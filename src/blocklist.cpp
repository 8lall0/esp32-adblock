#include "blocklist.h"
#include <LittleFS.h>

static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

static File blocklist;
uint32_t numHashes = 0;
// With PSRAM to spare, the whole list is copied there and binary-searched in RAM (a few us).
// Otherwise every uncached lookup is a LittleFS seek+read (~2 ms: random seeks walk the
// file's block chain), which was ~40% of the latency of a blocked answer.
// The buffer is kept across list replacements and refilled in place when the new list fits:
// freeing and reallocating ~0.5 MB fragmented PSRAM (anything >4 KB malloc'd meanwhile could
// land in the hole), after which the list never fit again and lookups silently went back to flash.
static uint8_t* listMem = nullptr;                 // valid while listInMem
static size_t listMemCap = 0;
static bool listInMem = false;
static const char* listMemState = "no psram";
static const size_t PSRAM_SPARE = 64 * 1024;       // left for everything else that lives in PSRAM

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

DomList customList = { "/custom.txt" };
DomList allowList  = { "/allow.txt" };

// ---------- hashing / matching ----------
uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inMemory(uint64_t h) {
  uint32_t lo = 0, hi = numHashes;                 // lower bound over 5-byte entries
  while (lo < hi) {
    uint32_t mid = (lo + hi) >> 1;
    if (unpackHash(listMem + (size_t)mid * HASH_BYTES) < h) lo = mid + 1; else hi = mid;
  }
  return lo < numHashes && unpackHash(listMem + (size_t)lo * HASH_BYTES) == h;
}
static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  if (listInMem) return inMemory(h);
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inList(const DomList& L, uint64_t h) { for (int i = 0; i < L.n; i++) if (L.hash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isListedHash(uint64_t h) {
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

// The domain and its parent suffixes down to two labels (a.b.example.com -> b.example.com ->
// example.com) are hashed once, then checked against the allowlist, custom list and blocklist.
static const int MAX_SUFFIXES = 16;
BlockWhy blockReason(const char* domain) {
  uint64_t h[MAX_SUFFIXES]; int n = 0;
  for (const char* p = domain; p && *p && n < MAX_SUFFIXES; ) {
    h[n++] = fnv40(p, strlen(p));
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  for (int i = 0; i < n && allowList.n; i++) if (inList(allowList, h[i])) return BW_ALLOW;
  for (int i = 0; i < n && customList.n; i++) if (inList(customList, h[i])) return BW_CUSTOM;
  for (int i = 0; i < n; i++) if (isListedHash(h[i])) return BW_LIST;
  return BW_NONE;
}

// ---------- custom / allow lists ----------
void loadList(DomList& L) {
  L.n = 0; if (!LittleFS.exists(L.path)) return;
  File f = LittleFS.open(L.path, "r"); if (!f) return;
  while (f.available() && L.n < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { L.dom[L.n] = l; L.hash[L.n] = fnv40(l.c_str(), l.length()); L.n++; }
  }
  f.close();
}
static void saveList(const DomList& L) { File f = LittleFS.open(L.path, "w"); if (!f) return; for (int i = 0; i < L.n; i++) f.println(L.dom[i]); f.close(); }
bool addToList(DomList& L, String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || L.n >= MAX_CUSTOM) return false;
  for (int i = 0; i < L.n; i++) if (L.dom[i] == d) return false;
  L.dom[L.n] = d; L.hash[L.n] = fnv40(d.c_str(), d.length()); L.n++; saveList(L); return true;
}
void removeFromList(DomList& L, String d) {
  d.trim(); d.toLowerCase();
  for (int i = 0; i < L.n; i++) if (L.dom[i] == d) {
    for (int j = i; j < L.n - 1; j++) { L.dom[j] = L.dom[j+1]; L.hash[j] = L.hash[j+1]; }
    L.n--; saveList(L); return;
  }
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The new list is written to /blocklist.new next to the live one whenever both fit, so a
// failed or truncated transfer leaves the old list serving. Only when the partition can't
// hold two lists do we free the old one first; while that swap runs numHashes=0 and the
// device fail-opens (forwards, no blocking).
const char* BLOCKLIST_NEW = "/blocklist.new";
static void freeListMem() { listInMem = false; if (listMem) { heap_caps_free(listMem); listMem = nullptr; listMemCap = 0; } }
static void loadListMem() {
  listInMem = false;
  const size_t sz = (size_t)numHashes * HASH_BYTES;
  if (!sz) return;
  if (!heap_caps_get_total_size(MALLOC_CAP_SPIRAM)) { listMemState = "no psram"; return; }
  if (sz > listMemCap) {                           // first list, or a bigger one
    freeListMem();
    if (heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) < sz || heap_caps_get_free_size(MALLOC_CAP_SPIRAM) < sz + PSRAM_SPARE) {
      listMemState = "no space"; return;
    }
    listMem = (uint8_t*)heap_caps_malloc(sz, MALLOC_CAP_SPIRAM);
    if (!listMem) { listMemState = "no space"; return; }
    listMemCap = sz;
  }
  blocklist.seek(0);
  for (size_t off = 0; off < sz; ) {               // chunked: a short read shows exactly where
    size_t n = blocklist.read(listMem + off, sz - off < 4096 ? sz - off : 4096);
    if (!n) { listMemState = "read failed"; Serial.printf("blocklist: PSRAM copy failed at %u/%u\n", off, sz); return; }
    off += n;
  }
  listInMem = true; listMemState = "ok";
}
void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  loadListMem();
  buildFlashIndex();
}
void openBlocklist() {
  if (!LittleFS.exists(BLOCKLIST_PATH)) return;
  reopenBlocklist();
  Serial.printf("blocklist: %u domains (%s)\n", numHashes, listInMem ? "in PSRAM" : "lookups from flash");
}
bool blocklistInMemory() { return listInMem; }
const char* blocklistMemState() { return listMemState; }
// expectBytes: incoming size if known (0 = unknown). Returns true if the old list was kept.
bool beginBlocklistSwap(size_t expectBytes) {
  LittleFS.remove(BLOCKLIST_NEW);
  size_t freeB = LittleFS.totalBytes() - LittleFS.usedBytes();
  if (expectBytes && expectBytes + 32768 <= freeB) return true;   // margin for fs metadata
  if (blocklist) blocklist.close();
  numHashes = 0; listInMem = false;                // buffer kept for the incoming list
  LittleFS.remove(BLOCKLIST_PATH);
  return false;
}
// A real blocklist.bin is a non-empty run of strictly ascending 5-byte hashes. Checking the
// order rejects HTML error pages, wrong files and corrupted transfers, not just bad sizes.
static bool validBlocklist(const char* path) {
  File f = LittleFS.open(path, "r"); if (!f) return false;
  size_t sz = f.size();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;
  uint64_t prev = 0; bool first = true;
  while (ok && f.available()) {
    int n = f.read(rangeBuf, sizeof(rangeBuf));    // reuses the lookup buffer (multiple of 5)
    if (n <= 0 || n % HASH_BYTES) { ok = false; break; }
    for (int i = 0; i < n; i += HASH_BYTES) {
      uint64_t v = unpackHash(rangeBuf + i);
      if (!first && v <= prev) { ok = false; break; }
      prev = v; first = false;
    }
  }
  f.close();
  return ok;
}
bool commitNewBlocklist(bool complete) {            // /blocklist.new -> live (validated)
  if (blocklist) blocklist.close();                 // rangeBuf is shared with lookups
  numHashes = 0; listInMem = false;
  bool ok = complete && validBlocklist(BLOCKLIST_NEW);
  if (ok) { LittleFS.remove(BLOCKLIST_PATH); ok = LittleFS.rename(BLOCKLIST_NEW, BLOCKLIST_PATH); }
  if (!ok) LittleFS.remove(BLOCKLIST_NEW);
  reopenBlocklist();
  return ok;
}
