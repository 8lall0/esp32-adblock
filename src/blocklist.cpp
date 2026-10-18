#include "blocklist.h"
#include <LittleFS.h>

static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

static File blocklist;
uint32_t numHashes = 0;

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

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
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

// Walks the domain and its parent suffixes down to two labels (a.b.example.com ->
// b.example.com -> example.com) and returns true if pred() matches any of them.
template <typename F> static bool anySuffix(const char* domain, F pred) {
  const char* p = domain;
  while (p && *p) {
    if (pred(fnv40(p, strlen(p)))) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}
BlockWhy blockReason(const char* domain) {
  if (allowList.n && anySuffix(domain, [](uint64_t h) { return inList(allowList, h); })) return BW_ALLOW;
  if (customList.n && anySuffix(domain, [](uint64_t h) { return inList(customList, h); })) return BW_CUSTOM;
  return anySuffix(domain, isListedHash) ? BW_LIST : BW_NONE;
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
void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
void openBlocklist() {
  if (!LittleFS.exists(BLOCKLIST_PATH)) return;
  reopenBlocklist();
  Serial.printf("blocklist: %u domains\n", numHashes);
}
// expectBytes: incoming size if known (0 = unknown). Returns true if the old list was kept.
bool beginBlocklistSwap(size_t expectBytes) {
  LittleFS.remove(BLOCKLIST_NEW);
  size_t freeB = LittleFS.totalBytes() - LittleFS.usedBytes();
  if (expectBytes && expectBytes + 32768 <= freeB) return true;   // margin for fs metadata
  if (blocklist) blocklist.close();
  numHashes = 0;
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
  numHashes = 0;
  bool ok = complete && validBlocklist(BLOCKLIST_NEW);
  if (ok) { LittleFS.remove(BLOCKLIST_PATH); ok = LittleFS.rename(BLOCKLIST_NEW, BLOCKLIST_PATH); }
  if (!ok) LittleFS.remove(BLOCKLIST_NEW);
  reopenBlocklist();
  return ok;
}
