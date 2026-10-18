#include "cache.h"

// Upstream answers are kept for their TTL (capped) so repeat lookups skip the round trip.
// Sized at boot to the hardware: with PSRAM, up to CACHE_SLOTS_PSRAM entries in what's left
// of it (the blocklist copy is allocated first);
// otherwise up to a quarter of the free internal heap (16..128 entries, ~0.5 KB each), which
// leaves room for the TLS handshake of remote blocklist updates. 2-way set associative.
// Only answers that fit in 512 bytes are kept: every client accepts that size.
static const int CACHE_SLOTS_PSRAM = 2048, CACHE_SLOTS_MIN = 16, CACHE_SLOTS_MAX = 128;   // powers of 2 (2048 ~ 1.1 MB)
static const int CACHE_MAX_ANSWER = 512;
static const uint32_t CACHE_MAX_TTL = 3600;
struct CacheEntry { uint64_t key; uint32_t storedAt, ttl; uint16_t len; uint8_t data[CACHE_MAX_ANSWER]; };
static CacheEntry* ansCache = nullptr; int cacheSlots = 0;
uint32_t cacheHits = 0;

void initAnswerCache() {
  const size_t ps = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
  if (ps > 64 * 1024) {
    int n = CACHE_SLOTS_PSRAM;
    while (n > CACHE_SLOTS_MAX && n * sizeof(CacheEntry) > ps - 64 * 1024) n /= 2;
    if (n > CACHE_SLOTS_MAX) ansCache = (CacheEntry*)heap_caps_calloc(n, sizeof(CacheEntry), MALLOC_CAP_SPIRAM);
    if (ansCache) cacheSlots = n;
  }
  if (!ansCache) {
    int n = CACHE_SLOTS_MAX;
    while (n > CACHE_SLOTS_MIN && n * sizeof(CacheEntry) > ESP.getFreeHeap() / 4) n /= 2;
    ansCache = (CacheEntry*)calloc(n, sizeof(CacheEntry));
    cacheSlots = ansCache ? n : 0;
  }
  Serial.printf("answer cache: %d entries (%s)\n", cacheSlots, cacheSlots > CACHE_SLOTS_MAX ? "PSRAM" : "internal RAM");
}
// Key = lowercased question + EDNS presence, DO, AD and CD bits (answers differ with DNSSEC).
uint64_t answerKey(const uint8_t* msg, int qlen, int qend) {
  if (!cacheSlots || qend <= 12 || qend > qlen) return 0;
  uint64_t h = 0xcbf29ce484222325ULL;
  for (int i = 12; i < qend; i++) { uint8_t c = msg[i]; if (c >= 'A' && c <= 'Z') c += 32; h ^= c; h *= 0x100000001b3ULL; }
  uint8_t flags = msg[3] & 0x30;                   // AD, CD
  const int arcount = (msg[10] << 8) | msg[11];
  if (arcount && qend + 11 <= qlen && msg[qend] == 0 && msg[qend + 1] == 0 && msg[qend + 2] == 41)
    flags |= 0x01 | (msg[qend + 7] & 0x80);        // OPT present, DO bit
  h ^= flags; h *= 0x100000001b3ULL;
  return h ? h : 1;
}
// Walks the resource records after the question. Returns the smallest TTL (OPT excluded,
// its "TTL" holds flags) or UINT32_MAX if there are none; with sub > 0 it also ages every
// TTL by sub seconds in place. Returns 0 on a malformed message.
static uint32_t walkTtls(uint8_t* m, int n, int pos, uint32_t sub) {
  const int rrs = ((m[6] << 8) | m[7]) + ((m[8] << 8) | m[9]) + ((m[10] << 8) | m[11]);
  uint32_t minTtl = UINT32_MAX;
  for (int r = 0; r < rrs; r++) {
    while (true) {                                 // owner name
      if (pos >= n) return 0;
      const uint8_t l = m[pos];
      if ((l & 0xC0) == 0xC0) { pos += 2; break; }
      if (l == 0) { pos += 1; break; }
      pos += l + 1;
    }
    if (pos + 10 > n) return 0;
    const uint16_t type = (m[pos] << 8) | m[pos + 1];
    uint32_t ttl = ((uint32_t)m[pos + 4] << 24) | ((uint32_t)m[pos + 5] << 16) | (m[pos + 6] << 8) | m[pos + 7];
    const uint16_t rdlen = (m[pos + 8] << 8) | m[pos + 9];
    if (type != 41) {
      if (ttl < minTtl) minTtl = ttl;
      if (sub) {
        ttl = ttl > sub ? ttl - sub : 0;
        m[pos + 4] = ttl >> 24; m[pos + 5] = ttl >> 16; m[pos + 6] = ttl >> 8; m[pos + 7] = ttl;
      }
    }
    pos += 10 + rdlen;
    if (pos > n) return 0;
  }
  return minTtl;
}
static CacheEntry* cacheFind(uint64_t key) {
  const int set = (int)(key & (uint64_t)(cacheSlots / 2 - 1)) * 2;
  for (int w = 0; w < 2; w++) if (ansCache[set + w].key == key) return &ansCache[set + w];
  return nullptr;
}
// msg holds a matched upstream reply of n bytes whose question is ql bytes long.
void cacheStore(const uint8_t* msg, uint64_t key, int n, int ql) {
  if (!key || n > CACHE_MAX_ANSWER) return;
  const uint8_t rcode = msg[3] & 0x0F;
  if (!(msg[2] & 0x80) || (msg[2] & 0x02) || (rcode != 0 && rcode != 3)) return;   // QR, !TC, NOERROR/NXDOMAIN
  if (((msg[4] << 8) | msg[5]) != 1) return;
  uint32_t ttl = walkTtls(const_cast<uint8_t*>(msg), n, 12 + ql, 0);   // sub = 0: read-only
  if (ttl == 0 || ttl == UINT32_MAX) return;       // malformed, zero TTL or nothing to time it by
  if (ttl > CACHE_MAX_TTL) ttl = CACHE_MAX_TTL;
  CacheEntry* e = cacheFind(key);
  if (!e) {                                        // pick the expired / older way of the set
    const int set = (int)(key & (uint64_t)(cacheSlots / 2 - 1)) * 2;
    CacheEntry *a = &ansCache[set], *b = &ansCache[set + 1];
    e = (!a->key || (int32_t)(a->storedAt - b->storedAt) < 0) ? a : b;
    if (!b->key) e = b;
  }
  e->key = key; e->storedAt = millis(); e->ttl = ttl; e->len = n; memcpy(e->data, msg, n);
}
// On a fresh hit, rewrites msg into the cached answer for this client and returns its length.
int cacheAnswer(uint8_t* msg, uint64_t key, int qend) {
  if (!key) return 0;
  CacheEntry* e = cacheFind(key); if (!e) return 0;
  const uint32_t age = (millis() - e->storedAt) / 1000;
  if (age >= e->ttl) { e->key = 0; return 0; }
  const int ql = qend - 12;
  if (12 + ql > e->len) return 0;
  uint8_t id0 = msg[0], id1 = msg[1], q[256];
  if (ql > (int)sizeof(q)) return 0;
  memcpy(q, msg + 12, ql);
  memcpy(msg, e->data, e->len);
  msg[0] = id0; msg[1] = id1;
  memcpy(msg + 12, q, ql);                         // the client's own spelling of the name
  if (age) walkTtls(msg, e->len, qend, age);
  cacheHits++;
  return e->len;
}
