// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <AsyncUDP.h>           // DNS sockets (raw lwIP: no 6-packet socket rx queue)
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <mbedtls/sha256.h>    // remote blocklist checksum
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
// Default upstream resolvers; both can be changed on the dashboard (saved to /upstream.cfg).
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM2_IP
#define UPSTREAM2_IP 149, 112, 112, 112           // Quad9 secondary (same operator, same policy)
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const char* UPSTREAM_CFG = "/upstream.cfg";
uint32_t upstream[2] = { (uint32_t)IPAddress(UPSTREAM_IP), (uint32_t)IPAddress(UPSTREAM2_IP) };  // [1] = 0: none
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
AsyncUDP dnsSock, upstreamSock;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

// User-managed domain lists, persisted one domain per line. Small enough to scan linearly.
static const int MAX_CUSTOM = 200;
struct DomList { const char* path; String dom[MAX_CUSTOM]; uint64_t hash[MAX_CUSTOM]; int n; };
DomList customList = { "/custom.txt" };   // always blocked (plus subdomains)
DomList allowList  = { "/allow.txt" };    // never blocked (plus subdomains), overrides the blocklist

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// Admin password for the dashboard (user WEB_USER) and network OTA. One set in the setup
// portal or on the dashboard is stored in NVS and overrides WEB_PASS/OTA_PASS from secrets.h,
// so prebuilt firmware (web flasher, CI) doesn't ship with the public placeholder passwords.
String webPass, otaPass;
static const unsigned MIN_PASS_LEN = 8;

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
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
static bool isBlockedHash(uint64_t h) {
  if (inList(customList, h)) return true;
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
static bool isBlocked(const char* domain) {
  if (allowList.n && anySuffix(domain, [](uint64_t h) { return inList(allowList, h); })) return false;
  return anySuffix(domain, isBlockedHash);
}

// ---------- persistence ----------
static void loadList(DomList& L) {
  L.n = 0; if (!LittleFS.exists(L.path)) return;
  File f = LittleFS.open(L.path, "r"); if (!f) return;
  while (f.available() && L.n < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { L.dom[L.n] = l; L.hash[L.n] = fnv40(l.c_str(), l.length()); L.n++; }
  }
  f.close();
}
static void saveList(const DomList& L) { File f = LittleFS.open(L.path, "w"); if (!f) return; for (int i = 0; i < L.n; i++) f.println(L.dom[i]); f.close(); }
static bool addToList(DomList& L, String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || L.n >= MAX_CUSTOM) return false;
  for (int i = 0; i < L.n; i++) if (L.dom[i] == d) return false;
  L.dom[L.n] = d; L.hash[L.n] = fnv40(d.c_str(), d.length()); L.n++; saveList(L); return true;
}
static void removeFromList(DomList& L, String d) {
  d.trim(); d.toLowerCase();
  for (int i = 0; i < L.n; i++) if (L.dom[i] == d) {
    for (int j = i; j < L.n - 1; j++) { L.dom[j] = L.dom[j+1]; L.hash[j] = L.hash[j+1]; }
    L.n--; saveList(L); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; if (!LittleFS.exists("/banned.txt")) return;
  File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Packet intake. The framework's precompiled lwIP gives each BSD/WiFiUDP socket a 6-packet
// rx queue, so a browser's burst of lookups (a page load fires dozens) lost everything past
// the sixth. AsyncUDP receives straight from lwIP; its callbacks (async_udp task) only copy
// the datagram into pktQ, and loop() does all the DNS work, so no state is shared across
// tasks except the queue itself.
struct Pkt { uint32_t ip; uint16_t port; bool fromUpstream; uint16_t len; uint8_t data[]; };
static const int PKT_QUEUE = 64;
static QueueHandle_t pktQ;
static void enqueuePkt(AsyncUDPPacket& p, bool fromUpstream) {
  size_t n = p.length();
  if (p.isIPv6() || n < 12 || n > sizeof(buf)) return;
  Pkt* k = (Pkt*)malloc(sizeof(Pkt) + n); if (!k) return;
  k->ip = (uint32_t)p.remoteIP(); k->port = p.remotePort(); k->fromUpstream = fromUpstream; k->len = n;
  memcpy(k->data, p.data(), n);
  if (xQueueSend(pktQ, &k, 0) != pdTRUE) free(k);  // full: drop, the client retries
}
static void sendTo(AsyncUDP& sock, uint32_t ip, uint16_t port, int len) { sock.writeTo(buf, len, IPAddress(ip), port); }

// Upstream forwarding is asynchronous: a query is sent with a fresh random txid and parked
// in this table, and replies are matched back to their client whenever they arrive. The old
// code waited up to 1 s per query, so one slow lookup stalled every other client, the
// dashboard and OTA. A reply is only accepted if its source is an upstream the query was sent
// to and its txid and question section match (issue #10: late replies must never reach the
// wrong client); the client's own txid is restored on the way back.
//
// Failover: a query unanswered after RETRY_MS is re-sent (same txid) to the other upstream and
// whichever answers first wins. FAILOVER_AFTER consecutive misses switch the active upstream;
// the primary is probed again every PRIMARY_RETRY_MS.
static const int MAX_PENDING = 32;
static const uint32_t PENDING_TIMEOUT_MS = 2000;   // clients retry on their own after this
static const uint32_t RETRY_MS = 700;
static const uint8_t  FAILOVER_AFTER = 3;
static const uint32_t PRIMARY_RETRY_MS = 60000;
struct Pending {
  bool used; uint8_t sentMask;                     // bit i: sent to upstream[i]
  uint16_t wid, cport, plen, ql; uint8_t cid0, cid1; uint32_t cip, t0;
  uint8_t pkt[300];                                // whole query (for the retry); ql = question bytes after the header
  uint64_t ckey;                                   // answer-cache key, 0 = don't cache the reply
};
static Pending pending[MAX_PENDING];
int upActive = 0; uint8_t upMisses[2] = { 0, 0 }; uint32_t upSwitchedAt = 0;

// ---------- answer cache ----------
// Upstream answers are kept for their TTL (capped) so repeat lookups skip the round trip.
// Sized at boot to the hardware: with working PSRAM, CACHE_SLOTS_PSRAM entries there;
// otherwise up to a quarter of the free internal heap (16..128 entries, ~0.5 KB each), which
// leaves room for the TLS handshake of remote blocklist updates. 2-way set associative.
// Only answers that fit in 512 bytes are kept: every client accepts that size.
static const int CACHE_SLOTS_PSRAM = 1024, CACHE_SLOTS_MIN = 16, CACHE_SLOTS_MAX = 128;   // powers of 2
static const int CACHE_MAX_ANSWER = 512;
static const uint32_t CACHE_MAX_TTL = 3600;
struct CacheEntry { uint64_t key; uint32_t storedAt, ttl; uint16_t len; uint8_t data[CACHE_MAX_ANSWER]; };
static CacheEntry* ansCache = nullptr; static int cacheSlots = 0;
uint32_t cacheHits = 0;

static void initAnswerCache() {
  if (psramFound()) {
    ansCache = (CacheEntry*)heap_caps_calloc(CACHE_SLOTS_PSRAM, sizeof(CacheEntry), MALLOC_CAP_SPIRAM);
    if (ansCache) cacheSlots = CACHE_SLOTS_PSRAM;
  }
  if (!ansCache) {
    int n = CACHE_SLOTS_MAX;
    while (n > CACHE_SLOTS_MIN && n * sizeof(CacheEntry) > ESP.getFreeHeap() / 4) n /= 2;
    ansCache = (CacheEntry*)calloc(n, sizeof(CacheEntry));
    cacheSlots = ansCache ? n : 0;
  }
  Serial.printf("answer cache: %d entries (%s)\n", cacheSlots, cacheSlots == CACHE_SLOTS_PSRAM ? "PSRAM" : "internal RAM");
}
// Key = lowercased question + EDNS presence, DO, AD and CD bits (answers differ with DNSSEC).
static uint64_t answerKey(int qlen, int qend) {
  if (!cacheSlots || qend <= 12 || qend > qlen) return 0;
  uint64_t h = 0xcbf29ce484222325ULL;
  for (int i = 12; i < qend; i++) { uint8_t c = buf[i]; if (c >= 'A' && c <= 'Z') c += 32; h ^= c; h *= 0x100000001b3ULL; }
  uint8_t flags = buf[3] & 0x30;                   // AD, CD
  const int arcount = (buf[10] << 8) | buf[11];
  if (arcount && qend + 11 <= qlen && buf[qend] == 0 && buf[qend + 1] == 0 && buf[qend + 2] == 41)
    flags |= 0x01 | (buf[qend + 7] & 0x80);        // OPT present, DO bit
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
// buf holds a matched upstream reply of n bytes whose question is ql bytes long.
static void cacheStore(uint64_t key, int n, int ql) {
  if (!key || n > CACHE_MAX_ANSWER) return;
  const uint8_t rcode = buf[3] & 0x0F;
  if (!(buf[2] & 0x80) || (buf[2] & 0x02) || (rcode != 0 && rcode != 3)) return;   // QR, !TC, NOERROR/NXDOMAIN
  if (((buf[4] << 8) | buf[5]) != 1) return;
  uint32_t ttl = walkTtls(buf, n, 12 + ql, 0);
  if (ttl == 0 || ttl == UINT32_MAX) return;       // malformed, zero TTL or nothing to time it by
  if (ttl > CACHE_MAX_TTL) ttl = CACHE_MAX_TTL;
  CacheEntry* e = cacheFind(key);
  if (!e) {                                        // pick the expired / older way of the set
    const int set = (int)(key & (uint64_t)(cacheSlots / 2 - 1)) * 2;
    CacheEntry *a = &ansCache[set], *b = &ansCache[set + 1];
    e = (!a->key || (int32_t)(a->storedAt - b->storedAt) < 0) ? a : b;
    if (!b->key) e = b;
  }
  e->key = key; e->storedAt = millis(); e->ttl = ttl; e->len = n; memcpy(e->data, buf, n);
}
// On a fresh hit, rewrites buf into the cached answer for this client and returns its length.
static int cacheAnswer(uint64_t key, int qend) {
  if (!key) return 0;
  CacheEntry* e = cacheFind(key); if (!e) return 0;
  const uint32_t age = (millis() - e->storedAt) / 1000;
  if (age >= e->ttl) { e->key = 0; return 0; }
  const int ql = qend - 12;
  if (12 + ql > e->len) return 0;
  uint8_t id0 = buf[0], id1 = buf[1], q[256];
  if (ql > (int)sizeof(q)) return 0;
  memcpy(q, buf + 12, ql);
  memcpy(buf, e->data, e->len);
  buf[0] = id0; buf[1] = id1;
  memcpy(buf + 12, q, ql);                         // the client's own spelling of the name
  if (age) walkTtls(buf, e->len, qend, age);
  cacheHits++;
  return e->len;
}

static int upstreamIndex(uint32_t ip) { for (int i = 0; i < 2; i++) if (upstream[i] && upstream[i] == ip) return i; return -1; }
static void sendPending(Pending& p, int u) {
  memcpy(buf, p.pkt, p.plen);
  sendTo(upstreamSock, upstream[u], UPSTREAM_PORT, p.plen);
  p.sentMask |= 1 << u;
}
static void forwardUpstream(uint32_t cip, uint16_t cport, int qlen, int qend, uint64_t ckey) {
  Pending* p = nullptr;
  for (int i = 0; i < MAX_PENDING; i++) {          // free slot, else evict the oldest
    if (!pending[i].used) { p = &pending[i]; break; }
    if (!p || (int32_t)(pending[i].t0 - p->t0) < 0) p = &pending[i];
  }
  uint16_t wid; bool clash;
  do {                                             // txid unique among in-flight queries
    wid = (uint16_t)esp_random(); clash = false;
    for (int i = 0; i < MAX_PENDING; i++) if (pending[i].used && &pending[i] != p && pending[i].wid == wid) clash = true;
  } while (clash);
  p->used = true; p->sentMask = 0; p->wid = wid; p->cip = cip; p->cport = cport;
  p->cid0 = buf[0]; p->cid1 = buf[1]; p->t0 = millis();
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  const bool fits = qlen <= (int)sizeof(p->pkt);
  p->plen = fits ? qlen : 0;                       // too big to keep: no retry, no question check
  p->ql = (fits && qend > 12 && qend <= qlen) ? qend - 12 : 0;
  if (fits) memcpy(p->pkt, buf, qlen);
  p->ckey = p->ql ? ckey : 0;
  sendTo(upstreamSock, upstream[upActive], UPSTREAM_PORT, qlen);
  p->sentMask = 1 << upActive;
}
static void handleReply(uint32_t ip, uint16_t port, int n) {
  int u = upstreamIndex(ip);
  if (u < 0 || port != UPSTREAM_PORT) return;
  const uint16_t wid = (buf[0] << 8) | buf[1];
  for (int i = 0; i < MAX_PENDING; i++) {
    Pending& p = pending[i];
    if (!p.used || p.wid != wid || !(p.sentMask & (1 << u))) continue;
    if (p.ql && (n < 12 + p.ql || memcmp(buf + 12, p.pkt + 12, p.ql) != 0)) return;
    buf[0] = p.cid0; buf[1] = p.cid1; p.used = false;
    upMisses[u] = 0;
    cacheStore(p.ckey, n, p.ql);
    sendTo(dnsSock, p.cip, p.cport, n);
    return;
  }
}
// Retries, failover and expiry for in-flight queries.
static void servicePending() {
  const uint32_t now = millis();
  const bool two = upstream[1] != 0;
  for (int i = 0; i < MAX_PENDING; i++) {
    Pending& p = pending[i];
    if (!p.used) continue;
    const uint32_t age = now - p.t0;
    if (age > PENDING_TIMEOUT_MS) { p.used = false; continue; }
    if (age > RETRY_MS && p.sentMask != 3 && p.plen) {
      const int first = (p.sentMask & 1) ? 0 : 1;
      if (upMisses[first] < 255) upMisses[first]++;
      if (two) sendPending(p, 1 - first); else p.sentMask = 3;   // single upstream: count once
    }
  }
  if (two && upMisses[upActive] >= FAILOVER_AFTER) {
    Serial.printf("[dns] upstream %s not answering, switching\n", IPAddress(upstream[upActive]).toString().c_str());
    upActive = 1 - upActive; upMisses[upActive] = 0; upSwitchedAt = now;
  }
  if (upActive == 1 && now - upSwitchedAt > PRIMARY_RETRY_MS) { upActive = 0; upMisses[0] = 0; }
}
static void loadUpstreams() {
  if (!LittleFS.exists(UPSTREAM_CFG)) return;
  File f = LittleFS.open(UPSTREAM_CFG, "r"); if (!f) return;
  IPAddress a, b;
  String l1 = f.readStringUntil('\n'), l2 = f.readStringUntil('\n'); f.close();
  l1.trim(); l2.trim();
  if (a.fromString(l1) && (uint32_t)a) upstream[0] = (uint32_t)a;
  upstream[1] = (l2.length() && b.fromString(l2)) ? (uint32_t)b : 0;
  upActive = 0;
}
static void saveUpstreams() {
  File f = LittleFS.open(UPSTREAM_CFG, "w"); if (!f) return;
  f.println(IPAddress(upstream[0]).toString());
  f.println(upstream[1] ? IPAddress(upstream[1]).toString() : String(""));
  f.close();
}
static void handleQuery(uint32_t cip, uint16_t cport, int qlen) {
  if (qlen < 13) return;
  char domain[256]; uint16_t qtype = 0; int qend = 0;   // qend stays 0 if the question can't be parsed
  size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
  Dev* c = getClient(cip);
  bool ban = c && c->banned;
  bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
  if (blocked) {
    if (!qend) qend = qlen;                        // banned client sent something unparseable
    int rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++;
    sendTo(dnsSock, cip, cport, rlen);
  } else {
    totalAllowed++; if (c) c->allowed++;
    const uint64_t key = dl ? answerKey(qlen, qend) : 0;
    int rlen = cacheAnswer(key, qend);
    if (rlen) sendTo(dnsSock, cip, cport, rlen);
    else      forwardUpstream(cip, cport, qlen, qend, key);
  }
}
// Drain a burst per call (capped, so web/OTA still get a turn). Returns true if it did work.
static bool handleDns() {
  bool did = false; Pkt* k;
  for (int budget = 0; budget < 32 && xQueueReceive(pktQ, &k, 0) == pdTRUE; budget++) {
    did = true;
    memcpy(buf, k->data, k->len);
    if (k->fromUpstream) handleReply(k->ip, k->port, k->len);
    else                 handleQuery(k->ip, k->port, k->len);
    free(k);
  }
  servicePending();
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

static void loadAuth() {
  prefs.begin("auth", false);
  String p = prefs.isKey("pass") ? prefs.getString("pass") : "";
  prefs.end();
  webPass = p.length() ? p : String(WEB_PASS);
  otaPass = p.length() ? p : String(OTA_PASS);
}
// ArduinoOTA only accepts a password before begin(), so OTA picks up a change on next boot.
static void saveAuth(const String& p) {
  prefs.begin("auth", false); prefs.putString("pass", p); prefs.end();
  loadAuth();
}
static bool defaultCreds() { return webPass.startsWith("CHANGE_ME") || otaPass.startsWith("CHANGE_ME"); }
static bool checkAuth() { return web.authenticate(WEB_USER, webPass.c_str()); }

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"up\":[\"" + IPAddress(upstream[0]).toString() + "\",\"" + (upstream[1] ? IPAddress(upstream[1]).toString() : String("")) + "\"]" +
             ",\"upActive\":" + upActive +
             ",\"cacheHits\":" + cacheHits + ",\"cacheSlots\":" + cacheSlots +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + (defaultCreds() ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  auto listJson = [&](const char* key, const DomList& L) {
    j += "],\""; j += key; j += "\":[";
    for (int i = 0; i < L.n; i++) { j += (i ? "," : ""); j += "\"" + jesc(L.dom[i]) + "\""; }
  };
  listJson("custom", customList);
  listJson("allow", allowList);
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (checkAuth()) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The new list is written to /blocklist.new next to the live one whenever both fit, so a
// failed or truncated transfer leaves the old list serving. Only when the partition can't
// hold two lists do we free the old one first; while that swap runs numHashes=0 and the
// device fail-opens (forwards, no blocking).
static const char* BLOCKLIST_NEW = "/blocklist.new";
static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
// expectBytes: incoming size if known (0 = unknown). Returns true if the old list was kept.
static bool beginBlocklistSwap(size_t expectBytes) {
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
static bool commitNewBlocklist(bool complete) {     // /blocklist.new -> live (validated)
  if (blocklist) blocklist.close();                 // rangeBuf is shared with lookups
  numHashes = 0;
  bool ok = complete && validBlocklist(BLOCKLIST_NEW);
  if (ok) { LittleFS.remove(BLOCKLIST_PATH); ok = LittleFS.rename(BLOCKLIST_NEW, BLOCKLIST_PATH); }
  if (!ok) LittleFS.remove(BLOCKLIST_NEW);
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: not a valid blocklist.bin (empty, wrong size or unsorted)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && checkAuth();
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false;
      beginBlocklistSwap(web.clientContentLength() > 0 ? web.clientContentLength() : 0);
      upFile = LittleFS.open(BLOCKLIST_NEW, "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist(true);
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove(BLOCKLIST_NEW); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  if (!LittleFS.exists("/update.cfg")) return;
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
// Mozilla's root CAs (tools/gen_crt_bundle.py), embedded via board_build.embed_files. HTTPS
// blocklist downloads are verified against it; they used to run with setInsecure(), so anyone
// on the path could serve a list that blocks everything or nothing. No clock is needed: this
// mbedTLS build doesn't check certificate dates.
extern const uint8_t caBundle[] asm("_binary_certs_x509_crt_bundle_bin_start");

// cs/cl must outlive the request. Returns the HTTP status, or a negative HTTPClient error.
static int httpGet(HTTPClient& http, WiFiClientSecure& cs, WiFiClient& cl, const String& url) {
  http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool ok;
  if (url.startsWith("https://")) { cs.setCACertBundle(caBundle); ok = http.begin(cs, url); }
  else ok = http.begin(cl, url);
  return ok ? http.GET() : HTTPC_ERROR_CONNECTION_REFUSED;
}
// HTTPClient reports every failed connect as "connection refused"; surface the TLS reason.
static String httpErr(int code, WiFiClientSecure& cs) {
  if (code >= 0) return "HTTP " + String(code);
  char tls[96];
  if (cs.lastError(tls, sizeof(tls)) != 0) return "TLS error: " + String(tls);
  return HTTPClient::errorToString(code);
}

// Optional "<url>.sha256" next to the list (sha256sum format; the weekly release publishes
// one). Returns 1 = got a checksum, 0 = none published (404), -1 = error (abort the update).
static int fetchChecksum(const String& url, uint8_t out[32]) {
  WiFiClientSecure cs; WiFiClient cl; HTTPClient http;
  int code = httpGet(http, cs, cl, url + ".sha256");
  if (code == 404) { http.end(); return 0; }
  if (code != HTTP_CODE_OK || http.getSize() > 512) { updateStatus = "checksum: " + httpErr(code, cs); http.end(); return -1; }
  String body = http.getString(); http.end(); body.trim();
  if (body.length() < 64) { updateStatus = "checksum: malformed .sha256"; return -1; }
  for (int i = 0; i < 32; i++) {
    char hex[3] = { body[2 * i], body[2 * i + 1], 0 }; char* e;
    out[i] = (uint8_t)strtoul(hex, &e, 16);
    if (*e) { updateStatus = "checksum: malformed .sha256"; return -1; }
  }
  return 1;
}

static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  uint8_t want[32];
  int haveSum = fetchChecksum(url, want);
  if (haveSum < 0) { Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }

  WiFiClientSecure cs; WiFiClient cl; HTTPClient http;
  int code = httpGet(http, cs, cl, url);
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = httpErr(code, cs); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  int len = http.getSize();
  beginBlocklistSwap(len > 0 ? len : 0);
  File f = LittleFS.open(BLOCKLIST_NEW, "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  mbedtls_sha256_context sha; mbedtls_sha256_init(&sha); mbedtls_sha256_starts_ret(&sha, 0);
  WiFiClient* stream = http.getStreamPtr();
  uint8_t b[1024]; size_t total = 0; uint32_t idle = millis(); bool wrOk = true;
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) {
      int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) { wrOk &= f.write(b, n) == (size_t)n; mbedtls_sha256_update_ret(&sha, b, n); total += n; idle = millis(); }
    } else { if (millis() - idle > 15000) break; delay(2); }
    handleDns();                                   // keep answering (old list, or fail-open) meanwhile
  }
  f.close(); http.end();
  uint8_t got[32]; mbedtls_sha256_finish_ret(&sha, got); mbedtls_sha256_free(&sha);
  // A dropped connection used to commit whatever had arrived if it happened to be a
  // multiple of 5 bytes. Require the full Content-Length (when the server sent one).
  bool complete = wrOk && (len < 0 || total == (size_t)len);
  bool sumOk = haveSum == 0 || memcmp(got, want, 32) == 0;
  bool ok = commitNewBlocklist(complete && sumOk);
  if (ok)             updateStatus = "ok: " + String(numHashes) + " domains";
  else if (!wrOk)     updateStatus = "flash full / write failed (" + String(total) + "B)";
  else if (!complete) updateStatus = "incomplete download (" + String(total) + "/" + String(len) + "B)";
  else if (!sumOk)    updateStatus = "sha256 mismatch";
  else                updateStatus = "bad data (" + String(total) + "B)";
  if (ok) updateStatus += haveSum ? ", sha256 verified" : ", no .sha256 published";
  if (ok && !url.startsWith("https://")) updateStatus += ", plain http (unauthenticated)";
  if (!ok && numHashes) updateStatus += ", kept old list";
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && checkAuth();
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.isKey("pass") ? prefs.getString("pass") : "";
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='WiFi password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<p style='color:#8b949e;margin:14px 0 0'>Admin password for the dashboard (user <b>" + htmlEscape(WEB_USER) + "</b>) and OTA updates" +
    String(defaultCreds() ? ":" : " &mdash; leave empty to keep the current one:") + "</p>"
    "<input name=a type=password minlength=8 placeholder='Admin password (8+ characters)'" + String(defaultCreds() ? " required" : "") +
    " style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p"), ap = web.arg("a");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  if (ap.length() ? ap.length() < MIN_PASS_LEN : defaultCreds()) {
    web.send(400, "text/plain", "admin password must be at least 8 characters"); return;
  }
  if (ap.length()) saveAuth(ap);
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadList(customList); loadList(allowList); loadBanned(); loadUpdateCfg(); loadAuth(); loadUpstreams();
  Serial.printf("custom: %d, allowed: %d, banned: %d\n", customList.n, allowList.n, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi + admin password and force the setup portal
  // (physical access is the recovery path for a forgotten password).
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      prefs.begin("auth", false); prefs.clear(); prefs.end(); loadAuth();
      Serial.println("[setup] BOOT held -> cleared saved WiFi and admin password"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (defaultCreds())
    Serial.println("[WARN] admin password is still the public placeholder from secrets.example.h. "
                    "Set one on the dashboard (Security) or in the setup portal before trusting this "
                    "device on a network you don't fully control.");

  initAnswerCache();
  pktQ = xQueueCreate(PKT_QUEUE, sizeof(Pkt*));
  dnsSock.listen(IPAddress(0, 0, 0, 0), DNS_PORT);   // IPv4 only: the client table keys on IPv4
  upstreamSock.listen(IPAddress(0, 0, 0, 0), 0);     // ephemeral source port for upstream queries
  dnsSock.onPacket([](AsyncUDPPacket& p) { enqueuePkt(p, false); });
  upstreamSock.onPacket([](AsyncUDPPacket& p) { enqueuePkt(p, true); });
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addToList(customList, web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeFromList(customList, web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/allow", []() { if (!requireAuth()) return; addToList(allowList, web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unallow", []() { if (!requireAuth()) return; removeFromList(allowList, web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/setpass", HTTP_POST, []() {
    if (!requireAuth()) return;
    String p = web.arg("p");
    if (p.length() < MIN_PASS_LEN) { web.send(400, "text/plain", "password must be at least 8 characters"); return; }
    saveAuth(p); web.send(200, "text/plain", "password changed (network OTA uses it after the next reboot)");
  });
  web.on("/setupstream", []() {             // /setupstream?p=9.9.9.9&s=149.112.112.112  (s empty = none)
    if (!requireAuth()) return;
    IPAddress a, b; String ss = web.arg("s"); ss.trim();
    const uint32_t self = (uint32_t)WiFi.localIP();
    if (!a.fromString(web.arg("p")) || !(uint32_t)a || (uint32_t)a == self ||
        (ss.length() && (!b.fromString(ss) || !(uint32_t)b || (uint32_t)b == self))) {
      web.send(400, "text/plain", "need a valid primary IPv4 (and optional secondary), not this device"); return;
    }
    upstream[0] = (uint32_t)a; upstream[1] = ss.length() ? (uint32_t)b : 0;
    upActive = 0; upMisses[0] = upMisses[1] = 0;
    saveUpstreams(); web.send(200, "text/plain", "ok");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/reboot", []() { if (!requireAuth()) return; web.send(200, "text/plain", "rebooting"); delay(300); ESP.restart(); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(otaPass.c_str());   // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
