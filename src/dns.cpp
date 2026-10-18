#include "dns.h"
#include <WiFi.h>
#include <AsyncUDP.h>           // DNS sockets (raw lwIP: no 6-packet socket rx queue)
#include <LittleFS.h>
#include "blocklist.h"
#include "cache.h"
#include "clients.h"

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
static const uint16_t DNS_PORT = 53;
uint32_t upstream[2] = { (uint32_t)IPAddress(UPSTREAM_IP), (uint32_t)IPAddress(UPSTREAM2_IP) };

static AsyncUDP dnsSock, upstreamSock;
static uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)
uint32_t totalBlocked = 0, totalAllowed = 0;
bool     blockingOn = true;
uint32_t resumeAt   = 0;

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
int upActive = 0;
static uint8_t upMisses[2] = { 0, 0 }; static uint32_t upSwitchedAt = 0;

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
    cacheStore(buf, p.ckey, n, p.ql);
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
void loadUpstreams() {
  if (!LittleFS.exists(UPSTREAM_CFG)) return;
  File f = LittleFS.open(UPSTREAM_CFG, "r"); if (!f) return;
  IPAddress a, b;
  String l1 = f.readStringUntil('\n'), l2 = f.readStringUntil('\n'); f.close();
  l1.trim(); l2.trim();
  if (a.fromString(l1) && (uint32_t)a) upstream[0] = (uint32_t)a;
  upstream[1] = (l2.length() && b.fromString(l2)) ? (uint32_t)b : 0;
  upActive = 0;
}
void setUpstreams(uint32_t primary, uint32_t secondary) {
  upstream[0] = primary; upstream[1] = secondary;
  upActive = 0; upMisses[0] = upMisses[1] = 0;
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
    const uint64_t key = dl ? answerKey(buf, qlen, qend) : 0;
    int rlen = cacheAnswer(buf, key, qend);
    if (rlen) sendTo(dnsSock, cip, cport, rlen);
    else      forwardUpstream(cip, cport, qlen, qend, key);
  }
}
void dnsBegin() {
  initAnswerCache();
  pktQ = xQueueCreate(PKT_QUEUE, sizeof(Pkt*));
  dnsSock.listen(IPAddress(0, 0, 0, 0), DNS_PORT);   // IPv4 only: the client table keys on IPv4
  upstreamSock.listen(IPAddress(0, 0, 0, 0), 0);     // ephemeral source port for upstream queries
  dnsSock.onPacket([](AsyncUDPPacket& p) { enqueuePkt(p, false); });
  upstreamSock.onPacket([](AsyncUDPPacket& p) { enqueuePkt(p, true); });
}
// Drain a burst per call (capped, so web/OTA still get a turn). Returns true if it did work.
bool handleDns() {
  bool did = false; Pkt* k;
  for (int budget = 0; budget < 32 && xQueueReceive(pktQ, &k, 0) == pdTRUE; budget++) {
    did = true;
    memcpy(buf, k->data, k->len);
    if (k->fromUpstream) handleReply(k->ip, k->port, k->len);
    else                 handleQuery(k->ip, k->port, k->len);
    free(k);
  }
  servicePending();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  return did;
}
