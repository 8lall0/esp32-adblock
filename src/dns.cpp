#include "dns.h"
#include <WiFi.h>
#include <AsyncUDP.h>           // DNS sockets (raw lwIP: no 6-packet socket rx queue)
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
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
struct Pkt { Addr from; uint16_t port; bool fromUpstream; uint16_t len; uint8_t data[]; };
static const int PKT_QUEUE = 64;
static QueueHandle_t pktQ;
// The sender address is read from the IP header in front of the payload. AsyncUDPPacket's own
// remoteIP()/isIPv6() can't be trusted: AsyncUDP queues a *pointer* to lwIP's "current
// packet source" global and reads it later from its own task, by which time it may describe
// another packet (any IPv6 traffic on the LAN, e.g. neighbour discovery, flips the type).
// IPv6 queries then showed up as bogus IPv4 clients, and IPv4 packets (including upstream
// replies) were mistaken for IPv6 and dropped. Strict checks: exactly one header must match.
static bool packetSource(AsyncUDPPacket& p, Addr& from) {
  const uint8_t* d = p.data(); const size_t n = p.length();
  const uint8_t* h4 = d - 8 - 20;                  // IPv4 header without options, then UDP
  const uint8_t* h6 = d - 8 - 40;                  // IPv6 header without extension headers, then UDP
  const bool v4 = h4[0] == 0x45 && h4[9] == 17 && (size_t)((h4[2] << 8) | h4[3]) == n + 28;
  const bool v6 = (h6[0] >> 4) == 6 && h6[6] == 17 && (size_t)((h6[4] << 8) | h6[5]) == n + 8;
  if (v4 == v6) return false;
  from = {};
  if (v4) memcpy(from.b, h4 + 12, 4);
  else  { from.v6 = true; memcpy(from.b, h6 + 8, 16); }
  return true;
}
static void enqueuePkt(AsyncUDPPacket& p, bool fromUpstream) {
  size_t n = p.length();
  if (n < 12 || n > sizeof(buf)) return;
  Addr from;
  if (!packetSource(p, from) || (fromUpstream && from.v6)) return;   // upstreams are IPv4
  Pkt* k = (Pkt*)malloc(sizeof(Pkt) + n); if (!k) return;
  k->from = from;
  k->port = p.remotePort(); k->fromUpstream = fromUpstream; k->len = n;
  memcpy(k->data, p.data(), n);
  if (xQueueSend(pktQ, &k, 0) != pdTRUE) free(k);  // full: drop, the client retries
}
static void sendUpstream(uint32_t ip, int len) { upstreamSock.writeTo(buf, len, IPAddress(ip), UPSTREAM_PORT); }
// IPv6 clients are usually link-local (fe80::/10), which lwIP only routes with a zone (the
// interface). AsyncUDP's IPv6Address overload leaves the zone field uninitialised, so whether
// a reply went out depended on stack garbage; build the address here with the zone set.
static void sendClient(const Addr& to, uint16_t port, int len) {
  if (!to.v6) { uint32_t ip; memcpy(&ip, to.b, 4); dnsSock.writeTo(buf, len, IPAddress(ip), port); return; }
  ip_addr_t d = {};
  d.type = IPADDR_TYPE_V6;
  memcpy(d.u_addr.ip6.addr, to.b, 16);
  esp_netif_t* sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  struct netif* nif = sta ? (struct netif*)esp_netif_get_netif_impl(sta) : nullptr;
  if (nif) ip6_addr_assign_zone(ip_2_ip6(&d), IP6_UNICAST, nif);
  dnsSock.writeTo(buf, len, &d, port, TCPIP_ADAPTER_IF_STA);
}

// Why each query got the answer it did, for /debug.json (diagnosing "a blocked domain
// resolved" reports). Counters per reason plus the last DECISION_LOG queries.
static const int DECISION_LOG = 32;
static const char* const WHY_NAMES[] = { "upstream", "cache", "allowlisted", "paused", "no-list", "unparsed",
                                         "banned", "custom", "blocklist" };
enum Why : uint8_t { W_UPSTREAM, W_CACHE, W_ALLOW, W_PAUSED, W_NOLIST, W_UNPARSED, W_BANNED, W_CUSTOM, W_LIST, W_COUNT };
struct Decision { uint32_t t; Addr client; char domain[64]; uint16_t qtype; Why why; bool tcp; };
static Decision decisions[DECISION_LOG]; static int decisionNext = 0, decisionCount = 0;
static uint32_t whyCount[W_COUNT];
static void recordDecision(const Addr& client, const char* domain, uint16_t qtype, Why why, bool tcp) {
  whyCount[why]++;
  Decision& d = decisions[decisionNext];
  d.t = millis(); d.client = client; d.qtype = qtype; d.why = why; d.tcp = tcp;
  strlcpy(d.domain, domain, sizeof(d.domain));
  decisionNext = (decisionNext + 1) % DECISION_LOG;
  if (decisionCount < DECISION_LOG) decisionCount++;
}

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
  uint16_t wid, cport, plen, ql; uint8_t cid0, cid1; Addr client; uint32_t t0;
  uint8_t pkt[300];                                // whole query (for the retry); ql = question bytes after the header
  uint64_t ckey;                                   // answer-cache key, 0 = don't cache the reply
};
static Pending pending[MAX_PENDING];
int upActive = 0;
static uint8_t upMisses[2] = { 0, 0 }; static uint32_t upSwitchedAt = 0;

static int upstreamIndex(uint32_t ip) { for (int i = 0; i < 2; i++) if (upstream[i] && upstream[i] == ip) return i; return -1; }
static void sendPending(Pending& p, int u) {
  memcpy(buf, p.pkt, p.plen);
  sendUpstream(upstream[u], p.plen);
  p.sentMask |= 1 << u;
}
static void forwardUpstream(const Addr& client, uint16_t cport, int qlen, int qend, uint64_t ckey) {
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
  p->used = true; p->sentMask = 0; p->wid = wid; p->client = client; p->cport = cport;
  p->cid0 = buf[0]; p->cid1 = buf[1]; p->t0 = millis();
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  const bool fits = qlen <= (int)sizeof(p->pkt);
  p->plen = fits ? qlen : 0;                       // too big to keep: no retry, no question check
  p->ql = (fits && qend > 12 && qend <= qlen) ? qend - 12 : 0;
  if (fits) memcpy(p->pkt, buf, qlen);
  p->ckey = p->ql ? ckey : 0;
  sendUpstream(upstream[upActive], qlen);
  p->sentMask = 1 << upActive;
}
static void handleReply(const Addr& from, uint16_t port, int n) {
  uint32_t ip; memcpy(&ip, from.b, 4);
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
    sendClient(p.client, p.cport, n);
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
// Decides the query in buf (shared by UDP and TCP). Returns the length of an answer now built
// in buf (blocked or cached), or 0 if it must go upstream; *qendOut / *keyOut are for that.
static int answerLocally(const Addr& client, int qlen, bool tcp, int* qendOut, uint64_t* keyOut) {
  char domain[256] = ""; uint16_t qtype = 0; int qend = 0;   // qend stays 0 if the question can't be parsed
  size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
  Dev* c = getClient(client);
  Why why;
  if (c && c->banned)  why = W_BANNED;
  else if (!dl)        why = W_UNPARSED;
  else if (!blockingOn) why = W_PAUSED;
  else if (!numHashes) why = W_NOLIST;               // list being replaced: fail open
  else switch (blockReason(domain)) {
    case BW_LIST:   why = W_LIST; break;
    case BW_CUSTOM: why = W_CUSTOM; break;
    case BW_ALLOW:  why = W_ALLOW; break;
    default:        why = W_UPSTREAM;
  }
  int rlen;
  uint64_t key = 0;
  if (why >= W_BANNED) {
    if (!qend) qend = qlen;                        // banned client sent something unparseable
    rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++;
  } else {
    totalAllowed++; if (c) c->allowed++;
    key = dl ? answerKey(buf, qlen, qend) : 0;
    rlen = cacheAnswer(buf, key, qend);
    if (rlen && why == W_UPSTREAM) why = W_CACHE;
  }
  recordDecision(client, domain, qtype, why, tcp);
  *qendOut = qend; *keyOut = key;
  return rlen;
}
static void handleQuery(const Addr& client, uint16_t cport, int qlen) {
  if (qlen < 13) return;
  int qend; uint64_t key;
  int rlen = answerLocally(client, qlen, false, &qend, &key);
  if (rlen) sendClient(client, cport, rlen);
  else      forwardUpstream(client, cport, qlen, qend, key);
}

// ---------- DNS over TCP (RFC 7766) ----------
// Clients retry over TCP when a UDP answer comes back truncated (TC bit), so without this
// big answers (long TXT/DNSKEY/CNAME chains) failed. Each message is prefixed with a 2-byte
// length. Queries are decided by answerLocally() like UDP ones; forwarded ones get their own
// TCP connection to the upstream, and the answer is streamed back in chunks, so its size
// (up to 64 KB) never has to fit in RAM. All sockets are non-blocking and polled from loop().
// Connections are few because lwIP has 16 sockets in total (web server, OTA, fetches...).
static const int MAX_TCP = 3;
static const uint32_t TCP_IDLE_MS = 10000;
static const int TCP_MAX_QUERY = 512;
enum TcpState : uint8_t { T_FREE, T_READ, T_CONNECT, T_SENDQ, T_RELAY_LEN, T_RELAY };
struct TcpConn {
  TcpState st; int cfd, ufd; Addr client; uint32_t t; int upIdx; bool triedOther;
  uint16_t qlen, have;                             // query: 2-byte length + body, read so far
  uint8_t q[2 + TCP_MAX_QUERY];
  uint32_t left;                                   // answer bytes still to relay
  uint16_t outLen, outOff; uint8_t out[512];       // chunk waiting to be written to the client
};
static TcpConn tcpConns[MAX_TCP];
static int tcpListen = -1;

static void tcpCloseUp(TcpConn& c) { if (c.ufd >= 0) { close(c.ufd); c.ufd = -1; } }
static void tcpClose(TcpConn& c) { tcpCloseUp(c); if (c.cfd >= 0) close(c.cfd); c.cfd = -1; c.st = T_FREE; }
static void nonBlocking(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK); }
// Writes as much of c.out as the socket takes; true once it's all gone.
static bool tcpFlush(TcpConn& c) {
  while (c.outOff < c.outLen) {
    int n = send(c.cfd, c.out + c.outOff, c.outLen - c.outOff, MSG_DONTWAIT);
    if (n > 0) { c.outOff += n; c.t = millis(); continue; }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false;
    tcpClose(c); return false;
  }
  return true;
}
static bool tcpConnectUp(TcpConn& c, int idx) {
  tcpCloseUp(c);
  if (!upstream[idx]) return false;
  c.ufd = socket(AF_INET, SOCK_STREAM, 0); if (c.ufd < 0) return false;
  nonBlocking(c.ufd);
  struct sockaddr_in sa = {}; sa.sin_family = AF_INET; sa.sin_port = htons(UPSTREAM_PORT); sa.sin_addr.s_addr = upstream[idx];
  int r = connect(c.ufd, (struct sockaddr*)&sa, sizeof(sa));
  if (r < 0 && errno != EINPROGRESS) { tcpCloseUp(c); return false; }
  c.upIdx = idx; c.st = T_CONNECT; c.t = millis();
  return true;
}
// Connect failed or upstream hung up early: try the other upstream once, else give up.
static void tcpUpFailed(TcpConn& c) {
  if (!c.triedOther && upstream[1] && tcpConnectUp(c, 1 - c.upIdx)) { c.triedOther = true; return; }
  tcpClose(c);
}
static void tcpQueryComplete(TcpConn& c) {
  memcpy(buf, c.q + 2, c.qlen);
  int qend; uint64_t key;
  int rlen = answerLocally(c.client, c.qlen, true, &qend, &key);
  if (rlen) {                                      // blocked / cached: answer straight away
    c.out[0] = rlen >> 8; c.out[1] = rlen & 0xFF;
    if (rlen > (int)sizeof(c.out) - 2) { tcpClose(c); return; }
    memcpy(c.out + 2, buf, rlen); c.outLen = rlen + 2; c.outOff = 0;
    c.have = 0; c.st = T_READ;
    tcpFlush(c);
    return;
  }
  c.triedOther = false;
  if (!tcpConnectUp(c, upActive)) tcpUpFailed(c);
}
static void tcpService(TcpConn& c) {
  const uint32_t now = millis();
  if (now - c.t > TCP_IDLE_MS) { tcpClose(c); return; }
  if (c.outOff < c.outLen && !tcpFlush(c)) return; // finish pending output first
  switch (c.st) {
    case T_READ: {                                 // length prefix, then the query
      const int want = c.have < 2 ? 2 - c.have : 2 + c.qlen - c.have;
      int n = recv(c.cfd, c.q + c.have, want, MSG_DONTWAIT);
      if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) { tcpClose(c); return; }
      if (n < 0) return;
      c.have += n; c.t = now;
      if (c.have == 2) {
        c.qlen = (c.q[0] << 8) | c.q[1];
        if (c.qlen < 13 || c.qlen > TCP_MAX_QUERY) { tcpClose(c); return; }
      }
      if (c.have >= 2 && c.have == 2 + c.qlen) tcpQueryComplete(c);
      return;
    }
    case T_CONNECT: {
      fd_set w; FD_ZERO(&w); FD_SET(c.ufd, &w); struct timeval tv = { 0, 0 };
      if (select(c.ufd + 1, nullptr, &w, nullptr, &tv) <= 0) {
        if (now - c.t > 3000) tcpUpFailed(c);      // connect timeout
        return;
      }
      int err = 0; socklen_t el = sizeof(err);
      getsockopt(c.ufd, SOL_SOCKET, SO_ERROR, &err, &el);
      if (err) { tcpUpFailed(c); return; }
      c.st = T_SENDQ; c.outLen = 0; c.outOff = 0;  // the query is still in c.q (prefix included)
      // fall through
    }
    case T_SENDQ: {
      int n = send(c.ufd, c.q + c.outOff, 2 + c.qlen - c.outOff, MSG_DONTWAIT);
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
      if (n <= 0) { tcpUpFailed(c); return; }
      c.outOff += n; c.t = now;
      if (c.outOff < 2 + c.qlen) return;
      c.outOff = 0; c.outLen = 0; c.have = 0; c.st = T_RELAY_LEN;
      return;
    }
    case T_RELAY_LEN: {                            // upstream's 2-byte length goes to the client as-is
      int n = recv(c.ufd, c.out + c.have, 2 - c.have, MSG_DONTWAIT);
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { if (now - c.t > 5000) tcpClose(c); return; }
      if (n <= 0) { tcpUpFailed(c); return; }
      c.have += n; c.t = now;
      if (c.have < 2) return;
      c.left = (c.out[0] << 8) | c.out[1];
      c.outLen = 2; c.outOff = 0; c.st = T_RELAY;
      tcpFlush(c);
      return;
    }
    case T_RELAY: {
      if (!c.left) {                               // answer done: next query on this connection
        tcpCloseUp(c); c.have = 0; c.st = T_READ; return;
      }
      int n = recv(c.ufd, c.out, c.left < sizeof(c.out) ? c.left : sizeof(c.out), MSG_DONTWAIT);
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
      if (n <= 0) { tcpClose(c); return; }       // upstream hung up mid-answer
      c.left -= n; c.outLen = n; c.outOff = 0; c.t = now;
      tcpFlush(c);
      return;
    }
    default: return;
  }
}
// Accepts new connections and advances the existing ones. Returns true if anything happened.
static bool handleTcp() {
  if (tcpListen < 0) return false;
  bool did = false;
  struct sockaddr_in6 sa; socklen_t sl = sizeof(sa);
  int fd = accept(tcpListen, (struct sockaddr*)&sa, &sl);
  if (fd >= 0) {
    did = true;
    TcpConn* c = nullptr;
    for (int i = 0; i < MAX_TCP; i++) if (tcpConns[i].st == T_FREE) { c = &tcpConns[i]; break; }
    if (!c) close(fd);                             // all busy: the client retries
    else {
      nonBlocking(fd);
      *c = {}; c->cfd = fd; c->ufd = -1; c->st = T_READ; c->t = millis();
      c->client = {};
      const uint8_t* a = (const uint8_t*)&sa.sin6_addr;
      if (sa.sin6_family == AF_INET) memcpy(c->client.b, &((struct sockaddr_in*)&sa)->sin_addr, 4);
      else if (!memcmp(a, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12)) memcpy(c->client.b, a + 12, 4);  // IPv4-mapped
      else { c->client.v6 = true; memcpy(c->client.b, a, 16); }
    }
  }
  for (int i = 0; i < MAX_TCP; i++) if (tcpConns[i].st != T_FREE) tcpService(tcpConns[i]);
  return did;                                      // open connections alone don't keep loop() from idling
}
static void tcpBegin() {
  for (int i = 0; i < MAX_TCP; i++) { tcpConns[i].st = T_FREE; tcpConns[i].cfd = tcpConns[i].ufd = -1; }
  int fd = socket(AF_INET6, SOCK_STREAM, 0); if (fd < 0) return;
  int off = 0; setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));   // dual-stack: IPv4 too
  int on = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  struct sockaddr_in6 sa = {}; sa.sin6_family = AF_INET6; sa.sin6_port = htons(DNS_PORT);
  if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0 || listen(fd, MAX_TCP) < 0) { close(fd); return; }
  nonBlocking(fd);
  tcpListen = fd;
}
void dnsBegin() {
  initAnswerCache();
  pktQ = xQueueCreate(PKT_QUEUE, sizeof(Pkt*));
  dnsSock.listen(DNS_PORT);                          // IPv4 + IPv6
  upstreamSock.listen(IPAddress(0, 0, 0, 0), 0);     // ephemeral source port for upstream queries
  dnsSock.onPacket([](AsyncUDPPacket& p) { enqueuePkt(p, false); });
  upstreamSock.onPacket([](AsyncUDPPacket& p) { enqueuePkt(p, true); });
  tcpBegin();
}
// Drain a burst per call (capped, so web/OTA still get a turn). Returns true if it did work.
bool handleDns() {
  bool did = false; Pkt* k;
  for (int budget = 0; budget < 32 && xQueueReceive(pktQ, &k, 0) == pdTRUE; budget++) {
    did = true;
    memcpy(buf, k->data, k->len);
    if (k->fromUpstream) handleReply(k->from, k->port, k->len);
    else                 handleQuery(k->from, k->port, k->len);
    free(k);
  }
  servicePending();
  did |= handleTcp();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  return did;
}

String dnsDebugJson() {
  String j = "{\"counts\":{";
  for (int i = 0; i < W_COUNT; i++) { j += (i ? ",\"" : "\""); j += WHY_NAMES[i]; j += "\":"; j += whyCount[i]; }
  j += "},\"blocking\":"; j += blockingOn ? "true" : "false";
  j += ",\"recent\":[";
  const uint32_t now = millis();
  for (int i = 0; i < decisionCount; i++) {          // newest first
    const Decision& d = decisions[(decisionNext - 1 - i + DECISION_LOG) % DECISION_LOG];
    String dom; for (const char* p = d.domain; *p; p++) if (*p != '"' && *p != '\\' && (uint8_t)*p >= 0x20) dom += *p;
    j += (i ? "," : ""); j += "{\"ago\":"; j += (now - d.t) / 1000; j += ",\"client\":\""; j += addrStr(d.client);
    j += "\",\"domain\":\""; j += dom; j += "\",\"qtype\":"; j += d.qtype; j += ",\"why\":\""; j += WHY_NAMES[d.why]; j += "\""; if (d.tcp) j += ",\"tcp\":true"; j += "}";
  }
  return j + "]}";
}
