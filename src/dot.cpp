#include "dot.h"
#include <LittleFS.h>
#include <WiFiClientSecure.h>
#include "dns.h"

extern const uint8_t caBundle[] asm("_binary_certs_x509_crt_bundle_bin_start");   // Mozilla roots (updates.cpp)

// The TLS handshake blocks for 100-300 ms and reads block until a whole answer is in, so the
// connection lives in its own task; loop() only queues queries (dotQ) and receives answers
// through the same packet queue as UDP replies (dnsInjectReply), where the pending table,
// question check, retries and cache handle them like any other upstream reply.
static const char* DOT_CFG = "/dot.cfg";
static const uint16_t DOT_PORT = 853;
static const uint32_t FAIL_BACKOFF_MS = 30000;     // after a failed connect, plain DNS (or SERVFAIL) for this long
// Quad9 closes an idle DoT connection after ~10-15 s and a handshake takes ~2.3 s on an S3, so
// while the network is in use (a real query within KEEP_WARM_MS) the connection is kept open
// with a tiny query (root SOA: always cached, says nothing about anyone's browsing) whenever
// it has been silent for KEEPALIVE_MS. Without it the device re-handshook every ~12 s.
static const uint32_t KEEP_WARM_MS = 15 * 60000;
static const uint32_t KEEPALIVE_MS = 8000;
static const int MAX_ANSWER = 16384;               // bigger answers are dropped (client retries / times out)
static const int MAX_INFLIGHT = 48;

bool dotEnabled = false, dotStrict = false;
String dotName[2];

enum DotState : uint8_t { D_OFF, D_CONNECTING, D_CONNECTED, D_FAILED };
static volatile DotState state = D_OFF;
static volatile uint32_t failedAt = 0, lastUse = 0;
static volatile uint32_t nSent = 0, nRecv = 0, nConnects = 0, nKeepalive = 0;
static char lastErr[96] = "";
static char connHost[64] = ""; static volatile uint32_t connIp = 0;
static SemaphoreHandle_t cfgLock;
static volatile uint32_t cfgGen = 0;               // bumped by setDot(): the task reconnects
// With the TLS connection live, OTA firmware updates ended in a task-watchdog reset (and the
// update failed); with DoT off they worked. During an update loop() serves no DNS anyway, so
// the task drops its connection and idles until the update finishes or fails.
static volatile bool paused = false;
void dotPause(bool p) { paused = p; }
void dotRestart() { failedAt = 0; cfgGen++; }       // upstreams changed: reconnect to the new ones

struct DotMsg { uint16_t wid; int8_t tcpSlot; uint16_t len; uint8_t data[]; };
static QueueHandle_t dotQ;
struct Inflight { bool used; uint16_t wid; int8_t tcpSlot; uint32_t t; };
static Inflight inflight[MAX_INFLIGHT];             // task-only: routes answers back

// Resolvers whose certificates name a host, not their IPs (mbedTLS 2.28 can't match IP SANs).
String tlsNameFor(int idx) {
  xSemaphoreTake(cfgLock, portMAX_DELAY);
  String n = dotName[idx];
  xSemaphoreGive(cfgLock);
  if (n.length()) return n;
  static const struct { const char* ip; const char* name; } known[] = {
    { "9.9.9.9", "dns.quad9.net" }, { "149.112.112.112", "dns.quad9.net" },
    { "9.9.9.10", "dns10.quad9.net" }, { "149.112.112.10", "dns10.quad9.net" },
    { "9.9.9.11", "dns11.quad9.net" }, { "149.112.112.11", "dns11.quad9.net" },
    { "1.1.1.1", "cloudflare-dns.com" }, { "1.0.0.1", "cloudflare-dns.com" },
    { "1.1.1.2", "security.cloudflare-dns.com" }, { "1.0.0.2", "security.cloudflare-dns.com" },
    { "8.8.8.8", "dns.google" }, { "8.8.4.4", "dns.google" },
    { "94.140.14.14", "dns.adguard-dns.com" }, { "94.140.15.15", "dns.adguard-dns.com" },
  };
  const String ip = IPAddress(upstream[idx]).toString();
  for (auto& k : known) if (ip == k.ip) return k.name;
  return "";
}

static void loadDotCfg() {
  dotEnabled = heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0;   // default: on where RAM is plentiful
  if (!LittleFS.exists(DOT_CFG)) return;
  File f = LittleFS.open(DOT_CFG, "r"); if (!f) return;
  String l[4]; for (auto& s : l) { s = f.readStringUntil('\n'); s.trim(); }
  f.close();
  dotEnabled = l[0] == "1"; dotStrict = l[1] == "1"; dotName[0] = l[2]; dotName[1] = l[3];
}
void setDot(bool on, bool strict, const String& n0, const String& n1) {
  xSemaphoreTake(cfgLock, portMAX_DELAY);
  dotEnabled = on; dotStrict = strict; dotName[0] = n0; dotName[1] = n1;
  xSemaphoreGive(cfgLock);
  failedAt = 0; cfgGen++;                          // task reconnects with the new settings
  File f = LittleFS.open(DOT_CFG, "w"); if (!f) return;
  f.println(on ? 1 : 0); f.println(strict ? 1 : 0); f.println(n0); f.println(n1); f.close();
}
bool dotUsable() {
  if (!dotEnabled) return false;
  return !(state == D_FAILED && millis() - failedAt < FAIL_BACKOFF_MS);
}
bool dotSend(const uint8_t* q, int len, uint16_t wid, int tcpSlot) {
  if (!dotUsable()) return false;
  DotMsg* m = (DotMsg*)malloc(sizeof(DotMsg) + len); if (!m) return false;
  m->wid = wid; m->tcpSlot = tcpSlot; m->len = len; memcpy(m->data, q, len);
  if (xQueueSend(dotQ, &m, 0) != pdTRUE) { free(m); return false; }
  lastUse = millis();
  return true;
}

// ---------- the task ----------
static bool readFull(WiFiClientSecure& c, uint8_t* p, int n, uint32_t timeoutMs) {
  uint32_t t0 = millis();
  while (n > 0) {
    int a = c.available();
    if (a < 0 || !c.connected()) return false;
    if (a == 0) { if (millis() - t0 > timeoutMs) return false; vTaskDelay(1); continue; }
    int r = c.read(p, n < a ? n : a); if (r <= 0) return false;
    p += r; n -= r;
  }
  return true;
}
static bool connectTo(WiFiClientSecure& c, int idx) {
  const uint32_t ip = upstream[idx];                // read once: the dashboard may change it meanwhile
  const String name = tlsNameFor(idx);
  if (!ip) return false;
  if (!name.length()) { snprintf(lastErr, sizeof(lastErr), "no TLS hostname for %s", IPAddress(ip).toString().c_str()); return false; }
  state = D_CONNECTING;
  if (!c.connect(IPAddress(ip), DOT_PORT, name.c_str(), nullptr, nullptr, nullptr)) {
    char e[80] = ""; c.lastError(e, sizeof(e));
    snprintf(lastErr, sizeof(lastErr), "%s: %s", name.c_str(), e[0] ? e : "connect failed");
    return false;
  }
  strlcpy(connHost, name.c_str(), sizeof(connHost)); connIp = ip;
  nConnects++; lastErr[0] = 0;
  return true;
}
static void flushQueue() { DotMsg* m; while (xQueueReceive(dotQ, &m, 0) == pdTRUE) free(m); }
static void dotTask(void*) {
  WiFiClientSecure c;
  c.setCACertBundle(caBundle);
  c.setHandshakeTimeout(5);
  int connIdx = -1, connFor = -1;                  // upstream connected to / upActive at that time
  uint32_t lastTraffic = 0;                        // last query/answer on this connection
  uint32_t gen = cfgGen;
  for (;;) {
    DotMsg* m = nullptr;
    if (gen != cfgGen) { gen = cfgGen; if (c.connected()) c.stop(); connIdx = -1; if (state != D_FAILED) state = D_OFF; }
    if (!dotEnabled || paused) {
      if (c.connected()) c.stop();
      connIdx = -1; state = D_OFF; flushQueue();
      vTaskDelay(pdMS_TO_TICKS(200)); continue;
    }
    if (state == D_FAILED && millis() - failedAt < FAIL_BACKOFF_MS) {
      flushQueue();                                // loop() uses plain DNS (or SERVFAIL) meanwhile
      vTaskDelay(pdMS_TO_TICKS(100)); continue;
    }
    // Follow a failover (upActive changed since we connected). Being on the other upstream because
    // the active one failed its handshake is fine: re-trying it every pass thrashed connections.
    if (c.connected() && upActive != connFor) { c.stop(); connIdx = -1; }
    if (!c.connected()) {
      connIdx = -1;
      if (state == D_CONNECTED) state = D_OFF;     // server closed an idle connection
      const bool want = uxQueueMessagesWaiting(dotQ) > 0 || millis() - lastUse < KEEP_WARM_MS;
      if (!want) { xQueuePeek(dotQ, &m, pdMS_TO_TICKS(200)); continue; }
      if (connectTo(c, upActive)) connIdx = upActive;
      else if (upstream[1] && connectTo(c, 1 - upActive)) connIdx = 1 - upActive;
      if (connIdx < 0) { state = D_FAILED; failedAt = millis(); flushQueue(); continue; }
      connFor = upActive; state = D_CONNECTED; lastTraffic = millis();
    }
    while (xQueueReceive(dotQ, &m, 0) == pdTRUE) { // send everything queued
      uint8_t hdr[2] = { (uint8_t)(m->len >> 8), (uint8_t)m->len };
      bool ok = c.write(hdr, 2) == 2 && c.write(m->data, m->len) == m->len;
      if (ok) {
        nSent++; lastTraffic = millis();
        int slot = -1;
        for (int i = 0; i < MAX_INFLIGHT; i++) if (!inflight[i].used || millis() - inflight[i].t > 10000) { slot = i; break; }
        if (slot >= 0) inflight[slot] = { true, m->wid, m->tcpSlot, millis() };
      }
      free(m);
      if (!ok) { c.stop(); break; }
    }
    while (c.connected() && c.available() >= 2) {  // read every answer that has arrived
      uint8_t hdr[2];
      if (!readFull(c, hdr, 2, 3000)) { c.stop(); break; }
      const int len = (hdr[0] << 8) | hdr[1];
      if (len < 12 || len > MAX_ANSWER) { c.stop(); break; }   // can't resync the stream
      uint8_t* a = (uint8_t*)malloc(len);
      if (!a || !readFull(c, a, len, 3000)) { free(a); c.stop(); break; }
      nRecv++; lastTraffic = millis();
      const uint16_t wid = (a[0] << 8) | a[1];
      int8_t tcpSlot = -1;
      for (int i = 0; i < MAX_INFLIGHT; i++) if (inflight[i].used && inflight[i].wid == wid) { tcpSlot = inflight[i].tcpSlot; inflight[i].used = false; break; }
      if (tcpSlot >= 0) dnsTcpReply(tcpSlot, wid, a, len);       // takes ownership of a
      else { dnsInjectReply(a, len, connIp); free(a); }
    }
    if (c.connected() && millis() - lastTraffic > KEEPALIVE_MS && millis() - lastUse < KEEP_WARM_MS) {
      static const uint8_t ka[] = { 0, 17, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1 };   // ". SOA IN" (+2-byte length)
      uint8_t msg[sizeof(ka)]; memcpy(msg, ka, sizeof(ka));
      const uint16_t id = (uint16_t)esp_random(); msg[2] = id >> 8; msg[3] = id;   // answer finds no pending query: dropped
      if (c.write(msg, sizeof(msg)) == sizeof(msg)) { nKeepalive++; lastTraffic = millis(); } else c.stop();
    }
    // Answers outstanding: check again in 1 ms (a 10 ms sleep added up to 10 ms per answer);
    // otherwise sleep until the next query is queued.
    bool waiting = false;
    for (int i = 0; i < MAX_INFLIGHT && !waiting; i++) waiting = inflight[i].used && millis() - inflight[i].t < 5000;
    if (waiting) vTaskDelay(1); else xQueuePeek(dotQ, &m, pdMS_TO_TICKS(20));
  }
}

void dotBegin() {
  cfgLock = xSemaphoreCreateMutex();
  loadDotCfg();
  dotQ = xQueueCreate(32, sizeof(DotMsg*));
  xTaskCreatePinnedToCore(dotTask, "dot", 10240, nullptr, 2, nullptr, 0);
}

String dotStatusJson() {
  const char* st = !dotEnabled ? "off" : state == D_CONNECTED ? "connected" : state == D_CONNECTING ? "connecting"
                 : state == D_FAILED ? "failed" : "idle";
  String j = "{\"on\":"; j += dotEnabled ? "true" : "false";
  j += ",\"strict\":"; j += dotStrict ? "true" : "false";
  j += ",\"state\":\""; j += st; j += "\"";
  j += ",\"host\":\""; j += connHost; j += "\",\"ip\":\""; j += connIp ? IPAddress(connIp).toString() : String(""); j += "\"";
  j += ",\"names\":[\""; j += tlsNameFor(0); j += "\",\""; j += tlsNameFor(1); j += "\"]";
  j += ",\"custom\":[\""; j += dotName[0]; j += "\",\""; j += dotName[1]; j += "\"]";
  j += ",\"sent\":"; j += nSent; j += ",\"recv\":"; j += nRecv; j += ",\"connects\":"; j += nConnects; j += ",\"keepalives\":"; j += nKeepalive;
  String e; for (const char* p = lastErr; *p; p++) if (*p != '"' && *p != '\\') e += *p;
  j += ",\"err\":\""; j += e; j += "\"}";
  return j;
}
