#include "web.h"
#include <WiFi.h>
#include <LittleFS.h>
#include <Update.h>            // firmware OTA
#include "auth.h"
#include "blocklist.h"
#include "cache.h"
#include "clients.h"
#include "dns.h"
#include "portal.h"
#include "updates.h"

WebServer web(80);

static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
String htmlEscape(const String& s) {
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
static bool checkAuth() { return web.authenticate(webUser, webPass.c_str()); }
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

void webBegin() {
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
    setUpstreams((uint32_t)a, ss.length() ? (uint32_t)b : 0);
    web.send(200, "text/plain", "ok");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/reboot", []() { if (!requireAuth()) return; web.send(200, "text/plain", "rebooting"); delay(300); ESP.restart(); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    clearSavedWifi(); delay(500); ESP.restart(); });
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
}
