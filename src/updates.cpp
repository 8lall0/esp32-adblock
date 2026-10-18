#include "updates.h"
#include <LittleFS.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <mbedtls/sha256.h>
#include "blocklist.h"
#include "dns.h"

String updateUrl = "";
uint32_t updateIntervalH = 24;
String updateStatus = "never";
static uint32_t lastCheckMs = 0;

void loadUpdateCfg() {
  if (!LittleFS.exists("/update.cfg")) return;
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
void saveUpdateCfg() {
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

bool fetchBlocklist(String url) {
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

void updatesTick() {
  if (!updateUrl.length()) return;
  uint32_t now = millis();
  if (lastCheckMs == 0) lastCheckMs = now;         // skip an immediate fetch on boot
  else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
}
