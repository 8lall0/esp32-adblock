// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM needed).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched (blocklist.cpp).
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, custom block/allow domains. All control state persisted to flash.
//
//   dns.cpp        queries in (IPv4 + IPv6), blocked answers, upstream forwarding + failover
//   ipv6.cpp       IPv6 addresses, optional RDNSS announcements
//   cache.cpp      TTL-aware answer cache
//   blocklist.cpp  flash hash list, custom/allow lists, list replacement
//   clients.cpp    per-client stats and bans
//   updates.cpp    remote blocklist download (TLS + sha256)
//   web.cpp        dashboard, auth, uploads, firmware OTA
//   portal.cpp     WiFi provisioning (captive portal)
//   auth.cpp       admin password

#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include "auth.h"
#include "blocklist.h"
#include "clients.h"
#include "dns.h"
#include "ipv6.h"
#include "portal.h"
#include "updates.h"
#include "web.h"

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  openBlocklist();
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
    if (digitalRead(BOOT_PIN) == LOW) { clearSavedWifi(); clearAuth();
      Serial.println("[setup] BOOT held -> cleared saved WiFi and admin password"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  ipv6Begin();
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (defaultCreds())
    Serial.println("[WARN] admin password is still the public placeholder from secrets.example.h. "
                    "Set one on the dashboard (Security) or in the setup portal before trusting this "
                    "device on a network you don't fully control.");

  dnsBegin();
  webBegin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(otaPass.c_str());   // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  updatesTick();                          // periodic remote blocklist auto-update
  ipv6Tick();                             // IPv6 DNS announcements (if enabled)
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
