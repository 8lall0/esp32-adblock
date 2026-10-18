#include "auth.h"
#include <Preferences.h>
#include "secrets.h"

String webPass, otaPass;
const char* const webUser = WEB_USER;

void loadAuth() {
  Preferences prefs;
  prefs.begin("auth", false);
  String p = prefs.isKey("pass") ? prefs.getString("pass") : "";
  prefs.end();
  webPass = p.length() ? p : String(WEB_PASS);
  otaPass = p.length() ? p : String(OTA_PASS);
}
// ArduinoOTA only accepts a password before begin(), so OTA picks up a change on next boot.
void saveAuth(const String& p) {
  Preferences prefs;
  prefs.begin("auth", false); prefs.putString("pass", p); prefs.end();
  loadAuth();
}
void clearAuth() {
  Preferences prefs;
  prefs.begin("auth", false); prefs.clear(); prefs.end();
  loadAuth();
}
bool defaultCreds() { return webPass.startsWith("CHANGE_ME") || otaPass.startsWith("CHANGE_ME"); }
