#pragma once
// Admin password for the dashboard (user WEB_USER) and network OTA. One set in the setup
// portal or on the dashboard is stored in NVS and overrides WEB_PASS/OTA_PASS from secrets.h,
// so prebuilt firmware (web flasher, CI) doesn't ship with the public placeholder passwords.
#include <Arduino.h>

extern String webPass, otaPass;
extern const char* const webUser;
static const unsigned MIN_PASS_LEN = 8;

void loadAuth();
void saveAuth(const String& p);            // network OTA picks it up on the next boot
void clearAuth();                          // back to the secrets.h passwords
bool defaultCreds();                       // still the public placeholder?
