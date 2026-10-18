#pragma once
// WiFi provisioning: saved credentials, the secrets.h fallback, and the captive setup portal.
#include <Arduino.h>

bool connectWiFi();                        // provisioned creds first, then secrets.h
[[noreturn]] void startConfigPortal();     // blocks until creds are saved, then reboots
void clearSavedWifi();
