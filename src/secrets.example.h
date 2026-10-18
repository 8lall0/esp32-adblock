#pragma once
// Copy this file to secrets.h and fill in your WiFi credentials.
// secrets.h is gitignored so your credentials never get committed.
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Auth for the dashboard's state-changing endpoints (/ban, /addblock, /upload,
// /update, /setupdate, /forgetwifi) and for network OTA (ArduinoOTA). These used
// to be wide open to anyone who could reach the device on the LAN — pick real
// values here, ideally not the same as your WiFi password. You can also leave the
// placeholders: the setup portal then asks for an admin password, stored on the
// device, which replaces both WEB_PASS and OTA_PASS (changeable on the dashboard).
static const char* WEB_USER = "admin";
static const char* WEB_PASS = "CHANGE_ME_WEB_PASSWORD";
static const char* OTA_PASS = "CHANGE_ME_OTA_PASSWORD";
