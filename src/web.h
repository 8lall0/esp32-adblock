#pragma once
// Dashboard at http://c3adblock.local : per-client stats, system info, lists, upstreams,
// blocklist/firmware updates. The setup portal shares the same server object.
#include <Arduino.h>
#include <WebServer.h>

extern WebServer web;

String htmlEscape(const String& s);
void webBegin();                           // registers the dashboard routes and starts the server
