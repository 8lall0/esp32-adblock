#pragma once
// IPv6 on the station interface: addresses, plus optionally announcing the device as an IPv6
// DNS server (Router Advertisement carrying only an RDNSS option, router lifetime 0, so clients
// add it to their DNS servers without ever routing through it).
#include <Arduino.h>

extern bool raEnabled;

void ipv6Begin();                          // after WiFi is connected
String ipv6AddrsJson();                    // ["fe80::...", "2001:..."]
void setRaEnabled(bool on);                // saves to flash; off sends a withdrawal
void ipv6Tick();                           // call from loop(): periodic announcements
