#pragma once
// DNS-over-TLS to the upstream resolvers (RFC 7858). Plain DNS on port 53 lets the ISP (or
// anyone on the path) read and alter every lookup; with DoT the device keeps one verified TLS
// connection to the active upstream and sends forwarded queries through it.
#include <Arduino.h>

extern bool dotEnabled, dotStrict;         // strict: never fall back to plain DNS
extern String dotName[2];                  // TLS hostname per upstream ("" = known default)

void dotBegin();                           // loads /dot.cfg and starts the DoT task
void setDot(bool on, bool strict, const String& name0, const String& name1);   // saves
bool dotUsable();                          // enabled and not backing off after a failure
// Queues a query (its DNS id must be wid). tcpSlot >= 0: the answer goes back whole to that
// TCP client connection (dnsTcpReply), else into the normal reply path (UDP clients).
bool dotSend(const uint8_t* q, int len, uint16_t wid, int tcpSlot);
String dotStatusJson();
String tlsNameFor(int idx);                // configured name, else the default for the IP
void dotPause(bool paused);                // during firmware updates (see dot.cpp)
void dotRestart();                         // upstream addresses changed
