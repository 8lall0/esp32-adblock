#pragma once
// DNS front end (IPv4 + IPv6): receives queries, answers blocked ones locally, serves cached answers and
// forwards the rest to the upstream resolvers (with failover).
#include <Arduino.h>

extern uint32_t totalBlocked, totalAllowed;
extern uint32_t upstream[2];               // IPv4, [1] = 0: no secondary
extern int upActive;                       // index of the upstream queries go to first

// Pi-hole-style "disable for a while"
extern bool     blockingOn;
extern uint32_t resumeAt;                  // millis() to auto-resume; 0 = indefinitely / not paused

void loadUpstreams();
void setUpstreams(uint32_t primary, uint32_t secondary);   // saves to flash
void dnsBegin();                           // opens the sockets; call once WiFi is up
bool handleDns();                          // drains queued packets; true if it did work
String dnsDebugJson();                     // per-reason counters + the last queries and why
