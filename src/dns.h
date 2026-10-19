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
void dnsWait(uint32_t ms);                 // idle sleep that ends early when a packet arrives
String dnsDebugJson();                     // per-reason counters + the last queries and why
extern uint32_t dotFallbacks;              // queries sent as plain DNS while DoT was enabled
// For the DoT task (thread-safe): an answer for a UDP client / a whole answer for TCP client slot.
void dnsInjectReply(const uint8_t* data, int len, uint32_t fromIp);
void dnsTcpReply(int slot, uint16_t wid, uint8_t* data, int len);   // takes ownership of data
