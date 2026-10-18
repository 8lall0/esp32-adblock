#pragma once
// Per-client stats and bans, keyed by IPv4 or IPv6 address.
#include <Arduino.h>

struct Addr { bool v6; uint8_t b[16]; };   // IPv4 uses b[0..3] in network order
Addr addrV4(uint32_t ip);                  // ip as stored by IPAddress (network order)
bool addrEq(const Addr& a, const Addr& b);
String addrStr(const Addr& a);
String ip6Str(const uint8_t b[16]);        // compressed form (fe80::1)
bool addrParse(const String& s, Addr& out);

struct Dev { Addr addr; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
extern Dev clients[MAX_CLIENTS];
extern int numClients;
extern int numBanned;

Dev* getClient(const Addr& a);             // finds or adds; nullptr when the table is full
void loadBanned();
void saveBanned();                         // persists the banned flags of the client table
