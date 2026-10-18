#pragma once
// Per-client stats, names and bans, keyed by IPv4 or IPv6 address.
#include <Arduino.h>

struct Addr { bool v6; uint8_t b[16]; };   // IPv4 uses b[0..3] in network order
Addr addrV4(uint32_t ip);                  // ip as stored by IPAddress (network order)
bool addrEq(const Addr& a, const Addr& b);
String addrStr(const Addr& a);
String ip6Str(const uint8_t b[16]);        // compressed form (fe80::1)
bool addrParse(const String& s, Addr& out);

// name: set by hand on the dashboard (manualName, saved by MAC) or learned from the router's
// reverse DNS (nameState: 0 = not asked yet, 1 = asked, 2 = answered or gave up at nameAt).
struct Dev {
  Addr addr; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned;
  String name; bool manualName; uint8_t nameState; uint32_t nameAt;
};
static const int MAX_CLIENTS = 96;
extern Dev clients[MAX_CLIENTS];
extern int numClients;
extern int numBanned;

Dev* getClient(const Addr& a);             // finds or adds (replacing the longest-idle one when full)
Dev* findClient(const Addr& a);            // finds only
bool hasMac(const Dev& c);
String displayName(const Dev& c);          // own name, else the name of another entry with the same MAC
void setManualName(Dev& c, String name);   // "" = back to the automatic name; saved to flash
void loadBanned();
void saveBanned();                         // persists the banned flags of the client table
void loadNames();
