#include "clients.h"
#include <LittleFS.h>
#include <IPv6Address.h>
#include "lwip/ip6_addr.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"

Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_BAN = 32;
static Addr bannedAddr[MAX_BAN]; int numBanned = 0;

Addr addrV4(uint32_t ip) { Addr a = {}; memcpy(a.b, &ip, 4); return a; }
bool addrEq(const Addr& a, const Addr& b) { return a.v6 == b.v6 && memcmp(a.b, b.b, a.v6 ? 16 : 4) == 0; }
String addrStr(const Addr& a) {
  if (!a.v6) { uint32_t ip; memcpy(&ip, a.b, 4); return IPAddress(ip).toString(); }
  return ip6Str(a.b);
}
String ip6Str(const uint8_t b[16]) {
  ip6_addr_t a = {}; memcpy(a.addr, b, 16);
  char s[IP6ADDR_STRLEN_MAX];
  String r(ip6addr_ntoa_r(&a, s, sizeof(s))); r.toLowerCase();    // lwIP prints upper case
  return r;
}
bool addrParse(const String& s, Addr& out) {
  out = {};
  if (s.indexOf(':') < 0) { IPAddress ip; if (!ip.fromString(s)) return false; out = addrV4((uint32_t)ip); return true; }
  ip6_addr_t ip6;                                  // IPv6Address::fromString only takes the 39-char form
  if (!ip6addr_aton(s.c_str(), &ip6)) return false;
  out.v6 = true; memcpy(out.b, ip6.addr, 16); return true;
}

static bool isBanned(const Addr& a) { for (int i = 0; i < numBanned; i++) if (addrEq(bannedAddr[i], a)) return true; return false; }
void loadBanned() {
  numBanned = 0; if (!LittleFS.exists("/banned.txt")) return;
  File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); if (l.length() && addrParse(l, bannedAddr[numBanned])) numBanned++; }
  f.close();
}
void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedAddr[numBanned++] = clients[i].addr;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) f.println(addrStr(bannedAddr[i]));
  f.close();
}

// IPv4: ARP table. IPv6: only EUI-64 addresses carry the MAC (ff:fe in the middle, U/L bit
// flipped); privacy addresses are random, so those clients show no MAC.
static void getMac(const Addr& a, uint8_t* mac) {
  memset(mac, 0, 6);
  if (a.v6) {
    const uint8_t* b = a.b;
    if (b[11] == 0xff && b[12] == 0xfe) { mac[0] = b[8] ^ 0x02; mac[1] = b[9]; mac[2] = b[10]; mac[3] = b[13]; mac[4] = b[14]; mac[5] = b[15]; }
    return;
  }
  ip4_addr_t ipa; memcpy(&ipa.addr, a.b, 4);
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
// ---------- names set by hand (persisted by MAC, or by address when there's no MAC) ----------
static const char* NAMES_PATH = "/names.txt";
static const int MAX_NAMES = 64;
struct SavedName { String key, name; };
static SavedName savedNames[MAX_NAMES]; static int numNames = 0;

bool hasMac(const Dev& c) { for (int i = 0; i < 6; i++) if (c.mac[i]) return true; return false; }
static String macKey(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String nameKey(const Dev& c) { return hasMac(c) ? macKey(c.mac) : addrStr(c.addr); }
void loadNames() {
  numNames = 0; if (!LittleFS.exists(NAMES_PATH)) return;
  File f = LittleFS.open(NAMES_PATH, "r"); if (!f) return;
  while (f.available() && numNames < MAX_NAMES) {
    String l = f.readStringUntil('\n'); l.trim();
    int sp = l.indexOf(' '); if (sp <= 0) continue;
    savedNames[numNames].key = l.substring(0, sp); savedNames[numNames].name = l.substring(sp + 1); numNames++;
  }
  f.close();
}
static void saveNames() {
  File f = LittleFS.open(NAMES_PATH, "w"); if (!f) return;
  for (int i = 0; i < numNames; i++) { f.print(savedNames[i].key); f.print(' '); f.println(savedNames[i].name); }
  f.close();
}
static void applySavedName(Dev& c) {
  const String k = nameKey(c);
  for (int i = 0; i < numNames; i++) if (savedNames[i].key == k) { c.name = savedNames[i].name; c.manualName = true; return; }
}
void setManualName(Dev& c, String name) {
  name.trim(); if (name.length() > 31) name = name.substring(0, 31);
  const String k = nameKey(c);
  int at = -1; for (int i = 0; i < numNames; i++) if (savedNames[i].key == k) at = i;
  if (name.length()) {
    if (at < 0 && numNames < MAX_NAMES) at = numNames++;
    if (at >= 0) { savedNames[at].key = k; savedNames[at].name = name; }
  } else if (at >= 0) {
    savedNames[at] = savedNames[--numNames];
  }
  saveNames();
  for (int i = 0; i < numClients; i++) {           // every entry of that machine (IPv4 + IPv6)
    Dev& d = clients[i];
    if (nameKey(d) != k) continue;
    if (name.length()) { d.name = name; d.manualName = true; }
    else { d.name = ""; d.manualName = false; d.nameState = 0; }   // ask the router again
  }
}
String displayName(const Dev& c) {
  if (c.name.length() || !hasMac(c)) return c.name;
  for (int i = 0; i < numClients; i++)
    if (&clients[i] != &c && clients[i].name.length() && !memcmp(clients[i].mac, c.mac, 6)) return clients[i].name;
  return "";
}

Dev* findClient(const Addr& a) {
  for (int i = 0; i < numClients; i++) if (addrEq(clients[i].addr, a)) return &clients[i];
  return nullptr;
}
Dev* getClient(const Addr& a) {
  if (Dev* c = findClient(a)) { c->lastSeen = millis(); return c; }
  Dev* c = nullptr;
  if (numClients < MAX_CLIENTS) c = &clients[numClients++];
  else {                                           // full: reuse the longest-idle entry that isn't banned
    const uint32_t now = millis(); uint32_t idle = 0;
    for (int i = 0; i < numClients; i++)
      if (!clients[i].banned && now - clients[i].lastSeen >= idle) { idle = now - clients[i].lastSeen; c = &clients[i]; }
    if (!c) return nullptr;
  }
  *c = Dev();
  c->addr = a; c->lastSeen = millis(); c->banned = isBanned(a);
  getMac(a, c->mac); applySavedName(*c);
  return c;
}
