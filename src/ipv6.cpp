#include "ipv6.h"
#include <WiFi.h>
#include <LittleFS.h>
#include <IPv6Address.h>
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/tcpip.h"
#include "lwip/raw.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "clients.h"

static const char* IPV6_CFG = "/ipv6.cfg";
static const uint32_t RA_INTERVAL_MS = 300000;     // re-announce every 5 min ...
static const uint32_t RDNSS_LIFETIME_S = 900;      // ... valid for 15 min (RFC 8106: >= 2x interval)
bool raEnabled = false;
static uint32_t lastRaMs = 0;
static volatile bool raSent = false;               // last announce() actually went out
static const uint32_t RA_RETRY_MS = 5000;          // until then (e.g. link-local still in DAD)
static struct raw_pcb* raPcb = nullptr;

static esp_netif_t* staNetif() { return esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"); }

void ipv6Begin() {
  WiFi.enableIpV6();                               // link-local now; SLAAC adds global ones if the LAN has a prefix
  if (LittleFS.exists(IPV6_CFG)) {
    File f = LittleFS.open(IPV6_CFG, "r");
    if (f) { raEnabled = f.readStringUntil('\n').toInt() == 1; f.close(); }
  }
}

String ipv6AddrsJson() {
  esp_ip6_addr_t a[LWIP_IPV6_NUM_ADDRESSES];
  int n = staNetif() ? esp_netif_get_all_ip6(staNetif(), a) : 0;
  String j = "[";
  for (int i = 0; i < n; i++) { j += (i ? ",\"" : "\""); j += ip6Str((const uint8_t*)a[i].addr); j += "\""; }
  return j + "]";
}

// Runs in the lwIP thread (tcpip_callback): the raw API isn't thread-safe without core locking.
static void sendRa(void* arg) {
  const uint32_t lifetime = (uint32_t)(uintptr_t)arg;
  struct netif* nif = staNetif() ? (struct netif*)esp_netif_get_netif_impl(staNetif()) : nullptr;
  if (!nif || !ip6_addr_isvalid(netif_ip6_addr_state(nif, 0))) return;   // no link-local yet
  // Advertise a global address if SLAAC gave us one, else the link-local (like most routers).
  int dnsIdx = 0;
  for (int i = 1; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    if (ip6_addr_isvalid(netif_ip6_addr_state(nif, i)) && !ip6_addr_islinklocal(netif_ip6_addr(nif, i))) { dnsIdx = i; break; }
  if (!raPcb) {
    raPcb = raw_new_ip_type(IPADDR_TYPE_V6, IP6_NEXTH_ICMP6);
    if (!raPcb) return;
    raPcb->chksum_reqd = 1; raPcb->chksum_offset = 2;          // ICMPv6 checksum over the pseudo-header
    raPcb->ttl = 255; raw_set_multicast_ttl(raPcb, 255);       // RFC 4861: receivers drop RAs with hop limit != 255
  }
  uint8_t m[16 + 24 + 8] = {};
  m[0] = 134;                                      // Router Advertisement; hop limit, flags, router lifetime, timers all 0
  uint8_t* o = m + 16;                             // RDNSS (RFC 8106)
  o[0] = 25; o[1] = 3;
  o[4] = lifetime >> 24; o[5] = lifetime >> 16; o[6] = lifetime >> 8; o[7] = lifetime;
  memcpy(o + 8, netif_ip6_addr(nif, dnsIdx)->addr, 16);
  o = m + 40;                                      // source link-layer address
  o[0] = 1; o[1] = 1; memcpy(o + 2, nif->hwaddr, 6);
  struct pbuf* p = pbuf_alloc(PBUF_IP, sizeof(m), PBUF_RAM); if (!p) return;
  memcpy(p->payload, m, sizeof(m));
  ip_addr_t dst, src;
  IP_ADDR6(&dst, PP_HTONL(0xff020000UL), 0, 0, PP_HTONL(0x00000001UL));   // all-nodes
  ip6_addr_assign_zone(ip_2_ip6(&dst), IP6_MULTICAST, nif);
  ip_addr_copy_from_ip6(src, *netif_ip6_addr(nif, 0));                       // RFC 4861: link-local source
  raSent = raw_sendto_if_src(raPcb, p, &dst, nif, &src) == ERR_OK;
  pbuf_free(p);
}
static void announce(uint32_t lifetime) { raSent = false; tcpip_callback(sendRa, (void*)(uintptr_t)lifetime); }

void setRaEnabled(bool on) {
  if (raEnabled && !on) announce(0);               // lifetime 0 withdraws the server from clients
  raEnabled = on; lastRaMs = 0;
  File f = LittleFS.open(IPV6_CFG, "w"); if (f) { f.println(on ? 1 : 0); f.close(); }
}

void ipv6Tick() {
  if (!raEnabled) return;
  const uint32_t now = millis();
  if (lastRaMs && now - lastRaMs < (raSent ? RA_INTERVAL_MS : RA_RETRY_MS)) return;
  lastRaMs = now ? now : 1;
  announce(RDNSS_LIFETIME_S);
}
