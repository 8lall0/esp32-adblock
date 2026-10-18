#pragma once
// Per-client stats and bans, keyed by IPv4 address.
#include <Arduino.h>

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
extern Dev clients[MAX_CLIENTS];
extern int numClients;
extern int numBanned;

Dev* getClient(uint32_t ip);               // finds or adds; nullptr when the table is full
void loadBanned();
void saveBanned();                         // persists the banned flags of the client table
