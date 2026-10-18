#pragma once
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched, plus the user's
// custom-block and allow lists.
#include <Arduino.h>

static const int HASH_BYTES = 5;
extern uint32_t numHashes;                 // entries in the flash list, 0 = none (fail open)

uint64_t fnv40(const char* s, size_t n);
void openBlocklist();                      // at boot: open the flash list and build the index
bool blocklistInMemory();                  // list copied to PSRAM (else lookups read flash)
const char* blocklistMemState();           // why: "ok", "no psram", "no space", "read failed"
// Why a domain (or a parent suffix) is or isn't blocked; the allowlist wins over both lists.
enum BlockWhy : uint8_t { BW_NONE, BW_ALLOW, BW_CUSTOM, BW_LIST };
BlockWhy blockReason(const char* domain);

// User-managed domain lists, persisted one domain per line. Small enough to scan linearly.
static const int MAX_CUSTOM = 200;
struct DomList { const char* path; String dom[MAX_CUSTOM]; uint64_t hash[MAX_CUSTOM]; int n; };
extern DomList customList;                 // always blocked (plus subdomains)
extern DomList allowList;                  // never blocked (plus subdomains), overrides the blocklist
void loadList(DomList& L);
bool addToList(DomList& L, String d);
void removeFromList(DomList& L, String d);

// Replacing the list (browser upload and remote fetch). Write the incoming file to
// BLOCKLIST_NEW between beginBlocklistSwap() and commitNewBlocklist().
extern const char* BLOCKLIST_NEW;
bool beginBlocklistSwap(size_t expectBytes);   // returns true if the old list keeps serving
bool commitNewBlocklist(bool complete);        // validates BLOCKLIST_NEW and swaps it in
void reopenBlocklist();                        // after an aborted transfer
