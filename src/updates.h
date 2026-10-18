#pragma once
// Remote blocklist auto-update: pulls a prebuilt blocklist.bin (e.g. a GitHub release asset).
#include <Arduino.h>

extern String updateUrl;                   // "" = auto-update off
extern uint32_t updateIntervalH;           // hours between auto-fetches
extern String updateStatus;                // shown on the dashboard

void loadUpdateCfg();
void saveUpdateCfg();
bool fetchBlocklist(String url);           // blocking, but keeps answering DNS meanwhile
void updatesTick();                        // call from loop(): runs the schedule
