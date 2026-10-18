#pragma once
// TTL-aware cache of upstream DNS answers. All functions work on a DNS message in msg.
#include <Arduino.h>

extern uint32_t cacheHits;
extern int cacheSlots;                     // 0 = cache disabled (allocation failed)

void initAnswerCache();
uint64_t answerKey(const uint8_t* msg, int qlen, int qend);    // 0 = not cacheable
void cacheStore(const uint8_t* msg, uint64_t key, int n, int ql);
int cacheAnswer(uint8_t* msg, uint64_t key, int qend);         // rewrites msg on a hit, returns its length
