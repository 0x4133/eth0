// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "ip_util.h"

#include <stdio.h>

#include <Arduino.h>

bool parseMAC(const char* str, uint8_t* out) {
  unsigned int vals[6];
  if (sscanf(str, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4],
             &vals[5]) == 6 ||
      sscanf(str, "%x-%x-%x-%x-%x-%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4],
             &vals[5]) == 6) {
    for (int i = 0; i < 6; i++) {
      if (vals[i] > 255)
        return false;
      out[i] = (uint8_t)vals[i];
    }
    return true;
  }
  return false;
}

bool parseIP(const char* str, uint8_t* out) {
  unsigned int vals[4];
  if (sscanf(str, "%u.%u.%u.%u", &vals[0], &vals[1], &vals[2], &vals[3]) == 4) {
    for (int i = 0; i < 4; i++) {
      if (vals[i] > 255)
        return false;
      out[i] = (uint8_t)vals[i];
    }
    return true;
  }
  return false;
}

void printMAC(const uint8_t* addr) {
  for (int i = 0; i < 6; i++) {
    if (i > 0)
      Serial.print(":");
    if (addr[i] < 0x10)
      Serial.print("0");
    Serial.print(addr[i], HEX);
  }
}

void printIP(const uint8_t* addr) {
  Serial.printf("%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}
