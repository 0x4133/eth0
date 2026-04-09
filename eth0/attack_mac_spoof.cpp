// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "attack_mac_spoof.h"

#include <string.h>

#include <Arduino.h>
#include <Ethernet2.h>
#include <esp_random.h>

#include "config.h"
#include "ip_util.h"
#include "state.h"

uint8_t  originalMAC[6];
bool     macAutoEnabled    = false;
uint32_t macAutoIntervalMs = 30000;
uint32_t macAutoLastRotate = 0;

void macSet(const uint8_t* newMAC) {
  memcpy(mac, newMAC, 6);
  // Ensure locally-administered bit is set (bit 1 of first octet)
  // and multicast bit is cleared (bit 0 of first octet)
  // unless setting back to original
  w5500.setMACAddress(mac);
  Serial.printf("[MAC] Set to %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3],
                mac[4], mac[5]);
}

void macRandom() {
  uint8_t newMAC[6];
  for (int i = 0; i < 6; i++)
    newMAC[i] = (uint8_t)esp_random();
  newMAC[0] = (newMAC[0] & 0xFC) | 0x02;  // locally administered, unicast
  macSet(newMAC);
}

void macReset() {
  memcpy(mac, originalMAC, 6);
  w5500.setMACAddress(mac);
  macAutoEnabled = false;
  Serial.printf("[MAC] Restored to %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3],
                mac[4], mac[5]);
}

void parseMacCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "set ", 4) == 0) {
    uint8_t newMAC[6];
    if (parseMAC(cmd + 4, newMAC)) {
      macSet(newMAC);
    } else {
      Serial.println("[MAC] Invalid MAC. Use: mac set AA:BB:CC:DD:EE:FF");
    }
  } else if (strncmp(cmd, "random", 6) == 0) {
    macRandom();
  } else if (strncmp(cmd, "reset", 5) == 0) {
    macReset();
  } else if (strncmp(cmd, "auto", 4) == 0) {
    cmd += 4;
    while (*cmd == ' ')
      cmd++;
    if (strncmp(cmd, "off", 3) == 0) {
      macAutoEnabled = false;
      Serial.println("[MAC] Auto-rotate disabled");
    } else {
      int sec = atoi(cmd);
      if (sec < MAC_AUTO_MIN_SEC)
        sec = 30;
      macAutoIntervalMs = (uint32_t)sec * 1000;
      macAutoEnabled = true;
      macAutoLastRotate = millis();
      Serial.printf("[MAC] Auto-rotate every %d seconds\n", sec);
    }
  } else {
    Serial.printf("[MAC] Current: %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3],
                  mac[4], mac[5]);
    if (memcmp(mac, originalMAC, 6) != 0)
      Serial.print(" (spoofed)");
    if (macAutoEnabled)
      Serial.printf(" [auto: %us]", macAutoIntervalMs / 1000);
    Serial.println();
    Serial.println("  mac set XX:XX:XX:XX:XX:XX  - set specific MAC");
    Serial.println("  mac random                 - generate random MAC");
    Serial.println("  mac reset                  - restore original");
    Serial.println("  mac auto [sec]             - auto-rotate (default 30s)");
    Serial.println("  mac auto off               - stop auto-rotate");
  }
}
