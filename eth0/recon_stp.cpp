// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_stp.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "eth_frame.h"
#include "ids.h"

// ── Storage for the externs in recon_stp.h ──

StpBridge stpTable[STP_BRIDGE_TABLE_SIZE];
uint8_t   stpBridgeCount   = 0;
bool      stpMonitorEnabled = false;  // passive monitoring

void stpInitTable() {
  memset(stpTable, 0, sizeof(stpTable));
  stpBridgeCount = 0;
}

void stpCheckBpdu(const uint8_t* pkt, uint16_t len) {
  // Minimum: ETH(14) + LLC(3) + BPDU(4 for TCN, 35 for Config)
  if (len < ETH_HEADER_LEN + 3 + 4)
    return;

  // Check destination MAC is STP multicast 01:80:C2:00:00:00
  if (pkt[0] != 0x01 || pkt[1] != 0x80 || pkt[2] != 0xC2 || pkt[3] != 0x00 || pkt[4] != 0x00 ||
      pkt[5] != 0x00)
    return;

  // Check LLC header (DSAP=0x42, SSAP=0x42, Control=0x03)
  const uint8_t* llc = pkt + ETH_HEADER_LEN;
  if (llc[0] != STP_LLC_DSAP || llc[1] != STP_LLC_SSAP || llc[2] != STP_LLC_CTRL)
    return;

  const uint8_t* bpdu = llc + 3;
  uint16_t bpduLen = len - ETH_HEADER_LEN - 3;

  // Protocol ID must be 0x0000
  if (bpduLen < 4)
    return;
  uint16_t protoID = pktRead16(bpdu);
  if (protoID != 0x0000)
    return;

  uint8_t version = bpdu[2];
  uint8_t type = bpdu[3];

  // TCN BPDU (type 0x80) — just a topology change notification, no bridge info
  if (type == 0x80) {
    if (stpMonitorEnabled) {
      Serial.printf("[STP] TCN BPDU from %02X:%02X:%02X:%02X:%02X:%02X\n", pkt[6], pkt[7], pkt[8],
                    pkt[9], pkt[10], pkt[11]);
    }
    return;
  }

  // Config BPDU (type 0x00) or RST BPDU (type 0x02) — need at least 35 bytes
  if (bpduLen < 35)
    return;

  uint8_t flags = bpdu[4];

  // Root Bridge ID: bytes 5-12 (priority 2 bytes + MAC 6 bytes)
  uint16_t rootPriority = pktRead16(bpdu + 5);
  const uint8_t* rootMAC = bpdu + 7;

  // Root Path Cost: bytes 13-16
  uint32_t rootPathCost = pktRead32(bpdu + 13);

  // Bridge ID: bytes 17-24 (priority 2 bytes + MAC 6 bytes)
  uint16_t bridgePriority = pktRead16(bpdu + 17);
  const uint8_t* bridgeMAC = bpdu + 19;

  // Port ID: bytes 25-26
  uint16_t portID = pktRead16(bpdu + 25);

  // Timers (in 1/256 seconds): message age, max age, hello, forward delay
  uint16_t messageAge = pktRead16(bpdu + 27);
  uint16_t maxAge = pktRead16(bpdu + 29);
  uint16_t helloTime = pktRead16(bpdu + 31);
  uint16_t forwardDelay = pktRead16(bpdu + 33);

  // Live monitoring output
  if (stpMonitorEnabled) {
    const char* verStr = (version == 0) ? "STP" : (version == 2) ? "RSTP" : "MSTP";
    bool isRoot = (memcmp(rootMAC, bridgeMAC, 6) == 0 && rootPriority == bridgePriority);
    Serial.printf(
        "[STP] %s BPDU: bridge=%04X:%02X:%02X:%02X:%02X:%02X:%02X "
        "root=%04X:%02X:%02X:%02X:%02X:%02X:%02X cost=%u port=0x%04X%s\n",
        verStr, bridgePriority, bridgeMAC[0], bridgeMAC[1], bridgeMAC[2], bridgeMAC[3],
        bridgeMAC[4], bridgeMAC[5], rootPriority, rootMAC[0], rootMAC[1], rootMAC[2], rootMAC[3],
        rootMAC[4], rootMAC[5], rootPathCost, portID, isRoot ? " [ROOT]" : "");
  }

  // Update bridge table
  int slot = -1;
  int freeSlot = -1;
  int oldestSlot = 0;
  uint32_t oldestTime = UINT32_MAX;

  for (int i = 0; i < STP_BRIDGE_TABLE_SIZE; i++) {
    if (!stpTable[i].active) {
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    // Match by bridge MAC + port ID (same bridge may have multiple ports)
    if (memcmp(stpTable[i].bridgeMAC, bridgeMAC, 6) == 0 && stpTable[i].portID == portID) {
      slot = i;
      break;
    }
    if (stpTable[i].lastSeen < oldestTime) {
      oldestTime = stpTable[i].lastSeen;
      oldestSlot = i;
    }
  }

  if (slot < 0) {
    slot = (freeSlot >= 0) ? freeSlot : oldestSlot;
    if (!stpTable[slot].active)
      stpBridgeCount++;
  }

  StpBridge& b = stpTable[slot];
  b.active = true;
  memcpy(b.bridgeMAC, bridgeMAC, 6);
  b.bridgePriority = bridgePriority;
  memcpy(b.rootMAC, rootMAC, 6);
  b.rootPriority = rootPriority;
  b.rootPathCost = rootPathCost;
  b.portID = portID;
  b.stpVersion = version;
  b.flags = flags;
  b.messageAge = messageAge;
  b.maxAge = maxAge;
  b.helloTime = helloTime;
  b.forwardDelay = forwardDelay;
  b.lastSeen = millis();
}

void stpPrintTopology() {
  if (stpBridgeCount == 0) {
    Serial.println("[STP] No bridges discovered yet.");
    Serial.println("  BPDUs are passively captured in promiscuous mode.");
    Serial.println("  Wait for STP hello interval (~2s) or use: recon stp on");
    return;
  }

  // Find the root bridge (lowest root priority + MAC combo, with path cost 0)
  int rootIdx = -1;
  for (int i = 0; i < STP_BRIDGE_TABLE_SIZE; i++) {
    if (!stpTable[i].active)
      continue;
    if (stpTable[i].rootPathCost == 0 &&
        memcmp(stpTable[i].bridgeMAC, stpTable[i].rootMAC, 6) == 0) {
      rootIdx = i;
      break;
    }
  }

  Serial.println("[STP] ═══ Spanning Tree Topology ═══");
  Serial.println();

  // Print root bridge
  if (rootIdx >= 0) {
    StpBridge& r = stpTable[rootIdx];
    const char* verStr = (r.stpVersion == 0) ? "STP" : (r.stpVersion == 2) ? "RSTP" : "MSTP";
    Serial.printf("  ROOT BRIDGE (%s):\n", verStr);
    Serial.printf("    Bridge ID:  %04X.%02X:%02X:%02X:%02X:%02X:%02X\n", r.bridgePriority,
                  r.bridgeMAC[0], r.bridgeMAC[1], r.bridgeMAC[2], r.bridgeMAC[3], r.bridgeMAC[4],
                  r.bridgeMAC[5]);
    Serial.printf("    Timers:     hello=%us  maxAge=%us  fwdDelay=%us\n", r.helloTime / 256,
                  r.maxAge / 256, r.forwardDelay / 256);
    Serial.printf("    Seen:       %us ago\n", (millis() - r.lastSeen) / 1000);
    Serial.println();
  } else {
    Serial.println("  ROOT BRIDGE: (not directly seen — may be multiple hops away)");
    // Show root from first entry
    for (int i = 0; i < STP_BRIDGE_TABLE_SIZE; i++) {
      if (!stpTable[i].active)
        continue;
      Serial.printf("    Root ID:    %04X.%02X:%02X:%02X:%02X:%02X:%02X (via bridge reports)\n",
                    stpTable[i].rootPriority, stpTable[i].rootMAC[0], stpTable[i].rootMAC[1],
                    stpTable[i].rootMAC[2], stpTable[i].rootMAC[3], stpTable[i].rootMAC[4],
                    stpTable[i].rootMAC[5]);
      break;
    }
    Serial.println();
  }

  // Print all bridges
  Serial.println("  BRIDGES:");
  Serial.println("  ──────────────────────────────────────────────────────────────");
  Serial.printf("  %-6s %-22s %-8s %-8s %-6s %s\n", "Ver", "Bridge ID", "Cost", "Port", "Flags",
                "Seen");
  Serial.println("  ──────────────────────────────────────────────────────────────");

  for (int i = 0; i < STP_BRIDGE_TABLE_SIZE; i++) {
    if (!stpTable[i].active)
      continue;
    StpBridge& b = stpTable[i];

    const char* verStr = (b.stpVersion == 0) ? "STP" : (b.stpVersion == 2) ? "RSTP" : "MSTP";
    bool isRoot = (b.rootPathCost == 0 && memcmp(b.bridgeMAC, b.rootMAC, 6) == 0);

    // Decode RSTP flags for port role
    const char* roleStr = "";
    if (b.stpVersion >= 2) {
      uint8_t role = (b.flags >> 2) & 0x03;
      switch (role) {
        case 0:
          roleStr = "Unkn";
          break;
        case 1:
          roleStr = "Alt ";
          break;
        case 2:
          roleStr = "Root";
          break;
        case 3:
          roleStr = "Desg";
          break;
      }
    }
    bool tc = (b.flags & 0x01) != 0;   // Topology Change
    bool tca = (b.flags & 0x80) != 0;  // TC Acknowledgment

    char flagStr[16];
    snprintf(flagStr, sizeof(flagStr), "%s%s%s", roleStr, tc ? " TC" : "", tca ? " TCA" : "");

    Serial.printf("  %-6s %04X.%02X:%02X:%02X:%02X:%02X:%02X  %-8u 0x%04X %-6s %us%s\n", verStr,
                  b.bridgePriority, b.bridgeMAC[0], b.bridgeMAC[1], b.bridgeMAC[2], b.bridgeMAC[3],
                  b.bridgeMAC[4], b.bridgeMAC[5], b.rootPathCost, b.portID, flagStr,
                  (millis() - b.lastSeen) / 1000, isRoot ? " [ROOT]" : "");
  }

  Serial.printf("\n  %u bridge(s) tracked\n", stpBridgeCount);
}
