// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "stats.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "eth_frame.h"
#include "pcap_writer.h"

StatsTalker statsTalkers[STATS_TALKER_TABLE];
bool        statsAutoEnabled  = false;
uint32_t    statsAutoInterval = STATS_INTERVAL_DEFAULT;
uint32_t    statsLastAuto     = 0;
uint32_t    statsWindowStart  = 0;
uint32_t    statsWindowPkts   = 0;
uint32_t    statsWindowBytes  = 0;
uint32_t    statsProtoTCP     = 0;
uint32_t    statsProtoUDP     = 0;
uint32_t    statsProtoICMP    = 0;
uint32_t    statsProtoARP     = 0;
uint32_t    statsProtoOther   = 0;

void statsTrackPacket(const uint8_t* pkt, uint16_t len) {
  statsWindowPkts++;
  statsWindowBytes += len;

  if (len < ETH_HEADER_LEN) {
    statsProtoOther++;
    return;
  }

  uint16_t etype = pktRead16(pkt + ETH_TYPE);

  if (etype == ETHERTYPE_ARP) {
    statsProtoARP++;
    return;
  }
  if (etype != ETHERTYPE_IPV4) {
    statsProtoOther++;
    return;
  }
  if (len < ETH_HEADER_LEN + 20) {
    statsProtoOther++;
    return;
  }

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  uint8_t proto = ipHdr[9];
  const uint8_t* srcIP = ipHdr + 12;

  switch (proto) {
    case IP_PROTO_TCP:
      statsProtoTCP++;
      break;
    case IP_PROTO_UDP:
      statsProtoUDP++;
      break;
    case IP_PROTO_ICMP:
      statsProtoICMP++;
      break;
    default:
      statsProtoOther++;
      break;
  }

  // Track source IP as talker
  int freeSlot = -1;
  for (int i = 0; i < STATS_TALKER_TABLE; i++) {
    if (!statsTalkers[i].active) {
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    if (memcmp(statsTalkers[i].ip, srcIP, 4) == 0) {
      statsTalkers[i].packets++;
      statsTalkers[i].bytes += len;
      return;
    }
  }
  // New talker
  if (freeSlot >= 0) {
    statsTalkers[freeSlot].active = true;
    memcpy(statsTalkers[freeSlot].ip, srcIP, 4);
    statsTalkers[freeSlot].packets = 1;
    statsTalkers[freeSlot].bytes = len;
  }
}

void statsPrint() {
  uint32_t elapsed = millis() - statsWindowStart;
  if (elapsed == 0)
    elapsed = 1;

  float pps = (float)statsWindowPkts * 1000.0f / elapsed;
  float bps = (float)statsWindowBytes * 8000.0f / elapsed;  // bits per sec

  Serial.println();
  Serial.println("[STATS] ═══ Packet Statistics ═══");
  Serial.printf("  Window:   %.1f seconds\n", elapsed / 1000.0f);
  Serial.printf("  Packets:  %u (%.1f pkt/s)\n", statsWindowPkts, pps);

  // Format bandwidth nicely
  if (bps >= 1000000.0f)
    Serial.printf("  Traffic:  %u bytes (%.2f Mbps)\n", statsWindowBytes, bps / 1000000.0f);
  else if (bps >= 1000.0f)
    Serial.printf("  Traffic:  %u bytes (%.1f Kbps)\n", statsWindowBytes, bps / 1000.0f);
  else
    Serial.printf("  Traffic:  %u bytes (%.0f bps)\n", statsWindowBytes, bps);

  // Protocol breakdown
  uint32_t total = statsProtoTCP + statsProtoUDP + statsProtoICMP + statsProtoARP + statsProtoOther;
  if (total == 0)
    total = 1;
  Serial.println("  ── Protocol Breakdown ──");
  if (statsProtoTCP)
    Serial.printf("    TCP:   %u (%u%%)\n", statsProtoTCP, statsProtoTCP * 100 / total);
  if (statsProtoUDP)
    Serial.printf("    UDP:   %u (%u%%)\n", statsProtoUDP, statsProtoUDP * 100 / total);
  if (statsProtoICMP)
    Serial.printf("    ICMP:  %u (%u%%)\n", statsProtoICMP, statsProtoICMP * 100 / total);
  if (statsProtoARP)
    Serial.printf("    ARP:   %u (%u%%)\n", statsProtoARP, statsProtoARP * 100 / total);
  if (statsProtoOther)
    Serial.printf("    Other: %u (%u%%)\n", statsProtoOther, statsProtoOther * 100 / total);

  // Top talkers (sort by packets, show top N)
  // Simple selection of top N from the table
  Serial.println("  ── Top Talkers ──");
  bool printed[STATS_TALKER_TABLE] = {false};
  int shown = 0;

  for (int n = 0; n < STATS_TOP_TALKERS; n++) {
    int best = -1;
    uint32_t bestPkts = 0;
    for (int i = 0; i < STATS_TALKER_TABLE; i++) {
      if (!statsTalkers[i].active || printed[i])
        continue;
      if (statsTalkers[i].packets > bestPkts) {
        bestPkts = statsTalkers[i].packets;
        best = i;
      }
    }
    if (best < 0)
      break;
    printed[best] = true;
    shown++;

    StatsTalker& t = statsTalkers[best];
    Serial.printf("    %u.%u.%u.%u  %u pkts  %u bytes\n", t.ip[0], t.ip[1], t.ip[2], t.ip[3],
                  t.packets, t.bytes);
  }
  if (shown == 0)
    Serial.println("    (no traffic)");

  // System info
  Serial.printf("  ── Capture ──\n");
  Serial.printf("    Saved: %u | Filtered: %u | Sent: %u | Alerts: %u\n", packetCount, droppedCount,
                txCount, alertCount);
  Serial.printf("    File: capture_%04u.pcap | Free heap: %u bytes\n", fileIndex,
                ESP.getFreeHeap());
  Serial.println();
}

void parseStatsCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (*cmd == '\0') {
    statsPrint();
  } else if (strncmp(cmd, "auto", 4) == 0) {
    cmd += 4;
    while (*cmd == ' ')
      cmd++;

    if (*cmd != '\0') {
      int sec = atoi(cmd);
      if (sec > 0)
        statsAutoInterval = (uint32_t)sec * 1000;
    }

    statsAutoEnabled = true;
    statsLastAuto = millis();
    Serial.printf("[STATS] Auto-print every %u seconds\n", statsAutoInterval / 1000);
  } else if (strncmp(cmd, "off", 3) == 0) {
    statsAutoEnabled = false;
    Serial.println("[STATS] Auto-print disabled");
  } else if (strncmp(cmd, "reset", 5) == 0) {
    statsReset();
    Serial.println("[STATS] Counters reset");
  } else {
    Serial.println("[STATS] Commands:");
    Serial.println("  stats          - show current stats");
    Serial.println("  stats auto [s] - auto-print every N seconds (default 5)");
    Serial.println("  stats off      - stop auto-print");
    Serial.println("  stats reset    - reset all counters");
  }
}

void statsReset() {
  memset(statsTalkers, 0, sizeof(statsTalkers));
  statsWindowStart = millis();
  statsWindowPkts = 0;
  statsWindowBytes = 0;
  statsProtoTCP = 0;
  statsProtoUDP = 0;
  statsProtoICMP = 0;
  statsProtoARP = 0;
  statsProtoOther = 0;
}
