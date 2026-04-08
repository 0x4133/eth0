// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "network_map.h"

#include <stdio.h>
#include <string.h>

#include <Arduino.h>

#include "arp_table.h"
#include "attack_tcp_rst.h"
#include "config.h"
#include "ids.h"
#include "recon_lldp.h"
#include "recon_mdns.h"
#include "recon_netbios.h"
#include "recon_os_fingerprint.h"
#include "recon_stp.h"
#include "state.h"
#include "stats.h"

// ══════════════════════════════════════════════════════════════
//  Network Map — Unified view of all discovered intelligence
// ══════════════════════════════════════════════════════════════

// Helper: format IP to string
static void ipToStr(const uint8_t* ip, char* out) {
  sprintf(out, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

// Helper: format MAC to string
static void macToStr(const uint8_t* m, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Helper: look up OS fingerprint for an IP
static const char* fpLookup(const uint8_t* ip) {
  for (int i = 0; i < FP_TABLE_SIZE; i++) {
    if (fpTable[i].active && memcmp(fpTable[i].ip, ip, 4) == 0)
      return fpTable[i].osGuess;
  }
  return NULL;
}

// Helper: look up mDNS hostname for an IP
static const char* mdnsLookup(const uint8_t* ip) {
  for (int i = 0; i < MDNS_TABLE_SIZE; i++) {
    if (mdnsTable[i].active && memcmp(mdnsTable[i].ip, ip, 4) == 0 && mdnsTable[i].hostname[0])
      return mdnsTable[i].hostname;
  }
  return NULL;
}

// Helper: look up NetBIOS name for an IP
static const char* netbiosLookup(const uint8_t* ip) {
  for (int i = 0; i < NETBIOS_TABLE_SIZE; i++) {
    if (netbiosTable[i].active && memcmp(netbiosTable[i].ip, ip, 4) == 0 && netbiosTable[i].name[0])
      return netbiosTable[i].name;
  }
  return NULL;
}

// Helper: look up NetBIOS workgroup for an IP
static const char* netbiosGroupLookup(const uint8_t* ip) {
  for (int i = 0; i < NETBIOS_TABLE_SIZE; i++) {
    if (netbiosTable[i].active && memcmp(netbiosTable[i].ip, ip, 4) == 0 &&
        netbiosTable[i].group[0])
      return netbiosTable[i].group;
  }
  return NULL;
}

// Helper: look up traffic stats for an IP
static bool statsLookup(const uint8_t* ip, uint32_t* pkts, uint32_t* bytes) {
  for (int i = 0; i < STATS_TALKER_TABLE; i++) {
    if (statsTalkers[i].active && memcmp(statsTalkers[i].ip, ip, 4) == 0) {
      *pkts = statsTalkers[i].packets;
      *bytes = statsTalkers[i].bytes;
      return true;
    }
  }
  return false;
}

// Helper: count active TCP connections for an IP
static int tcpConnCount(const uint8_t* ip) {
  int count = 0;
  for (int i = 0; i < TCP_CONN_TABLE_SIZE; i++) {
    if (!tcpConnTable[i].active)
      continue;
    if (memcmp(tcpConnTable[i].srcIP, ip, 4) == 0 || memcmp(tcpConnTable[i].dstIP, ip, 4) == 0)
      count++;
  }
  return count;
}

void printNetworkMap() {
  Serial.println();
  Serial.println("  ┌─────────────────────────────────────────────────────────────┐");
  Serial.println("  │                    eth0 — Network Map                        │");
  Serial.println("  └─────────────────────────────────────────────────────────────┘");

  // ── Our identity ──
  Serial.println();
  Serial.println("  THIS DEVICE");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  char ipStr[16], macStr[18];
  ipToStr(ourIP, ipStr);
  macToStr(mac, macStr);
  Serial.printf("    IP:      %s\n", ipStr);
  Serial.printf("    MAC:     %s", macStr);
  if (memcmp(mac, originalMAC, 6) != 0)
    Serial.print(" (spoofed)");
  Serial.println();
  ipToStr(ourGW, ipStr);
  Serial.printf("    Gateway: %s\n", ipStr);
  ipToStr(ourSubnet, ipStr);
  Serial.printf("    Subnet:  %s\n", ipStr);
  ipToStr(ourDNS, ipStr);
  Serial.printf("    DNS:     %s\n", ipStr);

  // Active attacks
  Serial.print("    Status:  ");
  bool anyActive = false;
  if (mitmActive) {
    Serial.print("MitM ");
    anyActive = true;
  }
  if (dnsSpoofEnabled) {
    Serial.print("DNS-Spoof ");
    anyActive = true;
  }
  if (poisonEnabled) {
    Serial.print("Poison ");
    anyActive = true;
  }
  if (dhcpStarveActive) {
    Serial.print("DHCP-Starve ");
    anyActive = true;
  }
  if (tunnelActive) {
    Serial.print("Tunnel ");
    anyActive = true;
  }
  if (!anyActive)
    Serial.print("Passive");
  Serial.println();

  // ── Infrastructure ──
  int lldpCount = 0;
  for (int i = 0; i < LLDP_TABLE_SIZE; i++)
    if (lldpTable[i].active)
      lldpCount++;

  if (lldpCount > 0 || stpBridgeCount > 0 || knownDhcpCount > 0) {
    Serial.println();
    Serial.println("  INFRASTRUCTURE");
    Serial.println("  ───────────────────────────────────────────────────────────────");

    // DHCP servers
    for (int i = 0; i < knownDhcpCount; i++) {
      ipToStr(knownDhcp[i].ip, ipStr);
      macToStr(knownDhcp[i].mac, macStr);
      Serial.printf("    [DHCP]   %s  %s%s\n", ipStr, macStr,
                    (i == 0) ? "  (trusted)" : "  (ROGUE!)");
    }

    // Switches (LLDP/CDP)
    for (int i = 0; i < LLDP_TABLE_SIZE; i++) {
      if (!lldpTable[i].active)
        continue;
      LldpNeighbor& n = lldpTable[i];
      macToStr(n.srcMAC, macStr);
      Serial.printf("    [%s]  %s  %s", n.isCDP ? "CDP " : "LLDP", macStr,
                    n.sysName[0] ? n.sysName : n.chassisId);
      if (n.portId[0])
        Serial.printf("  port:%s", n.portId);
      if (n.vlanId > 0)
        Serial.printf("  vlan:%u", n.vlanId);
      Serial.println();
    }

    // STP root bridge
    for (int i = 0; i < STP_BRIDGE_TABLE_SIZE; i++) {
      if (!stpTable[i].active)
        continue;
      if (stpTable[i].rootPathCost == 0 &&
          memcmp(stpTable[i].bridgeMAC, stpTable[i].rootMAC, 6) == 0) {
        macToStr(stpTable[i].bridgeMAC, macStr);
        const char* ver = (stpTable[i].stpVersion == 0)   ? "STP"
                          : (stpTable[i].stpVersion == 2) ? "RSTP"
                                                          : "MSTP";
        Serial.printf("    [%s]   %04X.%s  (root bridge)\n", ver, stpTable[i].bridgePriority,
                      macStr);
        break;
      }
    }
  }

  // ── Hosts ──
  // Collect all unique IPs from the ARP table as the master list
  int hostCount = 0;
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (!arpTable[i].active)
      continue;
    // Skip our own IP
    if (memcmp(arpTable[i].ip, ourIP, 4) == 0)
      continue;
    hostCount++;
  }

  Serial.println();
  Serial.printf("  HOSTS (%d discovered)\n", hostCount);
  Serial.println("  ───────────────────────────────────────────────────────────────");

  if (hostCount == 0) {
    Serial.println("    (none — run 'recon sweep' to discover hosts)");
  }

  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (!arpTable[i].active)
      continue;
    if (memcmp(arpTable[i].ip, ourIP, 4) == 0)
      continue;

    ipToStr(arpTable[i].ip, ipStr);
    macToStr(arpTable[i].mac, macStr);

    // First line: IP + MAC
    Serial.printf("\n    %-16s  %s\n", ipStr, macStr);

    // Hostname (mDNS or NetBIOS)
    const char* hostname = mdnsLookup(arpTable[i].ip);
    const char* nbName = netbiosLookup(arpTable[i].ip);
    const char* nbGroup = netbiosGroupLookup(arpTable[i].ip);

    if (hostname || nbName) {
      Serial.print("      Name:    ");
      if (nbName) {
        Serial.print(nbName);
        if (nbGroup)
          Serial.printf("  [%s]", nbGroup);
        if (hostname && strcmp(hostname, nbName) != 0)
          Serial.printf("  (%s)", hostname);
      } else {
        Serial.print(hostname);
      }
      Serial.println();
    }

    // OS fingerprint
    const char* os = fpLookup(arpTable[i].ip);
    if (os)
      Serial.printf("      OS:      %s\n", os);

    // Traffic stats
    uint32_t pkts = 0, bytes = 0;
    if (statsLookup(arpTable[i].ip, &pkts, &bytes)) {
      if (bytes >= 1048576)
        Serial.printf("      Traffic: %u pkts / %.1f MB\n", pkts, bytes / 1048576.0f);
      else if (bytes >= 1024)
        Serial.printf("      Traffic: %u pkts / %.1f KB\n", pkts, bytes / 1024.0f);
      else
        Serial.printf("      Traffic: %u pkts / %u B\n", pkts, bytes);
    }

    // Active TCP connections
    int conns = tcpConnCount(arpTable[i].ip);
    if (conns > 0)
      Serial.printf("      TCP:     %d active connection(s)\n", conns);

    // Special roles
    bool isGW = (memcmp(arpTable[i].ip, ourGW, 4) == 0);
    bool isDNS = (memcmp(arpTable[i].ip, ourDNS, 4) == 0);
    bool isDHCP = false;
    for (int d = 0; d < knownDhcpCount; d++) {
      if (memcmp(knownDhcp[d].ip, arpTable[i].ip, 4) == 0) {
        isDHCP = true;
        break;
      }
    }
    bool isMitmTarget = (mitmActive && memcmp(arpTable[i].ip, mitmVictimIP, 4) == 0);

    if (isGW || isDNS || isDHCP || isMitmTarget) {
      Serial.print("      Roles:   ");
      if (isGW)
        Serial.print("[Gateway] ");
      if (isDNS)
        Serial.print("[DNS] ");
      if (isDHCP)
        Serial.print("[DHCP] ");
      if (isMitmTarget)
        Serial.print("[MitM TARGET] ");
      Serial.println();
    }
  }

  // ── Summary ──
  Serial.println();
  Serial.println("  SUMMARY");
  Serial.println("  ───────────────────────────────────────────────────────────────");

  // Count various things
  int fpCount = 0;
  for (int i = 0; i < FP_TABLE_SIZE; i++)
    if (fpTable[i].active)
      fpCount++;
  int mdnsCount = 0;
  for (int i = 0; i < MDNS_TABLE_SIZE; i++)
    if (mdnsTable[i].active)
      mdnsCount++;
  int tcpCount = 0;
  for (int i = 0; i < TCP_CONN_TABLE_SIZE; i++)
    if (tcpConnTable[i].active)
      tcpCount++;

  uint32_t elapsed = millis() - statsWindowStart;
  float pps = (elapsed > 0) ? (float)statsWindowPkts * 1000.0f / elapsed : 0;

  Serial.printf("    Hosts: %d  |  Fingerprints: %d  |  TCP conns: %d\n", hostCount, fpCount,
                tcpCount);
  Serial.printf("    LLDP/CDP: %d  |  STP bridges: %d  |  NetBIOS: %u\n", lldpCount, stpBridgeCount,
                netbiosCount);
  Serial.printf("    mDNS: %d  |  DHCP servers: %d  |  Alerts: %u\n", mdnsCount, knownDhcpCount,
                alertCount);
  Serial.printf("    Packets: %u captured  |  %.1f pkt/s  |  %u sent\n", packetCount, pps, txCount);
  Serial.printf("    Uptime: %us  |  Free heap: %u bytes\n", millis() / 1000, ESP.getFreeHeap());
  Serial.println();
}
