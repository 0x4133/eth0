// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "ids.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "eth_frame.h"
#include "led.h"
#include "pcap_writer.h"
#include "state.h"
#include "svc_syslog.h"

// ── Storage for the externs in ids.h and arp_table.h ──

ArpEntry arpTable[ARP_TABLE_SIZE];

bool idsEnabled = IDS_ENABLED_DEFAULT;

DhcpServer  knownDhcp[DHCP_SERVER_MAX];
uint8_t     knownDhcpCount = 0;
bool        dhcpLearning   = true;

ScanTracker scanTrackers[SCAN_TRACK_SIZE];
DnsQuery    dnsTrack[DNS_TRACK_SIZE];

uint32_t alertCount     = 0;
uint32_t alertLedUntil  = 0;
uint32_t currentLedColor = COLOR_OFF;

// ── Utility: case-insensitive memmem for payload scanning ──

namespace {

const uint8_t* memmem_ci(const uint8_t* haystack, size_t hLen, const char* needle, size_t nLen) {
  if (nLen > hLen)
    return NULL;
  for (size_t i = 0; i <= hLen - nLen; i++) {
    bool match = true;
    for (size_t j = 0; j < nLen; j++) {
      char h = haystack[i + j];
      char n = needle[j];
      if (h >= 'A' && h <= 'Z')
        h += 32;
      if (n >= 'A' && n <= 'Z')
        n += 32;
      if (h != n) {
        match = false;
        break;
      }
    }
    if (match)
      return haystack + i;
  }
  return NULL;
}

}  // namespace

// ── Initialize all IDS tracking tables ──
void idsInitTables() {
  memset(arpTable, 0, sizeof(arpTable));
  memset(knownDhcp, 0, sizeof(knownDhcp));
  memset(scanTrackers, 0, sizeof(scanTrackers));
  memset(dnsTrack, 0, sizeof(dnsTrack));
  knownDhcpCount = 0;
  dhcpLearning = true;
  alertCount = 0;
}

// ── Alert output with severity + NeoPixel ──
void idsAlert(AlertLevel level, const char* fmt, ...) {
  alertCount++;
  const char* tag;
  uint32_t color;
  switch (level) {
    case ALERT_INFO:
      tag = "INFO";
      color = COLOR_YELLOW;
      break;
    case ALERT_WARN:
      tag = "WARN";
      color = COLOR_YELLOW;
      break;
    case ALERT_CRIT:
      tag = "CRIT";
      color = COLOR_RED;
      break;
    default:
      tag = "????";
      color = COLOR_RED;
      break;
  }

  Serial.printf("[ALERT #%u][%s] ", alertCount, tag);

  va_list args;
  va_start(args, fmt);
  char buf[200];
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  Serial.println(buf);

  // Forward to syslog server if configured
  if (syslogEnabled) {
    syslogSend(level, buf);
  }

  idsSetLed(color);
  alertLedUntil = millis() + ALERT_LED_MS;
}

// ── NeoPixel control ──
void idsSetLed(uint32_t color) {
  currentLedColor = color;
  pixel.setPixelColor(0, color);
  pixel.show();
}

void idsUpdateLed() {
  if (alertLedUntil > 0 && millis() > alertLedUntil) {
    alertLedUntil = 0;
    idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
  }
}

// ══════════════════════════════════════════
//  Main IDS Packet Dispatcher
// ══════════════════════════════════════════

void idsAnalyzePacket(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN)
    return;

  uint16_t ethertype = pktRead16(pkt + ETH_TYPE);

  // ── ARP analysis (works on ARP frames directly) ──
  if (ethertype == ETHERTYPE_ARP) {
    idsCheckArp(pkt, len);
    return;
  }

  // ── IPv4 analysis ──
  if (ethertype != ETHERTYPE_IPV4)
    return;
  if (len < ETH_HEADER_LEN + 20)
    return;

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  uint8_t ipHdrLen = (ipHdr[0] & 0x0F) * 4;
  uint16_t ipTotalLen = pktRead16(ipHdr + 2);
  uint8_t proto = ipHdr[9];

  // ── Port scan detection (TCP SYN tracking) ──
  if (proto == IP_PROTO_TCP) {
    idsCheckPortScan(ipHdr, ipHdrLen, ipTotalLen);
  }

  // ── UDP-based checks ──
  if (proto == IP_PROTO_UDP && len >= ETH_HEADER_LEN + ipHdrLen + 8) {
    const uint8_t* udpHdr = ipHdr + ipHdrLen;
    uint16_t srcPort = pktRead16(udpHdr);
    uint16_t dstPort = pktRead16(udpHdr + 2);

    // DHCP (server responses come from port 67)
    if (srcPort == 67 || dstPort == 67) {
      idsCheckDhcp(pkt, len, ipHdr, ipHdrLen);
    }

    // DNS (port 53)
    if (srcPort == 53 || dstPort == 53) {
      idsCheckDns(pkt, len, ipHdr, ipHdrLen);
    }
  }

  // ── Cleartext credential detection (TCP payloads) ──
  if (proto == IP_PROTO_TCP && len >= ETH_HEADER_LEN + ipHdrLen + 20) {
    idsCheckCleartext(pkt, len, ipHdr, ipHdrLen);
  }
}

// ══════════════════════════════════════════
//  1. ARP Spoof Detection
// ══════════════════════════════════════════

void idsCheckArp(const uint8_t* pkt, uint16_t len) {
  // ARP packet: ETH header (14) + ARP (28 minimum)
  if (len < ETH_HEADER_LEN + 28)
    return;

  const uint8_t* arp = pkt + ETH_HEADER_LEN;
  uint16_t op = pktRead16(arp + 6);

  // We care about ARP replies (op=2) and requests (op=1)
  // Both contain sender IP/MAC which we can track
  const uint8_t* senderMAC = arp + 8;
  const uint8_t* senderIP = arp + 14;

  // Skip 0.0.0.0 (gratuitous ARP probes)
  if (senderIP[0] == 0 && senderIP[1] == 0 && senderIP[2] == 0 && senderIP[3] == 0)
    return;

  // Look up in ARP table
  int freeSlot = -1;
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (!arpTable[i].active) {
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }

    if (memcmp(arpTable[i].ip, senderIP, 4) == 0) {
      // IP already known — check if MAC changed
      if (memcmp(arpTable[i].mac, senderMAC, 6) != 0) {
        // MAC CHANGED — possible ARP spoof!
        idsAlert(ALERT_CRIT,
                 "ARP SPOOF? %u.%u.%u.%u changed from "
                 "%02X:%02X:%02X:%02X:%02X:%02X to "
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 senderIP[0], senderIP[1], senderIP[2], senderIP[3], arpTable[i].mac[0],
                 arpTable[i].mac[1], arpTable[i].mac[2], arpTable[i].mac[3], arpTable[i].mac[4],
                 arpTable[i].mac[5], senderMAC[0], senderMAC[1], senderMAC[2], senderMAC[3],
                 senderMAC[4], senderMAC[5]);

        // Update the table (attacker's MAC is now current)
        memcpy(arpTable[i].mac, senderMAC, 6);
      }
      arpTable[i].lastSeen = millis();
      return;
    }
  }

  // New IP — add to table
  if (freeSlot >= 0) {
    arpTable[freeSlot].active = true;
    memcpy(arpTable[freeSlot].ip, senderIP, 4);
    memcpy(arpTable[freeSlot].mac, senderMAC, 6);
    arpTable[freeSlot].lastSeen = millis();
  }

  // Check for ARP flood (many different source MACs in short time)
  // Gratuitous ARP replies (op=2, unsolicited) are suspicious
  if (op == 2) {
    static uint32_t lastGratuitousAlert = 0;
    static uint8_t lastGratuitousMAC[6] = {0};
    static uint8_t gratuitousCount = 0;

    if (memcmp(lastGratuitousMAC, senderMAC, 6) == 0) {
      gratuitousCount++;
      if (gratuitousCount > 5 && (millis() - lastGratuitousAlert > 10000)) {
        idsAlert(ALERT_WARN,
                 "ARP flood: %u gratuitous replies from "
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 gratuitousCount, senderMAC[0], senderMAC[1], senderMAC[2], senderMAC[3],
                 senderMAC[4], senderMAC[5]);
        lastGratuitousAlert = millis();
        gratuitousCount = 0;
      }
    } else {
      memcpy(lastGratuitousMAC, senderMAC, 6);
      gratuitousCount = 1;
    }
  }
}

// ══════════════════════════════════════════
//  2. Rogue DHCP Server Detection
// ══════════════════════════════════════════

void idsCheckDhcp(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen) {
  const uint8_t* udpHdr = ipHdr + ipHdrLen;
  uint16_t srcPort = pktRead16(udpHdr);

  // Only check server→client (source port 67)
  if (srcPort != 67)
    return;

  // DHCP payload starts after UDP header (8 bytes)
  // Minimum DHCP: 240 bytes (fixed fields) + at least 4 bytes options
  uint16_t udpLen = pktRead16(udpHdr + 4);
  if (udpLen < 248)
    return;

  const uint8_t* dhcp = udpHdr + 8;
  uint8_t msgType = dhcp[0];  // op: 2 = BOOTREPLY

  if (msgType != 2)
    return;  // Not a server reply

  // Find DHCP message type in options (after 240 bytes of fixed fields)
  // Magic cookie at offset 236: 99.130.83.99 (0x63825363)
  if (udpLen < 248 + 8)
    return;
  const uint8_t* options = dhcp + 240;
  uint16_t optLen = udpLen - 8 - 240;

  uint8_t dhcpMsgType = 0;
  for (uint16_t i = 0; i < optLen - 1;) {
    uint8_t optCode = options[i];
    if (optCode == 0xFF)
      break;  // End
    if (optCode == 0) {
      i++;
      continue;
    }  // Padding
    if (i + 1 >= optLen)
      break;
    uint8_t optDataLen = options[i + 1];
    if (optCode == 53 && optDataLen >= 1) {  // DHCP Message Type
      dhcpMsgType = options[i + 2];
    }
    i += 2 + optDataLen;
  }

  // We care about Offer (2) and ACK (5)
  if (dhcpMsgType != 2 && dhcpMsgType != 5)
    return;

  const uint8_t* serverIP = ipHdr + 12;  // source IP of the packet
  const uint8_t* serverMAC = pkt + ETH_SRC_MAC;

  // Check against known servers
  for (int i = 0; i < knownDhcpCount; i++) {
    if (memcmp(knownDhcp[i].ip, serverIP, 4) == 0) {
      return;  // Known server, all good
    }
  }

  // New DHCP server detected
  if (dhcpLearning && knownDhcpCount == 0) {
    // First server — learn it as trusted
    if (knownDhcpCount < DHCP_SERVER_MAX) {
      memcpy(knownDhcp[knownDhcpCount].ip, serverIP, 4);
      memcpy(knownDhcp[knownDhcpCount].mac, serverMAC, 6);
      knownDhcp[knownDhcpCount].active = true;
      knownDhcpCount++;
      idsAlert(ALERT_INFO,
               "DHCP server learned: %u.%u.%u.%u "
               "(%02X:%02X:%02X:%02X:%02X:%02X)",
               serverIP[0], serverIP[1], serverIP[2], serverIP[3], serverMAC[0], serverMAC[1],
               serverMAC[2], serverMAC[3], serverMAC[4], serverMAC[5]);
    }
    dhcpLearning = false;
  } else {
    // ROGUE DHCP SERVER
    const char* typeStr = (dhcpMsgType == 2) ? "Offer" : "ACK";
    idsAlert(ALERT_CRIT,
             "ROGUE DHCP SERVER! %s from %u.%u.%u.%u "
             "(%02X:%02X:%02X:%02X:%02X:%02X)",
             typeStr, serverIP[0], serverIP[1], serverIP[2], serverIP[3], serverMAC[0],
             serverMAC[1], serverMAC[2], serverMAC[3], serverMAC[4], serverMAC[5]);

    // Still record it so we don't spam alerts
    if (knownDhcpCount < DHCP_SERVER_MAX) {
      memcpy(knownDhcp[knownDhcpCount].ip, serverIP, 4);
      memcpy(knownDhcp[knownDhcpCount].mac, serverMAC, 6);
      knownDhcp[knownDhcpCount].active = true;
      knownDhcpCount++;
    }
  }
}

// ══════════════════════════════════════════
//  3. Cleartext Credential Detection
// ══════════════════════════════════════════

void idsCheckCleartext(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen) {
  const uint8_t* tcpHdr = ipHdr + ipHdrLen;
  uint16_t srcPort = pktRead16(tcpHdr);
  uint16_t dstPort = pktRead16(tcpHdr + 2);
  uint8_t tcpHdrLen = ((tcpHdr[12] >> 4) & 0x0F) * 4;

  // Calculate payload offset and length
  uint16_t ipTotalLen = pktRead16(ipHdr + 2);
  int payloadLen = ipTotalLen - ipHdrLen - tcpHdrLen;
  if (payloadLen < 5)
    return;  // need at least a few bytes

  const uint8_t* payload = tcpHdr + tcpHdrLen;

  // Bounds check against actual packet length
  if ((payload + payloadLen) > (pkt + len)) {
    payloadLen = (pkt + len) - payload;
  }
  if (payloadLen < 5)
    return;

  // ── HTTP Basic Auth ──
  if (dstPort == 80 || dstPort == 8080 || srcPort == 80 || srcPort == 8080) {
    if (memmem_ci(payload, payloadLen, "Authorization: Basic", 20)) {
      const uint8_t* srcIP = ipHdr + 12;
      const uint8_t* dstIP = ipHdr + 16;
      idsAlert(ALERT_CRIT, "CLEARTEXT HTTP Basic Auth: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u", srcIP[0],
               srcIP[1], srcIP[2], srcIP[3], srcPort, dstIP[0], dstIP[1], dstIP[2], dstIP[3],
               dstPort);
      idsSetLed(COLOR_PURPLE);
      alertLedUntil = millis() + ALERT_LED_MS;
      return;
    }
  }

  // ── FTP (port 21) ──
  if (dstPort == 21 || srcPort == 21) {
    if (memmem_ci(payload, payloadLen, "USER ", 5) || memmem_ci(payload, payloadLen, "PASS ", 5)) {
      const uint8_t* srcIP = ipHdr + 12;
      const uint8_t* dstIP = ipHdr + 16;
      idsAlert(ALERT_CRIT, "CLEARTEXT FTP credentials: %u.%u.%u.%u -> %u.%u.%u.%u", srcIP[0],
               srcIP[1], srcIP[2], srcIP[3], dstIP[0], dstIP[1], dstIP[2], dstIP[3]);
      idsSetLed(COLOR_PURPLE);
      alertLedUntil = millis() + ALERT_LED_MS;
      return;
    }
  }

  // ── Telnet (port 23) ──
  if (dstPort == 23 || srcPort == 23) {
    if (memmem_ci(payload, payloadLen, "login:", 6) ||
        memmem_ci(payload, payloadLen, "password:", 9)) {
      const uint8_t* srcIP = ipHdr + 12;
      idsAlert(ALERT_WARN, "Telnet login activity: %u.%u.%u.%u (cleartext)", srcIP[0], srcIP[1],
               srcIP[2], srcIP[3]);
      idsSetLed(COLOR_PURPLE);
      alertLedUntil = millis() + ALERT_LED_MS;
      return;
    }
  }

  // ── POP3 (port 110) ──
  if (dstPort == 110) {
    if (memmem_ci(payload, payloadLen, "USER ", 5) || memmem_ci(payload, payloadLen, "PASS ", 5)) {
      const uint8_t* srcIP = ipHdr + 12;
      idsAlert(ALERT_CRIT, "CLEARTEXT POP3 credentials: %u.%u.%u.%u", srcIP[0], srcIP[1], srcIP[2],
               srcIP[3]);
      idsSetLed(COLOR_PURPLE);
      alertLedUntil = millis() + ALERT_LED_MS;
      return;
    }
  }

  // ── SMTP (port 25, 587) ──
  if (dstPort == 25 || dstPort == 587) {
    if (memmem_ci(payload, payloadLen, "AUTH LOGIN", 10) ||
        memmem_ci(payload, payloadLen, "AUTH PLAIN", 10)) {
      const uint8_t* srcIP = ipHdr + 12;
      idsAlert(ALERT_CRIT, "CLEARTEXT SMTP AUTH: %u.%u.%u.%u -> port %u", srcIP[0], srcIP[1],
               srcIP[2], srcIP[3], dstPort);
      idsSetLed(COLOR_PURPLE);
      alertLedUntil = millis() + ALERT_LED_MS;
      return;
    }
  }
}

// ══════════════════════════════════════════
//  4. DNS Anomaly Detection
// ══════════════════════════════════════════

void idsCheckDns(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen) {
  const uint8_t* udpHdr = ipHdr + ipHdrLen;
  uint16_t srcPort = pktRead16(udpHdr);
  uint16_t dstPort = pktRead16(udpHdr + 2);
  uint16_t udpLen = pktRead16(udpHdr + 4);

  if (udpLen < 8 + 12)
    return;  // UDP header + DNS header minimum

  const uint8_t* dns = udpHdr + 8;
  uint16_t txid = pktRead16(dns);
  uint8_t flags_hi = dns[2];
  bool isResponse = (flags_hi & 0x80) != 0;

  const uint8_t* srcIP = ipHdr + 12;
  const uint8_t* dstIP = ipHdr + 16;

  if (!isResponse && dstPort == 53) {
    // ── Outgoing DNS query — record it ──
    int freeSlot = -1;
    int oldestSlot = 0;
    uint32_t oldestTime = UINT32_MAX;

    for (int i = 0; i < DNS_TRACK_SIZE; i++) {
      if (!dnsTrack[i].active) {
        if (freeSlot < 0)
          freeSlot = i;
        continue;
      }
      // Expire old entries (>10 seconds)
      if (millis() - dnsTrack[i].timestamp > 10000) {
        dnsTrack[i].active = false;
        if (freeSlot < 0)
          freeSlot = i;
        continue;
      }
      if (dnsTrack[i].timestamp < oldestTime) {
        oldestTime = dnsTrack[i].timestamp;
        oldestSlot = i;
      }
    }

    int slot = (freeSlot >= 0) ? freeSlot : oldestSlot;
    dnsTrack[slot].txid = txid;
    memcpy(dnsTrack[slot].serverIP, dstIP, 4);  // expected DNS server
    dnsTrack[slot].timestamp = millis();
    dnsTrack[slot].active = true;
    dnsTrack[slot].answered = false;
  }

  if (isResponse && srcPort == 53) {
    // ── Incoming DNS response — check for anomalies ──
    for (int i = 0; i < DNS_TRACK_SIZE; i++) {
      if (!dnsTrack[i].active)
        continue;
      if (dnsTrack[i].txid != txid)
        continue;

      // Check: response from unexpected server?
      if (memcmp(dnsTrack[i].serverIP, srcIP, 4) != 0) {
        idsAlert(ALERT_CRIT,
                 "DNS SPOOF? TXID 0x%04X response from %u.%u.%u.%u "
                 "(expected %u.%u.%u.%u)",
                 txid, srcIP[0], srcIP[1], srcIP[2], srcIP[3], dnsTrack[i].serverIP[0],
                 dnsTrack[i].serverIP[1], dnsTrack[i].serverIP[2], dnsTrack[i].serverIP[3]);
        return;
      }

      // Check: duplicate response (already answered)?
      if (dnsTrack[i].answered) {
        idsAlert(ALERT_WARN,
                 "DNS duplicate response for TXID 0x%04X from %u.%u.%u.%u "
                 "(possible spoof race)",
                 txid, srcIP[0], srcIP[1], srcIP[2], srcIP[3]);
        return;
      }

      dnsTrack[i].answered = true;
      return;
    }

    // Response with no matching query — unsolicited
    idsAlert(ALERT_WARN, "DNS unsolicited response TXID 0x%04X from %u.%u.%u.%u", txid, srcIP[0],
             srcIP[1], srcIP[2], srcIP[3]);
  }
}

// ══════════════════════════════════════════
//  5. Port Scan Detection
// ══════════════════════════════════════════

void idsCheckPortScan(const uint8_t* ipHdr, uint8_t ipHdrLen, uint16_t ipTotalLen) {
  if (ipTotalLen < ipHdrLen + 20)
    return;  // need TCP header

  const uint8_t* tcpHdr = ipHdr + ipHdrLen;
  uint8_t tcpFlags = tcpHdr[13];
  bool isSyn = (tcpFlags & 0x02) && !(tcpFlags & 0x10);  // SYN set, ACK not set

  if (!isSyn)
    return;  // Only track initial SYN packets

  const uint8_t* srcIP = ipHdr + 12;
  uint16_t dstPort = pktRead16(tcpHdr + 2);
  uint32_t now = millis();

  // Find or allocate tracker for this source IP
  int slot = -1;
  int freeSlot = -1;
  int oldestSlot = 0;
  uint32_t oldestTime = UINT32_MAX;

  for (int i = 0; i < SCAN_TRACK_SIZE; i++) {
    if (!scanTrackers[i].active) {
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    // Expire old windows
    if (now - scanTrackers[i].windowStart > SCAN_WINDOW_MS) {
      scanTrackers[i].active = false;
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    if (memcmp(scanTrackers[i].srcIP, srcIP, 4) == 0) {
      slot = i;
      break;
    }
    if (scanTrackers[i].windowStart < oldestTime) {
      oldestTime = scanTrackers[i].windowStart;
      oldestSlot = i;
    }
  }

  if (slot < 0) {
    // New source IP
    slot = (freeSlot >= 0) ? freeSlot : oldestSlot;
    scanTrackers[slot].active = true;
    memcpy(scanTrackers[slot].srcIP, srcIP, 4);
    scanTrackers[slot].ports[0] = dstPort;
    scanTrackers[slot].portCount = 1;
    scanTrackers[slot].windowStart = now;
    scanTrackers[slot].alerted = false;
    return;
  }

  ScanTracker& t = scanTrackers[slot];

  // Check if this port is already tracked
  for (int i = 0; i < t.portCount; i++) {
    if (t.ports[i] == dstPort)
      return;  // already counted
  }

  // Add new port
  if (t.portCount < SCAN_THRESHOLD) {
    t.ports[t.portCount++] = dstPort;
  }

  // Threshold reached?
  if (t.portCount >= SCAN_THRESHOLD && !t.alerted) {
    t.alerted = true;
    idsAlert(ALERT_CRIT, "PORT SCAN detected from %u.%u.%u.%u (%u+ ports in %us)", srcIP[0],
             srcIP[1], srcIP[2], srcIP[3], SCAN_THRESHOLD, SCAN_WINDOW_MS / 1000);
  }
}

// ══════════════════════════════════════════
//  IDS Serial Commands
// ══════════════════════════════════════════

void parseIdsCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (*cmd == '\0') {
    // Toggle IDS
    idsEnabled = !idsEnabled;
    Serial.printf("[IDS] Detection %s\n", idsEnabled ? "ENABLED" : "DISABLED");
    return;
  }

  if (strncmp(cmd, "stats", 5) == 0) {
    idsPrintStats();
  } else if (strncmp(cmd, "arp", 3) == 0) {
    Serial.println("[IDS] ARP Table:");
    int count = 0;
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
      if (!arpTable[i].active)
        continue;
      count++;
      Serial.printf("  %u.%u.%u.%u -> %02X:%02X:%02X:%02X:%02X:%02X (seen %us ago)\n",
                    arpTable[i].ip[0], arpTable[i].ip[1], arpTable[i].ip[2], arpTable[i].ip[3],
                    arpTable[i].mac[0], arpTable[i].mac[1], arpTable[i].mac[2], arpTable[i].mac[3],
                    arpTable[i].mac[4], arpTable[i].mac[5],
                    (millis() - arpTable[i].lastSeen) / 1000);
    }
    if (count == 0)
      Serial.println("  (empty)");
    Serial.printf("  %d entries\n", count);
  } else if (strncmp(cmd, "dhcp", 4) == 0) {
    Serial.println("[IDS] Known DHCP Servers:");
    if (knownDhcpCount == 0) {
      Serial.println("  (none learned yet)");
    }
    for (int i = 0; i < knownDhcpCount; i++) {
      Serial.printf("  %s%u.%u.%u.%u (%02X:%02X:%02X:%02X:%02X:%02X)\n",
                    (i == 0) ? "(trusted) " : "(ROGUE!)  ", knownDhcp[i].ip[0], knownDhcp[i].ip[1],
                    knownDhcp[i].ip[2], knownDhcp[i].ip[3], knownDhcp[i].mac[0],
                    knownDhcp[i].mac[1], knownDhcp[i].mac[2], knownDhcp[i].mac[3],
                    knownDhcp[i].mac[4], knownDhcp[i].mac[5]);
    }
  } else if (strncmp(cmd, "reset", 5) == 0) {
    idsInitTables();
    Serial.println("[IDS] All tables cleared.");
  } else {
    Serial.println();
    Serial.println("  IDS");
    Serial.println("  ─────────────────────────────────────────────");
    Serial.println("    ids                Toggle on/off");
    Serial.println("    ids stats          Alert statistics");
    Serial.println("    ids arp            ARP binding table");
    Serial.println("    ids dhcp           Known DHCP servers");
    Serial.println("    ids reset          Clear all IDS tables");
    Serial.println();
  }
}

void idsPrintStats() {
  int arpEntries = 0;
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (arpTable[i].active)
      arpEntries++;
  }
  int activeDns = 0;
  for (int i = 0; i < DNS_TRACK_SIZE; i++) {
    if (dnsTrack[i].active)
      activeDns++;
  }

  Serial.println("[IDS] ═══ Detection Stats ═══");
  Serial.printf("  Status:        %s\n", idsEnabled ? "ACTIVE" : "disabled");
  Serial.printf("  Total alerts:  %u\n", alertCount);
  Serial.printf("  ARP entries:   %d / %d\n", arpEntries, ARP_TABLE_SIZE);
  Serial.printf("  DHCP servers:  %d (learning: %s)\n", knownDhcpCount,
                dhcpLearning ? "yes" : "no");
  Serial.printf("  DNS tracked:   %d / %d\n", activeDns, DNS_TRACK_SIZE);
  Serial.printf("  Packets:       %u captured, %u filtered, %u sent\n", packetCount, droppedCount,
                txCount);
}
