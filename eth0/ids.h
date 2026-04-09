// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Intrusion detection engine: classifies every captured frame and
// emits alerts when it sees ARP spoofing, rogue DHCP, cleartext
// credentials, DNS anomalies, or port scans. The capture loop calls
// idsAnalyzePacket() on every Ethernet frame regardless of the
// active capture filter — IDS analysis is unconditional.
//
// State tables (ARP cache, known DHCP servers, port-scan trackers,
// DNS query tracker) are exposed via `extern` for now so the
// network-map and stats displays can read them. Phase 8 will narrow
// these to accessor functions.

#pragma once

#include <stdint.h>

#include "arp_table.h"  // ArpEntry + extern arpTable[]
#include "config.h"

// ── Alert severity ──
//
// Used by both the IDS and the syslog forwarder. Lives in ids.h
// because the IDS is the primary producer.
enum AlertLevel {
  ALERT_INFO,
  ALERT_WARN,
  ALERT_CRIT,
};

// ── Tracking-table types ──

struct DhcpServer {
  uint8_t ip[4];
  uint8_t mac[6];
  bool    active;
};

struct ScanTracker {
  uint8_t  srcIP[4];
  uint16_t ports[SCAN_THRESHOLD];  // unique dst ports seen
  uint8_t  portCount;
  uint32_t windowStart;
  bool     active;
  bool     alerted;  // only alert once per window
};

struct DnsQuery {
  uint16_t txid;
  uint8_t  serverIP[4];
  uint32_t timestamp;
  bool     active;
  bool     answered;
};

// ── Engine state (defined in ids.cpp) ──

extern bool       idsEnabled;
extern DhcpServer knownDhcp[DHCP_SERVER_MAX];
extern uint8_t    knownDhcpCount;
extern bool       dhcpLearning;
extern ScanTracker scanTrackers[SCAN_TRACK_SIZE];
extern DnsQuery   dnsTrack[DNS_TRACK_SIZE];
extern uint32_t   alertCount;
extern uint32_t   alertLedUntil;
extern uint32_t   currentLedColor;

// ── API ──

// Wipe all detection tables and counters back to their boot state.
void idsInitTables();

// Print the IDS counters and table sizes to Serial.
void idsPrintStats();

// `ids …` serial command dispatcher.
void parseIdsCommand(const char* cmd);

// Master entry point: classify the frame and dispatch to the right
// detector(s). Safe to call on any frame, including non-IPv4.
void idsAnalyzePacket(const uint8_t* pkt, uint16_t len);

// Individual detectors. Exposed because the recon ARP sweep also
// feeds discovered hosts back into the ARP table via idsCheckArp.
void idsCheckArp(const uint8_t* pkt, uint16_t len);
void idsCheckDhcp(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen);
void idsCheckCleartext(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen);
void idsCheckDns(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen);
void idsCheckPortScan(const uint8_t* ipHdr, uint8_t ipHdrLen, uint16_t ipTotalLen);

// Emit a printf-formatted alert at the given severity. Bumps
// alertCount, prints to Serial, forwards to syslog if enabled, and
// flashes the NeoPixel.
void idsAlert(AlertLevel level, const char* fmt, ...);

// NeoPixel control. setLed sets the color immediately; updateLed
// reverts to the appropriate idle color when the alert latch
// expires.
void idsSetLed(uint32_t color);
void idsUpdateLed();
