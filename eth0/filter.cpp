// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "filter.h"

#include <stdlib.h>
#include <string.h>

#include <Arduino.h>

#include "eth_frame.h"
#include "ip_util.h"
#include "pcap_writer.h"

PacketFilter activeFilter = {FILTER_NONE};

bool packetMatchesFilter(const uint8_t* pkt, uint16_t len) {
  if (activeFilter.type == FILTER_NONE)
    return true;
  if (len < ETH_HEADER_LEN)
    return false;

  uint16_t ethertype = pktRead16(pkt + ETH_TYPE);

  if (activeFilter.type == FILTER_MAC) {
    return (memcmp(pkt + ETH_DST_MAC, activeFilter.macAddr, 6) == 0 ||
            memcmp(pkt + ETH_SRC_MAC, activeFilter.macAddr, 6) == 0);
  }

  if (activeFilter.type == FILTER_ETHERTYPE) {
    return (ethertype == activeFilter.ethertype);
  }

  // Everything below needs IPv4
  if (ethertype != ETHERTYPE_IPV4)
    return false;
  if (len < ETH_HEADER_LEN + 20)
    return false;

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  uint8_t ipHeaderLen = (ipHdr[0] & 0x0F) * 4;
  uint8_t ipProto = ipHdr[9];
  const uint8_t* srcIP = ipHdr + 12;
  const uint8_t* dstIP = ipHdr + 16;

  if (activeFilter.type == FILTER_IP) {
    return (memcmp(srcIP, activeFilter.ip, 4) == 0 || memcmp(dstIP, activeFilter.ip, 4) == 0);
  }

  if (activeFilter.type == FILTER_PROTOCOL) {
    return (ipProto == activeFilter.protocol);
  }

  if (activeFilter.type == FILTER_PORT) {
    if (ipProto != IP_PROTO_TCP && ipProto != IP_PROTO_UDP)
      return false;
    if (len < ETH_HEADER_LEN + ipHeaderLen + 4)
      return false;

    const uint8_t* transport = ipHdr + ipHeaderLen;
    uint16_t srcPort = pktRead16(transport);
    uint16_t dstPort = pktRead16(transport + 2);

    return (srcPort == activeFilter.port || dstPort == activeFilter.port);
  }

  return true;
}

void parseFilterCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "none", 4) == 0) {
    activeFilter.type = FILTER_NONE;
    Serial.println("[FILTER] Cleared - capturing all packets.");
  } else if (strncmp(cmd, "arp", 3) == 0) {
    activeFilter.type = FILTER_ETHERTYPE;
    activeFilter.ethertype = ETHERTYPE_ARP;
    Serial.println("[FILTER] ARP only.");
  } else if (strncmp(cmd, "ipv6", 4) == 0) {
    activeFilter.type = FILTER_ETHERTYPE;
    activeFilter.ethertype = ETHERTYPE_IPV6;
    Serial.println("[FILTER] IPv6 only.");
  } else if (strncmp(cmd, "ipv4", 4) == 0) {
    activeFilter.type = FILTER_ETHERTYPE;
    activeFilter.ethertype = ETHERTYPE_IPV4;
    Serial.println("[FILTER] IPv4 only.");
  } else if (strncmp(cmd, "tcp", 3) == 0) {
    activeFilter.type = FILTER_PROTOCOL;
    activeFilter.protocol = IP_PROTO_TCP;
    Serial.println("[FILTER] TCP only.");
  } else if (strncmp(cmd, "udp", 3) == 0) {
    activeFilter.type = FILTER_PROTOCOL;
    activeFilter.protocol = IP_PROTO_UDP;
    Serial.println("[FILTER] UDP only.");
  } else if (strncmp(cmd, "icmp", 4) == 0) {
    activeFilter.type = FILTER_PROTOCOL;
    activeFilter.protocol = IP_PROTO_ICMP;
    Serial.println("[FILTER] ICMP only.");
  } else if (strncmp(cmd, "port ", 5) == 0) {
    int port = atoi(cmd + 5);
    if (port > 0 && port <= 65535) {
      activeFilter.type = FILTER_PORT;
      activeFilter.port = (uint16_t)port;
      Serial.printf("[FILTER] Port %u only (TCP/UDP).\n", activeFilter.port);
    } else {
      Serial.println("[FILTER] Invalid port number.");
    }
  } else if (strncmp(cmd, "ip ", 3) == 0) {
    if (parseIP(cmd + 3, activeFilter.ip)) {
      activeFilter.type = FILTER_IP;
      Serial.printf("[FILTER] IP %u.%u.%u.%u only.\n", activeFilter.ip[0], activeFilter.ip[1],
                    activeFilter.ip[2], activeFilter.ip[3]);
    } else {
      Serial.println("[FILTER] Invalid IP. Use: f ip 192.168.1.1");
    }
  } else if (strncmp(cmd, "mac ", 4) == 0) {
    if (parseMAC(cmd + 4, activeFilter.macAddr)) {
      activeFilter.type = FILTER_MAC;
      Serial.print("[FILTER] MAC ");
      printMAC(activeFilter.macAddr);
      Serial.println(" only.");
    } else {
      Serial.println("[FILTER] Invalid MAC. Use: f mac AA:BB:CC:DD:EE:FF");
    }
  } else {
    Serial.println();
    Serial.println("  FILTER");
    Serial.println("  ─────────────────────────────────────────────");
    Serial.println("    f none                      Clear filter");
    Serial.println("    f arp|tcp|udp|icmp|ipv4     By protocol");
    Serial.println("    f port <N>                  By port number");
    Serial.println("    f ip <X.X.X.X>              By IP address");
    Serial.println("    f mac <XX:XX:..>            By MAC address");
    Serial.println();
  }

  droppedCount = 0;
}

void printCurrentFilter() {
  Serial.print("[FILTER] Active: ");
  switch (activeFilter.type) {
    case FILTER_NONE:
      Serial.println("none (capturing all)");
      break;
    case FILTER_ETHERTYPE:
      if (activeFilter.ethertype == ETHERTYPE_ARP)
        Serial.println("ARP");
      else if (activeFilter.ethertype == ETHERTYPE_IPV6)
        Serial.println("IPv6");
      else if (activeFilter.ethertype == ETHERTYPE_IPV4)
        Serial.println("IPv4");
      else
        Serial.printf("EtherType 0x%04X\n", activeFilter.ethertype);
      break;
    case FILTER_PROTOCOL:
      if (activeFilter.protocol == IP_PROTO_TCP)
        Serial.println("TCP");
      else if (activeFilter.protocol == IP_PROTO_UDP)
        Serial.println("UDP");
      else if (activeFilter.protocol == IP_PROTO_ICMP)
        Serial.println("ICMP");
      else
        Serial.printf("IP Protocol %u\n", activeFilter.protocol);
      break;
    case FILTER_PORT:
      Serial.printf("port %u\n", activeFilter.port);
      break;
    case FILTER_IP:
      Serial.printf("IP %u.%u.%u.%u\n", activeFilter.ip[0], activeFilter.ip[1], activeFilter.ip[2],
                    activeFilter.ip[3]);
      break;
    case FILTER_MAC:
      printMAC(activeFilter.macAddr);
      Serial.println();
      break;
  }
  Serial.printf("[STATS] %u saved, %u filtered, %u sent.\n", packetCount, droppedCount, txCount);
}
