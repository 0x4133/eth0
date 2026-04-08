// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "eth_frame.h"

#include <string.h>

#include "state.h"

uint16_t ipChecksum(const uint8_t* data, uint16_t len) {
  uint32_t sum = 0;
  for (uint16_t i = 0; i < len - 1; i += 2) {
    sum += ((uint16_t)data[i] << 8) | data[i + 1];
  }
  if (len & 1) {
    sum += (uint16_t)data[len - 1] << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return ~sum & 0xFFFF;
}

uint16_t tcpChecksum(const uint8_t* srcIP, const uint8_t* dstIP, const uint8_t* tcpSeg,
                     uint16_t tcpLen) {
  uint32_t sum = 0;

  // Pseudo-header: srcIP + dstIP + zero + proto(6) + TCP length
  for (int i = 0; i < 4; i += 2)
    sum += ((uint16_t)srcIP[i] << 8) | srcIP[i + 1];
  for (int i = 0; i < 4; i += 2)
    sum += ((uint16_t)dstIP[i] << 8) | dstIP[i + 1];
  sum += (uint16_t)IP_PROTO_TCP;
  sum += tcpLen;

  // TCP segment
  for (uint16_t i = 0; i < tcpLen - 1; i += 2)
    sum += ((uint16_t)tcpSeg[i] << 8) | tcpSeg[i + 1];
  if (tcpLen & 1)
    sum += (uint16_t)tcpSeg[tcpLen - 1] << 8;

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum & 0xFFFF;
}

uint16_t buildEthHeader(uint8_t* buf, const uint8_t* dstMAC, uint16_t ethertype) {
  memcpy(buf + ETH_DST_MAC, dstMAC, 6);
  memcpy(buf + ETH_SRC_MAC, mac, 6);
  pktWrite16(buf + ETH_TYPE, ethertype);
  return ETH_HEADER_LEN;
}

uint16_t buildIPv4Header(uint8_t* buf, const uint8_t* srcIP, const uint8_t* dstIP, uint8_t protocol,
                         uint16_t payloadLen) {
  static uint16_t ipID = 1;

  memset(buf, 0, 20);
  buf[0] = 0x45;                         // IPv4, IHL=5 (20 bytes)
  buf[1] = 0x00;                         // DSCP/ECN
  pktWrite16(buf + 2, 20 + payloadLen);  // Total length
  pktWrite16(buf + 4, ipID++);           // Identification
  pktWrite16(buf + 6, 0x4000);           // Flags: Don't Fragment
  buf[8] = 64;                           // TTL
  buf[9] = protocol;                     // Protocol
  // Checksum at offset 10-11 (zero for now)
  memcpy(buf + 12, srcIP, 4);  // Source IP
  memcpy(buf + 16, dstIP, 4);  // Destination IP

  // Calculate and set header checksum
  uint16_t cksum = ipChecksum(buf, 20);
  pktWrite16(buf + 10, cksum);

  return 20;
}
