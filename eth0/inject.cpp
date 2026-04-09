// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "inject.h"

#include <string.h>

#include <Arduino.h>
#include <Ethernet2.h>
#include <utility/socket.h>
#include <utility/w5500.h>

#include "arp_table.h"
#include "config.h"
#include "eth_frame.h"
#include "ids.h"
#include "pcap_writer.h"
#include "spi_bus.h"
#include "state.h"

uint16_t sendRawFrame(const uint8_t* frame, uint16_t len) {
  switchToEthSPI();

  if (len == 0 || len > w5500.SSIZE)
    return 0;

  // Wait for TX buffer space
  uint16_t freeSize;
  do {
    freeSize = w5500.getTXFreeSize(RAW_SOCKET);
  } while (freeSize < len);

  // Write frame data into W5500 TX buffer
  w5500.send_data_processing(RAW_SOCKET, (uint8_t*)frame, len);

  // Issue SEND command
  w5500.execCmdSn(RAW_SOCKET, Sock_SEND);

  // Wait for send completion
  uint32_t timeout = millis() + 500;
  while ((w5500.readSnIR(RAW_SOCKET) & SnIR::SEND_OK) != SnIR::SEND_OK) {
    if (w5500.readSnIR(RAW_SOCKET) & SnIR::TIMEOUT) {
      w5500.writeSnIR(RAW_SOCKET, SnIR::SEND_OK | SnIR::TIMEOUT);
      return 0;
    }
    if (millis() > timeout)
      return 0;
  }
  w5500.writeSnIR(RAW_SOCKET, SnIR::SEND_OK);

  txCount++;
  return len;
}

// ── Send ARP "who-has" request ──
void sendArpRequest(const uint8_t* targetIP) {
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint16_t pos = 0;

  // Ethernet header
  pos = buildEthHeader(txBuf, broadcast, ETHERTYPE_ARP);

  // ARP payload (28 bytes)
  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;  // Hardware type: Ethernet
  pktWrite16(txBuf + pos, 0x0800);
  pos += 2;          // Protocol type: IPv4
  txBuf[pos++] = 6;  // Hardware addr len
  txBuf[pos++] = 4;  // Protocol addr len
  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;  // Operation: Request
  memcpy(txBuf + pos, mac, 6);
  pos += 6;  // Sender MAC
  memcpy(txBuf + pos, ourIP, 4);
  pos += 4;  // Sender IP
  memset(txBuf + pos, 0x00, 6);
  pos += 6;  // Target MAC (unknown)
  memcpy(txBuf + pos, targetIP, 4);
  pos += 4;  // Target IP

  // Pad to minimum Ethernet frame size (60 bytes without FCS)
  while (pos < 60)
    txBuf[pos++] = 0;

  uint16_t sent = sendRawFrame(txBuf, pos);
  Serial.printf("[TX] ARP who-has %u.%u.%u.%u (%u bytes) %s\n", targetIP[0], targetIP[1],
                targetIP[2], targetIP[3], pos, sent ? "OK" : "FAIL");
}

// ── Send ICMP Echo Request (ping) ──
void sendPing(const uint8_t* targetIP) {
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint16_t pos = 0;

  // We use broadcast MAC since we may not know the target's MAC
  // The gateway/switch will handle routing
  pos = buildEthHeader(txBuf, broadcast, ETHERTYPE_IPV4);

  // ICMP payload: type(1) + code(1) + checksum(2) + id(2) + seq(2) + data(32) = 40 bytes
  uint16_t icmpLen = 40;

  // IPv4 header
  pos += buildIPv4Header(txBuf + pos, ourIP, targetIP, IP_PROTO_ICMP, icmpLen);

  // ICMP Echo Request
  uint16_t icmpStart = pos;
  txBuf[pos++] = 8;  // Type: Echo Request
  txBuf[pos++] = 0;  // Code
  txBuf[pos++] = 0;  // Checksum (placeholder)
  txBuf[pos++] = 0;
  static uint16_t pingID = 0x1234;
  static uint16_t pingSeq = 0;
  pktWrite16(txBuf + pos, pingID);
  pos += 2;  // Identifier
  pktWrite16(txBuf + pos, pingSeq++);
  pos += 2;  // Sequence

  // Payload data (32 bytes of pattern)
  for (int i = 0; i < 32; i++) {
    txBuf[pos++] = 'A' + (i % 26);
  }

  // Calculate ICMP checksum
  uint16_t icmpCksum = ipChecksum(txBuf + icmpStart, icmpLen);
  pktWrite16(txBuf + icmpStart + 2, icmpCksum);

  uint16_t sent = sendRawFrame(txBuf, pos);
  Serial.printf("[TX] ICMP ping -> %u.%u.%u.%u seq=%u (%u bytes) %s\n", targetIP[0], targetIP[1],
                targetIP[2], targetIP[3], pingSeq - 1, pos, sent ? "OK" : "FAIL");
}

// ── Send UDP packet with arbitrary payload ──
void sendUDP(const uint8_t* targetIP, uint16_t dstPort, const char* payload, uint16_t payloadLen) {
  // Try to resolve target MAC from ARP table, fall back to broadcast
  uint8_t dstMAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  const uint8_t* lookupIP = targetIP;

  // If off-subnet, look up gateway MAC instead
  bool sameSubnet = true;
  for (int i = 0; i < 4; i++) {
    if ((targetIP[i] & ourSubnet[i]) != (ourIP[i] & ourSubnet[i])) {
      sameSubnet = false;
      break;
    }
  }
  if (!sameSubnet)
    lookupIP = ourGW;

  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (arpTable[i].active && memcmp(arpTable[i].ip, lookupIP, 4) == 0) {
      memcpy(dstMAC, arpTable[i].mac, 6);
      break;
    }
  }

  uint16_t pos = 0;
  pos = buildEthHeader(txBuf, dstMAC, ETHERTYPE_IPV4);

  uint16_t udpLen = 8 + payloadLen;  // UDP header + payload

  // IPv4 header
  pos += buildIPv4Header(txBuf + pos, ourIP, targetIP, IP_PROTO_UDP, udpLen);

  // UDP header
  uint16_t srcPort = 12345;
  pktWrite16(txBuf + pos, srcPort);
  pos += 2;  // Source port
  pktWrite16(txBuf + pos, dstPort);
  pos += 2;  // Destination port
  pktWrite16(txBuf + pos, udpLen);
  pos += 2;  // Length
  pktWrite16(txBuf + pos, 0x0000);
  pos += 2;  // Checksum (0 = disabled for IPv4 UDP)

  // Payload
  if (payloadLen > 0 && payloadLen <= (MAX_FRAME_SIZE - pos)) {
    memcpy(txBuf + pos, payload, payloadLen);
    pos += payloadLen;
  }

  uint16_t sent = sendRawFrame(txBuf, pos);
  Serial.printf("[TX] UDP -> %u.%u.%u.%u:%u (%u bytes payload) %s\n", targetIP[0], targetIP[1],
                targetIP[2], targetIP[3], dstPort, payloadLen, sent ? "OK" : "FAIL");
}

// ── Send raw frame from hex string ──
int hexCharToVal(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

void sendRawHex(const char* hexStr) {
  uint16_t pos = 0;

  // Skip spaces, parse hex pairs
  while (*hexStr && pos < MAX_FRAME_SIZE) {
    // Skip spaces, colons, dashes
    while (*hexStr == ' ' || *hexStr == ':' || *hexStr == '-')
      hexStr++;
    if (!*hexStr)
      break;

    int hi = hexCharToVal(*hexStr++);
    if (hi < 0 || !*hexStr) {
      Serial.println("[TX] Invalid hex data.");
      return;
    }
    int lo = hexCharToVal(*hexStr++);
    if (lo < 0) {
      Serial.println("[TX] Invalid hex data.");
      return;
    }
    txBuf[pos++] = (hi << 4) | lo;
  }

  if (pos < 14) {
    Serial.println("[TX] Frame too short (need at least 14 bytes for Ethernet header).");
    return;
  }

  // Pad to minimum frame size
  while (pos < 60)
    txBuf[pos++] = 0;

  uint16_t sent = sendRawFrame(txBuf, pos);
  Serial.printf("[TX] Raw frame (%u bytes) %s\n", pos, sent ? "OK" : "FAIL");
}

// ── Build a TCP SYN packet, returns total frame length ──
uint16_t buildTcpSyn(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                     const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort) {
  uint16_t pos = 0;

  // Ethernet header
  pos = buildEthHeader(buf, dstMAC, ETHERTYPE_IPV4);

  // TCP header is 20 bytes (no options) + 4 bytes MSS option = 24 bytes
  uint16_t tcpLen = 24;

  // IPv4 header
  pos += buildIPv4Header(buf + pos, srcIP, dstIP, IP_PROTO_TCP, tcpLen);

  // TCP header
  uint16_t tcpStart = pos;
  pktWrite16(buf + pos, srcPort);
  pos += 2;  // Source port
  pktWrite16(buf + pos, dstPort);
  pos += 2;  // Destination port

  // Sequence number (random-ish)
  uint32_t seq = micros() ^ (dstPort << 16) ^ (srcPort);
  pktWrite32(buf + pos, seq);
  pos += 4;  // Seq number
  pktWrite32(buf + pos, 0);
  pos += 4;  // Ack number (0 for SYN)

  buf[pos++] = 0x60;  // Data offset: 6 (24 bytes / 4), upper nibble
  buf[pos++] = 0x02;  // Flags: SYN only
  pktWrite16(buf + pos, 65535);
  pos += 2;  // Window size
  pktWrite16(buf + pos, 0);
  pos += 2;  // Checksum (placeholder)
  pktWrite16(buf + pos, 0);
  pos += 2;  // Urgent pointer

  // TCP Option: MSS (kind=2, len=4, value=1460)
  buf[pos++] = 2;  // Kind: MSS
  buf[pos++] = 4;  // Length
  pktWrite16(buf + pos, 1460);
  pos += 2;  // MSS value

  // Calculate TCP checksum
  uint16_t cksum = tcpChecksum(srcIP, dstIP, buf + tcpStart, tcpLen);
  pktWrite16(buf + tcpStart + 16, cksum);

  return pos;
}

// ── Build a TCP SYN-ACK (server accepting connection) ──
uint16_t buildTcpSynAck(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                        const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort, uint32_t seqNum,
                        uint32_t ackNum) {
  uint16_t pos = 0;
  pos = buildEthHeader(buf, dstMAC, ETHERTYPE_IPV4);

  uint16_t tcpLen = 24;  // 20 header + 4 MSS option
  pos += buildIPv4Header(buf + pos, srcIP, dstIP, IP_PROTO_TCP, tcpLen);

  uint16_t tcpStart = pos;
  pktWrite16(buf + pos, srcPort);
  pos += 2;
  pktWrite16(buf + pos, dstPort);
  pos += 2;
  pktWrite32(buf + pos, seqNum);
  pos += 4;
  pktWrite32(buf + pos, ackNum);
  pos += 4;
  buf[pos++] = 0x60;  // Data offset: 6 (24 bytes)
  buf[pos++] = 0x12;  // Flags: SYN+ACK
  pktWrite16(buf + pos, 1460);
  pos += 2;  // Window (1 MSS)
  pktWrite16(buf + pos, 0);
  pos += 2;  // Checksum placeholder
  pktWrite16(buf + pos, 0);
  pos += 2;  // Urgent

  buf[pos++] = 2;  // MSS option kind
  buf[pos++] = 4;  // MSS option length
  pktWrite16(buf + pos, 1460);
  pos += 2;

  uint16_t cksum = tcpChecksum(srcIP, dstIP, buf + tcpStart, tcpLen);
  pktWrite16(buf + tcpStart + 16, cksum);
  return pos;
}

// ── Build a TCP FIN+ACK (graceful close) ──
uint16_t buildTcpFinAck(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                        const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort, uint32_t seqNum,
                        uint32_t ackNum) {
  uint16_t pos = 0;
  pos = buildEthHeader(buf, dstMAC, ETHERTYPE_IPV4);

  uint16_t tcpLen = 20;
  pos += buildIPv4Header(buf + pos, srcIP, dstIP, IP_PROTO_TCP, tcpLen);

  uint16_t tcpStart = pos;
  pktWrite16(buf + pos, srcPort);
  pos += 2;
  pktWrite16(buf + pos, dstPort);
  pos += 2;
  pktWrite32(buf + pos, seqNum);
  pos += 4;
  pktWrite32(buf + pos, ackNum);
  pos += 4;
  buf[pos++] = 0x50;  // Data offset: 5
  buf[pos++] = 0x11;  // Flags: FIN+ACK
  pktWrite16(buf + pos, 1460);
  pos += 2;
  pktWrite16(buf + pos, 0);
  pos += 2;
  pktWrite16(buf + pos, 0);
  pos += 2;

  uint16_t cksum = tcpChecksum(srcIP, dstIP, buf + tcpStart, tcpLen);
  pktWrite16(buf + tcpStart + 16, cksum);
  return pos;
}

// ── Build a TCP ACK packet (completing the handshake) ──
uint16_t buildTcpAck(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                     const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort, uint32_t seqNum,
                     uint32_t ackNum) {
  uint16_t pos = 0;
  pos = buildEthHeader(buf, dstMAC, ETHERTYPE_IPV4);

  uint16_t tcpLen = 20;  // no options
  pos += buildIPv4Header(buf + pos, srcIP, dstIP, IP_PROTO_TCP, tcpLen);

  uint16_t tcpStart = pos;
  pktWrite16(buf + pos, srcPort);
  pos += 2;
  pktWrite16(buf + pos, dstPort);
  pos += 2;
  pktWrite32(buf + pos, seqNum);
  pos += 4;
  pktWrite32(buf + pos, ackNum);
  pos += 4;
  buf[pos++] = 0x50;  // Data offset: 5 (20 bytes)
  buf[pos++] = 0x10;  // Flags: ACK
  pktWrite16(buf + pos, 65535);
  pos += 2;  // Window
  pktWrite16(buf + pos, 0);
  pos += 2;  // Checksum placeholder
  pktWrite16(buf + pos, 0);
  pos += 2;  // Urgent

  uint16_t cksum = tcpChecksum(srcIP, dstIP, buf + tcpStart, tcpLen);
  pktWrite16(buf + tcpStart + 16, cksum);
  return pos;
}

// ── Build a TCP PSH+ACK with payload (for sending HTTP probe, etc.) ──
uint16_t buildTcpDataPush(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                          const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort, uint32_t seqNum,
                          uint32_t ackNum, const uint8_t* payload, uint16_t payloadLen) {
  uint16_t pos = 0;
  pos = buildEthHeader(buf, dstMAC, ETHERTYPE_IPV4);

  uint16_t tcpLen = 20 + payloadLen;
  pos += buildIPv4Header(buf + pos, srcIP, dstIP, IP_PROTO_TCP, tcpLen);

  uint16_t tcpStart = pos;
  pktWrite16(buf + pos, srcPort);
  pos += 2;
  pktWrite16(buf + pos, dstPort);
  pos += 2;
  pktWrite32(buf + pos, seqNum);
  pos += 4;
  pktWrite32(buf + pos, ackNum);
  pos += 4;
  buf[pos++] = 0x50;  // Data offset: 5
  buf[pos++] = 0x18;  // Flags: PSH + ACK
  pktWrite16(buf + pos, 65535);
  pos += 2;
  pktWrite16(buf + pos, 0);
  pos += 2;  // Checksum placeholder
  pktWrite16(buf + pos, 0);
  pos += 2;

  // Copy payload
  memcpy(buf + pos, payload, payloadLen);
  pos += payloadLen;

  uint16_t cksum = tcpChecksum(srcIP, dstIP, buf + tcpStart, tcpLen);
  pktWrite16(buf + tcpStart + 16, cksum);
  return pos;
}

// ── Build a TCP RST to tear down connection ──
uint16_t buildTcpRst(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                     const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort, uint32_t seqNum) {
  uint16_t pos = 0;
  pos = buildEthHeader(buf, dstMAC, ETHERTYPE_IPV4);

  uint16_t tcpLen = 20;
  pos += buildIPv4Header(buf + pos, srcIP, dstIP, IP_PROTO_TCP, tcpLen);

  uint16_t tcpStart = pos;
  pktWrite16(buf + pos, srcPort);
  pos += 2;
  pktWrite16(buf + pos, dstPort);
  pos += 2;
  pktWrite32(buf + pos, seqNum);
  pos += 4;
  pktWrite32(buf + pos, 0);
  pos += 4;  // ack
  buf[pos++] = 0x50;
  buf[pos++] = 0x04;  // Flags: RST
  pktWrite16(buf + pos, 0);
  pos += 2;
  pktWrite16(buf + pos, 0);
  pos += 2;
  pktWrite16(buf + pos, 0);
  pos += 2;

  uint16_t cksum = tcpChecksum(srcIP, dstIP, buf + tcpStart, tcpLen);
  pktWrite16(buf + tcpStart + 16, cksum);
  return pos;
}

// ── Resolve target IP to MAC via ARP table or active ARP request ──
bool resolveMacForIP(const uint8_t* targetIP, uint8_t* outMAC) {
  // Check if on our subnet
  bool sameSubnet = true;
  for (int i = 0; i < 4; i++) {
    if ((targetIP[i] & ourSubnet[i]) != (ourIP[i] & ourSubnet[i])) {
      sameSubnet = false;
      break;
    }
  }

  const uint8_t* lookupIP = sameSubnet ? targetIP : ourGW;

  // Check ARP table first
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (arpTable[i].active && memcmp(arpTable[i].ip, lookupIP, 4) == 0) {
      memcpy(outMAC, arpTable[i].mac, 6);
      return true;
    }
  }

  // ARP resolve
  Serial.printf("  [SCAN] Resolving MAC for %u.%u.%u.%u...\n", lookupIP[0], lookupIP[1],
                lookupIP[2], lookupIP[3]);

  for (int attempt = 0; attempt < 3; attempt++) {
    sendArpRequest(lookupIP);
    uint32_t waitEnd = millis() + 500;
    while (millis() < waitEnd) {
      uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      if (rxSize == 0) {
        delay(5);
        continue;
      }
      uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (len > ETH_HEADER_LEN + 28 && pktRead16(packetBuf + ETH_TYPE) == ETHERTYPE_ARP) {
        const uint8_t* arp = packetBuf + ETH_HEADER_LEN;
        if (pktRead16(arp + 6) == 2 && memcmp(arp + 14, lookupIP, 4) == 0) {
          memcpy(outMAC, arp + 8, 6);
          if (idsEnabled)
            idsCheckArp(packetBuf, len);
          return true;
        }
      }
    }
  }
  return false;
}
