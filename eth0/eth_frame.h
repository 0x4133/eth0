// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Ethernet/IPv4/TCP wire-format constants, byte-order helpers, and
// frame builders. Called from capture, injection, recon, and attack
// modules — keep the API narrow and free of global state except
// what state.h declares.

#pragma once

#include <stdint.h>

// ── Ethernet frame offsets ──
#define ETH_DST_MAC    0
#define ETH_SRC_MAC    6
#define ETH_TYPE       12
#define ETH_HEADER_LEN 14

// ── EtherTypes ──
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV6 0x86DD

// ── IP protocol numbers ──
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

// ── Byte-order helpers (network = big-endian) ──
//
// Declared static inline so each translation unit that includes this
// header gets its own copy and the compiler can inline the call. No
// ODR concerns — the definitions are identical everywhere.

static inline uint16_t pktRead16(const uint8_t* p) {
  return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t pktRead32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static inline void pktWrite16(uint8_t* p, uint16_t val) {
  p[0] = (val >> 8) & 0xFF;
  p[1] = val & 0xFF;
}

static inline void pktWrite32(uint8_t* p, uint32_t val) {
  p[0] = (val >> 24) & 0xFF;
  p[1] = (val >> 16) & 0xFF;
  p[2] = (val >> 8) & 0xFF;
  p[3] = val & 0xFF;
}

// ── Checksums ──

// IPv4 header checksum (RFC 1071). Sums `len` bytes of `data` as
// 16-bit big-endian words, folds carry, returns the one's complement.
uint16_t ipChecksum(const uint8_t* data, uint16_t len);

// TCP checksum over the pseudo-header (srcIP, dstIP, proto, tcpLen)
// and the TCP segment. `tcpSeg` points to the start of the TCP header;
// `tcpLen` is header + data.
uint16_t tcpChecksum(const uint8_t* srcIP, const uint8_t* dstIP, const uint8_t* tcpSeg,
                     uint16_t tcpLen);

// ── Frame builders ──

// Writes a 14-byte Ethernet II header at `buf`. Uses the global
// source MAC from state.h. Returns ETH_HEADER_LEN.
uint16_t buildEthHeader(uint8_t* buf, const uint8_t* dstMAC, uint16_t ethertype);

// Writes a 20-byte IPv4 header at `buf` with the given source,
// destination, protocol and payload length. Fills in the header
// checksum. Returns 20.
uint16_t buildIPv4Header(uint8_t* buf, const uint8_t* srcIP, const uint8_t* dstIP, uint8_t protocol,
                         uint16_t payloadLen);
