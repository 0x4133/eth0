// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Packet injection: build common Ethernet/IPv4 frames and push them
// out via the W5500 MACRAW socket. The send-helpers (sendArpRequest,
// sendPing, sendUDP, sendRawHex) are user-facing — they correspond
// 1:1 with the `send …` serial commands. The buildTcp* helpers are
// used by the recon and attack modules to fabricate TCP segments
// without involving the W5500's TCP socket state machine.

#pragma once

#include <stdint.h>

// ── Low-level transmit ──

// Push a fully-formed Ethernet frame onto the wire via the MACRAW
// socket. Returns the number of bytes written, or 0 on failure
// (W5500 timeout, oversize frame, empty frame).
uint16_t sendRawFrame(const uint8_t* frame, uint16_t len);

// ── High-level send helpers ──

// Broadcast an ARP "who-has" request for `targetIP`. Echoes the
// outcome to Serial.
void sendArpRequest(const uint8_t* targetIP);

// Send an ICMP echo request to `targetIP` with a 32-byte 'A'-'Z'
// repeating payload. Echoes the outcome to Serial.
void sendPing(const uint8_t* targetIP);

// Send a UDP packet with arbitrary payload. Resolves the destination
// MAC via the ARP table; falls back to broadcast if not cached. If
// the target is off-subnet, looks up the gateway MAC instead.
void sendUDP(const uint8_t* targetIP, uint16_t dstPort, const char* payload, uint16_t payloadLen);

// Parse a hex string ("aa bb:cc-dd…") into a raw Ethernet frame and
// transmit it. Pads to the 60-byte minimum. Echoes the outcome to
// Serial.
void sendRawHex(const char* hexStr);

// Convert a single hex character to its 0-15 numeric value, or -1
// on a non-hex character.
int hexCharToVal(char c);

// ── TCP frame builders ──
//
// These build complete Ethernet+IPv4+TCP frames into `buf` and
// return the total frame length. The TCP checksum (computed over
// the pseudo-header) is filled in. They do NOT call sendRawFrame —
// the caller decides when and how to transmit.

uint16_t buildTcpSyn(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                     const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort);

uint16_t buildTcpSynAck(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                        const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort, uint32_t seqNum,
                        uint32_t ackNum);

uint16_t buildTcpFinAck(uint8_t* buf, const uint8_t* dstMAC, const uint8_t* srcIP,
                        const uint8_t* dstIP, uint16_t srcPort, uint16_t dstPort, uint32_t seqNum,
                        uint32_t ackNum);
