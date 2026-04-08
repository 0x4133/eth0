// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Two output sinks for captured packets that complement PCAP-on-SD:
//
//   hexdumpPacket()    — human-readable hex+ASCII dump to Serial,
//                        for live debugging.
//   pcapSerialPacket() — binary PCAP record on Serial, for live
//                        Wireshark via the Web Serial UI bridge.
//
// Both are gated by the booleans below; the capture loop checks
// them on every frame.

#pragma once

#include <stdint.h>

extern bool hexdumpEnabled;
extern bool hexdumpPcapSerial;

void hexdumpPacket(const uint8_t* pkt, uint16_t len);
void pcapSerialPacket(const uint8_t* pkt, uint16_t len);
void parseHexdumpCommand(const char* cmd);
