// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Encrypted UDP tunnel. Point-to-point AES-128-CBC channel over
// UDP, using hardware-accelerated AES on the ESP32-S3.

#pragma once

#include <stdint.h>

extern bool     tunnelActive;
extern uint8_t  tunnelPeerIP[4];
extern uint8_t  tunnelKey[16];
extern uint16_t tunnelPort;
extern uint32_t tunnelTxSeq;
extern uint32_t tunnelRxCount;
extern uint32_t tunnelTxCount;

void tunnelSendEncrypted(const uint8_t* data, uint16_t dataLen);
void tunnelCheckIncoming(const uint8_t* pkt, uint16_t len);
void parseTunnelCommand(const char* cmd);
