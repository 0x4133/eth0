// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// DNS covert channel. Encodes data as base32-encoded subdomains in
// outbound DNS A queries to a controlled nameserver. The data is
// carried in the QNAME itself; the server logs the queries and
// reassembles the original payload.

#pragma once

#include <stdint.h>

extern bool     covertActive;
extern uint8_t  covertServerIP[4];
extern char     covertDomain[64];
extern uint32_t covertSeq;
extern uint32_t covertSentCount;

void covertDnsSend(const char* data, uint16_t dataLen);
void parseCovertCommand(const char* cmd);
