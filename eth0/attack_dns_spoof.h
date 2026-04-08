// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// DNS spoofing engine. Intercepts DNS queries on the wire and
// races the real nameserver with a forged response that points the
// queried name at our chosen IP. Works best in combination with
// ARP MitM (so the victim's DNS queries actually flow through us).

#pragma once

#include <stdint.h>

#include "config.h"

struct DnsSpoofRule {
  char     domain[DNSSPOOF_MAX_DOMAIN];  // domain to match ("*" = all)
  uint8_t  spoofIP[4];                    // IP to respond with
  bool     active;
  uint32_t hitCount;
};

extern DnsSpoofRule dnsSpoofRules[DNSSPOOF_MAX_RULES];
extern bool         dnsSpoofEnabled;
extern uint32_t     dnsSpoofTotal;

void dnsSpoofInitRules();
bool dnsSpoofMatchDomain(const char* decoded, const char* rule);
void dnsSpoofSendResponse(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen,
                          const uint8_t* spoofIP);
void dnsSpoofCheck(const uint8_t* pkt, uint16_t len);
void parseDnsSpoofCommand(const char* cmd);
