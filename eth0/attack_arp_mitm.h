// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// ARP-spoofing man-in-the-middle. Tells the victim that we have
// the gateway's IP, and tells the gateway that we have the
// victim's IP. The traffic in both directions then flows through
// us, where the capture loop sees it. mitmRestore() sends correct
// ARP replies on shutdown to fix the network.

#pragma once

#include <stdint.h>

extern bool     mitmActive;
extern uint8_t  mitmVictimIP[4];
extern uint8_t  mitmVictimMAC[6];
extern uint8_t  mitmGatewayMAC[6];
extern uint32_t mitmLastPoison;
extern uint32_t mitmPktCount;

// Send a unicast ARP reply with arbitrary sender/target fields
// (used for both poisoning and restoration).
void sendArpReply(const uint8_t* senderMAC, const uint8_t* senderIP, const uint8_t* targetMAC,
                  const uint8_t* targetIP);

// Lifecycle: start the attack against `victimIP`, stop it, send a
// fresh round of poison ARPs (called periodically from loop()),
// and restore the original ARP bindings.
void mitmStart(const uint8_t* victimIP);
void mitmStop();
void mitmSendPoison();
void mitmRestore();

// `mitm …` serial command dispatcher.
void parseMitmCommand(const char* cmd);
