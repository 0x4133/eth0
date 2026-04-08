// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Minimal RFC 1459 IRC server, implemented entirely on top of the
// W5500 MACRAW socket. We don't use the Ethernet2 TCP stack — we
// hand-craft the SYN/SYN-ACK/ACK exchange and then track sequence
// numbers per client. Supports up to IRC_MAX_CLIENTS connected
// clients across IRC_MAX_CHANNELS channels.

#pragma once

#include <stdint.h>

#include "config.h"

enum IrcTcpState : uint8_t {
  IRC_TCP_FREE = 0,
  IRC_TCP_SYN_RCVD,
  IRC_TCP_ESTABLISHED,
  IRC_TCP_CLOSING,
};

enum IrcRegState : uint8_t {
  IRC_REG_NONE = 0,
  IRC_REG_NICK = 1,
  IRC_REG_USER = 2,
  IRC_REG_DONE = 3,
};

struct IrcClient {
  IrcTcpState tcpState;
  IrcRegState regState;
  uint8_t     peerMAC[6];
  uint8_t     peerIP[4];
  uint16_t    peerPort;
  uint32_t    mySeq;
  uint32_t    myAck;
  uint32_t    lastActivity;
  uint32_t    lastPingSent;
  bool        pongPending;
  char        nick[IRC_NICK_LEN];
  char        user[IRC_NICK_LEN];
  uint8_t     channels;  // bitmask of joined channels
  char        lineBuf[IRC_LINE_BUF];
  uint16_t    linePos;
};

struct IrcChannel {
  bool    active;
  char    name[IRC_CHAN_LEN];
  uint8_t memberMask;  // bitmask of client indices
};

// State exposed via extern only because the capture loop checks
// `ircServerActive` and the connection state on every frame.
extern IrcClient  ircClients[IRC_MAX_CLIENTS];
extern IrcChannel ircChannels[IRC_MAX_CHANNELS];
extern bool       ircServerActive;

// Lifecycle and per-loop tick.
void parseIrcCommand(const char* cmd);
void ircStart();
void ircStop();
void ircStatus();
void ircTick();

// Called from the capture loop on every received frame.
void ircCheckIncomingTcp(const uint8_t* pkt, uint16_t len);

// Internal IRC protocol helpers (exposed because they're declared
// in eth0.ino's existing forward-decl block; could become file-
// static in Phase 8).
void ircSendToClient(uint8_t idx, const char* data, uint16_t len);
void ircSendLine(uint8_t idx, const char* fmt, ...);
void ircBroadcastChannel(uint8_t chanIdx, uint8_t exceptClient, const char* fmt, ...);
void ircProcessLine(uint8_t idx, char* line);
void ircDisconnect(uint8_t idx, const char* reason);
void ircSendWelcome(uint8_t idx);
