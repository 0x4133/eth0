// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "svc_irc.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <Arduino.h>
#include <esp_random.h>

#include "config.h"
#include "eth_frame.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

IrcClient  ircClients[IRC_MAX_CLIENTS];
IrcChannel ircChannels[IRC_MAX_CHANNELS];
bool       ircServerActive = false;

// ══════════════════════════════════════════════════════════════
//  IRC Server — minimal RFC 1459 over raw TCP
// ══════════════════════════════════════════════════════════════

// Send a gratuitous ARP reply announcing our IP→MAC binding
void sendGratuitousArp() {
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint16_t pos = 0;
  pos = buildEthHeader(txBuf, broadcast, ETHERTYPE_ARP);

  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;
  pktWrite16(txBuf + pos, 0x0800);
  pos += 2;
  txBuf[pos++] = 6;
  txBuf[pos++] = 4;
  pktWrite16(txBuf + pos, 0x0002);
  pos += 2;
  memcpy(txBuf + pos, mac, 6);
  pos += 6;
  memcpy(txBuf + pos, ourIP, 4);
  pos += 4;
  memcpy(txBuf + pos, broadcast, 6);
  pos += 6;
  memcpy(txBuf + pos, ourIP, 4);
  pos += 4;
  while (pos < 60)
    txBuf[pos++] = 0;
  sendRawFrame(txBuf, pos);
}

// ── Find client by peer IP + port ──
static int8_t ircFindClient(const uint8_t* ip, uint16_t port) {
  for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
    if (ircClients[i].tcpState != IRC_TCP_FREE && memcmp(ircClients[i].peerIP, ip, 4) == 0 &&
        ircClients[i].peerPort == port)
      return i;
  }
  return -1;
}

// ── Find client by nick ──
static int8_t ircFindNick(const char* nick) {
  for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
    if (ircClients[i].tcpState == IRC_TCP_ESTABLISHED && ircClients[i].regState == IRC_REG_DONE &&
        strcasecmp(ircClients[i].nick, nick) == 0)
      return i;
  }
  return -1;
}

// ── Find channel by name ──
static int8_t ircFindChannel(const char* name) {
  for (uint8_t i = 0; i < IRC_MAX_CHANNELS; i++) {
    if (ircChannels[i].active && strcasecmp(ircChannels[i].name, name) == 0)
      return i;
  }
  return -1;
}

// ── Send raw TCP data to a connected client ──
void ircSendToClient(uint8_t idx, const char* data, uint16_t len) {
  IrcClient& c = ircClients[idx];
  if (c.tcpState != IRC_TCP_ESTABLISHED || len == 0)
    return;

  uint16_t frameLen = buildTcpDataPush(txBuf, c.peerMAC, ourIP, c.peerIP, IRC_PORT, c.peerPort,
                                       c.mySeq, c.myAck, (const uint8_t*)data, len);
  sendRawFrame(txBuf, frameLen);
  c.mySeq += len;
}

// ── Send a formatted IRC line to a client ──
void ircSendLine(uint8_t idx, const char* fmt, ...) {
  char buf[IRC_LINE_BUF];
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(buf, sizeof(buf) - 2, fmt, args);
  va_end(args);
  if (n < 0)
    return;
  if (n > (int)sizeof(buf) - 3)
    n = sizeof(buf) - 3;
  buf[n++] = '\r';
  buf[n++] = '\n';
  ircSendToClient(idx, buf, (uint16_t)n);
}

// ── Broadcast to all members of a channel (except one) ──
void ircBroadcastChannel(uint8_t chanIdx, uint8_t exceptClient, const char* fmt, ...) {
  char buf[IRC_LINE_BUF];
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(buf, sizeof(buf) - 2, fmt, args);
  va_end(args);
  if (n < 0)
    return;
  if (n > (int)sizeof(buf) - 3)
    n = sizeof(buf) - 3;
  buf[n++] = '\r';
  buf[n++] = '\n';

  uint8_t mask = ircChannels[chanIdx].memberMask;
  for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
    if (i != exceptClient && (mask & (1 << i)) && ircClients[i].tcpState == IRC_TCP_ESTABLISHED) {
      ircSendToClient(i, buf, (uint16_t)n);
    }
  }
}

// ── Broadcast to all channels a client is in (for QUIT, etc.) ──
static void ircBroadcastAllChannels(uint8_t idx, const char* fmt, ...) {
  char buf[IRC_LINE_BUF];
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(buf, sizeof(buf) - 2, fmt, args);
  va_end(args);
  if (n < 0)
    return;
  if (n > (int)sizeof(buf) - 3)
    n = sizeof(buf) - 3;
  buf[n++] = '\r';
  buf[n++] = '\n';

  // Collect all clients in shared channels, excluding sender
  uint8_t sentMask = 0;
  for (uint8_t ch = 0; ch < IRC_MAX_CHANNELS; ch++) {
    if (!ircChannels[ch].active || !(ircChannels[ch].memberMask & (1 << idx)))
      continue;
    uint8_t members = ircChannels[ch].memberMask;
    for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
      if (i != idx && (members & (1 << i)) && !(sentMask & (1 << i)) &&
          ircClients[i].tcpState == IRC_TCP_ESTABLISHED) {
        ircSendToClient(i, buf, (uint16_t)n);
        sentMask |= (1 << i);
      }
    }
  }
}

// ── Send IRC welcome numerics ──
void ircSendWelcome(uint8_t idx) {
  IrcClient& c = ircClients[idx];
  ircSendLine(idx, ":%s 001 %s :Welcome to the %s IRC network, %s!%s@%u.%u.%u.%u", IRC_SERVER_NAME,
              c.nick, IRC_SERVER_NAME, c.nick, c.user, c.peerIP[0], c.peerIP[1], c.peerIP[2],
              c.peerIP[3]);
  ircSendLine(idx, ":%s 002 %s :Your host is %s, running eth0-ircd v0.1", IRC_SERVER_NAME, c.nick,
              IRC_SERVER_NAME);
  ircSendLine(idx, ":%s 003 %s :This server was created on an ESP32-S3", IRC_SERVER_NAME, c.nick);
  ircSendLine(idx, ":%s 004 %s %s eth0-ircd-0.1 o o", IRC_SERVER_NAME, c.nick, IRC_SERVER_NAME);
  ircSendLine(idx, ":%s 005 %s CHANTYPES=# NICKLEN=%d CHANMODES=,,,nt :are supported",
              IRC_SERVER_NAME, c.nick, IRC_NICK_LEN - 1);
  ircSendLine(idx, ":%s 375 %s :- %s Message of the Day -", IRC_SERVER_NAME, c.nick,
              IRC_SERVER_NAME);
  ircSendLine(idx, ":%s 372 %s :- ESP32-S3-ETH network security tool", IRC_SERVER_NAME, c.nick);
  ircSendLine(idx, ":%s 372 %s :- Running on raw W5500 MACRAW — no TCP stack", IRC_SERVER_NAME,
              c.nick);
  ircSendLine(idx, ":%s 372 %s :- Max %d clients, %d channels. Be kind.", IRC_SERVER_NAME, c.nick,
              IRC_MAX_CLIENTS, IRC_MAX_CHANNELS);
  ircSendLine(idx, ":%s 376 %s :End of /MOTD command", IRC_SERVER_NAME, c.nick);
}

// ── Disconnect a client ──
void ircDisconnect(uint8_t idx, const char* reason) {
  IrcClient& c = ircClients[idx];
  if (c.tcpState == IRC_TCP_FREE)
    return;

  // Notify shared channels
  if (c.regState == IRC_REG_DONE) {
    ircBroadcastAllChannels(idx, ":%s!%s@%u.%u.%u.%u QUIT :%s", c.nick, c.user, c.peerIP[0],
                            c.peerIP[1], c.peerIP[2], c.peerIP[3], reason);
  }

  // Remove from all channels
  for (uint8_t ch = 0; ch < IRC_MAX_CHANNELS; ch++) {
    ircChannels[ch].memberMask &= ~(1 << idx);
    if (ircChannels[ch].active && ircChannels[ch].memberMask == 0)
      ircChannels[ch].active = false;  // Auto-destroy empty channel
  }

  // Send ERROR and RST
  if (c.tcpState == IRC_TCP_ESTABLISHED) {
    char errMsg[128];
    int n = snprintf(errMsg, sizeof(errMsg), "ERROR :Closing Link: %s (%s)\r\n", c.nick, reason);
    if (n > 0)
      ircSendToClient(idx, errMsg, (uint16_t)n);
    delay(5);
    uint16_t f = buildTcpRst(txBuf, c.peerMAC, ourIP, c.peerIP, IRC_PORT, c.peerPort, c.mySeq);
    sendRawFrame(txBuf, f);
  }

  Serial.printf("[IRC] Client %u disconnected (%s): %s\n", idx, c.nick[0] ? c.nick : "unregistered",
                reason);

  memset(&c, 0, sizeof(IrcClient));
}

// ── Process one complete IRC line from a client ──
void ircProcessLine(uint8_t idx, char* line) {
  IrcClient& c = ircClients[idx];
  c.lastActivity = millis();

  // Strip trailing \r\n
  int len = strlen(line);
  while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n'))
    line[--len] = '\0';
  if (len == 0)
    return;

  // Skip optional prefix (messages from client shouldn't have one, but tolerate it)
  char* cmd = line;
  if (*cmd == ':') {
    cmd = strchr(cmd, ' ');
    if (!cmd)
      return;
    while (*cmd == ' ')
      cmd++;
  }

  // Extract command and params
  char* params = strchr(cmd, ' ');
  if (params) {
    *params = '\0';
    params++;
    while (*params == ' ')
      params++;
  }

  // ── CAP (capability negotiation — acknowledge and move on) ──
  if (strcasecmp(cmd, "CAP") == 0) {
    if (params && strncasecmp(params, "LS", 2) == 0) {
      ircSendLine(idx, ":%s CAP * LS :", IRC_SERVER_NAME);
    }
    // CAP END — just ignore, registration continues normally
    return;
  }

  // ── NICK ──
  if (strcasecmp(cmd, "NICK") == 0) {
    if (!params || !params[0]) {
      ircSendLine(idx, ":%s 431 * :No nickname given", IRC_SERVER_NAME);
      return;
    }
    // Truncate
    char newNick[IRC_NICK_LEN];
    strncpy(newNick, params, IRC_NICK_LEN - 1);
    newNick[IRC_NICK_LEN - 1] = '\0';

    // Check collision
    int8_t existing = ircFindNick(newNick);
    if (existing >= 0 && existing != idx) {
      ircSendLine(idx, ":%s 433 %s %s :Nickname is already in use", IRC_SERVER_NAME,
                  c.nick[0] ? c.nick : "*", newNick);
      return;
    }

    // If already registered, broadcast nick change
    if (c.regState == IRC_REG_DONE) {
      ircBroadcastAllChannels(idx, ":%s!%s@%u.%u.%u.%u NICK :%s", c.nick, c.user, c.peerIP[0],
                              c.peerIP[1], c.peerIP[2], c.peerIP[3], newNick);
      ircSendLine(idx, ":%s!%s@%u.%u.%u.%u NICK :%s", c.nick, c.user, c.peerIP[0], c.peerIP[1],
                  c.peerIP[2], c.peerIP[3], newNick);
    }

    strcpy(c.nick, newNick);
    c.regState = (IrcRegState)(c.regState | IRC_REG_NICK);

    if (c.regState == IRC_REG_DONE) {
      // First-time registration complete
      ircSendWelcome(idx);
      Serial.printf("[IRC] Client %u registered as %s\n", idx, c.nick);
    }
    return;
  }

  // ── USER ──
  if (strcasecmp(cmd, "USER") == 0) {
    if (c.regState & IRC_REG_USER)
      return;  // Ignore duplicate USER
    if (!params || !params[0]) {
      ircSendLine(idx, ":%s 461 %s USER :Not enough parameters", IRC_SERVER_NAME,
                  c.nick[0] ? c.nick : "*");
      return;
    }
    // Extract just the username (first token)
    char* space = strchr(params, ' ');
    if (space)
      *space = '\0';
    strncpy(c.user, params, IRC_NICK_LEN - 1);
    c.user[IRC_NICK_LEN - 1] = '\0';
    c.regState = (IrcRegState)(c.regState | IRC_REG_USER);

    if (c.regState == IRC_REG_DONE) {
      ircSendWelcome(idx);
      Serial.printf("[IRC] Client %u registered as %s\n", idx, c.nick);
    }
    return;
  }

  // ── PASS (accept and ignore — no auth) ──
  if (strcasecmp(cmd, "PASS") == 0)
    return;

  // ── Everything below requires registration ──
  if (c.regState != IRC_REG_DONE) {
    ircSendLine(idx, ":%s 451 * :You have not registered", IRC_SERVER_NAME);
    return;
  }

  // ── PING ──
  if (strcasecmp(cmd, "PING") == 0) {
    ircSendLine(idx, ":%s PONG %s :%s", IRC_SERVER_NAME, IRC_SERVER_NAME,
                params ? params : IRC_SERVER_NAME);
    return;
  }

  // ── PONG ──
  if (strcasecmp(cmd, "PONG") == 0) {
    c.pongPending = false;
    return;
  }

  // ── JOIN ──
  if (strcasecmp(cmd, "JOIN") == 0) {
    if (!params || params[0] != '#') {
      ircSendLine(idx, ":%s 403 %s %s :No such channel", IRC_SERVER_NAME, c.nick,
                  params ? params : "*");
      return;
    }
    char chanName[IRC_CHAN_LEN];
    strncpy(chanName, params, IRC_CHAN_LEN - 1);
    chanName[IRC_CHAN_LEN - 1] = '\0';
    // Strip anything after a space or comma (multi-channel JOIN)
    char* sep = strpbrk(chanName, " ,");
    if (sep)
      *sep = '\0';

    int8_t ci = ircFindChannel(chanName);
    if (ci < 0) {
      // Create new channel
      for (uint8_t i = 0; i < IRC_MAX_CHANNELS; i++) {
        if (!ircChannels[i].active) {
          ci = i;
          ircChannels[i].active = true;
          strncpy(ircChannels[i].name, chanName, IRC_CHAN_LEN - 1);
          ircChannels[i].name[IRC_CHAN_LEN - 1] = '\0';
          ircChannels[i].memberMask = 0;
          break;
        }
      }
      if (ci < 0) {
        ircSendLine(idx, ":%s 405 %s %s :You have joined too many channels", IRC_SERVER_NAME,
                    c.nick, chanName);
        return;
      }
    }

    // Already a member?
    if (ircChannels[ci].memberMask & (1 << idx))
      return;

    ircChannels[ci].memberMask |= (1 << idx);
    c.channels |= (1 << ci);

    // Broadcast JOIN to channel (including joiner)
    ircBroadcastChannel(ci, 255, ":%s!%s@%u.%u.%u.%u JOIN %s", c.nick, c.user, c.peerIP[0],
                        c.peerIP[1], c.peerIP[2], c.peerIP[3], ircChannels[ci].name);

    // Send topic (332) — no topic set
    ircSendLine(idx, ":%s 331 %s %s :No topic is set", IRC_SERVER_NAME, c.nick,
                ircChannels[ci].name);

    // Send names list (353 + 366)
    char names[256] = {0};
    uint16_t npos = 0;
    for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
      if ((ircChannels[ci].memberMask & (1 << i)) && ircClients[i].regState == IRC_REG_DONE) {
        if (npos > 0 && npos < sizeof(names) - IRC_NICK_LEN - 1)
          names[npos++] = ' ';
        int w = snprintf(names + npos, sizeof(names) - npos, "%s", ircClients[i].nick);
        if (w > 0)
          npos += w;
      }
    }
    ircSendLine(idx, ":%s 353 %s = %s :%s", IRC_SERVER_NAME, c.nick, ircChannels[ci].name, names);
    ircSendLine(idx, ":%s 366 %s %s :End of /NAMES list", IRC_SERVER_NAME, c.nick,
                ircChannels[ci].name);
    return;
  }

  // ── PART ──
  if (strcasecmp(cmd, "PART") == 0) {
    if (!params)
      return;
    char chanName[IRC_CHAN_LEN];
    strncpy(chanName, params, IRC_CHAN_LEN - 1);
    chanName[IRC_CHAN_LEN - 1] = '\0';
    char* sep = strpbrk(chanName, " ,");
    const char* reason = sep ? sep + 1 : "Leaving";
    if (sep)
      *sep = '\0';
    while (*reason == ' ' || *reason == ':')
      reason++;

    int8_t ci = ircFindChannel(chanName);
    if (ci < 0 || !(ircChannels[ci].memberMask & (1 << idx))) {
      ircSendLine(idx, ":%s 442 %s %s :You're not on that channel", IRC_SERVER_NAME, c.nick,
                  chanName);
      return;
    }

    ircBroadcastChannel(ci, 255, ":%s!%s@%u.%u.%u.%u PART %s :%s", c.nick, c.user, c.peerIP[0],
                        c.peerIP[1], c.peerIP[2], c.peerIP[3], ircChannels[ci].name, reason);

    ircChannels[ci].memberMask &= ~(1 << idx);
    c.channels &= ~(1 << ci);
    if (ircChannels[ci].memberMask == 0)
      ircChannels[ci].active = false;
    return;
  }

  // ── PRIVMSG / NOTICE ──
  if (strcasecmp(cmd, "PRIVMSG") == 0 || strcasecmp(cmd, "NOTICE") == 0) {
    if (!params)
      return;
    char* text = strchr(params, ' ');
    if (!text)
      return;
    *text++ = '\0';
    while (*text == ' ')
      text++;
    if (*text == ':')
      text++;

    if (params[0] == '#') {
      // Channel message
      int8_t ci = ircFindChannel(params);
      if (ci < 0 || !(ircChannels[ci].memberMask & (1 << idx))) {
        ircSendLine(idx, ":%s 404 %s %s :Cannot send to channel", IRC_SERVER_NAME, c.nick, params);
        return;
      }
      ircBroadcastChannel(ci, idx, ":%s!%s@%u.%u.%u.%u %s %s :%s", c.nick, c.user, c.peerIP[0],
                          c.peerIP[1], c.peerIP[2], c.peerIP[3], cmd, ircChannels[ci].name, text);
    } else {
      // Private message
      int8_t target = ircFindNick(params);
      if (target < 0) {
        ircSendLine(idx, ":%s 401 %s %s :No such nick/channel", IRC_SERVER_NAME, c.nick, params);
        return;
      }
      ircSendLine(target, ":%s!%s@%u.%u.%u.%u %s %s :%s", c.nick, c.user, c.peerIP[0], c.peerIP[1],
                  c.peerIP[2], c.peerIP[3], cmd, ircClients[target].nick, text);
    }
    return;
  }

  // ── WHO ──
  if (strcasecmp(cmd, "WHO") == 0) {
    if (params && params[0] == '#') {
      int8_t ci = ircFindChannel(params);
      if (ci >= 0) {
        for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
          if ((ircChannels[ci].memberMask & (1 << i)) && ircClients[i].regState == IRC_REG_DONE) {
            ircSendLine(idx, ":%s 352 %s %s %s %u.%u.%u.%u %s H :0 %s", IRC_SERVER_NAME, c.nick,
                        ircChannels[ci].name, ircClients[i].user, ircClients[i].peerIP[0],
                        ircClients[i].peerIP[1], ircClients[i].peerIP[2], ircClients[i].peerIP[3],
                        ircClients[i].nick, ircClients[i].user);
          }
        }
      }
    }
    ircSendLine(idx, ":%s 315 %s %s :End of WHO list", IRC_SERVER_NAME, c.nick,
                params ? params : "*");
    return;
  }

  // ── WHOIS ──
  if (strcasecmp(cmd, "WHOIS") == 0) {
    if (!params)
      return;
    int8_t target = ircFindNick(params);
    if (target >= 0) {
      IrcClient& t = ircClients[target];
      ircSendLine(idx, ":%s 311 %s %s %s %u.%u.%u.%u * :%s", IRC_SERVER_NAME, c.nick, t.nick,
                  t.user, t.peerIP[0], t.peerIP[1], t.peerIP[2], t.peerIP[3], t.user);
    } else {
      ircSendLine(idx, ":%s 401 %s %s :No such nick", IRC_SERVER_NAME, c.nick, params);
    }
    ircSendLine(idx, ":%s 318 %s %s :End of WHOIS list", IRC_SERVER_NAME, c.nick, params);
    return;
  }

  // ── MODE ──
  if (strcasecmp(cmd, "MODE") == 0) {
    if (!params)
      return;
    if (params[0] == '#') {
      ircSendLine(idx, ":%s 324 %s %s +nt", IRC_SERVER_NAME, c.nick, params);
    } else {
      ircSendLine(idx, ":%s 221 %s +i", IRC_SERVER_NAME, c.nick);
    }
    return;
  }

  // ── QUIT ──
  if (strcasecmp(cmd, "QUIT") == 0) {
    const char* reason = (params && *params == ':') ? params + 1
                                                    : (params ? params : "Client Quit");
    ircDisconnect(idx, reason);
    return;
  }

  // ── USERHOST (some clients send this) ──
  if (strcasecmp(cmd, "USERHOST") == 0) {
    if (params) {
      int8_t target = ircFindNick(params);
      if (target >= 0) {
        ircSendLine(idx, ":%s 302 %s :%s=+%s@%u.%u.%u.%u", IRC_SERVER_NAME, c.nick,
                    ircClients[target].nick, ircClients[target].user, ircClients[target].peerIP[0],
                    ircClients[target].peerIP[1], ircClients[target].peerIP[2],
                    ircClients[target].peerIP[3]);
      }
    }
    return;
  }

  // ── Unknown command ──
  ircSendLine(idx, ":%s 421 %s %s :Unknown command", IRC_SERVER_NAME, c.nick, cmd);
}

// ── Handle incoming TCP packets for the IRC server ──
void ircCheckIncomingTcp(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN + 40)
    return;

  // Ignore our own frames (MACRAW echo)
  if (memcmp(pkt + ETH_SRC_MAC, mac, 6) == 0)
    return;

  uint16_t etype = pktRead16(pkt + ETH_TYPE);
  if (etype != ETHERTYPE_IPV4)
    return;

  const uint8_t* ipH = pkt + ETH_HEADER_LEN;
  if (ipH[9] != IP_PROTO_TCP)
    return;

  // Check destination is us
  if (memcmp(ipH + 16, ourIP, 4) != 0)
    return;

  uint8_t ihl = (ipH[0] & 0x0F) * 4;
  const uint8_t* tcpH = ipH + ihl;
  uint16_t dstPort = pktRead16(tcpH + 2);
  if (dstPort != IRC_PORT)
    return;

  uint16_t srcPort = pktRead16(tcpH);
  const uint8_t* srcIP = ipH + 12;
  uint32_t theirSeq = pktRead32(tcpH + 4);
  uint32_t theirAck = pktRead32(tcpH + 8);
  uint8_t flags = tcpH[13];
  uint8_t tcpHdrLen = ((tcpH[12] >> 4) & 0x0F) * 4;
  uint16_t ipTotalLen = pktRead16(ipH + 2);
  int payloadLen = ipTotalLen - ihl - tcpHdrLen;
  if (payloadLen < 0)
    payloadLen = 0;

  // ── RST: immediately free slot ──
  if (flags & 0x04) {
    int8_t ci = ircFindClient(srcIP, srcPort);
    if (ci >= 0) {
      Serial.printf("[IRC] Client %u RST from %u.%u.%u.%u\n", ci, srcIP[0], srcIP[1], srcIP[2],
                    srcIP[3]);
      // Remove from channels without sending anything
      for (uint8_t ch = 0; ch < IRC_MAX_CHANNELS; ch++) {
        ircChannels[ch].memberMask &= ~(1 << ci);
        if (ircChannels[ch].active && ircChannels[ch].memberMask == 0)
          ircChannels[ch].active = false;
      }
      if (ircClients[ci].regState == IRC_REG_DONE) {
        ircBroadcastAllChannels(ci, ":%s!%s@%u.%u.%u.%u QUIT :Connection reset",
                                ircClients[ci].nick, ircClients[ci].user, srcIP[0], srcIP[1],
                                srcIP[2], srcIP[3]);
      }
      memset(&ircClients[ci], 0, sizeof(IrcClient));
    }
    return;
  }

  // ── SYN (new connection) ──
  if ((flags & 0x02) && !(flags & 0x10)) {
    // Find free slot
    int8_t freeSlot = -1;
    for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
      if (ircClients[i].tcpState == IRC_TCP_FREE) {
        freeSlot = i;
        break;
      }
    }
    if (freeSlot < 0) {
      // No room — send RST
      uint16_t f = buildTcpRst(txBuf, pkt + ETH_SRC_MAC, ourIP, srcIP, IRC_PORT, srcPort, 0);
      sendRawFrame(txBuf, f);
      return;
    }

    IrcClient& c = ircClients[freeSlot];
    memset(&c, 0, sizeof(IrcClient));
    memcpy(c.peerMAC, pkt + ETH_SRC_MAC, 6);
    memcpy(c.peerIP, srcIP, 4);
    c.peerPort = srcPort;
    c.mySeq = micros() ^ (srcPort << 16) ^ freeSlot;
    c.myAck = theirSeq + 1;  // SYN consumes 1 seq
    c.lastActivity = millis();
    c.tcpState = IRC_TCP_SYN_RCVD;

    uint16_t f = buildTcpSynAck(txBuf, c.peerMAC, ourIP, c.peerIP, IRC_PORT, c.peerPort, c.mySeq,
                                c.myAck);
    sendRawFrame(txBuf, f);
    c.mySeq++;  // Our SYN consumes 1 seq

    Serial.printf("[IRC] SYN from %u.%u.%u.%u:%u -> slot %d\n", srcIP[0], srcIP[1], srcIP[2],
                  srcIP[3], srcPort, freeSlot);
    return;
  }

  // ── Everything else requires an existing client ──
  int8_t ci = ircFindClient(srcIP, srcPort);
  if (ci < 0)
    return;
  IrcClient& c = ircClients[ci];

  // ── ACK completing handshake (SYN_RCVD -> ESTABLISHED) ──
  if (c.tcpState == IRC_TCP_SYN_RCVD && (flags & 0x10)) {
    c.tcpState = IRC_TCP_ESTABLISHED;
    c.lastActivity = millis();
    Serial.printf("[IRC] Client %u connected from %u.%u.%u.%u:%u\n", ci, c.peerIP[0], c.peerIP[1],
                  c.peerIP[2], c.peerIP[3], c.peerPort);
    // No data to process yet in the handshake ACK (usually)
    if (payloadLen == 0)
      return;
  }

  if (c.tcpState != IRC_TCP_ESTABLISHED)
    return;

  // ── FIN ──
  if (flags & 0x01) {
    c.myAck = theirSeq + payloadLen + 1;  // FIN consumes 1 seq
    uint16_t f = buildTcpAck(txBuf, c.peerMAC, ourIP, c.peerIP, IRC_PORT, c.peerPort, c.mySeq,
                             c.myAck);
    sendRawFrame(txBuf, f);

    if (c.regState == IRC_REG_DONE) {
      ircBroadcastAllChannels(ci, ":%s!%s@%u.%u.%u.%u QUIT :Connection closed", c.nick, c.user,
                              c.peerIP[0], c.peerIP[1], c.peerIP[2], c.peerIP[3]);
    }
    for (uint8_t ch = 0; ch < IRC_MAX_CHANNELS; ch++) {
      ircChannels[ch].memberMask &= ~(1 << ci);
      if (ircChannels[ch].active && ircChannels[ch].memberMask == 0)
        ircChannels[ch].active = false;
    }

    // Send FIN+ACK back
    f = buildTcpFinAck(txBuf, c.peerMAC, ourIP, c.peerIP, IRC_PORT, c.peerPort, c.mySeq, c.myAck);
    sendRawFrame(txBuf, f);

    Serial.printf("[IRC] Client %u FIN (%s)\n", ci, c.nick[0] ? c.nick : "unregistered");
    memset(&c, 0, sizeof(IrcClient));
    return;
  }

  // ── Data (PSH+ACK or ACK with payload) ──
  if (payloadLen > 0) {
    // Retransmission check: if we already ACKed past this seq, re-ACK but don't reprocess
    if (theirSeq < c.myAck) {
      uint16_t f = buildTcpAck(txBuf, c.peerMAC, ourIP, c.peerIP, IRC_PORT, c.peerPort, c.mySeq,
                               c.myAck);
      sendRawFrame(txBuf, f);
      return;
    }

    // Out-of-order: ignore (client will retransmit)
    if (theirSeq > c.myAck)
      return;

    const uint8_t* payload = tcpH + tcpHdrLen;

    // Append to line buffer
    for (int i = 0; i < payloadLen && c.linePos < IRC_LINE_BUF - 1; i++) {
      c.lineBuf[c.linePos++] = payload[i];
    }

    // ACK the data
    c.myAck = theirSeq + payloadLen;
    uint16_t f = buildTcpAck(txBuf, c.peerMAC, ourIP, c.peerIP, IRC_PORT, c.peerPort, c.mySeq,
                             c.myAck);
    sendRawFrame(txBuf, f);
    c.lastActivity = millis();

    // Process complete lines
    while (true) {
      char* nl = (char*)memchr(c.lineBuf, '\n', c.linePos);
      if (!nl)
        break;
      *nl = '\0';
      ircProcessLine(ci, c.lineBuf);
      // If client was disconnected during processing, bail
      if (c.tcpState == IRC_TCP_FREE)
        return;
      uint16_t consumed = (nl - c.lineBuf) + 1;
      uint16_t remaining = c.linePos - consumed;
      if (remaining > 0)
        memmove(c.lineBuf, nl + 1, remaining);
      c.linePos = remaining;
    }

    // Overflow protection: if buffer full with no newline, discard
    if (c.linePos >= IRC_LINE_BUF - 1)
      c.linePos = 0;
  }
}

// ── Periodic tick: ping timeouts, abandoned handshakes ──
void ircTick() {
  static uint32_t lastTick = 0;
  if (millis() - lastTick < 1000)
    return;
  lastTick = millis();

  for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
    IrcClient& c = ircClients[i];

    if (c.tcpState == IRC_TCP_SYN_RCVD) {
      if (millis() - c.lastActivity > IRC_HANDSHAKE_TMO) {
        memset(&c, 0, sizeof(IrcClient));
      }
      continue;
    }

    if (c.tcpState != IRC_TCP_ESTABLISHED)
      continue;

    // Send PING if idle
    if (!c.pongPending && (millis() - c.lastActivity > IRC_PING_INTERVAL)) {
      ircSendLine(i, "PING :%s", IRC_SERVER_NAME);
      c.pongPending = true;
      c.lastPingSent = millis();
    }

    // Disconnect if PONG timeout
    if (c.pongPending && (millis() - c.lastPingSent > IRC_PONG_TIMEOUT)) {
      ircDisconnect(i, "Ping timeout");
    }
  }
}

// ── Serial command: irc start/stop/status ──
void parseIrcCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "start", 5) == 0) {
    ircStart();
  } else if (strncmp(cmd, "stop", 4) == 0) {
    ircStop();
  } else if (strncmp(cmd, "status", 6) == 0) {
    ircStatus();
  } else {
    Serial.println("[IRC] Usage:");
    Serial.println("  irc start    Start IRC server on port 6667");
    Serial.println("  irc stop     Stop IRC server");
    Serial.println("  irc status   Show connected clients");
  }
}

void ircStart() {
  memset(ircClients, 0, sizeof(ircClients));
  memset(ircChannels, 0, sizeof(ircChannels));
  ircServerActive = true;
  sendGratuitousArp();

  Serial.println("[IRC] Server listening on port 6667");
  Serial.printf("[IRC] Max %d clients, %d channels\n", IRC_MAX_CLIENTS, IRC_MAX_CHANNELS);
  Serial.printf("[IRC] Host: %u.%u.%u.%u\n", ourIP[0], ourIP[1], ourIP[2], ourIP[3]);
}

void ircStop() {
  for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
    if (ircClients[i].tcpState == IRC_TCP_ESTABLISHED) {
      ircDisconnect(i, "Server shutting down");
    } else if (ircClients[i].tcpState != IRC_TCP_FREE) {
      memset(&ircClients[i], 0, sizeof(IrcClient));
    }
  }
  memset(ircChannels, 0, sizeof(ircChannels));
  ircServerActive = false;
  Serial.println("[IRC] Server stopped.");
}

void ircStatus() {
  if (!ircServerActive) {
    Serial.println("[IRC] Server is not running.");
    return;
  }
  Serial.println("[IRC] Server status:");
  Serial.printf("[IRC] Listening on %u.%u.%u.%u:%u\n", ourIP[0], ourIP[1], ourIP[2], ourIP[3],
                IRC_PORT);

  uint8_t count = 0;
  for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++) {
    IrcClient& c = ircClients[i];
    if (c.tcpState == IRC_TCP_FREE)
      continue;
    count++;
    uint32_t idle = (millis() - c.lastActivity) / 1000;
    Serial.printf("[IRC]   [%u] %u.%u.%u.%u:%u  %s  state=%s  idle=%lus", i, c.peerIP[0],
                  c.peerIP[1], c.peerIP[2], c.peerIP[3], c.peerPort, c.nick[0] ? c.nick : "(none)",
                  c.tcpState == IRC_TCP_SYN_RCVD ? "SYN_RCVD" : "ESTABLISHED", idle);
    if (c.channels) {
      Serial.printf("  chans:");
      for (uint8_t ch = 0; ch < IRC_MAX_CHANNELS; ch++) {
        if (c.channels & (1 << ch) && ircChannels[ch].active)
          Serial.printf(" %s", ircChannels[ch].name);
      }
    }
    Serial.println();
  }

  if (count == 0)
    Serial.println("[IRC]   (no clients connected)");

  for (uint8_t ch = 0; ch < IRC_MAX_CHANNELS; ch++) {
    if (!ircChannels[ch].active)
      continue;
    uint8_t members = 0;
    for (uint8_t i = 0; i < IRC_MAX_CLIENTS; i++)
      if (ircChannels[ch].memberMask & (1 << i))
        members++;
    Serial.printf("[IRC]   Channel %s: %u members\n", ircChannels[ch].name, members);
  }
}
