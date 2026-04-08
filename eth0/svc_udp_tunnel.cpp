// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "svc_udp_tunnel.h"

#include <string.h>

#include <Arduino.h>
#include <esp_random.h>
#include <mbedtls/aes.h>

#include "config.h"
#include "eth_frame.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

bool     tunnelActive       = false;
uint8_t  tunnelPeerIP[4]    = {0};
uint8_t  tunnelKey[16]      = {0};
uint16_t tunnelPort         = TUNNEL_PORT;
uint32_t tunnelTxSeq        = 0;
uint32_t tunnelRxCount      = 0;
uint32_t tunnelTxCount      = 0;

// ══════════════════════════════════════════════════════════════
//  9. Encrypted UDP Tunnel (AES-128-CBC)
// ══════════════════════════════════════════════════════════════
// Point-to-point encrypted communication channel over UDP.
// Uses hardware-accelerated AES-128-CBC on ESP32-S3.
// Tunnel packet format: [2B magic][4B seq][16B IV][encrypted data]

void tunnelSendEncrypted(const uint8_t* data, uint16_t dataLen) {
  if (!tunnelActive || dataLen == 0)
    return;

  // Pad to 16-byte boundary (PKCS#7)
  uint8_t padLen = 16 - (dataLen % 16);
  uint16_t paddedLen = dataLen + padLen;
  if (paddedLen > TUNNEL_MTU) {
    Serial.println("[TUNNEL] Data too large");
    return;
  }

  // Build tunnel payload: magic(2) + seq(4) + IV(16) + encrypted
  uint8_t payload[TUNNEL_MTU + 64];
  uint16_t pos = 0;

  pktWrite16(payload + pos, TUNNEL_MAGIC);
  pos += 2;
  pktWrite32(payload + pos, tunnelTxSeq++);
  pos += 4;

  // Random IV
  uint8_t iv[16];
  for (int i = 0; i < 16; i++)
    iv[i] = (uint8_t)esp_random();
  memcpy(payload + pos, iv, 16);
  pos += 16;

  // Prepare plaintext with padding
  uint8_t plain[TUNNEL_MTU + 16];
  memcpy(plain, data, dataLen);
  for (uint8_t i = 0; i < padLen; i++)
    plain[dataLen + i] = padLen;

  // AES-128-CBC encrypt
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, tunnelKey, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, iv, plain, payload + pos);
  mbedtls_aes_free(&aes);
  pos += paddedLen;

  sendUDP(tunnelPeerIP, tunnelPort, (const char*)payload, pos);
  tunnelTxCount++;
}

void tunnelCheckIncoming(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN + 28)
    return;
  uint16_t etype = pktRead16(pkt + ETH_TYPE);
  if (etype != ETHERTYPE_IPV4)
    return;

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  if (ipHdr[9] != IP_PROTO_UDP)
    return;

  uint8_t ipHdrLen = (ipHdr[0] & 0x0F) * 4;
  const uint8_t* udpHdr = ipHdr + ipHdrLen;
  uint16_t dstPort = pktRead16(udpHdr + 2);
  if (dstPort != tunnelPort)
    return;

  const uint8_t* srcIP = ipHdr + 12;
  if (memcmp(srcIP, ourIP, 4) == 0)
    return;
  if (memcmp(pkt + ETH_SRC_MAC, mac, 6) == 0)
    return;

  uint16_t udpLen = pktRead16(udpHdr + 4);
  if (udpLen < 8 + 22 + 16)
    return;  // min: header(8) + magic(2)+seq(4)+iv(16) + 1 block

  const uint8_t* payload = udpHdr + 8;
  uint16_t payloadLen = udpLen - 8;

  // Verify magic
  if (pktRead16(payload) != TUNNEL_MAGIC)
    return;

  uint32_t seq = pktRead32(payload + 2);
  uint8_t iv[16];
  memcpy(iv, payload + 6, 16);

  const uint8_t* encrypted = payload + 22;
  uint16_t encLen = payloadLen - 22;
  if (encLen == 0 || (encLen % 16) != 0)
    return;

  // AES-128-CBC decrypt
  uint8_t decrypted[TUNNEL_MTU + 16];
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, tunnelKey, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encLen, iv, encrypted, decrypted);
  mbedtls_aes_free(&aes);

  // Remove PKCS#7 padding
  uint8_t padVal = decrypted[encLen - 1];
  if (padVal == 0 || padVal > 16)
    return;
  uint16_t plainLen = encLen - padVal;

  // Null-terminate for display
  if (plainLen < sizeof(decrypted))
    decrypted[plainLen] = '\0';

  tunnelRxCount++;
  Serial.printf("[TUNNEL] #%u from %u.%u.%u.%u: %.*s\n", seq, srcIP[0], srcIP[1], srcIP[2],
                srcIP[3], (int)plainLen, (char*)decrypted);
}

void parseTunnelCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "start", 5) == 0) {
    cmd += 5;
    while (*cmd == ' ')
      cmd++;

    // Parse: IP key_hex
    char ipStr[20];
    const char* space = strchr(cmd, ' ');
    if (!space) {
      Serial.println("[TUNNEL] Usage: tunnel start X.X.X.X <32-char-hex-key>");
      return;
    }
    int ipLen = space - cmd;
    if (ipLen <= 0 || ipLen >= (int)sizeof(ipStr)) {
      Serial.println("[TUNNEL] Invalid IP");
      return;
    }
    memcpy(ipStr, cmd, ipLen);
    ipStr[ipLen] = '\0';
    if (!parseIP(ipStr, tunnelPeerIP)) {
      Serial.println("[TUNNEL] Invalid IP");
      return;
    }

    // Parse hex key (32 hex chars = 16 bytes)
    const char* keyStr = space + 1;
    while (*keyStr == ' ')
      keyStr++;
    int keyIdx = 0;
    for (int i = 0; keyStr[i] && keyStr[i + 1] && keyIdx < 16; i += 2) {
      int hi = hexCharToVal(keyStr[i]);
      int lo = hexCharToVal(keyStr[i + 1]);
      if (hi < 0 || lo < 0) {
        Serial.println("[TUNNEL] Invalid key. Use 32 hex characters.");
        return;
      }
      tunnelKey[keyIdx++] = (hi << 4) | lo;
    }
    if (keyIdx < 16) {
      Serial.println("[TUNNEL] Key too short. Need 32 hex chars (128-bit).");
      return;
    }

    tunnelActive = true;
    tunnelTxSeq = 0;
    tunnelRxCount = 0;
    tunnelTxCount = 0;

    Serial.printf("[TUNNEL] ACTIVE — peer %u.%u.%u.%u port %u\n", tunnelPeerIP[0], tunnelPeerIP[1],
                  tunnelPeerIP[2], tunnelPeerIP[3], tunnelPort);
    Serial.println("[TUNNEL] Type 'tunnel send <message>' to send encrypted data");
  } else if (strncmp(cmd, "send", 4) == 0) {
    cmd += 4;
    while (*cmd == ' ')
      cmd++;
    if (!tunnelActive) {
      Serial.println("[TUNNEL] Not active. Start first.");
      return;
    }
    tunnelSendEncrypted((const uint8_t*)cmd, strlen(cmd));
    Serial.printf("[TUNNEL] Sent (%u bytes encrypted)\n", (unsigned)strlen(cmd));
  } else if (strncmp(cmd, "stop", 4) == 0) {
    tunnelActive = false;
    Serial.printf("[TUNNEL] Stopped. TX: %u  RX: %u\n", tunnelTxCount, tunnelRxCount);
  } else if (strncmp(cmd, "port", 4) == 0) {
    cmd += 4;
    while (*cmd == ' ')
      cmd++;
    int p = atoi(cmd);
    if (p > 0 && p <= 65535) {
      tunnelPort = (uint16_t)p;
      Serial.printf("[TUNNEL] Port set to %u\n", tunnelPort);
    }
  } else {
    Serial.printf("[TUNNEL] %s", tunnelActive ? "ACTIVE" : "Inactive");
    if (tunnelActive)
      Serial.printf(" — peer %u.%u.%u.%u:%u  TX:%u RX:%u", tunnelPeerIP[0], tunnelPeerIP[1],
                    tunnelPeerIP[2], tunnelPeerIP[3], tunnelPort, tunnelTxCount, tunnelRxCount);
    Serial.println();
    Serial.println("  tunnel start IP KEY  - start (KEY = 32 hex chars)");
    Serial.println("  tunnel send message  - send encrypted message");
    Serial.println("  tunnel port N        - change port (default 9998)");
    Serial.println("  tunnel stop          - disconnect");
  }
}
