// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "hexdump.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "eth_frame.h"
#include "pcap_writer.h"

bool hexdumpEnabled    = false;  // live hex output of captured packets
bool hexdumpPcapSerial = false;  // binary PCAP stream over serial

void hexdumpPacket(const uint8_t* pkt, uint16_t len) {
  // Header line with packet info
  uint16_t etype = (len >= ETH_HEADER_LEN) ? pktRead16(pkt + ETH_TYPE) : 0;
  Serial.printf("\n[HEX] ── Packet #%u (%u bytes) EtherType=0x%04X ──\n", packetCount, len, etype);

  for (uint16_t offset = 0; offset < len; offset += HEXDUMP_BYTES_PER_LINE) {
    // Offset
    Serial.printf("  %04X  ", offset);

    // Hex bytes
    for (uint16_t i = 0; i < HEXDUMP_BYTES_PER_LINE; i++) {
      if (offset + i < len)
        Serial.printf("%02X ", pkt[offset + i]);
      else
        Serial.print("   ");
      if (i == 7)
        Serial.print(" ");  // mid-line gap
    }

    Serial.print(" |");

    // ASCII
    for (uint16_t i = 0; i < HEXDUMP_BYTES_PER_LINE && (offset + i) < len; i++) {
      uint8_t c = pkt[offset + i];
      Serial.print((c >= 0x20 && c < 0x7F) ? (char)c : '.');
    }

    Serial.println("|");
  }
}

// Binary PCAP stream over serial — Wireshark can read this via:
//   socat - TCP-LISTEN:19000 | wireshark -k -i -
// or pipe directly. We send raw PCAP packet headers + data.
// The global header must be sent once when enabled.
void pcapSerialSendGlobalHeader() {
  // Send PCAP global header (24 bytes)
  uint8_t ghdr[24];
  // magic
  ghdr[0] = 0xD4;
  ghdr[1] = 0xC3;
  ghdr[2] = 0xB2;
  ghdr[3] = 0xA1;
  // version 2.4
  ghdr[4] = 0x02;
  ghdr[5] = 0x00;
  ghdr[6] = 0x04;
  ghdr[7] = 0x00;
  // thiszone, sigfigs
  memset(ghdr + 8, 0, 8);
  // snaplen
  ghdr[16] = 0xEA;
  ghdr[17] = 0x05;
  ghdr[18] = 0x00;
  ghdr[19] = 0x00;  // 1514
  // network (Ethernet)
  ghdr[20] = 0x01;
  ghdr[21] = 0x00;
  ghdr[22] = 0x00;
  ghdr[23] = 0x00;
  Serial.write(ghdr, 24);
}

void pcapSerialPacket(const uint8_t* pkt, uint16_t len) {
  // PCAP packet header (16 bytes, little-endian)
  uint32_t ms = millis();
  uint32_t sec = ms / 1000;
  uint32_t usec = (ms % 1000) * 1000;

  uint8_t phdr[16];
  memcpy(phdr + 0, &sec, 4);
  memcpy(phdr + 4, &usec, 4);
  memcpy(phdr + 8, &len, 4);   // incl_len (little-endian on ESP32)
  memcpy(phdr + 12, &len, 4);  // orig_len

  Serial.write(phdr, 16);
  Serial.write(pkt, len);
}

void parseHexdumpCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "pcap", 4) == 0) {
    cmd += 4;
    while (*cmd == ' ')
      cmd++;

    if (strncmp(cmd, "on", 2) == 0) {
      hexdumpEnabled = false;  // disable text hexdump to avoid mixing
      hexdumpPcapSerial = true;
      pcapSerialSendGlobalHeader();
      // No serial print after this — it would corrupt the PCAP stream
    } else if (strncmp(cmd, "off", 3) == 0) {
      hexdumpPcapSerial = false;
      Serial.println("[HEXDUMP] PCAP serial stream stopped");
    } else {
      Serial.printf("[HEXDUMP] PCAP serial: %s\n", hexdumpPcapSerial ? "ON" : "OFF");
      Serial.println("  hexdump pcap on   - start binary PCAP stream");
      Serial.println("  hexdump pcap off  - stop stream");
      Serial.println("  Pipe to Wireshark: cat /dev/ttyUSBx | wireshark -k -i -");
    }
    return;
  }

  if (strncmp(cmd, "on", 2) == 0) {
    hexdumpEnabled = true;
    hexdumpPcapSerial = false;  // disable binary to avoid conflict
    Serial.println("[HEXDUMP] Live hex dump ENABLED");
    Serial.println("  Warning: high traffic will flood serial output!");
  } else if (strncmp(cmd, "off", 3) == 0) {
    hexdumpEnabled = false;
    Serial.println("[HEXDUMP] Disabled");
  } else {
    Serial.printf("[HEXDUMP] Text: %s  |  PCAP serial: %s\n", hexdumpEnabled ? "ON" : "OFF",
                  hexdumpPcapSerial ? "ON" : "OFF");
    Serial.println("  hexdump on/off       - text hex+ASCII dump");
    Serial.println("  hexdump pcap on/off  - binary PCAP stream");
  }
}
