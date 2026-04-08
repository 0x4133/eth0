// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Compile-time configuration for eth0 subsystems. Numeric sizes,
// timeouts, protocol ports, and table capacities live here so they
// can be tuned in one place.
//
// Pin assignments live in pins.h. Wire-format offsets and ethertype
// constants live in eth_frame.h. NeoPixel GPIO is pins.h; the color
// palette is here because it's a runtime value, not a pin.
//
// These are still #define today to keep Phase 4 a pure move; the
// style guide (docs/STYLE.md section 4) schedules their conversion
// to `inline constexpr` for Phase 8.

#pragma once

// LWIP and ESP-IDF define `ARP_TABLE_SIZE` (= 10) for the standard
// IP stack's internal ARP cache. We're in MACRAW mode and never
// touch LWIP's stack, so override it with our own (much larger)
// value for the IDS-tracked ARP cache. The redefinition warning is
// real but harmless; the undef makes the override explicit.
#ifdef ARP_TABLE_SIZE
#undef ARP_TABLE_SIZE
#endif

// ── Capture ──
#define RAW_SOCKET       0                            // W5500 socket number for MACRAW (must be 0)
#define MAX_FRAME_SIZE   1518                         // Max Ethernet frame
#define COMMIT_INTERVAL  2000                         // Close/reopen file every 2 seconds (ms)
#define MAX_FILE_SIZE    (10UL * 1024UL * 1024UL)     // 10 MB per capture file
#define COMMIT_PKT_BATCH 20                           // Also commit every N packets

// ── IRC Server ──
#define IRC_PORT          6667
#define IRC_MAX_CLIENTS   6
#define IRC_MAX_CHANNELS  3
#define IRC_NICK_LEN      16
#define IRC_CHAN_LEN      20
#define IRC_LINE_BUF      512     // RFC 1459 max
#define IRC_PING_INTERVAL 120000  // Send PING every 2 min
#define IRC_PONG_TIMEOUT  60000   // Disconnect if no PONG in 60s
#define IRC_HANDSHAKE_TMO 10000   // Abandon SYN_RCVD after 10s
#define IRC_SERVER_NAME   "eth0"

// ── IDS / Detection ──
#define ARP_TABLE_SIZE      64    // Max tracked IP→MAC bindings
#define DHCP_SERVER_MAX     4     // Max known-good DHCP servers
#define SCAN_TRACK_SIZE     16    // Max tracked source IPs for port scan detection
#define SCAN_THRESHOLD      10    // Unique ports in window = port scan
#define SCAN_WINDOW_MS      5000  // Time window for port scan detection
#define ALERT_LED_MS        3000  // How long NeoPixel stays on alert color
#define DNS_TRACK_SIZE      32    // Tracked pending DNS queries
#define IDS_ENABLED_DEFAULT true  // IDS on at boot

// ── STP Topology Mapping ──
#define STP_BRIDGE_TABLE_SIZE 16    // Max tracked bridges
#define STP_MULTICAST_0       0x01  // STP dest MAC: 01:80:C2:00:00:00
#define STP_MULTICAST_1       0x80
#define STP_MULTICAST_2       0xC2
#define STP_MULTICAST_3       0x00
#define STP_MULTICAST_4       0x00
#define STP_MULTICAST_5       0x00
#define STP_LLC_DSAP          0x42
#define STP_LLC_SSAP          0x42
#define STP_LLC_CTRL          0x03

// ── ARP MitM ──
#define MITM_POISON_INTERVAL 2000  // Re-poison every 2 seconds

// ── DNS Spoof ──
#define DNSSPOOF_MAX_RULES  8   // Max spoofed domain rules
#define DNSSPOOF_MAX_DOMAIN 64  // Max domain name length

// ── Live Stats ──
#define STATS_INTERVAL_DEFAULT 5000  // Default auto-stats interval (ms)
#define STATS_TOP_TALKERS      5     // How many top talkers to track
#define STATS_TALKER_TABLE     32    // Size of IP tracking table

// ── Hexdump / PCAP-over-Serial ──
#define HEXDUMP_BYTES_PER_LINE 16  // Bytes per hexdump line

// ── NVS ──
#define NVS_NAMESPACE "eth0cfg"  // NVS namespace for persistent config

// ── Syslog ──
#define SYSLOG_DEFAULT_PORT 514  // Standard syslog UDP port
#define SYSLOG_FACILITY     4    // LOG_AUTH (security/authorization)
#define SYSLOG_MAX_MSG      200  // Max syslog message length

// ── MAC Spoofing ──
#define MAC_AUTO_MIN_SEC 5  // Minimum auto-rotate interval

// ── Packet Replay ──
#define REPLAY_DEFAULT_DELAY 0  // ms between replayed frames

// ── TCP RST Injection ──
#define TCP_CONN_TABLE_SIZE 64  // Tracked TCP connections
#define KILL_RST_COUNT      3   // RST packets per kill attempt

// ── DHCP Starvation ──
#define DHCPSTARVE_INTERVAL 100  // ms between DISCOVER packets

// ── NBNS/LLMNR Poisoning ──
#define NBNS_PORT          137
#define LLMNR_PORT         5355
#define NBSTAT_PORT        137
#define NETBIOS_TABLE_SIZE 32  // Max discovered NetBIOS hosts

// ── OS Fingerprinting ──
#define FP_TABLE_SIZE 32  // Tracked hosts for fingerprinting

// ── LLDP/CDP ──
#define LLDP_TABLE_SIZE 8  // Max tracked LLDP/CDP neighbors
#define LLDP_ETHERTYPE  0x88CC

// ── mDNS/NBNS Sniffer ──
#define MDNS_TABLE_SIZE 32  // Tracked mDNS hosts
#define MDNS_PORT       5353

// ── Encrypted UDP Tunnel ──
#define TUNNEL_PORT  9998    // Default tunnel port
#define TUNNEL_MAGIC 0xE7E0  // Packet header magic
#define TUNNEL_MTU   1400    // Max payload before encryption

// ── DNS Covert Channel ──
#define COVERT_MAX_LABEL 63   // DNS label max length
#define COVERT_MAX_DATA  200  // Max data per transfer

// ── Kasa Smart Device ──
#define KASA_PORT       9999  // TP-Link Kasa protocol port
#define KASA_XOR_KEY    171   // Initial XOR key for Kasa encryption
#define KASA_BUF_SIZE   2048  // Max response buffer
#define KASA_TIMEOUT_MS 3000  // TCP handshake + response timeout

// ── NeoPixel colors ──
#define COLOR_OFF    0x000000
#define COLOR_GREEN  0x001A00  // dim green = capturing normally
#define COLOR_YELLOW 0x1A1A00  // yellow = low-severity alert
#define COLOR_RED    0xFF0000  // red = high-severity alert
#define COLOR_BLUE   0x00001A  // blue = info/startup
#define COLOR_PURPLE 0x1A001A  // purple = cleartext creds detected
#define COLOR_ORANGE 0x1A0A00  // orange = MitM active
