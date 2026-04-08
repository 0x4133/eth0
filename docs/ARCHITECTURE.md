# eth0 Architecture

## Overview

eth0 is an Arduino sketch (`eth0/eth0.ino`) plus ~35 sibling C++
modules in the same folder. The Arduino IDE compiles every `.h` /
`.cpp` next to the main `.ino` as part of the same build, so the
multi-file structure works without any extra build glue.

The runtime model is single-threaded:

```
                        ┌──────────────────────┐
                        │       setup()        │
                        │ ────────────────────│
                        │ NeoPixel init       │
                        │ SPI / SD / W5500    │
                        │ DHCP                │
                        │ MACRAW socket open  │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │        loop()        │
                        ├──────────────────────┤
                        │ handleSerialCommand()│ ← user input
                        │                      │
                        │ MACRAW recv          │
                        │   ├─ stpCheckBpdu    │
                        │   ├─ idsAnalyzePacket│
                        │   ├─ dnsSpoofCheck   │
                        │   ├─ statsTrackPacket│
                        │   ├─ lldpCheckFrame  │
                        │   ├─ fpAnalyzePacket │
                        │   ├─ mdnsCheckPacket │
                        │   ├─ tcpTrackPacket  │
                        │   ├─ netbiosParse    │
                        │   ├─ poisonCheck     │
                        │   ├─ tunnelCheck     │
                        │   ├─ ircCheckIncoming│
                        │   ├─ filter          │
                        │   └─ writePcapPacket │
                        │                      │
                        │ periodic ticks:      │
                        │   commitCaptureFile  │
                        │   statsPrint         │
                        │   macRandom          │
                        │   dhcpStarveSend     │
                        │   mitmSendPoison     │
                        │   ircTick            │
                        │   idsUpdateLed       │
                        └──────────────────────┘
```

## Module map

```
eth0/
├── eth0.ino              setup() / loop() / serial dispatcher / W5500 reset
│
├── core/
│   ├── config.h          compile-time constants (sizes, ports, intervals)
│   ├── pins.h            board pin assignments
│   ├── state.{h,cpp}     cross-module shared globals (mac, ourIP, packetBuf, capturing)
│   ├── led.h             extern Adafruit_NeoPixel pixel
│   ├── spi_bus.{h,cpp}   sdSPI (HSPI) ownership + switchTo* stubs
│   ├── nvs_config.{h,cpp} persistent config (Preferences/NVS)
│   └── arp_table.h       shared ArpEntry struct + extern arpTable[]
│
├── net/
│   ├── eth_frame.{h,cpp} wire-format constants + pktRead/Write helpers
│   │                     + ipChecksum / tcpChecksum + buildEth/IPv4Header
│   ├── ip_util.{h,cpp}   parseIP / parseMAC / printIP / printMAC
│   ├── dns_util.{h,cpp}  dnsDecodeName (RFC 1035 wire-format helper)
│   ├── filter.{h,cpp}    capture filter engine
│   └── pcap_writer.{h,cpp} PCAP file format + capture counters
│
├── inject.{h,cpp}        sendArp / sendPing / sendUDP / sendRawHex
│                         + buildTcpSyn/Ack/SynAck/FinAck/Rst/DataPush
│                         + resolveMacForIP
│
├── ids.{h,cpp}           IDS engine + 5 detectors (ARP spoof, rogue DHCP,
│                         cleartext creds, DNS anomaly, port scan)
│
├── recon_arp_sweep.{h,cpp}    ARP host discovery (/16-/30 CIDR)
├── recon_port_scan.{h,cpp}    TCP SYN port probe
├── recon_service_scan.{h,cpp} TCP handshake + banner grab
├── recon_vlan_discover.{h,cpp} 802.1Q tagged ARP probes
├── recon_stp.{h,cpp}          passive STP/RSTP BPDU listener
├── recon_lldp.{h,cpp}         passive LLDP/CDP parser
├── recon_mdns.{h,cpp}         passive mDNS / NBNS sniffer
├── recon_netbios.{h,cpp}      active NBNS sweep + NBSTAT query
├── recon_os_fingerprint.{h,cpp} passive TCP SYN-based OS fingerprint
│
├── attack_arp_mitm.{h,cpp}    ARP-poison MitM
├── attack_dns_spoof.{h,cpp}   DNS query interception + forged response
├── attack_tcp_rst.{h,cpp}     TCP connection tracker + RST injector
├── attack_dhcp_starve.{h,cpp} DHCP DISCOVER flood
├── attack_nbns_poison.{h,cpp} NBNS / LLMNR name poisoning
├── attack_mac_spoof.{h,cpp}   MAC randomizer / auto-rotate
│
├── packet_replay.{h,cpp}      replay PCAP files from SD
│
├── svc_irc.{h,cpp}            minimal RFC 1459 IRC server (raw TCP)
├── svc_kasa.{h,cpp}           TP-Link Kasa device query (XOR-encrypted JSON)
├── svc_syslog.{h,cpp}         RFC 5424 syslog forwarder for IDS alerts
├── svc_udp_tunnel.{h,cpp}     point-to-point AES-128-CBC over UDP
└── svc_dns_covert.{h,cpp}     base32 DNS subdomain exfiltration
│
├── stats.{h,cpp}              packet/byte stats + protocol breakdown + top talkers
├── network_map.{h,cpp}        unified host/intelligence dump
└── hexdump.{h,cpp}            live hex output + binary PCAP-over-Serial
```

(The folder layout is logical — the actual files are flat in
`eth0/` because the Arduino IDE only compiles siblings of the main
`.ino` file. Names are prefix-grouped so `ls` keeps related modules
together.)

## State ownership

The codebase is single-threaded so we don't need locks, but we do
keep cross-module state minimal:

- **Truly shared** (declared in `state.h`, defined in `state.cpp`):
  `mac`, `ourIP`, `ourGW`, `ourSubnet`, `ourDNS`, `packetBuf`,
  `txBuf`, `capturing`. Every subsystem reads these.
- **Subsystem-owned** (declared `extern` in the subsystem header,
  defined in the subsystem `.cpp`): each module owns its tables —
  `arpTable[]`, `knownDhcp[]`, `scanTrackers[]`, `dnsTrack[]`,
  `tcpConnTable[]`, `mitmActive`, `dnsSpoofRules[]`, etc. Cross-
  module read access happens via `#include`-and-extern; cross-
  module **write** access is rare (network map and `printNetworkMap`
  are the main consumers).
- **File-private** (file-static or in an anonymous namespace): IDS
  helper `memmem_ci`, recon banner extractors, IRC client lookup
  helpers, etc.

The Phase 8 plan called for hiding the externs behind accessor
functions in per-subsystem `State` structs. That's deferred — the
current externs build cleanly and the encapsulation can land as a
separate, lower-risk PR later.

## Hot path

The MACRAW receive loop in `loop()` calls many subsystem hooks per
frame. Each hook is allowed at most O(N) over its own table; none
allocate memory. The strict ordering inside `loop()` is:

1. STP BPDU check (link-layer, runs before EtherType filtering)
2. IDS analyzer (consumes IPv4 / ARP frames)
3. DNS spoof (intercepts queries before they leave the segment)
4. Stats / LLDP / FP / mDNS / TCP-tracker / NetBIOS / Poison /
   Tunnel passive analyzers
5. Built-in ARP responder (so the MACRAW socket can still answer
   "who has me")
6. IRC server packet handling (if active)
7. Capture filter
8. PCAP write
9. Optional hex/PCAP-over-serial dump

After the receive section, `loop()` runs periodic ticks:
file commit, stats auto-print, MAC auto-rotate, DHCP starvation,
MitM re-poison, IRC keepalive, NeoPixel state machine.

## Why so many globals?

The original sketch had ~80 file-scope variables. Phase 4–7 split
them across modules but kept the `extern` model rather than
introducing accessor functions, because:

1. The Arduino single-threaded model means no synchronization
   concerns.
2. The hot path is performance-sensitive and accessor functions
   would inline anyway.
3. Replacing them is a mechanical refactor we can do in one
   directional PR rather than mixing it into the structural
   extraction.

The key win from Phase 4–7 is **knowing which subsystem owns
which state** — even though it's still extern, it's no longer
file-scoped in `eth0.ino`.

## Tests

`tests/` contains a small Unity-free host harness for the pure
helpers (parseIP, parseMAC, ipChecksum, dnsDecodeName, byte-order
helpers, CIDR math). It runs under plain `g++` on Linux, no ESP32
toolchain required, and is gated by the `host-tests` GitHub Actions
workflow on every push.
