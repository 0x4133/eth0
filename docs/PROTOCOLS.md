# Wire-format protocols

eth0 implements four custom or quasi-custom protocols whose specs
aren't visible from the source comments alone. They're documented
here so they can be re-implemented from the spec if needed.

---

## 1. TP-Link Kasa (`svc_kasa.{h,cpp}`)

**Transport:** TCP/9999.

**Framing:** 4-byte big-endian length prefix followed by an XOR-
chained ciphertext.

```
+--------+--------+--------+--------+--------+ ... +--------+
| len[0] | len[1] | len[2] | len[3] | C[0]   |     | C[N-1] |
+--------+--------+--------+--------+--------+ ... +--------+
   31..24   23..16   15..8    7..0
   length of plaintext (big-endian)         encrypted JSON
```

**Encryption** (per byte, applied to plaintext to get ciphertext):

```
key[0]     = 171
C[0]       = key[0] ^ P[0]
key[i]     = C[i-1]              for i >= 1
C[i]       = key[i] ^ P[i]
```

**Decryption** is the inverse: the ciphertext byte itself becomes
the next key, so the chain is self-keyed.

**Payload:** UTF-8 JSON. The system-info query is:

```json
{"system":{"get_sysinfo":{}}}
```

The cloud-info query (used by `kasa cloud`) is:

```json
{"cnCloud":{"get_info":{}}}
```

Implementation: `kasaEncrypt`, `kasaDecrypt`, `kasaSendRecv`,
`kasaQuerySysinfo`, `kasaQueryCloud` in `svc_kasa.cpp`.

---

## 2. AES-128-CBC UDP tunnel (`svc_udp_tunnel.{h,cpp}`)

**Transport:** UDP, configurable port (default `TUNNEL_PORT` =
9998 from `config.h`).

**Frame format:**

```
+--------+--------+--------+--------+--------+ ... +--------+
| MAGIC  | MAGIC  |     SEQ (4)     |    IV (16)      | DATA |
+--------+--------+--------+--------+--------+ ... +--------+
  0xE7E0 (TUNNEL_MAGIC)                              encrypted
```

- **MAGIC:** 2 bytes, `0xE7E0` (`TUNNEL_MAGIC` from `config.h`).
- **SEQ:** 4-byte big-endian sequence number, incremented per
  outgoing frame, used for replay detection on the receiver.
- **IV:** 16 random bytes per frame, supplied to AES-CBC.
- **DATA:** AES-128-CBC ciphertext using the shared 16-byte key.
  The key is established out-of-band (`tunnel start <ip> <hex-key>`).

**Cipher:** AES-128 in CBC mode, hardware-accelerated via
`mbedtls/aes.h` on the ESP32-S3.

**Maximum payload:** `TUNNEL_MTU` = 1400 bytes pre-encryption.

Implementation: `tunnelSendEncrypted`, `tunnelCheckIncoming`, plus
the `tunnel` serial command in `svc_udp_tunnel.cpp`.

---

## 3. DNS covert channel (`svc_dns_covert.{h,cpp}`)

**Transport:** UDP/53, sent to a controlled nameserver
(`covertServerIP`).

**Encoding:** input bytes are base32-encoded, then split into 63-
character chunks (the DNS label maximum), and embedded as
subdomains of a configured domain. Each chunk also gets a sequence
number prefix so the server can reassemble.

**Query format:**

```
<base32-chunk>.<seq>.<covertDomain>    A query
```

For example, with `covertDomain = "c.local"` and `covertSeq = 17`:

```
JBSWY3DPEBLW64TMMQ.17.c.local
```

The server answers with any A record (the answer is irrelevant —
the data exfiltration is the query name itself). The covert channel
implementation logs the queries via the IDS DNS detector if it's
enabled in passive mode, which is what makes this both an attack
and a self-test.

**Base32 alphabet:** `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` (RFC 4648).

**Limits:**

- `COVERT_MAX_LABEL` = 63 (DNS label max)
- `COVERT_MAX_DATA` = 200 bytes per `covert dns send` invocation

Implementation: `covertDnsSend`, `parseCovertCommand` in
`svc_dns_covert.cpp`.

---

## 4. IRC server (`svc_irc.{h,cpp}`)

**Transport:** TCP/6667. We do *not* use the Ethernet2 TCP socket
API; we hand-craft the SYN/SYN-ACK/ACK exchange ourselves on the
MACRAW socket so the IRC server runs alongside the packet capture.

**Protocol:** subset of RFC 1459. Supported commands:

| Command | Notes |
|---|---|
| `NICK` | Set nickname (≤ `IRC_NICK_LEN` chars) |
| `USER` | Registration; ignored args, just unblocks `IRC_REG_DONE` |
| `JOIN` | One channel at a time, max `IRC_MAX_CHANNELS` total |
| `PART` | Leave a channel |
| `PRIVMSG` | Message to channel or user |
| `NOTICE` | Same as PRIVMSG, no auto-reply |
| `PING` / `PONG` | Keepalive every `IRC_PING_INTERVAL` ms |
| `QUIT` | Sends RST and frees the slot |
| `LIST` | Returns the active channels |
| `NAMES` | Returns members of a channel |

**Per-client state** (`IrcClient` struct in `svc_irc.h`):

- `tcpState`: `IRC_TCP_FREE` / `SYN_RCVD` / `ESTABLISHED` /
  `CLOSING`
- `regState`: `IRC_REG_NONE` / `NICK` / `USER` / `DONE`
- `peerMAC[6]`, `peerIP[4]`, `peerPort`
- `mySeq`, `myAck` — TCP sequence/ack numbers we maintain
- `lastActivity`, `lastPingSent`, `pongPending` — keepalive state
- `nick`, `user`, `channels` (bitmask)
- `lineBuf[IRC_LINE_BUF]`, `linePos` — line accumulator

**Capacity:** `IRC_MAX_CLIENTS` = 6 simultaneous clients,
`IRC_MAX_CHANNELS` = 3, line buffer = 512 bytes (RFC 1459 max).

**Limitations:**

- No mode commands (`MODE`, `OPER`, `KICK`, `BAN`)
- No services / SASL / TLS
- Channel topics are not persisted across reconnects
- No flood control beyond TCP back-pressure

Implementation: `svc_irc.cpp`. The capture loop calls
`ircCheckIncomingTcp()` on every received frame and `ircTick()`
once per loop iteration for keepalive.

---

## PCAP-on-Serial format (`hexdump.{h,cpp}`)

When `hexdump pcap on` is set, every captured frame is emitted on
the Serial line as a binary PCAP record (16-byte header + raw
bytes). The Web Serial UI uses this to feed Wireshark live.

**Header (little-endian per `tcpdump.org/manpages/pcap-savefile.5`):**

```
+-------+-------+-------+-------+
|     ts_sec    |    ts_usec    |
+-------+-------+-------+-------+
|     incl_len  |    orig_len   |
+-------+-------+-------+-------+
```

The header is followed by `incl_len` raw bytes of the Ethernet
frame. There is no PCAP file global header — the consumer is
expected to know the link type is Ethernet (DLT_EN10MB = 1).
