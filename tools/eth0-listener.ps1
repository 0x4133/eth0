#═══════════════════════════════════════════════════════════════
#  eth0 Universal Listener
#  Receives all connection types from the eth0 network tool
#═══════════════════════════════════════════════════════════════
#
#  Usage:
#    .\eth0-listener.ps1                    # Listen on all ports
#    .\eth0-listener.ps1 -Mode chat         # Chat only
#    .\eth0-listener.ps1 -Mode syslog       # Syslog only
#    .\eth0-listener.ps1 -Mode tunnel       # Tunnel only
#    .\eth0-listener.ps1 -Mode covert       # DNS covert only
#    .\eth0-listener.ps1 -Mode pcap         # PCAP serial capture
#    .\eth0-listener.ps1 -DeviceIP 192.168.1.42
#
#  Requires: Run as Admin for port 53 (DNS covert)
#═══════════════════════════════════════════════════════════════

param(
    [string]$Mode = "all",
    [string]$DeviceIP = "",
    [int]$ChatPort = 9999,
    [int]$SyslogPort = 514,
    [int]$TunnelPort = 9998,
    [int]$CovertPort = 53,
    [string]$TunnelKey = "",
    [string]$ComPort = "",
    [string]$LogDir = ".\eth0-logs"
)

# ── Colors ──
function Write-C($msg, $color) { Write-Host $msg -ForegroundColor $color }
function Write-Ts($prefix, $msg, $color) {
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] " -NoNewline -ForegroundColor DarkGray
    Write-Host "$prefix " -NoNewline -ForegroundColor $color
    Write-Host $msg
}

# ── Banner ──
function Show-Banner {
    Write-Host ""
    Write-C "  ┌─────────────────────────────────────────────┐" Cyan
    Write-C "  │      eth0 — Universal Listener v1.0         │" Cyan
    Write-C "  └─────────────────────────────────────────────┘" Cyan
    Write-Host ""
    Write-C "  Listening for:" Yellow
    Write-Host ""
}

# ── Setup log directory ──
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$logAll = Join-Path $LogDir "eth0-all.log"
$logCreds = Join-Path $LogDir "eth0-creds.log"
$logAlerts = Join-Path $LogDir "eth0-alerts.log"
$logCovert = Join-Path $LogDir "eth0-covert.log"
$logChat = Join-Path $LogDir "eth0-chat.log"

function Log-To($file, $msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts  $msg" | Out-File -Append -FilePath $file -Encoding utf8
}

# ── Base32 Decoder ──
function Decode-Base32($encoded) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $encoded = $encoded.ToUpper() -replace '[^A-Z2-7]', ''
    $bits = ""
    foreach ($c in $encoded.ToCharArray()) {
        $val = $alphabet.IndexOf($c)
        if ($val -ge 0) { $bits += [Convert]::ToString($val, 2).PadLeft(5, '0') }
    }
    $bytes = New-Object System.Collections.ArrayList
    for ($i = 0; $i + 8 -le $bits.Length; $i += 8) {
        [void]$bytes.Add([Convert]::ToByte($bits.Substring($i, 8), 2))
    }
    return [System.Text.Encoding]::ASCII.GetString($bytes.ToArray())
}

# ── AES-128-CBC Decrypt (matches eth0 tunnel format) ──
function Decrypt-TunnelPacket($data, $keyHex) {
    if ($data.Length -lt 22) { return $null }
    # Parse: magic(2) + seq(4) + iv(16) + ciphertext
    $magic = ([int]$data[0] -shl 8) -bor $data[1]
    if ($magic -ne 0xE7E0) { return $null }
    $seq = ([uint32]$data[2] -shl 24) -bor ([uint32]$data[3] -shl 16) -bor ([uint32]$data[4] -shl 8) -bor $data[5]
    $iv = $data[6..21]
    $ciphertext = $data[22..($data.Length - 1)]
    if ($ciphertext.Length -eq 0 -or ($ciphertext.Length % 16) -ne 0) { return $null }

    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 128
        # Parse hex key
        $keyBytes = New-Object byte[] 16
        for ($i = 0; $i -lt 16; $i++) {
            $keyBytes[$i] = [Convert]::ToByte($keyHex.Substring($i * 2, 2), 16)
        }
        $aes.Key = $keyBytes
        $aes.IV = [byte[]]$iv
        $dec = $aes.CreateDecryptor()
        $plain = $dec.TransformFinalBlock([byte[]]$ciphertext, 0, $ciphertext.Length)
        $aes.Dispose()
        return @{ Seq = $seq; Data = [System.Text.Encoding]::ASCII.GetString($plain) }
    } catch {
        return $null
    }
}

# ── AES-128-CBC Encrypt (for sending tunnel messages) ──
function Encrypt-TunnelPacket($plaintext, $keyHex, [ref]$txSeq) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize = 128
    $keyBytes = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) {
        $keyBytes[$i] = [Convert]::ToByte($keyHex.Substring($i * 2, 2), 16)
    }
    $aes.Key = $keyBytes
    $aes.GenerateIV()
    $enc = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::ASCII.GetBytes($plaintext)
    $ciphertext = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $aes.Dispose()

    # Build packet: magic(2) + seq(4) + iv(16) + ciphertext
    $packet = New-Object System.Collections.ArrayList
    [void]$packet.Add([byte]0xE7)
    [void]$packet.Add([byte]0xE0)
    $s = $txSeq.Value; $txSeq.Value++
    [void]$packet.Add([byte](($s -shr 24) -band 0xFF))
    [void]$packet.Add([byte](($s -shr 16) -band 0xFF))
    [void]$packet.Add([byte](($s -shr 8) -band 0xFF))
    [void]$packet.Add([byte]($s -band 0xFF))
    foreach ($b in $aes.IV) { [void]$packet.Add($b) }
    # Re-get IV before disposal... actually we need to save it
    # The IV was already used in encryption, let's rebuild
    # Simpler: build manually
    $result = New-Object byte[] (6 + 16 + $ciphertext.Length)
    $result[0] = 0xE7; $result[1] = 0xE0
    $result[2] = [byte](($s -shr 24) -band 0xFF)
    $result[3] = [byte](($s -shr 16) -band 0xFF)
    $result[4] = [byte](($s -shr 8) -band 0xFF)
    $result[5] = [byte]($s -band 0xFF)
    # We need the IV that was actually used
    # Since we already disposed, let's redo properly
    return $null  # Will use simpler method below
}

# ── Simpler tunnel send ──
function Send-TunnelMessage($udpClient, $ip, $port, $message, $keyHex, [ref]$seq) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize = 128

    $keyBytes = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) {
        $keyBytes[$i] = [Convert]::ToByte($keyHex.Substring($i * 2, 2), 16)
    }
    $aes.Key = $keyBytes
    $aes.GenerateIV()
    $iv = $aes.IV

    $enc = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::ASCII.GetBytes($message)
    $ciphertext = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    # Build packet
    $s = $seq.Value; $seq.Value++
    $packet = New-Object byte[] (6 + 16 + $ciphertext.Length)
    $packet[0] = 0xE7; $packet[1] = 0xE0
    $packet[2] = [byte](($s -shr 24) -band 0xFF)
    $packet[3] = [byte](($s -shr 16) -band 0xFF)
    $packet[4] = [byte](($s -shr 8) -band 0xFF)
    $packet[5] = [byte]($s -band 0xFF)
    [Array]::Copy($iv, 0, $packet, 6, 16)
    [Array]::Copy($ciphertext, 0, $packet, 22, $ciphertext.Length)

    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ip), $port)
    $udpClient.Send($packet, $packet.Length, $ep) | Out-Null

    $aes.Dispose()
}

# ── Parse syslog priority for severity ──
function Parse-SyslogSeverity($msg) {
    if ($msg -match '^\<(\d+)\>') {
        $pri = [int]$Matches[1]
        $sev = $pri % 8
        $body = $msg -replace '^\<\d+\>', ''
        switch ($sev) {
            0 { return @{ Level = "EMERG"; Color = "Red"; Body = $body } }
            1 { return @{ Level = "ALERT"; Color = "Red"; Body = $body } }
            2 { return @{ Level = "CRIT "; Color = "Red"; Body = $body } }
            3 { return @{ Level = "ERROR"; Color = "Red"; Body = $body } }
            4 { return @{ Level = "WARN "; Color = "Yellow"; Body = $body } }
            5 { return @{ Level = "NOTCE"; Color = "Cyan"; Body = $body } }
            6 { return @{ Level = "INFO "; Color = "Green"; Body = $body } }
            7 { return @{ Level = "DEBUG"; Color = "Gray"; Body = $body } }
        }
    }
    return @{ Level = "?????"; Color = "White"; Body = $msg }
}

# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

Show-Banner

$listeners = @()
$runAll = ($Mode -eq "all")

# ── UDP Chat Listener ──
if ($runAll -or $Mode -eq "chat") {
    try {
        $chatUdp = New-Object System.Net.Sockets.UdpClient($ChatPort)
        $chatUdp.Client.ReceiveTimeout = 100
        Write-C "    [CHAT]    UDP :$ChatPort" Green
        $listeners += "chat"
    } catch {
        Write-C "    [CHAT]    Port $ChatPort in use — skipping" Red
        $chatUdp = $null
    }
}

# ── Syslog Listener ──
if ($runAll -or $Mode -eq "syslog") {
    try {
        $syslogUdp = New-Object System.Net.Sockets.UdpClient($SyslogPort)
        $syslogUdp.Client.ReceiveTimeout = 100
        Write-C "    [SYSLOG]  UDP :$SyslogPort" Yellow
        $listeners += "syslog"
    } catch {
        Write-C "    [SYSLOG]  Port $SyslogPort in use — skipping" Red
        $syslogUdp = $null
    }
}

# ── Tunnel Listener ──
if ($runAll -or $Mode -eq "tunnel") {
    try {
        $tunnelUdp = New-Object System.Net.Sockets.UdpClient($TunnelPort)
        $tunnelUdp.Client.ReceiveTimeout = 100
        $tunnelEnabled = ($TunnelKey.Length -eq 32)
        if ($tunnelEnabled) {
            Write-C "    [TUNNEL]  UDP :$TunnelPort (AES key loaded)" Magenta
        } else {
            Write-C "    [TUNNEL]  UDP :$TunnelPort (raw — no key, use -TunnelKey)" DarkYellow
        }
        $listeners += "tunnel"
    } catch {
        Write-C "    [TUNNEL]  Port $TunnelPort in use — skipping" Red
        $tunnelUdp = $null
    }
}

# ── DNS Covert Listener ──
if ($runAll -or $Mode -eq "covert") {
    try {
        $covertUdp = New-Object System.Net.Sockets.UdpClient($CovertPort)
        $covertUdp.Client.ReceiveTimeout = 100
        Write-C "    [COVERT]  UDP :$CovertPort (DNS)" Blue
        $listeners += "covert"
    } catch {
        Write-C "    [COVERT]  Port $CovertPort — need Admin, or in use — skipping" Red
        $covertUdp = $null
    }
}

# ── Serial PCAP ──
if ($Mode -eq "pcap") {
    if (!$ComPort) {
        Write-C "    [PCAP]    Scanning COM ports..." Cyan
        $ports = [System.IO.Ports.SerialPort]::GetPortNames()
        if ($ports.Count -gt 0) {
            $ComPort = $ports[0]
            Write-C "    [PCAP]    Using $ComPort" Cyan
        } else {
            Write-C "    [PCAP]    No COM ports found" Red
        }
    }
    if ($ComPort) {
        Write-C "    [PCAP]    Serial $ComPort -> eth0-capture.pcap" Cyan
        $listeners += "pcap"
    }
}

if ($listeners.Count -eq 0) {
    Write-C "  No listeners started. Check ports or run as Admin." Red
    exit 1
}

Write-Host ""
Write-C "  Logging to: $LogDir" DarkGray
Write-Host ""
Write-C "  ───────────────────────────────────────────────" DarkGray
Write-C "  Press Ctrl+C to stop. Type messages for chat." DarkGray
Write-C "  Prefix with /tunnel or /t to send via tunnel." DarkGray
Write-C "  ───────────────────────────────────────────────" DarkGray
Write-Host ""

$ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
$tunnelTxSeq = 0

# ── PCAP mode is blocking, handle separately ──
if ($Mode -eq "pcap" -and $ComPort) {
    $pcapFile = Join-Path $LogDir "eth0-capture.pcap"
    Write-Ts "PCAP" "Capturing serial PCAP to $pcapFile ..." Cyan
    Write-Ts "PCAP" "On the tool, run: hexdump pcap on" Cyan

    $serial = New-Object System.IO.Ports.SerialPort $ComPort, 115200
    $serial.Open()
    $fs = [System.IO.File]::Create($pcapFile)
    $total = 0

    try {
        while ($true) {
            if ($serial.BytesToRead -gt 0) {
                $buf = New-Object byte[] $serial.BytesToRead
                $n = $serial.Read($buf, 0, $buf.Length)
                $fs.Write($buf, 0, $n)
                $fs.Flush()
                $total += $n
                Write-Host "`r  Captured: $total bytes" -NoNewline
            }
            Start-Sleep -Milliseconds 5
        }
    } finally {
        $fs.Close()
        $serial.Close()
        Write-Host ""
        Write-Ts "PCAP" "Saved $total bytes to $pcapFile" Cyan
    }
    exit 0
}

# ── Main poll loop ──
# Check for keyboard input for sending chat/tunnel messages
$host.UI.RawUI.FlushInputBuffer()

try {
    while ($true) {

        # ── Check for keyboard input (send chat or tunnel) ──
        if ([Console]::KeyAvailable) {
            $line = Read-Host ">"
            if ($line) {
                if (($line.StartsWith("/tunnel ") -or $line.StartsWith("/t ")) -and $tunnelUdp -and $tunnelEnabled -and $DeviceIP) {
                    $msg = if ($line.StartsWith("/t ")) { $line.Substring(3) } else { $line.Substring(8) }
                    Send-TunnelMessage $tunnelUdp $DeviceIP $TunnelPort $msg $TunnelKey ([ref]$tunnelTxSeq)
                    Write-Ts "TUNNEL>>" $msg Magenta
                    Log-To $logAll "TUNNEL-TX: $msg"
                }
                elseif ($chatUdp -and $DeviceIP) {
                    $bytes = [System.Text.Encoding]::ASCII.GetBytes($line)
                    $dest = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($DeviceIP), $ChatPort)
                    $chatUdp.Send($bytes, $bytes.Length, $dest) | Out-Null
                    Write-Ts "CHAT>>" $line Green
                    Log-To $logChat "TX: $line"
                    Log-To $logAll "CHAT-TX: $line"
                }
                else {
                    Write-C "  Set -DeviceIP to send messages" Red
                }
            }
        }

        # ── Poll Chat ──
        if ($chatUdp) {
            try {
                $data = $chatUdp.Receive([ref]$ep)
                $msg = [System.Text.Encoding]::ASCII.GetString($data)
                Write-Ts "CHAT" "$($ep.Address) > $msg" Green
                Log-To $logChat "$($ep.Address): $msg"
                Log-To $logAll "CHAT: $($ep.Address): $msg"

                # Auto-detect device IP
                if (!$DeviceIP -and $ep.Address.ToString() -ne "0.0.0.0") {
                    $DeviceIP = $ep.Address.ToString()
                    Write-Ts "CHAT" "Device IP auto-set: $DeviceIP" DarkGreen
                }
            } catch [System.Net.Sockets.SocketException] { }
        }

        # ── Poll Syslog ──
        if ($syslogUdp) {
            try {
                $data = $syslogUdp.Receive([ref]$ep)
                $msg = [System.Text.Encoding]::ASCII.GetString($data)
                $parsed = Parse-SyslogSeverity $msg
                Write-Ts "ALERT" "[$($parsed.Level)] $($parsed.Body)" $parsed.Color
                Log-To $logAlerts "$($ep.Address) [$($parsed.Level)] $($parsed.Body)"
                Log-To $logAll "SYSLOG: $($ep.Address) $msg"

                # Check for credential-related alerts
                if ($msg -match "CLEARTEXT|credential|AUTH|PASS|password" ) {
                    Log-To $logCreds "$($ep.Address) $($parsed.Body)"
                    Write-Ts "CRED!" $parsed.Body Red
                }
            } catch [System.Net.Sockets.SocketException] { }
        }

        # ── Poll Tunnel ──
        if ($tunnelUdp) {
            try {
                $data = $tunnelUdp.Receive([ref]$ep)
                if ($tunnelEnabled) {
                    $result = Decrypt-TunnelPacket $data $TunnelKey
                    if ($result) {
                        Write-Ts "TUNNEL" "#$($result.Seq) from $($ep.Address): $($result.Data)" Magenta
                        Log-To $logAll "TUNNEL: #$($result.Seq) $($ep.Address): $($result.Data)"
                    } else {
                        Write-Ts "TUNNEL" "Decrypt failed from $($ep.Address) ($($data.Length) bytes)" Red
                    }
                } else {
                    # Raw hex dump if no key
                    $hex = ($data | ForEach-Object { $_.ToString("X2") }) -join " "
                    Write-Ts "TUNNEL" "$($ep.Address) [$($data.Length)B] $hex" DarkYellow
                    Log-To $logAll "TUNNEL-RAW: $($ep.Address) $hex"
                }

                if (!$DeviceIP -and $ep.Address.ToString() -ne "0.0.0.0") {
                    $DeviceIP = $ep.Address.ToString()
                }
            } catch [System.Net.Sockets.SocketException] { }
        }

        # ── Poll DNS Covert ──
        if ($covertUdp) {
            try {
                $data = $covertUdp.Receive([ref]$ep)
                if ($data.Length -gt 12) {
                    # Parse DNS query — extract QNAME labels
                    $i = 12; $labels = @()
                    while ($i -lt $data.Length -and $data[$i] -ne 0) {
                        $len = $data[$i]; $i++
                        if ($i + $len -gt $data.Length) { break }
                        $label = [System.Text.Encoding]::ASCII.GetString($data, $i, $len)
                        $labels += $label; $i += $len
                    }

                    if ($labels.Count -ge 2) {
                        # Data is in all labels except the last two (seq + domain)
                        $dataLabels = $labels[0..($labels.Count - 3)]
                        $encoded = $dataLabels -join ""
                        $seqLabel = $labels[$labels.Count - 2]

                        # Try base32 decode
                        try {
                            $decoded = Decode-Base32 $encoded
                            Write-Ts "COVERT" "[$seqLabel] $decoded" Blue
                            Log-To $logCovert "$($ep.Address) [$seqLabel] $decoded"
                            Log-To $logAll "COVERT: $($ep.Address) [$seqLabel] $decoded"
                        } catch {
                            Write-Ts "COVERT" "[$seqLabel] (raw) $encoded" DarkBlue
                            Log-To $logCovert "$($ep.Address) [$seqLabel] RAW:$encoded"
                        }

                        # Send a DNS response back (so the query doesn't hang)
                        $resp = New-Object byte[] ($data.Length + 16)
                        [Array]::Copy($data, $resp, $data.Length)
                        # Set QR bit (response)
                        $resp[2] = $resp[2] -bor 0x80
                        # ANCOUNT = 0 (no answer, just acknowledge)
                        $covertUdp.Send($resp, $data.Length, $ep) | Out-Null
                    }
                }
            } catch [System.Net.Sockets.SocketException] { }
        }

        Start-Sleep -Milliseconds 10
    }
} finally {
    Write-Host ""
    Write-C "  Shutting down listeners..." Yellow
    if ($chatUdp) { $chatUdp.Close() }
    if ($syslogUdp) { $syslogUdp.Close() }
    if ($tunnelUdp) { $tunnelUdp.Close() }
    if ($covertUdp) { $covertUdp.Close() }
    Write-C "  Logs saved to $LogDir" Green
    Write-Host ""
}
