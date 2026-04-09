param(
    [string]$EspIP = "192.168.50.92",
    [int]$Port = 9999
)

Write-Host "=== UDP Chat with ESP32 ===" -ForegroundColor Green
Write-Host "Target: $EspIP`:$Port"
Write-Host "Type 'exit' to quit."
Write-Host ""

# Single socket — sends FROM and receives ON the same port
# so the ESP32 sees a consistent source port to reply to
$udp = New-Object System.Net.Sockets.UdpClient($Port)
$udp.Client.ReceiveTimeout = 300
$dest = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($EspIP), $Port)
$ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

Write-Host "[*] Listening on UDP port $Port" -ForegroundColor DarkGray
Write-Host "[*] Incoming messages appear when you press Enter" -ForegroundColor DarkGray
Write-Host ""

while ($true) {
    # Drain all pending incoming messages
    $hasMessages = $true
    while ($hasMessages) {
        try {
            $data = $udp.Receive([ref]$ep)
            if ($null -ne $data -and $data.Length -gt 0) {
                $msg = [System.Text.Encoding]::ASCII.GetString($data)
                if ($msg.Trim().Length -gt 0) {
                    Write-Host "[ESP32] $msg" -ForegroundColor Cyan
                }
            }
        }
        catch {
            $hasMessages = $false
        }
    }

    # Get user input (blocks until Enter)
    $input = Read-Host "You"
    if ($input -eq "exit") { break }
    if ($input.Length -gt 0) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($input)
        $udp.Send($bytes, $bytes.Length, $dest) | Out-Null
    }
}

$udp.Close()
Write-Host "Chat closed." -ForegroundColor Yellow
