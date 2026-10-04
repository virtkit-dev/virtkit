# RDP from this machine to each of $env:RDP_SERVERS (space-separated service names): the
# connection request every RDP client opens with (an X.224 Connection Request asking for TLS or
# Network Level Authentication), and the server's answer, which must be an RDP negotiation
# response selecting NLA (CredSSP). A provisioning step runs without a desktop to open mstsc in;
# the sign-in itself is rdp-check.sh's, from Linux.
$ErrorActionPreference = 'Stop'

# TPKT (version 3, length 19), X.224 Connection Request, RDP_NEG_REQ for PROTOCOL_SSL | PROTOCOL_HYBRID.
[byte[]] $request = 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00

# Open an RDP connection to $address and return the server's 19-byte answer to $request.
function Negotiate([string] $address) {
    $tcp = New-Object Net.Sockets.TcpClient
    try {
        $tcp.Connect($address, 3389)
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 30000
        $stream.Write($request, 0, $request.Length)
        $response = New-Object byte[] 19
        $read = 0
        while ($read -lt 19) {
            $n = $stream.Read($response, $read, 19 - $read)
            if ($n -eq 0) { throw "the connection closed after $read bytes" }
            $read += $n
        }
        return ,$response
    } finally {
        $tcp.Close()
    }
}

foreach ($server in "$env:RDP_SERVERS".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
    # A service name, from vk's DNS: this machine's DNS is its domain's DC, which knows its
    # domain's members by their names but not the other forests', nor the DCs' service names.
    $address = (Resolve-DnsName $server -Server $env:VK_GATEWAY -Type A -DnsOnly |
        Where-Object Type -eq A | Select-Object -First 1).IPAddress
    if (-not $address) { throw "rdp to ${server}: does not resolve" }
    # Retry the whole exchange: a busy DC can accept the connection before it answers the
    # negotiation.
    for ($i = 1; ; $i++) {
        try { $response = Negotiate $address; break }
        catch {
            if ($i -ge 20) { throw "rdp to ${server}: $($_.Exception.Message)" }
            Start-Sleep 10
        }
    }
    # TPKT, X.224 Connection Confirm (0xd0), RDP_NEG_RSP (type 2), selected protocol.
    if ($response[0] -ne 3 -or $response[5] -ne 0xd0 -or $response[11] -ne 2) {
        throw "rdp to ${server}: no RDP negotiation response"
    }
    $selected = [BitConverter]::ToUInt32($response, 15)
    if ($selected -ne 2) { throw "rdp to ${server}: protocol $selected selected, not NLA" }
    "rdp to ${server}: RDP answers from $env:COMPUTERNAME, NLA (CredSSP) selected"
}
