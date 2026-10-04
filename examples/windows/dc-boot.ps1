# Provision the DC at every start: its own DNS, the vk switch forwarding every name AD does
# not hold, and vkjoin, the lab's Domain Admin (password in the join_password secret): members
# join with it and the accounts job creates the lab's users as it.
#
# $env:LAB_FORWARDERS (space-separated `zone:service`) sends each zone to the DC of that service:
# a trusted forest's DC resolves the forest that trusts it, and its members do through it.
#
# With $env:LAB_TRUST_DOMAIN, a forest trust with that forest (NetBIOS name
# $env:LAB_TRUST_NETBIOS, its DC the service $env:LAB_TRUST_DC), whose direction is
# $env:LAB_TRUST_DIRECTION as seen from here: Bidirectional, or Outbound for this forest to
# trust the other one only. Both forests' vkjoin share the join_password secret. With
# $env:LAB_TRUST_ADMINS too, that group of the trusted forest administers this domain (a member
# of its BUILTIN\Administrators), as a red forest's tier-0 admins administer production.
$ErrorActionPreference = 'Stop'
$secrets = 'C:\ProgramData\Docker\secrets'

# Run $step until it succeeds: right after boot the DNS Server and AD services are still
# starting, and answer RPC_S_SERVER_UNAVAILABLE.
function Retry([scriptblock] $step) {
    for ($i = 0; ; $i++) {
        try { return & $step } catch { if ($i -ge 60) { throw }; Start-Sleep 5 }
    }
}

# Create the domain user $name unless it exists. The name goes into an AD filter: letters and
# digits only.
function Ensure-User([string] $name, [string] $password) {
    if ($name -notmatch '^[a-z0-9]+$') { throw "user name '$name': letters and digits only" }
    if (-not (Retry { Get-ADUser -Filter "SamAccountName -eq '$name'" })) {
        $pw = ConvertTo-SecureString $password -AsPlainText -Force
        New-ADUser -Name $name -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
    }
}

$nic = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).ifIndex
Set-DnsClientServerAddress -InterfaceIndex $nic -ServerAddresses 127.0.0.1
Retry { Set-DnsServerForwarder -IPAddress $env:VK_GATEWAY }
# A start is a new address: register the DC's records under it.
ipconfig /registerdns | Out-Null
Retry { Get-ADDomain | Out-Null }
nltest /dsregdns | Out-Null

Ensure-User vkjoin (Get-Content "$secrets\join_password" -Raw).Trim()
Add-ADGroupMember 'Domain Admins' vkjoin

# Send $zone to the DC of the service $service, by its address on the run's LAN (the switch may
# not know a service that has just started yet).
function Forward([string] $zone, [string] $service) {
    $address = Retry { Resolve-DnsName $service -Server $env:VK_GATEWAY -Type A -DnsOnly |
        Select-Object -First 1 -ExpandProperty IPAddress }
    if (-not (Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue)) {
        Retry { Add-DnsServerConditionalForwarderZone -Name $zone -MasterServers $address }
    }
}
foreach ($pair in "$env:LAB_FORWARDERS".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
    $zone, $service = $pair.Split(':')
    Forward $zone $service
}

if ($env:LAB_TRUST_DOMAIN) {
    $password = (Get-Content "$secrets\join_password" -Raw).Trim()
    Forward $env:LAB_TRUST_DOMAIN $env:LAB_TRUST_DC
    $here = Get-ADDomain
    function Context([string] $forest, [string] $netbios) {
        New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $forest,
            "$netbios\vkjoin", $password)
    }
    $local = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(
        (Context $here.DNSRoot $here.NetBIOSName))
    # The other forest's DC may still be finishing its own start.
    $remote = Retry { [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(
        (Context $env:LAB_TRUST_DOMAIN $env:LAB_TRUST_NETBIOS)) }
    try {
        $local.GetTrustRelationship($env:LAB_TRUST_DOMAIN) | Out-Null
        "trust with $env:LAB_TRUST_DOMAIN exists"
    } catch {
        # The other DC can be up before it can make a trust (ERROR_GEN_FAILURE, "a device
        # attached to the system is not functioning"). Clear the failed attempt on both sides
        # and retry.
        for ($i = 1; ; $i++) {
            try { $local.CreateTrustRelationship($remote, $env:LAB_TRUST_DIRECTION); break }
            catch {
                $err = $_.Exception.InnerException.Message
                # An attempt that failed this way can have made the trust all the same.
                try {
                    $local.GetTrustRelationship($env:LAB_TRUST_DOMAIN) | Out-Null
                    "trust attempt $i reported a failure, but the trust is there: $err"
                    break
                } catch { }
                if ($i -ge 10) { throw }
                "trust attempt $i failed, retrying: $err"
                try { $local.DeleteTrustRelationship($remote) } catch { }
                Start-Sleep 30
            }
        }
        "trust with $env:LAB_TRUST_DOMAIN created ($env:LAB_TRUST_DIRECTION)"
    }
    if ($env:LAB_TRUST_ADMINS) {
        $cred = New-Object System.Management.Automation.PSCredential("$env:LAB_TRUST_NETBIOS\vkjoin",
            (ConvertTo-SecureString $password -AsPlainText -Force))
        $admins = Retry { Get-ADGroup $env:LAB_TRUST_ADMINS -Server $env:LAB_TRUST_DOMAIN -Credential $cred }
        Add-ADGroupMember -Identity Administrators -Members $admins
        "$env:LAB_TRUST_NETBIOS\$env:LAB_TRUST_ADMINS administers $($here.DNSRoot)"
    }
}
Get-ADDomain | Format-List DNSRoot,PDCEmulator
