# Provision the DC at every start: its own DNS, the vk switch forwarding every name AD does
# not hold, vkjoin (the Domain Admin members join with, password in join_password), and the
# lab's users ($env:LAB_USERS, space-separated, password in user_password). Both passwords
# come from secrets.
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
$password = (Get-Content "$secrets\user_password" -Raw).Trim()
foreach ($user in "$env:LAB_USERS".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
    Ensure-User $user $password
}
Get-ADDomain | Format-List DNSRoot,PDCEmulator
