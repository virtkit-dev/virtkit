# Provision a member at every start: use the DC ($env:LAB_DC, a service name) as its resolver,
# then join the domain under the service's name with vkjoin (password in the join_password
# secret). Joining requires a restart (exit 3010). Once joined, list the lab's users
# ($env:LAB_USERS) found in the directory.
$ErrorActionPreference = 'Stop'
$nic = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).ifIndex
$dc = Resolve-DnsName $env:LAB_DC -Server $env:VK_GATEWAY -Type A -DnsOnly |
    Select-Object -First 1 -ExpandProperty IPAddress
Set-DnsClientServerAddress -InterfaceIndex $nic -ServerAddresses $dc

$cs = Get-CimInstance Win32_ComputerSystem
if (-not $cs.PartOfDomain) {
    $cred = New-Object System.Management.Automation.PSCredential('CORP\vkjoin',
        (ConvertTo-SecureString (Get-Content C:\ProgramData\Docker\secrets\join_password -Raw).Trim() -AsPlainText -Force))
    # The DC may not answer yet: it is healthy once its DC locator answers, a little before the
    # rest of Active Directory does.
    for ($i = 1; ; $i++) {
        try { Add-Computer -DomainName corp.lab -NewName $env:VK_HOSTNAME -Credential $cred -Force; break }
        catch {
            # An attempt that timed out on a slow DC can have joined all the same.
            if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { "joined despite: $_"; break }
            if ($i -ge 30) { throw }
            "join attempt $i failed, retrying: $_"
            ipconfig /flushdns | Out-Null
            Start-Sleep 10
        }
    }
    # Rename for the next start if the join succeeded without its rename.
    $next = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
    if ($next -ne $env:VK_HOSTNAME) {
        for ($i = 1; ; $i++) {
            try { Rename-Computer -NewName $env:VK_HOSTNAME -DomainCredential $cred -Force; break }
            catch { if ($i -ge 20) { throw }; "rename attempt $i failed, retrying: $_"; Start-Sleep 15 }
        }
    }
    exit 3010
}
"$($cs.Name) is in $($cs.Domain)"
# As SYSTEM, the machine account reads the directory.
foreach ($user in "$env:LAB_USERS".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
    if (([adsisearcher]"(sAMAccountName=$user)").FindOne()) { "user $user found" }
    else { throw "user $user not found" }
}
