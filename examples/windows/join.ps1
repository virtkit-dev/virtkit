# Provision a member at every start: activate Windows if it is not, use the DC ($env:LAB_DC, a
# service name) as its resolver,
# then join the domain ($env:LAB_DOMAIN, corp.lab by default)
# under the service's name with vkjoin (password in the join_password secret). Joining
# requires a restart (exit 3010). Once joined, list the lab's users ($env:LAB_USERS) found in
# the directory, then those of a trusted forest ($env:LAB_REMOTE_USERS in
# $env:LAB_REMOTE_DOMAIN) read across the trust, then run the scripts $env:LAB_CHECK names
# (space-separated, beside this one), if any.
$ErrorActionPreference = 'Stop'

# Run $step with the attempt number until it succeeds, at most $tries times, $sleep seconds
# apart. Return its output; send failures to the host to keep them out of that output.
function Retry([int] $tries, [int] $sleep, [scriptblock] $step) {
    for ($i = 1; ; $i++) {
        try { return & $step $i }
        catch {
            if ($i -ge $tries) { throw }
            Write-Host "attempt $i of $tries failed, retrying: $_"
            Start-Sleep $sleep
        }
    }
}

$domain = if ($env:LAB_DOMAIN) { $env:LAB_DOMAIN } else { 'corp.lab' }
# An evaluation must be activated online: past its grace unactivated, Windows shuts down every
# hour. Activate it while the run's own resolver still answers for the Internet; without a
# network this fails and the lab goes on.
$windows = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
if ($windows -and $windows.LicenseStatus -ne 1) {
    cscript //nologo "$env:SystemRoot\System32\slmgr.vbs" /ato | Out-Host
}
$nic = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).ifIndex
$dc = Resolve-DnsName $env:LAB_DC -Server $env:VK_GATEWAY -Type A -DnsOnly |
    Select-Object -First 1 -ExpandProperty IPAddress
Set-DnsClientServerAddress -InterfaceIndex $nic -ServerAddresses $dc

$cs = Get-CimInstance Win32_ComputerSystem
if (-not $cs.PartOfDomain) {
    # By its UPN: resolved through DNS and the domain's own DC, where a NetBIOS domain name
    # (several DCs on one LAN answer for theirs) was seen to reach a DC that found no such user.
    $cred = New-Object System.Management.Automation.PSCredential("vkjoin@$domain",
        (ConvertTo-SecureString (Get-Content C:\ProgramData\Docker\secrets\join_password -Raw).Trim() -AsPlainText -Force))
    # The DC may not answer yet: a lab starts its members as soon as the DC is healthy, while its
    # DNS can still be busy (a forwarder to another forest being set up).
    Retry 30 10 {
        param($i)
        try { Add-Computer -DomainName $domain -NewName $env:VK_HOSTNAME -Credential $cred -Force }
        catch {
            # An attempt that timed out on a slow DC can have joined all the same.
            if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { "joined despite: $_"; return }
            if ($i -eq 3) {
                # Which DC this machine found, and how far its clock is from that DC's: through
                # cmd, as a native command's stderr is an error that would stop this script.
                try {
                    cmd /c "nltest /dsgetdc:$domain /force 2>&1" | Select-String 'DC:|Address:|Flags:|failed'
                    cmd /c "w32tm /stripchart /computer:$dc /samples:1 /dataonly 2>&1" | Select-Object -Last 1
                } catch { "no diagnostic: $_" }
            }
            ipconfig /flushdns | Out-Null
            throw
        }
    }
    # Rename for the next start if the join succeeded without its rename.
    $next = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
    if ($next -ne $env:VK_HOSTNAME) {
        # The DC can still be busy (a trust, a job's accounts): "the directory service is busy".
        Retry 20 15 { Rename-Computer -NewName $env:VK_HOSTNAME -DomainCredential $cred -Force }
    }
    exit 3010
}
"$($cs.Name) is in $($cs.Domain)"
# As SYSTEM, the machine account reads the directory, and a trusting forest's.
function Find-Users([string] $users, [string] $root) {
    foreach ($user in $users.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
        $searcher = if ($root) { New-Object DirectoryServices.DirectorySearcher([adsi]"LDAP://$root") }
                    else { New-Object DirectoryServices.DirectorySearcher }
        $searcher.Filter = "(sAMAccountName=$user)"
        $where = if ($root) { " in $root" } else { '' }
        # Across a trust, right after the join's restart, the machine can still be refused
        # ("the user name or password is incorrect") until its tickets for the other forest come.
        $found = Retry $(if ($root) { 30 } else { 1 }) 10 { $searcher.FindOne() }
        if ($found) { "user $user found$where" } else { throw "user $user not found$where" }
    }
}
Find-Users "$env:LAB_USERS" ''
if ($env:LAB_REMOTE_DOMAIN) { Find-Users "$env:LAB_REMOTE_USERS" $env:LAB_REMOTE_DOMAIN }
foreach ($check in "$env:LAB_CHECK".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
    & (Join-Path $PSScriptRoot $check)
}
