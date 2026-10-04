# The RDP server's provisioning, run at every start: the local account rdpuser, with the
# password in the user_password secret, allowed to sign in over Remote Desktop.
$ErrorActionPreference = 'Stop'
$password = ConvertTo-SecureString (Get-Content C:\ProgramData\Docker\secrets\user_password -Raw).Trim() -AsPlainText -Force
if (Get-LocalUser rdpuser -ErrorAction SilentlyContinue) {
    Set-LocalUser rdpuser -Password $password
} else {
    New-LocalUser rdpuser -Password $password -PasswordNeverExpires | Out-Null
}
if (-not (Get-LocalGroupMember 'Remote Desktop Users' -Member rdpuser -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember 'Remote Desktop Users' -Member rdpuser
}
# Up once the LAN reaches it: an image built without a network meets its adapter at this first
# start, and Windows takes a while to bring it up.
for ($i = 0; -not (Get-NetIPAddress -IPAddress $env:VK_IP -ErrorAction SilentlyContinue); $i++) {
    if ($i -ge 120) { ipconfig /all; throw "no address $env:VK_IP after 10 minutes" }
    Start-Sleep 5
}
"rdpuser may sign in over Remote Desktop on $env:COMPUTERNAME, at $env:VK_IP"
