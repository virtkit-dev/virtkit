# The red forest's checks, run on its privileged access workstation (a member of the bastion
# forest, $env:LAB_DOMAIN) once joined: the bastion's tier-0 admin ($env:LAB_TIER0_USER, in the
# group production's DC made an administrator) creates and deletes an account in production
# ($env:LAB_PROD_DOMAIN), across the one-way trust; a production user ($env:LAB_PROD_USER)
# cannot sign in to the bastion, which does not trust production. Passwords in the
# user_password secret.
$ErrorActionPreference = 'Stop'
$password = (Get-Content C:\ProgramData\Docker\secrets\user_password -Raw).Trim()
$bastion = $env:LAB_NETBIOS
$prod = $env:LAB_PROD_DOMAIN
$prodDn = ($prod.Split('.') | ForEach-Object { "DC=$_" }) -join ','

$users = New-Object DirectoryServices.DirectoryEntry("LDAP://$prod/CN=Users,$prodDn",
    "$bastion\$env:LAB_TIER0_USER", $password)
# Deleted through its container (the Delete right on it, which production's Administrators
# hold), not with DeleteTree (Delete Subtree, which they do not); one a cut-short check left is
# deleted first.
try { $users.Children.Remove($users.Children.Find('CN=paw-probe', 'user')) } catch { }
$probe = $users.Children.Add('CN=paw-probe', 'user')
$probe.Properties['sAMAccountName'].Value = 'paw-probe'
$probe.CommitChanges()
$users.Children.Remove($probe)
"$bastion\$env:LAB_TIER0_USER administers $prod"

# Whether $domain\$user signs in to the bastion's directory: a connection of its own, not one
# of ADSI's (they are cached per process, and this one already bound to the bastion as the
# machine, so a DirectoryEntry would answer whatever credentials it is given).
Add-Type -AssemblyName System.DirectoryServices.Protocols
function Test-SignIn([string] $domain, [string] $user) {
    $id = New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier($env:LAB_DOMAIN)
    $conn = New-Object DirectoryServices.Protocols.LdapConnection($id,
        (New-Object Net.NetworkCredential($user, $password, $domain)))
    $conn.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
    try { $conn.Bind(); $true } catch [DirectoryServices.Protocols.LdapException] { $false } finally { $conn.Dispose() }
}
$prodNetbios = $env:LAB_PROD_NETBIOS
# The bastion's own admin signs in: the check can tell a sign-in from a refusal.
if (-not (Test-SignIn $bastion $env:LAB_TIER0_USER)) { throw "$bastion\$env:LAB_TIER0_USER cannot sign in to $env:LAB_DOMAIN" }
if (Test-SignIn $prodNetbios $env:LAB_PROD_USER) { throw "$prodNetbios\$env:LAB_PROD_USER signed in to $env:LAB_DOMAIN" }
"$prodNetbios\$env:LAB_PROD_USER cannot sign in to $env:LAB_DOMAIN (one-way trust), $bastion\$env:LAB_TIER0_USER can"
