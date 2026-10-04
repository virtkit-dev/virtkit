# Make a DC the first of a new forest, $Domain (NetBIOS name $NetBios), at build; exit 3010 asks
# vk build for the restart promotion needs. Promotion wants a configured network adapter (a
# `RUN --network=default` step). About one in six attempts fails as NTDS first starts (event
# 1168, error 1327) and rolls back cleanly; the next attempt goes through.
# The DSRM password is an example value, public like secrets/: never expose a lab to a real
# network.
param([string] $Domain, [string] $NetBios)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ADDSDeployment
for ($i = 1; ; $i++) {
    try {
        $r = Install-ADDSForest -DomainName $Domain -DomainNetbiosName $NetBios -InstallDns `
            -SafeModeAdministratorPassword (ConvertTo-SecureString 'Vk-Dsrm-2025!' -AsPlainText -Force) `
            -NoRebootOnCompletion -Force -WarningAction SilentlyContinue
        if ($r.Status -eq 'Success') { break }
        throw $r.Message
    } catch {
        if ($i -ge 3) { throw }
        'promotion attempt {0} failed, retrying: {1}' -f $i, $_
    }
}
exit 3010
