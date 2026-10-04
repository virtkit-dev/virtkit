# More forests for multi-forest labs, beside lab.Dockerfile's corp.lab: the domain controllers of
# partner.lab (two-forests.compose.yaml) and admin.lab (red-forest.compose.yaml, the bastion
# forest), a member image that also carries the labs' checks, and the labs' member servers:
#
#   vk build -f lab.Dockerfile --target dc --out ./dc-out
#   vk build -f forests.Dockerfile --target dc-partner --out ./dc-partner-out
#   vk build -f forests.Dockerfile --target dc-admin --out ./dc-admin-out
#   vk build -f forests.Dockerfile --target srv-corp --out ./srv-corp-out      (and srv-partner,
#                                                                               srv-admin)
#
# Each forest is made at build, as lab.Dockerfile makes corp.lab; the trusts between them are
# made at start, by the trusting DC's provisioning (dc-boot.ps1). The base and the DC's features
# are lab.Dockerfile's steps, so the builds share their layers.

# vk: cpus=4 mem=4G
FROM winiso:ws2025-eval-en-us.iso@sha256:7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 \
    --edition="Windows Server 2025 Standard Evaluation" \
    --drivers=virtio-win.iso@sha256:303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d AS base
SHELL ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
RUN Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0; \
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'

# Generalized: a new forest's domain SID is its first DC's machine SID, and two forests whose
# DCs share a machine SID cannot trust each other. Each DC stage below starts from this image
# with a SID of its own, unlike lab.Dockerfile's corp.lab DC.
# vk: generalize=on
FROM base AS dc-features
SHELL ["powershell", "-NoLogo", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN Install-WindowsFeature AD-Domain-Services,DNS -IncludeManagementTools | Format-Table -AutoSize

# partner.lab, the other forest of a two-way forest trust.
FROM dc-features AS dc-partner
COPY promote.ps1 C:/vk/
RUN --network=default C:\vk\promote.ps1 partner.lab PARTNER; exit $LASTEXITCODE
RUN --network=default for ($i = 0; ; $i++) { \
      try { Get-ADDomain | Format-List DNSRoot,NetBIOSName,PDCEmulator; break } \
      catch { if ($i -ge 60) { throw }; Start-Sleep 5 } \
    }
COPY dc-boot.ps1 C:/vk/
CMD & C:\vk\dc-boot.ps1; exit $LASTEXITCODE

# admin.lab, a red forest (ESAE): the bastion forest holding the tier-0 admin accounts, which
# production trusts one way.
FROM dc-features AS dc-admin
COPY promote.ps1 C:/vk/
RUN --network=default C:\vk\promote.ps1 admin.lab ADMIN; exit $LASTEXITCODE
RUN --network=default for ($i = 0; ; $i++) { \
      try { Get-ADDomain | Format-List DNSRoot,NetBIOSName,PDCEmulator; break } \
      catch { if ($i -ge 60) { throw }; Start-Sleep 5 } \
    }
COPY dc-boot.ps1 C:/vk/
CMD & C:\vk\dc-boot.ps1; exit $LASTEXITCODE

# A member of any of the forests (join.ps1 reads which from its environment), with the checks
# its provisioning can run (red-forest-check.ps1, rdp-probe.ps1). Generalized.
# vk: generalize=on
FROM base AS member
SHELL ["powershell", "-NoLogo", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
COPY join.ps1 red-forest-check.ps1 rdp-probe.ps1 C:/vk/
CMD & C:\vk\join.ps1; exit $LASTEXITCODE

# The multi-forest labs' member servers, one image per machine: each stage boots the generalized
# member once at build for its own machine SID and Windows' first-boot setup. The lab only
# joins it to its domain at start.
FROM member AS srv-corp
RUN Write-Output 'srv-corp: specialized'

FROM member AS srv-partner
RUN Write-Output 'srv-partner: specialized'

FROM member AS srv-admin
RUN Write-Output 'srv-admin: specialized'
