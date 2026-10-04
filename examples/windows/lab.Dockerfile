# An Active Directory lab on Windows Server 2025: a domain controller for corp.lab and a member
# image that joins it at start. Brought up by lab-ad.compose.yaml:
#
#   vk build -f lab.Dockerfile --target dc --out ./dc-out
#   vk build -f lab.Dockerfile --target member --out ./member-out
#   vk run --compose lab-ad.compose.yaml
#
# The build reads two ISOs from this directory, pinned by digest:
#   ws2025-eval-en-us.iso  Windows Server 2025 evaluation (en-us), from the Microsoft
#                          Evaluation Center
#   virtio-win.iso         the virtio-win drivers and qemu-ga, from
#                          fedorapeople.org/groups/virt/virtio-win/direct-downloads
# The install takes about 20 minutes, once; every later step is a cached layer.

# vk: cpus=4 mem=4G
FROM winiso:ws2025-eval-en-us.iso@sha256:7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 \
    --edition="Windows Server 2025 Standard Evaluation" \
    --drivers=virtio-win.iso@sha256:303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d AS base
SHELL ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
RUN Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0; \
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'

# The domain controller: the forest is made at build, so every lab starts from the same
# corp.lab. Not generalized: a DC's identity is the forest's.
FROM base AS dc
SHELL ["powershell", "-NoLogo", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN Install-WindowsFeature AD-Domain-Services,DNS -IncludeManagementTools | Format-Table -AutoSize
# Promote it (promote.ps1), with the restart that takes.
COPY promote.ps1 C:/vk/
RUN --network=default C:\vk\promote.ps1 corp.lab CORP; exit $LASTEXITCODE
# Active Directory Web Services starts last after a boot.
RUN --network=default for ($i = 0; ; $i++) { \
      try { Get-ADDomain | Format-List DNSRoot,NetBIOSName,PDCEmulator; break } \
      catch { if ($i -ge 60) { throw }; Start-Sleep 5 } \
    }; \
    Get-Service NTDS,DNS,ADWS | Format-Table -AutoSize
COPY dc-boot.ps1 C:/vk/
CMD & C:\vk\dc-boot.ps1; exit $LASTEXITCODE

# A member: generalized, so every copy starts with a name and SID of its own, then joins the
# domain under its service name.
# vk: generalize=on
FROM base AS member
SHELL ["powershell", "-NoLogo", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
COPY join.ps1 C:/vk/
CMD & C:\vk\join.ps1; exit $LASTEXITCODE
