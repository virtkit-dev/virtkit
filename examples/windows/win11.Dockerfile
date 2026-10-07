# A Windows 11 workstation for the labs: installed from the Windows 11 Enterprise evaluation ISO,
# generalized, joining its lab's domain (join.ps1) under its service name at start. Each member
# has a TPM 2.0 of its own and boots with Secure Boot, as Windows 11 expects (BitLocker works);
# the install itself skips Setup's checks for them (Microsoft's LabConfig keys), and the build's
# steps run without a TPM.
#
# Secure Boot without SMM: vk keeps and checks the UEFI variables on the host, so PK, KEK, db and
# dbx are out of the guest's reach and Windows applies Microsoft's updates to them, but the
# firmware itself runs unprotected while it boots. Lab use only.
#
#   vk build -f win11.Dockerfile --target member11 --out ./member11-out
#
# The multi-forest labs' workstations are its targets ws-corp, ws-partner and paw (the red
# forest's privileged access workstation, which runs red-forest-check.ps1), one image per
# machine. To add one to lab-ad.compose.yaml:
#
#   win11:
#     image: ./member11-out
#     depends_on:
#       dc:
#         condition: service_healthy
#       accounts:
#         condition: service_completed_successfully
#     environment: *lab
#     secrets: [join_password]
#
# The build reads from this directory, pinned by digest, virtio-win.iso (see lab.Dockerfile) and
#   win11-ent-eval-en-us.iso  Windows 11 Enterprise evaluation (en-us, 64-bit), from the
#                             Microsoft Evaluation Center
# The install takes about 70 minutes, once.

# vk: cpus=4 mem=4G
FROM winiso:win11-ent-eval-en-us.iso@sha256:bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38 \
    --edition="Windows 11 Enterprise Evaluation" \
    --drivers=virtio-win.iso@sha256:303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d AS win11

# Generalized, so every copy starts with a name and SID of its own. A client's PowerShell
# runs no script by default (Restricted), hence Bypass for the provisioning.
# vk: generalize=on tpm=on firmware=uefi-secboot
FROM win11 AS member11
SHELL ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
# No automatic device encryption: Windows 11 would otherwise encrypt each member's disk with
# BitLocker at its first boot on the TPM. Turn BitLocker on where a test needs it.
RUN reg add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f
# Remote Desktop on, as on the servers (lab.Dockerfile's base).
RUN Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0; Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
COPY join.ps1 red-forest-check.ps1 rdp-probe.ps1 C:/vk/
CMD & C:\vk\join.ps1; exit $LASTEXITCODE

# The multi-forest labs' workstations, one image per machine, specialized at build like their
# servers (forests.Dockerfile): the lab only joins them at start.
FROM member11 AS ws-corp
RUN Write-Output 'ws-corp: specialized'

FROM member11 AS ws-partner
RUN Write-Output 'ws-partner: specialized'

FROM member11 AS paw
RUN Write-Output 'paw: specialized'
