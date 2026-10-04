# A standalone Windows Server 2025 (no domain) that takes Remote Desktop sessions: its
# provisioning makes a local account, rdpuser (password in the user_password secret), a member
# of Remote Desktop Users. Its base is lab.Dockerfile's, step for step, so the two share the
# install and the first layer:
#
#   vk build -f rdp.Dockerfile --target rdp-server --out ./rdp-server-out
#   vk run --compose rdp-session.compose.yaml

# vk: cpus=4 mem=4G
FROM winiso:ws2025-eval-en-us.iso@sha256:7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 \
    --edition="Windows Server 2025 Standard Evaluation" \
    --drivers=virtio-win.iso@sha256:303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d AS base
SHELL ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
RUN Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0; \
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'

FROM base AS rdp-server
SHELL ["powershell", "-NoLogo", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
COPY rdp-user.ps1 C:/vk/
CMD & C:\vk\rdp-user.ps1; exit $LASTEXITCODE
