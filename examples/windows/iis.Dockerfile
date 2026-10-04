# A web server: Windows Server 2025 with IIS serving one page. iis.compose.yaml brings it up with
# a Linux client that fetches the page once IIS answers:
#
#   vk build -f iis.Dockerfile --out ./iis-out
#   vk run --compose iis.compose.yaml
#
# The build reads the ISOs lab.Dockerfile describes from this directory; the base stage is the
# same as lab.Dockerfile's, so the two share the install and its first layer.

# vk: cpus=4 mem=4G
FROM winiso:ws2025-eval-en-us.iso@sha256:7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 \
    --edition="Windows Server 2025 Standard Evaluation" \
    --drivers=virtio-win.iso@sha256:303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d AS base
SHELL ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
RUN Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0; \
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'

# IIS opens its firewall rule for port 80 itself. No CMD: the service is up once Windows is.
FROM base AS iis
SHELL ["powershell", "-NoLogo", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN Install-WindowsFeature Web-Server | Format-Table -AutoSize
COPY iis-index.html C:/inetpub/wwwroot/index.html
