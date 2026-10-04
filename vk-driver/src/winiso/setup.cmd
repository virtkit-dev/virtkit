@echo off
rem WinPE under vk (winiso.rs): load the virtio drivers, find the install medium, start Setup.
wpeinit
for %%f in (X:\vk\drivers\viostor\*.inf X:\vk\drivers\NetKVM\*.inf) do drvload "%%f"
set SRC=
for /l %%i in (1,1,60) do (
  if not defined SRC for %%d in (C D E F G H I J K) do if exist %%d:\sources\install.swm set SRC=%%d:\sources\install.swm
  if not defined SRC ping -n 2 127.0.0.1 >nul
)
if not defined SRC (echo vk: no install medium found & goto failed)
X:\sources\setup.exe /unattend:X:\vk\autounattend.xml /installfrom:%SRC%
wpeutil shutdown
exit /b 0
rem A missing medium is told on the serial console, where vk reads it, before the power-off;
rem the write runs in the background so a UART that blocks cannot keep WinPE from powering off.
:failed
start "" /b cmd /c "echo vk-install-failed>COM1"
ping -n 3 127.0.0.1 >nul
wpeutil shutdown
exit /b 1
