#!/bin/sh
# Build a Windows install medium vk can boot without AHCI or ATAPI (winiso.rs): a GPT disk whose
# one FAT32 partition, typed basic data (WinPE gives an EFI System Partition no drive letter),
# holds the ISO's files with install.wim split for FAT32. boot.wim's Setup image carries the
# virtio drivers and a script, started by winpeshl.ini, that loads viostor and starts Setup on
# the answer file; sources\$OEM$\$1\vk holds the virtio-win and qemu-ga installers, which Setup
# copies to C:\vk for the first logon.
#
# In: /in/iso/$ISO, /in/drivers/$DRIVERS, /assets/{autounattend.xml,setup.cmd,winpeshl.ini},
#     $DRIVERDIR (virtio-win's directory for this Windows, e.g. 2k25). Out: /out/media.img.
set -eu
T=/out/tmp; rm -rf "$T"; mkdir -p "$T/iso" "$T/drv" "$T/vw"
echo "vk-media: extracting the ISO"
(cd "$T/iso" && 7z x -y "/in/iso/$ISO" >/dev/null)
[ -f "$T/iso/sources/install.wim" ] || { echo "vk-media: no sources/install.wim in the ISO" >&2; exit 1; }
echo "vk-media: splitting install.wim"
wimlib-imagex split "$T/iso/sources/install.wim" "$T/iso/sources/install.swm" 3800 >/dev/null
rm "$T/iso/sources/install.wim"
echo "vk-media: virtio drivers ($DRIVERDIR)"
(cd "$T/vw" && 7z x -y "/in/drivers/$DRIVERS" "viostor/$DRIVERDIR/amd64" "NetKVM/$DRIVERDIR/amd64" \
   "vioserial/$DRIVERDIR/amd64" virtio-win-gt-x64.msi guest-agent/qemu-ga-x86_64.msi >/dev/null)
for d in viostor NetKVM vioserial; do
  [ -d "$T/vw/$d/$DRIVERDIR/amd64" ] || { echo "vk-media: no $d/$DRIVERDIR in the drivers ISO" >&2; exit 1; }
  mkdir -p "$T/drv/$d" && cp "$T/vw/$d/$DRIVERDIR/amd64/"* "$T/drv/$d/"
done
mkdir -p "$T/iso/sources/\$OEM\$/\$1/vk"
cp "$T/vw/virtio-win-gt-x64.msi" "$T/vw/guest-agent/qemu-ga-x86_64.msi" "$T/iso/sources/\$OEM\$/\$1/vk/"
echo "vk-media: boot.wim"
wimlib-imagex update "$T/iso/sources/boot.wim" 2 >/dev/null <<EOC
add $T/drv /vk/drivers
add /assets/setup.cmd /vk/setup.cmd
add /assets/autounattend.xml /vk/autounattend.xml
add /assets/winpeshl.ini /Windows/System32/winpeshl.ini
EOC
echo "vk-media: FAT32 disk"
img=/out/media.img; mb=$(du -sm "$T/iso" | cut -f1); rm -f "$img"; truncate -s $((mb + 512))M "$img"
sgdisk -n 1:2048:-34 -t 1:0700 -c 1:VKINSTALL "$img" >/dev/null
last=$(sgdisk -i 1 "$img" | sed -n 's/^Last sector: \([0-9]*\).*/\1/p')
off=$((2048 * 512))
mformat -i "$img@@$off" -T $((last - 2048 + 1)) -h 64 -s 32 -F -v VKINSTALL ::
mcopy -i "$img@@$off" -s -Q "$T/iso/"* ::/
rm -rf "$T"
echo "vk-media: done"
