# Exporting appliances: VMDK, OVA, and auto-install ISOs

`vk build --disk` produces a fully installed, bootable raw disk: a Dockerfile
stage partitions the caller's disk file, copies the rootfs in and installs a
bootloader (see the flag's help). `vk export` then packages that disk — or a
staged directory around it — as a distributable artifact. Everything is
written natively; no qemu-img, ovftool or xorriso on the host.

## VMware: `vk export vmdk` and `vk export ova`

```sh
qemu-img create -f raw disk.raw 12G        # or truncate -s 12G disk.raw
vk build -f Dockerfile --disk disk.raw     # a RUN partitions + grub-installs it
vk export ova disk.raw appliance.ova --name my-appliance --cpus 4 --mem 8G
```

`vmdk` writes the streamOptimized subformat (compressed, stream-readable —
the one vSphere's OVF/OVA import requires). `ova` wraps it in an OVF
descriptor + SHA256 manifest: one file ESXi/vCenter import directly. The
descriptor declares a VirtualSCSI (pvscsi) controller and a VMXNET3 NIC;
`--guest-os` sets the VMware guest identifier and `--firmware bios|efi` must
match how the disk boots (BIOS/MBR grub vs. an ESP). The guest image needs
the matching drivers — Debian's `linux-image-cloud-amd64` carries
`vmw_pvscsi` and `vmxnet3`.

## Auto-install ISO: `vk export iso`

The ISO model is image-based install, not a distro installer: the medium
carries a kernel + small installer initramfs + the **finished disk image**
(compressed), boots, writes the image onto the target disk, grows the last
partition, reboots. `vk export iso` provides the container and the boot
plumbing — ISO 9660 with Rock Ridge, an El Torito catalog with BIOS and/or
UEFI entries, the BIOS boot-info-table patch, and an optional hybrid MBR so
the same file dd's onto a USB stick. What boots and what it does are staged
by you (usually a Dockerfile stage), exactly like `vk build --disk` leaves
partitioning policy to the Dockerfile.

Stage a tree:

```text
tree/
  boot/vmlinuz               # installer kernel (e.g. the image's own)
  boot/initrd.img            # installer initramfs: writes the payload to disk
  boot/grub/grub.cfg         # menu: linux /boot/vmlinuz vk.autoinstall ...
  boot/grub/eltorito.img     # BIOS El Torito image (grub-mkimage i386-pc)
  boot/grub/efi.img          # FAT ESP carrying EFI/BOOT/BOOTX64.EFI
  payload/disk.img.zst       # the vk-built raw disk, compressed
  install.sh                 # what the initramfs runs: pick disk, zstd -d, dd
```

then package it:

```sh
vk export iso tree/ installer.iso --volid MY_APPLIANCE \
    --bios-boot boot/grub/eltorito.img --efi-boot boot/grub/efi.img \
    --hybrid-mbr isohdpfx.bin
```

Notes on the boot images (both are ordinary members of the tree, so the
booted installer can read them back):

- **UEFI** (`--efi-boot`): a FAT image with the bootloader at
  `EFI/BOOT/BOOTX64.EFI`. `grub-mkstandalone -O x86_64-efi` produces a
  self-contained one whose embedded config can `search --file` for the ISO
  volume and source `/boot/grub/grub.cfg` from it. Build the FAT with
  mtools (`truncate` + `mformat`/`mmd`/`mcopy`) — no root needed.
- **BIOS** (`--bios-boot`): grub's `cdboot.img` + a `grub-mkimage
  -O i386-pc` core with the `iso9660` module (or isolinux.bin). vk patches
  the El Torito boot info table into it, which both loaders require.
- **USB** (`--hybrid-mbr`): pass x86 MBR boot code such as syslinux's
  `isohdpfx.bin`. vk lays it into the system area with a partition covering
  the ISO and, when an EFI image is present, a type-0xEF partition mapping
  the embedded ESP so USB UEFI firmware finds it without El Torito.

Limits, rejected loudly rather than mis-written: members of 4 GiB or more
(ISO multi-extent is not supported — keep the payload compressed or split
it), symlinks to directories, non-UTF-8 names. A symlink to a file is
followed: the staged link stores the file's content.

## Other formats

qcow2 (Proxmox/KVM), VHD (Azure) and VHDX (Hyper-V) remain a one-line
`qemu-img convert` away from the same `disk.raw`; they may join `vk export`
if a pipeline needs them host-tool-free.
