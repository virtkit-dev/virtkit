# The converter image tools/boot-disk/mkdisk.sh runs in, and a fixture source image to lay
# out (build context: tools/).
#
# converter: what lays the disk out: sfdisk, mkfs.vfat, mtools, mke2fs and mkfs.btrfs all
# write from userspace through loop devices, on vk's pinned kernel. Its UUIDs come from a
# counter seeded by VK_UUID_SEED (btrfs-root/uuidshim.c) and its clock is frozen by
# libfaketime. Its base and packages are not pinned.
FROM debian:trixie AS converter
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends btrfs-progs e2fsprogs dosfstools mtools fdisk mount gcc \
        libc6-dev faketime \
    && rm -rf /var/lib/apt/lists/*
COPY btrfs-root/uuidshim.c /tmp/uuidshim.c
RUN printf '%s\n' \
        'UUID_1.0 { global: uuid_generate; uuid_generate_random; uuid_generate_time; };' \
        'UUID_2.20 { global: uuid_generate_time_safe; } UUID_1.0;' > /tmp/uuid.map \
    && gcc -shared -fPIC -O2 -Wl,--version-script=/tmp/uuid.map \
        -o /usr/local/lib/libvkuuid.so /tmp/uuidshim.c

# converter-luks: the converter with what an encrypted layout needs: a kernel of its own,
# for the device mapper, cryptsetup and LVM.
FROM converter AS converter-luks
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends linux-image-amd64 kmod cryptsetup-bin lvm2 \
    && rm -rf /var/lib/apt/lists/*

# fixture: a machine that can boot from its own /boot — systemd, a Debian kernel, and an
# initramfs-tools initrd that carries modprobe, the modules vk's agent loads (virtio, ext4
# for /boot, btrfs for the root, vsock, virtiofs, net), and what unlocks an encrypted LVM
# root with a key file on /boot. No resume device: its swap is no hibernation image.
FROM debian:trixie AS fixture
RUN mkdir -p /etc/initramfs-tools/conf.d \
    && printf '%s\n' virtio_pci virtio_blk virtio_net virtio_balloon ext4 btrfs vfat \
        fuse virtiofs vsock vmw_vsock_virtio_transport > /etc/initramfs-tools/modules \
    && echo RESUME=none > /etc/initramfs-tools/conf.d/resume \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends systemd systemd-sysv dbus udev kmod linux-image-amd64 \
        initramfs-tools btrfs-progs dosfstools iproute2 ca-certificates cryptsetup \
        cryptsetup-initramfs lvm2 \
    && rm -rf /var/lib/apt/lists/*
# The PID 1 probe logs mount modes before systemd can remount /. The test checks the
# source marker on the ESP after each boot.
RUN printf '%s\n' '#!/bin/sh' \
        'o() { findmnt -rno OPTIONS --mountpoint "$1" | cut -d, -f1; }' \
        'echo "vk-handoff: root=$(o /) var=$(o /var)" > /dev/kmsg' \
        'exec /sbin/init "$@"' > /usr/local/sbin/vk-handoff-probe \
    && chmod 0755 /usr/local/sbin/vk-handoff-probe \
    && mkdir -p /boot/efi/EFI/vk && echo esp-ok > /boot/efi/EFI/vk/marker
CMD ["/sbin/init"]
