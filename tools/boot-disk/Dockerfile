# The converter image tools/boot-disk/mkdisk.sh runs in, and a fixture source image to lay
# out (build context: tools/).
#
# converter: what lays the disk out, on vk's pinned kernel: sfdisk, mkfs.vfat, mtools,
# mke2fs and mkfs.btrfs all write from userspace through loop devices. Its UUIDs come from a
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

# fixture: a machine that can boot from its own /boot — systemd, a Debian kernel, and an
# initramfs-tools initrd that carries modprobe and the modules vk's agent loads before it
# mounts the root (virtio, ext4 for /boot, btrfs for the root, vsock, virtiofs, net).
FROM debian:trixie AS fixture
RUN mkdir -p /etc/initramfs-tools \
    && printf '%s\n' virtio_pci virtio_blk virtio_net virtio_balloon ext4 btrfs vfat \
        fuse virtiofs vsock vmw_vsock_virtio_transport > /etc/initramfs-tools/modules \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends systemd systemd-sysv dbus udev kmod linux-image-amd64 \
        initramfs-tools btrfs-progs dosfstools iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
