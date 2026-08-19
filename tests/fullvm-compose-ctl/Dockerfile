# Target: the systemd-boot image with a NON-ROOT `USER`, for the compose control plane.
# The `FROM`, the apt-get layer and the marker unit are byte-identical to
# tests/systemd-boot/Dockerfile, so that whole prefix restores from the builder's stage cache;
# everything from the `groupadd` on is this image's own.
#
# systemd still runs as PID 1 (`--init image` hands it over as root, and only the `entrypoint`
# axis drops to the USER); the USER is what a served command — the `-- <cmd>` this e2e drives
# the control files from — is dropped to. That command is therefore NOT root, which is the
# point: writing `ctl` proves the control nodes belong to the run's own user.
#
# The image ships:
#   /sbin/init            -> systemd (PID 1 after the preinit hands off)
#   /boot/vmlinuz-<ver>   -> the Debian kernel (virtkit reads it host-side to boot)
#   /lib/modules/<ver>/   -> the matching modules (virtkit seeds the preinit initramfs
#                            with virtio_pci/virtio_blk/ext4/vsock from here, so the
#                            modular kernel can reach its rootfs+vsock)
FROM debian:bookworm

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv \
        linux-image-amd64 \
        iproute2 kmod; \
    rm -rf /var/lib/apt/lists/*

# A oneshot marker unit the e2e test looks for — proof that systemd became PID 1, reached
# multi-user.target, and ran a unit inside the microVM. Enabled by a static symlink (no
# running daemon at build time).
RUN set -eux; \
    printf '%s\n' \
      '[Unit]' \
      'Description=virtkit systemd-boot marker' \
      '[Service]' \
      'Type=oneshot' \
      'ExecStart=/bin/sh -c "echo VIRTKIT_SYSTEMD_UP > /run/virtkit-systemd-up"' \
      'RemainAfterExit=yes' \
      '[Install]' \
      'WantedBy=multi-user.target' \
      > /etc/systemd/system/virtkit-marker.service; \
    mkdir -p /etc/systemd/system/multi-user.target.wants; \
    ln -sf ../virtkit-marker.service \
      /etc/systemd/system/multi-user.target.wants/virtkit-marker.service

# A non-root user with a real passwd entry, and the image's declared USER. The control fs is
# attributed to whoever this resolves to, so the served command below owns `ctl`. The gid is
# pinned explicitly rather than left to useradd's choice, since the e2e asserts both numbers.
RUN set -eux; \
    groupadd --gid 1500 app; \
    useradd --create-home --uid 1500 --gid 1500 app

USER app

# The image's own init. virtkit's preinit execs this after loading modules + switch_root;
# the USER above applies to served commands, not to PID 1.
CMD ["/sbin/init"]
