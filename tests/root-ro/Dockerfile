# Debian bookworm (systemd 252) booting its own systemd and kernel, as an appliance does on
# its first boot: /etc/machine-id says `uninitialized`, so systemd applies the unit presets
# before anything remounts `/` rw.
#
# The image ships, beside systemd and its kernel:
#   /etc/fstab                     a `/` line, so systemd-remount-fs makes `/` rw
#   vk-preset-probe.service        enabled by a preset only, never by a symlink
#   vk-rw-probe.service            writes `/` by local-fs.target, enabled by a symlink
#   /usr/local/sbin/vk-test-init   the init `--init-argv` names: it logs its argv and how
#                                  `/` is mounted to the kernel log, then execs systemd
FROM debian:bookworm

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv \
        linux-image-amd64 \
        kmod; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    echo uninitialized > /etc/machine-id; \
    echo '/dev/vda / ext4 rw 0 0' > /etc/fstab; \
    printf '%s\n' \
      '[Unit]' \
      'Description=virtkit preset probe' \
      '[Service]' \
      'Type=oneshot' \
      'ExecStart=/bin/true' \
      '[Install]' \
      'WantedBy=multi-user.target' \
      > /etc/systemd/system/vk-preset-probe.service; \
    printf '%s\n' \
      '[Unit]' \
      'Description=virtkit: / is writable by local-fs.target' \
      'DefaultDependencies=no' \
      'After=systemd-remount-fs.service' \
      'Before=local-fs.target' \
      '[Service]' \
      'Type=oneshot' \
      'ExecStart=/bin/touch /var/lib/vk-rw-at-local-fs' \
      > /etc/systemd/system/vk-rw-probe.service; \
    mkdir -p /etc/systemd/system/local-fs.target.wants; \
    ln -s ../vk-rw-probe.service /etc/systemd/system/local-fs.target.wants/vk-rw-probe.service; \
    mkdir -p /etc/systemd/system-preset; \
    echo 'enable vk-preset-probe.service' > /etc/systemd/system-preset/10-vk.preset; \
    printf '%s\n' \
      '#!/bin/sh' \
      'root=$(awk '"'"'$2 == "/" { o = $4 } END { split(o, f, ","); print f[1] }'"'"' /proc/mounts)' \
      'echo "vk-test-init: root=$root argc=$# argv=$*" > /dev/kmsg' \
      'exec /lib/systemd/systemd "$@"' \
      > /usr/local/sbin/vk-test-init; \
    chmod 755 /usr/local/sbin/vk-test-init

CMD ["/sbin/init"]
