#!/bin/sh
# The image's ENTRYPOINT: prepare the machine, then hand PID 1 to the real init.
#
# This is the shape `--init image` cannot boot — it execs /sbin/init directly, so
# everything below is skipped in silence and systemd comes up with none of it.
set -eu

# Proof this ran, and that it ran as PID 1. Written to the rootfs, not /run: systemd
# mounts its own /run tmpfs over anything put there before it started.
# The argv goes in too: it is the image's CMD, so recording it proves ENTRYPOINT+CMD
# arrived whole rather than just the entrypoint.
echo "VIRTKIT_ENTRYPOINT_RAN pid=$$ args=$*" > /var/log/virtkit-entrypoint
# The guest's name as the entrypoint sees it — virtkit sets it before the handoff, so an
# appliance preparing the machine reads a real name and not the kernel default `(none)`.
# /proc/sys/kernel/hostname rather than hostname(1): the preinit mounts /proc, and a
# minimal image need not ship the binary.
echo "VIRTKIT_ENTRYPOINT_HOSTNAME=$(cat /proc/sys/kernel/hostname)" >> /var/log/virtkit-entrypoint
# And its address: virtkit applies the run-assigned one before the handoff, so an appliance
# configuring itself from the running interface has something to read.
echo "VIRTKIT_ENTRYPOINT_IPV4=$(ip -4 -o addr show eth0 | awk '{print $4}')" \
  >> /var/log/virtkit-entrypoint

# The preparation itself — a service that exists only because the entrypoint ran.
cat > /etc/systemd/system/virtkit-assembled.service <<'UNIT'
[Unit]
Description=assembled by the image entrypoint at boot
[Service]
Type=oneshot
ExecStart=/bin/sh -c "echo VIRTKIT_ASSEMBLED_UNIT_RAN > /run/virtkit-assembled"
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf ../virtkit-assembled.service \
  /etc/systemd/system/multi-user.target.wants/virtkit-assembled.service

# Hand PID 1 on, the way an init-execing entrypoint does under `docker run`.
exec /sbin/init "$@"
