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
