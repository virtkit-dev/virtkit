#!/usr/bin/env bash
# =====================================================================================
# TARGET TEST — NOT YET PASSING (the executable definition of "done").
# =====================================================================================
# Boot a stock Debian Bookworm image — its OWN systemd under its OWN (modular) kernel —
# on the libkrun backend, and confirm systemd took over PID 1 inside the microVM.
#
# Status today: FAILS. libkrun can LOAD a distro kernel (format sniffing), but reaching
# userspace still needs:
#   1. a preinit initramfs carrying vk-agent + the image's virtio_mmio/virtio_blk/ext4/
#      virtio_vsock/virtio_net modules (a stock Debian kernel has these as modules, and
#      libkrun already emits the `virtio_mmio.device=` cmdline params to discover them);
#   2. a vk-agent preinit that modprobes those, mounts the rootfs, switch_roots, forks a
#      persistent `vk-agent serve` (reparented to systemd), then execs /sbin/init.
#
# The `--init image --kernel image` invocation below is the intended interface. What is
# fixed is the OUTCOME asserted at the end. Run:  VK=./dist/vk tests/systemd-boot-e2e.sh
# Needs: a `vk` with an embedded agent, KVM, and build tooling.
set -euo pipefail

VK="${VK:-vk}"
if [ "${VIRTKIT_VMM:-libkrun}" != "libkrun" ]; then
  echo "SKIP: full-VM boot is libkrun-only (VIRTKIT_VMM=${VIRTKIT_VMM:-})"
  exit 0
fi
here="$(cd "$(dirname "$0")" && pwd)"
df="$here/systemd-boot/Dockerfile"
ctx="$here/systemd-boot"

echo "== build the stock Debian+systemd+kernel image and boot it as a full VM in one step =="
# One step: `run --init image --kernel image -f` builds the Dockerfile into an ext4, then
# virtkit extracts the image's /boot/vmlinuz, builds the preinit initramfs from its
# /lib/modules, boots libkrun on that kernel, and hands off to systemd; the reparented
# vk-agent serve carries this exec over vsock.
out="$(
  "$VK" run --init image --kernel image -f "$df" --context "$ctx" -- \
    sh -c '
      # The vk-agent serve becomes reachable the instant it forks — before the
      # exec'"'"'d systemd has finished booting and created its bus socket. Poll until
      # systemd reports a run state (its bus can be absent at first, so `--wait` alone
      # would error out), then read the marker the oneshot unit writes at multi-user.
      for i in $(seq 1 120); do
        state=$(systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) break;; esac
        sleep 1
      done
      echo "system-state: ${state:-unknown}"
      echo "---"
      cat /run/virtkit-systemd-up 2>/dev/null || echo NO-MARKER
    ' \
    2>&1
)"
echo "$out"

echo "== assertions =="
# systemd reached a run state (running, or degraded if some unit failed — still PID 1).
# `systemctl is-system-running` prints the state alone on a line, so match a whole line —
# a substring test would spuriously accept the echoed `is-system-running` command itself.
grep -Eq '^[[:space:]]*(running|degraded)[[:space:]]*$' <<<"$out" \
  || { echo "FAIL: systemd did not reach a run state (did the preinit hand off to /sbin/init?)"; exit 1; }
# our oneshot unit ran => systemd genuinely reached multi-user.target inside the VM.
grep -q 'VIRTKIT_SYSTEMD_UP' <<<"$out" \
  || { echo "FAIL: marker unit did not run"; exit 1; }

echo "PASS: Debian systemd booted under its own kernel on libkrun"
