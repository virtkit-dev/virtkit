#!/usr/bin/env bash
# =====================================================================================
# The executable definition of "done" for `vk run --init entrypoint`.
# =====================================================================================
# Boot an image whose ENTRYPOINT prepares the machine and only then execs the real init,
# and confirm all three links of the chain: the entrypoint ran as PID 1, the service it
# assembled at boot exists, and systemd took PID 1 over from it — plus the precondition
# the first link needs, that the guest was named before the handoff.
#
# `--init image` fails the first two by construction: it hands PID 1 straight to
# /sbin/init, so the preparation is skipped and only systemd itself comes up.
#
# Run:  VK=./dist/vk tests/entrypoint-init-e2e.sh
# Needs: a `vk` with an embedded agent, KVM, and build tooling.
set -euo pipefail

VK="${VK:-vk}"
if [ "${VIRTKIT_VMM:-libkrun}" != "libkrun" ]; then
  echo "SKIP: full-VM boot is libkrun-only (VIRTKIT_VMM=${VIRTKIT_VMM:-})"
  exit 0
fi
here="$(cd "$(dirname "$0")" && pwd)"
df="$here/entrypoint-init/Dockerfile"
ctx="$here/entrypoint-init"

echo "== build the entrypoint-execs-systemd image and boot it as a full VM in one step =="
# `--init entrypoint` execs the image's ENTRYPOINT+CMD as PID 1 (read from the boot
# config, not the kernel cmdline); `--kernel image` boots the image's own kernel, so this
# is the same preinit path `--init image` takes and differs only in what it execs.
if ! out="$(
  "$VK" run --init entrypoint --kernel image -f "$df" --context "$ctx" -- \
    sh -c '
      # The vk-agent serve is reachable the instant it forks — before the entrypoint has
      # exec'"'"'d systemd, let alone before systemd finished booting. Poll for a run
      # state (its bus can be absent at first, so `--wait` alone would error out).
      for i in $(seq 1 120); do
        state=$(systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) break;; esac
        sleep 1
      done
      echo "system-state: ${state:-unknown}"
      echo "---"
      cat /var/log/virtkit-entrypoint 2>/dev/null || echo NO-ENTRYPOINT-MARKER
      cat /run/virtkit-assembled 2>/dev/null || echo NO-ASSEMBLED-MARKER
    ' \
    2>&1
)"; then
  echo "$out"
  echo "FAIL: the run itself failed — see the output above"
  exit 1
fi
echo "$out"

echo "== assertions =="
# 1. the entrypoint ran at all — this is what `--init image` skips.
grep -q 'VIRTKIT_ENTRYPOINT_RAN' <<<"$out" \
  || { echo "FAIL: the image entrypoint never ran (did the preinit exec it?)"; exit 1; }
# 2. it ran AS PID 1, not forked under the agent (which is what service mode does), and
#    with the image's CMD as its argv — the axis execs ENTRYPOINT+CMD, not ENTRYPOINT.
grep -q 'VIRTKIT_ENTRYPOINT_RAN pid=1 args=--log-level=info' <<<"$out" \
  || { echo "FAIL: the entrypoint did not run as PID 1 with the image's CMD"; exit 1; }
# 3. systemd reached a run state (degraded still means it is PID 1), so the entrypoint's
#    `exec /sbin/init` handed PID 1 on. Anchored on the whole line the guest prints, so a
#    state named anywhere else in the output cannot satisfy it.
grep -Eq '^system-state: (running|degraded)$' <<<"$out" \
  || { echo "FAIL: systemd did not reach a run state after the entrypoint exec'd it"; exit 1; }
# 4. the unit the entrypoint assembled at boot ran => the preparation reached systemd.
grep -q 'VIRTKIT_ASSEMBLED_UNIT_RAN' <<<"$out" \
  || { echo "FAIL: the entrypoint-assembled unit did not run"; exit 1; }
# 5. the guest was named before the handoff, so the entrypoint read a name and not the
#    kernel default `(none)`. `vm` is the name a run without a compose `hostname:` assigns.
grep -q '^VIRTKIT_ENTRYPOINT_HOSTNAME=vm$' <<<"$out" \
  || { echo "FAIL: the entrypoint ran before the guest was named"; exit 1; }

echo "PASS: the image entrypoint ran as PID 1, prepared the machine, and handed off to systemd"
