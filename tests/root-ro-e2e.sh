#!/usr/bin/env bash
# `vk run --init image` on a read-only root, with a prepare command and an init argv.
#
# Boots the same first-boot Debian bookworm image (systemd 252) three times:
#   1. --root ro: prepare writes `/`, the init (vk-test-init, from --init-argv) starts on a
#      read-only `/` with its arguments, systemd remounts `/` rw from the fstab, and the
#      preset-only unit stays disabled — the first-boot presets could not write `/`;
#   2. the default rw root: the same presets enable that unit;
#   3. a failing prepare: no init starts, the agent keeps PID 1, and the host reads why in
#      the guest's status.
#
# Run:  VK=./dist/vk tests/root-ro-e2e.sh
# Needs: a `vk` with an embedded agent, KVM, and build tooling.
set -euo pipefail

VK="${VK:-vk}"
here="$(cd "$(dirname "$0")" && pwd)"
df="$here/root-ro/Dockerfile"
ctx="$here/root-ro"
base="${TMPDIR:-/tmp}"
WORK=$(mktemp -d "$base/vk-root-ro-e2e.XXXXXX")
# The detached run of case 3, addressed by its agent: its project directory is the caller's.
fail_addr="vsock-auto://$WORK/fail/vsock.sock:4444"
fail_pid=""
cleanup() {
  [ -z "$fail_pid" ] || "$VK" stop "$fail_pid" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Wait for systemd to settle, then report what the assertions read.
probe='
  for i in $(seq 1 300); do
    state=$(systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break;; esac
    sleep 1
  done
  echo "system-state: ${state:-unknown}"
  dmesg | grep -o "vk-test-init: .*" || echo "vk-test-init: none"
  echo "prepared: $(cat /var/lib/vk-prepared 2>/dev/null || echo none)"
  echo "preset-probe: $(systemctl is-enabled vk-preset-probe.service 2>/dev/null || true)"
  if touch /vk-rw-probe 2>/dev/null; then echo "root-now: rw"; else echo "root-now: ro"; fi
  [ -e /var/lib/vk-rw-at-local-fs ] && echo "rw-at-local-fs: yes" || echo "rw-at-local-fs: no"
'

boot() {
  "$VK" run --init image --kernel image -f "$df" --context "$ctx" \
    --init-argv '/usr/local/sbin/vk-test-init --log-level=info' \
    --prepare "sh -c 'echo yes > /var/lib/vk-prepared'" \
    "$@" -- sh -c "$probe" 2>&1
}

expect() { # <output> <line regex> <what>
  grep -Eq "$2" <<<"$1" || { echo "FAIL: $3"; exit 1; }
}

echo "== 1. read-only root =="
out=$(boot --root ro) || { echo "$out"; echo "FAIL: the ro run failed"; exit 1; }
echo "$out"
expect "$out" '^system-state: (running|degraded)$' "systemd did not reach a run state"
expect "$out" '^vk-test-init: root=ro argc=1 argv=--log-level=info$' \
  "the init did not start on a read-only / with its --init-argv"
expect "$out" '^prepared: yes$' "prepare did not run on a writable /"
expect "$out" '^preset-probe: disabled$' "the first-boot presets enabled a unit on a read-only /"
expect "$out" '^root-now: rw$' "systemd did not remount / rw from the fstab"
expect "$out" '^rw-at-local-fs: yes$' "/ was not writable by local-fs.target"

echo "== 2. read-write root =="
out=$(boot) || { echo "$out"; echo "FAIL: the rw run failed"; exit 1; }
echo "$out"
expect "$out" '^vk-test-init: root=rw argc=1 argv=--log-level=info$' \
  "the init did not start on a writable /"
expect "$out" '^preset-probe: enabled$' "the first-boot presets did not enable the unit on a writable /"

echo "== 3. failing prepare =="
# The boot is up once the guest answers, whatever the handoff does after: the guest stays up,
# and its status says why it holds.
# `sleep infinity` keeps the run, which ends with its command, until the cleanup stops it.
out=$("$VK" run --init image --kernel image -f "$df" --context "$ctx" \
  --state-dir "$WORK/fail" --detach --prepare false -- sleep infinity 2>&1) \
  || { echo "$out"; echo "FAIL: the detached run failed"; exit 1; }
echo "$out"
fail_pid=$(grep -o 'detached (pid [0-9]*' <<<"$out" | grep -o '[0-9]*$' || true)
status=""
for i in $(seq 1 60); do
  status=$("$VK" status "$fail_addr" 2>&1 || true)
  grep -q 'handoff:failed' <<<"$status" && break
  sleep 1
done
echo "$status"
expect "$status" 'handoff:failed \(prepare \["false"\] exited 1\)' \
  "vk status does not report the failed prepare"
# The agent, run as the initramfs's /init, still holds PID 1.
comm=$("$VK" exec "$fail_addr" -- cat /proc/1/comm 2>/dev/null) \
  || { echo "FAIL: the held guest does not take vk exec"; exit 1; }
[ "$comm" = init ] || { echo "FAIL: PID 1 is $comm, not the agent, after a failed prepare"; exit 1; }

echo "PASS: init image on a read-only root, with prepare and init argv"
