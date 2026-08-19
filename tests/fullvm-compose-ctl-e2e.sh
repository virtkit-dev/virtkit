#!/usr/bin/env bash
# =====================================================================================
# The executable definition of "done" for the compose control plane in a full VM.
# =====================================================================================
# Boot a compose group whose primary hands PID 1 to the image's own systemd, and drive a
# sibling service from inside it through /run/vk/services — read the service's state, stop
# it, start it again.
#
# The interesting part is that the control files outlive the handoff: they are mounted
# before the exec, under a /run that systemd would otherwise mount its own tmpfs over,
# hiding them (the mount stays listed in /proc/self/mounts and the path reads ENOENT).
#
# Run:  VK=./dist/vk tests/fullvm-compose-ctl-e2e.sh
# Needs: a `vk` with an embedded agent, KVM, build tooling, and a registry to pull alpine.
set -euo pipefail

VK="${VK:-vk}"
if [ "${VIRTKIT_VMM:-libkrun}" != "libkrun" ]; then
  echo "SKIP: full-VM boot is libkrun-only (VIRTKIT_VMM=${VIRTKIT_VMM:-})"
  exit 0
fi
here="$(cd "$(dirname "$0")" && pwd)"
df="$here/systemd-boot/Dockerfile"
ctx="$here/systemd-boot"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# One sibling service, plain enough to say nothing about the primary: what is under test is
# the primary's view of it, not the service itself.
cat > "$tmp/compose.yml" <<'EOF'
services:
  db:
    image: docker.io/library/alpine:3.21
    command: ["sleep", "infinity"]
EOF

echo "== boot the stock Debian+systemd image as the compose primary =="
if ! out="$(
  "$VK" run --init image --kernel image -f "$df" --context "$ctx" \
    --compose "$tmp/compose.yml" -- \
    sh -c '
      set -eu
      # The vk-agent serve is reachable the instant it forks — before the exec'"'"'d systemd
      # has finished booting. Poll for a run state, so the reads below happen in a guest
      # systemd has already taken over and set /run up in.
      for i in $(seq 1 120); do
        state=$(systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) break;; esac
        sleep 1
      done
      echo "system-state: ${state:-unknown}"
      echo "state: $(cat /run/vk/services/db/state 2>&1)"
      echo stop > /run/vk/services/db/ctl
      echo "after-stop: $(cat /run/vk/services/db/state 2>&1)"
      echo start > /run/vk/services/db/ctl
      echo "after-start: $(cat /run/vk/services/db/state 2>&1)"
    ' \
    2>&1
)"; then
  echo "$out"
  echo "FAIL: the run itself failed — see the output above"
  exit 1
fi
echo "$out"

echo "== assertions =="
# 1. systemd took PID 1 over (degraded still means it is PID 1), so the reads below ran in
#    a full VM and not in a guest the agent kept.
grep -Eq '^system-state: (running|degraded)$' <<<"$out" \
  || { echo "FAIL: systemd did not reach a run state"; exit 1; }
# 2. the control fs is readable after the handoff and reports the sibling the run started.
grep -Eq '^state: running$' <<<"$out" \
  || { echo "FAIL: /run/vk/services/db/state did not read the service's state"; exit 1; }
# 3. a write reaches the host service manager, in both directions.
grep -Eq '^after-stop: stopped$' <<<"$out" \
  || { echo "FAIL: writing stop to the control file did not stop the service"; exit 1; }
grep -Eq '^after-start: running$' <<<"$out" \
  || { echo "FAIL: writing start to the control file did not start the service"; exit 1; }

echo "PASS: a full-VM primary read and drove its compose sibling through /run/vk/services"
