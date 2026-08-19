#!/usr/bin/env bash
# =====================================================================================
# The executable definition of "done" for the compose control plane in a full VM.
# =====================================================================================
# Boot a compose group whose primary hands PID 1 to the image's own systemd, and drive a
# sibling service from inside it through /run/vk/services — read the service's state, stop
# it, start it again.
#
# Two things are interesting. The control files outlive the handoff: they are mounted before
# the exec, under a /run that systemd would otherwise mount its own tmpfs over, hiding them
# (the mount stays listed in /proc/self/mounts and the path reads ENOENT). And the primary
# here is NOT root — the image declares `USER app` — so driving a sibling proves the control
# nodes belong to the run's own user, `ctl` being writable by its owner alone.
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
df="$here/fullvm-compose-ctl/Dockerfile"
ctx="$here/fullvm-compose-ctl"
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

echo "== boot a Debian+systemd image with a non-root USER as the compose primary =="
if ! out="$(
  "$VK" run --init image --kernel image -f "$df" --context "$ctx" \
    --compose "$tmp/compose.yml" -- \
    sh -c '
      set -eu
      # The vk-agent serve is reachable the instant it forks — before the exec'"'"'d systemd
      # has finished booting. Wait for the marker the oneshot unit writes at multi-user, so
      # the reads below happen in a guest systemd has already taken over and set /run up in.
      # A file, not `systemctl`: this command is not root, and a non-root systemctl needs the
      # D-Bus system bus, which a --no-install-recommends systemd does not pull in.
      for i in $(seq 1 120); do
        [ -f /run/virtkit-systemd-up ] && break
        sleep 1
      done
      echo "marker: $(cat /run/virtkit-systemd-up 2>/dev/null || echo NO-MARKER)"
      echo "who: $(id -u):$(id -g)"
      echo "ctl-owner: $(stat -c '%u:%g:%a' /run/vk/services/db/ctl 2>&1)"
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
# 1. systemd took PID 1 over and reached multi-user.target, so the reads below ran in a full
#    VM and not in a guest the agent kept.
grep -Eq '^marker: VIRTKIT_SYSTEMD_UP$' <<<"$out" \
  || { echo "FAIL: systemd did not reach multi-user.target"; exit 1; }
# 2. the control fs is readable after the handoff and reports the sibling the run started.
grep -Eq '^state: running$' <<<"$out" \
  || { echo "FAIL: /run/vk/services/db/state did not read the service's state"; exit 1; }
# 3. the served command really is the image's non-root USER, and the control nodes are its —
#    write-only to it rather than to everyone who may read the states. Before the control fs
#    was attributed to the run's user these were 0:0, and every write below was EACCES.
grep -Eq '^who: 1500:1500$' <<<"$out" \
  || { echo "FAIL: the served command did not run as the image's USER"; exit 1; }
grep -Eq '^ctl-owner: 1500:1500:200$' <<<"$out" \
  || { echo "FAIL: /run/vk/services/db/ctl is not the run user's, write-only"; exit 1; }
# 4. a write reaches the host service manager, in both directions — as that non-root user.
grep -Eq '^after-stop: stopped$' <<<"$out" \
  || { echo "FAIL: writing stop to the control file did not stop the service"; exit 1; }
grep -Eq '^after-start: running$' <<<"$out" \
  || { echo "FAIL: writing start to the control file did not start the service"; exit 1; }

echo "PASS: a non-root full-VM primary read and drove its compose sibling through /run/vk/services"
