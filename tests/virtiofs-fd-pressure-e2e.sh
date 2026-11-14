#!/usr/bin/env bash
# End-to-end test for virtio-fs descriptor reclamation.
#
# Cached shared inodes can exhaust the VMM's descriptors without guest memory pressure,
# causing "Too many open files" errors. vk asks the guest to drop caches when the held-inode
# count reaches half the descriptor limit.
#
# Walk a share larger than half a small descriptor limit, then check that:
#   1. the VMM requested a trim and falls below half its limit plus an idle allowance
#      within 30 seconds of the walk ending;
#   2. the guest can still read and list the share.
# A trim may run during the walk, leaving later lookups cached. This test allows those
# descriptors; the watcher does not guarantee a ceiling for arbitrary workloads.
#
# Run:  VK=./dist/vk tests/virtiofs-fd-pressure-e2e.sh
# Needs: a `vk` with an embedded kernel/agent, KVM, network for the image pull,
#        GNU-coreutils `timeout`, and a vk configuration that leaves VMM processes their
#        default `vk:` name.
# Tunables: STEP_TIMEOUT caps the run (seconds, default 300); FDP_IMAGE overrides the guest
#        image.
set -euo pipefail
cd "$(dirname "$0")/.."

STEP_TIMEOUT=${STEP_TIMEOUT:-300}
case "$STEP_TIMEOUT" in ''|*[!0-9]*|0) echo "fd-pressure-e2e: invalid STEP_TIMEOUT" >&2; exit 2 ;; esac
FDP_IMAGE=${FDP_IMAGE:-docker.io/library/alpine:3.21}
NOFILE=4096
FILES=3000   # between half and all of NOFILE: a trim after halfway leaves fewer than half unvisited
IDLE=200     # an idle VMM's descriptors, generously
BOUND=$((NOFILE / 2 + IDLE))  # under FILES: a VMM that gave nothing back is over it

asked=${VK:-./dist/vk}
VK=$(command -v "$asked" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "fd-pressure-e2e: no executable vk at $asked (build one: ./build.sh --fast)" >&2; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")

[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "fd-pressure-e2e: no rw access to /dev/kvm" >&2; exit 2; }
command -v timeout >/dev/null || { echo "fd-pressure-e2e: need GNU-coreutils timeout" >&2; exit 2; }

echo "fd-pressure-e2e: testing $VK"

# Resolve symlinks to match the share's path in /proc when finding the VMM.
work=$(cd "$(mktemp -d)" && pwd -P)
run_pid=
cleanup() {
  [ -z "$run_pid" ] || kill "$run_pid" 2>/dev/null || true
  [ -z "$run_pid" ] || wait "$run_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir "$work/share" "$work/state"
for i in $(seq "$FILES"); do : > "$work/share/f$i"; done
echo intact > "$work/share/f1"

fail() { echo "fd-pressure-e2e: FAIL: $*" >&2; [ ! -s "$work/out.log" ] || sed 's/^/  | /' "$work/out.log" >&2; exit 1; }

# The guest walks the share, then idles until the host has measured, then reads it again.
guest='ls -l /share >/dev/null && touch /share/walked &&
  while [ ! -e /share/measured ]; do sleep 1; done &&
  cat /share/f1 && ls /share | wc -l'
(
  ulimit -n "$NOFILE"
  exec timeout -k 30 "$STEP_TIMEOUT" "$VK" run --state-dir "$work/state" \
    -v "$work/share:/share" "$FDP_IMAGE" -- sh -c "$guest"
) > "$work/out.log" 2>&1 &
run_pid=$!

# The VMM is the process holding the share open: it renames itself, and need not stay the
# run's child.
vmm_pid() {
  local comm p
  for comm in /proc/[0-9]*/comm; do
    p=${comm%/comm}
    case $(cat "$comm" 2>/dev/null) in vk:*) ;; *) continue ;; esac
    # Not `grep -q`: leaving early on a long listing fails `ls`, and the pipeline with it.
    if ls -l "$p/fd" 2>/dev/null | grep -F -- "-> $work/share" >/dev/null; then echo "${p#/proc/}"; return; fi
  done
}
fds() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }

for _ in $(seq "$STEP_TIMEOUT"); do
  kill -0 "$run_pid" 2>/dev/null || fail "the run ended before the guest walked the share"
  [ ! -e "$work/share/walked" ] || break
  sleep 1
done
[ -e "$work/share/walked" ] || fail "the guest never walked the share"
vmm=$(vmm_pid)
[ -n "$vmm" ] || fail "no VMM holds the share open"

now=
for _ in $(seq 30); do
  kill -0 "$vmm" 2>/dev/null || fail "the VMM went away while its descriptors were counted"
  now=$(fds "$vmm") || fail "the VMM went away while its descriptors were counted"
  [ "$now" -ge "$BOUND" ] || break
  sleep 1
done
[ "$now" -lt "$BOUND" ] || fail "the VMM still holds $now descriptors 30s after the guest walked $FILES files"
# Under the bound because of a trim, not because the walk held nothing.
grep -q "had it drop its" "$work/state/console.vmm.log" || fail "the VMM never had the guest drop its caches"
echo "fd-pressure-e2e: the VMM holds $now descriptors after the guest walked $FILES files"

touch "$work/share/measured"
wait "$run_pid" || fail "the run failed after its guest's caches were dropped"
run_pid=
grep -qx intact "$work/out.log" || fail "the guest did not read the share back"
grep -qx "$((FILES + 2))" "$work/out.log" || fail "the guest did not list the share back"

echo "fd-pressure-e2e: PASS"
