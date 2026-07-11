#!/usr/bin/env bash
# Repro + regression test for the dirty-tracking gap on a mid-stage reboot.
#
# The block device's dirty set lives in the VM; a source-batch reboot (a stage needing more
# than MAX_SOURCE_DISKS=12 distinct `COPY --from` sources) tears the VM down and boots a fresh
# one, resetting the set — but the qcow2 disk persists. Any write done before the reboot is
# still in the disk's allocation map yet gone from the new set, so the next checkpoint reports
# it as a gap. This drives exactly that: a big write, then >12 source COPYs (forcing a reboot),
# committed as one layer (`--build-cache layers`, so nothing drains before the reboot).
#
# On the buggy build the checkpoint logs (or, with the fatal check, aborts on) a dirty-tracking
# gap; on a fixed build the set is carried across the reboot and there is none.
#
#   VK=./dist/vk tests/dirty-tracking-reboot.sh
set -euo pipefail

VK=${VK:-./dist/vk}
SRC=${SRC:-14}   # > MAX_SOURCE_DISKS (12) so the churn stage reboots mid-build
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-dirty-reboot.XXXXXX")
CACHE="$WORK/cache"
trap 'rm -rf "$WORK"' EXIT

if [ "${VIRTKIT_VMM:-libkrun}" != "libkrun" ]; then
  echo "SKIP: dirty-tracking is libkrun-only (VIRTKIT_VMM=${VIRTKIT_VMM:-})"
  exit 0
fi

{
  echo "FROM debian:bookworm-slim AS base"
  for i in $(seq 1 "$SRC"); do
    printf 'FROM base AS s%s\nRUN echo %s > /f\n' "$i" "$i"
  done
  echo "FROM base AS churn"
  # A big write with nothing draining before the reboot below.
  echo "RUN dd if=/dev/urandom of=/big bs=1M count=256 status=none"
  # >12 distinct sources: attaching s13.. evicts the batch and reboots the stage guest.
  for i in $(seq 1 "$SRC"); do
    echo "COPY --from=s$i /f /s$i"
  done
} > "$WORK/Dockerfile"

echo "### build churn (--build-cache layers): a big write, then $SRC source COPYs -> a reboot"
# VIRTKIT_TIMING surfaces the reboot count so the test shows a reboot actually happened.
VIRTKIT_TIMING=1 "$VK" build -f "$WORK/Dockerfile" --target churn --build-jobs 1 \
  --build-cache layers --cache-registry "$CACHE" \
  --out "$WORK/churn.ext4" > "$WORK/build.log" 2>&1 || true   # may abort if the check is fatal

echo "### reboots this build did (expect >=1):"
grep "reboot.finish" "$WORK/build.log" | head -1 | sed 's/^/  /' || echo "  (none reported)"

if grep -q "dirty-tracking gap" "$WORK/build.log"; then
  echo "REPRODUCED: the dirty set dropped writes across a mid-stage reboot:"
  grep "dirty-tracking gap" "$WORK/build.log" | head -1
  exit 1
fi
echo "PASS: no dirty-tracking gap across the reboot"
