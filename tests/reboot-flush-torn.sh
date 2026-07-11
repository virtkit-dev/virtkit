#!/usr/bin/env bash
# Repro + regression test for a torn stage overlay across a mid-stage reboot.
#
# A source-batch reboot (a stage needing more than MAX_SOURCE_DISKS=12 distinct `COPY --from`
# sources) tears the VM down and boots a fresh one on the same qcow2. The pre-reboot VM's
# shutdown flush persists the overlay's L2 metadata but not the full tail data cluster, leaving
# an L2 entry that points past the file's physical end. A later native read of the overlay — the
# cache push or the final export — then fails:
#
#   reading qcow2 data cluster: ... file is N bytes — L2 entry points past EOF (torn overlay)
#
# This drives exactly that: a big write (so the overlay has a large tail), then >12 source COPYs
# forcing a reboot before the stage's read. It fails if the build tears the overlay, aborts, or
# exports a corrupt ext4.
#
#   VK=./dist/vk tests/reboot-flush-torn.sh
set -euo pipefail

VK=${VK:-./dist/vk}
SRC=${SRC:-14}   # > MAX_SOURCE_DISKS (12) so the churn stage reboots mid-build
MB=${MB:-200}    # size of the pre-reboot write; a big tail makes the tear reliable
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-reboot-torn.XXXXXX")
CACHE="$WORK/cache"
trap 'rm -rf "$WORK"' EXIT

command -v e2fsck >/dev/null || { echo "need e2fsck (e2fsprogs)"; exit 2; }
if [ "${VIRTKIT_VMM:-libkrun}" != "libkrun" ]; then
  echo "SKIP: libkrun-only (VIRTKIT_VMM=${VIRTKIT_VMM:-})"
  exit 0
fi

{
  echo "FROM debian:bookworm-slim AS base"
  echo "RUN echo base > /base"
  for i in $(seq 1 "$SRC"); do
    printf 'FROM base AS s%s\nRUN echo %s > /f\n' "$i" "$i"
  done
  echo "FROM base AS churn"
  # A big write whose tail must survive the reboot's shutdown flush.
  echo "RUN dd if=/dev/urandom of=/big bs=1M count=$MB status=none && sync"
  # >12 distinct sources: attaching s13.. evicts the batch and reboots the stage guest.
  for i in $(seq 1 "$SRC"); do
    echo "COPY --from=s$i /f /s$i"
  done
} > "$WORK/Dockerfile"

echo "### build churn: a ${MB}MiB write, then $SRC source COPYs -> a mid-stage reboot"
# VIRTKIT_TIMING surfaces the reboot count so the test shows a reboot actually happened.
VIRTKIT_TIMING=1 "$VK" build -f "$WORK/Dockerfile" --target churn --build-jobs 1 \
  --build-cache instructions --cache-registry "$CACHE" \
  --out "$WORK/churn.ext4" > "$WORK/build.log" 2>&1 || true

echo "### reboots this build did (expect >=1):"
grep "reboot.finish" "$WORK/build.log" | head -1 | sed 's/^/  /' || echo "  (none reported)"

if grep -qE "reading qcow2 data cluster|past EOF|torn overlay" "$WORK/build.log"; then
  echo "REPRODUCED: the stage overlay was torn across the reboot (L2 entry past EOF):"
  grep -E "reading qcow2 data cluster|past EOF|torn overlay" "$WORK/build.log" | head -1
  exit 1
fi
if grep -qE "async push failed|error:" "$WORK/build.log"; then
  echo "FAIL: the build reported an error:"
  grep -E "async push failed|error:" "$WORK/build.log" | head -2
  exit 1
fi
if [ ! -s "$WORK/churn.ext4" ]; then
  echo "FAIL: no output image was exported"
  tail -15 "$WORK/build.log"
  exit 1
fi
if ! e2fsck -fn "$WORK/churn.ext4" > "$WORK/fsck.log" 2>&1; then
  echo "FAIL: the exported image is a corrupt ext4:"
  grep -aE 'past the end|deleted|unattached|still has errors|Inode' "$WORK/fsck.log" | head
  exit 1
fi
echo "PASS: the overlay survived the reboot intact (no tear, image fsck-clean)"
