#!/usr/bin/env bash
# Repro for the "reading qcow2 data cluster" chunker failure, hypothesised to come from fstrim.
#
# Before every checkpoint, cache_save runs `fstrim /` so freed blocks don't enter the cached
# delta. fstrim issues virtio DISCARDs, imago deallocates (and may compact/truncate) the stage
# qcow2, and the block device also records the discarded ranges in the dirty set. If that leaves
# a still-live cluster's L2 entry pointing past the file's new EOF — or the dirty-set delta then
# reads a discarded cluster the qcow2 no longer holds — the background push fails with
# "chunker error: ... reading qcow2 data cluster" and the stage is left uncached.
#
# This drives that churn hard: allocate a big file, delete it (freeing a large region for the
# next fstrim), reallocate, repeat — one checkpoint (hence one fstrim) per step. It fails if any
# push errors, or if the exported / cache-restored image doesn't fsck clean.
#
#   VK=./dist/vk tests/dirty-tracking-trim.sh
#
# MB sizes the churned file (default 400).
set -euo pipefail

VK=${VK:-./dist/vk}
MB=${MB:-400}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-dirty-trim.XXXXXX")
CACHE="$WORK/cache"
trap 'rm -rf "$WORK"' EXIT

command -v e2fsck >/dev/null || { echo "need e2fsck (e2fsprogs)"; exit 2; }
if [ "${VIRTKIT_VMM:-libkrun}" != "libkrun" ]; then
  echo "SKIP: dirty-tracking is libkrun-only (VIRTKIT_VMM=${VIRTKIT_VMM:-})"
  exit 0
fi

# write -> delete -> reallocate, so each checkpoint's fstrim discards the previous step's file
# (a large freed region) that the next step reallocates. `sync` inside each RUN pushes the writes
# to the block device so the churn is real, not just page cache.
cat > "$WORK/Dockerfile" <<EOF
FROM debian:bookworm-slim AS trimchurn
RUN dd if=/dev/urandom of=/a bs=1M count=$MB status=none && sync
RUN rm -f /a && dd if=/dev/urandom of=/b bs=1M count=$MB status=none && sync
RUN rm -f /b && dd if=/dev/urandom of=/c bs=1M count=$MB status=none && sync
RUN rm -f /c && dd if=/dev/urandom of=/d bs=1M count=$MB status=none && sync
RUN rm -f /d && mkdir -p /many && for n in \$(seq 1 5000); do echo \$n > /many/f\$n; done && sync
EOF

fsck_clean() { # <ext4> <label>
  if ! e2fsck -fn "$1" > "$WORK/fsck.log" 2>&1; then
    echo "FAIL: $2 is a corrupt ext4:"
    grep -aE 'deleted|filetype|unattached|still has errors|past the end|Inode' "$WORK/fsck.log" | head
    exit 1
  fi
}

build() { # <out> <log> [extra args...]
  local out=$1 log=$2
  shift 2
  "$VK" build -f "$WORK/Dockerfile" --target trimchurn --build-jobs 1 \
    --build-cache instructions --cache-registry "$CACHE" \
    --out "$out" "$@" > "$log" 2>&1
}

echo "### cold build with fstrim churn (a checkpoint — and fstrim — per step)"
if ! build "$WORK/cold.ext4" "$WORK/cold.log"; then
  echo "FAIL: cold build aborted"
  tail -20 "$WORK/cold.log"
  exit 1
fi
# A failed push is logged but non-fatal (the stage is just left uncached) — catch it explicitly.
if grep -qE "async push failed|reading qcow2 data cluster|chunker error" "$WORK/cold.log"; then
  echo "REPRODUCED: a checkpoint push failed reading the trimmed snapshot:"
  grep -E "async push failed|reading qcow2 data cluster|chunker error" "$WORK/cold.log" | head -2
  exit 1
fi
fsck_clean "$WORK/cold.ext4" "the exported image"

echo "### warm rebuild restores every fstrim'd checkpoint from the cache"
if ! build "$WORK/warm.ext4" "$WORK/warm.log" --require-cached; then
  echo "FAIL: warm restore failed (a cached checkpoint may be unreadable/corrupt)"
  tail -10 "$WORK/warm.log"
  exit 1
fi
fsck_clean "$WORK/warm.ext4" "the cache-restored image"

# Faithfulness: the cache-restored image must be byte-identical to the one actually built.
# fsck passes either way (a trimmed block is unreferenced), but if a trimmed cluster reassembles
# as the parent's stale bytes instead of a hole, the two images differ here.
echo "### cache-restored image must be byte-identical to the exported one"
if ! cmp "$WORK/cold.ext4" "$WORK/warm.ext4"; then
  n=$(cmp -l "$WORK/cold.ext4" "$WORK/warm.ext4" 2>/dev/null | wc -l)
  echo "FAIL: restored image differs from the exported one at $n byte(s) — a checkpoint's"
  echo "      delta did not faithfully represent the stage (likely trimmed clusters reassembled"
  echo "      as stale parent data instead of holes)"
  exit 1
fi

echo "PASS: fstrim churn cached + restored cleanly, byte-faithful, no push read failures"
