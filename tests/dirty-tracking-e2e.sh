#!/usr/bin/env bash
# End-to-end test: libkrun's block dirty-tracking reports every guest write.
#
# On the libkrun backend each cache checkpoint drains the block device's dirty set and
# cross-checks it against the qcow2 allocation map. A cluster the guest allocated this
# interval but the dirty set failed to report is a dropped write, and the build ABORTS with
# "dirty-tracking gap ..." (see `cache_save` in vk-driver/src/build/exec.rs). The old
# side-channel dropped gigabytes on COPY-heavy stages, cached a stale delta, and a restored
# stage later failed fsck; this test drives that exact shape into a fresh local cache and
# fails if it recurs:
#
#   1. cold build (a checkpoint per step) must succeed — no fatal gap — and export a
#      clean ext4;
#   2. warm rebuild (--require-cached) must restore the whole stage and fsck clean;
#   3. a tail-only edit must restore the cached *prefix* (an intermediate checkpoint, the
#      case that surfaced the original corruption) and fsck clean.
#
# A dropped write surfaces as the fatal gap abort or a corrupt restored ext4 — either fails
# this test. Dirty tracking is libkrun-only; the check is a no-op on cloud-hypervisor.
#
# VK must be a `vk` built from the current tree with an embedded kernel/agent (a dev build
# has neither — build one, or use ./dist/vk once refreshed):
#
#   VK=./dist/vk tests/dirty-tracking-e2e.sh
#
# MB=512 enlarges each COPY (more likely to surface a size-dependent drop).
set -euo pipefail

VK=${VK:-./dist/vk}
MB=${MB:-256}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-dirty-e2e.XXXXXX")
CACHE="$WORK/cache"
CTX="$WORK/ctx"
trap 'rm -rf "$WORK"' EXIT

command -v e2fsck >/dev/null || { echo "need e2fsck (e2fsprogs)"; exit 2; }
if [ "${VIRTKIT_VMM:-libkrun}" != "libkrun" ]; then
  echo "SKIP: dirty-tracking is libkrun-only (VIRTKIT_VMM=${VIRTKIT_VMM:-})"
  exit 0
fi

fsck_clean() { # <ext4> <label>
  if ! e2fsck -fn "$1" > "$WORK/fsck.log" 2>&1; then
    echo "FAIL: $2 is a corrupt ext4:"
    grep -aE 'deleted|filetype|unattached|still has errors|Inode' "$WORK/fsck.log" | head
    exit 1
  fi
}

mkdir -p "$CTX"
# Incompressible context files: COPYing each writes real, non-dedupable clusters into the
# stage disk — the "COPY-heavy" shape that dropped writes before. `instructions` cache mode
# commits (and drains the dirty set) at every step, so every write is gap-checked.
dd if=/dev/urandom of="$CTX/big1" bs=1M count="$MB" status=none
dd if=/dev/urandom of="$CTX/big2" bs=1M count="$MB" status=none

cat > "$CTX/Dockerfile" <<'EOF'
FROM debian:bookworm-slim AS churn
COPY big1 /big1
COPY big2 /big2
RUN dd if=/dev/urandom of=/big1 bs=1M count=64 status=none
RUN mkdir -p /many && for n in $(seq 1 4000); do echo "$n" > /many/f$n; done
EOF

build() { # <dockerfile> <out> <log> [extra args...]
  local df=$1 out=$2 log=$3
  shift 3
  "$VK" build -f "$df" --target churn --build-jobs 1 \
    --build-cache instructions --cache-registry "$CACHE" \
    --out "$out" "$@" > "$log" 2>&1
}

echo "### 1. cold build into a fresh cache (a checkpoint per step)"
if ! build "$CTX/Dockerfile" "$WORK/cold.ext4" "$WORK/cold.log"; then
  echo "FAIL: cold build aborted"
  if grep -q "dirty-tracking gap" "$WORK/cold.log"; then
    echo "  the block device's dirty set DROPPED a write:"
    grep "dirty-tracking gap" "$WORK/cold.log"
  else
    tail -20 "$WORK/cold.log"
  fi
  exit 1
fi
fsck_clean "$WORK/cold.ext4" "the exported image"

echo "### 2. warm rebuild restores the whole stage from the cache"
if ! build "$CTX/Dockerfile" "$WORK/warm.ext4" "$WORK/warm.log" --require-cached; then
  echo "FAIL: warm restore failed"
  tail -10 "$WORK/warm.log"
  exit 1
fi
fsck_clean "$WORK/warm.ext4" "the cache-restored image"

echo "### 3. tail edit restores the cached prefix (an intermediate checkpoint) + re-runs the tail"
sed 's/seq 1 4000/seq 1 4001/' "$CTX/Dockerfile" > "$CTX/Dockerfile.2"
if ! build "$CTX/Dockerfile.2" "$WORK/prefix.ext4" "$WORK/prefix.log"; then
  echo "FAIL: prefix rebuild failed (an intermediate checkpoint may be corrupt)"
  tail -15 "$WORK/prefix.log"
  exit 1
fi
fsck_clean "$WORK/prefix.ext4" "the prefix-restored image"

echo "PASS: dirty set reported every write; cold + warm + prefix images fsck clean"
