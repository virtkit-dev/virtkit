#!/usr/bin/env bash
# Regression test for the cross-process instruction-cache corruption.
#
# A stage's diff push reuses its parent snapshot's chunks for the byte ranges it
# didn't touch. When several `vk` processes share one store, a concurrent push can
# clobber the parent's mutable *tag* with a byte-different (but content-equivalent)
# snapshot of the same instruction. A dependent diff push that re-fetched its parent
# chunks *by tag* then spliced that other build's bytes over its own backing, so an
# unchanged parent block (e.g. a base inode table) came back as a hole (zeros) and a
# restored stage failed fsck with "deleted inode referenced". The fix pins the parent
# by its immutable manifest digest, so the fetch resolves exactly the content this
# stage forked from (see `parent_for_push` in vk-driver/src/build/exec.rs).
#
# This test drives that exact scenario: N concurrent `vk` processes build one
# multi-stage target (a base + several independent diff stages + an assembling
# COPY target) into a shared fresh cache, then each diff stage is restored from
# the cache and fsck'd. On a buggy build several restores are corrupt; on a fixed
# build every restore is clean.
#
# Run against a build you want to check:
#   VK=./dist/vk tests/concurrent-cache-repro.sh
# To confirm the test actually catches the bug, run it against a pre-fix build —
# it must FAIL there.
set -euo pipefail

VK=${VK:-./dist/vk}
PROCS=${PROCS:-3}          # concurrent vk processes sharing the store
SIBLINGS=${SIBLINGS:-6}    # independent diff stages built concurrently
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-concurrent-cache.XXXXXX")
CACHE="$WORK/cache"
trap 'rm -rf "$WORK"' EXIT

command -v e2fsck >/dev/null || { echo "need e2fsck (e2fsprogs)"; exit 2; }

# --- self-contained Dockerfile: a debian base (real inode churn), SIBLINGS
# independent diff stages that only add files (leaving base blocks untouched, so
# they are *reused* parent chunks in each diff), and a scratch target that COPYs
# them all so one build materialises every sibling. ---
gen_dockerfile() {
  cat > "$WORK/Dockerfile" <<'EOF'
FROM debian:bookworm-slim AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps findutils file \
 && rm -rf /var/lib/apt/lists/*
EOF
  for i in $(seq 1 "$SIBLINGS"); do
    cat >> "$WORK/Dockerfile" <<EOF
FROM base AS s$i
RUN mkdir -p /s$i && for n in \$(seq 1 3000); do echo "s$i-\$n" > /s$i/f\$n; done
EOF
  done
  echo "FROM scratch AS all" >> "$WORK/Dockerfile"
  for i in $(seq 1 "$SIBLINGS"); do
    echo "COPY --from=s$i /s$i /s$i" >> "$WORK/Dockerfile"
  done
}

gen_dockerfile
rm -rf "$CACHE"
echo "### $PROCS concurrent 'vk build' processes -> shared fresh cache"
pids=()
for p in $(seq 1 "$PROCS"); do
  "$VK" build -f "$WORK/Dockerfile" --target all --build-jobs 1 \
    --cache-registry "$CACHE" --out "$WORK/all-$p.ext4" \
    > "$WORK/build-$p.log" 2>&1 &
  pids+=($!)
done
# a build may legitimately fail if it restores a stage another process poisoned
# mid-run; that is itself a symptom, so record but don't abort on it.
for pid in "${pids[@]}"; do wait "$pid" || true; done

echo "### restore + fsck each diff stage from the shared cache"
corrupt=0
for i in $(seq 1 "$SIBLINGS"); do
  if ! "$VK" build -f "$WORK/Dockerfile" --target "s$i" --require-cached \
        --cache-registry "$CACHE" --out "$WORK/r-s$i.ext4" \
        > "$WORK/restore-s$i.log" 2>&1; then
    echo "  s$i: RESTORE FAILED ($(tail -1 "$WORK/restore-s$i.log"))"
    corrupt=$((corrupt + 1))
    continue
  fi
  if e2fsck -fn "$WORK/r-s$i.ext4" > "$WORK/fsck-s$i.log" 2>&1; then
    echo "  s$i: clean"
  else
    echo "  s$i: CORRUPT ($(grep -aE 'deleted|filetype|still has errors' "$WORK/fsck-s$i.log" | head -1))"
    corrupt=$((corrupt + 1))
  fi
  rm -f "$WORK/r-s$i.ext4"
done

echo "### RESULT: $corrupt/$SIBLINGS diff entries corrupt"
if [ "$corrupt" -ne 0 ]; then
  echo "FAIL: concurrent cross-process pushes poisoned the cache"
  exit 1
fi
echo "PASS: concurrent cross-process pushes left every diff entry intact"
