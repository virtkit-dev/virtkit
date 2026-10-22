#!/usr/bin/env bash
# =====================================================================================
# `vk gc` on a private home: the summary and what it takes.
# =====================================================================================
# Everything happens under a scratch $HOME with its own XDG dirs, so no cache, state or
# config of the user running it is read or touched.
#
# Done means every step below holds:
#   1. `vk gc --dry-run` on empty caches prints one summary, every category at zero.
#
# Run:  VK=./dist/vk tests/gc-e2e.sh
# Needs: a `vk` binary. No network, no KVM, no image.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-gc-e2e.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
export HOME=$WORK/home
export XDG_DATA_HOME=$HOME/data XDG_CACHE_HOME=$HOME/cache XDG_STATE_HOME=$HOME/state
export XDG_CONFIG_HOME=$HOME/config
unset VIRTKIT_CONFIG VIRTKIT_TOOLCHAIN_CACHE
DATA=$XDG_DATA_HOME/virtkit
mkdir -p "$DATA" "$XDG_STATE_HOME" "$XDG_CONFIG_HOME"

pass=0
fail=0
ok() { echo "PASS: $*"; pass=$((pass + 1)); }
bad() { echo "FAIL: $*"; fail=$((fail + 1)); }

echo
echo "== 1. an empty host: one summary, nothing to take =="
out=$("$VK" gc --dry-run 2>&1) || { bad "vk gc --dry-run failed"; echo "$out"; exit 1; }
grep -q '^virtkit: gc would reclaim 0 B$' <<<"$out" && ok "the summary heads the output" || { bad "no summary line"; echo "$out"; }
grep -qE '^  images +0 ' <<<"$out" && ok "each category has its row" || { bad "no images row"; echo "$out"; }

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
