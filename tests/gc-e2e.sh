#!/usr/bin/env bash
# =====================================================================================
# `vk gc` on a private home: the summary, what it takes, and the config it reads.
# =====================================================================================
# Everything happens under a scratch $HOME with its own XDG dirs, so no cache, state or
# config of the user running it is read or touched.
#
# Done means every step below holds:
#   1. `vk gc --dry-run` on empty caches prints one summary, every category at zero.
#   2. a `[gc]` size that is not one is refused when the config loads.
#   3. a dead run's launch dir goes, unless its pid is alive, it changed within the hour, or
#      its lock is held; a dry run removes nothing and counts what a real pass removes.
#
# Run:  VK=./dist/vk tests/gc-e2e.sh
# Needs: a `vk` binary, flock and touch -d. No network, no KVM, no image.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
command -v flock >/dev/null || { echo "SKIP: no flock"; exit 0; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-gc-e2e.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
export HOME=$WORK/home
export XDG_DATA_HOME=$HOME/data XDG_CACHE_HOME=$HOME/cache XDG_STATE_HOME=$HOME/state
export XDG_CONFIG_HOME=$HOME/config
unset VIRTKIT_CONFIG VIRTKIT_TOOLCHAIN_CACHE
DATA=$XDG_DATA_HOME/virtkit
SCRATCH=$XDG_CACHE_HOME/virtkit
mkdir -p "$DATA" "$SCRATCH" "$XDG_STATE_HOME" "$XDG_CONFIG_HOME"

pass=0
fail=0
ok() { echo "PASS: $*"; pass=$((pass + 1)); }
bad() { echo "FAIL: $*"; fail=$((fail + 1)); }

# A pid nothing runs under: a child already reaped.
dead_pid() { sh -c 'echo $$'; }
# A launch dir as a run killed by a signal leaves it, last changed `$2` ago.
launch() {
  local dir=$SCRATCH/launch-$1
  mkdir -p "$dir"
  head -c 65536 /dev/zero > "$dir/root.qcow2.tmp"
  touch -d "$2" "$dir/root.qcow2.tmp" "$dir"
  echo "$dir"
}

echo
echo "== 1. an empty host: one summary, nothing to take =="
out=$("$VK" gc --dry-run 2>&1) || { bad "vk gc --dry-run failed"; echo "$out"; exit 1; }
grep -q '^virtkit: gc would reclaim 0 B$' <<<"$out" && ok "the summary heads the output" || { bad "no summary line"; echo "$out"; }
grep -qE '^  images +0 ' <<<"$out" && ok "each category has its row" || { bad "no images row"; echo "$out"; }

echo
echo "== 2. a [gc] size that is not one =="
mkdir -p "$XDG_CONFIG_HOME/virtkit"
printf '[gc]\nbuild_cache_max = "lots"\n' > "$XDG_CONFIG_HOME/virtkit/config.toml"
if out=$("$VK" gc --dry-run 2>&1); then
  bad "a bad build_cache_max was accepted"
else
  grep -q 'is not a size' <<<"$out" && ok "a bad build_cache_max is refused" || { bad "refused for another reason"; echo "$out"; }
fi
rm "$XDG_CONFIG_HOME/virtkit/config.toml"

echo
echo "== 3. dead launch dirs =="
dead=$(launch "$(dead_pid)" '2 hours ago')
live=$(launch $$ '2 hours ago')
fresh=$(launch "$(dead_pid)" '10 minutes ago')
held=$(launch "$(dead_pid)" '2 hours ago')
exec {lockfd}<"$held"
flock -n "$lockfd"
touch -d '2 hours ago' "$held"
out=$("$VK" gc --dry-run 2>&1)
grep -qE '^  launch dirs +1 ' <<<"$out" && ok "a dry run counts the one dead dir" || { bad "dry run count"; echo "$out"; }
[ -d "$dead" ] && ok "and removes nothing" || bad "the dry run removed the dead dir"
out=$("$VK" gc 2>&1)
grep -qE '^  launch dirs +1 ' <<<"$out" && ok "a pass removes it" || { bad "pass count"; echo "$out"; }
[ ! -e "$dead" ] && ok "the dead dir is gone" || bad "the dead dir stayed"
for d in "$live" "$fresh" "$held"; do
  [ -d "$d" ] && ok "kept $(basename "$d")" || bad "removed $(basename "$d")"
done
exec {lockfd}<&-

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
