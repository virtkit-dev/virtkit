#!/usr/bin/env bash
# =====================================================================================
# `vk gc` on a private home: the summary, what it takes, the config it reads, and the
# pass the commands that fill the caches start in the background.
# =====================================================================================
# Everything happens under a scratch $HOME with its own XDG dirs, so no cache, state or
# config of the user running it is read or touched.
#
# Done means every step below holds:
#   1. `vk gc --dry-run` on empty caches prints one summary, every category at zero.
#   2. a `[gc]` size that is not one is refused when the config loads.
#   3. a dead run's launch dir goes, unless its pid is alive, it changed within the hour, or
#      its lock is held; a dry run removes nothing and counts what a real pass removes.
#   4. a command that fills the caches starts a background pass when one is due, which
#      logs and dates itself; not within minutes of the last, not under VK_GC_AUTO=0, not
#      under `[gc] auto = false`.
#   5. short of space, a command starts a pass at once and says so; a pass that could not
#      get back above the floor holds the next such one off.
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
unset VIRTKIT_CONFIG VIRTKIT_TOOLCHAIN_CACHE VK_GC_AUTO
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
echo "== 4. the background pass =="
# `vk registry pull` fills a cache, so it starts a pass; with no registry configured it then
# fails on its own, which is all this needs of it.
pull() { "$VK" registry pull virtkit/none:x 2>&1 || true; }
wait_for() { for _ in $(seq 100); do [ -e "$1" ] && return 0; sleep 0.1; done; return 1; }
# The manual passes above dated themselves; this section starts from a host none has.
rm -f "$DATA/.gc-done" "$DATA/.gc-started"
VK_GC_AUTO=0 pull >/dev/null
[ ! -e "$DATA/gc.log" ] && ok "VK_GC_AUTO=0 starts none" || bad "VK_GC_AUTO=0 started a pass"
printf '[gc]\nauto = false\n' > "$XDG_CONFIG_HOME/virtkit/config.toml"
pull >/dev/null
[ ! -e "$DATA/gc.log" ] && ok "[gc] auto = false starts none" || bad "auto = false started a pass"
rm "$XDG_CONFIG_HOME/virtkit/config.toml"
pull >/dev/null
if wait_for "$DATA/.gc-done"; then
  ok "a due pass ran to its end"
else
  bad "no pass finished"
fi
grep -q '^virtkit: background gc at ' "$DATA/gc.log" && ok "it logged itself" || { bad "no log"; cat "$DATA/gc.log" || true; }
touch -d '5 minutes ago' "$DATA/.gc-started"
touch -d '2 days ago' "$DATA/.gc-done"
before=$(stat -c %Y "$DATA/.gc-started")
pull >/dev/null
sleep 1
[ "$(stat -c %Y "$DATA/.gc-started")" = "$before" ] && ok "none starts within minutes of the last" || bad "a second pass started at once"

echo
echo "== 5. short of space =="
printf '[gc]\nmin_free = "100%%"\n' > "$XDG_CONFIG_HOME/virtkit/config.toml"
touch -d '1 hour ago' "$DATA/.gc-started"
touch "$DATA/.gc-done"
rm -f "$DATA/.gc-short"
out=$(pull)
grep -q 'reclaiming unused caches in the background' <<<"$out" && ok "the command says it" || { bad "no word of it"; echo "$out"; }
if wait_for "$DATA/.gc-short"; then
  ok "a pass that cannot reach the floor says so"
else
  bad "no pass marked itself short"; cat "$DATA/gc.log" || true
fi
grep -q 'still short of space' "$DATA/gc.log" && ok "and logs why" || bad "no word of it in the log"
touch -d '1 hour ago' "$DATA/.gc-started"
before=$(stat -c %Y "$DATA/.gc-started")
out=$(pull)
sleep 1
[ "$(stat -c %Y "$DATA/.gc-started")" = "$before" ] && ok "the next pass short of space is held off" || { bad "another started at once"; echo "$out"; }
rm "$XDG_CONFIG_HOME/virtkit/config.toml"

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
