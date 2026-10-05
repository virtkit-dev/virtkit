#!/usr/bin/env bash
# Test updates with a hub holding a newer vk release and three node services with managed
# runners (tests/fleet/lib.sh), each running an installed copy of the vk under test.
#
# 1. A failing `[node] validate` rolls b back to its previous vk, with status
#    "update to <version> rolled back".
# 2. a requires a signature from its own release key: it refuses the unsigned release and
#    accepts the same binary once signed.
# 3. a updates through its phases to ready: the inventory reports the new version and the
#    installed vk matches the release binary. Both survive a guest restart.
# 4. A rollout updates one node per wave: a is skipped because it is already on the release;
#    b and c update in successive waves.
#
# Run:  VK=./dist/vk VK_NEXT=<vk of a higher version> tests/fleet-update-e2e.sh
# Skips without VK_NEXT. Build it from the same tree with the workspace minor version
# incremented, at least 0.85.0 (TRIAL_SINCE, the first version that takes part in a trial):
#   v=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
#   up=$(echo "$v" | awk -F. '{print $1"."$2+1".0"}')
#   sed -i "s/^version = \"$v\"\$/version = \"$up\"/" Cargo.toml &&
#     ./build.sh --fast && cp dist/vk /path/to/vk-next &&
#     git checkout Cargo.toml Cargo.lock && ./build.sh --fast
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, and a registry to pull alpine.
set -euo pipefail
if [ -z "${VK_NEXT:-}" ]; then
  echo "SKIP: VK_NEXT names no vk of a higher version to update to"
  exit 0
fi
[ -x "$VK_NEXT" ] || { echo "not an executable: $VK_NEXT"; exit 2; }
VK_NEXT=$(cd "$(dirname "$VK_NEXT")" && pwd)/$(basename "$VK_NEXT")
export VK_NEXT
. "$(dirname "$0")/fleet/lib.sh"

old=$("$VK" --version | awk '{print $2}')
next=$("$VK_NEXT" --version | awk '{print $2}')
[ "$old" != "$next" ] && [ "$(printf '%s\n' "$old" "$next" | sort -V | tail -n 1)" = "$next" ] ||
  fail "VK_NEXT is vk $next, not higher than the vk under test ($old)"
[ "$(printf '%s\n' 0.85.0 "$next" | sort -V | head -n 1)" = 0.85.0 ] ||
  fail "VK_NEXT is vk $next; updates need 0.85.0 or later"
old_sha=$(sha256sum "$VK" | awk '{print $1}')
next_sha=$(sha256sum "$VK_NEXT" | awk '{print $1}')

echo "== boot a hub and three nodes with managed runners =="
fleet_up a b c
pub=$("$VK" release-key generate --key "$FLEET/release.key")
sig=$("$VK" release-key sign --key "$FLEET/release.key" --version "$next" "$VK_NEXT")
managed='[node]
runner = "managed"
runner_config = "/etc/gitlab-runner/config.toml"
gitlab_runner = "/seed/gitlab-runner"'
node_config a <<EOF
$managed
release_keys = ["$pub"]
EOF
node_config b <<EOF
$managed
validate = ["sh", "-c", "test ! -e /root/fail-validate"]
EOF
node_config c <<<"$managed"
for n in a b c; do
  node_start "$n"
  in_node "$n" sh -c 'mkdir -p /etc/gitlab-runner && echo "concurrent = 1" >/etc/gitlab-runner/config.toml'
  node_join "$n" >/dev/null || fail "$n could not join"
done
a=$(node_id a)
b=$(node_id b)
c=$(node_id c)
for id in "$a" "$b" "$c"; do
  wait_for 60 node_reported "$id" || fail "node $id did not report in"
  wait_for 30 cell_is "$id" STATE ready || fail "node $id is $(node_cell "$id" STATE)"
done
hub nodes

# SHA-256 of the vk installed by node service <name>.
installed_sha() {
  in_node "$1" sha256sum /opt/vk/bin/vk | awk '{print $1}'
}
# An update command, as the audit log names it.
update='\(update to vk [^ ]+ \([0-9a-f]+\)\)'
# on <name> <version> <sha256>: check the node's reported vk version and installed binary.
on() {
  local id
  id=$(node_id "$1")
  cell_is "$id" VK "$2" || fail "$1 reports vk $(node_cell "$id" VK), not $2"
  [ "$(installed_sha "$1")" = "$3" ] || fail "$1's installed vk is not $3"
}

echo "== the hub holds vk $next, unsigned =="
rel=$(hub release add /usr/local/share/vk-next --version "$next")
[ "$rel" = "$next_sha" ] || fail "the hub holds the release as $rel, not $next_sha"
hub release list

echo "== b fails its validation: rolled back =="
in_node b touch /root/fail-validate
hub nodes update "$b" --release "$rel"
wait_for 300 cell_is "$b" STATE "ready, update to $next rolled back" ||
  { hub_audit "$b"; fail "b was not rolled back: $(node_cell "$b" STATE)"; }
audit_says "$b" "$update: failed: rolled back: validation failed" ||
  { hub_audit "$b"; fail "the audit log does not say why b was rolled back"; }
wait_for 30 cell_is "$b" VK "$old" || fail "b reports vk $(node_cell "$b" VK) once rolled back"
on b "$old" "$old_sha"
in_node b rm /root/fail-validate
hub nodes

echo "== a refuses the unsigned release, and takes it signed =="
hub nodes update "$a" --release "$rel"
wait_for 120 audit_says "$a" "$update: (failed|refused): .*unsigned" ||
  { hub_audit "$a"; fail "a did not refuse the unsigned release"; }
wait_for 30 cell_is "$a" STATE ready || fail "a is $(node_cell "$a" STATE) after refusing"
on a "$old" "$old_sha"
wait_for 30 hub release remove "$rel" || fail "the unsigned release could not be removed"
"$VK" exec "$RUN" -- sh -c "echo '$sig' >/tmp/vk-next.sig"
rel=$(hub release add /usr/local/share/vk-next --version "$next" --signature /tmp/vk-next.sig)
hub release list | grep -q "^$rel .* signed " || fail "the release is not listed as signed"

echo "== a updates to vk $next =="
hub nodes update "$a" --release "$rel"
wait_for 120 cell_is "$a" STATE "*updating to $next: *" ||
  fail "a was never shown updating: $(node_cell "$a" STATE)"
hub nodes
wait_for 300 cell_is "$a" VK "$next" || { hub_audit "$a"; fail "a did not update to vk $next"; }
wait_for 60 cell_is "$a" STATE ready || fail "a is $(node_cell "$a" STATE) once updated"
on a "$next" "$next_sha"
audit_says "$a" "$update: done" ||
  { hub_audit "$a"; fail "the audit log misses a's update"; }
hub nodes

echo "== the update survives a restart of a's guest =="
ctl a stop
wait_for 60 node_is "$a" unreachable || fail "a is not shown unreachable once stopped"
ctl a start
wait_for 60 node_is "$a" connected || fail "a did not reconnect once started"
wait_for 30 cell_is "$a" STATE ready || fail "a is $(node_cell "$a" STATE) after a restart"
on a "$next" "$next_sha"

echo "== a rollout of vk $next, a node per wave =="
ro=$(hub rollout create --release "$rel" --batch 1)
overlap=0
# Done, noting any moment two nodes were updating at once.
rollout_done() {
  local s
  s=$(hub rollout status "$ro")
  [ "$(grep -c '  updating for ' <<<"$s")" -le 1 ] || overlap=1
  head -n 1 <<<"$s" | grep -q '  done  '
}
wait_for 600 rollout_done || { hub rollout status "$ro"; fail "the rollout did not finish"; }
status=$(hub rollout status "$ro")
echo "$status"
[ "$overlap" = 0 ] || fail "two nodes of a one-node-per-wave rollout updated at once"
grep -qE "  $a  .*  skipped: " <<<"$status" || fail "the rollout did not skip a, already on it"
for n in b c; do
  id=$(node_id "$n")
  grep -qE "  $id  .*  succeeded at " <<<"$status" || fail "the rollout did not update $n"
  wait_for 60 cell_is "$id" VK "$next" || fail "$n reports vk $(node_cell "$id" VK)"
  wait_for 60 cell_is "$id" STATE ready || fail "$n is $(node_cell "$id" STATE) once updated"
  on "$n" "$next" "$next_sha"
done
[ "$(grep -E 'succeeded at ' <<<"$status" | awk '{print $2}' | sort -u | wc -l)" = 2 ] ||
  fail "b and c were updated in the same wave"
hub nodes

echo "PASS: updates roll back on a failed validation, need a signature where keys say so,"
echo "      install and survive a restart, and roll out a wave at a time"
