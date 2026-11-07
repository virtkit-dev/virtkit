#!/usr/bin/env bash
# Automatic updates to a target vk release, end to end: a hub (tests/fleet/lib.sh) with its web
# UI and `[nodes] release_keys`, and node services configured by nothing but their enrollment,
# each running an installed copy of the vk under test.
#
# 1. A node pins the hub's release keys when it joins, and reports them as pinned; one whose
#    config file sets `[node] release_keys` reports those instead.
# 2. The hub refuses a target that is unsigned or signed by a key it does not list.
# 3. A signed target rolls out to the older node; a node whose own keys reject the
#    signature is flagged and left alone.
# 4. A node that joins later, on the older vk, is updated to the target alone.
# 5. Once the target is cleared, a node behind it is left alone.
#
# Run:  VK=./dist/vk VK_NEXT=<vk of a higher version> tests/fleet-target-e2e.sh
# Skips without VK_NEXT; build it as tests/fleet-update-e2e.sh says.
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, curl, and a registry to pull alpine.
set -euo pipefail
if [ -z "${VK_NEXT:-}" ]; then
  echo "SKIP: VK_NEXT names no vk of a higher version to update to"
  exit 0
fi
[ -x "$VK_NEXT" ] || { echo "not an executable: $VK_NEXT"; exit 2; }
VK_NEXT=$(cd "$(dirname "$VK_NEXT")" && pwd)/$(basename "$VK_NEXT")
export VK_NEXT
HUB_UI=1
. "$(dirname "$0")/fleet/lib.sh"
command -v curl >/dev/null || { echo "need curl, for the hub's web UI"; exit 2; }

old=$("$VK" --version | awk '{print $2}')
next=$("$VK_NEXT" --version | awk '{print $2}')
[ "$old" != "$next" ] && [ "$(printf '%s\n' "$old" "$next" | sort -V | tail -n 1)" = "$next" ] ||
  fail "VK_NEXT is vk $next, not higher than the vk under test ($old)"
old_sha=$(sha256sum "$VK" | awk '{print $1}')
next_sha=$(sha256sum "$VK_NEXT" | awk '{print $1}')

# The fleet's release key, which the hub hands out at enrollment, and another one.
pub=$("$VK" release-key generate --key "$FLEET/release.key")
other=$("$VK" release-key generate --key "$FLEET/other.key")
HUB_TOML="[nodes]
release_keys = [\"$pub\"]"

# SHA-256 of the vk installed by node service <name>.
installed_sha() {
  in_node "$1" sha256sum /opt/vk/bin/vk | awk '{print $1}'
}
# on <name> <version> <sha256>: check the node's reported vk version and installed binary.
on() {
  local id
  id=$(node_id "$1")
  cell_is "$id" VK "$2" || fail "$1 reports vk $(node_cell "$id" VK), not $2"
  [ "$(installed_sha "$1")" = "$3" ] || fail "$1's installed vk is not $3"
}
# keys_are <id> <html>: node <id>'s page shows its release keys as <html>.
keys_are() {
  hub_ui "/node/$1" | grep -qF "<tr><th>Release keys</th><td>$2</td></tr>"
}
# release <signing key or ->: add VK_NEXT to the hub, signed with the key or unsigned.
release() {
  local sig=()
  if [ "$1" != - ]; then
    "$VK" exec "$RUN" -- sh -c "echo '$("$VK" release-key sign --key "$1" --version "$next" \
      "$VK_NEXT")' >/tmp/vk-next.sig"
    sig=(--signature /tmp/vk-next.sig)
  fi
  hub release add /usr/local/share/vk-next --version "$next" "${sig[@]}"
}
# standing <id>: node <id>'s row of `vk-hub release target`.
standing() {
  hub release target | awk -v id="(${1:0:8})" '$2 == id'
}
standing_is() {
  [ "$(standing "$1" | awk '{print $3}')" = "$2" ]
}

echo "== boot a hub with release keys, and two nodes =="
fleet_up a b c
node_config c <<EOF
[node]
release_keys = ["$other"]
EOF
node_up a
node_up c
a=$(node_id a)
c=$(node_id c)
for id in "$a" "$c"; do
  wait_for 60 node_reported "$id" || fail "node $id did not report in"
  wait_for 30 cell_is "$id" STATE ready || fail "node $id is $(node_cell "$id" STATE)"
done
hub nodes

echo "== a pins the hub's keys, c keeps its own =="
in_node a cat /var/lib/virtkit/node/enrollment.json | grep -qF "\"$pub\"" ||
  fail "a's enrollment does not pin the hub's release key"
wait_for 30 keys_are "$a" "<code>$pub</code>, pinned when it joined" ||
  fail "a does not report the hub's key as pinned when it joined"
wait_for 30 keys_are "$c" "<code>$other</code>, from its config file" ||
  fail "c does not report its own key from its config file"

echo "== a target must be signed by the hub's keys =="
for signer in - "$FLEET/other.key"; do
  rel=$(release "$signer")
  [ "$rel" = "$next_sha" ] || fail "the hub holds the release as $rel, not $next_sha"
  if hub release target "$rel" 2>"$FLEET/target.err"; then
    fail "the hub took a target signed by ${signer##*/}"
  fi
  echo "signed by ${signer##*/}: $(cat "$FLEET/target.err")"
  grep -q 'a target must be signed by one of them' "$FLEET/target.err" ||
    fail "the hub does not say why it refused the target"
  hub release remove "$rel"
done
rel=$(release "$FLEET/release.key")

echo "== the target is rolled out to a; c is flagged =="
hub release target "$rel"
wait_for 300 cell_is "$a" VK "$next" || { hub_audit "$a"; fail "a did not update to vk $next"; }
wait_for 60 cell_is "$a" STATE ready || fail "a is $(node_cell "$a" STATE) once updated"
on a "$next" "$next_sha"
wait_for 60 standing_is "$a" current || fail "a stands $(standing "$a") against the target"
standing_is "$c" flagged || fail "c stands $(standing "$c") against the target, not flagged"
standing "$c" | grep -q 'signature does not verify' ||
  fail "c's flag does not say its keys refuse the target's signature: $(standing "$c")"
on c "$old" "$old_sha"
hub release target

echo "== b joins on vk $old and is updated to the target alone =="
node_up b
b=$(node_id b)
wait_for 60 node_reported "$b" || fail "node $b did not report in"
wait_for 300 cell_is "$b" VK "$next" || { hub_audit "$b"; fail "b was not updated to vk $next"; }
wait_for 60 cell_is "$b" STATE ready || fail "b is $(node_cell "$b" STATE) once updated"
on b "$next" "$next_sha"
audit_says "$b" "updated to the target vk $next" ||
  { hub_audit "$b"; fail "the audit log does not say the target's updates took b there"; }
hub release target

echo "== cleared, the target updates no node behind it =="
hub release target --clear
hub release target 2>&1 | grep -q 'no target is set' || fail "the target is still set"
# c, back to its pinned keys, would now take the target.
node_config c </dev/null
ctl c stop
wait_for 60 node_is "$c" unreachable || fail "c is not shown unreachable once stopped"
ctl c start
wait_for 60 node_is "$c" connected || fail "c did not reconnect once started"
wait_for 30 cell_is "$c" STATE ready || fail "c is $(node_cell "$c" STATE) after a restart"
wait_for 30 keys_are "$c" "<code>$pub</code>, pinned when it joined" ||
  fail "c does not fall back to the key it pinned when it joined"
# Wait through several of the hub's 5 s target checks.
sleep 20
on c "$old" "$old_sha"
if audit_says "$c" "update to vk"; then
  hub_audit "$c"
  fail "c was sent an update with no target set"
fi
hub nodes

echo "PASS: nodes pin the hub's release keys, a signed target reaches every node behind it,"
echo "      joined before or after, but one whose keys refuse it, and stops once cleared"
