#!/usr/bin/env bash
# Enrollment, end to end: a fleet of a hub and two node services (tests/fleet/lib.sh).
#
# 1. A token enrolls one node only, and an expired one none.
# 2. An enrolled node, started, shows up connected with its inventory: its `vk` version and
#    its guest's CPUs and name.
# 3. A node enrolling again with the key it already has gets its node ID back.
# 4. `vk-hub nodes remove` revokes a node: its session ends, `vk node run` exits, and the
#    hub lists it no more.
#
# Run:  VK=./dist/vk tests/fleet-enrollment-e2e.sh
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting, openssl, and a
# registry to pull alpine.
set -euo pipefail
. "$(dirname "$0")/fleet/lib.sh"

echo "== boot a hub and two node services =="
fleet_up n1 n2
node_start n1
node_start n2

echo "== a token is single-use, and expires =="
token=$(hub token create)
node_join n1 "$token" || fail "a fresh token did not enroll n1"
if node_join n2 "$token" 2>"$FLEET/spent.err"; then
  fail "a spent token enrolled a second node"
fi
cat "$FLEET/spent.err"
token=$(hub token create --ttl 1s)
sleep 2
if node_join n2 "$token" 2>"$FLEET/late.err"; then
  fail "an expired token enrolled a node"
fi
cat "$FLEET/late.err"

echo "== an enrolled node appears with its inventory =="
n1=$(node_id n1)
wait_for 60 node_reported "$n1" || fail "n1 ($n1) did not report in"
row=$(node_row "$n1")
echo "$row"
version=$("$VK" --version | awk '{print $2}')
grep -qw n1 <<<"$row" || fail "n1's row does not name it by its guest's hostname"
# The guest's 2 vCPUs, compose's default.
[ "$(node_cell "$n1" CPUS)" = 2 ] || fail "n1's row does not show its 2 CPUs"
[ "$(node_cell "$n1" VK)" = "$version" ] || fail "n1's row does not show vk $version"

echo "== enrolling again with the same key gets the same node ID =="
in_node n1 sh -c 'rm /var/lib/virtkit/node/enrollment.json && pkill -f "vk node run"'
wait_for 30 eval '! in_node n1 pgrep -f "vk node run" >/dev/null' ||
  fail "n1's vk node run did not stop"
node_join n1 >/dev/null || fail "n1 could not enroll again"
[ "$(node_id n1)" = "$n1" ] || fail "n1 enrolled again as $(node_id n1), not $n1"
[ "$(hub nodes | awk -v id="$n1" '$1 == id' | wc -l)" = 1 ] || fail "n1 is listed twice"
wait_for 60 node_is "$n1" connected || fail "n1 did not reconnect once enrolled again"

echo "== removing a node ends its session and its vk node run =="
node_join n2 >/dev/null || fail "n2 could not join"
n2=$(node_id n2)
wait_for 60 node_is "$n2" connected || fail "n2 ($n2) did not connect"
hub nodes remove "$n2"
wait_for 30 eval '[ "$(service_state n2)" != running ]' ||
  fail "n2's vk node run still runs after its removal"
[ -z "$(node_row "$n2")" ] || fail "the hub still lists n2"
node_is "$n1" connected || fail "removing n2 disconnected n1"
if hub nodes remove "$n2" 2>"$FLEET/again.err"; then
  fail "removing a removed node succeeded"
fi
cat "$FLEET/again.err"

echo "PASS: tokens enroll once, nodes report in, keep their ID, and are revoked"
