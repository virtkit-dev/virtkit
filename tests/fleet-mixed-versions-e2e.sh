#!/usr/bin/env bash
# Mixed versions, end to end: nodes and hubs that speak fleet protocol version 1 only (vk and
# vk-hub 0.83.0 or 0.84.0) beside ones that steer (tests/fleet/lib.sh).
#
# 1. An old node on the test host, against the hub under test: it connects and reports its
#    inventory and workloads, is shown monitoring only, and a drain or a ceiling for it is
#    refused, saying to update its vk.
# 2. The hub swapped for the old one, on the same database: a node service under test
#    connects at version 1 and is monitored, and goes on applying the ceiling it had.
# 3. The hub under test back on that database, which the old hub rewrote without the desired
#    state: it adopts the ceiling the node service applied rather than lift it, and steers the
#    node again.
#
# Run:  VK=./dist/vk VK_V1=<old vk> VK_HUB_V1=<old vk-hub> tests/fleet-mixed-versions-e2e.sh
# Skips without VK_V1 and VK_HUB_V1: the vk and vk-hub assets of release v0.83.0 fit, checked
# against its vk.sha256 and vk-hub.sha256.
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, and a registry to pull alpine.
set -euo pipefail
if [ -z "${VK_V1:-}" ] || [ -z "${VK_HUB_V1:-}" ]; then
  echo "SKIP: VK_V1 and VK_HUB_V1 name no vk and vk-hub of protocol version 1"
  exit 0
fi
for bin in "$VK_V1" "$VK_HUB_V1"; do
  [ -x "$bin" ] || { echo "not an executable: $bin"; exit 2; }
done
VK_V1=$(cd "$(dirname "$VK_V1")" && pwd)/$(basename "$VK_V1")
VK_HUB_V1=$(cd "$(dirname "$VK_HUB_V1")" && pwd)/$(basename "$VK_HUB_V1")
export VK_HUB_V1
. "$(dirname "$0")/fleet/lib.sh"

echo "== boot a hub, a node service, and an old node on this host =="
fleet_up n1
node_up n1
fleet_kvm_node "$VK_V1"
n1=$(node_id n1)
old=$(node_id kvm)
wait_for 60 node_reported "$n1" || fail "n1 ($n1) did not report in"
wait_for 60 node_reported "$old" || fail "the old node ($old) did not report in"
hub nodes

echo "== the old node is monitored, not steered =="
old_version=$("$VK_V1" --version | awk '{print $2}')
cell_is "$old" VK "$old_version" || fail "the old node shows vk $(node_cell "$old" VK)"
cell_is "$old" STATE 'monitor only (v1)' || fail "the old node shows $(node_cell "$old" STATE)"
for cmd in "drain $old" "ceiling $old 2"; do
  # Unquoted: the command's words.
  if hub nodes $cmd 2>"$FLEET/refused.err"; then
    fail "the hub took \`nodes $cmd\` for a node it cannot steer"
  fi
  cat "$FLEET/refused.err"
  grep -q 'update its vk' "$FLEET/refused.err" || fail "\`nodes $cmd\` was refused without saying why"
done
hub workloads --node "$old" || fail "the old node's workloads are not listed"
counted() { case $(node_cell "$old" VMS) in '' | *[!0-9]*) return 1 ;; esac; }
wait_for 60 counted || fail "the old node's VM count is $(node_cell "$old" VMS)"

echo "== a ceiling on the node service, then the old hub on the same database =="
hub nodes ceiling "$n1" 2
wait_for 60 cell_is "$n1" SYNC ok || fail "n1 did not apply the ceiling"
wait_for 30 cell_is "$n1" CONC 2 || fail "n1 runs at $(node_cell "$n1" CONC), not 2"
hub_kill
HUB_BIN=vk-hub-v1
hub_start
wait_for 60 node_reported "$n1" || fail "n1 did not reconnect to the old hub"
wait_for 60 node_reported "$old" || fail "the old node did not reconnect to the old hub"
hub nodes
version=$("$VK" --version | awk '{print $2}')
cell_is "$n1" VK "$version" || fail "the old hub shows n1 as vk $(node_cell "$n1" VK)"
in_node n1 grep -qx 2 /var/lib/virtkit/schedule/desired-concurrency ||
  fail "n1 dropped its ceiling under the old hub"

echo "== the hub under test back: the node service is steered again =="
hub_kill
HUB_BIN=vk-hub
hub_start
wait_for 60 node_reported "$n1" || fail "n1 did not reconnect to the hub under test"
wait_for 60 cell_is "$n1" STATE ready || fail "n1 shows $(node_cell "$n1" STATE), not ready"
wait_for 60 cell_is "$n1" CEILING 2 || fail "the hub shows n1's ceiling as $(node_cell "$n1" CEILING)"
cell_is "$n1" SYNC ok || fail "n1 shows $(node_cell "$n1" SYNC), not in sync"
hub_audit "$n1" | grep "adopted the node's desired state" >/dev/null ||
  fail "the hub did not audit adopting n1's desired state"
in_node n1 grep -qx 2 /var/lib/virtkit/schedule/desired-concurrency ||
  fail "n1 dropped its ceiling once back on the hub under test"
hub nodes ceiling "$n1" 3
wait_for 60 cell_is "$n1" SYNC ok || fail "n1 did not apply the new ceiling: $(node_cell "$n1" SYNC)"
wait_for 30 cell_is "$n1" CONC 3 || fail "n1 runs at $(node_cell "$n1" CONC), not 3"
wait_for 60 node_reported "$old" || fail "the old node did not reconnect"
cell_is "$old" STATE 'monitor only (v1)' || fail "the old node shows $(node_cell "$old" STATE)"
hub nodes
hub_audit "$n1"

echo "PASS: version 1 nodes and hubs monitor, and steering resumes on version 2 with the node's ceiling kept"
