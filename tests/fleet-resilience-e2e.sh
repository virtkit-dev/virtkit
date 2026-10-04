#!/usr/bin/env bash
# A fleet riding out faults, end to end: a hub and two node services (tests/fleet/lib.sh).
#
# 1. The hub killed and started again on its database: both nodes reconnect on their own.
# 2. A node's guest stopped from the primary: the hub shows it unreachable; started again,
#    it reconnects as the same node.
# 3. A node cut off from the hub by nftables in its guest: shown unreachable while cut off,
#    connected again once the rule is gone.
#
# Run:  VK=./dist/vk tests/fleet-resilience-e2e.sh
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, and a registry to pull alpine.
set -euo pipefail
. "$(dirname "$0")/fleet/lib.sh"

echo "== boot a hub and two nodes =="
fleet_up n1 n2
node_up n1
node_up n2
n1=$(node_id n1)
n2=$(node_id n2)
wait_for 60 node_is "$n1" connected || fail "n1 did not connect"
wait_for 60 node_is "$n2" connected || fail "n2 did not connect"
hub nodes

echo "== the hub killed and restarted on its database =="
hub_kill
hub_start
# A node redials with a backoff doubling from a second, so a hub down for seconds is back
# within a few more.
wait_for 60 node_is "$n1" connected || fail "n1 did not reconnect to the restarted hub"
wait_for 60 node_is "$n2" connected || fail "n2 did not reconnect to the restarted hub"
hub nodes

echo "== a node's guest stopped and started from the primary =="
ctl n1 stop
wait_for 60 node_is "$n1" unreachable || fail "n1 is not shown unreachable once stopped"
node_is "$n2" connected || fail "n2 lost its session when n1 stopped"
hub nodes
ctl n1 start
wait_for 60 node_is "$n1" connected || fail "n1 did not reconnect once started"

echo "== a node cut off from the hub, then let back =="
in_node n2 sh -c 'nft add table inet cut &&
  nft add chain inet cut out "{ type filter hook output priority 0; }" &&
  nft add rule inet cut out tcp dport 8443 drop'
wait_for 120 node_is "$n2" unreachable || fail "n2 is not shown unreachable while cut off"
hub nodes
in_node n2 nft delete table inet cut
wait_for 180 node_is "$n2" connected || fail "n2 did not reconnect once let back"
node_is "$n1" connected || fail "n1 lost its session meanwhile"
hub nodes

echo "PASS: nodes came back after a hub restart, a guest restart and a partition"
