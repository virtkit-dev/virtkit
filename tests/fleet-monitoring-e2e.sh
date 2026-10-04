#!/usr/bin/env bash
# What a hub sees of its nodes, end to end: a hub, a node service, and a node on the test host
# with its KVM (tests/fleet/lib.sh).
#
# 1. Heartbeats keep a node's last-seen time fresh.
# 2. A VM started on the host's node shows up among its workloads, and is gone once stopped.
# 3. A node with no VMs reports none.
#
# Run:  VK=./dist/vk tests/fleet-monitoring-e2e.sh
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, and a registry to pull alpine.
set -euo pipefail
. "$(dirname "$0")/fleet/lib.sh"

echo "== boot a hub, a node service and a node on this host =="
fleet_up n1
node_up n1
fleet_kvm_node
n1=$(node_id n1)
kvm=$(node_id kvm)
wait_for 60 node_is "$n1" connected || fail "n1 did not connect"
wait_for 60 node_is "$kvm" connected || fail "the host's node did not connect"
hub nodes

# `<n>s ago`, in seconds; anything coarser is minutes or more.
seen_secs() {
  local seen
  seen=$(node_cell "$1" "LAST SEEN")
  case $seen in
    *s\ ago) echo "${seen%s ago}" ;;
    *) echo 9999 ;;
  esac
}

echo "== heartbeats keep the last-seen time fresh =="
# A heartbeat every few seconds: over half a minute, the node never goes unseen for long.
for _ in 1 2 3; do
  sleep 10
  for id in "$n1" "$kvm"; do
    secs=$(seen_secs "$id")
    echo "$id last seen ${secs}s ago"
    [ "$secs" -le 15 ] || fail "node $id was last seen ${secs}s ago"
  done
done

echo "== a VM started on the host's node appears among its workloads, and goes =="
WL=$FLEET/workload
counted() { case $(node_cell "$kvm" VMS) in '' | *[!0-9]*) return 1 ;; esac; }
wait_for 60 counted || fail "the host's node has not reported its VMs"
before=$(node_cell "$kvm" VMS)
"$VK" run --detach --inactivity-timeout 0 --state-dir "$WL" \
  docker.io/library/alpine:3.21 -- sleep infinity >"$FLEET/workload.log" 2>&1 ||
  { cat "$FLEET/workload.log"; fail "the workload VM did not boot"; }
listed() { hub workloads --node "$kvm" | grep -qF -- "$WL"; }
wait_for 60 listed || { hub workloads; fail "the VM in $WL is not among the host's workloads"; }
hub workloads --node "$kvm"
after=$(node_cell "$kvm" VMS)
[ "$after" = $((before + 1)) ] ||
  fail "the nodes table counts $after VMs on the host, not $((before + 1))"
"$VK" stop "$WL" >/dev/null
wait_for 60 eval '! listed' || fail "the VM in $WL is still listed once stopped"

echo "== a node with no VMs reports none =="
[ "$(node_cell "$n1" VMS)" = 0 ] || fail "n1 reports VMs it does not run"
hub workloads --node "$n1"

echo "PASS: heartbeats and workloads reach the hub"
