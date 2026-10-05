#!/usr/bin/env bash
# Steering, end to end: a hub and two node services (tests/fleet/lib.sh), one running a
# managed runner — the gitlab-runner stand-in in tests/fleet/node — and one leaving its
# runner external, as a node does by default.
#
# 1. A ceiling reaches both nodes: each reports it applied, and the managed one's runner
#    config carries it.
# 2. Acquisition stopped on the managed node quits its runner; resumed, a new one starts.
#    The external node reports it cannot stop its runner.
# 3. A drain on the managed node stays `draining` while its runner finishes, then reports
#    `drained`; undrained, the node is `ready` and its runner back.
# 4. A quarantine stops the managed node's runner, and holds across a restart of its guest
#    until released.
# 5. The external node refuses a drain, and the audit log says why.
#
# Run:  VK=./dist/vk tests/fleet-steering-e2e.sh
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, and a registry to pull alpine.
set -euo pipefail
. "$(dirname "$0")/fleet/lib.sh"

echo "== boot a hub, a node with a managed runner and one with an external runner =="
fleet_up managed external
node_config managed <<'EOF'
[node]
runner = "managed"
runner_config = "/etc/gitlab-runner/config.toml"
gitlab_runner = "/seed/gitlab-runner"
EOF
node_start managed
in_node managed sh -c 'mkdir -p /etc/gitlab-runner && echo "concurrent = 1" >/etc/gitlab-runner/config.toml'
node_join managed >/dev/null || fail "managed could not join"
node_up external
m=$(node_id managed)
x=$(node_id external)
wait_for 60 node_reported "$m" || fail "managed ($m) did not report in"
wait_for 60 node_reported "$x" || fail "external ($x) did not report in"
hub nodes

# The managed node's runner pid, if one runs.
runner_pid() {
  in_node managed pgrep -f 'seed/gitlab-runner run --config' || true
}
runner_up() { [ -n "$(runner_pid)" ]; }
runner_down() { [ -z "$(runner_pid)" ]; }
audit_says() { hub_audit "$1" | grep -qE -- "$2"; }

wait_for 30 runner_up || fail "the managed node did not start its runner"
wait_for 30 cell_is "$m" STATE ready || fail "managed is not ready: $(node_cell "$m" STATE)"
wait_for 30 cell_is "$m" ACQUIRE run || fail "managed is not taking jobs: $(node_cell "$m" ACQUIRE)"

echo "== a ceiling reaches both nodes =="
hub nodes ceiling "$m" 2
hub nodes ceiling "$x" 2
for id in "$m" "$x"; do
  wait_for 60 cell_is "$id" SYNC ok || fail "node $id did not apply the ceiling: $(node_cell "$id" SYNC)"
  wait_for 30 cell_is "$id" CEILING 2 || fail "node $id shows ceiling $(node_cell "$id" CEILING)"
  wait_for 30 cell_is "$id" CONC 2 || fail "node $id runs at $(node_cell "$id" CONC), not 2"
  audit_says "$id" 'applied generation 1' || fail "the audit log misses node $id applying it"
done
in_node managed grep -Eqx 'concurrent *= *2' /etc/gitlab-runner/config.toml ||
  fail "the managed node's runner config does not carry the ceiling"
hub nodes

echo "== acquisition stopped and resumed on the managed node =="
before=$(runner_pid)
hub nodes stop "$m"
wait_for 60 cell_is "$m" ACQUIRE stop || fail "managed still acquires: $(node_cell "$m" ACQUIRE)"
runner_down || fail "the managed node's runner still runs once stopped"
hub nodes resume "$m"
wait_for 60 cell_is "$m" ACQUIRE run || fail "managed did not resume: $(node_cell "$m" ACQUIRE)"
wait_for 30 runner_up || fail "the managed node did not start its runner again"
[ "$(runner_pid)" != "$before" ] || fail "the managed node's runner was never restarted"

echo "== the external node cannot stop its runner =="
notes() { hub nodes | grep -qF "external: cannot comply: stopping acquisition"; }
hub nodes stop "$x"
wait_for 60 notes || { hub nodes; fail "the external node did not say it cannot stop acquiring"; }
cell_is "$x" ACQUIRE 'stop (node: run)' || fail "external shows $(node_cell "$x" ACQUIRE)"
hub nodes
hub nodes resume "$x"
wait_for 60 eval '! notes' || fail "the external node's note stayed once resumed"

echo "== a drain on the managed node, then undrained =="
# The runner waits for the hold file to be removed before exiting, simulating job completion.
in_node managed touch /tmp/runner-hold
hub nodes drain "$m"
wait_for 60 cell_is "$m" STATE 'draining*' || fail "managed is not draining: $(node_cell "$m" STATE)"
hub nodes
sleep 5
cell_is "$m" STATE 'draining*' || fail "managed drained while its runner was still quitting"
in_node managed rm /tmp/runner-hold
wait_for 60 cell_is "$m" STATE drained || fail "managed did not drain: $(node_cell "$m" STATE)"
runner_down || fail "a drained node's runner still runs"
audit_says "$m" '\(drain\): done' || fail "the audit log misses the drain finishing"
hub nodes undrain "$m"
wait_for 60 cell_is "$m" STATE ready || fail "managed is not ready once undrained"
wait_for 30 runner_up || fail "the managed node did not start its runner once undrained"

echo "== a quarantine holds across a restart of the node =="
hub nodes quarantine "$m"
wait_for 60 cell_is "$m" STATE quarantined || fail "managed is not quarantined"
wait_for 30 runner_down || fail "a quarantined node's runner still runs"
ctl managed stop
wait_for 60 node_is "$m" unreachable || fail "managed is not shown unreachable once stopped"
ctl managed start
wait_for 60 node_is "$m" connected || fail "managed did not reconnect once started"
# The hub keeps the last report across a disconnect: ask the node's own state file.
in_node managed grep -q '"state": "quarantined"' /var/lib/virtkit/node/state.json ||
  fail "the quarantine did not survive a restart"
# Long enough for a runner to have been started, were it going to be.
sleep 5
runner_down || fail "a quarantined node started its runner on boot"
hub nodes release "$m"
wait_for 60 cell_is "$m" STATE ready || fail "managed is not ready once released"
wait_for 30 runner_up || fail "the managed node did not start its runner once released"

echo "== the external node refuses a drain =="
hub nodes drain "$x"
wait_for 60 audit_says "$x" '\(drain\): refused: .*runner = "external"' ||
  { hub_audit "$x"; fail "the audit log does not show the external node refusing a drain"; }
cell_is "$x" STATE ready || fail "external is $(node_cell "$x" STATE) after refusing a drain"
hub_audit "$x"

echo "PASS: a ceiling, acquisition, drain and quarantine reach the nodes, as each can take them"
