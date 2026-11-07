#!/usr/bin/env bash
# Hub settings, end to end: a hub (tests/fleet/lib.sh) with its web UI, an enrolled node on the
# test host whose config names only a state dir for this run, and a node service whose config
# sets executor.vm.max_cpus.
#
# 1. The test host's node sizes itself from the host: its memory budget is MemTotal less the
#    smaller of 4G and 10 %, its max_cpus the host's online CPUs, both reported as
#    autodetected, and its vCPU budget twice those CPUs. A job it runs gets the switch network.
# 2. Both nodes report a fleet-wide memory budget as coming from the hub. The test host's
#    node restarts `vk node run` in place to load it. A budget set for that node overrides the
#    fleet-wide value there only.
# 3. The node's config file overrides the hub's value for the same key.
# 4. `vk-hub settings set` rejects out-of-bounds values, wrong types and keys the hub may not
#    set before any node receives them.
# 5. Unsetting a key restores the fleet-wide value, then the node's own.
#
# Run:  VK=./dist/vk tests/fleet-settings-e2e.sh
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, curl, and a registry to pull alpine.
set -euo pipefail
HUB_UI=1
. "$(dirname "$0")/fleet/lib.sh"
command -v curl >/dev/null || { echo "need curl, for the hub's web UI"; exit 2; }

# setting <id> <key>: "<value> (<source>)" as node <id>'s page shows the key.
setting() {
  hub_ui "/node/$1" |
    grep -o "<code>$2</code></td><td>[^<]*</td><td>[^<]*</td>" |
    sed -E 's|.*</code></td><td>([^<]*)</td><td>([^<]*)</td>|\1 (\2)|'
}

setting_matches() {
  [ "$(setting "$1" "$2")" = "$3" ]
}

# setting_is <id> <key> <"value (source)">: wait for node <id> to report it.
setting_is() {
  wait_for 60 setting_matches "$1" "$2" "$3" ||
    fail "node $1 reports $2 as '$(setting "$1" "$2")', not '$3'"
}

# How many times the test host's node started again to load the hub's settings.
reloads() {
  grep -c "the hub's settings changed: starting again" "$FLEET/kvm/node.log" || true
}

# The host's figures, as an enrolled node derives its defaults from them.
total_mib=$(($(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024))
reserve=$(((total_mib + 9) / 10))
[ "$reserve" -le 4096 ] || reserve=4096
budget=$(((total_mib - reserve) / 1024))G
cpus=$(getconf _NPROCESSORS_ONLN)

echo "== boot a hub, a node service with a config file and a node on the test host =="
fleet_up n1
node_config n1 <<'EOF'
[executor.vm]
max_cpus = 1
EOF
node_up n1
n=$(node_id n1)
node_join kvm >/dev/null || fail "the test host's node could not join"
k=$(node_id kvm)

echo "== a job on the enrolled test host gets the switch network =="
# Journaled as `vk node run` journals a placed job (tests/node-job-e2e.sh), and run before the
# node starts, so it is the only one to know of it.
job=$FLEET/kvm/state/node/jobs/$(printf '%032x' 1)
mkdir -p "$job"
chmod 700 "$FLEET/kvm/state/node" "$FLEET/kvm/state/node/jobs" "$job"
cat >"$job/start.json" <<EOF
{"job": "$(printf '%032x' 1)", "envelope": {"mem_mib": 1024, "cpus": 1, "disk_bytes": 0},
 "spec": {"kind": "gitlab_ci",
  "server_url": "https://gitlab.example.com",
  "job": {"id": 1, "name": "e2e", "stage": "test", "pipeline_id": 1, "project_id": 12,
          "project_name": "web", "project_path": "acme/web", "namespace_id": 1,
          "root_namespace_id": 1, "user_id": 1, "runner_id": 1},
  "token": "glcbt-64_e2etoken",
  "timeout_secs": 600,
  "sources": {"repo_url": "https://gitlab.example.com/acme/web.git", "object_format": "sha1",
              "ref": "main", "ref_type": "branch", "sha": "$(printf '%040d' 0)",
              "before_sha": "$(printf '%040d' 0)", "depth": 0, "protected": false,
              "allow_fetch": false},
  "image": {"name": "alpine:3.21"},
  "variables": [
    {"key": "GIT_STRATEGY", "value": "none", "public": true, "file": false, "masked": false, "raw": false}
  ],
  "steps": [
    {"name": "script", "script": ["ip -4 addr show eth0", "ip -4 route | grep '^default'"],
     "timeout_secs": 600, "when": "on_success", "allow_failure": false}
  ],
  "trace": {"sections": true, "limit_bytes": 1048576}}}
EOF
printf '{"gitlab_id": 1, "slot": 0, "project_slot": 0, "project_id": 12}' >"$job/meta.json"
printf '{"id": 1, "job_info": {"name": "e2e", "project_id": 12, "project_full_path": "acme/web"}}' \
  >"$job/job_response.json"
VIRTKIT_CONFIG=$FLEET/kvm/config.toml "$VK" node job "$job" >"$FLEET/job.log" 2>&1 ||
  { cat "$FLEET/job.log"; fail "the job's driver failed"; }
cat "$job/output"
! grep -q '"failure"' "$job/result.json" || fail "the job failed: $(cat "$job/result.json")"
grep -q ' default via ' "$job/output" || fail "the job's guest has no default route"

echo "== the test host's node sizes itself from the host =="
kvm_node_run
wait_for 60 node_reported "$k" || fail "the test host's node ($k) did not report in"
wait_for 60 node_reported "$n" || fail "n1 ($n) did not report in"
hub nodes
setting_is "$k" executor.schedule.mem_budget "$budget (autodetected)"
setting_is "$k" executor.vm.max_cpus "$cpus (autodetected)"
setting_is "$n" executor.vm.max_cpus "1 (its config file)"
wait_for 30 cell_is "$k" ADMITTED "*/$budget" ||
  fail "the test host's node admits against $(node_cell "$k" ADMITTED), not $budget"
wait_for 30 cell_is "$k" VCPUS "*/$((cpus * 2))" ||
  fail "the test host's node has a vCPU budget of $(node_cell "$k" VCPUS), not $((cpus * 2))"

echo "== a fleet-wide setting reaches both nodes, a node's own wins there =="
before=$(reloads)
hub settings set executor.schedule.mem_budget 8G
setting_is "$k" executor.schedule.mem_budget "8G (the hub)"
setting_is "$n" executor.schedule.mem_budget "8G (the hub)"
[ "$(reloads)" -gt "$before" ] || fail "the test host's node did not start again to load it"
kill -0 "$KVM_NODE_PID" || fail "the test host's node exited rather than starting again in place"
wait_for 30 cell_is "$k" ADMITTED '*/8G' ||
  fail "the test host's node admits against $(node_cell "$k" ADMITTED), not 8G"
hub settings set executor.schedule.mem_budget 16G --node "$k"
setting_is "$k" executor.schedule.mem_budget "16G (the hub)"
wait_for 30 cell_is "$k" ADMITTED '*/16G' ||
  fail "the test host's node admits against $(node_cell "$k" ADMITTED), not 16G"
[ "$(setting "$n" executor.schedule.mem_budget)" = "8G (the hub)" ] ||
  fail "a setting for the test host's node reached n1"
hub settings

echo "== the node's config file wins over the hub =="
hub settings set executor.vm.max_cpus 3
setting_is "$k" executor.vm.max_cpus "3 (the hub)"
setting_is "$n" executor.vm.max_cpus "1 (its config file)"
wait_for 30 eval 'hub nodes | grep -qF "n1: settings: 1 from the hub, 1 from its config file"' ||
  { hub nodes; fail "n1 does not say where its settings come from"; }
if hub nodes | grep -F 'refused the hub'; then
  fail "a node refused a setting"
fi

echo "== values a key cannot take are refused up front =="
settings_before=$(hub settings)
while read -r key value; do
  if hub settings set "$key" "$value" </dev/null 2>"$FLEET/refused.err"; then
    fail "the hub took $key = $value"
  fi
  echo "$key = $value: $(cat "$FLEET/refused.err")"
done <<'EOF'
executor.vm.cpus 0
executor.vm.cpus 256
executor.vm.max_cpus 1.5
executor.schedule.mem_budget 8
executor.schedule.mem_budget 101%
executor.schedule.cpu_overcommit 65
executor.schedule.from_history yes
state_dir /tmp
EOF
[ "$(hub settings)" = "$settings_before" ] || fail "a refused value changed the hub's settings"

echo "== unset, a key goes back to the fleet's value, then to the node's own =="
hub settings unset executor.schedule.mem_budget --node "$k"
setting_is "$k" executor.schedule.mem_budget "8G (the hub)"
hub settings unset executor.schedule.mem_budget
setting_is "$k" executor.schedule.mem_budget "$budget (autodetected)"
hub settings unset executor.vm.max_cpus
setting_is "$k" executor.vm.max_cpus "$cpus (autodetected)"
setting_is "$n" executor.vm.max_cpus "1 (its config file)"
wait_for 30 cell_is "$k" ADMITTED "*/$budget" ||
  fail "the test host's node admits against $(node_cell "$k" ADMITTED), not $budget"
kill -0 "$KVM_NODE_PID" || fail "the test host's node exited"
hub settings

echo "PASS: nodes size themselves, take the hub's settings beneath their own, and drop them unset"
