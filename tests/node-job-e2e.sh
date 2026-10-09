#!/usr/bin/env bash
# =====================================================================================
# A placed GitLab job runs stage by stage in a microVM: `vk node job` on a journaled job.
# =====================================================================================
# What `vk node run` does once a hub has started a job on it, without the hub: the job's
# journal dir is written here as the node writes it, then `vk node job <dir>` runs it with
# the environment it computes from the journal.
#   1. A passing job: its trace has gitlab-runner's stage sections and headers, each command
#      echoed before its output, a masked variable shown as [MASKED], after_script run, and
#      `Job succeeded`; its result says no failure and the trace's length.
#   2. A failing job: the step's own exit code is the result's, classed `script`, and
#      after_script sees CI_JOB_STATUS=failed.
#   3. A graceful cancel stops the running step, runs after_script, and ends `canceled`.
#   4. An immediate cancel stops the running step, skips after_script, and ends `canceled`.
#   5. The job's timeout stops the running step, skips after_script, and ends `timeout`.
# The node's session — reservations, output streaming — is covered by the unit tests against
# an in-process hub.
#
# Run:  VK=./dist/vk tests/node-job-e2e.sh
# Needs: a `vk` with an embedded agent and kernel, KVM, and network to pull alpine.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }
IMAGE="${IMAGE:-alpine:3.21}"
root="$(realpath "$(mktemp -d "${TMPDIR:-/tmp}/vk-node-job-e2e.XXXXXX")")"
driver="" dir=""
# A driver still running when the script exits is stopped, and its VM cleaned up.
cleanup() {
  if [ -n "$driver" ] && kill -0 "$driver" 2>/dev/null; then
    kill -TERM -- "-$driver" 2>/dev/null || true
    wait "$driver" 2>/dev/null || true
    JOB_RESPONSE_FILE="$dir/job_response.json" "$VK" gitlab cleanup >/dev/null 2>&1 || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

mkdir -p "$root/state"
cat >"$root/config.toml" <<EOF
state_dir = "$root/state"

[executor]
atop = false
EOF
export VIRTKIT_CONFIG="$root/config.toml"

hub_id() { printf '%032x' "$1"; }

# Journal job $1 (the GitLab job ID) with the step script $2 (a JSON array of commands) and
# start its driver; $3, if set, is run once the step has started; $4 is the job's timeout in
# seconds (600).
run_job() {
  local id=$1 script=$2 during=${3:-} timeout=${4:-600}
  dir="$root/state/node/jobs/$(hub_id "$id")"
  mkdir -p "$dir"
  chmod 700 "$root/state/node" "$root/state/node/jobs" "$dir"
  cat >"$dir/start.json" <<EOF
{"job": "$(hub_id "$id")", "envelope": {"mem_mib": 1024, "cpus": 1, "disk_bytes": 0},
 "spec": {"kind": "gitlab_ci",
  "server_url": "https://gitlab.example.com",
  "job": {"id": $id, "name": "e2e", "stage": "test", "pipeline_id": 1, "project_id": 12,
          "project_name": "web", "project_path": "acme/web", "namespace_id": 1,
          "root_namespace_id": 1, "user_id": 1, "runner_id": 1},
  "token": "glcbt-64_e2etoken",
  "timeout_secs": $timeout,
  "sources": {"repo_url": "https://gitlab.example.com/acme/web.git", "object_format": "sha1",
              "ref": "main", "ref_type": "branch", "sha": "$(printf '%040d' 0)",
              "before_sha": "$(printf '%040d' 0)", "depth": 0, "protected": false,
              "allow_fetch": false},
  "image": {"name": "$IMAGE"},
  "variables": [
    {"key": "GIT_STRATEGY", "value": "none", "public": true, "file": false, "masked": false, "raw": false},
    {"key": "CI_JOB_ID", "value": "$id", "public": true, "file": false, "masked": false, "raw": false},
    {"key": "SECRET", "value": "s3cr3t-e2e-value", "public": false, "file": false, "masked": true, "raw": false}
  ],
  "steps": [
    {"name": "script", "script": $script, "timeout_secs": 600, "when": "on_success", "allow_failure": false},
    {"name": "after_script", "script": ["echo after:\$CI_JOB_STATUS"], "timeout_secs": 60, "when": "always", "allow_failure": false}
  ],
  "trace": {"sections": true, "limit_bytes": 1048576}}}
EOF
  printf '{"gitlab_id": %s, "slot": 0, "project_slot": 0, "project_id": 12}' "$id" >"$dir/meta.json"
  printf '{"id": %s, "job_info": {"name": "e2e", "project_id": 12, "project_full_path": "acme/web"}}' \
    "$id" >"$dir/job_response.json"
  # Its own session, as the node starts it: the trap stops the whole of it.
  setsid "$VK" node job "$dir" >"$dir/driver.log" 2>&1 &
  driver=$!
  if [ -n "$during" ]; then
    for _ in $(seq 1 600); do
      grep -q 'step-started' "$dir/output" 2>/dev/null && break
      sleep 0.5
    done
    eval "$during"
  fi
  wait "$driver" || { cat "$dir/driver.log"; echo "FAIL: the driver failed"; exit 1; }
  driver=""
  [ -s "$dir/result.json" ] || { cat "$dir/driver.log"; echo "FAIL: no result"; exit 1; }
  out="$dir/output" result="$dir/result.json"
}

expect() { grep -qF -- "$2" "$1" || { cat "$out"; echo "FAIL: no '$2' in $1"; exit 1; }; }
reject() { ! grep -qF -- "$2" "$1" || { cat "$out"; echo "FAIL: '$2' in $1"; exit 1; }; }

echo "== 1. a passing job =="
run_job 101 '["echo hello from $CI_JOB_ID", "echo the secret is $SECRET"]'
expect "$out" 'section_start:'
expect "$out" ':step_script'
expect "$out" 'Executing "step_script" stage of the job script'
expect "$out" '$ echo hello from $CI_JOB_ID'
expect "$out" 'hello from 101'
expect "$out" 'the secret is [MASKED]'
reject "$out" 's3cr3t-e2e-value'
expect "$out" 'after:success'
expect "$out" 'Job succeeded'
reject "$result" '"failure"'
len=$(stat -c %s "$out")
expect "$result" "\"output_len\":$len"

echo "== 2. a failing job =="
run_job 102 '["echo before", "exit 3", "echo never"]'
expect "$result" '"failure":"script"'
expect "$result" '"exit_code":3'
expect "$out" 'after:failed'
reject "$out" 'never'
expect "$out" 'Job failed: exit code 3'

echo "== 3. a graceful cancel =="
run_job 103 '["echo step-started", "sleep 300", "echo never"]' \
  'printf graceful >"$dir/cancel"'
expect "$result" '"failure":"canceled"'
expect "$out" 'after:canceled'
reject "$out" 'never'

echo "== 4. an immediate cancel =="
run_job 104 '["echo step-started", "sleep 300", "echo never"]' \
  'printf immediate >"$dir/cancel"'
expect "$result" '"failure":"canceled"'
reject "$out" 'after:'
reject "$out" 'never'

echo "== 5. the job's timeout =="
run_job 105 '["echo step-started", "sleep 300", "echo never"]' '' 5
expect "$result" '"failure":"timeout"'
expect "$out" 'execution took longer than 5s seconds'
reject "$out" 'after:'
reject "$out" 'never'

echo "PASS"
