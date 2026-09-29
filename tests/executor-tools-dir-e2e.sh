#!/usr/bin/env bash
# =====================================================================================
# A symlinked tools_dir reaches the guest; prepare warns a job left without gitlab-runner.
# =====================================================================================
# Each job's guest gets the tree the tools_dir link names when it boots, and a job the share
# leaves without gitlab-runner (so artifacts, caches and dotenv reports are not transferred)
# gets a warning in its trace with the reason.
#
# Drives `vk gitlab prepare|run|cleanup` directly, no GitLab needed:
#   1. tools_dir is a symlink to a populated directory: the guest has gitlab-runner on PATH
#      and prepare prints no tools warning.
#   2. the link is re-pointed at a directory without gitlab-runner: the next job's prepare
#      says so in its output, which is the job trace.
#   3. the link is re-pointed at an empty directory: prepare gives that as the reason.
#   4. the link is re-pointed at a directory whose gitlab-runner is not executable: it is
#      not linked, and prepare gives that as the reason.
# alpine ships no gitlab-runner; an image that does is covered by vk-agent's unit tests.
#
# Run:  VK=./dist/vk tests/executor-tools-dir-e2e.sh
# Needs: a `vk` with an embedded agent and kernel, KVM, and network to pull alpine.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }
IMAGE="${IMAGE:-alpine:3.21}"
# Canonical, so the warning's resolved tools_dir is "$root/…" as written below.
root="$(realpath "$(mktemp -d "${TMPDIR:-/tmp}/vk-tools-e2e.XXXXXX")")"
job=0
cleanup() {
  "$VK" gitlab cleanup >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT

mkdir -p "$root/tools.a" "$root/tools.b" "$root/tools.c" "$root/tools.d" "$root/state"
printf '#!/bin/sh\necho fake-gitlab-runner "$@"\n' >"$root/tools.a/gitlab-runner"
chmod +x "$root/tools.a/gitlab-runner"
printf '#!/bin/sh\necho fake-tool\n' >"$root/tools.b/vk-e2e-tool"
chmod +x "$root/tools.b/vk-e2e-tool"
cp "$root/tools.a/gitlab-runner" "$root/tools.d/gitlab-runner"
chmod 0644 "$root/tools.d/gitlab-runner"
ln -s "$root/tools.a" "$root/tools"

cat >"$root/config.toml" <<EOF
state_dir = "$root/state"

[executor]
tools_dir = "$root/tools"
atop = false
EOF
export VIRTKIT_CONFIG="$root/config.toml"
export CUSTOM_ENV_CI_JOB_IMAGE="$IMAGE"

# The prepare warning for a job without gitlab-runner, up to the reason the guest gives.
warning='virtkit: warning: this job has no gitlab-runner, so artifacts, caches and dotenv reports will not be transferred'

# One job: prepare (its output kept in $root/prepare.log), one stage running $1, cleanup.
run_job() {
  job=$((job + 1))
  export CUSTOM_ENV_CI_JOB_ID="tools-e2e-$$-$job"
  "$VK" gitlab prepare >"$root/prepare.log" 2>&1 || {
    cat "$root/prepare.log"
    echo "FAIL: prepare"
    exit 1
  }
  printf '%s\n' "$1" >"$root/stage.sh"
  local rc=0
  "$VK" gitlab run "$root/stage.sh" build_script >"$root/stage.log" 2>&1 || rc=$?
  "$VK" gitlab cleanup >/dev/null 2>&1 || true
  return "$rc"
}

echo "== 1. tools_dir is a symlink to a directory holding gitlab-runner =="
if ! run_job 'ls /run/virtkit-tools && gitlab-runner --version'; then
  cat "$root/prepare.log" "$root/stage.log"
  echo "FAIL: the guest did not get the tools the symlinked tools_dir names"
  exit 1
fi
grep -q 'fake-gitlab-runner --version' "$root/stage.log" || {
  cat "$root/stage.log"
  echo "FAIL: gitlab-runner on the guest PATH is not the shared one"
  exit 1
}
if grep -qF "$warning" "$root/prepare.log"; then
  cat "$root/prepare.log"
  echo "FAIL: prepare warned about a tools share that works"
  exit 1
fi
echo "ok: the guest runs the shared gitlab-runner, prepare is quiet"

echo "== 2. the link re-pointed at a directory without gitlab-runner =="
ln -s "$root/tools.b" "$root/tools.new"
mv -T "$root/tools.new" "$root/tools"
run_job 'vk-e2e-tool' || {
  cat "$root/prepare.log" "$root/stage.log"
  echo "FAIL: the next job did not get the tree the re-pointed link names"
  exit 1
}
grep -q 'fake-tool' "$root/stage.log" || {
  cat "$root/stage.log"
  echo "FAIL: the next job ran something other than the re-pointed tree's tool"
  exit 1
}
grep -qF "$warning ([executor] tools_dir $root/tools -> $root/tools.b: the share has no gitlab-runner)" \
  "$root/prepare.log" || {
  cat "$root/prepare.log"
  echo "FAIL: prepare did not warn that the job has no gitlab-runner"
  exit 1
}
echo "ok: the re-pointed link is served, and the missing gitlab-runner is in the trace"

echo "== 3. the link re-pointed at an empty directory =="
ln -s "$root/tools.c" "$root/tools.new"
mv -T "$root/tools.new" "$root/tools"
run_job 'true' || {
  cat "$root/prepare.log" "$root/stage.log"
  echo "FAIL: a job with an empty tools share did not run"
  exit 1
}
grep -qF "$warning ([executor] tools_dir $root/tools -> $root/tools.c: the share is empty)" \
  "$root/prepare.log" || {
  cat "$root/prepare.log"
  echo "FAIL: prepare did not say the tools share is empty"
  exit 1
}
echo "ok: the empty share is the reason in the trace"

echo "== 4. the link re-pointed at a directory whose gitlab-runner is not executable =="
ln -s "$root/tools.d" "$root/tools.new"
mv -T "$root/tools.new" "$root/tools"
run_job '! command -v gitlab-runner' || {
  cat "$root/prepare.log" "$root/stage.log"
  echo "FAIL: the share's non-executable gitlab-runner was put on the guest PATH"
  exit 1
}
grep -qF "$warning ([executor] tools_dir $root/tools -> $root/tools.d: the share's gitlab-runner is not an executable file the guest can reach)" \
  "$root/prepare.log" || {
  cat "$root/prepare.log"
  echo "FAIL: prepare did not say the share's gitlab-runner is not executable"
  exit 1
}
echo "ok: the non-executable gitlab-runner is the reason in the trace"
echo "PASS"
