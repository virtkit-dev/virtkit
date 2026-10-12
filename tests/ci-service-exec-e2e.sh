#!/usr/bin/env bash
# =====================================================================================
# A CI job runs commands in its compose services with `vk exec --service`, from its own VM.
# =====================================================================================
# Drives `vk gitlab prepare|run|cleanup` directly, no GitLab needed, on a `compose:` job with a
# `db` service:
#   1. the job's script runs `vk exec --service db -- …`: the command runs in the service, its
#      output and exit status come back;
#   2. what the host does not allow is refused: another `vk` command, a service the job does
#      not have, `vk service` (a job's services are fixed for it);
#   3. with `[executor] guest_service_exec = false`, the job VM has no such channel.
#
# Run:  VK=./dist/vk tests/ci-service-exec-e2e.sh
# Needs: a `vk` with an embedded agent and kernel, KVM, and network to pull alpine.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }
# Not under a tmpfs /tmp: the job dirs hold the VMs' disks.
root=$(realpath "$(mktemp -d "${WORK_DIR:-$HOME}/vk-ci-service-exec-e2e.XXXXXX")")
http_pid=
cleanup() {
  "$VK" gitlab cleanup >/dev/null 2>&1 || true
  [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
  rm -rf "$root"
}
trap cleanup EXIT

# The repository: the compose file, served over dumb HTTP for the host checkout.
src=$root/src
mkdir -p "$src/ci"
cat >"$src/ci/lab.compose.yaml" <<'EOF'
services:
  job:
    image: alpine:3.21
  db:
    image: alpine:3.21
    command: ["sh", "-c", "echo served-by-db > /tmp/marker; exec sleep 3600"]
EOF
git -C "$src" init -q -b main
git -C "$src" -c user.name=e2e -c user.email=e2e@example.invalid add -A
git -C "$src" -c user.name=e2e -c user.email=e2e@example.invalid commit -qm e2e
git clone -q --bare "$src" "$root/www/repo.git"
git -C "$root/www/repo.git" update-server-info
port=$((20000 + RANDOM % 20000))
python3 -m http.server -d "$root/www" -b 127.0.0.1 "$port" >"$root/http.log" 2>&1 &
http_pid=$!
for _ in $(seq 50); do
  git ls-remote "http://127.0.0.1:$port/repo.git" >/dev/null 2>&1 && break
  sleep 0.2
done

config() {
  cat >"$root/config.toml" <<EOF
state_dir = "$root/state"

[executor]
host_checkout = true
atop = false
guest_service_exec = $1

[net]
mode = "switch"
EOF
}
export VIRTKIT_CONFIG="$root/config.toml"
export XDG_DATA_HOME="$root/data"
export CUSTOM_ENV_MICROVM_IMAGE="compose:ci/lab.compose.yaml#job"
export CUSTOM_ENV_CI_REPOSITORY_URL="http://127.0.0.1:$port/repo.git"
export CUSTOM_ENV_CI_COMMIT_SHA=$(git -C "$src" rev-parse HEAD)
export CUSTOM_ENV_CI_COMMIT_REF_NAME=main
export CUSTOM_ENV_CI_PROJECT_ID=1
export CUSTOM_ENV_CI_PROJECT_PATH=e2e/service-exec
export CUSTOM_ENV_CI_PROJECT_PATH_SLUG=e2e-service-exec
export CUSTOM_ENV_CI_PROJECT_DIR=/builds/e2e/service-exec
export CUSTOM_ENV_CI_CONCURRENT_ID=0

job=0
# One job: prepare, the script $1 (its output in $root/stage.log), cleanup; its status.
run_job() {
  job=$((job + 1))
  export CUSTOM_ENV_CI_JOB_ID="service-exec-e2e-$$-$job"
  "$VK" gitlab prepare >"$root/prepare.log" 2>&1 || {
    cat "$root/prepare.log"
    echo "FAIL: prepare"
    exit 1
  }
  printf '%s\n' "$1" >"$root/stage.sh"
  local rc=0
  "$VK" gitlab run "$root/stage.sh" build_script >"$root/stage.log" 2>&1 || rc=$?
  # The host side of the job's command channel, for a failure.
  find "$root/state" -name service-exec.log -exec cat {} + >"$root/service-exec.log" 2>/dev/null || true
  "$VK" gitlab cleanup >/dev/null 2>&1 || true
  return "$rc"
}
fail() {
  cat "$root/prepare.log" "$root/stage.log"
  echo "-- service-exec.log:"
  cat "$root/service-exec.log" 2>/dev/null || true
  echo "FAIL: $*"
  exit 1
}

echo "== 1. the job runs commands in its service =="
config true
run_job 'set -e
out=$(vk exec --service db -- cat /tmp/marker)
echo "got: $out"
[ "$out" = served-by-db ]
rc=0; vk exec --service db -- sh -c "exit 7" || rc=$?
echo "status: $rc"
[ "$rc" = 7 ]
echo hello | vk exec --service db -- cat' || fail "the job could not run commands in its service"
grep -q "got: served-by-db" "$root/stage.log" || fail "the service's output did not come back"
grep -q "^hello" "$root/stage.log" || fail "stdin did not reach the service"
echo "ok"

echo "== 2. what the host does not allow is refused =="
run_job 'set -e
if vk exec --service nope -- true 2>err; then exit 1; fi
cat err
grep -q "no service" err
if vk version 2>err; then exit 1; fi
cat err
if vk service down db 2>err; then exit 1; fi
cat err
grep -q "fixed for the job" err' || fail "a command the host does not allow ran"
grep -q "the services: db" "$root/stage.log" || fail "the refusal does not name the job's services"
echo "ok"

echo "== 3. guest_service_exec = false: no channel =="
config false
run_job 'if vk exec --service db -- true 2>err; then exit 1; fi; cat err' ||
  fail "the job reached its service with guest_service_exec = false"
echo "ok"
echo "PASS"
