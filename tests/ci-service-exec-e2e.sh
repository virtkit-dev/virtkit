#!/usr/bin/env bash
# =====================================================================================
# A CI job, or a `vk run --compose` primary, runs commands in its compose services with
# `vk exec --service`, from its own VM.
# =====================================================================================
# Drives `vk gitlab prepare|run|cleanup` directly, no GitLab needed, on a `compose:` job with a
# `db` service:
#   1. the job's script runs `vk exec --service db … -- …`: the command runs in the service,
#      its output and exit status come back; --env, --dir, --user, -b, --clear-env and -t
#      (under script(1), for a terminal) apply;
#   2. what the host does not allow is refused: another `vk` command, a service the job does
#      not have, a raw request putting a host `vk` flag first, a fifth request at once; a raw
#      request's --dir and --user are ignored;
#   3. with `[executor] guest_service_exec = false`, the job VM has no `vk` and no channel;
#   4. a `vk run --compose` primary reaches its services the same way, has neither with
#      --no-service-exec, and is refused a state dir the guest can write.
#
# Run:  VK=./dist/vk tests/ci-service-exec-e2e.sh
# Needs: a `vk` with an embedded agent and kernel, KVM, and network to pull alpine and debian.
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
    image: debian:bookworm-slim  # script(1), to give `vk exec -t` a terminal
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
  # As gitlab-runner's own script does: the body runs in a subshell, stdin from /dev/null.
  printf '(\n%s\n) </dev/null\n' "$1" >"$root/stage.sh"
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
out=$(vk exec --service db --env FOO=bar --dir /tmp --user nobody -- sh -c "echo \$FOO \$(pwd) \$(id -un)")
echo "flags: $out"
[ "$out" = "bar /tmp nobody" ]
if vk exec --service db --clear-env -- /usr/bin/env | grep "^PATH="; then exit 1; fi
vk exec --service db -b -- sh -c "echo from-background > /tmp/bg"
i=0
until [ "$(vk exec --service db -- cat /tmp/bg 2>/dev/null)" = from-background ]; do
  i=$((i + 1)); [ "$i" -lt 50 ]; sleep 0.1
done
out=$(script -qc "vk exec --service db -t -- tty" /dev/null)
echo "tty: $out"
case $out in */dev/pts/*) ;; *) exit 1 ;; esac
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
# A raw request: a host `vk` flag first reaches no host `vk`, and its --dir is ignored.
raw="/run/vk/bin/vk-agent -s /run/vk/host.sock exec"
if $raw -- --config=/etc/passwd vk exec --service db -- true 2>err; then exit 1; fi
cat err
grep -q "runs only" err
$raw --dir /nonexistent/vk-e2e --user root -- vk exec --service db -- true
# The host runs four requests at once and refuses a fifth.
# Each of four retries until it holds a slot; the fifth is polled until it is refused.
for _ in 1 2 3 4; do
  (until vk exec --service db -- sleep 5 2>/dev/null; do sleep 0.1; done) &
done
i=0
while vk exec --service db -- true 2>err; do
  i=$((i + 1)); [ "$i" -lt 100 ]; sleep 0.1
done
cat err
grep -q "at most 4" err
wait' ||
  fail "a command the host does not allow ran"
grep -q "the services: db" "$root/stage.log" || fail "the refusal does not name the job's services"
echo "ok"

echo "== 3. guest_service_exec = false: no channel =="
config false
run_job 'if command -v vk; then exit 1; fi
[ ! -e /run/vk/host.sock ]' ||
  fail "the job has a vk or a host channel with guest_service_exec = false"
echo "ok"

echo "== 4. a vk run --compose primary =="
cat >"$root/run.compose.yaml" <<'EOF'
services:
  db:
    image: alpine:3.21
    command: ["sh", "-c", "echo served-by-db > /tmp/marker; exec sleep 3600"]
EOF
"$VK" run --state-dir "$root/run-state" --compose "$root/run.compose.yaml" alpine:3.21 \
  -- sh -c '[ "$(vk exec --service db -- cat /tmp/marker)" = served-by-db ]' \
  >"$root/stage.log" 2>&1 || fail "the primary could not run commands in its service"
"$VK" run --state-dir "$root/run-state" --compose "$root/run.compose.yaml" --no-service-exec \
  alpine:3.21 -- sh -c 'if command -v vk; then exit 1; fi; [ ! -e /run/vk/host.sock ]' \
  >"$root/stage.log" 2>&1 || fail "the primary has a vk or a host channel with --no-service-exec"
mkdir -p "$root/share"
if "$VK" run --state-dir "$root/share/state" --workdir "$root/share" \
  --compose "$root/run.compose.yaml" alpine:3.21 -- true >"$root/stage.log" 2>&1; then
  fail "the primary booted with a state dir the guest can write"
fi
grep -q -- "--no-service-exec" "$root/stage.log" || fail "the refusal does not name the way out"
echo "ok"

echo "PASS"
