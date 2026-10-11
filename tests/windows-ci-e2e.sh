#!/usr/bin/env bash
# =====================================================================================
# A CI job's Windows service: built from a Dockerfile in the repo, ISOs from the registry.
# =====================================================================================
# Drives `vk gitlab prepare|run|cleanup` directly, no GitLab needed, on a `compose:` job whose
# `win` service builds from a Windows Dockerfile in the repository, which holds no ISO:
#   1. prepare checks the repository out (host_checkout), builds the service — fetching the
#      ISOs it pins from the build cache registry, or pulling its layers from there when
#      another host built them — boots it beside the Linux job VM and waits for its
#      provisioning;
#   2. the job script reaches the service by its name on the job's LAN;
#   3. a second job finds every layer cached.
#
# Run:  REGISTRY=127.0.0.1:5077 VK=./dist/vk tests/windows-ci-e2e.sh
# Needs: a `vk` with an embedded agent, kernel and UEFI firmware, KVM, network to pull alpine,
# and a vk-registry at $REGISTRY (plain HTTP) holding the Windows Server 2025 evaluation ISO
# and virtio-win.iso (`vk registry put --cache-registry $REGISTRY --cache-insecure ...`),
# whose digests ISO_SHA256 and DRIVERS_SHA256 name. About 20 GB of disk and, the first time
# anywhere, a Windows install (20 minutes or more).
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }
[ -n "${REGISTRY:-}" ] || { echo "SKIP: no REGISTRY holding the ISOs"; exit 0; }
ISO_SHA256=${ISO_SHA256:-d0ef4502e350e3c6c53c15b1b3020d38a5ded011bf04998e950720ac8579b23d}
DRIVERS_SHA256=${DRIVERS_SHA256:-303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d}
# Not under a tmpfs /tmp: the job dirs hold the service's disks.
root=$(realpath "$(mktemp -d "${WORK_DIR:-$HOME}/vk-windows-ci-e2e.XXXXXX")")
http_pid=
cleanup() {
  "$VK" gitlab cleanup >/dev/null 2>&1 || true
  [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
  rm -rf "$root"
}
trap cleanup EXIT

# The repository: a compose file and the Windows Dockerfile, served over dumb HTTP.
src=$root/src
mkdir -p "$src/ci" "$src/windows"
cat >"$src/ci/lab.compose.yaml" <<'EOF'
services:
  job:
    image: alpine:3.21
  win:
    build: { context: ../windows, target: svc }
    x-virtkit: { cpus: 2, mem: 4G }
EOF
cat >"$src/windows/Dockerfile" <<EOF
# vk: cpus=4 mem=4G
FROM winiso:ws2025-eval-en-us.iso@sha256:$ISO_SHA256 \\
    --edition="Windows Server 2025 Standard Evaluation" \\
    --drivers=virtio-win.iso@sha256:$DRIVERS_SHA256 AS base
SHELL ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
RUN New-NetFirewallRule -DisplayName vk-e2e-ping -Protocol ICMPv4 -IcmpType 8 -Action Allow | Out-Null

FROM base AS svc
CMD Set-Content C:\\vk-provisioned.txt \$env:VK_HOSTNAME
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

cat >"$root/config.toml" <<EOF
state_dir = "$root/state"

[executor]
host_checkout = true
atop = false

[net]
mode = "switch"

[build]
cache_registry = "$REGISTRY"
cache_insecure = true
EOF
export VIRTKIT_CONFIG="$root/config.toml"
export XDG_DATA_HOME="$root/data"
export CUSTOM_ENV_MICROVM_IMAGE="compose:ci/lab.compose.yaml#job"
export CUSTOM_ENV_CI_REPOSITORY_URL="http://127.0.0.1:$port/repo.git"
export CUSTOM_ENV_CI_COMMIT_SHA=$(git -C "$src" rev-parse HEAD)
export CUSTOM_ENV_CI_COMMIT_REF_NAME=main
export CUSTOM_ENV_CI_PROJECT_ID=1
export CUSTOM_ENV_CI_PROJECT_PATH=e2e/windows-ci
export CUSTOM_ENV_CI_PROJECT_PATH_SLUG=e2e-windows-ci
export CUSTOM_ENV_CI_PROJECT_DIR=/builds/e2e/windows-ci
export CUSTOM_ENV_CI_CONCURRENT_ID=0

job=0
# One job: prepare (its output in $root/prepare.log), the script $1, cleanup.
run_job() {
  job=$((job + 1))
  export CUSTOM_ENV_CI_JOB_ID="windows-ci-e2e-$$-$job"
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

echo "== 1. a job with a Windows service built from the repository =="
t=$SECONDS
run_job 'ping -c 3 -W 5 win' || {
  cat "$root/prepare.log" "$root/stage.log"
  echo "FAIL: the job did not reach its Windows service"
  exit 1
}
grep -q 'service win ready' "$root/prepare.log" || {
  cat "$root/prepare.log"
  echo "FAIL: prepare did not wait for the service's provisioning"
  exit 1
}
echo "ok: the job reached its Windows service ($((SECONDS - t))s)"

echo "== 2. the next job builds nothing =="
t=$SECONDS
run_job 'ping -c 1 -W 5 win' || {
  cat "$root/prepare.log" "$root/stage.log"
  echo "FAIL: the second job"
  exit 1
}
if grep -q 'installing Windows\|done in' "$root/prepare.log"; then
  cat "$root/prepare.log"
  echo "FAIL: the second job built a layer again"
  exit 1
fi
echo "ok: every layer cached ($((SECONDS - t))s)"
echo "PASS"
