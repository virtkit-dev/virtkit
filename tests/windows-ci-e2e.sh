#!/usr/bin/env bash
# =====================================================================================
# A CI job's Windows service: built from a Dockerfile in the repo, ISOs from the registry.
# =====================================================================================
# Drives `vk gitlab prepare|run|cleanup` directly, no GitLab needed, on a `compose:` job whose
# `win` service builds from a Windows Dockerfile in the repository, which holds no ISO:
#   1. prepare checks the repository out (host_checkout), builds the service — fetching the
#      ISOs it pins from the build cache registry, or pulling its layers from there when
#      another host built them — boots it beside the Linux job VM and waits for its
#      provisioning (its CMD), which it reports ready only once that ran;
#   2. the job script reaches the service by its name on the job's LAN, which answers a ping
#      only once its CMD let pings through the firewall;
#   3. a second job finds every layer cached.
#
# Run:  VK=./dist/vk ISO_DIR=~/.cache/vk-windows tests/windows-ci-e2e.sh
#   or: REGISTRY=127.0.0.1:5077 VK=./dist/vk tests/windows-ci-e2e.sh
# Needs: a `vk` with an embedded agent, kernel and UEFI firmware, KVM, network to pull alpine,
# nothing of the host but bash and a POSIX userland (the test repository is made by
# vk-testkit, VK_TESTKIT, by default built with `./dev.sh build -p vk-testkit`, under vk), a
# vk-registry (VK_REGISTRY, by default the one beside $VK), which this script runs to serve
# the repository from its WebDAV area, and the Windows Server 2025 evaluation ISO and
# virtio-win.iso: either in ISO_DIR, put by this script into that vk-registry (and pinned by
# the digests of those files), or already in the vk-registry at $REGISTRY under the digests
# ISO_SHA256 and DRIVERS_SHA256 name (plain HTTP; `vk registry put --cache-registry $REGISTRY
# --cache-insecure ...`).
# About 20 GB of disk and, the first time anywhere, a Windows install (20 minutes or more).
# tests/release-e2e.sh runs this only when ISO_DIR is set, or when named.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }
[ -n "${REGISTRY:-}${ISO_DIR:-}" ] || { echo "SKIP: neither ISO_DIR nor a REGISTRY holding the ISOs"; exit 0; }
ISO_SHA256=${ISO_SHA256:-d0ef4502e350e3c6c53c15b1b3020d38a5ded011bf04998e950720ac8579b23d}
DRIVERS_SHA256=${DRIVERS_SHA256:-303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d}
# Not under a tmpfs /tmp: the job dirs hold the service's disks.
root=$(realpath "$(mktemp -d "${WORK_DIR:-$HOME}/vk-windows-ci-e2e.XXXXXX")")
registry_pid=
cleanup() {
  "$VK" gitlab cleanup >/dev/null 2>&1 || true
  [ -z "$registry_pid" ] || kill "$registry_pid" 2>/dev/null || true
  rm -rf "$root"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Wait up to $1 seconds for the command that follows to succeed.
wait_for() {
  local deadline=$((SECONDS + $1))
  shift
  until "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}

# The test's own helpers, built in the development VM: the script needs nothing of the host
# but bash and a POSIX userland.
VK_TESTKIT=${VK_TESTKIT:-}
if [ -z "$VK_TESTKIT" ]; then
  here=$(cd "$(dirname "$0")/.." && pwd)
  "$here/dev.sh" build -p vk-testkit >"$root/testkit-build.log" 2>&1 ||
    fail "building vk-testkit (see $root/testkit-build.log)"
  VK_TESTKIT=$here/target/x86_64-unknown-linux-musl/debug/vk-testkit
fi
[ -x "$VK_TESTKIT" ] || fail "no vk-testkit at $VK_TESTKIT"

# A vk-registry of this test's own: its WebDAV area serves the repository, and without a
# REGISTRY it also holds the ISOs from ISO_DIR. On a port the kernel picks, which it reports.
VK_REGISTRY=${VK_REGISTRY:-$(dirname "$VK")/vk-registry}
[ -x "$VK_REGISTRY" ] || fail "no vk-registry at $VK_REGISTRY (set VK_REGISTRY)"
mkdir -p "$root/registry"
"$VK_REGISTRY" serve --addr 127.0.0.1:0 --root "$root/registry" >"$root/registry.log" 2>&1 &
registry_pid=$!
wait_for 30 grep -q ' on http://' "$root/registry.log" ||
  fail "vk-registry did not come up (see $root/registry.log)"
local_registry=$(sed -n 's|.* on http://\(.*\)$|\1|p' "$root/registry.log")
if [ -z "${REGISTRY:-}" ]; then
  REGISTRY=$local_registry
  for iso in ws2025-eval-en-us.iso virtio-win.iso; do
    [ -f "$ISO_DIR/$iso" ] || fail "$ISO_DIR/$iso is missing (see examples/windows/lab.Dockerfile)"
    put=$("$VK" registry put --cache-registry "$REGISTRY" --cache-insecure "$ISO_DIR/$iso") ||
      fail "putting $iso in the registry"
    # The Dockerfile pins the digest of the file put: an ISO_DIR may hold another build.
    case $iso in
      ws2025-*) ISO_SHA256=${put##*sha256:} ;;
      virtio-*) DRIVERS_SHA256=${put##*sha256:} ;;
    esac
  done
fi

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
RUN Set-Content C:\\vk-e2e.txt base

FROM base AS svc
CMD New-NetFirewallRule -DisplayName "vk-e2e-ping-\$env:VK_HOSTNAME" -Protocol ICMPv4 -IcmpType 8 -Action Allow | Out-Null
EOF
# One commit of the files, as a bare repository git's dumb HTTP transport can clone.
bare=$root/repo.git
"$VK_TESTKIT" git-repo "$src" "$bare" main >"$root/commit" || fail "making the repository"
# Served from the registry's WebDAV area, one file per `files/<dir>:<name>`.
while IFS= read -r path; do
  path=${path#"$bare/"}
  dir=repo.git
  [ "${path%/*}" = "$path" ] || dir=repo.git/${path%/*}
  "$VK" registry put --cache-registry "$local_registry" --cache-insecure --dir "$dir" \
    "$bare/$path" >/dev/null 2>>"$root/serve.log" || fail "serving $path (see $root/serve.log)"
done < <(find "$bare" -type f)
repo_url=http://$local_registry/dav/files/repo.git

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
export CUSTOM_ENV_CI_REPOSITORY_URL=$repo_url
CUSTOM_ENV_CI_COMMIT_SHA=$(cat "$root/commit")
export CUSTOM_ENV_CI_COMMIT_SHA
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
# The layers and installs the host's Windows cache holds: a job that builds one adds an entry.
cached() {
  find "$root/data" -mindepth 1 -type d \
    \( -path '*/windows/layers/*' -o -path '*/windows/winiso/settled/*' \) -prune -print | sort
}
before=$(cached)
[ -n "$before" ] || fail "the first job left no layer in the host's Windows cache"
t=$SECONDS
run_job 'ping -c 1 -W 5 win' || {
  cat "$root/prepare.log" "$root/stage.log"
  echo "FAIL: the second job"
  exit 1
}
if [ "$(cached)" != "$before" ]; then
  cat "$root/prepare.log"
  diff <(echo "$before") <(cached) || true
  echo "FAIL: the second job built a layer again"
  exit 1
fi
echo "ok: every layer cached ($((SECONDS - t))s)"
echo "PASS"
