#!/usr/bin/env bash
# End-to-end: vk-gitlab between a real GitLab CE and a real virtkit fleet, all on this host.
#
#   GitLab CE ── job requests, traces ──> vk-gitlab ── client API ──> vk-hub ── session ──> vk node
#        ^                                                                                     │
#        └──────────── clone, artifacts (job token), from the job's microVM ───────────────────┘
#
# GitLab runs in a vk microVM (lib/gitlab.sh) whose state is cached across runs; vk-hub, a
# vk-registry for caches, one enrolled `vk node run` and vk-gitlab run as host processes
# (lib/fleet.sh). Each scenario (lib/scenarios.sh) pushes a branch with its own
# .gitlab-ci.yml and asserts the outcome through GitLab's API.
#
# Usage: tests/e2e/run.sh --vk <path> --vk-hub <path> [options]
#
#   --vk PATH            the vk under test: the node runs it (virtkit's ./build.sh output)
#   --vk-hub PATH        the vk-hub under test
#   --vk-registry PATH   vk-registry for the node's [registry] (default: beside --vk-hub);
#                        without one the cache scenario is skipped
#   --vk-boot PATH       the vk that boots GitLab (default: vk on PATH, else --vk)
#   --vk-gitlab PATH     use this vk-gitlab instead of building one with ./dev.sh
#   --scenario NAME      run only these (repeatable, or comma-separated); default: all
#   --keep               leave everything running (GitLab, hub, node, vk-gitlab)
#   --reset-gitlab       discard the cached GitLab instance first (a cold boot)
#   --stop-gitlab        stop a GitLab left running by --keep, and exit
#   --run-dir DIR        where logs and state go, absent or empty (default: target/e2e/<timestamp>,
#                        which `cargo clean` deletes, live VM sockets included)
#
# Environment: VK_GITLAB_E2E_CACHE (default ~/.cache/vk-gitlab-e2e) holds the GitLab
# instance; GL_MEM (6G) and GL_CPUS (4) size its VM; GL_BOOT_TIMEOUT (1500 s).
#
# Needs: KVM, curl, jq, git, openssl, ss, ip, shuf, network to Docker Hub; about 9 GiB of free RAM
# (GitLab 6 GiB, job VMs 1 GiB each) and 15 GiB of disk for the GitLab image and its state.
set -euo pipefail
CALLER=$PWD
cd "$(dirname "$0")"
E2E=$PWD
REPO=$(cd ../.. && pwd)

# shellcheck source=images.env
. "$E2E/images.env"
# shellcheck source=lib/common.sh
. "$E2E/lib/common.sh"
# shellcheck source=lib/gitlab.sh
. "$E2E/lib/gitlab.sh"
# shellcheck source=lib/fleet.sh
. "$E2E/lib/fleet.sh"
# shellcheck source=lib/scenarios.sh
. "$E2E/lib/scenarios.sh"

ALL_SCENARIOS=(basic scripts variables exit_codes artifacts cache services timeout cancel restart)

usage() {
  sed -n '/^# Usage:/,/^# Needs:/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

abs() {
  local p
  p=$(command -v "$1" 2>/dev/null) || die "$1: not found"
  [ -x "$p" ] || die "$1: not executable"
  echo "$(cd "$(dirname "$p")" && pwd)/$(basename "$p")"
}

# from_caller <path>: a relative path option resolved against the caller's directory, not
# this script's. A bare name stays as given (a binary looked up on PATH).
from_caller() {
  case $1 in
    /* | '') echo "$1" ;;
    */*) echo "$CALLER/$1" ;;
    *) if [ "${2:-}" = dir ]; then echo "$CALLER/$1"; else echo "$1"; fi ;;
  esac
}

VK='' VK_HUB='' VK_REGISTRY='' VK_BOOT='' VK_GITLAB='' KEEP='' RESET='' STOP_ONLY='' RUN=''
SCENARIOS=()
while [ $# -gt 0 ]; do
  case $1 in
    --vk) VK=$(from_caller "$2") && shift ;;
    --vk-hub) VK_HUB=$(from_caller "$2") && shift ;;
    --vk-registry) VK_REGISTRY=$(from_caller "$2") && shift ;;
    --vk-boot) VK_BOOT=$(from_caller "$2") && shift ;;
    --vk-gitlab) VK_GITLAB=$(from_caller "$2") && shift ;;
    --scenario) IFS=, read -r -a s <<<"$2" && SCENARIOS+=("${s[@]}") && shift ;;
    --keep) KEEP=1 ;;
    --reset-gitlab) RESET=1 ;;
    --stop-gitlab) STOP_ONLY=1 ;;
    --run-dir) RUN=$(from_caller "$2" dir) && shift ;;
    -h | --help) usage ;;
    *) echo "unknown argument: $1" >&2 && usage ;;
  esac
  shift
done

for tool in curl jq git openssl ss ip shuf; do
  command -v "$tool" >/dev/null || die "needs $tool"
done
if [ -z "$VK_BOOT" ]; then
  VK_BOOT=$(command -v vk || true)
  [ -n "$VK_BOOT" ] || VK_BOOT=$VK
fi
[ -n "$VK_BOOT" ] || usage
VK_BOOT=$(abs "$VK_BOOT")

GL_HOST=${GL_HOST:-$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')}
[ -n "$GL_HOST" ] || die "no host address for GitLab (set GL_HOST)"
digest=${GITLAB_IMAGE##*@sha256:}
GL_DIR=${VK_GITLAB_E2E_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/vk-gitlab-e2e}/gitlab-${digest:0:12}

if [ -n "$STOP_ONLY" ]; then
  gl_load
  gl_down
  exit 0
fi

[ -n "$VK" ] && [ -n "$VK_HUB" ] || usage
VK=$(abs "$VK")
VK_HUB=$(abs "$VK_HUB")
if [ -z "$VK_REGISTRY" ] && [ -x "$(dirname "$VK_HUB")/vk-registry" ]; then
  VK_REGISTRY=$(dirname "$VK_HUB")/vk-registry
fi
[ -z "$VK_REGISTRY" ] || VK_REGISTRY=$(abs "$VK_REGISTRY")
[ -r /dev/kvm ] && [ -w /dev/kvm ] || die "no writable /dev/kvm"

[ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=("${ALL_SCENARIOS[@]}")
for s in "${SCENARIOS[@]}"; do
  declare -F "sc_$s" >/dev/null || die "unknown scenario $s (known: ${ALL_SCENARIOS[*]})"
done

RUN_ID=$(date +%Y%m%d-%H%M%S)
RUN=${RUN:-$REPO/target/e2e/$RUN_ID}
[ ! -e "$RUN" ] || [ -z "$(ls -A "$RUN")" ] || die "--run-dir $RUN is not empty"
mkdir -p "$RUN"
RUN=$(cd "$RUN" && pwd)
LOGS=$RUN/logs
mkdir -p "$LOGS" "$RUN/results"
E2E_MASKED_VALUE="e2eMasked$(openssl rand -hex 8)"
E2E_FILE_VALUE="e2e-file-content-$RUN_ID"
log "run dir: $RUN"

T0=$(date +%s)
teardown() {
  local rc=$?
  set +e
  # Scenarios still running in the background (not `jobs -p`: the fleet's components are
  # background jobs too, and --keep leaves them up).
  local p
  for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null; done
  if [ -n "$KEEP" ]; then
    log "--keep: leaving everything up. GitLab: ${GL_URL:-?} (root / see $GL_DIR/instance.env);"
    log "  hub: $RUN/hub/hub.toml; node: VIRTKIT_CONFIG=$RUN/node/config.toml;"
    log "  stop with: tests/e2e/run.sh --stop-gitlab, and kill the pids in $RUN/*.pid"
  else
    fleet_down
    [ -z "${GL_PAT:-}" ] || [ -z "${GL_RUNNER_ID:-}" ] ||
      api DELETE "/runners/$GL_RUNNER_ID" >/dev/null 2>&1
    gl_down
  fi
  print_summary
  log "logs: $LOGS; job traces: $RUN/jobs; total $(($(date +%s) - T0))s"
  [ "$rc" -ne 0 ] || [ "$FAILED" -eq 0 ] || rc=1
  exit "$rc"
}
trap teardown EXIT
trap 'exit 130' INT TERM

if [ -n "$RESET" ]; then
  log "gitlab: discarding the cached instance in $GL_DIR"
  gl_load
  gl_down
  rm -rf "$GL_DIR"
fi

# vk-gitlab: a static-musl debug build from the pinned toolchain. `cargo test --no-run` on an
# integration test builds the binary beside it; dev.sh refuses `cargo build`. A development VM
# this boots powers off after two idle minutes, not dev.sh's half hour, to hand its memory back.
if [ -z "$VK_GITLAB" ]; then
  log "vk-gitlab: building with ./dev.sh"
  (cd "$REPO" && VK_DEV_IDLE_SECS=${VK_DEV_IDLE_SECS:-120} ./dev.sh test -p vk-gitlab --no-run --test hub_e2e) >"$LOGS/build-vk-gitlab.log" 2>&1 ||
    { tail -30 "$LOGS/build-vk-gitlab.log" >&2; die "building vk-gitlab failed"; }
  VK_GITLAB=$REPO/target/x86_64-unknown-linux-musl/debug/vk-gitlab
fi
VK_GITLAB=$(abs "$VK_GITLAB")
log "vk-gitlab: $("$VK_GITLAB" --version)"
log "vk: $("$VK" --version); vk-hub: $("$VK_HUB" --version 2>&1 | head -1)"

T_GL=$(date +%s)
gl_up
gl_seed
T_GL=$(($(date +%s) - T_GL))

if [ -n "$VK_REGISTRY" ]; then
  registry_up
fi
hub_up
node_up
vk_gitlab_config
"$VK_GITLAB" verify --config "$RUN/vk-gitlab/config.toml" >"$LOGS/vk-gitlab-verify.log" 2>&1 ||
  { cat "$LOGS/vk-gitlab-verify.log" >&2; die "vk-gitlab verify failed"; }
vk_gitlab_up

# run_scenario <name>: its log in $LOGS/scenario-<name>.log, its result in
# $RUN/results/<name>. Callers run it in a subshell (`&` or `( )`), and it forks none of its
# own, so killing that subshell stops the scenario.
run_scenario() {
  local name=$1
  local log=$LOGS/scenario-$name.log
  set +e
  {
    SC_ERRORS=0 SC_DETAIL=''
    log "scenario $name: start"
    if "sc_$name" && [ "$SC_ERRORS" -eq 0 ]; then
      echo "PASS|$SC_DETAIL" >"$RUN/results/$name"
    fi
    log "scenario $name: done"
  } >>"$log" 2>&1
  [ -s "$RUN/results/$name" ] ||
    echo "FAIL|$(grep -h 'assertion:' "$log" | head -3 | sed 's/.*assertion: //' | paste -sd ';')" \
      >"$RUN/results/$name"
}

T_SC=$(date +%s)
pids=()
for s in "${SCENARIOS[@]}"; do
  case $s in
    restart) ;;
    cache)
      if [ -z "$VK_REGISTRY" ]; then
        echo "SKIP|no vk-registry: the node keeps caches only in a remote [registry]" \
          >"$RUN/results/cache"
      else
        run_scenario cache &
        pids+=($!)
      fi
      ;;
    *)
      run_scenario "$s" &
      pids+=($!)
      ;;
  esac
done
for p in ${pids[@]+"${pids[@]}"}; do wait "$p" || true; done
pids=()
for s in "${SCENARIOS[@]}"; do
  [ "$s" = restart ] && (run_scenario restart)
done
T_SC=$(($(date +%s) - T_SC))

for s in "${SCENARIOS[@]}"; do
  r=$(cat "$RUN/results/$s" 2>/dev/null || echo "FAIL|no result")
  case ${r%%|*} in
    PASS) pass "$s" "${r#*|}" ;;
    SKIP) skip "$s" "${r#*|}" ;;
    *) failed "$s" "${r#*|} (see $LOGS/scenario-$s.log)" ;;
  esac
done
# Every hub request vk-gitlab drops mid-flight costs a connection (and a TLS handshake for the
# next). A few come from the restart scenario's SIGKILL; one per job is already a leak.
jobs_run=$(find "$RUN/jobs" -name '*.json' 2>/dev/null | wc -l)
aborts=$(grep -c 'connection closed before message completed' "$LOGS/hub.log" || true)
if [ "$aborts" -le "$jobs_run" ]; then
  pass hub_requests "$aborts requests dropped mid-flight over $jobs_run jobs"
else
  failed hub_requests "$aborts requests dropped mid-flight over $jobs_run jobs (see $LOGS/hub.log)"
fi
log "timings: gitlab up+seed ${T_GL}s ($([ -n "${GL_REUSED:-}" ] && echo reused || echo booted)), scenarios ${T_SC}s"
