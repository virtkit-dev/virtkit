#!/usr/bin/env bash
# dev.sh — fast, crate-scoped type checking, targeted tests and an interactive shell in a
# shared vk development VM that powers itself off once left idle. The mold-linking
# RUSTFLAGS and shared target/ directory match every build.sh invocation, and the dev
# profile matches build.sh --fast, so dependency artifacts are reused between the two
# workflows. The VK_EMBED_* vars build.sh sets are deliberately absent here (they must
# name an already built agent), so vk-driver's own build script reruns when you alternate
# the two.
#
# Examples:
#   ./dev.sh check -p vk-core
#   ./dev.sh check -p vk-driver --all-targets
#   ./dev.sh test -p vk-core --lib dockerignore::tests
#   ./dev.sh test -p vk-core --test exec disconnect_kills_remote_process
#   ./dev.sh test -p vk-driver --bin vk atop_view::tests
#   ./dev.sh shell
#   ./dev.sh stop
#
# VK_DEV_CPUS / VK_DEV_MEM size the VM (default: host cpus, 8G). VK_DEV_IDLE_SECS sets how
# long it survives with no cargo command or open shell (default: 1800, 0 = until
# ./dev.sh stop).
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$PWD

usage() {
  cat >&2 <<'EOF'
usage: ./dev.sh check -p <package> [cargo check arguments]
       ./dev.sh test  -p <package> <target> [test filter]
       ./dev.sh shell
       ./dev.sh stop

The fast loop is deliberately scoped: --workspace/--all and optimized profiles are
rejected. For tests, select exactly one target with --lib, --bin NAME or --test NAME
(--doc and --example NAME also count) and normally pass the changed module or test
name as a filter. `shell` opens an interactive shell in the same VM under the same
environment the cargo commands get, and holds the VM for as long as it runs. The
first command boots a vk development VM; by default it powers off after 1800 seconds
without a cargo command. Set VK_DEV_IDLE_SECS to change the window, or to 0 to keep
the VM until ./dev.sh stop.
EOF
  exit 2
}

command -v vk >/dev/null 2>&1 || {
  echo "dev.sh: vk is required for the Docker-free development loop" >&2
  exit 1
}
command -v flock >/dev/null 2>&1 || {
  echo "dev.sh: flock is required to coordinate the shared development VM" >&2
  exit 1
}
VK=$(command -v vk)
# Outside the repo on purpose. Inside target/ a `cargo clean` — host-side or from the
# guest, where target/ is shared read-write — would delete a live VM's sockets and lock
# from under it, and the VM's own control sockets would be re-exported into the guest
# over virtiofs. Keyed by checkout path so two checkouts get two VMs.
STATE_DIR="${XDG_STATE_HOME:-${HOME:?set HOME or XDG_STATE_HOME so the VM has a state directory}/.local/state}/virtkit/dev-vm-$(printf %s "$ROOT" | sha256sum | cut -c1-16)"

# Take the lock on fd 9 and hold it for the caller. It closes the window between probing
# the VM and starting one, which vk's own state-dir lock turns into a hard failure rather
# than a wait. The timeout keeps a wedged first boot from hanging every other terminal.
lock_state_dir() {
  mkdir -p "$STATE_DIR"
  exec 9>"$STATE_DIR/dev.lock"
  flock -w 600 9 || {
    echo "dev.sh: timed out waiting for another dev.sh to release the VM lock" >&2
    exit 1
  }
}

MODE=${1:-}
case "$MODE" in
  check | test)
    shift
    [ "$#" -gt 0 ] || usage
    ;;
  shell)
    shift
    [ "$#" -eq 0 ] || usage
    # The remote pty needs -t, which vk exec only accepts with both local ends on a
    # terminal; and a shell reading a redirected stdin would exit before the caller
    # could type into it.
    { [ -t 0 ] && [ -t 1 ]; } || {
      echo "dev.sh: shell needs a terminal on stdin and stdout" >&2
      exit 1
    }
    ;;
  stop)
    shift
    [ "$#" -eq 0 ] || usage
    [ -d "$STATE_DIR" ] || {
      echo "dev.sh: development VM is not running" >&2
      exit 0
    }
    lock_state_dir
    # Gate on the registry rather than on an agent probe: a VM still building its image,
    # or one whose agent has wedged, is running and must stay stoppable. `vk stop DIR`
    # exits non-zero when nothing matches, which is "already stopped" here.
    "$VK" stop "$STATE_DIR" || true
    exit 0
    ;;
  *) usage ;;
esac
args=("$@")

# Keep accidental broad or optimized invocations out of the edit loop. CI and release
# verification retain their existing workspace-wide commands.
has_package=""
has_test_target=""

reject() {
  echo "dev.sh: $1" >&2
  exit 2
}
# A glob spec (-p '*') selects every member, which is what --workspace is refused for.
check_package_spec() {
  case "$1" in
    *[\*\?\[]*) reject "a glob package spec selects the whole workspace; name one package" ;;
  esac
}
# cargo's `bench` profile inherits `release`, so both mean an optimized build.
check_profile() {
  case "$1" in
    release | bench) reject "the $1 profile is optimized and disabled here; use ./build.sh when shipping" ;;
  esac
}
note_test_target() {
  [ "$MODE" = test ] || return 0
  [ -z "$has_test_target" ] || reject "select exactly one test target, not several"
  has_test_target=1
}

# Vets one cargo invocation's arguments and exits non-zero on anything out of scope; reads
# $MODE for the test-only rules and accumulates into has_package/has_test_target, so it is
# called once per run.
check_cargo_args() {
  local argv=("$@") i arg
  for ((i = 0; i < ${#argv[@]}; i++)); do
    arg=${argv[$i]}
    # Everything past a bare `--` is the test binary's own argv, not cargo's: libtest
    # has flags of its own (`--test`, `--lib`) that must not read as target selection.
    if [ "$arg" = -- ]; then
      break
    fi
    case "$arg" in
      --workspace | --all)
        reject "$arg is intentionally disabled; select an affected package with -p"
        ;;
      -r | --release)
        reject "release builds are intentionally disabled; use ./build.sh when shipping"
        ;;
      --profile)
        [ $((i + 1)) -lt ${#argv[@]} ] || usage
        check_profile "${argv[$((i + 1))]}"
        ;;
      --profile=*) check_profile "${arg#--profile=}" ;;
      -p | --package)
        [ $((i + 1)) -lt ${#argv[@]} ] || usage
        check_package_spec "${argv[$((i + 1))]}"
        has_package=1
        ;;
      --package=*)
        check_package_spec "${arg#--package=}"
        has_package=1
        ;;
      # cargo's attached short form, e.g. -pvk-core.
      -p?*)
        check_package_spec "${arg#-p}"
        has_package=1
        ;;
      --lib | --doc | --bin | --bin=* | --test | --test=* | --example | --example=*)
        note_test_target
        ;;
      --all-targets | --bins | --tests | --benches | --examples)
        if [ "$MODE" = test ]; then
          reject "$arg is too broad for the edit loop; select one --lib, --bin or --test target"
        fi
        ;;
    esac
  done
  [ -n "$has_package" ] || {
    echo "dev.sh: select the affected package with -p/--package" >&2
    exit 2
  }
  if [ "$MODE" = test ] && [ -z "$has_test_target" ]; then
    echo "dev.sh: select one test target with --lib, --bin NAME, or --test NAME" >&2
    exit 2
  fi
}
# `shell` takes no cargo arguments to vet; every other mode is a cargo invocation.
[ "$MODE" = shell ] || check_cargo_args "${args[@]}"
# Checked on every invocation, not just the one that boots: a typo should surface before it
# has waited for the VM lock. `:-` already substituted for an empty value.
idle_secs=${VK_DEV_IDLE_SECS:-1800}
case "$idle_secs" in
  *[!0-9]*) reject "VK_DEV_IDLE_SECS must be a whole number of seconds (0 = no timeout)" ;;
esac

commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit (dirty)"
# Kept byte-identical to build.sh's BUILD_ENV, mold-linking RUSTFLAGS included: any
# divergence changes the unit fingerprints and silently stops the two workflows from
# sharing target/. Change both together.
DEV_ENV=(
  HOME=/tmp
  CARGO_HOME=/work/target/.cargo-home
  CARGO_TARGET_DIR=/work/target
  SOURCE_DATE_EPOCH=0
  "RUSTFLAGS=--remap-path-prefix=/work=/src --remap-path-prefix=/work/target/.cargo-home=/cargo -C link-arg=-fuse-ld=mold"
  "CFLAGS_x86_64_unknown_linux_musl=-ffile-prefix-map=/work=/src -ffile-prefix-map=/work/target/.cargo-home=/cargo"
  "VK_GIT_COMMIT=$commit"
)
if [ "$MODE" = shell ]; then
  # Not a login shell: Alpine's /etc/profile overwrites PATH with the system default,
  # which drops the image's cargo/rustup bin directory out of the interactive shell.
  guest_cmd=(/bin/sh)
  what="opening a shell"
else
  guest_cmd=(cargo "$MODE" "${args[@]}")
  what="running cargo $MODE"
fi

# Reboot only when the build image's inputs, or the toolchain its base tag tracks, change.
# rust-toolchain.toml is never COPYed into the image, but update.sh keeps the pinned base
# tag in sync with it, and the guest toolchain follows it. Source and Cargo manifest edits
# are shared live at /work and never require a reboot.
image_stamp=$(sha256sum \
  .devcontainer/Dockerfile \
  .devcontainer/apk-pins.txt \
  rust-toolchain.toml | sha256sum | cut -d ' ' -f 1)
stamp_file="$STATE_DIR/image.stamp"
lock_state_dir
agent_up=""
"$VK" status "$STATE_DIR" >/dev/null 2>&1 && agent_up=1
if [ -n "$agent_up" ] && [ "$(cat "$stamp_file" 2>/dev/null)" != "$image_stamp" ]; then
  echo "dev.sh: build image inputs changed; restarting the development VM" >&2
  "$VK" stop "$STATE_DIR" || true
  agent_up=""
fi

if [ -z "$agent_up" ]; then
  echo "dev.sh: starting the development VM" >&2
  # The timeout owns the VM's lifetime, so the startup command only has to succeed quietly —
  # `true` says that outright instead of falling through to vk run's boot-info probe.
  lifetime_args=(--inactivity-timeout "$idle_secs" -- true)
  # Keep the source tree self-hosting across an upgrade: the vk already on PATH may predate
  # --inactivity-timeout, and it must still be able to compile the vk that introduces it.
  # Without the probe that vk fails on the unknown argument and the caller is sent chasing
  # the stuck-lock advice below. Delete this branch once the released vk carries the flag.
  if [[ $("$VK" run --help 2>&1 || true) != *"--inactivity-timeout"* ]]; then
    echo "dev.sh: the vk on PATH predates --inactivity-timeout, so this VM ignores" >&2
    echo "        VK_DEV_IDLE_SECS and lives until ./dev.sh stop; install a current vk" >&2
    echo "        (./build.sh --fast, then install dist/vk) to get the idle timeout" >&2
    lifetime_args=(-- sleep infinity)
  fi
  # Launch from the state dir so the VM's registry entry points there and not at the
  # repo: `vk list`/`vk stop` select by launch directory or below, so a bare `vk stop`
  # in the checkout would otherwise sweep up this VM along with build.sh's.
  #
  # fd 9 is closed for the child: --detach daemonizes with fork+setsid and inherits open
  # descriptors, so the VM would hold this lock for its whole lifetime — an flock lives on
  # the open file description, so our own close would not release it, and every later
  # dev.sh (./dev.sh stop included) would block on it.
  (
    cd "$STATE_DIR"
    "$VK" run \
      --file "$ROOT/.devcontainer/Dockerfile" \
      --context "$ROOT/.devcontainer" \
      --workdir "$ROOT" \
      --state-dir "$STATE_DIR" \
      --net --cpus "${VK_DEV_CPUS:-host}" --mem "${VK_DEV_MEM:-8G}" --detach \
      "${lifetime_args[@]}"
  ) 9>&- || {
    echo "dev.sh: the development VM did not start; if a previous one is stuck holding" >&2
    echo "        $STATE_DIR — or one just expired and has not let go yet — clear it" >&2
    echo "        with ./dev.sh stop and retry" >&2
    exit 1
  }
  printf '%s\n' "$image_stamp" >"$stamp_file"
fi
exec 9>&-

# -t keeps cargo's colour and progress rendering, and is what makes the shell usable at
# all; vk exec requires both local stdin and stdout to be terminals for it, which `shell`
# has already insisted on.
exec_args=(--user dev --dir /work)
if [ -t 0 ] && [ -t 1 ]; then
  exec_args+=(-t)
fi
for entry in "${DEV_ENV[@]}"; do exec_args+=(--env "$entry"); done
echo "dev.sh: $what in the development VM" >&2
exec "$VK" exec "$STATE_DIR" "${exec_args[@]}" -- "${guest_cmd[@]}"
