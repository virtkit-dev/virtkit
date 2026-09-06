#!/usr/bin/env bash
# dev.sh — fast, crate-scoped type checking, linting, formatting and targeted tests, plus
# an interactive shell in a shared vk development VM that shuts down when idle. The
# mold-linking RUSTFLAGS and shared target/ directory match every build.sh invocation,
# and the dev profile matches build.sh --fast, so dependency artifacts are reused
# between the two workflows. The VK_EMBED_* vars build.sh sets are deliberately absent
# here (they must name an already built agent), so vk-driver's own build script reruns
# when you alternate the two.
#
# Examples:
#   ./dev.sh check
#   ./dev.sh clippy
#   ./dev.sh fmt
#   ./dev.sh fmt --check
#   ./dev.sh test
#   ./dev.sh check -p vk-core
#   ./dev.sh clippy -p vk-driver --lib
#   ./dev.sh test -p vk-core dockerignore::tests
#   ./dev.sh test -p vk-core --lib dockerignore::tests
#   ./dev.sh test -p vk-core --test exec disconnect_kills_remote_process
#   ./dev.sh test -p vk-driver --bin vk atop_view::tests
#   ./dev.sh shell
#   ./dev.sh stop
#
# VK_DEV_CPUS / VK_DEV_MEM size the VM (default: host cpus, 8G). VK_DEV_IDLE_SECS sets how
# long it survives with no cargo command or open shell (default: 1800, 0 = until
# ./dev.sh stop).
#
# The VM boots with nested virtualization when the host allows it and the vk on PATH can ask
# for it, so `./dev.sh shell` can run vk inside vk — build and boot microVMs, not just
# compile them.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$PWD

usage() {
  cat >&2 <<'EOF'
usage: ./dev.sh check  [-p <package>] [cargo check arguments]
       ./dev.sh clippy [-p <package>] [cargo clippy arguments] [-- <lint flags>]
       ./dev.sh fmt    [-p <package>] [cargo fmt arguments] [-- <rustfmt flags>]
       ./dev.sh test   [-p <package>] [target] [test filter]
       ./dev.sh shell
       ./dev.sh stop

Bare `./dev.sh check`, `clippy` or `test` covers the whole workspace, every target, the
way CI does it — so nothing hides in a crate or a test file you did not think to name.
Narrow it when the change is small: `-p <package>` for one crate, and --lib, --bin NAME
or --test NAME (--doc and --example NAME also count) for one target, plus the changed
module or test name as a filter. `check` and `clippy` pass --all-targets unless you
select a target, which excludes doctests — `test` does not need it, since cargo already
runs every target and the doctests with it. Optimized profiles stay rejected: use
./build.sh when shipping. `clippy` is `check` with the lints CI gates on: it defaults to
`-- -D warnings`, so a warning fails the command as it would on a pull request, and your
own `--` flags replace that default. `fmt` uses the pinned toolchain's rustfmt to match
CI; a different host rustfmt may disagree. `--check` reports without writing. With no
`-p` or `--all`, it formats the whole workspace. `shell` opens an interactive shell in
the same VM under the cargo commands' own environment, and holds the VM for as long as
it runs; that VM nests where the host allows it and the vk on PATH can ask for it, so
the shell can boot vk's own microVMs rather than only compile them, keeping their images
and boot scratch on the guest's disk. The first command boots a vk development VM; by
default it powers off after 1800 seconds without a cargo command. Set VK_DEV_IDLE_SECS
to change the window, or to 0 to keep the VM until ./dev.sh stop.
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
  check | clippy | fmt | test)
    shift
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

# Reject optimized profiles; broad validation is the default, and ./build.sh produces
# shippable binaries.
has_target=""
# Only fmt uses this to preserve an explicit scope (`--all`, `-p`). The shared parser
# also recognizes scope flags that cargo fmt does not use.
has_scope=""

reject() {
  echo "dev.sh: $1" >&2
  exit 2
}
# cargo's `bench` profile inherits `release`, so both mean an optimized build.
check_profile() {
  case "$1" in
    release | bench) reject "the $1 profile is optimized and disabled here; use ./build.sh when shipping" ;;
  esac
}
# Insert before a bare `--` to pass the argument to Cargo, not the invoked program.
insert_cargo_arg() {
  local out=() arg spliced=""
  for arg in ${args[@]+"${args[@]}"}; do
    if [ -z "$spliced" ] && [ "$arg" = -- ]; then
      out+=("$1")
      spliced=1
    fi
    out+=("$arg")
  done
  [ -n "$spliced" ] || out+=("$1")
  args=("${out[@]}")
}

# Validate Cargo arguments and record whether the caller selected a target.
check_cargo_args() {
  local argv=("$@") i arg
  for ((i = 0; i < ${#argv[@]}; i++)); do
    arg=${argv[$i]}
    # After `--`, arguments belong to libtest or rustfmt, not Cargo. Libtest's
    # `--test` and `--lib` must not count as Cargo target selection.
    if [ "$arg" = -- ]; then
      break
    fi
    case "$arg" in
      -r | --release)
        reject "release builds are intentionally disabled; use ./build.sh when shipping"
        ;;
      --profile)
        [ $((i + 1)) -lt ${#argv[@]} ] || usage
        check_profile "${argv[$((i + 1))]}"
        ;;
      --profile=*) check_profile "${arg#--profile=}" ;;
      --lib | --doc | --bin | --bin=* | --test | --test=* | --example | --example=* | \
        --all-targets | --bins | --tests | --benches | --examples)
        has_target=1
        ;;
      # `-p?*` covers both the attached (`-pvk-core`) and the `=` (`-p=vk-core`) forms.
      --all | --workspace | -p | -p?* | --package | --package=*)
        has_scope=1
        ;;
    esac
  done
}
# `shell` takes no cargo arguments to vet; every other mode is a cargo invocation.
[ "$MODE" = shell ] || check_cargo_args ${args[@]+"${args[@]}"}

# Default check/clippy to --all-targets to include test code, and fmt to --all to match
# CI's workspace scope. Leave test alone: Cargo runs every target; --all-targets omits doctests.
case "$MODE" in
  check | clippy) [ -n "$has_target" ] || insert_cargo_arg --all-targets ;;
  # Insert before `--` to support both Cargo's `./dev.sh fmt --check` and
  # rustfmt's `./dev.sh fmt -- --check`.
  fmt) [ -n "$has_scope" ] || insert_cargo_arg --all ;;
esac

# Match CI's `-D warnings` default unless the caller provides lint flags after a bare
# `--`. The exact match avoids treating arguments that merely contain `--` as separators.
if [ "$MODE" = clippy ]; then
  has_lint_sep=""
  for arg in "${args[@]}"; do
    if [ "$arg" = -- ]; then
      has_lint_sep=1
      break
    fi
  done
  [ -n "$has_lint_sep" ] || args+=(-- -D warnings)
fi
# Checked on every invocation, not just the one that boots: a typo should surface before it
# has waited for the VM lock. `:-` already substituted for an empty value.
idle_secs=${VK_DEV_IDLE_SECS:-1800}
case "$idle_secs" in
  *[!0-9]*) reject "VK_DEV_IDLE_SECS must be a whole number of seconds (0 = no timeout)" ;;
esac

commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit (dirty)"
# What the cargo modes pass is byte-identical to build.sh's BUILD_ENV, mold-linking
# RUSTFLAGS included: any divergence changes the unit fingerprints and silently stops the
# two workflows from sharing target/. Change both together.
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
  # Not a login shell: a login shell would run the image's profile scripts, which can reset
  # the PATH that puts the toolchain (/opt/toolchain/bin) in front.
  guest_cmd=(/bin/sh)
  what="opening a shell"
  # A vk run from the shell keeps its image cache and boot scratch on the guest's own
  # disk. HOME=/tmp above (which vk would otherwise derive both from) is the tmpfs the
  # agent mounts, capped at half the guest's RAM — an image conversion fills it. Added
  # in this branch only, so cargo's environment stays byte-identical to build.sh's.
  DEV_ENV+=(XDG_DATA_HOME=/var/tmp/vk/share XDG_CACHE_HOME=/var/tmp/vk/cache)
else
  guest_cmd=(cargo "$MODE" ${args[@]+"${args[@]}"})
  what="running cargo $MODE"
fi

# Does the host let a guest run guests of its own? `vk run --nested` refuses when it does
# not, and that must not take the whole dev loop down with it.
host_nests() {
  local path
  for path in /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested; do
    case "$(cat "$path" 2>/dev/null)" in
      1 | Y | y) return 0 ;;
    esac
  done
  return 1
}
# vk inside vk: with --nested the VM gets VMX/SVM and so its own /dev/kvm, which is what
# lets `./dev.sh shell` build and boot microVMs (./dist/vk run …, ./build.sh) rather than
# only compile them. Probed rather than assumed: the vk on PATH may predate the flag, and
# it must still be able to compile the vk that introduces it.
run_help=$("$VK" run --help 2>&1 || true)
nested_args=()
if [[ $run_help == *"--nested"* ]] && host_nests; then
  nested_args=(--nested)
fi

# Reboot only when the build image's inputs, the toolchain its base tag tracks, or whether
# the VM nests, change — a resize (VK_DEV_CPUS/VK_DEV_MEM) deliberately waits for the next
# boot instead. rust-toolchain.toml is never COPYed into the image, but update.sh keeps
# the flake's inline channel in sync with it, and the guest toolchain follows it.
# Source and Cargo manifest edits are shared live at /work and never require a reboot.
# The boot shape is in the stamp so installing a vk that can nest restarts the VM instead
# of leaving the next shell without a /dev/kvm. It restarts on losing nesting too — the
# rule is "the shape changed", which is simpler than ranking the two directions.
image_inputs=$(sha256sum \
  .devcontainer/Dockerfile \
  .devcontainer/nix/flake.nix \
  .devcontainer/nix/flake.lock \
  rust-toolchain.toml | sha256sum | cut -d ' ' -f 1)
vm_stamp=$(printf '%s %s\n' "$image_inputs" "${nested_args[*]}" | sha256sum | cut -d ' ' -f 1)
stamp_file="$STATE_DIR/vm.stamp"
lock_state_dir
# Retire the pre-rename stamp: a state dir is reused and never removed, so image.stamp
# would otherwise sit beside vm.stamp forever. Delete this line once no dev VM predating
# the rename can still be around.
rm -f "$STATE_DIR/image.stamp"
agent_up=""
"$VK" status "$STATE_DIR" >/dev/null 2>&1 && agent_up=1
if [ -n "$agent_up" ] && [ "$(cat "$stamp_file" 2>/dev/null)" != "$vm_stamp" ]; then
  echo "dev.sh: development VM inputs changed; restarting it" >&2
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
  if [[ $run_help != *"--inactivity-timeout"* ]]; then
    echo "dev.sh: the vk on PATH predates --inactivity-timeout, so this VM ignores" >&2
    echo "        VK_DEV_IDLE_SECS and lives until ./dev.sh stop; install a current vk" >&2
    echo "        (./build.sh --fast, then install dist/vk) to get the idle timeout" >&2
    lifetime_args=(-- sleep infinity)
  fi
  # --workdir associates this VM with the checkout, so list, stop and reboot from the tree
  # include it like any other VM in the project.
  #
  # fd 9 is closed for the child: --detach daemonizes with fork+setsid and inherits open
  # descriptors, so the VM would hold this lock for its whole lifetime — an flock lives on
  # the open file description, so our own close would not release it, and every later
  # dev.sh (./dev.sh stop included) would block on it.
  "$VK" run \
    --file "$ROOT/.devcontainer/Dockerfile" \
    --context "$ROOT/.devcontainer" \
    --workdir "$ROOT" \
    --state-dir "$STATE_DIR" \
    --net --cpus "${VK_DEV_CPUS:-host}" --mem "${VK_DEV_MEM:-8G}" --detach \
    "${nested_args[@]}" "${lifetime_args[@]}" 9>&- || {
    echo "dev.sh: the development VM did not start; if a previous one is stuck holding" >&2
    echo "        $STATE_DIR — or one just expired and has not let go yet — clear it" >&2
    echo "        with ./dev.sh stop and retry" >&2
    exit 1
  }
  printf '%s\n' "$vm_stamp" >"$stamp_file"
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
