#!/usr/bin/env bash
# Build the production static-musl binaries.
#
# Two backends produce the same artifact with the same toolchain:
#   - default: Docker — `docker build` the devcontainer image, then `docker run`
#     the compile in it.
#   - --use-virtkit=<DIST>: dogfood — use the vk binary in <DIST> to build the
#     devcontainer Dockerfile into a microVM and compile a shared checkout inside it.
#     vk embeds the kernel + agent and boots on its built-in libkrun, so DIST needs
#     only the vk binary. Set VK_CACHE=host:port to push/pull the build image from a
#     `vk registry serve` by its content key.
#
# Output goes to ./dist as stripped, static-pie musl ELF binaries. Both backends
# mount the repo at /work and pass identical flags, so the bytes match either way.
#
# --bootstrap-check: after the default Docker build, rebuild with the just-built vk
# (the dogfood backend, on a clean copy of the tree in a tmp dir) and assert the binaries
# are byte-for-byte identical — proof the microVM backend reproduces Docker, i.e. vk
# can rebuild itself. Needs dist/vmlinux (run ./build-kernel.sh first).
#
# --vmm=libkrun|cloud-hypervisor: VMM for the dogfood/bootstrap microVM (default:
# vk's built-in libkrun; cloud-hypervisor needs the external binary).
#
# --fast (alias --debug): build the debug cargo profile instead of release — a much
# faster compile for iteration, still static-musl and still embedding the kernel/agent,
# but unoptimized + unstripped and NOT reproducible, so not a release artifact (cannot
# combine with --bootstrap-check). Also links with mold and trims debuginfo to line
# tables to cut the edit-rebuild loop further; both are --fast-only and never touch the
# release build.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=virtkit-build
TARGET=x86_64-unknown-linux-musl
OUT=dist

# Wall-clock timings, printed to stderr (informational only — never written to
# build-info.txt, which must stay reproducible). Bash `SECONDS` counts whole seconds
# since the script started; `since` reports the delta from a captured value.
fmt_dur() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }
since()   { echo "build.sh: $1 in $(fmt_dur $(($SECONDS - $2)))" >&2; }

USE_VIRTKIT=""
BOOTSTRAP_CHECK=""
FORCE_DOCKER=""
FAST=""              # --fast/--debug: build the debug profile (much faster to compile,
                     # unoptimized + unstripped) for iteration — NOT a release artifact
VMM=libkrun          # dogfood VMM backend: libkrun (default) or cloud-hypervisor
for arg in "$@"; do
  case "$arg" in
    --use-virtkit=*) USE_VIRTKIT="${arg#*=}" ;;
    --bootstrap-check) BOOTSTRAP_CHECK=1 ;;
    --docker) FORCE_DOCKER=1 ;;
    --fast|--debug) FAST=1 ;;
    --vmm=libkrun|--vmm=cloud-hypervisor) VMM="${arg#*=}" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
# The debug profile is unoptimized and unstripped, so its bytes are neither the release
# artifact nor reproducible — it cannot back the reproducibility check.
if [ -n "$FAST" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--fast builds the debug profile; it cannot be combined with --bootstrap-check" >&2
  exit 2
fi
# Cargo profile flag + its target/ subdir, threaded through the embed env, build command,
# and artifact copy below so --fast changes all three consistently.
CARGO_PROFILE_FLAG="--release"; PROFILE_DIR=release
[ -n "$FAST" ] && { CARGO_PROFILE_FLAG=""; PROFILE_DIR=debug; }
if [ -n "$USE_VIRTKIT" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--bootstrap-check runs the Docker build first; it cannot be combined with --use-virtkit" >&2
  exit 2
fi
if [ -n "$FORCE_DOCKER" ] && [ -n "$USE_VIRTKIT" ]; then
  echo "--docker cannot be combined with --use-virtkit" >&2
  exit 2
fi

# Backend: an explicit --use-virtkit dir wins; otherwise dogfood a `vk` on PATH when there
# is one — unless --docker forces Docker, or this is the --bootstrap-check baseline (which
# must be the Docker build the vk rebuild compares against). Else Docker.
VK_BIN=""
if [ -n "$USE_VIRTKIT" ]; then
  VK_BIN="$USE_VIRTKIT/vk"
elif [ -z "$FORCE_DOCKER" ] && [ -z "$BOOTSTRAP_CHECK" ] && command -v vk >/dev/null 2>&1; then
  VK_BIN=$(command -v vk)
  echo "build.sh: building with vk from PATH ($VK_BIN); pass --docker to force the Docker backend" >&2
fi

if [ "$VMM" != libkrun ] && [ -z "$VK_BIN" ] && [ -z "$BOOTSTRAP_CHECK" ]; then
  echo "--vmm applies only to the vk backend (--use-virtkit, a vk on PATH, or --bootstrap-check)" >&2
  exit 2
fi

# Fail fast: check the dogfood-rebuild prerequisite up front, before the slow Docker
# build and compile. The fresh vk comes from the Docker build below with the guest
# kernel embedded and boots on its built-in libkrun — so the rebuild needs only
# dist/vmlinux (to embed into the vk it produces), no external VMM.
if [ -n "$BOOTSTRAP_CHECK" ]; then
  [ -e "$OUT/vmlinux" ] || {
    echo "--bootstrap-check needs $OUT/vmlinux (run ./build-kernel.sh first)" >&2
    exit 1
  }
  if [ "$VMM" = cloud-hypervisor ]; then
    [ -x "$OUT/cloud-hypervisor" ] || command -v cloud-hypervisor >/dev/null || {
      echo "--bootstrap-check --vmm=cloud-hypervisor needs cloud-hypervisor (in PATH or at $OUT/cloud-hypervisor)" >&2
      exit 1
    }
  fi
fi

# Reproducibility: SOURCE_DATE_EPOCH neutralises any build timestamp, and the build
# dir and cargo home are remapped to stable virtual prefixes (/src, /cargo) so the
# binary is independent of where it was built — this script and a teammate's checkout
# produce identical bytes. The repo is always mounted at /work, so these /work-relative
# values hold for both backends. Stripping is done by the release profile, not the host
# strip.
RUSTFLAGS_VAL="--remap-path-prefix=/work=/src --remap-path-prefix=/work/target/.cargo-home=/cargo"
# --fast: link with mold (in the build image via apk-pins.txt) instead of the default
# linker — the link step dominates an incremental rebuild, so this is the biggest win.
# Gated to --fast, so the reproducible release link is untouched.
[ -n "$FAST" ] && RUSTFLAGS_VAL="$RUSTFLAGS_VAL -C link-arg=-fuse-ld=mold"
# Resolve the source commit on the host and thread it into the compile as VK_GIT_COMMIT,
# so `vk --version` and dist/build-info.txt report the same value. The build sandbox can't
# reliably run git itself (the dogfood guest runs as root against a host-owned /work, which
# trips git's dubious-ownership check), so its `git rev-parse` fallback yields "unknown".
# VK_GIT_COMMIT lets a caller supply the commit — the --bootstrap-check rebuild runs in a
# tree copy with no .git, so it inherits the outer build's commit.
if [ -z "${VK_GIT_COMMIT:-}" ]; then
  VK_GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
  [ -n "$(git status --porcelain 2>/dev/null)" ] && VK_GIT_COMMIT="$VK_GIT_COMMIT (dirty)"
fi
commit="$VK_GIT_COMMIT"
BUILD_ENV=(
  HOME=/tmp
  CARGO_HOME=/work/target/.cargo-home
  CARGO_TARGET_DIR=/work/target
  SOURCE_DATE_EPOCH=0
  "RUSTFLAGS=$RUSTFLAGS_VAL"
  "CFLAGS_x86_64_unknown_linux_musl=-ffile-prefix-map=/work=/src -ffile-prefix-map=/work/target/.cargo-home=/cargo"
  "VK_GIT_COMMIT=$commit"
)
# --fast: trim the dev profile's debuginfo to line tables — keeps file:line in panics/
# backtraces but drops the bulky per-variable/type DWARF, so codegen and every relink are
# faster. Overridden via the env so it stays --fast-only and needs no [profile.dev] in
# Cargo.toml (which would slow a plain `cargo build` too).
if [ -n "$FAST" ]; then
  BUILD_ENV+=(CARGO_PROFILE_DEV_DEBUG=line-tables-only)
fi

# `vk` embeds the guest kernel and vk-agent, so the compile is two phases: build
# vk-agent first, then build vk with VK_EMBED_* pointing at that agent and the
# pinned vmlinux (both under /work, where the repo is mounted in either backend).
# The kernel is optional here — without dist/vmlinux, vk builds without an embedded
# kernel (it then needs --kernel at runtime); the release always has it.
EMBED_ENV="VK_EMBED_AGENT=/work/target/$TARGET/$PROFILE_DIR/vk-agent"
if [ -e "$OUT/vmlinux" ]; then
  EMBED_ENV="$EMBED_ENV VK_EMBED_KERNEL=/work/$OUT/vmlinux"
else
  echo "warning: $OUT/vmlinux not found — building vk without an embedded kernel (run ./build-kernel.sh first)" >&2
fi
# vk-registry (the standalone central server) and vk-runnerctl (the root-side setter for
# gitlab-runner's concurrent) embed nothing, so they build plainly (no EMBED_ENV) alongside vk.
BUILD_CMD="cargo build $CARGO_PROFILE_FLAG -p vk-agent && env $EMBED_ENV cargo build $CARGO_PROFILE_FLAG -p vk-driver && cargo build $CARGO_PROFILE_FLAG -p vk-registry && cargo build $CARGO_PROFILE_FLAG -p vk-runnerctl"

compile_start=$SECONDS
if [ -n "$VK_BIN" ]; then
  # ---- dogfood backend: vk builds the env image + compiles in a microVM ----
  # vk is self-contained (embedded kernel + agent), so it needs no external base.
  VK="$VK_BIN"
  [ -e "$VK" ] || { echo "missing vk at $VK" >&2; exit 1; }

  # VMM backend: built-in libkrun by default (no external binary); cloud-hypervisor for
  # a comparison run needs the CH binary and VIRTKIT_VMM set.
  vmm_env=()
  ch_args=()
  if [ "$VMM" = cloud-hypervisor ]; then
    if [ -n "$USE_VIRTKIT" ] && [ -x "$USE_VIRTKIT/cloud-hypervisor" ]; then ch="$USE_VIRTKIT/cloud-hypervisor"
    elif command -v cloud-hypervisor >/dev/null; then ch=$(command -v cloud-hypervisor)
    else
      echo "--vmm=cloud-hypervisor needs cloud-hypervisor (in PATH${USE_VIRTKIT:+ or at $USE_VIRTKIT/cloud-hypervisor})" >&2
      exit 1
    fi
    vmm_env+=(VIRTKIT_VMM=cloud-hypervisor)
    ch_args=(--cloud-hypervisor "$ch")
  fi

  cache_args=()
  [ -n "${VK_CACHE:-}" ] && cache_args=(--cache-registry "$VK_CACHE")

  # The guest command runs under `sh -c` in /work (the shared checkout); export the
  # build env there, then compile. Build the env image from .devcontainer/Dockerfile
  # (its RUN steps get egress for apk); --net gives the compile egress for cargo.
  exports=""
  for e in "${BUILD_ENV[@]}"; do
    v="${e#*=}"; v="${v//\'/\'\\\'\'}"   # escape embedded single quotes for the sh -c body
    exports+="export ${e%%=*}='$v'; "
  done

  # A release compile of the whole workspace is CPU- and memory-hungry, so size the
  # build VM for it: all the host's CPUs (--cpus host) for parallelism, and enough
  # RAM that rustc is not OOM-killed (the `run` defaults are 2 cpus / 1G).
  env "${vmm_env[@]}" "$VK" run \
    --file .devcontainer/Dockerfile \
    --context .devcontainer \
    --workdir "$PWD" \
    --net \
    --cpus host \
    --mem 8G \
    "${ch_args[@]}" \
    "${cache_args[@]}" \
    -- "${exports}${BUILD_CMD}"
else
  # ---- default backend: Docker ----
  docker build -t "$IMAGE" -f .devcontainer/Dockerfile .devcontainer

  # Build as the host user so target/ and the cargo cache stay writable and no
  # root-owned files leak onto the host. RUSTUP_HOME is read-only here — the
  # pinned toolchain is already baked into the image.
  docker_env=()
  for e in "${BUILD_ENV[@]}"; do docker_env+=(-e "$e"); done
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    "${docker_env[@]}" \
    -v "$PWD":/work -w /work \
    "$IMAGE" \
    sh -c "$BUILD_CMD"
fi
since "compile ($([ -n "$VK_BIN" ] && echo "$VMM microVM" || echo docker))" "$compile_start"

mkdir -p "$OUT"
# Replace atomically (write a temp, then rename): a plain cp truncates the destination and
# would fail "Text file busy" if the old $OUT/vk is still being executed (e.g. by a
# previous --use-virtkit / --bootstrap-check run); rename never does.
for b in vk vk-agent vk-registry vk-runnerctl; do
  cp "target/$TARGET/$PROFILE_DIR/$b" "$OUT/.$b.tmp"
  mv -f "$OUT/.$b.tmp" "$OUT/$b"
done

# Reproducibility manifest: the pinned inputs and the artifact hashes. Anyone can
# rebuild from the same commit + inputs and confirm byte-for-byte:
#   git checkout <git_commit> && ./build.sh && sha256sum -c dist/vk.sha256 dist/vk-agent.sha256 \
#                                                              dist/vk-registry.sha256 dist/vk-runnerctl.sha256
( cd "$OUT" && sha256sum vk > vk.sha256 && sha256sum vk-agent > vk-agent.sha256 && sha256sum vk-registry > vk-registry.sha256 && sha256sum vk-runnerctl > vk-runnerctl.sha256 )
base_image=$(sed -nE 's/^FROM (rust:[^ ]*).*$/\1/p' .devcontainer/Dockerfile)
toolchain=$(sed -nE 's/^channel = "(.*)"$/\1/p' rust-toolchain.toml)
# $commit was resolved above (before the compile) and threaded into the build as
# VK_GIT_COMMIT, so the embedded `vk --version` stamp and this manifest agree.
# --fast produces the debug profile: unoptimized, unstripped, not reproducible. Stamp the
# manifest so its hashes are never mistaken for a release artifact — the release "Verify"
# recipe would rebuild the release profile and fail sha256sum -c against these debug bytes.
if [ -n "$FAST" ]; then
  manifest_header="# virtkit DEBUG build manifest (--fast) — NOT reproducible, not a release artifact
profile:         debug"
else
  manifest_header="# virtkit reproducible build manifest
# Verify: git checkout <git_commit> && ./build.sh && sha256sum -c dist/vk.sha256 dist/vk-agent.sha256 dist/vk-registry.sha256 dist/vk-runnerctl.sha256
profile:         release"
fi
cat > "$OUT/build-info.txt" <<EOF
${manifest_header}
git_commit:      ${commit}
rust_toolchain:  ${toolchain}
base_image:      ${base_image}

$(cat "$OUT/vk.sha256")
$(cat "$OUT/vk-agent.sha256")
EOF

echo
echo "built into $OUT/:"
file "$OUT/vk" "$OUT/vk-agent"
echo
cat "$OUT/build-info.txt"

if [ -n "$BOOTSTRAP_CHECK" ]; then
  # Rebuild with the vk we just produced (the dogfood backend) and confirm it
  # reproduces the Docker build bit-for-bit. The just-built $OUT is itself a valid
  # --use-virtkit toolchain (the self-contained vk built above). The second build runs
  # on a clean copy of the tree in a tmp dir — a full independent compile, mounted at
  # the same /work path so the container-side paths (and thus the reproducible bytes)
  # match the Docker build.
  echo
  echo "bootstrap check: rebuilding with the freshly built vk in a microVM…"
  boot_dist="$PWD/$OUT"
  boot_tmp=$(mktemp -d)
  trap 'rm -rf "$boot_tmp"' EXIT
  # Clean working-tree copy (no target/.git/dist) so the rebuild can't reuse this build's
  # target/ and is a genuine from-scratch compile.
  tar -c --exclude=./.git --exclude=./target --exclude="./$OUT" . | tar -x -C "$boot_tmp"
  # `vk` embeds the kernel, so the rebuild must see the same vmlinux at dist/vmlinux
  # (the tree copy above excludes dist/); without it the two vk binaries would differ.
  mkdir -p "$boot_tmp/$OUT"
  cp "$boot_dist/vmlinux" "$boot_tmp/$OUT/vmlinux"
  rebuild_start=$SECONDS
  # Same VMM choice as requested, and the commit threaded in (the copy has no .git).
  ( cd "$boot_tmp" && VK_GIT_COMMIT="$commit" ./build.sh \
      --use-virtkit="$boot_dist" --vmm="$VMM" )
  since "bootstrap rebuild" "$rebuild_start"

  echo
  echo "bootstrap check: comparing sha256…"
  mismatch=""
  for b in vk vk-agent; do
    docker_sha=$(sha256sum < "$OUT/$b" | cut -d' ' -f1)
    virtkit_sha=$(sha256sum < "$boot_tmp/$OUT/$b" | cut -d' ' -f1)
    if [ "$docker_sha" = "$virtkit_sha" ]; then
      echo "  $b: OK      $docker_sha"
    else
      echo "  $b: DIFFER  docker=$docker_sha  virtkit=$virtkit_sha" >&2
      mismatch=1
    fi
  done
  if [ -n "$mismatch" ]; then
    echo "bootstrap check FAILED: the vk backend did not reproduce the Docker build" >&2
    exit 1
  fi
  echo "bootstrap check passed: Docker and vk backends produce identical binaries"
fi

since "total" 0
