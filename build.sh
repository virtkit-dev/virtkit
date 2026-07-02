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
VMM=libkrun          # dogfood VMM backend: libkrun (default) or cloud-hypervisor
for arg in "$@"; do
  case "$arg" in
    --use-virtkit=*) USE_VIRTKIT="${arg#*=}" ;;
    --bootstrap-check) BOOTSTRAP_CHECK=1 ;;
    --vmm=libkrun|--vmm=cloud-hypervisor) VMM="${arg#*=}" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
if [ -n "$USE_VIRTKIT" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--bootstrap-check runs the Docker build first; it cannot be combined with --use-virtkit" >&2
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
BUILD_ENV=(
  HOME=/tmp
  CARGO_HOME=/work/target/.cargo-home
  CARGO_TARGET_DIR=/work/target
  SOURCE_DATE_EPOCH=0
  "RUSTFLAGS=--remap-path-prefix=/work=/src --remap-path-prefix=/work/target/.cargo-home=/cargo"
  "CFLAGS_x86_64_unknown_linux_musl=-ffile-prefix-map=/work=/src -ffile-prefix-map=/work/target/.cargo-home=/cargo"
  LIBSECCOMP_LINK_TYPE=static
  LIBSECCOMP_LIB_PATH=/usr/lib
  LIBCAPNG_LINK_TYPE=static
  LIBCAPNG_LIB_PATH=/usr/lib
)

# `vk` embeds the guest kernel and vk-agent, so the compile is two phases: build
# vk-agent first, then build vk with VK_EMBED_* pointing at that agent and the
# pinned vmlinux (both under /work, where the repo is mounted in either backend).
# The kernel is optional here — without dist/vmlinux, vk builds without an embedded
# kernel (it then needs --kernel at runtime); the release always has it.
EMBED_ENV="VK_EMBED_AGENT=/work/target/$TARGET/release/vk-agent"
if [ -e "$OUT/vmlinux" ]; then
  EMBED_ENV="$EMBED_ENV VK_EMBED_KERNEL=/work/$OUT/vmlinux"
else
  echo "warning: $OUT/vmlinux not found — building vk without an embedded kernel (run ./build-kernel.sh first)" >&2
fi
BUILD_CMD="cargo build --release -p vk-agent && env $EMBED_ENV cargo build --release -p vk-driver"

compile_start=$SECONDS
if [ -n "$USE_VIRTKIT" ]; then
  # ---- dogfood backend: vk builds the env image + compiles in a microVM ----
  # vk is self-contained (embedded kernel + agent), so DIST needs only the vk binary.
  VK="$USE_VIRTKIT/vk"
  [ -e "$VK" ] || { echo "missing $VK (need a populated --use-virtkit dir)" >&2; exit 1; }

  # VMM backend: built-in libkrun by default (no external binary); cloud-hypervisor for
  # a comparison run needs the CH binary and VIRTKIT_VMM set.
  vmm_env=()
  ch_args=()
  if [ "$VMM" = cloud-hypervisor ]; then
    if [ -x "$USE_VIRTKIT/cloud-hypervisor" ]; then ch="$USE_VIRTKIT/cloud-hypervisor"
    elif command -v cloud-hypervisor >/dev/null; then ch=$(command -v cloud-hypervisor)
    else
      echo "--vmm=cloud-hypervisor needs cloud-hypervisor (in PATH or at $USE_VIRTKIT/cloud-hypervisor)" >&2
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
since "compile ($([ -n "$USE_VIRTKIT" ] && echo "$VMM microVM" || echo docker))" "$compile_start"

mkdir -p "$OUT"
# Replace atomically (write a temp, then rename): a plain cp truncates the destination and
# would fail "Text file busy" if the old $OUT/vk is still being executed (e.g. by a
# previous --use-virtkit / --bootstrap-check run); rename never does.
for b in vk vk-agent; do
  cp "target/$TARGET/release/$b" "$OUT/.$b.tmp"
  mv -f "$OUT/.$b.tmp" "$OUT/$b"
done

# Reproducibility manifest: the pinned inputs and the artifact hashes. Anyone can
# rebuild from the same commit + inputs and confirm byte-for-byte:
#   git checkout <git_commit> && ./build.sh && sha256sum -c dist/vk.sha256 dist/vk-agent.sha256
( cd "$OUT" && sha256sum vk > vk.sha256 && sha256sum vk-agent > vk-agent.sha256 )
base_image=$(sed -nE 's/^FROM (rust:.*)$/\1/p' .devcontainer/Dockerfile)
toolchain=$(sed -nE 's/^channel = "(.*)"$/\1/p' rust-toolchain.toml)
commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit (dirty)"
cat > "$OUT/build-info.txt" <<EOF
# virtkit reproducible build manifest
# Verify: git checkout <git_commit> && ./build.sh && sha256sum -c dist/vk.sha256 dist/vk-agent.sha256
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
  # Same VMM choice as requested.
  ( cd "$boot_tmp" && ./build.sh --use-virtkit="$boot_dist" --vmm="$VMM" )
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
