#!/usr/bin/env bash
# Build the production static-musl binaries.
#
# Two backends produce the same artifact with the same toolchain:
#   - default: Docker — `docker build` the devcontainer image, then `docker run`
#     the compile in it.
#   - --use-virtkit=<DIST>: dogfood — use the virtkit binary in <DIST> to build the
#     devcontainer Dockerfile into a microVM and compile a shared checkout inside it
#     (DIST also supplies vmlinux + vk-agent; cloud-hypervisor comes from PATH,
#     or DIST/cloud-hypervisor if present). Set VK_CACHE=host:port to push/pull the
#     build image from a `vk registry serve` by its content key.
#
# Output goes to ./dist as stripped, static-pie musl ELF binaries. Both backends
# mount the repo at /work and pass identical flags, so the bytes match either way.
#
# --bootstrap-check: after the default Docker build, rebuild with the just-built virtkit
# (the dogfood backend, on a clean copy of the tree in a tmp dir) and assert the binaries
# are byte-for-byte identical — proof the microVM backend reproduces Docker, i.e. virtkit
# can rebuild itself. Needs dist/vmlinux (run ./build-kernel.sh first).
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=virtkit-build
TARGET=x86_64-unknown-linux-musl
OUT=dist

USE_VIRTKIT=""
BOOTSTRAP_CHECK=""
for arg in "$@"; do
  case "$arg" in
    --use-virtkit=*) USE_VIRTKIT="${arg#*=}" ;;
    --bootstrap-check) BOOTSTRAP_CHECK=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
if [ -n "$USE_VIRTKIT" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--bootstrap-check runs the Docker build first; it cannot be combined with --use-virtkit" >&2
  exit 2
fi

# Fail fast: check the dogfood-rebuild prerequisites up front, before the slow Docker build
# and compile — not three minutes later when the rebuild starts. The fresh virtkit +
# vk-agent come from the Docker build below; only the guest kernel and the VMM are
# external to it.
if [ -n "$BOOTSTRAP_CHECK" ]; then
  [ -e "$OUT/vmlinux" ] || {
    echo "--bootstrap-check needs $OUT/vmlinux (run ./build-kernel.sh first)" >&2
    exit 1
  }
  [ -x "$OUT/cloud-hypervisor" ] || command -v cloud-hypervisor >/dev/null || {
    echo "--bootstrap-check needs cloud-hypervisor (in PATH or at $OUT/cloud-hypervisor)" >&2
    exit 1
  }
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

if [ -n "$USE_VIRTKIT" ]; then
  # ---- dogfood backend: virtkit builds the env image + compiles in a microVM ----
  VK="$USE_VIRTKIT/vk"
  KERNEL="$USE_VIRTKIT/vmlinux"
  AGENT="$USE_VIRTKIT/vk-agent"
  for f in "$VK" "$KERNEL" "$AGENT"; do
    [ -e "$f" ] || { echo "missing $f (need a populated --use-virtkit dir)" >&2; exit 1; }
  done
  ch_args=()
  if [ -x "$USE_VIRTKIT/cloud-hypervisor" ]; then
    ch_args=(--cloud-hypervisor "$USE_VIRTKIT/cloud-hypervisor")
  elif ! command -v cloud-hypervisor >/dev/null; then
    echo "missing cloud-hypervisor (in PATH or at $USE_VIRTKIT/cloud-hypervisor)" >&2
    exit 1
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

  "$VK" run \
    --file .devcontainer/Dockerfile \
    --context .devcontainer \
    --workdir "$PWD" \
    --net \
    --kernel "$KERNEL" \
    --agent "$AGENT" \
    "${ch_args[@]}" \
    "${cache_args[@]}" \
    -- "${exports}cargo build --release --workspace"
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
    cargo build --release --workspace
fi

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
  # Rebuild with the virtkit we just produced (the dogfood backend) and confirm it
  # reproduces the Docker build bit-for-bit. The just-built $OUT is itself a valid
  # --use-virtkit toolchain (vk + vk-agent built above, vmlinux from
  # build-kernel.sh). The second build runs on a clean copy of the tree in a tmp dir —
  # a full independent compile, mounted at the same /work path so the container-side
  # paths (and thus the reproducible bytes) match the Docker build.
  echo
  echo "bootstrap check: rebuilding with the freshly built virtkit in a microVM…"
  boot_dist="$PWD/$OUT"
  boot_tmp=$(mktemp -d)
  trap 'rm -rf "$boot_tmp"' EXIT
  # Clean working-tree copy (no target/.git/dist) so the rebuild can't reuse this build's
  # target/ and is a genuine from-scratch compile.
  tar -c --exclude=./.git --exclude=./target --exclude="./$OUT" . | tar -x -C "$boot_tmp"
  ( cd "$boot_tmp" && ./build.sh --use-virtkit="$boot_dist" )

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
    echo "bootstrap check FAILED: the virtkit backend did not reproduce the Docker build" >&2
    exit 1
  fi
  echo "bootstrap check passed: Docker and virtkit backends produce identical binaries"
fi
