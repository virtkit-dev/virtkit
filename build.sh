#!/usr/bin/env bash
# Build the production static-musl binaries.
#
# Two backends produce the same artifact with the same toolchain:
#   - default: Docker — `docker build` the devcontainer image, then `docker run`
#     the compile in it.
#   - --use-virtkit=<DIST>: dogfood — use the virtkit binary in <DIST> to build the
#     devcontainer Dockerfile into a microVM and compile a shared checkout inside it
#     (DIST also supplies vmlinux + virtkit-agent; cloud-hypervisor comes from PATH,
#     or DIST/cloud-hypervisor if present). Set VK_CACHE=host:port to push/pull the
#     build image from a `virtkit registry serve` by its content key.
#
# Output goes to ./dist as stripped, static-pie musl ELF binaries. Both backends
# mount the repo at /work and pass identical flags, so the bytes match either way.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=virtkit-build
TARGET=x86_64-unknown-linux-musl
OUT=dist

USE_VIRTKIT=""
for arg in "$@"; do
  case "$arg" in
    --use-virtkit=*) USE_VIRTKIT="${arg#*=}" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

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
  VK="$USE_VIRTKIT/virtkit"
  KERNEL="$USE_VIRTKIT/vmlinux"
  AGENT="$USE_VIRTKIT/virtkit-agent"
  for f in "$VK" "$KERNEL" "$AGENT"; do
    [ -e "$f" ] || { echo "missing $f (need a populated --use-virtkit dir)" >&2; exit 1; }
  done
  ch_args=()
  [ -x "$USE_VIRTKIT/cloud-hypervisor" ] && ch_args=(--cloud-hypervisor "$USE_VIRTKIT/cloud-hypervisor")
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
# would fail "Text file busy" if the old $OUT/virtkit is still being executed (e.g. by a
# previous --use-virtkit / --bootstrap-check run); rename never does.
for b in virtkit virtkit-agent; do
  cp "target/$TARGET/release/$b" "$OUT/.$b.tmp"
  mv -f "$OUT/.$b.tmp" "$OUT/$b"
done

# Reproducibility manifest: the pinned inputs and the artifact hashes. Anyone can
# rebuild from the same commit + inputs and confirm byte-for-byte:
#   git checkout <git_commit> && ./build.sh && sha256sum -c dist/virtkit.sha256 dist/virtkit-agent.sha256
( cd "$OUT" && sha256sum virtkit > virtkit.sha256 && sha256sum virtkit-agent > virtkit-agent.sha256 )
base_image=$(sed -nE 's/^FROM (rust:.*)$/\1/p' .devcontainer/Dockerfile)
toolchain=$(sed -nE 's/^channel = "(.*)"$/\1/p' rust-toolchain.toml)
commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit (dirty)"
cat > "$OUT/build-info.txt" <<EOF
# virtkit reproducible build manifest
# Verify: git checkout <git_commit> && ./build.sh && sha256sum -c dist/virtkit.sha256 dist/virtkit-agent.sha256
git_commit:      ${commit}
rust_toolchain:  ${toolchain}
base_image:      ${base_image}

$(cat "$OUT/virtkit.sha256")
$(cat "$OUT/virtkit-agent.sha256")
EOF

echo
echo "built into $OUT/:"
file "$OUT/virtkit" "$OUT/virtkit-agent"
echo
cat "$OUT/build-info.txt"
