#!/usr/bin/env bash
# Build the production static-musl binaries inside Docker.
#
# Uses the devcontainer image (pinned Rust + musl toolchain) so the release
# artifacts are produced with the exact toolchain we develop against. Output is
# written to ./dist as stripped, static-pie musl ELF binaries.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=virtkit-build
TARGET=x86_64-unknown-linux-musl
OUT=dist

docker build -t "$IMAGE" -f .devcontainer/Dockerfile .devcontainer

# Build as the host user so target/ and the cargo cache stay writable and no
# root-owned files leak onto the host. RUSTUP_HOME is read-only here — the
# pinned toolchain is already baked into the image.
#
# Reproducibility: SOURCE_DATE_EPOCH neutralises any build timestamp, and the
# build dir and cargo home are remapped to stable virtual prefixes (/src, /cargo)
# so the binary is independent of where it was built — this script and a
# teammate's checkout produce identical bytes. Stripping is done by the release
# profile, not the host strip.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/work/target/.cargo-home \
  -e CARGO_TARGET_DIR=/work/target \
  -e SOURCE_DATE_EPOCH=0 \
  -e RUSTFLAGS="--remap-path-prefix=/work=/src --remap-path-prefix=/work/target/.cargo-home=/cargo" \
  -e CFLAGS_x86_64_unknown_linux_musl="-ffile-prefix-map=/work=/src -ffile-prefix-map=/work/target/.cargo-home=/cargo" \
  -e LIBSECCOMP_LINK_TYPE=static -e LIBSECCOMP_LIB_PATH=/usr/lib \
  -e LIBCAPNG_LINK_TYPE=static -e LIBCAPNG_LIB_PATH=/usr/lib \
  -v "$PWD":/work -w /work \
  "$IMAGE" \
  cargo build --release --workspace

mkdir -p "$OUT"
cp "target/$TARGET/release/virtkit" "target/$TARGET/release/virtkit-agent" "$OUT/"

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
