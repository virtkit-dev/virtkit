#!/usr/bin/env bash
# build-kernel.sh — build the microVM guest kernel (vmlinux) into ./dist.
#
# The guest kernel is vanilla Linux + a vendored config (kernel/kernel-fragment.config:
# virtio blk/net/vsock/pci + ext4 + virtio-fs/FUSE + IP autoconfig, all built in, no
# modules) — the pinned kernel every microVM guest boots. Built in a docker container
# (the kernel version + sha are pinned in kernel/Dockerfile), extracted as a bare file.
#
# Kept separate from build.sh (the Rust artifacts): the kernel changes rarely, so it is
# rebuilt only on a pin bump. The docker layer cache makes an unchanged rerun a no-op;
# --no-cache forces a clean rebuild. Output joins ./dist next to the binaries, so
# consumers fetch dist/vmlinux the same way they fetch virtkit / virtkit-agent.
set -euo pipefail
cd "$(dirname "$0")"

OUT=dist
NOCACHE=""
[ "${1:-}" = "--no-cache" ] && NOCACHE="--no-cache"
export DOCKER_BUILDKIT=1
mkdir -p "$OUT"

# The kernel builds in the same image as the binaries (kernel/Dockerfile is
# `FROM virtkit-build`, the pinned rust:alpine devcontainer) — build it first so the
# base + rust toolchain + frozen apt/apk inputs are shared and reproducible.
echo "-- building the build image (virtkit-build) ..."
docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

echo "-- building the guest kernel (vmlinux) ..."
# the Dockerfile's `artifact` stage is just the vmlinux file; -o extracts it directly.
docker build ${NOCACHE:+$NOCACHE} --target artifact -o "type=local,dest=$OUT" kernel

echo
echo "built $OUT/vmlinux"
file "$OUT/vmlinux" 2>/dev/null || true

# Reproducibility manifest for the kernel: the pinned inputs and the vmlinux hash.
# Kept in its own file (build.sh owns build-info.txt and rewrites it whole), so the two
# scripts stay run-order independent. Verify a fetched vmlinux against the same commit:
#   git checkout <git_commit> && ./build-kernel.sh && sha256sum -c dist/vmlinux.sha256
base_image=$(sed -nE 's/^FROM (rust:.*)$/\1/p' .devcontainer/Dockerfile)
kernel_version=$(sed -nE 's/^ARG KERNEL_VERSION=(.*)$/\1/p' kernel/Dockerfile)
kernel_sha256=$(sed -nE 's/^ARG KERNEL_SHA256=(.*)$/\1/p' kernel/Dockerfile)
commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit (dirty)"

cd "$OUT"
sha256sum vmlinux > vmlinux.sha256
echo "recorded vmlinux in $OUT/vmlinux.sha256"

cat > kernel-build-info.txt <<EOF
# virtkit reproducible kernel build manifest
# Verify: git checkout <git_commit> && ./build-kernel.sh && sha256sum -c dist/vmlinux.sha256
git_commit:      ${commit}
kernel_version:  ${kernel_version}
kernel_sha256:   ${kernel_sha256}
base_image:      ${base_image}

$(cat vmlinux.sha256)
EOF

echo
cat kernel-build-info.txt
