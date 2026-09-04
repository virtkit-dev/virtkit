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
# consumers fetch dist/vmlinux the same way they fetch vk-driver / vk-agent.
set -euo pipefail
cd "$(dirname "$0")"

OUT=dist
NOCACHE=""
FORCE_DOCKER=""
for arg in "$@"; do
  case "$arg" in
    --no-cache) NOCACHE="--no-cache" ;;
    --docker) FORCE_DOCKER=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"

# Backend: dogfood a `vk` on PATH (the same microVM builder build.sh uses) unless --docker
# forces Docker. Either way the kernel builds in the pinned Nix devcontainer, so the base +
# toolchain + flake-locked inputs are shared and reproducible.
if [ -z "$FORCE_DOCKER" ] && command -v vk >/dev/null 2>&1; then
  VK_BIN=$(command -v vk)
  echo "-- building the guest kernel (vmlinux) with vk from PATH ($VK_BIN) ..."
  # Merge the devcontainer + kernel Dockerfiles so kernel's `FROM virtkit-build` resolves
  # to the devcontainer stage (vk has no docker image tags; each -f keeps its own dir as
  # its COPY context). Build up to `build` (which compiles vmlinux), boot it with the repo
  # mounted at /work, and copy vmlinux into dist/ — the workspace model, no artifact-stage
  # extraction. (--no-cache is docker-only; vk's content-addressed cache rebuilds whenever
  # the pinned inputs change.)
  "$VK_BIN" run \
    -f .devcontainer/Dockerfile -f kernel/Dockerfile \
    --target build \
    --workdir "$PWD" --cpus host --mem 8G \
    -- cp /build/vmlinux "$OUT/vmlinux"
else
  export DOCKER_BUILDKIT=1
  # The kernel builds in the same image as the binaries (kernel/Dockerfile is
  # `FROM virtkit-build`, the pinned Nix devcontainer) — build it first so the base + rust
  # toolchain + flake-locked inputs are shared and reproducible.
  echo "-- building the build image (virtkit-build) ..."
  docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

  echo "-- building the guest kernel (vmlinux) ..."
  # the Dockerfile's `artifact` stage is just the vmlinux file; -o extracts it directly.
  # kernel's `FROM virtkit-build` refers to the image tagged just above.
  docker build ${NOCACHE:+$NOCACHE} --target artifact -o "type=local,dest=$OUT" kernel
fi

echo
echo "built $OUT/vmlinux"
file "$OUT/vmlinux" 2>/dev/null || true

# Reproducibility manifest for the kernel: the pinned inputs and the vmlinux hash.
# Kept in its own file (build.sh owns build-info.txt and rewrites it whole), so the two
# scripts stay run-order independent. Verify a fetched vmlinux against the same commit:
#   git checkout <git_commit> && ./build-kernel.sh && ( cd dist && sha256sum -c vmlinux.sha256 )
# The sidecar names vmlinux bare, so the check runs from inside dist/.
# The rev flake.lock pins for one input: the first "rev" inside that input's node.
lock_rev() {
  awk -v n="\"$1\": {" 'index($0, n) { f = 1 } f && /"rev":/ { gsub(/[",]/, "", $2); print $2; exit }' \
    .devcontainer/nix/flake.lock
}
base_image=$(sed -nE 's/^FROM ([^ ]+).*$/\1/p' .devcontainer/Dockerfile | head -1)
nix_pins="nixpkgs:         $(lock_rev nixpkgs)"
kernel_version=$(sed -nE 's/^ARG KERNEL_VERSION=(.*)$/\1/p' kernel/Dockerfile)
kernel_sha256=$(sed -nE 's/^ARG KERNEL_SHA256=(.*)$/\1/p' kernel/Dockerfile)
commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit (dirty)"

cd "$OUT"
sha256sum vmlinux > vmlinux.sha256
echo "recorded vmlinux in $OUT/vmlinux.sha256"

cat > kernel-build-info.txt <<EOF
# virtkit reproducible kernel build manifest
# Verify: git checkout <git_commit> && ./build-kernel.sh && ( cd dist && sha256sum -c vmlinux.sha256 )
git_commit:      ${commit}
kernel_version:  ${kernel_version}
kernel_sha256:   ${kernel_sha256}
base_image:      ${base_image}
${nix_pins}

$(cat vmlinux.sha256)
EOF

echo
cat kernel-build-info.txt
