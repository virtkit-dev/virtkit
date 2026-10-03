#!/usr/bin/env bash
# build-firmware.sh — build the UEFI firmware (CLOUDHV.fd) a Windows guest boots into ./dist.
#
# edk2's OvmfPkg/CloudHv platform, from nixpkgs at the rev the devcontainer's flake.lock pins
# (firmware/Dockerfile). Separate from build.sh, like build-kernel.sh: the firmware changes
# only on a lock bump. --no-cache forces a clean Docker rebuild.
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

if [ -z "$FORCE_DOCKER" ] && command -v vk >/dev/null 2>&1; then
  VK_BIN=$(command -v vk)
  echo "-- building the UEFI firmware (CLOUDHV.fd) with vk from PATH ($VK_BIN) ..."
  # Same merge as build-kernel.sh: firmware's `FROM virtkit-build` resolves to the
  # devcontainer stage. --no-cache is docker-only in both scripts.
  "$VK_BIN" run \
    -f .devcontainer/Dockerfile -f firmware/Dockerfile \
    --target build \
    --workdir "$PWD" --cpus host --mem 4G \
    -- cp /build/CLOUDHV.fd /build/CLOUDHV.fd.storepath "$OUT/"
else
  export DOCKER_BUILDKIT=1
  echo "-- building the build image (virtkit-build) ..."
  docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer
  echo "-- building the UEFI firmware (CLOUDHV.fd) ..."
  docker build ${NOCACHE:+$NOCACHE} --target artifact -o "type=local,dest=$OUT" firmware
fi
store_path=$(cat "$OUT/CLOUDHV.fd.storepath")
rm "$OUT/CLOUDHV.fd.storepath"

echo
echo "built $OUT/CLOUDHV.fd"
file "$OUT/CLOUDHV.fd" 2>/dev/null || true

# Reproducibility manifest, like build-kernel.sh's. The sidecar names the file bare, so the
# check runs from inside dist/:
#   git checkout <git_commit> && ./build-firmware.sh && ( cd dist && sha256sum -c CLOUDHV.fd.sha256 )
# The rev flake.lock pins for one input: the first "rev" inside that input's node.
lock_rev() {
  awk -v n="\"$1\": {" 'index($0, n) { f = 1 } f && /"rev":/ { gsub(/[",]/, "", $2); print $2; exit }' \
    .devcontainer/nix/flake.lock
}
base_image=$(sed -nE 's/^FROM ([^ ]+).*$/\1/p' .devcontainer/Dockerfile | head -1)
nixpkgs_rev=$(lock_rev nixpkgs)
commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit (dirty)"

cd "$OUT"
sha256sum CLOUDHV.fd > CLOUDHV.fd.sha256
echo "recorded CLOUDHV.fd in $OUT/CLOUDHV.fd.sha256"

cat > firmware-build-info.txt <<EOF
# virtkit UEFI firmware build manifest
# Verify: git checkout <git_commit> && ./build-firmware.sh && ( cd dist && sha256sum -c CLOUDHV.fd.sha256 )
git_commit:      ${commit}
base_image:      ${base_image}
nixpkgs:         ${nixpkgs_rev}
store_path:      ${store_path}

$(cat CLOUDHV.fd.sha256)
EOF

echo
cat firmware-build-info.txt
