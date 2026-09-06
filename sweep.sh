#!/usr/bin/env bash
# sweep.sh — reclaim stale build artifacts from target/ with cargo-sweep, inside the
# devcontainer so it matches artifacts against the same pinned toolchain that produced
# them (build.sh/dev.sh compile in this image, writing to /work/target = the host's
# target/). Running sweep anywhere else would compare against a different rustc and could
# delete artifacts the real build toolchain still uses.
#
# Prefers a `vk` on PATH (the microVM builder, like build.sh); pass --docker to force the
# Docker backend. With no sweep criteria it defaults to `--installed` (drop everything not
# built by the image's toolchain); pass your own instead, e.g. `--time 15` (older than 15
# days) or `--maxsize 20` (trim to 20 GiB). Extra arguments are forwarded to cargo sweep.
set -euo pipefail
cd "$(dirname "$0")"

FORCE_DOCKER=""
args=()
for arg in "$@"; do
  case "$arg" in
    --docker) FORCE_DOCKER=1 ;;
    *) args+=("$arg") ;;
  esac
done
# cargo-sweep requires a criterion; default to --installed when the caller gave none.
[ ${#args[@]} -eq 0 ] && args=(--installed)

if [ -z "$FORCE_DOCKER" ] && command -v vk >/dev/null 2>&1; then
  # Dogfood the vk on PATH: it builds the devcontainer image and runs cargo sweep in a
  # microVM with the repo mounted at /work; virtiofs deletes the swept files on the host.
  # No --net — sweep only scans target/ and removes files, it neither compiles nor fetches.
  echo "sweep.sh: sweeping with vk from PATH ($(command -v vk)); pass --docker to force Docker" >&2
  exec vk run \
    --file .devcontainer/Dockerfile --context .devcontainer \
    --workdir "$PWD" \
    -- cargo sweep "${args[@]}"
fi

docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/work -w /work \
  virtkit-build \
  cargo sweep "${args[@]}"
