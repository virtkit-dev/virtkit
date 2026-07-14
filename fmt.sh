#!/usr/bin/env bash
# fmt.sh — reformat all sources with rustfmt (the pinned version from rust-toolchain.toml),
# inside the devcontainer so the rustfmt version matches CI exactly. Prefers a `vk` on PATH
# (the microVM builder, like build.sh); pass --docker to force the Docker backend. Extra
# arguments are forwarded to cargo fmt (e.g. --check).
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

if [ -z "$FORCE_DOCKER" ] && command -v vk >/dev/null 2>&1; then
  # Dogfood the vk on PATH: it builds the devcontainer image and runs cargo fmt in a microVM
  # with the repo mounted at /work; virtiofs writes the reformatted files back as the host
  # user. No --net — rustfmt neither compiles nor fetches.
  echo "fmt.sh: formatting with vk from PATH ($(command -v vk)); pass --docker to force Docker" >&2
  exec vk run \
    --file .devcontainer/Dockerfile --context .devcontainer \
    --workdir "$PWD" \
    -- cargo fmt --all "${args[@]}"
fi

docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/work -w /work \
  virtkit-build \
  cargo fmt --all "${args[@]}"
