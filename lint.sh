#!/usr/bin/env bash
# lint.sh — run clippy on all targets inside the devcontainer (pinned toolchain from
# rust-toolchain.toml). Prefers a `vk` on PATH (the microVM builder, like build.sh); pass
# --docker to force the Docker backend. Extra arguments are forwarded to clippy (e.g. --fix).
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
  # Dogfood the vk on PATH: it builds the devcontainer image and runs clippy in a microVM
  # with the repo mounted at /work. --net gives cargo egress to fetch crates; the workspace
  # compile wants every CPU and enough RAM not to OOM rustc (the run defaults are 2 cpus/1G).
  echo "lint.sh: linting with vk from PATH ($(command -v vk)); pass --docker to force Docker" >&2
  exec vk run \
    --file .devcontainer/Dockerfile --context .devcontainer \
    --workdir "$PWD" --net --cpus host --mem 8G \
    -- cargo clippy --workspace --all-targets -- -D warnings "${args[@]}"
fi

docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/work -w /work \
  virtkit-build \
  cargo clippy --workspace --all-targets -- -D warnings "${args[@]}"
