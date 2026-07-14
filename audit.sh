#!/usr/bin/env bash
# audit.sh — scan the dependency tree for known RUSTSEC advisories against the committed
# Cargo.lock, reading the ignore list in .cargo/audit.toml. Extra arguments are forwarded
# to cargo-audit (e.g. --deny warnings).
#
# Backend: prefers a `vk` on PATH (the microVM builder, like build.sh), else Docker — both
# run in the devcontainer where cargo-audit is baked in. With neither (e.g. CI invokes
# `sh audit.sh` inside the already-built image) it runs cargo audit directly, installing it
# on demand for a bare environment. Pass --docker to force the Docker backend.
#
# POSIX sh only (no bash arrays): CI runs this inside the Alpine image, which has no bash.
set -euo pipefail
cd "$(dirname "$0")"

# Split --docker out of the args forwarded to cargo-audit by rebuilding the positional
# parameters (POSIX has no arrays). Bounded by the original count so re-appended args
# are not re-scanned.
FORCE_DOCKER=""
n=$#
while [ "$n" -gt 0 ]; do
  arg="$1"; shift; n=$((n - 1))
  case "$arg" in
    --docker) FORCE_DOCKER=1 ;;
    *) set -- "$@" "$arg" ;;
  esac
done

if [ -z "$FORCE_DOCKER" ] && command -v vk >/dev/null 2>&1; then
  # Dogfood the vk on PATH: build the devcontainer image and run cargo audit in a microVM
  # with the repo mounted at /work (for Cargo.lock + .cargo/audit.toml). --net lets
  # cargo-audit fetch the RustSec advisory database.
  echo "audit.sh: auditing with vk from PATH ($(command -v vk)); pass --docker to force Docker" >&2
  exec vk run \
    --file .devcontainer/Dockerfile --context .devcontainer \
    --workdir "$PWD" --net \
    -- cargo audit "$@"
fi

if [ -z "$FORCE_DOCKER" ] && ! command -v docker >/dev/null 2>&1; then
  # Neither vk nor Docker: run cargo audit in the current environment. This is the
  # in-container path (CI runs `sh audit.sh` inside the devcontainer, where cargo-audit is
  # baked in). Fall back to installing it on demand for a bare host. Detect via
  # `cargo audit` (cargo finds subcommands in ~/.cargo/bin even off PATH), not `command -v`.
  if ! cargo audit --version >/dev/null 2>&1; then
    echo "cargo-audit not found, installing..." >&2
    cargo install cargo-audit --locked
  fi
  exec cargo audit "$@"
fi

# Docker backend: build the image (cargo-audit is baked in) and run the audit in it.
docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

exec docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/work -w /work \
  virtkit-build \
  cargo audit "$@"
