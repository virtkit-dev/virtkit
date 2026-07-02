#!/usr/bin/env bash
# lint.sh — run clippy on all targets inside the devcontainer (pinned toolchain from
# rust-toolchain.toml). Extra arguments are forwarded to clippy (e.g. --fix).
set -euo pipefail
cd "$(dirname "$0")"

docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/work -w /work \
  virtkit-build \
  cargo clippy --workspace --all-targets -- -D warnings "$@"
