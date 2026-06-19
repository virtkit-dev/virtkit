#!/usr/bin/env bash
# fmt.sh — reformat all sources with rustfmt (the pinned version from rust-toolchain.toml).
# Runs inside the devcontainer image so the rustfmt version matches CI exactly.
set -euo pipefail
cd "$(dirname "$0")"

docker build -t virtkit-build -f .devcontainer/Dockerfile .devcontainer

docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/work -w /work \
  virtkit-build \
  cargo fmt --all "$@"
