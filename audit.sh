#!/usr/bin/env bash
# Audit the dependency tree for known RUSTSEC advisories against the committed
# Cargo.lock. Extra arguments are forwarded to cargo-audit (e.g. --deny warnings).
set -euo pipefail
cd "$(dirname "$0")"

# Detect via `cargo audit` (cargo resolves subcommands from ~/.cargo/bin even
# when it isn't on PATH) rather than `command -v`, which gives false negatives.
if ! cargo audit --version >/dev/null 2>&1; then
  echo "cargo-audit not found, installing..."
  cargo install cargo-audit --locked
fi

cargo audit "$@"
