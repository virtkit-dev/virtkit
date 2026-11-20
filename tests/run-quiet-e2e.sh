#!/usr/bin/env bash
# Expect the guest command's stdout and check stderr for virtkit status notes, allowing warnings.
# Run: VK=./dist/vk bash tests/run-quiet-e2e.sh
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
IMAGE=${IMAGE:-docker.io/library/alpine:3.21}
err=$(mktemp)
trap 'rm -f "$err"' EXIT
out=$(timeout -k 30 300 "$VK" run -q "$IMAGE" -- echo hi 2>"$err")
[ "$out" = hi ] || { echo "FAIL: stdout was: $out"; exit 1; }
if grep -v 'warning' "$err" | grep -q '^virtkit:'; then
  echo "FAIL: --quiet still printed the run's notes:"
  cat "$err"
  exit 1
fi
echo "PASS: vk run --quiet printed the command's stdout and no non-warning virtkit notes"
