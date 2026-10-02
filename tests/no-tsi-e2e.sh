#!/usr/bin/env bash
# Check that a VM without network (`net.mode = "none"`) gets no TSI inet hijack.
# libkrun's implicit vsock appends `tsi_hijack` to the kernel cmdline of a NIC-less VM.
# Run: VK=./dist/vk bash tests/no-tsi-e2e.sh
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
IMAGE=${IMAGE:-docker.io/library/alpine:3.21}
timeout -k 30 300 "$VK" run "$IMAGE" -- \
  sh -ec 'cat /proc/cmdline; ! grep -qw tsi_hijack /proc/cmdline'
echo "PASS: no tsi_hijack on the cmdline of a VM without network"
