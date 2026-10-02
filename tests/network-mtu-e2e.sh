#!/usr/bin/env bash
# Check the switch link MTU.
# Run: VK=./dist/vk bash tests/network-mtu-e2e.sh
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}")
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
cd "$(dirname "$0")/.."
IMAGE=${IMAGE:-docker.io/library/alpine:3.21}
timeout -k 30 300 "$VK" run "$IMAGE" --net -- \
  sh -ec 'test "$(cat /sys/class/net/eth0/mtu)" = 65500'
echo "PASS: switch interface uses MTU 65500"
