#!/usr/bin/env bash
# Exercise the enqueue/completion race without patching guest instructions. The Rust
# VMM hook observes enqueue's int return with hardware breakpoints, logs real ENOSPC,
# and pauses that vCPU after the ring lock was released. Other vCPUs reap completions.
#
# VK=./dist/vk tests/virtiofs-full-ring-e2e.sh
# VIRTIOFS_KERNEL=/path/to/unfixed/vmlinux VIRTIOFS_EXPECT=10 tests/virtiofs-full-ring-e2e.sh
# Requires an x86_64 Linux host with KVM and a non-preemptible guest kernel with kallsyms
# and stable kernel text addresses between boots. VK must include the opt-in test hook.
# VIRTIOFS_SECONDS defaults to 60; STEP_TIMEOUT bounds each VM (default 180).
# VIRTIOFS_LOG_DIR retains complete logs; otherwise they are printed and removed.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

seconds=${VIRTIOFS_SECONDS:-60}
limit=${STEP_TIMEOUT:-180}
expected=${VIRTIOFS_EXPECT:-0}
for value in "$seconds" "$limit"; do
  case "$value" in ''|*[!0-9]*|0) echo 'virtiofs-full-ring: invalid duration' >&2; exit 2 ;; esac
done
[ "$seconds" -le 3600 ] && [ "$limit" -gt "$((seconds + 30))" ] || {
  echo 'virtiofs-full-ring: need seconds <= 3600 and STEP_TIMEOUT > seconds + 30' >&2; exit 2;
}
case "$expected" in 0|10) ;; *) echo 'virtiofs-full-ring: VIRTIOFS_EXPECT must be 0 or 10' >&2; exit 2 ;; esac
asked=${VK:-./dist/vk}
VK=$(command -v "$asked")
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo 'virtiofs-full-ring: need rw access to /dev/kvm' >&2; exit 2; }
timeout --version >/dev/null
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
logs=${VIRTIOFS_LOG_DIR:-$work/logs}
mkdir -p "$logs"
logs=$(cd "$logs" && pwd)
kernel=()
if [ -n "${VIRTIOFS_KERNEL:-}" ]; then kernel=(--kernel "$VIRTIOFS_KERNEL"); fi
image=${VIRTIOFS_IMAGE:-docker.io/library/alpine:3.21}
if [ -z "${VK_TESTKIT:-}" ]; then
  ./dev.sh build -p vk-testkit
  VK_TESTKIT=$here/target/x86_64-unknown-linux-musl/debug/vk-testkit
fi
cp "$VK_TESTKIT" "$work/vk-testkit"
for i in 0 1 2 3; do
  mkdir -p "$work/tree/d$i"
  for j in {0..39}; do : >"$work/tree/d$i/f$j"; done
done

# Resolve the function in the exact kernel being tested, without a host ELF toolchain.
timeout -k 5 "$limit" "$VK" run "$image" "${kernel[@]}" --cpus 8 --mem 1024 -- \
  sh -c 'uname -r; grep -w virtio_fs_enqueue_req /proc/kallsyms' >"$logs/symbol.log" 2>&1
cat "$logs/symbol.log"
pc=$(awk '$3 == "virtio_fs_enqueue_req" {print $1}' "$logs/symbol.log")
[[ "$pc" =~ ^ffff[[:xdigit:]]{12}$ ]] || {
  echo 'virtiofs-full-ring: missing or ambiguous enqueue symbol' >&2; exit 2;
}
cat >"$work/guest.sh" <<'EOF'
set -eu
pc=$1
seconds=$2
actual=$(awk '$3 == "virtio_fs_enqueue_req" {print $1}' /proc/kallsyms)
[ "$pc" = "$actual" ] || { echo 'kernel text moved between boots'; exit 2; }
mkdir -p /mnt/full-ring /mnt/full-ring-upper
mount -t tmpfs none /mnt/full-ring-upper
mkdir -p /mnt/full-ring-upper/u /mnt/full-ring-upper/w
for i in 0 1 2 3; do mkdir "/mnt/full-ring-upper/u/d$i"; done
mount -t overlay overlay -o lowerdir=/work/tree,upperdir=/mnt/full-ring-upper/u,workdir=/mnt/full-ring-upper/w /mnt/full-ring
# Execute from tmpfs: no demand paging from the share during the quiet/stall interval.
cp /work/vk-testkit /mnt/full-ring-upper/vk-testkit
exec /mnt/full-ring-upper/vk-testkit virtiofs-burst /mnt/full-ring /work 4 "$seconds"
EOF
status=0
VK_TEST_VIRTIOFS_ENQUEUE_PC=$pc timeout -k 5 "$limit" "$VK" run "$image" \
  "${kernel[@]}" --cpus 8 --mem 1024 --workdir "$work" --state-dir "$work/state" -- \
  sh /work/guest.sh "$pc" "$seconds" >"$logs/probe.log" 2>&1 || status=$?
cat "$logs/probe.log"
cp "$work/state/console.vmm.log" "$logs/vmm.log"
cp "$work/state/console.log" "$logs/console.log"
refusals=$(grep -c '^virtiofs-full-ring: ENOSPC ' "$logs/vmm.log" || true)
awk '/^virtiofs-full-ring: ENOSPC / {if (++n <= 3) print}' "$logs/vmm.log"
echo "virtiofs-full-ring: exit=$status expected=$expected refusals=$refusals"
[ "$refusals" -gt 0 ] || { echo 'FAIL: no observed ENOSPC; result is inconclusive' >&2; exit 1; }
[ "$status" -eq "$expected" ] || exit 1
if [ "$expected" -eq 10 ]; then
  grep -q '^freed by another request on the share' "$logs/probe.log"
else
  grep -q 'none stranded' "$logs/probe.log"
fi
