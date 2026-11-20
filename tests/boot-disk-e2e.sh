#!/usr/bin/env bash
# `vk run --boot-disk`: a persistent machine booted from the kernel in its own /boot, on an
# appliance-like disk — GPT with a BIOS boot partition, an ESP, an ext2 /boot, and LUKS2
# holding LVM vg00 (lvroot: btrfs subvolumes for /, /home, /root, /var, /var/log; lvswap;
# lvdata: ext4 on /var/data), unlocked at boot with a key file on /boot.
#
#   1. the seed boots on its kernel A through its own initrd (unlock, LVM, root mount), with
#      --root ro and a prepare hook. Its init sees a read-only / and writable /var. All
#      filesystems mount, the ESP contains the source marker, and swap is active;
#   2. the guest installs a newer kernel B with apt, whose scripts rebuild its initrd;
#   3. `systemctl reboot` in the guest comes back on B, same machine, same data;
#   4. a stop and a cold start boot B again.
#
# Run:  VK=./dist/vk tests/boot-disk-e2e.sh
# Needs: a `vk` with an embedded agent, KVM, network access to deb.debian.org, about 10 GiB
# of scratch space. Kernel B comes from trixie-backports, which must hold a kernel newer than
# trixie's: the test says so when it does not.
set -euo pipefail

VK="${VK:-vk}"
here="$(cd "$(dirname "$0")" && pwd)"
tools="$here/../tools"
base="${TMPDIR:-/tmp}"
WORK=$(mktemp -d "$base/vk-boot-disk-e2e.XXXXXX")
vm="$WORK/state"
cleanup() {
  "$VK" stop "$vm" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

expect() { # <output> <line regex> <what>
  grep -Eq "$2" <<<"$1" || { echo "FAIL: $3"; exit 1; }
}
expect_line() { # <output> <exact line> <what>
  grep -Fxq "$2" <<<"$1" || { echo "FAIL: $3"; exit 1; }
}
gx() { "$VK" exec "$vm" -- sh -c "$1"; }
start() {
  # 2G: the guest runs apt and rebuilds its initrd for kernel B.
  "$VK" run --net --detach --mem 2G --init image \
    --init-argv /usr/local/sbin/vk-handoff-probe \
    -f "$tools/boot-disk/Dockerfile" --context "$tools" --target fixture \
    --boot-disk "$WORK/disk.img" --boot-cmdline root=/dev/mapper/vg00-lvroot \
    --root ro --prepare "sh -c 'findmnt -rno OPTIONS /var > /var/lib/vk-prepared'" \
    --state-dir "$vm" -- sleep infinity
}
settle() { # wait for systemd, and print the machine's state
  gx '
    for i in $(seq 1 300); do
      state=$(systemctl is-system-running 2>/dev/null || true)
      case "$state" in running|degraded) break;; esac
      sleep 1
    done
    echo "system-state: ${state:-unknown}"
    echo "kernel: $(uname -r)"
    echo "boot-id: $(cat /proc/sys/kernel/random/boot_id)"
    echo "pid1: $(readlink /proc/1/exe)"
    h=$(dmesg | grep -o "vk-handoff: .*" | tail -1); echo "${h:-vk-handoff: none}"
    echo "esp: $(cat /boot/efi/EFI/vk/marker 2>/dev/null || echo none)"
    echo "prepared: $(cat /var/lib/vk-prepared 2>/dev/null || echo none)"
    if touch /vk-rw-probe 2>/dev/null; then echo "root-now: rw"; else echo "root-now: ro"; fi
    findmnt -rno TARGET,SOURCE,FSTYPE | grep -E " (btrfs|ext2|ext4|vfat)$" | sed "s/^/mount: /"
    lsblk -rno NAME,TYPE | grep -E " (crypt|lvm)$" | sed "s/^/block: /"
    echo "swap: $(swapon --noheadings --show=NAME | xargs -r -n1 readlink -f | xargs -r -n1 basename)"
    echo "swap-lv: $(readlink -f /dev/mapper/vg00-lvswap | xargs basename)"
    echo "failed-units: $(systemctl --failed --no-legend | wc -l)"
    for f in /var/data/vk-marker /home/vk-marker /var/log/vk-marker; do
      echo "marker $f: $(cat $f 2>/dev/null || echo none)"
    done
  '
}
# What every boot must show: systemd up, prepare run on this boot with /var writable, / made
# writable again by systemd, the encrypted volume open, the swap volume active.
expect_machine() { # <output>
  expect "$1" '^system-state: (running|degraded)$' "systemd did not reach a run state"
  expect "$1" '^pid1: .*/systemd$' "systemd is not PID 1"
  expect "$1" '^vk-handoff: root=ro var=rw$' \
    "the init did not start on a read-only / and a writable /var"
  expect "$1" '^esp: esp-ok$' "the ESP lost the source's /boot/efi"
  expect "$1" '^prepared: rw,' "prepare did not run on a writable /var"
  expect "$1" '^root-now: rw$' "systemd did not remount / rw"
  expect "$1" '^block: cryptroot crypt$' "the LUKS volume is not open"
  expect "$1" '^swap-lv: dm-[0-9]+$' "no lvswap device"
  expect_line "$1" "swap: $(sed -n 's/^swap-lv: //p' <<<"$1")" "lvswap is not the active swap"
  expect "$1" '^failed-units: 0$' "units failed"
}
expect_data() { # <output>
  for f in /var/data /home /var/log; do
    expect "$1" "^marker $f/vk-marker: kept$" "$f lost its data"
  done
}
# Wait until the guest answers with another boot id than <id>.
wait_reboot() { # <boot id>
  local id
  for i in $(seq 1 120); do
    id=$(timeout 30 "$VK" exec "$vm" -- cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    if [ -n "$id" ] && [ "$id" != "$1" ]; then return 0; fi
    sleep 2
  done
  echo "FAIL: the guest did not come back from its reboot"
  exit 1
}

echo "== building the fixture and its disk =="
"$VK" build -f "$tools/boot-disk/Dockerfile" --context "$tools" --target fixture \
  --out "$WORK/fixture.ext4" >/dev/null
VK="$VK" "$tools/boot-disk/mkdisk.sh" --luks "$WORK/fixture.ext4" "$WORK/disk.img" 8G
rm -f "$WORK/fixture.ext4"

echo "== 1. first boot =="
start
out=$(settle)
echo "$out"
expect_machine "$out"
for m in '/ /dev/mapper/vg00-lvroot\[/@rootfs\] btrfs' \
         '/home /dev/mapper/vg00-lvroot\[/@homefs\] btrfs' \
         '/root /dev/mapper/vg00-lvroot\[/@roothomefs\] btrfs' \
         '/var /dev/mapper/vg00-lvroot\[/@varfs\] btrfs' \
         '/var/log /dev/mapper/vg00-lvroot\[/@logfs\] btrfs' \
         '/boot /dev/vda3 ext2' '/boot/efi /dev/vda2 vfat' \
         '/var/data /dev/mapper/vg00-lvdata ext4'; do
  expect "$out" "^mount: $m$" "missing mount: $m"
done
kernel_a=$(sed -n 's/^kernel: //p' <<<"$out")
boot_a=$(sed -n 's/^boot-id: //p' <<<"$out")

echo "== 2. installing a newer kernel =="
# The prepare marker is removed, so the next boots show their own prepare ran.
gx 'for f in /var/data/vk-marker /home/vk-marker /var/log/vk-marker; do echo kept > $f; done
    rm -f /var/lib/vk-prepared
    echo "deb http://deb.debian.org/debian trixie-backports main" \
      > /etc/apt/sources.list.d/backports.list
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      -t trixie-backports linux-image-amd64 >/dev/null'
# The newest release as GRUB orders them, which vk boots.
kernel_b=$(gx 'ls /boot | sed -n "s/^vmlinuz-//p" | LC_ALL=C sort -V | tail -1')
echo "kernel A: $kernel_a, kernel B: $kernel_b"
[ "$kernel_b" != "$kernel_a" ] \
  || { echo "FAIL: trixie-backports has no kernel newer than $kernel_a"; exit 1; }

echo "== 3. reboot from the guest =="
gx 'systemctl reboot' >/dev/null 2>&1 || true
wait_reboot "$boot_a"
out=$(settle)
echo "$out"
expect_line "$out" "kernel: $kernel_b" "the guest did not reboot on the kernel it installed"
expect_machine "$out"
expect_data "$out"

echo "== 4. stop and cold start =="
gx 'rm -f /var/lib/vk-prepared'
"$VK" stop "$vm" >/dev/null
start
out=$(settle)
echo "$out"
expect_line "$out" "kernel: $kernel_b" "a cold start did not boot the installed kernel"
expect_machine "$out"
expect_data "$out"

echo "PASS"
