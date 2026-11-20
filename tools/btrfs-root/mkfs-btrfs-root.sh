#!/usr/bin/env bash
# Convert the ext4 from `vk build --out` to btrfs for `vk run --kernel image --root-image OUT`.
# This prototypes vk's planned conversion step. Repeat builds require the same source,
# output size and converter image (tools/btrfs-root/Dockerfile).
#
# Usage: mkfs-btrfs-root.sh SRC.ext4 OUT.img [SIZE]   (SIZE default 8G, sparse)
set -euo pipefail

VK=${VK:-vk}
here=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 2 ] && [ $# -le 3 ] || { echo "usage: $0 SRC.ext4 OUT.img [SIZE]" >&2; exit 2; }
src=$1 out=$2 size=${3:-8G}
[ -f "$src" ] || { echo "$src: no such file" >&2; exit 1; }
if [[ "$src" -ef "$out" ]]; then echo "$out is $src" >&2; exit 1; fi

# Fixed identity: the fsid and device UUID from the source's digest, the rest seeded by it.
digest=$(sha256sum "$src" | cut -c1-32)
fsid=${digest:0:8}-${digest:8:4}-4${digest:13:3}-8${digest:17:3}-${digest:20:12}
devid=${digest:16:8}-${digest:24:4}-4${digest:1:3}-8${digest:5:3}-${digest:8:12}

# Build beside the destination so a failed conversion preserves any existing image.
tmp=$(mktemp "$out.XXXXXX")
trap 'rm -f "$tmp"' EXIT
truncate -s "$size" "$tmp"
"$VK" run -f "$here/Dockerfile" --context "$here" --target converter \
    --disk "$src:ro" --disk "$tmp" -- sh -c "
set -e
mkdir -p /src && mount -o ro /dev/vdb /src
# Missing preload files let mkfs fall back to the real clock or random UUIDs.
set -- /usr/lib/*/faketime/libfaketime.so.1
[ \$# -eq 1 ] && [ -f \"\$1\" ] && [ -f /usr/local/lib/libvkuuid.so ] \
    || { echo 'converter image: libfaketime or libvkuuid missing' >&2; exit 1; }
# On failure, omit the expected btrfs-control warning from this kernel's mkfs log.
LD_PRELOAD=\"/usr/local/lib/libvkuuid.so \$1\" \
FAKETIME='2000-01-01 00:00:00' VK_UUID_SEED=${digest:0:16} \
    mkfs.btrfs -q -f --rootdir /src --uuid $fsid --device-uuid $devid /dev/vdc \
    >/tmp/mkfs.log 2>&1 || { grep -v btrfs-control /tmp/mkfs.log >&2; exit 1; }
btrfs check --readonly /dev/vdc >/dev/null
"
mv -T -- "$tmp" "$out"
trap - EXIT
echo "$out: btrfs, fsid $fsid"
