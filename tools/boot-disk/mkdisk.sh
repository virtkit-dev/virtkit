#!/usr/bin/env bash
# Lay a root ext4 (a `vk build --out`) out as a disk that boots from its own /boot, for
# `vk run --boot-disk OUT --init image`. Prototype of the seed vk would build itself
# (docs/vm-boot-from-disk-design.md, phase 1):
#
#   1  BIOS boot      1 MiB
#   2  ESP (vfat)     256 MiB   /boot/efi   the source's /boot/efi
#   3  XBOOTLDR ext2  512 MiB   /boot       the rest of the source's /boot
#   4  the rest:
#      plain   root btrfs (`Linux root (x86-64)`): booted with --boot-disk alone
#      --luks  LUKS2 (`Linux LUKS`) holding LVM vg00: lvroot btrfs, lvswap, lvdata ext4 on
#              /var/data; unlocked at boot with the key file /boot/luks.key (passdev), so
#              booted with --boot-cmdline root=/dev/mapper/vg00-lvroot
#
# The btrfs root has the subvolumes @rootfs (default, /), @homefs (/home), @roothomefs
# (/root), @varfs (/var) and @logfs (/var/log).
#
# Every ID derives from the source's digest and the formatters' clock is frozen, so in the
# plain layout the whole disk (GPT, ESP, /boot and btrfs root) comes out the same from one
# source, size and converter build (whose base and packages are not pinned). In the LUKS
# layout only the GPT and the ESP do: its key, volume key and LVM metadata are fresh, and its
# /boot holds an initrd rebuilt on the real clock.
#
# Usage: mkdisk.sh [--luks] SRC.ext4 OUT.img [SIZE]   (SIZE default 8G, sparse)
set -euo pipefail

VK=${VK:-vk}
here=$(cd "$(dirname "$0")" && pwd)
luks=
[ "${1:-}" = --luks ] && { luks=1; shift; }
[ $# -ge 2 ] && [ $# -le 3 ] || {
    echo "usage: $0 [--luks] SRC.ext4 OUT.img [SIZE]" >&2; exit 2
}
src=$1 out=$2 size=${3:-8G}
[ -f "$src" ] || { echo "$src: no such file" >&2; exit 1; }
if [[ "$src" -ef "$out" ]]; then echo "$out is $src" >&2; exit 1; fi

digest=$(sha256sum "$src" | cut -c1-64)
# A UUID from the digest and a role, so each object has its own.
uuid_for() {
    local h; h=$(printf '%s %s' "$digest" "$1" | sha256sum | cut -c1-32)
    echo "${h:0:8}-${h:8:4}-4${h:13:3}-8${h:17:3}-${h:20:12}"
}
disk_id=$(uuid_for disk) fs_id=$(uuid_for btrfs) dev_id=$(uuid_for btrfs-dev)
boot_id=$(uuid_for boot) luks_id=$(uuid_for luks) swap_id=$(uuid_for swap)
data_id=$(uuid_for data)
esp_vol=$(uuid_for esp | tr -d - | cut -c1-8)
esp_uuid="${esp_vol:0:4}-${esp_vol:4:4}"; esp_uuid=${esp_uuid^^}

if [ -n "$luks" ]; then
    p4_spec="type=CA7D7CCB-63ED-4C53-861C-1742536059CC, uuid=$(uuid_for p4), name=luks"
    # vk's kernel has no device mapper: cryptsetup and LVM run on the converter's own.
    converter=(--kernel image --target converter-luks)
else
    p4_spec="type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=$(uuid_for p4), name=root"
    converter=(--target converter)
fi

# Built beside the output and renamed over it once checked, so a failure leaves no disk.
tmp=$(mktemp "$out.XXXXXX")
trap 'rm -f "$tmp"' EXIT
truncate -s "$size" "$tmp"
# The partitions before the fourth take 770 MiB; LVM's volumes 1.5 GiB more, and the root.
if [ -n "$luks" ] && [ "$(stat -c %s "$tmp")" -lt $((4 << 30)) ]; then
    echo "--luks needs a SIZE of 4G or more" >&2; exit 1
fi
# 2G: /boot is staged in a tmpfs, and the LUKS layout builds an initrd.
"$VK" run "${converter[@]}" --mem 2G -f "$here/Dockerfile" --context "$here/.." \
    --disk "$src:ro" --disk "$tmp" -- sh -c "
set -eu
export FAKETIME='2000-01-01 00:00:00' E2FSPROGS_FAKE_TIME=946684800 MTOOLS_SKIP_CHECK=1
# No udev in the converter: LVM and cryptsetup make their own device nodes.
export DM_DISABLE_UDEV=1
if [ -n '$luks' ]; then modprobe -a loop dm_mod dm_crypt; fi
# Both preloads must be there: without them the formatters run on the real clock and
# random UUIDs.
set -- /usr/lib/*/faketime/libfaketime.so.1
[ \$# -eq 1 ] && [ -f \"\$1\" ] && [ -f /usr/local/lib/libvkuuid.so ] \\
    || { echo 'converter image: libfaketime or libvkuuid missing' >&2; exit 1; }
ft=\$1
mkdir -p /src && mount -o ro /dev/vdb /src
for d in boot etc home root var var/log; do
    [ -d /src/\$d ] || { echo \"the source has no /\$d\" >&2; exit 1; }
done
[ -f /src/etc/fstab ] || { echo 'the source has no /etc/fstab' >&2; exit 1; }

t_bios=21686148-6449-6E6F-744E-656564454649 t_esp=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
t_boot=BC13C2FF-59E6-4262-A352-B275FD6F7172
sfdisk -q /dev/vdc <<P
label: gpt
label-id: $disk_id
start=2048, size=2048, type=\$t_bios, uuid=$(uuid_for p1), name=biosgrub
start=4096, size=524288, type=\$t_esp, uuid=$(uuid_for p2), name=esp
start=528384, size=1048576, type=\$t_boot, uuid=$(uuid_for p3), name=boot
start=1576960, $p4_spec
P
# Each partition as a loop device over exactly its extent, as sfdisk laid it out.
part() {
    set -- \$(partx -g -o START,SECTORS -n \$1 /dev/vdc)
    losetup -f --show -o \$((\$1 * 512)) --sizelimit \$((\$2 * 512)) /dev/vdc
}
esp=\$(part 2) boot=\$(part 3) p4=\$(part 4)

# The ESP: the source's /boot/efi, through mtools, in sorted order and on the frozen clock: a
# kernel mount would stamp each entry's creation time with the real one. FAT holds
# directories and files: anything else in the source is refused, not flattened.
mkfs.vfat --invariant -i $esp_vol -n ESP \$esp >/dev/null
if [ -L /src/boot/efi ]; then echo '/boot/efi is a symlink' >&2; exit 1; fi
: > /tmp/esp.list
if [ -d /src/boot/efi ]; then
    other=\$(find /src/boot/efi -mindepth 1 ! -type d ! -type f)
    if [ -n \"\$other\" ]; then
        echo \"/boot/efi holds what FAT cannot: \$other\" >&2; exit 1
    fi
    (cd /src/boot/efi && find . -mindepth 1) > /tmp/esp.list
    LC_ALL=C sort -o /tmp/esp.list /tmp/esp.list
fi
while IFS= read -r f; do
    f=\${f#./}
    if [ -d \"/src/boot/efi/\$f\" ]; then
        LD_PRELOAD=\$ft mmd -i \$esp \"::/\$f\"
    else
        LD_PRELOAD=\$ft mcopy -i \$esp \"/src/boot/efi/\$f\" \"::/\$f\"
    fi
done < /tmp/esp.list

# /boot: the rest of the source's /boot, with an empty mountpoint for the ESP. The copy's
# times are the copy's own: fix them, as mke2fs fixes its own.
mkdir -p /stage && mount -t tmpfs tmpfs /stage
cp -a /src/boot /stage/boot
rm -rf /stage/boot/efi
mkdir -m 0700 /stage/boot/efi

# An encrypted machine: LUKS2 keyed by a fresh file on /boot, holding LVM vg00 with its root,
# swap and data volumes. A key on /boot, which is not encrypted, gives no confidentiality by
# design: the machine unlocks itself. A low PBKDF cost keeps its boot short. A failure below
# leaves the volumes open: the converter VM ends with them.
if [ -n '$luks' ]; then
    dd if=/dev/urandom of=/stage/boot/luks.key bs=64 count=1 status=none
    chmod 0400 /stage/boot/luks.key
    cryptsetup luksFormat -q --type luks2 --uuid $luks_id --pbkdf pbkdf2 \\
        --pbkdf-force-iterations 1000 --key-file /stage/boot/luks.key \$p4
    cryptsetup open --key-file /stage/boot/luks.key \$p4 cryptroot
    vgcreate -q vg00 /dev/mapper/cryptroot >/dev/null
    lvcreate -q -y -L 512M -n lvswap vg00 >/dev/null
    lvcreate -q -y -L 1G -n lvdata vg00 >/dev/null
    lvcreate -q -y -l 100%FREE -n lvroot vg00 >/dev/null
    vgmknodes vg00
    mkswap -q -U $swap_id /dev/vg00/lvswap
    # /var/data: the source's, with its root's owner and mode.
    mkdir -p /stage/data
    owner=0:0
    if [ -d /src/var/data ]; then
        cp -a /src/var/data/. /stage/data/
        chmod \$(stat -c %a /src/var/data) /stage/data
        owner=\$(stat -c %u:%g /src/var/data)
    fi
    mke2fs -q -t ext4 -U $data_id -E root_owner=\$owner -L data -d /stage/data \\
        /dev/vg00/lvdata
    root=/dev/vg00/lvroot
else
    root=\$p4
fi
touch -d @946684800 /stage/boot /stage/boot/efi
mke2fs -q -t ext2 -U $boot_id -E hash_seed=$boot_id,root_owner=0:0 -L boot \\
    -d /stage/boot \$boot
(cd /stage/boot && find .) | sed 's|^\\.||; s|^\$|/|; s|.*|sif \"&\" ctime @946684800|' \\
    > /tmp/boot.cmds
# debugfs exits 0 whatever its commands do: a line on stderr past its banner is a failure.
debugfs -w -f /tmp/boot.cmds \$boot >/dev/null 2>/tmp/debugfs.err
if grep -v '^debugfs ' /tmp/debugfs.err >&2; then exit 1; fi

# What the root tree adds to the source: its top directory, the fstab, and an empty
# directory, of the same owner and mode, to hide each nested subvolume in its parent (the
# source's xattrs and ACLs are not kept). They come from a small ext2 of their own with every
# time fixed: mkfs.btrfs records each inode's times, which a file made here would take from
# the real clock.
install -d -m 0755 /stage/add/tree
install -d -m 0755 /stage/add/tree/@rootfs /stage/add/tree/@homefs \\
    /stage/add/tree/@roothomefs /stage/add/tree/@varfs /stage/add/tree/@logfs
empty() {
    if [ -L \"\$1\" ]; then echo \"\$1 is a symlink, not a subvolume\" >&2; exit 1; fi
    install -d -m \$(stat -c %a \"\$1\") -o \$(stat -c %u \"\$1\") -g \$(stat -c %g \"\$1\") \\
        /stage/add/\$2
}
empty /src/boot boot; empty /src/home home; empty /src/root root; empty /src/var var
empty /src/var/log log
if [ -n '$luks' ] && [ -d /src/var/data ]; then empty /src/var/data data; fi
cat > /stage/add/fstab <<F
UUID=$fs_id / btrfs subvol=@rootfs 0 0
UUID=$fs_id /home btrfs subvol=@homefs 0 0
UUID=$fs_id /root btrfs subvol=@roothomefs 0 0
UUID=$fs_id /var btrfs subvol=@varfs 0 0
UUID=$fs_id /var/log btrfs subvol=@logfs 0 0
UUID=$boot_id /boot ext2 defaults 0 2
UUID=$esp_uuid /boot/efi vfat umask=0077 0 2
F
if [ -n '$luks' ]; then
    echo 'UUID=$data_id /var/data ext4 defaults 0 2' >> /stage/add/fstab
    echo 'UUID=$swap_id none swap sw 0 0' >> /stage/add/fstab
fi
chmod \$(stat -c %a /src/etc/fstab) /stage/add/fstab
chown \$(stat -c %u:%g /src/etc/fstab) /stage/add/fstab
truncate -s 8M /tmp/add.img
mke2fs -q -t ext2 -U $(uuid_for add) -E hash_seed=$(uuid_for add),root_owner=0:0 \\
    -d /stage/add /tmp/add.img
(cd /stage/add && find .) | sed 's|^\\.||; s|^\$|/|' | while IFS= read -r f; do
    for w in ctime mtime atime; do echo \"sif \\\"\$f\\\" \$w @946684800\"; done
done > /tmp/add.cmds
debugfs -w -f /tmp/add.cmds /tmp/add.img >/dev/null 2>/tmp/debugfs.err
if grep -v '^debugfs ' /tmp/debugfs.err >&2; then exit 1; fi
mkdir -p /add && mount -o ro,loop /tmp/add.img /add

# The root tree: each subvolume a view of the source, each nested one hidden in its parent.
t=/add/tree
mount --bind -o ro /src \$t/@rootfs
mount --bind -o ro /src/home \$t/@homefs
mount --bind -o ro /src/root \$t/@roothomefs
mount --bind -o ro /src/var \$t/@varfs
mount --bind -o ro /src/var/log \$t/@logfs
for d in boot home root var; do mount --bind /add/\$d \$t/@rootfs/\$d; done
mount --bind /add/log \$t/@varfs/log
if [ -n '$luks' ] && [ -d /src/var/data ]; then mount --bind /add/data \$t/@varfs/data; fi
mount --bind /add/fstab \$t/@rootfs/etc/fstab

# mkfs warns it cannot open btrfs-control on a kernel without btrfs: that line is dropped,
# the rest shown on failure.
LD_PRELOAD=\"/usr/local/lib/libvkuuid.so \$ft\" VK_UUID_SEED=${digest:0:16} \\
    mkfs.btrfs -q -f --rootdir \$t --uuid $fs_id --device-uuid $dev_id -L root \\
        --subvol default:@rootfs --subvol rw:@homefs --subvol rw:@roothomefs \\
        --subvol rw:@varfs --subvol rw:@logfs \$root >/tmp/mkfs.log 2>&1 \\
    || { grep -v btrfs-control /tmp/mkfs.log >&2; exit 1; }

# An encrypted machine also needs its crypttab, and an initrd that unlocks and activates
# what it boots from: built on the disk, by its own initramfs-tools.
if [ -n '$luks' ]; then
    m=/mnt
    mount -o subvol=@rootfs \$root \$m
    mount -o subvol=@homefs \$root \$m/home
    mount -o subvol=@roothomefs \$root \$m/root
    mount -o subvol=@varfs \$root \$m/var
    mount -o subvol=@logfs \$root \$m/var/log
    mount \$boot \$m/boot
    mkdir -p \$m/var/data
    key=/dev/disk/by-uuid/$boot_id:/luks.key
    echo \"cryptroot UUID=$luks_id \$key luks,discard,keyscript=passdev,initramfs\" \\
        > \$m/etc/crypttab
    for d in dev proc sys run; do mount --rbind /\$d \$m/\$d; done
    # No udev here, so no /dev/disk/by-uuid: the crypttab entry's initramfs option is what
    # puts it in the initrd regardless.
    chroot \$m update-initramfs -u -k all
    umount -R \$m
fi
btrfs check --readonly \$root >/dev/null 2>&1 || btrfs check --readonly \$root
e2fsck -fn \$boot >&2
fsck.vfat -n \$esp >&2
if [ -n '$luks' ]; then
    vgchange -q -an vg00 >/dev/null
    cryptsetup close cryptroot
fi
"
mv -T -- "$tmp" "$out"
trap - EXIT
echo "$out: GPT $disk_id, root btrfs $fs_id, /boot ext2 $boot_id${luks:+, LUKS $luks_id}"
