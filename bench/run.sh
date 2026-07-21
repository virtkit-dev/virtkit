#!/bin/sh
# virtio-fs vs overlay-over-virtiofs vs in-guest tmpfs per-op benchmark.
#
# Boots a throwaway microVM with a host tmpfs shared read-write at /work, then runs the
# per-op microbench (the fsbench crate) against the raw share, against an overlay whose
# lower is the share and whose upper/work are guest tmpfs (what `[gitlab] checkout_overlay`
# mounts), and against a plain in-guest tmpfs (the "shmfs" floor). fsbench is executed
# from /work so a noexec target dir does not bite.
#
# Usage: ./run.sh [VK_BINARY] [N_OPS]
set -eu

VK=${1:-vk}
N=${2:-20000}
case $N in *[!0-9]*|'') echo "N must be a positive integer, got: $N" >&2; exit 2;; esac
[ "$N" -gt 0 ] || { echo "N must be a positive integer, got: $N" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
share=$(mktemp -d /dev/shm/fsbench.XXXXXX)   # host tmpfs, mirrors CI's RAM-backed /builds
trap 'rm -rf "$share"' EXIT

echo "compiling fsbench (static musl, runs on any guest)"
cargo build --quiet --release --target x86_64-unknown-linux-musl \
  --manifest-path "$here/../Cargo.toml" -p fsbench
cp "$here/../target/x86_64-unknown-linux-musl/release/fsbench" "$share/fsbench"

echo "booting microVM ($VK), N=$N ops/case"
"$VK" run debian:trixie-slim --mem 6G --cpus 8 --workdir "$share" -- sh -ec '
  mkdir -p /mnt/shm && mount -t tmpfs tmpfs /mnt/shm
  mkdir -p /mnt/ovl && mount -t tmpfs -o nosuid,nodev,noatime,mode=0755 tmpfs /mnt/ovl
  mkdir -p /mnt/ovl/upper /mnt/ovl/work /mnt/ovl/merged
  echo "### virtio-fs share (/work) ###";        /work/fsbench /work           '"$N"'
  # Mounted only now: mutating the lower layer of a mounted overlay is undefined
  # behavior, so the raw-share case must finish before the overlay exists.
  mount -t overlay overlay -o \
    lowerdir=/work,upperdir=/mnt/ovl/upper,workdir=/mnt/ovl/work,redirect_dir=on,metacopy=on,index=off \
    /mnt/ovl/merged
  echo "### overlay over the share ###";         /work/fsbench /mnt/ovl/merged '"$N"'
  echo "### in-guest tmpfs (/mnt/shm) ###";      /work/fsbench /mnt/shm        '"$N"'
'
