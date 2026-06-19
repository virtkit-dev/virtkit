#!/usr/bin/env bash
# Bump the pinned guest kernel to the latest LTS (longterm) release, or --stable.
#
# Defaults to the newest longterm series, the right choice for a fleet of microVMs:
# years of upstream security/stability backports without chasing every mainline bump.
# Pass --stable to track the latest stable release instead.
#
# Rewrites KERNEL_VERSION + KERNEL_SHA256 in kernel/Dockerfile (and the vN.x download
# path, so a new major stays consistent) from kernel.org's published values. Review the
# diff, then run ./build-kernel.sh — the Dockerfile re-verifies the sha256 at build time,
# so a bad pin fails the build loudly. Idempotent: a no-op when already current. Requires
# curl. Kept separate from update.sh (the Rust toolchain) since the kernel moves on its
# own cadence.
set -euo pipefail
cd "$(dirname "$0")"

CHANNEL=lts
case "${1:-}" in
    ""|--lts) ;;
    --stable) CHANNEL=stable ;;
    *) echo >&2 "usage: $0 [--lts|--stable]"; exit 2 ;;
esac

# kernel.org's finger banner is the canonical source — stable plain-text lines, unlike
# releases.json which needs a JSON parser. For LTS, several "longterm" series are listed;
# pick the highest-versioned one (sort -V) as "the latest LTS".
BANNER=$(curl -fsSL https://www.kernel.org/finger_banner)
if [ "$CHANNEL" = stable ]; then
    LATEST=$(printf '%s\n' "$BANNER" \
        | sed -nE 's/^The latest stable version of the Linux kernel is:[[:space:]]*([0-9.]+)$/\1/p')
else
    LATEST=$(printf '%s\n' "$BANNER" \
        | sed -nE 's/^The latest longterm [0-9.]+ version of the Linux kernel is:[[:space:]]*([0-9.]+)$/\1/p' \
        | sort -V | tail -1)
fi
case "$LATEST" in
    [0-9]*.[0-9]*) ;; # looks like a version
    *) echo >&2 "ERROR: could not parse latest $CHANNEL kernel version (got '$LATEST')"; exit 1 ;;
esac
echo "latest $CHANNEL kernel: $LATEST"

CURRENT=$(sed -nE 's/^ARG KERNEL_VERSION=(.*)$/\1/p' kernel/Dockerfile)
if [ "$CURRENT" = "$LATEST" ]; then
    echo "kernel/Dockerfile is already on $LATEST — nothing to do."
    exit 0
fi

# Tarballs live under v<major>.x/; resolve the matching sha256 from the per-major
# checksum file (the same URL the Dockerfile comment points at).
VDIR="v${LATEST%%.*}.x"
SUMS_URL="https://cdn.kernel.org/pub/linux/kernel/${VDIR}/sha256sums.asc"
echo "resolving sha256 for linux-${LATEST}.tar.xz from ${SUMS_URL} ..."
SHA=$(curl -fsSL "$SUMS_URL" | awk -v f="linux-${LATEST}.tar.xz" '$2 == f { print $1 }')
# a sha256 is exactly 64 lowercase hex digits
if ! [[ "$SHA" =~ ^[0-9a-f]{64}$ ]]; then
    echo >&2 "ERROR: no valid sha256 for linux-${LATEST}.tar.xz in ${SUMS_URL} (got '$SHA')"
    exit 1
fi

sed -i -E \
    -e "s/^ARG KERNEL_VERSION=.*/ARG KERNEL_VERSION=${LATEST}/" \
    -e "s/^ARG KERNEL_SHA256=.*/ARG KERNEL_SHA256=${SHA}/" \
    -e "s#/v[0-9]+\.x/#/${VDIR}/#g" \
    kernel/Dockerfile

echo "updated kernel/Dockerfile ($CURRENT -> $LATEST):"
grep -nE '^ARG KERNEL_|sha256sums\.asc' kernel/Dockerfile | sed 's/^/  /'
echo "review the diff, then run ./build-kernel.sh"
