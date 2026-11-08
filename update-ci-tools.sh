#!/usr/bin/env bash
# Re-pin vk-hub's built-in CI tools definition (vk-hub/ci-tools/), then exit.
#
#   ./update-ci-tools.sh            nixpkgs at the commit .devcontainer/nix/flake.lock pins
#   ./update-ci-tools.sh --latest   nixpkgs at the head of nixos-unstable
#
# Rewrites the nixos/nix base image digest in vk-hub/ci-tools/Dockerfile, re-locks
# vk-hub/ci-tools/flake.lock, pins git-lfs in flake.nix to upstream's release of the version
# that nixpkgs packages, by sha256, and writes the versions the flake builds into the
# Dockerfile's GIT_VERSION / GIT_LFS_VERSION, which label the definition. Review the diff and
# commit it: the next vk-hub built holds the new definition, and nodes the hub
# keeps on the built-in tools build it. Idempotent: a no-op when already current. Requires
# docker and curl: it resolves the base digest, Nix runs in the nixos/nix image, never on
# the host, and curl fetches the release it pins.
set -euo pipefail
cd "$(dirname "$0")"

LATEST=0
case "${1:-}" in
    "") ;;
    --latest) LATEST=1 ;;
    *) echo >&2 "usage: $0 [--latest]"; exit 2 ;;
esac

DIR=vk-hub/ci-tools

# Base image: NIX_TAG fixes the nixos/nix release, as ./update.sh does for the build image.
NIX_TAG="${NIX_TAG:-2.35.2}"
IMG="nixos/nix:${NIX_TAG}"
DIGEST=$(docker buildx imagetools inspect "$IMG" | sed -nE 's/^Digest:[[:space:]]+//p' | head -1)
case "$DIGEST" in
    sha256:*) ;;
    *) echo >&2 "ERROR: could not resolve the digest of $IMG (got '$DIGEST')"; exit 1 ;;
esac
sed -i -E "s#^FROM nixos/nix:[^ ]*#FROM ${IMG}@${DIGEST}#" "$DIR/Dockerfile"

# nixpkgs: the build image's commit, so both build from one nixpkgs, unless --latest.
if [ "$LATEST" = 1 ]; then
    LOCK="flake update --flake path:/flake"
else
    REV=$(awk -v n='"nixpkgs": {' \
        'index($0, n) { f = 1 } f && /"rev":/ { gsub(/[",]/, "", $2); print $2; exit }' \
        .devcontainer/nix/flake.lock)
    [[ "$REV" =~ ^[0-9a-f]{40}$ ]] || {
        echo >&2 "ERROR: no nixpkgs commit in .devcontainer/nix/flake.lock (got '$REV')"
        exit 1
    }
    LOCK="flake lock --flake path:/flake --override-input nixpkgs github:NixOS/nixpkgs/$REV"
fi

# Re-lock inside the (pinned) image and read the versions nixpkgs packages there. The lock is
# written back through the bind mount as root; hand it back.
NIX="nix --extra-experimental-features nix-command --extra-experimental-features flakes"
nixed() { # <shell script>, run against the flake at /flake
    docker run --rm -v "$PWD/$DIR:/flake" "${IMG}@${DIGEST}" sh -ec "$1"
}
packaged=$(nixed "
    $NIX $LOCK >&2
    chown $(id -u):$(id -g) /flake/flake.lock
    printf 'git-lfs=%s\\n' \"\$($NIX eval --raw path:/flake#packaged.git-lfs)\"")

checked_version() { # <tool> <name=version lines>
    local v
    v=$(printf '%s\n' "$2" | sed -nE "s/^$1=(.+)$/\\1/p")
    [[ "$v" =~ ^[0-9][0-9A-Za-z.+_-]*$ ]] || { echo >&2 "ERROR: $1's version looks wrong: '$v'"; exit 1; }
    printf '%s\n' "$v"
}

# git-lfs: upstream's static release of the version nixpkgs packages, pinned by sha256 in
# flake.nix.
pin_release() { # <version-var> <sha-var> <version> <url>
    local sha
    echo "pinning $1 = $3 from $4 ..."
    sha=$(curl -fsSL --connect-timeout 10 --speed-limit 1024 --speed-time 30 "$4" | sha256sum | cut -d' ' -f1)
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo >&2 "ERROR: $2 looks wrong: '$sha'"; exit 1; }
    sed -i -E "s#^( *$1 = )\"[^\"]*\";#\\1\"$3\";#; s#^( *$2 = )\"[^\"]*\";#\\1\"$sha\";#" "$DIR/flake.nix"
}
lfs=$(checked_version git-lfs "$packaged")
pin_release gitLfsVersion gitLfsSha256 "$lfs" \
    "https://github.com/git-lfs/git-lfs/releases/download/v${lfs}/git-lfs-linux-amd64-v${lfs}.tar.gz"

# The labels: what the flake builds now, which the Dockerfile checks at build time.
versions=$(nixed "
    for n in git git-lfs; do
        printf '%s=%s\\n' \"\$n\" \"\$($NIX eval --no-update-lock-file --raw path:/flake#versions.\$n)\"
    done")
pin() { # <arg-name> <tool>
    local v
    v=$(checked_version "$2" "$versions")
    sed -i -E "s#^ARG $1=.*#ARG $1=$v#" "$DIR/Dockerfile"
}
pin GIT_VERSION git
pin GIT_LFS_VERSION git-lfs

echo "updated:"
grep -E '^FROM nixos' "$DIR/Dockerfile"
grep -E '^ARG GIT' "$DIR/Dockerfile" | sed 's/^/  /'
printf 'nixpkgs: %s\n' "$(awk '/"rev":/ { gsub(/[",]/, "", $2); print $2; exit }' "$DIR/flake.lock")"
