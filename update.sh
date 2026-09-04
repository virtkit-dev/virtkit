#!/usr/bin/env bash
# Bump the pinned Rust toolchain to the latest stable release and re-pin the build inputs.
#
# Rewrites the channel in rust-toolchain.toml and in .devcontainer/nix/flake.nix (the flake
# pins it inline — it cannot read rust-toolchain.toml from inside the .devcontainer build
# context), re-locks .devcontainer/nix/flake.lock (nixpkgs + rust-overlay, so the new channel
# is known and the packages move with it), and re-pins the nixos/nix base image digest in
# .devcontainer/Dockerfile. Review the diff, then run ./build-kernel.sh and ./build.sh — a
# toolchain bump re-baselines every artifact hash. Idempotent: a no-op when already current.
# Requires docker: it resolves the base digest, and Nix runs in the nixos/nix image, never
# on the host.
set -euo pipefail
cd "$(dirname "$0")"

# Ask the local rustup for the latest stable version rather than scraping release pages.
rustup update stable
LATEST=$(rustup run stable rustc --version | awk '{print $2}')
echo "latest stable: $LATEST"

sed -i -E "s/^channel = \".*\"/channel = \"$LATEST\"/" rust-toolchain.toml
sed -i -E "s/rust-bin\.stable\.\"[0-9.]+\"/rust-bin.stable.\"$LATEST\"/" .devcontainer/nix/flake.nix

# Base image: NIX_TAG fixes the nixos/nix release; bump it deliberately (it is only the Nix
# that realizes the flake — the toolchain itself comes from nixpkgs). Pin its manifest-list
# digest so the FROM line stays a digest, not a tag.
NIX_TAG="${NIX_TAG:-2.35.2}"
IMG="nixos/nix:${NIX_TAG}"
DIGEST=$(docker buildx imagetools inspect "$IMG" | sed -nE 's/^Digest:[[:space:]]+//p' | head -1)
case "$DIGEST" in
    sha256:*) ;;
    *) echo >&2 "ERROR: could not resolve the digest of $IMG (got '$DIGEST')"; exit 1 ;;
esac
sed -i -E "s#^FROM nixos/nix:[^ ]*#FROM ${IMG}@${DIGEST}#" .devcontainer/Dockerfile

# Re-lock the flake inside that (pinned) image. `flake update` moves every input: rust-overlay
# must be current for the new channel to exist at all, and nixpkgs moves with it. Then
# evaluate the toolchain closure once so an unknown channel fails here, not in the first
# ./build.sh. The lock is written back through the bind mount as root; hand it back.
NIX="nix --extra-experimental-features nix-command --extra-experimental-features flakes"
docker run --rm -v "$PWD/.devcontainer/nix:/flake" "${IMG}@${DIGEST}" sh -ec "
    $NIX flake update --flake path:/flake
    $NIX eval --raw 'path:/flake#packages.x86_64-linux.buildEnv.drvPath' >/dev/null
    chown $(id -u):$(id -g) /flake/flake.lock"

echo "updated:"
grep -E '^channel' rust-toolchain.toml
grep -oE 'rust-bin\.stable\."[0-9.]+"' .devcontainer/nix/flake.nix
grep -E '^FROM' .devcontainer/Dockerfile
for k in nixpkgs rust-overlay; do
    printf '%s: %s\n' "$k" "$(awk -v n="\"$k\": {" \
        'index($0, n) { f = 1 } f && /"rev":/ { gsub(/[",]/, "", $2); print $2; exit }' \
        .devcontainer/nix/flake.lock)"
done
