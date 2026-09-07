#!/bin/sh
# Install `vk` from a GitHub release — the bootstrap for a host that has no vk yet.
#
#   curl -fsSL https://github.com/virtkit-dev/virtkit/releases/latest/download/install.sh | sh
#
# Which release: $VIRTKIT_VERSION, else the `.virtkit/toolchain.lock` in the current
# directory or above it (so running this from a checkout installs exactly what the project
# pins, verified against the checksum the lock records), else the latest release.
#
# Where from: $VIRTKIT_DIST_URL is tried first; the lock's URLs, in the order it lists
# them, and GitHub follow. Each candidate is tried in turn. The download is checked against
# the lock's checksum, or against the `.sha256` published beside the asset when there is no
# lock — a truncated or corrupted transfer never becomes the installed binary.
#
# Where to: $BINDIR, else $XDG_BIN_HOME, else ~/.local/bin. The binary is published with a
# rename, so the destination is never a half-written file.
#
# Needs sh, curl or wget, and sha256sum or shasum. Deliberately nothing of vk's: this is
# what runs when there is no vk to run.
#
# POSIX sh, so two of the repo's shell conventions are deliberately absent. There is no
# `pipefail` to set: every pipeline whose failure matters is captured into a variable first
# and filtered afterwards. And no `cd "$(dirname "$0")"`: piped from curl there is no
# script file to find, and the current directory is what the lock is looked up from.

set -eu

REPO=virtkit-dev/virtkit
API=https://api.github.com
RELEASES=https://github.com/virtkit-dev/virtkit/releases/download
LOCK_FILE=.virtkit/toolchain.lock

usage() {
  cat <<EOF
Usage: install.sh [--force] [--help]

Install the vk binary from a virtkit release.

  --force   install even when that version is already there
  --help    print this and exit

Environment:
  VIRTKIT_VERSION   release to install (0.60.0 or v0.60.0)
  VIRTKIT_DIST_URL  base URL tried before the lock's URLs and $RELEASES
  BINDIR            install directory (default: \${XDG_BIN_HOME:-\$HOME/.local/bin})
EOF
}

force=
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "install.sh: unknown argument $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

die() {
  echo "install.sh: $*" >&2
  exit 1
}

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
  fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
  fetch_stdout() { wget -q -O - "$1"; }
else
  die "neither curl nor wget is installed"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "neither sha256sum nor shasum is installed"
fi

# The platform key the lock stores entries under: `<os>-<arch>`, as vk itself builds it —
# from Rust's own names for both, which are not uname's, so the two that differ are mapped.
# Releases are linux-x86_64 today; the mapping is here so a lock written elsewhere is read
# under the key it was written with.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in darwin) os=macos ;; esac
arch=$(uname -m)
case "$arch" in arm64) arch=aarch64 ;; esac
platform="$os-$arch"

# --- the lock, when there is one ---------------------------------------------------
#
# `.virtkit/toolchain.lock` is TOML written by `vk toolchain lock`. Only three things are
# read out of it — the version, and this platform's vk checksum and URLs — and the parsing
# below stays tolerant of layout: a table header is matched with its quoting and spacing
# removed, and `urls` is read as every quoted string from the `urls =` line up to the
# closing bracket, whether the writer put the array on one line or many. Anything it cannot
# find simply falls back to the release on GitHub.

# Stops at the checkout root, as vk's own lookup does: walking all the way to / would let
# a lock in $HOME decide what a directory with no project of its own installs.
find_lock() {
  dir=$PWD
  while :; do
    if [ -f "$dir/$LOCK_FILE" ]; then
      printf '%s\n' "$dir/$LOCK_FILE"
      return 0
    fi
    [ ! -e "$dir/.git" ] || return 1
    [ "$dir" != "/" ] || return 1
    dir=$(dirname "$dir")
  done
}

read_lock_version() {
  sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n 1
}

# One field of `[artifacts.vk.<platform>]`: the sha256, or every URL, one per line.
lock_field() {
  awk -v want="artifacts.vk.$2" -v field="$3" '
    /^[ \t]*\[/ {
      head = $0
      gsub(/[][" \t]/, "", head)
      inblock = (head == want)
      urls = 0
      next
    }
    !inblock { next }
    field == "sha256" && $1 == "sha256" {
      n = split($0, p, "\"")
      if (n >= 2) { print p[2]; exit }
    }
    field == "urls" && $1 == "urls" { urls = 1 }
    field == "urls" && urls {
      n = split($0, p, "\"")
      for (i = 2; i <= n; i += 2) print p[i]
      if (index($0, "]") > 0) exit
    }
  ' "$1"
}

lock=$(find_lock || true)
lock_version= lock_sha= lock_urls=
if [ -n "$lock" ]; then
  lock_version=$(read_lock_version "$lock")
  lock_sha=$(lock_field "$lock" "$platform" sha256)
  lock_urls=$(lock_field "$lock" "$platform" urls)
fi

# --- which release ------------------------------------------------------------------

version=${VIRTKIT_VERSION:-}
version=${version#v}
if [ -n "$version" ]; then
  origin="VIRTKIT_VERSION"
elif [ -n "$lock_version" ]; then
  version=$lock_version
  origin="$lock"
else
  # The tag of the latest release, from one JSON field; no jq on a bootstrap host. The
  # body is captured before it is filtered: a pipeline's status is its last command's, so
  # filtering in the same line would report every network failure as an empty release list.
  latest=$(fetch_stdout "$API/repos/$REPO/releases/latest") ||
    die "cannot reach $API to find the latest release"
  tag=$(printf '%s\n' "$latest" |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$tag" ] || die "no latest release in $REPO"
  version=${tag#v}
  origin="the latest release"
fi

# The lock's checksum and URLs describe the version it pins, and nothing else.
if [ "$version" != "$lock_version" ]; then
  lock_sha= lock_urls=
fi

# --- where from -----------------------------------------------------------------------

urls=
add_url() { urls="${urls:+$urls
}$1"; }
[ -z "${VIRTKIT_DIST_URL:-}" ] || add_url "${VIRTKIT_DIST_URL%/}/v$version/vk"
[ -z "$lock_urls" ] || add_url "$lock_urls"
case "$urls" in
  *"$RELEASES/v$version/vk"*) ;;
  *) add_url "$RELEASES/v$version/vk" ;;
esac

# --- where to --------------------------------------------------------------------------

if [ -n "${BINDIR:-}" ]; then
  bindir=$BINDIR
elif [ -n "${XDG_BIN_HOME:-}" ]; then
  bindir=$XDG_BIN_HOME
elif [ -n "${HOME:-}" ]; then
  bindir=$HOME/.local/bin
else
  die "set BINDIR: neither it, XDG_BIN_HOME nor HOME says where to install"
fi
mkdir -p "$bindir" || die "cannot create $bindir"
# Absolute from here on: every message names it, and the PATH note below compares it
# against $PATH, where a relative directory means nothing.
bindir=$(cd "$bindir" && pwd) || die "cannot enter $bindir"
dest=$bindir/vk

if [ -z "$force" ] && [ -x "$dest" ] && "$dest" --version 2>/dev/null | grep -q "[ ]$version[ (]"; then
  echo "vk $version is already installed at $dest"
  exit 0
fi

tmp=$bindir/.vk.install.$$
# A signal has to end the run, not just clean up after it: a handler that returns leaves
# the interrupted download to be swallowed by the mirror loop below and the next URL tried.
trap 'rm -f "$tmp"' EXIT
trap 'rm -f "$tmp"; exit 130' INT
trap 'rm -f "$tmp"; exit 143' TERM

echo "installing vk $version ($origin) into $bindir"

got=
for url in $urls; do
  rm -f "$tmp"
  fetch "$url" "$tmp" 2>/dev/null || {
    echo "  $url: unavailable" >&2
    continue
  }
  want=$lock_sha
  if [ -z "$want" ]; then
    # No lock to check against: the digest published beside the asset, which catches a
    # corrupted or truncated transfer of the release this URL is serving.
    sidecar=$(fetch_stdout "$url.sha256" 2>/dev/null) || {
      echo "  $url: no vk.sha256 published beside it" >&2
      continue
    }
    want=$(printf '%s\n' "$sidecar" |
      sed -n 's/^\([0-9a-f]*\)[[:space:]][[:space:]]*[*]\{0,1\}vk$/\1/p' | head -n 1)
    [ -n "$want" ] || {
      echo "  $url: its vk.sha256 has no line for vk" >&2
      continue
    }
  fi
  have=$(sha256_of "$tmp")
  if [ "$have" != "$want" ]; then
    echo "  $url: sha256 $have, expected $want" >&2
    continue
  fi
  got=$url
  break
done
[ -n "$got" ] || die "could not download a verified vk $version"

chmod 0755 "$tmp"
mv -f "$tmp" "$dest"
trap - EXIT INT TERM

echo "installed $("$dest" --version 2>/dev/null || echo "vk $version") as $dest"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) echo "note: $bindir is not on your PATH — add it with: export PATH=\"$bindir:\$PATH\"" ;;
esac
if [ -n "$lock" ] && [ "$version" = "$lock_version" ]; then
  echo "note: \`vk toolchain install\` fetches the rest of what $lock pins"
fi
