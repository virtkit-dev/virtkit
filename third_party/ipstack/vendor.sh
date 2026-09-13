#!/usr/bin/env bash
# vendor.sh — refresh third_party/ipstack from the virtkit-dev/ipstack fork.
#
#   third_party/ipstack/vendor.sh <fork checkout> [rev]
#
# Copies `rev` (default: main) of a checkout of https://github.com/virtkit-dev/ipstack
# over this directory, from `git archive`, so an uncommitted edit in the fork cannot leak
# in. Everything vendored before is deleted first, so a file the fork drops disappears
# here too.
#
# What the copy is trimmed to, and why:
#
#   - No dev-dependencies, no examples or benches, and no criterion harness in
#     `src/packet.rs`. Cargo refuses to test a patched crate outside the workspace that
#     declares dev-dependencies, and `./dev.sh test -p ipstack` is how this copy's tests
#     are run.
#   - The doc examples that reach for a dev-dependency are marked `ignore`: a `no_run`
#     example is still compiled by `cargo test`.
#   - No `[profile.*]`: a patched crate builds under the workspace's profiles, and cargo
#     warns about the ones it is ignoring.
#
# `rustfmt.toml` is vendored with the sources so an editor, or a `cargo fmt` run from this
# directory, keeps the fork's width and the copy stays comparable with it line for line.
# The workspace's own `cargo fmt --all` does not reach a crate it only patches in.
#
# Cargo.lock is regenerated at the end through ./dev.sh, which runs cargo in the
# development VM; nothing here builds on the host.
set -euo pipefail

usage() {
  echo "usage: third_party/ipstack/vendor.sh <fork checkout> [rev]" >&2
  exit 2
}

fork=${1:-}
rev=${2:-main}
[ -n "$fork" ] && [ "$#" -le 2 ] || usage
[ -d "$fork/.git" ] || {
  echo "vendor.sh: $fork is not a git checkout of the fork" >&2
  exit 1
}

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
sha=$(git -C "$fork" rev-parse --verify "$rev^{commit}")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$fork" archive --format=tar "$sha" \
  Cargo.toml LICENSE README.md rustfmt.toml build.rs src | tar -xf - -C "$tmp"

find "$here" -mindepth 1 -maxdepth 1 \
  ! -name VENDOR.md ! -name vendor.sh ! -name Cargo.lock -exec rm -rf {} +
cp -R "$tmp/." "$here/"

# Drop the sections a vendored, patched crate must not carry. A section runs to the next
# header at column 0; the comments leading up to a dropped header go with it.
awk '
  /^[[:space:]]*(#|$)/ { held = held $0 "\n"; next }
  /^\[/ {
    drop = ($0 ~ /^\[dev-dependencies/ || $0 ~ /^\[profile\./ ||
            $0 ~ /^\[\[(example|bench)\]\]/ ||
            ($0 ~ /^\[target\./ && $0 ~ /dev-dependencies/))
  }
  drop { held = ""; next }
  { printf "%s", held; held = ""; print }
' "$here/Cargo.toml" >"$tmp/Cargo.toml"
mv "$tmp/Cargo.toml" "$here/Cargo.toml"

# `src/packet.rs` ends in a `#[cfg(test)]` module that is a criterion benchmark rather
# than a unit test; it goes with the dev-dependency it is written against.
packet=$here/src/packet.rs
if grep -q 'use criterion::' "$packet"; then
  start=$(grep -n '^#\[cfg(test)\]$' "$packet" | tail -n 1 | cut -d: -f1)
  head -n "$((start - 1))" "$packet" |
    awk 'NF { while (blank-- > 0) print ""; blank = 0; print; next } { blank++ }' >"$tmp/packet.rs"
  mv "$tmp/packet.rs" "$packet"
fi
if grep -rl 'criterion' "$here/src" >/dev/null; then
  echo "vendor.sh: criterion is still referenced under src/ — trim it by hand" >&2
  exit 1
fi

# A `no_run` doc example is still compiled, so the ones that reach for a dev-dependency
# have to be `ignore`d. The rest keep their compile coverage.
find "$here/src" -name '*.rs' -print0 | { printf '%s\0' "$here/README.md"; cat; } |
  while IFS= read -r -d '' f; do
    awk '
    { line[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        body = line[i]
        sub(/^[[:space:]]*(\/\/\/|\/\/!)[[:space:]]?/, "", body)
        sub(/^[[:space:]]+/, "", body)
        if (body ~ /^```/) {
          if (open) { if (needs) sub(/no_run/, "ignore", line[start]); open = 0 }
          else if (body ~ /no_run/) { open = 1; start = i; needs = 0 }
          continue
        }
        if (open && line[i] ~ /(^|[^_[:alnum:]])(tun|udp_stream)::/) needs = 1
      }
      for (i = 1; i <= NR; i++) print line[i]
    }
    ' "$f" >"$tmp/doc" && mv "$tmp/doc" "$f"
  done

cat >"$here/VENDOR.md" <<EOF
# Vendored ipstack

Source: https://github.com/virtkit-dev/ipstack
Revision: \`$sha\`

Our fork of [narrowlink/ipstack](https://github.com/narrowlink/ipstack), branched from
upstream \`e1d8506\`. Every fix the switch needs lives there as its own commit, written to go
upstream as a pull request; nothing is patched here, so \`git log\` in the fork is the patch
list.

Refresh it with \`third_party/ipstack/vendor.sh <fork checkout> [rev]\`, which copies the
sources, trims the manifest down to what a patched crate outside the workspace can carry
(see the script's header) and regenerates \`Cargo.lock\`.

The root workspace's \`[patch.crates-io]\` points the \`ipstack\` dependency here, so the
switch (\`vk-driver/src/switch.rs\`) builds against this copy. Its requirement spells out the
fork's pre-release version, because a plain requirement matches none; keep the two in step
when the fork's version moves. Run the tests with \`./dev.sh test -p ipstack\`.
EOF

# Resolves the trimmed manifest and writes Cargo.lock, which is kept for a standalone
# build of this workspace-excluded crate.
"$root/dev.sh" check --manifest-path third_party/ipstack/Cargo.toml --lib
