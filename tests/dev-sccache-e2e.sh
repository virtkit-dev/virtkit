#!/usr/bin/env bash
# Run sccache in a `vk dev` environment against a shared cache, with the settings
# docs/dev.md gives and no AWS keys. A lib crate builds once (a miss), then again with
# sccache's local state and cargo's target emptied (a hit from the shared cache). The
# startup probe and cached object must exist as flat files without corresponding tags.
#
# Run: SCCACHE=/path/to/sccache VK=./dist/vk tests/dev-sccache-e2e.sh
# SCCACHE must be a static x86_64 Linux build: it runs in the guest (the musl release
# binary works). The test skips without it. IMAGE defaults to a Rust image on Alpine.
# XDG_STATE_HOME, XDG_DATA_HOME and XDG_CACHE_HOME point into the scratch directory, so
# neither the host's environments nor its shared caches are touched; the image is pulled into
# it.
# KEEP_WORK=1 retains the scratch directory. STEP_TIMEOUT caps each `vk dev` step.
set -euo pipefail
cd "$(dirname "$0")/.."

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
IMAGE=${IMAGE:-docker.io/library/rust:1-alpine}
[ -n "${SCCACHE:-}" ] && [ -x "$SCCACHE" ] || { echo "SKIP: set SCCACHE to a static sccache"; exit 0; }
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "SKIP: no writable /dev/kvm"; exit 0; }
for t in git python3 timeout; do command -v "$t" >/dev/null || { echo "SKIP: no $t"; exit 0; }; done

# The guest's vsock socket path is capped at 108 bytes: keep the scratch root short.
base=${TMPDIR:-/tmp}
[ "${#base}" -le 40 ] || base=/tmp
WORK=$(mktemp -d "$base/vk-dev-sccache.XXXXXX")
WS=$WORK/ws
export XDG_STATE_HOME=$WORK/state XDG_DATA_HOME=$WORK/data XDG_CACHE_HOME=$WORK/cache
STORE=$XDG_CACHE_HOME/virtkit/shared-cache

vkd() { timeout -k 30 "${STEP_TIMEOUT:-900}" "$VK" dev "$@"; }
cleanup() {
  cd /
  if [ -d "$WS" ]; then
    (cd "$WS" && vkd stop >/dev/null 2>&1 && vkd gc --yes >/dev/null 2>&1) || true
  fi
  if [ -n "${KEEP_WORK:-}" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT INT TERM
fail() { echo "FAIL: $*"; exit 1; }

mkdir -p "$WS/bin" "$WS/crate/src" "$WS/.virtkit"
cp "$SCCACHE" "$WS/bin/sccache"
cat >"$WS/crate/Cargo.toml" <<'EOF'
[package]
name = "cached"
version = "0.1.0"
edition = "2021"
EOF
# A lib: sccache caches rlibs, not binaries.
printf 'pub fn answer() -> u32 { 42 }\n' >"$WS/crate/src/lib.rs"
cat >"$WS/.virtkit/config.toml" <<EOF
schema = 1

[dev]
image = "$IMAGE"
workspace = "/w"
freshness = "reuse"
cpus = 2
mem = "2G"
EOF
# What docs/dev.md puts in local.toml, plus a wrapper path and local state of the test's own.
cat >"$WS/.virtkit/local.toml" <<'EOF'
[dev.cache]
shared = ["sccache"]

[dev.exec-env]
SCCACHE_ENDPOINT = "http://registry.vk/s3"
SCCACHE_BUCKET = "job"
SCCACHE_S3_KEY_PREFIX = "sccache"
SCCACHE_REGION = "auto"
SCCACHE_S3_NO_CREDENTIALS = "true"
SCCACHE_S3_USE_SSL = "false"
RUSTC_WRAPPER = "/w/bin/sccache"
SCCACHE_DIR = "/tmp/sccache-local"
SCCACHE_IDLE_TIMEOUT = "0"
CARGO_TARGET_DIR = "/tmp/target"
# sccache does not cache incremental builds.
CARGO_INCREMENTAL = "0"
EOF
cd "$WS"
git init -q .
git -c user.email=e2e@virtkit -c user.name=e2e commit -q --allow-empty -m init

vkd up >"$WORK/up.log" 2>&1 || { cat "$WORK/up.log"; fail "dev up"; }

# One build from empty local state; the stats, as JSON, on the last line.
build() {
  vkd exec -- env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY sh -euc '
    /w/bin/sccache --stop-server >/dev/null 2>&1 || true
    rm -rf "$SCCACHE_DIR" "$CARGO_TARGET_DIR"
    /w/bin/sccache --start-server >&2
    cd /w/crate && cargo build --offline >&2
    /w/bin/sccache --show-stats --stats-format=json' 2>"$WORK/build.log" | tail -n 1
}
count() { python3 -c "import json,sys; s=json.load(sys.stdin)['stats']['$1']; print(sum(s['counts'].values()) if isinstance(s, dict) else s)"; }

first=$(build) || { cat "$WORK/build.log"; fail "the first build"; }
[ "$(count cache_misses <<<"$first")" = 1 ] || fail "expected one miss: $first"
[ "$(count cache_errors <<<"$first")" = 0 ] || fail "cache errors: $first"
second=$(build) || { cat "$WORK/build.log"; fail "the second build"; }
[ "$(count cache_hits <<<"$second")" = 1 ] || fail "expected one hit from the shared cache: $second"
[ "$(count cache_misses <<<"$second")" = 0 ] || fail "a miss on the second build: $second"
echo "ok: a miss, then a hit from the shared cache after emptying local state"

flat=$STORE/flat/dev+sccache/objects
probe=$(printf %s dev/sccache/.sccache_check | sha256sum | cut -c1-64)
[ -f "$flat/${probe:0:2}/$probe" ] || fail "no startup probe in the flat store: $(find "$STORE/flat" 2>&1 | head)"
objects=$(find "$flat" -type f ! -name "$probe" | wc -l)
[ "$objects" -ge 1 ] || fail "no cached object in the flat store"
[ ! -e "$STORE/repos/files/dev/sccache" ] || fail "unexpected tag repository at repos/files/dev/sccache"
echo "ok: the probe and $objects object(s) are files of the shared cache's flat store"
echo PASS
