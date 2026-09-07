#!/usr/bin/env bash
# =====================================================================================
# `vk toolchain` with no network: a hand-written lock, a cache filled by hand, three verbs.
# =====================================================================================
# The design's promise is that a verified tool cache works offline. Everything here is
# local: the artifacts are files this script writes, the lock records their real sha256s,
# and $VIRTKIT_TOOLCHAIN_CACHE points the cache at the scratch directory holding them — so
# `install --offline` has nothing to fetch and the URLs the lock carries are never reached.
#
# Done means every step below holds:
#   1. `install --offline` accepts a cache that already matches the lock, and says so.
#   2. `status` and `export` agree with it: the same paths, the locked digests.
#   3. a cached file that no longer hashes to the lock is reported by `status`, refused by
#      `export`, and fetched again by `install` — which `--offline` then cannot do.
#   4. `--artifact` narrows an install to one name, and names one the lock does not carry.
#   5. a lock that pins a version or an artifact name that is not one, that gives an entry
#      no URL, or that covers no platform of ours, is refused rather than acted on.
#
# Run:  VK=./dist/vk tests/toolchain-e2e.sh
# Needs: a `vk` binary and sha256sum. No network, no KVM, no image.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
command -v sha256sum >/dev/null || { echo "SKIP: no sha256sum"; exit 0; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-toolchain-e2e.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
WS=$WORK/ws
VERSION=0.99.0
export VIRTKIT_TOOLCHAIN_CACHE=$WORK/cache
CACHE=$VIRTKIT_TOOLCHAIN_CACHE/$VERSION

pass=0
fail=0
ok() { echo "PASS: $*"; pass=$((pass + 1)); }
bad() { echo "FAIL: $*"; fail=$((fail + 1)); }
vkt() { "$VK" toolchain "$@"; }

# The stand-in release: a runnable vk and a kernel-shaped blob, so the two modes an install
# publishes with (0755 and 0644) are both exercised.
mkdir -p "$CACHE" "$WS/.virtkit"
printf '#!/bin/sh\necho "vk %s (stand-in)"\n' "$VERSION" > "$CACHE/vk"
printf 'not really a kernel\n' > "$CACHE/vmlinux"
chmod 0755 "$CACHE/vk"
sum() { sha256sum "$1" | cut -d' ' -f1; }
SUM_VK=$(sum "$CACHE/vk")
SUM_KERNEL=$(sum "$CACHE/vmlinux")

# The URLs are deliberately unreachable: an offline install that touched one would fail,
# which is the point of writing them down.
lock_file=$WS/.virtkit/toolchain.lock
write_lock() {
  cat > "$lock_file" <<EOF
version = "${1:-$VERSION}"

[artifacts.vk.linux-x86_64]
sha256 = "$SUM_VK"
urls = ["https://127.0.0.1:1/v$VERSION/vk"]

[artifacts.vmlinux.linux-x86_64]
sha256 = "$SUM_KERNEL"
urls = ["https://127.0.0.1:1/v$VERSION/vmlinux"]
EOF
}
write_lock
cd "$WS"

echo
echo "== 1. an install with everything already cached needs no network =="
if out=$(vkt install --offline 2>&1); then
  ok "install --offline accepted the filled cache"
else
  bad "install --offline failed"
  echo "$out"
  exit 1
fi
grep -qE "^vk .* cached $CACHE/vk\$" <<<"$out" && ok "it reports vk as cached" || { bad "install did not report vk as cached"; echo "$out"; }
grep -qE "^vmlinux .* cached $CACHE/vmlinux\$" <<<"$out" && ok "it reports vmlinux as cached" || bad "install did not report vmlinux as cached"

echo
echo "== 2. status and export agree with the cache =="
st=$(vkt status)
grep -qE "^version +$VERSION \(linux-x86_64\)\$" <<<"$st" && ok "status names the locked version and platform" || { bad "status lost the version line"; echo "$st"; }
grep -qF "installed $CACHE/vk" <<<"$st" && ok "status: vk installed" || { bad "status did not call vk installed"; echo "$st"; }
grep -qF "installed $CACHE/vmlinux" <<<"$st" && ok "status: vmlinux installed" || bad "status did not call vmlinux installed"
# The running binary is a row of its own, and not a second one labelled `vk`.
grep -qE "^this vk +.*$VK" <<<"$st" && ok "status labels the running binary 'this vk'" || { bad "status did not label the running binary"; echo "$st"; }
[ "$(grep -cE '^vk +' <<<"$st")" -eq 1 ] && ok "only one row is labelled vk" || { bad "two rows are labelled vk"; echo "$st"; }

eval "$(vkt export)"
[ "${VIRTKIT_VERSION:-}" = "$VERSION" ] && ok "export sets VIRTKIT_VERSION" || bad "export set VIRTKIT_VERSION=${VIRTKIT_VERSION:-}"
[ "${VIRTKIT_VK:-}" = "$CACHE/vk" ] && ok "export points VIRTKIT_VK at the cached artifact" || bad "export set VIRTKIT_VK=${VIRTKIT_VK:-}"
[ "${VIRTKIT_VK_SHA256:-}" = "$SUM_VK" ] && ok "export carries the locked digest beside it" || bad "export set VIRTKIT_VK_SHA256=${VIRTKIT_VK_SHA256:-}"
[ "${VIRTKIT_VMLINUX:-}" = "$CACHE/vmlinux" ] && ok "export points VIRTKIT_VMLINUX at the kernel" || bad "export set VIRTKIT_VMLINUX=${VIRTKIT_VMLINUX:-}"
"$VIRTKIT_VK" | grep -q "$VERSION" && ok "the exported path runs" || bad "the exported VIRTKIT_VK did not run"
json=$(vkt export --format json)
grep -qF "\"VIRTKIT_VK\": \"$CACHE/vk\"" <<<"$json" && ok "the JSON form carries the same path" || { bad "the JSON form disagrees"; echo "$json"; }

echo
echo "== 3. a cached file that no longer matches is not the locked artifact =="
printf 'tampered\n' > "$CACHE/vk"
grep -qF "$CACHE/vk does not match the lock" <<<"$(vkt status)" && ok "status reports the mismatch" || bad "status still called the tampered vk installed"
vk_var=$(vkt export | sed -n "s/^VIRTKIT_VK='\(.*\)'\$/\1/p")
[ -z "$vk_var" ] && ok "export refuses to hand out the tampered path" || bad "export still exported VIRTKIT_VK=$vk_var"
rc=0; out=$(vkt install --offline 2>&1) || rc=$?
[ "$rc" -ne 0 ] && ok "install --offline fails rather than accepting it" || { bad "install --offline accepted the tampered cache"; echo "$out"; }
grep -q "vk is not in the cache" <<<"$out" && ok "it names the artifact it cannot supply" || { bad "the offline refusal did not name vk"; echo "$out"; }
printf '#!/bin/sh\necho "vk %s (stand-in)"\n' "$VERSION" > "$CACHE/vk"
chmod 0755 "$CACHE/vk"
vkt install --offline >/dev/null && ok "restoring the bytes makes it installed again" || bad "the restored artifact is still not installed"

echo
echo "== 4. --artifact narrows the install =="
rm -f "$CACHE/vmlinux"
vkt install --offline --artifact vk >/dev/null && ok "--artifact vk ignores the missing kernel" || bad "--artifact vk did not narrow the install"
rc=0; out=$(vkt install --offline 2>&1) || rc=$?
[ "$rc" -ne 0 ] && grep -q vmlinux <<<"$out" && ok "a full install still misses the kernel" || { bad "the missing kernel went unreported"; echo "$out"; }
rc=0; out=$(vkt install --offline --artifact nope 2>&1) || rc=$?
[ "$rc" -ne 0 ] && grep -q "no nope artifact" <<<"$out" && ok "an artifact the lock does not carry is an error" || { bad "--artifact nope was accepted"; echo "$out"; }
printf 'not really a kernel\n' > "$CACHE/vmlinux"

echo
echo "== 5. a lock that could not be acted on safely is refused =="
refuses() {
  local what=$1 rc=0 out
  out=$(vkt status 2>&1) || rc=$?
  [ "$rc" -ne 0 ] && ok "$what is refused" || { bad "$what was accepted"; echo "$out"; }
}
write_lock '../../../../tmp/pwn'
refuses "a version that walks out of the cache"
write_lock "$VERSION"
sed -i 's/^\[artifacts\.vk\./[artifacts."..\/evil"./' "$lock_file"
refuses "an artifact name that walks out of the cache"
write_lock "$VERSION"
sed -i "s|^urls = \[\"https://127.0.0.1:1/v$VERSION/vk\"\]|urls = []|" "$lock_file"
refuses "an entry with no url to fetch from"
# Nothing for this platform: the install has to say so rather than exit 0 having done
# nothing, and name the platforms the lock does cover.
write_lock "$VERSION"
sed -i 's/\.linux-x86_64\]/.macos-aarch64]/' "$lock_file"
rc=0; out=$(vkt install --offline 2>&1) || rc=$?
[ "$rc" -ne 0 ] && grep -q "macos-aarch64" <<<"$out" && ok "a lock covering no platform of ours fails the install" || { bad "an install with nothing to do exited $rc"; echo "$out"; }

echo
echo "================ $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
