#!/usr/bin/env bash
# A registry the hub manages, end to end, on this host (no VM): a `vk-hub serve` and a
# `vk-registry serve` on loopback.
#
# 1. A registry token enrolls the registry (`vk-registry join`); `serve` reports in, its mode
#    and keys untouched, and the hub lists it connected.
# 2. The hub makes it read-only: a push is refused with 503 while reads go on; writable again,
#    the push is taken.
# 3. A command its `[hub] allow` does not list is refused, and reported refused.
# 4. An update to a vk-registry release the hub holds: the registry downloads it, runs it on
#    trial, and once back in session installs it over its own binary; then a second one.
# 5. `vk-registry leave` forgets the hub; `vk-hub registries remove` the registry.
#
# Run:  DIST=./dist tests/registry-hub-e2e.sh
# Needs: dist/vk-hub and dist/vk-registry built from this tree (./build.sh), curl.
set -euo pipefail

DIST=$(cd "${DIST:-./dist}" && pwd)
for b in vk-hub vk-registry; do
  [ -x "$DIST/$b" ] || { echo "no $DIST/$b (build it: ./build.sh)"; exit 2; }
done
WORK=$(mktemp -d "${WORK_DIR:-$HOME}/vk-registry-hub-e2e.XXXXXX")
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  echo "--- hub log"; tail -n 30 "$WORK/hub.log" || true
  echo "--- registry log"; tail -n 30 "$WORK/registry.log" || true
  exit 1
}
wait_for() {
  local secs=$1; shift
  for _ in $(seq "$((secs * 2))"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

HUB_PORT=$(port)
REG_PORT=$(port)
mkdir -p "$WORK/hub" "$WORK/store" "$WORK/bin"
cat >"$WORK/hub.toml" <<EOF
addr = "127.0.0.1:$HUB_PORT"
data_dir = "$WORK/hub"
EOF
hub() { "$DIST/vk-hub" "$@" --config "$WORK/hub.toml"; }
# The registry runs from a copy it may replace, as an installed one would.
cp "$DIST/vk-registry" "$WORK/bin/vk-registry"
cat >"$WORK/registry.toml" <<EOF
addr = "127.0.0.1:$REG_PORT"
root = "$WORK/store"

[hub]
allow = ["read-only", "update"]
EOF
"$DIST/vk-hub" serve --config "$WORK/hub.toml" >"$WORK/hub.log" 2>&1 &
pids+=($!)
wait_for 20 hub registries || fail "the hub did not come up"

echo "== 1. a registry token enrolls the registry, which reports in =="
hub token create --kind registry >"$WORK/token"
"$WORK/bin/vk-registry" join "http://127.0.0.1:$HUB_PORT" --token - \
  --config "$WORK/registry.toml" <"$WORK/token" >"$WORK/id" || fail "join"
id=$(cat "$WORK/id")
"$WORK/bin/vk-registry" serve --config "$WORK/registry.toml" >"$WORK/registry.log" 2>&1 &
reg_pid=$!
pids+=($reg_pid)
connected() { hub registries | awk -v id="$id" '$1 == id && $3 == "connected"' | grep -q .; }
wait_for 30 connected || fail "the registry did not connect"
hub registries
hub registries show "$id" | tee "$WORK/show"
grep -q "shared-secret" "$WORK/show" || fail "the registry's mode is not shown"
grep -q "read-only, update" "$WORK/show" || fail "what the hub may do is not shown"

push() { curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$REG_PORT/v2/e2e/blobs/uploads/"; }
echo "== 2. read-only from the hub refuses pushes, and writable takes them again =="
[ "$(push)" = 202 ] || fail "a push was refused before the hub asked anything"
hub registries read-only "$id" on
wait_for 15 eval '[ "$(push)" = 503 ]' || fail "the registry still takes pushes"
curl -sf "http://127.0.0.1:$REG_PORT/v2/" >/dev/null || fail "reads stopped with writes"
wait_for 15 eval 'hub registries | grep -q read-only' || fail "the hub does not show it read-only"
hub registries read-only "$id" off
wait_for 15 eval '[ "$(push)" = 202 ]' || fail "the registry did not take pushes again"

echo "== 3. what [hub] allow does not list is refused =="
hub registries gc "$id" --dry-run
wait_for 15 eval 'hub registries show "$id" | grep -q "refused: .*allow does not list gc"' ||
  fail "a gc the config does not allow was not refused"

echo "== 4. an update installs a vk-registry release on trial =="
version=$("$DIST/vk-registry" --version | awk '{print $2}')
# The same version, other bytes: a release of its own that still runs.
cp "$DIST/vk-registry" "$WORK/next"
printf 'vk-registry-hub-e2e' >>"$WORK/next"
sha=$(hub release add "$WORK/next" --version "$version" --program vk-registry)
before=$(sha256sum "$WORK/bin/vk-registry" | awk '{print $1}')
[ "$before" != "$sha" ] || fail "the release is the installed binary"
hub registries update "$id" --release "${sha:0:12}"
installed() { [ "$(sha256sum "$WORK/bin/vk-registry" | awk '{print $1}')" = "$sha" ]; }
wait_for 120 installed || fail "the release was not installed"
wait_for 30 eval 'hub registries show "$id" | grep -q "update to vk-registry .*: done"' ||
  fail "the hub does not show the update done"
kill -0 "$reg_pid" || fail "the registry exited across its update"
wait_for 30 connected || fail "the updated registry is not connected"
[ "$(push)" = 202 ] || fail "the updated registry does not serve"

# Again, now that the registry runs from the release it confirmed: the installed path is
# still what the update replaces, and only that release and the one before are kept.
cp "$DIST/vk-registry" "$WORK/next2"
printf 'vk-registry-hub-e2e-2' >>"$WORK/next2"
sha=$(hub release add "$WORK/next2" --version "$version" --program vk-registry)
hub registries update "$id" --release "${sha:0:12}"
wait_for 120 installed || fail "the second release was not installed"
kept() { [ "$(ls "$WORK/store/hub/releases" | wc -l)" -le 2 ]; }
wait_for 30 kept || fail "old releases were not pruned"
wait_for 30 connected || fail "the registry is not connected after its second update"
[ "$(push)" = 202 ] || fail "the registry does not serve after its second update"

echo "== 5. leave and remove =="
"$WORK/bin/vk-registry" leave --config "$WORK/registry.toml"
[ ! -e "$WORK/store/hub" ] || fail "leave left <root>/hub"
hub registries remove "$id"
wait_for 15 eval '[ -z "$(hub registries | awk -v id="$id" '\''$1 == id'\'')" ]' ||
  fail "the hub still lists the registry"
[ "$(push)" = 202 ] || fail "the registry stopped serving when removed from the hub"

echo "PASS: a registry joins, reports, is steered within [hub] allow, updates on trial, and leaves"
