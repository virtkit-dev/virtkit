#!/usr/bin/env bash
# sccache's S3 cache against vk-registry's S3 view (`s3 = true`), on this host: a registry in
# shared-bearer mode on loopback, the bearer as both AWS keys.
#
# 1. A small C file and one whose object is over 5 MiB (OpenDAL's multipart threshold) each
#    compile once as a miss, then, with sccache's local state wiped, as a hit from the
#    registry.
# 2. The objects sccache wrote are the WebDAV view's (`/dav/files/<bucket>/…`).
# 3. A wrong key is refused 403 AccessDenied, which stops sccache's startup check.
#
# Run:  SCCACHE=/path/to/sccache tests/s3-sccache-e2e.sh
# VK_REGISTRY is the vk-registry under test (default: the one beside $VK, else
# ./dist/vk-registry; build it with `./build.sh --fast --only=vk-registry`); SCCACHE the
# sccache (default: on PATH; a release's static musl binary does). KEEP_WORK=1 keeps the work
# directory. Skips without sccache, cc or python3, so release-e2e.sh passes on a runner
# without them. Needs: curl.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${VK_REGISTRY:-}" ]; then
  # Beside the vk under test when release-e2e.sh runs this, else this checkout's build.
  VK_REGISTRY=./dist/vk-registry
  [ -z "${VK:-}" ] || [ ! -x "$(dirname "$VK")/vk-registry" ] || VK_REGISTRY=$(dirname "$VK")/vk-registry
fi
[ -x "$VK_REGISTRY" ] || { echo "no $VK_REGISTRY (build it: ./build.sh --fast --only=vk-registry)"; exit 2; }
SCCACHE=$(command -v "${SCCACHE:-sccache}" || true)
[ -n "$SCCACHE" ] || { echo "SKIP: no sccache (set SCCACHE)"; exit 0; }
for t in cc curl python3; do command -v "$t" >/dev/null || { echo "SKIP: no $t"; exit 0; }; done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-s3-sccache.XXXXXX")
reg_pid=
cleanup() {
  SCCACHE_SERVER_PORT=${SCCACHE_SERVER_PORT:-0} "$SCCACHE" --stop-server >/dev/null 2>&1 || true
  [ -z "$reg_pid" ] || kill "$reg_pid" 2>/dev/null || true
  wait 2>/dev/null || true
  if [ -n "${KEEP_WORK:-}" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  echo "--- registry log"; tail -n 30 "$WORK/registry.log" || true
  echo "--- sccache log"; tail -n 30 "$WORK/sccache.log" 2>/dev/null || true
  exit 1
}
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

# The registry: shared bearer, S3 on.
BEARER=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '%s\n' "$BEARER" >"$WORK/token"
chmod 600 "$WORK/token"
REG_PORT=$(port)
cat >"$WORK/registry.toml" <<EOF
addr = "127.0.0.1:$REG_PORT"
root = "$WORK/store"
token_file = "$WORK/token"
s3 = true
EOF
"$VK_REGISTRY" serve --config "$WORK/registry.toml" >"$WORK/registry.log" 2>&1 &
reg_pid=$!
for _ in $(seq 40); do
  curl -fsS -o /dev/null -H "Authorization: Bearer $BEARER" "http://127.0.0.1:$REG_PORT/v2/" && break
  sleep 0.25
done
grep -q 'S3 view on' "$WORK/registry.log" || fail "the registry did not start with the S3 view"

# sccache, isolated from the host's AWS config and its own running server.
export SCCACHE_SERVER_PORT
SCCACHE_SERVER_PORT=$(port)
export SCCACHE_BUCKET=cache SCCACHE_S3_KEY_PREFIX=e2e SCCACHE_REGION=us-east-1
export SCCACHE_ENDPOINT=http://127.0.0.1:$REG_PORT/s3 SCCACHE_S3_USE_SSL=false
export SCCACHE_ERROR_LOG=$WORK/sccache.log SCCACHE_LOG=debug
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_ACCESS_KEY_ID=$BEARER AWS_SECRET_ACCESS_KEY=$BEARER
export SCCACHE_DIR=$WORK/sccache-local SCCACHE_IDLE_TIMEOUT=0

stats() { "$SCCACHE" --show-stats --stats-format=json; }
field() { python3 -c "import json,sys; s=json.load(sys.stdin)['stats']; print(sum(s['$1']['counts'].values()) if isinstance(s['$1'], dict) else s['$1'])"; }
restart() { "$SCCACHE" --stop-server >/dev/null 2>&1 || true; rm -rf "$SCCACHE_DIR"; "$SCCACHE" --start-server >/dev/null; }

mkdir -p "$WORK/src"
printf 'int answer(void) { return 42; }\n' >"$WORK/src/small.c"
# A 6 MiB initialized array: an object over OpenDAL's 5 MiB multipart threshold.
python3 -c '
import sys
n = 6 * 1024 * 1024
sys.stdout.write("const unsigned char blob[%d] = {" % n)
sys.stdout.write(",".join(str((i * 7919) % 251) for i in range(n)))
sys.stdout.write("};\n")' >"$WORK/src/big.c"

compile() { "$SCCACHE" cc -c "$WORK/src/$1.c" -o "$WORK/src/$1.o"; }

restart
compile small
compile big
[ "$(stats | field cache_misses)" = 2 ] || fail "expected two misses: $(stats)"
[ "$(stats | field cache_errors)" = 0 ] || fail "cache errors: $(stats)"
big_size=$(stat -c %s "$WORK/src/big.o")
[ "$big_size" -gt $((5 * 1024 * 1024)) ] || fail "big.o is only $big_size bytes"

restart
compile small
compile big
[ "$(stats | field cache_hits)" = 2 ] || fail "expected two hits from the registry: $(stats)"
echo "ok: miss then hit for a small object and a $big_size-byte one"

curl -fsS -o /dev/null -H "Authorization: Bearer $BEARER" \
  "http://127.0.0.1:$REG_PORT/dav/files/cache/e2e/.sccache_check" ||
  fail "sccache's check object is not under /dav/files/cache/e2e/"
echo "ok: the objects are the WebDAV view's"

# sccache's startup check reads `.sccache_check` and stops at a 403, as it does against S3.
"$SCCACHE" --stop-server >/dev/null 2>&1 || true
rm -rf "$SCCACHE_DIR"
if AWS_ACCESS_KEY_ID=wrong-key AWS_SECRET_ACCESS_KEY=wrong-key \
  "$SCCACHE" --start-server >"$WORK/wrong-key.log" 2>&1; then
  fail "sccache started with a wrong key"
fi
grep -q AccessDenied "$WORK/wrong-key.log" || fail "a wrong key was not refused: $(cat "$WORK/wrong-key.log")"
echo "ok: a wrong key is refused at sccache's startup check"
echo PASS
