#!/usr/bin/env bash
# vk-registry's S3 view (/s3/) driven by real clients in a microVM: sccache, the AWS CLI and
# rclone (tests/s3/Dockerfile), against a `vk-registry serve` in accounts mode on this host.
#
# 1. The registry listens with TLS on the host's LAN address (a guest cannot reach the host's
#    loopback, and credentials off loopback need TLS), with a certificate from a CA made for
#    the run; a `write:files/*` and a `read:files/*` key are minted over the admin socket.
# 2. The image boots detached with --net; the guest trusts the run's CA.
# 3. sccache: one miss then one hit; a read-only key hits and writes nothing; a wrong secret
#    fails its startup check.
# 4. AWS CLI: mb, cp of 1 KiB, 20 MiB and 100 MiB each way (multipart, aws-chunked bodies with
#    CRC32 trailers, ranged GETs), a paged listing, sync twice, head, ranged get, copy, batch
#    delete, a multipart upload by hand, a presigned URL refused, rb --force.
# 5. rclone: copy, ls, check, sync twice (the second copies nothing), delete.
# 6. On the host, with the registry stopped: `vk registry get` reads an object the CLI wrote,
#    and `vk-registry gc` keeps it.
#
# Run:  VK=vk VK_REGISTRY=./dist/vk-registry tests/s3-e2e.sh
#       VK=./dist/vk tests/release-e2e.sh tests/s3-e2e.sh
# VK is the vk that runs the guest (default: vk on PATH); VK_REGISTRY the vk-registry under
# test (default: the one beside $VK, else ./dist/vk-registry; build it with
# `./build.sh --fast --only=vk-registry`). WORK_DIR is where the store and logs go (default
# $HOME: the store holds a few hundred MiB, too much for a tmpfs /tmp); KEEP_WORK=1 keeps it.
# Needs: KVM, network (the image's packages), a host LAN IPv4 address, openssl, curl, python3.
set -euo pipefail

VK=$(command -v "${VK:-vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
if [ -z "${VK_REGISTRY:-}" ]; then
  VK_REGISTRY=./dist/vk-registry
  [ -x "$(dirname "$VK")/vk-registry" ] && VK_REGISTRY=$(dirname "$VK")/vk-registry
fi
[ -x "$VK_REGISTRY" ] || { echo "no $VK_REGISTRY (build it: ./build.sh --fast --only=vk-registry)"; exit 2; }
VK_REGISTRY=$(cd "$(dirname "$VK_REGISTRY")" && pwd)/$(basename "$VK_REGISTRY")
cd "$(dirname "$0")/.."
for t in openssl curl python3; do command -v "$t" >/dev/null || { echo "need $t"; exit 2; }; done

# The guest reaches the host's private LAN address through ordinary egress.
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }')
[ -n "$IP" ] || IP=$(hostname -I 2>/dev/null | awk '{ print $1 }')
case $IP in
  '' | 127.* | 169.254.*) echo "no LAN IPv4 address on this host for the guest to reach the registry"; exit 2 ;;
esac

WORK=$(mktemp -d "${WORK_DIR:-$HOME}/vk-s3-e2e.XXXXXX")
# Unix sockets (the admin socket, the VM's vsock) need a short path.
SOCKS=$(mktemp -d /tmp/vk-s3-e2e.XXXXXX)
VM=$SOCKS/vm
SHARE=$WORK/share
LOGS=$SHARE/logs
mkdir -p "$WORK/pki" "$WORK/store" "$LOGS"
reg_pid=
cleanup() {
  "$VK" stop "$VM" >/dev/null 2>&1 || true
  [ -z "$reg_pid" ] || kill "$reg_pid" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$SOCKS"
  if [ -n "${KEEP_WORK:-}" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  echo "--- registry log"; tail -n 40 "$WORK/registry.log" || true
  for f in "$LOGS"/*; do
    [ -f "$f" ] && [ -s "$f" ] || continue
    echo "--- $(basename "$f")"; tail -n 40 "$f"
  done
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
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("0.0.0.0",0)); print(s.getsockname()[1])'; }
# One client's scenario in the guest (tests/s3/clients.sh), its output kept in logs/.
client() {
  echo "== $1 =="
  if ! "$VK" exec "$VM" -- bash /e2e/clients.sh "$1" 2>&1 | tee "$LOGS/$1.out"; then fail "$1"; fi
}

echo "== 1. the registry, with TLS on $IP, and two keys =="
d=$WORK/pki
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj /CN=vk-s3-e2e-ca -keyout "$d/ca.key" -out "$d/ca.pem" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=vk-registry \
  -keyout "$d/server.key" -out "$d/server.csr" 2>/dev/null
printf '%s\n' "subjectAltName=IP:$IP" 'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' >"$d/server.ext"
openssl x509 -req -in "$d/server.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" \
  -CAcreateserial -days 2 -extfile "$d/server.ext" -out "$d/server.pem" 2>/dev/null
cp "$d/ca.pem" "$SHARE/ca.pem"

PORT=$(port)
# Accounts mode needs an [oidc] table; no one signs in, so its provider is never asked.
printf 'unused\n' >"$WORK/oidc-secret"
cat >"$WORK/registry.toml" <<EOF
addr = "$IP:$PORT"
root = "$WORK/store"
tls_cert = "$d/server.pem"
tls_key = "$d/server.key"
mode = "accounts"
admin_socket = "$SOCKS/admin.sock"
s3 = true

[oidc]
issuer = "https://login.example.com"
client_id = "vk-registry"
client_secret_file = "$WORK/oidc-secret"
public_url = "https://$IP:$PORT"
EOF
"$VK_REGISTRY" serve --config "$WORK/registry.toml" >"$WORK/registry.log" 2>&1 &
reg_pid=$!
URL=https://$IP:$PORT
wait_for 30 curl -sS --cacert "$d/ca.pem" -o /dev/null "$URL/v2/" || fail "the registry did not come up"
key() {
  "$VK_REGISTRY" accounts create-key --config "$WORK/registry.toml" --name "$1" --scope "$2" \
    2>>"$WORK/keys.log" || fail "create-key $1"
}
WKEY=$(key s3-e2e-write 'write:files/*')
RKEY=$(key s3-e2e-read 'read:files/*')
code=$(curl -sS --cacert "$d/ca.pem" -o /dev/null -w '%{http_code}' "$URL/s3/")
[ "$code" = 403 ] || fail "an unsigned ListBuckets got $code, not 403"
cat >"$SHARE/env" <<EOF
S3_ENDPOINT=$URL/s3
WKEY=$WKEY
RKEY=$RKEY
EOF
chmod 600 "$SHARE/env"
cp tests/s3/clients.sh "$SHARE/clients.sh"

echo "== 2. the clients' image, booted detached =="
start=$(date +%s)
"$VK" run -f tests/s3/Dockerfile --build-net all --net --mem 2G --cpus 2 \
  -v "$SHARE:/e2e" --state-dir "$VM" --detach --inactivity-timeout 0 \
  -- sleep infinity >"$WORK/vm.log" 2>&1 || { cat "$WORK/vm.log"; fail "the guest did not boot"; }
client trust

echo "== 3. sccache =="
client sccache
echo "== 4. AWS CLI =="
client awscli
echo "== 5. rclone =="
client rclone

echo "== 6. the host side: vk registry get, and gc keeps it =="
"$VK" stop "$VM" >/dev/null
kill "$reg_pid"
wait "$reg_pid" 2>/dev/null || true
reg_pid=
got() {
  rm -f "$WORK/got"
  "$VK" registry get --cache-registry "$WORK/store" -o "$WORK/got" keep/from-cli.bin \
    >>"$LOGS/vk-registry-get.log" 2>&1 &&
    [ "$(sha256sum <"$WORK/got" | cut -d' ' -f1)" = "$(cat "$SHARE/keep.sha256")" ]
}
got || fail "vk registry get does not fetch what the AWS CLI wrote"
"$VK_REGISTRY" gc --root "$WORK/store" >"$LOGS/gc.log" 2>&1 || fail "vk-registry gc"
got || fail "the gc did not keep what the AWS CLI wrote"

echo "PASS: sccache, the AWS CLI and rclone over /s3/, and the store keeps what they wrote, in $(($(date +%s) - start))s"
