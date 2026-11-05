#!/usr/bin/env bash
# The guest side of tests/s3-e2e.sh: one client's scenario against the registry's /s3/, run as
#   bash /e2e/clients.sh <trust|sccache|awscli|rclone>
# in the tests/s3/Dockerfile image. /e2e is the host's share: `env` (S3_ENDPOINT, WKEY, RKEY,
# written by the host script), `ca.pem` (the run's CA) and `logs/`, where each
# client's own output goes. A failed check prints FAIL and exits non-zero.
set -euo pipefail
. /e2e/env
LOGS=/e2e/logs
mkdir -p "$LOGS"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

fail() { echo "FAIL: $*"; exit 1; }
secs() { awk -v a="$1" -v b="$(date +%s.%N)" 'BEGIN { printf "%.2fs", b - a }'; }
same() { [ "$(sha256sum <"$1" | cut -d' ' -f1)" = "$(sha256sum <"$2" | cut -d' ' -f1)" ]; }

# The run's CA in the system store, which curl, rclone and sccache read; the AWS CLI does not
# (it takes AWS_CA_BUNDLE), and each client is also given the file explicitly below
# (sccache SSL_CERT_FILE, rclone --ca-cert).
trust() {
  cp /e2e/ca.pem /usr/local/share/ca-certificates/vk-s3-e2e.crt
  update-ca-certificates >/dev/null 2>&1
  curl -sS -o /dev/null "$S3_ENDPOINT/" || fail "curl does not reach $S3_ENDPOINT over TLS"
}

# ---------------------------------------------------------------------------- sccache
sccache_env() {
  export SCCACHE_BUCKET=sccache SCCACHE_ENDPOINT=$S3_ENDPOINT SCCACHE_S3_USE_SSL=true
  export SCCACHE_REGION=auto SCCACHE_S3_KEY_PREFIX=ci/ SCCACHE_IDLE_TIMEOUT=0
  export SSL_CERT_FILE=/e2e/ca.pem SCCACHE_LOG=debug
  export AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2
  export SCCACHE_ERROR_LOG=$LOGS/sccache-$3.server.log
}
# The value of one `--show-stats` counter, e.g. `stat "Cache hits"`.
stat() { sccache --show-stats | awk -v k="$1" 'index($0, k) == 1 { print $NF; exit }'; }
compile() {
  sccache gcc -c "$T/hello.c" -o "$T/hello.o"
  sccache --show-stats >"$LOGS/sccache-$1.stats"
}

# The bucket's entries, listed with the write key.
keys() {
  AWS_ACCESS_KEY_ID=$WKEY AWS_SECRET_ACCESS_KEY=$WKEY AWS_DEFAULT_REGION=us-east-1 \
    AWS_ENDPOINT_URL=$S3_ENDPOINT AWS_CA_BUNDLE=/e2e/ca.pem aws s3 ls --recursive s3://sccache/ |
    awk '{ print $NF }'
}

run_sccache() {
  # SCCACHE_LOG makes the client talk too: its stderr goes to a log of its own.
  exec 2>>"$LOGS/sccache-client.log"
  cat >"$T/hello.c" <<'EOF'
int hello(int x) { return x * 42; }
EOF
  # sccache never creates its bucket.
  AWS_ACCESS_KEY_ID=$WKEY AWS_SECRET_ACCESS_KEY=$WKEY AWS_DEFAULT_REGION=us-east-1 \
    AWS_ENDPOINT_URL=$S3_ENDPOINT AWS_CA_BUNDLE=/e2e/ca.pem aws s3 mb s3://sccache

  sccache_env "$WKEY" "$WKEY" write
  sccache --start-server
  compile miss
  [ "$(stat "Cache misses")" = 1 ] || fail "the first compile was not one miss"
  [ "$(stat "Cache hits")" = 0 ] || fail "the first compile hit"
  [ "$(stat "Cache write errors")" = 0 ] || fail "sccache could not write its entry"
  sccache --stop-server >/dev/null
  sccache --start-server
  compile hit
  [ "$(stat "Cache hits")" = 1 ] || fail "the second compile was not one hit"
  [ "$(stat "Cache misses")" = 0 ] || fail "the second compile missed"
  sccache --stop-server >/dev/null

  # A read-only key: the startup check finds the bucket read-only (its write of
  # .sccache_check is refused), the entry is still a hit, and a new one is not written.
  entries=$(keys)
  sccache_env "$RKEY" "$RKEY" read
  sccache --start-server
  grep -q 'server has setup with ReadOnly' "$SCCACHE_ERROR_LOG" ||
    fail "sccache did not find the bucket read-only with a read key"
  compile read-hit
  [ "$(stat "Cache hits")" = 1 ] || fail "the read-only key did not hit"
  echo 'int other(int x) { return x - 1; }' >"$T/hello.c"
  compile read-miss
  [ "$(stat "Cache misses")" = 1 ] || fail "the read-only key's new compile was not a miss"
  sccache --stop-server >/dev/null
  [ "$(keys)" = "$entries" ] || fail "an entry was written with the read-only key"

  # A wrong secret: the storage check at startup fails, and so does the server.
  sccache_env "$WKEY" "${WKEY}x" wrong
  if sccache --start-server >"$LOGS/sccache-wrong.out" 2>&1; then
    sccache --stop-server >/dev/null 2>&1 || true
    fail "sccache started with a wrong secret"
  fi
  grep -q SignatureDoesNotMatch "$LOGS/sccache-wrong.out" ||
    fail "sccache's startup failure does not name the signature"
  echo "sccache: a miss then a hit, read-only with a read key, refused with a wrong secret"
}

# ---------------------------------------------------------------------------- AWS CLI
run_awscli() {
  export AWS_ACCESS_KEY_ID=$WKEY AWS_SECRET_ACCESS_KEY=$WKEY AWS_DEFAULT_REGION=us-east-1
  export AWS_ENDPOINT_URL=$S3_ENDPOINT AWS_CA_BUNDLE=/e2e/ca.pem
  aws s3 mb s3://cli
  for size in 1K 20M 100M; do
    head -c "$size" /dev/urandom >"$T/$size.bin"
    s=$(date +%s.%N)
    aws s3 cp --no-progress "$T/$size.bin" "s3://cli/obj/$size.bin"
    put=$(secs "$s")
    s=$(date +%s.%N)
    aws s3 cp --no-progress "s3://cli/obj/$size.bin" "$T/$size.back"
    echo "timing: $size put $put, get $(secs "$s")"
    same "$T/$size.bin" "$T/$size.back" || fail "$size came back different"
  done
  # The CLI's default checksum, CRC64NVME, is taken unchecked: these the server checks, in a
  # PutObject's trailer and in each part's of a multipart upload.
  for algo in CRC32 SHA1 SHA256; do
    for size in 1K 20M; do
      aws s3 cp --no-progress --checksum-algorithm "$algo" "$T/$size.bin" "s3://cli/sum/$algo-$size"
      aws s3 cp --no-progress "s3://cli/sum/$algo-$size" "$T/sum.back"
      same "$T/$size.bin" "$T/sum.back" || fail "$size with $algo came back different"
    done
  done
  aws s3 ls s3://cli/obj/ | tee "$T/ls"
  [ "$(wc -l <"$T/ls")" = 3 ] || fail "s3 ls does not list 3 objects"

  # Seven keys, two a page.
  for i in 1 2 3 4 5 6 7; do echo "$i" | aws s3 cp - "s3://cli/page/k$i"; done
  token= pages=0
  : >"$T/keys"
  while :; do
    aws s3api list-objects-v2 --bucket cli --prefix page/ --max-keys 2 --no-paginate \
      ${token:+--continuation-token "$token"} --output json >"$T/page.json"
    python3 -I -c '
import json, sys
p = json.load(open(sys.argv[1]))
for o in p.get("Contents", []): print(o["Key"], file=open(sys.argv[2], "a"))
print(p.get("NextContinuationToken", "") if p["IsTruncated"] else "")' \
      "$T/page.json" "$T/keys" >"$T/next"
    pages=$((pages + 1))
    token=$(cat "$T/next")
    [ -n "$token" ] || break
    [ "$pages" -lt 10 ] || fail "the listing does not end"
  done
  [ "$pages" = 4 ] || fail "7 keys came in $pages pages of 2"
  [ "$(printf 'page/k%s\n' 1 2 3 4 5 6 7)" = "$(cat "$T/keys")" ] || fail "the pages: $(cat "$T/keys")"

  mkdir -p "$T/tree/sub"
  for f in a b sub/c; do head -c 3000 /dev/urandom >"$T/tree/$f"; done
  # sync uploads a file newer than its object, whose LastModified is in whole seconds, as
  # S3's is: a file written in the second its upload lands would go again.
  touch -d '-1 minute' "$T/tree/a" "$T/tree/b" "$T/tree/sub/c"
  aws s3 sync --no-progress "$T/tree" s3://cli/tree | tee "$T/sync1"
  [ "$(grep -c '^upload:' "$T/sync1")" = 3 ] || fail "the first sync did not upload 3 files"
  aws s3 sync --no-progress "$T/tree" s3://cli/tree >"$T/sync2"
  [ ! -s "$T/sync2" ] || fail "the second sync did something: $(cat "$T/sync2")"

  aws s3api head-object --bucket cli --key obj/1K.bin --output json >"$T/head.json"
  grep -q '"ContentLength": 1024' "$T/head.json" || fail "head-object: $(cat "$T/head.json")"
  aws s3api get-object --bucket cli --key obj/100M.bin --range bytes=0-9 "$T/range" >/dev/null
  [ "$(head -c 10 "$T/100M.bin" | od -An -tx1)" = "$(od -An -tx1 <"$T/range")" ] ||
    fail "get-object --range bytes=0-9 is not the first 10 bytes"
  s=$(date +%s.%N)
  aws s3api get-object --bucket cli --key obj/100M.bin --range bytes=52428800- "$T/tail" >/dev/null
  echo "timing: 100M ranged get of the second half $(secs "$s")"
  tail -c 52428800 "$T/100M.bin" | same /dev/stdin "$T/tail" || fail "the ranged second half differs"
  aws s3api copy-object --bucket cli --key obj/copy.bin --copy-source cli/obj/20M.bin >/dev/null
  aws s3 cp --no-progress s3://cli/obj/copy.bin "$T/copy.back"
  same "$T/20M.bin" "$T/copy.back" || fail "copy-object made other bytes"
  aws s3api delete-objects --bucket cli --output json \
    --delete '{"Objects":[{"Key":"page/k1"},{"Key":"page/k2"},{"Key":"page/none"}]}' >"$T/del.json"
  [ "$(grep -c '"Key"' "$T/del.json")" = 3 ] || fail "delete-objects: $(cat "$T/del.json")"
  [ "$(aws s3 ls s3://cli/page/ | wc -l)" = 5 ] || fail "delete-objects left the wrong keys"

  # A multipart upload by hand: three parts of 5 MiB, 5 MiB and 1 MiB.
  head -c 11534336 /dev/urandom >"$T/mp.bin"
  split -b 5242880 -d -a 1 "$T/mp.bin" "$T/mp.part"
  id=$(aws s3api create-multipart-upload --bucket cli --key obj/manual.bin --query UploadId --output text)
  parts=
  for n in 1 2 3; do
    etag=$(aws s3api upload-part --bucket cli --key obj/manual.bin --upload-id "$id" \
      --part-number "$n" --body "$T/mp.part$((n - 1))" --query ETag --output text)
    parts="$parts${parts:+,}{\"PartNumber\":$n,\"ETag\":$etag}"
  done
  aws s3api complete-multipart-upload --bucket cli --key obj/manual.bin --upload-id "$id" \
    --multipart-upload "{\"Parts\":[$parts]}" --output json >"$T/complete.json"
  grep -q -- '-3\\"' "$T/complete.json" || fail "complete-multipart-upload: $(cat "$T/complete.json")"
  aws s3 cp --no-progress s3://cli/obj/manual.bin "$T/manual.back"
  same "$T/mp.bin" "$T/manual.back" || fail "the manual multipart object differs"

  # Presigned URLs put a credential in a URL: refused.
  url=$(aws s3 presign s3://cli/obj/1K.bin)
  code=$(curl -sS --cacert /e2e/ca.pem -o "$T/presigned" -w '%{http_code}' "$url")
  [ "$code" = 400 ] && grep -q AuthorizationQueryParametersError "$T/presigned" ||
    fail "a presigned URL got $code: $(cat "$T/presigned")"

  # Kept for the host side: vk registry get, and the gc keeping it.
  aws s3 mb s3://keep
  aws s3 cp --no-progress "$T/1K.bin" s3://keep/from-cli.bin
  sha256sum <"$T/1K.bin" | cut -d' ' -f1 >/e2e/keep.sha256

  aws s3 rb --force s3://cli
  if aws s3api head-bucket --bucket cli 2>/dev/null; then fail "s3 rb --force left the bucket"; fi
  echo "awscli: cp up and down to 100 MiB, CRC32/SHA-1/SHA-256 checksums, paged listing, sync, ranges, copy, batch delete, multipart, presign refused, rb"
}

# ---------------------------------------------------------------------------- rclone
run_rclone() {
  export RCLONE_CONFIG_VKR_TYPE=s3 RCLONE_CONFIG_VKR_PROVIDER=Other
  export RCLONE_CONFIG_VKR_ENDPOINT=$S3_ENDPOINT RCLONE_CONFIG_VKR_FORCE_PATH_STYLE=true
  export RCLONE_CONFIG_VKR_ACCESS_KEY_ID=$WKEY RCLONE_CONFIG_VKR_SECRET_ACCESS_KEY=$WKEY
  export RCLONE_CONFIG_VKR_REGION=us-east-1
  r() { rclone --ca-cert /e2e/ca.pem --log-file "$LOGS/rclone.log" -v "$@"; }
  mkdir -p "$T/src/d"
  for f in one two d/three; do head -c 70000 /dev/urandom >"$T/src/$f"; done
  # A multipart upload of rclone's own (5 MiB parts, its MD5 kept in metadata).
  head -c 12M /dev/urandom >"$T/src/d/big"
  touch -d '2024-01-02 03:04:05' "$T/src/one"
  r mkdir vkr:rcl
  r copy --s3-upload-cutoff 5M --s3-chunk-size 5M "$T/src" vkr:rcl/data
  r ls vkr:rcl/data | tee "$T/ls"
  [ "$(wc -l <"$T/ls")" = 4 ] || fail "rclone ls does not list 4 files"
  r check "$T/src" vkr:rcl/data || fail "rclone check"
  r lsl vkr:rcl/data/one | grep -q '2024-01-02 03:04:05' || fail "rclone lost the modification time"
  head -c 500 /dev/urandom >"$T/src/four"
  : >"$LOGS/rclone.log"
  r sync "$T/src" vkr:rcl/data
  [ "$(grep -c ': Copied' "$LOGS/rclone.log")" = 1 ] || fail "the first sync did not copy one file"
  : >"$LOGS/rclone.log"
  r sync "$T/src" vkr:rcl/data
  if grep -q ': Copied\|: Updated' "$LOGS/rclone.log"; then fail "the second sync copied again"; fi
  r delete vkr:rcl/data
  [ -z "$(r ls vkr:rcl)" ] || fail "rclone delete left files"
  # Lists the bucket's multipart uploads to abort the stale ones.
  r cleanup vkr:rcl
  r rmdirs vkr:rcl
  echo "rclone: copy (multipart too), ls, check, sync twice, delete, cleanup"
}

case ${1:-} in
  trust) trust ;;
  sccache) run_sccache ;;
  awscli) run_awscli ;;
  rclone) run_rclone ;;
  *) echo "usage: $0 <trust|sccache|awscli|rclone>" >&2; exit 2 ;;
esac
