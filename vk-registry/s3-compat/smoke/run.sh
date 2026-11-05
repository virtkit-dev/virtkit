#!/usr/bin/env bash
# Real clients doing what their users do: the AWS CLI (pinned, through uv) and rclone (a
# pinned release) each create a bucket, upload small and large objects (the large one
# goes up in parts and comes down in ranges), list, sync, read back and compare, delete.
# Both take an endpoint with a path, so they go straight to /s3/ with real SigV4.
#
# Usage: run.sh [aws|rclone]   (default: both)
# Every step is reported PASS or FAIL and the run exits 1 when any failed; a FAIL names
# the step, and its log is in results/<time>/<client>.log.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../lib.sh
. ../lib.sh

AWSCLI_VERSION=1.46.2   # 2026-10-21, from PyPI through uv
RCLONE_VERSION=1.75.2   # 2026-10-09
RCLONE_URL=https://github.com/rclone/rclone/releases/download/v$RCLONE_VERSION/rclone-v$RCLONE_VERSION-linux-amd64.zip
RCLONE_SHA256=349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702

s3c_env
results=$(s3c_results "$PWD")
work=$results/work
mkdir -p "$work/up/dir"
head -c 1 /dev/urandom > "$work/up/one-byte"
head -c $((1 << 20)) /dev/urandom > "$work/up/dir/one-mib"
head -c $((20 << 20)) /dev/urandom > "$work/up/twenty-mib"   # past the 8 MiB part size
echo hello > "$work/up/dir/hello.txt"

failed=0
step() { # name command...: run it, log it, report it
  local name=$1 client=$2; shift 2
  if "$@" >> "$results/$client.log" 2>&1; then echo "PASS $client: $name"
  else echo "FAIL $client: $name (see $results/$client.log)"; failed=1; fi
}

smoke_aws() {
  need uvx "to run the AWS CLI (https://docs.astral.sh/uv/)"
  aws() { uvx --from "awscli==$AWSCLI_VERSION" aws --endpoint-url "$S3C_ENDPOINT" "$@"; }
  local b=s3compat-smoke-aws d=$work/down-aws
  mkdir -p "$d"
  step "make bucket" aws aws s3 mb "s3://$b"
  step "head bucket" aws aws s3api head-bucket --bucket "$b"
  step "put one byte" aws aws s3 cp "$work/up/one-byte" "s3://$b/one-byte"
  step "put 1 MiB" aws aws s3 cp "$work/up/dir/one-mib" "s3://$b/dir/one-mib"
  step "put 20 MiB (multipart)" aws aws s3 cp "$work/up/twenty-mib" "s3://$b/twenty-mib"
  step "head object" aws aws s3api head-object --bucket "$b" --key dir/one-mib
  step "list" aws aws s3 ls "s3://$b/"
  step "list v2 with prefix" aws aws s3api list-objects-v2 --bucket "$b" --prefix dir/
  step "get one byte" aws aws s3 cp "s3://$b/one-byte" "$d/one-byte"
  step "get 1 MiB" aws aws s3 cp "s3://$b/dir/one-mib" "$d/one-mib"
  step "get 20 MiB (ranges)" aws aws s3 cp "s3://$b/twenty-mib" "$d/twenty-mib"
  step "get a range" aws aws s3api get-object --bucket "$b" --key twenty-mib --range bytes=1000-1999 "$d/range"
  step "bytes round-trip" aws cmp "$work/up/twenty-mib" "$d/twenty-mib"
  step "range is 1000 bytes" aws test "$(stat -c %s "$d/range")" = 1000
  step "copy object" aws aws s3 cp "s3://$b/one-byte" "s3://$b/copy/one-byte"
  step "sync up" aws aws s3 sync "$work/up" "s3://$b/sync/"
  step "sync down" aws aws s3 sync "s3://$b/sync/" "$d/sync"
  step "sync round-trip" aws diff -r "$work/up" "$d/sync"
  step "delete recursive" aws aws s3 rm --recursive "s3://$b/"
  step "remove bucket" aws aws s3 rb "s3://$b"
}

smoke_rclone() {
  local bin=$s3c_tools/rclone-$RCLONE_VERSION/rclone zip
  if [ ! -x "$bin" ]; then
    need unzip "to unpack rclone"
    zip=$(s3c_fetch "$RCLONE_URL" "$RCLONE_SHA256")
    mkdir -p "$(dirname "$bin")"
    unzip -q -j -o "$zip" "rclone-v$RCLONE_VERSION-linux-amd64/rclone" -d "$(dirname "$bin")"
  fi
  export RCLONE_CONFIG_S3C_TYPE=s3 RCLONE_CONFIG_S3C_PROVIDER=Other
  export RCLONE_CONFIG_S3C_ENDPOINT=$S3C_ENDPOINT RCLONE_CONFIG_S3C_REGION=$AWS_DEFAULT_REGION
  export RCLONE_CONFIG_S3C_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
  export RCLONE_CONFIG_S3C_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
  export RCLONE_CONFIG_S3C_FORCE_PATH_STYLE=true RCLONE_CONFIG=/dev/null
  local b=s3compat-smoke-rclone d=$work/down-rclone
  mkdir -p "$d"
  step "make bucket" rclone "$bin" mkdir "s3c:$b"
  step "copy up" rclone "$bin" copy "$work/up" "s3c:$b/up"
  step "check" rclone "$bin" check "$work/up" "s3c:$b/up"
  step "list" rclone "$bin" lsl "s3c:$b"
  step "copy down" rclone "$bin" copy "s3c:$b/up" "$d"
  step "round-trip" rclone diff -r "$work/up" "$d"
  step "copy within" rclone "$bin" copyto "s3c:$b/up/one-byte" "s3c:$b/copy/one-byte"
  step "delete one" rclone "$bin" deletefile "s3c:$b/copy/one-byte"
  step "purge" rclone "$bin" purge "s3c:$b"
}

case ${1:-all} in
  aws) smoke_aws ;;
  rclone) smoke_rclone ;;
  all) smoke_aws; smoke_rclone ;;
  *) die "usage: run.sh [aws|rclone]" ;;
esac
rm -rf "$work"
exit $failed
