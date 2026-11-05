#!/usr/bin/env bash
# MinIO warp, the S3 benchmark, against the server under test. warp takes a host and a
# port, not a path, so it runs through the root-path proxy (S3C_ROOT_ENDPOINT): one
# connection per request through a Python byte pump, which is part of what gets measured.
# Numbers from here compare one build of the registry with another, not the registry with
# a server that is addressed directly.
#
# Usage: run.sh [mode] [warp flags...]
#   mode        mixed (default), get, put, list, stat, delete, multipart
#   flags       appended to warp's, e.g. --duration 3m --obj.size 8MiB --concurrent 16
#
#   S3C_WARP_DURATION    default 1m          S3C_WARP_OBJ_SIZE   default 1MiB
#   S3C_WARP_CONCURRENT  default 8           S3C_WARP_BUCKET     default s3compat-warp
#   S3C_WARP_PART_SIZE   default 5MiB        (multipart only: it takes --part.size and
#                                             --parts, and refuses --obj.size)
#
# Results: results/<time>/<mode>.json.zst (warp's benchdata, `warp analyze` reads it) and
# <mode>.log; results/latest.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../lib.sh
. ../lib.sh

WARP_VERSION=1.8.2   # 2026-09-24; the only Linux build of this release is the RDMA one,
                     # a dynamically linked binary with its library beside it (rpath)
WARP_URL=https://github.com/minio/warp/releases/download/v$WARP_VERSION/warp-rdma_linux_amd64.tar.gz
WARP_SHA256=e4d27a72bb7adaec1721963419b15684c2763778d43f437b24dcb9a6545ffdfa

mode=${1:-mixed}
if [ $# -gt 0 ]; then shift; fi

s3c_env
dir=$s3c_tools/warp-$WARP_VERSION
bin=$dir/warp
if [ ! -x "$bin" ]; then
  tarball=$(s3c_fetch "$WARP_URL" "$WARP_SHA256")
  mkdir -p "$dir"
  tar -xzf "$tarball" -C "$dir" --strip-components=1
fi

host=$(s3c_url_host "$S3C_ROOT_ENDPOINT")
tls=()
if s3c_url_https "$S3C_ROOT_ENDPOINT"; then tls=(--tls --insecure); fi
# multipart builds one object from parts and has no --obj.size: warp exits on the flag.
case $mode in
  multipart) size=(--part.size "${S3C_WARP_PART_SIZE:-5MiB}") ;;
  *) size=(--obj.size "${S3C_WARP_OBJ_SIZE:-1MiB}") ;;
esac
results=$(s3c_results "$PWD")
log "warp $mode against $host -> $results"
"$bin" "$mode" --host "$host" "${tls[@]}" \
  --access-key "$AWS_ACCESS_KEY_ID" --secret-key "$AWS_SECRET_ACCESS_KEY" \
  --region "$AWS_DEFAULT_REGION" --bucket "${S3C_WARP_BUCKET:-s3compat-warp}" \
  --duration "${S3C_WARP_DURATION:-1m}" "${size[@]}" \
  --concurrent "${S3C_WARP_CONCURRENT:-8}" --benchdata "$results/$mode" \
  "$@" 2>&1 | tee "$results/$mode.log"
