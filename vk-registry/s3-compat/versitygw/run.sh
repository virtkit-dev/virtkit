#!/usr/bin/env bash
# versitygw's client-side integration tests (Go, aws-sdk-go-v2) against the server under
# test: `versitygw test <suite>`, a pinned release binary. The SDK takes an endpoint with a
# path, so it goes straight to /s3/ (S3C_ENDPOINT) with real SigV4 signatures; should a
# version of the SDK drop the path, export S3C_VGW_ENDPOINT=$S3C_ROOT_ENDPOINT to go
# through the proxy instead.
#
# Usage: run.sh [--accept] [suite [flags...]]
#   no suite     full-flow (the whole S3 flow: buckets, objects, multipart, listing...)
#   suite        another `versitygw test` command: data-integrity-etag, noacl,
#                access-control, bench --bucket B --upload ..., throughput, or one test
#                by name (`versitygw test --help` lists them)
#   --accept     rewrite expected-failures.txt from this run's failures
#
# Results: results/<time>/{<suite>.log,outcomes.txt}, results/latest.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../lib.sh
. ../lib.sh

VGW_VERSION=1.10.0   # 2026-10-22
VGW_URL=https://github.com/versity/versitygw/releases/download/v$VGW_VERSION/versitygw_v${VGW_VERSION}_Linux_x86_64.tar.gz
VGW_SHA256=8f9869752939d4dc9cfe1bddb935a02cc6610e95319a3a9fc2947d2a6ebd2c91

accept=()
if [ "${1:-}" = --accept ]; then accept=(--accept); shift; fi
if [ $# -eq 0 ]; then set -- full-flow; fi

s3c_env
bin=$s3c_tools/versitygw-$VGW_VERSION/versitygw
if [ ! -x "$bin" ]; then
  tarball=$(s3c_fetch "$VGW_URL" "$VGW_SHA256")
  mkdir -p "$(dirname "$bin")"
  tar -xzf "$tarball" -C "$(dirname "$bin")" --strip-components=1
fi

results=$(s3c_results "$PWD")
suite=$1
log "versitygw test $* -> $results"
"$bin" test -a "$AWS_ACCESS_KEY_ID" -s "$AWS_SECRET_ACCESS_KEY" \
  -e "${S3C_VGW_ENDPOINT:-$S3C_ENDPOINT}" "$@" 2>&1 | tee "$results/$suite.log" || true
python3 -I ../outcomes.py from-log "$results/$suite.log" > "$results/outcomes.txt"
[ -s "$results/outcomes.txt" ] || die "no PASS/FAIL lines in $results/$suite.log"
s3c_compare "$results/outcomes.txt" expected-failures.txt "${accept[@]}"
