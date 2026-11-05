#!/usr/bin/env bash
# MSST-S3 (linux-kdevops/msst-s3, boto3; most of its tests ported from versitygw's) against
# the server under test, a test group at a time. Its runner takes an endpoint URL, so it
# goes straight to the registry's /s3/ (S3C_ENDPOINT) with real SigV4 signatures.
#
# Usage: run.sh [--accept] [--list] [group...]
#   no group     basic multipart edge batch (the groups covering what the registry serves)
#   --list       print the suite's tests and groups, and stop
#   --accept     rewrite expected-failures.txt from this run's failures
#
# Groups: basic multipart versioning acl encryption lifecycle performance stress edge
# integration advanced_basic advanced_multipart replication notifications lambda analytics
# batch tiering access_points object_lambda compliance ... (scripts/test-runner.py).
#
# Results: results/<time>/{<group>.xml,outcomes.txt,<group>.log}, results/latest.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../lib.sh
. ../lib.sh

MSST_URL=https://github.com/linux-kdevops/msst-s3.git
MSST_SHA=b84a323cca5ee862e87677043f672f156c46b448   # main, 2025-12-04

accept=()
if [ "${1:-}" = --accept ]; then accept=(--accept); shift; fi

s3c_env
s3c_clone "$MSST_URL" "$MSST_SHA" upstream
suite=$PWD/upstream
python=$(s3c_venv "$PWD" -r "$suite/requirements.txt")

results=$(s3c_results "$PWD")
cfg=$results/s3_config.yaml
use_ssl=false
if s3c_url_https "$S3C_ENDPOINT"; then use_ssl=true; fi
(umask 077; cat > "$cfg" <<YAML
# written by run.sh for scripts/test-runner.py
s3_endpoint_url: "$S3C_ENDPOINT"
s3_access_key: "$AWS_ACCESS_KEY_ID"
s3_secret_key: "$AWS_SECRET_ACCESS_KEY"
s3_region: "$AWS_DEFAULT_REGION"
s3_use_ssl: $use_ssl
s3_verify_ssl: false
s3_bucket_prefix: "s3compat-msst"
test_basic: true
test_multipart: true
test_versioning: true
test_acl: true
test_encryption: true
test_lifecycle: true
test_performance: true
test_stress: true
test_compatibility: true
test_run_mode: "sequential"
test_timeout: 120
test_retry_count: 0
test_object_sizes: "1KB,1MB"
test_bucket_count: 2
test_object_count: 5
output_format: "junit"
output_verbose: 1
output_dir: "$results"
output_timestamp: false
output_save_logs: true
vendor_type: "generic"
debug_enabled: false
debug_keep_buckets: false
YAML
)

runner() { (cd "$suite" && "$python" scripts/test-runner.py --config "$cfg" "$@"); }

if [ "${1:-}" = --list ]; then runner --list-tests; exit; fi
if [ $# -eq 0 ]; then set -- basic multipart edge batch; fi

: > "$results/outcomes.txt"
for group in "$@"; do
  log "group $group -> $results"
  before=$(ls "$results"/*.xml 2>/dev/null || true)
  runner --group "$group" --output-dir "$results" --output-format junit 2>&1 \
    | tee "$results/$group.log" || true
  for xml in "$results"/*.xml; do
    [ -f "$xml" ] || continue
    case " $before " in *" $xml "*) continue ;; esac
    python3 -I ../outcomes.py from-junit "$xml" >> "$results/outcomes.txt"
  done
done
[ -s "$results/outcomes.txt" ] || die "the runner wrote no junit results: see $results/*.log"
s3c_compare "$results/outcomes.txt" expected-failures.txt "${accept[@]}"
