#!/usr/bin/env bash
# Ceph's s3-tests (the broadest S3 conformance suite, boto3) against the server under test.
#
# The suite now lives in ceph/ceph under src/test/rgw/s3-tests, pinned below; it is cloned
# blobless and sparse, so only that directory's files are fetched. Its clients take a host
# and a port, not a path, so it runs through the root-path proxy (S3C_ROOT_ENDPOINT).
#
# Usage: run.sh [--accept] [pytest arguments...]
#   no arguments        s3tests/functional/test_s3.py, less the markers in markers.txt
#   -k EXPR, FILE::test narrows the run as pytest does (markers.txt still applies)
#   --accept            rewrite expected-failures.txt from this run's failures
#
# Results: results/<time>/{junit.xml,outcomes.txt,pytest.log}, results/latest.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../lib.sh
. ../lib.sh

CEPH_URL=https://github.com/ceph/ceph.git
CEPH_SHA=1cfa9f84f53c4ffd25ff92fe5e0b56154eaf0bfb   # main, 2026-11-05
SUITE=src/test/rgw/s3-tests

accept=()
if [ "${1:-}" = --accept ]; then accept=(--accept); shift; fi

s3c_env
s3c_clone "$CEPH_URL" "$CEPH_SHA" upstream "$SUITE"
suite=$PWD/upstream/$SUITE
python=$(s3c_venv "$PWD" -r "$suite/requirements.txt")

host=$(s3c_url_host "$S3C_ROOT_ENDPOINT")
secure=False
if s3c_url_https "$S3C_ROOT_ENDPOINT"; then secure=True; fi
case $host in
  *:*) port=${host##*:}; host=${host%:*} ;;
  *) port=443; [ $secure = True ] || port=80 ;;
esac
results=$(s3c_results "$PWD")
conf=$results/s3tests.conf
(umask 077; sed -e "s|@HOST@|$host|g" -e "s|@PORT@|$port|g" -e "s|@SECURE@|$secure|g" \
  -e "s|@ACCESS_KEY@|$AWS_ACCESS_KEY_ID|g" -e "s|@SECRET_KEY@|$AWS_SECRET_ACCESS_KEY|g" \
  s3tests.conf.in > "$conf")

# markers.txt: one marker per line to leave out, joined into pytest's -m expression
markers=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' markers.txt | sed 's/^[[:space:]]*/not /; s/[[:space:]]*$//' | paste -sd '&' - | sed 's/&/ and /g')

if [ $# -eq 0 ]; then set -- s3tests/functional/test_s3.py; fi
log "pytest in $suite -> $results"
status=0
(cd "$suite" && S3TEST_CONF=$conf "$python" -m pytest -p no:cacheprovider -q -rfE \
  --junitxml "$results/junit.xml" -m "$markers" "$@") 2>&1 | tee "$results/pytest.log" \
  || status=$?
[ -f "$results/junit.xml" ] || die "pytest wrote no junit.xml (status $status): see $results/pytest.log"
python3 -I ../outcomes.py from-junit "$results/junit.xml" > "$results/outcomes.txt"
s3c_compare "$results/outcomes.txt" expected-failures.txt "${accept[@]}"
