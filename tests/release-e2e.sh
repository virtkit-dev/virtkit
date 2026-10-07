#!/usr/bin/env bash
# Release end-to-end gate, run against one built `vk`.
#
# release.yml runs this on the binary build.yml produced and the publish job releases, so
# what is tested is what ships. Two identity checks come first and are preconditions — the
# sha256 sidecars beside the binaries (and, for a release, embedded UEFI firmware recorded
# in build-info.txt), and vk's version against the release tag (`vk update` compares them;
# a mismatch breaks self-update). Both must pass before booting a microVM. Then `vk check`,
# a plain image boot, `vk run`'s exit status, and every other script in this directory,
# each against the same vk. Failures do not stop the run: every script reports,
# and the exit status is non-zero if any failed.
#
#   VK=./dist/vk tests/release-e2e.sh                     # a local build, every script
#   VK=./dist/vk tests/release-e2e.sh tests/systemd-boot-e2e.sh  # the smoke checks + these
#   RELEASE_TAG=v0.61.0 VK=dist/vk tests/release-e2e.sh     # what release.yml runs
#   ISO_DIR=~/.cache/vk-windows VK=./dist/vk tests/release-e2e.sh   # the Windows tests too
#   E2E_GITLAB=1 VK=./dist/vk tests/release-e2e.sh        # the GitLab suite too (gitlab-e2e.sh)
#
# Needs: KVM, network for the image pulls the scripts do, e2fsprogs, and GNU coreutils
# (busybox `timeout` signals only its child, so a killed step would leak the microVMs it
# started). E2E_TIMEOUT caps each step, in seconds (default 1800, and 7200 for the windows-*
# tests, whose first run installs Windows, and the gitlab-* ones, whose first run boots
# GitLab), so a hung microVM fails the gate instead of holding it; E2E_BUDGET caps the run as
# a whole (default 0, no cap) so the results table still prints inside a CI job timeout.
set -euo pipefail

usage() {
  echo "usage: [VK=<vk>] [RELEASE_TAG=vX.Y.Z] [E2E_TIMEOUT=<s>] [E2E_BUDGET=<s>] $0 [test-script...]" >&2
  exit 2
}

here="$(cd "$(dirname "$0")" && pwd)"
self=$(basename "$0")
long_timeout=${E2E_TIMEOUT:-7200}
E2E_TIMEOUT=${E2E_TIMEOUT:-1800}
E2E_BUDGET=${E2E_BUDGET:-0}
# 0 would mean "no limit" to timeout, which is the one thing this cap exists to prevent.
case $E2E_TIMEOUT in *[!0-9]* | '' | 0) echo "release-e2e: E2E_TIMEOUT must be seconds, non-zero" >&2; exit 2 ;; esac
case $E2E_BUDGET in *[!0-9]* | '') echo "release-e2e: E2E_BUDGET must be seconds (0: no cap)" >&2; exit 2 ;; esac
for arg in "$@"; do
  case $arg in -*) usage ;; esac
done

# Absolute: the scripts run from any directory, and one bind-mounts the binary into a guest.
asked=${VK:-./dist/vk}
VK=$(command -v "$asked" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "release-e2e: no executable vk at $asked" >&2; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
export VK
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "release-e2e: no rw access to /dev/kvm" >&2; exit 2; }
# Fail tests that need unavailable KVM features (nesting): a skipped test cannot
# validate a release.
export E2E_REQUIRE_KVM=1
command -v e2fsck >/dev/null || { echo "release-e2e: need e2fsck (e2fsprogs)" >&2; exit 2; }

echo "release-e2e: testing $VK"

# The bytes under test are the bytes the sidecars vouch for: every sidecar beside vk is
# checked, not just vk's. vk's own is required — build.sh always writes it, so without it
# these are not the built artifacts and nothing below would be testing what ships.
echo
echo "################ sha256 sidecars"
dir=$(dirname "$VK")
base=$(basename "$VK")
[ -f "$dir/$base.sha256" ] || { echo "release-e2e: no $base.sha256 beside the binary" >&2; exit 1; }
( cd "$dir" && sha256sum -c ./*.sha256 )
# A release's vk embeds the UEFI firmware and its variable store templates. This checks the
# build manifest, not vk's bytes: build-info.txt lists each one's sha256 when it was embedded,
# "firmware: none" otherwise.
if [ -n "${RELEASE_TAG:-}" ]; then
  [ -f "$dir/build-info.txt" ] || { echo "release-e2e: no build-info.txt beside the binary" >&2; exit 1; }
  for fd in CLOUDHV.fd CLOUDHV_VARS.fd CLOUDHV_VARS.ms.fd; do
    grep -q " ${fd//./\\.}\$" "$dir/build-info.txt" || {
      echo "release-e2e: $dir/build-info.txt records no embedded $fd" >&2
      exit 1
    }
  done
fi

# `vk --version` prints `<crate> <version> (<commit>)`. Match the version as a whitespace
# token, the way vk-selfupdate does, so only the version itself is load-bearing.
echo
echo "################ version"
out=$("$VK" --version)
echo "$out"
if [ -n "${RELEASE_TAG:-}" ]; then
  want=${RELEASE_TAG#v}
  case " $out " in
    *" $want "*) echo "matches $RELEASE_TAG" ;;
    *) echo "release-e2e: the binary is not version $want (tag $RELEASE_TAG)" >&2; exit 1 ;;
  esac
elif [ -n "${CI:-}" ]; then
  echo "release-e2e: RELEASE_TAG unset; a gated release must compare the two" >&2
  exit 2
else
  echo "RELEASE_TAG unset; not compared"
fi

names=()
results=()
failed=0
not_run=0
started=$SECONDS
# Record each step's outcome and stream its output unchanged.
step() { # <name> <command...>
  local name=$1 rc=0 cap=$E2E_TIMEOUT left
  shift
  [[ $name != windows-* && $name != gitlab-* ]] || cap=$long_timeout
  names+=("$name")
  if [ "$E2E_BUDGET" -ne 0 ]; then
    left=$((E2E_BUDGET - (SECONDS - started)))
    if [ "$left" -le 0 ]; then
      results+=("FAIL (out of budget)")
      failed=$((failed + 1))
      return
    fi
    [ "$cap" -le "$left" ] || cap=$left
  fi
  echo
  echo "################ $name"
  # Through a child bash, so a smoke check (a function, exported below) runs under the
  # timeout like a script does — with the same shell options, which are not inherited.
  # timeout signals the whole process group, so a killed step takes its microVMs with it.
  timeout -k 30 "$cap" bash -euo pipefail -c '"$@"' -- "$@" || rc=$?
  if [ "$rc" -eq 0 ]; then
    results+=(PASS)
  else
    results+=("FAIL (exit $rc)")
    failed=$((failed + 1))
  fi
}

# Pull an image, boot it, run a command and read its output.
check_boot() {
  local out
  out=$("$VK" run docker.io/library/alpine:3.21 -- echo vk-release-e2e-ok)
  echo "$out"
  # vk's own reporting (timings) shares stdout, so look for the line rather than the whole.
  grep -qx vk-release-e2e-ok <<<"$out" || { echo "FAIL: the guest's output did not come back"; return 1; }
}
export -f check_boot

# vk run reproduces the guest's exit code or terminating signal. A shell reports 143 for
# both SIGTERM and exit(143); use python3 when available to distinguish their wait statuses.
check_exit_status() {
  local rc=0
  "$VK" run docker.io/library/alpine:3.21 -- sh -c 'exit 7' || rc=$?
  [ "$rc" -eq 7 ] || { echo "FAIL: guest exit 7 came back as $rc"; return 1; }
  rc=0
  "$VK" run docker.io/library/alpine:3.21 -- sh -c 'kill -TERM $$' || rc=$?
  [ "$rc" -eq 143 ] || { echo "FAIL: a guest killed by SIGTERM came back as $rc, not 143"; return 1; }
  command -v python3 >/dev/null || { echo "note: no python3, death by signal not checked"; return 0; }
  python3 -c '
import subprocess, sys
r = subprocess.run(sys.argv[1:]).returncode
r == -15 or sys.exit(f"FAIL: vk run returned {r}, not a death by SIGTERM")' \
    "$VK" run docker.io/library/alpine:3.21 -- sh -c 'kill -TERM $$'
}
export -f check_exit_status

step "vk check" "$VK" check
step "boot an image" check_boot
step "guest exit status" check_exit_status
# Every other script here is an end-to-end test of some part of vk; a new one gates the
# next release with no registration step. Naming scripts narrows the run to those.
if [ "$#" -gt 0 ]; then
  scripts=("$@")
else
  scripts=("$here"/*.sh)
fi
for script in "${scripts[@]}"; do
  name=$(basename "$script")
  [ "$name" != "$self" ] || continue   # never recurse, however this script was reached
  # The Windows tests install Windows from Microsoft's evaluation ISOs, which no one may
  # redistribute and a CI runner does not hold: run them when ISO_DIR names where they are,
  # list them as not run otherwise (named on the command line, they run regardless).
  if [ "$#" -eq 0 ] && [[ $name == windows-* ]] && [ -z "${ISO_DIR:-}" ]; then
    names+=("$name")
    results+=("not run (needs ISO_DIR, the Windows ISOs)")
    not_run=$((not_run + 1))
    continue
  fi
  # The GitLab suite boots a GitLab CE of its own (about 9 GiB of memory, up to 11 minutes)
  # and tests vk-gitlab rather than vk: run it when E2E_GITLAB=1 asks for it, list it as not
  # run otherwise (named on the command line, it runs regardless).
  if [ "$#" -eq 0 ] && [[ $name == gitlab-* ]] && [ "${E2E_GITLAB:-}" != 1 ]; then
    names+=("$name")
    results+=("not run (needs E2E_GITLAB=1)")
    not_run=$((not_run + 1))
    continue
  fi
  step "$name" bash "$script"
done

echo
echo "################ results"
for i in "${!names[@]}"; do
  printf '  %-36s %s\n' "${names[$i]}" "${results[$i]}"
done
if [ "$failed" -ne 0 ]; then
  echo "FAIL: $failed of ${#names[@]} steps failed"
  exit 1
fi
echo "PASS: $((${#names[@]} - not_run)) passed, $not_run not run"
