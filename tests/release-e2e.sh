#!/usr/bin/env bash
# Release end-to-end gate, run against one built `vk`.
#
# release.yml runs this on the binary build.yml produced and the release job publishes, so
# what is tested is what ships. Two identity checks come first and are preconditions — the
# sha256 sidecars beside the binaries, and vk's version against the release tag (`vk update`
# compares the two, so a mismatch breaks self-update); neither is worth booting a microVM
# past. Then `vk check`, a plain image boot, and every other script in this directory, each
# against the same vk. A failure there does not stop the run: every script reports, and the
# exit status is non-zero if any of them failed.
#
#   VK=./dist/vk tests/release-e2e.sh                     # a local build, every script
#   VK=./dist/vk tests/release-e2e.sh tests/systemd-boot-e2e.sh  # the smoke checks + these
#   RELEASE_TAG=v0.61.0 VK=dist/vk tests/release-e2e.sh     # what release.yml runs
#
# Needs: KVM, network for the image pulls the scripts do, e2fsprogs, and GNU coreutils
# (busybox `timeout` signals only its child, so a killed step would leak the microVMs it
# started). E2E_TIMEOUT caps each step, in seconds (default 1800), so
# a hung microVM fails the gate instead of holding it; E2E_BUDGET caps the run as a whole
# (default 0, no cap) so the results table still prints inside a CI job timeout.
set -euo pipefail

usage() {
  echo "usage: [VK=<vk>] [RELEASE_TAG=vX.Y.Z] [E2E_TIMEOUT=<s>] [E2E_BUDGET=<s>] $0 [test-script...]" >&2
  exit 2
}

here="$(cd "$(dirname "$0")" && pwd)"
self=$(basename "$0")
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
started=$SECONDS
# Record each step's outcome and stream its output unchanged.
step() { # <name> <command...>
  local name=$1 rc=0 cap=$E2E_TIMEOUT left
  shift
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

step "vk check" "$VK" check
step "boot an image" check_boot
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
echo "PASS: all ${#names[@]} steps passed"
