#!/usr/bin/env bash
# =====================================================================================
# End-to-end test of Windows compose services with an Active Directory lab.
# =====================================================================================
# Build examples/windows (a corp.lab domain controller and a generalized member image), then
# start lab-ad.compose.yaml: the DC, a Linux job that creates the lab's users with samba-tool,
# two members that join the domain at start, and a Linux job that signs in to each machine
# over RDP. Every service must report started after provisioning. For members, this includes
# the join, restart (exit 3010), and replay that confirms domain membership and finds the
# users the job created. Snapshot the lab, then restore it in under 30 s, with every guest
# resuming rather than booting. A stop must power every guest off without a kill.
#
# Run:  VK=./dist/vk ISO_DIR=~/.cache/vk-windows tests/windows-ad-e2e.sh  (KEEP_WORK=1 keeps its
#       work directory, logs and run state included)
# Needs: KVM, about 8 GiB of free memory, and in ISO_DIR (~/.cache/vk-windows by default) the
# two ISOs lab.Dockerfile pins (ws2025-eval-en-us.iso, virtio-win.iso). tests/release-e2e.sh
# runs this only when ISO_DIR is set, or when named. The first build installs Windows (about
# 20 minutes); later runs take their layers from the cache.
set -euo pipefail

VK="$(realpath "${VK:-./dist/vk}")"
ISO_DIR="${ISO_DIR:-$HOME/.cache/vk-windows}"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/vk-windows-ad.XXXXXX")"
lab=""
cleanup() {
  if [ -n "$lab" ] && kill -0 "$lab" 2>/dev/null; then
    kill -TERM "$lab"
    wait "$lab" || true
  fi
  if [ -n "${KEEP_WORK:-}" ]; then echo "work directory kept: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# The tracked files only: not ISOs or image bundles a local build left there.
(cd "$here/../examples/windows" && git ls-files -z . | xargs -0 cp --parents -t "$work")
for iso in ws2025-eval-en-us.iso virtio-win.iso; do
  [ -f "$ISO_DIR/$iso" ] || fail "$ISO_DIR/$iso is missing (see examples/windows/lab.Dockerfile)"
  ln -sf "$ISO_DIR/$iso" "$work/$iso"
done
cd "$work"

echo "== build the DC and member images =="
"$VK" build -f lab.Dockerfile --target dc --out ./dc-out
"$VK" build -f lab.Dockerfile --target member --out ./member-out

echo "== bring the lab up =="
mkdir run
"$VK" run --compose lab-ad.compose.yaml --state-dir "$work/run" > up.log 2>&1 &
lab=$!
# Generous, up to two hours: a generalized member's first start runs specialize and OOBE, then
# a restart, the Linux jobs' images are built on the way, and a loaded host's nested Windows can
# take most of vk's 45 minutes for each start.
for _ in $(seq 1 1440); do
  grep -q "compose up on" up.log && break
  kill -0 "$lab" 2>/dev/null || { cat up.log; fail "the lab exited before it was up"; }
  sleep 5
done
grep -q "5 of 5 service(s) started" up.log || { cat up.log; fail "the lab did not come up"; }
[ "$(grep -c "waiting for dc to be healthy" up.log)" = 3 ] \
  || { cat up.log; fail "the accounts job and the members did not wait for the DC's healthcheck"; }
[ "$(grep -c "waiting for accounts to complete" up.log)" = 2 ] \
  || { cat up.log; fail "the members did not wait for the accounts job"; }
for user in alice bob; do
  grep -rqs "^user $user created" run/svc-accounts/ \
    || { cat up.log; fail "the accounts job did not create $user"; }
done
echo "ok: the accounts job created alice and bob"

for member in member1 member2; do
  log="run/svc-$member/provision.log"
  name="${member^^}"
  grep -q "^$name is in corp.lab" "$log" || { cat "$log"; fail "$member did not join corp.lab"; }
  grep -q "exit 3010: restarting Windows" "$log" || fail "$member joined without the restart"
  for user in alice bob; do
    grep -q "^user $user found" "$log" || { cat "$log"; fail "$member does not see $user"; }
  done
  echo "ok: $member joined corp.lab as $name and sees alice and bob"
done

# The RDP check job ends after signing in to every machine or failing.
for _ in $(seq 1 240); do
  grep -qs "vk-agent init: service exited" run/svc-rdp-check/console.log && break
  kill -0 "$lab" 2>/dev/null || { cat up.log; fail "the lab exited during the RDP check"; }
  sleep 5
done
for machine in dc member1 member2; do
  grep -qs "^rdp $machine: CORP.vkjoin signed in" run/svc-rdp-check/console.log \
    || { tail -20 run/svc-rdp-check/console.log; fail "no RDP sign-in to $machine"; }
done
echo "ok: CORP\\vkjoin signs in over RDP to dc, member1 and member2"

echo "== snapshot the lab =="
"$VK" snapshot --run-dir "$work/run" --out "$work/snap"
for service in dc member1 member2; do
  [ -f "snap/$service/state.json" ] && compgen -G "snap/$service/memory-*" >/dev/null \
    || fail "no snapshot of $service"
done
# The snapshot ended the guests; the run itself stops as usual.
kill -TERM "$lab"
wait "$lab" || fail "the lab's run exited with $?"
lab=""
echo "ok: the lab's three guests are saved"

echo "== restore the lab from its snapshot =="
mkdir run2
started=$(date +%s)
"$VK" run --compose lab-ad.compose.yaml --state-dir "$work/run2" --from-snapshot "$work/snap" \
  > up2.log 2>&1 &
lab=$!
for _ in $(seq 1 120); do
  grep -q "compose up on" up2.log && break
  kill -0 "$lab" 2>/dev/null || { cat up2.log; fail "the restored lab exited before it was up"; }
  sleep 1
done
took=$(( $(date +%s) - started ))
grep -q "5 of 5 service(s) started" up2.log || { cat up2.log; fail "the restored lab did not come up"; }
[ "$(grep -c "resuming from its snapshot" up2.log)" = 3 ] || { cat up2.log; fail "a service booted instead"; }
[ "$took" -lt 30 ] || fail "the lab took ${took}s to come back (more than 30 s)"
echo "ok: the lab is back in ${took}s"

echo "== stop the lab =="
kill -TERM "$lab"
wait "$lab" || fail "the lab's run exited with $?"
lab=""
# vk's wording when a stop had to kill a guest (manager.rs).
if killed=$(grep -lE "killed: the guest did not power off|: killed \(the guest did not power off" \
  up.log up2.log); then
  cat $killed
  fail "a guest had to be killed (see $killed)"
fi
echo "ok: every guest powered off"
echo "PASS"
