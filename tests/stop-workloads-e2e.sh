#!/usr/bin/env bash
# Shutdown checks for guests running virtkit's own init.
# Four checks, one detached run:
#
# 1. A reboot request never turns into a power-off: the compose service `db` exits within a
#    second of SIGTERM and counts its boots in a shared file; after `vk service reboot db`
#    it must boot a second time and still be running.
# 2. That reboot stops `db`'s workloads before its service: a daemon left in it by
#    `vk exec --service db` records SIGTERM before the service's own TERM trap does.
# 3. `vk stop` lets a daemon left in the primary by `vk exec` handle SIGTERM rather than
#    meet the power cut, and the command the run booted with handle it too.
# 4. The stop powers `db` off alongside the primary: `db` stops while the primary's command
#    is still in its TERM trap, and the whole stop stays well within `vk stop`'s 90 s.
#
# Run:  VK=./dist/vk tests/stop-workloads-e2e.sh
# Needs: a `vk` with an embedded kernel/agent, KVM, and a registry to pull alpine.
set -euo pipefail

# Absolute: this binary is bind-mounted into the guest, which runs `vk service` itself.
VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
IMAGE=${IMAGE:-docker.io/library/alpine:3.21}
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-stop-workloads-e2e.XXXXXX")
OUT=$WORK/out
trap '"$VK" stop "$WORK" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

# The service exits within a second of SIGTERM (ash runs the trap once `sleep` returns).
cat > "$WORK/compose.yml" <<EOF
services:
  db:
    image: $IMAGE
    volumes:
      - $OUT:/out
    command:
      - sh
      - -c
      - >-
        echo boot >> /out/db-boots;
        trap 'echo service >> /out/db-order; echo db >> /out/stop-order; exit 0' TERM;
        while :; do sleep 1; done
EOF

fail() { echo "FAIL: $*"; exit 1; }
# wait_for <seconds> <condition...>: poll a host-side condition.
wait_for() {
  local i=0 limit=$(($1 * 5))
  shift
  until "$@"; do
    i=$((i + 1))
    [ "$i" -lt "$limit" ] || return 1
    sleep 0.2
  done
}
boots() { grep -c '^boot$' "$OUT/db-boots" 2>/dev/null || true; }
boots_are() { [ "$(boots)" = "$1" ]; }
file_is() { [ "$(cat "$1" 2>/dev/null)" = "$2" ]; }
# A daemon in a session of its own, so only the guest's stop can end it: it writes `up` to
# the file, then `term` on SIGTERM (appending, with --append).
daemon() {
  local op='>'
  [ "${2:-}" = --append ] && op='>>'
  printf '%s' "trap 'echo term $op $1; exit 0' TERM; echo up > $1.up; while :; do sleep 1; done"
}

# The startup command outlasts `db`'s stop by a few seconds once it gets SIGTERM. Its `sleep`
# ignores TERM: the guest's stop also signals processes that start during it.
CMD="trap 'echo term > /out/cmd; (trap \"\" TERM; exec sleep 7); echo primary >> /out/stop-order
exit 0' TERM
while :; do sleep 1; done"

# A writable `disk` volume makes the stop a guest power-off rather than a kill.
echo "== boot a detached run: a primary and a service-mode compose service =="
(
  cd "$WORK"
  "$VK" run --detach --inactivity-timeout 0 \
    --state-dir "$WORK/state" \
    --compose "$WORK/compose.yml" \
    -v "$VK:/usr/local/bin/vk:ro" \
    -v "$OUT:/out" \
    -v "$WORK/data.qcow2:/data:disk" \
    "$IMAGE" -- sh -c "$CMD"
) || fail "the run did not start"
"$VK" exec "$WORK" -- vk service up db
wait_for 60 boots_are 1 || fail "the service did not boot (boots: $(boots))"

echo "== leave a daemon in db, then reboot it =="
"$VK" exec --service db "$WORK" -- \
  sh -c "setsid sh -c \"$(daemon /out/db-order --append)\" </dev/null >/dev/null 2>&1 &"
wait_for 10 file_is "$OUT/db-order.up" up || fail "the daemon in db did not start"
"$VK" exec "$WORK" -- vk service reboot db
wait_for 60 boots_are 2 || fail "the service did not boot again after its reboot (boots: $(boots))"
status=$("$VK" exec "$WORK" -- vk service status db)
echo "$status"
grep -q running <<<"$status" || fail "the service is not running after its reboot"
order=$(head -n 2 "$OUT/db-order" | tr '\n' ' ')
[ "$order" = "term service " ] \
  || fail "db's daemon was not stopped before its service (recorded: $order)"

echo "== leave a daemon in the primary, then stop the run =="
"$VK" exec "$WORK" -- \
  sh -c "setsid sh -c \"$(daemon /out/daemon)\" </dev/null >/dev/null 2>&1 &"
wait_for 10 file_is "$OUT/daemon.up" up || fail "the daemon in the primary did not start"
rm -f "$OUT/stop-order"
started=$(date +%s)
"$VK" stop "$WORK"
took=$(($(date +%s) - started))
echo "the stop took ${took}s"
file_is "$OUT/daemon" term \
  || fail "the primary's daemon never saw SIGTERM (it recorded \"$(cat "$OUT/daemon" 2>/dev/null)\")"
file_is "$OUT/cmd" term \
  || fail "the startup command never saw SIGTERM (it recorded \"$(cat "$OUT/cmd" 2>/dev/null)\")"
order=$(tr '\n' ' ' 2>/dev/null < "$OUT/stop-order" || true)
[ "$order" = "db primary " ] || fail "db did not stop alongside the primary (recorded: $order)"
[ "$took" -lt 45 ] || fail "the stop took ${took}s"

echo "PASS: the service rebooted after its workloads stopped, and the stop let the daemon, the"
echo "startup command and the service exit together"
