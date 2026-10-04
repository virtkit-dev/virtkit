#!/usr/bin/env bash
# =====================================================================================
# A real Remote Desktop session into a Windows guest: not only RDP's authentication, but a
# session that opens, draws a desktop and is held.
# =====================================================================================
# Build examples/windows/rdp.Dockerfile (a standalone Windows Server 2025 with a local account)
# and bring up rdp-session.compose.yaml: the server, and a Linux client whose FreeRDP signs in
# with Network Level Authentication and keeps the session open. The client must capture a drawn
# desktop, and the server, asked through its guest agent while the session is held, must list
# the account's session as an active Remote Desktop one (rdp-tcp#N).
#
# Run:  VK=./dist/vk ISO_DIR=~/.cache/vk-windows tests/windows-rdp-e2e.sh  (KEEP_WORK=1 keeps its
#       work directory, the capture included)
# Needs: KVM, about 4 GiB of free memory, and in ISO_DIR the ISOs rdp.Dockerfile pins
# (ws2025-eval-en-us.iso, virtio-win.iso). The first build installs Windows (about 20 minutes);
# later runs take their layers from the cache.
set -euo pipefail

VK="$(realpath "${VK:-./dist/vk}")"
ISO_DIR="${ISO_DIR:-$HOME/.cache/vk-windows}"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/vk-windows-rdp.XXXXXX")"
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

# The tracked files only: not ISOs, image bundles or run state a local run left there.
(cd "$here/../examples/windows" && git ls-files -z . | xargs -0 cp --parents -t "$work")
for iso in ws2025-eval-en-us.iso virtio-win.iso; do
  [ -f "$ISO_DIR/$iso" ] || fail "$ISO_DIR/$iso is missing (see examples/windows/rdp.Dockerfile)"
  ln -sf "$ISO_DIR/$iso" "$work/$iso"
done
cd "$work"

echo "== build the RDP server image =="
"$VK" build -f rdp.Dockerfile --target rdp-server --out ./rdp-server-out

echo "== bring the server and the client up =="
mkdir run rdp-out
"$VK" run --compose rdp-session.compose.yaml --state-dir "$work/run" > up.log 2>&1 &
lab=$!
client="run/svc-rdp-client/console.log"
# Generous: the server's first start, then the client's image build and its sign-in.
for _ in $(seq 1 720); do
  grep -qs "rdp session open" "$client" && break
  grep -qs "vk-agent init: service exited" "$client" && { tail -20 "$client"; fail "the client ended before its session opened"; }
  kill -0 "$lab" 2>/dev/null || { cat up.log; fail "the lab exited before the session opened"; }
  sleep 5
done
grep -qs "rdp session open" "$client" || { tail -20 "$client"; fail "no session after an hour"; }
grep -q "rdpuser may sign in over Remote Desktop on .*, at " run/svc-rdp-server/provision.log \
  || fail "the server's provisioning did not make rdpuser"
[ -s rdp-out/session-logon.png ] || fail "no capture of the session"
echo "ok: $(grep -o 'rdp session open.*' "$client" | head -1)"

echo "== the server holds the session =="
# Remote Desktop sessions as the server lists them: the account on an rdp-tcp#N session, active.
sessions=$("$VK" exec "$work/run" --service rdp-server -- qwinsta 2>&1) || true
echo "$sessions"
echo "$sessions" | grep -Eiq "rdp-tcp#[0-9]+ +rdpuser +[0-9]+ +active" \
  || fail "the server lists no active RDP session for rdpuser"
echo "ok: the server lists rdpuser's Remote Desktop session as active"

# The desktop a minute in, past the sign-in.
for _ in $(seq 1 60); do
  grep -qs "rdp session captured" "$client" && break
  kill -0 "$lab" 2>/dev/null || { cat up.log; fail "the lab exited before the desktop was captured"; }
  sleep 5
done
[ -s rdp-out/session.png ] || { tail -20 "$client"; fail "no capture of the desktop"; }
echo "ok: the desktop is captured in rdp-out/session.png"

echo "== stop =="
kill -TERM "$lab"
wait "$lab" || fail "the run exited with $?"
lab=""
echo "PASS"
