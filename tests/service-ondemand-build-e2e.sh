#!/usr/bin/env bash
# =====================================================================================
# The executable definition of "done" for a service built on its first `vk service up`.
# =====================================================================================
# A service a profile excludes is declared but not built when the run starts: it is
# addressed by the stage fingerprint of its build context as it stands then, and only
# materialized when it is first brought up. Those are two different moments, so the
# context can move in between — and then the address the run predicted is not the entry
# the build writes.
#
# This test drives exactly that window: bring a run up with the context saying "one",
# edit it to "two" from inside the live guest, then `vk service up`. The service must
# boot the image the build just produced, so the payload it carries reads "two".
#
# Before the fix, the boot kept the predicted address and asked for an entry no build
# ever wrote, so `vk service up` failed outright — or, where the host's tier happened to
# hold that entry already, booted the stale image and the payload read "one". Either
# branch fails this test.
#
# Run:  VK=./dist/vk tests/service-ondemand-build-e2e.sh
# Needs: a `vk` with an embedded kernel/agent, KVM, and network for the build base.
# Builds into this host's shared build tier, like any service build does: --state-dir pins
# only the run's sockets and boot scratch, which the EXIT trap throws away.
set -euo pipefail

# Absolute: this binary is bind-mounted into the guest, which runs `vk service up` itself.
VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
BASE=${BASE:-debian:bookworm-slim}
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vk-svc-ondemand-e2e.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/ctx" "$WORK/out"

# A one-line payload is the whole observable: which build the booted image came from.
cat > "$WORK/ctx/Dockerfile" <<EOF
FROM $BASE
COPY payload /payload
EOF
echo one > "$WORK/ctx/payload"

# Absolute paths: a compose file's relative ones resolve against its own directory, and
# this one lives beside the context rather than under the caller's cwd.
cat > "$WORK/compose.yml" <<EOF
services:
  svc:
    build: $WORK/ctx
    # profiled-down: declared, but left for its first \`vk service up\` to build.
    profiles: [manual]
    volumes:
      - $WORK/out:/out
    command: ["sh", "-c", "cp /payload /out/booted"]
EOF

# The primary edits the context and brings the service up, both from inside the live run —
# the window the fix is about. It shares /out with the service, so it can wait for the boot
# to report which payload it carries.
guest=$(cat <<'EOF'
set -eu
echo "== the profiled-down service is declared and down =="
vk service status svc
echo "== move the build context: the address the run predicted is now stale =="
echo two > /ctx/payload
echo "== first bring-up: builds on demand, then boots =="
vk service up svc
i=0
while [ ! -s /out/booted ] && [ "$i" -lt 300 ]; do i=$((i + 1)); sleep 0.1; done
echo "== the booted image carries: $(cat /out/booted 2>/dev/null || echo '<nothing>') =="
EOF
)

echo "== boot the run (context says \"one\") =="
if ! "$VK" run \
  --state-dir "$WORK/state" \
  --compose "$WORK/compose.yml" \
  -v "$VK:/usr/local/bin/vk:ro" \
  -v "$WORK/ctx:/ctx" \
  -v "$WORK/out:/out" \
  "$BASE" -- sh -c "$guest"; then
  echo "FAIL: the run failed — see above; the regression looks like \`vk service up\`"
  echo "      erroring on a tier entry no build wrote (\"referencing svc image\")"
  exit 1
fi

booted=$(cat "$WORK/out/booted" 2>/dev/null || true)
if [ -z "$booted" ]; then
  echo "FAIL: the service never reported a payload — it did not boot"
  exit 1
fi
if [ "$booted" != "two" ]; then
  echo "FAIL: booted the image for the pre-edit context (payload \"$booted\", want \"two\")"
  echo "      the fresh build was materialized and then discarded"
  exit 1
fi
echo "PASS: the service booted the image its on-demand build produced (payload \"two\")"
