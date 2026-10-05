#!/bin/sh
# Wait for node_join to enroll the node inside the guest, then run it. The persistent guest
# root keeps the node's identity and /opt/vk/bin/vk, copied from the shared binary on first
# boot so updates can replace it. Restart `vk node run` after any exit, like a supervisor,
# unless the hub permanently refuses the node (removed or wrong pinned key), ending the
# service. Removing enrollment and stopping `vk node run` restores the wait for enrollment.
# /seed/config.toml (node_config) supplies the guest's vk config.
set -u
if [ -f /seed/config.toml ]; then
  mkdir -p /etc/virtkit && cp /seed/config.toml /etc/virtkit/config.toml
fi
installed=/opt/vk/bin/vk
if [ ! -x "$installed" ]; then
  mkdir -p "${installed%/*}"
  cp /usr/local/bin/vk "$installed.tmp" && mv "$installed.tmp" "$installed" ||
    { echo "run-node: cannot install $installed" >&2; exit 1; }
fi
# Run `vk` through PATH so `pkill -f "^vk node run"` matches across binary replacements.
PATH=${installed%/*}:$PATH
export PATH
enrollment=/var/lib/virtkit/node/enrollment.json
out=/tmp/run-node.out
while :; do
  until [ -f "$enrollment" ]; do sleep 0.5; done
  # Stream a file to the service log: a surviving gitlab-runner would hold a pipe open
  # and block the next start.
  : >"$out"
  tail -f "$out" &
  tailer=$!
  vk node run >>"$out" 2>&1
  rc=$?
  sleep 1
  kill "$tailer"
  [ -f "$enrollment" ] || continue
  # Permanent refusal ends `vk node run` with an error; transient refusal is only logged.
  if tail -n 1 "$out" | grep -q '^virtkit: error: .*the hub refused the session'; then
    exit "$rc"
  fi
  echo "run-node: vk node run exited $rc; starting it again" >&2
  sleep 1
done
