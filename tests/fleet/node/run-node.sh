#!/bin/sh
# A node service's command: wait for the test to enroll the node from inside the guest
# (node_join), then run it. The guest's root persists, and with it the node's identity. A
# test that removes the enrollment and stops `vk node run` gets the wait back, to enroll the
# node again. `vk node run` exits 75 while the `vk node join` that wrote the enrollment still
# holds the state dir, and is started again, for up to a minute; any other exit ends the
# service.
set -u
enrollment=/var/lib/virtkit/node/enrollment.json
locked=0
while :; do
  until [ -f "$enrollment" ]; do sleep 0.5; done
  vk node run
  rc=$?
  if [ "$rc" -eq 75 ]; then
    locked=$((locked + 1))
    if [ "$locked" -ge 60 ]; then
      echo "run-node: the state dir stayed locked for a minute" >&2
      exit 1
    fi
    sleep 1
    continue
  fi
  locked=0
  [ -f "$enrollment" ] || continue
  exit "$rc"
done
