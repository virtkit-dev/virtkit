#!/bin/sh
# A node service's command: wait for the test to enroll the node from inside the guest
# (node_join), then run it. The guest's root persists, and with it the node's identity. A
# test that removes the enrollment and stops `vk node run` gets the wait back, to enroll the
# node again; any other exit of `vk node run` ends the service.
set -u
enrollment=/var/lib/virtkit/node/enrollment.json
while :; do
  until [ -f "$enrollment" ]; do sleep 0.5; done
  vk node run
  rc=$?
  [ -f "$enrollment" ] || continue
  exit "$rc"
done
