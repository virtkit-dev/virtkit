# Shared by tests/fleet-*.sh: a fleet as one `vk` compose group.
#
# The primary runs `vk-hub serve` over TLS, its certificate from a CA made for the run; each
# node service runs `vk node run` with the `vk` under test shared in, not baked into an image.
# The tests drive the hub's CLI with `vk exec` into the primary, and start and stop node
# services from there through /run/vk/services. Node guests nest, so each passes `vk check`
# and enrolls itself with `vk node join`; its root persists, so it keeps its identity across
# restarts. A node service's vk config can be set with node_config before it boots, and a
# gitlab-runner stand-in is in its /seed (tests/fleet/node/gitlab-runner). `fleet_kvm_node`
# runs one more node on the test host itself, enrolled through the hub's port published on
# loopback.
#
# Source it, then call fleet_up; everything is torn down on exit.
#
# Env: VK (default ./dist/vk) and VK_HUB (default: the vk-hub beside VK), the binaries under
# test; IMAGE, the node services' base image (tests/fleet/node/Dockerfile otherwise);
# E2E_REQUIRE_KVM=1 fails, rather than skips, on a host without KVM or nesting.
# Needs: KVM with nesting, openssl, and a registry to pull alpine.

FLEET_LIB=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Absolute: both binaries are bind-mounted into the guests.
VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
VK_HUB=${VK_HUB:-$(dirname "$VK")/vk-hub}
[ -x "$VK_HUB" ] || { echo "no usable vk-hub at $VK_HUB (set VK_HUB)"; exit 2; }
VK_HUB=$(cd "$(dirname "$VK_HUB")" && pwd)/$(basename "$VK_HUB")
no_kvm() {
  [ "${E2E_REQUIRE_KVM:-}" = 1 ] && { echo "FAIL: $1 (E2E_REQUIRE_KVM=1)"; exit 1; }
  echo "SKIP: $1"
  exit 0
}
[ -r /dev/kvm ] && [ -w /dev/kvm ] || no_kvm "no writable /dev/kvm"
grep -qsx '[Y1]' /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested ||
  no_kvm "nested virtualization is off"
command -v openssl >/dev/null || { echo "fleet: need openssl, for the hub's certificate"; exit 2; }

FLEET=$(mktemp -d "${TMPDIR:-/tmp}/vk-fleet.XXXXXX")
RUN=$FLEET/run
HUB_CONFIG=/etc/vk-hub/hub.toml
HUB_PORT=
KVM_NODE_PID=

fail() {
  echo "FAIL: $*"
  exit 1
}

# wait_for <seconds> <condition...>: poll until the condition holds.
wait_for() {
  local i=0 limit=$(($1 * 2))
  shift
  until "$@"; do
    i=$((i + 1))
    [ "$i" -lt "$limit" ] || return 1
    sleep 0.5
  done
}

fleet_down() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -d "$RUN" ]; then
    echo "== evidence =="
    "$VK" exec "$RUN" -- sh -c 'tail -n 40 /var/log/vk-hub.log; for s in /run/vk/services/*; do
      echo "-- ${s##*/}: $(cat "$s/state")"; tail -n 20 "$s/log"; done' 2>&1 || true
    [ -f "$FLEET/kvm/node.log" ] && { echo "-- kvm node"; tail -n 20 "$FLEET/kvm/node.log"; }
  fi
  [ -z "$KVM_NODE_PID" ] || kill "$KVM_NODE_PID" 2>/dev/null || true
  "$VK" publish stop "$RUN" >/dev/null 2>&1 || true
  # Every VM under the fleet's directory: the group, and any a test started beside it.
  "$VK" stop "$FLEET" >/dev/null 2>&1 || true
  rm -rf "$FLEET"
  exit "$rc"
}
trap fleet_down EXIT

# A CA for the run, and the hub's certificate under it: by its compose name for the nodes in
# the group, by loopback for the ones on the test host.
fleet_certs() {
  local d=$FLEET/hub
  mkdir -p "$d"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=vk-fleet-e2e-ca -keyout "$FLEET/ca.key" -out "$FLEET/ca.pem" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=hub \
    -keyout "$d/key.pem" -out "$FLEET/hub.csr" 2>/dev/null
  printf '%s\n' 'subjectAltName=DNS:hub,DNS:localhost,IP:127.0.0.1' \
    'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' >"$FLEET/hub.ext"
  openssl x509 -req -in "$FLEET/hub.csr" -CA "$FLEET/ca.pem" -CAkey "$FLEET/ca.key" \
    -CAcreateserial -days 2 -extfile "$FLEET/hub.ext" -out "$d/cert.pem" 2>/dev/null
}

# fleet_up <node service>...: boot the group, the hub in its primary, and publish the hub on
# a loopback port of the test host.
fleet_up() {
  fleet_certs
  cat >"$FLEET/hub/hub.toml" <<EOF
addr = "0.0.0.0:8443"
tls_cert = "/etc/vk-hub/cert.pem"
tls_key = "/etc/vk-hub/key.pem"
data_dir = "/var/lib/vk-hub"
EOF
  cp -r "$FLEET_LIB/node" "$FLEET/node"
  {
    echo "services:"
    echo "  hub:"
    echo "    image: docker.io/library/alpine:3.21"
    echo "    command: [\"sleep\", \"infinity\"]"
    echo "    volumes:"
    echo "      - $VK_HUB:/usr/local/bin/vk-hub:ro"
    echo "      - ./hub:/etc/vk-hub:ro"
    echo "    x-virtkit: {mem: 512M}"
    local n
    for n in "$@"; do
      mkdir -p "$FLEET/seed/$n"
      cp "$FLEET_LIB/node/run-node.sh" "$FLEET_LIB/node/gitlab-runner" "$FLEET/ca.pem" \
        "$FLEET/seed/$n/"
      chmod +x "$FLEET/seed/$n/gitlab-runner"
      echo "  $n:"
      if [ -n "${IMAGE:-}" ]; then
        echo "    image: $IMAGE"
      else
        echo "    build: ./node"
      fi
      echo "    command: [\"sh\", \"/seed/run-node.sh\"]"
      echo "    volumes:"
      echo "      - \${VK_SELF}:/usr/local/bin/vk:ro"
      echo "      - ./seed/$n:/seed:ro"
      echo "    x-virtkit: {mem: 1G, nested: true, persist_root: true}"
    done
  } >"$FLEET/compose.yml"
  # Only the primary boots: a node service is started by node_start.
  (cd "$FLEET" && "$VK" run --compose compose.yml --primary hub --state-dir "$RUN" \
    --detach --inactivity-timeout 0 >"$FLEET/run.log" 2>&1) ||
    { cat "$FLEET/run.log"; fail "the fleet did not boot"; }
  hub_start
  local port rc
  for port in $(shuf -i 20000-60000 -n 20); do
    rc=0
    "$VK" publish ensure --name hub --listen "tcp://127.0.0.1:$port" \
      --to tcp://127.0.0.1:8443 "$RUN" >"$FLEET/publish.log" 2>&1 || rc=$?
    # 4: the port is taken; try another. Anything else will not go away.
    case $rc in
      0) HUB_PORT=$port && break ;;
      4) ;;
      *) cat "$FLEET/publish.log"; fail "could not publish the hub (exit $rc)" ;;
    esac
  done
  [ -n "$HUB_PORT" ] || fail "could not publish the hub on a loopback port"
}

# `vk-hub <args>` in the primary, against the hub's config.
hub() {
  "$VK" exec "$RUN" -- vk-hub "$@" --config "$HUB_CONFIG"
}

hub_start() {
  "$VK" exec -b "$RUN" -- sh -c \
    "exec vk-hub serve --config $HUB_CONFIG >>/var/log/vk-hub.log 2>&1"
  wait_for 30 hub nodes >/dev/null 2>&1 || fail "vk-hub serve did not come up"
}

hub_kill() {
  "$VK" exec "$RUN" -- sh -c 'kill -9 $(pidof vk-hub)'
}

# hub_audit <id>: node <id>'s lines of the audit log.
hub_audit() {
  hub audit --node "$1" --limit 200
}

# `vk node <args>` on the test host, as node <name>: its own config and state dir.
host_vk() {
  local name=$1
  shift
  mkdir -p "$FLEET/$name"
  [ -f "$FLEET/$name/config.toml" ] ||
    printf 'state_dir = "%s"\n' "$FLEET/$name/state" >"$FLEET/$name/config.toml"
  VIRTKIT_CONFIG=$FLEET/$name/config.toml "$VK" "$@"
}

# node_join <name> [token]: enroll node <name> with a new token, or the one given — from
# its guest for a node service, on the test host for `kvm`.
node_join() {
  local name=$1 token=${2:-}
  [ -n "$token" ] || token=$(hub token create) || return 1
  if [ "$name" = kvm ]; then
    printf '%s\n' "$token" |
      host_vk kvm node join "https://127.0.0.1:$HUB_PORT" --token - --ca "$FLEET/ca.pem"
  else
    in_node "$name" sh -c "printf '%s\n' '$token' |
      vk node join https://hub:8443 --token - --ca /seed/ca.pem"
  fi
}

# The ID node <name> was enrolled as.
node_id() {
  local enrollment
  if [ "$1" = kvm ]; then
    enrollment=$(cat "$FLEET/kvm/state/node/enrollment.json")
  else
    enrollment=$(in_node "$1" cat /var/lib/virtkit/node/enrollment.json)
  fi
  sed -n 's/.*"node_id": *"\([0-9a-f]*\)".*/\1/p' <<<"$enrollment"
}

# node_config <name>: node service <name>'s vk config, from stdin; its guest takes it as
# /etc/virtkit/config.toml when it boots.
node_config() {
  cat >"$FLEET/seed/$1/config.toml"
}

# Start node service <name> and enroll it.
node_up() {
  node_start "$1"
  node_join "$1" >/dev/null || fail "$1 could not join"
}

# Boot node service <name>: its `vk node run` starts once it is enrolled.
node_start() {
  ctl "$1" start
  wait_for 60 in_node "$1" true 2>/dev/null || fail "$1 did not boot"
}

# ctl <service> start|stop: from the primary, as a test drives the fleet from inside.
ctl() {
  "$VK" exec "$RUN" -- sh -c "echo $2 > /run/vk/services/$1/ctl"
}

service_state() {
  "$VK" exec "$RUN" -- cat "/run/vk/services/$1/state"
}

# in_node <service> <command...>: run a command in a node's guest.
in_node() {
  local name=$1
  shift
  "$VK" exec "$RUN" --service "$name" -- "$@"
}

# A node's row of `vk-hub nodes`, by ID.
node_row() {
  hub nodes | awk -v id="$1" '$1 == id'
}

# node_cell <id> <column>: one cell of a node's row, by its column's header. The table is
# aligned, and a cell may hold spaces (`3s ago`), so it is cut by the header's offsets.
node_cell() {
  hub nodes | awk -v id="$1" -v col="$2" '
    NR == 1 {
      start = index($0, col)
      rest = substr($0, start + length(col))
      end = match(rest, /[^ ]/) ? start + length(col) + RSTART - 1 : 0
      next
    }
    $1 == id {
      v = end ? substr($0, start, end - start) : substr($0, start)
      gsub(/^ +| +$/, "", v)
      print v
    }'
}

# cell_is <id> <column> <glob>: whether node <id>'s cell matches.
cell_is() {
  # Unquoted on the right: a glob.
  [[ "$(node_cell "$1" "$2")" == $3 ]]
}

# Whether node <id> is connected and its inventory has arrived.
node_reported() {
  node_is "$1" connected && [ "$(node_cell "$1" VK)" != - ]
}

# node_is <id> <connected|unreachable>
node_is() {
  node_row "$1" | grep -qw -- "$2"
}

# Start a node on the test host, with its KVM: enrolled as `kvm`, logging to kvm/node.log.
fleet_kvm_node() {
  node_join kvm >/dev/null || fail "the test host's node could not join"
  VIRTKIT_CONFIG=$FLEET/kvm/config.toml "$VK" node run >"$FLEET/kvm/node.log" 2>&1 &
  KVM_NODE_PID=$!
}
