# shellcheck shell=bash
# The fleet side: a vk-registry for caches, vk-hub over TLS, one enrolled `vk node run`, and
# vk-gitlab — all on this host, under $RUN, each logging to $LOGS. Sourced by gitlab-e2e.sh.
#
# Inputs: VK (the vk under test, for the node), VK_HUB, VK_REGISTRY (optional), VK_GITLAB,
# GL_URL, RUN, LOGS.

# bg <name> <command...>: start a long-running component, its output in $LOGS/<name>.log.
bg() {
  local name=$1
  shift
  "$@" >>"$LOGS/$name.log" 2>&1 &
  echo "$!" >"$RUN/$name.pid"
}

pid_of() { cat "$RUN/$1.pid" 2>/dev/null; }
alive() {
  local p
  p=$(pid_of "$1") && [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

# stop_bg <name> [signal] [seconds]: signal a component, wait for exit, then kill on timeout.
stop_bg() {
  local name=$1 sig=${2:-TERM} secs=${3:-30} p
  p=$(pid_of "$name") || return 0
  [ -n "$p" ] || return 0
  kill "-$sig" "$p" 2>/dev/null || return 0
  wait_for "$secs" eval "! kill -0 $p 2>/dev/null" || kill -KILL "$p" 2>/dev/null || true
  wait "$p" 2>/dev/null || true
  rm -f "$RUN/$name.pid"
}

# A CA for the run and the hub's certificate under it, for 127.0.0.1 (as tests/fleet/lib.sh
# makes them).
fleet_certs() {
  local d=$RUN/pki
  mkdir -p "$d"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=vk-gitlab-e2e-ca -keyout "$d/ca.key" -out "$d/ca.pem" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=hub \
    -keyout "$d/hub.key" -out "$d/hub.csr" 2>/dev/null
  printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' >"$d/hub.ext"
  openssl x509 -req -in "$d/hub.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" \
    -CAcreateserial -days 2 -extfile "$d/hub.ext" -out "$d/hub.pem" 2>/dev/null
}

# A plain-HTTP vk-registry on loopback: the node's [registry], where caches go. Enrolled with
# the hub, which mints job tokens for it ([hub] tokens = true), unless E2E_TOKENS=0.
registry_up() {
  REG_PORT=$(free_port)
  mkdir -p "$RUN/registry/store"
  {
    printf 'addr = "127.0.0.1:%s"\nroot = "%s"\n' "$REG_PORT" "$RUN/registry/store"
    [ "$E2E_TOKENS" = 0 ] || printf '\n[hub]\ntokens = true\n'
  } >"$RUN/registry/registry.toml"
  if [ "$E2E_TOKENS" != 0 ]; then
    hub token create --kind registry --url "http://127.0.0.1:$REG_PORT" 2>>"$LOGS/hub-cli.log" |
      "$VK_REGISTRY" join "https://127.0.0.1:$HUB_PORT" --token - --ca "$RUN/pki/ca.pem" \
        --config "$RUN/registry/registry.toml" >"$RUN/registry/id" 2>>"$LOGS/registry-join.log" ||
      { cat "$LOGS/registry-join.log" >&2; die "vk-registry join failed"; }
    REG_ID=$(cat "$RUN/registry/id")
  fi
  bg registry "$VK_REGISTRY" serve --config "$RUN/registry/registry.toml"
  wait_for 30 curl -fsS -o /dev/null "http://127.0.0.1:$REG_PORT/v2/" 2>/dev/null ||
    die "vk-registry did not come up (see $LOGS/registry.log)"
  if [ "$E2E_TOKENS" != 0 ]; then
    # Wait for the registry to apply the hub's keys by testing a hub-minted token.
    wait_for 60 registry_takes_tokens ||
      die "the registry does not take the hub's tokens (see $LOGS/registry.log, $LOGS/hub.log)"
    log "registry: 127.0.0.1:$REG_PORT, $REG_ID, taking hub tokens"
  else
    log "registry: 127.0.0.1:$REG_PORT"
  fi
}

registry_takes_tokens() {
  local t
  t=$(hub registries token "$REG_ID" --grant e2e-probe=r --ttl 60s 2>>"$LOGS/hub-cli.log") || return 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $t" \
    "http://127.0.0.1:$REG_PORT/v2/e2e-probe/tags/list")" = 200 ]
}

hub() { "$VK_HUB" "$@" --config "$RUN/hub/hub.toml"; }

hub_up() {
  fleet_certs
  HUB_PORT=$(free_port)
  mkdir -p "$RUN/hub/data"
  chmod 700 "$RUN/hub/data"
  cat >"$RUN/hub/hub.toml" <<EOF
addr = "127.0.0.1:$HUB_PORT"
tls_cert = "$RUN/pki/hub.pem"
tls_key = "$RUN/pki/hub.key"
data_dir = "$RUN/hub/data"
EOF
  bg hub "$VK_HUB" serve --config "$RUN/hub/hub.toml"
  wait_for 30 eval 'hub nodes >/dev/null 2>&1' || die "vk-hub did not come up (see $LOGS/hub.log)"
  # The relay's GitLab server and the test project, approved beforehand ({gitlab} = e2e): the
  # first job of a project the hub has not approved would fail.
  hub gitlabs add e2e "$GL_URL" >>"$LOGS/hub-cli.log" 2>&1 || die "vk-hub gitlabs add failed"
  hub gitlabs projects approve e2e "$GL_PROJECT_ID:$GL_PROJECT_PATH" >>"$LOGS/hub-cli.log" 2>&1 ||
    die "vk-hub gitlabs projects approve failed"
  log "hub: https://127.0.0.1:$HUB_PORT"
}

node_connected() { hub nodes | grep -q "^$NODE_ID .*connected"; }

node_vk() { VIRTKIT_CONFIG="$RUN/node/config.toml" "$VK" "$@"; }

node_up() {
  # Short: the node's job dirs hold VM sockets, whose paths are bounded.
  NODE_STATE=$RUN/n
  mkdir -p "$RUN/node" "$NODE_STATE"
  {
    printf 'state_dir = "%s"\n\n' "$NODE_STATE"
    # Job VMs need the per-job switch: the in-guest clone, artifact transfers and services.
    printf '[net]\nmode = "switch"\n\n'
    printf '[executor]\natop = false\n\n'
    # The node sizes a job's VM by its own template, not by the envelope (4G otherwise).
    printf '[executor.vm]\ncpus = 2\nmem = "1G"\n\n'
    printf '[node]\nlabels = ["e2e"]\n'
    if [ -n "${REG_PORT:-}" ]; then
      printf '\n[registry]\nrepo = "127.0.0.1:%s/vk"\ninsecure = true\n' "$REG_PORT"
      [ "$E2E_TOKENS" = 0 ] || printf 'guest_credential = "job"\n'
    fi
  } >"$RUN/node/config.toml"
  hub token create 2>>"$LOGS/hub-cli.log" | node_vk node join "https://127.0.0.1:$HUB_PORT" --token - \
    --ca "$RUN/pki/ca.pem" >"$LOGS/node-join.log" 2>&1 ||
    { cat "$LOGS/node-join.log" >&2; die "vk node join failed"; }
  NODE_ID=$(jq -r .node_id "$NODE_STATE/node/enrollment.json")
  hub nodes pools "$NODE_ID" e2e >/dev/null || die "could not put the node in pool e2e"
  bg node env VIRTKIT_CONFIG="$RUN/node/config.toml" "$VK" node run
  wait_for 60 node_connected ||
    die "the node did not connect (see $LOGS/node.log)"
  log "node: $NODE_ID connected"
}

vk_gitlab_config() {
  mkdir -p "$RUN/vk-gitlab"
  cat >"$RUN/vk-gitlab/config.toml" <<EOF
concurrent = 4
check_interval = 1
shutdown_timeout = 5
state_dir = "$RUN/vk-gitlab/state"
system_id_file = "$RUN/vk-gitlab/system-id"

[gitlab]
url = "$GL_URL"

[[runners]]
name = "e2e"
token_file = "$RUN/runner.token"
pool = "e2e"
labels = ["e2e"]
envelope = { mem = "1G", cpus = 1, disk = "4G" }
EOF
  hub token create --kind gitlab 2>>"$LOGS/hub-cli.log" |
    "$VK_GITLAB" join "https://127.0.0.1:$HUB_PORT" --token - --ca "$RUN/pki/ca.pem" \
      --config "$RUN/vk-gitlab/config.toml" >"$LOGS/vk-gitlab-join.log" 2>&1 ||
    { cat "$LOGS/vk-gitlab-join.log" >&2; die "vk-gitlab join failed"; }
  log "vk-gitlab: enrolled as relay $(jq -r .relay_id "$RUN/vk-gitlab/state/hub/enrollment.json")"
}

vk_gitlab_up() {
  [ -f "$RUN/vk-gitlab/config.toml" ] || vk_gitlab_config
  echo "=== start $(date +%T)" >>"$LOGS/vk-gitlab.log"
  bg vk-gitlab "$VK_GITLAB" --log-level debug run --config "$RUN/vk-gitlab/config.toml"
  sleep 2
  alive vk-gitlab || die "vk-gitlab exited at start (see $LOGS/vk-gitlab.log)"
}

fleet_down() {
  stop_bg vk-gitlab TERM 15
  # A first TERM closes the session; a second leaves at once.
  if alive node; then
    kill -TERM "$(pid_of node)" 2>/dev/null || true
    wait_for 15 eval '! alive node' || kill -TERM "$(pid_of node)" 2>/dev/null || true
    stop_bg node KILL 5
  fi
  if [ -n "${NODE_STATE:-}" ]; then
    # Any job VM a driver left behind, then the drivers: each leads its own session.
    "$VK" stop "$NODE_STATE" >/dev/null 2>&1 || true
    local f p
    for f in "$NODE_STATE"/node/jobs/*/driver.pid; do
      [ -f "$f" ] || continue
      p=$(cat "$f" 2>/dev/null) || continue
      [[ $p =~ ^[0-9]+$ ]] || continue
      tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -q ' node job ' || continue
      kill -KILL -- "-$p" 2>/dev/null || true
    done
  fi
  stop_bg hub TERM 10
  stop_bg registry TERM 10
}
