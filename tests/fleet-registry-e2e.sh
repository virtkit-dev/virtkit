#!/usr/bin/env bash
# A registry from the hub, end to end: a hub (tests/fleet/lib.sh), a `vk-registry serve` on the
# test host over TLS under a CA of its own, relaying Docker Hub and taking the hub's tokens but
# no anonymous request, and a node on the test host configured by nothing but its enrollment.
#
# 1. The registry enrolls with the hub, which binds it to its URL and CA (`registries set-url
#    --ca`); the hub's `registry` setting names it.
# 2. The node takes the registry from the hub and pins its CA in its state dir.
# 3. A job uses a registry token, as issued by the hub for a placed job, to pull its image
#    through the registry's relay. Its guest reaches the registry through `registry.vk`,
#    with no registry config on the node.
#
# Run:  VK=./dist/vk tests/fleet-registry-e2e.sh
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` and `vk-registry` beside it (or
# VK_REGISTRY), KVM with nesting, openssl, curl, python3, and network to Docker Hub.
set -euo pipefail
. "$(dirname "$0")/fleet/lib.sh"
VK_REGISTRY=${VK_REGISTRY:-$(dirname "$VK")/vk-registry}
[ -x "$VK_REGISTRY" ] || { echo "no usable vk-registry at $VK_REGISTRY (set VK_REGISTRY)"; exit 2; }
for c in curl python3; do
  command -v "$c" >/dev/null || { echo "need $c"; exit 2; }
done

REG=$FLEET/registry
REG_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
REG_URL=https://127.0.0.1:$REG_PORT
reg_pid=
# The registry goes before the fleet's directory does.
trap 'rc=$?; [ -z "$reg_pid" ] || kill "$reg_pid" 2>/dev/null || true; (exit "$rc"); fleet_down' EXIT

# The registry's CA and the certificate it signs; nodes receive the CA only from the hub.
mkdir -p "$REG/store" "$FLEET/hub"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj /CN=vk-registry-e2e-ca -keyout "$REG/ca.key" -out "$REG/ca.pem" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=registry \
  -keyout "$REG/key.pem" -out "$REG/csr.pem" 2>/dev/null
printf '%s\n' 'subjectAltName=IP:127.0.0.1' 'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' >"$REG/ext"
openssl x509 -req -in "$REG/csr.pem" -CA "$REG/ca.pem" -CAkey "$REG/ca.key" -CAcreateserial \
  -days 2 -extfile "$REG/ext" -out "$REG/cert.pem" 2>/dev/null
# Where `vk-hub registries set-url --ca` reads it, in the primary.
cp "$REG/ca.pem" "$FLEET/hub/registry-ca.pem"
# The registry's credential is not given to nodes.
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$REG/secret"
cat >"$REG/registry.toml" <<EOF
addr = "127.0.0.1:$REG_PORT"
root = "$REG/store"
tls_cert = "$REG/cert.pem"
tls_key = "$REG/key.pem"
token_file = "$REG/secret"

[[upstream]]
prefix = "docker.io"
url = "https://registry-1.docker.io"

[hub]
tokens = true
EOF
# reg_code <path> [curl args...]: the HTTP status of a GET of <path> on the registry.
reg_code() {
  local path=$1
  shift
  curl -s -o /dev/null -w '%{http_code}' --cacert "$REG/ca.pem" "$@" "$REG_URL$path"
}

echo "== boot a hub; the registry enrolls with it =="
fleet_up
hub token create --kind registry |
  "$VK_REGISTRY" join "https://127.0.0.1:$HUB_PORT" --token - --ca "$FLEET/ca.pem" \
    --config "$REG/registry.toml" >"$REG/id" || fail "the registry could not join"
id=$(cat "$REG/id")
"$VK_REGISTRY" serve --config "$REG/registry.toml" >"$REG/log" 2>&1 &
reg_pid=$!
wait_for 30 eval '[ "$(reg_code /v2/)" = 401 ]' ||
  { tail -n 20 "$REG/log"; fail "the registry did not come up, asking for credentials"; }
# The registry accepts hub tokens once it has the hub's token keys.
takes_tokens() {
  local t
  t=$(hub registries token "$id" --grant e2e-probe=r --ttl 60s 2>/dev/null) &&
    [ "$(reg_code /v2/e2e-probe/tags/list -H "Authorization: Bearer $t")" = 200 ]
}
wait_for 60 takes_tokens || { tail -n 20 "$REG/log"; fail "the registry does not take the hub's tokens"; }

echo "== the hub names the registry, bound to its URL and CA =="
hub registries set-url "$id" "$REG_URL" --ca /etc/vk-hub/registry-ca.pem
hub settings set registry "$id"
hub settings

echo "== a node with no config takes it, and pins its CA =="
fleet_kvm_node
k=$(node_id kvm)
wait_for 60 node_reported "$k" || fail "the test host's node ($k) did not report in"
pinned() {
  local f
  for f in "$FLEET"/kvm/state/node/registry-ca-*.pem; do
    cmp -s "$f" "$REG/ca.pem" && return 0
  done
  return 1
}
wait_for 60 pinned || fail "the node did not pin the registry's CA"
settings=$FLEET/kvm/state/node/settings.json
wait_for 30 grep -qF "127.0.0.1:$REG_PORT" "$settings" ||
  fail "the node's hub settings do not name the registry"
cat "$settings"
echo
! grep -q registry "$FLEET/kvm/config.toml" || fail "the node's config names a registry"
# The job below is the only one it runs: the node is stopped, its settings kept.
kill "$KVM_NODE_PID"
wait "$KVM_NODE_PID" 2>/dev/null || true
KVM_NODE_PID=

echo "== a job pulls its image from the registry with its token =="
[ "$(reg_code /v2/docker.io/library/alpine/manifests/3.21)" = 401 ] ||
  fail "the registry serves an anonymous pull"
# Files the registry stores besides its enrollment: relayed blobs and manifests land there.
stored() {
  find "$REG/store" -path "$REG/store/hub" -prune -o -type f -print | wc -l
}
before=$(stored)
token=$(hub registries token "$id" --grant docker.io=r --ttl 1h)
expires=$(($(date +%s) + 3600))
# Journal the job as `vk node run` does (tests/node-job-e2e.sh), including the registry
# access the hub gives a placed job.
job=$FLEET/kvm/state/node/jobs/$(printf '%032x' 1)
mkdir -p "$job"
chmod 700 "$FLEET/kvm/state/node" "$FLEET/kvm/state/node/jobs" "$job"
cat >"$job/start.json" <<EOF
{"job": "$(printf '%032x' 1)", "envelope": {"mem_mib": 1024, "cpus": 1, "disk_bytes": 0},
 "registry": {"registry_id": "$id", "token": "$token", "expires_at": $expires,
              "grants": [{"prefix": "docker.io", "read": true}]},
 "spec": {"kind": "gitlab_ci",
  "server_url": "https://gitlab.example.com",
  "job": {"id": 1, "name": "e2e", "stage": "test", "pipeline_id": 1, "project_id": 12,
          "project_name": "web", "project_path": "acme/web", "namespace_id": 1,
          "root_namespace_id": 1, "user_id": 1, "runner_id": 1},
  "token": "glcbt-64_e2etoken",
  "timeout_secs": 600,
  "sources": {"repo_url": "https://gitlab.example.com/acme/web.git", "object_format": "sha1",
              "ref": "main", "ref_type": "branch", "sha": "$(printf '%040d' 0)",
              "before_sha": "$(printf '%040d' 0)", "depth": 0, "protected": false,
              "allow_fetch": false},
  "image": {"name": "alpine:3.21"},
  "variables": [
    {"key": "GIT_STRATEGY", "value": "none", "public": true, "file": false, "masked": false, "raw": false}
  ],
  "steps": [
    {"name": "script", "script": [
      "echo \"registry=\$VK_REGISTRY namespaces=\$VK_REGISTRY_NAMESPACES\"",
      "code() { wget -S -q -O /dev/null \"\$VK_REGISTRY\$1\" 2>&1 | awk '/^ *HTTP\\\\//{c=\$2} END{print c}'; }",
      "echo \"guest-pull=\$(code /v2/docker.io/library/alpine/manifests/3.21)\""],
     "timeout_secs": 600, "when": "on_success", "allow_failure": false}
  ],
  "trace": {"sections": true, "limit_bytes": 1048576}}}
EOF
printf '{"gitlab_id": 1, "slot": 0, "project_slot": 0, "project_id": 12}' >"$job/meta.json"
printf '{"id": 1, "job_info": {"name": "e2e", "project_id": 12, "project_full_path": "acme/web"}}' \
  >"$job/job_response.json"
VIRTKIT_CONFIG=$FLEET/kvm/config.toml "$VK" node job "$job" >"$FLEET/job.log" 2>&1 ||
  { cat "$FLEET/job.log"; fail "the job's driver failed"; }
cat "$job/output"
! grep -q '"failure"' "$job/result.json" || fail "the job failed: $(cat "$job/result.json")"
! grep -q 'pulling it directly' "$FLEET/job.log" "$job/output" ||
  fail "the registry could not serve the job's image"
[ "$(stored)" -gt "$before" ] || fail "the job's image did not come through the registry"
grep -q 'namespaces=docker.io=r' "$job/output" || fail "the job was not told its namespaces"
grep -q 'guest-pull=200' "$job/output" || fail "the job's guest could not read the registry"
! grep -qF "$token" "$job/output" || fail "the job's token reached its trace"

echo "PASS: a node with no config takes the hub's registry and its CA, and a job pulls"
echo "      through it with its token"
