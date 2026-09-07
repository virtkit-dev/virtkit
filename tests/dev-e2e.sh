#!/usr/bin/env bash
# =====================================================================================
# The executable definition of "done" for `vk dev`: one project, one config, every verb.
# =====================================================================================
# A scratch git checkout gets a `.virtkit/config.toml` exercising an image source, a
# managed `${state}` mount, an optional missing one, `exec-env` taken from the host, a
# named endpoint on an `auto` loopback address, the three hooks, and two tasks. The run
# then walks the whole lifecycle against it: plan, doctor, status, up, exec, endpoints,
# session-only drift, ssh, storage reset, tasks, refresh preview and stop.
#
# Done means every step below holds:
#   1. `dev init` writes a config that `dev plan` parses.
#   2. plan/doctor/status read the config without booting or running a hook.
#   3. `dev up` runs hooks.init on the host, boots, and runs hooks.create/start in the guest;
#      exec lands where it should, with `exec-env`, and reproduces the exit status.
#   4. the named endpoint is published on its remembered loopback address and answers.
#   5. a changed `${localEnv:…}` value is session-only: new sessions see it, nothing reboots.
#   6. `storage reset` stops the owner and empties the item; the next start recreates it.
#   7. a `reuse` task runs in the running environment, reproducing its exit status.
#   8. `dev stop` takes the VM and its published endpoints away, and leaves nothing behind.
#   9. an `ephemeral` task runs in a throwaway VM whose workspace overlay never reaches the
#      host tree, and which is gone when it returns.
#  10. a compose source brings the sibling services with it: `service up|down`, a service's
#      endpoint, and the `disk` volume `storage list` names.
#
# Everything this touches lives under one scratch directory: XDG_STATE_HOME is redirected
# there for the whole run, so the host's own dev environments are never read or written.
# The host port an endpoint binds is probed free at the start rather than fixed, so a
# runner with something on that port fails nothing here.
#
# Run:  VK=./dist/vk tests/dev-e2e.sh
# Needs: a `vk` with an embedded kernel/agent, KVM, network for the image pull, and git.
# STEP_TIMEOUT caps each `vk dev` step, in seconds (default 600), so a guest that never
# answers fails the gate instead of holding it.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
IMAGE=${IMAGE:-docker.io/library/alpine:3.21}
[ -r /dev/kvm ] || { echo "SKIP: no /dev/kvm"; exit 0; }
command -v git >/dev/null || { echo "SKIP: no git"; exit 0; }

# The guest's vsock socket lives under the state directory, and a Unix socket path is
# capped at 108 bytes — so the scratch root has to be short, whatever TMPDIR says.
base=${TMPDIR:-/tmp}
[ "${#base}" -le 40 ] || base=/tmp
WORK=$(mktemp -d "$base/vk-dev-e2e.XXXXXX")
WS=$WORK/ws
WS2=$WORK/compose
export XDG_STATE_HOME=$WORK/state

cleanup() {
  cd /
  # Bounded: the summary has already printed, and a wedged guest must not hang the trap.
  for ws in "$WS" "$WS2"; do
    [ -d "$ws" ] && (cd "$ws" && timeout 120 "$VK" dev stop >/dev/null 2>&1) || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
ok() { echo "PASS: $*"; pass=$((pass + 1)); }
bad() { echo "FAIL: $*"; fail=$((fail + 1)); }
# A step that would take the whole gate down with it if the guest never answered.
vkd() { timeout "${STEP_TIMEOUT:-600}" "$VK" dev "$@"; }

# `vk dev` writes its lifecycle notes ("dev environment already running …") on stderr and
# leaves stdout to the command; checks on a note capture both, checks on output only stdout.
said() { grep -qx -- "$2" <<<"$1"; }
status_is() { grep -qE "^status +$1\$" <<<"$(vkd status)"; }
# The url of one endpoint, taken from its own JSON object: a second endpoint must not turn
# $url into two lines. `name` is the object's first key, so the range ends at its closing
# brace.
endpoint_url() { sed -n "/\"name\": \"$1\"/,/}/s/.*\"url\": \"\([^\"]*\)\".*/\1/p" | head -n 1; }

# A host port nothing here holds: the endpoint binds it for real, so a fixed number fails
# the gate on a runner that already has something there. A refused connection is the test.
free_port() {
  local p
  for _ in $(seq 1 50); do
    p=$((20000 + RANDOM % 20000))
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && exec 3>&- || { echo "$p"; return 0; }
  done
  echo "no free host port found in 50 tries" >&2
  return 1
}
PORT=$(free_port)
PORT2=$(free_port)
[ "$PORT" != "$PORT2" ] || PORT2=$((PORT + 1))

mkdir -p "$WS"
cd "$WS"
git init -q .
git -c user.email=e2e@virtkit -c user.name=e2e commit -q --allow-empty -m init
echo "workspace $WS"

echo
echo "== 1. init writes a config, and the hand-written one parses =="
if vkd init --from image --image "$IMAGE" >/dev/null && [ -f "$WS/.virtkit/config.toml" ]; then
  ok "dev init wrote .virtkit/config.toml"
else
  bad "dev init did not write .virtkit/config.toml"
  exit 1
fi
if vkd plan >/dev/null; then ok "dev plan parses what init wrote"; else bad "dev plan rejected what init wrote"; fi

# The config under test. `${state}/data` is managed storage; the second mount is optional
# and absent, so the boot must skip it rather than fail. The hooks are the three lifecycle
# points, and the tasks one of each policy that needs no second environment.
cat > "$WS/.virtkit/config.toml" <<'EOF'
schema = 1

[dev]
image = "IMAGE_REF"
workspace = "/w"
# user unset: sessions are the image's own default, root.
freshness = "reuse"
cpus = 2
mem = "1G"

[dev.exec-env]
E2E_TOKEN = "${localEnv:E2E_TOKEN:fallback}"

[dev.mounts.data]
source = "${state}/data"
to = "/data"

[dev.mounts.absent]
source = "${workspace}/no-such-file"
to = "/opt/absent"
optional = true

[dev.endpoints.web]
target = 8080
host-port = HOST_PORT
address = "auto"
scheme = "http"
path = "/"

# A host hook runs from the workspace, so a relative path is the workspace's own.
[dev.hooks]
init = ["touch", "init-marker"]
create = ["touch", "/data/created"]
start = ["touch", "/tmp/started"]

[dev.tasks.hello]
run = ["sh", "-c", "echo hello-$E2E_TOKEN; exit 3"]
policy = "reuse"

[dev.tasks.scratch]
run = ["sh", "-c", "touch /w/ephemeral-marker && echo MARK:$(ls /w)"]
policy = "ephemeral"
checkout = "overlay"
EOF
sed -i -e "s|IMAGE_REF|$IMAGE|" -e "s|HOST_PORT|$PORT|" "$WS/.virtkit/config.toml"

echo
echo "== 2. plan, doctor and status read it without booting =="
plan=$(vkd plan)
if grep -q '"workspace_folder": "/w"' <<<"$plan" && grep -q '"mem": "1G"' <<<"$plan"; then
  ok "plan resolves the workspace folder and memory"
else
  bad "plan lost workspace_folder=/w or mem=1G"
  echo "$plan"
fi
grep -q '"name": "web"' <<<"$plan" && ok "plan carries the web endpoint" || bad "plan lost the web endpoint"
STATE=$(sed -n 's/.*"state_dir": "\(.*\)".*/\1/p' <<<"$plan")
[ -n "$STATE" ] || { bad "plan named no state_dir"; exit 1; }
case $STATE in
  "$XDG_STATE_HOME"/*) ok "state lives under the scratch XDG_STATE_HOME" ;;
  *) bad "state escaped the scratch dir: $STATE"; exit 1 ;;
esac
if vkd doctor > "$WORK/doctor.txt" 2>&1; then ok "doctor says this host can run it"; else bad "doctor refused the host"; cat "$WORK/doctor.txt"; fi
status_is "not running" && ok "status: not running" || bad "status did not say 'not running' before the boot"
[ -e "$WS/init-marker" ] && bad "hooks.init ran for a read-only command" || ok "no hook ran for plan/doctor/status"

echo
echo "== 3. up boots it, and runs the hooks on both sides =="
export E2E_TOKEN=abc
if vkd up > "$WORK/up.txt" 2>&1; then ok "dev up booted the environment"; else bad "dev up failed"; cat "$WORK/up.txt"; exit 1; fi
[ -f "$WS/init-marker" ] && ok "hooks.init ran on the host" || bad "hooks.init left no marker in the workspace"
status_is "running \(pid [0-9]+\)" && ok "status: running" || bad "status did not report the running VM"
grep -q '"running": true' <<<"$(vkd status --json)" && ok "status --json: running true" || bad "status --json did not say running"
vkd exec -- test -f /data/created && ok "hooks.create ran in the guest" || bad "hooks.create left no /data/created"
vkd exec -- test -f /tmp/started && ok "hooks.start ran in the guest" || bad "hooks.start left no /tmp/started"
said "$(vkd exec -- sh -c 'echo $E2E_TOKEN')" abc \
  && ok "exec-env delivered \${localEnv:E2E_TOKEN} as abc" || bad "exec did not see E2E_TOKEN=abc"
said "$(vkd exec --dir / -- pwd)" / && ok "exec --dir / runs in /" || bad "exec --dir / did not run in /"
[ "$(vkd exec -- echo clean 2>/dev/null)" = clean ] \
  && ok "exec stdout carries the command's output alone" || bad "exec stdout carried more than the command's output"
rc=0; vkd exec -- sh -c 'exit 7' >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 7 ] && ok "exec reproduces the guest's exit status (7)" || bad "exec returned $rc, want 7"

echo
echo "== 4. the endpoint is published where it says it is =="
# busybox in this image has no httpd applet, so nc serves one canned response per connect.
listener=$(cat <<'EOF'
mkdir -p /srv
cat > /srv/reply <<'INNER'
#!/bin/sh
while read -r l; do [ "$(printf %s "$l" | tr -d '\r')" = "" ] && break; done
printf 'HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n'
INNER
chmod +x /srv/reply
setsid nc -lk -p 8080 -e /srv/reply </dev/null >/dev/null 2>&1 &
sleep 0.5
EOF
)
vkd exec -- sh -c "$listener" >/dev/null || bad "could not start the guest listener"
url=$(vkd endpoints --json | endpoint_url web)
eps=$(vkd endpoints)
if grep -qE "^web +http://127\.0\.[0-9]+\.[0-9]+:$PORT/ .*published\$" <<<"$eps"; then
  ok "endpoints: web published at $url"
else
  bad "endpoints did not publish web on an auto loopback address"
  echo "$eps"
fi
if command -v curl >/dev/null; then
  body=
  for _ in 1 2 3 4 5; do
    body=$(curl -sS --max-time 10 "$url" 2>/dev/null || true)
    [ "$body" = "ok" ] && break
    sleep 1
  done
  [ "$body" = "ok" ] && ok "curl $url answered from the guest" || bad "curl $url returned '$body', want 'ok'"
else
  echo "note: no curl; the endpoint was not fetched"
fi
said "$(vkd open web --print)" "$url" && ok "open --print prints the endpoint URL" || bad "open --print did not print $url"
up2=$(vkd up 2>&1)
grep -q "already running" <<<"$up2" && ok "a second up is a no-op" || { bad "a second up did not say 'already running'"; echo "$up2"; }
grep -q "published$" <<<"$(vkd endpoints)" && ok "the endpoint survives a second up" || bad "the endpoint went away on the second up"

echo
echo "== 5. a changed host value is session-only =="
export E2E_TOKEN=xyz
drift=$(vkd up 2>&1)
grep -q "only in what attaching applies" <<<"$drift" && ok "up reports the change as applied by attaching" || { bad "up did not call the change session-only"; echo "$drift"; }
grep -q "booting" <<<"$drift" && bad "up rebooted for a session-only change" || ok "nothing rebooted"
said "$(vkd exec -- sh -c 'echo $E2E_TOKEN')" xyz \
  && ok "the next exec session sees E2E_TOKEN=xyz" || bad "exec still saw the old E2E_TOKEN"
grep -q "changed since the boot only in what attaching applies" <<<"$(vkd status)" \
  && ok "status shows the session-only drift" || bad "status hid the session-only drift"
grep -q "session-only" <<<"$(vkd plan --diff)" \
  && ok "plan --diff classifies it as session-only" || bad "plan --diff did not classify the drift"
# ssh passes its arguments verbatim and the remote shell re-parses them, so ask for the
# variable with a command that needs no quoting of its own.
said "$(vkd ssh -- printenv E2E_TOKEN 2>/dev/null)" xyz \
  && ok "an ssh session gets exec-env too" || bad "ssh did not see E2E_TOKEN=xyz"
grep -q '^Host ' <<<"$(vkd ssh-config)" && ok "ssh-config prints a Host stanza" || bad "ssh-config printed no Host line"

echo
echo "== 6. storage reset stops the owner and empties the item =="
store=$(vkd storage list)
if grep -qF '${state}/data' <<<"$store" && grep -q created <<<"$store"; then
  ok "storage list shows \${state}/data as created"
else
  bad "storage list did not show \${state}/data as created"
  echo "$store"
fi
vkd exec -- touch /data/sentinel >/dev/null || bad "could not write into the managed mount"
vkd storage reset '${state}/data' --yes > "$WORK/reset.txt" 2>&1 \
  && ok "storage reset --yes accepted the durable item" || { bad "storage reset failed"; cat "$WORK/reset.txt"; }
[ -e "$STATE/data" ] && bad "storage reset left $STATE/data behind" || ok "the backing directory is gone"
status_is "not running" && ok "storage reset stopped the environment first" || bad "the environment still runs after a reset"
vkd up > "$WORK/up2.txt" 2>&1 || { bad "dev up after the reset failed"; cat "$WORK/up2.txt"; }
vkd exec -- test -d /data && ok "the next start recreated /data" || bad "/data did not come back"
after=$(vkd exec -- sh -c 'ls -A /data | sed "s/^/DATA:/"' | sed -n 's/^DATA://p' | tr '\n' ' ')
grep -q sentinel <<<"$after" && bad "the reset kept the data (sentinel survived)" || ok "the reset emptied it (no sentinel)"
# The create stamp is keyed on the materialized generation, and a reset directory gets a
# new generation token — so the hook that populated it runs again.
grep -q created <<<"$after" && ok "hooks.create re-ran for the recreated directory" \
  || { bad "hooks.create did not re-run after the reset"; echo "/data holds [${after% }]"; }

echo
echo "== 7. a reuse task runs in the running environment =="
out=$(vkd task hello) && rc=0 || rc=$?
said "$out" hello-xyz && ok "the reuse task ran with the environment's exec-env" || { bad "task hello printed no hello-xyz"; echo "$out"; }
[ "$rc" -eq 3 ] && ok "task hello reproduces its exit status (3)" || bad "task hello returned $rc, want 3"
# An ephemeral task is independent of the running environment: it gets a VM of its own,
# and the one that is up is neither used nor disturbed. Run for real again in step 9, with
# nothing running, so both halves of that claim are gated.
if vkd task scratch > "$WORK/eph-running.txt" 2>&1; then
  ok "an ephemeral task runs while the environment is up"
else
  bad "an ephemeral task failed while the environment was running"
  sed 's/^/      /' "$WORK/eph-running.txt"
fi
status_is "running \(pid [0-9]+\)" && ok "the running environment is untouched by it" \
  || bad "the ephemeral task disturbed the running environment"

echo
echo "== 8. refresh previews, and stop takes everything away =="
dry=$(vkd refresh --dry-run) && ok "refresh --dry-run reported without touching anything" || bad "refresh --dry-run failed"
grep -q refresh <<<"$dry" && ok "the preview says what a refresh would do" || { bad "refresh --dry-run printed no report"; echo "$dry"; }
vkd stop >/dev/null && ok "dev stop stopped it" || bad "dev stop failed"
status_is "not running" && ok "status: not running" || bad "status still reports a running VM"
grep -q "not published" <<<"$(vkd endpoints)" && ok "the endpoint is no longer published" || bad "the endpoint outlived the VM"
"$VK" list | grep -qF "$WS" && bad "vk list still shows a VM for this workspace" || ok "vk list has no VM from this environment"
# Stopping what is already stopped is what it asked for, so it succeeds; only a stop that
# could not do its job exits non-zero.
rc=0; second=$(vkd stop 2>&1) || rc=$?
[ "$rc" -eq 0 ] && ok "a second stop is a no-op" \
  || { bad "a second stop exited $rc"; echo "$second"; }

echo
echo "== 9. an ephemeral task keeps its writes to itself =="
out=$(vkd task scratch) && rc=0 || rc=$?
[ "$rc" -eq 0 ] && ok "the ephemeral task ran and tore its VM down" || { bad "the ephemeral task returned $rc"; echo "$out"; }
grep -q '^MARK:.*ephemeral-marker' <<<"$out" && ok "it wrote /w/ephemeral-marker in its own overlay" || { bad "the task never wrote its marker"; echo "$out"; }
[ -e "$WS/ephemeral-marker" ] && bad "the overlay write reached the host workspace" || ok "the host workspace is untouched"
"$VK" list | grep -qF "$WS" && bad "the ephemeral VM is still running" || ok "vk list has no leftover VM"

echo
echo "== 10. a compose source brings its services, their endpoints and their disks =="
# A second workspace: the compose path is a different source, and mixing it into the one
# above would say nothing about either. Two services — the one sessions land in, and a
# sibling with an endpoint and a durable disk, which is the shape a project actually has.
mkdir -p "$WS2/.virtkit"
cd "$WS2"
git init -q .
git -c user.email=e2e@virtkit -c user.name=e2e commit -q --allow-empty -m init
cat > "$WS2/.virtkit/compose.yaml" <<EOF
services:
  devcontainer:
    image: $IMAGE
    command: ["sleep", "infinity"]
  runner:
    image: $IMAGE
    command: ["sleep", "infinity"]
    volumes:
      - \${VK_WORKSPACE}/.virtkit/runner-data.qcow2:/var/data:disk,size=64M
EOF
cat > "$WS2/.virtkit/config.toml" <<EOF
schema = 1

[dev]
compose = ".virtkit/compose.yaml"
service = "devcontainer"
workspace = "/w"
freshness = "reuse"

[dev.endpoints."runner.web"]
service = "runner"
target = 8080
host-port = $PORT2
address = "auto"
scheme = "http"
path = "/"
EOF
if vkd plan >/dev/null 2>"$WORK/compose-plan.txt"; then
  ok "a compose config resolves to a plan"
else
  bad "dev plan rejected the compose config"
  cat "$WORK/compose-plan.txt"
fi
if vkd up > "$WORK/compose-up.txt" 2>&1; then
  ok "dev up booted the compose primary"
else
  bad "dev up failed for the compose source"
  cat "$WORK/compose-up.txt"
fi
if status_is "running \(pid [0-9]+\)"; then
  store=$(vkd storage list)
  grep -q '^runner:/var/data' <<<"$store" && ok "storage list names the runner's disk volume" \
    || { bad "storage list did not name runner:/var/data"; echo "$store"; }
  vkd service up runner > "$WORK/service-up.txt" 2>&1 \
    && ok "service up brought the runner up" || { bad "service up runner failed"; cat "$WORK/service-up.txt"; }
  eps=$(vkd endpoints --service runner)
  grep -qE "^runner\.web +runner +http://127\.0\.[0-9]+\.[0-9]+:$PORT2/ .*published\$" <<<"$eps" \
    && ok "endpoints --service shows the runner's endpoint published" \
    || { bad "the runner's endpoint was not published"; echo "$eps"; }
  vkd service down runner >/dev/null 2>&1 \
    && ok "service down stopped the runner" || bad "service down runner failed"
  grep -q "not published" <<<"$(vkd endpoints --service runner)" \
    && ok "its endpoint is withdrawn with it" || bad "the endpoint outlived the service"
  vkd stop >/dev/null && ok "dev stop took the compose environment away" || bad "dev stop failed"
  status_is "not running" && ok "compose status: not running" || bad "the compose environment still runs"
else
  bad "the compose environment never reported itself running"
fi
cd "$WS"

echo
echo "================ $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
