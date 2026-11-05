#!/usr/bin/env bash
# The server the suites run against: a vk-registry with one Basic user, S3 on, its store
# under .state/, plus the root-path proxy (proxy.py) for the tools that cannot address an
# S3 API living under /s3/. Writes .state/env.sh, which every run.sh here sources.
#
# Usage: serve.sh start [--fresh] | stop | status | env
#
#   VK_REGISTRY     the binary (default: dist/vk-registry, else the debug build cargo
#                   test leaves in target/)
#   S3C_STATE       where the store, config, logs and pids go (default: .state/)
#   S3C_PORT        the registry's port (default: 5300)
#   S3C_PROXY_PORT  the proxy's port (default: 5301)
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=lib.sh
. ./lib.sh

S3C_PORT=${S3C_PORT:-5300}
S3C_PROXY_PORT=${S3C_PROXY_PORT:-5301}
user=s3compat
state=$S3C_STATE

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }

registry_bin() {
  if [ -n "${VK_REGISTRY:-}" ]; then printf '%s\n' "$VK_REGISTRY"; return; fi
  local c
  for c in "$s3c_repo/dist/vk-registry" \
           "$s3c_repo/target/x86_64-unknown-linux-musl/debug/vk-registry"; do
    if [ -x "$c" ]; then printf '%s\n' "$c"; return; fi
  done
  die "no vk-registry binary: build one with '$s3c_repo/build.sh --fast --only=vk-registry' \
or point VK_REGISTRY at one"
}

alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

wait_http() { # url: until something answers there (any status), 20 s at most
  local i
  for i in $(seq 1 100); do
    if curl -s -o /dev/null -m 2 "$1"; then return 0; fi
    sleep 0.2
  done
  return 1
}

start() {
  local fresh=0 bin
  case ${1:-} in --fresh) fresh=1 ;; '') ;; *) usage ;; esac
  need curl "to wait for the server"
  bin=$(registry_bin)
  if alive "$state/registry.pid"; then die "already running (see '$0 status')"; fi
  mkdir -p "$state"
  if [ $fresh = 1 ]; then rm -rf "$state/store"; fi
  if [ ! -f "$state/password" ]; then
    (umask 077; head -c 24 /dev/urandom | base64 | tr -d '/+=' > "$state/password")
  fi
  cat > "$state/registry.toml" <<CFG
# written by serve.sh; the suites' throwaway server
addr = "127.0.0.1:$S3C_PORT"
root = "$state/store"
username = "$user"
password_file = "$state/password"
s3 = true
CFG
  log "starting $bin on 127.0.0.1:$S3C_PORT (log: $state/registry.log)"
  nohup "$bin" serve --config "$state/registry.toml" > "$state/registry.log" 2>&1 &
  echo $! > "$state/registry.pid"
  if ! wait_http "http://127.0.0.1:$S3C_PORT/s3/"; then
    tail -n 20 "$state/registry.log" >&2
    die "the registry did not come up"
  fi
  log "starting proxy.py on 127.0.0.1:$S3C_PROXY_PORT -> /s3/ (log: $state/proxy.log)"
  nohup python3 -I ./proxy.py --listen "127.0.0.1:$S3C_PROXY_PORT" \
    --upstream "127.0.0.1:$S3C_PORT" --prefix /s3 \
    --basic-user "$user" --password-file "$state/password" > "$state/proxy.log" 2>&1 &
  echo $! > "$state/proxy.pid"
  if ! wait_http "http://127.0.0.1:$S3C_PROXY_PORT/"; then
    tail -n 20 "$state/proxy.log" >&2
    die "the proxy did not come up"
  fi
  (umask 077; cat > "$state/env.sh" <<ENV
# written by serve.sh: the server under test, for the run.sh scripts and for a shell
export S3C_ENDPOINT='http://127.0.0.1:$S3C_PORT/s3'
export S3C_ROOT_ENDPOINT='http://127.0.0.1:$S3C_PROXY_PORT'
export AWS_ACCESS_KEY_ID='$user'
export AWS_SECRET_ACCESS_KEY='$(cat "$state/password")'
export AWS_DEFAULT_REGION='us-east-1'
export AWS_EC2_METADATA_DISABLED=true
ENV
  )
  status
}

stop() {
  local p
  for p in proxy registry; do
    if alive "$state/$p.pid"; then
      kill "$(cat "$state/$p.pid")" 2>/dev/null || true
      log "stopped $p"
    fi
    rm -f "$state/$p.pid"
  done
}

status() {
  local p
  for p in registry proxy; do
    if alive "$state/$p.pid"; then echo "$p: running, pid $(cat "$state/$p.pid")"
    else echo "$p: not running"; fi
  done
  if [ -f "$state/env.sh" ]; then
    echo "S3 endpoint (path-style, under /s3): http://127.0.0.1:$S3C_PORT/s3"
    echo "S3 endpoint at the root (proxy):      http://127.0.0.1:$S3C_PROXY_PORT"
    echo "credentials: $state/env.sh  (eval \"\$($0 env)\" loads them into a shell)"
  fi
}

case ${1:-} in
  start) shift; start "$@" ;;
  stop) stop ;;
  status) status ;;
  env) cat "$state/env.sh" ;;
  *) usage ;;
esac
