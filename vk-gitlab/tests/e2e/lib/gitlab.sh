# shellcheck shell=bash
# shellcheck disable=SC2034 # GL_REUSED is read by run.sh
# GitLab CE in a vk microVM, and its API. Sourced by run.sh.
#
# The image's own init (/assets/init-container: runsvdir, then `gitlab-ctl reconfigure`, then
# `wait`) runs as the trailing command of a detached `vk run`, under vk-agent as PID 1 — the
# omnibus image needs no init of its own, since runit is its supervisor. Its three volumes are
# vk `:disk` qcow2 files kept in GL_DIR, so the database, repositories and secrets survive the
# VM: a later run boots the same instance (reconfigure only, no migrations, no seeding).
#
# Inputs: GITLAB_IMAGE, VK_BOOT (the vk that boots it), GL_DIR (its state, keyed by the image
# digest), GL_HOST (an address both this host and the job VMs reach: the host's own LAN
# address, since the job VMs' egress refuses loopback), LOGS.

GL_MEM=${GL_MEM:-6G}
GL_CPUS=${GL_CPUS:-4}

gl_vm() { echo "$GL_DIR/vm"; }

# gl_load: the instance's persisted settings (port, root password, token), creating them.
gl_load() {
  mkdir -p "$GL_DIR"
  chmod 700 "$GL_DIR"
  if [ ! -f "$GL_DIR/instance.env" ]; then
    {
      echo "GL_PORT=$(free_port)"
      # GitLab refuses dictionary-like passwords for the seeded root.
      echo "GL_ROOT_PASSWORD=vkE2e-$(openssl rand -hex 12)"
    } >"$GL_DIR/instance.env"
  fi
  # shellcheck disable=SC1091
  . "$GL_DIR/instance.env"
  GL_URL="http://$GL_HOST:$GL_PORT"
}

# One line, `;`-separated: vk drops an --env value that holds a newline (vk 0.85: the guest
# command sees the variable unset).
gl_omnibus_config() {
  # Everything a runner test does not touch is off; puma in single mode and a small sidekiq
  # keep it within GL_MEM.
  cat <<EOF
external_url '$GL_URL'
package['modify_kernel_parameters'] = false
letsencrypt['enable'] = false
prometheus_monitoring['enable'] = false
registry['enable'] = false
gitlab_pages['enable'] = false
mattermost['enable'] = false
gitlab_kas['enable'] = false
gitlab_rails['gitlab_kas_enabled'] = false
gitlab_rails['usage_ping_enabled'] = false
puma['worker_processes'] = 0
sidekiq['concurrency'] = 5
EOF
}

gl_running() { "$VK_BOOT" status "$(gl_vm)" >/dev/null 2>&1; }

gl_ready() { curl -fsS -o /dev/null --max-time 10 "$GL_URL/users/sign_in" 2>/dev/null; }

# gl_up: boot GitLab (or reuse the one already running from GL_DIR) and wait for it.
gl_up() {
  gl_load
  local vm console
  vm=$(gl_vm)
  console="$LOGS/gitlab-console.log"
  if gl_running; then
    log "gitlab: reusing the running instance in $vm"
    GL_REUSED=1
  else
    GL_REUSED=''
    if [ -f "$GL_DIR/data.qcow2" ]; then
      log "gitlab: booting the cached instance in $GL_DIR"
    else
      log "gitlab: cold boot of $GITLAB_IMAGE (pull, reconfigure, migrations: ~5 min)"
    fi
    "$VK_BOOT" run "$GITLAB_IMAGE" \
      --state-dir "$vm" --mem "$GL_MEM" --cpus "$GL_CPUS" --net \
      --boot-timeout 300 --detach --inactivity-timeout 0 --detach-log "$console" \
      -v "$GL_DIR/etc.qcow2:/etc/gitlab:disk,size=1G" \
      -v "$GL_DIR/data.qcow2:/var/opt/gitlab:disk,size=32G" \
      -v "$GL_DIR/log.qcow2:/var/log/gitlab:disk,size=8G" \
      --env "GITLAB_OMNIBUS_CONFIG=$(gl_omnibus_config | paste -sd ';')" \
      --env "GITLAB_ROOT_PASSWORD=$GL_ROOT_PASSWORD" \
      --env GITLAB_DISABLE_OPENSSH=true \
      --env GITLAB_SKIP_TAIL_LOGS=true \
      -- /assets/init-container >"$LOGS/gitlab-boot.log" 2>&1 ||
      { cat "$LOGS/gitlab-boot.log" >&2; die "the GitLab VM did not boot"; }
  fi
  # The guest's nginx listens on the external_url's port; publish it on the host's address.
  "$VK_BOOT" publish ensure --name gitlab --listen "tcp://$GL_HOST:$GL_PORT" \
    --to "tcp://127.0.0.1:$GL_PORT" "$vm" >>"$LOGS/gitlab-boot.log" 2>&1 ||
    die "could not publish GitLab on $GL_HOST:$GL_PORT (see $LOGS/gitlab-boot.log)"
  local start deadline
  start=$(date +%s)
  deadline=$((start + ${GL_BOOT_TIMEOUT:-1500}))
  until gl_ready; do
    if [ -f "$console" ] && grep -q 'Error executing action' "$console"; then
      grep -n -A20 'Error executing action' "$console" | head -40 >&2
      die "gitlab-ctl reconfigure failed (see $console)"
    fi
    gl_running || die "the GitLab VM stopped while booting (see $console)"
    [ "$(date +%s)" -lt "$deadline" ] || die "GitLab not ready after ${GL_BOOT_TIMEOUT:-1500}s"
    sleep 5
  done
  log "gitlab: ready at $GL_URL after $(($(date +%s) - start))s"
}

# gl_down: stop GitLab cleanly, so the next run's boot finds a consistent database.
gl_down() {
  local vm
  vm=$(gl_vm)
  gl_running || return 0
  log "gitlab: stopping"
  "$VK_BOOT" exec "$vm" -- /opt/gitlab/bin/gitlab-ctl stop >/dev/null 2>&1 || true
  "$VK_BOOT" publish stop "$vm" >/dev/null 2>&1 || true
  "$VK_BOOT" stop "$vm" >/dev/null 2>&1 || true
}

# gl_rails <ruby>: run Ruby under `gitlab-rails runner` in the guest; stdin reaches it.
gl_rails() {
  "$VK_BOOT" exec "$(gl_vm)" -- /opt/gitlab/bin/gitlab-rails runner "$1"
}

# api <method> <path> [curl args...]: the REST API as root (GL_PAT); prints the body, fails
# with it on an HTTP error.
api() {
  local method=$1 path=$2 out code
  shift 2
  out=$(mktemp)
  # The token goes in on stdin, out of every process's argv.
  code=$(curl -sS -o "$out" -w '%{http_code}' -X "$method" \
    -H @- "$GL_URL/api/v4$path" "$@" <<<"PRIVATE-TOKEN: $GL_PAT") || code=000
  if [ "$code" -ge 400 ] || [ "$code" = 000 ]; then
    log "api: $method $path -> $code $(head -c 500 "$out")"
    rm -f "$out"
    return 1
  fi
  cat "$out"
  rm -f "$out"
}

# gl_seed: root's token, the test group and project, its CI/CD variables, and a fresh
# project runner (any left by an earlier run are deleted). Sets GL_PAT, GL_PROJECT_ID,
# GL_PROJECT_PATH, GL_RUNNER_ID and writes the runner token to $RUN/runner.token.
gl_seed() {
  GL_PAT=
  [ -f "$GL_DIR/pat" ] && GL_PAT=$(cat "$GL_DIR/pat")
  if [ -z "$GL_PAT" ] || ! api GET /user >/dev/null 2>&1; then
    log "gitlab: creating root's personal access token (gitlab-rails runner, ~1 min)"
    GL_PAT="glpat-$(openssl rand -hex 16)"
    gl_rails "
      u = User.find_by_username!('root')
      u.personal_access_tokens.where(name: 'vk-gitlab-e2e').each(&:revoke!)
      t = u.personal_access_tokens.build(name: 'vk-gitlab-e2e',
        scopes: %w[api create_runner read_repository write_repository],
        expires_at: 360.days.from_now, organization: u.organizations.first)
      t.set_token(STDIN.read.strip)
      t.save!
    " <<<"$GL_PAT" >"$LOGS/gitlab-seed.log" 2>&1 || { cat "$LOGS/gitlab-seed.log" >&2; die "seeding the token failed"; }
    (umask 077 && printf '%s\n' "$GL_PAT" >"$GL_DIR/pat")
    api GET /user >/dev/null || die "the seeded token does not authenticate"
  fi

  local gid
  gid=$(api GET "/groups/vk-e2e" 2>/dev/null | jq -r .id) || gid=
  if [ -z "$gid" ]; then
    gid=$(api POST /groups -d name=vk-e2e -d path=vk-e2e -d visibility=private | jq -r .id) ||
      die "creating the group failed"
  fi
  GL_PROJECT_PATH=vk-e2e/pipelines
  GL_PROJECT_ID=$(api GET "/projects/vk-e2e%2Fpipelines" 2>/dev/null | jq -r .id) || GL_PROJECT_ID=
  if [ -z "$GL_PROJECT_ID" ]; then
    GL_PROJECT_ID=$(api POST /projects -d name=pipelines -d path=pipelines \
      -d "namespace_id=$gid" -d visibility=private -d initialize_with_readme=true |
      jq -r .id) || die "creating the project failed"
  fi
  # Variables: a masked one and a file one. Set on every run, so a change here applies.
  local v
  for v in E2E_MASKED E2E_FILE; do
    api DELETE "/projects/$GL_PROJECT_ID/variables/$v" >/dev/null 2>&1 || true
  done
  api POST "/projects/$GL_PROJECT_ID/variables" -d key=E2E_MASKED \
    --data-urlencode "value=$E2E_MASKED_VALUE" -d masked=true >/dev/null ||
    die "creating E2E_MASKED failed"
  api POST "/projects/$GL_PROJECT_ID/variables" -d key=E2E_FILE \
    --data-urlencode "value=$E2E_FILE_VALUE" -d variable_type=file >/dev/null ||
    die "creating E2E_FILE failed"

  local old
  for old in $(api GET "/projects/$GL_PROJECT_ID/runners?type=project_type" | jq -r '.[].id'); do
    api DELETE "/runners/$old" >/dev/null 2>&1 || true
  done
  local runner
  runner=$(api POST /user/runners -d runner_type=project_type -d "project_id=$GL_PROJECT_ID" \
    -d "description=vk-gitlab e2e $RUN_ID" -d "tag_list=vk-e2e" -d run_untagged=false) ||
    die "creating the runner failed"
  GL_RUNNER_ID=$(jq -r .id <<<"$runner")
  (umask 077 && jq -r .token <<<"$runner" >"$RUN/runner.token")
  grep -q '^glrt-' "$RUN/runner.token" || die "the runner token is not a glrt- token"
  log "gitlab: project $GL_PROJECT_PATH ($GL_PROJECT_ID), runner $GL_RUNNER_ID"
}

# gl_push <branch> <dir>: replace the branch with a single commit of <dir>; print its SHA.
# lib/askpass.sh supplies root's token from $GL_DIR/pat without a credential helper.
gl_push() {
  local branch=$1 dir=$2
  (
    cd "$dir" || exit 1
    git init -q -b "$branch" .
    git add -A
    git -c user.name=e2e -c user.email=e2e@example.invalid commit -q -m "e2e $branch $RUN_ID"
    GIT_ASKPASS=$E2E/lib/askpass.sh GL_PAT_FILE=$GL_DIR/pat GIT_TERMINAL_PROMPT=0 \
      git -c credential.helper= push -q -f "http://root@$GL_HOST:$GL_PORT/$GL_PROJECT_PATH.git" \
      "HEAD:refs/heads/$branch" >/dev/null
    git rev-parse HEAD
  )
}

# gl_pipeline_for <sha> [timeout]: the ID of the pipeline GitLab created for a commit.
gl_pipeline_for() {
  local sha=$1 id='' deadline=$(($(date +%s) + ${2:-120}))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    id=$(api GET "/projects/$GL_PROJECT_ID/pipelines?sha=$sha" | jq -r '.[0].id // empty') || id=
    [ -n "$id" ] && {
      echo "$id"
      return
    }
    sleep 2
  done
  return 1
}

gl_pipeline() { api GET "/projects/$GL_PROJECT_ID/pipelines/$1"; }
gl_pipeline_jobs() { api GET "/projects/$GL_PROJECT_ID/pipelines/$1/jobs?include_retried=true&per_page=100"; }
gl_job() { api GET "/projects/$GL_PROJECT_ID/jobs/$1"; }
gl_trace() { api GET "/projects/$GL_PROJECT_ID/jobs/$1/trace"; }

# gl_job_id <pipeline> <job name>
gl_job_id() { gl_pipeline_jobs "$1" | jq -r --arg n "$2" '[.[] | select(.name == $n)][0].id // empty'; }

# gl_wait_pipeline <pipeline> <timeout>: until it is done; prints its status.
gl_wait_pipeline() {
  local p=$1 deadline=$(($(date +%s) + $2)) status
  while :; do
    status=$(gl_pipeline "$p" | jq -r .status) || status=
    case $status in
      success | failed | canceled | skipped) echo "$status" && return 0 ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || {
      echo "${status:-unknown}"
      return 1
    }
    sleep 3
  done
}

# gl_wait_job_state <job> <timeout> <state...>: until the job is in one of the states.
gl_wait_job_state() {
  local j=$1 deadline=$(($(date +%s) + $2)) status s
  shift 2
  while :; do
    status=$(gl_job "$j" | jq -r .status) || status=
    for s in "$@"; do [ "$status" = "$s" ] && return 0; done
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}
