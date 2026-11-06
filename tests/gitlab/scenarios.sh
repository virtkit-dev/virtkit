# shellcheck shell=bash
# shellcheck disable=SC2034 # SC_DETAIL is read by gitlab-e2e.sh
# Each scenario pushes a branch with its own .gitlab-ci.yml to the test project and checks
# GitLab's job status, failure_reason, trace and artifacts. Sourced by gitlab-e2e.sh, which runs
# every scenario but `restart` concurrently, each in a subshell.
#
# A scenario is a function `sc_<name>` that returns non-zero, after `bad` has said why, when an
# assertion fails; `SC_DETAIL` is the one-line detail shown in the summary on success.

# Every scenario's jobs: our runner's tag, the git-capable job image.
ci_header() {
  cat <<EOF
default:
  tags: [vk-e2e]
  image: $JOB_IMAGE
EOF
}

# A trace line's start: GitLab's own lines start with the text, a placed job's output with
# its timestamp and stream prefix (`2026-10-22T07:10:50.139347Z 01O `).
LINE="^([0-9TZ:.-]+ [0-9]{2}[OE]\\+? )?"

SC_ERRORS=0
bad() {
  log "  assertion: $*"
  SC_ERRORS=$((SC_ERRORS + 1))
}

# push_scenario <name> [suffix]: push README, e2e.txt, stdin as the CI file, and
# $PUSH_FILES directory contents (if set) to branch e2e/<name>; print the pipeline ID.
push_scenario() {
  local name=$1 suffix=${2:-} dir sha
  dir=$(mktemp -d "$RUN/tree.XXXXXX")
  [ -z "${PUSH_FILES:-}" ] || cp -R "$PUSH_FILES/." "$dir/"
  cat >"$dir/.gitlab-ci.yml"
  printf 'vk-gitlab e2e %s\n' "$name" >"$dir/README.md"
  printf 'e2e-marker-%s-%s%s\n' "$name" "$RUN_ID" "$suffix" >"$dir/e2e.txt"
  sha=$(gl_push "e2e/$name" "$dir") || {
    bad "git push of e2e/$name failed"
    return 1
  }
  rm -rf "$dir"
  gl_pipeline_for "$sha" || {
    bad "no pipeline for $name ($sha)"
    return 1
  }
}

# Save a job's trace and JSON as evidence under $RUN/jobs.
keep_job() {
  mkdir -p "$RUN/jobs"
  gl_job "$1" >"$RUN/jobs/$1.json" 2>/dev/null || true
  gl_trace "$1" >"$RUN/jobs/$1.log" 2>/dev/null || true
}

# trace_has <job> <fixed string>...
trace_has() {
  local j=$1 s
  shift
  [ -f "$RUN/jobs/$j.log" ] || keep_job "$j"
  for s in "$@"; do
    grep -qF -- "$s" "$RUN/jobs/$j.log" || bad "job $j's trace lacks '$s'"
  done
}
trace_lacks() {
  local j=$1 s
  shift
  [ -f "$RUN/jobs/$j.log" ] || keep_job "$j"
  for s in "$@"; do
    ! grep -qF -- "$s" "$RUN/jobs/$j.log" || bad "job $j's trace has '$s'"
  done
}
# job_field_is <job> <jq path> <value>
job_field_is() {
  local got
  [ -f "$RUN/jobs/$1.json" ] || keep_job "$1"
  got=$(jq -r "$2" "$RUN/jobs/$1.json")
  [ "$got" = "$3" ] || bad "job $1: $2 is '$got', want '$3'"
}

# wait_pipeline <pipeline> <want status> [timeout]: and keep every job's evidence.
wait_pipeline() {
  local p=$1 want=$2 status j
  status=$(gl_wait_pipeline "$p" "${3:-900}") || {
    bad "pipeline $p still $status after ${3:-900}s"
    return 1
  }
  for j in $(gl_pipeline_jobs "$p" | jq -r '.[].id'); do keep_job "$j"; done
  [ "$status" = "$want" ] || bad "pipeline $p ended $status, want $want"
}

# Jobs whose name is $2 in pipeline $1.
job() { gl_job_id "$1" "$2"; }

sc_basic() {
  local p j
  p=$({
    ci_header
    cat <<'EOF'
basic:
  script:
    - echo "hello from $CI_JOB_NAME at $CI_COMMIT_SHA"
    - cat e2e.txt
    - git log -1 --format=commit-%H
EOF
  } | push_scenario basic) || return 1
  wait_pipeline "$p" success || return 1
  j=$(job "$p" basic)
  local sha
  sha=$(gl_pipeline "$p" | jq -r .sha)
  trace_has "$j" "hello from basic at $sha" "e2e-marker-basic-$RUN_ID" "commit-$sha" \
    "Job succeeded"
  job_field_is "$j" .status success
  SC_DETAIL="pipeline $p"
}

sc_scripts() {
  local p ok fail
  p=$({
    ci_header
    cat <<'EOF'
ok:
  before_script: [echo before-marker]
  script: [echo script-marker]
  after_script: ['echo "after-marker status=$CI_JOB_STATUS"']
fails:
  before_script: [echo before-marker]
  script: [echo script-marker, exit 1, echo never-marker]
  after_script: ['echo "after-marker status=$CI_JOB_STATUS"']
  allow_failure: true
EOF
  } | push_scenario scripts) || return 1
  wait_pipeline "$p" success || return 1
  ok=$(job "$p" ok)
  fail=$(job "$p" fails)
  trace_has "$ok" before-marker script-marker "after-marker status=success"
  # Order: before_script, script, after_script.
  local b s a
  b=$(grep -nE "${LINE}before-marker" "$RUN/jobs/$ok.log" | head -1 | cut -d: -f1)
  s=$(grep -nE "${LINE}script-marker" "$RUN/jobs/$ok.log" | head -1 | cut -d: -f1)
  a=$(grep -nE "${LINE}after-marker" "$RUN/jobs/$ok.log" | head -1 | cut -d: -f1)
  [ -n "$b" ] && [ -n "$s" ] && [ -n "$a" ] && [ "$b" -lt "$s" ] && [ "$s" -lt "$a" ] ||
    bad "job $ok: before/script/after out of order ($b/$s/$a)"
  trace_has "$fail" "after-marker status=failed"
  trace_lacks "$fail" never-marker
  job_field_is "$fail" .status failed
  job_field_is "$fail" .failure_reason script_failure
  SC_DETAIL="pipeline $p"
}

sc_variables() {
  local p j
  p=$({
    ci_header
    cat <<'EOF'
variables:
  PIPE_VAR: pipeline-value
vars:
  variables:
    JOB_VAR: "job+$PIPE_VAR"
  script:
    - echo "job_var=$JOB_VAR"
    - echo "masked=$E2E_MASKED"
    - echo "file_is_path=$(test -f "$E2E_FILE" && echo yes)"
    - echo "file_content=$(cat "$E2E_FILE")"
EOF
  } | push_scenario variables) || return 1
  wait_pipeline "$p" success || return 1
  j=$(job "$p" vars)
  trace_has "$j" "job_var=job+pipeline-value" "masked=[MASKED]" "file_is_path=yes" \
    "file_content=$E2E_FILE_VALUE"
  trace_lacks "$j" "$E2E_MASKED_VALUE"
  SC_DETAIL="masked + file variables"
}

sc_exit_codes() {
  local p a n
  p=$({
    ci_header
    cat <<'EOF'
allowed:
  script: [echo before-exit, exit 42]
  allow_failure:
    exit_codes: [42]
not-allowed:
  script: [exit 3]
EOF
  } | push_scenario exit_codes) || return 1
  wait_pipeline "$p" failed || return 1
  a=$(job "$p" allowed)
  n=$(job "$p" not-allowed)
  job_field_is "$a" .status failed
  job_field_is "$a" .allow_failure true
  job_field_is "$a" .failure_reason script_failure
  trace_has "$a" "exit code 42"
  job_field_is "$n" .status failed
  job_field_is "$n" .allow_failure false
  job_field_is "$n" .failure_reason script_failure
  trace_has "$n" "exit code 3"
  SC_DETAIL="exit 42 allowed, exit 3 fails"
}

sc_artifacts() {
  local p prod cons
  p=$({
    ci_header
    cat <<'EOF'
stages: [build, test]
produce:
  stage: build
  script:
    - mkdir -p out
    - echo "artifact-$CI_PIPELINE_ID" > out/a.txt
    - echo junk > out/skip.log
  artifacts:
    paths: [out/]
    exclude: [out/*.log]
consume:
  stage: test
  dependencies: [produce]
  script:
    - cat out/a.txt
    - test ! -e out/skip.log && echo no-excluded-file
EOF
  } | push_scenario artifacts) || return 1
  wait_pipeline "$p" success || return 1
  prod=$(job "$p" produce)
  cons=$(job "$p" consume)
  job_field_is "$prod" '.artifacts_file.filename' artifacts.zip
  if api GET "/projects/$GL_PROJECT_ID/jobs/$prod/artifacts/out/a.txt" >"$RUN/jobs/$prod.a.txt"; then
    grep -qx "artifact-$p" "$RUN/jobs/$prod.a.txt" || bad "out/a.txt holds $(cat "$RUN/jobs/$prod.a.txt")"
  else
    bad "out/a.txt is not in job $prod's artifacts"
  fi
  if api GET "/projects/$GL_PROJECT_ID/jobs/$prod/artifacts/out/skip.log" >/dev/null 2>&1; then
    bad "the excluded out/skip.log was uploaded"
  fi
  trace_has "$cons" "artifact-$p" no-excluded-file
  SC_DETAIL="upload + dependency download"
}

sc_cache() {
  local ci p1 p2 j1 j2
  ci=$({
    ci_header
    cat <<EOF
cached:
  cache:
    key: e2e-$RUN_ID
    paths: [cache/]
  script:
    - mkdir -p cache
    - if [ -f cache/stamp ]; then echo "cache-hit:\$(cat cache/stamp)"; else echo cache-miss; fi
    - echo "\$CI_PIPELINE_ID" > cache/stamp
EOF
  })
  p1=$(push_scenario cache <<<"$ci") || return 1
  wait_pipeline "$p1" success || return 1
  p2=$(push_scenario cache -second <<<"$ci") || return 1
  wait_pipeline "$p2" success || return 1
  j1=$(job "$p1" cached)
  j2=$(job "$p2" cached)
  trace_has "$j1" cache-miss
  trace_has "$j2" "cache-hit:$p1"
  SC_DETAIL="miss in $p1, hit in $p2"
}

# A job uses its hub-minted token through the guest registry proxy: pushes and locks succeed
# in its pipeline's namespace and fail under other prefixes. The token stays out of the trace.
# HTTP statuses computed at runtime keep echoed command lines from satisfying the checks.
sc_registry() {
  local ci p j
  ci=$({
    ci_header
    cat <<'EOF'
scoped:
  script:
    - echo "registry=$VK_REGISTRY"
    - echo "namespaces=$VK_REGISTRY_NAMESPACES"
    - P=ci-pipeline/e2e/$CI_PROJECT_ID/$CI_PIPELINE_ID
    - code() { wget -S -q -O /dev/null --post-data= "$VK_REGISTRY$1" 2>&1 | awk '/^ *HTTP\//{c=$2} END{print c}'; }
    - echo "push-own=$(code /v2/$P/probe/blobs/uploads/)"
    - echo "push-other=$(code /v2/images/probe/blobs/uploads/)"
    - echo "lock-own=$(code "/lock/acquire?name=$P:k&ttl=30&wait=0")"
    - echo "lock-other=$(code "/lock/acquire?name=images:k&ttl=30&wait=0")"
EOF
  })
  p=$(push_scenario registry <<<"$ci") || return 1
  wait_pipeline "$p" success || return 1
  j=$(job "$p" scoped)
  keep_job "$j"
  local want
  for want in "registry=http://registry.vk" "namespaces=.*ci-pipeline/e2e/$GL_PROJECT_ID/$p=rwl" \
    push-own=202 push-other=403 lock-own=200 lock-other=403; do
    grep -qE "${LINE}${want}\$" "$RUN/jobs/$j.log" || bad "job $j's trace lacks a line '$want'"
  done
  trace_lacks "$j" vkt_
  SC_DETAIL="pipeline $p: own namespace writable and lockable, others refused"
}

# A job builds an image from a context it made (`vk-agent build`) and later jobs of its
# pipeline boot it, by the full reference passed on as a dotenv variable and as
# pipeline/build/<name>. Refused: a second build of the name in the job, a symlink in a
# context, a symlinked Dockerfile, a reference written straight into the pipeline namespace,
# and the image from another pipeline by either form.
sc_pipeline_build() {
  local p1 p2 b j ref want
  p1=$({
    ci_header
    cat <<EOF
stages: [build, test]
build:
  stage: build
  script:
    - mkdir -p ctx bad
    - echo "pipeline-marker-\$CI_PIPELINE_ID" > ctx/marker.txt
    - printf 'FROM %s\nCOPY marker.txt /pipeline-marker.txt\n' "$JOB_IMAGE" > runner.Dockerfile
    - ref=\$(vk-agent build -f runner.Dockerfile --as runner ctx)
    - echo "built=\$ref"
    - echo "RUNNER_IMAGE=\$ref" > build.env
    - rc=0; vk-agent build -f runner.Dockerfile --as runner ctx || rc=\$?; echo "again-rc=\$rc"
    - echo x > bad/file && ln -s file bad/link
    - rc=0; vk-agent build -f runner.Dockerfile --as bad bad || rc=\$?; echo "symlink-rc=\$rc"
    - ln -s runner.Dockerfile link.Dockerfile
    - rc=0; vk-agent build -f link.Dockerfile --as linked ctx || rc=\$?; echo "link-rc=\$rc"
  artifacts:
    reports:
      dotenv: build.env
use:
  stage: test
  needs: [build]
  variables:
    MICROVM_IMAGE: \$RUNNER_IMAGE
  script: [cat /pipeline-marker.txt]
use-current:
  stage: test
  needs: [build]
  variables:
    MICROVM_IMAGE: pipeline/build/runner
  script: [cat /pipeline-marker.txt]
direct:
  stage: build
  variables:
    MICROVM_IMAGE: 127.0.0.1:$REG_PORT/ci-pipeline/e2e/$GL_PROJECT_ID/1/builds/runner:current
  script: [echo never-marker]
  allow_failure: true
EOF
  } | push_scenario pipeline_build) || return 1
  wait_pipeline "$p1" success || return 1
  b=$(job "$p1" build)
  ref=$(grep -oE "${LINE}built=pipeline/build/runner:job-$b@sha256:[0-9a-f]{64}\$" \
    "$RUN/jobs/$b.log" | sed 's/.*built=//')
  [ -n "$ref" ] || bad "job $b's trace lacks a line 'built=pipeline/build/runner:job-$b@sha256:…'"
  for want in "again-rc=2" "symlink-rc=[1-9][0-9]*" "link-rc=[1-9][0-9]*"; do
    grep -qE "${LINE}${want}\$" "$RUN/jobs/$b.log" || bad "job $b's trace lacks a line '$want'"
  done
  trace_has "$b" "a job publishes a name once" "bad/link: a symlink" \
    "link.Dockerfile (a symlink is not sent"
  for j in "$(job "$p1" use)" "$(job "$p1" use-current)"; do
    job_field_is "$j" .status success
    grep -qE "${LINE}pipeline-marker-$p1\$" "$RUN/jobs/$j.log" ||
      bad "job $j's trace lacks a line 'pipeline-marker-$p1'"
  done
  j=$(job "$p1" direct)
  job_field_is "$j" .status failed
  trace_has "$j" "is in the pipeline namespace (ci-pipeline/)"
  trace_lacks "$j" never-marker
  [ -n "$ref" ] || return 1

  p2=$({
    ci_header
    cat <<EOF
full:
  variables:
    MICROVM_IMAGE: "$ref"
  script: [echo never-marker]
current:
  variables:
    MICROVM_IMAGE: pipeline/build/runner
  script: [echo never-marker]
EOF
  } | push_scenario pipeline_build -second) || return 1
  wait_pipeline "$p2" failed || return 1
  j=$(job "$p2" full)
  job_field_is "$j" .status failed
  trace_has "$j" "image $ref is not in this pipeline" "rerun job $b"
  trace_lacks "$j" never-marker
  j=$(job "$p2" current)
  job_field_is "$j" .status failed
  trace_has "$j" "image pipeline/build/runner is not in this pipeline"
  trace_lacks "$j" never-marker
  SC_DETAIL="built in $p1 ($ref), refused in $p2"
}

# A job's builds are cached per project, protection and scope: a second pipeline of a branch
# boots the layer the first built (`vk-agent build`), and a branch the ci-build namespace
# isolates builds its own, though the Dockerfile is the same. The RUN step writes a random
# stamp, which a later job of the pipeline prints: one stamp is one build. With one node, the
# reuse may come from its local tier; each build job also checks that its scope's build-cache
# in the registry holds a tag, and that its token reads and locks its own scope but not the
# other. The hub's ci-build namespace stays replaced for the rest of the run; it keeps the
# path, so every other branch's jobs still build in scope `all`.
sc_build_cache() {
  local files ci p1 p2 p3 b1 b3 s1 s2 s3 p want shared iso
  shared="ci-build/e2e/$GL_PROJECT_ID/unprotected/all"
  iso="ci-build/e2e/$GL_PROJECT_ID/unprotected/ref-e2e-build-cache-iso-$(
    printf 'branch:e2e/build_cache_iso' | sha256sum | cut -c1-32
  )"
  hub namespaces add "$REG_ID" ci-build \
    --path 'ci-build/{gitlab}/{project_id}/{protection}/{scope}' \
    --retention-days 14 --isolate e2e/build_cache_iso --grant 'rwl:own project' \
    >>"$LOGS/hub-cli.log" 2>&1 || {
    bad "vk-hub namespaces add ci-build --isolate failed (see $LOGS/hub-cli.log)"
    return 1
  }
  files=$(mktemp -d "$RUN/files.XXXXXX")
  mkdir "$files/ctx"
  printf 'FROM %s\nRUN head -c 8 /dev/urandom | od -An -tx1 | tr -d " \\n" > /build-stamp\n' \
    "$JOB_IMAGE" >"$files/stamp.Dockerfile"
  touch "$files/ctx/.keep"
  # Each build job probes both scopes: its HTTP status reading and locking each scope's
  # build-cache, and whether that repository holds a tag (the layers its build pushed).
  ci=$({
    ci_header
    cat <<EOF
stages: [build, test]
build:
  stage: build
  script:
    - vk-agent build -f stamp.Dockerfile --as stamp ctx
    - code() { wget -S -q -O /dev/null "\$@" 2>&1 | awk '/^ *HTTP\//{c=\$2} END{print c}'; }
    - tagged() { wget -q -O - "\$VK_REGISTRY/v2/\$1/build-cache/tags/list" 2>/dev/null | grep -c '"tags":\["'; }
    - echo "read-shared=\$(code "\$VK_REGISTRY/v2/$shared/build-cache/tags/list")"
    - echo "lock-shared=\$(code --post-data= "\$VK_REGISTRY/lock/acquire?name=$shared/build-cache:k&ttl=30&wait=0")"
    - echo "tagged-shared=\$(tagged $shared)"
    - echo "read-iso=\$(code "\$VK_REGISTRY/v2/$iso/build-cache/tags/list")"
    - echo "lock-iso=\$(code --post-data= "\$VK_REGISTRY/lock/acquire?name=$iso/build-cache:k&ttl=30&wait=0")"
    - echo "tagged-iso=\$(tagged $iso)"
use:
  stage: test
  needs: [build]
  variables:
    MICROVM_IMAGE: pipeline/build/stamp
  script:
    - echo "stamp=\$(cat /build-stamp)"
EOF
  })
  p1=$(PUSH_FILES=$files push_scenario build_cache <<<"$ci") || return 1
  wait_pipeline "$p1" success || return 1
  p2=$(PUSH_FILES=$files push_scenario build_cache -second <<<"$ci") || return 1
  wait_pipeline "$p2" success || return 1
  p3=$(PUSH_FILES=$files push_scenario build_cache_iso <<<"$ci") || return 1
  wait_pipeline "$p3" success || return 1
  rm -rf "$files"
  s1=$(grep -oE "${LINE}stamp=[0-9a-f]{16}\$" "$RUN/jobs/$(job "$p1" use).log" | sed 's/.*=//')
  s2=$(grep -oE "${LINE}stamp=[0-9a-f]{16}\$" "$RUN/jobs/$(job "$p2" use).log" | sed 's/.*=//')
  s3=$(grep -oE "${LINE}stamp=[0-9a-f]{16}\$" "$RUN/jobs/$(job "$p3" use).log" | sed 's/.*=//')
  if [ -z "$s1" ] || [ -z "$s2" ] || [ -z "$s3" ]; then
    bad "a use job's trace lacks its 'stamp=' line ($s1/$s2/$s3)"
    return 1
  fi
  [ "$s1" = "$s2" ] || bad "pipeline $p2 built again ($s2) instead of taking $p1's build ($s1)"
  [ "$s3" != "$s1" ] || bad "the isolated branch took the shared scope's build ($s3)"
  b1=$(job "$p1" build)
  b3=$(job "$p3" build)
  for want in read-shared=200 lock-shared=200 tagged-shared=1 read-iso=403 lock-iso=403; do
    grep -qE "${LINE}${want}\$" "$RUN/jobs/$b1.log" || bad "job $b1's trace lacks a line '$want'"
  done
  for want in read-shared=403 lock-shared=403 read-iso=200 lock-iso=200 tagged-iso=1; do
    grep -qE "${LINE}${want}\$" "$RUN/jobs/$b3.log" || bad "job $b3's trace lacks a line '$want'"
  done
  for p in "$b1" "$b3"; do
    trace_lacks "$p" "building with no build cache" "not cached"
  done
  SC_DETAIL="built once for $p1 and $p2 ($s1), apart for the isolated branch ($s3)"
}

sc_services() {
  local p j
  p=$({
    ci_header
    cat <<EOF
with-service:
  services:
    - name: $SERVICE_IMAGE
      alias: web
  script:
    - for i in \$(seq 1 30); do wget -qO /tmp/page http://web/ && break; sleep 2; done
    - grep -i "welcome to nginx" /tmp/page && echo service-reached
EOF
  } | push_scenario services) || return 1
  wait_pipeline "$p" success || return 1
  j=$(job "$p" with-service)
  trace_has "$j" service-reached
  SC_DETAIL="nginx as web"
}

sc_timeout() {
  local p j
  p=$({
    ci_header
    cat <<'EOF'
times-out:
  timeout: 1m
  script: [echo timeout-start, sleep 600, echo never-marker]
EOF
  } | push_scenario timeout) || return 1
  wait_pipeline "$p" failed 600 || return 1
  j=$(job "$p" times-out)
  job_field_is "$j" .failure_reason job_execution_timeout
  trace_has "$j" timeout-start
  trace_lacks "$j" never-marker
  local d
  d=$(jq -r '.duration | floor' "$RUN/jobs/$j.json")
  [ "$d" -ge 55 ] && [ "$d" -lt 240 ] || bad "job $j took ${d}s for a 1m timeout"
  SC_DETAIL="ended after ${d}s"
}

sc_cancel() {
  local p j
  p=$({
    ci_header
    cat <<'EOF'
canceled:
  script: [echo cancel-start, sleep 600, echo never-marker]
  after_script: ['echo "after-cancel status=$CI_JOB_STATUS"']
EOF
  } | push_scenario cancel) || return 1
  j=$(job "$p" canceled)
  wait_for 600 eval "gl_trace $j 2>/dev/null | grep -qE '${LINE}cancel-start'" || {
    bad "job $j never printed cancel-start"
    return 1
  }
  local t0
  t0=$(date +%s)
  api POST "/projects/$GL_PROJECT_ID/jobs/$j/cancel" >/dev/null || bad "cancel request failed"
  gl_wait_job_state "$j" 120 canceled || bad "job $j not canceled 120s after the request"
  local took=$(($(date +%s) - t0))
  wait_pipeline "$p" canceled 60
  trace_lacks "$j" never-marker
  SC_DETAIL="canceled in ${took}s"
}

# Runs alone: it restarts vk-gitlab under the job.
sc_restart() {
  local p j
  p=$({
    ci_header
    cat <<'EOF'
survives:
  script: [echo restart-start, sleep 45, echo restart-done]
EOF
  } | push_scenario restart) || return 1
  j=$(job "$p" survives)
  wait_for 600 eval "gl_trace $j 2>/dev/null | grep -qE '${LINE}restart-start'" || {
    bad "job $j never printed restart-start"
    return 1
  }
  log "  restart: killing vk-gitlab (SIGKILL) under job $j"
  stop_bg vk-gitlab KILL 5
  sleep 5
  vk_gitlab_up
  wait_pipeline "$p" success 600 || return 1
  trace_has "$j" restart-done "Job succeeded"
  local n
  n=$(grep -cE "${LINE}restart-start" "$RUN/jobs/$j.log")
  [ "$n" = 1 ] || bad "restart-start appears $n times in job $j's trace"
  SC_DETAIL="resumed after SIGKILL"
}
