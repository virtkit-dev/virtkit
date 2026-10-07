# shellcheck shell=bash
# Shared helpers for gitlab-e2e.sh: logging, polling, and the result table.

log() { printf '%s %s\n' "$(date +%T)" "$*" >&2; }
die() {
  log "FATAL: $*"
  exit 1
}

# wait_for <seconds> <command...>: poll every second until the command succeeds.
wait_for() {
  local deadline=$(($(date +%s) + $1))
  shift
  until "$@"; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 1
  done
}

# A host TCP port with no listener at the time of the check.
free_port() {
  local port
  for port in $(shuf -i 20000-60000 -n 50); do
    ss -Htln "sport = :$port" | grep -q . || {
      echo "$port"
      return
    }
  done
  die "no free port"
}

# Scenario results: name, PASS/FAIL/SKIP, detail.
RESULTS=()
FAILED=0

pass() { RESULTS+=("$1|PASS|${2:-}"); log "PASS $1 ${2:-}"; }
skip() { RESULTS+=("$1|SKIP|$2"); log "SKIP $1: $2"; }
failed() {
  RESULTS+=("$1|FAIL|$2")
  FAILED=$((FAILED + 1))
  log "FAIL $1: $2"
}

print_summary() {
  local r name status detail
  printf '\n%-18s %-5s %s\n' SCENARIO RESULT DETAIL
  for r in ${RESULTS[@]+"${RESULTS[@]}"}; do
    IFS='|' read -r name status detail <<<"$r"
    printf '%-18s %-5s %s\n' "$name" "$status" "$detail"
  done
}
