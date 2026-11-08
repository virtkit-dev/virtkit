#!/usr/bin/env bash
# CI tools kept by the hub, end to end: a hub (tests/fleet/lib.sh) and a node on the test host
# whose config names only a state dir, so no tools directory.
#
# 1. The hub holds its built-in definition from its start, labelled with its tools' versions;
#    an operator downloads it from the web UI as the tar nodes build, a viewer cannot.
# 2. With the `tools` setting naming a definition, a node that joins builds it with no tools
#    command from anyone, installs it as <state_dir>/tools/current, and hands it to its jobs.
# 3. A second node builds the same definition into the same files; neither is flagged.
#    Tampering with one byte of the tools installed on one node gets the next job that would be
#    given them refused before it boots, and the hub flags the node and has it build them anew.
# 4. A definition the setting names cannot be removed, and a manual build of other tools is
#    refused while the setting names these.
# 5. A failed build is tried again later on its own, not at once; `vk-hub nodes tools` tries it
#    again now, as the first attempt.
# 6. A build reaches only the hosts its definition declares; the failure names the one refused.
# 7. With the setting `none`, an operator builds any tools on the node.
# 8. Two nodes building a definition that is not reproducible install other files; tools
#    changed on a node the hub leaves alone stay flagged.
# Along the way, the web UI's pages show each state: a definition's page (its declared network,
# its nodes, their files and how they differ) and a node's CI tools (its check, a failed build
# and its next attempt, which an operator builds now from the page; a viewer cannot).
# With E2E_BUILTIN_TOOLS=1, the node then builds the hub's built-in tools, which needs network
# to the hosts its Dockerfile declares, and up to an hour.
#
# The definitions here hold a static stand-in for git: vk-testkit, VK_TESTKIT, by default built
# with `./dev.sh build -p vk-testkit`.
#
# Run:  VK=./dist/vk tests/fleet-tools-e2e.sh
# Needs: a `vk` with an embedded kernel/agent and the `vk-hub` beside it, KVM with nesting,
# openssl, curl, and a registry to pull alpine.
IMAGE_JOB=${IMAGE_JOB:-alpine:3.21}
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${VK_TESTKIT:-}" ]; then
  # CI supplies VK as an artifact path; dev.sh locates vk through PATH.
  bin=$(mktemp -d)
  ln -s "$(realpath "$(command -v "${VK:-./dist/vk}")")" "$bin/vk"
  PATH="$bin:$PATH" "$here/dev.sh" build -p vk-testkit >/dev/null 2>&1 ||
    { rm -rf "$bin"; echo "FAIL: building vk-testkit (./dev.sh build -p vk-testkit)"; exit 1; }
  rm -rf "$bin"
  VK_TESTKIT=$here/target/x86_64-unknown-linux-musl/debug/vk-testkit
fi
[ -x "$VK_TESTKIT" ] || { echo "no vk-testkit at $VK_TESTKIT"; exit 2; }
HUB_UI=1
. "$(dirname "$0")/fleet/lib.sh"
command -v curl >/dev/null || { echo "need curl, for the hub's web UI"; exit 2; }

# definition <name> <Dockerfile line>...: a build context the hub reads at
# /etc/vk-hub/<name>, its `git` the static stand-in.
definition() {
  local d=$FLEET/hub/$1
  shift
  mkdir -p "$d"
  printf '%s\n' "$@" >"$d/Dockerfile"
  cp "$VK_TESTKIT" "$d/git"
}
# operator_get <path> <file>: a download from the hub's web UI, as an operator signed in on
# first use.
operator_get() {
  local get=(curl -sSf --cacert "$FLEET/ca.pem" --connect-to "hub:8444:127.0.0.1:$UI_PORT"
    -H 'Sec-Fetch-Site: none' -b "$FLEET/operator.cookies" -c "$FLEET/operator.cookies")
  if ! grep -qs vk-hub "$FLEET/operator.cookies"; then
    local link
    link=$(hub ui login --role operator 2>/dev/null) || return 1
    "${get[@]}" -o /dev/null --data-urlencode "t=${link##*t=}" https://hub:8444/login || return 1
  fi
  "${get[@]}" -o "$2" "https://hub:8444$1"
}
# operator_post <path> <form>: a form posted to the hub's web UI as the operator, the way its
# page posts it, by htmx; prints the reply and its status last.
operator_post() {
  operator_get /settings "$FLEET/settings.html" || return 1
  local csrf
  csrf=$(grep -o 'name="_csrf" value="[^"]*"' "$FLEET/settings.html" | head -1 | cut -d'"' -f4)
  curl -sS --cacert "$FLEET/ca.pem" --connect-to "hub:8444:127.0.0.1:$UI_PORT" \
    -b "$FLEET/operator.cookies" -H 'Origin: https://hub:8444' -H 'HX-Request: true' \
    -w '\n%{http_code}\n' --data "_csrf=$csrf&$2" "https://hub:8444$1"
}
# page_has <who> <path> <fixed string>...: the page, as an operator or a viewer, holds each.
page_has() {
  local who=$1 path=$2 page
  shift 2
  if [ "$who" = operator ]; then
    operator_get "$path" "$FLEET/page.html" || return 1
    page=$(cat "$FLEET/page.html")
  else
    page=$(hub_ui "$path") || return 1
  fi
  for want in "$@"; do
    # Kept for a failure to show: the condition is polled.
    grep -qF -- "$want" <<<"$page" || { echo "$path lacks: $want" >"$FLEET/lacks"; return 1; }
  done
}
# ui_fail <why>: fail, saying what the page polled last lacked.
ui_fail() {
  fail "$1 ($(cat "$FLEET/lacks" 2>/dev/null))"
}
current() {
  readlink "$FLEET/kvm/state/tools/current" 2>/dev/null || true
}
has_tools() {
  [ "$(current)" = "$1" ] && [ -x "$FLEET/kvm/state/tools/current/git" ]
}
# issued <id> <actor> <label>: how many builds of tools <label> <actor> issued node <id>.
issued() {
  local a
  a=$(hub_audit "$1")
  grep -cE "$2 issued tools $3 " <<<"$a" || true
}
# The files the tools <sha256> installed on node <name> are recorded with: the manifest's
# `files` object, as the node writes it.
recorded() {
  local m
  if [ "$1" = kvm ]; then
    m=$(cat "$FLEET/kvm/state/tools/$2.json")
  else
    m=$(in_node "$1" cat "/var/lib/virtkit/tools/$2.json")
  fi
  sed -n '/^  "files": {/,/^  }/p' <<<"$m"
}
# job <script>: one CI job on the test host's node, as its gitlab-runner would run it — prepare
# (its output in $FLEET/prepare.log), one step running <script>, cleanup.
job() (
  rc=0
  # A job resolves its tools through directories no other user can write.
  chmod go-w "$FLEET" "$FLEET/kvm" "$FLEET/kvm/state"
  # In this subshell only: any other `vk` would take itself for a job's.
  export CUSTOM_ENV_CI_JOB_ID="tools-e2e-$$-$RANDOM" CUSTOM_ENV_CI_JOB_IMAGE=$IMAGE_JOB
  printf '%s\n' "$1" >"$FLEET/step.sh"
  host_vk kvm gitlab prepare >"$FLEET/prepare.log" 2>&1 || rc=$?
  [ "$rc" != 0 ] || host_vk kvm gitlab run "$FLEET/step.sh" build_script >"$FLEET/step.log" 2>&1 ||
    rc=$?
  host_vk kvm gitlab cleanup >/dev/null 2>&1 || true
  exit "$rc"
)
# What `vk-hub nodes` notes of the node's CI tools against the setting.
note() {
  local n
  n=$(hub nodes)
  grep -F "CI tools" <<<"$n" | grep -vF ": tools " || true
}

definition good 'FROM scratch AS tools' 'COPY git /git'
definition other 'FROM scratch AS tools' 'COPY git /git' '# another definition'
# No `tools` stage: the node's build fails.
definition bad 'FROM scratch AS other' 'COPY git /git'
# A step reaching a host its stage does not declare: the node's build is refused it, and fails.
definition sealed '# vk: allow-name=example.com' 'FROM alpine AS fetch' \
  'RUN wget -q -T 10 -O /page http://example.org/' 'FROM scratch AS tools' \
  'COPY --from=fetch /page /page' 'COPY git /git'
# Not reproducible: every build installs another stamp.
definition stamped 'FROM alpine AS stamp' 'RUN head -c 16 /dev/urandom >/stamp' \
  'FROM scratch AS tools' 'COPY --from=stamp /stamp /stamp' 'COPY git /git'

echo "== the hub holds its built-in tools =="
fleet_up n1
hub tools list
builtin=$(hub tools list | awk '$2 ~ /^git-[^-]+-lfs-[^-]+$/ {print $1}')
[ -n "$builtin" ] || fail "the hub holds no built-in tools"
operator_get "/tools/$builtin.tar" "$FLEET/builtin.tar" || fail "an operator could not download them"
[ "$(sha256sum <"$FLEET/builtin.tar" | awk '{print $1}')" = "$builtin" ] ||
  fail "the download is not the definition"
[ "$(tar -tf "$FLEET/builtin.tar" | tr '\n' ' ')" = "Dockerfile flake.lock flake.nix " ] ||
  fail "the built-in definition holds $(tar -tf "$FLEET/builtin.tar")"
hub_ui "/tools/$builtin.tar" >/dev/null 2>&1 && fail "a viewer downloaded a definition"

echo "== a node that joins builds the tools the setting names, unasked =="
good=$(hub tools add /etc/vk-hub/good --version e2e-good)
bad=$(hub tools add /etc/vk-hub/bad --version e2e-bad)
hub settings set tools "${good:0:12}"
hub settings | grep -qF "tools = $good" || fail "the setting does not keep the whole sha256"
mkdir -p "$FLEET/kvm"
printf 'state_dir = "%s"\n' "$FLEET/kvm/state" >"$FLEET/kvm/config.toml"
fleet_kvm_node
k=$(node_id kvm)
wait_for 60 node_reported "$k" || fail "the test host's node ($k) did not report in"
wait_for 600 has_tools "$good" || { hub nodes; fail "the node did not install the tools"; }
[ "$(issued "$k" auto-deploy e2e-good)" = 1 ] || fail "the hub did not ask once on its own"
hub_audit "$k" | grep -E "uid [0-9]+ issued tools" && fail "an operator's build was issued"
wait_for 90 eval '[ -z "$(note)" ]' || fail "the node is still noted: $(note)"
host_vk kvm paths --gitlab | grep -F "tools dir     $FLEET/kvm/state/tools/current" ||
  fail "the node's jobs are not given the tools"
kvm_host=$(node_cell "$k" NAME)
wait_for 60 page_has viewer "/tools/$good" '<h1>e2e-good</h1>' \
  '<tr><th>Named by the settings</th><td>fleet-wide</td></tr>' \
  "<a href=\"/node/$k\">$kvm_host</a></td><td>fleet-wide</td><td><span class=\"badge ok\">intact" \
  '<td><code>tools</code></td><td colspan="2">none: its steps reach no network</td>' \
  '<h3>Files <code>' || ui_fail "the definition's page does not show the node with its tools"
hub_ui "/tools/$good" | grep -qF 'download>Download' && fail "a viewer is offered the download"
page_has operator "/tools/$good" 'download>Download</a>' || ui_fail "an operator is not offered the download"
page_has viewer "/node/$k" '<section><h2>CI tools</h2>' "<a href=\"/tools/$good\">e2e-good</a>" \
  'by the fleet-wide setting' '<span class="badge ok">intact</span>' \
  '<summary>Files as installed (1)</summary>' || ui_fail "the node's page does not show its tools"
page_has viewer "/tools/$builtin" '<td><code>build</code></td><td>cache.nixos.org, github.com, release-assets.githubusercontent.com</td>' \
  || ui_fail "the built-in definition's page does not show the network it declares"

echo "== two nodes build the same files; tools tampered with are given to no job =="
node_up n1
n1=$(node_id n1)
wait_for 600 eval 'in_node n1 test -x "/var/lib/virtkit/tools/$good/git"' ||
  { hub nodes; fail "the second node did not install the tools"; }
[ -n "$(recorded kvm "$good")" ] || fail "the node recorded no checksums"
[ "$(recorded kvm "$good")" = "$(recorded n1 "$good")" ] ||
  fail "the two nodes recorded other files: $(recorded kvm "$good") / $(recorded n1 "$good")"
grep -F '"sha256"' <<<"$(recorded kvm "$good")" | grep -qF "$(sha256sum <"$VK_TESTKIT" | cut -c1-64)" ||
  fail "the recorded checksum is not git's"
sleep 5
hub nodes | grep -F "other files" && fail "nodes with the same files were flagged"
job 'test -x /run/virtkit-tools/git' ||
  { cat "$FLEET/prepare.log" "$FLEET/step.log" 2>/dev/null; fail "a job was not given the tools"; }
# A few bytes of git, in place: same size, same mode.
printf 'VKE2' | dd of="$FLEET/kvm/state/tools/$good/git" bs=1 seek=4096 conv=notrunc status=none
cmp -s "$VK_TESTKIT" "$FLEET/kvm/state/tools/$good/git" && fail "git was not changed"
job 'test -x /run/virtkit-tools/git' && fail "a job was given tampered tools"
grep -F "have changed since they were installed (git)" "$FLEET/prepare.log" ||
  { cat "$FLEET/prepare.log"; fail "the job's refusal does not say why"; }
wait_for 150 eval 'hub_audit "$k" | grep -qF "have changed since it installed them (git)"' ||
  { hub nodes; fail "the hub did not flag the tampered tools"; }
[ "$(issued "$k" auto-deploy e2e-good)" = 2 ] ||
  wait_for 60 eval '[ "$(issued "$k" auto-deploy e2e-good)" = 2 ]' ||
  fail "the hub did not have the tampered tools built anew"
wait_for 600 eval 'cmp -s "$VK_TESTKIT" "$FLEET/kvm/state/tools/$good/git"' ||
  { hub nodes; fail "the tampered tools were not built anew"; }
job 'test -x /run/virtkit-tools/git' ||
  { cat "$FLEET/prepare.log"; fail "a job was not given the tools built anew"; }
hub_audit "$n1" | grep -F "changed since" && fail "the untouched node was flagged"

echo "== the setting's definition is kept, other tools refused =="
hub tools remove "$good" && fail "a definition the setting names was removed"
hub nodes tools "$k" --tools "$bad" && fail "a build of other tools than the setting's was issued"

echo "== a failed build is tried again later, or now by an operator =="
hub settings set tools "$bad" --node "$k"
wait_for 120 eval 'note | grep -q "attempt 1 of 5 .* failed.*the next is due after"' ||
  { hub nodes; fail "the failed build and its retry are not noted"; }
note
page_has viewer "/node/$k" '<span class="badge bad">failed</span> attempt 1 of 5' \
  'The next attempt is due after' "<a href=\"/tools/$bad\">e2e-bad</a>" ||
  ui_fail "the node's page does not show the failed build"
hub_ui "/node/$k" | grep -qF 'Build now' && fail "a viewer is offered to build now"
page_has operator "/node/$k" "name=\"tools\" value=\"$bad\"><button>Build now</button>" ||
  ui_fail "an operator is not offered to build the failed build's tools now"
sleep 15
[ "$(issued "$k" auto-deploy e2e-bad)" = 1 ] || fail "the failed build was tried again at once"
hub nodes tools "$k"
wait_for 120 eval '[ "$(issued "$k" "uid [0-9]+" e2e-bad)" = 1 ]' ||
  fail "\`vk-hub nodes tools\` did not ask again"
wait_for 120 eval 'note | grep -q "attempt 1 of 5 .* failed"' ||
  fail "the second failure is not noted as a first attempt"
[ "$(current)" = "$good" ] || fail "a failed build changed the tools"
# Again from the node's page: the same as `vk-hub nodes tools`. Other tools are refused.
r=$(operator_post "/node/$k/action" "op=tools&tools=$good")
grep -qF "setting keeps it on" <<<"$r" && [ "$(tail -1 <<<"$r")" = 409 ] ||
  fail "the page built other tools than the setting names: $r"
wait_for 120 eval 'page_has operator "/node/$k" "Build now"' || fail "Build now is not offered"
r=$(operator_post "/node/$k/action" "op=tools&tools=$bad")
grep -qF "Issued the build of the CI tools" <<<"$r" || fail "the page did not build now: $r"
wait_for 120 eval '[ "$(issued "$k" "ui session [0-9a-f]+ \(operator\)" e2e-bad)" = 1 ]' ||
  fail "the page's build was not issued as the operator's"
wait_for 120 eval 'note | grep -q "attempt 1 of 5 .* failed"' ||
  fail "the page's build is not noted as a first attempt"

echo "== a build reaches only what its definition declares =="
sealed=$(hub tools add /etc/vk-hub/sealed --version e2e-sealed)
hub settings set tools "$sealed" --node "$k"
wait_for 300 eval 'note | grep -q "refused to example.org"' ||
  { hub nodes; fail "the build reached, or did not name, a host its definition does not declare"; }
page_has viewer "/tools/$sealed" '<td><code>fetch</code></td><td>example.com</td><td>none</td>' \
  "<a href=\"/node/$k\">$kvm_host</a></td><td>its own setting</td>" 'example.org' ||
  ui_fail "the sealed definition's page does not show what it declares and what was refused"
[ "$(current)" = "$good" ] || fail "a refused build changed the tools"

echo "== with the setting none, an operator builds any tools =="
other=$(hub tools add /etc/vk-hub/other --version e2e-other)
hub settings set tools none --node "$k"
wait_for 30 eval '[ -z "$(note)" ]' || fail "a node left alone is still noted: $(note)"
hub nodes tools "$k" --tools "$other"
wait_for 600 has_tools "$other" || { hub nodes; fail "the operator's tools were not installed"; }
sleep 10
[ "$(current)" = "$other" ] || fail "the hub moved a node it leaves alone"

echo "== nodes that built other files are told apart; changed tools stay flagged =="
stamped=$(hub tools add /etc/vk-hub/stamped --version e2e-stamped)
hub settings set tools "$stamped" --node "$k"
hub settings set tools "$stamped" --node "$n1"
wait_for 600 has_tools "$stamped" || { hub nodes; fail "the node did not install the stamped tools"; }
wait_for 600 eval 'in_node n1 test -x "/var/lib/virtkit/tools/$stamped/git"' ||
  { hub nodes; fail "the second node did not install the stamped tools"; }
wait_for 120 page_has viewer "/tools/$stamped" 'Which are right cannot be told' \
  '<span class="badge bad">differs</span>' || ui_fail "the definition's page does not tell the nodes apart"
[ "$(hub_ui "/tools/$stamped" | grep -o '<h3>Files <code>' | wc -l)" = 2 ] ||
  fail "the definition's page does not show two sets of files"
page_has viewer /updates '<span class="badge bad">files differ</span>' ||
  ui_fail "/updates does not flag the definition"
page_has viewer "/node/$k" '<span class="badge bad">other files</span> than' ||
  ui_fail "the node's page does not flag its files"
# Left alone, the node keeps tools changed since it installed them, and the hub shows them so.
hub settings set tools none --node "$k"
printf 'VKE2' | dd of="$FLEET/kvm/state/tools/$stamped/git" bs=1 seek=4096 conv=notrunc status=none
wait_for 150 page_has viewer "/node/$k" '<span class="badge bad">changed</span> since they were installed: git.' ||
  ui_fail "the node's page does not show its changed tools"
page_has viewer "/tools/$stamped" '<span class="badge bad">changed</span>' ||
  ui_fail "the definition's page does not show the changed tools"

if [ "${E2E_BUILTIN_TOOLS:-}" = 1 ]; then
  echo "== the node builds the hub's built-in tools =="
  hub settings unset tools --node "$k"
  hub settings set tools builtin
  wait_for 3600 has_tools "$builtin" || { hub nodes; fail "the built-in tools were not installed"; }
  for t in git git-remote-http git-remote-https git-submodule git-sh-setup git-sh-i18n \
    git-sh-i18n--envsubst git-upload-pack git-receive-pack git-lfs; do
    [ -x "$FLEET/kvm/state/tools/current/$t" ] || fail "the built-in tools lack $t"
  done
  [ ! -e "$FLEET/kvm/state/tools/current/gitlab-runner" ] ||
    fail "the built-in tools hold gitlab-runner"
fi

echo "PASS: nodes get the setting's tools unasked, keep them, retry a failed build later, and never give a job tools that changed; the web UI shows it all"
