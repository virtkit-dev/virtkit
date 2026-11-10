#!/usr/bin/env bash
# Install media through the hub, end to end, on this host (no VM): a `vk-hub serve` and a
# `vk-registry serve` on loopback, the registry taking the hub's tokens and no anonymous
# request.
#
# 1. `vk-hub media add` streams a medium from the hub's host to the registry, under the
#    repository path nodes' `[build] cache_registry` names, which stores it as `vk registry put
#    --keep --dir win-media` would there: `vk registry get sha256:<hex>`, as a node's Windows
#    build fetches media, gets it back whole. The hub records it once the
#    registry confirms its sha256, with what its volume label says, and approves it in the
#    fleet-wide `executor.windows_media`.
# 2. Its description is edited; approval is withdrawn and given again; the same bytes
#    uploaded again are recognised; removing the medium withdraws its approval and leaves
#    the registry's copy.
# 3. The web UI uploads a medium the same way, as a form post streamed on to the registry,
#    and shows it; an upload cut short leaves nothing behind on either side; known bytes keep
#    their description; one whose session ends meanwhile is held by the registry, not recorded.
# 4. A registry that is not connected is refused up front, and nothing is recorded.
#
# MEDIA_ISO=<file> also uploads that file (a real install ISO; several GB are fine) from the CLI
# and the web UI, and checks the hub's peak memory stays below 512 MiB.
#
# Run:  VK=./dist/vk tests/hub-media-e2e.sh
# Needs: VK (default ./dist/vk), and VK_HUB and VK_REGISTRY (default: the vk-hub and
# vk-registry beside VK) built from this tree (./build.sh), curl, python3. WORK_DIR (default
# $HOME) holds its scratch directory.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
VK_HUB=${VK_HUB:-$(dirname "$VK")/vk-hub}
VK_REGISTRY=${VK_REGISTRY:-$(dirname "$VK")/vk-registry}
for b in "$VK_HUB" "$VK_REGISTRY"; do
  [ -x "$b" ] || { echo "no usable $b (build it: ./build.sh, or set VK_HUB, VK_REGISTRY)"; exit 2; }
done
WORK=$(mktemp -d "${WORK_DIR:-$HOME}/vk-hub-media-e2e.XXXXXX")
pids=()
reg_pid=
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  echo "--- hub log"; tail -n 30 "$WORK/hub.log" || true
  echo "--- registry log"; tail -n 30 "$WORK/registry.log" || true
  exit 1
}
wait_for() {
  local secs=$1; shift
  for _ in $(seq "$((secs * 2))"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

HUB_PORT=$(port)
UI_PORT=$(port)
UI=http://127.0.0.1:$UI_PORT
REG_PORT=$(port)
REG_URL=http://127.0.0.1:$REG_PORT
mkdir -p "$WORK/hub" "$WORK/store" "$WORK/media"
cat >"$WORK/hub.toml" <<EOF
addr = "127.0.0.1:$HUB_PORT"
data_dir = "$WORK/hub"
ui_addr = "127.0.0.1:$UI_PORT"
ui_url = "$UI"
EOF
hub() { "$VK_HUB" "$@" --config "$WORK/hub.toml"; }
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$WORK/secret"
cat >"$WORK/registry.toml" <<EOF
addr = "127.0.0.1:$REG_PORT"
root = "$WORK/store"
token_file = "$WORK/secret"

[hub]
tokens = true
EOF
# What a node's build reads media with: the registry's credential, as `[build] cache_registry`.
cat >"$WORK/vk.toml" <<EOF
state_dir = "$WORK/vk-state"

[build]
cache_registry = "127.0.0.1:$REG_PORT/build-cache"
cache_insecure = true
cache_token_file = "$WORK/secret"
EOF
node_get() { VIRTKIT_CONFIG=$WORK/vk.toml "$VK" registry get "$@"; }

"$VK_HUB" serve --config "$WORK/hub.toml" >"$WORK/hub.log" 2>&1 &
pids+=($!)
wait_for 20 hub registries || fail "the hub did not come up"
hub token create --kind registry |
  "$VK_REGISTRY" join "http://127.0.0.1:$HUB_PORT" --token - \
    --config "$WORK/registry.toml" >"$WORK/id" || fail "join"
id=$(cat "$WORK/id")
start_registry() {
  "$VK_REGISTRY" serve --config "$WORK/registry.toml" >>"$WORK/registry.log" 2>&1 &
  reg_pid=$!
  pids+=("$reg_pid")
}
start_registry
connected() { hub registries | awk -v id="$id" '$1 == id && $3 == "connected"' | grep -q .; }
wait_for 30 connected || fail "the registry did not connect"
hub registries set-url "$id" "$REG_URL"
takes_tokens() {
  local t
  t=$(hub registries token "$id" --grant e2e-probe=r --ttl 60s 2>/dev/null) &&
    [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $t" \
      "$REG_URL/v2/e2e-probe/tags/list")" = 200 ]
}
wait_for 60 takes_tokens || fail "the registry does not take the hub's tokens"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$REG_URL/v2/")" = 401 ] ||
  fail "the registry answers anonymous requests"

# iso <file> <label> <MiB>: an ISO 9660 image's start, a volume label, then random bytes.
iso() {
  python3 - "$1" "$2" "$3" <<'EOF'
import os, sys
path, label, mib = sys.argv[1], sys.argv[2].encode(), int(sys.argv[3])
pvd = bytearray(2048)
pvd[0] = 1
pvd[1:6] = b"CD001"
pvd[40:72] = label.ljust(32)
with open(path, "wb") as f:
    f.write(bytes(0x8000) + pvd)
    for _ in range(mib):
        f.write(os.urandom(1 << 20))
EOF
}
iso "$WORK/media/ws2025-eval-en-us.iso" SSS_X64FREE_EN-US_DV9 24
iso "$WORK/media/virtio-win.iso" virtio-win-0.1.302 8
sha_of() { sha256sum "$1" | awk '{print $1}'; }
ws=$(sha_of "$WORK/media/ws2025-eval-en-us.iso")
virtio=$(sha_of "$WORK/media/virtio-win.iso")
approved() { hub settings | grep -F executor.windows_media | grep -qF "$1"; }

echo "== 1. a medium streams through the hub into the registry, recorded and approved =="
got=$(hub media add "$WORK/media/ws2025-eval-en-us.iso" --under build-cache \
  --product "Windows Server 2025" --edition "Datacenter Evaluation" --build 26100.1742 \
  --license evaluation --license-terms "Activated at build; each build runs 180 days." \
  --source "https://go.microsoft.com/fwlink/?linkid=2293312&clcid=0x409&culture=en-us&country=us" \
  --obtained 2026-11-09) || fail "media add"
[ "$got" = "$ws" ] || fail "the hub recorded $got, not the file's $ws"
hub media show "${ws:0:12}" | tee "$WORK/show"
for want in "approved +yes, fleet-wide" "arch +x64" "language +en-us" \
  "volume label +SSS_X64FREE_EN-US_DV9" "license +Evaluation" "registry +$id: build-cache/files/win-media:ws2025-eval-en-us.iso"; do
  grep -qE "$want" "$WORK/show" || fail "media show lacks /$want/"
done
approved "$ws" || fail "the medium is not approved fleet-wide"
node_get "sha256:$ws" -o "$WORK/fetched.iso" || fail "a node cannot fetch the medium by digest"
[ "$(sha_of "$WORK/fetched.iso")" = "$ws" ] || fail "the medium fetched is not the one uploaded"
manifest=$(curl -sf -H "Authorization: Bearer $(cat "$WORK/secret")" \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  "$REG_URL/v2/build-cache/files/win-media/manifests/ws2025-eval-en-us.iso") ||
  fail "the registry does not name the medium in win-media"
for want in '"org.virtkit.retention":"keep"' '"org.virtkit.media.build":"26100.1742"' \
  '"org.virtkit.media.arch":"x64"'; do
  grep -qF "$want" <<<"$manifest" || fail "the medium's manifest lacks $want"
done
[ -z "$(find "$WORK/store/uploads" -maxdepth 1 -type f)" ] || fail "the registry kept staging files"
[ -z "$(find "$WORK/hub" -size +1M -type f -not -name '*.redb')" ] || fail "the hub kept a copy"

got=$(hub media add "$WORK/media/virtio-win.iso" --under build-cache --no-approve \
  --license open-source) ||
  fail "media add --no-approve"
[ "$got" = "$virtio" ] || fail "the drivers were recorded as $got"
hub media show "$virtio" | tee "$WORK/show"
grep -qE "kind +Drivers" "$WORK/show" || fail "the drivers' kind was not read from their label"
grep -qE "version +0.1.302" "$WORK/show" || fail "the drivers' version was not read"
! approved "$virtio" || fail "a medium uploaded --no-approve was approved"
hub media list

echo "== 2. edited, approved, uploaded again, removed =="
hub media edit "${ws:0:12}" --notes "Rearm with slmgr /rearm; replace when Microsoft withdraws it." \
  --expires 2027-05-08 >/dev/null
hub media show "$ws" | grep -q "slmgr /rearm" || fail "the edit did not hold"
hub media approve "$virtio"
approved "$virtio" || fail "approve"
hub media unapprove "$virtio"
! approved "$virtio" || fail "unapprove"
hub media add "$WORK/media/virtio-win.iso" --no-approve --product other >/dev/null
hub media show "$virtio" | tee "$WORK/show"
grep -qE "registry +$id: files/win-media:virtio-win.iso" "$WORK/show" &&
  grep -qE "registry +$id: build-cache/files/win-media:virtio-win.iso" "$WORK/show" ||
  fail "an upload elsewhere in the registry was not recorded beside the first"
hub media show "$virtio" | grep -qE "product +virtio-win" ||
  fail "an upload of known bytes changed what was said of them"
hub media remove "$ws"
! approved "$ws" || fail "a removed medium stays approved"
! hub media show "$ws" 2>/dev/null || fail "a removed medium is still listed"
node_get "sha256:$ws" -o "$WORK/again.iso" || fail "removing a medium removed the registry's copy"
hub audit --limit 100 | tee "$WORK/audit" | grep -E "medium" || true
for want in "uploaded medium ${ws:0:12}" "edited medium ${ws:0:12}" "removed medium ${ws:0:12}"; do
  grep -qF "$want" "$WORK/audit" || fail "the audit log lacks '$want'"
done


echo "== 3. the web UI uploads a medium, streamed on; one cut short leaves nothing =="
# An operator's session, and its CSRF token from the media page.
ui() { curl -sS -b "$WORK/cookies" -c "$WORK/cookies" -H "Origin: $UI" "$@"; }
sign_in() {
  local link
  rm -f "$WORK/cookies"
  link=$(hub ui login --role operator)
  ui -o /dev/null -H 'Sec-Fetch-Site: same-origin' --data-urlencode "t=${link##*t=}" "$UI/login" ||
    fail "could not sign in to the web UI"
  csrf=$(ui "$UI/media" | sed -n 's/.*name="_csrf" value="\([0-9a-f]*\)".*/\1/p' | head -n 1)
  [ -n "$csrf" ] || fail "the media page has no upload form for an operator"
  # A form as a browser posts it: what is said of the medium, then the file, last.
  form=(-F "_csrf=$csrf" -F "registry=$id" -F under=build-cache -F approve=yes -F kind=windows
    -F "product=Windows 11" -F license=retail -F "notes=from the web UI")
}
sign_in
iso "$WORK/media/ui.iso" SSS_ARM64FRE_FR-FR_DV9 16
uisha=$(sha_of "$WORK/media/ui.iso")
code=$(ui -o "$WORK/reply" -w '%{http_code}' "${form[@]}" -F "file=@$WORK/media/ui.iso" \
  "$UI/media/upload") || fail "the web UI upload failed"
[ "$code" = 303 ] || { cat "$WORK/reply"; fail "the web UI upload answered $code"; }
hub media show "$uisha" | tee "$WORK/show"
for want in "arch +arm64" "language +fr-fr" "product +Windows 11" "approved +yes" \
  "registry +$id: build-cache/files/win-media:ui.iso"; do
  grep -qE "$want" "$WORK/show" || fail "the medium uploaded from the web UI lacks /$want/"
done
node_get "sha256:$uisha" -o "$WORK/ui-back.iso" || fail "a node cannot fetch the web UI's upload"
ui "$UI/media/$uisha" | grep -q "from the web UI" || fail "the medium's page does not show it"
# Cut short: the browser goes away a few MiB in.
iso "$WORK/media/cut.iso" CUT 64
cutsha=$(sha_of "$WORK/media/cut.iso")
! ui -o /dev/null --limit-rate 2M -m 3 "${form[@]}" -F "file=@$WORK/media/cut.iso" \
  "$UI/media/upload" 2>/dev/null || fail "the cut-short upload completed"
staged() { find "$WORK/store/uploads" -maxdepth 1 -type f | grep -q .; }
wait_for 60 eval '! staged' || fail "the registry kept the cut-short upload's staging file"
! hub media list | grep -qF "$cutsha" || fail "a cut-short upload was recorded"
! node_get "sha256:$cutsha" -o "$WORK/cut-back.iso" 2>/dev/null ||
  fail "the registry tagged a cut-short upload"
# The same bytes again: known, the description they have stands.
code=$(ui -o "$WORK/reply" -w '%{http_code}' -F "_csrf=$csrf" -F "registry=$id" \
  -F under=build-cache -F "notes=again" -F "file=@$WORK/media/ui.iso" "$UI/media/upload") ||
  fail "the web UI upload of known bytes failed"
[ "$code" = 200 ] && grep -q "Already uploaded" "$WORK/reply" ||
  { cat "$WORK/reply"; fail "the web UI upload of known bytes answered $code"; }
hub media show "$uisha" | grep -q "from the web UI" ||
  fail "the web UI upload of known bytes changed the description"
# The session ends while the file arrives: the registry holds it, the page says where, the hub
# records nothing, and the next upload is taken.
iso "$WORK/media/ended.iso" ENDED 32
endedsha=$(sha_of "$WORK/media/ended.iso")
ui -o "$WORK/reply" -w '%{http_code}' --limit-rate 4M "${form[@]}" \
  -F "file=@$WORK/media/ended.iso" "$UI/media/upload" >"$WORK/code" &
upload_pid=$!
sleep 3
hub ui logout --all >/dev/null
wait "$upload_pid" || fail "the upload whose session ended failed"
code=$(cat "$WORK/code")
case $code in 401 | 403) ;; *) cat "$WORK/reply"; fail "the upload whose session ended answered $code" ;; esac
grep -q "Not recorded: registry $id holds medium $endedsha as build-cache/files/win-media:ended.iso" \
  "$WORK/reply" || { cat "$WORK/reply"; fail "the page does not say where the file is"; }
! hub media list | grep -qF "$endedsha" || fail "the hub recorded an upload whose session ended"
node_get "sha256:$endedsha" -o "$WORK/ended-back.iso" || fail "the registry does not hold it"
sign_in
code=$(ui -o "$WORK/reply" -w '%{http_code}' "${form[@]}" -F "file=@$WORK/media/ended.iso" \
  "$UI/media/upload") || fail "uploading it again failed"
[ "$code" = 303 ] && hub media list | grep -qF "$endedsha" ||
  { cat "$WORK/reply"; fail "uploading it again answered $code and did not record it"; }

if [ -n "${MEDIA_ISO:-}" ]; then
  echo "== a real medium, from the CLI and the web UI: $MEDIA_ISO =="
  real=$(sha_of "$MEDIA_ISO")
  start=$(date +%s)
  got=$(hub media add "$MEDIA_ISO" --under build-cache --no-approve) ||
    fail "media add $MEDIA_ISO"
  echo "uploaded from the CLI in $(($(date +%s) - start))s"
  [ "$got" = "$real" ] || fail "the hub recorded $got for $MEDIA_ISO"
  start=$(date +%s)
  code=$(ui -o "$WORK/reply" -w '%{http_code}' "${form[@]}" -F "file=@$MEDIA_ISO" \
    "$UI/media/upload") || fail "the web UI upload of $MEDIA_ISO failed"
  # The CLI uploaded the same bytes: the page says so, and the description stands.
  [ "$code" = 200 ] && grep -q "Already uploaded" "$WORK/reply" ||
    { cat "$WORK/reply"; fail "the web UI upload of known bytes answered $code"; }
  ! hub media show "$real" | grep -q "from the web UI" ||
    fail "the web UI upload of known bytes changed the description"
  echo "uploaded from the web UI in $(($(date +%s) - start))s"
  hub media show "$real"
  node_get "sha256:$real" -o "$WORK/real.iso" || fail "a node cannot fetch $MEDIA_ISO"
  [ "$(sha_of "$WORK/real.iso")" = "$real" ] || fail "$MEDIA_ISO came back changed"
  rm -f "$WORK/real.iso"
  # Streamed through: the hub's peak memory stays below 512 MiB.
  peak=$(awk '/VmHWM/ {print $2}' "/proc/${pids[0]}/status")
  echo "hub peak memory: ${peak} kB"
  [ "$peak" -lt 524288 ] || fail "the hub's memory peaked at ${peak} kB"
fi

echo "== 4. a registry that is not connected is refused up front =="
kill "$reg_pid"
wait "$reg_pid" 2>/dev/null || true
wait_for 60 eval '! connected' || fail "the hub still lists the registry connected"
iso "$WORK/media/late.iso" LATE 1
! hub media add "$WORK/media/late.iso" --registry "$id" 2>"$WORK/err" ||
  fail "an upload to a registry gone was taken"
cat "$WORK/err"
grep -q "not connected" "$WORK/err" || fail "the refusal does not say why"
! hub media list | grep -q late.iso || fail "a refused upload was recorded"

echo "PASS: media stream through the hub into its registry, described, approved and fetched by digest"
