#!/usr/bin/env bash
# Run with VK=./dist/vk. Needs KVM and access to the Debian image.
set -euo pipefail
VK="${VK:-vk}"
VK="$(realpath "$(command -v "$VK")")"
cd "$(dirname "$0")"
multi=$'first line\nsecond \'quoted\' line\n'
"$VK" run -f run-env/Dockerfile --context run-env --target base --env "MULTI=$multi" -- sh -c '
    set -eu
    expected=$MULTI
    export EXPECTED="$expected"
    unset MULTI IMAGE_ONLY
    /bin/bash -lc '\''
        set -eu
        test "$MULTI" = "$EXPECTED"
        test "$IMAGE_ONLY" = from-image
        test "$(image-tool)" = image-path-ok
        test ! -e /etc/virtkit/env
        test ! -e /etc/virtkit/user
        test -f /run/vk/env.json
        test ! -e /virtkit-service.json
        before=$PATH
        . /etc/profile.d/zz-virtkit-env.sh
        . /etc/profile.d/zz-virtkit-env.sh
        test "$PATH" = "$before"
        test "$MULTI" = "$EXPECTED"
        IMAGE_ONLY=session
        export IMAGE_ONLY
        . /etc/profile.d/zz-virtkit-env.sh
        test "$IMAGE_ONLY" = session
    '\''
    # Inspect the covered root directory: no placeholder or boot config was written.
    mkdir /run/root-view
    mount --bind / /run/root-view
    test ! -e /run/root-view/etc/profile.d/zz-virtkit-env.sh
    test ! -e /run/root-view/virtkit-service.json
    umount /run/root-view
    printf invalid >/run/vk/env/0.json
    if output=$(/run/vk/bin/vk-agent env --export 2>/dev/null); then
        echo "corrupt environment unexpectedly accepted" >&2
        exit 1
    fi
    test -z "$output"
    echo "login environment: PASS"
'

# The RAM image carries its config inside the root initramfs: PID 1 must unlink it.
"$VK" run --ram --mem 2G --source oci debian:bookworm \
    --env "MULTI=$multi" --env PATH=/ram/image/bin:/usr/bin:/bin -- sh -c '
    set -eu
    export EXPECTED="$MULTI"
    unset MULTI
    /bin/bash -lc '\''
        set -eu
        test "$MULTI" = "$EXPECTED"
        case "$PATH" in /ram/image/bin:*) ;; *) exit 1 ;; esac
        test ! -e /virtkit-service.json
        test ! -e /etc/virtkit/env
        echo "RAM login environment: PASS"
    '\''
'

"$VK" run -f run-env/Dockerfile --context run-env --target nonroot \
    --env "MULTI=$multi" -- sh -c '
    set -eu
    test "$(id -u)" = 65534
    export EXPECTED="$MULTI"
    unset MULTI IMAGE_ONLY
    /bin/bash -lc '\''
        set -eu
        test "$MULTI" = "$EXPECTED"
        test "$IMAGE_ONLY" = from-image
        test "$(image-tool)" = image-path-ok
        test ! -r /run/vk/env.json
        echo "non-root login environment: PASS"
    '\''
'

# Plain OCI boots take a different conversion path from Dockerfile builds. Exercise
# both disk and RAM boots with an image that declares an unprivileged USER.
for medium in disk ram; do
    flags=()
    if [ "$medium" = ram ]; then flags+=(--ram); fi
    "$VK" run "${flags[@]}" --mem 2G --source oci nginxinc/nginx-unprivileged:1.27-alpine \
        --env "MULTI=$multi" -- sh -c '
        set -eu
        test "$(id -u)" -ne 0
        test "$(stat -c %u /var/cache/nginx)" = "$(id -u)"
        mkdir /var/cache/nginx/vk-env-private
        chmod 700 /var/cache/nginx/vk-env-private
        printf writable >/var/cache/nginx/vk-env-private/value
        test "$(cat /var/cache/nginx/vk-env-private/value)" = writable
        export EXPECTED="$MULTI"
        unset MULTI
        /bin/sh -lc '\''
            set -eu
            test "$MULTI" = "$EXPECTED"
            test ! -e /virtkit-service.json
            test ! -r /run/vk/env.json
            echo "plain non-root login environment: PASS"
        '\''
    '
done

# Keep the image entrypoint as PID 1 and use the reparented agent for exec and SSH.
work=$(mktemp -d)
cleanup() {
    # A failed boot may not have registered a VM yet.
    "$VK" stop "$work/vm" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
"$VK" run -f run-env/Dockerfile --context run-env --target fullvm --init entrypoint --kernel default \
    --env "MULTI=$multi" --env "EXPECTED=$multi" --ssh-client --state-dir "$work/vm" --detach \
    -- sleep infinity
"$VK" exec "$work/vm" -- sh -c '
    set -eu
    for i in $(seq 1 30); do
        test "$(cat /proc/1/comm)" = sleep && break
        sleep 1
    done
    test "$(cat /proc/1/comm)" = sleep
    test "$(stat -f -c %T /run)" = tmpfs
    test "$(stat -c %u:%g /etc/profile.d)" = 0:65534
    test "$(stat -c %u:%g /etc/profile.d/private)" = 0:65534
    unset MULTI IMAGE_ONLY
    /bin/bash -lc '\''
        set -eu
        test "$MULTI" = "$EXPECTED"
        test "$IMAGE_ONLY" = from-image
        test "$(image-tool)" = image-path-ok
        echo "full-VM login environment: PASS"
    '\''
'
"$VK" ssh "$work/vm" -- /bin/bash -l -s <<'GUEST'
set -eu
case "$PATH" in /opt/image/bin:*) ;; *) exit 1 ;; esac
unset MULTI IMAGE_ONLY
. /etc/profile.d/zz-virtkit-env.sh
test "$MULTI" = "$EXPECTED"
test "$IMAGE_ONLY" = from-image
GUEST
"$VK" exec "$work/vm" -- sh -c '
    set -eu
    umask 077
    printf "PATH=/session/bin:/usr/bin:/bin\n" >/run/virtkit-session-env
'
"$VK" ssh "$work/vm" -- /bin/bash -l -s <<'GUEST'
set -eu
test "$PATH" = /session/bin:/usr/bin:/bin
. /etc/profile.d/zz-virtkit-env.sh
test "$PATH" = /session/bin:/usr/bin:/bin
echo "SSH login PATH: PASS"
GUEST
