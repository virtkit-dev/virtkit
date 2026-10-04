#!/bin/sh
# Open a full Remote Desktop session to $RDP_SERVER as $RDP_USER (password in the user_password
# secret): FreeRDP connects with Network Level Authentication, its window on this job's own X
# server. Once the remote desktop has drawn, capture the screen to /out/session-logon.png and log
# "rdp session open"; a minute later, past the sign-in, capture it again to /out/session.png and
# log "rdp session captured". Hold the session for $RDP_HOLD seconds in all (default 300), then
# end. The password is on FreeRDP's command line (/p:), visible in this job's process list:
# /from-stdin would prompt on /dev/tty when the job has one.
set -eu
password=$(cat /run/secrets/user_password)
hold=${RDP_HOLD:-300}
address=$(getent hosts "$RDP_SERVER" | awk '{ print $1; exit }')
[ -n "$address" ] || { echo "rdp session: $RDP_SERVER does not resolve" >&2; exit 1; }
i=0
until nc -z -w 5 "$address" 3389; do
    i=$((i + 1)); [ "$i" -lt 120 ] || { echo "rdp session: port 3389 closed" >&2; exit 1; }
    sleep 5
done

export DISPLAY=:99
Xvfb :99 -screen 0 1280x800x24 -nolisten tcp &
sleep 2
xfreerdp3 /v:"$address" /u:"$RDP_USER" /p:"$password" /cert:ignore /sec:nla /size:1024x768 \
    /log-level:WARN > /tmp/freerdp.log 2>&1 &
rdp=$!

# The desktop has drawn once the screen holds more than a handful of colours; FreeRDP exiting
# first is a failed session.
i=0
while :; do
    kill -0 "$rdp" 2>/dev/null || { tail -20 /tmp/freerdp.log >&2; echo "rdp session: FreeRDP exited" >&2; exit 1; }
    colours=$(xwd -root -silent | convert xwd:- -format %k info: 2>/dev/null || echo 0)
    colours=${colours:-0}
    colours=${colours:-0}
    [ "$colours" -gt 16 ] && break
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "rdp session: nothing drawn after 5 minutes" >&2; exit 1; }
    sleep 5
done
mkdir -p /out
xwd -root -silent | convert xwd:- /out/session-logon.png
echo "rdp session open: $RDP_USER on $RDP_SERVER, the screen shows $colours colours"

sleep 60
kill -0 "$rdp" 2>/dev/null || { tail -20 /tmp/freerdp.log >&2; echo "rdp session: dropped after sign-in" >&2; exit 1; }
xwd -root -silent | convert xwd:- /out/session.png
echo "rdp session captured: /out/session.png"

sleep "$((hold > 60 ? hold - 60 : 0))"
kill -0 "$rdp" 2>/dev/null || { tail -20 /tmp/freerdp.log >&2; echo "rdp session: dropped while held" >&2; exit 1; }
kill "$rdp"
echo "rdp session closed after ${hold}s"
