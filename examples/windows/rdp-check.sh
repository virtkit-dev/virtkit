#!/bin/sh
# Sign in over RDP to each of $RDP_TARGETS (space-separated `service:DOMAIN\user`): the port
# answers, then FreeRDP authenticates the account with Network Level Authentication and stops
# there (/auth-only), so no desktop opens. FreeRDP's own verdict is no use (it reports "exit
# status 0" for a refused password too), so the check reads NLA's states in its debug log: an
# account is signed in once CredSSP reached its final state (the credentials accepted and
# delegated), and refused on STATUS_LOGON_FAILURE. vkjoin's password is in the join_password
# secret, every other account's in user_password. Fails on the first machine that refuses.
# The password is on FreeRDP's command line (/p:), visible in this job's process list:
# /from-stdin would prompt on /dev/tty when the job has one.
set -eu

join_password=$(cat /run/secrets/join_password)
user_password=$(cat /run/secrets/user_password 2>/dev/null || true)

for target in $RDP_TARGETS; do
    host=${target%%:*}
    account=${target#*:}
    domain=${account%%\\*}
    user=${account#*\\}
    if [ "$user" = vkjoin ]; then password=$join_password; else password=$user_password; fi
    address=$(getent hosts "$host" | awk '{ print $1; exit }')
    [ -n "$address" ] || { printf 'rdp %s: does not resolve\n' "$host" >&2; exit 1; }
    i=0
    until nc -z -w 5 "$address" 3389; do
        i=$((i + 1))
        [ "$i" -lt 30 ] || { printf 'rdp %s: port 3389 closed\n' "$host" >&2; exit 1; }
        sleep 2
    done
    # A few tries, for a machine that has only just come up.
    i=0
    until out=$(timeout 90 xvfb-run -a xfreerdp3 /v:"$address" /d:"$domain" /u:"$user" \
            /p:"$password" /cert:ignore /sec:nla /auth-only /log-level:DEBUG 2>&1 || true)
        printf '%s\n' "$out" | grep -q 'NLA_STATE_FINAL' &&
            ! printf '%s\n' "$out" | grep -q 'LOGON_FAILURE'; do
        i=$((i + 1))
        if [ "$i" -ge 5 ]; then
            printf '%s\n' "$out" | grep -E 'ERROR|error code' | tail -5 >&2
            printf 'rdp %s: %s\\%s refused\n' "$host" "$domain" "$user" >&2
            exit 1
        fi
        sleep 15
    done
    printf 'rdp %s: %s\\%s signed in\n' "$host" "$domain" "$user"
done
