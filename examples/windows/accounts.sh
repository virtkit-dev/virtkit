#!/bin/sh
# Create the lab's users ($LAB_USERS, space-separated) in the DC's domain unless they exist,
# with the password in the user_password secret and no expiry, then its groups ($LAB_GROUPS,
# space-separated `group:member,member`) with those members. samba-tool talks LDAP to the DC
# ($LAB_DC, a service name) as vkjoin, the lab's admin account ($LAB_NETBIOS\vkjoin, CORP by
# default; password in the join_password secret), over NTLM with signing and sealing: a
# Windows Server 2025 DC requires signed LDAP, and a password is only set over an encrypted
# connection.
set -eu

dc=$(getent hosts "$LAB_DC" | awk '{ print $1; exit }')
[ -n "$dc" ] || { echo "$LAB_DC does not resolve" >&2; exit 1; }
netbios=${LAB_NETBIOS:-CORP}
admin_password=$(cat /run/secrets/join_password)
user_password=$(cat /run/secrets/user_password)

tool() {
    timeout 60 samba-tool "$@" -H "ldap://$dc" -U "$netbios\\vkjoin" \
        --password="$admin_password" --use-kerberos=off
}

# The DC answers its healthcheck once the DC locator finds it; give LDAP a moment more.
i=0
until out=$(tool user list 2>&1); do
    i=$((i + 1))
    echo "LDAP to $LAB_DC ($dc) not answering yet: $(echo "$out" | grep ERROR | tail -1)" >&2
    [ "$i" -lt 90 ] || exit 1
    sleep 2
done

for user in ${LAB_USERS:-}; do
    # The members look each name up in an LDAP filter (join.ps1): letters and digits only.
    case $user in *[!a-z0-9]*) echo "user name '$user': letters and digits only" >&2; exit 1 ;; esac
    if tool user show "$user" >/dev/null 2>&1; then
        echo "user $user exists"
    else
        tool user create "$user" "$user_password" >/dev/null
        tool user setexpiry "$user" --noexpiry >/dev/null
        echo "user $user created"
    fi
done

for spec in ${LAB_GROUPS:-}; do
    group=${spec%%:*}
    members=${spec#*:}
    if ! tool group show "$group" >/dev/null 2>&1; then
        tool group add "$group" >/dev/null
        echo "group $group created"
    fi
    [ "$members" = "$spec" ] || tool group addmembers "$group" "$members" >/dev/null
    echo "group $group has $members"
done
