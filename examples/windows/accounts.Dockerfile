# The labs' accounts job (accounts.sh) creates a domain's users and groups with samba-tool
# over LDAP to its DC, then ends. Members wait for this Linux service to finish.
# python3-setproctitle keeps the admin password out of the process list.
# samba-dsdb-modules carries Samba's LDAP backend (ildap), which binds with samba-tool's
# credentials; without it, ldap:// goes to libldb's OpenLDAP backend, which binds anonymously.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-samba python3-setproctitle samba-common-bin \
      samba-dsdb-modules \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/samba && touch /etc/samba/smb.conf
COPY accounts.sh /usr/local/bin/accounts
CMD ["/usr/local/bin/accounts"]
