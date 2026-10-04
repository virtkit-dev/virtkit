# The labs' RDP check: a Linux job that signs in over RDP to each machine of a lab
# (rdp-check.sh), with Network Level Authentication and without opening a desktop, then ends.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends freerdp3-x11 xvfb xauth netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
COPY rdp-check.sh /usr/local/bin/rdp-check
CMD ["/usr/local/bin/rdp-check"]
