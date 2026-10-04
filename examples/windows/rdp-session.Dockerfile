# The client of rdp-session.compose.yaml: FreeRDP on an X server of its own (Xvfb), with xwd and
# ImageMagick to capture what the session shows.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends freerdp3-x11 xvfb x11-apps imagemagick netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY rdp-session.sh /usr/local/bin/rdp-session
CMD ["rdp-session"]
