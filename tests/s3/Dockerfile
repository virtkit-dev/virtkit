# The S3 clients tests/s3-e2e.sh drives against vk-registry's /s3/: sccache, the AWS CLI and
# rclone, plus gcc for sccache to wrap. No credential is baked in: the script passes keys and
# the run's CA at run time.
#
# The digest is trixie-slim's multi-platform index on Docker Hub, read with
#   docker manifest inspect -v debian:trixie-slim   (or, without docker, the
#   Docker-Content-Digest of GET registry-1.docker.io/v2/library/debian/manifests/trixie-slim)
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# awscli 2.23 and rclone 1.60 from trixie.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      awscli rclone gcc libc6-dev ca-certificates coreutils curl \
 && rm -rf /var/lib/apt/lists/*
# trixie's sccache (0.10) is built without its S3 backend, so the upstream static release,
# checked against the sha256 published beside it.
ARG SCCACHE_VERSION=0.18.0
ARG SCCACHE_SHA256=45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89
RUN cd /tmp \
 && t=sccache-v$SCCACHE_VERSION-x86_64-unknown-linux-musl \
 && curl -fsSLO https://github.com/mozilla/sccache/releases/download/v$SCCACHE_VERSION/$t.tar.gz \
 && echo "$SCCACHE_SHA256  $t.tar.gz" | sha256sum -c - \
 && tar xzf $t.tar.gz $t/sccache \
 && install -m 0755 $t/sccache /usr/local/bin/sccache \
 && rm -rf $t $t.tar.gz
