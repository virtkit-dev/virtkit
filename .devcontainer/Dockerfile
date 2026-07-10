# Official Rust Alpine image (musl-native), pinned by digest for reproducible
# builds. Tag and digest are kept in sync with rust-toolchain.toml by update.sh.
# Alpine (not Debian) for a musl-native gcc: the C our deps vendor (ring, zstd,
# jemalloc) then targets musl directly. No system C libraries are linked.
# Named so a file-merge build can reference it as a base stage (kernel/Dockerfile's
# `FROM virtkit-build`) — the `vk` backend of build.sh/build-kernel.sh has no docker image
# tags, so it resolves the base by stage name across merged -f files. Docker builds still
# tag the image `virtkit-build` via -t; the two namespaces are independent.
FROM rust:1.97.0-alpine3.21@sha256:8a34d94926e597c8755508a468ece234b6dbbe21d80c28ed77630f21e4b8e987 AS virtkit-build

# Build deps (one per line in apk-pins.txt, pinned to exact versions for byte-for-byte
# reproducibility — Alpine has no snapshot service, so the pins + the image digest
# above are what freeze the inputs; regenerate with ./update.sh):
#   gcc + musl-dev          ring (rustls' crypto backend) compiles C; Alpine's gcc
#                           is musl-native, so it is also the musl C compiler.
#   git, ca-certificates, file   dev/build basics.
COPY apk-pins.txt /tmp/apk-pins.txt
RUN apk add --no-cache $(grep -vE '^[[:space:]]*(#|$)' /tmp/apk-pins.txt)

# Lint/format components; x86_64-unknown-linux-musl is the native target on Alpine,
# so no `rustup target add`. Versions follow rust-toolchain.toml.
RUN rustup component add clippy rustfmt

# Non-root dev user owning the cargo/rustup homes so it can populate the registry
# cache and honour rust-toolchain.toml without root.
ARG USERNAME=dev
RUN adduser -D -s /bin/sh "${USERNAME}" \
 && chown -R "${USERNAME}": "${CARGO_HOME}" "${RUSTUP_HOME}"
USER ${USERNAME}
