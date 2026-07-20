# Official Rust Alpine image (musl-native), pinned by digest for reproducible
# builds. Tag and digest are kept in sync with rust-toolchain.toml by update.sh.
# Alpine (not Debian) for a musl-native gcc: the C our deps vendor (ring, zstd,
# jemalloc) then targets musl directly. No system C libraries are linked.
# Named so a file-merge build can reference it as a base stage (kernel/Dockerfile's
# `FROM virtkit-build`) — the `vk` backend of build.sh/build-kernel.sh has no docker image
# tags, so it resolves the base by stage name across merged -f files. Docker builds still
# tag the image `virtkit-build` via -t; the two namespaces are independent.
FROM rust:1.97.1-alpine3.21@sha256:7bae7c67364dad5ebbd4060923b34d734fbed66d7c1cf3af72aa2f062af93eb6 AS virtkit-build

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

# cargo-audit for audit.sh (RUSTSEC advisory scan). Not a rustup component, so install the
# pinned version as a binary; --locked builds it from its published Cargo.lock so the image
# stays reproducible. Lands in CARGO_HOME/bin (on PATH) and is chowned to dev below.
RUN cargo install cargo-audit --locked --version 0.22.2

# Non-root dev user owning the cargo/rustup homes so it can populate the registry
# cache and honour rust-toolchain.toml without root.
ARG USERNAME=dev
RUN adduser -D -s /bin/sh "${USERNAME}" \
 && chown -R "${USERNAME}": "${CARGO_HOME}" "${RUSTUP_HOME}"
USER ${USERNAME}
