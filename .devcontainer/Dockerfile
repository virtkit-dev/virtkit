# Official Rust Alpine image (musl-native), pinned by digest for reproducible
# builds. Tag and digest are kept in sync with rust-toolchain.toml by update.sh.
# Alpine (not Debian) so the bundled virtiofsd can link the static libseccomp /
# libcap-ng that Alpine ships as packages — Debian has no musl-static build of them.
FROM rust:1.96.0-alpine3.21@sha256:7dba3db75b0d5861af2e5dcf5b87347411e84403b5c9835be00ef1e72e299d2a

# Build deps (one per line in apk-pins.txt, pinned to exact versions for byte-for-byte
# reproducibility — Alpine has no snapshot service, so the pins + the image digest
# above are what freeze the inputs; regenerate with ./update.sh):
#   gcc + musl-dev          ring (rustls' crypto backend) compiles C; Alpine's gcc
#                           is musl-native, so it is also the musl C compiler.
#   libseccomp-static/-dev  the static FFI libs the bundled virtiofsd links
#   libcap-ng-static/-dev   (LIB*_LINK_TYPE=static in build.sh).
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
