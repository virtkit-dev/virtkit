# The build image: the pinned toolchain every release build, CI lint, audit and dev VM runs in.
# build.sh / build-kernel.sh / dev.sh / audit.sh / sweep.sh build this file
# (docker build, or `vk run --file`) and run their command inside it.
#
# Two pins freeze the inputs, and both are archival:
#   - the base: the official nixos/nix image, by manifest-list digest below — a public Docker
#     Hub image pulled like any other base, nothing is pushed anywhere;
#   - the packages: nix/flake.nix + nix/flake.lock (nixpkgs by commit). `nix build` runs
#     INSIDE this image at build time to realize that closure, so the host needs no Nix,
#     only docker or vk. Sources are content-addressed: the same lock rebuilds the exact
#     toolchain years later, from cache.nixos.org or from source.
# The previous rust:alpine base was dropped because Alpine keeps no package archive — its
# pinned apk versions vanish from the CDN and the build stops being rebuildable.
#
# Named so kernel/Dockerfile can chain onto it as a base stage (`FROM virtkit-build`) in the
# -f merge build-kernel.sh does for the vk backend; Docker builds tag it via -t.

# nixos/nix 2.35.2 by manifest-list digest. ./update.sh refreshes it
# (`docker buildx imagetools inspect nixos/nix:<ver>` -> Digest).
FROM nixos/nix:2.35.2@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c AS virtkit-build

# Flakes are gated behind experimental-features on the stock image, and the Nix sandbox
# needs user namespaces neither Docker's builder nor vk's give it.
RUN mkdir -p /etc/nix \
 && printf 'experimental-features = nix-command flakes\nsandbox = false\n' >> /etc/nix/nix.conf

# The flake is self-contained: it pins the Rust channel inline (kept in step with
# rust-toolchain.toml by ./update.sh) rather than reading that file, which sits outside this
# build context. flake.lock is the archival pin — it is always committed alongside.
COPY nix /src/nix

# Realize the toolchain closure — rust + musl cross gcc + host gcc + mold + make + git +
# cargo-audit/-sweep + busybox sh — into /opt/toolchain. The analogue of an `apk add`.
RUN nix build "path:/src/nix#buildEnv" --out-link /opt/toolchain

# PATH prepends /opt/toolchain/bin to the base image's own (nix's profile dirs, spelled out
# because the base is pinned): kernel/Dockerfile chains `FROM virtkit-build` and still needs
# `nix` to install its closure. SSL_CERT_FILE lets cargo reach crates.io as any uid — the
# scripts run as the host user with HOME=/tmp. Which compilers cargo uses for the musl
# target is declared in .cargo/config.toml, not here.
ENV PATH=/opt/toolchain/bin:/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/nix/var/nix/profiles/default/sbin \
    SSL_CERT_FILE=/opt/toolchain/etc/ssl/certs/ca-bundle.crt

# `dev` (uid 1000, the usual first host user): dev.sh execs into its VM as this user and
# devcontainer.json opens the workspace as it. The base ships no adduser; a passwd line is
# all a user is. /tmp is world-writable for the HOME=/tmp the scripts pass.
RUN printf 'dev:x:1000:1000:dev:/home/dev:/bin/sh\n' >> /etc/passwd \
 && printf 'dev:x:1000:\n' >> /etc/group \
 && mkdir -p /home/dev && chown 1000:1000 /home/dev \
 && chmod 1777 /tmp
