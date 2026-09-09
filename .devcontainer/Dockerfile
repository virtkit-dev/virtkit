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

# `dev`: devcontainer.json opens the workspace as it, and so does `vk dev` (.virtkit/config.toml).
# The rootless virtio-fs share lets root and the host owner's ids write /work and nothing else:
# the vk backend compiles as root, and `vk dev` runs as the non-root `dev` user, so that user is
# built with the host ids (DEV_UID/DEV_GID). build.sh passes no build args, so the release
# keeps the 1000/1000 defaults and its shipped binaries stay byte-identical. dev.sh does not
# use this user; it execs as the host ids directly. The base ships no adduser; a passwd line
# is all a user is. /tmp is
# world-writable for the HOME=/tmp the scripts pass.
ARG DEV_UID=1000
ARG DEV_GID=1000
RUN printf 'dev:x:%s:%s:dev:/home/dev:/bin/sh\n' "$DEV_UID" "$DEV_GID" >> /etc/passwd \
 && printf 'dev:x:%s:\n' "$DEV_GID" >> /etc/group \
 && mkdir -p /home/dev && chown "$DEV_UID:$DEV_GID" /home/dev \
 && chmod 1777 /tmp

# VS Code Remote-SSH downloads prebuilt, glibc-linked binaries (the server's node,
# rust-analyzer) into ~/.vscode-server after connecting. They carry no RPATH and expect
# an FHS system: the interpreter at /lib64/ld-linux-x86-64.so.2 and libstdc++ & co. on the
# loader's default search path. The nixos/nix base has neither, so Remote-SSH reports the
# host "does not meet the prerequisites for running VS Code Server".
#
# Fix, the NixOS way (programs.nix-ld): /lib64/ld-linux-x86-64.so.2 is nix-ld, a shim that
# execs the real glibc loader (NIX_LD) with NIX_LD_LIBRARY_PATH as the library search path.
# Both come from nix/flake.nix#fhsRuntime. Only foreign binaries name that interpreter, so the
# nix-store toolchain (its own store loader + RPATH) and the static musl release build are
# untouched, and the two variables are inert for them — unlike a global LD_LIBRARY_PATH.
# nixpkgs' glibc is NOT an option as the loader itself: its ld.so and ldconfig are patched to
# read <glibc-store-path>/etc/ld.so.cache, never /etc/ld.so.cache, so no ld.so.conf/ldconfig
# setup in the image can teach it where libstdc++ is.
#
# The CLI's prerequisites probe (vscode cli/src/util/prereqs.rs) needs, on x86_64:
# `ldd --version` on PATH >= 2.28 (the toolchain's glibc ldd, already there) and a
# /usr/lib64/libstdc++.so.6 to scan for GLIBCXX_ tags — it tries that exact path before
# falling back to `/sbin/ldconfig -p`, which nixpkgs' ldconfig cannot serve for the same
# cache-path reason. Hence the one symlink.
RUN nix build "path:/src/nix#fhsRuntime" --out-link /opt/fhs \
 && test -x /opt/fhs/libexec/nix-ld \
 && test -x /opt/fhs/lib/ld-linux-x86-64.so.2 \
 && test -e /opt/fhs/lib/libstdc++.so.6 \
 && mkdir -p /lib64 /usr/lib64 \
 && ln -sf /opt/fhs/libexec/nix-ld /lib64/ld-linux-x86-64.so.2 \
 && ln -sf /opt/fhs/lib/libstdc++.so.6 /usr/lib64/libstdc++.so.6
# `vk dev` and devcontainers hand the image environment to every guest session, ssh included,
# which is how these reach the server the Remote-SSH install script spawns.
ENV NIX_LD=/opt/fhs/lib/ld-linux-x86-64.so.2 \
    NIX_LD_LIBRARY_PATH=/opt/fhs/lib
