# The microVM guest kernel (vmlinux): vanilla Linux + kernel/patches/ + a vendored config fragment
# (kernel-fragment.config — kata's non-confidential x86_64 set: virtio blk/net/vsock/pci
# + ext4 + virtio-fs/FUSE + IP autoconfig, all built in, CONFIG_MODULES off) + virtkit's
# removals overlay (kernel-removals.config — drops options virtkit never uses:
# Mellanox/VFIO/SGX/NVDIMM/CIFS/9p/XFS/SCSI/FIPS, debug, exotic netfilter, CPU-freq/
# thermal/NUMA, and WireGuard/IPsec/VXLAN/tunnels — networking is host-side via the
# switch, and jobs needing those ship their own per-bundle kernel). The result is the
# pinned vmlinux a generic guest boots — no per-image kernel, initrd or modules.
#
# Built in the SAME image as the binaries (virtkit-build, the .devcontainer Nix image —
# base digest- and flake.lock-pinned, and it carries the rust toolchain recent kernels want
# for CONFIG_RUST). So the base is frozen; with the pinned kernel-build deps below + fixed
# KBUILD_BUILD_* the build is reproducible. build-kernel.sh builds virtkit-build first.
FROM virtkit-build AS build
USER root

ARG KERNEL_VERSION=6.18.49
# Primary source: the pinned tarball from cdn.kernel.org, integrity-checked against this
# sha256. https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc
ARG KERNEL_SHA256=ae826f33111fea6f1d279dde7299d7463c8dfd204aeb75a8fb5432bc60a28191
# Fallback source (used automatically when the CDN is unavailable): the PGP-signed stable
# git tag v${KERNEL_VERSION} on the gregkh/linux GitHub mirror. KERNEL_COMMIT is the
# immutable commit that signed tag resolves to; verified below against Greg KH's vendored
# signing key (kernel-signing-key.asc).
ARG KERNEL_COMMIT=1c732c6b94f0faee1526bd375add2fe10cba2e26

# Kernel build deps on top of the shared image: the `kernelBuildEnv` closure of the same
# flake (already at /src/nix in the base stage; `nix` is on its PATH). gcc/binutils here are
# the kernel's own C toolchain — a plain glibc gcc, NOT the musl cross gcc the Rust build
# uses; the kernel links no libc. Its /bin goes first so `cc`/`gcc`/`ld` resolve to it, ahead
# of the Rust toolchain. coreutils/findutils/diffutils/sed/grep are the GNU tools the kernel
# build expects. PKG_CONFIG_PATH: tools/objtool asks `pkg-config libelf` for its -I/-l, and
# the nixpkgs gcc wrapper searches no /opt paths on its own — scoped to pkg-config, so the
# kernel's own -nostdinc compiles see nothing extra.
RUN nix build "path:/src/nix#kernelBuildEnv" --out-link /opt/kernel-toolchain
ENV PATH=/opt/kernel-toolchain/bin:/opt/toolchain/bin:/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/nix/var/nix/profiles/default/sbin \
    SSL_CERT_FILE=/opt/kernel-toolchain/etc/ssl/certs/ca-bundle.crt \
    PKG_CONFIG_PATH=/opt/kernel-toolchain/lib/pkgconfig

WORKDIR /build
# Fetch the kernel source. Primary path: the pinned tarball from cdn.kernel.org, verified
# against KERNEL_SHA256. Fallback (taken automatically when the download or the checksum
# fails — e.g. a kernel.org mirror outage): clone the PGP-signed stable git tag from the
# gregkh/linux GitHub mirror, verify its signature against Greg KH's vendored key, and
# confirm it resolves to KERNEL_COMMIT. Both paths leave the source at linux-${KERNEL_VERSION}.
COPY kernel-signing-key.asc /tmp/kernel-signing-key.asc
RUN set -e; \
    if curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz" \
       && echo "${KERNEL_SHA256}  linux-${KERNEL_VERSION}.tar.xz" | sha256sum -c; then \
        tar xf "linux-${KERNEL_VERSION}.tar.xz"; \
        rm "linux-${KERNEL_VERSION}.tar.xz"; \
    else \
        echo "cdn.kernel.org unavailable — falling back to the signed git tag" >&2; \
        rm -f "linux-${KERNEL_VERSION}.tar.xz"; \
        export GNUPGHOME="$(mktemp -d)"; \
        gpg --batch --quiet --import /tmp/kernel-signing-key.asc; \
        git clone --quiet --depth 1 --branch "v${KERNEL_VERSION}" \
            https://github.com/gregkh/linux.git "linux-${KERNEL_VERSION}"; \
        git -C "linux-${KERNEL_VERSION}" verify-tag "v${KERNEL_VERSION}"; \
        test "$(git -C "linux-${KERNEL_VERSION}" rev-parse HEAD)" = "${KERNEL_COMMIT}"; \
        rm -rf "linux-${KERNEL_VERSION}/.git" "$GNUPGHOME"; \
    fi; \
    rm -f /tmp/kernel-signing-key.asc

COPY kernel-fragment.config /build/kernel-fragment.config
# Removals overlay: base-config options virtkit does not use. Merged AFTER the
# base fragment so it overrides those defaults (see kernel-removals.config).
COPY kernel-removals.config /build/kernel-removals.config

WORKDIR /build/linux-${KERNEL_VERSION}
# Local patches on top of the pinned vanilla source, applied with -p1 in lexical order.
# Keep them few, each documented in its own header, and preferably on their way
# upstream — every KERNEL_VERSION bump must re-check that they still apply and are
# still needed. `git apply` is the applier (git is a pinned build dep; `patch` is not).
COPY patches/ /build/patches/
RUN set -e; for p in /build/patches/*.patch; do \
        echo "applying $(basename "$p")"; git apply --verbose -p1 "$p"; \
    done

# Reproducible build metadata: no current date / user@host baked into the kernel banner.
ENV KBUILD_BUILD_TIMESTAMP="@0" KBUILD_BUILD_USER=virtkit KBUILD_BUILD_HOST=virtkit \
    SOURCE_DATE_EPOCH=0
# allnoconfig + the config fragment + virtkit's removals, then let kconfig resolve
# dependencies. Verify before the (long) compile that the load-bearing options survived
# AND that the removed options stayed disabled (olddefconfig can resurrect a symbol that
# something still selects) — so either failure is loud here, not at boot.
RUN export ARCH=x86_64 \
    && scripts/kconfig/merge_config.sh -n /build/kernel-fragment.config /build/kernel-removals.config \
    && make ARCH=x86_64 olddefconfig \
    && for opt in CONFIG_64BIT CONFIG_SMP CONFIG_EXT4_FS CONFIG_VIRTIO_BLK \
                  CONFIG_VIRTIO_NET CONFIG_VIRTIO_PCI CONFIG_VIRTIO_VSOCKETS \
                  CONFIG_VIRTIO_FS CONFIG_FUSE_FS CONFIG_IP_PNP CONFIG_OVERLAY_FS \
                  CONFIG_BLK_DEV_INITRD CONFIG_DEVTMPFS_MOUNT \
                  CONFIG_KVM CONFIG_KVM_INTEL CONFIG_KVM_AMD CONFIG_KVM_IOAPIC \
                  CONFIG_ACPI CONFIG_ACPI_BUTTON CONFIG_INPUT_EVDEV \
                  CONFIG_DUMMY CONFIG_IPV6 CONFIG_WIREGUARD; do \
           grep -q "^${opt}=y" .config || { echo "missing ${opt}=y in .config"; exit 1; }; \
       done \
    && for opt in CONFIG_MLX5_CORE CONFIG_VFIO CONFIG_X86_SGX CONFIG_VIRTIO_PMEM \
                  CONFIG_CIFS CONFIG_NET_9P CONFIG_XFS_FS CONFIG_CRYPTO_FIPS \
                  CONFIG_SCSI CONFIG_DEBUG_FS CONFIG_IP_VS CONFIG_IP_SET \
                  CONFIG_NETFILTER_XT_MATCH_RECENT CONFIG_CPU_FREQ \
                  CONFIG_NUMA CONFIG_VIRTIO_MEM CONFIG_XFRM \
                  CONFIG_VXLAN; do \
           grep -q "^${opt}=y" .config && { echo "removed option ${opt} resurrected by olddefconfig"; exit 1; } || true; \
       done \
    && make ARCH=x86_64 -j"$(nproc)" vmlinux \
    && strip --strip-all vmlinux \
    && cp vmlinux /build/vmlinux
# Keep the resolved config for provenance / auditing (separate layer, so it does not
# invalidate the compile cache): `docker build --target config` extracts it.
RUN cp .config /build/kernel.config

FROM scratch AS artifact
COPY --from=build /build/vmlinux /vmlinux

FROM scratch AS config
COPY --from=build /build/kernel.config /kernel.config
