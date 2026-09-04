{
  # The build toolchain: the closures .devcontainer/Dockerfile (`buildEnv`) and
  # kernel/Dockerfile (`kernelBuildEnv`) install. Lives under .devcontainer/nix/ so it sits
  # inside the Docker/vk build CONTEXT (.devcontainer): the Dockerfile's `COPY nix /src/nix`
  # resolves here.
  #
  # `buildEnv` provides, for the static-musl release build:
  #   - Rust (channel pinned inline — ./update.sh keeps it in step with rust-toolchain.toml;
  #     see the note at rustToolchain) with the x86_64-unknown-linux-musl target + clippy/rustfmt;
  #   - a musl cross gcc for the vendored C in ring / zstd-sys / jemalloc-sys, and a host gcc
  #     for build scripts and proc-macros (.cargo/config.toml names which is used where);
  #   - mold, make, git, ca-certificates, file, cargo-audit, cargo-sweep, the dev search tools.
  #
  # Everything is pinned by flake.lock (nixpkgs by git rev), so the inputs are
  # rebuildable-from-source years later. cache.nixos.org serves the binaries; if it ever
  # went away, the same lock rebuilds them from content-addressed sources. Nix runs only
  # INSIDE the build image (a `RUN nix build` at image-build time) — no Nix on any host.
  #
  # Verified: `./build-kernel.sh` builds vmlinux, and `./build.sh --bootstrap-check` passes —
  # the Docker build and a from-scratch vk microVM rebuild produce byte-identical binaries.
  #
  # On a host with Nix:  nix develop ./.devcontainer/nix    (the same toolchain, interactively)
  #                      nix build ./.devcontainer/nix#buildEnv

  inputs = {
    # Pin nixpkgs by a specific commit for reproducibility. `nix flake update` bumps it
    # and rewrites flake.lock; a release pins the lock the same way Cargo.lock is pinned.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Exact toolchain: channel 1.98.0, musl target, clippy + rustfmt. Kept in sync
        # with ../rust-toolchain.toml by hand. Reading that file directly (rust-overlay's
        # fromRustupToolchainFile) would require the flake at the repo ROOT — a flake
        # cannot read `..` outside its own dir in pure eval — so with the flake under
        # .devcontainer/nix/ the channel is inline. Moving flake.nix to the repo root would
        # let it be single-sourced from rust-toolchain.toml.
        rustToolchain = pkgs.rust-bin.stable."1.98.0".default.override {
          extensions = [ "clippy" "rustfmt" ];
          targets = [ muslTarget ];
        };

        muslTarget = "x86_64-unknown-linux-musl";

        # The crux of the migration: the vendored C (ring, zstd, jemalloc) must be compiled
        # for musl, exactly as Alpine's musl-native gcc does today. On a glibc host we point
        # cargo's cc-crate at a musl-targeting compiler for that target triple only; rustc
        # itself runs from the (glibc) host toolchain and cross-compiles the Rust to musl.
        muslPkgs = pkgs.pkgsCross.musl64;
        muslCC = "${muslPkgs.stdenv.cc}/bin/${muslPkgs.stdenv.cc.targetPrefix}cc";
        muslAR = "${muslPkgs.stdenv.cc.bintools.bintools}/bin/${muslPkgs.stdenv.cc.targetPrefix}ar";

        # The build tools. busybox supplies the `sh` that build.sh's
        # `docker run ... sh -c "$BUILD_CMD"` invokes.
        buildTools = with pkgs; [
          rustToolchain
          mold          # the linker every build.sh/dev.sh link runs through
          gnumake       # jemalloc-sys builds vendored jemalloc through it
          git
          cacert
          file
          ugrep         # dev.sh VM source search
          bfs
          busybox
          cargo-audit   # audit.sh (RUSTSEC scan)
          cargo-sweep   # sweep.sh (reclaim stale target/)
          # clippy + rustfmt come with rustToolchain.
          # The musl cross cc: `x86_64-unknown-linux-musl-{cc,gcc,ar,...}` land in the merged
          # /bin. .cargo/config.toml points CC_<triple> (the vendored C in ring/zstd/jemalloc)
          # and the musl target's linker at it, so nothing musl goes through the glibc driver.
          muslPkgs.stdenv.cc
          # A HOST (glibc) cc as well: cargo compiles build scripts and proc-macros for the
          # host triple and rustc links those with plain `cc`. Unprefixed `cc`/`gcc`/`ld` — no
          # clash with the prefixed musl set above.
          stdenv.cc
        ];

        # One merged prefix so a single PATH exposes the whole toolchain in the image.
        # /etc is linked too so cacert's ca-bundle.crt lands at <env>/etc/ssl/certs/... —
        # the SSL_CERT_FILE the image bakes (buildEnv links only /bin by default).
        binEnv = pkgs.buildEnv {
          name = "virtkit-build-bin";
          paths = buildTools;
          pathsToLink = [ "/bin" "/etc" "/lib" "/libexec" ];
        };

        # Env that mirrors build.sh's reproducibility knobs. The path-remap prefixes and
        # SOURCE_DATE_EPOCH are the same idea; the CC_* override is what replaces "Alpine
        # ships a musl gcc as the system cc".
        commonEnv = {
          "CC_${builtins.replaceStrings ["-"] ["_"] muslTarget}" = muslCC;
          "AR_${builtins.replaceStrings ["-"] ["_"] muslTarget}" = muslAR;
          CARGO_BUILD_TARGET = muslTarget;
          RUSTFLAGS = "-C link-arg=-fuse-ld=mold";
          SOURCE_DATE_EPOCH = "0";
        };
      in
      {
        # `nix develop ./nix` — an interactive shell equivalent to the build image.
        devShells.default = pkgs.mkShell (commonEnv // {
          packages = buildTools;
          shellHook = ''
            echo "virtkit nix devShell — rust $(rustc --version), musl cc: ${muslCC}"
          '';
        });

        # The whole toolchain as ONE closure with a merged /bin. .devcontainer/Dockerfile
        # realizes it INSIDE the nixos/nix base image (`nix build .#buildEnv --out-link
        # /opt/toolchain`) and puts it on PATH — stable /opt/toolchain paths, so no store
        # hashes leak into the Dockerfile. No image is built or pushed by Nix itself.
        packages.buildEnv = binEnv;

        # The kernel-build deps, installed on top of the build image by kernel/Dockerfile
        # (`FROM virtkit-build`). gcc/binutils are the kernel's own C toolchain here — NOT the
        # musl cross cc the Rust build uses; the kernel links no libc, so a glibc gcc builds it.
        packages.kernelBuildEnv = pkgs.buildEnv {
          name = "virtkit-kernel-bin";
          pathsToLink = [ "/bin" "/etc" "/lib" "/include" ];
          paths = with pkgs; [
            gcc binutils gnumake          # cc / ld / objcopy + make
            bc bison flex                 # kconfig + timeconst
            perl rsync cpio xz            # headers_install, initramfs tooling, tarball xz
            elfutils elfutils.dev         # objtool links libelf; headers + libelf.pc are in .dev
            pkg-config zlib.dev zstd.dev  # objtool finds libelf via pkg-config (libelf.pc
                                          # Requires.private zlib/zstd, so their .pc too)
            openssl                       # module/signing crypto
            pahole                        # BTF encoder, if DEBUG_INFO_BTF is ever on
            gnupg curl git                # source fetch: tarball + signed-tag fallback
            gettext                       # kconfig gettext calls
            coreutils findutils diffutils gnused gnugrep  # the GNU tools the kernel build
                                          # expects
            cacert python3                # TLS roots + kernel build scripts
          ];
        };
      });
}
