# The CI tools vk-hub gives its nodes: git (with its https helper and `git submodule`) and
# git-lfs, static so they run in any job image. vk-hub holds this directory as its
# built-in tools definition; each node builds the `tools` stage into <state_dir>/tools/current, which
# vk-agent links onto a job's PATH when the job image lacks the tools.
#
# Reproducible like the build image (.devcontainer/Dockerfile): the nixos/nix base by
# manifest-list digest, the packages by flake.nix + flake.lock (nixpkgs by commit).
# ./update-ci-tools.sh refreshes the digest, the lock, the pins and the versions below; do not
# edit them by hand. There is no gitlab-runner: jobs the hub places run none. A fleet whose
# nodes run a gitlab-runner of their own adds a definition that also builds one.
#
# The build reaches only what the line below declares, which a node holds it to: the static
# toolchain, git's sources and nixpkgs from cache.nixos.org; the git-lfs release from
# github.com, which hands the download to release-assets.githubusercontent.com (and nixpkgs,
# should the cache lack it, to codeload.github.com, under github.com). The base image is
# pulled by the host, not the build.
# vk: allow-name=cache.nixos.org,github.com,release-assets.githubusercontent.com
FROM nixos/nix:2.35.2@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c AS build

# Flakes are gated behind experimental-features on the stock image, and the Nix sandbox
# needs user namespaces a build VM does not give it.
RUN mkdir -p /etc/nix \
 && printf 'experimental-features = nix-command flakes\nsandbox = false\n' >> /etc/nix/nix.conf

COPY flake.nix flake.lock /src/

# The versions the tools are labelled with: checked against what the lock builds, so the
# label vk-hub gives this definition cannot drift from its contents.
ARG GIT_VERSION=2.56.0
ARG GIT_LFS_VERSION=3.8.0
RUN for pair in "git=${GIT_VERSION}" "git-lfs=${GIT_LFS_VERSION}"; do \
      name=${pair%%=*}; want=${pair#*=}; \
      got=$(nix eval --no-update-lock-file --raw "path:/src#versions.${name}"); \
      [ "$got" = "$want" ] || { echo "$name is $got in flake.lock, not $want" >&2; exit 1; }; \
    done \
 && nix build --no-update-lock-file "path:/src#tools" --out-link /result \
 && mkdir /out && cp -a /result/. /out/

# Export stage: the tools alone, flat, as the node installs them.
FROM scratch AS tools
COPY --from=build /out/ /
