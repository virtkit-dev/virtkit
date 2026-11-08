{
  # The CI tools nodes share into job VMs: a git, its https helper and `git submodule`'s
  # scripts, and git-lfs, each executable a static x86-64 one, so the same binaries run in any
  # job image whatever its libc. The Dockerfile beside this file builds the `tools` output and
  # exports it flat.
  #
  # nixpkgs is pinned by flake.lock, at the same commit as .devcontainer/nix/flake.lock;
  # ./update-ci-tools.sh moves it, and the pins below with it. git is built from source by
  # pkgsStatic (musl, linked statically) against the static toolchain cache.nixos.org serves.
  # git-lfs is upstream's static Go release, checked against its sha256.

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      static = pkgs.pkgsStatic;

      # Upstream's release: ./update-ci-tools.sh sets it to the version nixpkgs packages at
      # the pinned commit, and its sha256.
      gitLfsVersion = "3.8.0";
      gitLfsSha256 = "e455e00f15d9b95661b8d53498ffb0c3367962cf1ec73c31ab7369516cd6ab8d";

      # The git a CI checkout needs: https through libcurl (OpenSSL, HTTP/2), no Perl, Python,
      # PCRE, Rust or manual. Its test suite is skipped: it takes longer than the build. Its
      # shell is /bin/sh, which every job image has, never a path into the Nix store.
      #
      # configure's test link against a static libcurl lacks curl's own dependencies, so it
      # fails and silently drops https (no git-remote-http): force curl on, linked with what
      # `curl-config --static-libs` names.
      #
      # Its own directories are in the Nix store, absent where jobs run. Without a template
      # directory named, git copies no templates rather than warning about the missing default
      # one. `git submodule` is a script: it and the scripts it sources are kept as built,
      # before the install points their commands into the Nix store, and git-sh-setup finds
      # git-sh-i18n on PATH beside it rather than in git's exec path.
      curl = static.curlMinimal.override { scpSupport = false; };
      git = (static.gitMinimal.override {
        doInstallCheck = false;
        inherit curl;
      }).overrideAttrs (old: {
        makeFlags = old.makeFlags ++ [ "SHELL_PATH=/bin/sh" "NO_CURL=" ];
        postPatch = (old.postPatch or "") + ''
          substituteInPlace setup.c \
            --replace-fail 'dir = system_path(DEFAULT_GIT_TEMPLATE_DIR);' 'dir = xstrdup("");'
          substituteInPlace git-sh-setup.sh \
            --replace-fail '. "$(git --exec-path)/git-sh-i18n"' '. git-sh-i18n'
        '';
        preBuild = (old.preBuild or "") + ''
          makeFlags+=("CURL_LDFLAGS=$(${pkgs.lib.getDev curl}/bin/curl-config --static-libs)")
        '';
        # Not executable here, so the fixup leaves their /bin/sh alone.
        postInstall = (old.postInstall or "") + ''
          mkdir -p $out/share/ci-tools
          install -m 0644 git-submodule git-sh-setup git-sh-i18n $out/share/ci-tools/
        '';
      });

      git-lfs = pkgs.fetchurl {
        url = "https://github.com/git-lfs/git-lfs/releases/download/v${gitLfsVersion}/git-lfs-linux-amd64-v${gitLfsVersion}.tar.gz";
        sha256 = gitLfsSha256;
      };
    in
    {
      # What the Dockerfile checks its labels against, and ./update-ci-tools.sh writes there.
      versions = {
        git = git.version;
        git-lfs = gitLfsVersion;
      };
      # What ./update-ci-tools.sh pins git-lfs to.
      packaged = {
        git-lfs = pkgs.git-lfs.version;
      };

      packages.x86_64-linux.tools = pkgs.runCommand "ci-tools" { nativeBuildInputs = [ pkgs.binutils ]; } ''
        mkdir -p $out
        cp ${git}/bin/git $out/git
        # https is not built into git: it runs this helper, by either name, found on PATH.
        cp ${git}/libexec/git-core/git-remote-http $out/git-remote-http
        ln -s git-remote-http $out/git-remote-https
        # What a local or ssh fetch and push run by name: git itself, as installed.
        ln -s git $out/git-upload-pack
        ln -s git $out/git-receive-pack
        # `git submodule` messages are expanded by this helper.
        cp ${git}/libexec/git-core/git-sh-i18n--envsubst $out/git-sh-i18n--envsubst
        for f in git-submodule git-sh-setup git-sh-i18n; do cp ${git}/share/ci-tools/$f $out/$f; done
        # Nothing they run may be in the Nix store. git-sh-i18n names it only for gettext,
        # which this git is built without.
        if grep -l /nix/store $out/git-submodule $out/git-sh-setup; then
          echo "git submodule's scripts name the Nix store" >&2; exit 1
        fi
        grep -qx 'if test -n "fallthrough"' $out/git-sh-i18n ||
          { echo "git-sh-i18n uses gettext" >&2; exit 1; }
        tar -xzf ${git-lfs} --strip-components=1 git-lfs-${gitLfsVersion}/git-lfs
        mv git-lfs $out/git-lfs
        chmod 0755 $out/git $out/git-remote-http $out/git-lfs \
          $out/git-submodule $out/git-sh-setup $out/git-sh-i18n $out/git-sh-i18n--envsubst
        # Jobs run them in any image: none may ask for a dynamic loader.
        for f in $out/git $out/git-remote-http $out/git-sh-i18n--envsubst $out/git-lfs; do
          if readelf -l "$f" | grep -q INTERP; then echo "$f is not static" >&2; exit 1; fi
        done
      '';
    };
}
