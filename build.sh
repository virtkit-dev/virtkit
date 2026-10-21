#!/usr/bin/env bash
# Build the production static-musl binaries.
#
# Two backends produce the same artifact with the same toolchain:
#   - default: Docker — `docker build` the devcontainer image, then `docker run`
#     the compile in it.
#   - --use-virtkit=<DIST>: dogfood — use the vk binary in <DIST> to build the
#     devcontainer Dockerfile into a microVM and compile a shared checkout inside it.
#     vk embeds the kernel + agent and boots on its built-in libkrun, so DIST needs
#     only the vk binary. Set VK_CACHE=host:port to push/pull the build image from a
#     `vk registry serve` by its content key.
#
# Output goes to ./dist as stripped, static-pie musl ELF binaries. Both backends
# mount the repo at /work and pass identical flags, so the bytes match either way.
#
# Two steps: compile, then assemble. The compile leaves a bare vk in ./dist/vk-bare;
# assemble.sh then appends ./dist/vk-agent, ./dist/vmlinux and, when ./build-firmware.sh has
# made them, the UEFI firmware ./dist/CLOUDHV*.fd (UEFI guests only) to make the
# self-contained ./dist/vk, and build.sh writes its vk.sha256 and build-info.txt. So the guest
# kernel is needed for assembling only: run ./build-kernel.sh first (it changes rarely — one
# build serves every later build.sh run). Never strip or re-link ./dist/vk: that drops the
# payload. Strip ./dist/vk-bare instead, then assemble again.
#
# --only=<bin>[,<bin>...]: compile just these binaries (vk, vk-agent, vk-registry, vk-hub,
# vk-gitlab, vk-runnerctl; repeated options accumulate) without assembling. Each can build
# on a separate machine. --assemble uses existing ./dist parts without compiling; combined
# with --only, it assembles after compiling the selected binaries. Use the same --fast and
# --features options as when compiling: assembly rejects parts with a different profile,
# features or commit, which the manifest records. --no-kernel/--kernel-from apply only to
# assembly. Each part's ./dist/<part>.build records its build settings.
#
# --no-kernel: build a `vk` with no embedded kernel — the only way to build without a
# dist/vmlinux. That vk takes --kernel at runtime, so it is not a shippable binary.
#
# --kernel-from=<tag>: embed release <tag>'s dist/vmlinux to skip CI's kernel build.
# Record its provenance in the manifest: the release recipe builds the kernel from
# this commit and need not reproduce these bytes.
#
# --bootstrap-check: after the default Docker build, rebuild with the just-built vk
# (the dogfood backend, on a clean copy of the tree in a tmp dir) and assert every binary,
# the bare vk included, is byte-for-byte identical — proof the microVM backend reproduces
# Docker, i.e. vk can rebuild itself. It boots the vk it builds, so it cannot combine with
# --no-kernel.
#
# --fast (alias --debug): build the debug cargo profile instead of release — a much
# faster compile for iteration, still static-musl and still embedding the kernel/agent,
# but unoptimized + unstripped and NOT reproducible, so not a release artifact (cannot
# combine with --bootstrap-check). The dev profile also trims debuginfo to line tables,
# cutting the edit-rebuild loop further without touching the release profile.
#
# --features=<list>: extra cargo features for vk-driver (comma-separated; repeats add up).
# Such a vk is not the release artifact, so this cannot combine with --bootstrap-check, and
# its manifest says so.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=virtkit-build
TARGET=x86_64-unknown-linux-musl
OUT=dist

# Wall-clock timings, printed to stderr (informational only — never written to
# build-info.txt, which must stay reproducible). Bash `SECONDS` counts whole seconds
# since the script started; `since` reports the delta from a captured value.
fmt_dur() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }
since()   { echo "build.sh: $1 in $(fmt_dur $(($SECONDS - $2)))" >&2; }

USE_VIRTKIT=""
BOOTSTRAP_CHECK=""
FORCE_DOCKER=""
FAST=""              # --fast/--debug: build the debug profile (much faster to compile,
                     # unoptimized + unstripped) for iteration — NOT a release artifact
NO_KERNEL=""         # --no-kernel: build vk without embedding dist/vmlinux
KERNEL_FROM=""       # --kernel-from=<tag>: dist/vmlinux is that release's kernel
FEATURES=""          # --features=<list>: extra vk-driver cargo features
ONLY=""              # --only=<list>: compile just these binaries, unassembled
ASSEMBLE=""          # --assemble: assemble dist/vk (alone: from the parts in dist/)
ALL_BINS="vk-agent vk vk-registry vk-hub vk-gitlab vk-runnerctl"
for arg in "$@"; do
  case "$arg" in
    --use-virtkit=*) USE_VIRTKIT="${arg#*=}" ;;
    --bootstrap-check) BOOTSTRAP_CHECK=1 ;;
    --docker) FORCE_DOCKER=1 ;;
    --fast|--debug) FAST=1 ;;
    --no-kernel) NO_KERNEL=1 ;;
    --kernel-from=?*) KERNEL_FROM="${arg#*=}" ;;
    --features=?*) FEATURES="${FEATURES:+$FEATURES,}${arg#*=}" ;;
    --only=?*) ONLY="${ONLY:+$ONLY,}${arg#*=}" ;;
    --assemble) ASSEMBLE=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
# Compile and assemble everything by default. --only selects binaries and skips assembly
# unless paired with --assemble. --assemble alone compiles nothing.
if [ -n "$ONLY" ]; then
  case "$ONLY" in *[!a-z,-]*) echo "--only takes a comma-separated list of binaries" >&2; exit 2 ;; esac
  for b in ${ONLY//,/ }; do
    case " $ALL_BINS " in
      *" $b "*) ;;
      *) echo "--only takes binaries among: $ALL_BINS (not '$b')" >&2; exit 2 ;;
    esac
  done
  COMPILE=""
  for b in $ALL_BINS; do
    case ",$ONLY," in *",$b,"*) COMPILE="$COMPILE $b" ;; esac
  done
  COMPILE=${COMPILE# }
  [ -n "$COMPILE" ] || { echo "--only names no binary" >&2; exit 2; }
  DO_ASSEMBLE=$ASSEMBLE
elif [ -n "$ASSEMBLE" ]; then
  COMPILE=""
  DO_ASSEMBLE=1
else
  COMPILE=$ALL_BINS
  DO_ASSEMBLE=1
fi
compiles() { case " $COMPILE " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
# Reproducibility checks require full builds; --only and --assemble run partial builds.
if [ -n "$BOOTSTRAP_CHECK" ] && { [ -n "$ONLY" ] || [ -n "$ASSEMBLE" ]; }; then
  echo "--bootstrap-check builds and assembles everything; it cannot be combined with --only or --assemble" >&2
  exit 2
fi
# --no-kernel and --kernel-from apply only to assembly.
if [ -z "$DO_ASSEMBLE" ] && { [ -n "$NO_KERNEL" ] || [ -n "$KERNEL_FROM" ]; }; then
  echo "--no-kernel and --kernel-from describe the assembled vk; add --assemble to --only" >&2
  exit 2
fi
if [ -n "$FEATURES" ] && [ -z "$DO_ASSEMBLE" ] && ! compiles vk; then
  echo "--features applies to vk, which this build neither compiles nor assembles" >&2
  exit 2
fi
# Backend flags select where compilation runs; assembly runs locally.
if [ -z "$COMPILE" ] && { [ -n "$USE_VIRTKIT" ] || [ -n "$FORCE_DOCKER" ]; }; then
  echo "--use-virtkit and --docker choose the compile backend; --assemble alone compiles nothing" >&2
  exit 2
fi
# vk compiles to vk-bare; other binaries keep their names.
part_file() { if [ "$1" = vk ]; then echo vk-bare; else echo "$1"; fi; }
# The debug profile is unoptimized and unstripped, so its bytes are neither the release
# artifact nor reproducible — it cannot back the reproducibility check.
if [ -n "$FAST" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--fast builds the debug profile; it cannot be combined with --bootstrap-check" >&2
  exit 2
fi
# Spliced unquoted into BUILD_CMD: only a plain comma-separated feature list gets through.
case "$FEATURES" in
  *[!A-Za-z0-9_,/-]*) echo "--features takes a comma-separated list of cargo features" >&2; exit 2 ;;
esac
if [ -n "$FEATURES" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--features builds a non-release vk; it cannot be combined with --bootstrap-check" >&2
  exit 2
fi
# The rebuild boots a microVM on the vk this build produces, which takes its kernel from
# the one embedded in it — so a kernel-less build cannot back the check either.
if [ -n "$NO_KERNEL" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--bootstrap-check boots the vk it builds; it cannot be combined with --no-kernel" >&2
  exit 2
fi
if [ -n "$NO_KERNEL" ] && [ -n "$KERNEL_FROM" ]; then
  echo "--kernel-from names the kernel embedded; it cannot be combined with --no-kernel" >&2
  exit 2
fi
# The debug manifest has no room for the release kernel's provenance.
if [ -n "$FAST" ] && [ -n "$KERNEL_FROM" ]; then
  echo "--kernel-from stamps a release-profile manifest; it cannot be combined with --fast" >&2
  exit 2
fi
# Cargo profile flag + its target/ subdir, threaded through the build command and artifact
# copy below so --fast changes both consistently.
CARGO_PROFILE_FLAG="--release"; PROFILE_DIR=release
[ -n "$FAST" ] && { CARGO_PROFILE_FLAG=""; PROFILE_DIR=debug; }
if [ -n "$USE_VIRTKIT" ] && [ -n "$BOOTSTRAP_CHECK" ]; then
  echo "--bootstrap-check runs the Docker build first; it cannot be combined with --use-virtkit" >&2
  exit 2
fi
if [ -n "$FORCE_DOCKER" ] && [ -n "$USE_VIRTKIT" ]; then
  echo "--docker cannot be combined with --use-virtkit" >&2
  exit 2
fi

# Backend: an explicit --use-virtkit dir wins; otherwise dogfood a `vk` on PATH when there
# is one — unless --docker forces Docker, or this is the --bootstrap-check baseline (which
# must be the Docker build the vk rebuild compares against). Else Docker.
VK_BIN=""
if [ -z "$COMPILE" ]; then
  :
elif [ -n "$USE_VIRTKIT" ]; then
  VK_BIN="$USE_VIRTKIT/vk"
elif [ -z "$FORCE_DOCKER" ] && [ -z "$BOOTSTRAP_CHECK" ] && command -v vk >/dev/null 2>&1; then
  VK_BIN=$(command -v vk)
  echo "build.sh: building with vk from PATH ($VK_BIN); pass --docker to force the Docker backend" >&2
fi

# Fail fast: check the dogfood-rebuild prerequisite up front, before the slow Docker
# build and compile. The fresh vk comes from the Docker build below with the guest
# kernel embedded and boots on its built-in libkrun — so the rebuild needs only
# dist/vmlinux (to embed into the vk it produces), no external VMM.
if [ -n "$BOOTSTRAP_CHECK" ]; then
  [ -e "$OUT/vmlinux" ] || {
    echo "--bootstrap-check needs $OUT/vmlinux (run ./build-kernel.sh first)" >&2
    exit 1
  }
fi

# Reproducibility: SOURCE_DATE_EPOCH neutralises any build timestamp, and the build
# dir and cargo home are remapped to stable virtual prefixes (/src, /cargo) so the
# binary is independent of where it was built — this script and a teammate's checkout
# produce identical bytes. The repo is always mounted at /work, so these /work-relative
# values hold for both backends. Stripping is done by the release profile, not the host
# strip.
# One linker for every build: mold, pinned in the build image via the flake, instead of
# the GNU ld gcc defaults to. It is deterministic, so the reproducible release link is
# unaffected, and it keeps this string identical to dev.sh's RUSTFLAGS — the two share
# target/, and any divergence silently stops them reusing each other's artifacts. The time
# it saves is in the incremental link the edit loop is dominated by; thin LTO with one
# codegen unit leaves the release link little to do either way.
# Not the LLD the toolchain bundles: that copy is built without zlib support, and Alpine's
# gcc compresses the debug sections of the C that ring, zstd and jemalloc-sys vendor.
# Release and dev both leave dependencies debuginfo-free, but one RUSTFLAGS serves
# --profile debugging too, where [profile.debugging.package."*"] turns that C debuginfo
# back on and the compressed sections appear.
RUSTFLAGS_VAL="--remap-path-prefix=/work=/src --remap-path-prefix=/work/target/.cargo-home=/cargo -C link-arg=-fuse-ld=mold"
# Resolve the source commit on the host and thread it into the compile as VK_GIT_COMMIT,
# so `vk --version` and dist/build-info.txt report the same value. The build sandbox can't
# reliably run git itself (the dogfood guest runs as root against a host-owned /work, which
# trips git's dubious-ownership check), so its `git rev-parse` fallback yields "unknown".
# VK_GIT_COMMIT lets a caller supply the commit — the --bootstrap-check rebuild runs in a
# tree copy with no .git, so it inherits the outer build's commit.
if [ -z "${VK_GIT_COMMIT:-}" ]; then
  VK_GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
  [ -n "$(git status --porcelain 2>/dev/null)" ] && VK_GIT_COMMIT="$VK_GIT_COMMIT (dirty)"
fi
commit="$VK_GIT_COMMIT"
BUILD_ENV=(
  HOME=/tmp
  CARGO_HOME=/work/target/.cargo-home
  CARGO_TARGET_DIR=/work/target
  SOURCE_DATE_EPOCH=0
  "RUSTFLAGS=$RUSTFLAGS_VAL"
  "CFLAGS_x86_64_unknown_linux_musl=-ffile-prefix-map=/work=/src -ffile-prefix-map=/work/target/.cargo-home=/cargo"
  "VK_GIT_COMMIT=$commit"
)
# A dirty tree's commit names no source, so its stamp also records the diff against HEAD.
# Untracked files are not in that diff, and a tree with no .git ("unknown") has neither: a
# stamp tells such builds apart only by profile and features.
TREE=""
case $commit in
  *"(dirty)") TREE=$(git diff HEAD --binary 2>/dev/null | sha256sum | cut -d' ' -f1) ;;
esac
# Stamp binary $1 from file $2: SHA-256, profile, commit, tree diff and vk's extra features.
# Sort features so their order does not affect the dist/<part>.build comparison.
build_stamp() {
  echo "sha256:   $(sha256sum < "$2" | cut -d' ' -f1)"
  echo "profile:  $PROFILE_DIR"
  if [ "$1" = vk ]; then
    echo "features: $(printf '%s' "${FEATURES:-none}" | tr ',' '\n' | sort -u | paste -sd, -)"
  fi
  echo "commit:   $commit"
  [ -z "$TREE" ] || echo "tree:     $TREE"
}
# Ignore carriage returns and blank lines when comparing stamps.
stamp_norm() { tr -d '\r' | sed '/^[[:space:]]*$/d'; }
# The assembled vk embeds the guest kernel, vk-agent and, when present, the UEFI firmware.
# A missing kernel is an error rather than a quietly non-self-contained vk: it is the
# shippable binary's defining property, and the build that drops it is the one nobody
# notices until the vk fails to boot anything. --no-kernel asks for that vk explicitly.
# Checked here, before the image build and compile, so the fix comes back in seconds.
EMBED_ARGS=()
EMBED_FIRMWARE=""
if [ -n "$DO_ASSEMBLE" ]; then
  # A part this run does not compile must match its sidecar, and its .build must say it was
  # compiled as this run would compile it — same profile, features and commit: build-info.txt
  # records the part's hash under this run's manifest header and git_commit.
  for b in vk vk-agent; do
    compiles "$b" && continue
    f=$(part_file "$b")
    for need in "$f" "$f.sha256" "$f.build"; do
      [ -e "$OUT/$need" ] || {
        echo "missing $OUT/$need to assemble — build it (--only=$b) first" >&2
        exit 1
      }
    done
    # The digest only: the name in the sidecar is not trusted to be this file's.
    want=$(cut -d' ' -f1 < "$OUT/$f.sha256")
    got=$(sha256sum < "$OUT/$f" | cut -d' ' -f1)
    [ "$want" = "$got" ] || {
      echo "$OUT/$f does not match $OUT/$f.sha256" >&2
      exit 1
    }
    expected=$(build_stamp "$b" "$OUT/$f" | stamp_norm)
    recorded=$(stamp_norm < "$OUT/$f.build")
    if [ "$recorded" != "$expected" ]; then
      echo "$OUT/$f was not compiled as this build would compile it:" >&2
      diff <(echo "$expected") <(echo "$recorded") | sed -n 's/^[<>]/  &/p' >&2 || true
      echo "  (< this build, > $OUT/$f.build); rebuild it (--only=$b) with the same flags" >&2
      exit 1
    fi
  done
  EMBED_ARGS+=("vk-agent=$OUT/vk-agent")
  if [ -n "$NO_KERNEL" ]; then
    echo "build.sh: --no-kernel — the vk built here has no embedded kernel and needs --kernel at runtime" >&2
  elif [ -e "$OUT/vmlinux" ]; then
    EMBED_ARGS+=("vmlinux=$OUT/vmlinux")
  else
    echo "missing $OUT/vmlinux — run ./build-kernel.sh first (or --no-kernel to build a vk without an embedded kernel)" >&2
    exit 1
  fi
  # The UEFI firmware for UEFI (Windows) guests, when ./build-firmware.sh has produced it. A
  # vk without it still boots every Linux guest; a UEFI guest then needs VIRTKIT_UEFI_FIRMWARE.
  if [ -e "$OUT/CLOUDHV.fd" ]; then
    EMBED_FIRMWARE=1
    EMBED_ARGS+=("CLOUDHV.fd=$OUT/CLOUDHV.fd")
    # Its variable store templates (empty, and with Microsoft's Secure Boot keys): without
    # them a UEFI guest's variables live in RAM and are lost at each boot.
    for vars in CLOUDHV_VARS.fd CLOUDHV_VARS.ms.fd; do
      if [ -e "$OUT/$vars" ]; then
        EMBED_ARGS+=("$vars=$OUT/$vars")
      fi
    done
  else
    echo "build.sh: no $OUT/CLOUDHV.fd — the vk built here embeds no UEFI firmware (./build-firmware.sh)" >&2
  fi
fi
# One cargo build per binary: cargo resolves features per invocation, so a binary's bytes do
# not depend on which others this run builds, and each can be built alone. vk is
# vk-driver's binary; the others are their packages'.
BUILD_CMD=""
for b in $COMPILE; do
  case $b in
    vk) cmd="cargo build $CARGO_PROFILE_FLAG -p vk-driver${FEATURES:+ --features $FEATURES}" ;;
    *) cmd="cargo build $CARGO_PROFILE_FLAG -p $b" ;;
  esac
  BUILD_CMD="${BUILD_CMD:+$BUILD_CMD && }$cmd"
done

compile_start=$SECONDS
if [ -z "$COMPILE" ]; then
  :
elif [ -n "$VK_BIN" ]; then
  # ---- dogfood backend: vk builds the env image + compiles in a microVM ----
  # vk is self-contained (embedded kernel + agent), so it needs no external base.
  VK="$VK_BIN"
  [ -e "$VK" ] || { echo "missing vk at $VK" >&2; exit 1; }

  cache_args=()
  [ -n "${VK_CACHE:-}" ] && cache_args=(--cache-registry "$VK_CACHE")

  # The guest command runs under `sh -c` in /work (the shared checkout); export the
  # build env there, then compile. Build the env image from .devcontainer/Dockerfile
  # (its RUN steps get egress for apk); --net gives the compile egress for cargo.
  exports=""
  for e in "${BUILD_ENV[@]}"; do
    v="${e#*=}"; v="${v//\'/\'\\\'\'}"   # escape embedded single quotes for the sh -c body
    exports+="export ${e%%=*}='$v'; "
  done

  # A release compile of the whole workspace is CPU- and memory-hungry, so size the
  # build VM for it: all the host's CPUs (--cpus host) for parallelism, and enough
  # RAM that rustc is not OOM-killed (the `run` defaults are 2 cpus / 1G).
  "$VK" run \
    --file .devcontainer/Dockerfile \
    --context .devcontainer \
    --workdir "$PWD" \
    --net \
    --cpus host \
    --mem 8G \
    "${cache_args[@]}" \
    -- "${exports}${BUILD_CMD}"
else
  # ---- default backend: Docker ----
  docker build -t "$IMAGE" -f .devcontainer/Dockerfile .devcontainer

  # Build as the host user so target/ and the cargo cache stay writable and no
  # root-owned files leak onto the host. RUSTUP_HOME is read-only here — the
  # pinned toolchain is already baked into the image.
  docker_env=()
  for e in "${BUILD_ENV[@]}"; do docker_env+=(-e "$e"); done
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    "${docker_env[@]}" \
    -v "$PWD":/work -w /work \
    "$IMAGE" \
    sh -c "$BUILD_CMD"
fi
[ -z "$COMPILE" ] || since "compile ($([ -n "$VK_BIN" ] && echo "libkrun microVM" || echo docker))" "$compile_start"

mkdir -p "$OUT"
# Replace atomically (write a temp, then rename): a plain cp truncates the destination and
# would fail "Text file busy" if the old $OUT/vk is still being executed (e.g. by a
# previous --use-virtkit / --bootstrap-check run); rename never does. The compiled vk is the
# bare one; $OUT/vk is only ever the assembled binary.
# The sidecars name each binary without a directory, so a check runs from inside dist/.
# Each .build records the build settings for a later --assemble check.
for b in $COMPILE; do
  dest=$(part_file "$b")
  # Gone first, so a run that dies before writing the new stamp leaves none at all.
  rm -f "$OUT/$dest.build"
  cp "target/$TARGET/$PROFILE_DIR/$b" "$OUT/.$dest.tmp"
  mv -f "$OUT/.$dest.tmp" "$OUT/$dest"
  ( cd "$OUT" && sha256sum "$dest" > "$dest.sha256" )
  build_stamp "$b" "$OUT/$dest" > "$OUT/$dest.build"
done

if [ -z "$DO_ASSEMBLE" ]; then
  # A new part makes the assembled vk and its manifest describe what is no longer there.
  stale=""
  if compiles vk || compiles vk-agent; then
    for f in vk vk.sha256 build-info.txt; do
      if [ -e "$OUT/$f" ]; then stale="$stale $OUT/$f"; fi
    done
  fi
  if [ -n "$stale" ]; then
    # shellcheck disable=SC2086 # paths under dist/, no spaces
    rm -f $stale
    echo "build.sh: removed the now stale$stale; there is no $OUT/vk to run until --assemble makes it again" >&2
  fi
  echo
  echo "built into $OUT/ (unassembled):"
  for b in $COMPILE; do cat "$OUT/$(part_file "$b").sha256"; done
  since "total" 0
  exit 0
fi

# assemble.sh writes $OUT/vk by rename too.
sh ./assemble.sh "$OUT/vk" "$OUT/vk-bare" "${EMBED_ARGS[@]}"
( cd "$OUT" && sha256sum vk > vk.sha256 )

# Reproducibility manifest: the pinned inputs and the artifact hashes. Anyone can
# rebuild from the same commit + inputs and confirm byte-for-byte:
#   git checkout <git_commit> && ./build-kernel.sh && ./build.sh &&
#     ( cd dist && sha256sum -c vk.sha256 vk-bare.sha256 vk-agent.sha256 vk-registry.sha256 vk-hub.sha256 vk-gitlab.sha256 vk-runnerctl.sha256 )
# The inputs that fix the bytes: the base image digest (.devcontainer/Dockerfile's FROM) and
# the flake.lock revs of nixpkgs / rust-overlay.
# The rev flake.lock pins for one input: the first "rev" inside that input's node.
lock_rev() {
  awk -v n="\"$1\": {" 'index($0, n) { f = 1 } f && /"rev":/ { gsub(/[",]/, "", $2); print $2; exit }' \
    .devcontainer/nix/flake.lock
}
base_image=$(sed -nE 's/^FROM ([^ ]+).*$/\1/p' .devcontainer/Dockerfile | head -1)
nix_pins="nixpkgs:         $(lock_rev nixpkgs)
rust_overlay:    $(lock_rev rust-overlay)"
toolchain=$(sed -nE 's/^channel = "(.*)"$/\1/p' rust-toolchain.toml)
# vk's bytes depend on the embedded firmware: a rebuild must rebuild it first.
if [ -n "$EMBED_FIRMWARE" ]; then
  firmware_step="./build-firmware.sh && "
  # The variable store templates are embedded too, when present.
  firmware_line=$(cd "$OUT" && sha256sum CLOUDHV.fd $(ls CLOUDHV_VARS.fd CLOUDHV_VARS.ms.fd 2>/dev/null))
  # The nix store paths pin the exact edk2 derivations; absent for a CLOUDHV.fd placed by hand.
  store_path=$(awk '$1 == "store_path:" { print $2 }' "$OUT/firmware-build-info.txt" 2>/dev/null || true)
  [ -z "$store_path" ] || firmware_line="$firmware_line
firmware_store:  $store_path"
  vars_store_path=$(awk '$1 == "vars_store_path:" { print $2 }' "$OUT/firmware-build-info.txt" 2>/dev/null || true)
  [ -z "$vars_store_path" ] || firmware_line="$firmware_line
firmware_vars_store: $vars_store_path"
else
  firmware_step=""
  firmware_line="firmware:        none"
fi
# $commit was resolved above (before the compile) and threaded into the build as
# VK_GIT_COMMIT, so the embedded `vk --version` stamp and this manifest agree.
# --fast produces the debug profile: unoptimized, unstripped, not reproducible. Stamp the
# manifest so its hashes are never mistaken for a release artifact — the release "Verify"
# recipe would rebuild the release profile and fail sha256sum -c against these debug bytes.
if [ -n "$FAST" ]; then
  manifest_header="# virtkit DEBUG build manifest (--fast${NO_KERNEL:+ --no-kernel}${FEATURES:+ --features=$FEATURES}) — NOT reproducible, not a release artifact
profile:         debug"
elif [ -n "$FEATURES" ]; then
  # Release-profile bytes, but of a vk with extra features: the release recipe rebuilds the
  # default feature set, so it would fail against these hashes.
  manifest_header="# virtkit build manifest (--features=${FEATURES}) — extra features, not a release artifact
# Verify: git checkout <git_commit> && ${firmware_step}./build.sh --features=${FEATURES}${NO_KERNEL:+ --no-kernel}${KERNEL_FROM:+ --kernel-from=$KERNEL_FROM} && ( cd dist && sha256sum -c vk.sha256 vk-bare.sha256 vk-agent.sha256 vk-registry.sha256 vk-hub.sha256 vk-gitlab.sha256 vk-runnerctl.sha256 )
profile:         release
features:        ${FEATURES}"
elif [ -n "$NO_KERNEL" ]; then
  # Same trap as --fast, one step removed: the bytes are release-profile but kernel-less,
  # so the release recipe — which embeds the kernel — rebuilds something else entirely.
  manifest_header="# virtkit build manifest (--no-kernel) — no embedded kernel, not a release artifact
# Verify: git checkout <git_commit> && ${firmware_step}./build.sh --no-kernel && ( cd dist && sha256sum -c vk.sha256 vk-bare.sha256 vk-agent.sha256 vk-registry.sha256 vk-hub.sha256 vk-gitlab.sha256 vk-runnerctl.sha256 )
profile:         release"
elif [ -n "$KERNEL_FROM" ]; then
  # The kernel was built at the release's commit, not git_commit: the vk that embeds it is
  # not git_commit's release build.
  manifest_header="# virtkit CI build manifest — embeds ${KERNEL_FROM}'s guest kernel, not a release artifact
# Verify: git checkout <git_commit> && gh release download ${KERNEL_FROM} -p vmlinux -p vmlinux.sha256 -D dist && ( cd dist && sha256sum -c vmlinux.sha256 ) && ${firmware_step}./build.sh --kernel-from=${KERNEL_FROM} && ( cd dist && sha256sum -c vk.sha256 vk-bare.sha256 vk-agent.sha256 vk-registry.sha256 vk-hub.sha256 vk-gitlab.sha256 vk-runnerctl.sha256 )
profile:         release
kernel_from:     ${KERNEL_FROM}"
else
  manifest_header="# virtkit reproducible build manifest
# Verify: git checkout <git_commit> && ./build-kernel.sh && ${firmware_step}./build.sh && ( cd dist && sha256sum -c vk.sha256 vk-bare.sha256 vk-agent.sha256 vk-registry.sha256 vk-hub.sha256 vk-gitlab.sha256 vk-runnerctl.sha256 )
profile:         release"
fi
cat > "$OUT/build-info.txt" <<EOF
${manifest_header}
git_commit:      ${commit}
rust_toolchain:  ${toolchain}
base_image:      ${base_image}
${nix_pins}

$(cat "$OUT/vk.sha256")
$(cat "$OUT/vk-bare.sha256")
$(cat "$OUT/vk-agent.sha256")
${firmware_line}
EOF

echo
echo "built into $OUT/:"
if command -v file >/dev/null 2>&1; then file "$OUT/vk" "$OUT/vk-agent"; fi
echo
cat "$OUT/build-info.txt"

if [ -n "$BOOTSTRAP_CHECK" ]; then
  # Rebuild with the vk we just produced (the dogfood backend) and confirm it
  # reproduces the Docker build bit-for-bit. The just-built $OUT is itself a valid
  # --use-virtkit toolchain (the self-contained vk built above). The second build runs
  # on a clean copy of the tree in a tmp dir — a full independent compile, mounted at
  # the same /work path so the container-side paths (and thus the reproducible bytes)
  # match the Docker build.
  echo
  echo "bootstrap check: rebuilding with the freshly built vk in a microVM…"
  boot_dist="$PWD/$OUT"
  boot_tmp=$(mktemp -d)
  trap 'rm -rf "$boot_tmp"' EXIT
  # Clean working-tree copy (no target/.git/dist) so the rebuild can't reuse this build's
  # target/ and is a genuine from-scratch compile.
  tar -c --exclude=./.git --exclude=./target --exclude="./$OUT" . | tar -x -C "$boot_tmp"
  # `vk` embeds the kernel and any UEFI firmware and variable stores, so the rebuild must see
  # the same dist/vmlinux and dist/CLOUDHV*.fd (the tree copy above excludes dist/); without
  # them the two vk binaries would differ.
  mkdir -p "$boot_tmp/$OUT"
  cp "$boot_dist/vmlinux" "$boot_tmp/$OUT/vmlinux"
  if [ -n "$EMBED_FIRMWARE" ]; then
    cp "$boot_dist/CLOUDHV.fd" "$boot_tmp/$OUT/CLOUDHV.fd"
    for vars in CLOUDHV_VARS.fd CLOUDHV_VARS.ms.fd; do
      if [ -e "$boot_dist/$vars" ]; then
        cp "$boot_dist/$vars" "$boot_tmp/$OUT/$vars"
      fi
    done
  fi
  rebuild_start=$SECONDS
  # Thread the commit in: the copy has no .git.
  ( cd "$boot_tmp" && VK_GIT_COMMIT="$commit" ./build.sh \
      --use-virtkit="$boot_dist" )
  since "bootstrap rebuild" "$rebuild_start"

  echo
  echo "bootstrap check: comparing sha256…"
  mismatch=""
  for b in vk-bare vk vk-agent vk-registry vk-hub vk-gitlab vk-runnerctl; do
    docker_sha=$(sha256sum < "$OUT/$b" | cut -d' ' -f1)
    virtkit_sha=$(sha256sum < "$boot_tmp/$OUT/$b" | cut -d' ' -f1)
    if [ "$docker_sha" = "$virtkit_sha" ]; then
      echo "  $b: OK      $docker_sha"
    else
      echo "  $b: DIFFER  docker=$docker_sha  virtkit=$virtkit_sha" >&2
      mismatch=1
    fi
  done
  if [ -n "$mismatch" ]; then
    echo "bootstrap check FAILED: the vk backend did not reproduce the Docker build" >&2
    exit 1
  fi
  echo "bootstrap check passed: Docker and vk backends produce identical binaries"
fi

since "total" 0
