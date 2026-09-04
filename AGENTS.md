# AGENTS.md

This file provides guidance to AI coding assistants (Claude Code, Copilot, etc.) when working with code in this repository.

## Sourced Assertions

Verify load-bearing factual claims — code, tooling, third-party behaviour — against the code, the
repo docs, or a web search before stating them. Flag anything unverified, or a deduction.

Badge in chat output only (never in commit messages, code comments, or committed files), inline
right after the claim, with a `path:line` cite for code/doc:

- `✅ code` / `✅ doc` `path:line` — verified in the code / repo docs
- `✅ web` URL — verified online (bare URL, outside the code span; pin to a commit SHA, not a branch)
- `💭 deduction` — inferred from verified facts
- `⚠️ unverified` — unverifiable, or from training data

Skip badges on restatements, tool output, and descriptions of your own next step.

## Project Overview

virtkit — a rootless microVM toolkit shipped as static-musl binaries (`vk` + the
embedded `vk-agent`, plus the optional `vk-registry` central server and the
`vk-runnerctl` runner throttle), with the VMM built in. It boots OCI/Docker images as fast microVMs on its embedded
[libkrun](https://github.com/containers/libkrun) VMM ([Cloud Hypervisor](https://www.cloudhypervisor.org/)
stays available as an external backend via `VIRTKIT_VMM=cloud-hypervisor`), gives
them a shared LAN with egress over ordinary host sockets (no tap, no bridge, no
`CAP_NET_ADMIN`, no root), and drives commands into them over `vsock`.
The same codebase powers local compose-service VMs and a GitLab custom executor. See
[`README.md`](README.md) for the full feature tour.

## Architecture

A Cargo workspace (`Cargo.toml`, edition 2024) with seven crates:

- **`vk-core/`** — the shared host↔guest library: the wire protocol (`messages`,
  `framing`, `addr`, `net`, `status`, `fleetctl`), the formats both sides speak (`atop`,
  `oomkills`), plus the runtime helpers both sides build on (`exec`, `forward`, `pty`,
  `dockerignore`). Deliberately free of guest-only concerns and of russh, so the host
  links none of that.
- **`vk-driver/`** — the host driver (depends on `vk-core`): image building/conversion
  (OCI → ext4/initramfs), the compose service runner + control plane, the GitLab executor,
  the userspace L2 network switch (ARP/DHCP/DNS + transparent TCP/UDP egress via
  `ipstack`), the libkrun VMM backend (`vmm`/`libkrun_sys`, default; the pinned guest
  kernel and vk-agent are embedded so `vk` runs self-contained), and a bundled
  virtio-fs daemon (`virtiofsd`, serving cloud-hypervisor shares with the vendored
  libkrun fs engine).
- **`vk-agent/`** — the guest PID 1 / agent (depends on `vk-core`): brings a systemd-less
  guest up (mounts, networking, hostname, virtio-fs, optional SSH) and serves an exec
  channel over `vsock` so the host can run commands inside the VM.
- **`vk-registry/`** — the content-addressed OCI store (lib) plus a standalone server
  (bin). `vk-driver` links the lib for its in-process build cache. The `vk-registry`
  binary is a central OCI-distribution daemon meant to be shared by every runner: it
  serves the store over HTTP(S), fronts upstream registries as a pull-through cache
  (caching only digest-addressed content), coordinates build-once via a lease/heartbeat
  lock API (`/lock`), and is a backend for the `task` build cache. See its `DESIGN.md`.
- **`vk-selfupdate/`** — `<tool> update` for the binaries a user installs by hand: resolve a
  GitHub release, check the download against the digest published beside it, smoke-test it,
  and rename it over the running binary. Parameterized by tool so every one of them passes
  the same gates; the caller supplies only which asset it is and what version it was built
  as. `vk` and the `vk-registry` binary are the callers.
- **`vk-fs/`** — filesystem objects created private and published whole: mode asked for at
  creation rather than left to the process-wide umask, `rename` into place so a name never
  leads nowhere, a directory resolved once and worked through its descriptor, and a name
  acted on only where it cannot have become another user's. A leaf with no dependencies but
  `libc` and `anyhow`, so every crate here can use it — `vk-runnerctl` included.
- **`vk-runnerctl/`** — the only component that runs as root, and deliberately the smallest:
  it sets gitlab-runner's `concurrent` from a number unprivileged `vk` leaves in a file,
  clamped into a range only root can configure. It takes no arguments and no paths from its
  caller, so granting it `NOPASSWD` grants nothing else; all the policy lives in `vk`.

libkrun is vendored (its own cargo workspace, locally patched) under
`third_party/libkrun` — see its `VENDOR.md` for the patch list.

The guest kernel is a vanilla Linux `vmlinux` built from a vendored config fragment
(`kernel/`); it is pinned and built separately from the binaries.

## Development Environment

The release artifacts are built reproducibly inside a pinned devcontainer image
(`.devcontainer/Dockerfile`: the `nixos/nix` base by digest, the toolchain from
`.devcontainer/nix/flake.nix` pinned by `flake.lock`). Nix runs only inside that image at
build time — no Nix on the host. A musl cross gcc compiles the C our deps vendor (ring,
zstd, jemalloc) and links the static-musl binaries; no system C libraries are linked.
Release build scripts can use Docker or `vk`, so no local Rust setup is needed. The
fast edit loop below is deliberately `vk`-only and never invokes Docker.

```bash
./build-kernel.sh [--no-cache]      # guest kernel vmlinux -> dist/ (vk or Docker; slow) — run first
./build.sh                          # static-musl binaries -> dist/ (vk or Docker)
./build.sh --fast                   # same, but the debug profile -> much faster iteration
./dev.sh check                      # type/borrow checking, whole workspace, every target
./dev.sh clippy                     # the lints CI gates on, same scope
./dev.sh test                       # the whole test suite, doctests included
./dev.sh check -p vk-core           # the same, narrowed to one affected crate
./dev.sh test -p vk-core --lib …    # one module's unit tests (see below)
./dev.sh shell                      # interactive shell in that same VM
./audit.sh [--deny warnings]        # cargo-audit against the committed Cargo.lock
./sweep.sh [--time 15]              # cargo-sweep stale target/ artifacts (default --installed)
./update.sh                         # bump the pinned Rust toolchain + re-lock the flake
./update-kernel.sh [--lts|--stable] # bump the pinned guest kernel (defaults to LTS)
```

**When you need a runnable binary, use `./build.sh --fast`** (alias `--debug`). It builds the
unoptimized debug profile — a much faster compile that still produces the same static-musl
`vk` with the kernel + agent embedded. The output is not stripped and not reproducible, so it
is for iterating only, never a release artifact (it cannot combine with `--bootstrap-check`).
Use a plain `./build.sh` for anything you ship or compare bytes against.

Every local (non-release) build also gets line-tables-only debuginfo from `[profile.dev]`,
which keeps `file:line` in panics and backtraces while dropping the bulky per-variable
DWARF; dependencies get none at all. When you need a debugger, build with cargo's
`--profile debugging` (`./dev.sh check|test` accept it too) — `build.sh` offers only the
release and dev profiles.

Both `./build.sh` and `./build.sh --fast` embed `dist/vmlinux` and fail when it is absent,
so `./build-kernel.sh` comes first in a fresh checkout; `--no-kernel` builds a `vk` without
the embedded kernel instead (it then needs `--kernel` at runtime, and is not shippable).

### Fast edit/check/test loop

During iterative edits, do not run `cargo build` or release builds. Start with
`./dev.sh check -p <affected-crate>` for type and borrow checking. Then run only the test
target and module affected by the change, for example:

```bash
./dev.sh test -p vk-core --lib dockerignore::tests
./dev.sh test -p vk-core --test exec disconnect_kills_remote_process
./dev.sh test -p vk-driver --bin vk atop_view::tests
```

`./dev.sh clippy -p <crate>` runs CI's Clippy gate for one crate. It defaults to
`-- -D warnings`, and explicit `--` lint flags replace that default.

With no arguments, each mode covers the whole workspace. `check` and `clippy` add
`--all-targets`, so test code receives the same coverage as CI's Clippy run; `test`
keeps Cargo's defaults to include doctests. Run the broader commands before committing.
Keep the narrow forms for the edit loop itself — the wide ones take minutes where a
scoped run takes seconds.

`dev.sh` is Docker-free: on first use it boots the pinned build image as a shared
`vk` development VM; later invocations use `vk exec`, avoiding another image build and
boot. It reuses `target/` — its RUSTFLAGS match `build.sh`'s exactly, so it shares
dependency artifacts with `./build.sh --fast` — and rejects optimized invocations. The
VM powers itself off after half an hour with no cargo command or open shell, so a
forgotten one stops holding memory; `./dev.sh stop` ends it immediately. A
`vk` and a `flock` on `PATH` are required and there is deliberately no Docker fallback.
`VK_DEV_CPUS` and `VK_DEV_MEM` size the VM, `VK_DEV_IDLE_SECS` sets that idle window
(`0` keeps the VM until it is stopped). Use `./build.sh --fast` only when an executable
is actually needed for runtime testing. `./dev.sh shell` opens an interactive shell in
that VM (same user, directory and cargo environment) and holds the VM for as long as
the shell runs, for the odd cargo or toolchain command the modes above refuse.
That VM boots with nested virtualization where the host allows it and the `vk` on
`PATH` can ask for it, so the shell can also *run* what it builds: `./dist/vk run …`
works inside it, as does `./build.sh --fast --use-virtkit=./dist`, their images and
boot scratch redirected under `/var/tmp/vk` on the guest's own disk rather than the
RAM-backed `/tmp`. To search the tree from inside the VM, reach for `ugrep` and `bfs`;
the image's `grep` and `find` are busybox applets.

### Cargo commands (pinned toolchain)

The toolchain is pinned in `rust-toolchain.toml` (musl target, clippy + rustfmt). Run
cargo directly if you have it, or inside the devcontainer image to match CI exactly
(clippy compiles the workspace, so it needs `build.sh`'s writable cargo home — see
`.github/workflows/quality.yml`). These are the CI-parity commands, run to verify a
change; the edit loop above is what to use while iterating:

```bash
cargo build --release --workspace
cargo test --workspace                              # tests, e.g. vk-core/tests/exec.rs
cargo fmt --all                                     # format (check: --check)
cargo clippy --workspace --all-targets -- -D warnings
```

## Code Quality Config

- **Rust:** rustfmt + clippy, pinned via `rust-toolchain.toml` (edition 2024). CI runs
  `cargo fmt --check` and `cargo clippy ... -D warnings`.
- **Shell:** Bash, `set -euo pipefail`. Scripts that also run inside the build image
  (e.g. `audit.sh` under CI) must stay POSIX-compatible — assume only `sh` there.
- **Dependency audit:** `cargo-audit` with the RUSTSEC ignore list in `.cargo/audit.toml`
  (each entry documented with rationale + residual risk).

## CI

- **GitHub Actions** (`.github/workflows/`): `ci.yml` (lint + audit + build on push/PR),
  `release.yml` (publish a GitHub release on `v*` tag), with reusable `quality.yml`
  (lint + audit) and `build.yml`.
- **GitLab** (`.gitlab-ci.yml`): reproducible build + independent rebuild attestation +
  keyless Sigstore signing.

Reproducibility is load-bearing: the binaries are baked into microVM images. Keep
builds byte-deterministic (pinned toolchain/base image, `SOURCE_DATE_EPOCH`, path
remapping). Do not break the pinning when changing build inputs.

## Commit Messages

See [`.agents/commit-message-guidelines.md`](.agents/commit-message-guidelines.md) for
the format, scope list, body rules, and changelog rules. In short: one concern per
commit, independently buildable; single-line imperative summary (no trailing period)
with an optional `scope:` prefix (e.g. `ci:`, `build-kernel.sh:`); a wrapped body only
when the diff does not speak for itself, kept high-level. A user-visible change updates
`CHANGELOG.md` in the same commit, pitched even higher-level than the message.

## Code Review

Code review is expected on the production branch (`main`): one concern per commit, every
commit independently buildable, and every changed line auditable at a glance. Review
against the conventions in
[`.agents/coding-guidelines.md`](.agents/coding-guidelines.md) and the message rules in
[`.agents/commit-message-guidelines.md`](.agents/commit-message-guidelines.md).

## Coding Conventions

See [`.agents/coding-guidelines.md`](.agents/coding-guidelines.md) for general
conventions, formatting requirements, and per-language guidelines (Rust, Shell).
