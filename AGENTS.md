# AGENTS.md

This file provides guidance to AI coding assistants (Claude Code, Copilot, etc.) when working with code in this repository.

## Project Overview

virtkit — a rootless toolkit for [Cloud Hypervisor](https://www.cloudhypervisor.org/)
microVMs, shipped as two small static-musl binaries. It boots OCI/Docker images as
fast microVMs, gives them a shared LAN with egress over ordinary host sockets (no tap,
no bridge, no `CAP_NET_ADMIN`, no root), and drives commands into them over `vsock`.
The same codebase powers a local dev fleet and a GitLab custom executor. See
[`README.md`](README.md) for the full feature tour.

## Architecture

A Cargo workspace (`Cargo.toml`, edition 2024) with two crates:

- **`virtkit/`** — the host driver: image building/conversion (OCI → ext4/initramfs),
  the fleet orchestrator + control plane, the GitLab executor, the userspace L2
  network switch (ARP/DHCP/DNS + transparent TCP/UDP egress via `ipstack`), and a
  bundled virtio-fs daemon (`virtiofsd`).
- **`virtkit-agent/`** — the guest PID 1 / agent: brings a systemd-less guest up
  (mounts, networking, hostname, virtio-fs, optional SSH) and serves an exec channel
  over `vsock` so the host can run commands inside the VM.

The guest kernel is a vanilla Linux `vmlinux` built from a vendored config fragment
(`kernel/`); it is pinned and built separately from the binaries.

## Development Environment

The release artifacts are built reproducibly inside a pinned devcontainer image
(`.devcontainer/Dockerfile`, `rust:<ver>-alpine`, digest- and apk-pinned). Alpine is
required so the bundled `virtiofsd` can statically link `libseccomp` / `libcap-ng`.
All build scripts wrap Docker, so the host needs only Docker — no local Rust setup.

```bash
./build.sh                          # static-musl binaries -> dist/ (Docker)
./build-kernel.sh [--no-cache]      # guest kernel vmlinux -> dist/ (Docker; slow)
./audit.sh [--deny warnings]        # cargo-audit against the committed Cargo.lock
./update.sh                         # bump the pinned Rust toolchain + re-pin apk deps
./update-kernel.sh [--lts|--stable] # bump the pinned guest kernel (defaults to LTS)
```

### Cargo commands (pinned toolchain)

The toolchain is pinned in `rust-toolchain.toml` (1.96.1, musl target, clippy +
rustfmt). Run cargo directly if you have it, or inside the devcontainer image to
match CI exactly (clippy needs the static-FFI env — see `.github/workflows/quality.yml`):

```bash
cargo build --release --workspace
cargo test --workspace                              # tests, e.g. virtkit-agent/tests/exec.rs
cargo fmt --all                                     # format (check: --check)
cargo clippy --workspace --all-targets -- -D warnings
```

## Code Quality Config

- **Rust:** rustfmt + clippy, pinned via `rust-toolchain.toml` (edition 2024). CI runs
  `cargo fmt --check` and `cargo clippy ... -D warnings`.
- **Shell:** Bash, `set -euo pipefail`. Scripts that also run inside the Alpine image
  (e.g. `audit.sh` under CI) must stay POSIX-compatible — that image has no `bash`.
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
