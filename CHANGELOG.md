# Changelog

All notable changes to virtkit will be documented in this file.

## [Unreleased]

## [0.3.0] - 2026-06-30

### Added

- **microVM Dockerfile builder** (`virtkit build`): builds a bootable ext4 from a
  Dockerfile with no buildkit and no docker — each `RUN` runs in a Cloud Hypervisor guest,
  with a content-addressed instruction cache.
- **`virtkit run` boots a Dockerfile target or an image**: `-f <Dockerfile>` builds and
  boots a target; `--source oci|docker|auto` picks an image's rootfs. The command inherits
  the image environment, with `--workdir` for a shared cwd and `--net` for egress.
- **SSH-agent forwarding into guests**: host keys are relayed over vsock and never enter
  the guest — jobs via `[auth] ssh_agent`, `run` via `--ssh-agent` / `--ssh-host`.
- **Port-scoped egress** allowlist rules (`CIDR:port`).
- **`build.sh --use-virtkit`** builds virtkit with itself, and **`--bootstrap-check`**
  asserts the result is byte-for-byte identical to the Docker build.

### Changed

- **Breaking:** the `launch` subcommand is renamed to `run`.
- CoW overlays are created with an in-tree qcow2 writer instead of `qemu-img` (dropping
  that dependency).
- `virtkit docker-hash` now prints each stage's instruction-cache key.

### Removed

- **Breaking:** the buildkit-based `virtkit build` and its flags, superseded by the
  microVM builder above.

## [0.2.1] - 2026-06-28

### Added

- **`virtkit registry inspect <name>[:tag|@digest]`**: check a bundle exists in the
  `[registry]` repo without pulling it — prints the manifest digest and exits 0, or
  exits non-zero if absent. The CI build's already-built check, replacing
  `docker manifest inspect`.
- **Per-job egress narrowing** (`MICROVM_EGRESS_ALLOW_NAME` job variable): a gitlab
  job may restrict its switch egress to a subset of the host `[egress] allow_name`
  cap. The cap stays host-only, so a job can drop down to least privilege but never
  widen its egress; a requested name outside the cap fails the job.
- **`virtkit build --push-bundle <name>:<tag>`**: build a Dockerfile target and push
  the resulting ext4 straight to the `[registry]` as a bundle, in one process — no
  kept ext4 and no separate `registry push`. The fused buildkit → bundle path: the
  ext4 is materialized only transiently (point `TMPDIR` at tmpfs to keep it in RAM)
  and removed after the upload. A push failure fails the build.
- **`virtkit build --conf <virtkit.conf>`**: build a target declared in a project
  manifest with no external driver. The TOML manifest holds `dockerfiles`, a
  `[build_args]` table, and `[targets.<name>]` entries (`stage` + a `version`
  template); virtkit computes the stage hash (byte-for-byte matching the existing
  pipeline) and renders the tag from `{name}`/`{hash}`/`{ARG[<name>]}` tokens
  (`{ARG[debversion]}` → the effective `debversion` build-arg value), with optional
  bash-style strip transforms on `{ARG[...]}` — `%%<sep>*`/`%<sep>*` (before the
  first/last `sep`) and `##*<sep>`/`#*<sep>` (after the last/first `sep`), e.g.
  `{ARG[debversion]%%-*}` → the distro codename. It then
  push-bundles it to the `[registry]` (default), pushes an OCI image with
  `--push <ref>` (service images), loads it into the local container daemon with
  `--load` (the local-dev / docker-mode path), or writes a local ext4 with `--out`.
  `--conf --versions` lists every target's `<name> <version>` (the build's
  already-built / out.env source).
- **`virtkit build --load`**: build a Dockerfile target and load it straight into the
  local container daemon (buildkit `type=docker` streamed to `<cli> load`, no kept
  ext4/registry) — a normal local image, tagged by the `--conf` version (else
  `--name`). The loader is `docker`, overridable via `VIRTKIT_CONTAINER_CLI`.

## [0.2.0] - 2026-06-27

### Added

- **Per-job `switch` networking for the gitlab executor** (`net.mode = "switch"`):
  each job runs on its own userspace switch over vsock instead of a host tap — no
  host privileges and no virtio-net device. The in-guest agent bridges eth0 over
  vsock and takes a static address; the switch is spawned on `prepare` and torn
  down on `cleanup`.
- **DNS-pinned egress allowlist** for the switch (`virtkit switch --allow-ip
  <CIDR>` / `--allow-name <suffix>`, and the executor `[egress]` section): names
  outside the allowlist are refused (NXDOMAIN) and the A-records of allowed names
  are pinned for their TTL, so a guest can only reach a static allowed CIDR or a
  freshly resolved allowed name. Transparent; the default is unrestricted.
- **`virtkit build --push <registry>/<name>:<tag>`**: build a Dockerfile target and
  push it to a registry as an OCI image (no docker).
- **Embedded local OCI registry** (`virtkit registry serve` / `install-service`):
  a minimal v2 server over a content-addressed store, so dev worktrees share one
  bundle pool with no docker. Single musl-static binary.
- **Fleet bundle sharing** (`virtkit fleet --registry <repo>` / `--registry-serve
  <dir>`): build each unit's ext4 once and pull/push it across worktrees keyed by
  its content fingerprint; `--registry-serve` starts an inline ephemeral server
  over a shared store with no daemon. Best-effort — a registry failure never fails
  the build.
- **Transparent-zstd chunks** (`[registry] transparent_zstd`): chunks addressed by
  the *uncompressed* digest with the registry storing them zstd and negotiating
  `Content-Encoding` on the wire — compression-level-independent dedup, still
  OCI-interoperable. Auto-negotiated: used against a cooperating registry
  (virtkit's `regserve`, which advertises support on `/v2/`), with the
  compressed-digest layers as the fallback any dumb OCI registry stores compactly.

### Changed

- The bundle push compresses and uploads chunks concurrently (streaming, bounded),
  and caches each raw chunk's blob digest (`$XDG_CACHE_HOME/virtkit/chunkmap`) so a
  re-push skips recompressing unchanged chunks.

### Fixed

- File-capability xattrs (e.g. `/usr/bin/ping`'s `security.capability`) are
  preserved through the OCI layer flatten — they were dropped when the merger
  re-emitted the rootfs tar, leaving `ping` without `cap_net_raw`.

## [0.1.10] - 2026-06-27

### Fixed

- `read_boot_kind` trims the `boot.kind` marker before matching, so a marker
  written with a trailing newline (e.g. via `echo`) is read as the intended boot
  flavour instead of falling back to the systemd default.
- The guest agent writes `/etc/resolv.conf` from `VIRTKIT_VM_DNS` for every net
  mode, not only the vsock-bridge path. A guest on the kernel `ip=` (tap/pool) net
  previously got no resolver; it now gets one `nameserver` line per comma-separated
  entry.

## [0.1.9] - 2026-06-26

### Added

- Generic (`docker/`) converted guests now capture the image's `Config.User` and
  `Config.Env` into `/etc/virtkit/{user,env}` (which `docker export` drops), like
  the systemd path. The serve-mode agent restores the env and drops each stage to
  the image USER, so a plain image booted via `docker/<image>` runs exactly like
  `docker run` — as its USER, with its env — with no bespoke bootable variant.

### Changed

- Renamed the guest run-user env var `CMDRUNNER_DEFAULT_RUN_USER` →
  `VIRTKIT_DEFAULT_RUN_USER` (a leftover from the cmdrunner era).

## [0.1.8] - 2026-06-26

### Added

- New `[gitlab]` config section with a `dir` of static CI tool binaries (e.g.
  `git`, `git-lfs`, `gitlab-runner`) that the GitLab executor shares **read-only
  over virtio-fs** into every job VM. The in-guest agent links each tool onto the
  guest PATH (`/usr/local/bin`), skipping any the job image already provides
  (per-image opt-out, checked in-guest). Dynamic: the binaries stay on the host
  and are baked into no bundle, so updating them needs no re-conversion
  (`VIRTKIT_TOOLS=tag:mountpoint` drives the in-guest mount + link).
- `virtkit build --local-out <dir>` exports the target stage's rootfs to a host
  directory (buildctl `type=local`) instead of building an ext4 — e.g. to extract
  a built static binary from a scratch-final stage. `--out` and `--local-out` are
  mutually exclusive.

## [0.1.7] - 2026-06-25

### Added

- Native OCI bundle registry: `virtkit registry push <dir> <name>:<tag>` and `virtkit
  registry pull <name>[:tag|@sha256:…]` push/pull guest bundles (`runner.ext4` +
  `boot.kind` [+ `vmlinuz` + `initrd.img`]) straight to/from an OCI registry — no
  `oras`, no docker. `runner.ext4` is split with content-defined chunking (FastCDC) and
  each chunk is zstd-compressed and stored as its own blob keyed by the sha256 of the
  compressed bytes, so bundles that share data share blobs: pushes skip blobs the
  registry already has, and pulls skip chunks already in a local content-addressed
  cache. A new `[registry]` config section (registry repo allowlist + auth/TLS) gates it.
- New `local/` source for guest bundles baked on the host filesystem, configured by a
  new `[local]` section (`dir`, defaulting to `<state_dir>/images`, + `generic_kernel`).
  Each `<dir>/<name>/` is a bundle resolved straight from disk (no fetch).
- `MICROVM_IMAGE` is now fully prefix-based (the prefix names the source, split on the
  first `/`): `local/<name>` (a `[local]` bundle), `registry/<name>[:tag|@sha256:…]` (a
  `[registry]` bundle, pulled+cached like `[convert]` caches conversions), or
  `docker/<name>[:tag|@sha256:…]` (an on-demand `[convert]` conversion). Unset =
  `local/default`.

### Changed

- The default guest bundle now boots as a generic, agent-served disk guest
  (virtkit-agent is PID 1 on the ext4 root and serves the exec channel over vsock)
  instead of a self-booting systemd image. The run stage falls back to POSIX `sh`
  only for cpio/OCI guests; disk guests keep the configured `run_command` (bash).
- **Breaking:** the `MICROVM_IMAGE: default` keyword AND the single `[image]` config
  section are both removed. The builtin bundle is replaced by the `[local]` source: a
  default guest is now the `local/default` bundle (selected by leaving `MICROVM_IMAGE`
  unset, or explicitly). A bare `<name>` is no longer a registry image — registry
  bundles now require the explicit `registry/` prefix.

## [0.1.6] - 2026-06-24

### Changed

- `virtkit build`/`mkext-oci`: the flattened rootfs is now streamed straight into the
  ext4 builder over an OS pipe instead of being written to an intermediate rootfs tar
  and read back. For a large image (the dev VM is ~8 GB / 200k+ entries) this drops a
  multi-GB write+read pass.
- The rootless buildkit daemon root now lives under `XDG_CACHE_HOME` (`~/.cache/virtkit-buildkit`)
  instead of `XDG_DATA_HOME` (`~/.local/share`). It holds a purely regenerable, GC-bounded
  build cache, so it belongs under the cache hierarchy and can be reclaimed by cache-clearing
  tools.

## [0.1.5] - 2026-06-24

### Added

- `virtkit build`: build a bootable ext4 straight from a Dockerfile target with no
  docker or podman in the image path. It drives a rootless `buildkitd` (launched
  automatically — a native user-namespace unshare, falling back to `podman unshare`
  on AppArmor-restricted hosts) to an OCI archive, then flattens it to ext4. The
  output's UUID is a content fingerprint of the resolved stage tag plus injected
  files, so an unchanged rebuild is a fast no-op. Supports `--build-arg`, `--add-host`,
  `--label`, `--inject`, `--env-file`, `--free-gib` and `--force`.
- `virtkit mkext-oci`: flatten a local OCI image archive (the tar `buildctl --output
  type=oci` produces) into a bootable ext4, extracting the image config
  (Env/User/Entrypoint/Cmd) into `/etc/virtkit/{env,user,cmd}`. Replaces the
  `podman load → create → export → mkext-tar` chain.
- `fleet` can build each unit's ext4 in-process via the `virtkit build` machinery
  instead of shelling out to the `build-{service,vm}-image.sh` scripts: `--build-dockerfile`,
  `--build-context`, `--build-arg`, `--build-add-host`, `--build-free-gib`, per-unit
  `--unit-target NAME=STAGE`, `--unit-inject NAME=H:G:M`, `--unit-env-file NAME=PATH`,
  `--unit-free-gib NAME=N` and `--agent`. Units without a recipe keep the build-script path.
- `fleet --service NAME:EXT4:IP/CIDR:CID:autostart`: the `autostart` unit flag boots the
  service at fleet start.
- `virtkit-agent serve --exec-wrapper`: gate which commands the agent may execute, with
  the inherited environment filtered to an allowlist.

### Fixed

- OCI layer flattening now preserves hard/symlink targets longer than 100 bytes (the tar
  header field limit), which previously truncated long targets (e.g. uv's deep tool
  hardlinks) and made flattening fail.

## [0.1.4] - 2026-06-23

### Added

- `fleet --vm-ssh-key PUBKEY`: authorise an SSH public key for the dev VM (repeatable).
  Keys are passed inline on the kernel cmdline (`VIRTKIT_SSH_KEYS`), not via a file on
  disk; `fleet` rejects keys that are not in OpenSSH `type base64 [comment]` format.

### Changed

- **Breaking:** renamed the dev VM from "builder" to "vm" throughout — every `fleet
  --builder*` flag is now `--vm*` (`--builder` → `--vm`, `--builder-share` →
  `--vm-share`, `--builder-symlink`, `--builder-uid-map`, `--builder-gid-map`). Update
  invocations accordingly.
- `fleet --vm-name` is now optional; when omitted the VM hostname is derived from the
  ext4 filename stem (was a fixed `builder` default). The name is validated as a
  hostname (`[A-Za-z0-9-]`).
- `virtkit-agent ssh-serve`: replaced `--authorized-keys <file>` with a repeatable
  `--authorized-key <key>` taking inline OpenSSH keys; `init` decodes them from the
  `VIRTKIT_SSH_KEYS` cmdline parameter, so no `authorized_keys` file is read from disk.

## [0.1.3] - 2026-06-23

### Added

- `virtkit fingerprint <ext4> <parts>...`: new subcommand for build scripts to check
  freshness and compute the content UUID without reimplementing the algorithm.

### Changed

- Staleness check and fingerprint recipe moved from `ensure`/`fleet` into the build
  scripts; build scripts call `virtkit fingerprint` and own the UUID comparison.
- `fleet --agent` flag removed — build scripts no longer need to be told the agent
  binary path; they hash their own inputs directly.

## [0.1.2] - 2026-06-22

### Added

- `fleet --builder-share HOST:GUEST[:ro]`: share arbitrary host directories into the
  builder VM via virtiofs (repeatable).
- `fleet --builder-symlink SRC:DEST`: create guest symlinks after virtiofs mounts,
  driven by `VIRTKIT_SYMLINKS` on the kernel cmdline (repeatable).
- `fleet --builder-uid-map` / `--builder-gid-map`: per-share UID/GID translation for
  extra builder shares using virtiofsd's `soft_idmap` (PassthroughFs) mechanism.

### Changed

- ext4 images built from a tar archive now embed a 4 MiB JBD2 journal (inode 8),
  enabling crash recovery when the image is mounted read-write via a CoW overlay.
- `virtkit-agent` service mode (`VIRTKIT_MODE=service`) now forks the entrypoint
  instead of exec-ing it, keeping the agent as PID 1 to reap orphaned processes.
  `VIRTKIT_SERVE=1` optionally starts the vsock exec server alongside the service.

## [0.1.1] - 2026-06-22

### Changed

- Switch to jemalloc as the default allocator on musl targets (same approach as ripgrep).
- Bump `oci-client` 0.15 → 0.17, `sha2` 0.10 → 0.11, `toml` 0 → 1.
- `virtiofsd`: raise `RLIMIT_NOFILE` to 1 000 000 at startup to avoid exhaustion under large file trees.

## [0.1.0] - 2026-06-19

### Added

- Initial codebase: `virtkit` (host driver) and `virtkit-agent` (guest PID 1 / exec server).
- Rootless microVM fleet over Cloud Hypervisor — no tap devices, bridges, or `CAP_NET_ADMIN`.
- Userspace L2 network switch with ARP, DHCP, DNS gateway, and transparent TCP/UDP egress via `ipstack` over `vsock`.
- OCI/Docker image pull and conversion to bootable ext4 + initramfs bundles (`convert`, `oci-pull`, `mkext-tar`, `mkext`).
- Content-addressed ext4 images: filesystem UUID fingerprints build inputs for cheap staleness checks.
- GitLab custom executor lifecycle (`gitlab config / prepare / run / cleanup`) with per-job throwaway VMs and a tap pool.
- Dev fleet orchestrator (`fleet`) — builder + service VMs on a shared `*.lan` network; `virtctl` control client.
- In-VM agent: systemd-less guest init (`init`), vsock exec server (`serve`), and SSH `ProxyCommand` bridge (`connect`).
- Bundled vhost-user virtio-fs daemon (`virtiofsd`).
- Guest kernel build pipeline (`build-kernel.sh`, `update-kernel.sh`; vanilla Linux with vendored config fragment).
- Reproducible static-musl binaries from a digest-pinned Alpine devcontainer (`build.sh`, `update.sh`).

[Unreleased]: https://github.com/wallix/virtkit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/wallix/virtkit/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/wallix/virtkit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/wallix/virtkit/compare/v0.1.10...v0.2.0
[0.1.10]: https://github.com/wallix/virtkit/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/wallix/virtkit/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/wallix/virtkit/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/wallix/virtkit/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/wallix/virtkit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/wallix/virtkit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/wallix/virtkit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/wallix/virtkit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/wallix/virtkit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/wallix/virtkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wallix/virtkit/releases/tag/v0.1.0
