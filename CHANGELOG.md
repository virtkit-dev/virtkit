# Changelog

All notable changes to virtkit will be documented in this file.

## [Unreleased]

### Changed

- The default guest bundle now boots as a generic, agent-served disk guest
  (virtkit-agent is PID 1 on the ext4 root and serves the exec channel over vsock)
  instead of a self-booting systemd image. The run stage falls back to POSIX `sh`
  only for cpio/OCI guests; disk guests keep the configured `run_command` (bash).

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

[Unreleased]: https://github.com/wallix/virtkit/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/wallix/virtkit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/wallix/virtkit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/wallix/virtkit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/wallix/virtkit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/wallix/virtkit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/wallix/virtkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wallix/virtkit/releases/tag/v0.1.0
