# Changelog

All notable changes to virtkit will be documented in this file.

## [Unreleased]

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

[Unreleased]: https://github.com/wallix/virtkit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/wallix/virtkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wallix/virtkit/releases/tag/v0.1.0
