# virtkit

A **rootless toolkit for [Cloud Hypervisor](https://www.cloudhypervisor.org/)
microVMs**, in two small static binaries.

virtkit boots OCI/Docker images (or assembled rootfs) as fast Cloud Hypervisor
microVMs, gives them a shared LAN with egress through ordinary host sockets (no tap,
no bridge, no `CAP_NET_ADMIN`, no root), and drives commands into them over `vsock`.
From one codebase it powers, for example, a local **dev fleet** (a builder VM + service
VMs, like docker-compose but as VMs) and a **GitLab custom executor** (one throwaway VM
per CI job) — but the pieces (image building, the network switch, the in-VM agent) are
usable on their own.

## The two binaries

| Binary | Role |
| --- | --- |
| `virtkit` | **host driver** — image building/conversion, the fleet orchestrator + control plane, the GitLab executor, the userspace network switch, and a bundled virtio-fs daemon. |
| `virtkit-agent` | **guest PID 1 / agent** — brings a systemd-less guest up (mounts, networking, hostname, virtio-fs, optional SSH), and serves an exec channel over `vsock` so the host can run commands inside the VM. |

## Features

- **No host privileges.** A userspace L2 switch (ARP + DHCP + a DNS gateway, with
  transparent TCP/UDP egress via [`ipstack`](https://crates.io/crates/ipstack))
  carries guest traffic over `vsock` — no tap devices, bridges, or root.
- **microVM fleet.** Boot a builder + service VMs (redis, mysql, …) on one shared
  `*.lan` network; start/stop them on demand with the in-VM `virtctl` client.
- **GitLab CI executor.** A custom executor that boots a fresh microVM per job, runs
  each stage over `vsock`, and tears it down — with a tap pool for concurrent jobs and
  on-demand OCI-image conversion.
- **Content-addressed images.** `mkext-tar` streams a `docker export` straight into a
  native ext4 image (no `mke2fs`, no root); the filesystem UUID is a fingerprint of
  the build inputs, so staleness is a UUID compare.
- **Batteries included.** The guest kernel (`build-kernel.sh`) and a vhost-user
  virtio-fs daemon (`virtkit virtiofsd`) are built/bundled by virtkit itself — no
  separate binaries to track.
- **Reproducible builds.** Static-musl binaries from a digest-pinned Alpine toolchain
  with pinned apk versions; `./update.sh` records the pins.

## Build

```sh
./build.sh         # -> dist/{virtkit, virtkit-agent, SHA256SUMS, build-info.txt}
./build-kernel.sh  # -> dist/vmlinux (the guest kernel; rebuilt only on a pin bump)
```

Both run inside a pinned `rust:*-alpine` container (Docker required), so the artifacts
are byte-reproducible regardless of host. `./update.sh` bumps the Rust toolchain, the
base-image digest and the apk pins together.

## Subcommands

`virtkit`:

- `fleet` — orchestrate the dev fleet (builder + service VMs on one LAN).
- `gitlab config` / `gitlab prepare` / `gitlab run` / `gitlab cleanup` — the GitLab custom-executor lifecycle.
- `switch` — the userspace L2 network gateway (run in-process by `fleet`).
- `mkext-tar` / `mkext` — build an ext4 image from a rootfs tar / directory.
- `convert` / `oci-pull` — pull and convert OCI images to bootable bundles.
- `virtiofsd` — the bundled vhost-user virtio-fs daemon.
- `forward` / `launch` — byte forwarder / standalone microVM launcher.

`virtkit-agent`:

- `init` — PID 1 for a systemd-less guest (also runs the captured entrypoint /
  hands off to systemd, depending on `VIRTKIT_MODE`).
- `serve` — the exec server (`vsock`); `exec` / `connect` / `forward` are the host-
  side clients (e.g. `connect` is an SSH `ProxyCommand` over `vsock`).
- `net` — bridge a guest tap NIC to the host switch over `vsock`.
- Invoked as `virtctl`, it is the fleet control client (`virtctl start <unit>`, …).

## Layout

```
virtkit/         host driver crate
virtkit-agent/   guest agent crate (PID 1 + exec server)
kernel/          guest kernel build (Dockerfile + config fragment)
build.sh         build the binaries -> dist/
build-kernel.sh  build the guest kernel -> dist/vmlinux
update.sh        bump + re-pin toolchain / base image / apk versions
```

## License

Copyright © Vincent Vanackere. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
