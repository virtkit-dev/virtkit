# virtkit

Run Docker images as lightweight virtual machines — no root, no daemon, no setup.

virtkit boots any OCI/Docker image as a microVM that starts in about a second
and gets its own kernel, so whatever runs inside is fully isolated from the
host. Everything ships in two static binaries and runs as an ordinary user
process: the only thing it needs from the host is access to `/dev/kvm`.

From one tool you get a local **dev fleet** (a dev VM plus service VMs, like
docker-compose but with real VMs) and a **GitLab CI executor** (a fresh,
throwaway VM for every job) — and each piece (image building, networking, the
in-VM agent) is usable on its own.

## A taste

```sh
# boot an image and step inside
vk run alpine:latest --shell

# compile the current tree in a throwaway microVM: /work is this directory,
# so target/ lands back on the host
vk run rust:1-alpine --workdir . --net --cpus host --mem 4G -- cargo build --release

# build a Dockerfile (each RUN in its own microVM, instruction-cached),
# boot the resulting image and run a command in it
vk run -f Dockerfile --net -- ./run-tests.sh
```

## What you can do with it

- **Boot Docker images directly.** `vk run alpine:latest --shell` pulls the
  image, converts it to a bootable disk, and drops you into a shell.
  Conversions are cached and only redone when the image actually changes.
- **Give VMs internet access with a flag.** Pass `--net` and the VM can reach
  the network — no bridges, tap devices, or firewall rules to configure on the
  host, and no privileges needed.
- **Run a dev fleet.** `vk fleet` boots your dev VM alongside service VMs
  (redis, mysql, …) on a shared network where every VM is reachable as
  `<name>.lan`. From inside the dev VM, start and stop services on demand with
  `virtctl` (expose it with
  `fleet --vm-symlink /usr/local/bin/vk-agent:/usr/local/bin/virtctl`).
- **Isolate GitLab CI jobs.** The custom executor gives every job a fresh
  microVM and destroys it when the job ends. Concurrent jobs are supported, and
  Docker images from your `.gitlab-ci.yml` are converted on demand.
- **Build Dockerfiles without Docker.** `vk build` runs each `RUN` instruction
  in its own microVM, with per-instruction caching, and produces an image you
  can boot straight away.
- **Carry one file around.** The hypervisor, the guest kernel, and the guest
  agent are all embedded in `vk` — copy it to a Linux machine with `/dev/kvm`
  and it boots images. virtkit can even rebuild itself inside one of its own
  microVMs (`./build.sh --bootstrap-check`).

## The two binaries

| Binary | Role |
| --- | --- |
| `vk` | The host-side tool. Boots and manages VMs, builds and converts images, runs the fleet and the GitLab executor, and provides the guest network. Self-contained: the guest kernel and `vk-agent` are embedded. |
| `vk-agent` | Runs inside the guest as PID 1. Brings the system up (mounts, networking, hostname, shared folders, optional SSH) and lets the host run commands inside the VM. |

## Under the hood

For the curious — none of this is needed to use the tool:

- Guests boot on an embedded [libkrun](https://github.com/containers/libkrun)
  VMM, so there is no external hypervisor to install; a stock kernel and stock
  KVM are enough. [Cloud Hypervisor](https://www.cloudhypervisor.org/) is also
  supported as an external backend (`VIRTKIT_VMM=cloud-hypervisor`).
- Guest networking is a userspace switch living inside the `vk` process:
  traffic leaves through the host's regular sockets, which is why no privileged
  network setup is ever required.
- Images are converted to native ext4 disks entirely in userspace, and each
  disk is fingerprinted by its build inputs — checking whether a cached image
  is stale is instant.
- The host talks to guests over `vsock`: the same channel carries shells, CI
  job stages, and fleet control.
- The release binaries are static (musl) and built from a fully pinned Alpine
  toolchain, so builds are byte-for-byte reproducible; `./update.sh` records
  the pins.

## Build

```sh
./build.sh         # -> dist/{vk, vk-agent, *.sha256, build-info.txt}
./build-kernel.sh  # -> dist/vmlinux (the guest kernel; rebuilt only on a pin bump)
```

Both run inside a pinned `rust:*-alpine` container (Docker required), so the
artifacts are byte-reproducible regardless of host. `./update.sh` bumps the Rust
toolchain, the base-image digest and the apk pins together.

## Subcommands

`vk`:

- `run` — boot an image (or a Dockerfile target) as a microVM and run a command
  or an interactive shell in it.
- `fleet` — orchestrate the dev fleet (dev VM + service VMs on one LAN).
- `gitlab config` / `gitlab prepare` / `gitlab run` / `gitlab cleanup` — the GitLab custom-executor lifecycle.
- `build` — build a Dockerfile into a bootable image, each `RUN` in a microVM.
- `switch` — the guest network gateway (run in-process by `fleet`).
- `mkext-tar` / `mkext` — build a bootable ext4 image from a rootfs tar / directory.
- `oci-pull` — pull and flatten an OCI image to a rootfs tar.
- `registry push` / `registry pull` — push/pull guest bundles to/from an OCI
  registry, with chunk-level deduplication to keep transfers small.
- `virtiofsd` — the bundled virtio-fs daemon for sharing host directories
  (used with the Cloud Hypervisor backend).
- `forward` / `launch` — plumbing: byte forwarder / standalone microVM launcher.

`vk-agent`:

- `init` — PID 1 for the guest (also runs the image's entrypoint or hands off
  to systemd, depending on `VIRTKIT_MODE`).
- `serve` — the in-VM command server; `exec` / `connect` / `forward` are the
  host-side clients (e.g. `connect` works as an SSH `ProxyCommand`).
- `net` — connect a guest NIC to the host's network switch.
- Invoked as `virtctl` (a symlink exposed via `fleet --vm-symlink`), it is the
  fleet control client (`virtctl start <unit>`, …).

## Layout

```
vk-core/         shared host↔guest library (wire protocol + exec/pty/dockerignore)
vk-driver/       host driver crate
vk-agent/        guest agent crate (PID 1 + exec server)
third_party/     vendored libkrun (locally patched — see its VENDOR.md)
kernel/          guest kernel build (Dockerfile + config fragment)
build.sh         build the binaries -> dist/
build-kernel.sh  build the guest kernel -> dist/vmlinux
update.sh        bump + re-pin toolchain / base image / apk versions
```

## License

Copyright © Vincent Vanackere and WALLIX. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
