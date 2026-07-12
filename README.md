# virtkit

virtkit runs Docker images as lightweight virtual machines. It boots an OCI
image as a microVM in about a second, each with its own kernel, so whatever
runs inside is isolated from the host. There's no daemon and nothing to install
as root: it's two static binaries running as an ordinary user process, and the
only thing it needs from the host is access to `/dev/kvm`.

On top of that base you get docker-compose-style services running as real VMs
(per run or long-lived) and a GitLab CI executor that hands every job a fresh,
throwaway VM. The pieces underneath — image building, networking, the in-VM
agent — also work on their own.

## A few examples

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

## What it does

Boot Docker images directly. `vk run alpine:latest --shell` pulls the image,
converts it to a bootable disk, and drops you into a shell. Conversions are
cached and only redone when the image actually changes.

Give a VM internet access with a flag. Pass `--net` and the VM can reach the
network. There are no bridges, tap devices, or firewall rules to set up on the
host, and it doesn't need privileges.

Run compose services as VMs. `vk run --compose compose.yml` boots the services
(redis, mysql, and so on) on a shared network where each one resolves by name.
You can run them alongside your command, as the primary itself (`--primary`,
like `docker compose run`), or on their own (compose up, until ctrl-c). From
inside the primary, `/run/vk/services/<name>/{state,ctl,log}` lets you read
service state and start or stop services with plain shell writes. For a dev VM,
`vk run --ssh` boots any image with SSH access, and VS Code Remote-SSH works
against it out of the box.

Isolate GitLab CI jobs. The custom executor gives every job a fresh microVM and
destroys it when the job ends. Concurrent jobs work, and Docker images from your
`.gitlab-ci.yml` are converted on demand.

Build Dockerfiles without Docker. `vk build` runs each `RUN` instruction in its
own microVM, caches per instruction, and produces an image you can boot straight
away.

Carry one file around. The hypervisor, the guest kernel, and the guest agent are
all embedded in `vk`, so you can copy it to any Linux machine with `/dev/kvm`
and boot images. virtkit can even rebuild itself inside one of its own microVMs
(`./build.sh --bootstrap-check`).

## The two binaries

| Binary | Role |
| --- | --- |
| `vk` | The host-side tool. Boots and manages VMs, builds and converts images, runs the GitLab executor, and provides the guest network. Self-contained: the guest kernel and `vk-agent` are embedded. |
| `vk-agent` | Runs inside the guest as PID 1. Brings the system up (mounts, networking, hostname, shared folders, optional SSH) and lets the host run commands inside the VM. |

## How it works

You don't need any of this to use the tool, but if you're curious:

Guests boot on an embedded [libkrun](https://github.com/containers/libkrun)
VMM, so there's no external hypervisor to install; a stock kernel and stock KVM
are enough. [Cloud Hypervisor](https://www.cloudhypervisor.org/) also works as
an external backend (`VIRTKIT_VMM=cloud-hypervisor`).

Guest networking is a userspace switch living inside the `vk` process. Traffic
leaves through the host's regular sockets, which is why no privileged network
setup is ever required.

Images are converted to native ext4 disks entirely in userspace. Each disk is
fingerprinted by its build inputs, so checking whether a cached image has gone
stale is instant.

The host talks to guests over `vsock`, and the same channel carries shells, CI
job stages, and service control.

The release binaries are static (musl), built from a fully pinned Alpine
toolchain, so builds are byte-for-byte reproducible. `./update.sh` records the
pins.

## Build

```sh
./build.sh         # -> dist/{vk, vk-agent, *.sha256, build-info.txt}
./build-kernel.sh  # -> dist/vmlinux (the guest kernel; rebuilt only on a pin bump)
```

Both run inside a pinned `rust:*-alpine` container (Docker required), so the
artifacts come out byte-reproducible regardless of the host. `./update.sh` bumps
the Rust toolchain, the base-image digest, and the apk pins together.

## Subcommands

`vk`:

- `run` — boot an image (or a Dockerfile target) as a microVM and run a command
  or an interactive shell in it.
- `gitlab config` / `gitlab prepare` / `gitlab run` / `gitlab cleanup` — the GitLab custom-executor lifecycle.
- `build` — build a Dockerfile into a bootable image, each `RUN` in a microVM.
- `switch` — the guest network gateway (spawned per run/job).
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
