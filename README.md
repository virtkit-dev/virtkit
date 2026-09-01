# virtkit

virtkit boots OCI images as rootless Linux microVMs and builds Dockerfiles without
Docker. Each guest runs its own kernel; the host side is a single static binary with an
embedded VMM, guest kernel, and agent.

`vk` runs as an ordinary user and needs read/write access to `/dev/kvm`. There is no
host daemon in the local workflow and no requirement for tap devices, bridges, firewall
rules, or `CAP_NET_ADMIN`.

Typical uses are:

- running an OCI image as a disposable development or test machine;
- building Dockerfiles without a Docker daemon, with each `RUN` isolated in a microVM;
- running compose-style service fleets on a private guest network;
- isolating GitLab custom-executor jobs in fresh VMs; and
- producing raw disks, VMDKs, OVAs, and bootable ISOs from Dockerfile-driven builds.

virtkit is Linux- and KVM-specific. Release artifacts are built for x86-64 Linux
(`x86_64-unknown-linux-musl`); this is not a cross-platform Docker Desktop replacement.

## Requirements

- An x86-64 Linux host with KVM enabled.
- Read/write access to `/dev/kvm` for the user running `vk`.
- Network access when pulling images or using guest egress.
- Docker or an existing `vk` binary only when building virtkit itself from source.

Run the host preflight before debugging a failed boot:

```sh
vk check
```

It checks KVM access, the selected VMM backend, the guest kernel and agent, and the
host-side requirements for configured features. Scripts can require a release with
`vk check --min-version 0.45`, which exits non-zero on an older `vk`.

## Quick start

```sh
# Pull Alpine and open an interactive shell in a fresh microVM.
vk run alpine:latest --shell

# Run one command and return its exit status.
vk run debian:trixie-slim -- cat /etc/os-release

# Compile the current checkout in a disposable VM. /work maps this directory,
# so target/ remains on the host after the VM exits.
vk run rust:1-alpine --workdir . --net --cpus host --mem 4G -- \
  cargo build --release

# Build the final Dockerfile stage, boot it, and run the test entrypoint.
vk run -f Dockerfile --net -- ./run-tests.sh
```

Image conversions and Dockerfile build results are content-addressed and reused on
later runs. Use `vk help <command>` for full command documentation; short `-h` output is
kept intentionally compact.

## Core workflows

### Run an OCI image

`vk run IMAGE` pulls the image, converts its root filesystem to a bootable ext4 disk,
starts a microVM, and executes either the requested command or a shell. By default the
guest uses virtkit's embedded kernel and runs `vk-agent` as PID 1.

Use `--net` to allow guest egress. Networking is implemented by a userspace switch in
the `vk` process, and outbound traffic leaves through ordinary host sockets. The host
does not need a bridge, tap device, or firewall changes.

For images intended to boot as full machines, `--kernel image --init image` loads the
image's `/boot/vmlinuz`, modules, and init system. `--init entrypoint` instead runs the
image's ENTRYPOINT and CMD as PID 1. A kernel supplied with `--kernel <path>` is also
supported.

`--nested` exposes KVM to the guest so it can run microVMs of its own. The host must have
KVM nesting enabled (`kvm_intel.nested=1` or `kvm_amd.nested=1`), which the flag checks
before pulling or building anything. Treat this as a grant for trusted guests: nested
virtualization reaches the host kernel's KVM paths.

### Build a Dockerfile

`vk build` evaluates Dockerfiles directly; it does not call Docker. Each `RUN` executes
in a microVM, instruction snapshots are cached, and independent stages may build in
parallel. `vk run -f Dockerfile` is the convenient build-and-run form.

A stage can declare resources without making the Dockerfile incompatible with Docker:

```dockerfile
# vk: mem=8G cpus=16
FROM rust:1-alpine AS build
RUN cargo build --release
```

Per-run overrides take precedence:

```sh
vk build --stage-mem build=12G --stage-cpus build=8 -f Dockerfile --out rootfs.ext4
```

The resource hint is a comment and does not enter the instruction cache key. When a
stage asks for more memory than the host can allocate to one guest, virtkit clamps the
request and emits a warning explaining the effective size and OOM risk.

Builds report each stage's peak guest memory as the stage finishes and in a block under
the final timing breakdown:

```
 Stage memory (peak demand / guest size)
  [build]     3.1 GiB of 8.0 GiB
  [runtime]   412 MiB of 4.0 GiB
```

The guest measures `MemTotal - MemAvailable`, excluding reclaimable page cache so the
result reflects demand rather than every page touched. The per-stage line is printed as a
stage finishes, so a stage that fails has none; the final block still lists whatever its
guests had reported by then.

### Run compose services

`vk run --compose compose.yml` boots services as separate VMs on a shared network. Each
service resolves by name. Services can run alongside a primary command, as the primary
with `--primary`, or as a standalone fleet until interrupted.

virtkit-specific service settings live under `x-virtkit`:

Services default to 2 vCPUs and 1 GiB of memory. Set `cpus` and `mem` when a service
needs a different guest size:

```yaml
services:
  database:
    image: postgres:17
    x-virtkit:
      cpus: 2
      mem: 2G
  builder:
    image: local/builder
    x-virtkit:
      nested: true
```

`--service-cpus NAME=N` and `--service-mem NAME=SIZE` override those values for one run.
The same marker supports `init` and `kernel` for services that boot their own system.

Inside the primary guest, `/run/vk/services/<name>/{state,ctl,log}` exposes service
state, control, and logs through ordinary files. `vk service up|down|status` provides the
corresponding command interface. `vk run --ssh` enables SSH access for development VMs,
including VS Code Remote-SSH workflows.

### Isolate GitLab jobs

The GitLab custom executor creates a fresh microVM for each job and destroys it during
cleanup. Job images from `.gitlab-ci.yml` are converted on demand. A repository can also
use `image: dockerfile:…` to build its job image directly from a checked-in Dockerfile.

The executor supports concurrent jobs, service VMs, per-phase egress policy, resource
accounting, and optional host-load throttling through `vk-runnerctl`. Configuration and
the security model are covered in the [GitLab CI guide](docs/gitlab-ci.md).

### Build appliances

`vk build --disk` lets a Dockerfile stage partition and install a bootloader into a
caller-owned raw disk. That disk can then be packaged natively, without `qemu-img`,
`ovftool`, or `xorriso` on the host:

```sh
vk export vmdk disk.raw appliance.vmdk
vk export ova disk.raw appliance.ova
vk export iso staged-root installer.iso \
  --bios-boot boot/grub/eltorito.img \
  --efi-boot boot/grub/efi.img \
  --hybrid-mbr isohdpfx.bin
```

VMDK output uses VMware's streamOptimized format; OVA output is ready for ESXi/vCenter
import. ISO output can include BIOS and UEFI boot images, plus an optional hybrid MBR for
USB media. See the [appliance guide](docs/appliance.md) for the expected disk and
staged-tree layouts.

## Operational behavior

### Isolation and privilege

Each guest has its own kernel. The default local path is rootless and daemonless, but
the isolation boundary still depends on KVM and the selected VMM. Guest networking is
userspace-only on the host. Nested KVM should be reserved for trusted workloads.

`vk-runnerctl` is the one optional component designed to run as root. It accepts no
caller-controlled arguments or paths; it only applies the configured GitLab runner
concurrency range. Local image execution and building do not require it.

### Resource accounting

Builds, `vk run`, and CI jobs report host CPU time, peak memory, disk traffic, and guest
network traffic when they finish. Concurrent builds and compose fleets also identify the
largest host process, which helps distinguish an oversized guest from excessive
concurrency.

Treat the CPU, memory, and disk figures as ceilings: they include `vk` and its host
helpers alongside the guests. Network figures cover guest traffic alone because
host-side image pulls do not cross the userspace switch that counts it.

CI jobs also report how much of the guest's writable layer they filled. That layer can
hit `ENOSPC` while the host still has free disk space.

By default, each CI guest records an `atop -P`-compatible sample every 10 seconds,
covering CPU, memory, disk, network, and process activity. `vk atop` follows a running
recording or inspects one retained after the job VM has been removed. See the
[resource-usage documentation](docs/gitlab-ci.md#resource-usage) for accounting
boundaries and interpretation.

### Caching and registries

Local image conversion and build caches require no server. `vk-registry` is optional and
is useful when several runners need a shared OCI store, pull-through cache, or build-once
coordination. Its lease and heartbeat protocol prevents runners from independently
building the same content while a healthy peer is already doing so.

Use `vk registry push|pull|inspect` for guest bundles and `vk registry status|gc` for a
local store. The central server and storage model are documented in
[`vk-registry/DESIGN.md`](vk-registry/DESIGN.md).

## Binaries

| Binary | Purpose |
| --- | --- |
| `vk` | Host CLI, VMM, image builder, userspace network, compose runner, and GitLab executor. It embeds the default guest kernel and `vk-agent`. |
| `vk-agent` | Guest PID 1 and command server. It configures mounts, networking, hostname, shared directories, optional SSH, and host-driven execution over vsock. |
| `vk-registry` | Optional OCI-distribution server with a pull-through cache, shared build cache, and build-once locking. |
| `vk-runnerctl` | Optional root-side helper that adjusts GitLab runner concurrency within an administrator-configured range. |

## Architecture

The default VMM is the embedded [libkrun](https://github.com/containers/libkrun). An
external [Cloud Hypervisor](https://www.cloudhypervisor.org/) binary can be selected with
the `vmm` configuration key or `VIRTKIT_VMM=cloud-hypervisor`.

The host converts OCI layers to native ext4 images in userspace. Build inputs identify
cached disks and instruction snapshots. Guests communicate with the host over vsock for
command execution, service control, and CI lifecycle operations. Guest Ethernet frames
are handled by the in-process userspace switch, which provides ARP, DHCP, DNS, and TCP/UDP
egress through host sockets.

Release binaries are static musl PIE executables. The Rust toolchain, Alpine build image,
packages, guest kernel, and vendored libkrun source are pinned so release artifacts can be
rebuilt byte-for-byte.

## Command guide

| Command | Use it for |
| --- | --- |
| `vk run` | Boot an image, Dockerfile target, or compose fleet; run a command or shell. |
| `vk build` | Build Dockerfile stages into a bootable ext4 image or caller-owned disk. |
| `vk exec` | Run a command in an existing guest and return the command's exit status. |
| `vk list` | Discover registered background VMs and compose services. |
| `vk stop` | Stop a VM selected by pid or launch directory, or stop all registered VMs. |
| `vk status` | Probe a guest agent, or report whether its root image is stale. |
| `vk atop` | Follow or inspect guest resource recordings. |
| `vk check` | Validate KVM, VMM, embedded assets, configured host features, and an optional minimum `vk` version. |
| `vk gc` | Reclaim unused image bases, CI checkouts, and image-cache chunks. |
| `vk update` | Check for or install a digest-verified GitHub release. |
| `vk service up|down|status` | Control compose services from the primary guest. |
| `vk registry ...` | Publish, fetch, inspect, report on, or sweep OCI stores. |
| `vk gitlab ...` | Implement the GitLab custom-executor lifecycle. |
| `vk export ...` | Package raw disks or staged files as VMDK, OVA, or ISO artifacts. |

Advanced commands are listed by `vk help-all`. They include the stdio/vsock connector,
network forwarding processes, SSH agent proxy, path inspection, OCI/ext4 conversion
tools, image fingerprinting, and the bundled Cloud Hypervisor `virtiofsd`.

## Configuration

`vk` uses the first configuration source that applies:

1. `--config <path>`
2. `$VIRTKIT_CONFIG`
3. `$XDG_CONFIG_HOME/virtkit/config.toml`, or `~/.config/virtkit/config.toml`
4. `/etc/virtkit/config.toml`

An explicit path that does not exist is an error. Standard user and system paths are
optional. With no configuration file, local `run` and `build` workflows use defaults.

```sh
vk config             # print the effective TOML and its source
vk config --example   # print the annotated reference configuration
vk config --path      # print the resolved configuration path
vk paths              # print resolved state, cache, and registry paths
```

[`vk-driver/config.example.toml`](vk-driver/config.example.toml) documents every key.
The small environment-variable surface is:

| Variable | Effect |
| --- | --- |
| `VIRTKIT_CONFIG` | Select a configuration file. |
| `VIRTKIT_VMM` | Override the VMM backend; currently useful for `cloud-hypervisor`. |
| `VIRTKIT_DEBUG=1` | Enable verbose VMM and guest logging. |
| `VIRTKIT_TIMING=1` | Print per-phase build and boot timing. |
| `VIRTKIT_PROGRESS=plain` | Use line-oriented build progress suitable for CI logs. |
| `VIRTKIT_NO_TITLE` | Disable terminal-title updates without disabling the dashboard. |

Two configuration values can point at the same content-addressed store:

- `[build] cache_registry` stores build stages and base snapshots in `build-cache`.
- `[registry] repo` stores named bootable guest bundles.

Each accepts either a registry endpoint or a local absolute path/`file://` URL. Pointing
both local settings at one directory enables chunk deduplication across build cache and
guest bundles. `cache_registry = "none"` disables future build-cache writes. Use
`vk registry status` and `vk registry gc` to inspect and reclaim a local store.

`vk-registry` has a separate configuration namespace. Its store-oriented subcommands
recognize `VK_REGISTRY_CONFIG`, `VK_REGISTRY_ROOT`, and
`VK_REGISTRY_ADMIN_SOCKET` as documented in its design file and command help.

## Build from source

Build the pinned guest kernel first, then the static binaries:

```sh
./build-kernel.sh  # dist/vmlinux
./build.sh         # dist/{vk,vk-agent,vk-registry,vk-runnerctl,...}
```

The scripts use a `vk` found on `PATH` to build inside a microVM; otherwise they use
Docker. Pass `--docker` to force Docker. `build.sh --use-virtkit=<dist>` selects a
specific existing virtkit build.

`vk` normally embeds `dist/vmlinux`, so `build.sh` refuses to proceed when the kernel is
missing. `--no-kernel` produces a non-shippable binary that requires `--kernel` at
runtime. The kernel changes less often than the Rust binaries, so one kernel build can be
reused across normal edit/build cycles.

For iteration, use the repository's development commands:

```sh
./dev.sh check -p vk-core                          # one crate, while iterating
./dev.sh test -p vk-core --lib dockerignore::tests # one module's tests
./dev.sh check && ./dev.sh clippy && ./dev.sh test # the whole workspace, before committing
./build.sh --fast  # only when a runnable debug vk is needed
```

Release builds use the pinned toolchain and produce reproducible artifacts. `--fast`
uses the unoptimized development profile and is not a release artifact.
`./build.sh --bootstrap-check` performs a Docker build, rebuilds with the resulting `vk`,
and compares the binaries byte-for-byte.

## Repository layout

```text
vk-core/         shared host/guest protocol and runtime helpers
vk-driver/       host driver, builder, VMM, networking, compose, and GitLab executor
vk-agent/        guest PID 1 and exec server
vk-registry/     optional central OCI store and distribution server
vk-runnerctl/    optional root-side GitLab concurrency helper
vk-selfupdate/   shared self-update implementation for vk and vk-registry
vk-fs/           filesystem objects created private and published whole
third_party/     vendored libkrun and local patches
kernel/          pinned guest-kernel configuration and build inputs
docs/            operational guides
build.sh         reproducible binary build
build-kernel.sh  reproducible guest-kernel build
dev.sh           check/lint/test environment in a reusable development VM
```

## License

Copyright © Vincent Vanackere and WALLIX. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
