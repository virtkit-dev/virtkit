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

[`examples/compose.yaml`](examples/compose.yaml) exercises everything below in one
annotated file; it is parsed by the test suite, so it always matches what `vk` accepts.

#### The file

A compose file is `services:` and nothing else (a deprecated `version:` is accepted and
ignored). vk parses it strictly: an unknown key anywhere is an error, so a docker `volumes:`
or `networks:` section is refused rather than skipped, and named volumes are not supported —
bind a path. A service uses `image:` or `build:`, plus any of `environment`, `env_file`,
`command`, `entrypoint`, `user`, `hostname`, `depends_on`, `volumes`, `profiles` and the
`x-virtkit` marker. Every host path is relative to the compose file.

#### Images and builds

`image:` names an OCI image, pulled and converted host-side and shared across runs.
`build:` is a directory (`build: ./app`) or a mapping:

```yaml
services:
  app:
    build:
      context: ./app
      dockerfile: [Dockerfile, Dockerfile.dev]   # several files merge into one stage namespace
      target: runtime                            # any stage across them
      args:
        UID: "$VK_UID"                           # bare and braced both interpolate; keeps a
        GID: "${VK_GID}"                         # shared tree's ownership coherent
      additional_contexts:
        assets: ./assets                         # `COPY --from=assets`; local directories only
```

Built images are content-addressed and reused; a `build:` sibling is built on its first
start (`vk service up` streams the build), the `--primary` service up front.

#### Environment and interpolation

`environment:` (map or list) upserts over the image's own environment; `env_file:` is a
path, a list of paths, or `{path, required: false}` entries, layered beneath it.
`entrypoint:` replaces the image's entrypoint *and* drops its command; `command:` alone
replaces only the command; `user:` replaces the user. `hostname:` (a DNS label) defaults to
the service name and is what other services resolve.

Values interpolate `$VAR`, `${VAR}` and `${VAR:-default}` from the environment over a
sibling `.env`; `$$` is a literal `$`. An unset variable with no default **fails the load**
— an empty image tag or bind path is always a bug — and the other docker modifiers (`:?`,
`:+`, `${VAR-default}`) are rejected. Five reserved names come from the run itself, so a
committed file needs no host paths or ids: `${VK_WORKSPACE}` (`--workspace`, else the
cwd), `${VK_STATE_DIR}` (`--state-dir`, else the run's scratch), `${VK_SELF}` (the running
`vk`, to hand a guest its own copy), `${VK_UID}` and `${VK_GID}`. A variable holding several
newline-separated binds expands into several `volumes:` entries.

#### Start order and profiles

`depends_on` (a list, or a map whose only accepted `condition:` is `service_started`)
orders starts; there is no readiness wait, so retry a first connection. Services with
`profiles:` stay declared but down unless a profile is activated (`--profile NAME`,
repeatable) or an enabled service depends on them; `vk service up NAME` starts one anyway.

#### Guest size, init, kernel and NICs

virtkit-specific settings live under `x-virtkit`. Services default to 2 vCPUs and 1 GiB of
memory; set `cpus` and `mem` when a service needs a different guest size, and `nested: true`
for a service that runs microVMs of its own (the host must allow nesting):

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
    volumes:
      - ${VK_SELF}:/usr/local/bin/vk:ro          # the host's own vk, for nested builds
```

`--service-cpus NAME=N` and `--service-mem NAME=SIZE` override those values for one run.
`init` chooses PID 1 — `default` (the vk agent), `image` (the image's own `/sbin/init`) or
`entrypoint` (its ENTRYPOINT+CMD) — and `kernel` the kernel: `default` (the pinned guest
kernel), `image` (the image's own kernel and modules) or a kernel file path. Together they
boot a systemd or otherwise self-booting image as a service. `persist_root` keeps the root
filesystem across restarts (see [Volumes and persistent state](#volumes-and-persistent-state)).

Guests give idle memory back. Pages one frees return to the host through the balloon, and a
guest not under memory pressure also evicts the file cache it has not touched for a minute or
two (by age, through the kernel's multi-gen LRU) and hands those pages back, so a dev VM that
read a few gigabytes while building stops holding them once it idles, while what a running
build keeps re-reading stays cached. That is `reclaim: auto`; `off` keeps everything, a size
(`512M`) or share (`5%`) keeps that much as a fixed floor. `vk run --reclaim` sets it for the
primary and any service without its own, `[vm] reclaim` for the GitLab executor. It needs the
agent as PID 1, so an `init` of `image` or `entrypoint` opts out; `vk build` stage guests are
left alone as well, since trimming would move the peak-memory mark they are measured by.

A guest gets one interface, `eth0`, by default. `nics` gives it more — `eth1` upward, each
with its own address on the same LAN — for an appliance that assigns services to separate
interfaces:

```yaml
services:
  appliance:
    image: local/appliance
    x-virtkit:
      nics: 3
```

`--service-nics NAME=N` overrides that for one run, like `--service-cpus`/`--service-mem`.
`vk run --nics N` does the same for the primary VM (it needs `--net`, which `--compose`
implies). `eth0` keeps the default route and stays the address a service name resolves to;
the extra interfaces are addressed but given no route, so egress leaves through `eth0`
unless the guest routes it elsewhere. Every interface is a real port on the LAN: each has
its own MAC, answers ARP, and can carry its own listening services — which is what an
appliance separating admin from user traffic needs. Up to 8 per guest;
`vk check --feature nics` reports whether a `vk` supports them.

#### Volumes and persistent state

A service starts from a clean copy of its image every time: its root filesystem is a
throwaway layer over the image, and `volumes:` bind host paths into the guest. A bind is
`host:guest[:mode]`, with the host path relative to the compose file:

| mode | the guest sees | writes go |
|------|----------------|-----------|
| `rw` (default), `ro` | the host directory or file, live | to the host (`rw`), or are refused (`ro`) |
| `overlay` | the host tree, read-only underneath | to guest RAM — fast, gone at reboot |
| `overlay,persist[,size=SIZE]` | the host tree, read-only underneath | to a disk kept next to the compose file |
| `disk[,size=SIZE]` | a private filesystem of its own | to that disk; the host path is its image |
| `socket` | a unix socket at the guest path | each connection is relayed to the host socket |

`overlay` is for build trees and checkouts: reads come from the host, every write lands
in guest memory and never touches the host tree. Add `persist` to keep those writes on
disk instead. `disk` is for data that needs real filesystem semantics (ownership, sockets,
device nodes) a shared directory cannot offer — a database's data directory, say. `socket`
forwards a host service's unix socket and is implied when the host path is one — for
example, `/var/run/docker.sock:/var/run/docker.sock` lets the guest drive the host's Docker.
Only bytes cross over vsock, so the guest never learns the host path, but it receives
everything the socket grants: a Docker socket is host-root-equivalent, so grant it
deliberately. Shares take `,optional` to skip a bind whose source is absent; `size=` (`10G`,
`512M`) sets a new disk's capacity and is ignored once it exists.

Set `persist_root` when the whole root must persist — an appliance whose state is not
confined to a few directories:

```yaml
services:
  appliance:
    build: ./appliance
    x-virtkit:
      persist_root: true                       # / survives restart and down/up
    volumes:
      - ./config:/etc/appliance:ro
  database:
    image: postgres:17
    volumes:
      - ./pgdata.qcow2:/var/lib/postgresql:disk,size=20G
  builder:
    image: local/builder
    volumes:
      - ./src:/workspace:overlay                # scratch: reads from the host, writes in RAM
      - ./cache:/root/.cache:overlay,persist    # keeps its writes across restarts
```

Persistent state — a `persist_root` root, an `overlay,persist` layer — survives an in-guest
reboot, `vk service down`/`up`, and stopping and later restarting the run. It lives under
`.virtkit/` beside the compose file (add it to `.gitignore`), and is reset when what it
was built on changes: a new image rebuilds a persistent root from scratch, and a new image
or a changed host tree discards a persistent overlay's writes. A `disk` volume persists
unconditionally; delete its file to start over. All of this applies alike to a service
booted with `--primary` and to its siblings; ad-hoc `-v` binds on `vk run` accept every
mode but `overlay,persist`, which has no compose file to keep its state beside.

#### Running the fleet

`vk run --compose FILE` with an image or `-f` boots that as the primary VM and the services
beside it, torn down when the run exits. `--primary NAME` boots a compose service as the
primary instead — `docker compose run` semantics: its image is the rootfs, its config the
command's environment, with no trailing command its entrypoint and command run, and only
its `depends_on` chain boots alongside. With neither, `--compose` alone is compose up: the
services only, held until Ctrl-C.

Inside the primary guest, `/run/vk/services/<name>/{state,ctl,log}` exposes service
state, control, and logs through ordinary files. `vk service up|down|reboot|status` is the
corresponding command interface: `up` starts a declared (or profiled-down) service, building
it on first use; `down` powers it off; `reboot` restarts its guest in place on the same
disks; `status` reports one or all. `vk run --ssh` enables SSH access for development VMs,
including VS Code Remote-SSH workflows. In a CI fleet a service's `environment:` may also
carry its own egress allowlist — see [Per-service egress](docs/gitlab-ci.md#per-service-egress).

### Manage running VMs

A `vk run --state-dir DIR` boots a VM that outlives a single command: its sockets and
console log live in DIR, and the run is recorded in a host-side registry. `vk list` reads
that registry, dropping entries whose run has died, and is what `vk exec`, `vk status`,
`vk logs`, `vk stop` and `vk reboot` resolve a directory against — `vk logs` also reads the
console of a VM the registry has already dropped, since DIR keeps it. A run without
`--state-dir` is not listed; pair `--state-dir` with `--detach` for a background VM.

```sh
vk run --state-dir "$PWD/.vk" --detach --ssh -f Dockerfile --target dev
vk list
```

```
PID    UPTIME  NAME                SERVICES            PROJECT  PUBLISHED
41230  2h14m   app/Dockerfile:dev  -                   ~/app    127.0.0.1:8443->localhost:443
41877  35m     shop                db, redis, web, +4  ~/shop   127.0.0.1:5432->127.0.0.1:5432@db
```

NAME is the built Dockerfile with its target stage, the compose primary, or the image ref.
SERVICES lists the compose services running beside the primary, or every declared one when
the VM cannot be asked; `-` for none. Past three names, the rest are counted (`+4`).
PROJECT is the run's `--workspace`, then its `--workdir`, then its launch directory, with
`$HOME` shown as `~`. PUBLISHED is every port `vk publish ensure` holds open on the host
for the VM, as `listen->to`, with `@NAME` when a compose sibling rather than the primary
dials the target and `(unconfirmed)` when the publisher's liveness could not be checked;
`-` when nothing is published. `--wide` (`-w`) names every service, prints the project
directory in full and adds EXEC ADDRESS, recorded as given (a relative `--state-dir` lists a
relative path). `--json` and `--field` already report every field, so neither takes `--wide`.

An optional pid or directory scopes the list. A pid selects one VM, as with `vk stop`.
A directory selects VMs whose project is that directory or below it, or whose state dir
matches it exactly. If no VM matches, the message names the target:
`no running vk VM with pid 99999`, or `no running vk VM under <dir>`.

When a selector names exactly one VM, `vk list` prints its full record instead of a table
row: every field `--json` carries, then each compose service as name, state, LAN address and
exec address, and each published port as name, `listen->to` (with `@NAME` when a compose
sibling dials) and the publisher's pid. When liveness is unconfirmed, `(unconfirmed)`
marks the pid; in the table it marks the address. Nothing is folded in a full record,
so `--wide` has no effect.

```sh
vk list ~/work               # every VM under a tree (a table when several match)
vk list .                    # VMs for this tree or below; one VM prints in full
vk list 41877                # one VM, by pid
vk list /home/me/app/.vk     # one VM, by its state dir
```

```
NAME          shop
PID           41877
UPTIME        35m (since 2026/09/04 08:12:03 UTC)
PROJECT       /home/me/shop
STATE DIR     /home/me/shop/.vk
EXEC ADDRESS  vsock-auto:///home/me/shop/.vk/vsock.sock:4444
SSH           127.0.0.1:2222
GUEST IP      10.0.0.2
VMM           libkrun (pid 41902)
CPUS          4
MEM           8G
NESTED        no
ATOP LOG      -
SERVICES      db      running  10.0.0.3   vsock-auto:///home/me/shop/.vk/svc-db/vsock.sock:4444
              redis   running  10.0.0.4   vsock-auto:///home/me/shop/.vk/svc-redis/vsock.sock:4444
              web     running  10.0.0.5   vsock-auto:///home/me/shop/.vk/svc-web/vsock.sock:4444
              worker  running  10.0.0.6   vsock-auto:///home/me/shop/.vk/svc-worker/vsock.sock:4444
              mailer  running  10.0.0.7   vsock-auto:///home/me/shop/.vk/svc-mailer/vsock.sock:4444
              queue   running  10.0.0.8   vsock-auto:///home/me/shop/.vk/svc-queue/vsock.sock:4444
              minio   running  10.0.0.9   vsock-auto:///home/me/shop/.vk/svc-minio/vsock.sock:4444
              search  stopped  10.0.0.10  vsock-auto:///home/me/shop/.vk/svc-search/vsock.sock:4444
PUBLISHED     pg  127.0.0.1:5432->127.0.0.1:5432@db  pid 42011
```

`--json` gives an array of objects, one per VM, with `pid`, `label`, `project_dir`,
`exec_addr`, `state_dir`, `vmm`, `vmm_pid`, `cpus`, `mem`, `nested`, `guest_ip` (the eth0
address on a `--net` LAN), `ssh_addr`, `atop_log`, `created_secs`, `uptime_secs`,
`services` (every declared compose service with its `name`, `exec_addr`, `state` and LAN
`ip`), and `published` (each publisher's `name`, `listen`, `to` and `pid`, plus `via` when
a compose sibling dials — the one `vk publish ensure --via` named — and `"unconfirmed":
true` when its liveness could not be checked). `--field` picks fields without jq, one
`--field` per field: one line per VM and tab-separated in flag order, or with `--json`
objects holding only those fields; a dotted path reaches into nested values, and a key a
record omits reads `null`:

```sh
vk list . --field pid                   # the pid to hand to vk stop
vk list . --field guest_ip              # the VM's address on the --net LAN
vk list . --field label --field services.0.ip
vk list . --field published.0.listen    # where the first published port listens
vk list --json | jq '.[] | select(.vmm == "cloud-hypervisor")'
```

`--stale` adds a column to the table, and a `STALE` row to a full record, reading `yes`,
`no`, or `-` when unknown (as for an image boot). It says whether a fresh `vk run` would
rebuild the VM's image because the Dockerfile, build context or base image of the VM or of
one of its `build:` services changed since it booted. It resolves base image digests over
the network, so it is opt-in; `--json` then carries `stale` too.

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

The guest agent records processes killed by the guest kernel's OOM killer. The host reports
them alongside memory figures in build-stage completion output, CI traces, completed
`vk run` output, and `vk status` for a live VM. Each line identifies the victim, the
anonymous RSS reclaimed, its guest uptime at death, and the setting that raises the memory
limit. This can explain a command that exited with signal 9.

```
virtkit: guest OOM: the kernel killed cc1plus (pid 1234, 1.9 GiB RSS) at +48s (raise --mem)
```

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

Release binaries are static musl PIE executables. The Rust toolchain, build image, its
packages, guest kernel, and vendored libkrun source are pinned so release artifacts can be
rebuilt byte-for-byte — see [Build from source](#build-from-source).

## Command guide

| Command | Use it for |
| --- | --- |
| `vk run` | Boot an image, Dockerfile target, or compose fleet; run a command or shell. |
| `vk build` | Build Dockerfile stages into a bootable ext4 image or caller-owned disk. |
| `vk exec` | Run a command in an existing guest and return the command's exit status. |
| `vk list` | List running `--state-dir` VMs and their compose services; scope by pid or directory, `-w` for the full table, `--json`/`--field` for scripts. |
| `vk stop` | Stop a VM selected by pid or project directory, or stop all registered VMs. |
| `vk reboot` | Reboot a running VM in place through its guest, or power-cycle it with `--force`. |
| `vk status` | Probe a guest agent, or report whether its root image is stale. |
| `vk logs` | Show a VM's console log, telling kernel, agent and guest output apart; `--level warn`, `--agent`, `--service NAME`, `-f`. |
| `vk atop` | Follow or inspect guest resource recordings. |
| `vk check` | Validate KVM, VMM, embedded assets, configured host features, and an optional minimum `vk` version. |
| `vk gc` | Reclaim unused image bases, CI checkouts, and image-cache chunks. |
| `vk update` | Check for or install a digest-verified GitHub release. |
| `vk service up\|down\|reboot\|status` | Control compose services from the primary guest. |
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
./dev.sh fmt --check && ./dev.sh check && ./dev.sh clippy && ./dev.sh test # before committing
./build.sh --fast  # only when a runnable debug vk is needed
```

### Reproducible builds

Release builds produce byte-for-byte reproducible artifacts, and every input that fixes
those bytes is pinned to something that stays fetchable:

- the build image (`.devcontainer/Dockerfile`) is the official `nixos/nix` image by
  digest, and its toolchain — Rust, a musl cross gcc for the vendored C, mold, and the
  kernel build tools — comes from `.devcontainer/nix/flake.nix` locked to exact nixpkgs
  commits in `flake.lock`. Nix runs only inside the image while it is built; no host needs
  Nix, and nothing is pushed to any registry;
- the guest kernel is a pinned vanilla release, checked against its published sha256 (with
  a signed-tag fallback), and libkrun is vendored;
- `dist/build-info.txt` and `dist/kernel-build-info.txt` record the commit, base image
  digest, locked nixpkgs revision, and the sha256 of every artifact, with the exact
  command that rebuilds and verifies them.

`./build.sh --bootstrap-check` is the proof: it performs the Docker build, rebuilds a clean
copy of the tree from scratch in a microVM booted by the `vk` it just produced, and fails
unless the binaries are identical. Releases run this check in CI, so a published binary
has been reproduced independently before it is published. `--fast` uses the unoptimized
development profile and is not a release artifact.

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
.devcontainer/   pinned build image (nixos/nix base + nix/flake.nix and flake.lock toolchain)
kernel/          pinned guest-kernel configuration and build inputs
docs/            operational guides
examples/        annotated compose file exercising every compose feature
tests/           end-to-end scripts run against a built vk; release-e2e.sh gates a release
build.sh         reproducible binary build
build-kernel.sh  reproducible guest-kernel build
dev.sh           check/fmt/lint/test environment in a reusable development VM
```

## License

Copyright © Vincent Vanackere and WALLIX. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
