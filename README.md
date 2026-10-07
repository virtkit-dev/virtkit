<p align="center"><img src="docs/assets/logo.svg" alt="virtkit" width="480"></p>

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

## Install

```sh
curl -fsSL https://github.com/virtkit-dev/virtkit/releases/latest/download/install.sh | sh
```

This installs the latest `vk` into `$XDG_BIN_HOME` (else `~/.local/bin`) and verifies the
checksum published beside it. `BINDIR` selects another directory and `VIRTKIT_VERSION` another
release. From a checkout with `.virtkit/toolchain.lock`, it installs the pinned release.
`vk update` updates an installed `vk` to a later release.

`vk toolchain lock` pins the team's release in `.virtkit/toolchain.lock`, with each
artifact's checksum and download URLs. `vk toolchain install` populates a per-version
cache without changing the `vk` on PATH. `vk toolchain export` provides those paths and
checksums to scripts and image builds; `vk toolchain status` reports what is pinned and
installed.

Run the host preflight before debugging a failed boot:

```sh
vk check
```

It checks KVM access, the embedded VMM, the guest kernel and agent, and the
host-side requirements for configured features. Scripts can require a release with
`vk check --min-version 0.45`, which exits non-zero on an older `vk`.

### WSL2

A fresh WSL2 distro cannot boot microVMs: nested virtualization is off, and nothing loads
KVM or opens `/dev/kvm` to the user. `vk check` says which of those still holds and prints
the steps that remain. `vk check --fix` asks first, then takes the ones it can — the two
files below and the commands, leaving you the WSL restart and the new login — and reports
the checks again so what is left is visible. It needs a terminal to ask on.

In full, starting on the Windows side:

```ini
# %UserProfile%\.wslconfig — needs Windows 11, or the Store WSL on a recent Windows 10.
[wsl2]
nestedVirtualization=true
```

That key applies only when WSL itself restarts: run `wsl --shutdown` from Windows and reopen
the distro, after which `/proc/cpuinfo` carries `vmx` or `svm`. Then, in the distro:

```sh
sudo modprobe kvm_intel          # kvm_amd on an AMD host
sudo groupadd kvm                # only if the distro has no kvm group
sudo usermod -aG kvm "$USER"     # log in again before it applies
sudo chown root:kvm /dev/kvm
sudo chmod 660 /dev/kvm
```

Neither the module nor the device's ownership survives the next `wsl --shutdown`. An
`/etc/wsl.conf` boot command redoes both on every start of the distro:

```ini
[boot]
command = modprobe kvm_intel; chown root:kvm /dev/kvm; chmod 660 /dev/kvm
```

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

The image's `ENV`, with `--env` and `--env-file` over it, reaches commands the agent
starts. Its `USER` sets their default identity. Login shells recover the environment
through `/etc/profile.d/zz-virtkit-env.sh`, mounted from `/run` without writing the
hook to the root disk. The hook preserves session values and restores the image's
`PATH` ahead of the login profile's additions; SSH session PATH overrides take precedence.
It excludes login identity variables, and excludes `PATH` and loader variables for a
UID other than the run user's. Images without `/etc/profile.d` get no automatic hook.

Other processes can use `/run/vk/bin/vk-agent env --export`, `--print0`, or `--exec CMD`.
The environment lives on tmpfs: `/run/vk/env.json` is root-only, with private copies
for the run and SSH users. The export command validates its complete output before
printing; callers should check its exit status before evaluating it. Boot configuration
travels in the host-supplied initramfs, never in the guest root disk. Build `RUN` steps
receive their changing environment and user through the exec channel instead.
Older images' `/etc/virtkit/{env,user}` files are still read as a fallback.

Bundles must declare `generic-disk` in `boot.kind`; legacy `systemd` and unmarked
bundles are rejected. Rebuild them with `vk build`. When packaging an ext4 manually,
keep its generated `<out>.json` sidecar beside `runner.ext4` as `runner.ext4.json`.
For an image that needs its own init, use compose `x-virtkit.init: image` or
`entrypoint` (and `kernel: image` if needed); vk supplies the preinit agent and config.

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
`command`, `entrypoint`, `user`, `hostname`, `depends_on`, `healthcheck`, `volumes`,
`profiles` and the `x-virtkit` marker. Every host path is relative to the compose file.

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
the service name. Other guests resolve services, including the primary, by service name or
hostname. A non-service primary (an image or a `-f` build) resolves as `vm`. Siblings keep
shared names on collision with the primary.

Values interpolate `$VAR`, `${VAR}` and `${VAR:-default}` from the environment over a
sibling `.env`; `$$` is a literal `$`. An unset variable with no default **fails the load**
— an empty image tag or bind path is always a bug — and the other docker modifiers (`:?`,
`:+`, `${VAR-default}`) are rejected. Five reserved names come from the run itself, so a
committed file needs no host paths or ids: `${VK_WORKSPACE}` (`--workspace`, else the
cwd), `${VK_STATE_DIR}` (`--state-dir`, else the run's scratch), `${VK_SELF}` (the running
`vk`, to hand a guest its own copy), `${VK_UID}` and `${VK_GID}`. A variable holding several
newline-separated binds expands into several `volumes:` entries.

#### Start order and profiles

`depends_on` (a list, or a map of `condition:`s) orders starts. `service_started`, the
default, is start order alone: retry a first connection. `service_healthy` waits until the
dependency's `healthcheck` passes; `service_completed_successfully` waits until the
dependency's guest has ended, for a Linux one with its service's exit code 0 (a job). Any other
condition is refused when the file is read, as is waiting for the health of a service without a
healthcheck. `restart:` and `required: true` are accepted and ignored; `required: false` is
refused.

All independent services start at the same time: several
Windows guests provisioning side by side each take longer to start than one alone.

A `healthcheck` runs its `test` in the service's guest: `["CMD", prog, args…]` as is,
`["CMD-SHELL", "line"]` or a string under `/bin/sh -c` (as the service's `user`) in a Linux
guest and `cmd /S /C` in a Windows one; `["NONE"]` or `disable: true` declares none. `interval`
and `timeout` default to 30 s, `retries` to 3 (a zero means the default) and `start_period` to
none; `start_interval` is ignored. vk probes only for a dependent: once per start of the
dependency, until it passes or fails `retries` times in a row, the start period running from
when the dependent starts waiting. Services with
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
primary and any service without its own, `[executor.vm] reclaim` for the GitLab executor. It needs the
agent as PID 1, so an `init` of `image` or `entrypoint` opts out; `vk build` stage guests are
left alone as well, since trimming would move the peak-memory mark they are measured by.

Directory virtio-fs shares — `--workdir`, `-v` directory binds and compose volumes — use
DAX windows to read the host page cache directly. The host maps shared files into guest
address space, avoiding a second copy through the filesystem protocol. Several VMs cache a
shared tree once; host-side content edits are visible without a re-read, and reopening a
file no longer re-reads it. Mappings are 4 KiB-granular, so the win is in memory rather than
in per-fault latency.

The window reserves address space, not memory, and costs nothing until mapped. It defaults
to 8G per share; `vk run --dax`, a service's `x-virtkit.dax` and the executor's `[executor.vm] dax`
resize it or turn it `off`. Each mapping costs the host an mmap and the guest an EPT
invalidation per 2 MiB range whatever the file's size, so by default only regular files of
1M and more go through the window (`dax=inode`; the host marks them) and smaller files read
through the guest's page cache as without DAX; `<size>:always` maps every file, and
`<size>:inode=<min>` moves the floor. Each guest supports 64G of windows — eight at the
default size, with further shares served without DAX. Guests with more than 63.25G of RAM
have no room for windows and receive none. Single-file binds and `vk build` stage guests
are served the ordinary way.

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

`tap` puts a guest's `eth0` on a host tap instead, so the guest holds an address on the
LAN that tap is bridged to — a machine moved off another hypervisor keeps its MAC and IP:

```yaml
services:
  devbox:
    image: local/devbox
    x-virtkit:
      tap: { name: vkdev0, mac: BC:24:11:00:27:D9, ip: 10.10.132.201/23, gw: 10.10.132.1, dns: [10.10.0.53] }
```

The tap is the caller's: create it owned by the user running `vk` and enslave it to the
bridge (`ip tuntap add vkdev0 mode tap user $USER && ip link set vkdev0 master vmbr0 up`).
A static `ip` needs `gw` and `dns`; without one the guest asks the LAN's DHCP. The guest's
switch ports follow as `eth1` upward, addressed without a route: egress and DNS go through
the tap, it still reaches its siblings, and their names are pinned in its `/etc/hosts`
since the LAN's resolver does not know them. `vk` checks a tap before booting on it: it
must exist, be owned by or open to the user running `vk` (root included), and not be held
by another VM. Two services naming the same tap fail the run, as does a tap the CI executor
uses (`net.mode = "tap"` or a `pool` tap) and a static `ip` overlapping the switch LAN
(`192.168.127.0/24`).
`vk run --tap NAME` (with `--tap-mac`, `--tap-ip`, `--tap-gw`, `--tap-dns`) does the same
for the primary, overriding its service's `tap`, and combines with `--net`. A tap guest
rules out `--audit-egress` and a restricted egress policy, which live on the switch, and a
tap primary `--registry-proxy`.
`vk check --feature tap` reports whether a `vk` supports it.
A [Windows guest](#windows-guests) takes a tap too, `vk run --tap` on a bundle or `tap` on a
Windows service: Windows reads no kernel command line, so vk sets a static `ip` through
qemu-ga once Windows has started (until then the guest has no address on the tap), and
pins the siblings' names in `C:\Windows\System32\drivers\etc\hosts`; its switch port's
DHCP lease carries no router or DNS server, so the tap holds the only default route.

Without `mac` / `--tap-mac`, the MAC is derived from the host's machine ID and tap name,
so hosts using the same tap name get different MACs. On a host without `/etc/machine-id`,
the boot ID is used instead; set an explicit MAC to keep it across host reboots there.
The VMM claims the tap before starting the guest and holds it across guest resets.

#### Volumes and persistent state

A service starts from a clean copy of its image every time: its root filesystem is a
throwaway layer over the image, and `volumes:` bind host paths into the guest. A bind is
`host:guest[:mode]`, with the host path relative to the compose file:

| mode | the guest sees | writes go |
|------|----------------|-----------|
| `rw` (default), `ro` | the host directory or file, live | to the host (`rw`), or are refused (`ro`) |
| `overlay` | the host tree, read-only underneath | to guest RAM — fast, gone at reboot |
| `overlay,persist[,size=SIZE]` | the host tree, read-only underneath | to a disk that survives restarts (see below) |
| `disk[,size=SIZE]` | a private filesystem of its own | to that disk; the host path is its image |
| `socket` | a unix socket at the guest path | each connection is relayed to the host socket |

`overlay` is for build trees and checkouts: reads come from the host, every write lands
in guest memory and never touches the host tree. Add `persist` to keep those writes on
disk instead. A read-only share (`ro`, `overlay`) takes `immutable` when the host will not
change the tree while the service runs: the guest then keeps what it read for its whole
life, so a pass over the tree (`git status`, a build's dependency check) asks the host once
rather than on every pass, and the share carries no extended attributes. `disk` is for data that needs real filesystem semantics (ownership, sockets,
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
reboot, `vk service down`/`up`, and stopping and later restarting the run. When the run pins a
durable state directory — `vk dev`, or `vk run --state-dir` — it is kept there, out of the
workspace and so out of the guest's view; otherwise it lives under `.virtkit/` beside the
compose file (add that to `.gitignore`). Either way it is reset when what it
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
it on first use, and returns once it answers; `down` powers it off; `reboot` restarts its
guest in place on the same disks; `status` reports one or all. `vk run --ssh` enables SSH
access for development VMs, including VS Code Remote-SSH workflows. In a CI fleet a
service's `environment:` may also carry its own egress allowlist — see
[Per-service egress](docs/gitlab-ci.md#per-service-egress).

### Develop in a project environment

`vk dev` boots a project's development environment from `.virtkit/config.toml`.
The same configuration drives the shell, editor, services, hooks and host integration.

```sh
vk dev init                         # write a first config from devcontainer.json, a compose file,
                                    # a Dockerfile or a stock image; validate an existing one
vk dev shell                        # boot if needed, then a login shell as the config's user
vk dev exec -- cargo test           # a command in the environment, exit status reproduced
vk dev code                         # VS Code over Remote-SSH, extensions and settings reconciled
vk dev service up runner            # a profiled compose service, built on first use
vk dev endpoints                    # the stable host addresses its ports are published on
vk dev task pre-commit -- "$@"      # a project command under its declared execution policy
vk dev status                       # what is running and whether its configuration matches
vk dev plan                         # inspect the resolved configuration without running it
vk dev doctor                       # check the host and configuration requirements
vk dev refresh                      # rebuild and restart into the current config
vk dev stop
vk dev prune --dry-run              # preview local boot-image cleanup; --storage selects data
vk dev list                         # every environment this host keeps state for, from anywhere
vk dev gc --all-stale               # review/remove stale state; asks on a terminal
vk dev gc                           # remove this workspace's environment; asks first
```

Configuration, local overrides, compose services, endpoints, persistent storage, editor
setup, lifecycle hooks and isolated tasks are covered in the
[project development guide](docs/dev.md). It includes a complete workflow and a
service layout with on-demand test appliances.

### Manage running VMs

A `vk run --state-dir DIR` boots a VM that outlives a single command: its sockets and
console log live in DIR, and the run is recorded in a host-side registry. `vk list` reads
that registry, dropping entries whose run has died, and is what `vk exec`, `vk status`,
`vk logs`, `vk stop` and `vk reboot` resolve a directory against — `vk logs` also reads the
console of a VM the registry has already dropped, since DIR keeps it. A run without
`--state-dir` is not listed, unless it boots a UEFI bundle; pair `--state-dir` with
`--detach` for a background VM.

```sh
vk run --state-dir "$PWD/.vk" --detach --ssh -f Dockerfile --target dev
vk list
```

```
PID    UPTIME  MEM       NAME                SERVICES            PROJECT  PUBLISHED
41230  2h14m   1.2G/8G   app/Dockerfile:dev  -                   ~/app    127.0.0.1:8443->localhost:443
41877  35m     5.9G/16G  shop                db, redis, web, +4  ~/shop   127.0.0.1:5432->127.0.0.1:5432@db
```

MEM is what the VM is costing the host now over the size it booted with: the resident
memory of its whole process tree — the guest, its service VMs, the switch and the
forwards — counted proportionally so a page several of them map is charged once, over the
`--mem` token as the run recorded it. When proportional usage is unavailable,
resident usage is used instead and may count shared pages more than once. The total includes
service VMs and helpers, so it is not the primary guest's memory utilization.
Either half is `-` on its own when unknown,
and the cell is a bare `-` when neither is. NAME is the built Dockerfile with its target
stage, the compose primary, or the image ref.
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
MEM USED      5.9 GiB
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
`exec_addr`, `state_dir`, `vmm`, `vmm_pid`, `cpus`, `mem`, `mem_used_bytes` (what the VM's
process tree holds on the host now, in bytes — `null` when it could not be read),
`nested`, `guest_ip` (the eth0 address on a `--net` LAN), `ssh_addr`, `atop_log`,
`created_secs`, `uptime_secs`, `services` (every declared compose service with its
`name`, `exec_addr`, `state` and LAN `ip`), and `published` (each publisher's `name`,
`listen`, `to` and `pid`, plus `via` when a compose sibling dials — the one
`vk publish ensure --via` named — and `"unconfirmed": true` when its liveness could not
be checked). `--field` picks fields without jq, one `--field` per field: one line per VM
and tab-separated in flag order, or with `--json` objects holding only those fields; a
dotted path reaches into nested values, and a key a record omits reads `null`:

```sh
vk list . --field pid                   # the pid to hand to vk stop
vk list . --field guest_ip              # the VM's address on the --net LAN
vk list . --field label --field services.0.ip
vk list . --field published.0.listen    # where the first published port listens
vk list --json | jq '.[] | select(.label == "ci")'
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

### Windows guests

`vk` also boots UEFI guests such as Windows, natively in its own VMM; running one needs only
KVM on the host. The first build also needs network access (a Linux helper VM prepares the
install medium) and about 15 GB of cache. [`examples/windows`](examples/windows) builds whole labs this way (IIS, Active
Directory, two forests with a trust, a Windows 11 workstation, an RDP session).

**Build an image.** A Dockerfile stage starting `FROM winiso:` installs Windows unattended
from Microsoft's ISO. Each later step becomes a cached qcow2 layer through the guest's
qemu-ga:

```dockerfile
# vk: cpus=4 mem=4G disk=60G
FROM winiso:ws2025.iso@sha256:<digest> --edition="Windows Server 2025 Standard Evaluation" \
    --drivers=virtio-win.iso@sha256:<digest> AS base
SHELL ["powershell", "-NoProfile", "-Command"]
RUN Install-WindowsFeature Web-Server
COPY index.html C:/inetpub/wwwroot/index.html
COPY boot.ps1 C:/vk/
CMD & C:\vk\boot.ps1; exit $LASTEXITCODE
```

```sh
vk build -f Dockerfile --out ./web-out    # a bundle: vm.json, disks, admin-password
```

- The ISOs are local files pinned by digest; `--drivers` is virtio-win's ISO (drivers and
  qemu-ga). Without `--edition` the ISO's first image installs. For Windows 11, `--edition`
  must name a Windows 11 edition: otherwise it installs as a server would and Setup stops at
  its TPM check. The install takes about 20 minutes (70 for Windows 11) and is cached; so is
  every later step.
- `# vk:` directives: `disk=<size>` sizes the install (default 40G), `generalize=on` ends
  the stage with sysprep (each copy gets its own name and SID), `firmware=uefi-secboot`
  enrolls Microsoft's Secure Boot keys, `tpm=on` gives each machine a TPM 2.0, and
  `cpus`/`mem` size the build's guests and the bundle's machine.
- `RUN` has no network unless it says `--network=default`; exit code 3010 or 1641 restarts
  Windows (`--reboot=auto|always|never`). Steps run as SYSTEM. `ENV`, `WORKDIR`, `SHELL` and
  `COPY` apply; `USER`, `ARG`, `ADD`, `ONBUILD`, `ENTRYPOINT`, `COPY --from` and `$VAR`
  substitution in `ENV`, `WORKDIR` or `COPY` are refused.
- `CMD` is the image's provisioning command, run at each compose service start.
- Another Windows Dockerfile can start `FROM ./web-out`, on the build cache that made it.

**Evaluation media.** Microsoft's evaluation terms: Server evaluations must be activated
online within 10 days and then run 180 days from activation; Windows 11 Enterprise
evaluation 90 days. Evaluation media is for evaluation only: see Microsoft's terms before
sharing images built from it.

- A generalized image (`generalize=on`) starts a new 10-day grace on each machine, so each
  must activate online within 10 days of its start (e.g. `slmgr /ato` in its `CMD`, with a
  network), or Windows shuts down periodically.
- An image that is not generalized carries its build's licensing: activated online during
  its build (e.g. in a `RUN --network=default` step), its 180 days run from then for every
  machine started from it. `vk build` records when that ends, or when the activation grace
  of an image never activated does, and `vk run`, compose services and `FROM` the bundle
  warn from 30 days before an evaluation ends, or 3 days before that grace does.
- `vk build --reinstall` installs each `FROM winiso:` stage again under new cache keys and
  rebuilds every step on it. The old install and its layers stay cached (tens of GB): bundles
  built on them keep working until they are rebuilt. Nothing removes them: once no bundle
  uses the Windows build cache, `rm -rf ~/.local/share/virtkit/windows`
  (`$XDG_DATA_HOME/virtkit/windows` when that is set) frees it all, and the next build
  installs from the ISO again.

**Run it.** `vk run ./web-out` boots the bundle on fresh copy-on-write overlays (`--net`
for a DHCP lease, `--tap` for [a host network](#guest-size-init-kernel-and-nics), `--cpus`/`--mem` to
resize, `--state-dir` to keep its disks); `vk list`
shows it. In a compose file, `image: ./web-out` makes a Windows service on the run's LAN,
at the address its name resolves to:

- each start is a new machine; it is up once its provisioning (`command:`, else the image's
  `CMD`) has run as SYSTEM, with `VK_HOSTNAME`, `VK_IP`, `VK_PREFIX` and `VK_GATEWAY` set
  ahead of its `environment:`; exit code 3010 or 1641 restarts Windows and runs it again;
- `secrets:` land in `C:\ProgramData\Docker\secrets\<target>`, readable by SYSTEM and
  administrators only;
- `healthcheck:` runs through qemu-ga, so `depends_on` conditions work across Windows and
  Linux services, and services start side by side as their dependencies allow.

**Reach a running guest.** Everything goes through qemu-ga, as SYSTEM:

```sh
vk exec ./run -- ipconfig                       # a vk run --state-dir ./run of a bundle
vk cp setup.ps1 :C:/vk/setup.ps1 --target ./run
vk exec ./lab --service dc -- nltest /dsgetdc:corp.lab   # a compose run's --state-dir
vk cp --target ./lab --service dc :C:/Windows/debug/dcpromo.log .
vk console ./run                                # the serial console (SAC), when qemu-ga is down
vk pause ./run && vk resume ./run               # freeze and thaw a vk run of a bundle
```

**Snapshots.** `vk snapshot <pid|dir> --out <dir>` saves a running bundle's memory, device
state and disks, then ends it. `vk run <dir>` resumes it as often as wanted.
`vk snapshot --run-dir <state-dir> --out <dir>` does the same for every Windows service of
a compose run, and `vk run --compose … --from-snapshot <dir>` brings them back without
provisioning (the AD lab in 8 s). Each service must keep the address, tap, vCPUs and memory
it was snapshotted with. A restored guest's clock is set through qemu-ga; until then Kerberos
may fail. A snapshot depends on the bundle it was taken from and must be written on the
run's filesystem.

**Firmware, Secure Boot and TPM.** Released `vk` embeds edk2's CloudHv firmware; a source
build embeds `dist/CLOUDHV.fd` from `./build-firmware.sh` (`VIRTKIT_UEFI_FIRMWARE` selects
another). A bundle's `vm.json` says whether its machine has Secure Boot (`"secure_boot"`)
and a TPM (`"tpm"`). UEFI variables persist in `uefi-vars.fd` beside the disks. **Secure Boot is
experimental:** without SMM the guest's kernel can rewrite the variable store (PK, KEK, db,
dbx), so it guards only the boot chain below the kernel, and a db/dbx update Windows makes
at run time is known to crash the guest. The TPM runs inside `vk` (`vk-tpm`, a TPM 2.0 in
Rust; no swtpm), its state in `tpm-state`, carried by snapshots; build steps run without one.

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
is useful when several runners need a shared OCI store, pull-through cache, build-once
coordination, or a shared compiler cache. Its lease and heartbeat protocol prevents runners
from independently building the same content while a healthy peer is already doing so.

The whole store is also served over WebDAV under `/dav/`, behind the same TLS and
credentials as the rest of the server: `/dav/repos/` is a read-only view of every
repository's tags, manifests and blobs, and `/dav/files/` is a plain-file area where an
`sccache` pointed at `/dav/files/<dir>` lets jobs in throwaway microVMs reuse each other's
compiled units. In accounts mode, a key with `write:files/<dir>/*` fills the cache and one
with `read:files/<dir>/*` only reads it. Cached files expire under `vk-registry gc`'s tag
retention like any other tag. Set `webdav = false` in the server config to disable WebDAV.

Use `vk registry push|pull|inspect` for guest bundles and `vk registry status|gc` for a
local store. The central server and storage model are documented in
[`vk-registry/DESIGN.md`](vk-registry/DESIGN.md).

## Binaries

| Binary | Purpose |
| --- | --- |
| `vk` | Host CLI, VMM, image builder, userspace network, compose runner, and GitLab executor. It embeds the default guest kernel and `vk-agent`. |
| `vk-agent` | Guest PID 1 and command server. It configures mounts, networking, hostname, shared directories, optional SSH, and host-driven execution over vsock. |
| `vk-registry` | Optional OCI-distribution server with a pull-through cache, a WebDAV view of the store with a plain-file area for compiler caches, and build-once locking. |
| `vk-hub` | Experimental hub for a fleet of `vk node` hosts, and a web UI for the VMs on this machine: `vk-hub local` serves it on loopback. See the [fleet design](docs/fleet-design.md) and [prototype reference](docs/fleet-prototype.md). |
| `vk-gitlab` | Experimental GitLab runner for a `vk-hub` fleet: takes jobs from GitLab and has the hub run each on a `vk node`. See [GitLab dispatch](docs/gitlab-dispatch.md). |
| `vk-runnerctl` | Optional root-side helper that adjusts GitLab runner concurrency within an administrator-configured range. |

## Architecture

The VMM is the embedded [libkrun](https://github.com/containers/libkrun); `vk` needs no
external VMM binary.

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
| `vk build` | Build Dockerfile stages into a bootable ext4 image or caller-owned disk, or a Windows Dockerfile into a bundle. |
| `vk exec` | Run a command in an existing guest and return the command's exit status. |
| `vk list` | List running `--state-dir` VMs and UEFI bundle runs, and their compose services; scope by pid or directory, `-w` for the full table, `--json`/`--field` for scripts. |
| `vk stop` | Stop a VM selected by pid or project directory, or stop all registered VMs. |
| `vk reboot` | Reboot a running VM in place through its guest, or power-cycle it with `--force`. |
| `vk status` | Probe a guest agent, or report whether its root image is stale. |
| `vk logs` | Show a VM's console log, telling kernel, agent and guest output apart; `--level warn`, `--agent`, `--service NAME`, `-f`. |
| `vk cp`, `vk console`, `vk pause\|resume`, `vk snapshot` | Copy files into or out of a [Windows guest](#windows-guests), attach to its serial console, freeze it, or save it to restore later. |
| `vk atop` | Follow or inspect guest resource recordings. |
| `vk check` | Validate KVM, VMM, embedded assets, configured host features, and an optional minimum `vk` version. |
| `vk gc` | Reclaim unused image bases, CI checkouts, and image-cache chunks. |
| `vk update` | Check for or install a digest-verified GitHub release. |
| `vk dev ...` | Boot, enter, refresh and stop a project's development environment from `.virtkit/config.toml`; its services, endpoints, storage, tasks and editor. `vk dev list\|gc` covers every environment on the host. |
| `vk toolchain lock\|install\|export\|status` | Pin a project's virtkit release and install its artifacts from the lock. |
| `vk service up\|down\|reboot\|status` | Control compose services from the primary guest. |
| `vk registry ...` | Publish, fetch, inspect, report on, or sweep OCI stores. |
| `vk gitlab ...` | Implement the GitLab custom-executor lifecycle. |
| `vk export ...` | Package raw disks or staged files as VMDK, OVA, or ISO artifacts. |

Advanced commands are listed by `vk help-all`. They include the stdio/vsock connector,
network forwarding processes, SSH agent proxy, path inspection, OCI/ext4 conversion
tools, and image fingerprinting.

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
| `VIRTKIT_DEBUG=1` | Enable verbose VMM and guest logging. |
| `VK_SWITCH_LOG=debug` | Set the userspace network switch's log level in `switch.log` (default: `warn`). |
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
./build-kernel.sh    # dist/vmlinux
./build-firmware.sh  # dist/CLOUDHV.fd: UEFI firmware (optional; embedded by build.sh)
./build.sh           # dist/{vk,vk-agent,vk-registry,vk-hub,vk-gitlab,vk-runnerctl,...}
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
vk-hub/          experimental fleet hub, and local web UI for this machine's VMs
vk-gitlab/       experimental GitLab runner that hands jobs to a vk-hub fleet
vk-runnerctl/    optional root-side GitLab concurrency helper
vk-selfupdate/   shared self-update implementation for vk and vk-registry
vk-fs/           filesystem objects created private and published whole
vk-hub-proto/    the VM list `vk workloads` prints, and the hub↔node protocol
vk-oidc/         OIDC sign-in shared by vk-registry and vk-hub
third_party/     vendored libkrun and local patches
.devcontainer/   pinned build image (nixos/nix base + nix/flake.nix and flake.lock toolchain)
kernel/          pinned guest-kernel configuration and build inputs
firmware/        UEFI firmware (edk2 CloudHv) build inputs
docs/            operational guides and the fleet design
examples/        annotated compose file exercising every compose feature
tests/           end-to-end scripts run against a built vk; release-e2e.sh gates a release
build.sh         reproducible binary build
build-kernel.sh  reproducible guest-kernel build
build-firmware.sh  UEFI firmware build, for UEFI (Windows) guests
dev.sh           check/fmt/lint/test environment in a reusable development VM
```

## License

Copyright © Vincent Vanackere and WALLIX. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
