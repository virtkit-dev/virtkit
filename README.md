# virtkit

virtkit builds and runs Docker images as lightweight virtual machines. It
boots an OCI image as a microVM in about a second, each with its own kernel,
so whatever runs inside is isolated from the host — and it builds Dockerfiles
itself, no Docker needed, each `RUN` instruction executing in a microVM of its
own. There's no daemon and nothing to install as root: it's a single static
binary running as an ordinary user process, and the only thing it needs from
the host is access to `/dev/kvm`.

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

Build Dockerfiles without Docker. `vk build` runs each `RUN` instruction in its
own microVM, caches per instruction, and produces an image you can boot straight
away — `vk run -f Dockerfile` chains the two, build then boot, in one command.

Boot an image on its own kernel and init. By default virtkit boots every image
on its embedded kernel with `vk-agent` as PID 1, but `vk run --kernel image
--init image` boots the image's own `/boot/vmlinuz` (with its modules) and hands
PID 1 to the image's own init/systemd — so a stock distro image comes up as it
would on real hardware. `--kernel <path>` boots a kernel you supply. In compose,
a service picks this per service with an `x-virtkit: { init:, kernel: }` marker.

Give a VM internet access with a flag. Pass `--net` and the VM can reach the
network. There are no bridges, tap devices, or firewall rules to set up on the
host, and it doesn't need privileges.

Run compose services as VMs. `vk run --compose compose.yml` boots the services
(redis, mysql, and so on) on a shared network where each one resolves by name.
You can run them alongside your command, as the primary itself (`--primary`,
like `docker compose run`), or on their own (compose up, until ctrl-c). A
service sizes its own guest with `x-virtkit: { cpus:, mem: }` (default 2 vCPUs
/ 1G), and `--service-cpus`/`--service-mem NAME=VALUE` override it per run. From
inside the primary, `/run/vk/services/<name>/{state,ctl,log}` lets you read
service state and start or stop services with plain shell writes. For a dev VM,
`vk run --ssh` boots any image with SSH access, and VS Code Remote-SSH works
against it out of the box.

Isolate GitLab CI jobs. The custom executor gives every job a fresh microVM and
destroys it when the job ends. Concurrent jobs work, and Docker images from your
`.gitlab-ci.yml` are converted on demand — or built on demand from a Dockerfile
in the repo itself (`image: dockerfile:…`). See the
[GitLab CI guide](docs/gitlab-ci.md) for job variables, per-phase egress control,
and services.

Know what the work cost. A build, a `vk run`, and a CI job each end with the CPU
time, the peak memory, and the disk and network traffic they cost the host, the
guests' own execution included. Read the CPU, memory and disk as a ceiling — those
totals carry vk's own work and the host helpers alongside the guests — and the
network as the guests' share alone, since vk's own image pulls never cross the
switch that counts it. Size `--mem`/`--cpus` and their config equivalents from
what the work costs rather than by guess.
Where several guests run at once (concurrent build stages, a compose fleet) a
build and a `vk run` also name the largest single process, which is the
difference between giving each guest more memory and running fewer of them at a
time. See the [GitLab CI guide](docs/gitlab-ci.md#resource-usage) for what each
figure covers.

Carry one file around. The hypervisor, the guest kernel, and the guest agent are
all embedded in `vk`, so you can copy it to any Linux machine with `/dev/kvm`
and boot images. virtkit can even rebuild itself inside one of its own microVMs
(`./build.sh --bootstrap-check`).

## The binaries

| Binary | Role |
| --- | --- |
| `vk` | The host-side tool. Boots and manages VMs, builds and converts images, runs the GitLab executor, and provides the guest network. Self-contained: the guest kernel and `vk-agent` are embedded. |
| `vk-agent` | Runs inside the guest as PID 1. Brings the system up (mounts, networking, hostname, shared folders, optional SSH) and lets the host run commands inside the VM. |
| `vk-registry` | Optional central OCI-distribution server, shared by every runner: build-once dedup (a lease/heartbeat lock so an image is built once, not per runner), a pull-through cache for upstream registries (digest-addressed content only), and a backend for the `task` build cache. Not needed for local use — `vk` keeps its own on-disk store by default. |
| `vk-runnerctl` | Optional, and the only piece that runs as root: it sets gitlab-runner's `concurrent` from what `vk` measures, so a busy host stops taking work instead of overcommitting. It decides nothing and takes no arguments — see the [GitLab CI guide](docs/gitlab-ci.md#throttling-a-busy-runner). |

## How it works

You don't need any of this to use the tool, but if you're curious:

Guests boot on an embedded [libkrun](https://github.com/containers/libkrun)
VMM, so there's no external hypervisor to install; a stock kernel and stock KVM
are enough. [Cloud Hypervisor](https://www.cloudhypervisor.org/) also works as
an external backend (the `vmm` config key, or `VIRTKIT_VMM=cloud-hypervisor`).

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
./build.sh         # -> dist/{vk, vk-agent, vk-registry, vk-runnerctl, *.sha256, build-info.txt}
./build-kernel.sh  # -> dist/vmlinux (the guest kernel; rebuilt only on a pin bump)
```

Both run inside a pinned `rust:*-alpine` container (Docker required), so the
artifacts come out byte-reproducible regardless of the host. `./update.sh` bumps
the Rust toolchain, the base-image digest, and the apk pins together.

## Subcommands

The ones you'll actually type:

- `run` — boot an image, a Dockerfile target (`-f`), or a compose file as
  microVM(s) and run a command or an interactive shell (`--shell`, `-t`).
  This is where most of the flags live: `--net`, `--workdir`, `--volume`,
  `--ssh`, `--compose`, `--detach`, ...
- `build` — build a Dockerfile into a bootable ext4 image, each stage's `RUN`s
  executing in a microVM, instruction snapshots cached (`--build-cache`).
  `--tag` publishes the result to the `[registry]` as a bootable bundle the CI
  executor can pull.
- `exec` — run a command (or an interactive shell with `-t`) in an
  already-running guest over its agent channel, reproducing the command's own
  exit status. Addressed by launch directory like `list`/`stop`/`status` (or by
  a raw agent address); the command goes after `--` (`vk exec -- ls -la`), and
  `--service NAME` targets a running compose sibling instead of the primary.
- `list` / `stop` — discover and tear down background VMs. A `run --state-dir`
  registers its VM, so `list` shows the running ones and their compose services
  (with `--stale`, whether a fresh `run` would rebuild the image, services
  included) and `stop` brings one down by the directory it was launched from
  (or `--all`).
- `status` — probe a running VM's guest agent and print its reply (or exit
  non-zero if it does not answer): a liveness check that exercises the agent
  protocol, addressed by launch directory like `list`/`stop`, or by a raw agent
  address for plumbing. With `--stale`, skip the probe and print a single
  `fresh` / `stale` / `unknown` word for the VM's root image instead.
- `check` — preflight the host for the current user: `/dev/kvm` access, the VMM
  backend, a guest kernel/agent, and the host side of each configured feature
  (the CI-executor features only when named with `--feature`).
- `gc` — reclaim the host caches: evict image bases no VM is using, remove
  GitLab host checkouts no job is using, and drop unreferenced registry chunks.
- `update` — replace this `vk` with a release build from GitHub: the latest, or a
  version you name (an older one downgrades). It asks before replacing anything
  (`--yes` to skip), verifies the download against the digest published with the
  release so a corrupted or truncated transfer is never installed, and leaves
  running VMs untouched. `--check` reports what is available and installs nothing,
  exiting 1 when a newer release exists — enough for a cron or a login banner to
  nag with.
- `service up` / `service down` / `service status` — from inside the primary,
  control the run's compose services (build on demand + boot, stop, or query state).
- `gitlab config` / `gitlab prepare` / `gitlab run` / `gitlab cleanup` — the
  GitLab custom-executor lifecycle (see the [GitLab CI guide](docs/gitlab-ci.md)).
- `registry push` / `registry pull` / `registry inspect` / `registry status` /
  `registry gc` — manage guest bundles in an OCI store, with chunk-level
  deduplication to keep transfers small.

The rest is plumbing the commands above spawn for themselves, or development
tooling — listed by `vk help-all`, each documented in `vk help <cmd>`:
`connect` (splice stdio to a running guest — the shape SSH's
`ProxyCommand` wants), `paths` (print the effective host paths and how to
override each), `switch`, `forward` and `ssh-agent-proxy` (the per-run network
gateway and forwarders), and the image toolbox (`mkext`, `mkext-tar`,
`mkext-oci`, `oci-pull`, `docker-hash`, `fingerprint`, `qcow2-verify`).
`virtiofsd` (the bundled virtio-fs daemon for the Cloud Hypervisor backend)
dispatches before the CLI and documents itself via `vk virtiofsd --help`
instead.

`vk-agent` (embedded in `vk`; you rarely invoke it yourself): `init` is the
guest's PID 1, `serve` is the in-VM command server that `vk exec` / `vk
connect` / `vk status` dial, and `net` connects a guest NIC to the host's
network switch.

## Configuration

`vk` reads a single optional TOML file — the first that exists of:

1. `--config <path>` (a global flag, valid on any subcommand)
2. `$VIRTKIT_CONFIG`
3. `~/.config/virtkit/config.toml` (`$XDG_CONFIG_HOME`)
4. `/etc/virtkit/config.toml`

An explicit path (flag or env var) that doesn't exist is an error; the user and
system paths are skipped when absent. Every setting has a default, so with no
file at all `vk` still runs — the file is only needed to point at a registry, a
GitLab tools dir, egress rules, and the like. `vk-driver/config.example.toml` is
the annotated reference for every key.

Inspect and bootstrap it with `vk config`:

- `vk config` — the effective configuration as TOML, headed by which file it came from
- `vk config --example` — the annotated template to copy into place
- `vk config --path` — just the resolved config file path

`vk check` also reports the file in use, and `vk paths` shows where each host
path (state dir, image cache, registry store) resolves to.

Most things live in the config file or in CLI flags. The handful of environment
variables are:

| Variable | Effect |
| --- | --- |
| `VIRTKIT_CONFIG` | config file path (between `--config` and the user/system files) |
| `VIRTKIT_VMM` | VMM backend (`cloud-hypervisor`); overrides the `vmm` config key |
| `VIRTKIT_DEBUG=1` | verbose VMM/guest debug logging |
| `VIRTKIT_TIMING=1` | per-phase build/boot timing breakdown |
| `VIRTKIT_PROGRESS=plain` | plain build progress instead of the live dashboard (CI logs) |
| `VIRTKIT_NO_TITLE` | suppress terminal-title updates (keeps the dashboard) |

## Layout

```
vk-core/         shared host↔guest library (wire protocol + exec/pty/dockerignore)
vk-driver/       host driver crate
vk-agent/        guest agent crate (PID 1 + exec server)
vk-registry/     optional central OCI-distribution server (build-once lock + pull-through cache)
vk-runnerctl/    optional root-side setter for gitlab-runner's concurrent (see docs/gitlab-ci.md)
third_party/     vendored libkrun (locally patched — see its VENDOR.md)
kernel/          guest kernel build (Dockerfile + config fragment)
build.sh         build the binaries -> dist/
build-kernel.sh  build the guest kernel -> dist/vmlinux
update.sh        bump + re-pin toolchain / base image / apk versions
```

## License

Copyright © Vincent Vanackere and WALLIX. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
