//! gitlab-runner custom executor running each CI job in a throwaway Cloud Hypervisor
//! microVM.
//!
//! Wire-up in /etc/gitlab-runner/config.toml:
//!   [runners.custom]
//!     config_exec   = "/usr/local/bin/vk"
//!     config_args   = ["gitlab", "config"]
//!     prepare_exec  = "/usr/local/bin/vk"
//!     prepare_args  = ["gitlab", "prepare"]
//!     run_exec      = "/usr/local/bin/vk"
//!     run_args      = ["gitlab", "run"]
//!     cleanup_exec  = "/usr/local/bin/vk"
//!     cleanup_args  = ["gitlab", "cleanup"]

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod build;
mod check;
mod compose;
mod config;
mod convert;
mod cpio;
mod detach;
mod dockerhash;
mod embed;
mod ensure;
mod exec;
mod executor;
mod ext4;
mod ext4_read;
mod fullvm;
mod image;
mod initramfs;
mod jobctx;
#[cfg(feature = "libkrun")]
mod libkrun_sys;
mod local;
mod manager;
mod mkoci;
mod net;
mod oci;
mod qcow2;
mod registry;
mod regserve;
mod run;
mod scratch;
mod services;
mod source;
mod spawn;
mod sshagent;
mod sshconf;
mod switch;
mod timing;
mod units;
#[cfg(feature = "virtiofsd")]
mod virtiofsd;
mod vm;
mod vmm;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vk_core::addr::SocketAddr;

use crate::config::Config;
use crate::jobctx::JobCtx;

/// clap value parser for `--cpus`: a number, or `host` for the host's CPU count
/// (`available_parallelism`, which honours cgroup/affinity limits). libkrun and
/// cloud-hypervisor both take a flat vCPU count, so this matches the host's logical
/// CPUs; it does not replicate SMT/socket topology (libkrun exposes no such knob).
fn parse_cpus(s: &str) -> Result<u32, String> {
    if s == "host" {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .map_err(|e| format!("detecting the host CPU count: {e}"))
    } else {
        s.parse()
            .map_err(|_| format!("--cpus expects a number or \"host\", got {s:?}"))
    }
}

#[derive(Parser)]
#[command(
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("VK_GIT_HASH"), ")"),
    about
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum GitlabCmd {
    /// config_exec: describe the driver to gitlab-runner (JSON on stdout)
    Config,
    /// prepare_exec: boot the job's microVM, wait for the in-guest agent
    Prepare,
    /// run_exec: run one stage script inside the VM
    Run {
        script: PathBuf,
        /// Stage name (prepare_script, get_sources, build_script, ...), unused
        stage: Option<String>,
    },
    /// cleanup_exec: stop the VM and remove the job state (idempotent)
    Cleanup,
    /// internal: the detached per-job supervisor prepare spawns — owns the job's
    /// switch/virtiofsds/forwards/VMM as tied children until SIGTERM'd by cleanup
    #[command(hide = true)]
    Supervise {
        /// the job dir (pid-reuse guard on the cmdline; must match the environment)
        job_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum RegistryCmd {
    /// Push a local bundle dir (runner.ext4 + boot.kind [+ vmlinuz + initrd.img])
    /// to the [registry] repo at <name>:<tag>, with CDC+zstd chunk dedup.
    Push {
        /// Local bundle directory
        dir: PathBuf,
        /// Target reference, <name>:<tag> (a :tag is required for a push)
        reference: String,
    },
    /// Pull+cache a bundle from the [registry] repo and print its cache dir.
    Pull {
        /// Source reference, <name>[:tag|@sha256:…]
        reference: String,
    },
    /// Check a bundle exists in the [registry] repo without pulling it: print its
    /// manifest digest and exit 0, or exit non-zero if absent (the CI build's
    /// already-built check, replacing `docker manifest inspect`).
    Inspect {
        /// Source reference, <name>[:tag|@sha256:…]
        reference: String,
    },
    /// Run a local OCI registry server backed by a content-addressed store, so
    /// every worktree pointing its [registry] here shares one bundle pool (a
    /// chunk pushed from one is reused by the rest). Loopback, no auth/TLS — pair
    /// with `[registry] insecure = true`.
    Serve {
        /// Listen address (use a loopback address — there is no auth).
        #[arg(long, default_value = "127.0.0.1:5000")]
        addr: std::net::SocketAddr,
        /// Store directory [default: $XDG_DATA_HOME/virtkit/registry].
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Install + start a `systemd --user` unit running `registry serve`, so the
    /// shared store is always available (survives logout/reboot).
    InstallService {
        #[arg(long, default_value = "127.0.0.1:5000")]
        addr: std::net::SocketAddr,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Garbage-collect a registry store: drop tags idle past the retention window,
    /// then sweep the blobs no surviving manifest references and stale uploads
    /// (both after a grace window). Takes the store lock exclusive, briefly
    /// blocking concurrent pushers.
    Gc {
        /// Store directory [default: $XDG_DATA_HOME/virtkit/registry].
        #[arg(long)]
        root: Option<PathBuf>,
        /// Drop tags unused for more than this many days.
        #[arg(long, default_value_t = 30)]
        retention_days: u64,
        /// Keep unreferenced blobs and stale uploads this many days past their
        /// last use (protects in-flight multi-request pushes).
        #[arg(long, default_value_t = 1)]
        grace_days: u64,
        /// Report what would be removed without removing anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Bring a service up: build its image on first use (a profiled-down service — build
    /// progress streams live), then boot it. A no-op if it is already running.
    Up {
        /// service name (as declared in the compose file)
        name: String,
    },
    /// Stop a running service (a no-op if already stopped).
    Down {
        /// service name
        name: String,
    },
    /// Print a service's state and address, or every declared service when no name is given.
    Status {
        /// service name; omit to list all services
        name: Option<String>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Preflight: check this host is usable by the current user — /dev/kvm access,
    /// the VMM backend, a guest kernel/agent, and the host side of each feature the
    /// config enables (net.mode taps, [convert], [registry], ...). One line per
    /// check; exits non-zero if any fails.
    Check {
        /// check only these features, failing (instead of skipping) any that
        /// turn out unconfigured (repeatable)
        #[arg(long = "feature", value_enum, value_name = "FEATURE")]
        feature: Vec<check::Feature>,
    },
    /// GitLab custom-executor lifecycle (config / prepare / run / cleanup)
    Gitlab {
        #[command(subcommand)]
        cmd: GitlabCmd,
    },
    /// Native OCI bundle registry: push/pull guest bundles with content-defined chunk
    /// deduplication (CDC + per-chunk zstd), no oras, no docker.
    Registry {
        #[command(subcommand)]
        cmd: RegistryCmd,
    },
    /// Control the run's compose services from inside the guest: bring one up (building its
    /// image on demand, streaming build progress), take it down, or query state. Speaks the
    /// vsock control plane to the host service manager, so it only works inside a vk VM.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Build a Dockerfile target and export it as a bootable ext4 image — a from-scratch
    /// builder (no docker, no buildkit). Each RUN executes in a microVM guest (the
    /// embedded libkrun by default) and instruction snapshots are cached
    /// (`--cache-registry`). `--print-plan` parses + plans + prints the build without
    /// running it.
    Build {
        /// Dockerfile to build (repeatable: the files merge into one stage namespace,
        /// so a FROM/COPY --from in one file can name a stage declared in another)
        #[arg(short = 'f', long = "file", default_value = "Dockerfile")]
        file: Vec<PathBuf>,
        /// target stage (AS name or index; default: the last stage). Repeatable: several
        /// targets build together in one pass, sharing their common stages (built once) and
        /// running the rest concurrently. With one --out they export to <out>/<target>.ext4;
        /// with none they only warm the instruction cache
        #[arg(long)]
        target: Vec<String>,
        /// build the services `vk run --compose` would boot — the enabled set (profiled-down
        /// services excluded) plus every image: service — in one pass, so a prebuild warms
        /// exactly what a boot needs. Services sharing a Dockerfile build their common stages
        /// once. Warms the cache; with --out each exports to <out>/<name>.ext4. Excludes -f/--target
        #[arg(long)]
        compose: Option<PathBuf>,
        /// with --compose, also build the services this profile enables (repeatable) — the
        /// same profiled services `vk run --compose --profile` would boot
        #[arg(
            long = "profile",
            value_name = "NAME",
            requires = "compose",
            conflicts_with = "primary"
        )]
        profile: Vec<String>,
        /// with --compose, build the set `vk run --compose --primary <NAME>` would boot (this
        /// service plus its dependency closure, and every image: service) rather than the
        /// default profile-enabled set
        #[arg(long, value_name = "NAME", requires = "compose")]
        primary: Option<String>,
        /// build context for COPY (repeatable, zipped positionally with -f;
        /// default: each Dockerfile's own directory)
        #[arg(long)]
        context: Vec<PathBuf>,
        /// ext4 output path
        #[arg(long)]
        out: Option<PathBuf>,
        /// attach this caller-owned raw disk file read-write to the target stage's RUN
        /// guests as /dev/vdb (sources shift to vdc+). Its writes are the artifact — a RUN
        /// can partition it, mkfs and install a bootloader. Size + own the file yourself
        /// (e.g. `qemu-img create -f raw disk.raw 12G`); vk never creates or removes it.
        /// Pairs with `FROM --kernel=image` for a kernel that can drive the disk.
        #[arg(long = "disk", value_name = "PATH")]
        disk: Option<PathBuf>,
        /// parse + plan + print the build order and primitives; build nothing
        #[arg(long = "print-plan")]
        print_plan: bool,
        /// cloud-hypervisor binary — only used when VIRTKIT_VMM=cloud-hypervisor selects
        /// that backend; the default libkrun backend is embedded in `vk` and needs none
        /// (kernel/agent likewise default to the copies embedded in `vk`)
        #[arg(long = "cloud-hypervisor")]
        cloud_hypervisor: Option<PathBuf>,
        #[arg(long)]
        kernel: Option<PathBuf>,
        #[arg(long)]
        agent: Option<PathBuf>,
        /// instruction cache: a registry repo (e.g. 127.0.0.1:5000 of a `vk registry
        /// serve`), an absolute store directory path (accessed in-process), or `none`
        /// to disable. Default: the builtin local store `vk registry serve` also uses.
        #[arg(long = "cache-registry")]
        cache_registry: Option<String>,
        /// the cache registry speaks plain HTTP (a loopback regserve); registry
        /// caches only — the builtin/path store has no transport
        #[arg(long = "cache-insecure")]
        cache_insecure: bool,
        /// how aggressively to populate the instruction cache: `auto` (default;
        /// checkpoints only past a work threshold), `layers` (one snapshot per stage,
        /// no partial-prefix reuse), or `instructions` (one snapshot per RUN/COPY)
        #[arg(long = "build-cache", value_name = "auto|layers|instructions")]
        build_cache: Option<String>,
        /// add an ext4 journal to the exported image (the build stays journal-less)
        #[arg(long)]
        journal: bool,
        /// use a RAM tmpfs for each stage guest's `/tmp` instead of the default
        /// disk-backed scratch (which bounds a bulk `/tmp` write, e.g. a large toolchain
        /// unpack, by disk rather than ½·guest-RAM). Also settable as `tmp_tmpfs` in `[build]`
        #[arg(long = "build-tmp-tmpfs")]
        build_tmp_tmpfs: bool,
        /// override an ARG default: NAME=VALUE (repeatable)
        #[arg(long = "build-arg", value_name = "NAME=VALUE")]
        build_arg: Vec<String>,
        /// network for the microVM build's RUN steps: `all` (unrestricted) or `none`
        #[arg(long = "build-net", default_value = "all", value_name = "all|none")]
        build_net: String,
        /// restrict RUN egress to this destination IPv4 CIDR, optionally port-scoped
        /// as CIDR:port (repeatable; any --build-allow-* flag turns filtering on)
        #[arg(long = "build-allow-ip", value_name = "CIDR[:PORT]")]
        build_allow_ip: Vec<String>,
        /// restrict RUN egress to hosts at/under this DNS suffix, e.g. `crates.io`
        /// (repeatable; any --build-allow-* flag turns filtering on)
        #[arg(long = "build-allow-name", value_name = "SUFFIX")]
        build_allow_name: Vec<String>,
        /// restores from the instruction cache are allowed, but nothing may build:
        /// a cache miss aborts with exit code 3, so scripts can branch
        /// cached-vs-cold without paying for a build
        #[arg(long = "require-cached")]
        require_cached: bool,
        /// max stages built concurrently on the microVM backend (independent stages
        /// build in parallel over the dependency graph). Default: auto, bounded by host
        /// RAM; also settable via VIRTKIT_BUILD_JOBS. 1 forces a sequential build
        #[arg(long = "build-jobs", value_name = "N")]
        build_jobs: Option<usize>,
        /// verify each stage snapshot with e2fsck as it crosses the instruction cache
        /// (after a load, before an upload) to catch a corrupt ext4 early. Best-effort
        /// (skipped if e2fsck is absent); adds an fsck per instruction
        #[arg(long)]
        debug: bool,
    },
    /// Host side of a forward (companion of `virtkit-agent forward`): accept on
    /// `--listen` and splice each connection to `--to`, opaque to the protocol.
    /// Long-running, spawned detached per job — e.g. the VMM's per-port vsock
    /// unix socket -> a host-local service the guest must not reach directly.
    Forward {
        /// Local address to listen on (a unix socket path, tcp://host:port, ...)
        #[arg(long)]
        listen: SocketAddr,
        /// Target each accepted connection is spliced to
        #[arg(long)]
        to: SocketAddr,
    },
    /// plumbing: splice stdio to the target address — the SSH `ProxyCommand` shape. ssh
    /// hands its protocol stream on stdio; we relay it to the guest's ssh-serve (`run --ssh`
    /// prints the full invocation). Addresses: a unix path, vsock-mux://<path>:<port>,
    /// vsock-auto://<path>:<port> (best path per backend),
    /// tcp://host:port.
    Connect {
        /// Target address to dial
        addr: SocketAddr,
    },
    /// Probe a running guest's agent: round-trip the status request to the given address
    /// (the exec channel, e.g. vsock-auto://DIR/vsock.sock:4444) and print the reply, or
    /// exit non-zero if it does not answer. A liveness check that actually exercises
    /// the agent protocol — stronger than a socket stat — so external tooling can ask
    /// "is this VM up?" with `vk` alone, no separate agent binary.
    Status {
        /// Agent address to dial (the run's exec channel)
        addr: SocketAddr,
    },
    /// Run a command in a live guest over its agent exec channel — an interactive
    /// shell or a one-shot command, as `--user` in `--dir`. Reuses the same client
    /// the in-guest agent embeds, so a host reaches a running VM with `vk` alone,
    /// no separate `vk-agent` binary. `vk` exits with the command's own status.
    #[command(arg_required_else_help = true)]
    Exec {
        /// Agent address to dial (the run's exec channel, e.g. vsock-auto://DIR/vsock.sock:4444)
        addr: SocketAddr,
        /// Background mode: no stdio, do not wait for the command to exit
        #[arg(short, long)]
        background: bool,
        /// Start the remote process with an empty environment
        #[arg(long)]
        clear_env: bool,
        /// Add an environment variable, syntax KEY=value (repeatable)
        #[arg(long)]
        env: Vec<String>,
        /// Working directory for the remote process (default: the agent's own)
        #[arg(long)]
        dir: Option<String>,
        /// Allocate a remote pty and run interactively (requires local stdin/stdout
        /// to be a terminal; incompatible with --background)
        #[arg(short = 't', long)]
        tty: bool,
        /// Run the remote process as this Unix user (drops uid/gid/groups)
        #[arg(long)]
        user: Option<String>,
        /// Command to run, followed by its arguments (use `--` to end vk's own flags)
        cmd: String,
        args: Vec<String>,
    },
    /// Filtering ssh-agent proxy: serve the ssh-agent protocol on `--listen`, relaying to
    /// the real agent at `--upstream` but exposing only the keys in the `--allow` .pub
    /// files (refusing to sign with or list any other key). The host side of forwarding a
    /// subset of the agent into a guest.
    SshAgentProxy {
        /// Unix socket to serve on (the VMM's per-port vsock socket)
        #[arg(long)]
        listen: PathBuf,
        /// The real ssh-agent socket to relay to (e.g. $SSH_AUTH_SOCK)
        #[arg(long)]
        upstream: PathBuf,
        /// OpenSSH public-key file whose key may be exposed (repeatable)
        #[arg(long = "allow", value_name = "PUBKEY")]
        allow: Vec<PathBuf>,
    },
    /// Userspace L2 network gateway for microVM(s). Accepts the
    /// qemu vhost transport on each VM's hybrid-vsock guest-port socket, answers
    /// ARP + serves DHCP, and proxies guest TCP/UDP out through the host's own
    /// sockets — no host privileges, multi-VM on one LAN. Replaces gvproxy.
    Switch {
        /// VM qemu socket(s) to accept on (Cloud Hypervisor's <vsock.sock>_<port>);
        /// repeatable — one per VM on the shared LAN.
        #[arg(long = "listen", required = true)]
        listen: Vec<PathBuf>,
        /// Gateway IPv4 — also the DHCP server and DNS address.
        #[arg(long, default_value = "192.168.127.1")]
        gateway: std::net::Ipv4Addr,
        /// Subnet prefix length.
        #[arg(long, default_value_t = 24)]
        prefix: u8,
        /// service name the gateway resolver answers locally: name=ip (repeatable)
        #[arg(long = "host")]
        host: Vec<String>,
        /// per-MAC DHCP reservation: mac=ip (repeatable). A guest with this MAC gets
        /// exactly this address instead of a pool lease.
        #[arg(long = "reserve", value_name = "MAC=IP")]
        reserve: Vec<String>,
        /// egress allowlist — destination IPv4 CIDR for direct (non-proxied) egress,
        /// optionally port-scoped as CIDR:port (repeatable). With no
        /// --allow-ip/--allow-name, egress is unrestricted.
        #[arg(long = "allow-ip", value_name = "CIDR[:PORT]")]
        allow_ip: Vec<String>,
        /// egress allowlist — hostname suffix the http(s) proxy permits, e.g.
        /// `corp.example.com` (repeatable).
        #[arg(long = "allow-name", value_name = "SUFFIX")]
        allow_name: Vec<String>,
    },
    /// Dev: run a docker/OCI image as a microVM — boot it from a native ext4 disk
    /// (or a cpio initramfs in RAM with --ram), virtkit-agent as PID 1 over vsock, and
    /// run a command or interactive shell.
    Run {
        /// Image to boot (docker ref, or OCI reference with --source oci), e.g. alpine:3.20.
        /// Omit when booting a Dockerfile target with --file.
        image: Option<String>,
        /// Boot a Dockerfile target instead of an image: build (or cache-restore, with
        /// --cache-registry) the target into an ext4 and boot it — no explicit ext4
        /// file (repeatable: the files merge into one stage namespace)
        #[arg(short = 'f', long = "file")]
        file: Vec<PathBuf>,
        /// target stage to boot (AS name or index; default: the last stage), with --file
        #[arg(long)]
        target: Option<String>,
        /// build context for the Dockerfile's COPY (repeatable, zipped positionally
        /// with -f; default: each Dockerfile's own directory)
        #[arg(long)]
        context: Vec<PathBuf>,
        /// instruction cache for the --file build (push/pull each stage's ext4 by
        /// content key, so a repeat boot restores instead of rebuilding): a registry
        /// repo, an absolute store directory path, or `none` to disable. Default:
        /// the builtin local store `vk registry serve` also uses.
        #[arg(long = "cache-registry")]
        cache_registry: Option<String>,
        /// the cache registry speaks plain HTTP (a loopback regserve); registry
        /// caches only — the builtin/path store has no transport
        #[arg(long = "cache-insecure")]
        cache_insecure: bool,
        /// override an ARG default for the --file build: NAME=VALUE (repeatable)
        #[arg(long = "build-arg", value_name = "NAME=VALUE")]
        build_arg: Vec<String>,
        /// network for the --file build's RUN steps: `all` (unrestricted) or `none`.
        /// Independent of --net, which governs the booted guest.
        #[arg(long = "build-net", default_value = "all", value_name = "all|none")]
        build_net: String,
        /// restrict the --file build's RUN egress to this destination IPv4 CIDR,
        /// optionally port-scoped as CIDR:port (repeatable; any --build-allow-* flag
        /// turns filtering on)
        #[arg(long = "build-allow-ip", value_name = "CIDR[:PORT]")]
        build_allow_ip: Vec<String>,
        /// restrict the --file build's RUN egress to hosts at/under this DNS suffix,
        /// e.g. `crates.io` (repeatable; any --build-allow-* flag turns filtering on)
        #[arg(long = "build-allow-name", value_name = "SUFFIX")]
        build_allow_name: Vec<String>,
        /// share a host dir read-write into the guest (mounted at /work) and run the
        /// command there, so its outputs land back on the host
        #[arg(long, value_name = "DIR")]
        workdir: Option<PathBuf>,
        /// Kernel: `default` (virtkit's pinned kernel), `image` (the image's own
        /// /boot/vmlinuz + modules), or a path to a vmlinux/bzImage.
        #[arg(long, default_value = "default", value_parser = run::KernelSource::parse)]
        kernel: run::KernelSource,
        /// Where the rootfs comes from: oci (registry pull, no docker daemon), docker
        /// (docker export), or auto (registry, falling back to docker for an unpushed image)
        #[arg(long, value_enum, default_value = "auto")]
        source: run::SourceMode,
        /// PEM CA bundle the registry TLS cert chains to (oci/auto)
        #[arg(long)]
        ca: Option<PathBuf>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        /// plain HTTP registry (oci/auto)
        #[arg(long)]
        insecure: bool,
        /// Static (musl) vk-agent injected as PID 1. Defaults to the copy embedded in `vk`.
        #[arg(long = "agent")]
        agent: Option<PathBuf>,
        /// cloud-hypervisor binary
        #[arg(long, default_value = "cloud-hypervisor")]
        cloud_hypervisor: PathBuf,
        /// vCPUs: a number, or `host` for as many as the host has (its logical CPU count)
        #[arg(long, default_value = "2", value_parser = parse_cpus)]
        cpus: u32,
        #[arg(long, default_value = "1G")]
        mem: String,
        #[arg(long, default_value_t = 120)]
        boot_timeout: u64,
        /// Name for the VM's process (shown in `ps`/`top`): a template where `{name}`
        /// expands to the Dockerfile stage, image, or compose service name
        #[arg(long = "vm-name", default_value = "vk:{name}", value_name = "TEMPLATE")]
        vm_name: String,
        /// Boot the rootfs as a cpio initramfs held entirely in RAM: zero host
        /// scratch, but the guest needs --mem of roughly three times the image size
        #[arg(long)]
        ram: bool,
        /// Who runs as PID 1: `default` (vk-agent) or `image` (the image's own
        /// init/systemd, via the preinit handoff). `image` needs an image or `-f`
        /// build and is incompatible with --ram.
        #[arg(long, default_value = "default")]
        init: run::InitSource,
        /// Drop into an interactive shell in the guest (requires a terminal);
        /// ignores any trailing command
        #[arg(long)]
        shell: bool,
        /// Give the guest network egress via a userspace `vk switch`
        /// (DHCP + DNS + transparent proxy over vsock)
        #[arg(long)]
        net: bool,
        /// boot this compose file's services as sibling microVMs on the run's LAN
        /// (implies --net): the command reaches them by alias; everything is torn
        /// down when the run exits. No readiness wait — retry the first connect.
        /// Services declare `image:` or `build:` (`build.dockerfile` may be a
        /// list: the files merge into one stage namespace, `target` picks any
        /// stage across them). Alone (no image/-f/--primary) this is compose up:
        /// services only, held until ctrl-c.
        #[arg(long)]
        compose: Option<PathBuf>,
        /// activate a compose profile (repeatable): profiled services stay down
        /// unless activated or depended on
        #[arg(long = "profile", value_name = "NAME")]
        profile: Vec<String>,
        /// boot this compose service as the primary VM (like docker compose run):
        /// its image is the rootfs, its config the command's env — with no trailing
        /// command its entrypoint+cmd runs — and only its depends_on chain boots
        /// alongside. Requires --compose; replaces the image/-f
        #[arg(long, value_name = "NAME", requires = "compose")]
        primary: Option<String>,
        /// Forward the host SSH agent ($SSH_AUTH_SOCK) into the guest, so ssh/git in the
        /// guest use the host's keys without the keys ever entering the guest
        #[arg(long = "ssh-agent")]
        ssh_agent: bool,
        /// Expose only these ~/.ssh/config Host aliases to the guest: a filtered agent
        /// offers just their keys and their config stanzas are injected (repeatable).
        /// Implies --ssh-agent.
        #[arg(long = "ssh-host", value_name = "ALIAS")]
        ssh_host: Vec<String>,
        /// Serve SSH into the guest (the agent's in-VM ssh-serve over vsock — no sshd
        /// in the image): prints a ready-to-paste ssh command once booted. Sessions
        /// run as --ssh-user (default root); the VM lives for the duration of the run command.
        #[arg(long)]
        ssh: bool,
        /// public key authorised for --ssh (OpenSSH format, repeatable; implies --ssh).
        /// Default: your standard ~/.ssh/id_*.pub keys
        #[arg(long = "ssh-key", value_name = "PUBKEY")]
        ssh_key: Vec<String>,
        /// user --ssh sessions log in as — root is the only user every image is
        /// guaranteed to have, but a dev image's unprivileged user keeps
        /// shared-tree ownership coherent
        #[arg(long = "ssh-user", value_name = "NAME", default_value = "root",
              value_parser = run::parse_ssh_user)]
        ssh_user: String,
        /// pin the run's sockets, console log and build media to this directory
        /// (created/reused, mode 0700, never removed) instead of a fresh temp dir,
        /// so external tooling can attach to the running VM:
        /// `vk-agent -s vsock-auto://DIR/vsock.sock:4444 exec …`
        #[arg(long = "state-dir", value_name = "DIR")]
        state_dir: Option<PathBuf>,
        /// bind-mount an extra host dir into the guest (repeatable), beyond --workdir
        /// — e.g. persistent state a throwaway VM should keep on the host
        #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
        volume: Vec<String>,
        /// create an in-guest symlink after the mounts (repeatable) — the single-file
        /// share escape hatch (virtiofs shares directories only); a dangling SRC is
        /// skipped
        #[arg(long = "symlink", value_name = "SRC:DST")]
        symlink: Vec<String>,
        /// attach a raw host disk image as a block device (repeatable), ordered after
        /// any rootfs disk (so typically /dev/vdb, vdc, …; but /dev/vda first under
        /// --ram, which has no rootfs disk). The guest reads/writes it directly (no
        /// virtiofs), so it can partition, mkfs and install into a disk image; append
        /// `:ro` for read-only. HOST is a raw image file (qemu-img / truncate); qcow2
        /// is not accepted here.
        #[arg(long = "disk", value_name = "HOST[:ro]")]
        disk: Vec<String>,
        /// extra environment for the guest command and its login shells (repeatable);
        /// wins over the image env and any --env-file
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// KEY=VALUE lines of extra guest environment (`#` and blank lines skipped;
        /// repeatable, later files win; --env flags win over every file)
        #[arg(long = "env-file", value_name = "FILE")]
        env_file: Vec<PathBuf>,
        /// serve host commands to the guest at /run/vk/host.sock (over vsock): guest
        /// tooling runs `vk-agent -s /run/vk/host.sock exec -- CMD` on the host.
        /// WITHOUT --host-exec-wrapper the guest can run ANY host command as the host
        /// user (unrestricted); add --host-exec-wrapper to force every command through
        /// an allowlist program
        #[arg(long = "host-exec")]
        host_exec: bool,
        /// force every --host-exec command through this program (it receives the
        /// requested command line as its arguments and decides what to run)
        #[arg(
            long = "host-exec-wrapper",
            value_name = "PROGRAM",
            requires = "host_exec"
        )]
        host_exec_wrapper: Option<PathBuf>,
        /// client env vars passed through to the --host-exec-wrapper (repeatable;
        /// shell-style globs, e.g. `LC_*`)
        #[arg(
            long = "host-exec-env",
            value_name = "GLOB",
            requires = "host_exec_wrapper"
        )]
        host_exec_env: Vec<String>,
        /// the -f/--primary/compose builds may restore from the instruction cache but
        /// must not build: a cache miss aborts with exit code 3, so scripts can branch
        /// cached-vs-cold without paying for a build
        #[arg(long = "require-cached")]
        require_cached: bool,
        /// Daemonize once the guest is ready: run the build + boot in the foreground
        /// (Ctrl-C aborts them), then detach so the terminal is freed while the VM keeps
        /// running. Intended for a long-lived run (`--ssh`, or `-- sleep infinity`)
        #[arg(long = "detach")]
        detach: bool,
        /// With --detach, redirect the backgrounded VM's output here after detaching
        /// (default: discard). The foreground build/boot still prints to the terminal
        #[arg(long = "detach-log", value_name = "PATH", requires = "detach")]
        detach_log: Option<PathBuf>,
        /// Command to run in the guest (default: a boot-info probe). Several
        /// words are an argv, each passed as typed (like docker run — use
        /// `sh -c '…'` for shell features); a single word is a shell one-liner
        /// run verbatim
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Print each stage's build-cache key (its `stage_key`: the chained content key after
    /// the stage's last instruction) — the exact identity virtkit's instruction cache
    /// stores the stage's snapshot under. Prints `stage:key` lines. Resolves base
    /// digests + base image config over the network so the key matches a real build.
    DockerHash {
        /// Dockerfile to analyze (default: Dockerfile; repeatable: the files merge
        /// into one stage namespace, exactly as `vk build` sees them)
        #[arg(short = 'f', long = "file", default_value = "Dockerfile")]
        dockerfile: Vec<PathBuf>,
        /// Build arg affecting the key (KEY=VAL), repeatable
        #[arg(long = "build-arg")]
        build_arg: Vec<String>,
        /// Build context for context `COPY` content hashing (repeatable, zipped
        /// positionally with -f; default: each Dockerfile's own directory)
        #[arg(long)]
        context: Vec<PathBuf>,
        /// Stages to print (default: all, in build order)
        stages: Vec<String>,
    },
    /// Check whether an ext4 image is fresh given a list of content-fingerprint parts
    /// (pre-hashed strings or raw values): computes sha256(parts joined by '\n')
    /// formatted 8-4-4-4-12, reads the image's UUID, and exits 0 if they match (fresh)
    /// or 1 if they differ or the image is missing (stale). Always prints the UUID on
    /// stdout so the caller can pass it to `mkext-tar --uuid` on a stale build.
    Fingerprint {
        /// ext4 image to check for freshness
        ext4: PathBuf,
        /// Parts to hash (pre-computed hashes or raw strings), joined by '\n'
        parts: Vec<String>,
    },
    /// Dev: build an ext4 image from a directory tree (native, no mke2fs).
    Mkext { src: PathBuf, out: PathBuf },
    /// Dev: verify the native qcow2 reader against `qemu-img convert` for an image.
    Qcow2Verify { path: PathBuf },
    /// Build an ext4 image from a rootfs tar (e.g. `docker export`), injecting
    /// host files at guest paths. Native, no mke2fs, no root.
    MkextTar {
        /// rootfs tar (ownership/mode from its headers), or "-" to STREAM stdin
        /// (e.g. `docker export | … -`) — single pass, no intermediate tar
        tar: PathBuf,
        /// output ext4 image
        out: PathBuf,
        /// inject a host file at a guest path, HOST:GUEST:OCTAL_MODE (repeatable)
        #[arg(long = "inject", value_name = "HOST:GUEST:MODE")]
        inject: Vec<String>,
        /// spare free space (GiB) left in the filesystem for the guest to write
        #[arg(long, default_value_t = 0)]
        free_gib: u64,
        /// streaming only (tar = "-"): upper-bound rootfs size in GiB (the image is
        /// sparse, so over-estimating is free); required when streaming
        #[arg(long, default_value_t = 0)]
        size_gib: u64,
        /// streaming only: inode budget override (default: ~1 per 16 KiB)
        #[arg(long)]
        inodes: Option<u64>,
        /// filesystem UUID to stamp (32 hex digits, dashes optional) — set it to a
        /// content fingerprint to make the image's identity == what it was built from
        #[arg(long)]
        uuid: Option<String>,
        /// filesystem label to stamp (≤16 bytes; for blkid/lsblk)
        #[arg(long)]
        label: Option<String>,
    },
    /// Build an ext4 image straight from a local OCI image archive (the tar
    /// `buildctl --output type=oci` produces): flatten its layers AND extract the
    /// image config (Env/User/Entrypoint/Cmd into /etc/virtkit/{env,user,cmd}),
    /// no docker/podman. Replaces the podman load→create→export→mkext-tar chain.
    MkextOci {
        /// OCI image archive (tar), or "-" to STREAM stdin (spooled to a temp
        /// file first: OCI archives need random access, index.json is last)
        archive: PathBuf,
        /// output ext4 image
        out: PathBuf,
        /// inject a host file at a guest path, HOST:GUEST:OCTAL_MODE (repeatable)
        #[arg(long = "inject", value_name = "HOST:GUEST:MODE")]
        inject: Vec<String>,
        /// spare free space (GiB) left in the filesystem for the guest to write
        #[arg(long, default_value_t = 0)]
        free_gib: u64,
        /// filesystem UUID to stamp (32 hex digits, dashes optional) — set it to a
        /// content fingerprint to make the image's identity == what it was built from
        #[arg(long)]
        uuid: Option<String>,
        /// filesystem label to stamp (≤16 bytes; for blkid/lsblk)
        #[arg(long)]
        label: Option<String>,
    },
    /// Dev: pull an OCI image from a registry (no docker) and flatten it to a
    /// rootfs tar.
    OciPull {
        reference: String,
        out: PathBuf,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        /// PEM CA bundle the registry's TLS cert chains to
        #[arg(long)]
        ca: Option<PathBuf>,
        /// plain HTTP (a local/insecure registry)
        #[arg(long)]
        insecure: bool,
    },
}

/// Subprocess dispatches that must run before any Tokio runtime is created: they do
/// no async work themselves, and libkrun's qcow2 backend (imago) drives its own
/// runtime — so dispatching them inside a `#[tokio::main]` runtime panics with
/// "Cannot start a runtime from within a runtime". The CLI proper runs on the runtime
/// entered in `cli_main`.
fn main() -> ExitCode {
    // Raise this process's soft open-file limit toward its hard cap (≤1M) before anything
    // else: vk serves each guest's virtio-fs shares in-process (libkrun's built-in fs opens
    // a host fd per accessed shared file — and this same binary re-execs as the libkrun
    // boot child to run the VMM), so a heavy build (`cargo`/`make -j` on a shared workdir) needs far
    // more than a login shell's default soft limit, else the guest sees EMFILE. The separate
    // virtiofsd path already does this (see the virtiofsd module); the built-in path did not.
    raise_nofile();

    // `vk virtiofsd …` — the bundled vhost-user virtio-fs daemon. Dispatched
    // before the clap CLI / config load (it takes virtiofsd's own flags and needs no
    // executor config); the spawned daemon blocks until the VMM disconnects.
    #[cfg(feature = "virtiofsd")]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("virtiofsd") {
            return match virtiofsd::run(args[1..].to_vec()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            };
        }
    }

    // libkrun boot child — internal: boot one microVM under libkrun (the Libkrun Vmm
    // backend re-execs this binary per VM, passing the spec in BOOT_SPEC_ENV so argv is
    // free for the VM's process name). Dispatched before the CLI on that env var; it links
    // libkrun and blocks in krun_start_enter until the guest powers off.
    #[cfg(feature = "libkrun")]
    if let Ok(json) = std::env::var(vmm::BOOT_SPEC_ENV) {
        let spec: vmm::VmSpec = match serde_json::from_str(&json) {
            Ok(spec) => spec,
            Err(e) => return fail(&anyhow::anyhow!("libkrun boot: bad spec: {e}"), 2),
        };
        return match libkrun_sys::boot(&spec) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }

    // `vk run … --detach` — daemonize once the guest is ready. The fork must precede the
    // Tokio runtime (forking a live multi-threaded runtime is undefined behavior): the child
    // continues as the background daemon, the parent supervises the foreground build/boot.
    {
        let args: Vec<String> = std::env::args().collect();
        if detach::wants_detach(&args)
            && let detach::Forked::Parent(code) = detach::fork()
        {
            return code;
        }
    }

    // The CLI proper runs on a Tokio runtime (formerly `#[tokio::main]`).
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(cli_main()),
        Err(e) => fail(&anyhow::anyhow!("building the async runtime: {e}"), 1),
    }
}

/// Best-effort raise of the soft `RLIMIT_NOFILE` to the hard cap (capped at 1M). A user
/// process may lift its soft limit up to the hard limit without privilege; see the caller
/// in `main` for why vk needs it.
fn raise_nofile() {
    // SAFETY: getrlimit/setrlimit read/write only the `rlimit` we pass.
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let want = lim.rlim_max.min(1024 * 1024);
        if lim.rlim_cur < want {
            lim.rlim_cur = want;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &lim); // best-effort; never lowers
        }
    }
}

/// Drive a `vk service` subcommand against the host service manager over the vsock control
/// plane. `up` streams the on-demand build's progress to stderr as it arrives, then prints
/// the final reply; `down`/`status` are single round-trips.
async fn service_cmd(cmd: &ServiceCmd) -> ExitCode {
    use vk_core::fleetctl::{Client, Request};
    let mut client = Client::new();
    let reply = match cmd {
        ServiceCmd::Up { name } => {
            // build progress goes to stderr so stdout carries only the final result line.
            let mut on_progress = |line: &str| eprintln!("{line}");
            client
                .request_streamed(&Request::Start { unit: name.clone() }, &mut on_progress)
                .await
        }
        ServiceCmd::Down { name } => client.request(&Request::Stop { unit: name.clone() }).await,
        ServiceCmd::Status { name: Some(n) } => {
            client.request(&Request::Status { unit: n.clone() }).await
        }
        ServiceCmd::Status { name: None } => client.request(&Request::List).await,
    };
    match reply {
        Ok(reply) => {
            for u in &reply.units {
                println!("{:<16} {:<9} {}", u.name, u.state, u.ip);
            }
            if !reply.message.is_empty() {
                if reply.ok {
                    println!("{}", reply.message);
                } else {
                    eprintln!("{}", reply.message);
                }
            }
            if reply.ok {
                ExitCode::SUCCESS
            } else {
                exit_code(1)
            }
        }
        Err(e) => fail(&e, 1),
    }
}

async fn cli_main() -> ExitCode {
    // reqwest/rustls are compiled with no built-in crypto provider (rustls-no-provider,
    // to keep aws-lc-rs out of the build); install ring — the backend russh already
    // uses — as the process default before any TLS client is constructed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    // `service` talks to the host manager over vsock and needs no host config — handle it
    // before Config::load so it works from inside a guest that has none.
    if let Cmd::Service { cmd } = &cli.cmd {
        return service_cmd(cmd).await;
    }
    let cfg = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => return fail(&e, 2),
    };
    if let Cmd::Check { feature } = &cli.cmd {
        return if check::run(&cfg, feature) {
            ExitCode::SUCCESS
        } else {
            exit_code(1)
        };
    }
    // `run` is a standalone dev path: no JobCtx (no CUSTOM_ENV_* job context).
    if let Cmd::Run {
        image,
        file,
        target,
        context,
        cache_registry,
        cache_insecure,
        build_arg,
        build_net,
        build_allow_ip,
        build_allow_name,
        workdir,
        kernel,
        source,
        ca,
        username,
        password,
        insecure,
        agent,
        cloud_hypervisor,
        cpus,
        mem,
        boot_timeout,
        vm_name,
        ram,
        init,
        shell,
        net,
        compose,
        profile,
        primary,
        ssh_agent,
        ssh_host,
        ssh,
        ssh_key,
        ssh_user,
        state_dir,
        volume,
        symlink,
        disk,
        env,
        env_file,
        host_exec,
        host_exec_wrapper,
        host_exec_env,
        require_cached,
        detach,
        detach_log,
        command,
    } = &cli.cmd
    {
        let services_only = file.is_empty() && image.is_none() && primary.is_none();
        if services_only && compose.is_none() {
            return fail(
                &anyhow::anyhow!("run needs an image, --file <Dockerfile>, or a --compose file"),
                2,
            );
        }
        // Services-only (compose up): there is no primary VM to run anything in.
        if services_only
            && (!command.is_empty()
                || *shell
                || *ssh
                || !ssh_key.is_empty()
                || *ssh_agent
                || !ssh_host.is_empty()
                || workdir.is_some()
                || !volume.is_empty()
                || !symlink.is_empty()
                || !env.is_empty()
                || !env_file.is_empty()
                || *host_exec)
        {
            return fail(
                &anyhow::anyhow!(
                    "--compose without an image/-f/--primary is services-only (compose up) — \
                     there is no primary VM for a command, --shell, --ssh, --workdir, \
                     --volume, --symlink, --env, --env-file, or --host-exec"
                ),
                2,
            );
        }
        if primary.is_some() && (image.is_some() || !file.is_empty()) {
            return fail(
                &anyhow::anyhow!(
                    "--primary selects the primary VM from the compose file — drop the image/-f"
                ),
                2,
            );
        }
        let build_args: Vec<(String, String)> = build_arg
            .iter()
            .map(|a| {
                let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
                (k.to_string(), v.to_string())
            })
            .collect();
        let bnet = match build::BuildNet::from_flags(build_net, build_allow_ip, build_allow_name) {
            Ok(n) => n,
            Err(e) => return fail(&e, 2),
        };
        // --volume: compose bind-mount syntax, relative host paths anchored at the
        // caller's cwd (the compose loader anchors at the file's directory).
        let volumes = if volume.is_empty() {
            Vec::new()
        } else {
            let cwd = match std::env::current_dir() {
                Ok(d) => d,
                Err(e) => return fail(&anyhow::anyhow!(e).context("getting the current dir"), 1),
            };
            match volume
                .iter()
                .map(|v| compose::parse_volume(v, &cwd))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(v) => v,
                Err(e) => return fail(&e, 2),
            }
        };
        let symlinks = match symlink
            .iter()
            .map(|s| compose::parse_symlink(s))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(e) => return fail(&e, 2),
        };
        let extra_env = match collect_extra_env(env_file, env) {
            Ok(v) => v,
            Err(e) => return fail(&e, 2),
        };
        // --disk HOST[:ro]: raw block devices attached after any rootfs disk.
        let extra_disks = parse_disks(disk);
        let args = run::RunArgs {
            image: image.clone().unwrap_or_default(),
            dockerfiles: file.clone(),
            target: target.clone(),
            contexts: context.clone(),
            cache_registry: cache_registry.clone(),
            cache_insecure: *cache_insecure,
            build_args,
            workdir: workdir.clone(),
            kernel: kernel.clone(),
            agent: agent.clone(),
            cloud_hypervisor: cloud_hypervisor.clone(),
            source: *source,
            ca: ca.clone(),
            username: username.clone(),
            password: password.clone(),
            insecure: *insecure,
            cpus: *cpus,
            mem: mem.clone(),
            boot_timeout_secs: *boot_timeout,
            vm_name: vm_name.clone(),
            ram: *ram,
            init: *init,
            shell: *shell,
            // services live on the run switch's LAN: --compose implies it.
            net: *net || compose.is_some(),
            compose: compose.clone(),
            profiles: profile.clone(),
            primary: primary.clone(),
            build_net: bnet,
            ssh_agent: *ssh_agent,
            ssh_hosts: ssh_host.clone(),
            ssh: *ssh || !ssh_key.is_empty(),
            ssh_keys: ssh_key.clone(),
            ssh_user: ssh_user.clone(),
            state_dir: state_dir.clone(),
            volumes,
            symlinks,
            extra_disks,
            env: extra_env,
            host_exec: *host_exec,
            host_exec_wrapper: host_exec_wrapper.clone(),
            host_exec_env: host_exec_env.clone(),
            require_cached: *require_cached,
            detach: *detach,
            detach_log: detach_log.clone(),
            command: command.clone(),
        };
        return match run::run(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) if is_not_cached(&e) => fail(&e, 3),
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::DockerHash {
        dockerfile,
        build_arg,
        context,
        stages,
    } = &cli.cmd
    {
        let args: Vec<(String, String)> = build_arg
            .iter()
            .map(|a| {
                let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
                (k.to_string(), v.to_string())
            })
            .collect();
        return match dockerhash::run(dockerfile, context, &args, stages) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Mkext { src, out } = &cli.cmd {
        return match ext4::build_from_dir(src, out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Qcow2Verify { path } = &cli.cmd {
        return match qcow2::verify_against_convert(path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::MkextTar {
        tar,
        out,
        inject,
        free_gib,
        size_gib,
        inodes,
        uuid,
        label,
    } = &cli.cmd
    {
        let fsid = {
            let uuid = match uuid {
                Some(s) => match parse_uuid(s) {
                    Some(u) => Some(u),
                    None => {
                        return fail(&anyhow::anyhow!("bad --uuid {s:?} (want 32 hex digits)"), 2);
                    }
                },
                None => None,
            };
            ext4::FsId {
                uuid,
                label: label.clone(),
                with_journal: true,
            }
        };
        let parsed = match parse_injects(inject) {
            Ok(p) => p,
            Err(e) => return fail(&e, 2),
        };
        let injects: Vec<(&str, &Path, u16)> = parsed
            .iter()
            .map(|(g, h, m)| (g.as_str(), h.as_path(), *m))
            .collect();
        let extra_free = free_gib * (1024 * 1024 * 1024 / 4096); // GiB -> 4 KiB blocks
        let r = if tar.as_os_str() == "-" {
            if *size_gib == 0 {
                return fail(
                    &anyhow::anyhow!("--size-gib is required when streaming (tar = -)"),
                    2,
                );
            }
            let reader = ProgressReader::new(std::io::BufReader::with_capacity(
                1 << 20,
                std::io::stdin().lock(),
            ));
            let res = ext4::build_from_tar_stream(
                reader,
                &injects,
                size_gib * (1 << 30),
                extra_free,
                *inodes,
                &fsid,
                out,
            );
            eprintln!(); // terminate the progress line
            res
        } else {
            ext4::build_from_tar_injecting(tar, &injects, extra_free, &fsid, out)
        };
        return match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::MkextOci {
        archive,
        out,
        inject,
        free_gib,
        uuid,
        label,
    } = &cli.cmd
    {
        let fsid = {
            let uuid = match uuid {
                Some(s) => match parse_uuid(s) {
                    Some(u) => Some(u),
                    None => {
                        return fail(&anyhow::anyhow!("bad --uuid {s:?} (want 32 hex digits)"), 2);
                    }
                },
                None => None,
            };
            ext4::FsId {
                uuid,
                label: label.clone(),
                with_journal: true,
            }
        };
        let parsed = match parse_injects(inject) {
            Ok(p) => p,
            Err(e) => return fail(&e, 2),
        };
        let injects: Vec<(&str, &Path, u16)> = parsed
            .iter()
            .map(|(g, h, m)| (g.as_str(), h.as_path(), *m))
            .collect();
        let extra_free = free_gib * (1024 * 1024 * 1024 / 4096); // GiB -> 4 KiB blocks
        return match mkoci::archive_to_ext4(archive, out, &injects, &[], extra_free, &fsid) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Build {
        file,
        target,
        compose,
        profile,
        primary,
        context,
        out,
        disk,
        print_plan,
        cloud_hypervisor,
        kernel,
        agent,
        cache_registry,
        cache_insecure,
        build_cache,
        journal,
        build_tmp_tmpfs,
        build_arg,
        build_net,
        build_allow_ip,
        build_allow_name,
        require_cached,
        build_jobs,
        debug,
    } = &cli.cmd
    {
        // each --build-arg is NAME=VALUE; a bare NAME means an empty value.
        let build_args: Vec<(String, String)> = build_arg
            .iter()
            .map(|a| match a.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (a.clone(), String::new()),
            })
            .collect();
        let net = match build::BuildNet::from_flags(build_net, build_allow_ip, build_allow_name) {
            Ok(n) => n,
            Err(e) => return fail(&e, 2),
        };
        // CLI flag wins, else the [build] config default.
        let build_cache = match build_cache {
            Some(m) => match m.parse::<build::BuildCache>() {
                Ok(m) => m,
                Err(e) => return fail(&anyhow::anyhow!(e), 2),
            },
            None => cfg.build.build_cache,
        };
        // CLI flag wins; otherwise fall back to [build] config (and the top-level
        // cloud_hypervisor for the build guest's VMM). bool flags are opt-in, so a set
        // flag or a config `true` enables them.
        let b = &cfg.build;
        // Canonicalize --disk like `vk run --disk` (run.rs), so a relative path resolves
        // against the caller's cwd and a missing/inaccessible file fails clearly up front
        // rather than as a cryptic VMM boot error mid-build. vk never creates the file.
        let out_disk = match disk {
            Some(p) => match std::fs::canonicalize(p) {
                Ok(abs) => Some(abs),
                Err(e) => {
                    return fail(
                        &anyhow::anyhow!("--disk {}: cannot access: {e}", p.display()),
                        1,
                    );
                }
            },
            None => None,
        };
        let opts = build::Options {
            dockerfiles: file.clone(),
            // build_units (the multi-target / --compose path) reads targets from its units;
            // the single-image path uses this one (default: the last stage).
            target: target.first().cloned(),
            contexts: context.clone(),
            out: out.clone(),
            out_disk,
            print_plan: *print_plan,
            cloud_hypervisor: cloud_hypervisor
                .clone()
                .or_else(|| b.cloud_hypervisor.clone())
                .or_else(|| cfg.cloud_hypervisor.clone()),
            kernel: kernel.clone().or_else(|| b.kernel.clone()),
            agent: agent.clone().or_else(|| b.agent.clone()),
            cache_registry: cache_registry.clone().or_else(|| b.cache_registry.clone()),
            cache_insecure: *cache_insecure || b.cache_insecure,
            build_cache,
            journal: *journal || b.journal,
            tmp_tmpfs: *build_tmp_tmpfs || b.tmp_tmpfs,
            build_args,
            net,
            require_cached: *require_cached,
            build_jobs: *build_jobs,
            debug: *debug,
            progress_sink: None,
        };
        // A compose file, or more than one --target, builds several images together in one
        // pass: their common stages build once and the rest run concurrently. Each image
        // exports to <out>/<name>.ext4 when --out is given, else only the cache is warmed.
        // A single/absent target keeps the plain single-image build (and --print-plan).
        if compose.is_some() || target.len() > 1 {
            if *print_plan {
                return fail(
                    &anyhow::anyhow!(
                        "--print-plan builds one target; drop --compose / extra --target"
                    ),
                    2,
                );
            }
            if let Some(dir) = out
                && let Err(e) = std::fs::create_dir_all(dir)
            {
                return fail(
                    &anyhow::anyhow!("creating --out dir {}: {e}", dir.display()),
                    1,
                );
            }
            let out_file = |name: &str| out.as_ref().map(|d| d.join(format!("{name}.ext4")));
            let units = if let Some(path) = compose {
                if !target.is_empty() {
                    return fail(
                        &anyhow::anyhow!(
                            "--compose selects services from the compose file; --target does not apply"
                        ),
                        2,
                    );
                }
                // --compose uses each service's own Dockerfile, so a user-supplied -f has
                // no effect; reject it rather than silently ignore it (default: "Dockerfile").
                if file.len() != 1 || file[0] != Path::new("Dockerfile") {
                    return fail(
                        &anyhow::anyhow!(
                            "--compose builds each service's own Dockerfile; -f does not apply"
                        ),
                        2,
                    );
                }
                let cunits = match compose::load(path) {
                    Ok(u) => u,
                    Err(e) => return fail(&e, 1),
                };
                if cunits.is_empty() {
                    return fail(
                        &anyhow::anyhow!("{} declares no services", path.display()),
                        1,
                    );
                }
                let selected =
                    match run::compose_build_selection(&cunits, profile, primary.as_deref()) {
                        Ok(s) => s,
                        Err(e) => return fail(&e, 2),
                    };
                run::compose_build_units(&opts.build_args, &cunits, &selected, |u| {
                    out_file(&u.name)
                })
            } else {
                // several --target of one Dockerfile: one unit, one target per selector.
                // De-duplicate the selectors (first-seen order) so `--target app --target
                // app` — which the DAG builds once — does not export or report it twice.
                let mut seen = std::collections::HashSet::new();
                let targets = target
                    .iter()
                    .filter(|t| seen.insert((*t).clone()))
                    .map(|t| build::TargetSpec {
                        label: t.clone(),
                        selector: Some(t.clone()),
                        out: out_file(t),
                    })
                    .collect();
                vec![build::BuildUnit {
                    label: String::new(),
                    input: build::UnitInput::Build {
                        dockerfiles: file.clone(),
                        contexts: context.clone(),
                    },
                    build_args: opts.build_args.clone(),
                    targets,
                }]
            };
            return match build::build_units(units, &opts) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) if is_not_cached(&e) => fail(&e, 3),
                Err(e) => fail(&e, 1),
            };
        }
        return match build::build(&opts) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) if is_not_cached(&e) => fail(&e, 3),
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Fingerprint { ext4, parts } = &cli.cmd {
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let uuid = ensure::fingerprint(&refs);
        println!("{uuid}");
        if ext4::fs_uuid(ext4).as_deref() == Some(uuid.as_str()) {
            return ExitCode::SUCCESS;
        }
        return exit_code(1);
    }
    if let Cmd::OciPull {
        reference,
        out,
        username,
        password,
        ca,
        insecure,
    } = &cli.cmd
    {
        let ca_pem = match ca {
            Some(p) => match std::fs::read(p) {
                Ok(b) => Some(b),
                Err(e) => return fail(&anyhow::anyhow!("reading {}: {e}", p.display()), 1),
            },
            None => None,
        };
        return match oci::pull_flatten(
            reference,
            username.as_deref(),
            password.as_deref(),
            ca_pem,
            *insecure,
            out,
            &|m| println!("{m}"),
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Registry { cmd } = &cli.cmd {
        return match cmd {
            RegistryCmd::Push { dir, reference } => match registry::push(&cfg, dir, reference) {
                Ok(_digest) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            },
            RegistryCmd::Inspect { reference } => match registry::inspect(&cfg, reference) {
                Ok(digest) => {
                    println!("{digest}");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e, 1),
            },
            // pull consumes cfg (it builds a throwaway JobCtx to share the cache layout)
            RegistryCmd::Pull { reference } => match registry::pull(cfg, reference) {
                Ok(dir) => {
                    println!("{}", dir.display());
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e, 1),
            },
            RegistryCmd::Serve { addr, root } => {
                let root = match root.clone().map(Ok).unwrap_or_else(regserve::default_root) {
                    Ok(r) => r,
                    Err(e) => return fail(&e, 2),
                };
                match regserve::serve(*addr, root).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, 1),
                }
            }
            RegistryCmd::InstallService { addr, root } => {
                let root = match root.clone().map(Ok).unwrap_or_else(regserve::default_root) {
                    Ok(r) => r,
                    Err(e) => return fail(&e, 2),
                };
                match regserve::install_service(*addr, &root) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, 1),
                }
            }
            RegistryCmd::Gc {
                root,
                retention_days,
                grace_days,
                dry_run,
            } => {
                let root = match root.clone().map(Ok).unwrap_or_else(regserve::default_root) {
                    Ok(r) => r,
                    Err(e) => return fail(&e, 2),
                };
                let days = |d: u64| std::time::Duration::from_secs(d * 86_400);
                match regserve::gc(root, days(*retention_days), days(*grace_days), *dry_run) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, 1),
                }
            }
        };
    }
    if let Cmd::Switch {
        listen,
        gateway,
        prefix,
        host,
        reserve,
        allow_ip,
        allow_name,
    } = &cli.cmd
    {
        let mut hosts = std::collections::HashMap::new();
        for h in host {
            match h.split_once('=').and_then(|(n, ip)| {
                ip.parse::<std::net::Ipv4Addr>()
                    .ok()
                    .map(|ip| (n.to_ascii_lowercase(), ip))
            }) {
                Some((name, ip)) => {
                    hosts.insert(name, ip);
                }
                None => return fail(&anyhow::anyhow!("bad --host {h:?} (want name=ip)"), 2),
            }
        }
        let mut reservations = std::collections::HashMap::new();
        for r in reserve {
            match r.split_once('=').and_then(|(m, ip)| {
                Some((
                    switch::parse_mac(m)?,
                    ip.parse::<std::net::Ipv4Addr>().ok()?,
                ))
            }) {
                Some((mac, ip)) => {
                    reservations.insert(mac, ip);
                }
                None => return fail(&anyhow::anyhow!("bad --reserve {r:?} (want mac=ip)"), 2),
            }
        }
        let egress = match switch::Egress::new(allow_ip, allow_name) {
            Ok(e) => e,
            Err(e) => return fail(&e, 2),
        };
        return match switch::run(listen, *gateway, *prefix, hosts, reservations, egress).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    let ctx = match JobCtx::new(cfg) {
        Ok(ctx) => ctx,
        Err(e) => return fail(&e, 2),
    };

    match cli.cmd {
        Cmd::Gitlab { cmd } => match cmd {
            GitlabCmd::Config => {
                let info = serde_json::json!({
                    "driver": {
                        "name": "virtkit",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "builds_dir": ctx.cfg.guest.builds_dir,
                    "cache_dir": ctx.cfg.guest.cache_dir,
                    "builds_dir_is_shared": false,
                });
                println!("{info}");
                ExitCode::SUCCESS
            }
            GitlabCmd::Prepare => match vm::prepare(&ctx).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, ctx.system_failure),
            },
            GitlabCmd::Run { script, stage: _ } => match executor::run_stage(&ctx, &script).await {
                Ok(result) => match (result.code, result.signal) {
                    (Some(0), _) => ExitCode::SUCCESS,
                    // non-zero exit: the script already reported its error
                    (Some(_), _) => exit_code(ctx.build_failure),
                    (None, signal) => {
                        eprintln!("virtkit: stage script killed by signal {signal:?}");
                        exit_code(ctx.build_failure)
                    }
                },
                // can't reach/drive the VM: environment problem, job is retryable
                Err(e) => fail(&e, ctx.system_failure),
            },
            GitlabCmd::Supervise { job_dir } => match vm::supervise(&ctx, &job_dir).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            },
            GitlabCmd::Cleanup => match vm::cleanup(&ctx) {
                Ok(()) => ExitCode::SUCCESS,
                // gitlab-runner only logs cleanup failures; report and don't mask
                Err(e) => fail(&e, 1),
            },
        },
        // stdio↔socket splice for an SSH ProxyCommand; returns when either side closes.
        Cmd::Connect { addr } => match vk_core::forward::run_connect(&addr).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
        // Agent liveness probe: round-trip the status request (same client the boot
        // readiness wait uses) so a caller can check the VM is up with vk alone.
        Cmd::Status { addr } => match vk_core::status::get_status(&addr).await {
            Ok(status) => {
                println!("{status}");
                ExitCode::SUCCESS
            }
            // get_status yields a boxed std error; wrap it for the anyhow-typed reporter.
            Err(e) => fail(&anyhow::anyhow!("{e}"), 1),
        },
        // Run a command in a live guest, reproducing its exit status as our own.
        Cmd::Exec {
            addr,
            background,
            clear_env,
            env,
            dir,
            tty,
            user,
            cmd,
            args,
        } => match exec::run(addr, background, clear_env, env, dir, tty, user, cmd, args).await {
            Ok(result) => exec::exit(result),
            Err(e) => fail(&e, 1),
        },
        // run_forward only returns on a bind error; otherwise it serves until the
        // process is killed (cleanup tears the detached child down).
        Cmd::Forward { listen, to } => {
            match vk_core::forward::run_forward(&listen, &to, None).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
        Cmd::SshAgentProxy {
            listen,
            upstream,
            allow,
        } => match sshagent::load_allow(&allow)
            .and_then(|keys| sshagent::run_proxy(&listen, &upstream, &keys))
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
        // handled above, before JobCtx
        Cmd::Check { .. }
        | Cmd::Registry { .. }
        | Cmd::Switch { .. }
        | Cmd::Run { .. }
        | Cmd::Mkext { .. }
        | Cmd::Qcow2Verify { .. }
        | Cmd::MkextTar { .. }
        | Cmd::MkextOci { .. }
        | Cmd::Build { .. }
        | Cmd::OciPull { .. }
        | Cmd::DockerHash { .. }
        | Cmd::Fingerprint { .. }
        | Cmd::Service { .. } => {
            unreachable!()
        }
    }
}

fn fail(e: &anyhow::Error, code: i32) -> ExitCode {
    eprintln!("virtkit: error: {e:#}");
    exit_code(code)
}

/// `--require-cached` refusals get their own exit code (3), so scripts can branch
/// on cached-vs-cold. Checked at the chain root — contexts may wrap the error.
fn is_not_cached(e: &anyhow::Error) -> bool {
    e.root_cause().downcast_ref::<build::NotCached>().is_some()
}

use crate::ensure::parse_uuid;

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(code.clamp(1, 255) as u8)
}

/// Parse `--inject HOST:GUEST:OCTAL_MODE` specs into `(guest, host, mode)`, with
/// the guest path normalized to the image-relative form (no leading slash) the
/// ext4 writer expects. Shared by `mkext-tar` and `mkext-oci`.
fn parse_injects(specs: &[String]) -> anyhow::Result<Vec<(String, PathBuf, u16)>> {
    let mut out = Vec::new();
    for spec in specs {
        let p: Vec<&str> = spec.splitn(3, ':').collect();
        if p.len() != 3 {
            anyhow::bail!("--inject must be HOST:GUEST:MODE, got {spec:?}");
        }
        let mode = u16::from_str_radix(p[2], 8)
            .map_err(|_| anyhow::anyhow!("bad octal mode in {spec:?}"))?;
        out.push((
            p[1].trim_start_matches('/').to_string(),
            PathBuf::from(p[0]),
            mode,
        ));
    }
    Ok(out)
}

/// Parse `--disk HOST[:ro]` specs into `(host path, read-only)` pairs. A trailing
/// `:ro` marks the disk read-only; everything else is the host path (paths with a
/// literal `:` are rare enough that only the `:ro` suffix is special-cased — a file
/// genuinely named `foo:ro` can only attach read-only).
fn parse_disks(specs: &[String]) -> Vec<(PathBuf, bool)> {
    specs
        .iter()
        .map(|d| match d.strip_suffix(":ro") {
            Some(p) => (PathBuf::from(p), true),
            None => (PathBuf::from(d), false),
        })
        .collect()
}

/// Collect the extra guest env from `--env-file`s (in order, later files win)
/// then `--env` flags (they win over every file), upserted into one list — the
/// same upsert the guest applies. `#` and blank lines in a file are skipped.
fn collect_extra_env(files: &[PathBuf], flags: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut extra_env: Vec<(String, String)> = Vec::new();
    let mut env_upsert = |k: &str, v: &str| match extra_env.iter_mut().find(|(ek, _)| ek == k) {
        Some(e) => e.1 = v.to_string(),
        None => extra_env.push((k.to_string(), v.to_string())),
    };
    for path in files {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!(e).context(format!("reading {}", path.display())))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once('=') {
                Some((k, v)) => env_upsert(k, v),
                None => anyhow::bail!("bad line {line:?} in {} (want KEY=VALUE)", path.display()),
            }
        }
    }
    for e in flags {
        match e.split_once('=') {
            Some((k, v)) => env_upsert(k, v),
            None => anyhow::bail!("bad --env {e:?} (want KEY=VALUE)"),
        }
    }
    Ok(extra_env)
}

/// Wraps a reader to print a bytes-streamed indicator to stderr (so streaming a
/// `docker export` shows progress without depending on `pv`).
struct ProgressReader<R> {
    inner: R,
    bytes: u64,
    next_report: u64,
}

impl<R> ProgressReader<R> {
    fn new(inner: R) -> Self {
        ProgressReader {
            inner,
            bytes: 0,
            next_report: 0,
        }
    }
}

impl<R: std::io::Read> std::io::Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes += n as u64;
        if self.bytes >= self.next_report {
            use std::io::Write;
            eprint!(
                "\r   streaming rootfs: {:.1} GiB",
                self.bytes as f64 / (1u64 << 30) as f64
            );
            let _ = std::io::stderr().flush();
            self.next_report = self.bytes + (512 << 20); // report every 512 MiB
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A --inject value parses to a single (guest, host, mode) entry with the guest path
    // normalized to image-relative form.
    #[test]
    fn inject_value_parses() {
        let parsed = parse_injects(&["/host/x.sh:/etc/profile.d/x.sh:0644".to_string()]).unwrap();
        assert_eq!(
            parsed,
            vec![(
                "etc/profile.d/x.sh".to_string(),
                PathBuf::from("/host/x.sh"),
                0o644
            )]
        );
    }

    // --env-file entries load in order (later files win) and --env flags win over
    // every file; `#` and blank lines are skipped; malformed input errors out.
    #[test]
    fn extra_env_upserts_files_then_flags() {
        let dir = std::env::temp_dir().join(format!("virtkit-envfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f1 = dir.join("one.env");
        let f2 = dir.join("two.env");
        std::fs::write(&f1, "# comment\n\nA=1\nB=from-one\nEMPTY=\n").unwrap();
        std::fs::write(&f2, "B=from-two\nC=3\n").unwrap();
        let env = collect_extra_env(
            &[f1.clone(), f2],
            &["C=flag".to_string(), "D=4".to_string()],
        )
        .unwrap();
        assert_eq!(
            env,
            [
                ("A", "1"),
                ("B", "from-two"),
                ("EMPTY", ""),
                ("C", "flag"),
                ("D", "4")
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        // malformed file line and malformed flag both error
        std::fs::write(&f1, "NOEQUALS\n").unwrap();
        assert!(collect_extra_env(&[f1], &[]).is_err());
        assert!(collect_extra_env(&[], &["NOEQUALS".to_string()]).is_err());
        // an unreadable file errors with its path
        let err = collect_extra_env(&[dir.join("missing.env")], &[]).unwrap_err();
        assert!(format!("{err:#}").contains("missing.env"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --disk parses HOST[:ro]: a trailing `:ro` marks the disk read-only, everything
    // else is the host path verbatim; specs are attached in the order given.
    #[test]
    fn disk_specs_parse() {
        assert_eq!(
            parse_disks(&[
                "img.raw".to_string(),
                "/abs/data.img:ro".to_string(),
                "rel/scratch.img".to_string(),
            ]),
            vec![
                (PathBuf::from("img.raw"), false),
                (PathBuf::from("/abs/data.img"), true),
                (PathBuf::from("rel/scratch.img"), false),
            ]
        );
        // only the `:ro` suffix is special; a path merely containing `:` is kept whole
        assert_eq!(
            parse_disks(&["weird:name.img".to_string()]),
            vec![(PathBuf::from("weird:name.img"), false)]
        );
        assert!(parse_disks(&[]).is_empty());
    }

    // --cpus takes a plain number or `host` (the host's logical CPU count, >= 1);
    // anything else is rejected.
    #[test]
    fn cpus_value_parses() {
        assert_eq!(parse_cpus("2"), Ok(2));
        assert!(parse_cpus("host").is_ok_and(|n| n >= 1));
        assert!(parse_cpus("").is_err());
        assert!(parse_cpus("Host").is_err());
        assert!(parse_cpus("-1").is_err());
    }
}
