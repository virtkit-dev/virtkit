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

mod admit;
mod atop;
mod atop_attach;
mod atop_report;
mod atop_view;
mod atoplog;
mod blockrt;
mod build;
mod cachelock;
mod check;
mod checkout;
mod compose;
mod config;
mod consolelog;
mod cpio;
mod detach;
mod dockerhash;
mod dockerimg;
mod egress_report;
mod embed;
mod ensure;
mod exec;
mod executor;
mod ext4;
mod ext4_read;
mod fullvm;
mod image;
mod initramfs;
mod iso9660;
mod jobctx;
#[cfg(feature = "libkrun")]
mod libkrun_sys;
mod local;
mod manager;
mod mkoci;
mod net;
mod oci;
mod oomkills;
mod ova;
mod prio;
mod publish;
mod qcow2;
mod registry;
mod regproxy;
mod run;
mod schedule;
mod scratch;
mod services;
mod shutdown;
mod sites;
mod source;
mod spawn;
mod sshagent;
mod sshclient;
mod sshconf;
mod switch;
mod timing;
mod units;
mod usage;
#[cfg(feature = "virtiofsd")]
mod virtiofsd;
mod vm;
mod vmdk;
mod vmm;
mod vms;

use std::borrow::Cow;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vk_core::addr::SocketAddr;

use crate::config::Config;
use crate::jobctx::JobCtx;

/// This binary as `vk update` replaces it: the release asset `vk` ships as, and the
/// version this build was made from.
const VK: vk_selfupdate::Tool = vk_selfupdate::Tool {
    name: "vk",
    version: env!("CARGO_PKG_VERSION"),
};

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

/// clap value parser for `--build-jobs`: how many stages may build at once, at least one.
/// Parsing straight to `NonZeroUsize` would reject `0` on its own, but with std's wording
/// ("number would be zero for non-zero type"); this says it in the CLI's own terms.
fn parse_build_jobs(s: &str) -> Result<NonZeroUsize, String> {
    s.parse()
        .map_err(|_| format!("expected a positive stage count, got {s:?}"))
}

/// What `vk export` can package a raw disk image as.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
enum ExportFormat {
    /// streamOptimized VMDK — the subformat vSphere's OVF/OVA import requires
    ///
    /// Compressed and stream-readable.
    Vmdk,
    /// OVA appliance — importable by ESXi/vCenter as one file
    ///
    /// The VMDK wrapped in an OVF descriptor and a SHA256 manifest.
    Ova,
    /// bootable ISO 9660 image built from a staged directory tree
    ///
    /// An auto-install medium: bootloader + kernel + installer + disk payload.
    Iso,
}

impl ExportFormat {
    fn extension(self) -> &'static str {
        match self {
            ExportFormat::Vmdk => "vmdk",
            ExportFormat::Ova => "ova",
            ExportFormat::Iso => "iso",
        }
    }
}

/// clap value parser for `--service-cpus` / `--stage-cpus NAME=N`.
fn parse_named_cpus(s: &str) -> Result<(String, u32), String> {
    let (name, n) = s
        .split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .ok_or_else(|| format!("expected NAME=N, got {s:?}"))?;
    let n: u32 = n
        .parse()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("expected a positive vCPU count, got {n:?}"))?;
    Ok((name.to_string(), n))
}

/// Parse `--ssh-alias` before the image build starts.
fn parse_ssh_alias(s: &str) -> Result<String, String> {
    sshclient::validate_alias(s)
        .map(|()| s.to_string())
        .map_err(|e| format!("{e:#}"))
}

/// clap value parser for `--service-mem` / `--stage-mem NAME=SIZE` (`<n>G`, `<n>M` or a
/// MiB count).
fn parse_named_mem(s: &str) -> Result<(String, String), String> {
    let (name, size) = s
        .split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .ok_or_else(|| format!("expected NAME=SIZE, got {s:?}"))?;
    match run::parse_mem_mib(size).filter(|mib| *mib > 0) {
        Some(_) => Ok((name.to_string(), size.to_string())),
        None => Err(format!(
            "expected a non-zero <n>G, <n>M or MiB size, got {size:?}"
        )),
    }
}

/// clap value parser for `--service-nics NAME=N`. Enforce the same bound as
/// `x-virtkit.nics` does at load time, so a typo reports the limit instead of exhausting
/// the LAN's static addresses.
fn parse_named_nics(s: &str) -> Result<(String, u32), String> {
    let (name, n) = s
        .split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .ok_or_else(|| format!("expected NAME=N, got {s:?}"))?;
    let count: u32 = n
        .parse()
        .ok()
        .filter(|c| (1..=units::MAX_NICS).contains(c))
        .ok_or_else(|| {
            format!(
                "expected an interface count from 1 to {}, got {n:?}",
                units::MAX_NICS
            )
        })?;
    Ok((name.to_string(), count))
}

/// Boot OCI/Docker images as fast, rootless microVMs
#[derive(Parser)]
#[command(
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("VK_GIT_HASH"), ")"),
    after_help = "\
Examples:
  vk run alpine                          boot alpine:latest, interactive shell
  vk run alpine -- cat /etc/os-release   run one command, exit with its status
  vk run debian:trixie-slim --mem 2G --cpus 4
  vk run -f Dockerfile                   build the last stage and boot it
  vk run --compose compose.yaml          boot the file's services as a fleet
  vk check                               preflight this host

Every command's -h is a one-line summary per flag; --help adds the full detail.
Run 'vk help-all' to also list the advanced/plumbing commands."
)]
struct Cli {
    /// Config file [default: $VIRTKIT_CONFIG, else the first standard path that exists]
    ///
    /// $VIRTKIT_CONFIG names the file outright, so a path that is not there is an error.
    /// The standard paths are $XDG_CONFIG_HOME/virtkit/config.toml (else
    /// ~/.config/virtkit/config.toml), then /etc/virtkit/config.toml.
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
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
        /// the stage script gitlab-runner passes on the command line
        script: PathBuf,
        /// stage name (prepare_script, get_sources, build_script, …)
        ///
        /// It names the final stage, where the once-per-job summaries are emitted
        /// (see executor::run_stage).
        stage: Option<String>,
    },
    /// cleanup_exec: stop the VM and remove the job state (idempotent)
    Cleanup,
    /// Report what this runner's CI jobs have been reserving, per project
    ///
    /// For each project: every job's recent peak, the runs that peak rests on, and what
    /// its next run would reserve.
    Usage {
        /// report only projects whose directory name contains this
        ///
        /// Any part of the `<id>-<slug>` directory name matches, so the slug alone will
        /// do. Omitted, every project is reported.
        project: Option<String>,
    },
    /// internal: the detached per-job supervisor prepare spawns
    ///
    /// It owns the job's switch/virtiofsds/forwards/VMM as tied children until cleanup
    /// SIGTERMs it.
    #[command(hide = true)]
    Supervise {
        /// the job dir (pid-reuse guard on the cmdline; must match the environment)
        job_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum RegistryCmd {
    /// Push a local bundle dir to the [registry] repo at <name>:<tag>
    ///
    /// The directory holds runner.ext4 + boot.kind [+ vmlinuz + initrd.img], and its
    /// blobs are stored with CDC+zstd chunk dedup.
    Push {
        /// Local bundle directory
        dir: PathBuf,
        /// Target reference, <name>:<tag> (a :tag is required for a push)
        reference: String,
    },
    /// Pull+cache a bundle from the [registry] repo and print its cache dir
    Pull {
        /// Source reference, <name>[:tag|@sha256:…]
        reference: String,
    },
    /// Check a bundle exists in the [registry] repo without pulling it
    ///
    /// It prints the manifest digest and exits 0, or exits non-zero when the bundle is
    /// absent — the CI build's already-built check, replacing `docker manifest inspect`.
    Inspect {
        /// Source reference, <name>[:tag|@sha256:…]
        reference: String,
    },
    // Serving a store over HTTP now lives in the standalone `vk-registry` daemon;
    // `vk` accesses its local filesystem store in-process (registry.rs `mod local`).
    /// Report a registry store's usage and content
    ///
    /// On-disk size (both storage forms), dedup savings, and a per-repository breakdown
    /// (tags, latest tag, logical size). Read-only — it creates no store.
    Status {
        /// store directory [default: the store the build cache uses]
        ///
        /// The build cache's store is `[build] cache_registry`, else
        /// $XDG_DATA_HOME/virtkit/registry.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
    },
    /// Garbage-collect a registry store
    ///
    /// It drops tags idle past the retention window, then sweeps the blobs no surviving
    /// manifest references and the stale uploads (both after a grace window). It holds
    /// the store lock exclusive, briefly blocking concurrent pushers.
    Gc {
        /// store directory [default: the store the build cache uses]
        ///
        /// The build cache's store is `[build] cache_registry`, else
        /// $XDG_DATA_HOME/virtkit/registry.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// drop tags unused for more than this many days
        #[arg(long, default_value_t = 30, value_name = "DAYS")]
        retention_days: u64,
        /// keep unreferenced blobs and stale uploads this many days past their last use
        ///
        /// The window protects in-flight multi-request pushes.
        #[arg(long, default_value_t = 1, value_name = "DAYS")]
        grace_days: u64,
        /// report what would be removed without removing anything
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Bring a service up, building its image on first use
    ///
    /// The first-use build is a profiled-down service build and streams its progress
    /// live. A no-op when the service is already running. Persistent state an earlier
    /// `down` left behind — `x-virtkit.persist_root`, `overlay,persist` uppers and `disk`
    /// volumes — comes back with it; the rest of the guest starts clean from the image.
    Up {
        /// service name (as declared in the compose file)
        name: String,
    },
    /// Stop a running service (a no-op if already stopped)
    ///
    /// Powers the guest off cleanly. Its persistent state, if it declares any, waits for
    /// the next `up`; the rest of the guest is discarded.
    Down {
        /// service name
        name: String,
    },
    /// Reboot a running service's guest in place (same VM, no image rebuild)
    ///
    /// The guest comes back on the same disks, so even a throwaway root keeps its
    /// changes across a reboot; only a stop or restart starts it over.
    Reboot {
        /// service name
        name: String,
    },
    /// Print a service's state and address, or every service when no name is given
    Status {
        /// service name; omit to list all services
        name: Option<String>,
    },
}

/// The background half of `vk publish` — publishers a run keeps, rather than one held
/// open by a terminal. They are recorded under `<state-dir>/publish`, so a state dir is how
/// each of these names the set it works on.
#[derive(Subcommand)]
enum PublishAction {
    /// Publish a port in the background, or confirm it already is
    ///
    /// Returns once the address is bound, so the port is reachable the moment this exits.
    /// A publisher of the same name already doing the same thing is success and nothing is
    /// started; one doing something else is an error rather than a silent no-op. An address
    /// already taken exits 4, so a caller that picks its own addresses can try another.
    Ensure {
        /// the VM's state dir (`run --state-dir`), which also holds the publisher records
        #[arg(value_name = "DIR")]
        state_dir: PathBuf,
        /// what to call this publisher — how `list` and `stop` name it
        #[arg(long, value_name = "NAME")]
        name: String,
        /// Local address to accept connections on (tcp://host:port, or a unix path)
        #[arg(long)]
        listen: SocketAddr,
        /// Address the guest dials for each accepted connection
        #[arg(long, value_parser = parse_publish_to)]
        to: String,
        /// ask this compose sibling's agent instead of the primary's
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
    },
    /// List the publishers running for a state dir
    ///
    /// This is what is actually running: a record whose publisher is gone is dropped as it
    /// is read, so callers need not inspect pids or listening sockets themselves.
    List {
        /// the VM's state dir
        #[arg(value_name = "DIR")]
        state_dir: PathBuf,
        /// print the entries as JSON
        #[arg(long)]
        json: bool,
    },
    /// Stop a state dir's publishers and wait for them to go
    Stop {
        /// the VM's state dir
        #[arg(value_name = "DIR")]
        state_dir: PathBuf,
        /// stop only this publisher (default: all of them)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// seconds to wait for each to exit
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
    /// plumbing: the publisher process `ensure` starts
    ///
    /// Serves an already-bound listener inherited by descriptor and holds the name's claim
    /// for its lifetime; not useful to run by hand.
    #[command(hide = true)]
    Serve {
        /// the VM's state dir
        #[arg(value_name = "DIR")]
        state_dir: PathBuf,
        /// the publisher's name, whose record it removes when it stops
        #[arg(long)]
        name: String,
        /// the address its inherited listener is bound to
        #[arg(long)]
        listen: SocketAddr,
        /// address the guest dials for each accepted connection
        #[arg(long, value_parser = parse_publish_to)]
        to: String,
        /// ask this compose sibling's agent instead of the primary's
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// the inherited listening socket
        #[arg(long = "listen-fd")]
        listen_fd: i32,
        /// the inherited lifetime lock
        #[arg(long = "lock-fd")]
        lock_fd: i32,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Preflight this host: can the current user boot microVMs here?
    ///
    /// Checks /dev/kvm access, the VMM backend, a guest kernel/agent, and the host side
    /// of each feature the config enables (net.mode taps, [docker], [registry], ...).
    /// Checked only when named with --feature: the CI-executor features (gitlab,
    /// services), and two capability probes about this build rather than the host:
    /// `entrypoint` (can it hand PID 1 to an image's own entrypoint) and `publish`
    /// (can it run `vk publish`). --min-version asserts the release this binary is,
    /// for a capability a release added without gaining a feature name of its own.
    /// One line per check; exits non-zero if any fails.
    #[command(display_order = 5)]
    Check {
        /// check only these features (repeatable)
        ///
        /// Any that turn out unconfigured fail instead of being skipped.
        #[arg(long = "feature", value_enum, value_name = "FEATURE")]
        feature: Vec<check::Feature>,
        /// require this vk to be VERSION or newer (e.g. 0.45, 0.45.0, v0.45.0)
        ///
        /// A missing patch field is zero. Used alone it checks only the version, and
        /// needs no config file; with --feature it checks both.
        #[arg(long = "min-version", value_name = "VERSION")]
        min_version: Option<check::Version>,
    },
    /// Reclaim the host caches — a cron or manual sweep
    ///
    /// Evicts materialized bases (`<state_dir>/{registry, docker, build}`) no VM is using,
    /// removes GitLab host checkouts no job is using, and drops unreferenced registry
    /// chunks — all of them idle past the threshold. Reclaim otherwise happens as those
    /// caches are used, so this is for an otherwise-idle runner.
    #[command(display_order = 4)]
    Gc {
        /// Idle threshold in seconds; `0` reclaims every entry not currently in use
        ///
        /// Applies to images and checkouts alike, overriding both of their settings. Default:
        /// the config's `image_cache_idle_secs` and `checkout_cache_idle_secs` (30 min each).
        #[arg(long, value_name = "SECS")]
        idle_secs: Option<u64>,
    },
    /// Print the effective host paths and where each comes from
    ///
    /// The config file, state dir, image cache and registry store — with the override for each.
    #[command(hide = true)]
    Paths {
        /// also show the gitlab executor's paths (jobs dir, checkouts, tools dir)
        #[arg(long)]
        gitlab: bool,
    },
    /// Print the effective configuration as TOML
    ///
    /// The built-in defaults merged with the loaded config file, with a header naming which
    /// file it came from. Use it to see what a `vk` invocation actually sees. `--example`
    /// prints the annotated template instead; `--path` prints just the resolved config file
    /// path.
    #[command(hide = true)]
    Config {
        /// print the annotated example config template instead of the effective config
        #[arg(long)]
        example: bool,
        /// print only the resolved config file path (exit 1 if none is in use)
        #[arg(long, conflicts_with = "example")]
        path: bool,
    },
    /// Keep gitlab-runner's `concurrent` in step with what this host can hold
    ///
    /// Measures the memory its jobs have committed and leaves the concurrency that fits where
    /// the root-side `vk-runnerctl` applies it. Run from a timer every half minute or so (see
    /// the GitLab CI guide), so it is hidden from the everyday help like `vk gitlab`. Needs
    /// `[schedule] mem_budget`.
    #[command(hide = true)]
    Tune,
    /// GitLab custom executor
    ///
    /// The lifecycle hooks (config / prepare / run / cleanup) and the operator's view of what
    /// its jobs have been using (usage).
    #[command(hide = true)]
    Gitlab {
        #[command(subcommand)]
        cmd: GitlabCmd,
    },
    /// Native OCI bundle registry
    ///
    /// Push/pull guest bundles with content-defined chunk deduplication (CDC + per-chunk zstd),
    /// no oras, no docker.
    #[command(hide = true)]
    Registry {
        #[command(subcommand)]
        cmd: RegistryCmd,
    },
    /// Control the run's compose services from inside the guest
    ///
    /// Bring one up (building its image on demand, streaming build progress), take it down, or
    /// query state. Speaks the vsock control plane to the host service manager, so it only
    /// works inside a vk VM.
    #[command(hide = true)]
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Build a Dockerfile target into a bootable ext4 image
    ///
    /// A from-scratch builder (no docker, no buildkit): each RUN executes in a microVM
    /// guest (the embedded libkrun by default) and instruction snapshots are cached
    /// (`--cache-registry`). `--print-plan` parses + plans + prints the build without
    /// running it.
    #[command(display_order = 2)]
    Build {
        /// Dockerfile to build
        ///
        /// Repeatable: the files merge into one stage namespace, so a FROM/COPY --from in one
        /// file can name a stage declared in another.
        #[arg(
            short = 'f',
            long = "file",
            default_value = "Dockerfile",
            help_heading = "What to build"
        )]
        file: Vec<PathBuf>,
        /// target stage (AS name or index; default: the last stage)
        ///
        /// Repeatable: several targets build together in one pass, sharing their common stages
        /// (built once) and running the rest concurrently. With one --out they export to
        /// <out>/<target>.ext4; with none they only warm the instruction cache.
        #[arg(long, value_name = "NAME|INDEX", help_heading = "What to build")]
        target: Vec<String>,
        /// build the services `vk run --compose` would boot
        ///
        /// The enabled set (profiled-down services excluded) plus every image: service, in one
        /// pass, so a prebuild warms exactly what a boot needs. Services sharing a Dockerfile
        /// build their common stages once. Warms the cache; with --out each exports to
        /// <out>/<name>.ext4. Excludes -f/--target.
        #[arg(long, value_name = "FILE", help_heading = "What to build")]
        compose: Option<PathBuf>,
        /// with --compose, also build the services this profile enables (repeatable)
        ///
        /// The same profiled services `vk run --compose --profile` would boot.
        #[arg(
            long = "profile",
            value_name = "NAME",
            requires = "compose",
            conflicts_with = "primary",
            help_heading = "What to build"
        )]
        profile: Vec<String>,
        /// with --compose, build the set `vk run --compose --primary <NAME>` would boot
        ///
        /// That service plus its dependency closure, and every image: service, rather than the
        /// default profile-enabled set.
        #[arg(
            long,
            value_name = "NAME",
            requires = "compose",
            help_heading = "What to build"
        )]
        primary: Option<String>,
        /// with --compose, the workspace root it reads as `${VK_WORKSPACE}` [default: the cwd]
        ///
        /// The same value the eventual `vk run --workspace` passes, so a prebuild resolves the
        /// compose file exactly as the boot will.
        #[arg(
            long,
            value_name = "DIR",
            requires = "compose",
            help_heading = "What to build"
        )]
        workspace: Option<PathBuf>,
        /// with --compose, the run state dir it reads as `${VK_STATE_DIR}`
        ///
        /// A build keeps no state of its own; this only answers the builtin, so a compose file
        /// naming the run's state dir resolves the same here as under `vk run --state-dir`.
        #[arg(
            long = "state-dir",
            value_name = "DIR",
            requires = "compose",
            help_heading = "What to build"
        )]
        state_dir: Option<PathBuf>,
        /// build context for COPY
        ///
        /// Repeatable, zipped positionally with -f; default: each Dockerfile's own directory.
        #[arg(long, value_name = "DIR", help_heading = "What to build")]
        context: Vec<PathBuf>,
        /// an additional named context, `<name>=<dir>`, for `COPY --from` and `RUN --mount`
        ///
        /// `COPY --from=<name>` and `RUN --mount=…,from=<name>` read it.
        /// Repeatable, so a Dockerfile can reach files outside its own context with no staging
        /// copy. Resolved after the Dockerfile's own stages and before an image ref, so a name
        /// never shadows a stage. Not supported with --compose: a compose service declares its
        /// own contexts, and `vk run --compose` would otherwise rebuild what this built, under
        /// a different key.
        #[arg(
            long = "build-context",
            value_name = "NAME=DIR",
            conflicts_with = "compose",
            help_heading = "What to build"
        )]
        build_context: Vec<String>,
        /// ext4 output path
        #[arg(long, value_name = "PATH", help_heading = "Output")]
        out: Option<PathBuf>,
        /// build the target and publish it to the `[registry]` repo as `<name>:<tag>`
        ///
        /// A bootable bundle the executor pulls with `MICROVM_IMAGE: virtkit/<name>:<tag>`. The
        /// rootfs is byte-clean (its Env/User ride the bundle config), and its chunks dedup
        /// against `--cache-registry`, so a co-located registry makes this a near no-op (only
        /// the manifest is written).
        #[arg(long = "tag", value_name = "NAME:TAG", help_heading = "Output")]
        tag: Option<String>,
        /// attach a caller-owned raw disk read-write to the target stage's RUN guests
        ///
        /// It appears as /dev/vdb and sources shift to vdc+. Only the target stage sees it,
        /// so exactly one stage writes it. Its writes are the artifact — a RUN can partition
        /// it, mkfs and install a bootloader. Size and own the file yourself (e.g. `qemu-img
        /// create -f raw disk.raw 12G`); vk never creates or removes it. Pairs with
        /// `FROM --kernel=image` for a kernel that can drive the disk.
        #[arg(long = "disk", value_name = "PATH", help_heading = "Output")]
        disk: Option<PathBuf>,
        /// parse + plan + print the build order and primitives; build nothing
        #[arg(long = "print-plan", help_heading = "Output")]
        print_plan: bool,
        /// cloud-hypervisor binary, used only with VIRTKIT_VMM=cloud-hypervisor
        ///
        /// The default libkrun backend is embedded in `vk` and needs none.
        #[arg(
            long = "cloud-hypervisor",
            value_name = "PATH",
            help_heading = "Build environment"
        )]
        cloud_hypervisor: Option<PathBuf>,
        /// guest kernel the RUN steps boot
        ///
        /// Default: `[build] kernel`, else the one embedded in `vk`.
        #[arg(long, value_name = "PATH", help_heading = "Build environment")]
        kernel: Option<PathBuf>,
        /// static (musl) vk-agent the RUN guests run as PID 1
        ///
        /// Default: `[build] agent`, else the copy embedded in `vk`.
        #[arg(long, value_name = "PATH", help_heading = "Build environment")]
        agent: Option<PathBuf>,
        /// instruction cache: a registry repo, a store directory path, or `none` to disable
        ///
        /// A registry repo is e.g. 127.0.0.1:5000 of a `vk-registry` server; an absolute store
        /// directory path is accessed in-process. Default: `[build] cache_registry`, else the
        /// builtin local store `vk-registry` also uses.
        #[arg(
            long = "cache-registry",
            value_name = "REF|DIR|none",
            help_heading = "Instruction cache"
        )]
        cache_registry: Option<String>,
        /// the cache registry speaks plain HTTP (a loopback vk-registry)
        ///
        /// Registry caches only — the builtin/path store has no transport.
        #[arg(long = "cache-insecure", help_heading = "Instruction cache")]
        cache_insecure: bool,
        /// how aggressively to populate the instruction cache
        ///
        /// `auto` (default) checkpoints only past a work threshold, `layers` takes one snapshot
        /// per stage with no partial-prefix reuse, `instructions` one snapshot per RUN/COPY.
        #[arg(
            long = "build-cache",
            value_name = "auto|layers|instructions",
            help_heading = "Instruction cache"
        )]
        build_cache: Option<String>,
        /// opt out of the ext4 journal a build's exported image gets by default
        ///
        /// The build's own intermediate snapshots always stay journal-less regardless.
        #[arg(long, help_heading = "Output")]
        no_journal: bool,
        /// use a RAM tmpfs for each stage guest's `/tmp`
        ///
        /// Instead of the default disk-backed scratch, which bounds a bulk `/tmp` write (e.g. a
        /// large toolchain unpack) by disk rather than ½·guest-RAM. Also settable as
        /// `tmp_tmpfs` in `[build]`.
        #[arg(long = "build-tmp-tmpfs", help_heading = "Build environment")]
        build_tmp_tmpfs: bool,
        /// override an ARG default: NAME=VALUE (repeatable)
        #[arg(
            long = "build-arg",
            value_name = "NAME=VALUE",
            help_heading = "What to build"
        )]
        build_arg: Vec<String>,
        /// network for the build's RUN steps: `all` (unrestricted) or `none`
        #[arg(
            long = "build-net",
            default_value = "all",
            value_name = "all|none",
            help_heading = "Network (RUN steps)"
        )]
        build_net: String,
        /// restrict RUN egress to this destination IPv4 CIDR
        ///
        /// Optionally port-scoped as CIDR:port (repeatable; any --build-allow-* flag turns
        /// filtering on).
        #[arg(
            long = "build-allow-ip",
            value_name = "CIDR[:PORT]",
            help_heading = "Network (RUN steps)"
        )]
        build_allow_ip: Vec<String>,
        /// restrict RUN egress to hosts at or under this DNS suffix
        ///
        /// A suffix is e.g. `crates.io`. Repeatable; any --build-allow-* flag turns
        /// filtering on.
        #[arg(
            long = "build-allow-name",
            value_name = "SUFFIX",
            help_heading = "Network (RUN steps)"
        )]
        build_allow_name: Vec<String>,
        /// audit egress: which external domains the build's RUN steps contact
        ///
        /// Lists every one, and how many times, after the build. Observes only — it does not
        /// restrict egress.
        #[arg(long = "build-audit-egress", help_heading = "Network (RUN steps)")]
        build_audit_egress: bool,
        /// restores from the instruction cache are allowed, but nothing may build
        ///
        /// A cache miss aborts with exit code 3, so scripts can branch cached-vs-cold without
        /// paying for a build.
        #[arg(long = "require-cached", help_heading = "Instruction cache")]
        require_cached: bool,
        /// max stages built concurrently on the microVM backend
        ///
        /// Independent stages build in parallel over the dependency graph. Default: `[build]
        /// jobs`, else auto, bounded by the host's total RAM. 1 forces a sequential build.
        #[arg(
            long = "build-jobs",
            value_name = "N",
            value_parser = parse_build_jobs,
            help_heading = "Build environment"
        )]
        build_jobs: Option<NonZeroUsize>,
        /// guest RAM for one stage, over its `# vk:` hint and `[build] mem`
        ///
        /// NAME is the stage's `AS` name, or `stage<N>` by position when it has none.
        /// In a multi-unit build it sizes that stage in every unit declaring it.
        /// Repeatable; a name no unit has is an error.
        #[arg(
            long = "stage-mem",
            value_name = "NAME=SIZE",
            value_parser = parse_named_mem,
            help_heading = "Build environment"
        )]
        stage_mem: Vec<(String, String)>,
        /// guest vCPUs for one stage, over its `# vk:` hint and `[build] cpus`
        ///
        /// Addressed like `--stage-mem`; the two compose, so a stage can be given both.
        #[arg(
            long = "stage-cpus",
            value_name = "NAME=N",
            value_parser = parse_named_cpus,
            help_heading = "Build environment"
        )]
        stage_cpus: Vec<(String, u32)>,
        /// verify each stage snapshot with e2fsck as it crosses the instruction cache
        ///
        /// After a load and before an upload, to catch a corrupt ext4 early. Best-effort
        /// (skipped if e2fsck is absent); adds an fsck per instruction.
        #[arg(long, help_heading = "Instruction cache")]
        debug: bool,
    },
    /// Host side of a forward (companion of `vk-agent forward`)
    ///
    /// Accepts on `--listen` and splices each connection to `--to`, opaque to the protocol.
    /// Long-running, spawned detached per job — e.g. the VMM's per-port vsock unix socket -> a
    /// host-local service the guest must not reach directly.
    #[command(hide = true)]
    Forward {
        /// Local address to listen on (a unix socket path, tcp://host:port, ...)
        #[arg(long)]
        listen: SocketAddr,
        /// Target each accepted connection is spliced to
        #[arg(long)]
        to: SocketAddr,
    },
    /// SSH into a VM booted with `run --ssh-client`
    ///
    /// Runs the system ssh against the client setup in the VM's state dir — that run's
    /// config, key and alias — so none of your own identities are involved and there is
    /// nothing to configure. Arguments after the directory reach ssh as given:
    /// `vk ssh DIR -- uname -a`.
    Ssh {
        /// the run's state dir (`run --state-dir`)
        #[arg(value_name = "DIR")]
        state_dir: PathBuf,
        /// arguments passed to ssh verbatim, after the host
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARG"
        )]
        args: Vec<String>,
    },
    /// Print the ssh_config stanza of a VM booted with `run --ssh-client`
    ///
    /// The file `vk ssh` itself uses — read it to point another tool at the VM: `ssh -F`,
    /// an `Include` in your own config, Emacs TRAMP.
    #[command(name = "ssh-config")]
    SshConfig {
        /// the run's state dir (`run --state-dir`)
        #[arg(value_name = "DIR")]
        state_dir: PathBuf,
    },
    /// plumbing: splice stdio to the target address — the SSH `ProxyCommand` shape
    ///
    /// ssh hands its protocol stream on stdio; we relay it to the guest's ssh-serve (`run
    /// --ssh` prints the full invocation). Addresses: a unix path, vsock-mux://<path>:<port>,
    /// vsock-auto://<path>:<port> (best path per backend), tcp://host:port.
    #[command(hide = true)]
    Connect {
        /// Target address to dial
        addr: SocketAddr,
    },
    /// Probe a running VM's guest agent
    ///
    /// Prints its reply, or exits non-zero if it does not answer — a liveness check that
    /// exercises the agent protocol, stronger than a socket stat. Selects the VM whose project
    /// is the current directory by default; pass a DIR to select by project directory. A
    /// raw agent address (`vsock-auto://DIR/vsock.sock:4444`) probes it directly, for
    /// plumbing that already knows the socket.
    #[command(display_order = 7)]
    Status {
        /// which VM: a directory, or a raw agent address
        ///
        /// A directory (default: the current directory) resolves via the VM registry `vk list`
        /// uses; a raw agent address (`scheme://…`) is dialed directly.
        target: Option<String>,
        /// print whether the VM's root image is `fresh`, `stale` or `unknown`
        ///
        /// A single scriptable token; `stale` means a fresh `vk run` would rebuild it. Skips
        /// the agent probe but may resolve base image digests over the network; selects the VM
        /// by directory (a raw address has no build recipe).
        #[arg(long)]
        stale: bool,
    },
    /// Show a VM's console log: kernel, agent and guest output, filterable
    ///
    /// Reads the run's `console.log` — one serial console carrying the guest kernel's
    /// messages, the agent's `HH:MM:SS [LEVEL] vk-agent …` lines and whatever the guest's
    /// programs print — and tells the three apart, so `--level warn` shows only what went
    /// wrong and `--agent` only what vk-agent did. The source flags combine as a union
    /// (`--kernel --agent` shows both), and `--level` drops everything that carries no level
    /// — every guest program's line, and every routine kernel one. Selects the VM whose
    /// project is the current directory by default; `--service` reads a compose sibling's
    /// console instead.
    #[command(display_order = 7)]
    Logs {
        /// which VM: a project directory (default: the current directory)
        ///
        /// Resolves via the VM registry `vk list` uses. After the VM has exited it is no
        /// longer registered — name the run's `--state-dir` itself and its console is read
        /// straight from there.
        target: Option<PathBuf>,
        /// read this compose sibling's console instead of the primary's
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// show the last N lines (after filtering); 0 streams the whole log
        ///
        /// The log is read a line at a time and only N are held, so a bound costs no more
        /// memory on a console that has grown for days than on a fresh one.
        #[arg(short = 'n', long, default_value_t = 50, value_name = "N")]
        lines: usize,
        /// only lines at least this severe: error, warn, info, debug, trace
        ///
        /// Agent lines carry a level; a kernel panic, oops, BUG or OOM kill counts as error;
        /// other kernel lines and everything the guest's programs print have none and are
        /// dropped whenever a level is asked.
        #[arg(long, value_name = "LEVEL")]
        level: Option<consolelog::Level>,
        /// only the guest kernel's lines
        #[arg(long)]
        kernel: bool,
        /// only vk-agent's lines
        #[arg(long)]
        agent: bool,
        /// only what the guest's programs printed
        #[arg(long)]
        guest: bool,
        /// keep printing new lines as the guest writes them (until Ctrl-C or the VM ends)
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// Run a command in a live guest, or open an interactive shell in it
    ///
    /// Goes over the guest's agent exec channel, as `--user` in `--dir`. Reuses the same
    /// client the in-guest agent embeds, so a host reaches a running VM with `vk` alone,
    /// no separate `vk-agent` binary. `vk` exits with the command's own status. The
    /// command goes after `--`; the optional token before it selects the VM.
    #[command(arg_required_else_help = true, display_order = 3)]
    Exec {
        /// which VM: a directory, or a raw agent address
        ///
        /// A directory (default: the current directory) resolves via the VM registry `vk list`
        /// uses; a raw agent address (`scheme://…`) is dialed directly.
        target: Option<String>,
        /// run in this compose sibling service instead of the primary
        ///
        /// By name, as `vk list --wide` shows it; the service must be running.
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// Background mode: no stdio, do not wait for the command to exit
        #[arg(short, long)]
        background: bool,
        /// Start the remote process with an empty environment
        #[arg(long)]
        clear_env: bool,
        /// Add an environment variable, syntax KEY=value (repeatable)
        #[arg(long, value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Working directory for the remote process (default: the agent's own)
        #[arg(long)]
        dir: Option<String>,
        /// Allocate a remote pty and run interactively
        ///
        /// Requires local stdin/stdout to be a terminal; incompatible with --background.
        #[arg(short = 't', long)]
        tty: bool,
        /// Run the remote process as this Unix user (drops uid/gid/groups)
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
        /// Command to run and its arguments, after `--` (e.g. `vk exec -- ls -la`)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Publish a port on the guest's own network to the host
    ///
    /// Accepts connections on `--listen` and, for each one, asks the target VM's agent —
    /// over the same exec control channel `vk exec`/`vk status` use — to dial `--to` and
    /// splice raw bytes back, reusing that already-open channel for the relay. The VM is
    /// selected as `vk exec` selects it (a directory or a raw agent address, `--service`
    /// for a compose sibling), and `--to` can name any address that VM's own network
    /// reaches — a LAN peer's own compose hostname included, resolved through that VM's
    /// own DNS:
    /// `vk publish --service devcontainer --listen tcp://127.0.0.1:8443 --to tcp://runner:443`.
    ///
    /// That form runs in the foreground and goes with the terminal; `vk publish ensure` and
    /// its siblings keep one running in the background instead.
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Publish {
        /// which VM's agent to ask: a directory, or a raw agent address
        ///
        /// A directory (default: the current directory) resolves via the VM registry `vk list`
        /// uses; a raw agent address (`scheme://…`) is dialed directly.
        target: Option<String>,
        /// ask this compose sibling's agent instead of the primary's
        ///
        /// By name, as `vk list --wide` shows it; the service must be running.
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// Local address to accept connections on (tcp://host:port, a unix path, ...)
        #[arg(long, required = true)]
        listen: Option<SocketAddr>,
        /// Address the guest dials for each accepted connection (tcp://host:port, ...)
        ///
        /// A `tcp://` host may be a name instead of an IP literal — resolved by the
        /// guest's own DNS (a compose sibling's hostname, say), not here, since only
        /// the guest's network can resolve those.
        #[arg(long, value_parser = parse_publish_to, required = true)]
        to: Option<String>,
        /// Manage background publishers instead of running one in the foreground
        #[command(subcommand)]
        action: Option<PublishAction>,
    },
    /// Watch a running VM's guest live, or read what a recorded one did
    ///
    /// A directory a running VM matches (default: the current directory) attaches to it:
    /// a sampler starts in its guest and the follow panel opens on the recording as it
    /// grows (`<state dir>/atop/atop.log`) — with --summary, or with no terminal to draw
    /// the panel on, it records headless until Ctrl-C and then prints what it recorded. A
    /// VM booted with `vk run --atop` is already recording itself, so its own recording is
    /// read live instead: the flags answer off that log as it stands, with no attach to
    /// Ctrl-C. Anything else reads a recorded job: with no flag, print the log's path so a
    /// viewer can be pointed at it (`less $(vk atop 42137)`).
    #[command(display_order = 10)]
    Atop {
        /// A running VM's directory, or a recorded job
        ///
        /// A directory selects a running VM as `vk exec` does (default: the current directory).
        /// A recorded job is a job id, any part of a recorded job's directory name (its project
        /// or job name, with anything outside [A-Za-z0-9._-] replaced) with the newest run
        /// matching answering, or a path holding a `/`, so the path a job's trace printed works
        /// too.
        target: Option<String>,
        /// Account the whole job instead of printing a path
        ///
        /// What its guest did with its processors and memory, what it moved, where it stalled,
        /// and which of its processes the time went to.
        #[arg(long)]
        summary: bool,
        /// Write every sample as one line of JSON
        ///
        /// A pipeline can then take the samples a line at a time
        /// (`vk atop 42137 --json | jq …`). One of `--summary`, `--json` and the panel: each
        /// is a different answer to "what did this job do".
        #[arg(long, conflicts_with_all = ["summary", "view", "follow"])]
        json: bool,
        /// Walk the recording sample by sample in a full-screen panel
        ///
        /// What the guest's processors, memory, pressure, disks and network were doing at each
        /// moment, and which processes were using them.
        #[arg(long)]
        view: bool,
        /// The panel, kept up to date while the job is still running
        ///
        /// New samples appear as the guest commits them, and stepping back holds the view still
        /// until End.
        #[arg(long, conflicts_with = "view")]
        follow: bool,
        /// Sampling interval when attaching to a running VM, in seconds
        ///
        /// A recorded job — or a VM recording itself, whose cadence `vk run --atop` set at boot
        /// — was sampled at whatever cadence recorded it, so this says nothing about either.
        #[arg(
            long,
            value_name = "SECS",
            default_value_t = 5,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        interval: u64,
    },
    /// Filtering ssh-agent proxy: expose a subset of the host agent's keys
    ///
    /// Serves the ssh-agent protocol on `--listen`, relaying to the real agent at `--upstream`
    /// but exposing only the keys in the `--allow` .pub files (refusing to sign with or list
    /// any other key). The host side of forwarding a subset of the agent into a guest.
    #[command(hide = true)]
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
    /// Userspace L2 network gateway for microVM(s) — replaces gvproxy
    ///
    /// Accepts the qemu vhost transport on each VM's hybrid-vsock guest-port socket, answers
    /// ARP + serves DHCP, and proxies guest TCP/UDP out through the host's own sockets — no
    /// host privileges, multi-VM on one LAN.
    #[command(hide = true)]
    Switch {
        /// NIC socket to accept on, as `<vsock.sock>_<port>=<ip>[=<vm>]`
        ///
        /// The guest's qemu socket, paired with the address the run assigned that NIC;
        /// repeatable — one per NIC on the shared LAN. The switch binds the address to the
        /// socket so a guest can only source addresses of its own. `<vm>` groups the NICs of
        /// one multi-homed guest, which may then source any of its addresses from any of
        /// them; omitted, each socket is its own guest, keyed off its position. Don't mix
        /// omitted and explicit `<vm>` in one invocation — a position could collide with an
        /// explicit id and merge two guests. The driver always emits explicit ids.
        #[arg(long = "listen", required = true, value_name = "SOCKET=IP[=VM]")]
        listen: Vec<String>,
        /// Gateway IPv4 — also the DHCP server and DNS address
        #[arg(long, default_value = "192.168.127.1")]
        gateway: std::net::Ipv4Addr,
        /// Subnet prefix length
        #[arg(long, default_value_t = 24)]
        prefix: u8,
        /// service name the gateway resolver answers locally: name=ip (repeatable)
        #[arg(long = "host")]
        host: Vec<String>,
        /// per-MAC DHCP reservation: mac=ip (repeatable)
        ///
        /// A guest with this MAC gets exactly this address instead of a pool lease.
        #[arg(long = "reserve", value_name = "MAC=IP")]
        reserve: Vec<String>,
        /// egress allowlist — destination IPv4 CIDR for direct (non-proxied) egress
        ///
        /// Optionally port-scoped as CIDR:port (repeatable). With no --allow-ip/--allow-name,
        /// egress is unrestricted.
        #[arg(long = "allow-ip", value_name = "CIDR[:PORT]")]
        allow_ip: Vec<String>,
        /// egress allowlist — hostname suffix the http(s) proxy permits (repeatable)
        ///
        /// A suffix is e.g. `corp.example.com`.
        #[arg(long = "allow-name", value_name = "SUFFIX")]
        allow_name: Vec<String>,
        /// force allowlist mode even with no --allow-ip/--allow-name
        ///
        /// An empty allowlist then denies everything instead of leaving egress unrestricted
        /// (set internally by the gitlab executor when a job configures egress).
        #[arg(long = "egress-restrict")]
        egress_restrict: bool,
        /// per-source egress override `<src-ip>;<cidr,cidr>;<name,name>` (repeatable)
        ///
        /// Flows from that source use this restricted allowlist instead of the default; an
        /// empty field is an empty (deny) list. Set internally by the gitlab executor for a
        /// service that declared its own MICROVM_EGRESS_ALLOW_* in its `variables:`.
        #[arg(long = "source-egress", value_name = "IP;CIDRS;NAMES")]
        source_egress: Vec<String>,
        /// redirect guest flows aimed at a sentinel address to a host-local registry proxy
        ///
        /// The value is `<sentinel-ip>=<host:port>`, set internally by
        /// `vk run --registry-proxy`.
        #[arg(long = "registry-proxy", value_name = "IP=ADDR")]
        registry_proxy: Option<String>,
        /// append each egress denial as a typed record here
        ///
        /// The job trace surfaces the records. Set internally by the gitlab executor; see
        /// egress_report.
        #[arg(long = "denied-log", value_name = "PATH")]
        denied_log: Option<PathBuf>,
        /// audit mode: append every allowed external domain the guest resolves here
        ///
        /// The end-of-job "domains contacted" summary reads the log. Set internally by the
        /// gitlab executor; see egress_report.
        #[arg(long = "audit-log", value_name = "PATH")]
        audit_log: Option<PathBuf>,
        /// publish the bytes forwarded here
        ///
        /// The end-of-phase resource line reads the count. Set internally by `vk run`,
        /// `vk build` and the gitlab executor; see egress_report.
        #[arg(long = "net-bytes", value_name = "PATH")]
        net_bytes: Option<PathBuf>,
    },
    /// Boot a docker/OCI image as a microVM and run a command in it
    ///
    /// The rootfs boots from a native ext4 disk (or a cpio initramfs in RAM with
    /// `--ram`), vk-agent runs as PID 1 over vsock, and the trailing command — or an
    /// interactive shell — runs in the guest.
    #[command(display_order = 1)]
    Run {
        /// Image to boot, e.g. `alpine:3.20`
        ///
        /// A docker ref, or an OCI reference with `--source oci`. Omit when booting a
        /// Dockerfile target with `--file`.
        image: Option<String>,
        /// Boot a Dockerfile target instead of an image
        ///
        /// Builds the target into an ext4 and boots it — no explicit ext4 file — or
        /// cache-restores it with --cache-registry. Repeatable: the files merge into one stage
        /// namespace.
        #[arg(
            short = 'f',
            long = "file",
            help_heading = "Build (with -f or --compose)"
        )]
        file: Vec<PathBuf>,
        /// target stage to boot (AS name or index; default: the last stage), with --file
        #[arg(
            long,
            value_name = "NAME|INDEX",
            help_heading = "Build (with -f or --compose)"
        )]
        target: Option<String>,
        /// build context for the Dockerfile's COPY
        ///
        /// Repeatable, zipped positionally with -f; default: each Dockerfile's own directory.
        #[arg(
            long,
            value_name = "DIR",
            help_heading = "Build (with -f or --compose)"
        )]
        context: Vec<PathBuf>,
        /// an additional named context, `<name>=<dir>`, for `COPY --from` and `RUN --mount`
        ///
        /// `COPY --from=<name>` and `RUN --mount=…,from=<name>` read it.
        /// Repeatable — files outside the Dockerfile's own context, with no staging copy. The
        /// --file build only: a compose service declares its own contexts, and --compose would
        /// key the same service differently.
        #[arg(
            long = "build-context",
            value_name = "NAME=DIR",
            requires = "file",
            conflicts_with = "primary",
            help_heading = "Build (with -f or --compose)"
        )]
        build_context: Vec<String>,
        /// instruction cache for `-f` and `--compose` builds
        ///
        /// Pushes/pulls each stage's ext4 by content key, so a repeat boot restores instead of
        /// rebuilding: a registry repo, an absolute store directory path, or `none` to disable.
        /// Default: `[build] cache_registry`; otherwise, the builtin local store also used by
        /// `vk-registry`.
        #[arg(
            long = "cache-registry",
            value_name = "REF|DIR|none",
            help_heading = "Build (with -f or --compose)"
        )]
        cache_registry: Option<String>,
        /// the cache registry speaks plain HTTP (a loopback vk-registry)
        ///
        /// Registry caches only — the builtin/path store has no transport.
        #[arg(long = "cache-insecure", help_heading = "Build (with -f or --compose)")]
        cache_insecure: bool,
        /// override an ARG default for the --file build: NAME=VALUE (repeatable)
        #[arg(
            long = "build-arg",
            value_name = "NAME=VALUE",
            help_heading = "Build (with -f or --compose)"
        )]
        build_arg: Vec<String>,
        /// network for the --file build's RUN steps: `all` (unrestricted) or `none`
        ///
        /// It is independent of --net, which governs the booted guest.
        #[arg(
            long = "build-net",
            default_value = "all",
            value_name = "all|none",
            help_heading = "Build (with -f or --compose)"
        )]
        build_net: String,
        /// restrict the --file build's RUN egress to this destination IPv4 CIDR
        ///
        /// Optionally port-scoped as CIDR:port (repeatable; any --build-allow-* flag turns
        /// filtering on).
        #[arg(
            long = "build-allow-ip",
            value_name = "CIDR[:PORT]",
            help_heading = "Build (with -f or --compose)"
        )]
        build_allow_ip: Vec<String>,
        /// restrict the --file build's RUN egress to hosts at or under this DNS suffix
        ///
        /// A suffix is e.g. `crates.io`. Repeatable; any --build-allow-* flag turns
        /// filtering on.
        #[arg(
            long = "build-allow-name",
            value_name = "SUFFIX",
            help_heading = "Build (with -f or --compose)"
        )]
        build_allow_name: Vec<String>,
        /// Kernel: `default`, `image`, or a path to a vmlinux/bzImage
        ///
        /// `default` is virtkit's pinned kernel, `image` the image's own /boot/vmlinuz +
        /// modules.
        #[arg(
            long,
            default_value = "default",
            value_parser = run::KernelSource::parse,
            value_name = "default|image|PATH",
            help_heading = "Guest"
        )]
        kernel: run::KernelSource,
        /// keep console=ttyS0 for a BYO stock kernel (`--kernel <path>`)
        ///
        /// For a kernel whose virtio-console (hvc0) is a module, so early boot output reaches
        /// the legacy serial. Unneeded for the default or an image kernel.
        #[arg(long = "console-serial", help_heading = "Guest")]
        console_serial: bool,
        /// expose the guest PMU for in-guest `perf` — trusted guests only
        ///
        /// Cycles, instructions and the rest, via KVM's vPMU. SECURITY: host performance
        /// counters are a side-channel surface — enable only for trusted guests (a dev VM),
        /// never untrusted CI jobs. libkrun backend only; default off.
        #[arg(long, help_heading = "Guest")]
        pmu: bool,
        /// expose VMX/SVM for `vk` inside `vk` — trusted guests only
        ///
        /// Needs nested virtualization enabled on the host (kvm_intel.nested / kvm_amd.nested).
        /// SECURITY: the guest reaches host KVM's nested paths — for trusted guests only. Only
        /// the libkrun backend gates this; cloud-hypervisor guests nest whenever the host
        /// allows it. Default off.
        #[arg(long, help_heading = "Guest")]
        nested: bool,
        /// static (musl) vk-agent injected as PID 1
        ///
        /// Default: the copy embedded in `vk`.
        #[arg(long = "agent", value_name = "PATH", help_heading = "Guest")]
        agent: Option<PathBuf>,
        /// cloud-hypervisor binary, used only with VIRTKIT_VMM=cloud-hypervisor
        ///
        /// Default: the config's top-level `cloud_hypervisor`, else `cloud-hypervisor` on PATH.
        #[arg(long, value_name = "PATH", help_heading = "Guest")]
        cloud_hypervisor: Option<PathBuf>,
        /// vCPUs: a number, or `host` for the host's logical CPU count
        ///
        /// Default 2, or the --primary service's own x-virtkit.cpus.
        #[arg(
            long,
            value_parser = parse_cpus,
            value_name = "N|host",
            help_heading = "Guest"
        )]
        cpus: Option<u32>,
        /// guest RAM (`<n>G`, `<n>M`, or a MiB count)
        ///
        /// Default 1G, or the --primary service's own x-virtkit.mem.
        #[arg(long, value_name = "SIZE", help_heading = "Guest")]
        mem: Option<String>,
        /// interfaces the guest gets on the run LAN
        ///
        /// Default 1 (eth0 alone), or the --primary service's own x-virtkit.nics. More adds
        /// eth1 upward, each with its own address on the same segment; eth0 keeps the
        /// default route. Needs --net (or --compose, which implies it).
        #[arg(
            long,
            value_name = "N",
            help_heading = "Network",
            value_parser = clap::value_parser!(u32).range(1..)
        )]
        nics: Option<u32>,
        /// seconds to wait for the guest agent to answer before giving up on the boot
        #[arg(
            long,
            default_value_t = 120,
            value_name = "SECS",
            help_heading = "Guest"
        )]
        boot_timeout: u64,
        /// Name for the VM's process, as `ps`/`top` shows it
        ///
        /// A template where `{name}` expands to the Dockerfile stage, image, or compose service
        /// name.
        #[arg(
            long = "vm-name",
            default_value = "vk:{name}",
            value_name = "TEMPLATE",
            help_heading = "Guest"
        )]
        vm_name: String,
        /// Boot the rootfs as a cpio initramfs held entirely in RAM
        ///
        /// Zero host scratch, but the guest needs --mem of roughly three times the image size.
        #[arg(long, help_heading = "Guest")]
        ram: bool,
        /// Who runs as PID 1 in the guest
        ///
        /// `image` and `entrypoint` both go through the preinit handoff, so both need an
        /// image or `-f` build and neither works with --ram.
        #[arg(long, default_value = "default", help_heading = "Guest")]
        init: run::InitSource,
        /// share a host dir read-write into the guest at /work and run the command there
        ///
        /// The command's outputs then land back on the host.
        #[arg(long, value_name = "DIR", help_heading = "Running the command")]
        workdir: Option<PathBuf>,
        /// Drop into an interactive shell in the guest
        ///
        /// Requires a terminal; ignores any trailing command.
        #[arg(long, help_heading = "Running the command")]
        shell: bool,
        /// Allocate a pty for the trailing command, so it runs interactively
        ///
        /// `docker run -t`, wired to the local terminal; requires a terminal.
        #[arg(
            short = 't',
            long = "tty",
            conflicts_with = "detach",
            help_heading = "Running the command"
        )]
        tty: bool,
        /// Give the guest network egress via a userspace `vk switch`
        ///
        /// DHCP + DNS + transparent proxy over vsock.
        #[arg(long, help_heading = "Network")]
        net: bool,
        /// audit the booted guest's egress: which external domains it contacts
        ///
        /// Lists every one, and how many times, when the run ends. Observes only — it does not
        /// restrict egress. Requires --net (or --compose).
        #[arg(long = "audit-egress", help_heading = "Network")]
        audit_egress: bool,
        /// audit the `-f`/`--compose` build's RUN egress
        ///
        /// The build-phase counterpart of --audit-egress, like --build-net to --net. Prints
        /// after the build; observes only.
        #[arg(
            long = "build-audit-egress",
            help_heading = "Build (with -f or --compose)"
        )]
        build_audit_egress: bool,
        /// Run a host-local credential-injecting proxy to this upstream registry
        ///
        /// Takes the upstream's base URL (scheme://host); the guest reaches the proxy
        /// credential-free at `registry.vk`, which injects `--username`/`--password`/`--ca`.
        /// Needs `--net`. The job never sees the credentials.
        #[arg(long = "registry-proxy", value_name = "URL", help_heading = "Network")]
        registry_proxy: Option<String>,
        /// boot this compose file's services as sibling microVMs (implies --net)
        ///
        /// They share the run's LAN, the command reaches them by alias, and everything is torn
        /// down when the run exits. No readiness wait — retry the first connect. Services
        /// declare `image:` or `build:` (`build.dockerfile` may be a list: the files merge into
        /// one stage namespace, `target` picks any stage across them). Alone (no
        /// image/-f/--primary) this is compose up: services only, held until ctrl-c.
        ///
        /// `${VAR}` interpolates from the environment over a sibling `.env`, and the reserved
        /// `${VK_WORKSPACE}`, `${VK_STATE_DIR}`, `${VK_SELF}`, `${VK_UID}` and `${VK_GID}` from
        /// the run itself — so the committed file needs no host paths or ids of its own.
        ///
        /// Per-service `x-virtkit:` sets `cpus`, `mem`, `nested`, `nics`, `init`
        /// (default|image|entrypoint), `kernel` (default|image|<path>) and `persist_root`
        /// (keep `/` across restarts). Volume modes: `ro`, `rw`, `overlay` (writes in RAM),
        /// `overlay,persist[,size=]` (writes kept on disk) and `disk[,size=]` (a private
        /// filesystem). Persistent state lives under `.virtkit/` beside the compose file and
        /// is reset when the image (or, for an overlay, its shared host tree) changes.
        /// `examples/compose.yaml` in the source tree shows every compose feature a service
        /// can use.
        #[arg(long, value_name = "FILE", help_heading = "Compose services")]
        compose: Option<PathBuf>,
        /// activate a compose profile (repeatable)
        ///
        /// Profiled services stay down unless activated or depended on.
        #[arg(
            long = "profile",
            value_name = "NAME",
            help_heading = "Compose services"
        )]
        profile: Vec<String>,
        /// boot this compose service as the primary VM, like `docker compose run`
        ///
        /// Its image is the rootfs, its config the command's env — with no trailing command its
        /// entrypoint+cmd runs — and only its depends_on chain boots alongside. Requires
        /// --compose; replaces the image/-f.
        #[arg(
            long,
            value_name = "NAME",
            requires = "compose",
            help_heading = "Compose services"
        )]
        primary: Option<String>,
        /// override a compose service's vCPU count (repeatable)
        ///
        /// Wins over its x-virtkit.cpus declaration.
        #[arg(long = "service-cpus", value_name = "NAME=N", requires = "compose",
              value_parser = parse_named_cpus, help_heading = "Compose services")]
        service_cpus: Vec<(String, u32)>,
        /// override a compose service's guest RAM (repeatable, e.g. `db=2G`)
        ///
        /// Wins over its x-virtkit.mem declaration.
        #[arg(long = "service-mem", value_name = "NAME=SIZE", requires = "compose",
              value_parser = parse_named_mem, help_heading = "Compose services")]
        service_mem: Vec<(String, String)>,
        /// override how many NICs a compose service gets (repeatable, e.g. `appliance=3`)
        ///
        /// Wins over its x-virtkit.nics declaration.
        #[arg(long = "service-nics", value_name = "NAME=N", requires = "compose",
              value_parser = parse_named_nics, help_heading = "Compose services")]
        service_nics: Vec<(String, u32)>,
        /// Forward the host SSH agent ($SSH_AUTH_SOCK) into the guest
        ///
        /// ssh and git in the guest then use the host's keys, without the keys ever
        /// entering the guest.
        #[arg(long = "ssh-agent", help_heading = "SSH")]
        ssh_agent: bool,
        /// Expose only these ~/.ssh/config Host aliases to the guest (repeatable)
        ///
        /// A filtered agent offers just their keys, and their config stanzas are injected.
        /// Implies --ssh-agent.
        #[arg(long = "ssh-host", value_name = "ALIAS", help_heading = "SSH")]
        ssh_host: Vec<String>,
        /// Serve SSH into the guest — no sshd in the image
        ///
        /// The agent's in-VM ssh-serve over vsock: prints a ready-to-paste ssh command once
        /// booted. Sessions run as --ssh-user (default root); the VM lives for the duration of
        /// the run command.
        #[arg(long, help_heading = "SSH")]
        ssh: bool,
        /// public key authorised for --ssh (OpenSSH format, repeatable)
        ///
        /// Implies --ssh. Default: your standard ~/.ssh/id_*.pub keys.
        #[arg(long = "ssh-key", value_name = "PUBKEY", help_heading = "SSH")]
        ssh_key: Vec<String>,
        /// Write a ready-to-use SSH client setup into the state dir
        ///
        /// Implies --ssh and needs --state-dir. Generates a keypair of its own (reused on
        /// later boots, so nothing else is authorised by default), and writes `ssh-config`
        /// plus a `bin/ssh` shim beside it: connect with `vk ssh <state-dir>`, `ssh -F
        /// <state-dir>/ssh-config <alias>`, or by putting `<state-dir>/bin` first on PATH
        /// for a program that spawns bare `ssh` (VS Code Remote-SSH, Emacs TRAMP).
        #[arg(long = "ssh-client", requires = "state_dir", help_heading = "SSH")]
        ssh_client: bool,
        /// Host alias the --ssh-client config declares
        ///
        /// The name to `ssh` to, and the label in known_hosts terms. Letters, digits, '.',
        /// '_' and '-' only — it is an ssh_config `Host` pattern.
        #[arg(
            long = "ssh-alias",
            value_name = "ALIAS",
            default_value = "vk-run",
            requires = "ssh_client",
            value_parser = parse_ssh_alias,
            help_heading = "SSH"
        )]
        ssh_alias: String,
        /// user --ssh sessions log in as
        ///
        /// root is the only user every image is guaranteed to have, but a dev image's
        /// unprivileged user keeps shared-tree ownership coherent.
        #[arg(long = "ssh-user", value_name = "NAME", default_value = "root",
              value_parser = run::parse_ssh_user, help_heading = "SSH")]
        ssh_user: String,
        /// Where the rootfs comes from: oci, docker or auto
        #[arg(
            long,
            value_enum,
            default_value = "auto",
            help_heading = "Image source"
        )]
        source: run::SourceMode,
        /// PEM CA bundle the registry TLS cert chains to (oci/auto)
        #[arg(long, value_name = "FILE", help_heading = "Image source")]
        ca: Option<PathBuf>,
        /// registry username (oci/auto)
        #[arg(long, value_name = "NAME", help_heading = "Image source")]
        username: Option<String>,
        /// registry password (oci/auto)
        #[arg(long, value_name = "SECRET", help_heading = "Image source")]
        password: Option<String>,
        /// plain HTTP registry (oci/auto)
        #[arg(long, help_heading = "Image source")]
        insecure: bool,
        /// pin the run's sockets, console log and build media to this directory
        ///
        /// Created/reused, mode 0700, never removed — instead of a fresh temp dir, so external
        /// tooling can attach to the running VM: `vk-agent -s vsock-auto://DIR/vsock.sock:4444
        /// exec …`.
        #[arg(
            long = "state-dir",
            value_name = "DIR",
            help_heading = "Mounts and disks"
        )]
        state_dir: Option<PathBuf>,
        /// with --compose, the workspace root it reads as `${VK_WORKSPACE}` [default: the cwd]
        ///
        /// The project the run is about. Naming it here lets the committed file say
        /// `${VK_WORKSPACE}` instead of carrying a host path, and lets a caller boot from
        /// anywhere rather than having to cd first. It supplies the name and nothing else:
        /// what the tree is bound as, if anything, is the compose file's own business.
        #[arg(
            long,
            value_name = "DIR",
            requires = "compose",
            help_heading = "Compose services"
        )]
        workspace: Option<PathBuf>,
        /// bind-mount an extra host dir into the guest (repeatable)
        ///
        /// Beyond --workdir — e.g. persistent state a throwaway VM should keep on the host.
        /// `:ro` shares read-only, `:rw` (the default) read-write; `:overlay` shares
        /// read-only behind a tmpfs-backed overlay (the guest reads the host tree but writes
        /// stay in guest RAM, never touching it). `:disk[,size=SIZE]` instead attaches a whole
        /// filesystem in a host qcow2 as a real block device — full POSIX semantics
        /// (arbitrary chown, device nodes, sockets) and content that survives across boots,
        /// for state a service needs to own outright; the file is created and formatted the
        /// first time it is used (`size=` capacity, default 64G; only written blocks cost
        /// host disk). `:socket` forwards a host unix socket (`/var/run/docker.sock`) to
        /// the guest path — implied when HOST is one, and it hands the guest whatever that
        /// socket grants (a Docker socket is host-root-equivalent). A share (not a disk)
        /// may add `,optional` to skip an absent source instead of failing the boot.
        /// `overlay,persist` (an overlay whose writes are kept on disk) and
        /// `x-virtkit.persist_root` belong to compose services, which have a file to keep
        /// that state beside — see --compose.
        #[arg(
            short = 'v',
            long = "volume",
            value_name = "HOST:GUEST[:(ro|rw|overlay|socket)[,optional]|:disk[,size=SIZE]]",
            help_heading = "Mounts and disks"
        )]
        volume: Vec<String>,
        /// create an in-guest symlink after the mounts (repeatable)
        ///
        /// The single-file share escape hatch (virtiofs shares directories only); a dangling
        /// SRC is skipped.
        #[arg(
            long = "symlink",
            value_name = "SRC:DST",
            help_heading = "Mounts and disks"
        )]
        symlink: Vec<String>,
        /// attach a raw host disk image as a block device (repeatable)
        ///
        /// Ordered after any rootfs disk (so typically /dev/vdb, vdc, …; but /dev/vda first
        /// under --ram, which has no rootfs disk). The guest reads/writes it directly (no
        /// virtiofs), so it can partition, mkfs and install into a disk image; append `:ro` for
        /// read-only. HOST is a raw image file (qemu-img / truncate); qcow2 is not accepted
        /// here.
        #[arg(
            long = "disk",
            value_name = "HOST[:ro]",
            help_heading = "Mounts and disks"
        )]
        disk: Vec<String>,
        /// record what the guest does from boot, for `vk atop` to read
        ///
        /// One atop-format sample of its /proc per interval, landing in `<state
        /// dir>/atop/atop.log` (`vk atop` beside the running VM follows it live). `--atop`
        /// alone samples every 5 seconds; `--atop=SECS` picks the cadence.
        #[arg(
            long = "atop",
            value_name = "SECS",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "5",
            value_parser = clap::value_parser!(u64).range(1..),
            help_heading = "Recording"
        )]
        atop: Option<u64>,
        /// extra environment for the guest command and its login shells
        ///
        /// Repeatable; wins over the image env and any --env-file.
        #[arg(
            long = "env",
            value_name = "KEY=VALUE",
            help_heading = "Running the command"
        )]
        env: Vec<String>,
        /// KEY=VALUE lines of extra guest environment
        ///
        /// `#` and blank lines skipped; repeatable, later files win; --env flags win over every
        /// file.
        #[arg(
            long = "env-file",
            value_name = "FILE",
            help_heading = "Running the command"
        )]
        env_file: Vec<PathBuf>,
        /// serve host commands to the guest at /run/vk/host.sock — ANY command by default
        ///
        /// Guest tooling runs `vk-agent -s /run/vk/host.sock exec -- CMD` on the host, over
        /// vsock. WITHOUT --host-exec-wrapper the guest can run ANY host command as the host
        /// user (unrestricted); add --host-exec-wrapper to force every command through an
        /// allowlist program.
        #[arg(long = "host-exec", help_heading = "Host access from the guest")]
        host_exec: bool,
        /// force every --host-exec command through this program
        ///
        /// It receives the requested command line as its arguments and decides what to run.
        #[arg(
            long = "host-exec-wrapper",
            value_name = "PROGRAM",
            requires = "host_exec",
            help_heading = "Host access from the guest"
        )]
        host_exec_wrapper: Option<PathBuf>,
        /// client env vars passed through to the --host-exec-wrapper
        ///
        /// Repeatable; shell-style globs, e.g. `LC_*`.
        #[arg(
            long = "host-exec-env",
            value_name = "GLOB",
            requires = "host_exec_wrapper",
            help_heading = "Host access from the guest"
        )]
        host_exec_env: Vec<String>,
        /// the -f/--primary/compose builds may restore from cache but not build
        ///
        /// A cache miss aborts with exit code 3, so scripts can branch cached-vs-cold without
        /// paying for a build.
        #[arg(long = "require-cached", help_heading = "Build (with -f or --compose)")]
        require_cached: bool,
        /// Daemonize once the guest is ready
        ///
        /// The build + boot run in the foreground (Ctrl-C aborts them), then `vk` detaches so
        /// the terminal is freed while the VM keeps running. Intended for a long-lived run
        /// (`--ssh`, or `-- sleep infinity`).
        #[arg(long = "detach", help_heading = "Detach")]
        detach: bool,
        /// With --detach, power the VM off after this many idle seconds
        ///
        /// The VM outlives its startup command and goes down after this long without an active
        /// vk exec command. Only exec counts: status probes and --ssh sessions do not hold the
        /// VM up, and the startup command has to finish for the window to start. 0 keeps it
        /// running until explicitly stopped.
        #[arg(
            long = "inactivity-timeout",
            value_name = "SECS",
            requires = "detach",
            conflicts_with = "shell",
            help_heading = "Detach"
        )]
        inactivity_timeout: Option<u64>,
        /// With --detach, redirect the backgrounded VM's output here
        ///
        /// Default: discard. The foreground build/boot still prints to the terminal.
        #[arg(
            long = "detach-log",
            value_name = "PATH",
            requires = "detach",
            help_heading = "Detach"
        )]
        detach_log: Option<PathBuf>,
        /// Command to run in the guest (default: a boot-info probe)
        ///
        /// Several words are an argv, each passed as typed (like docker run — use `sh -c '…'`
        /// for shell features); a single word is a shell one-liner run verbatim.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// List the running vk VMs
    ///
    /// VMs started with `--state-dir`, with their pid, uptime, name, compose services,
    /// project directory (`--workspace`, then `--workdir`, then launch directory) and
    /// published ports (`listen->to`; `@service` when a compose sibling dials). The table
    /// folds `$HOME` to `~` and names at most three services; `--wide` shows every service,
    /// the project directory in full and the exec-channel address. With PID or DIR, only the
    /// VM with that pid, or the VMs whose project is DIR or below it (or whose state dir is
    /// DIR). Use `--json` or `--field` for scripts; neither takes `--wide`, since both
    /// already report every field.
    #[command(display_order = 6)]
    List {
        /// which VMs: a PID, or those whose project is DIR or below it (default: all)
        ///
        /// An all-digit argument is a pid, as the PID column prints; anything else a
        /// directory (a digit-only name needs a `./`).
        #[arg(value_name = "PID|DIR")]
        target: Option<std::ffi::OsString>,
        /// the full table: every service named, the project path in full, and EXEC ADDRESS
        #[arg(short = 'w', long, conflicts_with_all = ["json", "field"])]
        wide: bool,
        /// emit the entries as a JSON array instead of a table
        #[arg(long)]
        json: bool,
        /// print only this field of each VM (repeatable)
        ///
        /// A `--json` key, or a dotted path into one: `guest_ip`, `services.0.ip`. One line
        /// per VM, the fields tab-separated, each as `jq -r` would print it: a string bare,
        /// anything else as JSON; as text, nothing running prints nothing. Values are not
        /// escaped, so a path holding a tab or newline needs `--json`, which gives an array of
        /// objects holding only those fields.
        #[arg(long, value_name = "FIELD")]
        field: Vec<String>,
        /// also report, per VM, whether a fresh `vk run` would rebuild its image
        ///
        /// The report says whether the working tree drifted from what booted. It resolves
        /// base image digests, so it does network I/O.
        #[arg(long)]
        stale: bool,
    },
    /// Stop running vk VM(s)
    ///
    /// SIGTERMs the managing `vk run` (which tears down the VM and any compose siblings),
    /// then waits for it to exit. Selects the VM whose project is the current directory by
    /// default; pass a pid or a project directory to select one, or `--all`.
    #[command(display_order = 8)]
    Stop {
        /// the VM to stop: a PID or a project directory (default: the current directory)
        ///
        /// An all-digit argument is a pid, as `vk list` prints; anything else a directory —
        /// whose VM(s), and those of every directory below it, are stopped. A directory
        /// named only by digits therefore needs a `./` in front of it.
        #[arg(value_name = "PID|DIR")]
        target: Option<std::ffi::OsString>,
        /// stop every running vk VM
        #[arg(long, conflicts_with = "target")]
        all: bool,
        /// seconds to wait for each VM to go down before reporting it stuck
        ///
        /// A run allows its guests one minute to power off; the default leaves time for the
        /// run to exit without reporting an orderly shutdown as stuck.
        #[arg(long, default_value_t = 90, value_name = "SECS")]
        timeout: u64,
    },
    /// Reboot running vk VM(s) in place
    ///
    /// Asks the guest to reboot (`vk-agent reboot` over vsock); the VM comes back on the
    /// same disks, keeping its pid. Selects the VM whose project is the current directory by
    /// default; pass a pid or a project directory, or `--all`. `--force` skips the agent and
    /// hard-resets through the VMM (for a hung or agent-less guest).
    #[command(display_order = 8)]
    Reboot {
        /// the VM to reboot: a PID or a project directory (default: the current directory)
        #[arg(value_name = "PID|DIR")]
        target: Option<std::ffi::OsString>,
        /// reboot every running vk VM
        #[arg(long, conflicts_with = "target")]
        all: bool,
        /// hard-reset without waiting for the guest agent (a power-cycle, not a clean reboot)
        #[arg(long)]
        force: bool,
    },
    /// Replace this `vk` with a GitHub release build
    ///
    /// Installs the latest release, or the VERSION given. Prints what it is about to
    /// install and asks before touching anything; the download is checked against the
    /// digest published beside it and must report its own version before it replaces the
    /// running binary. Needs write access to the directory `vk` is installed in. VMs
    /// already running are unaffected. `--check` only reports what is available,
    /// downloading nothing. Exit: 0 up to date, installed, or declined at the prompt; 1 a
    /// newer release is available (`--check`); 2 the update or check itself failed.
    #[command(display_order = 9)]
    Update {
        /// release to install, `0.29.0` or `v0.29.0` (default: the latest release)
        ///
        /// An older version downgrades, which `--check` does not report as an update available.
        version: Option<String>,
        /// skip the confirmation prompt (for unattended use)
        #[arg(short = 'y', long, conflicts_with = "check")]
        yes: bool,
        /// report whether a newer release is available and exit
        ///
        /// Downloads nothing, installs nothing (exit 1 when there is one).
        #[arg(long)]
        check: bool,
    },
    /// Print each stage's build-cache key, as `stage:key` lines
    ///
    /// The `stage_key` is the chained content key after the stage's last instruction — the
    /// exact identity virtkit's instruction cache stores the stage's snapshot under. Resolves
    /// base digests + base image config over the network so the key matches a real build.
    #[command(hide = true)]
    DockerHash {
        /// Dockerfile to analyze (default: Dockerfile)
        ///
        /// Repeatable: the files merge into one stage namespace, exactly as `vk build` sees
        /// them.
        #[arg(short = 'f', long = "file", default_value = "Dockerfile")]
        dockerfile: Vec<PathBuf>,
        /// Build arg affecting the key (KEY=VAL), repeatable
        #[arg(long = "build-arg")]
        build_arg: Vec<String>,
        /// Build context for context `COPY` content hashing
        ///
        /// Repeatable, zipped positionally with -f; default: each Dockerfile's own directory.
        #[arg(long)]
        context: Vec<PathBuf>,
        /// Stages to print (default: all, in build order)
        stages: Vec<String>,
    },
    /// Check whether an ext4 image is fresh for a list of content-fingerprint parts
    ///
    /// The parts are pre-hashed strings or raw values: computes sha256(parts joined by '\n')
    /// formatted 8-4-4-4-12, reads the image's UUID, and exits 0 if they match (fresh) or 1 if
    /// they differ or the image is missing (stale). Always prints the UUID on stdout so the
    /// caller can pass it to `mkext-tar --uuid` on a stale build.
    #[command(hide = true)]
    Fingerprint {
        /// ext4 image to check for freshness
        ext4: PathBuf,
        /// Parts to hash (pre-computed hashes or raw strings), joined by '\n'
        parts: Vec<String>,
    },
    /// Export a built image as a VMDK, OVA or bootable ISO
    ///
    /// `vmdk` packages a raw disk (a `vk build --disk` artifact) as a streamOptimized
    /// VMDK (the compressed subformat vSphere's OVF/OVA import streams); `ova` wraps that
    /// in an OVF appliance descriptor + manifest; `iso` builds a bootable BIOS+UEFI ISO
    /// from a staged directory tree (see the appliance guide for the auto-install
    /// recipe). Native — no qemu-img, ovftool or xorriso.
    Export {
        /// output format
        #[arg(value_enum)]
        format: ExportFormat,
        /// what to package
        ///
        /// A raw disk image of whole 512-byte sectors (vmdk/ova), or a staged directory tree
        /// (iso).
        input: PathBuf,
        /// output path (default: the input with the format's extension)
        out: Option<PathBuf>,
        /// (ova) appliance/VM name (default: the disk's file stem)
        #[arg(long)]
        name: Option<String>,
        /// (ova) vCPUs the descriptor declares (default 2)
        #[arg(long, value_name = "N")]
        cpus: Option<u32>,
        /// (ova) memory the descriptor declares, <n>G/<n>M/MiB (default 4G)
        #[arg(long, value_name = "SIZE")]
        mem: Option<String>,
        /// (ova) VMware guest-OS identifier (default debian11_64Guest)
        #[arg(long = "guest-os", value_name = "OSTYPE")]
        guest_os: Option<String>,
        /// (ova) firmware the VM boots with (default bios)
        #[arg(long, value_enum)]
        firmware: Option<ova::Firmware>,
        /// (iso) volume identifier, 1-32 chars of [A-Z0-9_] (default VKISO)
        #[arg(long)]
        volid: Option<String>,
        /// (iso) BIOS El Torito boot image, as a path INSIDE the tree
        ///
        /// A tree path is e.g. boot/grub/eltorito.img. It gets the boot info table
        /// patched in.
        #[arg(long = "bios-boot", value_name = "TREE_PATH")]
        bios_boot: Option<PathBuf>,
        /// (iso) UEFI El Torito boot image, as a path INSIDE the tree
        ///
        /// A FAT ESP carrying EFI/BOOT/BOOTX64.EFI.
        #[arg(long = "efi-boot", value_name = "TREE_PATH")]
        efi_boot: Option<PathBuf>,
        /// (iso) make the ISO dd-able to a USB stick
        ///
        /// A host file with x86 MBR boot code (e.g. syslinux's isohdpfx.bin) laid into the
        /// system area, with partitions mapping the ISO and the ESP.
        #[arg(long = "hybrid-mbr", value_name = "FILE")]
        hybrid_mbr: Option<PathBuf>,
    },
    /// Dev: build an ext4 image from a directory tree (native, no mke2fs)
    #[command(hide = true)]
    Mkext {
        /// directory tree to pack
        src: PathBuf,
        /// ext4 image to write
        out: PathBuf,
    },
    /// Dev: verify the native qcow2 reader against `qemu-img convert` for an image
    #[command(hide = true)]
    Qcow2Verify {
        /// qcow2 image to read both ways and compare
        path: PathBuf,
    },
    /// Build an ext4 image from a rootfs tar (e.g. `docker export`)
    ///
    /// Injects host files at guest paths. Native, no mke2fs, no root.
    #[command(hide = true)]
    MkextTar {
        /// rootfs tar, or "-" to STREAM stdin
        ///
        /// Ownership and mode come from its headers. Streaming (e.g. `docker export | … -`) is
        /// a single pass, with no intermediate tar.
        tar: PathBuf,
        /// output ext4 image
        out: PathBuf,
        /// inject a host file at a guest path, HOST:GUEST:OCTAL_MODE (repeatable)
        #[arg(long = "inject", value_name = "HOST:GUEST:MODE")]
        inject: Vec<String>,
        /// spare free space (GiB) left in the filesystem for the guest to write
        #[arg(long, default_value_t = 0)]
        free_gib: u64,
        /// streaming only (tar = "-"): upper-bound rootfs size in GiB
        ///
        /// Required when streaming; the image is sparse, so over-estimating is free.
        #[arg(long, default_value_t = 0)]
        size_gib: u64,
        /// streaming only: inode budget override (default: ~1 per 16 KiB)
        #[arg(long)]
        inodes: Option<u64>,
        /// filesystem UUID to stamp (32 hex digits, dashes optional)
        ///
        /// Set it to a content fingerprint to make the image's identity == what it was built
        /// from.
        #[arg(long)]
        uuid: Option<String>,
        /// filesystem label to stamp (≤16 bytes; for blkid/lsblk)
        #[arg(long)]
        label: Option<String>,
    },
    /// Build an ext4 image straight from a local OCI image archive
    ///
    /// The tar `buildctl --output type=oci` produces: flattens its layers AND extracts the
    /// image config (Env/User/Entrypoint/Cmd into /etc/virtkit/{env,user,cmd}), no
    /// docker/podman. Replaces the podman load→create→export→mkext-tar chain.
    #[command(hide = true)]
    MkextOci {
        /// OCI image archive (tar), or "-" to STREAM stdin
        ///
        /// Streaming is spooled to a temp file first: OCI archives need random access, and
        /// index.json comes last.
        archive: PathBuf,
        /// output ext4 image
        out: PathBuf,
        /// inject a host file at a guest path, HOST:GUEST:OCTAL_MODE (repeatable)
        #[arg(long = "inject", value_name = "HOST:GUEST:MODE")]
        inject: Vec<String>,
        /// spare free space (GiB) left in the filesystem for the guest to write
        #[arg(long, default_value_t = 0)]
        free_gib: u64,
        /// filesystem UUID to stamp (32 hex digits, dashes optional)
        ///
        /// Set it to a content fingerprint to make the image's identity == what it was built
        /// from.
        #[arg(long)]
        uuid: Option<String>,
        /// filesystem label to stamp (≤16 bytes; for blkid/lsblk)
        #[arg(long)]
        label: Option<String>,
    },
    /// List the advanced/plumbing commands `vk --help` hides, with the everyday ones
    ///
    /// (`vk virtiofsd` dispatches on raw argv before this CLI and appears in neither help; see
    /// the README.)
    #[command(hide = true)]
    HelpAll,
    /// Dev: pull an OCI image from a registry (no docker) and flatten it to a rootfs tar
    #[command(hide = true)]
    OciPull {
        /// image reference, <name>[:tag|@sha256:…]
        reference: String,
        /// rootfs tar to write
        out: PathBuf,
        /// registry username
        #[arg(long, value_name = "NAME")]
        username: Option<String>,
        /// registry password
        #[arg(long, value_name = "SECRET")]
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
        return match libkrun_sys::keep(&spec) {
            Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
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
/// the final reply. `down` and `status` are single round-trips, but `down` may take up to a
/// minute while the guest powers off.
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
        ServiceCmd::Reboot { name } => {
            client
                .request(&Request::Reboot { unit: name.clone() })
                .await
        }
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

/// The state dir `vk run`/`vk gc` cache under: a configured `state_dir` (the CI
/// runner), else the rootless dev default (`$XDG_DATA_HOME/virtkit`). Distinct
/// from `Config::state_dir()`, the executor's root-owned `/var/lib/virtkit` default.
fn effective_state_dir(cfg: &Config) -> anyhow::Result<PathBuf> {
    match &cfg.state_dir {
        Some(d) => Ok(d.clone()),
        None => run::default_data_base(),
    }
}

/// `vk config`: print the effective configuration as TOML (defaults merged with the
/// loaded file), headed by which file it came from; or with `path`, just that file's
/// path (exit 1 when no file is in use). `--example` is handled before Config::load.
fn config_cmd(cfg: &Config, path: bool) -> ExitCode {
    if path {
        return match &cfg.source {
            Some(p) => {
                println!("{}", p.display());
                ExitCode::SUCCESS
            }
            None => exit_code(1),
        };
    }
    let toml = match toml::to_string(cfg) {
        Ok(t) => t,
        Err(e) => return fail(&anyhow::anyhow!(e).context("serializing the config"), 1),
    };
    match &cfg.source {
        Some(p) => println!(
            "# effective configuration (defaults merged with {})",
            p.display()
        ),
        None => println!("# effective configuration (no config file found; built-in defaults)"),
    }
    print!("{toml}");
    ExitCode::SUCCESS
}

/// The `vk paths` report: each effective host path, where it comes from, and how
/// to override it. Built as a string so tests can assert on the resolutions.
fn paths_report(cfg: &Config, gitlab: bool) -> anyhow::Result<String> {
    use std::fmt::Write;
    let mut out = String::new();
    // Which file Config::load read is recorded on the config itself; classify it
    // against the chain's fixed tiers for the note (an explicit --config /
    // VIRTKIT_CONFIG path that can't be read already failed Config::load).
    let user = config::user_path();
    match &cfg.source {
        Some(p) => {
            let note = if user.as_deref() == Some(p.as_path()) {
                "user config"
            } else if p.as_path() == Path::new(config::DEFAULT_PATH) {
                "system config"
            } else {
                "from --config / VIRTKIT_CONFIG"
            };
            writeln!(out, "config file     {} ({note})", p.display())?;
        }
        None => writeln!(out, "config file     (none found; built-in defaults)")?,
    }
    writeln!(
        out,
        "                chain: --config > $VIRTKIT_CONFIG > ~/.config/virtkit/config.toml > {}",
        config::DEFAULT_PATH
    )?;
    writeln!(out)?;
    let state_note = match &cfg.state_dir {
        Some(_) => "`state_dir` in the config",
        None => "default: $XDG_DATA_HOME/virtkit",
    };
    let state_dir = effective_state_dir(cfg)?;
    writeln!(
        out,
        "state dir       {} ({state_note})",
        state_dir.display()
    )?;
    writeln!(
        out,
        "                the root of everything vk stores on this host"
    )?;
    writeln!(
        out,
        "                override: `state_dir` in the config (unset, the CI executor uses /var/lib/virtkit)"
    )?;
    writeln!(
        out,
        "  registry/     image cache: bundles pulled from the [registry] remote"
    )?;
    writeln!(
        out,
        "  docker/       image cache: docker/OCI images converted to bootable disks"
    )?;
    writeln!(
        out,
        "  build/        image cache: compose `build:` stage snapshots"
    )?;
    let images = cfg.local_dir_under(&state_dir);
    if images == state_dir.join("images") {
        writeln!(
            out,
            "  images/       baked `local/<name>` bundles (override: `[local] dir`)"
        )?;
    } else {
        writeln!(
            out,
            "  images        {} (`[local] dir`) — baked `local/<name>` bundles",
            images.display()
        )?;
    }
    writeln!(
        out,
        "                the three image-cache tiers hold ready-to-boot disks; `vk gc` reclaims"
    )?;
    writeln!(
        out,
        "                idle ones. images/ is never reclaimed."
    )?;
    writeln!(out)?;
    // The instruction cache and `vk registry status`/`gc` use this store, so it is
    // resolved the way they resolve it: `[build] cache_registry` moves it when it names a
    // store here. `vk-registry serve` is a resolution of its own (its `--root`/`--config`)
    // and is not claimed here. A `[registry] repo` does not move it either — that only
    // routes the bundle pushes — so a local repo is reported separately.
    let configured = cfg.build.cache_registry.as_deref();
    match crate::build::cache_store(configured)? {
        crate::build::CacheStore::Dir(store) => {
            let from = match configured {
                // caching off: the builtin store is named because that is where whatever
                // was cached before still is, not because a setting put it there
                Some("none") => "`[build] cache_registry = \"none\"`: caching off",
                // name the key that moved it, rather than calling it the default it is not
                Some(_) => "`[build] cache_registry`",
                None => "default: $XDG_DATA_HOME/virtkit/registry",
            };
            writeln!(out, "registry store  {} ({from})", store.display())?;
            writeln!(
                out,
                "                a separate content-addressed store holding the build/instruction cache;"
            )?;
            writeln!(
                out,
                "                `vk registry status`/`gc` operate on it (a `vk-registry serve` takes its"
            )?;
            writeln!(
                out,
                "                root from its own `--root`/`--config`, which may differ)"
            )?;
            // Both spellings of one directory share it, so compare what they resolve to
            // rather than how they were written; neither has to exist to be reported.
            let shared = state_dir.join("registry");
            let same = match (store.canonicalize(), shared.canonicalize()) {
                (Ok(a), Ok(b)) => a == b,
                _ => store == shared,
            };
            if same {
                writeln!(
                    out,
                    "                (it shares this directory with the image cache's registry/ tier;"
                )?;
                writeln!(
                    out,
                    "                the layouts are independent and each GC ignores the other's files)"
                )?;
            }
            writeln!(
                out,
                "                override: `--cache-registry`/`[build] cache_registry` (instruction cache),"
            )?;
            writeln!(out, "                `--root` on `vk registry status`/`gc`")?;
        }
        // The cache is a `vk-registry` server: the store is on its host, so there is no
        // path here to print — and naming the builtin one this vk is not using would be
        // the bug `vk registry status` had.
        crate::build::CacheStore::Server(repo) => {
            writeln!(
                out,
                "registry store  on the host serving {repo} (`[build] cache_registry`)"
            )?;
            writeln!(
                out,
                "                the build/instruction cache lives there; `vk registry status`/`gc`"
            )?;
            writeln!(
                out,
                "                need `--root` to name a store in this filesystem"
            )?;
        }
    }
    writeln!(out)?;
    let vms = vms::registry_dir()?;
    writeln!(
        out,
        "vm registry     {} (default: $XDG_DATA_HOME/virtkit/vms)",
        vms.display()
    )?;
    writeln!(
        out,
        "                one entry per `vk run --state-dir` VM; `vk list`/`vk stop` read it"
    )?;
    writeln!(
        out,
        "                (self-pruned as VMs exit — no `vk gc` needed)"
    )?;
    if let Some(repo) = cfg.registry.as_ref().and_then(|r| r.local_root()) {
        writeln!(
            out,
            "bundle repo     {} (`[registry] repo`) — `vk registry push` and `vk build --tag` use it in-process",
            repo.display()
        )?;
    }
    if gitlab {
        // The executor roots its state at Config::state_dir() (/var/lib/virtkit when
        // unset) — not the dev default `vk run` caches under (see jobctx.rs).
        let exec_state = cfg.state_dir();
        writeln!(out)?;
        writeln!(out, "gitlab executor")?;
        writeln!(
            out,
            "  jobs dir      {} (per-job runtime state, removed at job cleanup)",
            exec_state.join("jobs").display()
        )?;
        let checkouts_note = match cfg.gitlab.as_ref().and_then(|g| g.checkout_dir.as_ref()) {
            Some(_) => "private subtree of `[gitlab] checkout_dir`",
            None => "default: <executor state dir>/checkouts",
        };
        writeln!(
            out,
            "  checkouts     {} ({checkouts_note}) — host_checkout clones, idle-reclaimed",
            cfg.checkout_root().display()
        )?;
        let stats_note = match atop::enabled(cfg) {
            true => format!(
                "per-job guest stats in `atop -P` format, one directory per day, {}",
                atop::retention_note(cfg)
            ),
            false => "off (`[gitlab] atop`)".to_string(),
        };
        writeln!(
            out,
            "  atop archive  {} ({stats_note})",
            atop::archive_root(cfg).display()
        )?;
        match cfg.gitlab.as_ref().and_then(|g| g.dir.as_ref()) {
            Some(d) => writeln!(
                out,
                "  tools dir     {} (`[gitlab] dir`) — static tools shared read-only into job VMs",
                d.display()
            )?,
            None => writeln!(out, "  tools dir     (unset; override: `[gitlab] dir`)")?,
        }
    } else {
        writeln!(out)?;
        writeln!(out, "gitlab executor paths: `vk paths --gitlab`")?;
    }
    Ok(out)
}

/// Whether a build's exported image gets an ext4 journal: on by default, opted out by
/// either the CLI's `--no-journal` or the config's `[build] no_journal` (either one suffices
/// to opt out — the CLI can only push toward "skip it," never force a journal back on over
/// a config-file opt-out, matching every other build bool flag's merge in this command).
fn journal_enabled(cli_no_journal: bool, cfg_no_journal: bool) -> bool {
    !(cli_no_journal || cfg_no_journal)
}

async fn cli_main() -> ExitCode {
    // reqwest/rustls are compiled with no built-in crypto provider (rustls-no-provider,
    // to keep aws-lc-rs out of the build); install ring — the backend russh already
    // uses — as the process default before any TLS client is constructed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    if let Cmd::HelpAll = &cli.cmd {
        // CommandFactory::command() names the command after the package
        // (vk-driver); only the parse path picks up the argv[0] bin name.
        let mut help = <Cli as clap::CommandFactory>::command()
            .bin_name("vk")
            .mut_subcommands(|c| c.hide(false))
            .after_help(None::<&str>);
        let _ = help.print_help();
        return ExitCode::SUCCESS;
    }
    // `service` talks to the host manager over vsock and needs no host config — handle it
    // before Config::load so it works from inside a guest that has none.
    if let Cmd::Service { cmd } = &cli.cmd {
        return service_cmd(cmd).await;
    }
    // `update` replaces the binary and reads nothing from the config — handle it before
    // Config::load, so a config file that no longer parses cannot block the upgrade that
    // fixes it.
    if let Cmd::Update {
        version,
        yes,
        check,
    } = &cli.cmd
    {
        // Errors exit 2 throughout, leaving 1 to mean `--check` found a newer release —
        // so a script can branch on "an update is available" without reading it as
        // failure.
        if *check {
            return match VK.check(version.as_deref()).await {
                Ok(false) => ExitCode::SUCCESS,
                Ok(true) => exit_code(1),
                Err(e) => fail(&e, 2),
            };
        }
        // Whichever way it went is already reported; `vk` has nothing to add, since the
        // rename leaves running VMs on the binary they booted from.
        return match VK.update(version.as_deref(), *yes).await {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 2),
        };
    }
    // `vk config --example` prints the bundled annotated template — before Config::load,
    // so a broken config file on disk cannot keep the user from seeing a valid example.
    if let Cmd::Config { example: true, .. } = &cli.cmd {
        print!("{}", include_str!("../config.example.toml"));
        return ExitCode::SUCCESS;
    }
    // Answer a version-only check before Config::load: it describes this binary, and an
    // unreadable host config must not look like an old `vk` to a script.
    if let Cmd::Check {
        feature,
        min_version: Some(min),
    } = &cli.cmd
        && feature.is_empty()
    {
        return match check::min_version_only(*min) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => exit_code(1),
            Err(e) => fail(&anyhow::anyhow!(e), 2),
        };
    }
    let cfg = match Config::load(cli.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(e) => return fail(&e, 2),
    };
    // Apply the host's `[build]` tuning and VMM-backend choice process-wide, before any
    // build or boot path runs (VIRTKIT_VMM still overrides the config key).
    build::set_tuning(&cfg.build);
    vmm::set_config_backend(cfg.vmm);
    if let Cmd::Config {
        example: false,
        path,
    } = &cli.cmd
    {
        return config_cmd(&cfg, *path);
    }
    if let Cmd::Check {
        feature,
        min_version,
    } = &cli.cmd
    {
        return match check::run(&cfg, feature, *min_version) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => exit_code(1),
            Err(e) => fail(&anyhow::anyhow!(e), 2),
        };
    }
    if let Cmd::Paths { gitlab } = &cli.cmd {
        return match paths_report(&cfg, *gitlab) {
            Ok(report) => {
                print!("{report}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, 2),
        };
    }
    if let Cmd::List {
        target,
        wide,
        json,
        field,
        stale,
    } = &cli.cmd
    {
        let target = match target.as_deref().map(vms::Selector::parse).transpose() {
            Ok(sel) => sel,
            Err(e) => return fail(&e, 2),
        };
        return match vms::list_report(target, *json, *stale, field, *wide) {
            Ok(report) => write_report(&report),
            Err(e) => fail(&e, 2),
        };
    }
    if let Cmd::Stop {
        target,
        all,
        timeout,
    } = &cli.cmd
    {
        let selector = match target.as_deref().map(vms::Selector::parse).transpose() {
            Ok(sel) => sel,
            Err(e) => {
                eprintln!("vk: {e:#}");
                return exit_code(2);
            }
        };
        return match vms::stop_cmd(selector, *all, *timeout) {
            Ok((report, all_down)) => match write_report(&report) {
                ExitCode::SUCCESS if !all_down => exit_code(1),
                code => code,
            },
            Err(e) => fail(&e, 2),
        };
    }
    if let Cmd::Reboot { target, all, force } = &cli.cmd {
        let selector = match target.as_deref().map(vms::Selector::parse).transpose() {
            Ok(sel) => sel,
            Err(e) => {
                eprintln!("vk: {e:#}");
                return exit_code(2);
            }
        };
        return match vms::reboot_cmd(selector, *all, *force) {
            Ok((report, all_ok)) => match write_report(&report) {
                ExitCode::SUCCESS if !all_ok => exit_code(1),
                code => code,
            },
            Err(e) => fail(&e, 2),
        };
    }
    if let Cmd::Gc { idle_secs } = &cli.cmd {
        let override_idle = idle_secs.map(std::time::Duration::from_secs);
        let image_idle = override_idle.unwrap_or_else(|| cfg.image_cache_idle());
        let checkout_idle = override_idle.unwrap_or_else(|| cfg.checkout_cache_idle());
        // Sweep the same state dir `vk run`/the executor cache under.
        let state_dir = match effective_state_dir(&cfg) {
            Ok(d) => d,
            Err(e) => return fail(&e, 2),
        };
        let registry = state_dir.join("registry");
        image::gc_idle(&registry, image_idle);
        image::sweep_chunks(&registry);
        image::gc_idle(&state_dir.join("docker"), image_idle);
        image::gc_idle(&state_dir.join("build"), image_idle);
        image::sweep_orphaned_build_tmp(&state_dir.join("docker"));
        image::sweep_orphaned_build_tmp(&state_dir.join("build"));
        // Checkouts are the executor's alone, and the executor roots its state at
        // `Config::state_dir()` — never the dev default `vk run` caches under, which is what
        // `effective_state_dir` may resolve to here. Sweeping that instead would walk a tree
        // nothing ever checks out into and silently reclaim nothing.
        checkout::gc_idle(&cfg.checkout_root(), checkout_idle);
        println!(
            "virtkit: gc done (idle threshold {}s for images, {}s for checkouts)",
            image_idle.as_secs(),
            checkout_idle.as_secs()
        );
        return ExitCode::SUCCESS;
    }
    // `run` is a standalone dev path: no JobCtx (no CUSTOM_ENV_* job context).
    if let Cmd::Run {
        image,
        file,
        target,
        context,
        build_context,
        cache_registry,
        cache_insecure,
        build_arg,
        build_net,
        build_allow_ip,
        build_allow_name,
        workdir,
        kernel,
        console_serial,
        pmu,
        nested,
        source,
        ca,
        username,
        password,
        insecure,
        agent,
        cloud_hypervisor,
        cpus,
        mem,
        nics,
        boot_timeout,
        vm_name,
        ram,
        init,
        shell,
        tty,
        net,
        audit_egress,
        build_audit_egress,
        registry_proxy,
        compose,
        profile,
        primary,
        service_cpus,
        service_mem,
        service_nics,
        ssh_agent,
        ssh_host,
        ssh,
        ssh_key,
        ssh_client,
        ssh_alias,
        ssh_user,
        state_dir,
        workspace,
        volume,
        symlink,
        disk,
        atop,
        env,
        env_file,
        host_exec,
        host_exec_wrapper,
        host_exec_env,
        require_cached,
        detach,
        inactivity_timeout,
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
                || *tty
                || *ssh
                || !ssh_key.is_empty()
                || *ssh_agent
                || !ssh_host.is_empty()
                || workdir.is_some()
                || !volume.is_empty()
                || !symlink.is_empty()
                || !env.is_empty()
                || !env_file.is_empty()
                || *host_exec
                || inactivity_timeout.is_some())
        {
            return fail(
                &anyhow::anyhow!(
                    "--compose without an image/-f/--primary is services-only (compose up) — \
                     there is no primary VM for a command, --shell, -t, --ssh, --workdir, \
                     --volume, --symlink, --env, --env-file, --host-exec, or \
                     --inactivity-timeout"
                ),
                2,
            );
        }
        if *audit_egress && !*net && compose.is_none() {
            return fail(
                &anyhow::anyhow!(
                    "--audit-egress lists the domains the guest contacts through the switch, so \
                     it requires --net (or --compose)"
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
        // Before the pull or the build, not at boot: a guest the host will never give
        // VMX/SVM to is not worth fetching an image for. `run::spawn_vmm` checks again at
        // boot, so the refusal does not depend on a flag having asked.
        if *nested && !vmm::host_nesting_enabled() {
            return fail(
                &anyhow::anyhow!(
                    "--nested needs nested virtualization enabled on the host \
                     (kvm_intel.nested / kvm_amd.nested)"
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
                // `:optional` on an absent source contributes no mount.
                .filter_map(|v| compose::parse_volume(v, &cwd).transpose())
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
        let build_contexts = match build::parse_build_contexts(build_context) {
            Ok(v) => v,
            Err(e) => return fail(&e, 2),
        };
        // Resolve the run's cache like `vk build`: CLI flags, then `[build]`. Doing this
        // once keeps a prebuild and the run it warms on the same destination.
        let cache =
            build::CacheOpts::resolve(cache_registry.as_deref(), *cache_insecure, &cfg.build);
        let args = run::RunArgs {
            image: image.clone().unwrap_or_default(),
            dockerfiles: file.clone(),
            target: target.clone(),
            contexts: context.clone(),
            build_contexts,
            cache,
            build_args,
            workdir: workdir.clone(),
            kernel: kernel.clone(),
            console_serial: *console_serial,
            pmu: *pmu,
            nested: *nested,
            agent: agent.clone(),
            // CLI flag wins; else the config's top-level cloud_hypervisor (bare
            // "cloud-hypervisor" when unset). `[build] cloud_hypervisor` sizes the build
            // guest, not the run's.
            cloud_hypervisor: cloud_hypervisor
                .clone()
                .unwrap_or_else(|| cfg.cloud_hypervisor().to_path_buf()),
            source: *source,
            ca: ca.clone(),
            username: username.clone(),
            password: password.clone(),
            insecure: *insecure,
            cpus: *cpus,
            mem: mem.clone(),
            nics: *nics,
            service_cpus: service_cpus.clone(),
            service_mem: service_mem.clone(),
            service_nics: service_nics.clone(),
            boot_timeout_secs: *boot_timeout,
            vm_name: vm_name.clone(),
            ram: *ram,
            init: *init,
            shell: *shell,
            tty: *tty,
            // services live on the run switch's LAN: --compose implies it.
            net: *net || compose.is_some(),
            audit_egress: *audit_egress,
            build_audit_egress: *build_audit_egress,
            registry_proxy: registry_proxy.clone(),
            compose: compose.clone(),
            profiles: profile.clone(),
            primary: primary.clone(),
            build_net: bnet,
            ssh_agent: *ssh_agent,
            ssh_hosts: ssh_host.clone(),
            ssh: *ssh || *ssh_client || !ssh_key.is_empty(),
            ssh_keys: ssh_key.clone(),
            ssh_client: *ssh_client,
            ssh_alias: ssh_alias.clone(),
            ssh_user: ssh_user.clone(),
            state_dir: state_dir.clone(),
            workspace: workspace.clone(),
            volumes,
            symlinks,
            extra_disks,
            atop: *atop,
            env: extra_env,
            host_exec: *host_exec,
            host_exec_wrapper: host_exec_wrapper.clone(),
            host_exec_env: host_exec_env.clone(),
            require_cached: *require_cached,
            detach: *detach,
            inactivity_timeout_secs: *inactivity_timeout,
            detach_log: detach_log.clone(),
            command: command.clone(),
        };
        return match run::run(&args, &cfg).await {
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
    if let Cmd::Export {
        format,
        input,
        out,
        name,
        cpus,
        mem,
        guest_os,
        firmware,
        volid,
        bios_boot,
        efi_boot,
        hybrid_mbr,
    } = &cli.cmd
    {
        let out = out
            .clone()
            .unwrap_or_else(|| input.with_extension(format.extension()));
        // By identity, not path spelling: a symlink or `./`-prefixed alias of the input
        // would otherwise pass the check and be truncated while still being read.
        let same_file = {
            use std::os::unix::fs::MetadataExt;
            match (std::fs::metadata(input), std::fs::metadata(&out)) {
                (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
                _ => out == *input,
            }
        };
        if same_file {
            return fail(
                &anyhow::anyhow!(
                    "output {} would overwrite the input — pass an output path",
                    out.display()
                ),
                2,
            );
        }
        // Each format has its own knobs; a flag for another format is a mistake
        // worth stopping on, not ignoring.
        let appliance_flags = name.is_some()
            || cpus.is_some()
            || mem.is_some()
            || guest_os.is_some()
            || firmware.is_some();
        let iso_flags =
            volid.is_some() || bios_boot.is_some() || efi_boot.is_some() || hybrid_mbr.is_some();
        if *format != ExportFormat::Ova && appliance_flags {
            return fail(
                &anyhow::anyhow!(
                    "--name/--cpus/--mem/--guest-os/--firmware describe an appliance — \
                     they apply to `vk export ova`"
                ),
                2,
            );
        }
        if *format != ExportFormat::Iso && iso_flags {
            return fail(
                &anyhow::anyhow!(
                    "--volid/--bios-boot/--efi-boot/--hybrid-mbr describe a boot medium — \
                     they apply to `vk export iso`"
                ),
                2,
            );
        }
        // (size to report, description of the input)
        let result: anyhow::Result<(u64, String)> = match format {
            ExportFormat::Vmdk => vmdk::write_stream_optimized(input, &out).map(|info| {
                (
                    info.written,
                    format!("{} MiB disk", info.capacity.div_ceil(1 << 20)),
                )
            }),
            ExportFormat::Ova => {
                // A zero either way is a usage error (exit 2), like an unparsable --mem;
                // write_ova's own check only backstops non-CLI callers.
                if *cpus == Some(0) {
                    return fail(&anyhow::anyhow!("--cpus must be at least 1"), 2);
                }
                let mem_mib = match mem.as_deref() {
                    None => 4096,
                    Some(m) => match run::parse_mem_mib(m).filter(|mib| *mib > 0) {
                        Some(mib) => mib,
                        None => {
                            return fail(
                                &anyhow::anyhow!("invalid --mem {m:?} (want <n>G, <n>M or MiB)"),
                                2,
                            );
                        }
                    },
                };
                let spec = ova::OvaSpec {
                    name: name.clone().unwrap_or_else(|| {
                        input
                            .file_stem()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "appliance".to_string())
                    }),
                    cpus: cpus.unwrap_or(2),
                    mem_mib,
                    guest_os: guest_os
                        .clone()
                        .unwrap_or_else(|| "debian11_64Guest".to_string()),
                    firmware: firmware.unwrap_or(ova::Firmware::Bios),
                };
                ova::write_ova(input, &out, &spec).map(|info| {
                    // the OVA wraps the VMDK, so its own size is the honest figure
                    let size = std::fs::metadata(&out).map_or(info.written, |m| m.len());
                    (
                        size,
                        format!("{} MiB disk", info.capacity.div_ceil(1 << 20)),
                    )
                })
            }
            ExportFormat::Iso => {
                let boot = iso9660::BootSpec {
                    bios: bios_boot.clone(),
                    efi: efi_boot.clone(),
                    hybrid_mbr: hybrid_mbr.clone(),
                };
                iso9660::write_iso(input, &out, volid.as_deref().unwrap_or("VKISO"), &boot)
                    .map(|info| (info.size, format!("tree of {} members", info.members)))
            }
        };
        return match result {
            Ok((size, what)) => {
                println!(
                    "virtkit: wrote {} ({} MiB for a {what})",
                    out.display(),
                    size.div_ceil(1 << 20),
                );
                ExitCode::SUCCESS
            }
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
        workspace,
        state_dir,
        context,
        build_context,
        out,
        tag,
        disk,
        print_plan,
        cloud_hypervisor,
        kernel,
        agent,
        cache_registry,
        cache_insecure,
        build_cache,
        no_journal,
        build_tmp_tmpfs,
        build_arg,
        build_net,
        build_allow_ip,
        build_allow_name,
        build_audit_egress,
        require_cached,
        build_jobs,
        stage_mem,
        stage_cpus,
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
        let build_contexts = match build::parse_build_contexts(build_context) {
            Ok(v) => v,
            Err(e) => return fail(&e, 2),
        };
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
        // --tag publishes the single built target as a bundle. It builds a byte-clean ext4
        // to a scratch dir (whose `runner.ext4.json` config sidecar rides the bundle), then
        // pushes; incompatible with the multi-target/--compose path.
        if tag.is_some() && (compose.is_some() || target.len() > 1) {
            return fail(
                &anyhow::anyhow!(
                    "--tag builds a single target; not usable with --compose or multiple --target"
                ),
                2,
            );
        }
        if tag.is_some() && out.is_some() {
            return fail(
                &anyhow::anyhow!(
                    "--tag publishes the built bundle to the registry; --out does not apply"
                ),
                2,
            );
        }
        let tag_bundle = tag
            .as_ref()
            .map(|_| std::env::temp_dir().join(format!("vk-tag-{}", std::process::id())));
        // Export renames/flattens into `<tag_bundle>/runner.ext4` but does not create the
        // parent, so make the scratch dir up front.
        if let Some(dir) = &tag_bundle
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            return fail(
                &anyhow::anyhow!("creating the --tag scratch dir {}: {e}", dir.display()),
                1,
            );
        }
        let tag_out = tag_bundle.as_ref().map(|d| d.join("runner.ext4"));
        let cache = build::CacheOpts::resolve(cache_registry.as_deref(), *cache_insecure, b);
        let opts = build::Options {
            dockerfiles: file.clone(),
            // build_units (the multi-target / --compose path) reads targets from its units;
            // the single-image path uses this one (default: the last stage).
            target: target.first().cloned(),
            stage_guests: build::stage_overrides(stage_mem, stage_cpus),
            contexts: context.clone(),
            build_contexts,
            out: tag_out.clone().or_else(|| out.clone()),
            out_disk,
            print_plan: *print_plan,
            cloud_hypervisor: cloud_hypervisor
                .clone()
                .or_else(|| b.cloud_hypervisor.clone())
                .or_else(|| cfg.cloud_hypervisor.clone()),
            kernel: kernel.clone().or_else(|| b.kernel.clone()),
            agent: agent.clone().or_else(|| b.agent.clone()),
            cache_registry: cache.registry,
            cache_insecure: cache.insecure,
            cache_auth: cache.auth,
            build_cache,
            journal: journal_enabled(*no_journal, b.no_journal),
            // A `vk build --out` artifact stays a raw ext4: it is what gets mounted, packaged
            // and pushed as a bundle.
            out_format: build::ImageFormat::Raw,
            tmp_tmpfs: *build_tmp_tmpfs || b.tmp_tmpfs,
            build_args,
            net,
            audit: *build_audit_egress,
            require_cached: *require_cached,
            build_jobs: build_jobs.or(b.jobs),
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
                // Match `vk run --compose` so prebuild and boot resolve the same cache keys.
                // Invalid --workspace or --state-dir values are flag errors (exit 2).
                let builtins =
                    match compose::Builtins::resolve(workspace.as_deref(), state_dir.as_deref()) {
                        Ok(b) => b,
                        Err(e) => return fail(&e, 2),
                    };
                let cunits = match compose::load(path, Some(&builtins)) {
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
                        build_contexts: opts.build_contexts.clone(),
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
            Ok(_) => match (&tag_bundle, tag) {
                (Some(dir), Some(t)) => {
                    // Byte-clean bundle: agent as PID 1 (from the boot), Env/User from the
                    // sidecar — boot.kind is generic-disk. Publish; chunks dedup against the
                    // build cache, so a co-located registry writes only the manifest.
                    let r = std::fs::write(dir.join("boot.kind"), "generic-disk")
                        .map_err(anyhow::Error::from)
                        .and_then(|()| crate::registry::push(&cfg, dir, t));
                    let _ = std::fs::remove_dir_all(dir);
                    match r {
                        Ok(digest) => {
                            println!("virtkit: tagged virtkit/{t} ({digest})");
                            ExitCode::SUCCESS
                        }
                        Err(e) => fail(&e, 1),
                    }
                }
                _ => ExitCode::SUCCESS,
            },
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
        let creds = oci::Creds {
            username: username.clone(),
            password: password.clone(),
            token: None,
            ca_pem: None,
            insecure: *insecure,
        };
        let creds = match creds.with_ca_file(ca.as_deref()) {
            Ok(c) => c,
            Err(e) => return fail(&e, 1),
        };
        return match oci::pull_flatten(reference, &creds, out, &|m| println!("{m}")).await {
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
            RegistryCmd::Status { root } => {
                let root = match store_root(&cfg, root) {
                    Ok(r) => r,
                    Err(e) => return fail(&e, 2),
                };
                match vk_registry::status(root) {
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
                let root = match store_root(&cfg, root) {
                    Ok(r) => r,
                    Err(e) => return fail(&e, 2),
                };
                let days = |d: u64| std::time::Duration::from_secs(d * 86_400);
                match vk_registry::gc(root, days(*retention_days), days(*grace_days), *dry_run) {
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
        egress_restrict,
        source_egress,
        registry_proxy,
        denied_log,
        audit_log,
        net_bytes,
    } = &cli.cmd
    {
        let mut listen_bind = Vec::with_capacity(listen.len());
        for (i, l) in listen.iter().enumerate() {
            // Split from the right: paths may contain '=', but IPv4 addresses and VM ids do
            // not. Legacy entries without a VM id use their position to remain distinct.
            let (head, last) = match l.rsplit_once('=') {
                Some(parts) => parts,
                None => return fail(&anyhow::anyhow!("bad --listen {l:?} (want socket=ip)"), 2),
            };
            let parsed = match last.parse::<u32>() {
                // An explicit VM id leaves the address in the preceding field.
                Ok(vm) => head.rsplit_once('=').and_then(|(path, ip)| {
                    Some((
                        PathBuf::from(path),
                        ip.parse::<std::net::Ipv4Addr>().ok()?,
                        vm,
                    ))
                }),
                Err(_) => last
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
                    .map(|ip| (PathBuf::from(head), ip, i as u32)),
            };
            match parsed {
                Some(entry) => listen_bind.push(entry),
                None => {
                    return fail(
                        &anyhow::anyhow!("bad --listen {l:?} (want socket=ip[=vm])"),
                        2,
                    );
                }
            }
        }
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
        // --egress-restrict forces allowlist mode: an empty allowlist denies everything
        // (the CI executor sets it when a job configures egress) rather than collapsing to
        // unrestricted the way the dev `vk switch` / `vk run` path does.
        let built = if *egress_restrict {
            switch::Egress::restricted(allow_ip, allow_name)
        } else {
            switch::Egress::new(allow_ip, allow_name)
        };
        let egress = match built {
            Ok(e) => e,
            Err(e) => return fail(&e, 2),
        };
        let proxy = match registry_proxy
            .as_deref()
            .map(parse_registry_proxy)
            .transpose()
        {
            Ok(p) => p,
            Err(e) => return fail(&e, 2),
        };
        let per_source = match parse_source_egress(source_egress) {
            Ok(m) => m,
            Err(e) => return fail(&e, 2),
        };
        return match switch::run(
            &listen_bind,
            *gateway,
            *prefix,
            hosts,
            reservations,
            egress,
            per_source,
            proxy,
            denied_log.clone(),
            audit_log.clone(),
            net_bytes.clone(),
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    let ctx = match JobCtx::new(cfg) {
        Ok(ctx) => ctx,
        Err(e) => return fail(&e, 2),
    };

    match cli.cmd {
        Cmd::Tune => match schedule::tune(&ctx.cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
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
            GitlabCmd::Run { script, stage } => {
                match executor::run_stage(&ctx, &script, stage.as_deref()).await {
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
                }
            }
            GitlabCmd::Supervise { job_dir } => match vm::supervise(&ctx, &job_dir).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            },
            GitlabCmd::Cleanup => match vm::cleanup(&ctx) {
                Ok(()) => ExitCode::SUCCESS,
                // gitlab-runner only logs cleanup failures; report and don't mask
                Err(e) => fail(&e, 1),
            },
            GitlabCmd::Usage { project } => {
                let history = ctx.history_dir();
                // The parse error is carried into the report rather than failing the command:
                // a host with an unreadable budget is exactly one an operator runs this to
                // understand.
                let budget = vm::budget_mib(&ctx.cfg).map(|r| r.map_err(|e| format!("{e:#}")));
                match admit::project_report(
                    &history,
                    project.as_deref().unwrap_or(""),
                    budget,
                    ctx.cfg.schedule.from_history,
                ) {
                    Some(report) => print!("{report}"),
                    // Not a failure either way, but say which: a runner that has run nothing
                    // looks the same as a project named in a way no directory answers to.
                    None => match &project {
                        Some(p) => println!(
                            "virtkit: no job history for a project matching {p:?} under {}",
                            history.display()
                        ),
                        None => println!("virtkit: no job history under {}", history.display()),
                    },
                }
                ExitCode::SUCCESS
            }
        },
        Cmd::Atop {
            target,
            summary,
            json,
            view,
            follow,
            interval,
        } => match atop_attach::classify(target.as_deref()) {
            Err(e) => fail(&e, 2),
            // A running VM: attach and record it — into the follow panel, or headless
            // for --summary. The two flags that only read a finished recording are
            // refused rather than silently attaching.
            Ok(atop_attach::Target::Live(entry)) => {
                // A VM already recording itself (`vk run --atop`) is read, never attached
                // to: a second sampler appending to the same share file would run two
                // recordings together. Its log is a recording still growing, so every
                // recorded-log flag works — only the default changes, to the live panel,
                // because a running VM was pointed at.
                // `is_file` then open is a check on a path the guest can write, which is
                // safe only because every reader below opens it with O_NOFOLLOW and
                // refuses anything but a regular file.
                if let Some(log) = entry.atop_log.as_deref().filter(|l| l.is_file()) {
                    // Named for the VM: the log sits in the run's archive directory, which
                    // would otherwise head the account `atop`.
                    read_recording(
                        log,
                        Some(&entry.label),
                        ReadAs::of(summary, json, view, follow, atop_view::can_draw()),
                    )
                } else if json || view {
                    fail(
                        &anyhow::anyhow!(
                            "{} ({}) is a running VM that is not recording itself — attach \
                             to it (no flag, or --summary), or give {} a recorded log's path",
                            entry.label,
                            entry
                                .project_dir
                                .as_deref()
                                .unwrap_or(&entry.state_dir)
                                .display(),
                            if json { "--json" } else { "--view" },
                        ),
                        2,
                    )
                } else {
                    match atop_attach::attach(&entry, interval, summary).await {
                        Err(e) => fail(&e, 1),
                        // Named for the VM: the log sits in the archive directory, which
                        // would otherwise head the account `atop`.
                        Ok(log) if summary => {
                            match atop_report::summarize_as(&log, Some(&entry.label)) {
                                Ok(report) => {
                                    eprintln!("virtkit: recorded -> {}", log.display());
                                    write_report(&report)
                                }
                                Err(e) => fail(&e, 1),
                            }
                        }
                        Ok(log) => {
                            // The recording outlives the attach; say how to read it again,
                            // off stdout so the path there still composes.
                            eprintln!(
                                "virtkit: recorded; read it back: vk atop {} --summary",
                                log.display()
                            );
                            write_path(&log)
                        }
                    }
                }
            }
            Ok(atop_attach::Target::Recorded(job)) => match atop::resolve(&ctx.cfg, &job) {
                // Exit 2 for a job nothing answers to, like `vk status`/`list`/`stop` — a
                // reader of the path must not be handed a success with no path.
                Err(e) => fail(&e, 2),
                // A recorded job names itself: its log sits in the directory the run made,
                // and it is finished, so no flag means its path rather than a panel.
                Ok(path) => {
                    read_recording(&path, None, ReadAs::of(summary, json, view, follow, false))
                }
            },
        },
        // Replace vk so the SSH session's exit status reaches the caller.
        Cmd::Ssh { state_dir, args } => match sshclient::exec_ssh(&state_dir, &args) {
            Ok(never) => match never {},
            Err(e) => fail(&e, 1),
        },
        Cmd::SshConfig { state_dir } => match sshclient::print_config(&state_dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
        // stdio↔socket splice for an SSH ProxyCommand; returns when either side closes.
        Cmd::Connect { addr } => match vk_core::forward::run_connect(&addr).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
        // `--stale`: report the VM's root-image freshness as a single scriptable token — a
        // directory-selected, host-side check that skips the agent probe. A raw address has
        // no build recipe, so it is rejected here.
        Cmd::Status {
            target,
            stale: true,
        } => match target.as_deref() {
            Some(s) if is_agent_addr(s) => fail(
                &anyhow::anyhow!("--stale selects a VM by directory, not a raw agent address"),
                2,
            ),
            other => match vms::resolve_one(other.map(Path::new)) {
                Ok(entry) => {
                    println!("{}", vms::freshness_all(&entry).as_str());
                    ExitCode::SUCCESS
                }
                // Resolution errors exit 2, matching the probe arm below and `vk list`/`vk stop`.
                Err(e) => fail(&e, 2),
            },
        },
        // Agent liveness probe: round-trip the status request (same client the boot readiness
        // wait uses) so a caller can check a VM is up with vk alone. The target is a directory
        // (default: cwd) resolved to its VM via the registry, or a raw agent address for plumbing.
        Cmd::Status {
            target,
            stale: false,
        } => {
            // Resolution/usage errors exit 2, matching `vk list`/`vk stop`; the code-1
            // result below is reserved for a resolved VM whose agent does not answer.
            let addr = match resolve_agent_addr(target.as_deref()) {
                Ok(a) => a,
                Err(e) => return fail(&e, 2),
            };
            match vk_core::status::get_status(&addr).await {
                Ok(status) => {
                    println!("{status}");
                    // Append OOM kills when the guest can report any.
                    if let Some(line) =
                        oomkills::line(oomkills::fetch(&addr, None).await.as_deref(), "raise --mem")
                    {
                        eprintln!("virtkit: {line}");
                    }
                    ExitCode::SUCCESS
                }
                // get_status yields a boxed std error; wrap it for the anyhow-typed reporter.
                Err(e) => fail(&anyhow::anyhow!("{e}"), 1),
            }
        }
        Cmd::Logs {
            target,
            service,
            lines,
            level,
            kernel,
            agent,
            guest,
            follow,
        } => {
            let mut sources = Vec::new();
            if kernel {
                sources.push(consolelog::Source::Kernel);
            }
            if agent {
                sources.push(consolelog::Source::Agent);
            }
            if guest {
                sources.push(consolelog::Source::Guest);
            }
            match console_log_path(target.as_deref(), service.as_deref()) {
                Ok(path) => {
                    match show_console_log(&path, target.as_deref(), &sources, level, lines, follow)
                        .await
                    {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(e) => fail(&e, 1),
                    }
                }
                Err(e) => fail(&e, 2),
            }
        }
        // Run a command in a live guest, reproducing its exit status as our own. The target
        // selects the VM the same way `vk status` does (directory via the registry, default cwd,
        // or a raw agent address); the command is the trailing `-- …` group.
        Cmd::Exec {
            target,
            service,
            background,
            clear_env,
            env,
            dir,
            tty,
            user,
            command,
        } => {
            // Resolution/usage errors exit 2, matching `vk status`/`vk list`/`vk stop` and
            // clap's own usage-error exit. Any vk-chosen code can collide with the remote
            // command's status vk reproduces below; 2 matches what the old CLI returned
            // when the positional address failed to parse.
            let addr = match resolve_exec_addr(target.as_deref(), service.as_deref()) {
                Ok(a) => a,
                Err(e) => return fail(&e, 2),
            };
            let mut command = command.into_iter();
            let cmd = command.next().expect("clap: required = true");
            let args: Vec<_> = command.collect();
            match exec::run(
                addr,
                background,
                clear_env,
                env,
                dir,
                tty,
                user,
                cmd,
                args,
                vk_core::exec::client::Stdin::Forward,
            )
            .await
            {
                Ok(result) => exec::exit(result),
                Err(e) => fail(&e, 1),
            }
        }
        // run_forward only returns on a bind error; otherwise it serves until the
        // process is killed (cleanup tears the detached child down).
        Cmd::Forward { listen, to } => {
            match vk_core::forward::run_forward(&listen, &to, None).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
        Cmd::Publish {
            action: Some(action),
            ..
        } => publish_action(action).await,
        // publish::run only returns on a bind error, like Cmd::Forward; the target VM is
        // selected the same way `vk exec` selects it.
        Cmd::Publish {
            target,
            service,
            listen,
            to,
            action: None,
        } => {
            // clap requires both without a subcommand.
            let (Some(listen), Some(to)) = (listen, to) else {
                return fail(&anyhow::anyhow!("--listen and --to are required"), 2);
            };
            let addr = match resolve_exec_addr(target.as_deref(), service.as_deref()) {
                Ok(a) => a,
                Err(e) => return fail(&e, 2),
            };
            match publish::run(&addr, &listen, &to).await {
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
        | Cmd::Paths { .. }
        | Cmd::Config { .. }
        | Cmd::Gc { .. }
        | Cmd::HelpAll
        | Cmd::Registry { .. }
        | Cmd::Switch { .. }
        | Cmd::Run { .. }
        | Cmd::Export { .. }
        | Cmd::Mkext { .. }
        | Cmd::Qcow2Verify { .. }
        | Cmd::MkextTar { .. }
        | Cmd::MkextOci { .. }
        | Cmd::Build { .. }
        | Cmd::OciPull { .. }
        | Cmd::DockerHash { .. }
        | Cmd::Fingerprint { .. }
        | Cmd::List { .. }
        | Cmd::Stop { .. }
        | Cmd::Reboot { .. }
        | Cmd::Update { .. }
        | Cmd::Service { .. } => {
            unreachable!()
        }
    }
}

/// The store `vk registry status`/`gc` work on: `--root` when given, else the one the
/// configuration puts the instruction cache in — so they report on and sweep the store
/// this `vk` is actually using, not the builtin default it may have been pointed away from.
fn store_root(cfg: &Config, root: &Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(r) = root {
        return Ok(r.clone());
    }
    match build::cache_store(cfg.build.cache_registry.as_deref())? {
        build::CacheStore::Dir(dir) => Ok(dir),
        // Which store a server keeps is the server's to know, not ours — but one on this
        // host is the common setup, so name the store it serves when neither its `--root`
        // nor its `--config` moved it. The hint never replaces the refusal: a default this
        // host cannot resolve degrades to naming where it comes from.
        build::CacheStore::Server(repo) => anyhow::bail!(
            "the instruction cache is the registry {repo}, whose store is on that host — \
             pass --root to name a store in this filesystem (a `vk-registry` on this host \
             with no --root and no `root` in its --config serves {})",
            vk_registry::default_root().map_or_else(
                |_| "$XDG_DATA_HOME/virtkit/registry".to_string(),
                |d| d.display().to_string()
            )
        ),
    }
}

fn fail(e: &anyhow::Error, code: i32) -> ExitCode {
    eprintln!("virtkit: error: {e:#}");
    exit_code(code)
}

/// Write a report to stdout and flush it, treating a closed pipe as the reader having seen
/// enough (`… | head`). `print!` panics there instead, and a report long enough to page is a
/// report somebody will pipe.
fn write_report(text: &str) -> ExitCode {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out
        .write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .err()
        .filter(|e| e.kind() != std::io::ErrorKind::BrokenPipe)
    {
        None => ExitCode::SUCCESS,
        Some(e) => fail(&anyhow::anyhow!(e), 1),
    }
}

/// Which read of a recording the `vk atop` flags ask for. `live` says the recording is still
/// growing (a VM recording itself), which is the only thing that changes the no-flag answer:
/// pointed at a running VM the panel is what "watch this" means, but only where one can be
/// drawn — otherwise the path is still the answer, so a no-flag read composes as ever.
#[derive(Debug, PartialEq)]
enum ReadAs {
    Summary,
    Json,
    Panel { follow: bool },
    Path,
}

impl ReadAs {
    fn of(summary: bool, json: bool, view: bool, follow: bool, live_panel: bool) -> ReadAs {
        if summary {
            ReadAs::Summary
        } else if json {
            ReadAs::Json
        } else if view || follow {
            ReadAs::Panel { follow }
        } else if live_panel {
            ReadAs::Panel { follow: true }
        } else {
            ReadAs::Path
        }
    }
}

/// Read one recording the way the `vk atop` flags ask: account it (`summary`), stream its
/// samples as JSON lines (`json`), walk it in the panel (`view`/`follow`), or — with no
/// flag — print its path, so it composes with whatever the operator reads logs with.
fn read_recording(path: &Path, named: Option<&str>, read: ReadAs) -> ExitCode {
    match read {
        ReadAs::Summary => match atop_report::summarize_as(path, named) {
            Ok(report) => write_report(&report),
            Err(e) => fail(&e, 1),
        },
        ReadAs::Json => match atoplog::read(path) {
            Ok(text) => {
                use std::io::Write;
                let parsed = atoplog::parse(&text);
                // On stderr, never on stdout: stdout is the JSON stream, and a
                // pipeline must not total a log that lost records as a whole one.
                if parsed.dropped > 0 {
                    eprintln!(
                        "virtkit: warning: {} — {} record(s) did not carry their \
                         label's fields and were left out",
                        path.display(),
                        parsed.dropped
                    );
                }
                let mut out = std::io::stdout().lock();
                match atoplog::write_json(&parsed.samples, &mut out).and_then(|()| out.flush()) {
                    Ok(()) => ExitCode::SUCCESS,
                    // A closed pipe (`| head`) is how a reader says it has seen enough.
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
                    Err(e) => fail(&anyhow::anyhow!(e), 1),
                }
            }
            Err(e) => fail(&e, 1),
        },
        ReadAs::Panel { follow } => match atop_view::view(path, follow) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
        ReadAs::Path => write_path(path),
    }
}

/// Write a path to stdout for another program to read: in its own bytes, as it was
/// recorded — a lossy rendering would send the reader to nothing.
fn write_path(path: &Path) -> ExitCode {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    let mut out = std::io::stdout().lock();
    match out
        .write_all(path.as_os_str().as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&anyhow::anyhow!(e), 1),
    }
}

/// True when `s` is a raw agent address (has a transport scheme) rather than a directory. Used
/// to tell an explicit `vsock-auto://…` from a directory selector — a bare path otherwise parses
/// as a `unix:` address, so scheme-matching is the only reliable split.
fn is_agent_addr(s: &str) -> bool {
    [
        "systemd://",
        "vsock://",
        "vsock-mux://",
        "vsock-auto://",
        "tcp://",
    ]
    .iter()
    .any(|scheme| s.starts_with(scheme))
}

/// The console log of the VM `target` selects (a project directory, default cwd), or of its
/// compose sibling `service`: `<state dir>/console.log` — the file the run's VMM writes the
/// serial console to. A sibling's runtime dir is what its exec address names.
fn console_log_path(target: Option<&Path>, service: Option<&str>) -> anyhow::Result<PathBuf> {
    use anyhow::Context;
    let dir = match vms::resolve_one(target) {
        Ok(entry) => match service {
            None => entry.state_dir,
            // `vsock-auto://<svc-dir>/vsock.sock:4444`: the directory is the socket's parent.
            Some(name) => match resolve_service_addr(&entry, name)? {
                SocketAddr::VsockAuto { path, .. } | SocketAddr::VsockMux { path, .. } => path
                    .parent()
                    .map(Path::to_path_buf)
                    .ok_or_else(|| anyhow::anyhow!("service {name:?}: odd exec address"))?,
                other => anyhow::bail!("service {name:?}: exec address {other} names no directory"),
            },
        },
        // The registry only lists live VMs, but the console of one that just died is exactly
        // what a reader reaches for, and `--state-dir` keeps it. Fall back to reading the
        // target as a state directory when it holds a console — but only for the primary's:
        // a sibling's directory is named by an exec address the registry no longer has.
        Err(e) => {
            let dir = match target {
                Some(t) => t.to_path_buf(),
                None => std::env::current_dir().context("resolving the current directory")?,
            };
            if service.is_none() && dir.join(run::CONSOLE_LOG).is_file() {
                dir
            } else {
                return Err(e);
            }
        }
    };
    Ok(dir.join(run::CONSOLE_LOG))
}

/// How often a follow looks for appended bytes, and how long a partial line may sit
/// unprinted before its newline arrives.
const FOLLOW_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// How often a follow asks whether its VM is still registered. Slower than [`FOLLOW_POLL`]
/// because the answer costs a walk over every registered VM's state dir, taking each one's
/// lock — a run starting up under the same directory races that.
const REGISTRY_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// The longest run of bytes a follow will hold waiting for a newline. A guest that never
/// writes one must not grow this process without bound; past it the partial line is printed
/// as it stands.
const MAX_PARTIAL_LINE: usize = 1 << 20;

/// Print `path`'s console lines from `sources` (all when empty) at least `level` severe, the
/// last `lines` of them (all when 0); with `follow`, keep printing what is appended until
/// Ctrl-C, until the VM this console belongs to leaves the registry, or until the reader
/// stops listening (`… | head`).
async fn show_console_log(
    path: &Path,
    target: Option<&Path>,
    sources: &[consolelog::Source],
    level: Option<consolelog::Level>,
    lines: usize,
    follow: bool,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::{BufRead, Write};
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    // Streamed, not slurped: a long-lived guest's console grows without bound and nothing
    // rotates it, while all that is printed is the last `lines` of it. Read a line at a time
    // as bytes — the console is written by whatever the guest runs, so it is not text — and
    // decoded lossily per line, for the reason `vk atop` reads its own log lossily: one
    // stray byte must not cost the reader the whole log.
    let mut reader = std::io::BufReader::new(&mut file);
    let mut offset = 0u64;
    let mut raw = Vec::new();
    let mut tail: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut out = std::io::stdout().lock();
    loop {
        raw.clear();
        let n = reader
            .read_until(b'\n', &mut raw)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        offset = offset.saturating_add(n as u64);
        let Some(line) = consolelog::select(&String::from_utf8_lossy(&raw), sources, level).next()
        else {
            continue;
        };
        // With no bound asked for, print as we go and hold nothing.
        if lines == 0 {
            if broken_pipe(writeln!(out, "{}", line.text))? {
                return Ok(());
            }
            continue;
        }
        if tail.len() == lines {
            tail.pop_front();
        }
        tail.push_back(line.text);
    }
    for l in &tail {
        if broken_pipe(writeln!(out, "{l}"))? {
            return Ok(());
        }
    }
    drop(tail);
    if !follow {
        return broken_pipe(out.flush()).map(|_| ());
    }
    // A fresh `ctrl_c()` future per iteration would miss a signal delivered while the loop
    // was reading or writing; one stream, polled every pass, does not.
    // Registering this replaces SIGINT's default disposition for the rest of the process,
    // and it is only observed at the top of the loop — so a Ctrl-C during a write to a
    // reader that has stopped draining waits for that write to complete.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("watching for Ctrl-C")?;
    let mut pending = String::new();
    let mut registry_check = std::time::Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(FOLLOW_POLL) => {}
            _ = interrupt.recv() => return Ok(()),
        }
        // The console outlives its VM, so the file going quiet says nothing: the registry is
        // what says the writer is gone for good. Checked on its own slower beat — resolving
        // walks and locks every registered VM's state dir, which a run starting up races
        // against.
        if registry_check.elapsed() >= REGISTRY_POLL {
            registry_check = std::time::Instant::now();
            if !vms::still_registered(target) {
                eprintln!("virtkit: the VM ended");
                return Ok(());
            }
        }
        // On the descriptor already held, not the path: a console swapped for another file
        // would otherwise be followed at an offset that means nothing in it.
        let Ok(len) = file.metadata().map(|m| m.len()) else {
            // A stat that failed says nothing about the file; look again next pass rather
            // than treat it as a truncation and re-print the whole log.
            continue;
        };
        if len < offset {
            // Truncated (a reboot in place rewrites it): start over from the top.
            offset = 0;
            pending.clear();
        }
        if len == offset {
            continue;
        }
        use std::io::{Read, Seek};
        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut chunk = Vec::new();
        file.read_to_end(&mut chunk)?;
        offset = offset.saturating_add(chunk.len() as u64);
        pending.push_str(&String::from_utf8_lossy(&chunk));
        // A whole line is what can be classified, so a torn tail waits for its newline —
        // unless the guest is writing one long enough to hold this process hostage.
        let complete = match pending.rfind('\n') {
            Some(i) => pending.drain(..=i).collect::<String>(),
            None if pending.len() >= MAX_PARTIAL_LINE => std::mem::take(&mut pending),
            None => continue,
        };
        for l in consolelog::select(&complete, sources, level) {
            if broken_pipe(writeln!(out, "{}", l.text))? {
                return Ok(());
            }
        }
        if broken_pipe(out.flush())? {
            return Ok(());
        }
    }
}

/// Return `Ok(true)` for a closed reader (`vk logs | head`), a normal command exit.
/// Propagate other write errors.
fn broken_pipe(r: std::io::Result<()>) -> anyhow::Result<bool> {
    match r {
        Ok(()) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Resolve a `vk status`/`vk exec` target to the agent address to dial: a raw `scheme://…`
/// address is used as-is; anything else (or nothing) is a directory selecting the VM through the
/// registry, defaulting to the current directory.
fn resolve_agent_addr(target: Option<&str>) -> anyhow::Result<SocketAddr> {
    match target {
        Some(s) if is_agent_addr(s) => s.parse::<SocketAddr>(),
        other => {
            let entry = vms::resolve_one(other.map(Path::new))?;
            entry.exec_addr.parse::<SocketAddr>()
        }
    }
}

/// Resolve a target VM (shared by `vk exec` and `vk publish`) to the agent address
/// to dial: the primary VM (as `resolve_agent_addr`), or — with `--service` — a
/// named sibling service of the VM selected by directory. A raw agent address can't
/// name a service (it isn't a registry entry).
/// Make each action's state dir absolute, so nothing downstream depends on the caller's
/// working directory.
fn resolve_state_dir(action: PublishAction) -> anyhow::Result<PublishAction> {
    let at = |dir: PathBuf| -> anyhow::Result<PathBuf> {
        std::fs::canonicalize(&dir).map_err(|e| anyhow::anyhow!("resolving {}: {e}", dir.display()))
    };
    Ok(match action {
        PublishAction::Ensure {
            state_dir,
            name,
            listen,
            to,
            service,
        } => PublishAction::Ensure {
            state_dir: at(state_dir)?,
            name,
            listen,
            to,
            service,
        },
        PublishAction::List { state_dir, json } => PublishAction::List {
            state_dir: at(state_dir)?,
            json,
        },
        PublishAction::Stop {
            state_dir,
            name,
            timeout,
        } => PublishAction::Stop {
            state_dir: at(state_dir)?,
            name,
            timeout,
        },
        // Already absolute: `ensure` resolved it before spawning this process.
        serve @ PublishAction::Serve { .. } => serve,
    })
}

fn resolve_exec_addr(target: Option<&str>, service: Option<&str>) -> anyhow::Result<SocketAddr> {
    let Some(svc) = service else {
        return resolve_agent_addr(target);
    };
    if target.is_some_and(is_agent_addr) {
        anyhow::bail!("--service selects a VM by directory, not a raw agent address");
    }
    let entry = vms::resolve_one(target.map(Path::new))?;
    resolve_service_addr(&entry, svc)
}

/// As [`resolve_exec_addr`], for a caller that already holds a path. Kept apart from the
/// `&str` form so a state dir that is not UTF-8 is an error here, rather than a `None`
/// that would quietly resolve the current directory's VM instead of the one asked for.
fn resolve_exec_addr_at(state_dir: &Path, service: Option<&str>) -> anyhow::Result<SocketAddr> {
    let Some(target) = state_dir.to_str() else {
        anyhow::bail!(
            "the state directory {} is not valid UTF-8",
            state_dir.display()
        );
    };
    resolve_exec_addr(Some(target), service)
}

/// The managed half of `vk publish`. Each action names its VM by state dir — the same
/// directory the publisher records live in — so `vk exec`'s directory resolution applies.
async fn publish_action(action: PublishAction) -> ExitCode {
    // Resolved once, here: `ensure` leaves a detached publisher that outlives this shell,
    // and a relative state dir would leave it depending on a working directory nobody
    // controls for both its own records and its VM lookup.
    let action = match resolve_state_dir(action) {
        Ok(a) => a,
        Err(e) => return fail(&e, 2),
    };
    match action {
        PublishAction::Ensure {
            state_dir,
            name,
            listen,
            to,
            service,
        } => {
            let addr = match resolve_exec_addr_at(&state_dir, service.as_deref()) {
                Ok(a) => a,
                Err(e) => return fail(&e, 2),
            };
            match publish::ensure(&state_dir, &name, &addr, &listen, &to, service.as_deref()).await
            {
                Ok(publish::Ensured::Started(e)) => write_report(&format!(
                    "published {} -> {} ({}, pid {})\n",
                    e.listen, e.to, e.name, e.pid
                )),
                Ok(publish::Ensured::AlreadyRunning(e)) => write_report(&format!(
                    "already published {} -> {} ({}, pid {})\n",
                    e.listen, e.to, e.name, e.pid
                )),
                // A taken address is the one failure a caller choosing addresses can act
                // on, so it gets a code of its own rather than the catch-all.
                Err(e) if e.downcast_ref::<publish::AddressInUse>().is_some() => fail(&e, 4),
                Err(e) => fail(&e, 1),
            }
        }
        PublishAction::List { state_dir, json } => match publish::list_report(&state_dir, json) {
            Ok(report) => write_report(&report),
            Err(e) => fail(&e, 1),
        },
        PublishAction::Stop {
            state_dir,
            name,
            timeout,
            // Off the runtime: `stop` waits on a lock with a blocking sleep, for as long as
            // `--timeout` allows, per publisher.
        } => match tokio::task::spawn_blocking(move || {
            publish::stop(
                &state_dir,
                name.as_deref(),
                std::time::Duration::from_secs(timeout),
            )
        })
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("the stop task failed: {e}")))
        {
            Ok((report, all_down)) => match write_report(&report) {
                ExitCode::SUCCESS if !all_down => exit_code(1),
                code => code,
            },
            Err(e) => fail(&e, 1),
        },
        PublishAction::Serve {
            state_dir,
            name,
            listen,
            to,
            service,
            listen_fd,
            lock_fd,
        } => {
            let addr = match resolve_exec_addr_at(&state_dir, service.as_deref()) {
                Ok(a) => a,
                Err(e) => return fail(&e, 2),
            };
            match publish::serve(&state_dir, &name, &addr, &listen, &to, listen_fd, lock_fd).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
    }
}

/// `vk publish --to`: a `SocketAddr` as-is, or — the one shape `SocketAddr::from_str`
/// rejects — a `tcp://host:port` whose host is a name rather than an IP literal.
/// Accepted here only so a typo is a clap usage error, not a live-connection
/// failure; resolving that name happens agent-side (`resolve_connect_target`), the
/// one place a compose sibling's hostname is actually reachable to resolve.
fn parse_publish_to(s: &str) -> Result<String, String> {
    let parse_err = match s.parse::<SocketAddr>() {
        // Re-rendered, not kept as typed: a managed publisher compares its target against
        // the recorded one, and two spellings of one address must not read as a conflict.
        Ok(parsed) => return Ok(parsed.to_string()),
        Err(e) => e,
    };
    match vk_core::addr::split_tcp_url(s) {
        // Lowercased like the SocketAddr branch is re-rendered: a hostname is
        // case-insensitive, and a managed publisher compares its target as a string.
        Some(Ok((host, port))) => Ok(format!("tcp://{}:{port}", host.to_ascii_lowercase())),
        Some(Err(e)) => Err(e.to_string()),
        None => Err(parse_err.to_string()),
    }
}

fn resolve_service_addr(entry: &vms::VmEntry, service: &str) -> anyhow::Result<SocketAddr> {
    let found = entry
        .services
        .iter()
        .find(|s| s.name == service)
        .ok_or_else(|| {
            let names: Vec<&str> = entry.services.iter().map(|s| s.name.as_str()).collect();
            let have = if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            };
            anyhow::anyhow!("no service {service:?} in this VM (services: {have})")
        })?;
    found.exec_addr.parse::<SocketAddr>()
}

/// Parse a switch `--registry-proxy` value `<sentinel-ip>=<host:port>`.
fn parse_registry_proxy(s: &str) -> anyhow::Result<(std::net::Ipv4Addr, std::net::SocketAddr)> {
    let (ip, addr) = s
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("registry-proxy {s:?}: want <ip>=<host:port>"))?;
    let ip = ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| anyhow::anyhow!("registry-proxy sentinel {ip:?}: {e}"))?;
    let addr = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("registry-proxy addr {addr:?}: {e}"))?;
    Ok((ip, addr))
}

/// Parse the repeatable `--source-egress <ip>;<cidr,cidr>;<name,name>` into a per-source
/// policy map. Each spec is a restricted allowlist (empty fields = deny), so an entry always
/// yields `Egress::restricted` — never unrestricted. The executor emits these; a malformed
/// one is a bug in that emission, so it fails the switch.
fn parse_source_egress(
    specs: &[String],
) -> anyhow::Result<std::collections::HashMap<std::net::Ipv4Addr, switch::Egress>> {
    let split = |s: &str| -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };
    let mut map = std::collections::HashMap::new();
    for spec in specs {
        let mut fields = spec.splitn(3, ';');
        let (ip, ips, names) = (
            fields.next().unwrap_or_default(),
            fields.next().unwrap_or_default(),
            fields.next().unwrap_or_default(),
        );
        let ip = ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("source-egress source ip {ip:?}: {e}"))?;
        let policy = switch::Egress::restricted(&split(ips), &split(names))
            .map_err(|e| anyhow::anyhow!("source-egress {spec:?}: {e}"))?;
        map.insert(ip, policy);
    }
    Ok(map)
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

/// Strip one matching pair of leading/trailing quotes (`'` or `"`) docker-compose's
/// env_file loader would strip — nothing past that: no escape-sequence decoding
/// (`\n`, octal, …), no `$VAR` expansion. Shared with `compose::load_dotenv`, whose
/// `.env` is the same convention.
///
/// The terminator is the first *unescaped* occurrence of the opening quote,
/// scanned left to right — not just the value's last byte — so `'it\'s here'`
/// round-trips to `it's here` (`\'`/`\"` unescape to a literal quote) instead of
/// being cut short at the embedded one; a backslash before anything else is kept
/// literal, same as compose's own scanner. A value with no opening quote,
/// unterminated quoting, or content trailing the close (`'abc'def`) is returned
/// unchanged — mismatched/malformed input is left as the raw string it always was,
/// not a hard error.
pub(crate) fn strip_env_quotes(v: &str) -> Cow<'_, str> {
    let quote = match v.as_bytes().first() {
        Some(&b @ (b'\'' | b'"')) => b as char,
        _ => return Cow::Borrowed(v),
    };

    let mut out = String::new();
    let mut escaped = false;
    for (i, c) in v.char_indices().skip(1) {
        if escaped {
            escaped = false;
            if c == quote {
                out.push(c);
            } else {
                out.push('\\');
                out.push(c);
            }
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == quote {
            return if i + c.len_utf8() == v.len() {
                Cow::Owned(out) // the terminator is the value's last char
            } else {
                Cow::Borrowed(v) // trailing content after the close
            };
        }
        out.push(c);
    }
    Cow::Borrowed(v) // unterminated
}

/// Collect the extra guest env from `--env-file`s (in order, later files win)
/// then `--env` flags (they win over every file), upserted into one list — the
/// same upsert the guest applies. `#` and blank lines in a file are skipped. A
/// file value wrapped in one matching pair of quotes has them stripped
/// (`strip_env_quotes`) — matching docker compose's `env_file:`, so a value that
/// itself starts with `$` (a reference a consumer *inside* the guest is meant to
/// expand, not vk) can be written `KEY='$OTHER'` without becoming a literal
/// quote-wrapped string in the guest's environment. A `--env` flag is never
/// quoted this way: the invoking shell already stripped any quoting from argv.
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
                Some((k, v)) => env_upsert(k, &strip_env_quotes(v)),
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

    #[test]
    fn journal_enabled_defaults_on_and_either_side_can_opt_out() {
        assert!(journal_enabled(false, false), "journaled by default");
        assert!(!journal_enabled(true, false), "--no-journal opts out");
        assert!(!journal_enabled(false, true), "[build] no_journal opts out");
        assert!(
            !journal_enabled(true, true),
            "both opting out still opts out"
        );
    }

    #[test]
    fn source_egress_specs_parse() {
        let m = parse_source_egress(&[
            "10.0.0.5;10.0.0.0/8,1.2.3.4:443;corp.com".to_string(),
            "10.0.0.6;;".to_string(), // deny-all: empty ip + name fields
        ])
        .unwrap();
        // A populated allowlist admits within it and refuses outside.
        let a = &m[&"10.0.0.5".parse().unwrap()];
        assert!(a.allows_host("corp.com") && a.contains_cidr("10.1.2.3/32").unwrap());
        assert!(!a.allows_host("evil.com"));
        // The empty spec is deny-all (restricted, not AllowAll).
        let b = &m[&"10.0.0.6".parse().unwrap()];
        assert!(!b.allows_host("corp.com") && !b.contains_cidr("10.0.0.0/8").unwrap());
        // A bad source ip is rejected.
        assert!(parse_source_egress(&["nope;;".to_string()]).is_err());
    }

    #[test]
    fn publish_to_normalizes_a_socket_addr() {
        assert_eq!(parse_publish_to("vsock://443").unwrap(), "vsock://443");
        // Re-rendered, so a managed publisher's recorded target is one spelling of the
        // address and comparing two `ensure` calls as strings is meaningful.
        assert_eq!(parse_publish_to("vsock://2:443").unwrap(), "vsock://2:443");
        for spelling in ["vsock://443", "tcp://127.0.0.1:80", "tcp://runner:443"] {
            let once = parse_publish_to(spelling).unwrap();
            assert_eq!(parse_publish_to(&once).unwrap(), once, "{spelling}");
        }
    }

    #[test]
    fn publish_to_accepts_a_tcp_hostname() {
        assert_eq!(
            parse_publish_to("tcp://runner:443").unwrap(),
            "tcp://runner:443"
        );
    }

    #[test]
    fn publish_to_rejects_tcp_with_no_port() {
        assert!(
            parse_publish_to("tcp://runner")
                .unwrap_err()
                .contains("<host>:<port>")
        );
    }

    #[test]
    fn publish_to_rejects_tcp_with_empty_host() {
        assert!(
            parse_publish_to("tcp://:443")
                .unwrap_err()
                .contains("non-empty host")
        );
    }

    #[test]
    fn publish_to_rejects_tcp_with_bad_port() {
        assert!(
            parse_publish_to("tcp://runner:notaport")
                .unwrap_err()
                .contains("invalid port")
        );
    }

    #[test]
    fn publish_to_keeps_a_non_tcp_scheme_error() {
        // vsock has no hostname notion to fall back to — the original parse error
        // (not a generic "invalid address") must surface, matching
        // `resolve_connect_target_keeps_a_non_tcp_scheme_error` in vk-core.
        assert!(
            parse_publish_to("vsock://not-a-port")
                .unwrap_err()
                .contains("port")
        );
    }

    // `vk paths --gitlab` must report the jobs root the executor actually uses:
    // Config::state_dir() (/var/lib/virtkit when unset), not the XDG dev default
    // `vk run` caches under.
    #[test]
    fn paths_report_gitlab_matches_jobctx() {
        let ctx =
            jobctx::JobCtx::new_for_job(config::Config::default(), "job-1".to_string()).unwrap();
        let report = paths_report(&config::Config::default(), true).unwrap();
        let jobs_root = ctx.job_dir.parent().unwrap();
        assert!(report.contains(&format!("jobs dir      {}", jobs_root.display())));
    }

    // The registry-store section names the store the configuration puts the build cache in
    // and which setting placed it there — and for a cache kept on a server, whose host it
    // is on rather than a local path nothing here writes to. `vk registry status`/`gc`
    // resolve the same store, so the report and the commands cannot disagree.
    #[test]
    fn paths_report_names_the_configured_registry_store() {
        let mut cfg = config::Config::default();
        let report = paths_report(&cfg, false).unwrap();
        assert!(
            report.contains(&format!(
                "registry store  {} (default:",
                vk_registry::default_root().unwrap().display()
            )),
            "{report}"
        );
        assert_eq!(
            store_root(&cfg, &None).unwrap(),
            vk_registry::default_root().unwrap()
        );

        cfg.build.cache_registry = Some("file:///srv/vk-cache".to_string());
        let report = paths_report(&cfg, false).unwrap();
        assert!(
            report.contains("registry store  /srv/vk-cache (`[build] cache_registry`)"),
            "{report}"
        );
        assert_eq!(
            store_root(&cfg, &None).unwrap(),
            PathBuf::from("/srv/vk-cache")
        );
        // `--root` still wins over the configured store
        let named = Some(PathBuf::from("/other"));
        assert_eq!(store_root(&cfg, &named).unwrap(), PathBuf::from("/other"));

        // caching off: the builtin store, named as the disabled setting it came from
        cfg.build.cache_registry = Some("none".to_string());
        let report = paths_report(&cfg, false).unwrap();
        assert!(report.contains("caching off"), "{report}");

        // a cache on a server: no path here, and the commands say so instead of sweeping
        // a local store the cache never writes to
        cfg.build.cache_registry = Some("127.0.0.1:5000".to_string());
        let report = paths_report(&cfg, false).unwrap();
        assert!(
            report.contains("registry store  on the host serving 127.0.0.1:5000"),
            "{report}"
        );
        let err = format!("{:#}", store_root(&cfg, &None).unwrap_err());
        assert!(
            err.contains("127.0.0.1:5000") && err.contains("--root"),
            "{err}"
        );
    }

    // `vk publish` CLI shape. The foreground form takes a positional target and requires
    // --listen/--to; the managed forms are subcommands that negate those requirements. A
    // positional that can look like a subcommand name is the part that silently changes
    // meaning when a flag is added, so every shape is pinned here.
    #[test]
    fn publish_cli_separates_the_foreground_form_from_its_subcommands() {
        let foreground = Cli::try_parse_from([
            "vk",
            "publish",
            "/proj",
            "--listen",
            "tcp://127.0.0.1:8443",
            "--to",
            "tcp://runner:443",
        ])
        .unwrap();
        let Cmd::Publish {
            target,
            listen,
            action,
            ..
        } = foreground.cmd
        else {
            panic!("expected publish")
        };
        assert_eq!(target.as_deref(), Some("/proj"));
        assert!(listen.is_some() && action.is_none());

        // No target: the current directory's VM, still the foreground form.
        let cli = Cli::try_parse_from([
            "vk",
            "publish",
            "--listen",
            "unix:///tmp/s",
            "--to",
            "vsock://80",
        ])
        .unwrap();
        assert!(matches!(cli.cmd, Cmd::Publish { target: None, .. }));

        // A subcommand takes its own state dir and does not want --listen/--to.
        let cli = Cli::try_parse_from([
            "vk",
            "publish",
            "ensure",
            "/proj",
            "--name",
            "web",
            "--listen",
            "tcp://127.0.0.1:1",
            "--to",
            "vsock://80",
        ])
        .unwrap();
        let Cmd::Publish {
            action: Some(PublishAction::Ensure { name, .. }),
            ..
        } = cli.cmd
        else {
            panic!("expected publish ensure")
        };
        assert_eq!(name, "web");
        assert!(matches!(
            Cli::try_parse_from(["vk", "publish", "list", "/proj"])
                .unwrap()
                .cmd,
            Cmd::Publish {
                action: Some(PublishAction::List { .. }),
                ..
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["vk", "publish", "stop", "/proj"])
                .unwrap()
                .cmd,
            Cmd::Publish {
                action: Some(PublishAction::Stop { .. }),
                ..
            }
        ));

        // Neither form on its own: a bare `vk publish` is missing what it needs.
        assert!(Cli::try_parse_from(["vk", "publish"]).is_err());
    }

    // `vk exec` CLI shape: the optional target precedes `--`, the command trails it,
    // and a command without `--` is rejected rather than swallowed as the target.
    #[test]
    fn exec_cli_takes_target_then_dashdash_command() {
        let cli = Cli::try_parse_from(["vk", "exec", "--", "ls", "-la"]).unwrap();
        let Cmd::Exec {
            target, command, ..
        } = cli.cmd
        else {
            panic!("expected Cmd::Exec")
        };
        assert_eq!(target, None);
        assert_eq!(command, ["ls", "-la"]);

        let cli = Cli::try_parse_from(["vk", "exec", "/proj", "--", "true"]).unwrap();
        let Cmd::Exec {
            target, command, ..
        } = cli.cmd
        else {
            panic!("expected Cmd::Exec")
        };
        assert_eq!(target.as_deref(), Some("/proj"));
        assert_eq!(command, ["true"]);

        let cli = Cli::try_parse_from(["vk", "exec", "--service", "db", "--", "true"]).unwrap();
        let Cmd::Exec {
            service, command, ..
        } = cli.cmd
        else {
            panic!("expected Cmd::Exec")
        };
        assert_eq!(service.as_deref(), Some("db"));
        assert_eq!(command, ["true"]);

        assert!(Cli::try_parse_from(["vk", "exec", "ls", "-la"]).is_err());
    }

    // `vk update` CLI shape: the version is an optional positional (absent = latest),
    // `-y` is a flag rather than the version, and `--check` (which installs nothing)
    // cannot be combined with the flag that skips the install prompt.
    #[test]
    fn update_cli_takes_optional_version_and_yes() {
        let cli = Cli::try_parse_from(["vk", "update"]).unwrap();
        let Cmd::Update {
            version,
            yes,
            check,
        } = cli.cmd
        else {
            panic!("expected Cmd::Update")
        };
        assert_eq!(version, None);
        assert!(!yes && !check);

        let cli = Cli::try_parse_from(["vk", "update", "-y", "v0.28.0"]).unwrap();
        let Cmd::Update { version, yes, .. } = cli.cmd else {
            panic!("expected Cmd::Update")
        };
        assert_eq!(version.as_deref(), Some("v0.28.0"));
        assert!(yes);

        let cli = Cli::try_parse_from(["vk", "update", "--check", "0.28.0"]).unwrap();
        let Cmd::Update { version, check, .. } = cli.cmd else {
            panic!("expected Cmd::Update")
        };
        assert_eq!(version.as_deref(), Some("0.28.0"));
        assert!(check);

        assert!(Cli::try_parse_from(["vk", "update", "--check", "--yes"]).is_err());
    }

    /// Reject an invalid minimum as a usage error, not a failed version check.
    #[test]
    fn check_cli_parses_the_minimum_version() {
        let cli = Cli::try_parse_from(["vk", "check"]).unwrap();
        let Cmd::Check {
            feature,
            min_version,
        } = cli.cmd
        else {
            panic!("expected Cmd::Check")
        };
        assert!(feature.is_empty() && min_version.is_none());

        let cli = Cli::try_parse_from(["vk", "check", "--min-version", "v0.45"]).unwrap();
        let Cmd::Check { min_version, .. } = cli.cmd else {
            panic!("expected Cmd::Check")
        };
        assert_eq!(
            min_version.map(|v| v.to_string()).as_deref(),
            Some("0.45.0")
        );

        assert!(Cli::try_parse_from(["vk", "check", "--min-version", "next"]).is_err());
    }

    /// An interval of zero would have the guest sampling without pause. Refused where every
    /// other bad value on the command line is — before anything dials a VM.
    #[test]
    fn atop_refuses_an_interval_of_zero() {
        assert!(Cli::try_parse_from(["vk", "atop", "--interval", "0"]).is_err());
        let cli = Cli::try_parse_from(["vk", "atop", "--interval", "30"]).unwrap();
        let Cmd::Atop { interval, .. } = cli.cmd else {
            panic!("expected Cmd::Atop")
        };
        assert_eq!(interval, 30);
    }

    /// A budget of no stages at all is not a build, so it is refused on the command line
    /// before anything boots — and in the flag's own vocabulary, not std's non-zero-type
    /// wording, which is the whole reason `parse_build_jobs` exists.
    #[test]
    fn build_jobs_refuses_zero() {
        let Err(err) = Cli::try_parse_from(["vk", "build", "--build-jobs", "0"]) else {
            panic!("--build-jobs 0 must be rejected")
        };
        assert!(err.to_string().contains("positive stage count"), "{err}");
        let cli = Cli::try_parse_from(["vk", "build", "--build-jobs", "4"]).unwrap();
        let Cmd::Build { build_jobs, .. } = cli.cmd else {
            panic!("expected Cmd::Build")
        };
        assert_eq!(build_jobs, NonZeroUsize::new(4));
    }

    /// `--atop` alone records at the default cadence and `--atop=SECS` picks one; the
    /// value only ever attaches with `=`, so `vk run --atop IMAGE` can never eat the
    /// image as an interval.
    #[test]
    fn run_atop_flag_takes_an_equals_value_or_defaults() {
        let atop_of = |argv: &[&str]| {
            let cli = Cli::try_parse_from(argv).unwrap();
            let Cmd::Run { atop, .. } = cli.cmd else {
                panic!("expected Cmd::Run")
            };
            atop
        };
        assert_eq!(atop_of(&["vk", "run", "debian:12"]), None);
        assert_eq!(atop_of(&["vk", "run", "--atop", "debian:12"]), Some(5));
        assert_eq!(atop_of(&["vk", "run", "--atop=30", "debian:12"]), Some(30));
        // Space-separated, the interval reads as a second image rather than a value.
        assert!(Cli::try_parse_from(["vk", "run", "--atop", "30", "debian:12"]).is_err());
        // A zero interval would have the guest sampling without pause.
        assert!(Cli::try_parse_from(["vk", "run", "--atop=0", "debian:12"]).is_err());
    }

    #[test]
    fn run_inactivity_timeout_needs_detach_refuses_shell_accepts_zero() {
        assert!(
            Cli::try_parse_from(["vk", "run", "--inactivity-timeout", "60", "debian:12"]).is_err()
        );
        // --shell returns before the keep-alive loop ever runs, so the flag would be
        // silently ignored rather than honored.
        assert!(
            Cli::try_parse_from([
                "vk",
                "run",
                "--detach",
                "--shell",
                "--inactivity-timeout",
                "60",
                "debian:12",
            ])
            .is_err()
        );

        let timeout_of = |value| {
            let cli = Cli::try_parse_from([
                "vk",
                "run",
                "--detach",
                "--inactivity-timeout",
                value,
                "debian:12",
            ])
            .unwrap();
            let Cmd::Run {
                inactivity_timeout, ..
            } = cli.cmd
            else {
                panic!("expected Cmd::Run")
            };
            inactivity_timeout
        };
        assert_eq!(timeout_of("60"), Some(60));
        assert_eq!(timeout_of("0"), Some(0));
    }

    /// Which read the `vk atop` flags ask for. The flags say the same thing about a finished
    /// recording and one still growing; only the no-flag case differs, because pointing at a
    /// VM that is recording itself is asking to watch it — but a panel needs a terminal, and
    /// without one the path is still the answer, so `LOG=$(vk atop <dir>)` keeps working.
    #[test]
    fn the_atop_flags_choose_one_read() {
        use ReadAs::*;
        // No flag: a path for a finished recording, the live panel for a growing one.
        assert_eq!(ReadAs::of(false, false, false, false, false), Path);
        assert_eq!(
            ReadAs::of(false, false, false, false, true),
            Panel { follow: true }
        );
        // Every explicit flag means the same thing either way.
        for live in [false, true] {
            assert_eq!(ReadAs::of(true, false, false, false, live), Summary);
            assert_eq!(ReadAs::of(false, true, false, false, live), Json);
            assert_eq!(
                ReadAs::of(false, false, true, false, live),
                Panel { follow: false }
            );
            assert_eq!(
                ReadAs::of(false, false, false, true, live),
                Panel { follow: true }
            );
            // clap lets --summary through beside the panel flags; accounting wins, so a
            // recording still growing is never left drawing a panel nobody asked for.
            assert_eq!(ReadAs::of(true, false, false, true, live), Summary);
            assert_eq!(ReadAs::of(true, false, true, false, live), Summary);
        }
    }

    #[test]
    fn exec_service_selects_named_sibling_and_rejects_raw_address() {
        let entry = vms::VmEntry {
            state_dir: PathBuf::from("/state/app"),
            project_dir: Some(PathBuf::from("/project")),
            pid: 1,
            label: "app".into(),
            exec_addr: "vsock-auto:///state/app/vsock.sock:4444".into(),
            ssh_addr: None,
            atop_log: None,
            created_secs: 0,
            vmm: None,
            vmm_pid: None,
            cpus: None,
            mem: None,
            nested: None,
            guest_ip: None,
            stale_recipe: None,
            services: vec![vms::ServiceEntry {
                name: "db".into(),
                exec_addr: "vsock-auto:///state/app/svc-db/vsock.sock:4444".into(),
                stale_recipe: None,
            }],
        };
        assert_eq!(
            resolve_service_addr(&entry, "db").unwrap(),
            "vsock-auto:///state/app/svc-db/vsock.sock:4444"
                .parse::<SocketAddr>()
                .unwrap()
        );

        let err = resolve_exec_addr(Some("vsock://3:4444"), Some("db")).unwrap_err();
        assert!(err.to_string().contains("not a raw agent address"), "{err}");
    }

    // A closed reader (`vk logs | head`) is the reader having seen enough, not this
    // command's failure; anything else is.
    #[test]
    fn a_closed_pipe_is_not_a_failure() {
        assert!(!broken_pipe(Ok(())).unwrap());
        assert!(broken_pipe(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))).unwrap());
        assert!(broken_pipe(Err(std::io::Error::from(std::io::ErrorKind::StorageFull))).is_err());
    }

    // `vk logs` on a directory the registry does not know reads its console anyway — a VM
    // that just exited is exactly the one whose console is wanted, and --state-dir keeps it.
    #[test]
    fn a_console_is_read_from_a_state_dir_the_registry_has_dropped() {
        let dir = std::env::temp_dir().join(format!("vk-logs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Nothing there yet: the registry's own error is what the caller gets.
        let err = console_log_path(Some(&dir), None).unwrap_err();
        assert!(err.to_string().contains("no running vk VM"), "{err}");
        // With a console in it, the directory is read as the state dir it is.
        std::fs::write(dir.join(run::CONSOLE_LOG), b"13:46:39 [INFO] hi\n").unwrap();
        assert_eq!(
            console_log_path(Some(&dir), None).unwrap(),
            dir.join(run::CONSOLE_LOG)
        );
        // A sibling's directory is named by an exec address the registry no longer has, so
        // the fallback does not apply to `--service`.
        assert!(console_log_path(Some(&dir), Some("db")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // `vk --help` is a curated list: a new Cmd variant must either join it
    // deliberately or carry #[command(hide = true)].
    #[test]
    fn everyday_help_is_curated() {
        let cmd = <Cli as clap::CommandFactory>::command();
        let visible: Vec<_> = cmd
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .map(|c| c.get_name().to_string())
            .collect();
        let mut sorted = visible.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            [
                "atop",
                "build",
                "check",
                "exec",
                "export",
                "gc",
                "list",
                "logs",
                "publish",
                "reboot",
                "run",
                "ssh",
                "ssh-config",
                "status",
                "stop",
                "update"
            ]
        );
    }

    // `-h` is a summary: a short line per command, per flag and per possible value, with
    // the detail in the doc comment's second paragraph (which clap shows as `--help`). A
    // one-paragraph doc comment is both, so it lands in `-h` in full — this is what
    // catches that. It also catches the opposite slip, an entry with no help at all.
    // Short is not the same as one rendered line: clap appends `[default: …]` and
    // `[possible values: …]`, and lays wide groups out on a second line regardless.
    #[test]
    fn help_summaries_stay_short() {
        // An 80-column terminal plus a little slack: the longest entry today is 81
        // (`vk oci-pull`'s about), so this catches a paragraph that slipped in without
        // failing on a summary that is merely close to the width.
        const LIMIT: usize = 84;

        // Every `-h` entry of `cmd` and, recursively, of its subcommands: the command's
        // own about, each argument's help, and each possible value's help.
        fn collect(path: &str, cmd: &clap::Command, out: &mut Vec<(String, Option<usize>)>) {
            out.push((format!("{path} about"), summary_len(cmd.get_about())));
            for arg in cmd.get_arguments() {
                let name = match arg.get_long() {
                    Some(long) => format!("--{long}"),
                    None => format!("<{}>", arg.get_id()),
                };
                out.push((format!("{path} {name}"), summary_len(arg.get_help())));
                // A bool flag carries synthetic true/false values clap never prints;
                // only an arg that takes a value gets a `[possible values: …]` line.
                let is_bool_flag = matches!(
                    arg.get_action(),
                    clap::ArgAction::SetTrue | clap::ArgAction::SetFalse
                );
                if !is_bool_flag {
                    for value in arg.get_possible_values() {
                        let what = format!("{path} {name}={}", value.get_name());
                        out.push((what, summary_len(value.get_help())));
                    }
                }
            }
            for sub in cmd.get_subcommands() {
                collect(&format!("{path} {}", sub.get_name()), sub, out);
            }
        }
        fn summary_len(text: Option<&clap::builder::StyledStr>) -> Option<usize> {
            Some(text?.to_string().chars().count())
        }

        let mut entries = Vec::new();
        collect(
            "vk",
            &<Cli as clap::CommandFactory>::command(),
            &mut entries,
        );
        let bad: Vec<_> = entries
            .into_iter()
            .filter_map(|(what, len)| match len {
                Some(len) if len > LIMIT => Some(format!("{what}: {len} chars")),
                None => Some(format!("{what}: no help")),
                Some(_) => None,
            })
            .collect();
        assert!(
            bad.is_empty(),
            "help entries over {LIMIT} chars or missing:\n  {}",
            bad.join("\n  ")
        );
    }

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

    // A file value wrapped in one matching pair of quotes has them stripped, docker
    // compose's env_file convention — so a `$VAR` a guest-side consumer means to expand
    // itself, not vk, survives instead of becoming a literal quote-wrapped string with
    // no leading `/` (TASK_TEMP_DIR='/workdir/.task/builder_$BUILDER_TAG' was landing as
    // a relative path named `'` before this). A `--env` flag is never quote-stripped:
    // the shell already handled its quoting before vk ever saw argv.
    #[test]
    fn extra_env_strips_one_matching_quote_pair_from_file_values() {
        let dir =
            std::env::temp_dir().join(format!("virtkit-envfile-quotes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("quoted.env");
        std::fs::write(
            &f,
            "SINGLE='/workdir/.task/builder_$BUILDER_TAG'\n\
             DOUBLE=\"two words\"\n\
             MISMATCHED='oops\"\n\
             LONE_QUOTE='\n\
             UNQUOTED=plain\n",
        )
        .unwrap();
        let env = collect_extra_env(
            std::slice::from_ref(&f),
            &["FLAG='kept-quoted'".to_string()],
        )
        .unwrap();
        assert_eq!(
            env,
            [
                ("SINGLE", "/workdir/.task/builder_$BUILDER_TAG"),
                ("DOUBLE", "two words"),
                ("MISMATCHED", "'oops\""),
                ("LONE_QUOTE", "'"),
                ("UNQUOTED", "plain"),
                ("FLAG", "'kept-quoted'"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The terminator is the first *unescaped* occurrence of the opening quote, not
    // just the value's last byte — so an embedded, escaped delimiter (`\'`/`\"`)
    // unescapes to a literal quote instead of ending the value early, matching
    // compose-go's own scanner; a backslash before anything else round-trips as-is.
    #[test]
    fn strip_env_quotes_unescapes_an_embedded_delimiter() {
        assert_eq!(strip_env_quotes(r"'it\'s here'").as_ref(), "it's here");
        assert_eq!(strip_env_quotes(r#""say \"hi\"""#).as_ref(), r#"say "hi""#);
        // a backslash not immediately before the quote char is kept literal
        assert_eq!(
            strip_env_quotes(r"'C:\Users\foo'").as_ref(),
            r"C:\Users\foo"
        );
        // content trailing the close, or no terminator at all: left fully raw
        assert_eq!(strip_env_quotes("'abc'def").as_ref(), "'abc'def");
        assert_eq!(
            strip_env_quotes(r"'unterminated\").as_ref(),
            r"'unterminated\"
        );
        assert_eq!(strip_env_quotes("''").as_ref(), "");
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
