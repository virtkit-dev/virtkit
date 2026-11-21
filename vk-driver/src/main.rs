//! gitlab-runner custom executor running each CI job in a throwaway libkrun microVM.
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

vk_hub_proto::version_mark!("vk");

mod activity;
mod admit;
mod atop;
mod atop_attach;
mod atop_report;
mod atop_view;
mod atoplog;
mod autogc;
mod blockrt;
mod bootdisk;
mod build;
mod cachelock;
mod check;
mod checkout;
mod compose;
mod config;
mod console;
mod consolelog;
mod cpio;
mod detach;
mod dev;
mod diskimg;
mod dockerhash;
mod dockerimg;
mod egress_report;
mod embed;
mod ensure;
mod exec;
mod executor;
mod ext4;
mod ext4_read;
mod fdpressure;
mod files;
mod fullvm;
mod gc;
mod gpt;
mod guestbuild;
mod health;
mod hostpolicy;
mod image;
mod initramfs;
mod iso9660;
mod jobctx;
mod jobevents;
mod libkrun_sys;
mod lifecycle;
mod local;
mod manager;
mod mkoci;
mod names;
mod net;
mod node;
mod numa;
mod oci;
mod oomkills;
mod outrelay;
mod ova;
mod pipeline;
mod prio;
mod publish;
mod qcow2;
mod qga;
mod quiet;
mod registry;
mod regproxy;
mod relay;
mod run;
mod rundirs;
mod schedule;
mod scratch;
mod services;
mod shell;
mod shutdown;
mod sites;
mod snapshot;
mod source;
mod spawn;
mod sshagent;
mod sshclient;
mod sshconf;
mod statefile;
mod switch;
mod task;
mod term;
mod termclean;
#[cfg(test)]
mod testutil;
mod tidy;
mod timing;
mod toolchain;
mod uefi;
mod units;
mod usage;
mod vm;
mod vmdk;
mod vmlist;
mod vmm;
mod vmmctl;
mod vmmthreads;
mod vms;
mod vmstate;
mod winbuild;
mod wincache;
mod wineval;
mod winexec;
mod winiso;
mod winsvc;
mod wintap;
mod workloads;
mod wsl;

use std::borrow::Cow;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vk_core::addr::SocketAddr;
use vk_peer::release_key;

use crate::config::Config;
use crate::jobctx::JobCtx;

/// This binary as `vk update` replaces it: the release asset `vk` ships as, and the
/// version this build was made from.
const VK: vk_selfupdate::Tool = vk_selfupdate::Tool {
    name: "vk",
    version: env!("CARGO_PKG_VERSION"),
};

/// clap value parser for `--cpus`: a number, or `host` for the host's CPU count
/// (`available_parallelism`, which honours cgroup/affinity limits). libkrun takes a flat
/// vCPU count, so this matches the host's logical CPUs; it does not replicate SMT/socket
/// topology (libkrun exposes no such knob).
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

/// Which program `vk release-key sign` signs a release of; the names `vk-hub release add
/// --program` takes.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
enum ReleaseProgram {
    /// vk, which nodes run
    Vk,
    /// vk-registry, which registries run
    VkRegistry,
    /// vk-gitlab, which GitLab relays run
    VkGitlab,
    /// vk-hub, which a hub updates itself to
    VkHub,
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
enum ReleaseKeyCmd {
    /// Make a release key, and print its public half
    Generate {
        /// Where to write the private key (never over an existing file)
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
    },
    /// Sign a release binary as a version, and print the signature
    Sign {
        /// The private key `generate` wrote
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        /// The version the binary's `--version` prints
        #[arg(long)]
        version: String,
        /// The program it is: vk, vk-registry, vk-gitlab or vk-hub
        #[arg(long, value_enum, default_value_t = ReleaseProgram::Vk)]
        program: ReleaseProgram,
        /// The binary
        binary: PathBuf,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Enroll this host with a hub, once
    ///
    /// Generates the node's ed25519 identity under <state_dir>/node/, refuses while `vk check`
    /// fails on KVM, the VMM or the guest kernel, and spends the single-use token that
    /// `vk-hub token create` printed. The hub pins the key; the host is then that node until
    /// <state_dir>/node/ is removed or the hub removes it.
    Join {
        /// The hub's base URL: https://host[:port] (http only to a loopback hub)
        hub: String,
        /// The enrollment token, or `-` to read it on stdin
        ///
        /// A token on the command line is visible to every local user in the process list
        /// while `join` runs; prefer `-` or --token-file.
        #[arg(
            long,
            required_unless_present = "token_file",
            conflicts_with = "token_file"
        )]
        token: Option<String>,
        /// Read the enrollment token from this file
        #[arg(long, value_name = "FILE")]
        token_file: Option<PathBuf>,
        /// Verify the hub against this PEM CA bundle alone
        ///
        /// The system's roots are then not trusted for the hub at all.
        #[arg(long, value_name = "FILE")]
        ca: Option<PathBuf>,
        /// Enroll a host already enrolled again, as a new node
        ///
        /// The old identity is moved aside to `<state_dir>/node.replaced-<time>`, not deleted;
        /// remove the old node from its hub with `vk-hub nodes remove <id>`.
        #[arg(long)]
        replace: bool,
        /// Set the host up for this user and enroll as it (root only)
        ///
        /// Creates the user when /etc/passwd has none, adds it to /dev/kvm's group, creates the
        /// state dir and hands it and what is in it to the user (not mounts, nor files also
        /// linked from outside it), checks the user can read the config, then enrolls as that
        /// user.
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
        /// Then run the node as a service, as `vk node service install` does
        ///
        /// A vk-node.service already running is stopped first, which waits for a managed
        /// runner's jobs, and started again on the new enrollment, or on the old one if the
        /// join fails with it still in place. Like `vk node run`, the join is refused where
        /// `[node] runner = "none"` but the host runs a gitlab-runner with the vk executor.
        #[arg(long)]
        service: bool,
        /// Join with --user although the host's CI jobs run as another user
        ///
        /// Without it, --user with an external runner is refused when the jobs' entries under
        /// the state dir belong to another user, or when gitlab-runner.service runs the vk
        /// custom executor as another: the node could not read the admission ledger and job
        /// dirs those jobs write.
        #[arg(long)]
        ignore_ci_user: bool,
    },
    /// Keep a session with the hub, and follow it, in the foreground
    ///
    /// Sends the host's inventory at the start and whenever it changes, and a heartbeat every
    /// few seconds; redials with backoff whenever the hub is unreachable. Sets the runner's
    /// concurrency every half minute, as `vk tune` would, within the hub's ceiling, and keeps
    /// what the hub asked across restarts. With `[node] runner = "managed"` it runs
    /// gitlab-runner too, and stops it taking jobs when the hub stops acquisition, drains or
    /// quarantines the node. With `[node] runner = "none"` the host runs no gitlab-runner and
    /// takes only the jobs the hub places; it refuses to start on a host that runs one with
    /// the vk executor. Unset, the mode is `"none"` where no gitlab-runner shows on the host,
    /// else `"external"`. SIGTERM or SIGINT stops it, after a managed runner has finished its
    /// jobs; a second one abandons them. Under systemd, use `KillMode=mixed`, so the stop
    /// reaches the node and not the runner. Exits 75 while another `vk node` holds the state
    /// dir.
    Run,
    /// internal: one placed job, which `vk node run` starts detached
    ///
    /// Runs the stages of the job journaled in DIR and writes how it ended there.
    #[command(hide = true)]
    Job {
        /// the job's journal dir under <state_dir>/node/jobs
        dir: PathBuf,
        /// the admission ledger entry it holds, inherited
        #[arg(long)]
        ledger_fd: Option<i32>,
    },
    /// Run `vk node run` as a systemd service
    ///
    /// As root, a system unit in /etc/systemd/system, running the node as root or as --user;
    /// as any other user, a user unit under
    /// $XDG_CONFIG_HOME/systemd/user (else ~/.config/systemd/user), with lingering enabled so
    /// it runs without a login.
    Service {
        #[command(subcommand)]
        cmd: NodeServiceCmd,
    },
}

#[derive(Subcommand)]
enum NodeServiceCmd {
    /// Write vk-node.service, enable it and start it
    ///
    /// The unit runs this vk, resolved, as the installed binary updates replace, with the
    /// config this command reads. Refuses on a host not enrolled, and where `[node] runner =
    /// "none"` but the host runs a gitlab-runner with the vk executor. Run again, it rewrites
    /// the unit and restarts the node if it is running.
    Install {
        /// Enable the unit without starting it
        #[arg(long)]
        no_start: bool,
        /// How long a stop waits for a managed runner's jobs before systemd kills them
        ///
        /// 90s, 10m, 1h, or a number of seconds; 0 waits for as long as they take.
        #[arg(long, value_name = "DURATION", default_value = node::service::DEFAULT_STOP_TIMEOUT,
              value_parser = dev::config::parse_duration)]
        stop_timeout: std::time::Duration,
        /// Run the node as this user, from a system unit (root only)
        ///
        /// The host must have been enrolled as that user, and the config must be readable
        /// by it. The user must be in /etc/passwd.
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
        /// Install although the host's CI jobs run as another user than the node would
        ///
        /// Without it, installing is refused as `vk node join --user` refuses joining.
        #[arg(long)]
        ignore_ci_user: bool,
    },
    /// Stop and disable vk-node.service and remove it, leaving the enrollment
    Uninstall,
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
    /// It owns the job's switch/forwards/VMM as tied children until cleanup
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
    /// The directory holds runner.ext4 + boot.kind, optionally runner.ext4.json, and its
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
    /// Put files in the build cache registry
    ///
    /// Each file is stored once, tagged by its digest (`sha256:<hex>`) and, with --dir, as
    /// `<dir>/<its name>`: the registry's WebDAV view serves it at `/dav/files/sha256/<hex>`
    /// and `/dav/files/<dir>/<name>`. A `FROM winiso:<file>@sha256:<hex>` stage whose ISO is
    /// not on the building host fetches it by digest, so install media need only be put once,
    /// by whoever holds them. A file is kept while it gets used, unless --ttl or
    /// --keep say otherwise; putting it again sets its retention anew, under its digest too.
    /// The build cache registry is --cache-registry, else `[build] cache_registry`, else this
    /// host's builtin store: a registry server, or a store on disk.
    Put {
        /// files to put
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// also name each file `<DIR>/<its name>`
        #[arg(long, value_name = "DIR")]
        dir: Option<String>,
        /// drop the files this long after the put (30m, 12h, 7d), used or not
        #[arg(long, value_name = "DURATION", conflicts_with = "keep", value_parser = files::parse_ttl)]
        ttl: Option<std::time::Duration>,
        /// keep the files however long they go unused
        #[arg(long)]
        keep: bool,
        /// the build cache registry [default: `[build] cache_registry`, else the builtin store]
        #[arg(long, value_name = "REPO")]
        cache_registry: Option<String>,
        /// reach the registry over plain HTTP
        #[arg(long)]
        cache_insecure: bool,
    },
    /// Fetch a file from the build cache registry
    ///
    /// The file is checked against its digest before it lands, and one fetched by digest
    /// must be the file of that digest. Without --output it lands in the current directory
    /// under its name — for a digest, the last component of the name it was put with — and
    /// never over a file already there.
    Get {
        /// `sha256:<hex>`, or `<dir>/<name>`
        reference: String,
        /// where to write it, over what is there [default: its name, in the current dir]
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// the build cache registry [default: `[build] cache_registry`, else the builtin store]
        #[arg(long, value_name = "REPO")]
        cache_registry: Option<String>,
        /// reach the registry over plain HTTP
        #[arg(long)]
        cache_insecure: bool,
    },
    // Serving a store over HTTP now lives in the standalone `vk-registry` daemon;
    // `vk` accesses its local filesystem store in-process (registry.rs `mod local`).
    /// Report a registry store's usage and content
    ///
    /// Stored bytes, space referenced by tags, uncompressed data in recorded completed
    /// stages, and each repository's tag count. Read-only — it creates no store.
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
    /// manifest references and the stale uploads (both after a grace window). A tag whose
    /// manifest is annotated `org.virtkit.retention=keep` is never dropped, and one
    /// annotated `org.virtkit.expires=<unix seconds>` is dropped once that time passes,
    /// used or not. It holds the store lock exclusive, briefly blocking concurrent pushers.
    Gc {
        /// store directory [default: the store the build cache uses]
        ///
        /// The build cache's store is `[build] cache_registry`, else
        /// $XDG_DATA_HOME/virtkit/registry.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// drop tags unused for more than this many days
        ///
        /// A tag whose manifest keeps or expires it (`org.virtkit.retention`,
        /// `org.virtkit.expires`) follows that instead.
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

/// `vk toolchain`: the release a project pins, and this host's copy of its artifacts.
#[derive(Subcommand)]
enum ToolchainCmd {
    /// Write the lock for a release: its artifacts, their digests and where to get them
    ///
    /// Resolves the release — the latest, or `--version` — reads each artifact's published
    /// digest, and writes `.virtkit/toolchain.lock` with the download URLs in order: the
    /// release itself, then each `--mirror` given. Re-running with another version rewrites
    /// the file; nothing else edits it. Track it in git.
    Lock {
        /// the release to pin, `0.60.0` or `v0.60.0` [default: the latest release]
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
        /// a mirror serving `<URL>/v<version>/<artifact>`, tried after the release
        ///
        /// Repeatable; the order given is the order `install` tries them in.
        #[arg(long, value_name = "URL")]
        mirror: Vec<String>,
        /// artifact to lock, repeatable [default: every artifact a release publishes]
        #[arg(long, value_name = "NAME")]
        artifact: Vec<String>,
        /// the lock file to write [default: `.virtkit/toolchain.lock` in this checkout]
        #[arg(long, value_name = "FILE")]
        lock: Option<PathBuf>,
    },
    /// Put the locked artifacts of this platform in the toolchain cache
    ///
    /// Fetches each one into the cache — `$VIRTKIT_TOOLCHAIN_CACHE` when it is set, else
    /// `$XDG_CACHE_HOME/virtkit/toolchain` or `~/.cache/virtkit/toolchain` — under the
    /// locked version, verifying the locked digest and publishing atomically; one already
    /// there with the right digest is left alone, so a re-run downloads nothing. Never
    /// touches the `vk` on PATH.
    Install {
        /// artifact to install, repeatable [default: every artifact the lock covers]
        #[arg(long, value_name = "NAME")]
        artifact: Vec<String>,
        /// fail rather than download; only what the cache already holds counts
        #[arg(long)]
        offline: bool,
        /// the lock file to read [default: `.virtkit/toolchain.lock` in this checkout]
        #[arg(long, value_name = "FILE")]
        lock: Option<PathBuf>,
    },
    /// Print the lock's version, artifact paths and digests for a script to consume
    ///
    /// `VIRTKIT_VERSION`, then `VIRTKIT_VK`, `VIRTKIT_VK_SHA256`, `VIRTKIT_VK_AGENT`, …
    /// A path is empty until that artifact is installed. The shell form assigns without
    /// `export`, for `eval "$(vk toolchain export)"`.
    Export {
        /// how to print it
        #[arg(long, value_enum, default_value = "shell")]
        format: toolchain::Format,
        /// the lock file to read [default: `.virtkit/toolchain.lock` in this checkout]
        #[arg(long, value_name = "FILE")]
        lock: Option<PathBuf>,
    },
    /// Report what is locked, what is installed, and which `vk` is answering
    ///
    /// One line per artifact: locked for this platform or not, installed in the cache,
    /// or installed with contents that no longer match the lock. Then the lock's version,
    /// the cache it resolves to, and where the `vk` running this stands against it. Reads
    /// only — `vk toolchain install` is what fetches anything.
    Status {
        /// the lock file to read [default: `.virtkit/toolchain.lock` in this checkout]
        #[arg(long, value_name = "FILE")]
        lock: Option<PathBuf>,
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
        /// have this compose sibling's agent dial instead of the primary's
        ///
        /// By name: the service part of a `vk list` row (`db` in `shop/db`); the service must
        /// be running. Reported as `via` by `vk publish list --json`, and as `@NAME` in
        /// `vk list`'s PUBLISHED.
        #[arg(long, visible_alias = "service", value_name = "NAME")]
        via: Option<String>,
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
        /// have this compose sibling's agent dial instead of the primary's
        // Keep the alias hidden for this internal command; another build of `ensure` may
        // still spawn it with the old spelling.
        #[arg(long, alias = "service", value_name = "NAME")]
        via: Option<String>,
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
    /// One line per check, with the sections this config never enabled named together at
    /// the end; exits non-zero if any fails.
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
        /// apply the steps a failed check knows how to take
        ///
        /// Prints them and asks before running any, so it needs a terminal; the checks
        /// are then reported again, leaving only what is still outstanding. Today only
        /// the kvm check offers steps, and only on a WSL2 distro. A version-only check
        /// (--min-version without --feature) has nothing to apply.
        #[arg(long)]
        fix: bool,
    },
    /// Reclaim what virtkit can recreate and nothing is using
    ///
    /// Evicts materialized bases (`<state_dir>/{registry, docker, build}`) no VM is using,
    /// removes GitLab host checkouts no job is using, and drops unreferenced registry
    /// chunks and the staging dirs of builds that died — the bases and checkouts once idle
    /// past the threshold. Collects the local build cache: entries unused past `[gc]
    /// build_cache_retention_days`, then the least recently used until it fits `[gc]
    /// build_cache_max`, never one a running build reads. Removes the boot images of `vk dev`
    /// environments stopped past `[gc] dev_image_idle_days`, the root images `vk run
    /// --state-dir` built into dirs unused past `[gc] run_image_idle_days`, and the scratch dirs
    /// of runs killed by a signal. `vk run` (not of a UEFI bundle), `vk build`, `vk export`,
    /// `vk registry pull` and a booting `vk dev` start a pass in the background once
    /// `[gc] interval_hours` have passed, and sooner under `[gc] min_free`. Then prints one
    /// summary: what each category freed, what was kept and why, and the free space before and
    /// after.
    #[command(display_order = 4)]
    Gc {
        /// Idle threshold in seconds; `0` reclaims every entry not currently in use
        ///
        /// Applies to images and checkouts alike, overriding both of their settings. Default:
        /// the config's `image_cache_idle_secs` and `checkout_cache_idle_secs` (30 min each).
        #[arg(long, value_name = "SECS", conflicts_with = "all_unused")]
        idle_secs: Option<u64>,
        /// Report what would be reclaimed without removing anything
        #[arg(long)]
        dry_run: bool,
        /// Ignore the configured retention and idle windows
        ///
        /// Everything above that nothing uses now goes. What keeps an entry safe still holds:
        /// a lock or a reference held by a VM, job or build, the 10 minutes an image or a
        /// checkout is left after its last use, and the hour a build-cache entry, a dev
        /// environment's images or a run state dir's root image is.
        #[arg(long)]
        all_unused: bool,
        /// Run as the background pass a command starts (`[gc] auto`)
        ///
        /// Waits for no lock another holds, and goes past the idle windows while the data
        /// dir's filesystem is under `[gc] min_free`.
        #[arg(long, hide = true, conflicts_with_all = ["dry_run", "all_unused", "idle_secs"])]
        auto: bool,
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
    /// Measures the memory its jobs have committed and leaves the concurrency that fits, capped
    /// at `[executor.schedule] max_concurrency`, where the root-side `vk-runnerctl` applies it.
    /// Run from a timer every half minute or so (see the GitLab CI guide), so it is hidden from
    /// the everyday help like `vk gitlab`. Needs `[executor.schedule] mem_budget` or
    /// `max_concurrency`, except on a fleet node, which has a budget by default.
    #[command(hide = true)]
    Tune,
    /// plumbing: what a VM's guest did on the network, for a local UI
    ///
    /// The refusals and the contacts its switch recorded in its dir — a CI job's, or the
    /// state dir of a `vk run --audit-egress` — as a job's trace reports them; nothing when
    /// it recorded none.
    #[command(hide = true)]
    EgressReport {
        /// a CI job's dir, or a `vk run`'s state dir
        dir: PathBuf,
    },
    /// plumbing: the VMs running on this host, as JSON for a local UI
    ///
    /// One line of JSON: pinned runs and dev environments from the registry `vk list` reads,
    /// and CI jobs whose supervisor is alive, each with what its process tree holds on the
    /// host. Its fields are only ever added to.
    #[command(hide = true)]
    Workloads {
        /// keep printing the list each time it changes, a line at a time, until stdin closes
        ///
        /// Stdin is expected to be a pipe the reader holds open: the watch ends when it closes.
        #[arg(long)]
        watch: bool,
        /// how often to look again, with --watch
        #[arg(long, value_name = "SECS", default_value_t = 2,
              value_parser = clap::value_parser!(u64).range(1..))]
        interval_secs: u64,
        /// how often to measure what each VM holds
        ///
        /// A walk of every page table of every process of every VM; a VM that appears is
        /// measured at once.
        #[arg(long, value_name = "SECS", default_value_t = 30,
              value_parser = clap::value_parser!(u64).range(1..))]
        mem_secs: u64,
    },
    /// Keys that sign vk, vk-registry and vk-gitlab releases for a fleet (experimental)
    ///
    /// `generate` makes a key and prints the public half for `[node] release_keys` (or a
    /// vk-registry's or vk-gitlab's `[hub] release_keys`); `sign` signs a binary as a version,
    /// for `vk-hub release add --signature`. Keep the key off the hub: a signature is what a
    /// node, registry or relay trusts when the hub itself might not be.
    #[command(hide = true)]
    ReleaseKey {
        #[command(subcommand)]
        cmd: ReleaseKeyCmd,
    },
    /// Membership in a fleet managed by a vk-hub (experimental)
    ///
    /// `join` enrolls this host with a hub; `run` then keeps a session with it, reporting the
    /// host's inventory and a heartbeat, and follows what the hub asks within local policy;
    /// `service install` runs it under systemd.
    #[command(hide = true)]
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
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
        /// network for the build's RUN steps: `all` (unrestricted), `declared` or `none`
        ///
        /// A stage may declare the egress its RUN steps need with a `# vk: allow-ip=CIDR,…
        /// allow-name=SUFFIX,…` line above its FROM; they then reach only that, under any
        /// setting but `none`. `declared` gives a stage that declares nothing no network.
        #[arg(
            long = "build-net",
            default_value = "all",
            value_name = "all|declared|none",
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
        /// A suffix is e.g. `crates.io`, dot-anchored; a URL, a pattern, a port or a trailing
        /// dot is refused, as for `vk run --allow-name`. Repeatable; any --build-allow-* flag
        /// turns filtering on.
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
        /// keep what the RUN steps contacted and were refused in this directory
        ///
        /// Set internally by a fleet node's CI tools build, which reads it afterwards.
        #[arg(long = "egress-record", value_name = "DIR", hide = true)]
        egress_record: Option<PathBuf>,
        /// restores from the instruction cache are allowed, but nothing may build
        ///
        /// A cache miss aborts with exit code 3, so scripts can branch cached-vs-cold without
        /// paying for a build. With a trailing command, a command that itself exits 3 looks
        /// the same.
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
        /// Windows: install each `FROM winiso:` stage again and rebuild every step on it
        ///
        /// For an evaluation image past or near its end. The new install is cached under new
        /// keys; the old one and its layers stay, so bundles built on them keep working until
        /// they are rebuilt.
        #[arg(long, help_heading = "What to build")]
        reinstall: bool,
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
        /// Splice at most N connections concurrently, closing any beyond
        #[arg(long, value_name = "N")]
        max_conns: Option<std::num::NonZeroUsize>,
    },
    /// Work in the environment a project's .virtkit/config.toml describes
    ///
    /// Finds `.virtkit/config.toml` in the current directory or above it, no further than
    /// the git checkout's root, layers `.virtkit/local.toml` over it, and resolves the
    /// result against this host: which compose service, image or Dockerfile target, what it
    /// mounts and publishes, who you are inside it, where its state directory lives. Every
    /// key is checked; one virtkit does not know is an error rather than a silent omission.
    #[command(display_order = 11)]
    Dev(crate::dev::cli::Dev),
    /// SSH into a VM booted with `run --ssh-client`
    ///
    /// Runs the system ssh against the client setup in the VM's state dir — that run's
    /// config, key and alias — so none of your own identities are involved and there is
    /// nothing to configure. Arguments after the VM reach ssh as given:
    /// `vk ssh NAME -- uname -a`.
    Ssh {
        /// the VM: its name, pid, project directory or state directory
        #[arg(value_name = "REF")]
        target: std::ffi::OsString,
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
        /// the VM: its name, pid, project directory or state directory
        #[arg(value_name = "REF")]
        target: std::ffi::OsString,
    },
    /// plumbing: apply a built-in host-command policy, then exec what it allows
    ///
    /// `[dev.host] git-gui = true` generates a wrapper that runs this, so the guest's exec
    /// channel reaches the host only through it. The policy allows `gitk` and `git gui` with
    /// an allowlist of rev-list options, refuses anything else with exit 126, and rebuilds
    /// the environment from the serving user's passwd entry plus the display and locale
    /// settings.
    #[command(name = "host-policy", hide = true)]
    HostPolicy {
        /// which policy to apply; `git-gui` is the only one
        policy: String,
        /// the environment's workspace root — the command must run inside it
        #[arg(long)]
        workspace: PathBuf,
        /// the command the guest asked for, after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// plumbing: a guest's `vk-agent exec --service` or `build`, over its host channel
    ///
    /// A CI job VM's or a `vk run --compose` primary's channel runs every request through
    /// this: a form `--allow` names runs — `vk exec --service NAME … -- CMD` into one of
    /// that VM's own services for `exec`, `vk build … --as NAME` with a context on stdin for
    /// `build`, under the `--config` given before the `--` — and anything else is refused
    /// with exit 2. The name, like `service-exec.log`, predates `build`.
    #[command(name = "service-exec", hide = true)]
    ServiceExec {
        /// the job's or run's directory, whose `svc-<name>` dirs are its services
        dir: PathBuf,
        /// the forms the VM may ask for, comma-separated: exec, build [default: exec]
        #[arg(long, value_name = "FORMS")]
        allow: Option<vm::HostForms>,
        /// the guest's request, `vk` first, after `--`
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// plumbing: remove a `vk-agent build` context once its build's process is gone
    ///
    /// Started by the build, in a session of its own, with the job's directory of build
    /// contexts on descriptor 4 and the job's build lock on descriptor 3; waits for stdin to
    /// close.
    #[command(name = "guest-build-reap", hide = true)]
    GuestBuildReap {
        /// the context's name in the directory of build contexts
        name: std::ffi::OsString,
    },
    /// plumbing: splice stdio to the target address — the SSH `ProxyCommand` shape
    ///
    /// ssh hands its protocol stream on stdio; we relay it to the guest's ssh-serve (`run
    /// --ssh` prints the full invocation). Addresses: a unix path, vsock-auto://<path>:<port>
    /// (the VMM's per-port socket), tcp://host:port.
    #[command(hide = true)]
    Connect {
        /// Target address to dial
        addr: SocketAddr,
    },
    /// Probe a running VM's guest agent
    ///
    /// Prints its reply, or exits non-zero if it does not answer — a liveness check that
    /// exercises the agent protocol, stronger than a socket stat. Selects the VM whose project
    /// is the current directory by default; pass a name, a pid or a directory to select
    /// another. A raw agent address (`vsock-auto://DIR/vsock.sock:4444`) probes it directly,
    /// for plumbing that already knows the socket.
    #[command(display_order = 7)]
    Status {
        /// which VM: a name, a pid, a project directory, or a raw agent address
        ///
        /// A REF as `vk list` prints it (`NAME/SERVICE` for a compose service; default: the
        /// current directory's VM); a raw agent address (`scheme://…`) is dialed directly.
        #[arg(value_name = "REF")]
        target: Option<String>,
        /// print whether the VM's root image is `fresh`, `stale` or `unknown`
        ///
        /// A single scriptable token; `stale` means a fresh `vk run` would rebuild it. Skips
        /// the agent probe but may resolve base image digests over the network; acts on a
        /// whole VM, so it takes neither `NAME/SERVICE` nor a raw address (no build recipe).
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
        /// which VM: a name, a pid or a project directory (default: the current directory's)
        ///
        /// `NAME/SERVICE` reads a compose service's console. After the VM has exited, its
        /// name, or its state directory, still leads to the console it left.
        #[arg(value_name = "REF")]
        target: Option<PathBuf>,
        /// read this compose sibling's console instead of the primary's
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// show the last N lines (after filtering); 0 streams the whole log
        ///
        /// The log is read back from its end and only N lines are held — a line over a MiB
        /// counts as one a MiB — so a bound costs no more on a console that has grown for days
        /// than on a fresh one, unless a filter matches rarely and reads further back.
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
        /// plumbing: read the console in the state dir or CI job dir TARGET names, exactly
        ///
        /// Without it a directory also selects the VM whose project lies under it, for a
        /// person at a shell; a program that has the dir in hand wants that dir's console only.
        #[arg(long, hide = true, requires = "target", conflicts_with_all = ["service", "follow"])]
        exact: bool,
    },
    /// Run a command in a live guest, or open an interactive shell in it
    ///
    /// Goes over the guest's agent exec channel, as `--user` in `--dir`. Reuses the same
    /// client the in-guest agent embeds, so a host reaches a running VM with `vk` alone,
    /// no separate `vk-agent` binary. `vk` exits with the command's own status. The
    /// command goes after `--`; the optional token before it selects the VM.
    ///
    /// A Windows (UEFI) guest runs it through its qemu-ga, as SYSTEM, its arguments passed
    /// verbatim; a cmd built-in such as `call` expands `%` in them again.
    #[command(arg_required_else_help = true, display_order = 3)]
    Exec {
        /// which VM: a name, a pid, a project directory, or a raw agent address
        ///
        /// A REF as `vk list` prints it (`NAME/SERVICE` for a compose service; default: the
        /// current directory's VM); a raw agent address (`scheme://…`) is dialed directly.
        #[arg(value_name = "REF")]
        target: Option<String>,
        /// run in this compose sibling service instead of the primary
        ///
        /// By name: the service part of a `vk list` row (`db` in `shop/db`); the service must
        /// be running.
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
        /// Run the remote process as this user or uid (drops uid/gid/groups)
        ///
        /// A name, a uid, or either with an explicit group: `uid:gid`, `name:group`.
        #[arg(long, value_name = "USER")]
        user: Option<String>,
        /// Command to run and its arguments, after `--` (e.g. `vk exec -- ls -la`)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Attach to the serial console of a live Windows (UEFI) guest
    ///
    /// Windows serves its Special Administration Console (SAC) there: `cmd` opens a command
    /// channel, `ch -si 1` switches to it, then log in. Keystrokes are paced (3 bytes every
    /// 180 ms) because SAC drops what arrives faster; Ctrl-] leaves. Input may be piped. It
    /// survives guest reboots. One console at a time: the newest wins, and the one it replaces
    /// ends.
    #[command(display_order = 3)]
    Console {
        /// which VM: a name, a pid or a directory (default: the current one's)
        #[arg(value_name = "REF")]
        target: Option<String>,
    },
    /// Copy a file into or out of a live Windows (UEFI) guest
    ///
    /// Goes through the guest's qemu-ga, as SYSTEM. The guest side is the path after a
    /// leading `:` (`vk cp setup.ps1 :C:/vk/setup.ps1`, `vk cp :C:/Windows/Panther/setupact.log
    /// .`); exactly one side is the guest's, and it must be a file's full path, not a
    /// directory. A host destination that is a directory gets the guest file's name.
    #[command(display_order = 3)]
    Cp {
        /// the file to copy: a host path, or `:` and a guest path
        source: String,
        /// where to copy it: a host path, or `:` and a guest path
        destination: String,
        /// which VM: a name, a pid or a directory (default: the current one's)
        #[arg(long, value_name = "REF")]
        target: Option<String>,
        /// copy to or from this Windows compose service instead, as `vk exec --service` does
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
    },
    /// Publish a port on the guest's own network to the host
    ///
    /// Accepts connections on `--listen` and, for each one, asks the target VM's agent —
    /// over the same exec control channel `vk exec`/`vk status` use — to dial `--to` and
    /// splice raw bytes back, reusing that already-open channel for the relay. The VM is
    /// selected as `vk exec` selects it (a name, a pid, a directory or a raw agent address;
    /// a compose service with `NAME/SERVICE` or `--via`), and `--to` can name any
    /// address that VM's own network reaches — a LAN peer's own compose hostname included,
    /// resolved through that VM's own DNS:
    /// `vk publish app/devcontainer --listen tcp://127.0.0.1:8443 --to tcp://runner:443`.
    ///
    /// That form runs in the foreground and goes with the terminal; `vk publish ensure` and
    /// its siblings keep one running in the background instead.
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Publish {
        /// which VM's agent to ask: a name, a pid, a project directory, or a raw agent address
        ///
        /// A REF as `vk list` prints it (`NAME/SERVICE` for a compose service; default: the
        /// current directory's VM); a raw agent address (`scheme://…`) is dialed directly.
        #[arg(value_name = "REF")]
        target: Option<String>,
        /// have this compose sibling's agent dial instead of the primary's
        ///
        /// By name: the service part of a `vk list` row (`db` in `shop/db`); the service must
        /// be running. This form
        /// records nothing, so nothing reports it; `vk publish ensure --via` is reported as
        /// `via`.
        #[arg(long, visible_alias = "service", value_name = "NAME")]
        via: Option<String>,
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
    /// viewer can be pointed at it (`zstdless $(vk atop 42137)`: a finished job's log is
    /// zstd-compressed).
    #[command(display_order = 10)]
    Atop {
        /// A running VM's name or directory, or a recorded job
        ///
        /// A VM's name, or a directory, selects a running VM as `vk exec` does (default: the
        /// current directory); a name wins over a recorded job spelled the same, and over a
        /// directory without a `./`. A recorded job is a job id, any part of a recorded job's directory name (its project
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
    /// Accepts the qemu vhost transport on each VM's per-port guest socket, answers
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
        /// address leased without a router or DNS server (repeatable)
        ///
        /// A port of a guest whose eth0 is a host tap, which routes through the tap.
        #[arg(long = "unrouted", value_name = "IP")]
        unrouted: Vec<std::net::Ipv4Addr>,
        /// egress allowlist — destination IPv4 CIDR for direct (non-proxied) egress
        ///
        /// Optionally port-scoped as CIDR:port (repeatable). With no --allow-ip/--allow-name,
        /// egress is unrestricted.
        #[arg(long = "allow-ip", value_name = "CIDR[:PORT]")]
        allow_ip: Vec<String>,
        /// egress allowlist — DNS suffix the guest may resolve and reach (repeatable)
        ///
        /// A suffix is e.g. `corp.example.com`, dot-anchored; a URL, a pattern, a port or a
        /// trailing dot is refused, as for `vk run --allow-name`.
        #[arg(long = "allow-name", value_name = "SUFFIX")]
        allow_name: Vec<String>,
        /// force allowlist mode even with no --allow-ip/--allow-name
        ///
        /// An empty allowlist then denies everything instead of leaving egress unrestricted
        /// (set internally by the gitlab executor when a job configures egress).
        #[arg(long = "egress-restrict")]
        egress_restrict: bool,
        /// take the egress allowlist from this JSON file, and follow its edits
        ///
        /// `{"allow_ip": [...], "allow_name": [...]}`, always restricted (empty lists deny
        /// everything). Reread when it changes, so a running guest's allowlist can be edited
        /// in place; a missing or malformed file keeps the one in force. Set internally by
        /// `vk dev` for `[dev.network] egress = "restricted"`.
        #[arg(
            long = "egress-file",
            value_name = "FILE",
            conflicts_with_all = ["allow_ip", "allow_name", "egress_restrict", "egress_dry_run"]
        )]
        egress_file: Option<PathBuf>,
        /// dry-run the allowlist: record what it would block, but block nothing
        ///
        /// Evaluate the allowlist and log would-be denials for the job trace, but carry the
        /// flow anyway (a denied name is still resolved and pinned). Set internally by the
        /// gitlab executor from `[egress] dry_run` / MICROVM_EGRESS_DRY_RUN (the job var only
        /// when the host sets no run-phase cap); no effect on an unrestricted policy.
        #[arg(long = "egress-dry-run")]
        egress_dry_run: bool,
        /// per-source egress filter `<src-ip>;<cidr,cidr>;<name,name>` (repeatable)
        ///
        /// Flows from that source are also held to this restricted allowlist, checked after the
        /// default; an empty field is an empty (deny) list. Set internally by the gitlab executor
        /// for a service that declared its own MICROVM_EGRESS_ALLOW_* in its `variables:`.
        #[arg(long = "source-egress", value_name = "IP;CIDRS;NAMES")]
        source_egress: Vec<String>,
        /// the node's egress cap, checked for every source before the allowlists
        ///
        /// `all`, or `<cidr,cidr>;<name,name>`, an empty field denying. Set internally by the
        /// gitlab executor.
        #[arg(long = "egress-cap", value_name = "all|CIDRS;NAMES")]
        egress_cap: Option<String>,
        /// a build stage's declared egress, checked for every source after the allowlists
        ///
        /// `<cidr,cidr>;<name,name>`, an empty field denying. Set internally by a build for a
        /// stage whose Dockerfile declares its egress.
        #[arg(long = "egress-declared", value_name = "CIDRS;NAMES")]
        egress_declared: Option<String>,
        /// the service VM an address belongs to, `<ip>=<name>` (repeatable)
        ///
        /// Recorded denials and contacts name their source by it. Set internally by the gitlab
        /// executor.
        #[arg(long = "vm-name", value_name = "IP=NAME")]
        vm_name: Vec<String>,
        /// the hub's egress layer for this phase, a JSON file read once at start
        ///
        /// Enforced for every source on top of the allowlists, dry-run or not; its dry-run
        /// rules only record what each would block. Set internally for a placed job's switches.
        #[arg(long = "hub-egress", value_name = "FILE")]
        hub_egress: Option<PathBuf>,
        /// stop recording denials and contacts once their log reaches this size, counting them
        ///
        /// What is dropped is counted, and the counts are recorded instead. Set internally for a
        /// placed job's switches.
        #[arg(long = "record-limit", value_name = "BYTES")]
        record_limit: Option<u64>,
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
    /// interactive shell — runs in the guest. Without `--detach`, `vk` exits with the guest
    /// command's status, dying of its signal if it was killed; a run failure exits 1 and a
    /// `--require-cached` miss exits 3. A `--shell` session exits 0 whatever its status.
    ///
    /// `--name`, `--state-dir` or `--detach` gives the primary a name that `vk list` keeps
    /// after shutdown. `vk start NAME` replays its saved command in the background unless the
    /// run used `-t` or `--shell`. Services-only compose runs have no primary to name.
    #[command(display_order = 1)]
    Run {
        /// Image to boot, e.g. `alpine:3.20`
        ///
        /// A docker ref, or an OCI reference with `--source oci`. Omit when booting a
        /// Dockerfile target with `--file`. A directory holding `vm.json` and the disks it
        /// names is a bundle, booted as a UEFI guest (Windows) without vk-agent.
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
        /// network for the --file build's RUN steps: `all` (unrestricted), `declared` or `none`
        ///
        /// It is independent of --net, which governs the booted guest. As for `vk build`, a
        /// stage's `# vk: allow-ip=… allow-name=…` holds its RUN steps to what it declares, and
        /// `declared` gives a stage that declares nothing no network.
        #[arg(
            long = "build-net",
            default_value = "all",
            value_name = "all|declared|none",
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
        /// A suffix is e.g. `crates.io`, dot-anchored; a URL, a pattern, a port or a trailing
        /// dot is refused, as for `vk run --allow-name`. Repeatable; any --build-allow-* flag
        /// turns filtering on.
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
        /// Boot a raw ext4 or btrfs disk image as the root, not the image's ext4 (experimental)
        ///
        /// The kernel stays this boot's own (--kernel, or the primary's). Needs
        /// `--init image|entrypoint` or `--kernel image`; a btrfs root needs `--kernel image`,
        /// whose btrfs module the preinit loads: the pinned kernel has none.
        #[arg(long, value_name = "PATH", help_heading = "Guest")]
        root_image: Option<PathBuf>,
        /// Boot this persistent disk on the kernel in its own /boot (experimental)
        ///
        /// A GPT disk with an ext2 /boot partition of type XBOOTLDR, written in place. Every
        /// boot, a guest reboot included, takes the newest vmlinuz/initrd.img pair in that
        /// /boot; the image provides only the run's config. The root is a partition of type
        /// `Linux root (x86-64)`, or what the disk's initrd mounts given --boot-cmdline.
        /// Needs `--init image|entrypoint`.
        #[arg(
            long,
            value_name = "PATH",
            help_heading = "Guest",
            conflicts_with = "root_image"
        )]
        boot_disk: Option<PathBuf>,
        /// With --boot-disk, let the disk's initrd mount the root, given these kernel arguments
        ///
        /// For a root only the guest knows how to reach (LUKS, LVM): e.g.
        /// `root=/dev/mapper/vg00-lvroot`. vk takes over the root once it is mounted. Needs
        /// a Debian initramfs-tools initrd with a merged /usr; refuses arguments that would
        /// override vk's own (`VIRTKIT_*`, `init=`, `rdinit=`, `--`).
        #[arg(
            long,
            value_name = "ARGS",
            help_heading = "Guest",
            requires = "boot_disk"
        )]
        boot_cmdline: Option<String>,
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
        /// never untrusted CI jobs. Default off.
        #[arg(long, help_heading = "Guest")]
        pmu: bool,
        /// expose VMX/SVM for `vk` inside `vk` — trusted guests only
        ///
        /// Needs nested virtualization enabled on the host (kvm_intel.nested / kvm_amd.nested).
        /// SECURITY: the guest reaches host KVM's nested paths — for trusted guests only.
        /// Default off.
        #[arg(long, help_heading = "Guest")]
        nested: bool,
        /// static (musl) vk-agent injected as PID 1
        ///
        /// Default: the copy embedded in `vk`.
        #[arg(long = "agent", value_name = "PATH", help_heading = "Guest")]
        agent: Option<PathBuf>,
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
        /// memory node for this VM: `off`, `auto`, `interleave`, or a node id
        ///
        /// Default `auto`: the host's `[numa] mode` decides, which on a multi-socket host
        /// means the emptiest node this VM fits on, or all of them interleaved when it fits
        /// none. Anything else overrides that mode for this VM alone — compose services and
        /// a -f build's stage guests follow the host's whatever the flag says.
        #[arg(
            long,
            value_parser = numa::NumaArg::parse,
            value_name = "off|auto|interleave|NODE",
            help_heading = "Guest"
        )]
        numa: Option<numa::NumaArg>,
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
        /// The init `--init image` execs, with its arguments, split like a compose `command:`
        ///
        /// Default `/sbin/init`, with no arguments. Overrides the --primary service's
        /// `x-virtkit.init_argv`.
        #[arg(long, value_name = "CMD", help_heading = "Guest")]
        init_argv: Option<String>,
        /// A command `--init image` runs to completion before handing PID 1 over
        ///
        /// It runs as root on the writable root, with the exec channel up, split like a
        /// compose `command:`. The init runs only if it exits 0; otherwise the guest stays up
        /// for inspection. Overrides the --primary service's `x-virtkit.prepare`.
        #[arg(long, value_name = "CMD", help_heading = "Guest")]
        prepare: Option<String>,
        /// How `/` is mounted when `--init image` hands PID 1 over
        ///
        /// `ro` is what a real boot hands its init, which remounts it rw from its fstab.
        /// Default rw. Overrides the --primary service's `x-virtkit.root`.
        #[arg(long, value_enum, value_name = "MODE", help_heading = "Guest")]
        root: Option<run::RootMode>,
        /// share a host dir read-write into the guest at /work and run the command there
        ///
        /// The command's outputs then land back on the host.
        #[arg(long, value_name = "DIR", help_heading = "Running the command")]
        workdir: Option<PathBuf>,
        /// How the --workdir share is cached: auto or ephemeral
        ///
        /// `auto` keeps host edits visible in the guest within seconds. `ephemeral` treats
        /// the tree as the guest's alone for this run — cached for its whole life, writes
        /// coalesced, no flush or fsync — for a scratch checkout, or a build whose outputs
        /// are read only after the VM exits.
        #[arg(
            long,
            value_enum,
            value_name = "MODE",
            default_value = "auto",
            requires = "workdir",
            help_heading = "Running the command"
        )]
        workdir_cache: crate::vmm::ShareCache,
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
        /// Attach eth0 to this host tap
        ///
        /// The guest is a port on whatever the tap is bridged to, with its own MAC, so it
        /// holds an address on that LAN. The tap must exist, be owned by the user running vk
        /// (`ip tuntap add NAME mode tap user USER`, then enslave it to the bridge) and not
        /// be held by another VM; vk checks this before boot.
        /// Without --tap-ip the guest asks DHCP: the default init runs dhclient, an image
        /// init (--init image) keeps its own network configuration. With --net or --compose
        /// the switch ports follow as eth1 upward, without a route: egress and DNS go
        /// through the tap, and the compose services' names are pinned in /etc/hosts. A
        /// --primary service's own `x-virtkit.tap` gives way to this flag.
        #[arg(long, value_name = "NAME", help_heading = "Network")]
        tap: Option<String>,
        /// MAC address of the --tap NIC [default: derived from host identity and tap name]
        #[arg(
            long = "tap-mac",
            value_name = "MAC",
            requires = "tap",
            help_heading = "Network"
        )]
        tap_mac: Option<String>,
        /// static address of the --tap NIC, as A.B.C.D/PREFIX (needs --tap-gw and --tap-dns)
        #[arg(
            long = "tap-ip",
            value_name = "CIDR",
            requires_all = ["tap", "tap_gw", "tap_dns"],
            help_heading = "Network"
        )]
        tap_ip: Option<String>,
        /// default gateway of the --tap-ip address
        #[arg(
            long = "tap-gw",
            value_name = "IP",
            requires = "tap_ip",
            help_heading = "Network"
        )]
        tap_gw: Option<std::net::Ipv4Addr>,
        /// nameserver for a --tap-ip guest (repeatable)
        #[arg(
            long = "tap-dns",
            value_name = "IP",
            requires = "tap_ip",
            help_heading = "Network"
        )]
        tap_dns: Vec<std::net::Ipv4Addr>,
        /// audit the booted guest's egress: which external domains it contacts
        ///
        /// Lists every one, and how many times, when the run ends. Observes only — it does not
        /// restrict egress. Requires --net (or --compose).
        #[arg(long = "audit-egress", help_heading = "Network")]
        audit_egress: bool,
        /// restrict the booted guest's egress to hosts at or under this DNS suffix
        ///
        /// Dot-anchored: `debian.org` also allows `deb.debian.org`; a URL, a pattern, a port or
        /// a trailing dot is refused. A name outside every suffix resolves to nothing, and the
        /// guest may reach the addresses an allowed name resolved to. Repeatable; any --allow-* flag turns filtering on. Requires --net (or
        /// --compose), whose services it binds too.
        #[arg(
            long = "allow-name",
            value_name = "SUFFIX",
            conflicts_with = "tap",
            help_heading = "Network"
        )]
        allow_name: Vec<String>,
        /// restrict the booted guest's egress to this destination IPv4 CIDR
        ///
        /// For destinations dialed by address, optionally port-scoped as CIDR:port; IPv6 is
        /// refused. An --allow-name host needs none: the guest may reach the addresses an
        /// allowed name resolved to. Repeatable; any --allow-* flag turns filtering on.
        /// Requires --net (or --compose), whose services it binds too.
        #[arg(
            long = "allow-ip",
            value_name = "CIDR[:PORT]",
            conflicts_with = "tap",
            help_heading = "Network"
        )]
        allow_ip: Vec<String>,
        /// restrict the booted guest's egress to the --allow-* lists, even empty ones
        ///
        /// Alone, it denies all egress; the compose services' names still resolve. Requires
        /// --net (or --compose).
        #[arg(
            long = "egress-restrict",
            conflicts_with = "tap",
            help_heading = "Network"
        )]
        egress_restrict: bool,
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
        /// Takes the upstream's base URL (`scheme://host[:port][/prefix]`); the guest reaches
        /// the proxy credential-free at `registry.vk`, which injects
        /// `--username`/`--password`/`--ca`. Needs `--net`. The job never sees the credentials.
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
        /// filesystem); `ro`/`overlay` take `,immutable` for a host tree that will not change
        /// while the service runs (the guest caches it for its life). Persistent state lives under `.virtkit/` beside the compose file and
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
        /// start each Windows service from its snapshot in this directory
        ///
        /// A directory `vk snapshot --run-dir` wrote: a Windows service with a bundle there
        /// resumes from it instead of booting and provisioning; the others boot as usual. Each
        /// must get the address, vCPUs and memory it was snapshotted with.
        #[arg(
            long,
            value_name = "DIR",
            requires = "compose",
            help_heading = "Compose services"
        )]
        from_snapshot: Option<PathBuf>,
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
        /// idle file cache the guests give back to the host: auto, off, a size or a share
        ///
        /// `auto` (the default) evicts what a guest has not touched for a minute or two,
        /// through the multi-gen LRU; a size (512M, 2G) or a share of RAM (5%) keeps that
        /// much cache as a fixed floor instead; `off` keeps all of it. Only ever while the
        /// guest is not under memory pressure. Applies to the primary and, unless a service
        /// declares its own `x-virtkit.reclaim`, to every service.
        #[arg(long, value_name = "POLICY")]
        reclaim: Option<vk_core::reclaim::Policy>,
        /// DAX window for virtio-fs shares: a size, off, <size>:always or <size>:inode=<min>
        ///
        /// With a window the guest maps the host's page cache for the shared files it
        /// reads, so a tree is not cached twice and a host-side edit is visible at once;
        /// the window is guest address space, not memory. A bare size maps only regular
        /// files of 1M and more (`dax=inode`): each mapping costs a host mmap per 2M range
        /// whatever the file's size, which a source tree's small files never repay.
        /// `:always` maps every file; `:inode=64K` moves the floor. The default is 8G per
        /// share, and a guest holds 64G of windows in total. The built-in VMM only. Applies
        /// to the primary and, unless a service declares its own `x-virtkit.dax`, to every
        /// service.
        #[arg(long, value_name = "SIZE")]
        dax: Option<crate::vmm::Dax>,
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
        /// Implies --ssh and needs a state dir: --state-dir, --name or --detach. Generates a keypair of its own (reused on
        /// later boots, so nothing else is authorised by default), and writes `ssh-config`
        /// plus `ssh`, `scp` and `sftp` shims in `bin/` beside it: connect with `vk ssh
        /// <state-dir>`, `ssh -F <state-dir>/ssh-config <alias>`, or by putting
        /// `<state-dir>/bin` first on PATH for a program that spawns the bare tools (VS Code
        /// Remote-SSH, Emacs TRAMP). Needs `ssh`, `scp` and `sftp` on the host's PATH.
        #[arg(long = "ssh-client", help_heading = "SSH")]
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
        /// Created/reused, mode 0700, kept (only an empty one under vk's own
        /// `$XDG_STATE_HOME/virtkit/run` may be removed) — instead of a fresh temp dir, so external
        /// tooling can attach to the running VM: `vk-agent -s vsock-auto://DIR/vsock.sock:4444
        /// exec …`.
        #[arg(
            long = "state-dir",
            value_name = "DIR",
            overrides_with = "state_dir",
            help_heading = "Mounts and disks"
        )]
        state_dir: Option<PathBuf>,
        /// name the VM, a handle it keeps after it stops and `vk list` shows
        ///
        /// Use 1 to 40 characters from a-z, 0-9, `.`, `_` and `-`, starting with a letter or
        /// digit. An all-digit name is reserved for pids. Without `--state-dir`, the VM keeps its
        /// state under `$XDG_STATE_HOME/virtkit/run` after shutdown. A `--state-dir` or `--detach`
        /// run without an explicit name gets one from what it boots;
        /// compose up, which boots no primary VM, takes none. A named run keeps its whole
        /// command line, `--password` included, in `run.json` in its state dir, readable by
        /// its owner alone. The last `--name`, `--state-dir` and `--detach` given win, so a
        /// script can override its own.
        #[arg(
            long,
            value_name = "NAME",
            overrides_with = "name",
            help_heading = "Detach"
        )]
        name: Option<String>,
        /// set by `main` for a remembered run: its name, recipe and state-dir lock
        #[arg(skip)]
        remembered: Option<std::sync::Arc<names::Remembered>>,
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
        /// may add `,optional` to skip an absent source instead of failing the boot. A
        /// read-only share (`ro`, `overlay`) may add `,immutable` when the host will not change
        /// the tree while the VM runs: the guest then keeps what it read for its whole life, so
        /// a pass over the tree (git status, a build's dependency check) asks the host once
        /// instead of once per pass.
        /// `overlay,persist` (an overlay whose writes are kept on disk) and
        /// `x-virtkit.persist_root` belong to compose services, which have a file to keep
        /// that state beside — see --compose.
        #[arg(
            short = 'v',
            long = "volume",
            value_name = "HOST:GUEST[:(ro|rw|overlay|socket)[,optional][,immutable]|:disk[,size=SIZE]]",
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
        /// force --host-exec commands through this program
        ///
        /// It receives the requested command line as its arguments and decides what to run. It
        /// runs in the --workdir (else here), as this user; the guest's `exec --dir` reaches it
        /// as $VK_EXEC_DIR, for it to check and enter. In a --compose primary, a command named
        /// `vk` goes to service exec instead (see --no-service-exec).
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
        /// give a --compose primary no `vk-agent exec --service` into its services
        ///
        /// By default it runs that one form, `vk exec --service` on the host, into this run's
        /// services, over the primary's host command channel, beside a --host-exec-wrapper's
        /// commands when there is one; --host-exec without a wrapper replaces it with the whole
        /// channel.
        #[arg(long = "no-service-exec", help_heading = "Host access from the guest")]
        no_service_exec: bool,
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
        ///
        /// A detached run is named and remembered as with `--name`, except a compose up, which
        /// boots no primary.
        #[arg(long = "detach", overrides_with = "detach", help_heading = "Detach")]
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
        /// Leave out the run's own progress notes
        ///
        /// Leaves out the run's progress: pull, build, boot and service notes, the build
        /// dashboard, the timing breakdown and the resource usage. A failed build still prints
        /// the end of its log, and what a flag asks for still prints: `--ssh`'s command,
        /// `--audit-egress`'s summary, `--detach`'s pid.
        #[arg(short = 'q', long)]
        quiet: bool,
        /// Command to run in the guest (default: a boot-info probe)
        ///
        /// Several words are an argv, each passed as typed (like docker run — use `sh -c '…'`
        /// for shell features); a single word is a shell one-liner run verbatim.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// List known VMs and their compose services by project
    ///
    /// Each primary has a row, followed by its services in name order. A service appears when
    /// its manager reports it active or its console log records a start. `vk list` includes dev
    /// environments, named runs and running UEFI bundles. A dev environment's project is its
    /// workspace. A run uses `--workspace`, then `--workdir`, then its launch directory.
    ///
    /// Use NAME with commands such as `vk start`, `vk stop` and `vk delete`. A dev environment
    /// without a stable name uses its state directory's name. Other unnamed running VMs use
    /// their pid. `vk list`, `start`, `stop`, `restart`, `delete`, `exec`, `cp`, `logs`,
    /// `status` and `publish` also accept `NAME/SERVICE`.
    ///
    /// On a running primary, MEM shows host memory used by its process tree over the recorded
    /// boot size (`1.2G/8G`). The tree includes its service VMs and helpers. Proportional
    /// usage counts shared pages once. The fallback to resident usage can count them more than once.
    /// The table abbreviates `$HOME` to `~`. `--wide` shows full project paths and exec addresses.
    ///
    /// Without `--json` or `--field`, a reference matching exactly one primary prints its full
    /// record if that primary is registered. A service reference or `--running`, `--stopped`,
    /// `--kind` or `--problems` selects table rows instead. Use `--json` or `--field` for scripts. For example,
    /// `vk list --running --kind service --field name` prints names for `vk exec`.
    #[command(display_order = 6, visible_alias = "ls")]
    List {
        /// which VMs: a name, a pid, or those of a project directory (default: all)
        ///
        /// A name as the NAME column prints it (`NAME/SERVICE` for one service row); an
        /// all-digit argument is a pid; a path (`/…`, `./…`, `../…`, `~…`) a project or
        /// state directory, matched exactly unless `--recursive`.
        #[arg(value_name = "REF")]
        target: Option<std::ffi::OsString>,
        /// with a directory (default: the current one), also every VM whose project is below it
        #[arg(short = 'r', long)]
        recursive: bool,
        /// only the VMs reported running, starting or stopping
        ///
        /// A service counts by its own state; one whose state could not be read is left out.
        #[arg(long, conflicts_with = "stopped")]
        running: bool,
        /// only stopped VMs and dev environments that never booted
        #[arg(long)]
        stopped: bool,
        /// only VMs of this kind
        #[arg(long, value_name = "KIND")]
        kind: Option<crate::vmlist::Kind>,
        /// only VMs with an overdue stop or stale records
        ///
        /// `!` marks a run still alive after a stop timed out or was interrupted. With neither
        /// `--json` nor `--field`, recovery advice goes to stderr. `*` marks a row derived from stale VM records. Listing leaves
        /// those records untouched.
        #[arg(long)]
        problems: bool,
        /// the full table: the project path in full, and EXEC ADDRESS
        #[arg(short = 'w', long, conflicts_with_all = ["json", "field"])]
        wide: bool,
        /// emit the rows as a JSON array instead of a table
        #[arg(long)]
        json: bool,
        /// print only this field of each VM (repeatable, one field per flag)
        ///
        /// A `--json` key, or a dotted path into one: `ip`, `published.0`. Several
        /// fields take one `--field` each, not a list. One line per VM, the fields
        /// tab-separated, each as `jq -r` would print it: a string bare, anything else as
        /// JSON; as text, no rows print nothing. Values are not escaped, so a value
        /// holding a tab or newline needs `--json`, which gives an array of objects holding
        /// only those fields.
        #[arg(long, value_name = "FIELD")]
        field: Vec<String>,
        /// check running primaries and their build services for stale images
        ///
        /// Reports whether a fresh `vk run` would rebuild an image. Checking base image digests
        /// can use the network. Service rows and primaries without a live registry entry show
        /// `-` (`null` in JSON).
        #[arg(long)]
        stale: bool,
    },
    /// Stop running VMs or compose services
    ///
    /// By default, stopping a VM sends SIGTERM to its `vk run` process and waits for it to exit. This
    /// also stops its compose siblings. Use `NAME/SERVICE` to stop one service through its
    /// manager. The current project is the default. Use `--all` to stop every registered running VM.
    /// Every REF is resolved first, then every VM is told to stop before any is waited for.
    #[command(display_order = 8)]
    Stop {
        /// VMs or services to stop (default: the current project)
        ///
        /// Select a VM by name or pid, or a service by `NAME/SERVICE` or `PID/SERVICE`. A path
        /// (absolute or starting with `./`, `../` or `~`) selects a project or state directory.
        /// Directories match exactly unless `--recursive`. Stopping a named VM also stops its
        /// published endpoints. An explicit reference to a stopped or still-starting VM exits 1.
        #[arg(value_name = "REF")]
        targets: Vec<std::ffi::OsString>,
        /// with a directory (default: the current one), also every VM whose project is below it
        #[arg(short = 'r', long, conflicts_with = "all")]
        recursive: bool,
        /// stop every registered running vk VM
        #[arg(long, conflicts_with = "targets")]
        all: bool,
        /// repair stale records and review timed-out or interrupted stops
        ///
        /// Forgets abandoned name claims and names of missing managed directories, clears stale
        /// state and registry records, and names dev environments with a valid recorded identity. On a
        /// terminal, asks before killing a run whose stop timed out or was interrupted (`!` in
        /// `vk list`). Exits 1 if an overdue stop remains or a repair fails.
        #[arg(long, conflicts_with_all = ["targets", "all", "recursive", "force", "kill", "timeout"])]
        tidy: bool,
        /// send SIGTERM once a second for 5 seconds, then kill the VMMs
        ///
        /// Use this for a VM that does not answer a plain stop. SIGKILL cuts power to the VM
        /// and its compose services, losing unwritten guest data. After the whole batch,
        /// surviving `vk run` processes get 5 seconds to finish cleanup before SIGKILL.
        /// Select whole VMs with this option.
        #[arg(short = 'f', long, conflicts_with = "kill")]
        force: bool,
        /// kill the VMMs immediately
        ///
        /// Send SIGKILL to the VMMs without requesting guest shutdown. This cuts power to
        /// the VM and its compose services, losing unwritten guest data. After the whole
        /// batch, surviving `vk run` processes get 5 seconds to finish cleanup before
        /// SIGKILL. Select whole VMs with this option.
        #[arg(long)]
        kill: bool,
        /// give up after this many seconds in all; 0 waits as long as it takes
        ///
        /// All VMs and services share this deadline. If a stop is unconfirmed at expiry, vk
        /// reports it and exits 1. The list table marks a recorded, overdue whole-VM stop
        /// `stopping!` while the run is alive. Expiry alone never triggers a kill. Shutdowns
        /// already in progress continue. During graceful shutdown, Linux guests get up to one
        /// minute to power off, Windows guests three minutes plus up to 10 seconds to flush
        /// their disks. A shorter timeout can expire during shutdown.
        #[arg(long, default_value_t = 210, value_name = "SECS")]
        timeout: u64,
    },
    /// Start a VM vk knows, or one of its compose services
    ///
    /// Use the dev environment's recorded workspace, environment and config for `vk dev start`
    /// (`vk dev up` with `--build`). Replay a run's `run.json` in its original directory with `--detach`.
    /// Runs recorded with `-t` or `--shell` need a terminal. Start those with `vk run`.
    /// Starting a running primary is a no-op. If it is already starting, vk reports that and
    /// returns successfully. A service start boots a stopped primary and refuses one still starting.
    /// Only what is already built boots: an image that would have to be built fails the
    /// start unless `--build`, with exit 3 when no target failed otherwise.
    #[command(display_order = 8)]
    Start {
        /// one or more VMs or compose services
        ///
        /// Select a VM by name, pid or directory, or a service by `NAME/SERVICE` or `PID/SERVICE`.
        #[arg(value_name = "REF", required = true)]
        targets: Vec<std::ffi::OsString>,
        /// build what is not built yet, as `vk dev up` does, instead of failing
        #[arg(long)]
        build: bool,
    },
    /// Restart a VM or a compose service
    ///
    /// Resolve each REF once, in order. Before stopping a primary, check its dev workspace
    /// and recorded config, or its run recipe, working directory and recorded `--config`.
    /// Start a stopped primary directly. Restarting a sibling service normally leaves the
    /// primary running. With `--build`, a dev environment's freshness policy can restart it too.
    /// Like `start`, boots only what is already built unless `--build`.
    #[command(display_order = 8)]
    Restart {
        /// one or more VMs or compose services
        ///
        /// Select a VM by name, pid or directory, or a service by `NAME/SERVICE` or `PID/SERVICE`.
        #[arg(value_name = "REF", required = true)]
        targets: Vec<std::ffi::OsString>,
        /// build what is not built yet, as `vk dev up` does, instead of failing
        #[arg(long)]
        build: bool,
        /// seconds to wait for VM shutdown or for each socket operation during a service stop
        #[arg(long, default_value_t = 210, value_name = "SECS")]
        timeout: u64,
    },
    /// Delete a stopped VM's state and name
    ///
    /// Deletes a directory directly under the dev state base, including storage and keys, if it
    /// holds a recorded dev identity and no run recipe. Deletes a directory directly under the
    /// run state base if vk marked it when allocating it. In other directories, removes only
    /// the name, `run.json` and `.virtkit-last.json`.
    ///
    /// Use `--force` to stop a running VM first. To delete a declared service's `svc-<name>/`
    /// and start it afresh, stop its VM first, even with `--force`.
    ///
    /// By default, lists the planned removals and prompts on a terminal. Without a terminal,
    /// pass `--yes` or `--force`. An unresolved REF or a busy VM prevents all removals.
    /// A failure during removal can leave some targets deleted.
    #[command(display_order = 8, visible_aliases = ["rm", "remove"])]
    Delete {
        /// VM or compose service to delete
        ///
        /// Use a VM name, state directory or unambiguous project directory. A named running VM
        /// also accepts its pid and requires `--force`. Add `--dry-run` to preview the stop and
        /// deletion. For a service, stop its VM first and use `NAME/SERVICE`.
        #[arg(value_name = "REF", required = true)]
        targets: Vec<std::ffi::OsString>,
        /// stop a running VM first; implies --yes
        #[arg(short = 'f', long)]
        force: bool,
        /// delete without asking
        #[arg(short = 'y', long)]
        yes: bool,
        /// list what would be deleted, and delete nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// seconds to wait for a VM `--force` stops
        #[arg(long, default_value_t = 210, value_name = "SECS")]
        timeout: u64,
    },
    /// Remove a dev environment's boot images or persistent data, keeping the environment
    ///
    /// Stop the environment first. As with `vk dev prune`, the default is boot images.
    /// Use `--storage` for persistent roots, overlays, disks, editor data and managed
    /// directories in state, or `--all` for both selections.
    #[command(display_order = 8)]
    Reset {
        /// the stopped dev environment's name or directory
        #[arg(value_name = "REF")]
        target: std::ffi::OsString,
        #[command(flatten)]
        options: crate::dev::prune::Options,
    },
    /// Give a VM another name
    #[command(display_order = 8)]
    Rename {
        /// the VM's name, pid or directory
        #[arg(value_name = "REF")]
        old: std::ffi::OsString,
        /// the name it takes: 1 to 40 of a-z, 0-9, `.`, `_`, `-`, starting with a-z or 0-9
        ///
        /// Not all digits, which would read as a pid.
        new: String,
    },
    /// Reboot running vk VM(s) in place
    ///
    /// Asks the guest to reboot (`vk-agent reboot` over vsock); the VM comes back on the
    /// same disks, keeping its pid. Selects the VM whose project is the current directory by
    /// default; pass a name, a pid or a project directory, or `--all`. `--force` skips the
    /// agent and hard-resets through the VMM (for a hung or agent-less guest).
    #[command(display_order = 8)]
    Reboot {
        /// the VM to reboot: a name, a pid or a directory (default: the current one's)
        #[arg(value_name = "REF")]
        target: Option<std::ffi::OsString>,
        /// with a directory (default: the current one), also every VM whose project is below it
        #[arg(short = 'r', long, conflicts_with = "all")]
        recursive: bool,
        /// reboot every running vk VM
        #[arg(long, conflicts_with = "target")]
        all: bool,
        /// hard-reset without waiting for the guest agent (a power-cycle, not a clean reboot)
        #[arg(long)]
        force: bool,
    },
    /// Freeze a running UEFI VM's vCPUs
    ///
    /// The guest stops where it is, its memory and devices kept, until `vk resume`. Selects
    /// the VM whose project is the current directory by default; pass a name, a pid or a
    /// project directory, or `--all`.
    #[command(display_order = 8)]
    Pause {
        /// the VM to pause: a name, a pid or a directory (default: the current one's)
        #[arg(value_name = "REF")]
        target: Option<std::ffi::OsString>,
        /// with a directory (default: the current one), also every VM whose project is below it
        #[arg(short = 'r', long, conflicts_with = "all")]
        recursive: bool,
        /// pause every running vk VM that can be
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// Snapshot a running UEFI VM, or a compose run's Windows services, ending them
    ///
    /// The bundle at `--out` holds the VM's memory, its CPU and device state and its disks as
    /// they were; `vk run <bundle>` starts from there instead of booting, as often as wanted,
    /// each time on fresh overlays. Selects the VM whose project is the current directory by
    /// default; pass a name, a pid or a project directory. With `--run-dir`, every Windows
    /// service of the compose run with that state directory is paused, then saved into
    /// `--out/<service>`, for `vk run --compose … --from-snapshot`.
    ///
    /// A snapshot's disks are overlays of the bundle the VM ran (and of any snapshot that one
    /// came from), named by path: moving or deleting that bundle breaks the snapshot. A
    /// restored guest's clock is set through qemu-ga once it answers; until then, or if that
    /// fails, Kerberos may fail.
    #[command(display_order = 8)]
    Snapshot {
        /// the VM to snapshot: a name, a pid or a directory (default: the current one's)
        #[arg(value_name = "REF", conflicts_with = "run_dir")]
        target: Option<std::ffi::OsString>,
        /// snapshot the Windows services of the compose run with this state directory
        #[arg(long, value_name = "DIR")]
        run_dir: Option<PathBuf>,
        /// the bundle directory to create, on the run's filesystem
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Run a VM `vk pause` froze again
    #[command(display_order = 8)]
    Resume {
        /// the VM to resume: a name, a pid or a directory (default: the current one's)
        #[arg(value_name = "REF")]
        target: Option<std::ffi::OsString>,
        /// with a directory (default: the current one), also every VM whose project is below it
        #[arg(short = 'r', long, conflicts_with = "all")]
        recursive: bool,
        /// resume every paused vk VM
        #[arg(long, conflicts_with = "target")]
        all: bool,
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
    /// Pin the virtkit release a project builds against, and install it
    ///
    /// `.virtkit/toolchain.lock` records the release and, per artifact and platform, its
    /// digest and where to fetch it. `install` fills a versioned cache from it — verifying
    /// the digest, whichever mirror answered — and `export` hands the cached paths to a
    /// script, an image build or CI, so everything builds against the same bytes. This is
    /// the team's reproducible pin; `[requires] min-version` stays the compatibility floor.
    #[command(display_order = 10)]
    Toolchain {
        #[command(subcommand)]
        cmd: ToolchainCmd,
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
    /// The tar `buildctl --output type=oci` produces: flattens its layers AND writes the
    /// image config (Env/User/WorkingDir/Entrypoint/Cmd) to `<out>.json`, no docker/podman.
    /// Replaces the podman load→create→export→mkext-tar chain.
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
/// [`on_runtime`] enters.
fn main() -> ExitCode {
    // Raise this process's soft open-file limit toward its hard cap (≤1M) before anything
    // else: vk serves each guest's virtio-fs shares in-process (libkrun's built-in fs opens
    // a host fd per accessed shared file — and this same binary re-execs as the libkrun
    // boot child to run the VMM), so a heavy build (`cargo`/`make -j` on a shared workdir) needs far
    // more than a login shell's default soft limit, else the guest sees EMFILE.
    raise_nofile();

    // libkrun boot child — internal: boot one microVM under libkrun (the Libkrun Vmm
    // backend re-execs this binary per VM, passing the spec in BOOT_SPEC_ENV so argv is
    // free for the VM's process name). Dispatched before the CLI on that env var; it links
    // libkrun and blocks in the VM's event loop until the guest powers off.
    if let Ok(json) = std::env::var(vmm::BOOT_SPEC_ENV) {
        quiet::inherit();
        let spec: vmm::VmSpec = match serde_json::from_str(&json) {
            Ok(spec) => spec,
            Err(e) => return fail(&anyhow::anyhow!("libkrun boot: bad spec: {e}"), 2),
        };
        return match libkrun_sys::keep(&spec) {
            Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
            Err(e) => fail(&e, 1),
        };
    }

    // Parsed here, before the fork below and before any runtime exists: what detaches is a
    // property of the command, and clap answers `--help`/`--version` by printing and
    // exiting — so neither is ever forked and printed twice.
    let mut cli = Cli::parse();
    // Read once, and cleared while this is the only thread: a run's host commands inherit
    // its environment, and a `vk run` among them is no replay.
    let from_recipe = std::env::var_os(FROM_RECIPE_ENV).is_some();
    // SAFETY: no other thread exists yet to read the environment meanwhile.
    unsafe { std::env::remove_var(FROM_RECIPE_ENV) };
    // Before the fork, so the detaching parent is quiet too.
    if let Cmd::Run { quiet: true, .. } = &cli.cmd {
        quiet::set();
    }

    // A named or detached run gets its name and state dir now, before the fork, so the
    // parent and the daemon agree on them and a failure is reported in the foreground: an
    // invalid or taken name as a usage error, a failure to record it as a run failure.
    let prepared = match prepare_run_name(&mut cli.cmd, from_recipe) {
        Ok(p) => p,
        Err(e) if e.downcast_ref::<names::Refused>().is_some() => return fail(&e, 2),
        Err(e) => return fail(&e, 1),
    };

    // `vk run … --detach`, and the `vk dev` actions that boot — daemonize once the guest is
    // ready. The fork must precede the Tokio runtime (forking a live multi-threaded runtime
    // is undefined behavior): the child continues as the background daemon, the parent
    // supervises the foreground build/boot.
    if detach::wants_detach(&cli.cmd)
        && let detach::Forked::Parent { code, ok } = detach::fork()
    {
        // For `vk dev` the boot is only the first half: the parent is released the moment
        // the guest is ready, which is where the steps *around* the boot belong — the child
        // is busy holding the VM for its lifetime.
        if ok && matches!(cli.cmd, Cmd::Dev(_)) {
            detach::note_after_boot();
            return on_runtime(cli);
        }
        // Report the final name, including any automatic collision suffix.
        if let (true, Cmd::Run { name: Some(n), .. }) = (ok, &cli.cmd) {
            quiet::enote!("virtkit: the VM is named {n}");
        }
        return code;
    }

    let code = on_runtime(cli);
    // Only the process that ran the VM knows whether it became ready.
    prepared.settle();
    code
}

/// Resources to release if the VM never becomes ready. A leftover provisional name
/// would block a retry until reclaimed.
#[derive(Debug, Default)]
struct Prepared {
    /// the remembered run, whose state-dir lock this holds until it is settled
    remembered: Option<std::sync::Arc<names::Remembered>>,
    /// this invocation gave the dir its name, under the index lock
    name_made: bool,
    /// this invocation created the dir, under the run base
    dir_made: bool,
}

impl Prepared {
    /// Take back what was made if the run never had a VM up. The state dir's lock is still
    /// held, as it has been since before the name was claimed, so no other run used the dir
    /// meanwhile: what was made is this run's alone.
    fn settle(&self) {
        let Some(r) = &self.remembered else {
            return;
        };
        if r.up() {
            return;
        }
        if self.name_made
            && let Err(e) = r.index().release(r.dir())
        {
            eprintln!("vk: warning: giving back the name {}: {e:#}", r.name());
        }
        if self.dir_made {
            // Name release is independent of this best-effort directory cleanup.
            let _ = std::fs::remove_dir_all(r.dir());
        }
    }
}

/// Set when `vk start` replays a run: the run keeps the recipe it was started from.
pub const FROM_RECIPE_ENV: &str = "VIRTKIT_FROM_RECIPE";

/// Prepare a primary VM's state directory and provisional name for `--name`,
/// `--state-dir` or `--detach`. Allocate a directory if needed and lock it before the
/// claim until the run ends. [`names::Remembered::publish`] commits the name at readiness.
/// Runs replayed through [`FROM_RECIPE_ENV`] keep their original `run.json`. Other runs
/// write their recipe. [`Prepared::settle`] handles an unsuccessful boot.
fn prepare_run_name(cmd: &mut Cmd, from_recipe: bool) -> anyhow::Result<Prepared> {
    prepare_run_name_in(cmd, from_recipe, || {
        Ok((names::Index::open()?, names::run_base()?))
    })
}

/// [`prepare_run_name`] with the name index and the run base `places()` returns.
fn prepare_run_name_in(
    cmd: &mut Cmd,
    from_recipe: bool,
    places: impl FnOnce() -> anyhow::Result<(names::Index, PathBuf)>,
) -> anyhow::Result<Prepared> {
    let Cmd::Run {
        name,
        state_dir,
        remembered,
        detach,
        image,
        file,
        compose,
        primary,
        target,
        workspace,
        workdir,
        ..
    } = cmd
    else {
        return Ok(Prepared::default());
    };
    if boots_no_primary(image.as_deref(), file, primary.as_deref()) {
        // Nothing to run at all: the run says so itself, and nothing is named for it.
        if compose.is_none() {
            return Ok(Prepared::default());
        }
        // Services-only compose runs have no primary VM to name.
        if let Some(n) = name {
            return Err(names::refuse(format!(
                "--name {n}: compose up (no image, -f or --primary) boots no VM to name; \
                 give it a primary, or leave the name out"
            )));
        }
        return Ok(Prepared::default());
    }
    if name.is_none() && state_dir.is_none() && !*detach {
        return Ok(Prepared::default());
    }
    if let Some(n) = name.as_deref() {
        names::validate(n)?;
    }
    let project = workspace
        .as_deref()
        .or(workdir.as_deref())
        .map(std::path::absolute)
        .transpose()?;
    let recipe = names::Recipe::now(project)?;
    let base = auto_name_base(
        image.as_deref(),
        !file.is_empty(),
        primary.as_deref(),
        target.as_deref(),
        &recipe.project_dir,
    );
    let (idx, run_base) = places()?;
    let (dir, dir_made) = match state_dir.as_deref() {
        Some(d) => (run_state_dir(d)?, false),
        None => {
            let readable = name.clone().unwrap_or_else(|| names::sanitize(&base));
            (new_run_dir(&run_base, &readable, detach::nonce)?, true)
        }
    };
    // The lock first: a name is claimed, and given back, only by the run that holds the dir.
    // Provisional until the VM is first up: a run killed before then leaves a name the next
    // claim takes back.
    let claimed = run::lock_state_dir(&dir).and_then(|lock| {
        let (given, created) = match name.as_deref() {
            Some(n) => (n.to_string(), idx.provisional().claim_exact(&dir, n)?),
            None => idx.provisional().claim(&dir, &base)?,
        };
        Ok((lock, given, created))
    });
    let (lock, given, name_made) = match claimed {
        Ok(claimed) => claimed,
        Err(e) => {
            if dir_made {
                // Made by this call, and holding nothing but its mark.
                names::remove_bare(&dir);
            }
            return Err(e);
        }
    };
    *name = Some(given.clone());
    *state_dir = Some(dir.clone());
    // Preserve the original recipe. The replay command line includes flags added by `vk start`.
    let recipe = (!from_recipe).then_some(recipe);
    let r = std::sync::Arc::new(names::Remembered::new(dir, lock, idx, given, recipe));
    *remembered = Some(r.clone());
    Ok(Prepared {
        remembered: Some(r),
        name_made,
        dir_made,
    })
}

/// Create missing directories with owner-only permissions and return the canonical
/// `--state-dir` path for the name index.
fn run_state_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    let dir = std::path::absolute(dir)?;
    crate::statefile::create_dir_all(&dir)?;
    Ok(vms::canonical(&dir))
}

/// A managed state dir for a run named `name`, `<run_base>/<name>-<token>`, created by this
/// call and no other: a token already taken is drawn again. `name` is cut short as needed
/// for the VMM's sockets to fit under the dir.
fn new_run_dir(
    run_base: &Path,
    name: &str,
    mut token: impl FnMut() -> String,
) -> anyhow::Result<PathBuf> {
    crate::statefile::create_dir_all(run_base)?;
    let run_base = vms::canonical(run_base);
    for _ in 0..16 {
        let token = token();
        let token = token.get(..8).unwrap_or(&token);
        // At least one byte of the name, then `-` and the token.
        let keep = crate::dev::plan::state_dir_room(&run_base)?
            .checked_sub(1 + token.len())
            .filter(|keep| *keep >= 1)
            .ok_or_else(|| crate::dev::plan::no_room(&run_base))?;
        // ASCII: a name is, and so is what sanitizing leaves.
        let readable = name.get(..keep.min(name.len())).unwrap_or(name);
        let dir = run_base.join(format!("{readable}-{token}"));
        match crate::statefile::create_dir(&dir) {
            Ok(()) => {
                // Mark the allocation so `vk delete` can remove the whole directory.
                let mark = dir.join(names::MADE);
                if let Err(e) = vk_fs::write_new(&mark, b"", crate::statefile::FILE_MODE) {
                    let _ = std::fs::remove_dir(&dir);
                    return Err(e.context(format!("writing {}", mark.display())));
                }
                return Ok(dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!("creating {}", dir.display())));
            }
        }
    }
    anyhow::bail!("no free state directory name under {}", run_base.display())
}

/// Whether the command supplies no primary image, Dockerfile or compose primary.
fn boots_no_primary(image: Option<&str>, file: &[PathBuf], primary: Option<&str>) -> bool {
    file.is_empty() && image.is_none() && primary.is_none()
}

/// What an unnamed run is called after, by the source it boots (as [`run`] picks it): the
/// compose primary; for a Dockerfile, its target, else its project directory's name, as a dev
/// environment is named; else the image's own name (no registry, no tag); else `vm`.
fn auto_name_base(
    image: Option<&str>,
    dockerfile: bool,
    primary: Option<&str>,
    target: Option<&str>,
    project: &Path,
) -> String {
    if let Some(p) = primary {
        return p.to_string();
    }
    if dockerfile {
        if let Some(t) = target {
            return t.to_string();
        }
        return project
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "vm".into());
    }
    let Some(image) = image else {
        return "vm".into();
    };
    let last = image
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(image);
    let last = last.split('@').next().unwrap_or(last);
    last.split(':').next().unwrap_or(last).to_string()
}

/// The CLI proper runs on a Tokio runtime (formerly `#[tokio::main]`).
fn on_runtime(cli: Cli) -> ExitCode {
    // `vk node run` leaves its host reads behind when it stops: one stuck on a hung mount
    // would hold the exit for as long as the mount hangs if dropping the runtime waited on it.
    let leave_blocking = matches!(cli.cmd, Cmd::Node { cmd: NodeCmd::Run });
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => {
            let code = rt.block_on(cli_main(cli));
            if leave_blocking {
                rt.shutdown_background();
            }
            code
        }
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
/// plane (see [`vk_core::fleetctl::ServiceOp::run`]).
async fn service_cmd(cmd: &ServiceCmd) -> ExitCode {
    use vk_core::fleetctl::{Client, ServiceOp};
    let op = match cmd {
        ServiceCmd::Up { name } => ServiceOp::Up(name.clone()),
        ServiceCmd::Down { name } => ServiceOp::Down(name.clone()),
        ServiceCmd::Reboot { name } => ServiceOp::Reboot(name.clone()),
        ServiceCmd::Status { name } => ServiceOp::Status(name.clone()),
    };
    let reply = op.run(&mut Client::new()).await;
    match reply {
        Ok(reply) => {
            reply.print();
            if reply.ok {
                ExitCode::SUCCESS
            } else {
                exit_code(1)
            }
        }
        Err(e) if control_plane_unreachable(&e) => fail(
            &e.context(
                "the environment's service control plane is unresponsive — restart the \
                 environment from the host (`vk dev refresh`, or `vk dev stop` then bring it \
                 back up) and retry",
            ),
            1,
        ),
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
    if let Some(note) = executor_omitted_note(cfg) {
        println!("{note}");
    }
    ExitCode::SUCCESS
}

/// The trailing note `vk config` prints when it drops an all-default `[executor]` — `None` when
/// the executor is configured and the whole section is shown instead. Built as a string so a
/// test can assert it; points at `vk config --example` for the keys it leaves out.
fn executor_omitted_note(cfg: &Config) -> Option<String> {
    cfg.executor.is_default().then(|| {
        "# [executor] omitted: the GitLab executor is left at its defaults — \
         `vk config --example` shows its keys"
            .to_string()
    })
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
        let checkouts_note = match cfg.executor.checkout_dir.as_ref() {
            Some(_) => "private subtree of `[executor] checkout_dir`",
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
            false => "off (`[executor] atop`)".to_string(),
        };
        writeln!(
            out,
            "  atop archive  {} ({stats_note})",
            atop::archive_root(cfg).display()
        )?;
        match cfg.executor.tools_dir.as_ref() {
            Some(d) => writeln!(
                out,
                "  tools dir     {} (`[executor] tools_dir`) — static tools shared read-only into job VMs",
                d.display()
            )?,
            None => writeln!(
                out,
                "  tools dir     (unset; override: `[executor] tools_dir`)"
            )?,
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

/// Build `vk switch`'s policy from `--allow-ip`, `--allow-name` and `--egress-restrict`,
/// using `vk run`'s checks and naming the flags in errors.
fn switch_egress_from_flags(
    allow_ip: &[String],
    allow_name: &[String],
    restrict: bool,
) -> anyhow::Result<switch::Egress> {
    switch::check_allowlist(allow_ip, allow_name, "--allow-ip", "--allow-name")?;
    // The CI executor sets --egress-restrict when a job configures egress, so empty lists
    // deny everything. Without it, empty lists mean unrestricted, as in `vk run`.
    if restrict {
        switch::Egress::restricted(allow_ip, allow_name)
    } else {
        switch::Egress::new(allow_ip, allow_name)
    }
}

async fn cli_main(cli: Cli) -> ExitCode {
    // reqwest/rustls are compiled with no built-in crypto provider (rustls-no-provider,
    // to keep aws-lc-rs out of the build); install ring — the backend russh already
    // uses — as the process default before any TLS client is constructed.
    let _ = rustls::crypto::ring::default_provider().install_default();

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
    // The host policy decides on its argv, the passwd database and its own environment —
    // handle it before Config::load, so the wrapper a boot generated keeps working whatever
    // the host config later becomes.
    if let Cmd::HostPolicy {
        policy,
        workspace,
        argv,
    } = &cli.cmd
    {
        return host_policy_cmd(policy, workspace, argv);
    }
    // Decide a guest's `vk-agent exec --service` request from its argv and the services
    // under its dir alone, before Config::load: guest input must not reach config loading.
    // A build loads the config the wrapper was given, never one the guest names.
    if let Cmd::GuestBuildReap { name } = &cli.cmd {
        return guestbuild::reap(name);
    }
    if let Cmd::ServiceExec { dir, allow, argv } = &cli.cmd {
        let forms = allow.unwrap_or(vm::HostForms::EXEC);
        return vm::service_exec(dir, forms, cli.config.as_deref(), argv).await;
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
    // The toolchain commands read the project's lock and the release API, and nothing from
    // the host config — handle them before Config::load, like `update`.
    if let Cmd::Toolchain { cmd } = &cli.cmd {
        return match toolchain_cmd(cmd).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 2),
        };
    }
    // Release keys are made and used on whatever machine holds them, with no host config.
    if let Cmd::ReleaseKey { cmd } = &cli.cmd {
        let printed = match cmd {
            ReleaseKeyCmd::Generate { key } => release_key::generate(key),
            ReleaseKeyCmd::Sign {
                key,
                version,
                program,
                binary,
            } => {
                let program = match program {
                    ReleaseProgram::Vk => release_key::Program::Vk,
                    ReleaseProgram::VkRegistry => release_key::Program::Registry,
                    ReleaseProgram::VkGitlab => release_key::Program::Gitlab,
                    ReleaseProgram::VkHub => release_key::Program::Hub,
                };
                release_key::sign(key, binary, version, program)
            }
        };
        return match printed {
            Ok(line) => {
                println!("{line}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, 1),
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
        ..
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
    // Apply the host's `[build]` tuning process-wide, before any build or boot path runs.
    build::set_tuning(&cfg.build);
    vmm::warn_if_cloud_hypervisor_requested(cfg.vmm);
    numa::set_policy(cfg.numa.mode);
    // The commands that fill the caches start a background `vk gc` when one is due. `vk run`
    // and a booting `vk dev` start theirs from the run, once it holds its state dir, so a pass
    // never finds the environment being booted unclaimed.
    let fills = matches!(
        &cli.cmd,
        Cmd::Build { .. }
            | Cmd::Export { .. }
            | Cmd::Registry {
                cmd: RegistryCmd::Pull { .. },
            }
    );
    if fills && let Ok(state_dir) = effective_state_dir(&cfg) {
        autogc::maybe_start(&cfg, &state_dir);
    }
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
        fix,
    } = &cli.cmd
    {
        return match check::run(&cfg, feature, *min_version, *fix) {
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
        recursive,
        running,
        stopped,
        kind,
        problems,
        wide,
        json,
        field,
        stale,
    } = &cli.cmd
    {
        let opts = vms::ListOpts {
            target: target.clone(),
            recursive: *recursive,
            json: *json,
            stale: *stale,
            fields: field.clone(),
            wide: *wide,
            filter: crate::vmlist::Filter {
                running: *running,
                stopped: *stopped,
                kind: *kind,
                service: None,
                problems: *problems,
            },
        };
        return match vms::list_report(opts) {
            Ok(report) => write_report(&report),
            Err(e) => fail(&e, 2),
        };
    }
    let opts = |timeout| lifecycle::Opts {
        config: cli.config.as_deref(),
        timeout,
        build: false,
    };
    match &cli.cmd {
        Cmd::Start { targets, build } => {
            return lifecycle::start(
                targets,
                lifecycle::Opts {
                    build: *build,
                    ..opts(210)
                },
            );
        }
        Cmd::Restart {
            targets,
            build,
            timeout,
        } => {
            let o = lifecycle::Opts {
                build: *build,
                ..opts(*timeout)
            };
            return lifecycle::restart(targets, o);
        }
        Cmd::Delete {
            targets,
            force,
            yes,
            dry_run,
            timeout,
        } => return lifecycle::delete(targets, *force, *yes, *dry_run, opts(*timeout)),
        Cmd::Reset { target, options } => {
            return match lifecycle::reset(target, options) {
                Ok(report) => write_report(&report),
                Err(e) => fail(&e, 1),
            };
        }
        Cmd::Rename { old, new } => {
            return match lifecycle::rename(old, new) {
                Ok(report) => write_report(&report),
                Err(e) => fail(&e, 1),
            };
        }
        Cmd::Stop {
            targets,
            recursive,
            all,
            tidy,
            force,
            kill,
            timeout,
        } => {
            if *tidy {
                let (report, settled) = tidy::thorough(|o| {
                    if !dev::on_terminal() {
                        return tidy::Decision::NoTerminal;
                    }
                    let question = format!(
                        "{} (pid {}): a stop {} and its run is still there. Kill its VM?",
                        o.name,
                        o.record.pid,
                        o.record.lapse(vms::unix_now())
                    );
                    match dev::ask_on_terminal(&question) {
                        Ok(true) => tidy::Decision::End,
                        _ => tidy::Decision::Leave,
                    }
                });
                return match write_report(&report) {
                    ExitCode::SUCCESS if !settled => exit_code(1),
                    code => code,
                };
            }
            let how = match (*force, *kill) {
                (_, true) => vms::StopHow::Kill,
                (true, false) => vms::StopHow::Force,
                (false, false) => vms::StopHow::Graceful,
            };
            let deadline = match *timeout {
                0 => vms::Deadline::NEVER,
                secs => vms::Deadline::in_secs(secs),
            };
            let config = cli.config.as_deref();
            return stop_refs(targets, *recursive, *all, config, deadline, how);
        }
        _ => {}
    }
    if let Cmd::Reboot {
        target,
        recursive,
        all,
        force,
    } = &cli.cmd
    {
        return act_on_vms(target.as_deref(), *recursive, |sel| {
            vms::reboot_cmd(sel, *all, *force)
        });
    }
    if let Cmd::Snapshot {
        run_dir: Some(run_dir),
        out,
        ..
    } = &cli.cmd
    {
        return match snapshot::snapshot_run(run_dir, out) {
            Ok(report) => write_report(&report),
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Snapshot { target, out, .. } = &cli.cmd {
        let selector = match target.as_deref().map(vms::Selector::parse).transpose() {
            Ok(sel) => sel,
            Err(e) => {
                eprintln!("vk: {e:#}");
                return exit_code(2);
            }
        };
        return match vms::snapshot_cmd(selector, out) {
            Ok(report) => write_report(&report),
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Pause {
        target,
        recursive,
        all,
    }
    | Cmd::Resume {
        target,
        recursive,
        all,
    } = &cli.cmd
    {
        let req = if matches!(cli.cmd, Cmd::Pause { .. }) {
            vms::PauseRequest::Pause
        } else {
            vms::PauseRequest::Resume
        };
        return act_on_vms(target.as_deref(), *recursive, |sel| {
            vms::pause_cmd(sel, *all, req)
        });
    }
    if let Cmd::Gc {
        idle_secs,
        dry_run,
        all_unused,
        auto,
    } = &cli.cmd
    {
        let override_idle = if *all_unused {
            Some(image::EVICT_GRACE)
        } else {
            idle_secs.map(std::time::Duration::from_secs)
        };
        // Sweep the same state dir `vk run`/the executor cache under.
        let state_dir = match effective_state_dir(&cfg) {
            Ok(d) => d,
            Err(e) => return fail(&e, 2),
        };
        let req = gc::Request {
            dry_run: *dry_run,
            all_unused: *all_unused,
            auto: *auto,
            image_idle: override_idle.unwrap_or_else(|| cfg.image_cache_idle()),
            checkout_idle: override_idle.unwrap_or_else(|| cfg.checkout_cache_idle()),
        };
        // One pass at a time: a manual one waits a while for a background one to finish.
        let wait = if *auto {
            std::time::Duration::ZERO
        } else {
            autogc::MANUAL_WAIT
        };
        let pass = autogc::lock(&state_dir, wait);
        if let autogc::Pass::Busy = pass {
            if *auto {
                println!("virtkit: gc: another pass is running");
                return ExitCode::SUCCESS;
            }
            eprintln!(
                "virtkit: gc: a background pass is running (log {}); try again once it is done",
                autogc::log_path(&state_dir).display()
            );
            return exit_code(1);
        }
        if *auto {
            println!("virtkit: background gc at {} (unix time)", vms::unix_now());
        }
        let sum = gc::run(&cfg, &state_dir, &req);
        print!("{}", sum.render());
        if !*dry_run {
            autogc::finished(&state_dir, sum.complete, sum.still_short);
        }
        drop(pass);
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
        workdir_cache,
        kernel,
        root_image,
        boot_disk,
        boot_cmdline,
        console_serial,
        pmu,
        nested,
        source,
        ca,
        username,
        password,
        insecure,
        agent,
        cpus,
        mem,
        numa,
        nics,
        boot_timeout,
        vm_name,
        ram,
        init,
        init_argv,
        prepare,
        root,
        shell,
        tty,
        net,
        tap,
        tap_mac,
        tap_ip,
        tap_gw,
        tap_dns,
        audit_egress,
        allow_name,
        allow_ip,
        egress_restrict,
        build_audit_egress,
        registry_proxy,
        compose,
        profile,
        primary,
        from_snapshot,
        service_cpus,
        service_mem,
        reclaim,
        dax,
        service_nics,
        ssh_agent,
        ssh_host,
        ssh,
        ssh_key,
        ssh_client,
        ssh_alias,
        ssh_user,
        state_dir,
        remembered,
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
        no_service_exec,
        require_cached,
        detach,
        inactivity_timeout,
        detach_log,
        command,
        ..
    } = &cli.cmd
    {
        let services_only = boots_no_primary(image.as_deref(), file, primary.as_deref());
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
                || inactivity_timeout.is_some()
                || init_argv.is_some()
                || prepare.is_some()
                || root.is_some())
        {
            return fail(
                &anyhow::anyhow!(
                    "--compose without an image/-f/--primary is services-only (compose up) — \
                     there is no primary VM for a command, --shell, -t, --ssh, --workdir, \
                     --volume, --symlink, --env, --env-file, --host-exec, \
                     --inactivity-timeout, --init-argv, --prepare or --root (a service \
                     takes x-virtkit.init_argv, prepare and root)"
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
        // Reject nonexistent nodes before pulling, rather than silently placing elsewhere.
        let numa = match numa.unwrap_or(numa::NumaArg::Auto).resolve() {
            Ok(numa) => numa,
            Err(e) => return fail(&e, 2),
        };
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
        // services live on the run switch's LAN: --compose implies it.
        let run_net = *net || compose.is_some();
        let egress_allow =
            match run::egress_from_flags(allow_ip, allow_name, *egress_restrict, run_net) {
                Ok(a) => a,
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
        let init_argv = match init_argv
            .as_deref()
            .map(|cmd| compose::shell_words(cmd).and_then(compose::exec_argv))
            .transpose()
        {
            Ok(v) => v.unwrap_or_default(),
            Err(e) => return fail(&e.context("--init-argv"), 2),
        };
        let prepare = match prepare
            .as_deref()
            .map(|cmd| compose::shell_words(cmd).and_then(compose::exec_argv))
            .transpose()
        {
            Ok(v) => v.unwrap_or_default(),
            Err(e) => return fail(&e.context("--prepare"), 2),
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
        let tap = match tap
            .as_deref()
            .map(|name| {
                net::TapNet::new(
                    name,
                    tap_mac.as_deref(),
                    tap_ip.as_deref(),
                    *tap_gw,
                    tap_dns,
                )
                .map_err(|e| e.context("--tap"))
            })
            .transpose()
        {
            Ok(tap) => tap,
            Err(e) => return fail(&e, 2),
        };
        let args = run::RunArgs {
            image: image.clone().unwrap_or_default(),
            dockerfiles: file.clone(),
            target: target.clone(),
            contexts: context.clone(),
            build_contexts,
            cache,
            base_registry: cfg.registry.clone(),
            build_args,
            workdir: workdir.clone(),
            workdir_cache: *workdir_cache,
            kernel: kernel.clone(),
            root_image: root_image.clone(),
            boot_disk: boot_disk.clone(),
            boot_cmdline: boot_cmdline.clone(),
            console_serial: *console_serial,
            pmu: *pmu,
            nested: *nested,
            agent: agent.clone(),
            source: *source,
            ca: ca.clone(),
            username: username.clone(),
            password: password.clone(),
            insecure: *insecure,
            cpus: *cpus,
            mem: mem.clone(),
            numa,
            nics: *nics,
            service_cpus: service_cpus.clone(),
            service_mem: service_mem.clone(),
            reclaim: *reclaim,
            dax: *dax,
            service_nics: service_nics.clone(),
            boot_timeout_secs: *boot_timeout,
            vm_name: vm_name.clone(),
            ram: *ram,
            init: *init,
            init_argv,
            prepare,
            root: *root,
            shell: *shell,
            tty: *tty,
            net: run_net,
            tap,
            audit_egress: *audit_egress,
            build_audit_egress: *build_audit_egress,
            egress_allow,
            // Fixed for the run: only `vk dev` edits a running guest's allowlist.
            egress_file: None,
            registry_proxy: registry_proxy.clone(),
            compose: compose.clone(),
            profiles: profile.clone(),
            primary: primary.clone(),
            from_snapshot: from_snapshot.clone(),
            build_net: bnet,
            ssh_agent: *ssh_agent,
            ssh_hosts: ssh_host.clone(),
            ssh_allow_pub: None,
            ssh_guest_config: None,
            ssh: *ssh || *ssh_client || !ssh_key.is_empty(),
            ssh_keys: ssh_key.clone(),
            ssh_client: *ssh_client,
            ssh_alias: ssh_alias.clone(),
            ssh_user: ssh_user.clone(),
            state_dir: state_dir.clone(),
            remembered: remembered.clone(),
            state_lock: None,
            workspace: workspace.clone(),
            volumes,
            symlinks,
            extra_disks,
            atop: *atop,
            env: extra_env,
            host_exec: *host_exec,
            host_exec_wrapper: host_exec_wrapper.clone(),
            compose_snapshot: None,
            host_exec_env: host_exec_env.clone(),
            no_service_exec: *no_service_exec,
            require_cached: *require_cached,
            detach: *detach,
            inactivity_timeout_secs: *inactivity_timeout,
            detach_log: detach_log.clone(),
            command: command.clone(),
        };
        // `main` gave a named or detached run its state dir; any other needs `--state-dir`.
        if args.ssh_client && args.state_dir.is_none() {
            return fail(
                &anyhow::anyhow!("--ssh-client needs a state dir: --state-dir, --name or --detach"),
                2,
            );
        }
        return match run::run(&args, &cfg).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) if build::not_cached(&e) => fail(&e, 3),
            // Returned rather than exited on, so `main` still gives back a name it made.
            Err(e) if let Some(code) = run::stop_code(&e) => {
                ExitCode::from(u8::try_from(code).unwrap_or(1))
            }
            Err(e) => match run::guest_exit(&e) {
                // Reproduce the guest's exit code or terminating signal, as `vk exec` does.
                Some(result) => exec::exit(result),
                None => fail(&e, 1),
            },
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
        return match dockerhash::run(dockerfile, context, &args, stages, cfg.registry.as_ref()) {
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
        return match mkoci::archive_to_ext4(archive, out, &injects, extra_free, &fsid) {
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
        egress_record,
        require_cached,
        build_jobs,
        stage_mem,
        stage_cpus,
        debug,
        reinstall,
    } = &cli.cmd
    {
        // A Windows Dockerfile (`FROM winiso:`, a windows platform, or a Windows bundle)
        // builds a bundle of qcow2 layers through qemu-ga instead of an ext4.
        let mut windows = false;
        if compose.is_none() {
            for f in file {
                // An unreadable file is the Linux build's to report.
                let Ok(text) = std::fs::read_to_string(f) else {
                    continue;
                };
                match winbuild::is_windows(&text, &windows_context(context, f)) {
                    Ok(w) => windows |= w,
                    Err(e) => return fail(&e.context(format!("{}", f.display())), 2),
                }
            }
        }
        if windows {
            return windows_build(&cli.cmd, &cfg).await;
        }
        if *reinstall {
            return fail(
                &anyhow::anyhow!("--reinstall applies to a Windows build only"),
                2,
            );
        }
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
        // CLI flag wins; otherwise fall back to [build] config. bool flags are opt-in, so a
        // set flag or a config `true` enables them.
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
            kernel: kernel.clone().or_else(|| b.kernel.clone()),
            agent: agent.clone().or_else(|| b.agent.clone()),
            cache: crate::build::CacheDest::Configured(cache),
            base_registry: cfg.registry.clone(),
            build_cache,
            journal: journal_enabled(*no_journal, b.no_journal),
            // A `vk build --out` artifact stays a raw ext4: it is what gets mounted, packaged
            // and pushed as a bundle.
            out_format: build::ImageFormat::Raw,
            tmp_tmpfs: *build_tmp_tmpfs || b.tmp_tmpfs,
            build_args,
            net,
            audit: *build_audit_egress,
            record: egress_record.clone().map(|dir| build::EgressRecord {
                dir,
                source: None,
                hub: None,
            }),
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
                // Build selection ignores backing paths, so leave `persist_anchor` unset.
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
                Err(e) if build::not_cached(&e) => fail(&e, 3),
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
            Err(e) if build::not_cached(&e) => fail(&e, 3),
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
            RegistryCmd::Put {
                files: paths,
                dir,
                ttl,
                keep,
                cache_registry,
                cache_insecure,
            } => {
                let rg = match files_registry(&cfg, cache_registry.as_deref(), *cache_insecure) {
                    Ok(rg) => rg,
                    Err(e) => return fail(&e, 2),
                };
                let retention = match (ttl, keep) {
                    (Some(ttl), _) => files::PutRetention::Ttl(*ttl),
                    (None, true) => files::PutRetention::Keep,
                    (None, false) => files::PutRetention::Idle,
                };
                for path in paths {
                    match files::put(&rg, path, dir.as_deref(), retention) {
                        Ok((_, refs)) => println!("{} {}", path.display(), refs.join(" ")),
                        Err(e) => {
                            return fail(&e.context(format!("putting {}", path.display())), 1);
                        }
                    }
                }
                ExitCode::SUCCESS
            }
            RegistryCmd::Get {
                reference,
                output,
                cache_registry,
                cache_insecure,
            } => {
                let rg = match files_registry(&cfg, cache_registry.as_deref(), *cache_insecure) {
                    Ok(rg) => rg,
                    Err(e) => return fail(&e, 2),
                };
                let dest = match output {
                    Some(path) => files::Dest::File(path),
                    None => files::Dest::Into(std::path::Path::new(".")),
                };
                match files::get(&rg, reference, dest) {
                    Ok(Some((file, dest))) => {
                        println!("{} sha256:{}", dest.display(), file.sha256);
                        ExitCode::SUCCESS
                    }
                    Ok(None) => fail(&anyhow::anyhow!("{reference}: no such file"), 1),
                    Err(e) => fail(&e, 1),
                }
            }
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
                match vk_registry::status("vk registry", root) {
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
                match vk_registry::gc(
                    "vk registry",
                    root,
                    days(*retention_days),
                    days(*grace_days),
                    *dry_run,
                ) {
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
        unrouted,
        allow_ip,
        allow_name,
        egress_restrict,
        egress_file,
        egress_dry_run,
        source_egress,
        egress_cap,
        egress_declared,
        vm_name,
        hub_egress,
        record_limit,
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
        let mut followed = None;
        let built = if let Some(f) = egress_file {
            // The bytes read are what the follower compares against, so an edit landing
            // between this read and its first poll is still applied.
            switch::EgressFile::load(f).map(|(policy, text)| {
                followed = Some((f.clone(), text));
                policy
            })
        } else {
            switch_egress_from_flags(allow_ip, allow_name, *egress_restrict)
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
        let cap = match egress_cap.as_deref().map(parse_egress_cap).transpose() {
            Ok(c) => c,
            Err(e) => return fail(&e, 2),
        };
        let declared = match egress_declared.as_deref().map(parse_egress_cap).transpose() {
            Ok(d) => d,
            Err(e) => return fail(&e, 2),
        };
        let vm_names = match parse_vm_names(vm_name) {
            Ok(m) => m,
            Err(e) => return fail(&e, 2),
        };
        let hub = match hub_egress
            .as_deref()
            .map(switch::HubLayer::read)
            .transpose()
        {
            Ok(h) => h,
            Err(e) => return fail(&e, 2),
        };
        // The switch logs into a file (a CI job's job dir, a run's work dir): a full
        // filesystem must not make a line a panic (see outrelay).
        let _relay = outrelay::relay();
        return match switch::run(
            &listen_bind,
            *gateway,
            *prefix,
            hosts,
            reservations,
            unrouted.iter().copied().collect(),
            egress,
            per_source,
            proxy,
            denied_log.clone(),
            audit_log.clone(),
            net_bytes.clone(),
            *egress_dry_run,
            cap,
            declared,
            vm_names,
            hub,
            *record_limit,
            followed,
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
        Cmd::EgressReport { dir } => {
            if !dir.is_dir() {
                return fail(&anyhow::anyhow!("{}: not a directory", dir.display()), 2);
            }
            match egress_report::report(&dir) {
                Some(report) => write_report(&format!("{report}\n")),
                None => ExitCode::SUCCESS,
            }
        }
        Cmd::Workloads {
            watch,
            interval_secs,
            mem_secs,
        } => match workloads::run(
            &ctx.cfg,
            watch,
            std::time::Duration::from_secs(interval_secs),
            std::time::Duration::from_secs(mem_secs),
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
        Cmd::Node { cmd } => match cmd {
            NodeCmd::Join {
                hub,
                token,
                token_file,
                ca,
                replace,
                user,
                service,
                ignore_ci_user,
            } => {
                let token = match (token, token_file) {
                    (_, Some(path)) => node::TokenSource::File(path),
                    (Some(t), None) if t == "-" => node::TokenSource::Stdin,
                    (Some(t), None) => node::TokenSource::Literal(t),
                    // clap requires one of the two; a usage error all the same if it did not.
                    (None, None) => {
                        return fail(&anyhow::anyhow!("give --token or --token-file"), 2);
                    }
                };
                let opts = node::JoinOptions {
                    replace,
                    user,
                    service,
                    ignore_ci_user,
                };
                match node::join(&ctx.cfg, &hub, &token, ca.as_deref(), &opts).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, 1),
                }
            }
            NodeCmd::Job { dir, ledger_fd } => {
                match node::jobs::driver::run(ctx.cfg, &dir, ledger_fd).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, 1),
                }
            }
            NodeCmd::Run => match node::run(ctx.cfg).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) if e.is::<node::Locked>() => fail(&e, node::LOCKED_EXIT),
                Err(e) => fail(&e, 1),
            },
            NodeCmd::Service { cmd } => {
                let done = match cmd {
                    NodeServiceCmd::Install {
                        no_start,
                        stop_timeout,
                        user,
                        ignore_ci_user,
                    } => node::service::install(
                        &ctx.cfg,
                        !no_start,
                        stop_timeout,
                        user.as_deref(),
                        match ignore_ci_user {
                            true => node::service::CiUser::Warn,
                            false => node::service::CiUser::Refuse,
                        },
                    ),
                    NodeServiceCmd::Uninstall => node::service::uninstall(),
                };
                match done {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, 1),
                }
            }
        },
        Cmd::Gitlab { cmd } => match cmd {
            GitlabCmd::Config => {
                let info = serde_json::json!({
                    "driver": {
                        "name": "virtkit",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "builds_dir": ctx.cfg.executor.guest.builds_dir,
                    "cache_dir": ctx.cfg.executor.guest.cache_dir,
                    "builds_dir_is_shared": false,
                });
                println!("{info}");
                ExitCode::SUCCESS
            }
            GitlabCmd::Prepare => {
                // The job runs under the hub's Fallback as it stands now, whatever it becomes.
                let mut ctx = ctx;
                let prepared = match ctx.take_fallback() {
                    Ok(()) => vm::prepare(&ctx).await,
                    Err(e) => Err(e),
                };
                match prepared {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, ctx.system_failure),
                }
            }
            GitlabCmd::Run { script, stage } => {
                // The Fallback the switch enforces since prepare, for the trace to name: one
                // that cannot be read leaves the trace without it, and the switch as it is.
                let mut ctx = ctx;
                if let Err(e) = ctx.load_fallback() {
                    eprintln!("virtkit: warning: {e:#}");
                }
                match executor::run_stage(&ctx, &script, stage.as_deref()).await {
                    Ok(result) => match (result.code, result.signal) {
                        (Some(0), _) => ExitCode::SUCCESS,
                        // non-zero exit: the script already reported its error
                        (Some(code), _) => {
                            write_build_exit_code(std::env::var_os("BUILD_EXIT_CODE_FILE"), code);
                            exit_code(ctx.build_failure)
                        }
                        (None, signal) => {
                            eprintln!("virtkit: stage script killed by signal {signal:?}");
                            exit_code(ctx.build_failure)
                        }
                    },
                    // can't reach/drive the VM: environment problem, job is retryable
                    Err(e) => fail(&e, ctx.system_failure),
                }
            }
            GitlabCmd::Supervise { job_dir } => {
                // Its stdout and stderr are a log in the job dir, so a full filesystem must
                // not make its every line a panic. Held past `fail`, whose line it drains.
                let _relay = outrelay::relay();
                // The Fallback its prepare kept, which the run phase's switch enforces: one that
                // cannot be read fails the job rather than run it without.
                let mut ctx = ctx;
                let supervised = match ctx.load_fallback() {
                    Ok(()) => vm::supervise(&ctx, &job_dir).await,
                    Err(e) => Err(e),
                };
                match supervised {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e, 1),
                }
            }
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
                    ctx.cfg.executor.schedule.from_history,
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
                        ReadAs::of(summary, json, view, follow, term::can_draw()),
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
        Cmd::Ssh { target, args } => {
            match state_dir_of(&target).and_then(|dir| sshclient::exec_ssh(&dir, &args)) {
                Ok(never) => match never {},
                Err(e) => fail(&e, 1),
            }
        }
        Cmd::SshConfig { target } => {
            match state_dir_of(&target).and_then(|dir| sshclient::print_config(&dir)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
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
                &anyhow::anyhow!("--stale selects a VM by REF, not a raw agent address"),
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
        // wait uses) so a caller can check a VM is up with vk alone. The target is a REF
        // (default: cwd), `NAME/SERVICE` probing that service's agent, or a raw agent address
        // for plumbing.
        Cmd::Status {
            target,
            stale: false,
        } => {
            // Resolution/usage errors exit 2, matching `vk list`/`vk stop`; the code-1
            // result below is reserved for a resolved VM whose agent does not answer.
            let addr = match exec_target(target.as_deref(), None, "--service")
                .and_then(|t| resolve_exec_addr(&t))
            {
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
            exact,
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
            let path = match (exact, &target) {
                // `--exact` cannot follow, so there is no VM to watch.
                (true, Some(dir)) => exact_console_log_path(dir).map(|p| (p, None)),
                _ => console_log_path(target.as_deref(), service.as_deref()),
            };
            match path {
                Ok((path, writer)) => {
                    match show_console_log(&path, writer.as_ref(), &sources, level, lines, follow)
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
        // selects the VM the same way `vk status` does (a name, pid or directory, default cwd,
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
            // Resolved once, for both the Windows check and the agent address below.
            let target = match exec_target(target.as_deref(), service.as_deref(), "--service") {
                Ok(t) => t,
                Err(e) => return fail(&e, 2),
            };
            // A Windows (UEFI) guest has no vk-agent: its qemu-ga runs the command instead.
            let socket = match windows_exec_socket(&target) {
                Ok(socket) => socket,
                Err(e) => return fail(&e, 2),
            };
            if let Some(socket) = socket {
                if tty || user.is_some() || clear_env {
                    return fail(
                        &anyhow::anyhow!(
                            "--tty, --user and --clear-env need vk-agent; a Windows guest runs \
                             commands through qemu-ga, as SYSTEM"
                        ),
                        2,
                    );
                }
                let env = match winexec::parse_env(&env) {
                    Ok(env) => env,
                    Err(e) => return fail(&e, 2),
                };
                if let Err(e) = winexec::check_command(&command, dir.as_deref()) {
                    return fail(&e, 2);
                }
                let ran = tokio::task::spawn_blocking(move || {
                    winexec::exec(&socket, &command, &env, dir.as_deref(), background)
                })
                .await;
                return match ran {
                    // A Windows exit code past 255 (an NTSTATUS) still reads as a failure.
                    Ok(Ok(code)) => u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from),
                    Ok(Err(e)) => fail(&e, 1),
                    Err(e) => fail(&anyhow::anyhow!("{e}"), 1),
                };
            }
            // Resolution/usage errors exit 2, matching `vk status`/`vk list`/`vk stop` and
            // clap's own usage-error exit. Any vk-chosen code can collide with the remote
            // command's status vk reproduces below; 2 matches what the old CLI returned
            // when the positional address failed to parse.
            let addr = match resolve_exec_addr(&target) {
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
        Cmd::Console { target } => {
            let entry = match vms::resolve_one(target.as_deref().map(Path::new)) {
                Ok(e) if e.guest_agent.is_some() => e,
                Ok(_) => {
                    return fail(
                        &anyhow::anyhow!(
                            "vk console attaches to a Windows (UEFI) guest; for this VM use `vk logs -f`"
                        ),
                        2,
                    );
                }
                Err(e) => return fail(&e, 2),
            };
            match tokio::task::spawn_blocking(move || console::run(&entry)).await {
                Ok(Ok(())) => ExitCode::SUCCESS,
                Ok(Err(e)) => fail(&e, 1),
                Err(e) => fail(&anyhow::anyhow!("{e}"), 1),
            }
        }
        Cmd::Cp {
            source,
            destination,
            target,
            service,
        } => {
            let target = exec_target(target.as_deref(), service.as_deref(), "--service");
            let socket = match target.and_then(|t| Ok((windows_exec_socket(&t)?, t))) {
                Ok((Some(s), _)) => s,
                Ok((None, t)) => {
                    let not = match t {
                        ExecTarget::Ref {
                            service: Some(s), ..
                        } => format!("no Windows service {s} runs here"),
                        _ => "this VM runs vk-agent".into(),
                    };
                    return fail(
                        &anyhow::anyhow!("vk cp copies to a Windows (UEFI) guest; {not}"),
                        2,
                    );
                }
                Err(e) => return fail(&e, 2),
            };
            let guest_side = source.strip_prefix(':').or(destination.strip_prefix(':'));
            if guest_side.is_some_and(|p| p.is_empty() || p.ends_with(['/', '\\'])) {
                return fail(
                    &anyhow::anyhow!(
                        "the guest side must be a file's full path, not a directory: vk cp \
                         copies one file"
                    ),
                    2,
                );
            }
            let copied = match (source.strip_prefix(':'), destination.strip_prefix(':')) {
                (None, Some(remote)) => {
                    let (local, remote) = (PathBuf::from(&source), remote.to_string());
                    tokio::task::spawn_blocking(move || winexec::copy_in(&socket, &local, &remote))
                        .await
                }
                (Some(remote), None) => {
                    let remote = remote.to_string();
                    let mut local = PathBuf::from(&destination);
                    if local.is_dir() {
                        let name = remote.rsplit(['\\', '/']).next().unwrap_or(&remote);
                        local.push(name);
                    }
                    tokio::task::spawn_blocking(move || winexec::copy_out(&socket, &remote, &local))
                        .await
                }
                _ => {
                    return fail(
                        &anyhow::anyhow!(
                            "exactly one of the two paths must be the guest's (a leading `:`)"
                        ),
                        2,
                    );
                }
            };
            match copied {
                Ok(Ok(_)) => ExitCode::SUCCESS,
                Ok(Err(e)) => fail(&e, 1),
                Err(e) => fail(&anyhow::anyhow!("{e}"), 1),
            }
        }
        // run_forward only returns on a bind error; otherwise it serves until the
        // process is killed (cleanup tears the detached child down).
        Cmd::Forward {
            listen,
            to,
            max_conns,
        } => {
            // A forward logs into a file, as the switch does (see outrelay).
            let _relay = outrelay::relay();
            match vk_core::forward::run_forward(&listen, &to, None, max_conns.map(|n| n.get()))
                .await
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
        Cmd::Dev(dev) => crate::dev::cli::run(dev, &ctx.cfg, cli.config.as_deref()).await,
        Cmd::Publish {
            action: Some(action),
            ..
        } => publish_action(action).await,
        // publish::run only returns on a bind error, like Cmd::Forward; the target VM is
        // selected the same way `vk exec` selects it.
        Cmd::Publish {
            target,
            via,
            listen,
            to,
            action: None,
        } => {
            // clap requires both without a subcommand.
            let (Some(listen), Some(to)) = (listen, to) else {
                return fail(&anyhow::anyhow!("--listen and --to are required"), 2);
            };
            let addr = match exec_target(target.as_deref(), via.as_deref(), "--via")
                .and_then(|t| resolve_exec_addr(&t))
            {
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
        | Cmd::ReleaseKey { .. }
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
        | Cmd::Start { .. }
        | Cmd::Restart { .. }
        | Cmd::Delete { .. }
        | Cmd::Reset { .. }
        | Cmd::Rename { .. }
        | Cmd::Stop { .. }
        | Cmd::Reboot { .. }
        | Cmd::Pause { .. }
        | Cmd::Resume { .. }
        | Cmd::Snapshot { .. }
        | Cmd::Update { .. }
        | Cmd::Toolchain { .. }
        | Cmd::HostPolicy { .. }
        | Cmd::ServiceExec { .. }
        | Cmd::GuestBuildReap { .. }
        | Cmd::Service { .. } => {
            unreachable!()
        }
    }
}

/// Resolve the explicit or checkout lock path before each toolchain action. `lock`
/// selects a path to create when no lock exists.
async fn toolchain_cmd(cmd: &ToolchainCmd) -> anyhow::Result<()> {
    match cmd {
        ToolchainCmd::Lock {
            version,
            mirror,
            artifact,
            lock,
        } => {
            let path = toolchain::lock_to_write(lock.as_deref())?;
            toolchain::lock(version.as_deref(), mirror, artifact, &path).await
        }
        ToolchainCmd::Install {
            artifact,
            offline,
            lock,
        } => {
            toolchain::install(
                &toolchain::lock_to_read(lock.as_deref())?,
                artifact,
                *offline,
            )
            .await
        }
        ToolchainCmd::Export { format, lock } => {
            toolchain::export(&toolchain::lock_to_read(lock.as_deref())?, *format)
        }
        ToolchainCmd::Status { lock } => {
            toolchain::status(&toolchain::lock_to_read(lock.as_deref())?)
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

/// `vk host-policy <policy> --workspace DIR -- <argv…>`: decide, then become the command.
///
/// 126 is the shell's "found but not executable" code, and what the guest sees for anything
/// the policy turns down — with the reason on stderr, since the guest shim shows it.
fn host_policy_cmd(policy: &str, workspace: &Path, argv: &[String]) -> ExitCode {
    const REFUSED: i32 = 126;
    let refuse = |why: String| {
        eprintln!("vk host-policy: {why}");
        exit_code(REFUSED)
    };
    if policy != "git-gui" {
        return refuse(format!("unknown policy: {policy}"));
    }
    // The exec channel runs this in the --workdir, the guest's `exec --dir` (relative to it)
    // in VK_EXEC_DIR. Entered first and checked as the directory this process is in, which
    // the command inherits: a path checked and then entered again could be a different
    // directory by then.
    let asked = std::env::var_os("VK_EXEC_DIR").unwrap_or_default();
    if !asked.is_empty()
        && let Err(e) = std::env::set_current_dir(&asked)
    {
        return refuse(format!(
            "cannot enter the working directory {}: {e}",
            Path::new(&asked).display()
        ));
    }
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => return refuse(format!("no working directory: {e}")),
    };
    let passwd = match hostpolicy::self_passwd() {
        Ok(p) => p,
        Err(e) => return refuse(format!("{e:#}")),
    };
    // The host operator's own environment; a non-UTF-8 entry is dropped rather than
    // panicking, and could not be in the passthrough allowlist anyway.
    let env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    match hostpolicy::git_gui(workspace, &cwd, argv, &env, (&passwd.0, &passwd.1)) {
        Err(e) => refuse(format!("{e:#}")),
        Ok(hostpolicy::Decision::Refused(why)) => refuse(why),
        Ok(hostpolicy::Decision::Run { program, args, env }) => {
            use std::os::unix::process::CommandExt;
            // env_clear + the rebuilt env is the whole environment the command gets, and the
            // PATH in it is what resolves the program name.
            let e = std::process::Command::new(&program)
                .args(&args)
                .env_clear()
                .envs(env)
                .exec();
            eprintln!("vk host-policy: {program}: {e}");
            exit_code(127)
        }
    }
}

/// A Windows build's context: `--context`, else the Dockerfile's directory.
fn windows_context(context: &[PathBuf], dockerfile: &Path) -> PathBuf {
    context
        .first()
        .cloned()
        .unwrap_or_else(|| match dockerfile.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => PathBuf::from("."),
        })
}

/// `vk build` of a Windows Dockerfile: a bundle of qcow2 layers made through qemu-ga
/// ([`winbuild`]) instead of an ext4, refusing the flags only the Linux build reads.
async fn windows_build(cmd: &Cmd, cfg: &config::Config) -> ExitCode {
    let Cmd::Build {
        file,
        target,
        context,
        build_context,
        out,
        tag,
        disk,
        print_plan,
        kernel,
        agent,
        cache_registry,
        cache_insecure,
        build_cache,
        no_journal,
        build_tmp_tmpfs,
        build_arg,
        build_allow_ip,
        build_allow_name,
        build_audit_egress,
        egress_record,
        require_cached,
        build_jobs,
        stage_mem,
        stage_cpus,
        debug,
        build_net,
        reinstall,
        ..
    } = cmd
    else {
        unreachable!("windows_build of a build command");
    };
    // What only the Linux build reads.
    let linux_only = [
        (file.len() > 1, "a second --file"),
        (target.len() > 1, "a second --target"),
        (context.len() > 1, "a second --context"),
        (!build_context.is_empty(), "--build-context"),
        (tag.is_some(), "--tag"),
        (disk.is_some(), "--disk"),
        (*print_plan, "--print-plan"),
        (kernel.is_some(), "--kernel"),
        (agent.is_some(), "--agent"),
        (build_cache.is_some(), "--build-cache"),
        (*no_journal, "--no-journal"),
        (*build_tmp_tmpfs, "--build-tmp-tmpfs"),
        (!build_arg.is_empty(), "--build-arg"),
        (*build_audit_egress, "--build-audit-egress"),
        (egress_record.is_some(), "--egress-record"),
        (*require_cached, "--require-cached"),
        (build_jobs.is_some(), "--build-jobs"),
        (!stage_mem.is_empty(), "--stage-mem"),
        (!stage_cpus.is_empty(), "--stage-cpus"),
        (*debug, "--debug"),
    ];
    if let Some((_, flag)) = linux_only.iter().find(|(given, _)| *given) {
        return fail(
            &anyhow::anyhow!("{flag} does not apply to a Windows build"),
            2,
        );
    }
    let net = match build::BuildNet::from_flags(build_net, build_allow_ip, build_allow_name) {
        Ok(net) => net,
        Err(e) => return fail(&e, 2),
    };
    let dockerfile = &file[0];
    let Some(out) = out.clone() else {
        return fail(
            &anyhow::anyhow!("a Windows build writes a bundle directory: pass --out <dir>"),
            2,
        );
    };
    let registry = match windows_registry(cache_registry.as_deref(), *cache_insecure, &cfg.build) {
        Ok(r) => r,
        Err(e) => return fail(&e, 2),
    };
    let context = windows_context(context, dockerfile);
    let context = match context.canonicalize() {
        Ok(c) => c,
        Err(e) => {
            return fail(
                &anyhow::anyhow!("build context {}: {e}", context.display()),
                2,
            );
        }
    };
    let (cpus, mem) = winbuild::default_size();
    let opts = winbuild::Options {
        dockerfile: dockerfile.clone(),
        context,
        target: target.first().cloned(),
        out,
        cpus,
        mem,
        net,
        reinstall: *reinstall,
        media_registry: registry
            .clone()
            .ok_or_else(|| winiso::NO_REGISTRY.to_string()),
        registry,
        approved_media: None,
        scope: None,
        pull_layers: true,
        ceiling: None,
    };
    match tokio::task::spawn_blocking(move || winbuild::build(&opts)).await {
        Ok(Ok(_refs)) => ExitCode::SUCCESS,
        Ok(Err(e)) => fail(&e, 1),
        Err(e) => fail(&anyhow::anyhow!("{e}"), 1),
    }
}

/// Run a `vk stop`-like command on the VMs its TARGET selects: print its report, and exit 1
/// unless every VM did it, 2 on a bad TARGET or an error.
fn act_on_vms(
    target: Option<&std::ffi::OsStr>,
    recursive: bool,
    run: impl FnOnce(Option<vms::Selector>) -> anyhow::Result<(String, bool)>,
) -> ExitCode {
    let selector = match vms::selector_of(target, recursive) {
        Ok(sel) => sel,
        Err(e) => {
            eprintln!("vk: {e:#}");
            return exit_code(2);
        }
    };
    report_vms(run(selector))
}

/// `vk stop [REF…]`. Each REF is read once, all of them before anything is stopped (a REF
/// that cannot be read exits 2), then stopped together by [`lifecycle::stop`]. With none,
/// the current directory's VMs, or `--all`, stop as [`vms::stop_cmd`] selects them.
/// One deadline covers all targets.
fn stop_refs(
    targets: &[std::ffi::OsString],
    recursive: bool,
    all: bool,
    config: Option<&Path>,
    deadline: vms::Deadline,
    how: vms::StopHow,
) -> ExitCode {
    if targets.is_empty() {
        let selector = recursive.then_some(vms::Selector::Here { below: true });
        return report_vms(vms::stop_cmd(selector, all, deadline, how));
    }
    let read: anyhow::Result<Vec<_>> = targets
        .iter()
        .map(|t| vms::Ref::parse(t).and_then(|r| vms::Selector::from_ref(r, recursive)))
        .collect();
    match read {
        Ok(refs) => lifecycle::stop(refs, config, deadline, how),
        Err(e) => {
            eprintln!("vk: {e:#}");
            exit_code(2)
        }
    }
}

/// Print what [`act_on_vms`]'s action reports; exit 1 unless it did it to every VM.
fn report_vms(result: anyhow::Result<(String, bool)>) -> ExitCode {
    match result {
        Ok((report, all_ok)) => match write_report(&report) {
            ExitCode::SUCCESS if !all_ok => exit_code(1),
            code => code,
        },
        Err(e) => fail(&e, 2),
    }
}

/// Resolve a Windows build's shared registry: `--cache-registry` and `--cache-insecure`
/// override `[build]`. Only registry servers can be shared across hosts. Reject a store on
/// disk named on the command line; ignore one named in config. With nothing configured,
/// use no registry and skip resolving the on-disk builtin store that Linux builds default to.
fn windows_registry(
    cli: Option<&str>,
    insecure: bool,
    b: &config::Build,
) -> anyhow::Result<Option<config::Registry>> {
    let cache = build::CacheOpts::resolve(cli, insecure, b);
    let registry = if cache.registry.is_some() {
        build::shared_cache_registry(&cache)?
    } else {
        None
    };
    if let Some(named) = cli
        && named != "none"
        && registry.is_none()
    {
        anyhow::bail!(
            "--cache-registry {named}: a Windows build shares only through a registry server, \
             not a store on disk"
        );
    }
    if insecure && registry.is_none() {
        anyhow::bail!("--cache-insecure: this Windows build uses no registry server");
    }
    Ok(registry)
}

/// The build cache registry `vk registry put|get` use: `--cache-registry`, else
/// `[build] cache_registry`, else the builtin store.
fn files_registry(
    cfg: &config::Config,
    cache_registry: Option<&str>,
    cache_insecure: bool,
) -> anyhow::Result<config::Registry> {
    let cache = build::CacheOpts::resolve(cache_registry, cache_insecure, &cfg.build);
    build::cache_registry(&cache)?.ok_or_else(|| {
        anyhow::anyhow!(
            "the build cache is off (`none`): set [build] cache_registry or pass --cache-registry"
        )
    })
}

fn fail(e: &anyhow::Error, code: i32) -> ExitCode {
    use std::io::Write;
    // Not `eprintln!`, which panics when the write fails: the job supervisor's stderr is a log
    // on the job dir's filesystem, and filling that would turn every error into exit 101.
    let _ = writeln!(std::io::stderr(), "virtkit: error: {e:#}");
    exit_code(code)
}

/// Whether `e` is a control-plane transport failure — the VM's vsock link was refused, reset,
/// broke, hit EOF, or timed out — rather than a refusal the manager sent back. Retrying the same
/// wedged VM will not help, so `vk service` appends a restart hint when this holds.
fn control_plane_unreachable(e: &anyhow::Error) -> bool {
    use std::io::ErrorKind::{
        BrokenPipe, ConnectionRefused, ConnectionReset, TimedOut, UnexpectedEof,
    };
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                ConnectionReset | ConnectionRefused | BrokenPipe | UnexpectedEof | TimedOut
            )
        })
    })
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
            Ok(parsed) => {
                use std::io::Write;
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
    ["systemd://", "vsock://", "vsock-auto://", "tcp://"]
        .iter()
        .any(|scheme| s.starts_with(scheme))
}

/// The console log of the VM `target` selects (a REF, default cwd), or of its compose
/// sibling `service`: `<state dir>/console.log` — the file the run's VMM writes the serial
/// console to. A sibling's runtime dir is what its exec address names. Also returns what
/// still writes it, for a follow to watch; `None` for a stopped VM's.
fn console_log_path(
    target: Option<&Path>,
    service: Option<&str>,
) -> anyhow::Result<(PathBuf, Option<Writer>)> {
    let (sel, service) = vms::resolve_target(target.map(Path::as_os_str), service)?;
    let (sel, entry) = vms::at_most_one(sel)?;
    let Some(entry) = entry else {
        // The registry only lists live VMs, but the console of one that just died is exactly
        // what a reader reaches for, and its state dir keeps it: a name still leads there, as
        // does the state directory itself. A stopped service's console is in its `svc-*` dir.
        // A services-only run registers no VM: its lock on the state dir says it still runs.
        let not_found = || anyhow::anyhow!("{}", sel.not_found().trim_end());
        let state = stopped_dir(&sel).ok_or_else(not_found)?;
        let dir = match service {
            Some(name) => state.join(format!("svc-{name}")),
            None => state.to_path_buf(),
        };
        let log = dir.join(run::CONSOLE_LOG);
        let writer = vms::dir_locked(state).then(|| Writer::Run(state.to_path_buf()));
        return if log.is_file() {
            Ok((log, writer))
        } else {
            Err(not_found())
        };
    };
    let dir = match service {
        None => entry.state_dir.clone(),
        // `vsock-auto://<svc-dir>/vsock.sock:4444`: the directory is the socket's parent.
        Some(name) => match resolve_service_addr(&entry, &name)? {
            SocketAddr::VsockAuto { path, .. } => path
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| anyhow::anyhow!("service {name:?}: odd exec address"))?,
            other => anyhow::bail!("service {name:?}: exec address {other} names no directory"),
        },
    };
    Ok((
        dir.join(run::CONSOLE_LOG),
        Some(Writer::Vm(Box::new(entry))),
    ))
}

/// What still writes a console a follow reads.
#[derive(Debug)]
enum Writer {
    /// a registered VM, the same `vk run` as when the console was found
    Vm(Box<vms::VmEntry>),
    /// a run that registers no VM (a services-only compose run), by the state dir it locks
    Run(PathBuf),
}

impl Writer {
    fn alive(&self) -> bool {
        match self {
            Writer::Vm(entry) => vms::still_registered(entry),
            Writer::Run(dir) => vms::dir_locked(dir),
        }
    }
}

/// Where a VM that no longer runs left its state, by the selector its REF resolved to: a
/// name's state dir, or a directory taken as the state dir itself. A pid leads nowhere.
fn stopped_dir(sel: &vms::Selector) -> Option<&Path> {
    match sel {
        vms::Selector::Named { dir, .. } | vms::Selector::Dir { dir, .. } => Some(dir),
        vms::Selector::Pid(_) | vms::Selector::Here { .. } => None,
    }
}

/// The state dir a REF stands for, running or not: a running VM's, a name's, or a path
/// taken as the state dir itself. Several running VMs matching is an error, not a fallback.
fn state_dir_of(target: &std::ffi::OsStr) -> anyhow::Result<PathBuf> {
    let (sel, service) = vms::resolve_target(Some(target), None)?;
    if service.is_some() {
        anyhow::bail!("ssh reaches a VM, not one of its compose services");
    }
    match vms::at_most_one(sel)? {
        (_, Some(entry)) => Ok(entry.state_dir),
        (sel, None) => stopped_dir(&sel)
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow::anyhow!("{}", sel.not_found().trim_end())),
    }
}

/// Find the console log in the named state or CI job `dir` without consulting the registry.
fn exact_console_log_path(dir: &Path) -> anyhow::Result<PathBuf> {
    let path = dir.join(run::CONSOLE_LOG);
    if !path.is_file() {
        anyhow::bail!("{}: no console log there", dir.display());
    }
    Ok(path)
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

/// The first window [`console_tail`] reads back from a console's end.
const TAIL_WINDOW: u64 = 1 << 20;

/// Print `path`'s console lines from `sources` (all when empty) at least `level` severe, the
/// last `lines` of them (all when 0); with `follow`, keep printing what is appended until
/// Ctrl-C or a closed pipe (`… | head`). Following also ends when the registry no longer
/// lists the writer or a services-only run releases its state-dir lock. With no writer,
/// print the console once.
async fn show_console_log(
    path: &Path,
    writer: Option<&Writer>,
    sources: &[consolelog::Source],
    level: Option<consolelog::Level>,
    lines: usize,
    follow: bool,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut out = std::io::stdout().lock();
    let reading = || format!("reading {}", path.display());
    let (mut offset, mut pieces) = if lines == 0 {
        // With no bound asked for, print as we go and hold nothing.
        let mut pieces = consolelog::Pieces::default();
        let mut stopped = None;
        let offset = scan_console(&mut file, 0, &mut pieces, |line| {
            if !consolelog::wanted(&line, sources, level) {
                return true;
            }
            match broken_pipe(writeln!(out, "{}", line.text)) {
                Ok(false) => true,
                // The reader closed (`Ok(true)`), or the write failed.
                r => {
                    stopped = Some(r);
                    false
                }
            }
        })
        .with_context(reading)?;
        if let Some(r) = stopped {
            return r.map(|_| ());
        }
        (offset, pieces)
    } else {
        let (tail, offset, pieces) =
            console_tail(&mut file, sources, level, lines, TAIL_WINDOW).with_context(reading)?;
        for l in &tail {
            if broken_pipe(writeln!(out, "{l}"))? {
                return Ok(());
            }
        }
        (offset, pieces)
    };
    let Some(writer) = writer.filter(|_| follow) else {
        return broken_pipe(out.flush()).map(|_| ());
    };
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
        // what says the writer is gone (an unreadable registry counts as gone). Checked on its own slower beat — resolving
        // walks and locks every registered VM's state dir, which a run starting up races
        // against.
        if registry_check.elapsed() >= REGISTRY_POLL {
            registry_check = std::time::Instant::now();
            if !writer.alive() {
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
            pieces = consolelog::Pieces::default();
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
        for piece in complete.split_inclusive('\n') {
            let l = pieces.classify(piece);
            if consolelog::wanted(&l, sources, level) && broken_pipe(writeln!(out, "{}", l.text))? {
                return Ok(());
            }
        }
        if broken_pipe(out.flush())? {
            return Ok(());
        }
    }
}

/// The last `lines` (at least one) console lines of `file` from `sources` at least `level`
/// severe, with the offset read to and the classifier's state there. Read back from the end:
/// from the first line that starts in the last `window` bytes, the window doubled while it
/// holds fewer than `lines` of them and does not reach the start. A bound thus costs no more
/// on a console that has grown for days than on a fresh one — unless a filter matches
/// rarely, which reads further back, up to the whole console. A line longer than
/// [`MAX_PARTIAL_LINE`] counts a line a piece, so at most `lines` pieces of
/// `MAX_PARTIAL_LINE` bytes each are held (more once invalid UTF-8 is decoded lossily).
fn console_tail(
    file: &mut std::fs::File,
    sources: &[consolelog::Source],
    level: Option<consolelog::Level>,
    lines: usize,
    mut window: u64,
) -> std::io::Result<(std::collections::VecDeque<String>, u64, consolelog::Pieces)> {
    use std::io::{BufRead, Seek};
    let len = file.metadata()?.len();
    loop {
        let back = len.saturating_sub(window);
        // The first line that starts at `back` or after: a read begun a byte early, through
        // the first newline. A line holding the whole window leaves none, and a wider one.
        let from = match back.checked_sub(1) {
            None => 0,
            Some(before) => {
                file.seek(std::io::SeekFrom::Start(before))?;
                let skipped = std::io::BufReader::new(&mut *file).skip_until(b'\n')?;
                before.saturating_add(skipped as u64)
            }
        };
        let mut tail = std::collections::VecDeque::new();
        let mut pieces = consolelog::Pieces::default();
        let offset = scan_console(file, from, &mut pieces, |line| {
            if consolelog::wanted(&line, sources, level) {
                if tail.len() == lines {
                    tail.pop_front();
                }
                tail.push_back(line.text);
            }
            true
        })?;
        if tail.len() >= lines || back == 0 {
            return Ok((tail, offset, pieces));
        }
        window = window.saturating_mul(2);
    }
}

/// Classify the console lines of `file` from byte `from`, a line's start, to its end, handing
/// each to `each` until it returns `false`, and return the offset read to. Streamed, not
/// slurped: a long-lived guest's console grows without bound and nothing rotates it. Read a
/// line at a time as bytes — the console is written by whatever the guest runs, so it is not
/// text — and decoded lossily per line, for the reason `vk atop` reads its own log lossily:
/// one stray byte must not cost the reader the whole log.
fn scan_console(
    file: &mut std::fs::File,
    from: u64,
    pieces: &mut consolelog::Pieces,
    mut each: impl FnMut(consolelog::Line) -> bool,
) -> std::io::Result<u64> {
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(from))?;
    let mut reader = std::io::BufReader::new(file);
    let mut offset = from;
    let mut raw = Vec::new();
    loop {
        raw.clear();
        let n = read_console_line(&mut reader, &mut raw)?;
        if n == 0 {
            return Ok(offset);
        }
        offset = offset.saturating_add(n as u64);
        if !each(pieces.classify(&String::from_utf8_lossy(&raw))) {
            return Ok(offset);
        }
    }
}

/// Read one console line into `raw`, its newline included — or, of one longer than
/// [`MAX_PARTIAL_LINE`], that many bytes, the rest left for the next read, as a follow prints
/// it — so a guest that never writes a newline cannot grow this process without bound.
/// `Ok(0)` at the end.
fn read_console_line(
    reader: &mut impl std::io::BufRead,
    raw: &mut Vec<u8>,
) -> std::io::Result<usize> {
    use std::io::{BufRead, Read};
    reader
        .by_ref()
        .take(MAX_PARTIAL_LINE as u64)
        .read_until(b'\n', raw)
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
            via,
        } => PublishAction::Ensure {
            state_dir: at(state_dir)?,
            name,
            listen,
            to,
            via,
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

/// `vk exec`, `cp`, `status` and `publish` resolve their target once so every check uses
/// the same VM. A REF defaults to the current directory. Either the REF or the service
/// option can select a compose service.
enum ExecTarget {
    Addr(SocketAddr),
    /// a Windows service's live qemu-ga socket, right under the directory the REF names
    Qga(PathBuf),
    Ref {
        sel: vms::Selector,
        vm: Option<Box<vms::VmEntry>>,
        service: Option<String>,
    },
}

/// Resolve `target` and `sibling`, given by `flag` (`--service` for `vk exec`, `--via` for
/// `vk publish`, so the error names what the caller actually typed).
fn exec_target(
    target: Option<&str>,
    sibling: Option<&str>,
    flag: &str,
) -> anyhow::Result<ExecTarget> {
    if let Some(addr) = target.filter(|t| is_agent_addr(t)) {
        if sibling.is_some() {
            anyhow::bail!("{flag} selects a VM by REF, not a raw agent address");
        }
        return Ok(ExecTarget::Addr(addr.parse::<SocketAddr>()?));
    }
    let (sel, service) = vms::resolve_target(target.map(std::ffi::OsStr::new), sibling)?;
    // A directory's own service socket answers first: a services-only run registers no VM,
    // and other VMs of the same project must not make the service it names ambiguous.
    let dir = match &sel {
        None => Some(Path::new(".")),
        Some(vms::Selector::Dir { dir, .. }) => Some(dir.as_path()),
        Some(_) => None,
    };
    if let (Some(dir), Some(svc)) = (dir, &service)
        && let Some(socket) = service_qga_socket(Some(dir), svc, || Ok(dir.to_path_buf()))?
    {
        return Ok(ExecTarget::Qga(socket));
    }
    let (sel, vm) = vms::at_most_one(sel)?;
    let vm = vm.map(Box::new);
    Ok(ExecTarget::Ref { sel, vm, service })
}

/// The running VM `vm` a REF's `sel` selected, or the error saying none runs there.
fn running_vm<'a>(
    sel: &vms::Selector,
    vm: &'a Option<Box<vms::VmEntry>>,
) -> anyhow::Result<&'a vms::VmEntry> {
    vm.as_deref()
        .ok_or_else(|| anyhow::anyhow!("{}", sel.not_found().trim_end()))
}

/// The agent to speak to: a compose service's when the target names one, else the VM's own.
fn resolve_exec_addr(target: &ExecTarget) -> anyhow::Result<SocketAddr> {
    match target {
        ExecTarget::Addr(addr) => Ok(addr.clone()),
        ExecTarget::Qga(socket) => anyhow::bail!(
            "that service is a Windows guest: it has no vk-agent, only qemu-ga at {}",
            socket.display()
        ),
        ExecTarget::Ref { sel, vm, service } => {
            let entry = running_vm(sel, vm)?;
            match service {
                None => entry.exec_addr.parse::<SocketAddr>(),
                Some(svc) => resolve_service_addr(entry, svc),
            }
        }
    }
}

/// The VM's qemu-ga socket, or a service's socket under `svc-<service>/` in its state dir.
/// [`exec_target`] checks a directory REF (default cwd) first. A name or pid selects only
/// its own run. Raw addresses and vk-agent guests, including Linux services, yield `None`.
/// A stale socket or a lookup that requires a missing running VM is an error.
fn windows_exec_socket(target: &ExecTarget) -> anyhow::Result<Option<PathBuf>> {
    let (sel, vm, service) = match target {
        ExecTarget::Addr(_) => return Ok(None),
        ExecTarget::Qga(socket) => return Ok(Some(socket.clone())),
        ExecTarget::Ref { sel, vm, service } => (sel, vm, service),
    };
    let registered = || Ok(running_vm(sel, vm)?.state_dir.clone());
    let Some(svc) = service else {
        return Ok(running_vm(sel, vm)?.guest_agent.clone());
    };
    match sel {
        vms::Selector::Dir { .. } | vms::Selector::Pid(_) | vms::Selector::Here { .. } => {
            service_qga_socket(None, svc, registered)
        }
        // A name's state dir is its run's, running or not: there is nowhere else to look.
        vms::Selector::Named { dir, .. } => service_qga_socket(Some(dir), svc, || Ok(dir.clone())),
    }
}

/// [`windows_exec_socket`] for a service: its socket under `named`, else under the run
/// `registered` returns. A socket nobody listens on is left from a run that ended (`vk stop`,
/// a crash) and is refused here, rather than waited on as a booting guest's would be.
fn service_qga_socket(
    named: Option<&Path>,
    service: &str,
    registered: impl FnOnce() -> anyhow::Result<PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
    let at = |run: &Path| {
        run.join(format!("svc-{service}"))
            .join(uefi::GUEST_AGENT_SOCKET)
    };
    let socket = match named.map(at) {
        Some(s) if s.exists() => s,
        _ => match at(&registered()?) {
            s if s.exists() => s,
            _ => return Ok(None),
        },
    };
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    match vk_core::unixpath::connect(&socket).map_err(|e| e.kind()) {
        Err(ConnectionRefused | NotFound) => {
            anyhow::bail!(
                "service {service} is not running (stale {})",
                socket.display()
            )
        }
        _ => Ok(Some(socket)),
    }
}

/// As [`resolve_exec_addr`], for a caller that already holds a path. Kept apart from the
/// `&str` form so a state dir that is not UTF-8 is an error here, rather than a `None`
/// that would quietly resolve the current directory's VM instead of the one asked for.
fn resolve_exec_addr_at(state_dir: &Path, via: Option<&str>) -> anyhow::Result<SocketAddr> {
    let Some(target) = state_dir.to_str() else {
        anyhow::bail!(
            "the state directory {} is not valid UTF-8",
            state_dir.display()
        );
    };
    // `ensure` canonicalizes the state dir, so only a hand-run `serve` reaches this
    // message — and `--via` is the right name there too.
    resolve_exec_addr(&exec_target(Some(target), via, "--via")?)
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
            via,
        } => {
            let addr = match resolve_exec_addr_at(&state_dir, via.as_deref()) {
                Ok(a) => a,
                Err(e) => return fail(&e, 2),
            };
            match publish::ensure(&state_dir, &name, &addr, &listen, &to, via.as_deref()).await {
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
            via,
            listen_fd,
            lock_fd,
        } => {
            let addr = match resolve_exec_addr_at(&state_dir, via.as_deref()) {
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
    vms::service_exec_addr(entry, service)
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

/// Parse a switch `--egress-cap`: `all`, or `<cidr,cidr>;<name,name>` as a restricted
/// allowlist (empty fields = deny), the shape of a `--source-egress` without its source.
fn parse_egress_cap(spec: &str) -> anyhow::Result<switch::Egress> {
    if spec == "all" {
        return Ok(switch::Egress::AllowAll);
    }
    let split = |s: &str| -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };
    let (ips, names) = spec.split_once(';').unwrap_or((spec, ""));
    switch::Egress::restricted(&split(ips), &split(names))
        .map_err(|e| anyhow::anyhow!("egress-cap {spec:?}: {e}"))
}

/// Parse the repeatable switch `--vm-name <ip>=<name>`.
fn parse_vm_names(
    specs: &[String],
) -> anyhow::Result<std::collections::HashMap<std::net::Ipv4Addr, String>> {
    specs
        .iter()
        .map(|spec| {
            let (ip, name) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("vm-name {spec:?}: want <ip>=<name>"))?;
            let ip = ip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|e| anyhow::anyhow!("vm-name {spec:?}: {e}"))?;
            Ok((ip, name.to_string()))
        })
        .collect()
}

use crate::ensure::parse_uuid;

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(code.clamp(1, 255) as u8)
}

/// Write a failing stage's exit code to `BUILD_EXIT_CODE_FILE`, if gitlab-runner provides it,
/// for `allow_failure: exit_codes` and the job's reported exit code.
fn write_build_exit_code(path: Option<std::ffi::OsString>, code: i32) {
    if let Some(path) = path {
        // Without it the job still fails, with the generic code.
        let _ = std::fs::write(path, format!("{code}\n"));
    }
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
    fn a_windows_build_shares_only_through_a_registry_server() {
        let none = config::Build::default();
        let on_disk = config::Build {
            cache_registry: Some("/var/cache/vk".to_string()),
            ..Default::default()
        };
        assert!(windows_registry(None, false, &none).unwrap().is_none());
        assert!(
            windows_registry(Some("none"), false, &on_disk)
                .unwrap()
                .is_none()
        );
        // A store the config names is not shared, and not an error either.
        assert!(windows_registry(None, false, &on_disk).unwrap().is_none());
        let configured = config::Build {
            cache_registry: Some("127.0.0.1:5000".to_string()),
            ..Default::default()
        };
        assert!(
            windows_registry(None, false, &configured)
                .unwrap()
                .is_some()
        );
        assert!(windows_registry(Some("/var/cache/vk"), false, &none).is_err());
        assert!(windows_registry(None, true, &none).is_err());
        assert!(windows_registry(Some("none"), true, &none).is_err());
        let server = windows_registry(Some("127.0.0.1:5000"), true, &none)
            .unwrap()
            .unwrap();
        assert!(server.local_root().is_none());
    }

    #[test]
    fn a_failing_scripts_exit_code_goes_to_build_exit_code_file() {
        let path = std::env::temp_dir().join(format!("vk-exit-code-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_build_exit_code(Some(path.clone().into()), 3);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "3\n");
        write_build_exit_code(None, 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_notes_an_omitted_default_executor() {
        // A pure-default host: the section is dropped and the note points at --example.
        let note = executor_omitted_note(&config::Config::default())
            .expect("a default executor prints the omission note");
        assert!(note.contains("[executor] omitted") && note.contains("vk config --example"));
        // Any configured executor key shows the section again, with no note.
        let cfg: config::Config = toml::from_str("[executor.vm]\ncpus = 6\n").unwrap();
        assert!(executor_omitted_note(&cfg).is_none());
    }

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
        assert!(a.allows_host("corp.com") && a.overlaps_cidr("10.1.2.3/32").unwrap());
        assert!(!a.allows_host("evil.com"));
        // The empty spec is deny-all (restricted, not AllowAll).
        let b = &m[&"10.0.0.6".parse().unwrap()];
        assert!(!b.allows_host("corp.com") && !b.overlaps_cidr("10.0.0.0/8").unwrap());
        // A bad source ip is rejected.
        assert!(parse_source_egress(&["nope;;".to_string()]).is_err());
    }

    #[test]
    fn egress_caps_and_vm_names_parse() {
        assert!(matches!(
            parse_egress_cap("all").unwrap(),
            switch::Egress::AllowAll
        ));
        let cap = parse_egress_cap("10.0.0.0/8;crates.io").unwrap();
        assert!(cap.allows_host("crates.io") && !cap.allows_host("evil.com"));
        // Empty fields deny, as a source's allowlist's do.
        let none = parse_egress_cap(";").unwrap();
        assert!(!none.allows_host("crates.io"));
        assert!(parse_egress_cap("nope;").is_err());
        let names = parse_vm_names(&["10.0.0.5=db".to_string()]).unwrap();
        assert_eq!(names[&"10.0.0.5".parse().unwrap()], "db");
        assert!(parse_vm_names(&["db".to_string()]).is_err());
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

    /// The service-exec wrapper puts the guest's argv after `--`, so a word the guest chose
    /// is never one of this vk's own flags: `--config=/x` in the program's slot stays the
    /// guest's argv[0], reaches no config, and is refused as not a service exec request.
    #[tokio::test]
    async fn service_exec_keeps_the_guests_argv_away_from_vk_flags() {
        let cli = Cli::try_parse_from([
            "vk",
            "service-exec",
            "/nonexistent/job",
            "--",
            "--config=/x",
            "vk",
            "exec",
            "--service",
            "db",
            "--",
            "true",
        ])
        .unwrap();
        assert_eq!(cli.config, None);
        let Cmd::ServiceExec { dir, allow, argv } = cli.cmd else {
            panic!("expected service-exec")
        };
        assert_eq!(allow, None);
        assert_eq!(argv[0], "--config=/x");
        assert_eq!(argv[1..3], ["vk", "exec"]);
        assert_eq!(
            vm::service_exec(&dir, vm::HostForms::EXEC, None, &argv).await,
            ExitCode::from(2),
            "{argv:?}"
        );
        // Without the `--` nothing runs at all.
        assert!(Cli::try_parse_from(["vk", "service-exec", "/job", "vk", "exec"]).is_err());
    }

    /// `--tidy` takes no REF, timeout or other stop option.
    #[test]
    fn stop_tidy_takes_nothing_else() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["vk", "stop", "--tidy"], args].concat());
        assert!(matches!(
            parse(&[]).unwrap().cmd,
            Cmd::Stop { tidy: true, .. }
        ));
        for other in [
            &["app"][..],
            &["--timeout", "5"],
            &["--all"],
            &["--kill"],
            &["-r"],
        ] {
            assert!(parse(other).is_err(), "{other:?}");
        }
    }

    /// Before `--`, `--allow` selects the wrapper's forms; after it, `--allow` belongs to
    /// the guest. Omitting it keeps exec-only access for serves started by an earlier vk.
    #[test]
    fn service_exec_takes_its_allowed_forms_before_the_guests_argv() {
        let allowed = |argv: &[&str]| {
            let Cmd::ServiceExec { allow, argv, .. } = Cli::try_parse_from(argv).unwrap().cmd
            else {
                panic!("expected service-exec")
            };
            (allow, argv)
        };
        let both = vm::HostForms {
            exec: true,
            build: true,
        };
        assert_eq!(
            allowed(&[
                "vk",
                "service-exec",
                "/job",
                "--allow",
                "exec,build",
                "--",
                "vk"
            ]),
            (Some(both), vec!["vk".to_string()])
        );
        assert_eq!(
            allowed(&["vk", "service-exec", "/job", "--", "--allow", "build"]),
            (None, vec!["--allow".to_string(), "build".to_string()])
        );
        for bad in ["", "shell"] {
            let argv = ["vk", "service-exec", "/job", "--allow", bad, "--", "vk"];
            assert!(Cli::try_parse_from(argv).is_err(), "{bad:?}");
        }
        // The config a build loads is the one given before the `--`, never the guest's.
        let cli = Cli::try_parse_from([
            "vk",
            "service-exec",
            "/job",
            "--allow",
            "build",
            "--config",
            "/etc/vk.toml",
            "--",
            "vk",
            "build",
            "--config",
            "/x",
        ])
        .unwrap();
        assert_eq!(cli.config.as_deref(), Some(Path::new("/etc/vk.toml")));
        // What the node passes parses back to the forms and config it gave.
        let (_, args) = vm::service_exec_command(
            Path::new("/job"),
            "exec,build".parse().unwrap(),
            Some(Path::new("/etc/vk.toml")),
        )
        .unwrap();
        let mut argv = vec!["vk".to_string()];
        argv.extend(args);
        argv.extend(["vk".to_string(), "build".to_string()]);
        let cli = Cli::try_parse_from(&argv).unwrap();
        assert_eq!(cli.config.as_deref(), Some(Path::new("/etc/vk.toml")));
        let Cmd::ServiceExec { allow, argv, .. } = cli.cmd else {
            panic!("expected service-exec")
        };
        assert_eq!(allow, Some(both));
        assert_eq!(argv, ["vk", "build"]);
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

    #[test]
    fn console_cli_takes_an_optional_target() {
        let cli = Cli::try_parse_from(["vk", "console"]).unwrap();
        let Cmd::Console { target } = cli.cmd else {
            panic!("expected Cmd::Console")
        };
        assert_eq!(target, None);

        let cli = Cli::try_parse_from(["vk", "console", "/run/win"]).unwrap();
        let Cmd::Console { target } = cli.cmd else {
            panic!("expected Cmd::Console")
        };
        assert_eq!(target.as_deref(), Some("/run/win"));

        assert!(Cli::try_parse_from(["vk", "console", "a", "b"]).is_err());
    }

    /// `vk publish` names the dialing sibling `--via`, and still answers to `--service`.
    #[test]
    fn publish_takes_via_under_either_spelling() {
        let via = |args: &[&str]| {
            let cli = Cli::try_parse_from(args).unwrap();
            match cli.cmd {
                Cmd::Publish {
                    via, action: None, ..
                } => via,
                Cmd::Publish {
                    action: Some(PublishAction::Ensure { via, .. }),
                    ..
                } => via,
                _ => panic!("expected Cmd::Publish"),
            }
        };
        let addrs = [
            "--listen",
            "tcp://127.0.0.1:8443",
            "--to",
            "tcp://runner:443",
        ];
        let foreground = |flag: &str| {
            let mut args = vec!["vk", "publish", flag, "db"];
            args.extend(addrs);
            via(&args)
        };
        assert_eq!(foreground("--via").as_deref(), Some("db"));
        assert_eq!(foreground("--service").as_deref(), Some("db"));

        let ensure = |flag: &str| {
            let mut args = vec![
                "vk", "publish", "ensure", "/state", "--name", "pg", flag, "db",
            ];
            args.extend(addrs);
            via(&args)
        };
        assert_eq!(ensure("--via").as_deref(), Some("db"));
        assert_eq!(ensure("--service").as_deref(), Some("db"));

        // The primary dials when neither is given.
        let mut bare = vec!["vk", "publish", "ensure", "/state", "--name", "pg"];
        bare.extend(addrs);
        assert_eq!(via(&bare), None);
    }

    /// Check that `serve` parses the argv from `ensure`. This internal command needs
    /// a test to catch flags renamed on only one side.
    #[test]
    fn the_spawned_publisher_argv_parses_as_serve() {
        let listen = "tcp://127.0.0.1:8443".parse().unwrap();
        for sibling in [Some("db"), None] {
            let argv = crate::publish::serve_argv(
                Path::new("/state/app"),
                "pg",
                &listen,
                "tcp://runner:443",
                sibling,
                3,
                4,
            );
            let cli = Cli::try_parse_from(std::iter::once("vk".into()).chain(argv)).unwrap();
            let Cmd::Publish {
                action: Some(PublishAction::Serve { name, via, .. }),
                ..
            } = cli.cmd
            else {
                panic!("expected `publish serve`")
            };
            assert_eq!(name, "pg");
            assert_eq!(via.as_deref(), sibling);
        }
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
            fix,
        } = cli.cmd
        else {
            panic!("expected Cmd::Check")
        };
        assert!(feature.is_empty() && min_version.is_none() && !fix);

        let cli = Cli::try_parse_from(["vk", "check", "--min-version", "v0.45"]).unwrap();
        let Cmd::Check { min_version, .. } = cli.cmd else {
            panic!("expected Cmd::Check")
        };
        assert_eq!(
            min_version.map(|v| v.to_string()).as_deref(),
            Some("0.45.0")
        );

        assert!(Cli::try_parse_from(["vk", "check", "--min-version", "next"]).is_err());

        // Applying the fixes is opt-in, and takes no value.
        let cli = Cli::try_parse_from(["vk", "check", "--fix"]).unwrap();
        let Cmd::Check { fix, .. } = cli.cmd else {
            panic!("expected Cmd::Check")
        };
        assert!(fix);
        assert!(Cli::try_parse_from(["vk", "check", "--fix", "kvm"]).is_err());
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

    /// `vk run --allow-name/--allow-ip` repeat into the run's allowlist, `--compose` gives
    /// the run the switch that enforces it, and a tap primary, whose egress bypasses the
    /// switch, refuses them. [`run::egress_from_flags`]'s own tests cover the rest.
    #[test]
    fn run_egress_flags_repeat_and_refuse_a_tap() {
        let egress_of = |argv: &[&str]| {
            let cli = Cli::try_parse_from(argv).unwrap();
            let Cmd::Run {
                allow_ip,
                allow_name,
                egress_restrict,
                net,
                compose,
                ..
            } = cli.cmd
            else {
                panic!("expected Cmd::Run")
            };
            run::egress_from_flags(
                &allow_ip,
                &allow_name,
                egress_restrict,
                net || compose.is_some(),
            )
        };
        let argv = [
            "vk",
            "run",
            "--net",
            "--allow-name",
            "debian.org",
            "--allow-name",
            "pypi.org",
            "--allow-ip",
            "192.0.2.10/32:22",
            "debian:12",
        ];
        assert_eq!(
            egress_of(&argv).unwrap(),
            Some(switch::EgressFile {
                allow_ip: vec!["192.0.2.10/32:22".into()],
                allow_name: vec!["debian.org".into(), "pypi.org".into()],
            })
        );
        assert_eq!(
            egress_of(&[
                "vk",
                "run",
                "--compose",
                "c.yml",
                "--allow-name",
                "debian.org"
            ])
            .unwrap(),
            Some(switch::EgressFile {
                allow_ip: vec![],
                allow_name: vec!["debian.org".into()],
            })
        );
        for flag in [
            &["--allow-name", "debian.org"][..],
            &["--allow-ip", "10.0.0.0/8"],
            &["--egress-restrict"],
        ] {
            let mut argv = vec!["vk", "run", "--net", "--tap", "vk0"];
            argv.extend_from_slice(flag);
            argv.push("debian:12");
            let Err(err) = Cli::try_parse_from(&argv) else {
                panic!("{flag:?} with --tap must be rejected")
            };
            assert!(err.to_string().contains("--tap"), "{err}");
        }
    }

    /// `vk switch`'s lists fail by the flag at fault, before the switch binds anything.
    #[test]
    fn switch_flags_name_the_list_at_fault() {
        let err = |ips: &[&str], names: &[&str]| {
            let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            format!(
                "{:#}",
                switch_egress_from_flags(&v(ips), &v(names), false)
                    .err()
                    .unwrap()
            )
        };
        assert!(err(&[], &["*.a.com"]).starts_with("--allow-name "));
        assert!(err(&["10.0.0.0/33"], &[]).starts_with("--allow-ip"));
        assert!(switch_egress_from_flags(&[], &[], false).is_ok());
        assert!(switch_egress_from_flags(&[], &["a.com".into()], true).is_ok());
    }

    /// `--numa` takes a mode or a node id, and nothing else — a typo names a node the host
    /// has to have, so it must not reach the boot as one.
    #[test]
    fn run_numa_flag_takes_a_mode_or_a_node() {
        let numa_of = |argv: &[&str]| {
            let cli = Cli::try_parse_from(argv).unwrap();
            let Cmd::Run { numa, .. } = cli.cmd else {
                panic!("expected Cmd::Run")
            };
            numa
        };
        assert_eq!(numa_of(&["vk", "run", "debian:12"]), None);
        assert_eq!(
            numa_of(&["vk", "run", "--numa", "off", "debian:12"]),
            Some(numa::NumaArg::Off)
        );
        assert_eq!(
            numa_of(&["vk", "run", "--numa", "interleave", "debian:12"]),
            Some(numa::NumaArg::Interleave)
        );
        assert_eq!(
            numa_of(&["vk", "run", "--numa", "1", "debian:12"]),
            Some(numa::NumaArg::Node(1))
        );
        let Err(err) = Cli::try_parse_from(["vk", "run", "--numa", "node1", "debian:12"]) else {
            panic!("--numa node1 must be rejected")
        };
        assert!(err.to_string().contains("off, auto, interleave"), "{err}");
    }

    /// `vk node service install` stops in an hour by default, and takes a duration.
    #[test]
    fn node_service_install_takes_a_stop_timeout() {
        let timeout_of = |argv: &[&str]| {
            let cli = Cli::try_parse_from(argv).unwrap();
            let Cmd::Node {
                cmd:
                    NodeCmd::Service {
                        cmd: NodeServiceCmd::Install { stop_timeout, .. },
                    },
            } = cli.cmd
            else {
                panic!("expected `vk node service install`")
            };
            stop_timeout.as_secs()
        };
        assert_eq!(timeout_of(&["vk", "node", "service", "install"]), 3600);
        assert_eq!(
            timeout_of(&["vk", "node", "service", "install", "--stop-timeout", "10m"]),
            600
        );
        assert!(
            Cli::try_parse_from(["vk", "node", "service", "install", "--stop-timeout", "1d"])
                .is_err()
        );
    }

    /// `--workdir-cache` parses into `ShareCache` and defaults to `Auto`. An explicit value
    /// requires `--workdir`; internal-only `Immutable` and unknown modes are rejected.
    #[test]
    fn run_workdir_cache_maps_to_share_cache_and_requires_workdir() {
        let cache_of = |argv: &[&str]| {
            let cli = Cli::try_parse_from(argv).unwrap();
            let Cmd::Run { workdir_cache, .. } = cli.cmd else {
                panic!("expected Cmd::Run")
            };
            workdir_cache
        };
        assert_eq!(
            cache_of(&["vk", "run", "debian:12"]),
            crate::vmm::ShareCache::Auto
        );
        assert_eq!(
            cache_of(&["vk", "run", "--workdir", "/w", "debian:12"]),
            crate::vmm::ShareCache::Auto
        );
        assert_eq!(
            cache_of(&[
                "vk",
                "run",
                "--workdir",
                "/w",
                "--workdir-cache",
                "ephemeral",
                "debian:12"
            ]),
            crate::vmm::ShareCache::Ephemeral
        );
        assert!(
            Cli::try_parse_from(["vk", "run", "--workdir-cache", "ephemeral", "debian:12"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "vk",
                "run",
                "--workdir",
                "/w",
                "--workdir-cache",
                "immutable",
                "debian:12"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "vk",
                "run",
                "--workdir",
                "/w",
                "--workdir-cache",
                "bogus",
                "debian:12"
            ])
            .is_err()
        );
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
            pid_start_ticks: None,
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
            guest_agent: None,
            control: None,
        };
        assert_eq!(
            resolve_service_addr(&entry, "db").unwrap(),
            "vsock-auto:///state/app/svc-db/vsock.sock:4444"
                .parse::<SocketAddr>()
                .unwrap()
        );

        // The error names the flag the caller typed, not whichever one the helper prefers.
        let err = exec_target(Some("vsock://3:4444"), Some("db"), "--service")
            .err()
            .unwrap();
        assert!(err.to_string().starts_with("--service selects"), "{err}");
        let err = exec_target(Some("vsock://3:4444"), Some("db"), "--via")
            .err()
            .unwrap();
        assert!(err.to_string().starts_with("--via selects"), "{err}");
    }

    // A closed reader (`vk logs | head`) is the reader having seen enough, not this
    // command's failure; anything else is.
    #[test]
    fn a_closed_pipe_is_not_a_failure() {
        assert!(!broken_pipe(Ok(())).unwrap());
        assert!(broken_pipe(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))).unwrap());
        assert!(broken_pipe(Err(std::io::Error::from(std::io::ErrorKind::StorageFull))).is_err());
    }

    /// A console of `lines`, in a scratch file.
    fn console_file(tag: &str, lines: &str) -> (PathBuf, std::fs::File) {
        let dir = std::env::temp_dir().join(format!("vk-console-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("console.log"), lines).unwrap();
        let file = std::fs::File::open(dir.join("console.log")).unwrap();
        (dir, file)
    }

    // The last lines are read back from the end, a window that holds too few of them widened
    // until it does, whatever the filter.
    #[test]
    fn a_console_tail_is_read_back_from_the_end() {
        use consolelog::{Level, Source};
        let mut text = String::new();
        for i in 0..200 {
            if i % 50 == 0 {
                text.push_str(&format!("12:00:00 [WARN] vk-agent w{i}\n"));
            } else {
                text.push_str(&format!("guest {i}\n"));
            }
        }
        text.push_str("torn");
        let (dir, mut file) = console_file("tail", &text);
        let len = text.len() as u64;
        // A window cutting a line in two, then lines that are all within reach.
        let (tail, offset, _) = console_tail(&mut file, &[], None, 3, 20).unwrap();
        assert_eq!(tail, ["guest 198", "guest 199", "torn"]);
        assert_eq!(offset, len);
        // Rare matches: read back until there are enough, or to the start.
        let (tail, offset, _) = console_tail(&mut file, &[], Some(Level::Warn), 3, 20).unwrap();
        assert_eq!(
            tail,
            [
                "12:00:00 [WARN] vk-agent w50",
                "12:00:00 [WARN] vk-agent w100",
                "12:00:00 [WARN] vk-agent w150"
            ]
        );
        assert_eq!(offset, len);
        let (tail, _, _) = console_tail(&mut file, &[Source::Agent], None, 10, 20).unwrap();
        assert_eq!(tail.len(), 4);
        // A window wider than the console reads it whole.
        let (tail, _, _) = console_tail(&mut file, &[], None, 1000, 1 << 30).unwrap();
        assert_eq!(tail.len(), 201);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The pieces of a line too long to hold at once are all the line's: selected by its
    // prefix, each counting as one of the last lines.
    #[test]
    fn a_long_line_s_pieces_are_classified_by_its_start() {
        use consolelog::Level;
        let long = format!("12:00:00 [WARN] vk-agent {}", "x".repeat(MAX_PARTIAL_LINE));
        let text = format!("12:00:00 [WARN] vk-agent before\n{long}\nguest after\n");
        let (dir, mut file) = console_file("pieces", &text);
        let (tail, _, _) = console_tail(&mut file, &[], Some(Level::Warn), 10, 64).unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0], "12:00:00 [WARN] vk-agent before");
        assert_eq!(tail[1].len() + tail[2].len(), long.len());
        assert!(tail[2].bytes().all(|b| b == b'x'));
        let (tail, _, _) = console_tail(&mut file, &[], None, 2, 64).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[1], "guest after");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A console line is read a bounded piece at a time, its newline ending the last piece.
    #[test]
    fn a_console_line_is_read_at_most_a_bound_at_once() {
        let long = "x".repeat(MAX_PARTIAL_LINE + 5);
        let mut reader = std::io::Cursor::new(format!("a\n{long}\nb").into_bytes());
        let mut pieces = Vec::new();
        loop {
            let mut raw = Vec::new();
            if read_console_line(&mut reader, &mut raw).unwrap() == 0 {
                break;
            }
            pieces.push(raw);
        }
        assert_eq!(pieces.len(), 4);
        assert_eq!(pieces[0], b"a\n");
        assert_eq!(pieces[1], long.as_bytes()[..MAX_PARTIAL_LINE]);
        assert_eq!(pieces[2], b"xxxxx\n");
        assert_eq!(pieces[3], b"b");
    }

    // `vk logs --exact` reads the named dir's console, and only that.
    #[test]
    fn an_exact_console_is_the_named_dir_s() {
        let dir = std::env::temp_dir().join(format!("vk-logs-exact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(exact_console_log_path(&dir).is_err());
        std::fs::write(dir.join(run::CONSOLE_LOG), b"").unwrap();
        assert_eq!(
            exact_console_log_path(&dir).unwrap(),
            dir.join(run::CONSOLE_LOG)
        );
        let cli = Cli::try_parse_from(["vk", "logs", "--exact", "-n", "5", "--", "/x"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Logs { exact: true, .. }));
        assert!(Cli::try_parse_from(["vk", "logs", "--exact"]).is_err());
        assert!(Cli::try_parse_from(["vk", "logs", "--exact", "-f", "/x"]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `path` spelled relative to `from`, as `../../…/path`.
    fn relative_to(from: &Path, path: &Path) -> String {
        let up = "../".repeat(from.components().count().saturating_sub(1));
        format!("{up}{}", path.strip_prefix("/").unwrap().display())
    }

    // `vk logs` on a directory the registry does not know reads its console anyway — a VM
    // that just exited is exactly the one whose console is wanted, and its state dir keeps it.
    #[test]
    fn a_console_is_read_from_a_state_dir_the_registry_has_dropped() {
        let homes = crate::dev::testutil::Homes::new("logs");
        std::fs::create_dir_all(homes.dir().join("saved/svc-db")).unwrap();
        let dir = std::fs::canonicalize(homes.dir().join("saved")).unwrap();
        // Nothing there yet: the registry's own error is what the caller gets.
        let err = console_log_path(Some(&dir), None).unwrap_err();
        assert!(err.to_string().contains("no running vk VM"), "{err}");
        // With a console in it, the directory is read as the state dir it is, and there is
        // no VM left to follow.
        std::fs::write(dir.join(run::CONSOLE_LOG), b"13:46:39 [INFO] hi\n").unwrap();
        let log = dir.join(run::CONSOLE_LOG);
        let found = console_log_path(Some(&dir), None).unwrap();
        assert!(found.0 == log && found.1.is_none());
        // The same through a nested relative path, a quoted `~/…` and a name.
        let cwd = std::env::current_dir().unwrap();
        let rel = PathBuf::from(relative_to(&cwd, &dir));
        assert_eq!(console_log_path(Some(&rel), None).unwrap().0, log);
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let tilde = PathBuf::from(format!("~/{}", relative_to(&home, &dir)));
        assert_eq!(console_log_path(Some(&tilde), None).unwrap().0, log);
        homes.name(&dir, "saved");
        let found = console_log_path(Some(Path::new("saved")), None).unwrap();
        assert!(found.0 == log && found.1.is_none());
        // A stopped service's console is in its own directory, by `--service` or the REF.
        assert!(console_log_path(Some(&dir), Some("db")).is_err());
        let db = dir.join("svc-db").join(run::CONSOLE_LOG);
        std::fs::write(&db, b"").unwrap();
        assert_eq!(console_log_path(Some(&dir), Some("db")).unwrap().0, db);
        assert_eq!(
            console_log_path(Some(Path::new("saved/db")), None)
                .unwrap()
                .0,
            db
        );
        // A service is one name, never a way out of the state dir.
        let err = console_log_path(Some(Path::new("saved/../x")), None).unwrap_err();
        assert!(
            err.to_string().contains("not a compose service name"),
            "{err}"
        );
        assert!(console_log_path(Some(&dir), Some("../saved")).is_err());
    }

    // `vk ssh`/`vk ssh-config` reach a stopped VM's state dir however the REF spells it.
    #[test]
    fn a_stopped_state_dir_is_found_by_any_ref() {
        let homes = crate::dev::testutil::Homes::new("ssh");
        let dir = homes.dir().join("saved");
        std::fs::create_dir_all(&dir).unwrap();
        let canon = std::fs::canonicalize(&dir).unwrap();
        let of = |t: &str| state_dir_of(std::ffi::OsStr::new(t));
        // A bare word that names nothing but is a directory where the tests run.
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(of("src").unwrap(), std::fs::canonicalize("src").unwrap());
        assert_eq!(of(&relative_to(&cwd, &dir)).unwrap(), canon);
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        assert_eq!(
            of(&format!("~/{}", relative_to(&home, &dir))).unwrap(),
            canon
        );
        homes.name(&dir, "saved");
        assert_eq!(of("saved").unwrap(), canon);
        assert!(of("saved/db").is_err());
        assert!(of("4294967295").is_err());
    }

    // A REF is resolved once, a name ahead of a directory spelled the same, and the service
    // a Windows guest's socket is looked for under is one name.
    #[test]
    fn a_windows_service_is_looked_for_in_the_named_run() {
        let homes = crate::dev::testutil::Homes::new("win");
        let (run, _live) = run_with_sockets("by-name", &[("win", true)]);
        let run = std::fs::canonicalize(run).unwrap();
        // `src` is also a directory where the tests run: the name wins.
        assert!(Path::new("src").is_dir());
        homes.name(&run, "src");
        let target = exec_target(Some("src/win"), None, "--service").unwrap();
        assert!(matches!(
            &target,
            ExecTarget::Ref {
                sel: vms::Selector::Named { dir, .. },
                service: Some(s),
                ..
            }
                if *dir == run && s == "win"
        ));
        assert_eq!(
            windows_exec_socket(&target).unwrap(),
            Some(run.join("svc-win").join(uefi::GUEST_AGENT_SOCKET))
        );
        // No socket under the name's own run: a Linux service, left to vk-agent.
        let target = exec_target(Some("src"), Some("db"), "--service").unwrap();
        assert_eq!(windows_exec_socket(&target).unwrap(), None);
        // A service with a path in it never reaches the filesystem.
        for bad in ["src/../win", "src/win/x"] {
            let err = exec_target(Some(bad), None, "--service").err().unwrap();
            assert!(
                err.to_string().contains("not a compose service name"),
                "{err}"
            );
        }
        assert!(exec_target(Some("src"), Some("../win"), "--service").is_err());
        // A word naming two directories is refused, not read as either.
        std::fs::create_dir_all(homes.dir().join("XDG_STATE_HOME/virtkit/dev/amb")).unwrap();
        let other = homes.dir().join("other");
        std::fs::create_dir_all(&other).unwrap();
        homes.name(&other, "amb");
        let err = exec_target(Some("amb/win"), None, "--service")
            .err()
            .unwrap();
        assert!(err.to_string().contains("ambiguous"), "{err}");
        std::fs::remove_dir_all(&run).unwrap();
    }

    /// An explicit `vk stop` of a VM that is not running exits 1, by its name as by its
    /// state dir.
    #[test]
    fn stopping_a_stopped_vm_exits_1_however_it_is_named() {
        let homes = crate::dev::testutil::Homes::new("stop-stopped");
        let dir = homes.dir().join("state");
        std::fs::create_dir_all(&dir).unwrap();
        homes.name(&dir, "app");
        for r in [std::ffi::OsStr::new("app"), dir.as_os_str()] {
            let code = stop_refs(
                &[r.to_owned()],
                false,
                false,
                None,
                vms::Deadline::in_secs(1),
                vms::StopHow::Graceful,
            );
            assert_eq!(code, exit_code(1), "{r:?}");
        }
    }

    // `-r` with no REF means the current directory and every one below it, through the
    // same dispatch `vk stop`, `reboot`, `pause` and `resume` take.
    #[test]
    fn recursive_without_a_ref_is_the_current_directory_and_below() {
        let _homes = crate::dev::testutil::Homes::new("recursive");
        let stop = |sel: Option<vms::Selector>| {
            vms::stop_cmd(
                sel,
                false,
                vms::Deadline::in_secs(1),
                vms::StopHow::Graceful,
            )
        };
        // Nothing running: `-r` alone is done already, as plain `vk stop` is; `-r .` names
        // a directory and says nothing was there.
        assert_eq!(act_on_vms(None, true, stop), ExitCode::SUCCESS);
        assert_eq!(act_on_vms(None, false, stop), ExitCode::SUCCESS);
        let here = Some(std::ffi::OsStr::new("."));
        assert_eq!(act_on_vms(here, true, stop), exit_code(1));
        let mut seen = None;
        let code = act_on_vms(None, true, |sel| {
            seen = Some(sel);
            Ok((String::new(), true))
        });
        assert_eq!(code, ExitCode::SUCCESS);
        let here = Some(vms::Selector::Here { below: true });
        assert_eq!(seen, Some(here.clone()));
        let cli = Cli::try_parse_from(["vk", "list", "-r"]).unwrap();
        let Cmd::List {
            target, recursive, ..
        } = cli.cmd
        else {
            panic!("not list");
        };
        assert_eq!(
            vms::selector_of(target.as_deref(), recursive).unwrap(),
            here
        );
        assert_eq!(vms::selector_of(None, false).unwrap(), None);
    }

    // A directory's own live service socket is the one meant, before the registry is asked:
    // a services-only run registers no VM, and other VMs of the project must not stand in
    // its way.
    #[test]
    fn a_directory_s_service_socket_answers_before_the_registry() {
        let _homes = crate::dev::testutil::Homes::new("direct");
        let (run, _live) = run_with_sockets("direct", &[("win", true)]);
        let socket = run.join("svc-win").join(uefi::GUEST_AGENT_SOCKET);
        let target = exec_target(run.to_str(), Some("win"), "--service").unwrap();
        assert!(matches!(&target, ExecTarget::Qga(s) if *s == socket));
        assert_eq!(windows_exec_socket(&target).unwrap(), Some(socket));
        assert!(resolve_exec_addr(&target).is_err());
        // No socket for that service: the registry decides, and nothing runs there.
        let target = exec_target(run.to_str(), Some("db"), "--service").unwrap();
        assert!(matches!(&target, ExecTarget::Ref { vm: None, .. }));
        assert!(windows_exec_socket(&target).is_err());
        std::fs::remove_dir_all(&run).unwrap();
    }

    // A services-only run registers no VM, so its state dir's lock is what says a follow of
    // one of its consoles still has a writer; released, the follow ends.
    #[tokio::test]
    async fn a_services_only_console_is_followed_while_its_run_holds_the_lock() {
        let homes = crate::dev::testutil::Homes::new("follow");
        let dir = std::fs::canonicalize(homes.dir()).unwrap();
        std::fs::create_dir_all(dir.join("svc-db")).unwrap();
        let log = dir.join("svc-db").join(run::CONSOLE_LOG);
        std::fs::write(&log, b"before\n").unwrap();
        // Stopped: printed, then done.
        let (_, writer) = console_log_path(Some(&dir), Some("db")).unwrap();
        assert!(writer.is_none());
        let lock = run::lock_state_dir(&dir).unwrap();
        let (path, writer) = console_log_path(Some(&dir), Some("db")).unwrap();
        assert!(matches!(&writer, Some(Writer::Run(d)) if *d == dir));
        let follow = show_console_log(&path, writer.as_ref(), &[], None, 0, true);
        tokio::pin!(follow);
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "after").unwrap();
        let held = tokio::time::timeout(REGISTRY_POLL + FOLLOW_POLL * 2, &mut follow).await;
        assert!(held.is_err(), "the run still holds its lock");
        drop(lock);
        tokio::time::timeout(REGISTRY_POLL * 3, follow)
            .await
            .expect("the follow ends once the run lets go")
            .unwrap();
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
                "console",
                "cp",
                "delete",
                "dev",
                "exec",
                "export",
                "gc",
                "list",
                "logs",
                "pause",
                "publish",
                "reboot",
                "rename",
                "reset",
                "restart",
                "resume",
                "run",
                "snapshot",
                "ssh",
                "ssh-config",
                "start",
                "status",
                "stop",
                "toolchain",
                "update"
            ]
        );
    }

    #[test]
    fn an_unnamed_run_is_named_after_what_it_boots() {
        let p = Path::new("/home/me/shop");
        let image = |i| auto_name_base(Some(i), false, None, None, p);
        assert_eq!(image("alpine:3.20"), "alpine");
        assert_eq!(image("ghcr.io/org/tool@sha256:ab"), "tool");
        assert_eq!(image("./bundles/win11/"), "win11");
        assert_eq!(
            auto_name_base(Some("x"), true, Some("devcontainer"), Some("t"), p),
            "devcontainer"
        );
        assert_eq!(auto_name_base(None, true, None, Some("dev"), p), "dev");
        // A Dockerfile with no target: the project it is about.
        assert_eq!(auto_name_base(None, true, None, None, p), "shop");
        assert_eq!(auto_name_base(None, true, None, None, Path::new("/")), "vm");
        // A Dockerfile supplies the root, so an image beside it names nothing.
        assert_eq!(auto_name_base(Some("alpine"), true, None, None, p), "shop");
    }

    /// A run with nothing to boot is refused by the run itself: nothing is named for it, so
    /// the corrected command that follows finds its name free.
    #[test]
    fn a_run_with_nothing_to_boot_claims_no_name() {
        let mut cli = Cli::try_parse_from(["vk", "run", "--name", "nothing-to-boot"]).unwrap();
        let made = prepare_run_name(&mut cli.cmd, false).unwrap();
        assert!(made.remembered.is_none() && !made.name_made && !made.dir_made);
        let Cmd::Run { state_dir, .. } = cli.cmd else {
            panic!("not a run");
        };
        assert_eq!(state_dir, None);
    }

    /// Services-only compose runs stay unnamed even with `--detach` and reject `--name`.
    #[test]
    fn compose_up_is_never_named() {
        let cmd = |args: &[&str]| {
            let mut cli = Cli::try_parse_from(["vk", "run"].iter().chain(args)).unwrap();
            prepare_run_name(&mut cli.cmd, false).map(|_| cli.cmd)
        };
        let Cmd::Run {
            name, state_dir, ..
        } = cmd(&["--compose", "c.yml", "--detach"]).unwrap()
        else {
            panic!("not a run");
        };
        assert_eq!((name, state_dir), (None, None));
        let Err(err) = cmd(&["--compose", "c.yml", "--name", "x"]) else {
            panic!("named");
        };
        assert!(format!("{err}").contains("compose up"), "{err}");
        assert!(err.downcast_ref::<names::Refused>().is_some());
        assert!(boots_no_primary(None, &[], None));
        assert!(!boots_no_primary(None, &[], Some("web")));
        assert!(!boots_no_primary(Some("alpine"), &[], None));
        assert!(!boots_no_primary(None, &["Dockerfile".into()], None));
    }

    /// `--name`, `--state-dir` and `--detach` accept overrides. Other single-value
    /// options, such as `--username`, still reject duplicates.
    #[test]
    fn run_takes_the_last_name_state_dir_and_detach_only() {
        let cli = Cli::try_parse_from([
            "vk",
            "run",
            "--state-dir",
            "/a",
            "--name",
            "x",
            "alpine",
            "--state-dir",
            "/b",
            "--detach",
            "--detach",
            "--name",
            "y",
            "--",
            "true",
        ])
        .unwrap();
        let Cmd::Run {
            state_dir, name, ..
        } = cli.cmd
        else {
            panic!("not a run");
        };
        assert_eq!(state_dir.as_deref(), Some(Path::new("/b")));
        assert_eq!(name.as_deref(), Some("y"));
        let twice = ["vk", "run", "--username", "a", "--username", "b", "alpine"];
        assert!(Cli::try_parse_from(twice).is_err());
    }

    /// A scratch state base, removed on drop.
    struct Base(PathBuf);
    impl Drop for Base {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn base(tag: &str) -> Base {
        let d = std::env::temp_dir().join(format!("vk-main-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Base(vms::canonical(&d))
    }

    /// Prepare `vk run ARGS` against the state base `b`.
    fn prepare(b: &Base, args: &[&str]) -> anyhow::Result<(Prepared, Cmd)> {
        let mut cli = Cli::try_parse_from(["vk", "run"].iter().chain(args)).unwrap();
        let places = (names::Index::at(b.0.join("names")), b.0.join("run"));
        let made = prepare_run_name_in(&mut cli.cmd, false, || Ok(places))?;
        Ok((made, cli.cmd))
    }

    /// A run that fails before its VM is up gives back the name it gave and touches nothing
    /// else in a state dir it did not make: a `run.json` there is another run's. The
    /// corrected command that follows gets the name.
    #[test]
    fn a_failed_run_gives_back_only_what_it_made() {
        let b = base("settle");
        let dir = b.0.join("mine");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(names::RECIPE), "{}").unwrap();
        let d = dir.to_str().unwrap();
        let (made, _) = prepare(&b, &["--state-dir", d, "--name", "test", "alpine"]).unwrap();
        assert!(made.name_made && !made.dir_made);
        made.settle();
        assert_eq!(std::fs::read(dir.join(names::RECIPE)).unwrap(), b"{}");
        let idx = names::Index::at(b.0.join("names"));
        assert_eq!(idx.lookup("test"), None);
        drop(made);
        // A managed dir is removed along with its name, and the name is free again.
        let (made, cmd) = prepare(&b, &["--name", "test", "alpine"]).unwrap();
        assert!(made.name_made && made.dir_made);
        let Cmd::Run { state_dir, .. } = cmd else {
            panic!("not a run");
        };
        let managed = state_dir.unwrap();
        assert!(
            managed.starts_with(b.0.join("run")),
            "{}",
            managed.display()
        );
        made.settle();
        assert!(!managed.exists());
        let (again, _) = prepare(&b, &["--name", "test", "alpine"]).unwrap();
        assert!(again.name_made);
        // A taken name is the caller's mistake, refused before anything is left behind.
        let Err(e) = prepare(&b, &["--name", "test", "alpine"]) else {
            panic!("a taken name was given");
        };
        assert!(e.downcast_ref::<names::Refused>().is_some(), "{e:#}");
        assert_eq!(std::fs::read_dir(b.0.join("run")).unwrap().count(), 1);
    }

    /// Replaying a named run or claiming an explicit name preserves unrelated claims and directories.
    #[test]
    fn a_claim_leaves_another_vm_s_abandoned_claim() {
        let b = base("local-claim");
        let idx = names::Index::at(b.0.join("names"));
        let boot = b.0.join("run/boot-00000000");
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::write(boot.join(names::MADE), b"").unwrap();
        assert!(idx.provisional().claim_exact(&boot, "boot").unwrap());
        let app = b.0.join("app");
        std::fs::create_dir(&app).unwrap();
        assert!(idx.claim_exact(&app, "app").unwrap());
        let d = app.to_str().unwrap();
        let replay = ["--detach", "--state-dir", d, "--name", "app", "alpine"];
        let (made, _) = prepare(&b, &replay).unwrap();
        assert!(!made.name_made);
        made.settle();
        let (made, _) = prepare(&b, &["--name", "web", "alpine"]).unwrap();
        assert!(made.name_made);
        made.settle();
        assert!(boot.exists() && idx.lookup("boot").is_some());
    }

    /// A run holds its state dir from before it claims the name until it ends, so a second
    /// run on the dir is refused meanwhile, and a run that fails never gives back a name a
    /// run that came up uses.
    #[test]
    fn only_the_run_holding_the_dir_gives_its_name_back() {
        let b = base("contend");
        let dir = b.0.join("shared");
        let d = dir.to_str().unwrap();
        let idx = names::Index::at(b.0.join("names"));
        let first = prepare(&b, &["--state-dir", d, "alpine"]).unwrap();
        assert!(first.0.name_made);
        let Err(e) = prepare(&b, &["--state-dir", d, "alpine"]) else {
            panic!("two runs share a dir");
        };
        assert!(format!("{e:#}").contains("in use"), "{e:#}");
        first.0.settle();
        drop(first);
        assert_eq!(idx.lookup("alpine"), None);
        // This one comes up: its name and recipe are published, and kept when it ends.
        let up = prepare(&b, &["--state-dir", d, "alpine"]).unwrap();
        let r = up.0.remembered.clone().unwrap();
        r.publish().unwrap();
        up.0.settle();
        drop((up, r));
        assert!(dir.join(names::RECIPE).exists());
        // A later run that fails gave nothing, so takes nothing back.
        let failed = prepare(&b, &["--state-dir", d, "alpine"]).unwrap();
        assert!(!failed.0.name_made);
        failed.0.settle();
        assert_eq!(idx.lookup("alpine"), Some(vms::canonical(&dir)));
    }

    /// A run killed before its VM was up — no settling — leaves its managed dir unlocked and
    /// without a recipe; one whose dir was removed leaves nothing. Either way the same
    /// `--name` is free again for the next run.
    #[test]
    fn a_killed_or_removed_run_leaves_its_name_free() {
        let b = base("killed");
        let (made, cmd) = prepare(&b, &["--name", "app", "alpine"]).unwrap();
        let Cmd::Run { state_dir, .. } = &cmd else {
            panic!("not a run");
        };
        let killed = state_dir.clone().unwrap();
        // Still running: the name is its own.
        assert!(prepare(&b, &["--name", "app", "alpine"]).is_err());
        drop((made, cmd));
        let (made, cmd) = prepare(&b, &["--name", "app", "alpine"]).unwrap();
        assert!(made.name_made && !killed.exists());
        // This one came up and stopped; then its dir was removed.
        made.remembered.as_ref().unwrap().publish().unwrap();
        let Cmd::Run { state_dir, .. } = &cmd else {
            panic!("not a run");
        };
        let removed = state_dir.clone().unwrap();
        drop((made, cmd));
        assert!(prepare(&b, &["--name", "app", "alpine"]).is_err());
        std::fs::remove_dir_all(&removed).unwrap();
        let (made, _) = prepare(&b, &["--name", "app", "alpine"]).unwrap();
        assert!(made.name_made);
    }

    /// Reclaiming a provisional name preserves files in both caller-supplied and managed
    /// directories. A committed name survives a missing recipe while its directory exists.
    #[test]
    fn a_killed_run_gives_up_its_name_but_keeps_its_files() {
        let b = base("leftovers");
        let own = b.0.join("mine");
        let d = own.to_str().unwrap();
        let (made, cmd) = prepare(&b, &["--state-dir", d, "--name", "app", "alpine"]).unwrap();
        std::fs::write(own.join("root.ext4"), "disk").unwrap();
        drop((made, cmd));
        let (made, cmd) = prepare(&b, &["--name", "app", "alpine"]).unwrap();
        assert!(made.name_made);
        assert_eq!(std::fs::read(own.join("root.ext4")).unwrap(), b"disk");
        // Killed again, after writing into the dir `vk` made for it: that dir stays too.
        let Cmd::Run { state_dir, .. } = &cmd else {
            panic!("not a run");
        };
        let managed = state_dir.clone().unwrap();
        std::fs::write(managed.join("console.log"), "boot").unwrap();
        drop((made, cmd));
        let (made, _) = prepare(&b, &["--name", "app", "alpine"]).unwrap();
        assert!(made.name_made);
        assert!(managed.join("console.log").exists());
        // A VM that came up but has no recipe (its write failed, say) keeps name and disk.
        let r = made.remembered.clone().unwrap();
        r.publish().unwrap();
        std::fs::remove_file(r.dir().join(names::RECIPE)).unwrap();
        std::fs::write(r.dir().join("root.ext4"), "disk").unwrap();
        let up = r.dir().to_path_buf();
        drop((made, r));
        let (other, _) = prepare(&b, &["--name", "other", "alpine"]).unwrap();
        assert!(other.name_made);
        let idx = names::Index::at(b.0.join("names"));
        assert_eq!(idx.lookup("app"), Some(up.clone()));
        assert_eq!(std::fs::read(up.join("root.ext4")).unwrap(), b"disk");
    }

    /// A run that waited for a dir `vk dev gc` removed meanwhile does not boot in whatever
    /// is made at the path next, and a held lock never gets its dir made again.
    #[test]
    fn a_lock_on_a_replaced_dir_is_refused() {
        let b = base("replaced");
        let dir = b.0.join("state");
        std::fs::create_dir(&dir).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        run::same_dir(&held, &dir).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        assert!(run::same_dir(&held, &dir).is_err());
        std::fs::create_dir(&dir).unwrap();
        let e = run::same_dir(&held, &dir).unwrap_err();
        assert!(format!("{e}").contains("replaced"), "{e}");
    }

    /// A managed dir is made by this run alone: a token already taken is drawn again, and
    /// the name is cut short for the VMM's sockets to fit, down to a byte; past that, the
    /// error says what to do.
    #[test]
    fn a_managed_dir_is_new_and_fits_the_socket_budget() {
        let b = base("rundir");
        let run_base = b.0.join("run");
        std::fs::create_dir_all(run_base.join("app-aaaaaaaa")).unwrap();
        let mut tokens = ["aaaaaaaa", "bbbbbbbb"].into_iter().map(String::from);
        let dir = new_run_dir(&run_base, "app", || tokens.next().unwrap()).unwrap();
        assert_eq!(dir, run_base.join("app-bbbbbbbb"));
        // A base that leaves room for exactly one byte of the name, then one that leaves none.
        let used = run_base.as_os_str().len() + 1;
        let pad = run::STATE_DIR_MAX - used - "/x-aaaaaaaa".len();
        let tight = run_base.join("p".repeat(pad));
        let dir = new_run_dir(&tight, "app", || "aaaaaaaa".into()).unwrap();
        assert_eq!(dir, tight.join("a-aaaaaaaa"));
        assert_eq!(dir.as_os_str().len(), run::STATE_DIR_MAX);
        let over = run_base.join("p".repeat(pad + 1));
        let e = new_run_dir(&over, "app", || "aaaaaaaa".into()).unwrap_err();
        assert!(format!("{e}").contains("XDG_STATE_HOME"), "{e}");
    }

    #[test]
    fn a_stop_by_a_signal_exits_as_the_signal_would() {
        let e = anyhow::Error::from(run::Stopped(libc::SIGINT)).context("starting");
        assert_eq!(run::stop_code(&e), Some(130));
        assert_eq!(run::stop_code(&anyhow::anyhow!("other")), None);
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

    #[test]
    fn control_plane_unreachable_detects_transport_failures() {
        // A reset io::Error anywhere in the chain — a wedged VM's vsock link — is a transport
        // failure worth a restart hint.
        let reset = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
            .context("connecting to the service manager (vsock host:1099)");
        assert!(control_plane_unreachable(&reset));
        // A peer hangup — read_msg reports it as UnexpectedEof — is transport, not a refusal.
        let eof = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "control peer closed the connection",
        ))
        .context("reading the service manager's reply");
        assert!(control_plane_unreachable(&eof));
        // A refusal the manager sent back is not a transport failure — no restart hint.
        assert!(!control_plane_unreachable(&anyhow::anyhow!(
            "service manager refused: no such unit \"redis\""
        )));
    }

    /// A run directory with, for each `(service, live)`, a qemu-ga socket under `svc-<service>/`
    /// that is listened on, or left behind by a listener that is gone. Keep the listeners.
    fn run_with_sockets(
        tag: &str,
        sockets: &[(&str, bool)],
    ) -> (PathBuf, Vec<std::os::unix::net::UnixListener>) {
        let run = std::env::temp_dir().join(format!("vk-qga-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let mut live = Vec::new();
        for &(service, up) in sockets {
            let dir = run.join(format!("svc-{service}"));
            std::fs::create_dir_all(&dir).unwrap();
            let listener = vk_core::unixpath::bind(&dir.join(uefi::GUEST_AGENT_SOCKET)).unwrap();
            if up {
                live.push(listener);
            }
        }
        (run, live)
    }

    #[test]
    fn a_service_socket_is_found_in_the_named_dir_before_the_registered_run() {
        let (run, _live) = run_with_sockets("named", &[("win", true)]);
        let found = service_qga_socket(Some(&run), "win", || panic!("the registry is not asked"));
        assert_eq!(
            found.unwrap(),
            Some(run.join("svc-win").join(uefi::GUEST_AGENT_SOCKET))
        );
        std::fs::remove_dir_all(&run).unwrap();
    }

    #[test]
    fn a_service_socket_is_found_in_the_registered_run() {
        let (run, _live) = run_with_sockets("registered", &[("win", true)]);
        let project = run.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let found = service_qga_socket(Some(&project), "win", || Ok(run.clone()));
        assert_eq!(
            found.unwrap(),
            Some(run.join("svc-win").join(uefi::GUEST_AGENT_SOCKET))
        );
        // Nothing registered for the named directory is the registry's error.
        let err = service_qga_socket(Some(&project), "win", || anyhow::bail!("no running vk VM"));
        assert!(err.unwrap_err().to_string().contains("no running vk VM"));
        std::fs::remove_dir_all(&run).unwrap();
    }

    #[test]
    fn a_service_without_a_socket_is_left_to_vk_agent() {
        let (run, _live) = run_with_sockets("linux", &[]);
        std::fs::create_dir_all(run.join("svc-db")).unwrap();
        assert_eq!(
            service_qga_socket(Some(&run), "db", || Ok(run.clone())).unwrap(),
            None
        );
        std::fs::remove_dir_all(&run).unwrap();
    }

    #[test]
    fn a_stale_service_socket_is_refused_at_once() {
        let (run, _live) = run_with_sockets("stale", &[("win", false)]);
        let err = service_qga_socket(Some(&run), "win", || Ok(run.clone())).unwrap_err();
        assert!(
            err.to_string()
                .contains("service win is not running (stale"),
            "{err}"
        );
        std::fs::remove_dir_all(&run).unwrap();
    }

    #[test]
    fn vk_cp_takes_a_service() {
        let cli =
            Cli::try_parse_from(["vk", "cp", "--service", "win", "a.txt", ":C:/a.txt"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Cp { service: Some(s), .. } if s == "win"));
    }
}
