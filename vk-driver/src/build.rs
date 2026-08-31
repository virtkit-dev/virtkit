//! `vk build` — a from-scratch Dockerfile builder (no docker, no buildkit).
//!
//! A from-scratch builder for the narrow job we actually need: build a Dockerfile
//! target and export it as a filesystem (ext4) image, with `RUN` steps run in a
//! microVM (the embedded libkrun by default) rather than rootless containers. It is
//! intentionally the *classic* (pre-buildkit) builder shape — a strict linear
//! per-instruction cache chain per stage — not a buildkit reimplementation with a
//! content-addressed per-op cache graph. Independent stages *do* build concurrently
//! over the dependency DAG (the microVM backend's parallel driver, `drive_microvm`);
//! the concurrency is coarse-grained, one guest per stage, not buildkit's fine-grained
//! per-op solver.
//!
//! Pipeline: [`parser`] (Dockerfile → instructions, lexing mirrors buildkit's
//! parser) → [`plan`] (stages + cross-stage deps + toposort) → [`exec`] (a backend
//! applies each stage). Backends: [`exec::DryRun`] (records the build, for tests +
//! `--print-plan`), [`exec::Host`] (`FROM scratch` + `COPY`, pure-Rust ext4), and
//! [`exec::MicroVm`] (`FROM <image>` + `RUN` in a CH guest, exported as a clean ext4).
//!
//! Instruction-level cache: each instruction advances a chained content key; for a
//! filesystem-changing instruction (RUN/COPY) the resulting ext4 snapshot is pushed
//! to / pulled from virtkit's own `[registry]` keyed by that key (the CDC chunk dedup
//! makes successive snapshots share almost all blobs). On a rebuild the longest cached
//! prefix is restored and only the changed tail re-runs; a stage whose last key is
//! cached restores that one snapshot directly (no per-instruction probes), and a stage
//! only such fully-cached consumers read is skipped entirely. How many intermediate
//! snapshots a cold build actually pushes is set by [`BuildCache`] (`--build-cache`):
//! stage-level reuse works in every mode, so the mode only trades per-instruction commit
//! overhead against how much of a stage a later edit re-runs.
//!
//! A context `COPY` also keys on a sha256 of the (sorted, `.dockerignore`-filtered)
//! content of the files it references, so editing a copied source busts the cache; a
//! `COPY --from=<stage>` is already covered by that stage's key chain.
//!
//! The key chain is computed once by [`resolve_stages`] (the single source of truth):
//! a `FROM <image>` seeds on the resolved manifest digest when available, so a moved tag
//! busts the cache; the build driver applies the resolved steps, and `docker-hash` prints
//! the same per-stage keys ([`stage_keys`]).

mod exec;
mod interp;
mod parser;

// Disk-device naming (0 = vda, 1 = vdb, …) — also used by `run::boot_session` to name the
// build guest's ephemeral /tmp scratch disk.
pub(crate) use exec::vd_name;
mod plan;
mod progress;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use exec::{DryRun, Executor, Host, MicroVm, ResolvedMount, Rootfs, ShellState};
use interp::Vars;
use parser::Instruction;
use plan::{Base, Plan, PlanInput};
use progress::{Outcome, Progress, StageInit};

use crate::timing::{Phase, Timings};

/// How aggressively a build populates the instruction cache.
///
/// Restoring a cached prefix and the fully-cached-stage fast path both work at stage
/// granularity in every mode, so a build whose target is unchanged costs the same
/// regardless. The mode only changes *which* intermediate `RUN`/`COPY` snapshots are
/// pushed on a cold or partial build — trading the per-instruction commit overhead (a
/// guest freeze + diff + push per step) against how much of a stage a later edit re-runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildCache {
    /// Checkpoint past a work threshold: a stage's final step is always cached (so
    /// stage-level reuse and `COPY --from` still hit), plus any intermediate step once
    /// the uncommitted run time since the last checkpoint crosses [`CHECKPOINT_SECS`]
    /// (override `[build] cache_checkpoint_secs`). Trivial steps fold into the
    /// next checkpoint's delta, so a long stage pays a handful of commits instead of one
    /// per instruction, while a late-instruction edit still resumes from a recent
    /// checkpoint.
    #[default]
    Auto,
    /// One commit per stage: cache only each stage's final snapshot, with no intermediate
    /// snapshots and no partial-prefix restore. Fastest cold build; any mid-stage change
    /// re-runs the whole stage.
    Layers,
    /// Cache every `RUN`/`COPY` snapshot, so a rebuild restores the longest cached prefix
    /// and re-runs only the changed tail — at the cost of a commit per instruction.
    Instructions,
}

impl std::str::FromStr for BuildCache {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "layers" => Ok(Self::Layers),
            "instructions" => Ok(Self::Instructions),
            other => Err(format!(
                "invalid build cache mode {other:?} (expected auto, layers, or instructions)"
            )),
        }
    }
}

/// `auto` mode's default checkpoint threshold (seconds): an intermediate snapshot is
/// pushed once this much uncommitted run time has accrued since the last checkpoint.
/// Bounds the work a late-instruction edit re-runs while sparing trivial steps a commit
/// each. The config's `[build] cache_checkpoint_secs` overrides it per build.
const CHECKPOINT_SECS: u64 = 20;

// Host-wide build-guest tuning, set once from `[build]` by [`set_tuning`] (formerly the
// VIRTKIT_BUILD_{CPUS,MEM,CACHE_CHECKPOINT_SECS} env vars). None of these has a CLI flag, so
// a process global carries each to every build path — the primary `-f` build, compose
// service builds, the on-demand manager build — and to the parallel stage workers, without
// threading them through the per-build `Options`. `--build-jobs` stays on `Options` because
// it *does* have a flag.
static CHECKPOINT_DEFAULT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(CHECKPOINT_SECS);
/// `[build] cpus`, or 0 when unset (→ the host CPU count, see [`exec::resolve_build_cpus`]).
static BUILD_CPUS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// `[build] mem`, or None when unset (→ 4G, see [`exec::resolve_build_mem`]).
static BUILD_MEM: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
/// `[build] no_mem_gate`: skip the host-memory admission gate (see [`MemLedger`]) and let
/// `jobs` alone bound the build, as it did before the gate existed.
static BUILD_NO_MEM_GATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Apply the host's `[build]` tuning process-wide. Called once from `cli_main` after the
/// config loads (and by the re-exec'd `gitlab supervise` that runs the on-demand builder),
/// before any build starts.
pub fn set_tuning(build: &crate::config::Build) {
    use std::sync::atomic::Ordering::Relaxed;
    CHECKPOINT_DEFAULT.store(
        build.cache_checkpoint_secs.unwrap_or(CHECKPOINT_SECS),
        Relaxed,
    );
    BUILD_CPUS.store(build.cpus.unwrap_or(0), Relaxed);
    BUILD_NO_MEM_GATE.store(build.no_mem_gate, Relaxed);
    *BUILD_MEM.lock().unwrap() = build.mem.clone();
    // The scheduling priority a build's guests, helpers and worker threads start at, which
    // the same `[build]` section configures.
    crate::prio::set_policy(build);
}

/// `MemTotal` for the host-memory gate to measure against, or `None` when there is no gate:
/// `/proc/meminfo` unreadable, or `[build] no_mem_gate` set. Takes the host reading the
/// `jobs` ceiling already made rather than making its own, so the two can never disagree
/// about the size of the host — the ceiling still derives from `MemTotal` with the gate off.
fn gate_total_mib(host_total_mib: Option<u64>) -> Option<u64> {
    if BUILD_NO_MEM_GATE.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    host_total_mib
}

/// The configured per-stage build vCPUs (`[build] cpus`), None when unset.
pub(crate) fn configured_build_cpus() -> Option<u32> {
    match BUILD_CPUS.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

/// The configured per-stage build RAM (`[build] mem`), None when unset.
pub(crate) fn configured_build_mem() -> Option<String> {
    BUILD_MEM.lock().unwrap().clone()
}

// Test-only override for `checkpoint_secs`: forces the `auto` threshold on the current
// thread so a test can exercise it without touching the process global (which would race
// other tests under the multithreaded runner). Thread-local, so it is invisible to other
// tests — `build_stage` reads it on the caller's thread.
#[cfg(test)]
thread_local! {
    static CHECKPOINT_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// The effective `auto` checkpoint threshold: the test override if set, else the
/// process-wide value from [`set_tuning`].
fn checkpoint_secs() -> u64 {
    #[cfg(test)]
    if let Some(secs) = CHECKPOINT_OVERRIDE.with(std::cell::Cell::get) {
        return secs;
    }
    CHECKPOINT_DEFAULT.load(std::sync::atomic::Ordering::Relaxed)
}

/// A sink for a build's plain `#N …` progress lines (see [`Options::progress_sink`]) — the
/// streamed transport the service manager forwards to a guest that requested a service start.
pub type ProgressSink = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

/// CA + HTTP Basic credentials for the build-cache registry (a remote vk-registry), so a
/// TLS-and-auth-gated cache/lock server is reachable. All-empty (the `Default`) = anonymous
/// over the system roots — a loopback or open cache, and the local-store case.
#[derive(Debug, Clone, Default)]
pub struct CacheAuth {
    pub ca_file: Option<PathBuf>,
    pub username: String,
    pub password_file: Option<PathBuf>,
    pub token_file: Option<PathBuf>,
}

impl CacheAuth {
    /// The `[build]` cache credentials. They travel with the cache wherever it was resolved
    /// to, including to a registry named by `--cache-registry` instead of the config: a host
    /// configures one cache server, and the flag moves builds between its repos.
    pub fn from_config(b: &crate::config::Build) -> Self {
        Self {
            ca_file: b.cache_ca_file.clone(),
            username: b.cache_username.clone(),
            password_file: b.cache_password_file.clone(),
            token_file: b.cache_token_file.clone(),
        }
    }
}

/// Where a build's instruction cache lives and how it authenticates there: the command line
/// first, then `[build]`.
///
/// Resolved once here so every entry point that builds reads the same answer, and the cache
/// one of them warms is the cache the next one restores from.
#[derive(Debug, Clone, Default)]
pub struct CacheOpts {
    pub registry: Option<String>,
    pub insecure: bool,
    pub auth: CacheAuth,
}

impl CacheOpts {
    pub fn resolve(registry: Option<&str>, insecure: bool, b: &crate::config::Build) -> Self {
        Self {
            registry: registry
                .map(str::to_string)
                .or_else(|| b.cache_registry.clone()),
            insecure: insecure || b.cache_insecure,
            auth: CacheAuth::from_config(b),
        }
    }

    /// The config's own cache, with no command line over it.
    pub fn from_config(b: &crate::config::Build) -> Self {
        Self::resolve(None, false, b)
    }
}

/// What/how to build.
pub struct Options {
    /// Dockerfile(s), merged into one stage namespace (see [`Plan::from_dockerfiles`]).
    pub dockerfiles: Vec<PathBuf>,
    /// Stage selector: an `AS` name or index; `None` = the last stage.
    pub target: Option<String>,
    /// `--stage-mem NAME=SIZE` / `--stage-cpus NAME=N`, by stage name: this run's last
    /// word on how big those stages' guests are, over any `# vk:` hint in the Dockerfile
    /// and over `[build] mem` / `[build] cpus`. A name matching no stage is an error, not
    /// a no-op — see [`apply_stage_overrides`].
    pub stage_guests: HashMap<String, parser::GuestHint>,
    /// Build-context roots, zipped positionally with `dockerfiles`; a file without one
    /// defaults to its own directory.
    pub contexts: Vec<PathBuf>,
    /// `--build-context <name>=<dir>`: additional contexts a `COPY --from=<name>` /
    /// `RUN --mount=…,from=<name>` can read, so a Dockerfile is not confined to the files
    /// under its own context. Resolved after stage names and before image refs.
    pub build_contexts: Vec<(String, PathBuf)>,
    /// ext4 output path (unused in `--print-plan`).
    pub out: Option<PathBuf>,
    /// `--disk <path>`: a caller-owned raw disk file attached read-write to the *target*
    /// stage's RUN guests as `/dev/vdb` (sources shift to `vdc`+). Its writes are the
    /// artifact — a RUN can partition it, mkfs and install a bootloader. Not snapshotted
    /// and never removed (the caller sizes and owns it). Pairs with `FROM --kernel=image`,
    /// which gives the RUNs a kernel that can drive block devices.
    pub out_disk: Option<PathBuf>,
    /// Parse + plan + print the build order and primitives, build nothing.
    pub print_plan: bool,
    /// cloud-hypervisor binary, only used when `VIRTKIT_VMM=cloud-hypervisor` selects
    /// that backend (the default libkrun backend is embedded and needs none).
    pub cloud_hypervisor: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub agent: Option<PathBuf>,
    /// instruction-cache destination: a registry repo (e.g. a `vk-registry` at
    /// `127.0.0.1:5000`), an absolute store directory path (accessed in-process), or
    /// `none` to disable caching. `None` = the builtin local store
    /// (`vk_registry::default_root`).
    pub cache_registry: Option<String>,
    /// the cache registry speaks plain HTTP (a loopback vk-registry).
    pub cache_insecure: bool,
    /// CA + Basic auth for the cache registry when it is a remote, TLS-and-auth-gated
    /// vk-registry. `Default` (empty) for a loopback/open cache or the local store.
    pub cache_auth: CacheAuth,
    /// how aggressively the instruction cache is populated (see [`BuildCache`]).
    pub build_cache: BuildCache,
    /// add an ext4 journal to the exported image (the build stays journal-less).
    pub journal: bool,
    /// `--build-tmp-tmpfs`: use a RAM tmpfs for each stage guest's `/tmp` instead of the
    /// default disk-backed scratch. Disk-backed `/tmp` (the default) lifts the ½·guest-RAM cap
    /// on bulk `/tmp` writes (e.g. a large toolchain unpack) via a separate device that never
    /// enters the stage snapshot; this opts back to the smaller, RAM-bound tmpfs.
    pub tmp_tmpfs: bool,
    /// `--build-arg NAME=VALUE` overrides for ARG defaults.
    pub build_args: Vec<(String, String)>,
    /// Egress for the microVM build's `RUN` guests (see [`BuildNet`]).
    pub net: BuildNet,
    /// Audit mode (`--build-audit-egress`): record every external domain the build's `RUN`
    /// steps resolve and print a "domains contacted" summary after the build. Observes only
    /// — egress is still governed by `net`.
    pub audit: bool,
    /// Restores from the instruction cache are allowed, but nothing may actually
    /// build: any stage whose final snapshot is not cached aborts the build with a
    /// [`NotCached`] error (exit 3 at the CLI), so a caller can branch on
    /// cached-vs-cold without paying for the build.
    pub require_cached: bool,
    /// Max stages built concurrently (microVM backend). `Some` (the `--build-jobs` flag,
    /// or the config's `[build] jobs`) overrides the `None` = auto default (bounded by
    /// the host's total RAM, each stage guest reserving a fixed slice). `1` forces the sequential
    /// build. Ignored by the host backend. Non-zero by type: a budget of no stages at all
    /// is not a build, and silently reading it as `1` would have the announced concurrency
    /// cite a configured number the build never used.
    ///
    /// The other build-guest tuning knobs — per-stage `cpus`/`mem` and the `auto`
    /// checkpoint threshold — are host-wide (no CLI flag), so they ride the process-global
    /// build tuning set once from `[build]` (see [`set_tuning`]), not this per-build struct.
    pub build_jobs: Option<NonZeroUsize>,
    /// Verify every stage snapshot with `e2fsck` (best-effort) as it crosses the cache
    /// boundary — after a cache load, and before an upload — to catch a corrupt ext4
    /// early instead of letting it poison the cache or ship in the image. Off by default
    /// (an `e2fsck` per instruction is not free).
    pub debug: bool,
    /// When set, the build streams its plain `#N …` progress lines to this sink instead of
    /// the terminal — used by the service manager to forward an on-demand build's progress
    /// to the guest that requested the start. `None` = the default terminal/plain reporter.
    pub progress_sink: Option<ProgressSink>,
}

/// The reporter for a build: the routed sink when [`Options::progress_sink`] is set (a
/// streamed on-demand build), else the default terminal/plain dashboard.
fn build_progress(opts: &Options) -> Arc<Progress> {
    match &opts.progress_sink {
        Some(sink) => Progress::routed(Arc::clone(sink)),
        None => Progress::new(),
    }
}

/// `--require-cached` refusal: the target needs stages whose final snapshots are
/// not in the instruction cache. A typed error so the CLI can map it to a distinct
/// exit code (3) — "not cached" is an expected branch for callers, not a failure.
#[derive(Debug)]
pub struct NotCached {
    /// names of the stages that would have to build
    pub stages: Vec<String>,
}

impl std::fmt::Display for NotCached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "--require-cached: stage(s) not in the instruction cache: {}",
            self.stages.join(", ")
        )
    }
}

impl std::error::Error for NotCached {}

/// Egress policy for the microVM build's `RUN` guests.
#[derive(Clone, Debug, PartialEq)]
pub enum BuildNet {
    /// No switch: `RUN` steps get no network.
    None,
    /// Unrestricted egress via the guest's `vk switch` (the default, as `docker build`).
    All,
    /// Egress restricted to destination CIDRs (optionally port-scoped) and DNS-name
    /// suffixes, enforced by the guest's `vk switch`: it refuses lookups of other
    /// names, and a connection may only reach a listed CIDR or an IP a permitted
    /// lookup just resolved.
    Allow {
        ips: Vec<String>,
        names: Vec<String>,
    },
}

impl BuildNet {
    /// Map the `--build-net` / `--build-allow-*` flags to a policy: allow flags
    /// restrict egress (and contradict `--build-net none`); with none of them,
    /// `--build-net` picks unrestricted (`all`, the default) or no network (`none`).
    /// Allowlist syntax is validated here so a bad flag fails before any build work.
    pub fn from_flags(net: &str, ips: &[String], names: &[String]) -> Result<BuildNet> {
        let restricted = !ips.is_empty() || !names.is_empty();
        match net {
            "none" if restricted => {
                bail!("--build-net none contradicts --build-allow-ip/--build-allow-name")
            }
            "none" => Ok(BuildNet::None),
            "all" if restricted => {
                crate::switch::Egress::new(ips, names)?;
                Ok(BuildNet::Allow {
                    ips: ips.to_vec(),
                    names: names.to_vec(),
                })
            }
            "all" => Ok(BuildNet::All),
            other => bail!("--build-net {other:?} (want all or none)"),
        }
    }
}

/// What a completed build exposes to its caller: the target stage's runtime config
/// (env/user/workdir/entrypoint/cmd — what a container runtime would read from the
/// image config), so a caller booting the exported image can run its command the way
/// `docker run` would — e.g. `run -f` putting the base image's `PATH` in scope so
/// `cargo` resolves. The same config is written as the `<out>.json` sidecar, so a
/// later boot of the ext4 (a fresh unit skipping a rebuild) reads it without a build.
#[derive(Default)]
pub struct Built {
    pub config: vk_core::runcfg::RunConfig,
}

/// The runtime-config sidecar path for a built ext4: `<out>.json` (appended, so
/// `svc.ext4` maps to `svc.ext4.json`).
pub fn config_sidecar(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".json");
    PathBuf::from(s)
}

/// A stage's final [`ShellState`] as the exported [`RunConfig`].
fn run_config(st: &ShellState) -> vk_core::runcfg::RunConfig {
    vk_core::runcfg::RunConfig {
        env: st.env.clone(),
        user: st.user.clone(),
        workdir: st.workdir.clone(),
        entrypoint: st.entrypoint.clone(),
        cmd: st.cmd.clone(),
        exposed_ports: st.exposed_ports.clone(),
    }
}

/// Resolve the instruction-cache destination: an explicit registry/store wins; `none`
/// disables; the default is the builtin local store — the same content-addressed root
/// a `vk registry serve` shares, accessed in-process (no server, no port). Only absolute
/// paths and `file://` URLs select the in-process store, everything else is a registry
/// host — so a spelling that names neither is refused rather than read as one of them.
pub(crate) fn cache_repo(cache_registry: Option<&str>) -> Result<Option<String>> {
    Ok(match cache_registry {
        Some("none") => None,
        // A hostname can start with neither a dot nor nothing at all, and a `file://` URL
        // that continues with anything but `/` is a path relative to wherever `vk` happens
        // to be running — all three of which Registry::local_root_of would otherwise take
        // for a registry host or for a store at a path nobody named.
        Some(repo)
            if repo.trim().is_empty()
                || repo.starts_with('.')
                || matches!(repo.strip_prefix("file://"), Some(p) if !p.starts_with('/')) =>
        {
            bail!(
                "cache destination {repo:?} names no absolute store path; \
                 an in-process store needs an absolute path (or a file:// URL)"
            )
        }
        Some(repo) => Some(repo.to_string()),
        None => Some(
            vk_registry::default_root()
                .context("resolving the builtin cache store dir")?
                .display()
                .to_string(),
        ),
    })
}

/// Where the instruction cache keeps what it caches, as [`cache_store`] answers it.
/// `Server` is not a failure: the store is simply on that host, and the one thing the
/// commands that operate on a store must not do is take the builtin one — which the cache
/// never touches — for it.
#[derive(Debug, PartialEq, Eq)]
pub enum CacheStore {
    /// a store in this filesystem
    Dir(PathBuf),
    /// a `vk-registry` repo: its store is on that host
    Server(String),
}

/// The store the instruction cache is configured to use: what `vk registry status`/`gc`
/// operate on, and what `vk paths` reports, when no `--root` names another store. It is
/// [`cache_repo`]'s destination whenever that is a store in this filesystem, and the
/// builtin store when caching is off — the store anything cached before it was turned off
/// is still in.
///
/// `Err` keeps meaning what it means everywhere else: a `cache_registry` that names no
/// store at all, or no place to put the builtin one.
pub fn cache_store(cache_registry: Option<&str>) -> Result<CacheStore> {
    let Some(repo) = cache_repo(cache_registry)? else {
        let dir = vk_registry::default_root().context("resolving the builtin cache store dir")?;
        return Ok(CacheStore::Dir(dir));
    };
    Ok(match crate::config::Registry::local_root_of(&repo) {
        Some(dir) => CacheStore::Dir(dir),
        None => CacheStore::Server(repo),
    })
}

/// The synthetic single-`FROM` plan for a pulled image — how `run --compose`
/// materializes an `image:` service through the builder (and its base cache)
/// instead of a separate pull path. The ref must be a plain reference: anything
/// with whitespace/control characters could smuggle extra instructions into the
/// parsed plan.
pub fn image_plan_input(image: &str) -> Result<PlanInput> {
    if image.is_empty() || image.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("invalid image reference {image:?}");
    }
    Ok(PlanInput {
        dockerfile: parser::parse(&format!("FROM {image}\n"))?,
        origin: image.into(),
        context: "/nonexistent".into(), // no COPY in a bare FROM plan
    })
}

/// Read + parse the Dockerfiles into [`PlanInput`]s, zipping each with its context
/// (`--context` values pair positionally with `-f`; a file without one defaults to
/// its own directory).
fn load_inputs(dockerfiles: &[PathBuf], contexts: &[PathBuf]) -> Result<Vec<PlanInput>> {
    if dockerfiles.is_empty() {
        bail!("no Dockerfile given");
    }
    if contexts.len() > dockerfiles.len() {
        bail!(
            "{} --context values for {} -f file(s) — contexts zip positionally with -f",
            contexts.len(),
            dockerfiles.len()
        );
    }
    dockerfiles
        .iter()
        .enumerate()
        .map(|(i, dockerfile)| {
            let src = std::fs::read_to_string(dockerfile)
                .with_context(|| format!("reading {}", dockerfile.display()))?;
            let context = contexts
                .get(i)
                .cloned()
                .unwrap_or_else(|| default_context(dockerfile));
            // Resolve to an absolute path: the microVM backend shares the context into the
            // guest over virtio-fs, and libkrun's in-process server mounts the host dir
            // directly — an empty or cwd-relative path serves nothing, so a context `COPY`
            // fails inside the guest with `Connection refused` (os error 111). (cloud-hypervisor
            // masked this: its virtiofsd resolves a relative/empty dir against its own cwd.)
            let context = std::path::absolute(&context)
                .with_context(|| format!("resolving build context {}", context.display()))?;
            Ok(PlanInput {
                dockerfile: parser::parse(&src)
                    .with_context(|| format!("parsing {}", dockerfile.display()))?,
                origin: dockerfile.clone(),
                context,
            })
        })
        .collect()
}

/// The default build context for a `-f <dockerfile>` given no explicit `--context`: the
/// Dockerfile's directory. `Path::parent()` of a bare filename (`-f Dockerfile`) is
/// `Some("")`, not `None`, so an empty parent must fall back to `.` too — otherwise the
/// context becomes the empty path, which serves no files into the guest.
fn default_context(dockerfile: &Path) -> PathBuf {
    match dockerfile.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Entry point for the `build` subcommand.
pub fn build(opts: &Options) -> Result<Built> {
    let inputs = load_inputs(&opts.dockerfiles, &opts.contexts)?;
    build_inputs(inputs, opts)
}

/// Filename prefix for a build's scratch dir, named `<prefix><pid>-<seq>-<nonce>`. The three
/// fields only keep concurrent builds off each other's dir; what marks one live is the lock
/// its owner holds on it (see [`claim_scratch`]), not anything in its name. The pid stays
/// first so a sweep can recognise this process's own dirs, and for the diagnostic value of
/// knowing which process left one behind.
const SCRATCH_PREFIX: &str = ".build-";

/// 64 random bits in hex, for a scratch dir name.
///
/// Pid and counter alone are not unique where a pid is not: a build in its own PID namespace
/// (a container sharing the output directory) starts its counter at 0 like everybody else, so
/// host pid 42 and container pid 42 name the same dir — and the loser of that collision fails
/// with "in use by another build" rather than getting on with it. Two builds on different
/// hosts sharing an output directory over a network filesystem collide the same way, which no
/// namespace-derived identifier would fix either.
///
/// Unlike `ext4`'s UUID this is not a hint, so there is no falling back to a constant: that
/// would put the collision straight back. A `/dev/urandom` that cannot be read is an error.
fn scratch_nonce() -> Result<String> {
    use std::io::Read;

    let mut bytes = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .context("reading /dev/urandom for a unique build scratch dir name")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The scratch dir for a build writing to `out`, unique per run
/// (`<prefix><pid>-<seq>-<nonce>`, see [`scratch_nonce`]).
/// Placed next to `out` so stage ext4s land on the real filesystem the caller chose, not
/// a small/RAM-backed tmpfs — but always made absolute: stage qcow2 overlays record their
/// backing image by path, and qcow2 resolves a *relative* backing against the overlay's
/// own directory, so a cwd-relative scratch (from a relative `--out`) would apply the
/// prefix twice and fail to open the backing.
fn build_scratch(out: &Path, seq: u64) -> Result<PathBuf> {
    let rel = out.parent().unwrap_or_else(|| Path::new(".")).join(format!(
        "{SCRATCH_PREFIX}{}-{seq}-{}",
        std::process::id(),
        scratch_nonce()?
    ));
    // Must be absolute (see above); the relative fallback would reintroduce the exact
    // backing-path bug, so surface the error instead of silently using it.
    std::path::absolute(&rel).context("resolving the build scratch dir to an absolute path")
}

/// How long [`claim_scratch`] keeps retrying a scratch dir it cannot take. Contention is a
/// sweep removing the dir we just created — no other build computes this name (see
/// [`scratch_nonce`]) — which resolves as soon as that removal finishes. But a scratch dir
/// holds whole stage images, so "as soon as" is not instant and a tight spin would fail a
/// build that only had to wait. Long enough to outlast any real removal, short enough that a
/// dir stuck locked is reported rather than waited on forever.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`claim_scratch`] waits between attempts. Same backoff `cachelock` uses when it
/// waits for a reclaim to finish.
const CLAIM_RETRY: Duration = Duration::from_millis(20);

/// Create `scratch` and claim it for the life of the returned handle: an exclusive,
/// non-blocking `flock` on the directory itself, which the kernel drops when the process
/// exits however it exits. [`sweep_stale_scratch`] reclaims a scratch dir only when it can
/// take that lock itself, i.e. when no live process holds it. The same scheme `vk run` uses
/// for its state dir (`run::lock_state_dir`, `vms::alive`).
///
/// This is what the pid in the dir name cannot do: a build running in its own PID namespace
/// (a container sharing the output directory over a bind mount) has a pid that means nothing
/// to a sweeper outside it, which would then read a live build as dead and delete its
/// scratch mid-run. A file lock is namespace-independent — it is the open file description
/// that holds it, not a pid the sweeper has to interpret. It does need the filesystem to
/// carry `flock` to the host, which a bind mount and NFS do but virtio-fs does not, so a
/// build inside a *microVM* writing to a share is no better off than before.
///
/// Locking the directory rather than a file inside it is what makes a sweep safe to race:
/// `remove_dir_all` empties the directory before removing it, and the directory inode — and
/// so the sweeper's lock on it — outlives that whole walk. A build cannot end up inside a
/// removal in progress; it either waits it out or claims the fresh directory afterwards.
fn claim_scratch(scratch: &Path) -> Result<std::fs::File> {
    claim_scratch_until(scratch, Instant::now() + CLAIM_TIMEOUT)
}

/// [`claim_scratch`] with the retry deadline spelled out, so a test can ask for a single
/// attempt (`Instant::now()`) instead of waiting the real one out.
fn claim_scratch_until(scratch: &Path, deadline: Instant) -> Result<std::fs::File> {
    use std::os::unix::io::AsRawFd;

    loop {
        std::fs::create_dir_all(scratch)
            .with_context(|| format!("creating the build scratch dir {}", scratch.display()))?;
        let dir = match std::fs::File::open(scratch) {
            Ok(dir) => Some(dir),
            // Swept between our create and our open — we had nothing to lock yet, so a sweep
            // was right to take it. Same answer as a `same_file` mismatch below: try again.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("opening {}", scratch.display())),
        };
        if let Some(dir) = dir {
            // SAFETY: the fd is owned by `dir`, which the caller keeps alive; flock returns
            // 0 or -1 and does not block under `LOCK_NB`.
            if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                // Only a lock on the directory the path still names is worth anything: a
                // sweep can have removed the one we opened before we locked it (see
                // `cachelock::acquire_shared` for the same reasoning about a file). If it
                // did, the next attempt creates one of our own.
                if crate::cachelock::same_file(&dir, scratch)? {
                    return Ok(dir);
                }
            } else {
                // A build must know it owns its scratch, so unlike the sweep — which reads
                // an unlockable dir as live and moves on — anything other than contention is
                // fatal here, including a filesystem that cannot `flock` at all.
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(err).with_context(|| format!("locking {}", scratch.display()));
                }
            }
        }
        if Instant::now() >= deadline {
            // Names carry a nonce, so no other build computes this one: whoever holds it is a
            // sweep that has been reclaiming it for the whole deadline.
            bail!(
                "the build scratch dir {} stayed locked by a reclaim for {}s — retry, or \
                 build with a different --out directory",
                scratch.display(),
                CLAIM_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(CLAIM_RETRY);
    }
}

/// Resolve the microVM's kernel + agent and hold them for the whole build: an embedded
/// asset lives in a memfd whose `/proc/self/fd` path is valid only while the fd is open,
/// and every stage boot (and the initramfs packer) reopens it — so the caller keeps the
/// returned handles alive until the build finishes.
fn resolve_kernel_agent(
    opts: &Options,
) -> Result<(crate::embed::Resolved, crate::embed::Resolved)> {
    let kernel = crate::embed::resolve(crate::embed::Asset::Kernel, opts.kernel.as_deref())?;
    if !kernel.is_embedded() && !kernel.path.is_file() {
        bail!(
            "kernel not found at {} (pass --kernel, or use a `vk` with it embedded)",
            kernel.path.display()
        );
    }
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, opts.agent.as_deref())?;
    if !agent.is_embedded() && !agent.path.is_file() {
        bail!(
            "vk-agent not found at {} (pass --agent, or use a `vk` with it embedded)",
            agent.path.display()
        );
    }
    Ok((kernel, agent))
}

/// Build the microVM backend for a build: its instruction-cache registry (if any), the
/// cloud-hypervisor binary (only needed when `VIRTKIT_VMM` selects that backend), and the
/// `MicroVm` itself over `scratch`. Shared by the single-target [`build_backend`] and the
/// unified multi-unit [`build_units`], so the two construct the backend identically.
fn make_microvm(
    opts: &Options,
    scratch: &Path,
    kernel: &Path,
    agent: &Path,
    timings: &Arc<Timings>,
) -> Result<MicroVm> {
    let cache = cache_repo(opts.cache_registry.as_deref())?.map(|repo| {
        crate::config::Registry::for_share(
            repo,
            opts.cache_insecure,
            opts.cache_auth.ca_file.clone(),
            opts.cache_auth.username.clone(),
            opts.cache_auth.password_file.clone(),
            opts.cache_auth.token_file.clone(),
            None,
        )
    });
    // cloud-hypervisor is only needed when VIRTKIT_VMM selects it; the default libkrun
    // backend is embedded in `vk` and drives no external VMM binary.
    let ch = if crate::vmm::libkrun_selected() {
        opts.cloud_hypervisor.clone().unwrap_or_default()
    } else {
        opts.cloud_hypervisor.clone().context(
            "the cloud-hypervisor backend (VIRTKIT_VMM=cloud-hypervisor) needs \
             --cloud-hypervisor",
        )?
    };
    let cpus = exec::resolve_build_cpus(configured_build_cpus(), exec::host_cpus());
    let mem = exec::resolve_build_mem(configured_build_mem().as_deref());
    Ok(MicroVm::new(
        ch,
        kernel.to_path_buf(),
        agent.to_path_buf(),
        scratch.to_path_buf(),
        cpus,
        mem,
        cache,
        opts.net.clone(),
        opts.debug,
        !opts.tmp_tmpfs,
        // Audit channel shared across the build's parallel stage switches (all workers
        // share `scratch`); the summary is drained once the build finishes.
        opts.audit.then(|| scratch.join(crate::run::AUDIT_LOG)),
        Arc::clone(timings),
    ))
}

/// Stamp an exported ext4 with its content-freshness UUID — `fingerprint([stage_key])`, the
/// identity `vk fingerprint` (and the dev-VM staleness check) expects a bootable image to
/// carry. The export tail (flatten + `normalize_superblock`) leaves the flattened base/cache
/// UUID untouched, so without this a freshly built/exported image never matches its own stage
/// key. Both export paths ([`build_backend`] and [`build_units`]) call this on every exported
/// image.
fn stamp_stage_uuid(out: &Path, stage_key: &str) -> Result<()> {
    let uuid = crate::ensure::parse_uuid(&crate::ensure::fingerprint(&[stage_key]))
        .expect("fingerprint is a canonical UUID");
    crate::ext4::set_uuid(out, &uuid)
}

/// [`build`] for a caller that already holds parsed [`PlanInput`]s — e.g. `vk run
/// --compose` materializing an `image:` service as the synthetic single-`FROM`
/// plan, with no Dockerfile on disk. `opts.dockerfiles`/`opts.contexts` are the
/// file-loading path's inputs and are ignored here; everything else applies.
pub fn build_inputs(inputs: Vec<PlanInput>, opts: &Options) -> Result<Built> {
    build_backend(inputs, opts, true)
}

/// Backend-parameterized [`build_inputs`]. `microvm` selects the real microVM backend
/// (every production build) or the host backend — `FROM scratch` + `COPY`, no VM — which
/// exists only so tests can exercise the whole pipeline (plan → drive → export → sidecar)
/// without KVM. There is no user-facing switch: production is always the microVM backend,
/// so `microvm == false` is reachable from `#[cfg(test)]` alone.
fn build_backend(inputs: Vec<PlanInput>, opts: &Options, microvm: bool) -> Result<Built> {
    let build_args: Vars = opts.build_args.iter().cloned().collect();
    // Timing breakdown, shared across the parallel stage workers and rendered once the
    // build finishes (see [`Timings::render`]). Started here so the plan phase is timed.
    let timings = Arc::new(Timings::new());
    // What the build costs the host, reported next to the breakdown (see `usage`). Started
    // alongside it, so the two cover the same work. Only for the microVM backend: the host
    // backend runs no guest to account for, and is only ever reached from this file's tests,
    // whose threads would otherwise meter the same process as `usage`'s own.
    let meter = microvm.then(crate::usage::Meter::start);
    let t_plan = Instant::now();
    let mut plan = Plan::from_dockerfiles(&inputs, &build_args)?;
    plan.named_contexts = named_context_map(&opts.build_contexts)?;
    // Before anything is resolved or built: a mistyped stage name should cost nothing.
    let matched = apply_stage_overrides(&mut plan, &opts.stage_guests);
    unmatched_stage_overrides(&opts.stage_guests, &matched, &stage_names(&plan))?;
    let target = plan.resolve_target(opts.target.as_deref())?;
    let order = plan.build_order(target)?;
    // Reject a cross-stage source under /tmp up front: /tmp is ephemeral and never
    // committed, so it would fail late with a cryptic "No such file" from the guest. Same for a
    // stage by a reserved name, which nothing could read from.
    plan.check_reserved_names(&order)?;
    plan.check_tmp_sources(&order)?;
    timings.record(Phase::Plan, "", t_plan.elapsed());

    // --print-plan: dry-run the whole pipeline and print the primitives, build nothing.
    if opts.print_plan {
        let mut ex = DryRun::new();
        drive(
            &plan,
            &order,
            &build_args,
            &mut ex,
            false,
            opts.build_cache,
            &Progress::disabled(),
            &timings,
        )?;
        println!("# build order: {order:?} (target stage {target})");
        for line in &ex.transcript {
            println!("{line}");
        }
        return Ok(Built::default());
    }

    // Real build: materialize each stage through the selected backend and export the
    // target as an ext4 (via virtkit's own builder — no docker/buildkit/mke2fs). The host
    // backend (tests only) handles just FROM scratch + COPY and errors on RUN / FROM
    // <image>; the microVM backend handles the full shape.
    // `--out` exports the target stage's rootfs ext4; `--disk` writes the artifact into a
    // caller-owned disk during the build. At least one is required (or --print-plan). With
    // only `--disk`, the disk is the sole output and no rootfs ext4 is exported.
    let out = opts.out.as_deref();
    let anchor = out
        .or(opts.out_disk.as_deref())
        .context("build needs --out <file> or --disk <file> (or --print-plan)")?;
    // Scratch placement + naming: see [`build_scratch`]. Keyed by an in-process counter (so
    // two builds in one process — `run --compose` materializing several services, or parallel
    // tests — never share, the first one's cleanup would otherwise delete the second's) plus a
    // nonce, which is what keeps builds that cannot see each other's pids apart.
    static BUILD_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = BUILD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let scratch = build_scratch(anchor, seq)?;
    // Self-heal: a build normally removes its scratch on exit (even on error), but a hard
    // kill (SIGKILL/OOM/Ctrl-C/panic) orphans it. Before starting, drop any sibling
    // scratch nobody is holding, so crashed runs don't accumulate.
    if let Some(parent) = scratch.parent() {
        sweep_stale_scratch(parent, SCRATCH_PREFIX);
    }
    // Resolve the microVM's kernel + agent up front and hold them for the whole build (see
    // [`resolve_kernel_agent`]).
    let (kernel, agent) = if microvm {
        let (k, a) = resolve_kernel_agent(opts)?;
        (Some(k), Some(a))
    } else {
        (None, None)
    };
    // Claim ours for the length of the build, so a concurrent sweep (another build starting
    // beside us) can tell it is live without having to interpret our pid. After the resolve
    // above, so its failure leaves no scratch dir behind.
    let _scratch_owner = claim_scratch(&scratch)?;
    // Live build overview (Docker/buildkit-style): a dashboard in a terminal, plain `#N`
    // lines otherwise. The drivers populate it (which stages/steps run) once they know the
    // needed set, and route each stage's guest output through it.
    let progress = build_progress(opts);
    let result = (|| -> Result<Built> {
        // The microVM backend drives stages in parallel over the dependency DAG (each
        // stage on its own guest); the host backend (FROM scratch + COPY) stays
        // sequential. Both produce the same committed map, then share the export tail.
        let (committed, states, mut ex): (_, _, Box<dyn Executor>) = if microvm {
            let kernel = kernel.as_ref().expect("resolved under microvm");
            let agent = agent.as_ref().expect("resolved under microvm");
            let mv = make_microvm(opts, &scratch, &kernel.path, &agent.path, &timings)?;
            // One reading for both: the ceiling fits stages into it, the gate measures
            // against it. The ceiling is over the sizes this build's stages actually
            // declare, not over one nominal size they no longer share.
            let host_total_mib = crate::schedule::host_total_mib();
            let sizes = stage_sizes(&plan, &order, mv.mem_mib());
            let jobs = resolve_build_jobs(opts, &sizes, host_total_mib);
            progress.note(&concurrency_line(
                jobs,
                mv.cpus(),
                mv.mem(),
                opts.build_jobs.is_some(),
                &sized_stages(&plan, &order, ""),
            ));
            let gate_mib = gate_total_mib(host_total_mib);
            if let Some(line) = gate_note(jobs, gate_mib) {
                progress.note(&line);
            }
            let (committed, states) = drive_microvm(
                &plan,
                &order,
                &build_args,
                &mv,
                jobs,
                gate_mib,
                opts.require_cached,
                opts.build_cache,
                opts.out_disk.as_deref(),
                &progress,
                &timings,
            )?;
            // `mv` shares the workers' `images` map (same Arc), so it can export the
            // target and is reused as the exporter.
            (committed, states, Box::new(mv))
        } else {
            let mut ex = Host::new(scratch.clone());
            let (committed, states) = drive(
                &plan,
                &order,
                &build_args,
                &mut ex,
                opts.require_cached,
                opts.build_cache,
                &progress,
                &timings,
            )?;
            (committed, states, Box::new(ex))
        };
        let fs = committed
            .get(&target)
            .context("internal: target stage not committed")?;
        let st = states.get(&target).cloned().unwrap_or_default();
        let config = run_config(&st);
        // Export the target's rootfs ext4 only when --out is given; a --disk-only build
        // has already written its artifact into the caller's disk during the RUNs.
        if let Some(out) = out {
            progress.export_start(0);
            let t_export = Instant::now();
            ex.export_ext4(fs, out)?;
            timings.record(Phase::Export, "", t_export.elapsed());
            progress.export_done(0);
            // Stamp the exported image with its content-freshness UUID (fingerprint of the
            // target's stage key) so `vk fingerprint` matches it. The keys are re-derived
            // read-only via the drive backend (base digests/configs it already memoized).
            let key = resolve_stages(&plan, &order, &build_args, ex.as_mut(), None)?
                .get(&target)
                .context("internal: target stage not resolved")?
                .final_key
                .clone();
            stamp_stage_uuid(out, &key)?;
            // Journal *after* the UUID stamp: `ext4::set_uuid` refuses an already-journaled
            // image (the JBD2 superblock embeds the UUID at journal creation), so this must
            // stay ordered after `stamp_stage_uuid` above, never before.
            if opts.journal {
                crate::ext4::add_journal(out)?;
            }
            // The sidecar persists the config the image itself deliberately does not
            // carry (clean-image model: config is supplied at boot, never baked in).
            let sidecar = config_sidecar(out);
            std::fs::write(&sidecar, serde_json::to_vec_pretty(&config)?)
                .with_context(|| format!("writing {}", sidecar.display()))?;
        }
        Ok(Built { config })
    })();
    // Leave the final dashboard frame on screen (FINISHED/FAILED) before any teardown log.
    progress.finish(result.is_ok());
    timings.render();
    // What the build cost the host, next to where its time went. Every stage guest is a
    // child this process has already waited for (each stage ends by tearing its guest down),
    // so the figures are complete. After the dashboard froze, so it is safe to print. Silent
    // when the meter cannot attribute them to this build alone (see `usage`).
    if let Some(usage) = meter.and_then(|m| m.read()) {
        // The egress figure comes from the stage switches, which publish into the scratch
        // this reads before removing it — a build's guests are gone by now, and each was
        // stopped rather than killed so nothing it carried went unpublished.
        let usage = usage.with_network(&scratch.join(crate::run::NET_BYTES));
        eprintln!("{}", usage.summary("build"));
    }
    // `--build-audit-egress`: the domains the build's RUN steps contacted (read before the
    // scratch, which holds the audit channel, is removed). After the dashboard froze, so it is
    // safe to print. "during the build" distinguishes it from a `vk run` guest summary. A
    // no-op when audit was off.
    if let Some(summary) = crate::egress_report::contacts_summary(
        &scratch.join(crate::run::AUDIT_LOG),
        "external domains contacted during the build (audit)",
    ) {
        eprintln!("{summary}");
    }
    if let Some(summary) = crate::egress_report::ip_contacts_summary(
        &scratch.join(crate::run::AUDIT_LOG),
        "external IPs/ports contacted during the build (audit)",
    ) {
        eprintln!("{summary}");
    }
    let _ = std::fs::remove_dir_all(&scratch); // best-effort scratch cleanup
    let built = result?;
    let srcs = inputs
        .iter()
        .map(|i| i.origin.display().to_string())
        .collect::<Vec<_>>()
        .join(" + ");
    match out {
        Some(out) => println!("virtkit: built {srcs} -> {}", out.display()),
        None => println!(
            "virtkit: built {srcs} -> disk {}",
            opts.out_disk.as_deref().unwrap().display()
        ),
    }
    Ok(built)
}

/// Where one build unit's stages come from (see [`build_units`]): built from
/// Dockerfile(s) + context(s), or pulled as the synthetic single-`FROM` plan of an
/// `image:` reference.
pub enum UnitInput {
    Build {
        dockerfiles: Vec<PathBuf>,
        /// zipped positionally with `dockerfiles` (a file without one defaults to its dir)
        contexts: Vec<PathBuf>,
        /// this unit's named build contexts: a compose service's `additional_contexts`, or
        /// the build-wide `--build-context` values on the `-f` multi-target path
        build_contexts: Vec<(String, PathBuf)>,
    },
    Image(String),
}

/// One target of a build unit: a stage of the unit's plan to materialize. `out` is where
/// its ext4 is exported (its config sidecar written beside it); `None` warms the
/// instruction cache without exporting anything — e.g. a prebuild that only wants the
/// cached snapshots. `label` names it in the dashboard and keys the returned [`Built`].
pub struct TargetSpec {
    pub label: String,
    /// stage selector (an `AS` name or index); `None` = the plan's last stage
    pub selector: Option<String>,
    pub out: Option<PathBuf>,
}

/// One build unit: a single plan (shared by all its `targets`) plus the build args it is
/// resolved under. Several targets of one unit share every common stage — it is built once
/// — so a multi-target unit is strictly cheaper than repeating a single-target build. Units
/// with different inputs stay separate (their stages can't be shared).
pub struct BuildUnit {
    /// disambiguates this unit's stage rows on the dashboard when a build spans several
    /// units (a lone unit needs no prefix). Also namespaces the executor's per-stage
    /// identity so two units with a same-named stage don't collide.
    pub label: String,
    pub input: UnitInput,
    pub build_args: Vec<(String, String)>,
    pub targets: Vec<TargetSpec>,
}

/// Build a set of units as ONE build: every unit's needed stages run in a single dependency
/// DAG over one job pool (so independent work runs concurrently under a single host-RAM
/// budget), sharing one microVM backend (identical bases build/restore once) and one live
/// dashboard. Within a unit, stages common to several targets build once; each target with
/// an `out` is exported there (with its config sidecar), and every target's runtime config
/// is returned keyed by its label. Microvm backend only (every compose / multi-target build).
///
/// A unit's stage identities are namespaced by its label — the executor keys its `images`
/// map and scratch files by stage name, so without the prefix two units with a same-named
/// (or both unnamed) stage would collide. There are no cross-unit build edges, so each unit
/// keeps its own [`Plan`].
pub fn build_units(units: Vec<BuildUnit>, opts: &Options) -> Result<HashMap<String, Built>> {
    if units.is_empty() {
        return Ok(HashMap::new());
    }
    let timings = Arc::new(Timings::new());
    let meter = crate::usage::Meter::start();
    let (kernel, agent) = resolve_kernel_agent(opts)?;

    // One scratch dir for the whole build, placed next to some target's output (any target
    // that exports), else the disk-backed scratch base for a cache-only build. NOT
    // std::env::temp_dir(): that is often a small RAM-backed tmpfs (e.g. a 16 GiB /tmp,
    // possibly quota-capped), and the stage qcow2/ext4 files a heavy build writes here would
    // exhaust it — surfacing as EDQUOT/ENOSPC on the host copy and, once a stage's qcow2 can
    // no longer grow, EIO inside the guest (a failed dpkg fsync). The run path already anchors
    // its cache-only scratch on default_scratch_base() for exactly this reason. Swept of
    // orphaned siblings first.
    let anchor = match units
        .iter()
        .flat_map(|u| &u.targets)
        .find_map(|t| t.out.clone())
    {
        Some(out) => out,
        None => crate::run::default_scratch_base()?.join("vk-build"),
    };
    static BUILD_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = BUILD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let scratch = build_scratch(&anchor, seq)?;
    if let Some(parent) = scratch.parent() {
        sweep_stale_scratch(parent, SCRATCH_PREFIX);
    }
    // As in `build_backend`: hold the scratch's own lock for the whole build.
    let _scratch_owner = claim_scratch(&scratch)?;
    let mut mv = make_microvm(opts, &scratch, &kernel.path, &agent.path, &timings)?;
    // One job budget for every unit's stages combined (not per unit), so concurrent work
    // stays within host RAM instead of multiplying live guests. The ceiling itself is
    // resolved further down, once every unit's plan says how big its stages are.
    let host_total_mib = crate::schedule::host_total_mib();

    // A lone unit's stage names are already unique, so it needs no prefix (the dashboard
    // reads exactly like a single build); several units prefix by label to disambiguate.
    let multi_unit = units.len() > 1;
    let prefix_of = |u: &BuildUnit| -> String {
        if multi_unit {
            format!("{}:", u.label)
        } else {
            String::new()
        }
    };

    let progress = build_progress(opts);
    let result = (|| -> Result<HashMap<String, Built>> {
        /// One resolved target of a unit: its stage index and where it exports.
        struct Tgt {
            idx: usize,
            label: String,
            out: Option<PathBuf>,
        }
        /// One resolved unit: its plan/keys, the needed subset, and the base offset that
        /// maps its local stage indices into the build-wide id space.
        struct Unit {
            prefix: String,
            plan: Plan,
            order: Vec<usize>,
            resolved: HashMap<usize, Resolved>,
            needed: HashSet<usize>,
            cached_final: HashMap<usize, String>,
            targets: Vec<Tgt>,
            /// this unit occupies global ids `[base, base + plan.stages.len())`.
            base: usize,
        }

        // Read-only resolve for every unit on one shared probe worker (so identical base
        // digests/configs are fetched once across units).
        let mut probe = mv.worker();
        let mut resolved_units: Vec<Unit> = Vec::with_capacity(units.len());
        let mut base = 0usize;
        let mut matched_overrides: HashSet<String> = HashSet::new();
        let mut known_stages: Vec<String> = Vec::new();
        for unit in &units {
            let build_args: Vars = unit.build_args.iter().cloned().collect();
            let inputs = match &unit.input {
                UnitInput::Build {
                    dockerfiles,
                    contexts,
                    ..
                } => load_inputs(dockerfiles, contexts),
                UnitInput::Image(image) => Ok(vec![image_plan_input(image)?]),
            }
            .with_context(|| format!("build unit {:?}", unit.label))?;
            let mut plan = Plan::from_dockerfiles(&inputs, &build_args)
                .with_context(|| format!("build unit {:?}", unit.label))?;
            // Each unit's own named contexts: a compose service's `additional_contexts`, or the
            // `--build-context` values the `-f` multi-target path copies into its single unit.
            // There is never a build-wide set to merge under a compose unit: `vk build` refuses
            // the flag with `--compose`, and a compose service build gets its options from
            // `service_build_options`, which declares none. An `image:` unit's synthetic
            // single-`FROM` plan has no COPY that could read one.
            if let UnitInput::Build { build_contexts, .. } = &unit.input {
                plan.named_contexts = named_context_map(build_contexts)?;
            }
            // A stage name addresses that stage in every unit declaring one: units are
            // separate Dockerfiles, and a name is wrong only if no unit has it at all.
            matched_overrides.extend(apply_stage_overrides(&mut plan, &opts.stage_guests));
            known_stages.extend(stage_names(&plan));
            let targets: Vec<Tgt> = unit
                .targets
                .iter()
                .map(|t| {
                    Ok(Tgt {
                        idx: plan.resolve_target(t.selector.as_deref())?,
                        label: t.label.clone(),
                        out: t.out.clone(),
                    })
                })
                .collect::<Result<_>>()
                .with_context(|| format!("build unit {:?}", unit.label))?;
            let target_idxs: Vec<usize> = targets.iter().map(|t| t.idx).collect();
            let order = plan.build_order_multi(&target_idxs)?;
            plan.check_reserved_names(&order)?;
            plan.check_tmp_sources(&order)?;
            let resolved = resolve_all(&plan, &order, &build_args, &mut probe, &target_idxs)?;
            let (needed, cached_final) = compute_needed(
                &plan,
                &order,
                &resolved,
                &mut probe,
                opts.require_cached,
                &target_idxs,
            )
            .with_context(|| format!("build unit {:?}", unit.label))?;
            let stages = plan.stages.len();
            resolved_units.push(Unit {
                prefix: prefix_of(unit),
                plan,
                order,
                resolved,
                needed,
                cached_final,
                targets,
                base,
            });
            base += stages;
        }
        drop(probe);
        // Later than `build_backend`'s equivalent, which rejects a mistyped name before
        // anything is resolved: here a name is only wrong once *every* unit has failed to
        // match it, and each unit's plan is resolved in the same pass that collects them.
        unmatched_stage_overrides(&opts.stage_guests, &matched_overrides, &known_stages)?;

        // Every unit's stages against one budget, so the ceiling is over what this build
        // will actually run — several units' worth of stages, each the size it declared.
        let sizes: Vec<u64> = resolved_units
            .iter()
            .flat_map(|u| stage_sizes(&u.plan, &u.order, mv.mem_mib()))
            .collect();
        let jobs = resolve_build_jobs(opts, &sizes, host_total_mib);
        timings.note_jobs(jobs); // so the timing header reports "busy across N jobs"
        let sized: Vec<String> = resolved_units
            .iter()
            .flat_map(|u| sized_stages(&u.plan, &u.order, &u.prefix))
            .collect();
        progress.note(&concurrency_line(
            jobs,
            mv.cpus(),
            mv.mem(),
            opts.build_jobs.is_some(),
            &sized,
        ));
        let gate_mib = gate_total_mib(host_total_mib);
        if let Some(line) = gate_note(jobs, gate_mib) {
            progress.note(&line);
        }

        // The dashboard: every unit's needed stages under one flat id space (prefixed per
        // unit); one export tail per target that actually exports.
        let inits: Vec<StageInit> = resolved_units
            .iter()
            .flat_map(|u| stage_inits(&u.plan, &u.order, &u.resolved, &u.needed, u.base, &u.prefix))
            .collect();
        let exports = resolved_units
            .iter()
            .flat_map(|u| &u.targets)
            .filter(|t| t.out.is_some())
            .count();
        progress.init(inits, exports);

        // The build-wide DAG: each unit's needed stages as global-id nodes, with edges only
        // among that unit's own stages (no cross-unit dependencies). A fully-cached stage
        // restores standalone, so it gets no deps.
        let mut nodes: Vec<usize> = Vec::new();
        let mut deps: HashMap<usize, Vec<usize>> = HashMap::new();
        for u in &resolved_units {
            for &idx in &u.order {
                if !u.needed.contains(&idx) {
                    continue;
                }
                let d = if u.cached_final.contains_key(&idx) {
                    Vec::new()
                } else {
                    u.plan
                        .deps(idx)
                        .into_iter()
                        .filter(|x| u.needed.contains(x))
                        .map(|x| u.base + x)
                        .collect()
                };
                nodes.push(u.base + idx);
                deps.insert(u.base + idx, d);
            }
        }

        // Decode a global id back to its unit (ids are contiguous per unit, in order), so the
        // worker can pick the right plan/keys and localize the done map.
        let bounds: Vec<(usize, usize)> = resolved_units
            .iter()
            .map(|u| (u.base, u.base + u.plan.stages.len()))
            .collect();
        let unit_of = |gid: usize| -> usize {
            bounds
                .iter()
                .position(|&(lo, hi)| lo <= gid && gid < hi)
                .expect("global stage id maps to a unit")
        };

        let cancel = CancellationToken::new();
        // `budget` caps concurrent guest builds — `jobs` slots, plus the host-memory
        // ledger — not the DAG dispatch pool: a fully-cached stage never touches a guest,
        // so it must not queue behind either just to restore from cache. Dispatch gets one
        // thread per node so every cache hit can proceed the moment its deps are ready;
        // total thread count (and any concurrent remote build-lock requests each node's
        // uncached path makes) now scales with the DAG instead of `jobs`, which is fine
        // since a node either restores instantly or waits on `budget` next.
        let budget = BuildBudget::new(jobs, gate_mib);
        let done = run_dag(
            &nodes,
            &deps,
            nodes.len(),
            Some(&cancel),
            |gid, done_global: &HashMap<usize, Rootfs>| {
                let u = &resolved_units[unit_of(gid)];
                let local = gid - u.base;
                // The done map is build-wide; hand this stage only its own unit's committed
                // rootfs, re-keyed to local indices (its deps are all same-unit).
                let committed: HashMap<usize, Rootfs> = done_global
                    .iter()
                    .filter(|&(&g, _)| g >= u.base && g < u.base + u.plan.stages.len())
                    .map(|(&g, fs)| (g - u.base, fs.clone()))
                    .collect();
                let mut ex = mv.worker();
                build_stage(
                    &u.plan,
                    &u.resolved,
                    &u.cached_final,
                    &committed,
                    &mut ex,
                    local,
                    opts.build_cache,
                    &progress,
                    &timings,
                    Some(&cancel),
                    &u.prefix,
                    gid,
                    &budget,
                )
            },
        )?;

        // Export each exporting target to its ext4 + config sidecar (a cache-only target
        // just reports its config); `mv` shares the workers' images map, so it can export
        // every target it just built. Returned keyed by target label.
        let mut built: HashMap<String, Built> = HashMap::new();
        let mut export_i = 0usize;
        for u in &resolved_units {
            for t in &u.targets {
                let fs = done
                    .get(&(u.base + t.idx))
                    .context("internal: target stage not committed")?;
                if let Some(out) = &t.out {
                    progress.export_start(export_i);
                    let t_export = Instant::now();
                    mv.export_ext4(fs, out)
                        .with_context(|| format!("target {:?}", t.label))?;
                    timings.record(Phase::Export, &t.label, t_export.elapsed());
                    progress.export_done(export_i);
                    export_i += 1;
                    // Stamp the content-freshness UUID (fingerprint of the target's stage key)
                    // so `vk fingerprint` — and the dev-VM staleness check on the exported
                    // root.ext4 — matches it; the export tail otherwise leaves the base UUID.
                    let key = &u
                        .resolved
                        .get(&t.idx)
                        .context("internal: target stage not resolved")?
                        .final_key;
                    stamp_stage_uuid(out, key)?;
                    // Journal *after* the UUID stamp — see the single-target export path
                    // above for why the order matters.
                    if opts.journal {
                        crate::ext4::add_journal(out)?;
                    }
                    let sidecar = config_sidecar(out);
                    let st = u
                        .resolved
                        .get(&t.idx)
                        .map(|r| r.final_state.clone())
                        .unwrap_or_default();
                    std::fs::write(&sidecar, serde_json::to_vec_pretty(&run_config(&st))?)
                        .with_context(|| format!("writing {}", sidecar.display()))?;
                }
                let st = u
                    .resolved
                    .get(&t.idx)
                    .map(|r| r.final_state.clone())
                    .unwrap_or_default();
                built.insert(
                    t.label.clone(),
                    Built {
                        config: run_config(&st),
                    },
                );
            }
        }
        Ok(built)
    })();
    // Leave the final dashboard frame on screen before any teardown log.
    progress.finish(result.is_ok());
    timings.render();
    // Dropped before the meter is read, so the terminal cache-push drain its worker pool
    // joins is charged to the build like build_backend's is — there the pool goes out of
    // scope with the closure. Nothing below needs it.
    drop(mv);
    // What the whole fleet build cost the host (see build_backend's counterpart).
    if let Some(usage) = meter.read() {
        let usage = usage.with_network(&scratch.join(crate::run::NET_BYTES));
        eprintln!("{}", usage.summary("build"));
    }
    // `--build-audit-egress`: the domains the build's RUN steps contacted (read before the
    // scratch, which holds the audit channel, is removed). After the dashboard froze, so it is
    // safe to print. "during the build" distinguishes it from a `vk run` guest summary. A
    // no-op when audit was off.
    if let Some(summary) = crate::egress_report::contacts_summary(
        &scratch.join(crate::run::AUDIT_LOG),
        "external domains contacted during the build (audit)",
    ) {
        eprintln!("{summary}");
    }
    if let Some(summary) = crate::egress_report::ip_contacts_summary(
        &scratch.join(crate::run::AUDIT_LOG),
        "external IPs/ports contacted during the build (audit)",
    ) {
        eprintln!("{summary}");
    }
    let _ = std::fs::remove_dir_all(&scratch); // best-effort scratch cleanup
    let built = result?;
    for u in &units {
        for t in &u.targets {
            match &t.out {
                Some(out) => println!("virtkit: built {} -> {}", t.label, out.display()),
                None => println!("virtkit: cached {}", t.label),
            }
        }
    }
    Ok(built)
}

/// One resolved instruction ready to apply: the interpolated instruction, its chain key
/// (the content hash up to and including it), and the shell state (ENV/USER/WORKDIR) in
/// effect when it runs. Only filesystem-changing instructions (RUN/COPY) become steps —
/// ENV/WORKDIR/USER fold into the following steps' state, ARG into the interpolation
/// scope. Produced by [`resolve_stages`] so the build driver and `docker-hash` share one
/// key + interpolation computation and cannot drift.
struct Step {
    instr: Instruction,
    key: String,
    state: ShellState,
}

/// A stage resolved to its keyed instruction stream, without materializing any rootfs.
struct Resolved {
    /// the filesystem-changing instructions in order, each with its chain key + state.
    steps: Vec<Step>,
    /// the stage's final chain key (its cache identity / `stage_key`) — the key after the
    /// stage's last instruction, even a trailing ENV/WORKDIR/USER.
    final_key: String,
    /// the stage's final shell state, inherited by a child `FROM <stage>`.
    final_state: ShellState,
}

/// Replay every stage's cache-key chain and ENV/USER/WORKDIR scope in topological order,
/// without materializing anything: the base seed (the resolved manifest digest when
/// available, so a moved tag busts the cache, else the image ref), then each
/// instruction's chained key against the interpolated form. Calls only the executor's
/// read-only queries ([`Executor::resolve_base_digest`], [`Executor::base_config`]) — no
/// pull/run/copy — so it is the single source of truth for a stage's identity, shared by
/// the build driver (which then applies the steps) and `docker-hash` (which just prints
/// the keys).
fn resolve_stages(
    plan: &Plan,
    order: &[usize],
    build_args: &Vars,
    ex: &mut dyn Executor,
    dsh: Option<&str>,
) -> Result<HashMap<usize, Resolved>> {
    let mut out: HashMap<usize, Resolved> = HashMap::new();
    for &idx in order {
        let stage = &plan.stages[idx];
        // base cache key (independent of materializing the rootfs). A `FROM <image>` keys
        // on the resolved manifest digest when available; a `FROM <stage>` continues its
        // parent's chain.
        let mut key = match &stage.base {
            Base::Image(image) => match ex.resolve_base_digest(image) {
                Some(d) => hash_key(&format!("FROM image {image}@{d}")),
                None => hash_key(&format!("FROM image {image}")),
            },
            Base::Scratch => hash_key("FROM scratch"),
            Base::Stage(parent) => out
                .get(parent)
                .map(|r| r.final_key.clone())
                .context("internal: parent stage resolved out of order")?,
        };
        // The kernel a stage's RUNs run under is part of its identity: `FROM --kernel=image`
        // can produce different bytes (a RUN partitions/mkfs on a full kernel) than the
        // embedded build kernel, so fold it into the key to bust the cache when toggled.
        if stage.image_kernel {
            // `key` is already a `snap-` key; re-salting it just re-roots the chain.
            key = hash_key(&format!("{key}\nKERNEL=image"));
        }
        // Seed the shell state: a stage inherits its base — a prior stage's final
        // state, or (for FROM <image>) the image config's ENV/USER/WORKDIR/
        // ENTRYPOINT/CMD — so RUNs get the base PATH etc. and the runtime config
        // survives RUN-less stages (a service stage that only COPYs still exports
        // its base's entrypoint). Fetched unconditionally (memoized per image).
        let mut state = match &stage.base {
            Base::Stage(parent) => out
                .get(parent)
                .map(|r| r.final_state.clone())
                .unwrap_or_default(),
            Base::Image(image) => {
                let cfg = ex.base_config(image)?;
                ShellState {
                    env: cfg.env,
                    user: cfg.user.unwrap_or_else(|| "root".into()),
                    workdir: cfg.workdir.unwrap_or_else(|| "/".into()),
                    entrypoint: cfg.entrypoint,
                    cmd: cfg.cmd,
                    exposed_ports: cfg.exposed_ports,
                    build_args: Vec::new(),
                }
            }
            Base::Scratch => ShellState::default(),
        };
        if state.user.is_empty() {
            state.user = "root".into();
        }
        if state.workdir.is_empty() {
            state.workdir = "/".into();
        }
        // Interpolation scope: the inherited ENV (base image / parent stage) plus the
        // stage's own ARG/ENV as they are declared. ARG is per-stage (not inherited).
        let mut vars: Vars = state.env.iter().cloned().collect();
        let mut steps: Vec<Step> = Vec::new();
        for raw in &stage.instructions {
            // ARG only feeds the interpolation scope; it does not chain into the key, and
            // is a cache input only through the instructions that reference it (once
            // expanded).
            if let Instruction::Arg { name: arg, default } = raw {
                // DOCKER_STAGE_HASH is a reserved, auto-injected arg: its value is the
                // declaring ancestor's stage_key (see [`drive`]). It is forced empty while
                // keying (`dsh` = None) so a stage's identity never depends on the injected
                // hash — that would make a self-declaring stage's key depend on itself — and
                // set to the injected value in the exec pass (`dsh` = Some). A user-supplied
                // `--build-arg DOCKER_STAGE_HASH` is ignored (the value is synthesized).
                let value = if arg == DOCKER_STAGE_HASH {
                    dsh.unwrap_or_default().to_string()
                } else {
                    let default = default.as_deref().map(|d| interp::interpolate(d, &vars));
                    if default.is_some() {
                        build_args.get(arg).cloned().or(default).unwrap_or_default()
                    } else {
                        build_args
                            .get(arg)
                            .or(plan.global_args.get(arg))
                            .cloned()
                            .unwrap_or_default()
                    }
                };
                vars.insert(arg.clone(), value);
                continue;
            }
            // expand $VAR / ${VAR} against the current scope, then key the result —
            // except ENTRYPOINT/CMD, which Docker stores verbatim in the image
            // config: any $VAR in them belongs to the *runtime* shell (a service's
            // env overrides must reach it), not to the build scope. Expanding here
            // would bake build-time values into the exported runtime config.
            let instr = match raw {
                Instruction::Entrypoint(_) | Instruction::Cmd(_) => raw.clone(),
                _ => interp::expand_instruction(raw, &vars),
            };
            // Content the key must track beyond the instruction text (Docker semantics —
            // the cache follows the bytes an instruction reads, not just its spelling):
            //   - a context COPY keys on the sha256 of the files it references, so
            //     editing a copied source busts the cache;
            //   - a RUN --mount=type=bind from the context keys on the sha256 of the
            //     mounted files, so editing a bind-mounted script busts the cache;
            //   - a COPY --from=<x> / RUN --mount=from=<x> keys on the source's content
            //     identity — a stage's final key, or an image's manifest digest — so a
            //     change anywhere in the source chains into every consumer; without it, a
            //     consumer whose own instructions did not change would restore a snapshot
            //     holding the *old* source content.
            let content = match &instr {
                Instruction::Copy(c) => match &c.from {
                    None => Some(context_files_hash(&stage.context, &c.sources)),
                    Some(r) => source_content_key(plan, &out, r, &c.sources, ex),
                },
                Instruction::Run(r) => {
                    // A --mount=from=<x> keys on that source; a bind mount from the context
                    // keys on its files (source defaults to the whole context). Non-bind
                    // mounts contribute nothing.
                    let mut parts: Vec<String> = Vec::new();
                    for m in &r.mounts {
                        let part = match &m.from {
                            Some(f) => {
                                // The mounted subpath is what a named context keys on, exactly
                                // as a context bind below does.
                                let src = m.source.clone().unwrap_or_else(|| "/".into());
                                source_content_key(plan, &out, f, &[src], ex)
                            }
                            None if m.typ == "bind" => {
                                // Default source matches the executor's bind default (build/exec.rs);
                                // copy_src_files resolves both "/" and "." to the context root.
                                let src = m.source.clone().unwrap_or_else(|| "/".into());
                                Some(context_files_hash(&stage.context, &[src]))
                            }
                            None => None,
                        };
                        parts.extend(part);
                    }
                    // The command is keyed raw via `canonical` (it executes verbatim). Fold
                    // in its interpolated form only when the in-scope vars actually change it
                    // — i.e. it references an ARG/ENV — so a change to a referenced value
                    // busts the cache, while a RUN using only shell-local variables keeps the
                    // key it would have with no scope at all.
                    let scoped = interp::interpolate_cmdline(&r.cmd, &vars);
                    let unscoped = interp::interpolate_cmdline(&r.cmd, &interp::Vars::new());
                    if scoped != unscoped {
                        parts.push(format!("cmd={scoped}"));
                    }
                    (!parts.is_empty()).then(|| parts.join("\n"))
                }
                _ => None,
            };
            key = chain_key(&key, &instr, content.as_deref());
            if matches!(instr, Instruction::Run(_) | Instruction::Copy(_)) {
                // a step runs under the state accumulated by the prior ENV/WORKDIR/USER.
                let mut st = state.clone();
                if matches!(instr, Instruction::Run(_)) {
                    // Export the in-scope ARG values into the RUN's shell so its raw `$VAR`
                    // references resolve there (ENV is already in `st.env`; drop names it
                    // shadows). Kept out of the running `state` so it never leaks into a
                    // child stage or the exported runtime config.
                    let env_keys: std::collections::BTreeSet<&str> =
                        st.env.iter().map(|(k, _)| k.as_str()).collect();
                    st.build_args = vars
                        .iter()
                        .filter(|(k, _)| !env_keys.contains(k.as_str()))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                }
                steps.push(Step {
                    instr,
                    key: key.clone(),
                    state: st,
                });
            } else {
                // ENV/WORKDIR/USER: fold into the running state (+ scope) for later steps.
                apply_meta(&mut state, &instr);
                if let Instruction::Env(kvs) = &instr {
                    for (k, v) in kvs {
                        vars.insert(k.clone(), v.clone()); // ENV joins the scope (overrides ARG)
                    }
                }
            }
        }
        out.insert(
            idx,
            Resolved {
                steps,
                final_key: key,
                final_state: state,
            },
        );
    }
    Ok(out)
}

/// Resolve every stage's cache key (name or index → `stage_key`: the chain key after the
/// stage's last instruction) without building — the exact identity virtkit's instruction
/// cache stores a stage's snapshot under. Resolves base digests + base image config over
/// the network (like a real build) so the keys match what a build would store. Backs the
/// `docker-hash` subcommand.
pub fn stage_keys(
    dockerfiles: &[PathBuf],
    contexts: &[PathBuf],
    build_contexts: &[(String, PathBuf)],
    build_args: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let inputs = load_inputs(dockerfiles, contexts)?;
    let ba: Vars = build_args.iter().cloned().collect();
    let mut plan = Plan::from_dockerfiles(&inputs, &ba)?;
    plan.named_contexts = named_context_map(build_contexts)?;
    let order = plan.all_order()?;
    let mut ex = exec::Planner::new();
    // canonical keys: DOCKER_STAGE_HASH is excluded (its injected value never affects a
    // stage's identity), so `docker-hash` prints exactly the key a build would store.
    let resolved = resolve_stages(&plan, &order, &ba, &mut ex, None)?;
    let mut out = Vec::new();
    for &idx in &order {
        let name = plan.stages[idx]
            .name
            .clone()
            .unwrap_or_else(|| idx.to_string());
        out.push((name, resolved[&idx].final_key.clone()));
    }
    Ok(out)
}

/// The final key of the stage a `--from=<x>` names — its content identity, folded into
/// the consuming instruction's key. `None` when `x` is not a stage of this plan (an external
/// image — see [`source_content_key`]) or an unresolvable `$VAR` ref (the same known limitation
/// as [`stage_source_refs`]). The source is always resolved first: it is a dependency, so
/// the topological order places it earlier.
fn source_stage_key(
    plan: &Plan,
    resolved: &HashMap<usize, Resolved>,
    reference: &str,
) -> Option<String> {
    let s = plan.stage_ref(reference)?;
    resolved.get(&s).map(|r| r.final_key.clone())
}

/// The content identity of whatever a `--from=<x>` names, folded into the consuming
/// instruction's key: a stage's final key, the sha256 of the `sources` a named build context
/// holds, or an external image's resolved manifest digest — so editing those files, or moving
/// that tag, busts every consumer's key exactly as a change in a source stage does. Resolved in
/// that order, matching how the source itself is resolved, so what a reference means never
/// depends on which of the three answered.
///
/// `None` when nothing resolves (no registry reachable, or an unresolvable `$VAR` ref); the
/// reference text alone then keys the instruction, which is all there is to go on.
fn source_content_key(
    plan: &Plan,
    resolved: &HashMap<usize, Resolved>,
    reference: &str,
    sources: &[String],
    ex: &mut dyn Executor,
) -> Option<String> {
    // `scratch` is the reserved empty base a `RUN --mount` gets as writable scratch, not a
    // source: it has no content to key on, and asking a registry to resolve it would cost a
    // round trip and a warning for an image that does not exist.
    if reference == "scratch" {
        return None;
    }
    // A reference that names a stage *is* that stage, whether or not this build resolved it (a
    // `--from=$ARG` outside the pruned order is not), so a named context can never answer for
    // it — exactly as `non_stage_source` resolves the source itself.
    if plan.stage_ref(reference).is_some() {
        return source_stage_key(plan, resolved, reference);
    }
    // A named build context is host files like the stage's own context, so it keys on their
    // content rather than on a snapshot key.
    if let Some(dir) = plan.named_context(reference) {
        return Some(context_files_hash(dir, sources));
    }
    ex.resolve_base_digest(reference)
        .map(|d| format!("{reference}@{d}"))
}

/// The cache key (`stage_key`) of one target stage in the merged Dockerfiles — the
/// content identity a unit image is fingerprinted with. `None` targets the last
/// stage, like a build. Resolves base digests/config over the network like a real
/// build, pruned to the target's dependency subgraph.
pub fn target_stage_key(
    dockerfiles: &[PathBuf],
    contexts: &[PathBuf],
    build_contexts: &[(String, PathBuf)],
    build_args: &[(String, String)],
    target: Option<&str>,
) -> Result<String> {
    let inputs = load_inputs(dockerfiles, contexts)?;
    let ba: Vars = build_args.iter().cloned().collect();
    let mut plan = Plan::from_dockerfiles(&inputs, &ba)?;
    plan.named_contexts = named_context_map(build_contexts)?;
    let t = plan.resolve_target(target)?;
    let order = plan.build_order(t)?;
    let mut ex = exec::Planner::new();
    let resolved = resolve_stages(&plan, &order, &ba, &mut ex, None)?;
    Ok(resolved[&t].final_key.clone())
}

/// The reserved build arg whose value virtkit synthesizes (the declaring stage's
/// `stage_key`) instead of taking from the user — see [`drive`]/[`resolve_stages`].
const DOCKER_STAGE_HASH: &str = "DOCKER_STAGE_HASH";

/// The stage nearest the `targets` (multi-source BFS over the dependency DAG, the targets
/// first) that declares `ARG DOCKER_STAGE_HASH`, or `None` if no stage in their combined
/// closure does. Mirrors wabbuilder docker-tool.sh `_closure_args`: the closest declarer
/// wins (a target itself included), and its `stage_key` is the value injected for the whole
/// build. A unified multi-target build passes all its targets: since a plan declares the arg
/// in one place (and the cache key is DSH-independent by construction), the nearest declarer
/// to any target is the single value to inject.
fn nearest_dsh_declarer(plan: &Plan, targets: &[usize]) -> Option<usize> {
    use std::collections::VecDeque;
    let declares = |i: usize| {
        plan.stages[i]
            .instructions
            .iter()
            .any(|ins| matches!(ins, Instruction::Arg { name, .. } if name == DOCKER_STAGE_HASH))
    };
    let mut seen = vec![false; plan.stages.len()];
    let mut queue = VecDeque::new();
    for &t in targets {
        if !seen[t] {
            seen[t] = true;
            queue.push_back(t);
        }
    }
    while let Some(cur) = queue.pop_front() {
        if declares(cur) {
            return Some(cur);
        }
        for d in plan.deps(cur) {
            if !seen[d] {
                seen[d] = true;
                queue.push_back(d);
            }
        }
    }
    None
}

/// Combine the canonical key pass (value-independent keys) with the exec pass (the
/// instructions + shell state interpolated with the injected DOCKER_STAGE_HASH): keep
/// each step's cache key from the key pass, take its executed instruction + state from
/// the exec pass. Both passes see the same instruction kinds/order, so the steps zip 1:1.
fn merge_exec(
    keyed: &HashMap<usize, Resolved>,
    exec: HashMap<usize, Resolved>,
) -> HashMap<usize, Resolved> {
    let mut out = HashMap::new();
    for (idx, xr) in exec {
        let kr = &keyed[&idx];
        let steps = kr
            .steps
            .iter()
            .zip(xr.steps)
            .map(|(k, x)| Step {
                instr: x.instr,
                key: k.key.clone(),
                state: x.state,
            })
            .collect();
        out.insert(
            idx,
            Resolved {
                steps,
                final_key: kr.final_key.clone(),
                final_state: xr.final_state,
            },
        );
    }
    out
}

/// Walk the stages in topological order, applying each stage's instructions through
/// the executor, and return each stage's committed rootfs (so later stages can fork
/// it / COPY --from it). Backend-agnostic. Keys + interpolation come from
/// [`resolve_stages`] (the shared identity computation), so the build and `docker-hash`
/// agree on every stage's cache key.
/// Resolve every stage to its keyed instruction stream, with `DOCKER_STAGE_HASH`
/// auto-injected for execution (its value is the stage_key of the declaring stage
/// nearest the target). The canonical cache keys stay value-independent, so the
/// injected hash never alters what is cached and `docker-hash` agrees with the build.
fn resolve_all(
    plan: &Plan,
    order: &[usize],
    build_args: &Vars,
    ex: &mut dyn Executor,
    targets: &[usize],
) -> Result<HashMap<usize, Resolved>> {
    // Canonical, value-independent keys (DOCKER_STAGE_HASH forced empty while keying).
    let keyed = resolve_stages(plan, order, build_args, ex, None)?;
    Ok(match nearest_dsh_declarer(plan, targets) {
        Some(d) => {
            let value = keyed
                .get(&d)
                .context("internal: DOCKER_STAGE_HASH declarer not resolved")?
                .final_key
                .clone();
            let exec = resolve_stages(plan, order, build_args, ex, Some(&value))?;
            merge_exec(&keyed, exec)
        }
        None => keyed,
    })
}

/// The set of stages the build must touch, and which of them are fully cached.
///
/// Back-to-front: a stage whose last snapshot is cached is "fully cached" (keys chain,
/// so that one key covers its whole history including its base and `COPY --from`
/// sources) — it restores that snapshot alone, with no per-instruction probes, and does
/// NOT pull its dependencies into `needed`. A stage only ever read by fully-cached
/// consumers is skipped outright. `needed` propagates from the target; a stage that
/// will run pulls in its parent stage and `--from` sources.
fn compute_needed(
    plan: &Plan,
    order: &[usize],
    resolved: &HashMap<usize, Resolved>,
    ex: &mut dyn Executor,
    require_cached: bool,
    targets: &[usize],
) -> Result<(HashSet<usize>, HashMap<usize, String>)> {
    let mut needed: HashSet<usize> = targets.iter().copied().collect();
    let mut cached_final: HashMap<usize, String> = HashMap::new();
    for &idx in order.iter().rev() {
        if !needed.contains(&idx) {
            continue;
        }
        let steps = &resolved
            .get(&idx)
            .context("internal: stage not resolved")?
            .steps;
        if let Some(last) = steps.last()
            && ex.cache_has(&last.key)
        {
            cached_final.insert(idx, last.key.clone());
            continue;
        }
        let stage = &plan.stages[idx];
        if let Base::Stage(parent) = &stage.base {
            needed.insert(*parent);
        }
        needed.extend(stage_source_refs(plan, &stage.instructions));
    }
    // --require-cached: `needed \ cached_final` is exactly the set of stages the driver
    // would build (materialize a base, run instructions) rather than restore. Refuse
    // with the typed error before any work starts.
    if require_cached {
        let missing: Vec<String> = order
            .iter()
            .filter(|i| needed.contains(i) && !cached_final.contains_key(i))
            .map(|&i| {
                plan.stages[i]
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("stage{i}"))
            })
            .collect();
        if !missing.is_empty() {
            return Err(NotCached { stages: missing }.into());
        }
    }
    Ok((needed, cached_final))
}

/// The needed stages (in build order) as the progress reporter's display list: a `FROM`
/// line plus one line per `RUN`/`COPY` per stage.
fn stage_inits(
    plan: &Plan,
    order: &[usize],
    resolved: &HashMap<usize, Resolved>,
    needed: &HashSet<usize>,
    id_offset: progress::StageId,
    name_prefix: &str,
) -> Vec<StageInit> {
    order
        .iter()
        .filter(|i| needed.contains(i))
        .map(|&idx| {
            let stage = &plan.stages[idx];
            let base_name = stage.name.clone().unwrap_or_else(|| format!("stage{idx}"));
            StageInit {
                // `id_offset`/`name_prefix` namespace a unified multi-service build so its
                // stages get globally-unique progress ids and per-service row labels; a
                // single build passes `0`/`""`, leaving ids = plan indices, names unchanged.
                id: id_offset + idx,
                name: format!("{name_prefix}{base_name}"),
                base_label: base_label(plan, &stage.base),
                steps: resolved[&idx]
                    .steps
                    .iter()
                    .map(|s| instr_label(&s.instr))
                    .collect(),
            }
        })
        .collect()
}

/// The `FROM …` line label for a stage's base.
fn base_label(plan: &Plan, base: &Base) -> String {
    match base {
        Base::Image(image) => format!("FROM {image}"),
        Base::Scratch => "FROM scratch".into(),
        Base::Stage(parent) => {
            let name = plan.stages[*parent]
                .name
                .clone()
                .unwrap_or_else(|| format!("stage{parent}"));
            format!("FROM {name}")
        }
    }
}

/// Build one stage to its committed rootfs. `committed` must already hold every stage
/// this one depends on (its base `FROM` and `COPY --from` / `RUN --mount=from` sources);
/// the driver guarantees that by ordering. A fully-cached stage restores its snapshot
/// directly and reads nothing from `committed`. Reused by both the sequential [`drive`]
/// and the parallel [`drive_microvm`], so the two cannot diverge.
#[allow(clippy::too_many_arguments)]
fn build_stage(
    plan: &Plan,
    resolved: &HashMap<usize, Resolved>,
    cached_final: &HashMap<usize, String>,
    committed: &HashMap<usize, Rootfs>,
    ex: &mut dyn Executor,
    idx: usize,
    cache: BuildCache,
    progress: &Arc<Progress>,
    timings: &Arc<Timings>,
    cancel: Option<&CancellationToken>,
    name_prefix: &str,
    display: progress::StageId,
    budget: &BuildBudget,
) -> Result<Rootfs> {
    // Abort before doing any work if an earlier stage already failed, and hand the token
    // to the backend so a RUN launched below is interrupted the moment a sibling fails.
    if let Some(c) = cancel {
        if c.is_cancelled() {
            bail!("build stopped after an earlier stage failed");
        }
        ex.set_cancel(c.clone());
    }
    let stage = &plan.stages[idx];
    // The executor identity (its `images` map key + scratch file names) and every label
    // is this `name`. A unified multi-service build prefixes it per service so same-named
    // stages across services (two `AS build`s, or two unnamed `stage0`s) stay distinct;
    // `display` is likewise a globally-unique progress id (a single build passes "" + idx).
    let base_name = stage.name.clone().unwrap_or_else(|| format!("stage{idx}"));
    let name = format!("{name_prefix}{base_name}");
    let steps = &resolved
        .get(&idx)
        .context("internal: stage not resolved")?
        .steps;
    // The stage's final content key: used below both for the build-once lock and to check
    // a remote vk-registry's build-failure memo (a no-op locally or outside CI) — if this
    // exact key already failed to build earlier in this pipeline, fail fast instead of
    // repeating a possibly expensive, doomed build (a runner-level retry of this job, or
    // any other job/stage in the pipeline needing the same stage).
    let final_key = steps.last().map(|s| s.key.clone());
    // Route this stage's guest output through the progress reporter (line-buffered +
    // stage-prefixed) so concurrent stages stay legible.
    ex.set_output_sink(progress.stage_sink(display));
    // The actual build attempt, isolated in a closure so any error from here on is a
    // candidate to memoize against `final_key` (just below) before it propagates — the
    // memoization guard there filters out a cascaded cancellation or an environmental
    // cause, so only this stage's own content failure actually poisons the key.
    let result: Result<Rootfs> = (|| {
        // Fully cached: restore the final snapshot directly, nothing to probe or run.
        if let Some(key) = cached_final.get(&idx) {
            progress.stage_fully_cached(display);
            progress.restore_start(display, &name);
            let t_restore = Instant::now();
            let fs = restore_into(ex, &name, key)?;
            timings.record(Phase::CachePull, &name, t_restore.elapsed());
            progress.restore_done(display);
            ex.stage_end(&fs, Some(key))?;
            return Ok(fs);
        }
        // Build-once across runners: take the lock on this stage's final content key (a no-op
        // unless the cache is a remote vk-registry) so peers building the same stage don't
        // duplicate it. After acquiring, re-check the cache — a peer may have finished while we
        // waited — and restore instead of building. The guard is held for the whole stage
        // (through the final `cache_save`) and releases on return.
        let _build_lock = match &final_key {
            Some(final_key) => {
                // On contention the lock names its holder; show it under this stage until acquired.
                let mut on_wait = |holder: &str| progress.wait_lock_start(display, &name, holder);
                let guard = ex.build_lock(final_key, &mut on_wait);
                progress.wait_lock_done(display);
                if guard.is_some() && ex.cache_has(final_key) {
                    progress.stage_fully_cached(display);
                    progress.restore_start(display, &name);
                    let t_restore = Instant::now();
                    let fs = restore_into(ex, &name, final_key)?;
                    timings.record(Phase::CachePull, &name, t_restore.elapsed());
                    progress.restore_done(display);
                    ex.stage_end(&fs, Some(final_key))?;
                    return Ok(fs);
                }
                guard
            }
            None => None,
        };
        // Checked only now — after both cache short-circuits above — so a peer that
        // finished (or a cache hit found only once we held the lock) always wins over a
        // stale failure memo; consulting the memo any earlier could fail this build even
        // though the content is now actually available.
        if let Some(key) = &final_key
            && let Some(fail) = ex.check_build_failure(key)
        {
            bail!(
                "stage {name} recently failed to build in this pipeline ({}s ago: {}) — not \
                 retrying automatically; restart the pipeline to retry",
                fail.age.as_secs(),
                fail.reason
            );
        }
        // Past this point the stage needs a live guest (at minimum to probe/build its
        // remaining steps), so it competes for the build budget: one of the `jobs` slots,
        // and its guest's RAM against what the host has left. Cache restores above never
        // reach here, so they run at full DAG-dispatch concurrency instead of queuing behind
        // real builds for one of these scarce permits.
        // Apply the stage hint before reserving memory. Clamp oversized requests and report
        // the effective value rather than failing the guest later during boot.
        // Read the default before applying the hint. Guest-backed stages use fresh workers;
        // only guest-less sequential builds reuse an executor.
        let default_mib = ex.stage_mem_mib().unwrap_or(0);
        let mut hint = stage.guest.clone();
        if let Some(mem) = &hint.mem
            && let Some(held_to) = clamp_stage_mem(mem, budget.mem.stage_cap_mib(), default_mib)
        {
            progress.warn(&format!(
                "virtkit: warning: build: [{name}] mem={mem} is more than this host can give \
                 one stage; using {held_to} instead. The stage runs with less RAM than it \
                 asked for, so a step sized for {mem} may be killed out of memory inside the \
                 guest."
            ));
            hint.mem = Some(held_to);
        }
        ex.set_stage_guest(&hint);
        let _admission = budget.admit(
            ex.stage_mem_mib().unwrap_or(0),
            cancel,
            progress,
            display,
            &name,
        );
        // Declare the stage's inputs — the source stages it copies/mounts from, and its
        // build context — so the backend can attach them before the guest boots. Read off the
        // resolved steps, not the raw plan: a `--from=$VAR` reaches the backend interpolated, so
        // declaring the raw text would materialize the wrong ref under a label no step asks for.
        let step_instrs: Vec<Instruction> = steps.iter().map(|s| s.instr.clone()).collect();
        let inputs = stage_input_rootfs(plan, &step_instrs, committed, ex)?;
        ex.stage_sources(&inputs, &stage.context)?;
        // `FROM --kernel=image`: this stage's RUNs boot on the base image's own kernel.
        ex.stage_kernel(stage.image_kernel);
        // Instruction-level cache + lazy base: every step carries the chained key; the base
        // rootfs is materialized only when something must actually run (the first cache
        // miss). A fully-cached prefix never pulls/flattens the base. `fs` is None until
        // materialized.
        let mut fs: Option<Rootfs> = None;
        let mut building = false;
        // Whether the FROM (cell 1) line has been emitted. It is shown in order — before the
        // step lines — so a cached prefix does not leave the FROM line trailing at the first
        // miss; materialization of the base itself stays lazy (deferred to that first miss).
        let mut base_shown = false;
        let mut last_hit: Option<String> = None;
        // `layers` never writes intermediate snapshots, so their keys can't hit — skip the
        // per-step probe (a registry round-trip each) and build the whole stage from base.
        // The fully-cached stage was already short-circuited above via `cached_final`.
        let probe = !matches!(cache, BuildCache::Layers);
        // `auto`: uncommitted run time accrued since the last checkpoint, and the threshold
        // it must cross to force one. Reset on every commit.
        let checkpoint = Duration::from_secs(checkpoint_secs());
        let mut uncommitted = Duration::ZERO;
        for (i, step) in steps.iter().enumerate() {
            // Stop between steps if another stage has failed (covers the gap between a fast
            // step finishing and the next boot; a long in-flight RUN is cut short in-guest).
            if let Some(c) = cancel
                && c.is_cancelled()
            {
                bail!("build stopped after an earlier stage failed");
            }
            if probe && !building && ex.cache_has(&step.key) {
                // A cached prefix restores the base as part of it, so the FROM line is CACHED;
                // emit it before this step's line so it prints in order.
                if !base_shown {
                    progress.base_done(display, Outcome::Cached);
                    base_shown = true;
                }
                progress.step_done(display, i, Outcome::Cached);
                last_hit = Some(step.key.clone());
                continue;
            }
            // first miss: materialize the rootfs — restore the last cached snapshot if there
            // was a cached prefix (the base folds into that restore, already shown above), else
            // build the base from scratch/image/stage (shown here, in order, before this step).
            if !building {
                fs = Some(match &last_hit {
                    Some(k) => {
                        progress.restore_start(display, &name);
                        let t_restore = Instant::now();
                        let f = restore_into(ex, &name, k)?;
                        timings.record(Phase::CachePull, &name, t_restore.elapsed());
                        progress.restore_done(display);
                        f
                    }
                    None => {
                        progress.base_start(display);
                        let t_base = Instant::now();
                        let f = materialize_base(ex, &stage.base, &name, committed)?;
                        timings.record(Phase::BasePull, &name, t_base.elapsed());
                        progress.base_done(display, Outcome::Ran);
                        base_shown = true;
                        f
                    }
                });
                building = true;
            }
            let f = fs.as_mut().expect("materialized on first miss");
            progress.step_start(display, i);
            let t0 = Instant::now();
            apply_fs(plan, committed, ex, f, &step.state, &step.instr)
                .inspect_err(|_| progress.step_failed(display, i))?;
            let ran = t0.elapsed();
            uncommitted += ran;
            timings.record(Phase::Instructions, &name, ran);
            // The stage's final step is always committed (so stage-level reuse and
            // `COPY --from` hit); which intermediate steps are, depends on the mode:
            // `instructions` commits every step, `layers` none, `auto` one once enough
            // uncommitted run time has accrued (deferring is safe — the overlay is
            // cumulative, so a later capture recovers the merged multi-step delta).
            let last = i + 1 == steps.len();
            let commit = match cache {
                BuildCache::Instructions => true,
                BuildCache::Layers => last,
                BuildCache::Auto => last || uncommitted >= checkpoint,
            };
            if commit {
                // The command is done; the snapshot + cache push that follow are commit
                // overhead, not the step's runtime — freeze the reported time here so a
                // trivial step isn't charged for the previous push's upload `cache_save` joins.
                progress.step_committing(display, i);
                let t_push = Instant::now();
                ex.cache_save(f, &step.key)
                    .inspect_err(|_| progress.step_failed(display, i))?;
                timings.record(Phase::CachePush, &name, t_push.elapsed());
                uncommitted = Duration::ZERO;
            }
            progress.step_done(display, i, Outcome::Ran);
        }
        // Nothing ran: the whole instruction run was cached → restore the final snapshot; or
        // there were no fs-changing instructions → the stage is the base.
        let final_fs = match fs {
            Some(f) => f,
            None => match &last_hit {
                // Every step was a cache hit: the FROM line was already shown (CACHED) at the
                // first hit in the loop, so just restore the final snapshot.
                Some(k) => {
                    progress.restore_start(display, &name);
                    let t_restore = Instant::now();
                    let f = restore_into(ex, &name, k)?;
                    timings.record(Phase::CachePull, &name, t_restore.elapsed());
                    progress.restore_done(display);
                    f
                }
                None => {
                    progress.base_start(display);
                    let t_base = Instant::now();
                    let f = materialize_base(ex, &stage.base, &name, committed)?;
                    timings.record(Phase::BasePull, &name, t_base.elapsed());
                    progress.base_done(display, Outcome::Ran);
                    f
                }
            },
        };
        // Finalize the stage: tear down its long-lived guest (if any) and commit its overlay
        // back into the stage ext4 so forks / COPY --from / export see the writes. This joins the
        // last step's still-uploading cache push (no next RUN overlapped it), so show a spinner —
        // otherwise the dashboard sits frozen on the header through that upload.
        progress.stage_finishing_start(display, &name);
        let r = ex.stage_end(&final_fs, steps.last().map(|s| s.key.as_str()));
        progress.stage_finishing_done(display);
        r?;
        // Report measured guest demand while the completed stage remains visible; unmeasured
        // stages have no line. "Guest" distinguishes this from the run's host-RSS peak.
        if let Some((peak, declared)) = timings.stage_mem(&name) {
            progress.note(&format!(
                "virtkit: build: [{name}] peak guest memory {} of {}",
                crate::usage::fmt_bytes(peak),
                crate::usage::fmt_bytes(declared)
            ));
        }
        Ok(final_fs)
    })();
    // Memoize a genuine failure against `final_key` so a peer in this pipeline fails fast
    // instead of repeating it — but only a genuine one:
    //  - a cascaded cancellation (a sibling stage failed; this one aborted mid-flight,
    //    inside the closure's own step loop or via the backend cutting an in-flight RUN
    //    short once `set_cancel` sees it) is not this key's fault, so re-check the token
    //    here rather than trust the error text of whatever `bail!`/interruption surfaced;
    //  - a failure whose root cause is environmental rather than content-related (out of
    //    disk, a transient network hiccup pulling the base image) would otherwise poison
    //    this key until the whole pipeline restarts, even though fixing the environment
    //    (e.g. freeing disk) makes the very next retry succeed.
    let cascaded = cancel.is_some_and(|c| c.is_cancelled());
    if let (Err(e), Some(key)) = (&result, &final_key)
        && !cascaded
        && !is_environmental_failure(e)
    {
        ex.report_build_failure(key, &e.to_string());
    }
    result
}

/// Best-effort classification of an error chain as environmental (transient infrastructure
/// trouble) rather than a genuine content/build failure — see `build_stage`'s memoization
/// guard. Deliberately conservative: only a narrow, well-understood set of I/O error kinds
/// qualifies; anything else (a failing RUN, a bad Dockerfile instruction, an unresolvable
/// COPY source) is still memoized as this key's own fault.
fn is_environmental_failure(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::StorageFull
                    | std::io::ErrorKind::OutOfMemory
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            )
        })
    })
}

/// Each stage's final ENV/USER/WORKDIR, so a caller booting the exported image can run a
/// command with the image's environment (e.g. `run -f` applying PATH).
fn final_states(resolved: &HashMap<usize, Resolved>) -> HashMap<usize, ShellState> {
    resolved
        .iter()
        .map(|(idx, r)| (*idx, r.final_state.clone()))
        .collect()
}

/// Sequential driver: walk the stages in topological order, building each through the
/// executor. Backend-agnostic — used by the host/dry-run backends (and as the reference
/// the parallel microVM driver must match).
#[allow(clippy::too_many_arguments)]
fn drive(
    plan: &Plan,
    order: &[usize],
    build_args: &Vars,
    ex: &mut dyn Executor,
    require_cached: bool,
    cache: BuildCache,
    progress: &Arc<Progress>,
    timings: &Arc<Timings>,
) -> Result<(HashMap<usize, Rootfs>, HashMap<usize, ShellState>)> {
    // Single-target driver: the target is the order's last stage.
    let targets = [*order.last().context("internal: empty build order")?];
    let resolved = resolve_all(plan, order, build_args, ex, &targets)?;
    let (needed, cached_final) =
        compute_needed(plan, order, &resolved, ex, require_cached, &targets)?;
    progress.init(stage_inits(plan, order, &resolved, &needed, 0, ""), 1);
    // Sequential driver: one stage at a time on the single `ex`, so neither the permit count
    // nor the memory gate has anything to hold back — they exist only to satisfy
    // `build_stage`'s signature.
    let budget = BuildBudget::new(1, None);
    let mut committed: HashMap<usize, Rootfs> = HashMap::new();
    for &idx in order {
        if !needed.contains(&idx) {
            continue;
        }
        let fs = build_stage(
            plan,
            &resolved,
            &cached_final,
            &committed,
            ex,
            idx,
            cache,
            progress,
            timings,
            None,
            "",
            idx,
            &budget,
        )?;
        committed.insert(idx, fs);
    }
    Ok((committed, final_states(&resolved)))
}

/// Mutable state shared by [`run_dag`]'s workers, behind one mutex.
struct Dag<R> {
    /// nodes whose deps are all done and that no worker has claimed yet.
    ready: Vec<usize>,
    /// node → number of its deps not yet done. Reaches 0 → the node becomes ready.
    indeg: HashMap<usize, usize>,
    /// finished node results so far (a worker snapshots this before building a node).
    done: HashMap<usize, R>,
    /// nodes not yet finished; the run is complete when this hits 0.
    remaining: usize,
    /// first worker error; set once, then every worker drains and returns.
    error: Option<anyhow::Error>,
}

/// A counting semaphore: bounds how many callers hold a permit at once. Used to cap
/// concurrent guest builds by host memory without also throttling the (cheap, I/O-bound)
/// cache restores that share the same DAG worker pool — see `run_dag`.
struct Semaphore {
    permits: Mutex<usize>,
    cv: Condvar,
}

impl Semaphore {
    fn new(permits: usize) -> Self {
        Self {
            permits: Mutex::new(permits),
            cv: Condvar::new(),
        }
    }

    fn acquire(&self) -> SemaphorePermit<'_> {
        let mut n = self.permits.lock().unwrap();
        while *n == 0 {
            n = self.cv.wait(n).unwrap();
        }
        *n -= 1;
        SemaphorePermit(self)
    }
}

struct SemaphorePermit<'a>(&'a Semaphore);

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        *self.0.permits.lock().unwrap() += 1;
        self.0.cv.notify_one();
    }
}

/// How often the stage at the head of the memory queue re-measures the host. What it is
/// waiting for is usually freed by something outside this build, which never touches the
/// condvar, so a wait that is not polled is a wait that does not end.
///
/// A measurement reads `/proc/meminfo` and then one `status` per process on the host
/// ([`build_rss_mib`]), which is what keeps this interval as long as it is. Only the head of
/// the queue polls — the rest sleep until their turn — so the cost is one walk every two
/// seconds however wide the build is, not one per waiting stage.
const MEM_POLL: Duration = Duration::from_secs(2);

/// The share of `MemTotal` a build keeps outside its own stage guests: the driver's own
/// footprint and the VMMs', the ext4 snapshots it writes, and enough slack that the host
/// stays usable. Lower than the runner's `schedule::RESERVE_PCT`, which also stands in for
/// job VMs it never measures — here every live guest is charged explicitly.
///
/// It is deliberately not the same 20% the auto `jobs` ceiling leaves ([`resolve_build_jobs`]):
/// the ceiling is a fixed share of the whole machine, this is measured against what is left
/// of it, so on a host with a real baseline the gate is the tighter of the two.
const BUILD_RESERVE_PCT: u64 = 10;

/// Floor under [`BUILD_RESERVE_PCT`], so a small host still keeps a GiB for itself.
const BUILD_RESERVE_MIN_MIB: u64 = 1024;

/// What a host of `total_mib` holds back from its build stages — [`BUILD_RESERVE_PCT`] of
/// it, never less than [`BUILD_RESERVE_MIN_MIB`].
fn build_reserve_mib(total_mib: u64) -> u64 {
    (total_mib.saturating_mul(BUILD_RESERVE_PCT) / 100).max(BUILD_RESERVE_MIN_MIB)
}

/// Host-memory admission for the stages of one build, on top of the `jobs` count ceiling.
struct MemLedger {
    /// `MemTotal`. `None` disables the gate entirely — no queue, no measuring
    /// ([`MemLedger::reserve`]): `/proc/meminfo` unreadable, `[build] no_mem_gate`, and the
    /// sequential backends, which run one stage at a time and have nothing to hold back.
    ///
    /// The ledger tests do give a total, and so do measure the machine they run on. They
    /// pass it a total of 1 MiB, which no stage can ever fit in, so what the host happens to
    /// report cannot change the answer.
    total_mib: Option<u64>,
    /// Held back from `total_mib` — see [`BUILD_RESERVE_PCT`].
    reserve_mib: u64,
    state: Mutex<LedgerState>,
    cv: Condvar,
}

/// [`MemLedger`]'s mutable half. Kept behind one lock so a queue position and the figure it
/// is judged against can never be read from two different moments.
#[derive(Default)]
struct LedgerState {
    /// Declared guest RAM of the stages holding a reservation right now.
    held_mib: u64,
    /// Next queue ticket to hand out; tickets only ever increase.
    next_ticket: u64,
    /// Tickets still waiting. The lowest is the one that may be admitted — held as a set
    /// rather than a counter so a stage that gives up (cancelled) drops out of the middle
    /// without stalling everyone queued behind it.
    waiting: BTreeSet<u64>,
}

impl MemLedger {
    fn new(total_mib: Option<u64>) -> Self {
        Self {
            total_mib,
            reserve_mib: total_mib.map(build_reserve_mib).unwrap_or(0),
            state: Mutex::new(LedgerState::default()),
            cv: Condvar::new(),
        }
    }

    /// What `want_mib` is short by right now: `0` when it fits (and always when the gate is
    /// off). Pure over its inputs, so the rule itself is testable without a host.
    fn short_by(&self, want_mib: u64, held_mib: u64, foreign_mib: u64) -> u64 {
        let Some(total) = self.total_mib else {
            return 0;
        };
        let room = total
            .saturating_sub(self.reserve_mib)
            .saturating_sub(foreign_mib)
            .saturating_sub(held_mib);
        want_mib.saturating_sub(room)
    }

    /// Reserve `want_mib` until the returned guard drops, waiting for the host to have room.
    /// Returns whether it parked and how that ended, so the caller can pair a spinner without
    /// tracking the same state twice; `on_wait` is called once, with the shortfall, when it parks.
    fn reserve(
        &self,
        want_mib: u64,
        cancel: Option<&CancellationToken>,
        mut on_wait: impl FnMut(u64),
    ) -> (MemReservation<'_>, MemWait) {
        // Nothing to account for, so nothing to queue behind either: the gate turned off (`[build]
        // no_mem_gate`, or a host whose memory cannot be read) and the guest-less backends
        // (`DryRun`, `Planner`, `Host`) both go straight through, without taking a ticket and
        // without walking `/proc`. `held_mib` is read by nothing else, so leaving it at zero costs
        // nothing.
        if want_mib == 0 || self.total_mib.is_none() {
            return (
                MemReservation {
                    ledger: self,
                    mib: 0,
                },
                MemWait::No,
            );
        }
        // Declared before the guard below so it is dropped *after* it: a queue place that
        // outlived its stage would be a head no one is behind, and every later waiter would
        // sleep out the build behind it.
        let queued = QueuedTicket::take(self);
        let ticket = queued.ticket;
        let mut st = self.lock();
        let mut wait = MemWait::No;
        let admitted = loop {
            if cancel.is_some_and(|c| c.is_cancelled()) {
                break false;
            }
            // Only the oldest waiter is measured against the host; the rest sleep until it
            // is their turn, so a late small stage cannot take the room an early large one
            // is waiting for.
            if st.waiting.first() == Some(&ticket) {
                if st.held_mib == 0 {
                    break true;
                }
                // Measured with the lock released: this walks `/proc`, and a stage releasing
                // its own reservation must never queue behind that.
                drop(st);
                let foreign = measure_foreign_mib().unwrap_or(0);
                st = self.lock();
                // Judged against what is held *now*, not against a snapshot from before the
                // walk: a reservation released in that window would otherwise go unseen
                // until the next poll, and a waiter that gave up mid-walk raises `held_mib`
                // from behind us. Only `foreign` is allowed to be a moment stale.
                let short = self.short_by(want_mib, st.held_mib, foreign);
                if short == 0 {
                    break true;
                }
                if wait == MemWait::No {
                    wait = MemWait::Abandoned; // until this stage is actually let in
                    drop(st);
                    on_wait(short);
                    st = self.lock();
                    continue; // the host may have moved on while that was reported
                }
            }
            // Timed, not a plain wait: the memory being waited for is usually freed by a
            // process outside this build, which will never notify us.
            st = self
                .cv
                .wait_timeout(st, MEM_POLL)
                .unwrap_or_else(poisoned)
                .0;
        };
        if admitted && wait == MemWait::Abandoned {
            wait = MemWait::Admitted;
        }
        st.held_mib = st.held_mib.saturating_add(want_mib);
        drop(st);
        drop(queued); // hands the queue to the next stage, and wakes it
        (
            MemReservation {
                ledger: self,
                mib: want_mib,
            },
            wait,
        )
    }

    /// The largest guest a single stage may hold on this host: everything the gate is
    /// willing to promise, with no siblings live. `None` when the gate is off, and so is
    /// promising nothing. A stage asking for more is clamped to it — see
    /// [`clamp_stage_mem`].
    fn stage_cap_mib(&self) -> Option<u64> {
        Some(self.total_mib?.saturating_sub(self.reserve_mib))
    }

    /// The ledger's state. Poison-tolerant throughout: a stage that panicked mid-update is
    /// one failed stage, and taking the rest of the build down with it — or, from a `Drop`
    /// during an unwind, aborting the process — helps nobody. Every field is a plain
    /// counter, so the worst a poisoned lock leaves behind is a figure to re-derive.
    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Whether a stage waited on host memory, and how that wait ended. A stage let through by
/// cancellation has its spinner cleared like any other, but must not also be announced as
/// starting: it is about to fail its own cancellation check.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum MemWait {
    No,
    Admitted,
    Abandoned,
}

/// One stage's place in [`MemLedger`]'s queue, released on drop.
///
/// A guard rather than a matching pair of statements because the window between them runs
/// `on_wait` — which reaches `println!` on the plain backend, and so panics on `EPIPE` the
/// moment a build's output is piped into something that stops reading. A ticket stranded by
/// that unwind would be a head that never advances, and every stage behind it would wait out
/// the build on the 2-second poll rather than fail with it.
struct QueuedTicket<'a> {
    ledger: &'a MemLedger,
    ticket: u64,
}

impl<'a> QueuedTicket<'a> {
    fn take(ledger: &'a MemLedger) -> Self {
        let mut st = ledger.lock();
        let ticket = st.next_ticket;
        st.next_ticket = st.next_ticket.saturating_add(1);
        st.waiting.insert(ticket);
        Self { ledger, ticket }
    }
}

impl Drop for QueuedTicket<'_> {
    fn drop(&mut self) {
        let mut st = self.ledger.lock();
        st.waiting.remove(&self.ticket);
        let next_waiting = !st.waiting.is_empty();
        drop(st);
        // The stage behind this one is now the head, and only the head measures anything.
        // Without this it would sit out a full `MEM_POLL` before noticing its turn came —
        // on an idle host, once per admission, for every stage in the queue.
        if next_waiting {
            self.ledger.cv.notify_all();
        }
    }
}

/// Recover a poisoned ledger guard — see [`MemLedger::lock`].
fn poisoned<T>(e: std::sync::PoisonError<T>) -> T {
    e.into_inner()
}

/// One stage's live reservation against a [`MemLedger`]; releases on drop, so a stage that
/// fails or panics frees what it held.
struct MemReservation<'a> {
    ledger: &'a MemLedger,
    mib: u64,
}

impl Drop for MemReservation<'_> {
    fn drop(&mut self) {
        if self.mib == 0 {
            return; // never queued (see `MemLedger::reserve`), so nothing to wake
        }
        // Never a second panic: this runs during a failing stage's unwind, and a panic out
        // of a `Drop` that is already unwinding aborts the process. So no assertion here
        // either, however tempting — `saturating_sub` is the only safe way to be wrong.
        let mut st = self.ledger.lock();
        st.held_mib = st.held_mib.saturating_sub(self.mib);
        drop(st);
        // The oldest waiter may not be the one this fits, and only it is allowed to take
        // the room anyway — so wake everyone and let the queue decide whose turn it is.
        self.ledger.cv.notify_all();
    }
}

/// Host memory committed to anything other than this build's guests, in MiB.
fn foreign_used_mib(host: crate::schedule::HostMemory, ours_mib: u64) -> u64 {
    (host.total_mib.saturating_add(host.shmem_mib))
        .saturating_sub(host.available_mib)
        .saturating_sub(ours_mib)
}

/// [`foreign_used_mib`] measured against this host, or `None` when `/proc` cannot be read.
/// The caller then reads it as zero foreign use, so the gate still holds a stage against
/// what this build itself has promised, and only stops seeing the rest of the host.
///
/// Note what this cannot see: a CI job VM that `crate::admit` granted RAM to seconds ago
/// but which has not faulted it in yet reads as free space here, exactly as an unwarmed
/// stage guest would without the ledger. Folding that ledger in needs the runner's state
/// dir, which a build does not carry.
fn measure_foreign_mib() -> Option<u64> {
    Some(foreign_used_mib(
        crate::schedule::host_memory()?,
        build_rss_mib(Path::new("/proc"))?,
    ))
}

/// Resident size of this process and every descendant of it, in MiB — the build's own
/// footprint, guests included (see [`foreign_used_mib`]). `proc` is the mount to read, so
/// this is testable against a fixture rather than only against the machine running it.
///
/// A process that exits mid-scan simply drops out; the reading is a sample either way.
fn build_rss_mib(proc: &Path) -> Option<u64> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut rss_kib: HashMap<u32, u64> = HashMap::new();
    // An unreadable `/proc` is `None` (no reading at all), but a single entry that cannot be
    // listed is just a process that is no longer there — skipped, like one that exits below.
    for entry in std::fs::read_dir(proc).ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue; // exited between the readdir and the open
        };
        let Some((ppid, rss)) = ppid_and_rss_kib(&status) else {
            continue;
        };
        children.entry(ppid).or_default().push(pid);
        rss_kib.insert(pid, rss);
    }
    // Walk down from this process rather than up from every process: a `ppid` chain read
    // one pid at a time can be re-parented to init mid-walk, which would silently drop a
    // whole subtree into the foreign figure.
    let mut total_kib = 0u64;
    let mut stack = vec![std::process::id()];
    let mut seen: HashSet<u32> = HashSet::new();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue; // a pid cannot be its own ancestor, but never loop on a bad reading
        }
        total_kib = total_kib.saturating_add(rss_kib.get(&pid).copied().unwrap_or(0));
        stack.extend(children.get(&pid).into_iter().flatten().copied());
    }
    Some(total_kib / 1024)
}

/// `(PPid, VmRSS)` in kB from one `/proc/<pid>/status`. `None` when either field is absent
/// or unparsable — a kernel thread (no `VmRSS`) reads as neither, which is what it is.
fn ppid_and_rss_kib(status: &str) -> Option<(u32, u64)> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))?
            .split_whitespace()
            .next()
    };
    Some((
        field("PPid:")?.parse().ok()?,
        field("VmRSS:")?.parse().ok()?,
    ))
}

/// What a stage must hold before it may boot a guest: one of the `jobs` slots, and its guest
/// RAM in the host-memory ledger. The slot bounds how many stages are in flight at all; the
/// ledger bounds how many bytes they commit between them — which is the one that has to
/// decide once stages stop being the same size.
struct BuildBudget {
    permits: Semaphore,
    mem: MemLedger,
}

impl BuildBudget {
    /// `gate_total_mib` is the host's `MemTotal` for the memory gate to measure against
    /// (see [`gate_total_mib`]); `None` builds a count-only budget.
    fn new(jobs: usize, gate_total_mib: Option<u64>) -> Self {
        Self {
            permits: Semaphore::new(jobs),
            mem: MemLedger::new(gate_total_mib),
        }
    }

    /// Hold a job slot and `want_mib` of host memory for as long as the guard lives. A wait
    /// on memory gets its own spinner: on the dashboard it is otherwise indistinguishable
    /// from a stage that is simply slow to boot.
    fn admit(
        &self,
        want_mib: u64,
        cancel: Option<&CancellationToken>,
        progress: &Progress,
        stage: progress::StageId,
        name: &str,
    ) -> BuildAdmission<'_> {
        let permit = self.permits.acquire();
        let (mem, wait) = self.mem.reserve(want_mib, cancel, |short| {
            progress.wait_mem_start(stage, name, short);
        });
        if wait != MemWait::No {
            progress.wait_mem_done(stage, name, wait == MemWait::Admitted);
        }
        BuildAdmission {
            _mem: mem,
            _permit: permit,
        }
    }
}

/// A stage's admission, held for as long as its guest may live.
///
/// The memory is declared first so it is released first: the stage taking the freed job slot
/// tickets immediately, and would otherwise measure the host with the departing stage's RAM
/// still charged — a needless `/proc` walk, and a "waiting for host memory" line for memory
/// that was free microseconds later.
struct BuildAdmission<'a> {
    _mem: MemReservation<'a>,
    _permit: SemaphorePermit<'a>,
}

/// Run a DAG of tasks with bounded concurrency. `nodes` is the set to run; `deps[n]`
/// lists the nodes that must finish before `n` (each must itself be in `nodes`).
/// `build(n, done)` produces `n`'s result given a snapshot of finished results that is
/// guaranteed to contain all of `n`'s deps. Returns every node's result, or the first
/// error (with remaining work abandoned). On the first error `cancel` (if given) is
/// triggered, so a `build` that honors the token can abort work already in flight.
///
/// The ordering matches a sequential topological walk — a node runs only once its deps
/// are in `done` — so `build` must be deterministic with respect to concurrency (its
/// result may not depend on which siblings ran alongside it). The microVM stage builder
/// satisfies this: stage cache keys are content-addressed, independent of build order.
fn run_dag<R, F>(
    nodes: &[usize],
    deps: &HashMap<usize, Vec<usize>>,
    jobs: usize,
    cancel: Option<&CancellationToken>,
    build: F,
) -> Result<HashMap<usize, R>>
where
    R: Send + Clone,
    F: Fn(usize, &HashMap<usize, R>) -> Result<R> + Sync,
{
    let mut indeg: HashMap<usize, usize> = HashMap::new();
    let mut dependents: HashMap<usize, Vec<usize>> = HashMap::new();
    for &n in nodes {
        let ds = deps.get(&n).map(Vec::as_slice).unwrap_or(&[]);
        indeg.insert(n, ds.len());
        for &d in ds {
            dependents.entry(d).or_default().push(n);
        }
    }
    let ready: Vec<usize> = nodes.iter().copied().filter(|n| indeg[n] == 0).collect();
    let jobs = jobs.max(1).min(nodes.len().max(1));
    let dag = Mutex::new(Dag {
        ready,
        indeg,
        done: HashMap::<usize, R>::new(),
        remaining: nodes.len(),
        error: None,
    });
    let cv = Condvar::new();
    // Borrow the owned state under distinct names so the workers share it by reference
    // while `dag` stays owned for the `into_inner` below.
    let (dagref, cv, build, dependents) = (&dag, &cv, &build, &dependents);
    // Still on the driver's own priority here, and the last moment that is true for a thread
    // this build creates: give the shared spawner and blocking-escape runtime their threads
    // now, so a `vk run` that boots after this build does not inherit its deferral.
    crate::prio::pin_shared_threads();
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(move || {
                // A worker exists to build stages, so it takes the build's scheduling
                // priority for its whole life — and everything it spawns inherits it,
                // `block_on`'s per-call thread included.
                crate::prio::lower_this_thread();
                loop {
                    // Claim the next ready node (or exit when the run is done / has failed),
                    // snapshotting the done map so the build reads its deps lock-free.
                    let (n, snapshot) = {
                        let mut g = dagref.lock().unwrap();
                        let n = loop {
                            if g.error.is_some() || g.remaining == 0 {
                                return;
                            }
                            if let Some(n) = g.ready.pop() {
                                break n;
                            }
                            g = cv.wait(g).unwrap();
                        };
                        (n, g.done.clone())
                    };
                    let res = build(n, &snapshot);
                    let mut g = dagref.lock().unwrap();
                    match res {
                        Ok(r) => {
                            g.done.insert(n, r);
                            g.remaining -= 1;
                            if let Some(ds) = dependents.get(&n) {
                                for &dep in ds {
                                    if let Some(c) = g.indeg.get_mut(&dep) {
                                        *c -= 1;
                                        if *c == 0 {
                                            g.ready.push(dep);
                                        }
                                    }
                                }
                            }
                            cv.notify_all();
                        }
                        Err(e) => {
                            if g.error.is_none() {
                                g.error = Some(e);
                                // Record the real first error under the lock, THEN cancel —
                                // so a cancellation-induced error from an interrupted sibling
                                // can never win the `is_none()` race and mask the true cause.
                                if let Some(c) = cancel {
                                    c.cancel();
                                }
                            }
                            cv.notify_all();
                            return;
                        }
                    }
                }
            });
        }
    });
    let dag = dag.into_inner().unwrap();
    if let Some(e) = dag.error {
        return Err(e);
    }
    Ok(dag.done)
}

/// Parallel driver for the microVM backend: build independent stages concurrently over
/// the dependency DAG. Each concurrent stage runs on its own [`MicroVm::worker`] (its own
/// guest and cache-push bookkeeping); the workers share only the committed-image maps,
/// and a stage is committed before any dependent starts — the same ordering the
/// sequential [`drive`] guarantees, so the exported image and cache are identical.
#[allow(clippy::too_many_arguments)]
fn drive_microvm(
    plan: &Plan,
    order: &[usize],
    build_args: &Vars,
    base: &MicroVm,
    jobs: usize,
    gate_total_mib: Option<u64>,
    require_cached: bool,
    cache: BuildCache,
    out_disk: Option<&Path>,
    progress: &Arc<Progress>,
    timings: &Arc<Timings>,
) -> Result<(HashMap<usize, Rootfs>, HashMap<usize, ShellState>)> {
    timings.note_jobs(jobs);
    // Read-only passes on a throwaway worker (shares `base`'s memoization + cache maps).
    let mut probe = base.worker();
    // Single-target driver: the target is the order's last stage.
    let targets = [*order.last().context("internal: empty build order")?];
    let resolved = resolve_all(plan, order, build_args, &mut probe, &targets)?;
    // `vk build --disk`: the target stage writes the caller's disk as an external side
    // effect the instruction cache does not capture, so it must never be served from
    // cache — a restore would skip the disk-writing RUNs and leave the disk untouched.
    // Mark its instruction keys non-cacheable; the probe (below) then keeps it out of
    // `cached_final` (deps still get pulled into `needed`), and the target worker refuses
    // to restore/save them, so its RUNs always run. Everything else caches normally.
    let uncacheable: std::collections::HashSet<String> = out_disk
        .map(|_| {
            resolved[&targets[0]]
                .steps
                .iter()
                .map(|s| s.key.clone())
                .collect()
        })
        .unwrap_or_default();
    probe.set_uncacheable(uncacheable.clone());
    let (needed, cached_final) =
        compute_needed(plan, order, &resolved, &mut probe, require_cached, &targets)?;
    drop(probe);
    progress.init(stage_inits(plan, order, &resolved, &needed, 0, ""), 1);

    // Dependency edges over the needed subset. A fully-cached stage restores standalone,
    // so it gets no deps (it can start immediately); a stage that consumes it still waits
    // for it, because the consumer keeps the edge in its own dep list.
    let needed_order: Vec<usize> = order
        .iter()
        .copied()
        .filter(|i| needed.contains(i))
        .collect();
    let mut deps: HashMap<usize, Vec<usize>> = HashMap::new();
    for &idx in &needed_order {
        let d = if cached_final.contains_key(&idx) {
            Vec::new()
        } else {
            plan.deps(idx)
                .into_iter()
                .filter(|x| needed.contains(x))
                .collect()
        };
        deps.insert(idx, d);
    }

    // Build-wide cancellation: `run_dag` fires it on the first stage failure, and each
    // stage honors it, so a failure interrupts the RUN steps in flight on sibling guests
    // instead of letting them run to completion before the build bails.
    let cancel = CancellationToken::new();
    // `budget` caps concurrent guest builds — `jobs` slots, plus the host-memory ledger —
    // not the DAG dispatch pool: a fully-cached stage never touches a guest, so it must not
    // queue behind either just to restore from cache. Dispatch gets one thread per
    // needed stage so every cache hit can proceed the moment its deps are ready; total
    // thread count (and any concurrent remote build-lock requests each node's uncached
    // path makes) now scales with the DAG instead of `jobs`, which is fine since a node
    // either restores instantly or waits on `budget` next.
    let budget = BuildBudget::new(jobs, gate_total_mib);
    let committed = run_dag(
        &needed_order,
        &deps,
        needed_order.len(),
        Some(&cancel),
        |idx, done| {
            // A fresh per-stage worker: its own guest + cache-push state, sharing only the
            // committed-image maps with `base`.
            let mut ex = base.worker();
            // `vk build --disk`: on the target stage's worker only, attach the caller's disk
            // (so exactly one stage writes it — no concurrent rw sharing) and mark its
            // instruction keys non-cacheable so its RUNs always run.
            if idx == targets[0] {
                ex.set_out_disk(out_disk.map(Path::to_path_buf));
                ex.set_uncacheable(uncacheable.clone());
            }
            build_stage(
                plan,
                &resolved,
                &cached_final,
                done,
                &mut ex,
                idx,
                cache,
                progress,
                timings,
                Some(&cancel),
                "",
                idx,
                &budget,
            )
        },
    )?;
    Ok((committed, final_states(&resolved)))
}

/// Resolve the parallel build's job count: the `opts.build_jobs` set from `--build-jobs` or
/// `[build] jobs` when present — taken as given, since the type rules out the one value that
/// would need correcting — else RAM-auto over `sizes`, the guest each stage of this build
/// will declare (its own `# vk:`/`--stage-mem` size, else `[build] mem`).
///
/// Dividing a memory budget by "the" stage size stopped being meaningful once stages size
/// themselves: four 2G stages and one 24G stage share no divisor. So the rule is instead the
/// most stages that could ever be co-resident — the smallest guests first, taking them while
/// they still fit in ~80% of `total_mib` — which is what "up to N at once" has to mean when
/// the N are different sizes. With every stage the same size it is exactly the old
/// division, and it can no longer exceed the number of stages there are to run. CPU is
/// intentionally allowed to oversubscribe (the host scheduler time-slices); RAM overcommit
/// would OOM.
///
/// The basis is what the host *has*, not the `MemAvailable` it happens to have free: that
/// figure moves with page cache and with whatever else is running, so a width read off it is
/// a width read off the minute the build started. A width derived from `MemTotal` is a
/// property of the host, which is what a budget announced once and held for the whole build
/// has to be.
///
/// The cost of that is a ceiling blind to how busy the host already is: auto claims its share
/// of the whole machine whatever else is admitted beside it. Which is why it is only a
/// ceiling — [`MemLedger`] holds each stage until the host actually has room for its guest,
/// so a build sized for the whole machine still yields to the jobs running next to it.
fn resolve_build_jobs(opts: &Options, sizes: &[u64], total_mib: Option<u64>) -> usize {
    if let Some(j) = opts.build_jobs {
        return j.get();
    }
    let usable = total_mib.unwrap_or(8 * 1024).saturating_mul(8) / 10;
    let mut sizes: Vec<u64> = sizes.iter().map(|&m| m.max(1)).collect();
    sizes.sort_unstable();
    let mut committed = 0u64;
    let mut fit = 0usize;
    for size in sizes {
        committed = committed.saturating_add(size);
        if committed > usable {
            break;
        }
        fit += 1;
    }
    fit.clamp(1, 16)
}

/// The guest RAM each stage of `order` will declare, in MiB: its own `# vk:` / `--stage-mem`
/// size where it has one, else the build-wide `[build] mem`. The input to
/// [`resolve_build_jobs`].
///
/// Unclamped, unlike what a stage finally boots at ([`clamp_stage_mem`]): the ceiling asks
/// how wide this build wants to run, and a host too small to grant a request is the case the
/// gate exists to handle, not one to divide by.
fn stage_sizes(plan: &Plan, order: &[usize], default_mib: u64) -> Vec<u64> {
    order
        .iter()
        .map(|&i| {
            plan.stages[i]
                .guest
                .mem
                .as_deref()
                .and_then(crate::run::parse_mem_mib)
                .unwrap_or(default_mib)
        })
        .collect()
}

/// The stages of `order` that asked for a size of their own, as `name mem=8G cpus=16`, for
/// the announcement — with mixed sizes, "each mem=4G" is no longer the whole story, and the
/// stages that differ are exactly the ones someone reading a trace needs named.
fn sized_stages(plan: &Plan, order: &[usize], prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for &i in order {
        let g = &plan.stages[i];
        if g.guest.mem.is_none() && g.guest.cpus.is_none() {
            continue;
        }
        let name = g.name.clone().unwrap_or_else(|| format!("stage{i}"));
        let mut parts = vec![format!("{prefix}{name}")];
        if let Some(m) = &g.guest.mem {
            parts.push(format!("mem={m}"));
        }
        if let Some(c) = g.guest.cpus {
            parts.push(format!("cpus={c}"));
        }
        out.push(parts.join(" "));
    }
    out
}

/// How wide the build may run, announced before any stage starts: the cap on stages built at
/// once, where that number came from (`configured` = `--build-jobs` or `[build] jobs`), the
/// size the stages take by default, and any stage that asked for a different one. A build
/// held to one stage at a time reads in a trace exactly like a build with nothing to
/// parallelize, and the two want opposite things done about them — so the line names its
/// source. It is a ceiling, not a prediction: what a stage actually waits for is the host
/// having room ([`MemLedger`]). Pure over its inputs, so the wording is testable without a
/// guest.
fn concurrency_line(
    jobs: usize,
    cpus: u32,
    mem: &str,
    configured: bool,
    sized: &[String],
) -> String {
    let source = if configured {
        "configured"
    } else {
        "from host memory"
    };
    let line = format!(
        "virtkit: build: up to {jobs} stage(s) at once ({source}), each cpus={cpus}, mem={mem}"
    );
    if sized.is_empty() {
        return line;
    }
    format!("{line}; sized apart: {}", sized.join(", "))
}

/// Fold `--stage-mem NAME=SIZE` and `--stage-cpus NAME=N` into one hint per stage, so the
/// two flags naming the same stage size it together rather than one winning. Both are
/// validated by their clap parsers, so anything here is already a size / a count.
pub fn stage_overrides(
    mem: &[(String, String)],
    cpus: &[(String, u32)],
) -> HashMap<String, parser::GuestHint> {
    let mut out: HashMap<String, parser::GuestHint> = HashMap::new();
    for (name, m) in mem {
        out.entry(name.clone()).or_default().mem = Some(m.clone());
    }
    for (name, n) in cpus {
        out.entry(name.clone()).or_default().cpus = Some(*n);
    }
    out
}

/// Overwrite the sizing of every stage an override names, and report which names matched.
///
/// A stage is addressed by its `AS` name, or `stage<N>` by position when it has none. (Not
/// `docker-hash`'s spelling, which numbers an unnamed stage `<N>` bare.) The flag is this run's decision, so it wins over the
/// Dockerfile's `# vk:` hint field by field — `--stage-cpus build=4` leaves a `mem=8G` hint
/// in place. The caller checks the names that matched nothing (a build spanning several
/// units has to ask every unit before deciding a name is wrong).
fn apply_stage_overrides(
    plan: &mut Plan,
    overrides: &HashMap<String, parser::GuestHint>,
) -> HashSet<String> {
    let mut matched = HashSet::new();
    for (idx, stage) in plan.stages.iter_mut().enumerate() {
        let name = stage.name.clone().unwrap_or_else(|| format!("stage{idx}"));
        if let Some(over) = overrides.get(&name) {
            if over.mem.is_some() {
                stage.guest.mem = over.mem.clone();
            }
            if over.cpus.is_some() {
                stage.guest.cpus = over.cpus;
            }
            matched.insert(name);
        }
    }
    matched
}

/// The error for `--stage-mem`/`--stage-cpus` naming a stage that does not exist: a typo
/// would otherwise size nothing and say nothing, which is the failure the `# vk:` hint is
/// strict about too. `known` is every stage the build declares, in source order.
fn unmatched_stage_overrides(
    overrides: &HashMap<String, parser::GuestHint>,
    matched: &HashSet<String>,
    known: &[String],
) -> Result<()> {
    let mut missing: Vec<&str> = overrides
        .keys()
        .filter(|n| !matched.contains(*n))
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    missing.sort_unstable();
    // Deduplicated, in declaration order: `known` is every unit's stages concatenated, and a
    // name declared by two units is one name to the flags, which size it in both. Order is
    // the Dockerfile's, which is how the reader will scan for the name they meant.
    let mut seen = HashSet::new();
    let declared: Vec<&str> = known
        .iter()
        .map(String::as_str)
        .filter(|n| seen.insert(*n))
        .collect();
    bail!(
        "--stage-mem/--stage-cpus {}: no such stage (declared: {})",
        missing.join(", "),
        declared.join(", ")
    )
}

/// Every stage a plan declares, named as [`apply_stage_overrides`] addresses them.
fn stage_names(plan: &Plan) -> Vec<String> {
    plan.stages
        .iter()
        .enumerate()
        .map(|(i, s)| s.name.clone().unwrap_or_else(|| format!("stage{i}")))
        .collect()
}

/// A stage's requested guest RAM, held to what this host could ever give one stage: `Some` with the
/// size to use instead when the request is over that, `None` when it stands as asked (including
/// when the host size is unknown, which promises nothing to hold it to).
fn clamp_stage_mem(want: &str, cap_mib: Option<u64>, default_mib: u64) -> Option<String> {
    let cap = cap_mib?.max(default_mib);
    let want_mib = crate::run::parse_mem_mib(want)?;
    (cap > 0 && want_mib > cap).then(|| format!("{cap}M"))
}

/// Summarize the memory currently available to stage guests.
///
/// The value is a current reading rather than an admission guarantee; stage sizes may differ
/// and other host workloads can change between readings.
fn gate_line(total_mib: u64, reserve_mib: u64, foreign_mib: u64) -> String {
    let room = total_mib
        .saturating_sub(reserve_mib)
        .saturating_sub(foreign_mib);
    format!(
        "virtkit: build: host memory {total_mib} MiB, {foreign_mib} MiB in use elsewhere, \
         {reserve_mib} MiB held back — {room} MiB free for stage guests now"
    )
}

/// [`gate_line`] for this build, measured now, or `None` when there is nothing to say:
/// the gate is off (`gate_total_mib` is `None`), or `jobs` is 1 and the ledger is
/// structurally inert — a build that never has two stages live has nothing to hold back,
/// and a line announcing room for stages it will not run only reads as noise.
fn gate_note(jobs: usize, gate_total_mib: Option<u64>) -> Option<String> {
    let total = gate_total_mib.filter(|_| jobs > 1)?;
    Some(gate_line(
        total,
        build_reserve_mib(total),
        measure_foreign_mib().unwrap_or(0),
    ))
}

/// Remove build scratch orphaned by earlier runs that were hard-killed (SIGKILL, OOM,
/// Ctrl-C, panic) before their normal on-exit cleanup could run. Scratch dirs in `dir` are
/// named `<prefix><pid>-<seq>-<nonce>` and a live one holds an exclusive lock on itself
/// ([`claim_scratch`]): a dir is stale only if this process can take that lock, whatever its
/// name says about a pid. Anything else is left untouched — worst case an orphan survives,
/// never the scratch of a build that takes the lock (a `vk` from before this scheme takes
/// none, so a mixed-version host can still lose one). Best-effort: any error (unreadable
/// dir, racing removal) is ignored.
fn sweep_stale_scratch(dir: &Path, prefix: &str) {
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(prefix))
            .and_then(|rest| rest.split_once('-'))
            .and_then(|(pid, _seq)| pid.parse::<u32>().ok())
        else {
            continue;
        };
        // Ours: a sibling in-process build may be between creating its dir and locking it.
        if pid == me {
            continue;
        }
        let path = entry.path();
        // Hold the claim across the removal: dropping it first would let a build claim the
        // dir in the window and have its files deleted from under it.
        let Some(_owner) = claim_if_abandoned(&path) else {
            continue;
        };
        let _ = std::fs::remove_dir_all(&path);
    }
}

/// Claim the scratch dir at `path` if it belongs to no live build, returning the handle
/// whose lock the caller must hold for as long as it acts on the dir. It is abandoned when
/// its directory can be locked exclusively — the owner is gone and the kernel released the
/// lock. A dir that cannot be locked has a live owner, including one in another PID
/// namespace, which is exactly what a pid cannot tell us. Anything unexpected (an unreadable
/// dir, a filesystem without `flock`) reads as live, so a sweep never removes what it does
/// not understand.
fn claim_if_abandoned(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;

    let dir = std::fs::File::open(path).ok()?;
    // SAFETY: the fd is owned by `dir`, which the caller keeps alive; flock returns 0 or -1
    // and does not block under `LOCK_NB`.
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    // A build recreating this dir between our open and our lock would hold a different
    // inode; removing what we opened would then delete nothing it owns, but reporting it
    // swept would be a lie. Only act on the dir the path still names.
    crate::cachelock::same_file(&dir, path).ok()?.then_some(dir)
}

/// The stage indices an instruction list references via `COPY --from` / `RUN
/// --mount=from` (distinct, in source order). Resolved on the raw `--from` text —
/// literal stage names; a `--from=$VAR` would not be seen (a known limitation).
fn stage_source_refs(plan: &Plan, instructions: &[Instruction]) -> Vec<usize> {
    let mut seen: Vec<usize> = Vec::new();
    for r in from_refs(instructions) {
        if let Some(si) = plan.stage_ref(r)
            && !seen.contains(&si)
        {
            seen.push(si);
        }
    }
    seen
}

/// Every `--from=` reference an instruction list makes (distinct, in source order), whether
/// it names a stage or an external image. `scratch` is excluded: it is the reserved empty
/// base a backend serves as an ephemeral writable mount, not a source to resolve.
fn from_refs(instructions: &[Instruction]) -> Vec<&str> {
    /// Append `f` unless it is `scratch` or already collected.
    fn note<'a>(refs: &mut Vec<&'a str>, f: &'a str) {
        if f != "scratch" && !refs.contains(&f) {
            refs.push(f);
        }
    }
    let mut refs: Vec<&str> = Vec::new();
    for instr in instructions {
        match instr {
            Instruction::Copy(c) => {
                if let Some(f) = &c.from {
                    note(&mut refs, f);
                }
            }
            Instruction::Run(r) => {
                for m in &r.mounts {
                    if let Some(f) = &m.from {
                        note(&mut refs, f);
                    }
                }
            }
            _ => {}
        }
    }
    refs
}

/// Parse one `--build-context NAME=DIR` value. Both halves are required: a nameless or
/// directoryless context could only fail later, inside the build.
pub fn parse_build_context(value: &str) -> Result<(String, PathBuf)> {
    match value.split_once('=') {
        Some((name, dir)) if !name.is_empty() && !dir.is_empty() => {
            Ok((name.to_string(), PathBuf::from(dir)))
        }
        _ => bail!("--build-context expects NAME=DIR, got {value:?}"),
    }
}

/// Every `--build-context NAME=DIR` value, in order. Shared by the flag's two front-ends
/// (`vk build` and `vk run -f`) so a bad value is rejected the same way for both.
pub fn parse_build_contexts(values: &[String]) -> Result<Vec<(String, PathBuf)>> {
    values.iter().map(|v| parse_build_context(v)).collect()
}

/// Declared named contexts — `--build-context <name>=<dir>`, or a CI job's `buildcontext=` —
/// as the plan's name → directory map, each resolved to an absolute path like the positional
/// contexts are: the directory is read host-side (packed into an ext4, and hashed into the cache
/// key), so a cwd-relative value must not be left for something later to re-resolve.
fn named_context_map(
    build_contexts: &[(String, PathBuf)],
) -> Result<std::collections::BTreeMap<String, PathBuf>> {
    let mut out = std::collections::BTreeMap::new();
    for (name, dir) in build_contexts {
        // `--from=scratch` always names the reserved empty base (see `Plan::check_reserved_names`),
        // so a context by that name could never be read from.
        if name == "scratch" {
            bail!("build context \"scratch\": the name is reserved");
        }
        let abs = std::path::absolute(dir)
            .with_context(|| format!("resolving build context {name} ({})", dir.display()))?;
        // Checked before any build work: the directory is both hashed into the cache key and
        // packed for the guest, and a missing one hashes as empty — so a typo would key a build
        // as if the context held nothing, then fail mid-build (or not at all, when cached).
        if !abs.is_dir() {
            bail!("build context {name}: {} is not a directory", abs.display());
        }
        if out.insert(name.clone(), abs).is_some() {
            bail!("build context {name} declared more than once");
        }
    }
    Ok(out)
}

/// Resolve a `--from=<x>` that does not name a build stage: a named build context when one
/// was declared under that name (`--build-context <x>=<dir>`), else an external image to pull.
fn non_stage_source(plan: &Plan, ex: &mut dyn Executor, reference: &str) -> Result<Rootfs> {
    match plan.named_context(reference) {
        Some(dir) => ex.context_source(reference, dir),
        None => ex.pull(reference),
    }
}

/// The read-only sources a stage reads, in first-use order: its committed source stages
/// (uncommitted ones are dropped — their consumers are fully cached, so no guest reads them)
/// plus every named build context and external image it references, materialized here.
/// Declared *before* the stage's guest boots, because a source that was not declared cannot
/// be attached later.
///
/// That ordering puts materialization ahead of the per-step cache probes, so a stage with a
/// cached prefix still pays the base-ext4 cache pull for an image only its cached steps read.
/// A fully cached stage is cheaper: it returns before this runs and pulls nothing.
fn stage_input_rootfs(
    plan: &Plan,
    instructions: &[Instruction],
    committed: &HashMap<usize, Rootfs>,
    ex: &mut dyn Executor,
) -> Result<Vec<Rootfs>> {
    let mut out: Vec<Rootfs> = Vec::new();
    for r in from_refs(instructions) {
        let fs = match plan.stage_ref(r) {
            Some(si) => match committed.get(&si) {
                Some(fs) => fs.clone(),
                None => continue,
            },
            // a named build context (packed read-only), else `--from=<image>` (pulled +
            // flattened); both memoized, so several references materialize once.
            None => non_stage_source(plan, ex, r)?,
        };
        if !out.iter().any(|o| o.label == fs.label) {
            out.push(fs);
        }
    }
    Ok(out)
}

/// Bump whenever a change to instruction-cache semantics — chunking, restore, or a
/// correctness fix in the cache-push path — means previously-cached content should no
/// longer be trusted, or whenever the key format itself changes. Folded into every root
/// cache key ([`hash_key`], `base_cache_key` in `exec.rs`); `chain_key` derives every
/// other key from one of those roots, so this alone invalidates a whole cache generation.
/// An old entry does not need deleting: it simply stops being looked up, and idle GC
/// reclaims it like any other unused blob.
const CACHE_KEY_VERSION: &str = "4";

/// The namespaces a build-cache key can belong to. One `build-cache` repository holds every
/// kind of cached artefact, so a key says which kind it is — both to a reader (`/browse`,
/// `vk registry status`, a gc log) and to the hash itself.
///
/// The label is folded into the hash *and* rendered as the key's prefix, which is two
/// separate jobs:
///
/// - **In the hash**, it is domain separation. Without it, two namespaces derived from the
///   same string collide: [`Ns::Base`]'s key is built from `"FROM image <ref>"` and so was
///   [`hash_key`]'s chain root for that same stage, giving byte-identical hashes that only
///   the prefix kept apart. Nothing tags a bare chain root today (`build_stage`'s
///   `final_key` comes from `steps.last()`), so that overlap was latent rather than
///   live — but it was one new key kind away from being real.
/// - **In the key**, it is the prefix, which makes every cache tag self-describing. It
///   sits on the key itself rather than being added at each use site, so a key and the
///   tag it is stored under can never disagree.
#[derive(Clone, Copy)]
enum Ns {
    /// An instruction snapshot: a stage's ext4 after one `RUN`/`COPY`, and the chain roots
    /// and stage keys those derive from.
    Snap,
    /// A base image's materialized ext4, keyed by the `FROM` reference it came from.
    Base,
}

impl Ns {
    /// Folded into the hash, and the key's prefix. Kept short: it is repeated in every tag.
    const fn label(self) -> &'static str {
        match self {
            Ns::Snap => "snap",
            Ns::Base => "base",
        }
    }

    /// A finished key in this namespace, from the hash's hex.
    fn key(self, hex: &str) -> String {
        format!("{}-{hex}", self.label())
    }
}

/// An [`Ns::Snap`] key from `s`, salted with [`CACHE_KEY_VERSION`] and namespaced. The
/// root-key constructor (a stage's base, with no prior instruction to chain from) — but
/// also reused wherever else a salted hash is needed, e.g. folding `image_kernel` into an
/// already-chained key.
fn hash_key(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CACHE_KEY_VERSION.as_bytes());
    h.update(b"\n");
    h.update(Ns::Snap.label().as_bytes());
    h.update(b"\n");
    h.update(s.as_bytes());
    Ns::Snap.key(&hex(&h.finalize()))
}

/// Chain the cache key with one instruction (an explicit canonical form, [`canonical`])
/// plus, for a context `COPY` or a `RUN --mount=type=bind`, a content hash of the files it
/// references. A change anywhere in the prefix — or in the referenced bytes — changes the key.
///
/// Stays in [`Ns::Snap`]: `prev` is already a namespaced, salted key, so both travel down
/// the chain through the hash without being folded in again.
fn chain_key(prev: &str, instr: &Instruction, content: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(canonical(instr).as_bytes());
    if let Some(c) = content {
        h.update(b"\n");
        h.update(c.as_bytes());
    }
    Ns::Snap.key(&hex(&h.finalize()))
}

/// An explicit, stable canonical string for an instruction — the cache-key identity. Spelled
/// out field by field (with a unit-separator delimiter) rather than the `Debug` repr, so the
/// key is a deliberate contract: refactoring the parser structs can't silently shift it.
fn canonical(instr: &Instruction) -> String {
    use parser::{Cmdline, Instruction as I};
    const US: char = '\u{1f}'; // unit separator — not expected in any field
    let cmd = |c: &Cmdline| match c {
        Cmdline::Shell(s) => format!("shell{US}{s}"),
        Cmdline::Exec(v) => format!("exec{US}{}", v.join(&US.to_string())),
    };
    let o = |x: &Option<String>| x.clone().unwrap_or_default();
    match instr {
        I::From(f) => format!(
            "FROM{US}{}{US}{}{US}{}",
            f.image,
            o(&f.as_name),
            o(&f.platform)
        ),
        I::Run(r) => format!(
            "RUN{US}{}{US}net={}{US}sec={}{US}mounts={}",
            cmd(&r.cmd),
            o(&r.network),
            o(&r.security),
            r.mounts
                .iter()
                .map(|m| format!(
                    "{}:from={}:src={}:tgt={}:ro={}:rw={}:uid={}:gid={}:mode={}",
                    m.typ,
                    o(&m.from),
                    o(&m.source),
                    o(&m.target),
                    m.readonly,
                    m.rw,
                    o(&m.uid),
                    o(&m.gid),
                    o(&m.mode),
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        I::Copy(c) => format!(
            "COPY{US}from={}{US}chown={}{US}chmod={}{US}link={}{US}{}->{}",
            o(&c.from),
            o(&c.chown),
            o(&c.chmod),
            c.link,
            c.sources.join(&US.to_string()),
            c.dest
        ),
        I::Arg { name, default } => format!("ARG{US}{name}={}", o(default)),
        I::Env(kvs) => format!("ENV{US}{}", kv(kvs, US)),
        I::Workdir(w) => format!("WORKDIR{US}{w}"),
        I::User(u) => format!("USER{US}{u}"),
        I::Label(kvs) => format!("LABEL{US}{}", kv(kvs, US)),
        I::Entrypoint(c) => format!("ENTRYPOINT{US}{}", cmd(c)),
        I::Cmd(c) => format!("CMD{US}{}", cmd(c)),
        I::Other { name, args } => format!("OTHER{US}{name}{US}{args}"),
    }
}

fn kv(kvs: &[(String, String)], sep: char) -> String {
    kvs.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(&sep.to_string())
}

/// sha256 over the (sorted, `.dockerignore`-filtered) content of the context files a set
/// of sources references — so the cache key tracks the referenced bytes, not just the
/// instruction text. Drives both a context `COPY` (without `--from`) and a `RUN
/// --mount=type=bind` from the context. Each source may be a file, a directory (recursed),
/// or a trailing-segment glob (`dir/*.json`). Unreadable/absent sources contribute a marker.
fn context_files_hash(context: &Path, sources: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let ign = vk_core::dockerignore::Ignore::load(context);
    let mut files: Vec<PathBuf> = Vec::new();
    for src in sources {
        files.extend(copy_src_files(context, &ign, src));
    }
    files.sort();
    files.dedup();
    let mut h = Sha256::new();
    for f in &files {
        let rel = f.strip_prefix(context).unwrap_or(f).to_string_lossy();
        h.update(rel.as_bytes());
        h.update(b"\0");
        match std::fs::read(f) {
            Ok(bytes) => h.update(Sha256::digest(&bytes)),
            Err(_) => h.update(b"?"),
        }
        h.update(b"\n");
    }
    hex(&h.finalize())
}

/// The context files one `COPY` source references (absolute, `.dockerignore`-filtered): a
/// literal file/dir (recursed), else a trailing-segment glob matched against its dir.
fn copy_src_files(context: &Path, ign: &vk_core::dockerignore::Ignore, src: &str) -> Vec<PathBuf> {
    let rel = src.trim_start_matches('/');
    let rel = rel.strip_prefix("./").unwrap_or(rel);
    let start = if rel.is_empty() || rel == "." {
        context.to_path_buf()
    } else {
        context.join(rel)
    };
    if start.exists() {
        return ign.included_files(&start);
    }
    // glob fallback: split into <dir>/<pattern> and match the dir's entries by name.
    let (dir, pat) = match rel.rsplit_once('/') {
        Some((d, p)) => (context.join(d), p),
        None => (context.to_path_buf(), rel),
    };
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for e in entries {
            if let Some(name) = e.file_name().and_then(|n| n.to_str())
                && glob_seg(pat, name)
            {
                out.extend(ign.included_files(&e));
            }
        }
    }
    out
}

/// Match one path segment against a `*`/`?` glob.
fn glob_seg(pat: &str, s: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => m(&p[1..], s) || (!s.is_empty() && m(p, &s[1..])),
            Some(b'?') => !s.is_empty() && m(&p[1..], &s[1..]),
            Some(&c) => !s.is_empty() && s[0] == c && m(&p[1..], &s[1..]),
        }
    }
    m(pat.as_bytes(), s.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A short human label for an instruction (the CACHED progress line).
fn instr_label(instr: &Instruction) -> String {
    match instr {
        Instruction::Run(r) => format!(
            "RUN {}",
            match &r.cmd {
                parser::Cmdline::Shell(s) => s.clone(),
                parser::Cmdline::Exec(v) => v.join(" "),
            }
        ),
        Instruction::Copy(c) => {
            let from = c
                .from
                .as_deref()
                .map(|f| format!("--from={f} "))
                .unwrap_or_default();
            format!("COPY {from}{} -> {}", c.sources.join(" "), c.dest)
        }
        other => format!("{other:?}"),
    }
}

/// Materialize a stage's base rootfs (pull/flatten an image, an empty scratch, or fork
/// a parent stage). Called lazily — only when the stage actually has to build.
fn materialize_base(
    ex: &mut dyn Executor,
    base: &Base,
    name: &str,
    committed: &HashMap<usize, Rootfs>,
) -> Result<Rootfs> {
    match base {
        Base::Image(image) => ex.from_image(name, image),
        Base::Scratch => ex.from_scratch(name),
        Base::Stage(parent) => {
            let parent_fs = committed
                .get(parent)
                .context("internal: base stage built out of order")?;
            ex.from_stage(name, parent_fs)
        }
    }
}

/// Restore a cached snapshot as stage `name`'s rootfs (no base build needed).
fn restore_into(ex: &mut dyn Executor, name: &str, key: &str) -> Result<Rootfs> {
    let fs = Rootfs {
        label: name.to_string(),
    };
    ex.cache_restore(&fs, key)?;
    Ok(fs)
}

/// Apply a non-filesystem instruction (ENV/WORKDIR/USER/ENTRYPOINT/CMD/EXPOSE) — updates the
/// shell state only, so it needs no materialized rootfs.
fn apply_meta(state: &mut ShellState, instr: &Instruction) {
    match instr {
        Instruction::Env(kvs) => {
            for (k, v) in kvs {
                upsert(&mut state.env, k, v);
            }
        }
        Instruction::Workdir(w) => state.workdir = w.clone(),
        Instruction::User(u) => state.user = u.clone(),
        Instruction::Entrypoint(c) => {
            state.entrypoint = cmdline_argv(c);
            // Docker: declaring ENTRYPOINT resets an inherited CMD (a CMD later in
            // the same stage still applies).
            state.cmd.clear();
        }
        Instruction::Cmd(c) => state.cmd = cmdline_argv(c),
        // The one `Other` the exported runtime config models: the sidecar records these, so a
        // service built from a Dockerfile gates readiness on its ports rather than on its guest
        // merely booting. The parser upper-cases the keyword, so any spelling lands here.
        Instruction::Other { name, args } if name == "EXPOSE" => {
            state.exposed_ports.extend(exposed_tcp_ports(args));
            state.exposed_ports.sort_unstable();
            state.exposed_ports.dedup();
        }
        // ARG/LABEL/any other `Other`: no effect here (ARG feeds interpolation upstream;
        // LABEL would land in an exported image config).
        _ => {}
    }
}

/// The TCP ports one `EXPOSE` declares: `<port>[/<proto>]` words and `<lo>-<hi>` ranges,
/// expanded the way docker records them. udp is dropped — readiness is a TCP connect — and a
/// word naming no protocol, or naming one in any case, is tcp, as docker lower-cases it before
/// looking. Port 0 is dropped too: nothing listens there, and the guest's gate would wait for it
/// forever. A word that does not parse as a port is ignored where docker would reject it: an
/// instruction this builder does not model has never failed a build here, and a readiness gate
/// is not worth making one that does.
fn exposed_tcp_ports(args: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for word in args.split_whitespace() {
        let (spec, proto) = word.split_once('/').unwrap_or((word, "tcp"));
        if !proto.is_empty() && !proto.eq_ignore_ascii_case("tcp") {
            continue;
        }
        match spec.split_once('-') {
            // an inverted range yields nothing, as an empty `lo..=hi` does
            Some((lo, hi)) => {
                if let (Ok(lo), Ok(hi)) = (lo.parse::<u16>(), hi.parse::<u16>()) {
                    ports.extend(lo..=hi);
                }
            }
            None => {
                if let Ok(p) = spec.parse::<u16>() {
                    ports.push(p);
                }
            }
        }
    }
    ports.retain(|&p| p != 0);
    ports
}

/// An ENTRYPOINT/CMD as argv: exec form verbatim, shell form wrapped `/bin/sh -c` —
/// Docker's runtime equivalence.
fn cmdline_argv(c: &parser::Cmdline) -> Vec<String> {
    match c {
        parser::Cmdline::Exec(v) => v.clone(),
        parser::Cmdline::Shell(s) => vec!["/bin/sh".into(), "-c".into(), s.clone()],
    }
}

/// Apply a filesystem-changing instruction (RUN/COPY) to the materialized rootfs.
fn apply_fs(
    plan: &Plan,
    committed: &HashMap<usize, Rootfs>,
    ex: &mut dyn Executor,
    fs: &mut Rootfs,
    state: &ShellState,
    instr: &Instruction,
) -> Result<()> {
    match instr {
        Instruction::Run(r) => {
            // resolve each --mount=…,from= to a committed stage rootfs (external-image
            // mounts are pulled). Hold the pulled handles so borrows outlive the call.
            let mut pulled: Vec<Rootfs> = Vec::new();
            let mut resolved: Vec<(usize, Option<usize>)> = Vec::new(); // (mount idx, committed key)
            for (mi, m) in r.mounts.iter().enumerate() {
                if let Some(from) = &m.from {
                    // `scratch` is the reserved empty base (Docker semantics), not a stage or
                    // image: an ephemeral writable scratch the backend serves without a source.
                    if from == "scratch" {
                        continue;
                    }
                    match plan.stage_ref(from) {
                        Some(s) => resolved.push((mi, Some(s))),
                        None => {
                            pulled.push(non_stage_source(plan, ex, from)?);
                            resolved.push((mi, None));
                        }
                    }
                }
            }
            let mut pi = 0;
            let mounts: Vec<ResolvedMount> = r
                .mounts
                .iter()
                .enumerate()
                .map(|(mi, m)| {
                    // `from=scratch` (reserved empty base) resolves to no source rootfs — the
                    // backend serves it as an ephemeral writable scratch, keyed off `spec.from`.
                    let from = if m.from.is_none() || m.from.as_deref() == Some("scratch") {
                        None
                    } else {
                        match resolved
                            .iter()
                            .find(|(i, _)| *i == mi)
                            .and_then(|(_, k)| *k)
                        {
                            Some(s) => committed.get(&s),
                            None => {
                                let r = pulled.get(pi);
                                pi += 1;
                                r
                            }
                        }
                    };
                    ResolvedMount { spec: m, from }
                })
                .collect();
            ex.run(fs, &r.cmd, &mounts, state)?;
        }
        Instruction::Copy(c) => {
            let from = match &c.from {
                None => None,
                Some(reference) => match plan.stage_ref(reference) {
                    Some(s) => committed.get(&s).cloned(),
                    // COPY --from=<named context> / --from=<external image>
                    None => Some(non_stage_source(plan, ex, reference)?),
                },
            };
            ex.copy(fs, c, from.as_ref(), &state.workdir)?;
        }
        // only RUN/COPY reach here (the driver routes ENV/WORKDIR/USER to apply_meta).
        _ => {}
    }
    Ok(())
}

fn upsert(env: &mut Vec<(String, String)>, k: &str, v: &str) {
    if let Some(e) = env.iter_mut().find(|(ek, _)| ek == k) {
        e.1 = v.to_string();
    } else {
        env.push((k.to_string(), v.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `[build]` section naming a gated remote cache.
    fn gated_cache() -> crate::config::Build {
        crate::config::Build {
            cache_registry: Some("registry.example/cache".into()),
            cache_insecure: true,
            cache_ca_file: Some("/etc/vk/ca.pem".into()),
            cache_username: "ci".into(),
            cache_password_file: Some("/etc/vk/pass".into()),
            cache_token_file: Some("/etc/vk/token".into()),
            ..Default::default()
        }
    }

    #[test]
    fn the_config_names_the_cache_until_the_command_line_overrides_it() {
        let b = gated_cache();

        let c = CacheOpts::resolve(None, false, &b);
        assert_eq!(c.registry.as_deref(), Some("registry.example/cache"));
        assert!(c.insecure);

        // The flag is the last word on where; the credentials follow it there.
        let c = CacheOpts::resolve(Some("/var/cache/vk"), false, &b);
        assert_eq!(c.registry.as_deref(), Some("/var/cache/vk"));
        assert_eq!(c.auth.username, "ci");

        // `--cache-insecure` adds to the config's, and stands alone without it.
        assert!(CacheOpts::resolve(None, true, &Default::default()).insecure);
        assert!(!CacheOpts::resolve(None, false, &Default::default()).insecure);

        // `none` gets no special case here; `cache_repo` reads it as caching off.
        let c = CacheOpts::resolve(Some("none"), false, &b);
        assert_eq!(c.registry.as_deref(), Some("none"));
    }

    #[test]
    fn every_cache_credential_reaches_the_build() {
        // All four move together: a build that authenticates with three of them and drops
        // the fourth fails at the registry, not here.
        let auth = CacheAuth::from_config(&gated_cache());
        assert_eq!(auth.ca_file.as_deref(), Some(Path::new("/etc/vk/ca.pem")));
        assert_eq!(auth.username, "ci");
        assert_eq!(
            auth.password_file.as_deref(),
            Some(Path::new("/etc/vk/pass"))
        );
        assert_eq!(
            auth.token_file.as_deref(),
            Some(Path::new("/etc/vk/token")),
            "the bearer token is the one credential with no Basic fallback"
        );

        // No `[build]` credentials at all is anonymous, which the local store wants.
        let anon = CacheAuth::from_config(&Default::default());
        assert!(
            anon.ca_file.is_none() && anon.password_file.is_none() && anon.token_file.is_none()
        );
        assert_eq!(anon.username, "");
    }

    /// A private directory for one test, removed and recreated so a rerun starts clean.
    /// Shared with the `exec` submodule's tests, so every temp dir the build tests take is
    /// minted here: nothing else under `std::env::temp_dir()` takes the `vk-build-` prefix,
    /// and the pid keeps a second suite on the same host off these paths. Keep `tag` unique
    /// across both test modules — two tests sharing a tag pull each other's tree out
    /// mid-run, as a hand-rolled pair once did.
    pub(super) fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-build-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Host-backend `build` / `build_inputs` (FROM scratch + COPY, no VM) — the path tests
    /// use to drive the whole pipeline without KVM. Production always builds in microVMs.
    fn build_host(opts: &Options) -> Result<Built> {
        let inputs = load_inputs(&opts.dockerfiles, &opts.contexts)?;
        build_backend(inputs, opts, false)
    }
    fn build_inputs_host(inputs: Vec<PlanInput>, opts: &Options) -> Result<Built> {
        build_backend(inputs, opts, false)
    }

    #[test]
    fn parse_build_context_requires_both_halves() {
        assert_eq!(
            parse_build_context("shared=shared").unwrap(),
            ("shared".to_string(), PathBuf::from("shared"))
        );
        // An absolute dir, and a dir containing '=' (only the first '=' splits).
        assert_eq!(
            parse_build_context("repo=/srv/shared").unwrap(),
            ("repo".to_string(), PathBuf::from("/srv/shared"))
        );
        assert_eq!(
            parse_build_context("x=a=b").unwrap(),
            ("x".to_string(), PathBuf::from("a=b"))
        );
        // Rejected rather than half-honoured: no '=', empty name, empty dir.
        assert!(parse_build_context("shared").is_err());
        assert!(parse_build_context("=shared").is_err());
        assert!(parse_build_context("shared=").is_err());
    }

    #[test]
    fn from_refs_collects_stage_and_image_sources_once() {
        let df = parser::parse(
            "FROM alpine AS base\n\
             COPY --from=base /a /a\n\
             COPY --from=golang:1.22 /usr/local/go /go\n\
             RUN --mount=type=bind,from=golang:1.22,target=/g \
                 --mount=type=bind,from=scratch,target=/s,rw \
                 --mount=type=tmpfs,target=/t build\n\
             COPY --from=base /b /b\n",
        )
        .unwrap();
        // Distinct, in first-use order: a stage and an image ref each appear once, the
        // reserved `scratch` base and a from-less tmpfs/bind mount are not sources.
        assert_eq!(
            from_refs(&df.instructions),
            vec!["base", "golang:1.22"],
            "refs must be deduped, ordered, and exclude scratch"
        );
    }

    /// An external image reaches the guest as a *declared* source: named in the stage's source
    /// declaration, which is the only way a real backend can attach it before the boot, and read
    /// under its `image/<ref>` label rather than silently resolved against the build context.
    #[test]
    fn copy_from_external_image_is_declared_before_the_stage_runs() {
        let t = transcript(
            "FROM alpine AS app\nCOPY --from=busybox:latest /bin/sh /sh\n",
            Some("app"),
        );
        assert!(
            t.contains(&"stage-sources [\"image/busybox:latest\"]".to_string()),
            "the image must be declared as a source, not pulled ad hoc: {t:#?}"
        );
        let pull = t
            .iter()
            .position(|l| l == "pull busybox:latest")
            .unwrap_or_else(|| panic!("no pull in {t:#?}"));
        let copy = t
            .iter()
            .position(|l| l.starts_with("copy from=image/busybox:latest "))
            .unwrap_or_else(|| panic!("copy did not read the image in {t:#?}"));
        assert!(pull < copy, "the image must be attached first: {t:#?}");
    }

    /// A `--from=$VAR` is declared under the text the step will ask for. The declaration reads
    /// the resolved steps, not the plan's raw instructions where the ref is still `${GO}` —
    /// otherwise the build materializes a ref that does not exist, under a label no instruction
    /// can ever match.
    #[test]
    fn copy_from_an_interpolated_image_ref_is_declared_expanded() {
        let t = transcript(
            "ARG GO=1.22\nFROM alpine AS app\nARG GO\nCOPY --from=golang:${GO} /go /go\n",
            Some("app"),
        );
        assert!(
            t.contains(&"stage-sources [\"image/golang:1.22\"]".to_string()),
            "the expanded ref must be the declared source: {t:#?}"
        );
        assert!(
            t.iter()
                .any(|l| l.starts_with("copy from=image/golang:1.22 ")),
            "the copy must read the expanded label: {t:#?}"
        );
    }

    /// Two builds that cannot tell each other's pids apart — one in a container sharing the
    /// output directory, or one on another host across a network filesystem — would otherwise
    /// compute the same `<pid>-<seq>` name and one of them would fail to claim it. The nonce
    /// makes the name unique without asking who anyone is, so same pid and same seq still means
    /// a different dir.
    #[test]
    fn two_builds_never_compute_the_same_scratch_name() {
        let out = Path::new("./test.ext4");
        let a = build_scratch(out, 0).unwrap();
        let b = build_scratch(out, 0).unwrap();
        assert_ne!(a, b, "same pid and seq must still yield distinct scratch");

        // The sweep still reads the pid out of the longer name, so it can tell its own dirs.
        let name = a.file_name().unwrap().to_str().unwrap();
        let pid = name
            .strip_prefix(SCRATCH_PREFIX)
            .and_then(|rest| rest.split_once('-'))
            .and_then(|(pid, _)| pid.parse::<u32>().ok());
        assert_eq!(pid, Some(std::process::id()), "unparseable name {name}");
    }

    /// Scratch is absolute even for a relative `--out`, so a stage qcow2's recorded backing
    /// path resolves against the overlay's own dir without doubling the scratch prefix.
    #[test]
    fn build_scratch_is_absolute_for_relative_out() {
        let s = build_scratch(Path::new("./test.ext4"), 0).unwrap();
        assert!(
            s.is_absolute(),
            "scratch must be absolute, got {}",
            s.display()
        );
        assert!(
            s.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(SCRATCH_PREFIX)),
            "scratch dir must carry the prefix, got {}",
            s.display()
        );
    }

    /// Sweep `root` until `dir` is gone. A single shot is racy under parallel test load: a
    /// concurrent test's `Command::spawn` forks with this test's lock fd still open, holding
    /// the lock alive until the child `exec`s — the same hazard `cachelock` documents for its
    /// own sweeps. Converges once the transient inheriting child is gone.
    fn swept_eventually(root: &Path, dir: &Path) -> bool {
        crate::cachelock::reclaimed_eventually(|| {
            sweep_stale_scratch(root, SCRATCH_PREFIX);
            !dir.exists()
        })
    }

    /// A pid that has certainly been reaped, so a dir named after it never looks live on
    /// its name alone.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// The startup sweep removes scratch nobody holds, keeps a dir this process is building
    /// in, and leaves anything that is not scratch alone.
    #[test]
    fn sweep_removes_only_unheld_scratch() {
        let root = tmpdir("sweep");
        let orphan = root.join(format!("{SCRATCH_PREFIX}{}-0", dead_pid()));
        let own_dir = root.join(format!("{SCRATCH_PREFIX}{}-3", std::process::id()));
        let unrelated = root.join("not-scratch");
        for d in [&orphan, &own_dir, &unrelated] {
            std::fs::create_dir_all(d).unwrap();
        }

        assert!(
            swept_eventually(&root, &orphan),
            "scratch nobody holds should be swept"
        );
        assert!(own_dir.exists(), "this process's own scratch must be kept");
        assert!(unrelated.exists(), "a non-scratch dir must be untouched");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A build's lock on its own scratch is what marks it live — not the pid in the name,
    /// which means nothing to a sweeper in another PID namespace (a build in a container
    /// sharing the output dir). A locked dir must survive a sweep even when its pid reads as
    /// dead here; releasing the lock makes it collectable.
    #[test]
    fn sweep_keeps_a_locked_scratch_whatever_its_pid_says() {
        let root = tmpdir("sweep-lock");
        let dead = dead_pid();

        let claimed = root.join(format!("{SCRATCH_PREFIX}{dead}-0"));
        let owner = claim_scratch(&claimed).unwrap();

        sweep_stale_scratch(&root, SCRATCH_PREFIX);
        assert!(
            claimed.exists(),
            "a scratch dir whose owner lock is held must survive the sweep"
        );

        // The owner goes away (the process exited, the kernel dropped its lock).
        drop(owner);
        assert!(
            swept_eventually(&root, &claimed),
            "once nobody holds the lock the scratch is collectable"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Claiming a scratch dir twice must fail rather than let two builds share one.
    #[test]
    fn a_second_claim_on_one_scratch_dir_is_refused() {
        let root = tmpdir("sweep-double-claim");
        let dir = root.join(format!("{SCRATCH_PREFIX}{}-0", std::process::id()));
        let _first = claim_scratch(&dir).unwrap();
        assert!(
            claim_scratch_until(&dir, Instant::now()).is_err(),
            "a scratch dir already claimed must not be handed out twice"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// How libtest addresses [`scratch_claim_holder`], for the re-exec below.
    const SCRATCH_HOLDER: &str = "build::tests::scratch_claim_holder";

    /// A child killed however its test ends. The holder below blocks forever by design, so
    /// a panicking assertion between spawning and killing it would otherwise leak a process
    /// still holding a lock under `$TMPDIR`.
    struct Reaped(std::process::Child);

    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Not a test in its own right: the subprocess half of
    /// [`sweep_reclaims_a_scratch_whose_owner_was_killed`]. Claims the scratch dir named by
    /// `VK_TEST_SCRATCH_CLAIM`, reports itself ready, and blocks until killed. `#[ignore]`
    /// keeps it out of ordinary runs; the parent re-runs this binary to reach it.
    #[test]
    #[ignore]
    fn scratch_claim_holder() {
        let (Ok(dir), Ok(ready)) = (
            std::env::var("VK_TEST_SCRATCH_CLAIM"),
            std::env::var("VK_TEST_SCRATCH_READY"),
        ) else {
            return;
        };
        let _owner = claim_scratch(Path::new(&dir)).unwrap();
        std::fs::write(&ready, b"claimed").unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    /// What the lock actually buys is that a *hard-killed* build stops holding its
    /// scratch: the kernel drops the lock with the process, and no in-process `drop` can
    /// stand in for that. Drive it for real — a subprocess claims the dir and blocks, the
    /// sweep must keep it, then `SIGKILL` must make it collectable.
    #[test]
    fn sweep_reclaims_a_scratch_whose_owner_was_killed() {
        let root = tmpdir("sweep-killed-owner");
        // Named after a dead pid, so only the subprocess's lock keeps it from the sweep.
        let claimed = root.join(format!("{SCRATCH_PREFIX}{}-0", dead_pid()));
        let ready = root.join("ready");

        let mut holder = Reaped(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "--ignored", SCRATCH_HOLDER])
                .env("VK_TEST_SCRATCH_CLAIM", &claimed)
                .env("VK_TEST_SCRATCH_READY", &ready)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the holder never claimed {}",
                claimed.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        sweep_stale_scratch(&root, SCRATCH_PREFIX);
        assert!(
            claimed.exists(),
            "a scratch dir a live process holds must survive the sweep"
        );

        holder.0.kill().unwrap();
        let died = holder.0.wait().unwrap();
        // Killed, not already gone — otherwise the sweep above proved nothing.
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&died),
            Some(libc::SIGKILL),
            "the holder was meant to still be blocking on its claim"
        );
        assert!(
            swept_eventually(&root, &claimed),
            "a killed owner's lock dies with it, making its scratch collectable"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The pid misleads in the other direction too: a scratch dir nobody owns, whose pid has
    /// since been reused by an unrelated live process, read as live and was never collected.
    /// That the lock is free settles it, whatever the pid says.
    #[test]
    fn sweep_reclaims_an_unclaimed_scratch_whose_pid_is_live() {
        let root = tmpdir("sweep-pid-reuse");
        // pid 1 is always alive, so only the free lock can make this collectable.
        let stale = root.join(format!("{SCRATCH_PREFIX}1-0"));
        drop(claim_scratch(&stale).unwrap());

        assert!(
            swept_eventually(&root, &stale),
            "a free lock means nobody owns the dir, whatever its pid"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A sweep must hold the claim it decided on for as long as it is deleting: releasing it
    /// first leaves a window where a build claims the dir and then has its files removed.
    /// The lock is on the directory, which `remove_dir_all` empties before removing it, so
    /// it covers the whole walk — including, as here, the part where the dir has already
    /// lost its contents but still exists under the name a build would claim.
    #[test]
    fn a_sweep_holds_its_claim_across_the_whole_removal() {
        let root = tmpdir("sweep-holds-claim");
        let dir = root.join(format!("{SCRATCH_PREFIX}{}-0", dead_pid()));
        drop(claim_scratch(&dir).unwrap());
        std::fs::write(dir.join("stage.ext4"), b"a stage half-removed").unwrap();

        let owner = claim_if_abandoned(&dir).expect("an unlocked scratch dir is abandoned");
        // Mid-walk: contents gone, the dir itself still to come.
        std::fs::remove_file(dir.join("stage.ext4")).unwrap();
        assert!(
            dir.exists(),
            "the removal has not reached the dir itself yet"
        );
        assert!(
            claim_scratch_until(&dir, Instant::now()).is_err(),
            "a build must not claim a dir a sweep is part-way through removing"
        );
        drop(owner);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// And the other side of that window: a claim landing after a sweep removed the dir must
    /// come back holding the directory the path now names, not the removed one it may have
    /// opened first — otherwise the build writes into nothing.
    #[test]
    fn a_claim_recreates_a_scratch_dir_a_sweep_removed() {
        let root = tmpdir("claim-after-sweep");
        let dir = root.join(format!("{SCRATCH_PREFIX}{}-0", dead_pid()));
        drop(claim_scratch(&dir).unwrap());
        assert!(
            swept_eventually(&root, &dir),
            "an unlocked scratch dir is swept"
        );

        let owner = claim_scratch(&dir).unwrap();
        assert!(
            crate::cachelock::same_file(&owner, &dir).unwrap(),
            "a claim must hold the dir its path names"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A claim landing *while* a sweep removes the dir waits that removal out rather than
    /// failing or joining it, and comes back holding a directory of its own — never the one
    /// the sweep emptied.
    #[test]
    fn a_claim_racing_a_sweep_waits_for_a_dir_of_its_own() {
        let root = tmpdir("claim-vs-sweep");
        let dir = root.join(format!("{SCRATCH_PREFIX}{}-0", dead_pid()));
        drop(claim_scratch(&dir).unwrap());

        let sweeping = claim_if_abandoned(&dir).expect("an unlocked scratch dir is abandoned");

        // The claim goes on the thread and the sweep stays here, so every fallible step of
        // the sweep reports the error it failed with instead of reaching us as a bare
        // `join` panic carrying nothing. The thread announces itself before claiming, and
        // waiting for that is what puts the build behind the sweep — no sleep has to be
        // long enough for it.
        let (announce, claiming_now) = std::sync::mpsc::channel();
        let claiming = std::thread::spawn({
            let dir = dir.clone();
            move || {
                announce.send(()).unwrap();
                claim_scratch(&dir)
            }
        });
        claiming_now.recv().unwrap();

        // Whether it has got as far as blocking is a race, but which way it can go is not:
        // the sweep still holds the dir the path names, and a claim cannot have the lock
        // and the path at once. So this wait is free to be as generous as it likes —
        // lengthening it gives the claim more room to finish and can never make a broken
        // one pass, which an ordering flag read after the fact could not promise.
        std::thread::sleep(CLAIM_RETRY * 3);
        assert!(
            !claiming.is_finished(),
            "a claim must wait the sweep out, not join the dir being swept"
        );

        std::fs::remove_dir_all(&dir).unwrap();
        drop(sweeping);

        // And what it came back holding is the live directory at that path, not the one the
        // sweep unlinked. Identity, not inode *inequality*: the kernel is free to hand the
        // freed inode straight back to the directory created in its place, so an
        // `assert_ne!` on (dev, ino) fails at random. It also cannot happen that `owner` is
        // the unlinked dir *and* the inode was reused — an open handle keeps it alive.
        let owner = claiming
            .join()
            .expect("the claim thread panicked")
            .expect("a claim must succeed once the sweep lets the dir go");
        assert!(
            crate::cachelock::same_file(&owner, &dir).unwrap(),
            "a build must hold the dir its path names, not the one the sweep emptied"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The unified multi-service build namespaces each service's stages: `stage_inits`
    /// offsets ids into a build-wide space and prefixes names, so two services with a
    /// same-named stage (both `AS build`) and an unnamed final stage never collide on the
    /// dashboard (the same namespacing keys the executor's images map + scratch files).
    #[test]
    fn stage_inits_namespace_services_by_offset_and_prefix() {
        let ba = Vars::new();
        let inits = |base: usize, prefix: &str| {
            let plan = plan_one("FROM scratch AS build\nRUN a\nFROM build\nRUN b\n", &ba);
            let target = plan.resolve_target(None).unwrap();
            let order = plan.build_order(target).unwrap();
            let needed: HashSet<usize> = order.iter().copied().collect();
            let mut ex = DryRun::new();
            let resolved = resolve_all(&plan, &order, &ba, &mut ex, &[target]).unwrap();
            stage_inits(&plan, &order, &resolved, &needed, base, prefix)
        };
        let web = inits(0, "web:");
        let db = inits(2, "db:");
        // ids are globally unique (each service offset by its base)
        let ids: Vec<usize> = web.iter().chain(&db).map(|s| s.id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3]);
        // names carry the service prefix, so the shared `build` name stays distinct, and
        // the unnamed final stage keeps its `stageN` fallback (also prefixed)
        let name = |s: &[StageInit], i: usize| s[i].name.clone();
        assert_eq!(name(&web, 0), "web:build");
        assert_eq!(name(&db, 0), "db:build");
        assert_eq!(name(&web, 1), "web:stage1");
        assert_eq!(name(&db, 1), "db:stage1");
    }

    /// One [`build_units_dry`] target: `(label, stage selector, export out)`.
    type TestTarget<'a> = (&'a str, Option<&'a str>, Option<PathBuf>);

    /// Drive several build units through the [`DryRun`] backend, mirroring the
    /// backend-agnostic core of [`build_units`] (per-unit plan/order/resolve, one flat
    /// id space with per-unit `base` offset + label prefix, then `build_stage` per needed
    /// stage in dependency order) — without the microVM-only bits it cannot exercise
    /// (`make_microvm`/`run_dag`'s worker pool). Returns the shared transcript plus the
    /// per-target-label result map, so a test can assert what got built, the stage-name
    /// namespacing, the cache-only (`out: None`) path, and the returned keying.
    ///
    /// Each unit is `(label, dockerfile, targets)` where a target is [`TestTarget`]
    /// `(label, selector, out)`. Stages run sequentially over the combined order (jobs=1
    /// semantics), which is deterministic — content-addressed keys make order irrelevant.
    fn build_units_dry(
        units: &[(&str, &str, Vec<TestTarget<'_>>)],
    ) -> (Vec<String>, HashMap<String, PathBuf>) {
        let ba = Vars::new();
        let mut ex = DryRun::new();
        let progress = Progress::disabled();
        let timings = Arc::new(Timings::new());
        let multi_unit = units.len() > 1;
        // Committed rootfs per global id, and the label -> export-out map the caller keys by.
        let mut committed_global: HashMap<usize, Rootfs> = HashMap::new();
        let mut result: HashMap<String, PathBuf> = HashMap::new();
        let mut base = 0usize;
        for (label, src, targets) in units {
            let prefix = if multi_unit {
                format!("{label}:")
            } else {
                String::new()
            };
            let plan = plan_one(src, &ba);
            let tidx: Vec<usize> = targets
                .iter()
                .map(|(_, sel, _)| plan.resolve_target(*sel).unwrap())
                .collect();
            let order = plan.build_order_multi(&tidx).unwrap();
            let resolved = resolve_all(&plan, &order, &ba, &mut ex, &tidx).unwrap();
            let (needed, cached_final) =
                compute_needed(&plan, &order, &resolved, &mut ex, false, &tidx).unwrap();
            // Build every needed stage in dependency order; hand each one only its own
            // unit's committed rootfs, re-keyed to local indices (as build_units does).
            let mut committed_local: HashMap<usize, Rootfs> = HashMap::new();
            let budget = BuildBudget::new(1, None);
            for &idx in &order {
                if !needed.contains(&idx) {
                    continue;
                }
                let fs = build_stage(
                    &plan,
                    &resolved,
                    &cached_final,
                    &committed_local,
                    &mut ex,
                    idx,
                    BuildCache::Instructions,
                    &progress,
                    &timings,
                    None,
                    &prefix,
                    base + idx,
                    &budget,
                )
                .unwrap();
                committed_local.insert(idx, fs.clone());
                committed_global.insert(base + idx, fs);
            }
            // Export each target that has an out, and record every target's label.
            for ((tlabel, _, out), &idx) in targets.iter().zip(&tidx) {
                if let Some(out) = out {
                    let fs = committed_global.get(&(base + idx)).unwrap();
                    ex.export_ext4(fs, out).unwrap();
                    result.insert(tlabel.to_string(), out.clone());
                }
            }
            base += plan.stages.len();
        }
        (ex.transcript, result)
    }

    #[test]
    fn build_units_shares_a_stage_and_builds_both_tails() {
        // One unit, two targets over a diamond: base -> {left, right}. The shared 'base'
        // must build once; both divergent tails must build.
        let out = |n: &str| Some(PathBuf::from(format!("/out/{n}.ext4")));
        let (t, _) = build_units_dry(&[(
            "",
            "FROM scratch AS base\nRUN common\n\
             FROM base AS left\nRUN l\n\
             FROM base AS right\nRUN r\n",
            vec![
                ("left", Some("left"), out("left")),
                ("right", Some("right"), out("right")),
            ],
        )]);
        // 'base' (from scratch) is materialized exactly once …
        assert_eq!(
            t.iter()
                .filter(|l| l.as_str() == "from-scratch base")
                .count(),
            1,
            "shared base built once:\n{t:#?}"
        );
        // … and each divergent tail runs its own step.
        assert!(
            t.iter().any(|l| l.contains("run [") && l.contains(" l")),
            "{t:#?}"
        );
        assert!(
            t.iter().any(|l| l.contains("run [") && l.contains(" r")),
            "{t:#?}"
        );
    }

    #[test]
    fn build_units_namespaces_stage_names_across_units() {
        // Two units, each with a same-named stage `build` and an unnamed final stage. Their
        // stage identities (the executor's images-map key / scratch names) must be prefixed
        // by the unit label so they never collide.
        let out = |n: &str| Some(PathBuf::from(format!("/out/{n}.ext4")));
        let (t, _) = build_units_dry(&[
            (
                "web",
                "FROM scratch AS build\nRUN wb\nFROM build\nRUN w\n",
                vec![("web", None, out("web"))],
            ),
            (
                "db",
                "FROM scratch AS build\nRUN db\nFROM build\nRUN d\n",
                vec![("db", None, out("db"))],
            ),
        ]);
        // Each unit's `build` stage is scratch-materialized under its own prefix — distinct,
        // no collision on a shared `build` name.
        assert!(t.iter().any(|l| l == "from-scratch web:build"), "{t:#?}");
        assert!(t.iter().any(|l| l == "from-scratch db:build"), "{t:#?}");
        // The unnamed final stages likewise get a prefixed `stageN` fallback, so two
        // otherwise-identical unnamed stages stay distinct.
        assert!(
            t.iter().any(|l| l.starts_with("from-stage web:stage")),
            "{t:#?}"
        );
        assert!(
            t.iter().any(|l| l.starts_with("from-stage db:stage")),
            "{t:#?}"
        );
    }

    #[test]
    fn build_units_cache_only_target_exports_nothing() {
        // A target with `out: None` warms the cache without exporting: the stage still
        // builds, but no export-ext4 line is emitted and the label is not in the result map.
        let (t, result) = build_units_dry(&[(
            "",
            "FROM scratch AS app\nRUN build-it\n",
            vec![("app", Some("app"), None)],
        )]);
        assert!(
            t.iter().any(|l| l.contains("build-it")),
            "stage still builds:\n{t:#?}"
        );
        assert!(
            !t.iter().any(|l| l.starts_with("export-ext4")),
            "cache-only target must not export:\n{t:#?}"
        );
        assert!(
            result.is_empty(),
            "cache-only target is not keyed with an out"
        );
    }

    #[test]
    fn build_units_result_is_keyed_by_target_label() {
        // The returned map is keyed by each exporting target's label, pointing at its out.
        let out = |n: &str| Some(PathBuf::from(format!("/out/{n}.ext4")));
        let (_, result) = build_units_dry(&[(
            "",
            "FROM scratch AS base\nRUN c\nFROM base AS left\nFROM base AS right\n",
            vec![
                ("left", Some("left"), out("left")),
                ("right", Some("right"), out("right")),
            ],
        )]);
        assert_eq!(result.get("left"), Some(&PathBuf::from("/out/left.ext4")));
        assert_eq!(result.get("right"), Some(&PathBuf::from("/out/right.ext4")));
        assert_eq!(result.len(), 2);
    }

    /// A single-file plan whose stages' context is `/nonexistent` (the tests' COPYs
    /// hash an empty file set — deterministic without touching the host).
    fn plan_one(src: &str, ba: &Vars) -> Plan {
        Plan::from_dockerfiles(
            &[PlanInput {
                dockerfile: parser::parse(src).unwrap(),
                origin: "Dockerfile".into(),
                context: "/nonexistent".into(),
            }],
            ba,
        )
        .unwrap()
    }

    fn transcript(src: &str, target: Option<&str>) -> Vec<String> {
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(target).unwrap();
        let order = plan.build_order(t).unwrap();
        let mut ex = DryRun::new();
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        ex.transcript
    }

    /// A [`DryRun`] with an instruction cache: `cache_save` records keys, `cache_has`
    /// answers from them, and every cache primitive lands in the transcript so tests
    /// can assert what a warm rebuild touches.
    #[derive(Default)]
    struct CachedDry {
        inner: DryRun,
        cache: HashSet<String>,
        /// key of the most recent `cache_save` — the target's final key after a cold
        /// run, so tests can evict it to simulate a partially cached rebuild.
        last_saved: Option<String>,
        /// preset answer for `check_build_failure` — a test's stand-in for a remote
        /// vk-registry's failure memo.
        fail_check: Option<vk_registry::FailInfo>,
        /// every `report_build_failure(key, reason)` call, in order — so a test can assert
        /// a genuine build error got memoized (and a cascaded/short-circuited one did not).
        fail_reports: Vec<(String, String)>,
        /// force `cache_save` to fail, standing in for a genuine build error partway
        /// through a stage.
        fail_save: bool,
        /// when `fail_save` also sets this, the synthetic failure wraps an `io::Error` of
        /// this kind instead of a plain string — standing in for an environmental error
        /// (e.g. `StorageFull`) instead of a genuine content/build one.
        fail_save_io_kind: Option<std::io::ErrorKind>,
        /// captured via `set_cancel`, exactly like the real backend — `cancel_after_run`
        /// uses it to simulate a sibling stage failing while this one is still mid-flight.
        cancel: Option<CancellationToken>,
        /// if true, a successful `run` cancels the captured token as a side effect, so the
        /// *next* step's between-steps check sees a cascaded cancellation.
        cancel_after_run: bool,
    }

    impl Executor for CachedDry {
        fn from_image(&mut self, stage: &str, image: &str) -> Result<Rootfs> {
            self.inner.from_image(stage, image)
        }
        fn from_scratch(&mut self, stage: &str) -> Result<Rootfs> {
            self.inner.from_scratch(stage)
        }
        fn from_stage(&mut self, stage: &str, parent: &Rootfs) -> Result<Rootfs> {
            self.inner.from_stage(stage, parent)
        }
        fn pull(&mut self, image: &str) -> Result<Rootfs> {
            self.inner.pull(image)
        }
        fn run(
            &mut self,
            fs: &Rootfs,
            cmd: &parser::Cmdline,
            mounts: &[ResolvedMount<'_>],
            state: &ShellState,
        ) -> Result<()> {
            let r = self.inner.run(fs, cmd, mounts, state);
            if r.is_ok()
                && self.cancel_after_run
                && let Some(c) = &self.cancel
            {
                c.cancel();
            }
            r
        }
        fn set_cancel(&mut self, cancel: CancellationToken) {
            self.cancel = Some(cancel);
        }
        fn copy(
            &mut self,
            fs: &Rootfs,
            op: &parser::Copy,
            from: Option<&Rootfs>,
            workdir: &str,
        ) -> Result<()> {
            self.inner.copy(fs, op, from, workdir)
        }
        fn export_ext4(&mut self, fs: &Rootfs, out: &Path) -> Result<()> {
            self.inner.export_ext4(fs, out)
        }
        fn cache_has(&mut self, key: &str) -> bool {
            let hit = self.cache.contains(key);
            self.inner
                .transcript
                .push(format!("cache-has {key} -> {hit}"));
            hit
        }
        fn cache_restore(&mut self, fs: &Rootfs, key: &str) -> Result<()> {
            self.inner
                .transcript
                .push(format!("cache-restore {} <- {key}", fs.label));
            Ok(())
        }
        fn cache_save(&mut self, _fs: &Rootfs, key: &str) -> Result<()> {
            if self.fail_save {
                if let Some(kind) = self.fail_save_io_kind {
                    return Err(std::io::Error::from(kind)).context("synthetic cache_save failure");
                }
                bail!("synthetic cache_save failure");
            }
            self.inner.transcript.push(format!("cache-save {key}"));
            self.cache.insert(key.to_string());
            self.last_saved = Some(key.to_string());
            Ok(())
        }
        fn stage_end(&mut self, fs: &Rootfs, final_key: Option<&str>) -> Result<()> {
            self.inner.transcript.push(format!(
                "stage-end {} key={}",
                fs.label,
                final_key.unwrap_or("-")
            ));
            Ok(())
        }
        fn check_build_failure(&mut self, _key: &str) -> Option<vk_registry::FailInfo> {
            self.fail_check.clone()
        }
        fn report_build_failure(&mut self, key: &str, reason: &str) {
            self.fail_reports
                .push((key.to_string(), reason.to_string()));
        }
    }

    /// Every `stage_end` is handed the key of that stage's own last cache push. The microVM
    /// backend re-pushes exactly that key from the finished image, so a key belonging to another
    /// stage — or one no step ever pushed — would publish this stage's bytes where they do not
    /// belong.
    #[test]
    fn stage_end_receives_the_stage_final_key() {
        let src =
            "FROM alpine AS builder\nRUN one\n\nFROM alpine\nCOPY --from=builder /a /a\nRUN two\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(None).unwrap();
        let order = plan.build_order(t).unwrap();
        let mut ex = CachedDry::default();
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        let mut last_save: Option<&str> = None;
        let mut ends = 0;
        for line in &ex.inner.transcript {
            if let Some(k) = line.strip_prefix("cache-save ") {
                last_save = Some(k);
            }
            if let Some(rest) = line.strip_prefix("stage-end ") {
                let key = rest.split_once("key=").unwrap().1;
                assert_eq!(
                    Some(key),
                    last_save,
                    "stage_end got {key}, not this stage's last pushed key"
                );
                ends += 1;
            }
        }
        assert_eq!(ends, 2, "one stage_end per stage");
    }

    #[test]
    fn fully_cached_build_restores_final_snapshot_only() {
        let src = "FROM alpine AS builder\nRUN one\n\nFROM alpine\nRUN two\nRUN three\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(None).unwrap();
        let order = plan.build_order(t).unwrap();
        // cold: everything runs and populates the cache
        let mut ex = CachedDry::default();
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        assert!(ex.inner.transcript.iter().any(|l| l.starts_with("run ")));
        // warm: one probe of the target's final key, one restore — no per-step
        // probes, nothing built, the builder stage never touched
        let mut ex = CachedDry {
            inner: DryRun::new(),
            cache: ex.cache,
            last_saved: None,
            ..Default::default()
        };
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        let t = &ex.inner.transcript;
        assert_eq!(t.len(), 3, "{t:?}");
        assert!(
            t[0].starts_with("cache-has ") && t[0].ends_with("-> true"),
            "{t:?}"
        );
        assert!(t[1].starts_with("cache-restore "), "{t:?}");
        // The restore still ends the stage, under the very key it restored: that is the key the
        // microVM backend would re-push from, and a restore ships its snapshot verbatim.
        let key = t[0]
            .strip_prefix("cache-has ")
            .and_then(|l| l.split_whitespace().next())
            .unwrap();
        assert_eq!(t[2], format!("stage-end stage1 key={key}"), "{t:?}");
    }

    #[test]
    fn require_cached_refuses_cold_and_allows_warm() {
        let src = "FROM alpine AS builder\nRUN one\n\nFROM alpine\nRUN two\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(None).unwrap();
        let order = plan.build_order(t).unwrap();
        // cold cache: refused with the typed error, before anything runs; the
        // unnamed final stage reports its `stage{i}` fallback name
        let mut ex = CachedDry::default();
        let err = drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            true,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap_err();
        let nc = err.downcast_ref::<NotCached>().expect("typed NotCached");
        assert_eq!(nc.stages, vec!["stage1".to_string()]);
        assert!(
            !ex.inner.transcript.iter().any(|l| l.starts_with("run ")),
            "{:?}",
            ex.inner.transcript
        );
        // a named uncached stage reports its real `AS` name, not the fallback
        let named = plan_one("FROM alpine AS app\nRUN build\n", &ba);
        let norder = named
            .build_order(named.resolve_target(None).unwrap())
            .unwrap();
        let err = drive(
            &named,
            &norder,
            &ba,
            &mut CachedDry::default(),
            true,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<NotCached>()
                .expect("typed NotCached")
                .stages,
            vec!["app".to_string()]
        );
        // populated cache: the same require-cached drive restores, builds nothing
        let mut ex = CachedDry::default();
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        let mut ex = CachedDry {
            inner: DryRun::new(),
            cache: ex.cache,
            last_saved: None,
            ..Default::default()
        };
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            true,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        let t = &ex.inner.transcript;
        assert!(t.iter().any(|l| l.starts_with("cache-restore ")), "{t:?}");
        assert!(!t.iter().any(|l| l.starts_with("run ")), "{t:?}");
    }

    #[test]
    fn partially_cached_build_fast_paths_cached_stages() {
        let src = "FROM alpine AS builder\nRUN one\nRUN two\n\n\
                   FROM alpine\nRUN three\nCOPY --from=builder /a /b\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(None).unwrap();
        let order = plan.build_order(t).unwrap();
        // cold run populates the cache; evict the target's final key so only the
        // target's last instruction must re-run
        let mut ex = CachedDry::default();
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        let mut cache = ex.cache;
        cache.remove(&ex.last_saved.unwrap());
        let mut ex = CachedDry {
            inner: DryRun::new(),
            cache,
            last_saved: None,
            ..Default::default()
        };
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        let t = &ex.inner.transcript;
        let count = |p: &str| t.iter().filter(|l| l.starts_with(p)).count();
        // probes: the target's last key (miss), the builder's last key (hit), then the
        // target per-step (hit, miss) — the builder's per-step keys are never probed
        assert_eq!(count("cache-has "), 4, "{t:?}");
        // restores: the builder's final snapshot + the target's cached prefix
        assert_eq!(count("cache-restore "), 2, "{t:?}");
        // only the evicted COPY re-runs; no RUN and no base pull anywhere
        assert_eq!(count("copy "), 1, "{t:?}");
        assert_eq!(count("run "), 0, "{t:?}");
        assert_eq!(count("from-image "), 0, "{t:?}");
    }

    /// The `--build-cache` modes differ only in which snapshots a cold build pushes:
    /// `layers` and (with instant DryRun steps, below the checkpoint) `auto` commit one
    /// snapshot per stage — its final step — while `instructions` commits every step.
    /// `layers` additionally skips the per-step prefix probe. Two stages of two steps
    /// each (the target `COPY --from` pulls the builder in), so a full-instruction build
    /// commits 4 snapshots and a stage-level build 2.
    #[test]
    fn build_cache_modes_control_which_snapshots_are_pushed() {
        let src = "FROM alpine AS builder\nRUN one\nRUN two\n\n\
                   FROM alpine\nRUN three\nCOPY --from=builder /a /b\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let order = plan
            .build_order(plan.resolve_target(None).unwrap())
            .unwrap();
        let cold = |mode| {
            let mut ex = CachedDry::default();
            drive(
                &plan,
                &order,
                &ba,
                &mut ex,
                false,
                mode,
                &Progress::disabled(),
                &Arc::new(Timings::new()),
            )
            .unwrap();
            let t = &ex.inner.transcript;
            let count = |p: &str| t.iter().filter(|l| l.starts_with(p)).count();
            (
                count("cache-save "),
                count("cache-has "),
                count("run ") + count("copy "),
            )
        };
        // every mode runs all four steps; they diverge only in commits (and, for
        // `layers`, in probes: no per-step `cache_has`, just the two stage-final probes).
        assert_eq!(cold(BuildCache::Instructions), (4, 4, 4));
        assert_eq!(cold(BuildCache::Auto), (2, 4, 4));
        assert_eq!(cold(BuildCache::Layers), (2, 2, 4));

        // Forcing the checkpoint to 0 makes `auto` cross the threshold on every step, so it
        // commits all four like `instructions` — exercising the upper `uncommitted >=
        // checkpoint` branch. The override is thread-local, so `cold` (which drives the build
        // synchronously on this thread) sees it while other tests are unaffected.
        CHECKPOINT_OVERRIDE.with(|c| c.set(Some(0)));
        let auto_zero = cold(BuildCache::Auto);
        CHECKPOINT_OVERRIDE.with(|c| c.set(None));
        assert_eq!(auto_zero, (4, 4, 4));
    }

    /// A build whose target is fully cached restores its final snapshot in every mode —
    /// each mode's cold run commits the target's last step, so the warm rebuild takes the
    /// fully-cached fast path (one probe, one restore, nothing runs) regardless.
    #[test]
    fn every_mode_restores_a_fully_cached_target() {
        let src = "FROM alpine\nRUN one\nRUN two\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let order = plan
            .build_order(plan.resolve_target(None).unwrap())
            .unwrap();
        for mode in [
            BuildCache::Auto,
            BuildCache::Layers,
            BuildCache::Instructions,
        ] {
            let mut cold = CachedDry::default();
            drive(
                &plan,
                &order,
                &ba,
                &mut cold,
                false,
                mode,
                &Progress::disabled(),
                &Arc::new(Timings::new()),
            )
            .unwrap();
            let mut warm = CachedDry {
                inner: DryRun::new(),
                cache: cold.cache,
                last_saved: None,
                ..Default::default()
            };
            drive(
                &plan,
                &order,
                &ba,
                &mut warm,
                false,
                mode,
                &Progress::disabled(),
                &Arc::new(Timings::new()),
            )
            .unwrap();
            let t = &warm.inner.transcript;
            assert!(!t.iter().any(|l| l.starts_with("run ")), "{mode:?}: {t:?}");
            assert!(
                t.iter().any(|l| l.starts_with("cache-restore ")),
                "{mode:?}: {t:?}"
            );
        }
    }

    #[test]
    fn cache_repo_resolution() {
        assert_eq!(cache_repo(Some("none")).unwrap(), None);
        assert_eq!(
            cache_repo(Some("127.0.0.1:5000")).unwrap().as_deref(),
            Some("127.0.0.1:5000")
        );
        // The default must be an absolute path so Registry::local_root treats it
        // as an in-process store rather than a registry host.
        let default = cache_repo(None).unwrap().unwrap();
        assert!(default.starts_with('/'), "not absolute: {default}");
        // A relative path would be misread as a registry host; refuse it.
        assert!(cache_repo(Some("./cache")).is_err());
    }

    // Where `vk registry status`/`gc` and `vk paths` look when no `--root` says otherwise:
    // the store the configured cache uses, not the builtin default it was pointed away
    // from. A cache on a `vk-registry` server has no store here, and is reported as the
    // server it is rather than as a failure to resolve one.
    #[test]
    fn cache_store_follows_the_configured_cache() {
        let default = CacheStore::Dir(vk_registry::default_root().unwrap());
        assert_eq!(cache_store(None).unwrap(), default);
        assert_eq!(
            cache_store(Some("/srv/vk-cache")).unwrap(),
            CacheStore::Dir(PathBuf::from("/srv/vk-cache"))
        );
        assert_eq!(
            cache_store(Some("file:///srv/vk-cache")).unwrap(),
            CacheStore::Dir(PathBuf::from("/srv/vk-cache"))
        );
        // caching off: nothing names a store, so the builtin one — where anything cached
        // before it was turned off still is — is what gets reported.
        assert_eq!(cache_store(Some("none")).unwrap(), default);
        // a server: its store is on that host, which is the answer rather than an error
        assert_eq!(
            cache_store(Some("127.0.0.1:5000")).unwrap(),
            CacheStore::Server("127.0.0.1:5000".to_string())
        );
        // and a setting that names no store at all stays an error, not a phantom server or
        // a store at a path relative to wherever `vk` was run from
        assert!(cache_store(Some("./cache")).is_err());
        assert!(cache_store(Some("")).is_err());
        assert!(cache_store(Some("  ")).is_err());
        assert!(cache_store(Some("file://")).is_err());
        assert!(cache_store(Some("file://srv/vk-cache")).is_err());
    }

    #[test]
    fn expose_ports_keeps_tcp_only_and_expands_ranges() {
        // Docker's own spellings, since a Dockerfile in the wild uses all of them.
        assert_eq!(exposed_tcp_ports("8080"), [8080]);
        assert_eq!(exposed_tcp_ports("8080/tcp"), [8080]);
        // docker lower-cases the protocol before it looks, so this is tcp — dropping it would
        // leave the service gating on nothing.
        assert_eq!(exposed_tcp_ports("8080/TCP"), [8080]);
        assert_eq!(exposed_tcp_ports("8080/"), [8080]);
        assert!(exposed_tcp_ports("53/udp").is_empty());
        assert_eq!(exposed_tcp_ports("80 443"), [80, 443]);
        assert_eq!(exposed_tcp_ports("9000-9002"), [9000, 9001, 9002]);
        assert!(exposed_tcp_ports("9000-9002/udp").is_empty());
        // an inverted range, junk, and a number no port can hold are ignored rather than
        // failing a build that used to work; port 0 would make the guest's gate wait forever.
        assert!(exposed_tcp_ports("9-7").is_empty());
        assert!(exposed_tcp_ports("nope").is_empty());
        assert!(exposed_tcp_ports("70000").is_empty());
        assert!(exposed_tcp_ports("0").is_empty());
        assert_eq!(exposed_tcp_ports("0-2"), [1, 2]);
    }

    #[test]
    fn expose_folds_into_the_exported_runtime_config() {
        // A pulled image's ports come from its OCI config; a built one's can only come from
        // EXPOSE, and without them a service built from a Dockerfile counts as ready the moment
        // its guest boots rather than when it is listening.
        let expose = |args: &str| Instruction::Other {
            name: "EXPOSE".into(),
            args: args.into(),
        };
        let mut st = ShellState::default();
        apply_meta(&mut st, &expose("8080"));
        apply_meta(&mut st, &expose("443/tcp 53/udp"));
        apply_meta(&mut st, &expose("9000-9002"));
        apply_meta(&mut st, &expose("8080")); // a repeat is not a second port
        apply_meta(
            &mut st,
            &Instruction::Other {
                name: "STOPSIGNAL".into(),
                args: "SIGTERM".into(),
            },
        );
        assert_eq!(run_config(&st).exposed_ports, [443, 8080, 9000, 9001, 9002]);

        // A base image's own ports are inherited, not replaced.
        let mut inherited = ShellState {
            exposed_ports: vec![5432],
            ..Default::default()
        };
        apply_meta(&mut inherited, &expose("6379"));
        assert_eq!(run_config(&inherited).exposed_ports, [5432, 6379]);
    }

    #[test]
    fn canonical_is_explicit_and_stable() {
        use parser::{Cmdline, Mount, Run};
        let run = |s: &str| {
            Instruction::Run(Run {
                cmd: Cmdline::Shell(s.into()),
                mounts: vec![],
                network: None,
                security: None,
            })
        };
        // an explicit, deliberate string (not the Debug repr)
        assert_eq!(
            canonical(&run("make")),
            "RUN\u{1f}shell\u{1f}make\u{1f}net=\u{1f}sec=\u{1f}mounts="
        );
        // content-sensitive and stable; distinct instruction kinds differ
        assert_ne!(canonical(&run("make")), canonical(&run("make test")));
        assert_ne!(
            canonical(&Instruction::Workdir("/a".into())),
            canonical(&Instruction::User("/a".into()))
        );
        // every scratch-mount option participates in the key, so two RUNs differing only in
        // rw/uid/gid/mode do not collide (and thus never reuse each other's cached snapshot).
        let run_mount = |m: Mount| {
            Instruction::Run(Run {
                cmd: Cmdline::Shell("build".into()),
                mounts: vec![m],
                network: None,
                security: None,
            })
        };
        let scratch = || Mount {
            typ: "bind".into(),
            from: Some("scratch".into()),
            target: Some("/s".into()),
            ..Mount::default()
        };
        let base = run_mount(scratch());
        assert_ne!(
            canonical(&base),
            canonical(&run_mount(Mount {
                rw: true,
                ..scratch()
            }))
        );
        assert_ne!(
            canonical(&base),
            canonical(&run_mount(Mount {
                uid: Some("1000".into()),
                ..scratch()
            }))
        );
        assert_ne!(
            canonical(&base),
            canonical(&run_mount(Mount {
                gid: Some("1000".into()),
                ..scratch()
            }))
        );
        assert_ne!(
            canonical(&base),
            canonical(&run_mount(Mount {
                mode: Some("0700".into()),
                ..scratch()
            }))
        );
    }

    #[test]
    fn context_files_hash_tracks_content_and_dockerignore() {
        let dir = tmpdir("copyhash");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/a.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("README.md"), "hi").unwrap();
        std::fs::write(dir.join(".dockerignore"), "*.md\n").unwrap();
        let srcs = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let h1 = context_files_hash(&dir, &srcs(&["."]));
        // editing a copied source changes the hash
        std::fs::write(dir.join("src/a.rs"), "fn main() { /* x */ }").unwrap();
        assert_ne!(h1, context_files_hash(&dir, &srcs(&["."])));
        // editing a .dockerignore'd file does NOT change the hash
        let before = context_files_hash(&dir, &srcs(&["."]));
        std::fs::write(dir.join("README.md"), "changed").unwrap();
        assert_eq!(before, context_files_hash(&dir, &srcs(&["."])));
        // a glob source matches by segment (src/*.rs covers a.rs)
        assert_eq!(
            context_files_hash(&dir, &srcs(&["src/*.rs"])),
            context_files_hash(&dir, &srcs(&["src/a.rs"]))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_keys_hash_the_stage_context() {
        // A context COPY's content hash reads the *stage's* recorded context — and the
        // context path itself never enters the key (same content in two places, same key).
        let tmp = tmpdir("stagectx");
        for d in ["a", "b", "c"] {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        std::fs::write(tmp.join("a/f.txt"), "one").unwrap();
        std::fs::write(tmp.join("b/f.txt"), "two").unwrap();
        std::fs::write(tmp.join("c/f.txt"), "one").unwrap(); // same content as a/
        let ba = Vars::new();
        let key = |ctx: &Path| {
            let plan = Plan::from_dockerfiles(
                &[PlanInput {
                    dockerfile: parser::parse("FROM scratch\nCOPY f.txt /f\n").unwrap(),
                    origin: "Dockerfile".into(),
                    context: ctx.to_path_buf(),
                }],
                &ba,
            )
            .unwrap();
            assert_eq!(plan.stages[0].context, ctx);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap()[&0]
                .final_key
                .clone()
        };
        let (a, b, c) = (tmp.join("a"), tmp.join("b"), tmp.join("c"));
        assert_ne!(key(&a), key(&b)); // different content -> different key
        assert_eq!(key(&a), key(&c)); // same content elsewhere -> same key
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The key `target_stage_key` computes must carry the named contexts it is given — this is
    /// what lets drift detection notice a file changing inside one. Without them threaded
    /// through, a `vk run` would recompute a key that never matches the one its build stamped.
    #[test]
    fn target_stage_key_tracks_a_named_context_file() {
        let tmp = tmpdir("ctxdrift");
        std::fs::create_dir_all(tmp.join("ctx")).unwrap();
        std::fs::create_dir_all(tmp.join("extra")).unwrap();
        std::fs::write(tmp.join("extra/setup.sh"), "one").unwrap();
        // `FROM scratch` so nothing is resolved over the network.
        let df = tmp.join("ctx/Dockerfile");
        std::fs::write(&df, "FROM scratch\nCOPY --from=extra setup.sh /setup.sh\n").unwrap();
        let named = vec![("extra".to_string(), tmp.join("extra"))];
        let key = || {
            target_stage_key(
                std::slice::from_ref(&df),
                &[tmp.join("ctx")],
                &named,
                &[],
                None,
            )
            .unwrap()
        };
        let before = key();
        std::fs::write(tmp.join("extra/setup.sh"), "two").unwrap();
        assert_ne!(before, key(), "an edit in the named context must be drift");
        // (That an *undeclared* name keys differently is covered by
        // `named_context_copy_keys_on_the_referenced_files`, which needs no registry:
        // resolving the ref as an image here would reach one.)
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn named_context_copy_keys_on_the_referenced_files() {
        // A COPY --from=<named context> reads a directory outside the stage's own context, so
        // that directory's content must enter the key — and a stage of the same name must keep
        // winning it, on the key path as well as the resolution path.
        let tmp = tmpdir("ctxkey");
        std::fs::create_dir_all(tmp.join("ctx")).unwrap();
        std::fs::create_dir_all(tmp.join("extra")).unwrap();
        std::fs::write(tmp.join("extra/setup.sh"), "one").unwrap();
        let ba = Vars::new();
        let key = |src: &str, declared: bool| {
            let mut plan = Plan::from_dockerfiles(
                &[PlanInput {
                    dockerfile: parser::parse(src).unwrap(),
                    origin: "Dockerfile".into(),
                    context: tmp.join("ctx"),
                }],
                &ba,
            )
            .unwrap();
            if declared {
                plan.named_contexts
                    .insert("shared".into(), tmp.join("extra"));
            }
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            let r = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
            r[order.last().unwrap()].final_key.clone()
        };
        let df = "FROM scratch\nCOPY --from=shared setup.sh /setup.sh\n";
        let before = key(df, true);
        // editing the referenced file busts the key...
        std::fs::write(tmp.join("extra/setup.sh"), "two").unwrap();
        let after = key(df, true);
        assert_ne!(
            before, after,
            "an edit to the copied file must bust the key"
        );
        // ...while an unreferenced file in the same directory does not.
        std::fs::write(tmp.join("extra/unused.txt"), "x").unwrap();
        assert_eq!(after, key(df, true), "only the referenced files are keyed");
        // Declaring the context is what makes it a context: undeclared, the ref keys as an image.
        assert_ne!(after, key(df, false));
        // A stage of the same name wins, declared context or not — the key follows what the
        // build actually reads.
        let shadow =
            "FROM scratch AS shared\nFROM scratch\nCOPY --from=shared setup.sh /setup.sh\n";
        assert_eq!(
            key(shadow, true),
            key(shadow, false),
            "a stage of that name must not be keyed on the context's files"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn run_bind_mount_keys_the_mounted_context_file() {
        // A `RUN --mount=type=bind` reads a file from the context but never copies it, so
        // its content must still enter the key — editing the mounted script busts the cache.
        // A `--mount=type=cache`, by contrast, reads no context bytes and must not.
        let tmp = tmpdir("runbind");
        std::fs::write(tmp.join("setup.sh"), "echo one\n").unwrap();
        let ba = Vars::new();
        let key = |dockerfile: &str| {
            let plan = Plan::from_dockerfiles(
                &[PlanInput {
                    dockerfile: parser::parse(dockerfile).unwrap(),
                    origin: "Dockerfile".into(),
                    context: tmp.clone(),
                }],
                &ba,
            )
            .unwrap();
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap()[&0]
                .final_key
                .clone()
        };

        // explicit source: editing the mounted script busts the key
        let explicit =
            "FROM scratch\nRUN --mount=type=bind,source=/setup.sh,target=/setup.sh /setup.sh\n";
        let before = key(explicit);
        // default source (whole context): editing a context file also busts the key
        let defaulted = "FROM scratch\nRUN --mount=type=bind,target=/ctx /ctx/setup.sh\n";
        let before_default = key(defaulted);
        // cache mount reads no context bytes, so its key must not track context content
        let cached = "FROM scratch\nRUN --mount=type=cache,target=/c echo hi\n";
        let before_cache = key(cached);

        std::fs::write(tmp.join("setup.sh"), "echo two\n").unwrap();
        assert_ne!(
            before,
            key(explicit),
            "editing a bind-mounted script must bust the cache"
        );
        assert_ne!(
            before_default,
            key(defaulted),
            "editing a context file must bust a default-source bind mount's key"
        );
        assert_eq!(
            before_cache,
            key(cached),
            "a cache mount reads no context bytes, so its key must not change"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn drive_declares_each_stage_context() {
        let t = transcript("FROM scratch AS s\nCOPY f /f\n", None);
        assert!(
            t.contains(&"stage-context /nonexistent".to_string()),
            "{t:#?}"
        );
    }

    #[test]
    fn default_context_defaults_bare_dockerfile_to_dot() {
        // `-f Dockerfile`: `parent()` is `Some("")`, which must fall back to `.` — not the
        // empty path, which resolves to nothing and serves no files into the guest.
        assert_eq!(default_context(Path::new("Dockerfile")), PathBuf::from("."));
        // A nested relative path keeps its directory as the context.
        assert_eq!(
            default_context(Path::new("sub/dir/Dockerfile")),
            PathBuf::from("sub/dir")
        );
        // An absolute path keeps its parent directory.
        assert_eq!(
            default_context(Path::new("/abs/dir/Dockerfile")),
            PathBuf::from("/abs/dir")
        );
    }

    #[test]
    fn load_inputs_zips_contexts_with_files() {
        let tmp = tmpdir("loadinputs");
        std::fs::create_dir_all(tmp.join("a")).unwrap();
        std::fs::create_dir_all(tmp.join("b")).unwrap();
        std::fs::write(tmp.join("a/Dockerfile"), "FROM scratch AS x\n").unwrap();
        std::fs::write(tmp.join("b/Dockerfile"), "FROM scratch AS y\n").unwrap();
        let files = [tmp.join("a/Dockerfile"), tmp.join("b/Dockerfile")];

        // no --context: each file defaults to its own directory.
        let inputs = load_inputs(&files, &[]).unwrap();
        assert_eq!(inputs[0].context, tmp.join("a"));
        assert_eq!(inputs[1].context, tmp.join("b"));
        // one --context: pairs with the first file, the second keeps its default.
        let inputs = load_inputs(&files, std::slice::from_ref(&tmp)).unwrap();
        assert_eq!(inputs[0].context, tmp);
        assert_eq!(inputs[1].context, tmp.join("b"));
        // more contexts than files / no files: errors.
        let err = load_inputs(&files[..1], &[tmp.clone(), tmp.clone()]).unwrap_err();
        assert!(format!("{err:#}").contains("zip positionally"), "{err:#}");
        assert!(load_inputs(&[], &[]).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_net_from_flags() {
        assert_eq!(
            BuildNet::from_flags("all", &[], &[]).unwrap(),
            BuildNet::All
        );
        assert_eq!(
            BuildNet::from_flags("none", &[], &[]).unwrap(),
            BuildNet::None
        );
        let ips = vec!["10.0.0.0/8:443".to_string()];
        let names = vec!["crates.io".to_string()];
        assert_eq!(
            BuildNet::from_flags("all", &ips, &names).unwrap(),
            BuildNet::Allow {
                ips: ips.clone(),
                names: names.clone()
            }
        );
        // `none` + an allowlist is contradictory; bad values fail before any build work.
        assert!(BuildNet::from_flags("none", &ips, &[]).is_err());
        assert!(BuildNet::from_flags("all", &["not-a-cidr".into()], &[]).is_err());
        assert!(BuildNet::from_flags("half", &[], &[]).is_err());
    }

    #[test]
    fn cross_file_build_uses_each_files_context() {
        // Two files, two contexts: the merged build hashes each stage's COPY against
        // its own file's context, and editing one context busts only that stage's key
        // (and its dependents' — the chain), not the other file's.
        let tmp = tmpdir("crossctx");
        for d in ["a", "b"] {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        std::fs::write(tmp.join("a/Dockerfile"), "FROM scratch AS lib\nCOPY f /f\n").unwrap();
        std::fs::write(tmp.join("a/f"), "lib-v1").unwrap();
        std::fs::write(
            tmp.join("b/Dockerfile"),
            "FROM scratch AS app\nCOPY --from=lib /f /lib-f\nCOPY f /app-f\n",
        )
        .unwrap();
        std::fs::write(tmp.join("b/f"), "app-v1").unwrap();
        let files = [tmp.join("a/Dockerfile"), tmp.join("b/Dockerfile")];

        let keys = || {
            let m: HashMap<String, String> = stage_keys(&files, &[], &[], &[])
                .unwrap()
                .into_iter()
                .collect();
            (m["lib"].clone(), m["app"].clone())
        };
        let (lib1, app1) = keys();
        // editing file a's context changes lib's key, and chains into app (which
        // COPY --froms it) …
        std::fs::write(tmp.join("a/f"), "lib-v2").unwrap();
        let (lib2, app2) = keys();
        assert_ne!(lib1, lib2);
        assert_ne!(app1, app2);
        // … while editing file b's context touches only app.
        std::fs::write(tmp.join("b/f"), "app-v2").unwrap();
        let (lib3, app3) = keys();
        assert_eq!(lib2, lib3);
        assert_ne!(app2, app3);

        // the drive declares each stage's own context to the backend.
        let ba = Vars::new();
        let plan = Plan::from_dockerfiles(&load_inputs(&files, &[]).unwrap(), &ba).unwrap();
        let order = plan
            .build_order(plan.resolve_target(Some("app")).unwrap())
            .unwrap();
        let mut ex = DryRun::new();
        drive(
            &plan,
            &order,
            &ba,
            &mut ex,
            false,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
        )
        .unwrap();
        let t = ex.transcript;
        assert!(
            t.contains(&format!("stage-context {}", tmp.join("a").display())),
            "{t:#?}"
        );
        assert!(
            t.contains(&format!("stage-context {}", tmp.join("b").display())),
            "{t:#?}"
        );
        assert!(t.iter().any(|l| l.starts_with("copy from=lib ")), "{t:#?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn end_to_end_multistage_drive() {
        let src = "\
FROM debian:bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y gcc
COPY . .
RUN make

FROM debian:bookworm AS final
USER app
COPY --from=build /src/out /usr/bin/out
RUN --mount=type=bind,from=build,source=/src,target=/s /usr/bin/out --selftest
";
        let t = transcript(src, Some("final"));
        // stage 'build' is based on an image; its working rootfs is labelled 'build'.
        assert!(
            t.contains(&"from-image build (debian:bookworm)".to_string()),
            "{t:#?}"
        );
        assert!(
            t.iter()
                .any(|l| l.starts_with("run [user=root cwd=/src") && l.contains("apt-get update"))
        );
        assert!(
            t.iter()
                .any(|l| l.starts_with("copy from=context") && l.contains("\".\""))
        );
        // final stage: COPY --from=build resolves to the build stage's rootfs (label
        // 'build'), and the RUN runs as the USER with the bind mount from that stage.
        assert!(
            t.iter()
                .any(|l| l.starts_with("copy from=build ") && l.contains("/usr/bin/out")),
            "COPY --from=build should resolve to the build stage:\n{t:#?}"
        );
        assert!(
            t.iter()
                .any(|l| l.starts_with("run [user=app") && l.contains("mounts_from=[\"build\"]")),
            "final RUN should run as 'app' with a bind mount from the build stage:\n{t:#?}"
        );
    }

    /// A [`DryRun`] that answers the base-digest lookup, standing in for a registry that
    /// replied — `DryRun` itself takes the trait default (`None`, i.e. "resolve failed").
    /// Forwards `DryRun`'s required primitives (none of which `resolve_stages` calls);
    /// `context_source`/`stage_sources` are left on the trait default, so a test that drives a
    /// whole build wants those forwarded too.
    struct Answered {
        inner: DryRun,
        digest: Option<String>,
    }

    impl Executor for Answered {
        fn resolve_base_digest(&mut self, _image: &str) -> Option<String> {
            self.digest.clone()
        }
        fn from_image(&mut self, stage: &str, image: &str) -> Result<Rootfs> {
            self.inner.from_image(stage, image)
        }
        fn from_scratch(&mut self, stage: &str) -> Result<Rootfs> {
            self.inner.from_scratch(stage)
        }
        fn from_stage(&mut self, stage: &str, parent: &Rootfs) -> Result<Rootfs> {
            self.inner.from_stage(stage, parent)
        }
        fn pull(&mut self, image: &str) -> Result<Rootfs> {
            self.inner.pull(image)
        }
        fn copy(
            &mut self,
            fs: &Rootfs,
            op: &parser::Copy,
            from: Option<&Rootfs>,
            workdir: &str,
        ) -> Result<()> {
            self.inner.copy(fs, op, from, workdir)
        }
        fn run(
            &mut self,
            fs: &Rootfs,
            cmd: &parser::Cmdline,
            mounts: &[ResolvedMount<'_>],
            state: &ShellState,
        ) -> Result<()> {
            self.inner.run(fs, cmd, mounts, state)
        }
        fn export_ext4(&mut self, fs: &Rootfs, out: &Path) -> Result<()> {
            self.inner.export_ext4(fs, out)
        }
    }

    #[test]
    fn a_base_digest_that_does_not_resolve_changes_the_stage_key() {
        // The stage key is NOT a function of the sources alone: a `FROM <image>` folds in the
        // base's resolved manifest digest, and keys by the bare ref when that lookup fails.
        // For a tag-pinned base the lookup is a live anonymous registry request every time
        // (`oci::resolve_digest`), so the same sources key two ways depending on whether the
        // registry answered. Anything addressing a tier entry another process built must ask
        // its build where it went rather than recompute this: one rate-limited request is
        // enough to name an entry that process never wrote (see `vm::plan_services`).
        let ba = Vars::new();
        let key = |digest: Option<&str>| {
            let plan = plan_one("FROM debian:bookworm\nRUN a\n", &ba);
            let order = plan.all_order().unwrap();
            let mut ex = Answered {
                inner: DryRun::new(),
                digest: digest.map(str::to_string),
            };
            resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap()[&0]
                .final_key
                .clone()
        };
        let resolved = key(Some("sha256:aa"));
        assert_ne!(
            resolved,
            key(None),
            "a failed digest lookup must be visible in the key — it is why the key cannot be \
             recomputed in another process"
        );
        // And it is the digest that carries, not merely "some digest": a moved tag re-keys.
        assert_ne!(resolved, key(Some("sha256:bb")));
    }

    #[test]
    fn resolve_stages_keys_are_stable_and_chained() {
        let src = "\
FROM debian:bookworm AS build
ENV V=1
RUN make $V
FROM build AS final
RUN ship
";
        let ba = Vars::new();
        let resolve = |source: &str| {
            let plan = plan_one(source, &ba);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap()
        };
        let r = resolve(src);
        // every stage key is a `snap-` key (its shape is
        // `every_key_names_its_namespace`'s subject), and the computation is deterministic.
        let r_again = resolve(src);
        for i in [0usize, 1] {
            let key = &r[&i].final_key;
            assert!(key.starts_with("snap-"), "{key}");
            assert_eq!(*key, r_again[&i].final_key);
        }
        // a `FROM <stage>` child continues a distinct chain from its parent.
        assert_ne!(r[&0].final_key, r[&1].final_key);
        // the build stage ends on a RUN, so its identity is that last step's key.
        assert_eq!(r[&0].final_key, r[&0].steps.last().unwrap().key);
        // a RUN command is left raw for the guest shell (`$V` resolves there against the
        // exported ENV), not textually substituted at plan time.
        assert!(matches!(
            &r[&0].steps.last().unwrap().instr,
            Instruction::Run(run) if matches!(&run.cmd, parser::Cmdline::Shell(s) if s == "make $V")
        ));
        // editing an upstream ENV busts the upstream key and chains through to the
        // dependent stage's key.
        let r2 = resolve(&src.replace("ENV V=1", "ENV V=2"));
        assert_ne!(r[&0].final_key, r2[&0].final_key);
        assert_ne!(r[&1].final_key, r2[&1].final_key);
    }

    #[test]
    fn source_stage_changes_chain_into_consumers() {
        // A consumer restoring its cached snapshot must re-key whenever a stage it
        // copies/mounts from changed — else it would restore the old source content.
        let ba = Vars::new();
        let keys = |src: &str| {
            let plan = plan_one(src, &ba);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            let r = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
            (r[&0].final_key.clone(), r[&1].final_key.clone())
        };
        // COPY --from=<stage>
        let a = "FROM alpine AS lib\nRUN one\nFROM alpine AS app\nCOPY --from=lib /f /f\n";
        let (lib1, app1) = keys(a);
        let (lib2, app2) = keys(&a.replace("RUN one", "RUN two"));
        assert_ne!(lib1, lib2);
        assert_ne!(app1, app2);
        // RUN --mount=from=<stage>
        let a = "FROM alpine AS lib\nRUN one\nFROM alpine AS app\n\
                 RUN --mount=type=bind,from=lib,target=/l use\n";
        let (lib1, app1) = keys(a);
        let (lib2, app2) = keys(&a.replace("RUN one", "RUN two"));
        assert_ne!(lib1, lib2);
        assert_ne!(app1, app2);
        // a COPY --from=<external image> folds in that image's identity, not a stage's, so the
        // consumer's key is indifferent to unrelated stage edits. (No digest resolves under
        // `DryRun`, so here the identity is the ref text; a real build folds in the digest.)
        let a = "FROM alpine AS lib\nRUN one\nFROM alpine AS app\n\
                 COPY --from=busybox:latest /bin/sh /sh\n";
        let (lib1, app1) = keys(a);
        let (lib2, app2) = keys(&a.replace("RUN one", "RUN two"));
        assert_ne!(lib1, lib2);
        assert_eq!(app1, app2);
    }

    #[test]
    fn kernel_image_flag_changes_stage_key() {
        // Toggling `FROM --kernel=image` must bust the cache: a RUN can produce different
        // bytes under the image's own kernel than under the embedded build kernel.
        let ba = Vars::new();
        let key = |src: &str| {
            let plan = plan_one(src, &ba);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap()[&0]
                .final_key
                .clone()
        };
        let plain = key("FROM alpine AS x\nRUN one\n");
        let imgk = key("FROM --kernel=image alpine AS x\nRUN one\n");
        assert_ne!(plain, imgk);
    }

    #[test]
    fn runtime_config_accumulates_and_inherits_across_stages() {
        // ENTRYPOINT/CMD/ENV/USER/WORKDIR fold into the stage state, inherit through
        // FROM <stage>, and follow Docker's ENTRYPOINT-resets-CMD rule.
        let ba = Vars::new();
        let src = "\
FROM scratch AS base
ENV A=1
EXPOSE 5432
ENTRYPOINT [\"/bin/app\"]
CMD [\"--serve\"]
FROM base AS child
EXPOSE 6379
FROM base AS override
ENTRYPOINT run me
";
        let plan = plan_one(src, &ba);
        let order = plan.all_order().unwrap();
        let mut ex = DryRun::new();
        let r = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
        let base = &r[&0].final_state;
        assert_eq!(base.entrypoint, ["/bin/app"]);
        assert_eq!(base.cmd, ["--serve"]);
        assert_eq!(base.exposed_ports, [5432]);
        // ENTRYPOINT/CMD are stored verbatim (Docker image-config semantics): a
        // $VAR in them is the runtime shell's to expand — a compose environment
        // override must be able to reach it — never baked at build time.
        let p2 = plan_one(
            "FROM scratch AS s\nENV A=built\nENTRYPOINT [\"sh\", \"-c\", \"echo $A\"]\n",
            &ba,
        );
        let order2 = p2.all_order().unwrap();
        let mut ex2 = DryRun::new();
        let r2 = resolve_stages(&p2, &order2, &ba, &mut ex2, None).unwrap();
        assert_eq!(r2[&0].final_state.entrypoint, ["sh", "-c", "echo $A"]);
        // a child inherits the base's ports and adds its own, as it does the rest of the state
        let child = &r[&1].final_state;
        assert_eq!(child.entrypoint, ["/bin/app"]);
        assert_eq!(child.cmd, ["--serve"]);
        assert_eq!(child.env, [("A".to_string(), "1".to_string())]);
        assert_eq!(child.exposed_ports, [5432, 6379]);
        // and a sibling that declares none keeps just the base's
        assert_eq!(r[&2].final_state.exposed_ports, [5432]);
        // re-declaring ENTRYPOINT (shell form -> /bin/sh -c) resets the inherited CMD
        let ov = &r[&2].final_state;
        assert_eq!(ov.entrypoint, ["/bin/sh", "-c", "run me"]);
        assert!(ov.cmd.is_empty());
    }

    #[test]
    fn image_plan_input_guards_against_instruction_smuggling() {
        // a plain ref parses to a single-FROM plan
        let pi = image_plan_input("redis:7-alpine").unwrap();
        assert_eq!(pi.origin, std::path::Path::new("redis:7-alpine"));
        // anything that could smuggle a second instruction is rejected
        assert!(image_plan_input("").is_err());
        assert!(image_plan_input("redis\nRUN evil").is_err());
        assert!(image_plan_input("redis 7").is_err());
        assert!(image_plan_input("redis\t7").is_err());
    }

    #[test]
    fn build_inputs_matches_the_file_path() {
        // an in-memory plan (the synthetic FROM plan `run --compose` uses for
        // image: services) builds the same artifact the file path would.
        let tmp = tmpdir("inputs");
        std::fs::write(tmp.join("f"), "x").unwrap();
        let src = "FROM scratch\nCOPY f /f\nENTRYPOINT [\"/f\"]\n";
        std::fs::write(tmp.join("Dockerfile"), src).unwrap();
        let opts = |out: PathBuf| Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            stage_guests: Default::default(),
            contexts: vec![],
            build_contexts: Vec::new(),
            out: Some(out),
            out_disk: None,
            print_plan: false,
            cloud_hypervisor: None,
            kernel: None,
            agent: None,
            cache_registry: Some("none".into()),
            cache_insecure: false,
            cache_auth: Default::default(),
            build_cache: BuildCache::default(),
            journal: false,
            tmp_tmpfs: false,
            build_args: vec![],
            net: BuildNet::None,
            audit: false,
            require_cached: false,
            build_jobs: None,
            debug: false,
            progress_sink: None,
        };
        let via_file = build_host(&opts(tmp.join("a.ext4"))).unwrap();
        let via_inputs = build_inputs_host(
            vec![PlanInput {
                dockerfile: parser::parse(src).unwrap(),
                origin: "inline".into(),
                context: tmp.clone(),
            }],
            &opts(tmp.join("b.ext4")),
        )
        .unwrap();
        assert_eq!(via_file.config, via_inputs.config);
        let (a, b) = (
            std::fs::read(tmp.join("a.ext4")).unwrap(),
            std::fs::read(tmp.join("b.ext4")).unwrap(),
        );
        // Bit-identical, superblock included: the only identity an exported image carries
        // is the UUID `stamp_stage_uuid` writes, and that is a fingerprint of the stage
        // key rather than a random one — so neither which entry point ran nor when it ran
        // can show up here. Compared by offset rather than with `assert_eq!` on the two
        // buffers, which would print 128 MiB of bytes on failure instead of naming the
        // one that moved.
        assert_eq!(a.len(), b.len(), "image sizes differ");
        if let Some((off, x, y)) = a
            .iter()
            .zip(&b)
            .enumerate()
            .find_map(|(i, (x, y))| (x != y).then_some((i, *x, *y)))
        {
            panic!("images differ at 0x{off:x}: {x:02x} != {y:02x}");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_writes_the_runtime_config_sidecar() {
        // a Host (FROM scratch + COPY) build exports the ext4 plus its config sidecar.
        let tmp = tmpdir("runcfg-sidecar");
        std::fs::write(tmp.join("f"), "x").unwrap();
        std::fs::write(
            tmp.join("Dockerfile"),
            "FROM scratch\nCOPY f /f\nENV PORT=6379\nUSER svc\nWORKDIR /srv\n\
             EXPOSE 6379/tcp 9000-9001\n\
             ENTRYPOINT [\"/bin/app\"]\nCMD [\"--port\", \"6379\"]\n",
        )
        .unwrap();
        let out = tmp.join("img.ext4");
        let built = build_host(&Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            stage_guests: Default::default(),
            contexts: vec![],
            build_contexts: Vec::new(),
            out: Some(out.clone()),
            out_disk: None,
            print_plan: false,
            cloud_hypervisor: None,
            kernel: None,
            agent: None,
            cache_registry: Some("none".into()),
            cache_insecure: false,
            cache_auth: Default::default(),
            build_cache: BuildCache::default(),
            journal: false,
            tmp_tmpfs: false,
            build_args: vec![],
            net: BuildNet::None, // host backend: no RUN guests, no network
            audit: false,
            require_cached: false,
            build_jobs: None,
            debug: false,
            progress_sink: None,
        })
        .unwrap();
        let sidecar = config_sidecar(&out);
        let cfg: vk_core::runcfg::RunConfig =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(cfg, built.config);
        assert_eq!(cfg.env, [("PORT".to_string(), "6379".to_string())]);
        assert_eq!(cfg.user, "svc");
        assert_eq!(cfg.workdir, "/srv");
        assert_eq!(cfg.argv(), ["/bin/app", "--port", "6379"]);
        // the ports the Dockerfile exposes reach the sidecar, so the guest gates on them
        assert_eq!(cfg.exposed_ports, [6379, 9000, 9001]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn export_stamps_the_stage_key_freshness_uuid() {
        // Regression: an exported image must carry fingerprint([stage_key]) as its ext4 UUID,
        // so `vk fingerprint` (and the dev-VM staleness check) matches a freshly built image.
        // The export tail (flatten + normalize_superblock) otherwise leaves the base UUID,
        // which never equals the fingerprint — the source of the perpetual "stale" prompt.
        let tmp = tmpdir("fp");
        std::fs::write(tmp.join("f"), "x").unwrap();
        std::fs::write(tmp.join("Dockerfile"), "FROM scratch\nCOPY f /f\n").unwrap();
        let out = tmp.join("img.ext4");
        let dockerfiles = vec![tmp.join("Dockerfile")];
        build_host(&Options {
            dockerfiles: dockerfiles.clone(),
            target: None,
            stage_guests: Default::default(),
            contexts: vec![],
            build_contexts: Vec::new(),
            out: Some(out.clone()),
            out_disk: None,
            print_plan: false,
            cloud_hypervisor: None,
            kernel: None,
            agent: None,
            cache_registry: Some("none".into()),
            cache_insecure: false,
            cache_auth: Default::default(),
            build_cache: BuildCache::default(),
            journal: false,
            tmp_tmpfs: false,
            build_args: vec![],
            net: BuildNet::None,
            audit: false,
            require_cached: false,
            build_jobs: None,
            debug: false,
            progress_sink: None,
        })
        .unwrap();
        // The stamped UUID must equal fingerprint([the target's stage key]).
        let key = target_stage_key(&dockerfiles, &[], &[], &[], None).unwrap();
        let expected = crate::ensure::fingerprint(&[&key]);
        assert_eq!(
            crate::ext4::fs_uuid(&out).as_deref(),
            Some(expected.as_str())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stamp_stage_uuid_overwrites_the_export_tail_uuid() {
        // The `build_units` (`vk build --compose` / `vk run --compose --primary`) export path
        // can only run end-to-end under a microVM, like all of `build_units`. It funnels
        // through the same `stamp_stage_uuid` helper as the host-testable `build_backend` path,
        // so pin that shared helper's contract directly: whatever UUID the export tail leaves
        // (here, an image built without any explicit stamp), stamping replaces it with
        // fingerprint([stage_key]) — the identity `vk fingerprint` expects.
        let tmp = tmpdir("stamp-uuid");
        std::fs::write(tmp.join("Dockerfile"), "FROM scratch\nCOPY Dockerfile /d\n").unwrap();
        let out = tmp.join("img.ext4");
        build_host(&Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            stage_guests: Default::default(),
            contexts: vec![],
            build_contexts: Vec::new(),
            out: Some(out.clone()),
            out_disk: None,
            print_plan: false,
            cloud_hypervisor: None,
            kernel: None,
            agent: None,
            cache_registry: Some("none".into()),
            cache_insecure: false,
            cache_auth: Default::default(),
            build_cache: BuildCache::default(),
            journal: false,
            tmp_tmpfs: false,
            build_args: vec![],
            net: BuildNet::None,
            audit: false,
            require_cached: false,
            build_jobs: None,
            debug: false,
            progress_sink: None,
        })
        .unwrap();
        // A synthetic key unrelated to the built content: stamping is a pure function of the
        // key it is handed, independent of whatever the build left behind.
        let key = "some-stage-key";
        stamp_stage_uuid(&out, key).unwrap();
        let expected = crate::ensure::fingerprint(&[key]);
        assert_eq!(
            crate::ext4::fs_uuid(&out).as_deref(),
            Some(expected.as_str())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // Regression test: `ext4::set_uuid` (which `stamp_stage_uuid` calls) refuses an
    // already-journaled image — the JBD2 superblock embeds the UUID at journal creation,
    // so a restamp would desynchronize them. `Options.journal = true` must therefore land
    // the journal *after* the UUID stamp in the export tail, not before; getting the order
    // backwards would make every default (journaled) `vk build --out` fail right here.
    #[test]
    fn journaled_export_stamps_the_uuid_before_adding_the_journal() {
        let tmp = tmpdir("journal-order");
        std::fs::write(tmp.join("Dockerfile"), "FROM scratch\nCOPY Dockerfile /d\n").unwrap();
        let out = tmp.join("img.ext4");
        build_host(&Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            stage_guests: Default::default(),
            contexts: vec![],
            build_contexts: Vec::new(),
            out: Some(out.clone()),
            out_disk: None,
            print_plan: false,
            cloud_hypervisor: None,
            kernel: None,
            agent: None,
            cache_registry: Some("none".into()),
            cache_insecure: false,
            cache_auth: Default::default(),
            build_cache: BuildCache::default(),
            journal: true,
            tmp_tmpfs: false,
            build_args: vec![],
            net: BuildNet::None,
            audit: false,
            require_cached: false,
            build_jobs: None,
            debug: false,
            progress_sink: None,
        })
        .expect("a journaled export must not fail stamping its own UUID");
        let key = target_stage_key(&[tmp.join("Dockerfile")], &[], &[], &[], None).unwrap();
        let expected = crate::ensure::fingerprint(&[&key]);
        assert_eq!(
            crate::ext4::fs_uuid(&out).as_deref(),
            Some(expected.as_str()),
            "the UUID must still be the one stamp_stage_uuid wrote, journal or not"
        );
        let mut sb = [0u8; 1024];
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(&out).unwrap();
            f.seek(SeekFrom::Start(1024)).unwrap();
            f.read_exact(&mut sb).unwrap();
        }
        let feat_compat = u32::from_le_bytes(sb[0x5c..0x60].try_into().unwrap());
        assert_eq!(
            feat_compat & 0x0004,
            0x0004,
            "journal: true must actually leave a journal in the exported image"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn docker_stage_hash_injects_into_exec_but_not_keys() {
        // 'core' declares ARG DOCKER_STAGE_HASH and bakes it into an ENV its RUN reads;
        // 'app' builds on 'core' without re-declaring. Building 'app' injects core's
        // stage_key as DOCKER_STAGE_HASH — and the cache keys must not depend on it.
        let src = "\
FROM debian:bookworm AS core
ARG DOCKER_STAGE_HASH
ENV BUILDER_TAG=$DOCKER_STAGE_HASH
RUN echo $BUILDER_TAG
FROM core AS app
RUN ship
";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let target = plan.resolve_target(Some("app")).unwrap();
        let order = plan.build_order(target).unwrap();
        // 'app' does not declare it; the nearest declarer in its closure is 'core' (0).
        assert_eq!(nearest_dsh_declarer(&plan, &[target]), Some(0));
        // With a multi-target search set the closest declarer is still 'core' (0): a
        // target that itself declares it wins over the shared dependency's declarer.
        let core = plan.resolve_target(Some("core")).unwrap();
        assert_eq!(nearest_dsh_declarer(&plan, &[core, target]), Some(0));

        // canonical (key-pass) keys, DOCKER_STAGE_HASH excluded.
        let mut ex = DryRun::new();
        let keyed = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
        let value = keyed[&0].final_key.clone();
        // exec pass injects core's stage_key, then merge keeps the canonical keys.
        let mut ex2 = DryRun::new();
        let exec = resolve_stages(&plan, &order, &ba, &mut ex2, Some(&value)).unwrap();
        let merged = merge_exec(&keyed, exec);

        // the executed RUN in 'core' sees the injected value via BUILDER_TAG — the command
        // stays raw (the shell expands it), with the value exported into its environment …
        let step = &merged[&0].steps[0];
        match &step.instr {
            Instruction::Run(r) => {
                assert_eq!(r.cmd, parser::Cmdline::Shell("echo $BUILDER_TAG".into()))
            }
            other => panic!("expected RUN, got {other:?}"),
        };
        assert!(
            step.state
                .env
                .iter()
                .any(|(k, v)| k == "BUILDER_TAG" && v == &value)
        );
        // … but its cache key is the canonical, value-independent one.
        assert_eq!(step.key, keyed[&0].steps[0].key);

        // injecting a different value yields identical keys (no self-reference circularity).
        let mut ex3 = DryRun::new();
        let exec_other = resolve_stages(&plan, &order, &ba, &mut ex3, Some("deadbeef")).unwrap();
        let merged_other = merge_exec(&keyed, exec_other);
        assert_eq!(merged_other[&0].steps[0].key, merged[&0].steps[0].key);
    }

    #[test]
    fn independent_stage_is_pruned_from_the_drive() {
        let src = "FROM a AS x\nRUN one\nFROM b AS y\nRUN two\nFROM x AS z\nRUN three\n";
        let t = transcript(src, Some("z"));
        assert!(t.iter().any(|l| l.contains("one")));
        assert!(t.iter().any(|l| l.contains("three")));
        assert!(
            !t.iter().any(|l| l.contains("two")),
            "stage y must be pruned"
        );
    }

    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    // A diamond DAG: 0 → {1, 2} → 3. Every node must see its deps already done, run
    // exactly once, and the results must be identical whether serial or concurrent.
    fn diamond() -> (Vec<usize>, HashMap<usize, Vec<usize>>) {
        let nodes = vec![0, 1, 2, 3];
        let deps = HashMap::from([(0, vec![]), (1, vec![0]), (2, vec![0]), (3, vec![1, 2])]);
        (nodes, deps)
    }

    #[test]
    fn run_dag_respects_deps_and_runs_each_node_once() {
        let (nodes, deps) = diamond();
        for jobs in [1usize, 4] {
            let built = Mutex::new(Vec::<usize>::new());
            let out = run_dag(&nodes, &deps, jobs, None, |n, done| {
                for d in &deps[&n] {
                    assert!(
                        done.contains_key(d),
                        "node {n} ran before dep {d} (jobs={jobs})"
                    );
                }
                built.lock().unwrap().push(n);
                Ok::<usize, anyhow::Error>(n * 10)
            })
            .unwrap();
            assert_eq!(out, HashMap::from([(0, 0), (1, 10), (2, 20), (3, 30)]));
            let mut b = built.into_inner().unwrap();
            b.sort_unstable();
            assert_eq!(
                b,
                vec![0, 1, 2, 3],
                "each node built exactly once (jobs={jobs})"
            );
        }
    }

    #[test]
    fn run_dag_surfaces_the_first_error() {
        let (nodes, deps) = diamond();
        let r = run_dag(&nodes, &deps, 4, None, |n, _done| {
            if n == 1 {
                anyhow::bail!("boom on {n}");
            }
            Ok::<usize, anyhow::Error>(n)
        });
        assert!(r.unwrap_err().to_string().contains("boom"));
    }

    #[test]
    fn run_dag_cancels_in_flight_work_on_first_error() {
        // Independent nodes: node 0 fails fast; the others block until cancelled. run_dag
        // must fire the token on the first error so in-flight siblings abort promptly
        // instead of running their (here: deliberately long) body to completion.
        let nodes: Vec<usize> = (0..4).collect();
        let deps: HashMap<usize, Vec<usize>> = nodes.iter().map(|&n| (n, vec![])).collect();
        let cancel = CancellationToken::new();
        let cancelled = AtomicUsize::new(0);
        let r = run_dag(&nodes, &deps, 4, Some(&cancel), |n, _done| {
            if n == 0 {
                anyhow::bail!("boom");
            }
            // Poll for cancellation; a working token trips within a tick, a broken one
            // runs out the (generous) ceiling and the assertion below fails.
            for _ in 0..500 {
                if cancel.is_cancelled() {
                    cancelled.fetch_add(1, SeqCst);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok::<usize, anyhow::Error>(n)
        });
        assert!(r.unwrap_err().to_string().contains("boom"));
        assert!(
            cancelled.load(SeqCst) >= 1,
            "the first failure should cancel the siblings still in flight"
        );
    }

    #[test]
    fn run_dag_runs_independent_nodes_concurrently() {
        // Four nodes with no edges + four workers: they must actually overlap.
        let nodes: Vec<usize> = (0..4).collect();
        let deps: HashMap<usize, Vec<usize>> = nodes.iter().map(|&n| (n, vec![])).collect();
        let cur = AtomicUsize::new(0);
        let max = AtomicUsize::new(0);
        run_dag(&nodes, &deps, 4, None, |_n, _done| {
            let now = cur.fetch_add(1, SeqCst) + 1;
            max.fetch_max(now, SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(40));
            cur.fetch_sub(1, SeqCst);
            Ok::<usize, anyhow::Error>(0)
        })
        .unwrap();
        assert!(
            max.load(SeqCst) >= 2,
            "independent nodes should run concurrently (peak {})",
            max.load(SeqCst)
        );
    }

    #[test]
    fn semaphore_blocks_beyond_capacity() {
        let sem = Arc::new(Semaphore::new(1));
        let held = sem.acquire();
        let entered = Arc::new(AtomicUsize::new(0));
        let (sem2, entered2) = (Arc::clone(&sem), Arc::clone(&entered));
        let waiter = std::thread::spawn(move || {
            let _p = sem2.acquire();
            entered2.store(1, SeqCst);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            entered.load(SeqCst),
            0,
            "second acquire must block while the only permit is held"
        );
        drop(held);
        waiter.join().unwrap();
        assert_eq!(
            entered.load(SeqCst),
            1,
            "second acquire should proceed once the permit is released"
        );
    }

    #[test]
    fn a_stage_size_hint_never_reaches_a_cache_key() {
        // The guarantee that makes the hint safe to add to a Dockerfile at all: sizing a
        // stage is not editing it, so every key stays what it was and no cache is thrown
        // away by tuning one. `docker-hash` publishes these keys, so this is a contract.
        let ba = Vars::new();
        let keys = |src: &str| {
            let plan = plan_one(src, &ba);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            let r = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
            order
                .iter()
                .map(|i| r[i].final_key.clone())
                .collect::<Vec<_>>()
        };
        let plain = "FROM alpine AS lib\nRUN one\nFROM alpine AS app\nCOPY --from=lib /f /f\n";
        let sized = "# vk: mem=8G cpus=16\nFROM alpine AS lib\nRUN one\n\
                     # vk: mem=512M\nFROM alpine AS app\nCOPY --from=lib /f /f\n";
        assert_eq!(keys(plain), keys(sized));
        // And the sizes did reach the plan — otherwise the assertion above passes for the
        // wrong reason.
        let plan = plan_one(sized, &ba);
        assert_eq!(plan.stages[0].guest.mem.as_deref(), Some("8G"));
        assert_eq!(plan.stages[0].guest.cpus, Some(16));
        assert_eq!(plan.stages[1].guest.mem.as_deref(), Some("512M"));
    }

    #[test]
    fn a_stage_flag_outranks_the_dockerfile_hint() {
        let ba = Vars::new();
        let mut plan = plan_one(
            "# vk: mem=8G cpus=16\nFROM alpine AS compile\nRUN one\nFROM alpine\nRUN two\n",
            &ba,
        );
        // The two flags naming one stage size it together, and each field stands alone:
        // --stage-cpus leaves the hint's mem=8G exactly where it was.
        let over = stage_overrides(
            &[("stage1".into(), "512M".into())],
            &[("compile".into(), 4), ("stage1".into(), 2)],
        );
        let matched = apply_stage_overrides(&mut plan, &over);
        assert_eq!(plan.stages[0].guest.mem.as_deref(), Some("8G"));
        assert_eq!(plan.stages[0].guest.cpus, Some(4));
        // A stage with no `AS` name is addressed as the log names it, and had no hint at all.
        assert_eq!(plan.stages[1].guest.mem.as_deref(), Some("512M"));
        assert_eq!(plan.stages[1].guest.cpus, Some(2));
        assert_eq!(matched, ["compile", "stage1"].map(String::from).into());
        assert_eq!(stage_names(&plan), ["compile", "stage1"]);
    }

    #[test]
    fn a_stage_flag_naming_no_stage_is_an_error() {
        // Reject misspelled stage names instead of silently ignoring their overrides.
        let over = stage_overrides(&[("compil".into(), "8G".into())], &[("nope".into(), 2)]);
        let matched = HashSet::new();
        let err = unmatched_stage_overrides(&over, &matched, &["compile".into(), "app".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("compil, nope"), "{err}");
        assert!(err.contains("declared: compile, app"), "{err}");
        // Names that all matched (a build spanning units matches them one unit at a time).
        let matched = ["compil", "nope"].map(String::from).into();
        assert!(unmatched_stage_overrides(&over, &matched, &[]).is_ok());
    }

    #[test]
    fn a_builds_declared_sizes_are_read_off_its_plan() {
        // What the ceiling divides and what the trace names: a stage's own size where it
        // asked for one, the build-wide default where it did not.
        let ba = Vars::new();
        let plan = plan_one(
            "# vk: mem=8G cpus=16\n\
             FROM alpine AS compile\n\
             RUN a\n\
             FROM alpine AS app\n\
             RUN b\n\
             # vk: cpus=2\n\
             FROM alpine\n\
             RUN c\n",
            &ba,
        );
        let order: Vec<usize> = (0..plan.stages.len()).collect();
        assert_eq!(stage_sizes(&plan, &order, 4096), vec![8192, 4096, 4096]);
        // Only the stages that differ are named, each with just the fields it set, and an
        // unnamed one by its position.
        assert_eq!(
            sized_stages(&plan, &order, ""),
            vec!["compile mem=8G cpus=16", "stage2 cpus=2"]
        );
        // A multi-unit build prefixes them, so a name says which unit it came from.
        assert_eq!(
            sized_stages(&plan, &order, "web:"),
            vec!["web:compile mem=8G cpus=16", "web:stage2 cpus=2"]
        );
    }

    #[test]
    fn a_stage_override_names_that_stage_in_every_unit() {
        // The flags address a bare name, so a name declared by two units sizes both — and
        // the "no such stage" list says each name once however many units declare it.
        let ba = Vars::new();
        let mut a = plan_one("FROM alpine AS build\nRUN a\n", &ba);
        let mut b = plan_one("FROM alpine AS build\nRUN b\nFROM alpine AS ship\n", &ba);
        let overrides = HashMap::from([(
            "build".to_string(),
            parser::GuestHint {
                mem: Some("8G".into()),
                cpus: None,
            },
        )]);
        let mut matched = HashSet::new();
        matched.extend(apply_stage_overrides(&mut a, &overrides));
        matched.extend(apply_stage_overrides(&mut b, &overrides));
        assert_eq!(a.stages[0].guest.mem.as_deref(), Some("8G"));
        assert_eq!(b.stages[0].guest.mem.as_deref(), Some("8G"));
        assert_eq!(b.stages[1].guest.mem, None, "only the named stage is sized");
        let mut known = stage_names(&a);
        known.extend(stage_names(&b));
        assert!(unmatched_stage_overrides(&overrides, &matched, &known).is_ok());
        // A name no unit declares fails, and each declared name is listed once.
        let absent = HashMap::from([("compile".to_string(), parser::GuestHint::default())]);
        let err = unmatched_stage_overrides(&absent, &HashSet::new(), &known)
            .unwrap_err()
            .to_string();
        assert!(err.contains("compile: no such stage"), "{err}");
        assert!(err.contains("declared: build, ship"), "{err}");
    }

    #[test]
    fn a_stage_asking_for_more_than_the_host_has_is_held_to_it() {
        // A Dockerfile is built on laptops as well as build hosts: the 24G stage has to
        // stay buildable on the 8 GiB machine, slowly, rather than fail to boot there.
        assert_eq!(
            clamp_stage_mem("24G", Some(6144), 4096).as_deref(),
            Some("6144M")
        );
        // Under the cap (and exactly at it) it stands as written.
        assert_eq!(clamp_stage_mem("4G", Some(6144), 4096), None);
        assert_eq!(clamp_stage_mem("6144M", Some(6144), 4096), None);
        // Nothing to hold it to: an unreadable host promises nothing, so it asks the VMM
        // for what the Dockerfile said and finds out there.
        assert_eq!(clamp_stage_mem("24G", None, 4096), None);
        // A size the parser would have rejected is left alone rather than turned into one.
        assert_eq!(clamp_stage_mem("lots", Some(6144), 4096), None);
        // Never below what an un-hinted stage gets. A 4 GiB host reserves a flat GiB (the
        // floor under BUILD_RESERVE_PCT), leaving a 3072 MiB cap — holding the stage that
        // asked for 8G to that would boot it smaller than the 4G stage beside it.
        assert_eq!(
            clamp_stage_mem("8G", Some(3072), 4096).as_deref(),
            Some("4096M"),
        );
        // And never to nothing: a host under that floor caps at zero, which is not a size.
        assert_eq!(clamp_stage_mem("8G", Some(0), 0), None);
    }

    #[test]
    fn foreign_use_counts_what_this_build_does_not_hold() {
        // 32 GiB host, 18 GiB of it available, 2 GiB of tmpfs, and 6 GiB resident across this
        // build's process tree (its stage guests, which are children — see `build_rss_mib`).
        // Unavailable is 14 GiB; the tmpfs counts as unavailable too (`MemAvailable` calls it
        // reclaimable, but it can only leave for swap), and our own 6 GiB comes back out, since the
        // ledger charges those guests by declaration.
        let host = crate::schedule::HostMemory {
            total_mib: 32768,
            available_mib: 18432,
            shmem_mib: 2048,
        };
        assert_eq!(foreign_used_mib(host, 6144), 32768 + 2048 - 18432 - 6144);
        // A guest that has faulted in nothing yet leaves the foreign reading unchanged —
        // this is what stops a just-booted stage from looking like free memory to the next.
        assert_eq!(foreign_used_mib(host, 0), 32768 + 2048 - 18432);
        // Nothing goes negative: a tree whose RSS exceeds what the host calls used (page
        // cache it owns, double-counted shared mappings) reads as no foreign use at all.
        assert_eq!(foreign_used_mib(host, u64::MAX / 2), 0);
    }

    #[test]
    fn one_status_file_yields_its_parent_and_resident_size() {
        assert_eq!(
            ppid_and_rss_kib("Name:\tvk\nPPid:\t41\nVmRSS:\t  2048 kB\n"),
            Some((41, 2048))
        );
        // A kernel thread has a PPid but no VmRSS, and is not a process holding host RAM.
        assert_eq!(ppid_and_rss_kib("Name:\tkthreadd\nPPid:\t2\n"), None);
        assert_eq!(ppid_and_rss_kib("VmRSS:\t 4 kB\n"), None);
        assert_eq!(ppid_and_rss_kib("PPid:\tx\nVmRSS:\t4 kB\n"), None);
    }

    #[test]
    fn the_build_footprint_is_the_whole_process_tree() {
        // The guests are children, not `/proc/self`: both backends run a VM in its own
        // process (libkrun re-execs this binary), so a reading that stopped at self would
        // miss every guest and charge each one twice — once here, once in `held_mib`.
        let proc = tmpdir("rss-tree");
        let proc = proc.as_path();
        let me = std::process::id();
        let write = |pid: u32, ppid: u32, rss_kib: u64| {
            let d = proc.join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("status"),
                format!("Name:\tp{pid}\nPPid:\t{ppid}\nVmRSS:\t{rss_kib} kB\n"),
            )
            .unwrap();
        };
        write(1, 0, 100 * 1024); // init: not ours
        write(me, 1, 3 * 1024); // the driver itself
        write(me + 1, me, 4096 * 1024); // a stage guest
        write(me + 2, me + 1, 8 * 1024); // its virtiofsd, a grandchild
        write(me + 3, 1, 9999 * 1024); // someone else's, sharing the host
        // Not a number, and a directory with no status: neither derails the scan.
        std::fs::create_dir_all(proc.join("self")).unwrap();
        std::fs::create_dir_all(proc.join(format!("{}", me + 4))).unwrap();
        assert_eq!(build_rss_mib(proc), Some(3 + 4096 + 8));
        assert_eq!(build_rss_mib(Path::new("/nonexistent")), None);
    }

    #[test]
    fn the_ledger_charges_declared_size_against_what_is_left() {
        // 32 GiB host: 10% held back (3276 MiB), 12 GiB used by things that are not us.
        let ledger = MemLedger::new(Some(32768));
        assert_eq!(ledger.reserve_mib, 3276);
        // 32768 - 3276 - 12288 = 17204 free to promise. A 4 GiB stage fits with 8 GiB of
        // siblings already promised (12288 + 4096 <= 17204) and not with 16 GiB (20480).
        assert_eq!(ledger.short_by(4096, 8192, 12288), 0);
        assert_eq!(ledger.short_by(4096, 16384, 12288), 4096 + 16384 - 17204);
        // A small host keeps the floor rather than 10% of very little.
        assert_eq!(
            MemLedger::new(Some(4096)).reserve_mib,
            BUILD_RESERVE_MIN_MIB
        );
        // Gate off: every size fits, whatever is held or in use elsewhere.
        assert_eq!(
            MemLedger::new(None).short_by(u64::MAX, u64::MAX, u64::MAX),
            0
        );
    }

    #[test]
    fn the_ledger_admits_the_first_stage_and_holds_the_next() {
        // A host too small for even one stage, so the fit check can never pass: the first
        // reservation must still go through (a build with nothing running has no way to make
        // room, and parking it forever would deadlock rather than throttle), and the second
        // must wait for that one to be released rather than pile on.
        let ledger = Arc::new(MemLedger::new(Some(1)));
        let (first, wait) = ledger.reserve(4096, None, |_| {});
        assert_eq!(
            wait,
            MemWait::No,
            "nothing of ours was live, so it cannot have waited"
        );
        // Signalled, not slept on: the assertion below is that the second stage is *still*
        // waiting, so it has to be taken at a moment the second stage has demonstrably
        // reached — a fixed sleep would let a slow machine pass it before the thread ran.
        let (tx, rx) = std::sync::mpsc::channel();
        let entered = Arc::new(AtomicUsize::new(0));
        let (l2, e2) = (Arc::clone(&ledger), Arc::clone(&entered));
        let second = std::thread::spawn(move || {
            let (_r, wait) = l2.reserve(4096, None, |short| tx.send(short).unwrap());
            e2.store(1, SeqCst);
            wait
        });
        let short = rx.recv().unwrap();
        assert!(short > 0, "a parked stage reports what it is short by");
        assert_eq!(
            entered.load(SeqCst),
            0,
            "a second stage must wait while the host has no room for it"
        );
        drop(first);
        assert_eq!(
            second.join().unwrap(),
            MemWait::Admitted,
            "and must report that it waited and was then let in"
        );
        assert_eq!(
            entered.load(SeqCst),
            1,
            "releasing the first stage's reservation should let the next one in"
        );
        assert_eq!(
            ledger.state.lock().unwrap().held_mib,
            0,
            "guards release on drop"
        );
    }

    #[test]
    fn the_ledger_admits_waiting_stages_oldest_first() {
        // Mixed sizes on a host with no room: the big stage queued first must get the
        // memory the release frees, even though the small one behind it would also fit.
        // Without that, a large stage is overtaken by every small one and never runs.
        let ledger = Arc::new(MemLedger::new(Some(1)));
        let (held, _) = ledger.reserve(1024, None, |_| {});
        // Queue depth, not the wait callback: only the oldest waiter measures the host and
        // so only it ever calls back, which is the very property under test.
        let queued = |n: usize| {
            for _ in 0..2000 {
                if ledger.state.lock().unwrap().waiting.len() == n {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            panic!("waited for {n} queued stage(s) and never saw them");
        };
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut waiters = Vec::new();
        for (i, (label, want)) in [("big", 8192u64), ("small", 512)].into_iter().enumerate() {
            let (l, o) = (Arc::clone(&ledger), Arc::clone(&order));
            waiters.push(std::thread::spawn(move || {
                let (_r, _) = l.reserve(want, None, |_| {});
                o.lock().unwrap().push(label);
                // Hold until every waiter has been admitted, so the order recorded is the
                // order they were let in and not the order they happened to finish.
                std::thread::sleep(Duration::from_millis(50));
            }));
            // Queue strictly: only once this one has a ticket does the next take one.
            queued(i + 1);
        }
        drop(held);
        for w in waiters {
            w.join().unwrap();
        }
        assert_eq!(
            *order.lock().unwrap(),
            vec!["big", "small"],
            "the stage that queued first is admitted first"
        );
    }

    #[test]
    fn a_guest_less_backend_never_queues() {
        // `DryRun`/`Planner`/`Host` declare no stage RAM (`stage_mem_mib` is None -> 0), so
        // they must pass straight through a ledger that is otherwise wedged shut.
        let ledger = MemLedger::new(Some(1));
        let (_blocking, _) = ledger.reserve(4096, None, |_| {});
        let (free, wait) = ledger.reserve(0, None, |_| panic!("must not park"));
        assert_eq!(wait, MemWait::No);
        assert_eq!(
            ledger.state.lock().unwrap().held_mib,
            4096,
            "a zero-size admission charges nothing"
        );
        assert!(
            ledger.state.lock().unwrap().waiting.is_empty(),
            "and takes no place in the queue"
        );
        drop(free);
    }

    #[test]
    fn a_cancelled_build_stops_waiting_for_memory() {
        // Same unfittable host, but the build is already cancelled: the stage is let through
        // to fail at its own cancellation check instead of parking behind memory that a
        // build now tearing down will never free.
        let ledger = MemLedger::new(Some(1));
        let (_first, _) = ledger.reserve(4096, None, |_| {});
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (_second, wait) = ledger.reserve(4096, Some(&cancel), |_| {
            panic!("a cancelled build must not park on memory")
        });
        assert_eq!(wait, MemWait::No);
        let st = ledger.state.lock().unwrap();
        assert_eq!(st.held_mib, 8192);
        assert!(
            st.waiting.is_empty(),
            "a stage that gives up leaves the queue"
        );
    }

    #[test]
    fn a_failing_stage_releases_the_memory_it_reserved() {
        // The reservation is a guard, so the unwind of a stage that panics has to hand its
        // memory back — otherwise one failure narrows the rest of the build for good.
        let ledger = Arc::new(MemLedger::new(Some(32768)));
        let l = Arc::clone(&ledger);
        let panicked = std::thread::spawn(move || {
            let (_r, _) = l.reserve(4096, None, |_| {});
            assert_eq!(l.state.lock().unwrap().held_mib, 4096);
            panic!("stage failed");
        })
        .join();
        assert!(panicked.is_err(), "the stage was supposed to panic");
        assert_eq!(
            ledger.state.lock().unwrap().held_mib,
            0,
            "an unwinding stage still releases its reservation"
        );
    }

    #[test]
    fn the_gate_line_reports_what_is_left_of_the_host() {
        // 32 GiB, 3276 held back, 12 GiB elsewhere -> 17204 MiB left to promise. In MiB and
        // not in stages: with stages sized individually there is no one stage size to
        // divide it by.
        let line = gate_line(32768, 3276, 12288);
        assert_eq!(
            line,
            "virtkit: build: host memory 32768 MiB, 12288 MiB in use elsewhere, \
             3276 MiB held back — 17204 MiB free for stage guests now"
        );
        // A host with nothing to give reads as nothing, not as a negative or a floor: the
        // first stage in is admitted anyway, and the line is a reading, not the rule.
        assert!(gate_line(32768, 3276, 32000).ends_with("0 MiB free for stage guests now"));
    }

    #[test]
    fn a_stage_that_panics_while_parking_leaves_the_queue() {
        // `on_wait` reaches `println!` on the plain backend, so it panics on EPIPE the
        // moment a build's output is piped into something that stops reading. The queue
        // place has to come back regardless: a ticket stranded by that unwind would be a
        // head that never advances, and the build would hang instead of failing.
        let ledger = Arc::new(MemLedger::new(Some(1)));
        let (held, _) = ledger.reserve(4096, None, |_| {});
        let l = Arc::clone(&ledger);
        let died = std::thread::spawn(move || {
            let _ = l.reserve(4096, None, |_| panic!("stdout went away"));
        })
        .join();
        assert!(died.is_err(), "the parking stage was supposed to panic");
        assert!(
            ledger.state.lock().unwrap().waiting.is_empty(),
            "an unwinding stage must give its queue place back"
        );
        // And the queue still works: without the guard above this would block forever
        // behind a ticket whose owner is gone.
        drop(held);
        let (_next, wait) = ledger.reserve(4096, None, |_| {});
        assert_eq!(wait, MemWait::No, "the next stage walks straight in");
    }

    #[test]
    fn admitting_one_stage_wakes_the_next_in_the_queue() {
        // Leaving the queue has to notify, not just releasing memory does. Otherwise the
        // stage that becomes head sleeps out a whole `MEM_POLL` before it even looks —
        // once per admission, on a host with nothing wrong with it.
        let ledger = Arc::new(MemLedger::new(Some(1)));
        let (first, _) = ledger.reserve(4096, None, |_| {});
        let queued = |n: usize| {
            for _ in 0..2000 {
                if ledger.state.lock().unwrap().waiting.len() == n {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            panic!("waited for {n} queued stage(s) and never saw them");
        };
        // The head: parks now, and is admitted as soon as `first` lets go.
        let (head_tx, head_rx) = std::sync::mpsc::channel();
        let l = Arc::clone(&ledger);
        let head = std::thread::spawn(move || {
            let (r, _) = l.reserve(4096, None, |_| {});
            head_tx.send(Instant::now()).unwrap();
            std::thread::sleep(Duration::from_millis(100)); // hold, so the next one parks
            drop(r);
        });
        queued(1);
        // Behind it: cannot measure anything until the head leaves, so the moment it first
        // reports a shortfall is the moment it learned its turn had come.
        let (next_tx, next_rx) = std::sync::mpsc::channel();
        let l = Arc::clone(&ledger);
        let next = std::thread::spawn(move || {
            let (_r, _) = l.reserve(4096, None, |_| next_tx.send(Instant::now()).unwrap());
        });
        queued(2);
        drop(first);
        let (admitted_at, noticed_at) = (head_rx.recv().unwrap(), next_rx.recv().unwrap());
        head.join().unwrap();
        next.join().unwrap();
        // Generously under the poll interval: the handoff is a condvar wake and a `/proc`
        // walk, microseconds of work. Without the notify it is the full `MEM_POLL`.
        assert!(
            noticed_at.duration_since(admitted_at) < MEM_POLL / 2,
            "the new head waited {:?} to notice its turn",
            noticed_at.duration_since(admitted_at),
        );
    }

    #[test]
    fn an_ungated_build_never_queues_or_measures() {
        // `[build] no_mem_gate` (and a host whose memory cannot be read) must not merely
        // make every size fit — it has to skip the queue and the `/proc` walk entirely,
        // which is what "the behaviour before the gate existed" means.
        let ledger = MemLedger::new(None);
        let (a, wait) = ledger.reserve(u64::MAX, None, |_| panic!("an ungated build cannot park"));
        let (b, _) = ledger.reserve(u64::MAX, None, |_| panic!("an ungated build cannot park"));
        assert_eq!(wait, MemWait::No);
        let st = ledger.state.lock().unwrap();
        assert_eq!(st.held_mib, 0, "nothing is charged when there is no gate");
        assert_eq!(st.next_ticket, 0, "and no queue place is ever taken");
        assert!(st.waiting.is_empty());
        drop(st);
        drop((a, b));
    }

    #[test]
    fn the_gate_announces_itself_only_when_it_can_bind() {
        // A sequential build has nothing to hold back — at most one stage is ever live, so
        // the ledger's own escape admits it whatever the host looks like. Announcing room
        // for stages such a build will not run is noise, not information.
        assert!(gate_note(1, Some(32768)).is_none());
        assert!(gate_note(4, None).is_none(), "gate off, nothing to say");
        assert!(gate_note(4, Some(32768)).is_some());
    }

    // Regression test for the dispatch/build-cap decoupling: the fully-cached fast path
    // must return before ever touching `budget`, so it has to complete even with
    // the semaphore fully exhausted (0 permits) — a build-bound acquire here would block
    // forever, so drive the call off-thread and assert it finishes instead of hanging.
    #[test]
    fn build_stage_cache_hit_skips_the_build_permit() {
        let src = "FROM alpine\nRUN one\n";
        let ba = Vars::new();
        let mut ex = CachedDry::default();
        let plan = plan_one(src, &ba);
        let target = plan.resolve_target(None).unwrap();
        let order = plan.build_order(target).unwrap();
        let resolved = resolve_all(&plan, &order, &ba, &mut ex, &[target]).unwrap();
        let key = resolved[&target].steps.last().unwrap().key.clone();
        ex.cache.insert(key);
        let (_needed, cached_final) =
            compute_needed(&plan, &order, &resolved, &mut ex, false, &[target]).unwrap();
        assert!(
            cached_final.contains_key(&target),
            "test setup: stage must be a full cache hit"
        );
        let budget = BuildBudget::new(0, None);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = build_stage(
                &plan,
                &resolved,
                &cached_final,
                &HashMap::new(),
                &mut ex,
                target,
                BuildCache::Instructions,
                &Progress::disabled(),
                &Arc::new(Timings::new()),
                None,
                "",
                target,
                &budget,
            );
            let _ = tx.send(result.is_ok());
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(ok) => assert!(ok, "cache-hit build_stage call returned an error"),
            Err(_) => panic!("cache-hit stage blocked on an exhausted build permit"),
        }
    }

    // Regression test for the retry-storm fix: a stage whose content-key already has a
    // memoized failure (from `Executor::check_build_failure`, backed by a remote
    // vk-registry) must fail fast — never touching the build permit — instead of
    // repeating the same doomed build. Run off-thread with the permit exhausted, exactly
    // like the cache-hit test above, so a regression that reaches the real build path
    // hangs the test instead of silently passing.
    #[test]
    fn build_stage_fails_fast_on_a_recent_failure_memo() {
        let src = "FROM alpine\nRUN one\n";
        let ba = Vars::new();
        let mut ex = CachedDry::default();
        let plan = plan_one(src, &ba);
        let target = plan.resolve_target(None).unwrap();
        let order = plan.build_order(target).unwrap();
        let resolved = resolve_all(&plan, &order, &ba, &mut ex, &[target]).unwrap();
        let (_needed, cached_final) =
            compute_needed(&plan, &order, &resolved, &mut ex, false, &[target]).unwrap();
        ex.fail_check = Some(vk_registry::FailInfo {
            reason: "ENOSPC".into(),
            age: Duration::from_secs(5),
        });
        let budget = BuildBudget::new(0, None);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = build_stage(
                &plan,
                &resolved,
                &cached_final,
                &HashMap::new(),
                &mut ex,
                target,
                BuildCache::Instructions,
                &Progress::disabled(),
                &Arc::new(Timings::new()),
                None,
                "",
                target,
                &budget,
            );
            let _ = tx.send(result.err().map(|e| e.to_string()));
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Some(msg)) => assert!(
                msg.contains("ENOSPC"),
                "error should surface the memoized failure's reason, got: {msg}"
            ),
            Ok(None) => panic!("a memoized failure must not let the build proceed"),
            Err(_) => panic!("fail-fast stage blocked on an exhausted build permit"),
        }
    }

    // Regression test for the retry-storm fix: a genuine build error must be memoized via
    // `Executor::report_build_failure` against the stage's own final content key, so a
    // peer in the same pipeline can fail fast instead of repeating it.
    #[test]
    fn build_stage_reports_a_genuine_failure_against_its_final_key() {
        let src = "FROM alpine\nRUN one\n";
        let ba = Vars::new();
        let mut ex = CachedDry {
            fail_save: true,
            ..Default::default()
        };
        let plan = plan_one(src, &ba);
        let target = plan.resolve_target(None).unwrap();
        let order = plan.build_order(target).unwrap();
        let resolved = resolve_all(&plan, &order, &ba, &mut ex, &[target]).unwrap();
        let key = resolved[&target].steps.last().unwrap().key.clone();
        let (_needed, cached_final) =
            compute_needed(&plan, &order, &resolved, &mut ex, false, &[target]).unwrap();
        let budget = BuildBudget::new(1, None);
        let result = build_stage(
            &plan,
            &resolved,
            &cached_final,
            &HashMap::new(),
            &mut ex,
            target,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
            None,
            "",
            target,
            &budget,
        );
        assert!(
            result.is_err(),
            "the synthetic cache_save failure must propagate"
        );
        assert_eq!(
            ex.fail_reports,
            vec![(key, "synthetic cache_save failure".to_string())]
        );
    }

    // Regression test: a cascaded cancellation (a sibling stage failed while this one was
    // mid-flight, tripping the between-steps check) is not this stage's own fault and must
    // not be memoized — otherwise the *next* pipeline run would fail fast on a key that
    // never actually failed to build.
    #[test]
    fn build_stage_does_not_memoize_a_cascaded_cancellation() {
        let src = "FROM alpine\nRUN one\nRUN two\n";
        let ba = Vars::new();
        let mut ex = CachedDry {
            // `run` cancels the token right after step 0 succeeds, so the between-steps
            // check ahead of step 1 sees a cascaded cancellation, exactly as a real sibling
            // failure elsewhere in the DAG would trigger it.
            cancel_after_run: true,
            ..Default::default()
        };
        let plan = plan_one(src, &ba);
        let target = plan.resolve_target(None).unwrap();
        let order = plan.build_order(target).unwrap();
        let resolved = resolve_all(&plan, &order, &ba, &mut ex, &[target]).unwrap();
        let (_needed, cached_final) =
            compute_needed(&plan, &order, &resolved, &mut ex, false, &[target]).unwrap();
        let budget = BuildBudget::new(1, None);
        let cancel = CancellationToken::new();
        let result = build_stage(
            &plan,
            &resolved,
            &cached_final,
            &HashMap::new(),
            &mut ex,
            target,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
            Some(&cancel),
            "",
            target,
            &budget,
        );
        assert!(
            result.is_err(),
            "the between-steps cancellation check must still abort the stage"
        );
        assert!(
            ex.fail_reports.is_empty(),
            "a cascaded cancellation must not be memoized as this key's own failure, got: {:?}",
            ex.fail_reports
        );
    }

    // Regression test: an environmental failure (out of disk, a transient connection
    // reset) is not this key's own content fault, and memoizing it would poison the key
    // until the whole pipeline restarts — even though the very next retry could succeed
    // once the environment recovers.
    #[test]
    fn build_stage_does_not_memoize_an_environmental_failure() {
        let src = "FROM alpine\nRUN one\n";
        let ba = Vars::new();
        let mut ex = CachedDry {
            fail_save: true,
            fail_save_io_kind: Some(std::io::ErrorKind::StorageFull),
            ..Default::default()
        };
        let plan = plan_one(src, &ba);
        let target = plan.resolve_target(None).unwrap();
        let order = plan.build_order(target).unwrap();
        let resolved = resolve_all(&plan, &order, &ba, &mut ex, &[target]).unwrap();
        let (_needed, cached_final) =
            compute_needed(&plan, &order, &resolved, &mut ex, false, &[target]).unwrap();
        let budget = BuildBudget::new(1, None);
        let result = build_stage(
            &plan,
            &resolved,
            &cached_final,
            &HashMap::new(),
            &mut ex,
            target,
            BuildCache::Instructions,
            &Progress::disabled(),
            &Arc::new(Timings::new()),
            None,
            "",
            target,
            &budget,
        );
        assert!(
            result.is_err(),
            "the synthetic ENOSPC failure must propagate"
        );
        assert!(
            ex.fail_reports.is_empty(),
            "an environmental (StorageFull) failure must not be memoized, got: {:?}",
            ex.fail_reports
        );
    }

    #[test]
    fn is_environmental_failure_matches_known_transient_io_kinds_only() {
        let env = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::StorageFull));
        assert!(is_environmental_failure(&env));
        let env = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
            .context("pulling the base image");
        assert!(
            is_environmental_failure(&env),
            "an io::Error wrapped deeper in the chain (via .context()) must still be found"
        );
        let content = anyhow::anyhow!("RUN exited with status 1");
        assert!(!is_environmental_failure(&content));
        let other_io =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(
            !is_environmental_failure(&other_io),
            "only the curated transient-kind set should be treated as environmental"
        );
    }

    #[test]
    fn build_jobs_override_beats_auto() {
        let opts = |j: Option<NonZeroUsize>| Options {
            dockerfiles: vec![],
            target: None,
            stage_guests: Default::default(),
            contexts: vec![],
            build_contexts: Vec::new(),
            out: None,
            out_disk: None,
            print_plan: false,
            cloud_hypervisor: None,
            kernel: None,
            agent: None,
            cache_registry: None,
            cache_insecure: false,
            cache_auth: Default::default(),
            build_cache: BuildCache::default(),
            journal: false,
            tmp_tmpfs: false,
            build_args: vec![],
            net: BuildNet::All,
            audit: false,
            require_cached: false,
            build_jobs: j,
            debug: false,
            progress_sink: None,
        };
        let host = Some(64 * 1024);
        let same = |n: usize, mib: u64| vec![mib; n];
        // Explicit build_jobs (--build-jobs, or [build] jobs) wins over the RAM-derived
        // default, and is used as given — zero is unrepresentable, so nothing to floor.
        assert_eq!(
            resolve_build_jobs(&opts(NonZeroUsize::new(3)), &same(20, 2048), host),
            3
        );
        // Auto is 80% of what the host *has* filled with stage guests smallest-first: 64 GiB
        // and 4 GiB stages is 12 wide, and it stays 12 however little of that is free.
        assert_eq!(resolve_build_jobs(&opts(None), &same(20, 4096), host), 12);
        // Never wider than there are stages to run: "up to 3 at once" is the truth about a
        // three-stage build, and dividing a budget would have claimed 12.
        assert_eq!(resolve_build_jobs(&opts(None), &same(3, 4096), host), 3);
        // Sized apart, there is no one size to divide by, so it is the most stages that
        // could be co-resident: on 8 GiB (6553 usable) the two 512M and the 4G fit, the 8G
        // does not — and a build of nothing but that 8G stage still gets its one job.
        assert_eq!(
            resolve_build_jobs(&opts(None), &[8192, 4096, 512, 512], Some(8192)),
            3
        );
        assert_eq!(resolve_build_jobs(&opts(None), &[8192], Some(8192)), 1);
        // A host whose memory cannot be read is treated as an 8 GiB one rather than an
        // unbounded one, so auto still lands somewhere a stage guest fits.
        assert_eq!(resolve_build_jobs(&opts(None), &same(20, 4096), None), 1);
        assert_eq!(resolve_build_jobs(&opts(None), &same(20, 1024), None), 6);
        // Clamped to [1, 16] at both ends: a stage guest the host cannot fit floors it, and
        // 1 MiB ones on a machine reporting all the memory there is stop at the ceiling
        // rather than overflowing the running total on the way.
        assert_eq!(
            resolve_build_jobs(&opts(None), &same(2, u64::MAX / 2), host),
            1
        );
        assert_eq!(
            resolve_build_jobs(&opts(None), &same(40, 1), Some(u64::MAX)),
            16
        );
        // Same 1 MiB stage guests, but an explicit 1: the override forces the sequential
        // build that auto would have widened, which is what makes it an override.
        assert_eq!(
            resolve_build_jobs(&opts(NonZeroUsize::new(1)), &same(40, 1), host),
            1
        );
    }

    #[test]
    fn concurrency_line_names_where_its_budget_came_from() {
        // The whole point of announcing the budget: a build pinned to one stage on purpose
        // must not read like one the RAM-derived default squeezed down to it.
        let pinned = concurrency_line(1, 2, "4G", true, &[]);
        assert!(pinned.starts_with("virtkit: build: "), "{pinned}");
        assert!(
            pinned.contains("up to 1 stage(s) at once (configured)"),
            "{pinned}"
        );
        assert!(pinned.contains("each cpus=2, mem=4G"), "{pinned}");
        assert!(!pinned.contains("sized apart"), "{pinned}");
        let auto = concurrency_line(6, 2, "4G", false, &[]);
        assert!(
            auto.contains("up to 6 stage(s) at once (from host memory)"),
            "{auto}"
        );
        // With stages sized individually, "each mem=4G" is no longer the whole story, so the
        // ones that differ are named — a trace showing 2 stages where the ceiling says 4 is
        // otherwise unreadable.
        let mixed = concurrency_line(
            4,
            2,
            "4G",
            false,
            &["compile mem=8G cpus=16".into(), "tools mem=512M".into()],
        );
        assert!(
            mixed.ends_with("sized apart: compile mem=8G cpus=16, tools mem=512M"),
            "{mixed}"
        );
    }

    /// A namespace's label must reach the *hash*, not just the prefix — asserted per
    /// namespace, since each folds its own and one doing so would otherwise mask the other.
    ///
    /// This is what keeps a base ext4 and a stage's chain root apart: `base_cache_key`'s
    /// input is the very `"FROM image <ref>"` that `hash_key` builds a chain root from, so
    /// before the label was folded in the two hashes were byte-identical and only the
    /// prefix separated them. Same shape as the `CACHE_KEY_VERSION` tests below.
    #[test]
    fn a_namespace_label_reaches_the_hash_not_just_the_prefix() {
        use sha2::{Digest, Sha256};
        let bare = |k: &str| k.split_once('-').map(|(_, h)| h.to_string()).unwrap();
        let unlabelled = |parts: &[&[u8]]| {
            let mut h = Sha256::new();
            h.update(CACHE_KEY_VERSION.as_bytes());
            h.update(b"\n");
            for p in parts {
                h.update(p);
            }
            hex(&h.finalize())
        };

        let input = "FROM image alpine:3.20@sha256:abc";
        let snap = hash_key(input);
        assert!(snap.starts_with("snap-"), "{snap}");
        assert_ne!(bare(&snap), unlabelled(&[input.as_bytes()]));

        let base = super::exec::base_cache_key("alpine:3.20@sha256:abc");
        assert!(base.starts_with("base-"), "{base}");
        assert_ne!(
            bare(&base),
            unlabelled(&[b"FROM image ", b"alpine:3.20@sha256:abc"])
        );

        // and the consequence the whole change exists for: the same string in two
        // namespaces is two different keys, under the hash as well as in the prefix.
        assert_ne!(bare(&snap), bare(&base));
    }

    /// Every key a build can produce says which namespace it is in — that is what makes a
    /// `build-cache` listing readable, and `vk docker-hash` prints these verbatim as the tag a
    /// snapshot lives at.
    #[test]
    fn every_key_names_its_namespace() {
        let run = Instruction::Run(parser::Run {
            cmd: parser::Cmdline::Shell("make".into()),
            mounts: vec![],
            network: None,
            security: None,
        });
        let root = hash_key("FROM scratch");
        let chained = chain_key(&root, &run, None);
        let content = chain_key(&root, &run, Some("ab"));
        // an all-hex remainder is also what says chaining stays in the namespace it
        // started in rather than nesting one prefix inside another.
        for key in [&root, &chained, &content] {
            let digest = key
                .strip_prefix("snap-")
                .unwrap_or_else(|| panic!("unnamespaced key: {key}"));
            assert_eq!(digest.len(), 64, "{key}");
            assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
        }
        assert_ne!(chained, content, "the content hash still reaches the key");
    }

    /// `hash_key` must actually fold in `CACHE_KEY_VERSION`, not just carry it in a doc
    /// comment: bumping the version is the whole invalidation mechanism, so a change that
    /// silently stopped salting the hash would leave old, possibly-corrupt cache entries
    /// resolving forever.
    #[test]
    fn hash_key_is_salted_by_the_cache_key_version() {
        use sha2::{Digest, Sha256};
        // Everything `hash_key` folds in *except* the version salt, in the same key
        // shape — so only dropping the salt can make the two agree.
        let unsalted = {
            let mut h = Sha256::new();
            h.update(b"snap\n");
            h.update(b"FROM scratch");
            Ns::Snap.key(&hex(&h.finalize()))
        };
        assert_ne!(hash_key("FROM scratch"), unsalted);
    }
}
