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

use std::collections::{HashMap, HashSet};
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
    *BUILD_MEM.lock().unwrap() = build.mem.clone();
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

/// What/how to build.
pub struct Options {
    /// Dockerfile(s), merged into one stage namespace (see [`Plan::from_dockerfiles`]).
    pub dockerfiles: Vec<PathBuf>,
    /// Stage selector: an `AS` name or index; `None` = the last stage.
    pub target: Option<String>,
    /// Build-context roots, zipped positionally with `dockerfiles`; a file without one
    /// defaults to its own directory.
    pub contexts: Vec<PathBuf>,
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
    /// host RAM, each stage guest reserving a fixed slice). `1` forces the sequential
    /// build. Ignored by the host backend.
    ///
    /// The other build-guest tuning knobs — per-stage `cpus`/`mem` and the `auto`
    /// checkpoint threshold — are host-wide (no CLI flag), so they ride the process-global
    /// build tuning set once from `[build]` (see [`set_tuning`]), not this per-build struct.
    pub build_jobs: Option<usize>,
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
        // EXPOSE is not tracked in ShellState, so a git-defined (dockerfile:) service
        // gates readiness on the guest booting, not on its ports. Pulled images (the
        // common services: case) carry ExposedPorts through the OCI config.
        exposed_ports: Vec::new(),
    }
}

/// Resolve the instruction-cache destination: an explicit registry/store wins; `none`
/// disables; the default is the builtin local store — the same content-addressed root
/// a `vk registry serve` shares, accessed in-process (no server, no port). A
/// dot-relative path is rejected: only absolute paths and `file://` URLs select the
/// in-process store, everything else is a registry host.
fn cache_repo(cache_registry: Option<&str>) -> Result<Option<String>> {
    Ok(match cache_registry {
        Some("none") => None,
        // A hostname can't start with a dot, so this is a relative path — which
        // Registry::local_root would silently treat as a registry host.
        Some(repo) if repo.starts_with('.') => bail!(
            "cache destination {repo:?} is a relative path; \
             an in-process store needs an absolute path (or a file:// URL)"
        ),
        Some(repo) => Some(repo.to_string()),
        None => Some(
            vk_registry::default_root()
                .context("resolving the builtin cache store dir")?
                .display()
                .to_string(),
        ),
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

/// Filename prefix for a build's scratch dir, named `<prefix><pid>-<seq>`. The embedded
/// pid lets a later run reclaim scratch orphaned by a hard-killed build (see
/// [`sweep_stale_scratch`]).
const SCRATCH_PREFIX: &str = ".build-";

/// The scratch dir for a build writing to `out`, unique per run (`<prefix><pid>-<seq>`).
/// Placed next to `out` so stage ext4s land on the real filesystem the caller chose, not
/// a small/RAM-backed tmpfs — but always made absolute: stage qcow2 overlays record their
/// backing image by path, and qcow2 resolves a *relative* backing against the overlay's
/// own directory, so a cwd-relative scratch (from a relative `--out`) would apply the
/// prefix twice and fail to open the backing.
fn build_scratch(out: &Path, seq: u64) -> Result<PathBuf> {
    let rel = out
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{SCRATCH_PREFIX}{}-{seq}", std::process::id()));
    // Must be absolute (see above); the relative fallback would reintroduce the exact
    // backing-path bug, so surface the error instead of silently using it.
    std::path::absolute(&rel).context("resolving the build scratch dir to an absolute path")
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
        opts.journal,
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
    let t_plan = Instant::now();
    let plan = Plan::from_dockerfiles(&inputs, &build_args)?;
    let target = plan.resolve_target(opts.target.as_deref())?;
    let order = plan.build_order(target)?;
    // Reject a cross-stage source under /tmp up front: /tmp is ephemeral and never
    // committed, so it would fail late with a cryptic "No such file" from the guest.
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
    // Scratch placement + naming: see [`build_scratch`]. Keyed by pid + an in-process
    // counter, so two builds in one process (e.g. `run --compose` materializing several
    // services, or parallel tests) never share — the first one's cleanup would otherwise
    // delete the second's scratch.
    static BUILD_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = BUILD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let scratch = build_scratch(anchor, seq)?;
    // Self-heal: a build normally removes its scratch on exit (even on error), but a hard
    // kill (SIGKILL/OOM/Ctrl-C/panic) orphans it. Before starting, drop any sibling
    // scratch whose owning process is gone, so crashed runs don't accumulate.
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
            let jobs = resolve_build_jobs(opts, mv.mem_mib());
            let (committed, states) = drive_microvm(
                &plan,
                &order,
                &build_args,
                &mv,
                jobs,
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
    let mut mv = make_microvm(opts, &scratch, &kernel.path, &agent.path, &timings)?;
    // One job budget for every unit's stages combined (not per unit), so concurrent work
    // stays within host RAM instead of multiplying live guests.
    let jobs = resolve_build_jobs(opts, mv.mem_mib());
    timings.note_jobs(jobs); // so the timing header reports "busy across N jobs"

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
        for unit in &units {
            let build_args: Vars = unit.build_args.iter().cloned().collect();
            let inputs = match &unit.input {
                UnitInput::Build {
                    dockerfiles,
                    contexts,
                } => load_inputs(dockerfiles, contexts),
                UnitInput::Image(image) => Ok(vec![image_plan_input(image)?]),
            }
            .with_context(|| format!("build unit {:?}", unit.label))?;
            let plan = Plan::from_dockerfiles(&inputs, &build_args)
                .with_context(|| format!("build unit {:?}", unit.label))?;
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
        let done = run_dag(
            &nodes,
            &deps,
            jobs,
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
            //   - a COPY --from=<stage> / RUN --mount=from=<stage> keys on the source
            //     stage's final key, so a change anywhere in the source stage chains
            //     into every consumer — without it, a consumer whose own instructions
            //     did not change would restore a snapshot holding the *old* source
            //     content. `--from=<image>` sources stay keyed by their reference text.
            let content = match &instr {
                Instruction::Copy(c) => match &c.from {
                    None => Some(context_files_hash(&stage.context, &c.sources)),
                    Some(r) => source_stage_key(plan, &out, r),
                },
                Instruction::Run(r) => {
                    // A --mount=from=<stage> keys on the source stage; a bind mount
                    // from the context keys on its files (source defaults to the whole
                    // context). --from=<image> and non-bind mounts contribute nothing.
                    let mut parts: Vec<String> = r
                        .mounts
                        .iter()
                        .filter_map(|m| match &m.from {
                            Some(f) => source_stage_key(plan, &out, f),
                            None if m.typ == "bind" => {
                                // Default source matches the executor's bind default (build/exec.rs);
                                // copy_src_files resolves both "/" and "." to the context root.
                                let src = m.source.clone().unwrap_or_else(|| "/".into());
                                Some(context_files_hash(&stage.context, &[src]))
                            }
                            None => None,
                        })
                        .collect();
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
    build_args: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let inputs = load_inputs(dockerfiles, contexts)?;
    let ba: Vars = build_args.iter().cloned().collect();
    let plan = Plan::from_dockerfiles(&inputs, &ba)?;
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
/// the consuming instruction's key. `None` when `x` is an external image (keyed by its
/// reference text alone) or an unresolvable `$VAR` ref (the same known limitation as
/// [`stage_source_refs`]). The source is always resolved first: it is a dependency, so
/// the topological order places it earlier.
fn source_stage_key(
    plan: &Plan,
    resolved: &HashMap<usize, Resolved>,
    reference: &str,
) -> Option<String> {
    let s = plan.stage_ref(reference)?;
    resolved.get(&s).map(|r| r.final_key.clone())
}

/// The cache key (`stage_key`) of one target stage in the merged Dockerfiles — the
/// content identity a unit image is fingerprinted with. `None` targets the last
/// stage, like a build. Resolves base digests/config over the network like a real
/// build, pruned to the target's dependency subgraph.
pub fn target_stage_key(
    dockerfiles: &[PathBuf],
    contexts: &[PathBuf],
    build_args: &[(String, String)],
    target: Option<&str>,
) -> Result<String> {
    let inputs = load_inputs(dockerfiles, contexts)?;
    let ba: Vars = build_args.iter().cloned().collect();
    let plan = Plan::from_dockerfiles(&inputs, &ba)?;
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
    // Route this stage's guest output through the progress reporter (line-buffered +
    // stage-prefixed) so concurrent stages stay legible.
    ex.set_output_sink(progress.stage_sink(display));
    // Fully cached: restore the final snapshot directly, nothing to probe or run.
    if let Some(key) = cached_final.get(&idx) {
        progress.stage_fully_cached(display);
        progress.restore_start(display, &name);
        let t_restore = Instant::now();
        let fs = restore_into(ex, &name, key)?;
        timings.record(Phase::CachePull, &name, t_restore.elapsed());
        progress.restore_done(display);
        ex.stage_end(&fs)?;
        return Ok(fs);
    }
    // Build-once across runners: take the lock on this stage's final content key (a no-op
    // unless the cache is a remote vk-registry) so peers building the same stage don't
    // duplicate it. After acquiring, re-check the cache — a peer may have finished while we
    // waited — and restore instead of building. The guard is held for the whole stage
    // (through the final `cache_save`) and releases on return.
    let _build_lock = match steps.last().map(|s| s.key.clone()) {
        Some(final_key) => {
            // On contention the lock names its holder; show it under this stage until acquired.
            let mut on_wait = |holder: &str| progress.wait_lock_start(display, &name, holder);
            let guard = ex.build_lock(&final_key, &mut on_wait);
            progress.wait_lock_done(display);
            if guard.is_some() && ex.cache_has(&final_key) {
                progress.stage_fully_cached(display);
                progress.restore_start(display, &name);
                let t_restore = Instant::now();
                let fs = restore_into(ex, &name, &final_key)?;
                timings.record(Phase::CachePull, &name, t_restore.elapsed());
                progress.restore_done(display);
                ex.stage_end(&fs)?;
                return Ok(fs);
            }
            guard
        }
        None => None,
    };
    // Declare the stage's inputs — the source stages it copies/mounts from, and its
    // build context — so the backend can attach them before the guest boots.
    ex.stage_sources(
        &stage_source_rootfs(plan, &stage.instructions, committed),
        &stage.context,
    )?;
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
    let r = ex.stage_end(&final_fs);
    progress.stage_finishing_done(display);
    r?;
    Ok(final_fs)
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
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(move || {
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
    let committed = run_dag(&needed_order, &deps, jobs, Some(&cancel), |idx, done| {
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
        )
    })?;
    Ok((committed, final_states(&resolved)))
}

/// Resolve the parallel build's job count: explicit `--build-jobs`, else the
/// `opts.build_jobs` (the `--build-jobs` flag or `[build] jobs`) when set, else RAM-auto —
/// each stage guest reserves `mem_mib`, so cap concurrency at ~80% of available RAM
/// divided by that, clamped to a sane ceiling. CPU is intentionally allowed to
/// oversubscribe (the host scheduler time-slices); RAM overcommit would OOM.
fn resolve_build_jobs(opts: &Options, mem_mib: u64) -> usize {
    if let Some(j) = opts.build_jobs {
        return j.max(1);
    }
    let avail = mem_available_mib().unwrap_or(8 * 1024);
    let usable = avail * 8 / 10;
    ((usable / mem_mib.max(1)) as usize).clamp(1, 16)
}

/// Remove build scratch orphaned by earlier runs that were hard-killed (SIGKILL, OOM,
/// Ctrl-C, panic) before their normal on-exit cleanup could run. Scratch dirs in `dir`
/// are named `<prefix><pid>-<seq>`; one whose owning `pid` is no longer a live process is
/// stale and removed. A dir owned by this process (a concurrent in-process build) or by a
/// live pid is left untouched — worst case an orphan survives, never a live build's
/// scratch deleted. Best-effort: any error (unreadable dir, racing removal) is ignored.
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
        if pid != me && !pid_alive(pid) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Whether `pid` is a live process. `kill(pid, 0)` sends no signal — it only reports
/// whether the target exists (`ESRCH` = gone; `EPERM` = alive but not ours, so live).
fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 performs only the existence/permission check, delivering nothing.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    // Read errno only on the failure branch: EPERM = alive but not ours; ESRCH = gone.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Available host RAM in MiB, from `/proc/meminfo` `MemAvailable`. `None` if unreadable.
fn mem_available_mib() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// The stage indices an instruction list references via `COPY --from` / `RUN
/// --mount=from` (distinct, in source order). Resolved on the raw `--from` text —
/// literal stage names; a `--from=$VAR` would not be seen (a known limitation).
fn stage_source_refs(plan: &Plan, instructions: &[Instruction]) -> Vec<usize> {
    let mut refs: Vec<&str> = Vec::new();
    for instr in instructions {
        match instr {
            Instruction::Copy(c) => {
                if let Some(f) = &c.from {
                    refs.push(f);
                }
            }
            Instruction::Run(r) => {
                for m in &r.mounts {
                    if let Some(f) = &m.from {
                        refs.push(f);
                    }
                }
            }
            _ => {}
        }
    }
    let mut seen: Vec<usize> = Vec::new();
    for r in refs {
        if let Some(si) = plan.stage_ref(r)
            && !seen.contains(&si)
        {
            seen.push(si);
        }
    }
    seen
}

/// [`stage_source_refs`] resolved to committed rootfs (stages not committed are
/// dropped — their consumers are fully cached, so no guest ever reads them).
fn stage_source_rootfs(
    plan: &Plan,
    instructions: &[Instruction],
    committed: &HashMap<usize, Rootfs>,
) -> Vec<Rootfs> {
    stage_source_refs(plan, instructions)
        .into_iter()
        .filter_map(|si| committed.get(&si).cloned())
        .collect()
}

/// sha256 hex of `s` — the base cache key.
fn hash_key(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

/// Chain the cache key with one instruction (an explicit canonical form, [`canonical`])
/// plus, for a context `COPY` or a `RUN --mount=type=bind`, a content hash of the files it
/// references. A change anywhere in the prefix — or in the referenced bytes — changes the key.
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
    hex(&h.finalize())
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

/// Apply a non-filesystem instruction (ENV/WORKDIR/USER/ENTRYPOINT/CMD) — updates the
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
        // ARG/LABEL/Other: no effect here (ARG feeds interpolation upstream; LABEL
        // would land in an exported image config).
        _ => {}
    }
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
                            pulled.push(ex.pull(from)?);
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
                    None => Some(ex.pull(reference)?), // COPY --from=<external image>
                },
            };
            ex.copy(fs, c, from.as_ref())?;
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

    /// Host-backend `build` / `build_inputs` (FROM scratch + COPY, no VM) — the path tests
    /// use to drive the whole pipeline without KVM. Production always builds in microVMs.
    fn build_host(opts: &Options) -> Result<Built> {
        let inputs = load_inputs(&opts.dockerfiles, &opts.contexts)?;
        build_backend(inputs, opts, false)
    }
    fn build_inputs_host(inputs: Vec<PlanInput>, opts: &Options) -> Result<Built> {
        build_backend(inputs, opts, false)
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

    /// The startup sweep removes scratch owned by a dead process but never a live pid's
    /// (nor this process's own, nor an unrelated dir).
    #[test]
    fn sweep_removes_only_dead_pid_scratch() {
        let root = std::env::temp_dir().join(format!("vk-sweep-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // A guaranteed-dead pid: spawn a child and reap it.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();

        let dead_dir = root.join(format!("{SCRATCH_PREFIX}{dead}-0"));
        let own_dir = root.join(format!("{SCRATCH_PREFIX}{}-3", std::process::id()));
        let live_dir = root.join(format!("{SCRATCH_PREFIX}1-0")); // pid 1 (init) always alive
        let unrelated = root.join("not-scratch");
        for d in [&dead_dir, &own_dir, &live_dir, &unrelated] {
            std::fs::create_dir_all(d).unwrap();
        }

        sweep_stale_scratch(&root, SCRATCH_PREFIX);

        assert!(!dead_dir.exists(), "dead-pid scratch should be swept");
        assert!(own_dir.exists(), "this process's own scratch must be kept");
        assert!(live_dir.exists(), "a live pid's scratch must be kept");
        assert!(unrelated.exists(), "a non-scratch dir must be untouched");
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
            self.inner.run(fs, cmd, mounts, state)
        }
        fn copy(&mut self, fs: &Rootfs, op: &parser::Copy, from: Option<&Rootfs>) -> Result<()> {
            self.inner.copy(fs, op, from)
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
            self.inner.transcript.push(format!("cache-save {key}"));
            self.cache.insert(key.to_string());
            self.last_saved = Some(key.to_string());
            Ok(())
        }
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
        assert_eq!(t.len(), 2, "{t:?}");
        assert!(
            t[0].starts_with("cache-has ") && t[0].ends_with("-> true"),
            "{t:?}"
        );
        assert!(t[1].starts_with("cache-restore "), "{t:?}");
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
        let dir = std::env::temp_dir().join(format!("vk-copyhash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
        let tmp = std::env::temp_dir().join(format!("vk-stagectx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
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

    #[test]
    fn run_bind_mount_keys_the_mounted_context_file() {
        // A `RUN --mount=type=bind` reads a file from the context but never copies it, so
        // its content must still enter the key — editing the mounted script busts the cache.
        // A `--mount=type=cache`, by contrast, reads no context bytes and must not.
        let tmp = std::env::temp_dir().join(format!("vk-runbind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
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
        let tmp = std::env::temp_dir().join(format!("vk-loadinputs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
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
        let tmp = std::env::temp_dir().join(format!("vk-crossctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
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
            let m: HashMap<String, String> =
                stage_keys(&files, &[], &[]).unwrap().into_iter().collect();
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
        // every stage key is a full sha256 hex, and the computation is deterministic.
        let r_again = resolve(src);
        for i in [0usize, 1] {
            assert_eq!(r[&i].final_key.len(), 64);
            assert_eq!(r[&i].final_key, r_again[&i].final_key);
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
        // a COPY --from=<external image> folds no stage key (keyed by its text alone):
        // the consumer's key is indifferent to unrelated stage edits.
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
ENTRYPOINT [\"/bin/app\"]
CMD [\"--serve\"]
FROM base AS child
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
        // an instruction-less child inherits everything
        let child = &r[&1].final_state;
        assert_eq!(child.entrypoint, ["/bin/app"]);
        assert_eq!(child.cmd, ["--serve"]);
        assert_eq!(child.env, [("A".to_string(), "1".to_string())]);
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
        let tmp = std::env::temp_dir().join(format!("vk-buildinputs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("f"), "x").unwrap();
        let src = "FROM scratch\nCOPY f /f\nENTRYPOINT [\"/f\"]\n";
        std::fs::write(tmp.join("Dockerfile"), src).unwrap();
        let opts = |out: PathBuf| Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            contexts: vec![],
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
        // identical past the primary superblock, whose UUID is random per build.
        // Relies on this fixture being a tiny single-group image: a larger one would
        // carry UUID-bearing backup superblocks (one per sparse_super group, 128 MiB
        // apart) past this offset — do not enlarge it without widening the compare.
        assert_eq!(a[2048..], b[2048..]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_writes_the_runtime_config_sidecar() {
        // a Host (FROM scratch + COPY) build exports the ext4 plus its config sidecar.
        let tmp = std::env::temp_dir().join(format!("vk-sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("f"), "x").unwrap();
        std::fs::write(
            tmp.join("Dockerfile"),
            "FROM scratch\nCOPY f /f\nENV PORT=6379\nUSER svc\nWORKDIR /srv\n\
             ENTRYPOINT [\"/bin/app\"]\nCMD [\"--port\", \"6379\"]\n",
        )
        .unwrap();
        let out = tmp.join("img.ext4");
        let built = build_host(&Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            contexts: vec![],
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
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn export_stamps_the_stage_key_freshness_uuid() {
        // Regression: an exported image must carry fingerprint([stage_key]) as its ext4 UUID,
        // so `vk fingerprint` (and the dev-VM staleness check) matches a freshly built image.
        // The export tail (flatten + normalize_superblock) otherwise leaves the base UUID,
        // which never equals the fingerprint — the source of the perpetual "stale" prompt.
        let tmp = std::env::temp_dir().join(format!("vk-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("f"), "x").unwrap();
        std::fs::write(tmp.join("Dockerfile"), "FROM scratch\nCOPY f /f\n").unwrap();
        let out = tmp.join("img.ext4");
        let dockerfiles = vec![tmp.join("Dockerfile")];
        build_host(&Options {
            dockerfiles: dockerfiles.clone(),
            target: None,
            contexts: vec![],
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
        let key = target_stage_key(&dockerfiles, &[], &[], None).unwrap();
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
        let tmp = std::env::temp_dir().join(format!("vk-stamp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("Dockerfile"), "FROM scratch\nCOPY Dockerfile /d\n").unwrap();
        let out = tmp.join("img.ext4");
        build_host(&Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            contexts: vec![],
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
    fn build_jobs_override_beats_auto() {
        let opts = |j: Option<usize>| Options {
            dockerfiles: vec![],
            target: None,
            contexts: vec![],
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
        // Explicit build_jobs (--build-jobs, or [build] jobs) wins and is floored to 1.
        assert_eq!(resolve_build_jobs(&opts(Some(3)), 2048), 3);
        assert_eq!(resolve_build_jobs(&opts(Some(0)), 2048), 1);
        // Auto is RAM-bounded and clamped to [1, 16].
        assert_eq!(resolve_build_jobs(&opts(None), u64::MAX / 2), 1);
        assert!((1..=16).contains(&resolve_build_jobs(&opts(None), 1)));
    }
}
