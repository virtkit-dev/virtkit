//! virtkit configuration. Exactly one TOML file is read, the first found of:
//! the `--config` flag, `$VIRTKIT_CONFIG`, the user config
//! (`~/.config/virtkit/config.toml`), the system config
//! (/etc/virtkit/config.toml). Every field has a default so the file can stay
//! minimal; no file at all yields the defaults (enough for `config`, not for
//! `prepare`, which validates the image paths). On a host enrolled with a fleet hub, the
//! hub's settings fill in the keys that file leaves unset; see [`crate::node::hub_settings`].

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/virtkit/config.toml";

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Per-job state lives under <state_dir>/jobs/<job id>/
    pub state_dir: Option<PathBuf>,
    /// VMM backend. Only `libkrun`, embedded in `vk`, remains: `cloud-hypervisor` is still
    /// parsed so an old config loads, but it boots on libkrun after a warning.
    pub vmm: Option<VmmBackend>,
    /// Materialized image bases (`<state_dir>/{registry,docker}/…/runner.ext4`) that have
    /// sat idle this many seconds — no VM overlaying them — are evicted the next time that
    /// same cache tier (`registry/` or `docker/`) takes a fresh pull; a base under a live
    /// overlay is never touched (reference-counted). Keep this well above zero: a near-zero
    /// value races the brief window between resolving a base and locking it. Default 1800
    /// (30 min). The compressed chunk store is the durable tier; the full ext4 is transient
    /// and re-materialized on demand.
    ///
    /// (A scalar, so it must stay ahead of the table-typed fields below for TOML
    /// serialization — a bare key after a `[section]` would bind to that section.)
    pub image_cache_idle_secs: Option<u64>,
    pub net: Net,
    /// Egress allowlist for `net.mode = "switch"`: the per-job switch refuses DNS
    /// names outside `allow_name` and direct connections outside `allow_ip` (plus
    /// the IPs it resolved for an allowed name). Empty (the default) = unrestricted
    /// — dev use leaves it empty; CI sets it as the corp egress gate.
    pub egress: Egress,
    /// Direct OCI boot of a registry image, backing the
    /// `MICROVM_IMAGE: docker/<name>[:tag|@sha256:…]` form; absent = that
    /// form is rejected
    pub docker: Option<Docker>,
    /// Native OCI bundle registry (push/pull with CDC+zstd chunk dedup), backing the
    /// `MICROVM_IMAGE: virtkit/<name>[:tag|@sha256:…]` form; absent = that form
    /// is rejected
    pub registry: Option<Registry>,
    /// Local guest bundles on the host filesystem, backing the
    /// `MICROVM_IMAGE: local/<name>` form (and the `local/default` default).
    pub local: Local,
    /// Defaults for `vk build` so a runner need not pass them every invocation;
    /// see [`Build`]. A CLI flag always overrides the matching config value.
    pub build: Build,
    /// Which memory node each VM this host boots is placed on; see [`Numa`]. On by default,
    /// and a no-op on the single-node hosts most machines are.
    pub numa: Numa,
    /// What `vk gc` collects beyond the image and checkout caches, and when; see [`Gc`].
    /// `vk config` omits it while untouched.
    #[serde(skip_serializing_if = "Gc::is_default")]
    pub gc: Gc,
    /// What `vk node` declares about this host to a fleet hub; see [`Node`]. `vk config`
    /// omits it while untouched.
    #[serde(skip_serializing_if = "Node::is_default")]
    pub node: Node,
    /// The GitLab custom executor: read by `vk gitlab
    /// config|prepare|run|cleanup|usage|supervise`, and — each for the subset it needs —
    /// by `vk gc` (the checkout-cache settings) and `vk tune` (the VM template and
    /// `[executor.schedule]`); never read by `vk run` /
    /// `vk build`. See [`Executor`]. Always present; an empty file is enough for its
    /// defaults (not for `prepare`, which validates the image paths). `vk config` omits it
    /// entirely when it is untouched, so a non-CI host is not shown a page of CI defaults.
    #[serde(skip_serializing_if = "Executor::is_default")]
    pub executor: Executor,
    /// The file this config was loaded from; None = built-in defaults (no file
    /// found). Set by [`Config::load`], not a config key.
    #[serde(skip)]
    pub source: Option<PathBuf>,
    /// The layers used by [`Config::load`]. Not a config key.
    #[serde(skip)]
    pub layers: Layers,
}

/// What a loaded config was made of: the local file and, on a host enrolled with a fleet hub,
/// the hub's settings under it, filling in what the file leaves unset.
#[derive(Debug, Default, Clone)]
pub struct Layers {
    /// The local file as read; empty with no file.
    pub local: toml::Table,
    /// The hub's settings taken, by dotted key: those the local file leaves unset.
    pub hub: std::collections::BTreeMap<String, serde_json::Value>,
    /// The dotted keys whose value an enrolled node derived from its host, where neither the
    /// file nor the hub sets them.
    pub detected: std::collections::BTreeSet<&'static str>,
}

/// VMM backend selector for the `vmm` config key. `cloud-hypervisor` and its old aliases
/// (`cloud_hypervisor`, `ch`) still parse so an old config loads, then warn at startup; a
/// typo still fails at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmmBackend {
    Libkrun,
    #[serde(alias = "cloud_hypervisor", alias = "ch")]
    CloudHypervisor,
}

/// Defaults for `vk build` (the experimental microVM Dockerfile builder). Most fields back a
/// CLI flag; the flag wins when given, so this just sets a host's defaults (e.g. the shared
/// instruction-cache registry and the build guest's kernel/agent). The host-tuning keys —
/// `cpus`, `mem`, `nice`, `ionice`, `cache_checkpoint_secs`, `no_mem_gate` — reach every
/// build path as process-wide state (see `build::set_tuning`) rather than as a per-build
/// argument; only `cpus` and `mem` have a flag, and it is per stage (`--stage-cpus`,
/// `--stage-mem`).
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Build {
    /// the build guest kernel (the pinned vmlinux with virtio + ext4 built in).
    pub kernel: Option<PathBuf>,
    /// the virtkit-agent injected into the build guest as PID 1.
    pub agent: Option<PathBuf>,
    /// instruction cache: a registry repo (a `vk-registry` server), an absolute store
    /// directory path, or `none` to disable; unset = the builtin local store.
    pub cache_registry: Option<String>,
    /// the cache registry speaks plain HTTP (a loopback vk-registry).
    pub cache_insecure: bool,
    /// PEM CA the cache registry's TLS cert chains to (rustls). Absent = system roots; set
    /// it when `cache_registry` is a remote vk-registry with a private/self-signed cert.
    pub cache_ca_file: Option<PathBuf>,
    /// HTTP Basic username for the cache registry. Empty = anonymous.
    pub cache_username: String,
    /// Path to a file holding the cache registry's Basic-auth password (read at runtime,
    /// trailing newline trimmed; only when `cache_username` is set). Provision 0600 out of band.
    pub cache_password_file: Option<PathBuf>,
    /// Path to a file holding a static bearer token for the cache registry — an alternative
    /// to `cache_username`/`cache_password_file` for a registry gated by `Auth::Bearer`.
    /// Takes precedence over Basic; read at runtime (trimmed), provision 0600.
    pub cache_token_file: Option<PathBuf>,
    /// how aggressively the instruction cache is populated: `auto` (default), `layers`
    /// (one snapshot per stage), or `instructions` (one per RUN/COPY).
    pub build_cache: crate::build::BuildCache,
    /// Skip adding an ext4 journal to the exported image (the build's own intermediate
    /// snapshots always stay journal-less regardless of this). A journal is added by
    /// default: a build output commonly outlives the build that produced it (e.g. attached
    /// read-write via `vk run --disk` across many later invocations), and a journal-less
    /// image left unclean by a non-graceful shutdown has no way to recover — deleted-inode
    /// references, `EUCLEAN`, `e2fsck` required by hand. Set this to opt back out.
    pub no_journal: bool,
    /// use a RAM tmpfs for each stage guest's `/tmp` instead of the default disk-backed
    /// scratch. Disk-backed `/tmp` (the default) bounds bulk `/tmp` writes by disk rather
    /// than ½·guest-RAM; set this to trade that for a RAM tmpfs. Default off (disk-backed).
    pub tmp_tmpfs: bool,
    /// Skip the host-memory admission gate: stages then start as soon as a `jobs` slot is
    /// free, without also waiting for the host to have room for the guest they are about to
    /// boot (the behaviour before the gate existed). The gate only ever narrows a build, so
    /// this is for a host where `jobs` is set by hand and deliberately overcommits — a
    /// build guest that balloons back most of its declared RAM, say. Default off (gated).
    pub no_mem_gate: bool,
    /// max stages built concurrently on the microVM backend (`--build-jobs` overrides).
    /// Unset = auto, bounded by the host's total RAM (each stage guest reserves `mem`).
    /// `1` forces a sequential build; `0` is refused when the config loads rather than read
    /// as a request for a build that runs nothing.
    pub jobs: Option<NonZeroUsize>,
    /// per-stage build guest vCPUs. Unset = the host's logical CPUs shared out among the
    /// stages running at once: a stage booting alone gets 4, one booting beside five
    /// others on a 12-CPU host 2 (never under 2). A set value goes to every stage as-is.
    pub cpus: Option<u32>,
    /// per-stage build guest RAM, e.g. "8G". Unset = 4G. A larger value lowers the
    /// RAM-derived `jobs` count, trading stage concurrency for per-stage throughput.
    pub mem: Option<String>,
    /// `auto` cache mode only: seconds of uncommitted run time in a stage before an
    /// intermediate snapshot is checkpointed. Unset = 20. Smaller = more snapshots (a late
    /// edit re-runs less), larger = fewer commits.
    pub cache_checkpoint_secs: Option<u64>,
    /// How much a build defers to the rest of the machine: the `nice` increment its stage
    /// guests, their helpers and its own worker threads start at, on top of whatever `vk`
    /// itself was started with. Unset = 10, which leaves a contended CPU to whatever the
    /// user is doing while the build still gets the whole machine when nothing else wants
    /// it; `0` renices nothing. Only ever raises the nice value — coming back down needs
    /// `RLIMIT_NICE` — and a value past the kernel's ceiling of 19 is clamped. See
    /// [`crate::prio`].
    pub nice: Option<u8>,
    /// The I/O priority class the same work starts at: `best-effort` (at its lowest level,
    /// the default), `idle`, or `none` to leave I/O priority alone. Only a block scheduler
    /// that honours I/O priority acts on it — BFQ, and mq-deadline; the `none` scheduler,
    /// what a host commonly leaves an NVMe on, ignores it, so this is no substitute for
    /// `nice`.
    pub ionice: Option<IoNice>,
    /// The node's own access to the registry its hub names, for a cache on that registry with
    /// no credential of its own ([`crate::build::cache_registry`]). Never read from a config.
    #[serde(skip)]
    pub(crate) node_access: Option<crate::node::registry_access::Source>,
}

/// `[build] ionice`: the I/O priority class a build's work runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IoNice {
    /// The ordinary class, at its lowest level: the build still gets its turn, behind
    /// everything asking at the default level.
    #[default]
    BestEffort,
    /// Only when nothing else wants the disk. The most a desktop can be spared, and the
    /// most a build can be starved by one.
    Idle,
    /// Leave the I/O priority as inherited.
    None,
}

/// Memory admission for CI jobs. A runner takes as many jobs as its `concurrent` limit
/// allows, with no idea what they will boot; past the host's RAM the OOM killer decides
/// which VM dies. With a budget set, a job reserves the guest RAM it is about to boot and
/// waits for room, oldest request first, so the host stays inside what it can back.
///
/// The budget is guest RAM, not host RAM: leave the difference for the VMMs themselves, the
/// tmpfs a `checkout_dir` may sit on, and everything else on the box.
///
/// Disk admission (`disk_admission`) keeps the filesystem the job dirs share from filling the
/// same way, and needs no budget: the filesystem's size is the budget.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Schedule {
    /// Total guest RAM this host admits at once, as an exact size (`"48G"`) or a share of this
    /// host's `MemTotal` rounded up to whole GiB (`"50%"`). Unset = no admission gate.
    pub mem_budget: Option<String>,
    /// Reserve what a job of this kind has actually been using rather than what it declares
    /// — jobs rarely touch their whole `MICROVM_MEM`, so declared sizes leave a host running
    /// far fewer of them than it could. Reservations then follow a job's recent peaks (with
    /// headroom, never above what it declares), and its first ever run falls back to the
    /// declared size. Default off: it trades a margin of safety for throughput, so turn it on
    /// once a few pipelines have been measured.
    pub from_history: bool,
    /// How long a job waits for room before giving up. It then exits a *system* failure,
    /// which GitLab retries when the job asks it to (`retry: { when: runner_system_failure }`)
    /// — set that on jobs you would rather see land on another runner than fail. Default 600.
    pub wait_timeout_secs: Option<u64>,
    /// Also hold a job back until the filesystem holding the job dirs (`<state_dir>/jobs`) has
    /// room for what its dir is expected to grow to — the rootfs overlay its guest writes, above
    /// all — on top of what the jobs already admitted there have yet to write. The expectation
    /// is the most its dir has held lately plus headroom (capped at the filesystem's size), or
    /// `disk_default` before it has a history. Its own test asks for at most what could come
    /// free (what is free now plus what the other admitted jobs' dirs hold), so a job alone on
    /// the filesystem never waits for disk; its claim on the ledger is still its full
    /// expectation. Free space is read off the filesystem, so whatever else fills it counts too.
    /// Independent of `mem_budget`; shares its queue and `wait_timeout_secs`. Default on;
    /// `false` turns it off.
    pub disk_admission: Option<bool>,
    /// The most jobs the runner is ever told to accept, whatever the host could take or a
    /// fleet hub allows: the ceiling in `min(estimate, hub ceiling, ceiling)`. On a fleet node
    /// taking the hub's jobs, it also caps placed jobs and reservations. At least one. Unset: no
    /// ceiling of the host's own.
    pub max_concurrency: Option<std::num::NonZeroU32>,
    /// What a job with no history of its own is expected to write into its job dir, as
    /// `"<n>G"`. Set larger than the filesystem, every such job fails at once. Default `"8G"`,
    /// capped at the filesystem's size.
    pub disk_default: Option<String>,
    /// Wait if admitting this job would exceed the host's online CPUs times this positive
    /// ratio (rounded down, at least one): `2` allows twice as many vCPUs as host CPUs.
    /// Counts each job's guest and services. Shares `mem_budget`'s queue and
    /// `wait_timeout_secs`. Unset: no vCPU gate, except on an enrolled fleet node, where it is 2.
    pub cpu_overcommit: Option<f64>,
}

/// `[executor.schedule] cpu_overcommit` on a host enrolled with a fleet hub when unset.
pub const ENROLLED_CPU_OVERCOMMIT: f64 = 2.0;

/// `[executor.schedule] wait_timeout_secs` when unset.
pub const WAIT_TIMEOUT_SECS: u64 = 600;

/// What `vk gc` collects beyond the image and checkout caches, and when the commands that fill
/// them run it in the background. Every key has a default, so a host needs none of them; an
/// older `vk` refuses a config that has the table at all.
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Gc {
    /// Let `vk run` (not of a UEFI bundle), `vk build`, `vk export`, `vk registry pull` and a
    /// booting `vk dev` start a `vk gc` pass in the background, at most every
    /// `interval_hours`, and sooner when the data dir's filesystem has less than `min_free`
    /// left. Default on; `VK_GC_AUTO=0` also turns it off.
    pub auto: Option<bool>,
    /// Hours between background passes; `0`: only under `min_free`. Default 24.
    pub interval_hours: Option<u64>,
    /// Free space below which a background pass starts whatever the interval, and goes on
    /// past the idle windows to images unused for 10 minutes, the build cache's least recently
    /// used entries and run images unused for a day, until this much is free again: a share
    /// of the filesystem (`"10%"`), a size (`"20G"`), or `"none"`. Default: 10% of the
    /// filesystem, at most 20G. A category turned off stays off.
    pub min_free: Option<Limit>,
    /// Drop a build-cache entry unused for this many days; `0` drops none for its age.
    /// Default 14.
    pub build_cache_retention_days: Option<u64>,
    /// Then drop the least recently used build-cache entries until the build cache fits:
    /// a share of its filesystem (`"10%"`), a size (`"50G"`), or `"none"`. Default: 10% of its
    /// filesystem, at most 50G. Entries used within the last day stay regardless.
    pub build_cache_max: Option<Limit>,
    /// Remove the boot images of a `vk dev` environment stopped this many days, as
    /// `vk dev prune --images` does; its next `up` rebuilds them. One whose config has a
    /// `hooks.create` is left unless `dev_images_with_create_hook`. `0` removes none. Default 14.
    pub dev_image_idle_days: Option<u64>,
    /// Also reclaim the images of an environment whose config has a `hooks.create`, which its
    /// next boot runs again on its persistent storage — so only for hooks that are idempotent.
    /// Default false: such environments are reported and left to `vk dev prune`.
    pub dev_images_with_create_hook: Option<bool>,
    /// Remove the root image a `vk run --state-dir` built into its state dir once no run has
    /// held the dir for this many days; the next run there builds it again. `0` removes none.
    /// Default 14.
    pub run_image_idle_days: Option<u64>,
}

/// The default of [`Gc::interval_hours`].
const GC_INTERVAL_HOURS: u64 = 24;
/// The ceiling of [`Gc::min_free`]'s default, 10% of the filesystem.
const MIN_FREE_DEFAULT_CEILING: u64 = 20 << 30;
/// The default of [`Gc::build_cache_retention_days`].
const BUILD_CACHE_RETENTION_DAYS: u64 = 14;
/// The default of [`Gc::dev_image_idle_days`] and [`Gc::run_image_idle_days`].
const IMAGE_IDLE_DAYS: u64 = 14;
/// The ceiling of [`Gc::build_cache_max`]'s default, 10% of the filesystem.
const BUILD_CACHE_MAX_DEFAULT_CEILING: u64 = 50 << 30;

impl Gc {
    fn is_default(&self) -> bool {
        *self == Gc::default()
    }

    /// Whether commands start a background pass.
    pub fn auto(&self) -> bool {
        self.auto.unwrap_or(true)
    }

    /// The time between background passes; `None` for none but under `min_free`.
    pub fn interval(&self) -> Option<std::time::Duration> {
        let hours = self.interval_hours.unwrap_or(GC_INTERVAL_HOURS);
        (hours > 0).then(|| std::time::Duration::from_secs(hours.saturating_mul(3600)))
    }

    /// The free space a filesystem of `fs_total` bytes is kept above; `None`: no floor.
    pub fn min_free(&self, fs_total: u64) -> Option<u64> {
        match self.min_free {
            Some(limit) => limit.of(fs_total),
            None => Limit::Percent(10)
                .of(fs_total)
                .map(|floor| floor.min(MIN_FREE_DEFAULT_CEILING)),
        }
    }

    /// How long an unused build-cache entry stays; `None` while its age drops none.
    pub fn build_cache_retention(&self) -> Option<std::time::Duration> {
        match self
            .build_cache_retention_days
            .unwrap_or(BUILD_CACHE_RETENTION_DAYS)
        {
            0 => None,
            days => Some(std::time::Duration::from_secs(days.saturating_mul(86_400))),
        }
    }

    /// How long a stopped dev environment keeps its boot images; `None`: for good.
    pub fn dev_image_idle(&self) -> Option<std::time::Duration> {
        days(self.dev_image_idle_days.unwrap_or(IMAGE_IDLE_DAYS))
    }

    /// How long a `vk run --state-dir` dir keeps its root image unused; `None`: for good.
    pub fn run_image_idle(&self) -> Option<std::time::Duration> {
        days(self.run_image_idle_days.unwrap_or(IMAGE_IDLE_DAYS))
    }

    /// Whether environments with a `hooks.create` have their images reclaimed too.
    pub fn dev_images_with_create_hook(&self) -> bool {
        self.dev_images_with_create_hook.unwrap_or(false)
    }

    /// The most the build cache may take on a filesystem of `fs_total` bytes; `None`: uncapped.
    pub fn build_cache_max(&self, fs_total: u64) -> Option<u64> {
        match self.build_cache_max {
            Some(limit) => limit.of(fs_total),
            None => Limit::Percent(10)
                .of(fs_total)
                .map(|cap| cap.min(BUILD_CACHE_MAX_DEFAULT_CEILING)),
        }
    }
}

/// `n` days; `None` for `0`, the spelling of never.
fn days(n: u64) -> Option<std::time::Duration> {
    (n > 0).then(|| std::time::Duration::from_secs(n.saturating_mul(86_400)))
}

/// A size limit: a share of the filesystem it applies to (`"10%"`), a size with a binary
/// suffix (`"50G"`, `"512M"`, `"2T"`), or `"none"`. Its own parser rather than another of the
/// size parsers here (`vmm`'s, the schedule's), which take neither a share nor `"none"`, and read
/// a bare number as MiB where a cap of a bare number is more likely a mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Limit {
    None,
    Percent(u8),
    Bytes(u64),
}

impl Limit {
    /// The limit on a filesystem of `fs_total` bytes; `None` for no limit.
    pub fn of(self, fs_total: u64) -> Option<u64> {
        match self {
            Limit::None => None,
            Limit::Percent(p) => Some(fs_total / 100 * u64::from(p)),
            Limit::Bytes(b) => Some(b),
        }
    }
}

impl TryFrom<String> for Limit {
    type Error = String;

    fn try_from(s: String) -> Result<Limit, String> {
        let bad = || format!("{s:?} is not a size: write \"10%\", \"50G\" or \"none\"");
        let t = s.trim();
        if t == "none" {
            return Ok(Limit::None);
        }
        if let Some(p) = t.strip_suffix('%') {
            return match p.parse::<u8>() {
                Ok(p @ 1..=100) => Ok(Limit::Percent(p)),
                _ => Err(bad()),
            };
        }
        let (digits, shift) = match t.char_indices().last() {
            Some((i, 'K' | 'k')) => (&t[..i], 10),
            Some((i, 'M' | 'm')) => (&t[..i], 20),
            Some((i, 'G' | 'g')) => (&t[..i], 30),
            Some((i, 'T' | 't')) => (&t[..i], 40),
            _ => return Err(bad()),
        };
        digits
            .parse::<u64>()
            .ok()
            .filter(|&n| n > 0)
            .and_then(|n| n.checked_mul(1u64 << shift))
            .map(Limit::Bytes)
            .ok_or_else(bad)
    }
}

impl From<Limit> for String {
    fn from(l: Limit) -> String {
        match l {
            Limit::None => "none".into(),
            Limit::Percent(p) => format!("{p}%"),
            Limit::Bytes(b) => {
                let (n, unit) = [(40, 'T'), (30, 'G'), (20, 'M'), (10, 'K')]
                    .into_iter()
                    .find(|&(shift, _)| b.is_multiple_of(1u64 << shift))
                    .map_or((b, ' '), |(shift, unit)| (b >> shift, unit));
                format!("{n}{unit}").trim_end().to_string()
            }
        }
    }
}

/// A size with a binary suffix (`"8G"`, `"512M"`, `"2T"`, `"64K"`), as [`Limit`] reads one:
/// neither a share nor `"none"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ByteSize(pub u64);

impl TryFrom<String> for ByteSize {
    type Error = String;

    fn try_from(s: String) -> Result<ByteSize, String> {
        let shown = format!("{s:?}");
        match Limit::try_from(s) {
            Ok(Limit::Bytes(b)) => Ok(ByteSize(b)),
            _ => Err(format!("{shown} is not a size: write \"8G\" or \"512M\"")),
        }
    }
}

impl From<ByteSize> for String {
    fn from(b: ByteSize) -> String {
        Limit::Bytes(b.0).into()
    }
}

/// `[numa]` — NUMA placement for every VM this host boots. On a multi-socket host a VM whose
/// memory is scattered across the sockets and whose vCPUs run on the far side of it loses
/// throughput to the interconnect for as long as it runs; placed on one node — vCPUs pinned
/// to it, memory preferring it — it does not. A single-node host has nothing to place, and
/// nothing here changes it.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Numa {
    pub mode: NumaMode,
}

/// `[numa] mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NumaMode {
    /// Place each VM on the emptiest node it fits on — by the admission ledger for a CI job
    /// on a host that has one, else by the nodes' live free memory — and interleave one that
    /// fits nowhere.
    #[default]
    Auto,
    /// Place nothing; the kernel decides, as it did before.
    Off,
    /// Interleave every VM across all nodes, choosing none. For a host whose VMs are all
    /// larger than a node, or one where the per-node accounting cannot be trusted because
    /// something outside virtkit is taking the memory.
    Interleave,
}

/// `[node]` — what `vk node` tells a fleet hub about this host that it cannot measure, and
/// the runner config `vk` edits directly (`runner_config`, read by `vk tune` too).
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Node {
    /// How fast the filesystem holding the job dirs (`<state_dir>/jobs`) is: `"fast"` or
    /// `"slow"`. Declared rather than measured, so a busy moment never changes what the node
    /// reports. Unset: not declared.
    pub jobs_speed: Option<vk_hub_proto::SpeedClass>,
    /// The same for the host-checkout root ([`Config::checkout_root`]).
    pub checkouts_speed: Option<vk_hub_proto::SpeedClass>,
    /// How often the memory each VM on the host holds is measured for the hub: a walk of
    /// every process of every VM, which on a large VMM takes a while. New VMs are measured
    /// when they appear; heartbeats in between repeat the last figures. Unset: 30.
    pub workload_mem_secs: Option<u64>,
    /// A gitlab-runner config this user owns, whose `concurrent` `vk` sets directly rather
    /// than leaving the number for `vk-runnerctl`. Unset: the runner is root's — or, with
    /// `runner = "managed"`, `~/.gitlab-runner/config.toml`.
    pub runner_config: Option<PathBuf>,
    /// Who runs gitlab-runner: `"external"` — a service of its own, whose concurrency is all a
    /// hub can steer, so a node refuses a reset and updates only with `--force` — or
    /// `"managed"`: `vk node run` runs it as a child, `gitlab-runner run --config
    /// <runner_config>`, restarts it when it dies, and stops it with `SIGQUIT` (finish the
    /// running jobs, take no new ones) when acquisition is to stop. Or `"none"`: the host runs
    /// no gitlab-runner and takes only the jobs the hub places, which the node stops itself;
    /// `vk node run` refuses to start where it finds a runner with the vk executor. Unset:
    /// `"none"` where no gitlab-runner shows on the host, else `"external"`
    /// ([`crate::node::runner_mode`]).
    pub runner: Option<vk_hub_proto::RunnerMode>,
    /// The gitlab-runner binary a managed runner runs. Unset: `gitlab-runner`, on `PATH`.
    pub gitlab_runner: Option<PathBuf>,
    /// Validation argv run after `vk check`, before accepting the new `vk`. For example,
    /// `["sh", "-c", "$VK_BINARY run alpine true"]` boots a small image with the release on
    /// trial, named by `VK_BINARY`. Must exit 0 within `validate_timeout_secs`.
    /// Unset: `vk check` alone.
    pub validate: Vec<String>,
    /// How long `validate` may take. Unset: 600.
    pub validate_timeout_secs: Option<u64>,
    /// Let an update install an older `vk` than the one running. Off by default, so a hub —
    /// or whoever holds it — cannot take the node back to a release with a known flaw. Even
    /// on, nothing older than the first release that takes part in a trial is installed.
    pub allow_downgrade: bool,
    /// The ed25519 public keys, base64, whose signature an update's release must carry —
    /// `vk release-key generate` prints one. Unset: the keys the hub gave when the node
    /// enrolled, pinned in its enrollment; with none, releases are not checked.
    pub release_keys: Vec<String>,
    /// Whether an update needs a signature by a configured or pinned release key. Defaults
    /// to true when any key exists. With keys, a supplied signature is always checked.
    pub require_signed: Option<bool>,
    /// Labels for job placement: a `vk-gitlab` runner requires nodes with all its labels.
    /// At most 32 labels, each 1–64 ASCII letters, digits or `-_.:/=` characters.
    pub labels: Vec<String>,
}

impl Node {
    fn is_default(&self) -> bool {
        *self == Node::default()
    }

    /// How often workloads' memory is measured, at least a second.
    pub fn workload_mem_every(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.workload_mem_secs.unwrap_or(30).max(1))
    }

    /// How long `validate` may take.
    pub fn validate_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.validate_timeout_secs.unwrap_or(600))
    }
}

/// Host credentials forwarded into job VMs. The SSH agent is relayed over a vsock
/// forward to the runner's `$SSH_AUTH_SOCK`, so the guest's ssh/git use the host keys
/// without the keys ever entering the guest (same model as the services registry proxy).
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Auth {
    /// Forward the runner's SSH agent into every job VM (no-op if `$SSH_AUTH_SOCK` is
    /// unset on the runner). Default off.
    pub ssh_agent: bool,
}

/// The GitLab custom executor. Read by `vk gitlab
/// config|prepare|run|cleanup|usage|supervise`, and — each for the subset it needs — by
/// `vk gc` (the checkout-cache settings) and `vk tune` (the VM template and
/// `[executor.schedule]`); nothing here is touched by `vk run` or
/// `vk build`. The scalar keys and the nested `[executor.vm]` / `[executor.guest]` /
/// `[executor.share]` / `[executor.auth]` / `[executor.schedule]` tables together
/// describe the CI job VM and how jobs are admitted.
///
/// `tools_dir` is a host directory of static tool binaries (e.g. `git`, `git-lfs`,
/// `gitlab-runner`) that virtkit shares **read-only over virtio-fs** into every job
/// VM; the in-guest agent links each one onto the guest PATH (`/usr/local/bin`), but
/// only for a tool the job image does not already provide (per-image opt-out, checked
/// in-guest). Dynamic: the binaries stay on the host and are baked into no bundle, so
/// updating them needs no re-conversion. On a host that runs a gitlab-runner of its own (one
/// `vk node` manages, or one on systemd's `PATH`), `vk check --feature gitlab` fails a
/// `tools_dir` without `gitlab-runner`, even for a runner whose job images all ship their own:
/// a job without one transfers no artifacts, caches or dotenv reports and still passes. Jobs a
/// hub places need only `git`: the node transfers their artifacts and caches.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Executor {
    /// Resolved at each job start. Every name on the way, a directory or a symlink at any depth,
    /// must sit where no one but the `vk` user or root can replace it: in a directory writable
    /// by no one else, or a sticky one where the entry is owned by them. Each symlink is also
    /// followed only from outside every tree jobs can write: whoever can replace a name on the
    /// way chooses what host directory every job reads. The directory it leads to may neither
    /// lie in nor hold such a tree — a link or not: a read-write `[executor.share]`, the host
    /// checkouts while `host_checkout` is on, and the atop archive while `atop` is on. What
    /// that directory holds is trusted as configured: its own mode is not checked.
    pub tools_dir: Option<PathBuf>,
    /// Check the job's git sources out on the HOST at prepare and share the tree into the
    /// guest over virtio-fs, instead of the in-guest `get_sources` clone. The job then sets
    /// `GIT_STRATEGY: none` so the checkout is reused and the git token never enters the guest
    /// (a security win), and the host has the tree available to build a git-defined image
    /// (`ci-boots-git-defined-images`). Off by default.
    pub host_checkout: bool,
    /// Host storage directory for `host_checkout`. Trees are keyed by concurrent slot + project
    /// in its private `vk` subtree, so sibling content from another executor is outside the idle
    /// sweep. Unset = `<state_dir>/checkouts` directly. Point it at the runner's
    /// RAM-backed builds tmpfs (e.g. `/builds`) so the clone (and, with `checkout_overlay =
    /// false`, every in-job write to the shared tree) stays in host RAM instead of hitting the
    /// state disk.
    pub checkout_dir: Option<PathBuf>,
    /// How long a reusable host checkout may sit with no prepare or guest sharing it before it
    /// is removed. Reclamation runs before each host checkout and from `vk gc`; unset inherits
    /// the top-level `image_cache_idle_secs` (30 minutes by default).
    pub checkout_cache_idle_secs: Option<u64>,
    /// How long an entry of the host's Windows build cache (a layer, an install, a medium, a
    /// fetched ISO: tens of GB each, hours to make again) may go unused before the sweep a CI
    /// host runs after each Windows build removes it; one a kept layer stands on stays. Unset
    /// = 7 days. `0` is refused when the config loads: a build drops its reference to the
    /// install under a layer it just published, and a sweep that scanned the layers before the
    /// publish would then take that install at once.
    pub windows_cache_idle_secs: Option<std::num::NonZeroU64>,
    /// Approved sha256 digests for install media (ISOs, drivers) outside a placed job's Windows
    /// build context, fetched from the registry's file store or found in the host's media cache.
    /// Applies on nodes caching placed jobs' builds by scope. The store holds whatever anyone
    /// put there, accessed under the node's credential, while the job's Dockerfile names the
    /// digest. Empty: none. Each is 64 hex digits, read lowercased.
    #[serde(default, deserialize_with = "media_digests")]
    pub windows_media: Vec<String>,
    /// Mount the `host_checkout` tree in the guest behind a tmpfs-backed overlayfs (default
    /// on). The share is then exported read-only — the guest can never touch the host tree —
    /// and every in-job write runs at guest-native speed instead of a 50–90µs synchronous
    /// virtio-fs round-trip per op. Guest writes land in guest RAM (an overlay tmpfs sized by
    /// `checkout_overlay_size`; raise MICROVM_MEM if a job needs more) and are discarded with
    /// the VM, which prepare's re-clean of the checkout did anyway. `false` restores the
    /// direct read-write mount — a rw virtio-fs share into an untrusted job guest is added
    /// host-side attack surface, and the checkout is re-cloned for every job rather than
    /// fetched.
    pub checkout_overlay: bool,
    /// How much of the VM's memory the `checkout_overlay` layer may take, as a tmpfs `size=`:
    /// a percentage (`"80%"`, the default) or an absolute `"12G"`/`"512M"`.
    ///
    /// The cap is what a build tree has to fit under, and a job that reaches it fails with
    /// `ENOSPC` however empty the host's disks are — so the figure trades two failures against
    /// each other. Set too low, a job the VM had memory for dies for want of a partition; set
    /// near 100%, the layer can starve the job's own processes and the kernel reaches for the
    /// OOM killer instead, which is far harder to read than a full filesystem. It costs nothing
    /// until a job reaches it — tmpfs pages are allocated on use — and the reservation admission
    /// takes out is `MICROVM_MEM` either way, so raising it commits no host memory that was not
    /// already set aside.
    ///
    /// 80% rather than the kernel's own 50% tmpfs default: that default protects a
    /// general-purpose machine's long-lived services from an unevictable tmpfs, and a one-shot
    /// job guest has none to protect. `"50%"` restores it. Each job's usage line reports the
    /// mark it reached against this capacity, which is what to size it from.
    pub checkout_overlay_size: String,
    /// With `checkout_overlay`, start the job with the whole worktree already in the overlay's
    /// tmpfs upper (default on): at boot the executor packs the checkout — everything but
    /// `.git` — into one tar that the guest streams through its DAX window and unpacks in RAM.
    /// Every read of the tree then comes from guest memory, where the read-only lower answers
    /// each file with a virtio-fs round trip (~200 µs; a 100k-file tree is ~20 s per pass) on
    /// every pass a build tool, scanner or git makes over it. Costs the tree's size in guest
    /// RAM, counted against `checkout_overlay_size`, and a second or two at boot. `false`
    /// leaves the lower to serve files on demand.
    pub checkout_tmpfs: bool,
    /// Record what each job's guest does: the in-guest agent samples its own `/proc` every
    /// `atop_interval_secs` and writes the samples to a per-job log under
    /// `<state_dir>/atop/<date>/<job>/`, in the text format `atop -P` prints — so an existing
    /// atop parser reads them. On by default: a host-side monitor sees one VMM process per job
    /// with every concurrent job mixed into it, while the guest *is* the job, and the log is
    /// the only account of what happened inside a VM that is destroyed when the job ends.
    ///
    /// What it costs, since it is on by default. The guest is given a read-write virtio-fs
    /// share — one directory, its own, which it can write anything and any amount into and
    /// leave symlinks in, so a reader of the log opens it without following them; and the
    /// guest kernel is booted with `psi=1`, which the guest's own scheduler pays for in
    /// exchange for the pressure figures. `false` gives up the recording and the share; idle
    /// page-cache trimming asks for `psi=1` as well, so the guest keeps paying for it unless
    /// `[executor.vm] reclaim` is `"off"` (or `[executor.vm] balloon` is, which stops the
    /// trimming too).
    pub atop: bool,
    /// Seconds between samples. Must be at least 1. Default 10.
    pub atop_interval_secs: u64,
    /// How many days back the archive keeps beside today's, counted in whole UTC days rather
    /// than elapsed time. A day past the window is dropped whole, by the first job recorded
    /// the following day. Default 14, as the runner hosts keep their own atop logs; `0` keeps
    /// only jobs recorded today — and drops the log of a job still running from the day
    /// before out from under it. Any job outliving the window loses its log the same way.
    pub atop_retention_days: u64,
    /// Let a job VM with compose services run commands in them: `vk-agent exec --service NAME
    /// [-b] [-t] [--user U] [--dir D] [--env K=V] [--clear-env] -- CMD…`, the host's `vk exec
    /// --service` reached over the guest's host command channel and confined
    /// to that one form and the job's own services — no other host command, no other job. Each
    /// request still starts a host `vk` process (at most 4 at once), and runs its command as
    /// whatever user it names in the service, root included; a service with wider egress than
    /// the job lends it that egress. Default true.
    pub guest_service_exec: bool,
    /// Let a job a fleet hub placed build an image from a context of its own: `vk-agent build
    /// [-f FILE] [--target STAGE] [--build-arg NAME=VALUE]… --as NAME CONTEXT`, sent over the
    /// guest's host command channel, built on the host as a `dockerfile:` image is, and
    /// published to the job's pipeline namespace as `pipeline/build/<NAME>`. Offered only to a
    /// job whose start names a pipeline namespace and carries a registry token. Unset: on,
    /// unless a guest registry proxy lends this node's credential (`[registry] proxy_guests`
    /// without `guest_credential = "job"`), which reaches every pipeline's images; `true`
    /// beside such a proxy is refused when the config loads. `false` turns it off.
    pub guest_build: Option<bool>,
    /// The most a `vk-agent build` context may take on the wire, tar headers included: a size
    /// with a binary suffix (`"8G"`, the default; `"512M"`). Crossing it stops the transfer.
    pub guest_build_max_context: ByteSize,
    /// The most entries, files and directories, a `vk-agent build` context may hold. Default
    /// 1000000. Crossing it stops the transfer.
    pub guest_build_max_entries: std::num::NonZeroU64,
    /// `[executor.vm]` — the job VM template: cpus/mem/hostname and the per-job
    /// MICROVM_CPUS/MICROVM_MEM ceilings. Only the CI job path reads it; `vk run` takes
    /// its sizing from flags and service VMs from the service name.
    pub vm: Vm,
    /// `[executor.guest]` — paths and the run command inside the job VM, reported to
    /// gitlab-runner by `vk gitlab config`.
    pub guest: Guest,
    /// `[executor.share]` — dev only: host dir shared as the guest's /workdir over
    /// virtio-fs (the POC runner image assembles itself from the repo). CI images must
    /// NOT use this: the job clones into the VM, nothing of the host is exposed.
    pub share: Option<Share>,
    /// `[executor.auth]` — host credentials forwarded into job VMs (currently the SSH
    /// agent); see [`Auth`].
    pub auth: Auth,
    /// `[executor.schedule]` — how many CI jobs this host lets run at once, by the memory
    /// they boot; see [`Schedule`]. Off by default — jobs are admitted the moment
    /// gitlab-runner hands them over.
    pub schedule: Schedule,
}

/// The default `checkout_overlay_size`. Named because the guest applies the kernel's own tmpfs
/// default when it is told nothing, so this is the policy and that is only the fallback.
pub const CHECKOUT_OVERLAY_SIZE: &str = "80%";

impl Executor {
    /// Whether the executor is entirely at its defaults — nothing on this host configures the
    /// GitLab executor. `vk config` uses it to omit the whole `[executor]` tree, which would
    /// otherwise print a page of CI defaults on a host that only runs `vk run`/`vk dev`.
    /// Compared through TOML so no field type has to grow a `PartialEq` for this alone.
    pub fn is_default(&self) -> bool {
        toml::Value::try_from(self).ok() == toml::Value::try_from(Self::default()).ok()
    }
}

impl Default for Executor {
    fn default() -> Self {
        Executor {
            tools_dir: None,
            host_checkout: false,
            checkout_dir: None,
            checkout_cache_idle_secs: None,
            windows_cache_idle_secs: None,
            windows_media: Vec::new(),
            checkout_overlay: true,
            checkout_overlay_size: CHECKOUT_OVERLAY_SIZE.to_string(),
            checkout_tmpfs: true,
            atop: true,
            atop_interval_secs: 10,
            atop_retention_days: 14,
            guest_service_exec: true,
            guest_build: None,
            guest_build_max_context: ByteSize(8 << 30),
            guest_build_max_entries: std::num::NonZeroU64::MIN.saturating_add(999_999),
            vm: Vm::default(),
            guest: Guest::default(),
            share: None,
            auth: Auth::default(),
            schedule: Schedule::default(),
        }
    }
}

/// One phase's egress allowlist for the per-job switch (`net.mode = "switch"`).
///
/// An *absent* list is unconstrained; a *present* list is an allowlist, so an explicit
/// empty list (`allow_name = []`) denies that dimension. A policy is unrestricted only
/// when both lists are absent (`audit` may still be on — the observe-to-discover mode);
/// once either is present the phase is a restricted allowlist and an omitted list denies
/// its dimension (DNS-resolved IPs of allowed names stay reachable via pinning).
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct EgressPolicy {
    /// Allowed destination IPv4 CIDRs for direct (non-DNS-resolved) egress, each
    /// optionally scoped to a single port as `CIDR:port` (e.g. `10.0.0.0/8:443`).
    /// `None` = unconstrained; `Some([])` = deny all direct-IP egress.
    pub allow_ip: Option<Vec<String>>,
    /// Allowed DNS name suffixes, dot-anchored (e.g. `corp.example.com` also allows
    /// `*.corp.example.com`). `None` = unconstrained; `Some([])` = deny all names.
    pub allow_name: Option<Vec<String>>,
    /// Audit mode: record every external domain this phase's guest resolves and print the
    /// "domains contacted" summary into the job trace. Independent of the allowlist — leave
    /// both lists absent (unrestricted egress) and set `audit = true` to observe without
    /// blocking and discover the allowlist a job needs. A job may also opt in per-run with
    /// the `MICROVM_EGRESS_AUDIT` / `MICROVM_BUILD_EGRESS_AUDIT` variables.
    pub audit: bool,
}

/// Egress for the CI job: the flat `[egress]` keys govern the run phase (the booted job
/// guest, and the service VMs sharing its LAN); the `[egress.build]` subtable governs the
/// build phase (git-defined image / compose `build:` service `RUN` steps). Each phase is an
/// [`EgressPolicy`]; a job may only *narrow* either via `MICROVM_EGRESS_*` /
/// `MICROVM_BUILD_EGRESS_*` variables, never widen.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Egress {
    /// Run phase (booted guest). Absent lists = unrestricted; `[]` = deny.
    pub allow_ip: Option<Vec<String>>,
    pub allow_name: Option<Vec<String>>,
    pub audit: bool,
    /// Dry-run the run-phase allowlist: evaluate it, report would-be denials in the job trace,
    /// block nothing (a denied name still resolves). A job may opt in with
    /// `MICROVM_EGRESS_DRY_RUN` only when the host sets no run-phase cap.
    pub dry_run: bool,
    /// `[egress.build]` — build phase RUN egress. Absent (the default) = unrestricted, as
    /// `docker build`.
    pub build: EgressPolicy,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Local {
    /// Directory of local guest bundles: each `<dir>/<name>/` is a bundle
    /// (`runner.ext4` + `boot.kind`, optionally `runner.ext4.json`). Unset =
    /// `<state_dir>/images` (see `Local::dir`).
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Vm {
    pub cpus: u32,
    pub mem: String,
    pub hostname: String,
    /// Guest vsock port the in-VM virtkit-agent listens on
    pub vsock_port: u32,
    /// virtio-balloon with free_page_reporting: memory freed by the guest
    /// returns to the host mid-job, making overcommit safe (like containers)
    pub balloon: bool,
    /// Idle page-cache trimming in every guest this host boots (job and service VMs), done
    /// while the guest is not under memory pressure. `"auto"` evicts file cache untouched for
    /// a minute or two (multi-gen LRU); `"512M"`/`"2G"` or `"5%"` keep that much as a fixed
    /// floor; `"off"` keeps everything. What goes returns to the host through the balloon.
    pub reclaim: String,
    /// DAX window per virtio-fs share in job and service VMs: a size (default `"8G"`),
    /// `"off"`, `"<size>:always"` or `"<size>:inode=<min>"`. Maps the host page cache into
    /// guest address space, avoiding a copy per VM. A bare size maps only regular files of
    /// 1M and more (`dax=inode`): a mapping costs a host mmap per 2M range whatever the
    /// file's size, which a source tree's small files never repay; `:always` maps every
    /// file, `:inode=` sets the floor. Reserves address space, not memory.
    pub dax: Option<String>,
    /// Ceilings for the per-job MICROVM_CPUS/MICROVM_MEM variables; unset =
    /// jobs cannot request more than the cpus/mem defaults above
    pub max_cpus: Option<u32>,
    pub max_mem: Option<String>,
    /// Expose VMX/SVM to the job's guest so it can boot microVMs of its own
    /// (`vk` inside `vk`). Off by default: nesting reaches host KVM's nested
    /// paths, so it widens what a job can attack. Deliberately runner-only —
    /// there is no MICROVM_* variable and a job's compose file is still refused,
    /// because the grant is the host admin's to make, not a job's.
    pub nested: bool,
    /// Appended verbatim to the kernel command line
    pub cmdline_extra: String,
    /// prepare: max seconds from the VMM spawn to a vk-agent status reply
    pub boot_timeout_secs: u64,
    /// cleanup: seconds granted to the ACPI poweroff before escalating
    pub shutdown_timeout_secs: u64,
}

impl Default for Vm {
    fn default() -> Self {
        Vm {
            cpus: 4,
            mem: "4G".into(),
            hostname: "vk".into(),
            vsock_port: 4444,
            balloon: true,
            reclaim: "auto".into(),
            dax: None,
            max_cpus: None,
            max_mem: None,
            nested: false,
            cmdline_extra: String::new(),
            boot_timeout_secs: 120,
            shutdown_timeout_secs: 15,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Guest {
    /// Paths inside the VM, reported to gitlab-runner by `config`
    pub builds_dir: String,
    pub cache_dir: String,
    /// Command the stage scripts are piped into (stdin), run by the in-VM agent
    pub run_command: Vec<String>,
    /// In-guest tmpfs mounts, "path:size" (e.g. "/builds:64G") — mounted by the agent
    /// from the VIRTKIT_TMPFS kernel cmdline variable. RAM-backed scratch space for
    /// hosts with slow disks; count it into vm.mem.
    pub tmpfs: Vec<String>,
}

impl Default for Guest {
    fn default() -> Self {
        Guest {
            builds_dir: "/builds".into(),
            cache_dir: "/cache".into(),
            run_command: vec!["bash".into()],
            tmpfs: vec![],
        }
    }
}

/// `[docker]` — OPTIONAL registry proxy for direct OCI image boots. Present, it *routes*
/// pulls: the `docker/<name>` MICROVM_IMAGE form and bare docker-hub-style names go
/// through `repo` (with these credentials); a `[docker.mirror]` redirects Docker Hub
/// references onto a pull-through mirror instead (the `registry-mirrors` equivalent).
/// A reference neither claims — and every reference when this section is absent — is
/// offered to the vk-registry `[build] cache_registry`/`[registry]` already names, under
/// its own registry as a prefix (`<vk-registry>/ghcr.io/o/i`), and pulled from the
/// registry it names when that one does not relay it. It never refuses an image: the
/// microVM boundary is the security model, so image sources are not gated. The native
/// OCI client fetches the image, the embedded vk-agent is PID 1, the embedded kernel
/// boots it. Auth mirrors `[registry]`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Docker {
    /// Registry repository prefix the `docker/<name>` form and bare image names are routed
    /// through, e.g. "registry.example.com/team" — a pull-through cache/proxy, not an
    /// allowlist. Absent = no such source (e.g. a `[docker]` present only to carry a
    /// `[docker.mirror]`); a `docker/<name>` job then pulls the bare name directly.
    /// Optional so the section can be empty or mirror-only.
    #[serde(default)]
    pub repo: Option<String>,
    /// PEM CA bundle the registry's TLS cert chains to (rustls). Absent = system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// HTTP Basic username. Empty = anonymous.
    #[serde(default)]
    pub username: String,
    /// Path to a file holding the Basic-auth password (read at runtime, trailing newline
    /// trimmed; sent only when `username` is set, and not read at all when a `token_file`
    /// supersedes it). Provision out of band, 0600.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Path to a file holding a static bearer token — an alternative to `username`/
    /// `password_file` for a registry gated by a bearer token, which a `vk-registry` in
    /// `mode = "accounts"` is: its API keys are bearer tokens and it has no shared
    /// password to configure instead. Takes precedence over Basic when set; read at
    /// runtime (trimmed), provision 0600. Sent over TLS (see `ca_file`).
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Plain HTTP registry (a local/insecure registry); default TLS.
    #[serde(default)]
    pub insecure: bool,
    /// Docker Hub pull-through mirror (the `registry-mirrors` equivalent): bare
    /// docker-hub names and explicit `docker.io/…` refs are fetched through it — with
    /// the `library/` prefix added for official images, and NO direct-to-Hub fallback —
    /// so a job needs no direct Docker Hub egress. Absent = Hub refs use the legacy
    /// routing (bare names onto `repo`, host-qualified refs pulled directly).
    #[serde(default)]
    pub mirror: Option<Mirror>,
}

/// `[docker.mirror]` — a Docker Hub pull-through cache (a Nexus/Artifactory/`registry:2`
/// proxy of `registry-1.docker.io`). ONLY Docker Hub references route through it — a bare
/// name, or one explicitly under docker.io/index.docker.io/registry-1.docker.io; any other
/// registry is left untouched. Auth is independent of the `[docker]` repo (a mirror usually
/// carries its own account).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mirror {
    /// Registry prefix Hub pulls are rewritten onto, e.g. "hq-nexus.example.com:8440".
    pub repo: String,
    /// PEM CA bundle the mirror's TLS cert chains to (rustls). Absent = system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// HTTP Basic username. Empty = anonymous.
    #[serde(default)]
    pub username: String,
    /// Path to a file holding the Basic-auth password (read at runtime, trailing newline
    /// trimmed; sent only when `username` is set, and not read at all when a `token_file`
    /// supersedes it). Provision out of band, 0600.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Path to a file holding a static bearer token, as `[docker]`'s — a mirror fronted by
    /// a `vk-registry` in `mode = "accounts"` is gated by one. Takes precedence over Basic,
    /// and is sent over TLS (see `ca_file`).
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Plain HTTP mirror (a local/insecure registry); default TLS.
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Registry repository prefix for the bundles — fixed host side: the
    /// allowlist (jobs only pick name[:ref]), e.g. "registry.example.com/team"
    pub repo: String,
    /// PEM CA bundle the registry's TLS cert chains to (rustls; the binary stays
    /// musl-static). Absent = the system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// HTTP Basic username. Empty = anonymous (no Authorization header sent).
    #[serde(default)]
    pub username: String,
    /// Path to a file holding the Basic-auth password — the secret stays OUT of
    /// this config; it is read at runtime (trailing newline trimmed) only when
    /// `username` is set. Provision it out of band with restrictive perms (0600).
    /// Sent over the (TLS, see `ca_file`) connection; pair with an HTTPS `repo`.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Path to a file holding a static bearer token — an alternative to `username`/
    /// `password_file` for a registry gated by `Auth::Bearer`. Takes precedence over Basic
    /// when set; read at runtime (trimmed), provision 0600. Sent over TLS (see `ca_file`).
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Plain HTTP registry (a local/insecure registry); default TLS
    #[serde(default)]
    pub insecure: bool,
    /// Push ext4 chunks addressed by the **uncompressed** chunk digest (the casync
    /// model): the client uploads raw chunks and the registry stores them zstd —
    /// dedup becomes compression-level-independent and the client never compresses
    /// to learn a digest (no chunkmap). Requires a cooperating registry that
    /// understands the encoding (virtkit's own `regserve`); a dumb OCI registry
    /// rejects it (the wire bytes don't hash to the uncompressed digest). Tri-state:
    /// unset = **auto** (probe the registry's `/v2/` for the capability and use
    /// transparent-zstd only if advertised, else the compressed-digest layers any OCI
    /// registry stores compactly); `true`/`false` force the choice. Pull auto-detects
    /// either form from the chunk media type regardless.
    #[serde(default)]
    pub transparent_zstd: Option<bool>,
    /// Run a credential-injecting registry proxy for executor guests: each job's switch
    /// exposes this registry at `registry.vk`, injecting these credentials, so a job
    /// pushes/pulls without ever holding the secret. Off by default.
    #[serde(default)]
    pub proxy_guests: bool,
    /// What the guest's registry proxy injects. `"node"` (the default): this section's own
    /// credential, and only when `proxy_guests` is on. `"job"`: the registry token the hub
    /// minted for the job, scoped to its namespaces, with the lock API and `/dav/files/`
    /// proxied too; the proxy then runs for every job, and one without a token gets a proxy
    /// that refuses everything, never this section's credential. That includes every job a
    /// local gitlab-runner gives this node: under `"job"`, only jobs the hub placed reach the
    /// registry through `registry.vk`. `"job-or-node"`: `"job"` for jobs the hub placed; a job
    /// a local gitlab-runner gives this node gets the token the hub gives the node for its
    /// runner's guests, scoped to what the hub's namespaces grant guests, and a proxy that
    /// refuses everything while the node holds none. Never this section's own credential.
    /// Either way the proxy needs `net.mode = "switch"`, the only network that serves
    /// `registry.vk`.
    #[serde(default)]
    pub guest_credential: GuestCredential,
    /// The root of the `ci-pipeline` namespace's path on this registry, as the hub's config
    /// gives that path: one or more leading components, `"ci-pipeline"` by default. A job's
    /// image naming a repository under it directly is refused, whatever the job, so a job
    /// reaches pipeline images through `pipeline/build/` alone.
    #[serde(default)]
    pub pipeline_root: Option<String>,
    /// A runtime bearer token for reaching the registry on a job's behalf, overriding the
    /// configured credential. Never read from a config. [`crate::registry::at_path`] sets it,
    /// required, on a copy for the job's own content, and a placed job's context on its own
    /// config when the node has no credential of its own; the node's `[registry]` is
    /// unchanged. [`crate::registry::credential`] supplies it to every request through that copy.
    #[serde(skip)]
    pub(crate) job_token: Option<JobToken>,
    /// Where the node's own token for this registry is read, on an enrolled host whose
    /// `[registry]` the hub names ([`crate::node::registry_access`]). Never read from a config.
    #[serde(skip)]
    pub(crate) node_access: Option<crate::node::registry_access::Source>,
}

/// A job's registry token, kept out of `Debug`, when it expires, and whether a request may go
/// on without it once it has.
#[derive(Clone)]
pub(crate) struct JobToken {
    token: String,
    /// Seconds since the epoch.
    expires_at: u64,
    /// Whether the request needs this token: the job's own content (its pipeline's images,
    /// its build cache), which no other credential may reach in its place.
    required: bool,
}

impl JobToken {
    pub(crate) fn new(token: &str, expires_at: u64) -> JobToken {
        JobToken {
            token: token.to_string(),
            expires_at,
            required: false,
        }
    }

    /// The token the hub gave a job for `registry`.
    pub(crate) fn of(registry: &vk_hub_proto::dispatch::JobRegistry) -> JobToken {
        JobToken::new(&registry.token, registry.expires_at)
    }

    /// This token, needed by every request made with it: past its expiry they fail, rather
    /// than go on with the node's own access ([`crate::registry::credential`]).
    pub(crate) fn required(self) -> JobToken {
        JobToken {
            required: true,
            ..self
        }
    }

    /// Whether requests need this token ([`JobToken::required`]).
    pub(crate) fn is_required(&self) -> bool {
        self.required
    }

    /// The token while it is live. From its expiry on, a registry refuses it, so a request
    /// does not send it.
    pub(crate) fn live(&self) -> Option<&str> {
        (vk_peer::now_secs() < self.expires_at).then_some(self.token.as_str())
    }

    /// The token, live or not.
    #[cfg(test)]
    pub(crate) fn secret(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for JobToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// `[registry] guest_credential`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestCredential {
    #[default]
    Node,
    Job,
    #[serde(rename = "job-or-node")]
    JobOrNode,
}

impl Registry {
    /// The store directory when `repo` names a local store rather than a remote
    /// registry: an absolute path (`/…`) or a `file://` URL. registry.rs then
    /// reads/writes the regserve content-addressed store in-process — no server,
    /// no port, no auth; `ca_file`/`username`/`insecure`/`transparent_zstd` are
    /// all meaningless and ignored for such a repo.
    pub fn local_root(&self) -> Option<PathBuf> {
        Self::local_root_of(&self.repo)
    }

    /// The remote registry's base URL, `<scheme>://<host>[:<port>]` with the host lowercased,
    /// and the repository prefix `repo` names below it (no leading or trailing `/`); `None`
    /// for a local store or a `repo` naming no host.
    pub fn base_url(&self) -> Option<(String, &str)> {
        if self.local_root().is_some() {
            return None;
        }
        let repo = self
            .repo
            .strip_prefix("https://")
            .or_else(|| self.repo.strip_prefix("http://"))
            .unwrap_or(&self.repo);
        let (authority, prefix) = repo.split_once('/').unwrap_or((repo, ""));
        if authority.is_empty() {
            return None;
        }
        let scheme = if self.insecure { "http" } else { "https" };
        Some((
            format!("{scheme}://{}", authority.to_ascii_lowercase()),
            prefix.trim_matches('/'),
        ))
    }

    /// [`Registry::pipeline_root`], defaulted.
    pub fn pipeline_root(&self) -> &str {
        self.pipeline_root.as_deref().unwrap_or("ci-pipeline")
    }

    /// Whether the guest's proxy lends this section's own credential: `proxy_guests` under
    /// `guest_credential = "node"`.
    pub fn lends_node_credential(&self) -> bool {
        self.proxy_guests && self.guest_credential == GuestCredential::Node
    }

    /// Whether the guest's proxy lends a placed job's token rather than this section's
    /// credential: `guest_credential = "job"` or `"job-or-node"` on a remote registry.
    pub fn lends_job_token(&self) -> bool {
        self.guest_credential != GuestCredential::Node && self.local_root().is_none()
    }

    /// Whether this section names a credential of the node's own: a `token_file`, or a
    /// `username`.
    pub fn has_credential(&self) -> bool {
        self.token_file.is_some() || !self.username.is_empty()
    }

    /// The node's own token for this registry, read again whenever the hub renewed it: `None`
    /// where it holds none for this registry; an error once the one it holds expired, rather
    /// than reaching the registry anonymously.
    pub(crate) fn node_token(&self) -> Result<Option<crate::node::registry_access::NodeToken>> {
        match &self.node_access {
            Some(source) => source.live(vk_peer::now_secs()),
            None => Ok(None),
        }
    }

    /// [`Registry::local_root`]'s test applied to a repo string that is not (yet) a
    /// configured registry — the instruction cache's destination, which reaches this from
    /// `[build] cache_registry` or `--cache-registry` and is a store or a server by the
    /// same rule.
    pub fn local_root_of(repo: &str) -> Option<PathBuf> {
        if let Some(p) = repo.strip_prefix("file://") {
            return Some(PathBuf::from(p));
        }
        repo.starts_with('/').then(|| PathBuf::from(repo))
    }

    /// Build a `Registry` for the build-sharing path, from the CLI flags rather than a
    /// config file (only push/pull-by-fingerprint; nothing boots or is cache-evicted here).
    pub fn for_share(
        repo: String,
        insecure: bool,
        ca_file: Option<PathBuf>,
        username: String,
        password_file: Option<PathBuf>,
        token_file: Option<PathBuf>,
        transparent_zstd: Option<bool>,
    ) -> Registry {
        Registry {
            repo,
            ca_file,
            username,
            password_file,
            token_file,
            insecure,
            transparent_zstd,
            proxy_guests: false,
            guest_credential: GuestCredential::Node,
            pipeline_root: None,
            job_token: None,
            node_access: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    /// Resolved at each job start, under the same rule as `[executor] tools_dir`, the host
    /// checkouts and the atop archive being the guest-writable trees it must stay out of and
    /// not hold: whoever can replace a name on the way chooses what host directory jobs read,
    /// and write unless `readonly`.
    pub dir: PathBuf,
    #[serde(default = "default_true")]
    pub readonly: bool,
}

/// `[executor] windows_media`: sha256 digests, lowercased, refused unless 64 hex digits each.
fn media_digests<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let digests: Vec<String> = Deserialize::deserialize(d)?;
    digests
        .into_iter()
        .map(|digest| {
            let lower = digest.to_ascii_lowercase();
            if lower.len() == 64 && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(lower)
            } else {
                Err(serde::de::Error::custom(format!(
                    "windows_media: {digest:?} is not a sha256 digest (64 hex digits)"
                )))
            }
        })
        .collect()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Net {
    /// "none"; "tap" (pre-created persistent tap; one VM at a time per tap);
    /// "pool" (a leased tap from the host pool — the hardened host networking);
    /// or "switch" (an unprivileged per-job userspace switch: a socket-backed virtio-net
    /// device, with `[egress]` enforced by the switch).
    pub mode: String,
    pub tap: String,
    pub mac: String,
    /// mode = "switch": base of the per-NIC port range. Interface i uses `net_port + i`
    /// at `<vsock.sock>_<net_port + i>`: libkrun backs its virtio-net device with that
    /// socket. Must differ from the services port.
    pub net_port: u32,
    /// Static guest config passed on the kernel command line (the kernel `ip=`
    /// autoconfig param + VIRTKIT_VM_DNS); ip is CIDR ("172.18.0.250/16")
    pub ip: String,
    /// Gateway/DNS; in pool mode they default to the subnet's .1 (the bridge)
    pub gw: String,
    pub dns: String,
    /// mode = "pool": host-precreated taps <tap_prefix>0..<count-1>, all on a
    /// NATed bridge; VM i gets a deterministic IP in `subnet` (see net.rs)
    pub tap_prefix: String,
    pub count: u32,
    pub subnet: String,
}

impl Default for Net {
    fn default() -> Self {
        Net {
            mode: "none".into(),
            tap: String::new(),
            mac: "52:54:00:d2:f0:01".into(),
            net_port: 1024,
            ip: String::new(),
            gw: String::new(),
            dns: String::new(),
            tap_prefix: "civtap".into(),
            count: 32,
            subnet: "192.168.231.0/24".into(),
        }
    }
}

/// The user-level config path: `$XDG_CONFIG_HOME/virtkit/config.toml`, else
/// `~/.config/virtkit/config.toml`. None when neither XDG_CONFIG_HOME nor HOME
/// is set (a bare service environment) — the system path still applies then.
pub fn user_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join("virtkit/config.toml"));
    }
    let home = std::env::var_os("HOME").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(home).join(".config/virtkit/config.toml"))
}

/// The pure tail of [`Config::load`]: read `explicit` when given (any failure,
/// including absence, is an error — the caller named that file), else the first
/// existing fallback; nothing found = the built-in defaults. On a host enrolled with a fleet
/// hub, the hub's settings fill in what the file leaves unset; when they would leave the
/// config unloadable, they are warned about and ignored. The loaded file is
/// recorded in `Config::source`. Split from `load` so tests can drive it
/// without mutating the process environment.
fn load_resolved(explicit: Option<PathBuf>, fallbacks: &[PathBuf]) -> Result<Config> {
    let path = match explicit {
        Some(p) => Some(p),
        None => fallbacks.iter().find(|p| p.is_file()).cloned(),
    };
    let local = match &path {
        Some(path) => read_local(path)?,
        None => toml::Table::new(),
    };
    let shown = path.as_deref().map(Path::display);
    let parsing = || match &shown {
        Some(path) => format!("parsing {path}"),
        None => "loading the built-in defaults".to_string(),
    };
    let mut cfg = from_table(local.clone()).with_context(parsing)?;
    if let Some(hub) = crate::node::hub_settings::layer(cfg.state_dir()) {
        let mut merged = local.clone();
        let taken = crate::node::hub_settings::merge(&mut merged, &hub);
        match from_table(merged) {
            Ok(with_hub) => {
                cfg = with_hub;
                cfg.layers.hub = taken;
                // The node's own access is for the registry the hub names, never one the file
                // sets.
                if cfg.layers.hub.contains_key("registry") {
                    let source = crate::node::registry_access::source(&cfg);
                    cfg.build.node_access.clone_from(&source);
                    if let Some(registry) = cfg.registry.as_mut() {
                        registry.node_access = source;
                    }
                }
            }
            Err(e) => eprintln!(
                "virtkit: warning: ignoring the fleet hub's settings, which leave the \
                 configuration unloadable: {e:#}"
            ),
        }
    }
    cfg.layers.local = local;
    if crate::node::enrolled(&cfg) {
        enrolled_defaults(
            &mut cfg,
            crate::schedule::host_total_mib(),
            Some(crate::node::online_cpus()),
        );
    }
    for warning in ineffective_settings(&cfg) {
        match &shown {
            Some(path) => eprintln!("virtkit: warning: {path}: {warning}"),
            None => eprintln!("virtkit: warning: {warning}"),
        }
    }
    cfg.source = path;
    Ok(cfg)
}

/// Fill in what a host enrolled with a fleet hub takes from its own size where neither the
/// local file nor the hub sets it (`docs/fleet-design.md`, *Defaults on an enrolled node*): a
/// memory budget of [`enrolled_budget_gib`], a per-job vCPU ceiling of the host's `cpus`
/// online, a vCPU overcommit of [`ENROLLED_CPU_OVERCOMMIT`], and the base VM held to them, so
/// a job that asks for nothing fits. A figure this host cannot read leaves its default as it
/// is. Its jobs get the per-job switch's network unless the local file says otherwise: the
/// hub's egress layer narrows it, and only the switch serves `registry.vk`. The hub never sets
/// the mode, so it takes only the file's.
fn enrolled_defaults(cfg: &mut Config, total_mib: Option<u64>, cpus: Option<u32>) {
    if !crate::node::hub_settings::is_set(&cfg.layers.local, "net.mode") {
        cfg.net.mode = "switch".into();
    }
    let detected = &mut cfg.layers.detected;
    let schedule = &mut cfg.executor.schedule;
    if schedule.mem_budget.is_none() {
        schedule.mem_budget = total_mib
            .map(enrolled_budget_gib)
            .filter(|gib| *gib > 0)
            .map(|gib| format!("{gib}G"));
        if schedule.mem_budget.is_some() {
            detected.insert("executor.schedule.mem_budget");
        }
    }
    let overcommit = *schedule
        .cpu_overcommit
        .get_or_insert(ENROLLED_CPU_OVERCOMMIT);
    let vm = &mut cfg.executor.vm;
    if vm.max_cpus.is_none() {
        vm.max_cpus = cpus.filter(|n| *n > 0);
        if vm.max_cpus.is_some() {
            detected.insert("executor.vm.max_cpus");
        }
    }
    let set = |key| {
        crate::node::hub_settings::is_set(&cfg.layers.local, key)
            || cfg.layers.hub.contains_key(key)
    };
    if !set("executor.vm.cpus") {
        let budget = cpus.and_then(|n| crate::vm::cpu_budget_of(n, overcommit));
        if let Some(max) = vm.max_cpus.into_iter().chain(budget).min()
            && max < vm.cpus
        {
            vm.cpus = max;
            cfg.layers.detected.insert("executor.vm.cpus");
        }
    }
    // A budget that does not resolve fails every job anyway, which says why.
    if !set("executor.vm.mem")
        && let Some(Ok(budget_mib)) = crate::vm::budget_mib(cfg)
        && let Ok(mem) = crate::vm::parse_gib(&cfg.executor.vm.mem)
        && let gib @ 1.. = budget_mib / 1024
        && gib < mem
    {
        cfg.executor.vm.mem = format!("{gib}G");
        cfg.layers.detected.insert("executor.vm.mem");
    }
}

/// An enrolled host's `total_mib` less the smaller of 4 GiB and 10 %, reserved for the host,
/// rounded down to whole GiB like job sizes.
fn enrolled_budget_gib(total_mib: u64) -> u64 {
    let reserve = total_mib.div_ceil(10).min(4 * 1024);
    total_mib.saturating_sub(reserve) / 1024
}

/// The local config file at `path` as a table, refused when it uses a key that moved and
/// stripped of keys that no longer do anything, with a warning.
fn read_local(path: &Path) -> Result<toml::Table> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut table: toml::Table =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    reject_migrated_keys(&table).with_context(|| format!("parsing {}", path.display()))?;
    for key in strip_removed_keys(&mut table) {
        eprintln!(
            "virtkit: warning: {}: ignoring `{key}`, which no longer has any effect; remove it",
            path.display()
        );
    }
    Ok(table)
}

/// The config `table` holds, refused when it sets what it cannot keep.
pub(crate) fn from_table(table: toml::Table) -> Result<Config> {
    let cfg: Config = table.try_into()?;
    refuse_conflicts(&cfg)?;
    Ok(cfg)
}

/// Reject old top-level sections with their new `[executor]` locations instead of bare
/// `deny_unknown_fields` errors. Report all stale keys at once so migration takes one pass.
fn reject_migrated_keys(table: &toml::Table) -> Result<()> {
    let hints: Vec<&str> = table
        .keys()
        .filter_map(|key| match key.as_str() {
            "vm" => Some("[vm] moved to [executor.vm]"),
            "guest" => Some("[guest] moved to [executor.guest]"),
            "share" => Some("[share] moved to [executor.share]"),
            "auth" => Some("[auth] moved to [executor.auth]"),
            "schedule" => Some("[schedule] moved to [executor.schedule]"),
            "gitlab" => {
                Some("[gitlab] keys now live directly under [executor] (dir is now tools_dir)")
            }
            "services" => Some("[services] is obsolete; remove it"),
            _ => None,
        })
        .collect();
    if !hints.is_empty() {
        anyhow::bail!("{}", hints.join("\n"));
    }
    Ok(())
}

/// Remove obsolete top-level keys and return their names so old configs load under
/// `deny_unknown_fields`. Unlike [`reject_migrated_keys`], these keys have no replacements:
/// the caller warns and continues.
fn strip_removed_keys(table: &mut toml::Table) -> Vec<&'static str> {
    // libkrun serves shares itself and needs neither virtiofsd nor an external VMM binary.
    const REMOVED: &[&str] = &["virtiofsd", "cloud_hypervisor"];
    let mut removed: Vec<&'static str> = REMOVED
        .iter()
        .copied()
        .filter(|key| table.remove(*key).is_some())
        .collect();
    if let Some(toml::Value::Table(build)) = table.get_mut("build")
        && build.remove("cloud_hypervisor").is_some()
    {
        removed.push("build.cloud_hypervisor");
    }
    removed
}

/// Refuse what `cfg` sets that it cannot keep.
fn refuse_conflicts(cfg: &Config) -> Result<()> {
    if let Some(ratio) = cfg.executor.schedule.cpu_overcommit
        && !(ratio.is_finite() && ratio > 0.0)
    {
        anyhow::bail!("`[executor.schedule] cpu_overcommit = {ratio}` must be a positive number");
    }
    if let Some(root) = cfg
        .registry
        .as_ref()
        .and_then(|r| r.pipeline_root.as_deref())
        && !vk_hub_proto::token::valid_prefix(root)
    {
        anyhow::bail!(
            "`[registry] pipeline_root = {root:?}` is not a repository path: lowercase \
             components separated by `/`"
        );
    }
    if cfg.executor.guest_build == Some(true)
        && cfg
            .registry
            .as_ref()
            .is_some_and(Registry::lends_node_credential)
    {
        anyhow::bail!(
            "`[executor] guest_build = true` beside `[registry] proxy_guests`, which lends every \
             job this node's credential and so every pipeline's images: set \
             `guest_credential = \"job\"` or drop `guest_build`"
        );
    }
    Ok(())
}

/// What `cfg` sets that has no effect, for the caller to warn about.
fn ineffective_settings(cfg: &Config) -> Vec<&'static str> {
    let mut found = Vec::new();
    if let Some(rg) = &cfg.registry
        && rg.guest_credential != GuestCredential::Node
        && !rg.lends_job_token()
    {
        found.push(
            "`[registry] guest_credential = \"job\"` or `\"job-or-node\"` needs a remote \
             registry: on a local store, jobs get no registry proxy",
        );
    }
    if cfg.registry.as_ref().is_some_and(Registry::lends_job_token) && cfg.net.mode != "switch" {
        found.push(
            "`[registry] guest_credential = \"job\"` or `\"job-or-node\"` needs `[net] mode = \
             \"switch\"`, the only network that serves registry.vk: under another, jobs get no \
             registry proxy",
        );
    }
    found
}

impl Config {
    /// Load the config from the first file found: the `--config` flag, then
    /// `$VIRTKIT_CONFIG`, then the user config, then the system config (see the
    /// module doc). Exactly one file is read — no merging across tiers — with the hub's
    /// settings under it on an enrolled host.
    pub fn load(flag: Option<&Path>) -> Result<Config> {
        let explicit = flag
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("VIRTKIT_CONFIG").map(PathBuf::from));
        let fallbacks: Vec<PathBuf> = user_path()
            .into_iter()
            .chain([PathBuf::from(DEFAULT_PATH)])
            .collect();
        load_resolved(explicit, &fallbacks)
    }

    /// Whether a job may ask for `vk-agent build` (`[executor] guest_build`): unset, unless
    /// the guests' registry proxy lends this node's credential.
    pub fn guest_build(&self) -> bool {
        self.executor.guest_build.unwrap_or(true)
            && !self
                .registry
                .as_ref()
                .is_some_and(Registry::lends_node_credential)
    }

    pub fn state_dir(&self) -> &Path {
        self.state_dir
            .as_deref()
            .unwrap_or(Path::new("/var/lib/virtkit"))
    }

    /// The local-bundles directory resolved against a caller-chosen `state_dir`:
    /// `[local] dir` if set, else `<state_dir>/images`. Threading the state dir (rather
    /// than reading the config default) lets a non-CI caller (`vk run`) share the resolve
    /// path while keeping its cache under its own state dir.
    pub fn local_dir_under(&self, state_dir: &Path) -> PathBuf {
        match &self.local.dir {
            Some(dir) => dir.clone(),
            None => state_dir.join("images"),
        }
    }

    /// The GitLab host-checkout root: a private `vk` subtree of `[executor] checkout_dir` if set,
    /// else `<state_dir>/checkouts`. The namespace confines the sweep to virtkit's own trees, so
    /// an explicit root such as `/builds` can stay shared with another executor. The default root
    /// gets no such subtree: it is already virtkit's own directory, so
    /// interposing one would strand the checkouts a runner has in it to buy a guarantee that
    /// already holds. Takes no state dir on purpose, unlike [`Config::local_dir_under`] —
    /// checkouts are the executor's alone, so no caller can hand this the dev root `vk run`
    /// caches under and leave the idle sweep walking a tree nothing checks out into.
    pub fn checkout_root(&self) -> PathBuf {
        match self.executor.checkout_dir.as_ref() {
            Some(dir) => dir.join("vk"),
            None => self.state_dir().join("checkouts"),
        }
    }

    /// How long a materialized image base may sit idle (no live overlay) before the
    /// cache GC evicts it. Default 30 min.
    pub fn image_cache_idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.image_cache_idle_secs
                .unwrap_or(vk_hub_proto::DEFAULT_IMAGE_CACHE_IDLE_SECS),
        )
    }

    /// How long an unused GitLab host checkout stays cached. By default checkouts and
    /// materialized images share one cache lifetime, while a runner with expensive clones may
    /// keep checkouts longer without also pinning extracted image bases.
    pub fn checkout_cache_idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.executor
                .checkout_cache_idle_secs
                .unwrap_or_else(|| self.image_cache_idle().as_secs()),
        )
    }

    /// How long an unused entry of a CI host's Windows build cache stays. Not the image
    /// cache's lifetime: an entry costs hours to make again, not a decompression.
    pub fn windows_cache_idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.executor
                .windows_cache_idle_secs
                .map_or(DEFAULT_WINDOWS_CACHE_IDLE_SECS, std::num::NonZeroU64::get),
        )
    }
}

/// [`Config::windows_cache_idle`] when the config sets none: a week.
const DEFAULT_WINDOWS_CACHE_IDLE_SECS: u64 = 7 * 24 * 3600;

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(toml: &str) -> Registry {
        let cfg: Config = toml::from_str(&format!("[registry]\n{toml}")).unwrap();
        cfg.registry.unwrap()
    }

    /// One reading of `repo` for every client: the base URL, its host lowercased and its
    /// scheme from `insecure`, and the repository prefix below it.
    #[test]
    fn a_registry_has_one_base_url_and_prefix() {
        let rg = registry("repo = \"Reg.Example:5000/team/ci/\"\n");
        assert_eq!(
            rg.base_url(),
            Some(("https://reg.example:5000".to_string(), "team/ci"))
        );
        let rg = registry("repo = \"http://10.0.0.5:5000\"\ninsecure = true\n");
        assert_eq!(
            rg.base_url(),
            Some(("http://10.0.0.5:5000".to_string(), ""))
        );
        assert_eq!(registry("repo = \"/srv/store\"\n").base_url(), None);
        assert_eq!(registry("repo = \"https:///x\"\n").base_url(), None);
    }

    /// Only a remote registry under `"job"` or `"job-or-node"` lends a job's token; neither
    /// lends the node's own credential.
    #[test]
    fn only_a_remote_registry_under_job_lends_the_token() {
        assert!(
            registry("repo = \"reg.example/t\"\nguest_credential = \"job\"\n").lends_job_token()
        );
        let either = registry(
            "repo = \"reg.example/t\"\nproxy_guests = true\nguest_credential = \"job-or-node\"\n",
        );
        assert_eq!(either.guest_credential, GuestCredential::JobOrNode);
        assert!(either.lends_job_token());
        assert!(!either.lends_node_credential());
        assert!(!registry("repo = \"reg.example/t\"\n").lends_job_token());
        assert!(!registry("repo = \"/srv/store\"\nguest_credential = \"job\"\n").lends_job_token());
    }

    /// `"job"` on a local store, or off the switch network, lends nothing: the load warns.
    #[test]
    fn job_credential_on_a_local_store_is_warned_about() {
        let cfg = |toml: &str| -> Config { toml::from_str(toml).unwrap() };
        let local = cfg("[registry]\nrepo = \"/srv/store\"\nguest_credential = \"job\"\n");
        assert_eq!(ineffective_settings(&local).len(), 1);
        let job = "[registry]\nrepo = \"reg.example/t\"\nguest_credential = \"job\"\n";
        let remote = cfg(&format!("{job}[net]\nmode = \"switch\"\n"));
        assert!(ineffective_settings(&remote).is_empty());
        let tap = cfg(&format!("{job}[net]\nmode = \"tap\"\n"));
        assert_eq!(ineffective_settings(&tap).len(), 1);
        let node = cfg("[registry]\nrepo = \"/srv/store\"\n");
        assert!(ineffective_settings(&node).is_empty());
        assert!(ineffective_settings(&Config::default()).is_empty());
    }

    /// A scratch dir of config files for the load_resolved tests; removed on drop.
    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Dir {
            let d = std::env::temp_dir().join(format!("vk-cfg-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            Dir(d)
        }
        fn file(&self, name: &str, text: &str) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, text).unwrap();
            p
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_explicit_file_wins_over_fallbacks() {
        let dir = Dir::new("explicit");
        let explicit = dir.file("explicit.toml", "[executor.vm]\ncpus = 7\n");
        let fallback = dir.file("fallback.toml", "[executor.vm]\ncpus = 9\n");
        let cfg = load_resolved(Some(explicit.clone()), std::slice::from_ref(&fallback)).unwrap();
        assert_eq!(cfg.executor.vm.cpus, 7);
        assert_eq!(cfg.source.as_deref(), Some(explicit.as_path()));
    }

    /// On an enrolled host the hub's settings fill in what the file leaves unset; they are
    /// ignored for another enrollment, or when unreadable.
    #[test]
    fn hub_settings_fill_in_under_the_file_on_an_enrolled_host() {
        let dir = Dir::new("hub-settings");
        let state = dir.0.join("state");
        let node = state.join("node");
        std::fs::create_dir_all(&node).unwrap();
        let node_id = "ab".repeat(16);
        std::fs::write(
            node.join("enrollment.json"),
            format!(r#"{{"hub": "https://hub.example", "node_id": "{node_id}"}}"#),
        )
        .unwrap();
        let settings = |hub: &str| {
            std::fs::write(
                node.join("settings.json"),
                format!(
                    r#"{{"hub": "{hub}", "node_id": "{node_id}", "generation": 3,
                        "settings": {{"executor.vm.cpus": 8, "executor.vm.max_cpus": 16,
                                      "state_dir": "/elsewhere"}}}}"#
                ),
            )
            .unwrap();
        };
        settings("https://hub.example");
        let file = dir.file(
            "c.toml",
            &format!("state_dir = {state:?}\n[executor.vm]\ncpus = 4\n"),
        );
        let cfg = load_resolved(Some(file.clone()), &[]).unwrap();
        assert_eq!(cfg.executor.vm.cpus, 4);
        assert_eq!(cfg.executor.vm.max_cpus, Some(16));
        assert_eq!(cfg.state_dir.as_deref(), Some(state.as_path()));
        assert_eq!(
            cfg.layers.hub.keys().collect::<Vec<_>>(),
            ["executor.vm.max_cpus"]
        );
        // Else the host's own size, as on any enrolled host.
        let online = Some(crate::node::online_cpus());
        settings("https://other.example");
        let cfg = load_resolved(Some(file.clone()), &[]).unwrap();
        assert_eq!(cfg.executor.vm.max_cpus, online);
        std::fs::write(node.join("settings.json"), "{").unwrap();
        let cfg = load_resolved(Some(file), &[]).unwrap();
        assert_eq!(
            (cfg.executor.vm.cpus, cfg.executor.vm.max_cpus),
            (4, online)
        );
    }

    /// The node's own registry access is read for a `[registry]` the hub names, never for one
    /// the file sets; it is live until it expires, then an error.
    #[test]
    fn the_node_s_registry_access_reaches_a_registry_the_hub_names() {
        let dir = Dir::new("node-access");
        let state = dir.0.join("state");
        let node = state.join("node");
        std::fs::create_dir_all(&node).unwrap();
        let node_id = "ab".repeat(16);
        std::fs::write(
            node.join("enrollment.json"),
            format!(r#"{{"hub": "https://hub.example", "node_id": "{node_id}"}}"#),
        )
        .unwrap();
        std::fs::write(
            node.join("settings.json"),
            format!(
                r#"{{"hub": "https://hub.example", "node_id": "{node_id}", "generation": 3,
                    "settings": {{"registry": {{"repo": "reg.example.com",
                                                "guest_credential": "job"}}}}}}"#
            ),
        )
        .unwrap();
        let issuer = crate::node::registry_access::Issuer {
            hub: "https://hub.example".into(),
            node_id: node_id.clone(),
        };
        let now = vk_peer::now_secs();
        let access = |expires_at: u64| vk_hub_proto::NodeRegistryAccess {
            registry_id: "cd".repeat(16),
            origin: "https://reg.example.com".into(),
            ca_sha256: None,
            generation: 3,
            issued_at: expires_at - 3600,
            expires_at,
            grants: Vec::new(),
            token: "vkt_node".into(),
            guest_token: None,
            guest_grants: Vec::new(),
        };
        crate::node::registry_access::store(&node, &issuer, &access(now + 600)).unwrap();
        let hub_named = dir.file("c.toml", &format!("state_dir = {state:?}\n"));
        let cfg = load_resolved(Some(hub_named.clone()), &[]).unwrap();
        // A build cache on that registry reaches it the same way.
        assert!(cfg.build.node_access.is_some());
        let registry = cfg.registry.as_ref().unwrap();
        assert!(!registry.has_credential());
        assert_eq!(registry.node_token().unwrap().unwrap().token, "vkt_node");
        assert!(!format!("{registry:?}").contains("vkt_"));
        crate::node::registry_access::store(&node, &issuer, &access(now - 1)).unwrap();
        assert!(registry.node_token().is_err());

        let own = dir.file(
            "own.toml",
            &format!("state_dir = {state:?}\n[registry]\nrepo = \"reg.example.com\"\n"),
        );
        let cfg = load_resolved(Some(own), &[]).unwrap();
        assert!(cfg.registry.as_ref().unwrap().node_access.is_none());
        assert!(cfg.build.node_access.is_none());
        assert_eq!(cfg.registry.unwrap().node_token().unwrap(), None);
    }

    /// An enrolled host with nothing set budgets its memory less a reserve, lets a job ask for
    /// every CPU and sizes the base VM within both; what a layer sets stays.
    #[test]
    fn an_enrolled_host_takes_defaults_from_its_size() {
        let defaults = |text: &str, hub: &[&str], total_mib, cpus| {
            let local: toml::Table = toml::from_str(text).unwrap();
            let mut cfg = from_table(local.clone()).unwrap();
            cfg.layers.local = local;
            cfg.layers.hub = hub
                .iter()
                .map(|k| (k.to_string(), serde_json::Value::Null))
                .collect();
            enrolled_defaults(&mut cfg, total_mib, cpus);
            let (schedule, vm) = (&cfg.executor.schedule, &cfg.executor.vm);
            let budget = schedule.mem_budget.clone();
            (budget, vm.max_cpus, vm.cpus, vm.mem.clone())
        };
        let some = |s: &str| Some(s.to_string());
        // 4 GiB kept back past 40 GiB, a tenth below; whole GiB.
        assert_eq!(
            defaults("", &[], Some(257_000), Some(64)),
            (some("246G"), Some(64), 4, "4G".into())
        );
        assert_eq!(
            defaults("", &[], Some(7_900), Some(2)),
            (some("6G"), Some(2), 2, "4G".into())
        );
        // The tenth rounded up: 4551 - 456 is under 4 GiB.
        assert_eq!(
            defaults("", &[], Some(4_551), Some(2)),
            (some("3G"), Some(2), 2, "3G".into())
        );
        // Unreadable figures leave the defaults as they are; a budget under a GiB is none.
        assert_eq!(
            defaults("", &[], None, Some(0)),
            (None, None, 4, "4G".into())
        );
        assert_eq!(
            defaults("", &[], Some(1_000), None),
            (None, None, 4, "4G".into())
        );
        // Set in the file or by the hub, a value stays; the base VM is held to a set ceiling.
        let set = "[executor.schedule]\nmem_budget = \"2G\"\n[executor.vm]\nmax_cpus = 3\n";
        assert_eq!(
            defaults(set, &[], Some(257_000), Some(64)),
            (some("2G"), Some(3), 3, "2G".into())
        );
        let vm = "[executor.vm]\ncpus = 8\nmem = \"8G\"\n";
        let (_, _, cpus, mem) = defaults(vm, &[], Some(4_551), Some(2));
        assert_eq!((cpus, mem.as_str()), (8, "8G"), "set in the file");
        let hub = ["executor.vm.cpus", "executor.vm.mem"];
        let (_, _, cpus, mem) = defaults("", &hub, Some(4_551), Some(2));
        assert_eq!((cpus, mem.as_str()), (4, "4G"), "set by the hub");
        // What the host's size supplied or held down is detected; the rest is built in.
        let detected = |total_mib, cpus| {
            let mut cfg = from_table(toml::Table::new()).unwrap();
            enrolled_defaults(&mut cfg, total_mib, cpus);
            cfg.layers.detected.into_iter().collect::<Vec<_>>()
        };
        assert_eq!(
            detected(Some(4_551), Some(2)),
            [
                "executor.schedule.mem_budget",
                "executor.vm.cpus",
                "executor.vm.max_cpus",
                "executor.vm.mem"
            ]
        );
        assert_eq!(
            detected(Some(257_000), Some(64)),
            ["executor.schedule.mem_budget", "executor.vm.max_cpus"]
        );
        assert!(detected(None, None).is_empty());
    }

    /// An enrolled host's jobs get the switch's network unless its file sets a mode, even
    /// the old default.
    #[test]
    fn an_enrolled_host_networks_its_jobs_through_the_switch() {
        let mode = |text: &str| {
            let local: toml::Table = toml::from_str(text).unwrap();
            let mut cfg = from_table(local.clone()).unwrap();
            cfg.layers.local = local;
            enrolled_defaults(&mut cfg, Some(257_000), Some(64));
            cfg.net.mode
        };
        assert_eq!(mode(""), "switch");
        assert_eq!(mode("[net]\nsubnet = \"10.9.8.0/24\"\n"), "switch");
        assert_eq!(mode("[net]\nmode = \"none\"\n"), "none");
        assert_eq!(mode("[net]\nmode = \"pool\"\n"), "pool");
        assert_eq!(Config::default().net.mode, "none", "not enrolled");
    }

    /// An enrolled host overcommits its CPUs twice unless told otherwise, and holds the base
    /// VM to the vCPU budget a smaller ratio leaves; a ratio must be positive, and may be
    /// written as a whole number.
    #[test]
    fn an_enrolled_host_overcommits_its_cpus_twice() {
        let defaults = |text: &str, cpus| {
            let local: toml::Table = toml::from_str(text).unwrap();
            let mut cfg = from_table(local.clone()).unwrap();
            cfg.layers.local = local;
            enrolled_defaults(&mut cfg, Some(257_000), cpus);
            (cfg.executor.schedule.cpu_overcommit, cfg.executor.vm.cpus)
        };
        assert_eq!(defaults("", Some(64)), (Some(2.0), 4));
        assert_eq!(defaults("", None), (Some(2.0), 4));
        let low = "[executor.schedule]\ncpu_overcommit = 0.5\n";
        assert_eq!(defaults(low, Some(6)), (Some(0.5), 3));
        let whole = "[executor.schedule]\ncpu_overcommit = 3\n";
        assert_eq!(defaults(whole, Some(6)), (Some(3.0), 4));
        for bad in ["0", "-1.5", "nan", "inf"] {
            let text = format!("[executor.schedule]\ncpu_overcommit = {bad}\n");
            let err = from_table(toml::from_str(&text).unwrap()).unwrap_err();
            assert!(format!("{err:#}").contains("positive"), "{bad}: {err:#}");
        }
        assert_eq!(crate::vm::cpu_budget_of(6, 0.1), Some(1));
        assert_eq!(crate::vm::cpu_budget_of(6, 1.5), Some(9));
        assert_eq!(crate::vm::cpu_budget_of(0, 2.0), None);
    }

    #[test]
    fn load_explicit_missing_is_an_error() {
        let dir = Dir::new("explicit-missing");
        let fallback = dir.file("fallback.toml", "[executor.vm]\ncpus = 9\n");
        // The caller named the file; silently falling back would mask the typo.
        assert!(load_resolved(Some(dir.0.join("nope.toml")), &[fallback]).is_err());
    }

    #[test]
    fn load_first_existing_fallback_wins() {
        let dir = Dir::new("fallbacks");
        let user = dir.file("user.toml", "[executor.vm]\ncpus = 2\n");
        let system = dir.file("system.toml", "[executor.vm]\ncpus = 3\n");
        let missing = dir.0.join("missing.toml");
        let cfg = load_resolved(None, &[missing, user.clone(), system]).unwrap();
        assert_eq!(cfg.executor.vm.cpus, 2);
        assert_eq!(cfg.source.as_deref(), Some(user.as_path()));
    }

    #[test]
    fn load_nothing_found_yields_defaults() {
        let dir = Dir::new("none");
        let cfg = load_resolved(None, &[dir.0.join("a.toml"), dir.0.join("b.toml")]).unwrap();
        assert_eq!(cfg.executor.vm.cpus, Vm::default().cpus);
        assert!(cfg.source.is_none());
    }

    #[test]
    fn load_parse_error_is_fatal_even_from_a_fallback() {
        let dir = Dir::new("bad");
        let bad = dir.file("bad.toml", "not toml at all [");
        assert!(load_resolved(None, &[bad]).is_err());
    }

    /// The migration hint reaches the real file-load path, not just `reject_migrated_keys`:
    /// a loaded file still carrying `[vm]` fails with the new location named.
    #[test]
    fn load_names_where_a_migrated_section_moved() {
        let dir = Dir::new("migrated");
        let stale = dir.file("stale.toml", "[vm]\ncpus = 1\n");
        let err = format!("{:#}", load_resolved(Some(stale), &[]).unwrap_err());
        assert!(err.contains("[executor.vm]"), "{err}");
    }

    /// `guest_build` is on by default unless the guests' proxy lends the node's credential, a
    /// config that does so still loads, and only an explicit `true` beside it is refused.
    #[test]
    fn guest_build_defaults_off_beside_a_node_credential_proxy() {
        let dir = Dir::new("guest-build");
        let load = |name: &str, text: &str| load_resolved(Some(dir.file(name, text)), &[]);
        const NODE: &str = "[registry]\nrepo = \"reg.example/x\"\nproxy_guests = true\n";
        const JOB: &str = "[registry]\nrepo = \"reg.example/x\"\nproxy_guests = true\nguest_credential = \"job\"\n";
        let cfg = load("none.toml", "").unwrap();
        assert!(cfg.guest_build());
        assert_eq!(cfg.executor.guest_build_max_context, ByteSize(8 << 30));
        assert_eq!(cfg.executor.guest_build_max_entries.get(), 1_000_000);
        assert!(!load("node.toml", NODE).unwrap().guest_build());
        assert!(load("job.toml", JOB).unwrap().guest_build());
        let explicit = format!("[executor]\nguest_build = true\n{JOB}");
        assert!(load("job-on.toml", &explicit).unwrap().guest_build());
        let off = "[executor]\nguest_build = false\n";
        assert!(!load("off.toml", off).unwrap().guest_build());
        let explicit = format!("[executor]\nguest_build = true\n{NODE}");
        let err = format!("{:#}", load("node-on.toml", &explicit).unwrap_err());
        assert!(err.contains("guest_credential"), "{err}");

        let sized = "[executor]\nguest_build_max_context = \"512M\"\nguest_build_max_entries = 5\n";
        let cfg = load("sized.toml", sized).unwrap();
        assert_eq!(cfg.executor.guest_build_max_context, ByteSize(512 << 20));
        assert_eq!(cfg.executor.guest_build_max_entries.get(), 5);
        for bad in [
            "guest_build_max_context = \"10%\"",
            "guest_build_max_context = \"none\"",
            "guest_build_max_context = \"8\"",
            "guest_build_max_context = \"0G\"",
            "guest_build_max_entries = 0",
        ] {
            assert!(
                load("bad.toml", &format!("[executor]\n{bad}\n")).is_err(),
                "{bad}"
            );
        }
    }

    /// `pipeline_root` defaults to the namespace's default path root and must be a path.
    #[test]
    fn pipeline_root_is_a_repository_path() {
        let dir = Dir::new("pipeline-root");
        let load = |name: &str, root: &str| {
            let text = format!("[registry]\nrepo = \"reg.example/x\"\n{root}");
            load_resolved(Some(dir.file(name, &text)), &[])
        };
        let root = |cfg: Config| cfg.registry.unwrap().pipeline_root().to_string();
        assert_eq!(root(load("default.toml", "").unwrap()), "ci-pipeline");
        let custom = load("custom.toml", "pipeline_root = \"org/pipelines\"\n").unwrap();
        assert_eq!(root(custom), "org/pipelines");
        for bad in ["", "/x", "x/", "X", "a//b", "a b"] {
            let line = format!("pipeline_root = {bad:?}\n");
            assert!(load("bad.toml", &line).is_err(), "{bad:?}");
        }
    }

    /// File loading strips `virtiofsd` rather than rejecting it under `deny_unknown_fields`.
    #[test]
    fn load_ignores_a_removed_key() {
        let dir = Dir::new("removed");
        let old = dir.file("old.toml", "virtiofsd = \"/x\"\n");
        load_resolved(Some(old), &[]).unwrap();
    }

    // `vk config` serializes the effective config to TOML; the defaults must
    // round-trip, and a scalar like image_cache_idle_secs must stay ahead of the
    // `[section]` tables (a value emitted after a table would re-parse into it).
    #[test]
    fn effective_config_round_trips() {
        let text = toml::to_string(&Config::default()).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.executor.vm.cpus, Config::default().executor.vm.cpus);

        let populated: Config = toml::from_str(
            r#"
            image_cache_idle_secs = 900
            [docker]
            repo = "reg.example.com/team"
            [registry]
            repo = "reg.example.com/bundles"
            [build]
            build_cache = "layers"
            [executor.vm]
            cpus = 6
            "#,
        )
        .unwrap();
        let text = toml::to_string(&populated).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.image_cache_idle_secs, Some(900));
        assert_eq!(back.executor.vm.cpus, 6);
        assert_eq!(
            back.docker.as_ref().unwrap().repo.as_deref(),
            Some("reg.example.com/team")
        );
        assert_eq!(back.build.build_cache, crate::build::BuildCache::Layers);
    }

    /// `[executor.vm] nested` is a host grant, so the default matters as much as the parse: a
    /// serde name that drifted would reject every runner config that sets it
    /// (`deny_unknown_fields`), and a default that drifted would grant it unasked.
    #[test]
    fn vm_nested_parses_and_defaults_off() {
        assert!(!Config::default().executor.vm.nested);
        let cfg: Config = toml::from_str("[executor.vm]\nnested = true\n").unwrap();
        assert!(cfg.executor.vm.nested);
        assert!(
            !toml::from_str::<Config>("[executor.vm]\nnested = false\n")
                .unwrap()
                .executor
                .vm
                .nested
        );
    }

    #[test]
    fn a_removed_key_is_stripped_and_named() {
        let mut table: toml::Table = toml::from_str(
            "virtiofsd = \"/usr/bin/virtiofsd\"\nstate_dir = \"/s\"\n\
             cloud_hypervisor = \"ch\"\n[build]\ncloud_hypervisor = \"ch\"\n",
        )
        .unwrap();
        assert_eq!(
            strip_removed_keys(&mut table),
            vec!["virtiofsd", "cloud_hypervisor", "build.cloud_hypervisor"]
        );
        let cfg: Config = table.try_into().unwrap();
        assert_eq!(cfg.state_dir(), Path::new("/s"));
        assert!(strip_removed_keys(&mut toml::Table::new()).is_empty());
    }

    #[test]
    fn vmm_key_parses_all_spellings_and_rejects_junk() {
        let cfg: Config = toml::from_str("vmm = \"cloud-hypervisor\"\n").unwrap();
        assert_eq!(cfg.vmm, Some(VmmBackend::CloudHypervisor));
        // the env var's alternative spellings are accepted as aliases too
        for s in ["cloud_hypervisor", "ch"] {
            let cfg: Config = toml::from_str(&format!("vmm = {s:?}\n")).unwrap();
            assert_eq!(cfg.vmm, Some(VmmBackend::CloudHypervisor));
        }
        assert_eq!(
            toml::from_str::<Config>("vmm = \"libkrun\"\n").unwrap().vmm,
            Some(VmmBackend::Libkrun)
        );
        assert!(Config::default().vmm.is_none());
        assert!(toml::from_str::<Config>("vmm = \"qemu\"\n").is_err());
    }

    #[test]
    fn executor_tools_dir_parses() {
        let cfg: Config = toml::from_str(
            r#"
            [executor]
            tools_dir = "/usr/local/lib/vk/ci-tools"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.executor.tools_dir.as_deref(),
            Some(Path::new("/usr/local/lib/vk/ci-tools"))
        );
    }

    #[test]
    fn node_speed_classes_parse_and_an_untouched_node_is_not_printed() {
        let cfg: Config =
            toml::from_str("[node]\njobs_speed = \"slow\"\ncheckouts_speed = \"fast\"\n").unwrap();
        assert_eq!(cfg.node.jobs_speed, Some(vk_hub_proto::SpeedClass::Slow));
        assert_eq!(
            cfg.node.checkouts_speed,
            Some(vk_hub_proto::SpeedClass::Fast)
        );
        assert!(toml::to_string(&cfg).unwrap().contains("[node]"));
        assert!(toml::from_str::<Config>("[node]\njobs_speed = \"quick\"\n").is_err());
        assert!(toml::from_str::<Config>("[node]\nspeed = \"fast\"\n").is_err());
        let bare: Config = toml::from_str("").unwrap();
        assert!(!toml::to_string(&bare).unwrap().contains("[node]"));
    }

    #[test]
    fn node_runner_modes_parse_and_unset_is_left_to_the_host() {
        use vk_hub_proto::RunnerMode;
        for (text, mode) in [
            ("managed", RunnerMode::Managed),
            ("external", RunnerMode::External),
            ("none", RunnerMode::None),
        ] {
            let cfg: Config = toml::from_str(&format!("[node]\nrunner = \"{text}\"\n")).unwrap();
            assert_eq!(cfg.node.runner, Some(mode));
            assert!(
                toml::to_string(&cfg)
                    .unwrap()
                    .contains(&format!("runner = \"{text}\""))
            );
        }
        let bare: Config = toml::from_str("[node]\n").unwrap();
        assert_eq!(bare.node.runner, None);
        assert!(toml::from_str::<Config>("[node]\nrunner = \"auto\"\n").is_err());
    }

    #[test]
    fn executor_checkout_dir_parses() {
        let cfg: Config = toml::from_str(
            r#"
            [executor]
            host_checkout = true
            checkout_dir = "/builds"
            checkout_cache_idle_secs = 7200
            "#,
        )
        .unwrap();
        let ex = &cfg.executor;
        assert!(ex.host_checkout);
        assert_eq!(ex.checkout_dir.as_deref(), Some(Path::new("/builds")));
        assert_eq!(cfg.checkout_root(), Path::new("/builds/vk"));
        assert_eq!(cfg.checkout_cache_idle().as_secs(), 7200);
        // absent = None: the on-disk `<state_dir>/checkouts` default is preserved, and the
        // checkout lifetime is the image cache's.
        let bare: Config = toml::from_str("[executor]\ntools_dir = \"/x\"\n").unwrap();
        assert!(bare.executor.checkout_dir.is_none());
        assert_eq!(
            bare.checkout_root(),
            Path::new("/var/lib/virtkit/checkouts"),
            "the default root is the executor's state dir, which is what `vk gc` must sweep"
        );
        assert_eq!(bare.checkout_cache_idle(), bare.image_cache_idle());
        // The Windows cache keeps its own, far longer lifetime, which a config can set.
        assert_eq!(bare.windows_cache_idle().as_secs(), 7 * 24 * 3600);
        let set: Config = toml::from_str("[executor]\nwindows_cache_idle_secs = 3600\n").unwrap();
        assert_eq!(set.windows_cache_idle().as_secs(), 3600);
        // No `[executor]` table at all still resolves a root, and a configured state dir moves it.
        assert_eq!(
            Config::default().checkout_root(),
            Path::new("/var/lib/virtkit/checkouts")
        );
        let moved = Config {
            state_dir: Some(PathBuf::from("/s")),
            ..Config::default()
        };
        assert_eq!(moved.checkout_root(), Path::new("/s/checkouts"));
    }

    #[test]
    fn executor_tools_dir_defaults_unset() {
        assert!(Config::default().executor.tools_dir.is_none());
    }

    #[test]
    fn executor_checkout_overlay_defaults_on() {
        // Both construction paths must agree: serde with the field absent, and Default.
        let cfg: Config = toml::from_str("[executor]\nhost_checkout = true\n").unwrap();
        assert!(cfg.executor.checkout_overlay);
        assert!(Executor::default().checkout_overlay);
        let off: Config =
            toml::from_str("[executor]\nhost_checkout = true\ncheckout_overlay = false\n").unwrap();
        assert!(!off.executor.checkout_overlay);
    }

    /// `[gc]`: the defaults, each spelling of a limit, `0` retention as none, a refused size,
    /// and a round trip through `vk config`.
    #[test]
    fn gc_table_parses_its_limits_and_round_trips() {
        let gib = 1u64 << 30;
        let cfg = Config::default();
        assert_eq!(
            cfg.gc.build_cache_retention(),
            Some(std::time::Duration::from_secs(14 * 86_400))
        );
        assert_eq!(cfg.gc.build_cache_max(100 * gib), Some(10 * gib));
        assert_eq!(cfg.gc.build_cache_max(2000 * gib), Some(50 * gib));
        assert!(cfg.gc.auto());
        assert_eq!(
            cfg.gc.interval(),
            Some(std::time::Duration::from_secs(24 * 3600))
        );
        assert_eq!(cfg.gc.min_free(100 * gib), Some(10 * gib));
        assert_eq!(cfg.gc.min_free(1000 * gib), Some(20 * gib));
        assert_eq!(
            cfg.gc.dev_image_idle(),
            Some(std::time::Duration::from_secs(14 * 86_400))
        );
        assert!(!toml::to_string(&cfg).unwrap().contains("[gc]"));

        for (text, fs, want) in [
            ("\"20%\"", 100 * gib, Some(20 * gib)),
            ("\"80G\"", 100 * gib, Some(80 * gib)),
            ("\"512M\"", 100 * gib, Some(512 << 20)),
            ("\"none\"", 100 * gib, None),
        ] {
            let cfg: Config = toml::from_str(&format!(
                "[gc]\nbuild_cache_max = {text}\nbuild_cache_retention_days = 0\n\
                 dev_image_idle_days = 0\nrun_image_idle_days = 0\n\
                 dev_images_with_create_hook = true\nauto = false\ninterval_hours = 0\n\
                 min_free = {text}\n"
            ))
            .unwrap();
            assert_eq!(cfg.gc.build_cache_max(fs), want, "{text}");
            assert_eq!(cfg.gc.build_cache_retention(), None);
            assert_eq!(cfg.gc.dev_image_idle(), None);
            assert_eq!(cfg.gc.run_image_idle(), None);
            assert!(cfg.gc.dev_images_with_create_hook());
            assert!(!cfg.gc.auto());
            assert_eq!(cfg.gc.interval(), None);
            assert_eq!(cfg.gc.min_free(fs), want, "{text}");
            let back: Config = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
            assert_eq!(back.gc, cfg.gc, "{text}");
        }
        for bad in [
            "\"0\"", "\"0G\"", "\"10\"", "\"101%\"", "\"0%\"", "\"lots\"",
        ] {
            assert!(
                toml::from_str::<Config>(&format!("[gc]\nbuild_cache_max = {bad}\n")).is_err(),
                "{bad}"
            );
        }
        assert!(toml::from_str::<Config>("[gc]\nbogus = 1\n").is_err());
    }

    /// `vk config --example` prints a config this `vk` loads.
    #[test]
    fn the_example_config_parses() {
        toml::from_str::<Config>(include_str!("../config.example.toml")).unwrap();
    }

    /// The nested tables parse under `[executor.*]` and round-trip through `vk config`.
    #[test]
    fn executor_nested_tables_parse_and_round_trip() {
        let cfg: Config = toml::from_str(
            r#"
            [executor.vm]
            cpus = 6
            [executor.guest]
            builds_dir = "/work"
            [executor.auth]
            ssh_agent = true
            [executor.schedule]
            mem_budget = "48G"
            disk_admission = false
            disk_default = "20G"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.executor.vm.cpus, 6);
        assert_eq!(cfg.executor.guest.builds_dir, "/work");
        assert!(cfg.executor.auth.ssh_agent);
        assert_eq!(cfg.executor.schedule.mem_budget.as_deref(), Some("48G"));
        let back: Config = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back.executor.vm.cpus, 6);
        assert_eq!(back.executor.schedule.mem_budget.as_deref(), Some("48G"));
        assert_eq!(back.executor.schedule.disk_admission, Some(false));
        assert_eq!(back.executor.schedule.disk_default.as_deref(), Some("20G"));
    }

    /// `[numa]` is host-wide — it governs every VM, not just the CI executor's — so it sits
    /// at the top level and round-trips through `vk config` from there.
    #[test]
    fn numa_mode_parses_at_the_top_level_and_round_trips() {
        let cfg: Config = toml::from_str("[numa]\nmode = \"interleave\"\n").unwrap();
        assert_eq!(cfg.numa.mode, NumaMode::Interleave);
        let back: Config = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back.numa.mode, NumaMode::Interleave);
        // Unset, every host places the VMs it boots.
        assert_eq!(Config::default().numa.mode, NumaMode::Auto);
        assert_eq!(
            toml::from_str::<Config>("").unwrap().numa.mode,
            NumaMode::Auto
        );
    }

    #[test]
    fn vk_config_omits_an_untouched_executor() {
        // A host that configures nothing CI-related: the effective config carries a default
        // executor, and `vk config` must not print a page of `[executor]` defaults for it.
        let bare = Config::default();
        assert!(bare.executor.is_default());
        let toml = toml::to_string(&bare).unwrap();
        assert!(!toml.contains("[executor"), "{toml}");

        // Configure a single nested executor key and the whole tree is shown again.
        let cfg: Config = toml::from_str("[executor.vm]\ncpus = 6\n").unwrap();
        assert!(!cfg.executor.is_default());
        let toml = toml::to_string(&cfg).unwrap();
        assert!(
            toml.contains("[executor.vm]") && toml.contains("cpus = 6"),
            "{toml}"
        );

        // A flat `[executor]` scalar shows it too, guarding the top-level-key path.
        let cfg: Config = toml::from_str("[executor]\natop = false\n").unwrap();
        assert!(!cfg.executor.is_default());
        let toml = toml::to_string(&cfg).unwrap();
        assert!(toml.contains("atop = false"), "{toml}");
    }

    /// Every section that moved under `[executor]` is refused at load with a hint
    /// pointing at the new location, rather than silently ignored.
    #[test]
    fn migrated_top_level_sections_are_refused_with_a_hint() {
        let refuse = |text: &str| -> String {
            let table: toml::Table = toml::from_str(text).unwrap();
            format!("{:#}", reject_migrated_keys(&table).unwrap_err())
        };
        assert!(refuse("[vm]\ncpus = 1\n").contains("[executor.vm]"));
        assert!(refuse("[guest]\nbuilds_dir = \"/w\"\n").contains("[executor.guest]"));
        assert!(refuse("[share]\ndir = \"/w\"\n").contains("[executor.share]"));
        assert!(refuse("[auth]\nssh_agent = true\n").contains("[executor.auth]"));
        assert!(refuse("[schedule]\nmem_budget = \"1G\"\n").contains("[executor.schedule]"));
        assert!(refuse("[gitlab]\ndir = \"/x\"\n").contains("tools_dir"));
        assert!(refuse("[services]\nstore_dir = \"/x\"\n").contains("obsolete"));
        // A config already on the new layout passes the check.
        let ok: toml::Table = toml::from_str("[executor.vm]\ncpus = 1\n").unwrap();
        assert!(reject_migrated_keys(&ok).is_ok());
    }

    /// Reject `[services]` so obsolete keys cannot appear to take effect.
    #[test]
    fn services_section_is_rejected() {
        let err = toml::from_str::<Config>("[services]\nstore_dir = \"/x\"\n").unwrap_err();
        assert!(err.to_string().contains("services"), "{err}");
    }

    #[test]
    fn egress_allowlist_parses() {
        let cfg: Config = toml::from_str(
            r#"
            [egress]
            allow_ip = ["10.0.0.0/8", "192.168.1.1/32"]
            allow_name = ["corp.example.com", "github.com"]

            [egress.build]
            allow_name = []
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.egress.allow_ip.as_deref(),
            Some(&["10.0.0.0/8".to_string(), "192.168.1.1/32".to_string()][..])
        );
        assert_eq!(
            cfg.egress.allow_name.as_deref(),
            Some(&["corp.example.com".to_string(), "github.com".to_string()][..])
        );
        // [egress.build] present with an explicit empty list = deny all names for the
        // build phase (Some([])), distinct from an absent list (None = unconstrained).
        assert_eq!(cfg.egress.build.allow_name.as_deref(), Some(&[][..]));
        assert_eq!(cfg.egress.build.allow_ip, None);
        // absent [egress] = unrestricted (both lists None)
        let none = Config::default();
        assert!(none.egress.allow_ip.is_none() && none.egress.allow_name.is_none());
        assert!(none.egress.build.allow_ip.is_none() && none.egress.build.allow_name.is_none());
    }

    #[test]
    fn net_port_default() {
        assert_eq!(Net::default().net_port, 1024);
    }

    #[test]
    fn docker_section_may_be_empty_or_mirror_only() {
        // An empty [docker] parses (every field defaults) — repo is optional now.
        let empty: Config = toml::from_str("[docker]\n").unwrap();
        let d = empty.docker.as_ref().unwrap();
        assert!(d.repo.is_none() && d.mirror.is_none());
        // A mirror-only [docker]: no repo, just the Hub pull-through.
        let cfg: Config = toml::from_str(
            r#"
            [docker.mirror]
            repo = "hq-nexus.example.com:8440"
            "#,
        )
        .unwrap();
        let d = cfg.docker.as_ref().unwrap();
        assert!(d.repo.is_none());
        assert_eq!(d.mirror.as_ref().unwrap().repo, "hq-nexus.example.com:8440");
    }

    #[test]
    fn docker_with_repo_and_mirror_parses() {
        let cfg: Config = toml::from_str(
            r#"
            [docker]
            repo = "10.10.140.49/common/wab-ci"
            username = "ci-push"

            [docker.mirror]
            repo = "hq-nexus.example.com:8440"
            insecure = true
            "#,
        )
        .unwrap();
        let d = cfg.docker.as_ref().unwrap();
        assert_eq!(d.repo.as_deref(), Some("10.10.140.49/common/wab-ci"));
        assert_eq!(d.username, "ci-push");
        let m = d.mirror.as_ref().unwrap();
        assert_eq!(m.repo, "hq-nexus.example.com:8440");
        assert!(m.insecure);
    }

    #[test]
    fn docker_rejects_unknown_fields() {
        assert!(toml::from_str::<Config>("[docker]\nrepoo = \"x\"\n").is_err());
    }

    #[test]
    fn auth_ssh_agent_parses() {
        let cfg: Config = toml::from_str("[executor.auth]\nssh_agent = true\n").unwrap();
        assert!(cfg.executor.auth.ssh_agent);
        // absent [executor.auth] = off
        assert!(!Config::default().executor.auth.ssh_agent);
    }

    #[test]
    fn build_defaults_parse() {
        let cfg: Config = toml::from_str(
            r#"
            [build]
            kernel = "/k/vmlinux"
            agent = "/k/virtkit-agent"
            cache_registry = "127.0.0.1:5000"
            cache_insecure = true
            build_cache = "layers"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.build.kernel.as_deref(), Some(Path::new("/k/vmlinux")));
        assert_eq!(cfg.build.cache_registry.as_deref(), Some("127.0.0.1:5000"));
        assert!(cfg.build.cache_insecure && !cfg.build.no_journal);
        assert_eq!(cfg.build.build_cache, crate::build::BuildCache::Layers);
        // absent [build] = all unset, cache mode defaults to auto
        assert!(Config::default().build.cache_registry.is_none());
        assert_eq!(
            Config::default().build.build_cache,
            crate::build::BuildCache::Auto
        );
    }

    #[test]
    fn build_no_journal_parses() {
        let cfg: Config = toml::from_str("[build]\nno_journal = true\n").unwrap();
        assert!(cfg.build.no_journal);
    }

    #[test]
    fn build_no_mem_gate_parses_and_defaults_to_gated() {
        let cfg: Config = toml::from_str("[build]\nno_mem_gate = true\n").unwrap();
        assert!(cfg.build.no_mem_gate);
        assert!(
            !Config::default().build.no_mem_gate,
            "the host-memory gate is on unless a host opts out"
        );
    }

    /// The renamed-away `journal` key (superseded by `no_journal` when the default
    /// flipped) must be a hard parse error, not silently ignored — a config written
    /// against the old key must not silently keep building journal-less images.
    #[test]
    fn build_rejects_the_renamed_away_journal_key() {
        assert!(toml::from_str::<Config>("[build]\njournal = true\n").is_err());
    }

    /// The stage budget is refused at load time, where the offending line is still on
    /// screen, rather than reaching the build as a request to run nothing.
    #[test]
    fn build_jobs_refuses_zero() {
        let cfg: Config = toml::from_str("[build]\njobs = 2\n").unwrap();
        assert_eq!(cfg.build.jobs, NonZeroUsize::new(2));
        assert!(toml::from_str::<Config>("[build]\njobs = 0\n").is_err());
    }

    /// A concurrency ceiling of zero is refused at load time too: gitlab-runner has no such
    /// throttle, and quietly running one job instead would hide the mistake.
    #[test]
    fn max_concurrency_refuses_zero() {
        let cfg: Config = toml::from_str("[executor.schedule]\nmax_concurrency = 3\n").unwrap();
        assert_eq!(
            cfg.executor.schedule.max_concurrency,
            std::num::NonZeroU32::new(3)
        );
        assert!(toml::from_str::<Config>("[executor.schedule]\nmax_concurrency = 0\n").is_err());
    }

    /// `windows_media` entries must be sha256 digests.
    #[test]
    fn windows_media_are_sha256_digests() {
        let digest = "AB".repeat(32);
        let cfg =
            toml::from_str::<Config>(&format!("[executor]\nwindows_media = [\"{digest}\"]\n"))
                .unwrap();
        assert_eq!(cfg.executor.windows_media, ["ab".repeat(32)]);
        assert!(Config::default().executor.windows_media.is_empty());
        for bad in ["ab", &"zz".repeat(32), &"ab".repeat(33)] {
            let err =
                toml::from_str::<Config>(&format!("[executor]\nwindows_media = [\"{bad}\"]\n"))
                    .unwrap_err()
                    .to_string();
            assert!(err.contains("not a sha256 digest"), "{err}");
        }
    }

    /// A Windows cache lifetime of zero is refused at load time: it would let a sweep take the
    /// install under a layer a build is publishing.
    #[test]
    fn windows_cache_idle_refuses_zero() {
        let err = toml::from_str::<Config>("[executor]\nwindows_cache_idle_secs = 0\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("windows_cache_idle_secs"), "{err}");
    }
}
