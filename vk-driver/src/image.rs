//! MICROVM_IMAGE resolution.
//!
//! `MICROVM_IMAGE` is prefix-based: the part before the first `/` names the
//! source, the rest is source-specific. Jobs select a guest image with it:
//!   - unset — treated as `local/default`.
//!   - `local/<name>` — a bundle directory under the host-configured
//!     `[local] dir` (see local.rs). `<name>` is a single safe path component;
//!     local bundles are never tagged or digested.
//!   - `virtkit/<name>[:tag|@sha256:…]` — a bundle in the host-configured
//!     `[registry] repo` (the allowlist), pulled+cached natively with CDC+zstd
//!     chunk dedup (see registry.rs). Only the name/reference is job-controlled.
//!   - `docker/<name>[:tag|@sha256:…]` — a docker image in the host-configured
//!     `[docker] repo` (the allowlist), pulled and booted directly via OCI on
//!     demand (see dockerimg.rs). Only the name/reference is job-controlled.
//!
//! This module is the thin dispatcher plus the reference-parsing and local-cache
//! helpers shared with the docker, registry and local paths.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};

use crate::config::Config;
use vk_hub_proto::dispatch::Activity;
use vk_registry::hostlock;

/// The boot flavour recorded per cached bundle (`boot.kind`), so a cache hit
/// — which skips the pull/build — still knows how to boot it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootKind {
    /// Generic OCI image, booted from an ext4 disk on the pinned guest kernel,
    /// virtkit-agent as PID 1.
    GenericDisk,
}

/// What `resolve` produced for a job's MICROVM_IMAGE.
pub enum ResolvedImage {
    /// A clean rootfs booted through the host agent's preinit initramfs.
    Disk {
        rootfs: PathBuf,
        /// Runtime config from the sidecar; older bundles may lack it.
        config: Option<vk_core::runcfg::RunConfig>,
    },
}

/// Resolve an explicit MICROVM_IMAGE-style `image_ref` to a concrete bootable image,
/// caching materialized bases under `state_dir`. The reference is prefix-based (the
/// prefix names the source, split on the FIRST `/`). Every consumer — the CI job image,
/// CI/compose service `image:` units, and `vk run` — resolves through here, so the same
/// ref shares one digest-keyed cache entry (each boots its own CoW overlay over the
/// shared rootfs). Takes just `(&Config, state_dir)` so a non-CI caller need not build a
/// `JobCtx`.
pub fn resolve_ref(cfg: &Config, state_dir: &Path, image_ref: &str) -> Result<ResolvedImage> {
    match image_ref.split_once('/') {
        // local/<name> = a bundle directory under [local] dir.
        Some(("local", rest)) => crate::local::resolve(cfg, state_dir, rest),
        // virtkit/<name>[:tag|@digest] = a native virtkit bundle in the [registry] repo,
        // pulled+cached natively (CDC+zstd chunk dedup); published by `vk build --tag`.
        Some(("virtkit", rest)) => crate::registry::resolve(cfg, state_dir, rest),
        // docker/<name>[:tag|@digest] = an OCI image, pulled and booted directly
        // (embedded kernel + agent; digest-keyed local cache).
        Some(("docker", rest)) => crate::dockerimg::resolve(cfg, state_dir, rest),
        // anything else = a raw OCI reference (the job's `image:`): booted directly.
        _ => crate::dockerimg::resolve_image(cfg, state_dir, image_ref),
    }
}

/// Resolve a supported bundle. The host supplies its kernel and agent at boot.
pub(crate) fn resolved_from_dir(dir: &Path, _kind: BootKind) -> ResolvedImage {
    let config = std::fs::read(dir.join("runner.ext4.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    ResolvedImage::Disk {
        rootfs: dir.join("runner.ext4"),
        config,
    }
}

/// Read the bundle marker. Missing and retired boot kinds are unsupported.
pub(crate) fn read_boot_kind(dir: &Path) -> Option<BootKind> {
    parse_boot_kind(
        std::fs::read_to_string(dir.join("boot.kind"))
            .ok()
            .as_deref(),
    )
}

pub(crate) fn parse_boot_kind(marker: Option<&str>) -> Option<BootKind> {
    match marker.map(str::trim) {
        Some("generic-disk") => Some(BootKind::GenericDisk),
        _ => None,
    }
}

/// The `boot.kind` marker string for a boot flavour (the value the registry
/// config blob and the bundle marker record).
pub(crate) fn boot_kind_tag(kind: BootKind) -> &'static str {
    match kind {
        BootKind::GenericDisk => "generic-disk",
    }
}

pub(crate) enum Reference {
    Tag(String),
    Digest(String),
}

/// `<name>[:tag|@sha256:<64 hex>]`; name and tag are restricted to one safe
/// path component each (they end up in registry URLs and cache paths).
pub(crate) fn parse_ref(s: &str) -> Result<(String, Reference)> {
    let (name, reference) = if let Some((n, d)) = s.split_once('@') {
        (n, Reference::Digest(d.to_string()))
    } else if let Some((n, t)) = s.split_once(':') {
        (n, Reference::Tag(t.to_string()))
    } else {
        (s, Reference::Tag("latest".into()))
    };
    let component_ok = |v: &str| {
        !v.is_empty()
            && !v.starts_with('.')
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    if !component_ok(name) {
        bail!("invalid MICROVM_IMAGE name {name:?}");
    }
    match &reference {
        Reference::Tag(t) if !component_ok(t) => bail!("invalid MICROVM_IMAGE tag {t:?}"),
        Reference::Digest(d) if parse_digest(d).is_none() => {
            bail!("invalid MICROVM_IMAGE digest {d:?} (want sha256:<64 lowercase hex>)")
        }
        _ => {}
    }
    Ok((name.to_string(), reference))
}

pub(crate) fn parse_digest(s: &str) -> Option<String> {
    vk_registry::digest_hex(s).map(|_| s.to_string())
}

/// The hex of `digest`, which must be exactly `sha256:` and 64 lowercase hex digits: what a
/// digest read from a manifest, an index, a registry's answer or a file of our own must pass
/// before it names a file, a cache entry, a lease or a `.vk_ro_img` record. Anything else
/// fails, never stripped or skipped: `sha256:sha256:<hex>` would otherwise name another
/// image's cached chunk, and a `/` or `..` a file outside the cache.
pub(crate) fn digest_hex(digest: &str) -> Result<&str> {
    vk_registry::digest_hex(digest)
        .with_context(|| format!("digest {digest:?} is not sha256:<64 lowercase hex>"))
}

/// Binding an abstract Unix socket derived from the image directory serializes pulls.
/// The name stays bound until the last listener descriptor closes, including inherited
/// copies. Removing `images/` during a pull cannot unlink the lock and let another prepare
/// race it. A hash collision only serializes two unrelated pulls.
///
/// The name is predictable and the abstract namespace has no permissions, so another local
/// user can bind it first. A waiter refuses a holder of a known foreign uid, or one that
/// three queries in a row could not connect to (see [`hostlock::judge`]), which turns that
/// into a failed pull rather than a hung one; it cannot stop it.
fn pull_lock_addr(dir: &Path) -> std::io::Result<SocketAddr> {
    hostlock::addr("virtkit-pull", dir.as_os_str().as_bytes())
}

/// A held pull lock. It answers waiters with `jobctx::job_identity()` until dropped.
pub(crate) struct PullLock {
    /// The activity set by [`PullLock::report`]. Declared before `_held` so it is withdrawn
    /// before the lock is let go.
    said: Option<crate::activity::Said>,
    _held: hostlock::Held,
    /// Where its holder tells the job's hub what it does.
    sink: Arc<crate::activity::Sink>,
}

impl PullLock {
    /// Tell the job's hub what is done under the lock, until it is released: for a caller
    /// whose cache, checked again under the lock, missed.
    pub(crate) fn report(&mut self, activity: Activity) {
        self.said = Some(self.sink.say(activity));
    }
}

/// `verb` names the serialized operation in the wait message ("pull" for a registry/OCI
/// fetch, "build" for a build-tier stage) — the lock itself is shared across both.
pub(crate) fn acquire_pull_lock(
    dir: &Path,
    verb: &str,
    name: &str,
    digest: &str,
) -> Result<PullLock> {
    // Off a terminal (a job log) nothing else shows the wait is still on; a terminal has the
    // first line and the dashboard to come.
    let beat = crate::build::plain_progress().then_some(crate::build::HEARTBEAT);
    acquire_pull_lock_with(
        dir,
        verb,
        name,
        digest,
        std::time::Duration::from_millis(200),
        beat,
        crate::activity::sink(),
    )
}

/// Report a wait at intervals of `every`, or stay silent when unset.
struct WaitBeat {
    every: Option<std::time::Duration>,
    /// How far into the wait the last report was.
    last: std::time::Duration,
}

impl WaitBeat {
    /// Check whether a report is due at elapsed time `waited`, and record it if so.
    fn due(&mut self, waited: std::time::Duration) -> bool {
        let Some(every) = self.every else {
            return false;
        };
        if waited.saturating_sub(self.last) < every {
            return false;
        }
        self.last = waited;
        true
    }
}

/// Whether `dir`'s pull lock is held, asked without taking it ([`hostlock::held`]).
fn pull_lock_held(dir: &Path) -> bool {
    let Ok(addr) = pull_lock_addr(dir) else {
        return true;
    };
    hostlock::held(&addr)
}

/// [`acquire_pull_lock`] without waiting: `None` when another process holds it. Held, it
/// answers waiters as a waited-for lock does, so they wait for it rather than give up.
fn try_acquire_pull_lock(dir: &Path) -> Option<PullLock> {
    let addr = pull_lock_addr(dir).ok()?;
    let held = hostlock::try_acquire(&addr, &crate::jobctx::job_identity()).ok()??;
    Some(pull_lock(held, crate::activity::sink()))
}

/// [`acquire_pull_lock`], retrying the bind every `poll`, and querying the holder at the first
/// refusal and every 25 polls after; at those queries, saying the wait is still on every
/// `beat`, if set; telling `sink` it waits, and for whom, until it is over either way.
fn acquire_pull_lock_with(
    dir: &Path,
    verb: &str,
    name: &str,
    digest: &str,
    poll: std::time::Duration,
    beat: Option<std::time::Duration>,
    sink: Arc<crate::activity::Sink>,
) -> Result<PullLock> {
    let addr = pull_lock_addr(dir)?;
    let identity = crate::jobctx::job_identity();
    // Said while it waits, and over when the wait is, the lock taken or not.
    let mut waiting: Option<crate::activity::Said> = None;
    // The holder it was last said to wait for.
    let mut waited_for: Option<String> = None;
    let mut polls: u32 = 0;
    // Consecutive unanswered queries while the name stays bound.
    let mut unanswered: u32 = 0;
    let since = std::time::Instant::now();
    let mut beat = WaitBeat {
        every: beat,
        last: std::time::Duration::ZERO,
    };
    loop {
        polls = polls.wrapping_add(1);
        let held =
            hostlock::try_acquire(&addr, &identity).context("binding the pull-lock socket")?;
        match held {
            Some(held) => return Ok(pull_lock(held, sink)),
            // Asked again every 25 polls (5 s by default), not only at the first refusal: the
            // holder can go and another user's process take the name while this one waits.
            None if waiting.is_none() || polls.is_multiple_of(25) => {
                let holder = hostlock::query_holder(&addr)
                    .context("asking the pull-lock holder who it is")?;
                unanswered = if holder.is_some() { 0 } else { unanswered + 1 };
                // SAFETY: geteuid(2) has no preconditions and cannot fail.
                let me = unsafe { libc::geteuid() };
                match hostlock::judge(holder.as_ref(), me, unanswered) {
                    hostlock::Verdict::Wait => {}
                    hostlock::Verdict::Foreign(uid) => bail!(
                        "the {verb} lock for {name}@{digest} is held by uid {uid}, not by a \
                         virtkit of this user — refusing to wait on it"
                    ),
                    hostlock::Verdict::Unanswering => bail!(
                        "the {verb} lock for {name}@{digest} is held by a process that does \
                         not answer — refusing to wait on it"
                    ),
                }
                // "A concurrent" build or pull: the holder may also be a sweep reclaiming a dead
                // staging dir of this entry (`TmpSweep::reclaim_if_dead`), which is brief.
                let who = holder.as_ref().and_then(|h| h.who.clone());
                if waiting.is_some() {
                    // A later query, `poll * 25` into the wait: say it is still on, at most
                    // every `beat`, so a job log does not go quiet for the whole of it.
                    let waited = since.elapsed();
                    if beat.due(waited) {
                        crate::quiet::note!(
                            "virtkit: still waiting for the concurrent {verb} of {name}, {}",
                            crate::build::fmt_wait(waited)
                        );
                    }
                } else {
                    match &who {
                        Some(who) => crate::quiet::note!(
                            "virtkit: waiting for a concurrent {verb} of {name}@{digest} \
                             (held by {who}) ..."
                        ),
                        None => crate::quiet::note!(
                            "virtkit: waiting for a concurrent {verb} of {name}@{digest} ..."
                        ),
                    }
                }
                // Said at the first refusal, and again when another holder answers: the one
                // waited for went, and another job took the name.
                let said = Activity::Waiting {
                    image: name.to_string(),
                    building: verb == "build",
                    holder: who.clone(),
                };
                if let Some(waiting) = &waiting {
                    if holder.is_some() && who != waited_for {
                        waiting.change(said);
                    }
                } else {
                    waiting = Some(sink.say(said));
                }
                if holder.is_some() {
                    waited_for = who;
                }
                std::thread::sleep(poll);
            }
            None => std::thread::sleep(poll),
        }
    }
}

fn pull_lock(held: hostlock::Held, sink: Arc<crate::activity::Sink>) -> PullLock {
    PullLock {
        said: None,
        _held: held,
        sink,
    }
}

/// Mark a resolved base as freshly used: ensure its `.inuse` lock file exists and bump the
/// `.used` idle marker to now, so the idle GC never reclaims a base the executor is about to
/// overlay. Called on every resolve (hit or miss). Best-effort.
pub(crate) fn mark_used(dir: &Path) {
    crate::cachelock::stamp(&dir.join(".inuse"), &dir.join(".used"));
}

/// The managed cache tiers under `state_dir`: pulled registry bundles, pulled docker
/// images, and built `build:` stages. A base in any of these is reference-counted and
/// idle-evicted; a baked `[local]` bundle or an ephemeral rootfs is not.
pub(crate) fn cache_tiers(state_dir: &Path) -> [PathBuf; 3] {
    [
        state_dir.join("registry"),
        state_dir.join("docker"),
        state_dir.join("build"),
    ]
}

/// Take a shared-lock reference on the materialized base backing `rootfs`, iff it lives in
/// a managed cache tier (see [`cache_tiers`]). Returns `None` for a baked `[local]` bundle
/// or an ephemeral rootfs — nothing there is reference-counted or evicted. Hold the returned
/// guard for as long as anything depends on the base — a live overlay over it, but equally a
/// caller that resolved it and only boots it later: a base is reclaimable the instant nobody
/// holds a reference, whatever a freshness check last said.
pub(crate) fn acquire_use_lock_for(
    state_dir: &Path,
    rootfs: &Path,
) -> Result<Option<crate::cachelock::Guard>> {
    let Some(dir) = rootfs.parent() else {
        return Ok(None);
    };
    if !cache_tiers(state_dir).iter().any(|t| dir.starts_with(t)) {
        return Ok(None);
    }
    // Date the entry from release, not from acquisition: these references are held for a whole
    // job now (a build's source, a running service's base), and dating from the moment it was
    // taken would leave a long job's base looking idle for the length of that job.
    Ok(Some(crate::cachelock::acquire_shared(
        &dir.join(".inuse"),
        &dir.join(".used"),
    )?))
}

/// What [`gc_idle`] or [`evict_for_room`] evicted.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Evicted {
    pub(crate) bases: u64,
    /// Unreferenced registry chunk files, which only [`evict_for_room`] counts.
    pub(crate) chunks: u64,
    /// The disk space they held.
    pub(crate) bytes: u64,
    /// On a dry run of [`collect_idle`], the bases it would evict, for [`collect_chunks`] to
    /// count the chunks only they reference.
    pub(crate) would_evict: Vec<PathBuf>,
}

/// Evict every materialized base under `root` that no process is overlaying and that has
/// been idle at least `idle`, on [`crate::cachelock`]'s protocol, and say once what went.
/// Bases are found without following a symlink or leaving the tier root's filesystem, and
/// removed through descriptors (see [`vk_fs::remove_tree_in`]): no symlink inside followed,
/// nothing mounted inside entered, nothing another user owns removed. Best-effort.
pub(crate) fn gc_idle(root: &Path, idle: std::time::Duration) -> Evicted {
    let evicted = collect_idle(root, idle, false);
    if evicted.bases > 0 {
        crate::quiet::note!(
            "virtkit: evicted {} idle image(s) under {}, {}",
            evicted.bases,
            root.display(),
            crate::usage::fmt_bytes(evicted.bytes)
        );
    }
    evicted
}

/// [`gc_idle`] without the report. With `dry_run`, count what it would evict and leave it: a
/// base is judged under the same exclusive lock, then measured once the lock is let go, by the
/// rule its removal counts by. Like a real pass, a dry one creates the `.inuse` sidecar of a
/// base that has none, to lock it.
pub(crate) fn collect_idle(root: &Path, idle: std::time::Duration, dry_run: bool) -> Evicted {
    let now = std::time::SystemTime::now();
    let mut evicted = Evicted::default();
    for base in base_dirs(root) {
        let judged = crate::cachelock::try_reclaim(
            &base.join(".inuse"),
            &base.join(".used"),
            idle,
            now,
            || {
                if !dry_run {
                    remove_counted(&base, &mut evicted);
                }
            },
        );
        if judged && dry_run {
            evicted.bases += 1;
            // A tree that cannot be read counts as nothing, as its removal would fail.
            let held = crate::usage::removable_bytes(&base).unwrap_or(0);
            evicted.bytes = evicted.bytes.saturating_add(held);
            evicted.would_evict.push(base);
        }
    }
    evicted
}

/// Evict `base` with [`gc_idle`]'s locking and removal rules but no idle delay.
/// Only unused entries are removed. Best-effort; removal failures are reported.
pub(crate) fn evict_unused(base: &Path) {
    let mut evicted = Evicted::default();
    crate::cachelock::try_reclaim(
        &base.join(".inuse"),
        &base.join(".used"),
        std::time::Duration::ZERO,
        std::time::SystemTime::now(),
        || {
            remove_counted(base, &mut evicted);
        },
    );
}

/// Remove `base` under the caller's exclusive lock and add its space to `evicted`.
/// Return whether removal succeeded.
fn remove_counted(base: &Path, evicted: &mut Evicted) -> bool {
    match remove_base(base) {
        Ok(bytes) => {
            evicted.bases += 1;
            evicted.bytes = evicted.bytes.saturating_add(bytes);
            true
        }
        Err(e) => {
            eprintln!("virtkit: evicting {}: {e:#}", base.display());
            false
        }
    }
}

/// Remove `base` and return the space it held. Remove its image first so interrupted removal
/// leaves a cache miss, never a hit on a half-removed image.
fn remove_base(base: &Path) -> Result<u64> {
    use std::os::fd::{AsFd, AsRawFd};

    let (Some(parent), Some(name)) = (base.parent(), base.file_name()) else {
        bail!("{} names no entry", base.display());
    };
    let parent = vk_fs::open_dir(parent)?;
    let dir = vk_fs::open_dir_in(parent.as_fd(), name)?;
    let mut bytes = 0u64;
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    for image in ["runner.ext4", crate::ensure::UNIT_IMAGE] {
        let image = std::ffi::OsStr::new(image);
        // Another user's is left to the tree removal, which reports it.
        let Some(st) = stat_in(dir.as_fd(), image).filter(|st| st.st_uid == me) else {
            continue;
        };
        let c_image = std::ffi::CString::new(image.as_bytes())?;
        // SAFETY: the descriptor is live and the name NUL-terminated.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), c_image.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e).with_context(|| format!("removing {}", base.join(image).display()));
            }
        } else if st.st_nlink <= 1 {
            let held = u64::try_from(st.st_blocks).unwrap_or(0).saturating_mul(512);
            bytes = bytes.saturating_add(held);
        }
    }
    let done = vk_fs::remove_tree_in(parent.as_fd(), name, dir.as_fd())?;
    if !done.skipped.is_empty() {
        let kept: Vec<_> = done
            .skipped
            .iter()
            .map(|p| base.with_file_name(p).display().to_string())
            .collect();
        bail!(
            "left in place (a mount, another filesystem or another user's): {}",
            kept.join(", ")
        );
    }
    Ok(bytes.saturating_add(done.bytes))
}

/// Run [`gc_idle`] on the job image tiers under `state_dir`: pulled `virtkit/` bundles,
/// pulled docker images and built stages. Also remove chunks no bundle references.
pub(crate) fn evict_idle_images(state_dir: &Path, idle: std::time::Duration) {
    let registry = state_dir.join("registry");
    gc_idle(&registry, idle);
    sweep_chunks(&registry);
    for tier in ["docker", "build"] {
        gc_idle(&state_dir.join(tier), idle);
    }
}

/// The least time [`evict_for_room`] lets a base sit unused before taking it, unless
/// `image_cache_idle_secs` is shorter still. A resolve stamps its base used and its caller only
/// then takes the reference that protects it (`registry::resolve_async`, `dockerimg`, then
/// `vm::prepare`, `vm::supervise`, `vm::plan_services`): moments apart in one process, but
/// moments a host deep in swap can stretch, and a base caught in between must not go. Short
/// against the hours an idle window runs to, so what pressure frees is still nearly everything.
pub(crate) const EVICT_GRACE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// The longest [`evict_for_room`] waits for the eviction ahead of it on the same state dir. On a
/// node the wait holds up its session, heartbeats included, so it is short.
pub(crate) const EVICT_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// A base [`evict_for_room`] may take, locked exclusively for as long as this lives: what was
/// counted toward the room is what is still there to remove.
struct Candidate {
    used: std::time::SystemTime,
    base: PathBuf,
    bytes: u64,
    _lock: crate::cachelock::Exclusive,
}

/// What [`evict_for_room`] did: what it evicted, and what taking everything it could would have
/// freed. Below the need it was asked for, that is why it evicted nothing; `None` where it did
/// not look, held up past its wait by the eviction ahead of it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ForRoom {
    pub(crate) evicted: Evicted,
    pub(crate) reach: Option<u64>,
}

impl ForRoom {
    pub(crate) fn reclaimed(&self) -> crate::admit::Reclaimed {
        crate::admit::Reclaimed {
            freed: self.evicted.bytes,
            reach: self.reach,
        }
    }
}

/// Make room for `need` bytes on the filesystem holding `on` (the job dirs) from the image
/// tiers [`evict_idle_images`] sweeps, those of them on that filesystem only: unreferenced
/// registry chunks first, then bases nobody holds, least recently used first and whatever their
/// idle window past a short grace ([`EVICT_GRACE`], or `idle` where that is shorter), stopping
/// once `need` has come free. A base in use is never touched, on [`crate::cachelock`]'s
/// protocol, nor one in `keep`: the bases the asking job is about to boot, which nothing
/// references yet. All or nothing: when everything it could take falls short of `need`, it
/// takes nothing, since a partial eviction would cost re-pulls without admitting anyone. Says
/// once what went; best-effort, like [`gc_idle`].
///
/// One at a time per state dir, behind `<state_dir>/.evict.lock`, waited for up to `wait`: two
/// evictions scanning at once would each lock a share of the candidates, and each find its
/// share short. [`gc_idle`] takes no part in that lock. It needs none: both take a base only
/// under its exclusive lock, so a base one of them holds the other passes over, and one gone
/// before this scan is simply not counted.
pub(crate) fn evict_for_room(
    state_dir: &Path,
    idle: std::time::Duration,
    on: &Path,
    need: u64,
    keep: &[PathBuf],
    wait: std::time::Duration,
) -> ForRoom {
    use std::os::unix::fs::MetadataExt;

    let mut room = ForRoom {
        evicted: Evicted::default(),
        reach: Some(0),
    };
    let Some(on_fs) = crate::usage::fs_id(on) else {
        return room;
    };
    // By identity, not spelling: a state dir reached through a symlink names one base two ways.
    let id = |p: &Path| std::fs::metadata(p).map(|m| (m.dev(), m.ino())).ok();
    let keep: Vec<_> = keep.iter().filter_map(|k| id(k)).collect();
    let tiers: Vec<PathBuf> = cache_tiers(state_dir)
        .into_iter()
        .filter(|t| crate::usage::fs_id(t) == Some(on_fs))
        .collect();
    if tiers.is_empty() {
        return room;
    }
    // Waited for, not just tried: the eviction ahead may be freeing what this one needs. Only
    // for so long, as the caller may be a node's session with heartbeats to send.
    let denied = |e: &anyhow::Error| {
        e.chain().any(|c| {
            c.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        })
    };
    let lock = state_dir.join(".evict.lock");
    let _serial = match crate::cachelock::lock_exclusive_within(&lock, wait) {
        Ok(Some(serial)) => Some(serial),
        Ok(None) => {
            println!(
                "virtkit: not evicting for room in {}: another eviction under {} held {} for {}s",
                on.display(),
                state_dir.display(),
                lock.display(),
                wait.as_secs()
            );
            room.reach = None;
            return room;
        }
        // Another user's lock, left 0600 by the runner that made it, is no reason to keep the
        // caches: the lock only spares two evictions each finding a share of the candidates
        // too short, and every base is still taken only under its own exclusive lock.
        Err(e) if denied(&e) => None,
        Err(e) => {
            eprintln!("virtkit: evicting for room: {e:#}");
            return room;
        }
    };
    let registry = state_dir.join("registry");
    let chunks = tiers.contains(&registry);
    let grace = idle.min(EVICT_GRACE);
    let now = std::time::SystemTime::now();
    let mut candidates: Vec<Candidate> = tiers
        .iter()
        .flat_map(|t| base_dirs(t))
        .filter(|b| id(b).is_none_or(|i| !keep.contains(&i)))
        .filter_map(|base| {
            let used = base.join(".used");
            // An undated base is mid-setup and never a candidate, as `try_reclaim` would refuse
            // it; checked before the lock, whose sidecar taking it would create.
            std::fs::metadata(&used).ok()?;
            let lock = crate::cachelock::try_exclusive(&base.join(".inuse"))?;
            // Dated under the lock, as `cachelock::is_idle` dates them.
            let at = std::fs::metadata(&used).and_then(|m| m.modified()).ok()?;
            crate::cachelock::is_idle(&used, grace, now).then(|| Candidate {
                used: at,
                bytes: removable_bytes(&base),
                base,
                _lock: lock,
            })
        })
        .collect();
    candidates.sort_by(|a, b| (a.used, &a.base).cmp(&(b.used, &b.base)));
    let sum =
        |chunks: &[(PathBuf, u64)]| chunks.iter().map(|(_, b)| *b).fold(0, u64::saturating_add);
    // What taking every candidate would free: their bases, and the chunks no other bundle names.
    let bases = candidates
        .iter()
        .map(|c| c.bytes)
        .fold(0, u64::saturating_add);
    let (dead_now, dead_after) = match chunks {
        true => {
            let taken = |b: &Path| candidates.iter().any(|c| c.base == b);
            let after = sum(&dead_chunks(&registry, |b| !taken(b)));
            (sum(&dead_chunks(&registry, |_| true)), after)
        }
        false => (0, 0),
    };
    // Counted short where it errs — a file another link keeps, a bundle's own chunks before it
    // goes — so the gate may refuse what removal would have freed, never pass on what it won't.
    let reach = bases.saturating_add(dead_after);
    room.reach = Some(reach);
    if reach < need {
        return room;
    }
    // Only the least recently used candidates that cover `need` stay locked; the rest go back
    // to their users now rather than wait out the removals. Counted on the bases and the chunks
    // already dead alone, which a bundle's own chunks only add to: where that falls short,
    // every candidate is kept.
    let mut covered = dead_now;
    if let Some(n) = candidates.iter().position(|c| {
        covered = covered.saturating_add(c.bytes);
        covered >= need
    }) {
        candidates.truncate(n + 1);
    }
    let evicted = &mut room.evicted;
    let drop_chunks = |evicted: &mut Evicted| {
        let (dropped, bytes) = drop_unreferenced_chunks(&registry);
        evicted.chunks = evicted.chunks.saturating_add(dropped as u64);
        evicted.bytes = evicted.bytes.saturating_add(bytes);
    };
    if chunks {
        drop_chunks(evicted);
    }
    // Each candidate's lock drops with it, as it goes or once `need` is met.
    for c in candidates {
        if evicted.bytes >= need {
            break;
        }
        // A registry bundle's chunks come free with the last bundle that used them.
        if remove_counted(&c.base, evicted) && chunks && c.base.starts_with(&registry) {
            drop_chunks(evicted);
        }
    }
    let what: Vec<String> = [
        (evicted.bases, "unused image(s)"),
        (evicted.chunks, "unreferenced cache chunk file(s)"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if !what.is_empty() {
        crate::quiet::note!(
            "virtkit: evicted {} under {} for room in {}: {} freed of the {} needed",
            what.join(" and "),
            state_dir.display(),
            on.display(),
            crate::usage::fmt_bytes(evicted.bytes),
            crate::usage::fmt_bytes(need)
        );
    }
    room
}

/// What removing `base` would free, counted as [`remove_base`] counts it: a file with another
/// link keeps its space. Walked as [`crate::usage::allocated_bytes`] walks a job dir.
fn removable_bytes(base: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;

    let Ok(dev) = std::fs::metadata(base).map(|m| m.dev()) else {
        return 0;
    };
    let mut total = 0u64;
    let mut dirs: Vec<_> = std::fs::read_dir(base).into_iter().collect();
    while let Some(entries) = dirs.pop() {
        for entry in entries.flatten() {
            // `DirEntry::metadata` does not traverse a symlink.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.dev() != dev {
                continue;
            }
            if meta.is_dir() || meta.nlink() <= 1 {
                total = total.saturating_add(meta.blocks().saturating_mul(512));
            }
            if meta.is_dir()
                && let Ok(sub) = std::fs::read_dir(entry.path())
            {
                dirs.push(sub);
            }
        }
    }
    total
}

/// Record the bases a job is about to boot under its usage `key` in `dir`, so its next
/// admission excludes them from [`evict_for_room`]. Admission precedes image resolution,
/// so the previous run is the best predictor of which bases it needs. Replace the note
/// by rename; omit paths containing newlines because each line holds one path.
/// Best-effort, like run history: losing the note costs a re-pull.
pub(crate) fn remember_bases(dir: &Path, key: &Path, bases: &[PathBuf]) {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    let Some(path) = crate::admit::under(dir, key) else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    // 0700 on create and on reuse, as the run history beside it; set through the directory
    // itself, opened without following a symlink in its place.
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .is_err()
    {
        return;
    }
    for private in [dir, parent] {
        let restricted = std::fs::File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(private)
            .and_then(|d| d.set_permissions(std::fs::Permissions::from_mode(0o700)));
        if restricted.is_err() {
            return;
        }
    }
    let mut text = Vec::new();
    for base in bases.iter().map(|b| b.as_os_str().as_bytes()) {
        if !base.contains(&b'\n') {
            text.extend_from_slice(base);
            text.push(b'\n');
        }
    }
    // Separate staging files let concurrent runs publish whole notes; the last rename wins.
    let _ = vk_fs::write_atomic_unsynced(&path, &text, 0o600);
}

/// What [`remember_bases`] last noted under `key`. Only ever a list of what to keep, so a note
/// naming anything else costs nothing; only absolute paths are read back.
pub(crate) fn remembered_bases(dir: &Path, key: &Path) -> Vec<PathBuf> {
    let Some(text) = crate::admit::under(dir, key).and_then(|p| std::fs::read(p).ok()) else {
        return Vec::new();
    };
    text.split(|&b| b == b'\n')
        .map(|line| PathBuf::from(std::ffi::OsStr::from_bytes(line)))
        .filter(|p| p.is_absolute())
        .collect()
}

/// Every materialized base under `root`: a directory directly holding a `runner.ext4`. The
/// name between `root` and the digest can be multi-level (a `team/img` docker repo), so walk
/// down, treating any dir with a `runner.ext4` as a base and not descending into it. This
/// also walks into a `.tmp` mid-build (it can already hold a `runner.ext4` before promotion)
/// — harmless, since `gc_idle`'s `try_reclaim` bails out on that path's missing `.used`
/// marker; a `.tmp`'s own cleanup is [`sweep_orphaned_build_tmp`]'s job, not this walk's.
/// A promoted image: pulled-tier `runner.ext4` or the current or legacy build-tier name.
fn is_base_dir(dir: &Path) -> bool {
    dir.join("runner.ext4").is_file() || dir.join(crate::ensure::UNIT_IMAGE).is_file()
}

fn base_dirs(root: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let mut out = Vec::new();
    // Allow an operator's symlink to the root, but keep the walk on that filesystem.
    let Ok(dev) = std::fs::metadata(root).map(|m| m.dev()) else {
        return out;
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if is_base_dir(&dir) {
            out.push(dir);
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            // The entry itself: a symlink is not walked into, nor another filesystem. The type
            // comes from the directory listing, so the files of a tier that shares its root with
            // the build-cache store (its blobs, by the hundred thousand) cost no stat each.
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if e.metadata().is_ok_and(|m| m.dev() == dev) {
                stack.push(e.path());
            }
        }
    }
    out
}

/// A tier's `.tmp` staging dir (a build stage under `ensure::ensure_build_tier`, or a
/// docker-tier pull under `dockerimg::build`), claimed for as long as this guard lives and
/// removed on drop unless [`Self::keep`] consumed it first — so it is wiped the instant its
/// build/pull fails or panics rather than left for a sweep. The claim is an exclusive `flock`
/// on the directory, which the kernel drops however the process ends; it is what
/// [`sweep_orphaned_build_tmp`] reads, with the pull lock, to tell a dead dir from a live one.
/// A SIGTERM or SIGINT that would end the process removes the dir first (see
/// [`crate::termclean`]).
pub(crate) struct TmpGuard<'a> {
    path: &'a Path,
    /// `None` on a filesystem that cannot take the `flock`, where the pull lock alone holds.
    claim: Option<vk_fs::LockFile>,
    _on_signal: crate::termclean::Registration,
    keep: bool,
}

impl<'a> TmpGuard<'a> {
    /// Create `path` afresh, removing what a past build or pull left there, and claim it. The
    /// caller holds the pull lock of the dir `path` is promoted to, so whatever it removes is
    /// dead. On a filesystem that cannot take the claim (NFS, or no `flock` support), the dir
    /// goes unclaimed and the pull lock alone holds; one already claimed is an error.
    pub(crate) fn create(path: &'a Path) -> Result<Self> {
        Self::create_locking(path, flock_nb)
    }

    /// [`Self::create`], claiming with `lock`.
    fn create_locking(
        path: &'a Path,
        lock: impl Fn(&std::fs::File) -> std::io::Result<()>,
    ) -> Result<Self> {
        // Ignored: under the pull lock whatever is there is dead, and the build writes every
        // file a promoted dir is read for; a remnant this cannot remove is only carried along.
        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
        let dir =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let claimed = match lock(&dir) {
            Ok(()) => true,
            // Held: a live build reached this dir without the pull lock, and it is its to
            // remove, not this one's — on a signal either.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(e).with_context(|| format!("claiming {}", path.display()));
            }
            Err(_) => false,
        };
        let on_signal = crate::termclean::remove_on_signal(path, std::os::fd::AsFd::as_fd(&dir));
        let claim = claimed.then(|| vk_fs::LockFile::new(dir));
        Ok(TmpGuard {
            path,
            claim,
            _on_signal: on_signal,
            keep: false,
        })
    }

    /// Transfer removal responsibility to the caller promoting (renaming) `path`. Return the
    /// claim for the caller to hold through the rename, keeping the `.tmp` directory claimed.
    /// Consume `self` rather than borrow it mutably: its destructor runs immediately with
    /// removal disabled by `keep`, without `mem::forget` or `ManuallyDrop`. That destructor
    /// also unregisters the dir from removal on a signal, before the caller promotes it.
    #[must_use = "the claim is to be held until the dir is renamed away"]
    pub(crate) fn keep(mut self) -> Option<vk_fs::LockFile> {
        self.keep = true;
        self.claim.take()
    }
}

impl Drop for TmpGuard<'_> {
    fn drop(&mut self) {
        if !self.keep
            && let Err(e) = std::fs::remove_dir_all(self.path)
        {
            eprintln!("virtkit: removing {}: {e}", self.path.display());
        }
    }
}

/// Take an exclusive `flock` on `file` without waiting: `WouldBlock` when another holds one.
fn flock_nb(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    // SAFETY: the fd is open for the borrow; flock returns 0 or -1 and does not block under
    // `LOCK_NB`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// How long a `.tmp` staging dir is left after it or an entry directly in it last changed,
/// whatever its locks say: a build from before [`TmpGuard`] claimed its dir, or on a
/// filesystem without `flock`, is judged by the pull lock alone.
const DEAD_TMP_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

/// How many name levels below a tier root [`sweep_orphaned_build_tmp`] descends: a bound on
/// the walk, not on names. The build tier's staging dirs sit right under it, the docker tier's
/// under a repository name a group deeper per level, up to 20 nested groups on GitLab.
const TMP_SWEEP_DEPTH: usize = 64;

/// Whether a sweep also names the dead dirs it left: another user's, and those a removal
/// could not finish. They stay until someone acts on them, so only the sweeps an operator
/// starts or reads — a node reset, the node's first — name them, not every build's and job's.
/// `vk gc` lists them in its summary instead ([`collect_orphaned_staging`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leftovers {
    Name,
    Quiet,
}

/// What [`sweep_orphaned_build_tmp`] reclaimed and left.
#[derive(Debug, Default)]
pub(crate) struct Swept {
    /// Dead staging dirs removed.
    pub(crate) dirs: u64,
    /// The disk space they held.
    pub(crate) bytes: u64,
    /// Dead staging dirs another user owns, left for that user's own sweeps.
    pub(crate) foreign: Vec<PathBuf>,
    /// What a removal left in place (a mount inside a staging dir) or failed on.
    pub(crate) left: Vec<String>,
}

impl Swept {
    /// Say in one line what the sweep of `root` reclaimed, nothing when it reclaimed nothing,
    /// and, with [`Leftovers::Name`], what it left.
    fn report(&self, root: &Path, leftovers: Leftovers) {
        if self.dirs > 0 {
            crate::quiet::note!(
                "virtkit: reclaimed {} dead build dir(s) under {}, {}",
                self.dirs,
                root.display(),
                crate::usage::fmt_bytes(self.bytes)
            );
        }
        if leftovers == Leftovers::Quiet {
            return;
        }
        if !self.foreign.is_empty() {
            let dirs: Vec<_> = self
                .foreign
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            eprintln!(
                "virtkit: left {} dead build dir(s) owned by another user: {}",
                dirs.len(),
                dirs.join(", ")
            );
        }
        for left in &self.left {
            eprintln!("virtkit: reclaiming a dead build dir: {left}");
        }
    }
}

/// Reclaim the `<name>.tmp` staging dirs under `root` (a build-tier or docker-tier cache dir)
/// left by builds and pulls that died before promoting them — a job killed with its node
/// service, cancelled, or OOM-killed runs no destructor. Such a dir never gets a `.used`
/// marker, so [`gc_idle`] never reaches it. Say in one line what was reclaimed.
///
/// A dir is dead when nothing holds either of its locks: the pull lock of the dir it is
/// promoted to (`acquire_pull_lock`, held from before the `.tmp` is created to after its
/// promotion or removal) and the [`TmpGuard`] claim on the dir itself, held until it is
/// renamed away. The pull lock is an abstract socket named after the path, so it alone
/// misjudges a build in another network namespace, or one that reached the tier by another
/// path; the claim is held by the open directory and alone misjudges a `vk` that predates it,
/// or a filesystem without `flock`. Both are held across the removal, so a build of the same
/// stage waits it out, and a dir that or an entry directly in it changed within
/// [`DEAD_TMP_GRACE`] is left whatever they say. A dir another user owns is left.
///
/// The dir removed is the inode judged, never what its name leads to by then, and the tree is
/// walked and removed through descriptors (see [`vk_fs::remove_tree_in`]): a symlink is never
/// followed, whether to a staging dir or out of one, and nothing mounted inside one is
/// entered. Best-effort: what cannot be read is left for the next sweep.
pub(crate) fn sweep_orphaned_build_tmp(root: &Path, leftovers: Leftovers) -> Swept {
    let swept = sweep_dead_tmp(root, DEAD_TMP_GRACE, false);
    swept.report(root, leftovers);
    swept
}

/// [`sweep_orphaned_build_tmp`] on both tiers under `state_dir` that stage: built stages and
/// pulled docker images.
pub(crate) fn sweep_orphaned_staging(state_dir: &Path, leftovers: Leftovers) {
    for tier in ["build", "docker"] {
        sweep_orphaned_build_tmp(&state_dir.join(tier), leftovers);
    }
}

/// [`sweep_orphaned_build_tmp`] on the staging tier at `root` (`build/` or `docker/`), without
/// the report. With `dry_run`, count the dead dirs it would remove and leave them.
pub(crate) fn collect_orphaned_staging(root: &Path, dry_run: bool) -> Swept {
    sweep_dead_tmp(root, DEAD_TMP_GRACE, dry_run)
}

/// [`sweep_orphaned_build_tmp`] with the grace spelled out, without the report.
fn sweep_dead_tmp(root: &Path, grace: std::time::Duration, dry_run: bool) -> Swept {
    let mut sweep = TmpSweep {
        grace,
        dry_run,
        now: std::time::SystemTime::now(),
        swept: Swept::default(),
    };
    // The root may be reached through a link of the operator's; nothing below it is.
    if let Ok(top) = vk_fs::open_dir(root) {
        sweep.level(&top, root, 0);
    }
    sweep.swept
}

/// [`sweep_dead_tmp`]'s state across the walk.
struct TmpSweep {
    grace: std::time::Duration,
    /// Count the dead dirs instead of removing them.
    dry_run: bool,
    now: std::time::SystemTime,
    swept: Swept,
}

impl TmpSweep {
    /// Reclaim the dead staging dirs in the open dir `dir`, shown as `path` and `depth` levels
    /// below the tier root, and descend into its other dirs but a promoted base. Names are
    /// read first and each opened in turn, so one descriptor per level is open at a time.
    fn level(&mut self, dir: &std::os::fd::OwnedFd, path: &Path, depth: usize) {
        use std::os::fd::AsFd;

        let Ok(names) = vk_fs::dir_names(dir.as_fd()) else {
            return;
        };
        for name in names {
            let at = path.join(&name);
            if Path::new(&name).extension() == Some(std::ffi::OsStr::new("tmp")) {
                self.reclaim_if_dead(dir, &name, &at);
                continue;
            }
            if depth + 1 >= TMP_SWEEP_DEPTH {
                continue;
            }
            // Refuses a symlink and anything but a directory.
            let Ok(sub) = vk_fs::open_dir_in(dir.as_fd(), &name) else {
                continue;
            };
            // A promoted base: nothing to sweep inside it.
            if !holds_base(&sub) {
                self.level(&sub, &at, depth + 1);
            }
        }
    }

    /// Remove the staging dir `name` in `parent`, shown as `at`, if it is dead — see
    /// [`sweep_orphaned_build_tmp`] — and account for it.
    fn reclaim_if_dead(
        &mut self,
        parent: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
        at: &Path,
    ) {
        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::fs::MetadataExt;

        let Ok(dir) = vk_fs::open_dir_in(parent.as_fd(), name) else {
            return; // gone, not a directory, or a symlink
        };
        // Hold the lock and answer waiters throughout removal. A dry run only probes it.
        let entry = at.with_extension("");
        let _pull = if self.dry_run {
            if pull_lock_held(&entry) {
                return; // a build or pull of this entry is in flight
            }
            None
        } else {
            let Some(pull) = try_acquire_pull_lock(&entry) else {
                return; // a build or pull of this entry is in flight
            };
            Some(pull)
        };
        // Reopened from the descriptor, the same inode, for a lock `flock` can take.
        let Ok(claim) =
            vk_fs::reopen_dir(dir.as_fd()).map(|fd| vk_fs::LockFile::new(std::fs::File::from(fd)))
        else {
            return;
        };
        let Ok(meta) = claim.metadata() else {
            return;
        };
        let Some(changed) = last_changed(&claim) else {
            return;
        };
        if self.now.duration_since(changed).unwrap_or_default() < self.grace {
            return;
        }
        // Held while the tree goes. Only a holder refuses it: where the filesystem has no
        // `flock`, no build holds one either, and the pull lock and the grace decide alone.
        if flock_nb(&claim).is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) {
            return; // claimed by a live build
        }
        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            self.swept.foreign.push(at.to_path_buf());
            return;
        }
        let swept = &mut self.swept;
        if self.dry_run {
            swept.dirs += 1;
            // Through the descriptor judged, not the name; a tree that cannot be read counts as
            // nothing, as its removal would fail.
            let held = format!("/proc/self/fd/{}", claim.as_raw_fd());
            let held = crate::usage::removable_bytes(Path::new(&held)).unwrap_or(0);
            swept.bytes = swept.bytes.saturating_add(held);
            return;
        }
        match vk_fs::remove_tree_in(parent.as_fd(), name, dir.as_fd()) {
            Ok(done) => {
                swept.bytes = swept.bytes.saturating_add(done.bytes);
                if done.skipped.is_empty() {
                    swept.dirs += 1;
                } else {
                    let kept: Vec<_> = done
                        .skipped
                        .iter()
                        .map(|p| at.with_file_name(p).display().to_string())
                        .collect();
                    swept.left.push(format!(
                        "{}: left in place (a mount, another filesystem or another user's): {}",
                        at.display(),
                        kept.join(", ")
                    ));
                }
            }
            Err(e) => swept.left.push(format!("{}: {e:#}", at.display())),
        }
    }
}

/// The `stat` of `name` in `dir`, unfollowed.
fn stat_in(dir: std::os::fd::BorrowedFd<'_>, name: &std::ffi::OsStr) -> Option<libc::stat> {
    use std::os::fd::AsRawFd;

    let name = std::ffi::CString::new(name.as_bytes()).ok()?;
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is open for the borrow, the name NUL-terminated, `st` writable.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    (rc == 0).then_some(st)
}

/// When the open dir `dir` or an entry directly in it last changed: a build writing its image
/// changes that file, not the dir. `None` when it cannot be read.
pub(crate) fn last_changed(dir: &std::fs::File) -> Option<std::time::SystemTime> {
    use std::os::fd::AsFd;

    let at = |st: &libc::stat| {
        let secs = u64::try_from(st.st_mtime).unwrap_or(0);
        let nanos = u32::try_from(st.st_mtime_nsec).unwrap_or(0);
        std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos)
    };
    let mut newest = dir.metadata().ok()?.modified().ok()?;
    for name in vk_fs::dir_names(dir.as_fd()).ok()? {
        // Gone since the listing: nothing newer to read.
        if let Some(st) = stat_in(dir.as_fd(), &name) {
            newest = newest.max(at(&st));
        }
    }
    Some(newest)
}

/// Whether the open dir `dir` is a promoted base, by [`is_base_dir`]'s test.
fn holds_base(dir: &std::os::fd::OwnedFd) -> bool {
    ["runner.ext4", crate::ensure::UNIT_IMAGE]
        .iter()
        .any(|name| {
            stat_in(std::os::fd::AsFd::as_fd(dir), std::ffi::OsStr::new(name))
                .is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG)
        })
}

/// The name a pull stages a chunk under before renaming it onto its digest: the digest,
/// then who is writing it. Two pulls of one chunk — concurrent stage restores within a
/// build, or two jobs sharing the store — must not share the file. Both write the same
/// bytes, since the name is the digest, so the hazard is not a mix but a truncation: one
/// writer reopening the file empty under another's finished write lets that writer's rename
/// publish a partial chunk. The pid separates processes, the counter the writes inside one.
pub(crate) fn staging_chunk_name(hex: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "{hex}.{}-{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Whether the pull that staged a [`staging_chunk_name`] in the chunk store is dead, so the
/// file will never be renamed into place. A name that does not carry a pid is from an older
/// `vk` (or is not ours at all) and is reported as still live — never reclaiming someone
/// else's in-flight write is worth leaving the odd stale file behind.
pub(crate) fn staging_writer_is_gone(name: &str) -> bool {
    name.strip_suffix(".tmp")
        .and_then(|rest| rest.rsplit_once('.'))
        .and_then(|(_hex, owner)| owner.split_once('-'))
        .and_then(|(pid, _seq)| pid.parse::<u32>().ok())
        .is_some_and(|pid| !crate::spawn::pid_alive(pid))
}

/// Drop chunk blobs in `<registry_root>/chunks/` that no cached bundle references. Each
/// pulled bundle records the chunk digests it was reassembled from in a `chunks.list`; the
/// union over every still-present bundle is the live set. A chunk is only a re-pull
/// optimization shared across bundles, so once every bundle that used it has been evicted it
/// is dead weight — this ties the deduped chunk store's lifetime to the idle-evicted bundles.
/// Re-materializing a swept chunk just re-downloads it. Best-effort.
pub(crate) fn sweep_chunks(registry_root: &Path) {
    let (dropped, _) = drop_unreferenced_chunks(registry_root);
    if dropped > 0 {
        println!("virtkit: swept {dropped} unreferenced cache chunk file(s)");
    }
}

/// [`sweep_chunks`] without the report: the number of chunk files removed and the space they
/// held. With `dry_run`, what it would remove, left in place, once the bases a dry
/// [`collect_idle`] of the registry tier would evict (`would_evict`) are gone.
pub(crate) fn collect_chunks(
    registry_root: &Path,
    dry_run: bool,
    would_evict: &[PathBuf],
) -> (u64, u64) {
    if !dry_run {
        let (dropped, bytes) = drop_unreferenced_chunks(registry_root);
        return (u64::try_from(dropped).unwrap_or(u64::MAX), bytes);
    }
    dead_chunks(registry_root, |b| !would_evict.iter().any(|w| w == b))
        .into_iter()
        .fold((0, 0), |(n, b), (_, held)| (n + 1, b.saturating_add(held)))
}

/// Sweep chunks without reporting; return the number removed and the space they held.
fn drop_unreferenced_chunks(registry_root: &Path) -> (usize, u64) {
    let (mut dropped, mut bytes) = (0usize, 0u64);
    for (p, held) in dead_chunks(registry_root, |_| true) {
        if std::fs::remove_file(&p).is_ok() {
            dropped += 1;
            bytes = bytes.saturating_add(held);
        }
    }
    (dropped, bytes)
}

/// List files in the `<registry_root>/chunks/` directories returned by
/// [`crate::registry::chunk_cache_dirs`] that no bundle accepted by `counts` references,
/// with the space each holds. These are what [`drop_unreferenced_chunks`] would remove
/// if the other bundles were gone.
fn dead_chunks(registry_root: &Path, counts: impl Fn(&Path) -> bool) -> Vec<(PathBuf, u64)> {
    use std::os::unix::fs::MetadataExt;

    let cache = registry_root.join("chunks");
    if !cache.is_dir() {
        return Vec::new();
    }
    let mut live = std::collections::HashSet::new();
    for base in base_dirs(registry_root).into_iter().filter(|b| counts(b)) {
        if let Ok(list) = std::fs::read_to_string(base.join("chunks.list")) {
            live.extend(
                list.lines()
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(str::to_string),
            );
        }
    }
    let mut dead = Vec::new();
    // A legacy entry and its codec link share an inode. Charge its blocks to the last
    // dead link only if the sweep accounts for every link.
    let mut links = std::collections::HashMap::<(u64, u64), u64>::new();
    let entries = crate::registry::chunk_cache_dirs(&cache)
        .into_iter()
        .flat_map(|dir| std::fs::read_dir(dir).into_iter().flatten().flatten());
    for e in entries {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let p = e.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // A chunk being staged into the store right now (a pull writes `<hex>.<pid>-<seq>.tmp`
        // beside its entry, then renames) is left alone; one whose writer is gone is
        // reclaimed, since nothing will ever rename it into place. An in-flight *bundle* is
        // instead kept live by its `chunks.list`, which `pull_into` writes into the staging
        // dir before fetching any chunk.
        let is_dead = if name.ends_with(".tmp") {
            staging_writer_is_gone(name)
        } else {
            !live.contains(name)
        };
        if !is_dead {
            continue;
        }
        let held = e.metadata().ok().map_or(0, |m| {
            let seen = links.entry((m.dev(), m.ino())).or_default();
            *seen += 1;
            if *seen >= m.nlink() {
                m.blocks().saturating_mul(512)
            } else {
                0
            }
        });
        dead.push((p, held));
    }
    dead
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::AtomicBool;

    /// Exactly `sha256:` and 64 lowercase hex digits names a file; every other spelling fails
    /// rather than being stripped down to one that would.
    #[test]
    fn only_a_canonical_digest_yields_its_hex() {
        let hex = "0123456789abcdef".repeat(4);
        assert_eq!(digest_hex(&format!("sha256:{hex}")).unwrap(), hex);
        for bad in [
            format!("sha256:sha256:{hex}"),
            hex.clone(),
            format!("sha256:{}", hex.to_uppercase()),
            format!("SHA256:{hex}"),
            format!("sha256:{}", &hex[..63]),
            format!("sha256:{hex}0"),
            format!("sha512:{hex}{hex}"),
            format!("sha256:{}/{}", &hex[..31], &hex[32..]),
            format!("sha256:../{}", &hex[..61]),
            "sha256:..".to_string(),
            format!("sha256:/{}", &hex[..63]),
            "sha256:/etc/passwd".to_string(),
            "sha256:".to_string(),
            String::new(),
        ] {
            let err = digest_hex(&bad).unwrap_err();
            assert!(err.to_string().contains(&format!("{bad:?}")), "{err}");
            assert_eq!(parse_digest(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn boot_kind_marker_is_trimmed() {
        // exact tags
        assert!(matches!(
            parse_boot_kind(Some("generic-disk")),
            Some(BootKind::GenericDisk)
        ));
        // trailing newline (echo) / surrounding whitespace must still match
        assert!(matches!(
            parse_boot_kind(Some("generic-disk\n")),
            Some(BootKind::GenericDisk)
        ));
        assert!(parse_boot_kind(Some("  systemd \n")).is_none());
        assert!(parse_boot_kind(None).is_none());
        // unknown markers (including the retired generic-cpio) -> stale bundle
        assert!(parse_boot_kind(Some("generic-cpio")).is_none());
        assert!(parse_boot_kind(Some("bogus")).is_none());
    }

    #[test]
    fn pull_lock_excludes_and_releases() {
        // In a process of its own: a child another test forks keeps a copy of the lock's
        // socket until it execs, and nothing unbinds a socket before then.
        const CHILD: &str = "VK_TEST_PULL_LOCK_DIR";
        let Some(dir) = crate::dev::testutil::child_marker(CHILD).map(PathBuf::from) else {
            let dir =
                std::env::temp_dir().join(format!("virtkit-test-pull-lock-{}", std::process::id()));
            crate::dev::testutil::in_child(
                "image::tests::pull_lock_excludes_and_releases",
                CHILD,
                &dir,
            );
            return;
        };
        let addr = pull_lock_addr(&dir).unwrap();
        let held = UnixListener::bind_addr(&addr).unwrap();
        let err = UnixListener::bind_addr(&addr).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(held);
        UnixListener::bind_addr(&addr).expect("the released lock addr binds again");
    }

    /// A squatter that never accepts, its backlog full, cannot hang a waiter: three queries
    /// that cannot connect fail the pull, which says it waits no more.
    #[test]
    fn a_waiter_gives_up_on_a_holder_that_never_accepts() {
        let dir = std::env::temp_dir().join(format!("virtkit-test-full-{}", std::process::id()));
        use std::os::fd::FromRawFd;
        let addr = pull_lock_addr(&dir).unwrap();
        // A listener with no backlog, which a connection or two fills — not one with the
        // default backlog, which would take thousands of descriptors to fill.
        let (sa, len) = hostlock::abstract_sockaddr(&addr).unwrap();
        // SAFETY: plain socket calls on a fresh descriptor, owned by `squatter` below; `sa`
        // and `len` describe exactly the address filled in.
        let squatter = unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0);
            assert_eq!(
                libc::bind(fd, (&raw const sa).cast(), len as libc::socklen_t),
                0
            );
            assert_eq!(libc::listen(fd, 0), 0);
            UnixListener::from_raw_fd(fd)
        };
        // Fill its backlog with connections it never accepts.
        let mut held = Vec::new();
        while let Some(c) = hostlock::connect_nonblocking(&addr).unwrap() {
            held.push(c);
            assert!(held.len() < 8, "a backlog of 0 never filled");
        }
        let said =
            std::env::temp_dir().join(format!("virtkit-test-full-said-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&said);
        std::fs::create_dir_all(&said).unwrap();
        let sink =
            crate::activity::Sink::new(Some(said.join(crate::node::jobs::journal::ACTIVITY)));
        let _outer = sink.say(Activity::Other);
        let err = acquire_pull_lock_with(
            &dir,
            "pull",
            "img",
            "sha256:x",
            std::time::Duration::from_millis(1),
            None,
            sink.clone(),
        )
        .err()
        .expect("a holder that never answers is refused")
        .to_string();
        assert!(err.contains("does not answer"), "{err}");
        assert_eq!(
            crate::node::jobs::journal::read_activity(&said),
            Some(Activity::Other)
        );
        let _ = std::fs::remove_dir_all(&said);
        drop((held, squatter));
    }

    // Asking leaves the lock as it found it.
    #[test]
    fn a_pull_lock_is_asked_after_without_taking_it() {
        let dir =
            std::env::temp_dir().join(format!("virtkit-test-pull-held-{}", std::process::id()));
        assert!(!pull_lock_held(&dir));
        let _held = try_acquire_pull_lock(&dir).expect("asking took nothing");
        assert!(pull_lock_held(&dir));
    }

    // The sweeper's lock, taken without waiting, answers like a build's: a waiter waits it out
    // rather than give up on an unanswering holder, and gets the lock once it goes.
    #[test]
    fn a_lock_taken_without_waiting_is_waited_out() {
        // A sibling fork could keep the listener bound after release. Its unanswered queries
        // would make the waiter give up. Use a short job URL so the query returns it in full.
        const CHILD: &str = "VK_TEST_PULL_WAITED_OUT";
        const NAME: &str = "image::tests::a_lock_taken_without_waiting_is_waited_out";
        const JOB: &str = "https://ci.example/job/7";
        let Some(dir) = crate::dev::testutil::child_marker(CHILD).map(PathBuf::from) else {
            let _guard = crate::dev::testutil::env_guard();
            let dir = std::env::temp_dir()
                .join(format!("virtkit-test-waited-out-{}", std::process::id()));
            let output = crate::dev::testutil::child_test(NAME)
                .env(CHILD, &dir)
                .env("CUSTOM_ENV_CI_JOB_URL", JOB)
                .output()
                .unwrap();
            crate::dev::testutil::ran_alone(NAME, &output);
            return;
        };
        assert_eq!(crate::jobctx::job_identity(), JOB);
        let held = try_acquire_pull_lock(&dir).expect("a free lock is taken");
        assert!(try_acquire_pull_lock(&dir).is_none(), "a held lock is not");
        let addr = pull_lock_addr(&dir).unwrap();
        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        // Check the responder's job identity as well as the kernel's peer UID.
        let answered = || {
            let holder = hostlock::query_holder(&addr).unwrap().unwrap();
            assert_eq!(holder.uid, Some(me));
            assert_eq!(holder.who.as_deref(), Some(JOB));
        };
        answered();
        let (heard, said) = std::sync::mpsc::channel();
        let waiter = {
            let dir = dir.clone();
            std::thread::spawn(move || {
                acquire_pull_lock_with(
                    &dir,
                    "build",
                    "img",
                    "sha256:x",
                    std::time::Duration::from_millis(1),
                    Some(std::time::Duration::ZERO),
                    crate::activity::Sink::heard(heard),
                )
                .map(drop)
            })
        };
        // Wait for the first contention report before querying the holder again.
        assert!(matches!(
            said.recv_timeout(std::time::Duration::from_secs(30))
                .expect("the waiter never said it waits"),
            Activity::Waiting { building: true, .. }
        ));
        // The responder must keep answering while the waiter is blocked.
        for _ in 0..3 {
            answered();
        }
        drop(held);
        waiter.join().unwrap().unwrap();
    }

    /// Report the wait and its holder until the lock is acquired, updating when the holder
    /// changes. Releasing a nested lock restores the outer activity; a lock that reported
    /// nothing leaves it unchanged.
    #[test]
    fn a_wait_is_said_until_the_lock_is_taken() {
        use crate::node::jobs::journal::{ACTIVITY, read_activity};
        // Isolate the listener so a sibling fork cannot keep its address bound and
        // unanswered when the waiter tries to claim it.
        const CHILD: &str = "VK_TEST_PULL_WAIT_SAID";
        let Some(root) = crate::dev::testutil::child_marker(CHILD).map(PathBuf::from) else {
            let root =
                std::env::temp_dir().join(format!("virtkit-test-wait-said-{}", std::process::id()));
            crate::dev::testutil::in_child(
                "image::tests::a_wait_is_said_until_the_lock_is_taken",
                CHILD,
                &root,
            );
            return;
        };
        let ms = std::time::Duration::from_millis;
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let (heard, said) = std::sync::mpsc::channel();
        let sink = crate::activity::Sink::heard_at(Some(root.join(ACTIVITY)), heard);
        let acquire = |name: &str, verb: &str| {
            acquire_pull_lock_with(
                &root.join(name),
                verb,
                name,
                "sha256:x",
                ms(1),
                None,
                sink.clone(),
            )
        };
        // A holder whose answer the test changes.
        let answer = Arc::new(std::sync::Mutex::new("job 1".to_string()));
        let stop = Arc::new(AtomicBool::new(false));
        let addr = pull_lock_addr(&root.join("img")).unwrap();
        let holder = {
            let lock = UnixListener::bind_addr(&addr).unwrap();
            let (answer, stop) = (answer.clone(), stop.clone());
            std::thread::spawn(move || {
                loop {
                    let (mut s, _) = lock.accept().expect("the fake holder cannot accept");
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let _ = s.write_all(answer.lock().unwrap().as_bytes());
                }
            })
        };
        /// Stop the holder even on panic so the scoped waiter can finish. Set the flag
        /// before connecting to wake `accept`. A connection failure after shutdown is harmless.
        struct Stop(Arc<AtomicBool>, std::os::unix::net::SocketAddr);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
                let _ = std::os::unix::net::UnixStream::connect_addr(&self.1);
            }
        }
        let waiter = std::thread::scope(|scope| {
            let stopping = Stop(stop, addr);
            let waiter = scope.spawn(|| acquire("img", "build"));
            let waiting = |holder: Option<&str>| Activity::Waiting {
                image: "img".into(),
                building: true,
                holder: holder.map(str::to_string),
            };
            let until = |want: Activity| {
                while said
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .unwrap_or_else(|e| panic!("{want:?} is never said: {e}"))
                    != want
                {}
                assert_eq!(read_activity(&root), Some(want));
            };
            until(waiting(Some("job 1")));
            *answer.lock().unwrap() = "job 2".into();
            until(waiting(Some("job 2")));
            // A holder that answers without saying who it is.
            answer.lock().unwrap().clear();
            until(waiting(None));
            drop(stopping);
            holder.join().unwrap();
            waiter.join().unwrap()
        });
        let mut lock = waiter.unwrap();
        assert_eq!(read_activity(&root), None);
        // Said under the lock, and under another taken within it, as a build restoring its
        // cache pulls it.
        let building = Activity::Building {
            image: "img".into(),
        };
        lock.report(building.clone());
        let mut inner = acquire("cache", "pull").unwrap();
        inner.report(Activity::Pulling {
            image: "cache".into(),
        });
        assert!(matches!(
            read_activity(&root),
            Some(Activity::Pulling { .. })
        ));
        drop(inner);
        assert_eq!(read_activity(&root), Some(building.clone()));
        drop(acquire("quiet", "pull").unwrap());
        assert_eq!(read_activity(&root), Some(building));
        drop(lock);
        assert_eq!(read_activity(&root), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    // Report at most once per interval, and never when the interval is unset.
    #[test]
    fn a_wait_beats_at_its_cadence() {
        let secs = std::time::Duration::from_secs;
        let mut beat = WaitBeat {
            every: Some(secs(10)),
            last: secs(0),
        };
        let due: Vec<_> = [5, 10, 15, 19, 20, 31].map(|s| beat.due(secs(s))).into();
        assert_eq!(due, [false, true, false, false, true, true]);
        let mut quiet = WaitBeat {
            every: None,
            last: secs(0),
        };
        assert!(!quiet.due(secs(3600)));
    }

    #[test]
    fn pull_lock_answers_holder_identity_then_releases() {
        // In a process of its own, for the reason `pull_lock_excludes_and_releases` gives.
        const CHILD: &str = "VK_TEST_PULL_HOLDER_DIR";
        let Some(dir) = crate::dev::testutil::child_marker(CHILD).map(PathBuf::from) else {
            let dir =
                std::env::temp_dir().join(format!("virtkit-test-holder-{}", std::process::id()));
            crate::dev::testutil::in_child(
                "image::tests::pull_lock_answers_holder_identity_then_releases",
                CHILD,
                &dir,
            );
            return;
        };
        let addr = pull_lock_addr(&dir).unwrap();
        let lock = acquire_pull_lock(&dir, "build", "myimg", "sha256:x").unwrap();
        // a waiter reads the holder's identity over the lock socket (pid fallback, no CI env)
        let holder = hostlock::query_holder(&addr)
            .unwrap()
            .expect("the holder should answer");
        assert!(holder.who.is_some_and(|w| !w.trim().is_empty()));
        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        assert_eq!(
            holder.uid,
            Some(unsafe { libc::geteuid() }),
            "the kernel names the binder"
        );
        // released on drop: the addr binds again
        drop(lock);
        UnixListener::bind_addr(&addr).expect("the released lock addr binds again");
    }

    /// `len` bytes no filesystem compresses below `len`, for a test that counts space freed.
    fn noise(len: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// Date `dir` an hour back, past any grace.
    fn age(dir: &Path) {
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::open(dir)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(then))
            .unwrap();
    }

    // Dead is neither lock held and nothing changed within the grace: a dir held by either
    // lock, or one just made, is a live build's.
    #[test]
    fn sweep_orphaned_build_tmp_reclaims_only_dead_staging_dirs() {
        // Isolate the immediate post-release sweep from forks that could inherit the socket.
        // The variable selects the child branch. The child creates its own sweep root.
        const CHILD: &str = "VK_TEST_SWEEP_TMP_ROOT";
        if crate::dev::testutil::child_marker(CHILD).is_none() {
            let t = crate::dev::testutil::scratch("sweep-tmp-parent");
            crate::dev::testutil::in_child(
                "image::tests::sweep_orphaned_build_tmp_reclaims_only_dead_staging_dirs",
                CHILD,
                &t.0,
            );
            return;
        }
        let root =
            std::env::temp_dir().join(format!("virtkit-test-sweep-tmp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dead = root.join("dead.tmp");
        std::fs::create_dir_all(dead.join(".build-1-0-x")).unwrap();
        std::fs::write(dead.join(".build-1-0-x/stage.ext4"), noise(64 * 1024)).unwrap();
        age(&dead.join(".build-1-0-x"));
        age(&dead);
        // A build in flight holds the pull lock of the dir it promotes to...
        let pulling = root.join("pulling.tmp");
        std::fs::create_dir_all(&pulling).unwrap();
        age(&pulling);
        let pull = acquire_pull_lock(&root.join("pulling"), "build", "myimg", "sha256:x").unwrap();
        // ...and its claim on the staging dir, which holds without the pull lock's socket.
        let claimed = root.join("claimed.tmp");
        let claim = TmpGuard::create(&claimed).unwrap();
        age(&claimed);
        let fresh = root.join("fresh.tmp");
        std::fs::create_dir_all(&fresh).unwrap();
        // A build writing its image changes the file, not the dir.
        let writing = root.join("writing.tmp");
        std::fs::create_dir_all(&writing).unwrap();
        std::fs::write(writing.join("runner.ext4"), b"x").unwrap();
        age(&writing);

        let swept = sweep_dead_tmp(&root, DEAD_TMP_GRACE, false);
        assert!(!dead.exists(), "a dead staging dir must be reclaimed");
        assert_eq!(swept.dirs, 1);
        assert!(swept.bytes >= 64 * 1024, "{}", swept.bytes);
        assert!(swept.foreign.is_empty() && swept.left.is_empty());
        assert!(
            pulling.exists(),
            "a dir under a held pull lock must be spared"
        );
        assert!(claimed.exists(), "a claimed dir must be spared");
        assert!(
            fresh.exists(),
            "a dir changed within the grace must be spared"
        );
        assert!(
            writing.exists(),
            "a dir whose file changed within the grace must be spared"
        );

        drop((pull, claim));
        age(&pulling);
        sweep_dead_tmp(&root, DEAD_TMP_GRACE, false);
        assert!(!pulling.exists(), "released, the dir is dead");
        assert!(!claimed.exists(), "a dropped guard removes its own dir");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A dry run spares a dir whose pull lock is bound but not listening, as a real sweep's
    /// bind would: the connection it asks with is refused all the same.
    #[test]
    fn a_dry_run_spares_a_dir_whose_pull_lock_is_bound_without_listening() {
        use std::os::fd::{FromRawFd, OwnedFd};
        let root =
            std::env::temp_dir().join(format!("virtkit-test-sweep-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["bound.tmp", "free.tmp", "dgram.tmp"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let bind = |dir: &str, ty: libc::c_int| {
            let (sa, len) =
                hostlock::abstract_sockaddr(&pull_lock_addr(&root.join(dir)).unwrap()).unwrap();
            // SAFETY: plain socket calls on a fresh descriptor, owned by the result; `sa` and
            // `len` describe exactly the address filled in.
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0);
                assert!(fd >= 0);
                let bound = OwnedFd::from_raw_fd(fd);
                assert_eq!(
                    libc::bind(fd, (&raw const sa).cast(), len as libc::socklen_t),
                    0
                );
                bound
            }
        };
        let bound = bind("bound", libc::SOCK_STREAM);
        // A datagram socket on the lock's name does not hold it: a stream socket binds it.
        let dgram = bind("dgram", libc::SOCK_DGRAM);
        assert!(pull_lock_held(&root.join("bound")));
        assert!(!pull_lock_held(&root.join("free")));
        assert!(!pull_lock_held(&root.join("dgram")));
        let swept = sweep_dead_tmp(&root, std::time::Duration::ZERO, true);
        assert_eq!(swept.dirs, 2, "only the free and datagram dirs count");
        for dir in ["bound.tmp", "free.tmp", "dgram.tmp"] {
            assert!(root.join(dir).exists(), "{dir}");
        }
        // Last: a child another test forks may keep this lock past its drop.
        let _taken = try_acquire_pull_lock(&root.join("dgram")).expect("a datagram name is free");
        drop((bound, dgram));
        let _ = std::fs::remove_dir_all(&root);
    }

    // A symlink is never followed: not one wearing a staging dir's name, not one on the way
    // to a staging dir, not one inside a staging dir being removed.
    #[test]
    fn sweep_orphaned_build_tmp_follows_no_symlink() {
        let base =
            std::env::temp_dir().join(format!("virtkit-test-sweep-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(outside.join("nested.tmp")).unwrap();
        std::fs::write(outside.join("nested.tmp/keep"), b"x").unwrap();
        std::fs::write(outside.join("keep"), b"x").unwrap();
        age(&outside.join("nested.tmp"));
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("named.tmp")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("img")).unwrap();
        let dead = root.join("dead.tmp");
        std::fs::create_dir_all(&dead).unwrap();
        std::os::unix::fs::symlink(&outside, dead.join("out")).unwrap();
        age(&dead);

        let swept = sweep_dead_tmp(&root, std::time::Duration::ZERO, false);
        assert_eq!(swept.dirs, 1);
        assert!(
            !dead.exists(),
            "the real staging dir goes, its link with it"
        );
        assert!(root.join("named.tmp").is_symlink());
        assert!(root.join("img").is_symlink());
        assert!(outside.join("keep").is_file());
        assert!(outside.join("nested.tmp/keep").is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    // The docker tier nests a `.tmp` one level deeper than the build tier
    // (`<name>/<digest>.tmp` vs. a fingerprint dir directly under `root`) — the sweep must
    // walk down to find it, and must not descend into an already-promoted base looking for
    // more (there is nothing to find there, and it would just be wasted work).
    #[test]
    fn sweep_orphaned_build_tmp_walks_nested_name_dirs_like_the_docker_tier() {
        let root =
            std::env::temp_dir().join(format!("virtkit-test-sweep-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let orphan = root.join("myimg").join("abc123.tmp");
        let promoted = root.join("otherimg").join("def456");
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::create_dir_all(&promoted).unwrap();
        std::fs::write(promoted.join("runner.ext4"), b"").unwrap();
        sweep_dead_tmp(&root, std::time::Duration::ZERO, false);
        assert!(
            !orphan.exists(),
            "a nested, unlocked .tmp orphan must be reclaimed"
        );
        assert!(
            promoted.join("runner.ext4").is_file(),
            "an already-promoted base must be left untouched"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tmp_guard_removes_on_drop_unless_kept() {
        let dir =
            std::env::temp_dir().join(format!("virtkit-test-tmpguard-{}", std::process::id()));
        let removed = dir.join("removed");
        std::fs::create_dir_all(removed.join("stale")).unwrap();
        let guard = TmpGuard::create(&removed).unwrap();
        assert!(
            !removed.join("stale").exists(),
            "a guard starts from an empty dir"
        );
        drop(guard);
        assert!(
            !removed.exists(),
            "an un-kept guard must remove its path on drop"
        );

        let kept = dir.join("kept");
        drop(TmpGuard::create(&kept).unwrap().keep());
        assert!(kept.exists(), "a kept guard must leave its path alone");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Whether another open of `dir` can take the claim.
    fn claimable(dir: &Path) -> bool {
        flock_nb(&vk_fs::LockFile::new(std::fs::File::open(dir).unwrap())).is_ok()
    }

    // The claim `keep` hands over still holds the dir once it is renamed to its final name, and
    // only dropping it releases the dir.
    #[test]
    fn tmp_guard_claim_outlives_keep_and_the_rename() {
        let dir = std::env::temp_dir().join(format!(
            "virtkit-test-tmpguard-claim-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let tmp = dir.join("img.tmp");
        let promoted = dir.join("img");
        let claim = TmpGuard::create(&tmp).unwrap().keep();
        assert!(claim.is_some());
        assert!(!claimable(&tmp), "a kept dir stays claimed");
        std::fs::rename(&tmp, &promoted).unwrap();
        assert!(!claimable(&promoted), "the claim holds through the rename");
        drop(claim);
        assert!(claimable(&promoted), "dropping the claim releases the dir");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A filesystem that cannot take the claim (NFS, no `flock`) builds unclaimed, under the pull
    // lock alone; a claim another holds is the one refusal, and that dir is left to its holder.
    #[test]
    fn tmp_guard_builds_unclaimed_where_flock_fails() {
        let dir = std::env::temp_dir().join(format!(
            "virtkit-test-tmpguard-noflock-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let tmp = dir.join("img.tmp");
        for errno in [libc::EBADF, libc::ENOLCK, libc::EOPNOTSUPP, libc::EINVAL] {
            let guard =
                TmpGuard::create_locking(&tmp, |_| Err(std::io::Error::from_raw_os_error(errno)))
                    .unwrap();
            assert!(tmp.is_dir());
            drop(guard);
            assert!(!tmp.exists(), "an unclaimed guard still removes its dir");
        }
        let held = TmpGuard::create_locking(&tmp, |_| {
            Err(std::io::Error::from_raw_os_error(libc::EWOULDBLOCK))
        });
        assert!(held.is_err());
        assert!(tmp.is_dir(), "a dir claimed by another is left to it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_refs() {
        // a bare name defaults to :latest
        let (n, r) = parse_ref("myimage").unwrap();
        assert_eq!(n, "myimage");
        assert!(matches!(r, Reference::Tag(t) if t == "latest"));

        let (n, r) = parse_ref("runner:20260610-abc").unwrap();
        assert_eq!(n, "runner");
        assert!(matches!(r, Reference::Tag(t) if t == "20260610-abc"));

        let digest = format!("sha256:{}", "a".repeat(64));
        let (n, r) = parse_ref(&format!("myimage@{digest}")).unwrap();
        assert_eq!(n, "myimage");
        assert!(matches!(r, Reference::Digest(d) if d == digest));

        for bad in [
            "",
            "../etc",
            "a/b",
            "name:",
            "name:tag:tag",
            "name@sha256:zz",
            "name@md5:abcd",
            ".hidden",
        ] {
            assert!(parse_ref(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    /// Run `gc_idle`, which must evict `base`.
    fn evicted(root: &Path, base: &Path) {
        gc_idle(root, std::time::Duration::ZERO);
        assert!(!base.exists(), "base {} was not reclaimed", base.display());
    }

    #[test]
    fn gc_idle_reference_counts_and_respects_the_timeout() {
        use std::time::Duration;
        let tmp = std::env::temp_dir().join(format!("vk-gcidle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("registry");
        // A materialized base under the managed cache: <root>/<name>/<digest>/runner.ext4.
        let base = |name: &str| -> PathBuf {
            let d = root.join(name).join("deadbeef");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("runner.ext4"), b"x").unwrap();
            d
        };
        let rootfs = |d: &Path| d.join("runner.ext4");

        // Idle (marked used, no live overlay): a zero timeout evicts it.
        let idle = base("idle");
        mark_used(&idle);
        evicted(&root, &idle);

        // Referenced: a held use-lock survives a zero timeout, and is reclaimed once dropped.
        let live = base("live");
        mark_used(&live);
        let guard = acquire_use_lock_for(&tmp, &rootfs(&live)).unwrap();
        assert!(
            guard.is_some(),
            "a base under the managed cache is reference-counted"
        );
        gc_idle(&root, Duration::ZERO);
        assert!(
            live.exists(),
            "a base under a live overlay must never be evicted"
        );
        drop(guard);
        evicted(&root, &live);

        // No `.used` marker (mid-materialize): never evicted, even at a zero timeout.
        let fresh = base("fresh");
        gc_idle(&root, Duration::ZERO);
        assert!(
            fresh.exists(),
            "a base still being set up (no .used) must be left alone"
        );

        // A non-zero timeout keeps a just-used base (its `.used` is recent).
        mark_used(&fresh);
        gc_idle(&root, Duration::from_secs(3600));
        assert!(
            fresh.exists(),
            "a recently used base must survive within the idle window"
        );

        // A base outside the managed cache is not reference-counted.
        let unmanaged = tmp.join("elsewhere");
        std::fs::create_dir_all(&unmanaged).unwrap();
        assert!(
            acquire_use_lock_for(&tmp, &unmanaged.join("runner.ext4"))
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // What the node's periodic sweep runs: idle bases of both tiers go, counted; a base in
    // use, one used within the window, and one reached only through a symlink stay.
    #[test]
    fn evict_idle_images_counts_what_went_and_follows_no_symlink() {
        use std::time::{Duration, SystemTime};
        let tmp = std::env::temp_dir().join(format!("vk-evict-idle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let state = tmp.join("state");
        let base = |dir: PathBuf, idle_for: Duration| -> PathBuf {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("runner.ext4"), noise(64 * 1024)).unwrap();
            mark_used(&dir);
            std::fs::File::open(dir.join(".used"))
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - idle_for))
                .unwrap();
            dir
        };
        let hour = Duration::from_secs(3600);
        let idle_build = base(state.join("build").join("fp"), hour);
        let idle_docker = base(state.join("docker").join("img").join("d1"), hour);
        let recent = base(state.join("docker").join("img").join("d2"), Duration::ZERO);
        let busy = base(state.join("build").join("busy"), hour);
        let guard = acquire_use_lock_for(&state, &busy.join("runner.ext4"))
            .unwrap()
            .unwrap();
        // Re-dated by the acquisition: age it again, so only the reference keeps it.
        std::fs::File::open(busy.join(".used"))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - hour))
            .unwrap();
        let outside = base(tmp.join("outside").join("fp"), hour);
        std::os::unix::fs::symlink(tmp.join("outside"), state.join("build").join("link")).unwrap();

        let build = gc_idle(&state.join("build"), Duration::from_secs(1800));
        assert!(!idle_build.exists());
        assert_eq!(build.bases, 1);
        assert!(build.bytes >= 64 * 1024, "{}", build.bytes);
        evict_idle_images(&state, Duration::from_secs(1800));
        assert!(!idle_build.exists());
        assert!(!idle_docker.exists());
        assert!(recent.exists(), "a base used within the window must stay");
        assert!(busy.exists(), "a base in use must stay");
        assert!(outside.exists(), "a base behind a symlink must stay");
        drop(guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // Under pressure: unreferenced chunks first, then unused bases oldest first, whatever the
    // idle window past a short grace, stopping as soon as the target is met, and nothing at all
    // for a target out of reach. A base in use stays, as does one just stamped used (resolved,
    // not yet referenced), one never dated, and one the asking job last booted; nothing on
    // another filesystem than the job dirs' is touched.
    #[test]
    fn evict_for_room_takes_the_least_recently_used_until_the_target_is_met() {
        use std::time::{Duration, SystemTime};
        let tmp = std::env::temp_dir().join(format!("vk-evict-room-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let state = tmp.join("state");
        let jobs = state.join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        let idle = Duration::from_secs(4 * 3600);
        let age = |dir: &Path, ago: Duration| {
            std::fs::File::open(dir.join(".used"))
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - ago))
                .unwrap();
        };
        let base = |dir: PathBuf, mins: u64| -> PathBuf {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("runner.ext4"), noise(64 * 1024)).unwrap();
            mark_used(&dir);
            age(&dir, Duration::from_secs(mins * 60));
            dir
        };
        let busy = base(state.join("build").join("busy"), 0);
        let guard = acquire_use_lock_for(&state, &busy.join("runner.ext4"))
            .unwrap()
            .unwrap();
        age(&busy, Duration::from_secs(4 * 3600));
        let oldest = base(state.join("docker").join("img").join("d1"), 180);
        let older = base(state.join("build").join("fp"), 120);
        let newest = base(state.join("registry").join("img").join("r1"), 60);
        let fresh = base(state.join("docker").join("img").join("d2"), 0);
        let undated = state.join("build").join("undated");
        std::fs::create_dir_all(&undated).unwrap();
        std::fs::write(undated.join("runner.ext4"), noise(64 * 1024)).unwrap();
        std::fs::write(newest.join("chunks.list"), "live\n").unwrap();
        let chunks = state.join("registry").join("chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        std::fs::write(chunks.join("live"), noise(64 * 1024)).unwrap();
        std::fs::write(chunks.join("dead"), noise(64 * 1024)).unwrap();
        let all = [&busy, &oldest, &older, &newest, &fresh, &undated];
        let stays = || busy.exists() && fresh.exists() && undated.join("runner.ext4").exists();

        // Another filesystem than the one asked about is left alone.
        let elsewhere = Path::new("/proc");
        assert_ne!(crate::usage::fs_id(elsewhere), crate::usage::fs_id(&jobs));
        assert_eq!(
            evict_for_room(&state, idle, elsewhere, 1, &[], EVICT_WAIT),
            ForRoom {
                evicted: Evicted::default(),
                reach: Some(0)
            }
        );
        assert!(all.iter().all(|b| b.exists()) && chunks.join("dead").exists());

        // Behind another eviction past its wait it does not look, and says so.
        let lock = state.join(".evict.lock");
        let ahead = crate::cachelock::lock_exclusive_within(&lock, Duration::ZERO)
            .unwrap()
            .unwrap();
        let held_up = evict_for_room(&state, idle, &jobs, 1, &[], Duration::from_millis(100));
        assert_eq!(held_up, ForRoom::default());
        drop(ahead);
        assert!(all.iter().all(|b| b.exists()) && chunks.join("dead").exists());

        // A target nothing could meet takes nothing, not even the dead chunk.
        let none = evict_for_room(&state, idle, &jobs, u64::MAX, &[], EVICT_WAIT);
        assert_eq!(none.evicted, Evicted::default());
        assert!(none.reach.is_some_and(|r| r >= 4 * 64 * 1024), "{none:?}");
        assert!(all.iter().all(|b| b.exists()) && chunks.join("dead").exists());

        // The dead chunk alone meets a small target.
        let once = evict_for_room(&state, idle, &jobs, 1, &[], EVICT_WAIT).evicted;
        assert_eq!((once.bases, once.chunks), (0, 1), "{once:?}");
        assert!(once.bytes >= 64 * 1024, "{once:?}");
        assert!(!chunks.join("dead").exists() && all.iter().all(|b| b.exists()));

        // Then the least recently used base nobody holds, and no more than the target needs —
        // passing over the one the asking job last booted, as its note gives it, reached here
        // through a symlink.
        let link = tmp.join("state-link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let notes = tmp.join("job-images");
        let key = Path::new("42-proj/build");
        remember_bases(&notes, key, &[link.join("docker").join("img").join("d1")]);
        let keep = remembered_bases(&notes, key);
        let once = evict_for_room(&state, idle, &jobs, 1, &keep, EVICT_WAIT).evicted;
        assert!(!older.exists());
        assert_eq!(once.bases, 1, "{once:?}");
        assert!(oldest.exists(), "the asking job's own base must stay");
        assert!(stays());

        // What is left to take: the two dated, unused bases and the chunk only one of them
        // names. A target a byte past that takes nothing — the fresh and undated bases do not
        // count toward it — and one that matches it takes them all.
        let blocks = |p: &Path| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(p).unwrap().blocks() * 512
        };
        let reach =
            removable_bytes(&oldest) + removable_bytes(&newest) + blocks(&chunks.join("live"));
        assert_eq!(
            evict_for_room(&state, idle, &jobs, reach + 1, &[], EVICT_WAIT),
            ForRoom {
                evicted: Evicted::default(),
                reach: Some(reach)
            }
        );
        assert!(oldest.exists() && newest.exists() && stays());
        let rest = evict_for_room(&state, idle, &jobs, reach, &[], EVICT_WAIT).evicted;
        assert!(!oldest.exists() && !newest.exists());
        assert_eq!((rest.bases, rest.chunks), (2, 1), "{rest:?}");
        assert!(rest.bytes >= reach, "{rest:?}");
        assert!(!chunks.join("live").exists());
        assert!(stays(), "a base in use, just stamped or undated must stay");
        drop(guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // A lock file another user left 0600 does not stop an eviction: it goes ahead unserialized.
    // Only observable unprivileged; as root the lock simply opens.
    #[test]
    fn evict_for_room_goes_ahead_past_a_lock_it_may_not_open() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, SystemTime};
        let tmp = std::env::temp_dir().join(format!("vk-evict-denied-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let base = tmp.join("build").join("old");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("runner.ext4"), noise(64 * 1024)).unwrap();
        mark_used(&base);
        std::fs::File::open(base.join(".used"))
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(SystemTime::now() - Duration::from_secs(3600)),
            )
            .unwrap();
        let lock = tmp.join(".evict.lock");
        std::fs::write(&lock, "").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
        let idle = Duration::from_secs(4 * 3600);
        assert_eq!(
            evict_for_room(&tmp, idle, &tmp, 1, &[], EVICT_WAIT)
                .evicted
                .bases,
            1
        );
        assert!(!base.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // A base counts for what removing it would free: a file with another link keeps its space.
    #[test]
    fn removable_bytes_leaves_out_what_another_link_keeps() {
        let tmp = std::env::temp_dir().join(format!("vk-removable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let base = tmp.join("base");
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("runner.ext4"), noise(64 * 1024)).unwrap();
        std::fs::write(base.join("sub").join("own"), noise(64 * 1024)).unwrap();
        let alone = removable_bytes(&base);
        assert!(alone >= 2 * 64 * 1024, "{alone}");
        std::fs::hard_link(base.join("runner.ext4"), tmp.join("elsewhere")).unwrap();
        let linked = removable_bytes(&base);
        assert!(linked + 64 * 1024 <= alone, "{linked} of {alone}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // What a job booted is read back by its next admission, replaced whole on each run; a key
    // that would leave the store, or a line that is not an absolute path, reads as nothing.
    #[test]
    fn a_jobs_bases_are_remembered_for_its_next_admission() {
        let dir = std::env::temp_dir().join(format!("vk-job-images-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = Path::new("42-proj/build");
        assert!(remembered_bases(&dir, key).is_empty());
        let first = [PathBuf::from("/s/build/a"), PathBuf::from("/s/docker/x/d")];
        remember_bases(&dir, key, &first);
        assert_eq!(remembered_bases(&dir, key), first);
        remember_bases(&dir, key, &first[..1]);
        assert_eq!(remembered_bases(&dir, key), first[..1]);
        std::fs::write(dir.join(key), "relative\n/s/build/b\n").unwrap();
        assert_eq!(remembered_bases(&dir, key), [PathBuf::from("/s/build/b")]);
        // Bytes, not text: a name that is not UTF-8 comes back as it went, and one with a
        // newline in it, which the note cannot hold, is left out.
        let odd = PathBuf::from(std::ffi::OsStr::from_bytes(b"/s/build/\xff"));
        remember_bases(&dir, key, &[odd.clone(), PathBuf::from("/s/a\nb")]);
        assert_eq!(remembered_bases(&dir, key), [odd]);
        remember_bases(&dir, Path::new("/abs"), &first);
        assert!(remembered_bases(&dir, Path::new("/abs")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The image goes first: a removal that stops part-way leaves a cache miss, not a base that
    // still looks whole. A dir this user cannot empty stops it, unless the test runs as root.
    #[test]
    fn remove_base_takes_the_image_before_the_rest() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("vk-remove-base-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let base = tmp.join("img").join("d1");
        std::fs::create_dir_all(base.join("a-locked")).unwrap();
        std::fs::write(base.join("a-locked/f"), b"x").unwrap();
        std::fs::write(base.join("runner.ext4"), noise(64 * 1024)).unwrap();
        let locked = base.join("a-locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = remove_base(&base);
        assert!(!base.join("runner.ext4").exists(), "{result:?}");
        if base.exists() {
            assert!(result.is_err());
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        } else {
            assert!(result.unwrap() >= 64 * 1024);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // A tier root shared with the build-cache store: bases are found beside the store's
    // files and directories, and neither a file nor a symlinked directory is taken for one.
    #[test]
    fn base_dirs_finds_bases_beside_store_files() {
        let tmp = std::env::temp_dir().join(format!("vk-base-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("registry");
        let base = root.join("img").join("d1");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("runner.ext4"), b"x").unwrap();
        let blobs = root.join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        for i in 0..8 {
            std::fs::write(blobs.join(format!("{i:064x}")), b"blob").unwrap();
        }
        std::fs::write(root.join("runner.ext4.not-a-dir"), b"x").unwrap();
        let outside = tmp.join("outside").join("d2");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("runner.ext4"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.join("outside"), root.join("link")).unwrap();

        assert_eq!(base_dirs(&root), vec![base]);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // A dry run judges a base as a real pass does and counts it the same, but leaves it; a base
    // in use is counted by neither. Dead staging dirs likewise.
    #[test]
    fn dry_runs_count_what_a_real_pass_removes() {
        use std::time::Duration;
        let tmp = std::env::temp_dir().join(format!("vk-gc-dry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let state = tmp.join("state");
        let root = state.join("build");
        let idle = root.join("idle");
        std::fs::create_dir_all(&idle).unwrap();
        std::fs::write(idle.join("runner.ext4"), noise(64 * 1024)).unwrap();
        mark_used(&idle);
        let busy = root.join("busy");
        std::fs::create_dir_all(&busy).unwrap();
        std::fs::write(busy.join("runner.ext4"), b"x").unwrap();
        let _guard = acquire_use_lock_for(&state, &busy.join("runner.ext4"))
            .unwrap()
            .unwrap();
        let dead = root.join("dead.tmp");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join("partial"), noise(32 * 1024)).unwrap();
        age(&dead);
        std::fs::File::open(dead.join("partial"))
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600)),
            )
            .unwrap();

        // A file linked from outside the base keeps its space: counted by neither pass.
        std::fs::write(tmp.join("outside"), noise(64 * 1024)).unwrap();
        std::fs::hard_link(tmp.join("outside"), idle.join("linked")).unwrap();

        let dry = collect_idle(&root, Duration::ZERO, true);
        assert_eq!(dry.bases, 1);
        assert!(
            dry.bytes >= 64 * 1024 && dry.bytes < 128 * 1024,
            "{}",
            dry.bytes
        );
        assert_eq!(dry.would_evict, vec![idle.clone()]);
        assert!(
            idle.join("runner.ext4").is_file(),
            "a dry run removes nothing"
        );
        let dry_tmp = collect_orphaned_staging(&root, true);
        assert_eq!(dry_tmp.dirs, 1);
        assert!(dry_tmp.bytes >= 32 * 1024, "{}", dry_tmp.bytes);
        assert!(dead.is_dir(), "a dry run removes nothing");

        let real = collect_idle(&root, Duration::ZERO, false);
        assert!(!idle.exists());
        assert_eq!(real.bases, dry.bases);
        assert!(
            real.bytes.abs_diff(dry.bytes) <= 8192,
            "{} {}",
            real.bytes,
            dry.bytes
        );
        assert!(busy.is_dir(), "a base in use stays");
        let real_tmp = collect_orphaned_staging(&root, false);
        assert_eq!(real_tmp.dirs, dry_tmp.dirs);
        assert!(!dead.exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gc_idle_tolerates_a_used_marker_in_the_future() {
        // The filesystem stamps `.used` from a coarse clock while `gc_idle` reads a precise
        // one, so under load the marker can read slightly ahead of `now`. Such a base must
        // still be reclaimable at a zero idle window (treated as elapsed 0), and still kept
        // within a non-zero window — never wrongly pinned forever by the skew.
        use std::time::{Duration, SystemTime};
        let tmp = std::env::temp_dir().join(format!("vk-gcidle-future-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("registry");
        let base = |name: &str| -> PathBuf {
            let d = root.join(name).join("deadbeef");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("runner.ext4"), b"x").unwrap();
            // Stamp `.used` a minute into the future to force the skew deterministically.
            let f = std::fs::File::create(d.join(".used")).unwrap();
            f.set_times(
                std::fs::FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(60)),
            )
            .unwrap();
            d
        };

        let keep = base("keep");
        gc_idle(&root, Duration::from_secs(3600));
        assert!(
            keep.exists(),
            "a future-skewed base must survive a non-zero idle window"
        );

        let evict = base("evict");
        evicted(&root, &evict);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A dry run counts the chunks only the bases it would evict reference, as a real pass
    /// that evicts them and then sweeps does.
    #[test]
    fn a_dry_run_counts_the_chunks_of_the_bases_it_would_evict() {
        use std::time::Duration;
        let tmp = std::env::temp_dir().join(format!("vk-dry-chunks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("registry");
        let base = |name: &str, chunks: &str| {
            let d = root.join(name).join("deadbeef");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("runner.ext4"), b"x").unwrap();
            std::fs::write(d.join("chunks.list"), chunks).unwrap();
            d
        };
        let idle = base("idle", "aaa\nbbb\n");
        mark_used(&idle);
        let busy = base("busy", "bbb\n");
        let _guard = acquire_use_lock_for(&tmp, &busy.join("runner.ext4"))
            .unwrap()
            .unwrap();
        let chunks = root.join("chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        for c in ["aaa", "bbb"] {
            std::fs::write(chunks.join(c), noise(8192)).unwrap();
        }

        let dry = collect_idle(&root, Duration::ZERO, true);
        assert_eq!(dry.bases, 1);
        let (dry_chunks, _) = collect_chunks(&root, true, &dry.would_evict);
        assert_eq!(dry_chunks, 1, "only the chunk no other base references");
        assert!(chunks.join("aaa").exists());

        collect_idle(&root, Duration::ZERO, false);
        assert!(!idle.exists());
        let (real_chunks, _) = collect_chunks(&root, false, &[]);
        assert_eq!(real_chunks, dry_chunks);
        assert!(!chunks.join("aaa").exists() && chunks.join("bbb").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sweep_chunks_drops_only_unreferenced_blobs() {
        let root = std::env::temp_dir().join(format!("vk-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // A cached bundle referencing chunk "aaa" (and nothing else).
        let bundle = root.join("img").join("deadbeef");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("runner.ext4"), b"x").unwrap();
        std::fs::write(bundle.join("chunks.list"), "aaa\n").unwrap();
        // The chunk store: a referenced blob, an orphan, and five staged temps. The live one
        // is named by `staging_chunk_name` itself, so keeping it also proves the name's
        // producer and its parser still agree; one is a dead writer's, to be reclaimed; the
        // last three cover every way the parser can fail to name a writer at all, each of
        // which must be read as live.
        // A guaranteed-dead pid: spawn a child and reap it.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let live_tmp = staging_chunk_name("ccc");
        let dead_tmp = format!("ddd.{dead}-0.tmp");
        let no_seq_tmp = format!("fff.{dead}.tmp");
        let chunks = root.join("chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        for f in [
            "aaa",
            "bbb",
            &live_tmp,
            &dead_tmp,
            "eee.tmp",
            &no_seq_tmp,
            "ggg.notapid-0.tmp",
        ] {
            std::fs::write(chunks.join(f), b"z").unwrap();
        }

        sweep_chunks(&root);
        assert!(chunks.join("aaa").exists(), "a referenced chunk is kept");
        assert!(!chunks.join("bbb").exists(), "an orphan chunk is dropped");
        assert!(
            chunks.join(&live_tmp).exists(),
            "an in-flight chunk is left alone"
        );
        assert!(
            !chunks.join(&dead_tmp).exists(),
            "a chunk staged by a dead pull is reclaimed"
        );
        assert!(
            chunks.join("eee.tmp").exists(),
            "a temp with no owner in its name is left alone"
        );
        assert!(
            chunks.join(&no_seq_tmp).exists(),
            "a temp naming no write counter is left alone"
        );
        assert!(
            chunks.join("ggg.notapid-0.tmp").exists(),
            "a temp whose owner is not a pid is left alone"
        );

        // Once the only bundle referencing "aaa" is evicted, "aaa" becomes reclaimable.
        std::fs::remove_dir_all(&bundle).unwrap();
        sweep_chunks(&root);
        assert!(
            !chunks.join("aaa").exists(),
            "a chunk no remaining bundle references is dropped"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The same live set and staging rules cover both codec directories and the cache root.
    /// Dry and real sweeps count a linked chunk's blocks once, at its last link.
    #[test]
    fn sweep_chunks_covers_every_chunk_location() {
        use std::os::unix::fs::MetadataExt;
        let root = std::env::temp_dir().join(format!("vk-sweep-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let bundle = root.join("img").join("deadbeef");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("runner.ext4"), b"x").unwrap();
        std::fs::write(bundle.join("chunks.list"), "aaa\nbbb\nccc\n").unwrap();
        let chunks = root.join("chunks");
        let [zstd, raw, _] = crate::registry::chunk_cache_dirs(&chunks);
        for dir in [&zstd, &raw] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let live_tmp = staging_chunk_name("ddd");
        let dead_tmp = format!("eee.{dead}-0.tmp");
        for (dir, name) in [
            (&zstd, "aaa"),
            (&raw, "bbb"),
            (&chunks, "ccc"),
            (&zstd, "fff"),
            (&raw, "ggg"),
            (&chunks, "hhh"),
            (&zstd, live_tmp.as_str()),
            (&raw, dead_tmp.as_str()),
        ] {
            std::fs::write(dir.join(name), noise(8192)).unwrap();
        }
        std::fs::hard_link(chunks.join("ccc"), raw.join("ccc")).unwrap();
        std::fs::hard_link(chunks.join("hhh"), zstd.join("hhh")).unwrap();

        let (dry, dry_bytes) = collect_chunks(&root, true, &[]);
        let (real, real_bytes) = collect_chunks(&root, false, &[]);
        // fff, ggg, both links of hhh, and the dead pull's staging.
        assert_eq!((dry, real), (5, 5));
        assert_eq!(dry_bytes, real_bytes);
        let each = std::fs::metadata(zstd.join("aaa")).unwrap().blocks() * 512;
        assert_eq!(
            real_bytes,
            4 * each,
            "a linked chunk's space is counted once"
        );
        for kept in [
            zstd.join("aaa"),
            raw.join("bbb"),
            chunks.join("ccc"),
            raw.join("ccc"),
            zstd.join(&live_tmp),
        ] {
            assert!(kept.exists(), "{}", kept.display());
        }
        for gone in [
            zstd.join("fff"),
            raw.join("ggg"),
            chunks.join("hhh"),
            zstd.join("hhh"),
            raw.join(&dead_tmp),
        ] {
            assert!(!gone.exists(), "{}", gone.display());
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sweep_chunks_keeps_chunks_of_an_in_flight_bundle() {
        // A pull stages a bundle in `<digest>.tmp/` and writes its `chunks.list` before
        // fetching any chunk, so a concurrent sweep must count that staging bundle as live
        // and not reclaim the chunks it is still reassembling.
        let root = std::env::temp_dir().join(format!("vk-sweep-inflight-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let staging = root.join("img").join("deadbeef.tmp");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("runner.ext4"), b"x").unwrap();
        std::fs::write(staging.join("chunks.list"), "aaa\n").unwrap();
        let chunks = root.join("chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        std::fs::write(chunks.join("aaa"), b"z").unwrap();

        sweep_chunks(&root);
        assert!(
            chunks.join("aaa").exists(),
            "a chunk referenced by an in-flight staging bundle is kept"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
