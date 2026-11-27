//! `vk gc`: reclaim unused, recreatable host caches. Summarize what was removed, what was
//! kept and why, and the change in free space on each filesystem.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::Config;
use crate::usage::fmt_bytes;

/// The least time a pass leaves a build-cache entry after its last use before its size cap
/// takes it, and an unreferenced store blob after it was written: a build may have pushed it
/// moments ago and be about to name it, which no lock covers.
const BUILD_CACHE_FLOOR: Duration = Duration::from_secs(86_400);
/// The least time `--all-unused` leaves a build-cache entry after its last use, and an
/// unreferenced blob after it was written.
const ALL_UNUSED_FLOOR: Duration = Duration::from_secs(3600);
/// The least time `--all-unused` leaves a stopped dev environment's boot images, or a
/// `vk run --state-dir` dir's root image, after it was last in use: one stopped moments ago
/// may be about to start again.
const DEV_IMAGE_FLOOR: Duration = Duration::from_secs(3600);
/// The longest a background pass waits for each lock on the build cache's store.
const AUTO_STORE_WAIT: Duration = Duration::from_secs(5);
/// The longest a manual pass waits for each lock on the build cache's store.
const STORE_WAIT: Duration = Duration::from_secs(60);

/// What a `vk gc` pass may take.
pub(crate) struct Request {
    /// Count what would go and remove nothing.
    pub(crate) dry_run: bool,
    /// Ignore the configured retention and idle windows; the floors above still hold.
    pub(crate) all_unused: bool,
    /// A background pass ([`crate::autogc`]): looks at no workspace, waits at most
    /// [`AUTO_STORE_WAIT`] for each store lock, and goes past the idle windows, on each
    /// filesystem of the image caches below `[gc] min_free`, while it is.
    pub(crate) auto: bool,
    /// How long a materialized base must sit unused.
    pub(crate) image_idle: Duration,
    /// How long a host checkout must sit unused.
    pub(crate) checkout_idle: Duration,
}

/// The image caches under `state_dir`.
const TIERS: [&str; 3] = ["registry", "docker", "build"];

/// The image tiers under `state_dir`, each of which may be a link to another filesystem.
fn tiers(state_dir: &Path) -> [PathBuf; 3] {
    TIERS.map(|t| state_dir.join(t))
}

/// Paths for checking `[gc] min_free` on each image-tier filesystem. Use `state_dir`
/// until a tier exists.
pub(crate) fn tier_filesystems(state_dir: &Path) -> Vec<PathBuf> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for tier in tiers(state_dir).into_iter().filter(|t| t.exists()) {
        let id = crate::usage::fs_id(&tier);
        if id.is_none() || !seen.contains(&id) {
            seen.push(id);
            out.push(tier);
        }
    }
    if out.is_empty() {
        out.push(state_dir.to_path_buf());
    }
    out
}

/// Run a pass over the image tiers under `state_dir` (the one `vk run` caches under) and the
/// executor's checkouts.
pub(crate) fn run(cfg: &Config, state_dir: &Path, req: &Request) -> Summary {
    let checkout_root = cfg.checkout_root();
    let store = cache_store(cfg);
    // Every filesystem the pass may free space on, its space read before anything goes.
    let tiers = tiers(state_dir);
    let mut roots = vec![state_dir, checkout_root.as_path()];
    roots.extend(tiers.iter().map(PathBuf::as_path));
    if let Ok(crate::build::CacheStore::Dir(dir)) = &store {
        roots.push(dir);
    }
    let shared = shared_store_dir();
    if let Ok(Some(dir)) = &shared {
        roots.push(dir);
    }
    let scratch = crate::run::default_scratch_base();
    if let Ok(base) = &scratch {
        roots.push(base);
    }
    let dev_base = crate::dev::plan::dev_state_base();
    if let Ok(base) = &dev_base {
        roots.push(base);
    }
    // A background pass reads no noted dir's filesystem up front: those it frees nothing on
    // cost it nothing, and it shows no space for the others.
    let noted = if req.auto {
        Vec::new()
    } else {
        crate::rundirs::noted_dirs()
    };
    roots.extend(noted.iter().map(PathBuf::as_path));
    let mut sum = Summary::new(req.dry_run, &roots);
    sum.lazy = req.auto;

    // Each tier's bytes on its own filesystem: one may be a link to another.
    let mut images = crate::image::Evicted::default();
    let mut freed = Vec::new();
    for tier in &tiers {
        let got = crate::image::collect_idle(tier, req.image_idle, req.dry_run);
        images.bases += got.bases;
        images.bytes = images.bytes.saturating_add(got.bytes);
        images.would_evict.extend(got.would_evict);
        freed.push((tier.as_path(), got.bytes));
    }
    sum.tier_row(
        "images",
        images.bases,
        &freed,
        state_dir,
        unused_for(req.image_idle),
    );
    let (chunks, chunk_bytes) =
        crate::image::collect_chunks(&tiers[0], req.dry_run, &images.would_evict);
    sum.row(
        "chunks",
        chunks,
        chunk_bytes,
        &tiers[0],
        "no cached image uses them".into(),
    );
    let mut staging = crate::image::Swept::default();
    let mut freed = Vec::new();
    for tier in &tiers[1..] {
        let got = crate::image::collect_orphaned_staging(tier, req.dry_run);
        staging.dirs += got.dirs;
        freed.push((tier.as_path(), got.bytes));
        staging.foreign.extend(got.foreign);
        staging.left.extend(got.left);
    }
    sum.tier_row(
        "leftovers",
        staging.dirs,
        &freed,
        state_dir,
        "staging of dead builds and pulls".into(),
    );
    for dir in &staging.foreign {
        sum.keep(format!("{}: another user's", dir.display()));
    }
    sum.kept.extend(staging.left);
    if let Ok(base) = &dev_base {
        let unfinished = crate::leftovers::collect(req.dry_run);
        sum.row(
            "unfinished builds",
            unfinished.dirs,
            unfinished.bytes,
            base,
            "left in state dirs by builds and tasks killed outright".into(),
        );
    }
    // Checkouts are the executor's alone, and the executor roots its state at
    // `Config::state_dir()` — never the dev default `vk run` caches under, which is what
    // `state_dir` may be here. Sweeping that instead would walk a tree nothing ever checks
    // out into and silently reclaim nothing.
    let trees = crate::checkout::collect_idle(&checkout_root, req.checkout_idle, req.dry_run);
    sum.row(
        "checkouts",
        trees.trees,
        trees.bytes,
        &checkout_root,
        unused_for(req.checkout_idle),
    );
    sum.kept.extend(trees.left);
    build_cache(cfg, &store, req, None, &mut sum);
    shared_cache(cfg, &shared, req, &mut sum);
    if let Ok(base) = &dev_base {
        dev_images(cfg, req, base, &mut sum);
    }
    run_images(cfg, req, &mut sum);
    let launches = crate::run::collect_dead_launch_dirs(req.dry_run);
    if let Ok(base) = &scratch {
        sum.row(
            "launch dirs",
            launches.dirs,
            launches.bytes,
            base,
            "left by runs killed by a signal".into(),
        );
    }
    sum.kept.extend(launches.left);
    if let Some((dir, releases, bytes)) = crate::toolchain::cache_usage()
        && releases > 0
    {
        sum.keep(format!(
            "toolchains: {releases} release(s), {} in {} — a project may pin any of them",
            fmt_bytes(bytes),
            dir.display()
        ));
    }
    if req.auto {
        pressure(cfg, state_dir, &store, req, &mut sum, &|path| {
            short_of(cfg, path)
        });
    }
    sum.finish();
    sum
}

const DAY: Duration = Duration::from_secs(86_400);

/// Reclaim extra space on image-tier filesystems below `[gc] min_free`, and only there,
/// cheapest to rebuild first, stopping once enough is free: images past the eviction grace,
/// least recently used build entries, then root images from run state directories unused for
/// a day. Disabled categories stay off. Dev images keep their idle window because rebuilding
/// them can rerun create hooks.
fn pressure(
    cfg: &Config,
    state_dir: &Path,
    store: &anyhow::Result<crate::build::CacheStore>,
    req: &Request,
    sum: &mut Summary,
    short: &dyn Fn(&Path) -> Option<u64>,
) {
    let filesystems = tier_filesystems(state_dir);
    let on_short = |path: &Path| {
        let id = crate::usage::fs_id(path);
        id.is_some()
            && filesystems
                .iter()
                .any(|f| crate::usage::fs_id(f) == id && short(f).is_some())
    };
    if !filesystems.iter().any(|f| short(f).is_some()) {
        return;
    }
    let grace = crate::image::EVICT_GRACE;
    let mut images = crate::image::Evicted::default();
    let mut freed = Vec::new();
    for tier in tiers(state_dir).iter().filter(|t| on_short(t)) {
        let got = crate::image::collect_idle(tier, grace, req.dry_run);
        images.bases += got.bases;
        freed.push((tier.clone(), got.bytes));
    }
    if !freed.is_empty() {
        let parts: Vec<(&Path, u64)> = freed.iter().map(|(p, b)| (p.as_path(), *b)).collect();
        sum.row_on(
            "images",
            images.bases,
            &parts,
            format!("short of space: {}", unused_for(grace)),
        );
    }
    if let Ok(crate::build::CacheStore::Dir(dir)) = store
        && on_short(dir)
        && let Some(need) = short(dir)
        && (cfg.gc.build_cache_retention().is_some() || cfg.gc.build_cache_max(u64::MAX).is_some())
    {
        build_cache(cfg, store, req, Some(need), sum);
    }
    if cfg.gc.run_image_idle().is_some() {
        // The identity tier_filesystems tells filesystems apart by: btrfs subvolumes drawing
        // on one pool are one.
        let mut ids = Vec::new();
        for f in &filesystems {
            if short(f).is_some()
                && let Some(id) = crate::usage::fs_id(f)
                && !ids.contains(&id)
            {
                ids.push(id);
            }
        }
        for id in ids {
            let done = crate::rundirs::collect(DAY, Some(id), req.dry_run);
            let parts: Vec<(&Path, u64)> = done
                .dirs
                .iter()
                .map(|(dir, bytes)| (dir.as_path(), *bytes))
                .collect();
            sum.row_on(
                "run images",
                u64::try_from(parts.len()).unwrap_or(u64::MAX),
                &parts,
                format!("short of space: state dirs unused for {}", fmt_secs(DAY)),
            );
            sum.kept.extend(done.kept);
        }
    }
    let still: Vec<&PathBuf> = filesystems.iter().filter(|f| short(f).is_some()).collect();
    for f in &still {
        sum.keep(format!(
            "{} is still short of space: what is left is in use, recent, turned off in [gc], \
             or not virtkit's to remove",
            f.display()
        ));
    }
    sum.still_short = Some(!still.is_empty());
}

/// What `path`'s filesystem lacks of its `[gc] min_free` floor, if anything.
fn short_of(cfg: &Config, path: &Path) -> Option<u64> {
    let space = crate::usage::fs_space(path).ok()?;
    let floor = cfg.gc.min_free(space.total)?;
    floor.checked_sub(space.avail).filter(|&need| need > 0)
}

/// Remove the boot images of the `vk dev` environments under `base` stopped longer than
/// `[gc] dev_image_idle_days`, by when their run last held the state dir. One no run of this
/// `vk` held is left, as when it stopped is not known; so is one whose config has a
/// `hooks.create`, unless `[gc] dev_images_with_create_hook`.
fn dev_images(cfg: &Config, req: &Request, base: &Path, sum: &mut Summary) {
    let Some(idle) = (if req.all_unused {
        Some(DEV_IMAGE_FLOOR)
    } else {
        cfg.gc.dev_image_idle()
    }) else {
        return;
    };
    let rows = if req.auto {
        crate::dev::list::state_unflagged()
    } else {
        crate::dev::list::state(false)
    };
    let Ok(rows) = rows else {
        return;
    };
    let now = std::time::SystemTime::now();
    let (mut envs, mut bytes, mut stale) = (0u64, 0u64, 0usize);
    let (mut undated, mut hooked) = (Vec::new(), Vec::new());
    for row in rows {
        if row
            .flags
            .contains(&crate::dev::list::Flag::WorkspaceMissing)
        {
            stale += 1;
        }
        if row.status != crate::dev::list::Status::Stopped {
            continue;
        }
        // Read again under the environment's locks before anything goes.
        let Some(last) = crate::run::last_active(&row.dir) else {
            undated.push(row.name);
            continue;
        };
        if now.duration_since(last).unwrap_or_default() < idle {
            continue;
        }
        let with_hook = cfg.gc.dev_images_with_create_hook();
        match crate::dev::prune::reclaim_images(&row.dir, idle, with_hook, req.dry_run) {
            Ok(crate::dev::prune::Reclaimed::Images { files, bytes: b }) => {
                if files > 0 {
                    envs += 1;
                    bytes = bytes.saturating_add(b);
                }
            }
            Ok(crate::dev::prune::Reclaimed::Unrecorded) => sum.keep(format!(
                "dev images: {}: its storage was never recorded — `vk reset {} --dry-run` previews \
                 what it would take",
                row.name, row.name
            )),
            Ok(crate::dev::prune::Reclaimed::CreateHook) => hooked.push(row.name),
            Ok(crate::dev::prune::Reclaimed::Recent) => {}
            Err(e) => sum.keep(format!("dev images: {}: {e:#}", row.name)),
        }
    }
    sum.row(
        "dev images",
        envs,
        bytes,
        base,
        format!("environments stopped for {}", fmt_secs(idle)),
    );
    for name in hooked {
        sum.keep(format!(
            "dev images: {name} has hooks.create; reclaim with `vk reset {name}`"
        ));
    }
    if !undated.is_empty() {
        sum.keep(format!(
            "dev images: last run by an older vk, so not known to be idle: {} — \
             `vk reset NAME` reclaims their images",
            undated.join(", ")
        ));
    }
    if stale > 0 {
        sum.keep(format!(
            "dev environments: {stale} whose workspace is gone — `vk dev gc --all-stale` \
             removes them, persistent storage included"
        ));
    }
}

/// Remove the root images `vk run --state-dir` built into state dirs no run has held for
/// `[gc] run_image_idle_days`, each charged to its own filesystem.
fn run_images(cfg: &Config, req: &Request, sum: &mut Summary) {
    let idle = if req.all_unused {
        Some(DEV_IMAGE_FLOOR)
    } else {
        cfg.gc.run_image_idle()
    };
    let Some(idle) = idle else {
        return;
    };
    let done = crate::rundirs::collect(idle, None, req.dry_run);
    let parts: Vec<(&Path, u64)> = done
        .dirs
        .iter()
        .map(|(dir, bytes)| (dir.as_path(), *bytes))
        .collect();
    sum.row_on(
        "run images",
        u64::try_from(parts.len()).unwrap_or(u64::MAX),
        &parts,
        format!("state dirs unused for {}", fmt_secs(idle)),
    );
    sum.kept.extend(done.kept);
}

/// Where the build cache keeps what it caches, as `vk registry gc` resolves it.
fn cache_store(cfg: &Config) -> anyhow::Result<crate::build::CacheStore> {
    crate::build::cache_store(cfg.build.cache_registry.as_deref())
}

/// Collect the build cache's `store`, when it is in this filesystem: tags of its build-cache
/// repository, as [`collect_store`] collects them.
fn build_cache(
    cfg: &Config,
    store: &anyhow::Result<crate::build::CacheStore>,
    req: &Request,
    free_bytes: Option<u64>,
    sum: &mut Summary,
) {
    let dir = match store {
        Ok(crate::build::CacheStore::Dir(dir)) => dir.clone(),
        Ok(crate::build::CacheStore::Server(repo)) => {
            sum.keep(format!("build cache: {repo} is collected on its own host"));
            return;
        }
        Err(e) => {
            sum.keep(format!("build cache: {e:#}"));
            return;
        }
    };
    let swept = Swept {
        what: "build cache",
        users: "builds",
        dir,
        repository: Some(vk_registry::BUILD_CACHE_REPO.into()),
        // A Windows layer's view outlives the build that pulled it, reading the store by path.
        keep_prefixes: vec![crate::wincache::TAG_PREFIX.into()],
    };
    collect_store(cfg, &swept, req, free_bytes, sum);
}

/// The shared cache store ([`crate::sharedcache`]), checked as a store of its own before
/// anything is collected or the pass reads space: `None` while there is none.
fn shared_store_dir() -> anyhow::Result<Option<PathBuf>> {
    let root = crate::sharedcache::store_root()?;
    crate::sharedcache::open_store(&root, crate::sharedcache::Missing::Leave)
}

/// Collect the shared cache `store` ([`shared_store_dir`]): the tags of every repository, as
/// [`collect_store`] collects them, under the build cache's retention and cap but held to
/// them apart from it.
fn shared_cache(
    cfg: &Config,
    store: &anyhow::Result<Option<PathBuf>>,
    req: &Request,
    sum: &mut Summary,
) {
    match store {
        Ok(Some(dir)) => {
            collect_store(cfg, &task_store(dir.clone()), req, None, sum);
            sccache(cfg, dir, req, sum);
        }
        Ok(None) => {}
        Err(e) => sum.keep(format!("shared caches: {e:#}")),
    }
}

/// Collect the sccache area at `dir` if its eviction lock is free. Above `[gc] sccache_max`,
/// the target is 90% of the cap. A serving evictor normally checks once a second.
fn sccache(cfg: &Config, dir: &Path, req: &Request, sum: &mut Summary) {
    const WHAT: &str = "sccache";
    let usage = if req.dry_run {
        vk_registry::flat::Use::Inspect
    } else {
        vk_registry::flat::Use::Collect
    };
    let store = (|| {
        let Some(store) = vk_registry::Store::open(dir)? else {
            return Ok(None);
        };
        store.bind_flat(crate::sharedcache::flat_bindings(dir, &cfg.gc)?, usage)?;
        anyhow::Ok(Some(store))
    })();
    let store = match store {
        Ok(Some(store)) => store,
        Ok(None) => return,
        Err(e) => return sum.keep(format!("{WHAT}: {e:#}")),
    };
    // A dry run reports usage and the cap only when the store exceeds it.
    if req.dry_run {
        for a in store.flat().usage() {
            match a.usage {
                Ok(Some(u)) if u.bytes > a.cap => sum.keep(format!(
                    "{WHAT}: {} in {} object(s), over its {} cap: the least recently used go",
                    fmt_bytes(u.bytes),
                    u.objects,
                    fmt_bytes(a.cap)
                )),
                Ok(_) => {}
                Err(e) => sum.keep(format!("{WHAT}: {e:#}")),
            }
        }
        return;
    }
    let evicted = anyhow::Ok(store.flat().evict());
    let evicted = match evicted {
        Ok(e) => e,
        Err(e) => return sum.keep(format!("{WHAT}: {e:#}")),
    };
    for e in evicted {
        match e.outcome {
            Ok(vk_registry::flat::Eviction::Done(r)) => sum.row(
                WHAT,
                r.evicted,
                r.freed,
                dir,
                format!("oldest recorded use first above {}", fmt_bytes(e.cap)),
            ),
            Ok(_) => {}
            Err(err) => sum.keep(format!("{WHAT}: {err:#}")),
        }
    }
}

/// The shared cache store at `dir`, as a pass collects it.
fn task_store(dir: PathBuf) -> Swept {
    Swept {
        what: "shared caches",
        users: "environments",
        dir,
        repository: None,
        keep_prefixes: Vec::new(),
    }
}

/// A content-addressed store a pass collects.
struct Swept {
    /// Its row in the summary, and what a note about it starts with.
    what: &'static str,
    /// Who else holds its locks, for a note to name.
    users: &'static str,
    dir: PathBuf,
    /// The one repository whose tags may go; `None`: every repository's.
    repository: Option<String>,
    /// Tags never dropped, by the start of their name.
    keep_prefixes: Vec<String>,
}

/// Collect the store `swept` names, if there is one: the tags unused past the build cache's
/// retention, then the least recently used until it fits the build cache's cap, then the
/// blobs nothing references any more. A pass waits up to [`STORE_WAIT`] ([`AUTO_STORE_WAIT`]
/// in the background) for each lock on the store its users hold, then leaves what it has not
/// reached for the next.
fn collect_store(
    cfg: &Config,
    swept: &Swept,
    req: &Request,
    free_bytes: Option<u64>,
    sum: &mut Summary,
) {
    let Swept {
        what, users, dir, ..
    } = swept;
    let store = match vk_registry::Store::open(dir) {
        Ok(Some(store)) => store,
        Ok(None) => return,
        Err(e) => {
            sum.keep(format!("{what}: {e:#}"));
            return;
        }
    };
    // A cap that cannot be sized is no cap, never one of nothing.
    let max = match crate::usage::fs_space(dir) {
        Ok(space) => cfg.gc.build_cache_max(space.total),
        Err(e) => {
            sum.keep(format!(
                "{what}: not capped, its filesystem cannot be read: {e}"
            ));
            None
        }
    };
    let (retention, floor) = if req.all_unused {
        (Some(ALL_UNUSED_FLOOR), ALL_UNUSED_FLOOR)
    } else {
        (cfg.gc.build_cache_retention(), BUILD_CACHE_FLOOR)
    };
    // A background pass waits for nobody long: the next one will find the store free.
    let wait = if req.auto {
        AUTO_STORE_WAIT
    } else {
        STORE_WAIT
    };
    let policy = vk_registry::GcPolicy {
        retention,
        grace: floor,
        repository: swept.repository.clone(),
        keep_prefixes: swept.keep_prefixes.clone(),
        max_bytes: max,
        free_bytes,
        min_age: floor,
        dry_run: req.dry_run,
        wait: vk_registry::Wait::Within(wait),
        lower_planning: req.auto.then_some(crate::autogc::lower_planning as fn()),
    };
    let r = match store.gc_with(&policy) {
        Ok(vk_registry::GcOutcome::Done(r)) => r,
        Ok(vk_registry::GcOutcome::Busy) => {
            sum.keep(format!(
                "{what}: in use for {}, left for the next pass",
                fmt_secs(wait)
            ));
            sum.complete = false;
            return;
        }
        Err(e) => {
            sum.keep(format!("{what}: {e:#}"));
            return;
        }
    };
    let why = match (retention, max) {
        _ if free_bytes.is_some() => "short of space: least recently used".into(),
        (Some(r), Some(m)) => format!("unused for {}, then over {}", fmt_secs(r), fmt_bytes(m)),
        (Some(r), None) => format!("unused for {}", fmt_secs(r)),
        (None, Some(m)) => format!("over {}", fmt_bytes(m)),
        (None, None) => "no longer referenced".into(),
    };
    sum.row(
        what,
        u64::try_from(r.tags_dropped + r.tags_capped).unwrap_or(u64::MAX),
        r.bytes_freed,
        dir,
        format!("{why}; {users} waited {} at most", fmt_hold(r.longest_hold)),
    );
    if r.incomplete {
        sum.keep(format!(
            "{what}: {users} held it part-way, the rest is left for the next pass"
        ));
        sum.complete = false;
    }
    if let (Some(after), Some(max)) = (r.bytes_after, max)
        && after > max
    {
        sum.keep(format!(
            "{what}: {} in {}, over its {} cap — the rest was used within {}, is kept by \
             its manifest or its name, or is read by running {users}",
            fmt_bytes(after),
            dir.display(),
            fmt_bytes(max),
            fmt_secs(floor)
        ));
    }
    if r.blobs_leased > 0 {
        sum.keep(format!(
            "{what}: {} chunk(s), {}, read by running {users}",
            r.blobs_leased,
            fmt_bytes(r.bytes_leased)
        ));
    }
}

/// A lock hold: `120 ms`, `2.4 s`.
fn fmt_hold(d: Duration) -> String {
    if d < Duration::from_secs(1) {
        format!("{} ms", d.as_millis())
    } else {
        format!("{:.1} s", d.as_secs_f64())
    }
}

/// Why an idle-windowed entry went: unused for at least `idle`.
fn unused_for(idle: Duration) -> String {
    if idle.is_zero() {
        "not in use".into()
    } else {
        format!("unused for {}", fmt_secs(idle))
    }
}

/// `1800s` as `30m`, `86400s` as `1d`: the largest unit that divides it.
fn fmt_secs(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0 => "0s".into(),
        _ if s.is_multiple_of(86_400) => format!("{}d", s / 86_400),
        _ if s.is_multiple_of(3600) => format!("{}h", s / 3600),
        _ if s.is_multiple_of(60) => format!("{}m", s / 60),
        _ => format!("{s}s"),
    }
}

/// What a pass reclaimed, per category, and what it kept.
#[derive(Debug, Default)]
pub(crate) struct Summary {
    dry_run: bool,
    rows: Vec<Row>,
    /// What the pass found but left, each with why.
    kept: Vec<String>,
    /// The filesystems the pass reclaimed on.
    space: Vec<Space>,
    /// Whether every category was collected: not when one was left for the next pass.
    pub(crate) complete: bool,
    /// After a pass short of space went past the idle windows, whether it still is.
    pub(crate) still_short: Option<bool>,
    /// Filesystems may first be named by a row, and then show no space.
    lazy: bool,
}

#[derive(Debug)]
struct Row {
    category: &'static str,
    count: u64,
    bytes: u64,
    /// Which of [`Summary::space`] the bytes came from, and how many from each.
    on: Vec<(Option<usize>, u64)>,
    why: String,
}

#[derive(Debug)]
struct Space {
    /// The first existing path the pass named on it, to show it by and read it through.
    path: PathBuf,
    id: Option<u64>,
    /// `None` where it could not be read, or was first named only after the pass began.
    before: Option<u64>,
    after: Option<u64>,
}

impl Summary {
    /// A summary of a pass over `roots`, with the space on their filesystems read now, before
    /// anything goes.
    fn new(dry_run: bool, roots: &[&Path]) -> Summary {
        let mut sum = Summary {
            dry_run,
            complete: true,
            ..Summary::default()
        };
        for root in roots {
            sum.register(root, true);
        }
        sum
    }

    /// The index of `path`'s filesystem in [`Self::space`], placed by its nearest existing
    /// ancestor (a tier never used does not exist); `None` when none exists. Added the first
    /// time, its space read now when `read`; a filesystem that cannot be identified is never
    /// matched to another and shows no space.
    fn register(&mut self, path: &Path, read: bool) -> Option<usize> {
        let at = path.ancestors().find(|p| p.exists())?;
        let id = crate::usage::fs_id(at);
        if let Some(i) = self.space.iter().position(|s| id.is_some() && s.id == id) {
            return Some(i);
        }
        let before = if read && id.is_some() {
            crate::usage::fs_space(at).ok().map(|s| s.avail)
        } else {
            None
        };
        self.space.push(Space {
            path: at.to_path_buf(),
            id,
            before,
            after: None,
        });
        Some(self.space.len() - 1)
    }

    /// Add a category's row, its bytes freed on `on`'s filesystem. A category with nothing to
    /// show whose root does not exist is left out.
    pub(crate) fn row(
        &mut self,
        category: &'static str,
        count: u64,
        bytes: u64,
        on: &Path,
        why: String,
    ) {
        if count == 0 && bytes == 0 && !on.exists() {
            return;
        }
        self.row_on(category, count, &[(on, bytes)], why);
    }

    /// [`Self::row`] for a category collected tier by tier: `parts`, each a tier and the bytes
    /// freed there, on its own filesystem. Left out like [`Self::row`] when there is nothing to
    /// show and `root` does not exist.
    fn tier_row(
        &mut self,
        category: &'static str,
        count: u64,
        parts: &[(&Path, u64)],
        root: &Path,
        why: String,
    ) {
        if count == 0 && parts.iter().all(|(_, b)| *b == 0) && !root.exists() {
            return;
        }
        self.row_on(category, count, parts, why);
    }

    /// Add a category's row whose bytes came off several filesystems: `parts`, each a path on
    /// one and the bytes freed there.
    pub(crate) fn row_on(
        &mut self,
        category: &'static str,
        count: u64,
        parts: &[(&Path, u64)],
        why: String,
    ) {
        let known = self.space.len();
        let on: Vec<_> = parts
            .iter()
            .map(|&(path, bytes)| (self.register(path, false), bytes))
            .collect();
        debug_assert!(
            self.lazy || self.space.len() == known,
            "{category}: on a filesystem the pass did not read up front"
        );
        // A category the pass came back to, short of space, stays one row.
        if let Some(row) = self.rows.iter_mut().find(|r| r.category == category) {
            row.count = row.count.saturating_add(count);
            row.bytes = on.iter().fold(row.bytes, |t, (_, b)| t.saturating_add(*b));
            row.on.extend(on);
            row.why = format!("{}; then {why}", row.why);
            return;
        }
        self.rows.push(Row {
            category,
            count,
            bytes: on.iter().fold(0u64, |t, (_, b)| t.saturating_add(*b)),
            on,
            why,
        });
    }

    /// Note what the pass found but left, once.
    pub(crate) fn keep(&mut self, what: String) {
        if !self.kept.contains(&what) {
            self.kept.push(what);
        }
    }

    /// Read the space each filesystem has after a real pass; a dry run estimates it.
    fn finish(&mut self) {
        for i in 0..self.space.len() {
            let Some(before) = self.space[i].before else {
                continue;
            };
            let after = if self.dry_run {
                Some(before.saturating_add(self.freed_on(i)))
            } else {
                crate::usage::fs_space(&self.space[i].path)
                    .ok()
                    .map(|sp| sp.avail)
            };
            self.space[i].after = after;
        }
    }

    /// What the rows freed on [`Self::space`] `i`.
    fn freed_on(&self, i: usize) -> u64 {
        self.rows
            .iter()
            .flat_map(|r| &r.on)
            .filter(|(fs, _)| *fs == Some(i))
            .fold(0u64, |t, (_, b)| t.saturating_add(*b))
    }

    pub(crate) fn total(&self) -> u64 {
        self.rows.iter().fold(0, |t, r| t.saturating_add(r.bytes))
    }

    /// The summary as printed.
    pub(crate) fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let verb = if self.dry_run {
            "would reclaim"
        } else {
            "reclaimed"
        };
        let _ = writeln!(out, "virtkit: gc {verb} {}", fmt_bytes(self.total()));
        let width = self
            .rows
            .iter()
            .map(|r| r.category.len())
            .max()
            .unwrap_or(0)
            .max(11);
        for r in &self.rows {
            let _ = writeln!(
                out,
                "  {:<width$}{:>6}  {:>10}  {}",
                r.category,
                r.count,
                fmt_bytes(r.bytes),
                r.why
            );
        }
        if !self.kept.is_empty() {
            let _ = writeln!(out, "kept:");
            for k in &self.kept {
                let _ = writeln!(out, "  {k}");
            }
        }
        // The filesystems something came off; with nothing freed, the first one registered.
        let freed = |i: usize| self.freed_on(i) > 0;
        let any = (0..self.space.len()).any(freed);
        for (i, s) in self.space.iter().enumerate() {
            if !(freed(i) || (!any && i == 0)) {
                continue;
            }
            let (Some(before), Some(after)) = (s.before, s.after) else {
                continue;
            };
            let then = if self.dry_run { "after, est." } else { "after" };
            let _ = writeln!(
                out,
                "free on {}: {} before, {} {then}",
                s.path.display(),
                fmt_bytes(before),
                fmt_bytes(after)
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(dry_run: bool) -> Summary {
        let mut sum = Summary {
            dry_run,
            ..Summary::default()
        };
        sum.space.push(Space {
            path: "/data/virtkit".into(),
            id: Some(1),
            before: Some(10 << 30),
            after: None,
        });
        sum.rows.push(Row {
            category: "images",
            count: 2,
            bytes: 3 << 30,
            on: vec![(Some(0), 3 << 30)],
            why: "unused for 30m".into(),
        });
        sum.rows.push(Row {
            category: "checkouts",
            count: 0,
            bytes: 0,
            on: vec![(Some(0), 0)],
            why: "unused for 30m".into(),
        });
        sum.keep("/data/virtkit/build/x.tmp: another user's".into());
        sum
    }

    /// A dry run reports that the store is over its cap. Collection brings it under `[gc] sccache_max`.
    #[test]
    fn the_sccache_store_is_held_to_its_cap() {
        let tmp = crate::testtmp::Scratch::dir("gc-sccache");
        let dir = tmp.join("shared-cache");
        vk_registry::Store::new(dir.clone()).unwrap();
        let mut cfg = Config::default();
        cfg.gc.sccache_max = Some(crate::config::Limit::Bytes(1000));
        {
            let area = dir.join("flat/dev+sccache");
            let fs = vk_registry::flatstore::FlatStore::open(&area, Default::default()).unwrap();
            for k in ["a", "b", "c"] {
                fs.put(k.as_bytes(), &mut &[0u8; 600][..]).unwrap();
            }
        }
        let req = |dry_run| Request {
            dry_run,
            all_unused: false,
            auto: false,
            image_idle: crate::image::EVICT_GRACE,
            checkout_idle: crate::image::EVICT_GRACE,
        };
        let pass = |dry_run| {
            let mut sum = Summary::new(dry_run, &[dir.as_path()]);
            sccache(&cfg, &dir, &req(dry_run), &mut sum);
            sum
        };
        let dry = pass(true);
        assert!(dry.rows.is_empty());
        assert!(
            dry.kept.iter().any(|k| k.contains("over its 1000 B cap")),
            "{}",
            dry.render()
        );
        let sum = pass(false);
        let rows: Vec<_> = sum.rows.iter().map(|r| (r.category, r.count)).collect();
        assert_eq!(rows, [("sccache", 2)], "{}", sum.render());
    }

    /// The shared cache has no repository of its own to collect: an entry goes wherever a
    /// guest put it once it sits unused, and a fresh one stays.
    #[test]
    fn the_shared_cache_loses_its_unused_entries_in_every_repository() {
        let tmp = crate::testtmp::Scratch::dir("gc-shared-cache");
        let dir = tmp.join("shared-cache");
        let store = vk_registry::Store::new(dir.clone()).unwrap();
        const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
        let entry = |repo: &str, tag: &str, content: &[u8]| {
            let digest = store.put_blob(content).unwrap();
            let manifest = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": MANIFEST,
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": digest, "size": content.len(),
                },
                "layers": [],
            });
            store
                .put_manifest(repo, tag, MANIFEST, manifest.to_string().as_bytes())
                .unwrap();
            dir.join("repos").join(repo).join("tags").join(tag)
        };
        let old = std::time::SystemTime::now() - Duration::from_secs(30 * 86_400);
        let stale = [
            entry("dev/task-cache", "stale", b"one"),
            entry("dev/other/ns", "stale", b"two"),
        ];
        for tag in &stale {
            std::fs::File::open(tag).unwrap().set_modified(old).unwrap();
        }
        let fresh = entry("dev/task-cache", "fresh", b"three");

        let req = |dry_run| Request {
            dry_run,
            all_unused: false,
            auto: false,
            image_idle: crate::image::EVICT_GRACE,
            checkout_idle: crate::image::EVICT_GRACE,
        };
        let pass = |dry_run| {
            let mut sum = Summary::new(dry_run, &[dir.as_path()]);
            let swept = task_store(dir.clone());
            collect_store(&Config::default(), &swept, &req(dry_run), None, &mut sum);
            sum
        };
        let dropped = |sum: &Summary| {
            let rows: Vec<_> = sum.rows.iter().map(|r| (r.category, r.count)).collect();
            assert_eq!(rows, [("shared caches", 2)], "{}", sum.render());
        };
        dropped(&pass(true));
        assert!(
            stale.iter().all(|tag| tag.exists()),
            "a dry run drops nothing"
        );
        dropped(&pass(false));
        assert!(stale.iter().all(|tag| !tag.exists()));
        assert!(fresh.exists());

        // No store yet: nothing to report, and none is made.
        let absent = tmp.join("absent");
        let mut sum = Summary::new(false, &[&*tmp]);
        let swept = task_store(absent.clone());
        collect_store(&Config::default(), &swept, &req(false), None, &mut sum);
        assert!(
            sum.rows.is_empty() && sum.kept.is_empty(),
            "{}",
            sum.render()
        );
        assert!(!absent.exists());
    }

    /// Shared cache gc collects unused S3 objects like its other entries: a collected key is
    /// a 404 over S3, and a fresh key stays readable. This applies to tag-backed S3 areas.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_shared_cache_loses_its_unused_s3_objects() {
        use crate::sharedcache::tests::{ask, request};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tmp = crate::testtmp::Scratch::dir("gc-shared-cache-s3");
        let dir = tmp.join("shared-cache");
        let cfg = crate::sharedcache::serve(&dir, &["objects".to_string()])
            .await
            .unwrap();
        let proxy = crate::regproxy::spawn(cfg).await.unwrap();
        let object = |key: &str| format!("/s3/job/objects/a/b/c/{key}");
        for key in ["stale", "fresh"] {
            let (status, put) = ask(&proxy, request("PUT", &object(key), "", key)).await;
            assert_eq!(status, 200, "{put}");
        }
        let tags = dir.join("repos/files/dev/objects/a/b/c/tags");
        let old = std::time::SystemTime::now() - Duration::from_secs(30 * 86_400);
        std::fs::File::open(tags.join("stale"))
            .unwrap()
            .set_modified(old)
            .unwrap();

        let req = Request {
            dry_run: false,
            all_unused: false,
            auto: false,
            image_idle: crate::image::EVICT_GRACE,
            checkout_idle: crate::image::EVICT_GRACE,
        };
        let mut sum = Summary::new(false, &[dir.as_path()]);
        tokio::task::block_in_place(|| {
            let swept = task_store(dir.clone());
            collect_store(&Config::default(), &swept, &req, None, &mut sum);
        });
        let rows: Vec<_> = sum.rows.iter().map(|r| (r.category, r.count)).collect();
        assert_eq!(rows, [("shared caches", 1)], "{}", sum.render());
        assert!(!tags.join("stale").exists());
        assert!(tags.join("fresh").exists());
        let (status, gone) = ask(&proxy, request("GET", &object("stale"), "", "")).await;
        assert_eq!(status, 404, "{gone}");
        let (status, kept) = ask(&proxy, request("GET", &object("fresh"), "", "")).await;
        assert_eq!(status, 200, "{kept}");
    }

    /// A shared cache store at `dir` holding one tag unused for 30 days; its tag file.
    fn stale_task_store(dir: &Path) -> PathBuf {
        const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
        let store = vk_registry::Store::new(dir.to_path_buf()).unwrap();
        let digest = store.put_blob(b"output").unwrap();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest, "size": 6,
            },
            "layers": [],
        });
        store
            .put_manifest(
                "dev/task-cache",
                "k",
                MANIFEST,
                manifest.to_string().as_bytes(),
            )
            .unwrap();
        let tag = dir.join("repos/dev/task-cache/tags/k");
        let old = std::time::SystemTime::now() - Duration::from_secs(30 * 86_400);
        std::fs::File::open(&tag)
            .unwrap()
            .set_modified(old)
            .unwrap();
        tag
    }

    /// A pass finds the shared cache where `vk dev` keeps it, reads its filesystem's space
    /// before anything goes — on a filesystem of its own when the host has a second one —
    /// and collects it only once it is a private store `vk` made: never through a link,
    /// nor one open to other users or holding something else, nor before the first boot.
    #[test]
    fn a_pass_collects_the_shared_cache_only_as_a_private_store_of_its_own() {
        const CHILD: &str = "VK_TEST_GC_TASK_STORE";
        const NAME: &str =
            "gc::tests::a_pass_collects_the_shared_cache_only_as_a_private_store_of_its_own";
        let Some(home) = crate::dev::testutil::child_marker(CHILD).map(PathBuf::from) else {
            let _guard = crate::dev::testutil::env_guard();
            let tmp = crate::dev::testutil::scratch("gc-task-store");
            // `/dev/shm` is a tmpfs apart from the scratch dir's filesystem on most hosts.
            let shm = Path::new("/dev/shm");
            let cache = match shm.is_dir() {
                true => shm.join(format!("vk-test-gc-task-store-{}", std::process::id())),
                false => tmp.0.join("cache"),
            };
            let _ = std::fs::remove_dir_all(&cache);
            std::fs::create_dir(&cache).unwrap();
            let output = crate::dev::testutil::child_test(NAME)
                .env(CHILD, &tmp.0)
                .env("XDG_STATE_HOME", tmp.0.join("state"))
                .env("XDG_DATA_HOME", tmp.0.join("data"))
                .env("XDG_CACHE_HOME", &cache)
                .output()
                .unwrap();
            let _ = std::fs::remove_dir_all(&cache);
            crate::dev::testutil::ran_alone(NAME, &output);
            return;
        };
        let root = crate::sharedcache::store_root().unwrap();
        assert!(
            root.starts_with(std::env::var_os("XDG_CACHE_HOME").unwrap()),
            "{}",
            root.display()
        );
        let state_dir = home.join("vk-state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let mut cfg = Config {
            state_dir: Some(state_dir.clone()),
            ..Config::default()
        };
        cfg.build.cache_registry = Some(home.join("build-cache").display().to_string());
        let req = Request {
            dry_run: false,
            all_unused: false,
            auto: false,
            image_idle: crate::image::EVICT_GRACE,
            checkout_idle: crate::image::EVICT_GRACE,
        };
        let pass = || run(&cfg, &state_dir, &req);
        let task_rows = |sum: &Summary| {
            sum.rows
                .iter()
                .filter(|r| r.category == "shared caches")
                .map(|r| r.count)
                .sum::<u64>()
        };
        let kept = |sum: &Summary, why: &str| {
            assert!(
                sum.kept
                    .iter()
                    .any(|k| k.starts_with("shared caches: ") && k.contains(why)),
                "{why}: {}",
                sum.render()
            );
        };

        // Before the first boot: nothing to say, and nothing made.
        let sum = pass();
        assert_eq!(task_rows(&sum), 0, "{}", sum.render());
        assert!(
            !sum.kept.iter().any(|k| k.starts_with("shared caches")),
            "{}",
            sum.render()
        );
        assert!(!root.exists());

        // A link to another store, however much it looks like one, leads the pass nowhere.
        let elsewhere = home.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let elsewhere_tag = stale_task_store(&elsewhere);
        std::fs::write(elsewhere.join("vk-shared-cache"), b"").unwrap();
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &root).unwrap();
        kept(&pass(), "symbolic link");
        assert!(elsewhere_tag.exists());
        std::fs::remove_file(&root).unwrap();

        // A store other users can reach is not the private one guests are promised.
        use std::os::unix::fs::PermissionsExt;
        crate::sharedcache::open_store(&root, crate::sharedcache::Missing::Create).unwrap();
        let tag = stale_task_store(&root);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        kept(&pass(), "open to other users");
        assert!(tag.exists());

        // Nor is a store `vk` did not make for the shared cache.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_file(root.join("vk-shared-cache")).unwrap();
        kept(&pass(), "not a shared cache store");
        assert!(tag.exists());

        // The store itself: collected, on a filesystem whose space was read up front.
        std::fs::write(root.join("vk-shared-cache"), b"").unwrap();
        let sum = pass();
        assert_eq!(task_rows(&sum), 1, "{}", sum.render());
        assert!(!tag.exists());
        let id = crate::usage::fs_id(&root);
        assert!(
            sum.space.iter().any(|s| s.id == id && s.before.is_some()),
            "{}",
            sum.render()
        );
    }

    #[test]
    fn a_dry_run_estimates_the_space_after() {
        let mut sum = summary(true);
        sum.finish();
        assert_eq!(
            sum.render(),
            "virtkit: gc would reclaim 3.0 GiB\n\
             \x20 images          2     3.0 GiB  unused for 30m\n\
             \x20 checkouts       0         0 B  unused for 30m\n\
             kept:\n\
             \x20 /data/virtkit/build/x.tmp: another user's\n\
             free on /data/virtkit: 10.0 GiB before, 13.0 GiB after, est.\n"
        );
    }

    /// Only the filesystems something came off show their space; one that freed nothing is
    /// left out, and with nothing freed anywhere the first one registered still shows.
    #[test]
    fn only_filesystems_that_freed_space_show_it() {
        let mut sum = summary(false);
        sum.space.push(Space {
            path: "/var/lib/virtkit".into(),
            id: Some(2),
            before: Some(5 << 30),
            after: Some(5 << 30),
        });
        sum.rows.push(Row {
            category: "launch dirs",
            count: 0,
            bytes: 0,
            on: vec![(Some(1), 0)],
            why: "left by runs killed by a signal".into(),
        });
        sum.space[0].after = Some(13 << 30);
        let out = sum.render();
        assert!(out.contains("free on /data/virtkit: 10.0 GiB before, 13.0 GiB after\n"));
        assert!(!out.contains("/var/lib/virtkit"), "{out}");

        sum.rows.retain(|r| r.bytes == 0);
        let out = sum.render();
        assert!(out.contains("free on /data/virtkit:"), "{out}");
        assert!(!out.contains("/var/lib/virtkit"), "{out}");
    }

    /// Snapshot paths and symlink targets. For other entries, record type, size and mtime.
    fn tree(root: &Path) -> Vec<(PathBuf, String)> {
        let mut out = Vec::new();
        let mut todo = vec![root.to_path_buf()];
        while let Some(dir) = todo.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let path = e.unwrap().path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let what = if meta.is_symlink() {
                    format!("-> {}", std::fs::read_link(&path).unwrap().display())
                } else {
                    format!(
                        "{:?} {} {:?}",
                        meta.file_type(),
                        meta.len(),
                        meta.modified().unwrap()
                    )
                };
                if meta.is_dir() {
                    todo.push(path.clone());
                }
                out.push((path, what));
            }
        }
        out.sort();
        out
    }

    /// Dry-run GC preserves registrations, names, state records and the run ledger for an
    /// idle `vk run --state-dir` and a stopped dev environment. A real pass reclaims the
    /// root images listed in the preview.
    #[test]
    fn a_dry_run_changes_no_registration_name_or_record() {
        // Set the XDG homes on a child process so other test threads keep their environment.
        const CHILD: &str = "VK_TEST_GC_DRY_RUN_HOMES";
        const NAME: &str = "gc::tests::a_dry_run_changes_no_registration_name_or_record";
        const HOMES: [&str; 3] = ["XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"];
        let Some(home) = crate::dev::testutil::child_marker(CHILD).map(PathBuf::from) else {
            let _guard = crate::dev::testutil::env_guard();
            let tmp = crate::dev::testutil::scratch("gc-dry-run");
            let output = crate::dev::testutil::child_test(NAME)
                .env(CHILD, &tmp.0)
                .envs(HOMES.map(|v| (v, tmp.0.join(v))))
                .output()
                .unwrap();
            crate::dev::testutil::ran_alone(NAME, &output);
            return;
        };
        // The test runs real garbage collection, so check all three homes first.
        for var in HOMES {
            assert_eq!(std::env::var_os(var), Some(home.join(var).into()), "{var}");
        }
        let name = |state: &Path, name: &str| {
            crate::names::Index::open()
                .unwrap()
                .claim_exact(state, name)
                .unwrap();
        };
        let old = std::time::SystemTime::now() - Duration::from_secs(2 * 86_400);
        let idle_vm = |dir: &Path| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("root.qcow2"), vec![1u8; 16 * 1024]).unwrap();
            let stamp = dir.join(crate::run::ACTIVE_STAMP);
            std::fs::write(&stamp, b"").unwrap();
            std::fs::File::open(&stamp)
                .unwrap()
                .set_modified(old)
                .unwrap();
            // A killed run leaves a registration but releases the directory lock.
            let entry = serde_json::from_value(serde_json::json!({
                "state_dir": crate::vms::canonical(dir),
                "pid": std::process::id(),
                "label": "gone",
                "exec_addr": "unused",
                "created_secs": 7,
            }))
            .unwrap();
            crate::vms::register(entry)
        };
        let run_dir = home.join("run-state");
        let _run = idle_vm(&run_dir);
        crate::rundirs::record(&run_dir).unwrap();
        name(&run_dir, "old-run");
        let dev_dir = crate::dev::plan::dev_state_base()
            .unwrap()
            .join("proj-1a2b");
        let _dev = idle_vm(&dev_dir);
        let identity = crate::dev::Identity {
            digest: "d".into(),
            booted_secs: 0,
            created_by: String::new(),
            generation: String::new(),
            manifest: serde_json::json!({ "environment": "dev", "hooks": { "create": null } }),
            storage_backings: Some(Vec::new()),
            readied_by_its_boot: true,
        };
        std::fs::write(
            dev_dir.join("dev.json"),
            serde_json::to_vec(&identity).unwrap(),
        )
        .unwrap();
        name(&dev_dir, "old-dev");
        assert_eq!(crate::vms::registered().1.len(), 2);

        let state_dir = home.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg = Config {
            state_dir: Some(state_dir.clone()),
            ..Config::default()
        };
        let req = |dry_run| Request {
            dry_run,
            all_unused: true,
            auto: false,
            image_idle: crate::image::EVICT_GRACE,
            checkout_idle: crate::image::EVICT_GRACE,
        };
        let count = |sum: &Summary, category| {
            sum.rows
                .iter()
                .filter(|r| r.category == category)
                .map(|r| r.count)
                .sum::<u64>()
        };
        let before = tree(&home);
        let dry = run(&cfg, &state_dir, &req(true));
        assert_eq!(tree(&home), before, "{}", dry.render());
        assert_eq!(count(&dry, "dev images"), 1, "{}", dry.render());
        assert_eq!(count(&dry, "run images"), 1, "{}", dry.render());

        let real = run(&cfg, &state_dir, &req(false));
        assert_eq!(count(&real, "dev images"), 1, "{}", real.render());
        assert_eq!(count(&real, "run images"), 1, "{}", real.render());
        assert!(!run_dir.join("root.qcow2").exists());
        assert!(!dev_dir.join("root.qcow2").exists());
        assert!(crate::vms::registered().1.is_empty(), "a real pass prunes");
    }

    /// Dry-run and real GC each count the migrated build entry once and preserve the old link.
    #[test]
    fn a_pass_after_the_move_collects_each_tier_once() {
        let homes = crate::dev::testutil::Homes::new("gc-moved");
        let data = homes.dir().join("XDG_DATA_HOME/virtkit");
        let cache = homes.dir().join("XDG_CACHE_HOME/virtkit");
        let base = data.join("build/fp");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("runner.ext4"), vec![1u8; 64 * 1024]).unwrap();
        crate::image::mark_used(&base);
        std::fs::File::open(base.join(".used"))
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600)),
            )
            .unwrap();
        let cfg = Config::default();
        let root = crate::run::cache_root(&cfg).unwrap();
        assert_eq!(root, cache);
        let req = |dry_run| Request {
            dry_run,
            all_unused: true,
            auto: false,
            image_idle: crate::image::EVICT_GRACE,
            checkout_idle: crate::image::EVICT_GRACE,
        };
        let images = |sum: &Summary| {
            sum.rows
                .iter()
                .filter(|r| r.category == "images")
                .map(|r| r.count)
                .sum::<u64>()
        };
        let dry = run(&cfg, &root, &req(true));
        assert_eq!(images(&dry), 1, "{}", dry.render());
        let real = run(&cfg, &root, &req(false));
        assert_eq!(images(&real), 1, "{}", real.render());
        assert!(!cache.join("build/fp").exists());
        assert_eq!(
            std::fs::read_link(data.join("build")).unwrap(),
            cache.join("build")
        );
    }

    /// A directory on a filesystem other than `base`'s, or `None` where the host has none to
    /// test with.
    fn elsewhere(base: &Path, tag: &str) -> Option<PathBuf> {
        let ours = crate::usage::fs_id(base)?;
        ["/dev/shm", "/var/tmp", "/run/user"]
            .iter()
            .map(|d| Path::new(d).join(format!("vk-gc-{tag}-{}", std::process::id())))
            .find(|d| {
                std::fs::create_dir_all(d).is_ok()
                    && crate::usage::fs_id(d).is_some_and(|id| id != ours)
            })
    }

    /// GC credits a linked tier's bytes to its filesystem. The pressure sweep leaves
    /// tiers on filesystems with enough space alone.
    #[test]
    fn each_tier_is_accounted_on_its_own_filesystem() {
        use std::os::unix::fs::MetadataExt;
        let homes = crate::dev::testutil::Homes::new("gc-devices");
        let root = homes.dir().join("XDG_CACHE_HOME/virtkit");
        let Some(other) = elsewhere(homes.dir(), "devices") else {
            eprintln!("no second filesystem to test with");
            return;
        };
        std::fs::create_dir_all(root.join("docker")).unwrap();
        std::os::unix::fs::symlink(&other, root.join("build")).unwrap();
        let idle = |base: &Path| {
            std::fs::create_dir_all(base).unwrap();
            std::fs::write(base.join("runner.ext4"), vec![1u8; 64 * 1024]).unwrap();
            crate::image::mark_used(base);
            std::fs::File::open(base.join(".used"))
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600)),
                )
                .unwrap();
        };
        idle(&root.join("docker/img/d"));
        idle(&root.join("build/fp"));
        let fs = tier_filesystems(&root);
        assert_eq!(fs, [root.join("docker"), root.join("build")]);

        let cfg = Config::default();
        let req = Request {
            dry_run: true,
            all_unused: true,
            auto: false,
            image_idle: crate::image::EVICT_GRACE,
            checkout_idle: crate::image::EVICT_GRACE,
        };
        let sum = run(&cfg, &root, &req);
        let images = sum.rows.iter().find(|r| r.category == "images").unwrap();
        let on = |path: &Path| {
            let id = crate::usage::fs_id(path);
            sum.space.iter().position(|s| s.id == id)
        };
        let credited = |path: &Path| {
            images
                .on
                .iter()
                .filter(|(i, _)| *i == on(path) && i.is_some())
                .map(|(_, b)| *b)
                .sum::<u64>()
        };
        assert!(credited(&other) >= 64 * 1024, "{}", sum.render());
        assert!(credited(&root) >= 64 * 1024, "{}", sum.render());

        // Short of space where `build` is, and only there.
        let dev = std::fs::metadata(&other).unwrap().dev();
        let short = |p: &Path| {
            std::fs::metadata(p)
                .is_ok_and(|m| m.dev() == dev)
                .then_some(1u64)
        };
        let mut sum = Summary::new(false, &[&root, &root.join("docker"), &root.join("build")]);
        sum.lazy = true;
        let req = Request {
            dry_run: false,
            auto: true,
            ..req
        };
        pressure(
            &cfg,
            &root,
            &Err(anyhow::anyhow!("no store")),
            &req,
            &mut sum,
            &short,
        );
        assert!(!root.join("build/fp").exists(), "{}", sum.render());
        assert!(root.join("docker/img/d").exists(), "{}", sum.render());
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn durations_take_their_largest_whole_unit() {
        assert_eq!(fmt_secs(Duration::from_secs(1800)), "30m");
        assert_eq!(fmt_secs(Duration::from_secs(7200)), "2h");
        assert_eq!(fmt_secs(Duration::from_secs(14 * 86_400)), "14d");
        assert_eq!(fmt_secs(Duration::from_secs(90)), "90s");
        assert_eq!(unused_for(Duration::ZERO), "not in use");
    }
}
