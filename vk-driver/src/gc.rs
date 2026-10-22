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
/// The least time `--all-unused` leaves a stopped dev environment's boot images after it was
/// last in use: one stopped moments ago may be about to start again.
const DEV_IMAGE_FLOOR: Duration = Duration::from_secs(3600);
/// The longest a manual pass waits for each lock on the build cache's store.
const STORE_WAIT: Duration = Duration::from_secs(60);

/// What a `vk gc` pass may take.
pub(crate) struct Request {
    /// Count what would go and remove nothing.
    pub(crate) dry_run: bool,
    /// Ignore the configured retention and idle windows; the floors above still hold.
    pub(crate) all_unused: bool,
    /// How long a materialized base must sit unused.
    pub(crate) image_idle: Duration,
    /// How long a host checkout must sit unused.
    pub(crate) checkout_idle: Duration,
}

/// Run a pass over the image tiers under `state_dir` (the one `vk run` caches under) and the
/// executor's checkouts.
pub(crate) fn run(cfg: &Config, state_dir: &Path, req: &Request) -> Summary {
    let checkout_root = cfg.checkout_root();
    let store = cache_store(cfg);
    // Every filesystem the pass may free space on, its space read before anything goes.
    let mut roots = vec![state_dir, checkout_root.as_path()];
    if let Ok(crate::build::CacheStore::Dir(dir)) = &store {
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
    let mut sum = Summary::new(req.dry_run, &roots);

    let mut images = crate::image::Evicted::default();
    for tier in ["registry", "docker", "build"] {
        let got = crate::image::collect_idle(&state_dir.join(tier), req.image_idle, req.dry_run);
        images.bases += got.bases;
        images.bytes = images.bytes.saturating_add(got.bytes);
        images.would_evict.extend(got.would_evict);
    }
    sum.row(
        "images",
        images.bases,
        images.bytes,
        state_dir,
        unused_for(req.image_idle),
    );
    let (chunks, chunk_bytes) = crate::image::collect_chunks(
        &state_dir.join("registry"),
        req.dry_run,
        &images.would_evict,
    );
    sum.row(
        "chunks",
        chunks,
        chunk_bytes,
        state_dir,
        "no cached image uses them".into(),
    );
    let staging = crate::image::collect_orphaned_staging(state_dir, req.dry_run);
    sum.row(
        "leftovers",
        staging.dirs,
        staging.bytes,
        state_dir,
        "staging of dead builds and pulls".into(),
    );
    for dir in &staging.foreign {
        sum.keep(format!("{}: another user's", dir.display()));
    }
    sum.kept.extend(staging.left);
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
    build_cache(cfg, store, req, &mut sum);
    if let Ok(base) = &dev_base {
        dev_images(cfg, req, base, &mut sum);
    }
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
    sum.finish();
    sum
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
    let Ok(rows) = crate::dev::list::state(false) else {
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
                "dev images: {}: its storage was never recorded — `vk dev prune {}` previews \
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
            "dev images: {name} has hooks.create; reclaim with `vk dev prune {name}`"
        ));
    }
    if !undated.is_empty() {
        sum.keep(format!(
            "dev images: last run by an older vk, so not known to be idle: {} — \
             `vk dev prune NAME` reclaims their images",
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

/// Where the build cache keeps what it caches, as `vk registry gc` resolves it.
fn cache_store(cfg: &Config) -> anyhow::Result<crate::build::CacheStore> {
    crate::build::cache_store(cfg.build.cache_registry.as_deref())
}

/// Collect the build cache's `store`, when it is in this filesystem: tags of its build-cache
/// repository unused past the retention, then the least recently used until it fits its cap,
/// then the blobs nothing references any more. A pass waits up to [`STORE_WAIT`] for each lock
/// on the store the builds using it hold, then leaves what it has not reached for the next.
fn build_cache(
    cfg: &Config,
    store: anyhow::Result<crate::build::CacheStore>,
    req: &Request,
    sum: &mut Summary,
) {
    let dir = match store {
        Ok(crate::build::CacheStore::Dir(dir)) => dir,
        Ok(crate::build::CacheStore::Server(repo)) => {
            sum.keep(format!("build cache: {repo} is collected on its own host"));
            return;
        }
        Err(e) => {
            sum.keep(format!("build cache: {e:#}"));
            return;
        }
    };
    let store = match vk_registry::Store::open(&dir) {
        Ok(Some(store)) => store,
        Ok(None) => return,
        Err(e) => {
            sum.keep(format!("build cache: {e:#}"));
            return;
        }
    };
    // A cap that cannot be sized is no cap, never one of nothing.
    let max = match crate::usage::fs_space(&dir) {
        Ok(space) => cfg.gc.build_cache_max(space.total),
        Err(e) => {
            sum.keep(format!(
                "build cache: not capped, its filesystem cannot be read: {e}"
            ));
            None
        }
    };
    let (retention, floor) = if req.all_unused {
        (Some(ALL_UNUSED_FLOOR), ALL_UNUSED_FLOOR)
    } else {
        (cfg.gc.build_cache_retention(), BUILD_CACHE_FLOOR)
    };
    let policy = vk_registry::GcPolicy {
        retention,
        grace: floor,
        repository: Some(vk_registry::BUILD_CACHE_REPO.into()),
        // A Windows layer's view outlives the build that pulled it, reading the store by path.
        keep_prefixes: vec![crate::wincache::TAG_PREFIX.into()],
        max_bytes: max,
        free_bytes: None,
        min_age: floor,
        dry_run: req.dry_run,
        wait: vk_registry::Wait::Within(STORE_WAIT),
        lower_planning: None,
    };
    let r = match store.gc_with(&policy) {
        Ok(vk_registry::GcOutcome::Done(r)) => r,
        Ok(vk_registry::GcOutcome::Busy) => {
            sum.keep(format!(
                "build cache: in use for {}, left for the next pass",
                fmt_secs(STORE_WAIT)
            ));
            return;
        }
        Err(e) => {
            sum.keep(format!("build cache: {e:#}"));
            return;
        }
    };
    let why = match (retention, max) {
        (Some(r), Some(m)) => format!("unused for {}, then over {}", fmt_secs(r), fmt_bytes(m)),
        (Some(r), None) => format!("unused for {}", fmt_secs(r)),
        (None, Some(m)) => format!("over {}", fmt_bytes(m)),
        (None, None) => "no longer referenced".into(),
    };
    sum.row(
        "build cache",
        u64::try_from(r.tags_dropped + r.tags_capped).unwrap_or(u64::MAX),
        r.bytes_freed,
        &dir,
        format!("{why}; builds waited {} at most", fmt_hold(r.longest_hold)),
    );
    if r.incomplete {
        sum.keep("build cache: builds held it part-way, the rest is left for the next pass".into());
    }
    if let (Some(after), Some(max)) = (r.bytes_after, max)
        && after > max
    {
        sum.keep(format!(
            "build cache: {} in {}, over its {} cap — the rest was used within {}, is kept by \
             its manifest or its name, or is read by running builds",
            fmt_bytes(after),
            dir.display(),
            fmt_bytes(max),
            fmt_secs(floor)
        ));
    }
    if r.blobs_leased > 0 {
        sum.keep(format!(
            "build cache: {} chunk(s), {}, read by running builds",
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
}

#[derive(Debug)]
struct Row {
    category: &'static str,
    count: u64,
    bytes: u64,
    /// Which of [`Summary::space`] the bytes came from.
    fs: Option<usize>,
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
        let known = self.space.len();
        let fs = self.register(on, false);
        debug_assert!(
            self.space.len() == known,
            "{} is on a filesystem the pass did not read up front",
            on.display()
        );
        self.rows.push(Row {
            category,
            count,
            bytes,
            fs,
            why,
        });
    }

    pub(crate) fn keep(&mut self, what: String) {
        self.kept.push(what);
    }

    /// Read the space each filesystem has after a real pass; a dry run estimates it.
    fn finish(&mut self) {
        for (i, s) in self.space.iter_mut().enumerate() {
            let Some(before) = s.before else {
                continue;
            };
            s.after = if self.dry_run {
                let freed = self
                    .rows
                    .iter()
                    .filter(|r| r.fs == Some(i))
                    .fold(0u64, |t, r| t.saturating_add(r.bytes));
                Some(before.saturating_add(freed))
            } else {
                crate::usage::fs_space(&s.path).ok().map(|sp| sp.avail)
            };
        }
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
        for r in &self.rows {
            let _ = writeln!(
                out,
                "  {:<11}{:>6}  {:>10}  {}",
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
        // The filesystems something came off, else the first: the data dir's.
        let freed = |i: usize| self.rows.iter().any(|r| r.fs == Some(i) && r.bytes > 0);
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
            fs: Some(0),
            why: "unused for 30m".into(),
        });
        sum.rows.push(Row {
            category: "checkouts",
            count: 0,
            bytes: 0,
            fs: Some(0),
            why: "unused for 30m".into(),
        });
        sum.keep("/data/virtkit/build/x.tmp: another user's".into());
        sum
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
    /// left out, and with nothing freed anywhere the data dir's still shows.
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
            fs: Some(1),
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

    #[test]
    fn durations_take_their_largest_whole_unit() {
        assert_eq!(fmt_secs(Duration::from_secs(1800)), "30m");
        assert_eq!(fmt_secs(Duration::from_secs(7200)), "2h");
        assert_eq!(fmt_secs(Duration::from_secs(14 * 86_400)), "14d");
        assert_eq!(fmt_secs(Duration::from_secs(90)), "90s");
        assert_eq!(unused_for(Duration::ZERO), "not in use");
    }
}
