//! Enforce `files/` policies from the server timer and offline gc via
//! [`Store::sweep_files_once`]. Object mtime tracks use: PUT sets it and GET refreshes it after
//! an hour. First build an idle-age histogram, then remove objects past the TTL or size cutoff
//! and prune empty subdirectories. Memory use scales with age buckets, not objects. A
//! concurrent PUT between stat and unlink may lose a fresh cache entry; avoiding that race
//! would require locking during the walk. Directories without policies are skipped. Every pass
//! also prunes staging files older than a day; active PUTs refresh staging mtime per chunk.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};

use crate::files_policy::{FilesDirStats, FilesPolicy, valid_dir};
use crate::{Store, human_bytes};

/// Age threshold for pruning stale staging files.
pub(crate) const STAGING_GRACE: Duration = Duration::from_secs(24 * 3600);

/// Interval for checking policy changes.
pub const SWEEP_TICK: Duration = Duration::from_secs(5 * 60);

/// Sweep interval when policies are unchanged. Size limits are enforced by sweeps, not on each
/// PUT.
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// What was done to one directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirSweep {
    pub dir: String,
    pub policy: PolicyState,
    pub objects_dropped: u64,
    pub bytes_freed: u64,
    pub dirs_dropped: u64,
    pub objects_kept: u64,
    pub bytes_kept: u64,
    /// unlinks and rmdirs that failed for a reason other than the entry being gone
    pub errors: u64,
}

/// Whether a directory's policy could be enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyState {
    Applied(FilesPolicy),
    /// the file is not a policy; nothing in the directory was touched
    Invalid(String),
}

/// One pass over every policy.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FilesSweepReport {
    /// one entry per policy file, valid or not, in directory order
    pub dirs: Vec<DirSweep>,
    pub staging_dropped: u64,
    /// Usage of directories without policies; these are never swept.
    pub unpoliced: Vec<(String, FilesDirStats)>,
}

impl FilesSweepReport {
    /// Report evictions, policy errors and stale staging removals. Return no lines for an
    /// unchanged pass.
    pub fn lines(&self, dry_run: bool) -> Vec<String> {
        let verb = if dry_run { "would drop" } else { "dropped" };
        let mut out = Vec::new();
        for d in &self.dirs {
            match &d.policy {
                PolicyState::Invalid(why) => {
                    out.push(format!("files/{}: policy not applied: {why}", d.dir));
                }
                PolicyState::Applied(p) if d.objects_dropped > 0 || d.dirs_dropped > 0 => {
                    let mut line = format!(
                        "files/{}: {verb} {} object(s) ({}) and {} directory(ies); {} object(s) \
                         ({}) kept [policy {}]",
                        d.dir,
                        d.objects_dropped,
                        human_bytes(d.bytes_freed),
                        d.dirs_dropped,
                        d.objects_kept,
                        human_bytes(d.bytes_kept),
                        p.describe(),
                    );
                    if d.errors > 0 {
                        line.push_str(&format!("; {} removal(s) failed", d.errors));
                    }
                    out.push(line);
                }
                PolicyState::Applied(_) if d.errors > 0 => {
                    out.push(format!("files/{}: {} removal(s) failed", d.dir, d.errors))
                }
                PolicyState::Applied(_) => {}
            }
        }
        if self.staging_dropped > 0 {
            out.push(format!(
                "files/.staging: {verb} {} abandoned upload(s)",
                self.staging_dropped
            ));
        }
        out
    }

    /// Summarize directories without policies, or return None if there are none.
    pub fn unpoliced_line(&self) -> Option<String> {
        if self.unpoliced.is_empty() {
            return None;
        }
        let list: Vec<String> = self
            .unpoliced
            .iter()
            .map(|(d, s)| format!("{d} ({} in {} object(s))", human_bytes(s.bytes), s.objects))
            .collect();
        Some(format!(
            "files/: no eviction policy on {}; `vk-registry files policy <dir> --ttl-days N \
             --max-bytes SIZE` sets one",
            list.join(", ")
        ))
    }
}

impl Store {
    /// Enforce `policy` on `files/<dir>`: see the module doc for the two walks. A missing
    /// directory is an empty one. `dry_run` walks and counts but removes nothing.
    pub fn sweep_files(&self, dir: &str, policy: &FilesPolicy, dry_run: bool) -> Result<DirSweep> {
        if !valid_dir(dir) {
            bail!("{dir:?} is not a name a files/ directory can have");
        }
        let root = self.files_dir().join(dir);
        let now = SystemTime::now();
        let mut report = DirSweep {
            dir: dir.to_string(),
            policy: PolicyState::Applied(policy.clone()),
            objects_dropped: 0,
            bytes_freed: 0,
            dirs_dropped: 0,
            objects_kept: 0,
            bytes_kept: 0,
            errors: 0,
        };
        // Read walk: how much lies at each idle age.
        let mut ages = Histogram::default();
        crate::files_policy::walk_files(&root, 0, &mut |_, meta| {
            ages.add(idle(now, meta), meta.len());
        });
        let Some(cutoff) = cutoff(&ages, policy) else {
            report.objects_kept = ages.objects();
            report.bytes_kept = ages.bytes();
            return Ok(report);
        };
        // Remove expired objects and empty subdirectories, preserving the top-level directory
        // for its policy and scope.
        let mut w = Writer {
            now,
            cutoff,
            dry_run,
            report: &mut report,
        };
        w.sweep_dir(&root, 0);
        Ok(report)
    }

    /// Remove staging files older than [`STAGING_GRACE`] and return the count.
    pub fn prune_files_staging(&self, dry_run: bool) -> Result<u64> {
        let dir = self.files_staging_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
        };
        let now = SystemTime::now();
        let mut dropped = 0;
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_file() || idle(now, &meta) < STAGING_GRACE {
                continue;
            }
            if dry_run || remove_file(&path) {
                dropped += 1;
            }
        }
        Ok(dropped)
    }

    /// Apply valid policies, report invalid ones, prune stale staging files and list unpoliced
    /// directories. Shared by the server and gc.
    pub fn sweep_files_once(&self, dry_run: bool) -> Result<FilesSweepReport> {
        let policies = self.read_files_policies()?;
        let mut report = FilesSweepReport::default();
        for (dir, policy) in &policies {
            report.dirs.push(match policy {
                Ok(p) => self.sweep_files(dir, p, dry_run)?,
                Err(e) => DirSweep {
                    dir: dir.clone(),
                    policy: PolicyState::Invalid(format!("{e:#}")),
                    objects_dropped: 0,
                    bytes_freed: 0,
                    dirs_dropped: 0,
                    objects_kept: 0,
                    bytes_kept: 0,
                    errors: 0,
                },
            });
        }
        report.staging_dropped = self.prune_files_staging(dry_run)?;
        for dir in self.files_dirs()? {
            if !policies.iter().any(|(d, _)| *d == dir) {
                let stats = self.files_stats(&dir)?;
                report.unpoliced.push((dir, stats));
            }
        }
        Ok(report)
    }
}

/// Time since the file's mtime; future timestamps have zero idle age.
fn idle(now: SystemTime, meta: &std::fs::Metadata) -> Duration {
    meta.modified()
        .ok()
        .and_then(|m| now.duration_since(m).ok())
        .unwrap_or(Duration::ZERO)
}

/// Bucket idle ages by minute below one day, then by hour. Keys increase with age; the
/// histogram stores no per-object data.
fn bucket(idle: Duration) -> u64 {
    let s = idle.as_secs();
    if s < 86_400 {
        s / 60
    } else {
        1440 + (s - 86_400) / 3600
    }
}

/// Objects and bytes per idle-age bucket.
#[derive(Default)]
struct Histogram(BTreeMap<u64, (u64, u64)>);

impl Histogram {
    fn add(&mut self, idle: Duration, len: u64) {
        let e = self.0.entry(bucket(idle)).or_insert((0, 0));
        e.0 += 1;
        e.1 += len;
    }
    fn objects(&self) -> u64 {
        self.0.values().map(|v| v.0).sum()
    }
    fn bytes(&self) -> u64 {
        self.0.values().map(|v| v.1).sum()
    }
}

/// Remove all objects older than `bucket`. Within it, remove everything if `partial` is None,
/// or enough objects to reclaim `partial` bytes. Order within a bucket is unspecified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cutoff {
    bucket: u64,
    partial: Option<u64>,
}

/// Start with the TTL cutoff, then lower it as needed to meet the size cap. Remove only the
/// excess bytes from the final bucket. Return None if no eviction is needed.
fn cutoff(ages: &Histogram, policy: &FilesPolicy) -> Option<Cutoff> {
    let mut cutoff = policy.ttl.map(|t| Cutoff {
        bucket: bucket(t),
        partial: None,
    });
    if let Some(cap) = policy.max_bytes {
        let mut kept: u64 = ages
            .0
            .iter()
            .filter(|(k, _)| cutoff.is_none_or(|c| **k < c.bucket))
            .map(|(_, v)| v.1)
            .sum();
        for (k, (_, bytes)) in ages.0.iter().rev() {
            if kept <= cap {
                break;
            }
            if cutoff.is_some_and(|c| *k >= c.bucket) {
                continue;
            }
            let over = kept - cap;
            kept -= bytes;
            cutoff = Some(Cutoff {
                bucket: *k,
                partial: (over < *bytes).then_some(over),
            });
        }
    }
    cutoff
}

/// The write walk.
struct Writer<'a> {
    now: SystemTime,
    cutoff: Cutoff,
    dry_run: bool,
    report: &'a mut DirSweep,
}

impl Writer<'_> {
    /// Check whether to evict an object and consume the partial bucket's byte allowance.
    fn drops(&mut self, key: u64, len: u64) -> bool {
        if key > self.cutoff.bucket {
            return true;
        }
        if key < self.cutoff.bucket {
            return false;
        }
        match &mut self.cutoff.partial {
            None => true,
            Some(left) if *left > 0 => {
                *left = left.saturating_sub(len);
                true
            }
            Some(_) => false,
        }
    }
}

impl Writer<'_> {
    /// Sweep a directory and return its remaining entry count. Treat directories beyond the DAV
    /// depth limit as occupied and leave them untouched.
    fn sweep_dir(&mut self, dir: &Path, depth: usize) -> usize {
        if depth > crate::dav::MAX_DEPTH {
            return 1;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut remaining = 0;
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if self.sweep_dir(&path, depth + 1) == 0 {
                    if self.dry_run || remove_dir(&path) {
                        self.report.dirs_dropped += 1;
                        continue;
                    }
                    self.report.errors += 1;
                }
                remaining += 1;
            } else if meta.is_file() {
                if self.drops(bucket(idle(self.now, &meta)), meta.len()) {
                    if self.dry_run || remove_file(&path) {
                        self.report.objects_dropped += 1;
                        self.report.bytes_freed += meta.len();
                        continue;
                    }
                    self.report.errors += 1;
                }
                self.report.objects_kept += 1;
                self.report.bytes_kept += meta.len();
                remaining += 1;
            } else {
                // Preserve unexpected entry types and their parent directory.
                remaining += 1;
            }
        }
        remaining
    }
}

/// Unlink, treating "already gone" as done: a concurrent `gc`, a client's `DELETE`.
fn remove_file(path: &Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

/// Remove an empty directory, treating "already gone" as done and "not empty any more" —
/// a `PUT` landed between the walk and here — as not done.
fn remove_dir(path: &Path) -> bool {
    match std::fs::remove_dir(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

/// Run on the first tick, a policy-directory mtime change, or after [`SWEEP_INTERVAL`].
#[derive(Debug, Default)]
pub(crate) struct SweepClock {
    last_pass: Option<Instant>,
    policy_mtime: Option<SystemTime>,
}

impl SweepClock {
    pub(crate) fn due(&self, now: Instant, policy_mtime: Option<SystemTime>) -> bool {
        match self.last_pass {
            None => true,
            Some(last) => {
                now.duration_since(last) >= SWEEP_INTERVAL || policy_mtime != self.policy_mtime
            }
        }
    }

    pub(crate) fn passed(&mut self, now: Instant, policy_mtime: Option<SystemTime>) {
        self.last_pass = Some(now);
        self.policy_mtime = policy_mtime;
    }
}

/// `.policy/`'s mtime, which a policy renamed into or out of it changes; `None` when there
/// is no such directory yet.
fn policy_dir_mtime(store: &Store) -> Option<SystemTime> {
    std::fs::metadata(store.files_policy_dir())
        .and_then(|m| m.modified())
        .ok()
}

/// Check [`SweepClock::due`] every [`SWEEP_TICK`] and sweep in spawn_blocking. Log failed
/// passes and retry on the next tick. Log unpoliced directories only when the set changes;
/// unchanged passes produce no eviction log.
pub(crate) async fn sweep_files_forever(store: Arc<Store>) {
    let mut ticks = tokio::time::interval(SWEEP_TICK);
    let mut clock = SweepClock::default();
    let mut unpoliced: Option<Vec<String>> = None;
    loop {
        ticks.tick().await;
        let mtime = policy_dir_mtime(&store);
        if !clock.due(Instant::now(), mtime) {
            continue;
        }
        let s = store.clone();
        let swept = tokio::task::spawn_blocking(move || s.sweep_files_once(false)).await;
        clock.passed(Instant::now(), mtime);
        match swept {
            Ok(Ok(report)) => {
                for line in report.lines(false) {
                    eprintln!("vk-registry: {line}");
                }
                let now: Vec<String> = report.unpoliced.iter().map(|(d, _)| d.clone()).collect();
                if unpoliced.as_ref() != Some(&now) {
                    if let Some(line) = report.unpoliced_line() {
                        eprintln!("vk-registry: {line}");
                    }
                    unpoliced = Some(now);
                }
            }
            Ok(Err(e)) => eprintln!("vk-registry: sweeping files/: {e:#}"),
            Err(e) => eprintln!("vk-registry: the files/ sweep did not run: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn days(n: u64) -> Duration {
        Duration::from_secs(n * 86_400)
    }

    fn hist(entries: &[(Duration, u64)]) -> Histogram {
        let mut h = Histogram::default();
        for (idle, len) in entries {
            h.add(*idle, *len);
        }
        h
    }

    /// Buckets are a minute wide under a day and an hour wide past it, and never go
    /// backwards as idleness grows.
    #[test]
    fn buckets_are_monotonic_and_coarsen_past_a_day() {
        assert_eq!(bucket(Duration::ZERO), 0);
        assert_eq!(bucket(Duration::from_secs(59)), 0);
        assert_eq!(bucket(Duration::from_secs(60)), 1);
        assert_eq!(bucket(days(1) - Duration::from_secs(1)), 1439);
        assert_eq!(bucket(days(1)), 1440);
        assert_eq!(bucket(days(1) + Duration::from_secs(3599)), 1440);
        assert_eq!(bucket(days(1) + Duration::from_secs(3600)), 1441);
        assert_eq!(bucket(days(30)), 1440 + 29 * 24);
        let mut last = 0;
        for s in (0..200_000).step_by(37) {
            let b = bucket(Duration::from_secs(s));
            assert!(b >= last, "{s}s: {b} < {last}");
            last = b;
        }
    }

    /// Test TTL, size cap, combined limits and no eviction.
    #[test]
    fn the_cutoff_is_the_ttl_lowered_until_the_cap_fits() {
        let ages = hist(&[
            (Duration::from_secs(0), 1000),
            (days(1), 1000),
            (days(2), 1000),
            (days(3), 1000),
            (days(40), 1000),
        ]);
        let ttl = |d| FilesPolicy {
            ttl: Some(days(d)),
            max_bytes: None,
        };
        let cap = |n| FilesPolicy {
            ttl: None,
            max_bytes: Some(n),
        };
        let whole = |b| {
            Some(Cutoff {
                bucket: b,
                partial: None,
            })
        };
        // TTL alone: everything idle 30 days or more.
        assert_eq!(cutoff(&ages, &ttl(30)), whole(bucket(days(30))));
        // TTL of zero: everything.
        assert_eq!(cutoff(&ages, &ttl(0)), whole(0));
        // Cap alone: the idlest go until 2500 fit — the two freshest survive, and of the
        // two-day bucket only the 500 bytes still over the cap need to go (which takes
        // its one 1000-byte object).
        assert_eq!(
            cutoff(&ages, &cap(2500)),
            Some(Cutoff {
                bucket: bucket(days(2)),
                partial: Some(500)
            })
        );
        // A cap everything fits under drops nothing.
        assert_eq!(cutoff(&ages, &cap(5000)), None);
        // Both: the TTL takes the 40-day object; 4000 is still over 2500, so the cap
        // lowers the cutoff to two days.
        assert_eq!(
            cutoff(
                &ages,
                &FilesPolicy {
                    ttl: Some(days(30)),
                    max_bytes: Some(2500)
                }
            ),
            Some(Cutoff {
                bucket: bucket(days(2)),
                partial: Some(500)
            })
        );
        // Both, with the TTL alone bringing it under the cap: the cutoff stays the TTL's.
        assert_eq!(
            cutoff(
                &ages,
                &FilesPolicy {
                    ttl: Some(days(30)),
                    max_bytes: Some(4000)
                }
            ),
            whole(bucket(days(30)))
        );
        // A cap nothing can meet — every object is bigger — reaches the freshest bucket
        // still 500 bytes over; its one 1000-byte object goes, and the directory empties.
        assert_eq!(
            cutoff(&ages, &cap(500)),
            Some(Cutoff {
                bucket: 0,
                partial: Some(500)
            })
        );
        // Nothing there, nothing to cut.
        assert_eq!(cutoff(&Histogram::default(), &cap(1)), None);
    }

    /// Several objects written within one minute share a bucket. A cap that lands in that
    /// bucket takes only as many of them as it needs, not the whole minute.
    #[test]
    fn a_cap_inside_one_bucket_takes_only_what_it_needs() {
        let dir = tmp("partial");
        let store = Store::new(dir.clone()).unwrap();
        for name in ["a", "b", "c"] {
            object(&store, &format!("p/{name}"), 2048, Duration::ZERO);
        }
        object(&store, "p/old1", 2048, days(10));
        object(&store, "p/old2", 2048, days(11));
        let r = store
            .sweep_files(
                "p",
                &FilesPolicy {
                    ttl: None,
                    max_bytes: Some(5000),
                },
                false,
            )
            .unwrap();
        assert_eq!(r.objects_dropped, 3, "{r:?}");
        assert_eq!(r.objects_kept, 2);
        assert_eq!(r.bytes_kept, 4096);
        let p = store.files_dir().join("p");
        assert!(!p.join("old1").exists() && !p.join("old2").exists());
        assert_eq!(std::fs::read_dir(&p).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vk-registry-files-sweep-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// Write an object of `len` bytes with its mtime set back by `age`.
    fn object(store: &Store, rel: &str, len: usize, age: Duration) -> std::path::PathBuf {
        let path = store.files_dir().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![0u8; len]).unwrap();
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
        path
    }

    fn ttl_policy(d: u64) -> FilesPolicy {
        FilesPolicy {
            ttl: Some(days(d)),
            max_bytes: None,
        }
    }

    /// TTL removes stale objects only in directories with policies. Dry runs report the same
    /// counts without deleting.
    #[test]
    fn the_ttl_drops_idle_objects_in_policed_directories_only() {
        let dir = tmp("ttl");
        let store = Store::new(dir.clone()).unwrap();
        let old_a = object(&store, "a/x/old", 100, days(2));
        let fresh_a = object(&store, "a/y/fresh", 100, Duration::from_secs(60));
        let old_b = object(&store, "b/old", 100, days(2));
        store.write_files_policy("a", Some(&ttl_policy(1))).unwrap();

        let dry = store.sweep_files_once(true).unwrap();
        assert_eq!(dry.dirs.len(), 1);
        let a = &dry.dirs[0];
        assert_eq!(a.dir, "a");
        assert_eq!(a.policy, PolicyState::Applied(ttl_policy(1)));
        assert_eq!((a.objects_dropped, a.bytes_freed), (1, 100));
        assert_eq!((a.objects_kept, a.bytes_kept), (1, 100));
        assert_eq!(a.dirs_dropped, 1, "x/ would be left empty");
        assert!(old_a.is_file(), "a dry run removes nothing");
        assert_eq!(dry.unpoliced.len(), 1);
        assert_eq!(dry.unpoliced[0].0, "b");
        assert_eq!(dry.unpoliced[0].1.bytes, 100);
        assert!(dry.lines(true)[0].contains("would drop 1 object(s)"));
        assert!(
            dry.unpoliced_line()
                .unwrap()
                .contains("b (100 B in 1 object(s))")
        );

        let wet = store.sweep_files_once(false).unwrap();
        assert_eq!(wet.dirs, dry.dirs, "the dry run predicted the pass");
        assert!(!old_a.exists());
        assert!(
            !old_a.parent().unwrap().exists(),
            "the emptied x/ went with it"
        );
        assert!(fresh_a.is_file());
        assert!(old_b.is_file(), "no policy, no sweep");
        assert!(store.files_dir().join("a").is_dir(), "the top level stays");
        assert!(wet.lines(false)[0].starts_with("files/a: dropped 1 object(s) (100 B) and 1 directory(ies); 1 object(s) (100 B) kept [policy 1d]"));

        // Nothing left to do: a pass that changes nothing says nothing.
        let quiet = store.sweep_files_once(false).unwrap();
        assert!(quiet.lines(false).is_empty(), "{:?}", quiet.lines(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Keep the two newest objects under the cap. A zero TTL removes all objects and empty
    /// shards, preserving the top-level directory.
    #[test]
    fn the_cap_keeps_the_freshest_and_a_zero_ttl_empties() {
        let dir = tmp("cap");
        let store = Store::new(dir.clone()).unwrap();
        let hour = Duration::from_secs(3600);
        for (i, age) in [0u32, 1, 2, 3, 4]
            .iter()
            .map(|h| (*h, *h * hour))
            .collect::<Vec<_>>()
        {
            object(&store, &format!("c/{i:02}/obj"), 1024, age);
        }
        let policy = FilesPolicy {
            ttl: None,
            max_bytes: Some(2500),
        };
        let r = store.sweep_files("c", &policy, false).unwrap();
        assert_eq!(r.objects_dropped, 3);
        assert_eq!(r.bytes_freed, 3 * 1024);
        assert_eq!(r.objects_kept, 2);
        assert!(r.bytes_kept <= 2500);
        assert_eq!(r.dirs_dropped, 3);
        let c = store.files_dir().join("c");
        assert!(c.join("00/obj").is_file());
        assert!(c.join("01/obj").is_file());
        for gone in ["02", "03", "04"] {
            assert!(!c.join(gone).exists(), "{gone}");
        }

        let r = store.sweep_files("c", &ttl_policy(0), false).unwrap();
        assert_eq!(r.objects_dropped, 2);
        assert_eq!(r.dirs_dropped, 2);
        assert_eq!(std::fs::read_dir(&c).unwrap().count(), 0);
        assert!(c.is_dir(), "the top level is the policy's, not the sweep's");
        // A missing directory is an empty one.
        let r = store.sweep_files("nothing", &ttl_policy(0), false).unwrap();
        assert_eq!(r.objects_dropped + r.objects_kept, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Prune day-old staging files on every pass, even without policies; keep recent files.
    #[test]
    fn abandoned_staging_files_are_pruned_without_any_policy() {
        let dir = tmp("staging");
        let store = Store::new(dir.clone()).unwrap();
        let dead = object(
            &store,
            ".staging/1-1",
            10,
            STAGING_GRACE + Duration::from_secs(3600),
        );
        let live = object(&store, ".staging/1-2", 10, Duration::from_secs(3600));
        let r = store.sweep_files_once(false).unwrap();
        assert_eq!(r.staging_dropped, 1);
        assert!(!dead.exists());
        assert!(live.is_file());
        assert_eq!(
            r.lines(false),
            ["files/.staging: dropped 1 abandoned upload(s)"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Report invalid policies without sweeping their directories; continue applying valid
    /// policies.
    #[test]
    fn an_invalid_policy_fails_closed_and_is_reported() {
        let dir = tmp("invalid");
        let store = Store::new(dir.clone()).unwrap();
        let old_a = object(&store, "a/old", 100, days(400));
        let old_b = object(&store, "b/old", 100, days(400));
        std::fs::create_dir_all(store.files_policy_dir()).unwrap();
        std::fs::write(
            store.files_policy_dir().join("a.toml"),
            "ttl_days = \"soon\"\n",
        )
        .unwrap();
        store
            .write_files_policy("b", Some(&ttl_policy(30)))
            .unwrap();

        let r = store.sweep_files_once(false).unwrap();
        assert_eq!(r.dirs.len(), 2);
        assert!(
            matches!(r.dirs[0].policy, PolicyState::Invalid(_)),
            "{:?}",
            r.dirs[0]
        );
        assert_eq!(r.dirs[0].objects_dropped, 0);
        assert!(
            old_a.is_file(),
            "an unreadable policy lifts no cap and drops nothing"
        );
        assert!(!old_b.exists());
        assert!(r.unpoliced.is_empty(), "a has a policy file, however bad");
        let lines = r.lines(false);
        assert!(
            lines[0].starts_with("files/a: policy not applied: "),
            "{lines:?}"
        );
        assert!(
            lines[1].starts_with("files/b: dropped 1 object(s)"),
            "{lines:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reload policy changes on the next pass.
    #[test]
    fn a_changed_policy_applies_on_the_next_pass() {
        let dir = tmp("change");
        let store = Store::new(dir.clone()).unwrap();
        let obj = object(&store, "a/obj", 100, days(10));
        store
            .write_files_policy("a", Some(&ttl_policy(30)))
            .unwrap();
        assert_eq!(
            store.sweep_files_once(false).unwrap().dirs[0].objects_dropped,
            0
        );
        assert!(obj.is_file());
        store.write_files_policy("a", Some(&ttl_policy(7))).unwrap();
        assert_eq!(
            store.sweep_files_once(false).unwrap().dirs[0].objects_dropped,
            1
        );
        assert!(!obj.exists());
        // Clearing the policy disables eviction.
        let obj = object(&store, "a/obj", 100, days(10));
        store.write_files_policy("a", None).unwrap();
        let r = store.sweep_files_once(false).unwrap();
        assert!(r.dirs.is_empty());
        assert_eq!(r.unpoliced.len(), 1);
        assert!(obj.is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The loop's three triggers, and the quiet case.
    #[test]
    fn a_pass_is_due_at_start_on_a_policy_change_and_hourly() {
        let t0 = Instant::now();
        let m1 = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
        let m2 = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(2));
        let mut clock = SweepClock::default();
        assert!(clock.due(t0, None), "the first tick runs");
        clock.passed(t0, None);
        assert!(!clock.due(t0 + SWEEP_TICK, None), "nothing changed");
        assert!(clock.due(t0 + SWEEP_TICK, m1), ".policy/ appeared");
        clock.passed(t0 + SWEEP_TICK, m1);
        assert!(!clock.due(t0 + 2 * SWEEP_TICK, m1));
        assert!(clock.due(t0 + 2 * SWEEP_TICK, m2), "a policy was written");
        clock.passed(t0 + 2 * SWEEP_TICK, m2);
        assert!(!clock.due(t0 + 2 * SWEEP_TICK + SWEEP_INTERVAL - SWEEP_TICK, m2));
        assert!(
            clock.due(t0 + 2 * SWEEP_TICK + SWEEP_INTERVAL, m2),
            "an hour passed"
        );
    }
}
