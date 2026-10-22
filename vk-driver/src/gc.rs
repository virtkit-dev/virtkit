//! `vk gc`: reclaim unused, recreatable host caches. Summarize what was removed, what was
//! kept and why, and the change in free space on each filesystem.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::Config;
use crate::usage::fmt_bytes;

/// What a `vk gc` pass may take.
pub(crate) struct Request {
    /// Count what would go and remove nothing.
    pub(crate) dry_run: bool,
    /// How long a materialized base must sit unused.
    pub(crate) image_idle: Duration,
    /// How long a host checkout must sit unused.
    pub(crate) checkout_idle: Duration,
}

/// Run a pass over the image tiers under `state_dir` (the one `vk run` caches under) and the
/// executor's checkouts.
pub(crate) fn run(cfg: &Config, state_dir: &Path, req: &Request) -> Summary {
    let checkout_root = cfg.checkout_root();
    let mut sum = Summary::new(req.dry_run, &[state_dir, &checkout_root]);

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
    sum.finish();
    sum
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
