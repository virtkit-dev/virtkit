//! Host side of the per-job guest statistics recording (`[gitlab] atop`).
//!
//! A CI job gets its own microVM, so the guest is the job: the in-guest agent samples
//! its own `/proc` and appends the samples in the text format `atop -P` prints (the schema
//! both sides speak is `vk_core::atop`). This module owns the host's half — where the log
//! lands, and how the guest is told to write it:
//!
//! * `prepare` creates this job's archive directory under `<state_dir>/atop/<date>/`
//!   and records its path in the job dir — and, on the day's first recorded job, drops
//!   the days past the retention window;
//! * `supervise` shares that directory into the guest read-write and puts
//!   [`vk_core::atop::cmdline_knob`] on the guest cmdline, which names the share and the
//!   interval.
//!
//! Only the job's own directory is shared, so what guest root can reach is that directory:
//! it can corrupt its own log, fill the directory, or leave a symlink where the log should
//! be. Nothing outside it is exposed, and a reader of the log has to open it without
//! following symlinks. Everything here is best effort: a job whose stats cannot be recorded
//! still runs.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use vk_core::atop::{LOG_NAME, date_dir, day_of, now_epoch, parse_date_dir};

use crate::config::{Config, Gitlab};
use crate::jobctx::JobCtx;

/// Whether this host records what its jobs' guests do (`[gitlab] atop`, on by
/// default). Off for a host with no `[gitlab]` table at all: it runs no executor.
pub fn enabled(cfg: &Config) -> bool {
    cfg.gitlab.as_ref().is_some_and(|g| g.atop)
}

/// The configured sampling interval. An interval of zero would have the guest sampling
/// without pause, so it is rejected here — where the error names the setting — rather
/// than clamped to something the operator did not ask for.
pub fn interval_secs(cfg: &Config) -> Result<u64> {
    // A host with no [gitlab] table configured nothing, so it gets the default rather than a
    // zero that would name a setting the operator never wrote.
    let secs = cfg.gitlab.as_ref().map_or_else(
        || Gitlab::default().atop_interval_secs,
        |g| g.atop_interval_secs,
    );
    if secs == 0 {
        bail!("[gitlab] atop_interval_secs must be at least 1 second (got 0)");
    }
    Ok(secs)
}

/// How many days of recorded jobs the archive keeps (`[gitlab] atop_retention_days`).
pub fn retention_days(cfg: &Config) -> u64 {
    // A host with no [gitlab] table configured nothing, so it gets the default rather than a
    // zero that would read as an explicit "keep only today".
    cfg.gitlab.as_ref().map_or_else(
        || Gitlab::default().atop_retention_days,
        |g| g.atop_retention_days,
    )
}

/// How the retention window reads in a report. `0` still keeps what is being recorded now, so
/// it is not "kept 0 days" — and one day is not "1 days".
pub fn retention_note(cfg: &Config) -> String {
    match retention_days(cfg) {
        0 => "today's only".to_string(),
        1 => "kept 1 day back".to_string(),
        d => format!("kept {d} days back"),
    }
}

/// Every job's archive on this host, one directory per day inside it. Shared by every
/// runner using this state dir, and outside the job dirs on purpose: a job's own dir is
/// wiped by its prepare and removed at cleanup, while the log outlives the job.
pub fn archive_root(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("atop")
}

/// Where this job's log goes: `<archive root>/<YYYY-MM-DD>/<job>`. The date groups a
/// day's jobs into one directory, which is the unit the retention window drops.
pub fn archive_dir(ctx: &JobCtx, date: &str) -> PathBuf {
    archive_root(&ctx.cfg).join(date).join(ctx.atop_component())
}

/// Create this job's archive directory and record its path in the job dir, where
/// `supervise` (a separate process) reads it and the final stage finds the log to
/// report. Returns the directory.
///
/// A directory already there was prepared by this same job id — a re-`prepare` of the run,
/// not a second CI run of the job — and is replaced: the job about to boot is the one the
/// log describes.
pub fn prepare_archive(ctx: &JobCtx) -> Result<PathBuf> {
    let dir = archive_dir(ctx, &today());
    // Removed without first asking whether it is there: one syscall settles it, where a
    // probe and a removal are two answers about a path that can change in between.
    if let Err(e) = std::fs::remove_dir_all(&dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(e).with_context(|| format!("removing stale {}", dir.display()));
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let marker = ctx.atop_dir_file();
    // The path in its own bytes: a state dir that is not UTF-8 has to come back as the
    // directory it is, not as a lossy rendering of one.
    std::fs::write(&marker, dir.as_os_str().as_bytes())
        .with_context(|| format!("writing {}", marker.display()))?;
    Ok(dir)
}

/// The archive directory prepare created for this job, or `None` where it recorded
/// none (recording off, or a prepare that could not create it).
pub fn job_archive_dir(ctx: &JobCtx) -> Option<PathBuf> {
    let raw = std::fs::read(ctx.atop_dir_file()).ok()?;
    // Only a trailing newline comes off; a path's own spaces are part of it.
    let bytes = raw.strip_suffix(b"\n").unwrap_or(&raw);
    (!bytes.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

/// Sweep the archive once a day rather than once a job: the first job recorded today has no
/// directory for today yet, and the sweep it runs is the one that day needs. A sweep per job
/// would charge every job on a busy runner for a recursive removal of trees that earlier
/// jobs' guests filled, on the path where the job is waiting to boot.
///
/// Tied to recording being on, so `[gitlab] atop = false` stops the reclamation with it: an
/// archive already on disk then stays until it is removed by hand.
pub fn prune_archive_daily(cfg: &Config) {
    prune_archive_daily_as_of(cfg, now_epoch());
}

/// [`prune_archive_daily`] against a given clock, so both the trigger and the window are read
/// from one instant — a test pins it, and a sweep never straddles midnight between the two.
fn prune_archive_daily_as_of(cfg: &Config, now: i64) {
    let root = archive_root(cfg);
    if root.join(date_dir(now)).exists() {
        return;
    }
    prune_archive_as_of(&root, retention_days(cfg), day_of(now));
}

/// The log `target` names, for `vk gitlab atop` to print — so a viewer can be pointed
/// straight at it (`less $(vk gitlab atop 42137)`).
///
/// A target carrying a path separator is that path (a log, or the directory holding one), so
/// the path a job's trace printed can be handed straight back. Anything else selects from the
/// recorded jobs: all digits is a job id, answering only for the id a directory name leads
/// with, and anything else is a substring of a job's or project's name — the newest run
/// answering, since the reason to name a job by its name rather than its id is to ask about
/// the last run of it.
pub fn resolve(cfg: &Config, target: &str) -> Result<PathBuf> {
    let root = archive_root(cfg);
    // A host that records nothing has no archive to search, which is worth saying plainly:
    // the alternative is an ENOENT on a path the operator never configured.
    if !root.exists() && !enabled(cfg) {
        bail!("nothing recorded on this host (`[gitlab] atop` is off)");
    }
    resolve_in(&root, target)
}

/// A regular `atop.log` in `dir`, and when it was last written. A symlink — or anything else
/// where the log goes — is not a recording this host wrote: guest root can reach its own
/// archive directory (see the module docs), and the path printed here goes straight to a
/// reader that would follow it.
fn recorded_log(dir: &Path) -> Option<(std::time::SystemTime, PathBuf)> {
    let log = dir.join(LOG_NAME);
    let md = std::fs::symlink_metadata(&log).ok()?;
    if !md.is_file() {
        eprintln!(
            "virtkit: warning: {} is not a regular file; not a recording",
            log.display()
        );
        return None;
    }
    Some((md.modified().unwrap_or(std::time::UNIX_EPOCH), log))
}

/// Whether a job's directory name — `<id>-<project>-<job name>` — answers to `target`: the
/// leading id exactly where the target is all digits, so job 42137 is not what `42` asked
/// for, and a substring of the name otherwise.
fn job_dir_answers(name: &std::ffi::OsStr, target: &str) -> bool {
    // A name this host did not write is not one of its jobs; matching a lossy rendering of
    // one would match on bytes that are not there.
    let Some(name) = name.to_str() else {
        return false;
    };
    match target.bytes().all(|b| b.is_ascii_digit()) {
        true => name.split('-').next() == Some(target),
        false => name.contains(target),
    }
}

/// The job a run belongs to, as distinct from the run: the directory name without the id that
/// leads it, so two runs of one job read as the same job and two different jobs do not.
fn job_identity(name: &str) -> &str {
    name.split_once('-').map_or(name, |(_, rest)| rest)
}

/// Say on stderr when a name fragment answered for more than one job. "The newest run" is the
/// right answer for repeated runs of one job, which is what a fragment usually names; when it
/// spans different jobs, the one chosen is an accident of which ran last. Stderr, so the path
/// on stdout still composes with whatever reads it.
fn note_other_jobs(
    target: &str,
    chosen: &std::ffi::OsStr,
    matches: &[(std::time::SystemTime, std::ffi::OsString, PathBuf)],
) {
    let job_of = |name: &std::ffi::OsStr| name.to_str().map(|n| job_identity(n).to_string());
    let Some(mine) = job_of(chosen) else {
        return;
    };
    let mut others: Vec<String> = matches
        .iter()
        .filter_map(|(_, name, _)| job_of(name))
        .filter(|job| *job != mine)
        .collect();
    others.sort();
    others.dedup();
    if !others.is_empty() {
        eprintln!(
            "virtkit: note: {target:?} also matches {} — answering for {mine}",
            others.join(", ")
        );
    }
}

fn resolve_in(root: &Path, target: &str) -> Result<PathBuf> {
    if target.is_empty() {
        bail!("name a job: an id, or part of a recorded job's name");
    }
    // A separator makes it a path. A bare word is a job to look up in the archive — never
    // whatever the operator's working directory happens to hold under that name.
    if target.contains('/') {
        let path = Path::new(target);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return recorded_log(path)
            .map(|(_, log)| log)
            .with_context(|| format!("no {LOG_NAME} under {}", path.display()));
    }
    // Newest day first, and inside a day the log written last: two runs of one job on one day
    // differ by when they ran, which their ids order only numerically — as the names they
    // lead, they are strings of different lengths.
    let mut days: Vec<(i64, PathBuf)> = std::fs::read_dir(root)
        .with_context(|| format!("reading the stats archive {}", root.display()))?
        .flatten()
        // A real directory, as the sweep requires: a file or a symlink named like a day is
        // not a day of recordings, whoever parked it here.
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| {
            let day = parse_date_dir(e.file_name().to_str()?)?;
            Some((day, e.path()))
        })
        .collect();
    days.sort_by_key(|(day, _)| std::cmp::Reverse(*day));
    for (_, day) in &days {
        // A day that cannot be read is not an older day's run: answering with a different job
        // than the one asked for is worse than saying the archive could not be read.
        let entries =
            std::fs::read_dir(day).with_context(|| format!("reading {}", day.display()))?;
        let mut matches: Vec<(std::time::SystemTime, std::ffi::OsString, PathBuf)> = entries
            .flatten()
            .filter(|e| job_dir_answers(&e.file_name(), target))
            .filter_map(|e| recorded_log(&e.path()).map(|(at, log)| (at, e.file_name(), log)))
            .collect();
        if matches.is_empty() {
            continue;
        }
        // Newest first, and the job id the name leads with settles a tie in the mtimes, so
        // one archive always answers the same way.
        matches.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let (_, chosen, log) = &matches[0];
        note_other_jobs(target, chosen, &matches);
        return Ok(log.clone());
    }
    bail!(
        "no recorded job matches {target:?} in {} (a job id, or part of a recorded job's \
         directory name; the archive keeps only the last `[gitlab] atop_retention_days` days)",
        root.display()
    );
}

/// Drop the days the retention window has passed, so a busy runner's archive stays
/// bounded with nobody sweeping it. Each date directory is one day of recorded jobs and
/// goes whole; a directory exactly `days` old is still inside the window and stays.
///
/// Only a directory whose name is one of the days this archive writes is considered, so a
/// file, a symlink, or a directory named anything else is left where the operator put it.
///
/// Best effort: a day that will not go — a permission problem, or another runner's sweep
/// already removing it — is left for the next sweep. No lock is taken for that reason: two
/// runners sweeping the same root want the same outcome, and the loser of the race has
/// nothing left to do.
///
/// A day goes whether or not a guest still holds its log open — unlinking one succeeds — so a
/// job that outlives the window loses the recording it is in the middle of writing. The
/// default window covers every job shorter than a fortnight; `atop_retention_days = 0` gives
/// that up for any job running past midnight, and a short window for any job outliving it.
///
/// `today` is passed in rather than read here, so one sweep judges every day in the archive
/// against one instant — and a test pins the window's boundary instead of racing the clock.
fn prune_archive_as_of(root: &Path, days: u64, today: i64) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return; // unreadable or not there yet: nothing this sweep can reclaim
    };
    // The oldest day still inside the window; a day exactly `days` old is one of them. An
    // absurd `days` saturates towards keeping everything, never towards dropping it.
    let keep_from = today.saturating_sub_unsigned(days);
    for entry in entries.flatten() {
        // A real directory, whatever its name: a file or a symlink an operator parked in the
        // archive is not a day of recordings and is not this sweep's to remove.
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        let Some(day) = name.to_str().and_then(parse_date_dir) else {
            continue;
        };
        if day >= keep_from {
            continue;
        }
        let dir = entry.path();
        // Already gone is a concurrent runner's sweep having got there first, which is the
        // outcome this one wanted.
        if let Err(e) = std::fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "virtkit: warning: could not drop expired stats archive {}: {e}",
                dir.display()
            );
        }
    }
}

/// The archive directory name for the day a job recorded now lands in.
fn today() -> String {
    date_dir(now_epoch())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn recording_is_on_for_an_executor_host_and_off_without_one() {
        let mut cfg = Config::default();
        assert!(!enabled(&cfg), "no [gitlab] table: no executor here");
        cfg.gitlab = Some(Gitlab::default());
        assert!(enabled(&cfg), "on by default once the executor is set up");
        assert_eq!(interval_secs(&cfg).unwrap(), 10);
        assert_eq!(retention_days(&cfg), 14);
        // Neither figure is read off a host that configured nothing: the default window, not
        // a zero that would sweep everything but today.
        assert_eq!(retention_days(&Config::default()), 14);
        assert_eq!(interval_secs(&Config::default()).unwrap(), 10);

        cfg.gitlab = Some(Gitlab {
            atop: false,
            ..Default::default()
        });
        assert!(!enabled(&cfg));

        // A zero interval would have the guest sampling in a loop: name the setting.
        cfg.gitlab = Some(Gitlab {
            atop_interval_secs: 0,
            ..Default::default()
        });
        let e = interval_secs(&cfg).expect_err("zero is rejected");
        assert!(format!("{e:#}").contains("atop_interval_secs"), "{e:#}");
    }

    /// A recorded job is found by its id or by any part of its name, the newest run
    /// answering; and a path that already exists is taken as it is, so what a job trace
    /// printed can be handed straight back.
    #[test]
    fn a_recorded_job_is_found_by_id_or_by_name() {
        let state = std::env::temp_dir().join(format!("vk-atop-resolve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        // The archive as a state dir holds it, so the lookup can be reached through a config
        // as well as directly.
        let root = state.join("atop");
        let record = |date: &str, job: &str| {
            let dir = root.join(date).join(job);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(LOG_NAME), b"RESET\nSEP\n").unwrap();
            dir.join(LOG_NAME)
        };
        let old = record("2026-08-09", "41000-acme-web-test_unit");
        let new = record("2026-08-11", "42137-acme-web-test_unit");
        let other = record("2026-08-11", "42140-acme-api-build");
        // A job whose guest died before writing anything is not an answer.
        std::fs::create_dir_all(root.join("2026-08-12").join("42200-acme-web-test_unit")).unwrap();

        // By job id, exactly this run.
        assert_eq!(resolve_in(&root, "41000").unwrap(), old);
        assert_eq!(resolve_in(&root, "42140").unwrap(), other);
        // By name: the newest day that has a run of it, skipping the empty one.
        assert_eq!(resolve_in(&root, "test_unit").unwrap(), new);
        assert_eq!(resolve_in(&root, "acme-api").unwrap(), other);

        // An existing log, and the directory holding one.
        assert_eq!(resolve_in(&root, &old.to_string_lossy()).unwrap(), old);
        assert_eq!(
            resolve_in(&root, &old.parent().unwrap().to_string_lossy()).unwrap(),
            old
        );

        // Nothing matching, an empty archive, and a directory with no log: each says so.
        for bad in ["nosuchjob", "42200"] {
            let e = resolve_in(&root, bad).expect_err(bad);
            assert!(format!("{e:#}").contains("no recorded job"), "{e:#}");
        }
        let empty = root.join("2026-08-12").join("42200-acme-web-test_unit");
        let e = resolve_in(&root, &empty.to_string_lossy()).expect_err("no log there");
        assert!(format!("{e:#}").contains(LOG_NAME), "{e:#}");
        // An archive that cannot be read is not "no such job": it names the path it tried.
        let e = resolve_in(&root.join("nope"), "42137").expect_err("no archive there");
        assert!(format!("{e:#}").contains("nope"), "{e:#}");
        // A job id answers only for the id a directory name leads with: a piece of one is a
        // different job, or none.
        for piece in ["42", "137", "4213"] {
            let e = resolve_in(&root, piece).expect_err(piece);
            assert!(
                format!("{e:#}").contains("no recorded job"),
                "{piece}: {e:#}"
            );
        }
        // Named with nothing at all, it asks rather than answering with the newest job here.
        assert!(resolve_in(&root, "").is_err());
        // The lookup is rooted at the archive under the state dir, not at the cwd.
        let cfg = Config {
            state_dir: Some(state.clone()),
            gitlab: Some(Gitlab::default()),
            ..Default::default()
        };
        assert_eq!(archive_root(&cfg), root);
        assert_eq!(resolve(&cfg, "41000").unwrap(), old);
        std::fs::remove_dir_all(&state).unwrap();
    }

    /// Which run of a job answers, when more than one could. The reason to name a job rather
    /// than a run is to ask about the last one, so the log written last wins — and a name that
    /// a guest replaced with a symlink is not a recording at all.
    #[test]
    fn the_newest_run_of_a_job_answers_and_a_planted_log_does_not() {
        let root = std::env::temp_dir().join(format!("vk-atop-newest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let day = root.join("2026-08-11");
        let record = |job: &str, written_at: std::time::SystemTime| {
            let dir = day.join(job);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join(LOG_NAME);
            std::fs::write(&log, b"RESET\nSEP\n").unwrap();
            // Pinned rather than taken from the order they were created in: it is the log's
            // own write time the lookup orders by, and a test that raced it would prove nothing.
            std::fs::File::options()
                .write(true)
                .open(&log)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(written_at))
                .unwrap();
            log
        };
        let epoch = std::time::UNIX_EPOCH;
        let first = record(
            "42137-acme-web-test_unit",
            epoch + Duration::from_secs(1000),
        );
        let second = record(
            "42140-acme-web-test_unit",
            epoch + Duration::from_secs(2000),
        );

        // Two runs of one job on one day: the one whose log was written last.
        assert_eq!(resolve_in(&root, "test_unit").unwrap(), second);
        // Either run still answers exactly to its own id.
        assert_eq!(resolve_in(&root, "42137").unwrap(), first);

        // A fragment spanning two different jobs still answers, by the same rule.
        let integration = record(
            "42150-acme-web-test_integration",
            epoch + Duration::from_secs(3000),
        );
        assert_eq!(resolve_in(&root, "test_").unwrap(), integration);

        // A log the guest replaced with a symlink is not a recording: the run is skipped and
        // the next newest answers, rather than a reader being pointed at the target.
        let planted = day.join("42160-acme-web-test_unit");
        std::fs::create_dir_all(&planted).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", planted.join(LOG_NAME)).unwrap();
        assert_eq!(resolve_in(&root, "test_unit").unwrap(), second);
        let e = resolve_in(&root, "42160").expect_err("a planted log is not a recording");
        assert!(format!("{e:#}").contains("no recorded job"), "{e:#}");

        // A file and a symlink named like a day are not days of recordings, so neither is
        // walked and neither can put the answer outside the archive.
        std::fs::write(root.join("2026-08-12"), b"not a directory").unwrap();
        let outside = root.join("elsewhere");
        std::fs::create_dir_all(outside.join("42999-acme-web-test_unit")).unwrap();
        std::fs::write(
            outside.join("42999-acme-web-test_unit").join(LOG_NAME),
            b"RESET\nSEP\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, root.join("2026-08-13")).unwrap();
        assert_eq!(
            resolve_in(&root, "test_unit").unwrap(),
            second,
            "the answer stays inside the archive"
        );
        assert!(
            resolve_in(&root, "42999").is_err(),
            "not a day of recordings"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The sweep drops whole days once they are past the window, keeps the day that is
    /// exactly at it, and leaves everything that is not a day of recordings alone.
    #[test]
    fn pruning_drops_the_days_past_the_retention_window() {
        let root = std::env::temp_dir().join(format!("vk-atop-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // One instant for the names and for the sweep, so the boundary is still the boundary
        // when the test runs across midnight.
        let now = now_epoch();
        let day = |offset: i64| date_dir(now - offset * 86_400);
        let today = day(0);
        let boundary = day(14);
        let expired = day(15);
        let ancient = day(400);
        for name in [&today, &boundary, &expired, &ancient] {
            // a day holds one directory per job, each holding the job's log
            let job = root.join(name).join("42-proj-build");
            std::fs::create_dir_all(&job).unwrap();
            std::fs::write(job.join(vk_core::atop::LOG_NAME), b"RESET\nSEP\n").unwrap();
        }
        std::fs::create_dir_all(root.join("notes")).unwrap();
        std::fs::write(root.join("README"), b"kept by hand").unwrap();
        // Named like an expired day, but neither is a day of recordings: a file the sweep
        // cannot remove as a directory, and a symlink whose target is not the sweep's to take.
        std::fs::write(root.join(day(30)), b"not a directory").unwrap();
        let outside = root.join("keep-me");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(day(31))).unwrap();

        prune_archive_as_of(&root, 14, day_of(now));

        assert!(root.join(&today).is_dir(), "today is being written");
        assert!(root.join(&boundary).is_dir(), "the boundary day is inside");
        assert!(!root.join(&expired).exists(), "a day past the window goes");
        assert!(!root.join(&ancient).exists());
        assert!(root.join("notes").is_dir(), "not a date, not swept");
        assert!(root.join("README").is_file());
        assert!(root.join(day(30)).is_file(), "a file is not a day of jobs");
        assert!(
            root.join(day(31)).symlink_metadata().is_ok(),
            "a symlink is not a day of jobs"
        );
        assert!(outside.is_dir(), "and its target is untouched");

        // A window of zero keeps only what is being recorded now.
        prune_archive_as_of(&root, 0, day_of(now));
        assert!(root.join(&today).is_dir());
        assert!(!root.join(&boundary).exists());

        // A window no archive could outlive keeps everything, rather than inverting.
        prune_archive_as_of(&root, u64::MAX, day_of(now));
        assert!(root.join(&today).is_dir());

        // An archive that does not exist yet is not an error.
        prune_archive_as_of(&root.join("nope"), 14, day_of(now));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The sweep runs once a day, not once a job: a runner that has already recorded a job
    /// today has swept today, and every later job that day goes straight to booting.
    #[test]
    fn the_sweep_runs_for_the_first_recorded_job_of_the_day() {
        let root = std::env::temp_dir().join(format!("vk-atop-daily-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cfg = Config {
            state_dir: Some(root.clone()),
            gitlab: Some(Gitlab::default()),
            ..Default::default()
        };
        let archive = archive_root(&cfg);
        // One instant for the trigger and the window, so neither call can straddle midnight.
        let now = now_epoch();
        let expired = archive.join(date_dir(now - 30 * 86_400));
        std::fs::create_dir_all(&expired).unwrap();

        // No directory for today yet: this is the day's first recorded job, so it sweeps.
        prune_archive_daily_as_of(&cfg, now);
        assert!(!expired.exists(), "the first job of the day reclaims");

        // That job then records into today's directory, as prepare creates it. With today's
        // directory standing, a later job leaves the archive alone — including a day that
        // expired while the runner was busy.
        std::fs::create_dir_all(archive.join(date_dir(now))).unwrap();
        let stale = archive.join(date_dir(now - 31 * 86_400));
        std::fs::create_dir_all(&stale).unwrap();
        prune_archive_daily_as_of(&cfg, now);
        assert!(stale.is_dir(), "swept once for the day, not once per job");

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The archive is one directory per day of the shared state dir, outside the job dirs
    /// that are wiped when a job ends — and a day's name reads back as the day it is, which
    /// is the only thing the sweep goes by.
    #[test]
    fn the_archive_is_a_dated_directory_under_the_state_dir() {
        let cfg = Config {
            state_dir: Some(PathBuf::from("/var/lib/vk")),
            gitlab: Some(Gitlab::default()),
            ..Default::default()
        };
        assert_eq!(archive_root(&cfg), PathBuf::from("/var/lib/vk/atop"));
        assert_eq!(today(), vk_core::atop::date_dir(vk_core::atop::now_epoch()));
    }

    /// prepare creates the directory and leaves its path where the supervisor and the last
    /// stage — separate processes, which must not each derive a date of their own around
    /// midnight — read it back.
    #[test]
    fn prepare_records_the_directory_it_created() {
        let root = std::env::temp_dir().join(format!("vk-atop-prepare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cfg = Config {
            state_dir: Some(root.clone()),
            gitlab: Some(Gitlab::default()),
            ..Default::default()
        };
        let ctx = JobCtx::new_for_job(cfg, "job1".into()).expect("a job context");
        std::fs::create_dir_all(&ctx.job_dir).unwrap();

        // Nothing recorded yet: no share to mount and no knob on the guest cmdline.
        assert_eq!(job_archive_dir(&ctx), None, "no marker, nothing recorded");

        let dir = prepare_archive(&ctx).expect("the archive directory");
        assert_eq!(dir, archive_dir(&ctx, &today()));
        assert!(dir.is_dir());
        assert_eq!(
            dir.parent().unwrap().parent().unwrap(),
            archive_root(&ctx.cfg)
        );
        // The path is read back exactly, byte for byte — it is what the guest's log is
        // shared from and what the trace names.
        assert_eq!(job_archive_dir(&ctx).as_deref(), Some(dir.as_path()));

        // A log left where this job's directory goes is a previous prepare of the same run:
        // the job about to boot is the one the log describes, so it starts empty.
        let stale = dir.join(vk_core::atop::LOG_NAME);
        std::fs::write(&stale, b"RESET\nSEP\n").unwrap();
        let again = prepare_archive(&ctx).expect("the archive directory");
        assert_eq!(again, dir);
        assert!(again.is_dir());
        assert!(!stale.exists(), "the previous log is not appended to");

        std::fs::remove_dir_all(&root).unwrap();
    }
}
