//! Host side of the per-job guest statistics recording (`[executor] atop`).
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
//!   interval;
//! * `cleanup`, once the guest is gone, compresses the log to [`LOG_ZST_NAME`] beside it
//!   ([`compress_log`]), and the daily sweep does the same for a log a crashed runner left
//!   plain.
//!
//! Only the job's own directory is shared, so what guest root can reach is that directory:
//! it can corrupt its own log, fill the directory, or leave a symlink where the log should
//! be. Nothing outside it is exposed, and a reader of the log has to open it without
//! following symlinks. Everything here is best effort: a job whose stats cannot be recorded
//! still runs.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use vk_core::atop::{LOG_NAME, date_dir, day_of, now_epoch, parse_date_dir};

use crate::config::Config;
use crate::jobctx::JobCtx;

/// A finished job's log, compressed, where [`LOG_NAME`] was. Only the host writes it, once the
/// guest is gone; the guest only ever writes the plain log.
pub const LOG_ZST_NAME: &str = "atop.log.zst";

/// The zstd level a finished log is compressed at. On a 736 KB job log (`zstd -b`, one core),
/// 9 compresses 23× at 166 MB/s; 19 reaches 26× at 1.8 MB/s, and 3 19× at 636 MB/s.
const ZSTD_LEVEL: i32 = 9;

/// The least time a plain log must have gone unwritten before the sweep takes it for a finished
/// job's, on top of no live supervisor claiming it: the sampler writes one every interval.
const IDLE_BEFORE_COMPRESS: Duration = Duration::from_secs(60 * 60);

/// How much plain log one sweep compresses, in bytes of it — about three seconds of one core
/// at [`ZSTD_LEVEL`], since the sweep runs while a job waits to boot. A log that does not fit
/// what is left waits for the next sweep; one larger than this whole budget stays plain.
const COMPRESS_BUDGET: u64 = 512 * 1024 * 1024;

/// The largest log a job's cleanup compresses, about half a minute of one core: a log larger
/// than that is a guest that filled its directory, and cleanup holds the runner's slot.
const CLEANUP_MAX: u64 = 4 * 1024 * 1024 * 1024;

/// Whether this host records what its jobs' guests do (`[executor] atop`, on by default).
pub fn enabled(cfg: &Config) -> bool {
    cfg.executor.atop
}

/// The configured sampling interval. An interval of zero would have the guest sampling
/// without pause, so it is rejected here — where the error names the setting — rather
/// than clamped to something the operator did not ask for.
pub fn interval_secs(cfg: &Config) -> Result<u64> {
    let secs = cfg.executor.atop_interval_secs;
    if secs == 0 {
        bail!("[executor] atop_interval_secs must be at least 1 second (got 0)");
    }
    Ok(secs)
}

/// How many days of recorded jobs the archive keeps (`[executor] atop_retention_days`).
pub fn retention_days(cfg: &Config) -> u64 {
    cfg.executor.atop_retention_days
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

/// Create this job's archive directory, which [`record_archive_dir`] then records. Returns
/// the directory.
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
    Ok(dir)
}

/// Record `dir`, the archive directory [`prepare_archive`] made, in the job dir, where
/// `supervise` (a separate process) reads it and the final stage finds the log to report.
/// Split from [`prepare_archive`] because it writes to the job dir's filesystem, not the
/// archive's, and the caller tells the two failures apart.
pub fn record_archive_dir(ctx: &JobCtx, dir: &Path) -> Result<()> {
    let marker = ctx.atop_dir_file();
    // The path in its own bytes: a state dir that is not UTF-8 has to come back as the
    // directory it is, not as a lossy rendering of one.
    std::fs::write(&marker, dir.as_os_str().as_bytes())
        .with_context(|| format!("writing {}", marker.display()))
}

/// The archive directory prepare created for this job, or `None` where it recorded
/// none (recording off, or a prepare that could not create it).
pub fn job_archive_dir(ctx: &JobCtx) -> Option<PathBuf> {
    job_archive_dir_in(&ctx.job_dir)
}

/// [`job_archive_dir`] of the job in `job_dir`.
fn job_archive_dir_in(job_dir: &Path) -> Option<PathBuf> {
    let raw = std::fs::read(JobCtx::atop_dir_file_in(job_dir)).ok()?;
    // Only a trailing newline comes off; a path's own spaces are part of it.
    let bytes = raw.strip_suffix(b"\n").unwrap_or(&raw);
    (!bytes.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

/// Sweep once a day: remove days past the retention window, then compress logs left by jobs
/// that missed `cleanup`. The first job recorded today triggers the sweep because today's
/// directory does not exist yet. Sweeping per job would make every job wait to boot while
/// recursively removing trees filled by earlier guests.
///
/// Tied to recording being on, so `[executor] atop = false` stops the reclamation with it: an
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
    // Job dirs that cannot be listed may hide a live job: compress nothing rather than risk it.
    let Some(live) = live_archive_dirs(&cfg.state_dir().join("jobs")) else {
        return;
    };
    // Twice the interval, so a slow sample is not a missing one — and never under the floor.
    let idle = interval_secs(cfg).map_or(IDLE_BEFORE_COMPRESS, |secs| {
        IDLE_BEFORE_COMPRESS.max(Duration::from_secs(secs.saturating_mul(2)))
    });
    compress_idle_logs(&root, now, idle, &live, COMPRESS_BUDGET);
}

/// The archive directories of the jobs whose supervisor is running on this host, as
/// `(device, inode)` so the spelling of the path each was recorded under does not matter.
/// `None` when the job dirs cannot be listed; no job dirs at all is an empty set.
///
/// A job's log appears only once its guest boots, which is after its supervisor starts, so a
/// job still in prepare has no log to protect; one between listing and compressing is new, and
/// the idle guard in [`compress_idle_logs`] leaves it.
fn live_archive_dirs(jobs: &Path) -> Option<std::collections::HashSet<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    let entries = match std::fs::read_dir(jobs) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Default::default()),
        Err(_) => return None,
    };
    let mut live = std::collections::HashSet::new();
    for entry in entries {
        let job_dir = entry.ok()?.path();
        if crate::vm::live_supervisor_pid_in(&job_dir).is_none() {
            continue;
        }
        if let Some(dir) = job_archive_dir_in(&job_dir)
            && let Ok(md) = std::fs::metadata(&dir)
        {
            live.insert((md.dev(), md.ino()));
        }
    }
    Some(live)
}

/// A target carrying a path separator names a recording directly rather than selecting one
/// from the archive — the one rule the guard below and the lookup itself go by, so neither
/// can drift from the other and leave the guard refusing a path it would have resolved.
fn is_path_target(target: &str) -> bool {
    target.contains('/')
}

/// The log `target` names, for `vk atop` to print — so a viewer can be pointed
/// straight at it (`zstdless $(vk atop 42137)`, which reads a plain log and a compressed one).
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
    // the alternative is an ENOENT on a path the operator never configured. A path target
    // is exempt — it names its recording itself, wherever that host got it from.
    if !is_path_target(target) && !root.exists() && !enabled(cfg) {
        bail!("nothing recorded on this host (`[executor] atop` is off)");
    }
    resolve_in(&root, target)
}

/// Which of `dir`'s two names holds its recording: the plain log wherever that name is taken,
/// else the compressed one. Both are there only for a moment of [`compress_log`] — or after a
/// crash in it — and the plain log is then the one the compressed copy was made from, so it is
/// the answer until the next pass compresses it again. Whatever is at the chosen name is the
/// reader's to vet: [`crate::atoplog::open_log`] refuses anything but a regular file.
pub fn log_path(dir: &Path) -> PathBuf {
    let plain = dir.join(LOG_NAME);
    match std::fs::symlink_metadata(&plain) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => dir.join(LOG_ZST_NAME),
        _ => plain,
    }
}

/// The regular log [`log_path`] names in `dir`, and when it was last written. A symlink — or
/// anything else where the log goes — is not a recording this host wrote: guest root can reach
/// its own archive directory (see the module docs), and the path printed here goes straight to
/// a reader that would follow it.
fn recorded_log(dir: &Path) -> Option<(std::time::SystemTime, PathBuf)> {
    let log = log_path(dir);
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
    if is_path_target(target) {
        let path = Path::new(target);
        // A regular file and not a symlink to one, on the same footing [`recorded_log`]
        // takes the archive on: a named path points into a directory a guest could write,
        // and the path handed back goes straight to a reader that would follow it.
        let found = std::fs::symlink_metadata(path);
        if found.as_ref().is_ok_and(|md| md.is_file()) {
            return Ok(path.to_path_buf());
        }
        // The plain log's path, as prepare printed it, once the job has ended and it has been
        // compressed: the job's directory answers instead.
        let path = match (&found, path.parent()) {
            (Err(e), Some(dir))
                if e.kind() == std::io::ErrorKind::NotFound
                    && path.file_name() == Some(LOG_NAME.as_ref()) =>
            {
                dir
            }
            _ => path,
        };
        return recorded_log(path)
            .map(|(_, log)| log)
            .with_context(|| format!("no {LOG_NAME} or {LOG_ZST_NAME} under {}", path.display()));
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
         directory name; the archive keeps only the last `[executor] atop_retention_days` days)",
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

/// Compress this job's log once its guest is gone — `cleanup`, after the supervisor stops.
/// A supervisor still alive is a guest that may still write, and its log is left plain for the
/// sweep. Best effort: a log that will not compress stays readable as it is.
pub fn compress_job_log(ctx: &JobCtx) {
    let Some(dir) = job_archive_dir(ctx) else {
        return;
    };
    if crate::vm::live_supervisor_pid(ctx).is_some() {
        return;
    }
    // A SIGKILLed supervisor's virtiofsd and VMM get their `PDEATHSIG` asynchronously, so a last
    // guest write can land after this point: one while the log is read breaks the pledged size
    // and leaves it plain; one after its end is read and before the unlink is lost. The signals
    // land within moments of the supervisor's exit; that is the whole window.
    if let Err(e) = compress_log(&dir, CLEANUP_MAX) {
        eprintln!("virtkit: warning: {e:#}");
    }
}

/// Replace the plain log in `dir` with [`LOG_ZST_NAME`], unless it is larger than `max`. Returns
/// how many bytes of plain log it read: zero where there was none, or it already was zstd.
///
/// Streamed at [`ZSTD_LEVEL`] into a staging file beside it, which is fsynced, given the plain
/// log's mtime (what the newest-run lookup orders by), renamed into place and the directory
/// fsynced, before the plain log is unlinked — so a crash at any point leaves a whole copy
/// under one of the two names, and [`log_path`] answers with the plain one while both are
/// there. The frame pledges the log's size and carries a checksum: a log that grows or shrinks
/// while it is read fails the frame and stays plain, and a reader can tell damage from an end.
///
/// The plain log is opened as every reader opens it ([`crate::atoplog::open_log`]): a symlink
/// or anything but a regular file is refused and left where it is.
pub fn compress_log(dir: &Path, max: u64) -> Result<u64> {
    let plain = dir.join(LOG_NAME);
    let (src, len) = match crate::atoplog::open_log(&plain) {
        Ok(opened) => opened,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(0);
        }
        Err(e) => return Err(e).context("stats log left plain"),
    };
    if len > max {
        bail!(
            "{} is {}, over the {} limit for compressing it; left plain",
            plain.display(),
            crate::usage::fmt_bytes(len),
            crate::usage::fmt_bytes(max)
        );
    }
    // A guest can leave a zstd frame under the plain name; it reads as it is, and compressing
    // it again would only nest it.
    if crate::atoplog::is_compressed(&src)
        .with_context(|| format!("reading {}", plain.display()))?
    {
        return Ok(0);
    }
    let modified = src
        .metadata()
        .and_then(|md| md.modified())
        .with_context(|| format!("reading {}", plain.display()))?;
    pack(dir, src, len, modified)
        .with_context(|| format!("compressing {}; left plain", plain.display()))?;
    // Already gone is a concurrent sweep that compressed the same log and unlinked it first:
    // the `.zst` either of them renamed into place is whole.
    if let Err(e) = std::fs::remove_file(&plain)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(e).with_context(|| {
            format!(
                "compressed to {}, but removing {}",
                dir.join(LOG_ZST_NAME).display(),
                plain.display()
            )
        });
    }
    Ok(len)
}

/// What the name of a staging file [`pack`] writes in starts and ends with; between them is
/// the writer's pid, so two runners sweeping one archive never share one.
const STAGING_PREFIX: &str = ".atop.log.zst.";
const STAGING_SUFFIX: &str = ".tmp";

/// Write `src`, pledged to be `len` bytes, to [`LOG_ZST_NAME`] in `dir` with mtime `modified`,
/// through a staging file that is removed again if anything fails — `src` ending before `len`
/// or going past it included.
fn pack(
    dir: &Path,
    mut src: impl std::io::Read,
    len: u64,
    modified: std::time::SystemTime,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let packed = dir.join(LOG_ZST_NAME);
    // One left by a crashed pass of this pid is removed rather than written through.
    let staged = dir.join(format!(
        "{STAGING_PREFIX}{}{STAGING_SUFFIX}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&staged);
    // `create_new` is `O_EXCL`, which refuses a name already taken — a symlink included.
    let out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        // Owner-only: a command line in the log can carry a job's secrets.
        .mode(0o600)
        .open(&staged)
        .with_context(|| format!("creating {}", staged.display()))?;
    let written = (|| -> std::io::Result<()> {
        let mut enc = zstd::stream::write::Encoder::new(out, ZSTD_LEVEL)?;
        enc.include_checksum(true)?;
        enc.set_pledged_src_size(Some(len))?;
        std::io::copy(&mut src, &mut enc)?;
        let mut out = enc.finish()?;
        out.flush()?;
        out.set_modified(modified)?;
        out.sync_all()?;
        std::fs::rename(&staged, &packed)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if let Err(e) = written {
        // Ignored: the failure above is the one to report, and a staging file that will not go
        // either is a name no reader looks at.
        let _ = std::fs::remove_file(&staged);
        return Err(e.into());
    }
    Ok(())
}

/// Remove the staging files [`pack`] left in `dir` when its process died mid-write, once their
/// status last changed before `before` (seconds since the epoch). `ctime`, not `mtime`: a
/// pass sets the plain log's old mtime on its staging file just before renaming it.
fn remove_stale_staging(dir: &Path, before: i64) {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !(name.starts_with(STAGING_PREFIX) && name.ends_with(STAGING_SUFFIX)) {
            continue;
        }
        if entry.metadata().is_ok_and(|md| md.ctime() < before) {
            // Ignored: a staging file is a name no reader looks at, and the next sweep retries.
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Compress plain logs left by runners that died before `cleanup`. Skip `live` job directories
/// (see [`live_archive_dirs`]) and logs written within `idle`, which also protects supervisors
/// this host cannot see. Walk only real directories, as the retention sweep does, and remove
/// abandoned staging files from them once unchanged for `idle`.
///
/// Charge each log's size against `budget` before reading it, including failed compression and
/// zstd content under the plain name, so repeated attempts still consume the sweep's budget.
/// Skip logs larger than the remaining budget.
fn compress_idle_logs(
    root: &Path,
    now: i64,
    idle: Duration,
    live: &std::collections::HashSet<(u64, u64)>,
    mut budget: u64,
) {
    use std::os::unix::fs::MetadataExt;
    let idle_since = std::time::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(now).unwrap_or(0)).saturating_sub(idle);
    let stale_before = now.saturating_sub_unsigned(idle.as_secs());
    // A directory that cannot be read is skipped: compressing is best effort, and the next
    // sweep looks again.
    let real_dirs = |dir: &Path| -> Vec<std::fs::DirEntry> {
        std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .collect()
            })
            .unwrap_or_default()
    };
    for day in real_dirs(root) {
        if day.file_name().to_str().and_then(parse_date_dir).is_none() {
            continue;
        }
        for job in real_dirs(&day.path()) {
            let dir = job.path();
            if std::fs::symlink_metadata(&dir).is_ok_and(|md| live.contains(&(md.dev(), md.ino())))
            {
                continue;
            }
            remove_stale_staging(&dir, stale_before);
            // A regular file only: anything else is refused by [`compress_log`], and would be
            // warned about again every day.
            let Ok(md) = std::fs::symlink_metadata(dir.join(LOG_NAME)) else {
                continue;
            };
            if !md.is_file() || !md.modified().is_ok_and(|at| at < idle_since) {
                continue;
            }
            let Some(left) = budget.checked_sub(md.len()) else {
                continue;
            };
            // Capped at what the budget had, in case the log grew since it was measured.
            let cap = budget;
            budget = left;
            if let Err(e) = compress_log(&dir, cap) {
                eprintln!("virtkit: warning: {e:#}");
            }
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
    fn recording_is_on_by_default_and_off_when_turned_off() {
        let mut cfg = Config::default();
        assert!(
            enabled(&cfg),
            "on by default, even without an [executor] table"
        );
        assert_eq!(interval_secs(&cfg).unwrap(), 10);
        assert_eq!(retention_days(&cfg), 14);

        cfg.executor.atop = false;
        assert!(!enabled(&cfg));

        // A zero interval would have the guest sampling in a loop: name the setting.
        cfg.executor.atop_interval_secs = 0;
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
            ..Default::default()
        };
        assert_eq!(archive_root(&cfg), root);
        assert_eq!(resolve(&cfg, "41000").unwrap(), old);
        std::fs::remove_dir_all(&state).unwrap();
    }

    /// A path target answers even with recording off — a host that turned it off can still
    /// be handed the path a run printed — while a job lookup there still says plainly that
    /// nothing is recorded here.
    #[test]
    fn a_path_target_answers_with_recording_off() {
        let state = std::env::temp_dir().join(format!("vk-atop-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        let dir = state.join("somewhere");
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join(LOG_NAME);
        std::fs::write(&log, b"RESET\nSEP\n").unwrap();
        let cfg = Config {
            state_dir: Some(state.clone()),
            executor: crate::config::Executor {
                atop: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!enabled(&cfg), "recording off: nothing recorded here");
        assert_eq!(resolve(&cfg, &log.to_string_lossy()).unwrap(), log);
        assert_eq!(
            resolve(&cfg, &dir.to_string_lossy()).unwrap(),
            log,
            "the directory holding the log answers too"
        );
        let e = resolve(&cfg, "42137").expect_err("a job lookup has no archive to search");
        assert!(format!("{e:#}").contains("nothing recorded"), "{e:#}");
        std::fs::remove_dir_all(&state).unwrap();
    }

    /// A named path is held to the same rule the archive lookup holds a log to: a symlink
    /// where the recording should be is not a recording, whoever put it there. A guest can
    /// write the directory its own log lives in, and the path this hands back goes to a
    /// reader that would follow it — so the two branches must not disagree about symlinks.
    #[test]
    fn a_path_target_that_is_a_symlink_is_not_a_recording() {
        let dir = std::env::temp_dir().join(format!("vk-atop-pathlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, b"RESET\nSEP\n").unwrap();
        let planted = dir.join(LOG_NAME);
        std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();
        let cfg = Config {
            state_dir: Some(dir.clone()),
            ..Default::default()
        };
        // Named directly, and found by naming the directory holding it: refused either way.
        assert!(resolve(&cfg, &planted.to_string_lossy()).is_err());
        assert!(resolve(&cfg, &dir.to_string_lossy()).is_err());
        // The file it points at is a recording in its own right, named as itself.
        assert_eq!(
            resolve(&cfg, &elsewhere.to_string_lossy()).unwrap(),
            elsewhere
        );
        std::fs::remove_dir_all(&dir).unwrap();
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
            ..Default::default()
        };
        let ctx = JobCtx::new_for_job(cfg, "job1".into()).expect("a job context");
        std::fs::create_dir_all(&ctx.job_dir).unwrap();

        // Nothing recorded yet: no share to mount and no knob on the guest cmdline.
        assert_eq!(job_archive_dir(&ctx), None, "no marker, nothing recorded");

        let dir = prepare_archive(&ctx).expect("the archive directory");
        record_archive_dir(&ctx, &dir).expect("the marker");
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

    /// A scratch archive directory holding one job's plain log, last written at `written_at`.
    fn job_with_log(dir: &Path, text: &str, written_at: std::time::SystemTime) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let log = dir.join(LOG_NAME);
        std::fs::write(&log, text).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&log)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(written_at))
            .unwrap();
        log
    }

    fn as_json(path: &Path) -> Vec<u8> {
        let text = crate::atoplog::read(path).unwrap();
        let mut out = Vec::new();
        crate::atoplog::write_json(&crate::atoplog::parse(&text).samples, &mut out).unwrap();
        out
    }

    /// A finished log compresses to the name beside it and reads back as exactly the samples it
    /// held; the job still resolves — by id, by name, by its directory — and still orders by
    /// when the guest last wrote it, not by when it was compressed.
    #[test]
    fn a_compressed_log_resolves_and_reads_back_the_same() {
        let root = std::env::temp_dir().join(format!("vk-atop-zst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let day = root.join("2026-08-11");
        let dir = day.join("42137-acme-web-test_unit");
        let written_at = std::time::UNIX_EPOCH + Duration::from_secs(5000);
        let text = crate::atoplog::synthetic_log(200);
        let plain = job_with_log(&dir, &text, written_at);
        let before = as_json(&plain);
        // A later run whose log was written earlier: the compressed one still answers first.
        job_with_log(
            &day.join("42140-acme-web-test_unit"),
            &text,
            written_at - Duration::from_secs(1000),
        );

        assert_eq!(compress_log(&dir, u64::MAX).unwrap(), text.len() as u64);
        let packed = dir.join(LOG_ZST_NAME);
        assert!(
            !plain.exists(),
            "the plain log goes once the copy is in place"
        );
        let md = std::fs::metadata(&packed).unwrap();
        assert!(md.len() * 10 < text.len() as u64, "{} bytes", md.len());
        assert_eq!(md.modified().unwrap(), written_at, "the guest's last write");
        assert_eq!(as_json(&packed), before, "the same samples");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "no staging file left"
        );

        assert_eq!(resolve_in(&root, "42137").unwrap(), packed);
        assert_eq!(resolve_in(&root, "test_unit").unwrap(), packed);
        assert_eq!(resolve_in(&root, &dir.to_string_lossy()).unwrap(), packed);
        assert_eq!(
            resolve_in(&root, &packed.to_string_lossy()).unwrap(),
            packed
        );
        // Nothing left to compress is not an error.
        assert_eq!(compress_log(&dir, u64::MAX).unwrap(), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Both names present — a crash between the rename and the unlink — answer with the plain
    /// log the copy was made from, and the next pass compresses it over the copy.
    #[test]
    fn with_both_names_present_the_plain_log_answers() {
        let dir = std::env::temp_dir().join(format!("vk-atop-both-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let text = crate::atoplog::synthetic_log(20);
        let plain = job_with_log(&dir, &text, std::time::SystemTime::now());
        std::fs::write(dir.join(LOG_ZST_NAME), b"a stale or partial copy").unwrap();
        assert_eq!(log_path(&dir), plain);
        assert_eq!(resolve_in(&dir, &dir.to_string_lossy()).unwrap(), plain);

        compress_log(&dir, u64::MAX).unwrap();
        assert_eq!(log_path(&dir), dir.join(LOG_ZST_NAME));
        assert_eq!(crate::atoplog::read(&log_path(&dir)).unwrap(), text);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Only a regular file is compressed or read: a guest can leave anything at either name,
    /// and a symlink there would have the host read, or unlink, what it points at.
    #[test]
    fn a_log_that_is_not_a_regular_file_is_neither_compressed_nor_read() {
        let dir = std::env::temp_dir().join(format!("vk-atop-zstlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, b"RESET\nSEP\n").unwrap();

        // A symlink as the plain log: refused, and neither it nor its target is touched.
        std::os::unix::fs::symlink(&elsewhere, dir.join(LOG_NAME)).unwrap();
        assert!(compress_log(&dir, u64::MAX).is_err());
        assert!(dir.join(LOG_NAME).symlink_metadata().is_ok());
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"RESET\nSEP\n");
        assert!(!dir.join(LOG_ZST_NAME).exists());
        // A directory there: not a regular file either.
        std::fs::remove_file(dir.join(LOG_NAME)).unwrap();
        std::fs::create_dir(dir.join(LOG_NAME)).unwrap();
        assert!(compress_log(&dir, u64::MAX).is_err());
        assert!(resolve_in(&dir, &dir.to_string_lossy()).is_err());
        std::fs::remove_dir(dir.join(LOG_NAME)).unwrap();

        // A symlink as the compressed log: not a recording, found or named.
        let packed = dir.join(LOG_ZST_NAME);
        std::os::unix::fs::symlink(&elsewhere, &packed).unwrap();
        assert!(resolve_in(&dir, &dir.to_string_lossy()).is_err());
        assert!(resolve_in(&dir, &packed.to_string_lossy()).is_err());
        assert!(crate::atoplog::read(&packed).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The sweep compresses a log nothing has written for longer than a sampler could stay
    /// quiet, and leaves alone one written recently or one a live job's supervisor claims —
    /// however old its mtime, which a guest can set. Each log is charged its size up front, and
    /// one that does not fit what is left of the budget waits.
    #[test]
    fn the_sweep_compresses_idle_logs_and_leaves_live_ones() {
        use std::os::unix::fs::MetadataExt;
        let root = std::env::temp_dir().join(format!("vk-atop-idle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let now = now_epoch();
        let day = root.join(date_dir(now));
        let at = |ago: Duration| std::time::SystemTime::now() - ago;
        let old = at(2 * IDLE_BEFORE_COMPRESS);
        let text = crate::atoplog::synthetic_log(20);
        let crashed = job_with_log(&day.join("41000-a-b"), &text, old);
        let running = job_with_log(&day.join("42000-a-b"), &text, at(Duration::from_secs(10)));
        let backdated = job_with_log(&day.join("42500-a-b"), &text, old);
        // Not a day of recordings: not walked.
        let parked = job_with_log(&root.join("notes").join("43000-a-b"), &text, old);
        let claimed = std::fs::metadata(backdated.parent().unwrap()).unwrap();
        let live = std::collections::HashSet::from([(claimed.dev(), claimed.ino())]);

        compress_idle_logs(&root, now, IDLE_BEFORE_COMPRESS, &live, COMPRESS_BUDGET);
        assert!(!crashed.exists());
        assert!(crashed.with_file_name(LOG_ZST_NAME).is_file());
        assert!(running.is_file(), "a log still being written stays plain");
        assert!(!running.with_file_name(LOG_ZST_NAME).exists());
        assert!(
            backdated.is_file(),
            "a live job's log stays plain, whatever its mtime"
        );
        assert!(parked.is_file());

        // Two idle logs and budget for one: the other is left for the next sweep.
        let a = job_with_log(&day.join("44000-a-b"), &text, old);
        let b = job_with_log(&day.join("45000-a-b"), &text, old);
        let budget = text.len() as u64;
        compress_idle_logs(&root, now, IDLE_BEFORE_COMPRESS, &live, budget);
        assert_eq!(
            [a.exists(), b.exists()]
                .iter()
                .filter(|plain| **plain)
                .count(),
            1,
            "one compressed, one left for the next sweep"
        );
        // A log larger than the whole budget is skipped, not started.
        let big = job_with_log(&day.join("46000-a-b"), &text, old);
        compress_idle_logs(&root, now, IDLE_BEFORE_COMPRESS, &live, budget - 1);
        assert!(big.is_file());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A job whose supervisor is running claims its archive directory, found through the
    /// marker in its job dir; a job dir whose supervisor is gone claims nothing.
    #[test]
    fn a_running_job_claims_its_archive_directory() {
        use std::os::unix::fs::MetadataExt;
        let root = std::env::temp_dir().join(format!("vk-atop-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let jobs = root.join("jobs");
        assert_eq!(
            live_archive_dirs(&jobs).map(|l| l.len()),
            Some(0),
            "no job dirs yet"
        );
        let archive = root.join("atop").join("2026-08-11");
        let job = |name: &str, pid: u32| {
            let job_dir = jobs.join(name);
            let dir = archive.join(name);
            std::fs::create_dir_all(&job_dir).unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                JobCtx::atop_dir_file_in(&job_dir),
                dir.as_os_str().as_bytes(),
            )
            .unwrap();
            std::fs::write(JobCtx::supervisor_pidfile_in(&job_dir), pid.to_string()).unwrap();
            let md = std::fs::metadata(&dir).unwrap();
            (md.dev(), md.ino())
        };
        // A stand-in supervisor: a live process whose command line names its job dir, which is
        // what `vm::live_supervisor_pid_in` goes by.
        let mut supervisor = std::process::Command::new("sh")
            // Not a lone `sleep`, which a shell may exec in its own place, dropping the argument.
            .args(["-c", "sleep 30; :", "sh"])
            .arg(jobs.join("running"))
            .spawn()
            .unwrap();
        let running = job("running", supervisor.id());
        // This test's own pid: alive, but not the supervisor of that job.
        let gone = job("gone", std::process::id());

        // `spawn` returns once exec is committed, but /proc/<pid>/cmdline reads empty until the
        // new image's argv is set up.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while crate::vm::live_supervisor_pid_in(&jobs.join("running")).is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "the stand-in supervisor's command line never named its job dir"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let live = live_archive_dirs(&jobs).expect("the job dirs list");
        supervisor.kill().unwrap();
        supervisor.wait().unwrap();
        assert!(
            live.contains(&running),
            "a live supervisor claims its archive dir"
        );
        assert!(
            !live.contains(&gone),
            "a pid that is not the job's claims nothing"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The plain log's path that prepare printed still answers once the job has ended and the
    /// log is compressed; a path under any other name does not stand in for the directory.
    #[test]
    fn the_printed_plain_path_resolves_after_compression() {
        let dir = std::env::temp_dir().join(format!("vk-atop-printed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let plain = job_with_log(
            &dir,
            &crate::atoplog::synthetic_log(3),
            std::time::SystemTime::now(),
        );
        compress_log(&dir, u64::MAX).unwrap();
        assert_eq!(
            resolve_in(&dir, &plain.to_string_lossy()).unwrap(),
            dir.join(LOG_ZST_NAME)
        );
        assert!(resolve_in(&dir, &dir.join("other.log").to_string_lossy()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A log over the size limit is refused before any of it is read, and stays plain.
    #[test]
    fn a_log_over_the_limit_stays_plain() {
        let dir = std::env::temp_dir().join(format!("vk-atop-max-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let text = crate::atoplog::synthetic_log(3);
        let plain = job_with_log(&dir, &text, std::time::SystemTime::now());
        let e = compress_log(&dir, text.len() as u64 - 1).expect_err("over the limit");
        assert!(format!("{e:#}").contains("left plain"), "{e:#}");
        assert!(plain.is_file() && !dir.join(LOG_ZST_NAME).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A source that ends before the pledged size or runs past it fails the frame: the staging
    /// file goes, and the plain log is all the directory holds.
    #[test]
    fn a_log_that_changes_while_read_stays_plain() {
        let dir = std::env::temp_dir().join(format!("vk-atop-frame-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let text = crate::atoplog::synthetic_log(3);
        job_with_log(&dir, &text, std::time::SystemTime::now());
        let len = text.len() as u64;
        let grown = format!("{text}more");
        let shrunk = &text.as_bytes()[..text.len() - 1];
        for src in [grown.as_bytes(), shrunk] {
            pack(&dir, src, len, std::time::SystemTime::now()).expect_err("size broke its pledge");
            let names: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(names, [LOG_NAME]);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A zstd frame under the plain name is left as it is rather than compressed again.
    #[test]
    fn a_plain_log_that_is_already_zstd_is_not_compressed_again() {
        let dir = std::env::temp_dir().join(format!("vk-atop-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let text = crate::atoplog::synthetic_log(3);
        let frame = zstd::encode_all(text.as_bytes(), 1).unwrap();
        std::fs::write(dir.join(LOG_NAME), &frame).unwrap();
        assert_eq!(compress_log(&dir, u64::MAX).unwrap(), 0);
        assert_eq!(std::fs::read(dir.join(LOG_NAME)).unwrap(), frame);
        assert!(!dir.join(LOG_ZST_NAME).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Staging files changed before the threshold are removed; newer ones, which a pass may
    /// still be writing, and every other name stay.
    #[test]
    fn stale_staging_files_are_removed() {
        let dir = std::env::temp_dir().join(format!("vk-atop-staging-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join(format!("{STAGING_PREFIX}1{STAGING_SUFFIX}"));
        std::fs::write(&staged, b"").unwrap();
        std::fs::write(dir.join(LOG_NAME), b"").unwrap();
        let now = now_epoch();
        remove_stale_staging(&dir, now - 60);
        assert!(staged.exists(), "too recent to be abandoned");
        remove_stale_staging(&dir, now + 60);
        assert!(!staged.exists());
        assert!(dir.join(LOG_NAME).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A job's cleanup compresses its log once the guest is gone, through the archive
    /// directory prepare recorded; a job that recorded nothing has nothing to compress.
    #[test]
    fn a_jobs_cleanup_compresses_its_log() {
        let root = std::env::temp_dir().join(format!("vk-atop-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cfg = Config {
            state_dir: Some(root.clone()),
            ..Default::default()
        };
        let ctx = JobCtx::new_for_job(cfg, "job1".into()).expect("a job context");
        std::fs::create_dir_all(&ctx.job_dir).unwrap();
        compress_job_log(&ctx); // no marker: nothing recorded, nothing to do

        let dir = prepare_archive(&ctx).unwrap();
        record_archive_dir(&ctx, &dir).unwrap();
        let text = crate::atoplog::synthetic_log(20);
        std::fs::write(dir.join(LOG_NAME), &text).unwrap();
        compress_job_log(&ctx);
        assert!(!dir.join(LOG_NAME).exists());
        assert_eq!(crate::atoplog::read(&dir.join(LOG_ZST_NAME)).unwrap(), text);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
