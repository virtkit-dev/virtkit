//! Host side of the per-job guest statistics recording (`[gitlab] atop`).
//!
//! A CI job gets its own microVM, so the guest is the job: the in-guest agent samples
//! its own `/proc` and appends the samples in the text format `atop -P` prints (the schema
//! both sides speak is `vk_core::atop`). This module owns the host's half — where the log
//! lands, and how the guest is told to write it:
//!
//! * `prepare` creates this job's archive directory under `<state_dir>/atop/<date>/`
//!   and records its path in the job dir;
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
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use vk_core::atop::{date_dir, now_epoch};

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

/// Every job's archive on this host, one directory per day inside it. Shared by every
/// runner using this state dir, and outside the job dirs on purpose: a job's own dir is
/// wiped by its prepare and removed at cleanup, while the log outlives the job.
pub fn archive_root(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("atop")
}

/// Where this job's log goes: `<archive root>/<YYYY-MM-DD>/<job>`. The date groups a
/// day's jobs into one directory, so the archive stays readable as it fills up.
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

/// The archive directory name for the day a job recorded now lands in.
fn today() -> String {
    date_dir(now_epoch())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_is_on_for_an_executor_host_and_off_without_one() {
        let mut cfg = Config::default();
        assert!(!enabled(&cfg), "no [gitlab] table: no executor here");
        cfg.gitlab = Some(Gitlab::default());
        assert!(enabled(&cfg), "on by default once the executor is set up");
        assert_eq!(interval_secs(&cfg).unwrap(), 10);

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

    /// The archive is one directory per day of the shared state dir, outside the job dirs
    /// that are wiped when a job ends.
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
