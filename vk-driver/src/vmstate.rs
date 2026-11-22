//! Pinned runs record startup in [`FILE`] until their primary registers. Whole-VM stops
//! record shutdown before signalling the run or killing its VMMs. A record identifies the run by
//! pid and start time and includes the transition time and any stop deadline.
//!
//! [`Transient::standing`] classifies a record from the time and process liveness, even
//! after a run dies mid-boot or a stop is interrupted. Writers hold [`LOCK`] and use a
//! single directory descriptor. A stop can replace or clear only its own run's record.

use std::ffi::OsStr;
use std::io::Read as _;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The record's file in a state dir.
pub const FILE: &str = ".virtkit-state.json";

/// Held while [`FILE`] is checked and changed. Never removed: a lock file that is unlinked
/// while held stops serializing.
const LOCK: &str = ".virtkit-state.lock";

/// Maximum age of a record whose run cannot be verified. A verified build may take longer.
pub const STARTING_UNSEEN_SECS: u64 = 3600;

/// A state a VM passes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// its run holds the state dir and is pulling, building or booting
    Starting,
    /// a whole-VM stop has begun and the run has not exited
    Stopping,
}

impl State {
    /// As `vk list` prints it.
    pub fn label(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Stopping => "stopping",
        }
    }
}

/// One transient state, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transient {
    pub state: State,
    /// the `vk run` it is about
    pub pid: u32,
    /// that process's start time, which tells it from a later one given the same pid
    #[serde(default)]
    pub pid_start_ticks: Option<u64>,
    /// when the state began
    pub since_secs: u64,
    /// when it lapses: a stop's timeout, when it was given one. A start has none
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_secs: Option<u64>,
    /// the `vk stop` waiting for the run to go
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_pid: Option<u32>,
    /// that command's start time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_start_ticks: Option<u64>,
}

/// Where a recorded transient state stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// the transition is current, including the grace period for an unverifiable run
    Holds,
    /// the run is alive, but the deadline passed or the stop command exited
    Overdue,
    /// the run exited or can no longer be assumed alive
    Gone,
}

impl Transient {
    /// Classify the record at `now`. The two liveness checks refer to the run and the stop
    /// command. `None` means unknown (or no stop command recorded). An unverified run
    /// counts as live for up to [`STARTING_UNSEEN_SECS`], unless the deadline passes or the
    /// stop command is known to have exited.
    pub fn standing(
        &self,
        now: u64,
        process_there: Option<bool>,
        by_there: Option<bool>,
    ) -> Standing {
        let overdue = self.timed_out(now) || by_there == Some(false);
        match (process_there, overdue) {
            (Some(false), _) => Standing::Gone,
            (Some(true), true) => Standing::Overdue,
            (Some(true), false) => Standing::Holds,
            (None, true) => Standing::Gone,
            (None, false) if now.saturating_sub(self.since_secs) <= STARTING_UNSEEN_SECS => {
                Standing::Holds
            }
            (None, false) => Standing::Gone,
        }
    }

    /// Whether it is about the run `pid` started at `ticks`, and not another given that pid.
    pub fn is_of(&self, pid: u32, ticks: Option<u64>) -> bool {
        self.pid == pid && self.pid_start_ticks == ticks
    }

    /// Whether its deadline has passed at `now`.
    fn timed_out(&self, now: u64) -> bool {
        self.deadline_secs.is_some_and(|d| now > d)
    }

    /// Report a timeout if the deadline has passed, otherwise an interrupted stop.
    pub fn lapse(&self, now: u64) -> String {
        match self.deadline_secs.filter(|_| self.timed_out(now)) {
            Some(d) => format!("timed out {} ago", crate::vms::fmt_uptime(now - d)),
            None => format!(
                "was interrupted (begun {} ago)",
                crate::vms::fmt_uptime(now.saturating_sub(self.since_secs))
            ),
        }
    }
}

impl Transient {
    /// Whether the run it is about is known to have exited.
    pub fn run_gone(&self) -> bool {
        there(self.pid, self.pid_start_ticks) == Some(false)
    }
}

/// Whether `pid`, started at `ticks`, is still running; `None` when that cannot be told: no
/// start time to compare, or procfs neither shows it nor shows it gone.
fn there(pid: u32, ticks: Option<u64>) -> Option<bool> {
    let ticks = ticks?;
    let pid = i32::try_from(pid).ok()?;
    if crate::usage::proc_exited(pid, ticks) {
        return Some(false);
    }
    (crate::usage::proc_starttime(pid) == Some(ticks)).then_some(true)
}

/// Record startup for this run. If the write fails, listing cannot report its startup.
pub fn starting(dir: &Path) {
    let record = Transient {
        state: State::Starting,
        pid: std::process::id(),
        pid_start_ticks: crate::vms::own_start_ticks(),
        since_secs: crate::vms::unix_now(),
        deadline_secs: None,
        by_pid: None,
        by_start_ticks: None,
    };
    let _ = locked(dir, Wait::Block, |d, _| d.write(&record));
}

/// Record this process as the stop command for `pid`, with `left` remaining or no deadline.
/// Skip a replacement run's record or a busy writer lock to stay within the stop deadline.
pub fn stopping(
    dir: &Path,
    pid: u32,
    pid_start_ticks: Option<u64>,
    left: Option<std::time::Duration>,
) {
    let record = stop_of(pid, pid_start_ticks, left);
    // If the writer lock is busy, keep the existing record.
    let _ = locked(dir, Wait::No, |d, recorded| {
        match recorded.is_none_or(|r| r.is_of(pid, pid_start_ticks)) {
            true => d.write(&record),
            false => Ok(()),
        }
    });
}

/// Claim the stop the user reviewed. Under the record lock, replace it with this process's
/// stop record only if it still matches `expected`. Return `Ok(false)` if it changed.
pub fn claim(
    dir: &Path,
    expected: &Transient,
    left: Option<std::time::Duration>,
) -> anyhow::Result<bool> {
    let record = stop_of(expected.pid, expected.pid_start_ticks, left);
    locked(dir, Wait::Block, |d, recorded| {
        match recorded.as_ref() == Some(expected) {
            true => d.write(&record).map(|()| true),
            false => Ok(false),
        }
    })
}

/// The record of a stop by this process of the run `pid` started at `pid_start_ticks`.
fn stop_of(pid: u32, pid_start_ticks: Option<u64>, left: Option<std::time::Duration>) -> Transient {
    let now = crate::vms::unix_now();
    Transient {
        state: State::Stopping,
        pid,
        pid_start_ticks,
        since_secs: now,
        // Rounded up: a record never lapses before the stop it describes.
        deadline_secs: left
            .map(|l| now.saturating_add(l.as_secs() + u64::from(l.subsec_nanos() > 0))),
        by_pid: Some(std::process::id()),
        by_start_ticks: crate::vms::own_start_ticks(),
    }
}

/// Clear the stopped run's record if its pid and start time still match. As in
/// [`stopping`], a busy writer lock must not delay the stop.
pub fn clear_of(dir: &Path, pid: u32, ticks: Option<u64>) {
    clear_where(dir, Wait::No, |r| r.is_of(pid, ticks));
}

/// Registration clears only this run's startup record. A concurrent stop keeps its record.
pub fn started(dir: &Path, pid: u32, ticks: Option<u64>) {
    clear_where(dir, Wait::Block, |r| {
        r.state == State::Starting && r.is_of(pid, ticks)
    });
}

/// Remove the record on `dir` if `of` holds for it. Best-effort, as every such clear: a
/// record left is read past once its process is gone.
fn clear_where(dir: &Path, wait: Wait, of: impl FnOnce(&Transient) -> bool) {
    let _ = locked(dir, wait, |d, recorded| match recorded {
        Some(r) if of(&r) => d.remove(),
        _ => Ok(()),
    });
}

/// Clear this run's record on teardown. Teardown can wait for the writer lock.
pub fn clear_own(dir: &Path) {
    let (pid, ticks) = (std::process::id(), crate::vms::own_start_ticks());
    clear_where(dir, Wait::Block, |r| r.is_of(pid, ticks));
}

/// Remove a transient record classified as [`Standing::Gone`]. Keep overdue stops.
/// Return `Ok(true)` on removal and propagate lock and removal errors. The lock is
/// nonblocking so cleanup before signalling cannot consume the stop deadline.
pub fn clear_if_stale(dir: &Path) -> anyhow::Result<bool> {
    let Some((judged, Standing::Gone)) = try_peek(dir)? else {
        return Ok(false);
    };
    locked(dir, Wait::No, |d, recorded| {
        // A new run may have replaced the record since the liveness check.
        match recorded == Some(judged) {
            true => d.remove().map(|()| true),
            false => Ok(false),
        }
    })
}

/// The transient state of the VM on `dir` that still holds, if any.
pub fn read(dir: &Path) -> Option<Transient> {
    match peek(dir)? {
        (record, Standing::Holds) => Some(record),
        _ => None,
    }
}

/// What is recorded for the VM on `dir`, and where it stands. Writes nothing.
pub fn peek(dir: &Path) -> Option<(Transient, Standing)> {
    // Listing skips unreadable records. `vk stop --tidy` reports them.
    try_peek(dir).ok().flatten()
}

/// Distinguish an unreadable record from a missing one so repair can report the failure.
fn try_peek(dir: &Path) -> anyhow::Result<Option<(Transient, Standing)>> {
    let Some(record) = read_raw(dir)? else {
        return Ok(None);
    };
    let standing = record.standing(
        crate::vms::unix_now(),
        there(record.pid, record.pid_start_ticks),
        record
            .by_pid
            .and_then(|by| there(by, record.by_start_ticks)),
    );
    Ok(Some((record, standing)))
}

/// Whether [`locked`] waits for [`LOCK`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wait {
    Block,
    /// fail at once while another writer holds it
    No,
}

/// A state dir, opened once: the lock, the read and every change go through this descriptor,
/// so a directory renamed and replaced meanwhile is not the one acted on.
struct Dir(OwnedFd);

impl Dir {
    /// `name` in it, opened with `flags` (created with the record's mode), never through a
    /// symlink.
    fn file(&self, name: &str, flags: libc::c_int) -> std::io::Result<std::fs::File> {
        let name = std::ffi::CString::new(name)?;
        // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                libc::c_uint::from(crate::statefile::FILE_MODE),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor this call owns.
        Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn read(&self) -> Option<Transient> {
        let mut json = Vec::new();
        (self.file(FILE, libc::O_RDONLY).ok()?)
            .read_to_end(&mut json)
            .ok()?;
        serde_json::from_slice(&json).ok()
    }

    fn write(&self, record: &Transient) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(record)?;
        let mode = crate::statefile::FILE_MODE;
        vk_fs::write_atomic_unsynced_in(self.0.as_fd(), OsStr::new(FILE), &json, mode)
    }

    fn remove(&self) -> anyhow::Result<()> {
        vk_fs::remove_file_in(self.0.as_fd(), OsStr::new(FILE))
    }
}

/// Read and update through one directory descriptor under [`LOCK`]. If the directory or
/// lock cannot be opened, or [`Wait::No`] finds it locked, return before calling `f`.
fn locked<T>(
    dir: &Path,
    wait: Wait,
    f: impl FnOnce(&Dir, Option<Transient>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    use anyhow::Context as _;
    let d = Dir(vk_fs::open_dir(dir)?);
    let lock = (d.file(LOCK, libc::O_WRONLY | libc::O_CREAT))
        .map(vk_fs::LockFile::new)
        .with_context(|| format!("opening {}", dir.join(LOCK).display()))?;
    let op = match wait {
        Wait::Block => libc::LOCK_EX,
        Wait::No => libc::LOCK_EX | libc::LOCK_NB,
    };
    // SAFETY: the fd is owned by `lock`, which outlives the call; it is released on drop.
    if unsafe { libc::flock(lock.as_raw_fd(), op) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(e).with_context(|| format!("locking {}", dir.join(LOCK).display()));
    }
    f(&d, d.read())
}

fn read_raw(dir: &Path) -> anyhow::Result<Option<Transient>> {
    use anyhow::Context as _;
    let path = dir.join(FILE);
    let json = match std::fs::read(&path) {
        Ok(json) => json,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    (serde_json::from_slice(&json).map(Some)).with_context(|| format!("reading {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(state: State, deadline: Option<u64>) -> Transient {
        Transient {
            state,
            pid: 1,
            pid_start_ticks: Some(7),
            since_secs: 1000,
            deadline_secs: deadline,
            by_pid: None,
            by_start_ticks: None,
        }
    }

    /// A record holds while its process is there and its deadline has not passed; a process
    /// that cannot be looked up is believed for a while, then not.
    #[test]
    fn a_record_goes_stale_with_its_process_or_its_deadline() {
        let start = record(State::Starting, None);
        let holds = |t: &Transient, now, there| t.standing(now, there, None) == Standing::Holds;
        assert!(holds(&start, 1001, Some(true)));
        assert!(holds(&start, 1_000_000, Some(true)), "a long build");
        assert!(!holds(&start, 1001, Some(false)), "its run is gone");
        assert!(holds(&start, 1000 + STARTING_UNSEEN_SECS, None));
        assert!(!holds(&start, 1001 + STARTING_UNSEEN_SECS, None));

        let stop = record(State::Stopping, Some(1210));
        assert!(holds(&stop, 1210, Some(true)));
        assert_eq!(stop.standing(1211, Some(true), None), Standing::Overdue);
        assert_eq!(stop.standing(1100, Some(false), None), Standing::Gone);
        assert_eq!(stop.standing(1211, None, None), Standing::Gone);
        // Its `vk stop` gone before the deadline: interrupted, not timed out.
        assert_eq!(
            stop.standing(1001, Some(true), Some(false)),
            Standing::Overdue
        );
        assert_eq!(stop.lapse(1001), "was interrupted (begun 1s ago)");
        assert_eq!(stop.lapse(1270), "timed out 1m ago");
        // With no timeout: held while its `vk stop` is there, overdue once it is gone.
        let waited = record(State::Stopping, None);
        assert_eq!(
            waited.standing(9_000_000, Some(true), Some(true)),
            Standing::Holds
        );
        assert_eq!(
            waited.standing(1001, Some(true), Some(false)),
            Standing::Overdue
        );
        assert!(waited.lapse(1001).starts_with("was interrupted"));
    }

    /// A record reads back until its run clears it; a stop never replaces or clears another
    /// run's.
    #[test]
    fn a_stop_touches_only_its_own_run_s_record() {
        let t = crate::dev::testutil::scratch("vmstate");
        let dir = &t.0;
        let (me, ticks) = (std::process::id(), crate::vms::own_start_ticks());
        assert_eq!(read(dir), None);
        starting(dir);
        let got = read(dir).expect("this process is starting it");
        assert_eq!((got.state, got.pid), (State::Starting, me));
        // Another run's stop, decided before this run took the dir: left alone, even one of
        // an earlier run given this pid.
        stopping(dir, me + 1, Some(1), None);
        clear_of(dir, me + 1, Some(1));
        stopping(dir, me, Some(1), None);
        assert_eq!(read(dir).map(|r| r.state), Some(State::Starting));
        clear_own(dir);
        assert_eq!(peek(dir), None);

        // A stop of this run, with a deadline: held until it passes.
        stopping(dir, me, ticks, Some(std::time::Duration::from_secs(30)));
        let got = read(dir).expect("stopping");
        assert_eq!(got.deadline_secs, Some(got.since_secs + 30));
        assert_eq!(got.by_pid, Some(me));
        stopping(dir, me, ticks, None);
        assert_eq!(read(dir).expect("stopping").deadline_secs, None);
        // A stop of another run started at another time under this pid: not this one.
        clear_of(dir, me, Some(1));
        assert!(read(dir).is_some());
        // The run registering ends its start, not a stop of it that began meanwhile.
        started(dir, me, ticks);
        assert_eq!(read(dir).map(|r| r.state), Some(State::Stopping));
        clear_of(dir, me, ticks);
        assert_eq!(peek(dir), None);
        starting(dir);
        started(dir, me, ticks);
        assert_eq!(peek(dir), None);
    }

    /// A stop does not wait on a record another writer holds, neither to record itself nor
    /// to clear its record once its run is down: it has a deadline to keep.
    #[test]
    fn a_stop_skips_a_record_it_would_wait_for() {
        let t = crate::dev::testutil::scratch("vmstate-held");
        let dir = &t.0;
        let held = vk_fs::LockFile::new(std::fs::File::create(dir.join(LOCK)).unwrap());
        // SAFETY: a lock on a file this test opened, released when `held` drops.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        let began = std::time::Instant::now();
        stopping(dir, std::process::id(), crate::vms::own_start_ticks(), None);
        assert!(began.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(peek(dir), None);
        drop(held);
        let (me, ticks) = (std::process::id(), crate::vms::own_start_ticks());
        stopping(dir, me, ticks, None);
        assert_eq!(read(dir).map(|r| r.state), Some(State::Stopping));
        let held = vk_fs::LockFile::new(std::fs::File::create(dir.join(LOCK)).unwrap());
        // SAFETY: as above.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        let began = std::time::Instant::now();
        clear_of(dir, me, ticks);
        assert!(began.elapsed() < std::time::Duration::from_secs(1));
        assert!(read(dir).is_some());
        drop(held);
        clear_of(dir, me, ticks);
        assert_eq!(peek(dir), None);

        // Nor to clear a stale record of its target before signalling it.
        let stale = Transient {
            pid: me,
            pid_start_ticks: Some(1),
            ..record(State::Starting, None)
        };
        std::fs::write(dir.join(FILE), serde_json::to_vec(&stale).unwrap()).unwrap();
        let held = vk_fs::LockFile::new(std::fs::File::create(dir.join(LOCK)).unwrap());
        // SAFETY: as above.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        let began = std::time::Instant::now();
        assert!(clear_if_stale(dir).is_err());
        assert!(began.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(peek(dir).map(|(r, _)| r), Some(stale));
        drop(held);
        assert!(clear_if_stale(dir).unwrap());
        assert_eq!(peek(dir), None);
    }

    /// A stop is taken over only while its record is still the one expected.
    #[test]
    fn a_claim_takes_only_the_record_it_expects() {
        let t = crate::dev::testutil::scratch("vmstate-claim");
        let dir = &t.0;
        let (me, ticks) = (std::process::id(), crate::vms::own_start_ticks());
        stopping(dir, me, ticks, None);
        let asked = read(dir).unwrap();
        let mut since = asked.clone();
        since.since_secs += 1;
        assert!(
            !claim(dir, &since, None).unwrap(),
            "another stop began since"
        );
        assert_eq!(read(dir).as_ref(), Some(&asked));
        let left = Some(std::time::Duration::from_secs(10));
        assert!(claim(dir, &asked, left).unwrap());
        assert!(read(dir).unwrap().deadline_secs.is_some());
    }

    #[test]
    fn the_record_names_its_state_in_words() {
        let json = serde_json::to_string(&record(State::Stopping, Some(5))).unwrap();
        assert!(json.contains(r#""state":"stopping""#), "{json}");
        assert!(json.contains(r#""deadline_secs":5"#), "{json}");
        let json = serde_json::to_string(&record(State::Starting, None)).unwrap();
        assert!(!json.contains("deadline_secs"), "{json}");
    }
}
