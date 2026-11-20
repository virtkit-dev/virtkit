//! What a VM is doing between stopped and running: `starting` from the moment its run takes
//! the state dir until the VM is registered, `stopping` from the moment a stop signals it
//! until it is gone. Kept as [`FILE`] in the VM's state dir, so a command that finds the VM
//! in neither the registry nor at rest can say which.
//!
//! The record says so itself rather than being inferred: it names the state, the process it
//! is about, when it began, and — for a stop, which has a timeout — when it lapses. A record
//! its writer never cleared (a run killed mid-boot, a stop that was interrupted) goes stale:
//! [`Transient::standing`] is pure, told the time and whether that process is still there.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The record's file in a state dir.
pub const FILE: &str = ".virtkit-state.json";

/// How long a `starting` record is believed when its process cannot be looked up (no start
/// time recorded: procfs was unreadable where it was written). A boot may build for a long
/// time; past this the record says nothing any more.
pub const STARTING_UNSEEN_SECS: u64 = 3600;

/// A state a VM passes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// its run holds the state dir and is pulling, building or booting
    Starting,
    /// a stop signalled its run, which has not gone yet
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
    /// the command carrying the state out, when that is not the process itself: the
    /// `vk stop` waiting for the run to go
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_pid: Option<u32>,
    /// that command's start time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_start_ticks: Option<u64>,
}

/// Where a recorded transient state stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// under way: its process is there, and its deadline, if it has one, has not passed
    Holds,
    /// its process is still there, and its deadline passed or the command carrying it out
    /// is gone: a stop that timed out, or was interrupted, on a run that did not go.
    /// Nothing settles this by itself — it is for the user to look at, and
    /// to stop again or end the process — so the record stays until the process is gone
    Overdue,
    /// its process is gone, or cannot be told to be there any more: the record describes
    /// nothing, and the tidy pass removes it
    Gone,
}

impl Transient {
    /// Where the record stands at `now`. `process_there` says whether the process it names
    /// is still running, `None` when that cannot be told: such a record is believed until
    /// its deadline, or for [`STARTING_UNSEEN_SECS`] from the start when it has none.
    /// `by_there` says the same of the command carrying it out (`None`: none recorded, or
    /// it cannot be told): once that is gone, nothing is waiting on the state any more.
    pub fn standing(
        &self,
        now: u64,
        process_there: Option<bool>,
        by_there: Option<bool>,
    ) -> Standing {
        let overdue = self.deadline_secs.is_some_and(|d| now > d) || by_there == Some(false);
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

    /// Whether the record still holds at `now`, the command carrying it out left aside
    /// (see [`Transient::standing`]).
    #[cfg(test)]
    fn fresh(&self, now: u64, process_there: Option<bool>) -> bool {
        self.standing(now, process_there, None) == Standing::Holds
    }

    /// Whether the command carrying the state out is still running; `None` when none was
    /// recorded, or without its start time to compare.
    fn by_there(&self) -> Option<bool> {
        let recorded = self.by_start_ticks?;
        let pid = i32::try_from(self.by_pid?).ok()?;
        Some(crate::usage::proc_starttime(pid) == Some(recorded))
    }

    /// Whether the process the record names is still running: its pid, started when the
    /// record says. `None` when the record has no start time to compare.
    fn process_there(&self) -> Option<bool> {
        let recorded = self.pid_start_ticks?;
        let pid = i32::try_from(self.pid).ok()?;
        Some(crate::usage::proc_starttime(pid) == Some(recorded))
    }
}

/// Record that this process's run on `dir` is starting. Best-effort, like the registry: a
/// record that cannot be written leaves the VM listed as stopped until it is up.
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
    let _ = write(dir, &record);
}

/// Record that this process asked the run `pid` on `dir` to stop and waits for it to go:
/// for `timeout` seconds, or with `None` for as long as it takes — an interrupted wait is
/// then told by this process being gone.
pub fn stopping(dir: &Path, pid: u32, pid_start_ticks: Option<u64>, timeout: Option<u64>) {
    let now = crate::vms::unix_now();
    let record = Transient {
        state: State::Stopping,
        pid,
        pid_start_ticks,
        since_secs: now,
        deadline_secs: timeout.map(|t| now.saturating_add(t)),
        by_pid: Some(std::process::id()),
        by_start_ticks: crate::vms::own_start_ticks(),
    };
    let _ = write(dir, &record);
}

/// The VM on `dir` is at rest or running: forget any transient state.
pub fn clear(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(FILE));
}

/// The transient state of the VM on `dir` that still holds, if any.
pub fn read(dir: &Path) -> Option<Transient> {
    match peek(dir)? {
        (record, Standing::Holds) => Some(record),
        _ => None,
    }
}

/// What is recorded for the VM on `dir`, and where it stands: a reader that writes nothing
/// tells a record that holds from one that is overdue or describes nothing with this.
pub fn peek(dir: &Path) -> Option<(Transient, Standing)> {
    let record = read_raw(dir)?;
    let standing = record.standing(
        crate::vms::unix_now(),
        record.process_there(),
        record.by_there(),
    );
    Some((record, standing))
}

/// Remove the record of the VM on `dir` if it describes nothing any more. An overdue one
/// is kept: its process is still there, and what to do about it is the user's call.
/// Whether one was removed.
pub fn clear_if_stale(dir: &Path) -> bool {
    match peek(dir) {
        Some((_, Standing::Gone)) => {
            clear(dir);
            true
        }
        _ => false,
    }
}

fn read_raw(dir: &Path) -> Option<Transient> {
    serde_json::from_slice(&std::fs::read(dir.join(FILE)).ok()?).ok()
}

fn write(dir: &Path, record: &Transient) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(record)?;
    crate::statefile::write_unsynced(&dir.join(FILE), &json)
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
        assert!(start.fresh(1001, Some(true)));
        assert!(start.fresh(1_000_000, Some(true)), "a long build");
        assert!(!start.fresh(1001, Some(false)), "its run is gone");
        assert!(start.fresh(1000 + STARTING_UNSEEN_SECS, None));
        assert!(!start.fresh(1001 + STARTING_UNSEEN_SECS, None));

        let stop = record(State::Stopping, Some(1210));
        assert!(stop.fresh(1210, Some(true)));
        assert!(!stop.fresh(1211, Some(true)), "the stop timed out");
        assert!(!stop.fresh(1100, Some(false)), "it went");
        // Timed out with its process still there is not the same as gone: it is overdue,
        // and stays on record until someone deals with it.
        assert_eq!(stop.standing(1211, Some(true), None), Standing::Overdue);
        assert_eq!(stop.standing(1211, Some(false), None), Standing::Gone);
        assert_eq!(stop.standing(1211, None, None), Standing::Gone);
        assert_eq!(start.standing(1_000_000, Some(true), None), Standing::Holds);
        // A stop with no timeout holds while the command waiting on it is there, and is
        // overdue the moment that command is gone — interrupted — with the run still up.
        let waited = record(State::Stopping, None);
        assert_eq!(
            waited.standing(9_000_000, Some(true), Some(true)),
            Standing::Holds
        );
        assert_eq!(
            waited.standing(1001, Some(true), Some(false)),
            Standing::Overdue
        );
        assert_eq!(
            waited.standing(1001, Some(false), Some(false)),
            Standing::Gone
        );
    }

    #[test]
    fn a_record_reads_back_until_cleared_and_a_dead_writer_leaves_none() {
        let dir = std::env::temp_dir().join(format!("vk-vmstate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read(&dir), None);
        starting(&dir);
        let got = read(&dir).expect("this process is starting it");
        assert_eq!((got.state, got.pid), (State::Starting, std::process::id()));
        assert_eq!(got.deadline_secs, None);
        clear(&dir);
        assert_eq!(read(&dir), None);

        // A stop of this process, which is still here: held until its deadline.
        stopping(
            &dir,
            std::process::id(),
            crate::vms::own_start_ticks(),
            Some(30),
        );
        let got = read(&dir).expect("stopping");
        assert_eq!(got.state, State::Stopping);
        assert_eq!(got.deadline_secs, Some(got.since_secs + 30));
        assert_eq!(
            got.by_pid,
            Some(std::process::id()),
            "this command waits on it"
        );
        // With no timeout: no deadline, held for as long as this command is there.
        stopping(
            &dir,
            std::process::id(),
            crate::vms::own_start_ticks(),
            None,
        );
        assert_eq!(read(&dir).expect("stopping").deadline_secs, None);
        assert!(!clear_if_stale(&dir), "it still holds");
        // A stop of this process whose deadline has passed: overdue, shown and kept.
        let overdue = Transient {
            state: State::Stopping,
            pid: std::process::id(),
            pid_start_ticks: crate::vms::own_start_ticks(),
            since_secs: 10,
            deadline_secs: Some(20),
            by_pid: None,
            by_start_ticks: None,
        };
        write(&dir, &overdue).unwrap();
        assert_eq!(read(&dir), None, "no longer under way");
        assert!(matches!(peek(&dir), Some((_, Standing::Overdue))));
        assert!(!clear_if_stale(&dir), "its process is still there");
        // A record naming a process that started at another time: not this one, so stale.
        stopping(&dir, std::process::id(), Some(1), Some(30));
        assert_eq!(read(&dir), None);
        assert!(
            matches!(peek(&dir), Some((_, Standing::Gone))),
            "there, and stale"
        );
        assert!(clear_if_stale(&dir));
        assert_eq!(peek(&dir), None);
        std::fs::remove_dir_all(&dir).unwrap();
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
