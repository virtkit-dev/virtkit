//! Everything that takes time, moved off the thread that draws.
//!
//! One rule shapes this module: **a slow read must never be a slow keystroke.** Listing the
//! environments walks a directory tree and reads a registry, either of which can sit behind
//! a filesystem that is not answering — a VM whose share is wedged is exactly what a reader
//! opens the dashboard to look into. Done between two frames, that would freeze the
//! dashboard precisely when it is needed.
//!
//! So nothing blocking happens on the drawing thread. Each concern gets a thread of its own
//! and they all feed one [`Event`] channel, which the loop reads with `recv_timeout` and
//! repaints from. A read that fails becomes an [`Event::Failed`] and a line in the key bar,
//! never a crash and never a stall.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::Duration;

use super::envs::{self, Env};
use crate::term::{self, Press};

/// How often a thread that is waiting looks at whether it has been stood down. A thread
/// that slept a whole refresh interval would hold the alternate screen for seconds after
/// the reader had left.
const TICK: Duration = Duration::from_millis(100);

/// Everything the loop reacts to, from whichever thread noticed it.
#[derive(Debug)]
pub(crate) enum Event {
    /// A key, from the terminal's own reader.
    Key(Press),
    /// A completed re-read of the environment list.
    Envs(Vec<Env>),
    /// What each state directory holds on disk, which is asked for by a key rather than by
    /// a timer.
    Sizes(Vec<(PathBuf, u64)>),
    /// Something could not be read. A line in the key bar, not the end of the session.
    Failed(String),
}

/// The flag every background thread watches, so leaving stops them all — and so a caller
/// about to hand the terminal to a child can stand the key reader down first.
#[derive(Debug, Clone, Default)]
pub(crate) struct Stop(Arc<AtomicBool>);

impl Stop {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn raise(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn raised(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Sleep, waking often enough to notice that it is over.
    fn sleep(&self, total: Duration) {
        let mut slept = Duration::ZERO;
        while slept < total {
            if self.raised() {
                return;
            }
            std::thread::sleep(TICK);
            slept = slept.saturating_add(TICK);
        }
    }
}

/// Forward the terminal's keys into the one channel the loop reads.
pub(crate) fn spawn_keys(tx: Sender<Event>, stop: &Stop) {
    let keys = term::key_thread_until(Arc::clone(&stop.0));
    std::thread::spawn(move || {
        for press in keys {
            if tx.send(Event::Key(press)).is_err() {
                return; // the dashboard is gone
            }
        }
    });
}

/// Re-read the environment list on a timer until told to stop.
pub(crate) fn spawn_refresher(tx: Sender<Event>, every: Duration, stop: Stop) {
    std::thread::spawn(move || {
        while !stop.raised() {
            if tx.send(refresh()).is_err() {
                return;
            }
            stop.sleep(every);
        }
    });
}

/// Re-read it once, now, because something asked: the `r` key, or an action that has just
/// changed what there is to read.
pub(crate) fn refresh_once(tx: Sender<Event>) {
    std::thread::spawn(move || {
        // A send that fails means the dashboard is gone, and this thread is finished
        // either way.
        let _ = tx.send(refresh());
    });
}

/// Total what each of these state directories holds on disk.
///
/// Its own thread and its own key, because this is the expensive one: it stats every file
/// in every environment, which on a host with a few of them takes seconds. On the refresh
/// timer it would make the dashboard unusable, which is why the timer path asks for no
/// sizes at all.
pub(crate) fn spawn_size_walk(dirs: Vec<PathBuf>, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let sizes = dirs
            .into_iter()
            .map(|dir| {
                let bytes = crate::dev::storage::dir_size(&dir);
                (dir, bytes)
            })
            .collect();
        // A send that fails means the dashboard is gone, and this thread is finished
        // either way.
        let _ = tx.send(Event::Sizes(sizes));
    });
}

/// One pass of both listings, joined — or the reason it did not happen.
fn refresh() -> Event {
    // One read of the VM registry for both halves of the join: reading it walks every entry
    // and prunes the dead ones, which is not work to do twice a pass.
    let vms = crate::vms::running();
    let running = crate::dev::list::running_vms(&vms);
    let rows = match crate::dev::list::state_with(&running, false) {
        Ok(rows) => rows,
        Err(report) => return Event::Failed(format!("{report:#}")),
    };
    let mut envs = envs::join(rows, vms);
    // A VM with no environment behind it had no row to carry its cost. The listing measured
    // its tree all the same, so the figure is looked up rather than walked a second time.
    for env in &mut envs {
        if env.mem_used.is_some() {
            continue;
        }
        env.mem_used = running
            .iter()
            .find(|vm| crate::vms::canonical(&vm.state_dir) == env.dir)
            .and_then(|vm| vm.mem_used);
    }
    Event::Envs(envs)
}

#[cfg(test)]
mod tests {
    // An assertion is how a test reports; the panic lints this module gates on exist to
    // keep a live terminal intact, which no test has.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use std::sync::mpsc;

    /// Leaving ends a sleeping thread promptly, so `q` puts the terminal back rather than
    /// holding the alternate screen for a refresh interval.
    #[test]
    fn leaving_wakes_a_sleeping_thread() {
        let stop = Stop::new();
        let waiter = stop.clone();
        let started = std::time::Instant::now();
        let handle = std::thread::spawn(move || waiter.sleep(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(150));
        stop.raise();
        handle.join().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the thread slept on"
        );
    }

    /// A directory that is not there totals nothing, rather than failing the walk that was
    /// asked for every other one.
    #[test]
    fn a_size_walk_answers_for_every_directory_it_was_given() {
        let (tx, rx) = mpsc::channel();
        spawn_size_walk(
            vec![
                PathBuf::from("/nonexistent/one"),
                PathBuf::from("/nonexistent/two"),
            ],
            tx,
        );
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Event::Sizes(sizes)) => assert_eq!(sizes.len(), 2),
            other => panic!("a size walk produced {other:?}"),
        }
    }
}
