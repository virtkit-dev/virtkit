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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::console::{Batch, Tail};
use super::envs::{self, Env};
use crate::term::{self, Press};

/// How often a thread that is waiting looks at whether it has been stood down. A thread
/// that slept a whole refresh interval would hold the alternate screen for seconds after
/// the reader had left.
const TICK: Duration = Duration::from_millis(100);

/// How often the console is read. Fast enough that a boot scrolls rather than arrives in
/// blocks, slow enough that a guest flooding its console costs four reads a second.
const CONSOLE_TICK: Duration = Duration::from_millis(250);

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
    /// One pass of the selected environment's console.
    Log(Batch),
    /// What the selected environment's process tree is costing this host.
    Sample(Sample),
    /// Something could not be read. A line in the key bar, not the end of the session.
    Failed(String),
}

/// What one environment's whole process tree had cost the host at one moment.
///
/// `/proc` reports cumulative totals. Each reading includes an instant so rates use the
/// actual elapsed time between samples, which differs from the requested interval.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sample {
    /// which process tree it was taken for ([`Selected::sample_epoch`])
    pub(crate) epoch: u64,
    /// CPU time the tree has used, guest execution included
    pub(crate) cpu: Duration,
    /// the most memory the tree was ever seen to hold at once
    pub(crate) peak_rss: u64,
    /// `(read, written)` against the block layer, or `None` where the kernel accounts none
    pub(crate) disk: Option<(u64, u64)>,
    pub(crate) at: Instant,
}

/// Which environment the threads that follow the selection are pointed at.
///
/// Each pass carries the selection epoch it began with. Discarding stale passes prevents
/// one guest's console appearing under another guest's name for a tick after selection moves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Selected {
    /// which selection the console is being read for
    pub(crate) epoch: u64,
    /// the same for the sampler, which moves on its own when an environment is restarted in
    /// place: the console of the boot that ended is still what the reader wants, and a
    /// reading of the process tree that ended is not
    pub(crate) sample_epoch: u64,
    /// the state directory, or nothing when there is no environment to follow
    pub(crate) dir: Option<PathBuf>,
    /// the pid at the root of its process tree, or nothing when it is not running
    pub(crate) pid: Option<i32>,
}

/// Where the threads that follow the selection read it from. The loop writes it; they read.
#[derive(Debug, Clone, Default)]
pub(crate) struct Follow(Arc<Mutex<Selected>>);

impl Follow {
    /// Point the following threads at this environment.
    pub(crate) fn point_at(&self, selected: Selected) {
        // A lock is poisoned only by a panic while it is held, and nothing here panics
        // holding it; taking the value back is better than losing the selection over it.
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *held = selected;
    }

    fn get(&self) -> Selected {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
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

/// Follow the console of whichever environment is selected, until told to stop.
///
/// One thread for every selection rather than one per environment: the reader looks at one
/// console at a time, and a `j` held down would otherwise open a descriptor on every
/// environment it passed through.
pub(crate) fn spawn_console(tx: Sender<Event>, stop: Stop, follow: Follow) {
    std::thread::spawn(move || {
        let mut epoch: Option<u64> = None;
        let mut tail: Option<Tail> = None;
        // Whether the dashboard has been told there is no console. Sending that once, and
        // again only when it changes, is what lets the pane say "this has never booted"
        // instead of looking as though a console were on its way.
        let mut told: Option<bool> = None;
        while !stop.raised() {
            let target = follow.get();
            if epoch != Some(target.epoch) {
                epoch = Some(target.epoch);
                tail = target.dir.as_deref().map(Tail::new);
                told = None;
            }
            if let (Some(epoch), Some(tail)) = (epoch, tail.as_mut()) {
                let batch = tail.drain(epoch);
                let speak =
                    !batch.lines.is_empty() || batch.restarted || told != Some(batch.missing);
                told = Some(batch.missing);
                if speak && tx.send(Event::Log(batch)).is_err() {
                    return; // the dashboard is gone
                }
            }
            stop.sleep(CONSOLE_TICK);
        }
    });
}

/// Read what the selected environment's process tree is costing the host, on a timer.
///
/// The same `/proc` walk `vk list` does for its memory column, and the reason it is here
/// rather than on the refresher: it is taken for one environment, and it has to be taken
/// again as soon as the reader selects another — a pane that waited out the whole interval
/// before saying anything reads as a pane that is broken.
pub(crate) fn spawn_sampler(tx: Sender<Event>, stop: Stop, follow: Follow, every: Duration) {
    std::thread::spawn(move || {
        let mut epoch: Option<u64> = None;
        let mut taken: Option<Instant> = None;
        while !stop.raised() {
            let target = follow.get();
            let due = taken.is_none_or(|at| at.elapsed() >= every);
            if epoch == Some(target.sample_epoch) && !due {
                std::thread::sleep(TICK);
                continue;
            }
            epoch = Some(target.sample_epoch);
            taken = Some(Instant::now());
            if let Some(pid) = target.pid
                && let Some(usage) = crate::usage::tree(pid)
            {
                let sample = Sample {
                    epoch: target.sample_epoch,
                    cpu: usage.cpu,
                    peak_rss: usage.peak_rss,
                    disk: usage.disk,
                    // Read after the walk, not before it: the walk is what took the time,
                    // and the rate is only as honest as the interval it is divided by.
                    at: Instant::now(),
                };
                if tx.send(Event::Sample(sample)).is_err() {
                    return; // the dashboard is gone
                }
            }
            std::thread::sleep(TICK);
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
