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
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::console::{Batch, Tail};
use super::envs::{self, Env};
use super::guest::{self, Began, Source, Spawner};
use crate::term::{self, Press};

/// How often a thread that is waiting looks at whether it has been stood down. A thread
/// that slept a whole refresh interval would hold the alternate screen for seconds after
/// the reader had left.
const TICK: Duration = Duration::from_millis(100);

/// How often the console is read. Fast enough that a boot scrolls rather than arrives in
/// blocks, slow enough that a guest flooding its console costs four reads a second.
const CONSOLE_TICK: Duration = Duration::from_millis(250);

/// How often the guest's own recording is looked at for samples it has committed. Well
/// under the shortest interval it can be asked to sample at, so one shows up as it lands.
const GUEST_TICK: Duration = Duration::from_millis(400);

/// How long the guest goes on recording itself after the reader has left the pane that
/// shows it. It costs the guest a sampler, so it does not run for ever unwatched — and it
/// is not restarted by a reader flipping between two panes either.
const LINGER: Duration = Duration::from_secs(30);

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
    /// What the selected environment's guest makes of itself.
    Guest {
        /// which process tree it was read for ([`Selected::sample_epoch`])
        epoch: u64,
        guest: Guest,
    },
    /// What removing an environment would take with it, for the question that asks.
    Preview {
        /// the environment it was read for, so an answer that arrives after the reader has
        /// moved on is dropped rather than shown under another name
        name: String,
        text: String,
    },
    /// How an action went, in the words the key bar has room for.
    Said(String),
    /// Something could not be read. A line in the key bar, not the end of the session.
    Failed(String),
}

/// The guest's own account of itself, as far as it has got.
#[derive(Debug)]
pub(crate) enum Guest {
    /// asked for, and nothing has come back yet
    Starting,
    /// its own recording is not there to read yet, and is being waited for, in the words the
    /// last look at it failed with
    Waiting(String),
    /// one sample, exactly as the guest recorded it. Boxed because it is much the largest
    /// thing the channel carries and every other event would be sized by it.
    Sample(Box<crate::atoplog::Sample>),
    /// it could not be had, in the words it failed with
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
    /// how to reach its guest, or nothing when there is no VM to reach
    pub(crate) guest: Option<GuestAddr>,
    /// whether the pane that draws the guest's own figures is showing. The guest is only
    /// asked for them while somebody is looking at them.
    pub(crate) want_guest: bool,
}

/// What it takes to get a guest's own figures: where its agent answers, where its recording
/// goes, and whether it is already recording itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestAddr {
    pub(crate) exec_addr: String,
    pub(crate) state_dir: PathBuf,
    /// The log a VM booted with `vk run --atop` is writing for itself.
    pub(crate) own_log: Option<PathBuf>,
}

impl GuestAddr {
    /// Where this environment's own figures are to come from.
    fn source(&self) -> Source {
        match &self.own_log {
            // A VM recording itself is read and never attached to: an attach truncates the
            // log it lays down, which would cut a running job's recording in half. That
            // holds for a log that is not there *yet* as well — it appears when the guest
            // first writes through the share — so the answer is still to read it, and the
            // reading waits for it.
            Some(log) => Source::Own(log.clone()),
            None => Source::Attached,
        }
    }
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

/// The terminal's reader as the loop holds it: the flag that stands it down, and the thread
/// itself, because standing it down is not the same as it being finished — the read it is
/// inside can still be holding a key.
pub(crate) struct Reader {
    stop: Stop,
    thread: JoinHandle<()>,
}

impl Reader {
    /// Stand the reader down and leave it to notice, for the way out: the process is going
    /// and nothing is waiting on stdin after it.
    pub(crate) fn raise(&self) {
        self.stop.raise();
    }

    /// Stand it down and wait until it is out of stdin, for a caller that is about to give
    /// stdin to a child: two readers on one terminal lose keystrokes between them.
    pub(crate) fn stand_down(self) {
        self.stop.raise();
        // A reader that panicked has already been reported by the hook; what matters here
        // is only that it is no longer reading.
        let _ = self.thread.join();
    }
}

/// A thread the loop can stand down by itself, apart from the [`Stop`] that ends them all.
/// The guest recorder is one: `a` hands the terminal to a `vk atop --follow` that wants the
/// same log, so the dashboard has to have let go of it before the child is started.
pub(crate) struct Watcher {
    stop: Stop,
    thread: JoinHandle<()>,
}

impl Watcher {
    /// Stand it down and wait until it has let go of what it was holding.
    pub(crate) fn stand_down(self) {
        self.stop.raise();
        // A thread that panicked has already been reported by the hook; what matters here
        // is only that it is no longer holding a recording.
        let _ = self.thread.join();
    }
}

/// Forward the terminal's keys into the one channel the loop reads.
pub(crate) fn spawn_keys(tx: Sender<Event>) -> Reader {
    let stop = Stop::new();
    let (keys, reading) = term::key_thread_until(Arc::clone(&stop.0));
    let thread = std::thread::spawn(move || {
        for press in keys {
            if tx.send(Event::Key(press)).is_err() {
                break; // the dashboard is gone
            }
        }
        // The reader is the thread holding stdin, so whoever waits for this one is waiting
        // for that one.
        let _ = reading.join();
    });
    Reader { stop, thread }
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

/// Record the selected environment's guest, and read back what it records, for as long as
/// the pane that draws it is up.
///
/// One thread for every selection, like the console's, and for the same reason. Unlike the
/// console's, this one *asks the guest for something* — a sampler running inside it — so it
/// is started only while somebody is looking at the pane, stopped when the process tree it
/// was started for ends, and let go of once the reader has been away from the pane for
/// [`LINGER`]. Letting go is all it takes to end it: the connection closes with it, and a
/// guest whose exec channel hangs up has its sampler killed.
pub(crate) fn spawn_guest(
    tx: Sender<Event>,
    follow: Follow,
    spawner: Arc<dyn Spawner>,
    interval: Duration,
) -> Watcher {
    let stop = Stop::new();
    let mine = stop.clone();
    let thread = std::thread::spawn(move || {
        // A recording is asked for in whole seconds, and zero is not one of them.
        let every = interval.as_secs().max(1);
        let mut epoch: Option<u64> = None;
        let mut watch = Watch::Idle;
        // When the reader left the pane, for as long as the recording is being kept on
        // anyway. `None` while they are on it, and while there is nothing to keep.
        let mut left_at: Option<Instant> = None;
        while !mine.raised() {
            let target = follow.get();
            if epoch != Some(target.sample_epoch) {
                // Another process tree: the recording of the one that ended is of a guest
                // that is not there any more, and letting go of it is what ends it.
                epoch = Some(target.sample_epoch);
                watch = Watch::Idle;
                left_at = None;
            }
            let keep;
            (keep, left_at) = keeping(
                target.want_guest,
                !matches!(watch, Watch::Idle),
                left_at,
                Instant::now(),
            );
            match target.guest.as_ref().filter(|_| keep) {
                // Nothing to record, or nobody looking: letting go of the watch is what
                // ends whatever it was holding.
                None => watch = Watch::Idle,
                Some(addr) => {
                    let was = std::mem::replace(&mut watch, Watch::Idle);
                    match step(was, &tx, epoch.unwrap_or_default(), addr, &*spawner, every) {
                        Some(next) => watch = next,
                        None => return, // the dashboard is gone
                    }
                }
            }
            mine.sleep(GUEST_TICK);
        }
    });
    Watcher { stop, thread }
}

/// Whether to go on recording, and since when the reader has been away from the pane.
///
/// The recording is kept for [`LINGER`] after they leave it, so flipping between two panes
/// does not stop and start a sampler inside somebody's guest over and over — and dropped
/// after that, because a sampler is not a thing to leave running for a reader who has
/// stopped reading. A pane never visited leaves the guest alone from the start.
fn keeping(
    want: bool,
    watching: bool,
    left_at: Option<Instant>,
    now: Instant,
) -> (bool, Option<Instant>) {
    if want {
        return (true, None);
    }
    let left_at = match (left_at, watching) {
        (None, true) => Some(now),
        (at, _) => at,
    };
    let keep = left_at.is_some_and(|at| now.duration_since(at) < LINGER);
    (keep, left_at)
}

/// What the thread above is doing for the environment it is pointed at.
enum Watch {
    /// nothing: nothing selected, nothing running, or nobody looking
    Idle,
    /// a recording was asked for and has not said where it is writing yet
    Starting(guest::Session),
    /// a VM records itself, and its log has yet to appear: looked at again every tick
    Waiting(PathBuf),
    /// samples are being read, holding the recording they come from where there is one
    Reading {
        /// Held for exactly as long as the samples are wanted: this is the recording, and
        /// dropping it ends it. `None` for a guest already recording itself.
        held: Option<guest::Session>,
        tail: crate::atop_view::Tail,
    },
    /// it could not be had, and saying so every tick would be noise
    Failed,
}

/// One step of following a guest: what the watch was, and what it is now. `None` where the
/// dashboard is gone and there is nobody left to tell.
fn step(
    watch: Watch,
    tx: &Sender<Event>,
    epoch: u64,
    addr: &GuestAddr,
    spawner: &dyn Spawner,
    interval_secs: u64,
) -> Option<Watch> {
    match watch {
        Watch::Idle => {
            say(tx, epoch, Guest::Starting)?;
            match addr.source() {
                Source::Own(log) => open_own(tx, epoch, log),
                Source::Attached => Some(Watch::Starting(guest::Session::start(
                    spawner,
                    &addr.exec_addr,
                    &addr.state_dir,
                    interval_secs,
                ))),
            }
        }
        Watch::Starting(recording) => match recording.began() {
            Began::Starting => Some(Watch::Starting(recording)),
            Began::At(log) => read_from(tx, epoch, &log, recording),
            Began::Failed(why) => {
                say(tx, epoch, Guest::Failed(retryable(why)))?;
                Some(Watch::Failed)
            }
        },
        Watch::Waiting(log) => open_own(tx, epoch, log),
        Watch::Reading { held, mut tail } => match tail.read() {
            Ok(samples) => {
                for sample in samples {
                    say(tx, epoch, Guest::Sample(Box::new(sample)))?;
                }
                Some(Watch::Reading { held, tail })
            }
            Err(report) => {
                say(tx, epoch, Guest::Failed(retryable(format!("{report:#}"))))?;
                Some(Watch::Failed)
            }
        },
        Watch::Failed => Some(Watch::Failed),
    }
}

/// Start reading the recording a VM is making of itself, or wait for it to appear.
///
/// The log a `vk run --atop` VM writes shows up when its guest first writes through the
/// share, which is after the job the reader is watching has started. Not being there is a
/// wait and never a failure: the alternative — attaching — would truncate that recording
/// the moment it landed.
fn open_own(tx: &Sender<Event>, epoch: u64, log: PathBuf) -> Option<Watch> {
    match crate::atop_view::Tail::open(&log) {
        Ok(tail) => Some(Watch::Reading { held: None, tail }),
        Err(report) => {
            say(tx, epoch, Guest::Waiting(format!("{report:#}")))?;
            Some(Watch::Waiting(log))
        }
    }
}

/// Start reading a recording that was asked for, or say why it cannot be read.
fn read_from(
    tx: &Sender<Event>,
    epoch: u64,
    log: &std::path::Path,
    held: guest::Session,
) -> Option<Watch> {
    match crate::atop_view::Tail::open(log) {
        Ok(tail) => Some(Watch::Reading {
            held: Some(held),
            tail,
        }),
        Err(report) => {
            say(tx, epoch, Guest::Failed(retryable(format!("{report:#}"))))?;
            Some(Watch::Failed)
        }
    }
}

/// Say a failure with the way out of it. A recording that could not be had is not asked for
/// again until the reader has been off the pane for [`LINGER`], so the pane would otherwise
/// read as a dead end for the rest of the session.
fn retryable(why: String) -> String {
    format!(
        "{why} — leave this pane for {}s and come back to ask again",
        LINGER.as_secs()
    )
}

/// Tell the dashboard, or say that there is no dashboard left to tell.
fn say(tx: &Sender<Event>, epoch: u64, guest: Guest) -> Option<()> {
    tx.send(Event::Guest { epoch, guest }).ok()
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

/// Read what removing these environments would take with it, for the question that asks
/// before one is removed.
///
/// On a thread for the same reason every other walk is: `preview` totals each top-level
/// entry of every state directory it is given, which means stat-ing an image and a server
/// tree — measured in seconds on a cold cache, and the reader pressed a key.
pub(crate) fn spawn_preview(rows: Vec<crate::dev::list::Row>, name: String, tx: Sender<Event>) {
    std::thread::spawn(move || {
        let text = crate::dev::list::preview(&rows);
        // A send that fails means the dashboard is gone, and this thread is finished
        // either way.
        let _ = tx.send(Event::Preview { name, text });
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

    /// A recording outlasts a glance at another pane, and not a reader who has left: a
    /// sampler running inside somebody's guest is not something to leave behind, and
    /// restarting one every time `1` and `3` are pressed is not something to do either.
    #[test]
    fn a_recording_outlasts_a_glance_at_another_pane_and_not_a_reader_who_left() {
        let now = Instant::now();
        let later = |secs| now + Duration::from_secs(secs);

        // On the pane: kept, with nothing to time.
        assert_eq!(keeping(true, true, None, now), (true, None));
        // A pane never visited asks the guest for nothing at all.
        assert_eq!(keeping(false, false, None, now), (false, None));
        // Left with a recording under way: kept, and the clock starts.
        assert_eq!(keeping(false, true, None, now), (true, Some(now)));
        assert!(keeping(false, true, Some(now), later(1)).0, "a glance away");
        assert!(
            !keeping(false, true, Some(now), later(LINGER.as_secs() + 1)).0,
            "it was kept for a reader who had gone"
        );
        // Coming back takes it up again.
        assert_eq!(keeping(true, false, Some(now), later(60)), (true, None));
    }

    /// What the thread that follows a guest is pointed at, as the loop points it.
    fn guest_target(epoch: u64, want: bool, own_log: Option<PathBuf>) -> Selected {
        Selected {
            epoch,
            sample_epoch: epoch,
            dir: Some(PathBuf::from("/state/a")),
            pid: Some(42),
            guest: Some(GuestAddr {
                exec_addr: "vsock-auto:///state/a/vsock.sock:4444".to_string(),
                state_dir: PathBuf::from("/state/a"),
                own_log,
            }),
            want_guest: want,
        }
    }

    /// One sample as a guest recording itself writes one.
    fn own_recording() -> &'static str {
        "RESET\n\
         CPU guest 1000 1970/01/01 00:16:40 30 100 1 10 20 0 700 0 0 0 0 0 0 100 0 0\n\
         SEP\n"
    }

    /// Wait for something to become true, or give up rather than hang the suite.
    fn until(mut ready: impl FnMut() -> bool) -> bool {
        for _ in 0..150 {
            if ready() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// The guest is asked for a recording once the pane is up, once per process tree, and
    /// the recording is let go of when that tree ends and when the dashboard does.
    #[test]
    fn a_guest_is_recorded_once_per_process_tree_and_let_go_of_with_it() {
        let (tx, rx) = mpsc::channel();
        let follow = Follow::default();
        let fake = Arc::new(guest::fixture::Fake::new(Began::Starting));
        let watcher = spawn_guest(
            tx,
            follow.clone(),
            Arc::clone(&fake) as Arc<dyn Spawner>,
            Duration::from_secs(1),
        );

        // Nobody is looking at the pane, so nothing is asked of the guest.
        follow.point_at(guest_target(1, false, None));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(fake.started(), 0, "a guest was recorded unwatched");

        // Showing the pane asks for one, and asking twice would be two samplers.
        follow.point_at(guest_target(1, true, None));
        assert!(until(|| fake.started() == 1), "the pane asked for nothing");
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            fake.started(),
            1,
            "the recording was restarted under a reader"
        );
        assert_eq!(fake.dropped(), 0);

        // Another process tree is another guest: the first recording goes, and the new tree
        // is asked for its own.
        follow.point_at(guest_target(2, true, None));
        assert!(
            until(|| fake.started() == 2 && fake.dropped() == 1),
            "the recording of the tree that ended was kept"
        );

        watcher.stand_down();
        assert_eq!(fake.dropped(), 2, "a sampler was left running in the guest");
        assert!(
            rx.try_iter().any(|event| matches!(
                event,
                Event::Guest {
                    guest: Guest::Starting,
                    ..
                }
            )),
            "the pane was never told it was being asked for"
        );
    }

    /// A VM already recording itself is read and never attached to. Attaching truncates the
    /// log it lays down, which would cut the recording of a job still running in half.
    #[test]
    fn a_guest_recording_itself_is_read_and_never_attached_to() {
        let dir = std::env::temp_dir().join(format!("vk-dash-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("atop.log");
        let text = own_recording();
        std::fs::write(&log, text).unwrap();

        let (tx, rx) = mpsc::channel();
        let follow = Follow::default();
        let fake = Arc::new(guest::fixture::Fake::new(Began::Starting));
        let watcher = spawn_guest(
            tx,
            follow.clone(),
            Arc::clone(&fake) as Arc<dyn Spawner>,
            Duration::from_secs(1),
        );
        follow.point_at(guest_target(1, true, Some(log.clone())));

        let mut sampled = false;
        while let Ok(event) = rx.recv_timeout(Duration::from_secs(5)) {
            if let Event::Guest { guest, .. } = &event {
                match guest {
                    Guest::Sample(_) => {
                        sampled = true;
                        break;
                    }
                    Guest::Failed(why) => panic!("its own recording was not read: {why}"),
                    Guest::Starting | Guest::Waiting(_) => {}
                }
            }
        }
        watcher.stand_down();
        assert!(sampled, "nothing was read out of the guest's own recording");
        assert_eq!(fake.started(), 0, "a VM recording itself was attached to");
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            text,
            "its own recording was truncated"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A VM recording itself is watched from before its log exists. The share it writes
    /// through carries nothing until its guest first writes to it, and a pane opened in that
    /// window used to settle on "No such file or directory" for the rest of the session —
    /// while attaching instead would truncate the job's recording the moment it landed.
    #[test]
    fn a_guests_own_recording_is_waited_for_until_it_appears() {
        let dir = std::env::temp_dir().join(format!("vk-dash-late-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("atop.log");

        let (tx, rx) = mpsc::channel();
        let follow = Follow::default();
        let fake = Arc::new(guest::fixture::Fake::new(Began::Starting));
        let watcher = spawn_guest(
            tx,
            follow.clone(),
            Arc::clone(&fake) as Arc<dyn Spawner>,
            Duration::from_secs(1),
        );
        follow.point_at(guest_target(1, true, Some(log.clone())));

        // Nothing there yet: the pane is told it is being waited for, not that it failed.
        let waited = loop {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(Event::Guest {
                    guest: Guest::Waiting(_),
                    ..
                }) => break true,
                Ok(Event::Guest {
                    guest: Guest::Failed(why),
                    ..
                }) => panic!("a log still to appear was given up on: {why}"),
                Ok(_) => {}
                Err(_) => break false,
            }
        };
        assert!(waited, "a log that is not there yet was never waited for");

        // And it is taken up as soon as the guest writes it.
        std::fs::write(&log, own_recording()).unwrap();
        let mut sampled = false;
        while let Ok(event) = rx.recv_timeout(Duration::from_secs(5)) {
            if let Event::Guest {
                guest: Guest::Sample(_),
                ..
            } = &event
            {
                sampled = true;
                break;
            }
        }
        watcher.stand_down();
        assert!(sampled, "the log that appeared was never read");
        assert_eq!(fake.started(), 0, "a VM recording itself was attached to");
        std::fs::remove_dir_all(&dir).unwrap();
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
