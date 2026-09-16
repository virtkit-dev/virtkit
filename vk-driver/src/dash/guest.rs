//! Where the guest's own figures come from.
//!
//! The dashboard already knows what a VM costs this host. What the guest makes of *itself*
//! is a different account and only the guest can give it: `vk-agent atop` sampling inside
//! it, writing the records [`crate::atoplog`] reads back. [`crate::dash::pane::guest`] draws
//! them; this is what gets them onto the host.
//!
//! Two ways in, and which one it is matters. A VM booted with `vk run --atop` is already
//! sampling itself into a log of its own: that one is read and never attached to, because an
//! attach truncates the log it lays down and would cut a running job's recording in half.
//! Every other VM is asked, over its exec channel, for a recording that lives exactly as
//! long as the reader is looking at it — letting go of it ends the connection, and a guest
//! whose exec channel hangs up has its sampler killed with the rest of its process group.
//!
//! Asking is asynchronous and the dashboard's threads are not, so it goes through a
//! [`Spawner`]: the real one puts the attach on the runtime `vk dash` was called from, and a
//! test hands over one that answers without a VM.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use tokio_util::sync::CancellationToken;

/// How long a drop waits for the recording to have been let go of, and how often it looks.
/// `a` hands the terminal to a `vk atop --follow` that takes the same lock on the same log,
/// and it would be refused for as long as this process still held it.
const LET_GO: Duration = Duration::from_secs(2);
const LET_GO_STEP: Duration = Duration::from_millis(5);

/// Where a selected environment's own figures are to come from.
pub(crate) enum Source {
    /// It records itself (`vk run --atop`): read that log, and start nothing.
    Own(PathBuf),
    /// Nothing records it: ask its guest for a recording of its own.
    Attached,
}

/// How far a recording that was asked for has got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Began {
    /// asked for, and the guest has not answered yet
    Starting,
    /// under way, writing here
    At(PathBuf),
    /// it could not be started, in the words it failed with
    Failed(String),
}

/// How a recording is started. The dashboard's own attaches to a real VM over its exec
/// channel; a test's answers without one.
pub(crate) trait Spawner: Send + Sync {
    /// Start recording the guest at `addr` into `state_dir`, saying through `began` where it
    /// gets to. The recording ends when the returned handle is dropped, which is the only
    /// thing that handle is for.
    fn start(
        &self,
        addr: String,
        state_dir: PathBuf,
        interval_secs: u64,
        began: Arc<Mutex<Began>>,
    ) -> Stopper;
}

/// What a [`Spawner`] hands back: the recording, held. Dropping it is what ends the
/// recording, and there is nothing else to do with it — which is why what is inside is
/// each spawner's own business and none of the holder's.
pub(crate) struct Stopper {
    _held: Box<dyn Send>,
}

impl Stopper {
    pub(crate) fn new(held: impl Send + 'static) -> Stopper {
        Stopper {
            _held: Box::new(held),
        }
    }
}

/// A recording the dashboard asked for, ended by letting go of it. Named apart from
/// [`crate::atop_attach::Recording`], which is the recording itself: this is the
/// dashboard's side of asking for one.
pub(crate) struct Session {
    began: Arc<Mutex<Began>>,
    /// Dropping this is what ends the recording; it is held for nothing else.
    _stop: Stopper,
}

impl Session {
    /// Ask for one.
    pub(crate) fn start(
        spawner: &dyn Spawner,
        addr: &str,
        state_dir: &Path,
        interval_secs: u64,
    ) -> Session {
        let began = Arc::new(Mutex::new(Began::Starting));
        let stop = spawner.start(
            addr.to_string(),
            state_dir.to_path_buf(),
            interval_secs,
            Arc::clone(&began),
        );
        Session { began, _stop: stop }
    }

    /// How far it has got.
    pub(crate) fn began(&self) -> Began {
        read(&self.began)
    }
}

/// What a shared progress cell says. A lock is poisoned only by a panic while it is held,
/// and nothing here panics holding one; taking the value back is better than losing the
/// recording over it.
fn read(began: &Mutex<Began>) -> Began {
    began
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn write(began: &Mutex<Began>, value: Began) {
    *began
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

/// The spawner the dashboard runs with: the attach goes on the runtime `vk dash` was called
/// from, whose workers are free — the thread that draws blocks and awaits nothing.
pub(crate) struct OnRuntime(tokio::runtime::Handle);

impl OnRuntime {
    pub(crate) fn new(handle: tokio::runtime::Handle) -> Self {
        Self(handle)
    }
}

impl Spawner for OnRuntime {
    fn start(
        &self,
        addr: String,
        state_dir: PathBuf,
        interval_secs: u64,
        began: Arc<Mutex<Began>>,
    ) -> Stopper {
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let stop = CancellationToken::new();
        let mine = stop.clone();
        self.0.spawn(async move {
            // Set wherever this future ends, and last of everything here: what it says is
            // that the recording — and the lock on its log — has been let go of.
            let _done = Done(flag);
            let attach = async {
                let addr = addr
                    .parse()
                    .with_context(|| crate::atop_attach::exec_addr_context(&addr))?;
                // No stderr relay: this process is drawing on the terminal, and what the
                // guest sampler complains about would land in the middle of a frame.
                crate::atop_attach::start(&addr, &state_dir, interval_secs, false).await
            };
            let started = tokio::select! {
                // Let go of before it was ever under way. Dropping the attach is enough to
                // end it: a half-started recording ends with the future that owns it.
                () = mine.cancelled() => return,
                started = attach => started,
            };
            match started {
                Ok(recording) => {
                    write(&began, Began::At(recording.log.clone()));
                    mine.cancelled().await;
                    // Ended in full rather than by dropping it: this returns only once the
                    // file holding the log's lock has gone, which is what the wait in
                    // `Stop`'s drop is waiting for.
                    recording.stop_now().await;
                }
                Err(report) => write(&began, Began::Failed(format!("{report:#}"))),
            }
        });
        Stopper::new(Stop { stop, done })
    }
}

/// The handle the dashboard holds while it wants the recording.
struct Stop {
    stop: CancellationToken,
    done: Arc<AtomicBool>,
}

impl Drop for Stop {
    fn drop(&mut self) {
        self.stop.cancel();
        // Waited for rather than left to happen: the letting go is carried out on a runtime
        // thread, and what comes next may be a `vk atop` wanting the very log this is still
        // holding. Bounded all the same — a guest that has stopped answering costs a reader
        // leaving the pane a moment, never the session.
        for _ in 0..(LET_GO.as_millis() / LET_GO_STEP.as_millis().max(1)) {
            if self.done.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(LET_GO_STEP);
        }
    }
}

/// Raises the flag above when the task's future is dropped, which is after the recording it
/// held has been let go of.
struct Done(Arc<AtomicBool>);

impl Drop for Done {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// A spawner that starts nothing, for the tests of everything built on one.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Answers with what it was told to and counts what was asked of it.
    pub(crate) struct Fake {
        /// what a recording asked of this reports as soon as it is asked for
        pub(crate) answer: Began,
        pub(crate) started: Arc<AtomicUsize>,
        pub(crate) dropped: Arc<AtomicUsize>,
    }

    impl Fake {
        pub(crate) fn new(answer: Began) -> Fake {
            Fake {
                answer,
                started: Arc::new(AtomicUsize::new(0)),
                dropped: Arc::new(AtomicUsize::new(0)),
            }
        }

        pub(crate) fn started(&self) -> usize {
            self.started.load(Ordering::Relaxed)
        }

        pub(crate) fn dropped(&self) -> usize {
            self.dropped.load(Ordering::Relaxed)
        }
    }

    impl Spawner for Fake {
        fn start(
            &self,
            _addr: String,
            _state_dir: PathBuf,
            _interval_secs: u64,
            began: Arc<Mutex<Began>>,
        ) -> Stopper {
            self.started.fetch_add(1, Ordering::Relaxed);
            write(&began, self.answer.clone());
            Stopper::new(Counter(Arc::clone(&self.dropped)))
        }
    }

    struct Counter(Arc<AtomicUsize>);

    impl Drop for Counter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
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

    /// A recording reports what the spawner made of it, and ends when it is let go of —
    /// which is the whole of how the dashboard stops asking a guest for samples.
    #[test]
    fn a_recording_ends_when_it_is_let_go_of() {
        let spawner = fixture::Fake::new(Began::At(PathBuf::from("/state/a/atop/atop.log")));
        let recording = Session::start(
            &spawner,
            "vsock-auto:///state/a/vsock.sock:4444",
            Path::new("/state/a"),
            3,
        );
        assert_eq!(spawner.started(), 1);
        assert_eq!(
            recording.began(),
            Began::At(PathBuf::from("/state/a/atop/atop.log"))
        );
        assert_eq!(spawner.dropped(), 0);
        drop(recording);
        assert_eq!(spawner.dropped(), 1);
    }

    /// A runtime with a worker of its own: the waits below are on this thread, and the task
    /// they are waiting for has to run somewhere else.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }

    /// Wait for something to become true, within the bound a drop is allowed to take.
    fn until(mut ready: impl FnMut() -> bool) -> bool {
        for _ in 0..(LET_GO.as_millis() / LET_GO_STEP.as_millis().max(1)) {
            if ready() {
                return true;
            }
            std::thread::sleep(LET_GO_STEP);
        }
        false
    }

    /// Letting go of a recording waits for it to have gone, not merely to have been asked
    /// to go: what comes next may be a `vk atop --follow` taking the same lock on the same
    /// log, and it would be refused for as long as this process still held it.
    #[test]
    fn letting_go_waits_for_the_recording_to_have_gone() {
        let runtime = runtime();
        let done = Arc::new(AtomicBool::new(false));
        let stop = CancellationToken::new();
        // Stands in for the recording and the file holding its log's lock.
        let held = Arc::new(());
        let running = Arc::new(AtomicBool::new(false));

        let (flag, mine, carried, up) = (
            Arc::clone(&done),
            stop.clone(),
            Arc::clone(&held),
            Arc::clone(&running),
        );
        runtime.spawn(async move {
            // The shape of the real task: the flag goes up last of all, once what is held
            // below it has been let go of.
            let _done = Done(flag);
            let _carried = carried;
            up.store(true, Ordering::Release);
            mine.cancelled().await;
            // The letting go itself takes a moment, as `Recording::stop_now` does.
            tokio::time::sleep(LET_GO_STEP).await;
        });
        assert!(
            until(|| running.load(Ordering::Acquire)),
            "it never started"
        );

        drop(Stop {
            stop,
            done: Arc::clone(&done),
        });
        assert!(
            done.load(Ordering::Acquire),
            "the recording had only been asked to end"
        );
        assert_eq!(Arc::strong_count(&held), 1, "the log was still held");
    }

    /// The dashboard's own spawner on an address that is no address: the pane is told what
    /// went wrong, rather than left waiting on a recording that never begins.
    #[test]
    fn the_real_spawner_says_why_an_address_it_cannot_dial_failed() {
        let runtime = runtime();
        let session = Session::start(
            &OnRuntime::new(runtime.handle().clone()),
            "vsock://not-a-port",
            Path::new("/state/a"),
            3,
        );
        assert!(
            until(|| !matches!(session.began(), Began::Starting)),
            "an address that cannot be parsed was still being dialled"
        );
        match session.began() {
            Began::Failed(why) => assert!(why.contains("exec address"), "{why}"),
            other => panic!("an address no VM answers to began {other:?}"),
        }
    }
}
