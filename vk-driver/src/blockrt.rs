//! Escape hatch for driving an async future to completion from sync code that may already
//! be running inside `main`'s tokio runtime: a nested `Handle::block_on` on the calling
//! thread would panic, so every call runs its future on a dedicated OS thread instead.
//!
//! That thread enters one process-wide runtime rather than building a fresh one per call.
//! Building one spins up a full `num_cpus` worker pool, and the sync call sites are hot —
//! `build/exec` comes through here for every `RUN`, freeze, thaw and finish of every
//! stage, and concurrent stages each finalize a cache push — so a runtime per call churned
//! through, and transiently held, num_callers × num_cpus worker threads.
//!
//! What the callers share is that pool, not a queue: `Runtime::block_on` drives the root
//! future on the calling thread, so each caller still gets a thread of its own. The workers
//! carry the tasks those futures spawn (hyper's connection tasks, say) plus the I/O and
//! time drivers — which is why this is a multi-thread runtime and not a current-thread one.
//!
//! Two invariants come with the sharing:
//!
//! - Never call [`block_on`] from a task running *on* this runtime, and never park one of
//!   its workers in unbounded blocking work. With a private runtime per call that could
//!   only stall its own caller; here it stalls every concurrent one, drivers included.
//! - The runtime stays lazily built. `main` forks to detach (`detach::fork`) before any
//!   caller reaches this module, and a tokio runtime must not straddle a fork.
//!
//! - Construct runtime-bound futures inside the `async` block passed to [`block_on`]. Tokio's
//!   timeout, sleep, and interval futures capture the current runtime when constructed, while
//!   synchronous callers may run on plain threads without one.

use std::sync::OnceLock;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            // `enable_all` is io + time today, and the signal and process drivers ride
            // along with io because vk-core enables their features for the whole build.
            // Call it rather than enumerating, so a driver a future tokio adds is not
            // silently missing from a path that reaches as far as booting a guest session.
            .enable_all()
            .thread_name("vk-blockrt")
            .build()
            .expect("building the shared blocking-escape tokio runtime")
    })
}

/// Drive `fut` to completion from a sync context, on a dedicated OS thread entering the
/// shared runtime. A panic inside `fut` propagates to the caller unchanged.
pub(crate) fn block_on<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|s| match s.spawn(|| runtime().block_on(fut)).join() {
        Ok(out) => out,
        Err(payload) => std::panic::resume_unwind(payload),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Callers that overlap on the one shared runtime all finish, tasks they spawned
    /// included — the property a runtime per call used to give for free.
    #[test]
    fn concurrent_callers_all_complete() {
        let done = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for i in 0..8u32 {
                let done = &done;
                s.spawn(move || {
                    let got = super::block_on(async move {
                        let spawned = tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            i * 2
                        });
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        spawned.await.expect("the spawned task ran to completion")
                    });
                    assert_eq!(got, i * 2);
                    done.fetch_add(1, Ordering::Relaxed);
                });
            }
        });
        assert_eq!(done.load(Ordering::Relaxed), 8);
    }

    /// The whole reason the module exists: called from inside a runtime, where a nested
    /// `Handle::block_on` would panic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn works_from_inside_a_runtime() {
        assert_eq!(super::block_on(async { 42 }), 42);
    }

    /// Runtime-bound futures must be constructed inside the block entered by [`block_on`].
    #[test]
    fn a_timeout_must_be_built_inside_the_block() {
        let got = super::block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async { 42 }).await
        });
        assert_eq!(
            got.expect("the inner future finished well inside the timeout"),
            42
        );

        let payload = std::panic::catch_unwind(|| {
            drop(tokio::time::timeout(Duration::from_secs(5), async {}));
        })
        .expect_err("constructing a timeout off-runtime panics");
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            msg.contains("runtime"),
            "expected tokio's missing-runtime panic, got {msg:?}"
        );
    }

    /// A panic in the future reaches the caller with its payload intact, not as an
    /// opaque join error — and does not leave the shared runtime unusable behind it.
    #[test]
    fn propagates_a_panic_without_poisoning_the_runtime() {
        // The hook is left alone on purpose: swapping it is process-wide, and would swallow
        // the panic output of whatever else the test binary is running at the same time.
        let payload = std::panic::catch_unwind(|| super::block_on(async { panic!("boom") }))
            .expect_err("the panic reached the caller");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"boom"));
        assert_eq!(super::block_on(async { 7 }), 7);
    }
}
