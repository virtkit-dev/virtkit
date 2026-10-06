//! Helpers shared by tests across modules.

use std::time::{Duration, Instant};

/// Whether `free` reports a just-dropped descriptor (flock or socket) free within five seconds.
/// A lock or bound socket belongs to the open file description, and a child another test is
/// spawning holds a copy of it until it execs (close-on-exec only acts at exec), so a dropped
/// one can briefly stay held.
pub(crate) fn released(mut free: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !free() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

/// `take`'s first `Some`, retried while it returns `None` until [`released`] gives up.
pub(crate) fn acquired<T>(mut take: impl FnMut() -> Option<T>) -> Option<T> {
    let mut taken = None;
    released(|| {
        taken = take();
        taken.is_some()
    });
    taken
}

/// Retry `op` while its error contains `contended`, until [`released`] gives up.
/// Return other errors and contention that outlasts the wait unchanged.
pub(crate) fn once_released<T>(
    contended: &str,
    mut op: impl FnMut() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut last = None;
    released(|| {
        let result = op();
        let held = matches!(&result, Err(e) if format!("{e:#}").contains(contended));
        last = Some(result);
        !held
    });
    last.expect("`released` runs `op` at least once")
}
