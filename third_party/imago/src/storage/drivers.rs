//! Internal functionality for storage drivers.

use crate::misc_helpers::Overlaps;
#[cfg(feature = "async")]
use futures::stream::{FuturesUnordered, StreamExt};
use maybe_async::maybe_async;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "sync")]
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
#[cfg(feature = "async")]
use tokio::sync::oneshot::{self, Sender};

/// Helper object for the [`StorageExt`](crate::StorageExt) implementation.
///
/// State such as write blockers needs to be kept somewhere, and instead of introducing a wrapper
/// (that might be bypassed), we store it directly in the [`Storage`](crate::Storage) objects so it
/// cannot be bypassed (at least when using the [`StorageExt`](crate::StorageExt) methods).
///
/// Async note: Overlapping write blockers from different async tasks are safe (the awaiting task
/// yields, letting the holding task make progress).  Same-task overlap still deadlocks, as the
/// task cannot drop its guard while suspended.
///
/// Sync note: Unlike in async mode, write blocker acquisition must not be nested on the same
/// thread.  Acquiring a blocker while already holding an overlapping one will deadlock on
/// `recv()`, because the existing blocker can only be released by the same (now blocked) thread.
#[derive(Debug, Default)]
pub struct CommonStorageHelper {
    /// Current in-flight write that allow concurrent writes to the same region.
    ///
    /// Normal non-async RwLock, so do not await while locked!
    weak_write_blockers: std::sync::RwLock<RangeBlockedList>,

    /// Current in-flight write that do not allow concurrent writes to the same region.
    strong_write_blockers: std::sync::RwLock<RangeBlockedList>,
}

/// A list of ranges blocked for some kind of concurrent access.
///
/// Depending on the use, some will block all concurrent access (i.e. serializing writes will block
/// both serializing and non-serializing writes (strong blockers)), while others will only block a
/// subset (non-serializing writes will only block serializing writes (weak blockers)).
#[derive(Debug, Default)]
struct RangeBlockedList {
    /// The list of ranges.
    ///
    /// Serializing writes (strong write blockers) are supposed to be rare, so it is important that
    /// entering and removing items into/from this list is cheap, not that iterating it is.
    blocked: Vec<Arc<RangeBlocked>>,
}

/// A range blocked for some kind of concurrent access.
#[derive(Debug)]
struct RangeBlocked {
    /// The range.
    range: Range<u64>,

    /// List of requests awaiting the range to become unblocked.
    ///
    /// When the corresponding `RangeBlockedGuard` is dropped, these will all be awoken (via
    /// `oneshot::Sender::send(())`).
    ///
    /// Normal non-async mutex, so do not await while locked!
    waitlist: std::sync::Mutex<Vec<Sender<()>>>,

    /// Index in the corresponding `RangeBlockedList.blocked` list, so it can be dropped quickly.
    ///
    /// (When the corresponding `RangeBlockedGuard` is dropped, this entry is swap-removed from the
    /// `blocked` list, and the other entry taking its place has its `index` updated.)
    ///
    /// Only access under `blocked` lock!
    index: AtomicUsize,

    /// For debugging only: Thread that created this blocker, for reentrancy detection.
    #[cfg(all(feature = "sync", debug_assertions))]
    owner_thread: std::thread::ThreadId,
}

/// Keeps a `RangeBlocked` alive.
///
/// When dropped, removes the `RangeBlocked` from its list, and wakes all requests in the `waitlist`.
#[derive(Debug)]
pub struct RangeBlockedGuard<'a> {
    /// List where this blocker resides.
    list: &'a std::sync::RwLock<RangeBlockedList>,

    /// `Option`, so `drop()` can `take()` it and unwrap the `Arc`.
    ///
    /// Consequently, do not clone: Must have refcount 1 when dropped.  (The only clone must be in
    /// `self.list.blocked`, under index `self.block.index`.)
    block: Option<Arc<RangeBlocked>>,
}

#[maybe_async]
impl CommonStorageHelper {
    /// Await concurrent strong write blockers for the given range.
    ///
    /// Strong write blockers are set up for writes that must not be intersected by any other
    /// write.  Await such intersecting concurrent write requests, and return a guard that will
    /// delay such new writes until the guard is dropped.
    pub async fn weak_write_blocker(&self, range: Range<u64>) -> RangeBlockedGuard<'_> {
        #[cfg(all(feature = "sync", debug_assertions))]
        Self::assert_no_same_thread_overlap(&self.strong_write_blockers, &range);

        #[cfg(feature = "async")]
        let mut intersecting = FuturesUnordered::new();
        #[cfg(feature = "sync")]
        let mut intersecting = Vec::new();

        // Create `RangeBlockedGuard` before the `await` below, so if the future is dropped,
        // `RangeBlockedGuard::drop()` will run, removing the blocker from the list
        let guard = {
            // Consistent ordering to avoid deadlock: Always acquire weak before strong
            let mut weak = self.weak_write_blockers.write().unwrap();
            let strong = self.strong_write_blockers.read().unwrap();

            strong.collect_intersecting(&range, &mut intersecting);

            RangeBlockedGuard {
                list: &self.weak_write_blockers,
                block: Some(weak.block(range)),
            }
        };

        // `RecvError` means the blocker's guard was dropped without signaling, so the blocking
        // operation is gone, and thus waiting for it is pointless.  We must still wait for all
        // other overlapping blockers, so drain until all are actually done, ignoring errors.
        #[cfg(feature = "async")]
        while intersecting.next().await.is_some() {}
        #[cfg(feature = "sync")]
        for rx in intersecting {
            let _ = rx.recv();
        }

        guard
    }

    /// Await any concurrent write request for the given range.
    ///
    /// Block the given range for any concurrent write requests until the returned guard object is
    /// dropped.  Existing requests are awaited, and new ones will be delayed.
    pub async fn strong_write_blocker(&self, range: Range<u64>) -> RangeBlockedGuard<'_> {
        #[cfg(all(feature = "sync", debug_assertions))]
        {
            Self::assert_no_same_thread_overlap(&self.weak_write_blockers, &range);
            Self::assert_no_same_thread_overlap(&self.strong_write_blockers, &range);
        }

        #[cfg(feature = "async")]
        let mut intersecting = FuturesUnordered::new();
        #[cfg(feature = "sync")]
        let mut intersecting = Vec::new();

        // Create `RangeBlockedGuard` before the `await` below, so if the future is dropped,
        // `RangeBlockedGuard::drop()` will run, removing the blocker from the list
        let guard = {
            // Consistent ordering to avoid deadlock: Always acquire weak before strong
            let weak = self.weak_write_blockers.read().unwrap();
            let mut strong = self.strong_write_blockers.write().unwrap();

            weak.collect_intersecting(&range, &mut intersecting);
            strong.collect_intersecting(&range, &mut intersecting);

            RangeBlockedGuard {
                list: &self.strong_write_blockers,
                block: Some(strong.block(range)),
            }
        };

        // `RecvError` means the blocker's guard was dropped without signaling, so the blocking
        // operation is gone, and thus waiting for it is pointless.  We must still wait for all
        // other overlapping blockers, so drain until all are actually done, ignoring errors.
        #[cfg(feature = "async")]
        while intersecting.next().await.is_some() {}
        #[cfg(feature = "sync")]
        for rx in intersecting {
            let _ = rx.recv();
        }

        guard
    }

    /// Panic if the current thread already holds a blocker in `list` that overlaps `range`.
    ///
    /// In sync mode, blocking on `recv()` to wait for an overlapping blocker held by the same
    /// thread would deadlock, because that blocker can only be released by this (now blocked)
    /// thread.  This check runs before any locks are acquired so that a panic does not poison
    /// them, allowing already-held guards to drop cleanly during unwinding.
    #[cfg(all(feature = "sync", debug_assertions))]
    fn assert_no_same_thread_overlap(
        list: &std::sync::RwLock<RangeBlockedList>,
        range: &Range<u64>,
    ) {
        let list = list.read().unwrap();
        let current = std::thread::current().id();
        for rb in &list.blocked {
            if rb.range.overlaps(range) && rb.owner_thread == current {
                panic!(
                    "Same-thread reentrancy: already holding write blocker for {:?}, \
                     acquiring overlapping blocker for {range:?} would deadlock",
                    rb.range,
                );
            }
        }
    }
}

impl RangeBlockedList {
    /// Collects futures/receivers to await intersecting request.
    ///
    /// Creates a channel for every intersecting request; blocking on the receiver will wait for
    /// the request to complete.
    fn collect_intersecting(
        &self,
        check_range: &Range<u64>,
        #[cfg(feature = "async")] intersecting: &mut FuturesUnordered<oneshot::Receiver<()>>,
        #[cfg(feature = "sync")] intersecting: &mut Vec<mpsc::Receiver<()>>,
    ) {
        for range_block in self.blocked.iter() {
            if range_block.range.overlaps(check_range) {
                #[cfg(feature = "async")]
                let (s, r) = oneshot::channel::<()>();
                #[cfg(feature = "sync")]
                let (s, r) = mpsc::channel();

                range_block.waitlist.lock().unwrap().push(s);
                intersecting.push(r);
            }
        }
    }

    /// Enter a new blocked range into the list.
    ///
    /// This only blocks new requests, old requests must separately be waited for by blocking on
    /// all receivers returned by `collect_intersecting()`.
    fn block(&mut self, range: Range<u64>) -> Arc<RangeBlocked> {
        let range_block = Arc::new(RangeBlocked {
            range,
            waitlist: Default::default(),
            index: self.blocked.len().into(),
            #[cfg(all(feature = "sync", debug_assertions))]
            owner_thread: std::thread::current().id(),
        });
        self.blocked.push(Arc::clone(&range_block));
        range_block
    }
}

impl Drop for RangeBlockedGuard<'_> {
    fn drop(&mut self) {
        let block = self.block.take().unwrap();

        {
            let mut list = self.list.write().unwrap();
            let i = block.index.load(Ordering::Relaxed);
            let removed = list.blocked.swap_remove(i);
            debug_assert!(Arc::ptr_eq(&removed, &block));
            if let Some(block) = list.blocked.get(i) {
                block.index.store(i, Ordering::Relaxed);
            }
        }

        let block = Arc::into_inner(block).unwrap();
        let waitlist = block.waitlist.into_inner().unwrap();
        for waiting in waitlist {
            // If the receiving end was dropped (e.g. because the request was dropped), then just
            // ignore that
            let _ = waiting.send(());
        }
    }
}

#[cfg(all(feature = "sync", test, debug_assertions))]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Same-thread reentrancy: already holding write blocker")]
    fn test_weak_then_overlapping_strong() {
        let helper = CommonStorageHelper::default();
        let _weak = helper.weak_write_blocker(0..100);
        let _strong = helper.strong_write_blocker(50..150);
    }

    #[test]
    #[should_panic(expected = "Same-thread reentrancy: already holding write blocker")]
    fn test_strong_then_overlapping_strong() {
        let helper = CommonStorageHelper::default();
        let _first = helper.strong_write_blocker(0..100);
        let _second = helper.strong_write_blocker(50..150);
    }

    #[test]
    #[should_panic(expected = "Same-thread reentrancy: already holding write blocker")]
    fn test_strong_then_overlapping_weak() {
        let helper = CommonStorageHelper::default();
        let _strong = helper.strong_write_blocker(0..100);
        let _weak = helper.weak_write_blocker(50..150);
    }

    #[test]
    fn test_non_overlapping() {
        let helper = CommonStorageHelper::default();
        let _first = helper.weak_write_blocker(0..100);
        let _second = helper.strong_write_blocker(100..200);
    }

    #[test]
    fn test_weak_then_overlapping_weak() {
        let helper = CommonStorageHelper::default();
        let _first = helper.weak_write_blocker(0..100);
        let _second = helper.weak_write_blocker(50..150);
    }
}
