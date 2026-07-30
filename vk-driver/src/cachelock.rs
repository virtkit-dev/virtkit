//! The reference-and-idle protocol the host's reclaimable caches share. A cache entry is a
//! directory some processes are using while another process may want the space back, and the
//! two questions are always the same: is anyone using it, and how long has nobody been?
//!
//! Two sidecar files answer them. Every user holds a shared advisory lock on the entry's
//! `.inuse` for as long as it needs the entry — the kernel releases it when the process exits
//! for any reason, so a crashed job never pins an entry — and a reclaim takes the same lock
//! exclusively and non-blocking, which fails outright while any user holds it. The `.used`
//! marker dates the entry, so one nobody is holding is still kept for a grace window instead
//! of being evicted the moment it falls idle.
//!
//! Callers own where the sidecars live and what removing an entry means; everything else about
//! the protocol is here, so the caches on it cannot drift apart from each other.

use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

/// A held reference to a cache entry: the shared lock lives exactly as long as this guard, so
/// a reclaim can never remove the entry underneath its user. Released on drop.
pub(crate) struct Guard {
    _file: std::fs::File,
}

/// Take a shared reference on the entry named by `lock`/`used`, waiting only behind a
/// reclaim's momentary exclusive lock, and date the entry to now. Stamping `used` is
/// best-effort: an entry with no marker is one [`try_reclaim`] leaves alone, and the next
/// acquisition stamps it again.
pub(crate) fn acquire_shared(lock: &Path, used: &Path) -> Result<Guard> {
    let file = open_lock(lock)?;
    // SAFETY: `file` owns this fd and the returned guard keeps it open.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("shared-locking {}", lock.display()));
    }
    let _ = std::fs::File::create(used);
    Ok(Guard { _file: file })
}

/// Ensure the entry's lock sidecar exists and bump its `.used` marker to now, without taking
/// a reference — for callers that resolve an entry before taking their reference, so both
/// sidecars are always created by this module with one mode. Best-effort.
pub(crate) fn stamp(lock: &Path, used: &Path) {
    let _ = open_lock(lock);
    let _ = std::fs::File::create(used);
}

/// Reclaim the entry named by `lock`/`used` when nobody holds it and it has been idle at least
/// `idle`, by running `remove` while still holding the exclusive lock — a would-be new user
/// blocks on it, then finds the entry gone and rebuilds it. Returns whether `remove` ran. Pass
/// one `now` for a whole sweep, so every entry in it is judged against the same instant.
/// Best-effort: an entry that cannot be locked or dated is left for the next sweep.
pub(crate) fn try_reclaim(
    lock: &Path,
    used: &Path,
    idle: Duration,
    now: SystemTime,
    remove: impl FnOnce(),
) -> bool {
    let Ok(file) = open_lock(lock) else {
        return false;
    };
    // A live user holds LOCK_SH, so a non-blocking LOCK_EX fails (EWOULDBLOCK): a sweep never
    // waits behind one.
    // SAFETY: the fd is owned by `file`, which outlives the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return false;
    }
    let idle_ok = match std::fs::metadata(used).and_then(|m| m.modified()) {
        // A `.used` timestamp can read microseconds *ahead* of `now`: the filesystem stamps
        // mtime from a coarse clock while `now` is precise, so under load the marker can appear
        // to be in the future. Treat that as "used just now" (zero elapsed) rather than "keep
        // forever", so a zero idle window still reclaims an unreferenced entry.
        Ok(t) => now.duration_since(t).unwrap_or_default() >= idle,
        Err(_) => false, // missing/unreadable marker: mid-setup, leave alone
    };
    if !idle_ok {
        return false;
    }
    remove();
    true
}

fn open_lock(lock: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock)
        .with_context(|| format!("opening {}", lock.display()))
}

/// Run a cache's own sweep until it reports the entry reclaimed, for tests. The liveness probe
/// is a non-blocking exclusive `flock`, and a *concurrent* test that spawns a subprocess (the
/// qcow2 tests run `qemu-img`) briefly leaks this test's `.inuse` fd into the forked child
/// across `fork()`, keeping the shared lock alive until the child `exec`s. That makes a
/// single-shot eviction check racy under parallel load, so retry — exactly as the periodic
/// production sweep would. Converges once the transient inheriting child is gone.
#[cfg(test)]
pub(crate) fn reclaimed_eventually(mut sweep: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if sweep() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// `(dir, lock, used)` under a fresh private directory; remove `dir` when done.
    fn sidecars(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vk-cachelock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join(".inuse");
        let used = dir.join(".used");
        (dir, lock, used)
    }

    #[test]
    fn a_held_entry_is_never_reclaimed() {
        let (dir, lock, used) = sidecars("held");
        let guard = acquire_shared(&lock, &used).unwrap();
        let mut removed = false;
        assert!(!try_reclaim(
            &lock,
            &used,
            Duration::ZERO,
            SystemTime::now(),
            || removed = true
        ));
        assert!(!removed, "a live reference must block the reclaim");
        drop(guard);
        assert!(reclaimed_eventually(|| try_reclaim(
            &lock,
            &used,
            Duration::ZERO,
            SystemTime::now(),
            || removed = true
        )));
        assert!(removed, "a released entry is reclaimable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_inside_its_idle_window_is_kept() {
        let (dir, lock, used) = sidecars("window");
        drop(acquire_shared(&lock, &used).unwrap());
        assert!(!try_reclaim(
            &lock,
            &used,
            Duration::from_secs(3600),
            SystemTime::now(),
            || panic!("a freshly used entry must be kept")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_undated_entry_is_left_alone() {
        // No marker means an entry mid-setup, whose user has not taken its reference yet.
        let (dir, lock, used) = sidecars("undated");
        assert!(!try_reclaim(
            &lock,
            &used,
            Duration::ZERO,
            SystemTime::now(),
            || panic!("an entry with no marker must be left alone")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_marker_ahead_of_the_sweep_clock_counts_as_just_used() {
        // The filesystem stamps `.used` from a coarse clock, so the marker can read ahead of a
        // precise `now`. That must mean "zero elapsed", not "keep forever": a non-zero idle
        // window keeps the entry, a zero window still reclaims it.
        let (dir, lock, used) = sidecars("skew");
        drop(acquire_shared(&lock, &used).unwrap());
        let earlier = SystemTime::now() - Duration::from_secs(60);
        assert!(!try_reclaim(
            &lock,
            &used,
            Duration::from_secs(1),
            earlier,
            || { panic!("zero elapsed is inside a non-zero idle window") }
        ));
        let mut removed = false;
        assert!(reclaimed_eventually(|| try_reclaim(
            &lock,
            &used,
            Duration::ZERO,
            earlier,
            || removed = true
        )));
        assert!(removed, "a zero idle window reclaims despite the skew");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
