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
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

/// A held reference to a cache entry: the shared lock lives exactly as long as this guard, so
/// a reclaim can never remove the entry underneath its user. Released on drop, which re-dates
/// the entry — every reference here is held for a whole job (a checkout, a base under a live
/// overlay, a base a later phase still means to boot), so dating the idle window from
/// acquisition instead would leave a long job's entry looking idle for the length of it.
// `Debug` so a `Result` carrying a guard stays `unwrap_err`-able in tests.
#[derive(Debug)]
pub(crate) struct Guard {
    _file: std::fs::File,
    used: PathBuf,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Best-effort, like every other stamp: an entry with no marker is one `try_reclaim`
        // leaves alone. Runs before `_file`, so the shared lock still holds off a reclaim.
        let _ = std::fs::File::create(&self.used);
    }
}

/// How many times [`acquire_shared`] re-opens the lock file before giving up on ever seeing a
/// stable entry. Only a rebuild that recreated the entry needs a retry at all — in the image
/// tiers, whose reclaim takes the whole directory, the next open just fails instead — so a
/// handful is already far past what a real sweep can produce.
const ACQUIRE_ATTEMPTS: u32 = 3;

/// Whether `e` is (or wraps) a "no such file or directory" — how an acquisition reports an
/// entry a reclaim took away entirely, which the image tiers read as "rebuild it".
pub(crate) fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

/// Take a shared reference on the entry named by `lock`/`used`, waiting only behind a
/// reclaim's exclusive lock, and date the entry to now — and again on release. Stamping
/// `used` is best-effort: an entry with no marker is one [`try_reclaim`] leaves alone, and
/// the next acquisition stamps it again.
pub(crate) fn acquire_shared(lock: &Path, used: &Path) -> Result<Guard> {
    for _ in 0..ACQUIRE_ATTEMPTS {
        let file = open_lock(lock)?;
        // SAFETY: `file` owns this fd and the returned guard keeps it open.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("shared-locking {}", lock.display()));
        }
        // A reclaim removes the entry while holding the lock exclusively, so blocking behind
        // one hands back a lock on a file that has since been unlinked — and if a rebuild
        // recreated the entry meanwhile, the next sweep sees its *new* sidecar unheld and
        // evicts an entry this guard claims to protect. Only a lock on the file the path
        // still names is worth anything; anything else, take again.
        if same_file(&file, lock)? {
            let _ = std::fs::File::create(used);
            return Ok(Guard {
                _file: file,
                used: used.to_path_buf(),
            });
        }
    }
    anyhow::bail!(
        "{} was replaced under every attempt to reference it",
        lock.display()
    )
}

/// Whether the open `file` is still the file `path` names — `false` once a reclaim has
/// unlinked it, or a rebuild has replaced it with a new one. Works on a directory just as
/// well as a file: `build::claim_scratch` uses it to check the scratch dir it locked is
/// still the one its path names.
pub(crate) fn same_file(file: &std::fs::File, path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let held = file
        .metadata()
        .with_context(|| format!("stat-ing the held {}", path.display()))?;
    match std::fs::metadata(path) {
        Ok(named) => Ok((held.dev(), held.ino()) == (named.dev(), named.ino())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("stat-ing {}", path.display())),
    }
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
    use std::os::unix::fs::MetadataExt;

    use super::*;

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
    fn an_entry_is_dated_from_the_last_reference_going_away() {
        // The marker is rewritten as the guard drops, so an entry held for a long job is not
        // already at the far end of its idle window by the time the job ends.
        let (dir, lock, used) = sidecars("release");
        let guard = acquire_shared(&lock, &used).unwrap();
        let at_acquire = std::fs::metadata(&used).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        drop(guard);
        assert!(std::fs::metadata(&used).unwrap().modified().unwrap() > at_acquire);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reference_is_only_ever_held_on_the_file_the_path_names() {
        // What the retry in `acquire_shared` turns on. A reclaim unlinks the sidecar while
        // holding it exclusively, so a lock taken from behind that reclaim can come back on an
        // inode the path no longer names — worthless, because the next sweep sees the *new*
        // sidecar unheld. Reproducing that interleaving needs the unlink to land while a caller
        // is blocked in `flock`, which no test can force, so the predicate is what is pinned.
        let (dir, lock, used) = sidecars("identity");
        let stale = open_lock(&lock).unwrap();
        assert!(same_file(&stale, &lock).unwrap());
        std::fs::remove_file(&lock).unwrap();
        assert!(
            !same_file(&stale, &lock).unwrap(),
            "an unlinked sidecar names nothing"
        );
        let _ = open_lock(&lock).unwrap();
        assert!(
            !same_file(&stale, &lock).unwrap(),
            "a recreated sidecar is a different file"
        );
        // And a reference taken across all that holds the file that is actually there.
        let guard = acquire_shared(&lock, &used).unwrap();
        let named = std::fs::metadata(&lock).unwrap();
        let held = guard._file.metadata().unwrap();
        assert_eq!((held.dev(), held.ino()), (named.dev(), named.ino()));
        drop((stale, guard));

        // The entry gone for good surfaces as a not-found, which callers read as "rebuild".
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(is_not_found(&acquire_shared(&lock, &used).unwrap_err()));
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
