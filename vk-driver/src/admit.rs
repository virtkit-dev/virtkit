//! Memory admission for CI jobs: a host-wide ledger that keeps a runner from committing
//! more guest RAM than it can back.
//!
//! Without it a runner takes every job its `concurrent` limit allows and the host's OOM
//! killer arbitrates — it takes a VMM, and that job dies mid-stage. So a job reserves what
//! it is about to boot before it boots it, and waits when the host is full.
//!
//! The ledger is one file per job under `<state_dir>/admit/`, holding what the job reserved
//! and when it asked. A reservation counts only while someone holds a shared `flock` on it:
//! `prepare` takes one while it waits and keeps it until it exits, and the supervisor takes
//! its own for the job's life, so the two overlap and the reservation never lapses between
//! them — and a job killed at any point has its reservation freed by the kernel. Admission
//! reads and writes the ledger under one exclusive lock on the directory, so concurrent
//! `prepare`s (a runner runs several, and a host may run several runners) admit one at a
//! time. The supervisor's [`hold`] and cleanup's [`release`] need no such lock: neither
//! consults the ledger, and both act only on this job's own entry.
//!
//! Admission is against the ledger, never against the host's free memory: a guest faults
//! its RAM in gradually, so a VM that just booted leaves `MemAvailable` looking roomy and
//! the next job in would be admitted against memory the previous one has not touched yet.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// The directory lock, taken for every ledger read and write.
const LOCK: &str = ".lock";
/// How often a waiting job re-checks the ledger.
const POLL: Duration = Duration::from_secs(2);

/// A job's granted reservation: the open, shared-locked ledger file. Dropping it (or the
/// process exiting) releases the lock, which is what makes the reservation stop counting —
/// the file itself stays for the next holder, and is removed by [`release`] at cleanup or
/// reclaimed by the next admission that finds it unlocked.
#[derive(Debug)]
pub struct Reservation {
    _file: File,
}

/// Reserve `want_mib` for `job_id` against `budget_mib`, waiting up to `timeout` for room.
/// Prints its wait to stdout — this runs in `prepare`, whose output the job trace keeps, so
/// a job that starts late says why.
///
/// Jobs are admitted oldest-request-first: a big job would otherwise wait behind an endless
/// stream of small ones that each fit. Erring the other way, a small job can queue behind a
/// big one it would have fit alongside — predictable beats optimal here.
pub fn acquire(
    dir: &Path,
    job_id: &str,
    want_mib: u64,
    budget_mib: u64,
    timeout: Duration,
) -> Result<Reservation> {
    if want_mib > budget_mib {
        // A per-job MICROVM_MEM is clamped to the budget before it reaches here, so a size
        // that still exceeds it came from the host's own `[vm] mem` default: name both, or the
        // message sends the reader after a job variable that is not the cause.
        bail!(
            "this job's {want_mib} MiB of guest memory exceeds the host's whole {budget_mib} MiB \
             budget ([schedule] mem_budget vs [vm] mem) — it can never be admitted"
        );
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    // 0700 on create AND reuse, as `vk run`'s pinned state dir does: this ledger is the host's
    // memory guard, and an entry another local user could plant in it — locked, claiming the
    // whole budget — would stall every job on the box. A pre-existing looser mode is the case
    // worth covering, so the mode is asserted and not merely requested at creation.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {} to 0700", dir.display()))?;
    let path = dir.join(job_id);
    let mut entry = Entry {
        want_mib,
        asked: now_nanos(),
        granted: false,
    };
    // Held from here on: while waiting it marks a live request other jobs must queue behind,
    // and once granted it is the reservation itself. Created under the directory lock, which
    // is what [`scan`] reaps dead entries under: an entry that exists unlocked for even the
    // instant between its creation and its lock would be taken for abandoned and removed,
    // leaving this job writing to an unlinked file that no later scan can see — its memory
    // then counted by nobody, which is the one thing this ledger exists to prevent.
    let file = {
        let _dir_lock = lock_dir(dir)?;
        let file = open_shared(&path)?;
        // Written before the lock drops, not on the next pass: an entry that exists but is
        // still empty parses as nothing, so a scan catching it in that state would report a
        // ledger anomaly against a job that is merely starting up — and leave its request out
        // of the queue order for that pass.
        entry.write(&file, &path)?;
        file
    };
    let deadline = Instant::now() + timeout;
    let mut waited_since = None;
    loop {
        // Both are composed under the directory lock and reported outside it: prepare's stdout
        // is a pipe gitlab-runner drains, and a stalled reader blocking on `write` must not
        // block every other runner's admission on the host-wide lock.
        let mut wait_note = None;
        let mut anomalies = Vec::new();
        // The block yields whether we got in and nothing more, so no reporting can sit inside
        // the critical section even by accident.
        let admitted = {
            let _dir_lock = lock_dir(dir)?;
            let (used_mib, ahead) = scan(dir, job_id, entry.asked, &mut anomalies)?;
            // Saturating, like the totals it compares: a corrupt entry must not add up to
            // apparent room.
            if ahead == 0 && used_mib.saturating_add(want_mib) <= budget_mib {
                entry.granted = true;
                entry.write(&file, &path)?;
                true
            } else {
                if waited_since.is_none() {
                    waited_since = Some(Instant::now());
                    wait_note = Some(format!(
                        "virtkit: waiting for {want_mib} MiB of the host's {budget_mib} MiB \
                         memory budget ({used_mib} MiB reserved, {ahead} job(s) asked first)"
                    ));
                }
                false
            }
        };
        report(&anomalies);
        if admitted {
            if let Some(since) = waited_since {
                println!(
                    "virtkit: admitted after waiting {:.0}s for memory",
                    Instant::now().duration_since(since).as_secs_f64()
                );
            }
            return Ok(Reservation { _file: file });
        }
        if let Some(note) = wait_note {
            println!("{note}");
        }
        if Instant::now() >= deadline {
            // Best-effort: the entry stops counting the moment this process drops its lock,
            // and a scan that got there first has already removed it.
            let _ = std::fs::remove_file(&path);
            bail!(
                "no room in the host's {budget_mib} MiB memory budget for this job's \
                 {want_mib} MiB within {}s ([schedule] wait_timeout_secs)",
                timeout.as_secs()
            );
        }
        std::thread::sleep(POLL);
    }
}

/// Re-open the reservation `prepare` was granted and hold it for this process's life — the
/// supervisor's half of the handoff. `None` when the job has no reservation (admission off),
/// which is not an error: the ledger only exists when a budget is configured.
///
/// Needs no directory lock, unlike [`acquire`]: prepare holds its own lock on this entry
/// until the guest answers, which is long after this runs, so no scan can take it for
/// abandoned in between.
pub fn hold(dir: &Path, job_id: &str) -> Option<Reservation> {
    let path = dir.join(job_id);
    // One open, and never creating. Testing for the file and then opening it would be two
    // resolutions of the same path: an entry removed in between — by a racing cleanup, or by
    // the scan that reaps abandoned ones — would be re-created here as an empty file, which no
    // scan can parse and none can reclaim while this process holds it locked. The job's memory
    // would then count for nobody for the whole of its life.
    match open_locked_shared(&path) {
        Ok(file) => Some(Reservation { _file: file }),
        // admission is off — prepare never made an entry
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        // An entry that exists but cannot be re-locked is not the same as no entry at all:
        // this job's memory stops counting against the budget for the rest of its life, so
        // say so in the supervisor log rather than degrading the host's guard in silence.
        Err(e) => {
            eprintln!(
                "virtkit: holding this job's memory reservation ({}): {e}",
                path.display()
            );
            None
        }
    }
}

/// Drop a job's reservation at cleanup. Best-effort: a reservation left behind stops
/// counting the moment its holders die, and the next admission removes the file.
pub fn release(dir: &Path, job_id: &str) {
    let _ = std::fs::remove_file(dir.join(job_id));
}

/// Report what a scan found odd. Called once the directory lock is gone: stderr is the
/// supervisor log or the runner's own, and blocking on it under the lock would stall every
/// admission on the host.
fn report(anomalies: &[String]) {
    for note in anomalies {
        eprintln!("{note}");
    }
}

/// What the live ledger holds, ignoring `job_id` (the caller's own entry): the granted MiB,
/// and how many jobs asked before `asked` and are still waiting. Entries nobody holds a lock
/// on are dead — their job is gone — and are removed as they are found. Callers hold the
/// directory lock.
///
/// An unreadable ledger is an error, never an empty one: reporting nothing reserved would
/// admit every job on the host against a guard that has stopped working. Anything odd but
/// survivable is pushed onto `anomalies` for the caller to report once it has let the lock go.
fn scan(
    dir: &Path,
    job_id: &str,
    asked: u128,
    anomalies: &mut Vec<String>,
) -> Result<(u64, usize)> {
    let (mut used_mib, mut ahead): (u64, usize) = (0, 0);
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading {}", dir.display()))?
            .path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == LOCK || name == job_id {
            continue;
        }
        let file = match File::open(&path) {
            Ok(file) => file,
            // Removed under us by another admission. Any other failure — no descriptors
            // left, say — would silently shrink the guard, so it is an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        };
        if !locked(&file) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Some(entry) = Entry::read(&file) else {
            // Every write happens under this lock and an entry is written as it is created,
            // so only a holder killed mid-write leaves a partial line. It would go on not
            // counting, so say so rather than letting the guard quietly shrink.
            anomalies.push(format!(
                "virtkit: ledger entry {} unreadable — not counted this pass",
                path.display()
            ));
            continue;
        };
        // Saturating: these are numbers parsed out of a file, and a wrapped total would read
        // as room where there is none.
        if entry.granted {
            used_mib = used_mib.saturating_add(entry.want_mib);
        } else if entry.asked < asked {
            ahead = ahead.saturating_add(1);
        }
    }
    Ok((used_mib, ahead))
}

/// One ledger entry: what the job wants, when it first asked (its place in the queue), and
/// whether it holds that memory yet.
struct Entry {
    want_mib: u64,
    asked: u128,
    granted: bool,
}

impl Entry {
    /// `<mib> <asked> <granted|waiting>`, rewritten whole each time so a reader either sees
    /// the previous line or the new one, never a splice of both.
    fn write(&self, mut file: &File, path: &Path) -> Result<()> {
        let state = if self.granted { "granted" } else { "waiting" };
        let line = format!("{} {} {state}\n", self.want_mib, self.asked);
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(line.as_bytes()))
            .and_then(|()| file.flush())
            .with_context(|| format!("writing {}", path.display()))
    }

    fn read(mut file: &File) -> Option<Entry> {
        let mut text = String::new();
        file.read_to_string(&mut text).ok()?;
        let mut fields = text.split_whitespace();
        Some(Entry {
            want_mib: fields.next()?.parse().ok()?,
            asked: fields.next()?.parse().ok()?,
            granted: fields.next()? == "granted",
        })
    }
}

/// Open (creating) `path` and take a shared lock on it — the mark of a live reservation.
/// Shared, so `prepare` and the supervisor can hold the same one across the handoff.
fn open_shared(path: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    lock_shared(&file).with_context(|| format!("locking {}", path.display()))?;
    Ok(file)
}

/// Open an existing `path` and take a shared lock on it, without creating. The `io::Error` is
/// returned unwrapped so a caller can tell a missing entry from one it could not lock.
fn open_locked_shared(path: &Path) -> std::io::Result<File> {
    let file = File::options().read(true).open(path)?;
    lock_shared(&file)?;
    Ok(file)
}

fn lock_shared(file: &File) -> std::io::Result<()> {
    // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Whether anyone holds `file`'s reservation, probed by trying to take it exclusively.
///
/// A lock lives until the last copy of the descriptor holding it closes, so a process that
/// forks while a reservation is being released keeps it alive for the instant before the
/// child execs. Erring that way is the right way round — a reservation read as live for one
/// poll costs a job two seconds, where reclaiming a live one would overcommit the host.
fn locked(file: &File) -> bool {
    // SAFETY: same as open_shared; LOCK_NB never blocks.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return true;
    }
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    false
}

/// Take the directory's exclusive lock, held until the returned file drops. Blocking: the
/// critical section is a directory scan, and a waiter is better than a spuriously refused job.
fn lock_dir(dir: &Path) -> Result<File> {
    let path = dir.join(LOCK);
    let file = File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("locking {}", path.display()));
    }
    Ok(file)
}

/// A request's place in the queue: nanoseconds since boot. Monotonic rather than wall clock,
/// which the whole oldest-first rule rests on — an NTP step backwards would otherwise stamp a
/// request that arrived later with an earlier time and let it cut in front of one already
/// waiting. Comparable across the processes sharing this ledger because they share a boot,
/// and entries never outlive one: nothing holds their locks afterwards, so the first scan
/// after a reboot reclaims them.
fn now_nanos() -> u128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes the timespec we own, and only on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        // Unreachable for CLOCK_MONOTONIC on Linux. Queue behind everyone rather than
        // ahead of them: waiting a turn too long beats taking someone else's.
        return u128::MAX;
    }
    ts.tv_sec as u128 * 1_000_000_000 + ts.tv_nsec as u128
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-admit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Read the live ledger the way production does. `scan` reaps entries it finds unlocked,
    /// so it must only ever run under the directory lock: an unlocked reader can unlink an
    /// entry a concurrent `acquire` is still between opening and locking, leaving that job's
    /// memory uncounted — which would mask the very over-admission these tests look for.
    fn live_mib(dir: &Path) -> u64 {
        live(dir).0
    }

    /// The reserved total, and how many entries the scan could not parse. A scan racing an
    /// `acquire` must see none of the latter: an entry is created and written in one critical
    /// section, so it is never observable empty.
    fn live(dir: &Path) -> (u64, usize) {
        let mut anomalies = Vec::new();
        let _dir_lock = lock_dir(dir).unwrap();
        let used = scan(dir, "nobody", u128::MAX, &mut anomalies).unwrap().0;
        (used, anomalies.len())
    }

    /// Wait for the live ledger to fall to `mib`. Releasing is not instant when something
    /// else in the process forks at the wrong moment (see [`locked`]), and the rest of this
    /// binary's tests spawn children constantly.
    fn until_ledger_is(dir: &Path, mib: u64) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while live_mib(dir) != mib {
            assert!(
                Instant::now() < deadline,
                "ledger stuck at {} MiB, expected {mib}",
                live_mib(dir)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A reservation held by this test, as another job's would be.
    fn held(dir: &Path, job: &str, want_mib: u64, asked: u128, granted: bool) -> File {
        let file = open_shared(&dir.join(job)).unwrap();
        Entry {
            want_mib,
            asked,
            granted,
        }
        .write(&file, &dir.join(job))
        .unwrap();
        file
    }

    #[test]
    fn admits_within_the_budget_and_refuses_beyond_it() {
        let dir = tmpdir("fits");
        let held_by_others = held(&dir, "other", 4096, 1, true);

        // 4 GiB reserved of an 8 GiB budget: a 4 GiB job still fits.
        let res = acquire(&dir, "mine", 4096, 8192, Duration::from_secs(0)).unwrap();
        assert_eq!(live_mib(&dir), 8192, "both counted");

        // The budget is now full: the next job waits, then gives up.
        let err = acquire(&dir, "third", 4096, 8192, Duration::from_secs(0)).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");
        // A refused job leaves nothing behind.
        assert!(!dir.join("third").exists());

        // Releasing frees the room for the next one.
        drop(res);
        crate::admit::release(&dir, "mine");
        drop(held_by_others);
        crate::admit::release(&dir, "other");
        until_ledger_is(&dir, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_job_larger_than_the_budget_fails_at_once() {
        let dir = tmpdir("too-big");
        let err = acquire(&dir, "huge", 16384, 8192, Duration::from_secs(60)).unwrap_err();
        assert!(err.to_string().contains("never be admitted"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_older_waiter_is_served_first() {
        let dir = tmpdir("fifo");
        // A big job that asked first and is still waiting, with the budget full.
        let _big = held(&dir, "big", 8192, 1, false);
        let _full = held(&dir, "running", 8192, 1, true);

        // A small job that would fit the moment the running one ends must not jump the queue.
        let err = acquire(&dir, "small", 512, 8192, Duration::from_secs(0)).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");

        // Once the older waiter is gone, the same job is admitted.
        drop(_big);
        crate::admit::release(&dir, "big");
        drop(_full);
        crate::admit::release(&dir, "running");
        acquire(&dir, "small", 512, 8192, Duration::from_secs(0)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reservation_nobody_holds_is_reclaimed() {
        let dir = tmpdir("stale");
        // A job that died: its file is left behind, but no one holds its lock.
        let dead = held(&dir, "dead", 8192, 1, true);
        drop(dead);

        // It neither counts against the budget nor survives the scan that found it.
        until_ledger_is(&dir, 0);
        assert!(!dir.join("dead").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The wait itself: a job that does not fit sits in the poll loop and is admitted once
    /// the reservation in its way goes, rather than being refused or granted on the spot.
    #[test]
    fn a_waiting_job_is_admitted_once_there_is_room() {
        let dir = tmpdir("waits");
        let blocker = held(&dir, "running", 8192, 1, true);

        let freed = std::thread::spawn({
            let dir = dir.clone();
            move || {
                // Only once the waiter has registered, so admission really does come from a
                // later pass of the loop and not from the first one.
                let deadline = Instant::now() + Duration::from_secs(30);
                while !dir.join("waiter").exists() {
                    assert!(Instant::now() < deadline, "the waiter never registered");
                    std::thread::sleep(Duration::from_millis(20));
                }
                std::thread::sleep(POLL);
                drop(blocker);
                release(&dir, "running");
            }
        });

        let asked_at = Instant::now();
        let res = acquire(&dir, "waiter", 8192, 8192, Duration::from_secs(120)).unwrap();
        assert!(asked_at.elapsed() >= POLL, "admitted without ever waiting");
        freed.join().unwrap();

        drop(res);
        release(&dir, "waiter");
        until_ledger_is(&dir, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The point of the directory lock: real concurrent admissions, of a size that only one
    /// can hold at a time, must never both be granted.
    #[test]
    fn concurrent_admissions_never_exceed_the_budget() {
        const BUDGET: u64 = 4096;
        const WANT: u64 = 3072; // two of these do not fit together
        let dir = tmpdir("contended");

        let watching = Arc::new(AtomicBool::new(true));
        let over = Arc::new(AtomicU64::new(0));
        let unparseable = Arc::new(AtomicU64::new(0));
        let watcher = std::thread::spawn({
            let (dir, watching, over, unparseable) = (
                dir.clone(),
                Arc::clone(&watching),
                Arc::clone(&over),
                Arc::clone(&unparseable),
            );
            move || {
                while watching.load(Ordering::Relaxed) {
                    let (used, odd) = live(&dir);
                    over.fetch_max(used, Ordering::Relaxed);
                    unparseable.fetch_add(odd as u64, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });

        // Stops the watcher however this test ends: a racer that panics unwinds past the
        // explicit stop below, and the watcher's poll loop has no deadline of its own.
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let _stop = StopOnDrop(Arc::clone(&watching));

        let racers: Vec<_> = (0..4)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let job = format!("job{i}");
                    let res = acquire(&dir, &job, WANT, BUDGET, Duration::from_secs(120))
                        .unwrap_or_else(|e| panic!("{job} was never admitted: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    drop(res);
                    release(&dir, &job);
                })
            })
            .collect();
        for r in racers {
            r.join().unwrap();
        }
        watching.store(false, Ordering::Relaxed);
        watcher.join().unwrap();

        assert!(
            over.load(Ordering::Relaxed) <= BUDGET,
            "the ledger held {} MiB of a {BUDGET} MiB budget",
            over.load(Ordering::Relaxed)
        );
        assert_eq!(
            unparseable.load(Ordering::Relaxed),
            0,
            "a scan caught an entry between its creation and its first write"
        );
        until_ledger_is(&dir, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_supervisor_picks_up_the_reservation_prepare_took() {
        let dir = tmpdir("handoff");
        let prepared = acquire(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
        // The supervisor takes its own lock on the same entry, then prepare exits.
        let supervised = hold(&dir, "job").expect("the entry prepare left");
        drop(prepared);

        // The reservation still counts, held by the supervisor alone.
        assert_eq!(live_mib(&dir), 2048);
        drop(supervised);
        until_ledger_is(&dir, 0);

        // A job with no reservation (admission off) has nothing to hold.
        assert!(hold(&dir, "unknown").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `hold` must never re-create an entry that has already gone: the file it made would be
    /// empty, so no scan could parse it, and none could reclaim it while this process held it
    /// locked — the job's memory would count for nobody for the whole of its life.
    #[test]
    fn hold_does_not_resurrect_an_entry_that_has_been_released() {
        let dir = tmpdir("hold-gone");
        let prepared = acquire(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
        drop(prepared);
        release(&dir, "job");

        assert!(hold(&dir, "job").is_none(), "nothing left to hold");
        assert!(!dir.join("job").exists(), "hold must not have created it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing a scan can see is ever half-written. An entry is created and written in one
    /// critical section, so a scanner — which must hold the directory lock, as this probe does
    /// — can only ever observe it complete. Were the write deferred to the next pass of the
    /// admission loop, a scan landing in between would fail to parse the entry: it would then
    /// report a ledger anomaly against a job that is merely starting up, and leave that job's
    /// request out of the queue order for the pass.
    ///
    /// The probe scans as fast as it can take the lock, against churn from admissions that
    /// never wait, so the window is sampled thousands of times rather than a handful.
    #[test]
    fn a_scan_never_observes_a_half_written_entry() {
        let dir = tmpdir("half-written");
        let watching = Arc::new(AtomicBool::new(true));
        let odd = Arc::new(AtomicU64::new(0));
        let scans = Arc::new(AtomicU64::new(0));
        let watcher = std::thread::spawn({
            let (dir, watching, odd, scans) = (
                dir.clone(),
                Arc::clone(&watching),
                Arc::clone(&odd),
                Arc::clone(&scans),
            );
            move || {
                while watching.load(Ordering::Relaxed) {
                    odd.fetch_add(live(&dir).1 as u64, Ordering::Relaxed);
                    scans.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let _stop = StopOnDrop(Arc::clone(&watching));

        // Four jobs that all fit together, so every acquire is granted on its first pass and
        // the churn is pure create-and-release.
        for _ in 0..50 {
            let held: Vec<_> = (0..4)
                .map(|i| {
                    let job = format!("job{i}");
                    (
                        acquire(&dir, &job, 512, 8192, Duration::from_secs(0)).unwrap(),
                        job,
                    )
                })
                .collect();
            for (res, job) in held {
                drop(res);
                release(&dir, &job);
            }
        }
        watching.store(false, Ordering::Relaxed);
        watcher.join().unwrap();

        assert!(scans.load(Ordering::Relaxed) > 100, "the probe barely ran");
        assert_eq!(
            odd.load(Ordering::Relaxed),
            0,
            "a scan could not parse an entry — it is not written where it is created"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ledger is the host's memory guard: an entry another local user could plant in it
    /// would stall every job on the box, so it must not inherit a permissive umask.
    #[test]
    fn the_ledger_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vk-admit-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let res = acquire(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700, "ledger directory");
        assert_eq!(mode(&dir.join("job")), 0o600, "ledger entry");
        assert_eq!(mode(&dir.join(LOCK)), 0o600, "directory lock");

        drop(res);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A locked entry nobody can parse — a holder killed mid-write — must not count as room.
    /// It stays until its lock goes, so the budget it stood for is neither freed nor doubled.
    #[test]
    fn an_unparseable_entry_is_kept_but_uncounted() {
        let dir = tmpdir("garbled");
        let garbled = open_shared(&dir.join("mid-write")).unwrap();

        assert_eq!(live_mib(&dir), 0, "an empty entry reserves nothing");
        assert!(dir.join("mid-write").exists(), "but is not reclaimed");

        // Once it finishes writing it counts, without having been reclaimed in between.
        Entry {
            want_mib: 2048,
            asked: 1,
            granted: true,
        }
        .write(&garbled, &dir.join("mid-write"))
        .unwrap();
        assert_eq!(live_mib(&dir), 2048);

        drop(garbled);
        release(&dir, "mid-write");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A non-zero timeout really is waited out, and the wait ends in a refusal rather than
    /// hanging — every other timeout case here passes zero.
    #[test]
    fn a_non_zero_timeout_expires_and_refuses() {
        let dir = tmpdir("expires");
        let _full = held(&dir, "running", 8192, 1, true);

        let asked_at = Instant::now();
        let err = acquire(&dir, "waiter", 8192, 8192, POLL + POLL / 2).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");
        assert!(
            asked_at.elapsed() >= POLL,
            "gave up before the timeout it was given"
        );
        assert!(!dir.join("waiter").exists(), "a refused job leaves nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
