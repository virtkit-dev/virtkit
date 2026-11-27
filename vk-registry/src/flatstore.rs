//! A flat store for caches such as sccache's. Each object occupies one file and retains
//! its original bytes. An optional size cap evicts the least recently modified files first.
//! An indexed miss avoids looking up the absent name and creating a negative dentry.
//!
//! ```text
//! <area>/objects/<hh>/<sha256(key) hex>   the objects, verbatim
//! <area>/runs/<id>/s-<n>                  an upload being written
//! <area>/runs/<id>/t-<n>/                 objects on their way out
//! <area>/evict.lock                       flock'd by the area's evictor
//! ```
//!
//! Processes sharing an area each have a [`FlatStore`] and an in-memory [`Index`] updated
//! by inotify. Requests take no cross-process locks. Each key has one name.
//!
//! - A miss in a loaded shard needs no object lookup.
//! - A hit opens the object. When [`Options::refresh`] is due, it tries to update mtime
//!   through the descriptor. A concurrent replacement keeps its own timestamp.
//! - A put writes a staging file in the instance's run directory, syncs it if
//!   [`Options::durable`], and renames it over the key's name. The last rename wins.
//! - A delete drains pending events before removing the key, so it sees puts that
//!   other instances completed before the delete began.
//!
//! Writers drain their own changes before returning. Other instances see changes when
//! they process their queues. If an indexed name vanishes before open, the reader drains
//! the queue and retries, up to three opens in all. These failed opens require a removal
//! racing the read. Ordinary index misses never open the name.
//!
//! Deletes and evictions normally move objects to trash under the run directory before
//! unlinking them. Trash rotates after [`TRASH_ROTATE`] moves. Removing the directory
//! frees the negative dentries left by its unlinks. If space or quota prevents creating
//! the trash directory or moving the object, the store unlinks the object in place.
//!
//! By default, power loss can leave a partial object. A cache that checks entries on
//! read, such as sccache with its ZIP checksums, can treat corruption as a miss.
//! [`Options::durable`] syncs each upload's bytes before publication. Neither mode syncs
//! directory changes. After power loss, an acknowledged put or delete can revert to the
//! previous object or leave the key absent. A process crash preserves acknowledged
//! changes in either mode.
//!
//! Each instance locks its run directory with `flock`. At startup and every
//! [`MAINTENANCE_INTERVAL`], it tries to reap abandoned runs. Temporary run names get
//! a grace period while their creators acquire the lock.
//!
//! Among capped instances, the holder of `evict.lock` loads all shards and checks object
//! sizes and modification times. Above the cap it aims for [`Options::evict_to`] times
//! the cap. It rechecks each candidate before removal. A replacement that lands after
//! the check can be evicted, leaving the key absent. Other capped instances retry the
//! lock and can take over when the evictor drops its [`FlatStore`] or exits.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, ensure};

pub use crate::objindex::Meta;
use crate::objindex::{Index, KeyHash, SHARDS, Stat, c_name, object_path, stat_at};

/// Moves per trash directory before rotation. A pass also rotates its last directory.
pub const TRASH_ROTATE: u64 = 1024;

/// Interval between background attempts to reap abandoned runs.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// Grace period before an unlocked temporary run can be reaped.
const UNNAMED_RUN_GRACE: Duration = Duration::from_secs(60);

/// Minimum background retry interval after an eviction error.
const EVICT_BACKOFF: Duration = Duration::from_secs(30);

/// A clock, in seconds since the epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// How a [`FlatStore`] behaves.
#[derive(Clone)]
pub struct Options {
    /// Area size cap in bytes. `None` disables eviction by this instance.
    pub cap: Option<u64>,
    /// Eviction target as a fraction of the cap, within `0..=1`. Values below one
    /// leave room for more puts between passes.
    pub evict_to: f64,
    /// Minimum age for a hit to attempt an mtime refresh, measured in whole seconds.
    /// The mtime must precede the current second.
    pub refresh: Duration,
    /// Background interval for checking the cap and retrying `evict.lock`, from 1 ms
    /// to one day.
    pub evict_interval: Duration,
    /// Clock for object timestamps. With `None`, the kernel timestamps each change so
    /// a delayed hit cannot write an earlier userspace sample.
    pub clock: Option<Clock>,
    /// Sync each upload's bytes before publication to protect them against power loss.
    /// Off by default so caches that reject corrupt entries can skip an `fdatasync` per put.
    pub durable: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            cap: None,
            evict_to: 0.9,
            refresh: Duration::from_secs(3600),
            evict_interval: Duration::from_secs(1),
            clock: None,
            durable: false,
        }
    }
}

impl Options {
    fn validate(&self) -> Result<()> {
        ensure!(
            (0.0..=1.0).contains(&self.evict_to),
            "evict_to must be within 0..=1, not {}",
            self.evict_to
        );
        ensure!(
            (Duration::from_millis(1)..=Duration::from_secs(86400)).contains(&self.evict_interval),
            "evict_interval must be from 1 ms to a day, not {:?}",
            self.evict_interval
        );
        Ok(())
    }
}

/// The [`Options`] an open store can change ([`FlatStore::set_policy`]).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Policy {
    pub cap: Option<u64>,
    pub evict_to: f64,
    pub durable: bool,
}

impl Policy {
    fn of(opts: &Options) -> Policy {
        Policy {
            cap: opts.cap,
            evict_to: opts.evict_to,
            durable: opts.durable,
        }
    }
}

/// An area's size, as the index knows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Keys present.
    pub objects: u64,
    /// Their bytes.
    pub bytes: u64,
}

/// What an eviction pass did.
#[derive(Clone, Debug, Default)]
pub struct EvictReport {
    /// Indexed bytes counted at the start of the pass.
    pub before: u64,
    /// Objects removed.
    pub evicted: u64,
    /// Measured bytes credited for successful unlinks.
    pub freed: u64,
    /// Candidates skipped after a removal, touch or replacement.
    pub raced: u64,
    /// Time spent draining events, loading shards and refreshing missing or stale stats.
    pub listed: Duration,
    /// Time spent choosing what to remove, listing included.
    pub select: Duration,
    /// The whole pass.
    pub total: Duration,
}

/// An object opened for reading.
#[derive(Debug)]
pub struct Object {
    pub file: File,
    pub meta: Meta,
}

/// One area, served by this process.
pub struct FlatStore {
    inner: Arc<Inner>,
    stop: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

struct Inner {
    /// For messages only: everything is resolved through the descriptors.
    root: PathBuf,
    root_fd: OwnedFd,
    /// `objects/`, which `<hh>/<name>` paths are resolved from.
    objects: OwnedFd,
    run: Run,
    index: Index,
    /// Options at open. Read mutable settings from `policy` (see [`FlatStore::set_policy`]).
    opts: Options,
    policy: Mutex<Policy>,
    /// `evict.lock`, held while this instance is the evictor.
    evictor: Mutex<Option<vk_fs::LockFile>>,
    is_evictor: AtomicBool,
    /// Held through a pass, so the background thread's and a caller's run one at a time.
    evicting: Mutex<()>,
    next_upload: AtomicU64,
}

/// This instance's run directory, flock'd for its lifetime.
struct Run {
    runs: OwnedFd,
    name: String,
    dir: OwnedFd,
    trash: Mutex<Trash>,
}

#[derive(Default)]
struct Trash {
    generation: u64,
    dir: Option<OwnedFd>,
    count: u64,
}

/// What [`Run::discard`] did.
#[derive(Debug, PartialEq, Eq)]
enum Discarded {
    /// Removed from the area. Carries the measured size, or zero if unmeasured or
    /// the trash unlink failed.
    Removed(u64),
    /// Already gone.
    Gone,
}

/// Whether `e` is the filesystem out of blocks or inodes, or the user out of quota.
fn out_of_space(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT))
}

/// [`Run::discard`] with no room to move `path` into the trash: unlinked where it lives,
/// leaving a negative dentry, rather than no space ever freed.
fn unlink_in_place(from: &OwnedFd, path: &str, measure: bool) -> Result<Discarded> {
    let size = match measure {
        true => match stat_at(from, path) {
            Ok(st) => Stat::of(&st).meta.size,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Discarded::Gone),
            Err(e) => return Err(e).with_context(|| format!("stat {path}")),
        },
        false => 0,
    };
    match unlink_at(from, path, 0) {
        Ok(()) => Ok(Discarded::Removed(size)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Discarded::Gone),
        Err(e) => Err(e).with_context(|| format!("unlinking {path}")),
    }
}

fn errno() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn open_dir_at(dir: &OwnedFd, name: &str) -> std::io::Result<OwnedFd> {
    let c = c_name(name).map_err(std::io::Error::other)?;
    // SAFETY: the descriptor is live and the name NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a mode-0700 directory and restore owner permissions masked by the umask.
fn mkdir_at(dir: &OwnedFd, name: &str) -> std::io::Result<()> {
    let c = c_name(name).map_err(std::io::Error::other)?;
    // SAFETY: `dir` is live and `c` is NUL-terminated.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        return Err(errno());
    }
    // SAFETY: `dir` is live and `c` names the directory just created.
    if unsafe { libc::fchmodat(dir.as_raw_fd(), c.as_ptr(), 0o700, 0) } != 0 {
        return Err(errno());
    }
    Ok(())
}

/// Make `root` and any missing parent as [`mkdir_at`] does, leaving one that exists as it is.
fn create_root(root: &Path) -> Result<()> {
    if root.is_dir() {
        return Ok(());
    }
    let parent = match root.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    create_root(parent)?;
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no UTF-8 final component", root.display()))?;
    match mkdir_at(&vk_fs::open_dir(parent)?, name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Create `name` or restore missing owner permissions. A process can die between
/// [`mkdir_at`]'s two steps.
fn ensure_dir(dir: &OwnedFd, name: &str) -> Result<()> {
    match mkdir_at(dir, name) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {name}/")),
    }
    let mode = stat_at(dir, name)
        .with_context(|| format!("stat {name}/"))?
        .st_mode;
    if mode & 0o700 != 0o700 {
        let c = c_name(name)?;
        // SAFETY: the descriptor is live and the name NUL-terminated.
        if unsafe { libc::fchmodat(dir.as_raw_fd(), c.as_ptr(), (mode & 0o7777) | 0o700, 0) } != 0 {
            return Err(errno()).with_context(|| format!("restoring {name}/'s mode"));
        }
    }
    Ok(())
}

/// Give `fd` the mode `mode`, whatever the umask made it.
fn fchmod(fd: &impl AsRawFd, mode: libc::mode_t) -> std::io::Result<()> {
    // SAFETY: a live descriptor.
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode) } != 0 {
        return Err(errno());
    }
    Ok(())
}

fn rename_at(from: &OwnedFd, old: &str, to: &OwnedFd, new: &str) -> std::io::Result<()> {
    let (o, n) = (
        c_name(old).map_err(std::io::Error::other)?,
        c_name(new).map_err(std::io::Error::other)?,
    );
    // SAFETY: both directory descriptors are live and both names are NUL-terminated.
    if unsafe { libc::renameat(from.as_raw_fd(), o.as_ptr(), to.as_raw_fd(), n.as_ptr()) } != 0 {
        return Err(errno());
    }
    Ok(())
}

fn unlink_at(dir: &OwnedFd, name: &str, flags: libc::c_int) -> std::io::Result<()> {
    let c = c_name(name).map_err(std::io::Error::other)?;
    // SAFETY: `dir` is live and `c` is NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), flags) } != 0 {
        return Err(errno());
    }
    Ok(())
}

fn try_flock(fd: &impl AsRawFd) -> std::io::Result<bool> {
    // SAFETY: plain flock on a live descriptor.
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = errno();
    if e.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(e)
    }
}

fn fstat(file: &File) -> std::io::Result<libc::stat> {
    // SAFETY: an all-zero `stat` is valid; the kernel overwrites it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a live descriptor and a writable `stat`.
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        return Err(errno());
    }
    Ok(st)
}

/// Set mtime to `secs` capped at `i64::MAX`, or to kernel time for `None`. Preserve atime.
fn set_mtime(file: &File, secs: Option<u64>) -> std::io::Result<()> {
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        match secs {
            Some(secs) => libc::timespec {
                tv_sec: secs.min(i64::MAX as u64) as _,
                tv_nsec: 0,
            },
            None => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_NOW,
            },
        },
    ];
    // SAFETY: a live descriptor and two timespecs.
    if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
        return Err(errno());
    }
    Ok(())
}

/// List UTF-8 entry names without statting individual entries.
fn names(dir: &OwnedFd) -> Result<Vec<String>> {
    // The store creates only UTF-8 names.
    Ok(vk_fs::dir_names(std::os::fd::AsFd::as_fd(dir))?
        .into_iter()
        .filter_map(|n| n.into_string().ok())
        .collect())
}

/// Remove interrupted uploads and trash from a run. Unrecognized top-level entries
/// stay. A later cleanup can retry failed removals.
fn clear_run(dir: &OwnedFd) {
    let numbered = |name: &str, prefix: &str| {
        name.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
    };
    for entry in names(dir).unwrap_or_default() {
        if !numbered(&entry, "s-") && !numbered(&entry, "t-") {
            continue; // not this store's
        }
        if entry.starts_with("t-") {
            if let Ok(t) = open_dir_at(dir, &entry) {
                for n in names(&t).unwrap_or_default() {
                    let _ = unlink_at(&t, &n, 0);
                }
            }
            let _ = unlink_at(dir, &entry, libc::AT_REMOVEDIR);
        } else {
            let _ = unlink_at(dir, &entry, 0);
        }
    }
}

/// Whether `name` is one [`Run::create`] gives: `<pid>-<16 hex digits>`.
pub fn is_run_name(name: &str) -> bool {
    name.split_once('-').is_some_and(|(pid, token)| {
        !pid.is_empty()
            && pid.bytes().all(|c| c.is_ascii_digit())
            && token.len() == 16
            && token
                .bytes()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    })
}

impl Run {
    /// Create the run under a temporary dot name. Publish its final name after
    /// acquiring the lock so a reaper can recognize a live published run.
    fn create(root: &OwnedFd) -> Result<Run> {
        ensure_dir(root, "runs")?;
        let runs = open_dir_at(root, "runs").context("opening runs/")?;
        let name = format!(
            "{}-{}",
            std::process::id(),
            crate::accounts::random_token(8)
        );
        let tmp = format!(".{name}");
        mkdir_at(&runs, &tmp).with_context(|| format!("creating runs/{tmp}"))?;
        let dir = open_dir_at(&runs, &tmp).with_context(|| format!("opening runs/{tmp}"))?;
        // A reaper can briefly hold the lock while checking the temporary name's age.
        // SAFETY: plain flock on a live descriptor.
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(errno()).context("locking a run directory");
        }
        rename_at(&runs, &tmp, &runs, &name).with_context(|| format!("naming runs/{name}"))?;
        Ok(Run {
            runs,
            name,
            dir,
            trash: Mutex::new(Trash::default()),
        })
    }

    /// Try to remove abandoned runs and their interrupted uploads and trash.
    /// Skip locked runs and young temporary names.
    fn reap(&self) -> Result<u64> {
        let mut reaped = 0;
        for name in names(&self.runs)? {
            if name == self.name || !is_run_name(name.strip_prefix('.').unwrap_or(&name)) {
                continue;
            }
            let Ok(dir) = open_dir_at(&self.runs, &name) else {
                continue; // another reaper may already have removed it
            };
            if !try_flock(&dir)? {
                continue;
            }
            if name.starts_with('.') {
                // Being made, or left by a process that died making it.
                let file = File::from(dir.try_clone()?);
                let age = file
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .unwrap_or_default();
                if age < UNNAMED_RUN_GRACE {
                    continue;
                }
            }
            clear_run(&dir);
            if unlink_at(&self.runs, &name, libc::AT_REMOVEDIR).is_ok() {
                reaped += 1;
            }
        }
        Ok(reaped)
    }

    /// Remove `path` relative to `from`. If `measure` is set, measure the object in
    /// trash. The in-place fallback measures the public name before unlinking it.
    fn discard(&self, from: &OwnedFd, path: &str, measure: bool) -> Result<Discarded> {
        let leaf = path.rsplit('/').next().unwrap_or(path);
        let mut t = self.trash.lock().unwrap_or_else(PoisonError::into_inner);
        let dir = match t.dir.take() {
            Some(dir) => dir,
            None => {
                let name = format!("t-{}", t.generation);
                match mkdir_at(&self.dir, &name) {
                    Ok(()) => {}
                    // made by an earlier call that failed to open it
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) if out_of_space(&e) => return unlink_in_place(from, path, measure),
                    Err(e) => return Err(e).with_context(|| format!("creating {name}")),
                }
                open_dir_at(&self.dir, &name).with_context(|| format!("opening {name}"))?
            }
        };
        let dir = t.dir.insert(dir);
        match rename_at(from, path, dir, leaf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Discarded::Gone),
            Err(e) if out_of_space(&e) => return unlink_in_place(from, path, measure),
            Err(e) => return Err(e).with_context(|| format!("moving {path} out")),
        }
        let size = match measure {
            true => stat_at(dir, leaf).map_or(0, |st| Stat::of(&st).meta.size),
            false => 0,
        };
        // A failure leaves it for the rotation to retry, and its bytes uncounted.
        let size = match unlink_at(dir, leaf, 0) {
            Ok(()) => size,
            Err(_) => 0,
        };
        t.count += 1;
        if t.count >= TRASH_ROTATE {
            self.rotate(&mut t);
        }
        Ok(Discarded::Removed(size))
    }

    /// Retire the current trash directory. [`clear_run`] retries failed removals at
    /// shutdown or when a reaper finds the abandoned run.
    fn rotate(&self, t: &mut Trash) {
        if let Some(dir) = t.dir.take() {
            for n in names(&dir).unwrap_or_default() {
                let _ = unlink_at(&dir, &n, 0);
            }
            let _ = unlink_at(
                &self.dir,
                &format!("t-{}", t.generation),
                libc::AT_REMOVEDIR,
            );
            t.generation += 1;
            t.count = 0;
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let mut t = self.trash.lock().unwrap_or_else(PoisonError::into_inner);
        self.rotate(&mut t);
        clear_run(&self.dir);
        // Left for the next reaper if it fails: the lock goes with the descriptor.
        let _ = unlink_at(&self.runs, &self.name, libc::AT_REMOVEDIR);
    }
}

/// An object being uploaded: written to a staging file, published by [`Upload::commit`],
/// discarded if dropped first.
pub struct Upload {
    inner: Arc<Inner>,
    file: Option<File>,
    name: String,
}

impl Write for Upload {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file
            .as_mut()
            .ok_or(std::io::ErrorKind::BrokenPipe)?
            .write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Upload {
    /// Clone the staging descriptor for writers that cannot use [`Write`], including async
    /// writers. Finish their writes before [`Upload::commit`].
    pub fn writer(&self) -> Result<File> {
        self.file
            .as_ref()
            .context("an upload's file is gone")?
            .try_clone()
            .context("duplicating an upload's descriptor")
    }

    /// Publish the upload under `key`, replacing its previous object. [`Options::durable`]
    /// syncs the bytes before publication. Drain queued events before returning.
    pub fn commit(mut self, key: &[u8]) -> Result<Meta> {
        let inner = Arc::clone(&self.inner);
        let file = self.file.take().context("an upload's file is gone")?;
        set_mtime(&file, inner.opts.clock.as_ref().map(|c| c())).context("stamping an upload")?;
        // Report data-sync errors before publishing the staging file.
        if inner.policy().durable {
            file.sync_data().context("syncing an upload")?;
        }
        let meta = Stat::of(&fstat(&file).context("an upload's size")?).meta;
        drop(file);
        let hash = KeyHash::of(key);
        let path = object_path(&hash);
        rename_at(&inner.run.dir, &self.name, &inner.objects, &path)
            .with_context(|| format!("publishing {path}"))?;
        self.name.clear();
        inner.index.drain()?;
        Ok(meta)
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.name.is_empty() {
            drop(self.file.take());
            // Through the trash, so the unlink's negative dentry goes with it. Should that
            // fail (no room for a trash directory, say), unlinked in place: the run directory
            // goes, and the dentry with it, when this instance ends.
            if self
                .inner
                .run
                .discard(&self.inner.run.dir, &self.name, false)
                .is_err()
            {
                let _ = unlink_at(&self.inner.run.dir, &self.name, 0);
            }
        }
    }
}

impl Inner {
    fn policy(&self) -> Policy {
        *self.policy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn usage(&self) -> Usage {
        let mut u = Usage::default();
        self.index.each_loaded(|_, s| {
            u.objects += s.keys.len() as u64;
            u.bytes += s.bytes;
        });
        u
    }

    /// Apply what is queued, load every shard and `stat` what is not known yet.
    fn catch_up(&self) -> Result<()> {
        self.index.drain()?;
        self.index.load_all()?;
        self.index.fill()
    }

    /// Take `evict.lock` if no one holds it; whether this instance is the evictor.
    fn elect(&self) -> Result<bool> {
        let mut held = self.evictor.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_some() {
            return Ok(true);
        }
        let c = c_name("evict.lock")?;
        // SAFETY: the descriptor is live and the name NUL-terminated.
        let fd = unsafe {
            libc::openat(
                self.root_fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(errno()).context("opening evict.lock");
        }
        // SAFETY: fresh descriptor.
        let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        fchmod(&file, 0o600).context("evict.lock's mode")?;
        if !try_flock(&file).context("locking evict.lock")? {
            return Ok(false);
        }
        *held = Some(vk_fs::LockFile::new(file));
        self.is_evictor.store(true, Ordering::Relaxed);
        Ok(true)
    }

    /// Give `evict.lock` up, for another instance to take.
    fn resign(&self) {
        let mut held = self.evictor.lock().unwrap_or_else(PoisonError::into_inner);
        self.is_evictor.store(false, Ordering::Relaxed);
        drop(held.take());
    }

    /// Serialize election and eviction under `evicting`. With `only_over`, check usage
    /// before starting a pass. On a pass error, release the role so another instance
    /// can try.
    fn evict(&self, cap: u64, evict_to: f64, only_over: bool) -> Result<Option<EvictReport>> {
        let _pass = self.evicting.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.elect()? {
            return Ok(None);
        }
        let done = (|| {
            if only_over {
                self.catch_up()?;
                if self.usage().bytes <= cap {
                    return Ok(None);
                }
            }
            self.pass(cap, evict_to).map(Some)
        })();
        if done.is_err() {
            self.resign();
        }
        done
    }

    fn pass(&self, cap: u64, evict_to: f64) -> Result<EvictReport> {
        let start = Instant::now();
        self.index.drain()?;
        // Recount before selecting candidates. Running totals can retain a replaced
        // object's old size when an event invalidates its stat, making an area under
        // cap appear over.
        let (_, before) = self.index.usage()?;
        let mut report = EvictReport {
            before,
            listed: start.elapsed(),
            ..EvictReport::default()
        };
        let mut live = Vec::new();
        self.index.each_loaded(|_, s| {
            live.extend(s.stats.iter().map(|(k, st)| (*st, *k)));
        });
        if report.before > cap {
            let target = (cap as f64 * evict_to) as u64;
            live.sort_unstable_by_key(|(st, _)| st.meta.mtime);
            report.select = start.elapsed();
            for (st, hash) in live {
                // Since selection, other processes may have freed space, replaced or
                // touched a candidate, or caused a queue overflow that requires relisting.
                self.index.drain()?;
                if self.index.usage()?.1 <= target {
                    break;
                }
                // Check both the cached stat and the name in case its event is still queued.
                let path = object_path(&hash);
                let unchanged = self.index.stat(&hash) == Some(st)
                    && match stat_at(&self.objects, &path) {
                        Ok(now) => Stat::of(&now) == st,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                        Err(e) => return Err(e).with_context(|| format!("stat {path}")),
                    };
                if !unchanged {
                    report.raced += 1;
                    continue;
                }
                // A replacement after this check may be evicted, leaving a miss.
                match self.run.discard(&self.objects, &path, true)? {
                    Discarded::Removed(size) => {
                        report.evicted += 1;
                        report.freed += size;
                    }
                    Discarded::Gone => report.raced += 1,
                }
            }
            self.index.drain()?;
        } else {
            report.select = start.elapsed();
        }
        {
            let mut t = self
                .run
                .trash
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.run.rotate(&mut t);
        }
        self.run.reap()?;
        report.total = start.elapsed();
        Ok(report)
    }
}

impl FlatStore {
    /// Open or create the area at `root` and reap abandoned runs. Shard contents
    /// load on demand.
    pub fn open(root: &Path, opts: Options) -> Result<FlatStore> {
        FlatStore::open_with(root, opts, true)
    }

    /// With `spawn` false, callers drive event processing and [`FlatStore::evict`]
    /// enforces the cap.
    fn open_with(root: &Path, opts: Options, spawn: bool) -> Result<FlatStore> {
        opts.validate()?;
        create_root(root).with_context(|| format!("creating {}", root.display()))?;
        let root_fd = vk_fs::open_dir(root)?;
        ensure_dir(&root_fd, "objects")?;
        let objects = open_dir_at(&root_fd, "objects").context("opening objects/")?;
        // List shards to identify missing directories without probing absent names.
        let mut present = [false; SHARDS];
        for name in names(&objects)? {
            if let Ok(s) = u8::from_str_radix(&name, 16)
                && name.len() == 2
                && name == format!("{s:02x}")
            {
                // Paths go through it: a symlink would lead puts and removals elsewhere.
                let st =
                    stat_at(&objects, &name).with_context(|| format!("stat objects/{name}"))?;
                ensure!(
                    st.st_mode & libc::S_IFMT == libc::S_IFDIR,
                    "objects/{name} is not a directory"
                );
                if st.st_mode & 0o700 != 0o700 {
                    // left by a process that died between mkdir_at's two steps
                    ensure_dir(&objects, &name)?;
                }
                present[usize::from(s)] = true;
            }
        }
        for s in (0..=u8::MAX).filter(|s| !present[usize::from(*s)]) {
            ensure_dir(&objects, &format!("{s:02x}"))
                .with_context(|| format!("creating objects/{s:02x}"))?;
        }
        let run = Run::create(&root_fd)?;
        run.reap()?;
        let index = Index::new(&objects)?;
        let inner = Arc::new(Inner {
            root: root.to_path_buf(),
            root_fd,
            objects,
            run,
            index,
            policy: Mutex::new(Policy::of(&opts)),
            opts,
            evictor: Mutex::new(None),
            is_evictor: AtomicBool::new(false),
            evicting: Mutex::new(()),
            next_upload: AtomicU64::new(0),
        });
        // SAFETY: no pointers; the result is checked.
        let stop = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if stop < 0 {
            return Err(errno()).context("creating an eventfd");
        }
        // SAFETY: fresh descriptor.
        let stop = unsafe { OwnedFd::from_raw_fd(stop) };
        let thread = if spawn {
            let inner = Arc::clone(&inner);
            let stop = stop.as_raw_fd();
            std::thread::Builder::new()
                .name("flatstore".into())
                .spawn(move || background(&inner, stop))
                .map(Some)
                .context("starting the flatstore thread")?
        } else {
            None
        };
        Ok(FlatStore {
            inner,
            stop,
            thread,
        })
    }

    /// Check the index for `key`, loading its shard on first use.
    pub fn contains(&self, key: &[u8]) -> Result<bool> {
        self.inner.index.contains(&KeyHash::of(key))
    }

    /// Open `key`'s object. An index miss in a loaded shard requires no object lookup.
    pub fn get(&self, key: &[u8]) -> Result<Option<Object>> {
        let inner = &self.inner;
        let hash = KeyHash::of(key);
        let path = object_path(&hash);
        // A removal can race the open. Drain its event and any replacement before retrying.
        for _ in 0..3 {
            if !inner.index.contains(&hash)? {
                return Ok(None);
            }
            let c = c_name(&path)?;
            // SAFETY: the descriptor is live and the path NUL-terminated.
            let fd = unsafe {
                libc::openat(
                    inner.objects.as_raw_fd(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let e = errno();
                if e.kind() == std::io::ErrorKind::NotFound {
                    inner.index.drain()?;
                    continue;
                }
                return Err(e).with_context(|| format!("opening {path}"));
            }
            // SAFETY: fresh descriptor.
            let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
            let mut meta = Stat::of(&fstat(&file).with_context(|| format!("stat {path}"))?).meta;
            let fixed = inner.opts.clock.as_ref().map(|c| c());
            let now = fixed.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            });
            // Refresh the open file even if its name has been replaced. A failed touch,
            // for example on another owner's object, affects only recency.
            if now > meta.mtime
                && now - meta.mtime >= inner.opts.refresh.as_secs()
                && set_mtime(&file, fixed).is_ok()
            {
                // Read back a kernel-chosen mtime when available.
                meta.mtime = match fixed {
                    Some(t) => t,
                    None => fstat(&file).map_or(now, |st| Stat::of(&st).meta.mtime),
                };
            }
            return Ok(Some(Object { file, meta }));
        }
        Ok(None)
    }

    /// Start an upload, to [`Upload::commit`] under a key once written.
    pub fn upload(&self) -> Result<Upload> {
        let inner = &self.inner;
        let name = format!("s-{}", inner.next_upload.fetch_add(1, Ordering::Relaxed));
        let c = c_name(&name)?;
        // SAFETY: the descriptor is live and the name NUL-terminated.
        let fd = unsafe {
            libc::openat(
                inner.run.dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(errno()).with_context(|| format!("creating {name}"));
        }
        let up = Upload {
            inner: Arc::clone(inner),
            // SAFETY: fresh descriptor.
            file: Some(File::from(unsafe { OwnedFd::from_raw_fd(fd) })),
            name,
        };
        // Readable by the instances that will open it, whatever the umask.
        if let Some(f) = &up.file {
            fchmod(f, 0o600).context("an upload's mode")?;
        }
        Ok(up)
    }

    /// Put `body` as `key`'s object.
    pub fn put(&self, key: &[u8], body: &mut impl Read) -> Result<Meta> {
        let mut up = self.upload()?;
        std::io::copy(body, &mut up).context("writing an upload")?;
        up.commit(key)
    }

    /// Remove `key`'s object; whether there was one. Removes any put, by any instance, that
    /// returned before this call began.
    pub fn delete(&self, key: &[u8]) -> Result<bool> {
        let inner = &self.inner;
        let hash = KeyHash::of(key);
        inner.index.drain()?;
        if !inner.index.contains(&hash)? {
            return Ok(false);
        }
        let done = inner
            .run
            .discard(&inner.objects, &object_path(&hash), false)?;
        inner.index.drain()?;
        Ok(done != Discarded::Gone)
    }

    /// The area's usage. Loads every shard and `stat`s every object not `stat`ed yet.
    pub fn usage(&self) -> Result<Usage> {
        self.inner.index.drain()?;
        let (objects, bytes) = self.inner.index.usage()?;
        Ok(Usage { objects, bytes })
    }

    /// Run an eviction pass now if this instance is, or can become, the evictor: `None` if
    /// another holds `evict.lock`, or this instance has no cap.
    pub fn evict(&self) -> Result<Option<EvictReport>> {
        // Use the same cap and target throughout the pass.
        let p = self.inner.policy();
        match p.cap {
            Some(cap) => self.inner.evict(cap, p.evict_to, false),
            None => Ok(None),
        }
    }

    /// The current cap, eviction target and durability.
    pub fn policy(&self) -> Policy {
        self.inner.policy()
    }

    /// Change the cap, eviction target and durability. The background thread reads the cap
    /// at its next check and releases `evict.lock` if still uncapped. Checks are scheduled
    /// every [`Options::evict_interval`] (one second by default). After an eviction error,
    /// the delay is the longer of that interval and [`EVICT_BACKOFF`].
    pub fn set_policy(&self, policy: Policy) -> Result<()> {
        Options {
            evict_to: policy.evict_to,
            ..self.inner.opts.clone()
        }
        .validate()?;
        *self
            .inner
            .policy
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = policy;
        Ok(())
    }

    /// Apply the queued inotify events now rather than when the background thread wakes.
    pub fn sync(&self) -> Result<()> {
        self.inner.index.drain()?;
        Ok(())
    }

    /// How many shards this instance has loaded, and so watches.
    pub fn loaded_shards(&self) -> usize {
        self.inner.index.loaded()
    }

    /// Whether this instance holds `evict.lock`.
    pub fn is_evictor(&self) -> bool {
        self.inner.is_evictor.load(Ordering::Relaxed)
    }
}

impl Drop for FlatStore {
    fn drop(&mut self) {
        let one = 1u64.to_ne_bytes();
        // SAFETY: an 8-byte write to a live eventfd. On failure, detach because joining
        // could block indefinitely.
        if let Some(t) = self.thread.take()
            && unsafe { libc::write(self.stop.as_raw_fd(), one.as_ptr().cast(), 8) } == 8
        {
            let _ = t.join();
        }
        // An upload still open keeps the rest of `Inner`, but not the evictor's role.
        self.inner.resign();
    }
}

/// Apply inotify events as they come, enforce the cap, and reap.
fn background(inner: &Inner, stop: i32) {
    let tick = inner.opts.evict_interval;
    let mut next_check = Instant::now() + tick;
    let mut next_reap = Instant::now() + MAINTENANCE_INTERVAL;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: inner.index.event_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: inner.index.wake_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait = next_check
            .min(next_reap)
            .saturating_duration_since(Instant::now());
        let ms = wait.as_micros().div_ceil(1000).min(60_000) as i32;
        // SAFETY: three valid pollfds.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 3, ms) };
        if n < 0 && errno().kind() != std::io::ErrorKind::Interrupted {
            eprintln!("flatstore {}: poll: {}", inner.root.display(), errno());
            return;
        }
        if fds[1].revents != 0 {
            return;
        }
        if fds[2].revents != 0 {
            inner.index.woken(); // re-read the event descriptor on the next poll
        }
        // Bound each drain so new arrivals cannot indefinitely postpone the deadline checks.
        if fds[0].revents != 0
            && let Err(e) = inner.index.drain()
        {
            eprintln!("flatstore {}: {e:#}", inner.root.display());
        }
        let now = Instant::now();
        if now >= next_check {
            next_check = now + tick;
            let p = inner.policy();
            match p.cap {
                // Only the elected instance loads all shards for background eviction.
                Some(cap) => {
                    if let Err(e) = inner.evict(cap, p.evict_to, true) {
                        eprintln!("flatstore {}: evicting: {e:#}", inner.root.display());
                        // Leave the role to others a while before trying again.
                        next_check = now + tick.max(EVICT_BACKOFF);
                    }
                }
                None if inner.is_evictor.load(Ordering::Relaxed) => {
                    // Let any active pass finish before releasing the role.
                    // The cap may change while waiting.
                    let _pass = inner
                        .evicting
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    if inner.policy().cap.is_none() {
                        inner.resign();
                    }
                }
                None => {}
            }
        }
        if now >= next_reap {
            next_reap = now + MAINTENANCE_INTERVAL;
            if let Err(e) = inner.run.reap() {
                eprintln!("flatstore {}: reaping: {e:#}", inner.root.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn area(name: &str) -> PathBuf {
        crate::testtmp::root().join(format!("flatstore-{name}"))
    }

    /// Options on a clock the test sets.
    fn opts(clock: &Arc<AtomicU64>) -> Options {
        let clock = Arc::clone(clock);
        Options {
            clock: Some(Arc::new(move || clock.load(Ordering::Relaxed))),
            ..Options::default()
        }
    }

    fn quiet(root: &Path, opts: Options) -> FlatStore {
        FlatStore::open_with(root, opts, false).unwrap()
    }

    fn put(store: &FlatStore, key: &str, body: &[u8]) -> Meta {
        store.put(key.as_bytes(), &mut &body[..]).unwrap()
    }

    fn read(store: &FlatStore, key: &str) -> Option<Vec<u8>> {
        let mut obj = store.get(key.as_bytes()).unwrap()?;
        let mut out = Vec::new();
        obj.file.read_to_end(&mut out).unwrap();
        Some(out)
    }

    /// Every file under `dir`, relative to it.
    fn files(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(d) = todo.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    todo.push(e.path());
                } else {
                    let rel = e.path().strip_prefix(dir).unwrap().display().to_string();
                    out.push(rel);
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn two_instances_see_each_others_puts_replacements_and_deletes() {
        let root = area("coherence");
        let clock = Arc::new(AtomicU64::new(1000));
        let (a, b) = (quiet(&root, opts(&clock)), quiet(&root, opts(&clock)));
        assert!(!b.contains(b"k").unwrap()); // loads b's shard before a writes
        let first = put(&a, "k", b"one");
        assert_eq!(
            first,
            Meta {
                size: 3,
                mtime: 1000
            }
        );
        b.sync().unwrap();
        assert!(b.contains(b"k").unwrap());
        assert_eq!(read(&b, "k").as_deref(), Some(&b"one"[..]));

        clock.store(1001, Ordering::Relaxed);
        put(&a, "k", b"second");
        assert_eq!(read(&b, "k").as_deref(), Some(&b"second"[..]));
        // one name per key, and nothing left beside the object
        assert_eq!(files(&root.join("objects")).len(), 1);
        assert!(files(&root.join("runs")).is_empty());

        assert!(b.delete(b"k").unwrap());
        a.sync().unwrap();
        assert!(!a.contains(b"k").unwrap());
        assert_eq!(read(&a, "k"), None);
        assert!(files(&root.join("objects")).is_empty());
    }

    #[test]
    fn the_later_of_two_puts_wins_whatever_its_size_or_the_index_lag() {
        let root = area("order");
        let clock = Arc::new(AtomicU64::new(1000));
        let (a, b) = (quiet(&root, opts(&clock)), quiet(&root, opts(&clock)));
        assert!(!b.contains(b"k").unwrap());
        put(&a, "k", &[1; 100]);
        // b has not applied a's put, and puts a smaller object in the same second
        put(&b, "k", &[2; 10]);
        a.sync().unwrap();
        for s in [&a, &b] {
            assert_eq!(read(s, "k"), Some(vec![2; 10]));
            assert_eq!(
                s.usage().unwrap(),
                Usage {
                    objects: 1,
                    bytes: 10
                }
            );
        }
        assert_eq!(files(&root.join("objects")).len(), 1);
    }

    #[test]
    fn a_delete_removes_a_put_its_instance_had_not_applied() {
        let root = area("delete-lag");
        let (a, b) = (
            quiet(&root, Options::default()),
            quiet(&root, Options::default()),
        );
        assert!(!a.contains(b"k").unwrap());
        put(&b, "k", b"x");
        assert!(a.delete(b"k").unwrap());
        assert!(!a.contains(b"k").unwrap());
        // and a put after the delete, by the instance that has not seen it, stays
        put(&b, "k", b"y");
        a.sync().unwrap();
        assert_eq!(read(&a, "k").as_deref(), Some(&b"y"[..]));
        assert!(!a.delete(b"absent").unwrap());
    }

    #[test]
    fn shards_load_on_first_touch_only() {
        let root = area("lazy");
        let a = quiet(&root, Options::default());
        put(&a, "x", b"x");
        let b = quiet(&root, Options::default());
        assert_eq!(b.loaded_shards(), 0);
        assert!(b.contains(b"x").unwrap());
        assert_eq!(b.loaded_shards(), 1);
        assert_eq!(
            b.usage().unwrap(),
            Usage {
                objects: 1,
                bytes: 1
            }
        );
        assert_eq!(b.loaded_shards(), SHARDS);
    }

    #[test]
    fn a_name_gone_under_the_index_is_a_miss_and_forgotten() {
        let root = area("enoent");
        let a = quiet(&root, Options::default());
        put(&a, "gone", b"abc");
        assert!(a.contains(b"gone").unwrap()); // loads the shard
        let path = root
            .join("objects")
            .join(object_path(&KeyHash::of(b"gone")));
        std::fs::rename(&path, root.join("elsewhere")).unwrap();
        // no sync: the index still has it
        assert!(a.contains(b"gone").unwrap());
        assert!(a.get(b"gone").unwrap().is_none());
        assert!(!a.contains(b"gone").unwrap());
    }

    #[test]
    fn a_hit_past_the_refresh_interval_renews_the_mtime_in_place() {
        let root = area("refresh");
        let clock = Arc::new(AtomicU64::new(1000));
        let (a, b) = (quiet(&root, opts(&clock)), quiet(&root, opts(&clock)));
        put(&a, "r", b"r");
        let name = files(&root.join("objects"));
        clock.store(1000 + 3599, Ordering::Relaxed);
        assert_eq!(a.get(b"r").unwrap().unwrap().meta.mtime, 1000);
        clock.store(1000 + 3600, Ordering::Relaxed);
        assert_eq!(a.get(b"r").unwrap().unwrap().meta.mtime, 4600);
        assert_eq!(files(&root.join("objects")), name);
        // b caches the refreshed mtime. The next touch invalidates it.
        assert_eq!(b.usage().unwrap().bytes, 1);
        let hash = KeyHash::of(b"r");
        assert_eq!(b.inner.index.stat(&hash).unwrap().meta.mtime, 4600);
        clock.store(9000, Ordering::Relaxed);
        a.get(b"r").unwrap().unwrap();
        b.sync().unwrap();
        assert_eq!(b.inner.index.stat(&hash), None);
        b.usage().unwrap();
        assert_eq!(b.inner.index.stat(&hash).unwrap().meta.mtime, 9000);
    }

    #[test]
    fn a_hit_with_a_lagging_index_reads_the_newest_object_and_keeps_it() {
        let root = area("refresh-race");
        let clock = Arc::new(AtomicU64::new(1000));
        let (a, b) = (quiet(&root, opts(&clock)), quiet(&root, opts(&clock)));
        put(&a, "k", b"old");
        let held = a.get(b"k").unwrap().unwrap();
        clock.store(1000 + 7200, Ordering::Relaxed);
        put(&b, "k", b"new");
        // a still holds the old file and has not applied b's put. Its next read opens the replacement.
        assert_eq!(read(&a, "k").as_deref(), Some(&b"new"[..]));
        drop(held);
        b.sync().unwrap();
        assert_eq!(read(&b, "k").as_deref(), Some(&b"new"[..]));
        assert_eq!(files(&root.join("objects")).len(), 1);
    }

    #[test]
    fn an_upload_dropped_uncommitted_leaves_nothing() {
        let root = area("abort");
        let a = quiet(&root, Options::default());
        let mut up = a.upload().unwrap();
        up.write_all(b"partial").unwrap();
        drop(up);
        assert!(files(&root.join("runs")).is_empty());
        assert!(files(&root.join("objects")).is_empty());
    }

    #[test]
    fn one_of_two_racing_evictors_brings_the_area_under_its_cap_oldest_first() {
        let root = area("evict");
        let clock = Arc::new(AtomicU64::new(1000));
        let capped = Options {
            cap: Some(1000),
            evict_to: 0.5,
            ..opts(&clock)
        };
        let (a, b) = (quiet(&root, capped.clone()), quiet(&root, capped));
        for i in 0..20u64 {
            clock.store(1000 + i, Ordering::Relaxed);
            put(
                if i % 2 == 0 { &a } else { &b },
                &format!("k{i}"),
                &[0; 100],
            );
        }
        let reports: Vec<_> = std::thread::scope(|s| {
            let ta = s.spawn(|| a.evict().unwrap());
            let tb = s.spawn(|| b.evict().unwrap());
            [ta.join().unwrap(), tb.join().unwrap()]
        })
        .into_iter()
        .flatten()
        .collect();
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!((reports[0].before, reports[0].evicted), (2000, 15));
        assert_eq!(a.is_evictor() as u8 + b.is_evictor() as u8, 1);
        for s in [&a, &b] {
            s.sync().unwrap();
            assert_eq!(
                s.usage().unwrap(),
                Usage {
                    objects: 5,
                    bytes: 500
                }
            );
            for i in 0..20 {
                assert_eq!(s.contains(format!("k{i}").as_bytes()).unwrap(), i >= 15);
            }
        }
        assert_eq!(files(&root.join("objects")).len(), 5);
        // Under the cap, a pass removes nothing.
        let again = if a.is_evictor() { &a } else { &b };
        assert_eq!(again.evict().unwrap().unwrap().evicted, 0);
    }

    #[test]
    fn what_a_dead_instance_left_is_removed_and_a_live_ones_kept() {
        let root = area("reap");
        let live = quiet(&root, Options::default());
        let runs = root.join("runs");
        let (dead1, dead2, young) = (
            "1-00000000000000d1",
            ".2-00000000000000d2",
            ".3-00000000000000a3",
        );
        std::fs::create_dir_all(runs.join("build-42")).unwrap();
        std::fs::write(runs.join("build-42").join("output"), b"not ours").unwrap();
        for dead in [dead1, dead2] {
            std::fs::create_dir_all(runs.join(dead).join("t-0")).unwrap();
            std::fs::write(runs.join(dead).join("s-0"), b"cut short").unwrap();
            std::fs::write(runs.join(dead).join("t-0").join("obj"), b"evicted").unwrap();
        }
        // A file this store would not make is left, and with it the directory.
        std::fs::write(runs.join(dead1).join("notes"), b"not ours").unwrap();
        // A dot name is young: kept until it is past the grace period.
        let born = File::open(runs.join(dead2)).unwrap();
        born.set_modified(SystemTime::now() - UNNAMED_RUN_GRACE * 2)
            .unwrap();
        std::fs::create_dir(runs.join(young)).unwrap();
        let _next = quiet(&root, Options::default());
        let mut left = files(&runs);
        left.retain(|f| !f.starts_with(&_next.inner.run.name));
        assert_eq!(
            left,
            vec![format!("{dead1}/notes"), "build-42/output".to_string()]
        );
        assert!(runs.join(&live.inner.run.name).is_dir());
        assert!(runs.join(young).is_dir());
        assert!(!runs.join(dead2).exists());
    }

    #[test]
    fn trash_directories_rotate_and_a_leftover_one_is_reused() {
        let root = area("rotate");
        let a = quiet(&root, Options::default());
        let run = root.join("runs").join(&a.inner.run.name);
        // As an earlier call that made it but failed to open it would leave it.
        std::fs::create_dir(run.join("t-0")).unwrap();
        for _ in 0..TRASH_ROTATE + 3 {
            put(&a, "same", b"x");
            assert!(a.delete(b"same").unwrap());
        }
        let trash: Vec<_> = std::fs::read_dir(&run)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(trash, vec!["t-1".to_string()]);
        drop(a);
        assert!(!run.exists());
    }

    #[test]
    fn an_upload_left_open_does_not_keep_the_evictor_role() {
        let root = area("resign");
        let capped = Options {
            cap: Some(1 << 30),
            ..Options::default()
        };
        let a = quiet(&root, capped.clone());
        assert!(a.evict().unwrap().is_some());
        let mut up = a.upload().unwrap();
        drop(a);
        let b = quiet(&root, capped);
        assert!(b.evict().unwrap().is_some());
        up.write_all(b"late").unwrap();
        up.commit(b"late").unwrap();
        b.sync().unwrap();
        assert_eq!(read(&b, "late").as_deref(), Some(&b"late"[..]));
    }

    #[test]
    fn options_out_of_range_are_refused() {
        let root = area("options");
        for bad in [
            Options {
                evict_to: 2.0,
                ..Options::default()
            },
            Options {
                evict_to: f64::NAN,
                ..Options::default()
            },
            Options {
                evict_interval: Duration::ZERO,
                ..Options::default()
            },
        ] {
            assert!(FlatStore::open_with(&root, bad, false).is_err());
        }
    }

    #[test]
    fn the_background_thread_applies_foreign_writes() {
        let root = area("background");
        let a = FlatStore::open(&root, Options::default()).unwrap();
        let b = quiet(&root, Options::default());
        assert!(!a.contains(b"bg").unwrap());
        put(&b, "bg", b"x");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !a.contains(b"bg").unwrap() {
            assert!(Instant::now() < deadline, "never saw the put");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_missing_root_and_its_parents_are_made_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let parent = area("made").join("parent");
        let root = parent.join("root");
        drop(quiet(&root, Options::default()));
        for dir in [&parent, &root] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", dir.display());
        }
    }

    #[test]
    fn puts_publish_whole_objects_durable_or_not() {
        for durable in [false, true] {
            let root = area(&format!("durable-{durable}"));
            let store = quiet(
                &root,
                Options {
                    durable,
                    ..Options::default()
                },
            );
            assert_eq!(put(&store, "k", b"body").size, 4);
            assert_eq!(read(&store, "k").as_deref(), Some(&b"body"[..]));
            assert!(files(&root.join("runs")).is_empty());
        }
    }

    #[test]
    fn a_shard_moved_away_and_remade_is_listed_again() {
        let root = area("moved-shard");
        let (a, b) = (
            quiet(&root, Options::default()),
            quiet(&root, Options::default()),
        );
        assert!(!a.contains(b"k").unwrap()); // a watches k's shard
        let hh = format!("{:02x}", KeyHash::of(b"k").shard());
        let objects = root.join("objects");
        std::fs::rename(objects.join(&hh), root.join("aside")).unwrap();
        std::fs::create_dir(objects.join(&hh)).unwrap();
        put(&b, "k", b"x");
        a.sync().unwrap();
        assert_eq!(read(&a, "k").as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn opening_restores_the_owner_bits_of_a_shard() {
        use std::os::unix::fs::PermissionsExt;
        let root = area("shard-mode");
        drop(quiet(&root, Options::default()));
        let shard = root.join("objects").join("2a");
        std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o000)).unwrap();
        drop(quiet(&root, Options::default()));
        let mode = std::fs::metadata(&shard).unwrap().permissions().mode();
        assert_eq!(mode & 0o700, 0o700);
    }
}
