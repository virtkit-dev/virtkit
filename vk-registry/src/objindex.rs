//! In-memory index of the objects in one [`crate::flatstore`] area.
//!
//! The 256 `objects/<hh>/` shards contain files named by the SHA-256 hex digest of
//! their keys ([`object_name`]). A directory listing gives the shard's key hashes.
//! Checking an absent key in memory avoids a lookup that could leave a negative dentry.
//!
//! First use installs an inotify watch before listing the shard. After listing, only
//! events update membership. Writers drain their own changes in queue order so a local
//! update cannot undo a later event. On overflow the index discards its watches and
//! listings and rebuilds each shard on demand.
//!
//! Usage reporting and eviction stat indexed names on demand for size and modification
//! time. A replacement or touch invalidates the cached stat. Its size remains in the
//! running estimate until the next accepted stat.

use std::collections::HashMap;
use std::ffi::CString;
use std::hash::{BuildHasherDefault, Hasher};
use std::os::fd::{AsFd as _, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError, RwLock, RwLockReadGuard};

use anyhow::{Context, Result, anyhow, bail};

/// The number of shard directories: one per first byte of the key hash.
pub(crate) const SHARDS: usize = 256;

/// The SHA-256 of a key, which names its object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct KeyHash(pub(crate) [u8; 32]);

impl KeyHash {
    pub(crate) fn of(key: &[u8]) -> KeyHash {
        use sha2::Digest as _;
        KeyHash(sha2::Sha256::digest(key).into())
    }

    /// The shard the object lives in.
    pub(crate) fn shard(&self) -> u8 {
        self.0[0]
    }
}

impl std::hash::Hash for KeyHash {
    // Already a uniform hash: eight of its bytes are the map's hash. Not the first byte,
    // which every key of a shard shares.
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut word = [0u8; 8];
        word.copy_from_slice(&self.0[8..16]);
        state.write_u64(u64::from_le_bytes(word));
    }
}

/// Passes through the `u64` [`KeyHash`] writes.
#[derive(Default)]
pub(crate) struct PassThrough(u64);

impl Hasher for PassThrough {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*b);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

/// An object's size in bytes, and its modification time in seconds since the epoch: when
/// it was put or last refreshed by a hit, the recency eviction goes by.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Meta {
    pub size: u64,
    pub mtime: u64,
}

/// What a `stat` of an object said.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Stat {
    pub(crate) meta: Meta,
    pub(crate) ino: u64,
}

impl Stat {
    pub(crate) fn of(st: &libc::stat) -> Stat {
        Stat {
            meta: Meta {
                size: u64::try_from(st.st_size).unwrap_or(0),
                mtime: u64::try_from(st.st_mtime).unwrap_or(0),
            },
            ino: st.st_ino,
        }
    }
}

/// The file name of `key`'s object: the 64 lowercase hex digits of its hash.
pub(crate) fn object_name(key: &KeyHash) -> String {
    use std::fmt::Write as _;
    let mut name = String::with_capacity(64);
    for b in key.0 {
        let _ = write!(name, "{b:02x}"); // a String takes every write
    }
    name
}

/// `shard/name`, relative to `objects/`.
pub(crate) fn object_path(key: &KeyHash) -> String {
    format!("{:02x}/{}", key.shard(), object_name(key))
}

/// The key hash an object's name carries; `None` for any other name, such as one left by
/// another tool.
pub(crate) fn parse_name(name: &[u8]) -> Option<KeyHash> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    if name.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (k, pair) in key.iter_mut().zip(name.as_chunks::<2>().0) {
        *k = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(KeyHash(key))
}

type Map<V> = HashMap<KeyHash, V, BuildHasherDefault<PassThrough>>;

/// One loaded shard.
#[derive(Default)]
pub(crate) struct Shard {
    /// Present keys and their listing or event sequence numbers. A stat is accepted
    /// only while the key still has the sequence number observed before the stat.
    pub(crate) keys: Map<u64>,
    /// What is known of their objects: filled by [`Index::fill`].
    pub(crate) stats: Map<Stat>,
    /// Keys of `stats` replaced or touched since: their size kept as an estimate, until
    /// `stat`ed again.
    pub(crate) touched: Map<()>,
    /// Bytes of the objects in `stats`.
    pub(crate) bytes: u64,
}

impl Shard {
    /// Record `key` from a listing or publication, invalidating any previous stat.
    pub(crate) fn present(&mut self, key: KeyHash, seq: u64) {
        self.keys.insert(key, seq);
        if self.stats.contains_key(&key) {
            self.touched.insert(key, ());
        }
    }

    /// `key`'s object, if present, was touched by event `seq`: its `stat` is out of date.
    pub(crate) fn changed(&mut self, key: KeyHash, seq: u64) {
        if let Some(s) = self.keys.get_mut(&key) {
            *s = seq;
            if self.stats.contains_key(&key) {
                self.touched.insert(key, ());
            }
        }
    }

    /// `key`'s object is gone.
    pub(crate) fn gone(&mut self, key: KeyHash) {
        self.keys.remove(&key);
        self.touched.remove(&key);
        if let Some(old) = self.stats.remove(&key) {
            self.bytes -= old.meta.size;
        }
    }

    /// Record `stat` for `key`, taken when its last event was `seq`, unless an event came
    /// since.
    pub(crate) fn record(&mut self, key: KeyHash, seq: u64, stat: Stat) {
        if self.keys.get(&key) == Some(&seq) {
            if let Some(old) = self.stats.insert(key, stat) {
                self.bytes -= old.meta.size;
            }
            self.bytes += stat.meta.size;
            self.touched.remove(&key);
        }
    }

    /// `key`'s `stat`, if known and current.
    pub(crate) fn fresh(&self, key: &KeyHash) -> Option<Stat> {
        match self.touched.contains_key(key) {
            true => None,
            false => self.stats.get(key).copied(),
        }
    }

    /// Whether every key's `stat` is known and current.
    pub(crate) fn complete(&self) -> bool {
        self.keys.len() == self.stats.len() && self.touched.is_empty()
    }

    /// The keys to `stat`, with their last event.
    fn stale(&self) -> Vec<(KeyHash, u64)> {
        (self.keys.iter())
            .filter(|(k, _)| !self.stats.contains_key(*k) || self.touched.contains_key(*k))
            .map(|(k, seq)| (*k, *seq))
            .collect()
    }
}

/// The index of one area's `objects/` directory, for this process.
pub(crate) struct Index {
    objects: OwnedFd,
    /// Replaced, along with every watch, when its queue overflows: the events it still
    /// holds are dropped with it, so none can apply to a shard listed since.
    /// `None` only during a recovery that has not got its new instance yet.
    inotify: RwLock<Option<OwnedFd>>,
    /// Shard lookups that observe this flag must complete recovery before returning.
    overflowed: AtomicBool,
    /// An eventfd written when the inotify instance is replaced, so a poll of the old one
    /// wakes to poll the new.
    wake: OwnedFd,
    /// `None` until first touched, and again after a queue overflow.
    shards: Box<[RwLock<Option<Shard>>]>,
    /// Map watch descriptors to shards. Register each watch under this lock so event
    /// dispatch can resolve it.
    watches: Mutex<HashMap<i32, u8>>,
    /// Held while events are read and applied, so two callers cannot apply them out of order.
    reading: Mutex<()>,
    loaded: AtomicUsize,
    /// The number of the next event applied or listing made, for [`Shard::keys`].
    seq: AtomicU64,
}

/// What an [`Index::drain`] call saw.
#[derive(Default, Debug)]
pub(crate) struct Events {
    pub(crate) applied: usize,
    pub(crate) overflowed: bool,
}

// An mtime-only refresh generates IN_MODIFY. Watch IN_ATTRIB for metadata changes too.
// The /proc/self/fd watch path must follow its symlink.
const WATCH_MASK: u32 = libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MODIFY
    | libc::IN_ATTRIB
    | libc::IN_MOVE_SELF
    | libc::IN_ONLYDIR;

fn read_lock<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(PoisonError::into_inner)
}

fn new_inotify() -> Result<OwnedFd> {
    // SAFETY: no pointers; the result is checked.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating an inotify instance");
    }
    // SAFETY: `fd` is fresh and owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fstatat` without following a symlink in the final path component.
pub(crate) fn stat_at(dir: &OwnedFd, path: &str) -> std::io::Result<libc::stat> {
    let c = c_name(path).map_err(std::io::Error::other)?;
    // SAFETY: an all-zero `stat` is valid; the kernel overwrites it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live, the path NUL-terminated, `st` writable.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

impl Index {
    /// The index of the `objects` directory, whose shard directories exist. Nothing is
    /// listed yet; every later access goes through this descriptor, not a path.
    pub(crate) fn new(objects: &OwnedFd) -> Result<Index> {
        let inotify = RwLock::new(Some(new_inotify()?));
        // SAFETY: no pointers; the result is checked.
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wake < 0 {
            return Err(std::io::Error::last_os_error()).context("creating an eventfd");
        }
        // SAFETY: fresh descriptor.
        let wake = unsafe { OwnedFd::from_raw_fd(wake) };
        Ok(Index {
            objects: objects.try_clone().context("duplicating objects/")?,
            inotify,
            overflowed: AtomicBool::new(false),
            wake,
            shards: (0..SHARDS).map(|_| RwLock::new(None)).collect(),
            watches: Mutex::new(HashMap::new()),
            reading: Mutex::new(()),
            loaded: AtomicUsize::new(0),
            seq: AtomicU64::new(0),
        })
    }

    /// Poll this descriptor for events. Read it again when [`Index::wake_fd`] becomes
    /// readable during overflow recovery.
    pub(crate) fn event_fd(&self) -> RawFd {
        // poll ignores a negative descriptor
        read_lock(&self.inotify)
            .as_ref()
            .map_or(-1, |fd| fd.as_raw_fd())
    }

    /// Signals pollers to read [`Index::event_fd`] again. [`Index::woken`] clears the signal.
    pub(crate) fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    pub(crate) fn woken(&self) {
        let mut n = [0u8; 8];
        // SAFETY: an 8-byte read into an 8-byte buffer; EAGAIN when not woken is fine.
        let _ = unsafe { libc::read(self.wake.as_raw_fd(), n.as_mut_ptr().cast(), 8) };
    }

    /// How many shards are loaded.
    pub(crate) fn loaded(&self) -> usize {
        self.loaded.load(Ordering::Relaxed)
    }

    /// Shard `s`, watched and listed first if not loaded. A failure leaves it unloaded, to be
    /// tried again on next use.
    pub(crate) fn shard(&self, s: u8) -> Result<RwLockReadGuard<'_, Option<Shard>>> {
        let lock = &self.shards[usize::from(s)];
        // Again if an overflow unloads it between the write lock and the read lock.
        loop {
            if self.overflowed.load(Ordering::Acquire) {
                self.recover()?;
            }
            {
                let guard = read_lock(lock);
                if guard.is_some() && !self.overflowed.load(Ordering::Acquire) {
                    return Ok(guard);
                }
            }
            let mut guard = lock.write().unwrap_or_else(PoisonError::into_inner);
            if guard.is_none() {
                *guard = Some(self.watch_and_list(s)?);
                self.loaded.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Whether `key` is present, as the index knows.
    pub(crate) fn contains(&self, key: &KeyHash) -> Result<bool> {
        let guard = self.shard(key.shard())?;
        Ok(guard.as_ref().is_some_and(|s| s.keys.contains_key(key)))
    }

    /// The known, current `stat` of `key`'s object.
    pub(crate) fn stat(&self, key: &KeyHash) -> Option<Stat> {
        read_lock(&self.shards[usize::from(key.shard())])
            .as_ref()
            .and_then(|s| s.fresh(key))
    }

    fn update(&self, s: u8, f: impl FnOnce(&mut Shard)) {
        let mut guard = self.shards[usize::from(s)]
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(shard) = guard.as_mut() {
            f(shard);
        }
    }

    /// Load every shard.
    pub(crate) fn load_all(&self) -> Result<()> {
        for s in 0..=u8::MAX {
            drop(self.shard(s)?);
        }
        Ok(())
    }

    /// Visit every loaded shard, in order, under its read lock.
    pub(crate) fn each_loaded(&self, mut f: impl FnMut(u8, &Shard)) {
        for (s, lock) in (0..=u8::MAX).zip(self.shards.iter()) {
            if let Some(shard) = read_lock(lock).as_ref() {
                f(s, shard);
            }
        }
    }

    /// `stat` every object of the loaded shards whose `stat` is not known. A name found gone
    /// is left for its event to remove.
    pub(crate) fn fill(&self) -> Result<()> {
        for s in 0..=u8::MAX {
            self.fill_shard(s)?;
        }
        Ok(())
    }

    /// [`Index::fill`] for shard `s`, `stat`ing with no lock held.
    fn fill_shard(&self, s: u8) -> Result<()> {
        let todo = match read_lock(&self.shards[usize::from(s)]).as_ref() {
            Some(sh) if !sh.complete() => sh.stale(),
            _ => return Ok(()),
        };
        let mut done = Vec::with_capacity(todo.len());
        for (key, seq) in todo {
            if let Some(stat) = self.stat_object(&key)? {
                done.push((key, seq, stat));
            }
        }
        self.update(s, |sh| {
            for (key, seq, stat) in done {
                sh.record(key, seq, stat);
            }
        });
        Ok(())
    }

    fn stat_object(&self, key: &KeyHash) -> Result<Option<Stat>> {
        let path = object_path(key);
        match stat_at(&self.objects, &path) {
            Ok(st) => Ok(Some(Stat::of(&st))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("stat {path}")),
        }
    }

    /// Count indexed objects and bytes across all shards. If events keep invalidating
    /// unlocked stats, finish the shard under its write lock and exclude names found
    /// gone. The count can span concurrent filesystem changes.
    pub(crate) fn usage(&self) -> Result<(u64, u64)> {
        let (mut objects, mut bytes) = (0, 0);
        'shards: for s in 0..=u8::MAX {
            for _ in 0..2 {
                drop(self.shard(s)?);
                self.fill_shard(s)?;
                if let Some(sh) = read_lock(&self.shards[usize::from(s)]).as_ref()
                    && sh.complete()
                {
                    objects += sh.keys.len() as u64;
                    bytes += sh.bytes;
                    continue 'shards;
                }
            }
            // Again if an overflow unloads it between loading and locking.
            loop {
                drop(self.shard(s)?);
                let mut guard = self.shards[usize::from(s)]
                    .write()
                    .unwrap_or_else(PoisonError::into_inner);
                let Some(sh) = guard.as_mut() else {
                    continue;
                };
                let (mut gone, mut gone_bytes) = (0, 0);
                for (key, seq) in sh.stale() {
                    match self.stat_object(&key)? {
                        Some(stat) => sh.record(key, seq, stat),
                        // its event has yet to come
                        None => {
                            gone += 1;
                            gone_bytes += sh.stats.get(&key).map_or(0, |st| st.meta.size);
                        }
                    }
                }
                objects += sh.keys.len() as u64 - gone;
                bytes += sh.bytes - gone_bytes;
                break;
            }
        }
        Ok((objects, bytes))
    }

    /// Watch shard `s` before listing its names, without statting its entries. Both
    /// operations use the directory opened relative to `objects/`, independent of the
    /// working directory.
    fn watch_and_list(&self, s: u8) -> Result<Shard> {
        let hh = format!("{s:02x}");
        let c = c_name(&hh)?;
        // SAFETY: the descriptor is live and the name NUL-terminated.
        let fd = unsafe {
            libc::openat(
                self.objects.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("opening objects/{hh}"));
        }
        // SAFETY: fresh descriptor.
        let dir = unsafe { OwnedFd::from_raw_fd(fd) };
        let path = c_name(&format!("/proc/self/fd/{}", dir.as_raw_fd()))?;
        {
            let mut watches = self.watches.lock().unwrap_or_else(PoisonError::into_inner);
            let inotify = read_lock(&self.inotify);
            let Some(inotify) = inotify.as_ref() else {
                bail!("recovering from an inotify overflow");
            };
            // SAFETY: the descriptor is live and the path is NUL-terminated.
            let wd =
                unsafe { libc::inotify_add_watch(inotify.as_raw_fd(), path.as_ptr(), WATCH_MASK) };
            if wd < 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("watching objects/{hh}"));
            }
            watches.insert(wd, s);
        }
        let mut shard = Shard::default();
        for name in
            vk_fs::dir_names(dir.as_fd()).with_context(|| format!("listing objects/{hh}"))?
        {
            if let Some(key) = parse_name(name.as_bytes())
                && key.shard() == s
            {
                shard.present(key, self.next_seq());
            }
        }
        Ok(shard)
    }

    /// With `reading` held, discard the old inotify instance, its watches and queued
    /// events. Unload shards before replacement and again after it succeeds to discard
    /// concurrent listings. If replacement fails, leave recovery pending for the next
    /// shard lookup or drain.
    fn restart(&self) -> Result<()> {
        self.overflowed.store(true, Ordering::Release);
        self.unload_all();
        // The old instance goes first, so the new one fits under the per-user limit.
        {
            let mut watches = self.watches.lock().unwrap_or_else(PoisonError::into_inner);
            *self.inotify.write().unwrap_or_else(PoisonError::into_inner) = None;
            watches.clear();
        }
        self.wake_poller();
        let fresh = new_inotify()?;
        *self.inotify.write().unwrap_or_else(PoisonError::into_inner) = Some(fresh);
        // A shard listed on the old instance since the first unload goes too.
        self.unload_all();
        self.overflowed.store(false, Ordering::Release);
        self.wake_poller();
        Ok(())
    }

    fn wake_poller(&self) {
        let one = 1u64.to_ne_bytes();
        // SAFETY: an 8-byte write to a live eventfd.
        let _ = unsafe { libc::write(self.wake.as_raw_fd(), one.as_ptr().cast(), 8) };
    }

    /// Finish an overflow recovery that failed earlier.
    fn recover(&self) -> Result<()> {
        let _reading = self.reading.lock().unwrap_or_else(PoisonError::into_inner);
        if self.overflowed.load(Ordering::Acquire) {
            self.restart()?;
        }
        Ok(())
    }

    fn unload_all(&self) {
        for lock in self.shards.iter() {
            if lock
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .is_some()
            {
                self.loaded.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Drain up to the byte count sampled after acquiring `reading`. New arrivals cannot
    /// extend the drain. A writer's completed changes to watched names are already queued
    /// when it drains, unless overflow requires a fresh listing.
    pub(crate) fn drain(&self) -> Result<Events> {
        #[repr(C, align(8))]
        struct Buf([u8; 64 * 1024]);
        let mut buf = Buf([0; 64 * 1024]);
        let mut seen = Events::default();
        let _reading = self.reading.lock().unwrap_or_else(PoisonError::into_inner);
        if self.overflowed.load(Ordering::Acquire) {
            self.restart()?;
        }
        if let Some(inotify) = read_lock(&self.inotify).as_ref() {
            let mut queued: libc::c_int = 0;
            // SAFETY: FIONREAD writes one int.
            if unsafe { libc::ioctl(inotify.as_raw_fd(), libc::FIONREAD, &mut queued) } != 0 {
                return Err(std::io::Error::last_os_error()).context("sizing the inotify queue");
            }
            let mut left = usize::try_from(queued).unwrap_or(0);
            while left > 0 && !seen.overflowed {
                // SAFETY: the buffer is writable for the length passed.
                let n = unsafe {
                    libc::read(
                        inotify.as_raw_fd(),
                        buf.0.as_mut_ptr().cast(),
                        buf.0.len().min(left),
                    )
                };
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    match e.kind() {
                        std::io::ErrorKind::WouldBlock => break,
                        std::io::ErrorKind::Interrupted => continue,
                        _ => return Err(e).context("reading inotify events"),
                    }
                }
                let n = n as usize; // checked nonnegative
                if n == 0 {
                    break;
                }
                left = left.saturating_sub(n);
                self.apply(inotify, &buf.0[..n], &mut seen);
            }
        }
        if seen.overflowed {
            self.restart()?;
        }
        Ok(seen)
    }

    fn apply(&self, inotify: &OwnedFd, buf: &[u8], seen: &mut Events) {
        const HEADER: usize = std::mem::size_of::<libc::inotify_event>();
        let mut at = 0;
        while at + HEADER <= buf.len() {
            // SAFETY: the kernel wrote a whole event header at `at`; read unaligned.
            let ev: libc::inotify_event =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(at).cast()) };
            let len = ev.len as usize;
            let name = buf.get(at + HEADER..at + HEADER + len).unwrap_or(&[]);
            let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
            at += HEADER + len;
            if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                // What follows is incomplete: the instance is replaced, unread events and all.
                seen.overflowed = true;
                return;
            }
            // A shard directory removed, or moved away: what its watch reports from now on
            // is no longer under objects/.
            let retired = ev.mask & (libc::IN_IGNORED | libc::IN_MOVE_SELF) != 0;
            // Never held with a shard lock: loading takes the two the other way round.
            let shard = {
                let mut watches = self.watches.lock().unwrap_or_else(PoisonError::into_inner);
                if retired {
                    watches.remove(&ev.wd)
                } else {
                    watches.get(&ev.wd).copied()
                }
            };
            if retired {
                if ev.mask & libc::IN_MOVE_SELF != 0 {
                    // SAFETY: plain call on a live descriptor; a stale wd is EINVAL.
                    unsafe { libc::inotify_rm_watch(inotify.as_raw_fd(), ev.wd) };
                }
                // Forget the shard, to watch and list what has its name on next use.
                if let Some(s) = shard {
                    let mut g = self.shards[usize::from(s)]
                        .write()
                        .unwrap_or_else(PoisonError::into_inner);
                    if g.take().is_some() {
                        self.loaded.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                continue;
            }
            let (Some(s), Some(key)) = (shard, parse_name(name)) else {
                continue;
            };
            if key.shard() != s {
                continue; // not where this store would look for it
            }
            let seq = self.next_seq();
            if ev.mask & (libc::IN_MOVED_TO | libc::IN_CREATE) != 0 {
                self.update(s, |sh| sh.present(key, seq));
            } else if ev.mask & (libc::IN_MOVED_FROM | libc::IN_DELETE) != 0 {
                self.update(s, |sh| sh.gone(key));
            } else if ev.mask & (libc::IN_MODIFY | libc::IN_ATTRIB) != 0 {
                self.update(s, |sh| sh.changed(key, seq));
            } else {
                continue;
            }
            seen.applied += 1;
        }
    }
}

/// `name` as a C string, for the `*at` calls.
pub(crate) fn c_name(name: &str) -> Result<CString> {
    CString::new(name).map_err(|_| anyhow!("{name:?} has a NUL"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> (PathBuf, OwnedFd) {
        let dir = crate::testtmp::root().join(format!("objindex-{name}"));
        let objects = dir.join("objects");
        for s in 0..SHARDS {
            std::fs::create_dir_all(objects.join(format!("{s:02x}"))).unwrap();
        }
        let fd = vk_fs::open_dir(&objects).unwrap();
        (objects, fd)
    }

    fn st(size: u64, ino: u64) -> Stat {
        Stat {
            meta: Meta { size, mtime: 1 },
            ino,
        }
    }

    #[test]
    fn names_round_trip_and_reject_others() {
        let key = KeyHash::of(b"a/b/c/abc");
        let name = object_name(&key);
        assert_eq!(parse_name(name.as_bytes()), Some(key));
        for bad in [
            &name[..63],
            &format!("{name}0"),
            &format!("{name}-1-2"),
            &name.to_uppercase(),
            ".tmp",
        ] {
            assert_eq!(parse_name(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn a_stat_taken_before_an_event_is_not_recorded() {
        let mut sh = Shard::default();
        let k = KeyHash::of(b"k");
        sh.present(k, 1);
        sh.record(k, 1, st(10, 1));
        assert_eq!((sh.fresh(&k), sh.bytes), (Some(st(10, 1)), 10));
        // replaced: the old size stands until a stat taken since is recorded
        sh.present(k, 2);
        assert_eq!((sh.fresh(&k), sh.bytes, sh.complete()), (None, 10, false));
        sh.record(k, 1, st(10, 1));
        assert_eq!(sh.fresh(&k), None);
        sh.record(k, 2, st(20, 2));
        assert_eq!(
            (sh.fresh(&k), sh.bytes, sh.complete()),
            (Some(st(20, 2)), 20, true)
        );
        sh.changed(k, 3);
        assert_eq!((sh.fresh(&k), sh.bytes), (None, 20));
        // deleted and put again: a stat taken before the delete is still refused
        sh.gone(k);
        sh.record(k, 3, st(20, 2));
        sh.present(k, 4);
        sh.record(k, 3, st(20, 2));
        assert_eq!((sh.keys.len(), sh.stats.len(), sh.bytes), (1, 0, 0));
        sh.gone(k);
        assert_eq!((sh.keys.len(), sh.stats.len(), sh.bytes), (0, 0, 0));
    }

    #[test]
    fn a_shard_loads_lazily_and_follows_events() {
        let (objects, fd) = tmp("lazy");
        let idx = Index::new(&fd).unwrap();
        let k = KeyHash::of(b"x");
        let path = objects.join(object_path(&k));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(idx.loaded(), 0);
        assert!(idx.contains(&k).unwrap());
        assert_eq!(idx.loaded(), 1);
        idx.fill().unwrap();
        assert_eq!(idx.stat(&k).unwrap().meta.size, 3);
        // replacement by rename preserves membership and invalidates the cached stat
        let staged = objects.join("staged");
        std::fs::write(&staged, b"abcdef").unwrap();
        std::fs::rename(&staged, &path).unwrap();
        idx.drain().unwrap();
        assert!(idx.contains(&k).unwrap());
        assert_eq!(idx.stat(&k), None);
        idx.fill().unwrap();
        assert_eq!(idx.stat(&k).unwrap().meta.size, 6);
        std::fs::remove_file(&path).unwrap();
        idx.drain().unwrap();
        assert!(!idx.contains(&k).unwrap());
    }

    #[test]
    fn a_queue_overflow_unloads_and_the_next_use_relists() {
        let (objects, fd) = tmp("overflow");
        let max: usize = std::fs::read_to_string("/proc/sys/fs/inotify/max_queued_events")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let idx = Index::new(&fd).unwrap();
        let k = KeyHash::of(b"y");
        assert!(!idx.contains(&k).unwrap());
        // Each rename queues two events; flip between two names past the queue's limit,
        // ending on the object's name.
        let shard = objects.join(format!("{:02x}", k.shard()));
        let names = [shard.join("other"), objects.join(object_path(&k))];
        std::fs::write(&names[0], b"").unwrap();
        let flips = (max / 2 + 9) | 1;
        for i in 0..flips {
            std::fs::rename(&names[i % 2], &names[(i + 1) % 2]).unwrap();
        }
        let ev = idx.drain().unwrap();
        assert!(ev.overflowed);
        assert_eq!(idx.loaded(), 0);
        assert!(idx.contains(&k).unwrap());
        assert_eq!(idx.loaded(), 1);
        // and the watch still works
        std::fs::rename(&names[1], &names[0]).unwrap();
        while idx.drain().unwrap().overflowed {}
        assert!(!idx.contains(&k).unwrap());
    }
}
