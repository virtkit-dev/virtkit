// A virtio-fs filesystem that exports exactly ONE host file as the sole persistent entry of an
// otherwise-empty root directory — the server primitive for a single-file bind mount.
//
// Unlike PassthroughFs (rooted at a directory, holding a descriptor to the whole subtree),
// SingleFileFs only ever opens the one file it was handed. The file's parent directory is
// never named or reachable by the guest: `lookup` accepts only the configured basename (plus
// temp files the guest itself created — see below), and there is no inode a guest could obtain
// for a pre-existing sibling. So isolation is structural — a hostile guest that remounts the tag
// and probes the root still cannot read a sibling — rather than a filter over a passthrough share.
//
// Atomic-rename config writers (temp file + rename, e.g. whatever rewrites `~/.claude.json`)
// are supported: the guest may `create` a new name, write it, and `rename` it over the bound
// file. Crucially a guest-created temp is always backed by a FRESH host file under a
// vk-controlled name in the parent directory — the guest's chosen name is never used on the
// host — so `create` can never open (and thus never leak) a pre-existing sibling. Backing the
// temp in the bound file's own directory keeps the final rename a same-directory atomic
// `renameat`.
//
// A temp lives until the guest renames it onto the bound file or unlinks it; a temp the guest
// abandons (created, then neither renamed nor unlinked) persists until the bind is torn down,
// when `Drop` reclaims every remaining scratch file.
//
// Ownership/mode/xattr changes and hardlink semantics are intentionally omitted (a single-file
// bind doesn't need them): setattr honors only size, and chmod/chown are accepted-but-ignored.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, OpenOptions, SetattrValid,
    ZeroCopyReader, ZeroCopyWriter,
};
use super::fuse;
use crate::virtio::bindings;

type Inode = u64;
type Handle = u64;

/// The bound file's inode. The root directory is `fuse::ROOT_ID` (1); guest-created scratch
/// files (see `Temp`) get inodes from `FIRST_TEMP_INODE` up.
const FILE_INODE: Inode = 2;
const FIRST_TEMP_INODE: Inode = 3;
/// Entry- and attr-cache lifetime handed to the guest kernel: zero, i.e. no caching. A
/// single-file bind serves exactly one file, so caching buys nothing — and a zero timeout keeps
/// the guest correct across an atomic-rename replace of the bound file. A `rename` onto the
/// bound name repoints the kernel's dentry at the (now-removed) temp inode and leaves the old
/// size/mtime cached; without immediate re-lookup, a read of the bound file right after the
/// rename would miss (ENOENT) or read the stale length until the timeout expired. Forcing a
/// fresh `lookup`/`getattr` on every access resolves the bound name back to `FILE_INODE` with
/// the current size.
const TTL: Duration = Duration::from_secs(0);

/// A guest-created scratch file, backed by a real file in the bound file's parent directory under
/// a vk-controlled host name. The guest addresses it by the `name` it chose; that name is never
/// used on the host, so `create` can never resolve or open a pre-existing sibling — single-file
/// read isolation is preserved even though writes now work. Backing it beside the bound file keeps
/// a rename onto the bound file a same-directory (atomic) `renameat`.
struct Temp {
    /// Guest-visible name within the root directory.
    name: CString,
    /// Real backing file in the parent directory.
    host_path: PathBuf,
}

/// Serves a single host file `path` as `/<name>` where `name` is its basename.
pub struct SingleFileFs {
    name: CString,
    path: PathBuf,
    /// Directory holding `path`; guest-created temps are backed here so a rename onto the bound
    /// file is a same-directory (atomic) `renameat`.
    parent: PathBuf,
    read_only: bool,
    /// Set in `init` when the peer negotiates writeback caching. With writeback the guest kernel
    /// owns append semantics, so an `O_APPEND` host fd must be cleared (see `open`).
    writeback: AtomicBool,
    handles: RwLock<HashMap<Handle, File>>,
    next_handle: AtomicU64,
    /// Guest-created scratch files, keyed by their fuse inode.
    temps: RwLock<HashMap<Inode, Temp>>,
    next_inode: AtomicU64,
    next_temp_seq: AtomicU64,
}

fn einval() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}
fn enoent() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}
fn erofs() -> io::Error {
    io::Error::from_raw_os_error(libc::EROFS)
}
fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}
fn eexist() -> io::Error {
    io::Error::from_raw_os_error(libc::EEXIST)
}
fn eperm() -> io::Error {
    io::Error::from_raw_os_error(libc::EPERM)
}

impl SingleFileFs {
    pub fn new(path: PathBuf, read_only: bool) -> io::Result<Self> {
        let name = path
            .file_name()
            .and_then(|n| CString::new(n.as_bytes()).ok())
            .ok_or_else(einval)?;
        // The dir that holds the bound file; temps must live here so a rename onto it stays atomic
        // (same filesystem). A bare basename has no parent component — fall back to the cwd.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(SingleFileFs {
            name,
            path,
            parent,
            read_only,
            writeback: AtomicBool::new(false),
            handles: RwLock::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            temps: RwLock::new(HashMap::new()),
            next_inode: AtomicU64::new(FIRST_TEMP_INODE),
            next_temp_seq: AtomicU64::new(0),
        })
    }

    fn cpath_of(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| einval())
    }

    /// `stat` a host path via `statx` (not `std::fs::metadata`, which on musl uses the legacy
    /// `stat` syscall the virtio-fs seccomp allowlist deliberately omits — PassthroughFs uses
    /// `statx` too), reporting it under `ino` so the fuse node id is stable; filled field-by-field
    /// because `bindings::stat64` is a target-specific alias (`libc::stat` on musl).
    fn stat_at(path: &Path, ino: Inode) -> io::Result<bindings::stat64> {
        use super::passthrough::statx_compat;
        let c = Self::cpath_of(path)?;
        let mut sx: statx_compat::Statx = unsafe { mem::zeroed() };
        // SAFETY: `c` is a valid C string; the kernel writes only into `sx`.
        let rc = unsafe {
            statx_compat::statx(
                libc::AT_FDCWD,
                c.as_ptr(),
                0,
                statx_compat::STATX_BASIC_STATS,
                &mut sx,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_ino = ino;
        st.st_mode = sx.stx_mode as _;
        st.st_nlink = 1;
        st.st_uid = sx.stx_uid;
        st.st_gid = sx.stx_gid;
        st.st_size = sx.stx_size as _;
        st.st_blksize = 4096;
        st.st_blocks = sx.stx_blocks as _;
        st.st_atime = sx.stx_atime.tv_sec as _;
        st.st_atime_nsec = sx.stx_atime.tv_nsec as _;
        st.st_mtime = sx.stx_mtime.tv_sec as _;
        st.st_mtime_nsec = sx.stx_mtime.tv_nsec as _;
        st.st_ctime = sx.stx_ctime.tv_sec as _;
        st.st_ctime_nsec = sx.stx_ctime.tv_nsec as _;
        Ok(st)
    }

    fn stat_file(&self) -> io::Result<bindings::stat64> {
        Self::stat_at(&self.path, FILE_INODE)
    }

    /// Open a host path via `openat` (not `std::fs::File::open`, which on musl uses the legacy
    /// `open` syscall the allowlist omits). Returns a `File` owning the fd.
    fn open_at(path: &Path, oflags: i32) -> io::Result<File> {
        use std::os::fd::FromRawFd;
        let c = Self::cpath_of(path)?;
        // SAFETY: `c` is a valid C string; openat writes nothing through our pointers.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), oflags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: we own `fd` (just opened, not handed out elsewhere).
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn renameat_host(old: &Path, new: &Path) -> io::Result<()> {
        let o = Self::cpath_of(old)?;
        let n = Self::cpath_of(new)?;
        // SAFETY: both are valid C strings; renameat writes nothing through our pointers.
        let rc = unsafe { libc::renameat(libc::AT_FDCWD, o.as_ptr(), libc::AT_FDCWD, n.as_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Best-effort remove of a host path (used to reclaim abandoned scratch files).
    fn unlink_host(path: &Path) {
        if let Ok(c) = Self::cpath_of(path) {
            // SAFETY: `c` is a valid C string; unlinkat writes nothing through our pointers.
            unsafe { libc::unlinkat(libc::AT_FDCWD, c.as_ptr(), 0) };
        }
    }

    fn root_attr() -> bindings::stat64 {
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_ino = fuse::ROOT_ID;
        st.st_mode = libc::S_IFDIR | 0o755;
        st.st_nlink = 2;
        st.st_blksize = 4096;
        st
    }

    fn entry(inode: Inode, attr: bindings::stat64) -> Entry {
        Entry {
            inode,
            generation: 0,
            attr,
            attr_flags: 0,
            attr_timeout: TTL,
            entry_timeout: TTL,
        }
    }

    /// Resolve a fuse inode to the host path it backs. The root has no backing path (it is served
    /// synthetically) so it resolves to `ENOENT` here, as does any unknown inode.
    fn path_for_inode(&self, inode: Inode) -> io::Result<PathBuf> {
        match inode {
            FILE_INODE => Ok(self.path.clone()),
            _ => self
                .temps
                .read()
                .unwrap()
                .get(&inode)
                .map(|t| t.host_path.clone())
                .ok_or_else(enoent),
        }
    }

    fn handle_file(&self, handle: Handle) -> io::Result<File> {
        self.handles
            .read()
            .unwrap()
            .get(&handle)
            .and_then(|f| f.try_clone().ok())
            .ok_or_else(ebadf)
    }

    /// Create a fresh, empty backing file in the parent dir under a vk-controlled name. `O_EXCL`
    /// guarantees a brand-new file — so a guest `create` never opens a pre-existing sibling — and
    /// the (vanishingly unlikely) name collision is retried. Returns the host path and an `O_RDWR`
    /// handle (RDWR so the read path works under writeback caching, matching `open`).
    fn create_temp_backing(&self, mode: u32) -> io::Result<(PathBuf, File)> {
        use std::os::fd::FromRawFd;
        let pid = std::process::id();
        for _ in 0..1000 {
            let seq = self.next_temp_seq.fetch_add(1, Ordering::Relaxed);
            let host_path = self.parent.join(format!(".vk-sff-tmp.{pid}.{seq}"));
            let c = Self::cpath_of(&host_path)?;
            let flags = libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC;
            // SAFETY: `c` is a valid C string; openat writes nothing through our pointers.
            let fd = unsafe {
                libc::openat(
                    libc::AT_FDCWD,
                    c.as_ptr(),
                    flags,
                    (mode & 0o777) as libc::c_uint,
                )
            };
            if fd >= 0 {
                // SAFETY: we own `fd` (just opened, not handed out elsewhere).
                return Ok((host_path, unsafe { File::from_raw_fd(fd) }));
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(err);
            }
        }
        Err(eexist())
    }

    /// Snapshot of the directory: `.`, `..`, the bound file, then each live temp (sorted by inode
    /// for a stable order across paginated `readdir`/`readdirplus` calls).
    fn dir_snapshot(&self) -> Vec<(Vec<u8>, Inode, u32)> {
        let mut v: Vec<(Vec<u8>, Inode, u32)> = vec![
            (b".".to_vec(), fuse::ROOT_ID, libc::DT_DIR as u32),
            (b"..".to_vec(), fuse::ROOT_ID, libc::DT_DIR as u32),
            (
                self.name.as_bytes().to_vec(),
                FILE_INODE,
                libc::DT_REG as u32,
            ),
        ];
        let mut temps: Vec<(Inode, Vec<u8>)> = self
            .temps
            .read()
            .unwrap()
            .iter()
            .map(|(i, t)| (*i, t.name.as_bytes().to_vec()))
            .collect();
        temps.sort_by_key(|(i, _)| *i);
        for (i, name) in temps {
            v.push((name, i, libc::DT_REG as u32));
        }
        v
    }
}

impl Drop for SingleFileFs {
    fn drop(&mut self) {
        // Reclaim scratch files a guest created but never renamed onto the bound file or unlinked.
        if let Ok(temps) = self.temps.read() {
            for t in temps.values() {
                Self::unlink_host(&t.host_path);
            }
        }
    }
}

impl FileSystem for SingleFileFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // Negotiate the same core features a passthrough share does; readdirplus resolves the
        // root's entries in a single round (and IS implemented below — advertising it without an
        // implementation is what made `ls` on the mount fail with ENOSYS).
        let mut opts = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        if capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        Ok(opts)
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        if parent != fuse::ROOT_ID {
            return Err(enoent());
        }
        if name == self.name.as_c_str() {
            return Ok(Self::entry(FILE_INODE, self.stat_file()?));
        }
        // A guest-created temp resolves by the name the guest chose; nothing else does, so a
        // pre-existing sibling is never reachable.
        let temps = self.temps.read().unwrap();
        for (ino, t) in temps.iter() {
            if name == t.name.as_c_str() {
                return Ok(Self::entry(*ino, Self::stat_at(&t.host_path, *ino)?));
            }
        }
        Err(enoent())
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        match inode {
            fuse::ROOT_ID => Ok((Self::root_attr(), TTL)),
            FILE_INODE => Ok((self.stat_file()?, TTL)),
            _ => {
                let temps = self.temps.read().unwrap();
                let t = temps.get(&inode).ok_or_else(enoent)?;
                Ok((Self::stat_at(&t.host_path, inode)?, TTL))
            }
        }
    }

    fn statfs(&self, _ctx: Context, _inode: Inode) -> io::Result<bindings::statvfs64> {
        let mut st: bindings::statvfs64 = unsafe { mem::zeroed() };
        st.f_bsize = 4096;
        st.f_frsize = 4096;
        st.f_namemax = 255;
        Ok(st)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        _handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        if self.read_only {
            return Err(erofs());
        }
        let path = self.path_for_inode(inode)?;
        // Truncation only (what a config-file rewrite needs); other attrs (mode/owner) are
        // accepted-but-ignored so a writer's chmod on its temp doesn't fail the write.
        if valid.contains(SetattrValid::SIZE) {
            Self::open_at(&path, libc::O_WRONLY)?.set_len(attr.st_size as u64)?;
        }
        Ok((Self::stat_at(&path, inode)?, TTL))
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        _kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let path = self.path_for_inode(inode)?;
        let write = matches!(
            flags as i32 & libc::O_ACCMODE,
            libc::O_WRONLY | libc::O_RDWR
        );
        if write && self.read_only {
            return Err(erofs());
        }
        // Open read-write when writable so the read path can pread the shared fd; carry the
        // guest's O_TRUNC.
        let acc = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let mut extra = flags as i32 & (libc::O_APPEND | libc::O_TRUNC);
        // With writeback caching the guest kernel owns append: it tracks the size and sends
        // positioned writes, but an O_APPEND host fd would (on Linux) ignore that offset and pwrite
        // at EOF, corrupting the file. Clear it, matching PassthroughFs::open_inode.
        if self.writeback.load(Ordering::Relaxed) {
            extra &= !libc::O_APPEND;
        }
        let file = Self::open_at(&path, acc | extra)?;
        let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(h, file);
        Ok((Some(h), OpenOptions::empty()))
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        _kill_priv: bool,
        flags: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        if parent != fuse::ROOT_ID {
            return Err(enoent());
        }
        if self.read_only {
            return Err(erofs());
        }
        // Creating the bound name itself is an open of the existing bound file (honoring O_TRUNC) —
        // this supports non-atomic writers that open the target directly with O_CREAT|O_TRUNC.
        if name == self.name.as_c_str() {
            if flags as i32 & libc::O_EXCL != 0 {
                return Err(eexist());
            }
            let (h, oo) = self.open(ctx, FILE_INODE, false, flags)?;
            return Ok((Self::entry(FILE_INODE, self.stat_file()?), h, oo));
        }
        // A create colliding with an existing temp of the same guest name reopens that temp
        // (honoring O_EXCL and O_TRUNC via `open`), rather than minting a second entry — two temps
        // sharing a name would make `lookup`/`readdir`/`rename` resolve to an arbitrary one.
        let existing = {
            let temps = self.temps.read().unwrap();
            temps
                .iter()
                .find(|(_, t)| name == t.name.as_c_str())
                .map(|(i, t)| (*i, t.host_path.clone()))
        };
        if let Some((ino, host_path)) = existing {
            if flags as i32 & libc::O_EXCL != 0 {
                return Err(eexist());
            }
            let (h, oo) = self.open(ctx, ino, false, flags)?;
            return Ok((Self::entry(ino, Self::stat_at(&host_path, ino)?), h, oo));
        }
        // Any other name is a brand-new scratch sibling, backed by a fresh host file under a
        // vk-controlled name — never the guest's name, so no pre-existing sibling is opened.
        let gname = CString::new(name.to_bytes()).map_err(|_| einval())?;
        let (host_path, file) = self.create_temp_backing(mode)?;
        let ino = self.next_inode.fetch_add(1, Ordering::Relaxed);
        let attr = Self::stat_at(&host_path, ino)?;
        let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(h, file);
        self.temps.write().unwrap().insert(
            ino,
            Temp {
                name: gname,
                host_path,
            },
        );
        Ok((Self::entry(ino, attr), Some(h), OpenOptions::empty()))
    }

    fn unlink(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        if parent != fuse::ROOT_ID {
            return Err(enoent());
        }
        if self.read_only {
            return Err(erofs());
        }
        // The bound host file is never deleted through the mount.
        if name == self.name.as_c_str() {
            return Err(eperm());
        }
        let mut temps = self.temps.write().unwrap();
        let ino = temps
            .iter()
            .find(|(_, t)| name == t.name.as_c_str())
            .map(|(i, _)| *i)
            .ok_or_else(enoent)?;
        let t = temps.remove(&ino).unwrap();
        drop(temps);
        Self::unlink_host(&t.host_path);
        Ok(())
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        if olddir != fuse::ROOT_ID || newdir != fuse::ROOT_ID {
            return Err(enoent());
        }
        if self.read_only {
            return Err(erofs());
        }
        // Atomic exchange has no meaning for a single-file bind (the bound file can't be swapped
        // out); reject rather than pretend.
        if flags & libc::RENAME_EXCHANGE != 0 {
            return Err(einval());
        }
        let noreplace = flags & libc::RENAME_NOREPLACE != 0;
        // The bound file may not be moved out from under the bind.
        if oldname == self.name.as_c_str() {
            return Err(eperm());
        }

        let mut temps = self.temps.write().unwrap();
        let src_ino = temps
            .iter()
            .find(|(_, t)| oldname == t.name.as_c_str())
            .map(|(i, _)| *i)
            .ok_or_else(enoent)?;

        if newname == self.name.as_c_str() {
            // Atomic replace of the bound file: renameat the temp's backing file onto it.
            if noreplace {
                return Err(eexist()); // the bound file always exists
            }
            let src = temps.get(&src_ino).unwrap().host_path.clone();
            Self::renameat_host(&src, &self.path)?;
            temps.remove(&src_ino);
            return Ok(());
        }

        // Rename within the virtual directory (temp -> another temp name). If a temp already holds
        // the destination name, it is replaced (its backing file removed), mirroring rename(2).
        let dest = temps
            .iter()
            .find(|(i, t)| **i != src_ino && newname == t.name.as_c_str())
            .map(|(i, _)| *i);
        if let Some(dino) = dest {
            if noreplace {
                return Err(eexist());
            }
            let d = temps.remove(&dino).unwrap();
            Self::unlink_host(&d.host_path);
        }
        let gname = CString::new(newname.to_bytes()).map_err(|_| einval())?;
        temps.get_mut(&src_ino).unwrap().name = gname;
        Ok(())
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        _inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        // write_from preads the fd, so the shared handle's offset is untouched.
        w.write_from(&self.handle_file(handle)?, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        _inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        if self.read_only {
            return Err(erofs());
        }
        r.read_to(&self.handle_file(handle)?, size as usize, offset)
    }

    fn flush(
        &self,
        _ctx: Context,
        _inode: Inode,
        _handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        Ok(())
    }

    fn fsync(
        &self,
        _ctx: Context,
        _inode: Inode,
        _datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.handle_file(handle)?.sync_all()
    }

    fn release(
        &self,
        _ctx: Context,
        _inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.handles.write().unwrap().remove(&handle);
        Ok(())
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if inode != fuse::ROOT_ID {
            return Err(enoent());
        }
        Ok((None, OpenOptions::empty()))
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        _size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if inode != fuse::ROOT_ID {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        let entries = self.dir_snapshot();
        for (i, (name, ino, type_)) in entries.iter().enumerate() {
            let next = i as u64 + 1; // resume token: 1-based, 0 means "from the start"
            if next <= offset {
                continue;
            }
            let stop = add_entry(DirEntry {
                ino: *ino,
                offset: next,
                type_: *type_,
                name: name.as_slice(),
            })? == 0;
            if stop {
                break; // kernel buffer full
            }
        }
        Ok(())
    }

    fn readdirplus<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        _size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        if inode != fuse::ROOT_ID {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        let entries = self.dir_snapshot();
        for (i, (name, ino, type_)) in entries.iter().enumerate() {
            let next = i as u64 + 1;
            if next <= offset {
                continue;
            }
            // Provide the Entry a lookup would return so the kernel can populate its dentry cache.
            let entry = match *ino {
                fuse::ROOT_ID => Self::entry(fuse::ROOT_ID, Self::root_attr()),
                FILE_INODE => Self::entry(FILE_INODE, self.stat_file()?),
                other => Self::entry(other, Self::stat_at(&self.path_for_inode(other)?, other)?),
            };
            let stop = add_entry(
                DirEntry {
                    ino: *ino,
                    offset: next,
                    type_: *type_,
                    name: name.as_slice(),
                },
                entry,
            )? == 0;
            if stop {
                break;
            }
        }
        Ok(())
    }

    fn releasedir(
        &self,
        _ctx: Context,
        _inode: Inode,
        _flags: u32,
        _handle: Handle,
    ) -> io::Result<()> {
        Ok(())
    }

    fn access(&self, _ctx: Context, inode: Inode, _mask: u32) -> io::Result<()> {
        match inode {
            fuse::ROOT_ID | FILE_INODE => Ok(()),
            _ if self.temps.read().unwrap().contains_key(&inode) => Ok(()),
            _ => Err(enoent()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_with(content: &[u8]) -> PathBuf {
        // Unique per call: the tests run in parallel and each removes its own dir.
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vk-sff-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("secret.json");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(content)
            .unwrap();
        // a sibling that must never be reachable through the fs
        std::fs::File::create(dir.join("other.txt"))
            .unwrap()
            .write_all(b"nope")
            .unwrap();
        p
    }

    fn ctx() -> Context {
        // Context is uid/gid/pid; zeroed is fine for these host-side calls.
        unsafe { mem::zeroed() }
    }

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn lookup_resolves_only_the_basename() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        // the file resolves...
        let e = fs.lookup(ctx(), fuse::ROOT_ID, &cs("secret.json")).unwrap();
        assert_eq!(e.inode, FILE_INODE);
        // ...the sibling does NOT (structural isolation — no inode is ever handed out for it)
        assert!(fs.lookup(ctx(), fuse::ROOT_ID, &cs("other.txt")).is_err());
        assert!(fs.lookup(ctx(), fuse::ROOT_ID, &cs("..")).is_err());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn readdir_lists_only_the_file() {
        let p = tmp_with(b"data");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let mut names = Vec::new();
        fs.readdir(ctx(), fuse::ROOT_ID, 0, 4096, 0, |e| {
            names.push(String::from_utf8_lossy(e.name).into_owned());
            Ok(1)
        })
        .unwrap();
        assert_eq!(names, vec![".", "..", "secret.json"]);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn readdirplus_yields_entries_with_attrs() {
        // The bug the report hit: DO_READDIRPLUS was advertised but readdirplus wasn't
        // implemented, so `ls` (getdents -> readdirplus) failed with ENOSYS.
        let p = tmp_with(b"hello world");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let mut seen = Vec::new();
        fs.readdirplus(ctx(), fuse::ROOT_ID, 0, 4096, 0, |d, e| {
            seen.push((
                String::from_utf8_lossy(d.name).into_owned(),
                e.inode,
                e.attr.st_size,
            ));
            Ok(1)
        })
        .unwrap();
        assert_eq!(seen[0].0, ".");
        assert_eq!(seen[1].0, "..");
        assert_eq!(seen[2].0, "secret.json");
        assert_eq!(seen[2].1, FILE_INODE);
        assert_eq!(seen[2].2, 11); // the file's size flows through the plus entry
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn getattr_reports_the_file_size() {
        let p = tmp_with(b"hello world");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let (st, _) = fs.getattr(ctx(), FILE_INODE, None).unwrap();
        assert_eq!(st.st_size, 11);
        let (rst, _) = fs.getattr(ctx(), fuse::ROOT_ID, None).unwrap();
        assert_eq!(rst.st_mode & libc::S_IFMT, libc::S_IFDIR);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn lookup_and_getattr_disable_caching() {
        // The guest must revalidate on every access so a read straight after an atomic-rename
        // replace resolves the current file rather than a stale cache entry; a nonzero timeout
        // reintroduces the stale-size/ENOENT window.
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let e = fs.lookup(ctx(), fuse::ROOT_ID, &cs("secret.json")).unwrap();
        assert_eq!(e.entry_timeout, Duration::ZERO);
        assert_eq!(e.attr_timeout, Duration::ZERO);
        let (_, ttl) = fs.getattr(ctx(), FILE_INODE, None).unwrap();
        assert_eq!(ttl, Duration::ZERO);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn read_only_rejects_write_open() {
        let p = tmp_with(b"x");
        let fs = SingleFileFs::new(p.clone(), true).unwrap();
        assert!(fs
            .open(ctx(), FILE_INODE, false, libc::O_WRONLY as u32)
            .is_err());
        assert!(fs
            .open(ctx(), FILE_INODE, false, libc::O_RDONLY as u32)
            .is_ok());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn read_only_rejects_create() {
        let p = tmp_with(b"x");
        let fs = SingleFileFs::new(p.clone(), true).unwrap();
        let r = fs.create(
            ctx(),
            fuse::ROOT_ID,
            &cs("secret.json.tmp"),
            0o644,
            false,
            (libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL) as u32,
            0,
            Extensions::default(),
        );
        assert_eq!(r.err().and_then(|e| e.raw_os_error()), Some(libc::EROFS));
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The core fix: an atomic-rename writer (create temp -> write shorter content -> rename over
    /// the target) replaces the bound file cleanly, with no stale tail from the larger original.
    #[test]
    fn atomic_rename_replaces_and_shrinks() {
        let big = vec![b'A'; 100_000];
        let p = tmp_with(&big);
        let fs = SingleFileFs::new(p.clone(), false).unwrap();

        // create a temp sibling
        let (entry, h, _) = fs
            .create(
                ctx(),
                fuse::ROOT_ID,
                &cs("secret.json.tmp"),
                0o644,
                false,
                (libc::O_CREAT | libc::O_RDWR | libc::O_EXCL) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let h = h.unwrap();

        // write a much shorter payload into it
        let small = br#"{"x":1}"#;
        {
            use std::os::fd::AsRawFd;
            let handles = fs.handles.read().unwrap();
            let fd = handles.get(&h).unwrap().as_raw_fd();
            let n = unsafe { libc::pwrite(fd, small.as_ptr() as *const _, small.len(), 0) };
            assert_eq!(n, small.len() as isize);
        }
        fs.release(ctx(), entry.inode, 0, h, false, false, None)
            .unwrap();

        // rename it over the bound file
        fs.rename(
            ctx(),
            fuse::ROOT_ID,
            &cs("secret.json.tmp"),
            fuse::ROOT_ID,
            &cs("secret.json"),
            0,
        )
        .unwrap();

        // the bound file now holds exactly the short payload — no 99_993-byte stale tail
        let after = std::fs::read(&p).unwrap();
        assert_eq!(after, small);
        // and the temp is gone from the namespace and the parent dir
        assert!(fs
            .lookup(ctx(), fuse::ROOT_ID, &cs("secret.json.tmp"))
            .is_err());
        assert!(fs.temps.read().unwrap().is_empty());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// Creating a name that collides with a real host sibling must NOT open that sibling — it gets
    /// a fresh empty backing file, so the sibling's contents stay unreachable.
    #[test]
    fn create_never_opens_a_preexisting_sibling() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let (entry, h, _) = fs
            .create(
                ctx(),
                fuse::ROOT_ID,
                &cs("other.txt"), // same name as the real sibling holding b"nope"
                0o644,
                false,
                (libc::O_CREAT | libc::O_RDWR) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        // the temp reads back empty, not the sibling's "nope"
        let (st, _) = fs.getattr(ctx(), entry.inode, None).unwrap();
        assert_eq!(st.st_size, 0);
        fs.release(ctx(), entry.inode, 0, h.unwrap(), false, false, None)
            .unwrap();
        // the real sibling is untouched on the host
        assert_eq!(
            std::fs::read(p.parent().unwrap().join("other.txt")).unwrap(),
            b"nope"
        );
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn unlink_removes_a_temp_but_not_the_bound_file() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let (_, h, _) = fs
            .create(
                ctx(),
                fuse::ROOT_ID,
                &cs("scratch"),
                0o644,
                false,
                (libc::O_CREAT | libc::O_RDWR | libc::O_EXCL) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        fs.release(ctx(), 0, 0, h.unwrap(), false, false, None).ok();
        fs.unlink(ctx(), fuse::ROOT_ID, &cs("scratch")).unwrap();
        assert!(fs.temps.read().unwrap().is_empty());
        // the bound file cannot be deleted through the mount
        assert_eq!(
            fs.unlink(ctx(), fuse::ROOT_ID, &cs("secret.json"))
                .err()
                .and_then(|e| e.raw_os_error()),
            Some(libc::EPERM)
        );
        assert!(p.exists());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The `O_ACCMODE`-masked flags actually set on the stored host fd.
    fn handle_fd_flags(fs: &SingleFileFs, h: Handle) -> i32 {
        use std::os::fd::AsRawFd;
        let handles = fs.handles.read().unwrap();
        let fd = handles.get(&h).unwrap().as_raw_fd();
        unsafe { libc::fcntl(fd, libc::F_GETFL) }
    }

    /// A read-only bind rejects every mutation, not just create/open: rename and unlink too.
    #[test]
    fn read_only_rejects_rename_and_unlink() {
        let p = tmp_with(b"x");
        let fs = SingleFileFs::new(p.clone(), true).unwrap();
        assert_eq!(
            fs.rename(
                ctx(),
                fuse::ROOT_ID,
                &cs("a"),
                fuse::ROOT_ID,
                &cs("secret.json"),
                0,
            )
            .err()
            .and_then(|e| e.raw_os_error()),
            Some(libc::EROFS)
        );
        assert_eq!(
            fs.unlink(ctx(), fuse::ROOT_ID, &cs("a"))
                .err()
                .and_then(|e| e.raw_os_error()),
            Some(libc::EROFS)
        );
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The bound file cannot be renamed out from under the bind (its name as the rename source).
    #[test]
    fn bound_file_cannot_be_renamed_away() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        assert_eq!(
            fs.rename(
                ctx(),
                fuse::ROOT_ID,
                &cs("secret.json"),
                fuse::ROOT_ID,
                &cs("moved"),
                0,
            )
            .err()
            .and_then(|e| e.raw_os_error()),
            Some(libc::EPERM)
        );
        assert!(p.exists());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// RENAME_EXCHANGE has no meaning for a single-file bind and is rejected with EINVAL;
    /// RENAME_NOREPLACE onto the always-present bound file fails with EEXIST.
    #[test]
    fn rename_exchange_and_noreplace_flags() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let (_, h, _) = fs
            .create(
                ctx(),
                fuse::ROOT_ID,
                &cs("t"),
                0o644,
                false,
                (libc::O_CREAT | libc::O_RDWR | libc::O_EXCL) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        fs.release(ctx(), 0, 0, h.unwrap(), false, false, None).ok();
        assert_eq!(
            fs.rename(
                ctx(),
                fuse::ROOT_ID,
                &cs("t"),
                fuse::ROOT_ID,
                &cs("secret.json"),
                libc::RENAME_EXCHANGE,
            )
            .err()
            .and_then(|e| e.raw_os_error()),
            Some(libc::EINVAL)
        );
        assert_eq!(
            fs.rename(
                ctx(),
                fuse::ROOT_ID,
                &cs("t"),
                fuse::ROOT_ID,
                &cs("secret.json"),
                libc::RENAME_NOREPLACE,
            )
            .err()
            .and_then(|e| e.raw_os_error()),
            Some(libc::EEXIST)
        );
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// Creating a name that already names a live temp reopens that temp (one entry, honoring
    /// O_TRUNC) rather than minting a second entry; with O_EXCL it fails EEXIST.
    #[test]
    fn create_of_an_existing_temp_name_reopens_it() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let make = |excl: bool| {
            let mut flags = libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC;
            if excl {
                flags |= libc::O_EXCL;
            }
            fs.create(
                ctx(),
                fuse::ROOT_ID,
                &cs("scratch"),
                0o644,
                false,
                flags as u32,
                0,
                Extensions::default(),
            )
        };
        // first create mints the temp and writes into it
        let (first, h, _) = make(true).unwrap();
        {
            use std::os::fd::AsRawFd;
            let handles = fs.handles.read().unwrap();
            let fd = handles.get(&h.unwrap()).unwrap().as_raw_fd();
            let payload = b"stale-larger-content";
            let n = unsafe { libc::pwrite(fd, payload.as_ptr() as *const _, payload.len(), 0) };
            assert_eq!(n, payload.len() as isize);
        }
        // a second O_EXCL create of the same name collides
        assert_eq!(
            make(true).err().and_then(|e| e.raw_os_error()),
            Some(libc::EEXIST)
        );
        // a non-exclusive create reopens the SAME inode (no duplicate entry) and O_TRUNC empties it
        let (second, h2, _) = make(false).unwrap();
        assert_eq!(second.inode, first.inode);
        assert_eq!(fs.temps.read().unwrap().len(), 1);
        let (st, _) = fs.getattr(ctx(), second.inode, None).unwrap();
        assert_eq!(st.st_size, 0);
        fs.release(ctx(), 0, 0, h2.unwrap(), false, false, None)
            .ok();
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// Creating under any parent other than the root inode is ENOENT — the root is the only
    /// directory, so a temp's inode passed as the parent must not be treated as one.
    #[test]
    fn create_under_a_non_root_parent_is_enoent() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        assert_eq!(
            fs.create(
                ctx(),
                FILE_INODE,
                &cs("x"),
                0o644,
                false,
                (libc::O_CREAT | libc::O_RDWR) as u32,
                0,
                Extensions::default(),
            )
            .err()
            .and_then(|e| e.raw_os_error()),
            Some(libc::ENOENT)
        );
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn writeback_clears_o_append_on_the_host_fd() {
        // With writeback the guest kernel sends positioned writes; an O_APPEND host fd would
        // (on Linux) ignore the offset and pwrite at EOF, so `open` must strip it.
        let p = tmp_with(b"log");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
        let (h, _) = fs
            .open(
                ctx(),
                FILE_INODE,
                false,
                (libc::O_RDWR | libc::O_APPEND) as u32,
            )
            .unwrap();
        assert_eq!(handle_fd_flags(&fs, h.unwrap()) & libc::O_APPEND, 0);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn without_writeback_o_append_is_preserved() {
        // No writeback negotiated: the host fd's O_APPEND is what provides append semantics.
        let p = tmp_with(b"log");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        let (h, _) = fs
            .open(
                ctx(),
                FILE_INODE,
                false,
                (libc::O_RDWR | libc::O_APPEND) as u32,
            )
            .unwrap();
        assert_ne!(handle_fd_flags(&fs, h.unwrap()) & libc::O_APPEND, 0);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }
}
