// A virtio-fs filesystem that exports exactly ONE host file as the sole entry of an
// otherwise-empty root directory — the server primitive for a single-file bind mount.
//
// Unlike PassthroughFs (rooted at a directory, holding a descriptor to the whole subtree),
// SingleFileFs only ever opens the one file it was handed. The file's parent directory is
// never opened, named, or reachable: `lookup` accepts only the configured basename, `readdir`
// lists only it, and there is no inode a guest could obtain for anything else. So isolation is
// structural — a hostile guest that remounts the tag and probes the root still cannot escape to
// siblings — rather than a filter layered over a broader passthrough share.
//
// Spike scope: enough to mount, stat, read, write and truncate the file. Ownership/mode/xattr
// changes and hardlink/rename semantics are intentionally omitted (a single-file bind doesn't
// need them); they'd be added for a production version.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use super::filesystem::{
    Context, DirEntry, Entry, FileSystem, FsOptions, OpenOptions, SetattrValid, ZeroCopyReader,
    ZeroCopyWriter,
};
use super::fuse;
use crate::virtio::bindings;

type Inode = u64;
type Handle = u64;

/// The lone file's inode. The root directory is `fuse::ROOT_ID` (1).
const FILE_INODE: Inode = 2;
const TTL: Duration = Duration::from_secs(1);

/// Serves a single host file `path` as `/<name>` where `name` is its basename.
pub struct SingleFileFs {
    name: CString,
    path: PathBuf,
    read_only: bool,
    /// Set in `init` when the peer negotiates writeback caching. With writeback the guest kernel
    /// owns append semantics, so an `O_APPEND` host fd must be cleared (see `open`).
    writeback: AtomicBool,
    handles: RwLock<HashMap<Handle, File>>,
    next_handle: AtomicU64,
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

impl SingleFileFs {
    pub fn new(path: PathBuf, read_only: bool) -> io::Result<Self> {
        let name = path
            .file_name()
            .and_then(|n| CString::new(n.as_bytes()).ok())
            .ok_or_else(einval)?;
        Ok(SingleFileFs {
            name,
            path,
            read_only,
            writeback: AtomicBool::new(false),
            handles: RwLock::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        })
    }

    fn cpath(&self) -> io::Result<CString> {
        CString::new(self.path.as_os_str().as_bytes()).map_err(|_| einval())
    }

    /// `stat` the backing host file via `statx` (not `std::fs::metadata`, which on musl uses the
    /// legacy `stat` syscall the virtio-fs seccomp allowlist deliberately omits — PassthroughFs
    /// uses `statx` too). Reported under `FILE_INODE` so the fuse node id is stable; filled
    /// field-by-field because `bindings::stat64` is a target-specific alias (`libc::stat` on musl).
    fn stat_file(&self) -> io::Result<bindings::stat64> {
        use super::passthrough::statx_compat;
        let c = self.cpath()?;
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
        st.st_ino = FILE_INODE;
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

    /// Open the backing file via `openat` (not `std::fs::File::open`, which on musl uses the
    /// legacy `open` syscall the allowlist omits). Returns a `File` owning the fd.
    fn open_backing(&self, oflags: i32) -> io::Result<File> {
        use std::os::fd::FromRawFd;
        let c = self.cpath()?;
        // SAFETY: `c` is a valid C string; openat writes nothing through our pointers.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), oflags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: we own `fd` (just opened, not handed out elsewhere).
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn root_attr() -> bindings::stat64 {
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_ino = fuse::ROOT_ID;
        st.st_mode = libc::S_IFDIR | 0o755;
        st.st_nlink = 2;
        st.st_blksize = 4096;
        st
    }

    fn handle_file(&self, handle: Handle) -> io::Result<File> {
        self.handles
            .read()
            .unwrap()
            .get(&handle)
            .and_then(|f| f.try_clone().ok())
            .ok_or_else(ebadf)
    }
}

impl FileSystem for SingleFileFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // Negotiate the same core features a passthrough share does; readdirplus resolves the
        // one-entry root in a single round.
        let mut opts = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        if capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        Ok(opts)
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        // The only name that resolves is the configured basename, only under the root.
        if parent != fuse::ROOT_ID || name != self.name.as_c_str() {
            return Err(enoent());
        }
        Ok(Entry {
            inode: FILE_INODE,
            generation: 0,
            attr: self.stat_file()?,
            attr_flags: 0,
            attr_timeout: TTL,
            entry_timeout: TTL,
        })
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
            _ => Err(enoent()),
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
        if inode != FILE_INODE {
            return Err(enoent());
        }
        if self.read_only {
            return Err(erofs());
        }
        // Truncation only (what a config-file rewrite needs); other attrs are ignored in the spike.
        if valid.contains(SetattrValid::SIZE) {
            self.open_backing(libc::O_WRONLY)?
                .set_len(attr.st_size as u64)?;
        }
        Ok((self.stat_file()?, TTL))
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        _kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if inode != FILE_INODE {
            return Err(enoent());
        }
        let write = matches!(
            flags as i32 & libc::O_ACCMODE,
            libc::O_WRONLY | libc::O_RDWR
        );
        if write && self.read_only {
            return Err(erofs());
        }
        // Open the one file — never the parent. Read-write when writable so the read path can
        // pread the shared fd; carry the guest's O_TRUNC.
        let acc = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let mut extra = flags as i32 & (libc::O_APPEND | libc::O_TRUNC);
        // With writeback caching the guest kernel owns append: it tracks the size and sends
        // positioned writes, but an O_APPEND host fd would (on Linux) ignore that offset and pwrite
        // at EOF, corrupting the file. Clear it, matching PassthroughFs::open_inode.
        if self.writeback.load(Ordering::Relaxed) {
            extra &= !libc::O_APPEND;
        }
        let file = self.open_backing(acc | extra)?;
        let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(h, file);
        Ok((Some(h), OpenOptions::empty()))
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
        let entries: [(&[u8], u64, u32); 3] = [
            (b".", fuse::ROOT_ID, libc::DT_DIR as u32),
            (b"..", fuse::ROOT_ID, libc::DT_DIR as u32),
            (self.name.as_bytes(), FILE_INODE, libc::DT_REG as u32),
        ];
        for (i, (name, ino, type_)) in entries.iter().enumerate() {
            let next = i as u64 + 1; // resume token: 1-based, 0 means "from the start"
            if next <= offset {
                continue;
            }
            let stop = add_entry(DirEntry {
                ino: *ino,
                offset: next,
                type_: *type_,
                name,
            })? == 0;
            if stop {
                break; // kernel buffer full
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

    #[test]
    fn lookup_resolves_only_the_basename() {
        let p = tmp_with(b"{}");
        let fs = SingleFileFs::new(p.clone(), false).unwrap();
        // the file resolves...
        let e = fs
            .lookup(ctx(), fuse::ROOT_ID, &CString::new("secret.json").unwrap())
            .unwrap();
        assert_eq!(e.inode, FILE_INODE);
        // ...the sibling does NOT (structural isolation — no inode is ever handed out for it)
        assert!(fs
            .lookup(ctx(), fuse::ROOT_ID, &CString::new("other.txt").unwrap())
            .is_err());
        assert!(fs
            .lookup(ctx(), fuse::ROOT_ID, &CString::new("..").unwrap())
            .is_err());
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

    /// The `O_ACCMODE`-masked flags actually set on the stored host fd.
    fn handle_fd_flags(fs: &SingleFileFs, h: Handle) -> i32 {
        use std::os::fd::AsRawFd;
        let handles = fs.handles.read().unwrap();
        let fd = handles.get(&h).unwrap().as_raw_fd();
        unsafe { libc::fcntl(fd, libc::F_GETFL) }
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
