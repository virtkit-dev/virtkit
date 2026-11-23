//! `flock(2)` locks that end when their holder drops them.
//!
//! A flock belongs to the open file description. If another thread forks while the lock is
//! held, the child inherits a descriptor. Close-on-exec leaves it open until exec, so a
//! probe can still find the lock held after the parent closes its copy. [`LockFile`] issues
//! `LOCK_UN` before closing to release the lock across all copies.

use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

/// Releases the file's flock on drop, including for inherited descriptors. Use
/// [`Self::into_file`] when a child should keep the lock.
#[derive(Debug)]
pub struct LockFile(ManuallyDrop<File>);

impl LockFile {
    /// Wraps a file without acquiring a lock.
    pub fn new(file: File) -> LockFile {
        LockFile(ManuallyDrop::new(file))
    }

    /// Returns the file without unlocking it. A child can then keep the lock until the
    /// last descriptor closes.
    pub fn into_file(self) -> File {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so the file is taken out exactly once.
        unsafe { ManuallyDrop::take(&mut this.0) }
    }
}

impl std::ops::Deref for LockFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}

// `DerefMut` would let callers replace the file that `Drop` unlocks. I/O needs only `&File`.
impl std::io::Read for LockFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl std::io::Write for LockFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

impl std::io::Seek for LockFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        (&*self.0).seek(pos)
    }
}

impl AsFd for LockFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for LockFile {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        // SAFETY: `self.0` owns the fd throughout the call. Unlocking an unlocked file is a
        // no-op. If unlocking fails, the lock lasts until the last descriptor closes.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        // SAFETY: this is the only drop of the inner file. `into_file` suppresses this destructor.
        unsafe { ManuallyDrop::drop(&mut self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn try_lock(f: &File) -> std::io::Result<()> {
        // SAFETY: the fd is owned by `f`; LOCK_NB never blocks.
        match unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }

    fn assert_held(probe: &File) {
        let err = try_lock(probe).expect_err("not held");
        assert_eq!(err.kind(), ErrorKind::WouldBlock, "{err}");
    }

    /// Isolates the lock file from other tests.
    fn private_dir() -> PathBuf {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let template = std::env::temp_dir().join("vk-lockfile-XXXXXX");
        let mut template = std::ffi::CString::new(template.as_os_str().as_bytes())
            .unwrap()
            .into_bytes_with_nul();
        // SAFETY: `template` is a NUL-terminated buffer mkdtemp rewrites in place.
        let made = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        assert!(!made.is_null(), "{}", std::io::Error::last_os_error());
        template.pop();
        let dir = PathBuf::from(std::ffi::OsString::from_vec(template));
        // A umask such as `0200` strips owner bits `mkdtemp` asked for.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// A fresh lock file in a private directory, and an independent probe of it.
    fn lock_file() -> (PathBuf, File, File) {
        let dir = private_dir();
        let path = dir.join("lock");
        let file = File::options()
            .create_new(true)
            .append(true)
            .open(&path)
            .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        // Writable: over NFS an exclusive flock needs write access.
        let probe = File::options().write(true).open(&path).unwrap();
        (dir, file, probe)
    }

    /// The duplicate stands in for a descriptor inherited across fork.
    #[test]
    fn dropping_releases_the_lock_under_every_copy() {
        let (dir, file, probe) = lock_file();
        let held = LockFile::new(file);
        try_lock(&held).unwrap();
        let copy = held.try_clone().unwrap();
        assert_held(&probe);
        drop(held);
        try_lock(&probe).expect("released although a copy is open");
        drop(copy);
        // Over NFS an open file is only renamed to `.nfs*`, and its directory stays.
        drop(probe);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A child's copy keeps the lock after the file returned by `into_file` closes.
    #[test]
    fn into_file_hands_the_lock_on() {
        let (dir, file, probe) = lock_file();
        let held = LockFile::new(file);
        try_lock(&held).unwrap();
        let file = held.into_file();
        let child = file.try_clone().unwrap();
        drop(file);
        assert_held(&probe);
        // A child forked by another test could still hold a copy, so unlock explicitly.
        drop(LockFile::new(child));
        try_lock(&probe).expect("held after the child let go");
        drop(probe);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
