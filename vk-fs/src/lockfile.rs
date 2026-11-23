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
