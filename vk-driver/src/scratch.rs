//! Process-lifetime scratch plumbing: unlinked files and OS pipes. A scratch file
//! never has a name on disk — it is an `O_TMPFILE` inode on the caller's filesystem
//! (or a memfd where that is unsupported), reopenable as `/proc/self/fd/<n>`. The
//! kernel frees it when the last fd closes, so an aborted run — Ctrl-C, SIGKILL,
//! panic — cannot leak it the way a named temp file can.

use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::path::Path;

use anyhow::{Context, Result};

/// Create an unlinked scratch file: `O_TMPFILE` in `dir` (no `O_EXCL`, so it can be
/// reopened through `/proc/self/fd`), falling back to a memfd where `dir`'s
/// filesystem lacks `O_TMPFILE` support. Pass the directory the data would otherwise
/// have lived in — not `$TMPDIR`, which is often tmpfs — so large scratch data stays
/// on disk. `name` is a debug label only (visible in the memfd's `/proc/<pid>/fd`
/// symlink target).
pub fn scratch(dir: &Path, name: &str) -> Result<File> {
    let cdir = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
        .context("scratch dir path has an interior nul")?;
    // SAFETY: `cdir` is a valid C string; open returns an owned fd or -1/errno.
    let fd = unsafe {
        libc::open(
            cdir.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` was just created and is owned by us.
        return Ok(unsafe { File::from_raw_fd(fd) });
    }
    // Fall back only when O_TMPFILE itself is unsupported: EOPNOTSUPP from the
    // filesystem, EISDIR from kernels that predate the flag. Any other failure
    // must surface to the caller.
    let err = std::io::Error::last_os_error();
    if !matches!(
        err.raw_os_error(),
        Some(libc::EOPNOTSUPP) | Some(libc::EISDIR)
    ) {
        return Err(err)
            .with_context(|| format!("O_TMPFILE in {} for scratch {name}", dir.display()));
    }
    let cname = std::ffi::CString::new(name).context("scratch name has an interior nul")?;
    // SAFETY: `cname` is a valid C string; memfd_create returns an owned fd or -1/errno.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("memfd_create for scratch {name}"));
    }
    // SAFETY: `fd` was just created and is owned by us.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// A unidirectional OS pipe as a (read, write) pair of owned files, for streaming
/// a producer thread's output (e.g. the flattened rootfs tar) into an in-process
/// consumer without materialising it.
pub fn os_pipe() -> Result<(File, File)> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2(2) writes two fresh fds into the array on success. O_CLOEXEC
    // keeps them from leaking into any concurrent fork+exec.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("creating pipe");
    }
    // SAFETY: both fds are freshly created and owned; wrap them in Files.
    let read = unsafe { File::from_raw_fd(fds[0]) };
    let write = unsafe { File::from_raw_fd(fds[1]) };
    Ok((read, write))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};
    use std::os::unix::io::AsRawFd;

    // The scratch file must be writable/seekable through the held fd and reopenable
    // through its /proc/self/fd/<n> path.
    #[test]
    fn write_seek_and_reopen_by_path() {
        let mut s = scratch(&std::env::temp_dir(), "test-blob").unwrap();
        s.write_all(b"hello").unwrap();
        s.seek(std::io::SeekFrom::Start(0)).unwrap();
        let path = format!("/proc/self/fd/{}", s.as_raw_fd());
        let mut reopened = File::open(&path).unwrap();
        let mut got = String::new();
        reopened.read_to_string(&mut got).unwrap();
        assert_eq!(got, "hello");
        // File::create-style reopen (what builders do with the out path) must work too.
        let f = File::create(&path).unwrap();
        f.set_len(1 << 20).unwrap();
    }
}
