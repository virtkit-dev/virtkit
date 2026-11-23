//! These [`LockFile`] tests run separately so writers forked by the library tests cannot
//! inherit a lock file and prevent directory removal on NFS.

use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use vk_fs::LockFile;

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
    // A umask of `0200` strips owner write permission from the directory. Restore its mode
    // through a descriptor opened without following symlinks.
    let fd = vk_fs::open_dir_nofollow(&dir).unwrap();
    std::fs::set_permissions(
        format!("/proc/self/fd/{}", fd.as_raw_fd()),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
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
    // Unlinking an open file on NFS can leave a `.nfs*` entry that blocks directory removal.
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
    drop(LockFile::new(child));
    try_lock(&probe).expect("held after the child let go");
    drop(probe);
    std::fs::remove_dir_all(dir).unwrap();
}
