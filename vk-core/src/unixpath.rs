//! Unix socket paths of any length.
//!
//! `bind` and `connect` accept paths up to [`SUN_PATH_MAX`] bytes in `sockaddr_un.sun_path`.
//! Longer paths use `/proc/self/fd/<n>/<name>`, whose length is independent of the directory
//! path. Binding creates an ordinary socket at the real path, which remains after the
//! descriptor closes. Peers connect through their own directory descriptor, or by name
//! if the path fits.
//!
//! Paths that fit are used unchanged. A `/proc/self/fd` path is valid only in the process
//! holding the descriptor, while it remains open.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Usable bytes in `sockaddr_un.sun_path`, its terminating NUL excluded.
pub const SUN_PATH_MAX: usize = 107;

/// A socket path that fits `sun_path`, holding any directory descriptor it needs.
/// Deferred callers such as libkrun may use [`SocketPath::as_path`] in this process
/// while the `SocketPath` lives.
#[derive(Debug)]
pub struct SocketPath {
    path: PathBuf,
    _dir: Option<OwnedFd>,
}

impl SocketPath {
    /// Use `path` unchanged if it fits, otherwise open its directory and use
    /// `/proc/self/fd/<n>/<name>`. Fail if the name makes that path too long.
    pub fn new(path: &Path) -> io::Result<SocketPath> {
        if path.as_os_str().len() <= SUN_PATH_MAX {
            return Ok(SocketPath {
                path: path.to_path_buf(),
                _dir: None,
            });
        }
        let Some(name) = path.file_name() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{path:?} does not name a socket"),
            ));
        };
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = open_dir(parent)?;
        let short = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
        if short.as_os_str().len() > SUN_PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{path:?} cannot be a unix socket: its {}-byte name is too long to reach \
                     through a directory descriptor",
                    name.len()
                ),
            ));
        }
        Ok(SocketPath {
            path: short,
            _dir: Some(dir),
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// `O_PATH`: the directory needs no read permission to be resolved through. Opened directly
/// rather than through `OpenOptions`, which drops `O_PATH` on musl (see `vk_fs::open_dir`).
fn open_dir(dir: &Path) -> io::Result<OwnedFd> {
    let c_dir = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: the pointer is NUL-terminated and outlives the call; the descriptor returned is
    // handed straight to `OwnedFd`, which closes it.
    let fd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// [`std::os::unix::net::UnixListener::bind`] for a path of any length.
pub fn bind(path: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    std::os::unix::net::UnixListener::bind(SocketPath::new(path)?.as_path())
}

/// [`std::os::unix::net::UnixStream::connect`] for a path of any length.
pub fn connect(path: &Path) -> io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(SocketPath::new(path)?.as_path())
}

/// [`tokio::net::UnixListener::bind`] for a path of any length.
pub fn bind_tokio(path: &Path) -> io::Result<tokio::net::UnixListener> {
    tokio::net::UnixListener::bind(SocketPath::new(path)?.as_path())
}

/// [`tokio::net::UnixStream::connect`] for a path of any length.
pub async fn connect_tokio(path: &Path) -> io::Result<tokio::net::UnixStream> {
    let socket = SocketPath::new(path)?;
    tokio::net::UnixStream::connect(socket.as_path()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::FileTypeExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-unixpath-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A directory deeper than `sun_path` holds, inside `root`.
    fn deep(root: &Path) -> PathBuf {
        let dir = root.join("d".repeat(60)).join("e".repeat(60));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dir.as_os_str().len() > SUN_PATH_MAX + 1);
        dir
    }

    #[test]
    fn a_path_that_fits_is_used_as_given() {
        let path = Path::new("/run/x/vsock.sock_4444");
        let socket = SocketPath::new(path).unwrap();
        assert_eq!(socket.as_path(), path);
    }

    #[test]
    fn a_socket_under_a_deep_directory_binds_and_connects_at_its_real_path() {
        let root = scratch("deep");
        let path = deep(&root).join("vsock.sock_65535");
        let listener = bind(&path).unwrap();
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket(),
            "the socket must be bound at {path:?}"
        );
        let mut client = connect(&path).unwrap();
        let (mut served, _) = listener.accept().unwrap();
        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        served.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The libkrun shape: the spelling is handed on, and bound and dialled later, while the
    /// guard lives.
    #[test]
    fn a_held_spelling_stays_usable() {
        let root = scratch("held");
        let path = deep(&root).join("dirty.sock");
        let socket = SocketPath::new(&path).unwrap();
        assert!(socket.as_path().starts_with("/proc/self/fd"));
        let _listener = std::os::unix::net::UnixListener::bind(socket.as_path()).unwrap();
        drop(socket);
        connect(&path).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn the_tokio_variants_reach_a_deep_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let root = scratch("tokio");
        let path = deep(&root).join("vsock.sock_1024");
        let listener = bind_tokio(&path).unwrap();
        let mut client = connect_tokio(&path).await.unwrap();
        let (mut served, _) = listener.accept().await.unwrap();
        client.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        served.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_name_too_long_for_any_spelling_is_refused() {
        let root = scratch("long-name");
        let path = root.join("n".repeat(100));
        let err = bind(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert!(
            err.to_string()
                .contains("100-byte name is too long to reach through a directory descriptor"),
            "{err}"
        );
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_directory_fails_as_not_found() {
        let root = scratch("missing");
        let path = deep(&root).join("gone").join("x".repeat(20));
        let err = connect(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
