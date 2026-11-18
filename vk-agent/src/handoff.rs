//! The link between `vk-agent init`, as PID 1 of a guest that hands PID 1 to its image's
//! init, and the exec server it forks first. Before the agent runs anything the host should be
//! able to watch (the `prepare` command), the server reports over it that it listens.
//!
//! A `SOCK_STREAM` socketpair: PID 1 keeps one end, close-on-exec, so the image's init never
//! inherits it, and the server gets the other as `serve --handoff-fd`.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// What the server sends once it listens.
const LISTENING: u8 = b'L';

/// PID 1's end of the link.
pub struct Link {
    sock: std::os::unix::net::UnixStream,
}

impl Link {
    /// A new link, and the end to hand the server: inheritable, unlike PID 1's, and to be
    /// closed once the server is forked so no later child inherits it.
    pub fn new() -> Result<(Link, OwnedFd)> {
        let mut fds = [0; 2];
        // SAFETY: socketpair(2) into a two-element array.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error()).context("socketpair for the handoff link");
        }
        // SAFETY: both descriptors were just created and are owned by nothing else.
        let (ours, theirs) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        set_cloexec(theirs.as_raw_fd(), false)?;
        Ok((
            Link {
                sock: std::os::unix::net::UnixStream::from(ours),
            },
            theirs,
        ))
    }

    /// Wait, at most `timeout`, for the server to report that it listens.
    pub fn wait_listening(&mut self, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let mut byte = [0u8];
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                bail!("the exec server did not listen within {timeout:?}");
            }
            self.sock.set_read_timeout(Some(left))?;
            return match self.sock.read(&mut byte) {
                Ok(1) if byte[0] == LISTENING => Ok(()),
                Ok(0) => bail!("the exec server ended before it listened"),
                Ok(_) => bail!("the exec server sent {:?}, not that it listens", byte[0]),
                // A signal cut the wait short: wait out what is left of it.
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    bail!("the exec server did not listen within {timeout:?}")
                }
                Err(e) => bail!("reading the handoff link: {e}"),
            };
        }
    }
}

/// The server's end, from `serve --handoff-fd`: taken over close-on-exec, so no command the
/// server runs inherits it, and returned to report on.
pub fn serve_end(fd: RawFd) -> Result<std::os::unix::net::UnixStream> {
    set_cloexec(fd, true).context("--handoff-fd")?;
    // SAFETY: the descriptor was handed to this process to own, and nothing else uses it.
    Ok(std::os::unix::net::UnixStream::from(unsafe {
        OwnedFd::from_raw_fd(fd)
    }))
}

/// Tell PID 1 the server listens.
pub fn report_listening(sock: &mut std::os::unix::net::UnixStream) {
    if let Err(e) = sock.write_all(&[LISTENING]) {
        log::warn!("handoff link: reporting that the server listens: {e}");
    }
}

fn set_cloexec(fd: RawFd, on: bool) -> Result<()> {
    // SAFETY: fcntl(2) on a descriptor this process holds.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let flags = if on {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_carries_that_the_server_listens() {
        let (mut link, theirs) = Link::new().unwrap();
        let mut serve = serve_end(theirs.as_raw_fd()).unwrap();
        std::mem::forget(theirs); // now owned by `serve`
        report_listening(&mut serve);
        link.wait_listening(Duration::from_secs(1)).unwrap();
        // a server that ends without listening is told apart from a slow one
        drop(serve);
        let err = link.wait_listening(Duration::from_secs(1)).unwrap_err();
        assert!(format!("{err:#}").contains("ended before"), "{err:#}");
        let (mut link, _theirs) = Link::new().unwrap();
        let err = link.wait_listening(Duration::from_millis(50)).unwrap_err();
        assert!(format!("{err:#}").contains("did not listen"), "{err:#}");
    }
}
