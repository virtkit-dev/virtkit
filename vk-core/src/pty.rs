//! Pty plumbing for `exec --tty`: master side wrapper (server), window-size ioctls,
//! and the client's raw-terminal guard.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Async wrapper around the master side of a pty.
pub struct PtyMaster(AsyncFd<OwnedFd>);

/// Open a pty pair with an initial window size.
pub fn openpty(rows: u16, cols: u16) -> io::Result<(PtyMaster, OwnedFd)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let ws = winsize(rows, cols);
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &ws,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    set_nonblocking(master.as_raw_fd())?;
    Ok((PtyMaster(AsyncFd::new(master)?), slave))
}

impl PtyMaster {
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.get_ref().as_raw_fd()
    }
}

/// Apply a window size to a tty (TIOCSWINSZ) — the kernel signals SIGWINCH to the
/// foreground process group of the pty.
pub fn set_winsize(fd: RawFd, rows: u16, cols: u16) -> io::Result<()> {
    let ws = winsize(rows, cols);
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Current window size of a tty (TIOCGWINSZ).
pub fn get_winsize(fd: RawFd) -> io::Result<(u16, u16)> {
    let mut ws = winsize(0, 0);
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((ws.ws_row, ws.ws_col))
}

fn winsize(rows: u16, cols: u16) -> libc::winsize {
    libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AsyncRead for PtyMaster {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // EIO on a pty master = every slave handle is closed (the command
                // and its children exited): that is the pty's end-of-file
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Poll::Ready(Ok(())),
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for PtyMaster {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Puts a local terminal in raw mode; the saved settings are restored on drop
/// (including on error paths) so the user's shell is never left broken.
pub struct RawModeGuard {
    fd: RawFd,
    saved: libc::termios,
}

impl RawModeGuard {
    pub fn enable(fd: RawFd) -> io::Result<RawModeGuard> {
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = saved;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(RawModeGuard { fd, saved })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

#[cfg(test)]
mod tests {
    use super::openpty;
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn pty_spawn_read_roundtrip() {
        let (mut master, slave) = openpty(24, 80).unwrap();
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg("stty size; echo hello")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        // the Command keeps the slave Stdio fds open: drop it or the master never
        // reaches EIO (= eof)
        drop(cmd);
        let status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .expect("wait timed out")
            .unwrap();
        assert!(status.success());
        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            master.read_to_end(&mut out),
        )
        .await
        .expect("read timed out")
        .unwrap();
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("24 80"), "out: {out}");
        assert!(out.contains("hello"), "out: {out}");
    }
}
