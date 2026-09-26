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

/// Open a pty pair with an initial window size. Both ends are opened close-on-exec at the
/// open call, so a fork on another thread can't inherit either before the flag is set: the
/// slave reaches a child only as its stdio, and the master never does — a copy left in a
/// child would keep the pty open after this process closes its own, so the hang-up would
/// never reach the shell.
pub fn openpty(rows: u16, cols: u16) -> io::Result<(PtyMaster, OwnedFd)> {
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    let master = unsafe { libc::posix_openpt(flags) };
    if master < 0 {
        return Err(io::Error::last_os_error());
    }
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    if unsafe { libc::grantpt(master.as_raw_fd()) } != 0
        || unsafe { libc::unlockpt(master.as_raw_fd()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // The slave straight from the master, not by name: nothing to look up, nothing to race.
    let slave = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTPEER, flags) };
    if slave < 0 {
        return Err(io::Error::last_os_error());
    }
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    set_winsize(slave.as_raw_fd(), rows, cols)?;
    set_nonblocking(master.as_raw_fd())?;
    Ok((PtyMaster(AsyncFd::new(master)?), slave))
}

impl PtyMaster {
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.get_ref().as_raw_fd()
    }
}

/// Where an RFC 4254 terminal mode (§8) lives in a Linux termios.
#[derive(Clone, Copy)]
enum Mode {
    Cc(usize),
    Iflag(libc::tcflag_t),
    Lflag(libc::tcflag_t),
    Oflag(libc::tcflag_t),
}

/// The RFC 4254 terminal modes Linux has a place for, by opcode. Line speeds, which a pty
/// does not use, and the character size and parity, which Linux fixes at CS8 without
/// parity on a pty, are left out, as are control characters Linux lacks.
const MODES: &[(u8, Mode)] = &[
    (1, Mode::Cc(libc::VINTR)),
    (2, Mode::Cc(libc::VQUIT)),
    (3, Mode::Cc(libc::VERASE)),
    (4, Mode::Cc(libc::VKILL)),
    (5, Mode::Cc(libc::VEOF)),
    (6, Mode::Cc(libc::VEOL)),
    (7, Mode::Cc(libc::VEOL2)),
    (8, Mode::Cc(libc::VSTART)),
    (9, Mode::Cc(libc::VSTOP)),
    (10, Mode::Cc(libc::VSUSP)),
    (12, Mode::Cc(libc::VREPRINT)),
    (13, Mode::Cc(libc::VWERASE)),
    (14, Mode::Cc(libc::VLNEXT)),
    (18, Mode::Cc(libc::VDISCARD)),
    (30, Mode::Iflag(libc::IGNPAR)),
    (31, Mode::Iflag(libc::PARMRK)),
    (32, Mode::Iflag(libc::INPCK)),
    (33, Mode::Iflag(libc::ISTRIP)),
    (34, Mode::Iflag(libc::INLCR)),
    (35, Mode::Iflag(libc::IGNCR)),
    (36, Mode::Iflag(libc::ICRNL)),
    (37, Mode::Iflag(libc::IUCLC)),
    (38, Mode::Iflag(libc::IXON)),
    (39, Mode::Iflag(libc::IXANY)),
    (40, Mode::Iflag(libc::IXOFF)),
    (41, Mode::Iflag(libc::IMAXBEL)),
    (42, Mode::Iflag(libc::IUTF8)),
    (50, Mode::Lflag(libc::ISIG)),
    (51, Mode::Lflag(libc::ICANON)),
    (52, Mode::Lflag(libc::XCASE)),
    (53, Mode::Lflag(libc::ECHO)),
    (54, Mode::Lflag(libc::ECHOE)),
    (55, Mode::Lflag(libc::ECHOK)),
    (56, Mode::Lflag(libc::ECHONL)),
    (57, Mode::Lflag(libc::NOFLSH)),
    (58, Mode::Lflag(libc::TOSTOP)),
    (59, Mode::Lflag(libc::IEXTEN)),
    (60, Mode::Lflag(libc::ECHOCTL)),
    (61, Mode::Lflag(libc::ECHOKE)),
    (62, Mode::Lflag(libc::PENDIN)),
    (70, Mode::Oflag(libc::OPOST)),
    (71, Mode::Oflag(libc::OLCUC)),
    (72, Mode::Oflag(libc::ONLCR)),
    (73, Mode::Oflag(libc::OCRNL)),
    (74, Mode::Oflag(libc::ONOCR)),
    (75, Mode::Oflag(libc::ONLRET)),
];

/// The control-character value RFC 4254 uses for "disabled".
const MODE_DISABLED: u32 = 255;

/// A terminal's current termios (tcgetattr).
fn get_termios(fd: RawFd) -> io::Result<libc::termios> {
    // SAFETY: termios is plain data, valid zeroed; tcgetattr fills it through a valid
    // pointer.
    let mut tio: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut tio) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(tio)
}

/// Encode terminal modes as RFC 4254 opcode/value pairs, as in an SSH pty request.
/// These preserve keys, line discipline, echo and output processing on the server.
pub fn terminal_modes(fd: RawFd) -> io::Result<Vec<(u8, u32)>> {
    let tio = get_termios(fd)?;
    let flag = |field: libc::tcflag_t, bit| u32::from(field & bit != 0);
    Ok(MODES
        .iter()
        .map(|&(op, mode)| {
            let value = match mode {
                Mode::Cc(i) if tio.c_cc[i] == libc::_POSIX_VDISABLE => MODE_DISABLED,
                Mode::Cc(i) => u32::from(tio.c_cc[i]),
                Mode::Iflag(bit) => flag(tio.c_iflag, bit),
                Mode::Lflag(bit) => flag(tio.c_lflag, bit),
                Mode::Oflag(bit) => flag(tio.c_oflag, bit),
            };
            (op, value)
        })
        .collect())
}

/// Apply RFC 4254 terminal modes as sshd does for a pty request. Skip unsupported
/// Linux opcodes and control characters outside 0..=255 instead of truncating them.
pub fn apply_terminal_modes(fd: RawFd, modes: &[(u8, u32)]) -> io::Result<()> {
    if modes.is_empty() {
        return Ok(());
    }
    let mut tio = get_termios(fd)?;
    for &(op, value) in modes {
        let Some(&(_, mode)) = MODES.iter().find(|(o, _)| *o == op) else {
            continue;
        };
        let (field, bit) = match mode {
            Mode::Cc(i) => {
                if value == MODE_DISABLED {
                    tio.c_cc[i] = libc::_POSIX_VDISABLE;
                } else if let Ok(c) = libc::cc_t::try_from(value) {
                    tio.c_cc[i] = c;
                }
                continue;
            }
            Mode::Iflag(bit) => (&mut tio.c_iflag, bit),
            Mode::Lflag(bit) => (&mut tio.c_lflag, bit),
            Mode::Oflag(bit) => (&mut tio.c_oflag, bit),
        };
        if value != 0 {
            *field |= bit;
        } else {
            *field &= !bit;
        }
    }
    // SAFETY: tcsetattr only reads the termios.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &tio) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    use std::os::fd::{AsRawFd, RawFd};
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn the_pair_is_close_on_exec() {
        let (master, slave) = openpty(24, 80).unwrap();
        for (name, fd) in [("master", master.as_raw_fd()), ("slave", slave.as_raw_fd())] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0);
            assert!(
                flags & libc::FD_CLOEXEC != 0,
                "{name} would leak into children"
            );
        }
    }

    #[tokio::test]
    async fn no_child_inherits_the_master() {
        let (mut master, slave) = openpty(24, 80).unwrap();
        // Check this master's fd: the child may inherit unrelated PTY masters (in vscode terminal for example).
        let master_fd = master.as_raw_fd();
        // List each child fd as `<fd> <target>`.
        const LIST_FDS: &str =
            r#"for f in /proc/self/fd/*; do echo "${f##*/} $(readlink "$f" 2>/dev/null)"; done"#;
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg(LIST_FDS)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        let mut child = cmd.spawn().unwrap();
        drop(cmd);
        tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .expect("wait timed out")
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            master.read_to_end(&mut out),
        )
        .await
        .expect("read timed out")
        .unwrap();
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("/dev/pts/"), "no listing: {out}");
        let leaked = out.lines().any(|line| {
            let mut words = line.split_whitespace();
            let fd = words.next().and_then(|fd| fd.parse::<RawFd>().ok());
            fd == Some(master_fd) && words.next() == Some("/dev/ptmx")
        });
        assert!(
            !leaked,
            "the master (fd {master_fd}) reached the child: {out}"
        );
    }

    /// RFC 4254 modes preserve every covered termios field on another pty.
    /// Tokio is required because the pty master registers with the reactor.
    #[tokio::test]
    async fn terminal_modes_carry_over_to_another_pty() {
        use super::{apply_terminal_modes, get_termios, terminal_modes};
        let (_m1, from) = openpty(24, 80).unwrap();
        let (_m2, to) = openpty(24, 80).unwrap();
        let mut tio = get_termios(from.as_raw_fd()).unwrap();
        tio.c_cc[libc::VINTR] = 2;
        tio.c_cc[libc::VERASE] = libc::_POSIX_VDISABLE;
        tio.c_iflag = (tio.c_iflag | libc::IUTF8) & !libc::ICRNL;
        tio.c_lflag &= !libc::ECHO;
        tio.c_oflag &= !libc::OPOST;
        assert_eq!(
            unsafe { libc::tcsetattr(from.as_raw_fd(), libc::TCSANOW, &tio) },
            0
        );

        let modes = terminal_modes(from.as_raw_fd()).unwrap();
        assert!(modes.contains(&(3, 255)), "erase is disabled: {modes:?}");
        apply_terminal_modes(to.as_raw_fd(), &modes).unwrap();
        let (a, b) = (tio, get_termios(to.as_raw_fd()).unwrap());
        assert_eq!(
            (a.c_iflag, a.c_lflag, a.c_oflag),
            (b.c_iflag, b.c_lflag, b.c_oflag)
        );
        assert_eq!(a.c_cc[libc::VINTR], b.c_cc[libc::VINTR]);
        assert_eq!(b.c_cc[libc::VERASE], libc::_POSIX_VDISABLE);
    }

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
