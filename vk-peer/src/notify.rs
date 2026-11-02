//! Telling the service manager that started a program what it needs to know: systemd's
//! `sd_notify(3)` protocol, a datagram of `KEY=value` lines to the socket `$NOTIFY_SOCKET`
//! names, a path or an abstract `@name` (not systemd's newer `vsock:` addresses). Without the
//! variable — no service manager listening, or a unit whose `NotifyAccess=` is `none` — there
//! is nobody to tell, and [`available`] says so.
//!
//! A program handing over to another process of its own uses it to name that process the
//! unit's main one (`MAINPID=`), then waits with [`barrier`] until the manager has read that,
//! before it exits: the manager ends a unit whose main process exits.

use std::ffi::OsString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// The variable naming the socket.
pub const ENV: &str = "NOTIFY_SOCKET";

/// The socket `$NOTIFY_SOCKET` names, if set and not empty.
fn target() -> Option<OsString> {
    std::env::var_os(ENV).filter(|v| !v.is_empty())
}

/// Whether a service manager listens: `$NOTIFY_SOCKET` names a socket.
pub fn available() -> bool {
    target().is_some()
}

/// The socket `$NOTIFY_SOCKET` names, or an error saying nobody listens.
fn manager() -> Result<OsString> {
    target().with_context(|| format!("no service manager listens: {ENV} is not set or empty"))
}

/// The address `target`, an absolute path or `@name` in the abstract namespace, and its length.
fn address(target: &[u8]) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: a zeroed sockaddr_un is valid; its path is filled below within its bounds.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // Abstract `@name` has a leading NUL and no trailing NUL; a path has a trailing NUL.
    let (abstract_name, bytes) = match target.split_first() {
        Some((b'@', rest)) => (true, rest),
        Some((b'/', _)) => (false, target),
        _ => bail!("{ENV} is neither an absolute path nor @name"),
    };
    if abstract_name && bytes.is_empty() {
        bail!("{ENV} names no abstract socket");
    }
    let used = bytes.len() + 1;
    if used > addr.sun_path.len() {
        bail!("{ENV} is too long for a socket address");
    }
    let start = usize::from(abstract_name);
    for (slot, b) in addr.sun_path.iter_mut().skip(start).zip(bytes) {
        *slot = *b as libc::c_char;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + used;
    Ok((addr, len as libc::socklen_t))
}

/// Send `state`, `KEY=value` lines, to the socket `target`, with `fd` passed along when given.
fn send_to(target: &[u8], state: &str, fd: Option<&OwnedFd>) -> Result<()> {
    let (mut addr, addr_len) = address(target)?;
    // SAFETY: socket(2) creates a descriptor owned below.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("opening a notification socket");
    }
    // SAFETY: `raw` was just created and nothing else owns it.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut iov = libc::iovec {
        iov_base: state.as_ptr() as *mut libc::c_void,
        iov_len: state.len(),
    };
    // Room for one descriptor's control message, aligned for its header.
    let mut control = [0u64; 8];
    // SAFETY: a zeroed msghdr is valid; every pointer set below outlives the sendmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut addr).cast();
    msg.msg_namelen = addr_len;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        let raw_fd = fd.as_raw_fd();
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // SAFETY: `control` is large enough for one descriptor's header and data, and the
        // header pointer is to its start.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), raw_fd);
        }
    }
    // SAFETY: `msg` points at live buffers of the lengths it states.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error()).context("telling the service manager");
    }
    Ok(())
}

/// Tell the service manager `state`, `KEY=value` lines such as `READY=1`.
pub fn notify(state: &str) -> Result<()> {
    send_to(manager()?.as_encoded_bytes(), state, None)
}

/// Wait, for at most `within`, until the service manager has read every message sent before:
/// it is sent a pipe's write end with `BARRIER=1`, and closes it once it gets there.
pub fn barrier(within: Duration) -> Result<()> {
    barrier_to(manager()?.as_encoded_bytes(), within)
}

/// [`barrier`], with the manager listening on `target`.
fn barrier_to(target: &[u8], within: Duration) -> Result<()> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 fills the two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("opening a barrier pipe");
    }
    // SAFETY: both were just created and nothing else owns them.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    send_to(target, "BARRIER=1", Some(&write))?;
    drop(write);
    let mut poll = libc::pollfd {
        fd: read.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    let deadline = std::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            bail!("the service manager did not read its messages within {within:?}");
        }
        // Rounded up: a wait cut to 0 ms would spin until the deadline.
        let ms =
            libc::c_int::try_from(left.as_nanos().div_ceil(1_000_000)).unwrap_or(libc::c_int::MAX);
        // SAFETY: `poll` is one live pollfd.
        match unsafe { libc::poll(&mut poll, 1, ms) } {
            // With no event asked for, only the write end closing (POLLHUP) or an error wakes it.
            n if n > 0 && poll.revents & libc::POLLHUP != 0 => return Ok(()),
            n if n > 0 => bail!("waiting on the barrier: poll revents {:#x}", poll.revents),
            n if n < 0 => {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(e).context("waiting on the barrier");
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    use super::*;

    /// An abstract name unique to this test run: abstract names are per network namespace,
    /// which runs in other pid namespaces may share.
    fn unique_name(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("vk-peer-notify-{tag}-{}-{nanos}", std::process::id())
    }

    fn manager(name: &str) -> UnixDatagram {
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        UnixDatagram::bind_addr(&addr).unwrap()
    }

    #[test]
    fn messages_and_a_barrier_reach_the_socket_named() {
        let name = unique_name("barrier");
        let manager = manager(&name);
        let target = format!("@{name}");
        let target = target.as_bytes();
        send_to(target, "MAINPID=42\nREADY=1", None).unwrap();
        let mut buf = [0u8; 256];
        let n = manager.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"MAINPID=42\nREADY=1");
        // The manager reads the barrier; `recv` takes no control message, so the kernel closes
        // the descriptor passed with it, which ends the wait.
        let reader = std::thread::spawn(move || {
            let n = manager.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"BARRIER=1");
            manager
        });
        barrier_to(target, Duration::from_secs(10)).unwrap();
        let manager = reader.join().unwrap();
        // The unread datagram holds the write end open, so the barrier times out.
        let e = barrier_to(target, Duration::from_millis(50)).unwrap_err();
        assert!(format!("{e:#}").contains("within"), "{e:#}");
        drop(manager);
    }

    #[test]
    fn a_path_is_reached() {
        let dir = std::path::Path::new("/tmp").join(unique_name("path"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let manager = UnixDatagram::bind(&path).unwrap();
        send_to(path.as_os_str().as_encoded_bytes(), "READY=1", None).unwrap();
        let mut buf = [0u8; 64];
        let n = manager.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_path_or_an_abstract_name_that_fits_is_an_address() {
        // SAFETY: a zeroed sockaddr_un is valid; only its size is read.
        let room = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
            .sun_path
            .len();
        let path = |n: usize| [b"/".as_slice(), &vec![b'a'; n - 1]].concat();
        let named = |n: usize| [b"@".as_slice(), &vec![b'a'; n]].concat();
        // A path takes a NUL after it, an abstract name one before it.
        assert!(address(&path(room - 1)).is_ok());
        assert!(address(&path(room)).is_err());
        assert!(address(&named(room - 1)).is_ok());
        assert!(address(&named(room)).is_err());
        for bad in [b"".as_slice(), b"@", b"relative", b"vsock:2:9"] {
            assert!(address(bad).is_err(), "{bad:?}");
        }
    }
}
