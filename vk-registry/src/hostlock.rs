//! A lock between the processes of one network namespace, held by binding an abstract Unix
//! stream socket.
//!
//! The name stays bound until the last descriptor of the socket closes, including copies
//! inherited by children: a holder that dies frees its lock once those close, and nothing
//! on a filesystem can be removed to let a second holder in. While it holds, the holder
//! answers each connection with its identity and closes it, so a waiter can name what it
//! waits for.
//!
//! The name is predictable and the abstract namespace has no permissions, so another local
//! user can bind it first. A waiter refuses a holder of a known foreign uid, or one that
//! three queries in a row could not connect to (see [`judge`]), which turns that into a
//! refused wait rather than a hung one; it cannot stop it.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The abstract socket name locking `key` among the locks of `prefix`: `<prefix>-<hash>`.
/// Hashing keeps the key's share of the 108-byte `sun_path` at 16 bytes; a `prefix` too long
/// for the rest is an error. A hash collision only makes two unrelated keys share a lock.
pub fn addr(prefix: &str, key: &[u8]) -> std::io::Result<SocketAddr> {
    SocketAddr::from_abstract_name(format!("{prefix}-{:016x}", fnv64(key)))
}

/// FNV-1a (lock names, not security).
fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}

/// Connect to the abstract socket `addr` without waiting: a holder that never accepts, its
/// backlog full, refuses at once (`EAGAIN`) rather than hanging the waiter. The stream is
/// returned blocking. `Ok(None)` when nothing listens on the name (`ECONNREFUSED`: the
/// holder is gone, or bound and not listening yet) or its backlog is full (`EAGAIN`); any
/// other failure is an error.
pub fn connect_nonblocking(addr: &SocketAddr) -> std::io::Result<Option<UnixStream>> {
    use std::os::fd::FromRawFd;
    let (sa, len) = abstract_sockaddr(addr).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not an abstract socket name that fits sun_path",
        )
    })?;
    // SAFETY: socket(2) has no memory preconditions; the descriptor is owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh socket owned by nothing else.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    // SAFETY: `sa` is a valid sockaddr_un and `len` covers exactly what was filled in.
    let rc = unsafe { libc::connect(fd, (&raw const sa).cast(), len as libc::socklen_t) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ECONNREFUSED | libc::EAGAIN) => Ok(None),
            _ => Err(e),
        };
    }
    stream.set_nonblocking(false)?;
    Ok(Some(stream))
}

/// `addr`'s abstract name as a `sockaddr_un` and its length: the leading NUL that marks the
/// abstract namespace, then the name, unterminated.
pub fn abstract_sockaddr(addr: &SocketAddr) -> Option<(libc::sockaddr_un, usize)> {
    let name = addr.as_abstract_name()?;
    // SAFETY: an all-zero sockaddr_un is valid; the name is copied after the leading NUL, and
    // the length check keeps it inside sun_path.
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if name.len() + 1 > sa.sun_path.len() {
        return None;
    }
    for (dst, src) in sa.sun_path[1..].iter_mut().zip(name) {
        *dst = *src as libc::c_char;
    }
    Some((
        sa,
        std::mem::size_of::<libc::sa_family_t>() + 1 + name.len(),
    ))
}

/// The uid of the process on the other end of `stream`, from the kernel (`SO_PEERCRED`): for
/// a connection to a listener, whoever called `listen` on it. `None` when the kernel does not
/// say.
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED writes one `ucred` through a pointer to a local of that size, and
    // the descriptor is `stream`'s, live for the call.
    (unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    } == 0)
        .then_some(cred.uid)
}

/// Who answers on a lock's abstract socket. The name is in a namespace every local user
/// shares and has no permissions, so anyone can bind it first; `uid` is that of whoever
/// called `listen` on it, from the kernel, and `who` what its responder said it is.
pub struct Holder {
    pub uid: Option<u32>,
    pub who: Option<String>,
}

/// Query the holder over its lock socket for what it says it is and its kernel-provided uid.
/// Return `Ok(None)` if the connection is refused or the backlog is full (the holder may
/// have just gone); propagate other connection errors such as descriptor exhaustion. Read
/// the response only from a holder known to run as our uid, giving it 1 s in total; a
/// failed or empty read leaves `who` unset. Keep at most 200 printable ASCII bytes, fit for
/// a log.
pub fn query_holder(addr: &SocketAddr) -> std::io::Result<Option<Holder>> {
    let Some(s) = connect_nonblocking(addr)? else {
        return Ok(None);
    };
    let uid = peer_uid(&s);
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    if uid != Some(unsafe { libc::geteuid() }) {
        return Ok(Some(Holder { uid, who: None }));
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    while buf.len() < 4096 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match (&s).read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let who: String = buf
        .iter()
        .map(|&b| char::from(b))
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect();
    let who = who.trim();
    Ok(Some(Holder {
        uid,
        who: (!who.is_empty()).then(|| who.to_string()),
    }))
}

/// What a waiter makes of a lock's holder.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Ours, or not known otherwise: keep waiting.
    Wait,
    /// Listening under another uid: nothing says it will ever let go, so the wait is refused
    /// rather than risk a hang.
    Foreign(u32),
    /// Three or more queries in a row could not connect. Whose the name is cannot be told,
    /// so the wait is refused rather than risk a hang.
    Unanswering,
}

/// Judge the latest [`query_holder`] result and the count of consecutive queries that could
/// not connect, including this one. `me` is our effective uid. A holder of unknown uid, or
/// one that connects and says nothing, is waited for.
pub fn judge(holder: Option<&Holder>, me: u32, unanswered: u32) -> Verdict {
    match holder {
        Some(Holder { uid: Some(uid), .. }) if *uid != me => Verdict::Foreign(*uid),
        None if unanswered >= 3 => Verdict::Unanswering,
        _ => Verdict::Wait,
    }
}

/// Probes the lock at `addr` by connecting. Binding to probe could block a taker until a
/// forked child closes the inherited descriptor at exec. Only a refused connection to a
/// name with no matching stream socket counts as free.
pub fn held(addr: &SocketAddr) -> bool {
    let Some((sa, len)) = abstract_sockaddr(addr) else {
        return true;
    };
    // SAFETY: socket(2) has no memory preconditions; the descriptor is owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return true;
    }
    // SAFETY: `fd` is a fresh socket owned by nothing else.
    let _sock = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    // SAFETY: `sa` is a valid sockaddr_un and `len` covers exactly what was filled in.
    let rc = unsafe { libc::connect(fd, (&raw const sa).cast(), len as libc::socklen_t) };
    if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ECONNREFUSED) {
        return true;
    }
    // A bound stream socket also refuses connections before it starts listening.
    addr.as_abstract_name().is_none_or(abstract_name_bound)
}

/// Looks up `@<name>` in this network namespace's Unix socket table. Only stream sockets
/// conflict with a stream bind. An accepted connection can retain the name in the table,
/// so a match can overreport contention. An unreadable table also counts as bound, as does
/// a name with a newline, which the table cannot show on one line.
fn abstract_name_bound(name: &[u8]) -> bool {
    if name.contains(&b'\n') {
        return true;
    }
    let Ok(table) = std::fs::read("/proc/net/unix") else {
        return true;
    };
    table_has_stream(&table, name)
}

/// Whether `table`, in the format of `/proc/net/unix`, lists a stream socket bound to the
/// abstract `name`.
fn table_has_stream(table: &[u8], name: &[u8]) -> bool {
    // Columns: Num RefCount Protocol Flags Type St Inode Path. The type is `SOCK_STREAM` as
    // `%04X`. The path is absent for an unbound socket; otherwise it is all that follows the
    // single space after the inode, spaces included, with an abstract name's NULs (its
    // leading one too) shown as `@`.
    table.split(|&b| b == b'\n').skip(1).any(|line| {
        let mut rest = line;
        let mut ty: &[u8] = b"";
        for column in 0..7 {
            let start = rest.iter().position(|&b| b != b' ').unwrap_or(rest.len());
            rest = &rest[start..];
            let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
            if end == 0 {
                return false;
            }
            if column == 4 {
                ty = &rest[..end];
            }
            rest = &rest[end..];
        }
        ty == b"0001"
            && rest.strip_prefix(b" @").is_some_and(|path| {
                path.len() == name.len()
                    && path
                        .iter()
                        .zip(name)
                        .all(|(shown, b)| *shown == if *b == 0 { b'@' } else { *b })
            })
    })
}

/// A held lock: the bound socket, and the responder that tells waiters who holds it. The
/// socket is held independently of the responder. Dropping the guard stops the responder,
/// waits for it, then closes its listener: up to the responder's 100 ms accept poll, or
/// mid-answer its 2 s write timeout. An inherited descriptor can keep the socket bound.
pub struct Held {
    _sock: Arc<UnixListener>,
    stop: Arc<AtomicBool>,
    responder: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.responder.take() {
            let _ = h.join();
        }
    }
}

/// Take the lock at `addr` without waiting, answering waiters with `identity` while it is
/// held: `Ok(None)` when the name is already bound, by a holder or by anything else.
pub fn try_acquire(addr: &SocketAddr, identity: &str) -> std::io::Result<Option<Held>> {
    match UnixListener::bind_addr(addr) {
        Ok(lock) => Ok(Some(spawn_holder(lock, identity.to_string()))),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
        Err(e) => Err(e),
    }
}

/// Start the holder's responder: a thread that shares the bound `lock` and answers each
/// waiter's connection with `identity` until the guard is dropped. It polls a non-blocking
/// accept every 100 ms against a stop flag, so drop ends it, and rides out accept errors
/// (`EMFILE`, `ECONNABORTED`, ...) rather than exiting: waiters give up on a holder they
/// repeatedly cannot connect to. The guard keeps its own reference to `lock`, so even if
/// this thread dies the socket stays bound (the lock is held).
fn spawn_holder(lock: UnixListener, identity: String) -> Held {
    let lock = Arc::new(lock);
    let stop = Arc::new(AtomicBool::new(false));
    let responder = {
        let accept_sock = lock.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let _ = accept_sock.set_nonblocking(true);
            while !stop.load(Ordering::Relaxed) {
                match accept_sock.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                        let _ = s.write_all(identity.as_bytes());
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(100)),
                }
            }
        })
    };
    Held {
        _sock: lock,
        stop,
        responder: Some(responder),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lock of `what`, a name of this test process: concurrent runs do not share it.
    fn test_addr(what: &str) -> SocketAddr {
        let key = format!("{what}-{}", std::process::id());
        addr("virtkit-test-hostlock", key.as_bytes()).unwrap()
    }

    /// The names older vk processes already use for these locks.
    #[test]
    fn a_name_is_its_prefix_and_the_hash_of_its_key() {
        let addr = addr("virtkit-pull", b"/var/lib/vk/images/x").unwrap();
        let name = addr.as_abstract_name().unwrap();
        assert_eq!(
            name,
            format!("virtkit-pull-{:016x}", fnv64(b"/var/lib/vk/images/x")).as_bytes()
        );
        assert_eq!(fnv64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv64(b"a"), 0xaf63dc4c8601ec8c);
    }

    /// A squatter that never accepts, its backlog full, cannot hang a waiter: the query gives
    /// up at once instead of blocking in connect.
    #[test]
    fn a_holder_that_never_accepts_does_not_hang_the_query() {
        use std::os::fd::FromRawFd;
        let addr = test_addr("full");
        // A listener with no backlog, which a few connections fill; a larger one would
        // cost the test as many descriptors.
        let (sa, len) = abstract_sockaddr(&addr).unwrap();
        // SAFETY: plain socket calls on a fresh descriptor, owned by `squatter` below; `sa`
        // and `len` describe exactly the address filled in.
        let squatter = unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0);
            assert_eq!(
                libc::bind(fd, (&raw const sa).cast(), len as libc::socklen_t),
                0
            );
            assert_eq!(libc::listen(fd, 0), 0);
            UnixListener::from_raw_fd(fd)
        };
        // Fill its backlog with connections it never accepts.
        let mut held = Vec::new();
        while let Some(c) = connect_nonblocking(&addr).unwrap() {
            held.push(c);
            assert!(held.len() < 8, "a backlog of 0 never filled");
        }
        let started = Instant::now();
        assert!(query_holder(&addr).unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop((held, squatter));
    }

    #[test]
    fn a_waiter_refuses_a_foreign_or_unanswering_holder() {
        let ours = Holder {
            uid: Some(1000),
            who: Some("job 1".into()),
        };
        let theirs = Holder {
            uid: Some(1001),
            who: None,
        };
        let unknown = Holder {
            uid: None,
            who: None,
        };
        assert_eq!(judge(Some(&ours), 1000, 0), Verdict::Wait);
        assert_eq!(judge(Some(&unknown), 1000, 0), Verdict::Wait);
        assert_eq!(judge(Some(&theirs), 1000, 0), Verdict::Foreign(1001));
        assert_eq!(judge(None, 1000, 1), Verdict::Wait);
        assert_eq!(judge(None, 1000, 2), Verdict::Wait);
        assert_eq!(judge(None, 1000, 3), Verdict::Unanswering);
    }

    /// Drop control bytes and truncate the holder's identity for logs: whatever binds the
    /// name under our uid can supply arbitrary bytes.
    #[test]
    fn a_holders_self_description_is_kept_printable() {
        let addr = test_addr("evil");
        let squatter = UnixListener::bind_addr(&addr).unwrap();
        let answer = std::thread::spawn(move || {
            let (mut s, _) = squatter.accept().unwrap();
            let mut say = b"\x1b[2Jevil\x07 job".to_vec();
            say.extend(std::iter::repeat_n(b'x', 1000));
            let _ = s.write_all(&say);
        });
        let holder = query_holder(&addr).unwrap().expect("the squatter answers");
        answer.join().unwrap();
        let who = holder.who.unwrap();
        assert!(who.starts_with("[2Jevil job"), "{who:?}");
        assert!(who.chars().all(|c| c.is_ascii_graphic() || c == ' '));
        assert!(who.len() <= 200);
    }

    /// A bound name is found in the socket table whatever it contains: the path column
    /// runs to the end of the line.
    #[test]
    fn the_socket_table_is_searched_for_names_with_spaces() {
        let table = b"Num       RefCount Protocol Flags    Type St Inode Path\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 12345 @a lock name\n\
            0000000000000000: 00000002 00000000 00000000 0002 01    77 @datagram\n\
            0000000000000000: 00000003 00000000 00000000 0001 03  4242\n\
            0000000000000000: 00000002 00000000 00010000 0001 01     9 @nul@inside \n\
            0000000000000000: 00000002 00000000 00010000 0001 01 54321 /run/a @path\n";
        assert!(table_has_stream(table, b"a lock name"));
        assert!(!table_has_stream(table, b"a lock"));
        assert!(!table_has_stream(table, b"name"));
        assert!(!table_has_stream(table, b"datagram"));
        assert!(table_has_stream(table, b"nul\0inside "));
        assert!(!table_has_stream(table, b"nul@inside"));
        assert!(!table_has_stream(table, b"path"));
        assert!(!table_has_stream(table, b""));

        // Against the kernel's own table: bound, not listening, so only the table says so.
        let name = format!("virtkit-test-hostlock a b-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(&name).unwrap();
        assert!(!held(&addr));
        let (sa, len) = abstract_sockaddr(&addr).unwrap();
        // SAFETY: plain socket calls on a fresh descriptor, owned by `bound` below; `sa`
        // and `len` describe exactly the address filled in.
        let bound = unsafe {
            use std::os::fd::FromRawFd;
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0);
            assert_eq!(
                libc::bind(fd, (&raw const sa).cast(), len as libc::socklen_t),
                0
            );
            std::os::fd::OwnedFd::from_raw_fd(fd)
        };
        assert!(held(&addr));
        drop(bound);
    }

    // Asking leaves the lock as it found it, and a held lock says who holds it.
    #[test]
    fn a_lock_is_asked_after_without_taking_it() {
        let addr = test_addr("held");
        assert!(!held(&addr));
        let _held = try_acquire(&addr, "job 7")
            .unwrap()
            .expect("asking took nothing");
        assert!(held(&addr));
        assert!(
            try_acquire(&addr, "job 8").unwrap().is_none(),
            "a held lock is not taken"
        );
        let holder = query_holder(&addr).unwrap().expect("the holder answers");
        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        assert_eq!(holder.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(holder.who.as_deref(), Some("job 7"));
    }
}
