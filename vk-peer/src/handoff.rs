//! Handing listening sockets to the next binary across `exec`, so a program updating itself
//! refuses no connection: while it hands over, connections queue in the sockets' backlogs,
//! and the release accepts them.
//!
//! - At start, a program registers each listening socket it serves in a [`Passing`], which
//!   keeps a close-on-exec duplicate of it.
//! - To hand over, it [`Passing::prepare`]s the duplicates, which clears their close-on-exec
//!   flag and names them in [`ENV`], and executes the release with that variable
//!   ([`exec_with`](crate::update::exec_with)). Should the exec fail, dropping the
//!   [`Prepared`] makes them close-on-exec again.
//! - The release takes what [`ENV`] names as it starts ([`Inherited::from_env`]): each socket
//!   inherited and still listening, of the expected family and serving where its config says,
//!   is served as it is ([`Inherited::take_tcp`], [`Inherited::take_unix`]). A socket taken
//!   but not served is closed, one refused is left open, and the program binds afresh.
//!
//! A descriptor keeps its number across `exec`, so [`ENV`] names numbers: `nodes=5,ui=6`. A
//! Unix socket's entry adds the device and inode of its socket file (`admin=7:2049:131`):
//! `getsockname` reports the name a socket was bound under, not the one it was renamed to, and
//! the file's identity also tells it from another socket since bound at that path.

use std::ffi::OsString;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use anyhow::{Context as _, Result, anyhow, bail};

/// The environment variable naming the sockets handed over: `name=fd[:dev:ino]`,
/// comma-separated.
pub const ENV: &str = "VK_LISTEN_FDS";

/// The most sockets handed over: what one [`ENV`] may name.
const MAX_SOCKETS: usize = 16;

/// Whether `name` may name a socket in [`ENV`]: 1 to 32 ASCII lowercase letters, digits and
/// `-`.
fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The listening sockets a program hands over, each a close-on-exec duplicate of one it
/// serves. The duplicates keep the sockets listening as long as this lives: a program that
/// stops serving one ends, or drops this, rather than leave connections queued unanswered.
#[derive(Default)]
pub struct Passing {
    fds: Mutex<Vec<Passed>>,
}

/// A socket handed over: its name, a duplicate of it, and for a Unix socket its socket file.
struct Passed {
    name: String,
    fd: OwnedFd,
    file: Option<FileId>,
}

/// A file's device and inode: its identity, whatever names it.
type FileId = (u64, u64);

impl Passing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hand over `socket`, a listening TCP socket, as `name`.
    pub fn add(&self, name: &str, socket: BorrowedFd<'_>) -> Result<()> {
        if !is_tcp(listening(socket.as_raw_fd()).context("handing a TCP socket over")?) {
            bail!("the {name} socket is not a TCP socket");
        }
        self.push(name, socket, None)
    }

    /// Hand over `socket`, a listening Unix socket serving at `path`, as `name`: the socket
    /// file there now is the one the release serves it at.
    pub fn add_unix(&self, name: &str, socket: BorrowedFd<'_>, path: &Path) -> Result<()> {
        if listening(socket.as_raw_fd()).context("handing a Unix socket over")? != libc::AF_UNIX {
            bail!("the {name} socket is not a Unix socket");
        }
        let file = socket_file(path)?;
        self.push(name, socket, Some(file))
    }

    fn push(&self, name: &str, socket: BorrowedFd<'_>, file: Option<FileId>) -> Result<()> {
        if !valid_name(name) {
            bail!("{name:?} cannot name a socket handed over");
        }
        let mut fds = lock(&self.fds);
        if fds.iter().any(|p| p.name == name) {
            bail!("a socket is handed over as {name} already");
        }
        if fds.len() >= MAX_SOCKETS {
            bail!("at most {MAX_SOCKETS} sockets are handed over");
        }
        // A close-on-exec duplicate (`F_DUPFD_CLOEXEC`), inherited only once prepared.
        let fd = socket
            .try_clone_to_owned()
            .with_context(|| format!("keeping the {name} socket to hand over"))?;
        fds.push(Passed {
            name: name.to_string(),
            fd,
            file,
        });
        Ok(())
    }

    /// Make the sockets survive an `exec`, and the environment entry naming them; dropping the
    /// [`Prepared`] makes them close-on-exec again, for when the exec failed. Meanwhile any
    /// child the program starts inherits them too: hold it only around the exec.
    pub fn prepare(&self) -> Result<Prepared<'_>> {
        let fds = lock(&self.fds);
        let raw: Vec<RawFd> = fds.iter().map(|p| p.fd.as_raw_fd()).collect();
        let prepared = Prepared {
            raw: raw.clone(),
            value: fds
                .iter()
                .map(|p| {
                    let mut entry = format!("{}={}", p.name, p.fd.as_raw_fd());
                    if let Some((dev, ino)) = p.file {
                        entry.push_str(&format!(":{dev}:{ino}"));
                    }
                    entry
                })
                .collect::<Vec<_>>()
                .join(","),
            _fds: fds,
        };
        for fd in raw {
            set_cloexec(fd, false).context("handing a socket over")?;
        }
        Ok(prepared)
    }

    /// The names of the sockets handed over, in the order added.
    pub fn names(&self) -> Vec<String> {
        lock(&self.fds).iter().map(|p| p.name.clone()).collect()
    }
}

/// Sockets ready to survive an `exec`: close-on-exec again once dropped.
pub struct Prepared<'a> {
    raw: Vec<RawFd>,
    value: String,
    /// Held so no socket is added or dropped meanwhile.
    _fds: std::sync::MutexGuard<'a, Vec<Passed>>,
}

impl Prepared<'_> {
    /// The environment entry naming the sockets, for the release.
    pub fn env(&self) -> (OsString, OsString) {
        (ENV.into(), self.value.clone().into())
    }
}

impl Drop for Prepared<'_> {
    fn drop(&mut self) {
        for &fd in &self.raw {
            // Best effort: a socket left inheritable leaks only into a child the program
            // starts, and it is still served here.
            let _ = set_cloexec(fd, true);
        }
    }
}

/// The listening sockets the previous binary handed over, by name, until taken.
#[derive(Default)]
pub struct Inherited {
    fds: Vec<Taken>,
    /// What was wrong with [`ENV`], for the program's log.
    pub problems: Vec<String>,
}

/// A socket inherited: its name, its descriptor, its address family, and for a Unix socket
/// the socket file it was handed over with.
struct Taken {
    name: String,
    fd: OwnedFd,
    family: libc::c_int,
    file: Option<FileId>,
}

/// Whether [`Inherited::from_env`] has run: the descriptors are owned once.
static TAKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Inherited {
    /// The sockets [`ENV`] names, made close-on-exec at once; the first call only, later ones
    /// take nothing. A number [`ENV`] names is taken only if it is an open socket listening,
    /// inherited (not close-on-exec), and only the first time it is named. The variable is left
    /// as it is — changing the environment of a process running threads is not safe — and
    /// [`crate::update::exec_with`] passes it on to no release unless told to. Call it before
    /// the program opens a descriptor without close-on-exec, so that one named by a stale
    /// variable is not already its own.
    pub fn from_env() -> Self {
        if TAKEN.swap(true, Ordering::SeqCst) {
            return Self::default();
        }
        match std::env::var(ENV) {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Self::default(),
            Err(std::env::VarError::NotUnicode(_)) => Self {
                problems: vec![format!("{ENV} is not UTF-8; no socket is taken from it")],
                ..Self::default()
            },
        }
    }

    fn parse(value: &str) -> Self {
        let mut taken = Self::default();
        for (i, entry) in value.split(',').filter(|e| !e.is_empty()).enumerate() {
            if i >= MAX_SOCKETS {
                taken
                    .problems
                    .push(format!("{ENV} names more than {MAX_SOCKETS} sockets"));
                break;
            }
            let Some((name, fd, file)) = entry.split_once('=').and_then(|(n, rest)| {
                let mut parts = rest.split(':');
                let fd = parts.next()?.parse::<RawFd>().ok()?;
                let file = match (parts.next(), parts.next(), parts.next()) {
                    (None, ..) => None,
                    (Some(dev), Some(ino), None) => Some((dev.parse().ok()?, ino.parse().ok()?)),
                    _ => return None,
                };
                (valid_name(n) && fd > 2).then_some((n, fd, file))
            }) else {
                taken.problems.push(format!(
                    "{ENV}: {entry:?} is not name=descriptor[:device:inode]"
                ));
                continue;
            };
            if taken
                .fds
                .iter()
                .any(|t| t.name == name || t.fd.as_raw_fd() == fd)
            {
                taken
                    .problems
                    .push(format!("{ENV} names {name} or descriptor {fd} twice"));
                continue;
            }
            // One refused is left as it is, open: this process may own it.
            match listening(fd).and_then(|family| inherited(fd).map(|()| family)) {
                Ok(family) => {
                    // SAFETY: it is open and was inherited, not opened close-on-exec by this
                    // process: nothing here owns it but what the previous binary passed for
                    // this to take, once.
                    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                    // Best effort: one left inheritable leaks only into a child the program
                    // starts.
                    let _ = set_cloexec(fd.as_raw_fd(), true);
                    taken.fds.push(Taken {
                        name: name.to_string(),
                        fd,
                        family,
                        file,
                    });
                }
                Err(e) => taken
                    .problems
                    .push(format!("{ENV}: {name} (descriptor {fd}): {e:#}")),
            }
        }
        taken
    }

    fn take(&mut self, name: &str) -> Option<Taken> {
        let i = self.fds.iter().position(|t| t.name == name)?;
        Some(self.fds.remove(i))
    }

    /// Take the TCP listener named `name` if it listens on `want`; port 0 accepts any port.
    /// Return `None` if absent, or an error with the socket closed if it does not match.
    pub fn take_tcp(&mut self, name: &str, want: SocketAddr) -> Option<Result<TcpListener>> {
        let taken = self.take(name)?;
        if !is_tcp(taken.family) {
            return Some(Err(anyhow!("it is not a TCP socket")));
        }
        let listener = TcpListener::from(taken.fd);
        Some(match listener.local_addr() {
            Ok(got) if got.ip() == want.ip() && (want.port() == 0 || got.port() == want.port()) => {
                listener
                    .set_nonblocking(true)
                    .context("making it non-blocking")
                    .map(|()| listener)
            }
            Ok(got) => Err(anyhow!("it listens on {got}, not {want}")),
            Err(e) => Err(anyhow!(e).context("reading its address")),
        })
    }

    /// The Unix socket handed over as `name`, if the socket file at `path` is the one it was
    /// handed over with: as [`Inherited::take_tcp`].
    pub fn take_unix(&mut self, name: &str, path: &Path) -> Option<Result<UnixListener>> {
        let taken = self.take(name)?;
        if taken.family != libc::AF_UNIX {
            return Some(Err(anyhow!("it is not a Unix socket")));
        }
        let listener = UnixListener::from(taken.fd);
        Some(match (taken.file, socket_file(path)) {
            (None, _) => Err(anyhow!("its entry names no socket file")),
            (Some(want), Ok(got)) if got == want => listener
                .set_nonblocking(true)
                .context("making it non-blocking")
                .map(|()| listener),
            (Some(_), Ok(_)) => Err(anyhow!(
                "{} is another socket than the one handed over",
                path.display()
            )),
            (Some(_), Err(e)) => Err(e),
        })
    }

    /// The names of the sockets not taken yet, which close when this drops.
    pub fn left(&self) -> Vec<&str> {
        self.fds.iter().map(|t| t.name.as_str()).collect()
    }
}

/// The identity of the socket file at `path`, not following a symlink.
fn socket_file(path: &Path) -> Result<FileId> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !meta.file_type().is_socket() {
        bail!("{} is not a socket", path.display());
    }
    Ok((meta.dev(), meta.ino()))
}

fn is_tcp(family: libc::c_int) -> bool {
    family == libc::AF_INET || family == libc::AF_INET6
}

/// Whether `fd` is an open stream socket, listening: its address family.
fn listening(fd: RawFd) -> Result<libc::c_int> {
    // SAFETY: fstat writes only into the zeroed buffer; an fd not open fails with EBADF.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("it is not open");
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        bail!("it is not a socket");
    }
    let option = |name| -> Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value` and `len` are live locals of the sizes passed.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                (&raw mut value).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("reading a socket option");
        }
        Ok(value)
    };
    if option(libc::SO_TYPE)? != libc::SOCK_STREAM {
        bail!("it is not a stream socket");
    }
    if option(libc::SO_ACCEPTCONN)? == 0 {
        bail!("it is not listening");
    }
    option(libc::SO_DOMAIN)
}

/// Whether `fd` was inherited: not close-on-exec, as std and tokio open every descriptor and
/// as the previous binary cleared it on what it handed over.
fn inherited(fd: RawFd) -> Result<()> {
    // SAFETY: F_GETFD reads a descriptor's flags and touches no memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("reading its flags");
    }
    if flags & libc::FD_CLOEXEC != 0 {
        bail!("it is close-on-exec: this process opened it, nothing handed it over");
    }
    Ok(())
}

fn set_cloexec(fd: RawFd, on: bool) -> Result<()> {
    // SAFETY: F_GETFD and F_SETFD read and set a descriptor's flags and touch no memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let flags = if on {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    fn tcp() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").unwrap()
    }

    /// What a release reads of the sockets `passing` prepared, without an exec: duplicates of
    /// its descriptors, here.
    fn inherit(passing: &Passing) -> Inherited {
        let prepared = passing.prepare().unwrap();
        let (_, value) = prepared.env();
        // Duplicates stand in for what the exec would keep, since `passing` still owns its.
        let value: Vec<String> = value
            .to_str()
            .unwrap()
            .split(',')
            .map(|e| {
                let (name, rest) = e.split_once('=').unwrap();
                let (fd, file) = match rest.split_once(':') {
                    Some((fd, file)) => (fd, format!(":{file}")),
                    None => (rest, String::new()),
                };
                // SAFETY: `fd` is open, owned by `passing`; the duplicate is owned by the
                // `Inherited` that takes it.
                let dup = unsafe { libc::dup(fd.parse().unwrap()) };
                assert!(dup > 2);
                format!("{name}={dup}{file}")
            })
            .collect();
        Inherited::parse(&value.join(","))
    }

    #[test]
    fn prepared_sockets_survive_an_exec_until_dropped() {
        let listener = tcp();
        let passing = Passing::new();
        passing.add("nodes", listener.as_fd()).unwrap();
        let fd = {
            let fds = lock(&passing.fds);
            fds[0].fd.as_raw_fd()
        };
        // SAFETY: `passing` keeps `fd` open throughout.
        let borrowed = || unsafe { BorrowedFd::borrow_raw(fd) };
        let inheritable = || inherited(borrowed().as_raw_fd()).is_ok();
        assert!(!inheritable());
        let prepared = passing.prepare().unwrap();
        assert!(inheritable());
        assert_eq!(prepared.env().1, OsString::from(format!("nodes={fd}")));
        drop(prepared);
        assert!(!inheritable());
    }

    #[test]
    fn a_release_takes_the_sockets_it_is_configured_for() {
        let (nodes, ui) = (tcp(), tcp());
        let dir =
            std::env::temp_dir().join(format!("vk-peer-handoff-takes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.sock");
        let passing = Passing::new();
        passing.add("nodes", nodes.as_fd()).unwrap();
        passing.add("ui", ui.as_fd()).unwrap();
        // Bound elsewhere and renamed into place, as `vk_fs::bind_private` binds: the entry says
        // where it serves.
        let bound = dir.join("bound.sock");
        let admin = UnixListener::bind(&bound).unwrap();
        std::fs::rename(&bound, &path).unwrap();
        passing.add_unix("admin", admin.as_fd(), &path).unwrap();
        assert!(passing.add("ui", ui.as_fd()).is_err());
        let mut inherited = inherit(&passing);
        assert!(inherited.problems.is_empty(), "{:?}", inherited.problems);
        let addr = nodes.local_addr().unwrap();
        let taken = inherited.take_tcp("nodes", addr).unwrap().unwrap();
        assert_eq!(taken.local_addr().unwrap(), addr);
        // Still the same socket: a connection queued on it is accepted through the duplicate.
        let _client = std::net::TcpStream::connect(addr).unwrap();
        taken.set_nonblocking(false).unwrap();
        taken.accept().unwrap();
        // Configured elsewhere now: refused, and closed.
        let elsewhere: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let refused = inherited.take_tcp("ui", elsewhere).unwrap().unwrap_err();
        assert!(
            format!("{refused:#}").contains("not 127.0.0.1:1"),
            "{refused:#}"
        );
        assert!(inherited.take_tcp("ui", elsewhere).is_none());
        // A path it is not bound at, then the one it is.
        assert!(
            inherited
                .take_unix("admin", &dir.join("other.sock"))
                .unwrap()
                .is_err()
        );
        let mut inherited = inherit(&passing);
        assert!(inherited.take_unix("admin", &path).unwrap().is_ok());
        // Any port, as configured with port 0.
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(inherited.take_tcp("ui", any).unwrap().is_ok());
        assert_eq!(inherited.left(), vec!["nodes"]);
        // Another socket bound at the path since: not the one handed over.
        let mut inherited = inherit(&passing);
        std::fs::remove_file(&path).unwrap();
        let _other = UnixListener::bind(&path).unwrap();
        let refused = inherited.take_unix("admin", &path).unwrap().unwrap_err();
        assert!(
            format!("{refused:#}").contains("another socket"),
            "{refused:#}"
        );
        // Each of the kind it is handed over as.
        let mut inherited = inherit(&passing);
        let refused = inherited.take_tcp("admin", any).unwrap().unwrap_err();
        assert!(format!("{refused:#}").contains("not a TCP"), "{refused:#}");
        let refused = inherited.take_unix("nodes", &path).unwrap().unwrap_err();
        assert!(format!("{refused:#}").contains("not a Unix"), "{refused:#}");
        // Nor once no socket file is there.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"").unwrap();
        let mut inherited = inherit(&passing);
        let refused = inherited.take_unix("admin", &path).unwrap().unwrap_err();
        assert!(
            format!("{refused:#}").contains("not a socket"),
            "{refused:#}"
        );
        // A name or a descriptor named twice is taken the first time only.
        // SAFETY: `nodes` is open; each duplicate is owned by what parses it, or closed here.
        let (a, b) = unsafe { (libc::dup(nodes.as_raw_fd()), libc::dup(nodes.as_raw_fd())) };
        let twice = Inherited::parse(&format!("x={a},x={b},y={a}"));
        assert_eq!(twice.left(), vec!["x"]);
        let problems = twice.problems.join("\n");
        assert!(
            problems.contains(&format!("names x or descriptor {b} twice")),
            "{problems}"
        );
        assert!(
            problems.contains(&format!("names y or descriptor {a} twice")),
            "{problems}"
        );
        // SAFETY: `b` was not taken: nothing else owns it.
        unsafe { libc::close(b) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_listening_sockets_of_their_kind_are_handed_over() {
        let passing = Passing::new();
        let server = tcp();
        let connected = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        assert!(passing.add("conn", connected.as_fd()).is_err());
        assert!(
            passing
                .add_unix("tcp", server.as_fd(), Path::new("/"))
                .is_err()
        );
        assert!(passing.add("bad name", server.as_fd()).is_err());
        assert!(passing.names().is_empty());
        for i in 0..MAX_SOCKETS {
            passing.add(&format!("s{i}"), server.as_fd()).unwrap();
        }
        assert!(passing.add("one-more", server.as_fd()).is_err());
    }

    #[test]
    fn the_sockets_are_taken_from_the_environment_once() {
        let _ = Inherited::from_env();
        assert!(TAKEN.load(Ordering::SeqCst));
        assert!(Inherited::from_env().left().is_empty());
    }

    #[test]
    fn what_is_not_a_listening_socket_is_not_taken() {
        let file = std::fs::File::open("/proc/self/exe").unwrap();
        let server = tcp();
        let connected = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        // Listening, but this process's own: close-on-exec, as named by a stale variable.
        let own = tcp();
        let value = format!(
            "a={},b={},c=99999,d,=5,e=1,f={},g={},h=7:1,i=7:1:2:3",
            file.as_raw_fd(),
            connected.as_raw_fd(),
            file.as_raw_fd(),
            own.as_raw_fd()
        );
        // Taken by nothing: each is refused before it is owned.
        let inherited = Inherited::parse(&value);
        assert!(inherited.left().is_empty());
        let problems = inherited.problems.join("\n");
        for want in [
            "a (descriptor",
            "not a socket",
            "not listening",
            "not open",
            "\"d\" is not name=descriptor",
            "\"=5\"",
            "\"e=1\"",
            "g (descriptor",
            "close-on-exec",
            "\"h=7:1\"",
            "\"i=7:1:2:3\"",
        ] {
            assert!(problems.contains(want), "{want}: {problems}");
        }
        // Still open: nothing took them.
        drop(inherited);
        assert!(file.metadata().is_ok());
        assert!(connected.peer_addr().is_ok());
        assert!(own.local_addr().is_ok());
        // No more than an environment entry may name.
        let many: Vec<String> = (0..=MAX_SOCKETS).map(|i| format!("s{i}=9999{i}")).collect();
        let problems = Inherited::parse(&many.join(",")).problems.join("\n");
        assert!(problems.contains("more than 16"), "{problems}");
    }
}
