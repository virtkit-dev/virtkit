use crate::addr::SocketAddr;
use crate::framing::{DeSink, SerStream, wrap_stream};
use anyhow::{Context, anyhow, bail};
use listenfd::ListenFd;
use log::{debug, info};
use std::ffi::{CString, OsStr};
use std::os::fd::RawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::prelude::{FromRawFd, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio_vsock::{VMADDR_CID_ANY, VMADDR_CID_HOST, VsockAddr, VsockListener, VsockStream};

/// Establishing a connection (including the vsock-mux handshake) must not hang on a
/// stuck server / VMM — running commands have no deadline, but connecting does.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Client side: open a connection to a virtkit-agent server.
pub async fn connect(socket: &SocketAddr) -> Result<(SerStream, DeSink), anyhow::Error> {
    tokio::time::timeout(CONNECT_TIMEOUT, connect_inner(socket))
        .await
        .map_err(|_| anyhow!("timed out connecting to {socket}"))?
}

async fn connect_inner(socket: &SocketAddr) -> Result<(SerStream, DeSink), anyhow::Error> {
    match socket {
        SocketAddr::Systemd => bail!("cannot connect to systemd:// (serve only)"),
        SocketAddr::Unix(path) => {
            let stream = UnixStream::connect(path)
                .await
                .with_context(|| format!("connecting to {}", path.display()))?;
            Ok(wrap_stream(stream))
        }
        SocketAddr::Vsock { cid, port } => {
            let addr = VsockAddr::new(cid.unwrap_or(VMADDR_CID_HOST), *port);
            let stream = VsockStream::connect(addr)
                .await
                .with_context(|| format!("connecting to vsock {addr:?}"))?;
            Ok(wrap_stream(stream))
        }
        SocketAddr::VsockMux { path, port } => Ok(wrap_stream(connect_mux(path, *port).await?)),
        SocketAddr::VsockAuto { path, port } => Ok(wrap_stream(connect_auto(path, *port).await?)),
        SocketAddr::Tcp(_) => bail!("tcp:// is for `forward` only, not the virtkit-agent protocol"),
    }
}

/// The host-side socket of guest `port` on the hybrid-vsock suffix convention:
/// `<base>_<port>` — the single spelling of that suffix, shared by the VMM
/// backends, the bridge forwards, and `vsock-auto://` resolution.
pub fn hybrid_socket(base: &Path, port: u32) -> PathBuf {
    let mut socket = base.as_os_str().to_owned();
    socket.push(format!("_{port}"));
    socket.into()
}

/// `vsock-auto://`: resolve the best host→guest path for a guest port at connect
/// time. A dedicated per-port listener at `<base>_<port>` (libkrun) is raw and
/// relay-free, so it is preferred; anything short of a connected socket falls
/// back to the `CONNECT` handshake on `<base>` (Cloud Hypervisor's hybrid
/// socket). One address form for every backend.
///
/// Only meaningful for host→guest ports: a guest→host bridge port puts a *host*
/// listener on the same `<base>_<port>` path, which this resolution would
/// connect to instead of the guest.
async fn connect_auto(path: &Path, port: u32) -> Result<UnixStream, anyhow::Error> {
    let per_port = hybrid_socket(path, port);
    let direct_err = match UnixStream::connect(&per_port).await {
        Ok(stream) => return Ok(stream),
        Err(e) => e,
    };
    connect_mux(path, port).await.with_context(|| {
        format!(
            "vsock-auto: per-port socket {} unusable ({direct_err}), and the mux handshake failed",
            per_port.display()
        )
    })
}

/// "Hybrid vsock" (Cloud Hypervisor, Firecracker): connect to the unix socket the VMM
/// exposes on the host and ask it to forward to a guest vsock port: send
/// `CONNECT <port>\n`, the VMM answers `OK <local port>\n` once the guest accepts, and
/// from there the stream is raw end-to-end.
async fn connect_mux(path: &Path, port: u32) -> Result<UnixStream, anyhow::Error> {
    let mut stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to vsock mux {}", path.display()))?;
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await?;
    // Read the status line one byte at a time: anything past the '\n' already belongs
    // to the virtkit-agent protocol and must not be consumed here.
    let mut line = Vec::new();
    loop {
        let b = stream
            .read_u8()
            .await
            .with_context(|| format!("vsock mux: guest port {port} unreachable"))?;
        if b == b'\n' {
            break;
        }
        line.push(b);
        if line.len() > 64 {
            bail!("vsock mux: invalid response (not a CONNECT status line)");
        }
    }
    let line = String::from_utf8_lossy(&line);
    if !line.starts_with("OK ") {
        bail!("vsock mux: connection to guest port {port} refused ({line})");
    }
    Ok(stream)
}

pub enum Listener {
    Unix(UnixListener),
    Vsock(VsockListener),
}

impl Listener {
    async fn accept(&self) -> std::io::Result<(SerStream, DeSink)> {
        match self {
            Listener::Unix(listener) => {
                let (stream, _addr) = listener.accept().await?;
                Ok(wrap_stream(stream))
            }
            Listener::Vsock(listener) => {
                // vsock has no file permissions: log who connects (host = cid 2;
                // in-guest peers would need the vsock_loopback module)
                let (stream, addr) = listener.accept().await?;
                debug!(
                    "vsock connection from cid {} port {}",
                    addr.cid(),
                    addr.port()
                );
                Ok(wrap_stream(stream))
            }
        }
    }
}

/// The listening side of a server: one listener, or several under socket
/// activation (e.g. a unix socket plus a vsock one in the microVM).
pub struct Listeners(Vec<Listener>);

impl Listeners {
    pub async fn accept(&self) -> std::io::Result<(SerStream, DeSink)> {
        let accepts = self.0.iter().map(|l| Box::pin(l.accept()));
        let (result, _index, _rest) = futures::future::select_all(accepts).await;
        result
    }
}

/// `sockaddr_un::sun_path`, terminator included: the ceiling on a unix socket path.
/// `vk-registry`'s admin socket keeps its own copy; the two crates share no code.
const SUN_PATH_MAX: usize = 108;

/// Staging names to try before giving up. Each is picked afresh, so one being taken takes a
/// remarkable coincidence — or someone who guessed it — and either way the way past is
/// another name rather than clearing a directory this did not make.
const STAGING_ATTEMPTS: u32 = 8;

/// Bind a unix socket that is `0600` from the moment anything can reach it.
/// Requires procfs mounted at `/proc`, whose descriptor links give `bind` a short path to
/// the staging directory without resolving the caller's path again.
///
/// `bind` honours the ambient umask, and neither obvious repair works: `fchmod` on the
/// listener changes the sockfs inode, not the directory entry anyone connects through, and
/// a `chmod` one syscall later leaves the socket connectable — and group-reachable — under
/// its final name in between. Setting the umask around the bind closes that window and opens
/// a worse one: the umask is process-wide, so every file *another thread* creates meanwhile
/// is created with it too, which is how a concurrent writer ends up with unreadable files
/// and directories missing the execute bit.
///
/// So bind inside a `0700` staging directory of its own and rename it onto `path`. The name
/// a client connects to only ever refers to a `0600` socket, and the rename replaces what is
/// at `path` in one step instead of unlinking it first, so the address is never briefly
/// bound to nothing. A *live* server loses the name as readily as a dead one: callers own
/// their socket path, as they did when this unlinked it.
///
/// The directory holding `path` is resolved once, and everything else happens relative to
/// that descriptor — `mkdirat` to make the staging directory, `openat` to enter it, `rename`
/// out of it, `unlinkat` to take it back down. `mkdir`'s `0700` is what makes it private: a
/// umask can only clear bits, so the directory is never laxer, only sometimes stripped of
/// the owner bits it needs to be usable, which an anchored `chmod` puts back.
///
/// Two costs, both borne by the caller's path: it must live in a directory that admits a
/// subdirectory and not just a socket, and where that directory lets other users swap names
/// in it, the staging directory is left behind empty rather than removed by a name that may
/// no longer be this call's — see [`dir_admits_only_us`]. What is left is inert: the next
/// bind picks its own name and never one already standing, so leavings do not accumulate
/// into a bind that fails for a socket path that is free.
fn bind_private(path: &Path) -> Result<UnixListener, anyhow::Error> {
    bind_private_from(path, staging_names())
}

/// The staging names one bind will try, in order.
///
/// Nothing derived from the pid: a pid is reused — the agent is PID 1 in a fresh namespace
/// on every boot — so a name built from one lands on whatever the last process of that pid
/// left behind. Where those leavings are kept rather than removed (see
/// [`dir_admits_only_us`]) a fixed set of candidates is used up, and a bind fails for a
/// socket path nothing holds. A name picked instead from `/dev/urandom` collides with
/// neither, and costs nothing: what `bind` is called on is the `/proc/self/fd` anchor,
/// never this.
fn staging_names() -> impl FnMut() -> Result<String, anyhow::Error> {
    use std::io::Read;

    || {
        let mut bytes = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .context("reading /dev/urandom for a staging directory name")?;
        Ok(format!(
            ".{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }
}

/// [`bind_private`], with the staging names supplied so a test can arrange a collision.
fn bind_private_from(
    path: &Path,
    mut next_name: impl FnMut() -> Result<String, anyhow::Error>,
) -> Result<UnixListener, anyhow::Error> {
    let Some(final_name) = path.file_name() else {
        bail!("{path:?} is not a path a socket can be bound at");
    };
    // `bind` sees only the short `/proc/self/fd` anchor below, and `renameat` sees a descriptor
    // plus the final component, so neither validates the address clients are given. Reject a
    // spelling they cannot pass back to `connect` before publishing a socket through it.
    let len = path.as_os_str().len();
    if len >= SUN_PATH_MAX {
        bail!(
            "{path:?} is too long for a unix socket: it is {len} bytes and {SUN_PATH_MAX} is \
             the limit — bind it on a shorter path"
        );
    }
    let final_name = cstr(final_name)?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    // The one name this resolves. A symlink here is the caller's own arrangement — `/run`
    // for `/var/run` — so it is followed; everything after is relative to what it led to,
    // and no later step can be sent somewhere else by a change to any of these components.
    let parent_fd = open_dir(parent)?;
    let cleanable = dir_admits_only_us(parent_fd.as_fd());
    for _ in 0..STAGING_ATTEMPTS {
        let name = cstr(OsStr::new(&next_name()?))?;
        // SAFETY: both pointers are NUL-terminated and outlive the call.
        if unsafe { libc::mkdirat(parent_fd.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let e = std::io::Error::last_os_error();
            // Whatever holds this name, this call did not make it, so it is not this call's
            // to clear — deleting one to make room is how a name becomes someone's lever.
            // Take the next name instead.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(anyhow!(e).context(format!("creating a staging directory in {parent:?}")));
        }
        return publish_into(parent_fd.as_fd(), &name, &final_name, path, cleanable);
    }
    bail!("found no free staging name beside {path:?} in {STAGING_ATTEMPTS} tries")
}

/// Stage a `0600` socket in the directory `name` names under `parent_fd`, rename it onto
/// `final_name` there, and take the staging directory back down when `cleanable` says the
/// name is still this call's to act on.
fn publish_into(
    parent_fd: BorrowedFd<'_>,
    name: &CString,
    final_name: &CString,
    path: &Path,
    cleanable: bool,
) -> Result<UnixListener, anyhow::Error> {
    // Reached through `parent_fd`, and `O_NOFOLLOW` refuses a symlink left in place of the
    // directory just made. `O_PATH` because its mode may not permit an ordinary open: a wide
    // umask can strip the owner bits `mkdir` asked for, and this has to put them back.
    let staging = openat_dir(parent_fd, name);
    let remove_staging = || {
        if cleanable {
            // Cleanup is best-effort: failure leaves only the private, inert directory this
            // call made and cannot invalidate either the published listener or the primary
            // error being returned.
            // SAFETY: the pointer is NUL-terminated and outlives the call.
            let _ =
                unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        }
    };
    let staging = match staging {
        Ok(fd) => fd,
        Err(e) => {
            remove_staging();
            return Err(e);
        }
    };
    let anchor = PathBuf::from(format!("/proc/self/fd/{}", staging.as_raw_fd()));
    let staged = anchor.join("s");
    let published = std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700))
        .with_context(|| {
            format!(
                "accessing the staging directory for {path:?} through {anchor:?} (requires \
                 procfs mounted at /proc)"
            )
        })
        .and_then(|()| {
            let listener = UnixListener::bind(&staged)
                .with_context(|| format!("binding a staged socket for {path:?}"))?;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restricting the staged socket for {path:?} to 0600"))?;
            // SAFETY: all four arguments are live descriptors and NUL-terminated names.
            let rc = unsafe {
                libc::renameat(
                    staging.as_raw_fd(),
                    c"s".as_ptr(),
                    parent_fd.as_raw_fd(),
                    final_name.as_ptr(),
                )
            };
            if rc != 0 {
                return Err(anyhow!(std::io::Error::last_os_error())
                    .context(format!("publishing the socket at {path:?}")));
            }
            Ok(listener)
        });
    // A staged socket the rename never moved, unlinked through the staging descriptor so
    // nothing outside the directory this call made is ever named.
    // On success the rename already moved this name; on failure this is best-effort cleanup
    // that must not hide the more useful publication error.
    // SAFETY: the descriptor is live and the name is NUL-terminated.
    let _ = unsafe { libc::unlinkat(staging.as_raw_fd(), c"s".as_ptr(), 0) };
    remove_staging();
    published
}

/// Whether the directory `fd` refers to admits its entries being swapped by another user —
/// the question every removal by name turns on, since a name proves nothing about what it
/// leads to by the time it is used.
///
/// Two ways it cannot. No group or other write, so no one else may touch the names at all;
/// or the sticky bit, where an entry may only be removed or renamed by whoever made it. Both
/// need the directory itself to belong to this user or to root, since its owner is bound by
/// neither. `/run/<user>` is the first, `/tmp` the second. Anything else — a directory
/// shared with another user, or belonging to one — is answered `false`, and the staging
/// directory is then left in place rather than removed through a name that may have become
/// someone else's.
fn dir_admits_only_us(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: a zeroed `stat` is a valid destination, and `fd` is open for the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    // The *effective* id: it is what the kernel checks when this creates and removes.
    // SAFETY: `geteuid` reads this process's own id and cannot fail.
    let ours = unsafe { libc::geteuid() };
    let owned_by_us_or_root = st.st_uid == ours || st.st_uid == 0;
    owned_by_us_or_root
        && (st.st_mode & (libc::S_IWGRP | libc::S_IWOTH) == 0 || st.st_mode & libc::S_ISVTX != 0)
}

/// A path as a NUL-terminated string, for the `libc` calls that take one.
fn cstr(name: &OsStr) -> Result<CString, anyhow::Error> {
    CString::new(name.as_bytes()).with_context(|| format!("{name:?} has an interior NUL"))
}

/// Open a directory as an `O_PATH` descriptor: a location to resolve from, whose own mode
/// cannot refuse the open the way an `O_RDONLY` one would.
///
/// `O_PATH` cannot travel through `OpenOptions::custom_flags` on musl, which defines
/// `O_ACCMODE` as `03|O_SEARCH` with `O_SEARCH == O_PATH`: std masks custom flags with
/// `!O_ACCMODE`, dropping the bit, and what runs is an ordinary `O_RDONLY` open — the one
/// thing a directory missing its read bit refuses.
fn open_dir(dir: &Path) -> Result<OwnedFd, anyhow::Error> {
    let c_dir = cstr(dir.as_os_str())?;
    // SAFETY: the pointer is NUL-terminated and outlives the call; the descriptor it returns
    // is handed straight to `OwnedFd`, which closes it.
    let fd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(anyhow!(std::io::Error::last_os_error()).context(format!("opening {dir:?}")));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// [`open_dir`] for a name under an already-open directory, so the parent is not re-resolved.
fn openat_dir(parent: BorrowedFd<'_>, name: &CString) -> Result<OwnedFd, anyhow::Error> {
    // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())
            .context(format!("opening the staging directory {name:?}")));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Server side: bind (or receive from systemd) the listening sockets.
pub fn listen(socket: &SocketAddr) -> Result<Listeners, anyhow::Error> {
    match socket {
        SocketAddr::Systemd => listeners_from_systemd(),
        SocketAddr::Unix(path) => {
            let listener = bind_private(path)?;
            info!(
                "virtkit-agent: (pid={}) listening to {}",
                std::process::id(),
                path.display()
            );
            Ok(Listeners(vec![Listener::Unix(listener)]))
        }
        SocketAddr::Vsock { cid, port } => {
            let addr = VsockAddr::new(cid.unwrap_or(VMADDR_CID_ANY), *port);
            let listener =
                VsockListener::bind(addr).with_context(|| format!("binding vsock {addr:?}"))?;
            info!(
                "virtkit-agent: (pid={}) listening to vsock cid {} port {}",
                std::process::id(),
                addr.cid(),
                addr.port()
            );
            Ok(Listeners(vec![Listener::Vsock(listener)]))
        }
        SocketAddr::VsockMux { .. } | SocketAddr::VsockAuto { .. } => {
            bail!(
                "cannot listen on vsock-mux:// / vsock-auto:// (host side of the VMM, connect only)"
            )
        }
        SocketAddr::Tcp(_) => bail!("tcp:// is for `forward` only, not the virtkit-agent protocol"),
    }
}

/// Take every socket passed by systemd (LISTEN_FDS), unix or vsock.
fn listeners_from_systemd() -> Result<Listeners, anyhow::Error> {
    let mut listenfd = ListenFd::from_env();
    let mut listeners = Vec::new();
    for idx in 0..listenfd.len() {
        let Some(fd) = listenfd.take_raw_fd(idx)? else {
            continue;
        };
        listeners.push(listener_from_fd(fd)?);
    }
    if listeners.is_empty() {
        return Err(anyhow!("cannot get systemd listener"));
    }
    info!(
        "virtkit-agent: (pid={}) got {} listener(s) from systemd",
        std::process::id(),
        listeners.len()
    );
    Ok(Listeners(listeners))
}

fn listener_from_fd(fd: RawFd) -> Result<Listener, anyhow::Error> {
    match socket_family(fd)? {
        libc::AF_UNIX => {
            let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            listener.set_nonblocking(true)?;
            Ok(Listener::Unix(UnixListener::from_std(listener)?))
        }
        libc::AF_VSOCK => Ok(Listener::Vsock(unsafe { VsockListener::from_raw_fd(fd) })),
        family => bail!("unsupported socket family {family} from systemd"),
    }
}

fn socket_family(fd: RawFd) -> Result<i32, anyhow::Error> {
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe { libc::getsockname(fd, std::ptr::from_mut(&mut addr).cast(), &mut len) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(i32::from(addr.ss_family))
}

// ---- Raw (unframed) byte streams, for forwarding ----
//
// Everything above wraps each stream in the virtkit-agent MessagePack framing. A
// forward instead splices opaque bytes between a local listener and a target, so
// it can carry any protocol (a docker registry pull, ...). `RawConn` unifies the
// kinds so a single `tokio::io::copy_bidirectional` drives any pairing.

/// A raw, unframed connection of any supported transport.
pub enum RawConn {
    Tcp(TcpStream),
    Unix(UnixStream),
    Vsock(VsockStream),
}

impl AsyncRead for RawConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawConn::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            RawConn::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            RawConn::Vsock(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RawConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            RawConn::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            RawConn::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            RawConn::Vsock(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawConn::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            RawConn::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            RawConn::Vsock(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawConn::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            RawConn::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            RawConn::Vsock(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Resolve a `CmdConnect` target: a `SocketAddr` as-is, or — the one case
/// `SocketAddr::from_str` can't parse — a `tcp://host:port` whose host is a name
/// instead of an IP literal, resolved with this side's own DNS. `CmdConnect` carries
/// its target as a raw string precisely so a caller can name a host only the far
/// side's network (and DNS) can reach — a compose sibling's hostname, say — instead
/// of forcing every caller to resolve it themselves before ever reaching that
/// network. Only a `tcp://` target retries this way: any other scheme that fails to
/// parse has no hostname notion to fall back to, so its original error stands.
/// Every address a name resolves to is returned, in the order `lookup_host` gave
/// them, for [`raw_connect_any`] to dial in turn: a host with both an AAAA and an A
/// record commonly listens on only one of the two, and `localhost` on a dual-stack
/// box is the everyday case.
pub async fn resolve_connect_target(target: &str) -> Result<Vec<SocketAddr>, anyhow::Error> {
    let parse_err = match target.parse::<SocketAddr>() {
        Ok(addr) => return Ok(vec![addr]),
        Err(e) => e,
    };
    let (host, port) = match crate::addr::split_tcp_url(target) {
        Some(r) => r?,
        None => return Err(parse_err),
    };
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host:?}"))?
        .map(SocketAddr::Tcp)
        .collect();
    if resolved.is_empty() {
        return Err(anyhow!("{host:?} resolved to no addresses"));
    }
    Ok(resolved)
}

/// Open a raw stream to `target`: tcp, unix, vsock, or hybrid vsock-mux (the
/// CONNECT handshake runs, then the stream is raw). systemd:// is serve-only.
pub async fn raw_connect(target: &SocketAddr) -> Result<RawConn, anyhow::Error> {
    Ok(match target {
        SocketAddr::Tcp(addr) => RawConn::Tcp(
            TcpStream::connect(addr)
                .await
                .with_context(|| format!("connecting to {addr}"))?,
        ),
        SocketAddr::Unix(path) => RawConn::Unix(
            UnixStream::connect(path)
                .await
                .with_context(|| format!("connecting to {}", path.display()))?,
        ),
        SocketAddr::Vsock { cid, port } => {
            let addr = VsockAddr::new(cid.unwrap_or(VMADDR_CID_HOST), *port);
            RawConn::Vsock(
                VsockStream::connect(addr)
                    .await
                    .with_context(|| format!("connecting to vsock {addr:?}"))?,
            )
        }
        SocketAddr::VsockMux { path, port } => RawConn::Unix(connect_mux(path, *port).await?),
        SocketAddr::VsockAuto { path, port } => RawConn::Unix(connect_auto(path, *port).await?),
        SocketAddr::Systemd => bail!("cannot connect to systemd:// (serve only)"),
    })
}

/// Dial `targets` in order and return the first connection that is accepted, with
/// the address that accepted it; if none does, the failure of the last address
/// tried. A name commonly resolves to both an AAAA and an A record while the host
/// behind it listens on only one of the two, so stopping at the first address makes
/// such a target unreachable. Each attempt gets its own `CONNECT_TIMEOUT`: an
/// address that blackholes the SYN rather than refusing it would otherwise stall on
/// the OS retry schedule (~127s), and trying several in turn multiplies that wait.
pub async fn raw_connect_any(
    targets: &[SocketAddr],
) -> Result<(RawConn, &SocketAddr), anyhow::Error> {
    let mut last_err = None;
    for target in targets {
        let e = match tokio::time::timeout(CONNECT_TIMEOUT, raw_connect(target)).await {
            Ok(Ok(conn)) => return Ok((conn, target)),
            Ok(Err(e)) => e,
            Err(_) => anyhow!("timed out connecting to {target}"),
        };
        debug!("{e:#}");
        last_err = Some(e);
    }
    // only the last failure is reported: with every address of one name refusing for
    // its own reason, the resolver's order decides which is shown, and a list of them
    // reads worse than the one the caller most likely cares about
    Err(last_err.unwrap_or_else(|| anyhow!("no address to dial")))
}

/// The local side of a forward.
pub enum RawListener {
    Tcp(TcpListener),
    Unix(UnixListener),
    Vsock(VsockListener),
}

/// Bind a raw listener (tcp/unix/vsock) for a forward's local side. A stale unix
/// socket path is removed first — one owner per job. Unlike `bind_private` this
/// leaves the socket at whatever the ambient umask gives it: a forward's local side is
/// a user-chosen endpoint whose reach is the caller's to set (see `run_forward`'s
/// `chown`), not a private channel like the agent's.
pub async fn raw_listen(local: &SocketAddr) -> Result<RawListener, anyhow::Error> {
    Ok(match local {
        SocketAddr::Tcp(addr) => RawListener::Tcp(
            TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding {addr}"))?,
        ),
        SocketAddr::Unix(path) => {
            let _ = std::fs::remove_file(path);
            RawListener::Unix(
                UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?,
            )
        }
        SocketAddr::Vsock { cid, port } => {
            let addr = VsockAddr::new(cid.unwrap_or(VMADDR_CID_ANY), *port);
            RawListener::Vsock(
                VsockListener::bind(addr).with_context(|| format!("binding vsock {addr:?}"))?,
            )
        }
        SocketAddr::VsockMux { .. } | SocketAddr::VsockAuto { .. } => {
            bail!("cannot listen on vsock-mux:// / vsock-auto:// (connect only)")
        }
        SocketAddr::Systemd => bail!("raw_listen does not support systemd://"),
    })
}

impl RawListener {
    pub async fn accept(&self) -> std::io::Result<RawConn> {
        Ok(match self {
            RawListener::Tcp(l) => RawConn::Tcp(l.accept().await?.0),
            RawListener::Unix(l) => RawConn::Unix(l.accept().await?.0),
            RawListener::Vsock(l) => RawConn::Vsock(l.accept().await?.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-net-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Binding a socket must not change how *other* work in the process creates files.
    /// The umask is process-wide, so restricting the socket that way handed its mask to
    /// every concurrent writer: files and directories came out unreadable, and a directory
    /// without its execute bit takes everything under it with it.
    #[tokio::test]
    async fn binding_a_socket_leaves_other_writers_permissions_alone() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        // Rounds each side must complete *while the other is still going*, and a ceiling on
        // the bind loop so a writer that died takes the test down instead of hanging it.
        const ROUNDS: u64 = 200;
        const GIVE_UP: u64 = ROUNDS * 100;

        let dir = scratch("bind-umask");
        // What this process creates when nothing is interfering — a file and a directory,
        // each its own reference, since the two get different modes from the same umask.
        std::fs::write(dir.join("reference"), b"x").unwrap();
        std::fs::create_dir(dir.join("reference.d")).unwrap();
        // A dotted directory beside the socket that no bind made. Binding must step around
        // a name it cannot prove is its own, never clear one to make room for staging.
        std::fs::create_dir(dir.join(".decoy")).unwrap();
        std::fs::write(dir.join(".decoy/keep"), b"x").unwrap();
        let file_mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let want_file = file_mode(&dir.join("reference"));
        let want_dir = file_mode(&dir.join("reference.d"));

        // Each side runs until the other has also had its rounds. The barrier alone only
        // lines the two up: it does not stop one from running to completion before the other
        // has done a single iteration, which would pass the test having tested nothing.
        let writes = Arc::new(AtomicU64::new(0));
        let binding = Arc::new(AtomicBool::new(true));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let writer = std::thread::spawn({
            let (dir, binding, barrier) = (dir.clone(), binding.clone(), barrier.clone());
            let writes = writes.clone();
            move || {
                let mut wrong = Vec::new();
                barrier.wait();
                let mut i = 0u32;
                while binding.load(Ordering::Relaxed) {
                    let file = dir.join(format!("f{i}"));
                    std::fs::write(&file, b"x").unwrap();
                    if file_mode(&file) != want_file {
                        wrong.push((file.clone(), file_mode(&file)));
                    }
                    std::fs::remove_file(&file).unwrap();
                    let d = dir.join(format!("d{i}"));
                    std::fs::create_dir(&d).unwrap();
                    if file_mode(&d) != want_dir {
                        wrong.push((d.clone(), file_mode(&d)));
                    }
                    std::fs::remove_dir(&d).unwrap();
                    writes.fetch_add(1, Ordering::Relaxed);
                    i = i.wrapping_add(1);
                }
                wrong
            }
        });

        // Stops the writer however this returns: a panic in the bind loop below would
        // otherwise leave a detached thread churning the directory for the rest of the run.
        struct StopWriter(Arc<AtomicBool>);
        impl Drop for StopWriter {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let stop = StopWriter(binding.clone());

        barrier.wait();
        let mut binds = 0u64;
        while binds < ROUNDS || writes.load(Ordering::Relaxed) < ROUNDS {
            assert!(binds < GIVE_UP, "the writer thread stopped making progress");
            let path = dir.join(format!("s{binds}.sock"));
            // Dropped at once: the listener is not what is under test, and holding every one
            // of them open would push a modest RLIMIT_NOFILE.
            drop(listen(&SocketAddr::Unix(path.clone())).unwrap());
            // …and the socket itself is private, which is what the umask was there for.
            assert_eq!(
                file_mode(&path),
                0o600,
                "the socket must not be reachable by anyone else"
            );
            binds += 1;
        }
        drop(stop);
        let wrong = writer.join().unwrap();
        assert!(
            wrong.is_empty(),
            "binding changed how {} other file(s) were created, e.g. {:?}",
            wrong.len(),
            &wrong[..wrong.len().min(3)]
        );
        // The staging directory must not outlive the bind that made it, and the decoy must
        // outlive all of them. `failed_publication_removes_its_staging_directory` covers the
        // corresponding cleanup after a staged socket has been made but cannot be published.
        let mut dotted: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.as_encoded_bytes().starts_with(b"."))
            .collect();
        dotted.sort();
        assert_eq!(
            dotted,
            [".decoy"],
            "staging left behind, or the decoy cleared"
        );
        assert!(dir.join(".decoy/keep").exists(), "the decoy was emptied");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rename publishes over whatever is at the path, so a socket a previous server
    /// left behind is replaced — and replaced by one that is private in its own right.
    #[tokio::test]
    async fn binding_replaces_a_socket_already_at_the_path() {
        use std::os::unix::fs::MetadataExt;

        let dir = scratch("bind-replace");
        let path = dir.join("agent.sock");

        let first = listen(&SocketAddr::Unix(path.clone())).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        drop(first);

        let _second = listen(&SocketAddr::Unix(path.clone())).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_ne!(
            (before.dev(), before.ino()),
            (after.dev(), after.ino()),
            "the second bind must publish its own socket, not reuse the first"
        );
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
        UnixStream::connect(&path)
            .await
            .expect("the replacement must be the socket that is listening");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path too long to bind is reported as such, not as an error naming the internal
    /// path it would have been staged under.
    #[tokio::test]
    async fn binding_refuses_a_path_too_long_for_a_socket() {
        let dir = scratch("bind-too-long");
        let long = dir.join("z".repeat(SUN_PATH_MAX));

        let err = match listen(&SocketAddr::Unix(long.clone())) {
            Ok(_) => panic!(
                "{} must not bind: it is longer than sun_path",
                long.display()
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("too long for a unix socket") && err.contains(&SUN_PATH_MAX.to_string()),
            "unhelpful error for an over-long path: {err}"
        );
        assert!(
            !long.exists(),
            "nothing may be published for a refused bind"
        );

        // Staging costs the caller nothing now that it happens under `/proc/self/fd`: a name
        // that fits binds, however deep the directory holding it.
        let deep = dir.join("d".repeat(SUN_PATH_MAX - 3 - dir.as_os_str().len() - 1));
        std::fs::create_dir_all(&deep).unwrap();
        let barely = deep.join("s");
        assert_eq!(barely.as_os_str().len(), SUN_PATH_MAX - 1);
        drop(listen(&SocketAddr::Unix(barely.clone())).unwrap());
        assert_eq!(
            std::fs::metadata(&barely).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A staging name already taken is stepped over, never cleared: whatever holds it, this
    /// call did not make it, and what sits there may be a live bind's directory.
    #[tokio::test]
    async fn binding_steps_over_a_taken_staging_name() {
        let dir = scratch("bind-collide");
        let path = dir.join("agent.sock");
        // Occupy the first names the generator below will hand out, each holding a file so a
        // recursive delete would leave a mark.
        for n in 0..2u64 {
            let taken = dir.join(format!(".taken{n}"));
            std::fs::create_dir(&taken).unwrap();
            std::fs::write(taken.join("keep"), b"x").unwrap();
        }

        let mut handed_out = 0u64;
        let listener = bind_private_from(&path, || {
            let n = handed_out;
            handed_out += 1;
            Ok(format!(".taken{n}"))
        })
        .unwrap();
        drop(listener);

        assert_eq!(
            handed_out, 3,
            "each taken name must be tried, then stepped past"
        );
        for n in 0..2u64 {
            assert!(
                dir.join(format!(".taken{n}/keep")).exists(),
                "a staging name this call did not make was cleared"
            );
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !dir.join(".taken2").exists(),
            "the staging directory it did make must not outlive the bind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed rename must remove both the staged socket and the directory made for it,
    /// while leaving the entry that prevented publication untouched.
    #[tokio::test]
    async fn failed_publication_removes_its_staging_directory() {
        let dir = scratch("bind-publish-fail");
        let path = dir.join("occupied");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("keep"), b"x").unwrap();

        let err = bind_private_from(&path, || Ok(".staged".to_string())).unwrap_err();

        assert!(
            format!("{err:#}").contains("publishing the socket"),
            "unexpected publication error: {err:#}"
        );
        assert!(path.join("keep").exists(), "the destination was disturbed");
        assert!(
            !dir.join(".staged").exists(),
            "failed publication left its staging directory behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A umask wide enough to strip the owner bits off `mkdir`'s `0700` must not stop the
    /// listener. Set on the directory rather than through the process umask — which is the
    /// very thing this must not reach for, and would fail every test running beside it.
    #[tokio::test]
    async fn publishing_restores_owner_bits_a_wide_umask_stripped() {
        let dir = scratch("bind-stripped");
        let parent_fd = open_dir(&dir).unwrap();
        // What `mkdir(0700)` is left with under `umask 0400`, `0100` and `0700`: private
        // either way, since a umask only clears bits, but missing the read bit an
        // `O_RDONLY` open needs, the execute bit `bind` needs, or both.
        for mode in [0o300, 0o600, 0o000] {
            let path = dir.join(format!("agent{mode:o}.sock"));
            let name = cstr(OsStr::new(&format!(".stripped{mode:o}"))).unwrap();
            assert_eq!(
                unsafe { libc::mkdirat(parent_fd.as_raw_fd(), name.as_ptr(), mode) },
                0
            );
            let final_name = cstr(path.file_name().unwrap()).unwrap();

            drop(
                publish_into(parent_fd.as_fd(), &name, &final_name, &path, true)
                    .unwrap_or_else(|e| panic!("mode {mode:o} must still publish: {e:#}")),
            );

            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "the socket staged under mode {mode:o} must still be private"
            );
            assert!(
                !dir.join(format!(".stripped{mode:o}")).exists(),
                "the staging directory must not outlive the publish"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cleanup happens by name, and a name in a parent others may write is not this call's
    /// to act on by the time it would: the staging directory is left behind there instead.
    /// Empty, and — as `kept_staging_directories_do_not_exhaust_later_binds` holds — not in
    /// the way of the binds that follow, which never pick a name already standing.
    #[tokio::test]
    async fn a_shared_parent_keeps_its_staging_directory() {
        let dir = scratch("bind-shared-parent");
        let path = dir.join("agent.sock");
        // World-writable and not sticky: anyone could swap a name here between two calls.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        drop(listen(&SocketAddr::Unix(path.clone())).unwrap());

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the socket is private wherever it was staged"
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().as_encoded_bytes().starts_with(b"."))
            .collect();
        assert_eq!(
            left.len(),
            1,
            "expected one staging directory kept: {left:?}"
        );
        assert!(left[0].is_dir() && std::fs::read_dir(&left[0]).unwrap().next().is_none());

        // Sticky is the other way a name stays ours: only its maker may remove it.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        drop(listen(&SocketAddr::Unix(dir.join("sticky.sock"))).unwrap());
        let after = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".")
            })
            .count();
        assert_eq!(after, 1, "a sticky parent must clean up after itself");

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Staging directories a shared parent keeps must not use up the names a later bind can
    /// pick. One more bind here than there are candidates per bind: with a name built from
    /// the pid — fixed for the process, and identical again the next time that pid comes
    /// round — the last of these finds every candidate standing and fails for a socket path
    /// nothing holds.
    #[tokio::test]
    async fn kept_staging_directories_do_not_exhaust_later_binds() {
        let dir = scratch("bind-exhaust");
        let path = dir.join("agent.sock");
        // World-writable and not sticky, so every bind below keeps its staging directory.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        for attempt in 0..=STAGING_ATTEMPTS {
            drop(
                bind_private_from(&path, staging_names()).unwrap_or_else(|e| {
                    panic!("bind {attempt} must succeed beside what is kept: {e:#}")
                }),
            );
        }

        let kept: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().as_encoded_bytes().starts_with(b"."))
            .collect();
        assert_eq!(
            kept.len() as u32,
            STAGING_ATTEMPTS + 1,
            "each bind keeps one directory of its own: {kept:?}"
        );
        assert!(
            kept.iter()
                .all(|p| p.is_dir() && std::fs::read_dir(p).unwrap().next().is_none()),
            "what is kept must be empty: {kept:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/tmp` is the case an ownership test alone gets wrong: root owns it, yet its sticky
    /// bit means no other unprivileged user can remove or rename an entry made there. Left
    /// unrecognised, every bind under it strands a staging directory.
    #[tokio::test]
    async fn a_root_owned_sticky_directory_is_ours_to_clean() {
        use std::os::unix::fs::MetadataExt;

        let meta = std::fs::metadata("/tmp").unwrap();
        assert!(
            meta.uid() == 0 && meta.mode() & 0o1000 != 0,
            "this asserts against a stock root-owned sticky /tmp, found uid {} mode {:o}",
            meta.uid(),
            meta.mode() & 0o7777
        );
        assert!(
            dir_admits_only_us(open_dir(Path::new("/tmp")).unwrap().as_fd()),
            "a root-owned sticky directory keeps this process's entries its own"
        );

        // And end to end, in that same directory rather than wherever `TMPDIR` points: a
        // socket bound directly in `/tmp` strands nothing. Compared as a before-and-after
        // set, since a staging name is picked and not derived from anything to match on.
        let dotted = || -> std::collections::BTreeSet<std::ffi::OsString> {
            std::fs::read_dir("/tmp")
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name())
                .filter(|n| n.as_encoded_bytes().starts_with(b"."))
                .collect()
        };
        let path = Path::new("/tmp").join(format!("vk-net-sticky-{}.sock", std::process::id()));
        let before = dotted();
        drop(listen(&SocketAddr::Unix(path.clone())).unwrap());
        let left: Vec<_> = dotted().difference(&before).cloned().collect();
        assert!(left.is_empty(), "staging left behind in /tmp: {left:?}");
        let _ = std::fs::remove_file(&path);
    }

    /// vsock-auto prefers the dedicated per-port socket: the stream is raw (the
    /// listener sees the payload bytes, no CONNECT line) even though a mux-style
    /// listener also sits on the base path.
    #[tokio::test]
    async fn vsock_auto_prefers_the_per_port_socket() {
        let dir = scratch("auto-direct");
        let base = dir.join("vsock.sock");
        // decoy on the base path: if the client wrongly dials it, direct.accept()
        // below never returns and the test times out instead of passing
        let decoy = UnixListener::bind(&base).unwrap();
        let direct = UnixListener::bind(hybrid_socket(&base, 4444)).unwrap();
        let mut conn = connect_auto(&base, 4444).await.unwrap();
        conn.write_all(b"raw-bytes").await.unwrap();
        let (mut served, _) = direct.accept().await.unwrap();
        let mut buf = [0u8; 9];
        served.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"raw-bytes");
        drop(decoy);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a per-port socket, vsock-auto falls back to the CONNECT handshake
    /// on the base path — the Cloud Hypervisor form.
    #[tokio::test]
    async fn vsock_auto_falls_back_to_the_mux_handshake() {
        let dir = scratch("auto-mux");
        let base = dir.join("vsock.sock");
        let mux = UnixListener::bind(&base).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = mux.accept().await.unwrap();
            let mut line = Vec::new();
            loop {
                let b = s.read_u8().await.unwrap();
                if b == b'\n' {
                    break;
                }
                line.push(b);
            }
            assert_eq!(line, b"CONNECT 4444");
            s.write_all(b"OK 4444\n").await.unwrap();
            let mut buf = [0u8; 9];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"raw-bytes");
        });
        let mut conn = connect_auto(&base, 4444).await.unwrap();
        conn.write_all(b"raw-bytes").await.unwrap();
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn resolve_connect_target_passes_through_an_ip_literal() {
        let addrs = resolve_connect_target("tcp://127.0.0.1:4444")
            .await
            .unwrap();
        assert_eq!(addrs, vec!["tcp://127.0.0.1:4444".parse().unwrap()]);
    }

    #[tokio::test]
    async fn resolve_connect_target_resolves_a_hostname() {
        let addrs = resolve_connect_target("tcp://localhost:4444")
            .await
            .unwrap();
        // every address the name has, not just the first: on a dual-stack host that is
        // both ::1 and 127.0.0.1, and dropping either is what breaks a target listening
        // on only one of them
        assert!(!addrs.is_empty());
        let expected = tokio::net::lookup_host(("localhost", 4444)).await.unwrap();
        assert_eq!(addrs.len(), expected.count());
        for addr in &addrs {
            let SocketAddr::Tcp(resolved) = addr else {
                panic!("expected a resolved Tcp address, got {addr:?}");
            };
            assert_eq!(resolved.port(), 4444);
            assert!(resolved.ip().is_loopback());
        }
    }

    /// The point of the whole change: a name whose first address refuses still reaches
    /// the target behind its second one.
    #[tokio::test]
    async fn raw_connect_any_falls_back_to_a_later_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = SocketAddr::Tcp(listener.local_addr().unwrap());
        // port 1 on loopback: nothing binds it, and loopback refuses rather than
        // blackholing, so the first attempt fails fast instead of waiting the timeout
        let dead: SocketAddr = "tcp://127.0.0.1:1".parse().unwrap();

        let targets = [dead, live.clone()];
        let Ok((_conn, used)) = raw_connect_any(&targets).await else {
            panic!("expected the second address to accept");
        };
        assert_eq!(used, &live);
    }

    #[tokio::test]
    async fn raw_connect_any_reports_the_last_failure() {
        let dead: SocketAddr = "tcp://127.0.0.1:1".parse().unwrap();
        let deader: SocketAddr = "tcp://127.0.0.1:2".parse().unwrap();
        let Err(err) = raw_connect_any(&[dead, deader]).await else {
            panic!("expected both addresses to refuse");
        };
        assert!(
            format!("{err:#}").contains("127.0.0.1:2"),
            "expected the last address in the error, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn raw_connect_any_rejects_an_empty_list() {
        let Err(err) = raw_connect_any(&[]).await else {
            panic!("expected an empty list to fail");
        };
        assert!(
            format!("{err:#}").contains("no address to dial"),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn resolve_connect_target_keeps_a_non_tcp_scheme_error() {
        // vsock has no hostname notion to fall back to — the original parse error
        // (not a DNS failure) must surface.
        let err = resolve_connect_target("vsock://not-a-port")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("port"), "{err}");
    }

    #[tokio::test]
    async fn resolve_connect_target_rejects_an_unresolvable_host() {
        // `.invalid` never resolves (RFC 2606), so this is deterministic, not flaky —
        // it's the one test here that touches the network (DNS resolution failure).
        let err = resolve_connect_target("tcp://this-host-does-not-exist.invalid:4444")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("this-host-does-not-exist"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn resolve_connect_target_rejects_an_empty_host() {
        let err = resolve_connect_target("tcp://:4444").await.unwrap_err();
        assert!(err.to_string().contains("non-empty host"), "{err}");
    }
}
