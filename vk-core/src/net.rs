use crate::addr::SocketAddr;
use crate::framing::{DeSink, SerStream, wrap_stream};
use anyhow::{Context, anyhow, bail};
use listenfd::ListenFd;
use log::{debug, info};
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
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

/// Stable, locally-administered unicast MAC for a run-assigned guest IPv4 address:
/// `52:54:00:<octet2>:<octet3>:<octet4>`. The prefix follows the QEMU convention; the
/// low three IPv4 octets distinguish every address in subnets up to a /8.
///
/// The host keys the switch's DHCP reservation on this MAC, and the guest assigns it to
/// the NIC's tap.
pub fn mac_for_ip(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("52:54:00:{:02x}:{:02x}:{:02x}", o[1], o[2], o[3])
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

/// Bind the agent's exec socket privately.
///
/// [`vk_fs::bind_private`] returns a blocking listener. Convert it here to keep `vk-fs`
/// runtime-free and reusable by `vk-registry`, whose bind path is also synchronous.
fn bind_private(path: &Path) -> Result<UnixListener, anyhow::Error> {
    let listener = vk_fs::bind_private(path)?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("making {} non-blocking", path.display()))?;
    UnixListener::from_std(listener).with_context(|| format!("registering {}", path.display()))
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

    /// Return the bound socket's descriptor for transfer across fork/exec.
    ///
    /// The socket remains bound and listening throughout the transfer.
    pub fn as_raw_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        match self {
            RawListener::Tcp(l) => l.as_raw_fd(),
            RawListener::Unix(l) => l.as_raw_fd(),
            RawListener::Vsock(l) => l.as_raw_fd(),
        }
    }

    /// Adopt a listening descriptor inherited from a parent process.
    ///
    /// `bound` selects the socket type because the descriptor has no variant label.
    /// [`OwnedFd`] transfers ownership on success and error, avoiding an ambiguous cleanup
    /// contract and possible double-close. The caller must verify that the descriptor is a
    /// listening socket of the expected family.
    pub fn adopt(bound: &SocketAddr, fd: OwnedFd) -> Result<Self, anyhow::Error> {
        Ok(match bound {
            SocketAddr::Tcp(_) => {
                let l = std::net::TcpListener::from(fd);
                l.set_nonblocking(true).context("adopted tcp listener")?;
                RawListener::Tcp(TcpListener::from_std(l)?)
            }
            SocketAddr::Unix(_) => {
                let l = std::os::unix::net::UnixListener::from(fd);
                l.set_nonblocking(true).context("adopted unix listener")?;
                RawListener::Unix(UnixListener::from_std(l)?)
            }
            other => bail!("cannot adopt an inherited listener for {other}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The MAC contains the QEMU-style prefix and low three IPv4 octets.
    #[test]
    fn mac_carries_the_low_three_ipv4_octets() {
        assert_eq!(
            mac_for_ip(Ipv4Addr::new(192, 168, 127, 2)),
            "52:54:00:a8:7f:02"
        );
        assert_eq!(
            mac_for_ip(Ipv4Addr::new(192, 168, 127, 254)),
            "52:54:00:a8:7f:fe"
        );
        assert_ne!(
            mac_for_ip(Ipv4Addr::new(192, 168, 127, 3)),
            mac_for_ip(Ipv4Addr::new(192, 168, 127, 4))
        );
        assert_ne!(
            mac_for_ip(Ipv4Addr::new(192, 168, 127, 2)),
            mac_for_ip(Ipv4Addr::new(192, 168, 128, 2))
        );
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-net-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `dup` stands in for fork: the address remains bound while ownership changes.
    #[tokio::test]
    async fn an_inherited_listener_is_adopted_still_bound() {
        let listener = raw_listen(&"tcp://127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let RawListener::Tcp(ref l) = listener else {
            panic!("expected a tcp listener")
        };
        let bound: SocketAddr = format!("tcp://{}", l.local_addr().unwrap())
            .parse()
            .unwrap();
        // SAFETY: dup returns a new descriptor for the same listening socket.
        let dup = unsafe { libc::dup(listener.as_raw_fd()) };
        assert!(dup >= 0, "dup: {}", std::io::Error::last_os_error());
        drop(listener);

        // SAFETY: `dup` is a fresh descriptor that nothing else owns.
        let dup = unsafe { OwnedFd::from_raw_fd(dup) };
        let adopted = RawListener::adopt(&bound, dup).unwrap();
        let client = tokio::spawn(async move { raw_connect(&bound).await });
        adopted
            .accept()
            .await
            .expect("the adopted listener accepts");
        client.await.unwrap().expect("the address stayed bound");
    }

    /// Reject vsock because `bound` is the only available socket-type label.
    #[test]
    fn adopting_refuses_an_address_it_cannot_label() {
        // SAFETY: `adopt` rejects the address without using the owned descriptor, then
        // closes it normally.
        let fd = std::fs::File::open("/dev/null").unwrap().into();
        let Err(err) = RawListener::adopt(&"vsock://443".parse().unwrap(), fd) else {
            panic!("a vsock address must not be adoptable");
        };
        assert!(format!("{err:#}").contains("cannot adopt"), "{err:#}");
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
        // outlive all of them. vk-fs's `failed_publication_removes_its_staging_directory`
        // covers the cleanup after a staged socket is made but cannot be published.
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
