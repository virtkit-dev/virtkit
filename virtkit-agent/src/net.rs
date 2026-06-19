use crate::addr::SocketAddr;
use crate::framing::{DeSink, SerStream, wrap_stream};
use anyhow::{Context, anyhow, bail};
use listenfd::ListenFd;
use log::{debug, info};
use std::os::fd::RawFd;
use std::os::unix::prelude::{FromRawFd, PermissionsExt};
use std::path::Path;
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
        SocketAddr::Tcp(_) => bail!("tcp:// is for `forward` only, not the virtkit-agent protocol"),
    }
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

/// Server side: bind (or receive from systemd) the listening sockets.
pub fn listen(socket: &SocketAddr) -> Result<Listeners, anyhow::Error> {
    match socket {
        SocketAddr::Systemd => listeners_from_systemd(),
        SocketAddr::Unix(path) => {
            let _ = std::fs::remove_file(path);
            // umask so the socket is 0600 from birth — chmod after bind() leaves a
            // window with umask-default permissions (process-wide, but listen() runs
            // before any other task can create files)
            let prev_umask = unsafe { libc::umask(0o177) };
            let listener = UnixListener::bind(path);
            unsafe { libc::umask(prev_umask) };
            let listener = listener?;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
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
        SocketAddr::VsockMux { .. } => {
            bail!("cannot listen on vsock-mux:// (host side of the VMM, connect only)")
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
        SocketAddr::Systemd => bail!("cannot connect to systemd:// (serve only)"),
    })
}

/// The local side of a forward.
pub enum RawListener {
    Tcp(TcpListener),
    Unix(UnixListener),
    Vsock(VsockListener),
}

/// Bind a raw listener (tcp/unix/vsock) for a forward's local side. A stale unix
/// socket path is removed first — one owner per job.
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
        SocketAddr::VsockMux { .. } => bail!("cannot listen on vsock-mux:// (connect only)"),
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
