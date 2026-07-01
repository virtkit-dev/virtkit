//! Guest-side tap NIC bridged to a host network backend over a raw stream.
//!
//! How a microVM joins the shared fleet LAN with no host privileges: a userspace
//! network backend (gvproxy today) runs unprivileged on the host and egresses
//! through ordinary host sockets; virtkit-agent — root in the guest, on a kernel we
//! control, where AppArmor's unprivileged-userns restriction does not apply —
//! owns a tap device and shuttles raw ethernet frames between it and the backend
//! over `--socket` (a vsock to the host).
//!
//! The wire framing is the "qemu" vhost-user protocol: each frame is a 4-byte
//! big-endian length prefix followed by the ethernet frame. The backend is
//! swappable behind this framing — a native Rust netstack could replace gvproxy
//! with no change here or in the guest. Addressing (IP/route/DNS) is deliberately
//! the caller's job, so the fleet's address policy lives outside the transport.

use anyhow::{Context, Result, bail};
use log::{debug, info};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::addr::SocketAddr;
use crate::net::{RawConn, raw_connect};

// tun/tap ioctl + flags (stable kernel ABI). Defined here rather than relying on
// libc's optional constants so the musl-static build needs nothing extra.
// `libc::Ioctl` is the ioctl request type — c_ulong on glibc, c_int on musl — so
// the request values (here and the SIOC* below) must be cast to it to build on
// both targets.
const TUNSETIFF: libc::Ioctl = 0x4004_54ca; // _IOW('T', 202, int)
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

/// A tap read/write never exceeds this (ethernet frame, jumbo included).
const MAX_FRAME: usize = 65535;

/// `struct ifreq` reduced to the fields we set (name + flags), padded to the
/// kernel struct's size so the ioctls read/write the right number of bytes.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

fn ifreq(name: &str) -> Result<IfReq> {
    if name.len() >= libc::IFNAMSIZ {
        bail!(
            "interface name {name:?} too long (max {})",
            libc::IFNAMSIZ - 1
        );
    }
    let mut req: IfReq = unsafe { std::mem::zeroed() };
    for (dst, b) in req.name.iter_mut().zip(name.as_bytes()) {
        *dst = *b as libc::c_char;
    }
    Ok(req)
}

/// Create tap `name` and return its non-blocking fd. The device is not persistent
/// — it vanishes when the fd closes, so virtkit-agent owns it for the VM's lifetime.
fn open_tap(name: &str) -> Result<OwnedFd> {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
    }
    // Owned from here so any early return closes it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = ifreq(name)?;
    req.flags = IFF_TAP | IFF_NO_PI;
    if unsafe { libc::ioctl(fd, TUNSETIFF, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF");
    }
    Ok(owned)
}

/// Bring `name` administratively up (SIOCSIFFLAGS | IFF_UP). Enabling the link is
/// transport, not address policy, so it belongs here; the IP/route/DNS do not.
fn set_up(name: &str) -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET)");
    }
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = ifreq(name)?;
    if unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCGIFFLAGS as libc::Ioctl,
            &raw mut req,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("SIOCGIFFLAGS");
    }
    req.flags |= libc::IFF_UP as libc::c_short;
    if unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCSIFFLAGS as libc::Ioctl,
            &raw mut req,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("SIOCSIFFLAGS");
    }
    Ok(())
}

/// Create tap `iface`, bring it up, and bridge it to the network backend reached
/// at `target` (qemu framing) until either side closes.
pub async fn run_net(target: &SocketAddr, iface: &str) -> Result<()> {
    let tap = open_tap(iface).with_context(|| format!("creating tap {iface}"))?;
    set_up(iface).with_context(|| format!("bringing {iface} up"))?;
    let conn = raw_connect(target)
        .await
        .with_context(|| format!("net: dialing backend {target}"))?;
    info!("net: tap {iface} up, bridging to {target} (qemu framing)");
    bridge(tap, conn).await
}

/// Splice tap frames to/from the backend connection with qemu length-prefix
/// framing. Returns when either direction ends.
async fn bridge(tap: OwnedFd, conn: RawConn) -> Result<()> {
    let tap = AsyncFd::new(tap)?;
    let (mut rd, mut wr) = tokio::io::split(conn);

    // tap -> backend: one ethernet frame becomes [BE32 len][frame].
    let up = async {
        let mut buf = vec![0u8; MAX_FRAME];
        loop {
            let n = read_frame(&tap, &mut buf).await?;
            if n == 0 {
                continue;
            }
            wr.write_all(&(n as u32).to_be_bytes()).await?;
            wr.write_all(&buf[..n]).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    // backend -> tap: read [BE32 len][frame], inject the frame into the tap.
    let down = async {
        let mut hdr = [0u8; 4];
        let mut buf = vec![0u8; MAX_FRAME];
        loop {
            rd.read_exact(&mut hdr).await?;
            let len = u32::from_be_bytes(hdr) as usize;
            if len > MAX_FRAME {
                bail!("backend frame length {len} exceeds {MAX_FRAME}");
            }
            rd.read_exact(&mut buf[..len]).await?;
            write_frame(&tap, &buf[..len]).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let r = tokio::select! {
        r = up => r,
        r = down => r,
    };
    debug!("net: bridge closed ({r:?})");
    r
}

/// Read one ethernet frame from the tap (async via readiness).
async fn read_frame(tap: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> Result<usize> {
    loop {
        let mut guard = tap.readable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(res) => return Ok(res?),
            Err(_would_block) => continue,
        }
    }
}

/// Inject one ethernet frame into the tap (async via readiness).
async fn write_frame(tap: &AsyncFd<OwnedFd>, frame: &[u8]) -> Result<()> {
    loop {
        let mut guard = tap.writable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::write(
                    inner.get_ref().as_raw_fd(),
                    frame.as_ptr().cast(),
                    frame.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(res) => {
                res?;
                return Ok(());
            }
            Err(_would_block) => continue,
        }
    }
}
