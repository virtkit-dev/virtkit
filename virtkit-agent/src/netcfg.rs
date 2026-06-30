//! Configure the guest's network with kernel ioctls instead of shelling out to
//! `ip`/`ifconfig`/`route` — those live in iproute2/net-tools, which busybox guests
//! have but minimal glibc images (e.g. `debian:*-slim`) do not. Without them such a
//! guest came up with an `eth0` link but no address, no default route and `lo` down,
//! so glibc's resolver could not even send a query. These set the same state over the
//! stable ioctl ABI, so any guest gets a working network.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, bail};

const IFNAMSIZ: usize = libc::IFNAMSIZ;

// `struct ifreq` is 40 bytes on Linux (name + a 24-byte union); we use two views of
// it — one carrying flags, one carrying an address — each padded to that size.
#[repr(C)]
struct IfReqFlags {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

#[repr(C)]
struct IfReqAddr {
    name: [libc::c_char; IFNAMSIZ],
    addr: libc::sockaddr_in,
    _pad: [u8; 8],
}

fn name_buf(name: &str) -> Result<[libc::c_char; IFNAMSIZ]> {
    if name.len() >= IFNAMSIZ {
        bail!("interface name {name:?} too long (max {})", IFNAMSIZ - 1);
    }
    let mut buf = [0 as libc::c_char; IFNAMSIZ];
    for (dst, b) in buf.iter_mut().zip(name.as_bytes()) {
        *dst = *b as libc::c_char;
    }
    Ok(buf)
}

fn inet_socket() -> Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket(AF_INET)");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn sockaddr_in(ip: Ipv4Addr) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    // s_addr is in network (big-endian) byte order.
    sa.sin_addr.s_addr = u32::from(ip).to_be();
    sa
}

/// `prefix` (e.g. 24) -> the IPv4 netmask (255.255.255.0).
fn mask_from_prefix(prefix: u32) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - prefix.min(32)))
    }
}

/// Bring interface `name` administratively up (SIOCGIFFLAGS | IFF_UP, SIOCSIFFLAGS).
pub fn set_up(name: &str) -> Result<()> {
    let sock = inet_socket()?;
    let mut req = IfReqFlags {
        name: name_buf(name)?,
        flags: 0,
        _pad: [0; 22],
    };
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS as _, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCGIFFLAGS");
    }
    req.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCSIFFLAGS");
    }
    Ok(())
}

/// Assign `ip`/`prefix` to `name` and bring it up (SIOCSIFADDR + SIOCSIFNETMASK).
pub fn set_addr(name: &str, ip: Ipv4Addr, prefix: u32) -> Result<()> {
    let sock = inet_socket()?;
    let mut req = IfReqAddr {
        name: name_buf(name)?,
        addr: sockaddr_in(ip),
        _pad: [0; 8],
    };
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR as _, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCSIFADDR");
    }
    req.addr = sockaddr_in(mask_from_prefix(prefix));
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK as _, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCSIFNETMASK");
    }
    set_up(name)
}

/// Add a default route via `gw` (SIOCADDRT with an all-zero destination/genmask).
pub fn add_default_route(gw: Ipv4Addr) -> Result<()> {
    let sock = inet_socket()?;
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    // dst 0.0.0.0/0 via gw; the sockaddr fields are generic sockaddr, but a
    // sockaddr_in is layout-compatible for AF_INET (same 16 bytes).
    let store = |dst: &mut libc::sockaddr, ip: Ipv4Addr| {
        let sa = sockaddr_in(ip);
        unsafe {
            std::ptr::copy_nonoverlapping((&raw const sa).cast::<libc::sockaddr>(), dst, 1);
        }
    };
    store(&mut rt.rt_dst, Ipv4Addr::UNSPECIFIED);
    store(&mut rt.rt_genmask, Ipv4Addr::UNSPECIFIED);
    store(&mut rt.rt_gateway, gw);
    rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as _;
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCADDRT as _, &raw const rt) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCADDRT");
    }
    Ok(())
}
