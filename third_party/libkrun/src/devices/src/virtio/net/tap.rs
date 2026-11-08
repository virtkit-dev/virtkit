use libc::{
    IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUN_F_UFO, c_char, c_int,
    ifreq,
};
use nix::fcntl::{FcntlArg, OFlag, fcntl, open};
use nix::sys::stat::Mode;
use nix::unistd::{read, write};
use nix::{ioctl_write_int, ioctl_write_ptr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::{io, mem, ptr};
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO,
};

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
ioctl_write_int!(tunsetoffload, b'T', 208);
ioctl_write_ptr!(tunsetvnethdrsz, b'T', 216, c_int);

pub struct Tap {
    fd: Arc<OwnedFd>,
    /// The driver negotiated `VIRTIO_NET_F_CSUM`, which every transmit offload depends on.
    /// Without it the guest's transmit header carries no meaning; see `write_frame`.
    tx_offloads: bool,
}

impl Tap {
    /// Create an endpoint using the file descriptor of a tap device
    pub fn new(tap_name: String, vnet_features: u64) -> Result<Self, ConnectError> {
        let fd = match open("/dev/net/tun", OFlag::O_RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(err) => return Err(ConnectError::OpenNetTun(err)),
        };

        let mut req: ifreq = unsafe { mem::zeroed() };

        unsafe {
            ptr::copy_nonoverlapping(
                tap_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tap_name.len(),
            );
        }

        req.ifr_ifru.ifru_flags = IFF_TAP as i16 | IFF_NO_PI as i16 | IFF_VNET_HDR as i16;

        unsafe {
            if let Err(err) = tunsetiff(fd.as_raw_fd(), &mut req as *mut _ as *mut _) {
                return Err(ConnectError::TunSetIff(io::Error::from(err)));
            }
        }
        Self::from_fd(Arc::new(fd), vnet_features)
    }

    /// Configure a tap already attached by the caller. Keeping the same open description
    /// prevents another VM from claiming the queue between validation and activation.
    pub fn from_fd(fd: Arc<OwnedFd>, vnet_features: u64) -> Result<Self, ConnectError> {
        unsafe {
            // TODO(slp): replace hardcoded vnet size with cons
            if let Err(err) = tunsetvnethdrsz(fd.as_raw_fd(), &12) {
                return Err(ConnectError::TunSetVnetHdrSz(io::Error::from(err)));
            }
        }
        set_offloads(&fd, vnet_features)?;

        match fcntl(fd.as_ref(), FcntlArg::F_GETFL) {
            Ok(flags) => {
                if let Err(e) = fcntl(
                    fd.as_ref(),
                    FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
                ) {
                    warn!("error switching to non-blocking: id={fd:?}, err={e}");
                }
            }
            Err(e) => error!("couldn't obtain fd flags id={fd:?}, err={e}"),
        };

        Ok(Self {
            fd,
            tx_offloads: tx_offloads(vnet_features),
        })
    }
}

fn tx_offloads(vnet_features: u64) -> bool {
    vnet_features & (1 << VIRTIO_NET_F_CSUM) != 0
}

/// Tell the tap which offloads the driver accepts, so it hands the guest only frames the
/// driver negotiated.
fn set_offloads(fd: &OwnedFd, vnet_features: u64) -> Result<(), ConnectError> {
    let mut offload_flags: u64 = 0;
    if (vnet_features & (1 << VIRTIO_NET_F_GUEST_CSUM)) != 0 {
        offload_flags |= TUN_F_CSUM as u64;
    }
    if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO4)) != 0 {
        offload_flags |= TUN_F_TSO4 as u64;
    }
    if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO6)) != 0 {
        offload_flags |= TUN_F_TSO6 as u64;
    }
    if (vnet_features & (1 << VIRTIO_NET_F_GUEST_UFO)) != 0 {
        offload_flags |= TUN_F_UFO as u64;
    }
    unsafe {
        if let Err(err) = tunsetoffload(fd.as_raw_fd(), offload_flags) {
            return Err(ConnectError::TunSetOffload(io::Error::from(err)));
        }
    }
    Ok(())
}

impl NetBackend for Tap {
    fn set_vnet_features(&mut self, vnet_features: u64) -> Result<(), ConnectError> {
        set_offloads(&self.fd, vnet_features)?;
        self.tx_offloads = tx_offloads(vnet_features);
        Ok(())
    }

    /// Try to read a frame from the tap devie. If no bytes are available reports
    /// ReadError::NothingRead.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let frame_length = match read(self.fd.as_ref(), buf) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead);
            }
            Err(e) => {
                return Err(ReadError::Internal(e));
            }
        };
        debug!("Read eth frame from tap: {frame_length} bytes");
        Ok(frame_length)
    }

    /// Try to write a frame to the tap device.
    ///
    /// Without negotiated transmit offloads the guest's virtio-net header is zeroed: the
    /// kernel would otherwise trust its checksum and GSO fields, and malformed ones reach
    /// host-kernel bugs (such as the IPv4 fragmentation read fixed by Linux 6785011f8b16).
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if !self.tx_offloads {
            let end = hdr_len.min(buf.len());
            buf[..end].fill(0);
        }
        let ret = write(self.fd.as_ref(), buf).map_err(WriteError::Internal)?;
        debug!("Written frame size={}, written={}", buf.len(), ret);
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn flush_frames(&mut self) -> Result<(), WriteError> {
        // The tap backend writes every frame whole and holds none back.
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::net::VNET_HDR_LEN;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

    /// A frame whose header asks for a partial checksum, as a hostile guest could send.
    fn hostile_frame() -> Vec<u8> {
        let mut frame = vec![0xa5u8; VNET_HDR_LEN + 64];
        frame[0] = 1; // VIRTIO_NET_HDR_F_NEEDS_CSUM
        frame
    }

    fn written(tx_offloads: bool) -> Vec<u8> {
        let (ours, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let mut tap = Tap {
            fd: Arc::new(ours),
            tx_offloads,
        };
        let mut frame = hostile_frame();
        tap.write_frame(VNET_HDR_LEN, &mut frame).unwrap();
        let mut out = vec![0u8; frame.len() + 1];
        let n = read(&peer, &mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn header_is_cleared_without_tx_offloads() {
        let out = written(false);
        assert!(out[..VNET_HDR_LEN].iter().all(|&b| b == 0));
        assert_eq!(out[VNET_HDR_LEN..], hostile_frame()[VNET_HDR_LEN..]);
    }

    #[test]
    fn header_is_kept_with_tx_offloads() {
        assert_eq!(written(true), hostile_frame());
    }

    #[test]
    fn tx_offloads_follow_csum() {
        assert!(!tx_offloads(0));
        assert!(tx_offloads(1 << VIRTIO_NET_F_CSUM));
    }
}
