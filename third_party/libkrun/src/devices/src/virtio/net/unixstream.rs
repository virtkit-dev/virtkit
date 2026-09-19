use nix::sys::socket::{
    connect, getsockopt, recv, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use std::{
    os::fd::{AsRawFd, OwnedFd, RawFd},
    path::PathBuf,
};

use crate::virtio::net::backend::ConnectError;

use super::backend::{NetBackend, ReadError, WriteError};
use super::{write_virtio_net_hdr, MAX_BUFFER_SIZE, VNET_HDR_LEN};

/// Each frame the network proxy is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const FRAME_HEADER_LEN: usize = 4;

/// How much of the stream one recv takes in. Sized so a burst of MTU-sized frames arrives
/// in a single syscall instead of two (length, then payload) per frame.
const RX_BUFFER_SIZE: usize = 128 * 1024;

/// Read a payload this large directly when none of it is buffered, avoiding an extra copy.
const DIRECT_READ_MIN: usize = 8 * 1024;
const _: () = assert!(RX_BUFFER_SIZE >= MAX_BUFFER_SIZE);

pub struct Unixstream {
    fd: OwnedFd,
    // 0 when a frame length has not been read
    expecting_frame_length: u32,
    // 0 if last write is fully complete, otherwise the length that was written
    last_partial_write_length: usize,
    // bytes taken from the socket but not yet handed to the guest, in rx_buf[rx_start..rx_end]
    rx_buf: Vec<u8>,
    rx_start: usize,
    rx_end: usize,
}

impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: OwnedFd) -> Self {
        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Self {
            fd,
            expecting_frame_length: 0,
            last_partial_write_length: 0,
            rx_buf: vec![0u8; RX_BUFFER_SIZE],
            rx_start: 0,
            rx_end: 0,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self {
            fd,
            expecting_frame_length: 0,
            last_partial_write_length: 0,
            rx_buf: vec![0u8; RX_BUFFER_SIZE],
            rx_start: 0,
            rx_end: 0,
        })
    }

    /// Try to read until filling the whole slice.
    fn read_loop(&self, buf: &mut [u8], block_until_has_data: bool) -> Result<(), ReadError> {
        let mut bytes_read = 0;
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        if !block_until_has_data {
            match recv(self.fd.as_raw_fd(), buf, flags) {
                Ok(0) => return Err(ReadError::Internal(nix::Error::ECONNRESET)),
                Ok(size) => bytes_read += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    return Err(ReadError::NothingRead)
                }
                Err(e) => return Err(ReadError::Internal(e)),
            }
        }

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_WAITALL | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_WAITALL;

        while bytes_read < buf.len() {
            match recv(self.fd.as_raw_fd(), &mut buf[bytes_read..], flags) {
                Ok(0) => return Err(ReadError::Internal(nix::Error::ECONNRESET)),
                Err(nix::Error::EINTR) => continue,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    log::warn!("read_loop: unexpected EAGAIN/EWOULDBLOCK on blocking socket");
                    continue;
                }
                Err(e) => return Err(ReadError::Internal(e)),
                Ok(size) => {
                    bytes_read += size;
                    //log::trace!("proxy recv {}/{}", bytes_read, buf.len());
                }
            }
        }

        Ok(())
    }

    /// Bytes read from the socket and not yet handed on.
    fn buffered(&self) -> usize {
        self.rx_end - self.rx_start
    }

    /// Take the next `dst.len()` bytes of the stream. Short reads go through the read
    /// buffer, so one recv can serve several queued frames.
    fn read_buffered(&mut self, dst: &mut [u8]) -> Result<(), ReadError> {
        if self.buffered() == 0 && dst.len() >= DIRECT_READ_MIN {
            return self.read_loop(dst, false);
        }
        self.fill(dst.len())?;
        let end = self.rx_start + dst.len();
        dst.copy_from_slice(&self.rx_buf[self.rx_start..end]);
        self.rx_start = end;
        if self.rx_start == self.rx_end {
            self.rx_start = 0;
            self.rx_end = 0;
        }
        Ok(())
    }

    /// Hold at least `n` bytes without consuming them. An unavailable socket reports
    /// `NothingRead`; buffered bytes and the saved frame length remain valid for a retry.
    fn fill(&mut self, n: usize) -> Result<(), ReadError> {
        if self.buffered() >= n {
            return Ok(());
        }
        if self.rx_buf.len() - self.rx_start < n {
            self.rx_buf.copy_within(self.rx_start..self.rx_end, 0);
            self.rx_end -= self.rx_start;
            self.rx_start = 0;
        }

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        // Pick up additional queued bytes, up to the available buffer space, rather than
        // one syscall per frame later.
        match recv(self.fd.as_raw_fd(), &mut self.rx_buf[self.rx_end..], flags) {
            Ok(0) => return Err(ReadError::Internal(nix::Error::ECONNRESET)),
            Ok(size) => self.rx_end += size,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) if self.buffered() == 0 => {
                return Err(ReadError::NothingRead)
            }
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {}
            Err(e) => return Err(ReadError::Internal(e)),
        }

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_WAITALL | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_WAITALL;

        // The frame has begun to arrive, so wait for the rest of it.
        while self.buffered() < n {
            let want = self.rx_start + n;
            match recv(
                self.fd.as_raw_fd(),
                &mut self.rx_buf[self.rx_end..want],
                flags,
            ) {
                Ok(0) => return Err(ReadError::Internal(nix::Error::ECONNRESET)),
                Err(nix::Error::EINTR) => continue,
                Ok(size) => self.rx_end += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    log::warn!("fill: unexpected EAGAIN/EWOULDBLOCK on blocking socket");
                    continue;
                }
                Err(e) => return Err(ReadError::Internal(e)),
            }
        }

        Ok(())
    }

    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut bytes_send = 0;

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        while bytes_send < buf.len() {
            match send(self.fd.as_raw_fd(), &buf[bytes_send..], flags) {
                Ok(size) => bytes_send += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    if bytes_send == 0 {
                        return Err(WriteError::NothingWritten);
                    } else {
                        log::trace!(
                            "Wrote {bytes_send} bytes, but socket blocked, will need try_finish_write() to finish"
                        );

                        self.last_partial_write_length += bytes_send;
                        return Err(WriteError::PartialWrite);
                    }
                }
                Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        self.last_partial_write_length = 0;
        Ok(())
    }
}

impl NetBackend for Unixstream {
    /// Try to read a frame from the proxy. If no bytes are available reports ReadError::NothingRead
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.expecting_frame_length == 0 {
            self.expecting_frame_length = {
                let mut frame_length_buf = [0u8; FRAME_HEADER_LEN];
                self.read_buffered(&mut frame_length_buf)?;
                u32::from_be_bytes(frame_length_buf)
            };
        }

        let frame_length = self.expecting_frame_length as usize;
        if buf.len() < VNET_HDR_LEN
            || frame_length > buf.len() - VNET_HDR_LEN
            || frame_length > MAX_BUFFER_SIZE - VNET_HDR_LEN
        {
            return Err(ReadError::Internal(nix::Error::EINVAL));
        }
        let hdr_len = write_virtio_net_hdr(buf);
        let buf = &mut buf[hdr_len..];
        self.read_buffered(&mut buf[..frame_length])?;
        self.expecting_frame_length = 0;
        log::trace!("Read eth frame from network proxy: {frame_length} bytes");
        Ok(hdr_len + frame_length)
    }

    /// Try to write a frame to the proxy.
    /// (Will mutate and override parts of buf, with a frame header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///   (such as vnet header), that can be overwritten. Must be >= FRAME_HEADER_LEN.
    /// * `buf` - the buffer to write to the proxy, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            panic!("Cannot write a frame to the proxy, while a partial write is not resolved.");
        }
        assert!(
            hdr_len >= FRAME_HEADER_LEN,
            "Not enough space to write the frame header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - FRAME_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());

        self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN..])?;
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length != 0
    }

    /// Try to finish a partial write
    ///
    /// If no partial write is required will do nothing and return Ok(())
    ///
    /// * `hdr_len` - must be the same value as passed to write_frame, that caused the partial write
    /// * `buf` - must be same buffer that was given to write_frame, that caused the partial write
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            let already_written = self.last_partial_write_length;
            log::trace!("Requested to finish partial write");
            self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN + already_written..])?;
            log::debug!("Finished partial write ({already_written}bytes written before)")
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    fn pair() -> (Unixstream, UnixStream) {
        let (reader, writer) = UnixStream::pair().unwrap();
        (Unixstream::new(reader.into()), writer)
    }

    fn framed(frames: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for frame in frames {
            bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            bytes.extend_from_slice(frame);
        }
        bytes
    }

    fn frame(reader: &mut Unixstream) -> Result<Vec<u8>, ReadError> {
        let mut buf = vec![0; MAX_BUFFER_SIZE];
        let n = reader.read_frame(&mut buf)?;
        Ok(buf[VNET_HDR_LEN..n].to_vec())
    }

    #[test]
    fn queued_frames_share_a_refill_and_survive_the_peer_closing() {
        let (mut reader, mut writer) = pair();
        let frames: [&[u8]; 3] = [b"one", b"second frame", b"three"];
        let wire = framed(&frames);
        writer.write_all(&wire).unwrap();
        assert_eq!(frame(&mut reader).unwrap(), frames[0]);
        assert_eq!(
            reader.buffered(),
            wire.len() - FRAME_HEADER_LEN - frames[0].len()
        );
        drop(writer);
        for expected in &frames[1..] {
            assert_eq!(frame(&mut reader).unwrap(), *expected);
        }
        assert!(matches!(
            frame(&mut reader),
            Err(ReadError::Internal(nix::Error::ECONNRESET))
        ));
    }

    #[test]
    fn a_payload_retry_keeps_the_consumed_length() {
        for size in [32, DIRECT_READ_MIN] {
            let (mut reader, mut writer) = pair();
            writer.write_all(&(size as u32).to_be_bytes()).unwrap();
            assert!(matches!(frame(&mut reader), Err(ReadError::NothingRead)));
            assert_eq!(reader.expecting_frame_length as usize, size);
            let body = vec![0x5a; size];
            writer.write_all(&body).unwrap();
            assert_eq!(frame(&mut reader).unwrap(), body);
        }
    }

    #[test]
    fn fragmented_headers_and_payloads_keep_the_frame_boundary() {
        let wire = framed(&[b"first frame", b"next"]);
        for split in [1, 3, 6] {
            let (mut reader, mut writer) = pair();
            // Model a short socket read already held in the buffer.
            reader.rx_buf[..split].copy_from_slice(&wire[..split]);
            reader.rx_end = split;
            writer.write_all(&wire[split..]).unwrap();
            assert_eq!(frame(&mut reader).unwrap(), b"first frame");
            assert_eq!(frame(&mut reader).unwrap(), b"next");
        }
    }

    #[test]
    fn a_partial_payload_at_the_end_of_scratch_is_compacted() {
        let (mut reader, mut writer) = pair();
        let body = vec![0xa5; 32];
        let wire = framed(&[&body]);
        reader.rx_start = RX_BUFFER_SIZE - 6;
        reader.rx_end = RX_BUFFER_SIZE;
        reader.rx_buf[reader.rx_start..].copy_from_slice(&wire[..6]);
        writer.write_all(&wire[6..]).unwrap();
        assert_eq!(frame(&mut reader).unwrap(), body);
        assert_eq!(reader.buffered(), 0);
    }

    #[test]
    fn large_frames_and_the_following_frame_arrive_intact() {
        let (mut reader, mut writer) = pair();
        let body: Vec<u8> = (0..MAX_BUFFER_SIZE - VNET_HDR_LEN)
            .map(|i| i as u8)
            .collect();
        let wire = framed(&[&body, b"tail"]);
        let send = std::thread::spawn(move || writer.write_all(&wire).unwrap());
        for expected in [body.as_slice(), b"tail"] {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let received = loop {
                match frame(&mut reader) {
                    Err(ReadError::NothingRead) => {
                        assert!(std::time::Instant::now() < deadline);
                        std::thread::yield_now();
                    }
                    result => break result.unwrap(),
                }
            };
            assert_eq!(received, expected);
        }
        send.join().unwrap();
    }

    #[test]
    fn invalid_lengths_and_short_destinations_are_errors() {
        for size in [MAX_BUFFER_SIZE as u32, u32::MAX] {
            let (mut reader, mut writer) = pair();
            writer.write_all(&size.to_be_bytes()).unwrap();
            assert!(matches!(
                frame(&mut reader),
                Err(ReadError::Internal(nix::Error::EINVAL))
            ));
        }
        let (mut reader, mut writer) = pair();
        writer.write_all(&framed(&[b"one"])).unwrap();
        assert!(matches!(
            reader.read_frame(&mut [0; 4]),
            Err(ReadError::Internal(nix::Error::EINVAL))
        ));
    }

    #[test]
    fn eof_in_headers_buffered_payloads_and_direct_payloads_returns() {
        for size in [32usize, DIRECT_READ_MIN] {
            for prefix in [0, 1, FRAME_HEADER_LEN, FRAME_HEADER_LEN + 1] {
                let (mut reader, mut writer) = pair();
                let wire = framed(&[&vec![0x5a; size]]);
                if prefix >= FRAME_HEADER_LEN {
                    writer.write_all(&wire[..FRAME_HEADER_LEN]).unwrap();
                    assert!(matches!(frame(&mut reader), Err(ReadError::NothingRead)));
                    writer.write_all(&wire[FRAME_HEADER_LEN..prefix]).unwrap();
                } else {
                    writer.write_all(&wire[..prefix]).unwrap();
                }
                drop(writer);
                // A regression in the direct read loop must fail instead of hanging the suite.
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || tx.send(frame(&mut reader)).unwrap());
                assert!(matches!(
                    rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap(),
                    Err(ReadError::Internal(nix::Error::ECONNRESET))
                ));
            }
        }
    }
}
