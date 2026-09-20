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

/// How many staged bytes one send carries. Guest frames are staged back to back and leave
/// together, so a burst costs one syscall instead of one per frame.
const TX_BATCH_SIZE: usize = 256 * 1024;

/// How many staged frames one send carries. Bounds how much copying a burst of small frames
/// does before any of it reaches the switch.
const TX_BATCH_FRAMES: usize = 256;

/// Send a frame this large straight from the caller's buffer when nothing is staged: past
/// this size copying it into the staging buffer costs about as much as the send it saves.
const TX_DIRECT_MIN: usize = 16 * 1024;

/// The staging buffer holds a whole batch plus the frame that takes it past the bound, so
/// staging a frame never has to wait for the socket.
const TX_BUFFER_SIZE: usize = TX_BATCH_SIZE + MAX_BUFFER_SIZE;

pub struct Unixstream {
    fd: OwnedFd,
    // 0 when a frame length has not been read
    expecting_frame_length: u32,
    // bytes taken from the socket but not yet handed to the guest, in rx_buf[rx_start..rx_end]
    rx_buf: Vec<u8>,
    rx_start: usize,
    rx_end: usize,
    // length-prefixed frames staged for the socket but not yet sent, in tx_buf[tx_start..tx_end]
    tx_buf: Vec<u8>,
    tx_start: usize,
    tx_end: usize,
    tx_frames: usize,
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
            rx_buf: vec![0u8; RX_BUFFER_SIZE],
            rx_start: 0,
            rx_end: 0,
            tx_buf: vec![0u8; TX_BUFFER_SIZE],
            tx_start: 0,
            tx_end: 0,
            tx_frames: 0,
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
            rx_buf: vec![0u8; RX_BUFFER_SIZE],
            rx_start: 0,
            rx_end: 0,
            tx_buf: vec![0u8; TX_BUFFER_SIZE],
            tx_start: 0,
            tx_end: 0,
            tx_frames: 0,
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

    /// Bytes staged for the socket but not yet sent.
    fn unsent(&self) -> usize {
        self.tx_end - self.tx_start
    }

    /// Append one length-prefixed frame to the staging buffer. Room is the caller's job:
    /// the bound in `write_frame` keeps a whole frame's worth free.
    fn stage(&mut self, frame: &[u8]) {
        if self.tx_buf.len() - self.tx_end < frame.len() {
            self.tx_buf.copy_within(self.tx_start..self.tx_end, 0);
            self.tx_end -= self.tx_start;
            self.tx_start = 0;
        }
        let end = self.tx_end + frame.len();
        self.tx_buf[self.tx_end..end].copy_from_slice(frame);
        self.tx_end = end;
        self.tx_frames += 1;
    }

    /// Send the staged bytes. The socket is a stream, so a short send only advances the
    /// start of what is left: the tail keeps its place in the frame it belongs to and goes
    /// out, unchanged, on the next call.
    fn send_staged(&mut self) -> Result<(), WriteError> {
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        let mut sent_any = false;
        while self.tx_start < self.tx_end {
            match send(
                self.fd.as_raw_fd(),
                &self.tx_buf[self.tx_start..self.tx_end],
                flags,
            ) {
                Ok(size) => {
                    self.tx_start += size;
                    sent_any = true;
                }
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    log::trace!("socket blocked with {} bytes staged", self.unsent());
                    return Err(if sent_any {
                        WriteError::PartialWrite
                    } else {
                        WriteError::NothingWritten
                    });
                }
                Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        self.tx_start = 0;
        self.tx_end = 0;
        self.tx_frames = 0;
        Ok(())
    }

    /// Send one frame straight from the caller's buffer, staging what the socket would not
    /// take so the resume path is the same as for a staged batch.
    fn send_direct(&mut self, frame: &[u8]) -> Result<(), WriteError> {
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        let mut sent = 0;
        while sent < frame.len() {
            match send(self.fd.as_raw_fd(), &frame[sent..], flags) {
                Ok(size) => sent += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => break,
                Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        if sent < frame.len() {
            self.stage(&frame[sent..]);
        }
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

    /// Take a frame for the proxy. Small frames are staged and leave with the frames behind
    /// them on the next `flush_frames`, so a burst costs one send rather than one each.
    /// (Will mutate and override parts of buf, with a frame header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///   (such as vnet header), that can be overwritten. Must be >= FRAME_HEADER_LEN.
    /// * `buf` - the buffer to write to the proxy, `buf[..hdr_len]` may be overwritten
    ///
    /// `buf` is the caller's to reuse on return: a frame this took is either on the socket or
    /// copied into the staging buffer. `WriteError::NothingWritten` means the frame was not
    /// taken, and the caller offers it again once the socket is writable.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        assert!(
            hdr_len >= FRAME_HEADER_LEN,
            "Not enough space to write the frame header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - FRAME_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());
        let frame = &buf[hdr_len - FRAME_HEADER_LEN..];

        // A full batch goes out before this frame joins it. A socket that cannot take the
        // batch cannot take this frame either, so it stays with the caller.
        if self.tx_frames >= TX_BATCH_FRAMES || self.unsent() >= TX_BATCH_SIZE {
            match self.send_staged() {
                Ok(()) | Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
                Err(e) => return Err(e),
            }
            if self.unsent() > 0 {
                return Err(WriteError::NothingWritten);
            }
        }

        // Frames the copy would cost as much as the send go out on their own, but only
        // when nothing is staged ahead of them: the stream's order is the frame order.
        if self.unsent() == 0 && frame.len() >= TX_DIRECT_MIN {
            return self.send_direct(frame);
        }
        self.stage(frame);
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        self.unsent() != 0
    }

    fn flush_frames(&mut self) -> Result<(), WriteError> {
        self.send_staged()
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn pair() -> (Unixstream, UnixStream) {
        let (reader, writer) = UnixStream::pair().unwrap();
        (Unixstream::new(reader.into()), writer)
    }

    /// Offer a frame the way the worker does: a vnet header's worth of space in front of it
    /// for the length prefix to go into.
    fn tx_frame(tx: &mut Unixstream, frame: &[u8]) -> Result<(), WriteError> {
        let mut buf = vec![0u8; VNET_HDR_LEN + frame.len()];
        buf[VNET_HDR_LEN..].copy_from_slice(frame);
        tx.write_frame(VNET_HDR_LEN, &mut buf)
    }

    /// Everything the peer can read right now.
    fn drain(peer: &mut UnixStream) -> Vec<u8> {
        peer.set_nonblocking(true).unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match peer.read(&mut chunk) {
                Ok(0) => break,
                Ok(size) => bytes.extend_from_slice(&chunk[..size]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("peer read failed: {e}"),
            }
        }
        bytes
    }

    /// Read the peer out while the backend retries, until it holds nothing back.
    fn drain_while_flushing(tx: &mut Unixstream, peer: &mut UnixStream) -> Vec<u8> {
        let mut bytes = drain(peer);
        for _ in 0..10_000 {
            if !tx.has_unfinished_write() {
                return bytes;
            }
            match tx.flush_frames() {
                Ok(()) | Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
                Err(e) => panic!("flush failed: {e:?}"),
            }
            bytes.extend_from_slice(&drain(peer));
        }
        panic!("the backend never finished its write");
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
    fn staged_frames_leave_together_and_in_order() {
        let (mut tx, mut peer) = pair();
        let frames: [&[u8]; 3] = [b"one", b"second frame", b"three"];
        for frame in frames {
            tx_frame(&mut tx, frame).unwrap();
        }
        assert_eq!(tx.unsent(), framed(&frames).len());
        assert!(drain(&mut peer).is_empty(), "no frame leaves on its own");

        tx.flush_frames().unwrap();
        assert_eq!(drain(&mut peer), framed(&frames));
        assert!(!tx.has_unfinished_write());
    }

    /// Either bound ends a batch, and only the frame that crossed it stays staged.
    #[test]
    fn a_burst_is_split_by_the_frame_and_the_byte_bound() {
        for body in [vec![0x11; 8], vec![0x22; 4096]] {
            let (mut tx, peer) = pair();
            let reading = std::thread::spawn(move || {
                let mut peer = peer;
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).unwrap();
                bytes
            });

            let mut staged = 0;
            while tx.tx_frames < TX_BATCH_FRAMES && tx.unsent() < TX_BATCH_SIZE {
                tx_frame(&mut tx, &body).unwrap();
                staged += 1;
            }
            // The two bounds are each what a burst of one of these frame sizes reaches.
            assert_eq!(staged >= TX_BATCH_FRAMES, body.len() == 8);

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match tx_frame(&mut tx, &body) {
                    Ok(()) => break,
                    Err(WriteError::NothingWritten) => {}
                    Err(e) => panic!("write failed: {e:?}"),
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the reader fell behind"
                );
            }
            assert_eq!(
                tx.tx_frames, 1,
                "the batch left before this frame joined it"
            );
            assert_eq!(tx.unsent(), FRAME_HEADER_LEN + body.len());

            while tx.has_unfinished_write() {
                match tx.flush_frames() {
                    Ok(()) | Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
                    Err(e) => panic!("flush failed: {e:?}"),
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the reader fell behind"
                );
            }
            drop(tx);
            let expected = framed(&vec![body.as_slice(); staged + 1]);
            assert_eq!(reading.join().unwrap(), expected);
        }
    }

    /// A send the socket cut short resumes at the byte it stopped at, whether that falls
    /// inside a frame or inside the length prefix in front of one.
    #[test]
    fn a_resume_continues_mid_frame_and_mid_header() {
        let wire = framed(&[b"first frame", b"next"]);
        for resume in [FRAME_HEADER_LEN + 2, FRAME_HEADER_LEN + 11 + 2] {
            let (mut tx, mut peer) = pair();
            tx.tx_buf[..wire.len()].copy_from_slice(&wire);
            tx.tx_end = wire.len();
            tx.tx_start = resume;
            tx.tx_frames = 1;
            assert!(tx.has_unfinished_write());

            tx.flush_frames().unwrap();
            assert!(!tx.has_unfinished_write());
            assert_eq!(drain(&mut peer), wire[resume..]);
        }
    }

    /// A socket too small for the batch takes it over several sends, and refuses further
    /// frames meanwhile rather than growing the staging buffer without bound.
    #[test]
    fn a_blocked_socket_holds_its_place_in_the_stream() {
        let (mut tx, mut peer) = pair();
        setsockopt(&tx.fd, sockopt::SndBuf, &4096).unwrap();
        let body = vec![0x5a; 1500];

        let mut taken = 0;
        loop {
            match tx_frame(&mut tx, &body) {
                Ok(()) => taken += 1,
                Err(WriteError::NothingWritten) => break,
                Err(e) => panic!("unexpected write error: {e:?}"),
            }
        }
        assert!(tx.has_unfinished_write());

        let bytes = drain_while_flushing(&mut tx, &mut peer);
        assert_eq!(bytes, framed(&vec![body.as_slice(); taken]));
    }

    /// A frame past the direct bound is sent from the caller's buffer, and needs no flush.
    #[test]
    fn a_frame_too_large_to_be_worth_staging_goes_straight_out() {
        let (mut tx, mut peer) = pair();
        let body = vec![0xc3; TX_DIRECT_MIN];
        tx_frame(&mut tx, &body).unwrap();
        assert!(!tx.has_unfinished_write());
        assert_eq!(drain(&mut peer), framed(&[body.as_slice()]));
    }

    /// Staged frames are in front of it in the stream, so it has to wait for them.
    #[test]
    fn a_staged_frame_holds_back_the_large_one_behind_it() {
        let (mut tx, mut peer) = pair();
        let small: &[u8] = b"small";
        let large = vec![0xc3; TX_DIRECT_MIN];
        tx_frame(&mut tx, small).unwrap();
        tx_frame(&mut tx, &large).unwrap();
        assert!(drain(&mut peer).is_empty());

        tx.flush_frames().unwrap();
        assert_eq!(drain(&mut peer), framed(&[small, large.as_slice()]));
    }

    /// The largest frame the device can produce, sent directly into a socket that takes
    /// only part of it: the tail is staged and resumes like any other.
    #[test]
    fn a_jumbo_frame_the_socket_truncates_keeps_its_tail() {
        let (mut tx, mut peer) = pair();
        setsockopt(&tx.fd, sockopt::SndBuf, &4096).unwrap();
        let body = vec![0x7e; MAX_BUFFER_SIZE - VNET_HDR_LEN];
        tx_frame(&mut tx, &body).unwrap();
        assert!(tx.has_unfinished_write());

        let bytes = drain_while_flushing(&mut tx, &mut peer);
        assert_eq!(bytes, framed(&[body.as_slice()]));
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
