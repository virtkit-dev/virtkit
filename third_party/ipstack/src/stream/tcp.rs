use super::seqnum::SeqNum;
use crate::{
    PacketReceiver, PacketSender, TTL,
    error::IpStackError,
    packet::{
        IpHeader, NetworkPacket, NetworkTuple, TransportHeader,
        tcp_flags::{ACK, FIN, PSH, RST, SYN},
        tcp_header_flags, tcp_header_fmt,
    },
    stream::tcb::{
        MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_RTO, MAX_SACK_BLOCKS, MAX_UNACK, MAX_WINDOW_SHIFT, MIN_RTO, PacketType,
        READ_BUFFER_SIZE, READ_CHUNK, RTO, Rto, Tcb, TcpState,
    },
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpHeader, TcpOptionElement};
use std::{
    io::ErrorKind::{BrokenPipe, ConnectionRefused, InvalidInput, UnexpectedEof},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// 2 * MSL (Maximum Segment Lifetime) is the maximum time a TCP connection can be in the TIME_WAIT state.
const TWO_MSL: Duration = Duration::from_secs(2);

const CLOSE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(60);
const LAST_ACK_MAX_RETRIES: usize = 3;
const LAST_ACK_TIMEOUT: Duration = Duration::from_millis(500);
const TIMEOUT: Duration = Duration::from_secs(60);

#[non_exhaustive]
#[derive(Debug, Clone)]
/// TCP configuration
pub struct TcpConfig {
    /// Maximum number of retries for sending the last ACK in the LAST_ACK state. Default is 3.
    pub last_ack_max_retries: usize,
    /// Timeout for the last ACK in the LAST_ACK state. Default is 500ms.
    pub last_ack_timeout: Duration,
    /// Wait up to 5 seconds by default for the application to write or close after the peer's
    /// FIN, then request a local close. The first write switches to `half_close_timeout`.
    pub close_wait_timeout: Duration,
    /// Write inactivity timeout before requesting a half-closed session's local close. Each write
    /// restarts it. The 60-second default allows a slow reply after the peer's `shutdown(SHUT_WR)`.
    pub half_close_timeout: Duration,
    /// How long a session may go without a packet from the peer before it is reset. Default
    /// is 60 seconds. Nothing the local side sends postpones it: a peer that is still there
    /// acknowledges what it is sent, so silence this long means it is gone. Reads report
    /// [`std::io::ErrorKind::ConnectionReset`] once the data already taken from the peer has
    /// been handed over.
    pub timeout: Duration,
    /// Timeout for the TIME_WAIT state. Default is 2 seconds.
    pub two_msl: Duration,
    /// Maximum number of unacknowledged bytes allowed in the send buffer.
    pub max_unacked_bytes: u32,
    /// Advertised receive window and reassembly-buffer bound, in bytes. The reader handoff holds
    /// about as much again in acknowledged data, for a total footprint of roughly twice this
    /// value. Both can overshoot: the next expected segment is admitted even when the buffer is
    /// full, and the handoff capacity is rounded to whole chunks. Advertising a receive window
    /// above 65,535 bytes requires the peer to offer window scaling (RFC 7323 § 2).
    pub read_buffer_size: usize,
    /// Maximum number of duplicate ACKs before triggering fast retransmission.
    pub max_count_for_dup_ack: usize,
    /// Retransmission timeout until the connection has measured a round trip, one second by
    /// default as RFC 6298 § 2.1 has it. From the first measurement onwards the timeout follows
    /// the round trip, between `min_rto` and `max_rto`. Must be positive and at most `max_rto`;
    /// it may be below `min_rto`. Timeouts back off until an unambiguous RTT sample arrives.
    pub rto: std::time::Duration,
    /// Floor for the measured retransmission timeout, 200ms by default. A peer a virtio hop away
    /// answers in well under a millisecond, and RFC 6298 § 2.4's floor of a second would leave the
    /// estimate no room to be of any use. Must be positive and at most `max_rto`.
    pub min_rto: std::time::Duration,
    /// Ceiling for the retransmission timeout, backoff included. Default is 60 seconds.
    /// Must fit the platform's timer. Invalid RTO settings reject new TCP streams with
    /// [`std::io::ErrorKind::InvalidInput`].
    pub max_rto: std::time::Duration,
    /// Maximum number of retransmissions before giving up.
    pub max_retransmit_count: usize,
    /// TCP options
    pub options: Option<Vec<TcpOptions>>,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum TcpOptions {
    /// Maximum segment size (MSS) for TCP connections.
    MaximumSegmentSize(u16),
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig {
            last_ack_max_retries: LAST_ACK_MAX_RETRIES,
            last_ack_timeout: LAST_ACK_TIMEOUT,
            close_wait_timeout: CLOSE_WAIT_TIMEOUT,
            half_close_timeout: HALF_CLOSE_TIMEOUT,
            timeout: TIMEOUT,
            two_msl: TWO_MSL,
            max_unacked_bytes: MAX_UNACK,
            read_buffer_size: READ_BUFFER_SIZE,
            max_count_for_dup_ack: MAX_COUNT_FOR_DUP_ACK,
            rto: RTO,
            min_rto: MIN_RTO,
            max_rto: MAX_RTO,
            max_retransmit_count: MAX_RETRANSMIT_COUNT,
            options: Default::default(),
        }
    }
}

#[derive(Debug)]
enum Shutdown {
    None,
    Pending(Waker),
    Ready,
}

impl Shutdown {
    fn pending(&mut self, w: Waker) {
        *self = Shutdown::Pending(w);
    }
    fn ready(&mut self) {
        if let Shutdown::Pending(w) = self {
            w.wake_by_ref();
        }
        *self = Shutdown::Ready;
    }
}

impl std::fmt::Display for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shutdown::None => write!(f, "None"),
            Shutdown::Pending(_) => write!(f, "Pending"),
            Shutdown::Ready => write!(f, "Ready"),
        }
    }
}

static SESSION_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

type TcbPtr = std::sync::Arc<std::sync::Mutex<Tcb>>;

/// A TCP stream in the IP stack.
///
/// This type represents a TCP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. It handles TCP state management, flow control,
/// and retransmission automatically.
///
/// Dropping the stream ends the connection: a peer that still believes it is open is reset, so
/// a flow the application abandons does not leave the peer waiting on its own timeouts.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
/// if let IpStackStream::Tcp(mut tcp_stream) = ip_stack.accept().await? {
///     println!("New TCP connection from {}", tcp_stream.peer_addr());
///     
///     // Read data
///     let mut buffer = [0u8; 1024];
///     let n = tcp_stream.read(&mut buffer).await?;
///     
///     // Write data
///     tcp_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
///     
///     // Shutdown the stream
///     tcp_stream.shutdown().await?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: Option<PacketReceiver>,
    up_packet_sender: PacketSender,
    tcb: TcbPtr,
    shutdown: std::sync::Arc<std::sync::Mutex<Shutdown>>,
    write_notify: WakerSlot,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    data_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    read_notify: WakerSlot,
    /// Tells the session task that a write put a segment in flight, so it recomputes its
    /// retransmission deadline instead of sleeping out the one it armed before the write.
    rearm: Arc<tokio::sync::Notify>,
    drain_notify: Arc<tokio::sync::Notify>,
    task_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    exit_notifier: Option<tokio::sync::mpsc::Sender<()>>,
    temp_read_buffer: Vec<u8>,
    config: Arc<TcpConfig>,
}

/// The TCP options a segment we send carries. Everything the connection negotiated goes through
/// here, so one place decides what rides on a segment and what it costs in header space.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct SendOptions {
    /// The largest payload we will take, offered on the SYN-ACK alone (RFC 9293 § 3.7.1).
    pub(crate) max_segment_size: Option<u16>,
    /// Our window scale, likewise on the SYN-ACK alone (RFC 7323 § 2.2).
    pub(crate) window_scale: Option<u8>,
    /// Our clock and the peer's echoed timestamp, on every segment of a connection that
    /// negotiated the option (RFC 7323 § 3.2).
    pub(crate) timestamp: Option<(u32, u32)>,
    /// Whether we accept selective acknowledgment, answered on the SYN-ACK alone to a SYN that
    /// offered it (RFC 2018 § 2).
    pub(crate) sack_permitted: bool,
    /// The ranges above the cumulative acknowledgment our reassembly buffer holds, newest first
    /// (RFC 2018 § 3). Empty on everything but an acknowledgment that stops at a hole.
    pub(crate) selective_ack: [Option<(u32, u32)>; MAX_SACK_BLOCKS],
}

impl SendOptions {
    /// Encode TCP options. Two NOPs before Timestamp align its TSval and TSecr fields
    /// on four-byte boundaries, bringing the option and padding to 12 bytes.
    fn elements(&self) -> Vec<TcpOptionElement> {
        let mut elements = Vec::new();
        if let Some(mss) = self.max_segment_size {
            elements.push(TcpOptionElement::MaximumSegmentSize(mss));
        }
        if let Some((tsval, tsecr)) = self.timestamp {
            elements.push(TcpOptionElement::Noop);
            elements.push(TcpOptionElement::Noop);
            elements.push(TcpOptionElement::Timestamp(tsval, tsecr));
        }
        if let Some(shift) = self.window_scale {
            elements.push(TcpOptionElement::WindowScale(shift));
        }
        if self.sack_permitted {
            elements.push(TcpOptionElement::SelectiveAcknowledgementPermitted);
        }
        let mut blocks = self.selective_ack.iter().flatten().copied();
        if let Some(first) = blocks.next() {
            let mut rest = [None; MAX_SACK_BLOCKS - 1];
            for (slot, block) in rest.iter_mut().zip(blocks) {
                *slot = Some(block);
            }
            elements.push(TcpOptionElement::SelectiveAcknowledgement(first, rest));
        }
        elements
    }
}

/// Yield complete TCP options (kind, length and body), skipping NOPs. Stop at EOL or report
/// the first malformed option; callers ignore unknown kinds using their declared lengths.
fn header_options(mut options: &[u8]) -> impl Iterator<Item = Result<(u8, &[u8]), &'static str>> {
    use etherparse::tcp_option::{KIND_END, KIND_NOOP};

    let mut done = false;
    std::iter::from_fn(move || {
        while !done {
            let (&kind, rest) = options.split_first()?;
            if kind == KIND_END {
                return None;
            }
            if kind == KIND_NOOP {
                options = rest;
                continue;
            }
            let Some((&length, _)) = rest.split_first() else {
                done = true;
                return Some(Err("missing option length"));
            };
            if length < 2 {
                done = true;
                return Some(Err("option length is less than two"));
            }
            let Some((option, remaining)) = options.split_at_checked(usize::from(length)) else {
                done = true;
                return Some(Err("option extends past the TCP header"));
            };
            options = remaining;
            return Some(Ok((kind, option)));
        }
        None
    })
}

/// Return the first window scale, stopping at EOL or a malformed option.
/// Malformed options after the first scale do not invalidate it.
fn syn_window_scale(options: &[u8]) -> Result<Option<u8>, &'static str> {
    use etherparse::tcp_option::{KIND_WINDOW_SCALE, LEN_WINDOW_SCALE};

    for option in header_options(options) {
        let (kind, option) = option?;
        if kind == KIND_WINDOW_SCALE {
            if option.len() != usize::from(LEN_WINDOW_SCALE) {
                return Err("invalid window scale option length");
            }
            return Ok(option.get(2).copied());
        }
    }
    Ok(None)
}

/// Return the SYN's first MSS offer, the peer's payload limit (RFC 9293 § 3.7.1).
fn syn_max_segment_size(options: &[u8]) -> Result<Option<u16>, &'static str> {
    use etherparse::tcp_option::{KIND_MAXIMUM_SEGMENT_SIZE, LEN_MAXIMUM_SEGMENT_SIZE};

    for option in header_options(options) {
        let (kind, option) = option?;
        if kind == KIND_MAXIMUM_SEGMENT_SIZE {
            if option.len() != usize::from(LEN_MAXIMUM_SEGMENT_SIZE) {
                return Err("invalid maximum segment size option length");
            }
            return Ok(Some(u16::from_be_bytes([option[2], option[3]])));
        }
    }
    Ok(None)
}

/// Return the SACK blocks an acknowledgment carries: the ranges of our stream the peer already
/// holds, above the sequence number it acknowledges (RFC 2018 § 3). A block that runs backwards
/// is no range at all and is passed over.
fn header_sack_blocks(options: &[u8]) -> Result<Vec<(SeqNum, SeqNum)>, &'static str> {
    use etherparse::tcp_option::KIND_SELECTIVE_ACK;

    for option in header_options(options) {
        let (kind, option) = option?;
        if kind == KIND_SELECTIVE_ACK {
            let body = &option[2..];
            if body.is_empty() || body.len() % 8 != 0 {
                return Err("invalid selective acknowledgment option length");
            }
            let edge = |bytes: &[u8]| SeqNum(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
            return Ok(body
                .chunks_exact(8)
                .map(|block| (edge(&block[..4]), edge(&block[4..])))
                .filter(|(start, end)| start < end)
                .collect());
        }
    }
    Ok(Vec::new())
}

/// Return the SYN's first SACK-Permitted offer (RFC 2018 § 2), stopping at EOL or an error.
/// Malformed options after a valid offer do not invalidate it.
fn syn_sack_permitted(options: &[u8]) -> Result<bool, &'static str> {
    use etherparse::tcp_option::{KIND_SELECTIVE_ACK_PERMITTED, LEN_SELECTIVE_ACK_PERMITTED};

    for option in header_options(options) {
        let (kind, option) = option?;
        if kind == KIND_SELECTIVE_ACK_PERMITTED {
            if option.len() != usize::from(LEN_SELECTIVE_ACK_PERMITTED) {
                return Err("invalid selective acknowledgment permitted option length");
            }
            return Ok(true);
        }
    }
    Ok(false)
}

/// Return a segment's first timestamps option: the peer's clock and the reading of ours it is
/// echoing back (RFC 7323 § 3.2).
fn header_timestamp(options: &[u8]) -> Result<Option<(u32, u32)>, &'static str> {
    use etherparse::tcp_option::{KIND_TIMESTAMP, LEN_TIMESTAMP};

    for option in header_options(options) {
        let (kind, option) = option?;
        if kind == KIND_TIMESTAMP {
            if option.len() != usize::from(LEN_TIMESTAMP) {
                return Err("invalid timestamp option length");
            }
            let tsval = u32::from_be_bytes([option[2], option[3], option[4], option[5]]);
            let tsecr = u32::from_be_bytes([option[6], option[7], option[8], option[9]]);
            return Ok(Some((tsval, tsecr)));
        }
    }
    Ok(None)
}

impl IpStackTcpStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeader,
        payload_len: usize,
        up_packet_sender: PacketSender,
        mtu: u16,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
        config: Arc<TcpConfig>,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let mut tcb = Tcb::new(
            SeqNum(tcp.sequence_number),
            mtu,
            config.max_unacked_bytes,
            config.read_buffer_size,
            config.max_count_for_dup_ack,
            Rto::new(config.rto, config.min_rto, config.max_rto)?,
            config.max_retransmit_count,
        );
        let tuple = NetworkTuple::new(src_addr, dst_addr, true);
        if !tcp.syn {
            if !tcp.rst
                && let Err(err) = reset_stray_segment(&up_packet_sender, tuple, &tcp, payload_len)
            {
                log::warn!("{tuple} error sending RST: {err}");
            }
            let info = format!("Invalid TCP packet: {tuple} {}", tcp_header_fmt(&tcp));
            return Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)));
        }
        let peer_window_shift = syn_window_scale(tcp.options.as_slice()).unwrap_or_else(|err| {
            log::warn!("{tuple}: malformed SYN options: {err}");
            None
        });
        tcb.accept_syn_window(tcp.window_size, peer_window_shift);
        log::debug!(
            "{tuple}: window scaling: peer offer {peer_window_shift:?}, effective peer shift {:?}, local shift {:?}",
            peer_window_shift.map(|shift| shift.min(MAX_WINDOW_SHIFT)),
            tcb.get_recv_window_shift()
        );
        let peer_mss = syn_max_segment_size(tcp.options.as_slice()).unwrap_or_else(|err| {
            log::warn!("{tuple}: malformed SYN options, falling back to the default MSS: {err}");
            None
        });
        tcb.accept_syn_mss(peer_mss, dst_addr.is_ipv4());
        log::debug!(
            "{tuple}: peer MSS offer {peer_mss:?}, sending segments of up to {} bytes",
            tcb.get_peer_mss()
        );
        let peer_timestamp = header_timestamp(tcp.options.as_slice()).unwrap_or_else(|err| {
            log::warn!("{tuple}: malformed SYN options, timestamps left off: {err}");
            None
        });
        tcb.accept_syn_timestamps(peer_timestamp.map(|(tsval, _)| tsval));
        log::debug!(
            "{tuple}: timestamps offered {peer_timestamp:?}, negotiated {}",
            tcb.timestamps_negotiated()
        );
        let peer_sack = syn_sack_permitted(tcp.options.as_slice()).unwrap_or_else(|err| {
            log::warn!("{tuple}: malformed SYN options, selective acknowledgment left off: {err}");
            false
        });
        tcb.accept_syn_sack_permitted(peer_sack);
        log::debug!("{tuple}: selective acknowledgment offered {peer_sack}");

        let (stream_sender, stream_receiver) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let data_channel_len = config.read_buffer_size.div_ceil(READ_CHUNK).max(1);
        let (data_tx, data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(data_channel_len);

        let mut stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Some(stream_receiver),
            up_packet_sender,
            tcb: std::sync::Arc::new(std::sync::Mutex::new(tcb.clone())),
            shutdown: std::sync::Arc::new(std::sync::Mutex::new(Shutdown::None)),
            write_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
            destroy_messenger,
            data_tx,
            data_rx,
            read_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
            rearm: Arc::new(tokio::sync::Notify::new()),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
            task_handle: None,
            exit_notifier: None,
            temp_read_buffer: Vec::new(),
            config,
        };

        let sessions = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst).saturating_add(1);
        let (seq, ack, state) = { (tcb.get_seq().0, tcb.get_ack().0, tcb.get_state()) };
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::debug!("{tuple} {state:?}: {l_info} session begins, total TCP sessions: {sessions}");

        stream.spawn_tasks()?;
        Ok(stream)
    }

    pub(crate) fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple::new(self.src_addr, self.dst_addr, true)
    }

    /// Returns the local socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let local_addr = tcp_stream.local_addr();
    /// println!("Local address: {}", local_addr);
    /// # }
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let peer_addr = tcp_stream.peer_addr();
    /// println!("Peer address: {}", peer_addr);
    /// # }
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    pub fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }
}

/// Whether the peer has said it is done sending: its FIN arrived in sequence and was accepted, or
/// the session is over. The reader turns that into an end of stream once the buffers have drained;
/// waiting for the farewell of our own to be acknowledged first leaves a proxy holding a
/// connection the peer has finished with for seconds.
fn peer_finished_sending(state: TcpState) -> bool {
    matches!(
        state,
        TcpState::CloseWait | TcpState::LastAck | TcpState::Closing | TcpState::TimeWait | TcpState::Closed
    )
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        // Complete reads with no remaining capacity without consuming queued data
        // or waiting for more data.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // if there is data in the temp buffer, read it first
        if !self.temp_read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.temp_read_buffer.len());
            buf.put_slice(&self.temp_read_buffer[..len]);
            self.temp_read_buffer.drain(..len); // remove the read data from the temp buffer
            return Poll::Ready(Ok(()));
        }

        let this = &mut *self;
        // Hold this lock across the handoff poll and waker registration, matching the session
        // task's lock order. A FIN or reset between them could find neither a parked waker nor
        // channel data to wake the reader, leaving it blocked on an ended connection.
        let mut tcb = this.tcb.lock().unwrap();
        let (state, aborted) = (tcb.get_state(), tcb.is_aborted());

        // Data the session took from the peer was acknowledged to it, so it belongs to the
        // application whatever has become of the connection since — a reset of our own included.
        // Read the handoff out before reporting the end of the stream.
        let polled = this.data_rx.poll_recv(cx);
        // An exhausted cooperative budget yields `Pending` even with queued data. Check
        // emptiness explicitly: treating that yield as EOF drops the acknowledged tail
        // of a long transfer.
        let drained = this.data_rx.is_empty();
        // Once the session task ends, nothing refills the handoff. Drain acknowledged data
        // left in reassembly directly. Reset sessions still report an error below instead.
        if matches!(polled, Poll::Pending)
            && drained
            && !aborted
            && state == TcpState::Closed
            && let Some(data) = tcb.consume_unordered_packets(buf.remaining())
        {
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        let buffered = tcb.get_unordered_packets_total_len();
        match polled {
            Poll::Ready(Some(data)) => {
                let capacity = buf.remaining();
                if capacity >= data.len() {
                    buf.put_slice(&data);
                } else {
                    // if `buf` is not enough, put the remaining data into the temp buffer
                    buf.put_slice(&data[..capacity]);
                    this.temp_read_buffer.extend_from_slice(&data[capacity..]);
                }
                // A channel slot just freed, so wake the loop to flush more and reopen the window.
                this.drain_notify.notify_one();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending if aborted && drained => {
                // A connection the stack reset did not end in an orderly close. Reporting the
                // end of the stream would tell the application the transfer finished, and a
                // proxy would go on holding the other side of a flow that is over.
                drop(tcb);
                this.shutdown.lock().unwrap().ready();
                this.write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)))
            }
            Poll::Pending if peer_finished_sending(state) && buffered == 0 && drained => {
                drop(tcb);
                if state == TcpState::Closed {
                    this.shutdown.lock().unwrap().ready();
                    this.write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                this.read_notify.lock().unwrap().replace(cx.waker().clone());
                drop(tcb);
                if buffered > 0 {
                    // The session still holds data the handoff had no room for; ask it to try again.
                    this.drain_notify.notify_one();
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let nt = self.network_tuple();

        let mut tcb = self.tcb.lock().unwrap();
        let state = tcb.get_state();
        let send_window = tcb.get_send_window();
        let is_full = tcb.is_send_buffer_full();

        if state == TcpState::Closed {
            self.shutdown.lock().unwrap().ready();
            self.read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection closed")));
        }
        if tcb.fin_requested() || !matches!(state, TcpState::SynReceived | TcpState::Established | TcpState::CloseWait) {
            // The local side has said it is done sending, or is about to. The peer discards
            // anything past that FIN, so the write has to fail rather than report bytes sent.
            log::debug!("{nt} {state:?}: [poll_write] the local side is closed for writing");
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection closed for writing")));
        }

        if send_window == 0 || is_full {
            self.write_notify.lock().unwrap().replace(cx.waker().clone());
            let info = format!("current send window: {send_window}, send buffer full: {is_full}");
            log::trace!("{nt} {state:?}: [poll_write] {info}, waiting for the other side to send ACK...");
            return Poll::Pending;
        }

        let sender = &self.up_packet_sender;
        let payload_len = write_packet_to_device(sender, nt, &mut tcb, None, ACK | PSH, None, Some(buf.to_vec()))?;
        let timer_was_idle = tcb.get_inflight_packets_total_len() == 0;
        tcb.add_inflight_packet(buf[..payload_len].to_vec())?;
        tcb.note_write();
        if timer_was_idle {
            // The task has no timer to run while the queue is empty, so this segment's is the
            // one it has to wake for. A segment joining a queue that already has one falls due
            // after it, and the deadline the task is already sleeping on still holds.
            self.rearm.notify_one();
        }

        let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{nt} {state:?}: [poll_write] {l_info} upstream data written to device, len = {payload_len}");

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let nt = self.network_tuple();
        // Hold both locks across the state read and waker registration. Otherwise the session
        // task can report completion through `shutdown` between them, and registration overwrites
        // it, leaving the caller waiting on a closed connection.
        let mut tcb = self.tcb.lock().unwrap();
        let mut shutdown = self.shutdown.lock().unwrap();
        let (state, seq) = (tcb.get_state(), tcb.get_seq());
        let is_ready = tcb.get_inflight_packets_total_len() == 0;
        log::trace!(
            "{nt} {state:?}: [poll_shutdown] seq = {seq}, ready = {is_ready}, shutdown {}",
            *shutdown
        );
        if state == TcpState::Closed {
            return Poll::Ready(Ok(()));
        }
        match *shutdown {
            Shutdown::None | Shutdown::Pending(_) => {
                if matches!(state, TcpState::Established | TcpState::CloseWait) {
                    // The FIN has to follow the data still on its way, not replace it, so the
                    // session task sends it — once the in-flight queue drains, and always from
                    // the one place that also arms the timer waiting for its acknowledgment.
                    tcb.request_fin();
                    self.rearm.notify_one();
                }
                // Registered on every poll: the waker this future was last polled with is the
                // one the task has to wake when the connection finishes closing.
                shutdown.pending(cx.waker().clone());
                Poll::Pending
            }
            Shutdown::Ready => Poll::Ready(Ok(())),
        }
    }
}

/// Where a half of the stream parks its waker while it waits on the session task.
type WakerSlot = std::sync::Arc<std::sync::Mutex<Option<Waker>>>;

/// Wake both halves of the stream, so the session task can report a connection ending that the
/// application did not ask for.
fn wake_both(read_notify: &WakerSlot, write_notify: &WakerSlot) {
    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
    read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
}

/// Retransmit the in-flight segments whose timers expired, and report whether the connection
/// was reset instead. Once retransmissions are exhausted the peer will never receive that
/// segment: leaving the connection Established would stall the stream on a hole that the peer's
/// duplicate ACKs can no longer get filled. Reset instead, so the application fails fast and
/// reconnects.
fn retransmit_or_reset(nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> std::io::Result<bool> {
    if tcb.get_send_window() == 0 {
        // Nothing may be sent to a peer with no room but a window probe, and counting the
        // silence as lost segments would reset a connection whose peer is merely flow-controlled.
        return Ok(false);
    }
    let (timed_out, exhausted) = tcb.collect_timed_out_inflight_packets();
    if exhausted {
        let state = tcb.get_state();
        log::warn!("{nt} {state:?}: retransmissions exhausted, resetting the connection");
        // The peer never took those bytes, so what it is waiting for is where they begin: the
        // highest acknowledgment it has sent. Under RFC 5961 that is the only sequence number a
        // reset is honoured at; anything else draws a challenge ACK or is dropped.
        let seq = tcb.get_last_received_ack();
        write_packet_to_device(sender, nt, tcb, None, RST | ACK, Some(seq), None)?;
        tcb.change_state(TcpState::Closed);
        tcb.mark_aborted();
        return Ok(true);
    }
    let rto = tcb.rto();
    for packet in timed_out {
        let (seq, count) = (packet.seq, packet.retransmit_count);
        log::debug!("{nt} inflight packet retransmission timeout: {seq:?}, retransmit_count: {count}, timeout now {rto:?}");
        write_packet_to_device(sender, nt, tcb, None, ACK | PSH, Some(seq), Some(packet.payload))?;
    }
    Ok(false)
}

/// Retransmit holes identified by the packet scoreboard. This uses SACK loss evidence
/// from RFC 6675 without implementing its full congestion-control machinery.
/// A closed peer window is handled by the existing persist probes.
fn retransmit_sacked_holes(nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> std::io::Result<()> {
    if tcb.get_send_window() == 0 {
        return Ok(());
    }
    for (seq, payload) in tcb.take_sack_retransmits() {
        let state = tcb.get_state();
        log::debug!(
            "{nt} {state:?}: the peer is missing seq {seq}, len = {}, sending it again",
            payload.len()
        );
        write_packet_to_device(sender, nt, tcb, None, ACK | PSH, Some(seq), Some(payload))?;
    }
    Ok(())
}

/// Probe a peer whose receive window is closed: a segment carrying no data, at a sequence number
/// it has already acknowledged, which it answers with an ACK reporting its window as it now
/// stands. The update that reopens the window can be lost like any other segment, and nothing
/// but this probe recovers a connection from that.
fn send_window_probe(nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> std::io::Result<()> {
    let seq = tcb.get_seq() - tcb.get_inflight_packets_total_len() as u32 - 1;
    let state = tcb.get_state();
    log::debug!("{nt} {state:?}: the peer's window is closed, probing it at seq {seq}");
    write_packet_to_device(sender, nt, tcb, None, ACK, Some(seq), None)?;
    Ok(())
}

/// When a half-closed session falls due, given the deadline CLOSE_WAIT began with: the leash
/// runs from the application's last write, and from the peer's close until it writes at all.
fn half_close_due(tcb: &Tcb, entered: tokio::time::Instant, half_close_timeout: Duration) -> tokio::time::Instant {
    match tcb.last_write_at() {
        Some(at) => tokio::time::Instant::from_std(at) + half_close_timeout,
        None => entered,
    }
}

/// Whether the peer has yet to say it is done sending. Tearing a session down in one of these
/// states leaves the application short of data it was never told about, so it is handed a reset
/// rather than an end of stream.
fn peer_still_owes_a_fin(state: TcpState) -> bool {
    matches!(
        state,
        TcpState::Listen | TcpState::SynReceived | TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
    )
}

/// Take a segment carrying the peer's FIN, and report whether the FIN was consumed. The data it
/// carries comes first: a peer that closes right after its last write puts the FIN on that write's
/// segment, and dropping the payload loses the tail of the stream. The FIN counts once the stream
/// reaches it — the application has yet to read what came before it, but the peer has been told
/// those bytes arrived. A FIN past a hole is left for the peer to repeat, with an acknowledgment
/// naming what is still missing, as RFC 9293 § 3.10.7.4 requires. Either way the segment draws
/// exactly one acknowledgment.
fn consume_fin_segment(
    nt: NetworkTuple,
    sender: &PacketSender,
    tcb: &mut Tcb,
    seq: SeqNum,
    payload: Vec<u8>,
    data_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    read_notify: &WakerSlot,
) -> std::io::Result<bool> {
    let len = payload.len() as u32;
    if !payload.is_empty() {
        tcb.add_unordered_packet(seq, payload);
    }
    hand_off_to_reader(tcb, nt, data_tx, read_notify)?;
    let taken = tcb.get_ack() == seq + len;
    if taken {
        tcb.increase_ack();
    } else {
        let state = tcb.get_state();
        log::debug!(
            "{nt} {state:?}: FIN at seq {seq} is ahead of the stream at {}, not consumed",
            tcb.get_ack()
        );
    }
    write_packet_to_device(sender, nt, tcb, None, ACK, None, None)?;
    Ok(taken)
}

/// Refuse a segment belonging to no session, as RFC 9293 § 3.10.7.1 requires: the reset takes
/// its sequence number from the segment's own acknowledgment, or acknowledges the segment when
/// it carries none. Numbered any other way the reset falls outside the peer's receive window,
/// where it is dropped, and the peer goes on retransmitting to a session that no longer exists
/// for its whole retry schedule (minutes on Linux).
fn reset_stray_segment(sender: &PacketSender, tuple: NetworkTuple, tcp: &TcpHeader, payload_len: usize) -> std::io::Result<()> {
    let (flags, seq, ack) = if tcp.ack {
        (RST, tcp.acknowledgment_number, 0)
    } else {
        let consumed = payload_len as u32 + u32::from(tcp.fin);
        (RST | ACK, 0, tcp.sequence_number.wrapping_add(consumed))
    };
    let (src, dst) = (tuple.dst, tuple.src); // Note: The address is reversed here
    let packet = create_raw_packet(src, dst, |_, _| 0, flags, TTL, seq, ack, 0, Vec::new(), SendOptions::default())?;
    sender.send(packet).map_err(|e| std::io::Error::new(UnexpectedEof, e))
}

/// Reset a connection the peer still believes is open, and return whether it reset one.
/// States the local side has already sent a FIN in are left alone: their close is under way and
/// a reset would discard data the peer has acknowledged but not yet handed to its application.
/// CloseWait is not one of them — only the peer has closed, the local side never said anything,
/// and the alternative leaves the peer in FIN_WAIT_2 for good. That state is short-lived anyway:
/// it sends its own FIN once the in-flight queue drains.
fn reset_open_connection(hint: &str, nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> bool {
    let state = tcb.get_state();
    if !matches!(state, TcpState::SynReceived | TcpState::Established | TcpState::CloseWait) {
        return false;
    }
    // At the next sequence number this side would send: where the peer is waiting, and what
    // Linux sends here. Unacknowledged data has usually arrived all the same — only the
    // acknowledgment is outstanding — so a reset at the front of it would land behind the
    // peer's RCV.NXT, where RFC 5961 has it discarded.
    let seq = tcb.get_seq();
    log::debug!("{nt} {state:?}: {hint} resetting the connection at seq {seq}");
    if let Err(err) = write_packet_to_device(sender, nt, tcb, None, RST | ACK, Some(seq), None) {
        log::warn!("{nt} {state:?}: {hint} error sending RST: {err}");
    }
    tcb.change_state(TcpState::Closed);
    tcb.mark_aborted();
    true
}

/// Send the local side's farewell and report the state it moved to: FinWait1 from Established,
/// LastAck from CloseWait. Refuses any other state, and any state with data still
/// unacknowledged — the FIN follows that data, so the caller leaves it to `request_fin` and the
/// session task.
fn send_local_fin(hint: &str, nt: NetworkTuple, sender: &PacketSender, tcb: &mut Tcb) -> std::io::Result<Option<TcpState>> {
    let state = tcb.get_state();
    let next = match state {
        TcpState::Established => TcpState::FinWait1,
        TcpState::CloseWait => TcpState::LastAck,
        _ => {
            log::debug!("{nt} {state:?}: {hint} session is not in a valid state to send FIN, skipping...");
            return Ok(None);
        }
    };
    if tcb.get_inflight_packets_total_len() != 0 {
        log::debug!("{nt} {state:?}: {hint} data is still unacknowledged, the FIN has to follow it");
        return Ok(None);
    }

    log::debug!("{nt} {state:?}: {hint} actively send a farewell packet to the other side...");
    write_packet_to_device(sender, nt, tcb, None, ACK | FIN, None, None)?;
    tcb.increase_seq();
    tcb.change_state(next);
    tcb.clear_fin_request();
    log::debug!("{nt} {next:?}: {hint} now in {next:?} state");

    Ok(Some(next))
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        let nt = self.network_tuple();
        // A flow the application abandons has to reach the peer as a reset; dropping the stream
        // silently leaves it with a connection that is open as far as it knows. The reset goes
        // out here rather than from the task, which is aborted below: the device channel is
        // unbounded, so the send neither blocks nor needs a runtime.
        let state = {
            let mut tcb = self.tcb.lock().unwrap();
            // A CloseWait session with nothing left owed either side ends with a farewell, which
            // leaves the peer's socket closing normally. Anything else — data the application
            // never read, data the peer never acknowledged, or a peer that still thinks the
            // connection is open in both directions — is a reset.
            let nothing_pending = tcb.get_state() == TcpState::CloseWait
                && tcb.get_unordered_packets_total_len() == 0
                && tcb.get_inflight_packets_total_len() == 0;
            let said_goodbye = nothing_pending
                && send_local_fin("[drop]", nt, &self.up_packet_sender, &mut tcb)
                    .inspect_err(|err| log::warn!("{nt}: [drop] error sending FIN: {err}"))
                    .is_ok_and(|state| state.is_some());
            if !said_goodbye {
                reset_open_connection("[drop]", nt, &self.up_packet_sender, &mut tcb);
            }
            tcb.get_state()
        };
        log::trace!("{nt} {state:?}: [drop] session dropping, ========================= ");
        if let Some(task_handle) = self.task_handle.take() {
            if !task_handle.is_finished() {
                if let Some(notifier) = self.exit_notifier.take() {
                    // The channel holds ten slots and one signal ends the task, so the send
                    // needs no runtime of its own.
                    _ = notifier.try_send(());
                }
                // Dropping the task drops its `destroy_messenger`, which wakes the watcher
                // that removes this session from the stack.
                task_handle.abort();
            } else {
                log::trace!("{nt} {state:?}: [drop] task already finished, no need to wait exiting");
            }
        }
        let sessions = SESSION_COUNTER.fetch_sub(1, std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
        log::debug!("{nt} {state:?}: [drop] session dropped, total TCP sessions: {sessions}");
    }
}

impl IpStackTcpStream {
    fn spawn_tasks(&mut self) -> std::io::Result<()> {
        let network_tuple = self.network_tuple();

        // task: data receiving and processing
        let tcb = self.tcb.clone();
        let stream_receiver = self.stream_receiver.take().unwrap();
        let up_packet_sender = self.up_packet_sender.clone();
        let shutdown = self.shutdown.clone();
        let write_notify = self.write_notify.clone();
        let read_notify = self.read_notify.clone();
        let (read_notify_done, write_notify_done) = (self.read_notify.clone(), self.write_notify.clone());
        let data_tx = self.data_tx.clone();
        let rearm = self.rearm.clone();
        let drain_notify = self.drain_notify.clone();
        let destroy_messenger = self.destroy_messenger.take();

        let (exit_task_notifier, exit_monitor) = tokio::sync::mpsc::channel::<()>(10);
        let exit_notifier = exit_task_notifier.clone();
        let config = self.config.clone();
        self.exit_notifier = Some(exit_task_notifier);

        let task_handle = tokio::spawn(async move {
            let v = tcp_main_logic_loop(
                tcb,
                config,
                stream_receiver,
                up_packet_sender,
                exit_notifier,
                network_tuple,
                write_notify,
                read_notify,
                rearm,
                data_tx,
                drain_notify,
                exit_monitor,
            )
            .await;
            if let Err(e) = &v {
                log::warn!("{network_tuple} task error: {e}");
            }
            _ = destroy_messenger.map(|m| m.send(())).unwrap_or(Ok(()));
            log::trace!("{network_tuple} task completed, destroy messenger sent successfully");
            // No more data can arrive after task completion. Wake both halves on every exit path
            // so blocked readers observe the end, even if the loop did not wake them before exiting.
            wake_both(&read_notify_done, &write_notify_done);
            shutdown.lock().unwrap().ready();
            log::trace!("{network_tuple} shutdown.lock().unwrap().ready() ==========");
            v
        });
        self.task_handle = Some(task_handle);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_main_logic_loop(
    tcb: TcbPtr,
    config: Arc<TcpConfig>,
    mut stream_receiver: PacketReceiver,
    up_packet_sender: PacketSender,
    exit_notifier: tokio::sync::mpsc::Sender<()>,
    network_tuple: NetworkTuple,
    write_notify: WakerSlot,
    read_notify: WakerSlot,
    rearm: Arc<tokio::sync::Notify>,
    data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    drain_notify: Arc<tokio::sync::Notify>,
    mut exit_monitor: tokio::sync::mpsc::Receiver<()>,
) -> std::io::Result<()> {
    {
        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state != TcpState::Listen {
            log::warn!("{network_tuple} {state:?}: Invalid TCP state, not in Listen state");
            return Ok::<(), std::io::Error>(());
        }

        tcb.increase_ack();
        let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{network_tuple} {state:?}: {l_info} session begins");
        write_packet_to_device(
            &up_packet_sender,
            network_tuple,
            &mut tcb,
            config.options.as_ref(),
            ACK | SYN,
            None,
            None,
        )?;
        tcb.increase_seq();
        tcb.change_state(TcpState::SynReceived);
        let state = tcb.get_state();
        log::trace!("{network_tuple} {state:?}: session now in {state:?} state");
    }

    let tcb_clone = tcb.clone();

    async fn task_wait_to_close(tcb: TcbPtr, exit_notifier: tokio::sync::mpsc::Sender<()>, nt: NetworkTuple, two_msl: Duration) {
        tokio::time::sleep(two_msl).await;
        {
            let mut tcb = tcb.lock().unwrap();
            tcb.change_state(TcpState::Closed);
            let state = tcb.get_state();
            log::debug!("{nt} {state:?}: [task_wait_to_close] session closed after {two_msl:?}");
        }
        exit_notifier.send(()).await.unwrap_or(());
    }

    async fn task_last_ack(
        tcb: TcbPtr,
        exit_notifier: tokio::sync::mpsc::Sender<()>,
        nt: NetworkTuple,
        pkt_sdr: PacketSender,
        last_ack_timeout: Duration,
        last_ack_max_retries: usize,
    ) {
        let hint = "[task_last_ack]";
        for idx in 1..=last_ack_max_retries {
            let state = { tcb.lock().unwrap().get_state() };
            if state == TcpState::Closed {
                log::debug!("{nt} {state:?}: {hint} session closed, exiting 1...");
                return;
            }

            tokio::time::sleep(last_ack_timeout).await;

            {
                let mut tcb = tcb.lock().unwrap();
                let state = tcb.get_state();
                if state == TcpState::Closed {
                    log::debug!("{nt} {state:?}: {hint} session closed, exiting 2...");
                    return;
                }
                log::debug!("{nt} {state:?}: {hint} timer expired, resending ACK|FIN (retry {idx}/{last_ack_max_retries})");
                _ = write_packet_to_device(&pkt_sdr, nt, &mut tcb, None, ACK | FIN, None, None);
            }
        }
        {
            let mut tcb = tcb.lock().unwrap();
            tcb.change_state(TcpState::Closed);
            let state = tcb.get_state();
            log::warn!("{nt} {state:?}: {hint} max retries reached, forcibly closing session");
        }
        exit_notifier.send(()).await.unwrap_or(());
    }

    // The session is idle from the moment it starts; every packet from the peer pushes the
    // deadline back. A write does not: a peer that is still there acknowledges what it is
    // sent, and one that is not must not be kept alive by our own traffic.
    let mut idle_deadline = tokio::time::Instant::now() + config.timeout;
    // Set when the peer closes its half. The write side stays open, but not forever: an
    // application that neither writes nor closes holds a session the peer has finished with.
    let mut close_wait_deadline: Option<tokio::time::Instant> = None;

    loop {
        let exit_notifier = exit_notifier.clone();

        // Wake on whichever comes first: the retransmission of the earliest in-flight segment,
        // the half-closed session's leash, or the session going idle. Retransmission driven by
        // incoming packets alone never fires for a peer that has stopped sending, which is
        // exactly the peer that needs it.
        let mut deadline = idle_deadline;
        {
            let mut tcb = tcb.lock().unwrap();
            #[cfg(test)]
            tcb.note_wake();
            if let Some(due) = tcb.next_timer_deadline() {
                deadline = deadline.min(tokio::time::Instant::from_std(due));
            }
            if let Some(entered) = close_wait_deadline {
                deadline = deadline.min(half_close_due(&tcb, entered, config.half_close_timeout));
            }
            // The application asked to close while data was in flight, or from a half-closed
            // session the task alone can end: the FIN goes out now that the queue has drained.
            if tcb.fin_requested()
                && let Some(new_state) = send_local_fin("[main loop]", network_tuple, &up_packet_sender, &mut tcb)?
            {
                close_wait_deadline = None;
                if new_state == TcpState::LastAck {
                    let up = up_packet_sender.clone();
                    tokio::spawn(task_last_ack(
                        tcb_clone.clone(),
                        exit_notifier.clone(),
                        network_tuple,
                        up,
                        config.last_ack_timeout,
                        config.last_ack_max_retries,
                    ));
                }
            }
        }

        let network_packet = tokio::select! {
            _ = exit_monitor.recv() => {
                log::debug!("{network_tuple} task exited due to exit signal");
                break;
            }
            // A write has put a segment in flight, so the deadline computed above predates it.
            _ = rearm.notified() => continue,
            _ = drain_notify.notified() => {
                // The upstream reader freed channel space, so flush whatever is buffered. Nothing
                // came from the peer to acknowledge here, so the only reason to send it anything
                // is a window worth hearing about. The session is no less idle for any of this,
                // so `idle_deadline` stays where it is.
                let mut tcb = tcb.lock().unwrap();
                hand_off_to_reader(&mut tcb, network_tuple, &data_tx, &read_notify)?;
                if tcb.get_state() != TcpState::Closed && tcb.window_update_due() {
                    write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
                }
                continue;
            }
            _ = tokio::time::sleep_until(deadline) => {
                let mut tcb = tcb.lock().unwrap();
                if tokio::time::Instant::now() >= idle_deadline {
                    let (state, timeout) = (tcb.get_state(), config.timeout);
                    log::warn!("{network_tuple} {state:?}: nothing received for {timeout:?}, resetting the session");
                    reset_open_connection("[idle]", network_tuple, &up_packet_sender, &mut tcb);
                    if peer_still_owes_a_fin(state) {
                        // The peer never said it was done sending, so whatever it had left is
                        // lost: an end of stream here would report a truncated transfer as whole.
                        tcb.mark_aborted();
                    }
                    tcb.change_state(TcpState::Closed);
                    drop(tcb);
                    wake_both(&read_notify, &write_notify);
                    break;
                }
                // Recompute expiry here: an intervening write can extend the deadline without
                // waking the task.
                if let Some(entered) = close_wait_deadline
                    && tokio::time::Instant::now() >= half_close_due(&tcb, entered, config.half_close_timeout)
                {
                    close_wait_deadline = None;
                    log::warn!("{network_tuple} CloseWait: the local side went quiet without closing, closing it");
                    tcb.request_fin();
                    continue;
                }
                // Half the idle timeout at most: a probe's answer must arrive before the session
                // is declared idle.
                if tcb.take_due_persist_probe(config.timeout / 2) {
                    send_window_probe(network_tuple, &up_packet_sender, &mut tcb)?;
                    continue;
                }
                if retransmit_or_reset(network_tuple, &up_packet_sender, &mut tcb)? {
                    drop(tcb);
                    wake_both(&read_notify, &write_notify);
                    break;
                }
                continue;
            }
            network_packet = stream_receiver.recv() => network_packet,
        };
        idle_deadline = tokio::time::Instant::now() + config.timeout;

        let Some(mut network_packet) = network_packet else {
            let state = { tcb.lock().unwrap().get_state() };
            log::debug!("{network_tuple} {state:?}: session closed unexpectedly by pipe broken, exiting task");
            tcb.lock().unwrap().change_state(TcpState::Closed);
            wake_both(&read_notify, &write_notify);
            break;
        };

        let payload = network_packet.payload.take().unwrap_or_default();
        let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
            log::warn!("{network_tuple} Invalid TCP packet");
            continue;
        };
        let flags = tcp_header_flags(tcp_header);
        let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
        let incoming_seq: SeqNum = tcp_header.sequence_number.into();
        let incoming_win = tcp_header.window_size;
        let incoming_ts = header_timestamp(tcp_header.options.as_slice()).unwrap_or_else(|err| {
            log::debug!("{network_tuple}: malformed options on the segment at {incoming_seq}: {err}");
            None
        });

        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state == TcpState::Closed {
            log::debug!("{network_tuple} {state:?}: session finished, exiting task...");
            break;
        }

        if flags & RST == RST {
            if incoming_seq != tcb.get_ack() {
                // RFC 5961 § 3.2: a reset counts only in sequence. One anywhere else is stale or
                // forged, and draws an acknowledgment naming the sequence a peer that really did
                // reset us must resend it at.
                log::debug!("{network_tuple} {state:?}: out-of-sequence reset at {incoming_seq}, challenging it");
                write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
                continue;
            }
            // End the task and wake both halves so a blocked reader and the stack's session
            // entry do not linger until the idle timeout after a peer reset.
            log::debug!("{network_tuple} {state:?}: reset by the peer, exiting task");
            tcb.change_state(TcpState::Closed);
            // The peer threw away whatever it had left to send, so this is not an end of stream:
            // reporting one would tell the application a cut-off transfer finished.
            tcb.mark_aborted();
            drop(tcb);
            wake_both(&read_notify, &write_notify);
            break;
        }

        // A missing or malformed negotiated timestamp must not bypass PAWS (RFC 7323 § 3.2).
        if tcb.timestamps_negotiated() && incoming_ts.is_none() {
            log::debug!("{network_tuple} {state:?}: missing negotiated timestamp at seq {incoming_seq}, dropping segment");
            continue;
        }

        // Apply PAWS before processing ACKs, windows, or payload (RFC 7323 § 5.3).
        // Resets above retain their sequence check.
        if let Some((tsval, _)) = incoming_ts
            && tcb.paws_rejects(tsval)
        {
            log::debug!("{network_tuple} {state:?}: timestamp {tsval} at seq {incoming_seq} predates TS.Recent, dropping it");
            write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
            continue;
        }

        tcb.update_duplicate_ack_count(incoming_ack);

        // The reading of our own clock the segment echoes, which means something only when the
        // ACK flag is set: RFC 7323 § 3.2 leaves TSecr undefined otherwise.
        let echo = incoming_ts.filter(|_| flags & ACK == ACK).map(|(_, tsecr)| tsecr);
        tcb.update_inflight_packet_queue(incoming_ack, echo);

        if retransmit_or_reset(network_tuple, &up_packet_sender, &mut tcb)? {
            drop(tcb);
            wake_both(&read_notify, &write_notify);
            break;
        }

        let pkt_type = tcb.check_pkt_type(tcp_header, &payload);

        let (state, seq, ack) = { (tcb.get_state(), tcb.get_seq(), tcb.get_ack()) };
        let (info, len) = (tcp_header_fmt(tcp_header), payload.len());
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{network_tuple} {state:?}: {l_info} {info}, {pkt_type:?}, len = {len}");
        // A segment the check above rejects — a reordered duplicate, say — still reports the room
        // the peer had when it was sent, so its window is taken even though its acknowledgment is
        // not: that ends persist mode a probe early. A retransmitted SYN is the exception: its
        // window is unscaled, and the handshake already took it.
        if flags & SYN == 0 {
            let reopened = tcb.get_send_window() == 0 && incoming_win > 0;
            tcb.update_send_window(incoming_win);
            if reopened {
                write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            }
        }

        if pkt_type == PacketType::Invalid {
            continue;
        }

        // Fully consumed duplicates cannot update TS.Recent (RFC 7323 § 5.3, R2/R3).
        // The Last.ACK.sent check in update_ts_recent excludes segments ahead of the stream.
        let sequence_len = len as u32 + u32::from(flags & FIN != 0) + u32::from(flags & SYN != 0);
        let timestamp_eligible = if sequence_len == 0 {
            incoming_seq == ack
        } else {
            tcb.get_recv_window_bytes() != 0 && incoming_seq + sequence_len > ack
        };
        if timestamp_eligible && let Some((tsval, _)) = incoming_ts {
            tcb.update_ts_recent(incoming_seq, tsval);
        }

        // RFC 2018 § 5: the blocks name what the peer holds above the acknowledgment, which is
        // what tells a hole from a segment still on its way. Whatever they show to be missing
        // goes out again, whether the acknowledgment repeated the one before it or advanced over
        // a hole that has since been filled. A connection that negotiated nothing reads none.
        if flags & ACK == ACK && tcb.sack_permitted() {
            let blocks = header_sack_blocks(tcp_header.options.as_slice()).unwrap_or_else(|err| {
                log::debug!("{network_tuple}: malformed options on the segment at {incoming_seq}: {err}");
                Vec::new()
            });
            tcb.record_sack_blocks(&blocks);
            retransmit_sacked_holes(network_tuple, &up_packet_sender, &mut tcb)?;
        }

        match state {
            TcpState::SynReceived if flags & ACK == ACK => {
                if len > 0 {
                    tcb.add_unordered_packet(incoming_seq, payload);
                    deliver_and_ack(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                }
                tcb.change_state(TcpState::Established);
            }
            TcpState::Established => {
                if flags & FIN == 0 {
                    // Everything but a close, whatever else the header carries: a data segment
                    // marked ECE or URG is still a data segment and still has to be acknowledged.
                    match pkt_type {
                        PacketType::WindowUpdate => {
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                        }
                        PacketType::KeepAlive => {
                            write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
                        }
                        // A peer with no room repeats its acknowledgment for every probe, which
                        // reads as a retransmission request; answering one would put an empty
                        // segment on the wire, since nothing fits in a closed window.
                        PacketType::RetransmissionRequest if tcb.get_send_window() == 0 => {}
                        PacketType::RetransmissionRequest => {
                            if let Some((s, p)) = tcb.take_fast_retransmit(incoming_ack) {
                                log::debug!(
                                    "{network_tuple} {state:?}: {l_info}, {pkt_type:?}, retransmission request, seq = {s}, len = {}",
                                    p.len()
                                );
                                write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK | PSH, Some(s), Some(p))?;
                            }
                        }
                        PacketType::NewPacket => {
                            // Data that arrives out of order is buffered like any other, bounded
                            // by the receive window: dropping it makes the peer resend a segment
                            // we already hold, and the whole window behind it along with it.
                            tcb.add_unordered_packet(incoming_seq, payload);
                            let nt = network_tuple;
                            deliver_and_ack(&up_packet_sender, &mut tcb, nt, &data_tx, &read_notify)?;
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                        }
                        PacketType::Ack => {
                            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                        }
                        PacketType::Invalid => {}
                    }
                } else if flags & (ACK | FIN) == (ACK | FIN) {
                    // The other side is closing. Its FIN may ride on the segment carrying its
                    // last data, PSH and all, so nothing past ACK|FIN decides here.
                    let nt = network_tuple;
                    let taken = consume_fin_segment(nt, &up_packet_sender, &mut tcb, incoming_seq, payload, &data_tx, &read_notify)?;
                    if taken {
                        // Only the peer's half is over. Ours stays open until the application
                        // closes it, so a reply written after the peer's `shutdown(SHUT_WR)`
                        // still gets out.
                        tcb.change_state(TcpState::CloseWait);
                        tcb.forget_writes();
                        close_wait_deadline = Some(tokio::time::Instant::now() + config.close_wait_timeout);
                        let s = tcb.get_state();
                        log::debug!("{network_tuple} {s:?}: {l_info}, {pkt_type:?}, the peer closed its half of the connection");
                        // The reader has an end of stream to report, the writer a window to use.
                        wake_both(&read_notify, &write_notify);
                    }
                } else {
                    // unnormal case, we do nothing here
                    log::trace!("{network_tuple} {state:?}: {l_info}, {pkt_type:?}, unnormal case, we do nothing here");
                }
            }
            TcpState::CloseWait => {
                // The peer is only acknowledging what we send it now, or repeating the farewell
                // whose acknowledgment it lost. Answering that costs one segment and saves it a
                // whole retransmission schedule; waking the writer is the rest of the work here,
                // because our own farewell waits for the application to ask for it.
                if flags & FIN == FIN || incoming_seq < tcb.get_ack() {
                    write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
                }
                write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            }
            TcpState::LastAck => {
                if flags & FIN == FIN || incoming_seq < tcb.get_ack() {
                    // The peer repeated its FIN: our acknowledgment of it was lost, and only
                    // another one stops it retransmitting for its whole retry schedule.
                    write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
                }
                if flags & ACK == ACK && incoming_ack == tcb.get_seq() {
                    tcb.change_state(TcpState::Closed);
                    tokio::spawn(async move {
                        if let Err(e) = exit_notifier.send(()).await {
                            log::debug!("exit_notifier send failed: {e}");
                        }
                    });
                    let new_state = tcb.get_state();
                    log::trace!("{network_tuple} {state:?}: Received final ACK, transitioned to {new_state:?}");
                }
            }
            TcpState::FinWait1 => {
                if flags & (ACK | FIN) == (ACK | FIN) {
                    // The peer's farewell, with the data it may carry. If it acknowledges our own
                    // FIN the teardown is over; if not, the two closes crossed and ours is still
                    // outstanding, which is what RFC 9293's CLOSING waits for.
                    let nt = network_tuple;
                    let ours_acknowledged = incoming_ack == tcb.get_seq();
                    let taken = consume_fin_segment(nt, &up_packet_sender, &mut tcb, incoming_seq, payload, &data_tx, &read_notify)?;
                    if taken {
                        if ours_acknowledged {
                            tcb.change_state(TcpState::TimeWait);
                            tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier, network_tuple, config.two_msl));
                        } else {
                            tcb.change_state(TcpState::Closing);
                        }
                        let new_state = tcb.get_state();
                        log::trace!("{network_tuple} {state:?}: the peer's ACK|FIN arrived, transitioned to {new_state:?}");
                    }
                } else if flags & ACK == ACK {
                    tcb.change_state(TcpState::FinWait2);
                    if len > 0 {
                        // if the other side is still sending data, we need to deal with it like PacketStatus::NewPacket
                        tcb.add_unordered_packet(incoming_seq, payload);
                        deliver_and_ack(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                        write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                    }
                    let new_state = tcb.get_state();
                    log::trace!("{network_tuple} {state:?}: Received ACK, transitioned to {new_state:?}");
                } else {
                    // unnormal case, we do nothing here
                    log::trace!("{network_tuple} {state:?}: Some unnormal case, we do nothing here");
                }
            }
            TcpState::FinWait2 => {
                if flags & (ACK | FIN) == (ACK | FIN) {
                    let nt = network_tuple;
                    let taken = consume_fin_segment(nt, &up_packet_sender, &mut tcb, incoming_seq, payload, &data_tx, &read_notify)?;
                    if taken {
                        tcb.change_state(TcpState::TimeWait);
                        tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier, network_tuple, config.two_msl));
                        let new_state = tcb.get_state();
                        log::trace!("{network_tuple} {state:?}: Received final ACK|FIN, transitioned to {new_state:?}");
                    }
                    write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                } else if flags & ACK == ACK && len == 0 {
                    // unnormal case, we do nothing here
                    let l_ack = tcb.get_ack();
                    if incoming_seq < l_ack {
                        log::trace!("{network_tuple} {state:?}: Ignoring duplicate ACK, seq {incoming_seq}, expected {l_ack}");
                    }
                } else if flags & ACK == ACK && len > 0 {
                    if pkt_type == PacketType::KeepAlive {
                        write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
                    } else {
                        // if the other side is still sending data, we need to deal with it like PacketStatus::NewPacket
                        tcb.add_unordered_packet(incoming_seq, payload);
                        deliver_and_ack(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
                        write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                    }
                } else {
                    // unnormal case, we do nothing here
                    log::trace!("{network_tuple} {state:?}: Some unnormal case, we do nothing here");
                }
            }
            TcpState::Closing if incoming_ack == tcb.get_seq() => {
                // Our farewell is acknowledged at last; only the quiet period is left.
                tcb.change_state(TcpState::TimeWait);
                tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier, network_tuple, config.two_msl));
                let new_state = tcb.get_state();
                log::trace!("{network_tuple} {state:?}: Received final ACK, transitioned to {new_state:?}");
            }
            TcpState::TimeWait if flags & (ACK | FIN) == (ACK | FIN) => {
                write_packet_to_device(&up_packet_sender, network_tuple, &mut tcb, None, ACK, None, None)?;
                // wait to timeout, can't call `tcb.change_state(TcpState::Closed);` to change state here
                // now we need to wait for the timeout to reach...
            }
            _ => {}
        } // end of match state

        tcb.update_last_received_ack(incoming_ack);
    } // end of loop
    Ok::<(), std::io::Error>(())
}

/// Deliver acknowledged data, one chunk per free channel slot, and report whether any moved.
/// Callers handle ACKs: receipt is independent of application reads. Delivery applies in every
/// state because acknowledged data belongs to the application even after the connection ends.
fn hand_off_to_reader(
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    data_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    read_notify: &WakerSlot,
) -> std::io::Result<bool> {
    let mut handed_over = 0usize;
    loop {
        // Reserve the handoff slot before consuming, so buffered data is removed only once it has
        // a guaranteed home.
        let permit = match data_tx.try_reserve() {
            Ok(permit) => permit,
            Err(tokio::sync::mpsc::error::TrySendError::Full(())) => break,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                return Err(std::io::Error::new(BrokenPipe, "data channel closed"));
            }
        };
        let Some(data) = tcb.consume_unordered_packets(READ_CHUNK) else {
            break;
        };
        handed_over += data.len();
        permit.send(data);
    }
    if handed_over > 0 {
        let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
        log::trace!("{network_tuple} {state:?}: local {{ seq: {seq}, ack: {ack} }} handed {handed_over} bytes to the reader");
        // One wake for the whole batch: the reader drains the channel, not a chunk of it.
        read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
    }
    Ok(handed_over > 0)
}

/// Deliver what the reader has room for and acknowledge the segment that arrived: RCV.NXT, the
/// window as it now stands, and blocks for whatever holes are left. Every segment carrying data
/// draws exactly one of these, duplicates included — a peer missing a segment learns of it from
/// the duplicate acknowledgments its later data draws (RFC 5681 § 3.2).
fn deliver_and_ack(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    data_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    read_notify: &WakerSlot,
) -> std::io::Result<()> {
    hand_off_to_reader(tcb, network_tuple, data_tx, read_notify)?;
    let state = tcb.get_state();
    if state == TcpState::Closed {
        log::debug!("{network_tuple} {state:?}: session closed, nothing left to acknowledge");
        return Ok(());
    }
    write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
    Ok(())
}

/// Send a TCP packet to the downstream device, with the specified flags, sequence number, and payload.
/// The returned value is the length of the `payload` sent, it may be shorter than the length of the incoming parameter `payload`.
pub(crate) fn write_packet_to_device(
    up_packet_sender: &PacketSender,
    tuple: NetworkTuple,
    tcb: &mut Tcb,
    options: Option<&Vec<TcpOptions>>,
    flags: u8,
    seq: Option<SeqNum>,
    payload: Option<Vec<u8>>,
) -> std::io::Result<usize> {
    use std::io::Error;
    let seq = seq.unwrap_or(tcb.get_seq()).0;
    // Silly-window-syndrome avoidance, in bytes: advertise a real window only when a full segment
    // fits, otherwise advertise zero so the peer enters persist mode until the reader frees space.
    let window_bytes = tcb.window_to_advertise();
    // Our scale rides on the SYN-ACK and applies from the segment after it: the handshake's own
    // window is read unscaled by both sides (RFC 7323 § 2.2).
    let (window_size, window_scale) = match flags & SYN {
        0 => (tcb.scale_recv_window(window_bytes), None),
        _ => (window_bytes.min(u16::MAX as usize) as u16, tcb.get_recv_window_shift()),
    };
    let ack = tcb.get_ack().0;
    let (src, dst) = (tuple.dst, tuple.src); // Note: The address is reversed here
    let mut send_options = SendOptions {
        window_scale,
        // Once negotiated the option goes on everything we send, the handshake included, since
        // the peer times the round trip off whichever of our segments its acknowledgment answers
        // (RFC 7323 § 3.2).
        timestamp: tcb.timestamp_to_send(),
        // RFC 2018 § 2 agrees the option in the handshake, so it rides on the SYN-ACK alone.
        sack_permitted: flags & SYN != 0 && tcb.sack_permitted(),
        ..SendOptions::default()
    };
    // RFC 2018 § 3: an acknowledgment that stops at a hole names the ranges beyond it, so the
    // peer can see which of its segments went missing and resend only those. The handshake has
    // nothing to report yet, and a reset is not an acknowledgment of anything.
    if flags & (SYN | RST) == 0 {
        let blocks = tcb.sack_blocks_to_send();
        for (slot, (start, end)) in send_options.selective_ack.iter_mut().zip(blocks) {
            *slot = Some((start.0, end.0));
        }
    }
    for option in options.into_iter().flatten() {
        match option {
            TcpOptions::MaximumSegmentSize(mss) => send_options.max_segment_size = Some(*mss),
        }
    }
    let calc = |ip_header_len: usize, tcp_header_len: usize| tcb.calculate_payload_max_len(ip_header_len, tcp_header_len);
    let packet = create_raw_packet(
        src,
        dst,
        calc,
        flags,
        TTL,
        seq,
        ack,
        window_size,
        payload.unwrap_or_default(),
        send_options,
    )?;
    let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
    if flags & ACK != 0 {
        // The peer learns where the stream stands from this segment, so it is the one that may
        // attribute a later timestamp to it (RFC 7323 § 4.3), and the window it carries is the
        // one a later update is measured against.
        tcb.note_ack_sent();
        tcb.note_window_advertised(window_size, flags & SYN != 0);
    }
    up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
    Ok(len)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_raw_packet(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    calculate_payload_max_len: impl Fn(usize, usize) -> usize,
    flags: u8,
    ttl: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mut payload: Vec<u8>,
    options: SendOptions,
) -> std::io::Result<NetworkPacket> {
    let mut tcp_header = etherparse::TcpHeader::new(src_addr.port(), dst_addr.port(), seq, win);
    tcp_header.acknowledgment_number = ack;
    tcp_header.syn = flags & SYN != 0;
    tcp_header.ack = flags & ACK != 0;
    tcp_header.rst = flags & RST != 0;
    tcp_header.fin = flags & FIN != 0;
    tcp_header.psh = flags & PSH != 0;

    // Set before the payload is sized: the length of these options is part of the header the
    // payload has to fit behind, in the link's MTU and in the peer's MSS alike.
    let tcp_options = options.elements();
    if !tcp_options.is_empty() {
        tcp_header
            .set_options(&tcp_options)
            .map_err(|e| std::io::Error::new(InvalidInput, e))?;
    }
    let ip_header = match (src_addr.ip(), dst_addr.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut ip_h =
                Ipv4Header::new(0, ttl, IpNumber::TCP, src.octets(), dst.octets()).map_err(|e| std::io::Error::new(InvalidInput, e))?;
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            ip_h.dont_fragment = true;
            IpHeader::Ipv4(ip_h)
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut ip_h = etherparse::Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: 0,
                next_header: IpNumber::TCP,
                hop_limit: ttl,
                source: src.octets(),
                destination: dst.octets(),
            };
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            let len = payload.len() + tcp_header.header_len();
            ip_h.set_payload_length(len).map_err(|e| std::io::Error::new(InvalidInput, e))?;

            IpHeader::Ipv6(ip_h)
        }
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "IP version mismatch")),
    };

    match ip_header {
        IpHeader::Ipv4(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv4(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
        IpHeader::Ipv6(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv6(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
    }
    Ok(NetworkPacket {
        ip: ip_header,
        transport: TransportHeader::Tcp(tcp_header),
        payload: Some(payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketReceiver;
    use crate::stream::tcb::{MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_UNACK, READ_BUFFER_SIZE, RTO};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PEER: &str = "10.0.0.2:40000";
    const SERVER: &str = "93.184.216.34:443";
    const PEER_ISN: u32 = 1_000;

    fn addrs() -> (SocketAddr, SocketAddr) {
        (PEER.parse().unwrap(), SERVER.parse().unwrap())
    }

    /// Build a peer segment for the stream's receiver. The payload cap exceeds all test payloads,
    /// so the caller controls the segment's length.
    fn segment(flags: u8, seq: u32, ack: u32, payload: Vec<u8>) -> NetworkPacket {
        segment_with_window(flags, seq, ack, payload, 64240)
    }

    /// The same, advertising a receive window of the peer's choosing.
    fn segment_with_window(flags: u8, seq: u32, ack: u32, payload: Vec<u8>, window: u16) -> NetworkPacket {
        segment_with_scale(flags, seq, ack, payload, window, None)
    }

    /// The same again, offering the peer's window scale — only ever meaningful on a SYN.
    fn segment_with_scale(flags: u8, seq: u32, ack: u32, payload: Vec<u8>, window: u16, shift: Option<u8>) -> NetworkPacket {
        let options = SendOptions {
            window_scale: shift,
            ..SendOptions::default()
        };
        segment_with_options(flags, seq, ack, payload, window, options)
    }

    /// A peer segment carrying options of the caller's making.
    fn segment_with_options(flags: u8, seq: u32, ack: u32, payload: Vec<u8>, window: u16, options: SendOptions) -> NetworkPacket {
        let (src, dst) = addrs();
        create_raw_packet(src, dst, |_, _| 60_000, flags, TTL, seq, ack, window, payload, options).unwrap()
    }

    /// A peer segment timestamped with the peer's clock, echoing a reading of ours.
    fn segment_with_timestamp(flags: u8, seq: u32, ack: u32, payload: Vec<u8>, tsval: u32, tsecr: u32) -> NetworkPacket {
        let options = SendOptions {
            timestamp: Some((tsval, tsecr)),
            ..SendOptions::default()
        };
        segment_with_options(flags, seq, ack, payload, 64240, options)
    }

    /// A SYN offering timestamps.
    fn syn_with_timestamp(tsval: u32) -> NetworkPacket {
        segment_with_timestamp(SYN, PEER_ISN, 0, Vec::new(), tsval, 0)
    }

    /// A SYN announcing the peer's maximum segment size: the largest payload it will receive.
    fn syn_with_mss(mss: u16) -> NetworkPacket {
        let options = SendOptions {
            max_segment_size: Some(mss),
            ..SendOptions::default()
        };
        segment_with_options(SYN, PEER_ISN, 0, Vec::new(), 64240, options)
    }

    /// The payload lengths of the segments the stack sends, until `total` bytes have gone out.
    async fn sent_payload_lengths(up_rx: &mut PacketReceiver, total: usize) -> Vec<usize> {
        let mut lengths: Vec<usize> = Vec::new();
        while lengths.iter().sum::<usize>() < total {
            let packet = next_packet(up_rx).await;
            match packet.payload.as_ref().map(|p| p.len()).unwrap_or(0) {
                0 => continue,
                len => lengths.push(len),
            }
        }
        lengths
    }

    /// Poll once into `buf` with a no-op waker, returning readiness without waiting.
    fn poll_read_once(stream: &mut IpStackTcpStream, buf: &mut [u8]) -> Poll<std::io::Result<()>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        let mut cx = Context::from_waker(Waker::noop());
        std::pin::Pin::new(stream).poll_read(&mut cx, &mut read_buf)
    }

    /// The window scale a header carries, if any.
    fn window_scale(header: &TcpHeader) -> Option<u8> {
        header.options_iterator().flatten().find_map(|option| match option {
            TcpOptionElement::WindowScale(shift) => Some(shift),
            _ => None,
        })
    }

    /// The TSval and TSecr a header carries, if any.
    fn timestamp(header: &TcpHeader) -> Option<(u32, u32)> {
        header_timestamp(header.options.as_slice()).unwrap()
    }

    /// Whether a header offers SACK-Permitted.
    fn sack_permitted(header: &TcpHeader) -> bool {
        syn_sack_permitted(header.options.as_slice()).unwrap()
    }

    /// The SACK blocks a header carries, in the order it reports them.
    fn sack_blocks(header: &TcpHeader) -> Vec<(u32, u32)> {
        header
            .options_iterator()
            .flatten()
            .find_map(|option| match option {
                TcpOptionElement::SelectiveAcknowledgement(first, rest) => {
                    Some(std::iter::once(first).chain(rest.into_iter().flatten()).collect())
                }
                _ => None,
            })
            .unwrap_or_default()
    }

    /// A SYN offering selective acknowledgment.
    fn syn_with_sack() -> NetworkPacket {
        let options = SendOptions {
            sack_permitted: true,
            ..SendOptions::default()
        };
        segment_with_options(SYN, PEER_ISN, 0, Vec::new(), 64240, options)
    }

    fn header(packet: &NetworkPacket) -> &TcpHeader {
        match packet.transport_header() {
            TransportHeader::Tcp(header) => header,
            _ => panic!("not a TCP packet"),
        }
    }

    /// The next packet the stack sends to the peer, or a failure if it sends none.
    async fn next_packet(up_rx: &mut PacketReceiver) -> NetworkPacket {
        tokio::time::timeout(Duration::from_secs(5), up_rx.recv())
            .await
            .expect("timed out waiting for a packet to the peer")
            .expect("the packet channel was closed")
    }

    /// Return the next peer-bound packet accepted by the predicate, skipping earlier packets.
    async fn packet_matching(up_rx: &mut PacketReceiver, want: impl Fn(&TcpHeader) -> bool) -> TcpHeader {
        loop {
            let packet = next_packet(up_rx).await;
            if want(header(&packet)) {
                return header(&packet).clone();
            }
        }
    }

    /// A stream whose handshake with the peer is complete.
    async fn established(up_tx: PacketSender, up_rx: &mut PacketReceiver, config: TcpConfig) -> IpStackTcpStream {
        established_with_messenger(up_tx, up_rx, config, None).await
    }

    /// Complete the handshake and report session termination through `messenger`, which the
    /// stack uses to remove the session from its table.
    async fn established_with_messenger(
        up_tx: PacketSender,
        up_rx: &mut PacketReceiver,
        config: TcpConfig,
        messenger: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> IpStackTcpStream {
        let syn = segment(SYN, PEER_ISN, 0, Vec::new());
        established_from_syn(up_tx, up_rx, config, messenger, syn).await.0
    }

    /// The same from a SYN of the caller's making, returning the SYN-ACK it was answered with.
    async fn established_from_syn(
        up_tx: PacketSender,
        up_rx: &mut PacketReceiver,
        config: TcpConfig,
        messenger: Option<tokio::sync::oneshot::Sender<()>>,
        syn: NetworkPacket,
    ) -> (IpStackTcpStream, TcpHeader) {
        established_from_syn_over(up_tx, up_rx, config, messenger, syn, 1500).await
    }

    /// Establish from the supplied SYN and local MTU, returning the stream and SYN-ACK.
    async fn established_from_syn_over(
        up_tx: PacketSender,
        up_rx: &mut PacketReceiver,
        config: TcpConfig,
        messenger: Option<tokio::sync::oneshot::Sender<()>>,
        syn: NetworkPacket,
        mtu: u16,
    ) -> (IpStackTcpStream, TcpHeader) {
        let (src, dst) = addrs();
        let stream = IpStackTcpStream::new(src, dst, header(&syn).clone(), 0, up_tx, mtu, messenger, Arc::new(config)).unwrap();
        let synack = header(&next_packet(up_rx).await).clone();
        assert_eq!(tcp_header_flags(&synack), SYN | ACK);
        let ours = synack.sequence_number.wrapping_add(1);
        let options = SendOptions {
            timestamp: timestamp(&synack).map(|(ours, peer)| (peer, ours)),
            ..SendOptions::default()
        };
        stream
            .stream_sender()
            .send(segment_with_options(ACK, PEER_ISN + 1, ours, Vec::new(), 64240, options))
            .unwrap();
        for _ in 0..500 {
            if stream.tcb.lock().unwrap().get_state() == TcpState::Established {
                return (stream, synack);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("the handshake never completed");
    }

    /// Poll `done` for up to a second, then panic with `never`.
    async fn wait_until(mut done: impl FnMut() -> bool, never: &str) {
        for _ in 0..500 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("{never}");
    }

    /// A flow the application gives up on has to reach the peer as a reset, and the session then
    /// leaves the stack without the drop waiting on anything: this runs on a current-thread
    /// runtime, which refuses a blocking wait outright.
    #[tokio::test]
    async fn dropping_an_established_stream_resets_the_peer() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (messenger, ended) = tokio::sync::oneshot::channel();
        let stream = established_with_messenger(up_tx, &mut up_rx, TcpConfig::default(), Some(messenger)).await;
        let ours = stream.tcb.lock().unwrap().get_seq().0;
        drop(stream);
        let reset = next_packet(&mut up_rx).await;
        assert_eq!(tcp_header_flags(header(&reset)), RST | ACK);
        // The peer discards a reset carrying any other sequence number as out of window.
        assert_eq!(header(&reset).sequence_number, ours);
        tokio::time::timeout(Duration::from_secs(5), ended)
            .await
            .expect("the session never reported its end")
            .ok();
    }

    /// The reset a dropped stream sends has to land where the peer is waiting: at the next
    /// sequence number this side would send, not at the front of data still in flight.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_drop_with_data_in_flight_resets_past_the_data() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        stream.write_all(b"hello").await.unwrap();
        let data = next_packet(&mut up_rx).await;
        assert_eq!(tcp_header_flags(header(&data)), ACK | PSH);
        let after_data = header(&data).sequence_number.wrapping_add(5);

        // Nothing acknowledges the write, so the five bytes are still in flight.
        drop(stream);
        let reset = packet_matching(&mut up_rx, |h| h.rst).await;
        assert_eq!(tcp_header_flags(&reset), RST | ACK);
        assert_eq!(reset.sequence_number, after_data, "the reset was behind the peer's window");
    }

    /// Feed a segment to a stack that has no session for it, and return the reset it answers with.
    async fn reset_for(stray: &NetworkPacket, payload_len: usize) -> TcpHeader {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (src, dst) = addrs();
        let config = Arc::new(TcpConfig::default());
        let err = IpStackTcpStream::new(src, dst, header(stray).clone(), payload_len, up_tx, 1500, None, config)
            .expect_err("a segment without SYN opens no session");
        assert_eq!(std::io::Error::from(err).kind(), ConnectionRefused);
        header(&next_packet(&mut up_rx).await).clone()
    }

    /// A segment for a connection the stack no longer has must be reset from the segment's own
    /// acknowledgment (RFC 9293 § 3.10.7.1): a reset carrying any other sequence number is
    /// outside the peer's receive window, and the peer drops it and keeps retransmitting.
    #[tokio::test]
    async fn a_segment_for_an_unknown_connection_is_reset() {
        let reset = reset_for(&segment(ACK | PSH, PEER_ISN + 1, 5_000, vec![7; 12]), 12).await;
        assert_eq!(tcp_header_flags(&reset), RST);
        assert_eq!(reset.sequence_number, 5_000);
        assert_eq!(reset.acknowledgment_number, 0);
    }

    /// Without an incoming ACK, the reset starts at zero and acknowledges the payload and FIN.
    #[tokio::test]
    async fn a_segment_with_no_acknowledgment_is_reset_from_zero() {
        let reset = reset_for(&segment(FIN, PEER_ISN, 0, vec![7; 12]), 12).await;
        assert_eq!(tcp_header_flags(&reset), RST | ACK);
        assert_eq!(reset.sequence_number, 0);
        assert_eq!(reset.acknowledgment_number, PEER_ISN + 12 + 1);
    }

    /// A peer that stops acknowledging sends nothing at all, so retransmission has to run off its
    /// own timer: the segment goes out again on a doubling timeout, and the connection is reset
    /// once the retries are used up.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unacknowledged_segment_is_retransmitted_then_reset() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            rto: Duration::from_millis(20),
            max_retransmit_count: 2,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let snd_una = stream.tcb.lock().unwrap().get_seq().0;
        stream.write_all(b"hello").await.unwrap();

        let mut retransmissions = 0;
        let reset = loop {
            let packet = next_packet(&mut up_rx).await;
            match tcp_header_flags(header(&packet)) {
                flags if flags == RST | ACK => break header(&packet).clone(),
                flags if flags == ACK | PSH => retransmissions += 1,
                flags => panic!("unexpected packet {flags:08b}"),
            }
        };
        // The first ACK|PSH is the write itself, every later one a retransmission.
        assert_eq!(retransmissions, 1 + 2, "the segment was not retransmitted twice");
        // The peer never took the segment, so it is still waiting at the front of it; a reset
        // anywhere past that is outside its window and RFC 5961 has it answer, not close.
        assert_eq!(reset.sequence_number, snd_una, "the reset was not where the peer is waiting");
    }

    #[test]
    fn invalid_rto_bounds_reject_the_stream_before_sending() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (src, dst) = addrs();
        let syn = segment(SYN, PEER_ISN, 0, Vec::new());
        let config = TcpConfig {
            max_rto: Duration::from_millis(100),
            ..TcpConfig::default()
        };
        let err = IpStackTcpStream::new(src, dst, header(&syn).clone(), 0, up_tx, 1500, None, Arc::new(config))
            .expect_err("reversed RTO bounds opened a session");
        assert_eq!(std::io::Error::from(err).kind(), InvalidInput);
        assert!(up_rx.try_recv().is_err());
    }

    /// The timer runs on the round trip the peer is answering in, not on the second the connection
    /// starts with: one segment lost to a peer a hop away costs the floor, not a stall the
    /// application can feel.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_segment_is_retransmitted_at_the_measured_timeout() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            min_rto: Duration::from_millis(50),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();

        // A write the peer acknowledges at once, which is the connection's only measurement.
        stream.write_all(b"hello").await.unwrap();
        let data = next_packet(&mut up_rx).await;
        let after_data = header(&data).sequence_number.wrapping_add(5);
        sender.send(segment(ACK, PEER_ISN + 1, after_data, Vec::new())).unwrap();
        wait_until(
            || tcb.lock().unwrap().rto() == Duration::from_millis(50),
            "the round trip was never measured",
        )
        .await;

        // The next segment is never acknowledged, so it comes back on the measured timeout.
        let sent = tokio::time::Instant::now();
        stream.write_all(b"lost").await.unwrap();
        assert_eq!(tcp_header_flags(header(&next_packet(&mut up_rx).await)), ACK | PSH);
        let again = next_packet(&mut up_rx).await;
        assert_eq!(tcp_header_flags(header(&again)), ACK | PSH);
        assert_eq!(header(&again).sequence_number, after_data, "another segment came back");
        let waited = sent.elapsed();
        assert!(waited >= Duration::from_millis(50), "the retransmission overtook the timeout");
        assert!(waited < Duration::from_millis(500), "the retransmission waited {waited:?}");
    }

    /// The session timeout belongs to the session, not to a reader: a stream nobody is polling
    /// is exactly the one a peer that has gone away leaves behind.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_session_times_out_with_nobody_polling_it() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // Comfortably longer than the poll interval the handshake helper above waits on.
        let config = TcpConfig {
            timeout: Duration::from_millis(300),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;

        let reset = next_packet(&mut up_rx).await;
        assert_eq!(tcp_header_flags(header(&reset)), RST | ACK);
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 64])).await;
        let err = read
            .expect("the reader was never woken")
            .expect_err("the timeout read as a clean end");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    /// Data the session acknowledged to the peer is the application's even when the stack itself
    /// ends the connection: an idle timeout must not throw away bytes the peer was told arrived.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_timeout_still_delivers_what_was_acknowledged() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            timeout: Duration::from_millis(300),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 4000])).unwrap();
        // The peer then goes quiet and the session times out.
        let reset = packet_matching(&mut up_rx, |h| h.rst).await;
        assert_eq!(tcp_header_flags(&reset), RST | ACK);

        let mut buf = vec![0u8; 4000];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the acknowledged data was discarded with the connection")
            .unwrap();
        assert!(buf.iter().all(|&b| b == 1));
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 64])).await;
        let err = read
            .expect("the reader was never woken")
            .expect_err("the reset read as a clean end of stream");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    /// A connection the stack itself gave up on has to read as an error, not as the end of the
    /// stream: a proxy told the transfer finished shuts down one half and keeps waiting on the
    /// other, holding open exactly the flow the teardown was there to reclaim.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_the_stack_resets_reads_as_an_error() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            rto: Duration::from_millis(20),
            max_retransmit_count: 2,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        stream.write_all(b"hello").await.unwrap();

        // Nothing acknowledges the write, so the retransmissions run out and reset the flow.
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        let err = read
            .expect("the reader was never woken")
            .expect_err("the reader saw a clean end of stream");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    /// A close while peer-bound data is unacknowledged still reaches the peer as a FIN — sent
    /// after that data, once the peer acknowledges it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_close_with_data_in_flight_sends_the_fin_after_the_ack() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            two_msl: Duration::from_millis(50),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        stream.write_all(b"hello").await.unwrap();
        let data = next_packet(&mut up_rx).await;
        assert_eq!(tcp_header_flags(header(&data)), ACK | PSH);
        let after_data = header(&data).sequence_number.wrapping_add(5);

        // The application is done writing, but the peer has not acknowledged the data yet.
        let tcb = stream.tcb.clone();
        let closing = tokio::spawn(async move { stream.shutdown().await });
        wait_until(|| tcb.lock().unwrap().fin_requested(), "the close was never taken up").await;
        assert!(up_rx.try_recv().is_err(), "the FIN overtook the data");

        sender.send(segment(ACK, PEER_ISN + 1, after_data, Vec::new())).unwrap();
        let fin = next_packet(&mut up_rx).await;
        assert_eq!(tcp_header_flags(header(&fin)), ACK | FIN);
        // The FIN sits right after the data, so the peer reads the whole transfer before the end.
        assert_eq!(header(&fin).sequence_number, after_data);

        // The peer closes in turn, and the shutdown the application is waiting on completes.
        let fin_seq = header(&fin).sequence_number.wrapping_add(1);
        sender.send(segment(ACK | FIN, PEER_ISN + 1, fin_seq, Vec::new())).unwrap();
        tokio::time::timeout(Duration::from_secs(5), closing)
            .await
            .expect("the shutdown never completed")
            .unwrap()
            .unwrap();
    }

    /// A reset from the peer ends the flow for the application too: the task tears the session
    /// down and wakes both halves, so a blocked reader is handed an error — not a clean end,
    /// since the peer discarded whatever it had left to send.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_reset_wakes_a_blocked_reader() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let mut buf = [0u8; 64];
        let (read, ()) = tokio::join!(
            async { tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await },
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                sender.send(segment(RST | ACK, PEER_ISN + 1, 101, Vec::new())).unwrap();
            }
        );
        let err = read.expect("the reader was never woken").expect_err("a reset read as a clean end");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    /// A reset is taken only in sequence (RFC 5961 § 3.2). One from anywhere else is stale or
    /// forged and draws an acknowledgment, not a teardown.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_out_of_sequence_reset_is_challenged() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();

        sender.send(segment(RST | ACK, PEER_ISN + 5_000, 101, Vec::new())).unwrap();
        let challenge = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(
            challenge.acknowledgment_number,
            PEER_ISN + 1,
            "the challenge named the wrong sequence"
        );
        assert_eq!(
            stream.tcb.lock().unwrap().get_state(),
            TcpState::Established,
            "a stray reset closed the session"
        );
    }

    /// A peer whose receive window is closed is flow-controlled, not gone: the stack probes it
    /// rather than retransmitting into it, never gives up on it however long it takes, and picks
    /// the transfer back up — the writer included — when the window reopens.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_closed_peer_window_is_probed_not_reset() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            rto: Duration::from_millis(20),
            max_retransmit_count: 2,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let snd_una = tcb.lock().unwrap().get_seq().0;

        stream.write_all(b"hello").await.unwrap();
        assert_eq!(tcp_header_flags(header(&next_packet(&mut up_rx).await)), ACK | PSH);
        // The peer has no room for it and says so, without acknowledging it.
        sender.send(segment_with_window(ACK, PEER_ISN + 1, snd_una, Vec::new(), 0)).unwrap();

        let (_, (probes, data_segments)) = tokio::join!(
            async {
                wait_until(|| tcb.lock().unwrap().get_send_window() == 0, "the window never closed").await;
                tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"more"))
                    .await
                    .expect("the writer was never woken past the closed window")
                    .unwrap();
            },
            async {
                // Well past the retransmission budget: two retries off a 20ms timer that doubles.
                let (mut probes, mut data_segments) = (0, 0);
                let until = tokio::time::Instant::now() + Duration::from_millis(800);
                while let Ok(Some(packet)) = tokio::time::timeout_at(until, up_rx.recv()).await {
                    let header = header(&packet);
                    assert_eq!(tcp_header_flags(header) & RST, 0, "a flow-controlled peer was reset");
                    if packet.payload.as_ref().map_or(0, |p| p.len()) > 0 {
                        data_segments += 1;
                    } else if header.sequence_number == snd_una.wrapping_sub(1) {
                        probes += 1;
                    }
                }
                sender
                    .send(segment_with_window(ACK, PEER_ISN + 1, snd_una, Vec::new(), 64240))
                    .unwrap();
                (probes, data_segments)
            }
        );
        assert!(probes >= 2, "the closed window drew {probes} probes");
        // Nothing but the probes: a closed window truncates a retransmission to nothing, and
        // those empty segments would count against the retransmission budget.
        assert_eq!(data_segments, 0, "the closed window was retransmitted into");
    }

    /// A peer that answers every probe is flow-controlled, not silent, however long it holds the
    /// window shut. Probing more slowly than the session tolerates silence would have the idle
    /// timeout reset the very peer the probes are waiting for.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_that_answers_probes_is_never_declared_idle() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            rto: Duration::from_millis(20),
            timeout: Duration::from_millis(200),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let snd_una = stream.tcb.lock().unwrap().get_seq().0;

        stream.write_all(b"hello").await.unwrap();
        sender.send(segment_with_window(ACK, PEER_ISN + 1, snd_una, Vec::new(), 0)).unwrap();

        // Three times the idle timeout, with the window held shut and every probe answered.
        let until = tokio::time::Instant::now() + Duration::from_millis(600);
        while let Ok(Some(packet)) = tokio::time::timeout_at(until, up_rx.recv()).await {
            let header = header(&packet);
            assert_eq!(tcp_header_flags(header) & RST, 0, "a peer answering probes was given up on");
            sender.send(segment_with_window(ACK, PEER_ISN + 1, snd_una, Vec::new(), 0)).unwrap();
        }
        assert_ne!(stream.tcb.lock().unwrap().get_state(), TcpState::Closed, "the session was closed");
    }

    /// Data the session acknowledged to the peer is the application's, even if the peer closes the
    /// connection — and the stack finishes closing it — before the application reads it.
    #[tokio::test(flavor = "multi_thread")]
    async fn data_acknowledged_before_a_close_is_still_delivered() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // Short enough that the local side's close is sent without the application asking.
        let config = TcpConfig {
            close_wait_timeout: Duration::from_millis(20),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;
        let tcb = stream.tcb.clone();

        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 4000])).unwrap();
        sender.send(segment(ACK | FIN, PEER_ISN + 4001, ours, Vec::new())).unwrap();

        // The stack sends its own FIN; the peer acknowledges it and the session is over.
        let farewell = packet_matching(&mut up_rx, |h| h.fin).await;
        let after_fin = farewell.sequence_number.wrapping_add(1);
        sender.send(segment(ACK, PEER_ISN + 4002, after_fin, Vec::new())).unwrap();
        wait_until(|| tcb.lock().unwrap().get_state() == TcpState::Closed, "the session never closed").await;

        let mut buf = vec![0u8; 4000];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the acknowledged data was discarded with the connection")
            .unwrap();
        assert!(buf.iter().all(|&b| b == 1));
        let end = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 64])).await;
        assert_eq!(end.expect("the reader was never woken").unwrap(), 0, "the stream never ended");
    }

    /// The peer's close reaches the application as soon as its FIN is in sequence and the data
    /// before it has been handed over, not once the farewell of our own has been acknowledged.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_close_ends_the_stream_before_the_teardown_finishes() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // Long enough that the unacknowledged farewell cannot close the session behind the test's
        // back, so the end of stream can only have come from the peer's own FIN.
        let config = TcpConfig {
            last_ack_timeout: Duration::from_secs(5),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 1000])).unwrap();
        sender.send(segment(ACK | FIN, PEER_ISN + 1001, ours, Vec::new())).unwrap();

        let mut buf = vec![0u8; 1000];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the data before the close never arrived")
            .unwrap();
        let end = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 64])).await;
        assert_eq!(end.expect("the end of stream waited for the teardown").unwrap(), 0);
        let state = stream.tcb.lock().unwrap().get_state();
        assert_ne!(state, TcpState::Closed, "the session had already finished closing");
    }

    /// After FIN, draining a long transfer exceeds the reader's cooperative budget.
    /// Treating the resulting yield as EOF would discard queued, acknowledged bytes.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_close_after_a_long_transfer_hands_over_every_byte() {
        /// More segments than a task gets to poll for in one turn.
        const SEGMENTS: usize = 400;
        const PAYLOAD: usize = 1_460;

        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // Hold the whole transfer in the handoff without receive-window backpressure.
        let config = TcpConfig {
            read_buffer_size: 4 << 20,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        let mut seq = PEER_ISN + 1;
        for _ in 0..SEGMENTS {
            sender.send(segment(ACK | PSH, seq, ours, vec![0x5a; PAYLOAD])).unwrap();
            seq = seq.wrapping_add(PAYLOAD as u32);
        }
        sender.send(segment(ACK | FIN, seq, ours, Vec::new())).unwrap();
        let tcb = stream.tcb.clone();
        wait_until(
            || tcb.lock().unwrap().get_state() == TcpState::CloseWait,
            "the peer's close was never accepted",
        )
        .await;

        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
            .await
            .expect("the read never finished")
            .unwrap();
        assert_eq!(received.len(), SEGMENTS * PAYLOAD, "the reader lost the tail of the transfer");
        assert!(received.iter().all(|&byte| byte == 0x5a), "the transfer arrived corrupt");
    }

    /// A cooperative yield must not report a reset while acknowledged data is still queued.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reset_after_a_long_transfer_hands_over_every_byte() {
        const SEGMENTS: usize = 400;
        const PAYLOAD: usize = 1_460;

        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: 4 << 20,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        let mut seq = PEER_ISN + 1;
        for _ in 0..SEGMENTS {
            sender.send(segment(ACK | PSH, seq, ours, vec![0x5a; PAYLOAD])).unwrap();
            seq = seq.wrapping_add(PAYLOAD as u32);
        }
        sender.send(segment(ACK | RST, seq, ours, Vec::new())).unwrap();
        let tcb = stream.tcb.clone();
        wait_until(|| tcb.lock().unwrap().is_aborted(), "the peer's reset was never accepted").await;

        let mut received = Vec::new();
        let err = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
            .await
            .expect("the read never finished")
            .expect_err("the reset read as a clean end of stream");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        assert_eq!(received.len(), SEGMENTS * PAYLOAD, "the reader lost the tail of the transfer");
        assert!(received.iter().all(|&byte| byte == 0x5a), "the transfer arrived corrupt");
    }

    /// Two closes that cross on the wire: the peer's FIN arrives while ours is still
    /// unacknowledged, so the session waits in RFC 9293's CLOSING rather than going straight
    /// to TIME-WAIT.
    #[tokio::test(flavor = "multi_thread")]
    async fn closes_that_cross_wait_in_closing() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            two_msl: Duration::from_millis(50),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        let closing = tokio::spawn(async move { stream.shutdown().await });
        let fin = packet_matching(&mut up_rx, |h| h.fin).await;
        assert_eq!(fin.sequence_number, ours);

        // The peer's own FIN, sent before it saw ours, so it acknowledges only the data.
        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        wait_until(
            || tcb.lock().unwrap().get_state() == TcpState::Closing,
            "the crossing closes were not noticed",
        )
        .await;
        let answer = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 2).await;
        assert_eq!(tcp_header_flags(&answer), ACK);

        // Our farewell is acknowledged at last, and the teardown runs to the end.
        sender.send(segment(ACK, PEER_ISN + 2, ours.wrapping_add(1), Vec::new())).unwrap();
        tokio::time::timeout(Duration::from_secs(5), closing)
            .await
            .expect("the shutdown never completed")
            .unwrap()
            .unwrap();
    }

    /// A data segment is a data segment whatever else its header carries: matching the flag set
    /// exactly dropped one marked ECE or URG, unacknowledged.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_data_segment_with_extra_flags_is_still_taken() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        const ECE: u8 = 0b0100_0000;
        sender.send(segment(ACK | PSH | ECE, PEER_ISN + 1, ours, vec![1; 300])).unwrap();

        let mut buf = vec![0u8; 300];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the segment was dropped for its flags")
            .unwrap();
        assert!(buf.iter().all(|&b| b == 1));
    }

    /// A write that joins a queue already carrying a segment must not wake the session task: that
    /// segment's timer falls due first, and the wake costs a scheduler round trip on the path from
    /// the peer's acknowledgment to the write it unblocks, where a bulk transfer spends its time.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_joining_a_running_timer_does_not_wake_the_task() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // Long enough that the retransmission timer cannot fire while the test watches.
        let config = TcpConfig {
            rto: Duration::from_secs(30),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let tcb = stream.tcb.clone();

        // The first write starts the timer, which the task does have to wake up to arm.
        let before = tcb.lock().unwrap().wakes();
        stream.write_all(b"first").await.unwrap();
        wait_until(|| tcb.lock().unwrap().wakes() > before, "the first write never armed the timer").await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let armed = tcb.lock().unwrap().wakes();

        // Nothing is acknowledged, so each of these joins a queue that already has a timer.
        for _ in 0..16 {
            stream.write_all(b"more").await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after = tcb.lock().unwrap().wakes();
        assert!(after <= armed + 1, "{} writes woke the task {} times", 16, after - armed);
    }

    /// Throughput harness for the wake and segment counts quoted in the commits that tightened
    /// them: the application writes 4 MiB to a peer that acknowledges every segment. Run with
    /// `cargo test -- --ignored --nocapture bench_session`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn bench_session() {
        const TOTAL: usize = 4 * 1024 * 1024;
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let before = tcb.lock().unwrap().wakes();

        let peer = tokio::spawn(async move {
            let (mut received, mut segments) = (0usize, 0usize);
            while received < TOTAL {
                let Some(packet) = up_rx.recv().await else { break };
                let len = packet.payload.as_ref().map_or(0, |p| p.len());
                if len == 0 {
                    continue;
                }
                received += len;
                segments += 1;
                let ack = header(&packet).sequence_number.wrapping_add(len as u32);
                sender.send(segment(ACK, PEER_ISN + 1, ack, Vec::new())).unwrap();
            }
            segments
        });

        let start = std::time::Instant::now();
        stream.write_all(&vec![7u8; TOTAL]).await.unwrap();
        let segments = peer.await.unwrap();
        let elapsed = start.elapsed();
        let wakes = tcb.lock().unwrap().wakes() - before;
        println!(
            "sent {TOTAL} bytes in {segments} segments, {elapsed:?}, {:.1} MiB/s, {wakes} wakes ({:.2}/segment)",
            TOTAL as f64 / 1048576.0 / elapsed.as_secs_f64(),
            wakes as f64 / segments as f64,
        );
    }

    /// A peer that has called `shutdown(SHUT_WR)` is still reading: the reply the application
    /// writes after its FIN has to reach it, followed by our own FIN when the application closes.
    /// Closing our half along with the peer's leaves that reply undelivered and its read hanging.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_half_closed_connection_still_carries_a_reply() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        wait_until(
            || tcb.lock().unwrap().get_state() == TcpState::CloseWait,
            "the peer's close was never taken",
        )
        .await;

        // The application answers over the half-closed connection and only then closes.
        tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"answer"))
            .await
            .expect("the writer was blocked by the peer's close")
            .unwrap();
        let reply = packet_matching(&mut up_rx, |h| h.psh).await;
        assert_eq!(tcp_header_flags(&reply), ACK | PSH);
        assert_eq!(reply.sequence_number, ours, "the reply did not start where the stream stood");

        let closing = tokio::spawn(async move { stream.shutdown().await });
        sender.send(segment(ACK, PEER_ISN + 2, ours.wrapping_add(6), Vec::new())).unwrap();
        let fin = packet_matching(&mut up_rx, |h| h.fin).await;
        assert_eq!(fin.sequence_number, ours.wrapping_add(6), "the FIN did not follow the reply");
        assert_eq!(tcb.lock().unwrap().get_state(), TcpState::LastAck);

        sender.send(segment(ACK, PEER_ISN + 2, ours.wrapping_add(7), Vec::new())).unwrap();
        tokio::time::timeout(Duration::from_secs(5), closing)
            .await
            .expect("the shutdown never completed")
            .unwrap()
            .unwrap();
    }

    /// A reply that takes longer than the leash to write is not cut short by it: the leash is on
    /// an application doing nothing, and every write pushes it back.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_written_in_pieces_outlives_the_leash() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            close_wait_timeout: Duration::from_millis(60),
            half_close_timeout: Duration::from_millis(100),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        wait_until(
            || tcb.lock().unwrap().get_state() == TcpState::CloseWait,
            "the peer's close was never taken",
        )
        .await;

        // Well past both the CLOSE_WAIT deadline and the leash, writing throughout, with one
        // segment left unacknowledged so the write side is never quiet.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(30)).await;
            tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"more"))
                .await
                .expect("the writer stalled")
                .unwrap();
            let (state, requested) = {
                let tcb = tcb.lock().unwrap();
                (tcb.get_state(), tcb.fin_requested())
            };
            assert_eq!(state, TcpState::CloseWait, "the reply was cut short by the leash");
            assert!(!requested, "the close was forced while the application was writing");
        }
        drop(up_rx);
    }

    /// Nothing may be written past the local side's own FIN: the peer discards it, so telling the
    /// caller the bytes went out is a lie it has no way to notice.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_after_the_local_close_is_refused() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            close_wait_timeout: Duration::from_millis(20),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        // The peer closes and the application does nothing, so the CLOSE_WAIT deadline sends
        // our FIN for it.
        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        wait_until(
            || tcb.lock().unwrap().get_state() == TcpState::LastAck,
            "the close was never forced",
        )
        .await;

        let err = stream.write_all(b"too late").await.expect_err("a write past the FIN was accepted");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// A peer whose FIN went unacknowledged — our ACK lost on the way — repeats it. Answering
    /// the repeat costs one segment and saves the peer its whole FIN retry schedule.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_repeated_peer_fin_is_acknowledged_again() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 2).await;

        // In CloseWait, with our own close not asked for yet.
        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        let again = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 2).await;
        assert_eq!(tcp_header_flags(&again), ACK);

        // And again once our own farewell is out and we are waiting for its acknowledgment.
        let closing = tokio::spawn(async move { stream.shutdown().await });
        wait_until(|| tcb.lock().unwrap().get_state() == TcpState::LastAck, "the close never went out").await;
        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        let in_last_ack = packet_matching(&mut up_rx, |h| !h.fin && h.acknowledgment_number == PEER_ISN + 2).await;
        assert_eq!(tcp_header_flags(&in_last_ack), ACK);
        closing.abort();
    }

    /// A half-closed session the application walks away from with nothing left owed either side
    /// ends with a farewell, not a reset: there is no unread data to cut short, and the peer's
    /// socket closes normally instead of erroring.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_a_half_closed_stream_says_goodbye() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, Vec::new())).unwrap();
        wait_until(
            || tcb.lock().unwrap().get_state() == TcpState::CloseWait,
            "the peer's close was never taken",
        )
        .await;
        drop(stream);

        let farewell = packet_matching(&mut up_rx, |h| h.fin || h.rst).await;
        assert_eq!(tcp_header_flags(&farewell), ACK | FIN, "a finished connection was reset");
        assert_eq!(farewell.sequence_number, ours);
    }

    /// Closing immediately after a write puts FIN on the final data segment. Deliver that tail
    /// to the reader before reporting EOF.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fin_delivers_the_data_it_carries() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | FIN, PEER_ISN + 1, ours, vec![1; 300])).unwrap();

        let mut buf = vec![0u8; 300];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the data the FIN carried never arrived")
            .unwrap();
        assert!(buf.iter().all(|&b| b == 1));
        let end = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 64])).await;
        assert_eq!(end.expect("the reader was never woken").unwrap(), 0, "the stream never ended");
    }

    /// Linux marks that closing segment PSH as well, and matching the flag set exactly left
    /// `FIN|PSH|ACK` unhandled and unacknowledged, so the peer repeated it for its whole retry
    /// schedule. The acknowledgment now covers the data and the FIN.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fin_with_psh_is_acknowledged_past_the_data() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH | FIN, PEER_ISN + 1, ours, vec![1; 300])).unwrap();

        let acked = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 1 + 300 + 1).await;
        assert_eq!(tcp_header_flags(&acked) & ACK, ACK);
        let state = stream.tcb.lock().unwrap().get_state();
        assert_ne!(state, TcpState::Established, "the close was ignored for its flags");
    }

    /// A FIN so far ahead that the window has no room for what it carries still has to be
    /// answered: the payload is dropped, so extraction has nothing to acknowledge, and silence
    /// leaves the peer repeating the FIN for its whole retry schedule.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fin_past_the_window_is_still_acknowledged() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: 8192,
            ..TcpConfig::default()
        };
        let stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender
            .send(segment(ACK | PSH | FIN, PEER_ISN + 1 + 20_000, ours, vec![1; 100]))
            .unwrap();

        let answer = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(answer.acknowledgment_number, PEER_ISN + 1, "the answer did not name the gap");
        assert_eq!(stream.tcb.lock().unwrap().get_state(), TcpState::Established);
    }

    /// Accept FIN only once the stream has reached it; accepting it over a hole would report an
    /// end the peer has yet to reach and strand the segment still on its way.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fin_ahead_of_a_hole_is_not_consumed() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        // The middle segment is lost, so the FIN that follows the third arrives over a hole.
        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 4000])).unwrap();
        sender.send(segment(ACK | FIN, PEER_ISN + 8001, ours, vec![3; 4000])).unwrap();
        let answer = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 4001).await;
        assert_eq!(tcp_header_flags(&answer), ACK);
        let state = stream.tcb.lock().unwrap().get_state();
        assert_eq!(state, TcpState::Established, "the FIN closed the connection early");

        // The gap fills, the peer repeats its FIN, and it is then in sequence.
        sender.send(segment(ACK, PEER_ISN + 4001, ours, vec![2; 4000])).unwrap();
        sender.send(segment(ACK | FIN, PEER_ISN + 8001, ours, vec![3; 4000])).unwrap();
        let farewell = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 12002).await;
        assert_eq!(tcp_header_flags(&farewell) & ACK, ACK);

        // Every byte reaches the reader, in order, and the stream then ends.
        let mut buf = vec![0u8; 12000];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the data around the hole was stranded")
            .unwrap();
        assert!(buf[..4000].iter().all(|&b| b == 1));
        assert!(buf[4000..8000].iter().all(|&b| b == 2));
        assert!(buf[8000..].iter().all(|&b| b == 3));
        let end = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 64])).await;
        assert_eq!(end.expect("the reader was never woken").unwrap(), 0, "the stream never ended");
    }

    /// Filling a gap can make more than one handoff chunk contiguous. Deliver every chunk without
    /// another incoming packet: the peer has no data left to send to trigger the remaining drain.
    #[tokio::test(flavor = "multi_thread")]
    async fn data_past_one_chunk_reaches_the_reader() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        // The peer's second segment arrives first, so nothing can be delivered until the gap
        // fills — and then both segments are contiguous at once.
        sender.send(segment(ACK, PEER_ISN + 1 + 8192, ours, vec![2; 8192])).unwrap();
        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 8192])).unwrap();

        let mut buf = vec![0u8; 16384];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the tail of the reassembled data never arrived")
            .unwrap();
        assert!(buf[..8192].iter().all(|&b| b == 1) && buf[8192..].iter().all(|&b| b == 2));
    }

    /// Reads with no remaining capacity leave queued and stashed data untouched.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_poll_with_a_full_buffer_keeps_the_data_behind_it() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        assert!(matches!(poll_read_once(&mut stream, &mut []), Poll::Ready(Ok(()))));
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        let sent: Vec<u8> = (0..100u8).collect();
        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, sent.clone())).unwrap();
        wait_until(|| !stream.data_rx.is_empty(), "the peer's data never reached the handoff").await;

        assert!(matches!(poll_read_once(&mut stream, &mut []), Poll::Ready(Ok(()))));
        assert!(!stream.data_rx.is_empty(), "the handoff was drained into a buffer with no room");

        // Reading 10 of 100 bytes stashes the remaining 90; a full-buffer poll must preserve them.
        let mut head = [0u8; 10];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(stream.temp_read_buffer.len(), 90);
        assert!(matches!(poll_read_once(&mut stream, &mut []), Poll::Ready(Ok(()))));
        assert_eq!(stream.temp_read_buffer.len(), 90, "the stashed bytes were dropped");

        let mut tail = [0u8; 90];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!([&head[..], &tail[..]].concat(), sent, "the stream lost or reordered bytes");
    }

    /// Deliver all received bytes, including the stashed remainder, before EOF after a peer FIN.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stash_outlives_the_peer_close() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, vec![1u8; 100])).unwrap();
        let mut head = [0u8; 10];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(stream.temp_read_buffer.len(), 90);

        sender.send(segment(ACK | FIN, PEER_ISN + 101, ours, Vec::new())).unwrap();
        wait_until(
            || peer_finished_sending(stream.tcb.lock().unwrap().get_state()),
            "the peer's FIN was never taken",
        )
        .await;
        assert!(matches!(poll_read_once(&mut stream, &mut []), Poll::Ready(Ok(()))));

        let mut tail = [0u8; 90];
        stream.read_exact(&mut tail).await.unwrap();
        assert!(tail.iter().all(|&b| b == 1), "the stashed bytes were not the peer's");
        let mut end = [0u8; 10];
        assert_eq!(stream.read(&mut end).await.unwrap(), 0, "the closed stream never ended");
    }

    /// A window the reader reopens has to be advertised without waiting to be asked. The peer has
    /// been told to stop sending and nothing else will tell it otherwise: it sits out its persist
    /// timer on every close of the window, or forever if it does not probe.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reader_that_drains_reopens_the_window_on_its_own() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // One handoff slot, so the second segment has nowhere to go and the window closes.
        let config = TcpConfig {
            read_buffer_size: 8192,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 4000])).unwrap();
        sender.send(segment(ACK, PEER_ISN + 4001, ours, vec![2; 8192])).unwrap();
        // Both segments arrived in order and are acknowledged as such; the second has nowhere to
        // go but the reassembly buffer, which is what closes the window.
        let closed = packet_matching(&mut up_rx, |h| h.window_size == 0).await;
        assert_eq!(closed.acknowledgment_number, PEER_ISN + 12193);

        // The peer sends nothing more, not even a probe. Draining alone has to reach it.
        let mut buf = vec![0u8; 12192];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the buffered data never reached the reader")
            .unwrap();
        let reopened = packet_matching(&mut up_rx, |h| h.window_size >= 1500).await;
        assert_eq!(reopened.acknowledgment_number, PEER_ISN + 12193);
    }

    /// With the receive buffer full the stack advertises a zero window, and the peer probes it
    /// with the byte the stream is waiting on. That byte is admitted despite the full buffer, and
    /// the probe draws an ACK carrying the window as it stands.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_zero_window_probe_is_acknowledged() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: 8192,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        // The first segment fills the single handoff slot; the second fills the receive buffer but
        // starts one byte past the end of the first, so nothing more is contiguous and the window
        // closes.
        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 4000])).unwrap();
        sender.send(segment(ACK, PEER_ISN + 4002, ours, vec![2; 8192])).unwrap();
        let closed = packet_matching(&mut up_rx, |h| h.window_size == 0).await;
        assert_eq!(closed.acknowledgment_number, PEER_ISN + 4001);

        // The probe byte closes the gap, so the acknowledgment it draws covers the buffered
        // segment behind it — with the window still shut, since nothing has been read.
        sender.send(segment(ACK, PEER_ISN + 4001, ours, vec![3; 1])).unwrap();
        let probed = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(probed.acknowledgment_number, PEER_ISN + 12194);
        assert_eq!(probed.window_size, 0, "the full buffer was advertised as room");

        // The reader drains everything, and the window the peer is waiting on reopens.
        let mut buf = vec![0u8; 12193];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the buffered data never reached the reader")
            .unwrap();
        let reopened = packet_matching(&mut up_rx, |h| h.window_size >= 1500).await;
        assert_eq!(reopened.acknowledgment_number, PEER_ISN + 12194, "the window never reopened");
    }

    /// A peer segment that overtakes the one before it is held, not thrown away: dropping it
    /// costs a retransmission of everything from the gap onwards.
    #[tokio::test(flavor = "multi_thread")]
    async fn out_of_order_data_is_held_until_the_gap_fills() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1001, ours, vec![2; 1000])).unwrap();
        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, vec![1; 1000])).unwrap();

        let mut buf = vec![0u8; 2000];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the data that arrived out of order was dropped")
            .unwrap();
        assert!(buf[..1000].iter().all(|&b| b == 1) && buf[1000..].iter().all(|&b| b == 2));
    }

    /// Data held for a gap is acknowledged all the same, with the sequence number the peer is
    /// expected to resend from. Those duplicate ACKs are what make it retransmit at once rather
    /// than sit out its retransmission timeout.
    #[tokio::test(flavor = "multi_thread")]
    async fn data_held_for_a_gap_draws_a_duplicate_ack() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1001, ours, vec![2; 1000])).unwrap();
        let dup_ack = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(dup_ack.acknowledgment_number, PEER_ISN + 1, "the gap was acknowledged as filled");
    }

    /// The stream is acknowledged as it arrives, not as it is read: two segments in order draw an
    /// acknowledgment of both, and what the reader has yet to take comes off the window instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn in_order_data_is_acknowledged_before_the_reader_takes_it() {
        const BUFFER: usize = 8192;
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // One handoff slot: a first segment fills it, so everything after it stays in the
        // reassembly buffer, where the advertised window can be read off.
        let config = TcpConfig {
            read_buffer_size: BUFFER,
            ..TcpConfig::default()
        };
        let stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, vec![0; 100])).unwrap();
        let handed = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 101).await;
        assert_eq!(handed.window_size as usize, BUFFER, "the handoff cost the peer window");

        // Nobody polls the stream, so these two reach nothing but the reassembly buffer.
        sender.send(segment(ACK | PSH, PEER_ISN + 101, ours, vec![1; 1000])).unwrap();
        sender.send(segment(ACK | PSH, PEER_ISN + 1101, ours, vec![2; 1000])).unwrap();

        let acked = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 2101).await;
        assert_eq!(tcp_header_flags(&acked), ACK);
        assert_eq!(
            acked.window_size as usize,
            BUFFER - 2000,
            "the window did not pay for the data held"
        );
    }

    /// RFC 2018 § 3: with a segment missing, the acknowledgment stops where the hole starts and a
    /// block names exactly what is held beyond it — not a range stretching back over data the
    /// reader has yet to take. Filling the hole retires the block.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hole_is_named_from_the_data_actually_missing() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        // The second of three segments is lost, and nobody polls the stream.
        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, vec![1; 1000])).unwrap();
        sender.send(segment(ACK | PSH, PEER_ISN + 2001, ours, vec![3; 1000])).unwrap();
        let held = packet_matching(&mut up_rx, |h| !sack_blocks(h).is_empty()).await;
        assert_eq!(
            held.acknowledgment_number,
            PEER_ISN + 1001,
            "the acknowledgment did not stop at the hole"
        );
        assert_eq!(sack_blocks(&held), vec![(PEER_ISN + 2001, PEER_ISN + 3001)]);

        sender.send(segment(ACK | PSH, PEER_ISN + 1001, ours, vec![2; 1000])).unwrap();
        let filled = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 3001).await;
        assert!(sack_blocks(&filled).is_empty(), "a filled hole was still reported");
    }

    /// One segment, one acknowledgment, however many chunks its payload takes to reach the reader:
    /// the handoff chunk is ours, and the peer must not be sent a segment for each of them.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_large_segment_draws_one_acknowledgment_not_one_per_chunk() {
        // A large IPv4 payload spanning several handoff chunks.
        const PAYLOAD: usize = 60_000;
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: 1 << 20,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;
        assert!(up_rx.try_recv().is_err(), "the handshake left a packet behind");

        let (src, dst) = addrs();
        let flags = ACK | PSH;
        let payload = vec![7u8; PAYLOAD];
        let big = create_raw_packet(
            src,
            dst,
            |_, _| PAYLOAD,
            flags,
            TTL,
            PEER_ISN + 1,
            ours,
            64240,
            payload,
            SendOptions::default(),
        );
        sender.send(big.unwrap()).unwrap();

        let mut received = vec![0u8; PAYLOAD];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
            .await
            .expect("the segment never reached the reader")
            .unwrap();
        assert!(received.iter().all(|&byte| byte == 7));

        let mut sent = Vec::new();
        let until = tokio::time::Instant::now() + Duration::from_millis(100);
        while let Ok(Some(packet)) = tokio::time::timeout_at(until, up_rx.recv()).await {
            sent.push(header(&packet).clone());
        }
        assert_eq!(sent.len(), 1, "one segment drew {} acknowledgments", sent.len());
        assert_eq!(sent[0].acknowledgment_number, PEER_ISN + 1 + PAYLOAD as u32);
    }

    /// A window the reader reopens is worth a segment of its own only once it has doubled, the
    /// rule Linux applies in `tcp_cleanup_rbuf`: four reads here free four chunks and draw three
    /// updates: one quarter, one half, and the whole buffer. The three-quarter window waits
    /// because it has not doubled since the previous update.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_drained_buffer_is_advertised_once_the_window_has_doubled() {
        const BUFFER: usize = 32_768;
        const CHUNK: usize = 8192;
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: BUFFER,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        // Eight chunks: four fill the handoff, four fill the reassembly buffer and shut the window.
        let mut seq = PEER_ISN + 1;
        for index in 0..8u8 {
            sender.send(segment(ACK | PSH, seq, ours, vec![index; CHUNK])).unwrap();
            seq = seq.wrapping_add(CHUNK as u32);
        }
        let shut = packet_matching(&mut up_rx, |h| h.acknowledgment_number == seq).await;
        assert_eq!(shut.window_size, 0, "a full buffer was advertised as room");

        // Every read frees one chunk of the buffer, and the task refills the handoff from it
        // before the test reads again, so each of these answers exactly one freed chunk.
        for left in [24_576, 16_384, 8_192, 0] {
            let mut buf = vec![0u8; CHUNK];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
                .await
                .expect("the reader stalled")
                .unwrap();
            wait_until(
                || tcb.lock().unwrap().get_unordered_packets_total_len() == left,
                "the handoff never followed the reader",
            )
            .await;
        }

        let mut updates = Vec::new();
        let until = tokio::time::Instant::now() + Duration::from_millis(100);
        while let Ok(Some(packet)) = tokio::time::timeout_at(until, up_rx.recv()).await {
            let header = header(&packet);
            assert_eq!(header.acknowledgment_number, seq, "a window update moved the acknowledgment");
            updates.push(header.window_size as usize);
        }
        assert_eq!(updates, vec![CHUNK, 2 * CHUNK, BUFFER], "four reads drew {updates:?}");
    }

    /// A FIN in sequence is acknowledged with data the reader has yet to take: the peer was told
    /// those bytes arrived, so there is nothing left for it to send. The reader gets all of them
    /// and then the end of the stream.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fin_over_undelivered_data_is_acknowledged() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // One handoff slot, so the second segment has nowhere to go until the reader reads.
        let config = TcpConfig {
            read_buffer_size: 8192,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, vec![1; 100])).unwrap();
        sender.send(segment(ACK | PSH, PEER_ISN + 101, ours, vec![2; 4000])).unwrap();
        wait_until(
            || tcb.lock().unwrap().get_unordered_packets_total_len() == 4000,
            "the second segment was never held",
        )
        .await;

        sender.send(segment(ACK | FIN, PEER_ISN + 4101, ours, Vec::new())).unwrap();
        let farewell = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 4102).await;
        assert_eq!(tcp_header_flags(&farewell), ACK);
        assert_eq!(tcb.lock().unwrap().get_state(), TcpState::CloseWait);

        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
            .await
            .expect("the read never finished")
            .unwrap();
        assert_eq!(received.len(), 4100, "the reader lost data the peer was told had arrived");
        assert!(received[..100].iter().all(|&b| b == 1) && received[100..].iter().all(|&b| b == 2));
    }

    /// After the session task ends, drain acknowledged reassembly data before reporting EOF.
    #[tokio::test(flavor = "multi_thread")]
    async fn data_acknowledged_but_not_handed_over_outlives_the_session() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // One handoff slot, and a close the stack answers without the application asking.
        let config = TcpConfig {
            read_buffer_size: 8192,
            close_wait_timeout: Duration::from_millis(20),
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, vec![1; 100])).unwrap();
        sender.send(segment(ACK | PSH, PEER_ISN + 101, ours, vec![2; 4000])).unwrap();
        wait_until(
            || tcb.lock().unwrap().get_unordered_packets_total_len() == 4000,
            "the second segment was never held",
        )
        .await;
        sender.send(segment(ACK | FIN, PEER_ISN + 4101, ours, Vec::new())).unwrap();

        // The stack closes its own half, the peer acknowledges it, and the session is over with
        // the second segment still in the reassembly buffer.
        let farewell = packet_matching(&mut up_rx, |h| h.fin).await;
        let after_fin = farewell.sequence_number.wrapping_add(1);
        sender.send(segment(ACK, PEER_ISN + 4102, after_fin, Vec::new())).unwrap();
        wait_until(|| tcb.lock().unwrap().get_state() == TcpState::Closed, "the session never closed").await;
        // Closed is set before the loop exits; wait until it can no longer refill the handoff.
        wait_until(
            || stream.task_handle.as_ref().unwrap().is_finished(),
            "the session task never exited",
        )
        .await;
        assert_eq!(tcb.lock().unwrap().get_unordered_packets_total_len(), 4000);

        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
            .await
            .expect("the read never finished")
            .unwrap();
        assert_eq!(received.len(), 4100, "acknowledged data was stranded with the session");
        assert!(received[..100].iter().all(|&b| b == 1) && received[100..].iter().all(|&b| b == 2));
    }

    /// RFC 5681 § 3.2: a segment the stream already holds is still worth an acknowledgment. The
    /// peer sent it because it believes something is missing, and silence costs it a whole
    /// retransmission timeout to learn otherwise.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retransmission_below_the_stream_still_draws_an_acknowledgment() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let stream = established(up_tx, &mut up_rx, TcpConfig::default()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        let data = segment(ACK | PSH, PEER_ISN + 1, ours, vec![1; 1000]);
        sender.send(data.clone()).unwrap();
        let first = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(first.acknowledgment_number, PEER_ISN + 1001);

        // Our acknowledgment was lost on the way, so the peer sends the whole segment again.
        sender.send(data).unwrap();
        let again = header(&next_packet(&mut up_rx).await).clone();
        assert_eq!(tcp_header_flags(&again), ACK);
        assert_eq!(again.acknowledgment_number, PEER_ISN + 1001, "the duplicate was taken in silence");
    }

    /// A 4 MiB buffer is worth nothing to a peer that is told about it in a 16-bit field: the
    /// SYN offering a scale is answered with one of our own, and every window after the handshake
    /// is advertised through it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scaled_syn_is_answered_with_our_own_scale() {
        const FOUR_MIB: usize = 4 * 1024 * 1024;
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: FOUR_MIB,
            max_unacked_bytes: FOUR_MIB as u32,
            ..TcpConfig::default()
        };
        let syn = segment_with_scale(SYN, PEER_ISN, 0, Vec::new(), 64240, Some(7));
        let (stream, synack) = established_from_syn(up_tx, &mut up_rx, config, None, syn).await;

        // Seven bits of scale are what a 4 MiB buffer needs to fit the window field.
        assert_eq!(window_scale(&synack), Some(7));
        // The handshake's own window is read unscaled, so it says no more than the field holds.
        assert_eq!(synack.window_size, u16::MAX);

        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;
        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 1000])).unwrap();

        let acked = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 1001).await;
        let advertised = (acked.window_size as usize) << 7;
        assert_eq!(advertised, FOUR_MIB, "the window was not advertised at the scale we asked for");
        assert!(advertised > u16::MAX as usize);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_syn_option_does_not_hide_window_scaling() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: 4 * 1024 * 1024,
            ..TcpConfig::default()
        };
        let mut syn = segment(SYN, PEER_ISN, 0, Vec::new());
        let TransportHeader::Tcp(tcp) = &mut syn.transport else {
            unreachable!();
        };
        tcp.set_options_raw(&[30, 2, 3, 3, 7, 0, 0, 0]).unwrap();
        let (stream, synack) = established_from_syn(up_tx, &mut up_rx, config, None, syn).await;

        assert_eq!(window_scale(&synack), Some(7));
        assert_eq!(stream.tcb.lock().unwrap().get_send_window(), 64240 << 7);
    }

    #[test]
    fn syn_window_scale_obeys_option_boundaries() {
        assert_eq!(syn_window_scale(&[]), Ok(None));
        assert_eq!(syn_window_scale(&[1, 3, 3, 0]), Ok(Some(0)));
        assert_eq!(syn_window_scale(&[30, 4, 3, 3, 3, 3, 255]), Ok(Some(255)));
        assert_eq!(syn_window_scale(&[0, 3, 3, 7]), Ok(None));
        assert_eq!(syn_window_scale(&[3, 3, 7, 3, 3, 2]), Ok(Some(7)));
        assert_eq!(syn_window_scale(&[3, 3, 7, 30, 0]), Ok(Some(7)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_syn_options_do_not_offer_window_scaling() {
        for options in [
            &[30, 0, 3, 3, 7, 0, 0, 0][..],
            &[30, 1, 3, 3, 7, 0, 0, 0],
            &[30, 9, 3, 3, 7, 0, 0, 0],
            &[3, 2, 3, 3, 7, 0, 0, 0],
            &[3, 4, 7, 0, 3, 3, 7, 0],
            &[1, 1, 3, 3],
            &[1, 1, 1, 30],
        ] {
            let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
            let config = TcpConfig {
                read_buffer_size: 4 * 1024 * 1024,
                ..TcpConfig::default()
            };
            let mut syn = segment(SYN, PEER_ISN, 0, Vec::new());
            let TransportHeader::Tcp(tcp) = &mut syn.transport else {
                unreachable!();
            };
            tcp.set_options_raw(options).unwrap();
            let (stream, synack) = established_from_syn(up_tx, &mut up_rx, config, None, syn).await;

            assert_eq!(window_scale(&synack), None, "accepted malformed options {options:?}");
            assert_eq!(synack.window_size, u16::MAX);
            assert_eq!(stream.tcb.lock().unwrap().get_send_window(), 64240);
        }
    }

    /// A SYN carrying no scale leaves the connection where it was: no option in the SYN-ACK, and
    /// windows that mean exactly what they say — all a peer that never agreed to scaling can read.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unscaled_syn_leaves_the_windows_as_they_are() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig {
            read_buffer_size: 4 * 1024 * 1024,
            ..TcpConfig::default()
        };
        let syn = segment(SYN, PEER_ISN, 0, Vec::new());
        let (stream, synack) = established_from_syn(up_tx, &mut up_rx, config, None, syn).await;

        assert_eq!(window_scale(&synack), None, "a scale was offered to a peer that asked for none");
        assert_eq!(synack.window_size, u16::MAX);

        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;
        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 1000])).unwrap();

        let acked = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 1001).await;
        assert_eq!(acked.window_size, u16::MAX, "the unscaled window did not say all the field holds");
        // The peer's own window is unscaled too, whatever shift the buffer would have chosen.
        assert_eq!(stream.tcb.lock().unwrap().get_send_window(), 64240);
    }

    /// A peer that offers timestamps is answered with one, and from the SYN-ACK onwards every
    /// segment carries them — data, pure acknowledgments and the farewell alike (RFC 7323 § 3.2).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_negotiated_timestamp_rides_on_every_segment() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let syn = syn_with_timestamp(7_000);
        let (mut stream, synack) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn).await;
        assert_eq!(
            timestamp(&synack).map(|(_, tsecr)| tsecr),
            Some(7_000),
            "the SYN's clock was not echoed"
        );
        let ours_at_handshake = timestamp(&synack).unwrap().0;

        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        stream.write_all(b"hello").await.unwrap();
        let data = packet_matching(&mut up_rx, |h| h.psh).await;
        let (tsval, tsecr) = timestamp(&data).expect("the data segment carried no timestamp");
        assert_eq!(tsecr, 7_000);
        assert!(tsval.wrapping_sub(ours_at_handshake) < i32::MAX as u32, "our clock ran backwards");

        // The peer's own data, and the pure acknowledgment it draws, which echoes it back.
        let peer_data = segment_with_timestamp(ACK | PSH, PEER_ISN + 1, ours.wrapping_add(5), vec![1; 100], 7_050, tsval);
        sender.send(peer_data).unwrap();
        let acked = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 101).await;
        assert_eq!(timestamp(&acked).map(|(_, tsecr)| tsecr), Some(7_050));

        let closing = tokio::spawn(async move { stream.shutdown().await });
        let fin = packet_matching(&mut up_rx, |h| h.fin).await;
        assert_eq!(
            timestamp(&fin).map(|(_, tsecr)| tsecr),
            Some(7_050),
            "the farewell carried no timestamp"
        );
        closing.abort();
    }

    /// A SYN without the option leaves it off for the whole connection: RFC 7323 § 3.2 makes
    /// timestamps something both sides agree to in the handshake or not at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_syn_without_timestamps_never_draws_one() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let syn = segment(SYN, PEER_ISN, 0, Vec::new());
        let (mut stream, synack) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn).await;
        assert_eq!(timestamp(&synack), None, "a peer that asked for no timestamps was sent one");

        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        stream.write_all(b"hello").await.unwrap();
        let data = packet_matching(&mut up_rx, |h| h.psh).await;
        assert_eq!(timestamp(&data), None);

        // Even a peer that starts timestamping mid-connection is answered without one.
        sender
            .send(segment_with_timestamp(
                ACK,
                PEER_ISN + 1,
                ours.wrapping_add(5),
                vec![1; 100],
                7_050,
                0,
            ))
            .unwrap();
        let acked = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 101).await;
        assert_eq!(timestamp(&acked), None);
    }

    /// A segment that overtakes the stream is held for the gap before it, and the peer cannot
    /// tell which of its segments the acknowledgment it draws answers: RFC 7323 § 4.3 has the
    /// echo stay where it was until the gap fills.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_segment_that_overtakes_the_stream_does_not_move_the_echo() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let syn = syn_with_timestamp(100);
        let (stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender
            .send(segment_with_timestamp(ACK | PSH, PEER_ISN + 1001, ours, vec![2; 1000], 500, 0))
            .unwrap();
        let held = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 1).await;
        assert_eq!(
            timestamp(&held).map(|(_, tsecr)| tsecr),
            Some(100),
            "a segment past the gap was echoed"
        );

        sender
            .send(segment_with_timestamp(ACK | PSH, PEER_ISN + 1, ours, vec![1; 1000], 400, 0))
            .unwrap();
        let filled = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 2001).await;
        assert_eq!(timestamp(&filled).map(|(_, tsecr)| tsecr), Some(400));
    }

    /// An old duplicate that the sequence space wrapped back into the window carries a timestamp
    /// from before the one we hold: RFC 7323 § 5.3 drops it and answers it, so the application
    /// is handed the peer's real data instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn paws_drops_an_old_duplicate_and_acknowledges_it() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_timestamp(5_000)).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender
            .send(segment_with_timestamp(ACK | PSH, PEER_ISN + 1, ours, vec![9; 100], 4_000, 0))
            .unwrap();
        let answer = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(answer.acknowledgment_number, PEER_ISN + 1, "the old duplicate was taken for data");

        sender
            .send(segment_with_timestamp(ACK | PSH, PEER_ISN + 1, ours, vec![1; 100], 5_100, 0))
            .unwrap();
        let mut buf = vec![0u8; 100];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the peer's data never arrived")
            .unwrap();
        assert!(buf.iter().all(|&b| b == 1), "the old duplicate reached the application");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_consumed_duplicate_does_not_poison_the_timestamp_echo() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_timestamp(100)).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;
        sender
            .send(segment_with_timestamp(ACK | PSH, PEER_ISN - 99, ours, vec![9; 100], 300, 0))
            .unwrap();
        sender
            .send(segment_with_timestamp(ACK | PSH, PEER_ISN + 1, ours, vec![1; 100], 200, 0))
            .unwrap();
        let mut buf = [0; 100];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, [1; 100]);
        let acked = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 101).await;
        assert_eq!(timestamp(&acked).unwrap().1, 200);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_or_malformed_timestamps_cannot_bypass_paws() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_timestamp(5000)).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;
        stream.write_all(b"reply").await.unwrap();
        let _sent = packet_matching(&mut up_rx, |h| h.psh).await;
        for options in [Vec::new(), vec![8, 9, 0, 0, 0, 0, 0, 0, 0]] {
            let mut packet = segment(ACK | PSH, PEER_ISN + 1, ours, vec![9; 100]);
            let TransportHeader::Tcp(tcp) = &mut packet.transport else {
                unreachable!()
            };
            tcp.set_options_raw(&options).unwrap();
            tcp.acknowledgment_number = ours.wrapping_add(5);
            tcp.window_size = 0;
            sender.send(packet).unwrap();
        }
        sender
            .send(segment_with_timestamp(ACK | PSH, PEER_ISN + 1, ours, vec![1; 100], 5100, 0))
            .unwrap();
        let mut buf = [0; 100];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, [1; 100]);
        assert_eq!(stream.tcb.lock().unwrap().get_inflight_packets_total_len(), 5);
        assert_eq!(header(&next_packet(&mut up_rx).await).acknowledgment_number, PEER_ISN + 101);
        assert!(up_rx.try_recv().is_err(), "missing timestamps should be dropped silently");

        // Resets remain valid without timestamps when their sequence number matches.
        sender.send(segment(RST, PEER_ISN + 101, 0, Vec::new())).unwrap();
        wait_until(|| stream.tcb.lock().unwrap().get_state() == TcpState::Closed, "reset was ignored").await;
    }

    /// A timestamp echo updates the retransmission timeout (RFC 7323 § 4.1).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_timestamped_acknowledgment_measures_the_round_trip() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // A sample moves the initial timeout to a fixed bound regardless of scheduler delay.
        let config = TcpConfig {
            rto: Duration::from_secs(30),
            min_rto: Duration::from_secs(60),
            max_rto: Duration::from_secs(60),
            ..TcpConfig::default()
        };
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, config, None, syn_with_timestamp(100)).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();

        stream.write_all(b"hello").await.unwrap();
        let data = packet_matching(&mut up_rx, |h| h.psh).await;
        let ours = timestamp(&data).expect("the data segment carried no timestamp").0;
        let after_data = data.sequence_number.wrapping_add(5);
        sender
            .send(segment_with_timestamp(ACK, PEER_ISN + 1, after_data, Vec::new(), 200, ours))
            .unwrap();

        wait_until(
            || tcb.lock().unwrap().rto() == Duration::from_secs(60),
            "the echoed round trip was never measured",
        )
        .await;
    }

    /// The twelve bytes a timestamp costs come out of the payload, not out of the link: a full
    /// segment to a peer offering the link's own MSS still fits the MTU (RFC 9293 § 3.7.1).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_segment_with_timestamps_still_fits_the_link() {
        const MTU: u16 = 65_500;
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let options = SendOptions {
            max_segment_size: Some(65_460),
            timestamp: Some((900, 0)),
            ..SendOptions::default()
        };
        let syn = segment_with_options(SYN, PEER_ISN, 0, Vec::new(), u16::MAX, options);
        let (mut stream, _) = established_from_syn_over(up_tx, &mut up_rx, TcpConfig::default(), None, syn, MTU).await;

        // Room at the peer for everything the link can carry, so nothing but the headers bounds
        // the segment.
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;
        sender
            .send(segment_with_options(
                ACK,
                PEER_ISN + 1,
                ours,
                Vec::new(),
                u16::MAX,
                SendOptions {
                    timestamp: Some((900, 0)),
                    ..SendOptions::default()
                },
            ))
            .unwrap();
        wait_until(
            || tcb.lock().unwrap().get_send_window() == u16::MAX as u32,
            "the peer's window never opened",
        )
        .await;

        let written = stream.write(&[7u8; 70_000]).await.unwrap();
        assert_eq!(written, 65_448, "the timestamp was not paid for out of the payload");
        let data = loop {
            let packet = next_packet(&mut up_rx).await;
            if packet.payload.as_ref().is_some_and(|payload| !payload.is_empty()) {
                break packet;
            }
        };
        assert!(timestamp(header(&data)).is_some());
        assert_eq!(
            data.to_bytes().unwrap().len(),
            MTU as usize,
            "the full segment did not fill the link exactly"
        );
    }

    #[test]
    fn header_timestamp_obeys_option_boundaries() {
        assert_eq!(header_timestamp(&[]), Ok(None));
        assert_eq!(header_timestamp(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]), Ok(Some((1, 2))));
        assert_eq!(header_timestamp(&[3, 3, 7, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0]), Ok(Some((1, 2))));
        assert_eq!(header_timestamp(&[0, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]), Ok(None));
        assert_eq!(
            header_timestamp(&[8, 9, 0, 0, 0, 1, 0, 0, 0, 2, 0]),
            Err("invalid timestamp option length")
        );
        assert_eq!(header_timestamp(&[8, 10, 0, 0, 0, 1]), Err("option extends past the TCP header"));
    }

    /// A guest's SYN MSS limits payload even when our link supports larger packets
    /// (RFC 9293 § 3.7.1).
    #[tokio::test(flavor = "multi_thread")]
    async fn segments_are_capped_at_the_peer_mss() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig::default();
        let (mut stream, _) = established_from_syn_over(up_tx, &mut up_rx, config, None, syn_with_mss(1460), 65500).await;

        stream.write_all(&[7u8; 5000]).await.unwrap();
        assert_eq!(sent_payload_lengths(&mut up_rx, 5000).await, vec![1460, 1460, 1460, 620]);
    }

    /// Without a SYN MSS offer, use the IPv4 default from RFC 9293 § 3.7.1.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_syn_without_an_mss_option_sends_the_default_segment() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig::default();
        let syn = segment(SYN, PEER_ISN, 0, Vec::new());
        let (mut stream, _) = established_from_syn_over(up_tx, &mut up_rx, config, None, syn, 65500).await;

        stream.write_all(&[7u8; 1200]).await.unwrap();
        assert_eq!(sent_payload_lengths(&mut up_rx, 1200).await, vec![536, 536, 128]);
    }

    /// A large peer MSS does not override the local MTU.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_mss_beyond_the_link_leaves_the_mtu_in_charge() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let config = TcpConfig::default();
        let (mut stream, _) = established_from_syn_over(up_tx, &mut up_rx, config, None, syn_with_mss(9000), 1500).await;

        stream.write_all(&[7u8; 3000]).await.unwrap();
        assert_eq!(sent_payload_lengths(&mut up_rx, 3000).await, vec![1460, 1460, 80]);
    }

    /// RFC 2018 § 2: a peer that offers SACK-Permitted is answered with one in the SYN-ACK, which
    /// is what turns selective acknowledgment on for the connection.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_syn_offering_selective_acknowledgment_is_answered_with_one() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (stream, synack) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;

        assert!(sack_permitted(&synack), "the offer was never answered");
        assert!(stream.tcb.lock().unwrap().sack_permitted());
    }

    /// A SYN without the option leaves it off for the whole connection, and the option belongs to
    /// the handshake: no later segment of ours carries it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_syn_without_selective_acknowledgment_never_draws_one() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let syn = segment(SYN, PEER_ISN, 0, Vec::new());
        let (mut stream, synack) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn).await;
        assert!(!sack_permitted(&synack), "a peer that asked for nothing was offered the option");
        assert!(!stream.tcb.lock().unwrap().sack_permitted());

        stream.write_all(b"hello").await.unwrap();
        let data = packet_matching(&mut up_rx, |h| h.psh).await;
        assert!(!sack_permitted(&data));
    }

    /// The option rides on the SYN-ACK alone, not on the segments that follow it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_permitted_option_is_not_repeated_past_the_handshake() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;

        stream.write_all(b"hello").await.unwrap();
        let data = packet_matching(&mut up_rx, |h| h.psh).await;
        assert!(!sack_permitted(&data), "the handshake option was repeated on a data segment");
    }

    /// RFC 2018 § 3: an acknowledgment that stops at a hole names the data beyond it, so the peer
    /// resends the segment that went missing instead of everything that followed it. The blocks
    /// go away with the hole.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_acknowledgment_stopping_at_a_hole_names_the_data_beyond_it() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1001, ours, vec![2; 1000])).unwrap();
        let held = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(held.acknowledgment_number, PEER_ISN + 1, "the gap was acknowledged as filled");
        assert_eq!(sack_blocks(&held), vec![(PEER_ISN + 1001, PEER_ISN + 2001)]);

        sender.send(segment(ACK | PSH, PEER_ISN + 1, ours, vec![1; 1000])).unwrap();
        let filled = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 2001).await;
        assert!(sack_blocks(&filled).is_empty(), "a filled hole was still reported");

        let mut buf = vec![0u8; 2000];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the data that arrived out of order was dropped")
            .unwrap();
    }

    /// RFC 2018 § 4 orders the blocks by arrival, newest first: a peer that loses one
    /// acknowledgment still learns of the newest buffered range from the next.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_holes_are_reported_newest_first() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK | PSH, PEER_ISN + 1001, ours, vec![2; 1000])).unwrap();
        sender.send(segment(ACK | PSH, PEER_ISN + 3001, ours, vec![3; 1000])).unwrap();

        let reported = packet_matching(&mut up_rx, |h| sack_blocks(h).len() == 2).await;
        assert_eq!(reported.acknowledgment_number, PEER_ISN + 1);
        assert_eq!(
            sack_blocks(&reported),
            vec![(PEER_ISN + 3001, PEER_ISN + 4001), (PEER_ISN + 1001, PEER_ISN + 2001)]
        );
    }

    /// The blocks are paid for out of the payload like the timestamp before them: a full segment
    /// to a peer offering the link's own MSS still fits the MTU with both aboard.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_segment_with_timestamps_and_three_blocks_still_fits_the_link() {
        const MTU: u16 = 65_500;
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let options = SendOptions {
            max_segment_size: Some(65_460),
            timestamp: Some((900, 0)),
            sack_permitted: true,
            ..SendOptions::default()
        };
        let syn = segment_with_options(SYN, PEER_ISN, 0, Vec::new(), u16::MAX, options);
        let (mut stream, _) = established_from_syn_over(up_tx, &mut up_rx, TcpConfig::default(), None, syn, MTU).await;
        let sender = stream.stream_sender();
        let tcb = stream.tcb.clone();
        let ours = tcb.lock().unwrap().get_seq().0;

        // Three buffered ranges beyond gaps, as many as fit alongside timestamps, and
        // room at the peer for everything the link can carry.
        for hole in [1001, 3001, 5001] {
            sender
                .send(segment_with_options(
                    ACK,
                    PEER_ISN + hole,
                    ours,
                    vec![1; 1000],
                    u16::MAX,
                    SendOptions {
                        timestamp: Some((900, 0)),
                        ..SendOptions::default()
                    },
                ))
                .unwrap();
        }
        wait_until(|| tcb.lock().unwrap().sack_blocks_to_send().len() == 3, "the holes were never held").await;

        let written = stream.write(&[7u8; 70_000]).await.unwrap();
        assert_eq!(written, 65_420, "the blocks were not paid for out of the payload");
        let data = packet_matching(&mut up_rx, |h| h.psh).await;
        assert_eq!(sack_blocks(&data).len(), 3);
        assert!(timestamp(&data).is_some());
        assert_eq!(data.header_len() + 20 + written, MTU as usize, "the segment overran the link");
    }

    /// A peer acknowledgment carrying SACK blocks of the caller's making.
    fn ack_with_blocks(ours: u32, blocks: &[(u32, u32)]) -> NetworkPacket {
        let mut selective_ack = [None; MAX_SACK_BLOCKS];
        for (slot, &block) in selective_ack.iter_mut().zip(blocks) {
            *slot = Some(block);
        }
        let options = SendOptions {
            selective_ack,
            ..SendOptions::default()
        };
        segment_with_options(ACK, PEER_ISN + 1, ours, Vec::new(), 64240, options)
    }

    /// Put `count` segments of 500 bytes on the wire and return where they start.
    async fn write_segments(stream: &mut IpStackTcpStream, up_rx: &mut PacketReceiver, count: u32) -> u32 {
        let start = stream.tcb.lock().unwrap().get_seq().0;
        for index in 0..count {
            stream.write_all(&[index as u8; 500]).await.unwrap();
            let sent = next_packet(up_rx).await;
            assert_eq!(header(&sent).sequence_number, start.wrapping_add(500 * index));
        }
        start
    }

    /// SACK evidence retransmits the missing segment without resending buffered data.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_blocks_retransmit_the_hole_and_nothing_else() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;
        let sender = stream.stream_sender();
        let start = write_segments(&mut stream, &mut up_rx, 4).await;

        // The peer took everything but the first segment, and says so.
        sender
            .send(ack_with_blocks(start, &[(start.wrapping_add(500), start.wrapping_add(2000))]))
            .unwrap();

        let again = next_packet(&mut up_rx).await;
        assert_eq!(header(&again).sequence_number, start, "the wrong segment was resent");
        assert_eq!(again.payload.as_ref().map(|p| p.len()), Some(500));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(up_rx.try_recv().is_err(), "a segment the peer already held was resent");
    }

    /// A second hole goes out as soon as the blocks reach past it, and the first is not repeated.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_further_block_sends_the_next_hole() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;
        let sender = stream.stream_sender();
        let start = write_segments(&mut stream, &mut up_rx, 8).await;

        sender
            .send(ack_with_blocks(start, &[(start.wrapping_add(500), start.wrapping_add(2000))]))
            .unwrap();
        assert_eq!(header(&next_packet(&mut up_rx).await).sequence_number, start);

        let blocks = [
            (start.wrapping_add(500), start.wrapping_add(2000)),
            (start.wrapping_add(2500), start.wrapping_add(4000)),
        ];
        sender.send(ack_with_blocks(start, &blocks)).unwrap();
        let second = next_packet(&mut up_rx).await;
        assert_eq!(
            header(&second).sequence_number,
            start.wrapping_add(2000),
            "the second hole was not sent"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(up_rx.try_recv().is_err(), "the first hole was sent again");
    }

    /// Duplicate acknowledgments that carry no block say no more than they ever did, so they are
    /// read as they ever were: the left edge is all they name.
    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_acknowledgments_without_blocks_ask_for_the_left_edge() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;
        let sender = stream.stream_sender();
        let start = write_segments(&mut stream, &mut up_rx, 4).await;

        for _ in 0..4 {
            sender.send(segment(ACK, PEER_ISN + 1, start, Vec::new())).unwrap();
        }
        let again = next_packet(&mut up_rx).await;
        assert_eq!(header(&again).sequence_number, start);
        assert_eq!(again.payload.as_ref().map(|p| p.len()), Some(500));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blockless_duplicate_acks_recover_after_an_earlier_sack() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        let (mut stream, _) = established_from_syn(up_tx, &mut up_rx, TcpConfig::default(), None, syn_with_sack()).await;
        let sender = stream.stream_sender();
        let start = write_segments(&mut stream, &mut up_rx, 4).await;
        sender
            .send(ack_with_blocks(start, &[(start.wrapping_add(500), start.wrapping_add(1000))]))
            .unwrap();
        for _ in 0..4 {
            sender.send(segment(ACK, PEER_ISN + 1, start, Vec::new())).unwrap();
        }
        assert_eq!(header(&next_packet(&mut up_rx).await).sequence_number, start);
    }

    #[test]
    fn header_sack_blocks_obeys_option_boundaries() {
        assert_eq!(header_sack_blocks(&[]), Ok(Vec::new()));
        assert_eq!(
            header_sack_blocks(&[1, 1, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2]),
            Ok(vec![(SeqNum(1), SeqNum(2))])
        );
        assert_eq!(
            header_sack_blocks(&[5, 18, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4]),
            Ok(vec![(SeqNum(1), SeqNum(2)), (SeqNum(3), SeqNum(4))])
        );
        // A block that runs backwards is no range at all.
        assert_eq!(header_sack_blocks(&[5, 10, 0, 0, 0, 2, 0, 0, 0, 1]), Ok(Vec::new()));
        assert_eq!(header_sack_blocks(&[5, 2]), Err("invalid selective acknowledgment option length"));
        assert_eq!(
            header_sack_blocks(&[5, 14, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]),
            Err("invalid selective acknowledgment option length")
        );
        assert_eq!(header_sack_blocks(&[5, 10, 0, 0]), Err("option extends past the TCP header"));
    }

    #[test]
    fn syn_sack_permitted_obeys_option_boundaries() {
        assert_eq!(syn_sack_permitted(&[]), Ok(false));
        assert_eq!(syn_sack_permitted(&[4, 2, 30]), Ok(true));
        assert_eq!(syn_sack_permitted(&[30, 1, 4, 2]), Err("option length is less than two"));
        assert_eq!(syn_sack_permitted(&[1, 4, 2, 0]), Ok(true));
        assert_eq!(syn_sack_permitted(&[3, 3, 7, 4, 2, 0, 0, 0]), Ok(true));
        assert_eq!(syn_sack_permitted(&[0, 4, 2, 0]), Ok(false));
        assert_eq!(
            syn_sack_permitted(&[4, 3, 0, 0]),
            Err("invalid selective acknowledgment permitted option length")
        );
        assert_eq!(syn_sack_permitted(&[4]), Err("missing option length"));
    }

    #[tokio::test]
    async fn the_handoff_reserves_before_consuming() {
        let (data_tx, mut data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let read_notify = std::sync::Arc::new(std::sync::Mutex::new(None));
        let nt = NetworkTuple::new("1.1.1.1:1".parse().unwrap(), "2.2.2.2:2".parse().unwrap(), true);

        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            Rto::new(RTO, MIN_RTO, MAX_RTO).unwrap(),
            MAX_RETRANSMIT_COUNT,
        );
        tcb.change_state(TcpState::Established);
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]);
        // Both arrived in order, so both are acknowledged before anything is handed over.
        assert_eq!(tcb.get_ack(), SeqNum(2000));

        // the first handoff fills the single channel slot with everything ready
        assert!(hand_off_to_reader(&mut tcb, nt, &data_tx, &read_notify).unwrap());
        assert_eq!(tcb.get_unordered_packets_total_len(), 0);

        // channel is full: the next segment stays in the map, acknowledged all the same
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]);
        assert!(!hand_off_to_reader(&mut tcb, nt, &data_tx, &read_notify).unwrap());
        assert_eq!(tcb.get_ack(), SeqNum(2500));
        assert_eq!(tcb.get_unordered_packets_total_len(), 500);

        // draining the reader frees a slot, and the next handoff flushes the tail
        let first = data_rx.recv().await.unwrap();
        assert_eq!(first.len(), 1000);
        assert!(hand_off_to_reader(&mut tcb, nt, &data_tx, &read_notify).unwrap());
        assert_eq!(tcb.get_unordered_packets_total_len(), 0);
        assert_eq!(data_rx.recv().await.unwrap().len(), 500);
    }
}
