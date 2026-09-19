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
        MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_UNACK, MAX_WINDOW_SHIFT, PacketType, READ_BUFFER_SIZE, READ_CHUNK, RTO, Tcb,
        TcpState,
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
    /// Retransmission timeout duration.
    pub rto: std::time::Duration,
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

/// Find the SYN's first window scale, skipping unknown options by their declared length.
/// Stop at EOL or a malformed option; bytes beyond either cannot offer a scale.
fn syn_window_scale(mut options: &[u8]) -> Result<Option<u8>, &'static str> {
    use etherparse::tcp_option::{KIND_END, KIND_NOOP, KIND_WINDOW_SCALE, LEN_WINDOW_SCALE};

    while let Some((&kind, rest)) = options.split_first() {
        match kind {
            KIND_END => return Ok(None),
            KIND_NOOP => {
                options = rest;
                continue;
            }
            _ => {}
        }
        let Some((&length, _)) = rest.split_first() else {
            return Err("missing option length");
        };
        if length < 2 {
            return Err("option length is less than two");
        }
        let Some((option, remaining)) = options.split_at_checked(usize::from(length)) else {
            return Err("option extends past the TCP header");
        };
        if kind == KIND_WINDOW_SCALE {
            if length != LEN_WINDOW_SCALE {
                return Err("invalid window scale option length");
            }
            return Ok(option.get(2).copied());
        }
        options = remaining;
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
            config.rto,
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
        let tcb = this.tcb.lock().unwrap();
        let (state, aborted, buffered) = (tcb.get_state(), tcb.is_aborted(), tcb.get_unordered_packets_total_len());

        // Data the session took from the peer was acknowledged to it, so it belongs to the
        // application whatever has become of the connection since — a reset of our own included.
        // Read the handoff out before reporting the end of the stream.
        let polled = this.data_rx.poll_recv(cx);
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
            Poll::Pending if aborted => {
                // A connection the stack reset did not end in an orderly close. Reporting the
                // end of the stream would tell the application the transfer finished, and a
                // proxy would go on holding the other side of a flow that is over.
                drop(tcb);
                this.shutdown.lock().unwrap().ready();
                this.write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)))
            }
            Poll::Pending if peer_finished_sending(state) && buffered == 0 => {
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
        let payload_len = write_packet_to_device(sender, nt, &tcb, None, ACK | PSH, None, Some(buf.to_vec()))?;
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
    for packet in timed_out {
        let (seq, count) = (packet.seq, packet.retransmit_count);
        log::debug!("{nt} inflight packet retransmission timeout: {seq:?}, retransmit_count: {count}");
        write_packet_to_device(sender, nt, tcb, None, ACK | PSH, Some(seq), Some(packet.payload))?;
    }
    Ok(false)
}

/// Probe a peer whose receive window is closed: a segment carrying no data, at a sequence number
/// it has already acknowledged, which it answers with an ACK reporting its window as it now
/// stands. The update that reopens the window can be lost like any other segment, and nothing
/// but this probe recovers a connection from that.
fn send_window_probe(nt: NetworkTuple, sender: &PacketSender, tcb: &Tcb) -> std::io::Result<()> {
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
/// segment, and dropping the payload loses the tail of the stream. The FIN itself counts only once
/// everything before it has been handed over — otherwise it is left for the peer to repeat, with
/// an acknowledgment naming what is still missing, as RFC 9293 § 3.10.7.4 requires.
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
    let mut acknowledged = false;
    if !payload.is_empty() {
        tcb.add_unordered_packet(seq, payload);
        // Acknowledges the data, unless the window had no room for it and nothing was taken —
        // then the peer still has to be told where the stream stands.
        acknowledged = extract_data_n_write_upstream(sender, tcb, nt, data_tx, read_notify)?;
    }
    if tcb.get_ack() != seq + len {
        if !acknowledged {
            write_packet_to_device(sender, nt, tcb, None, ACK, None, None)?;
        }
        let state = tcb.get_state();
        log::debug!(
            "{nt} {state:?}: FIN at seq {seq} is ahead of the stream at {}, not consumed",
            tcb.get_ack()
        );
        return Ok(false);
    }
    tcb.increase_ack();
    write_packet_to_device(sender, nt, tcb, None, ACK, None, None)?;
    Ok(true)
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
    let packet = create_raw_packet(src, dst, |_, _| 0, flags, TTL, seq, ack, 0, Vec::new(), None, None)?;
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
            &tcb,
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
                let tcb = tcb.lock().unwrap();
                let state = tcb.get_state();
                if state == TcpState::Closed {
                    log::debug!("{nt} {state:?}: {hint} session closed, exiting 2...");
                    return;
                }
                log::debug!("{nt} {state:?}: {hint} timer expired, resending ACK|FIN (retry {idx}/{last_ack_max_retries})");
                _ = write_packet_to_device(&pkt_sdr, nt, &tcb, None, ACK | FIN, None, None);
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
                // The upstream reader freed channel space, so flush whatever is buffered and
                // let the follow-up ACK carry the reopened window. The session is no less idle
                // for it, so `idle_deadline` stays where it is.
                let mut tcb = tcb.lock().unwrap();
                extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
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
                    send_window_probe(network_tuple, &up_packet_sender, &tcb)?;
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
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
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

        tcb.update_duplicate_ack_count(incoming_ack);

        tcb.update_inflight_packet_queue(incoming_ack);

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

        match state {
            TcpState::SynReceived if flags & ACK == ACK => {
                if len > 0 {
                    tcb.add_unordered_packet(incoming_seq, payload);
                    extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
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
                            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                        }
                        // A peer with no room repeats its acknowledgment for every probe, which
                        // reads as a retransmission request; answering one would put an empty
                        // segment on the wire, since nothing fits in a closed window.
                        PacketType::RetransmissionRequest if tcb.get_send_window() == 0 => {}
                        PacketType::RetransmissionRequest => {
                            if let Some(packet) = tcb.find_inflight_packet(incoming_ack) {
                                let (s, p) = (packet.seq, packet.payload.clone());
                                log::debug!(
                                    "{network_tuple} {state:?}: {l_info}, {pkt_type:?}, retransmission request, seq = {s}, len = {}",
                                    p.len()
                                );
                                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK | PSH, Some(s), Some(p))?;
                            }
                        }
                        PacketType::NewPacket => {
                            // Data that arrives out of order is buffered like any other, bounded
                            // by the receive window: dropping it makes the peer resend a segment
                            // we already hold, and the whole window behind it along with it.
                            tcb.add_unordered_packet(incoming_seq, payload);
                            let nt = network_tuple;
                            extract_data_n_write_upstream(&up_packet_sender, &mut tcb, nt, &data_tx, &read_notify)?;
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
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                }
                write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            }
            TcpState::LastAck => {
                if flags & FIN == FIN || incoming_seq < tcb.get_ack() {
                    // The peer repeated its FIN: our acknowledgment of it was lost, and only
                    // another one stops it retransmitting for its whole retry schedule.
                    write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
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
                        extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
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
                        write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                    } else {
                        // if the other side is still sending data, we need to deal with it like PacketStatus::NewPacket
                        tcb.add_unordered_packet(incoming_seq, payload);
                        extract_data_n_write_upstream(&up_packet_sender, &mut tcb, network_tuple, &data_tx, &read_notify)?;
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
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
                // wait to timeout, can't call `tcb.change_state(TcpState::Closed);` to change state here
                // now we need to wait for the timeout to reach...
            }
            _ => {}
        } // end of match state

        tcb.update_last_received_ack(incoming_ack);
    } // end of loop
    Ok::<(), std::io::Error>(())
}

/// Hand ready reassembly data to the reader and report whether an ACK was sent. A caller
/// handling a FIN must acknowledge it separately if this call sends no ACK.
fn extract_data_n_write_upstream(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    data_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    read_notify: &WakerSlot,
) -> std::io::Result<bool> {
    let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
    let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
    if state == TcpState::Closed {
        log::debug!("{network_tuple} {state:?}: {l_info} session closed, exiting \"data extraction task\"...");
        return Ok(false);
    }

    // Reserve the handoff slot before consuming, so buffered data is removed only once it has a
    // guaranteed home; the reserved permit shrinks the advertised window until the reader drains it.
    let permit = match data_tx.try_reserve() {
        Ok(permit) => Some(permit),
        Err(tokio::sync::mpsc::error::TrySendError::Full(())) => None,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
            return Err(std::io::Error::new(BrokenPipe, "data channel closed"));
        }
    };

    let mut handed_over = false;
    if let Some(permit) = permit
        && let Some(data) = tcb.consume_unordered_packets(READ_CHUNK)
    {
        let hint = if state == TcpState::Established { "normally" } else { "still" };
        log::trace!("{network_tuple} {state:?}: {l_info} {hint} receiving data, len = {}", data.len());
        permit.send(data);
        handed_over = true;
        read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
    }
    // ACK delivered data to advance the acknowledgment and window. Buffered data needs a duplicate
    // ACK naming the missing segment or advertising the shrunken window. With neither delivered
    // nor buffered data, an ACK would repeat the last one exactly.
    if handed_over || tcb.get_unordered_packets_total_len() > 0 {
        write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
        return Ok(true);
    }
    Ok(false)
}

/// Send a TCP packet to the downstream device, with the specified flags, sequence number, and payload.
/// The returned value is the length of the `payload` sent, it may be shorter than the length of the incoming parameter `payload`.
pub(crate) fn write_packet_to_device(
    up_packet_sender: &PacketSender,
    tuple: NetworkTuple,
    tcb: &Tcb,
    options: Option<&Vec<TcpOptions>>,
    flags: u8,
    seq: Option<SeqNum>,
    payload: Option<Vec<u8>>,
) -> std::io::Result<usize> {
    use std::io::Error;
    let seq = seq.unwrap_or(tcb.get_seq()).0;
    // Silly-window-syndrome avoidance, in bytes: advertise a real window only when a full segment
    // fits, otherwise advertise zero so the peer enters persist mode until the reader frees space.
    let available = tcb.get_recv_window_bytes();
    let window_bytes = if available >= tcb.get_mtu() as usize { available } else { 0 };
    // Our scale rides on the SYN-ACK and applies from the segment after it: the handshake's own
    // window is read unscaled by both sides (RFC 7323 § 2.2).
    let (window_size, window_scale) = match flags & SYN {
        0 => (tcb.scale_recv_window(window_bytes), None),
        _ => (window_bytes.min(u16::MAX as usize) as u16, tcb.get_recv_window_shift()),
    };
    let ack = tcb.get_ack().0;
    let (src, dst) = (tuple.dst, tuple.src); // Note: The address is reversed here
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
        options,
        window_scale,
    )?;
    let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
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
    options: Option<&Vec<TcpOptions>>,
    window_scale: Option<u8>,
) -> std::io::Result<NetworkPacket> {
    let mut tcp_header = etherparse::TcpHeader::new(src_addr.port(), dst_addr.port(), seq, win);
    tcp_header.acknowledgment_number = ack;
    tcp_header.syn = flags & SYN != 0;
    tcp_header.ack = flags & ACK != 0;
    tcp_header.rst = flags & RST != 0;
    tcp_header.fin = flags & FIN != 0;
    tcp_header.psh = flags & PSH != 0;

    let mut tcp_options = Vec::new();
    for opt in options.into_iter().flatten() {
        match opt {
            TcpOptions::MaximumSegmentSize(mss) => tcp_options.push(TcpOptionElement::MaximumSegmentSize(*mss)),
        }
    }
    if let Some(shift) = window_scale {
        tcp_options.push(TcpOptionElement::WindowScale(shift));
    }
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
        let (src, dst) = addrs();
        create_raw_packet(src, dst, |_, _| 60_000, flags, TTL, seq, ack, window, payload, None, shift).unwrap()
    }

    /// The window scale a header carries, if any.
    fn window_scale(header: &TcpHeader) -> Option<u8> {
        header.options_iterator().flatten().find_map(|option| match option {
            TcpOptionElement::WindowScale(shift) => Some(shift),
            _ => None,
        })
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
        let (src, dst) = addrs();
        let stream = IpStackTcpStream::new(src, dst, header(&syn).clone(), 0, up_tx, 1500, messenger, Arc::new(config)).unwrap();
        let synack = header(&next_packet(up_rx).await).clone();
        assert_eq!(tcp_header_flags(&synack), SYN | ACK);
        let ours = synack.sequence_number.wrapping_add(1);
        stream.stream_sender().send(segment(ACK, PEER_ISN + 1, ours, Vec::new())).unwrap();
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

    /// Accept FIN only after handing over all preceding data; accepting it earlier would strand
    /// buffered bytes at the end of the peer's stream.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fin_ahead_of_buffered_data_is_not_consumed() {
        let (up_tx, mut up_rx) = tokio::sync::mpsc::unbounded_channel();
        // One handoff slot, so the second segment has nowhere to go until the reader reads.
        let config = TcpConfig {
            read_buffer_size: 8192,
            ..TcpConfig::default()
        };
        let mut stream = established(up_tx, &mut up_rx, config).await;
        let sender = stream.stream_sender();
        let ours = stream.tcb.lock().unwrap().get_seq().0;

        sender.send(segment(ACK, PEER_ISN + 1, ours, vec![1; 4000])).unwrap();
        sender.send(segment(ACK, PEER_ISN + 4001, ours, vec![2; 4000])).unwrap();
        // The window the second segment is acknowledged with has shrunk by what is held back;
        // everything after that ACK is the answer to the FIN.
        packet_matching(&mut up_rx, |h| h.window_size < 8192).await;

        sender.send(segment(ACK | FIN, PEER_ISN + 8001, ours, Vec::new())).unwrap();
        let answer = header(&next_packet(&mut up_rx).await).clone();
        assert_eq!(tcp_header_flags(&answer), ACK);
        assert_eq!(answer.acknowledgment_number, PEER_ISN + 4001, "the FIN was taken ahead of the data");
        let state = stream.tcb.lock().unwrap().get_state();
        assert_eq!(state, TcpState::Established, "the FIN closed the connection early");

        // Both halves still reach the reader, and the FIN the peer repeats is then in sequence.
        let mut buf = vec![0u8; 8000];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the buffered data was stranded")
            .unwrap();
        assert!(buf[..4000].iter().all(|&b| b == 1) && buf[4000..].iter().all(|&b| b == 2));
        sender.send(segment(ACK | FIN, PEER_ISN + 8001, ours, Vec::new())).unwrap();
        let farewell = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 8002).await;
        assert_eq!(tcp_header_flags(&farewell) & ACK, ACK);
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
        let closed = packet_matching(&mut up_rx, |h| h.window_size == 0).await;
        assert_eq!(closed.acknowledgment_number, PEER_ISN + 4001);

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

        sender.send(segment(ACK, PEER_ISN + 4001, ours, vec![3; 1])).unwrap();
        let probed = packet_matching(&mut up_rx, |h| tcp_header_flags(h) == ACK).await;
        assert_eq!(
            probed.acknowledgment_number,
            PEER_ISN + 4001,
            "the probe byte was acknowledged too early"
        );

        // The reader drains everything, and the window the peer is waiting on reopens.
        let mut buf = vec![0u8; 12193];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .expect("the buffered data never reached the reader")
            .unwrap();
        let reopened = packet_matching(&mut up_rx, |h| h.acknowledgment_number == PEER_ISN + 12194).await;
        assert!(reopened.window_size >= 1500, "the window never reopened");
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

    #[tokio::test]
    async fn extract_reserves_before_consuming() {
        let (up_tx, _up_rx) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (data_tx, mut data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let read_notify = std::sync::Arc::new(std::sync::Mutex::new(None));
        let nt = NetworkTuple::new("1.1.1.1:1".parse().unwrap(), "2.2.2.2:2".parse().unwrap(), true);

        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );
        tcb.change_state(TcpState::Established);
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]);

        // first extract fills the single channel slot and advances ack over the first chunk
        extract_data_n_write_upstream(&up_tx, &mut tcb, nt, &data_tx, &read_notify).unwrap();
        assert_eq!(tcb.get_ack(), SeqNum(2000));

        // channel is full: extract leaves the remaining data in the map and does not advance ack
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]);
        extract_data_n_write_upstream(&up_tx, &mut tcb, nt, &data_tx, &read_notify).unwrap();
        assert_eq!(tcb.get_ack(), SeqNum(2000));
        assert_eq!(tcb.get_unordered_packets_total_len(), 500);

        // draining the reader frees a slot, and the next extract flushes the tail
        let first = data_rx.recv().await.unwrap();
        assert_eq!(first.len(), 1000);
        extract_data_n_write_upstream(&up_tx, &mut tcb, nt, &data_tx, &read_notify).unwrap();
        assert_eq!(tcb.get_ack(), SeqNum(2500));
        assert_eq!(tcb.get_unordered_packets_total_len(), 0);
    }
}
