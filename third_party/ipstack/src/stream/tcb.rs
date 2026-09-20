use super::seqnum::SeqNum;
use etherparse::TcpHeader;
use std::{collections::BTreeMap, time::Duration};

pub(super) const MAX_UNACK: u32 = 1024 * 16; // 16KB
pub(super) const READ_BUFFER_SIZE: usize = 1024 * 16; // 16KB
pub(super) const READ_CHUNK: usize = 8192; // 8KB, bytes drained from the reassembly buffer per handoff
pub(super) const MAX_COUNT_FOR_DUP_ACK: usize = 3; // Maximum number of duplicate ACKs before retransmission

/// Retransmission timeout used until the round trip has been measured, as RFC 6298 § 2.1 has it
pub(super) const RTO: std::time::Duration = std::time::Duration::from_secs(1);

/// Floor for the measured retransmission timeout. RFC 6298 § 2.4 puts it at a second; Linux uses
/// 200ms and so do we, because a peer one virtio hop away answers in well under a millisecond and
/// a second of silence per lost segment is the whole cost this estimate is here to avoid.
pub(super) const MIN_RTO: std::time::Duration = std::time::Duration::from_millis(200);

/// Ceiling for the retransmission timeout, backoff included (RFC 6298 § 2.5 allows 60 seconds).
pub(super) const MAX_RTO: std::time::Duration = std::time::Duration::from_secs(60);

/// Clock granularity, the `G` of RFC 6298 § 2: the session task's timer is driven by tokio, which
/// rounds its sleeps up to the millisecond, so a finer figure would claim precision we cannot wake
/// up with.
const CLOCK_GRANULARITY: std::time::Duration = std::time::Duration::from_millis(1);

/// Maximum count of retransmissions before dropping the packet
pub(super) const MAX_RETRANSMIT_COUNT: usize = 3;

/// Longest interval between window probes while the peer's receive window is closed
const MAX_PERSIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Largest window scale RFC 7323 § 2.3 permits, which is what the 32-bit sequence space allows.
pub(super) const MAX_WINDOW_SHIFT: u8 = 14;

/// Default send MSS without a SYN offer: the 576-byte datagram IPv4 hosts must accept, minus
/// 40 bytes of fixed headers (RFC 9293 § 3.7.1).
pub(super) const DEFAULT_SEND_MSS_IPV4: u16 = 536;

/// IPv6 default: the 1280-byte minimum link MTU minus 60 bytes of fixed headers (RFC 9293 § 3.7.1).
pub(super) const DEFAULT_SEND_MSS_IPV6: u16 = 1220;

/// Linux's `TCP_MIN_SND_MSS` floor limits header overhead for tiny offers and prevents a zero
/// offer from blocking payload transmission.
const MIN_SEND_MSS: u16 = 48;

/// Fixed TCP header size used by the MSS option, excluding options (RFC 9293 § 3.7.1).
const FIXED_TCP_HEADER_LEN: usize = 20;

/// The smallest shift that lets `buffer` be advertised in a 16-bit window field.
fn window_shift_for(buffer: usize) -> u8 {
    let mut shift = 0;
    while shift < MAX_WINDOW_SHIFT && (buffer >> shift) > u16::MAX as usize {
        shift += 1;
    }
    shift
}

/// The retransmission timeout, estimated from the round trip as RFC 6298 § 2 prescribes.
///
/// Until the first sample it is the configured `initial`; from then on it is the smoothed round
/// trip plus four times its variation, held between `min` and `max`. A timeout doubles it;
/// only a fresh, unambiguous RTT sample ends the backoff.
#[derive(Debug, Clone)]
pub(super) struct Rto {
    /// Smoothed round-trip time, `None` until the first sample: what says whether the estimate
    /// exists at all.
    srtt: Option<Duration>,
    /// Variation of the round trip around `srtt`.
    rttvar: Duration,
    /// What the timer actually runs on, backoff included.
    current: Duration,
    min: Duration,
    max: Duration,
}

impl Rto {
    pub(super) fn new(initial: Duration, min: Duration, max: Duration) -> std::io::Result<Self> {
        if initial.is_zero() || min.is_zero() || min > max || initial > max || std::time::Instant::now().checked_add(max).is_none() {
            let message = "RTO values must be positive, rto and min_rto must not exceed max_rto, and max_rto must fit the timer";
            log::warn!("Invalid TCP configuration: {message}");
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message));
        }
        Ok(Self {
            srtt: None,
            rttvar: Duration::ZERO,
            current: initial,
            min,
            max,
        })
    }

    /// The timeout to arm the retransmission timer with.
    pub(super) fn get(&self) -> Duration {
        self.current
    }

    /// Fold in a round trip measured on a segment that went out exactly once. Karn's algorithm is
    /// the caller's business: the acknowledgment of a segment sent twice says nothing about which
    /// copy it answers, and timing it against either would poison the estimate.
    pub(super) fn sample(&mut self, rtt: Duration) {
        match self.srtt {
            // The first measurement is all there is to go on, so it becomes the estimate outright
            // and its half stands in for a variation nothing has shown yet (RFC 6298 § 2.2).
            None => {
                self.rttvar = rtt / 2;
                self.srtt = Some(rtt);
            }
            // RFC 6298 § 2.3, in that order: the variation is measured against the smoothed value
            // the sample is being compared with, not against the one it has already moved.
            Some(srtt) => {
                self.rttvar = (self.rttvar * 3 + srtt.abs_diff(rtt)) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
        self.recompute();
    }

    /// RFC 6298 § 5.5: a timeout doubles the timeout, up to the ceiling. Left alone with nothing
    /// measured, the doubling is the only thing keeping a session from retransmitting into a peer
    /// that is gone.
    pub(super) fn back_off(&mut self) {
        self.current = self.current.saturating_mul(2).min(self.max);
    }

    /// The timeout RFC 6298 § 2.2 computes: the smoothed round trip plus four variations, never
    /// shorter than the clock can measure, and kept within the configured bounds.
    fn recompute(&mut self) {
        if let Some(srtt) = self.srtt {
            self.current = (srtt + std::cmp::max(CLOCK_GRANULARITY, self.rttvar * 4)).clamp(self.min, self.max);
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum TcpState {
    // Init, /* Since we always act as a server, it starts from `Listen`, so we don't use states Init & SynSent. */
    // SynSent,
    Listen,
    SynReceived,
    Established,
    FinWait1, // act as a client, actively send a farewell packet to the other side, followed with FinWait2, TimeWait, Closed
    FinWait2,
    Closing, // our farewell crossed the peer's; waiting for ours to be acknowledged
    TimeWait,
    CloseWait, // act as a server, followed with LastAck, Closed
    LastAck,
    Closed,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(super) enum PacketType {
    WindowUpdate,
    Invalid,
    RetransmissionRequest,
    NewPacket,
    Ack,
    KeepAlive,
}

/// TCP Control Block
/// - `inflight_packets` is prerepresented bytes stream from upstream application,
///   which have been sent to the lower device but not yet acknowledged.
/// - `unordered_packets` is the bytes stream received from the lower device,
///   which can be acknowledged and extracted by `consume_unordered_packets` method
///   then can be read by upstream application via `Tcp::poll_read` method.
#[derive(Debug, Clone)]
pub(crate) struct Tcb {
    seq: SeqNum,
    ack: SeqNum,
    mtu: u16,
    last_received_ack: SeqNum,
    /// The peer's receive window in bytes, already scaled by `peer_window_shift`.
    send_window: u32,
    /// Shift applied to the windows the peer advertises, from the scale in its SYN.
    peer_window_shift: u8,
    /// Peer payload limit from the SYN MSS offer or address-family default.
    peer_mss: u16,
    /// Shift applied to the windows we advertise, set only when the peer's SYN offered scaling:
    /// RFC 7323 § 2.2 makes scaling a property of the connection, so neither side scales without
    /// it. `None` is also what says the SYN-ACK carries no window scale of its own.
    recv_window_shift: Option<u8>,
    state: TcpState,
    inflight_packets: BTreeMap<SeqNum, InflightPacket>,
    retransmit_deadline: Option<std::time::Instant>,
    unordered_packets: BTreeMap<SeqNum, Vec<u8>>,
    duplicate_ack_count: usize,
    duplicate_ack_count_helper: SeqNum,
    max_unacked_bytes: u32,
    read_buffer_size: usize,
    max_count_for_dup_ack: usize,
    rto: Rto,
    max_retransmit_count: usize,
    /// Count session-task wakes in tests. Extra wakes add scheduler round trips between ACKs and
    /// the writes they unblock. Keeping the counter here reuses the lock held on each iteration
    /// without extra plumbing.
    #[cfg(test)]
    wakes: usize,
    aborted: bool,
    fin_requested: bool,
    last_write_at: Option<std::time::Instant>,
    persist_deadline: Option<std::time::Instant>,
    persist_timeout: std::time::Duration,
}

impl Tcb {
    pub(super) fn new(
        ack: SeqNum,
        mtu: u16,
        max_unacked_bytes: u32,
        read_buffer_size: usize,
        max_count_for_dup_ack: usize,
        rto: Rto,
        max_retransmit_count: usize,
    ) -> Tcb {
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq = rand::RngExt::random::<u32>(&mut rand::rng());
        let persist_timeout = rto.get();
        Tcb {
            seq: seq.into(),
            ack,
            mtu,
            last_received_ack: seq.into(),
            send_window: u16::MAX as u32,
            peer_window_shift: 0,
            // The SYN that opens the session replaces this through `accept_syn_mss`.
            peer_mss: DEFAULT_SEND_MSS_IPV4,
            recv_window_shift: None,
            state: TcpState::Listen,
            inflight_packets: BTreeMap::new(),
            retransmit_deadline: None,
            unordered_packets: BTreeMap::new(),
            duplicate_ack_count: 0,
            duplicate_ack_count_helper: seq.into(),
            max_unacked_bytes,
            read_buffer_size,
            max_count_for_dup_ack,
            rto,
            max_retransmit_count,
            #[cfg(test)]
            wakes: 0,
            aborted: false,
            fin_requested: false,
            last_write_at: None,
            persist_deadline: None,
            persist_timeout,
        }
    }

    /// The timeout the retransmission timer is running on, as the round trip has it.
    pub(crate) fn rto(&self) -> Duration {
        self.rto.get()
    }

    #[cfg(test)]
    pub(super) fn note_wake(&mut self) {
        self.wakes += 1;
    }

    #[cfg(test)]
    pub(super) fn wakes(&self) -> usize {
        self.wakes
    }

    /// Record a reset so the application receives an error instead of mistaking EOF for a
    /// completed transfer.
    pub(super) fn mark_aborted(&mut self) {
        self.aborted = true;
    }

    pub(super) fn is_aborted(&self) -> bool {
        self.aborted
    }

    /// Record that the local side is done writing while data it sent is still unacknowledged.
    /// The session task sends the FIN once the in-flight queue drains.
    pub(super) fn request_fin(&mut self) {
        self.fin_requested = true;
    }

    pub(super) fn fin_requested(&self) -> bool {
        self.fin_requested
    }

    /// Clear the request after sending FIN so the session task cannot send it twice.
    pub(super) fn clear_fin_request(&mut self) {
        self.fin_requested = false;
    }

    /// When the application last put data on the wire. The half-close deadline runs from here:
    /// the peer has stopped sending, so the application's own writing is all that says the
    /// session is still in use.
    pub(super) fn note_write(&mut self) {
        self.last_write_at = Some(std::time::Instant::now());
    }

    pub(super) fn forget_writes(&mut self) {
        self.last_write_at = None;
    }

    pub(super) fn last_write_at(&self) -> Option<std::time::Instant> {
        self.last_write_at
    }

    /// Bound payload by the remaining send window, local MTU and peer MSS (RFC 9293 § 3.7.1).
    /// The MSS assumes a fixed 20-byte TCP header; TCP options reduce its payload allowance.
    pub fn calculate_payload_max_len(&self, ip_header_size: usize, tcp_header_size: usize) -> usize {
        let send_window = self.get_send_window() as usize;
        let mtu = self.get_mtu() as usize;
        let peer_mss = (self.peer_mss as usize + FIXED_TCP_HEADER_LEN).saturating_sub(tcp_header_size);
        std::cmp::min(send_window, mtu.saturating_sub(ip_header_size + tcp_header_size)).min(peer_mss)
    }

    pub fn update_duplicate_ack_count(&mut self, rcvd_ack: SeqNum) {
        // If the received rcvd_ack is the same as duplicate_ack_count_helper and not all data has been acknowledged (rcvd_ack < self.seq), increment the count.
        if rcvd_ack == self.duplicate_ack_count_helper && rcvd_ack < self.seq {
            self.duplicate_ack_count = self.duplicate_ack_count.saturating_add(1);
        } else {
            self.duplicate_ack_count_helper = rcvd_ack;
            self.duplicate_ack_count = 0; // reset duplicate ACK count
        }
    }

    pub fn is_duplicate_ack_count_exceeded(&self) -> bool {
        self.duplicate_ack_count >= self.max_count_for_dup_ack
    }

    pub(super) fn add_unordered_packet(&mut self, seq: SeqNum, buf: Vec<u8>) {
        if seq < self.ack {
            // A retransmission reaching back over what is already acknowledged. Keeping the bytes
            // past `ack` saves the peer the round trip that dropping the whole segment would cost.
            let overlap = self.ack.distance(seq) as usize;
            if overlap >= buf.len() {
                #[rustfmt::skip]
                log::trace!("{:?}: Received fully acknowledged packet seq {seq} below ack {}, len = {}", self.state, self.ack, buf.len());
                return;
            }
            self.buffer_segment(self.ack, buf[overlap..].to_vec());
            return;
        }
        // The head-of-line segment always advances the stream, so it is admitted even at the limit;
        // any other segment beyond the receive window is dropped for the peer's RTO to resend.
        if seq != self.ack && self.get_unordered_packets_total_len() >= self.read_buffer_size {
            #[rustfmt::skip]
            log::warn!("{:?}: Receive window full, dropping packet seq {seq}, len = {}", self.state, buf.len());
            return;
        }
        // A segment further ahead than the window reaches was never ours to receive. Holding it
        // would keep the window closed on a gap nothing can fill until the session times out.
        if seq.distance(self.ack) as usize >= self.read_buffer_size {
            #[rustfmt::skip]
            log::warn!("{:?}: Dropping packet seq {seq} beyond the receive window at ack {}, len = {}", self.state, self.ack, buf.len());
            return;
        }
        self.buffer_segment(seq, buf);
    }

    /// Keep the longer segment at a given sequence number. A retransmission split into smaller
    /// segments can repeat only a prefix; replacing the buffered copy would leave a hole.
    fn buffer_segment(&mut self, seq: SeqNum, buf: Vec<u8>) {
        match self.unordered_packets.entry(seq) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().len() < buf.len() {
                    entry.insert(buf);
                }
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(buf);
            }
        }
    }
    #[inline]
    pub(crate) fn get_unordered_packets_total_len(&self) -> usize {
        self.unordered_packets.values().map(|p| p.len()).sum()
    }

    pub(super) fn consume_unordered_packets(&mut self, max_bytes: usize) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        let mut remaining_bytes = max_bytes;

        while remaining_bytes > 0 {
            if let Some(seq) = self.unordered_packets.keys().next().copied() {
                if seq > self.ack {
                    break; // sequence number is not continuous, stop extracting
                }

                if seq < self.ack {
                    // A retransmission re-segmented across `ack` left a stale head entry; trim the
                    // part already delivered so consumption can continue from `ack`.
                    let payload = self.unordered_packets.remove(&seq).unwrap();
                    let consumed = self.ack.distance(seq) as usize;
                    if consumed < payload.len() {
                        self.buffer_segment(self.ack, payload[consumed..].to_vec());
                    }
                    continue;
                }

                // remove and get the first packet
                let mut payload = self.unordered_packets.remove(&seq).unwrap();
                let payload_len = payload.len();

                if payload_len <= remaining_bytes {
                    // current packet can be fully extracted
                    data.extend(payload);
                    self.ack += payload_len as u32;
                    remaining_bytes -= payload_len;
                } else {
                    // current packet can only be partially extracted
                    let remaining_payload = payload.split_off(remaining_bytes);
                    data.extend_from_slice(&payload);
                    self.ack += remaining_bytes as u32;
                    self.buffer_segment(self.ack, remaining_payload);
                    break;
                }
            } else {
                break; // no more packets to extract
            }
        }

        if data.is_empty() { None } else { Some(data) }
    }

    pub(super) fn increase_seq(&mut self) {
        self.seq += 1;
    }
    pub(super) fn get_seq(&self) -> SeqNum {
        self.seq
    }
    pub(super) fn increase_ack(&mut self) {
        self.ack += 1;
    }
    pub(super) fn get_ack(&self) -> SeqNum {
        self.ack
    }
    pub(super) fn get_mtu(&self) -> u16 {
        self.mtu
    }
    pub(super) fn get_last_received_ack(&self) -> SeqNum {
        self.last_received_ack
    }
    pub(super) fn change_state(&mut self, state: TcpState) {
        self.state = state;
    }
    pub(super) fn get_state(&self) -> TcpState {
        self.state
    }
    /// Take the window fields of the peer's SYN. A SYN's own window is never scaled, whatever it
    /// negotiates, and the scale it carries — or does not — decides the connection: without one
    /// neither side scales (RFC 7323 § 2.2). Our own shift is the smallest that can advertise the
    /// read buffer in full.
    pub(super) fn accept_syn_window(&mut self, window: u16, peer_shift: Option<u8>) {
        self.send_window = window as u32;
        if let Some(shift) = peer_shift {
            // A shift past the maximum is the peer's error; RFC 7323 § 2.3 has it used as 14.
            if shift > MAX_WINDOW_SHIFT {
                log::warn!("Peer window scale {shift} exceeds {MAX_WINDOW_SHIFT}; clamping it");
            }
            self.peer_window_shift = shift.min(MAX_WINDOW_SHIFT);
            self.recv_window_shift = Some(window_shift_for(self.read_buffer_size));
        }
    }

    /// Accept the peer's SYN MSS, or the address-family default from RFC 9293 § 3.7.1 if absent.
    /// Clamp offers below `MIN_SEND_MSS` to that floor.
    pub(super) fn accept_syn_mss(&mut self, offered: Option<u16>, ipv4: bool) {
        let default = if ipv4 { DEFAULT_SEND_MSS_IPV4 } else { DEFAULT_SEND_MSS_IPV6 };
        let mss = offered.unwrap_or(default);
        if mss < MIN_SEND_MSS {
            log::warn!("Peer MSS {mss} is below {MIN_SEND_MSS}; sending segments of {MIN_SEND_MSS} bytes");
        }
        self.peer_mss = mss.max(MIN_SEND_MSS);
    }

    /// Send MSS selected during the handshake.
    pub(super) fn get_peer_mss(&self) -> u16 {
        self.peer_mss
    }

    /// Our window scale, when the handshake negotiated one: the shift the SYN-ACK advertises.
    pub(super) fn get_recv_window_shift(&self) -> Option<u8> {
        self.recv_window_shift
    }

    /// A window the peer advertised, in bytes.
    fn peer_window_bytes(&self, header_window: u16) -> u32 {
        (header_window as u32) << self.peer_window_shift
    }

    /// Take the peer's advertised window from a segment past the handshake, scale and all, arming
    /// the persist timer while it is closed: nothing may be sent to a peer with no room but a probe.
    pub(super) fn update_send_window(&mut self, header_window: u16) {
        let window = self.peer_window_bytes(header_window);
        if window == 0 {
            if self.persist_deadline.is_none() {
                // The probe interval starts where the retransmission timer stands: the round trip
                // is as good a first guess for a window update as it is for a retransmission.
                self.persist_timeout = self.rto.get();
                self.persist_deadline = Some(std::time::Instant::now() + self.persist_timeout);
            }
        } else {
            self.persist_deadline = None;
        }
        self.send_window = window;
    }

    /// Whether a window probe is due, re-arming the timer at twice the interval when it is.
    /// Probing replaces retransmission while the window is closed and never gives up on the
    /// peer. The interval is capped at `max_interval` as well as at a minute: the peer's answers
    /// to these probes are all that keep the session from being declared idle, so probing more
    /// slowly than the session tolerates silence would reset the very peer it is waiting for.
    pub(super) fn take_due_persist_probe(&mut self, max_interval: Duration) -> bool {
        let Some(deadline) = self.persist_deadline else {
            return false;
        };
        let now = std::time::Instant::now();
        if now < deadline {
            return false;
        }
        self.persist_timeout = (self.persist_timeout * 2).min(MAX_PERSIST_TIMEOUT).min(max_interval);
        self.persist_deadline = Some(now + self.persist_timeout);
        true
    }
    pub(super) fn get_send_window(&self) -> u32 {
        self.send_window
    }
    /// The window we may advertise, in bytes: what the reassembly buffer still has room for.
    pub(super) fn get_recv_window_bytes(&self) -> usize {
        self.read_buffer_size.saturating_sub(self.get_unordered_packets_total_len())
    }
    /// `bytes` as a header window field: shifted by our own scale, and clamped to what the field
    /// holds — which is all a peer that agreed to no scaling can be told about.
    pub(super) fn scale_recv_window(&self, bytes: usize) -> u16 {
        (bytes >> self.recv_window_shift.unwrap_or(0)).min(u16::MAX as usize) as u16
    }
    // #[inline(always)]
    // pub(super) fn buffer_size(&self, payload_len: u16) -> u16 {
    //     match MAX_UNACK - self.inflight_packets.len() as u32 {
    //         // b if b.saturating_sub(payload_len as u32 + 64) != 0 => payload_len,
    //         // b if b < 128 && b >= 4 => (b / 2) as u16,
    //         // b if b < 4 => b as u16,
    //         // b => (b - 64) as u16,
    //         b if b >= payload_len as u32 * 2 && b > 0 => payload_len,
    //         b if b < 4 => b as u16,
    //         b => (b / 2) as u16,
    //     }
    // }

    pub(super) fn check_pkt_type(&self, tcp_header: &TcpHeader, payload: &[u8]) -> PacketType {
        let rcvd_ack = SeqNum(tcp_header.acknowledgment_number);
        let rcvd_seq = SeqNum(tcp_header.sequence_number);
        let rcvd_window = tcp_header.window_size;
        let len = payload.len();
        let res = if rcvd_ack > self.seq {
            PacketType::Invalid
        } else {
            match rcvd_ack.cmp(&self.get_last_received_ack()) {
                std::cmp::Ordering::Less => PacketType::Invalid,
                std::cmp::Ordering::Equal => {
                    if self.ack - 1 == rcvd_seq && payload.len() <= 1 {
                        PacketType::KeepAlive
                    } else if !payload.is_empty() {
                        PacketType::NewPacket
                    } else if self.get_send_window() == self.peer_window_bytes(rcvd_window)
                        && self.seq != rcvd_ack
                        && self.is_duplicate_ack_count_exceeded()
                    {
                        PacketType::RetransmissionRequest
                    } else {
                        PacketType::WindowUpdate
                    }
                }
                std::cmp::Ordering::Greater => {
                    if payload.is_empty() {
                        PacketType::Ack
                    } else {
                        PacketType::NewPacket
                    }
                }
            }
        };
        #[rustfmt::skip]
        log::trace!("received {{ ack = {:08X?}, seq = {:08X?}, window = {rcvd_window} }}, self {{ ack = {:08X?}, seq = {:08X?}, send_window = {} }}, len = {len}, {res:?}", rcvd_ack.0, rcvd_seq.0, self.ack.0, self.seq.0, self.get_send_window());
        res
    }

    pub(super) fn add_inflight_packet(&mut self, buf: Vec<u8>) -> std::io::Result<()> {
        if buf.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Empty payload"));
        }
        let buf_len = buf.len() as u32;
        let packet = InflightPacket::new(self.seq, buf);
        if self.inflight_packets.is_empty() {
            self.retransmit_deadline = Some(packet.send_time + self.rto.get());
        }
        self.inflight_packets.insert(self.seq, packet);
        self.seq += buf_len;
        Ok(())
    }

    pub(super) fn update_last_received_ack(&mut self, ack: SeqNum) {
        self.last_received_ack = ack;
    }

    pub(crate) fn update_inflight_packet_queue(&mut self, ack: SeqNum) {
        self.update_inflight_packet_queue_at(ack, std::time::Instant::now());
    }

    fn update_inflight_packet_queue_at(&mut self, ack: SeqNum, now: std::time::Instant) {
        match self.inflight_packets.first_key_value() {
            None => return,
            Some((&seq, _)) if ack <= seq || ack > self.seq => return,
            _ => {}
        }
        // A cumulative ACK covering retransmitted data is ambiguous even when its last
        // segment was sent only once. Sample only fully acknowledged segments so partial
        // ACKs cannot measure the same transmission repeatedly.
        let ambiguous = self.inflight_packets.values().any(|p| p.seq < ack && p.retransmitted);
        if !ambiguous && let Some(acked) = self.inflight_packets.values().find(|p| p.seq + p.payload.len() as u32 <= ack) {
            let sample = now.saturating_duration_since(acked.send_time);
            self.rto.sample(sample);
            log::trace!("RTT sample {sample:?}, retransmission timeout {:?}", self.rto.get());
        }
        if let Some(seq) = self
            .inflight_packets
            .iter()
            .find(|(_, p)| p.contains_seq_num(ack - 1))
            .map(|(&s, _)| s)
        {
            let mut inflight_packet = self.inflight_packets.remove(&seq).unwrap();
            let distance = ack.distance(inflight_packet.seq) as usize;
            if distance < inflight_packet.payload.len() {
                inflight_packet.payload.drain(0..distance);
                inflight_packet.seq = ack;
                self.inflight_packets.insert(ack, inflight_packet);
            }
        }
        self.inflight_packets.retain(|_, p| ack < p.seq + p.payload.len() as u32);
        // Restart once per advancing ACK, including ACKs excluded from RTT sampling.
        self.retransmit_deadline = (!self.inflight_packets.is_empty()).then(|| now + self.rto.get());
    }

    /// The segment a run of duplicate ACKs is asking for, ready to be put on the wire again, with
    /// the copy noted so Karn's algorithm keeps its acknowledgment out of the estimate. A fast
    /// retransmit is not a timeout: it neither backs the timeout off nor spends one of the
    /// retransmissions the segment is allowed before the flow is abandoned.
    pub(crate) fn take_fast_retransmit(&mut self, seq: SeqNum) -> Option<(SeqNum, Vec<u8>)> {
        let packet = self.inflight_packets.get_mut(&seq)?;
        packet.retransmitted = true;
        packet.send_time = std::time::Instant::now();
        self.retransmit_deadline = Some(packet.send_time + self.rto.get());
        Some((packet.seq, packet.payload.clone()))
    }

    #[must_use]
    /// Collect packets due for retransmission and report any that exhausted `max_retransmit_count`.
    /// Exhausted packets leave the queue, so the caller must reset the connection: those bytes
    /// will never reach the peer, leaving a hole in the stream. Leave packets whose own timers
    /// have not expired alone, even if another packet's timer has expired.
    pub(crate) fn collect_timed_out_inflight_packets(&mut self) -> (Vec<InflightPacket>, bool) {
        self.collect_timed_out_inflight_packets_at(std::time::Instant::now())
    }

    fn collect_timed_out_inflight_packets_at(&mut self, now: std::time::Instant) -> (Vec<InflightPacket>, bool) {
        let mut retransmit_list = Vec::new();
        let mut exhausted = false;
        let rto = self.rto.get();
        if self.retransmit_deadline.is_none_or(|due| now < due) {
            return (retransmit_list, exhausted);
        }

        self.inflight_packets.retain(|_, packet| {
            if !packet.is_timed_out(now, rto) {
                return true; // keep the packet in the inflight_packets
            }
            if packet.retransmit_count >= self.max_retransmit_count {
                log::warn!("Packet with seq {:?} reached max retransmit count, dropping packet", packet.seq);
                exhausted = true;
                return false; // remove this packet
            }
            packet.retransmit_count += 1;
            packet.retransmitted = true;
            packet.send_time = now;
            retransmit_list.push(packet.clone());
            true
        });
        // Back off once per timer expiry, regardless of how many segments it retransmits.
        if !retransmit_list.is_empty() {
            self.rto.back_off();
        }
        // Staggered segments share one timer round; none may back it off again before
        // the interval armed by this expiry has elapsed.
        self.retransmit_deadline = if self.inflight_packets.is_empty() {
            None
        } else if retransmit_list.is_empty() {
            self.inflight_packets.values().map(|p| p.send_time + rto).min()
        } else {
            Some(now + self.rto.get())
        };
        (retransmit_list, exhausted)
    }

    /// Return the next window-probe deadline while the peer's window is closed, otherwise the
    /// earliest retransmission deadline, or `None` if neither exists. The session task uses this
    /// timer to retransmit and eventually abandon a silent peer without waiting for incoming data.
    pub(crate) fn next_timer_deadline(&self) -> Option<std::time::Instant> {
        if self.send_window == 0 {
            return self.persist_deadline;
        }
        self.retransmit_deadline
    }

    pub(crate) fn get_inflight_packets_total_len(&self) -> usize {
        self.inflight_packets.values().map(|p| p.payload.len()).sum()
    }

    #[allow(dead_code)]
    pub(crate) fn get_all_inflight_packets(&self) -> Vec<&InflightPacket> {
        self.inflight_packets.values().collect::<Vec<_>>()
    }

    pub fn is_send_buffer_full(&self) -> bool {
        // To respect the receiver's window (remote_window) size and avoid sending too many unacknowledged packets, which may cause packet loss
        // Simplified version: min(cwnd, rwnd)
        self.seq.distance(self.get_last_received_ack()) >= self.max_unacked_bytes.min(self.get_send_window())
    }
}

#[derive(Debug, Clone)]
pub struct InflightPacket {
    pub seq: SeqNum,
    pub payload: Vec<u8>,
    /// When the copy now on the wire went out: what the retransmission timer runs from, and what
    /// an acknowledgment is measured against.
    pub send_time: std::time::Instant,
    /// How many times the timer has given up on this segment, which is what `max_retransmit_count`
    /// bounds. A fast retransmit is not counted: it is the peer asking, not the peer silent.
    pub retransmit_count: usize,
    /// Whether this segment has been on the wire more than once, from the timer or from a run of
    /// duplicate ACKs. Karn's algorithm bars such a segment from timing the round trip.
    pub retransmitted: bool,
}

impl InflightPacket {
    fn new(seq: SeqNum, payload: Vec<u8>) -> Self {
        Self {
            seq,
            payload,
            send_time: std::time::Instant::now(),
            retransmit_count: 0,
            retransmitted: false,
        }
    }
    pub(crate) fn contains_seq_num(&self, seq: SeqNum) -> bool {
        self.seq <= seq && seq < self.seq + self.payload.len() as u32
    }
    pub(crate) fn is_timed_out(&self, now: std::time::Instant, rto: Duration) -> bool {
        now.saturating_duration_since(self.send_time) >= rto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An estimator starting from `initial`, with the crate's own bounds around it.
    fn estimator(initial: Duration) -> Rto {
        Rto::new(initial, MIN_RTO, MAX_RTO).unwrap()
    }

    /// Pretend every segment in flight went out a timeout ago, so the retransmission timer is due
    /// without the test sleeping through it.
    fn expire_inflight(tcb: &mut Tcb) {
        let rto = tcb.rto();
        for packet in tcb.inflight_packets.values_mut() {
            packet.send_time -= rto;
        }
        tcb.retransmit_deadline = Some(std::time::Instant::now());
    }

    #[test]
    fn test_in_flight_packet() {
        let p = InflightPacket::new((u32::MAX - 1).into(), vec![10, 20, 30, 40, 50]);

        assert!(p.contains_seq_num((u32::MAX - 1).into()));
        assert!(p.contains_seq_num(u32::MAX.into()));
        assert!(p.contains_seq_num(0.into()));
        assert!(p.contains_seq_num(1.into()));
        assert!(p.contains_seq_num(2.into()));

        assert!(!p.contains_seq_num(3.into()));
    }

    #[test]
    fn test_get_unordered_packets_with_max_bytes() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );

        // insert 3 consecutive packets
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]); // seq=1000, len=500
        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]); // seq=1500, len=500
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]); // seq=2000, len=500

        // test 1: extract up to 700 bytes
        let data = tcb.consume_unordered_packets(700).unwrap();
        assert_eq!(data.len(), 700); // extract 500 + 200
        assert_eq!(data[..500], vec![1; 500]); // the first packet
        assert_eq!(data[500..700], vec![2; 200]); // the first 200 bytes of the second packet
        assert_eq!(tcb.ack, SeqNum(1700)); // ack increased by 700
        assert_eq!(tcb.unordered_packets.len(), 2); // remaining two packets
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1700)).unwrap().len(), 300); // the second packet remaining 300 bytes
        assert_eq!(tcb.unordered_packets.get(&SeqNum(2000)).unwrap().len(), 500); // the third packet unchanged

        // test 2: extract up to 800 bytes
        let data = tcb.consume_unordered_packets(800).unwrap();
        assert_eq!(data.len(), 800); // extract 300 bytes of the second packet and the third packet
        assert_eq!(data[..300], vec![2; 300]); // the remaining 300 bytes of the second packet
        assert_eq!(data[300..800], vec![3; 500]); // the third packet
        assert_eq!(tcb.ack, SeqNum(2500)); // ack increased by 800
        assert_eq!(tcb.unordered_packets.len(), 0); // no remaining packets

        // test 3: no data to extract
        let data = tcb.consume_unordered_packets(1000);
        assert!(data.is_none());
    }

    /// A retransmission starting behind `ack` carries bytes already delivered; only what follows
    /// them is new, and a segment with nothing new at all is ignored.
    #[test]
    fn an_overlapping_retransmit_keeps_only_the_new_bytes() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_unordered_packet(SeqNum(900), vec![1; 300]);
        let data = tcb.consume_unordered_packets(10_000).unwrap();
        assert_eq!(data.len(), 200); // the 100 bytes below ack are dropped, the rest kept
        assert_eq!(tcb.ack, SeqNum(1200));

        tcb.add_unordered_packet(SeqNum(900), vec![1; 300]);
        assert_eq!(tcb.get_unordered_packets_total_len(), 0);
    }

    /// A retransmission re-segmented into a short repeat of what is buffered must not replace it:
    /// the shorter copy would leave a hole in data the stream already holds.
    #[test]
    fn a_shorter_repeat_does_not_shrink_a_buffered_segment() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_unordered_packet(SeqNum(1200), vec![1; 400]);
        tcb.add_unordered_packet(SeqNum(1200), vec![2; 100]);
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1200)).unwrap().len(), 400);
    }

    #[test]
    fn test_add_unordered_packet_enforces_read_buffer() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );

        // a segment further ahead than the window reaches is dropped, buffer or no buffer
        tcb.add_unordered_packet(SeqNum(1000 + READ_BUFFER_SIZE as u32), vec![6; 500]);
        assert_eq!(tcb.get_unordered_packets_total_len(), 0);

        // fill the receive buffer to its limit with an out-of-order gap held open
        tcb.add_unordered_packet(SeqNum(1100), vec![7; READ_BUFFER_SIZE]);
        assert_eq!(tcb.get_unordered_packets_total_len(), READ_BUFFER_SIZE);

        // a further out-of-order segment is dropped, keeping the buffer bounded
        tcb.add_unordered_packet(SeqNum(1050), vec![8; 500]);
        assert_eq!(tcb.get_unordered_packets_total_len(), READ_BUFFER_SIZE);

        // the head-of-line segment is admitted even at the limit, so the stream advances
        tcb.add_unordered_packet(SeqNum(1000), vec![9; 500]);
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1000)).unwrap().len(), 500);
    }

    #[test]
    fn test_consume_trims_overlapping_head_entry() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );

        // an out-of-order segment stored ahead of ack
        tcb.add_unordered_packet(SeqNum(1200), vec![2; 300]);
        // the gap-filler that a retransmission re-segmented to overlap the stored one
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 400]);

        // consuming pulls [1000..1400), advancing ack into the stored entry keyed at 1200
        let data = tcb.consume_unordered_packets(10_000).unwrap();
        assert_eq!(data.len(), 500); // 400 + the 100 bytes of the stored entry past ack
        assert_eq!(tcb.ack, SeqNum(1500));
        assert_eq!(tcb.unordered_packets.len(), 0);
    }

    #[test]
    fn test_update_inflight_packet_queue() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );
        tcb.seq = SeqNum(100); // setting the initial seq

        // insert 3 consecutive packets
        tcb.add_inflight_packet(vec![1; 500]).unwrap(); // seq=100, len=500
        tcb.add_inflight_packet(vec![2; 500]).unwrap(); // seq=600, len=500
        tcb.add_inflight_packet(vec![3; 500]).unwrap(); // seq=1100, len=500

        // test 1: confirm partial packets (ack=800)
        tcb.update_inflight_packet_queue(SeqNum(800));
        assert_eq!(tcb.inflight_packets.len(), 2); // remaining two packets
        let first_packet = tcb.inflight_packets.first_key_value().unwrap().1;
        assert_eq!(first_packet.seq, SeqNum(800)); // the remaining part of the first packet
        assert_eq!(first_packet.payload.len(), 300); // remaining 300 bytes in the first packet
        let second_packet = tcb.inflight_packets.last_key_value().unwrap().1;
        assert_eq!(second_packet.seq, SeqNum(1100)); // no change in the second packet

        // An ACK beyond the sent data cannot retire it or change the timer.
        tcb.update_inflight_packet_queue(SeqNum(2000));
        assert_eq!(tcb.inflight_packets.len(), 2);

        // Confirm all bytes actually sent.
        tcb.update_inflight_packet_queue(SeqNum(1600));
        assert_eq!(tcb.inflight_packets.len(), 0); // all packets are acknowledged
    }

    #[test]
    fn test_update_inflight_packet_queue_cumulative_ack() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );
        tcb.seq = SeqNum(1000);

        // Insert 3 consecutive packets
        tcb.add_inflight_packet(vec![1; 500]).unwrap(); // seq=1000, len=500
        tcb.add_inflight_packet(vec![2; 500]).unwrap(); // seq=1500, len=500
        tcb.add_inflight_packet(vec![3; 500]).unwrap(); // seq=2000, len=500

        // Emulate cumulative ACK: ack=2500
        tcb.update_inflight_packet_queue(SeqNum(2500));
        assert_eq!(tcb.inflight_packets.len(), 0); // all packets should be removed
    }

    #[test]
    fn test_retransmit_with_exponential_backoff() {
        let rto = std::time::Duration::from_millis(5);
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(rto),
            MAX_RETRANSMIT_COUNT,
        );
        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        // Simulate retransmission timeouts
        for i in 0..MAX_RETRANSMIT_COUNT {
            // Simulate a timeout for the first packet
            expire_inflight(&mut tcb);

            let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
            assert_eq!(packets.len(), 1);
            assert!(!exhausted, "the packet was given up on with retransmissions left");
            assert_eq!(packets[0].retransmit_count, i + 1);
            // RFC 6298 § 5.5: one doubling per timeout, so the schedule is 5, 10, 20, 40ms here.
            assert_eq!(tcb.rto(), rto * 2u32.pow(i as u32 + 1));
        }

        // The last retransmission is unacknowledged too, which takes one more timeout to learn.
        expire_inflight(&mut tcb);
        let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
        assert!(packets.is_empty() && exhausted);
        assert!(tcb.inflight_packets.is_empty());
    }

    /// A segment that used up its retransmissions is dropped from the queue and reported as
    /// exhausted, so the connection can be reset rather than left with a hole in the stream.
    #[test]
    fn exhausted_retransmissions_are_reported() {
        let rto = std::time::Duration::from_millis(5);
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(rto),
            2,
        );
        tcb.add_inflight_packet(vec![1; 100]).unwrap();
        let mut exhausted = false;
        for _ in 0..8 {
            expire_inflight(&mut tcb);
            let (_, e) = tcb.collect_timed_out_inflight_packets();
            if e {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted, "retransmission exhaustion was never reported");
        assert!(tcb.inflight_packets.is_empty());
        let (packets, again) = tcb.collect_timed_out_inflight_packets();
        assert!(packets.is_empty() && !again, "an empty queue reports nothing");
    }

    fn tcb_with(max_unacked_bytes: u32, read_buffer_size: usize, rto: Duration) -> Tcb {
        Tcb::new(
            SeqNum(1000),
            1500,
            max_unacked_bytes,
            read_buffer_size,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(rto),
            MAX_RETRANSMIT_COUNT,
        )
    }

    /// Our own shift is the smallest that can advertise the read buffer in full, capped where
    /// RFC 7323 § 2.3 caps it.
    #[test]
    fn the_advertised_shift_covers_the_read_buffer() {
        assert_eq!(window_shift_for(READ_BUFFER_SIZE), 0);
        assert_eq!(window_shift_for(u16::MAX as usize), 0);
        assert_eq!(window_shift_for(u16::MAX as usize + 1), 1);
        assert_eq!(window_shift_for(4 * 1024 * 1024), 7);
        assert_eq!(window_shift_for(usize::MAX), MAX_WINDOW_SHIFT);
    }

    /// A read buffer larger than the window field holds is worth nothing until it is advertised
    /// through the scale.
    #[test]
    fn a_large_read_buffer_is_advertised_scaled() {
        const FOUR_MIB: usize = 4 * 1024 * 1024;
        let mut tcb = tcb_with(MAX_UNACK, FOUR_MIB, RTO);
        tcb.accept_syn_window(64240, Some(7));

        assert_eq!(tcb.get_recv_window_shift(), Some(7));
        let bytes = tcb.get_recv_window_bytes();
        assert_eq!(bytes, FOUR_MIB);
        assert_eq!((tcb.scale_recv_window(bytes) as usize) << 7, bytes);
    }

    /// The scale in the peer's SYN applies to every window it advertises afterwards, so a
    /// 1000-byte field at shift 7 is 128 000 bytes of room to fill.
    #[test]
    fn a_scaled_peer_window_admits_the_bytes_it_stands_for() {
        let mut tcb = tcb_with(256 * 1024, READ_BUFFER_SIZE, RTO);
        tcb.accept_syn_window(64240, Some(7));
        assert_eq!(tcb.get_send_window(), 64240, "the SYN's own window was scaled");

        tcb.update_send_window(1000);
        assert_eq!(tcb.get_send_window(), 128_000);
        tcb.seq = SeqNum(5000);
        tcb.update_last_received_ack(SeqNum(5000));
        assert!(!tcb.is_send_buffer_full());
        tcb.seq += 127_999;
        assert!(!tcb.is_send_buffer_full(), "the peer's window was cut short of what it scales to");
        tcb.seq += 1;
        assert!(tcb.is_send_buffer_full());
    }

    /// A SYN without the option leaves the connection unscaled in both directions, and one asking
    /// for more than RFC 7323 § 2.3 allows is taken as asking for the maximum.
    #[test]
    fn a_peer_shift_is_used_only_when_offered_and_never_past_the_maximum() {
        let mut unscaled = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        unscaled.accept_syn_window(64240, None);
        unscaled.update_send_window(1000);
        assert_eq!(unscaled.get_send_window(), 1000);
        assert_eq!(unscaled.get_recv_window_shift(), None);
        assert_eq!(unscaled.scale_recv_window(1000), 1000);

        let mut capped = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        capped.accept_syn_window(64240, Some(20));
        capped.update_send_window(1);
        assert_eq!(capped.get_send_window(), 1 << MAX_WINDOW_SHIFT);
    }

    /// Payload must fit the send window, local MTU after headers, and peer MSS.
    #[test]
    fn the_payload_is_bounded_by_the_window_the_link_and_the_peer_mss() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO); // an MTU of 1500
        tcb.accept_syn_mss(Some(9000), true);
        assert_eq!(tcb.calculate_payload_max_len(20, 20), 1460, "the link was not the limit");
        assert_eq!(
            tcb.calculate_payload_max_len(40, 20),
            1440,
            "the larger IPv6 header was not paid for"
        );

        tcb.accept_syn_mss(Some(1000), true);
        assert_eq!(tcb.calculate_payload_max_len(20, 20), 1000);
        // TCP options reduce the MSS payload allowance (RFC 9293 § 3.7.1).
        assert_eq!(tcb.calculate_payload_max_len(20, 32), 988);

        tcb.update_send_window(500);
        assert_eq!(tcb.calculate_payload_max_len(20, 20), 500, "the peer's window was overrun");
    }

    /// Missing MSS offers use the address-family default; tiny offers use the send floor.
    #[test]
    fn absent_and_small_mss_offers_use_defaults_and_the_send_floor() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.accept_syn_mss(None, true);
        assert_eq!(tcb.get_peer_mss(), DEFAULT_SEND_MSS_IPV4);
        tcb.accept_syn_mss(None, false);
        assert_eq!(tcb.get_peer_mss(), DEFAULT_SEND_MSS_IPV6);
        tcb.accept_syn_mss(Some(0), true);
        assert_eq!(tcb.get_peer_mss(), MIN_SEND_MSS);
        assert_eq!(tcb.calculate_payload_max_len(20, 20), MIN_SEND_MSS as usize);
    }

    /// Zero is zero at any scale: a peer that closes its window still has to be probed before
    /// anything more is sent to it.
    #[test]
    fn a_closed_window_arms_the_persist_timer_when_scaled() {
        let rto = Duration::from_secs(60);
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, rto);
        tcb.accept_syn_window(64240, Some(7));

        tcb.update_send_window(0);
        assert_eq!(tcb.get_send_window(), 0);
        assert!(
            !tcb.take_due_persist_probe(Duration::from_secs(1)),
            "probed before the timer was due"
        );
        tcb.persist_deadline = Some(std::time::Instant::now());
        assert!(tcb.take_due_persist_probe(Duration::from_secs(1)));

        // The smallest window the peer can reopen with is a scaled one, and it ends persist mode.
        tcb.update_send_window(1);
        assert_eq!(tcb.get_send_window(), 128);
        assert!(!tcb.take_due_persist_probe(Duration::from_secs(1)));
    }

    /// A packet is given up on only after its own timer expires with its retransmissions spent.
    #[test]
    fn a_packet_whose_timer_has_not_expired_is_not_given_up_on() {
        let rto = std::time::Duration::from_millis(5);
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(rto),
            1,
        );
        tcb.add_inflight_packet(vec![1; 100]).unwrap();

        std::thread::sleep(rto * 4);
        let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
        assert_eq!(packets.len(), 1, "the only retransmission never went out");
        assert!(!exhausted);

        // The retransmission has just gone out; its timer has not expired again.
        let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
        assert!(packets.is_empty() && !exhausted, "the packet was given up on before its timer");
        assert_eq!(tcb.inflight_packets.len(), 1);
    }

    /// RFC 6298 § 2.1: with no round trip measured yet, the timeout is the one the connection was
    /// configured with.
    #[test]
    fn the_timeout_starts_at_the_configured_value() {
        let tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        assert_eq!(tcb.rto(), Duration::from_secs(1));
        assert_eq!(tcb.rto.srtt, None);
    }

    /// The first measurement is all there is to go on: it becomes the smoothed round trip outright,
    /// with half of it standing in for the variation, and the timeout follows (RFC 6298 § 2.2).
    #[test]
    fn the_first_round_trip_sets_the_estimate() {
        let mut rto = estimator(RTO);
        rto.sample(Duration::from_millis(100));

        assert_eq!(rto.srtt, Some(Duration::from_millis(100)));
        assert_eq!(rto.rttvar, Duration::from_millis(50));
        assert_eq!(rto.get(), Duration::from_millis(300), "100ms + 4 * 50ms");
    }

    /// Later measurements move the smoothed values by the gains of RFC 6298 § 2.3, the variation
    /// measured against the smoothed round trip as it stood before the sample.
    #[test]
    fn later_round_trips_move_the_estimate() {
        let mut rto = estimator(RTO);
        rto.sample(Duration::from_millis(100));
        rto.sample(Duration::from_millis(200));

        // rttvar = 3/4 * 50ms + 1/4 * |100ms - 200ms|, srtt = 7/8 * 100ms + 1/8 * 200ms
        assert_eq!(rto.rttvar, Duration::from_micros(62_500));
        assert_eq!(rto.srtt, Some(Duration::from_micros(112_500)));
        assert_eq!(rto.get(), Duration::from_micros(362_500), "112.5ms + 4 * 62.5ms");
    }

    /// Bound both measured timeouts and each backed-off interval.
    #[test]
    fn the_estimate_is_held_between_its_bounds() {
        let mut floored = estimator(RTO);
        floored.sample(Duration::from_micros(200));
        assert_eq!(floored.get(), MIN_RTO);

        let mut capped = estimator(RTO);
        for _ in 0..12 {
            capped.back_off();
        }
        assert_eq!(capped.get(), MAX_RTO);
        capped.sample(MAX_RTO);
        assert_eq!(capped.get(), MAX_RTO);
    }

    /// Only a fresh RTT sample ends the backoff; an ambiguous ACK preserves it.
    #[test]
    fn an_acknowledgment_of_new_data_measures_and_clears_the_backoff() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.seq = SeqNum(1000);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        let sent = tcb.inflight_packets[&SeqNum(1000)].send_time;
        tcb.update_inflight_packet_queue_at(SeqNum(1500), sent + Duration::from_millis(1));
        let measured = tcb.rto();
        assert!(tcb.rto.srtt.is_some(), "the round trip was never measured");
        assert_eq!(measured, MIN_RTO, "a round trip of microseconds did not floor the timeout");

        // A second segment, given up on once and acknowledged afterwards.
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        expire_inflight(&mut tcb);
        let (packets, _) = tcb.collect_timed_out_inflight_packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(tcb.rto(), measured * 2);

        tcb.update_inflight_packet_queue(SeqNum(2000));
        assert_eq!(tcb.rto(), measured * 2, "an ambiguous ACK cleared the backoff");

        tcb.add_inflight_packet(vec![3; 500]).unwrap();
        let sent = tcb.inflight_packets[&SeqNum(2000)].send_time;
        tcb.update_inflight_packet_queue_at(SeqNum(2500), sent + Duration::from_millis(1));
        assert_eq!(tcb.rto(), measured, "a fresh sample did not clear the backoff");
    }

    /// Karn's algorithm: an acknowledgment of a segment that has been on the wire twice cannot say
    /// which copy it answers, so it times nothing at all.
    #[test]
    fn a_retransmitted_segment_is_not_measured() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.seq = SeqNum(1000);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        expire_inflight(&mut tcb);
        let (packets, _) = tcb.collect_timed_out_inflight_packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(tcb.rto(), RTO * 2);

        tcb.update_inflight_packet_queue(SeqNum(1500));
        assert_eq!(tcb.rto.srtt, None, "an ambiguous acknowledgment was measured");
        assert_eq!(tcb.rto(), RTO * 2, "an ambiguous ACK cleared the backoff");
    }

    #[test]
    fn invalid_rto_settings_are_rejected() {
        for (initial, min, max) in [
            (RTO, MIN_RTO, Duration::from_millis(100)),
            (Duration::ZERO, MIN_RTO, MAX_RTO),
            (RTO, Duration::ZERO, MAX_RTO),
            (RTO, MIN_RTO, Duration::ZERO),
            (MAX_RTO * 2, MIN_RTO, MAX_RTO),
            (RTO, MIN_RTO, Duration::MAX),
        ] {
            assert_eq!(Rto::new(initial, min, max).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        }
        assert_eq!(
            Rto::new(Duration::from_millis(5), MIN_RTO, MAX_RTO).unwrap().get(),
            Duration::from_millis(5)
        );
        let mut capped = Rto::new(MAX_RTO, MIN_RTO, MAX_RTO).unwrap();
        capped.back_off();
        assert_eq!(capped.get(), MAX_RTO);
    }

    #[test]
    fn staggered_packets_share_one_backoff_deadline() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.seq = SeqNum(1000);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        let start = tcb.inflight_packets[&SeqNum(1000)].send_time;
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        tcb.inflight_packets.get_mut(&SeqNum(1500)).unwrap().send_time = start + Duration::from_millis(10);
        assert_eq!(tcb.next_timer_deadline(), Some(start + RTO));

        let (packets, exhausted) = tcb.collect_timed_out_inflight_packets_at(start + RTO);
        assert!(!exhausted);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].seq, SeqNum(1000));
        assert_eq!(tcb.rto(), RTO * 2);
        assert_eq!(tcb.next_timer_deadline(), Some(start + RTO * 3));

        let (packets, exhausted) = tcb.collect_timed_out_inflight_packets_at(start + Duration::from_millis(2010));
        assert!(packets.is_empty() && !exhausted);
        assert_eq!(tcb.rto(), RTO * 2);
        assert_eq!(tcb.next_timer_deadline(), Some(start + RTO * 3));

        let (packets, exhausted) = tcb.collect_timed_out_inflight_packets_at(start + RTO * 3);
        assert!(!exhausted);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].retransmit_count, 2);
        assert_eq!(packets[1].retransmit_count, 1);
        assert_eq!(tcb.rto(), RTO * 4);
        assert_eq!(tcb.next_timer_deadline(), Some(start + RTO * 7));
    }

    #[test]
    fn cumulative_acks_covering_retransmissions_are_not_measured() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.seq = SeqNum(1000);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        tcb.take_fast_retransmit(SeqNum(1000)).unwrap();
        tcb.update_inflight_packet_queue(SeqNum(2000));
        assert_eq!(tcb.rto.srtt, None);
        assert!(tcb.inflight_packets.is_empty());
        assert_eq!(tcb.next_timer_deadline(), None);
    }

    #[test]
    fn advancing_acks_restart_the_timer_and_measure_each_segment_once() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.seq = SeqNum(1000);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        let start = tcb.inflight_packets[&SeqNum(1000)].send_time;
        let partial = start + Duration::from_millis(100);
        tcb.update_inflight_packet_queue_at(SeqNum(1250), partial);
        assert_eq!(tcb.rto.srtt, None);
        assert_eq!(tcb.next_timer_deadline(), Some(partial + RTO));
        tcb.update_inflight_packet_queue_at(SeqNum(1250), partial + RTO);
        tcb.update_inflight_packet_queue_at(SeqNum(2001), partial + RTO);
        assert_eq!(
            tcb.next_timer_deadline(),
            Some(partial + RTO),
            "invalid and duplicate ACKs restarted the timer"
        );

        let full = start + Duration::from_millis(200);
        tcb.update_inflight_packet_queue_at(SeqNum(1500), full);
        assert_eq!(tcb.rto.srtt, Some(Duration::from_millis(200)));
        assert_eq!(tcb.rto(), Duration::from_millis(600));
        assert_eq!(tcb.next_timer_deadline(), Some(full + tcb.rto()));
        tcb.update_inflight_packet_queue_at(SeqNum(1500), full + RTO);
        assert_eq!(tcb.rto.srtt, Some(Duration::from_millis(200)));
    }

    /// A fast retransmit is the peer asking for a segment, not the peer gone silent: it spends
    /// none of the segment's retransmissions and leaves the timeout where it is. The second copy
    /// it puts on the wire does make the segment ambiguous, so Karn's algorithm applies to it too.
    #[test]
    fn a_fast_retransmit_is_not_a_timeout() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.seq = SeqNum(1000);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        let (seq, payload) = tcb.take_fast_retransmit(SeqNum(1000)).expect("the segment was not in flight");
        assert_eq!((seq, payload.len()), (SeqNum(1000), 500));
        assert_eq!(tcb.rto(), RTO, "a fast retransmit backed the timeout off");
        assert_eq!(tcb.inflight_packets[&SeqNum(1000)].retransmit_count, 0);
        let sent = tcb.inflight_packets[&SeqNum(1000)].send_time;
        assert_eq!(tcb.next_timer_deadline(), Some(sent + RTO));
        assert!(tcb.collect_timed_out_inflight_packets_at(sent + RTO / 2).0.is_empty());

        tcb.update_inflight_packet_queue(SeqNum(1500));
        assert_eq!(tcb.rto.srtt, None, "a fast-retransmitted segment timed the round trip");
    }
}
