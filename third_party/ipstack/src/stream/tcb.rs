use super::seqnum::SeqNum;
use etherparse::TcpHeader;
use std::{collections::BTreeMap, time::Duration};

pub(super) const MAX_UNACK: u32 = 1024 * 16; // 16KB
pub(super) const READ_BUFFER_SIZE: usize = 1024 * 16; // 16KB
pub(super) const READ_CHUNK: usize = 8192; // 8KB, bytes drained from the reassembly buffer per handoff
pub(super) const MAX_COUNT_FOR_DUP_ACK: usize = 3; // Maximum number of duplicate ACKs before retransmission

/// Retransmission timeout
pub(super) const RTO: std::time::Duration = std::time::Duration::from_secs(1);

/// Maximum count of retransmissions before dropping the packet
pub(super) const MAX_RETRANSMIT_COUNT: usize = 3;

/// Longest interval between window probes while the peer's receive window is closed
const MAX_PERSIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Largest window scale RFC 7323 § 2.3 permits, which is what the 32-bit sequence space allows.
pub(super) const MAX_WINDOW_SHIFT: u8 = 14;

/// The smallest shift that lets `buffer` be advertised in a 16-bit window field.
fn window_shift_for(buffer: usize) -> u8 {
    let mut shift = 0;
    while shift < MAX_WINDOW_SHIFT && (buffer >> shift) > u16::MAX as usize {
        shift += 1;
    }
    shift
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
    /// Shift applied to the windows we advertise, set only when the peer's SYN offered scaling:
    /// RFC 7323 § 2.2 makes scaling a property of the connection, so neither side scales without
    /// it. `None` is also what says the SYN-ACK carries no window scale of its own.
    recv_window_shift: Option<u8>,
    state: TcpState,
    inflight_packets: BTreeMap<SeqNum, InflightPacket>,
    unordered_packets: BTreeMap<SeqNum, Vec<u8>>,
    duplicate_ack_count: usize,
    duplicate_ack_count_helper: SeqNum,
    max_unacked_bytes: u32,
    read_buffer_size: usize,
    max_count_for_dup_ack: usize,
    rto: std::time::Duration,
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
        rto: std::time::Duration,
        max_retransmit_count: usize,
    ) -> Tcb {
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq = rand::RngExt::random::<u32>(&mut rand::rng());
        Tcb {
            seq: seq.into(),
            ack,
            mtu,
            last_received_ack: seq.into(),
            send_window: u16::MAX as u32,
            peer_window_shift: 0,
            recv_window_shift: None,
            state: TcpState::Listen,
            inflight_packets: BTreeMap::new(),
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
            persist_timeout: rto,
        }
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

    pub fn calculate_payload_max_len(&self, ip_header_size: usize, tcp_header_size: usize) -> usize {
        let send_window = self.get_send_window() as usize;
        let mtu = self.get_mtu() as usize;
        std::cmp::min(send_window, mtu.saturating_sub(ip_header_size + tcp_header_size))
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
                self.persist_timeout = self.rto;
                self.persist_deadline = Some(std::time::Instant::now() + self.rto);
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
        self.inflight_packets.insert(self.seq, InflightPacket::new(self.seq, buf, self.rto));
        self.seq += buf_len;
        Ok(())
    }

    pub(super) fn update_last_received_ack(&mut self, ack: SeqNum) {
        self.last_received_ack = ack;
    }

    pub(crate) fn update_inflight_packet_queue(&mut self, ack: SeqNum) {
        match self.inflight_packets.first_key_value() {
            None => return,
            Some((&seq, _)) if ack < seq => return,
            _ => {}
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
    }

    pub(crate) fn find_inflight_packet(&self, seq: SeqNum) -> Option<&InflightPacket> {
        self.inflight_packets.get(&seq)
    }

    #[must_use]
    /// Collect packets due for retransmission and report any that exhausted `max_retransmit_count`.
    /// Exhausted packets leave the queue, so the caller must reset the connection: those bytes
    /// will never reach the peer, leaving a hole in the stream. Leave packets whose own timers
    /// have not expired alone, even if another packet's timer has expired.
    pub(crate) fn collect_timed_out_inflight_packets(&mut self) -> (Vec<InflightPacket>, bool) {
        let mut retransmit_list = Vec::new();
        let mut exhausted = false;

        self.inflight_packets.retain(|_, packet| {
            if !packet.is_timed_out() {
                return true; // keep the packet in the inflight_packets
            }
            if packet.retransmit_count >= self.max_retransmit_count {
                log::warn!("Packet with seq {:?} reached max retransmit count, dropping packet", packet.seq);
                exhausted = true;
                return false; // remove this packet
            }
            packet.retransmit_count += 1;
            packet.retransmit_timeout *= 2; // increase timeout exponentially
            packet.send_time = std::time::Instant::now();
            retransmit_list.push(packet.clone());
            true
        });
        (retransmit_list, exhausted)
    }

    /// Return the next window-probe deadline while the peer's window is closed, otherwise the
    /// earliest retransmission deadline, or `None` if neither exists. The session task uses this
    /// timer to retransmit and eventually abandon a silent peer without waiting for incoming data.
    pub(crate) fn next_timer_deadline(&self) -> Option<std::time::Instant> {
        if self.send_window == 0 {
            return self.persist_deadline;
        }
        self.inflight_packets.values().map(|p| p.send_time + p.retransmit_timeout).min()
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
    pub send_time: std::time::Instant,
    pub retransmit_count: usize,
    pub retransmit_timeout: std::time::Duration, // current retransmission timeout
}

impl InflightPacket {
    fn new(seq: SeqNum, payload: Vec<u8>, rto: Duration) -> Self {
        Self {
            seq,
            payload,
            send_time: std::time::Instant::now(),
            retransmit_count: 0,
            retransmit_timeout: rto,
        }
    }
    pub(crate) fn contains_seq_num(&self, seq: SeqNum) -> bool {
        self.seq <= seq && seq < self.seq + self.payload.len() as u32
    }
    pub(crate) fn is_timed_out(&self) -> bool {
        self.send_time.elapsed() >= self.retransmit_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_flight_packet() {
        let p = InflightPacket::new((u32::MAX - 1).into(), vec![10, 20, 30, 40, 50], RTO);

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
            RTO,
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
            RTO,
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
            RTO,
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
            RTO,
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
            RTO,
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
            RTO,
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

        // test 2: confirm all packets (ack=2000)
        tcb.update_inflight_packet_queue(SeqNum(2000));
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
            RTO,
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
            rto,
            MAX_RETRANSMIT_COUNT,
        );
        let slack = std::time::Duration::from_millis(5);

        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        // Simulate retransmission timeouts
        for i in 0..MAX_RETRANSMIT_COUNT {
            // Simulate a timeout for the first packet
            let timeout = tcb.inflight_packets.values().next().unwrap().retransmit_timeout + slack;
            std::thread::sleep(timeout);

            let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
            assert_eq!(packets.len(), 1);
            assert!(!exhausted, "the packet was given up on with retransmissions left");
            let packet = &packets[0];
            assert_eq!(packet.retransmit_count, i + 1);
            assert!(packet.retransmit_timeout > rto);
        }

        // The last retransmission is unacknowledged too, which takes one more timeout to learn.
        let timeout = tcb.inflight_packets.values().next().unwrap().retransmit_timeout + slack;
        std::thread::sleep(timeout);
        let (packets, exhausted) = tcb.collect_timed_out_inflight_packets();
        assert!(packets.is_empty() && exhausted);
        assert!(tcb.inflight_packets.is_empty());
    }

    /// A segment that used up its retransmissions is dropped from the queue and reported as
    /// exhausted, so the connection can be reset rather than left with a hole in the stream.
    #[test]
    fn exhausted_retransmissions_are_reported() {
        let rto = std::time::Duration::from_millis(5);
        let mut tcb = Tcb::new(SeqNum(1000), 1500, MAX_UNACK, READ_BUFFER_SIZE, MAX_COUNT_FOR_DUP_ACK, rto, 2);
        tcb.add_inflight_packet(vec![1; 100]).unwrap();
        let mut exhausted = false;
        for _ in 0..8 {
            std::thread::sleep(rto * 8);
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
            rto,
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
        let mut tcb = Tcb::new(SeqNum(1000), 1500, MAX_UNACK, READ_BUFFER_SIZE, MAX_COUNT_FOR_DUP_ACK, rto, 1);
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
}
