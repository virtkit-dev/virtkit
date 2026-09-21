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

/// How many SACK blocks an acknowledgment can carry. A block costs eight bytes on top of the
/// option's two, and the options field holds forty (RFC 2018 § 3).
pub(super) const MAX_SACK_BLOCKS: usize = 4;

/// The same for a connection with timestamps, whose twelve bytes ride on every segment we send
/// and leave room for one block fewer.
pub(super) const MAX_SACK_BLOCKS_WITH_TIMESTAMPS: usize = 3;

/// Keep recency markers for eight distinct buffered runs, enough to order every block
/// that fits in a SACK option (RFC 2018 § 4).
const RECENT_OUT_OF_ORDER: usize = 8;

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

    /// Fold in an unambiguous round-trip sample. The caller applies Karn's algorithm
    /// unless an echoed timestamp identifies the transmission being acknowledged.
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

/// Expire TS.Recent after 24 days, before a millisecond clock can wrap its sign bit
/// and make timestamp ordering ambiguous (RFC 7323 § 5.5).
const TS_RECENT_LIFETIME: Duration = Duration::from_secs(24 * 24 * 60 * 60);

/// The TCP Timestamps option of RFC 7323 § 3, held only by a connection whose SYN offered one:
/// the option belongs to the connection, so a peer that did not ask for it never gets one.
#[derive(Debug, Clone)]
struct Timestamps {
    /// Monotonic milliseconds since connection start, within RFC 7323 § 5.4's
    /// 1 ms–1 s tick range. A random per-connection offset hides process uptime.
    start: std::time::Instant,
    offset: u32,
    /// TS.Recent: the peer timestamp we echo, taken from the newest segment that arrived in
    /// order.
    recent: u32,
    /// When TS.Recent was last taken. PAWS trusts it only while it is fresh (RFC 7323 § 5.5).
    recent_at: std::time::Instant,
    /// Last.ACK.sent: what the last segment we sent acknowledged. A peer can only match an
    /// acknowledgment to data it sent below that point, which is what decides whose timestamp
    /// may be echoed (RFC 7323 § 4.3).
    last_ack_sent: SeqNum,
}

impl Timestamps {
    /// Our clock as of `now`, wrapping through the 32 bits the option field holds.
    fn value_at(&self, now: std::time::Instant) -> u32 {
        self.offset
            .wrapping_add(now.saturating_duration_since(self.start).as_millis() as u32)
    }

    /// Measure an echoed clock reading with signed modular subtraction (RFC 7323 § 4.1).
    /// Reject future echoes and floor samples at the millisecond clock granularity.
    /// Zero is a valid reading when the clock wraps.
    fn round_trip(&self, tsecr: u32, now: std::time::Instant) -> Option<Duration> {
        let elapsed = self.value_at(now).wrapping_sub(tsecr) as i32;
        (elapsed >= 0).then(|| std::cmp::max(Duration::from_millis(elapsed as u64), CLOCK_GRANULARITY))
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
    /// RCV.NXT: the end of contiguous received data, acknowledged by every outgoing segment
    /// (RFC 9293 § 3.4). Advance on receipt, independently of application reads.
    rcv_nxt: SeqNum,
    /// How far the reassembly buffer has been handed to the reader. Everything between it and
    /// `rcv_nxt` is acknowledged data waiting for room in the handoff.
    delivered: SeqNum,
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
    /// Timestamps state, set only when the peer's SYN offered the option (RFC 7323 § 3.2).
    timestamps: Option<Timestamps>,
    /// Whether the SYN offered SACK-Permitted. This implementation answers the offer
    /// and enables SACK in both directions; otherwise it neither sends nor reads blocks.
    sack_permitted: bool,
    /// The sequence numbers of the out-of-order segments that arrived most recently, newest
    /// first: what decides the order the SACK blocks are reported in (RFC 2018 § 4).
    recent_out_of_order: Vec<SeqNum>,
    /// End of the flight at RTO; defer fast recovery until it is cumulatively ACKed.
    sack_timeout_end: Option<SeqNum>,
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
    /// The receive window, in bytes, that the last acknowledgment we sent advertised. An
    /// unsolicited window update is worth a segment only when the window has grown well past it.
    last_advertised_window: usize,
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
            rcv_nxt: ack,
            delivered: ack,
            mtu,
            last_received_ack: seq.into(),
            send_window: u16::MAX as u32,
            peer_window_shift: 0,
            // The SYN that opens the session replaces this through `accept_syn_mss`.
            peer_mss: DEFAULT_SEND_MSS_IPV4,
            recv_window_shift: None,
            // The SYN that opens the session turns them on through `accept_syn_timestamps`.
            timestamps: None,
            // Likewise through `accept_syn_sack_permitted`.
            sack_permitted: false,
            recent_out_of_order: Vec::new(),
            sack_timeout_end: None,
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
            last_advertised_window: read_buffer_size,
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
    /// The MSS assumes a fixed 20-byte TCP header, so `tcp_header_size` is passed with whatever
    /// options the segment carries already counted in: they come out of the peer's allowance as
    /// much as out of the link's, which is what keeps a segment carrying timestamps within both.
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

    pub(super) fn add_unordered_packet(&mut self, mut seq: SeqNum, mut buf: Vec<u8>) {
        if seq < self.rcv_nxt {
            // A retransmission reaching back over what is already acknowledged. Keeping the bytes
            // past RCV.NXT saves the peer the round trip that dropping the whole segment would cost.
            let overlap = self.rcv_nxt.distance(seq) as usize;
            if overlap >= buf.len() {
                #[rustfmt::skip]
                log::trace!("{:?}: Received fully acknowledged packet seq {seq} below ack {}, len = {}", self.state, self.rcv_nxt, buf.len());
                return;
            }
            buf = buf[overlap..].to_vec();
            seq = self.rcv_nxt;
        }
        // At the limit, admit only data filling a gap before a buffered run. Once the buffer
        // is contiguous, advancing RCV.NXT must not admit more data until the reader frees space.
        let fills_gap = seq == self.rcv_nxt && self.unordered_packets.range(self.rcv_nxt..).next().is_some();
        if !fills_gap && self.get_unordered_packets_total_len() >= self.read_buffer_size {
            #[rustfmt::skip]
            log::warn!("{:?}: Receive window full, dropping packet seq {seq}, len = {}", self.state, buf.len());
            return;
        }
        // A segment further ahead than the window reaches was never ours to receive. Holding it
        // would keep the window closed on a gap nothing can fill until the session times out.
        if seq.distance(self.rcv_nxt) as usize >= self.read_buffer_size {
            #[rustfmt::skip]
            log::warn!("{:?}: Dropping packet seq {seq} beyond the receive window at ack {}, len = {}", self.state, self.rcv_nxt, buf.len());
            return;
        }
        self.buffer_segment(seq, buf);
        if seq > self.rcv_nxt {
            if self.sack_permitted {
                self.note_out_of_order(seq);
            }
        } else {
            self.advance_rcv_nxt();
        }
    }

    /// Advance over all contiguous buffered segments after a gap fills (RFC 9293 § 3.4).
    fn advance_rcv_nxt(&mut self) {
        let mut next = self.rcv_nxt;
        // Overlapping arrivals are trimmed to RCV.NXT; tails reinserted by consumption are
        // already acknowledged. Start here to avoid scanning thousands of unread entries
        // below RCV.NXT for every arriving segment.
        for (&seq, payload) in self.unordered_packets.range(self.rcv_nxt..) {
            if seq > next {
                break;
            }
            next = std::cmp::max(next, seq + payload.len() as u32);
        }
        self.rcv_nxt = next;
    }

    /// Report the buffered run containing the newest out-of-order arrival first (RFC 2018 § 4).
    fn note_out_of_order(&mut self, seq: SeqNum) {
        let runs = self.buffered_runs();
        let mut remembered_runs = Vec::new();
        self.recent_out_of_order.insert(0, seq);
        // Keep one marker per current run; discard consumed runs and merged duplicates.
        self.recent_out_of_order.retain(|&remembered| {
            let Some(&run) = runs.iter().find(|&&(start, end)| start <= remembered && remembered < end) else {
                return false;
            };
            if remembered_runs.contains(&run) {
                return false;
            }
            remembered_runs.push(run);
            true
        });
        self.recent_out_of_order.truncate(RECENT_OUT_OF_ORDER);
    }

    /// The contiguous runs the reassembly buffer holds above the cumulative acknowledgment: the
    /// data past the hole the acknowledgment stops at. Neighbouring entries are one run, since a
    /// block describes a range and not a segment. Omit runs beginning at or below the
    /// cumulative acknowledgment because they have no preceding gap.
    fn buffered_runs(&self) -> Vec<(SeqNum, SeqNum)> {
        let mut runs: Vec<(SeqNum, SeqNum)> = Vec::new();
        for (&seq, payload) in &self.unordered_packets {
            let end = seq + payload.len() as u32;
            match runs.last_mut() {
                Some((_, run_end)) if seq <= *run_end => *run_end = std::cmp::max(*run_end, end),
                _ => runs.push((seq, end)),
            }
        }
        // A run reaching RCV.NXT has no gap before it: the cumulative acknowledgment covers it, so
        // only the runs past the hole it stops at are worth a block.
        runs.retain(|&(start, _)| start > self.rcv_nxt);
        runs
    }

    /// Report the newest buffered range first, then recently reported ranges and
    /// older ranges that fit (RFC 2018 §§ 3–4). Return no blocks without SACK
    /// negotiation or gaps in the reassembly buffer.
    pub(super) fn sack_blocks_to_send(&self) -> Vec<(SeqNum, SeqNum)> {
        if !self.sack_permitted {
            return Vec::new();
        }
        let runs = self.buffered_runs();
        let max = match self.timestamps {
            Some(_) => MAX_SACK_BLOCKS_WITH_TIMESTAMPS,
            None => MAX_SACK_BLOCKS,
        };
        let mut blocks: Vec<(SeqNum, SeqNum)> = Vec::new();
        for &seq in &self.recent_out_of_order {
            if blocks.len() == max {
                break;
            }
            let holding = runs.iter().find(|&&(start, end)| start <= seq && seq < end);
            if let Some(&run) = holding
                && !blocks.contains(&run)
            {
                blocks.push(run);
            }
        }
        // Fill unused option space with older buffered ranges.
        for &run in &runs {
            if blocks.len() == max {
                break;
            }
            if !blocks.contains(&run) {
                blocks.push(run);
            }
        }
        blocks
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

    /// Take up to `max_bytes` of the run the stream has already acknowledged: everything between
    /// what the reader has been given and RCV.NXT. Data above RCV.NXT is still waiting for a gap
    /// to be filled and is left where it is.
    pub(super) fn consume_unordered_packets(&mut self, max_bytes: usize) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        let mut remaining_bytes = max_bytes;

        while remaining_bytes > 0 {
            if let Some(seq) = self.unordered_packets.keys().next().copied() {
                if seq >= self.rcv_nxt {
                    break; // beyond the contiguous run, stop extracting
                }

                if seq < self.delivered {
                    // Overlapping retransmissions leave an entry reaching below what the reader
                    // already has; trim it so consumption continues from `delivered`.
                    let payload = self.unordered_packets.remove(&seq).unwrap();
                    let consumed = self.delivered.distance(seq) as usize;
                    if consumed < payload.len() {
                        self.buffer_segment(self.delivered, payload[consumed..].to_vec());
                    }
                    continue;
                }

                // remove and get the first packet
                let mut payload = self.unordered_packets.remove(&seq).unwrap();
                let payload_len = payload.len();

                if payload_len <= remaining_bytes {
                    // current packet can be fully extracted
                    data.extend(payload);
                    self.delivered += payload_len as u32;
                    remaining_bytes -= payload_len;
                } else {
                    // current packet can only be partially extracted
                    let remaining_payload = payload.split_off(remaining_bytes);
                    data.extend_from_slice(&payload);
                    self.delivered += remaining_bytes as u32;
                    self.buffer_segment(self.delivered, remaining_payload);
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
    /// Take the one sequence number a SYN or FIN occupies. It is acknowledged like data but
    /// carries none, so the handoff pointer steps over it whenever it has nothing left to deliver;
    /// a FIN consumed while data is still buffered leaves it behind and it never catches up, which
    /// costs nothing because no data can follow a FIN.
    pub(super) fn increase_ack(&mut self) {
        if self.delivered == self.rcv_nxt {
            self.delivered += 1;
        }
        self.rcv_nxt += 1;
    }
    /// The cumulative acknowledgment every segment we send carries: RCV.NXT.
    pub(super) fn get_ack(&self) -> SeqNum {
        self.rcv_nxt
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

    /// Take the timestamps offer from the peer's SYN: its TSval becomes TS.Recent, echoed from
    /// the SYN-ACK onwards. RFC 7323 § 3.2 makes the option a property of the connection, so a
    /// SYN that carries none leaves every segment of this session without one.
    pub(super) fn accept_syn_timestamps(&mut self, offered: Option<u32>) {
        let Some(tsval) = offered else { return };
        let now = std::time::Instant::now();
        self.timestamps = Some(Timestamps {
            start: now,
            offset: rand::RngExt::random::<u32>(&mut rand::rng()),
            recent: tsval,
            recent_at: now,
            last_ack_sent: self.rcv_nxt,
        });
    }

    /// Whether the handshake negotiated timestamps.
    pub(super) fn timestamps_negotiated(&self) -> bool {
        self.timestamps.is_some()
    }

    /// Record the peer's permission to receive SACK (RFC 2018 § 2). We answer with our
    /// own permission in the SYN-ACK, enabling both directions.
    pub(super) fn accept_syn_sack_permitted(&mut self, offered: bool) {
        self.sack_permitted = offered;
    }

    /// Whether the handshake negotiated selective acknowledgment.
    pub(super) fn sack_permitted(&self) -> bool {
        self.sack_permitted
    }

    /// The TSval and TSecr a segment sent now carries, or `None` for a connection that never
    /// negotiated the option.
    pub(super) fn timestamp_to_send(&self) -> Option<(u32, u32)> {
        let timestamps = self.timestamps.as_ref()?;
        Some((timestamps.value_at(std::time::Instant::now()), timestamps.recent))
    }

    /// Record what a segment we just sent acknowledged, RFC 7323 § 4.3's Last.ACK.sent.
    pub(super) fn note_ack_sent(&mut self) {
        let ack = self.rcv_nxt;
        if let Some(timestamps) = self.timestamps.as_mut() {
            timestamps.last_ack_sent = ack;
        }
    }

    /// Update TS.Recent for seq <= Last.ACK.sent when TSval has not gone backwards
    /// (RFC 7323 § 4.3), or the saved timestamp has expired (§ 5.5). Keep the echo
    /// unchanged for out-of-order arrivals: their ACKs cannot identify a transmission
    /// and would produce misleading RTT samples.
    pub(super) fn update_ts_recent(&mut self, seq: SeqNum, tsval: u32) {
        let Some(timestamps) = self.timestamps.as_mut() else {
            return;
        };
        if seq <= timestamps.last_ack_sent
            && (tsval.wrapping_sub(timestamps.recent) as i32 >= 0 || timestamps.recent_at.elapsed() >= TS_RECENT_LIFETIME)
        {
            timestamps.recent = tsval;
            timestamps.recent_at = std::time::Instant::now();
        }
    }

    /// Reject timestamps older than a still-valid TS.Recent (RFC 7323 § 5.3).
    pub(super) fn paws_rejects(&self, tsval: u32) -> bool {
        self.timestamps.as_ref().is_some_and(|timestamps| {
            (tsval.wrapping_sub(timestamps.recent) as i32) < 0 && timestamps.recent_at.elapsed() < TS_RECENT_LIFETIME
        })
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
    /// The window a segment sent now carries: the room left, or nothing at all while a whole
    /// segment does not fit, so the peer waits instead of dribbling (RFC 1122 § 4.2.3.3).
    pub(super) fn window_to_advertise(&self) -> usize {
        let available = self.get_recv_window_bytes();
        if available >= self.mtu as usize { available } else { 0 }
    }
    /// Record what the segment just sent told the peer about the window.
    pub(super) fn note_window_advertised(&mut self, window: u16, syn: bool) {
        let shift = if syn { 0 } else { self.recv_window_shift.unwrap_or(0) };
        self.last_advertised_window = (window as usize) << shift;
    }
    /// Follow Linux's `tcp_cleanup_rbuf`: send an update when the last window was at most half
    /// the buffer and the new one is at least twice as large. Smaller gains ride on the next
    /// segment, limiting updates per fill-and-drain cycle while promptly reopening a zero window.
    pub(super) fn window_update_due(&self) -> bool {
        let advertised = self.last_advertised_window;
        let now = (self.scale_recv_window(self.window_to_advertise()) as usize) << self.recv_window_shift.unwrap_or(0);
        now > 0 && advertised <= self.read_buffer_size / 2 && advertised <= now / 2
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
                    if self.rcv_nxt - 1 == rcvd_seq && payload.len() <= 1 {
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
        log::trace!("received {{ ack = {:08X?}, seq = {:08X?}, window = {rcvd_window} }}, self {{ ack = {:08X?}, seq = {:08X?}, send_window = {} }}, len = {len}, {res:?}", rcvd_ack.0, rcvd_seq.0, self.rcv_nxt.0, self.seq.0, self.get_send_window());
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

    /// Retire acknowledged data and measure RTT from the echoed local clock reading
    /// when timestamps are negotiated.
    pub(crate) fn update_inflight_packet_queue(&mut self, ack: SeqNum, echo: Option<u32>) {
        self.update_inflight_packet_queue_at(ack, echo, std::time::Instant::now());
    }

    fn update_inflight_packet_queue_at(&mut self, ack: SeqNum, echo: Option<u32>, now: std::time::Instant) {
        match self.inflight_packets.first_key_value() {
            None => return,
            Some((&seq, _)) if ack <= seq || ack > self.seq => return,
            _ => {}
        }
        if self.sack_timeout_end.is_some_and(|end| ack >= end) {
            self.sack_timeout_end = None;
        }
        let sample = match self.timestamps.as_ref() {
            // The echo names the transmission the acknowledgment answers, so there is nothing
            // ambiguous left for Karn's algorithm to guard against: a segment that went out twice
            // is timed like any other (RFC 7323 § 4.1).
            Some(timestamps) => echo.and_then(|tsecr| timestamps.round_trip(tsecr, now)),
            // A cumulative ACK covering retransmitted data is ambiguous even when its last
            // segment was sent only once. Sample only fully acknowledged segments so partial
            // ACKs cannot measure the same transmission repeatedly.
            None => {
                let ambiguous = self.inflight_packets.values().any(|p| p.seq < ack && p.retransmitted);
                (!ambiguous)
                    .then(|| self.inflight_packets.values().find(|p| p.seq + p.payload.len() as u32 <= ack))
                    .flatten()
                    .map(|acked| now.saturating_duration_since(acked.send_time))
            }
        };
        if let Some(sample) = sample {
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
        // What the cumulative acknowledgment covers has left the queue, and with it whatever the
        // scoreboard held against it; the segments still in flight are judged over again against
        // what is left above them.
        self.refresh_lost_marks();
        // Restart once per advancing ACK, including ACKs excluded from RTT sampling.
        self.retransmit_deadline = (!self.inflight_packets.is_empty()).then(|| now + self.rto.get());
    }

    /// Mark only packets fully covered by valid SACK ranges (RFC 2018 § 5).
    /// Partial coverage is ignored because this scoreboard tracks whole packets.
    /// Ignore DSACK and ranges outside the transmitted sequence interval.
    pub(crate) fn record_sack_blocks(&mut self, blocks: &[(SeqNum, SeqNum)]) {
        if !self.sack_permitted || blocks.is_empty() {
            return;
        }
        let Some((&oldest, _)) = self.inflight_packets.first_key_value() else {
            return;
        };
        let blocks: Vec<_> = blocks
            .iter()
            .copied()
            .filter(|&(start, end)| {
                let valid = oldest <= start && start < end && end <= self.seq;
                if !valid {
                    log::debug!("Ignoring SACK range {start}..{end} outside flight {oldest}..{}", self.seq);
                }
                valid
            })
            .collect();
        for packet in self.inflight_packets.values_mut() {
            let end = packet.seq + packet.payload.len() as u32;
            if blocks.iter().any(|&(start, block_end)| start <= packet.seq && end <= block_end) {
                packet.sacked = true;
            }
        }
        self.refresh_lost_marks();
    }

    /// Whether the scoreboard holds anything at all. With nothing selectively acknowledged there
    /// is no scoreboard to retransmit from, whatever the handshake negotiated.
    #[cfg(test)]
    pub(crate) fn has_sacked_segments(&self) -> bool {
        self.inflight_packets.values().any(|packet| packet.sacked)
    }

    /// Infer loss from DupThresh discontiguous SACKed runs or more than
    /// (DupThresh - 1) * SMSS bytes above a segment (RFC 6675 § 4).
    fn refresh_lost_marks(&mut self) {
        let threshold = self.max_count_for_dup_ack;
        let bytes_threshold = threshold.saturating_sub(1).saturating_mul(self.peer_mss as usize);
        let (mut runs_above, mut bytes_above) = (0usize, 0usize);
        let mut next_sacked_start = None;
        for packet in self.inflight_packets.values_mut().rev() {
            if packet.sacked {
                if next_sacked_start != Some(packet.seq + packet.payload.len() as u32) {
                    runs_above += 1;
                }
                next_sacked_start = Some(packet.seq);
                bytes_above += packet.payload.len();
                packet.lost = false;
            } else {
                next_sacked_start = None;
                packet.lost = runs_above >= threshold || bytes_above > bytes_threshold;
            }
        }
    }

    /// Count unsacked data still in flight, including retransmissions even when
    /// later SACK reports mark the original transmission lost again.
    fn pipe(&self) -> usize {
        self.inflight_packets
            .values()
            .filter(|packet| !packet.sacked && (!packet.lost || packet.sack_retransmitted))
            .map(|packet| packet.payload.len())
            .sum()
    }

    /// Select lost packets in sequence order, within both the recovery allowance
    /// and the peer's advertised window. Skip SACKed packets and packets retransmitted
    /// in this recovery; the timer handles loss of a retransmission.
    pub(crate) fn take_sack_retransmits(&mut self) -> Vec<(SeqNum, Vec<u8>)> {
        if !self.sack_permitted || self.sack_timeout_end.is_some() {
            return Vec::new();
        }
        let Some((&oldest, _)) = self.inflight_packets.first_key_value() else {
            return Vec::new();
        };
        let window_end = oldest + self.get_send_window();
        let allowance = self.max_unacked_bytes.min(self.get_send_window()) as usize;
        let now = std::time::Instant::now();
        let mut pipe = self.pipe();
        let mut retransmits = Vec::new();
        for packet in self.inflight_packets.values_mut() {
            if !packet.lost || packet.sacked || packet.sack_retransmitted {
                continue;
            }
            if packet.seq + packet.payload.len() as u32 > window_end || pipe + packet.payload.len() > allowance {
                break;
            }
            pipe += packet.payload.len();
            // On the wire again, so the scoreboard counts it in the pipe rather than as a hole,
            // and Karn's algorithm keeps its acknowledgment out of the round-trip estimate.
            packet.lost = false;
            packet.sack_retransmitted = true;
            packet.retransmitted = true;
            packet.send_time = now;
            retransmits.push((packet.seq, packet.payload.clone()));
        }
        if !retransmits.is_empty() {
            self.retransmit_deadline = Some(now + self.rto.get());
        }
        retransmits
    }

    /// The segment a run of duplicate ACKs is asking for, ready to be put on the wire again, with
    /// the copy noted so Karn's algorithm keeps its acknowledgment out of the estimate. A fast
    /// retransmit is not a timeout: it neither backs the timeout off nor spends one of the
    /// retransmissions the segment is allowed before the flow is abandoned.
    pub(crate) fn take_fast_retransmit(&mut self, seq: SeqNum) -> Option<(SeqNum, Vec<u8>)> {
        if self.sack_permitted && self.sack_timeout_end.is_some() {
            return None;
        }
        let packet = self.inflight_packets.get_mut(&seq)?;
        if self.sack_permitted && (packet.sacked || packet.sack_retransmitted) {
            return None;
        }
        packet.sack_retransmitted = self.sack_permitted;
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
            // Discard SACK state because the receiver may have reneged (RFC 2018 § 8).
            // Wait for this flight's cumulative ACK before fast recovery (RFC 6675 § 5.1),
            // preserving Karn's lifetime retransmission history.
            if self.sack_permitted {
                self.sack_timeout_end = Some(self.seq);
            }
            for packet in self.inflight_packets.values_mut() {
                packet.sacked = false;
                packet.lost = false;
                packet.sack_retransmitted = false;
            }
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
    /// Peer-reported receipt in its reassembly buffer (RFC 2018 §§ 5, 8).
    /// The peer may discard it, so retain the payload until cumulative acknowledgment.
    pub sacked: bool,
    /// Already retransmitted during this SACK recovery, separate from Karn's lifetime flag.
    pub sack_retransmitted: bool,
    /// Whether the SACK evidence meets the loss threshold derived from RFC 6675 § 4.
    pub lost: bool,
}

impl InflightPacket {
    fn new(seq: SeqNum, payload: Vec<u8>) -> Self {
        Self {
            seq,
            payload,
            send_time: std::time::Instant::now(),
            retransmit_count: 0,
            retransmitted: false,
            sacked: false,
            sack_retransmitted: false,
            lost: false,
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
    fn window_updates_use_the_encoded_window() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            1 << 20,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );
        // Without scaling, a full header field cannot grow despite extra buffer space.
        tcb.note_window_advertised(u16::MAX, false);
        assert!(!tcb.window_update_due());

        tcb.recv_window_shift = Some(14);
        tcb.note_window_advertised(2, false);
        assert_eq!(tcb.last_advertised_window, 32_768);
        tcb.note_window_advertised(2, true);
        assert_eq!(tcb.last_advertised_window, 2, "SYN windows must remain unscaled");

        // Free space below one scale unit still encodes zero and cannot reopen a window.
        tcb.read_buffer_size = 16_383;
        tcb.note_window_advertised(0, false);
        assert!(!tcb.window_update_due());
        tcb.read_buffer_size = 16_384;
        assert!(tcb.window_update_due());
        tcb.note_window_advertised(1, false);
        tcb.read_buffer_size = 32_767;
        assert!(!tcb.window_update_due());
        tcb.read_buffer_size = 32_768;
        assert!(tcb.window_update_due());
    }

    #[test]
    fn an_unbounded_config_does_not_overflow_the_window_update_threshold() {
        let tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            usize::MAX,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );
        assert!(!tcb.window_update_due());
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
        // All three arrived in order, so the peer is told about all three at once.
        assert_eq!(tcb.get_ack(), SeqNum(2500));

        // test 1: extract up to 700 bytes
        let data = tcb.consume_unordered_packets(700).unwrap();
        assert_eq!(data.len(), 700); // extract 500 + 200
        assert_eq!(data[..500], vec![1; 500]); // the first packet
        assert_eq!(data[500..700], vec![2; 200]); // the first 200 bytes of the second packet
        assert_eq!(tcb.delivered, SeqNum(1700)); // handed over 700 bytes
        assert_eq!(tcb.unordered_packets.len(), 2); // remaining two packets
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1700)).unwrap().len(), 300); // the second packet remaining 300 bytes
        assert_eq!(tcb.unordered_packets.get(&SeqNum(2000)).unwrap().len(), 500); // the third packet unchanged

        // test 2: extract up to 800 bytes
        let data = tcb.consume_unordered_packets(800).unwrap();
        assert_eq!(data.len(), 800); // extract 300 bytes of the second packet and the third packet
        assert_eq!(data[..300], vec![2; 300]); // the remaining 300 bytes of the second packet
        assert_eq!(data[300..800], vec![3; 500]); // the third packet
        assert_eq!(tcb.delivered, SeqNum(2500)); // handed over another 800 bytes
        assert_eq!(tcb.unordered_packets.len(), 0); // no remaining packets

        // test 3: no data to extract
        let data = tcb.consume_unordered_packets(1000);
        assert!(data.is_none());
    }

    /// A retransmission starting behind RCV.NXT carries bytes the stream already has; only what
    /// follows them is new, and a segment with nothing new at all is ignored.
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
        assert_eq!(tcb.get_ack(), SeqNum(1200));
        let data = tcb.consume_unordered_packets(10_000).unwrap();
        assert_eq!(data.len(), 200); // the 100 bytes below RCV.NXT are dropped, the rest kept
        assert_eq!(tcb.delivered, SeqNum(1200));

        tcb.add_unordered_packet(SeqNum(900), vec![1; 300]);
        assert_eq!(tcb.get_unordered_packets_total_len(), 0);
    }

    /// A segment filling a gap carries the stream over everything buffered behind it: all of it
    /// has been received, whatever the reader has got round to (RFC 9293 § 3.4).
    #[test]
    fn a_filled_gap_carries_the_stream_over_what_was_held() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]);
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]);
        assert_eq!(tcb.get_ack(), SeqNum(1000), "data past a hole was acknowledged");
        // The window pays for everything held, acknowledged or not.
        assert_eq!(tcb.get_recv_window_bytes(), READ_BUFFER_SIZE - 1000);

        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]);
        assert_eq!(tcb.get_ack(), SeqNum(2500));
        assert_eq!(tcb.get_recv_window_bytes(), READ_BUFFER_SIZE - 1500);
        assert_eq!(tcb.consume_unordered_packets(10_000).unwrap().len(), 1500);
        assert_eq!(tcb.get_recv_window_bytes(), READ_BUFFER_SIZE);
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
    fn a_full_contiguous_buffer_rejects_new_data_until_consumed() {
        for start in [SeqNum(1000), SeqNum(u32::MAX - 100)] {
            let mut tcb = Tcb::new(
                start,
                1500,
                MAX_UNACK,
                READ_BUFFER_SIZE,
                MAX_COUNT_FOR_DUP_ACK,
                estimator(RTO),
                MAX_RETRANSMIT_COUNT,
            );
            tcb.add_unordered_packet(start, vec![1; READ_BUFFER_SIZE]);
            let end = start + READ_BUFFER_SIZE as u32;
            for _ in 0..3 {
                tcb.add_unordered_packet(end, vec![2; 100]);
                tcb.add_unordered_packet(end - 100, vec![3; 200]);
                assert_eq!(tcb.get_ack(), end, "a full buffer acknowledged new data");
                assert_eq!(tcb.get_unordered_packets_total_len(), READ_BUFFER_SIZE);
            }
            assert_eq!(tcb.consume_unordered_packets(100).unwrap(), vec![1; 100]);
            tcb.add_unordered_packet(end, vec![2; 100]);
            assert_eq!(tcb.get_ack(), end + 100);
            let received = tcb.consume_unordered_packets(READ_BUFFER_SIZE).unwrap();
            assert_eq!(&received[..READ_BUFFER_SIZE - 100], vec![1; READ_BUFFER_SIZE - 100]);
            assert_eq!(&received[READ_BUFFER_SIZE - 100..], vec![2; 100]);
        }
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

        // the gap-filler makes both entries one run, so the stream reaches the end of the stored one
        assert_eq!(tcb.get_ack(), SeqNum(1500));

        // consuming pulls [1000..1400), reaching into the stored entry keyed at 1200
        let data = tcb.consume_unordered_packets(10_000).unwrap();
        assert_eq!(data.len(), 500); // 400 + the 100 bytes of the stored entry past it
        assert_eq!(tcb.delivered, SeqNum(1500));
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
        tcb.update_inflight_packet_queue(SeqNum(800), None);
        assert_eq!(tcb.inflight_packets.len(), 2); // remaining two packets
        let first_packet = tcb.inflight_packets.first_key_value().unwrap().1;
        assert_eq!(first_packet.seq, SeqNum(800)); // the remaining part of the first packet
        assert_eq!(first_packet.payload.len(), 300); // remaining 300 bytes in the first packet
        let second_packet = tcb.inflight_packets.last_key_value().unwrap().1;
        assert_eq!(second_packet.seq, SeqNum(1100)); // no change in the second packet

        // An ACK beyond the sent data cannot retire it or change the timer.
        tcb.update_inflight_packet_queue(SeqNum(2000), None);
        assert_eq!(tcb.inflight_packets.len(), 2);

        // Confirm all bytes actually sent.
        tcb.update_inflight_packet_queue(SeqNum(1600), None);
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
        tcb.update_inflight_packet_queue(SeqNum(2500), None);
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

    /// RFC 7323 § 4.3: the timestamp we echo follows the stream. A segment that overtook it
    /// carries one the peer cannot match to the acknowledgment it draws, so it is not echoed
    /// until the gap before it is filled, and nothing ever moves the echo backwards.
    #[test]
    fn the_echoed_timestamp_follows_the_stream() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.accept_syn_timestamps(Some(100));
        tcb.increase_ack(); // the peer's SYN
        tcb.note_ack_sent(); // the SYN-ACK carrying the echo of it
        assert_eq!(tcb.timestamp_to_send().map(|(_, tsecr)| tsecr), Some(100));

        let ack = tcb.get_ack();
        tcb.update_ts_recent(ack + 1000, 200);
        assert_eq!(
            tcb.timestamp_to_send().map(|(_, tsecr)| tsecr),
            Some(100),
            "a segment that overtook the stream was echoed"
        );

        tcb.update_ts_recent(ack, 150);
        assert_eq!(tcb.timestamp_to_send().map(|(_, tsecr)| tsecr), Some(150));

        tcb.update_ts_recent(ack, 120);
        assert_eq!(
            tcb.timestamp_to_send().map(|(_, tsecr)| tsecr),
            Some(150),
            "the echo went backwards"
        );
    }

    /// A SYN without the option leaves the connection without one in either direction.
    #[test]
    fn timestamps_are_never_sent_to_a_peer_that_offered_none() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.accept_syn_timestamps(None);
        assert!(!tcb.timestamps_negotiated());
        assert_eq!(tcb.timestamp_to_send(), None);

        tcb.update_ts_recent(tcb.get_ack(), 100);
        tcb.note_ack_sent();
        assert_eq!(tcb.timestamp_to_send(), None);
    }

    /// The clock is milliseconds since the connection began, started wherever the per-connection
    /// offset puts it: monotonic, and ticking inside the millisecond-to-a-second range RFC 7323
    /// § 5.4 allows.
    #[test]
    fn the_timestamp_clock_counts_milliseconds_from_the_connection() {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.accept_syn_timestamps(Some(1));
        let timestamps = tcb.timestamps.clone().unwrap();
        let start = timestamps.start;

        assert_eq!(timestamps.value_at(start), timestamps.offset);
        assert_eq!(
            timestamps.value_at(start + Duration::from_millis(1)),
            timestamps.offset.wrapping_add(1)
        );
        assert_eq!(
            timestamps.value_at(start + Duration::from_secs(1)),
            timestamps.offset.wrapping_add(1000)
        );
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
    fn an_absent_or_unusable_mss_falls_back_to_what_the_rfc_prescribes() {
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
        tcb.update_inflight_packet_queue_at(SeqNum(1500), None, sent + Duration::from_millis(1));
        let measured = tcb.rto();
        assert!(tcb.rto.srtt.is_some(), "the round trip was never measured");
        assert_eq!(measured, MIN_RTO, "a round trip of microseconds did not floor the timeout");

        // A second segment, given up on once and acknowledged afterwards.
        tcb.add_inflight_packet(vec![2; 500]).unwrap();
        expire_inflight(&mut tcb);
        let (packets, _) = tcb.collect_timed_out_inflight_packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(tcb.rto(), measured * 2);

        tcb.update_inflight_packet_queue(SeqNum(2000), None);
        assert_eq!(tcb.rto(), measured * 2, "an ambiguous ACK cleared the backoff");

        tcb.add_inflight_packet(vec![3; 500]).unwrap();
        let sent = tcb.inflight_packets[&SeqNum(2000)].send_time;
        tcb.update_inflight_packet_queue_at(SeqNum(2500), None, sent + Duration::from_millis(1));
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

        tcb.update_inflight_packet_queue(SeqNum(1500), None);
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
        tcb.update_inflight_packet_queue(SeqNum(2000), None);
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
        tcb.update_inflight_packet_queue_at(SeqNum(1250), None, partial);
        assert_eq!(tcb.rto.srtt, None);
        assert_eq!(tcb.next_timer_deadline(), Some(partial + RTO));
        tcb.update_inflight_packet_queue_at(SeqNum(1250), None, partial + RTO);
        tcb.update_inflight_packet_queue_at(SeqNum(2001), None, partial + RTO);
        assert_eq!(
            tcb.next_timer_deadline(),
            Some(partial + RTO),
            "invalid and duplicate ACKs restarted the timer"
        );

        let full = start + Duration::from_millis(200);
        tcb.update_inflight_packet_queue_at(SeqNum(1500), None, full);
        assert_eq!(tcb.rto.srtt, Some(Duration::from_millis(200)));
        assert_eq!(tcb.rto(), Duration::from_millis(600));
        assert_eq!(tcb.next_timer_deadline(), Some(full + tcb.rto()));
        tcb.update_inflight_packet_queue_at(SeqNum(1500), None, full + RTO);
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

        tcb.update_inflight_packet_queue(SeqNum(1500), None);
        assert_eq!(tcb.rto.srtt, None, "a fast-retransmitted segment timed the round trip");
    }

    /// A connection whose handshake negotiated selective acknowledgment, its stream starting at
    /// 1000.
    fn sack_tcb() -> Tcb {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.accept_syn_sack_permitted(true);
        tcb
    }

    /// RFC 2018 § 3: an acknowledgment stopping at a hole reports the range beyond it, and
    /// reports nothing at all once the hole is filled and the data delivered.
    #[test]
    fn a_hole_in_the_stream_is_reported_and_then_forgotten() {
        let mut tcb = sack_tcb();
        tcb.add_unordered_packet(SeqNum(1500), vec![1; 500]);
        assert_eq!(tcb.sack_blocks_to_send(), vec![(SeqNum(1500), SeqNum(2000))]);

        tcb.add_unordered_packet(SeqNum(1000), vec![2; 500]);
        assert_eq!(tcb.consume_unordered_packets(10_000).unwrap().len(), 1000);
        assert_eq!(tcb.get_ack(), SeqNum(2000));
        assert!(tcb.sack_blocks_to_send().is_empty(), "a filled hole was still reported");
    }

    /// A block describes a range, not a segment: neighbouring segments are one block, and a peer
    /// that negotiated nothing is told nothing.
    #[test]
    fn neighbouring_segments_are_one_block() {
        let mut tcb = sack_tcb();
        tcb.add_unordered_packet(SeqNum(1500), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(2000), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(3000), vec![1; 500]);
        assert_eq!(
            tcb.sack_blocks_to_send(),
            vec![(SeqNum(3000), SeqNum(3500)), (SeqNum(1500), SeqNum(2500))]
        );

        let mut unnegotiated = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        unnegotiated.add_unordered_packet(SeqNum(1500), vec![1; 500]);
        assert!(unnegotiated.sack_blocks_to_send().is_empty());
    }

    /// RFC 2018 § 4: the first block holds the segment that arrived last, so a peer which loses
    /// an acknowledgment still learns of the newest buffered range from the next one.
    #[test]
    fn the_newest_buffered_range_is_reported_first() {
        let mut tcb = sack_tcb();
        tcb.add_unordered_packet(SeqNum(2500), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(1500), vec![1; 500]);
        assert_eq!(
            tcb.sack_blocks_to_send(),
            vec![(SeqNum(1500), SeqNum(2000)), (SeqNum(2500), SeqNum(3000))]
        );

        tcb.add_unordered_packet(SeqNum(3500), vec![1; 500]);
        assert_eq!(
            tcb.sack_blocks_to_send(),
            vec![
                (SeqNum(3500), SeqNum(4000)),
                (SeqNum(1500), SeqNum(2000)),
                (SeqNum(2500), SeqNum(3000)),
            ]
        );
    }

    #[test]
    fn extending_one_run_preserves_other_blocks_recency() {
        let mut tcb = sack_tcb();
        for start in [1500, 3500, 5500, 7500, 9500] {
            tcb.add_unordered_packet(SeqNum(start), vec![1; 100]);
        }
        for start in (9600..10400).step_by(100) {
            tcb.add_unordered_packet(SeqNum(start), vec![1; 100]);
        }
        assert_eq!(
            tcb.sack_blocks_to_send(),
            vec![
                (SeqNum(9500), SeqNum(10400)),
                (SeqNum(7500), SeqNum(7600)),
                (SeqNum(5500), SeqNum(5600)),
                (SeqNum(3500), SeqNum(3600)),
            ]
        );
    }

    /// TCP options hold forty bytes. SACK uses two bytes plus eight per block, padded to
    /// four-byte alignment: four blocks fit, or three alongside twelve bytes of timestamps.
    #[test]
    fn the_blocks_reported_are_the_newest_that_fit() {
        let holes = |tcb: &mut Tcb| {
            for start in [5500, 4500, 3500, 2500, 1500] {
                tcb.add_unordered_packet(SeqNum(start), vec![1; 500]);
            }
        };

        let mut tcb = sack_tcb();
        holes(&mut tcb);
        assert_eq!(
            tcb.sack_blocks_to_send(),
            vec![
                (SeqNum(1500), SeqNum(2000)),
                (SeqNum(2500), SeqNum(3000)),
                (SeqNum(3500), SeqNum(4000)),
                (SeqNum(4500), SeqNum(5000)),
            ]
        );

        let mut timestamped = sack_tcb();
        timestamped.accept_syn_timestamps(Some(1));
        holes(&mut timestamped);
        assert_eq!(
            timestamped.sack_blocks_to_send(),
            vec![
                (SeqNum(1500), SeqNum(2000)),
                (SeqNum(2500), SeqNum(3000)),
                (SeqNum(3500), SeqNum(4000)),
            ]
        );
    }

    /// A block never reaches below the cumulative acknowledgment: what it covers is exactly what
    /// the acknowledgment does not.
    #[test]
    fn no_block_reaches_below_the_acknowledgment() {
        let mut tcb = sack_tcb();
        tcb.add_unordered_packet(SeqNum(2000), vec![1; 500]);
        tcb.add_unordered_packet(SeqNum(1000), vec![2; 1500]);
        assert_eq!(tcb.consume_unordered_packets(1200).unwrap().len(), 1200);
        assert_eq!(tcb.get_ack(), SeqNum(2500));

        // This run overlaps the cumulative ACK and has no preceding gap,
        // so it is omitted from the reported out-of-order runs.
        assert!(tcb.sack_blocks_to_send().is_empty());

        // A buffered range beyond a gap is reported from its actual start.
        tcb.add_unordered_packet(SeqNum(3000), vec![3; 500]);
        assert_eq!(tcb.sack_blocks_to_send(), vec![(SeqNum(3000), SeqNum(3500))]);
    }

    /// A connection with selective acknowledgment negotiated and `count` segments of 500 bytes in
    /// flight, the first of them at 1000.
    fn sack_tcb_in_flight(count: usize, max_unacked_bytes: u32) -> Tcb {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            max_unacked_bytes,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            estimator(RTO),
            MAX_RETRANSMIT_COUNT,
        );
        tcb.accept_syn_sack_permitted(true);
        tcb.seq = SeqNum(1000);
        for index in 0..count {
            tcb.add_inflight_packet(vec![index as u8; 500]).unwrap();
        }
        tcb
    }

    /// The sequence numbers a round of retransmission put back on the wire.
    fn retransmitted(tcb: &mut Tcb) -> Vec<SeqNum> {
        tcb.take_sack_retransmits().into_iter().map(|(seq, _)| seq).collect()
    }

    /// Enough SACKed bytes above the first segment identify it as lost; only it is resent.
    #[test]
    fn the_hole_is_retransmitted_and_what_the_peer_holds_is_not() {
        let mut tcb = sack_tcb_in_flight(4, MAX_UNACK);
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000))]);
        assert!(tcb.has_sacked_segments());

        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);
        assert_eq!(
            tcb.get_inflight_packets_total_len(),
            2000,
            "a segment left the queue unacknowledged"
        );
        assert!(retransmitted(&mut tcb).is_empty(), "the hole went out twice on the same blocks");
    }

    /// A block covering part of a segment says nothing about the rest of it, so the segment is
    /// still on its way as far as the scoreboard is concerned.
    #[test]
    fn a_partly_covered_segment_is_not_selectively_acknowledged() {
        let mut tcb = sack_tcb_in_flight(4, MAX_UNACK);
        tcb.record_sack_blocks(&[(SeqNum(1600), SeqNum(3000))]);
        assert!(!tcb.inflight_packets[&SeqNum(1500)].sacked);
        assert!(tcb.inflight_packets[&SeqNum(2000)].sacked);
        // One contiguous SACK range and 1000 bytes are below both loss thresholds.
        assert!(retransmitted(&mut tcb).is_empty(), "a hole was declared on two segments");
    }

    /// The other half of IsLost: bytes rather than segments, which is what catches a peer whose
    /// blocks cover more ground than DupThresh segments of ours.
    #[test]
    fn enough_bytes_above_a_segment_declare_it_lost_as_well() {
        let mut tcb = sack_tcb_in_flight(3, MAX_UNACK);
        tcb.accept_syn_mss(Some(100), true);
        // Two segments above the left edge, and 1000 bytes where 201 are enough.
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(2500))]);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);
    }

    /// A second hole is sent as soon as the blocks show it up, and the first is not sent again:
    /// retransmission inside one recovery moves forward only.
    #[test]
    fn a_second_hole_goes_out_as_the_blocks_reach_it() {
        let mut tcb = sack_tcb_in_flight(8, MAX_UNACK);
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000))]);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);

        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000)), (SeqNum(3500), SeqNum(5000))]);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(3000)]);
    }

    /// The window bounds a round of retransmission like any other sending: the pipe counts what
    /// is really on the wire, and the second hole waits for room.
    #[test]
    fn the_window_bounds_what_goes_out_at_once() {
        let mut tcb = sack_tcb_in_flight(8, 500);
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000)), (SeqNum(3500), SeqNum(5000))]);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);
    }

    #[test]
    fn invalid_sack_ranges_do_not_mark_transmitted_packets() {
        for block in [(1500, 3500), (900, 3000), (500, 1000), (2500, 1500)] {
            let mut tcb = sack_tcb_in_flight(4, MAX_UNACK);
            tcb.record_sack_blocks(&[(SeqNum(block.0), SeqNum(block.1))]);
            assert!(!tcb.has_sacked_segments(), "accepted invalid block {block:?}");
        }
    }

    #[test]
    fn sack_ranges_can_cross_sequence_wraparound() {
        let mut tcb = sack_tcb_in_flight(0, MAX_UNACK);
        tcb.seq = SeqNum(u32::MAX - 999);
        let start = tcb.seq;
        for _ in 0..4 {
            tcb.add_inflight_packet(vec![1; 500]).unwrap();
        }
        tcb.record_sack_blocks(&[(start + 500, start + 2000)]);
        assert_eq!(retransmitted(&mut tcb), vec![start]);
    }

    #[test]
    fn a_large_duplicate_threshold_does_not_overflow() {
        let mut tcb = sack_tcb_in_flight(4, MAX_UNACK);
        tcb.max_count_for_dup_ack = usize::MAX;
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000))]);
        assert!(retransmitted(&mut tcb).is_empty());
    }

    #[test]
    fn contiguous_short_segments_count_as_one_sacked_run() {
        let mut tcb = sack_tcb_in_flight(0, MAX_UNACK);
        tcb.accept_syn_mss(Some(1460), true);
        for _ in 0..4 {
            tcb.add_inflight_packet(vec![1; 100]).unwrap();
        }
        tcb.record_sack_blocks(&[(SeqNum(1100), SeqNum(1400))]);
        assert!(retransmitted(&mut tcb).is_empty());
        assert!(tcb.take_fast_retransmit(SeqNum(1000)).is_some());
        assert!(tcb.take_fast_retransmit(SeqNum(1000)).is_none());
    }

    #[test]
    fn three_discontiguous_sacked_runs_declare_a_short_segment_lost() {
        let mut tcb = sack_tcb_in_flight(0, MAX_UNACK);
        tcb.accept_syn_mss(Some(1460), true);
        for _ in 0..6 {
            tcb.add_inflight_packet(vec![1; 100]).unwrap();
        }
        tcb.record_sack_blocks(&[
            (SeqNum(1100), SeqNum(1200)),
            (SeqNum(1300), SeqNum(1400)),
            (SeqNum(1500), SeqNum(1600)),
        ]);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);
    }

    #[test]
    fn repeated_sack_reports_keep_retransmissions_in_the_pipe() {
        let mut tcb = sack_tcb_in_flight(8, 500);
        let blocks = [(SeqNum(1500), SeqNum(3000)), (SeqNum(3500), SeqNum(5000))];
        tcb.record_sack_blocks(&blocks);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);
        tcb.record_sack_blocks(&blocks);
        assert!(
            retransmitted(&mut tcb).is_empty(),
            "an outstanding retransmission exceeded the allowance"
        );
    }

    #[test]
    fn sack_retransmissions_stay_inside_the_peer_window() {
        let mut tcb = sack_tcb_in_flight(8, MAX_UNACK);
        tcb.update_send_window(500);
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000)), (SeqNum(3500), SeqNum(5000))]);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);
        tcb.update_inflight_packet_queue(SeqNum(1500), None);
        assert!(
            retransmitted(&mut tcb).is_empty(),
            "data beyond the advertised right edge was resent"
        );
    }

    /// RFC 2018 § 8: the cumulative acknowledgment is what retires data for good, and the
    /// scoreboard it leaves behind holds nothing about what has gone.
    #[test]
    fn a_cumulative_acknowledgment_takes_the_marks_with_it() {
        let mut tcb = sack_tcb_in_flight(4, MAX_UNACK);
        tcb.record_sack_blocks(&[(SeqNum(2000), SeqNum(2500))]);
        assert!(tcb.has_sacked_segments());

        tcb.update_inflight_packet_queue(SeqNum(2500), None);
        assert_eq!(tcb.get_inflight_packets_total_len(), 500);
        assert!(!tcb.has_sacked_segments(), "a mark outlived the data it was made for");
        assert!(retransmitted(&mut tcb).is_empty());
    }

    /// Expiring every packet retransmits even SACKed data and resets recovery state.
    /// Fast recovery resumes only after the timeout flight is cumulatively acknowledged.
    #[test]
    fn a_timeout_throws_the_scoreboard_away() {
        let mut tcb = sack_tcb_in_flight(4, MAX_UNACK);
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000))]);
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(1000)]);

        expire_inflight(&mut tcb);
        let (timed_out, exhausted) = tcb.collect_timed_out_inflight_packets();
        assert!(!exhausted);
        let sequences: Vec<SeqNum> = timed_out.iter().map(|packet| packet.seq).collect();
        assert_eq!(
            sequences,
            vec![SeqNum(1000), SeqNum(1500), SeqNum(2000), SeqNum(2500)],
            "the timeout went on trusting the blocks"
        );
        assert!(!tcb.has_sacked_segments());
        assert!(retransmitted(&mut tcb).is_empty(), "a hole outlived the scoreboard");
        assert!(tcb.inflight_packets.values().all(|packet| packet.retransmitted));
        assert!(tcb.inflight_packets.values().all(|packet| !packet.sack_retransmitted));
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000))]);
        assert!(retransmitted(&mut tcb).is_empty(), "repeated SACKs resent the timeout flight");
        assert!(tcb.take_fast_retransmit(SeqNum(1000)).is_none());

        // New data may join the flight, but recovery waits for the RTO boundary, not this new end.
        for _ in 0..4 {
            tcb.add_inflight_packet(vec![2; 500]).unwrap();
        }
        tcb.record_sack_blocks(&[(SeqNum(3500), SeqNum(5000))]);
        tcb.update_inflight_packet_queue(SeqNum(2500), None);
        assert!(retransmitted(&mut tcb).is_empty());
        tcb.update_inflight_packet_queue(SeqNum(3000), None);
        assert_eq!(tcb.rto.srtt, None, "the timeout reset cleared Karn's retransmission history");
        assert_eq!(retransmitted(&mut tcb), vec![SeqNum(3000)]);
    }

    /// A connection that negotiated nothing keeps no scoreboard, whatever a peer sends it.
    #[test]
    fn blocks_from_an_unnegotiated_peer_are_ignored() {
        let mut tcb = sack_tcb_in_flight(4, MAX_UNACK);
        tcb.accept_syn_sack_permitted(false);
        tcb.record_sack_blocks(&[(SeqNum(1500), SeqNum(3000))]);
        assert!(!tcb.has_sacked_segments());
        assert!(retransmitted(&mut tcb).is_empty());
    }

    /// A connection with a fixed local clock offset and the given peer timestamp.
    fn timestamped(peer_tsval: u32) -> Tcb {
        let mut tcb = tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO);
        tcb.accept_syn_timestamps(Some(peer_tsval));
        tcb.timestamps.as_mut().unwrap().offset = 1000;
        tcb.seq = SeqNum(1000);
        tcb
    }

    /// An acknowledgment carrying an echo of our clock as it read `ago` milliseconds ago.
    fn echo_of(tcb: &Tcb, ago: u32, now: std::time::Instant) -> Option<u32> {
        Some(tcb.timestamps.as_ref().unwrap().value_at(now).wrapping_sub(ago))
    }

    /// RFC 7323 § 4.1: the echo says which transmission the acknowledgment answers, so Karn's
    /// restriction lifts and a segment that went out twice is timed like any other — the
    /// opposite of `a_retransmitted_segment_is_not_measured`, which has no timestamps to go on.
    #[test]
    fn an_echoed_timestamp_measures_a_retransmitted_segment() {
        let mut tcb = timestamped(1);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        expire_inflight(&mut tcb);
        let (packets, _) = tcb.collect_timed_out_inflight_packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(tcb.rto(), RTO * 2);

        let now = std::time::Instant::now();
        tcb.update_inflight_packet_queue_at(SeqNum(1500), echo_of(&tcb, 40, now), now);
        assert_eq!(tcb.rto.srtt, Some(Duration::from_millis(40)), "the echoed round trip was ignored");
        assert_eq!(tcb.rto(), MIN_RTO, "the backoff outlived an unambiguous measurement");
    }

    /// Floor samples at the millisecond clock granularity.
    #[test]
    fn a_round_trip_inside_one_clock_tick_still_measures_a_tick() {
        let mut tcb = timestamped(1);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        let now = std::time::Instant::now();
        tcb.update_inflight_packet_queue_at(SeqNum(1500), echo_of(&tcb, 0, now), now);
        assert_eq!(tcb.rto.srtt, Some(CLOCK_GRANULARITY));
        assert_eq!(tcb.rto(), MIN_RTO);
    }

    #[test]
    fn zero_and_wrapped_echoes_measure_the_round_trip() {
        for (offset, elapsed, echo) in [(0, 40, 0), (u32::MAX - 19, 40, u32::MAX - 19)] {
            let mut tcb = timestamped(1);
            tcb.timestamps.as_mut().unwrap().offset = offset;
            tcb.add_inflight_packet(vec![1; 500]).unwrap();
            let now = tcb.timestamps.as_ref().unwrap().start + Duration::from_millis(elapsed);
            tcb.update_inflight_packet_queue_at(SeqNum(1500), Some(echo), now);
            assert_eq!(tcb.rto.srtt, Some(Duration::from_millis(40)));
        }
    }

    #[test]
    fn a_future_echo_is_ignored() {
        let mut tcb = timestamped(1);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        let now = tcb.timestamps.as_ref().unwrap().start;
        let ahead = echo_of(&tcb, 0, now + Duration::from_secs(1));
        tcb.update_inflight_packet_queue_at(SeqNum(1500), ahead, now);
        assert_eq!(tcb.rto.srtt, None, "an echo from ahead of our clock timed a round trip");
    }

    /// PAWS uses modular timestamp ordering while TS.Recent is valid (RFC 7323 § 5.3).
    #[test]
    fn paws_rejects_a_timestamp_older_than_the_one_held() {
        let mut tcb = timestamped(100);
        assert!(tcb.paws_rejects(99));
        assert!(!tcb.paws_rejects(100));
        assert!(!tcb.paws_rejects(101));

        tcb.timestamps.as_mut().unwrap().recent_at -= TS_RECENT_LIFETIME;
        assert!(!tcb.paws_rejects(99), "a stale TS.Recent was still being judged against");

        assert!(timestamped(0).paws_rejects(u32::MAX), "the comparison did not wrap");
        assert!(
            !tcb_with(MAX_UNACK, READ_BUFFER_SIZE, RTO).paws_rejects(1),
            "a connection without timestamps applied PAWS"
        );
    }

    #[test]
    fn an_expired_timestamp_is_replaced_and_paws_resumes() {
        let mut tcb = timestamped(100);
        tcb.timestamps.as_mut().unwrap().recent_at -= TS_RECENT_LIFETIME;
        assert!(!tcb.paws_rejects(50));
        tcb.update_ts_recent(tcb.get_ack() + 1, 50);
        assert_eq!(tcb.timestamp_to_send().unwrap().1, 100);
        tcb.update_ts_recent(tcb.get_ack(), 50);
        assert_eq!(tcb.timestamp_to_send().unwrap().1, 50);
        assert!(tcb.paws_rejects(49));
        assert!(!tcb.paws_rejects(51));
    }

    /// With timestamps negotiated, an acknowledgment that carries none times nothing: the segment
    /// it answers is exactly what the echo was there to name.
    #[test]
    fn an_acknowledgment_without_an_echo_measures_nothing() {
        let mut tcb = timestamped(1);
        tcb.add_inflight_packet(vec![1; 500]).unwrap();
        tcb.update_inflight_packet_queue(SeqNum(1500), None);
        assert_eq!(tcb.rto.srtt, None);
    }
}
