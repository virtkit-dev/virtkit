use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE};
use crate::virtio::queue::Queue;
use crate::virtio::{DeviceQueue, InterruptTransport};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::{FrontendError, RxError, TxError, VirtioNetBackend};
use super::VNET_HDR_LEN;

#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::Ordering;
use std::thread;
use std::{cmp, result};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use virtio_bindings::virtio_net::VIRTIO_NET_F_MRG_RXBUF;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// Offset of `num_buffers` in the virtio-net header: past flags, gso_type, hdr_len,
/// gso_size, csum_start and csum_offset.
const NUM_BUFFERS_OFFSET: usize = 10;

/// A descriptor chain taken to receive part of a frame.
struct RxChain {
    /// Index of the chain's head, which is what the used ring names.
    head: u16,
    /// Where this chain's writable descriptors begin in the shared iovec.
    iovec_start: usize,
    written: u32,
}

pub struct NetWorker {
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,
    /// Whether the driver negotiated mergeable receive buffers, and so posts buffers a frame
    /// may have to be spread over.
    rx_mergeable: bool,
    rx_chains: Vec<RxChain>,
    rx_iovec: Vec<(GuestAddress, usize)>,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_has_deferred_frame: bool,
}

impl NetWorker {
    pub fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        vnet_features: u64,
        cfg_backend: VirtioNetBackend,
    ) -> Result<Self, ConnectError> {
        let backend = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixstreamPath(path) => {
                Box::new(Unixstream::open(path)?) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => {
                Box::new(Unixgram::open(path, vfkit_magic)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => {
                Box::new(Tap::new(tap_name, vnet_features)?) as Box<dyn NetBackend + Send>
            }
        };

        Ok(Self {
            rx_q,
            tx_q,

            mem,
            backend,
            interrupt,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,
            rx_mergeable: vnet_features & (1 << VIRTIO_NET_F_MRG_RXBUF) != 0,
            rx_chains: Vec::with_capacity(QUEUE_SIZE as usize),
            rx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            tx_has_deferred_frame: false,
        })
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        #[cfg(target_os = "macos")]
        const TX_TIMER_FD: RawFd = -2;

        let virtq_rx_ev_fd = self.rx_q.event.as_raw_fd();
        let virtq_tx_ev_fd = self.tx_q.event.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_rx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_tx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
                backend_socket as u64,
            ),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_rx_ev_fd => {
                                self.process_rx_queue_event();
                            }
                            EventSet::IN if source == virtq_tx_ev_fd => {
                                self.process_tx_queue_event();
                            }
                            _ if source == backend_socket => {
                                if event_set.contains(EventSet::HANG_UP)
                                    || event_set.contains(EventSet::READ_HANG_UP)
                                {
                                    log::error!("Got {event_set:?} on backend fd, virtio-net will stop working");
                                    eprintln!("LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!");
                                } else {
                                    if event_set.contains(EventSet::IN) {
                                        self.process_backend_socket_readable()
                                    }

                                    if event_set.contains(EventSet::OUT) {
                                        self.process_backend_socket_writeable()
                                    }
                                }
                            }
                            #[cfg(target_os = "macos")]
                            _ if event_set.is_empty() && source == TX_TIMER_FD => {
                                self.process_tx_loop();
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }

                    // Arm the retry timer after processing all events, so it
                    // reflects the final state of tx_has_deferred_frame.
                    #[cfg(target_os = "macos")]
                    if self.tx_has_deferred_frame {
                        let delay = self.backend.write_retry_delay_us();
                        if delay > 0 {
                            epoll.add_oneshot_timer(delay, TX_TIMER_FD as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.rx_q.event.read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        self.process_rx_loop();
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        match self.tx_q.event.read() {
            Ok(_) => self.process_tx_loop(),
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_backend_socket_readable(&mut self) {
        self.process_rx_loop();
    }

    fn process_rx_loop(&mut self) {
        loop {
            let observed = match self.rx_q.queue.avail_idx(&self.mem, Ordering::Acquire) {
                Ok(index) => index,
                Err(e) => {
                    error!("error reading available receive buffers: {e:?}");
                    return;
                }
            };
            if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
                error!("error disabling queue notifications: {e:?}");
                return;
            }
            if let Err(e) = self.process_rx() {
                error!("Failed to process rx: {e:?}");
                return;
            }
            if !self.rx_has_deferred_frame {
                return;
            }
            match self.rx_q.queue.enable_notification_at(&self.mem, observed) {
                Ok(true) => continue,
                Ok(false) => return,
                Err(e) => {
                    error!("error enabling queue notifications: {e:?}");
                    return;
                }
            }
        }
    }

    pub(crate) fn process_backend_socket_writeable(&mut self) {
        match self.backend.flush_frames() {
            Ok(()) => self.process_tx_loop(),
            Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
            Err(e @ WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        let mut signal_queue = false;
        let result = self.process_rx_frames(&mut signal_queue);
        if signal_queue {
            self.interrupt
                .try_signal_used_queue()
                .map_err(RxError::DeviceError)?;
        }
        result
    }

    fn process_rx_frames(&mut self, signal_queue: &mut bool) -> result::Result<(), RxError> {
        // if we have a deferred frame we try to process it first,
        // if that is not possible, we don't continue processing other frames
        if self.rx_has_deferred_frame {
            if self.write_frame_to_guest(signal_queue) {
                self.rx_has_deferred_frame = false;
            } else {
                return Ok(());
            }
        }

        // Read as many frames as possible.
        loop {
            match self.read_into_rx_frame_buf_from_backend() {
                Ok(()) => {
                    if !self.write_frame_to_guest(signal_queue) {
                        self.rx_has_deferred_frame = true;
                        break Ok(());
                    }
                }
                Err(ReadError::NothingRead) => break Ok(()),
                Err(e @ ReadError::Internal(_)) => break Err(RxError::Backend(e)),
            }
        }
    }

    fn process_tx_loop(&mut self) {
        loop {
            self.tx_q.queue.disable_notification(&self.mem).unwrap();

            self.tx_has_deferred_frame = match self.process_tx() {
                Err(TxError::Backend(WriteError::NothingWritten)) => true,
                Err(e) => {
                    log::error!("Failed to process tx: {e:?}");
                    false
                }
                _ => false,
            };

            let has_new_entries = self.tx_q.queue.enable_notification(&self.mem).unwrap();
            if self.tx_has_deferred_frame || !has_new_entries {
                break;
            }
        }
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let tx_queue = &mut self.tx_q.queue;

        if self.backend.has_unfinished_write() {
            match self.backend.flush_frames() {
                Ok(()) => {}
                Err(WriteError::PartialWrite | WriteError::NothingWritten) => {
                    return Err(TxError::Backend(WriteError::NothingWritten));
                }
                Err(e) => return Err(TxError::Backend(e)),
            }
        }

        let mut raise_irq = false;
        let mut result = Ok(());

        while let Some(head) = tx_queue.pop(&self.mem) {
            let head_index = head.index;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            let mut read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {e:?}");
                        read_count = 0;
                        break;
                    }
                }
            }

            match self
                .backend
                .write_frame(VNET_HDR_LEN, &mut self.tx_frame_buf[..read_count])
            {
                // The backend has the frame's bytes, on the socket or staged for the next
                // flush. Either way tx_frame_buf is free again and the chain is done with:
                // the socket is a stream, so a staged frame cannot be reordered or lost
                // behind the frames that follow it.
                Ok(()) => {
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                }
                // The backend could not take the frame at all, so the chain goes back on
                // the queue and the frame is offered again when the socket drains.
                Err(WriteError::NothingWritten) => {
                    tx_queue.undo_pop();
                    result = Err(TxError::Backend(WriteError::NothingWritten));
                    break;
                }
                Err(e) => return Err(TxError::Backend(e)),
            }
        }

        // Frames staged above leave in one send. What the socket cannot take now keeps its
        // place in the backend and goes out on the next writable event, so there is nothing
        // to wait for here: the switch could itself be blocked sending to us.
        if result.is_ok() {
            match self.backend.flush_frames() {
                Ok(()) => {}
                Err(WriteError::PartialWrite | WriteError::NothingWritten) => {
                    result = Err(TxError::Backend(WriteError::NothingWritten));
                }
                Err(e) => result = Err(TxError::Backend(e)),
            }
        }

        if raise_irq && tx_queue.needs_notification(&self.mem).unwrap() {
            self.interrupt
                .try_signal_used_queue()
                .map_err(TxError::DeviceError)?;
        }

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        write_frame_to_chains(
            &mut self.rx_q.queue,
            &self.mem,
            &mut self.rx_frame_buf[..self.rx_frame_buf_len],
            self.rx_mergeable,
            &mut self.rx_chains,
            &mut self.rx_iovec,
        )
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self, signal_queue: &mut bool) -> bool {
        let max_iterations = self.rx_q.queue.actual_size();
        for _ in 0..max_iterations {
            let used = self.rx_q.queue.next_used;
            let result = self.write_frame_to_guest_impl();
            *signal_queue |= self.rx_q.queue.next_used != used;
            match result {
                Ok(()) => return true,
                // The guest has not posted room for this frame. The chains it did post were
                // left where they were, so trying again now would only take them again: the
                // caller defers the frame until the driver adds buffers and kicks the queue.
                Err(FrontendError::EmptyQueue) => return false,
                // That chain could not take the frame and has been returned used-but-empty,
                // so the retry meets the ones behind it.
                Err(_) => continue,
            }
        }

        false
    }

    /// Fills self.rx_frame_buf with an ethernet frame from backend and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_backend(&mut self) -> result::Result<(), ReadError> {
        self.rx_frame_buf_len = self.backend.read_frame(&mut self.rx_frame_buf)?;
        Ok(())
    }
}

/// Copies `frame` — a virtio-net header followed by an ethernet frame — into the guest's
/// receive buffers.
///
/// With `mergeable`, the driver posts buffers that need not each hold a whole frame and
/// reads how many to join out of `num_buffers` in the first one's header (virtio 1.1
/// § 5.1.6.4), so the frame is spread over as many descriptor chains as it takes. Without
/// it, a frame has to fit the first chain.
///
/// Nothing is written until enough chains are in hand: a frame the driver has not posted
/// room for yet leaves the queue exactly as it found it, so it can be retried whole once
/// more buffers arrive. Chains that will never hold it — too small, or not writable — are
/// instead returned used-but-empty, so a caller retrying meets the ones behind them.
///
/// `chains` and `iovec` are scratch the caller owns only to keep this off the allocator.
fn write_frame_to_chains(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    frame: &mut [u8],
    mergeable: bool,
    chains: &mut Vec<RxChain>,
    iovec: &mut Vec<(GuestAddress, usize)>,
) -> result::Result<(), FrontendError> {
    let max_chains = if mergeable {
        queue.actual_size() as usize
    } else {
        1
    };
    chains.clear();
    iovec.clear();

    let mut capacity = 0usize;
    let mut read_only = false;
    while capacity < frame.len() && chains.len() < max_chains {
        let Some(head) = queue.pop(mem) else { break };
        chains.push(RxChain {
            head: head.index,
            iovec_start: iovec.len(),
            written: 0,
        });
        let mut next = Some(head);
        while let Some(descriptor) = &next {
            if !descriptor.is_write_only() {
                read_only = true;
                break;
            }
            iovec.push((descriptor.addr, descriptor.len as usize));
            capacity += descriptor.len as usize;
            next = descriptor.next_descriptor();
        }
        if read_only {
            break;
        }
    }

    if capacity < frame.len() {
        if !read_only && chains.len() < max_chains && iovec.len() < queue.actual_size() as usize {
            // The driver has posted nothing more for now. `pop` only moved the queue's
            // cursor, so putting it back leaves every chain available for the retry.
            for _ in 0..chains.len() {
                queue.undo_pop();
            }
            return Err(FrontendError::EmptyQueue);
        }
        log::warn!("Receiving buffer is too small to hold frame of current size");
    }
    if capacity < frame.len() || read_only {
        for chain in chains.iter() {
            queue
                .write_used(mem, chain.head, 0)
                .map_err(FrontendError::QueueError)?;
        }
        queue.publish_used(mem).map_err(FrontendError::QueueError)?;
        return Err(if read_only {
            FrontendError::ReadOnlyDescriptor
        } else {
            FrontendError::DescriptorChainTooSmall
        });
    }

    // The count goes in before a byte is copied, so the header the guest reads out of the
    // first buffer already names every buffer it has to join.
    if mergeable && frame.len() >= NUM_BUFFERS_OFFSET + 2 {
        let num_buffers = chains.len() as u16;
        frame[NUM_BUFFERS_OFFSET..NUM_BUFFERS_OFFSET + 2]
            .copy_from_slice(&num_buffers.to_le_bytes());
    }

    let mut offset = 0usize;
    let mut result = Ok(());
    for i in 0..chains.len() {
        let start = chains[i].iovec_start;
        let end = chains
            .get(i + 1)
            .map_or(iovec.len(), |chain| chain.iovec_start);
        let mut written = 0u32;
        for &(addr, len) in &iovec[start..end] {
            let take = cmp::min(frame.len() - offset, len);
            if take == 0 || result.is_err() {
                break;
            }
            match mem.write_slice(&frame[offset..offset + take], addr) {
                Ok(()) => {
                    offset += take;
                    written += take as u32;
                }
                Err(e) => {
                    log::error!("Failed to write slice: {e:?}");
                    result = Err(FrontendError::GuestMemory(e));
                    written = 0;
                    break;
                }
            }
        }
        chains[i].written = written;
    }
    // Decide all lengths only after the copy succeeds: a failed later buffer must not
    // leave a successful-looking first buffer naming a truncated frame.
    for chain in chains.iter() {
        let len = if result.is_ok() { chain.written } else { 0 };
        queue
            .write_used(mem, chain.head, len)
            .map_err(FrontendError::QueueError)?;
    }
    // One publish for the whole frame: a driver that saw the first chain before the rest
    // were recorded would read `num_buffers` and find the buffers it names missing.
    queue.publish_used(mem).map_err(FrontendError::QueueError)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::tests::{VirtQueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use vm_memory::GuestAddress;

    const QSIZE: u16 = 16;
    /// Guest address of the first receive buffer. Well clear of the rings, which VirtQueue
    /// lays out from address 0.
    const BUF_BASE: u64 = 0x1000;
    /// Every posted buffer in these tests is this long, so a frame's split across them is
    /// arithmetic rather than a guess.
    const BUF_LEN: u32 = 64;

    /// A frame of `len` bytes: a zeroed virtio-net header, then a body whose every byte
    /// names its own offset, so a misplaced copy shows up as a mismatch rather than zeros.
    fn make_frame(len: usize) -> Vec<u8> {
        let mut frame = vec![0u8; len];
        for (i, b) in frame.iter_mut().enumerate().skip(VNET_HDR_LEN) {
            *b = i as u8;
        }
        frame
    }

    /// Post `count` single-descriptor buffers of `BUF_LEN` bytes, `BUF_BASE` apart.
    fn post_buffers(vq: &VirtQueue, count: u16) {
        for i in 0..count {
            vq.dtable[i as usize].set(BUF_BASE * (i as u64 + 1), BUF_LEN, VIRTQ_DESC_F_WRITE, 0);
            vq.avail.ring[i as usize].set(i);
        }
        vq.avail.idx.set(count);
    }

    /// What the guest holds after the write: the used ring's (head, len) pairs, and the
    /// bytes they name, concatenated in the order the ring lists them.
    fn received(vq: &VirtQueue, mem: &GuestMemoryMmap) -> (Vec<(u32, u32)>, Vec<u8>) {
        let mut used = Vec::new();
        let mut bytes = Vec::new();
        for i in 0..vq.used.idx.get() as usize {
            let elem = vq.used.ring[i].get();
            used.push((elem.id, elem.len));
            let addr = GuestAddress(BUF_BASE * (elem.id as u64 + 1));
            let mut buf = vec![0u8; elem.len as usize];
            mem.read_slice(&mut buf, addr).unwrap();
            bytes.extend_from_slice(&buf);
        }
        (used, bytes)
    }

    /// A frame longer than one buffer is spread over consecutive chains, and the count goes
    /// into `num_buffers` of the header the first chain carries.
    #[test]
    fn a_mergeable_frame_spans_chains_and_names_their_count() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        let mut queue = vq.create_queue();
        post_buffers(&vq, 4);

        // 212 bytes over 64-byte buffers: three full chains and a fourth holding 20.
        let mut frame = make_frame(212);
        write_frame_to_chains(
            &mut queue,
            mem,
            &mut frame,
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let (used, bytes) = received(&vq, mem);
        assert_eq!(used, vec![(0, 64), (1, 64), (2, 64), (3, 20)]);
        // The header the guest reads names all four, and the body arrives unbroken.
        assert_eq!(
            u16::from_le_bytes([bytes[NUM_BUFFERS_OFFSET], bytes[NUM_BUFFERS_OFFSET + 1]]),
            4
        );
        frame[NUM_BUFFERS_OFFSET..NUM_BUFFERS_OFFSET + 2].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(bytes, frame);
    }

    /// A frame that fills its chains exactly takes no more of them, and leaves the rest of
    /// the queue for the next frame.
    #[test]
    fn a_mergeable_frame_takes_only_the_chains_it_fills() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        let mut queue = vq.create_queue();
        post_buffers(&vq, 4);

        let mut frame = make_frame(3 * BUF_LEN as usize);
        write_frame_to_chains(
            &mut queue,
            mem,
            &mut frame,
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let (used, bytes) = received(&vq, mem);
        assert_eq!(used, vec![(0, 64), (1, 64), (2, 64)]);
        assert_eq!(
            u16::from_le_bytes([bytes[NUM_BUFFERS_OFFSET], bytes[NUM_BUFFERS_OFFSET + 1]]),
            3
        );
        // The fourth buffer was never taken.
        assert_eq!(queue.pop(mem).unwrap().index, 3);
    }

    /// Too few buffers for the frame is not a failure, only "not yet": the queue is left
    /// exactly as it was so the same frame can be written once the driver posts more.
    #[test]
    fn a_frame_the_driver_has_no_room_for_leaves_the_queue_untouched() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        let mut queue = vq.create_queue();
        post_buffers(&vq, 2);

        let mut frame = make_frame(212);
        let err = write_frame_to_chains(
            &mut queue,
            mem,
            &mut frame,
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(matches!(err, FrontendError::EmptyQueue));
        assert_eq!(vq.used.idx.get(), 0);
        assert_eq!(queue.pop(mem).unwrap().index, 0);
        assert_eq!(queue.pop(mem).unwrap().index, 1);
    }

    fn worker(
        mem: &GuestMemoryMmap,
        vq: &VirtQueue,
    ) -> (NetWorker, std::os::unix::net::UnixStream) {
        use crate::legacy::DummyIrqChip;
        use std::os::fd::IntoRawFd;
        use std::sync::Arc;
        use utils::eventfd::EventFd;

        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut queue = vq.create_queue();
        queue.set_event_idx(true);
        let interrupt = InterruptTransport::new(DummyIrqChip::new().into(), "test".into()).unwrap();
        let mut worker = NetWorker::new(
            DeviceQueue::new(queue, Arc::new(EventFd::new(0).unwrap())),
            DeviceQueue::new(Queue::new(QSIZE), Arc::new(EventFd::new(0).unwrap())),
            interrupt,
            mem.clone(),
            1 << VIRTIO_NET_F_MRG_RXBUF,
            VirtioNetBackend::UnixstreamFd(socket.into_raw_fd()),
        )
        .unwrap();
        let frame = make_frame(212);
        worker.rx_frame_buf[..frame.len()].copy_from_slice(&frame);
        worker.rx_frame_buf_len = frame.len();
        worker.rx_has_deferred_frame = true;
        (worker, peer)
    }

    #[test]
    fn blocked_transmit_yields_and_resumes_without_another_guest_kick() {
        let (done, completed) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use nix::sys::socket::{send, MsgFlags};
            use std::io::Read;

            let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
            let (mut worker, mut peer) = worker(mem, &vq);
            worker.tx_q.queue = vq.create_queue();
            worker.tx_q.queue.set_event_idx(true);
            peer.set_nonblocking(true).unwrap();

            // Fill the socket before staging a frame, so the flush makes no progress.
            let fd = worker.backend.raw_socket_fd();
            loop {
                match send(fd, &[0; 4096], MsgFlags::MSG_DONTWAIT) {
                    Ok(n) => assert!(n > 0),
                    Err(nix::Error::EAGAIN) => break,
                    Err(e) => panic!("fill failed: {e}"),
                }
            }
            let frame = make_frame(64);
            mem.write_slice(&frame, GuestAddress(BUF_BASE)).unwrap();
            vq.dtable[0].set(BUF_BASE, frame.len() as u32, 0, 0);
            vq.avail.ring[0].set(0);
            vq.avail.idx.set(1);

            // The final flush blocks after consuming the first descriptor.
            worker.process_tx_loop();
            assert!(worker.tx_has_deferred_frame);
            assert_eq!(vq.used.idx.get(), 1);
            assert!(worker.backend.has_unfinished_write());
            assert_ne!(worker.interrupt.status().load(Ordering::SeqCst), 0);

            // A new descriptor must not make the pending-flush path spin or consume it.
            vq.dtable[1].set(BUF_BASE, frame.len() as u32, 0, 0);
            vq.avail.ring[1].set(1);
            vq.avail.idx.set(2);
            worker.process_tx_loop();
            assert!(worker.tx_has_deferred_frame);
            assert_eq!(vq.used.idx.get(), 1);

            let mut filler = Vec::new();
            assert_eq!(
                peer.read_to_end(&mut filler).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            worker.process_backend_socket_writeable();
            assert!(!worker.tx_has_deferred_frame);
            assert!(!worker.backend.has_unfinished_write());
            assert_eq!(vq.used.idx.get(), 2);
            let mut wire = Vec::new();
            assert_eq!(
                peer.read_to_end(&mut wire).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let body = &frame[VNET_HDR_LEN..];
            let mut expected = Vec::new();
            for _ in 0..2 {
                expected.extend_from_slice(&(body.len() as u32).to_be_bytes());
                expected.extend_from_slice(body);
            }
            assert_eq!(wire, expected);
            done.send(()).unwrap();
        });
        completed
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    }

    #[test]
    fn a_refill_retries_the_whole_frame_and_interrupts_without_more_socket_data() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        post_buffers(&vq, 2);
        let (mut worker, _peer) = worker(mem, &vq);
        worker.process_backend_socket_readable();
        assert!(worker.rx_has_deferred_frame);
        assert_eq!(vq.used.idx.get(), 0);
        assert_eq!(vq.used.event.get(), 2);
        assert_eq!(worker.interrupt.status().load(Ordering::SeqCst), 0);

        post_buffers(&vq, 4);
        // virtio's event-index test: this refill must cross the requested event.
        let event = std::num::Wrapping(vq.used.event.get());
        assert!(std::num::Wrapping(4u16) - event - std::num::Wrapping(1) < std::num::Wrapping(2));
        worker.rx_q.event.write(1).unwrap();
        worker.process_rx_queue_event();
        assert!(!worker.rx_has_deferred_frame);
        let (used, bytes) = received(&vq, mem);
        assert_eq!(used, vec![(0, 64), (1, 64), (2, 64), (3, 20)]);
        assert_eq!(&bytes[VNET_HDR_LEN..], &make_frame(212)[VNET_HDR_LEN..]);
        assert_ne!(worker.interrupt.status().load(Ordering::SeqCst), 0);
    }

    #[test]
    fn returning_an_unwritable_chain_interrupts_even_without_a_delivered_frame() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        post_buffers(&vq, 1);
        vq.dtable[0].flags.set(0);
        let (mut worker, _peer) = worker(mem, &vq);
        worker.process_backend_socket_readable();
        assert!(worker.rx_has_deferred_frame);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().len, 0);
        assert_ne!(worker.interrupt.status().load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_full_table_of_short_multidescriptor_chains_is_returned_empty() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        let mut queue = vq.create_queue();
        for i in 0..QSIZE {
            let flags = VIRTQ_DESC_F_WRITE | if i % 2 == 0 { VIRTQ_DESC_F_NEXT } else { 0 };
            vq.dtable[i as usize].set(BUF_BASE + i as u64, 1, flags, i + 1);
        }
        for i in 0..QSIZE / 2 {
            vq.avail.ring[i as usize].set(i * 2);
        }
        vq.avail.idx.set(QSIZE / 2);
        let err = write_frame_to_chains(
            &mut queue,
            mem,
            &mut make_frame(212),
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FrontendError::DescriptorChainTooSmall));
        assert_eq!(vq.used.idx.get(), QSIZE / 2);
        assert!(received(&vq, mem).0.iter().all(|&(_, len)| len == 0));
    }

    #[test]
    fn a_later_copy_failure_returns_every_chain_empty() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        let mut queue = vq.create_queue();
        post_buffers(&vq, 4);
        vq.dtable[2].addr.set(0x30000);
        let err = write_frame_to_chains(
            &mut queue,
            mem,
            &mut make_frame(212),
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FrontendError::GuestMemory(_)));
        assert_eq!(received(&vq, mem).0, vec![(0, 0), (1, 0), (2, 0), (3, 0)]);
    }

    #[test]
    fn mergeable_delivery_wraps_both_ring_indices() {
        use std::num::Wrapping;
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        let mut queue = vq.create_queue();
        post_buffers(&vq, 3);
        queue.next_avail = Wrapping(u16::MAX - 1);
        queue.next_used = Wrapping(u16::MAX - 1);
        for (slot, head) in [(14, 0), (15, 1), (0, 2)] {
            vq.avail.ring[slot].set(head);
        }
        vq.avail.idx.set(1);
        write_frame_to_chains(
            &mut queue,
            mem,
            &mut make_frame(180),
            true,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(queue.next_avail, Wrapping(1));
        for (slot, head, len) in [(14, 0, 64), (15, 1, 64), (0, 2, 52)] {
            let elem = vq.used.ring[slot].get();
            assert_eq!((elem.id, elem.len), (head, len));
        }
    }

    /// Without the feature the driver reads no count and joins nothing, so the frame has to
    /// fit the first chain — across its descriptors, but no further.
    #[test]
    fn without_the_feature_a_frame_must_fit_one_chain() {
        let mem = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), mem, QSIZE);
        let mut queue = vq.create_queue();
        // One chain of four buffers, then a lone one.
        post_buffers(&vq, 5);
        for i in 0..3 {
            vq.dtable[i]
                .flags
                .set(VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT);
            vq.dtable[i].next.set(i as u16 + 1);
        }
        vq.avail.ring[1].set(4);
        vq.avail.idx.set(2);

        let mut frame = make_frame(212);
        write_frame_to_chains(
            &mut queue,
            mem,
            &mut frame,
            false,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();

        // One used entry for the whole frame, and num_buffers left alone.
        let (used, bytes) = received(&vq, mem);
        assert_eq!(used, vec![(0, 212)]);
        assert_eq!(&bytes[..VNET_HDR_LEN], &[0u8; VNET_HDR_LEN]);
        let mut scattered = Vec::new();
        for i in 0..4 {
            let mut part = vec![0; (frame.len() - scattered.len()).min(BUF_LEN as usize)];
            mem.read_slice(&mut part, GuestAddress(BUF_BASE * (i + 1)))
                .unwrap();
            scattered.extend_from_slice(&part);
        }
        assert_eq!(scattered, frame);

        // The lone 64-byte chain behind it cannot take the next frame, and is handed back
        // empty rather than half-filled.
        let mut next = make_frame(212);
        let err = write_frame_to_chains(
            &mut queue,
            mem,
            &mut next,
            false,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FrontendError::DescriptorChainTooSmall));
        assert_eq!(vq.used.ring[1].get().len, 0);
    }
}
