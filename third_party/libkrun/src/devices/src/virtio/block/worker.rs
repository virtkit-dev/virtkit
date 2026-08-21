use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::device::{CacheType, DiskProperties};

use crate::virtio::{DescriptorChain, InterruptTransport};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::result;
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestMemoryMmap};

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

/// Guest requests dispatched to concurrent threads per batch. Real disk-backed images (SSD/NVMe)
/// have per-request latency worth overlapping; a fixed small batch hides most of that latency
/// without oversubscribing a single virtqueue's worth of work onto too many OS threads. `readv`/
/// `writev`/`flush`/`sync`/`write_zeroes` take a shared `RwLock` read lock on the image (imago's
/// own internal locking, not this one, is what actually serializes conflicting accesses), so
/// batched requests genuinely run concurrently; `discard`/write-zeroes-with-unmap need a `&mut`
/// borrow of the image and take the write lock instead, briefly serializing against the rest of
/// the batch — correct, and rare enough not to matter.
///
/// Threads within one batch have no ordering between each other: a `FLUSH` and a write it is
/// meant to make durable must never land in the same batch. This relies on the guest never
/// submitting a `FLUSH` before observing completion of the writes it covers — true of compliant
/// block layers (Linux's included), which is why this isn't itself enforced here.
const IO_PARALLELISM: usize = 8;

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_ev_fd = self.device_queue.event.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                self.process_queue_event();
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn process_queue_event(&mut self) {
        if let Err(e) = self.device_queue.event.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process device virtio queue(s).
    fn process_virtio_queues(&mut self) {
        let mem = self.mem.clone();
        loop {
            self.device_queue.queue.disable_notification(&mem).unwrap();

            self.process_queue(&mem);

            if !self.device_queue.queue.enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    fn process_queue(&mut self, mem: &GuestMemoryMmap) {
        loop {
            let mut batch = Vec::with_capacity(IO_PARALLELISM);
            while batch.len() < IO_PARALLELISM {
                match self.device_queue.queue.pop(mem) {
                    Some(head) => batch.push(head),
                    None => break,
                }
            }
            if batch.is_empty() {
                break;
            }

            // Each request gets its own thread for the duration of the batch: the actual I/O
            // (and, for reads/writes, the guest memory copy) runs concurrently, hiding a
            // real disk's per-request latency. `disk` is only ever borrowed (`&DiskProperties`)
            // by these threads — see `process_one` / `process_request` for how conflicting
            // accesses are still synchronized (imago's own `RwLock`, not this scope).
            let disk = &self.disk;
            let completions: Vec<Option<(u16, usize)>> = thread::scope(|scope| {
                batch
                    .into_iter()
                    .map(|head| scope.spawn(move || Self::process_one(mem, disk, head)))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|handle| handle.join().unwrap())
                    .collect()
            });

            let mut completed_any = false;
            for (index, len) in completions.into_iter().flatten() {
                if let Err(e) = self.device_queue.queue.add_used(mem, index, len as u32) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
                completed_any = true;
            }

            if completed_any && self.device_queue.queue.needs_notification(mem).unwrap() {
                if let Err(e) = self.interrupt.try_signal_used_queue() {
                    error!("error signalling queue: {e:?}");
                }
            }
        }
    }

    /// Runs one guest request to completion: builds its `Reader`/`Writer`, dispatches it, and
    /// writes the status byte. Returns the descriptor's table index and used length for
    /// `add_used`, or `None` if the chain itself was unusable (nothing to report back for it).
    fn process_one(
        mem: &GuestMemoryMmap,
        disk: &DiskProperties,
        head: DescriptorChain,
    ) -> Option<(u16, usize)> {
        let mut reader = match Reader::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                return None;
            }
        };
        let mut writer = match Writer::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                return None;
            }
        };
        let request_header: RequestHeader = match reader.read_obj() {
            Ok(h) => h,
            Err(e) => {
                error!("invalid request header: {e:?}");
                return None;
            }
        };

        let (status, len): (u8, usize) =
            match Self::process_request(disk, request_header, &mut reader, &mut writer) {
                Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                Err(e) => {
                    error!("error processing request: {e:?}");
                    (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                }
            };

        if let Err(e) = writer.write_obj(status) {
            error!("Failed to write virtio block status: {e:?}")
        }

        Some((head.index, len))
    }

    fn process_request(
        disk: &DiskProperties,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes() - 1;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    let written = reader
                        .read_to_at(disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::ReadingFromDescriptor)?;
                    disk.record_write(request_header.sector * 512, data_len as u64);
                    Ok(written)
                }
            }
            VIRTIO_BLK_T_FLUSH => match disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = disk.file.read().unwrap();
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync().map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = disk.image_id();
                if data_len < disk_id.len() {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                // `&mut` op (allocation bookkeeping): takes the write lock, briefly excluding
                // the rest of the batch.
                let mut diskfile = disk.file.write().unwrap();
                diskfile
                    .discard_to_any(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::Discarding)?;
                drop(diskfile);
                disk.record_discard(
                    discard_write_data.sector * 512,
                    discard_write_data.num_sectors as u64 * 512,
                );
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                if unmap {
                    // `&mut` op, same as discard above: write lock.
                    disk.file
                        .write()
                        .unwrap()
                        .discard_to_zero(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    disk.file
                        .read()
                        .unwrap()
                        .write_zeroes(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::WritingZeroes)?;
                }
                // Freed or zeroed either way — record as a discard so the checkpoint holes it.
                disk.record_discard(
                    discard_write_data.sector * 512,
                    discard_write_data.num_sectors as u64 * 512,
                );
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }
}
