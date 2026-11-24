use crate::virtio::descriptor_utils::{Error as DescriptorUtilsError, Reader, Writer};

use super::super::DeviceQueue;
use super::SECTOR_SHIFT;
use super::device::{CacheType, DiskProperties, write_zeroes_exclusive};

use crate::virtio::{DescriptorChain, DetachedChain, InterruptTransport};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::panic::{self, AssertUnwindSafe};
use std::result;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
#[cfg(target_os = "windows")]
use utils::windows::AsRawFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap, VolatileSlice};

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    DiskFailed,
    FlushingToDisk(io::Error),
    InvalidChain(DescriptorUtilsError),
    InvalidDataLength,
    InvalidOffset,
    ReadingHeader(io::Error),
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnsupportedFlags(u32),
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

/// Guest requests run concurrently per batch: the worker thread and up to `IO_PARALLELISM - 1`
/// helper threads, started on the first batch that needs them and kept until the worker stops; a
/// batch of one runs on the worker thread alone. Real disk-backed images (SSD/NVMe) have
/// per-request latency worth overlapping; a fixed small batch hides most of that latency without
/// oversubscribing a single virtqueue's worth of work onto too many OS threads.
/// `readv`/`writev`/`flush`/`sync` take a shared `RwLock` read lock on the image (imago's own
/// internal locking, not this one, is what actually serializes conflicting accesses), so batched
/// requests genuinely run concurrently; `discard` and both forms of write-zeroes take the write
/// lock instead, briefly serializing against the rest of the batch — correct, and rare enough not
/// to matter. (Discard and write-zeroes-with-unmap need a `&mut` borrow of the image anyway; plain
/// write-zeroes does not, but must not run beside a write into the same cluster — see
/// `device::write_zeroes_exclusive`.)
///
/// Requests within one batch have no ordering between each other: a `FLUSH` and a write it is
/// meant to make durable must never land in the same batch. This relies on the guest never
/// submitting a `FLUSH` before observing completion of the writes it covers — true of compliant
/// block layers (Linux's included), which is why this isn't itself enforced here.
const IO_PARALLELISM: usize = 8;

/// What the worker thread shares with its helpers. Every thread reaches guest memory and the
/// disk through it, so a request is handed over as plain data and nothing a helper holds
/// borrows from the worker thread.
struct Shared {
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    batch: Mutex<Batch>,
    /// Helpers wait here for requests to claim, or for `stop`.
    posted: Condvar,
    /// The worker thread waits here for the batch's last running request.
    finished: Condvar,
}

/// The batch being run: requests `next..len` are unclaimed, `unfinished` have not completed.
/// Requests run unlocked and catch their own panics (`BlockWorker::process_one`).
struct Batch {
    requests: [Option<DetachedChain>; IO_PARALLELISM],
    results: [Option<(u16, usize)>; IO_PARALLELISM],
    len: usize,
    next: usize,
    unfinished: usize,
    /// Helpers blocked on `posted`.
    idle: usize,
    /// The worker thread is blocked on `finished`.
    waiting: bool,
    stop: bool,
}

fn lock(batch: &Mutex<Batch>) -> MutexGuard<'_, Batch> {
    // Poison carries no meaning: requests, the only code expected to panic, run unlocked.
    batch.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wait<'a>(cond: &Condvar, guard: MutexGuard<'a, Batch>) -> MutexGuard<'a, Batch> {
    cond.wait(guard).unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    /// Claims and runs the batch's unclaimed requests on this thread until none is left.
    /// `wake` idle helpers are woken once the first request is claimed and the lock released,
    /// so they do not wake into a held lock.
    fn serve<'a>(
        &'a self,
        mut batch: MutexGuard<'a, Batch>,
        mut wake: usize,
    ) -> MutexGuard<'a, Batch> {
        while batch.next < batch.len {
            let slot = batch.next;
            batch.next += 1;
            let head = batch.requests[slot].take();
            drop(batch);
            for _ in 0..std::mem::take(&mut wake) {
                self.posted.notify_one();
            }
            let completion = head.map(|head| {
                BlockWorker::process_one(&self.mem, &self.disk, head.attach(&self.mem))
            });
            batch = lock(&self.batch);
            batch.results[slot] = completion;
            batch.unfinished -= 1;
        }
        batch
    }

    /// A helper thread's loop: serve every batch it is woken for, until `stop`.
    fn help(&self) {
        let mut batch = lock(&self.batch);
        while !batch.stop {
            if batch.next < batch.len {
                batch = self.serve(batch, 0);
                if batch.unfinished == 0 && batch.waiting {
                    self.finished.notify_one();
                }
            } else {
                batch.idle += 1;
                batch = wait(&self.posted, batch);
                batch.idle -= 1;
            }
        }
    }
}

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    shared: Arc<Shared>,
    /// Up to `IO_PARALLELISM - 1`, joined when the worker is dropped.
    helpers: Vec<thread::JoinHandle<()>>,
    /// A helper failed to start: retried on later batches, reported once.
    spawn_failed: bool,
    stop_fd: EventFd,
}

impl Drop for BlockWorker {
    /// Stops and joins the helpers. No batch is running here: `run_batch` returns only once
    /// its batch has finished.
    fn drop(&mut self) {
        lock(&self.shared.batch).stop = true;
        self.shared.posted.notify_all();
        for helper in self.helpers.drain(..) {
            // Requests catch their own panics, so a helper returns unless the code around
            // them panics.
            let _ = helper.join();
        }
    }
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
    ) -> Self {
        let shared = Arc::new(Shared {
            mem: mem.clone(),
            disk,
            batch: Mutex::new(Batch {
                requests: [None; IO_PARALLELISM],
                results: [None; IO_PARALLELISM],
                len: 0,
                next: 0,
                unfinished: 0,
                idle: 0,
                waiting: false,
                stop: false,
            }),
            posted: Condvar::new(),
            finished: Condvar::new(),
        });
        Self {
            device_queue,
            interrupt,
            mem,
            shared,
            helpers: Vec::new(),
            spawn_failed: false,
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

        let mut epoll = Epoll::new().unwrap();

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

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
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
            let _writing = crate::virtio::device_writes();
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
        // Reused across batches; only a batch of two or more requests fills them.
        let mut batch = Vec::new();
        let mut completions = Vec::new();
        while let Some(head) = self.device_queue.queue.pop(mem) {
            let Some(second) = self.device_queue.queue.pop(mem) else {
                // A lone request runs on this thread: it would only wait here for a helper
                // to finish it.
                let completion = Self::process_one(mem, &self.shared.disk, head);
                self.complete(mem, [completion]);
                continue;
            };
            batch.reserve(IO_PARALLELISM);
            batch.push(head);
            batch.push(second);
            while batch.len() < IO_PARALLELISM {
                match self.device_queue.queue.pop(mem) {
                    Some(head) => batch.push(head),
                    None => break,
                }
            }

            self.run_batch(&mut batch, &mut completions);
            self.complete(mem, completions.drain(..).flatten());
        }
    }

    /// Runs a batch of two or more requests concurrently, hiding a real disk's per-request
    /// latency: idle helpers are woken for all but one request, and this thread runs whatever
    /// they have not claimed yet, then waits for the rest. Results land in `completions` in batch
    /// order, and no helper touches guest memory after this returns. How conflicting accesses
    /// are synchronized: see `IO_PARALLELISM` (imago's own `RwLock`).
    fn run_batch(
        &mut self,
        batch: &mut Vec<DescriptorChain>,
        completions: &mut Vec<Option<(u16, usize)>>,
    ) {
        self.start_helpers(batch.len() - 1);
        let shared = &*self.shared;
        let mut state = lock(&shared.batch);
        let len = batch.len();
        for (slot, head) in state.requests.iter_mut().zip(batch.drain(..)) {
            *slot = Some(head.detach());
        }
        state.len = len;
        state.next = 0;
        state.unfinished = len;
        let wake = state.idle.min(len - 1);
        state = shared.serve(state, wake);
        state.waiting = true;
        while state.unfinished > 0 {
            state = wait(&shared.finished, state);
        }
        state.waiting = false;
        completions.extend_from_slice(&state.results[..len]);
        state.len = 0;
        state.next = 0;
    }

    /// Grows the helpers to `want` (at most `IO_PARALLELISM - 1`). They are spawned from this
    /// thread, so they inherit its scheduling and I/O priority and its OS thread name. If one
    /// cannot be spawned, the worker thread runs the requests left over.
    fn start_helpers(&mut self, want: usize) {
        while self.helpers.len() < want.min(IO_PARALLELISM - 1) {
            let shared = Arc::clone(&self.shared);
            match thread::Builder::new().spawn(move || shared.help()) {
                Ok(helper) => self.helpers.push(helper),
                Err(e) => {
                    if !std::mem::replace(&mut self.spawn_failed, true) {
                        warn!("cannot start a block request thread: {e}");
                    }
                    break;
                }
            }
        }
    }

    /// Returns a batch's finished requests to the guest, in order, and raises the interrupt
    /// once if any finished and the guest wants it.
    fn complete(
        &mut self,
        mem: &GuestMemoryMmap,
        completions: impl IntoIterator<Item = (u16, usize)>,
    ) {
        let mut completed_any = false;
        for (index, len) in completions {
            if let Err(e) = self.device_queue.queue.add_used(mem, index, len as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
            completed_any = true;
        }

        if completed_any
            && self.device_queue.queue.needs_notification(mem).unwrap()
            && let Err(e) = self.interrupt.try_signal_used_queue()
        {
            error!("error signalling queue: {e:?}");
        }
    }

    /// Runs one guest request to completion and returns the descriptor's table index and used
    /// length for `add_used`: every chain is returned to the guest, once. A request that panics
    /// fails the disk (see `DiskProperties::fail`) and gets an I/O error status, if its chain
    /// has one; its data buffers are left as they are.
    fn process_one(
        mem: &GuestMemoryMmap,
        disk: &DiskProperties,
        head: DescriptorChain,
    ) -> (u16, usize) {
        let index = head.index;
        let mut status_byte = None;
        panic::catch_unwind(AssertUnwindSafe(|| {
            Self::run_request(mem, disk, head, &mut status_byte)
        }))
        .unwrap_or_else(|payload| {
            disk.fail(&*payload);
            let Some(status_byte) = status_byte else {
                return (index, 0);
            };
            if let Err(e) = status_byte.write_obj(VIRTIO_BLK_S_IOERR as u8, 0) {
                error!("Failed to write virtio block status: {e:?}")
            }
            // What the request wrote before it panicked is undefined: only the status counts.
            (index, 1)
        })
    }

    /// `process_one`'s request: builds its `Reader`/`Writer`, records where the status byte is
    /// in `status_byte` before running anything, dispatches the request unless the disk has
    /// failed, and writes the status. A
    /// malformed chain gets an I/O error status if its writable buffers are in guest memory and
    /// hold at least one byte, and otherwise used length 0 with nothing run.
    fn run_request<'a>(
        mem: &'a GuestMemoryMmap,
        disk: &DiskProperties,
        head: DescriptorChain<'a>,
        status_byte: &mut Option<VolatileSlice<'a>>,
    ) -> (u16, usize) {
        let mut writer = match Writer::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                return (head.index, 0);
            }
        };
        // virtio-blk fixes the status position even when the data buffer is only partly filled.
        *status_byte = writer.split_last_byte();
        let Some(status_slot) = *status_byte else {
            // The guest needs a status byte to learn the outcome.
            error!("virtio-blk request without a status byte");
            return (head.index, 0);
        };

        let outcome = if disk.has_failed() {
            Err(RequestError::DiskFailed)
        } else {
            Reader::new(mem, head.clone())
                .map_err(RequestError::InvalidChain)
                .and_then(|mut reader| {
                    let request_header: RequestHeader =
                        reader.read_obj().map_err(RequestError::ReadingHeader)?;
                    Self::process_request(disk, request_header, &mut reader, &mut writer)
                })
        };
        let status: u8 = match outcome {
            Ok(()) => VIRTIO_BLK_S_OK.try_into().unwrap(),
            // Why it failed was logged when it did.
            Err(RequestError::DiskFailed) => VIRTIO_BLK_S_IOERR.try_into().unwrap(),
            Err(e @ (RequestError::UnknownRequest | RequestError::UnsupportedFlags(_))) => {
                error!("unsupported request: {e:?}");
                VIRTIO_BLK_S_UNSUPP.try_into().unwrap()
            }
            Err(e) => {
                error!("error processing request: {e:?}");
                VIRTIO_BLK_S_IOERR.try_into().unwrap()
            }
        };

        if let Err(e) = status_slot.write_obj(status, 0) {
            error!("Failed to write virtio block status: {e:?}")
        }

        // The used length counts the bytes written into the chain: the request's, then the
        // status.
        (head.index, writer.bytes_written() + 1)
    }

    /// The byte offset of a `len`-byte request at guest `sector`, refused (IOERR) unless the
    /// whole range fits the disk's `capacity` bytes: a guest-chosen sector must neither wrap
    /// (release) nor panic the worker (debug), and a write past the end must not reach the
    /// dirty tracker.
    fn request_offset(capacity: u64, sector: u64, len: u64) -> result::Result<u64, RequestError> {
        sector
            .checked_mul(512)
            .filter(|off| off.checked_add(len).is_some_and(|end| end <= capacity))
            .ok_or(RequestError::InvalidOffset)
    }

    fn process_request(
        disk: &DiskProperties,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<(), RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    let offset = Self::request_offset(
                        disk.nsectors() << SECTOR_SHIFT,
                        request_header.sector,
                        data_len as u64,
                    )?;
                    writer
                        .write_from_at(disk, data_len, offset)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(())
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    let offset = Self::request_offset(
                        disk.nsectors() << SECTOR_SHIFT,
                        request_header.sector,
                        data_len as u64,
                    )?;
                    reader
                        .read_to_at(disk, data_len, offset)
                        .map_err(RequestError::ReadingFromDescriptor)?;
                    disk.record_write(offset, data_len as u64);
                    Ok(())
                }
            }
            VIRTIO_BLK_T_FLUSH => match disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = disk.image().map_err(RequestError::FlushingToDisk)?;
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync().map_err(RequestError::FlushingToDisk)?;
                    Ok(())
                }
                CacheType::Unsafe => Ok(()),
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
                    Ok(())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                // Virtio reserves `UNMAP` for write-zeroes.
                if discard_write_data.flags != 0 {
                    return Err(RequestError::UnsupportedFlags(discard_write_data.flags));
                }
                let offset = Self::request_offset(
                    disk.nsectors() << SECTOR_SHIFT,
                    discard_write_data.sector,
                    discard_write_data.num_sectors as u64 * 512,
                )?;
                // `&mut` op (allocation bookkeeping): takes the write lock, briefly excluding
                // the rest of the batch.
                let mut diskfile = disk.image_mut().map_err(RequestError::Discarding)?;
                diskfile
                    .discard_to_any(offset, discard_write_data.num_sectors as u64 * 512)
                    .map_err(RequestError::Discarding)?;
                drop(diskfile);
                // A discard's partial edge clusters stay out of the written set: what the format
                // layer zeroes inside them is content DISCARD leaves undefined anyway.
                disk.record_discard(offset, discard_write_data.num_sectors as u64 * 512);
                Ok(())
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                if discard_write_data.flags & !VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP != 0 {
                    return Err(RequestError::UnsupportedFlags(discard_write_data.flags));
                }
                let offset = Self::request_offset(
                    disk.nsectors() << SECTOR_SHIFT,
                    discard_write_data.sector,
                    discard_write_data.num_sectors as u64 * 512,
                )?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                if unmap {
                    // `&mut` op, same as discard above: write lock.
                    disk.image_mut()
                        .map_err(RequestError::DiscardingToZero)?
                        .discard_to_zero(offset, discard_write_data.num_sectors as u64 * 512)
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    // Write lock like the unmap case above, for a different reason — see
                    // `write_zeroes_exclusive`.
                    write_zeroes_exclusive(
                        &mut *disk.image_mut().map_err(RequestError::WritingZeroes)?,
                        offset,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::WritingZeroes)?;
                }
                // Zeroed either way: whole clusters are holed, a partial one at an end is read
                // whole.
                disk.record_zeroes(offset, discard_write_data.num_sectors as u64 * 512);
                Ok(())
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, RwLock, mpsc};
    use std::time::{Duration, Instant};

    use imago::io_buffers::{IoVector, IoVectorMut};
    use imago::storage::drivers::CommonStorageHelper;
    use imago::{
        DynStorage, FormatAccess, Storage, StorageOpenOptions, file::File as ImagoFile, raw::Raw,
    };
    use utils::eventfd::EventFd;
    use utils::tempfile::TempFile;
    use virtio_bindings::virtio_blk::*;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::super::device::{CacheType, DiskProperties};
    use super::{BlockWorker, DiscardWriteData, RequestError, RequestHeader};
    use crate::virtio::device::{InterruptHandler, InterruptType};
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::{DeviceQueue, InterruptTransport};

    pub(crate) const DISK_LEN: usize = 64 * 1024;
    pub(crate) const QUEUE_SIZE: u16 = 64;
    /// Request `i` keeps its header at `REQ_BASE + i * REQ_STRIDE`, its status byte 16 bytes
    /// after it and its data 4 KiB after it.
    const REQ_BASE: u64 = 0x4000;
    const REQ_STRIDE: u64 = 0x2000;

    pub(crate) struct CountIrqs(pub(crate) AtomicUsize);

    impl InterruptHandler for CountIrqs {
        fn try_signal(&self, _interrupt: InterruptType) -> Result<(), crate::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Sector `s` of the test disk holds the byte `s`.
    fn disk_bytes() -> Vec<u8> {
        (0..DISK_LEN).map(|i| (i / 512) as u8).collect()
    }

    pub(crate) struct Setup {
        _file: TempFile,
        pub(crate) path: std::path::PathBuf,
        pub(crate) mem: GuestMemoryMmap,
        pub(crate) irqs: Arc<CountIrqs>,
    }

    pub(crate) fn setup() -> Setup {
        let file = TempFile::new().unwrap();
        std::fs::write(file.as_path(), disk_bytes()).unwrap();
        Setup {
            path: file.as_path().to_path_buf(),
            _file: file,
            mem: GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap(),
            irqs: Arc::new(CountIrqs(AtomicUsize::new(0))),
        }
    }

    /// A worker over a writable raw disk with a write-back cache, serving `vq`.
    fn worker(s: &Setup, vq: &VirtQueue) -> BlockWorker {
        worker_with(s, vq, CacheType::Writeback).0
    }

    type Image = Arc<RwLock<FormatAccess<Box<dyn DynStorage>>>>;

    /// A worker over a writable raw disk with cache `cache`, serving `vq`, and its image.
    fn worker_with(s: &Setup, vq: &VirtQueue, cache: CacheType) -> (BlockWorker, Image) {
        let file =
            ImagoFile::open(StorageOpenOptions::new().write(true).filename(&s.path)).unwrap();
        let raw = Raw::<Box<dyn DynStorage>>::open_image(Box::new(file), true).unwrap();
        let image = Arc::new(RwLock::new(FormatAccess::new(raw)));
        (worker_on(s, vq, image.clone(), cache), image)
    }

    /// A worker over `image` with cache `cache`, serving `vq`.
    fn worker_on(s: &Setup, vq: &VirtQueue, image: Image, cache: CacheType) -> BlockWorker {
        let disk = DiskProperties::new(
            image,
            vec![0; VIRTIO_BLK_ID_BYTES as usize],
            cache,
            None,
            None,
            Default::default(),
        )
        .unwrap();
        BlockWorker::new(
            DeviceQueue::new(vq.create_queue(), Arc::new(EventFd::new(0).unwrap())),
            InterruptTransport::from_handler(s.irqs.clone()),
            s.mem.clone(),
            disk,
            EventFd::new(0).unwrap(),
        )
    }

    /// A sector whose read panics in the storage (see [`Probe`]).
    pub(crate) const PANIC_SECTOR: u64 = 120;
    /// A sector whose read waits in the storage until a read of `PANIC_SECTOR` has panicked.
    pub(crate) const GATE_SECTOR: u64 = 121;

    /// What a [`ProbeStorage`] saw, and when it panics.
    #[derive(Debug, Default)]
    pub(crate) struct Probe {
        /// Reads, writes, flushes and syncs that reached the storage.
        pub(crate) calls: AtomicUsize,
        /// Flushes and syncs.
        pub(crate) flushes: AtomicUsize,
        /// Reads of other sectors finished.
        reads: AtomicUsize,
        /// A read of `PANIC_SECTOR` first waits for this many other reads.
        pub(crate) reads_before_panic: AtomicUsize,
        /// The thread a read of `PANIC_SECTOR` panicked on.
        pub(crate) panicked_on: Mutex<Option<std::thread::ThreadId>>,
    }

    impl Probe {
        fn wait_for(&self, what: &str, done: impl Fn() -> bool) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !done() {
                assert!(
                    Instant::now() < deadline,
                    "probe: timed out waiting for {what}"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// A file that reports to its [`Probe`]: a read of `PANIC_SECTOR` panics, as a bug in the
    /// storage would.
    #[derive(Debug)]
    pub(crate) struct ProbeStorage {
        inner: ImagoFile,
        probe: Arc<Probe>,
    }

    impl std::fmt::Display for ProbeStorage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "probe:{}", self.inner)
        }
    }

    #[maybe_async::maybe_async(AFIT)]
    impl Storage for ProbeStorage {
        fn size(&self) -> std::io::Result<u64> {
            self.inner.size()
        }

        async unsafe fn pure_readv(
            &self,
            bufv: IoVectorMut<'_>,
            offset: u64,
        ) -> std::io::Result<()> {
            let probe = &self.probe;
            probe.calls.fetch_add(1, Ordering::SeqCst);
            if offset == PANIC_SECTOR * 512 {
                let want = probe.reads_before_panic.load(Ordering::SeqCst);
                probe.wait_for("reads", || probe.reads.load(Ordering::SeqCst) >= want);
                *probe.panicked_on.lock().unwrap() = Some(std::thread::current().id());
                panic!("probe: injected panic");
            }
            if offset == GATE_SECTOR * 512 {
                probe.wait_for("the panic", || probe.panicked_on.lock().unwrap().is_some());
            }
            // SAFETY: forwarded as received.
            let result = unsafe { self.inner.pure_readv(bufv, offset) };
            probe.reads.fetch_add(1, Ordering::SeqCst);
            result
        }

        async unsafe fn pure_writev(&self, bufv: IoVector<'_>, offset: u64) -> std::io::Result<()> {
            self.probe.calls.fetch_add(1, Ordering::SeqCst);
            // SAFETY: forwarded as received.
            unsafe { self.inner.pure_writev(bufv, offset) }
        }

        async fn flush(&self) -> std::io::Result<()> {
            self.probe.calls.fetch_add(1, Ordering::SeqCst);
            self.probe.flushes.fetch_add(1, Ordering::SeqCst);
            self.inner.flush()
        }

        async fn sync(&self) -> std::io::Result<()> {
            self.probe.calls.fetch_add(1, Ordering::SeqCst);
            self.probe.flushes.fetch_add(1, Ordering::SeqCst);
            self.inner.sync()
        }

        async unsafe fn invalidate_cache(&self) -> std::io::Result<()> {
            // SAFETY: forwarded as received.
            unsafe { self.inner.invalidate_cache() }
        }

        fn get_storage_helper(&self) -> &CommonStorageHelper {
            self.inner.get_storage_helper()
        }
    }

    /// A writable raw image over `path` whose storage reports to the returned [`Probe`].
    pub(crate) fn probe_image(path: &std::path::Path) -> (Image, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        let storage = ProbeStorage {
            inner: ImagoFile::open(StorageOpenOptions::new().write(true).filename(path)).unwrap(),
            probe: probe.clone(),
        };
        let raw = Raw::<Box<dyn DynStorage>>::open_image(Box::new(storage), true).unwrap();
        (Arc::new(RwLock::new(FormatAccess::new(raw))), probe)
    }

    /// A worker like [`worker_with`]'s whose image is a [`probe_image`].
    fn probe_worker(s: &Setup, vq: &VirtQueue, cache: CacheType) -> (BlockWorker, Arc<Probe>) {
        let (image, probe) = probe_image(&s.path);
        (worker_on(s, vq, image, cache), probe)
    }

    fn helper_ids(w: &BlockWorker) -> Vec<std::thread::ThreadId> {
        w.helpers.iter().map(|h| h.thread().id()).collect()
    }

    /// Makes request `i` available to the device: descriptors `3i..3i + 3` (header, `len` data
    /// bytes unless `len` is 0, status). `header_len` short of 16 makes the header unreadable.
    pub(crate) fn queue_request(
        mem: &GuestMemoryMmap,
        vq: &VirtQueue,
        i: u16,
        request_type: u32,
        sector: u64,
        len: u32,
        header_len: u32,
    ) {
        let base = REQ_BASE + u64::from(i) * REQ_STRIDE;
        let header = RequestHeader {
            request_type,
            _reserved: 0,
            sector,
        };
        mem.write_obj(header, GuestAddress(base)).unwrap();
        mem.write_obj(0xffu8, GuestAddress(base + 16)).unwrap();
        let head = 3 * i;
        let mut next = head + 1;
        vq.dtable[head as usize].set(base, header_len, VIRTQ_DESC_F_NEXT, next);
        if len > 0 {
            let flags = if request_type == VIRTIO_BLK_T_IN {
                VIRTQ_DESC_F_WRITE
            } else {
                0
            };
            vq.dtable[next as usize].set(base + 0x1000, len, flags | VIRTQ_DESC_F_NEXT, next + 1);
            next += 1;
        }
        vq.dtable[next as usize].set(base + 16, 1, VIRTQ_DESC_F_WRITE, 0);
        let slot = vq.avail.idx.get();
        vq.avail.ring[(slot % QUEUE_SIZE) as usize].set(head);
        vq.avail.idx.set(slot.wrapping_add(1));
    }

    pub(crate) fn status(mem: &GuestMemoryMmap, i: u16) -> u8 {
        mem.read_obj(GuestAddress(REQ_BASE + u64::from(i) * REQ_STRIDE + 16))
            .unwrap()
    }

    fn data(mem: &GuestMemoryMmap, i: u16, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        mem.read_slice(
            &mut out,
            GuestAddress(REQ_BASE + u64::from(i) * REQ_STRIDE + 0x1000),
        )
        .unwrap();
        out
    }

    /// The used ring's `(head index, len)` entries so far.
    pub(crate) fn used(vq: &VirtQueue) -> Vec<(u32, u32)> {
        (0..vq.used.idx.get())
            .map(|k| {
                let e = vq.used.ring[(k % QUEUE_SIZE) as usize].get();
                (e.id, e.len)
            })
            .collect()
    }

    const OK: u8 = VIRTIO_BLK_S_OK as u8;
    pub(crate) const IOERR: u8 = VIRTIO_BLK_S_IOERR as u8;
    const UNSUPP: u8 = VIRTIO_BLK_S_UNSUPP as u8;

    /// Lone reads, writes, flushes and failing requests are answered as a batch's would be: the
    /// same status, used entry and data, and one interrupt per completed request, a chain
    /// without a readable header included.
    #[test]
    fn lone_requests_complete_and_signal_one_at_a_time() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let mut w = worker(&s, &vq);
        let irqs = || s.irqs.0.load(Ordering::SeqCst);

        // Read sectors 2..4.
        queue_request(&s.mem, &vq, 0, VIRTIO_BLK_T_IN, 2, 1024, 16);
        w.process_queue(&s.mem);
        assert_eq!(used(&vq), [(0, 1025)]);
        assert_eq!((status(&s.mem, 0), irqs()), (OK, 1));
        assert_eq!(data(&s.mem, 0, 1024), disk_bytes()[1024..2048]);

        // Write sector 4, then flush.
        let base = REQ_BASE + REQ_STRIDE;
        s.mem
            .write_slice(&[0x5a; 512], GuestAddress(base + 0x1000))
            .unwrap();
        queue_request(&s.mem, &vq, 1, VIRTIO_BLK_T_OUT, 4, 512, 16);
        w.process_queue(&s.mem);
        assert_eq!((status(&s.mem, 1), irqs()), (OK, 2));
        queue_request(&s.mem, &vq, 2, VIRTIO_BLK_T_FLUSH, 0, 0, 16);
        w.process_queue(&s.mem);
        assert_eq!((status(&s.mem, 2), irqs()), (OK, 3));
        let on_disk = std::fs::read(&s.path).unwrap();
        assert!(on_disk[2048..2560].iter().all(|&b| b == 0x5a));
        assert_eq!(on_disk[..2048], disk_bytes()[..2048]);

        // A write past the end of the disk: an I/O error, still completed and signalled.
        queue_request(
            &s.mem,
            &vq,
            3,
            VIRTIO_BLK_T_OUT,
            (DISK_LEN / 512) as u64,
            512,
            16,
        );
        w.process_queue(&s.mem);
        assert_eq!((status(&s.mem, 3), irqs()), (IOERR, 4));

        // No readable header: an I/O error too.
        queue_request(&s.mem, &vq, 4, VIRTIO_BLK_T_IN, 0, 512, 8);
        w.process_queue(&s.mem);
        assert_eq!((status(&s.mem, 4), irqs()), (IOERR, 5));
        assert_eq!(used(&vq), [(0, 1025), (3, 1), (6, 1), (9, 1), (12, 1)]);

        // Nothing left: no completion, no interrupt.
        w.process_queue(&s.mem);
        assert_eq!((used(&vq).len(), irqs()), (5, 5));
    }

    /// Nine requests queued at once run as a batch of eight, then one alone; each batch is
    /// completed in queue order with one interrupt, a broken chain inside a batch included.
    #[test]
    fn a_batch_then_a_lone_request_complete_in_queue_order() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let mut w = worker(&s, &vq);

        for i in 0..9u16 {
            let header_len = if i == 3 { 8 } else { 16 };
            queue_request(
                &s.mem,
                &vq,
                i,
                VIRTIO_BLK_T_IN,
                u64::from(i),
                512,
                header_len,
            );
        }
        w.process_queue(&s.mem);

        let expected: Vec<(u32, u32)> = (0..9u32)
            .map(|i| (3 * i, if i == 3 { 1 } else { 513 }))
            .collect();
        assert_eq!(used(&vq), expected);
        assert_eq!(s.irqs.0.load(Ordering::SeqCst), 2);
        for i in (0..9u16).filter(|&i| i != 3) {
            assert_eq!(status(&s.mem, i), OK);
            let sector = usize::from(i) * 512;
            assert_eq!(data(&s.mem, i, 512), disk_bytes()[sector..sector + 512]);
        }
        assert_eq!(status(&s.mem, 3), IOERR);
        assert_eq!(data(&s.mem, 3, 512), [0; 512]);
    }

    /// Helpers start with the first batch that needs them, at most seven, and are kept across
    /// batches; each batch still completes in queue order with one interrupt.
    #[test]
    fn helpers_start_on_demand_and_are_reused() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let mut w = worker(&s, &vq);
        let irqs = || s.irqs.0.load(Ordering::SeqCst);
        let read_back = |i: u16, sector: u64| {
            assert_eq!(status(&s.mem, i), OK);
            let at = sector as usize * 512;
            assert_eq!(data(&s.mem, i, 512), disk_bytes()[at..at + 512]);
        };

        queue_request(&s.mem, &vq, 0, VIRTIO_BLK_T_IN, 0, 512, 16);
        w.process_queue(&s.mem);
        assert!(w.helpers.is_empty());

        for i in 1..3u16 {
            queue_request(&s.mem, &vq, i, VIRTIO_BLK_T_IN, u64::from(i), 512, 16);
        }
        w.process_queue(&s.mem);
        let first = helper_ids(&w);
        assert_eq!(first.len(), 1);
        assert_eq!((used(&vq).len(), irqs()), (3, 2));

        let mut seven = None;
        for round in 0..4u64 {
            for i in 0..8u16 {
                let sector = round * 8 + u64::from(i);
                queue_request(&s.mem, &vq, i, VIRTIO_BLK_T_IN, sector, 512, 16);
            }
            w.process_queue(&s.mem);
            let ids = helper_ids(&w);
            assert_eq!((ids.len(), ids[0]), (7, first[0]));
            assert_eq!(*seven.get_or_insert_with(|| ids.clone()), ids);
            let used = used(&vq);
            let batch: Vec<_> = (0..8u32).map(|i| (3 * i, 513)).collect();
            assert_eq!(used[used.len() - 8..], batch);
            assert_eq!(irqs(), 3 + round as usize);
            for i in 0..8u16 {
                read_back(i, round * 8 + u64::from(i));
            }
        }
    }

    /// Stopping a running worker joins its helpers: once its thread has ended, nothing
    /// holds what they shared with it.
    #[test]
    fn stopping_the_worker_joins_its_helpers() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let w = worker(&s, &vq);
        let shared = Arc::downgrade(&w.shared);
        let kick = w.device_queue.event.clone();
        let stop = w.stop_fd.try_clone().unwrap();
        for i in 0..8u16 {
            queue_request(&s.mem, &vq, i, VIRTIO_BLK_T_IN, u64::from(i), 512, 16);
        }

        let thread = w.run();
        kick.write(1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while vq.used.idx.get() < 8 {
            assert!(Instant::now() < deadline, "the batch never completed");
            std::thread::sleep(Duration::from_millis(1));
        }
        // The worker and its seven helpers.
        assert_eq!(shared.strong_count(), 8);

        stop.write(1).unwrap();
        thread.join().unwrap();
        assert_eq!(shared.strong_count(), 0);
    }

    /// Waits up to 30 s for `vq` to have `n` used entries.
    pub(crate) fn wait_used(vq: &VirtQueue, n: u16) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while vq.used.idx.get() < n {
            assert!(Instant::now() < deadline, "the request never completed");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Requests on a failed disk complete with an I/O error and never reach its image: a
    /// read, a write, a flush and a disk ID request, each alone.
    fn later_requests_fail(s: &Setup, vq: &VirtQueue, probe: &Probe, mut run: impl FnMut()) {
        let calls = probe.calls.load(Ordering::SeqCst);
        let first = vq.used.idx.get();
        let base = |i: u16| GuestAddress(REQ_BASE + u64::from(i) * REQ_STRIDE + 0x1000);
        for (i, request_type) in [
            (4, VIRTIO_BLK_T_IN),
            (5, VIRTIO_BLK_T_OUT),
            (6, VIRTIO_BLK_T_FLUSH),
            (7, VIRTIO_BLK_T_GET_ID),
        ] {
            s.mem.write_slice(&[0xa5; 512], base(i)).unwrap();
            let len = if request_type == VIRTIO_BLK_T_FLUSH {
                0
            } else {
                512
            };
            queue_request(&s.mem, vq, i, request_type, 1, len, 16);
            if request_type == VIRTIO_BLK_T_GET_ID {
                let flags = VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT;
                vq.dtable[3 * usize::from(i) + 1].set(base(i).0, 512, flags, 3 * i + 2);
            }
            run();
            assert_eq!(status(&s.mem, i), IOERR);
            assert_eq!(data(&s.mem, i, 512), [0xa5; 512]);
        }
        let used = used(vq);
        assert_eq!(
            used[usize::from(first)..],
            [(12, 1), (15, 1), (18, 1), (21, 1)]
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), calls);
        assert_eq!(std::fs::read(&s.path).unwrap(), disk_bytes());
    }

    /// A lone request that panics completes with an I/O error and fails the disk: the worker
    /// thread keeps serving, every later request fails without reaching the image, and stopping
    /// the worker drops the write-back disk without flushing it.
    #[test]
    fn a_panicking_lone_request_fails_the_disk() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let (w, probe) = probe_worker(&s, &vq, CacheType::Writeback);
        let kick = w.device_queue.event.clone();
        let stop = w.stop_fd.try_clone().unwrap();
        let thread = w.run();

        queue_request(&s.mem, &vq, 0, VIRTIO_BLK_T_IN, PANIC_SECTOR, 512, 16);
        kick.write(1).unwrap();
        wait_used(&vq, 1);
        assert_eq!(used(&vq), [(0, 1)]);
        assert_eq!(
            (status(&s.mem, 0), s.irqs.0.load(Ordering::SeqCst)),
            (IOERR, 1)
        );
        assert!(probe.panicked_on.lock().unwrap().is_some());

        later_requests_fail(&s, &vq, &probe, || {
            let n = vq.used.idx.get();
            kick.write(1).unwrap();
            wait_used(&vq, n + 1);
        });
        assert!(!thread.is_finished());
        assert_eq!(s.irqs.0.load(Ordering::SeqCst), 5);

        stop.write(1).unwrap();
        thread.join().unwrap();
        assert_eq!(probe.flushes.load(Ordering::SeqCst), 0);
    }

    /// A batch of eight whose request in slot `panicking` panics, on the worker thread for slot
    /// 0 and on a helper otherwise, once every other request but the worker thread's has been
    /// read. The worker thread holds slot 0 throughout (it claims it before any helper can).
    fn a_batch_with_a_panic(panicking: u16) {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let (mut w, probe) = probe_worker(&s, &vq, CacheType::Writeback);
        // Every other read but the gate's.
        let others = if panicking == 0 { 7 } else { 6 };
        probe.reads_before_panic.store(others, Ordering::SeqCst);
        for i in 0..8u16 {
            let sector = match i {
                _ if i == panicking => PANIC_SECTOR,
                // Read on the worker thread until the helper's request has panicked.
                0 => GATE_SECTOR,
                _ => u64::from(i),
            };
            queue_request(&s.mem, &vq, i, VIRTIO_BLK_T_IN, sector, 512, 16);
        }
        w.process_queue(&s.mem);

        let on_worker = *probe.panicked_on.lock().unwrap() == Some(std::thread::current().id());
        assert_eq!(on_worker, panicking == 0);
        let expected: Vec<_> = (0..8u16)
            .map(|i| (3 * u32::from(i), if i == panicking { 1 } else { 513 }))
            .collect();
        assert_eq!(used(&vq), expected);
        assert_eq!(s.irqs.0.load(Ordering::SeqCst), 1);
        for i in (0..8u16).filter(|&i| i != panicking) {
            assert_eq!(status(&s.mem, i), OK);
            let at = if i == 0 {
                GATE_SECTOR as usize
            } else {
                usize::from(i)
            } * 512;
            assert_eq!(data(&s.mem, i, 512), disk_bytes()[at..at + 512]);
        }
        assert_eq!(status(&s.mem, panicking), IOERR);
        assert_eq!(w.helpers.len(), 7);
        assert!(w.helpers.iter().all(|h| !h.is_finished()));

        later_requests_fail(&s, &vq, &probe, || w.process_queue(&s.mem));
        drop(w);
        assert_eq!(probe.flushes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_panicking_request_on_a_helper_fails_the_disk() {
        a_batch_with_a_panic(1);
    }

    #[test]
    fn a_panicking_request_on_the_worker_thread_fails_the_disk() {
        a_batch_with_a_panic(0);
    }

    /// Requests that find the image lock poisoned, by a writer that panicked holding it, get an
    /// I/O error rather than panic; the batch completes with one interrupt, the helpers keep
    /// running, later requests fail too, and the write-back disk is dropped without panicking.
    #[test]
    fn a_poisoned_image_lock_fails_the_disk() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let (mut w, image) = worker_with(&s, &vq, CacheType::Writeback);

        // Eight reads, blocked on the image lock until its holder panics.
        let (locked_tx, locked_rx) = mpsc::channel();
        let poisoner = std::thread::spawn(move || {
            let _held = image.write().unwrap();
            locked_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            panic!("poisoning the image lock");
        });
        locked_rx.recv().unwrap();
        for i in 0..8u16 {
            queue_request(&s.mem, &vq, i, VIRTIO_BLK_T_IN, u64::from(i), 512, 16);
        }
        w.process_queue(&s.mem);
        assert!(poisoner.join().is_err());
        let expected: Vec<_> = (0..8u32).map(|i| (3 * i, 1)).collect();
        assert_eq!(used(&vq), expected);
        assert!((0..8).all(|i| status(&s.mem, i) == IOERR));
        assert_eq!(s.irqs.0.load(Ordering::SeqCst), 1);
        assert_eq!(w.helpers.len(), 7);
        assert!(w.helpers.iter().all(|h| !h.is_finished()));

        queue_request(&s.mem, &vq, 0, VIRTIO_BLK_T_FLUSH, 0, 0, 16);
        w.process_queue(&s.mem);
        assert_eq!((status(&s.mem, 0), used(&vq).len()), (IOERR, 9));
        drop(w);
    }

    /// Statusless requests must complete with a used length of zero and leave the disk intact.
    #[test]
    fn a_request_without_a_status_byte_is_not_run() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let mut w = worker(&s, &vq);

        // A read and a write, each a lone header descriptor.
        for (i, request_type) in [(0u16, VIRTIO_BLK_T_IN), (1, VIRTIO_BLK_T_OUT)] {
            queue_request(&s.mem, &vq, i, request_type, 1, 0, 16);
            let base = REQ_BASE + u64::from(i) * REQ_STRIDE;
            vq.dtable[3 * usize::from(i)].set(base, 16, 0, 0);
            w.process_queue(&s.mem);
        }
        // A write whose last descriptor is readable: data, but nowhere to put a status.
        let base = REQ_BASE + 2 * REQ_STRIDE;
        s.mem
            .write_slice(&[0x5a; 512], GuestAddress(base + 0x1000))
            .unwrap();
        queue_request(&s.mem, &vq, 2, VIRTIO_BLK_T_OUT, 1, 512, 16);
        vq.dtable[7].set(base + 0x1000, 512, 0, 0);
        w.process_queue(&s.mem);

        assert_eq!(used(&vq), [(0, 0), (3, 0), (6, 0)]);
        assert_eq!(std::fs::read(&s.path).unwrap(), disk_bytes());
    }

    /// The status lands in the last writable byte. Rejected reads preserve the data buffer; a
    /// short disk ID preserves the unused tail.
    #[test]
    fn the_status_is_the_last_writable_byte() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let mut w = worker(&s, &vq);
        let fill = |i: u16| {
            let base = REQ_BASE + u64::from(i) * REQ_STRIDE;
            s.mem
                .write_slice(&[0xa5; 1024], GuestAddress(base + 0x1000))
                .unwrap();
        };

        // Reject a read past the disk end and a read of a partial sector.
        fill(0);
        queue_request(
            &s.mem,
            &vq,
            0,
            VIRTIO_BLK_T_IN,
            (DISK_LEN / 512) as u64,
            512,
            16,
        );
        fill(1);
        queue_request(&s.mem, &vq, 1, VIRTIO_BLK_T_IN, 0, 100, 16);
        // Request the disk ID in an oversized buffer.
        fill(2);
        queue_request(&s.mem, &vq, 2, VIRTIO_BLK_T_GET_ID, 0, 64, 16);
        let base = REQ_BASE + 2 * REQ_STRIDE;
        vq.dtable[7].set(base + 0x1000, 64, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 8);
        w.process_queue(&s.mem);

        // Used lengths count what was written: the failed reads' status, the ID and its status.
        assert_eq!(used(&vq), [(0, 1), (3, 1), (6, 21)]);
        assert_eq!((status(&s.mem, 0), status(&s.mem, 1)), (IOERR, IOERR));
        assert_eq!(data(&s.mem, 0, 1024), [0xa5; 1024]);
        assert_eq!(data(&s.mem, 1, 1024), [0xa5; 1024]);
        assert_eq!(status(&s.mem, 2), OK);
        let id = data(&s.mem, 2, 1024);
        assert_eq!(
            id[..VIRTIO_BLK_ID_BYTES as usize],
            [0; VIRTIO_BLK_ID_BYTES as usize]
        );
        assert!(
            id[VIRTIO_BLK_ID_BYTES as usize..]
                .iter()
                .all(|&b| b == 0xa5)
        );
    }

    /// A chain whose buffers are not all in guest memory is still returned to the guest: with
    /// an I/O error if only its header is out of reach, with nothing written if a writable
    /// buffer is.
    #[test]
    fn a_chain_outside_guest_memory_is_returned() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let mut w = worker(&s, &vq);
        let outside = 0x100000;

        queue_request(&s.mem, &vq, 0, VIRTIO_BLK_T_IN, 0, 512, 16);
        vq.dtable[0].set(outside, 16, VIRTQ_DESC_F_NEXT, 1);
        queue_request(&s.mem, &vq, 1, VIRTIO_BLK_T_IN, 0, 512, 16);
        vq.dtable[4].set(outside, 512, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 5);
        w.process_queue(&s.mem);

        assert_eq!(used(&vq), [(0, 1), (3, 0)]);
        assert_eq!((status(&s.mem, 0), status(&s.mem, 1)), (IOERR, 0xff));
    }

    /// Rejected requests complete with `VIRTIO_BLK_S_UNSUPP` and leave the disk unchanged.
    #[test]
    fn unsupported_requests_and_flags_are_refused() {
        let s = setup();
        let vq = VirtQueue::new(GuestAddress(0), &s.mem, QUEUE_SIZE);
        let mut w = worker(&s, &vq);

        queue_request(&s.mem, &vq, 0, 99, 0, 0, 16);
        for (i, request_type, flags) in [
            (1, VIRTIO_BLK_T_DISCARD, VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP),
            (2, VIRTIO_BLK_T_DISCARD, 1 << 5),
            (3, VIRTIO_BLK_T_WRITE_ZEROES, 1 << 5),
        ] {
            let range = DiscardWriteData {
                sector: 1,
                num_sectors: 1,
                flags,
            };
            let base = REQ_BASE + u64::from(i) * REQ_STRIDE;
            s.mem.write_obj(range, GuestAddress(base + 0x1000)).unwrap();
            queue_request(&s.mem, &vq, i, request_type, 0, 16, 16);
        }
        w.process_queue(&s.mem);

        assert_eq!(used(&vq), [(0, 1), (3, 1), (6, 1), (9, 1)]);
        for i in 0..4 {
            assert_eq!(status(&s.mem, i), UNSUPP);
        }
        assert_eq!(std::fs::read(&s.path).unwrap(), disk_bytes());
    }

    #[test]
    fn a_request_must_fit_the_disk() {
        let cap = 4096;
        assert_eq!(BlockWorker::request_offset(cap, 3, 512).ok(), Some(1536));
        assert_eq!(BlockWorker::request_offset(cap, 7, 512).ok(), Some(3584));
        // Ends past the disk, starts past it, or overflows on the way: all refused.
        for (sector, len) in [
            (7, 1024),
            (9, 0),
            (u64::MAX / 512 + 1, 0),
            (u64::MAX / 512, 1024),
        ] {
            assert!(matches!(
                BlockWorker::request_offset(cap, sector, len),
                Err(RequestError::InvalidOffset)
            ));
        }
    }
}
