//! A read-only [`imago::Storage`] backend for `.vk_ro_img` manifests.
//!
//! A `.vk_ro_img` file is written by vk-driver instead of a fully reassembled raw ext4 when
//! restoring a cached build-stage image: it lists the content-addressed, zstd-compressed
//! chunks that tile the image (offset-sorted and non-overlapping, but not necessarily
//! contiguous — a gap between chunks reads as zero) plus the local chunk-cache directory they
//! live in, but holds none of the chunk bytes itself. `LazyChunkStorage` decompresses each
//! chunk lazily, the first time a guest read actually touches it, instead of vk-driver eagerly
//! decompressing the whole image up front.
//!
//! This is deliberately local-disk-only: vk-driver is responsible for ensuring every chunk
//! blob referenced by the manifest is already present in the cache directory before it
//! attaches a `.vk_ro_img` disk (fetching over the network, if needed, happens there) — this
//! module reads local chunks and decompresses zstd chunks without adding a network or async
//! runtime dependency to libkrun.
//!
//! ## `.vk_ro_img` format
//!
//! Both this reader and vk-driver's writer (`vk-driver/src/registry.rs`) hand-encode this
//! layout independently — there is no shared crate between the two workspaces — so a change
//! here must be mirrored there and vice versa. The `.vk_ro_img` *file extension* is part of
//! that same cross-workspace contract, not just the bytes: it is what
//! [`LazyAwareOpenGate`] keys on to resolve a manifest. vk-driver hardcodes it when it names
//! one (`build/exec.rs`, `registry.rs`), requires it when it writes a qcow2 overlay over one
//! (`qcow2.rs::create_overlay`), and matches on it to pick a disk's format (`run.rs`).
//!
//! ```text
//! magic:          [u8; 8]   = b"VKROIMG1"
//! total_size:     u64 LE    // virtual size of the image this is a lazy view of
//! layout:         u8        // 0 = flat, 1 = store_root — see `Layout` below
//! cache_dir_len:  u32 LE
//! cache_dir:      [u8; cache_dir_len]   // UTF-8 path; meaning depends on `layout`
//! chunk_count:    u64 LE
//! chunks:         [ChunkEntry; chunk_count], offset-sorted, non-overlapping, gaps read as
//!                 zero, within [0, total_size)
//!
//! ChunkEntry:
//!   offset:       u64 LE   // position in the reassembled image
//!   length:       u32 LE   // decompressed length
//!   codec:        u8       // 0 = zstd, 1 = raw (stored blob already uncompressed)
//!   digest:       [u8; 32] // raw sha256 naming the chunk (of its stored or its decoded
//!                          // bytes); cache filename is its hex form
//! ```
//!
//! `layout` picks how a chunk's digest maps to a path under `cache_dir`:
//! - `flat`: `cache_dir/<hex>` — the remote-registry chunk cache (`state_dir/registry/chunks/`)
//!   as older vk-driver wrote it.
//! - `store_root`: `cache_dir/blobs/zstd/<hex>` or `cache_dir/blobs/sha256/<hex>` depending on
//!   `codec` — a local registry (`vk_registry::Store`, which picks whichever form is smaller per
//!   blob), and the remote-registry chunk cache, which keeps each chunk in the form it arrived.

use imago::file::File as ImagoFile;
use imago::format::gate::ImplicitOpenGate;
use imago::io_buffers::{IoVector, IoVectorMut};
use imago::storage::drivers::CommonStorageHelper;
use imago::{
    DynStorage, FormatAccess, FormatDriverBuilder, Storage, StorageCreateOptions,
    StorageOpenOptions,
};
use maybe_async::maybe_async;
use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::io::{self, BufReader, Read};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use zstd::zstd_safe::{DCtx, ResetDirective};

const MAGIC: &[u8; 8] = b"VKROIMG1";
const CODEC_ZSTD: u8 = 0;
const CODEC_RAW: u8 = 1;
const LAYOUT_FLAT: u8 = 0;
const LAYOUT_STORE_ROOT: u8 = 1;

/// How many decompressed chunks to keep in memory. Guest reads are far smaller than a
/// chunk (ext4-block-ish), so without this, adjacent small reads within one chunk would
/// redecompress it repeatedly.
const DECODED_CACHE_ENTRIES: usize = 128;
/// Encoded size of one `ChunkEntry`: offset (8) + length (4) + codec (1) + digest (32).
const CHUNK_ENTRY_SIZE: u64 = 8 + 4 + 1 + 32;
/// Largest chunk vk writes (`CDC_MAX` in vk-driver). Initial buffer requests are capped at
/// this size plus the one-byte overrun probe, even for larger manifest lengths.
const MAX_CHUNK: usize = 16 << 20;

/// Process-wide idle buffer limit, sized for one disk at the block worker's `IO_PARALLELISM`.
const IDLE_BUFFERS: usize = 8;
/// Total capacity of the idle decoded-chunk buffers.
const IDLE_BUFFER_BYTES: usize = 64 << 20;
/// Allow up to 1/`REUSE_SLACK` of the requested size in spare capacity per cached chunk.
const REUSE_SLACK: usize = 4;
/// Idle zstd decoder contexts kept for later misses, process-wide.
const IDLE_DECODERS: usize = 8;
/// A context grown past this (a frame with a large window) is freed rather than kept. vk's
/// chunk frames need about 1 MiB.
const MAX_IDLE_DECODER_BYTES: usize = 8 << 20;

/// Largest read buffer a thread keeps between requests: the largest request vk's Linux guest
/// sends by default (`max_sectors_kb` 4096; the device sets no `size_max`). A larger request
/// gets a buffer freed after it.
const MAX_KEPT_BOUNCE: usize = 4 << 20;

thread_local! {
    /// Stages reads that cross a chunk boundary. The block worker and its helpers each
    /// retain at most one buffer until shutdown, for a per-disk limit of `IO_PARALLELISM`
    /// buffers of up to `MAX_KEPT_BOUNCE` bytes each.
    static BOUNCE: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

static CHUNK_BUFFERS: BufferPool = BufferPool::new();
static DECODERS: Mutex<Vec<DCtx<'static>>> = Mutex::new(Vec::new());

/// Evicted chunk buffers, reused so a miss can skip allocating and faulting in a new one.
///
/// All lazy disks share the pool limits. Oldest-first eviction eventually frees buffers that
/// no longer fit new requests. Keeping the initialized length avoids zeroing those bytes on
/// the next decode.
struct BufferPool {
    /// Oldest first.
    idle: Mutex<VecDeque<Vec<u8>>>,
}

impl BufferPool {
    const fn new() -> Self {
        BufferPool {
            idle: Mutex::new(VecDeque::new()),
        }
    }

    /// Each push or pop is complete or has made no change, so a poisoned lock is recovered.
    fn lock(&self) -> MutexGuard<'_, VecDeque<Vec<u8>>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take the smallest buffer within the `REUSE_SLACK` limit, or allocate for `need` bytes.
    fn take(&self, need: usize) -> Vec<u8> {
        let mut idle = self.lock();
        let fit = idle
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                (need..=need.saturating_add(need / REUSE_SLACK)).contains(&b.capacity())
            })
            .min_by_key(|(_, b)| b.capacity())
            .map(|(i, _)| i);
        match fit.and_then(|i| idle.remove(i)) {
            Some(buf) => buf,
            None => {
                drop(idle);
                Vec::with_capacity(need)
            }
        }
    }

    /// Keep `buf` for a later miss, dropping the oldest buffers to stay within the limits.
    fn put(&self, buf: Vec<u8>) {
        if buf.capacity() > MAX_CHUNK + 1 {
            return;
        }
        let mut freed = Vec::new();
        {
            let mut idle = self.lock();
            let mut held: usize = idle.iter().map(Vec::capacity).sum();
            while idle.len() >= IDLE_BUFFERS || held + buf.capacity() > IDLE_BUFFER_BYTES {
                let Some(old) = idle.pop_front() else { break };
                held -= old.capacity();
                freed.push(old);
            }
            idle.push_back(buf);
        }
        // Freed outside the lock.
        drop(freed);
    }
}

/// A zstd decoder context from the idle pool, or a new one.
fn take_decoder() -> io::Result<DCtx<'static>> {
    // Pop in a separate statement so the lock is released before the reset.
    let kept = DECODERS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .pop();
    // A context abandoned mid-frame or after an error starts over clean.
    if let Some(mut ctx) = kept
        && ctx.reset(ResetDirective::SessionAndParameters).is_ok()
    {
        return Ok(ctx);
    }
    DCtx::try_create().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "zstd could not allocate a decoder context",
        )
    })
}

fn put_decoder(ctx: DCtx<'static>) {
    if ctx.sizeof() > MAX_IDLE_DECODER_BYTES {
        return;
    }
    let mut idle = DECODERS.lock().unwrap_or_else(PoisonError::into_inner);
    if idle.len() < IDLE_DECODERS {
        idle.push(ctx);
    }
}

/// Track file read failures so the caller can preserve their error kind through zstd decoding.
struct Source<'a> {
    file: std::fs::File,
    failed: &'a Cell<bool>,
}

impl Read for Source<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.file.read(buf);
        if result
            .as_ref()
            .is_err_and(|e| e.kind() != io::ErrorKind::Interrupted)
        {
            self.failed.set(true);
        }
        result
    }
}

/// Decode concatenated zstd frames into `buf`, stopping at `limit` output bytes. Before that
/// limit, truncated frames and trailing junk are errors. On success, `buf` contains only the
/// decoded bytes. Reuse avoids zeroing the initialized part of the buffer.
fn decode_zstd(file: impl Read, buf: &mut Vec<u8>, limit: usize) -> io::Result<()> {
    let mut ctx = take_decoder()?;
    let result = {
        let input = BufReader::with_capacity(DCtx::in_size(), file);
        let mut decoder = zstd::stream::read::Decoder::with_context(input, &mut ctx);
        buf.resize(limit.min(MAX_CHUNK + 1), 0);
        let mut n = 0;
        loop {
            if n == buf.len() {
                if n == limit {
                    break Ok(n);
                }
                // Only a chunk declared larger than `MAX_CHUNK` gets here.
                buf.resize(limit.min(n.saturating_mul(2)), 0);
            }
            match decoder.read(&mut buf[n..]) {
                Ok(0) => break Ok(n),
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        }
    };
    put_decoder(ctx);
    buf.truncate(result?);
    Ok(())
}

struct ChunkEntry {
    offset: u64,
    length: u32,
    codec: u8,
    digest: [u8; 32],
}

/// Read-only lazy view over a `.vk_ro_img` manifest. See the module docs for the format.
pub struct LazyChunkStorage {
    filename: PathBuf,
    total_size: u64,
    layout: u8,
    cache_dir: PathBuf,
    /// Offset-sorted, non-overlapping, gaps read as zero, within `[0, total_size)` — see the
    /// format doc.
    chunks: Vec<ChunkEntry>,
    decoded: DecodedChunks,
    common_storage_helper: CommonStorageHelper,
}

/// Recently decoded chunks and in-flight decodes, keyed by chunk index.
///
/// The first reader of a missing chunk reads and decodes it outside the cache lock.
/// Other readers of that chunk wait for its result. Hits and misses on other chunks can proceed.
///
/// In-flight decodes neither count toward LRU capacity nor compete for eviction. Each reader
/// decodes one chunk at a time, so the block worker has at most `IO_PARALLELISM` in flight.
struct DecodedChunks {
    state: Mutex<DecodedState>,
    /// Source of buffers for misses and destination for evicted buffers.
    buffers: &'static BufferPool,
}

struct DecodedState {
    lru: lru::LruCache<usize, Arc<Vec<u8>>>,
    loading: HashMap<usize, Arc<Load>>,
}

/// An `io::Error` cannot be cloned. Each waiter rebuilds it from the kind and message.
type LoadResult = Result<Arc<Vec<u8>>, (io::ErrorKind, String)>;

/// Completion shared by readers waiting for the same decode.
#[derive(Default)]
struct Load {
    result: Mutex<Option<LoadResult>>,
    done: Condvar,
}

impl Load {
    fn wait(&self) -> io::Result<Arc<Vec<u8>>> {
        let result = self.result.lock().unwrap_or_else(PoisonError::into_inner);
        let result = self
            .done
            .wait_while(result, |r| r.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        match result.as_ref() {
            Some(Ok(data)) => Ok(Arc::clone(data)),
            Some(Err((kind, msg))) => Err(io::Error::new(*kind, msg.clone())),
            None => Err(io::Error::other("chunk decode finished without a result")),
        }
    }
}

/// Publishes the decode result and wakes its waiters. If decoding panics, dropping the loader
/// publishes an error and frees the index for retry.
struct Loader<'a> {
    chunks: &'a DecodedChunks,
    idx: usize,
    load: Arc<Load>,
    published: bool,
}

impl Loader<'_> {
    fn publish(&mut self, result: LoadResult) {
        self.published = true;
        let evicted;
        {
            let mut state = self.chunks.lock();
            // A decode started before a clear must not repopulate the cache.
            if state
                .loading
                .get(&self.idx)
                .is_some_and(|l| Arc::ptr_eq(l, &self.load))
            {
                state.loading.remove(&self.idx);
                evicted = match &result {
                    Ok(data) => state.lru.push(self.idx, Arc::clone(data)),
                    Err(_) => None,
                };
            } else {
                evicted = None;
            }
        }
        // Recycle the evicted buffer outside the cache lock if its last reader has released it.
        if let Some((_, data)) = evicted
            && let Ok(buf) = Arc::try_unwrap(data)
        {
            self.chunks.buffers.put(buf);
        }
        *self
            .load
            .result
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(result);
        self.load.done.notify_all();
    }
}

impl Drop for Loader<'_> {
    fn drop(&mut self) {
        if !self.published {
            let msg = format!("decoding chunk {} panicked", self.idx);
            self.publish(Err((io::ErrorKind::Other, msg)));
        }
    }
}

impl DecodedChunks {
    fn new(capacity: NonZeroUsize) -> Self {
        Self::with_buffers(capacity, &CHUNK_BUFFERS)
    }

    fn with_buffers(capacity: NonZeroUsize, buffers: &'static BufferPool) -> Self {
        DecodedChunks {
            state: Mutex::new(DecodedState {
                lru: lru::LruCache::new(capacity),
                loading: HashMap::new(),
            }),
            buffers,
        }
    }

    /// Recover a poisoned lock. The critical sections operate only on cache entries and contain
    /// no reader-supplied code.
    fn lock(&self) -> MutexGuard<'_, DecodedState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reuse a cached or in-flight result, or run `load` on this thread.
    fn get_or_load(
        &self,
        idx: usize,
        load: impl FnOnce() -> io::Result<Vec<u8>>,
    ) -> io::Result<Arc<Vec<u8>>> {
        let load_slot = {
            let mut state = self.lock();
            if let Some(data) = state.lru.get(&idx) {
                return Ok(Arc::clone(data));
            }
            match state.loading.entry(idx) {
                Entry::Occupied(e) => {
                    let pending = Arc::clone(e.get());
                    drop(state);
                    return pending.wait();
                }
                Entry::Vacant(e) => Arc::clone(e.insert(Arc::default())),
            }
        };
        let mut loader = Loader {
            chunks: self,
            idx,
            load: load_slot,
            published: false,
        };
        match load() {
            Ok(data) => {
                let data = Arc::new(data);
                loader.publish(Ok(Arc::clone(&data)));
                Ok(data)
            }
            Err(e) => {
                loader.publish(Err((e.kind(), e.to_string())));
                Err(e)
            }
        }
    }

    /// Clear the cache. Existing waiters keep their result. The first subsequent miss on each
    /// index starts a new decode.
    fn clear(&self) {
        let mut state = self.lock();
        state.lru.clear();
        state.loading.clear();
    }
}

fn digest_hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for b in digest {
        write!(&mut hex, "{b:02x}").unwrap();
    }
    hex
}

fn check_length(path: &Path, got: usize, expected: u32) -> io::Result<()> {
    if got == expected as usize {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "chunk {}: decompressed to {got} bytes, expected {expected}",
            path.display()
        ),
    ))
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!(".vk_ro_img: {e}")))
}

impl LazyChunkStorage {
    fn parse(mut f: std::fs::File, filename: PathBuf) -> io::Result<Self> {
        let file_len = f.metadata()?.len();
        let mut magic = [0u8; 8];
        read_exact_or_eof(&mut f, &mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                ".vk_ro_img: bad magic",
            ));
        }
        let mut u64buf = [0u8; 8];
        read_exact_or_eof(&mut f, &mut u64buf)?;
        let total_size = u64::from_le_bytes(u64buf);

        let mut layout_buf = [0u8; 1];
        read_exact_or_eof(&mut f, &mut layout_buf)?;
        let layout = layout_buf[0];
        if layout != LAYOUT_FLAT && layout != LAYOUT_STORE_ROOT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(".vk_ro_img: unknown layout {layout}"),
            ));
        }

        let mut u32buf = [0u8; 4];
        read_exact_or_eof(&mut f, &mut u32buf)?;
        let cache_dir_len = u32::from_le_bytes(u32buf) as usize;
        if cache_dir_len as u64 > file_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(".vk_ro_img: cache_dir_len {cache_dir_len} exceeds file size {file_len}"),
            ));
        }
        let mut cache_dir_bytes = vec![0u8; cache_dir_len];
        read_exact_or_eof(&mut f, &mut cache_dir_bytes)?;
        let cache_dir =
            PathBuf::from(String::from_utf8(cache_dir_bytes).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!(".vk_ro_img: {e}"))
            })?);

        read_exact_or_eof(&mut f, &mut u64buf)?;
        let chunk_count = u64::from_le_bytes(u64buf) as usize;
        if (chunk_count as u64).saturating_mul(CHUNK_ENTRY_SIZE) > file_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(".vk_ro_img: chunk_count {chunk_count} exceeds file size {file_len}"),
            ));
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        let mut expect_offset = 0u64;
        for _ in 0..chunk_count {
            read_exact_or_eof(&mut f, &mut u64buf)?;
            let offset = u64::from_le_bytes(u64buf);
            read_exact_or_eof(&mut f, &mut u32buf)?;
            let length = u32::from_le_bytes(u32buf);
            let mut codec = [0u8; 1];
            read_exact_or_eof(&mut f, &mut codec)?;
            let mut digest = [0u8; 32];
            read_exact_or_eof(&mut f, &mut digest)?;
            // Chunks are offset-sorted and non-overlapping, but NOT necessarily contiguous: a
            // diff push can drop a region that went fully back to zero since its parent
            // instead of re-chunking it (see vk-driver's `push_ext4_diff`) — a gap here reads
            // as zero, exactly like the eager reassembly path leaves it an untouched hole.
            if offset < expect_offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(".vk_ro_img: overlapping chunk at offset {offset}"),
                ));
            }
            expect_offset = offset.checked_add(length as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, ".vk_ro_img: overflow")
            })?;
            chunks.push(ChunkEntry {
                offset,
                length,
                codec: codec[0],
                digest,
            });
        }
        if expect_offset > total_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    ".vk_ro_img: chunks cover {expect_offset} bytes, expected at most {total_size}"
                ),
            ));
        }

        Ok(LazyChunkStorage {
            filename,
            total_size,
            layout,
            cache_dir,
            chunks,
            decoded: DecodedChunks::new(NonZeroUsize::new(DECODED_CACHE_ENTRIES).unwrap()),
            common_storage_helper: Default::default(),
        })
    }

    fn chunk_path(&self, chunk: &ChunkEntry) -> PathBuf {
        let hex = digest_hex(&chunk.digest);
        match self.layout {
            LAYOUT_STORE_ROOT => {
                let sub = if chunk.codec == CODEC_ZSTD {
                    "blobs/zstd"
                } else {
                    "blobs/sha256"
                };
                self.cache_dir.join(sub).join(hex)
            }
            _ => self.cache_dir.join(hex),
        }
    }

    /// Decompressed bytes of chunk `idx`, from the decoded-chunk cache or freshly read off disk.
    fn decode_chunk(&self, idx: usize) -> io::Result<Arc<Vec<u8>>> {
        self.decoded.get_or_load(idx, || self.load_chunk(idx))
    }

    /// Read raw or compressed chunk `idx` into a buffer from the pool and verify its length.
    fn load_chunk(&self, idx: usize) -> io::Result<Vec<u8>> {
        let chunk = &self.chunks[idx];
        let path = self.chunk_path(chunk);
        let reading = |e: io::Error| {
            io::Error::new(
                e.kind(),
                format!(
                    "reading chunk {} for {}: {e}",
                    path.display(),
                    self.filename.display()
                ),
            )
        };
        let file = std::fs::File::open(&path).map_err(reading)?;
        if chunk.codec != CODEC_ZSTD && chunk.codec != CODEC_RAW {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk {}: unknown codec {}", path.display(), chunk.codec),
            ));
        }
        // One extra byte detects an overrun without buffering the rest of an oversized chunk.
        let limit = chunk.length as usize + 1;
        let mut buf = self.decoded.buffers.take(limit.min(MAX_CHUNK + 1));
        let result = if chunk.codec == CODEC_ZSTD {
            let read_failed = Cell::new(false);
            let source = Source {
                file,
                failed: &read_failed,
            };
            decode_zstd(source, &mut buf, limit).map_err(|e| {
                if read_failed.get() {
                    reading(e)
                } else if e.kind() == io::ErrorKind::OutOfMemory {
                    e
                } else {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("zstd-decompressing chunk {}: {e}", path.display()),
                    )
                }
            })
        } else {
            buf.clear();
            file.take(limit as u64)
                .read_to_end(&mut buf)
                .map(drop)
                .map_err(reading)
        };
        let result = result.and_then(|()| check_length(&path, buf.len(), chunk.length));
        match result {
            Ok(()) => Ok(buf),
            Err(e) => {
                self.decoded.buffers.put(buf);
                Err(e)
            }
        }
    }

    /// Index of the first chunk that could contain or come after byte `pos` — either the
    /// chunk covering `pos`, or (if `pos` falls in a gap) the next chunk after the gap, or
    /// `chunks.len()` if `pos` is at or past the last chunk's end (a trailing gap to EOF).
    fn chunk_at(&self, pos: u64) -> usize {
        self.chunks
            .partition_point(|c| c.offset + c.length as u64 <= pos)
    }

    fn read_range(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or_else(|| io::Error::other("read offset overflow"))?;
        let mut pos = offset;
        while pos < end {
            if pos >= self.total_size {
                // Past EOF: the rest reads as zero.
                out[(pos - offset) as usize..].fill(0);
                break;
            }
            let idx = self.chunk_at(pos);
            let in_gap = idx >= self.chunks.len() || self.chunks[idx].offset > pos;
            let copy_end = if in_gap {
                // A gap (dropped by a diff push because it went back to zero) reads as
                // zero, up to wherever the next chunk starts (or EOF).
                let gap_end = self
                    .chunks
                    .get(idx)
                    .map(|c| c.offset)
                    .unwrap_or(self.total_size)
                    .min(end);
                out[(pos - offset) as usize..(gap_end - offset) as usize].fill(0);
                gap_end
            } else {
                let chunk = &self.chunks[idx];
                let chunk_end = chunk.offset + chunk.length as u64;
                let data = self.decode_chunk(idx)?;
                let copy_end = chunk_end.min(end);
                let src = &data[(pos - chunk.offset) as usize..(copy_end - chunk.offset) as usize];
                let dst_start = (pos - offset) as usize;
                out[dst_start..dst_start + src.len()].copy_from_slice(src);
                copy_end
            };
            pos = copy_end;
        }
        Ok(())
    }
}

impl fmt::Debug for LazyChunkStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyChunkStorage")
            .field("filename", &self.filename)
            .field("total_size", &self.total_size)
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

impl Display for LazyChunkStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "vk_ro_img:{:?}", self.filename)
    }
}

#[maybe_async(AFIT)]
impl Storage for LazyChunkStorage {
    async fn open(opts: StorageOpenOptions) -> io::Result<Self> {
        // `opts.write`/`opts.direct` have no public getters on `StorageOpenOptions` (only
        // `get_filename` does) — a caller requesting O_DIRECT or writable semantics can't be
        // detected or honored here. Chunk files always use read-only, page-cache-backed I/O.
        let Some(filename) = opts.get_filename() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Filename required",
            ));
        };
        let filename = filename.to_path_buf();
        let f = std::fs::File::open(&filename)?;
        Self::parse(f, filename)
    }

    async fn create_open(_opts: StorageCreateOptions) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.total_size)
    }

    fn get_filename(&self) -> Option<PathBuf> {
        Some(self.filename.clone())
    }

    async unsafe fn pure_readv(&self, mut bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        let len = usize::try_from(bufv.len()).map_err(io::Error::other)?;
        if len == 0 {
            return Ok(());
        }
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::other("read offset overflow"))?;
        // A read within one chunk or gap needs no staging buffer. Decoding must succeed
        // before the first guest write so a failure leaves every segment untouched.
        let idx = self.chunk_at(offset);
        match self.chunks.get(idx) {
            Some(chunk) if chunk.offset < end => {
                if chunk.offset <= offset && end <= chunk.offset + chunk.length as u64 {
                    let data = self.decode_chunk(idx)?;
                    let start = (offset - chunk.offset) as usize;
                    bufv.copy_from_slice(&data[start..start + len]);
                    return Ok(());
                }
            }
            _ => {
                bufv.fill(0);
                return Ok(());
            }
        }
        let mut out = if len <= MAX_KEPT_BOUNCE {
            BOUNCE.take()
        } else {
            Vec::new()
        };
        if out.len() < len {
            out.reserve_exact(len - out.len());
            out.resize(len, 0);
        }
        // `read_range` writes every byte of the range, so bytes left over from an earlier
        // request never reach the guest; on an error the guest buffers stay untouched.
        let result = self.read_range(offset, &mut out[..len]);
        if result.is_ok() {
            bufv.copy_from_slice(&out[..len]);
        }
        if out.capacity() <= MAX_KEPT_BOUNCE {
            BOUNCE.set(out);
        }
        result
    }

    async unsafe fn pure_writev(&self, _bufv: IoVector<'_>, _offset: u64) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    async unsafe fn invalidate_cache(&self) -> io::Result<()> {
        self.decoded.clear();
        Ok(())
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        &self.common_storage_helper
    }
}

/// The extension vk-driver gives a `.vk_ro_img` manifest, in [`std::path::Path::extension`]
/// form (no leading dot), and the only thing that marks one as a backing file: the name is
/// chosen by the host driver, never by a guest, so keying on it (rather than sniffing the
/// file's magic) keeps a guest-writable image from ever being promoted into a manifest —
/// which would let it name any host directory as its chunk cache. Part of the
/// cross-workspace contract described in this module's header.
const VK_RO_IMG_EXT: &str = "vk_ro_img";

/// Opens implicit qcow2 dependencies, resolving a `.vk_ro_img` backing file (see
/// [`LazyChunkStorage`]) at *any* depth of the chain instead of letting imago read the
/// manifest file's own bytes as the image.
///
/// A build stage's disk is a qcow2 whose backing is the stage it forked from, so a cached
/// stage restored as a manifest sits at the bottom of a chain that can be arbitrarily deep:
/// `stage.qcow2` → `parent.qcow2` → `cached.vk_ro_img`. The gate hands a fresh copy of itself
/// to every nested open, so each level along the way keeps that behaviour.
///
/// The gate supplies only the *storage*; imago still picks the format layer wrapped around it
/// from the parent's recorded `backing_format`, so a manifest must be recorded as `raw` (what
/// vk-driver's `create_overlay` writes) — `qcow2` would parse the decompressed image as a
/// qcow2 and fail. Every non-manifest open is exactly what imago's own
/// `PermissiveImplicitOpenGate` would have done, which is what this replaced.
#[derive(Clone, Copy, Debug, Default)]
pub struct LazyAwareOpenGate;

#[maybe_async(AFIT)]
impl ImplicitOpenGate<Box<dyn DynStorage>> for LazyAwareOpenGate {
    async fn open_format<F: FormatDriverBuilder<Box<dyn DynStorage>>>(
        &mut self,
        builder: F,
    ) -> io::Result<FormatAccess<Box<dyn DynStorage>>> {
        // `maybe-async`'s `is_sync` is pinned on for this crate (see its Cargo.toml), so this
        // is a plain call — no `Box::pin` recursion dance like imago's own
        // `PermissiveImplicitOpenGate` needs for its async build.
        Ok(FormatAccess::new(builder.open(*self)?))
    }

    async fn open_storage(
        &mut self,
        options: StorageOpenOptions,
    ) -> io::Result<Box<dyn DynStorage>> {
        let is_manifest = options
            .get_filename()
            .is_some_and(|f| f.extension().is_some_and(|e| e == VK_RO_IMG_EXT));
        if is_manifest {
            // A manifest is a view over immutable, content-addressed chunks and
            // `LazyChunkStorage` has no write path at all, so it is opened read-only whatever
            // the caller asked for. `StorageOpenOptions` exposes no `write` getter, so
            // `LazyChunkStorage::open` cannot observe the flag either way — this call states
            // the intent for a reader, it does not enforce anything.
            //
            // Note the gate cannot tell a backing-file open (imago asks for `write(false)`)
            // from an external-data-file one (`write(true)`): a `.vk_ro_img` named as a
            // qcow2 data file would be accepted here and then fail late with `Unsupported` on
            // the guest's first write. vk-driver never writes such a header.
            Ok(Box::new(LazyChunkStorage::open(options.write(false))?))
        } else {
            Ok(Box::new(ImagoFile::open(options)?))
        }
    }
}

/// Test support shared with `device.rs`'s tests, which exercise this reader through a qcow2
/// backing chain. It lives here, next to `parse`, so the hand-encoded manifest layout has
/// exactly one test-side copy to keep in sync with the reader.
#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    /// Digest bytes derived from a small counter so each test chunk gets a distinct,
    /// deterministic "hash" without pulling in a real sha256 dependency just for tests.
    /// The values are arbitrary: nothing in this reader verifies a chunk against its digest,
    /// it only uses the hex form as the cache filename.
    pub fn fake_digest(n: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[31] = n;
        d
    }

    /// A temp directory removed on drop, so a failing assert does not leak it.
    pub struct Fixture {
        pub dir: std::path::PathBuf,
    }
    impl Fixture {
        pub fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vk-lazy-chunk-storage-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Fixture { dir }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Build a `.vk_ro_img` manifest by hand, mirroring `LazyChunkStorage::parse`'s expected
    /// byte layout.
    pub fn write_manifest(
        path: &std::path::Path,
        total_size: u64,
        layout: u8,
        cache_dir: &std::path::Path,
        chunks: &[(u64, u32, u8, [u8; 32])],
    ) {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&total_size.to_le_bytes());
        buf.push(layout);
        let cache_dir_bytes = cache_dir.to_str().unwrap().as_bytes();
        buf.extend_from_slice(&(cache_dir_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(cache_dir_bytes);
        buf.extend_from_slice(&(chunks.len() as u64).to_le_bytes());
        for &(offset, length, codec, digest) in chunks {
            buf.extend_from_slice(&offset.to_le_bytes());
            buf.extend_from_slice(&length.to_le_bytes());
            buf.push(codec);
            buf.extend_from_slice(&digest);
        }
        std::fs::write(path, buf).unwrap();
    }

    /// The cache filename a chunk's digest maps to. Delegates to the reader's own
    /// `digest_hex` so a test writes its blobs under exactly the name the reader looks for
    /// (a `pub use` cannot re-export it — it is private to this module).
    pub fn blob_name(digest: &[u8; 32]) -> String {
        digest_hex(digest)
    }

    /// The format constants a caller outside this module needs to describe a chunk. Aliases
    /// rather than `pub use` for the same reason as `blob_name`.
    pub const LAYOUT_FLAT: u8 = super::LAYOUT_FLAT;
    pub const CODEC_ZSTD: u8 = super::CODEC_ZSTD;
    pub const CODEC_RAW: u8 = super::CODEC_RAW;
}

#[cfg(test)]
mod tests {
    use super::test_support::{Fixture, fake_digest, write_manifest};
    use super::*;

    /// Two chunks — one zstd, one raw — laid out flat (remote-registry style): reads
    /// spanning both, exactly at the boundary, and fully within one, all reassemble the
    /// original bytes.
    #[test]
    fn reads_across_chunk_boundaries_flat_layout() {
        let fx = Fixture::new("flat");
        let chunk_a: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let chunk_b: Vec<u8> = (0..3000u32).map(|i| ((i * 7) % 251) as u8).collect();
        let digest_a = fake_digest(1);
        let digest_b = fake_digest(2);
        let compressed_a = zstd::encode_all(&chunk_a[..], 3).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_a)), &compressed_a).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_b)), &chunk_b).unwrap();

        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            (chunk_a.len() + chunk_b.len()) as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, chunk_a.len() as u32, CODEC_ZSTD, digest_a),
                (
                    chunk_a.len() as u64,
                    chunk_b.len() as u32,
                    CODEC_RAW,
                    digest_b,
                ),
            ],
        );

        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        assert_eq!(
            storage.size().unwrap(),
            (chunk_a.len() + chunk_b.len()) as u64
        );

        let mut whole = chunk_a.clone();
        whole.extend_from_slice(&chunk_b);

        // Fully within chunk_a.
        let mut out = vec![0u8; 100];
        storage.read_range(10, &mut out).unwrap();
        assert_eq!(out, whole[10..110]);

        // Spans the boundary between chunk_a and chunk_b.
        let mut out = vec![0u8; 40];
        let start = chunk_a.len() as u64 - 20;
        storage.read_range(start, &mut out).unwrap();
        assert_eq!(out, whole[start as usize..start as usize + 40]);

        // Fully within chunk_b.
        let mut out = vec![0u8; 50];
        storage
            .read_range(chunk_a.len() as u64 + 10, &mut out)
            .unwrap();
        assert_eq!(out, whole[chunk_a.len() + 10..chunk_a.len() + 60]);

        // The whole image in one read.
        let mut out = vec![0u8; whole.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, whole);
    }

    /// `store_root` layout: a zstd chunk lives under `blobs/zstd/`, a raw one under
    /// `blobs/sha256/` — same directory root, picked per chunk by `codec`, matching
    /// `vk_registry::Store`'s adaptive on-disk layout.
    #[test]
    fn store_root_layout_picks_the_right_subdirectory_per_codec() {
        let fx = Fixture::new("store-root");
        std::fs::create_dir_all(fx.dir.join("blobs/zstd")).unwrap();
        std::fs::create_dir_all(fx.dir.join("blobs/sha256")).unwrap();
        let chunk_a: Vec<u8> = vec![0xAB; 2000];
        let chunk_b: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        let digest_a = fake_digest(3);
        let digest_b = fake_digest(4);
        std::fs::write(
            fx.dir.join("blobs/zstd").join(digest_hex(&digest_a)),
            zstd::encode_all(&chunk_a[..], 3).unwrap(),
        )
        .unwrap();
        std::fs::write(
            fx.dir.join("blobs/sha256").join(digest_hex(&digest_b)),
            &chunk_b,
        )
        .unwrap();

        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            (chunk_a.len() + chunk_b.len()) as u64,
            LAYOUT_STORE_ROOT,
            &fx.dir,
            &[
                (0, chunk_a.len() as u32, CODEC_ZSTD, digest_a),
                (
                    chunk_a.len() as u64,
                    chunk_b.len() as u32,
                    CODEC_RAW,
                    digest_b,
                ),
            ],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        let mut whole = chunk_a.clone();
        whole.extend_from_slice(&chunk_b);
        let mut out = vec![0u8; whole.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, whole);
    }

    /// A gap between chunks (a diff push drops a region that went back to zero since its
    /// parent instead of re-chunking it — see `push_ext4_diff` in vk-driver) reads as zero,
    /// exactly like the eager reassembly path leaves it an untouched hole. Also covers a
    /// trailing gap between the last chunk and `total_size`.
    #[test]
    fn gaps_between_chunks_read_as_zero() {
        let fx = Fixture::new("gap");
        let chunk_a = vec![0xAAu8; 100];
        let chunk_c = vec![0xCCu8; 100];
        let digest_a = fake_digest(1);
        let digest_c = fake_digest(2);
        std::fs::write(fx.dir.join(digest_hex(&digest_a)), &chunk_a).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_c)), &chunk_c).unwrap();

        let manifest = fx.dir.join("test.vk_ro_img");
        // [0,100) = chunk_a, [100,150) = gap, [150,250) = chunk_c, [250,300) = trailing gap.
        write_manifest(
            &manifest,
            300,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, 100, CODEC_RAW, digest_a),
                (150, 100, CODEC_RAW, digest_c),
            ],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();

        let mut want = vec![0u8; 300];
        want[0..100].copy_from_slice(&chunk_a);
        want[150..250].copy_from_slice(&chunk_c);

        let mut out = vec![0u8; 300];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, want, "whole-image read must zero-fill both gaps");

        // A read entirely inside the inter-chunk gap.
        let mut out = vec![0u8; 20];
        storage.read_range(110, &mut out).unwrap();
        assert_eq!(out, vec![0u8; 20]);

        // A read spanning chunk_a's tail, the gap, and chunk_c's head.
        let mut out = vec![0u8; 100];
        storage.read_range(80, &mut out).unwrap();
        assert_eq!(out, want[80..180]);
    }

    const SENTINEL: u8 = 0x5A;

    /// `readv` at `offset` into sentinel-filled guest segments of `sizes` bytes. Returns the
    /// result and the segments' bytes, concatenated.
    fn readv_into(
        storage: &LazyChunkStorage,
        offset: u64,
        sizes: &[usize],
    ) -> (io::Result<()>, Vec<u8>) {
        use imago::StorageExt;
        let mut segments: Vec<Vec<u8>> = sizes.iter().map(|&n| vec![SENTINEL; n]).collect();
        let slices: Vec<io::IoSliceMut<'_>> = segments
            .iter_mut()
            .map(|s| io::IoSliceMut::new(s))
            .collect();
        let result = storage.readv(IoVectorMut::from(slices), offset);
        (result, segments.concat())
    }

    /// The calling thread's kept read buffer: (address, capacity).
    fn kept_bounce() -> (*const u8, usize) {
        let buf = BOUNCE.take();
        let kept = (buf.as_ptr(), buf.capacity());
        BOUNCE.set(buf);
        kept
    }

    /// Reads across chunks, gaps and EOF land in guest segments of awkward sizes, empty ones
    /// included, with every byte of the request written.
    #[test]
    fn readv_fills_uneven_segments_across_chunks_gaps_and_eof() {
        let fx = Fixture::new("readv-segments");
        let chunk_a: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let chunk_b: Vec<u8> = (0..3000u32).map(|i| ((i * 7) % 253) as u8 | 1).collect();
        let (digest_a, digest_b) = (fake_digest(1), fake_digest(2));
        std::fs::write(
            fx.dir.join(digest_hex(&digest_a)),
            zstd::encode_all(&chunk_a[..], 3).unwrap(),
        )
        .unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_b)), &chunk_b).unwrap();
        // [0,5000) = a, [5000,6000) = gap, [6000,9000) = b, [9000,10000) = trailing gap.
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            10_000,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, 5000, CODEC_ZSTD, digest_a),
                (6000, 3000, CODEC_RAW, digest_b),
            ],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
        let mut want = vec![0u8; 12_000];
        want[..5000].copy_from_slice(&chunk_a);
        want[6000..9000].copy_from_slice(&chunk_b);

        for (offset, sizes) in [
            (0u64, &[1usize, 7, 4093, 3, 0, 5896][..]),
            (4990, &[11, 0, 999, 10][..]),
            (5100, &[100][..]),
            (8990, &[3, 1007][..]),
            (9000, &[1, 1999][..]),
            (2, &[4999, 1, 1, 1997, 2000][..]),
            (10, &[1, 0, 4093, 3][..]),
            (6001, &[2998, 1][..]),
            (9500, &[100, 600][..]),
            (10_500, &[100][..]),
            (5000, &[999, 1][..]),
        ] {
            let (result, got) = readv_into(&storage, offset, sizes);
            result.unwrap();
            let start = offset as usize;
            assert_eq!(
                got,
                want[start..start + got.len()],
                "readv at {offset} into {sizes:?}"
            );
        }
    }

    /// A thread keeps its read buffer for later requests, but never one larger than
    /// `MAX_KEPT_BOUNCE`, and bytes from an earlier request never reach a later one.
    #[test]
    fn read_buffer_is_kept_within_its_cap_and_never_leaks_old_bytes() {
        let fx = Fixture::new("readv-kept");
        let chunk = vec![0xABu8; 1 << 20];
        let digest = fake_digest(1);
        std::fs::write(fx.dir.join(digest_hex(&digest)), &chunk).unwrap();
        // [0, 1 MiB) = chunk, then a gap to 4 MiB.
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            4 << 20,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, 1 << 20, CODEC_RAW, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();

        // A fresh thread, so the buffer starts out empty whatever ran before on this one.
        std::thread::scope(|s| {
            s.spawn(|| {
                // Chunk and gap: assembled in the kept buffer.
                let (result, got) = readv_into(&storage, 0, &[(1 << 20) + 4096]);
                result.unwrap();
                assert_eq!(got[..1 << 20], chunk[..]);
                assert!(got[1 << 20..].iter().all(|&b| b == 0));
                let (ptr, cap) = kept_bounce();
                assert!(
                    ((1 << 20) + 4096..=MAX_KEPT_BOUNCE).contains(&cap),
                    "kept {cap} bytes"
                );

                // Larger than the cap: served from a buffer of its own, the kept one untouched.
                let (result, got) = readv_into(&storage, 0, &[MAX_KEPT_BOUNCE + 4096]);
                result.unwrap();
                assert_eq!(got[..1 << 20], chunk[..]);
                assert!(got[1 << 20..].iter().all(|&b| b == 0));
                assert_eq!(kept_bounce(), (ptr, cap));

                // The kept buffer still holds the chunk's bytes: a read straddling the chunk's
                // end must carry exactly its own bytes, and a gap must read as zero.
                let (result, got) = readv_into(&storage, (1 << 20) - 512, &[100, 3996]);
                result.unwrap();
                assert!(got[..512].iter().all(|&b| b == 0xAB));
                assert!(got[512..].iter().all(|&b| b == 0));
                assert_eq!(kept_bounce(), (ptr, cap));

                // Inside one chunk or one gap: straight to the guest, no buffer taken.
                drop(BOUNCE.take());
                let (result, got) = readv_into(&storage, 4096, &[3, 4093]);
                result.unwrap();
                assert!(got.iter().all(|&b| b == 0xAB));
                let (result, got) = readv_into(&storage, 2 << 20, &[4096]);
                result.unwrap();
                assert_eq!(got, vec![0u8; 4096]);
                assert_eq!(kept_bounce().1, 0);
            });
        });
    }

    /// A decode error in the only chunk or partway through a read fails the request.
    /// Every guest segment stays untouched, and the thread's next read succeeds.
    #[test]
    fn a_failed_chunk_leaves_the_guest_segments_untouched() {
        let fx = Fixture::new("readv-error");
        let chunk_a = vec![0x11u8; 4096];
        let (digest_a, digest_b) = (fake_digest(1), fake_digest(2));
        std::fs::write(fx.dir.join(digest_hex(&digest_a)), &chunk_a).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_b)), b"not a zstd frame").unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            8192,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, 4096, CODEC_RAW, digest_a),
                (4096, 4096, CODEC_ZSTD, digest_b),
            ],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();

        for (offset, sizes) in [(0u64, &[100usize, 5000, 3092][..]), (4100, &[1, 4091][..])] {
            let (result, got) = readv_into(&storage, offset, sizes);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(got.iter().all(|&b| b == SENTINEL));
        }

        let (result, got) = readv_into(&storage, 0, &[4000, 96]);
        result.unwrap();
        assert_eq!(got, chunk_a);
    }

    /// Overlapping chunks (offsets going backwards) are a corrupt manifest, unlike a gap —
    /// reject it rather than silently misplacing reads.
    #[test]
    fn rejects_overlapping_chunks() {
        let fx = Fixture::new("overlap");
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            150,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, 100, CODEC_RAW, fake_digest(1)),
                (50, 100, CODEC_RAW, fake_digest(2)),
            ],
        );
        let err =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A decoded chunk is cached: a second read into the same chunk must not need the
    /// backing blob file any more (deleting it between reads still succeeds).
    #[test]
    fn decoded_chunks_are_cached_across_reads() {
        let fx = Fixture::new("cache");
        let chunk: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let digest = fake_digest(9);
        let path = fx.dir.join(digest_hex(&digest));
        std::fs::write(&path, &chunk).unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            chunk.len() as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, chunk.len() as u32, CODEC_RAW, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        let mut out = vec![0u8; chunk.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, chunk);
        std::fs::remove_file(&path).unwrap();
        let mut out2 = vec![0u8; chunk.len()];
        storage.read_range(0, &mut out2).unwrap();
        assert_eq!(
            out2, chunk,
            "second read should hit the decoded-chunk cache"
        );
    }

    /// `invalidate_cache` drops decoded chunks, so a read afterwards must go back to the
    /// backing blob file (and fail once that file is gone).
    #[test]
    fn invalidate_cache_forces_redecode() {
        let fx = Fixture::new("invalidate");
        let chunk: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let digest = fake_digest(9);
        let path = fx.dir.join(digest_hex(&digest));
        std::fs::write(&path, &chunk).unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            chunk.len() as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, chunk.len() as u32, CODEC_RAW, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        let mut out = vec![0u8; chunk.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, chunk);

        std::fs::remove_file(&path).unwrap();
        unsafe { storage.invalidate_cache() }.unwrap();
        storage
            .read_range(0, &mut out)
            .expect_err("cache was invalidated, blob file is gone");
    }

    /// A `cache_dir_len` (or `chunk_count`) bigger than the whole manifest file can't possibly
    /// be legitimate — a corrupted or truncated `.vk_ro_img` must fail cleanly instead of
    /// driving an unbounded allocation.
    #[test]
    fn rejects_length_fields_that_exceed_the_file_size() {
        let fx = Fixture::new("oversized-lengths");

        let bad_cache_dir_len = fx.dir.join("bad_cache_dir_len.vk_ro_img");
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.push(LAYOUT_FLAT);
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&bad_cache_dir_len, &buf).unwrap();
        let err = LazyChunkStorage::parse(
            std::fs::File::open(&bad_cache_dir_len).unwrap(),
            bad_cache_dir_len,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let bad_chunk_count = fx.dir.join("bad_chunk_count.vk_ro_img");
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.push(LAYOUT_FLAT);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&u64::MAX.to_le_bytes());
        std::fs::write(&bad_chunk_count, &buf).unwrap();
        let err = LazyChunkStorage::parse(
            std::fs::File::open(&bad_chunk_count).unwrap(),
            bad_chunk_count,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A header that ends mid-field (crash mid-write, truncated copy) must be reported as
    /// `InvalidData`, not panic or silently read garbage.
    #[test]
    fn rejects_truncated_header() {
        let fx = Fixture::new("truncated");
        let manifest = fx.dir.join("test.vk_ro_img");
        std::fs::write(&manifest, &MAGIC[..4]).unwrap();
        let err =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A chunk blob whose bytes aren't a valid zstd frame must surface as `InvalidData`
    /// instead of panicking the decode.
    #[test]
    fn rejects_corrupt_zstd_chunk() {
        let fx = Fixture::new("corrupt-zstd");
        let digest = fake_digest(1);
        std::fs::write(fx.dir.join(digest_hex(&digest)), b"not a zstd frame").unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            100,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, 100, CODEC_ZSTD, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
        let mut out = vec![0u8; 100];
        let err = storage.read_range(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A chunk that decompresses to a different length than the manifest declared must be
    /// rejected rather than silently reassembled with the wrong bytes.
    #[test]
    fn rejects_decompressed_length_mismatch() {
        let fx = Fixture::new("length-mismatch");
        let chunk: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let digest = fake_digest(1);
        let compressed = zstd::encode_all(&chunk[..], 3).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest)), &compressed).unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        // Manifest claims 200 bytes; the blob actually decompresses to 100.
        write_manifest(
            &manifest,
            200,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, 200, CODEC_ZSTD, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        let mut out = vec![0u8; 200];
        let err = storage.read_range(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Manifest claims 50 bytes; the blob inflates past them to 100.
        write_manifest(
            &manifest,
            50,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, 50, CODEC_ZSTD, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
        let mut out = vec![0u8; 50];
        let err = storage.read_range(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Open a flat image of consecutive chunks with a cache of `entries` chunks. Return the
    /// storage, its private buffer pool, and the expected image bytes.
    fn open_chunks(
        fx: &Fixture,
        entries: usize,
        chunks: &[(Vec<u8>, u8)],
    ) -> (LazyChunkStorage, &'static BufferPool, Vec<u8>) {
        let mut whole = Vec::new();
        let mut manifest_entries = Vec::new();
        for (n, (data, codec)) in chunks.iter().enumerate() {
            let digest = fake_digest(n as u8 + 1);
            let blob = match *codec {
                CODEC_ZSTD => zstd::encode_all(&data[..], 3).unwrap(),
                _ => data.clone(),
            };
            std::fs::write(fx.dir.join(digest_hex(&digest)), blob).unwrap();
            manifest_entries.push((whole.len() as u64, data.len() as u32, *codec, digest));
            whole.extend_from_slice(data);
        }
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            whole.len() as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &manifest_entries,
        );
        let mut storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
        let pool: &'static BufferPool = Box::leak(Box::new(BufferPool::new()));
        storage.decoded = DecodedChunks::with_buffers(NonZeroUsize::new(entries).unwrap(), pool);
        (storage, pool, whole)
    }

    fn idle_ptrs(pool: &BufferPool) -> Vec<*const u8> {
        pool.lock().iter().map(|b| b.as_ptr()).collect()
    }

    /// Raw and zstd misses reuse evicted buffers and expose only the new chunk's bytes.
    /// Readers keep their buffers after eviction. A failed decode returns its buffer.
    #[test]
    fn evicted_buffers_are_reused_for_later_misses() {
        let fx = Fixture::new("reuse");
        let pattern = |len: usize, mul: u32| -> Vec<u8> {
            (0..len as u32)
                .map(|i| (i.wrapping_mul(mul) % 251) as u8)
                .collect()
        };
        let chunks = [
            (vec![0xAA; 72 << 10], CODEC_ZSTD),
            (pattern(64 << 10, 3), CODEC_ZSTD),
            (pattern(60 << 10, 5), CODEC_RAW),
            (pattern(56 << 10, 7), CODEC_ZSTD),
        ];
        let (storage, pool, whole) = open_chunks(&fx, 1, &chunks);
        let span = |idx: usize| {
            let start: usize = chunks[..idx].iter().map(|c| c.0.len()).sum();
            start..start + chunks[idx].0.len()
        };
        let read = |idx: usize| {
            let range = span(idx);
            let mut out = vec![0x55; range.len()];
            storage.read_range(range.start as u64, &mut out).unwrap();
            assert_eq!(out, whole[range], "chunk {idx}");
        };

        read(0);
        read(1);
        let buf0 = idle_ptrs(pool);
        assert_eq!(buf0.len(), 1, "chunk 0's buffer was kept");
        read(2);
        assert_eq!(storage.decode_chunk(2).unwrap().as_ptr(), buf0[0]);
        let buf1 = idle_ptrs(pool);
        assert_eq!(buf1.len(), 1, "chunk 1's buffer was kept");
        read(3);
        let held = storage.decode_chunk(3).unwrap();
        assert_eq!(held.as_ptr(), buf1[0]);
        assert_eq!(*held, whole[span(3)]);

        // Chunk 0 takes chunk 2's buffer back and evicts chunk 3, which is still held.
        read(0);
        assert!(idle_ptrs(pool).is_empty());
        assert_eq!(*held, whole[span(3)]);
        drop(held);

        // A chunk that decodes short returns its buffer.
        std::fs::write(
            fx.dir.join(digest_hex(&fake_digest(2))),
            zstd::encode_all(&[1u8; 100][..], 3).unwrap(),
        )
        .unwrap();
        let mut out = vec![0; 10];
        let err = storage
            .read_range(span(1).start as u64, &mut out)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(idle_ptrs(pool).len(), 1);
    }

    #[test]
    fn buffer_pool_limits() {
        let pool = BufferPool::new();
        for cap in 1..=IDLE_BUFFERS + 1 {
            pool.put(Vec::with_capacity(cap));
        }
        let caps: Vec<usize> = pool.lock().iter().map(Vec::capacity).collect();
        assert_eq!(
            caps,
            (2..=IDLE_BUFFERS + 1).collect::<Vec<_>>(),
            "oldest dropped"
        );

        // Best fit, but never more than a quarter over the need.
        let pool = BufferPool::new();
        for cap in [126, 110, 100, 125, 90] {
            pool.put(Vec::with_capacity(cap));
        }
        for cap in [100, 110, 125] {
            assert_eq!(pool.take(100).capacity(), cap);
        }
        let fresh = pool.take(100);
        assert_eq!(
            fresh.capacity(),
            100,
            "a new buffer: 126 is too large, 90 too small"
        );
        assert_eq!(pool.lock().len(), 2);

        let pool = BufferPool::new();
        pool.put(Vec::with_capacity(MAX_CHUNK + 2));
        assert!(pool.lock().is_empty(), "larger than any chunk vk writes");
        for _ in 0..IDLE_BUFFERS {
            pool.put(Vec::with_capacity(MAX_CHUNK + 1));
        }
        let held: usize = pool.lock().iter().map(Vec::capacity).sum();
        assert_eq!(pool.lock().len(), IDLE_BUFFER_BYTES / (MAX_CHUNK + 1));
        assert!(held <= IDLE_BUFFER_BYTES);
    }

    /// Concatenated frames form one chunk. Truncated frames, trailing junk and raw blobs of the
    /// wrong length fail.
    #[test]
    fn chunk_blobs_must_decode_to_exactly_the_declared_bytes() {
        let fx = Fixture::new("framing");
        let a: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let b = vec![0x42u8; 3000];
        let frame_a = zstd::encode_all(&a[..], 3).unwrap();
        let frame_b = zstd::encode_all(&b[..], 3).unwrap();
        let both = [a.clone(), b.clone()].concat();
        let check = |name: &str, blob: Vec<u8>, codec: u8, ok: bool| {
            let digest = fake_digest(1);
            std::fs::write(fx.dir.join(digest_hex(&digest)), blob).unwrap();
            let manifest = fx.dir.join(format!("{name}.vk_ro_img"));
            let len = both.len() as u32;
            write_manifest(
                &manifest,
                len.into(),
                LAYOUT_FLAT,
                &fx.dir,
                &[(0, len, codec, digest)],
            );
            let storage =
                LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
            let mut out = vec![0u8; both.len()];
            match storage.read_range(0, &mut out) {
                Ok(()) => {
                    assert!(ok, "{name}: accepted");
                    assert_eq!(out, both, "{name}");
                }
                Err(e) => {
                    assert!(!ok, "{name}: {e}");
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{name}");
                }
            }
        };
        check(
            "concatenated",
            [&frame_a[..], &frame_b[..]].concat(),
            CODEC_ZSTD,
            true,
        );
        let cut = [&frame_a[..], &frame_b[..frame_b.len() - 3]].concat();
        check("truncated", cut, CODEC_ZSTD, false);
        let trailing = [&frame_a[..], &frame_b[..], b"junk"].concat();
        check("trailing", trailing, CODEC_ZSTD, false);
        check("raw", both.clone(), CODEC_RAW, true);
        check("raw-short", both[1..].to_vec(), CODEC_RAW, false);
        check("raw-long", [&both[..], &[0]].concat(), CODEC_RAW, false);
    }

    /// Chunks larger than vk writes can grow the buffer up to the declared length plus one.
    /// A single extra decoded byte fails the length check.
    #[test]
    fn chunks_declared_larger_than_vk_writes_decode_within_their_length() {
        let fx = Fixture::new("oversized");
        let data = vec![0u8; MAX_CHUNK + 4096];
        let digest = fake_digest(1);
        std::fs::write(
            fx.dir.join(digest_hex(&digest)),
            zstd::encode_all(&data[..], 1).unwrap(),
        )
        .unwrap();
        for (declared, ok) in [(data.len(), true), (data.len() - 1, false)] {
            let manifest = fx.dir.join("test.vk_ro_img");
            let len = declared as u32;
            write_manifest(
                &manifest,
                len.into(),
                LAYOUT_FLAT,
                &fx.dir,
                &[(0, len, CODEC_ZSTD, digest)],
            );
            let storage =
                LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
            match storage.decode_chunk(0) {
                Ok(chunk) => {
                    assert!(ok, "declared {declared}: accepted");
                    assert_eq!(chunk.len(), declared);
                    assert!(chunk.iter().all(|&b| b == 0));
                }
                Err(e) => {
                    assert!(!ok, "declared {declared}: {e}");
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                }
            }
        }
    }

    mod decoded_chunks {
        use super::super::DecodedChunks;
        use std::io;
        use std::num::NonZeroUsize;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        const TIMEOUT: Duration = Duration::from_secs(10);

        fn chunks(capacity: usize) -> DecodedChunks {
            DecodedChunks::new(NonZeroUsize::new(capacity).unwrap())
        }

        /// Wait for `n` readers to join the decode of chunk `idx`. Each holds one handle,
        /// as do the in-flight map and the reader running the decode.
        fn wait_for_waiters(chunks: &DecodedChunks, idx: usize, n: usize) {
            let deadline = Instant::now() + TIMEOUT;
            loop {
                let held = chunks.lock().loading.get(&idx).map_or(0, Arc::strong_count);
                if held == n + 2 {
                    return;
                }
                assert!(Instant::now() < deadline, "{held} handles, want {}", n + 2);
                std::thread::yield_now();
            }
        }

        /// Signal `started` and wait for `release` so the test can run during the decode.
        fn stalled(
            started: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            result: io::Result<Vec<u8>>,
        ) -> impl FnOnce() -> io::Result<Vec<u8>> {
            move || {
                started.send(()).unwrap();
                release.recv_timeout(TIMEOUT).expect("never released");
                result
            }
        }

        fn never() -> io::Result<Vec<u8>> {
            panic!("this read must not decode")
        }

        #[test]
        fn concurrent_misses_on_one_chunk_share_one_decode() {
            let chunks = chunks(4);
            let decodes = AtomicUsize::new(0);
            let (started_tx, started) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            std::thread::scope(|s| {
                let leader = s.spawn(|| {
                    let decode = stalled(started_tx, release_rx, Ok(vec![7; 10]));
                    chunks.get_or_load(0, || {
                        decodes.fetch_add(1, Ordering::SeqCst);
                        decode()
                    })
                });
                started.recv_timeout(TIMEOUT).unwrap();
                let waiters: Vec<_> = (0..7)
                    .map(|_| {
                        s.spawn(|| {
                            chunks.get_or_load(0, || {
                                decodes.fetch_add(1, Ordering::SeqCst);
                                Ok(vec![9])
                            })
                        })
                    })
                    .collect();
                wait_for_waiters(&chunks, 0, 7);
                release.send(()).unwrap();
                let first = leader.join().unwrap().unwrap();
                assert_eq!(*first, vec![7; 10]);
                for w in waiters {
                    assert!(Arc::ptr_eq(&w.join().unwrap().unwrap(), &first));
                }
                assert!(Arc::ptr_eq(&chunks.get_or_load(0, never).unwrap(), &first));
            });
            assert_eq!(decodes.load(Ordering::SeqCst), 1);
            assert!(chunks.lock().loading.is_empty());
        }

        /// A hit on one chunk and a miss on another both complete while a third chunk's decode
        /// is stalled.
        #[test]
        fn other_chunks_do_not_wait_for_a_decode() {
            let chunks = chunks(4);
            chunks.get_or_load(1, || Ok(vec![1])).unwrap();
            let (started_tx, started) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            std::thread::scope(|s| {
                let leader =
                    s.spawn(|| chunks.get_or_load(0, stalled(started_tx, release_rx, Ok(vec![0]))));
                started.recv_timeout(TIMEOUT).unwrap();
                assert_eq!(*chunks.get_or_load(1, never).unwrap(), vec![1]);
                assert_eq!(*chunks.get_or_load(2, || Ok(vec![2])).unwrap(), vec![2]);
                release.send(()).unwrap();
                assert_eq!(*leader.join().unwrap().unwrap(), vec![0]);
            });
        }

        #[test]
        fn a_failed_decode_reaches_every_waiter_and_is_retried() {
            let chunks = chunks(4);
            let (started_tx, started) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            std::thread::scope(|s| {
                let leader = s.spawn(|| {
                    let err = io::Error::new(io::ErrorKind::InvalidData, "corrupt frame");
                    chunks.get_or_load(0, stalled(started_tx, release_rx, Err(err)))
                });
                started.recv_timeout(TIMEOUT).unwrap();
                let waiters: Vec<_> = (0..3)
                    .map(|_| s.spawn(|| chunks.get_or_load(0, never)))
                    .collect();
                wait_for_waiters(&chunks, 0, 3);
                release.send(()).unwrap();
                let err = leader.join().unwrap().unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                for w in waiters {
                    let err = w.join().unwrap().unwrap_err();
                    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                    assert!(err.to_string().contains("corrupt frame"), "{err}");
                }
            });
            assert!(chunks.lock().loading.is_empty());
            assert!(chunks.lock().lru.is_empty());
            assert_eq!(*chunks.get_or_load(0, || Ok(vec![5])).unwrap(), vec![5]);
        }

        #[test]
        fn a_panicking_decode_fails_its_waiters_and_is_retried() {
            let chunks = chunks(4);
            let (started_tx, started) = mpsc::channel::<()>();
            let (release, release_rx) = mpsc::channel::<()>();
            std::thread::scope(|s| {
                let chunks = &chunks;
                let leader = s.spawn(move || {
                    chunks.get_or_load(0, || {
                        started_tx.send(()).unwrap();
                        release_rx.recv_timeout(TIMEOUT).unwrap();
                        panic!("decoder panicked");
                    })
                });
                started.recv_timeout(TIMEOUT).unwrap();
                let waiters: Vec<_> = (0..3)
                    .map(|_| s.spawn(|| chunks.get_or_load(0, never)))
                    .collect();
                wait_for_waiters(chunks, 0, 3);
                release.send(()).unwrap();
                assert!(leader.join().is_err());
                for w in waiters {
                    w.join().unwrap().unwrap_err();
                }
            });
            assert!(chunks.lock().loading.is_empty());
            assert_eq!(*chunks.get_or_load(0, || Ok(vec![5])).unwrap(), vec![5]);
        }

        /// Eviction affects only finished chunks. An in-flight decode can still enter the cache,
        /// and readers retain the bytes of evicted chunks.
        #[test]
        fn eviction_leaves_decodes_in_flight_alone() {
            let chunks = chunks(2);
            let (started_tx, started) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            std::thread::scope(|s| {
                let leader = s.spawn(|| {
                    chunks.get_or_load(0, stalled(started_tx, release_rx, Ok(vec![0; 3])))
                });
                started.recv_timeout(TIMEOUT).unwrap();
                let waiter = s.spawn(|| chunks.get_or_load(0, never));
                wait_for_waiters(&chunks, 0, 1);
                let held = chunks.get_or_load(1, || Ok(vec![1; 3])).unwrap();
                for idx in 2..5u8 {
                    chunks.get_or_load(idx.into(), || Ok(vec![idx; 3])).unwrap();
                }
                assert!(chunks.lock().loading.contains_key(&0));
                assert!(!chunks.lock().lru.contains(&1), "chunk 1 was evicted");
                assert_eq!(*held, vec![1; 3]);
                release.send(()).unwrap();
                let first = leader.join().unwrap().unwrap();
                assert!(Arc::ptr_eq(&waiter.join().unwrap().unwrap(), &first));
                assert!(Arc::ptr_eq(&chunks.get_or_load(0, never).unwrap(), &first));
            });
            assert_eq!(chunks.lock().lru.len(), 2);
            assert!(chunks.lock().loading.is_empty());
        }

        /// A pre-clear decode serves only its existing waiters. The cache keeps the new result.
        #[test]
        fn a_decode_from_before_a_clear_is_not_cached() {
            let chunks = chunks(4);
            let (started_tx, started) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            std::thread::scope(|s| {
                let leader = s.spawn(|| {
                    chunks.get_or_load(0, stalled(started_tx, release_rx, Ok(b"old".to_vec())))
                });
                started.recv_timeout(TIMEOUT).unwrap();
                let waiter = s.spawn(|| chunks.get_or_load(0, never));
                wait_for_waiters(&chunks, 0, 1);
                chunks.clear();
                assert_eq!(
                    *chunks.get_or_load(0, || Ok(b"new".to_vec())).unwrap(),
                    b"new"
                );
                release.send(()).unwrap();
                assert_eq!(*leader.join().unwrap().unwrap(), b"old");
                assert_eq!(*waiter.join().unwrap().unwrap(), b"old");
            });
            assert_eq!(*chunks.get_or_load(0, never).unwrap(), b"new");
            assert!(chunks.lock().loading.is_empty());
        }
    }

    /// Eight readers check the same slice of the first chunk. Seven then check the original
    /// bytes across each of the seven chunk boundaries, one reader per boundary.
    #[test]
    fn concurrent_reads_on_same_and_different_chunks() {
        let fx = Fixture::new("concurrent");
        let chunk_len = 4096usize;
        let mut whole = Vec::new();
        let mut entries = Vec::new();
        for n in 0..8u8 {
            let chunk: Vec<u8> = (0..chunk_len)
                .map(|i| (i as u8).wrapping_mul(n + 1))
                .collect();
            let digest = fake_digest(n + 1);
            std::fs::write(
                fx.dir.join(digest_hex(&digest)),
                zstd::encode_all(&chunk[..], 3).unwrap(),
            )
            .unwrap();
            entries.push((whole.len() as u64, chunk_len as u32, CODEC_ZSTD, digest));
            whole.extend_from_slice(&chunk);
        }
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            whole.len() as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &entries,
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    let mut out = vec![0u8; 100];
                    storage.read_range(10, &mut out).unwrap();
                    assert_eq!(out, whole[10..110]);
                });
            }
        });
        std::thread::scope(|s| {
            for n in 1..8 {
                let (storage, whole) = (&storage, &whole);
                s.spawn(move || {
                    let start = n * chunk_len - 50;
                    let mut out = vec![0u8; 100];
                    storage.read_range(start as u64, &mut out).unwrap();
                    assert_eq!(out, whole[start..start + 100]);
                });
            }
        });
    }
}
