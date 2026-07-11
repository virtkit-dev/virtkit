// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use imago::{
    file::File as ImagoFile, qcow2::Qcow2, raw::Raw, vmdk::Vmdk, DynStorage, FormatDriverBuilder,
    PermissiveImplicitOpenGate, Storage, StorageOpenOptions, SyncFormatAccess,
};
use log::{error, warn};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::worker::BlockWorker;
use super::{
    super::{ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice, TYPE_BLOCK},
    Error, NUM_QUEUES, QUEUE_CONFIG, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::virtio::{
    block::{ImageType, SyncMode},
    ActivateError, InterruptTransport, VmmExitObserver,
};

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl CacheType {
    /// Picks the appropriate cache type based on disk image or device path.
    /// Special files like `/dev/rdisk*` on macOS do not support flush/sync.
    pub fn auto(_path: &str) -> CacheType {
        #[cfg(target_os = "macos")]
        if _path.starts_with("/dev/rdisk") {
            return CacheType::Unsafe;
        }
        CacheType::Writeback
    }
}

/// A read-only `mmap` of a raw disk image. Guest reads are served by copying straight from
/// the host page cache through this mapping instead of a `pread` per request. Created only
/// for read-only raw images (a stage's `COPY --from` source or a read-only root), where the
/// guest block offset is the file offset; qcow2 needs format translation and `direct_io`
/// asks to bypass the page cache, so both keep the imago read path.
pub(crate) struct DiskMmap {
    ptr: *mut libc::c_void,
    /// length handed to `mmap`/`munmap` (the file size; the tail of the final page reads as
    /// zero but is never exposed — the guest capacity is floored to whole sectors).
    len: usize,
}

// SAFETY: the mapping is `PROT_READ` and the image is immutable for the mapping's lifetime,
// so the raw pointer is sound to read from any thread.
unsafe impl Send for DiskMmap {}
unsafe impl Sync for DiskMmap {}

impl DiskMmap {
    fn open(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty disk image",
            ));
        }
        // SAFETY: `fd` is valid for the duration of the call; a read-only shared mapping of
        // `len` bytes. The mapping outlives `file` (mmap keeps its own reference).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { ptr, len })
    }

    /// The mapped image as a byte slice; indices in `[0, len)` are valid.
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` maps `len` readable bytes for the lifetime of `self`.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for DiskMmap {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` are exactly what `open` passed to `mmap`.
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

/// Cluster granularity (bytes) at which guest writes are recorded for the dirty tracker.
/// Matches the qcow2 cluster size the host-side reader/pusher works in, so a drained range
/// aligns to whole clusters.
const DIRTY_CLUSTER: u64 = 64 * 1024;

/// Guest-logical clusters mutated since the last drain, split so the virtkit build backend can
/// capture only a checkpoint's delta instead of the whole cumulative overlay. `written` holds
/// clusters any write touched (to read and push as data); `discarded` holds clusters any discard
/// or write-zeroes touched. A write wins over a discard at the 64 KiB cluster granularity: a
/// cluster present in both was only partly freed, so it must be read whole (the overlay reflects
/// the true content, zeroed sub-parts included) rather than holed — [`Self::take`] subtracts the
/// written set out of the discarded one. A host-side control connection (see
/// [`Block::spawn_dirty_control`]) drains both at each checkpoint.
#[derive(Default)]
pub(crate) struct DirtyRanges {
    written: std::collections::BTreeSet<u64>,
    discarded: std::collections::BTreeSet<u64>,
}

impl DirtyRanges {
    /// Record that `[offset, offset+len)` was written, at cluster granularity.
    fn record_write(&mut self, offset: u64, len: u64) {
        for c in cluster_range(offset, len) {
            self.written.insert(c);
        }
    }

    /// Record that `[offset, offset+len)` was freed or zeroed (discard / write-zeroes). Only
    /// whole clusters *fully* inside the range become holes — a partial cluster at either end
    /// may still hold live data (an ext4 block freed next to live ones in the same 64 KiB
    /// cluster), so rounding a hole outward would zero that data. Writes round outward instead
    /// (see [`cluster_range`]): touching any part of a cluster keeps it read whole.
    fn record_discard(&mut self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        let first = offset.div_ceil(DIRTY_CLUSTER); // first cluster fully at/after offset
        let end_cluster = (offset + len) / DIRTY_CLUSTER; // one past the last fully-covered one
        for c in first..end_cluster {
            self.discarded.insert(c);
        }
    }

    /// Take the written clusters and the purely-discarded ones (discarded minus written) as
    /// coalesced byte ranges (clamped to `size`), clearing both sets.
    fn take(&mut self, size: u64) -> (Vec<(u64, u64)>, Vec<(u64, u64)>) {
        let written = std::mem::take(&mut self.written);
        let discarded = &std::mem::take(&mut self.discarded) - &written;
        (
            clusters_to_ranges(written, size),
            clusters_to_ranges(discarded, size),
        )
    }
}

/// The whole clusters `[offset, offset+len)` spans (empty for a zero-length request).
fn cluster_range(offset: u64, len: u64) -> std::ops::RangeInclusive<u64> {
    if len == 0 {
        return 1..=0; // empty
    }
    (offset / DIRTY_CLUSTER)..=((offset + len - 1) / DIRTY_CLUSTER)
}

/// Coalesce a cluster set into byte ranges clamped to `size`; adjacent clusters merge so the
/// caller reads/pushes contiguously.
fn clusters_to_ranges(clusters: std::collections::BTreeSet<u64>, size: u64) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for c in clusters {
        let off = c * DIRTY_CLUSTER;
        if off >= size {
            continue;
        }
        let len = DIRTY_CLUSTER.min(size - off);
        match out.last_mut() {
            Some(last) if last.0 + last.1 == off => last.1 += len,
            _ => out.push((off, len)),
        }
    }
    out
}

/// Encode a drain reply on the dirty-control wire: `u32 count` then `count × (u64 offset,
/// u64 len)`, all little-endian. The host side (virtkit's `VmSession::drain_dirty`) decodes
/// this exact layout; keep the two in lockstep — `encode_decode_round_trips` pins the format.
fn encode_dirty_reply(ranges: &[(u64, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + ranges.len() * 16);
    buf.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
    for (off, len) in ranges {
        buf.extend_from_slice(&off.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
    }
    buf
}

#[cfg(test)]
mod dirty_tests {
    use super::{encode_dirty_reply, DirtyRanges, DIRTY_CLUSTER};

    #[test]
    fn coalesces_adjacent_and_gaps() {
        let mut d = DirtyRanges::default();
        d.record_write(0, 100); // cluster 0 (sub-cluster write rounds up)
        d.record_write(DIRTY_CLUSTER, 10); // cluster 1 — adjacent to 0, coalesces
        d.record_write(3 * DIRTY_CLUSTER, 1); // cluster 3 — gap, separate range
        let big = 100 * DIRTY_CLUSTER;
        let (written, discarded) = d.take(big);
        assert_eq!(
            written,
            vec![(0, 2 * DIRTY_CLUSTER), (3 * DIRTY_CLUSTER, DIRTY_CLUSTER)]
        );
        assert!(discarded.is_empty());
        // take drains: a second drain sees nothing new.
        assert_eq!(d.take(big), (vec![], vec![]));
    }

    #[test]
    fn rewriting_a_cluster_stays_one_range() {
        // An in-place rewrite of an already-dirtied cluster must still appear exactly once —
        // this is the property that makes the tracker correct where allocation-diff was not.
        let mut d = DirtyRanges::default();
        d.record_write(1000, 8);
        d.record_write(2000, 8); // same cluster 0, different bytes
        assert_eq!(d.take(10 * DIRTY_CLUSTER).0, vec![(0, DIRTY_CLUSTER)]);
    }

    #[test]
    fn a_written_cluster_is_never_holed() {
        // A write wins over a discard on the same cluster, either order: the cluster was only
        // partly freed and must be read whole, not holed. Only purely-discarded clusters hole.
        let mut d = DirtyRanges::default();
        d.record_write(0, 8); // cluster 0 written...
        d.record_discard(0, DIRTY_CLUSTER); // ...then a full-cluster discard — stays written
        d.record_discard(DIRTY_CLUSTER, DIRTY_CLUSTER); // cluster 1 discarded...
        d.record_write(DIRTY_CLUSTER, 8); // ...then written — stays written
        d.record_discard(2 * DIRTY_CLUSTER, DIRTY_CLUSTER); // cluster 2 purely discarded
        let (written, discarded) = d.take(10 * DIRTY_CLUSTER);
        assert_eq!(written, vec![(0, 2 * DIRTY_CLUSTER)]);
        assert_eq!(discarded, vec![(2 * DIRTY_CLUSTER, DIRTY_CLUSTER)]);
    }

    #[test]
    fn a_partial_cluster_discard_is_not_a_hole() {
        // A discard that frees only part of a cluster (an ext4 block freed next to live ones)
        // must not hole the whole cluster. Only the fully-covered middle cluster is a hole.
        let mut d = DirtyRanges::default();
        // Free [half of cluster 0 .. half of cluster 3): clusters 1 and 2 are fully inside.
        d.record_discard(DIRTY_CLUSTER / 2, 3 * DIRTY_CLUSTER);
        let (written, discarded) = d.take(10 * DIRTY_CLUSTER);
        assert!(written.is_empty());
        assert_eq!(discarded, vec![(DIRTY_CLUSTER, 2 * DIRTY_CLUSTER)]);
    }

    #[test]
    fn clamps_tail_to_image_size() {
        let mut d = DirtyRanges::default();
        d.record_write(0, 1);
        let size = DIRTY_CLUSTER / 2;
        assert_eq!(d.take(size).0, vec![(0, size)]);
        // A cluster wholly past the image size is dropped.
        let mut d = DirtyRanges::default();
        d.record_discard(5 * DIRTY_CLUSTER, 1);
        assert_eq!(d.take(DIRTY_CLUSTER), (vec![], vec![]));
    }

    #[test]
    fn encode_decode_round_trips() {
        // Decode exactly the way virtkit's `VmSession::drain_dirty` does. If either side's
        // byte layout drifts, this fails — the guard the two crates otherwise lack.
        let ranges = vec![
            (0u64, DIRTY_CLUSTER),
            (7 * DIRTY_CLUSTER, 2 * DIRTY_CLUSTER),
        ];
        let buf = encode_dirty_reply(&ranges);

        let count = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(count, ranges.len());
        let mut decoded = Vec::with_capacity(count);
        for c in buf[4..].chunks_exact(16) {
            let off = u64::from_le_bytes(c[..8].try_into().unwrap());
            let len = u64::from_le_bytes(c[8..16].try_into().unwrap());
            decoded.push((off, len));
        }
        assert_eq!(decoded, ranges);

        // An empty delta encodes to just the count header.
        assert_eq!(encode_dirty_reply(&[]), 0u32.to_le_bytes());
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    pub(crate) file: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    /// Set for read-only raw images; when present, reads are served from it instead of `file`.
    pub(crate) mmap: Option<Arc<DiskMmap>>,
    nsectors: u64,
    image_id: Vec<u8>,
    /// Clusters written since the last drain; shared with the dirty-control listener. Only
    /// populated for a writable disk that opted into tracking (`spawn_dirty_control`).
    dirty: Arc<Mutex<DirtyRanges>>,
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
        mmap: Option<Arc<DiskMmap>>,
        dirty: Arc<Mutex<DirtyRanges>>,
    ) -> io::Result<Self> {
        let disk_size = disk_image.lock().unwrap().size();

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if !disk_size.is_multiple_of(SECTOR_SIZE) {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: disk_image_id,
            file: disk_image,
            mmap,
            dirty,
        })
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    /// Record a guest write for the dirty tracker (no-op unless tracking was enabled).
    /// Called by the block worker after each data-writing request.
    pub(crate) fn record_write(&self, offset: u64, len: u64) {
        self.dirty.lock().unwrap().record_write(offset, len);
    }

    /// Record a guest discard / write-zeroes for the dirty tracker (no-op unless tracking was
    /// enabled). Called by the block worker after each request that frees or zeroes clusters,
    /// so the checkpoint represents them as holes rather than reading or reusing stale data.
    pub(crate) fn record_discard(&self, offset: u64, len: u64) {
        self.dirty.lock().unwrap().record_discard(offset, len);
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_id
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                // flush() first to force any cached data out.
                if self.file.lock().unwrap().flush().is_err() {
                    error!("Failed to flush block data on drop.");
                }
                // Sync data out to physical media on host.
                if self.file.lock().unwrap().sync().is_err() {
                    error!("Failed to sync block data on drop.")
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkTopology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    disk: Option<DiskProperties>,
    cache_type: CacheType,
    disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    disk_image_id: Vec<u8>,
    mmap: Option<Arc<DiskMmap>>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    /// Dirty-cluster tracker, shared with the block worker and (if tracking was enabled) the
    /// host-side control listener. Empty and unused unless a control socket was configured.
    dirty: Arc<Mutex<DirtyRanges>>,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config: VirtioBlkConfig,

    // Transport related fields.
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: ImageType,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
        dirty_control_socket: Option<String>,
    ) -> io::Result<Block> {
        let disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;

        let disk_image_id = DiskProperties::build_disk_image_id(&disk_image);

        // Read-only raw images are served from an mmap (see [`DiskMmap`]); a failed map
        // falls back to the buffered imago read path rather than aborting the boot.
        let mmap =
            if is_disk_read_only && !direct_io && matches!(&disk_image_format, ImageType::Raw) {
                match DiskMmap::open(&disk_image_path) {
                    Ok(m) => Some(Arc::new(m)),
                    Err(e) => {
                        warn!("virtio-blk: mmap of {disk_image_path} failed ({e}); buffered reads");
                        None
                    }
                }
            } else {
                None
            };

        let file_opts = StorageOpenOptions::new()
            .write(!is_disk_read_only)
            .filename(disk_image_path)
            .direct(direct_io);

        #[cfg(target_os = "macos")]
        let file_opts = file_opts.relaxed_sync(sync_mode == SyncMode::Relaxed);
        let file = ImagoFile::open_sync(file_opts)?;
        let discard_alignment = file.discard_align();

        let disk_image = match disk_image_format {
            ImageType::Qcow2 => {
                let mut qcow2 =
                    Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::open_image_sync(
                        Box::new(file),
                        !is_disk_read_only,
                    )?;
                qcow2.open_implicit_dependencies_sync()?;
                SyncFormatAccess::new(qcow2)?
            }
            ImageType::Raw => {
                let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(
                    Box::new(file),
                    !is_disk_read_only,
                )?;
                SyncFormatAccess::new(raw)?
            }
            ImageType::Vmdk => {
                let vmdk = Vmdk::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::builder(
                    Box::new(file),
                )
                .open_sync(PermissiveImplicitOpenGate::default())?;
                SyncFormatAccess::new(vmdk)?
            }
        };

        let disk_image = Arc::new(Mutex::new(disk_image));

        let dirty = Arc::new(Mutex::new(DirtyRanges::default()));

        let disk_properties = DiskProperties::new(
            disk_image.clone(),
            disk_image_id.clone(),
            cache_type,
            mmap.clone(),
            dirty.clone(),
        )?;

        // Host-side dirty-drain control (virtkit build backend): serve a DRAIN protocol on the
        // configured socket so a checkpoint captures only the delta. Spawned once here — the
        // worker (re)constructs its own `DiskProperties` from the shared `dirty` Arc on activate.
        if let Some(socket) = dirty_control_socket {
            Self::spawn_dirty_control(socket, disk_image.clone(), dirty.clone());
        }

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_BLK_F_DISCARD)
            | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if sync_mode != SyncMode::None {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let config = VirtioBlkConfig {
            capacity: disk_properties.nsectors(),
            size_max: 0,
            // QUEUE_SIZE - 2
            seg_max: 254,
            max_discard_sectors: u32::MAX,
            max_discard_seg: 1,
            discard_sector_alignment: discard_alignment as u32 / 512,
            max_write_zeroes_sectors: u32::MAX,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: 1,
            ..Default::default()
        };

        Ok(Block {
            id,
            partuuid,
            config,
            disk: Some(disk_properties),
            cache_type,
            disk_image,
            disk_image_id,
            mmap,
            avail_features,
            acked_features: 0u64,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK)?,
            dirty,
        })
    }

    /// Spawn the host-side dirty-drain control listener on `socket_path`. On each connection it
    /// reads a one-byte command:
    /// - `b'D'` (DRAIN) flushes the disk image to its backing file and replies with the clusters
    ///   mutated since the previous drain as two back-to-back blocks — written clusters, then
    ///   discarded ones — each encoded as `u32 count` then `count × (u64 offset, u64 len)`
    ///   little-endian. The caller freezes the guest fs first, so the flush + take is a
    ///   consistent point-in-time delta.
    /// - `b'F'` (FLUSH) makes the write-back cache durable on the host image (flush + sync)
    ///   without draining, and replies one byte (0 ok / 1 error). The caller flushes before it
    ///   kills the VMM, so a later host read sees a complete image without a graceful power-off.
    ///
    /// Errors are logged and the listener keeps serving; a dead socket just means no checkpoints
    /// (the build falls back correctly on the virtkit side).
    fn spawn_dirty_control(
        socket_path: String,
        disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
        dirty: Arc<Mutex<DirtyRanges>>,
    ) {
        use std::os::unix::net::UnixListener;

        let _ = std::fs::remove_file(&socket_path);
        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                error!("virtio-blk: dirty-control bind {socket_path} failed: {e}");
                return;
            }
        };
        std::thread::Builder::new()
            .name("blk dirty-control".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    let mut conn = match conn {
                        Ok(c) => c,
                        Err(e) => {
                            error!("virtio-blk: dirty-control accept failed: {e}");
                            continue;
                        }
                    };
                    let mut cmd = [0u8; 1];
                    if conn.read_exact(&mut cmd).is_err() {
                        continue;
                    }
                    match cmd[0] {
                        // DRAIN: persist all writes to the backing file, then take the delta. The
                        // guest is frozen by the caller, so nothing races these two steps.
                        b'D' => {
                            let (written, discarded) = {
                                let df = disk_image.lock().unwrap();
                                let size = df.size();
                                if let Err(e) = df.flush().and_then(|()| df.sync()) {
                                    error!("virtio-blk: dirty-control flush failed: {e}");
                                    continue;
                                }
                                dirty.lock().unwrap().take(size)
                            };
                            // Two range blocks back to back: written first, then discarded.
                            let mut buf = encode_dirty_reply(&written);
                            buf.extend_from_slice(&encode_dirty_reply(&discarded));
                            if let Err(e) = conn.write_all(&buf) {
                                error!("virtio-blk: dirty-control reply failed: {e}");
                            }
                        }
                        // FLUSH: make the write-back cache durable on the host image without
                        // draining the dirty set — the caller flushes before killing the VMM, so a
                        // later host read sees a complete image (replaces a graceful power-off).
                        // Reply one byte: 0 ok, 1 error.
                        b'F' => {
                            let reply = match {
                                let df = disk_image.lock().unwrap();
                                df.flush().and_then(|()| df.sync())
                            } {
                                Ok(()) => 0u8,
                                Err(e) => {
                                    error!("virtio-blk: dirty-control flush failed: {e}");
                                    1u8
                                }
                            };
                            let _ = conn.write_all(&[reply]);
                        }
                        _ => continue,
                    }
                }
            })
            .expect("spawn blk dirty-control thread");
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }
}

impl VmmExitObserver for Block {
    /// Flush the write-back cache to the host image before the VMM terminates on a clean
    /// guest power-off. The VMM stops with `libc::_exit`, which skips `DiskProperties`'
    /// `Drop`, and the block device has no other clean-shutdown flush — so without this a
    /// power-off can leave imago's cached metadata/data unwritten and truncate the image (an
    /// L2 entry left pointing past EOF, which a later native read then rejects). A no-op for
    /// `Unsafe` caching, where guest flushes are advisory.
    fn on_vmm_exit(&mut self) {
        if self.cache_type != CacheType::Writeback {
            return;
        }
        let disk = self.disk_image.lock().unwrap();
        if let Err(e) = disk.flush().and_then(|()| disk.sync()) {
            error!("block: failed to flush image on VMM exit: {e}");
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn device_name(&self) -> &str {
        "block"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Guest attempted to write config");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_blk: worker thread already exists");
        }

        let [blk_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        let disk = match self.disk.take() {
            Some(d) => d,
            None => DiskProperties::new(
                Arc::clone(&self.disk_image),
                self.disk_image_id.clone(),
                self.cache_type,
                self.mmap.clone(),
                Arc::clone(&self.dirty),
            )
            .map_err(|_| ActivateError::BadActivate)?,
        };

        let worker = BlockWorker::new(
            blk_q,
            interrupt.clone(),
            mem.clone(),
            disk,
            self.worker_stopfd.try_clone().unwrap(),
        );
        self.worker_thread = Some(worker.run());

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::descriptor_utils::{create_descriptor_chain, DescriptorType, Writer};
    use crate::virtio::file_traits::FileReadWriteAtVolatile;
    use vm_memory::{Bytes, GuestAddress, GuestMemory};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("blk-mmap-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A read-only raw [`DiskProperties`] backed by `path`, with the mmap read path enabled —
    /// the same wiring `Block::new` produces for a read-only raw image.
    fn mmap_disk(path: &std::path::Path) -> DiskProperties {
        let p = path.to_str().unwrap().to_string();
        let ifile = ImagoFile::open_sync(StorageOpenOptions::new().filename(p.clone())).unwrap();
        let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(Box::new(ifile), false).unwrap();
        let sfa = SyncFormatAccess::new(raw).unwrap();
        DiskProperties::new(
            Arc::new(Mutex::new(sfa)),
            vec![0u8; VIRTIO_BLK_ID_BYTES as usize],
            CacheType::Unsafe,
            Some(Arc::new(DiskMmap::open(&p).unwrap())),
            Arc::new(Mutex::new(DirtyRanges::default())),
        )
        .unwrap()
    }

    /// `DiskMmap::as_slice` exposes exactly the file's bytes.
    #[test]
    fn diskmmap_maps_file_contents() {
        let dir = temp_dir("unit");
        let path = dir.join("disk");
        let bytes: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
        std::fs::write(&path, &bytes).unwrap();

        let m = DiskMmap::open(path.to_str().unwrap()).unwrap();
        assert_eq!(m.as_slice(), &bytes[..]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serving a guest read from the mmap must fill exactly `count` bytes with the disk's
    /// contents and leave the rest of the descriptor untouched — the same contract the
    /// buffered `pread` path honors (see `write_from_at_must_not_overread_past_count`).
    #[test]
    fn mmap_read_serves_disk_bytes_and_respects_count() {
        use DescriptorType::*;

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let buf_addr = GuestAddress(0x1000);
        let chain =
            create_descriptor_chain(&mem, GuestAddress(0), buf_addr, vec![(Writable, 100)], 0)
                .unwrap();
        // 0xAA marks bytes past the requested count that must stay untouched.
        mem.write_slice(&[0xAAu8; 100], buf_addr).unwrap();

        let dir = temp_dir("read");
        let path = dir.join("disk");
        std::fs::write(&path, vec![0xBBu8; 512]).unwrap();
        let disk = mmap_disk(&path);
        assert!(disk.mmap.is_some(), "mmap read path must be enabled");

        let mut writer = Writer::new(&mem, chain).unwrap();
        let n = writer
            .write_from_at(&disk, 50, 0)
            .expect("write_from_at failed");

        let mut got = [0u8; 100];
        mem.read_slice(&mut got, buf_addr).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(n, 50, "must report exactly count=50 bytes read");
        assert!(
            got[..50].iter().all(|&b| b == 0xBB),
            "first 50 bytes must come from the mmap'd disk"
        );
        assert!(
            got[50..].iter().all(|&b| b == 0xAA),
            "bytes past count=50 must be untouched: {:?}",
            &got[50..]
        );
    }

    /// A request that would read past the end of the mapping is rejected rather than
    /// faulting on out-of-bounds memory.
    #[test]
    fn mmap_read_past_end_errors() {
        let dir = temp_dir("eof");
        let path = dir.join("disk");
        std::fs::write(&path, vec![0xBBu8; 512]).unwrap();
        let disk = mmap_disk(&path);

        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let slice = mem.get_slice(GuestAddress(0x1000), 512).unwrap();
        // Offset 256 + 512 bytes runs 256 past the 512-byte image.
        let err = disk.read_vectored_at_volatile(&[slice], 256).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A read spanning several descriptors must copy sequential file bytes into each in
    /// order — exercises the per-slice `off` advance in the mmap branch.
    #[test]
    fn mmap_read_spans_multiple_descriptors() {
        use DescriptorType::*;

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let buf_addr = GuestAddress(0x1000);
        // Three contiguous writable descriptors (no gaps), total 128 bytes.
        let chain = create_descriptor_chain(
            &mem,
            GuestAddress(0),
            buf_addr,
            vec![(Writable, 16), (Writable, 32), (Writable, 80)],
            0,
        )
        .unwrap();

        let dir = temp_dir("multi");
        let path = dir.join("disk");
        // A distinct byte per offset so any misordering or gap between slices is caught.
        let bytes: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let disk = mmap_disk(&path);

        let want = 16 + 32 + 80;
        let mut writer = Writer::new(&mem, chain).unwrap();
        // Start at a non-zero, non-aligned file offset.
        let n = writer.write_from_at(&disk, want, 4).unwrap();

        let mut got = vec![0u8; want];
        mem.read_slice(&mut got, buf_addr).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(n, want);
        assert_eq!(got.as_slice(), &bytes[4..4 + want]);
    }
}
