// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
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
    ActivateError, InterruptTransport,
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

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    pub(crate) file: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    /// Set for read-only raw images; when present, reads are served from it instead of `file`.
    pub(crate) mmap: Option<Arc<DiskMmap>>,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
        mmap: Option<Arc<DiskMmap>>,
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
        })
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
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

        let disk_properties = DiskProperties::new(
            disk_image.clone(),
            disk_image_id.clone(),
            cache_type,
            mmap.clone(),
        )?;

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
        })
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
