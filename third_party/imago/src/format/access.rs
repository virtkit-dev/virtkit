//! Actual public image access functionality.
//!
//! Provides access to different image formats via `FormatAccess` objects.

use super::drivers::{FormatDriverInstance, ShallowMapping};
use super::PreallocateMode;
use crate::io_buffers::{IoVector, IoVectorMut};
use crate::storage::ext::write_full_zeroes;
use crate::{Storage, StorageExt};
#[cfg(feature = "async")]
use futures::stream::{FuturesUnordered, StreamExt};
use maybe_async::maybe_async;
use std::fmt::{self, Display, Formatter};
use std::{cmp, io, ptr};

/// Provides access to a disk image.
#[derive(Debug)]
pub struct FormatAccess<S: Storage + 'static> {
    /// Image format driver.
    inner: Box<dyn FormatDriverInstance<Storage = S>>,

    /// Whether this image may be modified.
    writable: bool,

    /// How many asynchronous requests to perform per read request in parallel.
    #[cfg(feature = "async")]
    read_parallelization: usize,

    /// How many asynchronous requests to perform per write request in parallel.
    #[cfg(feature = "async")]
    write_parallelization: usize,
}

/// Fully recursive mapping information.
///
/// Mapping information that resolves down to the storage object layer (except for special data).
#[derive(Debug)]
#[non_exhaustive]
pub enum Mapping<'a, S: Storage + 'static> {
    /// Raw data.
    #[non_exhaustive]
    Raw {
        /// Storage object where this data is stored.
        storage: &'a S,

        /// Offset in `storage` where this data is stored.
        offset: u64,

        /// Whether this mapping may be written to.
        ///
        /// If `true`, you can directly write to `offset` on `storage` to change the disk image’s
        /// data accordingly.
        ///
        /// If `false`, the disk image format does not allow writing to `offset` on `storage`; a
        /// new mapping must be allocated first.
        writable: bool,
    },

    /// Range is to be read as zeroes.
    #[non_exhaustive]
    Zero {
        /// Whether these zeroes are explicit on this image (the top layer).
        ///
        /// Differential image formats (like qcow2) track information about the status for all
        /// blocks in the image (called clusters in case of qcow2).  Perhaps most importantly, they
        /// track whether a block is allocated or not:
        /// - Allocated blocks have their data in the image.
        /// - Unallocated blocks do not have their data in this image, but have to be read from a
        ///   backing image (which results in [`ShallowMapping::Indirect`] mappings).
        ///
        /// Thus, such images represent the difference from their backing image (hence
        /// “differential”).
        ///
        /// Without a backing image, this feature can be used for sparse allocation: Unallocated
        /// blocks are simply interpreted to be zero.  These ranges will be noted as
        /// [`Mapping::Zero`] with `explicit` set to false.
        ///
        /// Formats like qcow2 can track more information beyond just the allocation status,
        /// though, for example, whether a block should read as zero. Such blocks similarly do not
        /// need to have their data stored in the image file, but are still not treated as
        /// unallocated, so will never be read from a backing image, regardless of whether one
        /// exists or not.
        ///
        /// These ranges are noted as [`Mapping::Zero`] with `explicit` set to true.
        explicit: bool,
    },

    /// End of file reached.
    ///
    /// The accompanying length is always 0.
    #[non_exhaustive]
    Eof {},

    /// Data is encoded in some manner, e.g. compressed or encrypted.
    ///
    /// Such data cannot be accessed directly, but must be interpreted by the image format driver.
    #[non_exhaustive]
    Special {
        /// Format layer where this special data was encountered.
        layer: &'a FormatAccess<S>,

        /// Original (“guest”) offset on `layer` to pass to `readv_special()`.
        offset: u64,
    },
}

// When adding new public methods, don’t forget to add them to sync_wrappers, too.
#[maybe_async]
impl<S: Storage + 'static> FormatAccess<S> {
    /// Wrap a format driver instance in `FormatAccess`.
    ///
    /// `FormatAccess` provides I/O access to disk images, based on the functionality offered by
    /// the individual format drivers via `FormatDriverInstance`.
    pub fn new<D: FormatDriverInstance<Storage = S> + 'static>(inner: D) -> Self {
        let writable = inner.writable();
        FormatAccess {
            inner: Box::new(inner),
            #[cfg(feature = "async")]
            read_parallelization: 1,
            #[cfg(feature = "async")]
            write_parallelization: 1,
            writable,
        }
    }

    /// Return the contained format driver instance.
    pub fn inner(&self) -> &dyn FormatDriverInstance<Storage = S> {
        self.inner.as_ref()
    }

    /// Return the contained format driver instance.
    pub fn inner_mut(&mut self) -> &mut dyn FormatDriverInstance<Storage = S> {
        self.inner.as_mut()
    }

    /// Return the disk size in bytes.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Set the number of simultaneous async requests per read.
    ///
    /// When issuing read requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    #[cfg(feature = "async")]
    pub fn set_async_read_parallelization(&mut self, count: usize) {
        self.read_parallelization = count;
    }

    /// Set the number of simultaneous async requests per write.
    ///
    /// When issuing write requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    #[cfg(feature = "async")]
    pub fn set_async_write_parallelization(&mut self, count: usize) {
        self.write_parallelization = count;
    }

    /// Return all storage dependencies of this image.
    ///
    /// Includes recursive dependencies, i.e. those from other image dependencies like backing
    /// images.
    pub(crate) fn collect_storage_dependencies(&self) -> Vec<&S> {
        self.inner.collect_storage_dependencies()
    }

    /// Minimal I/O alignment, for both length and offset.
    ///
    /// All requests to this image should be aligned to this value, both in length and offset.
    ///
    /// Requests that do not match this alignment will be realigned internally, which requires
    /// creating bounce buffers and read-modify-write cycles for write requests, which is costly,
    /// so should be avoided.
    pub fn req_align(&self) -> usize {
        self.inner
            .collect_storage_dependencies()
            .into_iter()
            .fold(1, |max, s| cmp::max(max, s.req_align()))
    }

    /// Minimal memory buffer alignment, for both address and length.
    ///
    /// All buffers used in requests to this image should be aligned to this value, both their
    /// address and length.
    ///
    /// Request buffers that do not match this alignment will be realigned internally, which
    /// requires creating bounce buffers, which is costly, so should be avoided.
    pub fn mem_align(&self) -> usize {
        self.inner
            .collect_storage_dependencies()
            .into_iter()
            .fold(1, |max, s| cmp::max(max, s.mem_align()))
    }

    /// Read the data from the given mapping.
    async fn read_chunk(
        &self,
        mut bufv: IoVectorMut<'_>,
        mapping: Mapping<'_, S>,
    ) -> io::Result<()> {
        match mapping {
            Mapping::Raw {
                storage,
                offset,
                writable: _,
            } => storage.readv(bufv, offset).await,

            Mapping::Zero { explicit: _ } | Mapping::Eof {} => {
                bufv.fill(0);
                Ok(())
            }

            // FIXME: TOCTTOU problem.  Not sure how to fully fix it, if possible at all.
            // (Concurrent writes can change the mapping, but the driver will have to reload the
            // mapping because it cannot pass it in `NonRecursiveMapping::Special`.  It may then
            // find that this is no longer a “special” range.  Even passing the low-level mapping
            // information in `Mapping::Special` wouldn’t fully fix it, though: If concurrent
            // writes change the low-level cluster type, and the driver then tries to e.g.
            // decompress the data that was there, that may well fail.)
            Mapping::Special { layer, offset } => layer.inner.readv_special(bufv, offset).await,
        }
    }

    /// Return the shallow mapping at `offset`.
    ///
    /// Find what `offset` is mapped to, which may be another format layer, return that
    /// information, and the length of the continuous mapping (from `offset`).
    ///
    /// Use [`FormatAccess::get_mapping()`] to recursively fully resolve references to other format
    /// layers.
    pub async fn get_shallow_mapping(
        &self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(ShallowMapping<'_, S>, u64)> {
        self.inner
            .get_mapping(offset, max_length)
            .await
            .map(|(m, l)| (m, cmp::min(l, max_length)))
    }

    /// Return the recursively resolved mapping at `offset`.
    ///
    /// Find what `offset` is mapped to, return that mapping information, and the length of that
    /// continuous mapping (from `offset`).
    ///
    /// All data references to other format layers are automatically resolved (recursively), so
    /// that the result are more “trivial” mappings (unless prevented by special mappings like
    /// compressed clusters).
    pub async fn get_mapping(
        &self,
        mut offset: u64,
        mut max_length: u64,
    ) -> io::Result<(Mapping<'_, S>, u64)> {
        let mut format_layer = self;
        let mut writable_gate = true;

        loop {
            let (mapping, length) = format_layer.get_shallow_mapping(offset, max_length).await?;

            match mapping {
                ShallowMapping::Raw {
                    storage,
                    offset,
                    writable,
                } => {
                    return Ok((
                        Mapping::Raw {
                            storage,
                            offset,
                            writable: writable && writable_gate,
                        },
                        length,
                    ))
                }

                ShallowMapping::Indirect {
                    layer: recurse_layer,
                    offset: recurse_offset,
                    writable: recurse_writable,
                } => {
                    format_layer = recurse_layer;
                    offset = recurse_offset;
                    writable_gate = recurse_writable;
                    max_length = length;
                }

                ShallowMapping::Zero { explicit } => {
                    // If this is not the top layer, always clear `explicit`
                    return if explicit && ptr::eq(format_layer, self) {
                        Ok((Mapping::Zero { explicit: true }, length))
                    } else {
                        Ok((Mapping::Zero { explicit: false }, length))
                    };
                }

                ShallowMapping::Eof {} => {
                    // Return EOF only on top layer, zero otherwise
                    return if ptr::eq(format_layer, self) {
                        Ok((Mapping::Eof {}, 0))
                    } else {
                        Ok((Mapping::Zero { explicit: false }, max_length))
                    };
                }

                ShallowMapping::Special { offset } => {
                    return Ok((
                        Mapping::Special {
                            layer: format_layer,
                            offset,
                        },
                        length,
                    ));
                }
            }
        }
    }

    /// Create a raw data mapping at `offset`.
    ///
    /// Ensure that `offset` is directly mapped to some storage object, up to a length of `length`.
    /// Return the storage object, the corresponding offset there, and the continuous length that
    /// we were able to map (less than or equal to `length`).
    ///
    /// If `overwrite` is true, the contents in the range are supposed to be overwritten and may be
    /// discarded.  Otherwise, they are kept.
    pub async fn ensure_data_mapping(
        &self,
        offset: u64,
        length: u64,
        overwrite: bool,
    ) -> io::Result<(&S, u64, u64)> {
        let (storage, mapped_offset, mapped_length) = self
            .inner
            .ensure_data_mapping(offset, length, overwrite)
            .await?;
        let mapped_length = cmp::min(length, mapped_length);
        assert!(mapped_length > 0);
        Ok((storage, mapped_offset, mapped_length))
    }

    /// Read data at `offset` into `bufv`.
    ///
    /// Reads until `bufv` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `bufv` is filled with 0.
    pub async fn readv(&self, mut bufv: IoVectorMut<'_>, mut offset: u64) -> io::Result<()> {
        #[cfg(feature = "async")]
        let mut workers = (self.read_parallelization > 1).then(FuturesUnordered::new);

        while !bufv.is_empty() {
            let (mapping, chunk_length) = self.get_mapping(offset, bufv.len()).await?;
            if chunk_length == 0 {
                assert!(mapping.is_eof());
                bufv.fill(0);
                break;
            }

            #[cfg(feature = "async")]
            if let Some(workers) = workers.as_mut() {
                while workers.len() >= self.read_parallelization {
                    workers.next().await.unwrap()?;
                }
            }

            let (chunk, remainder) = bufv.split_at(chunk_length);
            bufv = remainder;
            offset += chunk_length;

            #[cfg(feature = "async")]
            if let Some(workers) = workers.as_mut() {
                workers.push(self.read_chunk(chunk, mapping));
            } else {
                self.read_chunk(chunk, mapping).await?;
            }
            #[cfg(feature = "sync")]
            self.read_chunk(chunk, mapping)?;
        }

        #[cfg(feature = "async")]
        if let Some(mut workers) = workers {
            while workers.next().await.transpose()?.is_some() {}
        }

        Ok(())
    }

    /// Read data at `offset` into `buf`.
    ///
    /// Reads until `buf` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `buf` is filled with 0.
    pub async fn read<'a>(
        &'a self,
        buf: impl Into<IoVectorMut<'a>>,
        offset: u64,
    ) -> io::Result<()> {
        self.readv(buf.into(), offset).await
    }

    /// Write data from `bufv` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub async fn writev(&self, mut bufv: IoVector<'_>, mut offset: u64) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::other("Image is read-only"));
        }

        // Limit to disk size
        let disk_size = self.inner.size();
        if offset >= disk_size {
            return Ok(());
        }
        if bufv.len() > disk_size - offset {
            bufv = bufv.split_at(disk_size - offset).0;
        }

        #[cfg(feature = "async")]
        let mut workers = (self.write_parallelization > 1).then(FuturesUnordered::new);

        while !bufv.is_empty() {
            let (storage, st_offset, st_length) =
                self.ensure_data_mapping(offset, bufv.len(), true).await?;

            #[cfg(feature = "async")]
            if let Some(workers) = workers.as_mut() {
                while workers.len() >= self.write_parallelization {
                    workers.next().await.unwrap()?;
                }
            }

            let (chunk, remainder) = bufv.split_at(st_length);
            bufv = remainder;
            offset += st_length;

            #[cfg(feature = "async")]
            if let Some(workers) = workers.as_mut() {
                workers.push(storage.writev(chunk, st_offset));
            } else {
                storage.writev(chunk, st_offset).await?;
            }
            #[cfg(feature = "sync")]
            storage.writev(chunk, st_offset)?;
        }

        #[cfg(feature = "async")]
        if let Some(mut workers) = workers {
            while workers.next().await.transpose()?.is_some() {}
        }

        Ok(())
    }

    /// Write data from `buf` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub async fn write<'a>(&'a self, buf: impl Into<IoVector<'a>>, offset: u64) -> io::Result<()> {
        self.writev(buf.into(), offset).await
    }

    /// Check whether the given range is zero.
    ///
    /// Checks for zero mappings, not zero data (although this might be changed in the future).
    ///
    /// Errors are treated as non-zero areas.
    async fn is_range_zero(&self, mut offset: u64, mut length: u64) -> bool {
        while length > 0 {
            match self.get_mapping(offset, length).await {
                Ok((Mapping::Zero { explicit: _ }, mlen)) => {
                    offset += mlen;
                    length -= mlen;
                }
                _ => return false,
            };
        }

        true
    }

    /// Ensure the given range reads as zeroes, without write-zeroes support.
    ///
    /// Does not require support for efficient zeroing, instead writing zeroes when the range is
    /// not zero yet.  If `allocate` is true, areas that are not currently allocated will be
    /// allocated to write zeroes there; if it is false, unallocated areas that currently read as
    /// zero are left alone.
    ///
    /// However, can still use efficient zero support if present.
    ///
    /// The main use case is to handle unaligned zero requests.  Quite inefficient for large areas.
    async fn soft_ensure_zero(&self, mut offset: u64, mut length: u64) -> io::Result<()> {
        // “Fast” path: Try to efficiently zero as much as possible
        if let Some(gran) = self.inner.zero_granularity() {
            let end = offset.checked_add(length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Write-zero wrap-around: {offset} + {length}"),
                )
            })?;
            let mut aligned_start = offset - offset % gran;
            // Could be handled, but don’t bother
            let mut aligned_end = end.checked_next_multiple_of(gran).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Write-zero wrap-around at cluster granularity",
                )
            })?;

            aligned_end = cmp::min(aligned_end, self.size());

            // Whether the whole area could be efficiently zeroed
            let mut fully_zeroed = true;

            if offset > aligned_start
                && !self
                    .is_range_zero(aligned_start, offset - aligned_start)
                    .await
            {
                // Non-zero head, we cannot zero that cluster.  Still try to zero as much as
                // possible.
                fully_zeroed = false;
                aligned_start += gran;
            }
            if end < aligned_end && !self.is_range_zero(end, aligned_end - end).await {
                // Non-zero tail, we cannot zero that cluster.  Still try to zero as much as
                // possible.
                fully_zeroed = false;
                aligned_end -= gran;
            }

            while aligned_start < aligned_end {
                let res = self
                    .inner
                    .ensure_zero_mapping(aligned_start, aligned_end - aligned_start)
                    .await;
                if let Ok((zofs, zlen)) = res {
                    if zofs != aligned_start || zlen == 0 {
                        // Produced a gap, so will need to fall back, but still try to zero as
                        // much as possible
                        fully_zeroed = false;
                        if zlen == 0 {
                            // Cannot go on
                            break;
                        }
                    }
                    aligned_start = zofs + zlen;
                } else {
                    // Ignore errors, just fall back
                    fully_zeroed = false;
                    break;
                }
            }

            if fully_zeroed {
                // Everything zeroed, no need to check
                return Ok(());
            }
        }

        // Slow path: Everything that is not zero in this layer is allocated as data and zeroes are
        // written.  The more we zeroed in the fast path, the quicker this will be.
        while length > 0 {
            let (mapping, mlen) = self.inner.get_mapping(offset, length).await?;
            let mlen = cmp::min(mlen, length);

            let mapping = match mapping {
                ShallowMapping::Raw {
                    storage,
                    offset,
                    writable,
                } => writable.then_some((storage, offset)),
                // For already zero clusters, we don’t need to do anything
                ShallowMapping::Zero { explicit: true } => {
                    // Nothing to be done
                    offset += mlen;
                    length -= mlen;
                    continue;
                }
                // For unallocated clusters, we should establish zero data
                ShallowMapping::Zero { explicit: false }
                | ShallowMapping::Indirect {
                    layer: _,
                    offset: _,
                    writable: _,
                } => None,
                ShallowMapping::Eof {} => {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                ShallowMapping::Special { offset: _ } => None,
            };

            let (file, mofs, mlen) = if let Some((file, mofs)) = mapping {
                (file, mofs, mlen)
            } else {
                self.ensure_data_mapping(offset, mlen, true).await?
            };

            write_full_zeroes(file, mofs, mlen).await?;
            offset += mlen;
            length -= mlen;
        }

        Ok(())
    }

    /// Ensure the given range reads as zeroes.
    ///
    /// May use efficient zeroing for a subset of the given range, if supported by the format.
    /// Will not discard anything, which keeps existing data mappings usable, albeit writing to
    /// mappings that are now zeroed may have no effect.
    ///
    /// Check if [`FormatAccess::discard_to_zero()`] better suits your needs: It may work better on
    /// a wider range of formats (`write_zeroes()` requires support for preallocated zero clusters,
    /// which qcow2 does have, but other formats may not), and can actually free up space.
    /// However, because it can break existing data mappings, it requires a mutable `self`
    /// reference.
    pub async fn write_zeroes(&self, mut offset: u64, length: u64) -> io::Result<()> {
        let max_offset = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Write-zeroes range overflow")
        })?;

        while offset < max_offset {
            let (zofs, zlen) = self
                .inner
                .ensure_zero_mapping(offset, max_offset - offset)
                .await?;
            if zlen == 0 {
                break;
            }
            // Fill up head, i.e. the range [offset, zofs)
            self.soft_ensure_zero(offset, zofs - offset).await?;
            offset = zofs + zlen;
        }

        // Fill up tail, i.e. the remaining range [offset, max_offset)
        self.soft_ensure_zero(offset, max_offset - offset).await?;
        Ok(())
    }

    /// Discard the given range, ensure it is read back as zeroes.
    ///
    /// Effectively the same as [`FormatAccess::write_zeroes()`], but discard as much of the
    /// existing allocation as possible.  This breaks existing data mappings, so needs a mutable
    /// reference to `self`, which ensures that existing data references (which have the lifetime
    /// of an immutable `self` reference) cannot be kept.
    ///
    /// Areas that cannot be discarded (because of format-inherent alignment restrictions) are
    /// still overwritten with zeroes, unless discarding is not supported altogether.
    pub async fn discard_to_zero(&mut self, offset: u64, length: u64) -> io::Result<()> {
        // Safe: `&mut self` guarantees nobody has concurrent data mappings
        unsafe { self.discard_to_zero_unsafe(offset, length).await }
    }

    /// Discard the given range, ensure it is read back as zeroes.
    ///
    /// Unsafe variant of [`FormatAccess::discard_to_zero()`], only requiring an immutable `&self`.
    ///
    /// # Safety
    ///
    /// This function may invalidate existing data mappings.  The caller must ensure to invalidate
    /// all concurrently existing data mappings they have.  Note that this includes concurrent
    /// accesses through this type ([`FormatAccess`]), which may hold these mappings internally
    /// while they run.
    ///
    /// One way to ensure safety is to have a mutable reference to `self`, which allows using the
    /// safe variant [`FormatAccess::discard_to_zero()`].
    pub async unsafe fn discard_to_zero_unsafe(
        &self,
        mut offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let max_offset = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Discard-to-zero range overflow",
            )
        })?;

        while offset < max_offset {
            // Safe: Caller guarantees this is safe
            let (zofs, zlen) = unsafe {
                self.inner
                    .discard_to_zero_unsafe(offset, max_offset - offset)
                    .await?
            };
            if zlen == 0 {
                break;
            }
            // Fill up head, i.e. the range [offset, zofs)
            self.soft_ensure_zero(offset, zofs - offset).await?;
            offset = zofs + zlen;
        }

        // Fill up tail, i.e. the remaining range [offset, max_offset)
        self.soft_ensure_zero(offset, max_offset - offset).await?;
        Ok(())
    }

    /// Discard the given range, not guaranteeing specific data on read-back.
    ///
    /// Discard as much of the given range as possible, and keep the rest as-is.  Does not
    /// guarantee any specific data on read-back, in contrast to
    /// [`FormatAccess::discard_to_zero()`].
    ///
    /// Discarding being unsupported by this format is still returned as an error
    /// ([`std::io::ErrorKind::Unsupported`])
    pub async fn discard_to_any(&mut self, offset: u64, length: u64) -> io::Result<()> {
        unsafe { self.discard_to_any_unsafe(offset, length).await }
    }

    /// Discard the given range, not guaranteeing specific data on read-back.
    ///
    /// Unsafe variant of [`FormatAccess::discard_to_any()`], only requiring an immutable `&self`.
    ///
    /// # Safety
    ///
    /// This function may invalidate existing data mappings.  The caller must ensure to invalidate
    /// all concurrently existing data mappings they have.  Note that this includes concurrent
    /// accesses through this type ([`FormatAccess`]), which may hold these mappings internally
    /// while they run.
    ///
    /// One way to ensure safety is to have a mutable reference to `self`, which allows using the
    /// safe variant [`FormatAccess::discard_to_any()`].
    pub async unsafe fn discard_to_any_unsafe(
        &self,
        mut offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let max_offset = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Discard-to-any range overflow")
        })?;

        while offset < max_offset {
            // Safe: Caller guarantees this is safe
            let (dofs, dlen) = unsafe {
                self.inner
                    .discard_to_any_unsafe(offset, max_offset - offset)
                    .await?
            };
            if dlen == 0 {
                break;
            }
            offset = dofs + dlen;
        }

        Ok(())
    }

    /// Discard the given range, such that the backing image becomes visible.
    ///
    /// Discard as much of the given range as possible so that a backing image’s data becomes
    /// visible, and keep the rest as-is.  This breaks existing data mappings, so needs a mutable
    /// reference to `self`, which ensures that existing data references (which have the lifetime
    /// of an immutable `self` reference) cannot be kept.
    pub async fn discard_to_backing(&mut self, offset: u64, length: u64) -> io::Result<()> {
        // Safe: `&mut self` guarantees nobody has concurrent data mappings
        unsafe { self.discard_to_backing_unsafe(offset, length).await }
    }

    /// Discard the given range, such that the backing image becomes visible.
    ///
    /// Unsafe variant of [`FormatAccess::discard_to_backing()`], only requiring an immutable
    /// `&self`.
    ///
    /// # Safety
    ///
    /// This function may invalidate existing data mappings.  The caller must ensure to invalidate
    /// all concurrently existing data mappings they have.  Note that this includes concurrent
    /// accesses through this type ([`FormatAccess`]), which may hold these mappings internally
    /// while they run.
    ///
    /// One way to ensure safety is to have a mutable reference to `self`, which allows using the
    /// safe variant [`FormatAccess::discard_to_backing()`].
    pub async unsafe fn discard_to_backing_unsafe(
        &self,
        mut offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let max_offset = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Discard-to-backing range overflow",
            )
        })?;

        while offset < max_offset {
            // Safe: Caller guarantees this is safe
            let (dofs, dlen) = unsafe {
                self.inner
                    .discard_to_backing_unsafe(offset, max_offset - offset)
                    .await?
            };
            if dlen == 0 {
                break;
            }
            offset = dofs + dlen;
        }

        Ok(())
    }

    /// Flush internal buffers.  Always call this before drop! (except in sync mode)
    ///
    /// Does not necessarily sync those buffers to disk.  When using `flush()`, consider whether
    /// you want to call `sync()` afterwards.
    ///
    /// In async mode, because of the current lack of stable `async_drop`, you must manually call
    /// this before dropping a `FormatAccess` instance!  (Not necessarily for read-only images,
    /// though.)  In sync mode, `Drop` calls this automatically.
    ///
    /// Note that this will not drop the buffers, so they may still be used to serve later
    /// accesses.  Use [`FormatAccess::invalidate_cache()`] to drop all buffers.
    pub async fn flush(&self) -> io::Result<()> {
        self.inner.flush().await
    }

    /// Sync data already written to the storage hardware.
    ///
    /// This does not necessarily include flushing internal buffers, i.e. `flush`.  When using
    /// `sync()`, consider whether you want to call `flush()` before it.
    pub async fn sync(&self) -> io::Result<()> {
        self.inner.sync().await
    }

    /// Drop internal buffers.
    ///
    /// This drops all internal buffers, but does not flush them!  All cached data is reloaded from
    /// disk on subsequent accesses.
    ///
    /// # Safety
    /// Not flushing internal buffers may cause image corruption.  You must ensure the on-disk
    /// state is consistent.
    pub async unsafe fn invalidate_cache(&self) -> io::Result<()> {
        // Safety ensured by caller
        unsafe { self.inner.invalidate_cache() }.await
    }

    /// Resize to the given size.
    ///
    /// Set the disk size to `new_size`.  If `new_size` is smaller than the current size, ignore
    /// both preallocation modes and discard the data after `new_size`.
    ///
    /// If `new_size` is larger than the current size, `prealloc_mode` determines whether and how
    /// the new range should be allocated; depending on the image format, is possible some
    /// preallocation modes are not supported, in which case an [`std::io::ErrorKind::Unsupported`]
    /// is returned.
    ///
    /// This may break existing data mappings, so needs a mutable reference to `self`, which
    /// ensures that existing data references (which have the lifetime of an immutable `self`
    /// reference) cannot be kept.
    ///
    /// See also [`FormatAccess::resize_grow()`] and [`FormatAccess::resize_shrink()`], whose more
    /// specialized interface may be useful when you know whether you want to grow or shrink the
    /// image.
    pub async fn resize(
        &mut self,
        new_size: u64,
        prealloc_mode: PreallocateMode,
    ) -> io::Result<()> {
        match new_size.cmp(&self.size()) {
            std::cmp::Ordering::Less => self.resize_shrink(new_size).await,
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Greater => self.resize_grow(new_size, prealloc_mode).await,
        }
    }

    /// Resize to the given size, which must be greater than the current size.
    ///
    /// Set the disk size to `new_size`, preallocating the new space according to `prealloc_mode`.
    /// Depending on the image format, it is possible some preallocation modes are not supported,
    /// in which case an [`std::io::ErrorKind::Unsupported`] is returned.
    ///
    /// If the current size is already `new_size` or greater, do nothing.
    pub async fn resize_grow(
        &self,
        new_size: u64,
        prealloc_mode: PreallocateMode,
    ) -> io::Result<()> {
        self.inner.resize_grow(new_size, prealloc_mode).await
    }

    /// Truncate to the given size, which must be smaller than the current size.
    ///
    /// Set the disk size to `new_size`, discarding the data after `new_size`.
    ///
    /// May break existing data mappings thanks to the mutable `self` reference.
    ///
    /// If the current size is already `new_size` or smaller, do nothing.
    pub async fn resize_shrink(&mut self, new_size: u64) -> io::Result<()> {
        self.inner.resize_shrink(new_size).await
    }
}

impl<S: Storage> Mapping<'_, S> {
    /// Return `true` if and only if this mapping signifies the end of file.
    pub fn is_eof(&self) -> bool {
        matches!(self, Mapping::Eof {})
    }
}

impl<S: Storage> Display for FormatAccess<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<S: Storage> Display for Mapping<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Mapping::Raw {
                storage,
                offset,
                writable,
            } => {
                let writable = if *writable { "rw" } else { "ro" };
                write!(f, "{storage}:0x{offset:x}/{writable}")
            }

            Mapping::Zero { explicit } => {
                let explicit = if *explicit { "explicit" } else { "unallocated" };
                write!(f, "<zero:{explicit}>")
            }

            Mapping::Eof {} => write!(f, "<eof>"),

            Mapping::Special { layer, offset } => {
                write!(f, "<special:{layer}:0x{offset:x}>")
            }
        }
    }
}

#[cfg(feature = "sync")]
impl<S: Storage> Drop for FormatAccess<S> {
    fn drop(&mut self) {
        if let Err(err) = self.flush() {
            let inner = &self.inner;
            tracing::error!("Failed to flush {inner}: {err}");
        }
    }
}

/*
#[cfg(feature = "async-drop")]
impl<S: Storage> std::future::AsyncDrop for FormatAccess<S> {
    type Dropper<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> where S: 'a;

    fn async_drop(self: std::pin::Pin<&mut Self>) -> Self::Dropper<'_> {
        Box::pin(async move {
            if let Err(err) = self.flush().await {
                let inner = &self.inner;
                tracing::error!("Failed to flush {inner}: {err}");
            }
        })
    }
}
*/
