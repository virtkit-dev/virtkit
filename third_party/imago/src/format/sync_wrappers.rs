//! Synchronous wrapper around [`FormatAccess`].

use super::drivers::FormatDriverInstance;
use super::PreallocateMode;
use crate::io_buffers::{IoVector, IoVectorMut};
use crate::{FormatAccess, Mapping, Storage};
use std::io;

/// Synchronous wrapper around [`FormatAccess`].
///
/// Creates and keeps a tokio runtime in which to run I/O.
pub struct SyncFormatAccess<S: Storage + 'static> {
    /// Wrapped asynchronous [`FormatAccess`].
    inner: FormatAccess<S>,

    /// Tokio runtime in which I/O is run.
    runtime: tokio::runtime::Runtime,
}

impl<S: Storage + 'static> SyncFormatAccess<S> {
    /// Like [`FormatAccess::new()`], but create a synchronous wrapper.
    pub fn new<D: FormatDriverInstance<Storage = S> + 'static>(inner: D) -> io::Result<Self> {
        FormatAccess::new(inner).try_into()
    }

    /// Get a reference to the contained async [`FormatAccess`] object.
    pub fn inner(&self) -> &FormatAccess<S> {
        &self.inner
    }

    /// Return the disk size in bytes.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Set the number of simultaneous async requests per read.
    ///
    /// When issuing read requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    ///
    /// Note that inside of this synchronous wrapper, we still run async functions, so this setting
    /// is valid even for [`SyncFormatAccess`].
    pub fn set_async_read_parallelization(&mut self, count: usize) {
        self.inner.set_async_read_parallelization(count)
    }

    /// Set the number of simultaneous async requests per write.
    ///
    /// When issuing write requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    ///
    /// Note that inside of this synchronous wrapper, we still run async functions, so this setting
    /// is valid even for [`SyncFormatAccess`].
    pub fn set_async_write_parallelization(&mut self, count: usize) {
        self.inner.set_async_write_parallelization(count)
    }

    /// Minimal I/O alignment, for both length and offset.
    ///
    /// All requests to this image should be aligned to this value, both in length and offset.
    ///
    /// Requests that do not match this alignment will be realigned internally, which requires
    /// creating bounce buffers and read-modify-write cycles for write requests, which is costly,
    /// so should be avoided.
    pub fn req_align(&self) -> usize {
        self.inner.req_align()
    }

    /// Minimal memory buffer alignment, for both address and length.
    ///
    /// All buffers used in requests to this image should be aligned to this value, both their
    /// address and length.
    ///
    /// Request buffers that do not match this alignment will be realigned internally, which
    /// requires creating bounce buffers, which is costly, so should be avoided.
    pub fn mem_align(&self) -> usize {
        self.inner.mem_align()
    }

    /// Return the mapping at `offset`.
    ///
    /// Find what `offset` is mapped to, return that mapping information, and the length of that
    /// continuous mapping (from `offset`).
    pub fn get_mapping_sync(
        &self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(Mapping<'_, S>, u64)> {
        self.runtime
            .block_on(self.inner.get_mapping(offset, max_length))
    }

    /// Create a raw data mapping at `offset`.
    ///
    /// Ensure that `offset` is directly mapped to some storage object, up to a length of `length`.
    /// Return the storage object, the corresponding offset there, and the continuous length that
    /// we were able to map (less than or equal to `length`).
    ///
    /// If `overwrite` is true, the contents in the range are supposed to be overwritten and may be
    /// discarded.  Otherwise, they are kept.
    pub fn ensure_data_mapping(
        &self,
        offset: u64,
        length: u64,
        overwrite: bool,
    ) -> io::Result<(&S, u64, u64)> {
        self.runtime
            .block_on(self.inner.ensure_data_mapping(offset, length, overwrite))
    }

    /// Read data at `offset` into `bufv`.
    ///
    /// Reads until `bufv` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `bufv` is filled with 0.
    pub fn readv(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        self.runtime.block_on(self.inner.readv(bufv, offset))
    }

    /// Read data at `offset` into `buf`.
    ///
    /// Reads until `buf` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `buf` is filled with 0.
    pub fn read<'a>(&'a self, buf: impl Into<IoVectorMut<'a>>, offset: u64) -> io::Result<()> {
        self.readv(buf.into(), offset)
    }

    /// Write data from `bufv` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub fn writev(&self, bufv: IoVector<'_>, offset: u64) -> io::Result<()> {
        self.runtime.block_on(self.inner.writev(bufv, offset))
    }

    /// Write data from `buf` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub fn write<'a>(&'a self, buf: impl Into<IoVector<'a>>, offset: u64) -> io::Result<()> {
        self.writev(buf.into(), offset)
    }

    /// Ensure the given range reads as zeroes.
    ///
    /// May use efficient zeroing for a subset of the given range, if supported by the format.
    /// Will not discard anything, which keeps existing data mappings usable, albeit writing to
    /// mappings that are now zeroed may have no effect.
    ///
    /// Check if [`SyncFormatAccess::discard_to_zero()`] better suits your needs: It may work
    /// better on a wider range of formats (`write_zeroes()` requires support for preallocated zero
    /// clusters, which qcow2 does have, but other formats may not), and can actually free up
    /// space.  However, because it can break existing data mappings, it requires a mutable `self`
    /// reference.
    pub fn write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        self.runtime
            .block_on(self.inner.write_zeroes(offset, length))
    }

    /// Discard the given range, ensure it is read back as zeroes.
    ///
    /// Effectively the same as [`SyncFormatAccess::write_zeroes()`], but discard as much of the
    /// existing allocation as possible.  This breaks existing data mappings, so needs a mutable
    /// reference to `self`, which ensures that existing data references (which have the lifetime
    /// of an immutable `self` reference) cannot be kept.
    ///
    /// Areas that cannot be discarded (because of format-inherent alignment restrictions) are
    /// still overwritten with zeroes, unless discarding is not supported altogether.
    pub fn discard_to_zero(&mut self, offset: u64, length: u64) -> io::Result<()> {
        self.runtime
            .block_on(self.inner.discard_to_zero(offset, length))
    }

    /// Discard the given range, ensure it is read back as zeroes.
    ///
    /// Unsafe variant of [`SyncFormatAccess::discard_to_zero()`], only requiring an immutable
    /// `&self`.
    ///
    /// # Safety
    ///
    /// This function may invalidate existing data mappings.  The caller must ensure to invalidate
    /// all concurrently existing data mappings they have.  Note that this includes concurrent
    /// accesses through this type ([`SyncFormatAccess`]), which may hold these mappings internally
    /// while they run.
    ///
    /// One way to ensure safety is to have a mutable reference to `self`, which allows using the
    /// safe variant [`SyncFormatAccess::discard_to_zero()`].
    pub unsafe fn discard_to_zero_unsafe(&self, offset: u64, length: u64) -> io::Result<()> {
        // Safe: Caller guarantees this is safe
        self.runtime
            .block_on(unsafe { self.inner.discard_to_zero_unsafe(offset, length) })
    }

    /// Discard the given range, not guaranteeing specific data on read-back.
    ///
    /// Discard as much of the given range as possible, and keep the rest as-is.  Does not
    /// guarantee any specific data on read-back, in contrast to
    /// [`SyncFormatAccess::discard_to_zero()`].
    ///
    /// Discarding being unsupported by this format is still returned as an error
    /// ([`std::io::ErrorKind::Unsupported`])
    pub fn discard_to_any(&mut self, offset: u64, length: u64) -> io::Result<()> {
        self.runtime
            .block_on(self.inner.discard_to_any(offset, length))
    }

    /// Discard the given range, not guaranteeing specific data on read-back.
    ///
    /// Unsafe variant of [`SyncFormatAccess::discard_to_any()`], only requiring an immutable
    /// `&self`.
    ///
    /// # Safety
    ///
    /// This function may invalidate existing data mappings.  The caller must ensure to invalidate
    /// all concurrently existing data mappings they have.  Note that this includes concurrent
    /// accesses through this type ([`SyncFormatAccess`]), which may hold these mappings internally
    /// while they run.
    ///
    /// One way to ensure safety is to have a mutable reference to `self`, which allows using the
    /// safe variant [`SyncFormatAccess::discard_to_any()`].
    pub unsafe fn discard_to_any_unsafe(&self, offset: u64, length: u64) -> io::Result<()> {
        // Safe: Caller guarantees this is safe
        self.runtime
            .block_on(unsafe { self.inner.discard_to_any_unsafe(offset, length) })
    }

    /// Discard the given range, such that the backing image becomes visible.
    ///
    /// Discard as much of the given range as possible so that a backing image’s data becomes
    /// visible, and keep the rest as-is.  This breaks existing data mappings, so needs a mutable
    /// reference to `self`, which ensures that existing data references (which have the lifetime
    /// of an immutable `self` reference) cannot be kept.
    pub fn discard_to_backing(&mut self, offset: u64, length: u64) -> io::Result<()> {
        self.runtime
            .block_on(self.inner.discard_to_backing(offset, length))
    }

    /// Discard the given range, such that the backing image becomes visible.
    ///
    /// Unsafe variant of [`SyncFormatAccess::discard_to_backing()`], only requiring an immutable
    /// `&self`.
    ///
    /// # Safety
    ///
    /// This function may invalidate existing data mappings.  The caller must ensure to invalidate
    /// all concurrently existing data mappings they have.  Note that this includes concurrent
    /// accesses through this type ([`SyncFormatAccess`]), which may hold these mappings internally
    /// while they run.
    ///
    /// One way to ensure safety is to have a mutable reference to `self`, which allows using the
    /// safe variant [`SyncFormatAccess::discard_to_backing()`].
    pub unsafe fn discard_to_backing_unsafe(&self, offset: u64, length: u64) -> io::Result<()> {
        // Safe: Caller guarantees this is safe
        self.runtime
            .block_on(unsafe { self.inner.discard_to_backing_unsafe(offset, length) })
    }

    /// Flush internal buffers.
    ///
    /// Does not necessarily sync those buffers to disk.  When using `flush()`, consider whether
    /// you want to call `sync()` afterwards.
    ///
    /// Note that this will not drop the buffers, so they may still be used to serve later
    /// accesses.  Use [`SyncFormatAccess::invalidate_cache()`] to drop all buffers.
    pub fn flush(&self) -> io::Result<()> {
        self.runtime.block_on(self.inner.flush())
    }

    /// Sync data already written to the storage hardware.
    ///
    /// This does not necessarily include flushing internal buffers, i.e. `flush`.  When using
    /// `sync()`, consider whether you want to call `flush()` before it.
    pub fn sync(&self) -> io::Result<()> {
        self.runtime.block_on(self.inner.sync())
    }

    /// Drop internal buffers.
    ///
    /// This drops all internal buffers, but does not flush them!  All cached data is reloaded from
    /// disk on subsequent accesses.
    ///
    /// # Safety
    /// Not flushing internal buffers may cause image corruption.  You must ensure the on-disk
    /// state is consistent.
    pub unsafe fn invalidate_cache(&self) -> io::Result<()> {
        // Safety ensured by caller
        self.runtime
            .block_on(unsafe { self.inner.invalidate_cache() })
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
    /// See also [`SyncFormatAccess::resize_grow()`] and [`SyncFormatAccess::resize_shrink()`],
    /// whose more specialized interface may be useful when you know whether you want to grow or
    /// shrink the image.
    pub fn resize(&mut self, new_size: u64, prealloc_mode: PreallocateMode) -> io::Result<()> {
        self.runtime
            .block_on(self.inner.resize(new_size, prealloc_mode))
    }

    /// Resize to the given size, which must be greater than the current size.
    ///
    /// Set the disk size to `new_size`, preallocating the new space according to `prealloc_mode`.
    /// Depending on the image format, it is possible some preallocation modes are not supported,
    /// in which case an [`std::io::ErrorKind::Unsupported`] is returned.
    pub fn resize_grow(&self, new_size: u64, prealloc_mode: PreallocateMode) -> io::Result<()> {
        self.runtime
            .block_on(self.inner.resize_grow(new_size, prealloc_mode))
    }

    /// Truncate to the given size, which must be smaller than the current size.
    ///
    /// Set the disk size to `new_size`, discarding the data after `new_size`.
    ///
    /// May break existing data mappings thanks to the mutable `self` reference.
    pub fn resize_shrink(&mut self, new_size: u64) -> io::Result<()> {
        self.runtime.block_on(self.inner.resize_shrink(new_size))
    }
}

impl<S: Storage> TryFrom<FormatAccess<S>> for SyncFormatAccess<S> {
    type Error = io::Error;

    fn try_from(async_access: FormatAccess<S>) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|err| {
                io::Error::other(format!(
                    "Failed to create a tokio runtime for synchronous image access: {err}"
                ))
            })?;

        Ok(SyncFormatAccess {
            inner: async_access,
            runtime,
        })
    }
}

// #[cfg(not(feature = "async-drop"))]
impl<S: Storage> Drop for SyncFormatAccess<S> {
    fn drop(&mut self) {
        if let Err(err) = self.flush() {
            let inner = &self.inner;
            tracing::error!("Failed to flush {inner}: {err}");
        }
    }
}
