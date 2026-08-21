//! Internal image format driver interface.
//!
//! Provides the internal interface for image format drivers to provide their services, on which
//! the publically visible interface [`FormatAccess`] is built.

use super::{Format, PreallocateMode};
use crate::io_buffers::IoVectorMut;
use crate::{FormatAccess, Storage};
use maybe_async::maybe_async;
use std::any::Any;
use std::fmt::{Debug, Display};
use std::io;

/// Implementation of a disk image format.
#[maybe_async(?Send)]
pub trait FormatDriverInstance: Any + Debug + Display + Send + Sync {
    /// Type of storage used.
    type Storage: Storage;

    /// Return which format this is.
    fn format(&self) -> Format;

    /// Check whether `storage` has this format.
    ///
    /// This is only a rough test and does not guarantee that opening `storage` under this format
    /// will succeed.  Generally, it will only check the magic bytes (if available).  For formats
    /// that do not have distinct features (like raw), this will always return `true`.
    ///
    /// # Safety
    /// Probing is inherently dangerous: Image formats like qcow2 allow referencing external files;
    /// if you use imago to give untrusted parties (like VM guests) access to VM disk image files,
    /// this will give those parties access to data in those files.  Opening images from untrusted
    /// sources can therefore be quite dangerous.  Gating
    /// ([`ImplicitOpenGate`](super::gate::ImplicitOpenGate)) can help mitigate this.
    ///
    /// If you do not know an image’s format, that is a sign it does not come from a trusted
    /// source, and so opening it in a non-raw format may be quite dangerous.
    ///
    /// Perhaps most important to note is that giving an untrusted party (like a VM guest) access
    /// to a raw image file allows that party to modify the whole file.  It may write image headers
    /// into this image file, causing a subsequent probe operation to recognize it as a non-raw
    /// image, referencing arbitrary files on the host filesystem!
    ///
    /// When using imago to give an untrusted third party access to VM disk images, the guidelines
    /// for probing are thus:
    /// - Do not probe.  If at all possible, obtain an image’s format from a trusted side channel.
    /// - If there is no other way, probe each given image only once, before that untrusted third
    ///   party (like a VM guest) had write access to it; remember the probed format, and open the
    ///   image exclusively as that format.
    ///
    /// When working with even potentially untrusted images, you should always use an
    /// [`ImplicitOpenGate`](super::gate::ImplicitOpenGate) to prevent access to files you do not
    /// wish to access.
    async unsafe fn probe(storage: &Self::Storage) -> io::Result<bool>
    where
        Self: Sized;

    /// Size of the disk represented by this image.
    fn size(&self) -> u64;

    /// Granularity on which blocks can be marked as zero.
    ///
    /// This is the granularity for [`FormatDriverInstance::ensure_zero_mapping()`].
    ///
    /// Return `None` if zero blocks are not supported.
    fn zero_granularity(&self) -> Option<u64> {
        None
    }

    /// Recursively collect all storage objects associated with this image.
    ///
    /// “Recursive” means to recurse to other images like e.g. a backing file.
    fn collect_storage_dependencies(&self) -> Vec<&Self::Storage>;

    /// Return whether this image may be modified.
    ///
    /// This state must not change via interior mutability, i.e. as long as this FDI is wrapped in
    /// a `FormatAccess`, its writability must remain constant.
    fn writable(&self) -> bool;

    /// Return the mapping at `offset`.
    ///
    /// Find what `offset` is mapped to, return that mapping information, and the length of that
    /// continuous mapping (from `offset`).
    ///
    /// To determine that continuous mapping length, drivers should not perform additional I/O
    /// beyond what is necessary to get mapping information for `offset` itself.
    ///
    /// `max_length` is a hint how long of a range is required at all, but the returned length may
    /// exceed that value if that simplifies the implementation.
    ///
    /// The returned length must only be 0 if `ShallowMapping::Eof` is returned.
    #[allow(clippy::needless_lifetimes)] // Elidable in sync, but async needs a named lifetime for the boxed future bound
    async fn get_mapping<'a>(
        &'a self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(ShallowMapping<'a, Self::Storage>, u64)>;

    /// Ensure that `offset` is directly mapped to some storage object, up to a length of `length`.
    ///
    /// Return the storage object, the corresponding offset there, and the continuous length that
    /// the driver was able to map (less than or equal to `length`).
    ///
    /// If the returned length is less than `length`, drivers can expect subsequent calls to
    /// allocate the rest of the original range.  Therefore, if a driver knows in advance that it
    /// is impossible to fully map the given range (e.g. because it lies partially or fully beyond
    /// the end of the disk), it should return an error immediately.
    ///
    /// If `overwrite` is true, the contents in the range are supposed to be overwritten and may be
    /// discarded.  Otherwise, they must be kept.
    ///
    /// Should not break existing data mappings, i.e. not discard or repurpose existing data
    /// mappings.  Making them unused, but retaining them as allocated so they can safely be
    /// written to (albeit with no effect) is OK; discarding them so that they may be reused for
    /// other mappings is not.
    #[allow(clippy::needless_lifetimes)] // Elidable in sync, but async needs a named lifetime for the boxed future bound
    async fn ensure_data_mapping<'a>(
        &'a self,
        offset: u64,
        length: u64,
        overwrite: bool,
    ) -> io::Result<(&'a Self::Storage, u64, u64)>;

    /// Ensure that the given range is efficiently mapped as zeroes.
    ///
    /// Must not write any data.  Return the range (offset and length) that could actually be
    /// zeroed, which must be a subset of the range given by `offset` and `length`.  The returned
    /// offset must be as close to `offset` as possible, i.e. no zero mapping is possible between
    /// `offset` and the returned offset (e.g. because of format-inherent granularity).
    ///
    /// The returned length may be zero in case zeroing would theoretically be possible, but not
    /// for this range at this granularity.
    ///
    /// Should not break existing data mappings, i.e. not discard or repurpose existing data
    /// mappings.  Making them unused, but retaining them as allocated so they can safely be
    /// written to (albeit with no effect) is OK; discarding them so that they may be reused for
    /// other mappings is not.
    async fn ensure_zero_mapping(&self, _offset: u64, _length: u64) -> io::Result<(u64, u64)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Discard the given range, ensure it is read back as zeroes.
    ///
    /// Effectively the same as [`FormatDriverInstance::ensure_zero_mapping()`], but may break
    /// existing data mappings thanks to the mutable `self` reference, which ensures that old data
    /// mappings returned by [`FormatDriverInstance::get_mapping()`] cannot be held onto.
    async fn discard_to_zero(&mut self, offset: u64, length: u64) -> io::Result<(u64, u64)> {
        // Safe: `&mut self` guarantees nobody has concurrent data mappings
        unsafe { self.discard_to_zero_unsafe(offset, length).await }
    }

    /// Discard the given range, ensure it is read back as zeroes.
    ///
    /// Unsafe variant of [FormatDriverInstance::discard_to_zero()], only requiring an immutable
    /// &self
    ///
    /// # Safety
    /// This function is marked as unsafe because:
    /// - It may invalidate all existing data mappings.
    ///
    /// The caller must ensure that no other references to this driver instance exist and that
    /// the caller must ensure that all previously looked up mappings are no longer assumed to
    /// be valid after this operation.
    ///
    /// Because mappings contain references to the block driver instance, one way to do so is
    /// to have a mutable reference to the block driver instance, which will automatically
    /// ensure there are no other references (and thus no mappings).  In that case, you can use
    /// the safe variant [`Self::discard_to_zero()`].
    async unsafe fn discard_to_zero_unsafe(
        &self,
        _offset: u64,
        _length: u64,
    ) -> io::Result<(u64, u64)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Discard the given range.
    ///
    /// Effectively the same as [`FormatDriverInstance::discard_to_zero()`], but the discarded area
    /// may read as any data.  Backing file data should not reappear, however.
    async fn discard_to_any(&mut self, offset: u64, length: u64) -> io::Result<(u64, u64)> {
        // Safe: `&mut self` guarantees nobody has concurrent data mappings
        unsafe { self.discard_to_any_unsafe(offset, length).await }
    }

    /// Discard the given range.
    ///
    /// Unsafe variant of [FormatDriverInstance::discard_to_any()], only requiring an immutable
    /// &self
    ///
    /// # Safety
    /// This function is marked as unsafe because:
    /// - It may invalidate all existing data mappings.
    ///
    /// The caller must ensure that no other references to this driver instance exist and that
    /// the caller must ensure that all previously looked up mappings are no longer assumed to
    /// be valid after this operation.
    ///
    /// Because mappings contain references to the block driver instance, one way to do so is
    /// to have a mutable reference to the block driver instance, which will automatically
    /// ensure there are no other references (and thus no mappings).  In that case, you can use
    /// the safe variant [`Self::discard_to_any()`].
    async unsafe fn discard_to_any_unsafe(
        &self,
        _offset: u64,
        _length: u64,
    ) -> io::Result<(u64, u64)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Discard the given range, such that the backing image becomes visible.
    ///
    /// Deallocate the range such that in deallocated blocks, the backing image’s data (if one
    /// exists) will show, i.e. [`FormatDriverInstance::get_mapping()`] should return an indirect
    /// mapping.  When there is no backing image, those blocks should appear as zero.
    ///
    /// Return the range (offset and length) that could actually be discarded, which must be a
    /// subset of `offset` and `length`, and the returned offset must be as close to `offset` as
    /// possible (like for [`FormatDriverInstance::discard_to_backing()`].
    ///
    /// May break existing data mappings thanks to the mutable `self` reference.
    async fn discard_to_backing(&mut self, offset: u64, length: u64) -> io::Result<(u64, u64)> {
        // Safe: `&mut self` guarantees nobody has concurrent data mappings
        unsafe { self.discard_to_backing_unsafe(offset, length).await }
    }

    /// Discard the given range, such that the backing image becomes visible.
    ///
    /// Unsafe variant of [FormatDriverInstance::discard_to_backing()], only requiring an immutable
    /// &self
    ///
    /// # Safety
    /// This function is marked as unsafe because:
    /// - It may invalidate all existing data mappings.
    ///
    /// The caller must ensure that no other references to this driver instance exist and that
    /// the caller must ensure that all previously looked up mappings are no longer assumed to
    /// be valid after this operation.
    ///
    /// Because mappings contain references to the block driver instance, one way to do so is
    /// to have a mutable reference to the block driver instance, which will automatically
    /// ensure there are no other references (and thus no mappings).  In that case, you can use
    /// the safe variant [`Self::discard_to_backing()`].
    async unsafe fn discard_to_backing_unsafe(
        &self,
        _offset: u64,
        _length: u64,
    ) -> io::Result<(u64, u64)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Read data from a `ShallowMapping::Special` area.
    async fn readv_special(&self, _bufv: IoVectorMut<'_>, _offset: u64) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Flush internal buffers.
    ///
    /// Does not need to ensure those buffers are synced to disk (hardware), and does not need to
    /// drop them, i.e. they may still be used on later accesses.
    async fn flush(&self) -> io::Result<()>;

    /// Sync data already written to the storage hardware.
    ///
    /// Does not need to ensure internal buffers are written, i.e. should generally just be passed
    /// through to `Storage::sync()` for all underlying storage objects.
    async fn sync(&self) -> io::Result<()>;

    /// Drop internal buffers.
    ///
    /// Drop all internal buffers, but do not flush them!  All internal data must then be reloaded
    /// from disk.
    ///
    /// # Safety
    /// Not flushing internal buffers may cause image corruption.  The caller must ensure the
    /// on-disk state is consistent.
    async unsafe fn invalidate_cache(&self) -> io::Result<()>;

    /// Resize to the given size, which must be greater than the current size.
    ///
    /// Set the disk size to `new_size`, preallocating the new space according to `prealloc_mode`.
    /// Depending on the image format, it is possible some preallocation modes are not supported,
    /// in which case an [`std::io::ErrorKind::Unsupported`] is returned.
    ///
    /// If the current size is already `new_size` or greater, do nothing.
    async fn resize_grow(&self, new_size: u64, prealloc_mode: PreallocateMode) -> io::Result<()>;

    /// Truncate to the given size, which must be smaller than the current size.
    ///
    /// Set the disk size to `new_size`, discarding the data after `new_size`.
    ///
    /// May break existing data mappings thanks to the mutable `self` reference.
    ///
    /// If the current size is already `new_size` or smaller, do nothing.
    async fn resize_shrink(&mut self, new_size: u64) -> io::Result<()>;
}

/// Non-recursive mapping information.
///
/// Mapping information as returned by [`FormatDriverInstance::get_mapping()`], only looking at
/// that format layer’s information.
#[derive(Debug)]
#[non_exhaustive]
pub enum ShallowMapping<'a, S: Storage + 'static> {
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

    /// Data lives in a different disk image (e.g. a backing file).
    #[non_exhaustive]
    Indirect {
        /// Format instance where this data can be obtained.
        layer: &'a FormatAccess<S>,

        /// Offset in `layer` where this data can be obtained.
        offset: u64,

        /// Whether this mapping may be written to.
        ///
        /// If `true`, you can directly write to `offset` on `layer` to change the disk image’s
        /// data accordingly.
        ///
        /// If `false`, the disk image format does not allow writing to `offset` on `layer`; a new
        /// mapping must be allocated first.
        writable: bool,
    },

    /// Range is to be read as zeroes.
    #[non_exhaustive]
    Zero {
        /// Whether these zeroes are explicit on this layer.
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
        /// [`ShallowMapping::Zero`] with `explicit` set to false.
        ///
        /// Formats like qcow2 can track more information beyond just the allocation status,
        /// though, for example, whether a block should read as zero. Such blocks similarly do not
        /// need to have their data stored in the image file, but are still not treated as
        /// unallocated, so will never be read from a backing image, regardless of whether one
        /// exists or not.
        ///
        /// These ranges are noted as [`ShallowMapping::Zero`] with `explicit` set to true.
        explicit: bool,
    },

    /// End of file reached.
    #[non_exhaustive]
    Eof {},

    /// Data is encoded in some manner, e.g. compressed or encrypted.
    ///
    /// Such data cannot be accessed directly, but must be interpreted by the image format driver.
    #[non_exhaustive]
    Special {
        /// Original (“guest”) offset to pass to `FormatDriverInstance::readv_special()`.
        offset: u64,
    },
}
