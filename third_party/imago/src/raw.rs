//! Access generic files as images.
//!
//! Allows accessing generic storage objects (`Storage`) as images (i.e. `FormatAccess`).

use crate::format::builder::{
    FormatCreateBuilder, FormatCreateBuilderBase, FormatDriverBuilder, FormatDriverBuilderBase,
};
use crate::format::drivers::FormatDriverInstance;
use crate::format::gate::ImplicitOpenGate;
use crate::format::{Format, PreallocateMode};
use crate::{
    storage, DenyImplicitOpenGate, ShallowMapping, Storage, StorageExt, StorageOpenOptions,
};
use maybe_async::maybe_async;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Wraps a storage object without any translation.
#[derive(Debug)]
pub struct Raw<S: Storage + 'static> {
    /// Wrapped storage object.
    inner: S,

    /// Whether this image may be modified.
    writable: bool,

    /// Disk size, which is the file size when this object was created.
    size: AtomicU64,
}

#[maybe_async]
impl<S: Storage + 'static> Raw<S> {
    /// Create a new [`FormatDriverBuilder`] instance for the given image.
    pub fn builder(image: S) -> RawOpenBuilder<S> {
        RawOpenBuilder::new(image)
    }

    /// Create a new [`FormatDriverBuilder`] instance for an image under the given path.
    pub fn builder_path<P: AsRef<Path>>(image_path: P) -> RawOpenBuilder<S> {
        RawOpenBuilder::new_path(image_path)
    }

    /// Create a new [`FormatCreateBuilder`] instance for the given file.
    pub fn create_builder(image: S) -> RawCreateBuilder<S> {
        RawCreateBuilder::new(image)
    }

    /// Wrap `inner`, allowing it to be used as a disk image in raw format.
    pub async fn open_image(inner: S, writable: bool) -> io::Result<Self> {
        let size = inner.size()?;
        Ok(Raw {
            inner,
            writable,
            size: size.into(),
        })
    }

    /// Open the given path as a storage object, and wrap it in `Raw`.
    pub async fn open_path<P: AsRef<Path>>(path: P, writable: bool) -> io::Result<Self> {
        let storage_opts = StorageOpenOptions::new().write(writable).filename(path);
        let inner = S::open(storage_opts).await?;
        Self::open_image(inner, writable).await
    }

    /// Wrap `inner`, allowing it to be used as a disk image in raw format.
    #[cfg(feature = "sync-wrappers")]
    pub fn open_image_sync(inner: S, writable: bool) -> io::Result<Self> {
        let size = inner.size()?;
        Ok(Raw {
            inner,
            writable,
            size: size.into(),
        })
    }

    #[cfg(feature = "sync-wrappers")]
    /// Synchronous wrapper around [`Raw::open_path()`].
    pub fn open_path_sync<P: AsRef<Path>>(path: P, writable: bool) -> io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(Self::open_path(path, writable))
    }
}

#[maybe_async(?Send)]
impl<S: Storage + 'static> FormatDriverInstance for Raw<S> {
    type Storage = S;

    fn format(&self) -> Format {
        Format::Raw
    }

    async unsafe fn probe(_storage: &S) -> io::Result<bool>
    where
        Self: Sized,
    {
        Ok(true)
    }

    fn size(&self) -> u64 {
        self.size.load(Ordering::Relaxed)
    }

    fn zero_granularity(&self) -> Option<u64> {
        None
    }

    fn collect_storage_dependencies(&self) -> Vec<&S> {
        vec![&self.inner]
    }

    fn writable(&self) -> bool {
        self.writable
    }

    #[allow(clippy::needless_lifetimes)] // Elidable in sync, but async needs a named lifetime for the boxed future bound
    async fn get_mapping<'a>(
        &'a self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(ShallowMapping<'a, S>, u64)> {
        let remaining = match self.size().checked_sub(offset) {
            None | Some(0) => return Ok((ShallowMapping::Eof {}, 0)),
            Some(remaining) => remaining,
        };

        Ok((
            ShallowMapping::Raw {
                storage: &self.inner,
                offset,
                writable: true,
            },
            std::cmp::min(max_length, remaining),
        ))
    }

    #[allow(clippy::needless_lifetimes)] // Elidable in sync, but async needs a named lifetime for the boxed future bound
    async fn ensure_data_mapping<'a>(
        &'a self,
        offset: u64,
        length: u64,
        _overwrite: bool,
    ) -> io::Result<(&'a S, u64, u64)> {
        let Some(remaining) = self.size().checked_sub(offset) else {
            return Err(io::Error::other("Cannot allocate past the end of file"));
        };
        if length > remaining {
            return Err(io::Error::other("Cannot allocate past the end of file"));
        }

        Ok((&self.inner, offset, length))
    }

    async fn ensure_zero_mapping(&self, offset: u64, length: u64) -> io::Result<(u64, u64)> {
        let zero_align = self.inner.zero_align();
        assert!(zero_align.is_power_of_two());

        let zero_align_mask = zero_align as u64 - 1;

        let aligned_end = (offset + length) & !zero_align_mask;
        let aligned_offset = (offset + zero_align_mask) & !zero_align_mask;
        let aligned_length = aligned_end.saturating_sub(aligned_offset);
        if aligned_length == 0 {
            return Ok((aligned_offset, 0));
        }

        // FIXME: Introduce request flags, and request no fallback
        self.inner
            .write_zeroes(aligned_offset, aligned_length)
            .await?;
        Ok((aligned_offset, aligned_length))
    }

    async unsafe fn discard_to_zero_unsafe(
        &self,
        offset: u64,
        length: u64,
    ) -> io::Result<(u64, u64)> {
        self.ensure_zero_mapping(offset, length).await
    }

    async unsafe fn discard_to_any_unsafe(
        &self,
        offset: u64,
        length: u64,
    ) -> io::Result<(u64, u64)> {
        let discard_align = self.inner.discard_align();
        assert!(discard_align.is_power_of_two());

        let discard_align_mask = discard_align as u64 - 1;

        let aligned_end = (offset + length) & !discard_align_mask;
        let aligned_offset = (offset + discard_align_mask) & !discard_align_mask;
        let aligned_length = aligned_end.saturating_sub(aligned_offset);
        if aligned_length == 0 {
            return Ok((aligned_offset, 0));
        }

        self.inner.discard(aligned_offset, aligned_length).await?;
        Ok((aligned_offset, aligned_length))
    }

    async unsafe fn discard_to_backing_unsafe(
        &self,
        offset: u64,
        length: u64,
    ) -> io::Result<(u64, u64)> {
        unsafe { self.discard_to_zero_unsafe(offset, length).await }
    }

    async fn flush(&self) -> io::Result<()> {
        // No internal buffers to flush
        self.inner.flush().await
    }

    async fn sync(&self) -> io::Result<()> {
        self.inner.sync().await
    }

    async unsafe fn invalidate_cache(&self) -> io::Result<()> {
        // No internal buffers to drop
        // Safe: Caller says we should do this
        unsafe { self.inner.invalidate_cache() }.await
    }

    async fn resize_grow(
        &self,
        new_size: u64,
        format_prealloc_mode: PreallocateMode,
    ) -> io::Result<()> {
        if self
            .size
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                (new_size > old).then_some(new_size)
            })
            .is_err()
        {
            return Ok(()); // only grow, else do nothing
        }

        let storage_prealloc_mode = match format_prealloc_mode {
            PreallocateMode::None => storage::PreallocateMode::None,
            PreallocateMode::Zero | PreallocateMode::FormatAllocate => {
                storage::PreallocateMode::Zero
            }
            PreallocateMode::FullAllocate => storage::PreallocateMode::Allocate,
            PreallocateMode::WriteData => storage::PreallocateMode::WriteData,
        };
        self.inner.resize(new_size, storage_prealloc_mode).await
    }

    async fn resize_shrink(&mut self, new_size: u64) -> io::Result<()> {
        if self
            .size
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                (new_size < old).then_some(new_size)
            })
            .is_err()
        {
            return Ok(()); // only shrink, else do nothing
        }

        self.inner
            .resize(new_size, storage::PreallocateMode::None)
            .await
    }
}

impl<S: Storage + 'static> Display for Raw<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "raw[{}]", self.inner)
    }
}

/// Options builder for opening a raw image.
pub struct RawOpenBuilder<S: Storage + 'static>(FormatDriverBuilderBase<S>);

#[maybe_async(AFIT)]
impl<S: Storage + 'static> FormatDriverBuilder<S> for RawOpenBuilder<S> {
    type Format = Raw<S>;
    const FORMAT: Format = Format::Raw;

    fn new(image: S) -> Self {
        RawOpenBuilder(FormatDriverBuilderBase::new(image))
    }

    fn new_path<P: AsRef<Path>>(path: P) -> Self {
        RawOpenBuilder(FormatDriverBuilderBase::new_path(path))
    }

    fn write(mut self, writable: bool) -> Self {
        self.0.set_write(writable);
        self
    }

    fn storage_open_options(mut self, options: StorageOpenOptions) -> Self {
        self.0.set_storage_open_options(options);
        self
    }

    async fn open<G: ImplicitOpenGate<S>>(self, mut gate: G) -> io::Result<Self::Format> {
        let writable = self.0.get_writable();
        let file = self.0.open_image(&mut gate).await?;
        Raw::open_image(file, writable).await
    }

    fn get_image_path(&self) -> Option<PathBuf> {
        self.0.get_image_path()
    }

    fn get_writable(&self) -> bool {
        self.0.get_writable()
    }

    fn get_storage_open_options(&self) -> Option<&StorageOpenOptions> {
        self.0.get_storage_opts()
    }
}

/// Creation builder for a new raw image.
pub struct RawCreateBuilder<S: Storage + 'static>(FormatCreateBuilderBase<S>);

#[maybe_async(AFIT)]
impl<S: Storage + 'static> FormatCreateBuilder<S> for RawCreateBuilder<S> {
    const FORMAT: Format = Format::Raw;
    type DriverBuilder = RawOpenBuilder<S>;

    fn new(image: S) -> Self {
        RawCreateBuilder(FormatCreateBuilderBase::new(image))
    }

    fn size(mut self, size: u64) -> Self {
        self.0.set_size(size);
        self
    }

    fn preallocate(mut self, prealloc_mode: PreallocateMode) -> Self {
        self.0.set_preallocate(prealloc_mode);
        self
    }

    fn get_size(&self) -> u64 {
        self.0.get_size()
    }

    fn get_preallocate(&self) -> PreallocateMode {
        self.0.get_preallocate()
    }

    async fn create(self) -> io::Result<()> {
        self.create_open(DenyImplicitOpenGate::default(), |image| {
            Ok(Raw::builder(image))
        })
        .await?;
        Ok(())
    }

    async fn create_open<
        G: ImplicitOpenGate<S>,
        F: FnOnce(S) -> io::Result<Self::DriverBuilder>,
    >(
        self,
        open_gate: G,
        open_builder_fn: F,
    ) -> io::Result<Raw<S>> {
        let size = self.0.get_size();
        let prealloc = self.0.get_preallocate();
        let image = self.0.get_image();

        // Clear of data (and allow for full preallocation, if requested)
        if image.size()? > 0 {
            image.resize(size, storage::PreallocateMode::None).await?;
        }

        let img = open_builder_fn(image)?.write(true).open(open_gate).await?;
        if size > 0 {
            img.resize_grow(size, prealloc).await?;
        }

        Ok(img)
    }
}
