//! Builder for defining open options for images.

use super::drivers::FormatDriverInstance;
use super::gate::ImplicitOpenGate;
use super::wrapped::WrappedFormat;
use super::{Format, PreallocateMode};
use crate::misc_helpers::ResultErrorContext;
use crate::qcow2::Qcow2OpenBuilder;
use crate::raw::RawOpenBuilder;
use crate::vmdk::VmdkOpenBuilder;
use crate::{Storage, StorageOpenOptions};
use maybe_async::maybe_async;
use std::io;
use std::path::{Path, PathBuf};

/// Prepares opening an image.
///
/// There are common options for all kinds of formats, which are accessible through this trait’s
/// methods, but there are also specialized options that depend on the format itself.  Each
/// implementation will also provide such specialized methods, but opening an image should
/// generally not require invoking those methods (i.e. sane defaults should apply).
///
/// See [`Qcow2OpenBuilder`] for an example implementation.
#[maybe_async(AFIT)]
pub trait FormatDriverBuilder<S: Storage + 'static>: Sized {
    /// The format object that this builder will create.
    type Format: FormatDriverInstance<Storage = S>;

    /// Which format this is.
    const FORMAT: Format;

    /// Prepare opening the given image.
    fn new(image: S) -> Self;

    /// Prepare opening an image under the given path.
    fn new_path<P: AsRef<Path>>(path: P) -> Self;

    /// Whether the image should be writable or not.
    fn write(self, writable: bool) -> Self;

    /// Set base storage options for opened storage objects.
    ///
    /// When opening files (e.g. a backing file, or the path given to
    /// [`FormatDriverBuilder::new_path()`]), use these options as the basis for opening their
    /// respective storage objects.
    ///
    /// Any filename in `options` is ignored, as is writability. Both are overridden case by case
    /// as needed.
    fn storage_open_options(self, options: StorageOpenOptions) -> Self;

    /// Open the image.
    ///
    /// Opens the image according to the options specified in `self`.  If files are to be opened
    /// implicitly (e.g. backing files), the corresponding functions in `gate` will be invoked to
    /// do so, which can decide, based on the options, to do so, or not, or modify the options
    /// before opening the respective image/file.
    ///
    /// To prevent any implicitly referenced objects from being opened, use
    /// [`DenyImplicitOpenGate`](crate::DenyImplicitOpenGate), to allow all implicitly referenced
    /// objects to be opened as referenced, use
    /// [`PermissiveImplicitOpenGate`](crate::PermissiveImplicitOpenGate) (but note the cautionary
    /// note there).
    ///
    /// For example:
    /// ```no_run
    /// # #[cfg(feature = "async")]
    /// # let _ = async {
    /// use imago::file::File;
    /// use imago::qcow2::Qcow2;
    /// use imago::{DenyImplicitOpenGate, FormatDriverBuilder};
    ///
    /// // Note we only override the backing file, not a potential external data file.  If the
    /// // image has one, qcow2 would still attempt to open it, but `DenyImplicitOpenGate` would
    /// // prevent that.
    /// let image = Qcow2::<File>::builder_path("/path/to/image.qcow2")
    ///     .backing(None)
    ///     .open(DenyImplicitOpenGate::default())
    ///     .await?;
    /// # Ok::<(), std::io::Error>(())
    /// # };
    /// ```
    #[allow(async_fn_in_trait)] // No need for Send
    async fn open<G: ImplicitOpenGate<S>>(self, gate: G) -> io::Result<Self::Format>;

    /// Synchronous wrapper around [`FormatDriverBuilder::open()`].
    ///
    /// This creates an async runtime, so the [`ImplicitOpenGate`] implementation is still supposed
    /// to be async.
    #[cfg(feature = "sync-wrappers")]
    fn open_sync<G: ImplicitOpenGate<S>>(self, gate: G) -> io::Result<Self::Format> {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(self.open(gate))
    }

    /// If possible, get the image’s path.
    fn get_image_path(&self) -> Option<PathBuf>;

    /// Return the set writable state.
    fn get_writable(&self) -> bool;

    /// Return the set storage options (if any).
    fn get_storage_open_options(&self) -> Option<&StorageOpenOptions>;
}

/// Prepares creating (formatting) an image.
///
/// There are common options for all kinds of formats, which are accessible through this trait’s
/// methods, but there are also specialized options that depend on the format itself.  Each
/// implementation will provide such specialized methods.
///
/// See [`Qcow2CreateBuilder`](crate::qcow2::Qcow2CreateBuilder) for an example implementation.
#[maybe_async(AFIT)]
pub trait FormatCreateBuilder<S: Storage + 'static>: Sized {
    /// Which format this is.
    const FORMAT: Format;

    /// Open builder type for this format.
    type DriverBuilder: FormatDriverBuilder<S>;

    /// Prepare formatting the given image file.
    fn new(image: S) -> Self;

    /// Set the virtual disk size.
    fn size(self, size: u64) -> Self;

    /// Set the desired preallocation mode.
    fn preallocate(self, prealloc_mode: PreallocateMode) -> Self;

    /// Format the image file.
    ///
    /// Formats the underlying image file according to the options specified in `self`.
    ///
    /// This will delete any currently present data in the image!
    #[allow(async_fn_in_trait)] // No need for Send
    async fn create(self) -> io::Result<()>;

    /// Format the image file and open it.
    ///
    /// Same as [`FormatCreateBuilder::create()`], but also opens the image file.
    ///
    /// Note that the image file will always be opened as writable, regardless of whether this was
    /// set in `open_builder` or not.  This is because formatting requires the image to be
    /// writable.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn create_open<G: ImplicitOpenGate<S>, F: FnOnce(S) -> io::Result<Self::DriverBuilder>>(
        self,
        open_gate: G,
        open_builder_fn: F,
    ) -> io::Result<<Self::DriverBuilder as FormatDriverBuilder<S>>::Format>;

    /// Get the set virtual disk size.
    fn get_size(&self) -> u64;

    /// Get the preallocation mode.
    fn get_preallocate(&self) -> PreallocateMode;
}

/// Image open builder with the most basic options.
pub struct FormatDriverBuilderBase<S: Storage> {
    /// Metadata (image) file
    image: StorageOrPath<S>,

    /// Whether the image is writable or not
    writable: bool,

    /// Options to be used for implicitly opened storage
    storage_opts: Option<StorageOpenOptions>,
}

/// Image creation builder with the most basic options.
pub struct FormatCreateBuilderBase<S: Storage> {
    /// Metadata (image) file
    image: S,

    /// Virtual disk size
    size: u64,

    /// Preallocation mode
    prealloc_mode: PreallocateMode,
}

#[maybe_async]
impl<S: Storage + 'static> FormatDriverBuilderBase<S> {
    /// Create a new instance of this type.
    fn do_new(image: StorageOrPath<S>) -> Self {
        FormatDriverBuilderBase {
            image,
            writable: false,
            storage_opts: None,
        }
    }

    /// Helper for [`FormatDriverBuilder::new()`].
    pub fn new(image: S) -> Self {
        Self::do_new(StorageOrPath::Storage(image))
    }

    /// Helper for [`FormatDriverBuilder::new_path()`].
    pub fn new_path<P: AsRef<Path>>(path: P) -> Self {
        Self::do_new(StorageOrPath::Path(path.as_ref().to_path_buf()))
    }

    /// Helper for [`FormatDriverBuilder::write()`].
    pub fn set_write(&mut self, writable: bool) {
        self.writable = writable;
    }

    /// Helper for [`FormatDriverBuilder::storage_open_options()`].
    pub fn set_storage_open_options(&mut self, options: StorageOpenOptions) {
        self.storage_opts = Some(options);
    }

    /// If possible, get the image’s path.
    pub fn get_image_path(&self) -> Option<PathBuf> {
        match &self.image {
            StorageOrPath::Storage(s) => s.get_filename(),
            StorageOrPath::Path(p) => Some(p.clone()),
        }
    }

    /// Return the set writable state.
    pub fn get_writable(&self) -> bool {
        self.writable
    }

    /// Return the set storage options (if any).
    pub fn get_storage_opts(&self) -> Option<&StorageOpenOptions> {
        self.storage_opts.as_ref()
    }

    /// Create storage options.
    ///
    /// If any were set, return those, overriding their writable state based on the set writable
    /// state ([`FormatDriverBuilderBase::set_write()`]).  Otherwise, create an empty set (again
    /// with the writable state set as appropriate).
    pub fn make_storage_opts(&self) -> StorageOpenOptions {
        self.storage_opts
            .as_ref()
            .cloned()
            .unwrap_or(StorageOpenOptions::new())
            .write(self.writable)
    }

    /// Open the image’s storage object.
    pub async fn open_image<G: ImplicitOpenGate<S>>(self, gate: &mut G) -> io::Result<S> {
        let opts = self.make_storage_opts();
        self.image.open_storage(opts, gate).await
    }
}

impl<S: Storage> FormatCreateBuilderBase<S> {
    /// Helper for [`FormatCreateBuilder::new()`].
    pub fn new(image: S) -> Self {
        FormatCreateBuilderBase {
            image,
            size: 0,
            prealloc_mode: PreallocateMode::None,
        }
    }

    /// Helper for [`FormatCreateBuilder::size()`].
    pub fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    /// Helper for [`FormatCreateBuilder::preallocate()`].
    pub fn set_preallocate(&mut self, prealloc_mode: PreallocateMode) {
        self.prealloc_mode = prealloc_mode;
    }

    /// Get the set virtual disk size.
    pub fn get_size(&self) -> u64 {
        self.size
    }

    /// Get the preallocation mode.
    pub fn get_preallocate(&self) -> PreallocateMode {
        self.prealloc_mode
    }

    /// Get the image file to be formatted.
    pub fn get_image(self) -> S {
        self.image
    }

    /// Get the image file to be formatted, by reference.
    pub fn get_image_ref(&self) -> &S {
        &self.image
    }
}

/// Alternatively a storage object or a path to it.
///
/// Only for internal use.  Externally, two separate functions should be provided.
pub(crate) enum StorageOrPath<S: Storage> {
    /// Storage object
    Storage(S),

    /// Path
    Path(PathBuf),
}

#[maybe_async]
impl<S: Storage + 'static> StorageOrPath<S> {
    /// Open the storage object.
    pub async fn open_storage<G: ImplicitOpenGate<S>>(
        self,
        opts: StorageOpenOptions,
        gate: &mut G,
    ) -> io::Result<S> {
        match self {
            StorageOrPath::Storage(s) => Ok(s),
            StorageOrPath::Path(p) => gate
                .open_storage(opts.filename(&p))
                .await
                .err_context(|| p.to_string_lossy()),
        }
    }
}

/// Alternatively an image or parameters for a builder for it.
///
/// Only for internal use.  Externally, two separate functions should be provided.
pub(crate) enum FormatOrBuilder<S: Storage + 'static, F: WrappedFormat<S>> {
    /// Image object
    Format(F),

    /// Qcow2 image builder
    Qcow2Builder(Box<Qcow2OpenBuilder<S>>),

    /// Raw image builder
    RawBuilder(Box<RawOpenBuilder<S>>),

    /// Vmdk image builder
    VmdkBuilder(Box<VmdkOpenBuilder<S>>),
}

#[maybe_async]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> FormatOrBuilder<S, F> {
    /// Create a new builder variant.
    ///
    /// Create a builder variant for the given format, opening the given image.
    pub fn new_builder<P: AsRef<Path>>(format: Format, path: P) -> Self {
        match format {
            Format::Qcow2 => Self::Qcow2Builder(Box::new(Qcow2OpenBuilder::new_path(path))),
            Format::Raw => Self::RawBuilder(Box::new(RawOpenBuilder::new_path(path))),
            Format::Vmdk => Self::VmdkBuilder(Box::new(VmdkOpenBuilder::new_path(path))),
        }
    }

    /// Open the image.
    pub async fn open_format<G: ImplicitOpenGate<S>>(
        self,
        opts: StorageOpenOptions,
        gate: &mut G,
    ) -> io::Result<F> {
        let f = match self {
            FormatOrBuilder::Format(f) => return Ok(f),
            FormatOrBuilder::Qcow2Builder(b) => {
                let b = b.storage_open_options(opts);
                gate.open_format(b).await?
            }
            FormatOrBuilder::RawBuilder(b) => {
                let b = b.storage_open_options(opts);
                gate.open_format(b).await?
            }
            FormatOrBuilder::VmdkBuilder(b) => {
                let b = b.storage_open_options(opts);
                gate.open_format(b).await?
            }
        };
        Ok(F::wrap(f))
    }
}
