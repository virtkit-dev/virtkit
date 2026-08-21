//! Builders for opening and creating qcow2 images.

use super::*;
use crate::format::builder::{
    FormatCreateBuilderBase, FormatDriverBuilderBase, FormatOrBuilder, StorageOrPath,
};
use crate::DenyImplicitOpenGate;
use std::marker::PhantomData;
use std::path::PathBuf;

/// Options builder for opening a qcow2 image.
///
/// Allows setting various options one by one to open a qcow2 image.
pub struct Qcow2OpenBuilder<S: Storage + 'static, F: WrappedFormat<S> + 'static = FormatAccess<S>> {
    /// Basic options.
    base: FormatDriverBuilderBase<S>,

    /// Backing image
    ///
    /// `None` to open the image as specified by the image header, `Some(None)` to not open any
    /// backing image, and `Some(Some(_))` to use that backing image.
    backing: Option<Option<FormatOrBuilder<S, F>>>,

    /// External data file
    ///
    /// `None` to open the file as specified by the image header, `Some(None)` to not open any data
    /// file, and `Some(Some(_))` to use that data file.
    data_file: Option<Option<StorageOrPath<S>>>,
}

/// Options builder for creating (formatting) a qcow2 image.
///
/// Allows setting various options for a new qcow2 image.
pub struct Qcow2CreateBuilder<S: Storage + 'static, F: WrappedFormat<S> + 'static = FormatAccess<S>>
{
    /// Basic options.
    base: FormatCreateBuilderBase<S>,

    /// Backing image filename and format
    backing: Option<(String, String)>,

    /// External data file name and the file itself
    data_file: Option<(String, S)>,

    /// Cluster size
    cluster_size: usize,

    /// Refcount bit width
    refcount_width: usize,

    /// Needed for the correct `create_open()` return type
    _wrapped_format: PhantomData<F>,
}

impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Qcow2OpenBuilder<S, F> {
    /// Create a new instance.
    fn with_base(base: FormatDriverBuilderBase<S>) -> Self {
        Qcow2OpenBuilder {
            base,
            backing: None,
            data_file: None,
        }
    }

    /// Set a backing image.
    ///
    /// This overrides the implicit backing image given in the image header.  Passing `None` means
    /// not to use any backing image (regardless of whether the image header defines a backing
    /// image).
    pub fn backing(mut self, backing: Option<F>) -> Self {
        self.backing = Some(backing.map(FormatOrBuilder::Format));
        self
    }

    /// Declare a backing image by path.
    ///
    /// Let imago open the given path as an image with the given format.
    ///
    /// Use with caution, as the given image will be opened with default options.
    /// [`Qcow2OpenBuilder::backing()`] is preferable, as it allows you control over how the
    /// backing image is opened.
    pub fn backing_path<P: AsRef<Path>>(mut self, backing: P, format: Format) -> Self {
        self.backing = Some(Some(FormatOrBuilder::new_builder(format, backing)));
        self
    }

    /// Set an external data file.
    ///
    /// This overrides the implicit external data file given in the image header.  Passing `None`
    /// means not to use any external data file (regardless of whether the image header defines an
    /// external data file, and regardless of whether the image header says the image has an
    /// external data file).
    ///
    /// Similarly, passing a data file will then always use that data file, regardless of whether
    /// the image header says the image has an external data file.
    ///
    /// Note that it is wrong to set a data file for an image that does not have one, and it is
    /// wrong to enforce not using a data file for an image that has one.  There is no way to know
    /// whether the image needs an external data file until it is opened.
    ///
    /// If you want to open a specific data file if and only if the image needs it, call
    /// `Qcow2OpenBuilder::data_file(None)` to prevent any data file from being automatically
    /// opened; open the image, then check [`Qcow2::requires_external_data_file()`], and, if true,
    /// invoke [`Qcow2::set_data_file()`].
    pub fn data_file(mut self, data_file: Option<S>) -> Self {
        self.data_file = Some(data_file.map(StorageOrPath::Storage));
        self
    }
}

#[maybe_async(AFIT)]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> FormatDriverBuilder<S>
    for Qcow2OpenBuilder<S, F>
{
    type Format = Qcow2<S, F>;
    const FORMAT: Format = Format::Qcow2;

    fn new(image: S) -> Self {
        Self::with_base(FormatDriverBuilderBase::new(image))
    }

    fn new_path<P: AsRef<Path>>(path: P) -> Self {
        Self::with_base(FormatDriverBuilderBase::new_path(path))
    }

    fn write(mut self, write: bool) -> Self {
        self.base.set_write(write);
        self
    }

    fn storage_open_options(mut self, options: StorageOpenOptions) -> Self {
        self.base.set_storage_open_options(options);
        self
    }

    async fn open<G: ImplicitOpenGate<S>>(self, mut gate: G) -> io::Result<Self::Format> {
        let writable = self.base.get_writable();
        let storage_opts = self.base.make_storage_opts();
        let metadata = self.base.open_image(&mut gate).await?;

        let mut qcow2 = Qcow2::<S, F>::do_open(metadata, writable, storage_opts.clone()).await?;

        if let Some(backing) = self.backing {
            let backing = match backing {
                None => None,
                Some(backing) => Some(
                    backing
                        .open_format(storage_opts.clone().write(false), &mut gate)
                        .await
                        .err_context(|| "Backing file")?,
                ),
            };
            qcow2.set_backing(backing);
        }

        if let Some(data_file) = self.data_file {
            let data_file = match data_file {
                None => None,
                Some(data_file) => Some(
                    data_file
                        .open_storage(storage_opts, &mut gate)
                        .await
                        .err_context(|| "External data file")?,
                ),
            };
            qcow2.set_data_file(data_file);
        }

        qcow2.open_implicit_dependencies_gated(gate).await?;

        Ok(qcow2)
    }

    fn get_image_path(&self) -> Option<PathBuf> {
        self.base.get_image_path()
    }

    fn get_writable(&self) -> bool {
        self.base.get_writable()
    }

    fn get_storage_open_options(&self) -> Option<&StorageOpenOptions> {
        self.base.get_storage_opts()
    }
}

impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Qcow2CreateBuilder<S, F> {
    /// Set a backing image.
    ///
    /// Set the path to the backing image to be written into the image header; this path will be
    /// interpreted relative to the qcow2 image file.
    ///
    /// The backing format should be one of “qcow2” or “raw”.
    ///
    /// Neither of filename or format are checked for validity.
    pub fn backing(mut self, backing_filename: String, backing_format: String) -> Self {
        self.backing = Some((backing_filename, backing_format));
        self
    }

    /// Set an external data file.
    ///
    /// Set the path for an external data file.  This path will be interpreted relative to the
    /// qcow2 image file.  This path is not checked for whether it matches `file` or even points to
    /// anything at all.
    ///
    /// `file` is the data file itself; it is necessary to pass this storage object into the
    /// builder for preallocation purposes.
    pub fn data_file(mut self, filename: String, file: S) -> Self {
        self.data_file = Some((filename, file));
        self
    }

    /// Set the cluster size (in bytes).
    ///
    /// A cluster is the unit of allocation for qcow2 images.  Smaller clusters can lead to better
    /// COW performance, but worse performance for fully allocated images, and have increased
    /// metadata size overhead.
    ///
    /// Must be a power of two between 512 and 2 MiB (inclusive).
    ///
    /// The default is 64 KiB.
    pub fn cluster_size(mut self, size: usize) -> Self {
        self.cluster_size = size;
        self
    }

    /// Set the refcount width in bits.
    ///
    /// Reference counting is used to determine empty areas in the image file, though this only
    /// needs refcounts of 0 and 1, i.e. a reference bit width of 1.
    ///
    /// Larger refcount bit widths are only needed when using internal snapshots, in which case
    /// multiple snapshots can share clusters.
    ///
    /// Must be a power of two between 1 and 64 (inclusive).
    ///
    /// The default is 16 bits.
    pub fn refcount_width(mut self, bits: usize) -> Self {
        self.refcount_width = bits;
        self
    }
}

#[maybe_async(AFIT)]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> FormatCreateBuilder<S>
    for Qcow2CreateBuilder<S, F>
{
    const FORMAT: Format = Format::Qcow2;
    type DriverBuilder = Qcow2OpenBuilder<S, F>;

    fn new(image: S) -> Self {
        Qcow2CreateBuilder {
            base: FormatCreateBuilderBase::new(image),
            backing: None,
            data_file: None,
            cluster_size: 65536,
            refcount_width: 16,
            _wrapped_format: PhantomData,
        }
    }

    fn size(mut self, size: u64) -> Self {
        self.base.set_size(size);
        self
    }

    fn preallocate(mut self, prealloc_mode: PreallocateMode) -> Self {
        self.base.set_preallocate(prealloc_mode);
        self
    }

    fn get_size(&self) -> u64 {
        self.base.get_size()
    }

    fn get_preallocate(&self) -> PreallocateMode {
        self.base.get_preallocate()
    }

    async fn create(self) -> io::Result<()> {
        self.create_open(DenyImplicitOpenGate::default(), |image| {
            // data file will be set by `create_open()`
            Ok(Qcow2::<S, F>::builder(image).backing(None).write(true))
        })
        .await?
        .flush()
        .await?;

        Ok(())
    }

    async fn create_open<
        G: ImplicitOpenGate<S>,
        OBF: FnOnce(S) -> io::Result<Qcow2OpenBuilder<S, F>>,
    >(
        self,
        open_gate: G,
        open_builder_fn: OBF,
    ) -> io::Result<Qcow2<S, F>> {
        let size = self.base.get_size();
        let prealloc = self.base.get_preallocate();
        let image = self.base.get_image();

        let cluster_size = self.cluster_size;
        if !cluster_size.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cluster size {cluster_size} is not a power of two"),
            ));
        }

        let cs_range = MIN_CLUSTER_SIZE..=MAX_CLUSTER_SIZE;
        if !cs_range.contains(&cluster_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cluster size {cluster_size} not in {cs_range:?}"),
            ));
        }

        let cluster_bits = cluster_size.trailing_zeros();
        assert!(1 << cluster_bits == cluster_size);

        let refcount_width = self.refcount_width;
        if !refcount_width.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refcount width {refcount_width} is not a power of two"),
            ));
        }

        let rw_range = MIN_REFCOUNT_WIDTH..=MAX_REFCOUNT_WIDTH;
        if !rw_range.contains(&refcount_width) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refcount width {refcount_width} not in {rw_range:?}"),
            ));
        }

        let refcount_order = refcount_width.trailing_zeros();
        assert!(1 << refcount_order == refcount_width);

        Qcow2::<S, F>::check_valid_preallocation(prealloc, self.backing.is_some())?;

        // Clear of data
        if image.size()? > 0 {
            image.resize(size, storage::PreallocateMode::None).await?;
        }

        // Allocate just header and a minimal refcount structure.  The image will have a length of
        // 0 at first, so doesn’t need an L1 table.
        // To give the image the correct size, we just open and resize it.
        //
        // Cluster use:
        // 0. Header
        // 1. Refcount table
        // 2. Refcount block
        //
        // Technically, we could also just write the header without refcount info, but the dirty
        // bit set.  Too cheeky for my taste, though.

        let (backing_fname, backing_format) = match self.backing {
            Some((fname, fmt)) => (Some(fname), Some(fmt)),
            None => (None, None),
        };

        let (data_file_name, data_file) = match self.data_file {
            Some((fname, file)) => (Some(fname), Some(file)),
            None => (None, None),
        };

        let mut header = Header::new(
            cluster_bits,
            refcount_order,
            backing_fname,
            backing_format,
            data_file_name,
        );

        let mut rb = RefBlock::new_cleared(&image, &header)?;
        rb.set_cluster(HostCluster(2));
        {
            let mut rb_locked = rb.lock_write().await;
            rb_locked.increment(0)?; // header
            rb_locked.increment(1)?; // reftable
            rb_locked.increment(2)?; // refblock
        }
        rb.write(&image).await?;

        let mut rt = RefTable::from_data(Box::new([]), &header).clone_and_grow(&header, 0)?;
        rt.set_cluster(HostCluster(1));
        rt.enter_refblock(0, &rb)?;
        rt.write(&image).await?;

        header.set_reftable(&rt)?;
        header.write(&image).await?;

        let img = open_builder_fn(image)?
            .write(true)
            .data_file(data_file)
            .open(open_gate)
            .await?;
        if size > 0 {
            img.resize_grow(size, prealloc).await?;
        }

        Ok(img)
    }
}
