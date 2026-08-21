//! VMDK implementation.

use crate::format::builder::{FormatDriverBuilder, FormatDriverBuilderBase};
use crate::format::drivers::FormatDriverInstance;
use crate::format::gate::ImplicitOpenGate;
use crate::format::wrapped::WrappedFormat;
use crate::format::{Format, PreallocateMode};
use crate::io_buffers::IoBuffer;
use crate::misc_helpers::{invalid_data, ResultErrorContext};
use crate::storage::ext::StorageExt;
use crate::{FormatAccess, ShallowMapping, Storage, StorageOpenOptions};
use maybe_async::maybe_async;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Range, RangeInclusive};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::{cmp, io};

/// As usual, VMDK sector size is 512 bytes as a fixed value
const VMDK_SECTOR_SIZE: u64 = 512;
/// VMDK SPARSE data signature
const VMDK4_MAGIC: u32 = 0x564d444b; // 'KDMV'
/// Supported version range
const VMDK_VERSION_RANGE: RangeInclusive<u32> = 1..=3;

/// Represents the data storage for a VMDK extent
#[derive(Debug, Clone)]
enum VmdkStorage<S: Storage + 'static> {
    /// A FLAT extent with a RAW file starting from the exact offset
    Flat {
        /// Storage object containing linear (raw) data
        file: S,
        /// Offset in `file` where the data for this extent begins
        offset: u64,
    },
    /// A zero-filled extent
    Zero,
}

/// VMDK extent information after parsing, before opening
#[derive(Debug)]
enum VmdkParsedStorage {
    /// A FLAT extent with a RAW file starting from the exact offset
    Flat {
        /// Path to storage object containing linear (raw) data
        filename: String,
        /// Offset in the storage object where the data for this extent begins
        offset: u64,
    },
    /// A zero-filled extent
    Zero,
}

/// Access type for VMDK extents
#[derive(Debug, Clone, PartialEq)]
enum VmdkAccessType {
    /// Read-write access
    RW,
    /// Read-only access
    RdOnly,
    /// No access
    NoAccess,
}

/// VMDK extent
#[derive(Debug)]
struct VmdkExtent<S: Storage + 'static> {
    /// Access type (RW, RDONLY, NOACCESS).
    access_type: VmdkAccessType,
    /// Part of the virtual disk covered by this extent.
    ///
    /// The start is equal to the end of the extent before it (0 if none), and the end is equal to
    /// the start plus this extent’s length.
    disk_range: Range<u64>,
    /// Data source
    ///
    /// Present if and only if the access type is not NOACCESS.
    storage: Option<VmdkStorage<S>>,
}

/// VMDK extent descriptor information after parsing, before opening
#[derive(Debug)]
struct VmdkParsedExtent {
    /// Access type (RW, RDONLY, NOACCESS).
    access_type: VmdkAccessType,
    /// Number of sectors.
    sectors: u64,
    /// Data source
    ///
    /// Present if and only if the access type is not NOACCESS.
    storage: Option<VmdkParsedStorage>,
}

/// VMDK disk image format implementation.
#[derive(Debug)]
pub struct Vmdk<S: Storage + 'static, F: WrappedFormat<S> + 'static = FormatAccess<S>> {
    /// Storage object containing the VMDK descriptor file
    descriptor_file: Arc<S>,

    /// Backing image type.
    ///
    /// We do not support backing (parent) images yet, but capture the type so that when we do
    /// support it, the change will be syntactically compatible.
    parent_type: PhantomData<F>,

    /// Base options to be used for implicitly opened storage objects.
    storage_open_options: StorageOpenOptions,

    /// Virtual disk size in bytes.
    size: AtomicU64,

    /// Parsed VMDK descriptor.
    desc: VmdkDesc,

    /// Extent information as parsed from the VMDK descriptor file.
    parsed_extents: Vec<VmdkParsedExtent>,

    /// Storage objects for each extent.
    extents: Vec<VmdkExtent<S>>,
}

/// VMDK descriptor information.
#[derive(Debug, Clone)]
struct VmdkDesc {
    /// Version number of the VMDK descriptor
    version: u32,
    /// Content ID
    cid: String,
    /// Content ID of the parent link
    parent_cid: String,
    /// Type of virtual disk
    create_type: String,
    /// The disk geometry value (sectors)
    sectors: u64,
    /// The disk geometry value (heads)
    heads: u64,
    /// The disk geometry value (cylinders)
    cylinders: u64,
}

impl VmdkParsedExtent {
    /// Parse an extent descriptor line.
    fn try_from_descriptor_line(line: &str) -> io::Result<VmdkParsedExtent> {
        // See https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#221-extent-descriptor

        let mut parts = line.split_whitespace();

        let access_type = match parts
            .next()
            .ok_or_else(|| invalid_data("Access type missing"))?
        {
            "RW" => VmdkAccessType::RW,
            "RDONLY" => VmdkAccessType::RdOnly,
            "NOACCESS" => VmdkAccessType::NoAccess,
            other => return Err(invalid_data(format!("Invalid access type '{other}'"))),
        };

        let sectors = parts
            .next()
            .ok_or_else(|| invalid_data("Sector count missing"))?
            .parse()
            .map_err(|_| invalid_data("Invalid sector count"))?;

        if access_type == VmdkAccessType::NoAccess {
            return Ok(VmdkParsedExtent {
                access_type,
                sectors,
                storage: None,
            });
        }

        let extent_type = parts
            .next()
            .ok_or_else(|| invalid_data("Extent type missing"))?;
        if extent_type == "ZERO" {
            return Ok(VmdkParsedExtent {
                access_type,
                sectors,
                storage: Some(VmdkParsedStorage::Zero),
            });
        }
        if extent_type != "FLAT" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported extent type {extent_type}"),
            ));
        }

        // filename is enclosed in quotes and may contain spaces, so split the whole line by quotes
        // (We could simplify this if we could do `line.splitn_whitespace(4)` at the beginning of
        // this function, but `splitn_whitespace()` does not exist.)
        let mut quote_split = line.splitn(3, '"').map(|part| part.trim());
        // We know the line isn’t empty, so we must at least get one part
        let before_filename = quote_split.next().unwrap();
        let filename = quote_split
            .next()
            .ok_or_else(|| invalid_data("Extent filename missing"))?;
        let after_filename = quote_split
            .next()
            .ok_or_else(|| invalid_data("Extent filename not terminated"))?;

        let part_count_before_filename = before_filename.split_whitespace().count();
        if part_count_before_filename != 3 {
            return Err(invalid_data(format!(
                "Expected filename at field index 3, found at {part_count_before_filename}"
            )));
        }

        // Continue parsing after filename
        parts = after_filename.split_whitespace();

        let offset = parts
            .next()
            .map_or(Ok(0), |ofs_str| ofs_str.parse())
            .map_err(|_| invalid_data("Invalid offset"))?;

        Ok(VmdkParsedExtent {
            access_type,
            sectors,
            storage: Some(VmdkParsedStorage::Flat {
                filename: filename.to_string(),
                offset,
            }),
        })
    }
}

/// Remove double quotes around `input` if there are any.
fn strip_quotes(input: &str) -> &str {
    input
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(input)
}

/// Helper to parse an integer from the descriptor file.
fn parse_desc_value<F: FromStr>(key: &str, value: &str) -> io::Result<F> {
    let stripped = strip_quotes(value);

    stripped
        .parse::<F>()
        .map_err(|_| invalid_data(format!("Invalid '{key}' value: {stripped}")))
}

#[maybe_async]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Vmdk<S, F> {
    /// Create a new [`FormatDriverBuilder`] instance for the given image.
    pub fn builder(image: S) -> VmdkOpenBuilder<S, F> {
        VmdkOpenBuilder::new(image)
    }

    /// Create a new [`FormatDriverBuilder`] instance for an image under the given path.
    pub fn builder_path<P: AsRef<Path>>(image_path: P) -> VmdkOpenBuilder<S, F> {
        VmdkOpenBuilder::new_path(image_path)
    }

    /// Open an extent from the information in `extent`.
    ///
    /// `in_disk_offset` is the offset in the virtual disk where this extent fits in.  It should be
    /// the end offset of the extent before it.
    async fn open_implicit_extent<G: ImplicitOpenGate<S>>(
        &self,
        extent: &VmdkParsedExtent,
        in_disk_offset: u64,
        open_gate: &mut G,
    ) -> io::Result<VmdkExtent<S>> {
        let sectors = extent.sectors;
        let size = sectors.checked_mul(VMDK_SECTOR_SIZE).ok_or_else(|| {
            invalid_data(format!(
                "Extent size overflow: {sectors} * {VMDK_SECTOR_SIZE}"
            ))
        })?;
        let disk_range = in_disk_offset..in_disk_offset.checked_add(size).ok_or_else(|| {
            invalid_data(format!("Extent offset overflow: {in_disk_offset} + {size}"))
        })?;

        let Some(storage) = extent.storage.as_ref() else {
            return Ok(VmdkExtent {
                access_type: extent.access_type.clone(),
                disk_range,
                storage: None,
            });
        };

        let storage = match storage {
            VmdkParsedStorage::Flat { filename, offset } => {
                let absolute = self
                    .descriptor_file
                    .resolve_relative_path(filename)
                    .err_context(|| format!("Cannot resolve storage file name {filename}"))?;

                let mut file_opts = self.storage_open_options.clone().filename(absolute.clone());
                if extent.access_type == VmdkAccessType::RdOnly {
                    file_opts = file_opts.write(false);
                }

                let file = open_gate
                    .open_storage(file_opts)
                    .await
                    .err_context(|| format!("Data storage file {absolute:?}"))?;

                VmdkStorage::Flat {
                    file,
                    offset: *offset,
                }
            }

            VmdkParsedStorage::Zero => VmdkStorage::Zero,
        };

        Ok(VmdkExtent {
            access_type: extent.access_type.clone(),
            disk_range,
            storage: Some(storage),
        })
    }

    /// Checks if the VMDK version is supported and returns an error if not
    fn error_out_unsupported_version(&self) -> io::Result<()> {
        let version = self.desc.version;
        if !VMDK_VERSION_RANGE.contains(&version) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported version {version}"),
            ));
        }
        Ok(())
    }

    /// Parse a line in the VMDK descriptor file
    fn parse_descriptor_line(&mut self, line: &str) -> io::Result<()> {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }

        // Parse extent descriptors (RW/RDONLY/NOACCESS)
        if let Some((access, _)) = line.split_once(char::is_whitespace) {
            if matches!(access, "RW" | "RDONLY" | "NOACCESS") {
                let extent = VmdkParsedExtent::try_from_descriptor_line(line)?;
                self.parsed_extents.push(extent);
                return Ok(());
            }
        }

        let Some((key, value)) = line.split_once('=') else {
            // Silently ignore
            return Ok(());
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "version" => {
                self.desc.version = value
                    .parse()
                    .map_err(|_| invalid_data("Invalid version format"))?;
            }
            "CID" => self.desc.cid = value.to_string(),
            "parentCID" => self.desc.parent_cid = value.to_string(),
            "createType" => self.desc.create_type = strip_quotes(value).to_string(),
            "parentFileNameHint" => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported VMDK differential image (delta link)",
                ))
            }
            "ddb.geometry.sectors" => self.desc.sectors = parse_desc_value(key, value)?,
            "ddb.geometry.heads" => self.desc.heads = parse_desc_value(key, value)?,
            "ddb.geometry.cylinders" => self.desc.cylinders = parse_desc_value(key, value)?,

            // Ignore unidentified "ddb." (The Disk Database) items
            key if key.starts_with("ddb.") => (),

            key => {
                return Err(invalid_data(format!(
                    "Unrecognized VMDK descriptor file key '{key}'"
                )))
            }
        }

        Ok(())
    }

    /// Read and parse the VMDK descriptor by reading in lines until we find the end
    async fn parse_descriptor_file(&mut self) -> io::Result<()> {
        let desc_file_sz = self.descriptor_file.size()?;
        if desc_file_sz < 4 {
            return Err(invalid_data("VMDK descriptor file too short"));
        }
        // Sanity check to avoid unbounded allocation
        if desc_file_sz > 2 * 1024 * 1024 {
            return Err(invalid_data(
                "VMDK descriptor file too long (max. 2 MB supported)",
            ));
        }

        let desc_file_sz: usize = desc_file_sz.try_into().unwrap();
        let mut desc_file = IoBuffer::new(desc_file_sz, self.descriptor_file.mem_align())?;
        self.descriptor_file.read(desc_file.as_mut(), 0).await?;

        let desc_file = desc_file.as_ref().into_slice();

        // Check if it's a SPARSE format, bail it out now
        if u32::from_le_bytes(desc_file[..4].try_into().unwrap()) == VMDK4_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unsupported VMDK sparse data file",
            ));
        }

        for (line_i, line) in desc_file.split(|chr| *chr == b'\n').enumerate() {
            let line = str::from_utf8(line).map_err(|e| {
                invalid_data(format!(
                    "{}: Line {}: {e}",
                    self.descriptor_file,
                    line_i + 1
                ))
            })?;

            self.parse_descriptor_line(line)
                .err_context(|| format!("{}: Line {}", self.descriptor_file, line_i + 1))?;
        }

        self.error_out_unsupported_version()?;
        self.size = self
            .parsed_extents
            .iter()
            .try_fold(0u64, |sum, extent| {
                let sectors = extent.sectors;
                let size = sectors.checked_mul(VMDK_SECTOR_SIZE).ok_or_else(|| {
                    invalid_data(format!(
                        "Extent size overflow: {sectors} * {VMDK_SECTOR_SIZE}"
                    ))
                })?;
                sum.checked_add(size)
                    .ok_or_else(|| invalid_data(format!("Extent offset overflow: {sum} + {size}")))
            })?
            .into();

        Ok(())
    }

    /// Internal implementation for opening a VMDK image.
    async fn do_open(
        descriptor_file: S,
        storage_open_options: StorageOpenOptions,
    ) -> io::Result<Self> {
        let mut vmdk = Vmdk {
            descriptor_file: Arc::new(descriptor_file),
            parent_type: PhantomData,
            desc: VmdkDesc {
                version: 0,
                cid: String::new(),
                parent_cid: String::new(),
                create_type: String::new(),
                sectors: 0,
                heads: 0,
                cylinders: 0,
            },
            parsed_extents: vec![],
            extents: vec![],
            size: 0.into(),
            storage_open_options,
        };

        vmdk.parse_descriptor_file().await?;
        Ok(vmdk)
    }

    /// Opens a VMDK file.
    ///
    /// This will not open any other storage objects needed, i.e. no extent data files.  Handling
    /// those manually is not yet supported, so you have to make use of the implicit references
    /// given in the image header, for which you can use
    /// [`Vmdk::open_implicit_dependencies_gated()`].
    pub async fn open_image(descriptor_file: S, writable: bool) -> io::Result<Self> {
        if writable {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "No VMDK write support",
            ));
        }
        Self::do_open(descriptor_file, StorageOpenOptions::new()).await
    }

    /// Open all implicit dependencies.
    ///
    /// In the case of VMDK, these are the extent data files.
    pub async fn open_implicit_dependencies_gated<G: ImplicitOpenGate<S>>(
        &mut self,
        mut gate: G,
    ) -> io::Result<()> {
        if self.extents.is_empty() {
            let mut in_disk_offset = 0;
            for extent in &self.parsed_extents {
                let opened = self
                    .open_implicit_extent(extent, in_disk_offset, &mut gate)
                    .await?;
                in_disk_offset = opened.disk_range.end;
                self.extents.push(opened);
            }
        }

        Ok(())
    }

    /// Return the extent covering `offset`, if any.
    fn get_extent_at(&self, offset: u64) -> Option<&VmdkExtent<S>> {
        self.extents
            .binary_search_by(|extent| {
                if extent.disk_range.contains(&offset) {
                    cmp::Ordering::Equal
                } else if extent.disk_range.end <= offset {
                    // disk_range is half-open [start, end); use <= so that
                    // end == offset returns Less, not Greater.
                    cmp::Ordering::Less
                } else {
                    cmp::Ordering::Greater
                }
            })
            .ok()
            .map(|index| &self.extents[index])
    }
}

impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Display for Vmdk<S, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "vmdk[{}]", self.descriptor_file)
    }
}

#[maybe_async(?Send)]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> FormatDriverInstance for Vmdk<S, F> {
    type Storage = S;

    fn format(&self) -> Format {
        Format::Vmdk
    }

    async unsafe fn probe(storage: &S) -> io::Result<bool>
    where
        Self: Sized,
    {
        // Check that the potential descriptor file has a reasonable length, is utf8, and contains
        // a supported `version` key.
        // (Or has the `VMDK4_MAGIC`.)

        let desc_file_size = storage.size()?;
        if !(4..=2 * 1024 * 1024).contains(&desc_file_size) {
            return Ok(false);
        }

        let desc_file_size: usize = desc_file_size.try_into().unwrap();
        let mut desc_file = IoBuffer::new(desc_file_size, storage.mem_align())?;
        storage.read(desc_file.as_mut(), 0).await?;

        let desc_file = desc_file.as_ref().into_slice();
        if u32::from_le_bytes(desc_file[..4].try_into().unwrap()) == VMDK4_MAGIC {
            return Ok(true);
        }

        for line in desc_file.split(|chr| *chr == b'\n') {
            let Ok(line) = str::from_utf8(line) else {
                return Ok(false);
            };

            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == "version" {
                let Ok(version) = value.trim().parse() else {
                    return Ok(false);
                };
                return Ok(VMDK_VERSION_RANGE.contains(&version));
            }
        }

        Ok(false)
    }

    fn size(&self) -> u64 {
        self.size.load(Ordering::Relaxed)
    }

    fn zero_granularity(&self) -> Option<u64> {
        None
    }

    fn collect_storage_dependencies(&self) -> Vec<&S> {
        let mut v = vec![self.descriptor_file.as_ref()];
        for e in &self.extents {
            let Some(storage) = e.storage.as_ref() else {
                continue;
            };
            match storage {
                VmdkStorage::Flat { file, offset: _ } => v.push(file),
                VmdkStorage::Zero => (),
            }
        }
        v
    }

    fn writable(&self) -> bool {
        false
    }

    #[allow(clippy::needless_lifetimes)] // Elidable in sync, but async needs a named lifetime for the boxed future bound
    async fn get_mapping<'a>(
        &'a self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(ShallowMapping<'a, S>, u64)> {
        let max_length = match self.size().checked_sub(offset) {
            None | Some(0) => return Ok((ShallowMapping::Eof {}, 0)),
            Some(remaining) => cmp::min(remaining, max_length),
        };

        let Some(extent) = self.get_extent_at(offset) else {
            return Ok((ShallowMapping::Eof {}, 0));
        };
        // `get_extent_at` guarantees this won’t underflow
        let in_extent_offset = offset - extent.disk_range.start;

        let writable = match extent.access_type {
            VmdkAccessType::RW => true,
            VmdkAccessType::RdOnly => false,
            VmdkAccessType::NoAccess => {
                // Is that right?  Should this be ::Special?
                return Err(io::Error::other("NOACCESS extent is accessed"));
            }
        };

        // `access_type != NoAccess`, so `unwrap()` is safe
        let mapping = match extent.storage.as_ref().unwrap() {
            VmdkStorage::Flat {
                file,
                offset: base_offset,
            } => ShallowMapping::Raw {
                storage: file,
                offset: base_offset.checked_add(in_extent_offset).ok_or_else(|| {
                    invalid_data(format!(
                        "Extent offset overflow: {base_offset} + {in_extent_offset}"
                    ))
                })?,
                writable,
            },

            VmdkStorage::Zero => ShallowMapping::Zero { explicit: true },
        };

        Ok((
            mapping,
            cmp::min(max_length, extent.disk_range.end - offset),
        ))
    }

    #[allow(clippy::needless_lifetimes)] // Elidable in sync, but async needs a named lifetime for the boxed future bound
    async fn ensure_data_mapping<'a>(
        &'a self,
        _offset: u64,
        _length: u64,
        _overwrite: bool,
    ) -> io::Result<(&'a S, u64, u64)> {
        Err(io::Error::other("Image is read-only"))
    }

    async fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    async unsafe fn invalidate_cache(&self) -> io::Result<()> {
        Ok(())
    }

    async fn resize_grow(&self, _new_size: u64, _prealloc_mode: PreallocateMode) -> io::Result<()> {
        Err(io::Error::other("Image is read-only"))
    }

    async fn resize_shrink(&mut self, _new_size: u64) -> io::Result<()> {
        Err(io::Error::other("Image is read-only"))
    }
}

/// Options builder for opening a VMDK image.
pub struct VmdkOpenBuilder<S: Storage + 'static, F: WrappedFormat<S> + 'static = FormatAccess<S>>(
    FormatDriverBuilderBase<S>,
    PhantomData<F>,
);

#[maybe_async(AFIT)]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> FormatDriverBuilder<S>
    for VmdkOpenBuilder<S, F>
{
    type Format = Vmdk<S, F>;
    const FORMAT: Format = Format::Vmdk;

    fn new(image: S) -> Self {
        VmdkOpenBuilder(FormatDriverBuilderBase::new(image), PhantomData)
    }

    fn new_path<P: AsRef<Path>>(path: P) -> Self {
        VmdkOpenBuilder(FormatDriverBuilderBase::new_path(path), PhantomData)
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
        if self.0.get_writable() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "No VMDK write support",
            ));
        }

        let file = self.0.open_image(&mut gate).await?;
        let mut vmdk = Vmdk::open_image(file, false).await?;
        vmdk.open_implicit_dependencies_gated(gate).await?;
        Ok(vmdk)
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
