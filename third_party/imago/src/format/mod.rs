//! Core functionality.
//!
//! Provides access to different image formats via `FormatAccess` objects.

pub mod access;
pub mod builder;
pub mod drivers;
pub mod gate;
#[cfg(feature = "sync-wrappers")]
pub mod sync_wrappers;
pub mod wrapped;

/// List of imago formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Format {
    /// Raw format (no metadata at all, everything stored 1:1)
    Raw,

    /// Qcow2 format (version 2 or 3)
    Qcow2,

    /// VMDK format
    Vmdk,
}

/// Format layer preallocation modes.
///
/// When resizing or create an image, this mode determines whether and how the new data range is to
/// be preallocated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreallocateMode {
    /// No preallocation.
    ///
    /// Reading the new range may return random data.
    None,

    /// Ensure range reads as zeroes.
    ///
    /// Does not necessarily allocate data, but has to ensure the new range will read back as
    /// zeroes (e.g. a backing file’s contents must not show through).
    Zero,

    /// Metadata preallocation.
    ///
    /// Do not write data, but ensure all blocks are mapped as data.  For images without a backing
    /// file, that data must read as zeroes.  For images with a backing file, that data must be the
    /// same as the backing file’s contents, and zeroes beyond the backing file EOF.
    FormatAllocate,

    /// Metadata and extent preallocation.
    ///
    /// Same as `FormatAllocate`, but also allocate all blocks on the underlying storage.
    FullAllocate,

    /// Full data preallocation.
    ///
    /// Write data to the whole range.  For images without a backing file, that data must read as
    /// zeroes.  For images with a backing file, that data must be the same as the backing file’s
    /// contents, and zeroes beyond the backing file EOF.
    WriteData,
}
