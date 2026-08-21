// #![feature(async_drop)] -- enable with async-drop
#![cfg_attr(all(doc, nightly), feature(doc_cfg))] // expect nightly for doc
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

//! Provides access to VM image formats.
//!
//! Simple example (requires the `sync` feature):
//! ```no_run
//! # #[cfg(feature = "sync")]
//! # let _ = || -> Result<(), std::io::Error> {
//! use imago::file::File;
//! use imago::qcow2::Qcow2;
//! use imago::{FormatAccess, FormatDriverBuilder, PermissiveImplicitOpenGate};
//!
//! let qcow2 =
//!     Qcow2::<File>::builder_path("image.qcow2").open(PermissiveImplicitOpenGate::default())?;
//!
//! let qcow2 = FormatAccess::new(qcow2);
//!
//! let mut buf = vec![0u8; 512];
//! qcow2.read(&mut buf, 0)?;
//! # Ok(())
//! # };
//! ```
//!
//! Another example, using the native async interface instead of sync wrapper functions, explicitly
//! overriding the implicit references contained in qcow2 files, and showcasing using different
//! types of storage (specifically normal files and null storage):
//! ```no_run
//! # #[cfg(feature = "async")]
//! # let _ = async {
//! use imago::file::File;
//! use imago::null::Null;
//! use imago::qcow2::Qcow2;
//! use imago::raw::Raw;
//! use imago::{
//!     DenyImplicitOpenGate, DynStorage, FormatAccess, FormatDriverBuilder,
//!     PermissiveImplicitOpenGate, Storage, StorageOpenOptions,
//! };
//! use std::sync::Arc;
//!
//! // Produce qcow2 instance with arbitrary (and potentially mixed) storage instances
//! // (By using `Box<dyn DynStorage>` as the `Storage` type.)
//!
//! let backing_storage: Box<dyn DynStorage> = Box::new(Null::new(0));
//! let backing = Raw::builder(backing_storage)
//!     .open(DenyImplicitOpenGate::default())
//!     .await?;
//! let backing = Arc::new(FormatAccess::new(backing));
//!
//! // `Box<dyn DynStorage>::open()` defaults to using the `imago::file::File` driver, so we can
//! // use paths with `Box<dyn DynStorage>`, too.
//! // Despite explicitly setting a backing image, we still need `PermissiveImplicitOpenGate`
//! // instead of `DenyImplicitOpenGate`, because `builder_path()` will need to implicitly open
//! // that storage object.  Passing an explicitly opened storage object via `builder()` would
//! // remedy that.
//! let qcow2 = Qcow2::builder_path("image.qcow2")
//!     .storage_open_options(StorageOpenOptions::new().direct(true))
//!     .write(true)
//!     .backing(Some(Arc::clone(&backing)))
//!     .open(PermissiveImplicitOpenGate::default())
//!     .await?;
//!
//! let qcow2 = FormatAccess::new(qcow2);
//!
//! let mut buf = vec![0u8; 512];
//! qcow2.read(&mut buf, 0).await?;
//!
//! qcow2.flush().await?;
//! # Ok::<(), std::io::Error>(())
//! # };
//! ```
//!
//! # Flushing
//!
//! In async mode, given that `AsyncDrop` is not stable yet (and probably will not be stable for a
//! long time), callers must ensure that images are properly flushed before dropping them, i.e.
//! call `.flush().await` on any image that is not read-only.
//!
//! (The synchronous wrapper `SyncFormatAccess` does perform a synchronous flush in its `Drop`
//! implementation.)
//!
//! In sync mode, [`FormatAccess`] implements `Drop` and flushes automatically.
//!
//! # Features
//!
//! - `async` *(default)*: Build with `async` support, which requires `tokio` (for async locking),
//!   `async-trait`, and `futures`.
//!
//! - `sync`: Build as a fully synchronous library, with no `async`, no `tokio` dependency.  All
//!   I/O methods become plain `fn`.  Enable via
//!   `imago = { default-features = false, features = ["sync"] }`.
//!   Incompatible with `sync-wrappers`.
//!
//! - `sync-wrappers`: Provide synchronous wrappers for the native `async` interface.  Note that
//!   these build a `tokio` runtime in which they run the `async` functions, so prefer using `sync`
//!   instead, which provides native synchronous methods without the `tokio` overhead.
//!   Incompatible with `sync`, and planned to be deprecated in the future.
//!
//! - `vm-memory`: Provide conversion functions
//!   [`IoVector::from_volatile_slice`](io_buffers::IoVector::from_volatile_slice) and
//!   [`IoVectorMut::from_volatile_slice`](io_buffers::IoVectorMut::from_volatile_slice) to convert
//!   the vm-memory crate’s `[VolatileSlice]` arrays into imago’s native I/O vectors.

#[cfg(not(any(feature = "async", feature = "sync")))]
compile_error!("Either the `async` feature (included in defaults) or `sync` must be enabled!");

#[cfg(all(feature = "sync-wrappers", feature = "sync"))]
compile_error!("The `sync` feature conflicts with `sync-wrappers`. Consider using `sync` alone.");

#[cfg(all(feature = "async", feature = "sync"))]
compile_error!(
    "The `async` and `sync` features are mutually exclusive. \
    `async` is in defaults, so use `--no-default-features --features=sync` for sync mode."
);

pub mod annotated;
mod async_lru_cache;
pub mod file;
pub mod format;
pub mod io_buffers;
mod macros;
mod misc_helpers;
pub mod null;
pub mod qcow2;
pub mod raw;
pub mod storage;
mod sync_primitives;
pub mod vmdk;

pub use format::access::{FormatAccess, Mapping};
pub use format::builder::{FormatCreateBuilder, FormatDriverBuilder};
pub use format::drivers::ShallowMapping;
pub use format::gate::{DenyImplicitOpenGate, PermissiveImplicitOpenGate};
#[cfg(feature = "sync-wrappers")]
pub use format::sync_wrappers::SyncFormatAccess;
pub use storage::ext::StorageExt;
pub use storage::{DynStorage, Storage, StorageCreateOptions, StorageOpenOptions};
