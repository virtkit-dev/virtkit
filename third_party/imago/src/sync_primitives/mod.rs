//! Feature-agnostic synchronization primitives
//!
//! In async mode, re-exports `tokio::sync` types.  In sync mode, provides `std::sync` wrappers
//! with a matching API.

#[cfg(feature = "sync")]
mod sync_impl;

#[cfg(feature = "async")]
#[allow(unused_imports)]
pub(crate) use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(feature = "sync")]
#[allow(unused_imports)]
pub(crate) use std::sync::{MutexGuard, RwLockReadGuard, RwLockWriteGuard};
#[cfg(feature = "sync")]
#[allow(unused_imports)]
pub(crate) use sync_impl::{Mutex, RwLock};
