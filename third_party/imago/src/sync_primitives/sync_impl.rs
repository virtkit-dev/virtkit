//! Wrappers around `std::sync` types that hide lock poisoning by panicking in case of it.

use std::sync::{
    Mutex as StdMutex, MutexGuard, RwLock as StdRwLock, RwLockReadGuard, RwLockWriteGuard,
};

/// Wrapper around [`std::sync::Mutex`], panicking on poisoned locks.
#[derive(Debug, Default)]
pub(crate) struct Mutex<T>(StdMutex<T>);

impl<T> Mutex<T> {
    /// Create a new mutex.
    pub fn new(t: T) -> Self {
        Mutex(StdMutex::new(t))
    }

    /// Lock the mutex, propagating poison as a panic.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().expect("lock poisoned")
    }
}

/// Wrapper around [`std::sync::RwLock`], panicking on poisoned locks.
#[derive(Debug, Default)]
pub(crate) struct RwLock<T>(StdRwLock<T>);

impl<T> RwLock<T> {
    /// Create a new read-write lock.
    pub fn new(t: T) -> Self {
        RwLock(StdRwLock::new(t))
    }

    /// Acquire a read lock, propagating poison as a panic.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().expect("lock poisoned")
    }

    /// Acquire a write lock, propagating poison as a panic.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().expect("lock poisoned")
    }
}
