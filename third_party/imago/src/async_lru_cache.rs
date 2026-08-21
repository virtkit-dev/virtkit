//! Provides a least-recently-used cache with async access.
//!
//! To operate, this cache is bound to an I/O back-end object that provides the loading and
//! flushing of cache entries.
//!
//! The cache holds `map.write()` during eviction I/O, so cross-cache flush dependencies
//! (e.g. “flush cache B before evicting from cache A”) must be handled externally (see e.g.
//! qcow2’s [`MetadataCaches`](../qcow2/cache/struct.MetadataCaches.html)).

#![allow(dead_code)]

use crate::sync_primitives::{RwLock, RwLockWriteGuard};
#[cfg(feature = "async")]
use futures::stream::{FuturesUnordered, StreamExt};
use maybe_async::maybe_async;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{io, mem};
use tracing::{error, instrument, trace};

/// Cache entry structure, wrapping the cached object.
pub(crate) struct AsyncLruCacheEntry<V> {
    /// Cached object.
    ///
    /// Always set during operation, only cleared when trying to unwrap the `Arc` on eviction.
    value: Option<Arc<V>>,

    /// When this entry was last accessed.
    last_used: AtomicUsize,
}

/// Least-recently-used cache with async access.
struct AsyncLruCacheInner<
    Key: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
    Value: Send + Sync,
    IoBackend: AsyncLruCacheBackend<Key = Key, Value = Value>,
> {
    /// I/O back-end that performs loading and flushing of cache entries.
    backend: IoBackend,

    /// Cache entries.
    map: RwLock<HashMap<Key, AsyncLruCacheEntry<Value>>>,

    /// Monotonically increasing counter to generate “timestamps”.
    lru_timer: AtomicUsize,

    /// Upper limit of how many entries to cache.
    limit: usize,
}

/// Least-recently-used cache with async access.
///
/// Keeps the least recently used entries up to a limited count.  Accessing and flushing is
/// async-aware.
///
/// `K` is the key used to uniquely identify cache entries, `V` is the cached data.
pub(crate) struct AsyncLruCache<
    K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
    V: Send + Sync,
    B: AsyncLruCacheBackend<Key = K, Value = V>,
>(Arc<AsyncLruCacheInner<K, V, B>>);

/// Provides loading and flushing for cache entries.
#[maybe_async(AFIT)]
pub(crate) trait AsyncLruCacheBackend: Send + Sync {
    /// Key type.
    type Key: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync;
    /// Value (object) type.
    type Value: Send + Sync;

    /// Load the given object.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn load(&self, key: Self::Key) -> io::Result<Self::Value>;

    /// Flush the given object.
    ///
    /// The implementation should itself check whether the object is dirty; `flush()` is called for
    /// all evicted cache entries, regardless of whether they actually are dirty or not.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn flush(&self, key: Self::Key, value: &Self::Value) -> io::Result<()>;

    /// Drop the given object without flushing.
    ///
    /// The cache owner is invalidating the cache, evicting all objects without flushing them.  If
    /// dropping the object as-is would cause problems (e.g. because it is verified not to be
    /// dirty), those problems need to be resolved here.
    ///
    /// # Safety
    /// Depending on the nature of the cache, this operation may be unsafe.  Must only be performed
    /// if the cache owner requested it and guarantees it is safe.
    unsafe fn evict(&self, key: Self::Key, value: Self::Value);
}

#[maybe_async]
impl<
        K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
        V: Send + Sync,
        B: AsyncLruCacheBackend<Key = K, Value = V>,
    > AsyncLruCache<K, V, B>
{
    /// Create a new cache.
    ///
    /// `size` is the maximum number of entries to keep in the cache.
    pub fn new(backend: B, size: usize) -> Self {
        AsyncLruCache(Arc::new(AsyncLruCacheInner {
            backend,
            map: Default::default(),
            lru_timer: AtomicUsize::new(0),
            limit: size,
        }))
    }

    /// Retrieve an entry from the cache.
    ///
    /// If there is no entry yet, load it via the backend.
    ///
    /// If there is no more room in the cache for a new entry and `may_flush` is true, flush out
    /// the oldest entry via `flush()` to make space.
    ///
    /// `Ok(None)` is returned if and only if there is no more room in the cache and `may_flush` is
    /// false.
    pub async fn get_or_insert(&self, key: K, may_flush: bool) -> io::Result<Option<Arc<V>>> {
        self.0.get_or_insert(key, may_flush).await
    }

    /// Force-insert the given object into the cache.
    ///
    /// If there is an existing object under that key and `may_flush` is true, it is flushed first.
    ///
    /// If there is no existing object yet, i.e. a new entry must be created, but there is no more
    /// room in the cache for this new entry, and `may_flush` is true, the oldest entry is flushed
    /// out first to make space.
    ///
    /// On success, `Ok(true)` is returned.  `Ok(false)` is returned if and only if `may_flush` was
    /// false, but an older cache entry would need to be flushed.
    pub async fn insert(&self, key: K, value: Arc<V>, may_flush: bool) -> io::Result<bool> {
        self.0.insert(key, value, may_flush).await
    }

    /// Flush all cache entries.
    ///
    /// Those entries are not evicted, but remain in the cache.
    pub async fn flush(&self) -> io::Result<()> {
        self.0.flush().await
    }

    /// Evict all cache entries.
    ///
    /// Evicts all cache entries without flushing them.
    ///
    /// # Safety
    /// Depending on the nature of the cache, this operation may be unsafe.  Perform at your own
    /// risk.
    pub async unsafe fn invalidate(&self) -> io::Result<()> {
        unsafe { self.0.invalidate() }.await
    }
}

#[maybe_async]
impl<
        K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
        V: Send + Sync,
        B: AsyncLruCacheBackend<Key = K, Value = V>,
    > AsyncLruCacheInner<K, V, B>
{
    /// Ensure there is at least one free entry in the cache.
    ///
    /// If there are free entries, return `Ok(true)` immediately.
    ///
    /// If there are no free entries and `may_evict` is true, evict the least-recently-used entry
    /// by flushing it via `backend.flush()`, then return `Ok(true)` on success.
    ///
    /// If there are no free entries and `may_evict` is false, return `Ok(false)`.
    ///
    /// Note that this function holds the write lock for its entire lifetime, so `backend.flush()`
    /// must not call back into this cache directly or indirectly.  Cross-cache flush ordering must
    /// be handled externally (e.g. by qcow2’s
    /// [`MetadataCaches`](../qcow2/cache/struct.MetadataCaches.html)).
    #[instrument(
        level = "trace",
        name = "AsyncLruCache::ensure_free_entry",
        skip_all,
        fields(self = &self as *const _ as usize),
    )]
    async fn ensure_free_entry(
        &self,
        map: &mut RwLockWriteGuard<'_, HashMap<K, AsyncLruCacheEntry<V>>>,
        may_evict: bool,
    ) -> io::Result<bool> {
        if map.len() < self.limit {
            return Ok(true);
        } else if !may_evict {
            return Ok(false);
        }

        while map.len() >= self.limit {
            trace!("{} / {} used", map.len(), self.limit);

            let now = self.lru_timer.load(Ordering::Relaxed);
            let oldest = map
                .iter()
                .filter(|(_key, entry)| Arc::strong_count(entry.value()) == 1)
                .fold((0, None), |oldest, (key, entry)| {
                    // Users must not create weak references, and so we know that with a `strong_count`
                    // of 1 (while holding the map’s write lock), no one can access this entry anymore
                    // and we could safely drop it.
                    assert_eq!(Arc::weak_count(entry.value()), 0);

                    let age = now.wrapping_sub(entry.last_used.load(Ordering::Relaxed));
                    if age >= oldest.0 {
                        (age, Some(*key))
                    } else {
                        oldest
                    }
                });

            let Some(oldest_key) = oldest.1 else {
                error!("Cannot evict entry from cache; everything is in use");
                return Err(io::Error::other(
                    "Cannot evict entry from cache; everything is in use",
                ));
            };

            trace!("Removing entry with key {oldest_key:?}, aged {}", oldest.0);

            let oldest_entry = map.remove(&oldest_key).unwrap();

            // We checked `strong_count` above to be 1, and there are no weak references, so the
            // only reference to this entry must have been the one in the map.  We held the write
            // lock throughout, there was no await point between the check and here, so the
            // `strong_count` must still be 1 and we can thus safely unwrap the `Arc`.
            let evicted_object = Arc::try_unwrap(oldest_entry.value.unwrap())
                .unwrap_or_else(|_| panic!("entry has gained external references"));

            trace!("Flushing {oldest_key:?}");
            if let Err(err) = self.backend.flush(oldest_key, &evicted_object).await {
                map.insert(
                    oldest_key,
                    AsyncLruCacheEntry {
                        value: Some(Arc::new(evicted_object)),
                        last_used: oldest_entry.last_used.load(Ordering::Relaxed).into(),
                    },
                );
                return Err(err);
            }
        }

        Ok(true)
    }

    /// Retrieve an entry from the cache.
    ///
    /// If there is no entry yet, load it via the backend.
    ///
    /// If there is no more room in the cache for a new entry and `may_flush` is true, flush out
    /// the oldest entry via `flush()` to make space.
    ///
    /// `Ok(None)` is returned if and only if there is no more room in the cache and `may_flush` is
    /// false.
    ///
    /// Users must not create weak references to the returned `Arc`.
    async fn get_or_insert(&self, key: K, may_flush: bool) -> io::Result<Option<Arc<V>>> {
        {
            let map = self.map.read().await;
            if let Some(entry) = map.get(&key) {
                entry.last_used.store(
                    self.lru_timer.fetch_add(1, Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                return Ok(Some(Arc::clone(entry.value())));
            }
        }

        let mut map = self.map.write().await;
        if let Some(entry) = map.get(&key) {
            entry.last_used.store(
                self.lru_timer.fetch_add(1, Ordering::Relaxed),
                Ordering::Relaxed,
            );
            return Ok(Some(Arc::clone(entry.value())));
        }

        if !self.ensure_free_entry(&mut map, may_flush).await? {
            return Ok(None);
        }

        let object = Arc::new(self.backend.load(key).await?);

        let new_entry = AsyncLruCacheEntry {
            value: Some(Arc::clone(&object)),
            last_used: AtomicUsize::new(self.lru_timer.fetch_add(1, Ordering::Relaxed)),
        };
        map.insert(key, new_entry);

        Ok(Some(object))
    }

    /// Force-insert the given object into the cache.
    ///
    /// If there is an existing object under that key and `may_flush` is true, it is flushed first.
    ///
    /// If there is no existing object yet, i.e. a new entry must be created, but there is no more
    /// room in the cache for this new entry, and `may_flush` is true, the oldest entry is flushed
    /// out first to make space.
    ///
    /// On success, `Ok(true)` is returned.  `Ok(false)` is returned if and only if `may_flush` was
    /// false, but an older cache entry would need to be flushed.
    async fn insert(&self, key: K, value: Arc<V>, may_flush: bool) -> io::Result<bool> {
        let mut map = self.map.write().await;
        if let Some(entry) = map.get_mut(&key) {
            if !may_flush {
                return Ok(false);
            }

            entry.last_used.store(
                self.lru_timer.fetch_add(1, Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.backend.flush(key, entry.value()).await?;
            entry.value = Some(value);
        } else {
            if !self.ensure_free_entry(&mut map, may_flush).await? {
                return Ok(false);
            }

            let new_entry = AsyncLruCacheEntry {
                value: Some(value),
                last_used: AtomicUsize::new(self.lru_timer.fetch_add(1, Ordering::Relaxed)),
            };
            map.insert(key, new_entry);
        }

        Ok(true)
    }

    /// Flush all cache entries.
    ///
    /// Those entries are not evicted, but remain in the cache.
    #[instrument(
        level = "trace",
        name = "AsyncLruCache::flush",
        skip_all,
        fields(self = &self as *const _ as usize)
    )]
    async fn flush(&self) -> io::Result<()> {
        #[cfg(feature = "async")]
        let mut futs = FuturesUnordered::new();

        let map = self.map.read().await;
        let mut first_err: Option<io::Error> = None;
        for (key, entry) in map.iter() {
            let key = *key;
            trace!("Flushing {key:?}");
            #[cfg(feature = "async")]
            futs.push({
                let object = Arc::clone(entry.value());
                async move { self.backend.flush(key, &object).await }
            });
            #[cfg(feature = "sync")]
            if let Err(e) = self.backend.flush(key, entry.value()) {
                first_err.get_or_insert(e);
            }
        }

        #[cfg(feature = "async")]
        while let Some(result) = futs.next().await {
            if let Err(e) = result {
                first_err.get_or_insert(e);
            }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    /// Evict all cache entries.
    ///
    /// Evicts all cache entries without flushing them.
    ///
    /// # Safety
    /// Depending on the nature of the cache, this operation may be unsafe.  Perform at your own
    /// risk.
    #[instrument(
        level = "trace",
        name = "AsyncLruCache::invalidate",
        skip_all,
        fields(self = &self as *const _ as usize)
    )]
    async unsafe fn invalidate(&self) -> io::Result<()> {
        let mut in_use = Vec::new();

        let mut map = self.map.write().await;
        // Clear the map; we could use `.drain()`, but doing this allows the following loop to put
        // objects back into the new map in case they cannot be evicted.
        let old_map = mem::take(&mut *map);
        for (key, mut entry) in old_map {
            let object = entry.value.take().unwrap();
            trace!("Evicting {key:?}");
            match Arc::try_unwrap(object) {
                Ok(object) => {
                    // Caller guarantees this is safe
                    unsafe { self.backend.evict(key, object) };
                }

                Err(arc) => {
                    trace!("Entry is still in use, retaining it");
                    entry.value = Some(arc);
                    map.insert(key, entry);
                    in_use.push(key);
                }
            }
        }

        if in_use.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Cannot invalidate cache, entries still in use: {}",
                in_use
                    .iter()
                    .map(|key| format!("{key:?}"))
                    .collect::<Vec<String>>()
                    .join(", "),
            )))
        }
    }
}

impl<V> AsyncLruCacheEntry<V> {
    /// Return the cached object.
    fn value(&self) -> &Arc<V> {
        self.value.as_ref().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Minimal backend for testing: load returns the key, flush is a no-op
    struct DummyBackend;

    #[maybe_async(AFIT)]
    impl AsyncLruCacheBackend for DummyBackend {
        type Key = usize;
        type Value = usize;

        async fn load(&self, key: usize) -> io::Result<usize> {
            Ok(key)
        }

        async fn flush(&self, _key: usize, _value: &usize) -> io::Result<()> {
            Ok(())
        }

        unsafe fn evict(&self, _key: usize, _value: usize) {}
    }

    /// Backend that records flush calls in order
    #[derive(Default)]
    struct RecordingBackend {
        flushed: std::sync::Mutex<Vec<(usize, usize)>>,
    }

    #[maybe_async(AFIT)]
    impl AsyncLruCacheBackend for RecordingBackend {
        type Key = usize;
        type Value = usize;

        async fn load(&self, key: usize) -> io::Result<usize> {
            Ok(key)
        }

        async fn flush(&self, key: usize, value: &usize) -> io::Result<()> {
            self.flushed.lock().unwrap().push((key, *value));
            Ok(())
        }

        unsafe fn evict(&self, _key: usize, _value: usize) {}
    }

    #[maybe_async(AFIT)]
    impl<B: AsyncLruCacheBackend> AsyncLruCacheBackend for Arc<B> {
        type Key = <B as AsyncLruCacheBackend>::Key;
        type Value = <B as AsyncLruCacheBackend>::Value;

        async fn load(&self, key: Self::Key) -> io::Result<Self::Value> {
            (**self).load(key).await
        }

        async fn flush(&self, key: Self::Key, value: &Self::Value) -> io::Result<()> {
            (**self).flush(key, value).await
        }

        unsafe fn evict(&self, key: Self::Key, value: Self::Value) {
            unsafe { (**self).evict(key, value) }
        }
    }

    /// `flush()` must continue past individual entry errors and report the first one, not stop at
    /// the first failure
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_flush_continues_past_errors() {
        #[derive(Default)]
        struct FailOddBackend {
            flush_count: AtomicUsize,
        }

        #[maybe_async(AFIT)]
        impl AsyncLruCacheBackend for FailOddBackend {
            type Key = usize;
            type Value = usize;

            async fn load(&self, key: usize) -> io::Result<usize> {
                Ok(key)
            }

            async fn flush(&self, key: usize, _value: &usize) -> io::Result<()> {
                self.flush_count.fetch_add(1, Ordering::Relaxed);
                if key % 2 == 1 {
                    Err(io::Error::other("odd key"))
                } else {
                    Ok(())
                }
            }

            unsafe fn evict(&self, _key: usize, _value: usize) {}
        }

        const ENTRIES: usize = 42;

        let backend = Arc::new(FailOddBackend::default());
        let cache = AsyncLruCache::new(Arc::clone(&backend), ENTRIES);

        for i in 0..ENTRIES {
            cache.get_or_insert(i, false).await.unwrap().unwrap();
        }

        let err = cache.flush().await.unwrap_err();
        assert!(err.to_string().contains("odd key"));

        assert_eq!(backend.flush_count.load(Ordering::Relaxed), ENTRIES);
    }

    /// Eviction must remove the least-recently-used entry
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_lru_eviction_order() {
        const ENTRIES: usize = 3;

        let backend = Arc::new(RecordingBackend::default());
        let cache = AsyncLruCache::new(Arc::clone(&backend), ENTRIES);

        for i in 0..ENTRIES {
            cache.get_or_insert(i, false).await.unwrap().unwrap();
        }

        // Touch key 0 so it becomes most-recently-used
        cache.get_or_insert(0, false).await.unwrap().unwrap();

        // Insert one more key — must evict key 1 (the oldest untouched)
        let entry = cache.get_or_insert(ENTRIES, false).await.unwrap();
        assert_eq!(entry, None);
        cache.get_or_insert(ENTRIES, true).await.unwrap().unwrap();

        assert_eq!(*backend.flushed.lock().unwrap(), [(1, 1)]);
    }

    /// Entries with external `Arc` references must not be evicted
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_in_use_entries_not_evicted() {
        let backend = Arc::new(RecordingBackend::default());
        let cache = AsyncLruCache::new(Arc::clone(&backend), 2);

        let held = cache.get_or_insert(0, false).await.unwrap().unwrap();
        cache.get_or_insert(1, false).await.unwrap().unwrap();

        // Insert key 2 — key 0 is oldest but in use, so key 1 must be evicted
        let entry = cache.get_or_insert(2, false).await.unwrap();
        assert_eq!(entry, None);
        cache.get_or_insert(2, true).await.unwrap().unwrap();

        assert_eq!(*backend.flushed.lock().unwrap(), [(1, 1)]);
        assert_eq!(*held, 0);
    }

    /// When all entries are in use, eviction must fail with an error
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_cache_full_all_in_use() {
        const ENTRIES: usize = 23;

        let cache = AsyncLruCache::new(DummyBackend, ENTRIES);

        let mut held = vec![];
        for i in 0..ENTRIES {
            held.push(cache.get_or_insert(i, false).await.unwrap().unwrap());
        }

        let entry = cache.get_or_insert(ENTRIES, false).await.unwrap();
        assert_eq!(entry, None);
        let err = cache.get_or_insert(ENTRIES, true).await.unwrap_err();
        assert!(err.to_string().contains("everything is in use"));
    }

    /// `invalidate()` must retain entries that are still in use and evict the rest
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_invalidate_retains_in_use() {
        let cache = AsyncLruCache::new(DummyBackend, 16);

        let held = cache.get_or_insert(0, false).await.unwrap().unwrap();
        cache.get_or_insert(1, false).await.unwrap().unwrap();
        cache.get_or_insert(2, false).await.unwrap().unwrap();

        let err = unsafe { cache.invalidate() }.await.unwrap_err();
        assert!(err.to_string().contains("still in use"));

        let from_cache = cache.get_or_insert(0, false).await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&from_cache, &held));
        let from_cache = cache.get_or_insert(0, true).await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&from_cache, &held));

        let len = cache.0.map.read().await.len();
        assert_eq!(len, 1);
    }

    /// When eviction flush fails, the entry must be re-inserted and remain accessible
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_eviction_flush_failure_reinserts_entry() {
        struct FailFlushBackend;

        #[maybe_async(AFIT)]
        impl AsyncLruCacheBackend for FailFlushBackend {
            type Key = usize;
            type Value = usize;

            async fn load(&self, key: usize) -> io::Result<usize> {
                Ok(key)
            }

            async fn flush(&self, _key: usize, _value: &usize) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }

            unsafe fn evict(&self, _key: usize, _value: usize) {}
        }

        const ENTRIES: usize = 2;

        let cache = AsyncLruCache::new(FailFlushBackend, ENTRIES);

        for i in 0..ENTRIES {
            cache.get_or_insert(i, false).await.unwrap().unwrap();
        }

        // Cache is full
        let entry = cache.get_or_insert(ENTRIES, false).await.unwrap();
        assert_eq!(entry, None);
        // And eviction flush fails
        let err = cache.get_or_insert(ENTRIES, true).await.unwrap_err();
        assert!(err.to_string().contains("flush failed"));

        // All original entries must still be in the cache
        let len = cache.0.map.read().await.len();
        assert_eq!(len, ENTRIES);
        for i in 0..ENTRIES {
            let entry = cache.get_or_insert(i, false).await.unwrap().unwrap();
            assert_eq!(*entry, i);
        }

        // New entry was never inserted
        let entry = cache.get_or_insert(ENTRIES, false).await.unwrap();
        assert_eq!(entry, None);
        let err = cache.get_or_insert(ENTRIES, true).await.unwrap_err();
        assert!(err.to_string().contains("flush failed"));
    }

    /// `insert()` over an existing key must flush the old value first
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_insert_flushes_existing() {
        let backend = Arc::new(RecordingBackend::default());
        let cache = AsyncLruCache::new(Arc::clone(&backend), 16);

        cache.get_or_insert(5, false).await.unwrap().unwrap();
        let inserted = cache.insert(5, Arc::new(55), false).await.unwrap();
        assert!(!inserted);
        let inserted = cache.insert(5, Arc::new(55), true).await.unwrap();
        assert!(inserted);

        assert_eq!(*backend.flushed.lock().unwrap(), [(5, 5)]);
        let entry = *cache.get_or_insert(5, false).await.unwrap().unwrap();
        assert_eq!(entry, 55);
        let entry = *cache.get_or_insert(5, true).await.unwrap().unwrap();
        assert_eq!(entry, 55);
        let len = cache.0.map.read().await.len();
        assert_eq!(len, 1);
    }
}
