//! Provides functionality for the L2 and refblock caches.

use super::*;
use crate::async_lru_cache::AsyncLruCacheBackend;
use tracing::trace;

/// I/O back-end for the L2 table cache.
struct L2CacheBackend<S: Storage> {
    /// Qcow2 metadata file.
    file: Arc<S>,

    /// Qcow2 header.
    header: Arc<Header>,
}

/// I/O back-end for the refblock cache.
struct RefBlockCacheBackend<S: Storage> {
    /// Qcow2 metadata file.
    file: Arc<S>,

    /// Qcow2 header.
    header: Arc<Header>,
}

impl<S: Storage> L2CacheBackend<S> {
    /// Create a new `L2CacheBackend`.
    ///
    /// `file` is the qcow2 metadata (image) file.
    pub fn new(file: Arc<S>, header: Arc<Header>) -> Self {
        L2CacheBackend { file, header }
    }
}

#[maybe_async(AFIT)]
impl<S: Storage> AsyncLruCacheBackend for L2CacheBackend<S> {
    type Key = HostCluster;
    type Value = L2Table;

    async fn load(&self, l2_cluster: HostCluster) -> io::Result<L2Table> {
        trace!("Loading L2 table");

        L2Table::load(
            self.file.as_ref(),
            &self.header,
            l2_cluster,
            self.header.l2_entries(),
        )
        .await
    }

    async fn flush(&self, l2_cluster: HostCluster, l2_table: &L2Table) -> io::Result<()> {
        trace!("Flushing L2 table");
        if l2_table.is_modified() {
            assert!(l2_table.get_cluster().unwrap() == l2_cluster);
            l2_table.write(self.file.as_ref()).await?;
        }
        Ok(())
    }

    unsafe fn evict(&self, _l2_cluster: HostCluster, l2_table: L2Table) {
        trace!(
            "Evicting L2 table {}",
            l2_table.get_offset().unwrap_or(HostOffset(0))
        );
        l2_table.clear_modified();
    }
}

impl<S: Storage> RefBlockCacheBackend<S> {
    /// Create a new `RefBlockCacheBackend`.
    ///
    /// `file` is the qcow2 metadata (image) file.
    pub fn new(file: Arc<S>, header: Arc<Header>) -> Self {
        RefBlockCacheBackend { file, header }
    }
}

#[maybe_async(AFIT)]
impl<S: Storage> AsyncLruCacheBackend for RefBlockCacheBackend<S> {
    type Key = HostCluster;
    type Value = RefBlock;

    async fn load(&self, rb_cluster: HostCluster) -> io::Result<RefBlock> {
        RefBlock::load(self.file.as_ref(), &self.header, rb_cluster).await
    }

    async fn flush(&self, rb_cluster: HostCluster, refblock: &RefBlock) -> io::Result<()> {
        if refblock.is_modified() {
            assert!(refblock.get_cluster().unwrap() == rb_cluster);
            refblock.write(self.file.as_ref()).await?;
        }
        Ok(())
    }

    unsafe fn evict(&self, _rb_cluster: HostCluster, refblock: RefBlock) {
        refblock.clear_modified();
    }
}

/// Current flush dependency direction between L2 and refblock caches
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CacheDependency {
    /// No dependency set yet
    #[default]
    None,
    /// Write refblock cache before writing anything from the L2 cache (during cluster allocation)
    L2DependsOnRb,
    /// Write L2 cache before writing anything from the refblock cache (during cluster freeing)
    RbDependsOnL2,
}

/// Qcow2 metadata caches with flush-ordering coordination.
///
/// When allocating clusters, we need to increment the refcounts (from 0 to 1) before writing the
/// L2 pointers.  Therefore, before anything is written from the L2 cache to disk, we need to flush
/// the refblock cache.
///
/// When freeing clusters, we need to clear the L2 pointers before decrementing the refcounts (to
/// 0).  Therefore before anything is written from the refblock cache to disk, we need to flush the
/// L2 cache.
///
/// This structure takes care to heed those dependencies (though the general qcow2 code still needs
/// to announce them by calling `.l2_depends_on_rb()` for allocations and `.rb_depends_on_l2()` for
/// freeing).
pub(super) struct MetadataCaches<S: Storage> {
    /// L2 table cache
    l2: AsyncLruCache<HostCluster, L2Table, L2CacheBackend<S>>,

    /// Refblock cache
    rb: AsyncLruCache<HostCluster, RefBlock, RefBlockCacheBackend<S>>,

    /// Current dependency direction
    ///
    /// Wrapped methods hold a read guard for their entire execution,
    /// preventing the direction from changing mid-operation.  Direction
    /// switch methods take a write guard.
    direction: RwLock<CacheDependency>,
}

#[maybe_async]
impl<S: Storage> MetadataCaches<S> {
    /// Create metadata caches for the given file, with the given header.
    ///
    /// The L2 cache is going to hold `l2_entries` tables, the refblock cache will have
    /// `rb_entries` refcount blocks.
    pub fn new(file: &Arc<S>, header: &Arc<Header>, l2_entries: usize, rb_entries: usize) -> Self {
        let l2_backend = L2CacheBackend::new(Arc::clone(file), Arc::clone(header));
        let rb_backend = RefBlockCacheBackend::new(Arc::clone(file), Arc::clone(header));

        MetadataCaches {
            l2: AsyncLruCache::new(l2_backend, l2_entries),
            rb: AsyncLruCache::new(rb_backend, rb_entries),
            direction: Default::default(),
        }
    }

    /// Make sure the refblock cache is flushed before the L2 cache.
    ///
    /// Use before allocating new clusters.
    pub async fn l2_depends_on_rb(&self) -> io::Result<()> {
        let mut dir = self.direction.write().await;
        if *dir == CacheDependency::L2DependsOnRb {
            return Ok(());
        }
        if *dir == CacheDependency::RbDependsOnL2 {
            self.l2.flush().await?;
        }
        *dir = CacheDependency::L2DependsOnRb;
        Ok(())
    }

    /// Make sure the L2 cache is flushed before the refblock cache.
    ///
    /// Use before freeing clusters.
    pub async fn rb_depends_on_l2(&self) -> io::Result<()> {
        let mut dir = self.direction.write().await;
        if *dir == CacheDependency::RbDependsOnL2 {
            return Ok(());
        }
        if *dir == CacheDependency::L2DependsOnRb {
            self.rb.flush().await?;
        }
        *dir = CacheDependency::RbDependsOnL2;
        Ok(())
    }

    /// Flush both L2 and refblock cache to disk.
    pub async fn flush_all(&self) -> io::Result<()> {
        let dir = self.direction.read().await;
        if *dir == CacheDependency::L2DependsOnRb {
            self.rb.flush().await?;
            self.l2.flush().await?;
        } else {
            self.l2.flush().await?;
            self.rb.flush().await?;
        }

        Ok(())
    }

    /// Retrieve an L2 table from the cache.
    ///
    /// See [`AsyncLruCache::get_or_insert()`] for details.
    pub async fn l2_get_or_insert(&self, cluster_index: HostCluster) -> io::Result<Arc<L2Table>> {
        let dir = self.direction.read().await;
        if let Some(l2) = self.l2.get_or_insert(cluster_index, false).await? {
            return Ok(l2);
        }

        if *dir == CacheDependency::L2DependsOnRb {
            self.rb.flush().await?;
        }

        // `unwrap()` is safe: Will never return `Ok(None)` with `may_flush` set to true.
        let l2 = self.l2.get_or_insert(cluster_index, true).await?.unwrap();
        Ok(l2)
    }

    /// Force-insert an L2 table.
    ///
    /// See [`AsyncLruCache::insert()`] for details.
    pub async fn l2_insert(
        &self,
        cluster_index: HostCluster,
        table: Arc<L2Table>,
    ) -> io::Result<()> {
        let dir = self.direction.read().await;
        if !self
            .l2
            .insert(cluster_index, Arc::clone(&table), false)
            .await?
        {
            if *dir == CacheDependency::L2DependsOnRb {
                self.rb.flush().await?;
            }

            let inserted = self.l2.insert(cluster_index, table, true).await?;
            // Will always insert with `may_flush` set to true.
            assert!(inserted);
        }

        Ok(())
    }

    /// Invalidate the L2 cache.
    ///
    /// # Safety
    /// May cause image corruption, you must guarantee the on-disk state is consistent.
    pub async unsafe fn invalidate_l2(&self) -> io::Result<()> {
        unsafe { self.l2.invalidate() }.await
    }

    /// Retrieve a refblock from the cache.
    ///
    /// See [`AsyncLruCache::get_or_insert()`] for details.
    pub async fn rb_get_or_insert(&self, cluster_index: HostCluster) -> io::Result<Arc<RefBlock>> {
        let dir = self.direction.read().await;
        if let Some(rb) = self.rb.get_or_insert(cluster_index, false).await? {
            return Ok(rb);
        }

        if *dir == CacheDependency::RbDependsOnL2 {
            self.l2.flush().await?;
        }

        // `unwrap()` is safe: Will never return `Ok(None)` with `may_flush` set to true.
        let rb = self.rb.get_or_insert(cluster_index, true).await?.unwrap();
        Ok(rb)
    }

    /// Force-insert a refblock.
    ///
    /// See [`AsyncLruCache::insert()`] for details.
    pub async fn rb_insert(&self, cluster_index: HostCluster, rb: Arc<RefBlock>) -> io::Result<()> {
        let dir = self.direction.read().await;
        if !self
            .rb
            .insert(cluster_index, Arc::clone(&rb), false)
            .await?
        {
            if *dir == CacheDependency::RbDependsOnL2 {
                self.l2.flush().await?;
            }

            let inserted = self.rb.insert(cluster_index, rb, true).await?;
            // Will always insert with `may_flush` set to true.
            assert!(inserted);
        }

        Ok(())
    }

    /// Flush the refblock cache to disk.
    pub async fn flush_rb(&self) -> io::Result<()> {
        let dir = self.direction.read().await;
        if *dir == CacheDependency::RbDependsOnL2 {
            self.l2.flush().await?;
        }
        self.rb.flush().await
    }

    /// Invalidate the refblock cache.
    ///
    /// # Safety
    /// May cause image corruption, you must guarantee the on-disk state is consistent.
    pub async unsafe fn invalidate_rb(&self) -> io::Result<()> {
        unsafe { self.rb.invalidate() }.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::null::Null;

    fn make_test_caches() -> MetadataCaches<Null> {
        let null = Arc::new(Null::new(1 << 16));
        let header = Arc::new(Header::new(16, 1, None, None, None));
        MetadataCaches::new(&null, &header, 16, 16)
    }

    #[cfg(feature = "sync")]
    fn block_on<T>(v: T) -> T {
        v
    }

    #[cfg(feature = "async")]
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Direction switching is idempotent and doesn't error.
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_direction_switch() {
        let caches = make_test_caches();

        caches.l2_depends_on_rb().await.unwrap();
        caches.l2_depends_on_rb().await.unwrap();
        caches.rb_depends_on_l2().await.unwrap();
        caches.rb_depends_on_l2().await.unwrap();
        caches.l2_depends_on_rb().await.unwrap();
    }

    /// Cross-cache eviction must not deadlock.
    ///
    /// Fill both caches to capacity with l2→rb active.  Two threads
    /// concurrently trigger eviction on each cache.  The coordinator
    /// flushes deps before map.write(), so no cross-cache lock
    /// nesting occurs.
    #[test]
    fn test_cross_cache_eviction_no_deadlock() {
        use std::thread;

        let null = Arc::new(Null::new(1 << 20));
        let header = Arc::new(Header::new(16, 1, None, None, None));
        let caches = Arc::new(MetadataCaches::new(&null, &header, 1, 1));

        block_on(caches.l2_depends_on_rb()).unwrap();

        // Create entries with cluster set and modified cleared so
        // flush is a no-op (avoids needing real I/O on Null storage).
        let mut l2_entry = L2Table::new_cleared(&header);
        l2_entry.set_cluster(HostCluster(0));
        l2_entry.clear_modified();
        let mut rb_entry = RefBlock::new_cleared(null.as_ref(), &header).unwrap();
        rb_entry.set_cluster(HostCluster(0));
        rb_entry.clear_modified();

        block_on(caches.l2_insert(HostCluster(0), Arc::new(l2_entry))).unwrap();
        block_on(caches.rb_insert(HostCluster(0), Arc::new(rb_entry))).unwrap();

        let c1 = Arc::clone(&caches);
        let c2 = Arc::clone(&caches);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let bar1 = Arc::clone(&barrier);
        let bar2 = Arc::clone(&barrier);

        // Thread 1: insert new l2 entry (evicts old one, dep-flushes rb)
        let header1 = Arc::clone(&header);
        let t1 = thread::spawn(move || {
            let mut entry = L2Table::new_cleared(&header1);
            entry.set_cluster(HostCluster(1));
            entry.clear_modified();
            bar1.wait();
            block_on(c1.l2_insert(HostCluster(1), Arc::new(entry))).unwrap();
        });

        // Thread 2: insert new rb entry (evicts old one)
        let header2 = Arc::clone(&header);
        let null2 = Arc::new(Null::new(1 << 20));
        let t2 = thread::spawn(move || {
            let mut entry = RefBlock::new_cleared(null2.as_ref(), &header2).unwrap();
            entry.set_cluster(HostCluster(1));
            entry.clear_modified();
            bar2.wait();
            block_on(c2.rb_insert(HostCluster(1), Arc::new(entry))).unwrap();
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }

    /// Concurrent direction switching must not deadlock or corrupt
    /// the direction state.
    #[test]
    fn test_concurrent_direction_switch() {
        use std::thread;

        let caches = Arc::new(make_test_caches());

        let c1 = Arc::clone(&caches);
        let c2 = Arc::clone(&caches);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let bar1 = Arc::clone(&barrier);
        let bar2 = Arc::clone(&barrier);

        let t1 = thread::spawn(move || {
            bar1.wait();
            block_on(c1.l2_depends_on_rb()).unwrap();
        });

        let t2 = thread::spawn(move || {
            bar2.wait();
            block_on(c2.rb_depends_on_l2()).unwrap();
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }

    /// Direction switch must flush the opposing cache's dirty entries.
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_direction_switch_flushes_opposing() {
        let null = Arc::new(Null::new(1 << 20));
        let header = Arc::new(Header::new(16, 1, None, None, None));
        let caches = MetadataCaches::new(&null, &header, 16, 16);

        // Insert a dirty rb entry
        let mut rb_entry = RefBlock::new_cleared(null.as_ref(), &header).unwrap();
        rb_entry.set_cluster(HostCluster(0));
        // Leave modified = true (new_cleared sets it)
        let rb_arc = Arc::new(rb_entry);
        caches
            .rb_insert(HostCluster(0), Arc::clone(&rb_arc))
            .await
            .unwrap();

        assert!(rb_arc.is_modified());

        // Set l2→rb, then switch to rb→l2 — must flush rb
        caches.l2_depends_on_rb().await.unwrap();
        caches.rb_depends_on_l2().await.unwrap();

        // rb was flushed during the direction switch
        assert!(!rb_arc.is_modified());
    }

    /// Dep cache must be flushed before the main cache evicts.
    ///
    /// With l2→rb active, inserting into a full l2 cache must flush
    /// rb (the dependency) before evicting the l2 entry.
    #[maybe_async::test(feature = "sync", async(feature = "async", tokio::test))]
    async fn test_dep_flushed_before_eviction() {
        let null = Arc::new(Null::new(1 << 20));
        let header = Arc::new(Header::new(16, 1, None, None, None));
        let caches = MetadataCaches::new(&null, &header, 1, 16);

        caches.l2_depends_on_rb().await.unwrap();

        // Insert a dirty rb entry
        let mut rb_entry = RefBlock::new_cleared(null.as_ref(), &header).unwrap();
        rb_entry.set_cluster(HostCluster(0));
        let rb_arc = Arc::new(rb_entry);
        caches
            .rb_insert(HostCluster(0), Arc::clone(&rb_arc))
            .await
            .unwrap();

        // Fill l2 cache (size 1)
        let mut l2_entry = L2Table::new_cleared(&header);
        l2_entry.set_cluster(HostCluster(0));
        l2_entry.clear_modified();
        caches
            .l2_insert(HostCluster(0), Arc::new(l2_entry))
            .await
            .unwrap();

        // Insert another l2 entry — triggers eviction.
        // The coordinator must flush rb (dep) before the l2 eviction.
        let mut l2_entry2 = L2Table::new_cleared(&header);
        l2_entry2.set_cluster(HostCluster(1));
        l2_entry2.clear_modified();
        caches
            .l2_insert(HostCluster(1), Arc::new(l2_entry2))
            .await
            .unwrap();

        // rb must have been flushed by the dep flush
        assert!(
            !rb_arc.is_modified(),
            "rb entry must be flushed before l2 eviction"
        );
    }
}
