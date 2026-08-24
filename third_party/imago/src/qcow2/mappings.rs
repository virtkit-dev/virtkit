//! Get and establish cluster mappings.

use super::cow::ClusterAllocation;
use super::*;
use crate::format::drivers::PendingDataMapping;
use crate::sync_primitives::RwLockWriteGuard;

#[maybe_async]
impl<S: Storage, F: WrappedFormat<S>> Qcow2<S, F> {
    /// Get the given range’s mapping information.
    ///
    /// Underlying implementation for [`Qcow2::get_mapping()`].
    pub(super) async fn do_get_mapping(
        &self,
        offset: GuestOffset,
        max_length: u64,
    ) -> io::Result<(ShallowMapping<'_, S>, u64)> {
        let Some(l2_table) = self.get_l2(offset, false).await? else {
            let cb = self.header.cluster_bits();
            let len = cmp::min(offset.remaining_in_l2_table(cb), max_length);
            let mapping = if let Some(backing) = self.backing.as_ref() {
                ShallowMapping::Indirect {
                    layer: backing.inner(),
                    offset: offset.0,
                    writable: false,
                }
            } else {
                ShallowMapping::Zero { explicit: false }
            };
            return Ok((mapping, len));
        };

        self.do_get_mapping_with_l2(offset, max_length, &l2_table)
            .await
    }

    /// Get the given range’s mapping information, when we already have the L2 table.
    pub(super) async fn do_get_mapping_with_l2(
        &self,
        offset: GuestOffset,
        max_length: u64,
        l2_table: &L2Table,
    ) -> io::Result<(ShallowMapping<'_, S>, u64)> {
        let cb = self.header.cluster_bits();

        // Get mapping at `offset`
        let mut current_guest_cluster = offset.cluster(cb);
        let first_mapping = l2_table.get_mapping(current_guest_cluster)?;
        let return_mapping = match first_mapping {
            L2Mapping::DataFile {
                host_cluster,
                copied,
            } => ShallowMapping::Raw {
                storage: self.storage(),
                offset: host_cluster.relative_offset(offset, cb).0,
                writable: copied,
            },

            L2Mapping::Backing { backing_offset } => {
                if let Some(backing) = self.backing.as_ref() {
                    ShallowMapping::Indirect {
                        layer: backing.inner(),
                        offset: backing_offset + offset.in_cluster_offset(cb) as u64,
                        writable: false,
                    }
                } else {
                    ShallowMapping::Zero { explicit: false }
                }
            }

            L2Mapping::Zero {
                host_cluster: _,
                copied: _,
            } => ShallowMapping::Zero { explicit: true },

            L2Mapping::Compressed {
                host_offset: _,
                length: _,
            } => ShallowMapping::Special { offset: offset.0 },
        };

        // Find out how long this consecutive mapping is, but only within the current L2 table
        let mut consecutive_length = offset.remaining_in_cluster(cb);
        let mut preceding_mapping = first_mapping;
        while consecutive_length < max_length {
            let Some(next) = current_guest_cluster.next_in_l2(cb) else {
                break;
            };
            current_guest_cluster = next;

            let mapping = l2_table.get_mapping(current_guest_cluster)?;
            if !mapping.is_consecutive(&preceding_mapping, cb) {
                break;
            }

            preceding_mapping = mapping;
            consecutive_length += self.header.cluster_size() as u64;
        }

        consecutive_length = cmp::min(consecutive_length, max_length);
        Ok((return_mapping, consecutive_length))
    }

    /// Make the given range be mapped by data clusters.
    ///
    /// Underlying implementation for [`Qcow2::ensure_data_mapping()`].
    ///
    /// `skip_cow` is equivalent to [`Qcow2::ensure_data_mapping()`]’s `overwrite`: It indicates
    /// the area is to be overwritten, so COW can be skipped on it.  `skip_cow_to_eof` indicates
    /// that the mapping will go until the EOF, so no COW needs to be performed at all past
    /// `offset`.  Only use this for preallocation on resize or create.
    pub(super) async fn do_ensure_data_mapping(
        &self,
        offset: GuestOffset,
        length: u64,
        skip_cow: bool,
        skip_cow_to_eof: bool,
    ) -> io::Result<(&S, u64, u64, Qcow2Pending<'_, S, F>)> {
        let l2_table = self.ensure_l2(offset).await?;

        // Fast path for if everything is already allocated, which should be the common case at
        // runtime.
        // It must really be everything, though; we know our caller will want to have everything
        // allocated eventually, so if anything is missing, go down to the allocation path so we
        // try to allocate clusters such that they are not fragmented (if possible) and we can
        // return as big of a single mapping as possible.
        let existing = self
            .do_get_mapping_with_l2(offset, length, &l2_table)
            .await?;
        if let ShallowMapping::Raw {
            storage,
            offset,
            writable: true,
        } = existing.0
        {
            if existing.1 >= length {
                // Already fully, validly mapped — nothing new was established, so there is
                // nothing to commit or abort.
                return Ok((storage, offset, existing.1, Qcow2Pending::empty(self)));
            }
        }

        let l2_table_locked = l2_table.lock_write().await;
        let mut pending_entries = Vec::<(u64, ClusterAllocation)>::new();
        // Liveness token for the claims established below: it lives in the `Qcow2Pending`
        // returned here, so a batch dropped without committing or aborting takes it with it and
        // its claims stop being shareable once no other batch holds them (see
        // `PendingAllocations`).
        let owner = Arc::new(());

        let res = self
            .ensure_data_mapping_no_cleanup(
                offset,
                length,
                skip_cow,
                skip_cow_to_eof,
                l2_table_locked,
                PendingBatch {
                    entries: &mut pending_entries,
                    owner: &owner,
                },
            )
            .await;

        let pending = Qcow2Pending {
            qcow2: self,
            l2_table: Some(l2_table),
            entries: pending_entries,
            _owner: Some(owner),
        };

        let (host_offset, length) = match res {
            Ok(ok) => ok,
            Err(e) => {
                // Nothing here will ever be committed — free whatever was freshly allocated
                // before propagating the error, rather than leaking it.
                pending.abort().await;
                return Err(e);
            }
        };

        Ok((self.storage(), host_offset, length, pending))
    }

    /// Make the given range be mapped by a fixed kind of clusters.
    ///
    /// Allows zeroing or discarding clusters.  `mapping` says which kind of mapping to create.
    ///
    /// Return the offset of the first affected cluster, and the byte length affected (may be 0).
    ///
    /// Does not consult [`PendingAllocations`](super::cow::PendingAllocations), so a concurrent
    /// write's later commit can still map its own cluster over what this establishes. Only the
    /// write-zeroes-without-unmap path gets here under a mere read lock, so this is unchanged
    /// pre-existing behaviour; the registry now makes it visible enough to fix, should it matter.
    pub(super) async fn ensure_fixed_mapping(
        &self,
        offset: GuestOffset,
        length: u64,
        mapping: FixedMapping,
    ) -> io::Result<(GuestOffset, u64)> {
        match mapping {
            FixedMapping::ZeroDiscard | FixedMapping::ZeroRetainAllocation => {
                self.header.require_version(3)?;
            }
            FixedMapping::FullDiscard => (),
        }

        let cb = self.header.cluster_bits();

        // We can only touch full clusters
        let cluster_align_mask = self.header.cluster_size() as u64 - 1;
        let end = (offset + length).0;
        let aligned_end = if end == self.header.size() {
            // Up-align operations until the image end to a full cluster (the remainder of this
            // cluster is not used for anything)
            (end + cluster_align_mask) & !cluster_align_mask
        } else {
            // Otherwise, align down (only full clusters)
            end & !cluster_align_mask
        };
        let aligned_offset = (offset + cluster_align_mask).0 & !cluster_align_mask;
        let aligned_length = aligned_end.saturating_sub(aligned_offset);

        // We have aligned this, so we can unwrap
        let first_cluster = GuestOffset(aligned_offset).checked_cluster(cb).unwrap();
        let cluster_count = ClusterCount::checked_from_byte_size(aligned_length, cb).unwrap();

        if cluster_count.0 == 0 {
            return Ok((GuestOffset(aligned_offset), 0));
        }

        let l2_table = self.ensure_l2(first_cluster.offset(cb)).await?;
        let l2_table = l2_table.lock_write().await;
        let mut leaked_allocations = Vec::<(HostCluster, ClusterCount)>::new();

        let res = self
            .ensure_fixed_mapping_no_cleanup(
                first_cluster,
                cluster_count,
                mapping,
                l2_table,
                &mut leaked_allocations,
            )
            .await;

        for alloc in leaked_allocations {
            self.free_data_clusters(alloc.0, alloc.1).await;
        }

        let count = res?;

        let affected_offset = first_cluster.offset(cb);
        let affected_length = count.byte_size(cb);

        let head = affected_offset - offset;
        // We may overshoot for the last cluster in the image, limit the returned value to the
        // range given by the caller
        let affected_length = cmp::min(affected_length, length.saturating_sub(head));

        Ok((affected_offset, affected_length))
    }

    /// Get the L2 table referenced by the given L1 table index, if any.
    ///
    /// `writable` says whether the L2 table should be modifiable.
    ///
    /// If the L1 table index does not point to any L2 table, or the existing entry is not
    /// modifiable but `writable` is true, return `Ok(None)`.
    pub(super) async fn get_l2(
        &self,
        offset: GuestOffset,
        writable: bool,
    ) -> io::Result<Option<Arc<L2Table>>> {
        let cb = self.header.cluster_bits();

        let l1_entry = self.l1_table.read().await.get(offset.l1_index(cb));
        if let Some(l2_offset) = l1_entry.l2_offset() {
            if writable && !l1_entry.is_copied() {
                return Ok(None);
            }
            let l2_cluster = l2_offset.checked_cluster(cb).ok_or_else(|| {
                invalid_data(format!(
                    "Unaligned L2 table for {offset:?}; L1 entry: {l1_entry:?}"
                ))
            })?;

            self.caches.l2_get_or_insert(l2_cluster).await.map(Some)
        } else {
            Ok(None)
        }
    }

    /// Get a L2 table for the given L1 table index.
    ///
    /// If there already is an L2 table at that index, return it.  Otherwise, create one and hook
    /// it up.
    pub(super) async fn ensure_l2(&self, offset: GuestOffset) -> io::Result<Arc<L2Table>> {
        let cb = self.header.cluster_bits();

        if let Some(l2) = self.get_l2(offset, true).await? {
            return Ok(l2);
        }

        self.need_writable()?;

        let mut l1_locked = self.l1_table.write().await;
        let l1_index = offset.l1_index(cb);
        if !l1_locked.in_bounds(l1_index) {
            l1_locked = self.grow_l1_table(l1_locked, l1_index).await?;
        }

        let l1_entry = l1_locked.get(l1_index);
        let mut l2_table = if let Some(l2_offset) = l1_entry.l2_offset() {
            let l2_cluster = l2_offset.checked_cluster(cb).ok_or_else(|| {
                invalid_data(format!(
                    "Unaligned L2 table for {offset:?}; L1 entry: {l1_entry:?}"
                ))
            })?;

            let l2 = self.caches.l2_get_or_insert(l2_cluster).await?;
            if l1_entry.is_copied() {
                return Ok(l2);
            }

            L2Table::clone(&l2)
        } else {
            L2Table::new_cleared(&self.header)
        };

        let l2_cluster = self.allocate_meta_cluster().await?;
        l2_table.set_cluster(l2_cluster);
        l2_table.write(self.metadata.as_ref()).await?;

        l1_locked.enter_l2_table(l1_index, &l2_table)?;
        l1_locked
            .write_entry(self.metadata.as_ref(), l1_index)
            .await?;

        // Free old L2 table, if any
        if let Some(l2_offset) = l1_entry.l2_offset() {
            self.free_meta_clusters(l2_offset.cluster(cb), ClusterCount(1))
                .await;
        }

        let l2_table = Arc::new(l2_table);
        self.caches
            .l2_insert(l2_cluster, Arc::clone(&l2_table))
            .await?;
        Ok(l2_table)
    }

    /// Create a new L1 table covering at least `at_least_index`.
    ///
    /// Create a new L1 table of the required size with all the entries of the previous L1 table.
    pub(super) async fn grow_l1_table<'a>(
        &self,
        mut l1_locked: RwLockWriteGuard<'a, L1Table>,
        at_least_index: usize,
    ) -> io::Result<RwLockWriteGuard<'a, L1Table>> {
        let mut new_l1 = l1_locked.clone_and_grow(at_least_index, &self.header)?;

        let l1_start = self.allocate_meta_clusters(new_l1.cluster_count()).await?;

        new_l1.set_cluster(l1_start);
        new_l1.write(self.metadata.as_ref()).await?;

        self.header.set_l1_table(&new_l1)?;
        self.header
            .write_l1_table_pointer(self.metadata.as_ref())
            .await?;

        if let Some(old_l1_cluster) = l1_locked.get_cluster() {
            let old_l1_size = l1_locked.cluster_count();
            l1_locked.unset_cluster();
            self.free_meta_clusters(old_l1_cluster, old_l1_size).await;
        }

        *l1_locked = new_l1;

        Ok(l1_locked)
    }

    /// Inner implementation for [`Qcow2::do_ensure_data_mapping()`].
    ///
    /// Does not map any freshly allocated cluster into the L2 table — every cluster this touches
    /// (whether freshly allocated or an already-valid, reused mapping) is instead entered into
    /// `pending_entries` as `(cluster's guest offset, allocation)`, for the caller to turn into a
    /// [`Qcow2Pending`] once it knows whether the write it is about to perform into the returned
    /// range actually succeeds. See [`Qcow2Pending`] for why: mapping a cluster in before that
    /// write has happened would let a mid-write failure leave it allocated with whatever
    /// undefined bytes happened to already be there, indistinguishable from valid data. Any
    /// cluster a commit supersedes (discovered only then, since nothing is mapped in here yet) is
    /// freed by the commit itself.
    ///
    /// The caller must route `batch.entries` through a [`Qcow2Pending`], in both cases of success
    /// and of error.
    async fn ensure_data_mapping_no_cleanup(
        &self,
        offset: GuestOffset,
        full_length: u64,
        skip_cow: bool,
        skip_cow_to_eof: bool,
        l2_table: L2TableWriteGuard<'_>,
        batch: PendingBatch<'_>,
    ) -> io::Result<(u64, u64)> {
        let PendingBatch {
            entries: pending_entries,
            owner,
        } = batch;
        let cb = self.header.cluster_bits();

        let partial_skip_cow = skip_cow.then(|| {
            let start = offset.in_cluster_offset(cb);
            let end = if skip_cow_to_eof {
                1 << cb
            } else {
                cmp::min(start as u64 + full_length, 1 << cb) as usize
            };
            start..end
        });

        let mut current_guest_cluster = offset.cluster(cb);

        // Without a mandatory host offset, this should never return `Ok(None)`
        let allocation = self
            .cow_cluster(
                current_guest_cluster,
                None,
                partial_skip_cow,
                &l2_table,
                owner,
            )
            .await?
            .ok_or_else(|| io::Error::other("Internal allocation error"))?;
        pending_entries.push((current_guest_cluster.offset(cb).0, allocation));

        let host_cluster = allocation.host_cluster();
        let host_offset_start = host_cluster.relative_offset(offset, cb);
        let mut allocated_length = offset.remaining_in_cluster(cb);
        let mut current_host_cluster = host_cluster;

        while allocated_length < full_length {
            let Some(next) = current_guest_cluster.next_in_l2(cb) else {
                break;
            };
            current_guest_cluster = next;

            let chunk_length = cmp::min(full_length - allocated_length, 1 << cb) as usize;
            let partial_skip_cow = match (skip_cow, skip_cow_to_eof) {
                (false, _) => None,
                (true, false) => Some(0..chunk_length),
                (true, true) => Some(0..(1 << cb)),
            };

            let next_host_cluster = current_host_cluster + ClusterCount(1);
            let allocation = self
                .cow_cluster(
                    current_guest_cluster,
                    Some(next_host_cluster),
                    partial_skip_cow,
                    &l2_table,
                    owner,
                )
                .await?;

            let Some(allocation) = allocation else {
                // Cannot continue continuous mapping range
                break;
            };
            let host_cluster = allocation.host_cluster();
            assert!(host_cluster == next_host_cluster);
            pending_entries.push((current_guest_cluster.offset(cb).0, allocation));
            current_host_cluster = host_cluster;

            allocated_length += chunk_length as u64;
        }

        Ok((host_offset_start.0, allocated_length))
    }

    /// Inner implementation for [`Qcow2::ensure_fixed_mapping()`].
    ///
    /// Does not do any clean-up: The L2 table will probably be modified, but not written to disk.
    /// Any existing allocations that have been removed from it (and are thus leaked) are entered
    /// into `leaked_allocations`, but not freed.
    ///
    /// The caller must do both, ensuring it is done both in case of success and in case of error.
    ///
    /// Allows zeroing or discarding clusters.  `mapping` says which kind of mapping to create.
    async fn ensure_fixed_mapping_no_cleanup(
        &self,
        first_cluster: GuestCluster,
        count: ClusterCount,
        mapping: FixedMapping,
        mut l2_table: L2TableWriteGuard<'_>,
        leaked_allocations: &mut Vec<(HostCluster, ClusterCount)>,
    ) -> io::Result<ClusterCount> {
        self.header.require_version(3)?;

        let cb = self.header.cluster_bits();
        let mut cluster = first_cluster;
        let end_cluster = first_cluster + count;
        let mut done = ClusterCount(0);

        while cluster < end_cluster {
            let l2i = cluster.l2_index(cb);
            let leaked = match mapping {
                FixedMapping::ZeroDiscard => l2_table.zero_cluster(l2i, false)?,
                FixedMapping::ZeroRetainAllocation => l2_table.zero_cluster(l2i, true)?,
                FixedMapping::FullDiscard => l2_table.discard_cluster(l2i),
            };
            if let Some(leaked) = leaked {
                leaked_allocations.push(leaked);
            }

            done += ClusterCount(1);
            let Some(next) = cluster.next_in_l2(cb) else {
                break;
            };
            cluster = next;
        }

        Ok(done)
    }
}

/// Possible mapping types for [`Qcow2::ensure_fixed_mapping()`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FixedMapping {
    /// Make all clusters zero clusters, discarding previous allocations.
    ///
    /// Note this breaks existing mapping information, which must be communicated somehow, for
    /// example by requiring mutable access to the `Qcow2` object.
    ZeroDiscard,

    /// Make all clusters zero clusters, retaining previous allocations.
    ///
    /// Retains previous data cluster allocations in the form of preallocated zero clusters, but
    /// cannot retain previously existing compressed cluster allocations.  Because those mappings
    /// are not returned through the mapping interface, however, concurrent accesses should be
    /// reasonably safe.
    ///
    /// (Writing to zeroed data cluster mappings will just have no effect.)
    ZeroRetainAllocation,

    /// Fully remove clusters’ mappings, allowing backing data to appear.
    ///
    /// Note this breaks existing mapping information, which must be communicated somehow, for
    /// example by requiring mutable access to the `Qcow2` object.
    FullDiscard,
}

/// The two batch-scoped things [`Qcow2::ensure_data_mapping_no_cleanup()`] fills in: where the
/// claims it establishes are collected, and the token that says the batch collecting them is
/// still alive. Both end up in the [`Qcow2Pending`] its caller builds, which is what makes them
/// one parameter rather than two.
pub(super) struct PendingBatch<'a> {
    /// Where to record each cluster established, for the caller's [`Qcow2Pending`].
    entries: &'a mut Vec<(u64, ClusterAllocation)>,
    /// The batch's liveness token (see [`PendingAllocations`](super::cow::PendingAllocations)).
    owner: &'a Arc<()>,
}

/// Clusters [`Qcow2::do_ensure_data_mapping()`] established but has not yet mapped into the L2
/// table.
///
/// Establishing a mapping (allocating or COW'ing a cluster) and writing the caller's actual data
/// into it are two separate steps, with the write happening only after this is returned. If the
/// cluster were mapped in immediately, a write that then fails would leave it allocated with
/// whatever undefined bytes happened to already be there — real, valid-looking storage, not a
/// hole, indistinguishable from valid data to both the failed write's own caller (which only
/// sees the one `io::Error`) and to a later reader or flush/checkpoint.
///
/// The caller must therefore call exactly one of [`commit()`](Self::commit) — once its write into
/// the range this was returned alongside has actually succeeded — or [`abort()`](Self::abort) —
/// if it hasn't — exactly once, before dropping this.  `abort()` cannot fail: freeing a cluster is
/// already a best-effort operation crate-wide (see [`Qcow2::free_data_clusters()`]).  `commit()`
/// can, but only for a claim a concurrent write holed (see
/// [`PendingAllocations`](super::cow::PendingAllocations)); mapping a cluster in is otherwise a
/// plain, infallible in-memory L2 table update (the same one a direct, non-deferred write would
/// have done).
///
/// Dropping this without calling either leaks the freshly allocated cluster.  The claim on it is
/// reaped rather than left registered — the next write into that guest cluster finds this batch's
/// token dead and claims a cluster of its own (see
/// [`PendingAllocations`](super::cow::PendingAllocations)) — so what is left is waste, not the
/// silent corruption it would otherwise be.  A write already sharing the claim when this went away
/// still ends up with a cluster nobody covered the rest of, though, and the leak is real either
/// way, so every path out of a `writev` must still route its `Qcow2Pending`s through one of the
/// two.  (A write arriving *after* joins the claim only while some user still holds it; once the
/// last one is gone it is reaped rather than handed out, because a user's token is dropped by its
/// own `release()` and not left to die with its batch.)  There is no `Drop` impl enforcing it because the async free it would need cannot run in
/// one.
#[must_use = "must be committed or aborted"]
pub(super) struct Qcow2Pending<'a, S: Storage + 'static, F: WrappedFormat<S> + 'static> {
    /// The image this pending batch's entries belong to, needed by both `commit()` (to lock the
    /// L2 table) and `abort()` (to free any freshly allocated cluster).
    qcow2: &'a Qcow2<S, F>,
    /// The (single) L2 table every entry belongs to — `ensure_data_mapping_no_cleanup()`'s loop
    /// never crosses an L2 table boundary, so one is always enough. `None` iff `entries` is
    /// empty (nothing new was established, so there is no table to commit anything into).
    l2_table: Option<Arc<L2Table>>,
    /// `(guest offset of the cluster, its allocation)`, in the order established.
    entries: Vec<(u64, ClusterAllocation)>,
    /// Liveness token for this batch's claims: held only here, so dropping this — including
    /// without the commit or abort the contract asks for — is what lets a later write see those
    /// claims as wreckage, once no other batch holding them is live either (see
    /// [`PendingAllocations`](super::cow::PendingAllocations)).
    _owner: Option<Arc<()>>,
}

#[maybe_async]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Qcow2Pending<'_, S, F> {
    /// A pending batch with nothing in it — for when nothing new was established at all (e.g.
    /// the whole range was already validly mapped).
    fn empty(qcow2: &Qcow2<S, F>) -> Qcow2Pending<'_, S, F> {
        Qcow2Pending {
            qcow2,
            l2_table: None,
            entries: Vec::new(),
            // No claims, so no token to keep alive — and this is the fast path, so no allocation.
            _owner: None,
        }
    }

    /// Map every freshly allocated or reused-zero cluster into the L2 table (clearing the
    /// latter's "zero" flag), freeing whatever it superseded. Clusters already validly mapped
    /// as data are left untouched (nothing to commit).
    ///
    /// Fails if a concurrent write sharing one of these claims gave up before its own write
    /// landed, which leaves a hole in the cluster it never filled in (see
    /// [`PendingAllocations`](super::cow::PendingAllocations)): that cluster must not go live,
    /// so this write's bytes cannot be made visible and it must be reported as failed rather
    /// than silently dropped. Everything not holed is still mapped in, and every claim is
    /// released either way.
    pub(super) async fn commit(self) -> io::Result<()> {
        // Only `empty()` has no token, and it has no entries either, so the loop below never
        // asks for one.
        let owner = self._owner.as_ref();
        let Some(l2_table) = self.l2_table else {
            return Ok(());
        };
        let cb = self.qcow2.header.cluster_bits();
        let mut l2_table = l2_table.lock_write().await;
        let mut holed = false;
        for (guest_offset, allocation) in self.entries {
            let new_cluster = match allocation {
                ClusterAllocation::MappedExisting(_) => continue,
                ClusterAllocation::ReusedZero(new_cluster)
                | ClusterAllocation::Fresh(new_cluster)
                | ClusterAllocation::SharedPending(new_cluster) => new_cluster,
            };
            let claimant = !matches!(allocation, ClusterAllocation::SharedPending(_));
            // Release first: mapping in is this claim's to do only if no other user of it has
            // already given up on filling the cluster. Releasing also tells a concurrent write
            // that shares the claim and then fails that the cluster is live now and must not be
            // freed.
            let released =
                self.qcow2
                    .pending_allocs
                    .lock()
                    .await
                    .release(guest_offset, true, claimant, owner);
            if released.holed {
                holed = true;
            } else {
                let l2i = GuestOffset(guest_offset).cluster(cb).l2_index(cb);
                if let Some(leaked) = l2_table.map_cluster(l2i, new_cluster) {
                    self.qcow2.free_data_clusters(leaked.0, leaked.1).await;
                }
            }
            if let Some(orphan) = released.orphan {
                self.qcow2.free_data_clusters(orphan, ClusterCount(1)).await;
            }
        }
        if holed {
            return Err(io::Error::other(
                "Concurrent write into the same cluster failed; this write cannot be made visible",
            ));
        }
        Ok(())
    }

    /// Give up: free every freshly allocated cluster this call is the last user of, and that
    /// nobody mapped in (a concurrent write may have shared the claim and landed — see
    /// [`PendingAllocations`](super::cow::PendingAllocations)). The L2 table was never touched,
    /// so there is nothing to undo there, and already-valid mappings were never this call's to
    /// free. Giving up while another write still shares a claim holes it: that cluster can no
    /// longer go live, and the sharer's `commit()` fails instead of exposing it.
    pub(super) async fn abort(self) {
        // As in `commit()`: no token only where there is nothing to release.
        let owner = self._owner.as_ref();
        for (guest_offset, allocation) in self.entries {
            if matches!(allocation, ClusterAllocation::MappedExisting(_)) {
                continue;
            }
            let claimant = !matches!(allocation, ClusterAllocation::SharedPending(_));
            // Freeing is the last user's call, and only if none of them mapped the cluster in:
            // a write sharing this claim may have landed and committed already. The registry
            // lock is dropped before the free, which takes the allocator's.
            let released = self.qcow2.pending_allocs.lock().await.release(
                guest_offset,
                false,
                claimant,
                owner,
            );
            if let Some(orphan) = released.orphan {
                self.qcow2.free_data_clusters(orphan, ClusterCount(1)).await;
            }
        }
    }
}

#[maybe_async(?Send)]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> PendingDataMapping
    for Qcow2Pending<'_, S, F>
{
    async fn commit(self: Box<Self>) -> io::Result<()> {
        Qcow2Pending::commit(*self).await
    }

    async fn abort(self: Box<Self>) {
        Qcow2Pending::abort(*self).await;
    }
}
