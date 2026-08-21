//! Copy-on-write operations.
//!
//! Implements copy-on-write when writing to clusters that are not simple allocated data clusters.

use super::*;
use crate::io_buffers::IoBuffer;

/// The outcome of [`Qcow2::cow_cluster()`]: which host cluster a guest write may target, and
/// whether mapping it into the L2 table is still pending.
///
/// Deliberately not [`Copy`]/[`Clone`]-derived-away-from: callers must route every value through
/// exactly one of a commit (map it in, `MappedExisting` excepted) or an abort (free it, `Fresh`
/// only) — see [`Qcow2Pending`](super::mappings::Qcow2Pending).
#[derive(Debug, Clone, Copy)]
pub(super) enum ClusterAllocation {
    /// Already validly mapped as a writable data cluster before this call. Committing it is a
    /// no-op; it must never be freed — it may still be in use even if this particular write is
    /// aborted.
    MappedExisting(HostCluster),
    /// An existing, already-referenced pre-allocated zero cluster being reused as-is: no new
    /// physical allocation, so it must never be freed on abort. But its L2 entry still carries
    /// the "zero" flag, so — unlike `MappedExisting` — committing it is not a no-op: it must
    /// still be mapped in on commit to clear that flag, or a write that lands real data there
    /// keeps reading back as zero forever.
    ReusedZero(HostCluster),
    /// Freshly claimed by this call, not yet mapped into the L2 table. Must be freed if it is
    /// never committed, or it leaks; must not be exposed via the L2 table before the guest's
    /// own write into it has actually succeeded, or an unwritten cluster becomes indistinguishable
    /// from a valid one holding whatever bytes happened to already be there.
    Fresh(HostCluster),
}

impl ClusterAllocation {
    /// The host cluster a guest write into this allocation may target, regardless of which
    /// variant this is.
    pub(super) fn host_cluster(&self) -> HostCluster {
        match *self {
            ClusterAllocation::MappedExisting(hc)
            | ClusterAllocation::ReusedZero(hc)
            | ClusterAllocation::Fresh(hc) => hc,
        }
    }
}

#[maybe_async]
impl<S: Storage, F: WrappedFormat<S>> Qcow2<S, F> {
    /// Do copy-on-write for the given guest cluster, if necessary.
    ///
    /// If the given guest cluster is backed by an allocated copied data cluster, return that
    /// cluster, so it can just be written into.
    ///
    /// Otherwise, allocate a new data cluster and copy the previously visible cluster contents
    /// there:
    /// - For non-copied data clusters, copy the cluster contents.
    /// - For zero clusters, write zeroes.
    /// - For unallocated clusters, copy data from the backing file (if any, zeroes otherwise).
    /// - For compressed clusters, decompress the data and write it into the new cluster.
    ///
    /// Return the new cluster, if any was allocated, or the old cluster in case it was already
    /// safe to write to.  I.e., the returned cluster is where data for `cluster` may be written
    /// to. Does NOT map a freshly allocated cluster into the L2 table — that is deferred to the
    /// caller's [`Qcow2Pending`](super::mappings::Qcow2Pending), once the write into it (which
    /// the caller performs after this returns) is known to have succeeded.
    ///
    /// `cluster` is the guest cluster to COW.
    ///
    /// `mandatory_host_cluster` may specify the cluster that must be used for the new allocation,
    /// or that an existing data cluster allocation must match.  If it does not match, or that
    /// cluster is already allocated and cannot be used, return `Ok(None)`.
    ///
    /// `partial_skip_cow` may give an in-cluster range that is supposed to be overwritten
    /// immediately anyway, i.e. that need not be copied.
    ///
    /// `l2_table` is the L2 table for `offset`.
    pub(super) async fn cow_cluster(
        &self,
        cluster: GuestCluster,
        mandatory_host_cluster: Option<HostCluster>,
        partial_skip_cow: Option<Range<usize>>,
        l2_table: &L2TableWriteGuard<'_>,
    ) -> io::Result<Option<ClusterAllocation>> {
        // No need to do COW when writing the full cluster
        let full_skip_cow = if let Some(skip) = partial_skip_cow.as_ref() {
            skip.start == 0 && skip.end == self.header.cluster_size()
        } else {
            false
        };

        let existing_mapping = l2_table.get_mapping(cluster)?;
        if let L2Mapping::DataFile {
            host_cluster,
            copied: true,
        } = existing_mapping
        {
            if let Some(mandatory_host_cluster) = mandatory_host_cluster {
                if host_cluster != mandatory_host_cluster {
                    return Ok(None);
                }
            }
            return Ok(Some(ClusterAllocation::MappedExisting(host_cluster)));
        };

        self.need_writable()?;

        // Whether `new_cluster` below is a fresh allocation (must be freed if never committed)
        // or an existing, already-referenced one being reused as-is (must never be freed).
        let mut fresh = false;

        let new_cluster = if let L2Mapping::Zero {
            host_cluster: Some(host_cluster),
            copied: true,
        } = existing_mapping
        {
            if let Some(mandatory_host_cluster) = mandatory_host_cluster {
                if host_cluster == mandatory_host_cluster {
                    Some(host_cluster)
                } else {
                    // Discard existing mapping
                    fresh = true;
                    self.allocate_data_cluster_at(cluster, Some(mandatory_host_cluster))
                        .await?
                }
            } else {
                Some(host_cluster)
            }
        } else {
            fresh = true;
            self.allocate_data_cluster_at(cluster, mandatory_host_cluster)
                .await?
        };
        let Some(new_cluster) = new_cluster else {
            // Allocation at `mandatory_host_cluster` failed
            return Ok(None);
        };

        if !full_skip_cow {
            match existing_mapping {
                L2Mapping::DataFile {
                    host_cluster: _,
                    copied: true,
                } => unreachable!(),

                L2Mapping::DataFile {
                    host_cluster,
                    copied: false,
                } => {
                    self.cow_copy_storage(
                        self.storage(),
                        host_cluster,
                        new_cluster,
                        partial_skip_cow,
                    )
                    .await?
                }

                L2Mapping::Backing { backing_offset } => {
                    if let Some(backing) = self.backing.as_ref() {
                        self.cow_copy_format(backing, backing_offset, new_cluster, partial_skip_cow)
                            .await?
                    } else {
                        self.cow_zero(new_cluster, partial_skip_cow).await?
                    }
                }

                L2Mapping::Zero {
                    host_cluster: _,
                    copied: _,
                } => self.cow_zero(new_cluster, partial_skip_cow).await?,

                L2Mapping::Compressed {
                    host_offset,
                    length,
                } => {
                    self.cow_compressed(host_offset, length, new_cluster)
                        .await?
                }
            }
        }

        Ok(Some(if fresh {
            ClusterAllocation::Fresh(new_cluster)
        } else {
            // Reused an existing pre-allocated zero cluster as-is (the `Some(host_cluster) =
            // Some(new_cluster)` branches above): no new allocation, but the L2 entry's "zero"
            // flag still needs clearing on commit.
            ClusterAllocation::ReusedZero(new_cluster)
        }))
    }

    /// Calculate what range of a cluster we need to COW.
    ///
    /// Given potentially a range to skip, calculate what we should COW.  The range will only be
    /// taken into account if it is at one end of the cluster, to always yield a continuous range
    /// to COW (one without a hole in the middle).
    ///
    /// The returned range is also aligned to `alignment` if possible.
    fn get_cow_range(
        &self,
        partial_skip_cow: Option<Range<usize>>,
        alignment: usize,
    ) -> Option<Range<usize>> {
        let mut copy_range = 0..self.header.cluster_size();
        if let Some(partial_skip_cow) = partial_skip_cow {
            if partial_skip_cow.start == copy_range.start {
                copy_range.start = partial_skip_cow.end;
            } else if partial_skip_cow.end == copy_range.end {
                copy_range.end = partial_skip_cow.start;
            }
        }

        if copy_range.is_empty() {
            return None;
        }

        let alignment = cmp::min(alignment, self.header.cluster_size());
        debug_assert!(alignment.is_power_of_two());
        let mask = alignment - 1;

        if copy_range.start & mask != 0 {
            copy_range.start &= !mask;
        }
        if copy_range.end & mask != 0 {
            copy_range.end = (copy_range.end & !mask) + alignment;
        }

        Some(copy_range)
    }

    /// Copy data from one data file cluster to another.
    ///
    /// Used for COW on non-copied data clusters.
    async fn cow_copy_storage(
        &self,
        from: &S,
        from_cluster: HostCluster,
        to_cluster: HostCluster,
        partial_skip_cow: Option<Range<usize>>,
    ) -> io::Result<()> {
        let to = self.storage();

        let align = cmp::max(from.req_align(), to.req_align());
        let Some(cow_range) = self.get_cow_range(partial_skip_cow, align) else {
            return Ok(());
        };

        let mut buf = IoBuffer::new(cow_range.end - cow_range.start, from.mem_align())?;

        let cb = self.header.cluster_bits();
        let from_offset = from_cluster.offset(cb);
        let to_offset = to_cluster.offset(cb);

        from.read(&mut buf, from_offset.0 + cow_range.start as u64)
            .await?;

        to.write(&buf, to_offset.0 + cow_range.start as u64).await?;

        Ok(())
    }

    /// Copy data from another image into our data file.
    ///
    /// Used for COW on clusters served by a backing image.
    async fn cow_copy_format(
        &self,
        from: &F,
        from_offset: u64,
        to_cluster: HostCluster,
        partial_skip_cow: Option<Range<usize>>,
    ) -> io::Result<()> {
        let to = self.storage();
        let from = from.inner();

        let align = cmp::max(from.req_align(), to.req_align());
        let Some(cow_range) = self.get_cow_range(partial_skip_cow, align) else {
            return Ok(());
        };

        let mut buf = IoBuffer::new(cow_range.end - cow_range.start, from.mem_align())?;

        let to_offset = to_cluster.offset(self.header.cluster_bits());

        from.read(&mut buf, from_offset + cow_range.start as u64)
            .await?;

        to.write(&buf, to_offset.0 + cow_range.start as u64).await?;

        Ok(())
    }

    /// Fill the given cluster with zeroes.
    ///
    /// Used for COW on zero clusters.
    async fn cow_zero(
        &self,
        to_cluster: HostCluster,
        partial_skip_cow: Option<Range<usize>>,
    ) -> io::Result<()> {
        let to = self.storage();

        let align = to.req_align();
        let Some(cow_range) = self.get_cow_range(partial_skip_cow, align) else {
            return Ok(());
        };

        let to_offset = to_cluster.offset(self.header.cluster_bits());
        to.write_zeroes(
            to_offset.0 + cow_range.start as u64,
            (cow_range.end - cow_range.start) as u64,
        )
        .await?;

        Ok(())
    }

    /// Decompress a cluster into the target cluster.
    ///
    /// Used for COW on compressed clusters.
    async fn cow_compressed(
        &self,
        compressed_offset: HostOffset,
        compressed_length: u64,
        to_cluster: HostCluster,
    ) -> io::Result<()> {
        let to = self.storage();

        let mut buf = IoBuffer::new(self.header.cluster_size(), to.mem_align())?;
        self.read_compressed_cluster(
            buf.as_mut().into_slice(),
            compressed_offset,
            compressed_length,
        )
        .await?;

        let to_offset = to_cluster.offset(self.header.cluster_bits());
        to.write(&buf, to_offset.0).await?;

        Ok(())
    }
}
