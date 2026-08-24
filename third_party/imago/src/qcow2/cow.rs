//! Copy-on-write operations.
//!
//! Implements copy-on-write when writing to clusters that are not simple allocated data clusters.

use super::*;
use crate::io_buffers::IoBuffer;
use std::collections::HashMap;
use std::sync::Weak;

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
    /// Freshly claimed by this call, not yet mapped into the L2 table. Must be freed if nothing
    /// ever commits it, or it leaks; must not be exposed via the L2 table before the guest's
    /// own write into it has actually succeeded, or an unwritten cluster becomes indistinguishable
    /// from a valid one holding whatever bytes happened to already be there. A concurrent write
    /// into the same cluster may share it, which is what makes freeing it the last user's call
    /// rather than this one's (see [`PendingAllocations`]).
    Fresh(HostCluster),
    /// Claimed by a write that is still in flight (see
    /// [`PendingAllocations`]) and shared with it: its copy-on-write
    /// is already done, so this call adds none of its own. Committing it maps it in like the
    /// claim it shares; freeing it is never this call's to do — the last user standing decides
    /// that.
    SharedPending(HostCluster),
}

impl ClusterAllocation {
    /// The host cluster a guest write into this allocation may target, regardless of which
    /// variant this is.
    pub(super) fn host_cluster(&self) -> HostCluster {
        match *self {
            ClusterAllocation::MappedExisting(hc)
            | ClusterAllocation::ReusedZero(hc)
            | ClusterAllocation::Fresh(hc)
            | ClusterAllocation::SharedPending(hc) => hc,
        }
    }
}

/// Allocations in flight, so that concurrent writes into one guest cluster share the host
/// cluster claimed for it instead of each claiming one of their own.
///
/// A freshly claimed host cluster is deliberately not mapped into the L2 table until the write
/// into it has succeeded (see [`Qcow2Pending`](super::mappings::Qcow2Pending)), so the L2 table
/// alone cannot tell a second writer that a first one is already working on that cluster: both
/// would claim a cluster, both would write their own part of it, and whichever committed last
/// would map its own cluster in and free the other's — dropping bytes the guest had written and
/// been told were on disk. Every claim is registered here for the length of that window instead,
/// so the second writer finds the first one's cluster (its copy-on-write already done, under the
/// same L2 table write guard) and writes into it.
///
/// Every registered claim is released exactly once per user, by that user's commit or abort — or,
/// if every batch holding it was dropped without either, reaped by the next
/// [`share()`](PendingAllocations::share) that finds all its tokens dead.
#[derive(Debug, Default)]
pub(super) struct PendingAllocations {
    /// Guest cluster offset → the claim in flight for it.
    in_flight: HashMap<u64, PendingAllocation>,
}

/// One entry of [`PendingAllocations`].
#[derive(Debug)]
struct PendingAllocation {
    /// The host cluster claimed for this guest cluster.
    host_cluster: HostCluster,
    /// How many writes are using it, i.e. how many claims are yet to be released.
    users: usize,
    /// Whether any of them has mapped it into the L2 table. Once one has, the cluster is live
    /// and the last release must not free it, however the other writes ended.
    mapped: bool,
    /// Whether the claim was a fresh allocation (as opposed to an existing zero cluster being
    /// reused), i.e. whether the last release has anything to free at all.
    fresh: bool,
    /// Whether the claimant gave up while others were still holding the claim. The claimant skips
    /// the copy-on-write for the range it is about to write (that is the point of
    /// `partial_skip_cow`), so if that write never lands, the range keeps whatever bytes the host
    /// cluster happened to already have. That is exactly what deferred mapping exists to keep out
    /// of the L2 table, so the cluster can never go live: the remaining users fail their writes
    /// instead of exposing it. A sharer giving up holes nothing — it does no copy-on-write of its
    /// own precisely because the claimant's already covers every byte outside the claimant's own
    /// range.
    holed: bool,
    /// One token per *current* user — the claimant's and one per sharer; the order is not
    /// meaningful ([`release()`](PendingAllocations::release) uses `swap_remove`). Releasing is
    /// the caller's contract (commit or abort, see
    /// [`Qcow2Pending`](super::mappings::Qcow2Pending)), and a batch dropped without either
    /// already leaks its cluster — but it would also leave this entry behind forever, and a later
    /// write into the same cluster would then share a host cluster nobody is going to map in,
    /// holding whatever the abandoned write left.
    ///
    /// Only once *no* token is live is the entry that wreckage rather than a claim in flight. A
    /// claimant that has aborted (leaving the claim holed) while a sharer is still going to
    /// commit must keep the entry, or that sharer would release against a stranger's claim and
    /// map the holed cluster in.
    ///
    /// And it must be the *release* that drops a token, not the token dying with its batch: a
    /// batch's token outlives its `release()` (it goes with the `Qcow2Pending`). A claim whose
    /// remaining users have all abandoned it would otherwise still read as live while batches
    /// that already released it linger, and be handed to a write that would inherit a host
    /// cluster the abandoned write left half-covered.
    owners: Vec<Weak<()>>,
}

/// What [`PendingAllocations::share()`] found for a caller wanting to write into a guest cluster.
#[derive(Debug, Clone, Copy)]
pub(super) enum SharedClaim {
    /// No write is in flight into this cluster; the caller must claim a host cluster itself.
    Unclaimed,
    /// A write is in flight, and the caller now shares the host cluster it claimed.
    Shared(HostCluster),
    /// A write is in flight, but it claimed a host cluster other than the one the caller must
    /// have — exactly like an existing mapping that does not match, so the caller gives up on
    /// this cluster rather than claiming a second one.
    Elsewhere,
}

/// What one [`PendingAllocations::release()`] leaves its caller to do.
#[derive(Debug, Default)]
pub(super) struct Released {
    /// The host cluster to free: the last user is gone, none of them mapped it in, and it was a
    /// fresh allocation.
    pub(super) orphan: Option<HostCluster>,
    /// The claim is holed (see [`PendingAllocation::holed`]), so the caller must not map the
    /// cluster into the L2 table, and must fail its write instead of reporting bytes it cannot
    /// make visible.
    pub(super) holed: bool,
}

impl PendingAllocations {
    /// Take a share of the claim already in flight for `guest_offset`, if there is one, counting
    /// the caller (and its `owner` token, see [`PendingAllocation::owners`]) as one of its users.
    /// `mandatory_host_cluster` (a caller extending a contiguous run) rejects a claim that sits
    /// elsewhere.
    pub(super) fn share(
        &mut self,
        guest_offset: u64,
        mandatory_host_cluster: Option<HostCluster>,
        owner: &Arc<()>,
    ) -> SharedClaim {
        let Some(entry) = self.in_flight.get_mut(&guest_offset) else {
            return SharedClaim::Unclaimed;
        };
        if entry.owners.iter().all(|token| token.strong_count() == 0) {
            // Nobody is going to release it: every batch holding it went away without committing
            // or aborting. Forget the entry (its cluster is leaked either way, as its own
            // contract says) and let the caller claim a cluster of its own. Checked before the
            // mandatory-cluster test below, so a run-extender is told to claim rather than given
            // a permanent `Elsewhere` against wreckage.
            self.in_flight.remove(&guest_offset);
            return SharedClaim::Unclaimed;
        }
        if mandatory_host_cluster.is_some_and(|mandatory| mandatory != entry.host_cluster) {
            return SharedClaim::Elsewhere;
        }
        entry.owners.push(Arc::downgrade(owner));
        entry.users += 1;
        SharedClaim::Shared(entry.host_cluster)
    }

    /// Register a claim just made for `guest_offset`, with the caller as its first user. Only
    /// ever reached when [`share()`](Self::share) just found no claim for it, under the same L2
    /// table write guard, so it never overwrites a live one.
    pub(super) fn claim(
        &mut self,
        guest_offset: u64,
        host_cluster: HostCluster,
        fresh: bool,
        owner: &Arc<()>,
    ) {
        let previous = self.in_flight.insert(
            guest_offset,
            PendingAllocation {
                host_cluster,
                users: 1,
                mapped: false,
                fresh,
                holed: false,
                owners: vec![Arc::downgrade(owner)],
            },
        );
        debug_assert!(
            previous.is_none(),
            "claim over a live registration for guest offset {guest_offset}"
        );
    }

    /// Release one user's claim on `guest_offset`. `mapped` tells whether it is mapping the
    /// cluster into the L2 table (i.e. committing) or giving up (aborting); `claimant` whether it
    /// is the call that made the claim, as opposed to one that shared it — only the claimant can
    /// leave a hole behind (see [`PendingAllocation::holed`]). `owner` is the releasing batch's
    /// token, dropped from the claim here; `None` only for a batch that established nothing and
    /// so has no entry to release in the first place.
    pub(super) fn release(
        &mut self,
        guest_offset: u64,
        mapped: bool,
        claimant: bool,
        owner: Option<&Arc<()>>,
    ) -> Released {
        let Some(entry) = self.in_flight.get_mut(&guest_offset) else {
            return Released::default();
        };
        if let Some(owner) = owner {
            // This user is done, so its token no longer speaks for the claim. Each batch shares
            // a given guest offset at most once, so this drops exactly one.
            let target = Arc::as_ptr(owner);
            if let Some(i) = entry
                .owners
                .iter()
                .position(|token| std::ptr::eq(token.as_ptr(), target))
            {
                entry.owners.swap_remove(i);
            }
        }
        if mapped {
            // A holed claim must not go live, so a commit on one maps nothing in.
            entry.mapped |= !entry.holed;
        } else if claimant && entry.users > 1 {
            entry.holed = true;
        }
        let holed = entry.holed;
        debug_assert!(entry.users > 0, "claim released more often than taken");
        entry.users = entry.users.saturating_sub(1);
        if entry.users > 0 {
            return Released {
                orphan: None,
                holed,
            };
        }
        let entry = self
            .in_flight
            .remove(&guest_offset)
            .expect("just looked it up");
        Released {
            orphan: (!entry.mapped && entry.fresh).then_some(entry.host_cluster),
            holed,
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
        owner: &Arc<()>,
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

        let guest_offset = cluster.offset(self.header.cluster_bits()).0;

        // A write already in flight into this cluster has claimed a host cluster for it that the
        // L2 table cannot show yet (see `PendingAllocations`) — write into that one rather than
        // claim a second, and skip the copy-on-write it has already done. Only reachable once its
        // claimant has dropped this L2 table's write guard, so that COW is complete by now.
        let shared = {
            let mut pending_allocs = self.pending_allocs.lock().await;
            pending_allocs.share(guest_offset, mandatory_host_cluster, owner)
        };
        match shared {
            SharedClaim::Shared(host_cluster) => {
                return Ok(Some(ClusterAllocation::SharedPending(host_cluster)));
            }
            // Claimed, but not where this caller needs it: give up on continuing the contiguous
            // run here, exactly as a mismatching existing mapping does above. Claiming a second
            // cluster for the same guest cluster instead would supersede the one in flight, which
            // is the very race this registry exists to close.
            SharedClaim::Elsewhere => return Ok(None),
            SharedClaim::Unclaimed => (),
        }

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

        // Register the claim for as long as the write into it is in flight, so a concurrent
        // write into the same cluster shares it instead of superseding it.
        self.pending_allocs
            .lock()
            .await
            .claim(guest_offset, new_cluster, fresh, owner);

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

#[cfg(test)]
mod tests {
    use super::{HostCluster, PendingAllocations, SharedClaim};
    use std::sync::Arc;

    /// An owner token standing in for a `Qcow2Pending`, kept alive for as long as the batch
    /// that made the claim would be.
    fn owner() -> Arc<()> {
        Arc::new(())
    }

    /// `share()` must distinguish "nothing in flight" (claim your own) from "in flight, but
    /// elsewhere" (give up): conflating them lets a caller extending a contiguous run claim a
    /// second host cluster for a guest cluster that already has one in flight, whose claim it
    /// then overwrites — the very race the registry closes.
    #[test]
    fn a_claim_elsewhere_is_not_an_unclaimed_cluster() {
        let (here, elsewhere) = (HostCluster(1), HostCluster(2));
        let keep = owner();
        let mut pending = PendingAllocations::default();

        assert!(matches!(
            pending.share(0, Some(here), &keep),
            SharedClaim::Unclaimed
        ));
        pending.claim(0, here, true, &keep);

        assert!(matches!(pending.share(0, None, &keep), SharedClaim::Shared(hc) if hc == here));
        assert!(
            matches!(pending.share(0, Some(here), &keep), SharedClaim::Shared(hc) if hc == here)
        );
        assert!(matches!(
            pending.share(0, Some(elsewhere), &keep),
            SharedClaim::Elsewhere
        ));
    }

    /// A fresh claim is freed once, by whichever user is last, and only if none of them mapped
    /// it into the L2 table — a cluster another write has already made live must survive this
    /// one's failure.
    #[test]
    fn only_the_last_user_of_an_unmapped_fresh_claim_frees_it() {
        let hc = HostCluster(1);

        // Everyone gives up: the last one out frees it.
        let keep = owner();
        let mut pending = PendingAllocations::default();
        pending.claim(0, hc, true, &keep);
        assert!(matches!(
            pending.share(0, None, &keep),
            SharedClaim::Shared(_)
        ));
        assert_eq!(pending.release(0, false, true, Some(&keep)).orphan, None);
        assert_eq!(
            pending.release(0, false, true, Some(&keep)).orphan,
            Some(hc)
        );

        // One of them mapped it in: it is live, and nobody frees it.
        let mut pending = PendingAllocations::default();
        pending.claim(0, hc, true, &keep);
        assert!(matches!(
            pending.share(0, None, &keep),
            SharedClaim::Shared(_)
        ));
        assert_eq!(pending.release(0, true, true, Some(&keep)).orphan, None);
        assert_eq!(pending.release(0, false, true, Some(&keep)).orphan, None);

        // A reused zero cluster was never this registry's to free, however it ends.
        let mut pending = PendingAllocations::default();
        pending.claim(0, hc, false, &keep);
        assert_eq!(pending.release(0, false, true, Some(&keep)).orphan, None);
    }

    /// The claimant skips the copy-on-write for the range it is about to write, so if it gives up
    /// while others still hold the claim, that range keeps whatever bytes were already there and
    /// nothing will fill it. The cluster must never go live: the remaining users' commits fail
    /// instead, and it is freed rather than mapped in.
    #[test]
    fn a_claimant_giving_up_holes_a_claim_others_still_hold() {
        let hc = HostCluster(1);
        let keep = owner();
        let mut pending = PendingAllocations::default();
        pending.claim(0, hc, true, &keep);
        assert!(matches!(
            pending.share(0, None, &keep),
            SharedClaim::Shared(_)
        ));

        let aborted = pending.release(0, false, true, Some(&keep));
        assert!(aborted.holed);
        assert_eq!(aborted.orphan, None);

        let committed = pending.release(0, true, false, Some(&keep));
        assert!(committed.holed, "a holed claim must not go live");
        assert_eq!(
            committed.orphan,
            Some(hc),
            "a claim nobody may map in is an orphan, not a live cluster"
        );
    }

    /// A sharer, though, holes nothing when it gives up: it does no copy-on-write of its own
    /// precisely because the claimant's already covers every byte outside the claimant's range.
    /// Failing the claimant's own successful write over it would be a write lost for nothing.
    #[test]
    fn a_sharer_giving_up_holes_nothing() {
        let hc = HostCluster(1);
        let keep = owner();
        let mut pending = PendingAllocations::default();
        pending.claim(0, hc, true, &keep);
        assert!(matches!(
            pending.share(0, None, &keep),
            SharedClaim::Shared(_)
        ));

        let aborted = pending.release(0, false, false, Some(&keep));
        assert!(!aborted.holed);
        assert_eq!(aborted.orphan, None);

        let committed = pending.release(0, true, true, Some(&keep));
        assert!(!committed.holed, "the claimant's write must still stand");
        assert_eq!(
            committed.orphan, None,
            "a cluster mapped in is live, not an orphan"
        );
    }

    /// The last user giving up alone leaves no hole behind — there is nobody left to expose the
    /// cluster to, and it is freed whole.
    #[test]
    fn a_lone_user_giving_up_holes_nothing() {
        let keep = owner();
        let mut pending = PendingAllocations::default();
        pending.claim(0, HostCluster(1), true, &keep);
        let released = pending.release(0, false, true, Some(&keep));
        assert!(!released.holed);
        assert_eq!(released.orphan, Some(HostCluster(1)));
    }

    /// Releasing a claim that is gone (its last user already released it) is a no-op, not a
    /// panic: a `MappedExisting` allocation never registers one in the first place.
    #[test]
    fn releasing_an_unregistered_cluster_does_nothing() {
        let keep = owner();
        let mut pending = PendingAllocations::default();
        let released = pending.release(0, true, true, Some(&keep));
        assert!(!released.holed);
        assert_eq!(released.orphan, None);
    }

    /// A claim outlives the batch that made it for as long as anyone else still holds it: the
    /// claimant can abort (holing the claim) and drop its token while a sharer is still going to
    /// commit. Reaping the entry then would let the sharer release against a stranger's claim and
    /// map the holed cluster in — the very exposure the hole exists to prevent.
    #[test]
    fn a_claim_a_sharer_still_holds_is_not_reaped() {
        let (shared, elsewhere) = (HostCluster(1), HostCluster(2));
        let mut pending = PendingAllocations::default();

        let claimant = owner();
        pending.claim(0, shared, true, &claimant);
        let sharer = owner();
        assert!(matches!(pending.share(0, None, &sharer), SharedClaim::Shared(hc) if hc == shared));

        // The claimant gives up and goes away; the sharer is still live.
        assert!(pending.release(0, false, true, Some(&claimant)).holed);
        drop(claimant);

        let next = owner();
        assert!(
            matches!(pending.share(0, None, &next), SharedClaim::Shared(hc) if hc == shared),
            "a claim a live sharer still holds must not be reaped as wreckage"
        );
        // Still a live claim, so a run-extender wanting another cluster is refused as usual —
        // the liveness check does not swallow a genuine mismatch.
        assert!(matches!(
            pending.share(0, Some(elsewhere), &next),
            SharedClaim::Elsewhere
        ));

        // And it is still holed, so neither of them can map it in.
        assert!(pending.release(0, true, false, Some(&sharer)).holed);
        let last = pending.release(0, true, false, Some(&next));
        assert!(last.holed);
        assert_eq!(
            last.orphan,
            Some(shared),
            "a holed claim nobody mapped in is freed by its last release"
        );
    }

    /// One batch abandoning a claim others still hold does not make it wreckage: reaping is
    /// "every token dead", not "any". Reaping on the first dead one would hand the next write a
    /// cluster of its own for a guest cluster that already has a claim in flight — superseding
    /// it, which is exactly the loss this registry exists to prevent.
    #[test]
    fn one_abandoned_user_does_not_reap_a_claim_others_hold() {
        let mut pending = PendingAllocations::default();

        let claimant = owner();
        pending.claim(0, HostCluster(1), true, &claimant);
        let abandoner = owner();
        assert!(matches!(
            pending.share(0, None, &abandoner),
            SharedClaim::Shared(_)
        ));
        drop(abandoner); // no release(): that batch went away

        let next = owner();
        assert!(
            matches!(pending.share(0, None, &next), SharedClaim::Shared(hc) if hc == HostCluster(1)),
            "one dead token must not reap a claim its claimant still holds"
        );
    }

    /// A user's token stops speaking for the claim when that user releases, not when its batch
    /// is finally dropped — the two are not the same moment, since the token goes with the
    /// `Qcow2Pending` the caller still holds. Without that, a claim whose remaining user had
    /// abandoned it would read as live off a token belonging to a batch that already released,
    /// and be handed to the next write.
    #[test]
    fn a_released_user_stops_keeping_a_claim_alive() {
        let mut pending = PendingAllocations::default();

        let claimant = owner();
        pending.claim(0, HostCluster(1), true, &claimant);
        let sharer = owner();
        assert!(matches!(
            pending.share(0, None, &sharer),
            SharedClaim::Shared(_)
        ));

        // The sharer is done, but its batch lives on (as a `Qcow2Pending` not yet dropped).
        pending.release(0, false, false, Some(&sharer));
        assert!(Arc::strong_count(&sharer) > 0);
        // The claimant, the only user left, goes away without releasing.
        drop(claimant);

        let next = owner();
        assert!(
            matches!(pending.share(0, None, &next), SharedClaim::Unclaimed),
            "a token whose user already released must not keep wreckage alive"
        );
    }

    /// A batch dropped without committing or aborting leaks its cluster (its own documented
    /// contract) — but its registration must not outlive it as something to share: the cluster
    /// holds whatever the abandoned write left, and nobody is coming to map it in. A later write
    /// into that cluster must find it unclaimed and claim one of its own.
    #[test]
    fn an_abandoned_claim_is_not_shared_with_the_next_write() {
        let (abandoned, mine) = (HostCluster(1), HostCluster(2));
        let mut pending = PendingAllocations::default();

        let keep = owner();

        let gone = owner();
        pending.claim(0, abandoned, true, &gone);
        drop(gone); // the batch went away without commit() or abort()

        // A run-extender first, against untouched wreckage: it must be told to claim, not given
        // a permanent `Elsewhere` — liveness is judged before the mandatory cluster. `mine` is
        // deliberately not `abandoned`, so only that ordering can produce `Unclaimed`.
        assert!(matches!(
            pending.share(0, Some(mine), &keep),
            SharedClaim::Unclaimed
        ));

        // And the plain case, against wreckage the reap above has not already removed.
        let gone = owner();
        pending.claim(0, abandoned, true, &gone);
        drop(gone);
        assert!(
            matches!(pending.share(0, None, &keep), SharedClaim::Unclaimed),
            "an abandoned claim must not be handed to the next write"
        );

        // And the cluster the next write claims for itself behaves like any other claim.
        pending.claim(0, mine, true, &keep);
        assert!(matches!(pending.share(0, None, &keep), SharedClaim::Shared(hc) if hc == mine));
        assert_eq!(pending.release(0, false, false, Some(&keep)).orphan, None);
        assert_eq!(
            pending.release(0, false, true, Some(&keep)).orphan,
            Some(mine)
        );
    }
}
