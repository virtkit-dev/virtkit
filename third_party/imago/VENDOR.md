# Vendored imago

Source: https://gitlab.com/hreitz/imago (published to crates.io as `imago`)
Revision: `0.2.4`

Only the Rust sources are vendored: `Cargo.toml`, `Cargo.lock`, `LICENSE`, `build.rs`, and
`src/`. `README.md`, `rustfmt.toml`, and the GitLab CI files are dropped as unneeded for the
build.

A leaf crate (no sub-crates), so unlike `third_party/libkrun` it does not need its own
workspace exclusion beyond the root `Cargo.toml`'s `exclude`. `third_party/libkrun/src/devices`
depends on it by path instead of the crates.io release.

## Feature selection

`third_party/libkrun/src/devices` builds imago with `default-features = false, features =
["sync"]`, not the default `async` (+ `sync-wrappers` for a blocking API on top of it). The
virtio-blk worker (`block/worker.rs`) is a single-threaded epoll loop that pulls one virtqueue
descriptor at a time and blocks on it synchronously — there is no batching or queue depth, so
nothing in that path benefits from async scheduling. `sync-wrappers` (what the code used before)
still built the full `async` implementation and drove every `readv`/`writev` through a
`tokio::runtime::Runtime::block_on()` call — pure per-request overhead for zero concurrency
gain. `sync` (`maybe-async/is_sync`) compiles the same logic as plain, non-async `fn`s with no
tokio dependency at all; imago's own docs already call `sync-wrappers` deprecated in favor of it.

Trade-off: `set_async_read_parallelization()`/`set_async_write_parallelization()` (fan a single
request out into concurrent sub-fetches across non-contiguous qcow2 clusters) only exist under
`async`/`sync-wrappers` and are unavailable under `sync`. The block worker never set either
(both default to `1`), so this cost nothing today; revisit if the worker is later changed to
keep multiple guest requests in flight.

Call-site fallout from the switch: `imago::SyncFormatAccess` doesn't exist under `sync` (it's
`#[cfg(feature = "sync-wrappers")]`) — `block/device.rs` uses plain `imago::FormatAccess`
instead. Every `_sync`-suffixed method (`open_sync`, `open_image_sync`,
`open_implicit_dependencies_sync`, ...) is likewise `sync-wrappers`-only; under `sync`,
`#[maybe_async]` already turns the unsuffixed methods (`open`, `open_image`,
`open_implicit_dependencies`, ...) into plain synchronous calls, so those are used directly.
`FormatAccess::new()` returns `Self` (not `io::Result<Self>`) in both modes — it never builds a
runtime — so the call sites that used to have a trailing `?` after `SyncFormatAccess::new(...)`
lost it.

## Local patches

**Bug:** `ensure_data_mapping()` allocates (or COWs) a cluster and commits it to the L2 table
*before* the caller's own write into it happens. If that write fails, the cluster stays mapped
in with whatever undefined bytes were already there — real, allocated storage, not a hole, so
it's invisible to a plain allocation-vs-write-tracking check (virtkit's own dirty-tracking gap
check included) and can be picked up as real data by a later flush.

**Fix:** `ensure_data_mapping()` returns a fourth item, `PendingDataMapping`
(`format/drivers.rs`). The mapping is only committed to the L2 table when the caller calls
`commit()` (write succeeded) — `abort()` frees it instead (write failed). Allocate → write →
expose is now transactional; a failed write never gets exposed.

- `raw.rs` / `vmdk/mod.rs`: no real allocation step, return no-op `NoopPending`.
- `qcow2/cow.rs`: `cow_cluster()` returns `ClusterAllocation::{MappedExisting,ReusedZero,Fresh}`
  instead of mapping the cluster in itself — `MappedExisting` is a real no-op (already mapped as
  data); `ReusedZero` (an already-allocated, zero-flagged cluster reused as-is) still needs
  mapping in on commit to clear that flag, even though, like `MappedExisting`, it must never be
  freed on abort.
- `qcow2/mappings.rs`: `do_ensure_data_mapping()`/`ensure_data_mapping_no_cleanup()` collect
  allocations into a `Qcow2Pending` instead of committing as they go; on internal error, aborts
  everything collected so far (a mid-range failure no longer leaves earlier clusters exposed).
- `qcow2/preallocation.rs`: `preallocate()` commits on success / aborts on failure through the
  same mechanism.

Abort can't fail: its free is already best-effort crate-wide (see
`Qcow2::free_data_clusters()`). Commit is otherwise an infallible in-memory L2 update, and fails
only for a holed claim (see the second patch below).

**Bug:** deferring the mapping also hides it from a *concurrent* writer. Two guest writes into the
same qcow2 cluster (the virtio-blk worker pool dispatches them to different threads, see
`block/worker.rs`) each found the cluster unmapped, each claimed a host cluster of its own, and
whichever committed last mapped its own in and freed the other's — dropping bytes the guest had
been told were on disk. A hole inside a region the guest wrote whole, surfacing later and at
random: an unreadable file in a built image, a stage that would not boot.

**Fix:** `qcow2/cow.rs` gains `PendingAllocations`, a registry of the claims in flight keyed by
guest cluster offset, held in `Qcow2::pending_allocs`. `cow_cluster()` consults it before
allocating and registers its own claim before returning; each claim is released exactly once per
user by `Qcow2Pending::commit()`/`abort()`.

- `ClusterAllocation::SharedPending` is the fourth variant: this call is writing into a claim
  another write in flight made, whose copy-on-write is already done (it happened under the same L2
  table write guard), so this call adds none of its own.
- `share()` is three-valued. "In flight, but at another host cluster" is *not* "unclaimed": a
  caller extending a contiguous run demands one specific host cluster, and must break the run
  there rather than claim a second cluster for a guest cluster that already has one in flight —
  claiming one would supersede the claim in flight, which is the very loss being fixed.
- Freeing a fresh claim is the last user's call, and only if none of them mapped it in.
- Holed claims: the *claimant* skips the copy-on-write for the range it is about to write, so if
  it gives up while others still hold the claim, that range keeps whatever bytes the host cluster
  already had — exactly what deferred mapping exists to keep out of the L2 table. Such a claim can
  never go live: the remaining users' `commit()`s fail (so the guest is told its write failed,
  rather than being handed a cluster with a hole in it) and the cluster is freed. A sharer giving
  up holes nothing, and must not fail the claimant's successful write.
- `format/access.rs`: `writev`'s `async` `write_parallelization > 1` path used to drop its
  `FuturesUnordered` on the first error — and on an `ensure_data_mapping()` error — dropping
  uncommitted, unaborted `PendingDataMapping`s with it. That leaves a claim behind that nobody
  will release; it drains the workers instead (`drain()`). `readv`'s workers own no mappings and
  still return on the first error.
- Liveness tokens: every batch holds an `Arc<()>` and each of its claims a `Weak<()>` of it, so a
  claim that outlived every batch holding it is recognisable as wreckage and reaped by the next
  `share()` rather than handed out — a host cluster nobody is going to map in, holding whatever
  the abandoned write left. Per *user*, not per claimant: a claimant can abort (holing the claim)
  and go away while a sharer is still going to commit, and reaping the entry then would let that
  sharer release against a stranger's claim and map the holed cluster in. A user's token is
  dropped by its own `release()`, not left to die with its batch, so the vector tracks the current
  users: a claim whose remaining users have all abandoned it is reaped even while batches that
  already released it linger. Dropping a batch without committing or aborting still leaks its
  cluster, which is why `drain()` above stays.

**Known gap.** One ordering is still not covered: a sharer commits (mapping the cluster in) and
*then* the claimant's own write fails. The cluster is live by then, so no flag can hold it back,
and its claimant's skipped range keeps stale bytes. Closing it properly means never sharing a
cluster that is not already valid — i.e. dropping the `partial_skip_cow`/`full_skip_cow`
optimisation for any claim that gets registered, which costs a full cluster copy on every
first write to a backed cluster. Deliberately not taken here: the window needs a genuine storage
failure (`ENOSPC`/`EIO`) racing a second write into the same cluster, and the unpatched code
loses data on that second write alone, with no failure required.

**Tests (deferred mapping):** `format::access::writev_failure_tests`, all three fail if `abort()`
is swapped for `commit()`:
- `a_failed_fresh_allocation_never_becomes_a_visible_mapping` — mock (`MemStorage`) write
  failure; `Null` can't stand in, it doesn't round-trip writes, so it can't back qcow2's own
  metadata.
- `a_real_efbig_mid_write_never_becomes_a_visible_mapping` — real repro: real file,
  `RLIMIT_FSIZE` forces a genuine mid-write `EFBIG`. Confirms this isn't a short-write-reported-
  as-success bug (`file.rs`'s `pure_writev()` loops pwritev to completion and only ever returns
  `Err` on a real syscall error) — some bytes truly land, `Err` is truthful, and the *caller*
  still must not expose the rest of the cluster.
- `a_write_into_a_reused_zero_cluster_stays_visible` — covers the `ReusedZero` case above: writes
  data, `write_zeroes()`s it back (retaining the allocation), then writes again and checks the
  new data reads back correctly instead of the stale zero flag hiding it.

All three are written as `#[maybe_async]` bodies driven through a small `block_on_test!` macro
(current-thread `tokio` runtime under `async`, direct call under `sync`), so they — and the
whole crate's test suite — compile and pass under `cargo test --no-default-features --features
sync` too, not just the crate's default `async` build. They weren't originally: the rest of
imago's pre-existing test suite is `async`-only (an unconditional `tokio` dev-dependency, tests
built on raw `tokio::runtime::Builder::block_on`), so nothing here exercised `sync` before we
started building `third_party/libkrun/src/devices` with it (see Feature selection above).

**Tests (shared claims):** `qcow2::cow::tests` covers the registry's decisions directly — that a
claim elsewhere is not an unclaimed cluster, that only the last user of an unmapped fresh claim
frees it, and that a user giving up holes a claim others still hold. The liveness tokens add four:
an abandoned claim is not shared with the next write, one a live sharer still holds is not reaped,
one dead token among live ones does not reap either, and a token whose user already released stops
keeping the claim alive. Being plain unit tests they run in both feature modes and need no thread
interleaving to be deterministic.

The end-to-end races live with the virtio-blk device that provokes them, in
`third_party/libkrun/src/devices` (`block/device.rs`), since they need real threads writing
through a shared `FormatAccess` and only that crate builds imago with `sync`:
`concurrent_writes_into_one_qcow2_cluster_all_land` (two writes into one cluster) and
`a_write_extending_its_run_never_supersedes_a_claim_in_flight` (a multi-cluster write's contiguous
run meeting a claim in flight). Both fail against the unpatched `qcow2/cow.rs`. They are
probabilistic by nature, so both loop over many rounds rather than racing once.

Suspected (not confirmed upstream) root cause of a `vk build` corruption incident: real
`Input/output error`s from ext4 on unrelated later operations touching the same region. Image is
tmpfs-backed, so likely trigger is `ENOSPC` under concurrent build load, not a disk fault. Not
reported upstream yet.
