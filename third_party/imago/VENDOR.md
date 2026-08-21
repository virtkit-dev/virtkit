# Vendored imago

Source: https://gitlab.com/hreitz/imago (published to crates.io as `imago`)
Revision: `0.2.4`

Only the Rust sources are vendored: `Cargo.toml`, `Cargo.lock`, `LICENSE`, `build.rs`, and
`src/`. `README.md`, `rustfmt.toml`, and the GitLab CI files are dropped as unneeded for the
build.

A leaf crate (no sub-crates), so unlike `third_party/libkrun` it does not need its own
workspace exclusion beyond the root `Cargo.toml`'s `exclude`. `third_party/libkrun/src/devices`
depends on it by path instead of the crates.io release.

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

Commit/abort can't fail: commit is an infallible in-memory L2 update; abort's free is already
best-effort crate-wide (see `Qcow2::free_data_clusters()`).

**Tests:** `format::access::writev_failure_tests`, both fail if `abort()` is swapped for
`commit()`:
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

Suspected (not confirmed upstream) root cause of a `vk build` corruption incident: real
`Input/output error`s from ext4 on unrelated later operations touching the same region. Image is
tmpfs-backed, so likely trigger is `ENOSPC` under concurrent build load, not a disk fault. Not
reported upstream yet.
