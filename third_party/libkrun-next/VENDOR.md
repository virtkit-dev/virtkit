# Vendored libkrun 2.0 (development branch)

Source: https://github.com/libkrun/libkrun (formerly `containers/libkrun`)
Revision: `97a914ee06210fa2553b2ab75493bf6e8888910e` (`main`, version 2.0.0-dev), plus
upstream PR #875 (modern virtio-pci transport and the PCI host bridge in ACPI) at `cfb03d6`
(base `e66cad1`), its eight commits cherry-picked onto that revision.

This tree replaces `third_party/libkrun` (stable-1.19.x) once virtkit is ported to the 2.0
Rust API; until then nothing links it. Only the Rust sources are vendored: `Cargo.toml`,
`Cargo.lock`, `LICENSE` and `src/`. It is its own cargo workspace, excluded from the root
virtkit workspace.

## Local patches

`Cargo.toml` (workspace) — drop the `init/init-blob` and `bindings/*` members, which are not
vendored and depend on the `ffier` git crate, and the `examples/gtk_display` and
`init/init-binary` excludes, which are not vendored either. Exclude `src/display` and
`src/input` from the members: they stay reachable as optional path dependencies of the
`gpu`/`input`/`vhost-user` features, but as members a plain workspace build or clippy would
run their bindgen.

`src/libkrun/Cargo.toml` + `src/devices/Cargo.toml` — drop the `ffier`/`ffier-builtins` git
dependencies: Cargo locks optional dependencies too, so they would fetch a git repository
into an offline, reproducible build. `devices`' `ffi` feature stays, empty, and `libkrun`'s
keeps its non-ffier members (`serde_json`, `devices/ffi`), so the code they gate still parses
as a known cfg; nothing enables them, and enabling them no longer builds. `crate-type` is
`lib` only.

`src/libkrun/build.rs` — drop the `cdylib` soname link arguments (no cdylib is built).

`src/devices/src/virtio/fs/linux/passthrough.rs` — `statx` through the raw syscall
(`mod statx_compat`): libc no longer exports its musl `statx` struct, function and `STATX_*`
constants, and virtkit builds for `x86_64-unknown-linux-musl`. This tree's own `Cargo.lock`
pins libc 0.2.183; the patch is for the root workspace's lock (0.2.189 when vendored), which
builds the tree once vk-driver links it. `struct statx` is fixed by the kernel UAPI, so the
module mirrors it and calls `SYS_statx`; behaviour, including the returned `stx_mnt_id`, is
unchanged; a const assertion pins the struct at the UAPI's 256 bytes.

`src/devices/src/virtio/descriptor_utils.rs` — clamp the final descriptor in
`DescriptorChainConsumer::consume`, forward-ported from the 1.19 tree. Its contract is that
the slices handed to the callback total `<= count`, but it pushed the last descriptor whole,
so a vectored disk read (`Writer::write_from_at`) filled past `count` into guest memory the
driver never asked for. Covered by `write_from_at_must_not_overread_past_count`.

### virtio-fs passthrough (forward-ported from the 1.19 tree)

`src/devices/src/virtio/fs/{linux,macos}/passthrough.rs` — share options the passthrough
`Config` did not carry (`no_sync` on both hosts, the rest on Linux): `negative_timeout` (a
missed lookup answers a zero-inode entry with that validity instead of ENOENT, so the guest
caches the miss; zero, the default, keeps the error),
`no_sync` (FLUSH, FSYNC and FSYNCDIR answer ENOSYS, which the FUSE client takes as "never
again" for the mount; on macOS the errno goes through `linux_error`, since the host's ENOSYS
is not Linux's) and `dax_inode_min` (per-inode DAX by size: INIT takes `HAS_INODE_DAX`
when the guest offers it, a `dax=inode` mount, and entries of regular files at or above the
floor carry `ATTR_DAX`, added to `fuse.rs`). Defaults leave behaviour unchanged.

`src/devices/src/virtio/fs/{linux,macos}/passthrough.rs` — `do_open` on a directory under
`CachePolicy::Always` replies `FOPEN_CACHE_DIR | FOPEN_KEEP_CACHE`: `fuse_dir_open` drops the
readdir cache on every `opendir` without `FOPEN_KEEP_CACHE`, so every directory was re-read on
every pass over the tree. On Linux a `CachePolicy::Always` share also serves directories
without `opendir`: INIT takes `ZERO_MESSAGE_OPENDIR` and `opendir` answers ENOSYS, which sets
`fc->no_opendir`; READDIR, READDIRPLUS and FSYNCDIR then arrive without a handle and go
through a descriptor opened from the inode for that request. `auto`/`never` keep `opendir`.

`src/devices/src/virtio/fs/linux/passthrough.rs` — `setupmapping` serves a DAX window from an
fd already open on the inode (matched by inode and access mode), reopening through
`/proc/self/fd` only when none is. The guest passes `fh = u64::MAX` with every DAX mapping, and
a reopen re-derives access from the inode's current mode: a file opened writable then chmod'd
0444 (git's temp pack, rewritten in place on an incremental fetch) could no longer be mapped
writable, turning in-place writes into EACCES or SIGBUS. `removemapping` merges the adjacent
ranges of a batch into one mmap (`merge_mappings`).

`src/devices/src/virtio/fs/read_only.rs` — on Linux, REMOVEMAPPING on a read-only share keeps
the DAX mapping in place, bounds still checked: a guest reading a source tree reclaims a range
for nearly every file once its window is full, each costing an mmap and a KVM invalidation,
and a kept read-only mapping is replaced by the next SETUPMAPPING (MAP_FIXED). On macOS it
still delegates: there the inner removemapping releases the host mmap, and the next
SETUPMAPPING maps afresh, so a kept mapping would leak.

`src/devices/src/virtio/fs/server.rs` — READDIRPLUS forgets an entry that did not fit the
reply. Its lookup took an inode reference the guest never counted, so no FORGET released it
and the O_PATH fd stayed open for the life of the mount (362 pinned inodes on a 37k-entry
tree). Upstream virtiofsd does the same.

Covered by the passthrough `negative_lookup_*`, `no_sync_*`, `setupmapping_*`,
`removemapping_*` and `lookup_marks_large_regular_files_for_dax` tests,
`removemapping_keeps_the_mapping_but_checks_bounds`,
`readdirplus_forgets_the_entry_that_did_not_fit`, and `unknown_ioctl_returns_enotty` (the
1.19 tree's guard on an ENOTTY reply 2.0 already gives).

Not carried over: the 1.19 tree's `Reader/Writer::from_volatile_slices` constructors and
public `filesystem`/`read_only` modules, which only virtkit's removed vhost-user daemon used.

### Directory-entry names (forward-ported from the 1.19 tree)

`src/devices/src/virtio/fs/server.rs` — a directory-entry name from the guest must be exactly
one component. `LOOKUP`, `MKNOD`, `MKDIR`, `SYMLINK` (its new name, not the target), `UNLINK`,
`RMDIR`, `RENAME`/`RENAME2` (both names), `LINK` and `CREATE` answer `EINVAL` for an empty name,
`.`, `..` or one containing `/`, before any filesystem sees it. The passthrough engines
resolve names with `*at()` against the parent's `O_PATH` descriptor and relied on the guest
kernel never sending such a name, so a guest kernel that did — and a job can bring its own —
walked out of the share to anything the VMM's user can read or write. Upstream virtiofsd
refuses the same names (`validate_path_component`). In the server, so the in-process engines
and their read-only, id-mapped and `AugmentFs` wrappers all get it. Unix hosts only: the
Windows engine joins names onto a `PathBuf`, where `\` and drive prefixes are separators
too. LOOKUP and RENAME tests drive the refusal through the server and check that only single
components reach the filesystem. Search for `entry_name`.

### Single-file shares (forward-ported from the 1.19 tree)

`src/devices/src/virtio/fs/{single_file.rs (new),mod.rs,worker.rs}` — on Linux, a share whose
root is a regular file serves that file alone, never its parent directory (a single-file bind
mount, which `vk run -v host-file:guest-file` asks for). `SingleFileFs` exposes a root
directory holding the one file, read-only or read-write as the share is; a guest create or
rename stages vk-named scratch files in the host parent directory, reclaimed on drop. It has
no `AugmentFs` wrapper or virtual entries. Elsewhere a file root still fails in
`PassthroughFs::new`. The 1.19 tree's public `single_file` module is private here. Covered by
`single_file::tests`.

### Id-mapped shares (forward-ported from the 1.19 tree)

`src/devices/src/virtio/fs/{idmap.rs (new),mod.rs,worker.rs,device.rs}` — UID/GID mapping for
virtio-fs shares. `idmap` parses virtiofsd-compatible `--uid-map`/`--gid-map` rules (`map:`,
`squash-guest:`, `forbid-guest:`, …) and `IdMapFs` applies them at the `FileSystem` boundary,
wrapped inside `AugmentFs` when a map is set (`Fs::set_id_maps`). virtkit squashes a CI job's
checkout share onto the host runner user with it, so a non-root job can write it. Unmapped
shares have no wrapper and are served exactly as upstream. A mapped share does not offer
`FUSE_ALLOW_IDMAP` (2.0 offers it under `LinuxComplete`, 1.19 always): with it the guest
kernel sends `FUSE_INVALID_UIDGID` for every request but the creating ones, which the soft
map would translate, or let past `forbid-guest`, in place of the caller's ids. The 1.19
tree's public `IdMap`/`IdMapFs`/`IdTable` re-exports are not carried. Covered by
`idmap::tests` and `a_mapped_share_never_offers_allow_idmap`. A single-file share ignores
the maps.

### Share-option setters

`src/devices/src/virtio/fs/device.rs` — `Fs::passthrough_config_mut` lets the API configure
a host-backed share before activation without adding parameters to `Fs::new`.

`src/libkrun/src/api/{device_builders.rs,mod.rs}` — `FsDevice` setters for the share options
the 1.19 tree's `krun_add_virtiofs7` carried: `set_id_maps`, `set_cache` (policy,
entry/attr/negative validity; `FsCachePolicy` re-exports the passthrough `CachePolicy`),
`set_xattr`, `set_writeback`, `set_no_sync` (not on Windows) and `set_dax_inode_min` (Linux
only; `set_cache`'s negative validity is ignored elsewhere). With upstream's
`set_dax_window_size` and `new_read_only` they cover every `krun_add_virtiofs7` argument.
Two differ from 1.19: the passthrough setters refuse a null share with `InvalidParam`, where
1.19 dropped the options, and `set_dax_inode_min(Some(0))` marks every regular file, where
1.19 took a floor of 0 as off. Rust-only (no `ffier` export). Additive: a device built
without them behaves as upstream's. Covered by `fs_option_tests`.

### virtio-blk (forward-ported from the 1.19 tree)

`src/devices/Cargo.toml` — imago is virtkit's vendored `third_party/imago` (0.2.4 plus its
local patches, see its VENDOR.md), by path, still `sync` + `vm-memory`. The lazy chunk storage
below adds `zstd`, `lru` (until now a macOS-only dependency) and `maybe-async` (`is_sync`).

`src/devices/src/virtio/block/{device.rs,file_traits.rs}` — serve reads from read-only raw disks
out of an `mmap` of the image (`DiskMmap`) instead of a `pread` per request: such an image
(a build stage's `COPY --from` source, a read-only root) is immutable and its block offset is
its file offset. qcow2 and `direct_io` keep the imago path; a failed `mmap` falls back to it,
and so does every disk off Unix hosts.

`src/devices/src/virtio/block/{device.rs,worker.rs}` — the image sits behind an `RwLock`, and
the worker pops up to `IO_PARALLELISM` requests and runs each on a scoped thread, since imago's
`readv`/`writev` need only `&self`; write-zeroes and the dirty-control commands take the write
lock. Interrupts are raised once per batch that completed anything.

`src/devices/src/virtio/block/{device.rs,worker.rs}` + `src/libkrun/src/api/device_builders.rs` —
track guest-written clusters and drain them on demand, so virtkit's build backend captures only
a checkpoint's delta. The worker records every write, discard and write-zeroes in a per-disk
`DirtyRanges` (64 KiB clusters); with `BlockDevice::set_dirty_control_socket`,
`Block::spawn_dirty_control` serves `b'D'` (flush, then reply the written and discarded ranges
since the last drain: `u32 count` then `count × (u64 offset, u64 len)`, little-endian) and
`b'F'` (flush only). Consumed by virtkit's `VmSession::drain_dirty` and `flush_disk`. Unix
hosts only: elsewhere the socket is ignored with a warning. The setter is Rust-only (no
`ffier` export).

`src/devices/src/virtio/block/device.rs` + `src/libkrun/src/api/device_builders.rs` —
`VmmExitObserver for Block` flushes a write-back cache on a clean power-off, and `BlockDevice`
registers it: the VMM `_exit`s, so without it imago's cached metadata could stay unwritten and
the image end truncated (an L2 entry past EOF).

`src/devices/src/virtio/block/{lazy_chunk_storage.rs (new),device.rs,mod.rs}` — read a cached
build-stage image lazily out of its compressed chunks. A `.vk_ro_img` manifest (written by
vk-driver's `registry.rs`, layout documented on the module) lists the content-addressed chunks
tiling an image and the local directory holding them; `LazyChunkStorage` is a read-only
`imago::Storage` that decompresses a chunk the first time a read touches it. Attached directly
as `DiskFormat::VkLazyChunks` (= 3), and resolved as a backing file at any depth of a qcow2
chain by `LazyAwareOpenGate`, which swaps in the lazy storage for an implicitly opened
`*.vk_ro_img` file. Keying on the host-chosen extension rather than the magic keeps a
guest-writable image from ever being promoted into a manifest naming a host directory.

A disk with neither option set, and no manifest in its chain, behaves as upstream's except for
the batched requests behind the `RwLock`, the mmap reads of a read-only raw image and the
flush of a write-back cache on power-off, which every disk gets. Covered by
`block::device::tests` (mmap, concurrency, backing chains), `block::device::dirty_tests` and
`block::lazy_chunk_storage::tests`.