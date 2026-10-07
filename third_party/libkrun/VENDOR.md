# Vendored libkrun 2.0 (development branch)

Source: https://github.com/libkrun/libkrun (formerly `containers/libkrun`)
Revision: `97a914ee06210fa2553b2ab75493bf6e8888910e` (`main`, version 2.0.0-dev), plus
upstream PR #875 (modern virtio-pci transport and the PCI host bridge in ACPI) at `cfb03d6`
(base `e66cad1`), its eight commits cherry-picked onto that revision.

vk-driver drives it through the 2.0 Rust API (`src/libkrun_sys.rs`). It replaced a
stable-1.19.x tree (`9a8fedc` with PR #728) whose patches are carried forward below, or listed
under "Not carried from the 1.19 tree". Only the Rust sources are vendored: `Cargo.toml`,
`Cargo.lock`, `LICENSE` and `src/`. It is its own cargo workspace, excluded from the root
virtkit workspace.

## Local patches

`src/libkrun/src/api/device_builders.rs` + `src/devices/src/virtio/net/` — add
`NetDevice::new_tap_fd` for an already attached tap. The backend owns a shared descriptor
through activation instead of reopening the device name, so vk can reject attachment
errors before boot and retain the queue across guest resets. The name-based API remains
available to other callers.

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
builds this tree (vk-driver links it). `struct statx` is fixed by the kernel UAPI, so the
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
a checkpoint's delta. With `BlockDevice::set_dirty_control_socket` bound, the worker records
every write, discard and write-zeroes in a per-disk `DirtyRanges` (64 KiB clusters), and
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

`src/devices/src/virtio/block/lazy_chunk_storage.rs` — a chunk is zstd-decoded no further
than one byte past the decompressed length its `.vk_ro_img` entry claims, then refused if it
does not come to exactly that length: a frame that inflates beyond it (the chunks come from a
registry anyone with push access fills) is no longer held whole in memory first. Forward-ported
from the 1.19 tree. Search for `take(u64::from(chunk.length) + 1)`.

`src/devices/src/virtio/block/{device.rs,worker.rs}` — a write-zeroes records the partial
clusters at its ends as written, not only its whole clusters as holes. The 1.19 tree recorded
it as a discard, which rounds inward, so the zeroed bytes of a partial head or tail cluster
reached neither set and a checkpoint kept that cluster's old contents. New in this tree.
Covered by `a_partial_cluster_write_zeroes_reads_its_edges_whole`.

`src/devices/src/virtio/block/device.rs` — a disk tracks dirty clusters only when it has a
dirty-control socket it could bind. The 1.19 tree recorded every write of every disk into
sets nothing but that socket drains, so a disk without one grew them for the life of the VM,
up to one entry per 64 KiB of distinct disk written. New in this tree.

`src/devices/src/virtio/block/worker.rs` — a read, write, discard or write-zeroes whose byte
range does not fit the disk answers IOERR before it reaches imago or the dirty tracker. The
1.19 tree multiplied the guest's sector unchecked, wrapping in release builds and panicking
the worker in debug ones, and recorded writes past the end as dirty. New in this tree.

`src/devices/src/virtio/block/device.rs` — the dirty-control socket is owner-only (0600) and
waits at most 5 s on a connection's command byte or reply, since connections are served one at
a time. The mode is set after the bind, so the caller still puts the socket in a private
directory. The 1.19 tree left it at the process umask and blocked on a stalled client. New in
this tree.

`src/devices/src/virtio/block/device.rs` — a `DiskFormat::VkLazyChunks` disk is read-only
whatever the caller asks: its manifest opens read-only and the guest sees `VIRTIO_BLK_F_RO`,
where the 1.19 tree offered a writable disk whose every write failed. New in this tree.

### virtio-net (forward-ported from the 1.19 tree)

`src/devices/src/virtio/net/{mod.rs,device.rs}` + `src/libkrun/src/api/device_builders.rs` — a
configurable link MTU. `VirtioNetConfig` gains the `mtu` field at offset 10; `Net::new` takes an
`Option<u16>` (`Net::set_mtu` sets it later) and advertises `VIRTIO_NET_F_MTU` only when one is
set. `NetDevice::set_mtu` validates it against `MIN_MTU..=MAX_MTU` (68..=65535, the ceiling
being what still fits `MAX_BUFFER_SIZE` once the virtio-net and ethernet headers are counted,
tied by a static assertion). Used by virtkit for switch NICs on a 65500-byte link.

`src/devices/src/virtio/net/{device.rs,worker/unix.rs}` + `src/devices/src/virtio/queue.rs` —
`VIRTIO_NET_F_MRG_RXBUF` on a NIC with an MTU, so one frame may span several descriptor chains:
without it the driver sizes every buffer for the largest frame (17-page chains at MTU 65500,
56 per 1024-descriptor ring). `write_frame_to_chains` takes whole chains until they hold the
frame before writing, so a frame without room yet is retried with the queue untouched; the
count goes in `num_buffers` of the first header. `Queue::add_used` is split into `write_used`
+ `publish_used` so a frame's chains reach the used ring before the index naming them moves,
and `enable_notification_at` arms a refill notification at an observed available index (it
keeps upstream's bus-master check).

`src/devices/src/virtio/net/{backend.rs,tap.rs,unixgram.rs,worker/unix.rs}` — the unix
`NetBackend` trait replaces `try_finish_write` with `flush_frames`: `write_frame` may batch
frames, and the worker flushes after draining the transmit queue and on a writable socket.
The Windows backend and worker remain upstream's; setting an MTU on Windows does not enable
mergeable receive buffers.

`src/devices/src/virtio/net/unixstream/{mod.rs,unix.rs}` — the unix network-proxy backend is
virtkit's rewrite (the Windows one stays upstream's). Reads go through a 128 KiB buffer so one
`recv` collects several queued frames; buffered bytes and the saved payload length survive
`NothingRead`; payloads of 8 KiB or more read straight into the caller's buffer when nothing is
buffered; EOF and oversized lengths fail the read. Writes are staged: `write_frame` copies the
length-prefixed frame and returns, `flush_frames` sends the batch (up to 256 KiB or 256
frames), a short send only advances the start of what is left, and frames of 16 KiB or more
skip staging when nothing is staged ahead of them.

Covered by `virtio::net::device::tests`, `virtio::net::worker::unix::tests` (their interrupt
checks now count through a test `InterruptHandler`, upstream having dropped the status word),
`virtio::queue::tests` and the socket-pair tests in `unixstream::unix`.

`src/devices/src/virtio/net/worker/unix.rs` — a TX chain holding no more than the virtio-net
header (short, or all write-only) is returned used without a frame. Upstream and the 1.19
tree handed it to the backend, whose `write_frame` asserts on it, so a guest could panic the
net worker. Covered by `a_header_only_transmit_chain_is_returned_without_a_frame`.

`src/devices/src/virtio/net/{device.rs,backend.rs,tap.rs,worker/{mod.rs,unix.rs}}` — virtio-net
resets on unix hosts. The worker thread stops on an eventfd of the device's and returns its
backend, which the device keeps for the next activation: opened once, because an `*Fd`
backend owns its descriptor (a second open would take a closed or reused number) and a
unixstream backend holds the rest of a frame it was sending or receiving. The next driver's
features go to the kept backend through `NetBackend::set_vnet_features`, which a tap answers
with `TUNSETOFFLOAD`. Windows' virtio-net driver resets its device as it starts and again when
another virtio function makes it start over (a virtio-rng); refused, it left the guest without
network. The Windows backend and worker remain upstream's and still refuse. Covered by
`a_reset_keeps_the_backend_for_the_next_activation`.

### virtio-vsock (forward-ported from the 1.19 tree)

`src/devices/src/virtio/vsock/unix_proxy/unix.rs` — `release` shuts down the host socket and
stops polling on an established connection's guest `OP_RST` or bidirectional `OP_SHUTDOWN`.
Removal stays deferred; otherwise the host peer reads EOF only when the reaper drops the
proxy 5 s later. Upstream already removes not-yet-connected proxies immediately. The 1.19
patch originally covered those connections (a readiness probe during boot). Unix hosts
only; Windows `release` remains upstream's.

`src/devices/src/virtio/vsock/{muxer.rs,mod.rs}` — `UnixProxy::new` failure (host `socket()`
under fd or memory exhaustion) resets the guest's connect instead of panicking the device
thread, poisoning the queue mutex and wedging the VM's whole vsock. The muxer RX queue grows
from 256 to 1024 slots; a full queue drops host->guest packets, including a connect's
`OP_RESPONSE`.

### Guest PMU (forward-ported from the 1.19 tree)

`src/cpuid/src/transformer/{mod.rs,intel.rs}` + `src/libkrun/src/vmm/{resources.rs,
linux/vstate.rs,builder.rs}` + `src/libkrun/src/api/vmm_builder.rs` — `VmmBuilder::pmu(true)`
keeps CPUID leaf 0xA as KVM reports it instead of zeroing it (`VmSpec::with_pmu_enabled`,
carried by `VcpuConfig::pmu_enabled`), so KVM's vPMU backs in-guest `perf` hardware events.
Off by default, as upstream: host counters widen the side-channel surface. Used by `vk run --pmu`.

With the switch off, the VM's vPMU is also turned off at VM level
(`KVM_CAP_PMU_CAPABILITY` / `KVM_PMU_CAP_DISABLE`, before any vCPU exists), and on AMD the AMD
transformer clears `PERFCTR_CORE` (0x80000001 ECX bit 23) and zeroes PerfMonV2 (0x80000022,
which 2.0 no longer hides by clamping the largest extended leaf), as Intel's leaf 0xA is: CPUID
alone hid the PMU only on Intel. A host KVM without the capability (Linux < 5.18, or its vPMU
off already) is left as it is. The SEV/TDX builds do not turn the vPMU off. Covered by
`test_update_perf_mon_entry` and `without_a_pmu_amd_hides_its_core_counters`.

### ACPI power-off, power button and reset (forward-ported from the 1.19 tree)

`src/arch/src/x86_64/{acpi.rs,layout.rs}` + `src/arch/Cargo.toml` — with ACPI enabled, the
tables describe fixed hardware instead of a HW-reduced platform. The FADT carries the PM1 event
and control blocks at `ACPI_PM_BASE` (0x600), the SCI on `SCI_GSI` (9), the reset register
(0x60C, value 1), `SLP_BUTTON` and `RESET_REG_SUP`, and points at a 64-byte-aligned FACS.
The DSDT defines `\_S5`; the MADT's interrupt source override sets the SCI to edge/high,
matching its irqfd. No SMI command port. The PM timer is added for UEFI firmware, and a GPE0
block for VM snapshots, declared only when the VM has a generation ID (both under "UEFI
firmware and Windows guests" below). arch's `zerocopy` enables `derive` for the override
structure, which `acpi_tables` lacks. Covered by `x86_64::acpi::tests`.

`src/devices/src/legacy/{acpi_pm.rs (new),mod.rs}` + `src/libkrun/src/vmm/{builder.rs,
device_manager/legacy.rs}` — the `AcpiPm` PIO device serves that block. An S5 write to PM1a_CNT
fires the Vmm exit event for power-off; writing the reset value to the reset register fires
it for reset. The host's shutdown eventfd latches PWRBTN_STS and raises the SCI (an irqfd on
GSI 9, reserved by the MMIO and PCI IRQ allocators) so the guest's fixed-feature power button
driver runs an orderly shutdown. `VmmBuilder::shutdown_support(true)` also creates that
eventfd on x86_64 Linux, and `VmmHandle::shutdown` writes it. Building with shutdown support
on x86_64 Linux requires `acpi(true)`; otherwise shutdown would do nothing.
Covered by `acpi_pm::tests`.

The fixed-hardware FADT is built on every x86_64 host, but `AcpiPm` and the SCI irqfd exist on
Linux only: a Windows (WHP) guest with ACPI on is told about a PM1 block, SCI and reset
register nothing serves, so its S5 power-off goes nowhere. virtkit only boots Linux hosts.
2.0's other table choices stay: no `IAPC_VGA_NOT_PRESENT`, MADT `PCAT_COMPAT` clear, and no
Local APIC NMI entry. `0xcf9` (PCI reset control) is not served, as in the 1.19 tree.

`src/libkrun/src/vmm/{mod.rs,linux/vstate.rs}` + `src/devices/src/legacy/i8042.rs` — a guest
reset (triple fault, `KVM_SYSTEM_EVENT_RESET`, the i8042 `0xFE` command or the ACPI reset
register) exits with `KRUN_EXIT_GUEST_RESET` (154) instead of 0, so a supervisor can tell a reboot
from a power-off and relaunch the VM; a shared `reset_flag` carries the distinction for the
device-driven paths. `linux/vstate.rs` is shared, so aarch64 Linux's triple fault and PSCI
`SYSTEM_RESET` exit 154 too. A reset outranks a guest-set exit code, and a guest kernel panic
under `reboot=k panic=-1` is a reset: a supervisor that relaunches on 154 relaunches a panicking
guest. `src/libkrun/src/api/mod.rs` re-exports `KRUN_EXIT_GUEST_RESET` for a supervisor to
match on.

### virtio-pci parity with the 1.19 tree (on top of PR #875)

`src/devices/src/virtio/{msix.rs (new),mod.rs,pci.rs}` + `src/devices/src/legacy/{gsi.rs (new),
mod.rs}` + `src/libkrun/src/vmm/device_manager/kvm/pci.rs` — MSI-X for the PR #875 transport,
which only had INTx. An MSI-X capability closes the capability list, with a two-vector table at
BAR0 0x4000 and its PBA at 0x5000 (device config is now bounded to 0x1000 bytes). The common
config keeps the vectors the driver picks, an unknown one reading back as NO_VECTOR; once MSI-X
is enabled an interrupt goes to the driver's vectors (a queue event to every distinct vector a
queue is mapped to, the device not naming the queue) and never to INTx; enabling MSI-X
deasserts an INTx left pending, and a device reset drops pending PBA bits. Only naturally
aligned 4- and 8-byte table and PBA accesses reach the MSI-X state; others read all ones.
`MsixConfig` and `GsiRoutes` are the 1.19 tree's: each vector has an eventfd registered as a
KVM irqfd on its own MSI GSI above the IOAPIC pins, and a message write re-commits the full
`KVM_SET_GSI_ROUTING` table (default IOAPIC/PIC routes plus the MSI ones). Each queue's
notification register gets an ioeventfd on the queue eventfd, so a kick no longer traps to the
VMM thread; when the guest relocates BAR0 the transport tells the VMM (`on_bar0_moved`), which
moves the ioeventfds with it, so none is left to swallow writes at the old address. They stay
armed while the guest turns memory decoding off (the trapping path then answers nothing).

`src/arch/src/x86_64/{layout.rs,mod.rs,acpi.rs}` + `src/libkrun/src/vmm/{device_manager/shm.rs,
builder.rs}` + `src/devices/src/virtio/pci.rs` — shared-memory regions (virtio-fs DAX windows)
over virtio-pci. Regions are carved from a fixed span (`SHM_MEM_START`, 64 GiB at 64 GiB) that
the DSDT declares as a 64-bit window of the PCI host bridge, each with a power-of-two size of at
least 2 MiB and a base aligned to it, so a BAR describes it exactly. A guest whose RAM reaches
the span fails to boot (`ShmCreate(OutOfSpace)`) if it asks for a window on virtio-pci;
vk-driver keeps that from happening: it gives a guest with more than `DAX_MAX_GUEST_MIB` of RAM
no windows, and drops windows past `DAX_TOTAL_MAX`. The transport pins BAR2/BAR3 (64-bit,
prefetchable memory) on the region, answering size probes, and describes it with a
`VIRTIO_PCI_CAP_SHARED_MEMORY_CFG` capability (`virtio_pci_cap64`, region id 0); only virtio-fs
may carry a region. The builder's refusal of shared memory over PCI now applies to the GPU
region only.

The fixed span is for virtio-pci only: on virtio-mmio, regions keep upstream's page-aligned
placement above the guest's RAM, unbounded, and the GPU region (MMIO-only) with them. The DSDT
declares the span only for a guest whose RAM stays below it. Covered by the `shm::tests` and
`the_shm_window_is_declared_only_when_the_guest_has_one`.

`src/libkrun/src/vmm/device_manager/kvm/pci.rs` + `src/devices/src/virtio/pci.rs` — devices
past the INTx GSIs (5–23 less the SCI's 9) get interrupt pin 0, line 0xff and no `_PRT` entry
and interrupt over MSI-X alone, so bus 0's 31 slots are the limit.

Covered by the `virtio::pci::tests` (`msix_*`, `with_msix_enabled_*`, `without_msix_*`,
`queue_notify_ioevents_*`, `a_shared_memory_region_*`, `a_device_without_intx_*`), the
`virtio::msix` and `legacy::gsi` tests.

### Interrupt trigger mode

`src/arch/src/x86_64/acpi.rs` — the DSDT declares virtio-mmio interrupts edge-triggered.
Each one is a one-shot KVM irqfd pulse with no resample fd; declared level (upstream), the
IOAPIC drops a pulse that arrives while the previous one awaits its EOI, and a busy guest then
waits forever on I/O that already completed. Covered by
`virtio_mmio_interrupts_are_edge_triggered`.

`src/devices/src/virtio/{pci.rs,device.rs}` — a reset the device cannot perform (vsock and
balloon implement none, nor net on a Windows host) reads back as done. Linux's virtio-pci driver
polls the status until it reads 0 after writing 0 (`vp_modern_set_status`), which recent kernels
do to every device at reboot and power-off, so the guest hung there and never reached its ACPI
reset or S5. The transport drops its own state as for a reset, but the device stays failed
underneath, its workers running, and the status reads 0 from then on (hiding FAILED): a later
re-initialization gets no further than its first write and gives up (Linux at FEATURES_OK)
rather than activating it twice. vk relaunches the VM on a reset, so nothing reuses the rings. A
FAILED the driver wrote itself is now cleared by a reset, as the spec has it, instead of making
a resettable device look like one that cannot reset. Covered by
`a_reset_the_device_cannot_do_still_reads_back_as_done` and
`a_driver_written_failed_is_cleared_by_a_reset`.

### Not carried from the 1.19 tree

- Initrd placement below 4 GiB: upstream in 2.0.
- `IRQ_MAX` 23: upstream. The MP table's routing of all 24 IOAPIC pins is not carried: the MP
  table only matters with `acpi=off`, which vk never sets.
- The early 16550 COM1 console in `builder.rs`: superseded by `VmmBuilder::add_serial_console`.
- The legacy PCI host bridge, virtio-pci INTx transport and per-slot allocation: PR #875.
- `krun_disable_balloon`: 2.0 attaches no implicit balloon; vk adds one when it wants it.
- The `krun_*` C entry points (`krun_add_virtiofs*`, `krun_set_pmu`, `krun_set_block_dirty_socket`,
  …): replaced by the Rust builder setters above.
- The VM name for the 15-byte `comm` (`krun_start_enter` reading `VIRTKIT_VM_NAME`): vk-driver
  sets it itself.

### Building off Linux x86_64

`src/devices/src/virtio/{mod.rs,device.rs}` — the virtio-pci transport builds on Linux x86_64
only, where the VMM attaches it: it depends on the KVM-only MSI-X state and GSI routing, and the
macOS build stopped compiling once they came in. Its bus-master gate is gated with it.

### Tests on current KVM

`src/arch/src/x86_64/linux/regs.rs` — `test_setup_sregs` gives its vCPU KVM's supported CPUID
before setting long-mode sregs: KVM refuses `EFER.LME` (`EINVAL`) on a vCPU whose CPUID lacks
long mode, as a fresh vCPU's does, so the test failed where the VMM itself works.

### UEFI firmware and Windows guests

`src/devices/src/legacy/acpi_pm.rs` + `src/arch/src/x86_64/acpi.rs` — the ACPI PM timer: a
free-running 32-bit counter at 3.579545 MHz at `ACPI_PM_BASE + 8` (0x608), declared in the FADT
(`PM_TMR_BLK`, `X_PM_TMR_BLK`, `TMR_VAL_EXT`). UEFI firmware's delays poll it (edk2's
`AcpiTimerLib`), and Windows calibrates against it. Covered by
`the_pm_timer_counts_at_3_58_mhz` and the FADT test.

`src/devices/src/pci.rs` + `src/libkrun/src/vmm/device_manager/kvm/pci.rs` — a host bridge at
00:00.0 (`PciHostBridge`, 8086:0d57, class 06/00/00, cloud-hypervisor's IDs). OVMF's CloudHv
platform library identifies the platform by that function's device ID and stops in a dead
loop on any other, or none; with it, `CLOUDHV.fd` (cloud-hypervisor's edk2 build, booted as a
PVH ELF) reaches its boot manager. Covered by
`the_host_bridge_identifies_itself_and_ignores_config_writes`.

`src/arch/src/x86_64/{layout.rs,acpi.rs}` + `src/libkrun/src/vmm/{builder.rs,
device_manager/kvm/pci.rs}` — the 32-bit hole starts at 3 GiB (1 GiB, as cloud-hypervisor lays
it out) instead of 3.25 GiB. CloudHv firmware reassigns PCI BARs from 3 GiB up, where
they landed on guest RAM (which reached 3.25 GiB) or, past it, on addresses nothing routed. The
range 3 GiB–3.25 GiB is now a second BAR window (`PCI_MMIO32_LOW_*`), declared in the host
bridge's `_CRS`, and virtio-mmio devices start above it (`MMIO_DEVICES_START`). Covered by
`the_host_bridge_declares_the_low_bar_window`.

`src/devices/src/legacy/x86_64/cmos.rs` — an MC146818 RTC on every host; upstream emulated it
only on Windows hosts and served plain NVRAM elsewhere. Time fields read the host clock plus a
guest-set offset. Register B selects BCD or binary and 12- or 24-hour mode; its SET bit holds
the clock during field writes. Register A shows an update in progress in each second's last
244 µs, C reads 0 and D reads valid-RAM-and-time. edk2's `PcRtc` reported "Device Error" against
plain NVRAM and stopped the boot; Windows also reads and sets the clock through it. Memory-size
bytes remain read-only. Covered by the tests in that file.

`src/devices/src/virtio/pci.rs` — enabling a queue copies its size from `queue_size`, which
resets to the maximum. edk2 leaves that register unchanged; the queue itself started at size 0,
so requests remained pending, none could be popped and the block worker spun. Linux always
writes the size, hiding the fault. Covered by
`a_queue_enabled_without_a_size_write_keeps_the_maximum_size`.

`src/arch/src/x86_64/acpi.rs` — the XSDT lists the FACS as well as the FADT pointing at it. edk2's
CloudHv platform rebuilds the tables from the XSDT entries (plus the FADT's DSDT); a FACS it never
saw makes its table driver zero the FADT's `FIRMWARE_CTRL`, and Windows stops on
`ACPI_BIOS_ERROR (0x11, 3)`. Linux logs the FACS twice and is otherwise unaffected. Covered by
`setup_acpi_places_an_aligned_facs` and `setup_acpi_adds_mcfg_to_xsdt`.

`src/devices/src/virtio/console/device.rs` — reopening a running port is a no-op. Its queues
move into its I/O threads on first open and keep running after a guest close. A second open
found no queues and panicked the VMM ("port rx queue should exist"); Windows' qemu-ga closes
and reopens its port. Covered by `a_port_the_guest_closes_and_reopens_keeps_running`.

`src/arch/src/x86_64/acpi.rs` — the DSDT declares COM1 and COM2 only. COM3 and COM4 are still
emulated (as sinks) but share COM1's and COM2's ISA IRQs, and Windows marks every port of a
shared pair as conflicting (code 12), COM1 — the EMS console — included. QEMU declares the same
two. Covered by `dsdt_declares_only_com1_and_com2`.

`src/devices/src/virtio/pci.rs` — every virtio function has QEMU's subsystem IDs, `1AF4:1100`,
instead of `1AF4:0040 + type`. virtio-win's INFs list `SUBSYS_11001AF4` hardware IDs; Windows
binds its drivers through the generic ID anyway, but Windows Setup only installs onto a disk
whose controller matches an exact hardware ID of the driver it was given, and refused a
virtio-blk disk ("Windows needs the driver for device Red Hat VirtIO SCSI controller").
Linux takes a modern device's type from its device ID and ignores the subsystem. Covered by
`advertises_modern_virtio_identity_and_capabilities`.

`src/arch/src/x86_64/linux/hyperv.rs` + `src/libkrun/src/{api/vmm_builder.rs,vmm/resources.rs,
vmm/linux/vstate.rs}` — `VmmBuilder::hyperv(true)` presents KVM's Hyper-V enlightenments: the
leaves `KVM_GET_SUPPORTED_HV_CPUID` recommends take 0x40000000 and KVM's own leaves move to
0x40000100, the SynIC is enabled per vCPU (`KVM_CAP_HYPERV_SYNIC2`; without it the synthetic
timers are hidden), and the guest crash MSRs, the extended hypercalls and the synthetic debugger
(leaves 0x40000080–0x40000082 and its feature bit, as QEMU without `hv-syndbg`) stay hidden. A
KVM built without Hyper-V emulation (`CONFIG_KVM_HYPERV` off, an option since Linux 6.8) fails
`KVM_GET_SUPPORTED_HV_CPUID`: the guest then keeps the plain KVM CPUID, with a warning. The vCPU
loop accepts `KVM_EXIT_HYPERV`: a SynIC exit needs nothing without VMBus, a hypercall left to
userspace gets `HV_STATUS_INVALID_HYPERCALL_CODE`. `KVM_CAP_HYPERV_ENFORCE_CPUID` stays off, so
the hidden features remain reachable to a guest that ignores CPUID; Windows follows CPUID, and
every `KVM_EXIT_HYPERV` is answered. Windows then enables its SynIC on every vCPU and takes the
reference TSC page, synthetic timers and the TLB-flush/IPI hypercalls. Covered by the merge tests
in `hyperv.rs` and, against the host's KVM, `test_configure_vcpu_with_hyperv` in `vstate.rs`.

`src/arch/src/x86_64/{acpi.rs,layout.rs,mod.rs}` + `src/devices/src/legacy/x86_64/pvpanic.rs` +
`src/libkrun/src/{api/vmm_builder.rs,vmm/*}` — the ACPI devices a Windows guest expects:
- pvpanic, for every x86_64 guest with ACPI: QEMU's ISA device at port 0x505 (`QEMU0001` in the
  DSDT); a guest's write of PANICKED / CRASH_LOADED is logged. virtio-win's driver binds it
  ("QEMU PVPanic Device").
- `VmmBuilder::vm_generation_id`: Microsoft's VM generation ID, the 16 bytes at
  `VMGENID_ADDR` (the last page of the reserved window below 1 MiB, past the tables) behind a
  `VGEN` device (`QEMUVGID`, `_CID "VM_Gen_Counter"`, `ADDR`); Windows binds its "Hyper-V
  Generation Counter". The caller keeps the ID across boots of one disk.
- The Windows platform (`setup_acpi`'s `windows_platform`, set with the Hyper-V
  enlightenments) shapes the DSDT for Windows:
  - processor objects (`ACPI0007`, `_UID` = MADT id), which Windows binds its processor driver
    to. Not for others: a Linux kernel without cpufreq warns about each.
  - no PS/2 keyboard (`KBD0`, PNP0303). Windows' i8042prt resets the keyboard and our i8042
    answers with an ACK but no self-test result, so every boot waited out a timeout of about
    ten seconds. A headless Windows has no use for the keyboard and resets through the FADT
    reset register. qemu-ga now answers 15.5 s after `vk run` on average over 50 boots,
    instead of 22 s.

Covered by the DSDT and `setup_acpi` tests in `acpi.rs` and the pvpanic test.

`src/libkrun/src/{api/vmm_builder.rs,vmm/builder.rs,vmm/mod.rs,vmm/linux/vstate.rs}` —
`VmmHandle::pause`/`resume` on Linux/KVM, which upstream implements on macOS only (Linux
returned `FeatureDisabled`). The same `VmCtl` channel reaches the event loop, which sends
`Pause`/`Resume` to every vCPU and waits for each to answer: the vCPU's kick signal sets
`immediate_exit`, so `KVM_RUN` completes a pending I/O and returns, and the thread parks.
`VmCtl::Pause`/`Resume` carry a reply channel, so `pause`/`resume` return the outcome rather
than once the request is queued (macOS too). If a vCPU fails to answer, those that did are
switched back, so the VM stays as it was; a vCPU that exits meanwhile leaves its code for the
`exit_evt` handler. A paused vCPU now answers a second `Pause` instead of leaving it
unanswered. The guest's clock is the TSC, which runs on, so a Windows guest's time is right on
resume. The `KVM_KVMCLOCK_CTRL` TODO in `Vcpu::running` matters only to a Linux guest's
kvmclock (its soft-lockup watchdog), and virtkit pauses only UEFI guests. Covered by
`test_vcpu_pause_resume` in `vstate.rs` and `pause_and_resume_return_the_event_loops_answer`
in `vmm_builder.rs`.

`src/arch/src/x86_64/linux/{hyperv.rs,msr.rs}` + `src/libkrun/{Cargo.toml,src/vmm/mod.rs,
src/vmm/linux/vstate.rs}` — the CPU half of a snapshot, behind a `snapshot` feature (serde,
and kvm-bindings' `serde`). `Vmm::save_cpu_state` / `restore_cpu_state` take and put back, on
a paused VM, every vCPU's state and the VM's in-kernel state (PIT, PIC, IOAPIC, kvmclock) as
a serializable `CpuState`, through the vCPU threads (`VcpuEvent::SaveState` /
`RestoreState`; a running vCPU refuses), with the drain of stale answers and the `Exited`
handling of pause and resume (`exchange_vcpus`, which also reports a vCPU's
`VcpuResponse::Error`). It uses the save/restore code inherited from Firecracker, which
nothing called, with these changes: the MSRs it keeps add the Hyper-V ones (`SNAPSHOT_MSRS`,
restored after the others and in their order: guest OS ID before the hypercall page, SynIC
control before its pages, timer configurations before counts) and a few a modern guest sets
(XSS, ARCH_CAPABILITIES, TSX_CTRL, UMWAIT_CONTROL, KVM poll control); an MSR this KVM refuses
is skipped at save rather than tripping an assert, and one refused at restore is an error that
names it. The saved kvmclock drops `KVM_CLOCK_REALTIME` and `KVM_CLOCK_HOST_TSC` as well as
`TSC_STABLE` (which `KVM_SET_CLOCK` refuses): with REALTIME, which Linux 5.16+ reports, the
restore would move the clock on by the host time since the snapshot, so the guest's clock
resumes where the snapshot froze it, whatever the host kernel; the caller sets the guest's
time after a restore. Covered by tests that move a vCPU's state into a fresh vCPU through JSON,
plain and with Hyper-V (skipped where KVM has no Hyper-V, as in a nested dev VM), one that
restores the VM state, and one of `exchange_vcpus`'s error path.

`src/devices/{Cargo.toml,src/virtio/{device.rs,pci.rs,console/device.rs}}` — the virtio half of
a snapshot. `VirtioPciTransport::save_state` keeps the device type and what the driver wrote
(BAR0, command, MSI-X table and control, status, acked features, configuration vector, each
queue's size, vector and ring addresses; the transport now keeps the queues' setup when
activation hands them to the device) plus the device's own words (`VirtioDevice::save_state`,
empty by default). `restore_state` refuses another device type or queue count, writes it all
again in a fresh transport through the same register handlers, in a driver's order, so every
side effect (BAR routing, MSI-X routes, activation) happens as it did, and fails unless the
transport then saves the state it was given. Each queue resumes at the index its used ring
holds in the restored memory, so a request taken but not finished is taken again (idempotent
for a disk, a duplicate frame for a NIC), and every ready queue is kicked and the guest
interrupted once. The console's state is the ports the guest started, which a restore starts
again (the start loop moved into `Console::start_ports`). Serializable behind a `snapshot`
feature. Covered by a round trip through a fresh transport and the refusals in `pci.rs`.

`src/arch/src/x86_64/{acpi.rs,layout.rs}` + `src/devices/src/legacy/{acpi_pm.rs,i8042.rs,
mod.rs,x86_64/{cmos.rs,serial.rs}}` + `src/libkrun/{Cargo.toml,src/api/vmm_builder.rs,
src/vmm/{builder.rs,mod.rs,resources.rs,snapshot.rs,device_manager/kvm/pci.rs}}` +
`src/devices/src/virtio/pci.rs` — VM snapshots. `VmmHandle::snapshot(dir)` (a
`VmCtl::Snapshot` with a reply channel, as `pause`) pauses the VM and writes into `dir`
(created 0700, its files 0600) `state.json` — the CPU state, the legacy devices' (CMOS NVRAM,
clock offset and a time being set, the UARTs', i8042's and ACPI PM's registers, the PM
timer's count), every virtio-pci transport's in registration order (the PCI host manager now
keeps them typed) — and a memory image, the RAM regions in a sparse file whose zero pages are
holes. The VM stays paused; `VmmHandle::quit` (`VmCtl::Quit`) ends it as a power-off does,
devices flushing on the way out. The commit is atomic: the image is written under a new name
(`memory-<nonce>`) and synced, then `state.json.tmp`, which names it, is synced and renamed
over `state.json`, the directory synced, and only then the previous image removed; a snapshot
that fails at any point leaves the previous one whole. `state.json` also records the
kvm-bindings release (whose serialized structs the CPU state is) and the host CPU (CPUID
vendor, family/model/stepping and feature leaves), and a restore refuses a snapshot of
another version, kvm-bindings or CPU model: a snapshot restores on the same host model only.
`VmmBuilder::restore_from(dir)` builds the VM as usual, then, with its vCPUs started paused,
loads the memory (reading data extents, clearing what the build itself wrote where the image
has holes), restores the legacy devices (refusing another serial port count) and the
transports, then the CPU state, and only then kicks the virtio queues and interrupts the guest
(`kick_restored`, split from `restore_state` so no interrupt is raised before the interrupt
controllers are back); a failed restore is `StartMicrovmError::Restore`. The VM must be built
as the snapshotted one was. A restore reads the image in rather than mapping it privately
over the RAM: Windows touches its working set at once, and faulting it in lazily made it
slower to its first commands.

The VM generation ID changes on a restore, as Microsoft's spec requires of a VM brought back
to an earlier point (an Active Directory domain controller relies on it against USN
rollback): the restored RAM holds the snapshot's ID, which the restore overwrites with the one
the VM is configured with, and a restore refuses a snapshot whose guest has an ID unless it
is given one (and one without unless not). It then notifies the guest as QEMU's vmgenid
does: the `AcpiPm` device gains a GPE0 block at `ACPI_PM_BASE + 0x10` (GPE0_STS, then
GPE0_EN, 2 bytes each, byte-addressable, status write-1-to-clear), declared in the FADT
(`GPE0_BLK`, `GPE0_BLK_LEN` 4, `X_GPE0_BLK`) and the DSDT
(`Scope (\_GPE) { Method (_E05) { Notify (\_SB.VGEN, 0x80) } }`, GPE 5 as QEMU) only when
the VM has a generation ID; after resuming, the restore latches GPE 5 and raises the SCI if
the guest enabled it, as the power button does. Covered by byte-level tests of the FADT
fields and the AML in `acpi.rs`, of the GPE registers in `acpi_pm.rs`, round trips of the
serial port, i8042 and ACPI PM state, and tests of the memory image, the atomic commit and
the refusals in `snapshot.rs`.

`src/devices/src/virtio/{mod.rs,block/worker.rs,net/worker/unix.rs,console/{process_rx.rs,
process_tx.rs}}` + `src/libkrun/src/vmm/mod.rs` — a snapshot quiesces the devices: one
process-wide gate (`device_writes` / `quiesce_devices`) that the virtio-blk worker holds
around a queue pass, the virtio-net worker around each wakeup's events and the console ports
around writing input and publishing completions, and that a snapshot takes exclusively before
it reads the devices' state and the guest's memory, so no batch or frame lands halfway
through the dump. A snapshot waits up to 10 s for it, then fails rather than stall. virtio-rng
and virtio-balloon run on the VMM's event loop, which the snapshot itself occupies. A snapshot
refuses a VM with any other virtio device (vsock, virtio-fs, GPU, input, vhost-user: their
threads write guest memory ungated) or with virtio-mmio devices, which it does not save.
Checked by snapshotting a Windows guest while it downloads and writes files: after the
restore every file matches its logged hash and the guest carries on.

`src/arch/{Cargo.toml,src/x86_64/{mod.rs,layout.rs,acpi.rs}}` + `src/smbios/src/{lib.rs,table.rs}` +
`src/libkrun/src/{api/vmm_builder.rs,vmm/{builder,mod,resources}.rs}` — the Windows platform
gets SMBIOS 3.0 tables (BIOS and system information, OEM strings, from the `smbios` crate the
aarch64 side already uses) at `SMBIOS_START` (0xF0000), where edk2's CloudHv firmware's
SmbiosPlatformDxe looks for them, as cloud-hypervisor writes them; the ACPI tables now end below
that address. Windows reports a vendor and model (`Libkrun`, `libkrun Virtual Machine`) and
`SMBIOSPresent` instead of finding no SMBIOS at all; `VmmBuilder::add_smbios_oem_string` reaches
it too. `krun-smbios` becomes an unconditional dependency of `krun-arch` (it was non-Windows
only), and `smbios::Error` derives `PartialEq` for the arch error type.
`VmmBuilder::system_uuid` gives the system information a UUID (RFC 4122 byte order in, SMBIOS's
little-endian first three fields out: `smbios::setup_smbios_with_uuid`,
`SystemInfo::with_uuid`), nil otherwise; Windows reports it as
`Win32_ComputerSystemProduct.UUID`. Covered by a configuration test.

`src/devices/src/legacy/x86_64/flash.rs` + `src/libkrun/src/vmm/{builder.rs,resources.rs,
snapshot.rs}` + `src/libkrun/src/api/vmm_builder.rs` + `src/arch/src/x86_64/layout.rs` — a UEFI
variable store flash: `VmmBuilder::uefi_vars(path)` maps a CFI flash device over the file at
`UEFI_VARS_FLASH_START` (0xFFC00000, below the TSS KVM keeps under 4 GiB), where vk's CloudHv
firmware build looks for its variable store. The device implements the part of Intel's command
set edk2's QEMU flash driver uses (byte program, block erase, read/clear status, read array) and
answers its probe as a writable flash; programs and erases go straight to the file, synced when
the firmware ends them with the read array command, so the firmware's UEFI variables persist
across boots. Every access traps: the variable driver reads the store once and works from its
cache. A snapshot keeps the device's mode and status in its `state.json`, and a restore refuses a
VM that has no flash where the snapshot had one, or the reverse; its contents are the file's,
which the embedder keeps with the snapshot like the disks. Covered by tests replaying edk2's
probe and its program and erase sequences.

`src/devices/src/legacy/x86_64/{uefi_vars.rs,fw_cfg.rs}` + `src/devices/Cargo.toml` +
`src/arch/src/x86_64/layout.rs` + `src/libkrun/{Cargo.toml,src/vmm/{builder.rs,snapshot.rs}}` —
the UEFI variables on the host (`uefi-vars` feature), in place of the flash above for a machine
that boots: virtkit's `vk-uefi-vars` (a path dependency on the crate in virtkit's workspace, as
`vk-tpm` is; a change to its dependencies needs `cargo update -p vk-uefi-vars` here) keeps the
variables in the same store file and checks authenticated writes, and the firmware's variable
driver is edk2's client of such a service (VirtMmCommunicationDxe, as for QEMU's
`uefi-vars-x64`). The device serves edk2's `QemuUefiVars.h` register interface at
`UEFI_VARS_START` (0xFED50000, a page): magic, reset, and DMA transfers of the firmware's 64 KiB
MM communication buffer, answered in place before the command's status reads back; a command
that changed a non-volatile variable has the store file replaced (written whole, synced,
renamed over it) first. The firmware finds the device through QEMU's fw_cfg, here its
traditional I/O ports only (selector 0x510, data 0x511, no DMA) with one file,
`etc/hardware-info` (a HardwareInfoTypeQemuUefiVars entry giving the address). A snapshot keeps
the service's phase, volatile variables, policies and locks (`UefiVarsState`), its
non-volatile variables being the file's; a snapshot taken with the flash has none, and restores
with the flash, whose firmware its memory holds. Covered by vk-uefi-vars' tests and a fw_cfg
directory test.

`src/devices/src/legacy/x86_64/tpm.rs` + `src/devices/Cargo.toml` + `src/arch/src/x86_64/{acpi.rs,
layout.rs,mod.rs}` + `src/libkrun/src/vmm/{builder.rs,resources.rs,snapshot.rs,mod.rs}` +
`src/libkrun/src/api/vmm_builder.rs` — a TPM 2.0 (`tpm` feature): virtkit's `vk-tpm` engine (a
path dependency on the crate in virtkit's workspace, `../../vk-tpm` from this directory: one copy
of the engine for both workspaces, and no C or OpenSSL; this workspace's `Cargo.lock` locks its
dependencies too, so a change to them needs `cargo update -p vk-tpm` here), behind the TCG CRB
interface at `TPM_CRB_START` (0xFED40000), as QEMU presents swtpm, so the host needs no swtpm.
`VmmBuilder::tpm_state(path)` attaches it, with its permanent state in `path` (written after
every command that changes it and before the guest sees the response, owner-only, through a
synced rename; only a missing file is a new TPM, manufactured on first use with its RSA 2048 and
P-256 endorsement keys persistent at 0x81010001 and 0x81010002, without certificates; one that
cannot be read, is empty, or is not a `vk-tpm` state fails the TPM rather than replace it, and a
libtpms state, from the engine this device ran before, is named as such: there is no
migration). A TPM whose state cannot be written answers TPM_RC_FAILURE from then on. The ACPI tables declare it: an MSFT0101 device in the DSDT and a TPM2
table (revision 4, start method 7, no log area: the firmware gives Windows its event log through
the EFI TCG2 protocol). Commands run on the vCPU that starts them, and only once the driver holds
locality 0 and has made the interface ready, as on QEMU. A snapshot keeps the CRB registers and
buffer and the TPM's permanent and volatile state, so it is whole without the file; a restore
starts the TPM on them, writing the permanent state to `path` for the machine's next start. A
restore refuses a VM without the TPM the snapshot has (a build without the feature included), or
with one it has not. Covered by tests driving the CRB registers through TPM2_Startup,
TPM2_GetRandom, PCR extend and read, and a secret sealed, loaded and unsealed, through a snapshot
round trip and a power cycle; by tests of the state file (a foreign or unwritable one); and by ACPI
tests. The TPM device has a `_DSM` modelled on QEMU's, which Windows' TPM driver evaluates and
otherwise fails on (event 15, STATUS_OBJECT_NAME_NOT_FOUND, `Get-Tpm` then errors): TCG Physical
Presence 1.3 with nothing pending and the requests that would queue an operation not
implemented, and the memory clear interface, accepted as a no-op (a guest reboot relaunches the
VMM, with zeroed RAM). Windows Server 2025 then reports the TPM present, ready and owned.
