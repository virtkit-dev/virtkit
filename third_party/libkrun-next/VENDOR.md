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
reached neither set and a checkpoint kept that cluster's old contents. Not yet in the 1.19
tree. Covered by `a_partial_cluster_write_zeroes_reads_its_edges_whole`.

`src/devices/src/virtio/block/device.rs` — a disk tracks dirty clusters only when it has a
dirty-control socket it could bind. The 1.19 tree recorded every write of every disk into
sets nothing but that socket drains, so a disk without one grew them for the life of the VM,
up to one entry per 64 KiB of distinct disk written. Not yet in the 1.19 tree.

`src/devices/src/virtio/block/worker.rs` — a read, write, discard or write-zeroes whose byte
range does not fit the disk answers IOERR before it reaches imago or the dirty tracker. The
1.19 tree multiplied the guest's sector unchecked, wrapping in release builds and panicking
the worker in debug ones, and recorded writes past the end as dirty. Not yet in the 1.19
tree.

`src/devices/src/virtio/block/device.rs` — the dirty-control socket is owner-only (0600) and
waits at most 5 s on a connection's command byte or reply, since connections are served one
at a time. The mode is set after the bind, so the caller still puts the socket in a private
directory. The 1.19 tree left it at the process umask and blocked on a stalled client. Not
yet in the 1.19 tree.

`src/devices/src/virtio/block/device.rs` — a `DiskFormat::VkLazyChunks` disk is read-only
whatever the caller asks: its manifest opens read-only and the guest sees `VIRTIO_BLK_F_RO`,
where the 1.19 tree offered a writable disk whose every write failed. Not yet in the 1.19
tree.

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
Off by default, as upstream: host counters widen the side-channel surface. For `vk run --pmu`
once vk-driver moves onto this tree.

Known gap, as in the 1.19 tree: the switch only gates Intel's leaf 0xA. On AMD, KVM's vPMU
(the legacy counters, `PERFCTR_CORE` in 0x80000001 ECX) stays exposed whatever the flag, and
2.0 no longer clamps the largest extended leaf to 0x8000001f, so PerfMonV2 (0x80000022) is
visible too. Turning the vPMU off at VM level (`KVM_CAP_PMU_CAPABILITY`) would close it on
both vendors.

### ACPI power-off, power button and reset (forward-ported from the 1.19 tree)

`src/arch/src/x86_64/{acpi.rs,layout.rs}` + `src/arch/Cargo.toml` — with ACPI enabled, the
tables describe fixed hardware instead of a HW-reduced platform. The FADT carries the PM1 event
and control blocks at `ACPI_PM_BASE` (0x600), the SCI on `SCI_GSI` (9), the reset register
(0x60C, value 1), `SLP_BUTTON` and `RESET_REG_SUP`, and points at a 64-byte-aligned FACS.
The DSDT defines `\_S5`; the MADT's interrupt source override sets the SCI to edge/high,
matching its irqfd. No PM timer, GPE block or SMI command port. arch's `zerocopy` enables
`derive` for the override structure, which `acpi_tables` lacks. Covered by `x86_64::acpi::tests`.

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
VMM thread; the trapping path stays for a relocated BAR0, whose ioeventfds are not moved.

`src/arch/src/x86_64/{layout.rs,mod.rs,acpi.rs}` + `src/libkrun/src/vmm/{device_manager/shm.rs,
builder.rs}` + `src/devices/src/virtio/pci.rs` — shared-memory regions (virtio-fs DAX windows)
over virtio-pci. Regions are carved from a fixed span (`SHM_MEM_START`, 64 GiB at 64 GiB) that
the DSDT declares as a 64-bit window of the PCI host bridge, each with a power-of-two size of at
least 2 MiB and a base aligned to it, so a BAR describes it exactly. A guest whose RAM reaches
the span, on either transport, fails to boot (`ShmCreate(OutOfSpace)`) if it asks for a window;
vk-driver drops windows past `DAX_MAX_GUEST_MIB` first. The transport pins BAR2/BAR3 (64-bit,
prefetchable memory) on the region, answering size probes, and describes it with a
`VIRTIO_PCI_CAP_SHARED_MEMORY_CFG` capability (`virtio_pci_cap64`, region id 0); only virtio-fs
may carry a region. The builder's refusal of shared memory over PCI now applies to the GPU
region only.

Known gaps: the DSDT declares the span even for a guest whose RAM overlaps it, and the
virtio-mmio path also places regions in the span and rounds them to a power of two.

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

`src/devices/src/virtio/{pci.rs,device.rs}` — a reset the device cannot perform (net, vsock and
balloon implement none) reads back as done. Linux's virtio-pci driver polls the status until it
reads 0 after writing 0 (`vp_modern_set_status`), which recent kernels do to every device at
reboot and power-off, so the guest hung there and never reached its ACPI reset or S5. The
transport drops its own state as for a reset, but the device stays failed underneath, its
workers running, and the status reads 0 from then on (hiding FAILED): a later
re-initialization gets no further than its first write and gives up (Linux at FEATURES_OK)
rather than activating it twice. vk relaunches the VM on a reset, so nothing reuses the rings.
A FAILED the driver wrote itself is now cleared by a reset, as the spec has it, instead of
making a resettable device look like one that cannot reset. Covered by
`a_reset_the_device_cannot_do_still_reads_back_as_done` and
`a_driver_written_failed_is_cleared_by_a_reset`.
