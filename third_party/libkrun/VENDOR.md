# Vendored libkrun

Source: https://github.com/containers/libkrun
Revision: `9a8fedc7fa425a36ae978d529a6c0dc7124efe7d` (stable-1.19.x, carries PR #728)

Only the Rust sources are vendored: `Cargo.toml`, `Cargo.lock`, `LICENSE`, and
`src/`. Everything else upstream is dropped (the `libkrun` crate does not need it for
the `blk` + `net` Linux build virtkit uses). Note that this includes `init/`, the C
sources compiled by the build script of the `init-blob` default feature — so the crate
builds only with `--no-default-features --features blk,net`; a plain `cargo build` in
this workspace fails in `init_blob`'s build script.

This is its own cargo workspace, excluded from the root virtkit workspace. The host
crate will depend on `src/libkrun` (package `libkrun`, lib name `krun`) as a path
dependency, so it shares virtkit's `std` — avoiding the double-std / broken-unwinding
that a static `libkrun.a` link hits.

## Local patches

`src/devices/src/virtio/fs/{idmap.rs,mod.rs,worker.rs}` + `src/vmm/src/vmm_config/fs.rs`
+ `src/vmm/src/builder.rs` + `src/libkrun/src/lib.rs` — UID/GID mapping for virtio-fs
shares. A new `idmap` module (soft, virtiofsd `--uid-map`/`--gid-map`-compatible: `map:`,
`squash-guest:`, `forbid-guest:`, …) wraps `PassthroughFs` inside `AugmentFs` when a map is
configured; `FsDeviceConfig` carries the maps and `krun_add_virtiofs4(…, uid_map, gid_map)`
sets them (`krun_add_virtiofs3` delegates with none). The `idmap` module is the same engine
the bundled `vk virtiofsd` uses (moved here from vk-driver so both backends share it).
Additive: with no map, behaviour is unchanged. Used by virtkit to squash the GitLab
`host_checkout` share onto the host runner user so a non-root job can write it.

`src/devices/src/virtio/descriptor_utils.rs` + `src/devices/src/virtio/fs/mod.rs` —
expose the fs engine to external transports: `Reader/Writer::from_volatile_slices`
constructors (build a FUSE request view from buffers collected by another virtio
transport, e.g. vhost-user) and public `filesystem`/`read_only` modules plus `pub use`
of `Server` and `InodeAllocator`. Additive only — nothing upstream changes behaviour.
Used by virtkit's bundled `vk virtiofsd` daemon (vk-driver/src/virtiofsd), which serves
cloud-hypervisor's vhost-user shares with this fs engine instead of the virtiofsd crate.

`src/arch/src/x86_64/mod.rs` — place the initrd below 4 GiB. It was placed at the top
of all guest RAM, but the boot protocol's `setup_header` here has no `ext_ramdisk_image`
field, so the address is passed only through the 32-bit `ramdisk_image`. Once the guest
has more than ~3 GiB, the top of RAM is above 4 GiB and the address truncated, so the
kernel could not find the initrd and panicked (`Unable to mount root fs`). The initrd is
now placed at the top of the sub-gap (below-4 GiB) RAM region. Search for `initrd_addr`.

`src/libkrun/Cargo.toml` + `src/libkrun/build.rs` — dropped `cdylib` from the crate's
`crate-type` (now just `lib`). virtkit links the crate as an rlib path dependency; the
upstream `cdylib` (`libkrun.so`, for C consumers) is never built and is unsupported on
the static-PIE musl target, so cargo emitted a "dropping unsupported crate type
`cdylib`" warning on every build. The build script did nothing but set the
`libkrun.so`/`.dylib` soname via `cargo:rustc-cdylib-link-arg` (itself warned about
with no cdylib target), so it is now a no-op.

`src/arch/src/x86_64/layout.rs` + `src/arch/src/x86_64/mptable.rs` — raise the
virtio-mmio IRQ ceiling to the full single IOAPIC. Upstream caps `IRQ_MAX` at 15 and
the MPTABLE routes only the 16 legacy ISA INTSRC pins, while the emulated IOAPIC
(`devices/legacy/ioapic.rs`) already exposes 24 pins. `IRQ_MAX` is now
`IOAPIC_NUM_PINS - 1` (23) and the MPTABLE routes and sizes all 24 pins, so a guest can
wire virtio-mmio devices landing on the high pins (19 usable IRQs instead of 11). A
`mptable::tests::intsrc_entry_count` test locks the routed-pin count to `IOAPIC_NUM_PINS`.
Search for `IOAPIC_NUM_PINS`.

`src/devices/src/virtio/fs/linux/passthrough.rs` — the passthrough fs device called
`libc::statx` with `libc::STATX_BASIC_STATS | libc::STATX_MNT_ID`. libc dropped its
musl `statx` struct/fn/constants after 0.2.183, but virtkit needs a newer libc (its
dependency tree pulls libc >= 0.2.186). `struct statx` is defined by the kernel UAPI
to be architecture-independent, so the patch reproduces exactly the fields the device
reads and issues the raw `SYS_statx` syscall. Behaviour is identical, including the
returned `stx_mnt_id`. Search for `mod statx_compat` in that file.

`src/devices/src/virtio/descriptor_utils.rs` — clamp the final descriptor in
`DescriptorChainConsumer::consume`. It documents that the combined length of the slices
handed to the callback is `<= count`, but pushed the last descriptor whole and only
clamped the byte counter, so a vectored disk read (`Writer::write_from_at` ->
`DiskProperties::read_vectored_at_volatile`) filled the entire final descriptor and
over-read past `count` into guest memory the guest never requested — a read-path
corruption whose trigger depends on the guest's per-request descriptor layout. The final
slice is now `subslice`d to the remaining count, matching the byte-copy `write()` path
that already clamps. Covered by the `write_from_at_must_not_overread_past_count` test.
Search for `subslice` in `consume`.

`src/devices/src/virtio/vsock/unix.rs` — `UnixProxy::release` shuts the host socket down
and stops polling it. A guest `OP_RST` on a host-initiated connection (its port has no
listener yet, the usual case for a readiness probe during boot) only deferred the proxy's
removal, so the host peer read EOF when the reaper dropped the proxy 5 s later; it now
reads it at once. Search for `release: shutdown failed`.

`src/devices/src/virtio/block/device.rs` + `src/devices/src/virtio/file_traits.rs` —
serve reads from read-only raw disks out of an `mmap` of the backing file instead of a
`pread` per request. Upstream reads every block through imago's positioned-I/O file
storage; a read-only raw image (a build stage's `COPY --from` source, a read-only root)
is immutable and its guest block offset is its file offset, so it is mapped once
(`PROT_READ`, `MAP_SHARED`) and each guest read becomes a copy straight from the host
page cache. qcow2 (needs format translation) and `direct_io` (asks to bypass the cache)
keep the imago path, and a failed `mmap` falls back to it rather than aborting the boot.
Covered by the `block::device::tests` mmap tests. Search for `DiskMmap`.

`src/devices/src/virtio/block/{device.rs,worker.rs}` + `src/libkrun/src/lib.rs` +
`src/vmm/src/vmm_config/block.rs` — track guest-written clusters and drain them on demand,
so virtkit's build backend can capture only a stage checkpoint's delta instead of the whole
cumulative overlay. The block worker records every write/discard/write-zeroes into a
per-disk `DirtyRanges` (64 KiB cluster granularity); when `dirty_control_socket` is set on a
block device, `Block::spawn_dirty_control` serves a Unix-socket protocol (`b'D'` DRAIN →
flush + reply the coalesced ranges since the last drain, encoded `u32 count` then
`count × (u64 offset, u64 len)` little-endian). Exposed to C consumers via
`krun_set_block_dirty_socket`. Additive only — no upstream behaviour changes when the socket
is unset. Consumed by virtkit's `VmSession::drain_dirty` (vk-driver/src/run.rs). Covered by
the `block::device::dirty_tests`. Search for `DirtyRanges`.

`src/vmm/src/builder.rs` — feed an early 16550 COM1 serial from `console_output` on non-EFI
x86_64 boots. Upstream builds the legacy serial only for EFI/firmware boots, so a stock modular
distro kernel (virtio_console as a module, hvc0) emits no early boot output — a BYO-kernel boot is
impossible to observe. When `serial_devices` is empty, the implicit console is enabled, and
`console_output` is set, a serial is added writing (append) to that file so COM1 (0x3f8, IRQ 4)
carries early boot. Additive only; the embedded kernel keeps `console=hvc0` and never triggers it.
Search for `virtkit: give the guest an early 16550 COM1 console`.

`src/devices/src/legacy/pci.rs` (new) + `src/devices/src/legacy/mod.rs` +
`src/vmm/src/device_manager/legacy.rs` — a minimal legacy PCI host bridge so a guest kernel
enumerates a PCI bus, the foundation for virtio-pci support. `PciConfigIo` implements the type-1
config mechanism on the PIO bus at 0xcf8 (CONFIG_ADDRESS latch) / 0xcfc (CONFIG_DATA window),
with the BDF/register decode adapted from cloud-hypervisor's `PciConfigIo`; a `PciBus` holds a
single host-bridge `PciDevice` at 00:00.0 (vendor 0x1b36 / device 0x0008, class 0x060000, header
type 0). Registered by `PortIODeviceManager`. x86_64 only; additive — no upstream behaviour
change until PCI devices are attached later. Covered by `legacy::pci` unit tests.
Search for `PciConfigIo`.

`src/devices/src/virtio/pci.rs` (new) + `src/devices/src/legacy/pci.rs` +
`src/arch/src/x86_64/{mod.rs,mptable.rs}` + `src/vmm/src/device_manager/kvm/mmio.rs` +
`src/vmm/src/builder.rs` — a modern virtio-pci transport over legacy INTx.
`VirtioPciDevice` wraps a `VirtioDevice` and serves the virtio common /
ISR / device / notify structures out of a single 64-bit BAR0 on the MMIO bus, with a vendor
capability list pointing a driver at each structure; `PciDevice` gains a type-0 endpoint
header, 64-bit memory-BAR sizing, and capability-list assembly. Interrupts use legacy INTx
routed through an MP-table PCI-bus INTSRC entry (KVM irqfd, single-pulse). The block device now
attaches over virtio-pci instead of virtio-mmio on x86_64 (00:01.0 for the first device). MSI-X
and multi-device slot allocation are out of scope here (added separately). x86_64 only; additive.
Covered by `legacy::pci` unit tests. Search for `VirtioPciDevice`.

`src/devices/src/virtio/msix.rs` (new) + `src/devices/src/legacy/gsi.rs` (new) +
`src/devices/src/virtio/{pci.rs,mmio.rs}` + `src/devices/src/legacy/pci.rs` +
`src/vmm/src/device_manager/kvm/mmio.rs` + `src/vmm/src/builder.rs` +
`src/vmm/src/linux/vstate.rs` — MSI-X for the virtio-pci transport, so many virtio devices
can be attached without exhausting the scarce IOAPIC pins.
Each virtio-pci device advertises a two-vector MSI-X capability (vector 0 = config, vector 1 =
shared across all virtqueues, since libkrun's `InterruptTransport` carries no queue index); the
`MsixConfig` table/PBA live in BAR0 while the capability's message-control (enable/mask) lives
in config space, both sharing one `Arc<Mutex<MsixConfig>>`. Interrupts are delivered by writing
a per-vector eventfd registered with `KVM_IRQFD` against a dedicated MSI GSI (>= 24); a
`GsiRoutes` manager owns `KVM_SET_GSI_ROUTING`, re-supplying the default IOAPIC/PIC routes
(0..=23) on every commit because the ioctl replaces the whole table. INTx is retained as a
fallback on a single shared, shareable GSI (PCI INTx is level-shareable), so it no longer
consumes one pin per device. `Vm.fd` became `Arc<VmFd>` so routing ioctls can run off the
config-write path. x86_64 only; additive — the virtio-mmio transport, other arches, and the
INTx path when the guest leaves MSI-X disabled are unchanged. Covered by `virtio::msix`,
`legacy::gsi`, and `legacy::pci` unit tests. Search for `MsixConfig` and `GsiRoutes`.

`src/cpuid/src/transformer/{mod.rs,intel.rs}` + `src/vmm/src/linux/vstate.rs` +
`src/vmm/src/resources.rs` + `src/vmm/src/builder.rs` + `src/libkrun/src/lib.rs` —
opt-in guest PMU: `krun_set_pmu(ctx, enabled)` (mirroring `krun_set_nested_virt`)
plumbs `VmResources.pmu_enabled` through `VcpuConfig` into the cpuid `VmSpec`, and
`update_perf_mon_entry` then leaves leaf 0xA as KVM reports it instead of zeroing
it, so KVM's vPMU backs in-guest `perf` hardware counters (cycles, instructions).
Default remains off — host performance counters are a side-channel surface, so
only trusted guests (dev VMs) should enable this, never untrusted CI jobs.
Additive: without the call, behaviour is unchanged. Used by `vk run --pmu`.

`src/vmm/src/resources.rs` + `src/vmm/src/builder.rs` + `src/libkrun/src/lib.rs` — make the
virtio-balloon device opt-out: `krun_disable_balloon(ctx)` sets `VmResources.disable_balloon`,
which `build_microvm` checks before attaching it. Upstream always attaches one, so a caller
could not boot without free-page reporting or reclaim the virtio-pci slot it spends — and
virtkit's own `VmSpec::balloon` axis was silently ignored on this backend while
cloud-hypervisor honored it. Spelled as a disable (like `disable_implicit_console`) so the
`Default` keeps attaching a balloon. Additive: without the call, behaviour is unchanged.
Search for `disable_balloon`.

`src/devices/src/virtio/block/{lazy_chunk_storage.rs (new),device.rs,mod.rs}` +
`src/devices/Cargo.toml` — read a cached build-stage image lazily out of its compressed chunks
instead of a reassembled raw file. A `.vk_ro_img` manifest (written by vk-driver,
`registry.rs`; byte layout documented on the module) lists the content-addressed chunks tiling
an image plus the local cache directory holding them;
`LazyChunkStorage` is a read-only `imago::Storage` that decompresses each chunk the first time
a guest read touches it, so a cache restore costs only the parts a stage's steps actually read.
Attached directly as `ImageType::VkLazyChunks`, and — since a stage forked from a restored one
is a qcow2 over a qcow2 over the manifest — resolved as a *backing* file at any depth of a
chain by `LazyAwareOpenGate`, an `ImplicitOpenGate` that swaps in the lazy storage for any
implicitly opened file named `*.vk_ro_img` (imago still picks the format layer from the
parent's recorded `backing_format`, which must be `raw`). Keying on the host-chosen extension
rather than sniffing the magic is deliberate: it keeps a guest-writable image from ever being
promoted into a manifest and thereby naming an arbitrary host directory as its chunk cache.
Local-disk-only (`std::fs::read` + zstd decode), so no network or async runtime enters
libkrun; the crate gains `zstd`, `lru` and `maybe-async` for it. Additive — no upstream
behaviour changes for a disk that is not a manifest and has none in its chain. Covered by
`block::lazy_chunk_storage::tests` and the backing-chain tests in `block::device::tests`.
Search for `LazyChunkStorage`.
