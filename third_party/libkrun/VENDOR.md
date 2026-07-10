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

`src/devices/src/virtio/block/device.rs` + `src/devices/src/virtio/file_traits.rs` —
serve reads from read-only raw disks out of an `mmap` of the backing file instead of a
`pread` per request. Upstream reads every block through imago's positioned-I/O file
storage; a read-only raw image (a build stage's `COPY --from` source, a read-only root)
is immutable and its guest block offset is its file offset, so it is mapped once
(`PROT_READ`, `MAP_SHARED`) and each guest read becomes a copy straight from the host
page cache. qcow2 (needs format translation) and `direct_io` (asks to bypass the cache)
keep the imago path, and a failed `mmap` falls back to it rather than aborting the boot.
Covered by the `block::device::tests` mmap tests. Search for `DiskMmap`.
