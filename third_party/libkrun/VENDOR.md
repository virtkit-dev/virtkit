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

`src/devices/src/virtio/fs/linux/passthrough.rs` — the passthrough fs device called
`libc::statx` with `libc::STATX_BASIC_STATS | libc::STATX_MNT_ID`. libc dropped its
musl `statx` struct/fn/constants after 0.2.183, but virtkit needs a newer libc (its
dependency tree pulls libc >= 0.2.186). `struct statx` is defined by the kernel UAPI
to be architecture-independent, so the patch reproduces exactly the fields the device
reads and issues the raw `SYS_statx` syscall. Behaviour is identical, including the
returned `stx_mnt_id`. Search for `mod statx_compat` in that file.
