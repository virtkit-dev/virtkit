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
