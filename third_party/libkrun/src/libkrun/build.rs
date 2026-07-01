// virtkit builds this crate as an rlib only (see Cargo.toml `crate-type` and
// VENDOR.md). Upstream this script sets the `libkrun.so`/`.dylib` soname via
// `cargo:rustc-cdylib-link-arg`, which cargo warns about with no cdylib target — so
// with the cdylib dropped there is nothing for it to do.
fn main() {}
