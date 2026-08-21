# Vendored imago

Source: https://gitlab.com/hreitz/imago (published to crates.io as `imago`)
Revision: `0.2.4`

Only the Rust sources are vendored: `Cargo.toml`, `Cargo.lock`, `LICENSE`, `build.rs`, and
`src/`. `README.md`, `rustfmt.toml`, and the GitLab CI files are dropped as unneeded for the
build.

A leaf crate (no sub-crates), so unlike `third_party/libkrun` it does not need its own
workspace exclusion beyond the root `Cargo.toml`'s `exclude`. `third_party/libkrun/src/devices`
depends on it by path instead of the crates.io release, so a local patch can be applied — see
this file's own history for what that patch is and why.

## Local patches

None yet.
