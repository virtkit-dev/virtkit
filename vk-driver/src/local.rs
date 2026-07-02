//! Local guest bundles on the host filesystem, backing the
//! `MICROVM_IMAGE: local/<name>` form (and the `local/default` default when
//! MICROVM_IMAGE is unset).
//!
//! Each `<[local] dir>/<name>/` is a baked bundle — a `runner.ext4`, a
//! `boot.kind`, and OPTIONALLY a `vmlinuz` + `initrd.img` — produced by
//! build-image.sh or pulled into place. Nothing is fetched: this is the
//! on-disk counterpart of the registry/convert cached-dir path, resolved to a
//! `ResolvedImage` exactly the same way (the boot shape from `boot.kind`,
//! the shared `[local] generic_kernel` for kernel-less bundles).

use anyhow::{Context, Result, bail};

use crate::image::{self, ResolvedImage};
use crate::jobctx::JobCtx;

/// Resolve a local bundle `<[local] dir>/<name>/` to a `ResolvedImage`. `name` is a
/// single safe path component (local bundles are never tagged or digested).
pub fn resolve(ctx: &JobCtx, name: &str) -> Result<ResolvedImage> {
    // a single safe path component: no separators, no tag/digest, no leading dot.
    if name.is_empty() || name.starts_with('.') || name.contains(['/', ':', '@']) {
        bail!(
            "invalid local image name {name:?} (want a single safe component; \
             local bundles are not tagged or digested)"
        );
    }
    let dir = ctx.cfg.local_dir().join(name);
    if !dir.join("runner.ext4").is_file() || !dir.join("boot.kind").is_file() {
        bail!(
            "local image {name:?} not found at {} — bake it with build-image.sh or pull it",
            dir.display()
        );
    }
    let boot_kind = image::read_boot_kind(&dir).with_context(|| {
        format!("local image {name:?}: unsupported boot.kind marker — rebuild the image")
    })?;
    println!("virtkit: image local/{name} ({boot_kind:?})");
    Ok(image::resolved_from_dir(
        &ctx.cfg.local.generic_kernel,
        &dir,
        boot_kind,
    ))
}
