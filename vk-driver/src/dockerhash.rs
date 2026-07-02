//! `vk docker-hash` — print each stage's build-cache key (its `stage_key`: the
//! chained content key after the stage's last instruction). That key is the exact
//! identity virtkit's instruction cache stores a stage's snapshot under, so a printed
//! key is the tag the build's resulting ext4 lives at in the cache registry.
//!
//! The keys are computed by replaying the build's key chain (shared with the builder via
//! [`crate::build::stage_keys`]) without materializing anything — base manifest digests
//! and base image config are resolved over the network so a printed key matches what a
//! real build would store. A context `COPY` folds in the sha256 of the files it copies,
//! so the key tracks the copied bytes too.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// CLI entry: print `stage:key` for the requested stages (or every stage, in build
/// order, if none requested). Several Dockerfiles merge into one stage namespace,
/// exactly as `vk build` sees them.
pub fn run(
    dockerfiles: &[PathBuf],
    contexts: &[PathBuf],
    build_args: &[(String, String)],
    requested: &[String],
) -> Result<()> {
    let keys = crate::build::stage_keys(dockerfiles, contexts, build_args)?;
    if requested.is_empty() {
        for (name, key) in &keys {
            println!("{name}:{key}");
        }
        return Ok(());
    }
    for s in requested {
        let key = keys
            .iter()
            .find(|(n, _)| n == s)
            .map(|(_, k)| k)
            .with_context(|| {
                format!(
                    "stage '{s}' not found in {}",
                    dockerfiles
                        .iter()
                        .map(|f| f.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" + ")
                )
            })?;
        println!("{s}:{key}");
    }
    Ok(())
}
