//! `fleet` ensure — bring each VM's ext4 up to date before boot. Each image is
//! content-addressed: its ext4 UUID is a fingerprint of what it was built from, so
//! the staleness check is just a UUID compare. The staleness check and the fingerprint
//! recipe both live in the build script (`build-{builder,service}-image.sh`), which
//! calls `virtkit fingerprint` to compute the UUID and `blkid` to check the existing
//! image. This module just invokes the build script; the script exits 0 immediately
//! when the image is already fresh.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::build::{self, BuildSpec};

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let d = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// Content fingerprint as a canonical UUID: sha256 of the parts joined by '\n', the
/// first 16 bytes formatted 8-4-4-4-12. Called by the `virtkit fingerprint` subcommand
/// so build scripts can compute the same value without reimplementing the algorithm.
pub fn fingerprint(parts: &[&str]) -> String {
    let hex = sha256_hex(parts.join("\n"));
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Run the VM's build script. The script owns the staleness check (UUID compare)
/// and exits 0 immediately when the image is already fresh.
pub fn ensure_vm(build_script: &Path) -> Result<()> {
    run_build(build_script, &[])
}

/// Run build-service-image.sh <image> <name>. The script owns the staleness check
/// and exits 0 immediately when the image is already fresh.
pub fn ensure_service(name: &str, image: &str, build_script: &Path) -> Result<()> {
    run_build(build_script, &[image, name])
}

/// A fleet-level build recipe shared by every unit built in-process: the
/// Dockerfile(s), context, and global build inputs. The per-unit `target` stage,
/// tag NAME, output ext4 and injected agent are supplied per call.
pub struct BuildRecipe {
    pub dockerfiles: Vec<PathBuf>,
    pub context: PathBuf,
    pub build_args: BTreeMap<String, String>,
    pub add_hosts: Vec<(String, String)>,
    pub free_gib: u64,
    pub buildkit_addr: Option<String>,
    pub buildctl: Option<PathBuf>,
    pub buildkitd: Option<PathBuf>,
    /// Shared bundle registry: when set, each unit's ext4 is pulled (if a sibling
    /// worktree already built this exact fingerprint) or pushed after a build, so the
    /// fleet shares one bundle pool across worktrees. `None` = build locally only.
    pub registry: Option<crate::config::Registry>,
}

/// Per-unit build overrides layered on top of the fleet-level [`BuildRecipe`]: extra
/// injects (in addition to the agent), extra env-files appended to `/etc/virtkit/env`,
/// and an optional free-gib override (else the recipe's `free_gib`). The services pass
/// the default (empty) value, so their build is identical to before.
#[derive(Default, Clone)]
pub struct UnitOverrides {
    pub injects: Vec<(String, PathBuf, u16)>,
    pub env_files: Vec<PathBuf>,
    pub free_gib: Option<u64>,
}

/// Ensure a unit's ext4 in-process via the `virtkit build` machinery (instead of
/// shelling to build-service-image.sh). `target` is the unit's Dockerfile stage,
/// `name` the tag/label NAME (the `:<tag>`-stripped `--service-image` value), `out`
/// the unit ext4, `agent` the static musl agent injected at the standard guest path.
/// `overrides` layers per-unit injects/env-files/free-gib on top of the recipe.
pub fn ensure_service_build(
    recipe: &BuildRecipe,
    target: &str,
    name: &str,
    out: &Path,
    agent: &Path,
    overrides: &UnitOverrides,
) -> Result<()> {
    // The agent inject is always present; per-unit --unit-inject entries are layered on.
    let mut injects = vec![(
        "usr/local/bin/virtkit-agent".to_string(),
        agent.to_path_buf(),
        0o755,
    )];
    injects.extend(overrides.injects.iter().cloned());
    let spec = BuildSpec {
        dockerfiles: recipe.dockerfiles.clone(),
        context: recipe.context.clone(),
        target: target.to_string(),
        name: name.to_string(),
        output: build::BuildOutput::Ext4(out.to_path_buf()),
        build_args: recipe.build_args.clone(),
        add_hosts: recipe.add_hosts.clone(),
        labels: Vec::new(),
        injects,
        env_files: overrides.env_files.clone(),
        free_gib: overrides.free_gib.unwrap_or(recipe.free_gib),
        buildkit_addr: recipe.buildkit_addr.clone(),
        buildctl: recipe.buildctl.clone(),
        buildkitd: recipe.buildkitd.clone(),
        ensure_daemon: true,
        force: false,
        registry: recipe.registry.clone(),
    };
    build::run(&spec)
}

/// Derive the tag/label NAME from a `--service-image NAME=<image-ref>` value by
/// stripping the `:<tag>` suffix (e.g. `wabmysql-bookworm:716aecf` ->
/// `wabmysql-bookworm`); no colon -> the value verbatim.
pub fn image_name(image_ref: &str) -> &str {
    image_ref.split_once(':').map_or(image_ref, |(n, _)| n)
}

fn run_build(script: &Path, args: &[&str]) -> Result<()> {
    let st = Command::new(script)
        .args(args)
        .status()
        .with_context(|| format!("running {}", script.display()))?;
    if !st.success() {
        bail!("{} failed ({st})", script.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_a_canonical_uuid_and_stable() {
        let fp = fingerprint(&["myservice:tag", "abc123"]);
        // 8-4-4-4-12 lowercase hex
        let parts: Vec<&str> = fp.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(fp.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        // deterministic + order-sensitive
        assert_eq!(fp, fingerprint(&["myservice:tag", "abc123"]));
        assert_ne!(fp, fingerprint(&["abc123", "myservice:tag"]));
    }

    #[test]
    fn image_name_strips_tag_suffix() {
        // `:<tag>` suffix dropped -> the tag/label NAME.
        assert_eq!(image_name("wabmysql-bookworm:716aecf"), "wabmysql-bookworm");
        // no colon -> verbatim passthrough.
        assert_eq!(image_name("wabmysql-bookworm"), "wabmysql-bookworm");
    }
}
