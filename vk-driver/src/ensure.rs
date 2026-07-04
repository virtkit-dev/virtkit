//! Unit ensure — bring each service's ext4 up to date before boot. Each image is
//! content-addressed: its ext4 UUID is a fingerprint of what it was built from, so
//! the staleness check is a UUID compare.
//!
//! Service units are byte-clean images (no agent, no config baked in — both arrive
//! at boot) produced in-process: built from a Dockerfile stage of the merged
//! plan (fingerprint = the builder's stage key, the chained content identity of
//! everything the stage is made of) or pulled from a registry (fingerprint = the
//! image's manifest digest). Both leave the runtime config next to the image as the
//! builder's JSON sidecar, so a fresh unit boots without rebuilding anything.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

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
/// first 16 bytes formatted 8-4-4-4-12. Called by the `vk fingerprint` subcommand
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

/// Parse a UUID (32 hex digits, dashes optional) into 16 bytes.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// How unit images build in-process: the merged Dockerfiles and the builder
/// wiring, shared by every `build:` unit (each unit picks its target stage).
pub struct BuildRecipe {
    pub dockerfiles: Vec<PathBuf>,
    /// Build contexts, zipped positionally with `dockerfiles` (missing = the file's dir).
    pub contexts: Vec<PathBuf>,
    pub build_args: Vec<(String, String)>,
    pub kernel: Option<PathBuf>,
    pub cloud_hypervisor: Option<PathBuf>,
    pub agent: Option<PathBuf>,
    pub cache_registry: Option<String>,
    pub cache_insecure: bool,
}

/// A unit image is fresh when its UUID is the expected fingerprint *and* its runtime
/// config sidecar is present (a boot needs both).
fn unit_fresh(out: &Path, expected_uuid: &str) -> bool {
    crate::ext4::fs_uuid(out).as_deref() == Some(expected_uuid)
        && crate::build::config_sidecar(out).exists()
}

/// Ensure a `build:` unit's image: skip when the ext4's UUID already equals
/// `fingerprint(stage_key)` — the stage key is the chained content identity of
/// everything the stage is built from (base digest, instructions, copied files,
/// source stages), so a UUID match means byte-equivalent content. Otherwise build
/// the stage (the instruction cache makes that incremental) and stamp the UUID.
pub fn ensure_unit_build(
    recipe: &BuildRecipe,
    target: Option<&str>,
    stage_key: &str,
    out: &Path,
) -> Result<()> {
    let expected = fingerprint(&[stage_key]);
    if unit_fresh(out, &expected) {
        println!("virtkit: {} fresh", out.display());
        return Ok(());
    }
    crate::build::build(&crate::build::Options {
        dockerfiles: recipe.dockerfiles.clone(),
        target: target.map(String::from),
        contexts: recipe.contexts.clone(),
        out: Some(out.to_path_buf()),
        print_plan: false,
        microvm: true,
        cloud_hypervisor: recipe.cloud_hypervisor.clone(),
        kernel: recipe.kernel.clone(),
        agent: recipe.agent.clone(),
        cache_registry: recipe.cache_registry.clone(),
        cache_insecure: recipe.cache_insecure,
        journal: false,
        build_args: recipe.build_args.clone(),
        // unrestricted RUN egress, like `docker build` (and `vk build`'s default) —
        // service stages install packages.
        net: crate::build::BuildNet::All,
        require_cached: false,
    })?;
    let uuid = parse_uuid(&expected).expect("fingerprint is a canonical UUID");
    crate::ext4::set_uuid(out, &uuid)
}

/// Ensure an `image:` unit's image: a byte-clean ext4 of the pulled rootfs (no agent
/// — it rides the boot initramfs), UUID = `fingerprint(manifest digest)`, runtime
/// config sidecar from the image's OCI config. Anonymous registry access.
pub async fn ensure_unit_pull(image: &str, out: &Path) -> Result<()> {
    let digest = crate::oci::resolve_digest(image)
        .await
        .with_context(|| format!("resolving {image}"))?;
    let expected = fingerprint(&[&digest]);
    if unit_fresh(out, &expected) {
        println!("virtkit: {} fresh ({image}@{digest})", out.display());
        return Ok(());
    }
    let source = crate::source::Source::Oci {
        reference: image.to_string(),
        username: None,
        password: None,
        ca_pem: None,
        insecure: false,
    };
    let uuid = parse_uuid(&expected).expect("fingerprint is a canonical UUID");
    let scratch = out.parent().unwrap_or_else(|| Path::new("."));
    source
        .stream_tar(scratch, |tar, hints| {
            // Same sizing as the `vk run` image path, plus writable headroom for the
            // service's own writes: units boot through a CoW overlay, but the
            // *filesystem* still needs free blocks to allocate (mirrors the builder's
            // bases).
            crate::ext4::build_from_tar_stream(
                tar,
                &[], // clean image: nothing injected
                hints.image_bytes(),
                32u64 * 1024 * 1024 * 1024 / 4096,
                Some(hints.inode_count()),
                &crate::ext4::FsId {
                    uuid: Some(uuid),
                    label: None,
                    with_journal: false,
                },
                out,
            )
        })
        .await?;
    let cfg = crate::oci::pull_config(image, None, None, None, false).await?;
    let config = vk_core::runcfg::RunConfig {
        env: cfg.env,
        user: cfg.user.unwrap_or_default(),
        workdir: cfg.workdir.unwrap_or_default(),
        entrypoint: cfg.entrypoint,
        cmd: cfg.cmd,
    };
    let sidecar = crate::build::config_sidecar(out);
    std::fs::write(&sidecar, config.to_json())
        .with_context(|| format!("writing {}", sidecar.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_parses_back_into_uuid_bytes() {
        let fp = fingerprint(&["stage-key"]);
        let bytes = parse_uuid(&fp).expect("fingerprint is canonical");
        // round-trips through the dash format
        assert_eq!(parse_uuid(&fp.replace('-', "")), Some(bytes));
        assert_eq!(parse_uuid("not-a-uuid"), None);
    }

    #[test]
    fn unit_build_skips_when_uuid_and_sidecar_match() {
        let tmp = std::env::temp_dir().join(format!("vk-ensure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let tree = tmp.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("f"), "x").unwrap();
        let out = tmp.join("svc.ext4");
        crate::ext4::build_from_dir(&tree, &out).unwrap();

        // a recipe whose Dockerfile does not exist: any attempt to build errors,
        // so an Ok() proves the freshness check short-circuited.
        let recipe = BuildRecipe {
            dockerfiles: vec![tmp.join("no-such-Dockerfile")],
            contexts: vec![],
            build_args: vec![],
            kernel: None,
            cloud_hypervisor: None,
            agent: None,
            cache_registry: Some("none".into()),
            cache_insecure: false,
        };
        let key = "deadbeef";
        let expected = fingerprint(&[key]);
        crate::ext4::set_uuid(&out, &parse_uuid(&expected).unwrap()).unwrap();

        // UUID matches but the sidecar is missing -> stale (a boot needs the config).
        assert!(ensure_unit_build(&recipe, Some("svc"), key, &out).is_err());
        std::fs::write(crate::build::config_sidecar(&out), "{}").unwrap();
        // UUID + sidecar -> fresh, no build attempted.
        ensure_unit_build(&recipe, Some("svc"), key, &out).unwrap();
        // a different stage key -> stale again.
        assert!(ensure_unit_build(&recipe, Some("svc"), "other", &out).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

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
}
