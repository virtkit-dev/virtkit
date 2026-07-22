//! `build:` unit ensure — bring a compose `build:` service's ext4 up to date before
//! boot. The image is content-addressed: its ext4 UUID is a fingerprint of the stage
//! it was built from (the chained content identity of the base digest, instructions,
//! copied files and source stages), so the staleness check is a UUID compare.
//!
//! The image is byte-clean (no agent, no config baked in — both arrive at boot) built
//! in-process from a Dockerfile stage of the merged plan, leaving the runtime config
//! next to the image as the builder's JSON sidecar so a fresh unit boots without
//! rebuilding. Pulled units (`image:`/`virtkit/`) resolve through the shared image
//! cache instead (see image.rs), so there is no pull path here.

use std::path::{Path, PathBuf};
use std::time::Duration;

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
    pub cache_auth: crate::build::CacheAuth,
    /// Egress policy for the build's RUN guests (`[egress.build]`, narrowed per job).
    /// `BuildNet::All` = unrestricted (the docker-build-like default when unconfigured).
    pub net: crate::build::BuildNet,
    /// Audit the build's RUN egress into the job trace (`[egress.build] audit` /
    /// `MICROVM_BUILD_EGRESS_AUDIT`).
    pub audit: bool,
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
    progress_sink: Option<crate::build::ProgressSink>,
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
        out_disk: None,
        print_plan: false,
        cloud_hypervisor: recipe.cloud_hypervisor.clone(),
        kernel: recipe.kernel.clone(),
        agent: recipe.agent.clone(),
        cache_registry: recipe.cache_registry.clone(),
        cache_insecure: recipe.cache_insecure,
        cache_auth: recipe.cache_auth.clone(),
        build_cache: crate::build::BuildCache::default(),
        journal: false,
        tmp_tmpfs: false,
        build_args: recipe.build_args.clone(),
        // Build-phase egress: the CI job's effective `[egress.build]` policy (unrestricted
        // by default, like `docker build`, when unconfigured) + its build-audit flag.
        net: recipe.net.clone(),
        audit: recipe.audit,
        require_cached: false,
        build_jobs: None,
        debug: false,
        progress_sink,
    })?;
    let uuid = parse_uuid(&expected).expect("fingerprint is a canonical UUID");
    crate::ext4::set_uuid(out, &uuid)
}

/// The shared build-cache tier directory for a `build:` stage: `<state_dir>/build/<uuid>/`,
/// keyed by the stage's content fingerprint (the same value stamped into the ext4). An
/// identical stage — same base, instructions, copied files — maps to the same dir, so it is
/// built once and shared across services, runs, and runners. Slots into the generic
/// idle-eviction GC (`image::gc_idle`/`base_dirs`) like the pulled `registry/`/`docker/`
/// tiers.
pub fn build_tier_dir(state_dir: &Path, stage_key: &str) -> PathBuf {
    state_dir.join("build").join(fingerprint(&[stage_key]))
}

/// Ensure a `build:` stage is materialized in the shared build tier, returning its cache dir
/// (holding `runner.ext4` + its config sidecar). On a fingerprint miss it builds under a
/// pull lock into a tmp sibling, stamps the UUID, and promotes atomically — so a killed
/// build never leaves a half-image a freshness check would trust, and concurrent identical
/// builds serialize (the loser then finds it fresh). Marks the base used and runs idle GC on
/// the tier. `label` names the stage (its compose service / git-defined image name) in the
/// concurrent-build wait message. `sink` streams build progress when set.
pub fn ensure_build_tier(
    state_dir: &Path,
    idle: Duration,
    recipe: &BuildRecipe,
    target: Option<&str>,
    stage_key: &str,
    label: &str,
    sink: Option<crate::build::ProgressSink>,
) -> Result<PathBuf> {
    let dir = build_tier_dir(state_dir, stage_key);
    let expected = fingerprint(&[stage_key]);
    if unit_fresh(&dir.join("runner.ext4"), &expected) {
        crate::image::mark_used(&dir);
        return Ok(dir);
    }
    // `label` (the service / git-defined image name) names the stage in the concurrent-build
    // wait message; the fingerprint is the cache identity.
    let _lock = crate::image::acquire_pull_lock(&dir, "build", label, &expected)?;
    // Re-check under the lock: a concurrent build of the same stage may have just promoted it.
    if unit_fresh(&dir.join("runner.ext4"), &expected) {
        crate::image::mark_used(&dir);
        return Ok(dir);
    }
    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    // ensure_unit_build writes the ext4 + config sidecar and stamps the UUID at the out path.
    ensure_unit_build(recipe, target, stage_key, &tmp.join("runner.ext4"), sink)?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&tmp, &dir)
        .with_context(|| format!("promoting {} to {}", tmp.display(), dir.display()))?;
    crate::image::mark_used(&dir);
    crate::image::gc_idle(&state_dir.join("build"), idle);
    Ok(dir)
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
            cache_auth: Default::default(),
            net: crate::build::BuildNet::All,
            audit: false,
        };
        let key = "deadbeef";
        let expected = fingerprint(&[key]);
        crate::ext4::set_uuid(&out, &parse_uuid(&expected).unwrap()).unwrap();

        // UUID matches but the sidecar is missing -> stale (a boot needs the config).
        assert!(ensure_unit_build(&recipe, Some("svc"), key, &out, None).is_err());
        std::fs::write(crate::build::config_sidecar(&out), "{}").unwrap();
        // UUID + sidecar -> fresh, no build attempted.
        ensure_unit_build(&recipe, Some("svc"), key, &out, None).unwrap();
        // a different stage key -> stale again.
        assert!(ensure_unit_build(&recipe, Some("svc"), "other", &out, None).is_err());
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
