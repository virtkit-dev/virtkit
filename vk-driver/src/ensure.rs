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
    /// Named build contexts (`--build-context <name>=<dir>`, or a job's `buildcontext=`): extra
    /// directories a `COPY --from=<name>` or `RUN --mount=…,from=<name>` may read. Job-authored
    /// values must already be confined to the checkout by the caller, like
    /// `dockerfiles`/`contexts` are.
    pub build_contexts: Vec<(String, PathBuf)>,
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
/// config sidecar is present (a boot needs both). The builder's export tail publishes the
/// two in an order that makes this check trustworthy: the stamped image is renamed into
/// place only after the previous sidecar is gone, and the new sidecar is written last.
pub(crate) fn unit_fresh(out: &Path, expected_uuid: &str) -> bool {
    crate::ext4::fs_uuid(out).as_deref() == Some(expected_uuid)
        && crate::build::config_sidecar(out).exists()
}

/// Ensure a `build:` unit's image: skip when the ext4's UUID already equals
/// `fingerprint(stage_key)` — the stage key is the chained content identity of
/// everything the stage is built from (base digest, instructions, copied files,
/// source stages), so a UUID match means byte-equivalent content. Otherwise build
/// the stage (the instruction cache makes that incremental); the build's export tail
/// stamps that UUID onto the image.
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
        stage_guests: Default::default(),
        contexts: recipe.contexts.clone(),
        build_contexts: recipe.build_contexts.clone(),
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
        // A `build:` unit's image lands in the shared, content-addressed, cross-restart
        // build tier `vk build`'s own journal-by-default exists for — match that default
        // here rather than leave this one path silently exempt. Every current boot of it
        // goes through a throwaway CoW overlay (never a raw read-write attach), so this is
        // precautionary consistency with the CLI default, not a fix for an unclean-shutdown
        // failure mode actually reachable on this specific path today.
        journal: true,
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
    Ok(())
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

/// A held reference on `dir` iff it is already fresh, `None` when it must be (re)built.
///
/// Check, acquire, re-check. The idle GC only backs off a base once something holds its
/// `.inuse`, so the reference has to be taken before the answer is trusted — a peek that
/// found the dir fresh says nothing about the moment the caller actually uses it. The
/// re-check is what separates a reference worth having from one taken on a dir the GC
/// removed, or a concurrent builder replaced, while this was blocked on the lock.
fn reference_if_fresh(
    state_dir: &Path,
    dir: &Path,
    expected: &str,
) -> Result<Option<crate::cachelock::Guard>> {
    let out = dir.join("runner.ext4");
    if !unit_fresh(&out, expected) {
        return Ok(None);
    }
    let guard = match crate::image::acquire_use_lock_for(state_dir, &out) {
        Ok(Some(guard)) => guard,
        // Unreachable: a build-tier dir is always `<state_dir>/build/…`, a managed tier. Were
        // it not, the re-check below would answer `None` too, so every call would rebuild.
        Ok(None) => return Ok(None),
        // The GC removed the dir between the peek and the open, so there is nothing left to
        // put a sidecar in: that is "not fresh", not a failure.
        Err(e) if crate::cachelock::is_not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    if unit_fresh(&out, expected) {
        Ok(Some(guard))
    } else {
        // The GC won the race between our first check and taking the lock (or a concurrent
        // builder is mid-promotion): the guard is worthless, fall back to rebuilding.
        Ok(None)
    }
}

/// Ensure a `build:` stage is materialized in the shared build tier, returning its cache dir
/// (holding `runner.ext4` + its config sidecar) together with a held reference on it. On a
/// fingerprint miss it builds under a pull lock into a tmp sibling, stamps the UUID, and
/// promotes atomically — so a killed build never leaves a half-image a freshness check would
/// trust, and concurrent identical builds serialize (the loser then finds it fresh). Runs idle
/// GC on the tier. `label` names the stage (its compose service / git-defined image name) in
/// the concurrent-build wait message. `sink` streams build progress when set.
///
/// The caller MUST hold the returned guard for as long as it depends on the dir — the idle GC
/// removes a build-tier entry the instant nobody holds its `.inuse`, regardless of how recently
/// `unit_fresh` last found it good. This very function sweeps the tier after every build, so a
/// caller that resolves one stage and builds the next has already given the sweep that can
/// evict the first a chance to run.
pub fn ensure_build_tier(
    state_dir: &Path,
    idle: Duration,
    recipe: &BuildRecipe,
    target: Option<&str>,
    stage_key: &str,
    label: &str,
    sink: Option<crate::build::ProgressSink>,
) -> Result<(PathBuf, crate::cachelock::Guard)> {
    let dir = build_tier_dir(state_dir, stage_key);
    let expected = fingerprint(&[stage_key]);
    if let Some(guard) = reference_if_fresh(state_dir, &dir, &expected)? {
        return Ok((dir, guard));
    }
    // `label` (the service / git-defined image name) names the stage in the concurrent-build
    // wait message; the fingerprint is the cache identity.
    let _lock = crate::image::acquire_pull_lock(&dir, "build", label, &expected)?;
    // Re-check under the lock: a concurrent build of the same stage may have just promoted it.
    if let Some(guard) = reference_if_fresh(state_dir, &dir, &expected)? {
        return Ok((dir, guard));
    }
    // Reclaim scratch orphaned by earlier failed/killed builds of *other* stages before
    // asking for more space ourselves — otherwise a tier stuck failing (e.g. ENOSPC) never
    // gets a chance to recover, since the success path below is never reached.
    crate::image::sweep_orphaned_build_tmp(&state_dir.join("build"));
    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    // Wipe `tmp` the instant the build below fails (or panics) — don't leave that for a
    // later sweep to notice. `ensure_unit_build`'s `?` runs this on the way out.
    let cleanup = crate::image::TmpGuard::new(&tmp);
    // ensure_unit_build writes the ext4 + config sidecar and stamps the UUID at the out path.
    ensure_unit_build(recipe, target, stage_key, &tmp.join("runner.ext4"), sink)?;
    cleanup.keep(); // built successfully: the rename below takes ownership of `tmp`.
    // The one removal that ignores references — but by construction nobody holds one: a
    // holder found the entry fresh, and so would the two `reference_if_fresh` checks above,
    // which would have returned long before here.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&tmp, &dir)
        .with_context(|| format!("promoting {} to {}", tmp.display(), dir.display()))?;
    // Take the reference right away, still under the pull lock (still `_lock`-held) and with
    // no `.used` marker yet on the freshly promoted dir — so there is no instant, before this
    // returns, in which the idle GC could see the promoted dir as a reclaimable, unreferenced
    // entry.
    let guard = crate::image::acquire_use_lock_for(state_dir, &dir.join("runner.ext4"))?
        .context("internal invariant: the build tier is one of the managed cache tiers")?;
    let build_root = state_dir.join("build");
    crate::image::gc_idle(&build_root, idle);
    crate::image::sweep_orphaned_build_tmp(&build_root);
    Ok((dir, guard))
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
            build_contexts: Vec::new(),
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

    // Regression test: before `TmpGuard`, a build failure left its `<fingerprint>.tmp`
    // scratch on disk forever (nothing but a later rebuild of that exact key, or a manual
    // `vk gc`, would ever touch it — see `image::sweep_orphaned_build_tmp`).
    #[test]
    fn ensure_build_tier_wipes_its_tmp_scratch_when_the_build_fails() {
        let state_dir =
            std::env::temp_dir().join(format!("vk-ensure-tier-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        // a recipe whose Dockerfile does not exist: the build always fails.
        let recipe = BuildRecipe {
            dockerfiles: vec![state_dir.join("no-such-Dockerfile")],
            contexts: vec![],
            build_contexts: Vec::new(),
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
        let key = "will-fail";
        let result = ensure_build_tier(
            &state_dir,
            Duration::from_secs(3600),
            &recipe,
            Some("svc"),
            key,
            "svc",
            None,
        );
        assert!(
            result.is_err(),
            "test setup: the build must fail (missing Dockerfile)"
        );
        let tmp = build_tier_dir(&state_dir, key).with_extension("tmp");
        assert!(
            !tmp.exists(),
            "a failed build must not leave its .tmp scratch behind"
        );
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    // Regression test: `ensure_build_tier`'s fast (already-fresh) path used to return a bare
    // path with only a point-in-time `.used` stamp — no reference the idle GC had to respect —
    // so a `vk gc` racing a caller that resolved the dir and kept it around a while (rather
    // than booting it immediately) could remove the dir out from under that later use.
    #[test]
    fn ensure_build_tier_fast_path_holds_a_guard_the_idle_gc_must_respect() {
        let state_dir =
            std::env::temp_dir().join(format!("vk-ensure-tier-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        let key = "already-fresh";
        let dir = build_tier_dir(&state_dir, key);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("runner.ext4");
        let tree = state_dir.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        crate::ext4::build_from_dir(&tree, &out).unwrap();
        let expected = fingerprint(&[key]);
        crate::ext4::set_uuid(&out, &parse_uuid(&expected).unwrap()).unwrap();
        std::fs::write(crate::build::config_sidecar(&out), "{}").unwrap();

        // A recipe whose Dockerfile does not exist: any attempt to actually build errors, so
        // returning `Ok` here is only possible via the already-fresh fast path.
        let recipe = BuildRecipe {
            dockerfiles: vec![state_dir.join("no-such-Dockerfile")],
            contexts: vec![],
            build_contexts: Vec::new(),
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
        let (got_dir, guard) = ensure_build_tier(
            &state_dir,
            Duration::from_secs(3600),
            &recipe,
            Some("svc"),
            key,
            "svc",
            None,
        )
        .unwrap();
        assert_eq!(got_dir, dir);

        let build_root = state_dir.join("build");
        // A zero idle window would otherwise reclaim any base nothing holds a reference on.
        crate::image::gc_idle(&build_root, Duration::ZERO);
        assert!(
            dir.exists(),
            "a base the caller holds a guard on must never be evicted"
        );

        drop(guard);
        assert!(
            crate::cachelock::reclaimed_eventually(|| {
                crate::image::gc_idle(&build_root, Duration::ZERO);
                !dir.exists()
            }),
            "the base must become reclaimable once the guard is released"
        );

        let _ = std::fs::remove_dir_all(&state_dir);
    }

    // `reference_if_fresh`'s three deterministic answers. The fourth — acquired, then the
    // re-check fails because the GC or a concurrent promotion landed in between — needs two
    // processes racing on the same entry and is covered by the guard test above instead.
    #[test]
    fn reference_if_fresh_answers_none_for_a_missing_or_stale_dir() {
        let state_dir = std::env::temp_dir().join(format!("vk-ensure-ref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        let key = "reference-if-fresh";
        let expected = fingerprint(&[key]);
        let dir = build_tier_dir(&state_dir, key);

        // Nothing on disk at all: not fresh, and no error for the absent sidecar.
        assert!(
            reference_if_fresh(&state_dir, &dir, &expected)
                .unwrap()
                .is_none()
        );

        // Present but stamped with another stage's fingerprint: still not fresh.
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("runner.ext4");
        let tree = state_dir.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        crate::ext4::build_from_dir(&tree, &out).unwrap();
        crate::ext4::set_uuid(&out, &parse_uuid(&fingerprint(&["other"])).unwrap()).unwrap();
        std::fs::write(crate::build::config_sidecar(&out), "{}").unwrap();
        assert!(
            reference_if_fresh(&state_dir, &dir, &expected)
                .unwrap()
                .is_none()
        );

        // Right fingerprint: a reference the idle GC has to respect.
        crate::ext4::set_uuid(&out, &parse_uuid(&expected).unwrap()).unwrap();
        let guard = reference_if_fresh(&state_dir, &dir, &expected)
            .unwrap()
            .expect("a fresh dir hands back a reference");
        crate::image::gc_idle(&state_dir.join("build"), Duration::ZERO);
        assert!(dir.exists(), "a referenced base must not be evicted");
        drop(guard);

        let _ = std::fs::remove_dir_all(&state_dir);
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
