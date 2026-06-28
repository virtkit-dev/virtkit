//! `virtkit build`: Dockerfile target -> bootable ext4 in one tool. Resolves the
//! stage's content hash to a `<name>:<hash>` tag + fingerprint UUID (skips the
//! build when the existing image already carries it), ensures a buildkitd, drives
//! buildctl to an OCI archive, then flattens it to ext4 via the `mkext-oci` path.
//!
//! Extracted from the `Cmd::Build` dispatch so both the CLI and `fleet` (its
//! in-process ensure) drive the identical analyze -> hash -> fingerprint-skip ->
//! ensure-daemon -> buildctl -> mkext-oci flow.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::{buildkit, dockerhash, ensure, ext4, fleet, mkoci};

/// Where a build puts its result.
pub enum BuildOutput {
    /// Flatten the target stage into a bootable ext4 image at this path.
    Ext4(PathBuf),
    /// Export the target stage's rootfs to this host dir (buildctl `type=local`) —
    /// used to extract a built artifact (e.g. a static binary) from a scratch-final
    /// stage. No ext4, no fingerprint-skip (always rebuilds).
    Local(PathBuf),
    /// Push the target stage to a registry as an OCI image (buildctl
    /// `type=image,push=true`) — build a normal container image from a Dockerfile
    /// with no docker. No ext4, no fingerprint-skip (always builds). The string is
    /// the image reference `<registry>/<name>:<tag>`.
    Push(String),
    /// Build the ext4 and push it straight to the `[registry]` as a bundle tagged
    /// `<name>:<tag>`, materializing the ext4 only transiently (no kept artifact) —
    /// the direct buildkit → bundle-registry path. Requires `spec.registry`. The
    /// string is the bundle reference `<name>:<tag>`.
    Bundle(String),
    /// Build the target stage and load it into the local container daemon (buildkit
    /// `type=docker` streamed to `<cli> load`) — a normal local image, no registry,
    /// no ext4. The string is the image reference `<name>:<tag>`. The loader defaults
    /// to `docker`, overridable via `VIRTKIT_CONTAINER_CLI` (e.g. `podman`).
    Load(String),
}

/// A resolved build request: the CLI layer (and `fleet`) parse their flags into
/// this, then call [`run`]. Paths/args carry no further parsing.
pub struct BuildSpec {
    pub dockerfiles: Vec<PathBuf>,
    pub context: PathBuf,
    pub target: String,
    pub name: String,
    pub output: BuildOutput,
    pub build_args: BTreeMap<String, String>,
    pub add_hosts: Vec<(String, String)>, // (host, ip)
    pub labels: Vec<(String, String)>,
    pub injects: Vec<(String, PathBuf, u16)>, // (guest-path-relative, host, mode)
    pub env_files: Vec<PathBuf>,              // appended to /etc/virtkit/env, in order
    pub free_gib: u64,
    pub buildkit_addr: Option<String>,
    pub buildctl: Option<PathBuf>,
    pub buildkitd: Option<PathBuf>,
    pub ensure_daemon: bool,
    pub force: bool,
    /// Shared bundle registry (Ext4 output only): when set, the build is content
    /// shared across worktrees — pull `<name>:<fingerprint>` instead of building if
    /// present, and push the result after a build. Best-effort (a registry failure
    /// never fails the build). `None` = build locally only.
    pub registry: Option<crate::config::Registry>,
}

/// Drive a [`BuildSpec`] to a bootable ext4. Identical behavior/staleness contract
/// to the former `Cmd::Build` dispatch.
pub fn run(spec: &BuildSpec) -> Result<()> {
    // 1. analyze + hash the target stage -> tag identity.
    let analysis = dockerhash::merge_analyses(&spec.dockerfiles, &[])?;
    let hashes = dockerhash::hash_all(&analysis, &spec.build_args)?;
    let hash = hashes.get(&spec.target).with_context(|| {
        format!(
            "stage '{}' not found in {:?}",
            spec.target, spec.dockerfiles
        )
    })?;
    let tag = format!("{}:{hash}", spec.name);

    // 2. freshness: the fingerprint reflects everything baked into the ext4, not just
    // the agent (see [`fingerprint_hashes`]), vs the image UUID.
    let part_hashes = fingerprint_hashes(spec)?;
    let mut fp_parts: Vec<&str> = vec![tag.as_str()];
    fp_parts.extend(part_hashes.iter().map(String::as_str));
    let uuid = ensure::fingerprint(&fp_parts);
    // ext4 mode only: skip the rebuild when the output already carries this
    // fingerprint (local cache), else try the shared registry before building. Local
    // (artifact export) always rebuilds — there is no ext4 to compare against.
    if let BuildOutput::Ext4(out) = &spec.output
        && !spec.force
    {
        if fleet::fs_uuid(out).as_deref() == Some(uuid.as_str()) {
            println!("virtkit: {tag} fresh ({})", out.display());
            return Ok(());
        }
        // shared registry: a sibling worktree may have built this exact fingerprint —
        // pull it instead of rebuilding. The placed ext4 keeps its UUID (fresh next time).
        if let Some(rg) = &spec.registry {
            match crate::registry::try_pull_ext4(rg, &spec.name, &uuid, out) {
                Ok(true) => {
                    println!(
                        "virtkit: {tag} pulled from shared registry -> {}",
                        out.display()
                    );
                    return Ok(());
                }
                Ok(false) => {}
                Err(e) => eprintln!(
                    "virtkit: shared-registry pull of {}:{uuid} failed ({e:#}); building",
                    spec.name
                ),
            }
        }
    }

    // 3. resolve the daemon tools (also gives us buildctl), then ensure a buildkitd
    // unless told to just dial a given address.
    let bk = buildkit::Buildkit::resolve(spec.buildctl.as_deref(), spec.buildkitd.as_deref())?;
    let buildctl_bin = bk.buildctl.clone();
    let addr = if !spec.ensure_daemon {
        spec.buildkit_addr
            .clone()
            .context("--no-ensure-daemon needs --buildkit-addr")?
    } else if let Some(a) = &spec.buildkit_addr {
        a.clone()
    } else {
        bk.ensure()?
    };

    // 4. project the build args for buildctl.
    let hashes_map: std::collections::HashMap<String, String> =
        hashes.clone().into_iter().collect();
    let proj = dockerhash::build_args_for(&analysis, &hashes_map, &spec.target, &spec.build_args)?;

    // 5. drive buildctl to a temp OCI archive.
    let first = spec.dockerfiles.first().context("no -f Dockerfile")?;
    let df_dir = first.parent().unwrap_or_else(|| Path::new("."));
    let df_name = first
        .file_name()
        .context("Dockerfile path has no file name")?;
    let ctx_dir = &spec.context;

    let mut bc = std::process::Command::new(&buildctl_bin);
    bc.arg("--addr").arg(&addr).arg("build");
    bc.arg("--frontend").arg("dockerfile.v0");
    bc.arg("--local")
        .arg(format!("context={}", ctx_dir.display()));
    bc.arg("--local")
        .arg(format!("dockerfile={}", df_dir.display()));
    bc.arg("--opt")
        .arg(format!("filename={}", df_name.to_string_lossy()));
    bc.arg("--opt").arg(format!("target={}", spec.target));
    for (k, v) in &proj {
        bc.arg("--opt").arg(format!("build-arg:{k}={v}"));
    }
    if !spec.add_hosts.is_empty() {
        // buildkit wants HOST=IP entries comma-joined in one add-hosts opt.
        let hosts = spec
            .add_hosts
            .iter()
            .map(|(h, ip)| format!("{h}={ip}"))
            .collect::<Vec<_>>()
            .join(",");
        bc.arg("--opt").arg(format!("add-hosts={hosts}"));
    }
    for (k, v) in &spec.labels {
        bc.arg("--opt").arg(format!("label:{k}={v}"));
    }

    // Local: export the target stage's rootfs to a host dir and stop — no ext4,
    // no fingerprint. A scratch-final stage yields just the built artifact(s).
    if let BuildOutput::Local(dir) = &spec.output {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        bc.arg("--output")
            .arg(format!("type=local,dest={}", dir.display()));
        eprintln!(
            "virtkit: building {tag} (target {}) -> {} via {addr}",
            spec.target,
            dir.display()
        );
        let st = bc
            .status()
            .with_context(|| format!("running {}", buildctl_bin.display()))?;
        if !st.success() {
            bail!("buildctl build failed ({st})");
        }
        println!("virtkit: exported {tag} rootfs -> {}", dir.display());
        return Ok(());
    }

    // Push: build the target stage and push it to a registry as an OCI image — a
    // normal container image from a Dockerfile, no docker. No ext4.
    if let BuildOutput::Push(reference) = &spec.output {
        bc.arg("--output")
            .arg(format!("type=image,name={reference},push=true"));
        eprintln!(
            "virtkit: building {tag} (target {}) -> push {reference} via {addr}",
            spec.target
        );
        let st = bc
            .status()
            .with_context(|| format!("running {}", buildctl_bin.display()))?;
        if !st.success() {
            bail!("buildctl build/push failed ({st})");
        }
        println!("virtkit: pushed {tag} -> {reference}");
        return Ok(());
    }

    // Load: build the target stage and stream the docker-format archive straight into
    // the local container daemon (`buildctl … --output type=docker | <cli> load`) — a
    // normal local image, no registry, no ext4 (the `--vm`/CI side uses bundles).
    if let BuildOutput::Load(reference) = &spec.output {
        let cli = std::env::var("VIRTKIT_CONTAINER_CLI").unwrap_or_else(|_| "docker".into());
        bc.arg("--output")
            .arg(format!("type=docker,name={reference}"));
        bc.stdout(std::process::Stdio::piped());
        eprintln!(
            "virtkit: building {tag} (target {}) -> {cli} load {reference} via {addr}",
            spec.target
        );
        let mut builder = bc
            .spawn()
            .with_context(|| format!("running {}", buildctl_bin.display()))?;
        let archive = builder.stdout.take().expect("piped buildctl stdout");
        let mut loader = std::process::Command::new(&cli)
            .arg("load")
            .stdin(archive)
            .spawn()
            .with_context(|| format!("running `{cli} load`"))?;
        // wait for both ends; report whichever failed.
        let build_st = builder.wait().context("waiting for buildctl")?;
        let load_st = loader
            .wait()
            .with_context(|| format!("waiting for `{cli} load`"))?;
        if !build_st.success() {
            bail!("buildctl build failed ({build_st})");
        }
        if !load_st.success() {
            bail!("`{cli} load` failed ({load_st})");
        }
        println!("virtkit: built + loaded {tag} -> {reference}");
        return Ok(());
    }

    // 5b. ext4 mode: build to a temp OCI archive, then flatten it. Ext4 and Bundle
    // both flatten to an ext4; Bundle materializes it transiently (a temp file, ideal
    // on tmpfs) and pushes it as a stable tag, keeping no artifact.
    let out_buf = match &spec.output {
        BuildOutput::Ext4(o) => o.clone(),
        BuildOutput::Bundle(_) => bundle_tmp_path(&spec.name),
        _ => unreachable!("Local and Push handled above"),
    };
    let out = &out_buf;
    std::fs::create_dir_all(out.parent().unwrap_or_else(|| Path::new(".")))
        .with_context(|| format!("creating output dir for {}", out.display()))?;
    let tmp_oci = out.with_extension("build.oci");
    let _ = std::fs::remove_file(&tmp_oci);
    bc.arg("--output")
        .arg(format!("type=oci,dest={}", tmp_oci.display()));

    eprintln!(
        "virtkit: building {tag} (target {}) via {addr}",
        spec.target
    );
    let st = bc
        .status()
        .with_context(|| format!("running {}", buildctl_bin.display()))?;
    if !st.success() {
        let _ = std::fs::remove_file(&tmp_oci);
        bail!("buildctl build failed ({st})");
    }

    // 6. OCI archive -> ext4, stamping the fingerprint UUID + name label.
    let fsid = ext4::FsId {
        uuid: crate::parse_uuid(&uuid),
        label: Some(spec.name.clone()),
        with_journal: true,
    };
    let inj: Vec<(&str, &Path, u16)> = spec
        .injects
        .iter()
        .map(|(g, h, m)| (g.as_str(), h.as_path(), *m))
        .collect();
    let free_blocks = spec.free_gib * (1024 * 1024 * 1024 / 4096);
    let r = mkoci::archive_to_ext4(&tmp_oci, out, &inj, &spec.env_files, free_blocks, &fsid);
    let _ = std::fs::remove_file(&tmp_oci);
    r?;

    // Bundle: chunk + upload the ext4 to the [registry] as a stable tag, then drop
    // the transient image. A failed push fails the build (this IS the build product),
    // unlike the best-effort fleet share below.
    if let BuildOutput::Bundle(reference) = &spec.output {
        let boot_kind = crate::image::boot_kind_tag(crate::image::BootKind::GenericDisk);
        let r = push_bundle(spec, reference, out, boot_kind);
        let _ = std::fs::remove_file(out); // transient — never kept
        r?;
        return Ok(());
    }

    println!("virtkit: built {tag} -> {} (uuid {uuid})", out.display());

    // shared registry: publish the freshly built bundle so sibling worktrees can pull
    // it. Best-effort — a registry hiccup must not fail an otherwise-good build.
    if let Some(rg) = &spec.registry {
        let boot_kind = crate::image::boot_kind_tag(crate::image::BootKind::GenericDisk);
        match crate::registry::push_ext4(rg, &spec.name, &uuid, out, boot_kind) {
            Ok(()) => println!(
                "virtkit: pushed {}:{uuid} to the shared registry",
                spec.name
            ),
            Err(e) => eprintln!(
                "virtkit: shared-registry push of {}:{uuid} failed ({e:#}) — built locally",
                spec.name
            ),
        }
    }
    Ok(())
}

/// Push a freshly built ext4 to the `[registry]` as the stable bundle `<name>:<tag>`
/// (the fused build → bundle path). The reference must carry a `:tag`.
fn push_bundle(spec: &BuildSpec, reference: &str, ext4: &Path, boot_kind: &str) -> Result<()> {
    let rg = spec
        .registry
        .as_ref()
        .context("--push-bundle needs a [registry] section in the host config")?;
    let (name, refr) = crate::image::parse_ref(reference)?;
    let tag = match refr {
        crate::image::Reference::Tag(t) => t,
        crate::image::Reference::Digest(_) => {
            bail!("--push-bundle needs a :tag, not an @digest ({reference:?})")
        }
    };
    crate::registry::push_ext4(rg, &name, &tag, ext4, boot_kind)?;
    println!("virtkit: built + pushed bundle {name}:{tag}");
    Ok(())
}

/// A transient ext4 path for a `--push-bundle` build: under the system temp dir
/// (point `TMPDIR` at tmpfs to keep it in RAM), name-sanitized + pid-scoped so
/// concurrent builds don't collide.
fn bundle_tmp_path(name: &str) -> PathBuf {
    let safe = name.replace(['/', '\\', ':'], "_");
    std::env::temp_dir().join(format!("virtkit-bundle-{safe}-{}.ext4", std::process::id()))
}

/// The fingerprint parts (after the tag) for a spec: each inject's host-file sha256
/// sorted by guest path, then each env-file's sha256 in order. This reflects
/// everything baked into the ext4. For a unit whose only inject is the agent and with
/// no env-files (the services), this is exactly `[sha256(agent)]`, so prepending the
/// tag yields `[tag, sha256(agent)]` and existing service ext4s stay fresh.
fn fingerprint_hashes(spec: &BuildSpec) -> Result<Vec<String>> {
    let mut injects_sorted: Vec<&(String, PathBuf, u16)> = spec.injects.iter().collect();
    injects_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut parts: Vec<String> = Vec::with_capacity(injects_sorted.len() + spec.env_files.len());
    for (_, host, _) in injects_sorted {
        parts.push(sha256_file(host)?);
    }
    for ef in &spec.env_files {
        parts.push(sha256_file(ef)?);
    }
    Ok(parts)
}

/// sha256 hex of a host file's contents (a fingerprint part).
fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let d = Sha256::digest(&bytes);
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_tmp_path_is_a_single_safe_component() {
        // a repo-qualified name must not leak path separators into the temp path
        let p = bundle_tmp_path("common/ci-bundles/appbuilder");
        let file = p.file_name().unwrap().to_str().unwrap();
        assert!(file.starts_with("virtkit-bundle-"));
        assert!(file.ends_with(".ext4"));
        assert!(!file.contains('/') && !file.contains('\\') && !file.contains(':'));
        // it lands under the system temp dir, not the cwd
        assert_eq!(p.parent().unwrap(), std::env::temp_dir());
    }

    fn spec_with(injects: Vec<(String, PathBuf, u16)>, env_files: Vec<PathBuf>) -> BuildSpec {
        BuildSpec {
            dockerfiles: vec![],
            context: PathBuf::from("."),
            target: String::new(),
            name: String::new(),
            output: BuildOutput::Ext4(PathBuf::from("out.ext4")),
            build_args: BTreeMap::new(),
            add_hosts: vec![],
            labels: vec![],
            injects,
            env_files,
            free_gib: 0,
            buildkit_addr: None,
            buildctl: None,
            buildkitd: None,
            ensure_daemon: true,
            force: false,
            registry: None,
        }
    }

    // A unit whose only inject is the agent and with no env-files (the services) must
    // fingerprint to exactly [tag, sha256(agent)] — the same value as before this
    // generalization — so existing service ext4s stay fresh.
    #[test]
    fn agent_only_fingerprint_matches_legacy() {
        let dir = std::env::temp_dir().join(format!("virtkit-fp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let agent = dir.join("virtkit-agent");
        std::fs::write(&agent, b"fake agent bytes").unwrap();

        let spec = spec_with(
            vec![(
                "usr/local/bin/virtkit-agent".to_string(),
                agent.clone(),
                0o755,
            )],
            vec![],
        );

        let agent_sha = sha256_file(&agent).unwrap();
        // legacy recipe: [tag, sha256(agent)]
        let tag = "appmysql-bookworm:abc123";
        let legacy = ensure::fingerprint(&[tag, agent_sha.as_str()]);

        let part_hashes = fingerprint_hashes(&spec).unwrap();
        let mut parts: Vec<&str> = vec![tag];
        parts.extend(part_hashes.iter().map(String::as_str));
        let got = ensure::fingerprint(&parts);

        assert_eq!(part_hashes, vec![agent_sha]);
        assert_eq!(got, legacy);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
