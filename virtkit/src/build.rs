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

/// A resolved build request: the CLI layer (and `fleet`) parse their flags into
/// this, then call [`run`]. Paths/args carry no further parsing.
pub struct BuildSpec {
    pub dockerfiles: Vec<PathBuf>,
    pub context: PathBuf,
    pub target: String,
    pub name: String,
    pub out: PathBuf,
    pub build_args: BTreeMap<String, String>,
    pub add_hosts: Vec<(String, String)>, // (host, ip)
    pub labels: Vec<(String, String)>,
    pub injects: Vec<(String, PathBuf, u16)>, // (guest-path-relative, host, mode)
    pub free_gib: u64,
    pub buildkit_addr: Option<String>,
    pub buildctl: Option<PathBuf>,
    pub buildkitd: Option<PathBuf>,
    pub ensure_daemon: bool,
    pub force: bool,
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

    // 2. freshness: fingerprint = [tag, sha256(injected agent)] vs the image UUID.
    let agent_hash = spec
        .injects
        .iter()
        .find(|(g, _, _)| g == "usr/local/bin/virtkit-agent")
        .map(|(_, h, _)| sha256_file(h))
        .transpose()?;
    let mut fp_parts: Vec<&str> = vec![tag.as_str()];
    if let Some(h) = &agent_hash {
        fp_parts.push(h.as_str());
    }
    let uuid = ensure::fingerprint(&fp_parts);
    if !spec.force && fleet::fs_uuid(&spec.out).as_deref() == Some(uuid.as_str()) {
        println!("virtkit: {tag} fresh ({})", spec.out.display());
        return Ok(());
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

    std::fs::create_dir_all(spec.out.parent().unwrap_or_else(|| Path::new(".")))
        .with_context(|| format!("creating output dir for {}", spec.out.display()))?;
    let tmp_oci = spec.out.with_extension("build.oci");
    let _ = std::fs::remove_file(&tmp_oci);

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
    let r = mkoci::archive_to_ext4(&tmp_oci, &spec.out, &inj, free_blocks, &fsid);
    let _ = std::fs::remove_file(&tmp_oci);
    r?;
    println!(
        "virtkit: built {tag} -> {} (uuid {uuid})",
        spec.out.display()
    );
    Ok(())
}

/// sha256 hex of a host file's contents (the agent fingerprint part).
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
