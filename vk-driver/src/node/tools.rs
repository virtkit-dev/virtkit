//! Build and install the CI tools requested by [`vk_hub_proto::Operation::Tools`]: download
//! the build context packed by the hub, build its `tools` stage with `vk build`, validate
//! the tools, and switch `<state_dir>/tools/current`, which `[executor] tools_dir` names.
//!
//! A child `vk build` runs with `--cache-registry none`, so it neither reads nor writes the
//! node's instruction cache, local or shared through `vk-registry`. `XDG_CACHE_HOME` and
//! `XDG_DATA_HOME` point into its scratch directory; removing it afterwards removes anything
//! else the build stores there. The build uses the node's `[build]` settings, runs one stage
//! at a time (`--build-jobs 1`), and has [`BUILD_TIMEOUT`] to finish.
//!
//! Its RUN steps reach only what each stage of the definition declares (`# vk: allow-ip=…
//! allow-name=…` above its `FROM`), within the node's `[egress.build]`: a stage that declares
//! nothing has no network. What they contacted and were refused is kept in the manifest of
//! the tools installed, and said with the failure of a build that fails.
//!
//! The stage is exported as raw ext4. [`crate::ext4_read`] reads its root in-process:
//! regular files and symlinks to regular files beside them (`git-remote-https` →
//! `git-remote-http`). Directories such as `lost+found` are skipped.
//!
//! [`vk_hub_proto::REQUIRED_TOOLS`] must be static x86-64 ELF executables, so they run
//! regardless of the guest image's libc. Host `--version` probes run only when the node
//! accepts unsigned releases, which already lets its hub run arbitrary code on the host.
//! Nodes requiring signed releases run the tools only in job VMs and report no versions.
//!
//! Tools are installed in `<state_dir>/tools/<sha256>/` (directory and files `0755`), with
//! a `<sha256>.json` manifest beside it recording each file's sha256 and each link's target.
//! Renaming a new link over `current` switches tools for future jobs. Each job keeps the
//! directory it resolves at startup ([`crate::vm`]), and is not given tools that are no longer
//! what their manifest records ([`for_job`]); the inventory says whether they still are, so
//! the hub has them installed again. The previous tools remain available; older ones are
//! removed unless a job directory's `tools.root` still names them.
//!
//! One build runs at a time in the background, without interrupting the session. After a
//! node stops, its next start restarts the build from the beginning.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use vk_hub_proto::{ToolsCheck, ToolsEgress, ToolsFile, ToolsInstalled, ToolsPhase};

use super::core::Core;
use super::session::Node;
use super::state::ToolsJob;
use crate::config::Config;

/// Under the state dir: the tools built, their manifests, and [`CURRENT`].
const TOOLS_DIR: &str = "tools";

/// The link `[executor] tools_dir` names.
const CURRENT: &str = "current";

/// The file at a definition's root that a node builds.
const DOCKERFILE: &str = "Dockerfile";

/// The stage a definition's Dockerfile must have, holding the tools at its root.
const TARGET: &str = "tools";

/// How long a build may take: a static git compiled from source is minutes.
const BUILD_TIMEOUT: Duration = Duration::from_secs(3600);

/// How long a download may take in all.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long to wait before ending a build again when the node's state could not be saved.
const SAVE_RETRY: Duration = Duration::from_secs(30);

/// How long a tool has to print its `--version`, and the most of it read.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_MAX: u64 = 4096;

/// The tools whose `--version` is reported.
const PROBED: [&str; 3] = ["git", "git-lfs", "gitlab-runner"];

/// The most files a tools stage's root may hold, and the largest one.
const MAX_FILES: usize = vk_hub_proto::MAX_TOOLS_FILES;
const MAX_TOOL: u64 = 256 << 20;

/// The most entries a definition's tar may hold.
const MAX_ENTRIES: usize = 4096;

/// `<state_dir>/tools`.
fn root(cfg: &Config) -> PathBuf {
    cfg.state_dir().join(TOOLS_DIR)
}

/// The link `[executor] tools_dir` names to give jobs the tools installed here, current or not.
pub fn current_path(cfg: &Config) -> PathBuf {
    root(cfg).join(CURRENT)
}

/// What is kept beside an installed tools directory, `<sha256>.json`.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    version: String,
    #[serde(default)]
    tools: BTreeMap<String, String>,
    /// What the build that made them reached and was refused.
    #[serde(default)]
    egress: ToolsEgress,
    /// Each entry installed, by name, as it was installed. Empty from a `vk` that recorded none.
    #[serde(default)]
    files: BTreeMap<String, ToolsFile>,
}

/// The most hosts a failed build's message names as refused.
const REFUSED_SHOWN: usize = 16;

/// Under a build's home: where its `vk build` records its egress.
const EGRESS_RECORD: &str = "egress";

/// What the build whose home is `home` recorded of its egress: every stage's, from every build
/// directory `vk build` made under [`EGRESS_RECORD`].
fn build_egress(home: &Path) -> ToolsEgress {
    let mut contacted = std::collections::BTreeSet::new();
    let mut refused = std::collections::BTreeSet::new();
    let Ok(dirs) = std::fs::read_dir(home.join(EGRESS_RECORD)) else {
        return ToolsEgress::default();
    };
    for dir in dirs.flatten() {
        let dir = dir.path();
        let audit = dir.join(crate::run::AUDIT_LOG);
        let contacts = crate::egress_report::read_contacts(&audit)
            .into_iter()
            .chain(crate::egress_report::read_ip_contacts(&audit));
        contacted.extend(contacts.map(|(target, _)| target));
        let denied = crate::jobctx::JobCtx::egress_denied_log_in(&dir);
        let (denials, _) = crate::egress_report::read_records_since(&denied, 0);
        refused.extend(denials.into_iter().map(|(d, _)| d.target));
    }
    ToolsEgress {
        contacted: contacted.into_iter().collect(),
        refused: refused.into_iter().collect(),
    }
}

/// How the tools build's RUN steps reach the network: only as each stage declares, and within
/// the node's `[egress.build]` where it sets one; not at all where that allows nothing.
fn build_net_args(cfg: &Config) -> Vec<String> {
    let build = &cfg.egress.build;
    if build.allow_ip.is_none() && build.allow_name.is_none() {
        return vec!["--build-net".into(), "declared".into()];
    }
    let ips = build.allow_ip.as_deref().unwrap_or_default();
    let names = build.allow_name.as_deref().unwrap_or_default();
    // No flags would read as no cap at all.
    if ips.is_empty() && names.is_empty() {
        return vec!["--build-net".into(), "none".into()];
    }
    let mut args = vec!["--build-net".into(), "declared".into()];
    for ip in ips {
        args.extend(["--build-allow-ip".into(), ip.clone()]);
    }
    for name in names {
        args.extend(["--build-allow-name".into(), name.clone()]);
    }
    args
}

fn manifest_path(root: &Path, sha256: &str) -> PathBuf {
    root.join(format!("{sha256}.json"))
}

fn read_manifest(root: &Path, sha256: &str) -> Option<Manifest> {
    let bytes = std::fs::read(manifest_path(root, sha256)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The definition [`CURRENT`] names, when it names one.
fn current(root: &Path) -> Option<String> {
    let target = std::fs::read_link(root.join(CURRENT)).ok()?;
    let name = target.to_str()?;
    vk_hub_proto::valid_sha256(name).then(|| name.to_string())
}

/// Whether the tools of `sha256` are installed whole and as recorded: their directory, and
/// its manifest, which is written first, recording what the directory holds. Tools a `vk`
/// that recorded nothing installed are built again.
fn installed_here(root: &Path, sha256: &str) -> bool {
    std::fs::symlink_metadata(root.join(sha256)).is_ok_and(|m| m.is_dir())
        && read_manifest(root, sha256)
            .is_some_and(|m| check(&root.join(sha256), &m) == ToolsCheck::Intact)
}

/// The tools [`CURRENT`] names, as the inventory reports them, checked against their
/// manifest.
pub fn installed(cfg: &Config) -> Option<ToolsInstalled> {
    let root = root(cfg);
    let sha256 = current(&root)?;
    let manifest = read_manifest(&root, &sha256)?;
    let check = check(&root.join(&sha256), &manifest);
    let cut = |mut hosts: Vec<String>| {
        hosts.truncate(vk_hub_proto::MAX_TOOLS_EGRESS_HOSTS);
        hosts
    };
    Some(ToolsInstalled {
        sha256,
        version: manifest.version,
        tools: manifest.tools,
        in_use: in_use(cfg),
        files: manifest.files,
        egress: Some(ToolsEgress {
            contacted: cut(manifest.egress.contacted),
            refused: cut(manifest.egress.refused),
        }),
        check: Some(check),
    })
}

/// `dir` against `manifest`: [`ToolsCheck::Modified`] names each entry it records that is
/// missing, of another kind or mode, or holds other contents or another link, and each entry
/// it does not record.
fn check(dir: &Path, manifest: &Manifest) -> ToolsCheck {
    if manifest.files.is_empty() {
        return ToolsCheck::Unrecorded;
    }
    let mut entries = std::collections::BTreeSet::new();
    match std::fs::read_dir(dir) {
        Ok(listing) => {
            for entry in listing {
                let Ok(entry) = entry else {
                    // Unreadable: nothing in it can be vouched for.
                    entries.extend(manifest.files.keys().cloned());
                    break;
                };
                let name = entry.file_name().to_string_lossy().into_owned();
                if !manifest.files.contains_key(&name) {
                    entries.insert(name);
                }
            }
        }
        Err(_) => entries.extend(manifest.files.keys().cloned()),
    }
    for (name, recorded) in &manifest.files {
        // Only a plain name is one installed.
        let plain = !name.is_empty() && !name.contains('/') && name != "." && name != "..";
        if !plain || !entry_is(&dir.join(name), recorded) {
            entries.insert(name.clone());
        }
    }
    if entries.is_empty() {
        ToolsCheck::Intact
    } else {
        ToolsCheck::Modified {
            entries: entries.into_iter().collect(),
        }
    }
}

/// Whether `path` is what `recorded` says: the same link, or a regular file `0755` with the
/// same contents.
fn entry_is(path: &Path, recorded: &ToolsFile) -> bool {
    match recorded {
        ToolsFile::Link { target } => {
            std::fs::read_link(path).is_ok_and(|t| t.as_os_str() == target.as_str())
        }
        ToolsFile::File { sha256, size } => {
            let Ok(file) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
            else {
                return false;
            };
            let Ok(meta) = file.metadata() else {
                return false;
            };
            if !meta.is_file() || meta.permissions().mode() & 0o7777 != 0o755 || meta.len() != *size
            {
                return false;
            }
            let mut hasher = Sha256::new();
            let (mut file, mut read, mut buf) = (file.take(*size + 1), 0u64, vec![0u8; 1 << 16]);
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        hasher.update(&buf[..n]);
                        read += n as u64;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return false,
                }
            }
            read == *size && vk_hub_proto::to_hex(&hasher.finalize()) == *sha256
        }
    }
}

/// Before a job is given the tools directory `dir` (resolved, as its boot shares it): when it
/// is tools this node installed for its hub, refuse them unless they are what their manifest
/// records. Others are the operator's, and given as they are; tools a `vk` that recorded
/// nothing installed are given unchecked.
pub fn for_job(cfg: &Config, dir: &Path) -> Result<()> {
    let Some(sha256) = dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| vk_hub_proto::valid_sha256(n))
    else {
        return Ok(());
    };
    let Ok(root) = std::fs::canonicalize(root(cfg)) else {
        return Ok(());
    };
    if dir.parent() != Some(root.as_path()) {
        return Ok(());
    }
    let short = sha256.get(..12).unwrap_or(sha256);
    let Some(manifest) = read_manifest(&root, sha256) else {
        bail!("this node's CI tools {short} are not installed whole, so no job is given them");
    };
    match check(dir, &manifest) {
        ToolsCheck::Intact | ToolsCheck::Unrecorded => Ok(()),
        ToolsCheck::Modified { entries } => bail!(
            "this node's CI tools {} ({short}) have changed since they were installed ({}), so \
             no job is given them until they are installed again",
            manifest.version,
            entries.join(", ")
        ),
    }
}

/// Whether `[executor] tools_dir` is `<state_dir>/tools/current` itself — the same entry,
/// not only where it leads now, so jobs follow the next switch too.
fn in_use(cfg: &Config) -> bool {
    let Some(dir) = &cfg.executor.tools_dir else {
        return false;
    };
    // Rebuilt from its components: a trailing slash would have the kernel follow the link.
    let dir: PathBuf = dir.components().collect();
    let id = |p: &Path| {
        std::fs::symlink_metadata(p)
            .ok()
            .map(|m| (m.dev(), m.ino()))
    };
    let ours = id(&root(cfg).join(CURRENT));
    ours.is_some() && id(&dir) == ours
}

/// What `vk node run` and `vk check` say when the hub's tools are installed but jobs are
/// given others.
pub fn unused_warning(cfg: &Config) -> Option<String> {
    let installed = installed(cfg).filter(|t| !t.in_use)?;
    Some(format!(
        "the CI tools the hub had this node build ({}, {}) are not what jobs get: set \
         [executor] tools_dir = \"{}\"",
        installed.version,
        installed.sha256.get(..12).unwrap_or(&installed.sha256),
        root(cfg).join(CURRENT).display()
    ))
}

/// Why a build failed, and the end of what it printed.
#[derive(Debug)]
struct Failed {
    message: String,
    log: Vec<String>,
}

impl From<anyhow::Error> for Failed {
    fn from(e: anyhow::Error) -> Self {
        Failed {
            message: format!("{e:#}"),
            log: Vec::new(),
        }
    }
}

/// A build's future.
type Building<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// How a definition's `tools` stage becomes an ext4: `context` is the unpacked definition,
/// `out` the ext4 to write, `home` a directory for whatever the build keeps, `log` where
/// its output goes.
type Build = for<'a> fn(&'a Config, &'a Path, &'a Path, &'a Path, &'a Path) -> Building<'a>;

/// Follow the node's state and carry out a tools build as one comes. Runs until `stop`; a
/// build cut short by it is taken up again by the next `vk node run`.
pub async fn maintain(
    core: Arc<Core>,
    cfg: Arc<Config>,
    node: Arc<Node>,
    stop: watch::Receiver<bool>,
) {
    let (core, cfg, node) = (&*core, &*cfg, &*node);
    let work = |job: ToolsJob| async move {
        let probe = !core.release_policy().required();
        let download = |tar: PathBuf| {
            let job = &job;
            async move {
                let fetch = super::update::Fetch {
                    kind: super::update::Kind::Tools,
                    sha256: &job.sha256,
                    size: job.size.min(vk_hub_proto::MAX_TOOLS_DEFINITION),
                    mode: 0o600,
                };
                super::update::download(node, &fetch, &tar).await
            }
        };
        run(core, cfg, &job, download, vk_build, probe).await
    };
    follow(core, cfg, stop, SAVE_RETRY, work).await;
}

/// [`maintain`], with `work` carrying out a build, and `retry` how long to wait before
/// ending a build again when the state could not be saved.
async fn follow<F>(
    core: &Core,
    cfg: &Config,
    mut stop: watch::Receiver<bool>,
    retry: Duration,
    work: impl Fn(ToolsJob) -> F,
) where
    F: Future<Output = Result<(), Failed>>,
{
    let mut changes = core.subscribe();
    loop {
        changes.borrow_and_update();
        if let Some(job) = core.persisted().tools {
            let (version, sha256) = (job.version.clone(), job.sha256.clone());
            let failed = tokio::select! {
                outcome = work(job) => outcome.err(),
                () = super::session::stopped(&mut stop) => return,
            };
            match &failed {
                None => {
                    say!("CI tools {version} ({sha256}) are current");
                    if let Some(warning) = unused_warning(cfg) {
                        say!("warning: {warning}");
                    }
                }
                Some(f) => say!("the tools build failed: {}", f.message),
            }
            if let Err(e) = core.change(|p| p.end_tools(failed.map(|f| (f.message, f.log)))) {
                // The build is still under way as far as the state goes: it is run again,
                // after `retry` rather than at once. Installed already, it is only switched to.
                say!("{e:#}");
                tokio::select! {
                    () = tokio::time::sleep(retry) => {}
                    () = super::session::stopped(&mut stop) => return,
                }
            }
            continue;
        }
        tokio::select! {
            _ = changes.changed() => {}
            () = super::session::stopped(&mut stop) => return,
        }
    }
}

/// [`install`] `job`'s definition, first fetching it into the tools dir with `download`
/// unless it is installed already.
async fn run<D>(
    core: &Core,
    cfg: &Config,
    job: &ToolsJob,
    download: impl FnOnce(PathBuf) -> D,
    build: Build,
    probe: bool,
) -> Result<(), Failed>
where
    D: Future<Output = Result<()>>,
{
    // Checked before any path is built of it.
    vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SHA256_LEN }>(&job.sha256)
        .with_context(|| format!("the tools' sha256 {:?} is not valid", job.sha256))?;
    // Absolute: the build and the version probe run in directories of their own.
    let state = std::path::absolute(cfg.state_dir())
        .with_context(|| format!("resolving {}", cfg.state_dir().display()))?;
    let root = state.join(TOOLS_DIR);
    let tar = blocking({
        let root = root.clone();
        let sha256 = job.sha256.clone();
        let jobs = state.join("jobs");
        move || {
            prepare_root(&root, &jobs)?;
            Ok(root.join(format!(".{sha256}.tar")))
        }
    })
    .await?;
    let phase = |phase| {
        // What is reported, not what is done: a failure to save it is the next change's.
        if let Err(e) = core.change(|p| p.tools_phase(phase)) {
            say!("{e:#}");
        }
    };
    if !installed_here(&root, &job.sha256) {
        // The phase saved may be a later one, from a build a stop cut short.
        phase(ToolsPhase::Downloading);
        say!("downloading CI tools {} ({})", job.version, job.sha256);
        tokio::time::timeout(DOWNLOAD_TIMEOUT, download(tar.clone()))
            .await
            .map_err(|_| anyhow!("the download took longer than {DOWNLOAD_TIMEOUT:?}"))??;
    }
    let jobs = state.join("jobs");
    install(cfg, &root, &jobs, job, &tar, build, probe, &phase).await
}

/// Build `job`'s definition from `tar` and make the tools current, unless they are installed
/// already, in which case they are only made current; `tar` is removed either way. Their
/// `--version` is read on this host only with `probe`. `phase` hears each phase as it
/// starts. A tools directory a job dir under `jobs` names is never removed.
#[allow(clippy::too_many_arguments)]
async fn install(
    cfg: &Config,
    root: &Path,
    jobs: &Path,
    job: &ToolsJob,
    tar: &Path,
    build: Build,
    probe: bool,
    phase: &(dyn Fn(ToolsPhase) + Sync),
) -> Result<(), Failed> {
    let sha256 = job.sha256.clone();
    let scratch = root.join(format!(".build-{sha256}"));
    let outcome = async {
        if !installed_here(root, &sha256) {
            phase(ToolsPhase::Building);
            let context = scratch.join("context");
            let (out, home, log) = (
                scratch.join("tools.ext4"),
                scratch.join("home"),
                scratch.join("build.log"),
            );
            blocking({
                let (scratch, context, tar) = (scratch.clone(), context.clone(), tar.to_path_buf());
                move || {
                    private_dir(&scratch)?;
                    private_dir(&context)?;
                    unpack(&tar, &context)
                }
            })
            .await?;
            say!("building CI tools {} ({sha256})", job.version);
            let built =
                tokio::time::timeout(BUILD_TIMEOUT, build(cfg, &context, &out, &home, &log))
                    .await
                    .unwrap_or_else(|_| {
                        Err(anyhow!("the build took longer than {BUILD_TIMEOUT:?}"))
                    });
            let egress = blocking({
                let home = home.clone();
                move || Ok(build_egress(&home))
            })
            .await?;
            if let Err(e) = built {
                let mut message = format!("{e:#}");
                if !egress.refused.is_empty() {
                    let shown = &egress.refused[..egress.refused.len().min(REFUSED_SHOWN)];
                    message.push_str(&format!(
                        "; its network access was refused to {}",
                        shown.join(", ")
                    ));
                    if egress.refused.len() > shown.len() {
                        message
                            .push_str(&format!(" and {} more", egress.refused.len() - shown.len()));
                    }
                }
                return Err(Failed {
                    message,
                    log: tail(&log, vk_hub_proto::MAX_TOOLS_LOG_LINES),
                });
            }
            phase(ToolsPhase::Installing);
            let stage = root.join(format!(".stage-{sha256}"));
            let files = blocking({
                let (out, stage) = (out.clone(), stage.clone());
                move || {
                    let files = extract(&out, &stage)?;
                    check_stage(&stage)?;
                    Ok(files)
                }
            })
            .await?;
            let tools = if probe {
                probe_versions(&stage).await
            } else {
                BTreeMap::new()
            };
            let manifest = Manifest {
                version: job.version.clone(),
                tools,
                egress,
                files,
            };
            blocking({
                let (root, jobs, sha256) = (root.to_path_buf(), jobs.to_path_buf(), sha256.clone());
                move || publish(&root, &sha256, &stage, &manifest, &jobs)
            })
            .await?;
        } else {
            phase(ToolsPhase::Installing);
        }
        blocking({
            let (root, jobs, sha256) = (root.to_path_buf(), jobs.to_path_buf(), sha256.clone());
            move || {
                let previous = switch(&root, &sha256)?;
                let mut keep = vec![sha256];
                keep.extend(previous);
                prune(&root, &keep, &jobs);
                Ok(())
            }
        })
        .await?;
        Ok(())
    }
    .await;
    // Best effort: what is left is swept as the next build starts. A stage published is
    // gone from its name already.
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(root.join(format!(".stage-{sha256}")));
    let _ = std::fs::remove_file(tar);
    outcome
}

/// Run `f` off the runtime: unpacking, extracting and hashing tens of megabytes.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .context("running a file operation")?
}

/// Create the tools directory if it is not there, and remove what a build cut short left in
/// it: every name starting with `.`, but tools [`publish`] moved aside while a job dir under
/// `jobs` names tools of their name. One build runs at a time, under the node's lock.
fn prepare_root(root: &Path, jobs: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(root)
        .with_context(|| format!("creating {}", root.display()))?;
    for entry in std::fs::read_dir(root).with_context(|| format!("listing {}", root.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.as_encoded_bytes();
        if !name.starts_with(b".") {
            continue;
        }
        let replaced = name
            .strip_prefix(b".gone-")
            .and_then(|rest| rest.get(..vk_hub_proto::SHA256_LEN * 2 + 1))
            .and_then(|rest| rest.strip_suffix(b"-"))
            .and_then(|sha| std::str::from_utf8(sha).ok());
        if replaced.is_some_and(|sha| named_by_jobs(jobs, sha)) {
            continue;
        }
        // Best effort: a leftover costs space, not correctness.
        let _ = match entry.file_type() {
            Ok(t) if t.is_dir() => std::fs::remove_dir_all(entry.path()),
            _ => std::fs::remove_file(entry.path()),
        };
    }
    Ok(())
}

/// A new directory only this user can enter.
fn private_dir(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Unpack the definition `tar` into the empty directory `dest`: regular files and
/// directories at plain relative paths, nothing else. They take the modes `docker build`
/// gives a context, which `COPY` keeps: `0755` directories, files `0755` when executable
/// and `0644` otherwise; the scratch directory above keeps them private.
fn unpack(tar: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(tar).with_context(|| format!("opening {}", tar.display()))?;
    let mut archive = tar::Archive::new(file);
    let mut count = 0usize;
    for entry in archive.entries().context("reading the definition")? {
        let mut entry = entry.context("reading the definition")?;
        count = count.saturating_add(1);
        if count > MAX_ENTRIES {
            bail!("the definition holds more than {MAX_ENTRIES} entries");
        }
        let path = entry.path().context("reading a path")?.into_owned();
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            bail!(
                "the definition holds {}, which is not a plain relative path",
                path.display()
            );
        }
        let to = dest.join(&path);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(&to)
                .with_context(|| format!("creating {}", to.display()))?;
            continue;
        }
        if !kind.is_file() {
            bail!(
                "the definition holds {}, which is neither a file nor a directory",
                path.display()
            );
        }
        if let Some(parent) = to.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let executable = entry.header().mode().is_ok_and(|m| m & 0o111 != 0);
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if executable { 0o755 } else { 0o644 })
            .open(&to)
            .with_context(|| format!("creating {}", to.display()))?;
        std::io::copy(&mut entry, &mut out).with_context(|| format!("writing {}", to.display()))?;
    }
    Ok(())
}

/// `vk build` of the context's `tools` stage, as a child process of this very binary, apart
/// from the node's build cache. Only its cache and data dirs are its own: it loads this
/// node's config, whose state dir holds the enrollment and the registry access the hub issued,
/// so its base images on the hub's registry are pulled with the node's token, while
/// `--cache-registry none` keeps it from caching anywhere.
fn vk_build<'a>(
    cfg: &'a Config,
    context: &'a Path,
    out: &'a Path,
    home: &'a Path,
    log: &'a Path,
) -> Building<'a> {
    Box::pin(async move {
        let log_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(log)
            .with_context(|| format!("creating {}", log.display()))?;
        // The running binary itself, whatever has been put at its path since.
        let mut cmd = tokio::process::Command::new("/proc/self/exe");
        if let Some(source) = &cfg.source {
            // As given, it may be relative to this process's directory, not the child's.
            let source = std::path::absolute(source)
                .with_context(|| format!("resolving {}", source.display()))?;
            cmd.arg("--config").arg(source);
        }
        cmd.arg("build")
            .arg("--file")
            .arg(context.join(DOCKERFILE))
            .arg("--context")
            .arg(context)
            .args(["--target", TARGET, "--out"])
            .arg(out)
            .args([
                "--no-journal",
                "--cache-registry",
                "none",
                "--build-jobs",
                "1",
            ])
            .args(build_net_args(cfg))
            .arg("--egress-record")
            .arg(home.join(EGRESS_RECORD))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_DATA_HOME", home.join("data"))
            .current_dir(context)
            .stdin(std::process::Stdio::null())
            .stdout(log_file.try_clone().context("opening the build log")?)
            .stderr(log_file)
            .process_group(0)
            .kill_on_drop(true);
        let mut child = cmd.spawn().context("starting vk build")?;
        // Dropped with this future, cut short by the timeout or a stop: the whole group goes.
        let mut group = super::update::KillGroup(child.id().and_then(|p| i32::try_from(p).ok()));
        let status = child.wait().await.context("waiting for vk build")?;
        end_group(&mut group);
        if !status.success() {
            bail!("vk build failed ({status})");
        }
        Ok(())
    })
}

/// Kill what is left of `group` once its leader is reaped, and disarm it. Done at once: while a
/// member lives the id cannot be taken by another group, but once the last is gone it can,
/// and a kill held until the guard drops could reach that other group.
fn end_group(group: &mut super::update::KillGroup) {
    if let Some(pgid) = group.0.take() {
        // SAFETY: a kill of the group the child led, `process_group(0)`. ESRCH, no member
        // left, is the usual outcome and is nothing to report.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
}

/// The last `lines` lines of `log`, made fit to show.
fn tail(log: &Path, lines: usize) -> Vec<String> {
    const READ: u64 = 64 * 1024;
    let Ok(file) = std::fs::File::open(log) else {
        return Vec::new();
    };
    let len = file.metadata().map_or(0, |m| m.len());
    let from = len.saturating_sub(READ);
    let mut buf = vec![0u8; usize::try_from(len - from).unwrap_or(0)];
    if file.read_exact_at(&mut buf, from).is_err() {
        return Vec::new();
    }
    // Shown to an operator, not kept: lossy is enough.
    let text = String::from_utf8_lossy(&buf);
    let all: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .collect();
    all.iter()
        .skip(all.len().saturating_sub(lines))
        .map(|l| vk_hub_proto::display_safe(l))
        .collect()
}

/// Copy the root of the ext4 `image` into the new directory `stage`: its regular files, and
/// its symlinks to a regular file beside them, all `0755`. The directory is `0755` once
/// filled. Returns what it holds, each file with its sha256.
fn extract(image: &Path, stage: &Path) -> Result<BTreeMap<String, ToolsFile>> {
    use crate::ext4_read::{Ext4Reader, FileType};
    let fs = Ext4Reader::open(image).with_context(|| format!("reading {}", image.display()))?;
    let mut entries = fs.list_dir("/").context("listing the tools stage")?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if entries.len() > MAX_FILES {
        bail!("the tools stage holds more than {MAX_FILES} entries at its root");
    }
    private_dir(stage)?;
    let mut files = BTreeMap::new();
    let regular = |name: &str| {
        entries
            .iter()
            .any(|(n, t)| n == name && *t == FileType::Regular)
    };
    for (name, kind) in &entries {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            bail!("the tools stage holds an entry named {name:?}");
        }
        let to = stage.join(name);
        match kind {
            FileType::Regular => {
                let data = fs
                    .read_file(&format!("/{name}"), MAX_TOOL)
                    .with_context(|| format!("reading {name} from the tools stage"))?;
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o700)
                    .open(&to)
                    .with_context(|| format!("creating {}", to.display()))?;
                file.write_all_at(&data, 0)
                    .with_context(|| format!("writing {}", to.display()))?;
                // Still private to this user in the stage directory: set whatever the umask.
                file.set_permissions(std::fs::Permissions::from_mode(0o755))
                    .with_context(|| format!("setting the mode on {}", to.display()))?;
                file.sync_all()
                    .with_context(|| format!("flushing {}", to.display()))?;
                files.insert(
                    name.clone(),
                    ToolsFile::File {
                        sha256: vk_hub_proto::to_hex(&Sha256::digest(&data)),
                        size: data.len() as u64,
                    },
                );
            }
            FileType::Symlink => {
                let target = fs
                    .read_link(&format!("/{name}"))
                    .with_context(|| format!("reading the link {name}"))?;
                if target.contains('/') || !regular(&target) {
                    bail!(
                        "{name} in the tools stage links to {target:?}: a link must name a file \
                         beside it"
                    );
                }
                std::os::unix::fs::symlink(&target, &to)
                    .with_context(|| format!("creating {}", to.display()))?;
                files.insert(name.clone(), ToolsFile::Link { target });
            }
            // `lost+found`, and anything else the stage has besides its files.
            FileType::Dir | FileType::Other => {}
        }
    }
    let dir = std::fs::File::open(stage).with_context(|| format!("opening {}", stage.display()))?;
    dir.set_permissions(std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("setting the mode on {}", stage.display()))?;
    dir.sync_all()
        .with_context(|| format!("flushing {}", stage.display()))?;
    Ok(files)
}

/// Require each of [`vk_hub_proto::REQUIRED_TOOLS`] in `stage`, a static x86-64 ELF
/// executable, reached through a link beside it or not.
fn check_stage(stage: &Path) -> Result<()> {
    for name in vk_hub_proto::REQUIRED_TOOLS {
        let path = stage.join(name);
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("the tools stage has no {name} at its root")
            }
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        };
        let meta = file.metadata()?;
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            bail!("{name} in the tools stage is not an executable file");
        }
        static_x86_64(&mut file).map_err(|why| anyhow!("{name} in the tools stage {why}"))?;
    }
    Ok(())
}

/// `Ok` when `file` is an x86-64 ELF executable with no program interpreter: statically
/// linked, so it runs in a job whatever the image's libc. A position-independent one is
/// `ET_DYN` with an entry point; a shared object has none. Else what it is not.
fn static_x86_64(file: &mut std::fs::File) -> Result<(), String> {
    const PT_INTERP: u32 = 3;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| "is not an x86-64 ELF executable".to_string())?;
    let u16_at = |at: usize| {
        header
            .get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let elf = header.starts_with(b"\x7fELF") && header[4] == 2 && header[5] == 1;
    if !elf || u16_at(18) != Some(0x3e) {
        return Err("is not an x86-64 ELF executable".into());
    }
    let entry = u64::from_le_bytes(header[24..32].try_into().map_err(|_| "is truncated")?);
    match u16_at(16) {
        Some(2) => {}
        Some(3) if entry != 0 => {}
        _ => return Err("is an ELF file but not an executable".into()),
    }
    let phoff = u64::from_le_bytes(header[32..40].try_into().map_err(|_| "is truncated")?);
    let phentsize = u64::from(u16_at(54).unwrap_or(0));
    let phnum = u64::from(u16_at(56).unwrap_or(0));
    if phentsize < 4 && phnum > 0 {
        return Err("has a malformed program header table".into());
    }
    for i in 0..phnum {
        let at = phentsize
            .checked_mul(i)
            .and_then(|o| o.checked_add(phoff))
            .ok_or("has a malformed program header table")?;
        let mut kind = [0u8; 4];
        file.read_exact_at(&mut kind, at)
            .map_err(|_| "has a truncated program header table".to_string())?;
        if u32::from_le_bytes(kind) == PT_INTERP {
            return Err(
                "is dynamically linked: a job image may lack its libc, so the tools must be \
                 static"
                    .into(),
            );
        }
    }
    Ok(())
}

/// The first line each of [`PROBED`] in `dir` prints for `--version`, run on this host with
/// an empty environment and [`PROBE_TIMEOUT`]. One that fails is left out.
async fn probe_versions(dir: &Path) -> BTreeMap<String, String> {
    use tokio::io::AsyncReadExt;
    let mut found = BTreeMap::new();
    for name in PROBED {
        let path = dir.join(name);
        if !path.is_file() {
            continue;
        }
        let mut cmd = tokio::process::Command::new(&path);
        cmd.arg("--version")
            .env_clear()
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let Ok(mut child) = cmd.spawn() else {
            continue;
        };
        let mut group = super::update::KillGroup(child.id().and_then(|p| i32::try_from(p).ok()));
        let Some(stdout) = child.stdout.take() else {
            continue;
        };
        let mut said = Vec::new();
        let read = tokio::time::timeout(PROBE_TIMEOUT, async {
            stdout.take(PROBE_MAX).read_to_end(&mut said).await?;
            child.wait().await
        })
        .await;
        if let Ok(Ok(_)) = read {
            end_group(&mut group);
        }
        if !matches!(read, Ok(Ok(status)) if status.success()) {
            continue;
        }
        // Shown to an operator, not kept for anything else: lossy is enough.
        let said = String::from_utf8_lossy(&said);
        if let Some(line) = said.lines().map(str::trim).find(|l| !l.is_empty()) {
            found.insert(name.to_string(), vk_hub_proto::display_safe(line));
        }
    }
    found
}

/// Install `stage` as the tools of `sha256`: the manifest beside where they go first, then
/// the directory, by rename. A directory there — without a manifest, or no longer what it
/// records — is moved aside first, and removed unless a job dir under `jobs` names tools of
/// that name: a running job keeps what it was given.
fn publish(
    root: &Path,
    sha256: &str,
    stage: &Path,
    manifest: &Manifest,
    jobs: &Path,
) -> Result<()> {
    let dest = root.join(sha256);
    if std::fs::symlink_metadata(&dest).is_ok() {
        let mut random = [0u8; 8];
        super::fill_random(&mut random)?;
        let gone = root.join(format!(".gone-{sha256}-{}", vk_hub_proto::to_hex(&random)));
        std::fs::rename(&dest, &gone)
            .with_context(|| format!("moving {} aside", dest.display()))?;
        if !named_by_jobs(jobs, sha256) {
            // Best effort: out of the way already, and swept as a later build starts.
            let _ = std::fs::remove_dir_all(&gone);
        }
    }
    let json = serde_json::to_vec_pretty(manifest).context("encoding the manifest")?;
    let path = manifest_path(root, sha256);
    vk_fs::write_atomic(&path, &json, 0o644)
        .with_context(|| format!("writing {}", path.display()))?;
    std::fs::rename(stage, &dest).with_context(|| format!("publishing {}", dest.display()))?;
    sync_dir(root)
}

/// Where the tools of `sha256` are moved before they are removed: a dotted name, which
/// [`prepare_root`] sweeps.
fn gone_path(root: &Path, sha256: &str) -> PathBuf {
    root.join(format!(".gone-{sha256}"))
}

/// Point [`CURRENT`] at the tools of `sha256` by renaming a new link over it. Returns the
/// tools it named before, if others.
fn switch(root: &Path, sha256: &str) -> Result<Option<String>> {
    let previous = current(root);
    let mut random = [0u8; 8];
    super::fill_random(&mut random)?;
    let tmp = root.join(format!(".current-{}", vk_hub_proto::to_hex(&random)));
    std::os::unix::fs::symlink(sha256, &tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let link = root.join(CURRENT);
    if let Err(e) = std::fs::rename(&tmp, &link) {
        // Best effort: the error is what matters.
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replacing {}", link.display()));
    }
    sync_dir(root)?;
    Ok(previous.filter(|p| p != sha256))
}

fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("syncing {}", dir.display()))
}

/// Remove the tools in `root` other than `keep`, with their manifests, unless a job dir under
/// `jobs` says its job was given them: a job keeps the directory it resolved as it started.
/// Each directory is moved to a dotted name first, then its manifest removed, then the
/// directory: cut short, what is left is never taken for installed tools. Manifests without a
/// directory go too.
fn prune(root: &Path, keep: &[String], jobs: &Path) {
    let used = given_to_jobs(jobs);
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut orphans = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(sha256) = name.strip_suffix(".json") {
            if vk_hub_proto::valid_sha256(sha256) && !keep.iter().any(|k| k == sha256) {
                orphans.push(sha256.to_string());
            }
            continue;
        }
        if !vk_hub_proto::valid_sha256(name) || keep.iter().any(|k| k == name) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_dir() || used.contains(&(meta.dev(), meta.ino())) {
            continue;
        }
        // Best effort, each step: what is left is tried again at the next switch, and a
        // dotted name is swept as the next build starts.
        let gone = gone_path(root, name);
        if std::fs::rename(entry.path(), &gone).is_err() {
            continue;
        }
        let _ = std::fs::remove_file(manifest_path(root, name));
        let _ = std::fs::remove_dir_all(&gone);
    }
    for sha256 in orphans {
        if std::fs::symlink_metadata(root.join(&sha256)).is_err() {
            // Best effort, as above.
            let _ = std::fs::remove_file(manifest_path(root, &sha256));
        }
    }
}

/// The tools roots the job dirs under `jobs` record.
fn job_roots(jobs: &Path) -> Vec<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let Ok(entries) = std::fs::read_dir(jobs) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| std::fs::read(crate::jobctx::JobCtx::tools_root_file_in(&e.path())).ok())
        .map(|bytes| PathBuf::from(std::ffi::OsString::from_vec(bytes)))
        .collect()
}

/// The directories, by device and inode, that a job dir under `jobs` records as its tools
/// root.
fn given_to_jobs(jobs: &Path) -> Vec<(u64, u64)> {
    job_roots(jobs)
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| (m.dev(), m.ino()))
        .collect()
}

/// Whether a job dir under `jobs` records tools named `sha256` as its root, wherever they
/// are now: tools replaced under the same name are told apart by nothing else.
fn named_by_jobs(jobs: &Path, sha256: &str) -> bool {
    job_roots(jobs)
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n == sha256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-tools-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The smallest static x86-64 executable as far as [`static_x86_64`] looks: a header and
    /// one loadable segment, with a program interpreter when `dynamic`.
    fn elf(dynamic: bool) -> Vec<u8> {
        let mut h = vec![0u8; 64 + 56];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        h[16] = 2;
        h[18] = 0x3e;
        h[32..40].copy_from_slice(&64u64.to_le_bytes());
        h[54..56].copy_from_slice(&56u16.to_le_bytes());
        h[56..58].copy_from_slice(&1u16.to_le_bytes());
        h[64..68].copy_from_slice(&(if dynamic { 3u32 } else { 1u32 }).to_le_bytes());
        h
    }

    /// A definition's tar, as the hub packs one.
    fn definition(dir: &Path) -> PathBuf {
        let tar = dir.join("def.tar");
        let mut b = tar::Builder::new(std::fs::File::create(&tar).unwrap());
        let mut add = |path: &str, data: &[u8], dir: bool| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(if dir {
                tar::EntryType::Directory
            } else {
                tar::EntryType::Regular
            });
            h.set_mode(if dir { 0o755 } else { 0o644 });
            h.set_size(data.len() as u64);
            b.append_data(&mut h, path, data).unwrap();
        };
        add("Dockerfile", b"FROM scratch AS tools\n", false);
        add("sub", b"", true);
        add("sub/pins.txt", b"git=2.49.0\n", false);
        drop(add);
        b.into_inner().unwrap().flush().unwrap();
        tar
    }

    /// The stage a fake build exports: what `FAKE_STAGE` names, packed as the build's ext4.
    fn fake_build<'a>(
        _: &'a Config,
        context: &'a Path,
        out: &'a Path,
        home: &'a Path,
        log: &'a Path,
    ) -> Building<'a> {
        Box::pin(async move {
            std::fs::write(log, "step 1/2\nstep 2/2\n")?;
            assert!(context.join("Dockerfile").is_file());
            assert!(context.join("sub/pins.txt").is_file());
            std::fs::create_dir_all(home)?;
            // What `vk build --egress-record` keeps: a directory per build, its channels in it.
            let record = home.join(EGRESS_RECORD).join("build-1");
            std::fs::create_dir_all(&record)?;
            let audit = record.join(crate::run::AUDIT_LOG);
            let attrs = crate::egress_report::Attrs::default();
            for name in ["github.com", "cache.nixos.org", "github.com"] {
                crate::egress_report::append_contact(&audit, name, &attrs);
            }
            crate::egress_report::append_ip_contact(&audit, "192.0.2.1:443", &attrs);
            // `<dir>/state/tools/.build-<sha256>/context`: the stage is `<dir>/stage-src`.
            let dir = context.ancestors().nth(4).context("no test dir")?;
            crate::ext4::build_from_dir(&dir.join("stage-src"), out)
        })
    }

    fn failing_build<'a>(
        _: &'a Config,
        _: &'a Path,
        _: &'a Path,
        home: &'a Path,
        log: &'a Path,
    ) -> Building<'a> {
        Box::pin(async move {
            let record = home.join(EGRESS_RECORD).join("build-1");
            std::fs::create_dir_all(&record)?;
            let denied = crate::jobctx::JobCtx::egress_denied_log_in(&record);
            let attrs = crate::egress_report::Attrs::default();
            for target in ["example.org", "198.51.100.7:80", "example.org"] {
                let proto = if target.contains(':') {
                    crate::egress_report::Proto::Tcp
                } else {
                    crate::egress_report::Proto::Dns
                };
                crate::egress_report::append(&denied, proto, target, &attrs);
            }
            let mut text = String::new();
            for i in 0..60 {
                text.push_str(&format!("line {i}\n"));
            }
            text.push_str("ERROR: no stage tools\u{1b}[2J\n");
            std::fs::write(log, text)?;
            bail!("vk build failed (exit status: 1)")
        })
    }

    /// A stage source in `<dir>/stage-src` with the tools a definition needs, where
    /// [`fake_build`] finds it.
    fn stage_source(dir: &Path, git: &[u8]) {
        let src = dir.join("stage-src");
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("lost+found")).unwrap();
        std::fs::write(src.join("git"), git).unwrap();
        std::fs::write(src.join("git-remote-http"), elf(false)).unwrap();
        std::os::unix::fs::symlink("git-remote-http", src.join("git-remote-https")).unwrap();
        std::fs::write(src.join("gitlab-runner"), elf(false)).unwrap();
    }

    /// What [`stage_source`] with a static `git` installs, as the manifest records it.
    fn recorded() -> BTreeMap<String, ToolsFile> {
        let file = || ToolsFile::File {
            sha256: vk_hub_proto::to_hex(&Sha256::digest(elf(false))),
            size: elf(false).len() as u64,
        };
        BTreeMap::from([
            ("git".into(), file()),
            ("git-remote-http".into(), file()),
            (
                "git-remote-https".into(),
                ToolsFile::Link {
                    target: "git-remote-http".into(),
                },
            ),
            ("gitlab-runner".into(), file()),
        ])
    }

    fn job(sha256: &str) -> ToolsJob {
        ToolsJob {
            command: "ab".repeat(16),
            version: "2026.10".into(),
            sha256: sha256.into(),
            size: 10240,
        }
    }

    /// Install the definition in `dir` as `sha256` with [`fake_build`], the tools dir at
    /// `<dir>/state/tools`.
    async fn install_as(dir: &Path, sha256: &str, build: Build) -> Result<(), Failed> {
        let root = dir.join("state/tools");
        prepare_root(&root, &dir.join("state/jobs")).unwrap();
        let tar = root.join(format!(".{sha256}.tar"));
        std::fs::copy(definition(dir), &tar).unwrap();
        let phases = std::sync::Mutex::new(Vec::new());
        let outcome = install(
            &Config::default(),
            &root,
            &dir.join("state/jobs"),
            &job(sha256),
            &tar,
            build,
            false,
            &|p| phases.lock().unwrap().push(p),
        )
        .await;
        // Nothing of the build is left, whatever came of it.
        let dotted: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.as_encoded_bytes().starts_with(b"."))
            .collect();
        assert!(dotted.is_empty(), "{dotted:?}");
        outcome
    }

    #[test]
    fn the_build_reaches_only_what_the_definition_declares_within_the_node_s_cap() {
        let mut cfg = Config::default();
        assert_eq!(build_net_args(&cfg), ["--build-net", "declared"]);
        cfg.egress.build.allow_name = Some(vec!["github.com".into()]);
        assert_eq!(
            build_net_args(&cfg),
            [
                "--build-net",
                "declared",
                "--build-allow-name",
                "github.com"
            ]
        );
        cfg.egress.build.allow_ip = Some(vec!["10.0.0.0/8".into()]);
        cfg.egress.build.allow_name = None;
        assert_eq!(
            build_net_args(&cfg),
            ["--build-net", "declared", "--build-allow-ip", "10.0.0.0/8"]
        );
        // A cap that allows nothing: no network, rather than no cap.
        cfg.egress.build.allow_ip = Some(Vec::new());
        assert_eq!(build_net_args(&cfg), ["--build-net", "none"]);
    }

    #[tokio::test]
    async fn tools_are_built_checked_installed_and_switched_to_keeping_the_previous() {
        let dir = scratch("install");
        stage_source(&dir, &elf(false));
        let root = dir.join("state/tools");
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        install_as(&dir, &a, fake_build).await.unwrap();
        assert_eq!(current(&root).as_deref(), Some(a.as_str()));
        let installed = root.join(&a);
        let mut names: Vec<String> = std::fs::read_dir(&installed)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "git",
                "git-remote-http",
                "git-remote-https",
                "gitlab-runner"
            ]
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            (mode(&installed), mode(&installed.join("git"))),
            (0o755, 0o755)
        );
        assert_eq!(
            std::fs::read_link(installed.join("git-remote-https")).unwrap(),
            Path::new("git-remote-http")
        );
        assert_eq!(std::fs::read(installed.join("git")).unwrap(), elf(false));
        assert_eq!(
            read_manifest(&root, &a).unwrap(),
            Manifest {
                version: "2026.10".into(),
                tools: BTreeMap::new(),
                egress: ToolsEgress {
                    contacted: vec![
                        "192.0.2.1:443".into(),
                        "cache.nixos.org".into(),
                        "github.com".into()
                    ],
                    refused: Vec::new(),
                },
                files: recorded(),
            }
        );

        // b replaces a, which is kept as the previous; c replaces b, and a goes — unless a job
        // still has it.
        install_as(&dir, &b, fake_build).await.unwrap();
        assert_eq!(current(&root).as_deref(), Some(b.as_str()));
        assert!(root.join(&a).is_dir());
        let job_dir = dir.join("state/jobs/101");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::write(
            crate::jobctx::JobCtx::tools_root_file_in(&job_dir),
            root.join(&a)
                .canonicalize()
                .unwrap()
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        install_as(&dir, &c, fake_build).await.unwrap();
        assert!(root.join(&a).is_dir() && root.join(&b).is_dir());
        std::fs::remove_dir_all(&job_dir).unwrap();
        // Back to b, installed already: switched to without a build, and a goes.
        install_as(&dir, &b, failing_build).await.unwrap();
        assert_eq!(current(&root).as_deref(), Some(b.as_str()));
        assert!(!root.join(&a).exists() && !manifest_path(&root, &a).exists());
        assert!(root.join(&c).is_dir());
        // Nothing else is left behind.
        let mut left: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                b.clone(),
                format!("{b}.json"),
                c.clone(),
                format!("{c}.json"),
                "current".into()
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failed_build_or_check_keeps_the_tools_current_and_says_why() {
        let dir = scratch("failed");
        stage_source(&dir, &elf(false));
        let root = dir.join("state/tools");
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        install_as(&dir, &a, fake_build).await.unwrap();

        let failed = install_as(&dir, &b, failing_build).await.unwrap_err();
        assert_eq!(
            failed.message,
            "vk build failed (exit status: 1); its network access was refused to \
             198.51.100.7:80, example.org"
        );
        assert_eq!(failed.log.len(), vk_hub_proto::MAX_TOOLS_LOG_LINES);
        assert_eq!(failed.log.last().unwrap(), "ERROR: no stage tools[2J");
        assert_eq!(failed.log.first().unwrap(), "line 21");

        stage_source(&dir, &elf(true));
        let failed = install_as(&dir, &c, fake_build).await.unwrap_err();
        assert!(
            failed
                .message
                .contains("git in the tools stage is dynamically linked"),
            "{}",
            failed.message
        );
        stage_source(&dir, b"#!/bin/sh\necho git\n");
        let failed = install_as(&dir, &c, fake_build).await.unwrap_err();
        assert!(
            failed.message.contains("is not an x86-64 ELF"),
            "{}",
            failed.message
        );
        stage_source(&dir, &elf(false));
        std::fs::remove_file(dir.join("stage-src/git")).unwrap();
        let failed = install_as(&dir, &c, fake_build).await.unwrap_err();
        assert!(failed.message.contains("has no git"), "{}", failed.message);
        // A link out of the stage is refused, not followed.
        stage_source(&dir, &elf(false));
        std::os::unix::fs::symlink("/etc/passwd", dir.join("stage-src/passwd")).unwrap();
        let failed = install_as(&dir, &c, fake_build).await.unwrap_err();
        assert!(
            failed.message.contains("a link must name a file"),
            "{}",
            failed.message
        );

        assert_eq!(current(&root).as_deref(), Some(a.as_str()));
        assert!(!root.join(&b).exists() && !root.join(&c).exists());
        // gitlab-runner is optional: jobs a hub places run none.
        stage_source(&dir, &elf(false));
        std::fs::remove_file(dir.join("stage-src/gitlab-runner")).unwrap();
        install_as(&dir, &c, fake_build).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_definition_unpacks_only_plain_relative_files_and_directories() {
        let dir = scratch("unpack");
        let dest = dir.join("ctx");
        private_dir(&dest).unwrap();
        unpack(&definition(&dir), &dest).unwrap();
        assert_eq!(
            std::fs::read(dest.join("sub/pins.txt")).unwrap(),
            b"git=2.49.0\n"
        );
        for (path, kind) in [
            ("../escape", tar::EntryType::Regular),
            ("/abs", tar::EntryType::Regular),
            ("link", tar::EntryType::Symlink),
        ] {
            let tar = dir.join("bad.tar");
            let mut b = tar::Builder::new(std::fs::File::create(&tar).unwrap());
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_size(0);
            h.set_mode(0o644);
            // Written raw: the builder itself refuses such paths.
            h.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
            if kind == tar::EntryType::Symlink {
                h.set_link_name("/etc/passwd").unwrap();
            }
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            b.into_inner().unwrap().flush().unwrap();
            let fresh = dir.join(format!("ctx-{}", path.replace('/', "_")));
            private_dir(&fresh).unwrap();
            let err = unpack(&tar, &fresh).unwrap_err();
            assert!(
                format!("{err:#}").contains("not a plain relative path")
                    || format!("{err:#}").contains("neither a file nor a directory"),
                "{path}: {err:#}"
            );
        }
        assert!(!dir.join("escape").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[executor] tools_dir = "<state_dir>/tools/current"` passes the rules a job's boot
    /// resolves it under, and leads to the tools current; another path is not in use.
    #[tokio::test]
    async fn the_managed_tools_dir_resolves_as_a_job_would_and_counts_as_in_use() {
        let dir = scratch("resolve");
        stage_source(&dir, &elf(false));
        let a = "aa".repeat(32);
        install_as(&dir, &a, fake_build).await.unwrap();
        let state = dir.join("state");
        let mut cfg = Config {
            state_dir: Some(state.clone()),
            ..Config::default()
        };
        assert!(!in_use(&cfg));
        assert!(installed(&cfg).is_some_and(|t| !t.in_use));
        assert!(unused_warning(&cfg).is_some());
        cfg.executor.tools_dir = Some(state.join("tools/current/"));
        assert!(in_use(&cfg));
        assert_eq!(unused_warning(&cfg), None);
        let resolved = crate::vm::share_root(
            &cfg,
            cfg.executor.tools_dir.as_deref().unwrap(),
            crate::vm::ShareRoot::Tools,
        )
        .unwrap();
        assert_eq!(
            resolved,
            state.join("tools").join(&a).canonicalize().unwrap()
        );
        let installed = installed(&cfg).unwrap();
        assert_eq!(
            (installed.sha256, installed.version),
            (a.clone(), "2026.10".into())
        );
        // Pinned to the tools of now rather than to the link: not what the hub switches.
        cfg.executor.tools_dir = Some(state.join("tools").join(&a));
        assert!(!in_use(&cfg));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Installed tools are checked against what their manifest records: as the inventory
    /// reports them, before a job is given them, and before they are switched to again, which
    /// builds them anew when they changed or were recorded by nothing.
    #[tokio::test]
    async fn tools_changed_since_installed_are_reported_given_to_no_job_and_rebuilt() {
        let dir = scratch("check");
        stage_source(&dir, &elf(false));
        let a = "aa".repeat(32);
        install_as(&dir, &a, fake_build).await.unwrap();
        let state = dir.join("state");
        let root = state.join("tools");
        let cfg = Config {
            state_dir: Some(state.clone()),
            ..Config::default()
        };
        let installed_dir = root.join(&a).canonicalize().unwrap();
        let reported = installed(&cfg).unwrap();
        assert_eq!(reported.files, recorded());
        assert_eq!(reported.check, Some(ToolsCheck::Intact));
        assert_eq!(
            reported.egress.unwrap().contacted,
            ["192.0.2.1:443", "cache.nixos.org", "github.com"]
        );
        for_job(&cfg, &installed_dir).unwrap();
        // Another directory is the operator's, given as it is.
        for_job(&cfg, &dir).unwrap();

        let modified = |entries: &[&str]| {
            Some(ToolsCheck::Modified {
                entries: entries.iter().map(|e| e.to_string()).collect(),
            })
        };
        // One byte of git, the same size and mode.
        let git = installed_dir.join("git");
        let mut bytes = std::fs::read(&git).unwrap();
        bytes[100] ^= 1;
        std::fs::write(&git, &bytes).unwrap();
        assert_eq!(installed(&cfg).unwrap().check, modified(&["git"]));
        let err = for_job(&cfg, &installed_dir).unwrap_err().to_string();
        assert!(
            err.contains("changed since they were installed (git)"),
            "{err}"
        );
        bytes[100] ^= 1;
        std::fs::write(&git, &bytes).unwrap();
        assert_eq!(installed(&cfg).unwrap().check, Some(ToolsCheck::Intact));
        // A mode, a link's target, a file added, a file gone.
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o777)).unwrap();
        let link = installed_dir.join("git-remote-https");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("git", &link).unwrap();
        std::fs::write(installed_dir.join("sh"), b"#!/bin/sh\n").unwrap();
        std::fs::remove_file(installed_dir.join("gitlab-runner")).unwrap();
        assert_eq!(
            installed(&cfg).unwrap().check,
            modified(&["git", "git-remote-https", "gitlab-runner", "sh"])
        );
        assert!(for_job(&cfg, &installed_dir).is_err());
        assert!(!installed_here(&root, &a));

        // Asked for again, they are built anew rather than only switched to.
        install_as(&dir, &a, fake_build).await.unwrap();
        assert_eq!(installed(&cfg).unwrap().check, Some(ToolsCheck::Intact));
        assert!(!root.join(&a).join("sh").exists());
        for_job(&cfg, &root.join(&a).canonicalize().unwrap()).unwrap();

        // Recorded by nothing: reported so and given unchecked, and built anew when asked for.
        let mut legacy = read_manifest(&root, &a).unwrap();
        legacy.files.clear();
        std::fs::write(
            manifest_path(&root, &a),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert_eq!(installed(&cfg).unwrap().check, Some(ToolsCheck::Unrecorded));
        for_job(&cfg, &root.join(&a).canonicalize().unwrap()).unwrap();
        assert!(!installed_here(&root, &a));
        install_as(&dir, &a, fake_build).await.unwrap();
        assert_eq!(installed(&cfg).unwrap().check, Some(ToolsCheck::Intact));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Tools replaced under their own name stay, moved aside, while a job dir names them, and
    /// go once none does.
    #[tokio::test]
    async fn tools_replaced_under_a_job_stay_until_it_is_gone() {
        let dir = scratch("replaced");
        stage_source(&dir, &elf(false));
        let a = "aa".repeat(32);
        let (root, jobs) = (dir.join("state/tools"), dir.join("state/jobs"));
        install_as(&dir, &a, fake_build).await.unwrap();
        let job_dir = jobs.join("7");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::write(
            crate::jobctx::JobCtx::tools_root_file_in(&job_dir),
            root.join(&a).as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        let old_git = root.join(&a).join("git");
        std::fs::write(&old_git, b"changed").unwrap();
        let manifest = read_manifest(&root, &a).unwrap();
        let stage = root.join(".stage");
        std::fs::create_dir(&stage).unwrap();
        publish(&root, &a, &stage, &manifest, &jobs).unwrap();
        let aside = |root: &Path| -> Vec<PathBuf> {
            std::fs::read_dir(root)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.to_string_lossy().contains(".gone-"))
                .collect()
        };
        let kept = aside(&root);
        assert_eq!(kept.len(), 1);
        assert_eq!(std::fs::read(kept[0].join("git")).unwrap(), b"changed");
        prepare_root(&root, &jobs).unwrap();
        assert_eq!(aside(&root), kept);
        std::fs::remove_dir_all(&job_dir).unwrap();
        prepare_root(&root, &jobs).unwrap();
        assert!(aside(&root).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tools directory without its manifest, and a manifest without its directory — what a
    /// removal cut short leaves — are not installed tools, and are built over.
    #[tokio::test]
    async fn half_removed_tools_are_not_installed_and_do_not_block_a_build() {
        let dir = scratch("half");
        stage_source(&dir, &elf(false));
        let root = dir.join("state/tools");
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        std::fs::create_dir_all(root.join(&a)).unwrap();
        std::fs::write(root.join(&a).join("git"), b"left").unwrap();
        std::fs::write(manifest_path(&root, &b), b"{\"version\":\"old\"}").unwrap();
        assert!(!installed_here(&root, &a) && !installed_here(&root, &b));
        install_as(&dir, &a, fake_build).await.unwrap();
        assert_eq!(
            std::fs::read(root.join(&a).join("git")).unwrap(),
            elf(false)
        );
        install_as(&dir, &b, fake_build).await.unwrap();
        assert_eq!(read_manifest(&root, &b).unwrap().version, "2026.10");
        // A manifest left without its directory is pruned with the tools.
        std::fs::write(manifest_path(&root, &c), b"{}").unwrap();
        prune(&root, std::slice::from_ref(&b), &dir.join("state/jobs"));
        assert!(!root.join(&a).exists() && !manifest_path(&root, &a).exists());
        assert!(!manifest_path(&root, &c).exists());
        assert!(installed_here(&root, &b));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shared_object_is_not_an_executable() {
        let dir = scratch("elf");
        let path = dir.join("tool");
        let check = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            static_x86_64(&mut std::fs::File::open(&path).unwrap())
        };
        assert_eq!(check(&elf(false)), Ok(()));
        // ET_DYN: a static PIE has an entry point, a shared object none.
        let mut pie = elf(false);
        pie[16] = 3;
        pie[24..32].copy_from_slice(&0x1040u64.to_le_bytes());
        assert_eq!(check(&pie), Ok(()));
        pie[24..32].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            check(&pie),
            Err("is an ELF file but not an executable".to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What a probe leaves running in its process group is killed with it.
    #[tokio::test]
    async fn what_a_probe_leaves_behind_is_killed() {
        let dir = scratch("probe-group");
        let pid = dir.join("pid");
        let path = dir.join("git");
        // Named whole: the probe runs with an empty environment, so no PATH.
        let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|d| d.join("sleep"))
            .find(|p| p.is_file())
            .expect("no sleep on PATH");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n{} 30 >/dev/null 2>&1 &\necho $! > {}\necho 'git version 2'\n",
                sleep.display(),
                pid.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let found = probe_versions(&dir).await;
        assert_eq!(found.get("git").map(String::as_str), Some("git version 2"));
        let pid: i32 = std::fs::read_to_string(&pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // Killed: gone, or a zombie its new parent has yet to reap.
        let state = || {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            stat.rsplit_once(") ")
                .and_then(|(_, rest)| rest.chars().next())
        };
        let mut waited = 0;
        while matches!(state(), Some('R' | 'S' | 'D')) && waited < 500 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            waited += 1;
        }
        // SAFETY: the test's own background `sleep`, should it have been left.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        assert!(waited < 500, "the probe's leftover still runs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn node_core(dir: &Path) -> Arc<Core> {
        let state = dir.join("node");
        std::fs::create_dir_all(&state).unwrap();
        let issuer = super::super::state::Issuer {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
        };
        Core::open(&state, issuer, crate::node::core::Runner::External).unwrap()
    }

    /// Give `core` the tools build of `sha256` to carry out, its phase `phase` as saved.
    fn start(core: &Core, sha256: &str, phase: ToolsPhase) {
        core.change(|p| {
            let job = job(sha256);
            p.tools_progress = Some(vk_hub_proto::ToolsProgress {
                command: job.command.clone(),
                version: job.version.clone(),
                sha256: job.sha256.clone(),
                phase,
                message: None,
                log: Vec::new(),
            });
            p.tools = Some(job);
        })
        .unwrap();
    }

    /// Wait until `done` holds of `core`'s state.
    async fn settle(core: &Core, done: impl Fn(&super::super::state::Persisted) -> bool) {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !done(&core.persisted()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the node state did not settle");
    }

    /// What [`follow`] carries out in the tests: [`run`], with a download that copies the
    /// definition and counts, and [`failing_build`] for `failing`.
    struct Harness {
        dir: PathBuf,
        core: Arc<Core>,
        cfg: Config,
        failing: String,
        downloads: std::sync::Mutex<Vec<Option<ToolsPhase>>>,
        runs: std::sync::atomic::AtomicUsize,
    }

    impl Harness {
        fn new(tag: &str) -> Self {
            let dir = scratch(tag);
            stage_source(&dir, &elf(false));
            let core = node_core(&dir);
            let cfg = Config {
                state_dir: Some(dir.join("state")),
                ..Config::default()
            };
            Harness {
                dir,
                core,
                cfg,
                failing: "ff".repeat(32),
                downloads: std::sync::Mutex::new(Vec::new()),
                runs: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        async fn work(&self, job: ToolsJob) -> Result<(), Failed> {
            let download = |tar: PathBuf| async move {
                let phase = self.core.persisted().tools_progress.map(|p| p.phase);
                self.downloads.lock().unwrap().push(phase);
                std::fs::copy(definition(&self.dir), &tar)?;
                Ok::<_, anyhow::Error>(())
            };
            let build: Build = if job.sha256 == self.failing {
                failing_build
            } else {
                fake_build
            };
            let outcome = run(&self.core, &self.cfg, &job, download, build, false).await;
            self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            outcome
        }

        fn runs(&self) -> usize {
            self.runs.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn absolute_build<'a>(
        cfg: &'a Config,
        context: &'a Path,
        out: &'a Path,
        home: &'a Path,
        log: &'a Path,
    ) -> Building<'a> {
        for p in [context, out, home, log] {
            assert!(p.is_absolute(), "{}", p.display());
        }
        fake_build(cfg, context, out, home, log)
    }

    /// A relative state dir reaches the build absolute: it runs in a directory of its own.
    #[tokio::test]
    async fn a_relative_state_dir_reaches_the_build_absolute() {
        let h = Harness::new("relative");
        let a = "aa".repeat(32);
        let cwd = std::env::current_dir().unwrap();
        let up: PathBuf = cwd.components().skip(1).map(|_| "..").collect();
        let state = up.join(h.dir.join("state").strip_prefix("/").unwrap());
        assert!(state.is_relative());
        let cfg = Config {
            state_dir: Some(state.clone()),
            ..Config::default()
        };
        let dir = &h.dir;
        let download = |tar: PathBuf| async move {
            assert!(tar.is_absolute(), "{}", tar.display());
            std::fs::copy(definition(dir), &tar)?;
            Ok::<_, anyhow::Error>(())
        };
        run(&h.core, &cfg, &job(&a), download, absolute_build, false)
            .await
            .unwrap();
        assert_eq!(current(&state.join(TOOLS_DIR)).as_deref(), Some(a.as_str()));
        let _ = std::fs::remove_dir_all(&h.dir);
    }

    /// A build is downloaded, reported from its first phase again, and ended in the state; one
    /// installed already is not downloaded again; a failed one is ended with why.
    #[tokio::test]
    async fn the_node_carries_out_each_tools_build_and_ends_it() {
        let h = Harness::new("follow");
        let a = "aa".repeat(32);
        let root = h.dir.join("state/tools");
        let (stop_tx, stop) = watch::channel(false);
        // Saved as installing by a node stopped mid-build: reported as downloading again.
        start(&h.core, &a, ToolsPhase::Installing);
        let drive = async {
            settle(&h.core, |p| p.tools.is_none()).await;
            let progress = h.core.persisted().tools_progress.unwrap();
            assert_eq!(
                (progress.sha256, progress.phase),
                (a.clone(), ToolsPhase::Done)
            );
            assert_eq!(current(&root).as_deref(), Some(a.as_str()));
            assert_eq!(
                *h.downloads.lock().unwrap(),
                [Some(ToolsPhase::Downloading)]
            );

            start(&h.core, &a, ToolsPhase::Downloading);
            settle(&h.core, |p| p.tools.is_none()).await;
            assert_eq!(h.downloads.lock().unwrap().len(), 1);
            assert_eq!(h.runs(), 2);

            start(&h.core, &h.failing, ToolsPhase::Downloading);
            settle(&h.core, |p| p.tools.is_none()).await;
            let progress = h.core.persisted().tools_progress.unwrap();
            assert_eq!(progress.phase, ToolsPhase::Failed);
            // What the build was refused goes with the failure to the hub.
            assert_eq!(
                progress.message.as_deref(),
                Some(
                    "vk build failed (exit status: 1); its network access was refused to \
                     198.51.100.7:80, example.org"
                )
            );
            assert_eq!(progress.log.len(), vk_hub_proto::MAX_TOOLS_LOG_LINES);
            assert_eq!(current(&root).as_deref(), Some(a.as_str()));
            stop_tx.send(true).unwrap();
        };
        tokio::join!(
            follow(&h.core, &h.cfg, stop, SAVE_RETRY, |job| h.work(job)),
            drive
        );
        let _ = std::fs::remove_dir_all(&h.dir);
    }

    /// A build whose end cannot be saved is run again after a wait, not at once, and ended
    /// once the state saves.
    #[tokio::test]
    async fn a_build_whose_end_cannot_be_saved_is_retried_after_a_wait() {
        let h = Harness::new("retry");
        let a = "aa".repeat(32);
        let (stop_tx, stop) = watch::channel(false);
        start(&h.core, &a, ToolsPhase::Downloading);
        // A directory where the state file goes: no save succeeds.
        let state = super::super::state::path(&h.dir.join("node"));
        let _ = std::fs::remove_file(&state);
        std::fs::create_dir_all(state.join("blocker")).unwrap();
        let drive = async {
            tokio::time::timeout(Duration::from_secs(30), async {
                while h.runs() == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(h.runs(), 1);
            assert!(h.core.persisted().tools.is_some());
            std::fs::remove_dir_all(&state).unwrap();
            settle(&h.core, |p| p.tools.is_none()).await;
            // Run again, installed by then: switched to without a download.
            assert_eq!(h.runs(), 2);
            assert_eq!(h.downloads.lock().unwrap().len(), 1);
            assert_eq!(
                h.core.persisted().tools_progress.map(|p| p.phase),
                Some(ToolsPhase::Done)
            );
            stop_tx.send(true).unwrap();
        };
        tokio::join!(
            follow(&h.core, &h.cfg, stop, Duration::from_secs(1), |job| h
                .work(job)),
            drive
        );
        let _ = std::fs::remove_dir_all(&h.dir);
    }

    /// Run on the host, a tool's `--version` is its first line; one that fails or hangs is
    /// left out.
    #[tokio::test]
    async fn versions_are_the_first_line_each_tool_prints() {
        let dir = scratch("probe");
        let script = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        script("git", "echo 'git version 2.49.0'; echo more");
        script("git-lfs", "exit 1");
        script(
            "gitlab-runner",
            "printf '\\nVersion:      19.1.0\\nGit revision: x\\n'",
        );
        let found = probe_versions(&dir).await;
        assert_eq!(
            found,
            BTreeMap::from([
                ("git".to_string(), "git version 2.49.0".to_string()),
                (
                    "gitlab-runner".to_string(),
                    "Version:      19.1.0".to_string()
                ),
            ])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
