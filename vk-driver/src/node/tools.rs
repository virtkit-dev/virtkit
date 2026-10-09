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
//! a `<sha256>.json` manifest beside it. Renaming a new link over `current` switches tools
//! for future jobs. Each job keeps the directory it resolves at startup ([`crate::vm`]).
//! The previous tools remain available; older ones are removed unless a job directory's
//! `tools.root` still names them.
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
use tokio::sync::watch;
use vk_hub_proto::{ToolsInstalled, ToolsPhase};

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
const MAX_FILES: usize = 64;
const MAX_TOOL: u64 = 256 << 20;

/// The most entries a definition's tar may hold.
const MAX_ENTRIES: usize = 4096;

/// `<state_dir>/tools`.
fn root(cfg: &Config) -> PathBuf {
    cfg.state_dir().join(TOOLS_DIR)
}

/// What is kept beside an installed tools directory, `<sha256>.json`.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    version: String,
    #[serde(default)]
    tools: BTreeMap<String, String>,
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

/// Whether the tools of `sha256` are installed whole: their directory, and its manifest,
/// which is written first.
fn installed_here(root: &Path, sha256: &str) -> bool {
    std::fs::symlink_metadata(root.join(sha256)).is_ok_and(|m| m.is_dir())
        && read_manifest(root, sha256).is_some()
}

/// The tools [`CURRENT`] names, as the inventory reports them.
pub fn installed(cfg: &Config) -> Option<ToolsInstalled> {
    let root = root(cfg);
    let sha256 = current(&root)?;
    let manifest = read_manifest(&root, &sha256)?;
    Some(ToolsInstalled {
        sha256,
        version: manifest.version,
        tools: manifest.tools,
        in_use: in_use(cfg),
    })
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
        move || {
            prepare_root(&root)?;
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
            if let Err(e) = built {
                return Err(Failed {
                    message: format!("{e:#}"),
                    log: tail(&log, vk_hub_proto::MAX_TOOLS_LOG_LINES),
                });
            }
            phase(ToolsPhase::Installing);
            let stage = root.join(format!(".stage-{sha256}"));
            blocking({
                let (out, stage) = (out.clone(), stage.clone());
                move || {
                    extract(&out, &stage)?;
                    check(&stage)
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
            };
            blocking({
                let (root, sha256) = (root.to_path_buf(), sha256.clone());
                move || publish(&root, &sha256, &stage, &manifest)
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
/// it: every name starting with `.`. One build runs at a time, under the node's lock.
fn prepare_root(root: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(root)
        .with_context(|| format!("creating {}", root.display()))?;
    for entry in std::fs::read_dir(root).with_context(|| format!("listing {}", root.display()))? {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().starts_with(b".") {
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
/// from the node's build cache.
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
/// filled.
fn extract(image: &Path, stage: &Path) -> Result<()> {
    use crate::ext4_read::{Ext4Reader, FileType};
    let fs = Ext4Reader::open(image).with_context(|| format!("reading {}", image.display()))?;
    let mut entries = fs.list_dir("/").context("listing the tools stage")?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if entries.len() > MAX_FILES {
        bail!("the tools stage holds more than {MAX_FILES} entries at its root");
    }
    private_dir(stage)?;
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
            }
            // `lost+found`, and anything else the stage has besides its files.
            FileType::Dir | FileType::Other => {}
        }
    }
    let dir = std::fs::File::open(stage).with_context(|| format!("opening {}", stage.display()))?;
    dir.set_permissions(std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("setting the mode on {}", stage.display()))?;
    dir.sync_all()
        .with_context(|| format!("flushing {}", stage.display()))
}

/// Require each of [`vk_hub_proto::REQUIRED_TOOLS`] in `stage`, a static x86-64 ELF
/// executable, reached through a link beside it or not.
fn check(stage: &Path) -> Result<()> {
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
/// the directory, by rename. A directory there without a manifest is not installed tools,
/// and is removed first.
fn publish(root: &Path, sha256: &str, stage: &Path, manifest: &Manifest) -> Result<()> {
    let dest = root.join(sha256);
    if std::fs::symlink_metadata(&dest).is_ok() {
        let gone = gone_path(root, sha256);
        std::fs::rename(&dest, &gone)
            .with_context(|| format!("moving {} aside", dest.display()))?;
        // Best effort: out of the way already, and swept as the next build starts.
        let _ = std::fs::remove_dir_all(&gone);
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

/// The directories, by device and inode, that a job dir under `jobs` records as its tools
/// root.
fn given_to_jobs(jobs: &Path) -> Vec<(u64, u64)> {
    use std::os::unix::ffi::OsStringExt;
    let Ok(entries) = std::fs::read_dir(jobs) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| std::fs::read(crate::jobctx::JobCtx::tools_root_file_in(&e.path())).ok())
        .filter_map(|bytes| {
            std::fs::metadata(PathBuf::from(std::ffi::OsString::from_vec(bytes))).ok()
        })
        .map(|m| (m.dev(), m.ino()))
        .collect()
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
            // `<dir>/state/tools/.build-<sha256>/context`: the stage is `<dir>/stage-src`.
            let dir = context.ancestors().nth(4).context("no test dir")?;
            crate::ext4::build_from_dir(&dir.join("stage-src"), out)
        })
    }

    fn failing_build<'a>(
        _: &'a Config,
        _: &'a Path,
        _: &'a Path,
        _: &'a Path,
        log: &'a Path,
    ) -> Building<'a> {
        Box::pin(async move {
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
        prepare_root(&root).unwrap();
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
        assert_eq!(failed.message, "vk build failed (exit status: 1)");
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
        Core::open(&state, issuer, None).unwrap()
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
            assert_eq!(
                progress.message.as_deref(),
                Some("vk build failed (exit status: 1)")
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
