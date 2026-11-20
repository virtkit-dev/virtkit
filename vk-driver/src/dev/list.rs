//! Workspace and host-wide dev environment inventories, and garbage collection of dev state.
//!
//! [`crate::dev::plan`] derives a state directory from the canonical workspace path and the
//! environment name, so the directories under [`crate::dev::plan::dev_state_base`] are the
//! host-wide state inventory — and nothing in a checkout points back at them. Deleting a worktree
//! therefore leaves its environment's storage behind with nothing to name it, and a task
//! that ran in a throwaway environment leaves a directory holding a root image and console
//! logs but no `dev.json`. Both are read here from the directories themselves rather than
//! from any config, which is why `list --all` and `gc --all-stale` resolve none. A bare
//! `list` reads the config only to pick its workspace's rows and add what it declares
//! ([`with_services`]).
//!
//! The scan is pure: [`scan`] turns the base directory and the set of running state dirs
//! into rows, [`select_gc`] decides which of them a `gc` takes, and only [`remove`] touches
//! anything — under each directory's own lock, the one a boot holds, so nothing is deleted
//! from under a boot that started while the caller was answering a prompt.
//!
//! `vk dev list --json` returns an array of environment rows. Field names are append-only.
//! A declaration without state has status `not-built`, a null `name` and its expected
//! `dir_name`. Empty service lists and unmeasured sizes are omitted. `--no-sizes` skips
//! the disk walk. Live memory is always requested. A stopped VM or an unreadable memory
//! figure gives `mem_used_bytes: null`.

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::usage::fmt_bytes;

/// Timeout for stopping each publisher before removing its environment.
const PUBLISH_STOP: std::time::Duration = std::time::Duration::from_secs(5);

/// Environment status from live VMs, on-disk state and workspace declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// a VM is up on this state dir
    Running,
    /// booted at some point, nothing running now
    Stopped,
    /// no identity recorded: an ephemeral run, or a boot that never completed
    NeverBooted,
    /// declared environment with no state directory
    NotBuilt,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Running => "running",
            Status::Stopped => "stopped",
            Status::NeverBooted => "never booted",
            Status::NotBuilt => "not built",
        }
    }
}

/// What makes an environment a candidate for `gc --all-stale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flag {
    /// the workspace the identity records is gone, and the directory that held it is still
    /// there — an unmounted share is not a deleted checkout
    WorkspaceMissing,
    /// no identity recorded: the shape a task run or an aborted boot leaves
    Ephemeral,
}

impl Flag {
    fn label(self) -> &'static str {
        match self {
            Flag::WorkspaceMissing => "workspace missing",
            Flag::Ephemeral => "ephemeral",
        }
    }
}

/// A running VM as [`scan`] needs it: the state directory that ties it to a row, plus the
/// memory facts that row reports. Carried as its own type rather than a [`crate::vms::VmEntry`]
/// so `scan` stays a pure function over facts a test can state outright — measuring a live
/// process tree is the caller's job, not the scan's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    /// the VM's `--state-dir`, as the registry recorded it
    pub state_dir: PathBuf,
    /// what its whole process tree holds on the host now (`crate::usage::tree_resident`);
    /// `None` when the tree could not be read
    pub mem_used: Option<u64>,
    /// the memory size it booted with, the `--mem` token verbatim
    pub mem: Option<String>,
}
/// One environment in the inventory.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Row {
    /// VM name accepted by `vk dev stop`, `gc` and `prune`, or the state directory name. An
    /// environment never brought up claims none until it boots: [`json`] prints `null` for
    /// it, as another VM may go by that name
    #[serde(skip)]
    pub name: String,
    /// the state directory's own name, which still names the environment too
    pub dir_name: String,
    pub dir: PathBuf,
    /// workspace from the boot identity or matching declaration, when known
    pub workspace: Option<PathBuf>,
    /// the guest directory standing for the workspace, as the boot recorded it; not part of
    /// `vk dev list --json`
    #[serde(skip)]
    pub workspace_folder: Option<String>,
    /// the `--dev-config` the boot read, as it recorded it; not part of `vk dev list --json`
    #[serde(skip)]
    pub config: Option<PathBuf>,
    /// the primary compose service recorded at boot, omitted from `vk dev list --json`
    #[serde(skip)]
    pub primary: Option<String>,
    pub environment: Option<String>,
    pub status: Status,
    /// the `vk` that booted it, as it recorded itself
    pub created_by: Option<String>,
    pub booted_secs: Option<u64>,
    /// how long ago that boot was, at the time of the scan
    pub age_secs: Option<u64>,
    /// what the environment's VM holds on the host right now, in bytes: its whole process
    /// tree, counted proportionally, the same figure `vk list` reports. `null` for an
    /// environment that is not running — a stopped one holds nothing, which is a fact, not a
    /// missing measurement — and for a running one whose tree could not be read.
    pub mem_used_bytes: Option<u64>,
    /// the memory size its VM booted with, the `--mem` token as recorded; `null` when it is
    /// not running, or the run recorded none
    pub mem: Option<String>,
    /// directory size in bytes when measured, omitted for missing state and with `--no-sizes`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub flags: Vec<Flag>,
    /// whether the directory passes the ownership check for deletion ([`owned`])
    pub deletable: bool,
    /// Declared secondary compose services, one table row each. Omitted from host-wide listings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,
}

/// One compose service of an environment, beside its primary.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Service {
    pub name: String,
    /// A live manager's non-stopped state, or null if there is no evidence of a boot.
    /// A previously booted service defaults to stopped, or unknown if its running
    /// environment's manager is unreachable.
    pub status: Option<String>,
    /// where its VM keeps its state, `svc-<name>/` in the environment's state dir
    pub dir: PathBuf,
    /// what its directory holds; measured by default, omitted with `--no-sizes` and for a
    /// service that has no VM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

/// One environment the workspace's config declares: where its state goes, and the compose
/// services it runs beside its primary.
#[derive(Debug, Clone, PartialEq)]
pub struct Declared {
    pub environment: String,
    pub workspace: PathBuf,
    pub state_dir: PathBuf,
    pub services: Vec<String>,
}

/// What a running environment's service manager reports of its units, as `(name, state)`;
/// `None` for an environment that is not running or cannot be asked.
pub type UnitStates<'a> = dyn Fn(&Path) -> Option<Vec<(String, String)>> + 'a;

/// Match declarations to state directories in config order, then append undeclared state.
/// A missing directory yields a [`Status::NotBuilt`] row. A matching declaration supplies
/// the workspace and environment if a boot left no identity. Each declaration supplies
/// its secondary services. `states` queries running managers and `sizes` enables disk usage.
pub fn with_services(
    rows: Vec<Row>,
    declared: &[Declared],
    sizes: bool,
    states: &UnitStates,
) -> Vec<Row> {
    let mut left = rows;
    let mut out = Vec::new();
    for d in declared {
        let dir = crate::vms::canonical(&d.state_dir);
        let found = left
            .iter()
            .position(|r| crate::vms::canonical(&r.dir) == dir);
        let dir_name: String = (d.state_dir.file_name())
            .unwrap_or_default()
            .to_string_lossy()
            .into();
        let mut row = match found {
            Some(i) => left.remove(i),
            // Not `default_name`: another workspace's environment may hold that name, which
            // `vk stop` and `vk delete` would then reach.
            None => Row {
                name: dir_name.clone(),
                dir_name,
                dir: d.state_dir.clone(),
                workspace: Some(d.workspace.clone()),
                workspace_folder: None,
                config: None,
                primary: None,
                environment: Some(d.environment.clone()),
                status: Status::NotBuilt,
                created_by: None,
                booted_secs: None,
                age_secs: None,
                mem_used_bytes: None,
                mem: None,
                size_bytes: None,
                flags: Vec::new(),
                deletable: false,
                services: Vec::new(),
            },
        };
        // A boot that never recorded its identity: the declaration says whose it is.
        if row.workspace.is_none() {
            row.workspace = Some(d.workspace.clone());
            row.environment = Some(d.environment.clone());
        }
        let running = row.status == Status::Running;
        let reported = match running {
            true => states(&row.dir),
            false => None,
        };
        row.services = d
            .services
            .iter()
            .map(|name| {
                let dir = row.dir.join(format!("svc-{name}"));
                service(name, dir, running, reported.as_deref(), sizes)
            })
            .collect();
        out.push(row);
    }
    out.extend(left);
    out
}

/// As in `vk list`, a non-stopped unit or an existing console log identifies a service VM.
/// A previously booted service is unknown if its running manager cannot be queried.
fn service(
    name: &str,
    dir: PathBuf,
    running: bool,
    reported: Option<&[(String, String)]>,
    sizes: bool,
) -> Service {
    let booted = crate::vmlist::booted(&dir);
    let state = |units: &[(String, String)]| {
        let (_, state) = units.iter().find(|(n, _)| n == name)?;
        (state != crate::vmlist::STOPPED).then(|| state.clone())
    };
    let status = match (running, reported) {
        (true, Some(units)) => state(units),
        (true, None) if booted => Some("unknown".to_string()),
        _ => None,
    }
    .or_else(|| booted.then(|| crate::vmlist::STOPPED.to_string()));
    Service {
        name: name.to_string(),
        size_bytes: (sizes && status.is_some()).then(|| crate::dev::storage::dir_size(&dir)),
        status,
        dir,
    }
}

impl Row {
    fn has(&self, flag: Flag) -> bool {
        self.flags.contains(&flag)
    }

    /// Eligible for `--all-stale`: not running, with a missing checkout or no identity.
    fn stale(&self) -> bool {
        self.status != Status::Running
            && (self.has(Flag::WorkspaceMissing) || self.has(Flag::Ephemeral))
    }
}

/// Migrate older environments without rebooting them. Claim names in boot order so the
/// oldest gets the unsuffixed name when it is free. An up-to-date index needs no writes.
/// If a claim fails, remaining environments still resolve by their state directory names.
pub fn name_unnamed() {
    let (Ok(base), Ok(idx)) = (
        crate::dev::plan::dev_state_base(),
        crate::names::Index::open(),
    ) else {
        return;
    };
    if let Err(e) = name_unnamed_in(&base, &idx) {
        eprintln!("vk: warning: naming dev environments: {e:#}");
    }
}

/// [`name_unnamed`] for the environments under `base`, in the index `idx`. An ephemeral
/// directory (no `dev.json`) gets no name.
pub(crate) fn name_unnamed_in(base: &Path, idx: &crate::names::Index) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Ok(());
    };
    let named: std::collections::HashSet<PathBuf> =
        idx.all().into_iter().map(|(_, dir)| dir).collect();
    let mut todo: Vec<(u64, PathBuf, String)> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| crate::vms::canonical(&e.path()))
        .filter(|dir| !named.contains(dir))
        .filter_map(|dir| {
            let bytes = std::fs::read(dir.join("dev.json")).ok()?;
            let identity: crate::dev::Identity = serde_json::from_slice(&bytes).ok()?;
            let text = |key: &str| identity.manifest.get(key)?.as_str().map(str::to_string);
            let base = default_name(
                Path::new(&text("workspace").unwrap_or_default()),
                &text("environment").unwrap_or_else(|| "dev".into()),
            );
            Some((identity.booted_secs, dir, base))
        })
        .collect();
    if todo.is_empty() {
        return Ok(());
    }
    todo.sort();
    let _lock = idx.lock()?;
    for (_, dir, base) in todo {
        idx.claim_locked(&dir, &base)?;
    }
    Ok(())
}

/// List unindexed dev state directories by directory name and presence of `dev.json`.
/// Includes both candidates for [`name_unnamed`] and directories without a recorded boot.
/// A missing dev base is empty. Other directory read errors propagate.
pub fn unnamed_dirs(named: &[(String, PathBuf)]) -> Result<Vec<(String, PathBuf, bool)>> {
    let base = crate::dev::plan::dev_state_base()?;
    let read = |e| anyhow::Error::from(e).context(format!("reading {}", base.display()));
    let entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(read(e)),
    };
    let named: std::collections::HashSet<&Path> = named.iter().map(|(_, d)| d.as_path()).collect();
    let mut out = Vec::new();
    for e in entries {
        let e = e.map_err(read)?;
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = crate::vms::canonical(&e.path());
        if named.contains(dir.as_path()) || named.contains(e.path().as_path()) {
            continue;
        }
        let Some(own) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let booted = dir.join("dev.json").is_file();
        out.push((own, dir, booted));
    }
    Ok(out)
}

/// The name a dev environment is first given: its workspace's directory name, then
/// `-<environment>` for any environment but `dev`.
pub fn default_name(workspace: &Path, environment: &str) -> String {
    let ws = workspace
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "workspace".into());
    match environment {
        "dev" => crate::names::sanitize(&ws),
        env => crate::names::sanitize(&format!("{ws}-{env}")),
    }
}

/// A recorded dev identity and the absence of a run recipe make `dir` a dev environment's
/// alone, which `vk delete` removes whole. Forgetting a run recipe still leaves a directory
/// with an unreadable identity ineligible.
pub fn owned(dir: &Path) -> Result<()> {
    let recipe = dir.join(crate::names::RECIPE);
    match std::fs::symlink_metadata(&recipe) {
        Ok(_) => bail!(
            "{} also holds a run's {}: it is not known to be only a dev environment's",
            dir.display(),
            crate::names::RECIPE
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", recipe.display())),
    }
    let path = dir.join("dev.json");
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice::<crate::dev::Identity>(&bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(())
}

/// A top-level entry of a state directory, for the listing `gc` prints before it removes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub name: String,
    pub size_bytes: u64,
}

/// List state directories under `base`, using `running` to identify active VMs. Read-only.
/// Keep rows with absent or unreadable `dev.json` so `gc` can collect them.
/// `sizes` measures each directory, walking its root images and server trees. A missing
/// `base` is empty; another error reading it is returned, not taken for an empty inventory.
pub fn scan(base: &Path, running: &[Running], sizes: bool) -> Result<Vec<Row>> {
    let read = |e| anyhow::Error::from(e).context(format!("reading {}", base.display()));
    let entries = match std::fs::read_dir(base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(read(e)),
    };
    let mut rows = Vec::new();
    for e in entries {
        let e = e.map_err(read)?;
        let kind = match e.file_type() {
            Ok(kind) => kind,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(
                    anyhow::Error::from(err).context(format!("reading {}", e.path().display()))
                );
            }
        };
        if kind.is_dir() {
            rows.push(row(&e.path(), running, sizes, true));
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

/// Like [`scan`], but only for running environments under `base`, without flags or sizes.
/// Reads only running state dirs, never workspaces, to avoid triggering automounts or
/// blocking on hung shares, even for stopped environments.
pub fn running_rows(base: &Path, running: &[Running]) -> Vec<Row> {
    let base = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    running
        .iter()
        .filter(|r| r.state_dir.parent() == Some(base.as_path()))
        .map(|r| row(&r.state_dir, running, false, false))
        .collect()
}

fn row(dir: &Path, running: &[Running], with_sizes: bool, with_flags: bool) -> Row {
    let identity = std::fs::read(dir.join("dev.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<crate::dev::Identity>(&b).ok());
    let manifest = |key: &str| -> Option<String> {
        Some(identity.as_ref()?.manifest.get(key)?.as_str()?.to_string())
    };
    let workspace = manifest("workspace").map(PathBuf::from);
    // The registry records canonical state dirs, so compare against both forms: the base
    // itself reaches us through `$HOME`, which is a symlink on some hosts.
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let live = running
        .iter()
        .find(|r| r.state_dir == dir || r.state_dir == canonical);
    let mut flags = Vec::new();
    // Require the workspace's parent to exist: an unmounted share or unplugged disk must
    // not make its environments stale and let `gc --all-stale --yes` destroy their storage.
    if with_flags
        && let Some(w) = &workspace
        && !w.exists()
        && w.parent().is_some_and(Path::exists)
    {
        flags.push(Flag::WorkspaceMissing);
    }
    // Use the identity, as `status` does. An unreadable `dev.json` also leaves no record
    // and must remain collectable.
    if with_flags && identity.is_none() {
        flags.push(Flag::Ephemeral);
    }
    let booted_secs = identity.as_ref().map(|i| i.booted_secs);
    Row {
        name: dir.file_name().unwrap_or_default().to_string_lossy().into(),
        dir_name: dir.file_name().unwrap_or_default().to_string_lossy().into(),
        dir: dir.to_path_buf(),
        workspace,
        workspace_folder: manifest("workspace_folder"),
        config: manifest("config").map(PathBuf::from),
        primary: (identity.as_ref())
            .and_then(|i| i.manifest.pointer("/source/Compose/service")?.as_str())
            .map(String::from),
        environment: manifest("environment"),
        status: match (live.is_some(), identity.is_some()) {
            (true, _) => Status::Running,
            (false, true) => Status::Stopped,
            (false, false) => Status::NeverBooted,
        },
        created_by: identity
            .as_ref()
            .map(|i| i.created_by.clone())
            .filter(|by| !by.is_empty()),
        booted_secs,
        age_secs: booted_secs.map(|s| crate::vms::unix_now().saturating_sub(s)),
        mem_used_bytes: live.and_then(|r| r.mem_used),
        mem: live.and_then(|r| r.mem.clone()),
        size_bytes: with_sizes.then(|| crate::dev::storage::dir_size(dir)),
        flags,
        deletable: owned(dir).is_ok(),
        services: Vec::new(),
    }
}

/// The state directory's top-level entries, minus the ones a running VM owns rather than the
/// user: console and switch logs, and the sockets it listens on. What is left is what
/// removing the directory actually destroys — the editor's server storage, managed mounts,
/// the SSH identity, the root image, the recorded endpoints.
pub fn contents(dir: &Path) -> Vec<Entry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<Entry> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let socket = e.file_type().is_ok_and(|t| t.is_socket());
            // `vk`'s own bookkeeping (`.virtkit-active` and the like) is not data.
            !socket && !name.ends_with(".log") && !name.starts_with(".virtkit-")
        })
        .map(|e| Entry {
            name: e.file_name().to_string_lossy().into(),
            size_bytes: match e.file_type().is_ok_and(|t| t.is_dir()) {
                true => crate::dev::storage::dir_size(&e.path()),
                false => e.metadata().map(|m| m.len()).unwrap_or(0),
            },
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Column layout for `vk list` and the dev environment, storage and endpoint tables.
/// Widths include the header. Columns have two spaces between them and no trailing
/// padding. Short rows keep their columns, and extra cells widen the table.
pub(crate) fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut width: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            let seen = cell.chars().count();
            match width.get_mut(i) {
                Some(w) => *w = (*w).max(seen),
                None => width.push(seen),
            }
        }
    }
    let header: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    let mut out = String::new();
    for row in std::iter::once(&header).chain(rows) {
        let line: Vec<String> = row
            .iter()
            .zip(&width)
            .map(|(cell, w)| format!("{cell:<width$}", width = *w))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

/// Render one row per environment and a `NAME/SERVICE` row per declared secondary service.
/// A declaration without state has dashes for its VM name, creator, last boot and usage.
/// Service rows have no creator, last boot or memory reading. `wide` shows full workspace
/// paths instead of their shortest distinguishing suffixes.
pub fn render(rows: &[Row], wide: bool) -> String {
    if rows.is_empty() {
        return "no dev environment state on this host\n".into();
    }
    let dash = || "-".to_string();
    let listed: Vec<&Path> = rows.iter().filter_map(|r| r.workspace.as_deref()).collect();
    let short = short_paths(&listed);
    let mut lines: Vec<Vec<String>> = Vec::new();
    for r in rows {
        let not_built = r.status == Status::NotBuilt;
        let workspace = match (&r.workspace, wide) {
            (None, _) => "?".to_string(),
            (Some(w), true) => w.display().to_string(),
            (Some(w), false) => short
                .get(w.as_path())
                .cloned()
                .unwrap_or_else(|| w.display().to_string()),
        };
        let environment = r.environment.clone().unwrap_or_else(|| "?".into());
        let name = match not_built {
            true => dash(),
            false => r.name.clone(),
        };
        lines.push(vec![
            name.clone(),
            workspace.clone(),
            environment.clone(),
            r.status.label().into(),
            match not_built {
                true => dash(),
                false => r
                    .created_by
                    .as_deref()
                    .map(short_creator)
                    .unwrap_or_default(),
            },
            match not_built {
                true => dash(),
                false => r.age_secs.map(crate::vms::fmt_uptime).unwrap_or_default(),
            },
            crate::vms::mem_cell(r.mem_used_bytes, r.mem.as_deref()),
            fmt_size(r.size_bytes),
            r.flags
                .iter()
                .map(|f| f.label())
                .collect::<Vec<_>>()
                .join(", "),
        ]);
        for s in &r.services {
            lines.push(vec![
                format!("{name}/{}", s.name),
                workspace.clone(),
                environment.clone(),
                s.status.clone().unwrap_or_else(dash),
                dash(),
                dash(),
                dash(),
                fmt_size(s.size_bytes),
                String::new(),
            ]);
        }
    }
    let rows = lines;
    table(
        &[
            "NAME",
            "WORKSPACE",
            "ENV",
            "STATUS",
            "CREATED BY",
            "LAST BOOT",
            "MEM",
            "ON DISK",
            "FLAGS",
        ],
        &rows,
    )
}

/// Use the shortest unique suffix: `shop` alone, or `a/shop` and `b/shop` for two
/// checkouts. Keep the full path if it is itself a suffix of another path.
fn short_paths<'a>(paths: &[&'a Path]) -> std::collections::HashMap<&'a Path, String> {
    let mut distinct: Vec<&Path> = paths.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    let tail = |p: &Path, n: usize| -> Option<PathBuf> {
        let parts: Vec<_> = p.components().collect();
        // Not the whole of it: the root is no part of a short form.
        (n < parts.len()).then(|| parts[parts.len() - n..].iter().collect())
    };
    distinct
        .iter()
        .map(|p| {
            let short = (1..)
                .map_while(|n| tail(p, n))
                .find(|short| {
                    !distinct
                        .iter()
                        .any(|other| other != p && other.ends_with(short))
                })
                .map_or_else(|| p.display().to_string(), |s| s.display().to_string());
            (*p, short)
        })
        .collect()
}

/// A size the caller asked for, or `-` where there is none to show — either because the
/// caller did not ask to measure, or because there is nothing there yet.
pub(super) fn fmt_size(size: Option<u64>) -> String {
    size.map(fmt_bytes).unwrap_or_else(|| "-".into())
}

/// The creator, shortened to the release: what was recorded is `vk --version` in full, whose
/// commit hash would double the column's width without telling the reader anything a
/// `vk dev status` would not.
fn short_creator(created_by: &str) -> String {
    created_by
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Which rows a `gc` takes: the ones named, plus — under `--all-stale` — every one whose
/// checkout is gone or that never recorded a boot. A running environment is never removed;
/// naming one is an error, not a silent skip.
/// `resolve` maps a word to the state dir it names, as [`crate::names::resolve`] does.
pub fn select_gc(
    rows: Vec<Row>,
    names: &[String],
    all_stale: bool,
    resolve: impl Fn(&str) -> Result<Option<PathBuf>>,
) -> Result<Vec<Row>> {
    // The CLI calls this only for `--all-stale`. Reject an empty selection from other callers.
    if names.is_empty() && !all_stale {
        bail!("name an environment to remove (`vk dev list`), or pass --all-stale");
    }
    let mut selected: Vec<Row> = Vec::new();
    for name in names {
        selected.push(find(&rows, name, &resolve)?.clone());
    }
    if all_stale {
        selected.extend(rows.iter().filter(|r| r.stale()).cloned());
    }
    selected.sort_by(|a, b| a.name.cmp(&b.name));
    selected.dedup_by(|a, b| a.dir == b.dir);
    refuse_running(selected)
}

/// The rows on the state dirs `dirs`, as `gc` resolved them in this workspace: by directory,
/// so a name taken by another environment meanwhile does not redirect it. A dir without state
/// selects nothing.
pub fn select_dirs(rows: Vec<Row>, dirs: &[PathBuf]) -> Result<Vec<Row>> {
    let dirs: Vec<PathBuf> = dirs.iter().map(|d| crate::vms::canonical(d)).collect();
    refuse_running(
        rows.into_iter()
            .filter(|r| dirs.contains(&crate::vms::canonical(&r.dir)))
            .collect(),
    )
}

/// `selected`, unless one of them is running.
fn refuse_running(selected: Vec<Row>) -> Result<Vec<Row>> {
    if let Some(row) = selected.iter().find(|r| r.status == Status::Running) {
        bail!("{} is running — `vk stop {}` first", row.name, row.name);
    }
    Ok(selected)
}

/// Resolve `word` to a directory before selecting its row. [`crate::names::resolve`]
/// rejects a VM name that also names a different state directory.
pub fn find<'a>(
    rows: &'a [Row],
    word: &str,
    resolve: impl Fn(&str) -> Result<Option<PathBuf>>,
) -> Result<&'a Row> {
    let Some(dir) = resolve(word)? else {
        bail!("no dev environment state named {word} (`vk dev list --all` names them)");
    };
    let dir = crate::vms::canonical(&dir);
    rows.iter()
        .find(|r| crate::vms::canonical(&r.dir) == dir)
        .with_context(|| format!("{word} is not a dev environment ({})", dir.display()))
}

/// Preview each selected environment with its top-level state entries and sizes,
/// so durable storage is visible before removal.
pub fn preview(selected: &[Row]) -> String {
    let mut out = format!("would remove {} environment(s):\n", selected.len());
    for row in selected {
        out.push_str(&format!(
            "  {}  {}  {}\n",
            row.name,
            row.workspace
                .as_ref()
                .map(|w| w.display().to_string())
                .unwrap_or_else(|| "?".into()),
            fmt_size(row.size_bytes)
        ));
        for entry in contents(&row.dir) {
            out.push_str(&format!(
                "    {}  {}\n",
                entry.name,
                fmt_bytes(entry.size_bytes)
            ));
        }
    }
    out
}

/// Take a state directory's lock — the one a boot and a live run hold — for as long as the
/// returned file lives. `None` when somebody else holds it, or when the directory is gone.
pub(crate) fn try_lock_state_dir(dir: &Path) -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(dir).ok()?;
    // SAFETY: the fd is owned by `f`, which the caller keeps alive; LOCK_NB does not block.
    match unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } {
        0 => Some(f),
        _ => None,
    }
}

/// Remove selected state directories after stopping their publishers.
///
/// Lock all directories before removing any, and hold each lock until its directory is gone.
/// Refuse the whole operation if a boot or live VM holds a lock. Selection predates the
/// prompt, so these locks and a fresh running-VM check protect boots started meanwhile.
/// Each one's names are forgotten in `index`, under its lock across the removal, so a boot
/// that makes the directory again meanwhile keeps the name it claims.
pub fn remove(selected: &[Row], index: &crate::names::Index) -> Result<String> {
    let mut locked = Vec::new();
    for row in selected {
        let Some(lock) = try_lock_state_dir(&row.dir) else {
            let held = crate::dev::lock_holder(&row.dir).unwrap_or_else(|| "another vk".into());
            bail!(
                "{} is in use by {held} — try again when it is done",
                row.name
            );
        };
        locked.push((row, lock));
    }
    let running = running_dirs();
    for (row, _) in &locked {
        let canonical = std::fs::canonicalize(&row.dir).unwrap_or_else(|_| row.dir.clone());
        if running.iter().any(|r| *r == row.dir || *r == canonical) {
            bail!("{} is running — `vk stop {}` first", row.name, row.name);
        }
    }
    let mut out = String::new();
    for (row, lock) in locked {
        // A cache-only start may have restored the identity since GC listed this directory.
        if row.stale() && !self::row(&row.dir, &[], false, true).stale() {
            out.push_str(&format!("kept {}: it is no longer stale\n", row.name));
            continue;
        }
        crate::publish::stop_all_quietly(&row.dir, PUBLISH_STOP);
        let names = index.lock()?;
        std::fs::remove_dir_all(&row.dir)
            .with_context(|| format!("removing {}", row.dir.display()))?;
        if let Err(e) = index.release_locked(&row.dir) {
            eprintln!("vk: warning: forgetting the name of {}: {e:#}", row.name);
        }
        drop(names);
        drop(lock);
        out.push_str(&format!(
            "removed {} ({})\n",
            row.name,
            fmt_size(row.size_bytes)
        ));
    }
    Ok(out)
}

/// Running VMs' state directories. `remove` needs only liveness, so this skips the memory
/// walk in [`running_vms`].
fn running_dirs() -> Vec<PathBuf> {
    crate::vms::running()
        .into_iter()
        .map(|e| e.state_dir)
        .collect()
}
/// Always read live memory so a missing figure means it was unavailable. One `/proc`
/// walk per VM is cheaper than the optional disk walk over every file.
fn running_vms(live: &[crate::vms::VmEntry]) -> Vec<Running> {
    live.iter()
        .map(|e| Running {
            mem_used: i32::try_from(e.pid)
                .ok()
                .and_then(crate::usage::tree_resident),
            mem: e.mem.clone(),
            state_dir: e.state_dir.clone(),
        })
        .collect()
}

/// Every environment this host keeps state for, as `vk dev list --all` sees it:
/// the state base scanned against what is running. Measuring what each holds on disk is a stat
/// walk of every file in it, done by default; `--no-sizes` (`sizes = false`) opts out.
pub fn state(sizes: bool) -> Result<Vec<Row>> {
    state_in(&crate::vms::running(), sizes)
}

/// [`state`] against `live`, the running VMs as the caller read them.
pub fn state_in(live: &[crate::vms::VmEntry], sizes: bool) -> Result<Vec<Row>> {
    let mut rows = scan(
        &crate::dev::plan::dev_state_base()?,
        &running_vms(live),
        sizes,
    )?;
    apply_names(&mut rows);
    Ok(rows)
}

/// Measure disk usage after filtering rows so excluded directories need no walk.
pub fn measure(rows: &mut [Row]) {
    for row in rows {
        row.size_bytes = Some(crate::dev::storage::dir_size(&row.dir));
    }
}

/// Name every row as the name index does, naming the environments that have none first,
/// and order them by name.
pub fn apply_names(rows: &mut [Row]) {
    name_unnamed();
    let Ok(idx) = crate::names::Index::open() else {
        return;
    };
    let all = idx.all();
    for row in rows.iter_mut() {
        let canonical = crate::vms::canonical(&row.dir);
        if let Some((name, _)) = all.iter().find(|(_, d)| *d == row.dir || *d == canonical) {
            row.name = name.clone();
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
}

/// [`state`] without sizes or flags: no workspace is looked at, so a hung share or an
/// automount cannot stall the caller — a background `vk gc`, which holds its lock meanwhile.
pub fn state_unflagged() -> Result<Vec<Row>> {
    let base = crate::dev::plan::dev_state_base()?;
    let running = running_vms(&crate::vms::running());
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Ok(Vec::new());
    };
    let mut rows: Vec<Row> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| row(&e.path(), &running, false, false))
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

/// The rows as `--json` prints them: `name` is `null` for a [`Status::NotBuilt`] row, which
/// `dir_name` still identifies.
pub fn json(rows: &[Row]) -> Result<String> {
    #[derive(Serialize)]
    struct Named<'a> {
        name: Option<&'a str>,
        #[serde(flatten)]
        row: &'a Row,
    }
    let rows: Vec<Named> = rows
        .iter()
        .map(|row| Named {
            name: (row.status != Status::NotBuilt).then_some(row.name.as_str()),
            row,
        })
        .collect();
    Ok(format!("{}\n", serde_json::to_string_pretty(&rows)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn scratch(tag: &str) -> TmpDir {
        let dir = std::env::temp_dir().join(format!("vk-devlist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }

    /// A scratch name index beside the scratch dev base `base`.
    fn index(base: &Path) -> crate::names::Index {
        crate::names::Index::at(base.with_file_name("names"))
    }

    /// What `names::resolve` does, against [`index`] and `base`.
    fn resolver(base: &Path) -> impl Fn(&str) -> Result<Option<PathBuf>> + '_ {
        move |word| crate::names::resolve_in(&index(base), base, word)
    }

    /// A state dir with a `dev.json` recording `workspace`, as `after_boot` writes one.
    fn booted(base: &Path, name: &str, workspace: &Path, created_by: &str) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = serde_json::json!({
            "digest": "d",
            "booted_secs": crate::vms::unix_now() - 120,
            "created_by": created_by,
            "manifest": {
                "workspace": workspace.display().to_string(),
                "environment": "dev",
            },
        });
        std::fs::write(dir.join("dev.json"), identity.to_string()).unwrap();
        std::fs::write(dir.join("console.log"), "boot\n").unwrap();
        std::fs::write(dir.join("id_ed25519"), "key").unwrap();
        dir
    }

    /// What an ephemeral task run leaves behind: a root image and console logs, no identity.
    fn ephemeral(base: &Path, name: &str) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("root.qcow2"), vec![0u8; 4096]).unwrap();
        std::fs::write(dir.join("console.log"), "boot\n").unwrap();
        dir
    }

    /// Declared environments and their secondary services precede undeclared state.
    /// A missing environment has status `not-built`. A stopped service needs a console log.
    #[test]
    fn declared_environments_and_their_services_are_listed() {
        let tmp = scratch("declared");
        let base = tmp.0.join("dev");
        let ws = tmp.0.join("shop");
        let dev = booted(&base, "shop-aaaa", &ws, "vk 1.0.0");
        let old = booted(&base, "shop-old-bbbb", &ws, "vk 1.0.0");
        std::fs::create_dir_all(dev.join("svc-db")).unwrap();
        std::fs::write(dev.join("svc-db").join(crate::run::CONSOLE_LOG), "").unwrap();
        let declare = |environment: &str, state_dir: PathBuf| Declared {
            environment: environment.into(),
            workspace: ws.clone(),
            state_dir,
            services: vec!["db".into(), "cache".into()],
        };
        let declared = [
            declare("dev", dev.clone()),
            declare("ci", base.join("shop-ci-cccc")),
        ];
        let rows = with_services(scan(&base, &[], false).unwrap(), &declared, false, &|_| {
            None
        });
        let dirs: Vec<&Path> = rows.iter().map(|r| r.dir.as_path()).collect();
        assert_eq!(dirs, [dev.as_path(), &base.join("shop-ci-cccc"), &old]);
        assert_eq!(rows[0].status, Status::Stopped);
        let status: Vec<Option<&str>> = rows[0]
            .services
            .iter()
            .map(|s| s.status.as_deref())
            .collect();
        assert_eq!(status, [Some("stopped"), None]);
        assert_eq!(rows[1].status, Status::NotBuilt);
        assert_eq!(rows[1].name, "shop-ci-cccc");
        assert!(!rows[1].deletable);
        assert!(rows[1].services.iter().all(|s| s.status.is_none()));
        assert!(rows[2].services.is_empty());
        let out = render(&rows, false);
        assert!(out.lines().any(|l| l.starts_with("shop-aaaa/db ")), "{out}");
        assert_eq!(serde_json::to_value(Status::NotBuilt).unwrap(), "not-built");
    }

    /// Report read errors so declared environments cannot be mistaken for missing state.
    #[test]
    fn an_unreadable_base_is_an_error_not_an_empty_inventory() {
        let tmp = scratch("unreadable");
        assert!(scan(&tmp.0.join("gone"), &[], false).unwrap().is_empty());
        let file = tmp.0.join("file");
        std::fs::write(&file, "").unwrap();
        let err = format!("{:#}", scan(&file, &[], false).unwrap_err());
        assert!(err.contains("reading"), "{err}");
    }

    /// Both workspaces would claim `shop`. Show `-` for the unbuilt one so a copied name
    /// cannot stop the other workspace's VM.
    #[test]
    fn an_environment_never_brought_up_borrows_no_name() {
        let tmp = scratch("unnamed");
        let base = tmp.0.join("dev");
        let theirs = booted(&base, "shop-aaaa", &tmp.0.join("a/shop"), "vk 1.0.0");
        let mut all = scan(&base, &[], false).unwrap();
        all[0].name = "shop".into();
        assert_eq!(all[0].dir, theirs);
        let declared = [Declared {
            environment: "dev".into(),
            workspace: tmp.0.join("b/shop"),
            state_dir: base.join("shop-bbbb"),
            services: vec!["db".into()],
        }];
        let rows = with_services(Vec::new(), &declared, false, &|_| None);
        assert_eq!(rows[0].name, "shop-bbbb");
        let out = render(&rows, false);
        let lines: Vec<&str> = out.lines().skip(1).collect();
        assert!(
            lines[0].starts_with("-  ") && lines[0].contains("not built"),
            "{out}"
        );
        assert!(lines[1].starts_with("-/db "), "{out}");
        assert!(!out.lines().any(|l| l.starts_with("shop")), "{out}");
    }

    /// A failed first boot keeps its on-disk state and takes its identity from the declaration.
    #[test]
    fn a_declared_dir_with_state_but_no_identity_keeps_what_it_holds() {
        let tmp = scratch("half-booted");
        let base = tmp.0.join("dev");
        let ws = tmp.0.join("shop");
        let dir = ephemeral(&base, "shop-aaaa");
        let declared = [Declared {
            environment: "ci".into(),
            workspace: ws.clone(),
            state_dir: dir.clone(),
            services: Vec::new(),
        }];
        let rows = with_services(scan(&base, &[], true).unwrap(), &declared, false, &|_| None);
        assert_eq!(rows.len(), 1, "{rows:?}");
        let row = &rows[0];
        assert_eq!(row.status, Status::NeverBooted);
        assert_eq!(row.flags, [Flag::Ephemeral]);
        assert!(row.size_bytes.is_some_and(|n| n > 0));
        assert_eq!(row.workspace.as_deref(), Some(ws.as_path()));
        assert_eq!(row.environment.as_deref(), Some("ci"));
    }

    /// Previously booted services are unknown if the running manager is unreachable and
    /// stopped if the environment is down. Service rows omit the creator and last boot.
    #[test]
    fn a_service_is_unknown_when_its_running_manager_cannot_be_asked() {
        let tmp = scratch("unreachable");
        let base = tmp.0.join("dev");
        let dir = booted(&base, "shop-aaaa", &tmp.0.join("shop"), "vk 1.0.0");
        for svc in ["db", "cache"] {
            std::fs::create_dir_all(dir.join(format!("svc-{svc}"))).unwrap();
            std::fs::write(
                dir.join(format!("svc-{svc}/{}", crate::run::CONSOLE_LOG)),
                "",
            )
            .unwrap();
        }
        let declared = [Declared {
            environment: "dev".into(),
            workspace: tmp.0.join("shop"),
            state_dir: dir.clone(),
            services: vec!["db".into(), "cache".into(), "web".into()],
        }];
        let live = Running {
            state_dir: dir.clone(),
            mem_used: None,
            mem: None,
        };
        let statuses = |running: &[Running], states: &UnitStates| -> Vec<Option<String>> {
            let rows = with_services(
                scan(&base, running, false).unwrap(),
                &declared,
                false,
                states,
            );
            rows[0].services.iter().map(|s| s.status.clone()).collect()
        };
        let s = |v: &str| Some(v.to_string());
        let up = std::slice::from_ref(&live);
        assert_eq!(statuses(up, &|_| None), [s("unknown"), s("unknown"), None]);
        let reported = |_: &Path| Some(vec![("db".to_string(), "running".to_string())]);
        assert_eq!(statuses(up, &reported), [s("running"), s("stopped"), None]);
        assert_eq!(statuses(&[], &reported), [s("stopped"), s("stopped"), None]);
        let rows = with_services(scan(&base, up, false).unwrap(), &declared, false, &reported);
        let out = render(&rows, false);
        let db = out
            .lines()
            .find(|l| l.starts_with("shop-aaaa/db "))
            .unwrap();
        assert!(!db.contains("vk 1.0.0"), "{out}");
    }

    #[test]
    fn workspaces_are_shortened_to_what_tells_them_apart() {
        let paths = [
            Path::new("/home/me/code/shop"),
            Path::new("/home/me/code/api"),
            Path::new("/home/me/work/shop"),
            Path::new("/srv/ci/builds/7/work/shop"),
            Path::new("/home/me/code/shop"),
        ];
        let short = short_paths(&paths);
        assert_eq!(short[paths[0]], "code/shop");
        assert_eq!(short[paths[1]], "api");
        assert_eq!(short[paths[2]], "me/work/shop");
        assert_eq!(short[paths[3]], "7/work/shop");
        assert_eq!(short.len(), 4, "the same workspace twice is one");
        // Alone, a name is enough; a path that is another's tail stays whole.
        let alone = Path::new("/a/b/shop");
        assert_eq!(short_paths(&[alone])[alone], "shop");
        let nested = [Path::new("/shop"), Path::new("/x/shop")];
        let short = short_paths(&nested);
        assert_eq!(short[nested[0]], "/shop");
        assert_eq!(short[nested[1]], "x/shop");
    }

    #[test]
    fn unnamed_environments_get_names_oldest_boot_first_and_ephemeral_ones_none() {
        let tmp = scratch("names");
        let base = tmp.0.join("dev");
        let idx = crate::names::Index::at(tmp.0.join("names"));
        let with = |name: &str, ws: &str, env: &str, booted: u64| {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let identity = serde_json::json!({
                "digest": "d", "booted_secs": booted,
                "manifest": {"workspace": ws, "environment": env},
            });
            std::fs::write(dir.join("dev.json"), identity.to_string()).unwrap();
            crate::vms::canonical(&dir)
        };
        // Two checkouts named `app`: the one booted first keeps the plain name.
        let newer = with("app-1111", "/a/app", "dev", 200);
        let older = with("app-2222", "/b/app", "dev", 100);
        let ci = with("app-ci-3333", "/a/app", "ci", 300);
        ephemeral(&base, "app-task-x-44");
        name_unnamed_in(&base, &idx).unwrap();
        assert_eq!(idx.name_of(&older).as_deref(), Some("app"));
        assert_eq!(idx.name_of(&newer).as_deref(), Some("app-2"));
        assert_eq!(idx.name_of(&ci).as_deref(), Some("app-ci"));
        assert_eq!(idx.all().len(), 3);
        // Run again, nothing changes.
        name_unnamed_in(&base, &idx).unwrap();
        assert_eq!(idx.all().len(), 3);
        assert_eq!(default_name(Path::new("/x/My Repo"), "dev"), "my-repo");
        assert_eq!(default_name(Path::new("/"), "e2e"), "workspace-e2e");
    }

    #[test]
    fn a_live_checkout_is_not_stale_and_a_deleted_one_is() {
        let tmp = scratch("stale");
        let base = tmp.0.join("state");
        let workspace = tmp.0.join("repo");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&base).unwrap();
        booted(&base, "repo-aaaa", &workspace, "vk 0.62.0 (abcdef)");
        booted(
            &base,
            "gone-bbbb",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abcdef)",
        );

        let rows = scan(&base, &[], true).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["gone-bbbb", "repo-aaaa"]
        );
        let gone = &rows[0];
        assert_eq!(gone.flags, [Flag::WorkspaceMissing]);
        assert_eq!(gone.status, Status::Stopped);
        assert!(gone.stale());
        let live = &rows[1];
        assert_eq!(live.flags, []);
        assert_eq!(live.workspace.as_deref(), Some(workspace.as_path()));
        assert_eq!(live.environment.as_deref(), Some("dev"));
        assert_eq!(live.created_by.as_deref(), Some("vk 0.62.0 (abcdef)"));
        assert!(!live.stale());
        assert!(live.size_bytes.is_some_and(|n| n > 0));
    }

    /// Only the running environments are read, and none is flagged: a stopped one, or one
    /// whose workspace is gone, is not looked at.
    #[test]
    fn running_rows_read_only_the_running_environments() {
        let tmp = scratch("running-rows");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        let up = booted(&base, "gone-aaaa", &tmp.0.join("removed"), "vk 0.80.0");
        booted(&base, "down-bbbb", &tmp.0.join("repo"), "vk 0.80.0");
        let elsewhere = tmp.0.join("not-dev");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let running = |dir: &Path| Running {
            state_dir: std::fs::canonicalize(dir).unwrap(),
            mem_used: None,
            mem: Some("2G".into()),
        };
        let rows = running_rows(&base, &[running(&up), running(&elsewhere)]);
        assert_eq!(rows.len(), 1, "{rows:?}");
        let row = &rows[0];
        assert_eq!(row.name, "gone-aaaa");
        assert_eq!(row.status, Status::Running);
        assert_eq!(row.environment.as_deref(), Some("dev"));
        assert_eq!(row.flags, [], "the missing workspace is not looked at");
        assert_eq!(row.size_bytes, None);
    }

    #[test]
    fn a_directory_with_no_identity_is_ephemeral_and_never_booted() {
        let tmp = scratch("ephemeral");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        ephemeral(&base, "repo-hook-cccc");

        let rows = scan(&base, &[], true).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, Status::NeverBooted);
        assert_eq!(rows[0].flags, [Flag::Ephemeral]);
        assert_eq!(rows[0].workspace, None);
        assert_eq!(rows[0].booted_secs, None);
        assert!(rows[0].stale());
        assert!(!rows[0].deletable);
    }

    /// `vk delete` removes whole only a directory that recorded its boot and holds no run's
    /// recipe beside it; the row says so with the same check.
    #[test]
    fn only_a_directory_that_is_a_dev_environment_s_alone_is_deletable() {
        let tmp = scratch("deletable");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        let gone = tmp.0.join("gone");
        booted(&base, "alone-aaaa", &gone, "vk 1");
        let mixed = booted(&base, "mixed-bbbb", &gone, "vk 1");
        std::fs::write(mixed.join(crate::names::RECIPE), "{}").unwrap();

        let rows = scan(&base, &[], false).unwrap();
        let by = |name: &str| rows.iter().find(|r| r.name == name).unwrap();
        assert!(by("alone-aaaa").deletable);
        assert!(!by("mixed-bbbb").deletable);
        assert_eq!(by("mixed-bbbb").status, Status::Stopped);
        assert!(owned(&mixed).is_err());
    }

    #[test]
    fn a_workspace_whose_whole_mount_is_gone_is_not_stale() {
        let tmp = scratch("unmounted");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        // The checkout was deleted out of a directory that is still there: stale.
        booted(
            &base,
            "gone-aaaa",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abc)",
        );
        // The directory that held it is gone too — an unmounted share or an unplugged
        // disk, not a deleted checkout — so its durable storage is nobody's to collect.
        booted(
            &base,
            "unmounted-bbbb",
            &tmp.0.join("mnt/nas/repo"),
            "vk 0.62.0 (abc)",
        );

        let rows = scan(&base, &[], false).unwrap();
        let by = |n: &str| rows.iter().find(|r| r.name == n).unwrap();
        assert_eq!(by("gone-aaaa").flags, [Flag::WorkspaceMissing]);
        assert!(by("gone-aaaa").stale());
        assert_eq!(by("unmounted-bbbb").flags, []);
        assert!(!by("unmounted-bbbb").stale());
        // Nothing was measured either, and the JSON says so by leaving the field out.
        assert_eq!(by("gone-aaaa").size_bytes, None);
        let json = serde_json::to_string(by("gone-aaaa")).unwrap();
        assert!(!json.contains("size_bytes"), "{json}");
    }

    #[test]
    fn an_unreadable_identity_is_as_collectable_as_a_missing_one() {
        let tmp = scratch("corrupt");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(base.join("half-aaaa")).unwrap();
        std::fs::write(base.join("half-aaaa/dev.json"), "{\"digest\":").unwrap();

        let rows = scan(&base, &[], false).unwrap();
        assert_eq!(rows[0].status, Status::NeverBooted);
        assert_eq!(
            rows[0].flags,
            [Flag::Ephemeral],
            "a dev.json nothing can read records nothing"
        );
        assert!(rows[0].stale(), "or `gc --all-stale` could never take it");
    }

    #[test]
    fn a_directory_somebody_is_booting_is_not_removed() {
        // Holds a state-dir lock across the assertions; a concurrent fork must not inherit it.
        let _env = crate::dev::testutil::env_guard();
        let tmp = scratch("locked");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        let dir = booted(
            &base,
            "gone-bbbb",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abc)",
        );
        let selected =
            select_gc(scan(&base, &[], true).unwrap(), &[], true, resolver(&base)).unwrap();

        // A boot that started while the caller was answering the prompt holds the lock.
        let held = try_lock_state_dir(&dir).expect("free to begin with");
        let e = remove(&selected, &index(&base)).unwrap_err();
        assert!(format!("{e:#}").contains("is in use by"), "{e:#}");
        assert!(dir.exists(), "the boot's state directory survived");
        drop(held);
        let removed =
            crate::testutil::once_released("is in use by", || remove(&selected, &index(&base)))
                .unwrap();
        assert!(removed.starts_with("removed gone-bbbb"));
        assert!(!dir.exists());
    }

    #[test]
    fn a_running_environment_is_reported_and_never_selected() {
        let tmp = scratch("running");
        let base = tmp.0.join("state");
        let workspace = tmp.0.join("repo");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&base).unwrap();
        let dir = booted(&base, "repo-aaaa", &workspace, "vk 0.62.0 (abcdef)");

        let live = Running {
            state_dir: dir,
            mem_used: Some(1_288_490_189),
            mem: Some("8G".into()),
        };
        let rows = scan(&base, std::slice::from_ref(&live), true).unwrap();
        assert_eq!(rows[0].status, Status::Running);
        // A running row carries the live figure and the size it booted with, so the MEM
        // column has both halves; a stopped one has neither (see the render test).
        assert_eq!(rows[0].mem_used_bytes, Some(1_288_490_189));
        assert_eq!(rows[0].mem.as_deref(), Some("8G"));
        assert!(!rows[0].stale());
        let e = select_gc(rows, &["repo-aaaa".into()], false, resolver(&base)).unwrap_err();
        assert!(format!("{e:#}").contains("repo-aaaa is running"), "{e:#}");
    }

    #[test]
    fn selection_takes_names_and_all_stale_and_rejects_an_unknown_one() {
        let tmp = scratch("select");
        let base = tmp.0.join("state");
        let workspace = tmp.0.join("repo");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&base).unwrap();
        booted(&base, "repo-aaaa", &workspace, "vk 0.62.0 (abcdef)");
        booted(
            &base,
            "gone-bbbb",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abcdef)",
        );
        ephemeral(&base, "repo-hook-cccc");
        let rows = scan(&base, &[], true).unwrap();

        let stale = select_gc(rows.clone(), &[], true, resolver(&base)).unwrap();
        assert_eq!(
            stale.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["gone-bbbb", "repo-hook-cccc"]
        );
        // A name is taken whether or not it is stale, and never twice.
        let named = select_gc(rows.clone(), &["repo-aaaa".into()], true, resolver(&base)).unwrap();
        assert_eq!(named.len(), 3);
        let both = select_gc(rows.clone(), &["gone-bbbb".into()], true, resolver(&base)).unwrap();
        assert_eq!(both.len(), 2);
        let e = select_gc(rows.clone(), &["nope".into()], false, resolver(&base)).unwrap_err();
        assert!(
            format!("{e:#}").contains("no dev environment state named nope"),
            "{e:#}"
        );
        let e = select_gc(rows, &[], false, resolver(&base)).unwrap_err();
        assert!(format!("{e:#}").contains("--all-stale"), "{e:#}");
    }

    /// Environment A is named `app` in `app-aaaa`. A workspace called `app-aaaa` gets that
    /// as its VM name, as can a `vk run --name app-aaaa`: the word then names two VMs, so a
    /// destructive command refuses it, as `vk dev stop` does. Each one's other name, or a
    /// bare `gc`'s own state dir, selects only that one.
    #[test]
    fn a_name_that_is_another_vms_dir_name_is_refused() {
        let tmp = scratch("collide");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        let (a_ws, b_ws) = (tmp.0.join("app"), tmp.0.join("app-aaaa"));
        for ws in [&a_ws, &b_ws] {
            std::fs::create_dir_all(ws).unwrap();
        }
        let a = booted(&base, "app-aaaa", &a_ws, "vk 0.62.0 (abcdef)");
        let b = booted(&base, "app-aaaa-bbbb", &b_ws, "vk 0.62.0 (abcdef)");
        let idx = index(&base);
        idx.claim_exact(&a, "app").unwrap();
        idx.claim_exact(&b, "app-aaaa").unwrap();
        let rows = scan(&base, &[], false).unwrap();
        let e = select_gc(rows.clone(), &["app-aaaa".into()], false, resolver(&base)).unwrap_err();
        assert!(format!("{e:#}").contains("ambiguous"), "{e:#}");
        assert_eq!(find(&rows, "app", resolver(&base)).unwrap().dir, a);
        assert_eq!(
            find(&rows, "app-aaaa-bbbb", resolver(&base)).unwrap().dir,
            b
        );
        let own = select_dirs(rows.clone(), std::slice::from_ref(&b)).unwrap();
        assert_eq!(own.iter().map(|r| &r.dir).collect::<Vec<_>>(), [&b]);
        // A run takes over the name: the word is still two VMs', and a run is no dev row.
        idx.release(&b).unwrap();
        let run = tmp.0.join("elsewhere/app-aaaa-1234");
        std::fs::create_dir_all(&run).unwrap();
        idx.claim_exact(&run, "app-aaaa").unwrap();
        let e = find(&rows, "app-aaaa", resolver(&base)).unwrap_err();
        assert!(format!("{e:#}").contains("ambiguous"), "{e:#}");
        idx.claim_exact(&run, "runner").unwrap_err();
        idx.release(&run).unwrap();
        idx.claim_exact(&run, "runner").unwrap();
        let e = find(&rows, "runner", resolver(&base)).unwrap_err();
        assert!(format!("{e:#}").contains("not a dev environment"), "{e:#}");
    }

    /// GC forgets a removed environment's name, in the index it is given.
    #[test]
    fn removal_forgets_the_name() {
        let tmp = scratch("forget");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        let dir = booted(
            &base,
            "gone-aaaa",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abcdef)",
        );
        let idx = index(&base);
        idx.claim_exact(&dir, "gone").unwrap();
        let selected = select_gc(
            scan(&base, &[], false).unwrap(),
            &["gone".into()],
            false,
            resolver(&base),
        )
        .unwrap();
        remove(&selected, &idx).unwrap();
        assert_eq!(idx.lookup("gone"), None);
        assert!(!dir.exists());
    }

    #[test]
    fn render_aligns_the_columns_and_names_what_is_missing() {
        let tmp = scratch("render");
        let base = tmp.0.join("state");
        let workspace = tmp.0.join("repo");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let up = booted(&base, "a-live-dddd", &workspace, "vk 0.62.0 (abcdef)");
        booted(
            &base,
            "gone-bbbb",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abcdef)",
        );
        ephemeral(&base, "repo-hook-cccc");
        let live = Running {
            state_dir: up,
            mem_used: Some(1_288_490_189),
            mem: Some("8G".into()),
        };
        let mut rows = scan(&base, std::slice::from_ref(&live), true).unwrap();
        // Fixed, so the columns read the same on every run.
        for row in &mut rows {
            row.age_secs = row.age_secs.map(|_| 7200);
        }

        let out = render(&rows, true);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("NAME"), "{out}");
        assert!(
            lines[0].contains("CREATED BY  LAST BOOT  MEM      ON DISK  FLAGS"),
            "{out}"
        );
        // The running row is the only one holding memory: what its tree holds now over the
        // size it booted with, the same cell `vk list` prints.
        assert!(
            lines[1].contains("running") && lines[1].contains("1.2G/8G"),
            "{out}"
        );
        assert!(
            lines[2].contains("stopped") && lines[2].contains("vk 0.62.0"),
            "{out}"
        );
        // A stopped environment holds nothing, and the column says so rather than guessing
        // from the `--mem` its last boot used.
        assert!(
            lines[2].contains("2h0m") && lines[2].ends_with("workspace missing"),
            "{out}"
        );
        assert!(
            lines[2].contains("  -  ") || lines[2].contains(" -       "),
            "a stopped row dashes MEM: {out}"
        );
        // Nothing was recorded, so the workspace and environment columns say so.
        assert!(lines[3].starts_with("repo-hook-cccc  ?"), "{out}");
        assert!(
            lines[3].contains("never booted") && lines[3].ends_with("ephemeral"),
            "{out}"
        );
        assert_eq!(
            render(&[], false),
            "no dev environment state on this host\n"
        );
    }

    #[test]
    fn gc_lists_the_storage_it_would_remove_and_then_removes_exactly_that() {
        let tmp = scratch("gc");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        let workspace = tmp.0.join("repo");
        std::fs::create_dir_all(&workspace).unwrap();
        let keep = booted(&base, "repo-aaaa", &workspace, "vk 0.62.0 (abcdef)");
        let go = booted(
            &base,
            "gone-bbbb",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abcdef)",
        );
        std::fs::create_dir_all(go.join("vscode-server/extensions")).unwrap();
        std::fs::write(go.join("vscode-server/extensions/x"), vec![0u8; 2048]).unwrap();
        std::fs::write(go.join("endpoints.json"), "{}").unwrap();

        let selected =
            select_gc(scan(&base, &[], true).unwrap(), &[], true, resolver(&base)).unwrap();
        let text = preview(&selected);
        assert!(
            text.starts_with("would remove 1 environment(s):\n"),
            "{text}"
        );
        assert!(text.contains("\n    vscode-server  2 KiB\n"), "{text}");
        assert!(text.contains("\n    endpoints.json  2 B\n"), "{text}");
        assert!(text.contains("\n    dev.json  "), "{text}");
        // Logs belong to the run, not the user: they are not offered as storage.
        assert!(!text.contains("console.log"), "{text}");

        let report = remove(&selected, &index(&base)).unwrap();
        assert!(report.starts_with("removed gone-bbbb ("), "{report}");
        assert!(!go.exists(), "the stale state dir survived");
        assert!(keep.exists(), "the live state dir was removed");
    }
}
