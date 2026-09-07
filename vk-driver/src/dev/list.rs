//! `vk dev list` and `vk dev gc`: every dev environment this host keeps state for, and the
//! one command that removes that state.
//!
//! [`crate::dev::plan`] derives a state directory from the canonical workspace path and the
//! environment name, so the directories under [`crate::dev::plan::dev_state_base`] are the
//! whole population — and nothing in a checkout points back at them. Deleting a worktree
//! therefore leaves its environment's storage behind with nothing to name it, and a task
//! that ran in a throwaway environment leaves a directory holding a root image and console
//! logs but no `dev.json`. Both are read here from the directories themselves rather than
//! from any config, which is why neither command resolves one.
//!
//! The scan is pure: [`scan`] turns the base directory and the set of running state dirs
//! into rows, [`select_gc`] decides which of them a `gc` takes, and only [`remove`] touches
//! anything — under each directory's own lock, the one a boot holds, so nothing is deleted
//! from under a boot that started while the caller was answering a prompt.
//!
//! `vk dev list --json` is an array of [`Row`], and its field names are the interface: they
//! are added to, never renamed or repurposed. `size_bytes` is the exception that is absent
//! rather than null — measuring a state directory walks all of it, so `--sizes` asks for it.

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::usage::fmt_bytes;

/// How long to wait for each publisher of an environment being removed to go.
const PUBLISH_STOP: std::time::Duration = std::time::Duration::from_secs(5);

/// Where an environment stands, from its state directory alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// a VM is up on this state dir
    Running,
    /// booted at some point, nothing running now
    Stopped,
    /// no identity recorded: an ephemeral run, or a boot that never completed
    NeverBooted,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Running => "running",
            Status::Stopped => "stopped",
            Status::NeverBooted => "never booted",
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

/// One state directory, as `vk dev list` reports it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Row {
    /// the directory's own name, and what `vk dev gc` takes
    pub name: String,
    pub dir: PathBuf,
    /// the workspace the identity records; `None` when nothing was recorded
    pub workspace: Option<PathBuf>,
    pub environment: Option<String>,
    pub status: Status,
    /// the `vk` that booted it, as it recorded itself
    pub created_by: Option<String>,
    pub booted_secs: Option<u64>,
    /// how long ago that boot was, at the time of the scan
    pub age_secs: Option<u64>,
    /// what the directory holds, when the caller asked to measure it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub flags: Vec<Flag>,
}

impl Row {
    fn has(&self, flag: Flag) -> bool {
        self.flags.contains(&flag)
    }

    /// Removable by `--all-stale`: nothing is running on it, and either its checkout is gone
    /// or it never recorded what it was.
    fn stale(&self) -> bool {
        self.status != Status::Running
            && (self.has(Flag::WorkspaceMissing) || self.has(Flag::Ephemeral))
    }
}

/// A top-level entry of a state directory, for the listing `gc` prints before it removes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub name: String,
    pub size_bytes: u64,
}

/// Every state directory under `base`, with `running` the state dirs VMs are up on. Reads
/// only the directories: a `dev.json` that is absent or unreadable leaves the row saying so
/// rather than dropping it, since a directory with no record is exactly what `gc` is for.
/// `sizes` measures each directory, which walks every root image and server tree under it.
pub fn scan(base: &Path, running: &[PathBuf], sizes: bool) -> Vec<Row> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut rows: Vec<Row> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| row(&e.path(), running, sizes))
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

fn row(dir: &Path, running: &[PathBuf], sizes: bool) -> Row {
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
    let is_running = running.iter().any(|r| r == dir || r == &canonical);
    let mut flags = Vec::new();
    // Gone, and the directory that held it still there. Without the second half an
    // unmounted share or an unplugged disk makes every environment on it stale, and
    // `gc --all-stale --yes` then destroys durable storage nobody meant to lose.
    if let Some(w) = &workspace
        && !w.exists()
        && w.parent().is_some_and(Path::exists)
    {
        flags.push(Flag::WorkspaceMissing);
    }
    // Keyed on the identity, the same thing `status` reads: a `dev.json` that is there but
    // unreadable is a directory with no record either, and has to stay collectable.
    if identity.is_none() {
        flags.push(Flag::Ephemeral);
    }
    let booted_secs = identity.as_ref().map(|i| i.booted_secs);
    Row {
        name: dir.file_name().unwrap_or_default().to_string_lossy().into(),
        dir: dir.to_path_buf(),
        workspace,
        environment: manifest("environment"),
        status: match (is_running, identity.is_some()) {
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
        size_bytes: sizes.then(|| crate::dev::storage::dir_size(dir)),
        flags,
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
            !socket && !name.ends_with(".log")
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

/// The padded-column renderer the dev listings share: `vk dev list`, `vk dev storage list`
/// and `vk dev endpoints`. Each column is as wide as its widest cell, header included,
/// columns are two spaces apart, and a line's trailing padding is trimmed. A row shorter
/// than the header keeps the columns it has; a longer one widens the table.
pub(super) fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
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

/// `vk dev list` as text: one line per state directory.
pub fn render(rows: &[Row]) -> String {
    if rows.is_empty() {
        return "no dev environment state on this host\n".into();
    }
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.name.clone(),
                r.workspace
                    .as_ref()
                    .map(|w| w.display().to_string())
                    .unwrap_or_else(|| "?".into()),
                r.environment.clone().unwrap_or_else(|| "?".into()),
                r.status.label().into(),
                r.created_by
                    .as_deref()
                    .map(short_creator)
                    .unwrap_or_default(),
                r.age_secs.map(crate::vms::fmt_uptime).unwrap_or_default(),
                fmt_size(r.size_bytes),
                r.flags
                    .iter()
                    .map(|f| f.label())
                    .collect::<Vec<_>>()
                    .join(", "),
            ]
        })
        .collect();
    table(
        &[
            "NAME",
            "WORKSPACE",
            "ENV",
            "STATUS",
            "CREATED BY",
            "LAST BOOT",
            "ON DISK",
            "FLAGS",
        ],
        &rows,
    )
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
/// checkout is gone or that never recorded a boot. A running environment is never removed,
/// naming it is the caller's mistake to fix rather than something to skip quietly.
pub fn select_gc(rows: Vec<Row>, names: &[String], all_stale: bool) -> Result<Vec<Row>> {
    if names.is_empty() && !all_stale {
        bail!("name an environment to remove (`vk dev list`), or pass --all-stale");
    }
    let mut selected: Vec<Row> = Vec::new();
    for name in names {
        let Some(row) = rows.iter().find(|r| &r.name == name) else {
            bail!("no dev environment state named {name} (`vk dev list` names them)");
        };
        selected.push(row.clone());
    }
    if all_stale {
        selected.extend(rows.iter().filter(|r| r.stale()).cloned());
    }
    selected.sort_by(|a, b| a.name.cmp(&b.name));
    selected.dedup_by(|a, b| a.name == b.name);
    if let Some(row) = selected.iter().find(|r| r.status == Status::Running) {
        bail!(
            "{} is running — `vk dev stop` in {} first",
            row.name,
            row.workspace
                .as_ref()
                .map(|w| w.display().to_string())
                .unwrap_or_else(|| "its workspace".into())
        );
    }
    Ok(selected)
}

/// What a `gc` would destroy: each environment, with the top-level entries of its state
/// directory and their sizes, so the durable ones are visible before anything goes.
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
pub(super) fn try_lock_state_dir(dir: &Path) -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(dir).ok()?;
    // SAFETY: the fd is owned by `f`, which the caller keeps alive; LOCK_NB does not block.
    match unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } {
        0 => Some(f),
        _ => None,
    }
}

/// Remove the selected state directories, each with whatever it still publishes stopped
/// first.
///
/// Every directory is locked first and held until it is gone: a lock somebody else has is a
/// boot in flight or a live VM, and the whole operation refuses rather than removing what
/// came before it. Holding them is what closes the gap the selection leaves — the scan
/// behind `selected` was taken before a prompt of unbounded length, and a boot that started
/// in the meantime would otherwise lose its state directory under it. What is running is
/// read again here for the same reason.
pub fn remove(selected: &[Row]) -> Result<String> {
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
            bail!(
                "{} is running — `vk dev stop` in {} first",
                row.name,
                row.workspace
                    .as_ref()
                    .map(|w| w.display().to_string())
                    .unwrap_or_else(|| "its workspace".into())
            );
        }
    }
    let mut out = String::new();
    for (row, lock) in locked {
        crate::publish::stop_all_quietly(&row.dir, PUBLISH_STOP);
        std::fs::remove_dir_all(&row.dir)
            .with_context(|| format!("removing {}", row.dir.display()))?;
        drop(lock);
        out.push_str(&format!(
            "removed {} ({})\n",
            row.name,
            fmt_size(row.size_bytes)
        ));
    }
    Ok(out)
}

/// The state dirs VMs are currently up on.
fn running_dirs() -> Vec<PathBuf> {
    crate::vms::running()
        .into_iter()
        .map(|e| e.state_dir)
        .collect()
}

/// Every environment this host keeps state for, as `vk dev list` and `vk dev gc` see it:
/// the state base scanned against what is running. Measuring what each holds on disk reads
/// every file in it, so it is asked for rather than assumed.
pub fn state(sizes: bool) -> Result<Vec<Row>> {
    Ok(scan(
        &crate::dev::plan::dev_state_base()?,
        &running_dirs(),
        sizes,
    ))
}

/// The rows as `--json` prints them.
pub fn json(rows: &[Row]) -> Result<String> {
    Ok(format!("{}\n", serde_json::to_string_pretty(rows)?))
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

        let rows = scan(&base, &[], true);
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

    #[test]
    fn a_directory_with_no_identity_is_ephemeral_and_never_booted() {
        let tmp = scratch("ephemeral");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        ephemeral(&base, "repo-hook-cccc");

        let rows = scan(&base, &[], true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, Status::NeverBooted);
        assert_eq!(rows[0].flags, [Flag::Ephemeral]);
        assert_eq!(rows[0].workspace, None);
        assert_eq!(rows[0].booted_secs, None);
        assert!(rows[0].stale());
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

        let rows = scan(&base, &[], false);
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

        let rows = scan(&base, &[], false);
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
        let tmp = scratch("locked");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        let dir = booted(
            &base,
            "gone-bbbb",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abc)",
        );
        let selected = select_gc(scan(&base, &[], true), &[], true).unwrap();

        // A boot that started while the caller was answering the prompt holds the lock.
        let held = try_lock_state_dir(&dir).expect("free to begin with");
        let e = remove(&selected).unwrap_err();
        assert!(format!("{e:#}").contains("is in use by"), "{e:#}");
        assert!(dir.exists(), "the boot's state directory survived");
        drop(held);
        assert!(remove(&selected).unwrap().starts_with("removed gone-bbbb"));
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

        let rows = scan(&base, &[dir], true);
        assert_eq!(rows[0].status, Status::Running);
        assert!(!rows[0].stale());
        let e = select_gc(rows, &["repo-aaaa".into()], false).unwrap_err();
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
        let rows = scan(&base, &[], true);

        let stale = select_gc(rows.clone(), &[], true).unwrap();
        assert_eq!(
            stale.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["gone-bbbb", "repo-hook-cccc"]
        );
        // A name is taken whether or not it is stale, and never twice.
        let named = select_gc(rows.clone(), &["repo-aaaa".into()], true).unwrap();
        assert_eq!(named.len(), 3);
        let both = select_gc(rows.clone(), &["gone-bbbb".into()], true).unwrap();
        assert_eq!(both.len(), 2);
        let e = select_gc(rows.clone(), &["nope".into()], false).unwrap_err();
        assert!(
            format!("{e:#}").contains("no dev environment state named nope"),
            "{e:#}"
        );
        let e = select_gc(rows, &[], false).unwrap_err();
        assert!(format!("{e:#}").contains("--all-stale"), "{e:#}");
    }

    #[test]
    fn render_aligns_the_columns_and_names_what_is_missing() {
        let tmp = scratch("render");
        let base = tmp.0.join("state");
        std::fs::create_dir_all(&base).unwrap();
        booted(
            &base,
            "gone-bbbb",
            &tmp.0.join("removed"),
            "vk 0.62.0 (abcdef)",
        );
        ephemeral(&base, "repo-hook-cccc");
        let mut rows = scan(&base, &[], true);
        // Fixed, so the column reads the same on every run.
        rows[0].age_secs = Some(7200);

        let out = render(&rows);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("NAME"), "{out}");
        assert!(
            lines[0].contains("CREATED BY  LAST BOOT  ON DISK  FLAGS"),
            "{out}"
        );
        assert!(
            lines[1].contains("stopped") && lines[1].contains("vk 0.62.0"),
            "{out}"
        );
        assert!(
            lines[1].contains("2h0m") && lines[1].ends_with("workspace missing"),
            "{out}"
        );
        // Nothing was recorded, so the workspace and environment columns say so.
        assert!(lines[2].starts_with("repo-hook-cccc  ?"), "{out}");
        assert!(
            lines[2].contains("never booted") && lines[2].ends_with("ephemeral"),
            "{out}"
        );
        assert_eq!(render(&[]), "no dev environment state on this host\n");
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

        let selected = select_gc(scan(&base, &[], true), &[], true).unwrap();
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

        let report = remove(&selected).unwrap();
        assert!(report.starts_with("removed gone-bbbb ("), "{report}");
        assert!(!go.exists(), "the stale state dir survived");
        assert!(keep.exists(), "the live state dir was removed");
    }
}
