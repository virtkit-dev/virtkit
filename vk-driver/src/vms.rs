//! Host-side registry of running vk VMs.
//!
//! A `vk run --state-dir DIR` records an entry here once its VMM is spawned and removes it when
//! the run exits, so `vk list` can discover running VMs and `vk stop` can bring one down by
//! directory — no grepping the process table. Only pinned (`--state-dir`) runs are tracked:
//! they expose a stable exec socket external tooling attaches to, and they hold an advisory
//! `flock` on the state dir that gives a pid-reuse-proof liveness signal. Ephemeral runs (a
//! temp state dir removed on exit, no attachable socket) are deliberately not recorded.
//!
//! The registry is advisory. An entry can outlive its VM if the run was `SIGKILL`ed before its
//! removal ran, so readers reconcile liveness by probing the state-dir lock (`alive`) and prune
//! entries whose owner is gone. Entries live under `<data base>/vms/` (the same
//! `$XDG_DATA_HOME/virtkit` home `vk run`'s image cache uses), one JSON file per VM.

use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// One running VM's record. Serialized as `<slug(state_dir)>.json` in the registry dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmEntry {
    /// The run's `--state-dir`, canonicalized — the VM's identity and the file's key.
    pub state_dir: PathBuf,
    /// The directory `vk run` was invoked from (canonicalized), i.e. the project this VM
    /// belongs to. `vk list DIR` / `vk stop DIR` match on this. `None` if it was unavailable.
    #[serde(default)]
    pub project_dir: Option<PathBuf>,
    /// PID of the `vk run` process managing the VM (the one holding the state-dir lock).
    /// `vk stop` signals it; it tears the VM and any compose siblings down on exit.
    pub pid: u32,
    /// A short human label: the compose primary / image / `-f <target>` this VM boots.
    pub label: String,
    /// Exec-channel address, e.g. `vsock-auto://<state_dir>/vsock.sock:4444`.
    pub exec_addr: String,
    /// SSH address (`…:2222`) when the run served SSH (`--ssh`), else `None`.
    #[serde(default)]
    pub ssh_addr: Option<String>,
    /// Unix time (seconds) the entry was recorded — the VM's start, for an uptime column.
    pub created_secs: u64,
    /// Inputs to recompute the root image's build key against the working tree, so `vk list
    /// --stale` can tell whether a fresh `vk run` would rebuild it. `None` for an image boot
    /// (nothing is built from a Dockerfile, so there is no working tree to drift from).
    #[serde(default)]
    pub stale_recipe: Option<StaleRecipe>,
    /// Sibling compose services this run provisioned (empty for a non-compose run), including
    /// services available for on-demand start. Each records its agent socket so `vk list` can
    /// name it, `vk exec --service` can reach it while running, and `--stale` can fold a
    /// `build:` service's image into the freshness check.
    #[serde(default)]
    pub services: Vec<ServiceEntry>,
}

/// A sibling compose service declared alongside the primary VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    /// The service VM's agent exec channel, `vsock-auto://<svc-dir>/vsock.sock:4444`.
    pub exec_addr: String,
    /// Build recipe for a `build:` service (for `--stale`); `None` for an `image:` service.
    #[serde(default)]
    pub stale_recipe: Option<StaleRecipe>,
}

/// What the root image was built from, captured at boot so its freshness can be re-checked
/// later without the caller re-deriving the recipe. Mirrors exactly how `vk run` forms the
/// build inputs (a `-f` boot's args, or a compose `--primary` service's `build:` — its context
/// replicated per Dockerfile, the run's build-args merged with the service's), so a recomputed
/// key matches the one the boot stamped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleRecipe {
    pub dockerfiles: Vec<PathBuf>,
    pub contexts: Vec<PathBuf>,
    /// Named build contexts, so editing a file in one is seen as drift like any other input.
    /// Defaulted: an entry written before this field existed must still load, or the VM it
    /// describes drops out of the registry (`load_all_in` skips what it cannot parse).
    #[serde(default)]
    pub build_contexts: Vec<(String, PathBuf)>,
    pub build_args: Vec<(String, String)>,
    pub target: Option<String>,
    /// The built root image whose ext4 UUID carries its stamped stage key.
    pub root_ext4: PathBuf,
}

/// Whether the running VM's root image still matches the working tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// A fresh `vk run` would rebuild — the recomputed key no longer matches the image.
    Stale,
    /// The image matches the current sources.
    Fresh,
    /// Not determinable: an image boot (no recipe), the image is gone, or the key recompute
    /// failed (e.g. a base digest could not be resolved). Never reported as stale, so a probe
    /// failure never nags a rebuild — matching how the dev-VM scripts treat "unknown".
    Unknown,
}

impl Freshness {
    fn cell(self) -> &'static str {
        match self {
            Freshness::Stale => "yes",
            Freshness::Fresh => "no",
            Freshness::Unknown => "-",
        }
    }
    /// A scriptable one-word token for `vk status --stale`, so tooling can decide with a
    /// plain string compare.
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Stale => "stale",
            Freshness::Fresh => "fresh",
            Freshness::Unknown => "unknown",
        }
    }
    fn json(self) -> Option<bool> {
        match self {
            Freshness::Stale => Some(true),
            Freshness::Fresh => Some(false),
            Freshness::Unknown => None,
        }
    }
}

/// Recompute a recipe's build key and compare it to the key its image carries (the ext4 UUID is
/// `fingerprint([stage_key])`). Resolves base image digests, so this does network I/O — only on
/// `--stale`, never plain `list`.
fn freshness_of_recipe(r: &StaleRecipe) -> Freshness {
    // Read the on-disk image's stamped key first: it's a cheap local stat, and if the image is
    // absent (a `build:` service that was never started/built) there is nothing to compare, so
    // skip the network stage-key recompute entirely and report Unknown.
    let Some(uuid) = crate::ext4::fs_uuid(&r.root_ext4) else {
        return Freshness::Unknown;
    };
    let Ok(key) = crate::build::target_stage_key(
        &r.dockerfiles,
        &r.contexts,
        &r.build_contexts,
        &r.build_args,
        r.target.as_deref(),
    ) else {
        return Freshness::Unknown;
    };
    if uuid == crate::ensure::fingerprint(&[&key]) {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}

/// Freshness of the VM's own root image (ignoring services). `Unknown` for an image boot.
pub fn freshness(entry: &VmEntry) -> Freshness {
    entry
        .stale_recipe
        .as_ref()
        .map_or(Freshness::Unknown, freshness_of_recipe)
}

/// Combined freshness of the VM and its `build:` services: `Stale` if any component's image has
/// drifted from the working tree (a fresh `vk run` would rebuild it), else `Fresh` if any is
/// known current, else `Unknown`. So a sibling's Dockerfile change flags the workload, while an
/// undeterminable component (image service, uncached/never-built image) never forces a nag.
pub fn freshness_all(entry: &VmEntry) -> Freshness {
    let services = entry.services.iter().map(|s| {
        s.stale_recipe
            .as_ref()
            .map_or(Freshness::Unknown, freshness_of_recipe)
    });
    combine(std::iter::once(freshness(entry)).chain(services))
}

/// Fold component verdicts: any `Stale` wins, else any `Fresh`, else `Unknown`.
fn combine(parts: impl Iterator<Item = Freshness>) -> Freshness {
    let mut any_fresh = false;
    for f in parts {
        match f {
            Freshness::Stale => return Freshness::Stale,
            Freshness::Fresh => any_fresh = true,
            Freshness::Unknown => {}
        }
    }
    if any_fresh {
        Freshness::Fresh
    } else {
        Freshness::Unknown
    }
}

/// The registry directory: `<data base>/vms`, alongside `vk run`'s image cache. Public so
/// `vk paths` can report it.
pub fn registry_dir() -> Result<PathBuf> {
    Ok(crate::run::default_data_base()?.join("vms"))
}

/// Content-addressed file name for a state dir: a short hash of its path, so distinct state
/// dirs never collide and the same one always maps to the same file.
fn slug(state_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(state_dir.as_os_str().as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Seconds since the Unix epoch (0 if the clock is before it — only used for display).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn record_in(dir: &Path, entry: &VmEntry) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{}.json", slug(&entry.state_dir)));
    // Write-and-rename so a reader never sees a half-written entry.
    let tmp = dir.join(format!(".{}.json.tmp", slug(&entry.state_dir)));
    let json = serde_json::to_vec_pretty(entry).context("serializing VM entry")?;
    let mut f =
        std::fs::File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(&json).and_then(|_| f.sync_all())?;
    std::fs::rename(&tmp, &path).with_context(|| format!("publishing {}", path.display()))?;
    // fsync the directory so the rename itself survives a host crash, not just the file body.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn remove_in(dir: &Path, state_dir: &Path) {
    let _ = std::fs::remove_file(dir.join(format!("{}.json", slug(state_dir))));
}

fn load_all_in(dir: &Path) -> Vec<VmEntry> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue; // skip the .tmp write-and-rename staging files
        }
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        if let Ok(entry) = serde_json::from_slice::<VmEntry>(&bytes) {
            out.push(entry);
        }
    }
    out
}

/// True while the managing `vk run` is alive. The run holds an exclusive `flock` on its state
/// dir for its whole lifetime, so if we can take that lock the owner has exited (and the entry
/// is stale). A missing state dir also counts as dead. Pid-reuse-proof, unlike signalling the
/// recorded pid blind.
pub fn alive(entry: &VmEntry) -> bool {
    let Ok(f) = std::fs::File::open(&entry.state_dir) else {
        return false;
    };
    // SAFETY: the fd is owned by `f` and kept alive across the call; flock returns 0/-1 and
    // does not block under LOCK_NB.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        // Acquired => the owning run released it => dead. Drop it right back.
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        false
    } else {
        true // held by the live run
    }
}

/// All recorded VMs that are still alive, pruning any stale (dead-owner) entries as a
/// side effect. Sorted oldest-first.
pub fn running() -> Vec<VmEntry> {
    let Ok(dir) = registry_dir() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in load_all_in(&dir) {
        if alive(&entry) {
            out.push(entry);
        } else {
            remove_in(&dir, &entry.state_dir);
        }
    }
    out.sort_by_key(|e| e.created_secs);
    out
}

/// RAII handle: removes the VM's registry entry when the run drops it (clean exit or unwind).
/// A `SIGKILL` skips this — those stale entries are pruned by `alive` on the next read.
pub struct Registration {
    state_dir: Option<PathBuf>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let (Some(state_dir), Ok(dir)) = (&self.state_dir, registry_dir()) {
            remove_in(&dir, state_dir);
        }
    }
}

/// Record a VM and return a handle that unregisters it on drop. Best-effort: a write failure
/// only warns (the registry is a convenience, never a reason to fail a boot) and yields a
/// no-op handle.
pub fn register(entry: VmEntry) -> Registration {
    match registry_dir().and_then(|dir| record_in(&dir, &entry)) {
        Ok(()) => Registration {
            state_dir: Some(entry.state_dir),
        },
        Err(e) => {
            eprintln!("virtkit: warning: could not record VM in the registry: {e:#}");
            Registration { state_dir: None }
        }
    }
}

/// Canonicalize a path for comparison, falling back to it as-given if it does not resolve.
fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Does `entry` belong to the directory `filter` — i.e. is `filter` the VM's project dir (or
/// an ancestor of it), or the VM's own state dir?
fn matches_dir(entry: &VmEntry, filter: &Path) -> bool {
    if entry.state_dir == filter {
        return true;
    }
    match &entry.project_dir {
        Some(p) => p == filter || p.starts_with(filter),
        None => false,
    }
}

/// The running VMs a directory selects (default: the current directory), and the
/// canonical directory that did the selecting — for callers that decide for themselves
/// what zero or several matches mean, where [`resolve_one`] would refuse.
pub fn matching(dir: Option<&Path>) -> Result<(PathBuf, Vec<VmEntry>)> {
    let target = match dir {
        Some(d) => canonical(d),
        None => std::env::current_dir().context("resolving the current directory")?,
    };
    let matched = running()
        .into_iter()
        .filter(|e| matches_dir(e, &target))
        .collect();
    Ok((target, matched))
}

/// Resolve the single running VM for a directory (default: the current directory) — the
/// selector `vk status`/`vk stop <dir>` use. Errors when none match, or when more than one does
/// (an ambiguous parent directory), so a by-directory command never acts on the wrong VM.
pub fn resolve_one(dir: Option<&Path>) -> Result<VmEntry> {
    let (target, mut matched) = matching(dir)?;
    match matched.len() {
        0 => bail!("no running vk VM for {}", target.display()),
        1 => Ok(matched.pop().unwrap()),
        n => bail!(
            "{n} running vk VMs match {} — name a more specific directory",
            target.display()
        ),
    }
}

fn uptime(created_secs: u64) -> String {
    let s = unix_now().saturating_sub(created_secs);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86400 {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d{}h", s / 86400, (s % 86400) / 3600)
    }
}

/// The public shape of a VM in `vk list --json`: the user-facing fields plus a computed
/// `uptime_secs` and (with `--stale`) `stale`. Deliberately omits the internal `stale_recipe`,
/// so the JSON stays a stable contract for scripts.
#[derive(Serialize)]
struct VmView<'a> {
    state_dir: &'a Path,
    project_dir: Option<&'a Path>,
    pid: u32,
    label: &'a str,
    exec_addr: &'a str,
    ssh_addr: Option<&'a str>,
    created_secs: u64,
    uptime_secs: u64,
    /// A double option so `--stale` is self-describing: the outer `None` (no `--stale`) omits
    /// the field, while `Some(None)` — freshness requested but unknown — serializes as an
    /// explicit `null`, distinct from a known `true`/`false`. Reflects the VM *and* its services.
    #[serde(skip_serializing_if = "Option::is_none")]
    stale: Option<Option<bool>>,
    /// Sibling compose services (empty for a non-compose VM).
    services: Vec<ServiceView<'a>>,
}

#[derive(Serialize)]
struct ServiceView<'a> {
    name: &'a str,
    exec_addr: &'a str,
}

fn view(entry: &VmEntry, freshness: Freshness, stale: bool) -> VmView<'_> {
    VmView {
        state_dir: &entry.state_dir,
        project_dir: entry.project_dir.as_deref(),
        pid: entry.pid,
        label: &entry.label,
        exec_addr: &entry.exec_addr,
        ssh_addr: entry.ssh_addr.as_deref(),
        created_secs: entry.created_secs,
        uptime_secs: unix_now().saturating_sub(entry.created_secs),
        stale: if stale { Some(freshness.json()) } else { None },
        services: entry
            .services
            .iter()
            .map(|service| ServiceView {
                name: &service.name,
                exec_addr: &service.exec_addr,
            })
            .collect(),
    }
}

fn display_name(entry: &VmEntry) -> String {
    if entry.services.is_empty() {
        entry.label.clone()
    } else {
        let services: Vec<&str> = entry
            .services
            .iter()
            .map(|service| service.name.as_str())
            .collect();
        format!("{} (+{})", entry.label, services.join(", "))
    }
}

/// `vk list`: the running VMs (optionally only those under `filter`) as a table, or JSON. With
/// `stale`, each VM's freshness is computed (network I/O — see `freshness_all`) and shown.
pub fn list_report(filter: Option<&Path>, json: bool, stale: bool) -> Result<String> {
    let mut vms = running();
    if let Some(f) = filter {
        let f = canonical(f);
        vms.retain(|e| matches_dir(e, &f));
    }
    let fresh: Vec<Freshness> = vms
        .iter()
        .map(|e| {
            if stale {
                freshness_all(e)
            } else {
                Freshness::Unknown
            }
        })
        .collect();

    if json {
        let views: Vec<VmView> = vms
            .iter()
            .zip(&fresh)
            .map(|(entry, freshness)| view(entry, *freshness, stale))
            .collect();
        return Ok(serde_json::to_string_pretty(&views).context("serializing VM list")? + "\n");
    }
    if vms.is_empty() {
        return Ok("no running vk VMs\n".to_string());
    }
    // Columns: the STALE column is only added with `--stale`.
    let mut headers: Vec<&str> = vec!["PID", "UPTIME", "NAME", "PROJECT", "EXEC ADDRESS"];
    if stale {
        headers.push("STALE");
    }
    let rows: Vec<Vec<String>> = vms
        .iter()
        .zip(&fresh)
        .map(|(e, f)| {
            // NAME shows the primary plus its sibling services: `devcontainer (+redis, mysql)`.
            let mut row = vec![
                e.pid.to_string(),
                uptime(e.created_secs),
                display_name(e),
                e.project_dir
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".to_string()),
                e.exec_addr.clone(),
            ];
            if stale {
                row.push(f.cell().to_string());
            }
            row
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let mut out = String::new();
    let fmt_row = |cells: &[String], out: &mut String| {
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                out.push_str(cell); // last column: no trailing pad
            } else {
                out.push_str(&format!("{cell:<width$}  ", width = widths[i]));
            }
        }
        out.push('\n');
    };
    fmt_row(
        &headers.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
        &mut out,
    );
    for row in &rows {
        fmt_row(row, &mut out);
    }
    Ok(out)
}

/// SIGTERM the run managing `entry` and wait up to `timeout` seconds for it to exit (the
/// state-dir lock frees). Prunes the entry once it is down. Returns whether it went down.
/// A no-op-success if it was already dead.
fn stop_one(entry: &VmEntry, timeout: u64) -> bool {
    if !alive(entry) {
        if let Ok(dir) = registry_dir() {
            remove_in(&dir, &entry.state_dir);
        }
        return true;
    }
    // SAFETY: kill with a signal number is always safe; an ESRCH (already gone) is fine. We
    // just confirmed the owner live via the state-dir lock, so the sub-millisecond window in
    // which it could exit and its pid be recycled before this signal lands is negligible.
    unsafe { libc::kill(entry.pid as i32, libc::SIGTERM) };
    for _ in 0..(timeout * 2) {
        if !alive(entry) {
            if let Ok(dir) = registry_dir() {
                remove_in(&dir, &entry.state_dir);
            }
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// Whether an empty selection counts as success. An explicit `vk stop DIR` naming a target
/// that isn't running is a not-found the caller should see (exit 1), so a script can tell
/// "stopped it" from "there was nothing there"; `--all` and the current-directory default
/// treat "nothing to stop" as already done.
fn empty_selection_ok(explicit_dir: bool) -> bool {
    !explicit_dir
}

/// `vk stop`: stop the selected VMs. Selection is `--all`, else those under `dir`, else those
/// matching the current directory. Returns the summary and whether every selected VM went down.
pub fn stop_cmd(dir: Option<&Path>, all: bool, timeout: u64) -> Result<(String, bool)> {
    let vms = running();
    let selected: Vec<VmEntry> = if all {
        vms
    } else {
        let target = match dir {
            Some(d) => canonical(d),
            None => std::env::current_dir().context("resolving the current directory")?,
        };
        vms.into_iter()
            .filter(|e| matches_dir(e, &target))
            .collect()
    };
    if selected.is_empty() {
        return match dir {
            Some(d) => Ok((
                format!("no running vk VM under {}\n", canonical(d).display()),
                empty_selection_ok(true),
            )),
            None => Ok((
                "no matching running vk VM\n".to_string(),
                empty_selection_ok(false),
            )),
        };
    }
    let mut out = String::new();
    let mut ok = true;
    for e in &selected {
        if stop_one(e, timeout) {
            out.push_str(&format!("stopped {} (pid {})\n", e.label, e.pid));
        } else {
            out.push_str(&format!(
                "{} (pid {}) did not stop after {timeout}s\n",
                e.label, e.pid
            ));
            ok = false;
        }
    }
    Ok((out, ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "vk-vms-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn entry(state_dir: PathBuf, project: Option<PathBuf>) -> VmEntry {
        VmEntry {
            state_dir,
            project_dir: project,
            pid: std::process::id(),
            label: "devcontainer".into(),
            exec_addr: "vsock-auto:///tmp/x/vsock.sock:4444".into(),
            ssh_addr: None,
            created_secs: unix_now(),
            stale_recipe: None,
            services: Vec::new(),
        }
    }

    #[test]
    fn record_load_and_remove_roundtrip() {
        let reg = tmpdir("reg");
        let a = entry(tmpdir("state-a"), Some(PathBuf::from("/proj/a")));
        let b = entry(tmpdir("state-b"), Some(PathBuf::from("/proj/b")));
        record_in(&reg, &a).unwrap();
        record_in(&reg, &b).unwrap();

        let loaded = load_all_in(&reg);
        assert_eq!(loaded.len(), 2);
        assert!(
            loaded
                .iter()
                .any(|e| e.state_dir == a.state_dir && e.label == "devcontainer")
        );

        remove_in(&reg, &a.state_dir);
        let loaded = load_all_in(&reg);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].state_dir, b.state_dir);

        std::fs::remove_dir_all(&reg).ok();
    }

    #[test]
    fn slug_is_stable_and_path_specific() {
        let p1 = Path::new("/home/x/state");
        let p2 = Path::new("/home/y/state");
        assert_eq!(slug(p1), slug(p1));
        assert_ne!(slug(p1), slug(p2));
    }

    #[test]
    fn matches_dir_by_project_state_and_descendants() {
        let e = entry(
            PathBuf::from("/state/vm1"),
            Some(PathBuf::from("/home/vince/repo")),
        );
        // exact project dir, an ancestor of it, and the state dir all select the VM
        assert!(matches_dir(&e, Path::new("/home/vince/repo")));
        assert!(matches_dir(&e, Path::new("/home/vince")));
        assert!(matches_dir(&e, Path::new("/state/vm1")));
        // an unrelated dir, and a *descendant* of the project, do not
        assert!(!matches_dir(&e, Path::new("/home/other")));
        assert!(!matches_dir(&e, Path::new("/home/vince/repo/sub")));
    }

    #[test]
    fn alive_tracks_the_state_dir_flock() {
        let state = tmpdir("state-live");
        let e = entry(state.clone(), None);
        // Nobody holds the lock yet.
        assert!(!alive(&e));

        // Simulate the owning run: hold an exclusive flock on the state dir.
        let f = std::fs::File::open(&state).unwrap();
        assert_eq!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(alive(&e)); // probed from an independent fd -> sees it held

        // Release -> dead again.
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        drop(f);
        assert!(!alive(&e));

        std::fs::remove_dir_all(&state).ok();
    }

    #[test]
    fn running_prunes_dead_entries() {
        // A dead entry (no lock held on its state dir) is dropped from the file set.
        let reg = tmpdir("reg-prune");
        let dead = entry(tmpdir("state-dead"), None);
        record_in(&reg, &dead).unwrap();
        assert_eq!(load_all_in(&reg).len(), 1);
        // running() uses the real registry dir, so exercise the prune logic directly:
        for e in load_all_in(&reg) {
            if !alive(&e) {
                remove_in(&reg, &e.state_dir);
            }
        }
        assert_eq!(load_all_in(&reg).len(), 0);
        std::fs::remove_dir_all(&reg).ok();
    }

    #[test]
    fn empty_stop_is_success_only_without_an_explicit_dir() {
        // `vk stop` / `vk stop --all` with nothing running: success (nothing to do).
        assert!(empty_selection_ok(false));
        // `vk stop DIR` naming a target that isn't running: not-found (exit 1).
        assert!(!empty_selection_ok(true));
    }

    #[test]
    fn freshness_is_unknown_without_a_recipe() {
        // An image boot records no recipe -> freshness can't be judged (never "stale").
        let e = entry(PathBuf::from("/state/img"), None);
        assert!(e.stale_recipe.is_none());
        assert_eq!(freshness(&e), Freshness::Unknown);
        assert_eq!(Freshness::Unknown.cell(), "-");
        assert_eq!(Freshness::Unknown.json(), None);
        assert_eq!(Freshness::Unknown.as_str(), "unknown");
        assert_eq!(Freshness::Stale.cell(), "yes");
        assert_eq!(Freshness::Stale.json(), Some(true));
        assert_eq!(Freshness::Stale.as_str(), "stale");
        assert_eq!(Freshness::Fresh.cell(), "no");
        assert_eq!(Freshness::Fresh.json(), Some(false));
        assert_eq!(Freshness::Fresh.as_str(), "fresh");
    }

    #[test]
    fn freshness_all_folds_in_services() {
        // No recipes anywhere (image primary + image services) -> nothing to judge, so the
        // combined verdict is Unknown (never a spurious "stale").
        let mut e = entry(PathBuf::from("/state/img"), None);
        assert_eq!(freshness_all(&e), Freshness::Unknown);
        e.services.push(ServiceEntry {
            name: "db".into(),
            exec_addr: "vsock-auto:///state/img/svc-db/vsock.sock:4444".into(),
            stale_recipe: None,
        });
        assert_eq!(freshness_all(&e), Freshness::Unknown);
    }

    #[test]
    fn combine_stale_dominates_then_fresh_then_unknown() {
        use Freshness::*;
        // Any stale component flags the workload, wherever it sits.
        assert_eq!(combine([Fresh, Unknown, Stale].into_iter()), Stale);
        assert_eq!(combine([Stale, Fresh].into_iter()), Stale);
        // A known-current component upgrades an otherwise-unknown verdict.
        assert_eq!(combine([Unknown, Fresh].into_iter()), Fresh);
        // Nothing determinable stays unknown (never a spurious "stale").
        assert_eq!(combine([Unknown, Unknown].into_iter()), Unknown);
    }

    #[test]
    fn list_view_reports_compose_services_in_text_and_json() {
        let mut e = entry(PathBuf::from("/state/app"), Some(PathBuf::from("/project")));
        e.label = "app".into();
        e.services = vec![
            ServiceEntry {
                name: "db".into(),
                exec_addr: "vsock-auto:///state/app/svc-db/vsock.sock:4444".into(),
                stale_recipe: None,
            },
            ServiceEntry {
                name: "redis".into(),
                exec_addr: "vsock-auto:///state/app/svc-redis/vsock.sock:4444".into(),
                stale_recipe: None,
            },
        ];

        assert_eq!(display_name(&e), "app (+db, redis)");
        let json = serde_json::to_value(view(&e, Freshness::Unknown, false)).unwrap();
        assert_eq!(json["services"][0]["name"], "db");
        assert_eq!(
            json["services"][0]["exec_addr"],
            "vsock-auto:///state/app/svc-db/vsock.sock:4444"
        );
        assert_eq!(json["services"][1]["name"], "redis");
    }

    #[test]
    fn json_stale_field_distinguishes_absent_unknown_and_known() {
        let dir = PathBuf::from("/state/x");
        let view = |stale: Option<Option<bool>>| VmView {
            state_dir: &dir,
            project_dir: None,
            pid: 1,
            label: "x",
            exec_addr: "a",
            ssh_addr: None,
            created_secs: 0,
            uptime_secs: 0,
            stale,
            services: vec![],
        };
        // No `--stale`: the field is omitted entirely.
        let j = serde_json::to_string(&view(None)).unwrap();
        assert!(!j.contains("\"stale\""), "{j}");
        // `--stale` but freshness unknown: an explicit null, not omitted.
        assert!(
            serde_json::to_string(&view(Some(None)))
                .unwrap()
                .contains("\"stale\":null")
        );
        // `--stale` with a verdict: the bool.
        assert!(
            serde_json::to_string(&view(Some(Some(true))))
                .unwrap()
                .contains("\"stale\":true")
        );
    }

    // An entry written before `build_contexts` existed has to keep loading: `load_all_in` skips
    // whatever it cannot parse, so a required field would drop the whole VM out of the registry
    // — `vk list` would lose it and `vk stop <dir>` would fail, with the VM still running.
    #[test]
    fn stale_recipe_loads_without_build_contexts() {
        let json = r#"{"dockerfiles":["/p/Dockerfile"],"contexts":["/p"],
            "build_args":[],"target":null,"root_ext4":"/p/root.ext4"}"#;
        let r: StaleRecipe = serde_json::from_str(json).unwrap();
        assert!(r.build_contexts.is_empty());
    }

    #[test]
    fn uptime_formats_across_scales() {
        let now = unix_now();
        assert_eq!(uptime(now), "0s");
        assert!(uptime(now.saturating_sub(90)).ends_with('m'));
        assert!(uptime(now.saturating_sub(7200)).contains('h'));
        assert!(uptime(now.saturating_sub(200_000)).contains('d'));
    }
}
