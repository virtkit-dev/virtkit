//! Host-side registry of running vk VMs.
//!
//! A `vk run --state-dir DIR` records an entry after spawning its VMM and removes it on exit.
//! `vk list` discovers running VMs from these entries; it, `vk stop` and `vk reboot` select one
//! by directory or displayed pid without searching the process table. Only pinned (`--state-dir`) runs are
//! tracked: they expose a stable exec socket for external tooling and hold an advisory `flock`
//! on the state dir as a pid-reuse-proof liveness signal. Ephemeral runs have a temporary state
//! dir and no attachable socket, so they are deliberately not recorded. A UEFI bundle run is
//! the exception: its qemu-ga socket is in its directory, temporary or not, and it locks that
//! directory as a pinned run does.
//!
//! The registry is advisory. An entry can outlive its VM if the run was `SIGKILL`ed before its
//! removal ran, so readers reconcile liveness by probing the state-dir lock (`alive`) and prune
//! entries whose owner is gone. Entries live under `<data base>/vms/`
//! (`$XDG_DATA_HOME/virtkit`), one JSON file per VM.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use vk_core::fleetctl::{Frame, Reply, Request, UnitStatus};

/// One running VM's record. Serialized as `<slug(state_dir)>.json` in the registry dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmEntry {
    /// The canonical state directory identifies the VM and keys its registry file. Paths
    /// serialize as UTF-8 strings or as `{"bytes": [...]}` for other byte sequences.
    #[serde(with = "crate::names::os_string")]
    pub state_dir: PathBuf,
    /// Canonical project directory: `--workspace`, then `--workdir`, then the `vk run`
    /// launch directory. `vk list DIR` and `vk stop DIR` match it; `None` when unavailable.
    #[serde(default, with = "crate::names::opt_os_string")]
    pub project_dir: Option<PathBuf>,
    /// PID of the managing `vk run`, which holds the state-dir lock. `vk list` displays it, and
    /// `vk stop` can select and signal it. On exit, it tears down the VM and compose siblings.
    pub pid: u32,
    /// A short human label: the compose primary, image ref, or Dockerfile this VM boots.
    pub label: String,
    /// Exec-channel address, e.g. `vsock-auto://<state_dir>/vsock.sock:4444`.
    pub exec_addr: String,
    /// SSH address (`…:2222`) when the run served SSH (`--ssh`), else `None`.
    #[serde(default)]
    pub ssh_addr: Option<String>,
    /// The boot-time recording (`vk run --atop`) this VM's guest is writing, else `None`.
    /// `vk atop` follows this log instead of attaching a second sampler.
    #[serde(default, with = "crate::names::opt_os_string")]
    pub atop_log: Option<PathBuf>,
    /// Unix time (seconds) the entry was recorded — the VM's start, for an uptime column.
    pub created_secs: u64,
    /// When `pid` started, in clock ticks since boot (`/proc/<pid>/stat`'s `starttime`): which
    /// process the pid is, unmoved by a wall-clock step. `None` on an entry recorded before
    /// the field existed, or where it could not be read.
    #[serde(default)]
    pub pid_start_ticks: Option<u64>,
    /// The VMM backend hosting the guest, as `vk run` names it (`libkrun` for every new
    /// entry). This and the fields down to `guest_ip` are boot-time facts `vk run` files; each
    /// is `None` on an entry recorded before the field existed.
    #[serde(default)]
    pub vmm: Option<String>,
    /// The pid to inspect or signal when the managing `vk run` itself is unresponsive: the
    /// libkrun boot subprocess (with `--reboot`, the keeper that relaunches the guest in
    /// place, so the pid is stable across reboots).
    #[serde(default)]
    pub vmm_pid: Option<u32>,
    /// The vCPU count the guest booted with: `--cpus`, a `--primary` service's marker, or
    /// the run default.
    #[serde(default)]
    pub cpus: Option<u32>,
    /// The memory size token handed to the VMM verbatim (`8G`, `512M`, ...), from `--mem`,
    /// a `--primary` service's marker, or the run default. Not normalized to bytes.
    #[serde(default)]
    pub mem: Option<String>,
    /// Whether the guest sees VMX/SVM (`--nested`), i.e. can run `vk` itself.
    #[serde(default)]
    pub nested: Option<bool>,
    /// The primary's eth0 address on the run's `--net` LAN; `None` without `--net`. Extra
    /// NICs (`--nics`, `x-virtkit.nics`) are not recorded.
    #[serde(default)]
    pub guest_ip: Option<std::net::Ipv4Addr>,
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
    /// The qemu-ga socket of an agent-less guest (a UEFI bundle: Windows), which `vk exec` and
    /// `vk cp` use instead of `exec_addr`; `None` for a guest running vk-agent.
    #[serde(default, with = "crate::names::opt_os_string")]
    pub guest_agent: Option<PathBuf>,
    /// The VM's control socket ([`crate::vmmctl`]), which `vk pause` and `vk resume` use;
    /// `None` for a VM without one.
    #[serde(default, with = "crate::names::opt_os_string")]
    pub control: Option<PathBuf>,
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
    #[serde(with = "crate::names::os_strings")]
    pub dockerfiles: Vec<PathBuf>,
    #[serde(with = "crate::names::os_strings")]
    pub contexts: Vec<PathBuf>,
    /// Named build contexts, so editing a file in one is seen as drift like any other input.
    /// Defaulted: an entry written before this field existed must still load, or the VM it
    /// describes drops out of the registry (`load_all_in` skips what it cannot parse).
    #[serde(default, with = "crate::names::named_os_strings")]
    pub build_contexts: Vec<(String, PathBuf)>,
    pub build_args: Vec<(String, String)>,
    pub target: Option<String>,
    /// The built root image whose ext4 UUID carries its stamped stage key.
    #[serde(with = "crate::names::os_string")]
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
    /// The single token printed by `vk ping --stale`.
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Stale => "stale",
            Freshness::Fresh => "fresh",
            Freshness::Unknown => "unknown",
        }
    }
    pub(crate) fn json(self) -> Option<bool> {
        match self {
            Freshness::Stale => Some(true),
            Freshness::Fresh => Some(false),
            Freshness::Unknown => None,
        }
    }
}

/// Recompute a recipe's build key and compare it to the key its image carries (the ext4 UUID is
/// `fingerprint([stage_key])`). Resolves base image digests, so this does network I/O — only on
/// `--stale` or a refresh deciding whether to keep a boot it joined, never plain `list`.
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
        None,
        // Freshness checks never download `ADD` inputs. An unpinned URL makes freshness unknown.
        crate::build::Fetch::offline(),
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

/// Whether every image the VM was booted from is known to match the sources: its own root
/// image and each service's must be `Fresh`. Stricter than [`freshness_all`], where one
/// known-current component outweighs undeterminable ones — here an `Unknown` counts against
/// it, whether an image boot, an image gone or a key that could not be recomputed. A service
/// booted from a prebuilt image carries no recipe and counts as unknown too: its tag may have
/// moved since, which a boot would pull. Resolves base image digests, so this does network
/// I/O.
pub fn all_fresh(entry: &VmEntry) -> bool {
    all_fresh_by(entry, freshness_of_recipe)
}

/// [`all_fresh`], each recipe judged by `verdict`.
fn all_fresh_by(entry: &VmEntry, verdict: impl Fn(&StaleRecipe) -> Freshness) -> bool {
    let fresh = |r: &StaleRecipe| verdict(r) == Freshness::Fresh;
    entry.stale_recipe.as_ref().is_some_and(fresh)
        && entry
            .services
            .iter()
            .all(|s| s.stale_recipe.as_ref().is_some_and(fresh))
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
    #[cfg(test)]
    if let Some(dir) = THREAD_REGISTRY.with_borrow(Clone::clone) {
        return Ok(dir);
    }
    Ok(crate::run::default_data_base()?.join("vms"))
}

#[cfg(test)]
std::thread_local! {
    /// This thread's override for [`registry_dir`].
    static THREAD_REGISTRY: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Override [`registry_dir`] on the current thread and restore it on drop. Tests can prune
/// a private registry without changing the process environment.
#[cfg(test)]
pub(crate) struct ThreadRegistry(Option<PathBuf>);

#[cfg(test)]
impl ThreadRegistry {
    pub(crate) fn set(dir: &Path) -> ThreadRegistry {
        ThreadRegistry(THREAD_REGISTRY.replace(Some(dir.to_path_buf())))
    }
}

#[cfg(test)]
impl Drop for ThreadRegistry {
    fn drop(&mut self) {
        THREAD_REGISTRY.set(self.0.take());
    }
}

/// Content-addressed file name for a state dir: a short hash of its path, so distinct state
/// dirs never collide and the same one always maps to the same file.
pub(crate) fn slug(state_dir: &Path) -> String {
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

/// This process's [`VmEntry::pid_start_ticks`], for the entry its run registers.
pub(crate) fn own_start_ticks() -> Option<u64> {
    i32::try_from(std::process::id())
        .ok()
        .and_then(crate::usage::proc_starttime)
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
    // Listing and ordinary VM operations skip unreadable registry entries.
    try_load_all_in(dir).map(|(all, _)| all).unwrap_or_default()
}

/// Return readable registry entries and a diagnostic for each unreadable entry.
/// A missing registry is empty. Other directory read errors propagate.
fn try_load_all_in(dir: &Path) -> Result<(Vec<VmEntry>, Vec<String>)> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let (mut out, mut unread) = (Vec::new(), Vec::new());
    for e in rd {
        let e = e.with_context(|| format!("reading {}", dir.display()))?;
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue; // skip the .tmp write-and-rename staging files
        }
        let read = std::fs::read(&p)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| {
                serde_json::from_slice::<VmEntry>(&bytes).map_err(anyhow::Error::from)
            });
        match read {
            Ok(entry) => out.push(entry),
            Err(e) => unread.push(format!("registry entry {} not read: {e}", p.display())),
        }
    }
    Ok((out, unread))
}

/// True while the managing `vk run` is alive. The run holds an exclusive `flock` on its state
/// dir for its whole lifetime, so if we can take that lock the owner has exited (and the entry
/// is stale). A missing state dir also counts as dead. Pid-reuse-proof, unlike signalling the
/// recorded pid blind. The lock may be another run's, which took the dir over from one that
/// was killed: an entry whose process is known to have exited is dead whoever holds it.
pub fn alive(entry: &VmEntry) -> bool {
    dir_locked(&entry.state_dir) && !exited(entry) && !superseded(entry)
}

/// Whether the run `entry` records is known to have exited: its pid is gone, or is another
/// process's now. `false` when that cannot be told (no start time recorded).
fn exited(entry: &VmEntry) -> bool {
    let pid = i32::try_from(entry.pid).ok();
    (pid.zip(entry.pid_start_ticks))
        .is_some_and(|(pid, ticks)| crate::usage::proc_exited(pid, ticks))
}

/// Whether another run has taken `entry`'s state dir and is starting on it: the lock that
/// makes the entry look alive is that run's, and the entry is left from a run that was
/// killed.
fn superseded(entry: &VmEntry) -> bool {
    crate::vmstate::read(&entry.state_dir).is_some_and(|t| {
        t.state == crate::vmstate::State::Starting && !t.is_of(entry.pid, entry.pid_start_ticks)
    })
}

/// Whether a run holds `dir`'s state-dir lock — the one [`alive`] reads — including a run that
/// registers no VM, such as a services-only compose run.
pub fn dir_locked(dir: &Path) -> bool {
    let Ok(f) = std::fs::File::open(dir) else {
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
    running_in(&dir)
}

/// Live registrations, oldest first, and the state directories of dead registrations.
/// Readers leave both intact. [`running`] also prunes dead registrations it can lock.
pub fn registered() -> (Vec<VmEntry>, Vec<PathBuf>) {
    let Ok(dir) = registry_dir() else {
        return (Vec::new(), Vec::new());
    };
    let (mut alive_ones, dead): (Vec<VmEntry>, Vec<VmEntry>) =
        load_all_in(&dir).into_iter().partition(alive);
    alive_ones.sort_by_key(|e| e.created_secs);
    (alive_ones, dead.into_iter().map(|e| e.state_dir).collect())
}

/// Prune a dead registration for `state_dir` without scanning other VMs.
pub fn forget_if_gone(state_dir: &Path) {
    let Ok(dir) = registry_dir() else {
        return;
    };
    let path = dir.join(format!("{}.json", slug(&canonical(state_dir))));
    let entry = std::fs::read(path)
        .ok()
        .and_then(|json| serde_json::from_slice::<VmEntry>(&json).ok());
    if let Some(entry) = entry.filter(|e| !alive(e)) {
        prune_gone(&dir, &entry);
    }
}

/// [`running`], for the registry at `dir`.
pub(crate) fn running_in(dir: &Path) -> Vec<VmEntry> {
    let mut out = Vec::new();
    for entry in load_all_in(dir) {
        if alive(&entry) {
            out.push(entry);
        } else {
            prune_gone(dir, &entry);
        }
    }
    out.sort_by_key(|e| e.created_secs);
    out
}

/// The last registry entry of a VM, kept in its state dir.
pub const LAST: &str = ".virtkit-last.json";

fn record_last(entry: &VmEntry) -> Result<()> {
    crate::statefile::write(
        &entry.state_dir.join(LAST),
        &serde_json::to_vec_pretty(entry)?,
    )
}

/// Read the last registration. Older VMs may have no saved copy.
pub fn last_entry(state_dir: &Path) -> Result<Option<VmEntry>> {
    let path = state_dir.join(LAST);
    match std::fs::read(&path) {
        Ok(json) => serde_json::from_slice(&json)
            .map(Some)
            .with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// RAII handle: removes the VM's registry entry when the run drops it (clean exit or unwind).
/// A `SIGKILL` leaves the entry for a later pruning scan or target repair.
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

/// Register a VM until the returned handle drops. Both writes are best-effort. A failed
/// state-directory copy only warns. A failed registry write also yields a no-op handle.
pub fn register(entry: VmEntry) -> Registration {
    // Serialized against a correction to the same entry (see `WRITES`); taken here rather than
    // in `record_in`, which the correction calls while already holding it.
    let _writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
    // Refresh the saved boot details for the next stopped listing. A failed write can leave
    // an older registration in the state directory.
    if let Err(e) = record_last(&entry) {
        eprintln!("virtkit: warning: could not keep the VM's entry in its state dir: {e:#}");
    }
    let registration = match registry_dir().and_then(|dir| record_in(&dir, &entry)) {
        Ok(()) => Registration {
            state_dir: Some(entry.state_dir.clone()),
        },
        Err(e) => {
            eprintln!("virtkit: warning: could not record VM in the registry: {e:#}");
            Registration { state_dir: None }
        }
    };
    // Attempt registration before clearing startup so a successful handoff has no gap.
    crate::vmstate::started(&entry.state_dir, entry.pid, entry.pid_start_ticks);
    registration
}

/// Point a service's recorded build recipe at the image it actually booted. The entry is
/// filed with the address provisioning predicted for a `build:` service, which is all that is
/// known then; the service manager may go on to adopt a different tier entry when it builds
/// that service on demand (`manager::Manager::start_streamed`), and `vk list --stale` would
/// otherwise recompute freshness against an image the service never booted.
///
/// Best-effort, exactly like [`register`]: whether the registry can be written never decides
/// whether a service starts, and a no-op when there is no entry to update. Several runs have
/// none — an unpinned run (no `--state-dir`), and a services-only compose run, neither of
/// which are recorded — and an exited run has already removed its own. This carries the starts
/// that arrive over the control plane; `manager::Manager::refresh_service_images` enforces the
/// ordering and folds in the adoptions that precede the entry.
pub fn note_service_image(run_dir: &Path, service: &str, root_ext4: &Path) {
    let done =
        registry_dir().and_then(|dir| note_service_image_in(&dir, run_dir, service, root_ext4));
    if let Err(e) = done {
        eprintln!("virtkit: warning: could not update the VM registry: {e:#}");
    }
}

/// Serializes writers of one run's entry. [`record_in`] stages every version through a single
/// path keyed by the run, and the correction below is a read-modify-write, so unserialized
/// callers both interleave into that staging file — publishing an entry no reader can parse,
/// which drops the VM from `vk list` — and lose each other's updates. [`register`] takes it
/// too: a leftover entry from a run that was killed makes a correction reachable before this
/// run files its own, and an uncontended mutex costs nothing on the path that files it.
/// Guards `()`, so a poisoning is nothing to propagate.
static WRITES: Mutex<()> = Mutex::new(());

fn note_service_image_in(
    dir: &Path,
    run_dir: &Path,
    service: &str,
    root_ext4: &Path,
) -> Result<()> {
    let _writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
    // The entry is filed under the canonicalized run dir (`run::registry_key`), so resolve the
    // key the same way here rather than trusting every caller to: a raw or symlinked path would
    // miss the file and correct nothing, silently.
    let path = dir.join(format!("{}.json", slug(&canonical(run_dir))));
    let json = match std::fs::read(&path) {
        Ok(json) => json,
        // Nothing filed under this run: recreating it here would leave an entry no run owns.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut entry: VmEntry =
        serde_json::from_slice(&json).with_context(|| format!("parsing {}", path.display()))?;
    // An `image:` service carries no recipe, and a prediction that held needs no rewrite —
    // the common case, since only an edit between provisioning and the build moves the entry.
    // Comparing the two paths as paths is enough here: both are one `build_tier_dir` off the
    // same cache root, so they differ only where the stage key does, and the worst a spurious
    // mismatch could cost is rewriting the entry with the value it already holds.
    let Some(recipe) = entry
        .services
        .iter_mut()
        .find(|s| s.name == service)
        .and_then(|s| s.stale_recipe.as_mut())
        .filter(|r| r.root_ext4 != root_ext4)
    else {
        return Ok(());
    };
    recipe.root_ext4 = root_ext4.to_path_buf();
    record_in(dir, &entry)
}

/// Canonicalize a path for comparison, falling back to it as-given if it does not resolve.
pub(crate) fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Does `entry` belong to the directory `filter` — i.e. is `filter` the VM's state dir, its
/// project dir, or (with `below`) an ancestor of its project dir?
fn matches_dir(entry: &VmEntry, filter: &Path, below: bool) -> bool {
    if entry.state_dir == filter {
        return true;
    }
    match &entry.project_dir {
        Some(p) => p == filter || (below && p.starts_with(filter)),
        None => false,
    }
}

/// The running VMs a directory selects exactly (default: the current directory), and the
/// canonical directory that did the selecting — for callers that decide for themselves
/// what zero or several matches mean, where [`resolve_one`] would refuse.
pub fn matching(dir: Option<&Path>) -> Result<(PathBuf, Vec<VmEntry>)> {
    let target = match dir {
        Some(d) => canonical(d),
        None => std::env::current_dir().context("resolving the current directory")?,
    };
    let matched = (registered().0.into_iter())
        .filter(|e| matches_dir(e, &target, false))
        .collect();
    Ok((target, matched))
}

/// The single running VM a REF names (default: the current directory) — see
/// [`resolve_ref`]; a `NAME/SERVICE` here is refused, the caller acting on whole VMs.
pub fn resolve_one(target: Option<&Path>) -> Result<VmEntry> {
    match resolve_ref(target.map(Path::as_os_str), None)? {
        (entry, None) => Ok(entry),
        (_, Some(service)) => {
            bail!("that names the compose service {service}: this command acts on whole VMs")
        }
    }
}

/// `vk logs -f` follows a registered writer while the registry lists its pid with the
/// same recorded start time (if any). An unreadable registry yields an empty list and
/// ends the follow.
pub fn still_registered(entry: &VmEntry) -> bool {
    match select_running(Some(Selector::Pid(entry.pid))) {
        Ok((_, m)) => m.iter().any(|e| e.pid_start_ticks == entry.pid_start_ticks),
        Err(_) => true,
    }
}

fn uptime(created_secs: u64) -> String {
    fmt_uptime(unix_now().saturating_sub(created_secs))
}

/// How long something has been up, as `vk list`'s UPTIME column renders it: `45s`, `19m`,
/// `3h7m`, `2d4h`. Shared so a run named anywhere else — the refusal a second `vk run`
/// on its state dir gets, say — reads the same as it does in the listing.
pub(crate) fn fmt_uptime(s: u64) -> String {
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

/// A managed publisher's record and whether it was shown to be running.
pub(crate) type Published = (crate::publish::Entry, crate::publish::Liveness);

/// The reported status of the declared service `name`, if the VM answered and listed it.
fn find_unit<'a>(units: Option<&'a [UnitStatus]>, name: &str) -> Option<&'a UnitStatus> {
    units?.iter().find(|u| u.name == name)
}

/// The service manager reports addresses as `ip/prefix`; the view shows only the address.
pub(crate) fn bare_ip(ip: &str) -> &str {
    ip.split_once('/').map_or(ip, |(addr, _)| addr)
}

/// Ask the run's service manager for every unit's status, or `None` if it cannot be reached
/// or refuses (callers then fall back to the registry's declared set).
pub(crate) fn service_units(entry: &VmEntry) -> Option<Vec<UnitStatus>> {
    if entry.services.is_empty() {
        return None;
    }
    let ctl = control_socket(entry)?;
    match query_units(&ctl) {
        Ok(units) => Some(units),
        // Report the failure before falling back to declared services.
        Err(e) => {
            eprintln!("virtkit: {}: querying service status: {e:#}", entry.label);
            None
        }
    }
}

/// The VM's managed publishers (`vk publish ensure`), or none if its records cannot be read.
/// Read past exited publishers and leave their files intact.
fn published(entry: &VmEntry) -> Vec<Published> {
    match crate::publish::snapshot(&entry.state_dir) {
        Ok(published) => published,
        // Report the failure; the VM is still listed, just without its ports.
        Err(e) => {
            eprintln!("virtkit: {}: reading publishers: {e:#}", entry.label);
            Vec::new()
        }
    }
}

/// One publisher as `listen->to`, with `@service` when a compose sibling rather than the
/// primary dials the target.
pub(crate) fn published_addr(e: &crate::publish::Entry) -> String {
    let mut addr = format!("{}->{}", bare_tcp(&e.listen), bare_tcp(&e.to));
    if let Some(service) = &e.service {
        addr.push('@');
        addr.push_str(service);
    }
    addr
}

fn bare_tcp(addr: &str) -> &str {
    addr.strip_prefix("tcp://").unwrap_or(addr)
}

/// Query with `Request::List`, ignoring progress frames until `Done`; an error reply is an
/// `Err`. Two-second I/O timeouts keep `vk list` from blocking on a wedged VMM.
fn query_units(ctl: &Path) -> Result<Vec<UnitStatus>> {
    let reply = control(ctl, &Request::List, Some(Duration::from_secs(2)), |_| {})?;
    if !reply.ok {
        bail!("service manager refused: {}", reply.message);
    }
    Ok(reply.units)
}

/// The manager's host-only control socket, or `None` for a run without services.
/// Fall back to the guest-facing per-port control socket for runs started by an older `vk`.
pub fn control_socket(entry: &VmEntry) -> Option<PathBuf> {
    if entry.services.is_empty() {
        return None;
    }
    match vk_core::addr::SocketAddr::from_str(&entry.exec_addr) {
        Ok(vk_core::addr::SocketAddr::VsockAuto { path, .. }) => {
            let host = crate::manager::host_control_socket(&path);
            if host.exists() {
                Some(host)
            } else {
                Some(vk_core::net::hybrid_socket(
                    &path,
                    vk_core::fleetctl::CONTROL_PORT,
                ))
            }
        }
        _ => None,
    }
}

/// One request to a run's service manager over `ctl`, from the host: the same protocol
/// `vk-agent service` speaks from inside the guest. Progress lines (an on-demand build a `Start`
/// streams) go to `on_progress`; the terminal reply is returned as is, refusals included.
/// `timeout` bounds each connect, read and write. Operations that build pass `None`.
pub fn control(
    ctl: &Path,
    req: &Request,
    timeout: Option<Duration>,
    on_progress: impl FnMut(&str),
) -> Result<Reply> {
    control_by(ctl, req, Deadline::NEVER, timeout, on_progress)
}

/// [`control`], with no connect, read or write going past `deadline`.
pub fn control_by(
    ctl: &Path,
    req: &Request,
    deadline: Deadline,
    timeout: Option<Duration>,
    on_progress: impl FnMut(&str),
) -> Result<Reply> {
    Control::open(ctl, deadline, timeout, None)?.request(req, on_progress)
}

/// A connection to a run's service manager. Every read and write on it, as its connect,
/// waits no longer than its timeout, nor past its deadline.
pub(crate) struct Control {
    stream: std::os::unix::net::UnixStream,
    deadline: Deadline,
    timeout: Option<Duration>,
}

impl Control {
    /// Connect to the manager on `ctl`. With `run`, only one that run serves is kept.
    pub(crate) fn open(
        ctl: &Path,
        deadline: Deadline,
        timeout: Option<Duration>,
        run: Option<&Held>,
    ) -> Result<Self> {
        let bound = bound(deadline, timeout).context("control")?;
        let stream = vk_core::unixpath::connect_within(ctl, bound)
            .with_context(|| format!("control: connect {}", ctl.display()))?;
        if let Some(run) = run
            && !run.serves(&stream).context("control: reading its peer")?
        {
            bail!(
                "control: {} is no longer served by the run selected (pid {})",
                ctl.display(),
                run.pid
            );
        }
        Ok(Control {
            stream,
            deadline,
            timeout,
        })
    }

    /// Send `req`, then read its reply. Progress lines (an on-demand build a `Start`
    /// streams) go to `on_progress`.
    pub(crate) fn request(self, req: &Request, mut on_progress: impl FnMut(&str)) -> Result<Reply> {
        use std::io::{BufRead, BufReader};
        let mut text = serde_json::to_string(req).context("encoding the control request")?;
        text.push('\n');
        let mut rd = BufReader::new(self);
        rd.get_mut().write_all(text.as_bytes())?;
        let mut line = String::new();
        loop {
            line.clear();
            if rd.read_line(&mut line)? == 0 {
                bail!("control peer closed before Done");
            }
            match serde_json::from_str::<Frame>(line.trim_end())
                .context("decoding control frame")?
            {
                Frame::Progress(p) => on_progress(&p),
                Frame::Done(reply) => return Ok(reply),
            }
        }
    }
}

/// What a socket operation may wait: `timeout`, or what is left before `deadline` when that
/// is less; an error once it has passed.
fn bound(deadline: Deadline, timeout: Option<Duration>) -> std::io::Result<Option<Duration>> {
    match deadline.left() {
        None => Ok(timeout),
        Some(left) if left.is_zero() => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "out of time",
        )),
        Some(left) => Ok(Some(timeout.map_or(left, |t| t.min(left)))),
    }
}

// Bounded call by call, so a peer trickling a reply cannot hold a read past the deadline.
impl std::io::Read for Control {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream
            .set_read_timeout(bound(self.deadline, self.timeout)?)?;
        std::io::Read::read(&mut self.stream, buf)
    }
}

impl std::io::Write for Control {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(bound(self.deadline, self.timeout)?)?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// The agent exec address of the compose service `name` in this run.
pub fn service_exec_addr(entry: &VmEntry, name: &str) -> Result<vk_core::addr::SocketAddr> {
    let found = entry
        .services
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| {
            let names: Vec<&str> = entry.services.iter().map(|s| s.name.as_str()).collect();
            let have = if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            };
            anyhow::anyhow!("no service {name:?} in this VM (services: {have})")
        })?;
    found.exec_addr.parse::<vk_core::addr::SocketAddr>()
}

/// How [`await_agent`] ended when `still_up` never failed.
pub enum AgentWait {
    /// The agent answered a status probe.
    Answered,
    /// `still_up` reported the guest shut down cleanly before its agent answered.
    Ended,
    /// The timeout passed; the last probe's error.
    TimedOut(String),
}

/// Poll the agent on `addr` until it answers or `timeout` passes. After each missed probe,
/// `still_up` checks the guest is still coming up: `Ok(false)` (it shut down cleanly) or an
/// error ends the wait.
pub async fn await_agent<F, Fut>(
    addr: &vk_core::addr::SocketAddr,
    timeout: Duration,
    mut still_up: F,
) -> Result<AgentWait>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    use vk_core::status::{BOOT_PROBE_BUDGET, get_status_within};
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // The probe's error is not `Send`: keep only its text across the awaits below.
        let probe = get_status_within(addr, BOOT_PROBE_BUDGET)
            .await
            .map_err(|e| e.to_string());
        let Err(e) = probe else {
            return Ok(AgentWait::Answered);
        };
        if !still_up().await? {
            return Ok(AgentWait::Ended);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(AgentWait::TimedOut(e));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The `MEM` cell pairs live process-tree usage with the boot-time size: `1.2G/8G`.
/// Usage includes service VMs and helpers, so this is not guest used/total memory.
/// Each unknown half reads `-` (an unreadable tree or an older `vk run` that did not record
/// `--mem`); when both are unknown, the cell is a single `-`.
pub(crate) fn mem_cell(used: Option<u64>, configured: Option<&str>) -> String {
    if used.is_none() && configured.is_none() {
        return "-".to_string();
    }
    format!(
        "{}/{}",
        used.map_or_else(|| "-".to_string(), compact_bytes),
        configured.unwrap_or("-")
    )
}

/// A memory figure in the narrowest form that still reads — `1.2G`, `780M`, `64K`. The
/// spacious `usage::fmt_bytes` (`1.6 GiB`) is what the detail view uses; the table holds two
/// figures and a slash in one column, so this drops the space and the `iB` and keeps the
/// unit letter of the `--mem` token it sits beside.
fn compact_bytes(bytes: u64) -> String {
    let (gib, mib, kib) = (
        bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        bytes as f64 / (1024.0 * 1024.0),
        bytes as f64 / 1024.0,
    );
    // Each arm branches on the rounded figure it is about to print rather than a coarser
    // one, for the reason `usage::fmt_bytes` spells out: branching on the untruncated MiB
    // while printing the rounded one renders 1023.7 MiB as "1024M".
    match bytes {
        _ if mib.round() >= 1024.0 => format!("{gib:.1}G"),
        _ if kib.round() >= 1024.0 => format!("{mib:.0}M"),
        1024.. => format!("{kib:.0}K"),
        _ => format!("{bytes}B"),
    }
}

/// The PROJECT column: the directory as recorded, or with `$HOME` folded to `~` unless
/// `wide`. `-` when the run recorded none.
pub(crate) fn project_cell(project_dir: Option<&Path>, home: Option<&Path>, wide: bool) -> String {
    let Some(dir) = project_dir else {
        return "-".to_string();
    };
    if wide {
        return dir.display().to_string();
    }
    tilde(dir, home)
}

/// `dir` with `home` replaced by `~`, when `home` is a whole leading component of it.
///
/// Both sides must already be canonical for the prefix to match: `project_dir` is recorded
/// canonicalized, so callers canonicalize `$HOME` too — otherwise a symlinked or
/// automounted home (`/home/me` -> `/data/me`) would silently never fold. `/` is rejected
/// along with a relative or empty `home`: folding it would make every path longer
/// (`~/home/me/app`), not shorter.
fn tilde(dir: &Path, home: Option<&Path>) -> String {
    let Some(home) = home.filter(|h| h.is_absolute() && h.parent().is_some()) else {
        return dir.display().to_string();
    };
    match dir.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => dir.display().to_string(),
    }
}

/// Reject malformed or duplicate `--field` paths before querying VMs. Whitespace and
/// commas can mean several names in one flag. Empty segments and JSON pointer
/// metacharacters (`/`, `~`) are invalid. Duplicates would collapse into one JSON key.
/// [`select`] checks the top-level name on each selected row.
///
/// Paths are quoted in every message, so a stray space or tab shows.
fn check_fields(fields: &[String]) -> Result<()> {
    for path in fields {
        // Check multiple names first so `"pid label."` gets the more useful diagnosis
        // instead of an empty-segment error.
        if path.contains(',') || path.chars().any(char::is_whitespace) {
            bail!(
                "--field {path:?}: a field name holds no whitespace or comma; \
                 repeat --field for several fields"
            );
        }
        if path.split('.').any(str::is_empty) {
            bail!("--field {path:?}: empty path segment");
        }
        if path.contains(['/', '~']) {
            bail!("--field {path:?}: no such field ('/' and '~' never occur in a field name)");
        }
    }
    let mut seen = HashSet::new();
    if let Some(dup) = fields.iter().find(|f| !seen.insert(f.as_str())) {
        bail!("--field {dup:?}: given twice");
    }
    Ok(())
}

/// Resolve a dotted field path such as `ip` or `published.0` on one row. An unknown
/// top-level field is an error listing the valid names. A missing nested value is `null`.
fn select(view: &serde_json::Value, path: &str) -> Result<serde_json::Value> {
    let head = path.split_once('.').map_or(path, |(head, _)| head);
    let fields = view.as_object().context("VM view is not a JSON object")?;
    if !fields.contains_key(head) {
        let hint = if head == "stale" {
            " (pass --stale)"
        } else {
            ""
        };
        let known = fields
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        bail!("--field {path:?}: no field {head:?}{hint}; the fields are: {known}");
    }
    let pointer = format!("/{}", path.replace('.', "/"));
    Ok(view
        .pointer(&pointer)
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

/// A value the way `jq -r` prints it: a string bare, anything else as compact JSON.
fn bare(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `vk list --field`: only `fields` (already past `check_fields`) of each view. As text, one
/// line per VM with the values tab-separated (see `bare`); as JSON, an array of objects
/// holding just those fields, keyed by the path as given.
fn fields_report(views: &[serde_json::Value], fields: &[String], json: bool) -> Result<String> {
    if json {
        let rows = views
            .iter()
            .map(|view| {
                fields
                    .iter()
                    .map(|f| Ok((f.clone(), select(view, f)?)))
                    .collect::<Result<serde_json::Map<_, _>>>()
                    .map(serde_json::Value::Object)
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(serde_json::to_string_pretty(&rows).context("serializing VM fields")? + "\n");
    }
    let mut out = String::new();
    for view in views {
        let cells = fields
            .iter()
            .map(|f| select(view, f).map(|v| bare(&v)))
            .collect::<Result<Vec<_>>>()?;
        out.push_str(&cells.join("\t"));
        out.push('\n');
    }
    Ok(out)
}

#[derive(Debug, Default)]
pub struct ListOpts {
    pub target: Option<std::ffi::OsString>,
    pub recursive: bool,
    pub json: bool,
    pub stale: bool,
    pub fields: Vec<String>,
    pub wide: bool,
    /// Render detail records for the selected VMs.
    pub detail: bool,
    pub filter: crate::vmlist::Filter,
}

/// Render the selected rows in the requested format. A single match still defaults to
/// the table.
pub fn list_report(opts: ListOpts) -> Result<String> {
    use crate::vmlist::{Filter, Kind, Known, Live};
    use crate::vmstate::Standing;
    check_fields(&opts.fields)?;
    let mut filter = opts.filter;
    let target = match &opts.target {
        Some(t) => {
            // Resolve the primary first. The service suffix filters its rows.
            let (sel, service) = Selector::from_ref(Ref::parse(t)?, opts.recursive)?;
            filter.service = service;
            Some(sel.resolved())
        }
        None => selector_of(None, opts.recursive)?.map(Selector::resolved),
    };
    let stale = opts.stale;
    let idx = crate::names::Index::open()?;
    let named = idx.try_all()?;
    // An unindexed dev directory is still selectable by its directory name.
    let unnamed = crate::dev::list::unnamed_dirs(&named)?;
    // Read startup records before the registry. Registration attempts to publish the
    // entry before it clears startup.
    let transients: HashMap<&Path, (crate::vmstate::Transient, Standing)> = (named.iter())
        .map(|(_, dir)| dir)
        .chain(unnamed.iter().map(|(_, dir, _)| dir))
        .filter_map(|dir| Some((dir.as_path(), crate::vmstate::peek(dir)?)))
        .collect();
    let (mut vms, dead) = registered();
    // Exclude every running directory from stopped results, even if the selector misses it.
    let running_dirs: HashSet<PathBuf> = vms.iter().map(|e| e.state_dir.clone()).collect();
    if let Some(sel) = &target {
        vms.retain(|e| sel.matches(e));
    }
    let name_of = |dir: &Path| crate::names::name_in(&named, dir);
    let dev_base = crate::dev::plan::dev_state_base()
        .map(|b| canonical(&b))
        .ok();
    let kind_of = |dir: &Path| kind_of(dir, dev_base.as_deref());
    // A dev environment without an indexed name uses its directory name, including during
    // first boot or a throwaway task. Other unnamed runs (older VMs and foreground UEFI
    // bundles) use their pid.
    let listed_name = |e: &VmEntry| {
        name_of(&e.state_dir).or_else(|| {
            let dir_name = e.state_dir.file_name()?.to_str()?;
            (kind_of(&e.state_dir) == Kind::Dev).then(|| dir_name.to_string())
        })
    };
    let now = unix_now();
    let live: Vec<Live> = vms
        .iter()
        .map(|e| {
            let name = listed_name(e);
            // An unindexed dev environment is stale only after it records a boot.
            let unnamed = name_of(&e.state_dir).is_none()
                && kind_of(&e.state_dir) == Kind::Dev
                && e.state_dir.join("dev.json").is_file();
            // A registered VM is running unless its pid has an active or overdue stop record.
            let stopping = crate::vmstate::peek(&e.state_dir).filter(|(t, standing)| {
                t.state == crate::vmstate::State::Stopping
                    && t.pid == e.pid
                    && *standing != Standing::Gone
            });
            let shown = name.clone().unwrap_or_else(|| e.pid.to_string());
            Live {
                entry: e,
                name,
                kind: kind_of(&e.state_dir),
                environment: dev_identity(&e.state_dir).1,
                units: service_units(e),
                published: published(e),
                mem_used: i32::try_from(e.pid)
                    .ok()
                    .and_then(crate::usage::tree_resident),
                fresh: stale.then(|| freshness_all(e)),
                transient: stopping.as_ref().map(|(t, _)| t.state.label()),
                attention: stopping.and_then(|(t, s)| attention(&t, s, &shown, now)),
                stale_record: unnamed,
            }
        })
        .collect();
    let warn = |e: anyhow::Error| eprintln!("virtkit: warning: {e:#}");
    let known: Vec<Known> = named
        .iter()
        .map(|(name, dir)| {
            let provisional = idx.is_provisional(name);
            (name, dir, crate::vmlist::STOPPED, provisional, false)
        })
        .chain(unnamed.iter().map(|(name, dir, booted)| match booted {
            true => (name, dir, crate::vmlist::STOPPED, false, true),
            false => (name, dir, crate::vmlist::NEVER_BOOTED, false, false),
        }))
        .filter(|(_, dir, ..)| dir.is_dir() && !running_dirs.contains(&canonical(dir)))
        .filter_map(|(name, dir, at_rest, provisional, owed_name)| {
            let recorded = transients.get(dir.as_path());
            // Use a transient state while its liveness check still accepts the record.
            let transient = recorded.filter(|(_, s)| *s != Standing::Gone);
            // Otherwise an uncommitted claim belongs to an abandoned run, and a held lock to a
            // run that registers no VM, or took the directory after its record was read.
            if transient.is_none() && (provisional || dir_locked(dir)) {
                return None;
            }
            let status = transient.map_or(at_rest, |(t, _)| t.state.label());
            let attention = transient.and_then(|(t, s)| attention(t, *s, name, now));
            let stale_record = owed_name
                || (recorded.is_some() && transient.is_none())
                || dead.contains(&canonical(dir));
            let kind = kind_of(dir);
            let last = last_entry(dir).unwrap_or_else(|e| {
                warn(e);
                None
            });
            let (project, environment) = project_of(dir, kind, last.as_ref());
            let k = Known {
                name: name.clone(),
                dir: dir.clone(),
                kind,
                status,
                attention,
                stale_record,
                last,
                project,
                environment,
            };
            let keep = match &target {
                None => true,
                Some(Selector::Pid(_)) => false,
                Some(Selector::Named { dir: d, .. }) => canonical(dir) == *d,
                Some(Selector::Dir { dir: d, below }) => {
                    canonical(dir) == *d
                        || k.project.as_deref().is_some_and(|p| {
                            let p = canonical(p);
                            p == *d || (*below && p.starts_with(d))
                        })
                }
                Some(Selector::Here { .. }) => unreachable!("resolved to a directory above"),
            };
            keep.then_some(k)
        })
        .collect();
    // `--detail` lists a stopped primary's services even when the filter drops their rows.
    let all = crate::vmlist::rows(&live, &known, now);
    let mut rows: Vec<crate::vmlist::Row> =
        all.iter().filter(|r| filter.keeps(r)).cloned().collect();
    if stale {
        // Keep the requested key on every row, including unknown results.
        for r in &mut rows {
            r.stale.get_or_insert(None);
        }
    }
    if !opts.fields.is_empty() {
        let views = rows
            .iter()
            .map(|r| {
                let mut view = serde_json::to_value(r).context("serializing VM row")?;
                // An explicitly selected attention field is null when the full row omits it.
                if let Some(fields) = view.as_object_mut() {
                    fields.entry("attention").or_insert(serde_json::Value::Null);
                    fields.entry("stale_record").or_insert(false.into());
                }
                Ok(view)
            })
            .collect::<Result<Vec<_>>>()?;
        return fields_report(&views, &opts.fields, opts.json);
    }
    if opts.json {
        return Ok(serde_json::to_string_pretty(&rows).context("serializing VM list")? + "\n");
    }
    // Report attention on stderr for both tables and detail records.
    for r in &rows {
        if let Some(why) = &r.attention {
            eprintln!("vk: {}: {why}", r.name);
        }
    }
    let unfiltered = filter == Filter::default();
    // An unfiltered host-wide listing also counts abandoned or dangling names and dead
    // registrations without a listed VM.
    let marked = rows.iter().filter(|r| r.stale_record).count();
    let unlisted = match target.is_none() && unfiltered {
        true => {
            let listed: HashSet<PathBuf> = known.iter().map(|k| canonical(&k.dir)).collect();
            let names = named.iter().filter(|(n, d)| idx.forgettable(n, d)).count();
            names + unlisted_entries(&dead, &listed)
        }
        false => 0,
    };
    if let Some(note) = out_of_date(marked, unlisted) {
        eprintln!("vk: note: {note}");
    }
    if opts.detail && !rows.is_empty() {
        return Ok(details(&rows, &all, &live, stale));
    }
    if rows.is_empty() {
        return Ok(match (&opts.target, &target) {
            (Some(r), _) => format!("no matching vk VM for {}\n", r.to_string_lossy()),
            (None, Some(_)) => "no matching vk VM\n".to_string(),
            (None, None) if !unfiltered => "no matching vk VM\n".to_string(),
            (None, None) => "no vk VMs\n".to_string(),
        });
    }
    // `tilde` matches against a canonical `project_dir`, so canonicalize `$HOME` as well;
    // only the narrow table folds it.
    let home = (!opts.wide)
        .then(|| std::env::var_os("HOME").map(|h| canonical(Path::new(&h))))
        .flatten();
    Ok(crate::vmlist::render(
        &rows,
        home.as_deref(),
        opts.wide,
        stale,
    ))
}

/// Classify a VM by `dev.json` or `run.json`. If both or neither exist, classify direct
/// children of the canonical dev base as dev environments. `vk list` and lifecycle commands
/// share this rule. A run can place its state directory in the dev base, so the kind
/// cannot establish directory ownership.
pub(crate) fn kind_of(dir: &Path, dev_base: Option<&Path>) -> crate::vmlist::Kind {
    use crate::vmlist::Kind;
    let dev = dir.join("dev.json").is_file();
    let run = dir.join(crate::names::RECIPE).is_file();
    if dev != run {
        return if dev { Kind::Dev } else { Kind::Run };
    }
    match canonical(dir).parent() == dev_base {
        true => Kind::Dev,
        false => Kind::Run,
    }
}

/// Count dead registrations without a listed VM, including those whose directories were removed.
fn unlisted_entries(dead: &[PathBuf], listed: &HashSet<PathBuf>) -> usize {
    dead.iter().filter(|d| !listed.contains(*d)).count()
}

/// Summarize marked rows and stale records without a row. Return `None` if both counts are zero.
fn out_of_date(marked: usize, unlisted: usize) -> Option<String> {
    let said: Vec<String> = [
        (marked > 0).then(|| format!("{marked} VM(s) listed from out-of-date records")),
        (unlisted > 0).then(|| format!("{unlisted} out-of-date record(s) of no VM listed")),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!said.is_empty()).then(|| {
        format!(
            "{}. Run `vk stop --tidy` to check all stale records",
            said.join("; ")
        )
    })
}

/// Recovery advice for an overdue stop whose run is still alive.
fn attention(
    t: &crate::vmstate::Transient,
    standing: crate::vmstate::Standing,
    name: &str,
    now: u64,
) -> Option<String> {
    (standing == crate::vmstate::Standing::Overdue).then(|| {
        format!(
            "a stop {} and its run (pid {}) is still there — `vk logs {name}` and `vk list \
             --detail {name}` show it, `vk stop {name}` tries again, `vk stop --force {name}` insists \
             then kills it",
            t.lapse(now),
            t.pid
        )
    })
}

/// Project and environment for a stopped VM in `vk list`. Use the workspace from
/// `dev.json` or the project from `run.json`, falling back to the last registration's
/// project for both display and directory matching.
pub(crate) fn project_of(
    dir: &Path,
    kind: crate::vmlist::Kind,
    last: Option<&VmEntry>,
) -> (Option<PathBuf>, Option<String>) {
    let (project, environment) = match kind {
        crate::vmlist::Kind::Dev => dev_identity(dir),
        _ => match crate::names::Recipe::read(dir) {
            Ok(recipe) => (recipe.map(|r| r.project_dir), None),
            Err(e) => {
                eprintln!("virtkit: warning: {e:#}");
                (None, None)
            }
        },
    };
    (
        project.or_else(|| last.and_then(|e| e.project_dir.clone())),
        environment,
    )
}

/// Read the workspace and environment from `dev.json`. A missing file is normal.
/// Other read errors and malformed JSON produce a warning.
fn dev_identity(state_dir: &Path) -> (Option<PathBuf>, Option<String>) {
    let path = state_dir.join("dev.json");
    let read = match std::fs::read(&path) {
        Ok(json) => serde_json::from_slice::<crate::dev::Identity>(&json)
            .with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (None, None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let identity = match read {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("virtkit: warning: {e:#}");
            return (None, None);
        }
    };
    let text = |key: &str| {
        identity
            .manifest
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    (text("workspace").map(PathBuf::from), text("environment"))
}

/// Render records in table order with a blank line between them. A service gets its
/// own record only when its primary is absent (`NAME/SERVICE` or `--kind service`).
/// Unfiltered rows supply a stopped primary's previously started services.
fn details(
    rows: &[crate::vmlist::Row],
    all: &[crate::vmlist::Row],
    live: &[crate::vmlist::Live],
    stale: bool,
) -> String {
    let primaries: HashSet<&Path> = (rows.iter())
        .filter(|r| r.parent.is_none())
        .map(|r| r.primary_dir.as_path())
        .collect();
    let records: Vec<String> = rows
        .iter()
        .filter(|r| r.parent.is_none() || !primaries.contains(r.primary_dir.as_path()))
        .map(|r| {
            if r.parent.is_some() {
                return detail_service(r, stale);
            }
            match live.iter().find(|l| l.entry.state_dir == r.state_dir) {
                Some(vm) => detail(
                    vm.entry,
                    &record_head(r),
                    vm.units.as_deref(),
                    &vm.published,
                    vm.fresh.unwrap_or(Freshness::Unknown),
                    stale,
                    vm.mem_used,
                ),
                None => detail_unregistered(r, all, stale),
            }
        })
        .collect();
    records.join("\n")
}

/// Detail records use plain STATUS and separate fields for the table's `!` and `*` marks.
fn record_head(r: &crate::vmlist::Row) -> Vec<(&'static str, String)> {
    vec![
        ("NAME", r.name.clone()),
        ("KIND", r.kind.label().to_string()),
        ("STATUS", r.status.clone()),
        (
            "ATTENTION",
            r.attention.clone().unwrap_or_else(|| "-".into()),
        ),
        (
            "STALE RECORD",
            if r.stale_record { "yes" } else { "no" }.into(),
        ),
    ]
}

/// With `--stale`, the IMAGE STALE line of a record whose freshness is never checked.
fn unknown_freshness(stale: bool) -> Option<(&'static str, String)> {
    stale.then(|| ("IMAGE STALE", Freshness::Unknown.cell().to_string()))
}

/// For a primary without a registered run (stopped, never booted or starting), match
/// previously started services by state directory because display names can repeat.
fn detail_unregistered(r: &crate::vmlist::Row, all: &[crate::vmlist::Row], stale: bool) -> String {
    let dash = || "-".to_string();
    let services: Vec<[String; 2]> = (all.iter())
        .filter(|s| s.parent.is_some() && s.primary_dir == r.state_dir)
        .map(|s| {
            let name = s.name.rsplit_once('/').map_or(&*s.name, |(_, n)| n);
            [name.to_string(), s.status.clone()]
        })
        .collect();
    let mut lines = record_head(r);
    lines.extend([
        ("IMAGE", r.image.clone().unwrap_or_else(dash)),
        (
            "PROJECT",
            r.project
                .as_ref()
                .map_or_else(dash, |p| p.display().to_string()),
        ),
        ("STATE DIR", r.state_dir.display().to_string()),
        ("MEM", r.mem.clone().unwrap_or_else(dash)),
    ]);
    lines.extend(unknown_freshness(stale));
    lines.push(("SERVICES", block(&aligned(&services))));
    layout(&lines)
}

/// The `--detail` record of a compose service listed without its primary.
fn detail_service(r: &crate::vmlist::Row, stale: bool) -> String {
    let dash = || "-".to_string();
    let mut lines = record_head(r);
    lines.extend([
        (
            "PROJECT",
            r.project
                .as_ref()
                .map_or_else(dash, |p| p.display().to_string()),
        ),
        ("STATE DIR", r.state_dir.display().to_string()),
        ("EXEC ADDRESS", r.exec_addr.clone().unwrap_or_else(dash)),
        ("IP", r.ip.clone().unwrap_or_else(dash)),
    ]);
    lines.extend(unknown_freshness(stale));
    lines.push(("PUBLISHED", block(&r.published)));
    layout(&lines)
}

/// Align values two spaces past the widest key, including continuation lines.
fn layout(rows: &[(&str, String)]) -> String {
    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (key, value) in rows {
        let mut lines = value.lines();
        out.push_str(&format!(
            "{key:<width$}  {}\n",
            lines.next().unwrap_or_default()
        ));
        for line in lines {
            out.push_str(&format!("{:<width$}  {line}\n", ""));
        }
    }
    out
}

/// A running primary's record includes all declared services (name, state, LAN and
/// exec addresses) and publishers. Paths are full. Missing boot fields and unreported
/// service state or IP appear as `-`.
///
/// `MEM` is the boot-time token. `MEM USED` is the current process-tree usage from
/// `/proc`, or `-` if unreadable. The table combines the two.
fn detail(
    e: &VmEntry,
    head: &[(&'static str, String)],
    units: Option<&[UnitStatus]>,
    published: &[Published],
    freshness: Freshness,
    stale: bool,
    mem_used: Option<u64>,
) -> String {
    let dash = || "-".to_string();
    let opt = |v: Option<String>| v.unwrap_or_else(dash);
    let path = |p: Option<&Path>| opt(p.map(|p| p.display().to_string()));
    let (date, time) = vk_core::atop::date_time(i64::try_from(e.created_secs).unwrap_or(i64::MAX));
    let vmm = match (&e.vmm, e.vmm_pid) {
        (Some(vmm), Some(pid)) => format!("{vmm} (pid {pid})"),
        (Some(vmm), None) => vmm.clone(),
        (None, _) => dash(),
    };
    let yes_no = |b: Option<bool>| opt(b.map(|b| if b { "yes" } else { "no" }.to_string()));
    let mut rows: Vec<(&str, String)> = head.to_vec();
    rows.extend([
        ("IMAGE", e.label.clone()),
        ("PID", e.pid.to_string()),
        (
            "UPTIME",
            format!("{} (since {date} {time} UTC)", uptime(e.created_secs)),
        ),
        ("PROJECT", path(e.project_dir.as_deref())),
        ("STATE DIR", e.state_dir.display().to_string()),
        ("EXEC ADDRESS", e.exec_addr.clone()),
        ("SSH", opt(e.ssh_addr.clone())),
        ("GUEST IP", opt(e.guest_ip.map(|ip| ip.to_string()))),
        ("VMM", vmm),
        ("CPUS", opt(e.cpus.map(|n| n.to_string()))),
        ("MEM", opt(e.mem.clone())),
        ("MEM USED", opt(mem_used.map(crate::usage::fmt_bytes))),
        ("NESTED", yes_no(e.nested)),
        ("ATOP LOG", path(e.atop_log.as_deref())),
    ]);
    if stale {
        rows.push(("IMAGE STALE", freshness.cell().to_string()));
    }
    let services: Vec<[String; 4]> = e
        .services
        .iter()
        .map(|s| {
            let unit = find_unit(units, &s.name);
            [
                s.name.clone(),
                opt(unit.map(|u| u.state.clone())),
                opt(unit.map(|u| bare_ip(&u.ip).to_string())),
                s.exec_addr.clone(),
            ]
        })
        .collect();
    let published_rows: Vec<[String; 3]> = published
        .iter()
        .map(|(p, liveness)| {
            let mut pid = format!("pid {}", p.pid);
            if liveness.unconfirmed() {
                // The lock could not be tested: mark the unconfirmed pid, not the address.
                pid.push_str(" (unconfirmed)");
            }
            [p.name.clone(), published_addr(p), pid]
        })
        .collect();
    rows.push(("SERVICES", block(&aligned(&services))));
    rows.push(("PUBLISHED", block(&aligned(&published_rows))));
    layout(&rows)
}

/// Pad columns to their widest cell, one line per row, with no padding on the last column.
/// Count characters to match the formatter; byte widths add an unwanted space for each
/// extra UTF-8 byte in a non-ASCII service name.
fn aligned<const N: usize>(rows: &[[String; N]]) -> Vec<String> {
    let mut widths = [0usize; N];
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    rows.iter()
        .map(|row| {
            let mut line = String::new();
            let mut cells = row.iter().zip(&widths).peekable();
            while let Some((cell, width)) = cells.next() {
                if cells.peek().is_none() {
                    line.push_str(cell);
                } else {
                    line.push_str(&format!("{cell:<width$}  "));
                }
            }
            line
        })
        .collect()
}

/// A multi-line detail value: the lines joined, or `-` for none.
fn block(lines: &[String]) -> String {
    if lines.is_empty() {
        "-".to_string()
    } else {
        lines.join("\n")
    }
}

/// When a command's time is up: one instant on the monotonic clock, or never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    /// No bound.
    pub const NEVER: Self = Self(None);

    /// `secs` seconds from now; never when that is past what the clock can hold.
    pub fn in_secs(secs: u64) -> Self {
        Self(Instant::now().checked_add(Duration::from_secs(secs)))
    }

    /// What is left of it, zero once it has passed; `None` without a bound.
    pub fn left(self) -> Option<Duration> {
        self.0
            .map(|end| end.saturating_duration_since(Instant::now()))
    }

    /// Whether it has passed.
    pub fn passed(self) -> bool {
        self.left().is_some_and(|left| left.is_zero())
    }

    /// `d`, or what is left of it when that is less.
    pub fn cap(self, d: Duration) -> Duration {
        self.left().map_or(d, |left| left.min(d))
    }
}

/// How often a stop looks whether its runs are gone.
const STOP_POLL: Duration = Duration::from_millis(100);

/// A process held by its pidfd: a signal sent through it reaches the process it was opened
/// on or nothing, whatever its pid has come to name since, and it reads as exited once that
/// process has, reaped or not.
pub(crate) struct Held {
    fd: std::os::fd::OwnedFd,
    pid: i32,
}

impl Held {
    /// Process `pid`, or `None` when it is gone. Any other failure — no pidfds before Linux
    /// 5.3, or a filter denying them — is the caller's to report.
    fn open(pid: i32) -> std::io::Result<Option<Self>> {
        use std::os::fd::FromRawFd;
        // SAFETY: `pidfd_open` takes a pid and flags and returns a new descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ESRCH) => Ok(None),
                _ => Err(e),
            };
        }
        let fd = i32::try_from(fd).map_err(|_| std::io::Error::other("pidfd out of range"))?;
        // SAFETY: a fresh descriptor nothing else owns.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        Ok(Some(Held { fd, pid }))
    }

    /// Another handle on the same process.
    fn try_clone(&self) -> std::io::Result<Self> {
        let fd = self.fd.try_clone()?;
        Ok(Held { fd, pid: self.pid })
    }

    /// Send it `signal`: `Ok(false)` when it is gone already.
    fn signal(&self, signal: libc::c_int) -> std::io::Result<bool> {
        // SAFETY: `pidfd_send_signal` on a pidfd this value owns, with no siginfo.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 {
            return Ok(true);
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            _ => Err(e),
        }
    }

    /// Whether it has exited: its pidfd reads as ready.
    pub(crate) fn exited(&self) -> bool {
        let mut fd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd this frame owns, and a zero timeout: it never blocks.
        unsafe { libc::poll(&raw mut fd, 1, 0) > 0 }
    }

    /// Whether `stream` is connected to a listener this process opened, and the process is
    /// still running: a listener's credentials are those of whoever called `listen`, and a
    /// pid is not reused while its process lives.
    fn serves(&self, stream: &std::os::unix::net::UnixStream) -> std::io::Result<bool> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: SO_PEERCRED writes one `ucred` through a pointer to a local of that size,
        // and the descriptor is `stream`'s, live for the call.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cred.pid == self.pid && !self.exited())
    }
}

/// What a pid is to the run a [`VmEntry`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    Run,
    Other,
    /// the entry recorded no start time and procfs names no holder of its state-dir lock
    Unknown,
}

/// Whether `pid` is the run `entry` records: started at the recorded time, or, for an entry
/// that recorded none, the holder of its state-dir lock.
fn identity(entry: &VmEntry, pid: i32) -> Identity {
    let of = |same: bool| if same { Identity::Run } else { Identity::Other };
    if let Some(ticks) = entry.pid_start_ticks {
        return of(crate::usage::proc_starttime(pid) == Some(ticks));
    }
    std::fs::File::open(&entry.state_dir)
        .ok()
        .and_then(|f| crate::run::flock_holder_pid(&f))
        .map_or(Identity::Unknown, |holder| of(holder == pid))
}

/// The run `entry` records, held by its pidfd once identified, so neither a signal nor the
/// wait for its exit can reach another process: `Ok(None)` when it is gone, or an error
/// saying why it is not signalled. A run whose identity cannot be told is never signalled.
pub(crate) fn held_run(entry: &VmEntry) -> std::result::Result<Option<Held>, String> {
    let pid = i32::try_from(entry.pid)
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| "its record has an unusable pid".to_string())?;
    let Some(held) = Held::open(pid).map_err(|e| format!("cannot hold pid {pid}: {e}"))? else {
        return Ok(None);
    };
    match identity(entry, pid) {
        Identity::Run => Ok(Some(held)),
        // A free lock or a replacement run's startup record identifies a departed run.
        // Otherwise report an unconfirmed identity without signalling the lock holder.
        _ if !dir_locked(&entry.state_dir) || superseded(entry) => Ok(None),
        Identity::Other => {
            Err("another process holds its state dir now, so nothing was signalled".to_string())
        }
        Identity::Unknown => Err(format!(
            "cannot confirm pid {pid} is its run (no start time recorded, no lock holder \
             named), so it was not signalled"
        )),
    }
}

/// Whether both entries have the same [`run_id`].
pub(crate) fn same_run(a: &VmEntry, b: &VmEntry) -> bool {
    run_id(a) == run_id(b)
}

/// Identify a registration by pid, optional process start time and registration time.
pub(crate) fn run_id(entry: &VmEntry) -> String {
    let ticks = entry
        .pid_start_ticks
        .map_or("-".to_string(), |t| t.to_string());
    format!("{}:{ticks}:{}", entry.pid, entry.created_secs)
}

/// Set on the `vk dev service down` that `vk stop` runs, to the [`run_id`] of the run it
/// selected: the service is stopped only while its environment is still that run.
pub const STOP_RUN_ENV: &str = "VIRTKIT_STOP_RUN";

/// Remove the registry record, in `dir`, of the run `entry` records, once that run is gone:
/// under its state-dir lock, so a run that took the directory over keeps its own record, and
/// only while the record is still that run's.
/// A record whose state dir cannot be locked, or is gone, is left: a run may be creating it
/// again.
fn prune_gone(dir: &Path, entry: &VmEntry) -> Pruned {
    let lock = match std::fs::File::open(&entry.state_dir) {
        Ok(lock) => vk_fs::LockFile::new(lock),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Pruned::DirGone,
        Err(e) => return Pruned::Failed(format!("{}: {e}", entry.state_dir.display())),
    };
    // SAFETY: the fd is owned by `lock`, which outlives the call; LOCK_NB never blocks. The
    // lock is released when `lock` drops.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Pruned::Held;
    }
    let path = dir.join(format!("{}.json", slug(&entry.state_dir)));
    let recorded = match std::fs::read(&path) {
        Ok(json) => serde_json::from_slice::<VmEntry>(&json),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Pruned::Replaced,
        Err(e) => return Pruned::Failed(format!("{}: {e}", path.display())),
    };
    match recorded {
        Ok(r) if same_run(&r, entry) => {}
        Ok(_) => return Pruned::Replaced,
        Err(e) => return Pruned::Failed(format!("{}: {e}", path.display())),
    }
    match std::fs::remove_file(&path) {
        Ok(()) => Pruned::Removed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Pruned::Replaced,
        Err(e) => Pruned::Failed(format!("{}: {e}", path.display())),
    }
}

/// What [`prune_gone`] did with an entry whose run is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pruned {
    Removed,
    /// the entry is another run's now, or another command removed it first
    Replaced,
    /// left: its state dir is gone, and a run may be making it again
    DirGone,
    /// left because the state directory could not be locked
    Held,
    /// left: why it could not be removed
    Failed(String),
}

/// Pruning outcomes by state directory and diagnostics for unreadable entries.
pub type Pruning = (Vec<(PathBuf, Pruned)>, Vec<String>);

/// Try to remove dead entries as [`running`] does and report each outcome to `vk stop --tidy`.
pub fn prune_dead() -> Result<Pruning> {
    let dir = registry_dir()?;
    let (all, unread) = try_load_all_in(&dir)?;
    let pruned = (all.into_iter().filter(|e| !alive(e)))
        .map(|e| {
            let pruned = prune_gone(&dir, &e);
            (e.state_dir, pruned)
        })
        .collect();
    Ok((pruned, unread))
}

/// How `vk stop` goes about stopping a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StopHow {
    /// Send SIGTERM once and wait for the run to shut down its guests
    #[default]
    Graceful,
    /// `--force`: SIGTERM once a second for [`FORCE_TERM_SECS`], then kill
    Force,
    /// `--kill`: kill right away — the VMMs first, the run only if it does not follow
    Kill,
}

/// How long `--force` keeps asking with SIGTERM before it kills.
pub const FORCE_TERM_SECS: u64 = 5;

/// Seconds for runs to finish cleanup after the VMM batch. After SIGKILL to the runs,
/// only the command deadline limits the wait.
pub const KILL_WAIT_SECS: u64 = 5;

/// Intervals before killing VMMs and before killing the surviving runs.
#[derive(Debug, Clone, Copy)]
struct Pace {
    term: Duration,
    kill_wait: Duration,
}

const PACE: Pace = Pace {
    term: Duration::from_secs(FORCE_TERM_SECS),
    kill_wait: Duration::from_secs(KILL_WAIT_SECS),
};

/// Where the stop of one run stands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fate {
    /// told to stop, not gone yet
    Stopping,
    Down,
    /// not stopped, and why
    Failed(String),
}

/// One run [`Stops`] is stopping.
struct RunStop {
    entry: VmEntry,
    /// the run, held from the moment it is identified
    run: Option<Held>,
    fate: Fate,
    /// VMMs whose exit must be confirmed before reporting the run down
    vmms: Vec<Held>,
}

impl RunStop {
    fn of(entry: VmEntry) -> Self {
        let (run, fate) = match held_run(&entry) {
            Ok(Some(run)) => (Some(run), Fate::Stopping),
            Ok(None) => (None, Fate::Down),
            Err(why) => (None, Fate::Failed(why)),
        };
        RunStop {
            entry,
            run,
            fate,
            vmms: Vec::new(),
        }
    }

    /// Signal a run still stopping. [`RunStop::check`] also waits for its VMMs to exit.
    fn signal(&mut self, signal: libc::c_int) {
        let (Fate::Stopping, Some(run)) = (&self.fate, &self.run) else {
            return;
        };
        match run.signal(signal) {
            Ok(_) => {}
            Err(e) => {
                self.fate = Fate::Failed(format!("cannot signal pid {}: {e}", self.entry.pid))
            }
        }
    }

    /// Cut power to the primary, compose service and build VMs. The registry identifies only
    /// the primary's VMM. [`crate::vmm::processes_under`] finds the others by their boot
    /// environments. Recheck the held run after collecting the VMM pidfds.
    ///
    /// Signal in reverse acquisition order so a boot child discovered with or after its
    /// keeper gets SIGKILL first. A child forked after the final scan is missed. It arms
    /// parent-death SIGTERM after fork, so delivery depends on when the keeper exits.
    /// The run can finish cleanup after its VMs exit.
    fn kill_vmms(&mut self) {
        let (Fate::Stopping, Some(run)) = (&self.fate, &self.run) else {
            return;
        };
        let Ok(pid) = i32::try_from(self.entry.pid) else {
            return;
        };
        let killed = hold_vmms(|| crate::vmm::processes_under(pid)).and_then(|held| {
            if run.exited() {
                return Ok(None);
            }
            let mut killed = Vec::new();
            // Signal newly discovered children before their keepers.
            for (vmm, h) in held.into_iter().rev() {
                h.signal(libc::SIGKILL)
                    .map_err(|e| format!("cannot kill its VMM pid {vmm}: {e}"))?;
                killed.push(h);
            }
            Ok(Some(killed))
        });
        match killed {
            Ok(Some(killed)) => self.vmms.extend(killed),
            Ok(None) => self.fate = Fate::Down,
            Err(why) => self.fate = Fate::Failed(why),
        }
    }

    /// Mark the run down once it and its targeted VMMs have exited.
    fn check(&mut self) {
        if self.fate == Fate::Stopping
            && self.run.as_ref().is_some_and(Held::exited)
            && self.vmms.iter().all(Held::exited)
        {
            self.fate = Fate::Down;
        }
    }

    /// Report the outcome after `waited` seconds, with a retry hint for a plain stop.
    fn line(&self, waited: u64, how: StopHow) -> String {
        let RunStop { entry, .. } = self;
        let next = match how {
            StopHow::Graceful => format!(" (`vk stop --force {}` insists, then kills)", entry.pid),
            StopHow::Force | StopHow::Kill => String::new(),
        };
        match &self.fate {
            Fate::Down => format!("stopped {} (pid {})\n", entry.label, entry.pid),
            Fate::Stopping => format!(
                "{} (pid {}) did not stop after {waited}s{next}\n",
                entry.label, entry.pid
            ),
            Fate::Failed(why) => format!("{} (pid {}): {why}\n", entry.label, entry.pid),
        }
    }
}

/// Stop the managed publishers of `runs`, and those left on record in each of `stale`, a
/// state dir no run holds, on a thread of their own: a publisher's lock held elsewhere delays
/// no signal and no wait. They go while their targets shut down, rather than hold unusable
/// bound addresses until their next probe; they normally exit at once on SIGTERM, so each is
/// given at most five seconds, within `deadline`.
fn unpublish(
    runs: &[RunStop],
    stale: Vec<PathBuf>,
    deadline: Deadline,
) -> std::thread::JoinHandle<()> {
    let mut dirs: Vec<(PathBuf, Option<Held>)> = (runs.iter())
        .filter(|r| !matches!(r.fate, Fate::Failed(_)))
        .map(|r| {
            let run = r.run.as_ref().and_then(|h| h.try_clone().ok());
            (r.entry.state_dir.clone(), run)
        })
        .collect();
    dirs.extend(stale.into_iter().map(|dir| (dir, None)));
    std::thread::spawn(move || {
        for (dir, run) in dirs {
            // Under the publisher lock, clean up only while the selected run is alive or
            // the state directory is unlocked. A replacement may already hold that directory.
            let still = || run.as_ref().is_some_and(|h| !h.exited()) || !dir_locked(&dir);
            crate::publish::stop_all_within(&dir, deadline, &still);
        }
    })
}

/// Open pidfds for newly listed VMMs. Rescan until every listed PID is already held, so
/// a boot child forked between scans can be included. Return the handles still listed,
/// in acquisition order. Fail if the last scan still contains a new PID.
fn hold_vmms(mut scan: impl FnMut() -> Vec<i32>) -> std::result::Result<Vec<(i32, Held)>, String> {
    let mut held: Vec<(i32, Held)> = Vec::new();
    for _ in 0..VMM_SCANS {
        let now = scan();
        let new: Vec<i32> = (now.iter().copied())
            .filter(|vmm| !held.iter().any(|(h, _)| h == vmm))
            .collect();
        if new.is_empty() {
            held.retain(|(vmm, _)| now.contains(vmm));
            return Ok(held);
        }
        for vmm in new {
            match Held::open(vmm) {
                Ok(Some(h)) => held.push((vmm, h)),
                Ok(None) => {}
                Err(e) => return Err(format!("cannot hold its VMM pid {vmm}: {e}")),
            }
        }
    }
    Err(format!(
        "its VMMs still changed after {VMM_SCANS} listings, so none was killed"
    ))
}

/// How many times at most [`hold_vmms`] lists them.
const VMM_SCANS: usize = 8;

/// Runs stopped together: every one is told to stop ([`Stops::begin`]) before any is waited
/// for ([`Stops::finish`]), and one deadline bounds both. The deadline never kills: a run
/// still there when it passes is reported, whatever `how`.
pub(crate) struct Stops {
    runs: Vec<RunStop>,
    deadline: Deadline,
    /// where their records are pruned once they are gone
    registry: Option<PathBuf>,
    began: Instant,
    how: StopHow,
    pace: Pace,
    /// start of the retry interval and number of SIGTERM rounds, including the initial round
    asked: (Instant, u32),
    /// when the batch of VMM kill attempts finished
    vmms_killed: Option<Instant>,
    /// whether the run SIGKILL round has been attempted
    runs_killed: bool,
    /// the stop of their publishers, under way beside the wait
    unpublishing: std::thread::JoinHandle<()>,
}

impl Stops {
    /// Send every run in `entries` SIGTERM, or with [`StopHow::Kill`] kill its VMMs, then
    /// stop the managed publishers of each, and those left on record in each of `stale`, a
    /// state dir no run holds.
    pub(crate) fn begin(
        entries: Vec<VmEntry>,
        stale: Vec<PathBuf>,
        deadline: Deadline,
        how: StopHow,
    ) -> Self {
        Self::begin_in(registry_dir().ok(), entries, stale, deadline, how, PACE)
    }

    /// [`Stops::begin`], against the registry at `registry`, at `pace`.
    fn begin_in(
        registry: Option<PathBuf>,
        entries: Vec<VmEntry>,
        stale: Vec<PathBuf>,
        deadline: Deadline,
        how: StopHow,
        pace: Pace,
    ) -> Self {
        let began = Instant::now();
        let mut runs: Vec<RunStop> = entries.into_iter().map(RunStop::of).collect();
        // Record each held run before signalling it. The stop becomes overdue if its run
        // outlives the deadline or the stop command.
        for r in runs.iter().filter(|r| r.fate == Fate::Stopping) {
            let e = &r.entry;
            crate::vmstate::stopping(&e.state_dir, e.pid, e.pid_start_ticks, deadline.left());
        }
        let vmms_killed = match how {
            StopHow::Kill => {
                runs.iter_mut().for_each(RunStop::kill_vmms);
                Some(Instant::now())
            }
            StopHow::Graceful | StopHow::Force => {
                runs.iter_mut().for_each(|r| r.signal(libc::SIGTERM));
                None
            }
        };
        let unpublishing = unpublish(&runs, stale, deadline);
        Stops {
            runs,
            deadline,
            registry,
            began,
            how,
            pace,
            asked: (Instant::now(), 1),
            vmms_killed,
            runs_killed: false,
            unpublishing,
        }
    }

    /// Start the shared cleanup interval after attempting every run's VMMs.
    fn kill_vmms(&mut self) {
        self.runs.iter_mut().for_each(RunStop::kill_vmms);
        self.vmms_killed = Some(Instant::now());
    }

    /// Retry SIGTERM during the force interval, then kill the VMMs. Give all runs one
    /// cleanup interval before SIGKILL. The command deadline bounds subsequent waits.
    fn escalate(&mut self) {
        match (self.how, self.vmms_killed, self.runs_killed) {
            (StopHow::Graceful, ..) => {}
            (StopHow::Force, None, _) => {
                let (at, terms) = self.asked;
                let asking = at.elapsed();
                if asking >= self.pace.term {
                    self.kill_vmms();
                } else if asking >= Duration::from_secs(u64::from(terms)) {
                    // A run may handle signals only between build or boot steps.
                    self.runs.iter_mut().for_each(|r| r.signal(libc::SIGTERM));
                    self.asked.1 = terms.saturating_add(1);
                }
            }
            (_, Some(at), false) if at.elapsed() >= self.pace.kill_wait => {
                self.runs.iter_mut().for_each(|r| r.signal(libc::SIGKILL));
                self.runs_killed = true;
            }
            _ => {}
        }
    }

    /// Wait for every run to exit, or the deadline to pass; prune the records of those gone.
    /// Returns one report line per run, and whether every one went down. A run still
    /// stopping when the deadline passes is reported and left to finish its shutdown.
    pub(crate) fn finish(mut self) -> (String, bool) {
        loop {
            self.runs.iter_mut().for_each(RunStop::check);
            if self.runs.iter().all(|r| r.fate != Fate::Stopping) || self.deadline.passed() {
                break;
            }
            self.escalate();
            std::thread::sleep(self.deadline.cap(STOP_POLL));
        }
        // It ends by the deadline too; a panic there is not the stop's to report.
        let _ = self.unpublishing.join();
        let waited = self.began.elapsed().as_secs();
        let mut out = String::new();
        for r in &self.runs {
            if let (Fate::Down, Some(registry)) = (&r.fate, &self.registry) {
                prune_gone(registry, &r.entry);
            }
            // Leave unfinished stops on record so listing can report them as overdue.
            if r.fate != Fate::Stopping {
                let e = &r.entry;
                crate::vmstate::clear_of(&e.state_dir, e.pid, e.pid_start_ticks);
            }
            out.push_str(&r.line(waited, self.how));
        }
        let down = self.runs.iter().all(|r| r.fate == Fate::Down);
        (out, down)
    }
}

/// Whether an empty selection succeeds. An explicit `vk stop TARGET` returns not-found (exit 1)
/// so scripts can distinguish "stopped it" from "there was nothing there". `--all` and the
/// current-directory default treat an empty selection as already done.
fn empty_selection_ok(explicit_target: bool) -> bool {
    !explicit_target
}

/// A VM reference (see [`Ref::parse`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ref {
    /// the pid of a VM's managing `vk run`, as `vk list` prints it; with a compose service
    /// of that VM, for `PID/SERVICE`
    Pid(u32, Option<String>),
    /// a project directory or a state directory
    Path(PathBuf),
    /// a VM name, or a bare word that may still be a directory (see [`Selector::from_ref`]);
    /// `NAME/SERVICE` names one of its compose services
    Name { vm: String, service: Option<String> },
}

impl Ref {
    /// ASCII digits within `u32` name a pid. `+5` and numbers above `u32::MAX` are words.
    /// `/…`, `./…`, `../…`, `~…`, `.` and `..` are paths, as is any non-UTF-8 argument.
    /// Paths retain their original bytes. Other words are names. For a compose service,
    /// use `NAME/SERVICE` or `PID/SERVICE`, including when the primary has no name.
    pub fn parse(arg: &OsStr) -> Result<Self> {
        let bytes = arg.as_bytes();
        if bytes.is_empty() {
            bail!("empty target — pass a name, a pid or a directory");
        }
        if bytes.iter().all(u8::is_ascii_digit)
            && let Some(pid) = arg.to_str().and_then(|s| s.parse::<u32>().ok())
        {
            return Ok(Ref::Pid(pid, None));
        }
        let pathlike = bytes.starts_with(b"/")
            || bytes.starts_with(b"./")
            || bytes.starts_with(b"../")
            || bytes == b"."
            || bytes == b"..";
        if pathlike {
            return Ok(Ref::Path(PathBuf::from(arg)));
        }
        if bytes.starts_with(b"~") {
            return Ok(Ref::Path(expand_tilde(arg)));
        }
        let Some(text) = arg.to_str() else {
            // Not UTF-8, so no name: only a directory can be meant.
            return Ok(Ref::Path(PathBuf::from(arg)));
        };
        Ok(match text.split_once('/') {
            Some((vm, service)) => {
                let service =
                    Some(service.trim_end_matches('/').to_string()).filter(|s| !s.is_empty());
                // No name is all digits, so digits before the slash are a pid.
                match vm.parse::<u32>() {
                    Ok(pid) if vm.bytes().all(|b| b.is_ascii_digit()) => Ref::Pid(pid, service),
                    _ => Ref::Name {
                        vm: vm.to_string(),
                        service,
                    },
                }
            }
            None => Ref::Name {
                vm: text.to_string(),
                service: None,
            },
        })
    }
}

/// `~` or `~/rest` with `$HOME` put in; any other `~…` as it is.
fn expand_tilde(arg: &OsStr) -> PathBuf {
    let bytes = arg.as_bytes();
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty());
    match (home, bytes) {
        (Some(home), b"~") => PathBuf::from(home),
        (Some(home), _) if bytes.starts_with(b"~/") => {
            // `~//x` is `$HOME/x`: a rest still starting with `/` would replace `$HOME`.
            let mut rest = bytes.get(1..).unwrap_or_default();
            while let [b'/', tail @ ..] = rest {
                rest = tail;
            }
            PathBuf::from(home).join(OsStr::from_bytes(rest))
        }
        _ => PathBuf::from(arg),
    }
}

/// Select a primary by pid, name, state directory or project directory. With `below`,
/// include descendant projects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Pid(u32),
    Dir {
        dir: PathBuf,
        below: bool,
    },
    Named {
        name: String,
        dir: PathBuf,
    },
    /// the current directory no REF stands for — `-r` alone — which, unlike an explicit
    /// directory, may select nothing (see [`empty_selection_ok`]); a [`Selector::Dir`] once
    /// [`Selector::resolved`]
    Here {
        below: bool,
    },
}

impl Selector {
    /// [`Ref::parse`] then [`Selector::from_ref`], for a command that has no service form.
    pub fn parse(arg: &OsStr) -> Result<Self> {
        Self::parse_below(arg, false)
    }

    /// [`Selector::parse`] with `--recursive`'s `below`.
    pub fn parse_below(arg: &OsStr, below: bool) -> Result<Self> {
        match Self::from_ref(Ref::parse(arg)?, below)? {
            (sel, None) => Ok(sel),
            (_, Some(service)) => bail!(
                "{} names the compose service {service}: this command acts on whole VMs",
                arg.to_string_lossy()
            ),
        }
    }

    /// Look up the VM name or dev state directory name first. From its parent, a dev
    /// checkout can have the same name as its VM. `./word` selects the directory.
    /// For compatibility with `vk stop DIR`, an unmatched word can select an existing
    /// directory with a note. [`check_service`] validates any selected service.
    pub fn from_ref(r: Ref, below: bool) -> Result<(Self, Option<String>)> {
        let (sel, service) = match r {
            Ref::Pid(pid, service) => (Selector::Pid(pid), service),
            Ref::Path(dir) => (Selector::Dir { dir, below }, None),
            Ref::Name { vm, service } => match crate::names::resolve(&vm)? {
                Some(dir) => (Selector::Named { name: vm, dir }, service),
                None => {
                    let word = match &service {
                        Some(s) => format!("{vm}/{s}"),
                        None => vm.clone(),
                    };
                    if !Path::new(&word).is_dir() {
                        bail!("no VM is named {vm} (`vk list` names them)");
                    }
                    eprintln!(
                        "vk: note: reading {word} as a directory; write ./{word} — a bare \
                         word is a VM name"
                    );
                    let dir = PathBuf::from(word);
                    (Selector::Dir { dir, below }, None)
                }
            },
        };
        if let Some(s) = &service {
            check_service(s)?;
        }
        Ok((sel, service))
    }

    /// Resolve a directory once so every entry is matched against the same path.
    fn resolved(self) -> Self {
        match self {
            Selector::Dir { dir, below } => Selector::Dir {
                dir: canonical(&dir),
                below,
            },
            Selector::Named { name, dir } => Selector::Named {
                name,
                dir: canonical(&dir),
            },
            Selector::Here { below } => Selector::Dir {
                dir: canonical(Path::new(".")),
                below,
            },
            pid => pid,
        }
    }

    /// Whether this selector picks `entry`. The directory is already [`Selector::resolved`].
    fn matches(&self, entry: &VmEntry) -> bool {
        match self {
            Selector::Pid(pid) => entry.pid == *pid,
            Selector::Dir { dir, below } => matches_dir(entry, dir, *below),
            Selector::Named { dir, .. } => entry.state_dir == *dir,
            Selector::Here { below } => matches_dir(entry, &canonical(Path::new(".")), *below),
        }
    }

    /// What to report when it picks nothing.
    pub fn not_found(&self) -> String {
        match self {
            Selector::Pid(pid) => format!("no running vk VM with pid {pid}\n"),
            Selector::Dir { dir, below: true } => {
                format!("no running vk VM under {}\n", dir.display())
            }
            Selector::Dir { dir, below: false } => {
                format!("no running vk VM for {}\n", dir.display())
            }
            Selector::Named { name, .. } => {
                format!("{name} is not running (`vk start {name}`)\n")
            }
            Selector::Here { .. } => "no matching running vk VM\n".to_string(),
        }
    }
}

/// The running VMs `target` selects, the current directory's (exactly) when it is `None`.
fn select_running(target: Option<Selector>) -> Result<(Selector, Vec<VmEntry>)> {
    let sel = match target {
        Some(sel) => sel.resolved(),
        None => Selector::Dir {
            dir: std::env::current_dir().context("resolving the current directory")?,
            below: false,
        },
    };
    let matched = (registered().0.into_iter())
        .filter(|e| sel.matches(e))
        .collect();
    Ok((sel, matched))
}

/// The one running VM a REF names (default: the current directory's), and the compose
/// service it names, merged with a `--service` given beside it. Errors when nothing runs
/// there, or when several VMs match a directory.
pub fn resolve_ref(
    target: Option<&OsStr>,
    service: Option<&str>,
) -> Result<(VmEntry, Option<String>)> {
    let (sel, service) = resolve_target(target, service)?;
    Ok((one_running(sel)?, service))
}

/// Resolve a REF once (`None`: the current directory's VM) into what it selects and the
/// compose service it names, merged with a `--service` given beside it and checked by
/// [`check_service`].
pub fn resolve_target(
    target: Option<&OsStr>,
    service: Option<&str>,
) -> Result<(Option<Selector>, Option<String>)> {
    let (sel, named) = match target {
        Some(t) => {
            let (sel, named) = Selector::from_ref(Ref::parse(t)?, false)?;
            (Some(sel), named)
        }
        None => (None, None),
    };
    let service = match (named, service) {
        (Some(a), Some(b)) if a != b => {
            bail!("the REF selects the service {a} and the option selects {b}: choose one")
        }
        (a, b) => a.or(b.map(str::to_string)),
    };
    if let Some(s) = &service {
        check_service(s)?;
    }
    Ok((sel, service))
}

/// Require one service name before joining `svc-<service>` to the state directory.
/// A slash could introduce another path component. Leading dots are also disallowed.
pub fn check_service(service: &str) -> Result<()> {
    if !is_service_name(service) {
        bail!("{service:?} is not a compose service name");
    }
    Ok(())
}

/// Whether `s` can be a compose service's name: `[A-Za-z0-9_.-]+`, not starting with `.`.
pub fn is_service_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The one running VM `sel` selects (default: the current directory's). Errors when nothing
/// runs there, or when several VMs match a directory.
pub fn one_running(sel: Option<Selector>) -> Result<VmEntry> {
    let (sel, entry) = at_most_one(sel)?;
    entry.ok_or_else(|| anyhow::anyhow!("{}", sel.not_found().trim_end()))
}

/// The running VM `sel` selects (default: the current directory's), `None` when nothing
/// runs there, with the selector resolved — a caller falling back to a stopped VM's state
/// dir takes it from there. Errors when several VMs match.
pub fn at_most_one(sel: Option<Selector>) -> Result<(Selector, Option<VmEntry>)> {
    let (sel, matched) = select_running(sel)?;
    Ok((sel, single(matched)?))
}

/// The one VM of `matched`, if any; several is an error that lists each as a REF to pass.
fn single(mut matched: Vec<VmEntry>) -> Result<Option<VmEntry>> {
    match matched.len() {
        0 | 1 => Ok(matched.pop()),
        n => bail!(
            "{n} running vk VMs match: {} — name one",
            matched
                .iter()
                .map(display_name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// How a VM is named in a message, as a REF to pass back: its name, else its pid.
pub fn display_name(entry: &VmEntry) -> String {
    crate::names::Index::open()
        .ok()
        .and_then(|idx| idx.name_of(&entry.state_dir))
        .unwrap_or_else(|| entry.pid.to_string())
}

/// The selector a list/stop/reboot/pause/resume REF stands for; with `recursive` and no REF,
/// every VM at or below the current directory.
pub fn selector_of(target: Option<&OsStr>, recursive: bool) -> Result<Option<Selector>> {
    match target {
        Some(t) => Selector::parse_below(t, recursive).map(Some),
        None if recursive => Ok(Some(Selector::Here { below: true })),
        None => Ok(None),
    }
}

/// The VMs a stop/reboot command should act on: either a non-empty selection, or the summary
/// and exit status to report when nothing matched.
enum Selection {
    Matched(Vec<VmEntry>),
    Empty(String, bool),
}

/// Resolve `--all`, a pid or project directory, or the current directory (the default) into
/// the running VMs to act on. Shared by [`stop_cmd`] and [`reboot_cmd`].
fn select_vms(target: Option<Selector>, all: bool) -> Result<Selection> {
    let vms = registered().0;
    let explicit = matches!(&target, Some(sel) if !matches!(sel, Selector::Here { .. }));
    let target = target.map(Selector::resolved);
    let selected: Vec<VmEntry> = match (all, &target) {
        (true, _) => vms,
        (false, Some(sel)) => vms.into_iter().filter(|e| sel.matches(e)).collect(),
        (false, None) => {
            let cwd = std::env::current_dir().context("resolving the current directory")?;
            vms.into_iter()
                .filter(|e| matches_dir(e, &cwd, false))
                .collect()
        }
    };
    if selected.is_empty() {
        return Ok(match &target {
            Some(sel) if explicit => Selection::Empty(sel.not_found(), empty_selection_ok(true)),
            _ => Selection::Empty(
                "no matching running vk VM\n".to_string(),
                empty_selection_ok(false),
            ),
        });
    }
    Ok(Selection::Matched(selected))
}

/// Stop VMs selected by `--all`, a pid or project directory, or the current directory by
/// default, all at once and as `how` says, with `deadline` bounding the whole of it. Returns
/// the summary and whether every selected VM went down.
pub fn stop_cmd(
    target: Option<Selector>,
    all: bool,
    deadline: Deadline,
    how: StopHow,
) -> Result<(String, bool)> {
    let selected = match select_vms(target, all)? {
        Selection::Matched(v) => v,
        Selection::Empty(out, ok) => return Ok((out, ok)),
    };
    Ok(Stops::begin(selected, Vec::new(), deadline, how).finish())
}

/// Whether procfs identifies a different pid holding the state-directory lock. An unknown
/// holder passes this check. [`held_run`] still verifies identity before signalling.
pub(crate) fn held_by_another(entry: &VmEntry) -> bool {
    std::fs::File::open(&entry.state_dir)
        .ok()
        .and_then(|f| crate::run::flock_holder_pid(&f))
        .is_some_and(|pid| u32::try_from(pid) != Ok(entry.pid))
}

/// Stop the VM `entry` records, and only it: `None`, with nothing stopped or signalled,
/// when [`held_by_another`]. Otherwise the report line, and whether it went down.
pub(crate) fn stop_entry(entry: &VmEntry, timeout: u64) -> Option<(String, bool)> {
    if held_by_another(entry) {
        return None;
    }
    let deadline = Deadline::in_secs(timeout);
    Some(Stops::begin(vec![entry.clone()], Vec::new(), deadline, StopHow::Graceful).finish())
}

/// The running VMs `sel` selects, and what to say when it selects none.
pub(crate) fn running_selected(sel: Selector) -> Result<(Vec<VmEntry>, String)> {
    let (sel, matched) = select_running(Some(sel))?;
    Ok((matched, sel.not_found()))
}

/// How a VM was rebooted, or why it was not.
enum Rebooted {
    /// Clean reboot through the guest agent.
    Agent,
    /// Power-cycled through the VMM keeper: `--force`, or the agent was unreachable.
    HardReset,
    NotRunning,
}

/// Reboot the guest managed by `entry` in place. Unless `force`, ask its agent to reboot
/// (over vsock); on `force` or an unreachable agent, SIGUSR1 the managing `vk run`, which
/// hard-resets the VM through its keeper.
fn reboot_one(entry: &VmEntry, force: bool) -> Rebooted {
    if !alive(entry) {
        return Rebooted::NotRunning;
    }
    if !force
        && let Ok(addr) = vk_core::addr::SocketAddr::from_str(&entry.exec_addr)
        && crate::shutdown::request_reboot(&addr)
    {
        return Rebooted::Agent;
    }
    // Hard reset: the managing `vk run` forwards SIGUSR1 to the VMM keeper (see run.rs).
    if let Ok(pid) = i32::try_from(entry.pid) {
        // SAFETY: kill(2) with a plain signal number; worst case ESRCH if the pid is gone.
        unsafe { libc::kill(pid, libc::SIGUSR1) };
    }
    Rebooted::HardReset
}

/// Reboot VMs selected by `--all`, a pid or project directory, or the current directory by
/// default. Returns the summary and whether every selected VM was rebooted.
pub fn reboot_cmd(target: Option<Selector>, all: bool, force: bool) -> Result<(String, bool)> {
    let selected = match select_vms(target, all)? {
        Selection::Matched(v) => v,
        Selection::Empty(out, ok) => return Ok((out, ok)),
    };
    let mut out = String::new();
    let mut ok = true;
    for e in &selected {
        match reboot_one(e, force) {
            Rebooted::Agent => out.push_str(&format!("rebooting {} (pid {})\n", e.label, e.pid)),
            Rebooted::HardReset => {
                out.push_str(&format!("hard-resetting {} (pid {})\n", e.label, e.pid));
            }
            Rebooted::NotRunning => {
                out.push_str(&format!("{} (pid {}) is not running\n", e.label, e.pid));
                ok = false;
            }
        }
    }
    Ok((out, ok))
}

/// What `vk pause` or `vk resume` asks of each VM's control socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseRequest {
    Pause,
    Resume,
}

impl PauseRequest {
    fn request(self) -> &'static str {
        match self {
            PauseRequest::Pause => "pause",
            PauseRequest::Resume => "resume",
        }
    }

    fn done(self) -> &'static str {
        match self {
            PauseRequest::Pause => "paused",
            PauseRequest::Resume => "resumed",
        }
    }
}

/// Pause or resume VMs through their control sockets. Select by `--all`, pid or project
/// directory; default to the current directory. `--all` skips VMs without a control socket.
/// Return the summary and whether every VM acted on succeeded.
pub fn pause_cmd(target: Option<Selector>, all: bool, req: PauseRequest) -> Result<(String, bool)> {
    let selected = match select_vms(target, all)? {
        Selection::Matched(v) => v,
        Selection::Empty(out, ok) => return Ok((out, ok)),
    };
    let mut out = String::new();
    let mut ok = true;
    for e in selected.iter().filter(|e| !all || e.control.is_some()) {
        let (line, done) = pause_line(e, req);
        out.push_str(&line);
        ok &= done;
    }
    if out.is_empty() {
        out.push_str("no running vk VM can be paused (only UEFI guests can)\n");
    }
    Ok((out, ok))
}

/// Send `req` to the VM in `entry`, as [`pause_cmd`] does for each VM.
/// Return the report line and whether the request succeeded.
fn pause_line(entry: &VmEntry, req: PauseRequest) -> (String, bool) {
    let vm = format!("{} (pid {})", entry.label, entry.pid);
    if !alive(entry) {
        return (format!("{vm} is not running\n"), false);
    }
    let Some(socket) = &entry.control else {
        return (
            format!("{vm} has no control socket (only UEFI guests can be paused)\n"),
            false,
        );
    };
    match crate::vmmctl::request(socket, req.request()) {
        Ok(()) => (format!("{} {vm}\n", req.done()), true),
        Err(e) => (format!("{vm}: {e:#}\n"), false),
    }
}

/// Snapshot the UEFI VM selected by a pid or project directory (the current directory by
/// default) into the new bundle `out`, ending the VM ([`crate::snapshot`]).
pub fn snapshot_cmd(target: Option<Selector>, out: &Path) -> Result<String> {
    let entry = match select_vms(target, false)? {
        Selection::Matched(mut v) if v.len() == 1 => v.remove(0),
        Selection::Matched(_) => bail!("more than one VM matches; name one by its pid"),
        Selection::Empty(out, _) => bail!("{}", out.trim()),
    };
    let control = entry
        .control
        .as_ref()
        .with_context(|| format!("{} (pid {}) cannot be snapshotted", entry.label, entry.pid))?;
    let machine = |_: &Path| {
        Ok(crate::snapshot::Machine {
            cpus: entry.cpus,
            mem: entry.mem.clone(),
            addr: entry.guest_ip,
        })
    };
    let if_paused = format!("`vk resume {}` runs it again", entry.pid);
    crate::snapshot::snapshot_vm(control, out, machine, || !alive(&entry), &if_paused)?;
    Ok(format!(
        "snapshotted {} (pid {}) into {}\n",
        entry.label,
        entry.pid,
        out.display()
    ))
}

/// Bind a control socket that answers the first request line with `frames`, in order.
/// `None` closes the connection without answering.
#[cfg(test)]
pub(crate) fn serve_frames(
    tag: &str,
    frames: Option<Vec<Frame>>,
) -> (PathBuf, std::thread::JoinHandle<()>) {
    serve_connections(tag, vec![frames])
}

/// [`serve_frames`] for several connections: the `n`th accepted is answered from `conns[n]`.
#[cfg(test)]
pub(crate) fn serve_connections(
    tag: &str,
    conns: Vec<Option<Vec<Frame>>>,
) -> (PathBuf, std::thread::JoinHandle<()>) {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    let sock = std::env::temp_dir().join(format!(
        "vk-vms-ctl-{tag}-{}-{:?}.sock",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::remove_file(&sock).ok();
    let listener = UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        for frames in conns {
            let (stream, _) = listener.accept().unwrap();
            let Some(frames) = frames else { continue };
            let mut rd = BufReader::new(stream.try_clone().unwrap());
            let mut req = String::new();
            rd.read_line(&mut req).unwrap();
            let mut w = stream;
            for frame in frames {
                let mut line = serde_json::to_string(&frame).unwrap();
                line.push('\n');
                w.write_all(line.as_bytes()).unwrap();
            }
        }
    });
    (sock, server)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::publish::Liveness;

    fn tmpdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = crate::testtmp::root().join(format!(
            "vms-{}-{}",
            tag,
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    pub(crate) fn entry(state_dir: PathBuf, project: Option<PathBuf>) -> VmEntry {
        VmEntry {
            state_dir,
            project_dir: project,
            pid: std::process::id(),
            label: "devcontainer".into(),
            exec_addr: "vsock-auto:///tmp/x/vsock.sock:4444".into(),
            ssh_addr: None,
            atop_log: None,
            created_secs: unix_now(),
            pid_start_ticks: None,
            vmm: None,
            vmm_pid: None,
            cpus: None,
            mem: None,
            nested: None,
            guest_ip: None,
            stale_recipe: None,
            services: Vec::new(),
            guest_agent: None,
            control: None,
        }
    }

    fn unit(name: &str, state: &str, ip: &str) -> UnitStatus {
        UnitStatus {
            name: name.into(),
            state: state.into(),
            ip: ip.into(),
        }
    }

    /// An `app` VM declaring the `db` and `redis` compose services.
    fn compose_entry() -> VmEntry {
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
        e
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
    fn a_service_image_correction_lands_on_the_recorded_entry() {
        // The entry is filed with the address provisioning predicted; the manager corrects it
        // to the tier entry an on-demand build actually settled on, so `--stale` judges the
        // image that booted. Everything with nothing to correct stays a silent no-op.
        let reg = tmpdir("reg-note");
        // Filed under the canonicalized dir, as `run::registry_key` files it in production.
        let state = canonical(&tmpdir("state-note"));
        let mut e = entry(state.clone(), None);
        e.services = vec![
            ServiceEntry {
                name: "db".into(),
                exec_addr: "vsock-auto:///tmp/db/vsock.sock:4444".into(),
                stale_recipe: Some(StaleRecipe {
                    dockerfiles: vec![PathBuf::from("/ctx/Dockerfile")],
                    contexts: vec![PathBuf::from("/ctx")],
                    build_contexts: Vec::new(),
                    build_args: Vec::new(),
                    target: None,
                    root_ext4: PathBuf::from("/tier/predicted/runner.ext4"),
                }),
            },
            ServiceEntry {
                name: "cache".into(),
                exec_addr: "vsock-auto:///tmp/cache/vsock.sock:4444".into(),
                stale_recipe: None, // an `image:` service — nothing is built, nothing to fix
            },
        ];
        record_in(&reg, &e).unwrap();
        let svc = |name: &str| {
            let all = load_all_in(&reg);
            assert_eq!(all.len(), 1, "the correction must not file a second entry");
            all[0]
                .services
                .iter()
                .find(|s| s.name == name)
                .expect("service still recorded")
                .clone()
        };

        let built = Path::new("/tier/built/runner.ext4");
        note_service_image_in(&reg, &state, "db", built).unwrap();
        assert_eq!(svc("db").stale_recipe.unwrap().root_ext4, built);

        // An `image:` service, an unknown name, and a run with no entry filed (an unpinned
        // run records none): each a no-op that neither errors nor creates anything.
        note_service_image_in(&reg, &state, "cache", built).unwrap();
        note_service_image_in(&reg, &state, "absent", built).unwrap();
        note_service_image_in(&reg, &tmpdir("state-unpinned"), "db", built).unwrap();
        assert!(svc("cache").stale_recipe.is_none());
        assert_eq!(svc("db").stale_recipe.unwrap().root_ext4, built);

        // The prediction that held — the common case — rewrites nothing at all. Compared by
        // inode, not bytes: `record_in` republishes by rename, and every field round-trips
        // byte-identically, so equal contents would not tell a no-op from a rewrite.
        use std::os::unix::fs::MetadataExt as _;
        let filed = reg.join(format!("{}.json", slug(&state)));
        let before = std::fs::metadata(&filed).unwrap().ino();
        note_service_image_in(&reg, &state, "db", built).unwrap();
        assert_eq!(
            before,
            std::fs::metadata(&filed).unwrap().ino(),
            "a correction to the filed value must not republish the entry"
        );

        // The entry is keyed by the canonicalized run dir, so a caller holding a symlink to it
        // still corrects the right file: the one way this feature could silently do nothing.
        let link = std::env::temp_dir().join(format!("vk-vms-link-{}", std::process::id()));
        std::fs::remove_file(&link).ok();
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let relinked = Path::new("/tier/relinked/runner.ext4");
        note_service_image_in(&reg, &link, "db", relinked).unwrap();
        assert_eq!(svc("db").stale_recipe.unwrap().root_ext4, relinked);
        std::fs::remove_file(&link).ok();

        // An entry that does not parse is reported, not skipped like `load_all_in` does and not
        // a panic: the correction is best-effort, but a corrupt entry is worth saying out loud.
        std::fs::write(reg.join(format!("{}.json", slug(&state))), b"{ not json").unwrap();
        assert!(note_service_image_in(&reg, &state, "db", built).is_err());
        std::fs::remove_dir_all(&reg).ok();
    }

    #[test]
    fn concurrent_corrections_keep_the_entry_readable() {
        // Two services brought up on demand at once arrive on their own threads, and every
        // version of an entry is staged through one path keyed by the run — so unserialized
        // writers interleave into it and publish something `load_all_in` then skips, taking
        // the VM out of `vk list`. Both corrections must land, on one parseable entry.
        let reg = tmpdir("reg-concurrent");
        let state = canonical(&tmpdir("state-concurrent"));
        let recipe = |ext4: &str| {
            Some(StaleRecipe {
                dockerfiles: vec![PathBuf::from("/ctx/Dockerfile")],
                contexts: vec![PathBuf::from("/ctx")],
                build_contexts: Vec::new(),
                build_args: Vec::new(),
                target: None,
                root_ext4: PathBuf::from(ext4),
            })
        };
        let names: Vec<String> = (0..8).map(|i| format!("svc{i}")).collect();
        let mut e = entry(state.clone(), None);
        e.services = names
            .iter()
            .map(|name| ServiceEntry {
                name: name.clone(),
                exec_addr: format!("vsock-auto:///tmp/{name}/vsock.sock:4444"),
                stale_recipe: recipe("/tier/predicted/runner.ext4"),
            })
            .collect();
        record_in(&reg, &e).unwrap();

        std::thread::scope(|sc| {
            for name in &names {
                let (reg, state) = (reg.clone(), state.clone());
                sc.spawn(move || {
                    let built = PathBuf::from(format!("/tier/built-{name}/runner.ext4"));
                    note_service_image_in(&reg, &state, name, &built).unwrap();
                });
            }
        });

        let all = load_all_in(&reg);
        assert_eq!(
            all.len(),
            1,
            "the entry must still parse, and stay the only one"
        );
        for name in &names {
            let svc = all[0].services.iter().find(|s| &s.name == name).unwrap();
            assert_eq!(
                svc.stale_recipe.as_ref().unwrap().root_ext4,
                PathBuf::from(format!("/tier/built-{name}/runner.ext4")),
                "{name}'s correction was lost to a concurrent writer"
            );
        }
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
        assert!(matches_dir(&e, Path::new("/home/vince/repo"), false));
        assert!(!matches_dir(&e, Path::new("/home/vince"), false));
        assert!(matches_dir(&e, Path::new("/home/vince"), true));
        assert!(matches_dir(&e, Path::new("/state/vm1"), false));
        // an unrelated dir, and a *descendant* of the project, do not
        assert!(!matches_dir(&e, Path::new("/home/other"), true));
        assert!(!matches_dir(&e, Path::new("/home/vince/repo/sub"), true));
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
        assert!(running_in(&reg).is_empty());
        assert_eq!(load_all_in(&reg).len(), 0);
        std::fs::remove_dir_all(&reg).ok();
    }

    #[test]
    fn empty_stop_is_success_only_without_an_explicit_target() {
        // `vk stop` / `vk stop --all` with nothing running: success (nothing to do).
        assert!(empty_selection_ok(false));
        // `vk stop PID|DIR` naming a target that isn't running: not-found (exit 1).
        assert!(!empty_selection_ok(true));
    }

    fn parse(arg: &str) -> Ref {
        Ref::parse(OsStr::new(arg)).unwrap()
    }

    fn name(vm: &str, service: Option<&str>) -> Ref {
        Ref::Name {
            vm: vm.into(),
            service: service.map(Into::into),
        }
    }

    #[test]
    fn a_ref_reads_digits_as_a_pid_paths_as_paths_and_words_as_names() {
        assert_eq!(parse("2144802"), Ref::Pid(2144802, None));
        assert_eq!(parse("007"), Ref::Pid(7, None));
        // A service of a VM that has no name, as `vk list` prints it.
        assert_eq!(parse("4242/db"), Ref::Pid(4242, Some("db".into())));
        assert_eq!(parse("4242/"), Ref::Pid(4242, None));
        assert_eq!(parse("42a/db"), name("42a", Some("db")));
        assert_eq!(
            parse("/home/vince/repo"),
            Ref::Path("/home/vince/repo".into())
        );
        assert_eq!(parse("./123"), Ref::Path("./123".into()));
        assert_eq!(parse("../x"), Ref::Path("../x".into()));
        assert_eq!(parse("."), Ref::Path(".".into()));
        assert_eq!(parse(".."), Ref::Path("..".into()));
        assert_eq!(parse("app"), name("app", None));
        assert_eq!(parse("app/db"), name("app", Some("db")));
        assert_eq!(parse("app/db/"), name("app", Some("db")));
        assert_eq!(parse("app/"), name("app", None));
        // A signed number and a value past u32 are words, not pids.
        assert_eq!(parse("+5"), name("+5", None));
        assert_eq!(parse("99999999999"), name("99999999999", None));
        // A non-UTF-8 argument can only be a directory.
        let raw = OsStr::from_bytes(b"\xffdir");
        assert_eq!(Ref::parse(raw).unwrap(), Ref::Path(PathBuf::from(raw)));
        // An empty argument names nothing; the advice names no flag `vk list` lacks.
        let empty = Ref::parse(OsStr::new("")).unwrap_err().to_string();
        assert!(!empty.contains("--all"), "{empty}");
    }

    #[test]
    fn a_tilde_is_the_home_directory() {
        let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else {
            return;
        };
        assert_eq!(parse("~"), Ref::Path(PathBuf::from(&home)));
        assert_eq!(parse("~/x/y"), Ref::Path(PathBuf::from(&home).join("x/y")));
        assert_eq!(parse("~other"), Ref::Path("~other".into()));
        // Repeated separators stay under `$HOME`, never at the root.
        assert_eq!(
            parse("~//work"),
            Ref::Path(PathBuf::from(&home).join("work"))
        );
        assert_eq!(parse("~///"), Ref::Path(PathBuf::from(&home)));
    }

    #[test]
    fn several_matches_are_refused_naming_each_as_a_ref() {
        let a = entry(PathBuf::from("/state/vk-test-a"), None);
        let mut b = entry(PathBuf::from("/state/vk-test-b"), None);
        b.pid = a.pid.wrapping_add(1);
        assert!(single(vec![]).unwrap().is_none());
        assert_eq!(single(vec![a.clone()]).unwrap().unwrap().pid, a.pid);
        let err = single(vec![a.clone(), b.clone()]).unwrap_err().to_string();
        assert!(err.starts_with("2 running vk VMs match: "), "{err}");
        assert!(err.contains(&format!("{}, {} —", a.pid, b.pid)), "{err}");
        assert!(!err.contains("pid "), "{err}");
    }

    #[test]
    fn a_service_is_one_name() {
        for ok in ["db", "win-2", "a_b.c"] {
            assert!(is_service_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", ".x", "../x", "a/b", "a\\b"] {
            assert!(!is_service_name(bad), "{bad}");
        }
        // `PID/SERVICE` and `--service` are checked alike, before any path is built.
        assert!(Selector::from_ref(Ref::Pid(1, Some("../x".into())), false).is_err());
        assert!(resolve_target(Some(OsStr::new("1/../x")), None).is_err());
        assert!(resolve_target(None, Some("a/b")).is_err());
        let (sel, svc) = resolve_target(Some(OsStr::new("1/db")), None).unwrap();
        assert_eq!((sel, svc.as_deref()), (Some(Selector::Pid(1)), Some("db")));
    }

    #[test]
    fn recursive_with_no_ref_is_the_current_directory_and_below() {
        let here = Selector::Here { below: true };
        assert_eq!(selector_of(None, true).unwrap(), Some(here));
        assert_eq!(selector_of(None, false).unwrap(), None);
        assert_eq!(
            selector_of(Some(OsStr::new("/x")), true).unwrap(),
            Some(Selector::Dir {
                dir: "/x".into(),
                below: true
            })
        );
    }

    #[test]
    fn a_selector_matches_by_pid_by_exact_directory_below_on_request_and_by_name() {
        let e = entry(
            PathBuf::from("/state/vm1"),
            Some(PathBuf::from("/home/vince/repo")),
        );
        let dir = |d: &str, below| Selector::Dir {
            dir: d.into(),
            below,
        };
        assert!(Selector::Pid(e.pid).matches(&e));
        assert!(!Selector::Pid(e.pid.wrapping_add(1)).matches(&e));
        assert!(dir("/home/vince/repo", false).matches(&e));
        assert!(dir("/state/vm1", false).matches(&e));
        assert!(!dir("/home/vince", false).matches(&e));
        assert!(dir("/home/vince", true).matches(&e));
        assert!(!dir("/home/other", true).matches(&e));
        let named = |d: &str| Selector::Named {
            name: "x".into(),
            dir: d.into(),
        };
        assert!(named("/state/vm1").matches(&e));
        assert!(!named("/home/vince/repo").matches(&e));
        // A pid selector never falls back to the directory that spells it.
        let digits = entry(PathBuf::from("/state/vm2"), Some(PathBuf::from("/123")));
        assert!(!Selector::Pid(123).matches(&digits));
        assert!(dir("/123", false).matches(&digits));
        // Each says what it looked for when it finds nothing.
        assert_eq!(
            Selector::Pid(4242).not_found(),
            "no running vk VM with pid 4242\n"
        );
        assert_eq!(
            dir("/home/other", true).not_found(),
            "no running vk VM under /home/other\n"
        );
        assert_eq!(
            dir("/home/other", false).not_found(),
            "no running vk VM for /home/other\n"
        );
        assert_eq!(named("/s").not_found(), "x is not running (`vk start x`)\n");
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
    fn all_fresh_needs_the_vm_and_every_service_known_current() {
        let recipe = |name: &str| StaleRecipe {
            dockerfiles: Vec::new(),
            contexts: Vec::new(),
            build_contexts: Vec::new(),
            build_args: Vec::new(),
            target: None,
            root_ext4: PathBuf::from(name),
        };
        // Each recipe's verdict is named by its image path.
        let verdict = |r: &StaleRecipe| match r.root_ext4.to_str() {
            Some("fresh") => Freshness::Fresh,
            Some("stale") => Freshness::Stale,
            _ => Freshness::Unknown,
        };
        let service = |name: &str, image: Option<&str>| ServiceEntry {
            name: name.into(),
            exec_addr: "unused".into(),
            stale_recipe: image.map(recipe),
        };
        let mut e = entry(PathBuf::from("/state/img"), None);
        // An image boot has nothing known current.
        assert!(!all_fresh_by(&e, verdict));
        e.stale_recipe = Some(recipe("fresh"));
        assert!(all_fresh_by(&e, verdict));
        e.services.push(service("web", Some("fresh")));
        assert!(all_fresh_by(&e, verdict));
        // A service not known current counts against it: stale, undeterminable, or booted
        // from a prebuilt image, which has nothing to judge.
        for image in [Some("stale"), Some("unknown"), None] {
            e.services.push(service("worker", image));
            assert!(!all_fresh_by(&e, verdict), "{image:?}");
            e.services.pop();
        }
        // As does the VM's own image not known current, whatever its services say.
        e.stale_recipe = Some(recipe("unknown"));
        assert!(!all_fresh_by(&e, verdict));
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
    fn project_cell_folds_home_to_tilde_unless_wide() {
        let home = Path::new("/home/me");
        let dir = Path::new("/home/me/app");
        assert_eq!(project_cell(Some(dir), Some(home), false), "~/app");
        assert_eq!(project_cell(Some(dir), Some(home), true), "/home/me/app");
        assert_eq!(project_cell(Some(home), Some(home), false), "~");
        // Only a whole leading component folds: /home/meow is not under /home/me.
        assert_eq!(
            project_cell(Some(Path::new("/home/meow/x")), Some(home), false),
            "/home/meow/x"
        );
        assert_eq!(project_cell(Some(dir), None, false), "/home/me/app");
        assert_eq!(
            project_cell(Some(dir), Some(Path::new("")), false),
            "/home/me/app"
        );
        // A relative or root home folds nothing: `~/home/me/app` is longer than the path
        // it replaces, and `/` itself is not the home directory in any useful sense.
        assert_eq!(
            project_cell(Some(dir), Some(Path::new("home")), false),
            "/home/me/app"
        );
        assert_eq!(
            project_cell(Some(dir), Some(Path::new("/")), false),
            "/home/me/app"
        );
        assert_eq!(
            project_cell(Some(Path::new("/")), Some(Path::new("/")), false),
            "/"
        );
        assert_eq!(project_cell(None, Some(home), false), "-");
    }

    #[test]
    fn tilde_folds_a_symlinked_home_once_both_sides_are_canonical() {
        let real = canonical(&tmpdir("tilde-home"));
        let link = real.with_extension("link");
        let _ = std::fs::remove_file(&link); // best-effort: a leftover from an earlier run
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let dir = real.join("app");
        // `$HOME` as the environment spells it does not match the canonical project dir.
        assert_eq!(tilde(&dir, Some(&link)), dir.display().to_string());
        // Canonicalized the way `list_report` does, it folds.
        assert_eq!(tilde(&dir, Some(&canonical(&link))), "~/app");
        // Best-effort cleanup: a leaked temp dir fails no assertion.
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&real);
    }

    #[test]
    fn detail_lays_out_every_recorded_fact_with_services_and_ports() {
        let mut e = compose_entry();
        e.pid = 41877;
        e.created_secs = 1_756_972_800; // 2025-09-04 08:00:00 UTC
        e.ssh_addr = Some("127.0.0.1:2222".into());
        e.atop_log = Some(PathBuf::from("/state/app/atop.log"));
        e.vmm = Some("libkrun".into());
        e.vmm_pid = Some(4242);
        e.cpus = Some(4);
        e.mem = Some("8G".into());
        e.nested = Some(true);
        e.guest_ip = Some("10.0.0.2".parse().unwrap());
        let units = [
            unit("db", "running", "10.0.0.3/24"),
            unit("redis", "stopped", "10.0.0.4/24"),
        ];
        let published = [(
            publisher(
                "pg",
                "tcp://127.0.0.1:5432",
                "tcp://127.0.0.1:5432",
                Some("db"),
            ),
            Liveness::Held,
        )];
        // Only uptime depends on the clock. NAME identifies the VM and IMAGE identifies what it boots.
        let expected = format!(
            "\
NAME          shop
IMAGE         app
PID           41877
UPTIME        {up} (since 2025/09/04 08:00:00 UTC)
PROJECT       /project
STATE DIR     /state/app
EXEC ADDRESS  vsock-auto:///tmp/x/vsock.sock:4444
SSH           127.0.0.1:2222
GUEST IP      10.0.0.2
VMM           libkrun (pid 4242)
CPUS          4
MEM           8G
MEM USED      1.6 GiB
NESTED        yes
ATOP LOG      /state/app/atop.log
IMAGE STALE   yes
SERVICES      db     running  10.0.0.3  vsock-auto:///state/app/svc-db/vsock.sock:4444
              redis  stopped  10.0.0.4  vsock-auto:///state/app/svc-redis/vsock.sock:4444
PUBLISHED     pg  127.0.0.1:5432->127.0.0.1:5432@db  pid 4242
",
            up = uptime(e.created_secs)
        );
        assert_eq!(
            detail(
                &e,
                &[("NAME", "shop".into())],
                Some(&units),
                &published,
                Freshness::Stale,
                true,
                Some(1_717_986_918)
            ),
            expected
        );
    }

    #[test]
    fn detail_dashes_every_fact_a_plain_run_did_not_record() {
        let mut plain = entry(PathBuf::from("/state/x"), None);
        plain.pid = 7;
        plain.created_secs = 1_756_972_800;
        let expected = format!(
            "\
NAME          7
IMAGE         devcontainer
PID           7
UPTIME        {up} (since 2025/09/04 08:00:00 UTC)
PROJECT       -
STATE DIR     /state/x
EXEC ADDRESS  vsock-auto:///tmp/x/vsock.sock:4444
SSH           -
GUEST IP      -
VMM           -
CPUS          -
MEM           -
MEM USED      -
NESTED        -
ATOP LOG      -
SERVICES      -
PUBLISHED     -
",
            up = uptime(plain.created_secs)
        );
        // Without --stale, omit IMAGE STALE.
        assert_eq!(
            detail(
                &plain,
                &[("NAME", "7".into())],
                None,
                &[],
                Freshness::Unknown,
                false,
                None
            ),
            expected
        );
    }

    #[test]
    fn details_carry_each_rows_status_and_keep_a_service_listed_alone() {
        use crate::vmlist::{Filter, Kind, Known, Live, STOPPED};
        let e = compose_entry();
        let live = [Live {
            entry: &e,
            name: Some("shop".into()),
            kind: Kind::Run,
            environment: None,
            units: Some(vec![unit("db", "running", "10.0.0.3/24")]),
            published: Vec::new(),
            mem_used: None,
            fresh: None,
            transient: Some("stopping"),
            attention: Some("overdue".into()),
            stale_record: false,
        }];
        let known = [Known {
            name: "old".into(),
            dir: PathBuf::from("/state/old"),
            kind: Kind::Run,
            status: STOPPED,
            attention: None,
            stale_record: true,
            last: None,
            project: None,
            environment: None,
        }];
        let rows = crate::vmlist::rows_with(&live, &known, 100, |_| false);
        let text = details(&rows, &rows, &live, false);
        // The primary includes its service. Detail records spell out both table marks.
        assert_eq!(text.matches("NAME  ").count(), 2, "{text}");
        assert!(
            text.starts_with(
                "NAME          shop\nKIND          run\nSTATUS        stopping\n\
                 ATTENTION     overdue\nSTALE RECORD  no\nIMAGE         app\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "\n\nNAME          old\nKIND          run\nSTATUS        stopped\n\
                 ATTENTION     -\nSTALE RECORD  yes\nIMAGE         -\n"
            ),
            "{text}"
        );
        // Selecting only the service gives it a record.
        let filter = Filter {
            service: Some("db".into()),
            ..Filter::default()
        };
        let only_db: Vec<_> = rows.iter().filter(|r| filter.keeps(r)).cloned().collect();
        let text = details(&only_db, &rows, &live, false);
        assert!(
            text.starts_with(
                "NAME          shop/db\nKIND          service\nSTATUS        running\n"
            ),
            "{text}"
        );
        assert!(text.contains("\nIP            10.0.0.3\n"), "{text}");
    }

    /// Two stopped compose runs both listed as `shop`, in different state directories:
    /// `/a/shop` once started `db`, `/b/shop` once started `cache`.
    fn same_named_stopped_runs() -> Vec<crate::vmlist::Row> {
        use crate::vmlist::{Kind, Known, STOPPED};
        let known = [("a", "db"), ("b", "cache")].map(|(at, svc)| {
            let dir = PathBuf::from(format!("/{at}/shop"));
            let mut last = entry(dir.clone(), None);
            last.services = vec![ServiceEntry {
                name: svc.into(),
                exec_addr: format!("vsock-auto://{}/svc-{svc}/vsock.sock:4444", dir.display()),
                stale_recipe: None,
            }];
            Known {
                name: "shop".into(),
                dir,
                kind: Kind::Run,
                status: STOPPED,
                attention: None,
                stale_record: false,
                last: Some(last),
                project: Some(PathBuf::from(format!("/project-{at}"))),
                environment: None,
            }
        });
        crate::vmlist::rows_with(&[], &known, 100, |_| true)
    }

    #[test]
    fn a_stopped_primarys_record_lists_its_own_services_whatever_the_filter() {
        use crate::vmlist::{Filter, Kind};
        let all = same_named_stopped_runs();
        let text = details(&all, &all, &[], false);
        let records: Vec<&str> = text.split("\n\n").collect();
        assert_eq!(records.len(), 2, "{text}");
        assert!(records[0].contains("\nSTATE DIR     /a/shop\n"), "{text}");
        assert!(
            records[0].ends_with("\nSERVICES      db  stopped"),
            "{text}"
        );
        assert!(records[1].contains("\nSTATE DIR     /b/shop\n"), "{text}");
        assert!(
            records[1].ends_with("\nSERVICES      cache  stopped\n"),
            "{text}"
        );
        // With --kind run, both primary records still list their services.
        let filter = Filter {
            kind: Some(Kind::Run),
            ..Filter::default()
        };
        let runs: Vec<_> = all.iter().filter(|r| filter.keeps(r)).cloned().collect();
        assert_eq!(runs.len(), 2);
        assert_eq!(details(&runs, &all, &[], false), text);
        // A service whose primary is not listed keeps its record, even beside another
        // primary of the same name.
        let mixed: Vec<_> = (all.iter())
            .filter(|r| r.name == "shop/db" || r.state_dir == Path::new("/b/shop"))
            .cloned()
            .collect();
        let text = details(&mixed, &all, &[], false);
        assert!(text.starts_with("NAME          shop/db\n"), "{text}");
        assert!(text.contains("\n\nNAME          shop\n"), "{text}");
    }

    #[test]
    fn stale_puts_an_unknown_image_stale_line_on_unchecked_records() {
        let all = same_named_stopped_runs();
        let pick = |name: &str| -> Vec<_> {
            let row = all.iter().find(|r| r.name == name).cloned();
            row.into_iter().collect()
        };
        for rows in [pick("shop"), pick("shop/db")] {
            let text = details(&rows, &all, &[], true);
            assert!(text.contains("\nIMAGE STALE   -\n"), "{text}");
            let text = details(&rows, &all, &[], false);
            assert!(!text.contains("IMAGE STALE"), "{text}");
        }
    }

    #[test]
    fn detail_reads_the_other_side_of_every_recorded_fact() {
        let mut e = compose_entry();
        e.nested = Some(false);
        // A VMM the run named but whose pid it did not record prints bare.
        e.vmm = Some("libkrun".into());
        let text = detail(
            &e,
            &[("NAME", "app".into())],
            None,
            &[],
            Freshness::Fresh,
            true,
            None,
        );
        assert!(text.contains("\nVMM           libkrun\n"), "{text}");
        assert!(text.contains("\nNESTED        no\n"), "{text}");
        assert!(text.contains("\nIMAGE STALE   no\n"), "{text}");
    }

    #[test]
    fn detail_dashes_a_service_the_vm_did_not_report_but_keeps_its_exec_address() {
        // The VM answered and knows of neither service, so only the recorded facts remain.
        let text = detail(
            &compose_entry(),
            &[("NAME", "app".into())],
            Some(&[]),
            &[],
            Freshness::Unknown,
            true,
            None,
        );
        assert!(
            text.contains(
                "SERVICES      db     -  -  vsock-auto:///state/app/svc-db/vsock.sock:4444\n"
            ),
            "{text}"
        );
        // Asked for but not determinable prints `-`, in the cell a fresh or stale answer
        // would fill.
        assert!(text.contains("\nIMAGE STALE   -\n"), "{text}");
    }

    #[test]
    fn detail_aligns_several_publishers_and_marks_the_pid_it_cannot_vouch_for() {
        let published = [
            (
                publisher(
                    "pg",
                    "tcp://127.0.0.1:5432",
                    "tcp://127.0.0.1:5432",
                    Some("db"),
                ),
                Liveness::Held,
            ),
            (
                publisher("web", "tcp://127.0.0.1:8443", "tcp://runner:443", None),
                Liveness::Unknown,
            ),
        ];
        let text = detail(
            &compose_entry(),
            &[("NAME", "app".into())],
            None,
            &published,
            Freshness::Unknown,
            false,
            None,
        );
        let lines: Vec<&str> = text.lines().collect();
        let published_at = lines
            .iter()
            .position(|l| l.starts_with("PUBLISHED"))
            .unwrap();
        assert_eq!(
            lines[published_at],
            "PUBLISHED     pg   127.0.0.1:5432->127.0.0.1:5432@db  pid 4242"
        );
        // The name column is padded to `web`, and the marker sits on the pid it discredits
        // rather than on the address, which is recorded and trustworthy either way.
        assert_eq!(
            lines[published_at + 1],
            "              web  127.0.0.1:8443->runner:443         pid 4242 (unconfirmed)"
        );
    }

    #[test]
    fn aligned_measures_width_in_characters_not_bytes() {
        // "caf\u{e9}" is four characters in five UTF-8 bytes; measured in bytes the first
        // column would reserve a blank it does not need and push the second one over.
        let accented = aligned(&[["caf\u{e9}".to_string(), "x".to_string()]]);
        let ascii = aligned(&[["cafe".to_string(), "x".to_string()]]);
        assert_eq!(accented[0].chars().count(), ascii[0].chars().count());
        assert_eq!(accented[0], "caf\u{e9}  x");
    }

    /// Synthetic records for field projection, including nested arrays and missing values.
    fn field_views() -> Vec<serde_json::Value> {
        let svc = |name: &str, state: Option<&str>, ip: Option<&str>| {
            serde_json::json!({
                "exec_addr": format!("vsock-auto:///state/app/svc-{name}/vsock.sock:4444"),
                "ip": ip,
                "name": name,
                "state": state,
            })
        };
        vec![
            serde_json::json!({
                "guest_ip": null, "label": "app", "nested": true, "pid": 4242,
                "services": [svc("db", Some("running"), Some("10.0.0.2")), svc("redis", None, None)],
            }),
            serde_json::json!({
                "guest_ip": null, "label": "plain", "nested": null, "pid": 7, "services": [],
            }),
        ]
    }

    fn fields(views: &[serde_json::Value], names: &[&str], json: bool) -> Result<String> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        fields_report(views, &names, json)
    }

    #[test]
    fn field_text_prints_bare_like_jq_r() {
        let views = field_views();
        // One line per VM; strings bare, numbers, bools and nulls as JSON, tab-separated in
        // the order asked.
        assert_eq!(fields(&views, &["label"], false).unwrap(), "app\nplain\n");
        assert_eq!(
            fields(
                &views,
                &["pid", "nested", "guest_ip", "services.0.ip"],
                false
            )
            .unwrap(),
            "4242\ttrue\tnull\t10.0.0.2\n7\tnull\tnull\tnull\n"
        );
        // A non-scalar prints as compact JSON on the one line.
        assert_eq!(
            fields(&views, &["services"], false).unwrap(),
            "[{\"exec_addr\":\"vsock-auto:///state/app/svc-db/vsock.sock:4444\",\"ip\":\"10.0.0.2\",\
             \"name\":\"db\",\"state\":\"running\"},{\"exec_addr\":\"vsock-auto:///state/app/svc-redis/\
             vsock.sock:4444\",\"ip\":null,\"name\":\"redis\",\"state\":null}]\n[]\n"
        );
        // A branch below a known field that does not exist is null, not an error.
        assert_eq!(
            fields(&views, &["services.1.ip"], false).unwrap(),
            "null\nnull\n"
        );
        // With no rows, field names are never looked up.
        assert_eq!(fields(&[], &["nope"], false).unwrap(), "");
    }

    #[test]
    fn field_json_holds_only_the_fields_asked() {
        let views = field_views();
        assert_eq!(
            fields(&views, &["label", "services.0.state"], true).unwrap(),
            "[\n  {\n    \"label\": \"app\",\n    \"services.0.state\": \"running\"\n  },\n  {\n    \
             \"label\": \"plain\",\n    \"services.0.state\": null\n  }\n]\n"
        );
        assert_eq!(fields(&[], &["nope"], true).unwrap(), "[]\n");
    }

    #[test]
    fn field_errors_name_the_fields_and_reject_malformed_paths() {
        let views = field_views();
        // An unknown field is an error that names the fields there are; `stale` is only there
        // with --stale, so the error says how to get it.
        let err = fields(&views, &["guest-ip"], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no field \"guest-ip\""), "{err}");
        assert!(err.contains(r#"--field "guest-ip""#), "{err}");
        assert!(err.contains("guest_ip, label"), "{err}");
        let err = fields(&views, &["stale"], false).unwrap_err().to_string();
        assert!(err.contains("(pass --stale)"), "{err}");
        let with_stale = [serde_json::json!({"label": "plain", "stale": null})];
        assert_eq!(fields(&with_stale, &["stale"], false).unwrap(), "null\n");

        // Malformed and duplicate paths fail even with no rows.
        let check = |names: &[&str]| {
            let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            check_fields(&names).unwrap_err().to_string()
        };
        assert!(check(&["guest_ip."]).contains("empty path segment"));
        // Several names in one flag, however spelled. Only a dotted first name reached the
        // JSON pointer and printed `null`; the rest erred with a VM running, just less
        // helpfully, and printed nothing without one.
        for several in [
            "pid label",
            "pid,label",
            "pid, label",
            "pid\tlabel",
            "pid\nlabel",
            "services.0.ip pid",
            "pid label.",
        ] {
            let err = check(&[several]);
            assert!(
                err.contains("repeat --field for several"),
                "{several:?}: {err}"
            );
            // Quoted, so a stray space shows and a tab or newline reads as an escape.
            assert!(err.contains(&format!("--field {several:?}")), "{err}");
        }
        assert!(check(&["services.0/ip"]).contains("no such field"));
        assert!(check(&["pid", "label", "pid"]).contains(r#"--field "pid": given twice"#));
        check_fields(&["pid".to_string(), "services.0.ip".to_string()]).unwrap();
    }

    #[test]
    fn bare_ip_strips_the_prefix_length() {
        assert_eq!(bare_ip("10.0.0.2/24"), "10.0.0.2");
        assert_eq!(bare_ip("10.0.0.2"), "10.0.0.2");
    }

    #[test]
    fn query_units_reads_through_progress_to_done() {
        use vk_core::fleetctl::Reply;

        let (sock, server) = serve_frames(
            "progress",
            Some(vec![
                Frame::Progress("building svc-db".into()),
                Frame::Done(Reply::list(vec![
                    unit("db", "running", "10.0.0.2/24"),
                    unit("redis", "stopped", "10.0.0.3/24"),
                ])),
            ]),
        );
        let units = query_units(&sock).unwrap();
        server.join().unwrap();
        std::fs::remove_file(&sock).ok();

        assert_eq!(units.len(), 2);
        assert_eq!(
            (units[0].name.as_str(), units[0].state.as_str()),
            ("db", "running")
        );
        assert_eq!(
            (units[1].name.as_str(), units[1].state.as_str()),
            ("redis", "stopped")
        );
        assert_eq!(units[1].ip, "10.0.0.3/24");
    }

    #[test]
    fn query_units_errors_on_an_error_reply() {
        use vk_core::fleetctl::Reply;

        let (sock, server) =
            serve_frames("err", Some(vec![Frame::Done(Reply::err("manager busy"))]));
        let res = query_units(&sock);
        server.join().unwrap();
        std::fs::remove_file(&sock).ok();

        assert_eq!(
            res.unwrap_err().to_string(),
            "service manager refused: manager busy"
        );
    }

    #[test]
    fn query_units_errors_when_peer_closes_early() {
        let (sock, server) = serve_frames("early", None);
        let res = query_units(&sock);
        server.join().unwrap();
        std::fs::remove_file(&sock).ok();

        assert!(res.is_err());
    }

    fn publisher(
        name: &str,
        listen: &str,
        to: &str,
        service: Option<&str>,
    ) -> crate::publish::Entry {
        crate::publish::Entry {
            name: name.into(),
            listen: listen.into(),
            to: to.into(),
            service: service.map(str::to_string),
            pid: 4242,
            created_secs: 0,
        }
    }

    // An entry written before `atop_log` and the boot-time fields existed still loads:
    // `load_all_in` skips what it cannot parse, so a required field would drop a live VM out
    // of the registry. The view then reports each missing fact as an explicit `null`.
    #[test]
    fn vm_entry_loads_without_optional_fields() {
        let json =
            r#"{"state_dir":"/state/x","pid":1,"label":"x","exec_addr":"a","created_secs":0}"#;
        let e: VmEntry = serde_json::from_str(json).unwrap();
        assert!(e.atop_log.is_none());
        assert_eq!(e.vmm, None);
        assert_eq!(e.vmm_pid, None);
        assert_eq!(e.cpus, None);
        assert_eq!(e.mem, None);
        assert_eq!(e.nested, None);
        assert_eq!(e.guest_ip, None);
        assert_eq!(e.project_dir, None);
        // Paths written as plain strings read back as they always did.
        let json = r#"{"state_dir":"/state/x","project_dir":"/p","pid":1,"label":"x","exec_addr":"a","created_secs":0}"#;
        let e: VmEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.state_dir, PathBuf::from("/state/x"));
        assert_eq!(e.project_dir, Some(PathBuf::from("/p")));
        assert_eq!(serde_json::to_value(&e).unwrap()["project_dir"], "/p");
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

    #[test]
    fn mem_cell_pairs_what_is_held_with_what_was_asked_for() {
        // Both known: the live figure over the boot token, as recorded.
        assert_eq!(mem_cell(Some(1_288_490_189), Some("8G")), "1.2G/8G");
        // Preserve the VMM token's spelling and units, even when the usage units differ.
        assert_eq!(mem_cell(Some(817_889_280), Some("2048m")), "780M/2048m");
        // Either half alone still prints, so a row says which of the two it is missing.
        assert_eq!(mem_cell(None, Some("512M")), "-/512M");
        assert_eq!(mem_cell(Some(1024), None), "1K/-");
        // Neither: one dash, not "-/-", which reads as two known-absent facts.
        assert_eq!(mem_cell(None, None), "-");
    }

    #[test]
    fn compact_bytes_keeps_a_table_cell_narrow_without_lying_at_a_boundary() {
        assert_eq!(compact_bytes(0), "0B");
        assert_eq!(compact_bytes(1023), "1023B");
        assert_eq!(compact_bytes(1024), "1K");
        assert_eq!(compact_bytes(1024 * 1024), "1M");
        assert_eq!(compact_bytes(1024 * 1024 * 1024), "1.0G");
        assert_eq!(compact_bytes(1_717_986_918), "1.6G");
        // Round into the larger unit instead of printing "1024M" or "1024K" by branching
        // on the rounded figure, as `usage::fmt_bytes` does.
        assert_eq!(compact_bytes(1024 * 1024 * 1024 - 1), "1.0G");
        assert_eq!(compact_bytes(1024 * 1024 - 1), "1M");
    }

    #[test]
    fn a_deadline_past_what_the_clock_holds_is_never() {
        assert_eq!(Deadline::in_secs(u64::MAX), Deadline::NEVER);
        assert_eq!(Deadline::NEVER.left(), None);
        assert!(!Deadline::NEVER.passed());
        let second = Duration::from_secs(1);
        assert_eq!(Deadline::NEVER.cap(second), second);
        assert!(Deadline::in_secs(0).passed());
        assert_eq!(Deadline::in_secs(0).cap(second), Duration::ZERO);
        assert!(Deadline::in_secs(60).cap(second) == second);
    }

    /// The registry record of `stand_in`, run on `dir`, as `vk run` writes it: with its start
    /// time.
    fn run_entry(dir: &Path, stand_in: &crate::dev::testutil::StandIn) -> VmEntry {
        let mut e = entry(dir.to_path_buf(), None);
        e.pid = stand_in.id();
        e.pid_start_ticks = crate::usage::proc_starttime(i32::try_from(e.pid).unwrap());
        assert!(e.pid_start_ticks.is_some());
        e
    }

    /// Whether `reg` holds a record of `e`'s run.
    fn recorded(reg: &Path, e: &VmEntry) -> bool {
        load_all_in(reg).iter().any(|r| same_run(r, e))
    }

    /// One run that ignores its stop holds none of the others back, and the deadline bounds
    /// the whole stop: each is signalled before any is waited for.
    #[test]
    fn a_stop_signals_every_run_before_waiting_for_any() {
        use crate::dev::testutil::StandIn;
        let _env = crate::dev::testutil::env_guard();

        let reg = tmpdir("stops-reg");
        let (stuck_dir, quick_dir) = (tmpdir("stops-stuck"), tmpdir("stops-quick"));
        let mut stuck = StandIn::locking(&stuck_dir, true);
        let mut quick = StandIn::locking(&quick_dir, false);
        let entries = vec![run_entry(&stuck_dir, &stuck), run_entry(&quick_dir, &quick)];
        for e in &entries {
            record_in(&reg, e).unwrap();
        }
        let began = Instant::now();
        let stops = Stops::begin_in(
            Some(reg.clone()),
            entries.clone(),
            Vec::new(),
            Deadline::in_secs(2),
            StopHow::Graceful,
            PACE,
        );
        let (out, down) = stops.finish();
        assert!(began.elapsed() < Duration::from_secs(4), "{out}");
        assert!(!down, "{out}");
        assert!(
            out.contains(&format!("(pid {}) did not stop after", stuck.id())),
            "{out}"
        );
        assert!(
            out.contains(&format!("stopped devcontainer (pid {})", quick.id())),
            "{out}"
        );
        assert!(stuck.alive());
        assert!(!quick.alive());
        // Only the record of the run that went is pruned.
        assert!(recorded(&reg, &entries[0]));
        assert!(!recorded(&reg, &entries[1]));
        for d in [reg, stuck_dir, quick_dir] {
            std::fs::remove_dir_all(d).ok();
        }
    }

    /// A stop waits for the run it signalled, not for whatever holds its state dir after: a
    /// run that takes the directory over is neither waited for nor stripped of its record or
    /// its publishers.
    #[test]
    fn a_stop_ends_with_its_run_not_with_a_replacement() {
        use crate::dev::testutil::StandIn;
        let _env = crate::dev::testutil::env_guard();

        let reg = tmpdir("stops-replaced-reg");
        let dir = tmpdir("stops-replaced");
        let mut first = StandIn::locking(&dir, false);
        let gone = run_entry(&dir, &first);
        record_in(&reg, &gone).unwrap();
        // Publishers are stopped once their operation lock is free, by then the replacement's.
        let op = crate::publish::hold_op_lock(&dir);
        let stops = Stops::begin_in(
            Some(reg.clone()),
            vec![gone.clone()],
            Vec::new(),
            Deadline::in_secs(30),
            StopHow::Graceful,
            PACE,
        );
        while first.alive() {
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut second = StandIn::locking(&dir, true);
        let replacement = run_entry(&dir, &second);
        record_in(&reg, &replacement).unwrap();
        // The replacement says it is starting, over the stop's record of the first run: that
        // stays its own.
        let pid = replacement.pid;
        let starting = crate::vmstate::Transient {
            state: crate::vmstate::State::Starting,
            pid,
            pid_start_ticks: replacement.pid_start_ticks,
            since_secs: unix_now(),
            deadline_secs: None,
            by_pid: None,
            by_start_ticks: None,
        };
        let file = dir.join(crate::vmstate::FILE);
        std::fs::write(file, serde_json::to_vec(&starting).unwrap()).unwrap();
        let mut relay = StandIn::spawn();
        let addr = "tcp://127.0.0.1:8601";
        let _relay =
            crate::publish::fake_publisher(&dir, "web", addr, "vsock://80", relay.id(), None);
        drop(op);
        let began = Instant::now();
        let (out, down) = stops.finish();
        assert!(down, "{out}");
        assert!(began.elapsed() < Duration::from_secs(5), "{out}");
        assert!(second.alive());
        assert!(relay.alive(), "the replacement's publisher was stopped");
        assert!(recorded(&reg, &replacement));
        let kept = crate::vmstate::peek(&dir).map(|(t, _)| t.pid);
        assert_eq!(kept, Some(pid), "the replacement's record was cleared");
        drop(second);
        std::fs::remove_dir_all(&reg).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A pid that names another process than the recorded run is never signalled, nor
    /// reported stopped while something else holds the run's state dir, forced or not.
    #[test]
    fn a_pid_that_is_no_longer_its_run_is_never_signalled() {
        use crate::dev::testutil::StandIn;
        let _env = crate::dev::testutil::env_guard();

        let dir = tmpdir("stops-other");
        let _holder = StandIn::locking(&dir, false);
        let mut other = StandIn::spawn();
        let mut e = run_entry(&dir, &other);
        e.pid_start_ticks = e.pid_start_ticks.map(|t| t + 1);
        for how in [StopHow::Graceful, StopHow::Kill] {
            let deadline = Deadline::in_secs(1);
            let stops = Stops::begin_in(None, vec![e.clone()], Vec::new(), deadline, how, PACE);
            let (out, down) = stops.finish();
            assert!(!down, "{out}");
            assert!(out.contains("nothing was signalled"), "{out}");
            assert!(other.alive());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A publisher's operation lock held elsewhere holds back no run's signal, whether a run's
    /// or a stopped one's.
    #[test]
    fn a_contended_publisher_lock_delays_no_signal() {
        use crate::dev::testutil::StandIn;
        let _env = crate::dev::testutil::env_guard();

        let (a_dir, b_dir) = (tmpdir("stops-contended-a"), tmpdir("stops-contended-b"));
        let stale = tmpdir("stops-contended-stale");
        let mut a = StandIn::locking(&a_dir, false);
        let mut b = StandIn::locking(&b_dir, false);
        let entries = vec![run_entry(&a_dir, &a), run_entry(&b_dir, &b)];
        let ops = [&stale, &a_dir].map(|d| crate::publish::hold_op_lock(d));
        let stale_dirs = vec![stale.clone()];
        let stops = std::thread::spawn(move || {
            let deadline = Deadline::in_secs(30);
            Stops::begin_in(None, entries, stale_dirs, deadline, StopHow::Graceful, PACE).finish()
        });
        let began = Instant::now();
        while a.alive() || b.alive() {
            assert!(began.elapsed() < Duration::from_secs(10), "not signalled");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !stops.is_finished(),
            "a's publishers went without their lock"
        );
        drop(ops);
        let (out, down) = stops.join().unwrap();
        assert!(down, "{out}");
        for d in [a_dir, b_dir, stale] {
            std::fs::remove_dir_all(d).ok();
        }
    }

    /// A shell that holds the state-directory lock while running `script`. With
    /// `ignores_term`, the shell and its children inherit an ignored SIGTERM. Its group is
    /// killed on drop or test process death.
    struct FakeRun(crate::testchild::Kept);

    impl FakeRun {
        fn spawn(dir: &Path, script: &str, ignores_term: bool) -> Self {
            use std::os::unix::process::CommandExt;
            let dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
            let mut cmd = std::process::Command::new("sh");
            cmd.args(["-c", script]);
            // SAFETY: only `signal`, `open` and `flock` run between fork and exec, all
            // async-signal-safe; the locked descriptor is left open across the exec.
            unsafe {
                cmd.pre_exec(move || {
                    if ignores_term && libc::signal(libc::SIGTERM, libc::SIG_IGN) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                    let fd = libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
                    if fd < 0 || libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            FakeRun(crate::testchild::Kept::spawn(&mut cmd))
        }

        fn pid(&self) -> i32 {
            i32::try_from(self.0.id()).unwrap()
        }

        /// Its VMM and the other process it started, held, once both are up.
        fn children(&self) -> (Held, Held) {
            let began = Instant::now();
            loop {
                let all = crate::usage::descendants_of(self.pid());
                let vmms = crate::vmm::processes_under(self.pid());
                if let ([vmm], 2) = (vmms.as_slice(), all.len()) {
                    let other = all.iter().find(|p| *p != vmm).unwrap();
                    let hold = |pid: i32| Held::open(pid).unwrap().unwrap();
                    return (hold(*vmm), hold(*other));
                }
                assert!(
                    began.elapsed() < Duration::from_secs(10),
                    "{all:?} {vmms:?}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// Its record, with its start time.
        fn entry(&self, dir: &Path) -> VmEntry {
            let mut e = entry(dir.to_path_buf(), None);
            e.pid = self.0.id();
            e.pid_start_ticks = crate::usage::proc_starttime(self.pid());
            e
        }
    }

    /// The other process a fake run started outlives its stop: it is ended here.
    fn end(other: &Held) {
        assert!(!other.exited(), "a process that is no VMM was killed");
        other.signal(libc::SIGKILL).unwrap();
    }

    /// An immediate kill targets the VMM. The run exits on its own and its other child survives.
    #[test]
    fn a_kill_takes_the_vmms_and_leaves_the_run_to_follow() {
        let _env = crate::dev::testutil::env_guard();
        let dir = tmpdir("stops-kill");
        let var = crate::vmm::BOOT_SPEC_ENV;
        let script = format!("sleep 600 & {var}=x sleep 600 & wait $!");
        let run = FakeRun::spawn(&dir, &script, false);
        let (vmm, other) = run.children();
        let pace = Pace {
            term: Duration::from_millis(300),
            kill_wait: Duration::from_secs(5),
        };
        let began = Instant::now();
        let stops = Stops::begin_in(
            None,
            vec![run.entry(&dir)],
            Vec::new(),
            Deadline::in_secs(30),
            StopHow::Kill,
            pace,
        );
        let (out, down) = stops.finish();
        assert!(down, "{out}");
        assert!(
            began.elapsed() < pace.kill_wait,
            "the run was killed: {out}"
        );
        assert!(vmm.exited());
        end(&other);
        drop(run);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Both runs share each escalation interval, even while a publisher lock is held.
    /// Their other children survive.
    #[test]
    fn a_forced_stop_escalates_on_every_run_together() {
        let _env = crate::dev::testutil::env_guard();
        let var = crate::vmm::BOOT_SPEC_ENV;
        let script = format!("{var}=x sleep 600 & sleep 600 & wait");
        let dirs = [tmpdir("stops-force-a"), tmpdir("stops-force-b")];
        let runs: Vec<FakeRun> = dirs
            .iter()
            .map(|d| FakeRun::spawn(d, &script, true))
            .collect();
        let held: Vec<(Held, Held)> = runs.iter().map(FakeRun::children).collect();
        let entries = runs.iter().zip(&dirs).map(|(r, d)| r.entry(d)).collect();
        let pace = Pace {
            term: Duration::from_millis(500),
            kill_wait: Duration::from_secs(1),
        };
        let op = crate::publish::hold_op_lock(&dirs[0]);
        let began = Instant::now();
        let stops = std::thread::spawn(move || {
            let deadline = Deadline::in_secs(30);
            let stops = Stops::begin_in(None, entries, Vec::new(), deadline, StopHow::Force, pace);
            stops.finish()
        });
        while !held.iter().all(|(vmm, _)| vmm.exited()) {
            assert!(began.elapsed() < Duration::from_secs(10), "not killed");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(op);
        let (out, down) = stops.join().unwrap();
        let took = began.elapsed();
        assert!(down, "{out}");
        // Asked first, then the VMMs, then the runs: one wait for all of them.
        assert!(took >= pace.term + pace.kill_wait, "{took:?}");
        assert!(took < pace.term + pace.kill_wait * 2, "{took:?}");
        for (vmm, other) in &held {
            assert!(vmm.exited());
            end(other);
        }
        drop(runs);
        for d in dirs {
            std::fs::remove_dir_all(d).ok();
        }
    }

    /// A connect waits for room in a full backlog no longer than the deadline, and a reply
    /// trickled in holds no read past it either.
    #[test]
    fn a_control_request_ends_at_its_deadline() {
        let dir = tmpdir("control-deadline");
        let req = Request::Stop { unit: "db".into() };
        let full = dir.join("full.sock");
        let listener = vk_core::unixpath::bind(&full).unwrap();
        // SAFETY: listen(2) on a socket `listener` owns; a backlog of 0 holds one connection.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let mut queued = Vec::new();
        while let Ok(s) = vk_core::unixpath::connect_within(&full, Some(Duration::from_millis(50)))
        {
            queued.push(s);
            assert!(queued.len() < 64, "the backlog never filled");
        }
        let began = Instant::now();
        let err = control_by(&full, &req, Deadline::in_secs(1), None, |_| {}).unwrap_err();
        assert!(began.elapsed() < Duration::from_secs(3), "{err:#}");

        let slow = dir.join("slow.sock");
        let listener = vk_core::unixpath::bind(&slow).unwrap();
        let serve = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // Never a whole frame, until the client goes.
            while conn.write_all(b"x").is_ok() {
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let began = Instant::now();
        let err = control_by(&slow, &req, Deadline::in_secs(1), None, |_| {}).unwrap_err();
        assert!(began.elapsed() < Duration::from_secs(3), "{err:#}");
        serve.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A manager the run held serves is sent the request.
    #[test]
    fn a_control_request_goes_to_the_run_held() {
        use std::io::BufRead;
        let dir = tmpdir("control-held");
        let ctl = dir.join("ctl.sock");
        let listener = vk_core::unixpath::bind(&ctl).unwrap();
        let serve = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(&conn).read_line(&mut line).unwrap();
            let done = Frame::Done(Reply::ok("db stopped"));
            let text = serde_json::to_string(&done).unwrap() + "\n";
            conn.write_all(text.as_bytes()).unwrap();
            line
        });
        let this = Held::open(i32::try_from(std::process::id()).unwrap())
            .unwrap()
            .unwrap();
        let req = Request::Stop { unit: "db".into() };
        let conn = Control::open(&ctl, Deadline::in_secs(30), None, Some(&this)).unwrap();
        assert_eq!(conn.request(&req, |_| {}).unwrap().message, "db stopped");
        assert!(serve.join().unwrap().contains("db"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A keeper that forks its boot child between two listings has the child held too,
    /// listed after it.
    #[test]
    fn a_vmm_forked_between_listings_is_held() {
        use crate::dev::testutil::StandIn;
        let _env = crate::dev::testutil::env_guard();

        let (keeper, child) = (StandIn::spawn(), StandIn::spawn());
        let ids = [keeper.id(), child.id()].map(|p| i32::try_from(p).unwrap());
        let mut listings = vec![vec![ids[0]], ids.to_vec(), ids.to_vec()].into_iter();
        let held = hold_vmms(|| listings.next().unwrap()).unwrap();
        let pids: Vec<i32> = held.iter().map(|(p, _)| *p).collect();
        assert_eq!(pids, ids);
        assert_eq!(listings.len(), 0, "listed until nothing new showed");
    }

    /// A new VMM on the final scan fails the batch and releases its pidfds.
    #[test]
    fn vmms_that_never_settle_are_not_held() {
        use crate::dev::testutil::StandIn;
        let _env = crate::dev::testutil::env_guard();

        let all: Vec<StandIn> = (0..VMM_SCANS).map(|_| StandIn::spawn()).collect();
        let ids: Vec<i32> = all.iter().map(|s| i32::try_from(s.id()).unwrap()).collect();
        let mut listed = 0;
        let held = hold_vmms(|| {
            listed += 1;
            ids[..listed].to_vec()
        });
        let Err(err) = held else {
            panic!("held VMMs that kept changing")
        };
        assert!(err.contains("none was killed"), "{err}");
    }

    /// A run is down only once every VMM of it that was killed is gone too.
    #[test]
    fn a_run_is_down_only_with_its_vmms() {
        use crate::dev::testutil::StandIn;
        let _env = crate::dev::testutil::env_guard();

        let dir = tmpdir("stops-vmms");
        let run = StandIn::spawn();
        let vmm = StandIn::spawn();
        let hold = |s: &StandIn| Held::open(i32::try_from(s.id()).unwrap()).unwrap().unwrap();
        let mut r = RunStop {
            entry: run_entry(&dir, &run),
            run: Some(hold(&run)),
            fate: Fate::Stopping,
            vmms: vec![hold(&vmm)],
        };
        drop(run);
        r.check();
        assert_eq!(r.fate, Fate::Stopping);
        // Nor does the run's last signal, finding it gone, take it for down.
        r.signal(libc::SIGKILL);
        r.check();
        assert_eq!(r.fate, Fate::Stopping);
        drop(vmm);
        r.check();
        assert_eq!(r.fate, Fate::Down);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A state-dir lock held by a process other than the entry's `vk run` reads as a run that
    /// replaced it: neither that run nor its relays are signalled.
    #[test]
    fn stop_entry_leaves_a_vm_whose_lock_another_process_holds() {
        use crate::dev::testutil::StandIn;

        let dir = tmpdir("stop-entry");
        let lock = std::fs::File::open(&dir).unwrap();
        // SAFETY: the fd is owned by `lock`, which outlives the call.
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        // stop_entry takes a holder procfs cannot name for the entry's own run, so this
        // needs procfs to name the test process.
        assert_eq!(
            crate::run::flock_holder_pid(&lock),
            i32::try_from(std::process::id()).ok()
        );
        let mut run = StandIn::spawn();
        let mut relay = StandIn::spawn();
        let _relay_lock = crate::publish::fake_publisher(
            &dir,
            "web",
            "tcp://127.0.0.1:8600",
            "vsock://80",
            relay.id(),
            None,
        );
        let mut e = entry(dir.clone(), None);
        e.pid = run.id();
        assert!(stop_entry(&e, 1).is_none());
        assert!(run.alive(), "the entry's run was signalled");
        assert!(relay.alive(), "its relay was stopped");
        assert!(dir.join("publish/web.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A VM control that pauses and refuses to resume.
    struct PauseOnly;

    impl crate::vmmctl::Control for PauseOnly {
        fn pause(&self) -> Result<()> {
            Ok(())
        }

        fn resume(&self) -> Result<()> {
            bail!("vcpu 1 exited")
        }

        fn snapshot(&self, _: &Path) -> Result<()> {
            unreachable!()
        }

        fn quit(&self) -> Result<()> {
            unreachable!()
        }
    }

    /// Pause and resume require a running VM with a control socket; report the socket's error.
    #[test]
    fn pause_line_reports_each_vm() {
        let dir = tmpdir("pause");
        let sock = dir.join("vmm.sock");
        crate::vmmctl::serve(&sock, PauseOnly).unwrap();
        let mut e = entry(dir.clone(), None);
        e.control = Some(sock);
        let (line, ok) = pause_line(&e, PauseRequest::Pause);
        assert_eq!(
            line,
            format!("devcontainer (pid {}) is not running\n", e.pid)
        );
        assert!(!ok);

        // The run holds its state dir's lock.
        let lock = std::fs::File::open(&dir).unwrap();
        // SAFETY: the fd is owned by `lock`, which outlives the call.
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let (line, ok) = pause_line(&e, PauseRequest::Pause);
        assert_eq!(line, format!("paused devcontainer (pid {})\n", e.pid));
        assert!(ok);
        let (line, ok) = pause_line(&e, PauseRequest::Resume);
        assert_eq!(
            line,
            format!("devcontainer (pid {}): vcpu 1 exited\n", e.pid)
        );
        assert!(!ok);

        e.control = None;
        let (line, ok) = pause_line(&e, PauseRequest::Pause);
        assert_eq!(
            line,
            format!(
                "devcontainer (pid {}) has no control socket (only UEFI guests can be paused)\n",
                e.pid
            )
        );
        assert!(!ok);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// End-to-end listing with a temporary name index and registry.
    mod listing {
        use super::*;
        use crate::dev::testutil::Homes;
        use crate::vmlist::{Filter, Kind};
        use std::ffi::OsString;

        /// Register a running primary, hold its state directory lock and give each service a console log.
        fn up(dir: &Path, project: &Path, services: &[&str]) -> (Registration, vk_fs::LockFile) {
            std::fs::create_dir_all(dir).unwrap();
            let dir = canonical(dir);
            let mut e = entry(dir.clone(), Some(canonical(project)));
            e.exec_addr = format!("vsock-auto://{}/vsock.sock:4444", dir.display());
            for s in services {
                let svc = dir.join(format!("svc-{s}"));
                std::fs::create_dir_all(&svc).unwrap();
                std::fs::write(svc.join(crate::run::CONSOLE_LOG), "").unwrap();
                e.services.push(ServiceEntry {
                    name: s.to_string(),
                    exec_addr: format!("vsock-auto://{}/vsock.sock:4444", svc.display()),
                    stale_recipe: None,
                });
            }
            let lock = crate::dev::list::try_lock_state_dir(&dir).unwrap();
            (register(e), lock)
        }

        /// A stopped run in `run/<name>`, named `name`, launched for `project`.
        fn stopped(homes: &Homes, name: &str, project: &Path) -> PathBuf {
            let dir = run_dir(name);
            std::fs::create_dir_all(&dir).unwrap();
            let recipe = crate::names::Recipe {
                args: vec!["run".into()],
                cwd: project.to_path_buf(),
                project_dir: project.to_path_buf(),
            };
            recipe.write(&dir).unwrap();
            homes.name(&dir, name);
            dir
        }

        fn run_dir(name: &str) -> PathBuf {
            crate::names::run_base().unwrap().join(name)
        }

        fn project(homes: &Homes) -> PathBuf {
            let p = homes.dir().join("proj");
            std::fs::create_dir_all(&p).unwrap();
            canonical(&p)
        }

        fn list(target: Option<&OsStr>, filter: Filter, fields: &[&str], json: bool) -> String {
            list_report(ListOpts {
                target: target.map(OsStr::to_os_string),
                fields: fields.iter().map(|f| f.to_string()).collect(),
                json,
                filter,
                ..ListOpts::default()
            })
            .unwrap()
        }

        fn stopped_only() -> Filter {
            Filter {
                stopped: true,
                ..Filter::default()
            }
        }

        fn detail(target: &OsStr) -> String {
            list_report(ListOpts {
                target: Some(target.to_os_string()),
                detail: true,
                ..ListOpts::default()
            })
            .unwrap()
        }

        #[test]
        fn the_flags_alone_choose_a_table_or_records() {
            let homes = Homes::new("list-detail");
            let proj = project(&homes);
            let app = run_dir("app");
            let _app = up(&app, &proj, &[]);
            homes.name(&app, "app");
            let app = OsStr::new("app");
            // A single named VM still gets the default table.
            let table = list(Some(app), Filter::default(), &[], false);
            let head: Vec<&str> = table
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .take(2)
                .collect();
            assert_eq!(head, ["NAME", "KIND"], "{table}");
            let record = detail(app);
            assert!(record.starts_with("NAME          app\n"), "{record}");
            assert!(record.contains("\nSTATUS        running\n"), "{record}");
            assert!(
                record.contains("\nIMAGE         devcontainer\n"),
                "{record}"
            );
            assert_eq!(
                list(Some(app), stopped_only(), &[], false),
                "no matching vk VM for app\n"
            );
            assert_eq!(list(Some(app), stopped_only(), &[], true), "[]\n");
            // A project with a running and a stopped primary is a table of both.
            stopped(&homes, "old", &proj);
            let dir = proj.as_os_str();
            let table = list(Some(dir), Filter::default(), &[], false);
            assert!(table.starts_with("NAME "), "{table}");
            assert!(table.lines().any(|l| l.starts_with("app ")), "{table}");
            assert!(table.lines().any(|l| l.starts_with("old ")), "{table}");
            let json: serde_json::Value =
                serde_json::from_str(&list(Some(dir), Filter::default(), &[], true)).unwrap();
            let names: Vec<&str> = json
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["name"].as_str().unwrap())
                .collect();
            assert_eq!(names, ["app", "old"]);
            // The directory matches both primaries, including the stopped one.
            let records = detail(dir);
            assert!(records.starts_with("NAME          app\n"), "{records}");
            assert!(
                records
                    .contains("\n\nNAME          old\nKIND          run\nSTATUS        stopped\n"),
                "{records}"
            );
        }

        // The claim can outlive a run killed during its first boot.
        #[test]
        fn a_provisional_name_is_not_listed_as_stopped() {
            let _homes = Homes::new("list-claim");
            let dir = run_dir("boot");
            std::fs::create_dir_all(&dir).unwrap();
            let held = crate::dev::list::try_lock_state_dir(&dir).unwrap();
            let idx = crate::names::Index::open().unwrap();
            assert!(idx.provisional().claim_exact(&dir, "boot").unwrap());
            for filter in [Filter::default(), stopped_only()] {
                assert_eq!(list(None, filter, &["name"], false), "", "held");
            }
            drop(held);
            for filter in [Filter::default(), stopped_only()] {
                assert_eq!(list(None, filter, &["name"], false), "", "abandoned");
            }
            idx.commit("boot").unwrap();
            assert_eq!(list(None, stopped_only(), &["name"], false), "boot\n");
        }

        // Null fields remain selectable. A service with unknown status does not match `--running`.
        #[test]
        fn every_row_has_every_field() {
            let homes = Homes::new("list-fields");
            let proj = project(&homes);
            let app = run_dir("app");
            let _app = up(&app, &proj, &["db"]);
            homes.name(&app, "app");
            stopped(&homes, "old", &proj);
            let report = |fields: &[&str], stale: bool| {
                list_report(ListOpts {
                    fields: fields.iter().map(|f| f.to_string()).collect(),
                    stale,
                    ..ListOpts::default()
                })
            };
            assert_eq!(
                report(&["name", "parent"], false).unwrap(),
                "app\tnull\napp/db\tapp\nold\tnull\n"
            );
            assert_eq!(
                report(&["name", "stale"], true).unwrap(),
                "app\tnull\napp/db\tnull\nold\tnull\n"
            );
            let err = report(&["stale"], false).unwrap_err().to_string();
            assert!(err.contains("pass --stale"), "{err}");
            let running = Filter {
                running: true,
                ..Filter::default()
            };
            assert_eq!(list(None, running, &["name"], false), "app\n");
            let services = Filter {
                kind: Some(Kind::Service),
                ..Filter::default()
            };
            assert_eq!(list(None, services, &["status"], false), "-\n");
        }

        // A directory-name alias selects the service under its primary's displayed name.
        #[test]
        fn a_service_is_found_by_its_vm_s_directory_name() {
            let homes = Homes::new("list-alias");
            let proj = project(&homes);
            let alias = "shop-3f9c0d1e2a4b5c6d";
            let dir = crate::dev::plan::dev_state_base().unwrap().join(alias);
            let running = up(&dir, &proj, &["db"]);
            homes.name(&dir, "shop");
            let db = OsString::from(format!("{alias}/db"));
            let fields = ["name", "status"];
            assert_eq!(
                list(Some(&db), Filter::default(), &fields, false),
                "shop/db\t-\n"
            );
            drop(running);
            assert_eq!(
                list(Some(&db), Filter::default(), &fields, false),
                "shop/db\tstopped\n"
            );
            let web = OsString::from(format!("{alias}/web"));
            assert_eq!(
                list(Some(&web), Filter::default(), &[], false),
                format!("no matching vk VM for {alias}/web\n")
            );
        }

        // A recipe's non-UTF-8 project survives both JSON output and field selection.
        #[test]
        fn a_project_that_is_not_utf8_is_listed() {
            use std::os::unix::ffi::OsStrExt;
            let homes = Homes::new("list-bytes");
            stopped(&homes, "odd", Path::new(OsStr::from_bytes(b"/w/\xff")));
            let json: serde_json::Value =
                serde_json::from_str(&list(None, Filter::default(), &[], true)).unwrap();
            assert_eq!(
                json[0]["project"],
                serde_json::json!({"bytes": [47, 119, 47, 255]})
            );
            assert_eq!(list(None, Filter::default(), &["name"], false), "odd\n");
        }

        // A retargeted symlink can make the recipe and live registration name different projects.
        #[test]
        fn a_running_vm_missed_by_the_ref_is_not_stopped() {
            let homes = Homes::new("list-moved");
            let (a, b) = (homes.dir().join("a"), project(&homes));
            std::fs::create_dir_all(&a).unwrap();
            let app = stopped(&homes, "app", &b);
            let _app = up(&app, &a, &[]);
            assert_eq!(
                list(Some(b.as_os_str()), stopped_only(), &["name"], false),
                ""
            );
            assert_eq!(
                list(Some(b.as_os_str()), Filter::default(), &[], false),
                format!("no matching vk VM for {}\n", b.display())
            );
            assert_eq!(
                list(None, Filter::default(), &["status"], false),
                "running\n"
            );
        }

        // Non-UTF-8 project and build paths survive registration and the stopped-listing copy.
        #[test]
        fn a_running_vm_with_paths_that_are_not_utf8_is_running() {
            use std::os::unix::ffi::OsStrExt;
            let homes = Homes::new("list-bytes-up");
            let odd = PathBuf::from(OsStr::from_bytes(b"/w/\xff"));
            let dir = stopped(&homes, "odd", &odd);
            let dir = canonical(&dir);
            let lock = crate::dev::list::try_lock_state_dir(&dir).unwrap();
            let mut e = entry(dir.clone(), Some(odd.clone()));
            let dockerfile = odd.join("Dockerfile");
            e.stale_recipe = Some(StaleRecipe {
                dockerfiles: vec![dockerfile.clone()],
                contexts: vec![odd.clone()],
                build_contexts: vec![("extra".into(), odd.clone())],
                build_args: Vec::new(),
                target: None,
                root_ext4: odd.join("root.ext4"),
            });
            let _reg = register(e);
            let last = last_entry(&dir).unwrap().unwrap();
            assert_eq!(last.project_dir, Some(odd.clone()));
            let recipe = last.stale_recipe.unwrap();
            assert_eq!(recipe.dockerfiles, [dockerfile]);
            assert_eq!(recipe.contexts, std::slice::from_ref(&odd));
            assert_eq!(recipe.build_contexts, [("extra".to_string(), odd.clone())]);
            assert_eq!(recipe.root_ext4, odd.join("root.ext4"));
            let running = Filter {
                running: true,
                ..Filter::default()
            };
            assert_eq!(list(None, running, &["name"], false), "odd\n");
            drop(lock);
        }

        /// A run on its way up is listed `starting`, its first boot's claim and lock
        /// notwithstanding, until it registers; a stop of it is listed `stopping`, and once
        /// that stop is overdue, with what can be done.
        #[test]
        fn a_vm_on_its_way_up_or_down_says_so() {
            let homes = Homes::new("list-transient");
            let proj = project(&homes);
            let dir = canonical(&run_dir("boot"));
            std::fs::create_dir_all(&dir).unwrap();
            let held = crate::dev::list::try_lock_state_dir(&dir).unwrap();
            let idx = crate::names::Index::open().unwrap();
            assert!(idx.provisional().claim_exact(&dir, "boot").unwrap());
            crate::vmstate::starting(&dir);
            let running = Filter {
                running: true,
                ..Filter::default()
            };
            let fields = ["name", "status", "attention"];
            assert_eq!(
                list(None, running.clone(), &fields, false),
                "boot\tstarting\tnull\n"
            );
            idx.commit("boot").unwrap();
            let mut e = entry(dir.clone(), Some(proj));
            e.pid_start_ticks = own_start_ticks();
            let _reg = register(e.clone());
            assert_eq!(crate::vmstate::peek(&dir), None, "registered is running");
            assert_eq!(
                list(None, Filter::default(), &fields, false),
                "boot\trunning\tnull\n"
            );
            // A stop of this very run that timed out a minute ago.
            let now = unix_now();
            let overdue = crate::vmstate::Transient {
                state: crate::vmstate::State::Stopping,
                pid: e.pid,
                pid_start_ticks: e.pid_start_ticks,
                since_secs: now - 270,
                deadline_secs: Some(now - 60),
                by_pid: None,
                by_start_ticks: None,
            };
            let file = dir.join(crate::vmstate::FILE);
            std::fs::write(&file, serde_json::to_vec(&overdue).unwrap()).unwrap();
            let json: serde_json::Value =
                serde_json::from_str(&list(None, running.clone(), &[], true)).unwrap();
            assert_eq!(json[0]["status"], "stopping");
            let why = json[0]["attention"].as_str().unwrap();
            assert!(why.starts_with("a stop timed out 1m ago"), "{why}");
            // A stop of another run, which this one replaced, says nothing of this one.
            let other = crate::vmstate::Transient {
                pid: e.pid + 1,
                ..overdue
            };
            std::fs::write(&file, serde_json::to_vec(&other).unwrap()).unwrap();
            assert_eq!(
                list(None, running.clone(), &fields, false),
                "boot\trunning\tnull\n"
            );
            drop(held);
        }

        /// Listings and lookups preserve dead registrations, transient records and publisher files.
        /// A dead registration or transient marks the VM stale. A dead publisher alone does not.
        /// Selecting `stale_record` returns a boolean for both rows.
        #[test]
        fn a_listing_writes_nothing_and_marks_what_is_out_of_date() {
            let homes = Homes::new("list-readonly");
            let proj = project(&homes);
            let app = canonical(&run_dir("app"));
            let _app = up(&app, &proj, &[]);
            homes.name(&app, "app");
            drop(crate::publish::fake_publisher(
                &app,
                "web",
                "tcp://127.0.0.1:1",
                "vsock://80",
                1,
                None,
            ));
            let publish = app.join("publish");
            std::fs::write(publish.join("web.log"), "kept").unwrap();
            // The killed run left both its registration and its stopping record.
            let gone = canonical(&stopped(&homes, "gone", &proj));
            let mut dead = entry(gone.clone(), Some(proj.clone()));
            dead.pid_start_ticks = Some(1);
            let reg = registry_dir().unwrap();
            record_in(&reg, &dead).unwrap();
            let lapsed = crate::vmstate::Transient {
                state: crate::vmstate::State::Stopping,
                pid: dead.pid,
                pid_start_ticks: Some(1),
                since_secs: 0,
                deadline_secs: None,
                by_pid: None,
                by_start_ticks: None,
            };
            let file = gone.join(crate::vmstate::FILE);
            std::fs::write(&file, serde_json::to_vec(&lapsed).unwrap()).unwrap();
            let fields = ["name", "status", "stale_record"];
            assert_eq!(
                list(None, Filter::default(), &fields, false),
                "app\trunning\tfalse\ngone\tstopped\ttrue\n"
            );
            let problems = Filter {
                problems: true,
                ..Filter::default()
            };
            assert_eq!(list(None, problems, &["name"], false), "gone\n");
            let table = list(None, Filter::default(), &[], false);
            assert!(table.contains("stopped*"), "{table}");
            assert!(!list(Some(OsStr::new("app")), Filter::default(), &[], false).is_empty());
            assert_eq!(
                at_most_one(Some(Selector::Pid(std::process::id())))
                    .unwrap()
                    .1
                    .unwrap()
                    .state_dir,
                app
            );
            for kept in [
                publish.join("web.json"),
                publish.join("web.lock"),
                publish.join("web.log"),
                file,
            ] {
                assert!(kept.exists(), "{} was removed", kept.display());
            }
            assert!(recorded(&reg, &dead), "the dead entry was pruned");
            assert_eq!(
                out_of_date(1, 0).unwrap(),
                "1 VM(s) listed from out-of-date records. Run `vk stop --tidy` to \
                 check all stale records"
            );
            assert_eq!(out_of_date(0, 0), None);
            // A removed directory still counts as an unlisted registration.
            std::fs::remove_dir_all(&gone).unwrap();
            let listed = HashSet::from([app.clone()]);
            assert_eq!(unlisted_entries(&registered().1, &listed), 1);
        }

        /// An entry left by a run that was killed is not taken for the run now starting on its
        /// directory, whose lock it would otherwise pass for its own.
        #[test]
        fn a_new_start_is_not_the_old_run_that_registered() {
            let homes = Homes::new("list-superseded");
            let dir = stopped(&homes, "app", &project(&homes));
            let dir = canonical(&dir);
            let mut old = entry(dir.clone(), None);
            old.pid += 1;
            record_in(&registry_dir().unwrap(), &old).unwrap();
            let held = crate::dev::list::try_lock_state_dir(&dir).unwrap();
            crate::vmstate::starting(&dir);
            assert!(!alive(&old));
            // Nor one of an earlier run that had this run's pid.
            let mut reused = entry(dir.clone(), None);
            reused.pid = std::process::id();
            reused.pid_start_ticks = own_start_ticks().map(|t| t - 1);
            assert!(!alive(&reused));
            reused.pid_start_ticks = own_start_ticks();
            assert!(
                alive(&reused),
                "the run starting is alive once it registers"
            );
            assert_eq!(
                list(None, Filter::default(), &["name", "status", "pid"], false),
                "app\tstarting\tnull\n"
            );
            drop(held);
        }

        // A run can acquire its state lock after the registry snapshot.
        #[test]
        fn a_locked_state_dir_is_not_stopped() {
            let homes = Homes::new("list-locked");
            let proj = project(&homes);
            let dir = stopped(&homes, "app", &proj);
            let held = crate::dev::list::try_lock_state_dir(&dir).unwrap();
            assert_eq!(list(None, stopped_only(), &["name"], false), "");
            drop(held);
            assert_eq!(list(None, stopped_only(), &["name"], false), "app\n");
        }

        #[test]
        fn an_unreadable_index_is_an_error() {
            use std::os::unix::fs::PermissionsExt;
            let homes = Homes::new("list-unreadable");
            stopped(&homes, "app", &project(&homes));
            let bases = [
                crate::names::state_base().unwrap().join("names"),
                crate::dev::plan::dev_state_base().unwrap(),
            ];
            for dir in bases {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).unwrap();
                // Root may still read the directory after chmod.
                let readable = std::fs::read_dir(&dir).is_ok();
                let report = list_report(ListOpts::default());
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                if !readable {
                    let err = format!("{:#}", report.unwrap_err());
                    assert!(err.contains(&dir.display().to_string()), "{err}");
                }
            }
        }

        #[test]
        fn a_bad_state_home_is_an_error() {
            let _homes = Homes::new("list-badhome");
            // SAFETY: serialized by `Homes`, which puts it back on drop.
            unsafe { std::env::set_var("XDG_STATE_HOME", "relative") };
            let err = list_report(ListOpts::default()).unwrap_err();
            assert!(format!("{err:#}").contains("XDG_STATE_HOME"), "{err:#}");
        }

        // Without a recipe, the saved registration supplies the project for display and selection.
        #[test]
        fn a_stopped_run_is_selected_by_the_project_it_shows() {
            let homes = Homes::new("list-last");
            let proj = project(&homes);
            let dir = run_dir("last");
            std::fs::create_dir_all(&dir).unwrap();
            record_last(&entry(canonical(&dir), Some(proj.clone()))).unwrap();
            homes.name(&dir, "last");
            let fields = ["name", "project"];
            let row = format!("last\t{}\n", proj.display());
            assert_eq!(list(None, Filter::default(), &fields, false), row);
            assert_eq!(
                list(Some(proj.as_os_str()), stopped_only(), &fields, false),
                row
            );
            // Distinguish a malformed registration from a missing file.
            std::fs::write(dir.join(LAST), "{").unwrap();
            assert!(last_entry(&dir).is_err());
            std::fs::remove_file(dir.join(LAST)).unwrap();
            assert!(last_entry(&dir).unwrap().is_none());
        }
    }
}
