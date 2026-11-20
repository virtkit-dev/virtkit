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
//! entries whose owner is gone. Entries live under `<data base>/vms/` (the same
//! `$XDG_DATA_HOME/virtkit` home `vk run`'s image cache uses), one JSON file per VM.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use vk_core::fleetctl::{Frame, Reply, Request, UnitStatus};

/// One running VM's record. Serialized as `<slug(state_dir)>.json` in the registry dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmEntry {
    /// The run's `--state-dir`, canonicalized — the VM's identity and the file's key.
    pub state_dir: PathBuf,
    /// Canonical project directory: `--workspace`, then `--workdir`, then the `vk run`
    /// launch directory. `vk list DIR` and `vk stop DIR` match it; `None` when unavailable.
    #[serde(default)]
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
    #[serde(default)]
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
    #[serde(default)]
    pub guest_agent: Option<PathBuf>,
    /// The VM's control socket ([`crate::vmmctl`]), which `vk pause` and `vk resume` use;
    /// `None` for a VM without one.
    #[serde(default)]
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
    Ok(crate::run::default_data_base()?.join("vms"))
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
    running_in(&dir)
}

/// [`running`], for the registry at `dir`.
pub(crate) fn running_in(dir: &Path) -> Vec<VmEntry> {
    let mut out = Vec::new();
    for entry in load_all_in(dir) {
        if alive(&entry) {
            out.push(entry);
        } else {
            remove_in(dir, &entry.state_dir);
        }
    }
    out.sort_by_key(|e| e.created_secs);
    out
}

/// RAII handle: removes the VM's registry entry when the run drops it (clean exit or unwind).
/// A `SIGKILL` skips this — those stale entries are pruned by `alive` on the next read.
/// The last registry entry of a VM, kept in its state dir.
pub const LAST: &str = ".virtkit-last.json";

/// Write `entry` into its own state dir as [`LAST`].
fn record_last(entry: &VmEntry) -> Result<()> {
    crate::statefile::write(
        &entry.state_dir.join(LAST),
        &serde_json::to_vec_pretty(entry)?,
    )
}

/// The entry a VM last registered from `state_dir`, if it left one.
pub fn last_entry(state_dir: &Path) -> Option<VmEntry> {
    serde_json::from_slice(&std::fs::read(state_dir.join(LAST)).ok()?).ok()
}

pub struct Registration {
    state_dir: Option<PathBuf>,
}

/// Whether this process registered a VM: its run got as far as a VM that is up.
static REGISTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this process ever registered a VM (see [`register`]). A named run that ends
/// without having done so never had a VM, and gives its name back.
pub fn ever_registered() -> bool {
    REGISTERED.load(std::sync::atomic::Ordering::Relaxed)
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
    // Serialized against a correction to the same entry (see `WRITES`); taken here rather than
    // in `record_in`, which the correction calls while already holding it.
    let _writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
    // A copy beside the VM, read once it has stopped: what `vk list` shows of a VM that is
    // known but not running.
    let _ = record_last(&entry);
    // Registered is running: the start is over.
    crate::vmstate::clear(&entry.state_dir);
    REGISTERED.store(true, std::sync::atomic::Ordering::Relaxed);
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

/// Does `entry` belong to the directory `filter` — i.e. is `filter` the VM's project dir (or
/// an ancestor of it), or the VM's own state dir?
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
    let matched = running()
        .into_iter()
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

/// What [`still_registered`] watches: the selector a REF resolved to, once.
pub enum Watched {
    /// the VMs this selects (`None`: the current directory's)
    Selected(Option<Selector>),
    /// a REF that does not resolve: nothing can be said about it
    Unknown,
}

impl Watched {
    /// Resolve `target` once, for a loop that then asks [`still_registered`] repeatedly:
    /// resolving reads the name index and may print a note, neither of which belongs in
    /// every round.
    pub fn of(target: Option<&OsStr>) -> Watched {
        match target.map(|t| Ref::parse(t).and_then(|r| Selector::from_ref_quietly(r, false))) {
            Some(Ok((sel, _))) => Watched::Selected(Some(sel)),
            Some(Err(_)) => Watched::Unknown,
            None => Watched::Selected(None),
        }
    }
}

/// Whether a VM still answers to `watched`. Anything short of a definite "nothing matches" —
/// an unreadable registry, two VMs matching — counts as still there: `vk logs -f` ends its
/// stream on a `false` and must not do that over a transient.
pub fn still_registered(watched: &Watched) -> bool {
    let Watched::Selected(sel) = watched else {
        return true;
    };
    !matches!(select_running(sel.clone()), Ok((_, m)) if m.is_empty())
}

/// Whether `arg` is a VM's name (or its `NAME/SERVICE`), as opposed to a pid, a path, or a
/// bare word that is only a directory.
pub fn names_a_vm(arg: &OsStr) -> bool {
    matches!(
        Ref::parse(arg),
        Ok(Ref::Name { vm, .. }) if crate::names::resolve(&vm).is_ok_and(|d| d.is_some())
    )
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
/// Like `vk publish list`, this prunes the records of publishers that have exited.
fn published(entry: &VmEntry) -> Vec<Published> {
    match crate::publish::live(&entry.state_dir) {
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
/// `timeout` bounds each read and write — `None` for an op that builds.
pub fn control(
    ctl: &Path,
    req: &Request,
    timeout: Option<Duration>,
    mut on_progress: impl FnMut(&str),
) -> Result<Reply> {
    use std::io::{BufRead, BufReader};
    let mut stream = vk_core::unixpath::connect(ctl)
        .with_context(|| format!("control: connect {}", ctl.display()))?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    let mut text = serde_json::to_string(req).context("encoding the control request")?;
    text.push('\n');
    stream.write_all(text.as_bytes())?;
    let mut rd = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        if rd.read_line(&mut line)? == 0 {
            bail!("control peer closed before Done");
        }
        match serde_json::from_str::<Frame>(line.trim_end()).context("decoding control frame")? {
            Frame::Progress(p) => on_progress(&p),
            Frame::Done(reply) => return Ok(reply),
        }
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

/// Reject `--field` paths that no view could satisfy, before any VM is asked: several names
/// in one flag (any whitespace or a comma — every segment is a field name or an array index,
/// so neither can occur in a valid path), an empty segment (`guest_ip.`), a segment with a
/// JSON-pointer metacharacter (`/`, `~`), or a path given twice (the `--json` object could
/// hold it only once, and the text would silently disagree). Unknown names are checked per
/// view by `select`.
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

/// One `--field` of a VM view. `path` is dotted (`guest_ip`, `services.0.ip`) and resolved as
/// a JSON pointer, so a missing branch below the first segment is `null` — a non-compose VM
/// has no `services.0`, and a record omits a key that does not apply. An unknown first
/// segment is an error naming the fields there are.
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

/// What `vk list` was asked for.
#[derive(Debug, Default)]
pub struct ListOpts {
    pub target: Option<std::ffi::OsString>,
    pub recursive: bool,
    pub json: bool,
    pub stale: bool,
    pub fields: Vec<String>,
    pub wide: bool,
    pub filter: crate::vmlist::Filter,
}

/// `vk list`: every VM this host knows, running or stopped, one row each (see
/// [`crate::vmlist`]). A REF that names exactly one running VM prints its full record.
pub fn list_report(opts: ListOpts) -> Result<String> {
    use crate::vmlist::{Kind, Known, Live};
    check_fields(&opts.fields)?;
    let mut filter = opts.filter;
    let mut pid_service = None;
    let target = match &opts.target {
        Some(t) => {
            let (sel, service) = Selector::from_ref(Ref::parse(t)?, opts.recursive)?;
            match (&sel, service) {
                (Selector::Named { name, .. }, Some(service)) => {
                    filter.name = Some(format!("{name}/{service}"));
                }
                (_, service) => pid_service = service,
            }
            Some(sel.resolved())
        }
        None => None,
    };
    let stale = opts.stale;
    let mut vms = running();
    if let Some(sel) = &target {
        vms.retain(|e| sel.matches(e));
    }
    let idx = crate::names::Index::open().ok();
    crate::dev::list::name_unnamed();
    let named = idx.as_ref().map(|i| i.all()).unwrap_or_default();
    let name_of = |dir: &Path| {
        let canonical = canonical(dir);
        named
            .iter()
            .find(|(_, d)| *d == dir || *d == canonical)
            .map(|(n, _)| n.clone())
    };
    let dev_base = crate::dev::plan::dev_state_base()
        .map(|b| canonical(&b))
        .ok();
    let kind_of = |dir: &Path| match canonical(dir).parent() == dev_base.as_deref() {
        true => Kind::Dev,
        false => Kind::Run,
    };
    // What a running VM is listed as: its name, else — for a dev environment that has none
    // yet, in its first boot or a task's throwaway one — its state dir's own name, which
    // names it to every command too. Only a run from before names is left with its pid.
    let listed_name = |e: &VmEntry| {
        name_of(&e.state_dir).or_else(|| {
            let dir_name = e.state_dir.file_name()?.to_str()?;
            (kind_of(&e.state_dir) == Kind::Dev).then(|| dir_name.to_string())
        })
    };
    let units: Vec<Option<Vec<UnitStatus>>> = vms.iter().map(service_units).collect();
    let fresh: Vec<Freshness> = vms
        .iter()
        .map(|e| match stale {
            true => freshness_all(e),
            false => Freshness::Unknown,
        })
        .collect();
    let mem_used: Vec<Option<u64>> = vms
        .iter()
        .map(|e| {
            i32::try_from(e.pid)
                .ok()
                .and_then(crate::usage::tree_resident)
        })
        .collect();
    let published_by_vm: Vec<Vec<Published>> = vms.iter().map(published).collect();
    // A `PID/SERVICE` names one row of the VM with that pid, under whatever that VM is
    // listed as.
    if let (Some(service), [only]) = (&pid_service, vms.as_slice()) {
        let vm = listed_name(only).unwrap_or_else(|| only.pid.to_string());
        filter.name = Some(format!("{vm}/{service}"));
    }
    use crate::vmstate::Standing;
    let now = unix_now();
    let listed = |e: &VmEntry| listed_name(e).unwrap_or_else(|| e.pid.to_string());
    let transients: Vec<_> = vms
        .iter()
        .map(|e| crate::vmstate::peek(&e.state_dir))
        .collect();
    let live: Vec<Live> = vms
        .iter()
        .enumerate()
        .map(|(i, e)| Live {
            entry: e,
            name: listed_name(e),
            kind: kind_of(&e.state_dir),
            environment: dev_environment(&e.state_dir),
            units: units[i].clone(),
            published: published_by_vm[i].clone(),
            mem_used: mem_used[i],
            fresh: stale.then_some(fresh[i]),
            // On record as under way or overdue: said as recorded. One that describes
            // nothing any more is read past.
            transient: transients[i]
                .as_ref()
                .filter(|(_, standing)| *standing != Standing::Gone)
                .map(|(t, _)| t.state.label()),
            attention: transients[i]
                .as_ref()
                .and_then(|(t, standing)| attention(t, *standing, &listed(e), now)),
        })
        .collect();
    let running_dirs: Vec<&Path> = vms.iter().map(|e| e.state_dir.as_path()).collect();
    // What is known and not running: every named VM, and every dev state dir that has no
    // name — one that recorded no boot, or one that could not be named — which its own
    // directory name still names.
    let unnamed = crate::dev::list::unnamed_dirs(&named);
    let known: Vec<Known> = named
        .iter()
        .map(|(name, dir)| (name, dir, crate::vmlist::STOPPED))
        .chain(unnamed.iter().map(|(name, dir, booted)| match booted {
            true => (name, dir, crate::vmlist::STOPPED),
            false => (name, dir, crate::vmlist::NEVER_BOOTED),
        }))
        .filter(|(_, dir, _)| dir.is_dir() && !running_dirs.contains(&canonical(dir).as_path()))
        .filter_map(|(name, dir, at_rest)| {
            let kind = kind_of(dir);
            let last = last_entry(dir);
            // Its run holds the dir and has no VM up yet: neither stopped nor running. A
            // record that no longer holds is read past.
            let transient = crate::vmstate::peek(dir);
            let status = match &transient {
                Some((_, Standing::Gone)) => at_rest,
                // Under way or overdue: as its record words it.
                Some((t, _)) => t.state.label(),
                None => at_rest,
            };
            let attention = transient
                .as_ref()
                .and_then(|(t, standing)| attention(t, *standing, name, now));
            let (project, environment) = match kind {
                Kind::Dev => dev_identity(dir),
                _ => (
                    crate::names::Recipe::read(dir)
                        .ok()
                        .flatten()
                        .map(|r| r.project_dir),
                    None,
                ),
            };
            let k = Known {
                name: name.clone(),
                dir: dir.clone(),
                kind,
                status,
                attention,
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
            };
            keep.then_some(k)
        })
        .collect();
    let rows: Vec<crate::vmlist::Row> = crate::vmlist::rows(&live, &known, now)
        .into_iter()
        .filter(|r| filter.keeps(r))
        .collect();
    if !opts.fields.is_empty() {
        let views = rows
            .iter()
            .map(|r| serde_json::to_value(r).context("serializing VM row"))
            .collect::<Result<Vec<_>>>()?;
        return fields_report(&views, &opts.fields, opts.json);
    }
    if opts.json {
        return Ok(serde_json::to_string_pretty(&rows).context("serializing VM list")? + "\n");
    }
    // What needs someone's attention is said in full, with what can be done about it: a
    // listing shows it, and neither asks nor acts.
    for r in rows.iter().filter(|r| r.attention.is_some()) {
        eprintln!(
            "vk: {}: {}",
            r.name,
            r.attention.as_deref().unwrap_or_default()
        );
    }
    // One running VM asked for by name, pid or directory: its full record.
    if filter.name.is_none() && full_record(target.as_ref(), vms.len()) {
        return Ok(detail(
            &vms[0],
            units[0].as_deref(),
            &published_by_vm[0],
            fresh[0],
            stale,
            mem_used[0],
        ));
    }
    if rows.is_empty() {
        return Ok(match &target {
            Some(sel) => sel.not_found(),
            None => "no vk VMs\n".to_string(),
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

/// What to say of a VM whose recorded transient state is overdue — a stop that timed out
/// while its run is still there — and what can be done about it; `None` for any other
/// standing. Said by `vk list`, which leaves the doing to the user.
fn attention(
    t: &crate::vmstate::Transient,
    standing: crate::vmstate::Standing,
    name: &str,
    now: u64,
) -> Option<String> {
    if standing != crate::vmstate::Standing::Overdue {
        return None;
    }
    let pid = t.pid;
    let ago = fmt_uptime(now.saturating_sub(t.deadline_secs.unwrap_or(t.since_secs)));
    // With a deadline it ran out; without one, the command waiting on it went away.
    let how = match t.deadline_secs {
        Some(_) => "timed out",
        None => "was interrupted, begun",
    };
    Some(match t.state {
        crate::vmstate::State::Stopping => format!(
            "a stop {how} {ago} ago and its run (pid {pid}) is still there — `vk logs \
             {name}` and `vk list {name}` show it, `vk stop {name}` tries again, \
             `vk stop --force {name}` insists then kills it"
        ),
        crate::vmstate::State::Starting => format!(
            "its start is overdue by {ago} and its run (pid {pid}) is still there — `vk logs \
             {name}` shows it, `kill {pid}` ends it"
        ),
    })
}

/// A dev environment's environment name, from its `dev.json`.
fn dev_environment(state_dir: &Path) -> Option<String> {
    dev_identity(state_dir).1
}

/// A dev environment's workspace and environment name, from its `dev.json`.
pub(crate) fn dev_identity(state_dir: &Path) -> (Option<PathBuf>, Option<String>) {
    let Some(identity) = std::fs::read(state_dir.join("dev.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<crate::dev::Identity>(&b).ok())
    else {
        return (None, None);
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

/// `vk list PID|DIR` when it names exactly one VM: every recorded fact about it as
/// `KEY  value` lines — what `--json` carries, laid out to read — then one line per compose
/// service (name, state, LAN address, exec address) and per published port. Nothing is
/// folded or left out here, so `--wide` has nothing to add. A field the run did not record
/// (an older `vk`, no `--ssh`, no `--net`) reads `-`; a service's state reads `-` when the
/// VM could not be asked, or did not report it.
///
/// `MEM USED` comes from `/proc` at report time; `MEM` is the recorded boot-time token.
/// The table combines them, but the detail record keeps them separate. Unreadable usage
/// reads `-`.
fn detail(
    e: &VmEntry,
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
    let mut rows: Vec<(&str, String)> = vec![
        ("NAME", e.label.clone()),
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
    ];
    if stale {
        rows.push(("STALE", freshness.cell().to_string()));
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

    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (key, value) in &rows {
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

/// Show a full record only when an explicit target matches exactly one VM.
/// A bare `vk list` keeps its table even for one VM, so its shape stays stable as VMs
/// come and go.
fn full_record(target: Option<&Selector>, matched: usize) -> bool {
    target.is_some() && matched == 1
}

/// A multi-line detail value: the lines joined, or `-` for none.
fn block(lines: &[String]) -> String {
    if lines.is_empty() {
        "-".to_string()
    } else {
        lines.join("\n")
    }
}

/// How `vk stop` goes about stopping a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StopHow {
    /// SIGTERM once, then wait for the timeout: the guest powers off cleanly
    #[default]
    Graceful,
    /// `--force`: SIGTERM once a second for [`FORCE_TERM_SECS`], then kill
    Force,
    /// `--kill`: kill right away — the VMM first, the run only if it does not follow
    Kill,
}

/// How long `--force` keeps asking with SIGTERM before it kills.
pub const FORCE_TERM_SECS: u64 = 5;

/// How long a stop waits after each kill: for the run to tear down once its VMM is killed,
/// and for a run it then had to kill itself to be gone.
pub const KILL_WAIT_SECS: u64 = 5;

impl StopHow {
    /// How long a stop of this kind may take, given `--timeout` (`None`: as long as it
    /// takes): what its `stopping` record carries as its deadline. A forced stop is bounded
    /// by its own steps, and by the timeout when that is shorter.
    pub fn budget_secs(self, timeout: Option<u64>) -> Option<u64> {
        // A kill is two waits: for the run to tear down once its VMM is gone, then for a
        // run that had to be killed itself.
        let own = match self {
            StopHow::Graceful => return timeout,
            StopHow::Force => FORCE_TERM_SECS + 2 * KILL_WAIT_SECS,
            StopHow::Kill => 2 * KILL_WAIT_SECS,
        };
        Some(timeout.map_or(own, |t| t.min(own)))
    }
}

/// Send `signal` to the run `entry` records — if its pid is still that process. A SIGKILL
/// must not land on a process the pid was handed to since: where the entry recorded its
/// start time, a pid started at another is left alone. The result of `kill` is dropped
/// because neither failure changes what to do: ESRCH means it went down in the meantime,
/// and EPERM that the pid is no longer the run we recorded — the wait that follows then
/// reports it as still standing, which is the truth either way.
fn signal_run(entry: &VmEntry, signal: libc::c_int) {
    let Ok(pid) = i32::try_from(entry.pid) else {
        return;
    };
    if entry
        .pid_start_ticks
        .is_some_and(|ticks| crate::usage::proc_starttime(pid) != Some(ticks))
    {
        return;
    }
    // SAFETY: kill with a signal number is always safe.
    unsafe { libc::kill(pid, signal) };
}

/// SIGKILL every VMM the run `entry` records has under it: its VM, its compose services'
/// and any build's, cut off as by a power cut. They are found among the run's descendants
/// by what they were launched with ([`crate::vmm::processes_under`]), not from the
/// registry, which records only the primary's. Each VM itself — the boot child — goes
/// before its keeper: a keeper killed first would leave its VM a power-button press, not a
/// kill. The run then sees its VMs gone and tears down what is left.
///
/// Nothing is sent when the pid is no longer that run (where the entry recorded its start
/// time to tell): [`stop_many`] then finds the run gone, or kills it after its wait.
fn kill_vmms(entry: &VmEntry) {
    let Ok(run) = i32::try_from(entry.pid) else {
        return;
    };
    if entry
        .pid_start_ticks
        .is_some_and(|ticks| crate::usage::proc_starttime(run) != Some(ticks))
    {
        return;
    }
    // Listed parents first, so killed in reverse.
    for vmm in crate::vmm::processes_under(run).into_iter().rev() {
        // SAFETY: kill with a signal number is always safe.
        unsafe { libc::kill(vmm, libc::SIGKILL) };
    }
}

/// Stop the runs managing `entries`, all at once, and wait for them to exit (their
/// state-dir locks free): every stop order goes out before the first wait, and `timeout`
/// — seconds, `None` for as long as it takes — bounds the whole of it, not each VM.
///
/// [`StopHow::Graceful`] sends SIGTERM once; [`StopHow::Force`] sends it once a second for
/// [`FORCE_TERM_SECS`] to those still there, then kills; [`StopHow::Kill`] kills at once.
/// A kill is SIGKILL to every VMM under the run ([`kill_vmms`]), [`KILL_WAIT_SECS`] for the run to tear
/// down by itself, and only then SIGKILL to a run still there, with as long again for it
/// to go. Each entry is pruned as its run goes. Returns,
/// per entry, whether it went down; one already dead counts as down. Managed publishers
/// are stopped first, on a short budget of their own.
///
/// A VM whose VMM is killed is not powered off: what its guest had not written is lost. A
/// run killed in turn cannot tidy after itself: its helpers, tied to it, go with it, and
/// its registry entry and state record are removed here. A run still
/// standing at the end keeps its `stopping` record, which `vk list` shows as overdue until
/// the run is gone or a stop succeeds — what to do about it is the user's call.
fn stop_many(entries: &[VmEntry], timeout: Option<u64>, how: StopHow) -> Vec<bool> {
    use std::time::{Duration, Instant};
    let down = |e: &VmEntry| {
        if let Ok(dir) = registry_dir() {
            remove_in(&dir, &e.state_dir);
        }
        crate::vmstate::clear(&e.state_dir);
    };
    // Publishers detect an already-gone VM on their next probe. A dead entry is not
    // signalled: it may only be stale.
    let mut went: Vec<bool> = entries.iter().map(|e| !alive(e)).collect();
    let pending = |went: &[bool]| -> Vec<&VmEntry> {
        entries
            .iter()
            .zip(went)
            .filter(|(_, gone)| !**gone)
            .map(|(e, _)| e)
            .collect()
    };
    for (e, _) in entries.iter().zip(&went).filter(|(_, gone)| **gone) {
        down(e);
    }
    // Stop publishers before their targets disappear and they retain unusable bound
    // addresses until the next probe. Give them at most five seconds each instead of the
    // stop's own timeout; publishers normally exit immediately on SIGTERM.
    let publishers = Duration::from_secs(timeout.map_or(5, |t| t.min(5)));
    for e in pending(&went) {
        crate::publish::stop_all_quietly(&e.state_dir, publishers);
    }
    let started = Instant::now();
    let overall = timeout.map(|t| started + Duration::from_secs(t));
    // Every order goes out before any wait. Each run is said to be stopping for as long as
    // this command waits on it: the record lapses by itself, at its deadline or when this
    // process is gone, should the wait be interrupted.
    for e in pending(&went) {
        crate::vmstate::stopping(
            &e.state_dir,
            e.pid,
            e.pid_start_ticks,
            how.budget_secs(timeout),
        );
        match how {
            StopHow::Kill => kill_vmms(e),
            StopHow::Graceful | StopHow::Force => signal_run(e, libc::SIGTERM),
        }
    }
    let mut terms = 1u64;
    // A kill goes to the VMMs first — the VM's, and its services' — found under the run:
    // with them gone the run tears the rest down itself — helpers, its registry entry. Only a run still there [`KILL_WAIT_SECS`]
    // later is killed in turn, which takes what is tied to it along.
    let mut vmm_killed_at = (how == StopHow::Kill).then_some(started);
    let mut run_killed_at = None;
    let kill_wait = Duration::from_secs(KILL_WAIT_SECS);
    loop {
        for (i, e) in entries.iter().enumerate() {
            if !went[i] && !alive(e) {
                down(e);
                went[i] = true;
            }
        }
        let now = Instant::now();
        if went.iter().all(|gone| *gone) || overall.is_some_and(|end| now >= end) {
            break;
        }
        match (how, vmm_killed_at, run_killed_at) {
            (StopHow::Graceful, ..) => {}
            (StopHow::Force, None, _) => {
                let elapsed = now.duration_since(started).as_secs();
                if elapsed >= FORCE_TERM_SECS {
                    pending(&went).into_iter().for_each(kill_vmms);
                    vmm_killed_at = Some(now);
                } else if elapsed >= terms {
                    // Asked again each second: a run busy in a build or a boot may only
                    // come to its signals between steps.
                    pending(&went)
                        .into_iter()
                        .for_each(|e| signal_run(e, libc::SIGTERM));
                    terms += 1;
                }
            }
            (_, Some(at), None) if now >= at + kill_wait => {
                pending(&went)
                    .into_iter()
                    .for_each(|e| signal_run(e, libc::SIGKILL));
                run_killed_at = Some(now);
            }
            (_, _, Some(at)) if now >= at + kill_wait => break,
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    went
}

/// Whether an empty selection succeeds. An explicit `vk stop TARGET` returns not-found (exit 1)
/// so scripts can distinguish "stopped it" from "there was nothing there". `--all` and the
/// current-directory default treat an empty selection as already done.
fn empty_selection_ok(explicit_target: bool) -> bool {
    !explicit_target
}

/// A VM reference, as every VM command takes it (see [`Ref::parse`]).
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
    /// Read a REF: all digits is a pid; `/…`, `./…`, `../…`, `~…`, `.` and `..` are paths;
    /// anything else is a name, `NAME/SERVICE` for a compose service — `PID/SERVICE` for one
    /// of a VM that has no name, as `vk list` prints it.
    ///
    /// Paths are kept as bytes so a non-UTF-8 directory still works. The digit check keeps
    /// `+5` from reading as a pid; digit strings past `u32` stay names (and fail as such).
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
            PathBuf::from(home).join(OsStr::from_bytes(&bytes[2..]))
        }
        _ => PathBuf::from(arg),
    }
}

/// Which running VMs a command means: a pid, a directory (exactly, or with `below` every VM
/// whose project is that directory or under it), or the state dir a name stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Pid(u32),
    Dir { dir: PathBuf, below: bool },
    Named { name: String, dir: PathBuf },
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

    /// Resolve a REF: a name through the name index, else a dev state dir's own name. A
    /// name wins over a directory of the same name here — a dev environment is named after
    /// its checkout, so from the directory above both exist — and `./word` is how to mean
    /// the directory. A bare word that names nothing but is a directory is read as that
    /// directory, with a note: the form `vk stop DIR` had before names.
    /// Returns the compose service a `NAME/SERVICE` names.
    pub fn from_ref(r: Ref, below: bool) -> Result<(Self, Option<String>)> {
        Self::from_ref_noting(r, below, true)
    }

    /// [`Selector::from_ref`], saying nothing about a bare word read as a directory: for a
    /// caller that resolves again a REF the user was already told about.
    pub fn from_ref_quietly(r: Ref, below: bool) -> Result<(Self, Option<String>)> {
        Self::from_ref_noting(r, below, false)
    }

    fn from_ref_noting(r: Ref, below: bool, note: bool) -> Result<(Self, Option<String>)> {
        match r {
            Ref::Pid(pid, service) => Ok((Selector::Pid(pid), service)),
            Ref::Path(dir) => Ok((Selector::Dir { dir, below }, None)),
            Ref::Name { vm, service } => {
                if let Some(dir) = crate::names::resolve(&vm)? {
                    return Ok((Selector::Named { name: vm, dir }, service));
                }
                let word = match &service {
                    Some(s) => format!("{vm}/{s}"),
                    None => vm.clone(),
                };
                if !Path::new(&word).is_dir() {
                    bail!("no VM is named {vm} (`vk list` names them)");
                }
                if note {
                    eprintln!(
                        "vk: note: reading {word} as a directory; write ./{word} — a bare \
                         word is a VM name"
                    );
                }
                Ok((
                    Selector::Dir {
                        dir: PathBuf::from(word),
                        below,
                    },
                    None,
                ))
            }
        }
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
            pid => pid,
        }
    }

    /// Whether this selector picks `entry`. The directory is already [`Selector::resolved`].
    fn matches(&self, entry: &VmEntry) -> bool {
        match self {
            Selector::Pid(pid) => entry.pid == *pid,
            Selector::Dir { dir, below } => matches_dir(entry, dir, *below),
            Selector::Named { dir, .. } => entry.state_dir == *dir,
        }
    }

    /// What to report when it picks nothing.
    fn not_found(&self) -> String {
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
    let matched = running().into_iter().filter(|e| sel.matches(e)).collect();
    Ok((sel, matched))
}

/// The one running VM a REF names (default: the current directory's), and the compose
/// service it names, merged with a `--service` given beside it. Errors when nothing runs
/// there, or when several VMs match a directory.
pub fn resolve_ref(
    target: Option<&OsStr>,
    service: Option<&str>,
) -> Result<(VmEntry, Option<String>)> {
    let (sel, named) = match target {
        Some(t) => {
            let (sel, named) = Selector::from_ref(Ref::parse(t)?, false)?;
            (Some(sel), named)
        }
        None => (None, None),
    };
    let service = match (named, service) {
        (Some(a), Some(b)) if a != b => {
            bail!("the target names the service {a} and --service names {b}: give one")
        }
        (a, b) => a.or(b.map(str::to_string)),
    };
    Ok((one_running(sel)?, service))
}

/// The one running VM `sel` selects (default: the current directory's). Errors when nothing
/// runs there, or when several VMs match a directory.
pub fn one_running(sel: Option<Selector>) -> Result<VmEntry> {
    let (sel, mut matched) = select_running(sel)?;
    match matched.len() {
        0 => bail!("{}", sel.not_found().trim_end()),
        1 => Ok(matched.pop().unwrap()),
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

/// How a VM is named in a message: its name, else its pid.
pub fn display_name(entry: &VmEntry) -> String {
    crate::names::Index::open()
        .ok()
        .and_then(|idx| idx.name_of(&entry.state_dir))
        .unwrap_or_else(|| format!("pid {}", entry.pid))
}

/// The VMs a stop/reboot command should act on: either a non-empty selection, or the summary
/// and exit status to report when nothing matched.
enum Selection {
    Matched(Vec<VmEntry>),
    Empty(String, bool),
}

/// Resolve `--all`, a pid or project directory, or the current directory (the default) into
/// the running VMs to act on. Shared by [`stop_cmd_how`] and [`reboot_cmd`].
fn select_vms(target: Option<Selector>, all: bool) -> Result<Selection> {
    let vms = running();
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
            Some(sel) => Selection::Empty(sel.not_found(), empty_selection_ok(true)),
            None => Selection::Empty(
                "no matching running vk VM\n".to_string(),
                empty_selection_ok(false),
            ),
        });
    }
    Ok(Selection::Matched(selected))
}

/// Stop VMs selected by `--all`, a pid or project directory, or the current directory by
/// default, as `how` says and all at once, `timeout` bounding the whole of it (`None`: as
/// long as it takes). Returns the summary and whether every selected VM went down.
pub fn stop_cmd_how(
    target: Option<Selector>,
    all: bool,
    timeout: Option<u64>,
    how: StopHow,
) -> Result<(String, bool)> {
    let selected = match select_vms(target, all)? {
        Selection::Matched(v) => v,
        Selection::Empty(out, ok) => return Ok((out, ok)),
    };
    Ok(stop_reports(&selected, timeout, how))
}

/// [`stop_many`] on `entries`, as its report: one line per VM, and whether every one went
/// down.
pub(crate) fn stop_reports(
    entries: &[VmEntry],
    timeout: Option<u64>,
    how: StopHow,
) -> (String, bool) {
    let waited = std::time::Instant::now();
    let went = stop_many(entries, timeout, how);
    let waited = waited.elapsed().as_secs();
    let mut out = String::new();
    for (e, down) in entries.iter().zip(&went) {
        out.push_str(&stop_line(e, *down, waited, how));
    }
    (out, went.iter().all(|down| *down))
}

/// What to say of the stop of `entry`: `down` is whether it went, `waited` how many seconds
/// the stop waited in all.
fn stop_line(entry: &VmEntry, down: bool, waited: u64, how: StopHow) -> String {
    if down {
        return format!("stopped {} (pid {})\n", entry.label, entry.pid);
    }
    let next = match how {
        StopHow::Graceful => " (`vk stop --force` insists, then kills)",
        StopHow::Force | StopHow::Kill => "",
    };
    format!(
        "{} (pid {}) did not stop after {waited}s{next}\n",
        entry.label, entry.pid
    )
}

/// Whether the state-dir lock of `entry` is held by a process other than its `vk run` — a
/// run that replaced it there. [`alive`] reads any holder of the lock as this VM, which is
/// right for `vk stop`, asked about a directory, but not for a caller that means this one
/// VM. A holder procfs cannot name (see [`crate::run::flock_holder`]) is taken to be its
/// own run, as `alive` takes it.
pub(crate) fn held_by_another(entry: &VmEntry) -> bool {
    std::fs::File::open(&entry.state_dir)
        .ok()
        .and_then(|f| crate::run::flock_holder_pid(&f))
        .is_some_and(|pid| u32::try_from(pid) != Ok(entry.pid))
}

/// Stop the VM `entry` records, and only it: `None`, with nothing stopped or signalled,
/// when [`held_by_another`]. Otherwise the report line, and whether it went down.
pub(crate) fn stop_entry(entry: &VmEntry, timeout: u64) -> Option<(String, bool)> {
    stop_entry_how(entry, Some(timeout), StopHow::Graceful)
}

/// [`stop_entry`], stopping the VM as `how` says.
pub(crate) fn stop_entry_how(
    entry: &VmEntry,
    timeout: Option<u64>,
    how: StopHow,
) -> Option<(String, bool)> {
    if held_by_another(entry) {
        return None;
    }
    Some(stop_reports(std::slice::from_ref(entry), timeout, how))
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
        let d = std::env::temp_dir().join(format!(
            "vk-vms-{}-{}-{}",
            tag,
            std::process::id(),
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
        // Only the uptime moves with the clock; every other line is fixed by the entry.
        let expected = format!(
            "\
NAME          app
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
STALE         yes
SERVICES      db     running  10.0.0.3  vsock-auto:///state/app/svc-db/vsock.sock:4444
              redis  stopped  10.0.0.4  vsock-auto:///state/app/svc-redis/vsock.sock:4444
PUBLISHED     pg  127.0.0.1:5432->127.0.0.1:5432@db  pid 4242
",
            up = uptime(e.created_secs)
        );
        assert_eq!(
            detail(
                &e,
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
NAME          devcontainer
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
        // Without --stale the STALE row is absent entirely, not reported as unknown.
        assert_eq!(
            detail(&plain, None, &[], Freshness::Unknown, false, None),
            expected
        );
    }

    #[test]
    fn detail_reads_the_other_side_of_every_recorded_fact() {
        let mut e = compose_entry();
        e.nested = Some(false);
        // A VMM the run named but whose pid it did not record prints bare.
        e.vmm = Some("libkrun".into());
        let text = detail(&e, None, &[], Freshness::Fresh, true, None);
        assert!(text.contains("\nVMM           libkrun\n"), "{text}");
        assert!(text.contains("\nNESTED        no\n"), "{text}");
        assert!(text.contains("\nSTALE         no\n"), "{text}");
    }

    #[test]
    fn detail_dashes_a_service_the_vm_did_not_report_but_keeps_its_exec_address() {
        // The VM answered and knows of neither service, so only the recorded facts remain.
        let text = detail(
            &compose_entry(),
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
        assert!(text.contains("\nSTALE         -\n"), "{text}");
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

    #[test]
    fn a_full_record_needs_a_target_and_exactly_one_match() {
        let sel = Selector::Pid(41877);
        assert!(full_record(Some(&sel), 1));
        // A bare `vk list` keeps its table, so a one-VM host does not change shape.
        assert!(!full_record(None, 1));
        assert!(!full_record(Some(&sel), 0));
        assert!(!full_record(Some(&sel), 2));
    }

    /// A compose VM with one running service and a plain VM, as `--field` sees them.
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
        // Nothing running: nothing printed, whatever was asked.
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

        // Malformed paths and repeats are rejected up front, even with nothing running.
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
}
