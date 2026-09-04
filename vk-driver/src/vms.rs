//! Host-side registry of running vk VMs.
//!
//! A `vk run --state-dir DIR` records an entry after spawning its VMM and removes it on exit.
//! `vk list` discovers running VMs from these entries, and `vk stop` selects one by directory or
//! displayed pid without searching the process table. Only pinned (`--state-dir`) runs are
//! tracked: they expose a stable exec socket for external tooling and hold an advisory `flock`
//! on the state dir as a pid-reuse-proof liveness signal. Ephemeral runs have a temporary state
//! dir and no attachable socket, so they are deliberately not recorded.
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
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use vk_core::fleetctl::{Frame, Request, UnitStatus};

/// One running VM's record. Serialized as `<slug(state_dir)>.json` in the registry dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmEntry {
    /// The run's `--state-dir`, canonicalized — the VM's identity and the file's key.
    pub state_dir: PathBuf,
    /// The directory `vk run` was invoked from (canonicalized), i.e. the project this VM
    /// belongs to. `vk list DIR` / `vk stop DIR` match on this. `None` if it was unavailable.
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
    /// The VMM backend hosting the guest: `libkrun` or `cloud-hypervisor`. This and the
    /// fields down to `guest_ip` are boot-time facts `vk run` files; each is `None` on an
    /// entry recorded before the field existed.
    #[serde(default)]
    pub vmm: Option<String>,
    /// The pid to inspect or signal when the managing `vk run` itself is unresponsive: the
    /// libkrun boot subprocess (with `--reboot`, the keeper that relaunches the guest in
    /// place, so the pid is stable across reboots) or the external `cloud-hypervisor` process.
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
    // Serialized against a correction to the same entry (see `WRITES`); taken here rather than
    // in `record_in`, which the correction calls while already holding it.
    let _writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
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

/// The public shape of a VM in `vk list --json`: the user-facing fields plus a computed
/// `uptime_secs` and (with `--stale`) `stale`. Deliberately omits the internal `stale_recipe`,
/// so the JSON stays a stable contract for scripts. Fields an older `vk run` did not record
/// serialize as `null`.
#[derive(Serialize)]
struct VmView<'a> {
    state_dir: &'a Path,
    project_dir: Option<&'a Path>,
    pid: u32,
    vmm: Option<&'a str>,
    vmm_pid: Option<u32>,
    label: &'a str,
    exec_addr: &'a str,
    ssh_addr: Option<&'a str>,
    guest_ip: Option<std::net::Ipv4Addr>,
    cpus: Option<u32>,
    mem: Option<&'a str>,
    nested: Option<bool>,
    atop_log: Option<&'a Path>,
    created_secs: u64,
    uptime_secs: u64,
    /// A double option so `--stale` is self-describing: the outer `None` (no `--stale`) omits
    /// the field, while `Some(None)` — freshness requested but unknown — serializes as an
    /// explicit `null`, distinct from a known `true`/`false`. Reflects the VM *and* its services.
    #[serde(skip_serializing_if = "Option::is_none")]
    stale: Option<Option<bool>>,
    /// Every declared compose service (empty for a non-compose VM), each with its state.
    services: Vec<ServiceView<'a>>,
    /// The ports `vk publish ensure` holds open on the host for this VM.
    published: Vec<PublishedView<'a>>,
}

/// A managed publisher's record and whether it was shown to be running.
type Published = (crate::publish::Entry, crate::publish::Liveness);

/// One managed publisher (`<state dir>/publish/<name>.json`) as `vk list --json` shows it.
#[derive(Serialize)]
struct PublishedView<'a> {
    name: &'a str,
    /// The host address it accepts connections on.
    listen: &'a str,
    /// The address the guest dials for each connection.
    to: &'a str,
    /// The compose sibling that dials, or `null` for the primary.
    service: Option<&'a str>,
    pid: u32,
    /// `false` when its lock could not be tested (see `vk publish list`), so the pid is not
    /// to be trusted.
    confirmed: bool,
}

#[derive(Serialize)]
struct ServiceView<'a> {
    name: &'a str,
    exec_addr: &'a str,
    /// `"running"` or `"stopped"`. `null` when the VM could not be asked (the text view then
    /// names every declared service) or when its reply omits the declared name (the text view
    /// then leaves it out).
    state: Option<&'a str>,
    /// The service's address on the run's LAN, without the prefix length; `null` whenever
    /// `state` is.
    ip: Option<&'a str>,
}

fn view<'a>(
    entry: &'a VmEntry,
    units: Option<&'a [UnitStatus]>,
    published: &'a [Published],
    freshness: Freshness,
    stale: bool,
) -> VmView<'a> {
    VmView {
        state_dir: &entry.state_dir,
        project_dir: entry.project_dir.as_deref(),
        pid: entry.pid,
        vmm: entry.vmm.as_deref(),
        vmm_pid: entry.vmm_pid,
        label: &entry.label,
        exec_addr: &entry.exec_addr,
        ssh_addr: entry.ssh_addr.as_deref(),
        guest_ip: entry.guest_ip,
        cpus: entry.cpus,
        mem: entry.mem.as_deref(),
        nested: entry.nested,
        atop_log: entry.atop_log.as_deref(),
        created_secs: entry.created_secs,
        uptime_secs: unix_now().saturating_sub(entry.created_secs),
        stale: if stale { Some(freshness.json()) } else { None },
        services: entry
            .services
            .iter()
            .map(|service| {
                let unit = find_unit(units, &service.name);
                ServiceView {
                    name: &service.name,
                    exec_addr: &service.exec_addr,
                    state: unit.map(|u| u.state.as_str()),
                    ip: unit.map(|u| bare_ip(&u.ip)),
                }
            })
            .collect(),
        published: published
            .iter()
            .map(|(e, liveness)| PublishedView {
                name: &e.name,
                listen: &e.listen,
                to: &e.to,
                service: e.service.as_deref(),
                pid: e.pid,
                confirmed: *liveness == crate::publish::Liveness::Held,
            })
            .collect(),
    }
}

/// The reported status of the declared service `name`, if the VM answered and listed it.
fn find_unit<'a>(units: Option<&'a [UnitStatus]>, name: &str) -> Option<&'a UnitStatus> {
    units?.iter().find(|u| u.name == name)
}

/// The service manager reports addresses as `ip/prefix`; the view shows only the address.
fn bare_ip(ip: &str) -> &str {
    ip.split_once('/').map_or(ip, |(addr, _)| addr)
}

/// Whether the text view names `name`: when the VM reports it running, or when the VM could
/// not be asked (`units` is `None`) and the declared set is all there is.
fn named_in_text(units: Option<&[UnitStatus]>, name: &str) -> bool {
    units.is_none() || find_unit(units, name).is_some_and(|u| u.state == "running")
}

/// Ask the run's service manager for every unit's status, or `None` if it cannot be reached
/// or refuses (callers then fall back to the registry's declared set).
fn service_units(entry: &VmEntry) -> Option<Vec<UnitStatus>> {
    if entry.services.is_empty() {
        return None;
    }
    let path = match vk_core::addr::SocketAddr::from_str(&entry.exec_addr) {
        Ok(vk_core::addr::SocketAddr::VsockAuto { path, .. }) => path,
        _ => return None,
    };
    let ctl = vk_core::net::hybrid_socket(&path, vk_core::fleetctl::CONTROL_PORT);
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

/// The PUBLISHED column: each publisher as `listen->to`, `@service` appended when a compose
/// sibling dials, comma-separated; `-` when nothing is published. `tcp://` is dropped from
/// both ends since it is the common case; any other scheme stays spelled out. A publisher
/// whose lock could not be tested is marked `(unconfirmed)`, as `vk publish list` marks it.
fn published_cell(published: &[Published]) -> String {
    if published.is_empty() {
        return "-".to_string();
    }
    published
        .iter()
        .map(|(e, liveness)| {
            let mut cell = format!("{}->{}", bare_tcp(&e.listen), bare_tcp(&e.to));
            if let Some(service) = &e.service {
                cell.push('@');
                cell.push_str(service);
            }
            if *liveness == crate::publish::Liveness::Unknown {
                cell.push_str(" (unconfirmed)");
            }
            cell
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn bare_tcp(addr: &str) -> &str {
    addr.strip_prefix("tcp://").unwrap_or(addr)
}

/// Query with `Request::List`, ignoring progress frames until `Done`; an error reply is an
/// `Err`. Two-second I/O timeouts keep `vk list` from blocking on a wedged VMM.
fn query_units(ctl: &Path) -> Result<Vec<UnitStatus>> {
    use std::io::{BufRead, BufReader};
    let timeout = Some(Duration::from_secs(2));
    let mut stream =
        UnixStream::connect(ctl).with_context(|| format!("control: connect {}", ctl.display()))?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    let mut req = serde_json::to_string(&Request::List).context("encoding List request")?;
    req.push('\n');
    stream.write_all(req.as_bytes())?;
    let mut rd = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        if rd.read_line(&mut line)? == 0 {
            bail!("control peer closed before Done");
        }
        match serde_json::from_str::<Frame>(line.trim_end()).context("decoding control frame")? {
            Frame::Progress(_) => continue,
            Frame::Done(reply) => {
                if !reply.ok {
                    bail!("service manager refused: {}", reply.message);
                }
                return Ok(reply.units);
            }
        }
    }
}

fn display_name(entry: &VmEntry, units: Option<&[UnitStatus]>) -> String {
    let services: Vec<&str> = entry
        .services
        .iter()
        .map(|service| service.name.as_str())
        .filter(|name| named_in_text(units, name))
        .collect();
    if services.is_empty() {
        entry.label.clone()
    } else {
        format!("{} (+{})", entry.label, services.join(", "))
    }
}

/// Reject `--field` paths that no view could satisfy, before any VM is asked: an empty
/// segment (`guest_ip.`), a segment with a JSON-pointer metacharacter (`/`, `~`), or a path
/// given twice (the `--json` object could hold it only once, and the text would silently
/// disagree). Unknown names are checked per view by `select`.
fn check_fields(fields: &[String]) -> Result<()> {
    for path in fields {
        if path.split('.').any(str::is_empty) {
            bail!("--field {path}: empty path segment");
        }
        if path.contains(['/', '~']) {
            bail!("--field {path}: no such field ('/' and '~' never occur in a field name)");
        }
    }
    let mut seen = HashSet::new();
    if let Some(dup) = fields.iter().find(|f| !seen.insert(f.as_str())) {
        bail!("--field {dup}: given twice");
    }
    Ok(())
}

/// One `--field` of a VM view. `path` is dotted (`guest_ip`, `services.0.ip`) and resolved as
/// a JSON pointer, so a missing branch below the first segment is `null` (a non-compose VM has
/// no `services.0`). An unknown first segment is an error naming the fields there are.
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
        bail!("--field {path}: no field {head:?}{hint}; the fields are: {known}");
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

/// `vk list`: the running VMs (optionally only those under `filter`) as a table, or JSON. With
/// `stale`, each VM's freshness is computed (network I/O — see `freshness_all`) and shown.
/// With `fields`, only those fields of each VM (see `fields_report`).
pub fn list_report(
    filter: Option<&Path>,
    json: bool,
    stale: bool,
    fields: &[String],
) -> Result<String> {
    check_fields(fields)?;
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
    let units_by_vm: Vec<Option<Vec<UnitStatus>>> = vms.iter().map(service_units).collect();
    let published_by_vm: Vec<Vec<Published>> = vms.iter().map(published).collect();

    if json || !fields.is_empty() {
        let views: Vec<VmView> = vms
            .iter()
            .zip(&units_by_vm)
            .zip(&published_by_vm)
            .zip(&fresh)
            .map(|(((entry, units), published), freshness)| {
                view(entry, units.as_deref(), published, *freshness, stale)
            })
            .collect();
        if !fields.is_empty() {
            let views = views
                .iter()
                .map(|v| serde_json::to_value(v).context("serializing VM view"))
                .collect::<Result<Vec<_>>>()?;
            return fields_report(&views, fields, json);
        }
        return Ok(serde_json::to_string_pretty(&views).context("serializing VM list")? + "\n");
    }
    if vms.is_empty() {
        return Ok("no running vk VMs\n".to_string());
    }
    // Columns: the STALE column is only added with `--stale`.
    let mut headers: Vec<&str> = vec![
        "PID",
        "UPTIME",
        "NAME",
        "PROJECT",
        "EXEC ADDRESS",
        "PUBLISHED",
    ];
    if stale {
        headers.push("STALE");
    }
    let rows: Vec<Vec<String>> = vms
        .iter()
        .zip(&units_by_vm)
        .zip(&published_by_vm)
        .zip(&fresh)
        .map(|(((e, units), published), f)| {
            let mut row = vec![
                e.pid.to_string(),
                uptime(e.created_secs),
                display_name(e, units.as_deref()),
                e.project_dir
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".to_string()),
                e.exec_addr.clone(),
                published_cell(published),
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
/// A no-op success if already dead. Stop managed publishers first on a separate short
/// budget.
fn stop_one(entry: &VmEntry, timeout: u64) -> bool {
    if !alive(entry) {
        // Publishers detect an already-gone VM on their next probe. Do not signal here
        // because the entry may only be stale.
        if let Ok(dir) = registry_dir() {
            remove_in(&dir, &entry.state_dir);
        }
        return true;
    }
    // Stop publishers before their target disappears and they retain unusable bound
    // addresses until the next probe. Give them at most five seconds each instead of the
    // per-VM `--timeout`; publishers normally exit immediately on SIGTERM.
    crate::publish::stop_all_quietly(
        &entry.state_dir,
        std::time::Duration::from_secs(timeout.min(5)),
    );
    // The result is dropped because neither failure changes what to do: ESRCH means it went
    // down between the check above and here, and EPERM means the pid is no longer the run we
    // recorded — the wait below then reports it as still standing, which is the truth either
    // way. The state-dir lock was just held, so that window is a handful of instructions.
    // SAFETY: kill with a signal number is always safe.
    unsafe { libc::kill(entry.pid as i32, libc::SIGTERM) };
    for _ in 0..timeout.saturating_mul(2) {
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

/// Whether an empty selection succeeds. An explicit `vk stop TARGET` returns not-found (exit 1)
/// so scripts can distinguish "stopped it" from "there was nothing there". `--all` and the
/// current-directory default treat an empty selection as already done.
fn empty_selection_ok(explicit_target: bool) -> bool {
    !explicit_target
}

/// A `vk stop TARGET`: either the pid shown by `vk list` or a launch directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Pid(u32),
    Dir(PathBuf),
}

impl Selector {
    /// An all-digit argument that fits `u32` is a pid; anything else is a directory. Prefix a
    /// digit-only directory such as `123` with `./`.
    ///
    /// Parse paths as bytes so non-UTF-8 names remain valid. The digit check prevents
    /// `u32::from_str` from treating `+5` as a pid; digit strings larger than `u32` also remain
    /// paths.
    pub fn parse(arg: &OsStr) -> Result<Self> {
        if arg.is_empty() {
            bail!("no VM named — pass a pid, a launch directory, or --all");
        }
        if arg.as_bytes().iter().all(u8::is_ascii_digit)
            && let Some(pid) = arg.to_str().and_then(|s| s.parse::<u32>().ok())
        {
            return Ok(Selector::Pid(pid));
        }
        Ok(Selector::Dir(PathBuf::from(arg)))
    }

    /// Resolve a directory once so every entry is matched against the same path.
    fn resolved(self) -> Self {
        match self {
            Selector::Dir(dir) => Selector::Dir(canonical(&dir)),
            pid => pid,
        }
    }

    /// Whether this selector picks `entry`. The directory is already [`Selector::resolved`].
    fn matches(&self, entry: &VmEntry) -> bool {
        match self {
            Selector::Pid(pid) => entry.pid == *pid,
            Selector::Dir(dir) => matches_dir(entry, dir),
        }
    }

    /// What to report when it picks nothing.
    fn not_found(&self) -> String {
        match self {
            Selector::Pid(pid) => format!("no running vk VM with pid {pid}\n"),
            Selector::Dir(dir) => format!("no running vk VM under {}\n", dir.display()),
        }
    }
}

/// The VMs a stop/reboot command should act on: either a non-empty selection, or the summary
/// and exit status to report when nothing matched.
enum Selection {
    Matched(Vec<VmEntry>),
    Empty(String, bool),
}

/// Resolve `--all`, a pid or launch directory, or the current directory (the default) into the
/// running VMs to act on. Shared by [`stop_cmd`] and [`reboot_cmd`].
fn select_vms(target: Option<Selector>, all: bool) -> Result<Selection> {
    let vms = running();
    let target = target.map(Selector::resolved);
    let selected: Vec<VmEntry> = match (all, &target) {
        (true, _) => vms,
        (false, Some(sel)) => vms.into_iter().filter(|e| sel.matches(e)).collect(),
        (false, None) => {
            let cwd = std::env::current_dir().context("resolving the current directory")?;
            vms.into_iter().filter(|e| matches_dir(e, &cwd)).collect()
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

/// Stop VMs selected by `--all`, a pid or launch directory, or the current directory by default.
/// Returns the summary and whether every selected VM went down.
pub fn stop_cmd(target: Option<Selector>, all: bool, timeout: u64) -> Result<(String, bool)> {
    let selected = match select_vms(target, all)? {
        Selection::Matched(v) => v,
        Selection::Empty(out, ok) => return Ok((out, ok)),
    };
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

/// Reboot VMs selected by `--all`, a pid or launch directory, or the current directory by
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

#[cfg(test)]
mod tests {
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

    fn entry(state_dir: PathBuf, project: Option<PathBuf>) -> VmEntry {
        VmEntry {
            state_dir,
            project_dir: project,
            pid: std::process::id(),
            label: "devcontainer".into(),
            exec_addr: "vsock-auto:///tmp/x/vsock.sock:4444".into(),
            ssh_addr: None,
            atop_log: None,
            created_secs: unix_now(),
            vmm: None,
            vmm_pid: None,
            cpus: None,
            mem: None,
            nested: None,
            guest_ip: None,
            stale_recipe: None,
            services: Vec::new(),
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
    fn empty_stop_is_success_only_without_an_explicit_target() {
        // `vk stop` / `vk stop --all` with nothing running: success (nothing to do).
        assert!(empty_selection_ok(false));
        // `vk stop PID|DIR` naming a target that isn't running: not-found (exit 1).
        assert!(!empty_selection_ok(true));
    }

    fn parse(arg: &str) -> Selector {
        Selector::parse(OsStr::new(arg)).unwrap()
    }

    #[test]
    fn a_stop_target_parses_digits_as_a_pid() {
        // Digits that fit u32 select the pid shown by `vk list`; `./` makes a digit-only name a
        // directory.
        assert_eq!(parse("2144802"), Selector::Pid(2144802));
        assert_eq!(parse("007"), Selector::Pid(7));
        assert_eq!(
            parse("/home/vince/repo"),
            Selector::Dir(PathBuf::from("/home/vince/repo"))
        );
        assert_eq!(parse("./123"), Selector::Dir(PathBuf::from("./123")));
        // A signed number and a value past u32 remain directories.
        assert_eq!(parse("+5"), Selector::Dir(PathBuf::from("+5")));
        assert_eq!(
            parse("99999999999"),
            Selector::Dir(PathBuf::from("99999999999"))
        );
        // A non-UTF-8 path still names a VM and cannot be mistaken for a pid.
        let raw = OsStr::from_bytes(b"/tmp/\xff");
        assert_eq!(
            Selector::parse(raw).unwrap(),
            Selector::Dir(PathBuf::from(raw))
        );
        // Refuse an empty argument because `Path::starts_with("")` accepts every path.
        assert!(Selector::parse(OsStr::new("")).is_err());
    }

    #[test]
    fn a_stop_target_selects_by_pid_or_by_directory() {
        let e = entry(
            PathBuf::from("/state/vm1"),
            Some(PathBuf::from("/home/vince/repo")),
        );
        assert!(Selector::Pid(e.pid).matches(&e));
        assert!(!Selector::Pid(e.pid.wrapping_add(1)).matches(&e));
        // Directory selection matches `vk list DIR`: the project, its ancestor, or the state
        // directory.
        assert!(Selector::Dir(PathBuf::from("/home/vince")).matches(&e));
        assert!(Selector::Dir(PathBuf::from("/state/vm1")).matches(&e));
        assert!(!Selector::Dir(PathBuf::from("/home/other")).matches(&e));
        // A pid selector never falls back to the directory that spells it; use `./123` for the
        // directory.
        let digits = entry(PathBuf::from("/state/vm2"), Some(PathBuf::from("/123")));
        assert!(!Selector::Pid(123).matches(&digits));
        assert!(Selector::Dir(PathBuf::from("/123")).matches(&digits));
        // Each says what it looked for when it finds nothing.
        assert_eq!(
            Selector::Pid(4242).not_found(),
            "no running vk VM with pid 4242\n"
        );
        assert_eq!(
            Selector::Dir(PathBuf::from("/home/other")).not_found(),
            "no running vk VM under /home/other\n"
        );
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

    fn service_json(name: &str, state: Option<&str>, ip: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "exec_addr": format!("vsock-auto:///state/app/svc-{name}/vsock.sock:4444"),
            "state": state,
            "ip": ip,
        })
    }

    fn services_json(e: &VmEntry, units: Option<&[UnitStatus]>) -> serde_json::Value {
        serde_json::to_value(view(e, units, &[], Freshness::Unknown, false)).unwrap()["services"]
            .take()
    }

    #[test]
    fn list_view_falls_back_to_every_declared_service_when_unqueried() {
        let e = compose_entry();
        // No answer from the VM: the text view names every recorded service and the JSON
        // carries an explicit null state and ip for each.
        assert_eq!(display_name(&e, None), "app (+db, redis)");
        assert_eq!(
            services_json(&e, None),
            serde_json::json!([
                service_json("db", None, None),
                service_json("redis", None, None)
            ])
        );
    }

    #[test]
    fn text_view_names_only_running_services() {
        let e = compose_entry();
        let units = [
            unit("db", "running", "10.0.0.2/24"),
            unit("redis", "stopped", "10.0.0.3/24"),
        ];
        assert_eq!(display_name(&e, Some(&units)), "app (+db)");
        assert_eq!(display_name(&e, Some(&[])), "app");
    }

    #[test]
    fn json_view_lists_every_declared_service_with_state_and_bare_ip() {
        let e = compose_entry();
        let units = [
            unit("db", "running", "10.0.0.2/24"),
            unit("redis", "stopped", "10.0.0.3/24"),
        ];
        assert_eq!(
            services_json(&e, Some(&units)),
            serde_json::json!([
                service_json("db", Some("running"), Some("10.0.0.2")),
                service_json("redis", Some("stopped"), Some("10.0.0.3")),
            ])
        );
    }

    #[test]
    fn service_missing_from_the_reply_is_null_in_json_and_unnamed_in_text() {
        let e = compose_entry();
        // The VM answered but knows nothing of `redis` (registry/manager drift).
        let units = [unit("db", "running", "10.0.0.2/24")];
        assert_eq!(display_name(&e, Some(&units)), "app (+db)");
        assert_eq!(
            services_json(&e, Some(&units)),
            serde_json::json!([
                service_json("db", Some("running"), Some("10.0.0.2")),
                service_json("redis", None, None),
            ])
        );
    }

    /// A compose VM with one running service and a plain VM, as `--field` sees them.
    fn field_views() -> Vec<serde_json::Value> {
        let mut e = compose_entry();
        e.pid = 4242;
        e.nested = Some(true);
        let units = [unit("db", "running", "10.0.0.2/24")];
        let mut plain = entry(PathBuf::from("/state/plain"), None);
        plain.label = "plain".into();
        plain.pid = 7;
        vec![
            serde_json::to_value(view(&e, Some(&units), &[], Freshness::Unknown, false)).unwrap(),
            serde_json::to_value(view(&plain, None, &[], Freshness::Unknown, false)).unwrap(),
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
        assert!(err.contains("guest_ip, label"), "{err}");
        let err = fields(&views, &["stale"], false).unwrap_err().to_string();
        assert!(err.contains("(pass --stale)"), "{err}");
        let plain = entry(PathBuf::from("/state/plain"), None);
        let with_stale =
            [serde_json::to_value(view(&plain, None, &[], Freshness::Unknown, true)).unwrap()];
        assert_eq!(fields(&with_stale, &["stale"], false).unwrap(), "null\n");

        // Malformed paths and repeats are rejected up front, even with nothing running.
        let check = |names: &[&str]| {
            let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            check_fields(&names).unwrap_err().to_string()
        };
        assert!(check(&["guest_ip."]).contains("empty path segment"));
        assert!(check(&["services.0/ip"]).contains("no such field"));
        assert!(check(&["pid", "label", "pid"]).contains("--field pid: given twice"));
        check_fields(&["pid".to_string(), "services.0.ip".to_string()]).unwrap();
    }

    #[test]
    fn bare_ip_strips_the_prefix_length() {
        assert_eq!(bare_ip("10.0.0.2/24"), "10.0.0.2");
        assert_eq!(bare_ip("10.0.0.2"), "10.0.0.2");
    }

    /// Bind a control socket that answers the first request line with `frames`, in order.
    /// `None` closes the connection without answering.
    fn serve_frames(
        tag: &str,
        frames: Option<Vec<Frame>>,
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
            let (stream, _) = listener.accept().unwrap();
            let Some(frames) = frames else { return };
            let mut rd = BufReader::new(stream.try_clone().unwrap());
            let mut req = String::new();
            rd.read_line(&mut req).unwrap();
            let mut w = stream;
            for frame in frames {
                let mut line = serde_json::to_string(&frame).unwrap();
                line.push('\n');
                w.write_all(line.as_bytes()).unwrap();
            }
        });
        (sock, server)
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

    #[test]
    fn published_cell_maps_listen_to_target_and_marks_the_dialing_service_and_unconfirmed() {
        assert_eq!(published_cell(&[]), "-");
        let published = [
            (
                publisher("web", "tcp://127.0.0.1:8443", "tcp://runner:443", None),
                Liveness::Held,
            ),
            (
                publisher("db", "/tmp/pg.sock", "tcp://127.0.0.1:5432", Some("db")),
                Liveness::Unknown,
            ),
        ];
        assert_eq!(
            published_cell(&published),
            "127.0.0.1:8443->runner:443, /tmp/pg.sock->127.0.0.1:5432@db (unconfirmed)"
        );
    }

    #[test]
    fn json_view_lists_publishers_with_service_and_confirmation() {
        let e = entry(PathBuf::from("/state/app"), None);
        let published = [
            (
                publisher("web", "tcp://127.0.0.1:8443", "tcp://runner:443", None),
                Liveness::Held,
            ),
            (
                publisher(
                    "db",
                    "tcp://127.0.0.1:5432",
                    "tcp://127.0.0.1:5432",
                    Some("db"),
                ),
                Liveness::Unknown,
            ),
        ];
        let json =
            serde_json::to_value(view(&e, None, &published, Freshness::Unknown, false)).unwrap();
        assert_eq!(
            json["published"],
            serde_json::json!([
                {
                    "name": "web",
                    "listen": "tcp://127.0.0.1:8443",
                    "to": "tcp://runner:443",
                    "service": null,
                    "pid": 4242,
                    "confirmed": true,
                },
                {
                    "name": "db",
                    "listen": "tcp://127.0.0.1:5432",
                    "to": "tcp://127.0.0.1:5432",
                    "service": "db",
                    "pid": 4242,
                    "confirmed": false,
                },
            ])
        );
        // Nothing published is an empty array, not an absent key, so `--field` into it reads
        // null rather than failing.
        let none = serde_json::to_value(view(&e, None, &[], Freshness::Unknown, false)).unwrap();
        assert_eq!(none["published"], serde_json::json!([]));
        assert_eq!(
            fields(&[json, none], &["published.0.listen"], false).unwrap(),
            "tcp://127.0.0.1:8443\nnull\n"
        );
    }

    #[test]
    fn list_view_reports_boot_time_fields() {
        let mut e = entry(PathBuf::from("/state/app"), None);
        e.vmm = Some("libkrun".into());
        e.vmm_pid = Some(4242);
        e.cpus = Some(4);
        e.mem = Some("8G".into());
        e.nested = Some(true);
        e.guest_ip = Some(std::net::Ipv4Addr::new(10, 42, 0, 2));
        let json = serde_json::to_value(view(&e, None, &[], Freshness::Unknown, false)).unwrap();
        assert_eq!(json["vmm"], "libkrun");
        assert_eq!(json["vmm_pid"], 4242);
        assert_eq!(json["cpus"], 4);
        assert_eq!(json["mem"], "8G");
        assert_eq!(json["nested"], true);
        assert_eq!(json["guest_ip"], "10.42.0.2");

        // A run without `--net` has no address: an explicit null, not an absent key, so
        // scripts can tell it from a field this `vk` never emitted.
        let e = entry(PathBuf::from("/state/app"), None);
        let json = serde_json::to_value(view(&e, None, &[], Freshness::Unknown, false)).unwrap();
        assert_eq!(json.get("guest_ip"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn json_stale_field_distinguishes_absent_unknown_and_known() {
        let dir = PathBuf::from("/state/x");
        let view = |stale: Option<Option<bool>>| VmView {
            state_dir: &dir,
            project_dir: None,
            pid: 1,
            vmm: None,
            vmm_pid: None,
            label: "x",
            exec_addr: "a",
            ssh_addr: None,
            guest_ip: None,
            cpus: None,
            mem: None,
            nested: None,
            atop_log: None,
            created_secs: 0,
            uptime_secs: 0,
            stale,
            services: vec![],
            published: vec![],
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
        let json = serde_json::to_value(view(&e, None, &[], Freshness::Unknown, false)).unwrap();
        for key in [
            "atop_log", "vmm", "vmm_pid", "cpus", "mem", "nested", "guest_ip",
        ] {
            assert_eq!(json.get(key), Some(&serde_json::Value::Null), "{key}");
        }
    }

    #[test]
    fn list_view_reports_the_atop_log_path() {
        let mut e = entry(PathBuf::from("/state/app"), None);
        e.atop_log = Some(PathBuf::from("/state/app/atop/atop.log"));
        let json = serde_json::to_value(view(&e, None, &[], Freshness::Unknown, false)).unwrap();
        assert_eq!(json["atop_log"], "/state/app/atop/atop.log");
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
