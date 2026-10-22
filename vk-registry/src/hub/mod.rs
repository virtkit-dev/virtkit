//! A registry managed by a `vk-hub`: `vk-registry join` enrolls it with a single-use token,
//! and `serve` then holds a session with the hub — inventory, heartbeats, store usage and
//! reports one way, desired state and commands the other — for as long as it runs, redialing
//! when the session is lost. See `docs/registry-hub.md`.
//!
//! The registry's mode, database, keys and UI are not touched: it serves exactly as it would
//! without a hub, reachable or not. The hub may only do what `[hub] allow` lists — make the
//! registry read-only, schedule or run gc, update it — and anything else it asks is refused
//! and reported as refused.
//!
//! Everything kept for the hub is under `<root>/hub/`, a `0700` directory: `key.pk8` (the
//! registry's private key), `enrollment.json` (the hub's URL and the registry's ID), `ca.pem`
//! (the CA the hub is verified against, when `join` was given one), `state.json` (what the
//! hub asked, and the command journal) and `releases/` (an update's release, and the binary
//! it replaces). `vk-registry leave` deletes it.

mod session;
mod state;
mod update;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use vk_hub_proto::registry::{
    ALLOW_GC, ALLOW_READ_ONLY, Command, DesiredState, GcPolicy, GcRun, Heartbeat, Inventory,
    Operation, Report, Usage,
};
use vk_hub_proto::{CommandAck, EnrollRequest, Outcome};
use vk_peer::identity::Identity;

use crate::ServerState;
use crate::config::HubSettings;
pub use state::Persisted;
pub use update::{Start, on_start};

const ENROLLMENT_FILE: &str = "enrollment.json";
const CA_FILE: &str = "ca.pem";

/// How often a registry not enrolled looks for an enrollment `join` made meanwhile, and a
/// scheduled gc checks whether it is due.
const POLL: Duration = Duration::from_secs(60);

/// How often the store is counted again for the hub.
const USAGE_EVERY: Duration = Duration::from_secs(600);

/// `<root>/hub`.
pub fn dir(root: &Path) -> PathBuf {
    root.join("hub")
}

/// What `join` leaves for `serve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub hub: String,
    pub registry_id: String,
    /// Whether the hub is verified against `ca.pem` alone rather than the system's roots.
    #[serde(default)]
    pub ca: bool,
}

/// `vk-registry join`: generate the registry's key under `<root>/hub/` and enroll it with
/// `hub` using `token`. Refused on a registry already enrolled unless `replace`, which
/// enrolls it anew, the old enrollment moved aside, and put back if the new one fails.
/// Returns the registry's ID.
pub async fn join(
    root: &Path,
    hub: &str,
    token: &vk_peer::net::TokenSource,
    ca: Option<&Path>,
    replace: bool,
) -> Result<String> {
    let hub = vk_peer::net::normalize_hub_url(hub)?;
    let dir = dir(root);
    let existing = read_enrollment(&dir).ok();
    if let Some(existing) = &existing
        && !replace
    {
        bail!(
            "this registry is already enrolled with {} as {}: `vk-registry leave` first, \
             or pass --replace",
            existing.hub,
            existing.registry_id
        );
    }
    if token.on_command_line() {
        eprintln!(
            "vk-registry: warning: a token on the command line is visible to every local user \
             in the process list; prefer `--token -` or --token-file"
        );
    }
    let token = token.read()?;
    let ca_pem = match ca {
        Some(path) => {
            let pem = vk_peer::net::read_nofollow(path)?;
            vk_peer::net::roots_from_pem(&pem, path)?;
            Some(pem)
        }
        None => None,
    };
    let aside = match existing {
        Some(_) => Some(move_aside(&dir)?),
        None => None,
    };
    let enrolled = enroll(&dir, &hub, token, ca_pem.as_deref()).await;
    match (enrolled, aside) {
        (Ok(id), Some(aside)) => {
            eprintln!(
                "vk-registry: the previous enrollment is kept in {}",
                aside.display()
            );
            Ok(id)
        }
        (Err(e), Some(aside)) => {
            if let Err(e) = std::fs::remove_dir_all(&dir)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("vk-registry: removing {}: {e}", dir.display());
            }
            std::fs::rename(&aside, &dir).with_context(|| {
                format!(
                    "{e:#}; and putting the previous enrollment back from {}",
                    aside.display()
                )
            })?;
            Err(e)
        }
        (enrolled, None) => enrolled,
    }
}

/// Move the enrollment in `dir` to a sibling of its own, `hub.replaced-<time>`, and return
/// where.
fn move_aside(dir: &Path) -> Result<PathBuf> {
    let stem = format!("hub.replaced-{}", vk_peer::now_secs());
    // A rename onto an empty directory would replace it, hence a name found free.
    let aside = (0..)
        .map(|n| match n {
            0 => dir.with_file_name(&stem),
            n => dir.with_file_name(format!("{stem}.{n}")),
        })
        .find(|p| std::fs::symlink_metadata(p).is_err())
        .context("no free name to move the enrollment aside to")?;
    std::fs::rename(dir, &aside)
        .with_context(|| format!("moving {} aside to {}", dir.display(), aside.display()))?;
    Ok(aside)
}

/// Enroll a new key under `dir` with `hub`, and write the enrollment there.
async fn enroll(dir: &Path, hub: &str, token: String, ca_pem: Option<&[u8]>) -> Result<String> {
    vk_peer::net::create_dir(dir)?;
    let identity = Identity::load_or_create(dir)?;
    let ask = EnrollRequest {
        signature: identity.sign(&vk_hub_proto::enroll_message(&token, identity.public_key())),
        public_key: vk_hub_proto::to_hex(identity.public_key()),
        token,
        hostname: hostname(),
    };
    let answer: vk_hub_proto::registry::EnrollResponse =
        vk_peer::net::enroll(hub, vk_hub_proto::registry::ENROLL_PATH, ca_pem, &ask).await?;
    if !vk_hub_proto::valid_id(&answer.registry_id) {
        bail!(
            "the hub assigned a malformed registry ID {:?}",
            vk_hub_proto::display_safe(&answer.registry_id)
        );
    }
    if let Some(pem) = ca_pem {
        vk_fs::write_atomic(&dir.join(CA_FILE), pem, 0o600).context("keeping the CA")?;
    }
    let enrollment = Enrollment {
        hub: hub.to_string(),
        registry_id: answer.registry_id.clone(),
        ca: ca_pem.is_some(),
    };
    let json = serde_json::to_vec_pretty(&enrollment).context("encoding the enrollment")?;
    vk_fs::write_atomic(&dir.join(ENROLLMENT_FILE), &json, 0o600)
        .context("writing the enrollment")?;
    Ok(answer.registry_id)
}

/// `vk-registry leave`: forget the hub. Whether there was an enrollment to forget.
pub fn leave(root: &Path) -> Result<bool> {
    let dir = dir(root);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", dir.display())),
    }
}

/// `enrollment.json`, checked as `join` writes it.
pub fn read_enrollment(dir: &Path) -> Result<Enrollment> {
    let path = dir.join(ENROLLMENT_FILE);
    let bytes = vk_peer::net::read_nofollow(&path)?;
    let mut e: Enrollment =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    e.hub = vk_peer::net::normalize_hub_url(&e.hub)?;
    if !vk_hub_proto::valid_id(&e.registry_id) {
        bail!("{} holds a malformed registry ID", path.display());
    }
    Ok(e)
}

/// The host's name, as the hub lists the registry.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}

/// What a serving registry is, from its config: for its inventory and its steering.
#[derive(Clone, Debug)]
pub struct Facts {
    pub listen: String,
    pub tls: bool,
    pub mode: &'static str,
    pub webdav: bool,
    pub upstreams: Vec<String>,
    pub max_connections: usize,
    pub settings: HubSettings,
    pub config_hash: String,
}

/// A registry's link to its hub while it serves.
pub(crate) struct Link {
    dir: PathBuf,
    enrollment: Enrollment,
    identity: Identity,
    tls: Arc<rustls::ClientConfig>,
    incarnation: String,
    ctx: Facts,
    state: Arc<ServerState>,
    persisted: Mutex<Persisted>,
    /// Woken when the report changed.
    changed: Notify,
    policy: vk_peer::release_key::Policy,
    usage: Mutex<Option<Usage>>,
    /// Held while a gc runs, and by an update from recording its trial to its exec, so the
    /// registry never executes a release in the middle of a gc.
    gc_running: tokio::sync::Mutex<()>,
}

/// Hold the hub link for as long as `serve` runs: wait for an enrollment if there is none,
/// then apply what the hub last asked and keep a session with it.
pub fn start(state: Arc<ServerState>, ctx: Facts) {
    restore_read_only(&dir(&state.store.root), &state, &ctx.settings);
    tokio::spawn(async move {
        let root = state.store.root.clone();
        let dir = dir(&root);
        let mut waiting_said = false;
        let link = loop {
            match open(&dir, &state, &ctx) {
                Ok(Some(link)) => break Arc::new(link),
                Ok(None) => {}
                Err(e) => {
                    if !waiting_said {
                        eprintln!("vk-registry: hub: {e:#}");
                        waiting_said = true;
                    }
                }
            }
            tokio::time::sleep(POLL).await;
        };
        eprintln!(
            "vk-registry: hub: managed by {} as registry {}",
            link.enrollment.hub, link.enrollment.registry_id
        );
        // Read once, before the first inventory names the binary by it.
        let _ = tokio::task::spawn_blocking(vk_peer::update::own_sha256).await;
        tokio::spawn(scheduled_gc(link.clone()));
        tokio::spawn(count_usage(link.clone()));
        session::hold(link).await;
    });
}

/// Make the registry read-only again if the hub last asked so, before `serve` takes a
/// connection, whether or not its link to the hub opens.
fn restore_read_only(dir: &Path, state: &ServerState, settings: &HubSettings) {
    let (Ok(enrollment), Ok(p)) = (read_enrollment(dir), Persisted::load(dir)) else {
        return;
    };
    let asked = p.issuer == Some((enrollment.hub, enrollment.registry_id))
        && p.applied.is_some_and(|d| d.read_only == Some(true));
    if asked && settings.allows(ALLOW_READ_ONLY) {
        eprintln!("vk-registry: hub: read-only, as the hub asked");
        state.store.set_read_only(true);
    }
}

/// The link for an enrolled registry, with what the hub last asked applied; `None` when it
/// is not enrolled.
fn open(dir: &Path, state: &Arc<ServerState>, ctx: &Facts) -> Result<Option<Link>> {
    let enrollment = match read_enrollment(dir) {
        Ok(e) => e,
        Err(e) if vk_peer::net::is_not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    vk_peer::net::check_private(dir)?;
    let identity = Identity::load(dir)?;
    let tls = vk_peer::net::client_tls(enrollment.ca.then(|| dir.join(CA_FILE)).as_deref())?;
    let mut incarnation = [0u8; vk_hub_proto::ID_BYTES];
    vk_peer::fill_random(&mut incarnation)?;
    let mut persisted = Persisted::load(dir)?;
    persisted.adopt_issuer(&enrollment.hub, &enrollment.registry_id);
    let mut changed = persisted.fail_interrupted();
    if let Ok(exe) = std::env::current_exe()
        && let Some(installed) = update::installed_after(persisted.installed.as_deref(), exe, dir)
    {
        persisted.installed = Some(installed);
        changed = true;
    }
    if changed {
        persisted.save(dir)?;
    }
    let policy = ctx.settings.release_policy()?;
    let link = Link {
        dir: dir.to_path_buf(),
        enrollment,
        identity,
        tls,
        incarnation: vk_hub_proto::to_hex(&incarnation),
        ctx: ctx.clone(),
        state: state.clone(),
        persisted: Mutex::new(persisted),
        changed: Notify::new(),
        policy,
        usage: Mutex::new(None),
        gc_running: tokio::sync::Mutex::new(()),
    };
    // What the hub asked before a restart holds until it asks otherwise.
    let applied = link.persisted().applied.clone();
    if let Some(d) = applied {
        link.apply_effects(&d);
    }
    Ok(Some(link))
}

impl Link {
    fn persisted(&self) -> std::sync::MutexGuard<'_, Persisted> {
        self.persisted.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Change the persisted state with `f`, save it, and wake the session to report. Nothing
    /// changes, in memory or on disk, when the save fails.
    fn update<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> Result<R> {
        let out = {
            let mut p = self.persisted();
            let mut next = p.clone();
            let out = f(&mut next);
            next.save(&self.dir)?;
            *p = next;
            out
        };
        self.changed.notify_one();
        Ok(out)
    }

    fn allows(&self, what: &str) -> bool {
        self.ctx.settings.allows(what)
    }

    /// The gc schedule in effect: the hub's, when its config lets it set one.
    fn gc_policy(&self) -> Option<GcPolicy> {
        self.persisted()
            .applied
            .as_ref()
            .and_then(|d| self.taken_gc(d))
    }

    /// The gc schedule `desired` sets, when `[hub] allow` lists gc and the schedule is
    /// within the config's floors.
    fn taken_gc(&self, desired: &DesiredState) -> Option<GcPolicy> {
        desired
            .gc
            .filter(|p| self.allows(ALLOW_GC) && self.ctx.settings.check_gc_policy(p).is_ok())
    }

    /// Make `desired`'s effects real, within what `[hub] allow` lets the hub set.
    fn apply_effects(&self, desired: &DesiredState) {
        if let Some(policy) = &desired.gc
            && self.allows(ALLOW_GC)
            && let Err(why) = self.ctx.settings.check_gc_policy(policy)
        {
            eprintln!("vk-registry: hub: gc schedule refused: {why}");
        }
        let read_only = self.allows(ALLOW_READ_ONLY) && desired.read_only == Some(true);
        if read_only != self.state.store.read_only() {
            eprintln!(
                "vk-registry: hub: {}",
                if read_only {
                    "read-only, as the hub asked"
                } else {
                    "taking writes again"
                }
            );
        }
        self.state.store.set_read_only(read_only);
    }

    /// Apply desired state the hub sent, if newer than what was applied.
    fn apply_desired(&self, desired: DesiredState) -> Result<()> {
        let newer = self
            .persisted()
            .applied
            .as_ref()
            .is_none_or(|a| a.generation < desired.generation);
        if !newer {
            return Ok(());
        }
        // Kept first, so what takes effect is what a restart applies again.
        self.update(|p| p.applied = Some(desired.clone()))?;
        self.apply_effects(&desired);
        Ok(())
    }

    /// What the registry reports.
    fn report(&self) -> Report {
        let p = self.persisted();
        let mut refused = Vec::new();
        if let Some(d) = &p.applied {
            if d.read_only == Some(true) && !self.allows(ALLOW_READ_ONLY) {
                refused.push(ALLOW_READ_ONLY.to_string());
            }
            if d.gc.is_some() && self.taken_gc(d).is_none() {
                refused.push(ALLOW_GC.to_string());
            }
        }
        Report {
            applied: p.applied.as_ref().map(|d| d.generation),
            read_only: self.state.store.read_only(),
            gc: p.applied.as_ref().and_then(|d| self.taken_gc(d)),
            last_gc: p.last_gc.clone(),
            update: p.update.clone(),
            refused,
        }
    }

    /// Take `command`: answer one journaled already with its outcome, refuse an expired one
    /// or one `[hub] allow` does not list, a gc below the config's floors, and start the
    /// others. The ack to send now.
    fn command(self: &Arc<Self>, command: Command) -> Result<CommandAck> {
        if let Some(entry) = self.persisted().entry(&command.id) {
            return Ok(CommandAck {
                id: entry.id.clone(),
                outcome: entry.outcome.clone(),
            });
        }
        let now = vk_peer::now_secs();
        let outcome = if command.expires_at <= now {
            Outcome::Expired
        } else if !self.allows(command.op.allowed_by()) {
            Outcome::Refused {
                reason: format!(
                    "this registry's [hub] allow does not list {}",
                    command.op.allowed_by()
                ),
            }
        } else {
            match &command.op {
                Operation::Gc {
                    retention_days,
                    grace_days,
                    ..
                } => match self.ctx.settings.check_gc(*retention_days, *grace_days) {
                    Ok(()) => Outcome::Accepted,
                    Err(reason) => Outcome::Refused { reason },
                },
                Operation::Update { .. } => match update::accept(self, &command) {
                    Ok(outcome) => outcome,
                    Err(reason) => Outcome::Refused { reason },
                },
            }
        };
        let (id, op) = (command.id.clone(), command.op.clone());
        self.update(|p| p.journal(&id, op.clone(), command.expires_at, outcome.clone()))?;
        if outcome == Outcome::Accepted {
            match op {
                Operation::Gc {
                    retention_days,
                    grace_days,
                    dry_run,
                } => {
                    let (link, id) = (self.clone(), id.clone());
                    tokio::spawn(async move {
                        let run = link
                            .gc(Some(id.clone()), retention_days, grace_days, dry_run)
                            .await;
                        let outcome = match &run.error {
                            None => Outcome::Done,
                            Some(e) => Outcome::Failed { message: e.clone() },
                        };
                        if let Err(e) = link.update(|p| {
                            p.last_gc = Some(run);
                            p.set_outcome(&id, outcome);
                        }) {
                            eprintln!("vk-registry: hub: {e:#}");
                        }
                    });
                }
                Operation::Update { .. } => update::spawn(self.clone(), command),
            }
        }
        Ok(CommandAck { id, outcome })
    }

    /// Run gc on the store, as `vk-registry gc` does, for `command` or the schedule, and
    /// refresh the usage.
    async fn gc(
        &self,
        command: Option<String>,
        retention_days: u64,
        grace_days: u64,
        dry_run: bool,
    ) -> GcRun {
        let _running = self.gc_running.lock().await;
        let store = self.state.store.clone();
        let at = vk_peer::now_secs();
        eprintln!(
            "vk-registry: hub: gc{} (retention {retention_days} days, grace {grace_days})",
            if dry_run { " dry run" } else { "" }
        );
        let report = tokio::task::spawn_blocking(move || {
            store.gc(
                Duration::from_secs(retention_days.saturating_mul(86_400)),
                Duration::from_secs(grace_days.saturating_mul(86_400)),
                dry_run,
            )
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r);
        let run = match report {
            Ok(r) => GcRun {
                command,
                at,
                dry_run,
                tags_dropped: r.tags_dropped as u64,
                manifests_dropped: r.manifests_dropped as u64,
                blobs_dropped: r.blobs_dropped as u64,
                bytes_freed: r.bytes_freed,
                uploads_dropped: r.uploads_dropped as u64,
                blobs_leased: r.blobs_leased as u64,
                error: None,
            },
            Err(e) => GcRun {
                command,
                at,
                dry_run,
                error: Some(format!("{e:#}")),
                ..GcRun::default()
            },
        };
        self.refresh_usage().await;
        run
    }

    /// Count the store again, as `vk-registry status` does.
    async fn refresh_usage(&self) {
        let store = self.state.store.clone();
        match tokio::task::spawn_blocking(move || store.stats()).await {
            Ok(Ok(stats)) => {
                *self.usage.lock().unwrap_or_else(|e| e.into_inner()) = Some(usage_of(&stats));
                self.changed.notify_one();
            }
            Ok(Err(e)) => eprintln!("vk-registry: hub: counting the store: {e:#}"),
            Err(e) => eprintln!("vk-registry: hub: counting the store: {e}"),
        }
    }

    fn usage(&self) -> Option<Usage> {
        self.usage.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn inventory(&self) -> Inventory {
        Inventory {
            hostname: hostname(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            sha256: vk_peer::update::known_sha256(),
            listen: self.ctx.listen.clone(),
            tls: self.ctx.tls,
            mode: self.ctx.mode.to_string(),
            webdav: self.ctx.webdav,
            upstreams: self.ctx.upstreams.clone(),
            store: self.state.store.root.display().to_string(),
            store_size_bytes: store_space(&self.state.store.root).0,
            config_hash: self.ctx.config_hash.clone(),
            allow: self.ctx.settings.allow.clone(),
            requires_signed: self.policy.required(),
        }
    }

    fn heartbeat(&self) -> Heartbeat {
        let uploads = std::fs::read_dir(self.state.store.root.join("uploads"))
            .map(|d| {
                d.flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                    .count()
            })
            .unwrap_or(0);
        Heartbeat {
            connections: u32::try_from(self.state.store.connections()).unwrap_or(u32::MAX),
            max_connections: u32::try_from(self.ctx.max_connections).unwrap_or(u32::MAX),
            uploads: u32::try_from(uploads).unwrap_or(u32::MAX),
            locks: u32::try_from(self.state.locks.held_count()).unwrap_or(u32::MAX),
            store_free_bytes: store_space(&self.state.store.root).1,
        }
    }
}

/// The store's filesystem's size and free space, in bytes; zeros when it cannot be read.
fn store_space(root: &Path) -> (u64, u64) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(root.as_os_str().as_bytes()) else {
        return (0, 0);
    };
    // SAFETY: `path` is NUL-terminated and outlives the call; `st` is a zeroed out-struct
    // statvfs fills.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return (0, 0);
    }
    let frsize = st.f_frsize as u64;
    (
        (st.f_blocks as u64).saturating_mul(frsize),
        (st.f_bavail as u64).saturating_mul(frsize),
    )
}

fn usage_of(s: &crate::StoreStats) -> Usage {
    let mut repos: Vec<_> = s
        .repos
        .iter()
        .map(|r| vk_hub_proto::registry::RepoUsage {
            name: r.name.clone(),
            tags: r.tags as u64,
            bytes: r.logical_bytes,
        })
        .collect();
    repos.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    repos.truncate(vk_hub_proto::registry::MAX_REPOS);
    Usage {
        at: vk_peer::now_secs(),
        blobs: (s.identity_blobs + s.zstd_blobs) as u64,
        stored_bytes: s.identity_bytes + s.zstd_bytes,
        referenced_bytes: s.referenced_ondisk,
        tags: s.total_tags as u64,
        manifests: s.total_manifests as u64,
        repos,
    }
}

/// Run gc on the schedule the hub set, as long as `serve` runs.
async fn scheduled_gc(link: Arc<Link>) {
    loop {
        tokio::time::sleep(POLL).await;
        let Some(policy) = link.gc_policy() else {
            continue;
        };
        let now = vk_peer::now_secs();
        let due = link
            .persisted()
            .scheduled_gc_at
            .is_none_or(|at| now.saturating_sub(at) >= policy.every_secs);
        if !due {
            continue;
        }
        let run = link
            .gc(None, policy.retention_days, policy.grace_days, false)
            .await;
        if let Err(e) = link.update(|p| {
            p.scheduled_gc_at = Some(now);
            p.last_gc = Some(run);
        }) {
            eprintln!("vk-registry: hub: {e:#}");
        }
    }
}

/// Count the store for the hub every [`USAGE_EVERY`], as long as `serve` runs; the session
/// sends each count when it is ready.
async fn count_usage(link: Arc<Link>) {
    loop {
        link.refresh_usage().await;
        tokio::time::sleep(USAGE_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh store `tag`, enrolled with a hub it never reaches.
    fn enrolled(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("vk-registry-link-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = dir(&root);
        vk_peer::net::create_dir(&dir).unwrap();
        Identity::load_or_create(&dir).unwrap();
        let enrollment = Enrollment {
            hub: "https://hub.invalid".into(),
            registry_id: "0".repeat(32),
            ca: false,
        };
        std::fs::write(
            dir.join(ENROLLMENT_FILE),
            serde_json::to_vec(&enrollment).unwrap(),
        )
        .unwrap();
        root
    }

    /// The link `serve` opens on `root`, configured with `settings`.
    /// The state `serve` builds over the store at `root`.
    fn server_state(root: &Path) -> Arc<ServerState> {
        Arc::new(ServerState {
            store: Arc::new(crate::Store::new(root.to_path_buf()).unwrap()),
            upstreams: Vec::new(),
            locks: crate::lock::LockManager::new(),
            auth: crate::Authenticator::Shared(crate::auth::Auth::None),
            tls: None,
            webdav: false,
        })
    }

    fn open_link(root: &Path, settings: HubSettings) -> Arc<Link> {
        let state = server_state(root);
        let facts = Facts {
            listen: "127.0.0.1:5000".into(),
            tls: false,
            mode: "shared-secret",
            webdav: false,
            upstreams: Vec::new(),
            max_connections: 1,
            settings,
            config_hash: String::new(),
        };
        Arc::new(open(&dir(root), &state, &facts).unwrap().unwrap())
    }

    fn link(tag: &str, settings: HubSettings) -> Arc<Link> {
        open_link(&enrolled(tag), settings)
    }

    fn allowing_gc() -> HubSettings {
        HubSettings {
            allow: vec![ALLOW_GC.into()],
            ..HubSettings::default()
        }
    }

    fn schedule(every_secs: u64, retention_days: u64, grace_days: u64) -> DesiredState {
        DesiredState {
            generation: every_secs + retention_days + grace_days,
            read_only: None,
            gc: Some(GcPolicy {
                every_secs,
                retention_days,
                grace_days,
            }),
        }
    }

    #[test]
    fn a_gc_schedule_below_the_floors_is_refused_and_reported() {
        let link = link("schedule", allowing_gc());
        for refused in [
            schedule(0, 30, 1),
            schedule(3600, 6, 1),
            schedule(3600, 7, 0),
        ] {
            link.apply_desired(refused).unwrap();
            let report = link.report();
            assert_eq!(report.gc, None);
            assert_eq!(report.refused, vec![ALLOW_GC.to_string()]);
            assert_eq!(link.gc_policy(), None);
        }
        let taken = schedule(3600, 7, 1);
        link.apply_desired(taken.clone()).unwrap();
        let report = link.report();
        assert_eq!(report.gc, taken.gc);
        assert!(report.refused.is_empty());
        assert_eq!(link.gc_policy(), taken.gc);
    }

    #[tokio::test]
    async fn a_gc_command_below_the_floors_is_refused() {
        let settings = HubSettings {
            min_retention_days: 30,
            min_grace_days: 2,
            ..allowing_gc()
        };
        let link = link("command", settings);
        let gc = |id: &str, retention_days, grace_days| Command {
            id: id.into(),
            expires_at: u64::MAX,
            op: Operation::Gc {
                retention_days,
                grace_days,
                dry_run: true,
            },
        };
        for (id, retention, grace, floor) in [
            ("a", 29, 2, "min_retention_days = 30"),
            ("b", 30, 1, "min_grace_days = 2"),
        ] {
            let ack = link.command(gc(id, retention, grace)).unwrap();
            let Outcome::Refused { reason } = ack.outcome else {
                panic!("{id}: {:?}", ack.outcome);
            };
            assert!(reason.contains(floor), "{reason}");
        }
        let ack = link.command(gc("c", 30, 2)).unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
    }

    fn gc_command(id: &str, retention_days: u64) -> Command {
        Command {
            id: id.into(),
            expires_at: u64::MAX,
            op: Operation::Gc {
                retention_days,
                grace_days: 1,
                dry_run: true,
            },
        }
    }

    #[tokio::test]
    async fn a_restart_keeps_what_the_hub_asked_and_answers_from_the_journal() {
        let settings = HubSettings {
            allow: vec![ALLOW_READ_ONLY.into(), ALLOW_GC.into()],
            ..HubSettings::default()
        };
        let root = enrolled("restart");
        let first = open_link(&root, settings.clone());
        first
            .apply_desired(DesiredState {
                generation: 1,
                read_only: Some(true),
                gc: None,
            })
            .unwrap();
        assert!(first.state.store.read_only());
        let refused = first.command(gc_command("r", 1)).unwrap();
        assert!(matches!(refused.outcome, Outcome::Refused { .. }));
        // Accepted, then cut short by the restart.
        first
            .update(|p| p.journal("cut", gc_command("cut", 30).op, u64::MAX, Outcome::Accepted))
            .unwrap();
        drop(first);

        let again = open_link(&root, settings);
        // What an update replaces: the binary serve runs from, outside the hub directory.
        assert_eq!(again.persisted().installed, std::env::current_exe().ok());
        assert!(again.state.store.read_only());
        assert_eq!(again.report().applied, Some(1));
        // Redelivered after a reconnect: answered from the journal, not run again.
        assert_eq!(again.command(gc_command("r", 30)).unwrap(), refused);
        let cut = again.command(gc_command("cut", 30)).unwrap();
        assert!(matches!(cut.outcome, Outcome::Failed { .. }), "{cut:?}");
    }

    #[test]
    fn only_asking_for_read_only_is_refused_when_not_allowed() {
        let link = link("read-only", HubSettings::default());
        let read_only = |generation, read_only| DesiredState {
            generation,
            read_only: Some(read_only),
            gc: None,
        };
        link.apply_desired(read_only(1, false)).unwrap();
        assert!(link.report().refused.is_empty());
        link.apply_desired(read_only(2, true)).unwrap();
        assert_eq!(link.report().refused, vec![ALLOW_READ_ONLY.to_string()]);
        assert!(!link.state.store.read_only());
    }

    #[test]
    fn a_second_update_waits_for_the_first() {
        let settings = HubSettings {
            allow: vec![vk_hub_proto::registry::ALLOW_UPDATE.into()],
            ..HubSettings::default()
        };
        let link = link("second-update", settings);
        let update = |id: &str| Command {
            id: id.into(),
            expires_at: u64::MAX,
            op: Operation::Update {
                version: "9.9.9".into(),
                sha256: "0".repeat(64),
                size: 1,
                signature: None,
            },
        };
        link.update(|p| p.journal("u", update("u").op, u64::MAX, Outcome::Accepted))
            .unwrap();
        let ack = link.command(update("v")).unwrap();
        let Outcome::Refused { reason } = ack.outcome else {
            panic!("{:?}", ack.outcome);
        };
        assert!(reason.contains("under way"), "{reason}");
    }

    #[tokio::test]
    async fn a_failed_replace_puts_the_old_enrollment_back() {
        // As `main` does, for the enrollment's client.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = enrolled("replace");
        let dir = dir(&root);
        let key = std::fs::read(vk_peer::identity::key_path(&dir)).unwrap();
        let token = vk_peer::net::TokenSource::Literal("t".into());
        assert!(
            join(&root, "http://127.0.0.1:1", &token, None, true)
                .await
                .is_err()
        );
        assert_eq!(read_enrollment(&dir).unwrap().registry_id, "0".repeat(32));
        assert_eq!(
            std::fs::read(vk_peer::identity::key_path(&dir)).unwrap(),
            key
        );
        let names: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| n.starts_with("hub.replaced")),
            "{names:?}"
        );
        // Without --replace, nothing is touched at all.
        assert!(
            join(&root, "http://127.0.0.1:1", &token, None, false)
                .await
                .is_err()
        );
        assert_eq!(read_enrollment(&dir).unwrap().registry_id, "0".repeat(32));
    }

    #[test]
    fn read_only_holds_across_a_restart_before_the_hub_is_reached() {
        let settings = HubSettings {
            allow: vec![ALLOW_READ_ONLY.into()],
            ..HubSettings::default()
        };
        let root = enrolled("read-only-restart");
        open_link(&root, settings.clone())
            .apply_desired(DesiredState {
                generation: 1,
                read_only: Some(true),
                gc: None,
            })
            .unwrap();
        let state = server_state(&root);
        restore_read_only(&dir(&root), &state, &HubSettings::default());
        assert!(!state.store.read_only(), "its config no longer allows it");
        restore_read_only(&dir(&root), &state, &settings);
        assert!(state.store.read_only());
    }

    #[test]
    fn a_failed_save_changes_nothing() {
        // SAFETY: reads the effective user ID and touches no memory.
        if unsafe { libc::geteuid() } == 0 {
            return; // root writes whatever the mode says
        }
        use std::os::unix::fs::PermissionsExt;
        let settings = HubSettings {
            allow: vec![ALLOW_READ_ONLY.into(), ALLOW_GC.into()],
            ..HubSettings::default()
        };
        let link = link("unsaved", settings);
        let mode = |m| std::fs::set_permissions(&link.dir, std::fs::Permissions::from_mode(m));
        mode(0o500).unwrap();
        assert!(link.command(gc_command("g", 30)).is_err());
        let desired = DesiredState {
            generation: 1,
            read_only: Some(true),
            gc: None,
        };
        assert!(link.apply_desired(desired).is_err());
        mode(0o700).unwrap();
        let p = link.persisted();
        assert!(p.entry("g").is_none());
        assert!(p.applied.is_none());
        assert!(!link.state.store.read_only());
    }

    #[test]
    fn an_update_that_could_not_exec_leaves_no_trial() {
        let link = link("unexecuted", HubSettings::default());
        let command = Command {
            id: "u".into(),
            expires_at: u64::MAX,
            op: Operation::Update {
                version: "9.9.9".into(),
                sha256: "0".repeat(64),
                size: 1,
                signature: None,
            },
        };
        let releases = link.dir.join("releases");
        std::fs::create_dir_all(&releases).unwrap();
        for release in ["0", "1"] {
            std::fs::write(releases.join(release.repeat(64)), b"r").unwrap();
        }
        link.update(|p| {
            p.journal("u", command.op.clone(), u64::MAX, Outcome::Accepted);
            p.trial = Some(state::Trial {
                command: "u".into(),
                version: "9.9.9".into(),
                sha256: "0".repeat(64),
                exe: link.dir.join("exe"),
                exe_id: (0, 0),
                next: releases.join("0".repeat(64)),
                previous: "1".repeat(64),
                attempts: 1,
                deadline: u64::MAX,
            });
        })
        .unwrap();
        update::failed(&link, &command, "exec failed").unwrap();
        let p = Persisted::load(&link.dir).unwrap();
        assert!(p.trial.is_none());
        assert!(matches!(
            p.entry("u").unwrap().outcome,
            Outcome::Failed { .. }
        ));
        assert_eq!(p.update.unwrap().phase, vk_hub_proto::UpdatePhase::Failed);
        let kept: Vec<_> = std::fs::read_dir(&releases)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(kept, vec![std::ffi::OsString::from("1".repeat(64))]);
    }
}
