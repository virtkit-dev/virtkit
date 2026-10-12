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
/// enrolls it anew. Returns the registry's ID.
pub async fn join(
    root: &Path,
    hub: &str,
    token: &vk_peer::net::TokenSource,
    ca: Option<&Path>,
    replace: bool,
) -> Result<String> {
    let hub = vk_peer::net::normalize_hub_url(hub)?;
    let dir = dir(root);
    if let Ok(existing) = read_enrollment(&dir) {
        if !replace {
            bail!(
                "this registry is already enrolled with {} as {}: `vk-registry leave` first, \
                 or pass --replace",
                existing.hub,
                existing.registry_id
            );
        }
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
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
    vk_peer::net::create_dir(&dir)?;
    let identity = Identity::load_or_create(&dir)?;
    let ask = EnrollRequest {
        signature: identity.sign(&vk_hub_proto::enroll_message(&token, identity.public_key())),
        public_key: vk_hub_proto::to_hex(identity.public_key()),
        token,
        hostname: hostname(),
    };
    let answer: vk_hub_proto::registry::EnrollResponse = vk_peer::net::enroll(
        &hub,
        vk_hub_proto::registry::ENROLL_PATH,
        ca_pem.as_deref(),
        &ask,
    )
    .await?;
    if !vk_hub_proto::valid_id(&answer.registry_id) {
        bail!(
            "the hub assigned a malformed registry ID {:?}",
            vk_hub_proto::display_safe(&answer.registry_id)
        );
    }
    if let Some(pem) = &ca_pem {
        vk_fs::write_atomic(&dir.join(CA_FILE), pem, 0o600).context("keeping the CA")?;
    }
    let enrollment = Enrollment {
        hub,
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
}

/// Hold the hub link for as long as `serve` runs: wait for an enrollment if there is none,
/// then apply what the hub last asked and keep a session with it.
pub fn start(state: Arc<ServerState>, ctx: Facts) {
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
        session::hold(link).await;
    });
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
    let policy = vk_peer::release_key::Policy::from_config_in(
        "[hub]",
        &ctx.settings.release_keys,
        ctx.settings.require_signed,
    )?;
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

    /// Change the persisted state with `f`, save it, and wake the session to report.
    fn update<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> Result<R> {
        let out = {
            let mut p = self.persisted();
            let out = f(&mut p);
            p.save(&self.dir)?;
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
            .and_then(|d| d.gc)
            .filter(|_| self.allows(ALLOW_GC))
    }

    /// Make `desired`'s effects real, within what `[hub] allow` lets the hub set.
    fn apply_effects(&self, desired: &DesiredState) {
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
        self.apply_effects(&desired);
        self.update(|p| p.applied = Some(desired))
    }

    /// What the registry reports.
    fn report(&self) -> Report {
        let p = self.persisted();
        let mut refused = Vec::new();
        if let Some(d) = &p.applied {
            if d.read_only.is_some() && !self.allows(ALLOW_READ_ONLY) {
                refused.push(ALLOW_READ_ONLY.to_string());
            }
            if d.gc.is_some() && !self.allows(ALLOW_GC) {
                refused.push(ALLOW_GC.to_string());
            }
        }
        Report {
            applied: p.applied.as_ref().map(|d| d.generation),
            read_only: self.state.store.read_only(),
            gc: p
                .applied
                .as_ref()
                .and_then(|d| d.gc)
                .filter(|_| self.allows(ALLOW_GC)),
            last_gc: p.last_gc.clone(),
            update: p.update.clone(),
            refused,
        }
    }

    /// Take `command`: answer one journaled already with its outcome, refuse an expired one
    /// or one `[hub] allow` does not list, and start the others. The ack to send now.
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
                Operation::Gc { .. } => Outcome::Accepted,
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
                        let run = link.gc(retention_days, grace_days, dry_run).await;
                        let outcome = match &run.error {
                            None => Outcome::Done,
                            Some(e) => Outcome::Failed { message: e.clone() },
                        };
                        let _ = link.update(|p| {
                            p.last_gc = Some(run);
                            p.set_outcome(&id, outcome);
                        });
                    });
                }
                Operation::Update { .. } => update::spawn(self.clone(), command),
            }
        }
        Ok(CommandAck { id, outcome })
    }

    /// Run gc on the store, as `vk-registry gc` does, and refresh the usage.
    async fn gc(&self, retention_days: u64, grace_days: u64, dry_run: bool) -> GcRun {
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
                at,
                dry_run,
                tags_dropped: r.tags_dropped as u64,
                manifests_dropped: r.manifests_dropped as u64,
                blobs_dropped: r.blobs_dropped as u64,
                bytes_freed: r.bytes_freed,
                uploads_dropped: r.uploads_dropped as u64,
                error: None,
            },
            Err(e) => GcRun {
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
        let (size, free) = store_space(&self.state.store.root);
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
            store_size_bytes: size,
            store_free_bytes: free,
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
            .gc(policy.retention_days, policy.grace_days, false)
            .await;
        if let Err(e) = link.update(|p| {
            p.scheduled_gc_at = Some(now);
            p.last_gc = Some(run);
        }) {
            eprintln!("vk-registry: hub: {e:#}");
        }
    }
}
