//! Updating the relay to a `vk-gitlab` release its hub holds, on trial, when `[hub] allow`
//! lists `update`. It follows `vk-registry`'s update:
//!
//! 1. the release is downloaded from the hub under the relay's signature into
//!    `<state_dir>/hub/releases/<sha256>`, checked against the command's digest and size, its
//!    signature against `[hub] release_keys`, and its `--version` against the command's;
//! 2. the running binary is kept beside it, by its own sha256, to go back to;
//! 3. the runners stop asking GitLab for jobs, and the requests out end — a job GitLab hands
//!    to a request is recorded in its runner's state file before the request counts as ended;
//! 4. the relay records a trial and executes the release in its place, `alarm(2)` armed past
//!    the trial's deadline. Its jobs go on: the release resumes them from the state files, as
//!    after any restart, and their logs pick up where GitLab acknowledged them;
//! 5. the release, once it is in session with the hub, records that it passed, then installs
//!    itself over the installed binary's path, by rename, and reports the update done; a relay
//!    stopped in between finishes the install on its next start.
//!
//! Until confirmation, `vk-gitlab run` starts the unchanged installed binary, whether invoked
//! by a person or a supervisor after a crash or hang. It counts the attempt and retries
//! ([`on_start`]), or takes the relay back and reports rollback after [`MAX_ATTEMPTS`] or the
//! deadline. `run` needs a restarting supervisor: the alarm ends a release that cannot reach
//! the hub, but does not restart the relay.
//!
//! A relay stopping on SIGTERM or SIGINT takes no update, and one that starts stopping during
//! an update stops rather than executing the release.
//!
//! The commands, their outcomes and the trial are kept in `<state_dir>/hub/update.json`,
//! written whole, so a command redelivered after a reconnect is answered with its outcome
//! rather than run twice. The installed binary is the one `run` last started from outside
//! `<state_dir>/hub/`: a confirmed release goes on running from `releases/`, and the next
//! update still replaces the installed path.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use vk_hub_proto::gitlab::{Command, Operation};
use vk_hub_proto::{CommandAck, Outcome, UpdatePhase, UpdateProgress};
use vk_peer::update::{Binary, exec, keep_previous, own_sha256, running_is};

use crate::config::HubConfig;
use crate::poll::ShutdownHandle;
use crate::relay::Relay;
use crate::session::Status;

/// How many times a release on trial may be started before the previous binary takes the
/// relay back.
pub const MAX_ATTEMPTS: u32 = 3;

/// How long a release on trial has to reach the hub.
const TRIAL_WINDOW: Duration = Duration::from_secs(120);

/// The largest release a relay takes, whatever a command says.
const MAX_RELEASE: u64 = 1 << 30;

/// How long a download may take in all.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How long the job requests out to GitLab may take to end. Past it the release is executed
/// all the same, as a restart would: a job GitLab hands to a request cut short is lost to
/// GitLab's stuck-job timeout.
const REQUESTS_WAIT: Duration = Duration::from_secs(10 * 60);

const STATE_FILE: &str = "update.json";

/// The most commands the journal keeps; past it, the oldest settled ones go.
const JOURNAL_MAX: usize = 64;

fn releases_dir(dir: &Path) -> PathBuf {
    dir.join("releases")
}

/// Set the moment SIGTERM or SIGINT arrives, before the runtime's task handling them runs:
/// what the last check before an exec reads.
static SIGNALLED: AtomicBool = AtomicBool::new(false);

/// Note SIGTERM and SIGINT in [`SIGNALLED`] as they arrive, beside the handling `run`
/// installs; once, before an update can start.
pub fn note_signals() -> Result<()> {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: the action only stores to an atomic, which is async-signal-safe.
        unsafe {
            signal_hook_registry::register(signal, || SIGNALLED.store(true, Ordering::SeqCst))
        }
        .with_context(|| format!("noting signal {signal}"))?;
    }
    Ok(())
}

/// A command as the relay journaled it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub op: Operation,
    pub expires_at: u64,
    pub outcome: Outcome,
    /// The outcome the hub said it stored; the ack is repeated until it matches.
    #[serde(default)]
    pub recorded: Option<Outcome>,
}

/// An update between its download and its end.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trial {
    /// The command that asked it.
    pub command: String,
    pub version: String,
    pub sha256: String,
    /// The installed binary, which the release replaces once it has passed, and its
    /// `(device, inode)` when the trial began.
    pub exe: PathBuf,
    pub exe_id: (u64, u64),
    /// The release, under `<state_dir>/hub/releases/`.
    pub next: PathBuf,
    /// The installed binary's sha256, kept there too to go back to.
    pub previous: String,
    /// Starts of the release so far, and when it must have reached the hub by.
    pub attempts: u32,
    pub deadline: u64,
    /// The release reached the hub: what is left is installing it, which any start finishes.
    #[serde(default)]
    pub confirmed: bool,
}

/// What the relay keeps of its hub's commands across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Persisted {
    /// The hub and relay ID these were asked under; a new enrollment forgets them.
    #[serde(default)]
    pub issuer: Option<(String, String)>,
    #[serde(default)]
    pub journal: Vec<Entry>,
    #[serde(default)]
    pub trial: Option<Trial>,
    #[serde(default)]
    pub update: Option<UpdateProgress>,
    /// The installed `vk-gitlab` an update replaces.
    #[serde(default)]
    pub installed: Option<PathBuf>,
}

impl Persisted {
    /// The state in `dir`, empty when there is none.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(STATE_FILE);
        match vk_peer::net::read_nofollow(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if vk_peer::net::is_not_found(&e) => Ok(Persisted::default()),
            Err(e) => Err(e),
        }
    }

    /// Write it whole, private, and its directory synced: a trial confirmed must be found so
    /// after a crash, before the release is installed.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join(STATE_FILE);
        let bytes = serde_json::to_vec_pretty(self).context("encoding the update state")?;
        vk_fs::write_atomic(&path, &bytes, 0o600)
            .with_context(|| format!("writing {}", path.display()))?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("syncing {}", dir.display()))
    }

    /// Forget what another hub or enrollment asked.
    fn adopt_issuer(&mut self, hub: &str, id: &str) -> bool {
        let issuer = (hub.to_string(), id.to_string());
        if self.issuer.as_ref() == Some(&issuer) {
            return false;
        }
        *self = Persisted {
            issuer: Some(issuer),
            installed: self.installed.take(),
            ..Persisted::default()
        };
        true
    }

    /// The journaled entry for command `id`.
    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.journal.iter().find(|e| e.id == id)
    }

    /// Journal a command with its first outcome, at `now`, dropping the oldest ended entries
    /// past [`JOURNAL_MAX`]: those the hub stored, and the expired ones it did not, which a
    /// hub sending them again gets refused as expired.
    fn journal(&mut self, id: &str, op: Operation, expires_at: u64, outcome: Outcome, now: u64) {
        self.journal.push(Entry {
            id: id.to_string(),
            op,
            expires_at,
            outcome,
            recorded: None,
        });
        while self.journal.len() > JOURNAL_MAX {
            let settled = self.journal.iter().position(|e| {
                e.outcome != Outcome::Accepted
                    && (e.recorded.as_ref() == Some(&e.outcome) || e.expires_at <= now)
            });
            match settled {
                Some(i) => {
                    self.journal.remove(i);
                }
                None => break,
            }
        }
    }

    /// Record command `id`'s new outcome.
    fn set_outcome(&mut self, id: &str, outcome: Outcome) {
        if let Some(e) = self.journal.iter_mut().find(|e| e.id == id) {
            e.outcome = outcome;
        }
    }

    /// The acks the hub has not stored yet.
    fn unrecorded(&self) -> Vec<CommandAck> {
        self.journal
            .iter()
            .filter(|e| e.recorded.as_ref() != Some(&e.outcome))
            .map(|e| CommandAck {
                id: e.id.clone(),
                outcome: e.outcome.clone(),
            })
            .collect()
    }

    /// Whether an update is under way: accepted and not ended.
    fn update_under_way(&self) -> bool {
        self.journal.iter().any(|e| e.outcome == Outcome::Accepted)
    }

    /// Fail what a restart cut short: an accepted update but the one on trial, and the
    /// progress of an update that never reached its trial. Whether anything changed.
    fn fail_interrupted(&mut self) -> bool {
        const WHY: &str = "interrupted by a restart";
        let on_trial = self.trial.as_ref().map(|t| t.command.clone());
        let mut changed = false;
        for e in &mut self.journal {
            if e.outcome == Outcome::Accepted && on_trial.as_ref() != Some(&e.id) {
                e.outcome = Outcome::Failed {
                    message: WHY.to_string(),
                };
                changed = true;
            }
        }
        if let Some(u) = &mut self.update
            && matches!(
                u.phase,
                UpdatePhase::Downloading | UpdatePhase::Draining | UpdatePhase::Validating
            )
            && on_trial.as_ref() != Some(&u.command)
        {
            u.phase = UpdatePhase::Failed;
            u.message = Some(WHY.to_string());
            changed = true;
        }
        changed
    }

    /// The hub stored `ack`.
    fn recorded(&mut self, ack: &CommandAck) {
        if let Some(e) = self.journal.iter_mut().find(|e| e.id == ack.id) {
            e.recorded = Some(ack.outcome.clone());
        }
    }
}

/// What `run` does on starting.
pub enum Start {
    Run,
    /// Execute this binary in place of this one, `alarm(2)` armed for this deadline.
    Exec(Binary, Option<u64>),
}

/// The previous binary's part in a trial, run by `run` before anything else, under the
/// relay's lock: count the start and hand over to the release, or, past [`MAX_ATTEMPTS`] or
/// the deadline, end the trial and run on as the relay's binary. The release on trial arms its
/// own deadline. A state that cannot be read or written is logged and the relay runs: what
/// the hub asked must never stop it.
pub fn on_start(state_dir: &Path, now: u64) -> Start {
    let dir = crate::relay::dir(state_dir);
    if !dir.is_dir() {
        return Start::Run;
    }
    let mut p = match Persisted::load(&dir) {
        Ok(p) => p,
        Err(e) => {
            log::error!(error = format!("{e:#}").as_str(); "Reading the update state failed; running on");
            return Start::Run;
        }
    };
    let save = |p: &Persisted| {
        if let Err(e) = p.save(&dir) {
            log::error!(error = format!("{e:#}").as_str(); "Writing the update state failed");
        }
    };
    let Some(trial) = p.trial.clone() else {
        return Start::Run;
    };
    if trial.confirmed {
        return finish_install(&dir, &mut p, &trial);
    }
    if running_is(&trial.next) {
        vk_peer::update::alarm(Some(trial.deadline), now);
        return Start::Run;
    }
    let failed = if trial.attempts >= MAX_ATTEMPTS {
        Some(format!(
            "the release did not reach the hub in {MAX_ATTEMPTS} starts"
        ))
    } else if now > trial.deadline {
        Some("the release did not reach the hub before its deadline".to_string())
    } else {
        None
    };
    let next = match failed {
        Some(why) => Err(why),
        None => Binary::open(&trial.next, Some(&trial.sha256)).map_err(|e| format!("{e:#}")),
    };
    match next {
        Ok(binary) => {
            if let Some(t) = p.trial.as_mut() {
                t.attempts += 1;
            }
            save(&p);
            log::warn!(version = trial.version.as_str(), attempt = trial.attempts + 1; "Starting vk-gitlab on trial");
            Start::Exec(binary, Some(trial.deadline))
        }
        Err(why) => {
            log::error!(version = trial.version.as_str(), error = why.as_str(); "Update rolled back");
            end(
                &mut p,
                &trial,
                UpdatePhase::RolledBack,
                Outcome::Failed {
                    message: format!("rolled back: {why}"),
                },
                Some(why),
            );
            save(&p);
            prune(&dir, &[&trial.previous]);
            Start::Run
        }
    }
}

/// Install `trial`'s release, confirmed by the hub but not installed before the relay stopped,
/// and end the update; then run the release, if this is another binary.
fn finish_install(dir: &Path, p: &mut Persisted, trial: &Trial) -> Start {
    let installed = install(trial);
    match &installed {
        Ok(()) => end(p, trial, UpdatePhase::Done, Outcome::Done, None),
        Err(e) => end(
            p,
            trial,
            UpdatePhase::Failed,
            Outcome::Failed {
                message: format!("{e:#}"),
            },
            Some(format!("{e:#}")),
        ),
    }
    if let Err(e) = p.save(dir) {
        log::error!(error = format!("{e:#}").as_str(); "Writing the update state failed");
        return Start::Run;
    }
    let Err(e) = installed else {
        prune(dir, &[&trial.sha256, &trial.previous]);
        log::info!(version = trial.version.as_str(), path = trial.exe.display().to_string().as_str(); "vk-gitlab installed");
        if own_sha256().as_deref() == Some(trial.sha256.as_str()) {
            return Start::Run;
        }
        return match Binary::open(&trial.exe, Some(&trial.sha256)) {
            Ok(binary) => Start::Exec(binary, None),
            Err(e) => {
                log::error!(error = format!("{e:#}").as_str(); "Starting the installed release failed; running on");
                Start::Run
            }
        };
    };
    log::error!(error = format!("{e:#}").as_str(); "Installing the update failed");
    Start::Run
}

/// The installed binary to record when `run` runs `exe`, `recorded` before; `None` to keep
/// what is recorded. A binary under the hub directory `dir` is a release, never the installed
/// one.
fn installed_after(recorded: Option<&Path>, exe: PathBuf, dir: &Path) -> Option<PathBuf> {
    (exe.is_file() && !vk_peer::update::under(&exe, dir) && recorded != Some(exe.as_path()))
        .then_some(exe)
}

/// Keep only the releases named in `keep` under `dir`: the one installed and the one before
/// it, or after a rollback the one running.
fn prune(dir: &Path, keep: &[&str]) {
    let Ok(entries) = std::fs::read_dir(releases_dir(dir)) else {
        return;
    };
    for entry in entries.flatten() {
        if !keep
            .iter()
            .any(|k| entry.file_name().as_encoded_bytes() == k.as_bytes())
        {
            // Best effort: a release left over costs only space, and the next prune retries.
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// End `trial` in `p` with `phase` and `outcome`.
fn end(
    p: &mut Persisted,
    trial: &Trial,
    phase: UpdatePhase,
    outcome: Outcome,
    why: Option<String>,
) {
    p.trial = None;
    p.update = Some(UpdateProgress {
        command: trial.command.clone(),
        version: trial.version.clone(),
        sha256: trial.sha256.clone(),
        phase,
        message: why,
    });
    p.set_outcome(&trial.command, outcome);
}

/// Install the release over `trial.exe`, unless another binary replaced it meanwhile.
fn install(trial: &Trial) -> Result<()> {
    let meta = std::fs::metadata(&trial.exe)
        .with_context(|| format!("reading {}", trial.exe.display()))?;
    if vk_peer::update::hash_file(&trial.exe).ok().as_deref() == Some(trial.sha256.as_str()) {
        return Ok(());
    }
    if trial.exe_id != (meta.dev(), meta.ino()) {
        return Err(anyhow!(
            "{} was replaced by another binary during the trial; the release is not installed \
             over it",
            trial.exe.display()
        ));
    }
    let mode = (std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777) | 0o100;
    vk_peer::update::copy_published(&trial.next, &trial.exe, mode, Some(&trial.sha256))
}

/// Whether the relay may install over the installed binary `installed`: recorded, a file
/// outside `dir`, in a directory this user can write, since the release is renamed into it.
fn can_replace(installed: Option<&Path>, dir: &Path) -> Result<(), String> {
    let exe = installed.ok_or_else(|| {
        "the installed vk-gitlab is not known yet: restart vk-gitlab run from it".to_string()
    })?;
    if !exe.is_file() {
        return Err(format!("{} is gone", exe.display()));
    }
    if vk_peer::update::under(exe, dir) {
        return Err(format!(
            "{} is inside the relay's hub directory; run vk-gitlab from its installed path",
            exe.display()
        ));
    }
    let parent = exe
        .parent()
        .ok_or_else(|| format!("{} has no directory", exe.display()))?;
    let c_dir = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("{} has a NUL in it", parent.display()))?;
    // SAFETY: NUL-terminated and outlives the call.
    if unsafe { libc::access(c_dir.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
        return Err(format!(
            "vk-gitlab cannot replace {}: {} is not writable by this user",
            exe.display(),
            parent.display()
        ));
    }
    Ok(())
}

/// Whether a relay running `own` may update to `candidate`: not to an older version unless
/// `allow_downgrade`. Versions are `MAJOR.MINOR.PATCH`.
fn check_version(own: &str, candidate: &str, allow_downgrade: bool) -> Result<(), String> {
    fn fields(v: &str) -> Option<Vec<u64>> {
        let v: Vec<u64> = v
            .split('.')
            .map(|f| f.parse().ok())
            .collect::<Option<_>>()?;
        (v.len() == 3).then_some(v)
    }
    match (fields(candidate), fields(own)) {
        (Some(c), Some(o)) if c >= o || allow_downgrade => Ok(()),
        (Some(_), Some(_)) => Err(format!(
            "vk-gitlab {candidate} is older than this relay's {own}; [hub] allow_downgrade = \
             true lets an update install it"
        )),
        _ if candidate == own => Ok(()),
        _ => Err(format!(
            "vk-gitlab {candidate} cannot be ordered against {own}; versions are \
             MAJOR.MINOR.PATCH"
        )),
    }
}

/// The relay's side of the hub's commands: what it was sent and how each went, and the update
/// they start.
pub struct Updater {
    /// `<state_dir>/hub`.
    dir: PathBuf,
    relay: Arc<Relay>,
    hub: HubConfig,
    policy: vk_peer::release_key::Policy,
    status: Arc<Status>,
    /// Stops the runners' job requests before the release is executed.
    shutdown: Arc<ShutdownHandle>,
    persisted: Mutex<Persisted>,
    /// Why the persisted state could not be read: no update is taken, and the file is left
    /// as it is.
    broken: Option<String>,
    /// Whether an update stopped the job requests and is executing the release, or has given
    /// up: until then, the relay must not end with its runners' last job.
    handover: watch::Sender<Handover>,
}

/// Where an update is in taking over from the running relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handover {
    None,
    /// The job requests are stopped: the release is about to run.
    Started,
    /// The relay stopped instead: it ends as it was told.
    Ended,
}

impl std::fmt::Debug for Updater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Updater")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl Updater {
    /// The updater of the relay `state_dir` holds, with what it last kept; an interrupted
    /// update is failed, and the binary `run` started from recorded as the installed one. A
    /// state that cannot be read or written is logged, and the relay takes no update: what the
    /// hub asked must never stop it.
    pub fn open(
        state_dir: &Path,
        relay: Arc<Relay>,
        hub: HubConfig,
        status: Arc<Status>,
        shutdown: Arc<ShutdownHandle>,
    ) -> Result<Arc<Self>> {
        let dir = crate::relay::dir(state_dir);
        let (persisted, broken) = match Self::load(&dir, &relay) {
            Ok(p) => (p, None),
            Err(e) => {
                log::error!(error = format!("{e:#}").as_str(); "The update state cannot be used; taking no update");
                (Persisted::default(), Some(format!("{e:#}")))
            }
        };
        let policy = hub.release_policy()?;
        Ok(Arc::new(Updater {
            dir,
            relay,
            hub,
            policy,
            status,
            shutdown,
            persisted: Mutex::new(persisted),
            broken,
            handover: watch::channel(Handover::None).0,
        }))
    }

    /// The state in `dir`, made current for `relay`'s enrollment and this start, and saved if
    /// that changed it.
    fn load(dir: &Path, relay: &Relay) -> Result<Persisted> {
        let mut persisted = Persisted::load(dir)?;
        let mut changed = persisted.adopt_issuer(&relay.enrollment.hub, &relay.enrollment.relay_id);
        changed |= persisted.fail_interrupted();
        if let Ok(exe) = std::env::current_exe()
            && let Some(installed) = installed_after(persisted.installed.as_deref(), exe, dir)
        {
            persisted.installed = Some(installed);
            changed = true;
        }
        if changed {
            persisted.save(dir)?;
        }
        Ok(persisted)
    }

    /// Wait, once the runners' loop has ended, for an update that stopped its job requests to
    /// execute the release, which does not return, or to give up because the relay is
    /// stopping. Returns at once when no update stopped them.
    pub async fn handed_over(&self) {
        let mut rx = self.handover.subscribe();
        // The sender is `self`'s, so an error cannot come.
        let _ = rx.wait_for(|h| *h != Handover::Started).await;
    }

    /// Whether the relay is stopping, or was just told to.
    fn stopping(&self) -> bool {
        self.shutdown.stopping() || SIGNALLED.load(Ordering::SeqCst)
    }

    fn persisted(&self) -> std::sync::MutexGuard<'_, Persisted> {
        self.persisted.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Change the persisted state with `f`, save it, and wake the session to report. Nothing
    /// changes, in memory or on disk, when the save fails.
    fn change<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> Result<R> {
        let out = {
            let mut p = self.persisted();
            let mut next = p.clone();
            let out = f(&mut next);
            next.save(&self.dir)?;
            *p = next;
            out
        };
        self.status.touch();
        Ok(out)
    }

    /// The update in progress, or the last one's end.
    pub fn progress(&self) -> Option<UpdateProgress> {
        self.persisted().update.clone()
    }

    /// The acks the hub has not stored yet.
    pub fn unrecorded(&self) -> Vec<CommandAck> {
        self.persisted().unrecorded()
    }

    /// The hub stored `ack`: it is not sent again. Nothing to keep with a state that cannot be
    /// read, which is left as it is.
    pub fn recorded(&self, ack: &CommandAck) -> Result<()> {
        let stored = self
            .persisted()
            .entry(&ack.id)
            .is_none_or(|e| e.recorded.as_ref() == Some(&ack.outcome));
        // Nothing to save: an ack sent twice is recorded twice.
        if self.broken.is_some() || stored {
            return Ok(());
        }
        self.change(|p| p.recorded(ack))
    }

    /// Take `command`: answer one journaled already with its outcome, refuse an expired one,
    /// one `[hub] allow` does not list, or an update this relay would not install, and start
    /// the others. The ack to send now.
    pub fn command(self: &Arc<Self>, command: Command) -> Result<CommandAck> {
        if let Some(entry) = self.persisted().entry(&command.id) {
            return Ok(CommandAck {
                id: entry.id.clone(),
                outcome: entry.outcome.clone(),
            });
        }
        if let Some(why) = &self.broken {
            // Not journaled: there is no journal to keep it in.
            return Ok(CommandAck {
                id: command.id,
                outcome: Outcome::Refused {
                    reason: format!("the relay's update state cannot be used: {why}"),
                },
            });
        }
        let now = vk_peer::now_secs();
        let outcome = if command.expires_at <= now {
            Outcome::Expired
        } else if !self.hub.allows(command.op.allowed_by()) {
            Outcome::Refused {
                reason: format!(
                    "this relay's [hub] allow does not list {}",
                    command.op.allowed_by()
                ),
            }
        } else {
            match self.accept(&command) {
                Ok(outcome) => outcome,
                Err(reason) => Outcome::Refused { reason },
            }
        };
        let (id, op) = (command.id.clone(), command.op.clone());
        self.change(|p| {
            // Under way from its acceptance on, so a report sent before the download starts
            // names it.
            if outcome == Outcome::Accepted {
                let Operation::Update {
                    version, sha256, ..
                } = &op;
                p.update = Some(UpdateProgress {
                    command: id.clone(),
                    version: version.clone(),
                    sha256: sha256.clone(),
                    phase: UpdatePhase::Downloading,
                    message: None,
                });
            }
            p.journal(&id, op.clone(), command.expires_at, outcome.clone(), now);
        })?;
        if outcome == Outcome::Accepted {
            let updater = self.clone();
            tokio::spawn(async move {
                if let Err(e) = updater.prepare(&command).await {
                    log::error!(error = format!("{e:#}").as_str(); "Update failed");
                    if let Err(e) = updater.failed(&command, &format!("{e:#}")) {
                        log::error!(error = format!("{e:#}").as_str(); "Recording the failed update failed");
                    }
                }
            });
        }
        Ok(CommandAck { id, outcome })
    }

    /// Whether the relay takes `command`, an update: `Ok` with its first outcome, `Err` with
    /// why it refuses.
    fn accept(&self, command: &Command) -> Result<Outcome, String> {
        let Operation::Update {
            version,
            sha256,
            size,
            signature,
        } = &command.op;
        if self.stopping() {
            return Err("the relay is stopping".to_string());
        }
        if self.persisted().update_under_way() {
            return Err("an update is under way already".to_string());
        }
        if !vk_hub_proto::valid_sha256(sha256) {
            return Err(format!("{sha256:?} is not a sha256"));
        }
        if *size > MAX_RELEASE {
            return Err(format!("the release is {size} bytes, past {MAX_RELEASE}"));
        }
        if own_sha256().as_deref() == Some(sha256.as_str()) {
            return Ok(Outcome::Done);
        }
        check_version(env!("CARGO_PKG_VERSION"), version, self.hub.allow_downgrade)?;
        self.policy.check(sha256, version, signature.as_deref())?;
        can_replace(self.persisted().installed.as_deref(), &self.dir)?;
        Ok(Outcome::Accepted)
    }

    /// Record that the update `command` failed with `why`. A trial recorded before an exec that
    /// failed is undone, and its release dropped: no release runs on trial.
    fn failed(&self, command: &Command, why: &str) -> Result<()> {
        let Operation::Update {
            version, sha256, ..
        } = &command.op;
        let undone = self.change(|p| {
            p.update = Some(UpdateProgress {
                command: command.id.clone(),
                version: version.clone(),
                sha256: sha256.clone(),
                phase: UpdatePhase::Failed,
                message: Some(why.to_string()),
            });
            p.set_outcome(
                &command.id,
                Outcome::Failed {
                    message: why.to_string(),
                },
            );
            p.trial.take_if(|t| t.command == command.id)
        })?;
        if let Some(trial) = undone {
            prune(&self.dir, &[&trial.previous]);
        }
        Ok(())
    }

    /// Carry out the update `command` was accepted for: download and check the release, keep
    /// the running binary, end the job requests, record the trial and execute the release.
    /// Returns an error on a failure before the job requests are stopped. After that it does
    /// not return, unless the relay is stopping: then it records the failure itself, its trial
    /// undone, before letting the relay end, and returns `Ok`.
    async fn prepare(&self, command: &Command) -> Result<()> {
        let Operation::Update {
            version,
            sha256,
            size,
            ..
        } = &command.op;
        let progress = |phase| UpdateProgress {
            command: command.id.clone(),
            version: version.clone(),
            sha256: sha256.clone(),
            phase,
            message: None,
        };
        let releases = releases_dir(&self.dir);
        vk_peer::net::create_dir(&releases)?;
        vk_peer::update::sweep_partial(&releases);
        let next = releases.join(sha256);
        if !next.is_file() {
            let fetch = vk_peer::update::Download {
                hub: &self.relay.enrollment.hub,
                tls: &self.relay.tls,
                identity: &self.relay.identity,
                id: &self.relay.enrollment.relay_id,
                id_header: vk_hub_proto::client::RELAY_HEADER,
                path: vk_hub_proto::gitlab::RELEASE_PATH,
                sign: vk_hub_proto::download_message,
                sha256,
                size: *size,
                mode: 0o700,
            };
            tokio::time::timeout(DOWNLOAD_TIMEOUT, vk_peer::update::download(&fetch, &next))
                .await
                .map_err(|_| anyhow!("the download took longer than {DOWNLOAD_TIMEOUT:?}"))??;
        }
        let installed = self.persisted().installed.clone();
        let (dir, next2, version2, sha2, id) = (
            self.dir.clone(),
            next.clone(),
            version.clone(),
            sha256.clone(),
            command.id.clone(),
        );
        let (trial, binary) = tokio::task::spawn_blocking(move || -> Result<(Trial, Binary)> {
            let binary = Binary::open(&next2, Some(&sha2))?;
            vk_selfupdate::smoke_test_file("vk-gitlab", binary.file(), binary.path(), &version2)?;
            let own = own_sha256().context("reading the running binary")?;
            keep_previous(&releases_dir(&dir), &own)?;
            let exe = installed.context("the installed vk-gitlab is not known")?;
            let meta =
                std::fs::metadata(&exe).with_context(|| format!("reading {}", exe.display()))?;
            let trial = Trial {
                command: id,
                version: version2,
                sha256: sha2,
                exe,
                exe_id: (meta.dev(), meta.ino()),
                next: next2,
                previous: own,
                attempts: 1,
                deadline: 0,
                confirmed: false,
            };
            Ok((trial, binary))
        })
        .await
        .context("checking the release")??;
        if self.stopping() {
            return Err(anyhow!("the relay is stopping"));
        }
        self.change(|p| p.update = Some(progress(UpdatePhase::Draining)))?;
        log::info!(version = version.as_str(); "Updating: no new job requests; waiting for those out to end");
        self.handover.send_replace(Handover::Started);
        self.shutdown.stop_requests();
        let e = self.hand_over(command, trial, &binary).await;
        if self.stopping() {
            // SIGTERM or SIGINT came meanwhile: the relay stops, as it was told, its trial
            // undone first so that no later start executes the release.
            if let Err(e) = self.failed(command, &format!("{e:#}")) {
                log::error!(error = format!("{e:#}").as_str(); "Recording the failed update failed");
            }
            self.handover.send_replace(Handover::Ended);
            return Ok(());
        }
        // Its runners no longer ask for jobs: this binary starts over, as a restart would.
        if let Err(e) = self.failed(command, &format!("{e:#}")) {
            log::error!(error = format!("{e:#}").as_str(); "Recording the failed update failed");
        }
        log::error!(error = format!("{e:#}").as_str(); "The update failed; starting this vk-gitlab again");
        let again = Binary::open(Path::new("/proc/self/exe"), None)
            .map_or_else(|e| e, |own| exec(&own, None));
        log::error!(error = format!("{again:#}").as_str(); "Starting again failed; exiting for the supervisor to restart the relay");
        std::process::exit(1);
    }

    /// Once the job requests have ended, record `trial` and execute `binary`, the release, in
    /// place of this one; returns only why it did not. A relay that starts stopping meanwhile
    /// does not execute the release, and its trial is undone.
    async fn hand_over(&self, command: &Command, trial: Trial, binary: &Binary) -> anyhow::Error {
        let Operation::Update { version, .. } = &command.op;
        if tokio::time::timeout(REQUESTS_WAIT, self.shutdown.requests_ended())
            .await
            .is_err()
        {
            log::warn!(waited_s = REQUESTS_WAIT.as_secs(); "Job requests still out, or jobs not recorded; executing the release all the same");
        }
        if self.stopping() {
            return anyhow!("the relay is stopping");
        }
        let trial = Trial {
            deadline: vk_peer::now_secs() + TRIAL_WINDOW.as_secs(),
            ..trial
        };
        let deadline = trial.deadline;
        let progress = UpdateProgress {
            command: command.id.clone(),
            version: version.clone(),
            sha256: trial.sha256.clone(),
            phase: UpdatePhase::Validating,
            message: None,
        };
        if let Err(e) = self.change(|p| {
            p.trial = Some(trial);
            p.update = Some(progress);
        }) {
            return e;
        }
        // A signal is noted as it arrives, before the task handling it runs: one that comes
        // after this check, in the exec itself, is lost with this process, and the
        // supervisor's own timeout ends the release instead.
        if self.stopping() {
            return anyhow!("the relay is stopping");
        }
        log::warn!(version = version.as_str(); "Executing vk-gitlab on trial; running jobs resume from the state files");
        exec(binary, Some(deadline))
    }

    /// The release on trial reached the hub: install it over the installed binary and report
    /// the update done. Nothing to do when no trial runs this binary.
    pub fn confirm(&self) {
        let trial = self.persisted().trial.clone();
        let Some(trial) = trial.filter(|t| running_is(&t.next) && !t.confirmed) else {
            return;
        };
        // Confirmed before it is installed: a relay stopped in between installs it on its next
        // start, rather than taking the installed binary for the previous one.
        if let Err(e) = self.change(|p| {
            if let Some(t) = &mut p.trial {
                t.confirmed = true;
            }
        }) {
            log::error!(error = format!("{e:#}").as_str(); "Confirming the update failed");
            return;
        }
        vk_peer::update::alarm(None, 0);
        let installed = install(&trial);
        let result = self.change(|p| match &installed {
            Ok(()) => end(p, &trial, UpdatePhase::Done, Outcome::Done, None),
            Err(e) => end(
                p,
                &trial,
                UpdatePhase::Failed,
                Outcome::Failed {
                    message: format!("{e:#}"),
                },
                Some(format!("{e:#}")),
            ),
        });
        match (installed, result) {
            (Ok(()), Ok(())) => {
                prune(&self.dir, &[&trial.sha256, &trial.previous]);
                log::info!(version = trial.version.as_str(), path = trial.exe.display().to_string().as_str(); "vk-gitlab installed");
            }
            (Err(e), _) | (_, Err(e)) => {
                log::error!(error = format!("{e:#}").as_str(); "Installing the update failed")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("vk-gitlab-update-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(crate::relay::dir(&root)).unwrap();
        root
    }

    fn update() -> Operation {
        Operation::Update {
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            size: 1,
            signature: None,
        }
    }

    fn trial(command: &str, dir: &Path, attempts: u32, deadline: u64) -> Trial {
        Trial {
            command: command.into(),
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            exe: dir.join("absent-exe"),
            exe_id: (0, 0),
            next: dir.join("absent-next"),
            previous: "1".repeat(64),
            attempts,
            deadline,
            confirmed: false,
        }
    }

    #[test]
    fn versions_only_go_forward_unless_allowed() {
        assert!(check_version("0.101.0", "0.102.0", false).is_ok());
        assert!(check_version("0.101.0", "0.101.0", false).is_ok());
        assert!(check_version("0.101.0", "0.100.0", false).is_err());
        assert!(check_version("0.101.0", "0.100.0", true).is_ok());
        assert!(check_version("0.101.0", "nightly", true).is_err());
    }

    #[test]
    fn an_ack_is_repeated_until_the_hub_stores_it() {
        let mut p = Persisted::default();
        p.journal("a", update(), 10, Outcome::Accepted, 0);
        assert_eq!(p.unrecorded().len(), 1);
        p.recorded(&CommandAck {
            id: "a".into(),
            outcome: Outcome::Accepted,
        });
        assert!(p.unrecorded().is_empty());
        p.set_outcome("a", Outcome::Done);
        assert_eq!(p.unrecorded()[0].outcome, Outcome::Done);
    }

    #[test]
    fn another_hub_s_commands_are_forgotten_but_the_installed_binary() {
        let mut p = Persisted::default();
        p.adopt_issuer("https://a", "1");
        p.journal("x", update(), 10, Outcome::Done, 0);
        p.installed = Some(PathBuf::from("/usr/local/bin/vk-gitlab"));
        p.adopt_issuer("https://a", "1");
        assert!(p.entry("x").is_some());
        p.adopt_issuer("https://b", "1");
        assert!(p.entry("x").is_none());
        assert!(p.installed.is_some());
    }

    #[test]
    fn the_journal_is_bounded_by_settled_entries() {
        let mut p = Persisted::default();
        for i in 0..JOURNAL_MAX + 10 {
            let id = i.to_string();
            p.journal(&id, update(), 10, Outcome::Done, 0);
            p.recorded(&CommandAck {
                id,
                outcome: Outcome::Done,
            });
        }
        assert_eq!(p.journal.len(), JOURNAL_MAX);
        assert!(p.entry("0").is_none());
    }

    /// Entries the hub never stored go too once expired, but not before, nor an update under
    /// way.
    #[test]
    fn the_journal_drops_expired_entries_the_hub_never_stored() {
        let mut p = Persisted::default();
        p.journal("accepted", update(), 10, Outcome::Accepted, 0);
        p.journal("live", update(), 1000, Outcome::Done, 0);
        for i in 0..JOURNAL_MAX {
            p.journal(&i.to_string(), update(), 10, Outcome::Done, 100);
        }
        assert_eq!(p.journal.len(), JOURNAL_MAX);
        assert!(p.entry("accepted").is_some() && p.entry("live").is_some());
        assert!(p.entry("0").is_none() && p.entry("1").is_none());
    }

    #[test]
    fn a_restart_fails_the_update_it_interrupted_but_the_trial() {
        let progress = |command: &str, phase| UpdateProgress {
            command: command.into(),
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            phase,
            message: None,
        };
        let mut p = Persisted::default();
        p.journal("u", update(), 10, Outcome::Accepted, 0);
        p.update = Some(progress("u", UpdatePhase::Draining));
        assert!(p.update_under_way());
        assert!(p.fail_interrupted());
        assert!(matches!(
            p.entry("u").unwrap().outcome,
            Outcome::Failed { .. }
        ));
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Failed);
        assert!(!p.update_under_way());
        assert!(!p.fail_interrupted());

        // The update on trial goes on: the release confirms or the previous binary ends it.
        p.journal("t", update(), 10, Outcome::Accepted, 0);
        p.update = Some(progress("t", UpdatePhase::Validating));
        p.trial = Some(trial("t", Path::new("/"), 1, 1));
        assert!(!p.fail_interrupted());
        assert_eq!(p.entry("t").unwrap().outcome, Outcome::Accepted);
        assert!(p.update_under_way());
    }

    #[test]
    fn a_trial_past_its_attempts_or_deadline_is_rolled_back_on_start() {
        for (tag, attempts, deadline) in [("attempts", MAX_ATTEMPTS, u64::MAX), ("late", 1, 0)] {
            let root = temp(tag);
            let dir = crate::relay::dir(&root);
            let mut p = Persisted::default();
            p.journal("c", update(), u64::MAX, Outcome::Accepted, 0);
            p.trial = Some(trial("c", &dir, attempts, deadline));
            p.save(&dir).unwrap();
            std::fs::create_dir_all(releases_dir(&dir)).unwrap();
            for release in ["0", "1", "2"] {
                std::fs::write(releases_dir(&dir).join(release.repeat(64)), b"r").unwrap();
            }
            assert!(matches!(on_start(&root, 1), Start::Run), "{tag}");
            let p = Persisted::load(&dir).unwrap();
            assert!(p.trial.is_none(), "{tag}");
            assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::RolledBack);
            assert!(matches!(
                p.entry("c").unwrap().outcome,
                Outcome::Failed { .. }
            ));
            // Only the binary that runs again is kept.
            let kept: Vec<_> = std::fs::read_dir(releases_dir(&dir))
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(
                kept,
                vec![std::ffi::OsString::from("1".repeat(64))],
                "{tag}"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// A release still within its attempts and deadline is started again, the attempt counted.
    #[test]
    fn a_trial_within_its_attempts_starts_the_release_again() {
        let root = temp("again");
        let dir = crate::relay::dir(&root);
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        let next = releases_dir(&dir).join("2".repeat(64));
        std::fs::write(&next, b"release").unwrap();
        let sha = vk_peer::update::hash_file(&next).unwrap();
        let mut p = Persisted::default();
        p.journal("c", update(), u64::MAX, Outcome::Accepted, 0);
        p.trial = Some(Trial {
            sha256: sha,
            next: next.clone(),
            ..trial("c", &dir, 1, u64::MAX)
        });
        p.save(&dir).unwrap();
        let Start::Exec(binary, deadline) = on_start(&root, 1) else {
            panic!("the release is not started again");
        };
        assert_eq!((binary.path(), deadline), (next.as_path(), Some(u64::MAX)));
        assert_eq!(Persisted::load(&dir).unwrap().trial.unwrap().attempts, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A release confirmed but stopped before it installed itself: the next start installs it,
    /// ends the update done, and runs it rather than the binary it replaced.
    #[test]
    fn a_confirmed_release_is_installed_on_the_next_start() {
        let root = temp("confirmed");
        let dir = crate::relay::dir(&root);
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        let exe = root.join("vk-gitlab");
        std::fs::write(&exe, b"previous").unwrap();
        let next = releases_dir(&dir).join("2".repeat(64));
        std::fs::write(&next, b"release").unwrap();
        let sha = vk_peer::update::hash_file(&next).unwrap();
        let meta = std::fs::metadata(&exe).unwrap();
        let mut p = Persisted::default();
        p.journal("c", update(), u64::MAX, Outcome::Accepted, 0);
        p.trial = Some(Trial {
            sha256: sha.clone(),
            exe: exe.clone(),
            exe_id: (meta.dev(), meta.ino()),
            next,
            confirmed: true,
            ..trial("c", &dir, MAX_ATTEMPTS, 0)
        });
        p.save(&dir).unwrap();
        let Start::Exec(binary, deadline) = on_start(&root, 1) else {
            panic!("the installed release is not run");
        };
        assert_eq!((binary.path(), deadline), (exe.as_path(), None));
        assert_eq!(vk_peer::update::hash_file(&exe).unwrap(), sha);
        let p = Persisted::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Done);
        assert_eq!(p.entry("c").unwrap().outcome, Outcome::Done);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_state_that_cannot_be_read_does_not_stop_the_relay() {
        let root = temp("corrupt");
        let dir = crate::relay::dir(&root);
        std::fs::write(dir.join(STATE_FILE), b"{ not json").unwrap();
        assert!(matches!(on_start(&root, 1), Start::Run));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The installed binary is the last one `run` started from outside the hub directory:
    /// a confirmed release running from `releases/` leaves it as recorded.
    #[test]
    fn the_installed_binary_is_never_a_release() {
        let root = temp("installed");
        let dir = crate::relay::dir(&root);
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        let installed = root.join("vk-gitlab");
        let release = releases_dir(&dir).join("0".repeat(64));
        for f in [&installed, &release] {
            std::fs::write(f, b"bin").unwrap();
        }
        assert_eq!(
            installed_after(None, installed.clone(), &dir),
            Some(installed.clone())
        );
        assert_eq!(
            installed_after(Some(&installed), installed.clone(), &dir),
            None
        );
        assert_eq!(
            installed_after(Some(&installed), release.clone(), &dir),
            None
        );
        assert_eq!(installed_after(None, root.join("absent"), &dir), None);

        assert!(can_replace(None, &dir).unwrap_err().contains("not known"));
        assert!(can_replace(Some(&release), &dir).is_err());
        can_replace(Some(&installed), &dir).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }
}
