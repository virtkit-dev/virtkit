//! The hub updating itself to a `vk-hub` release it holds, on trial, without closing its
//! listeners: `/updates` or `vk-hub update --release <prefix>`, once `[update] allow`.
//!
//! 1. An update is refused while a release, tools or an install medium is being added, fetched
//!    or renamed, and those are refused from its start on ([`Handover::long_call`]): the exec
//!    would cut them, and the CLI waiting on them, after the seconds the hand-over gives
//!    connections. The release
//!    is copied into `<data_dir>/update/releases/`, checked against its digest, its signature
//!    against `[update] release_keys` and its `--version`; the running binary is kept beside it
//!    to go back to ([`vk_peer::trial`]).
//! 2. The hub settles its jobs ([`Handover`]): it takes no new job or reservation — the client
//!    API answers 503, which relays retry — and waits for the jobs queued to start on a node,
//!    then places none and waits for the starts sent to be answered: a job no node has
//!    accepted keeps its spec in memory only, and would be lost. Should a job be left queued
//!    after [`QUEUE_WAIT`], or a start unanswered after [`START_WAIT`], the update fails and the
//!    hub goes on as it was. Then it stops handling node sessions' job messages and placing,
//!    between two of them, so that nothing is told before it is written.
//! 3. It stops accepting connections, the sockets left open so the kernel queues new ones, and
//!    asks those open to end: an HTTP connection after its request, a live page's stream at
//!    once, which the browser opens again. Those still open after [`GRACE`] are cut, as are
//!    the peers' sessions, which redial.
//! 4. It seals its database ([`Db::seal`](crate::store::Db::seal)), records the trial, and
//!    executes the release with its listening sockets ([`vk_peer::handoff`]) and the web UI's
//!    OIDC sign-ins under way and questions asked first ([`take_handed`]), `alarm(2)` armed past
//!    the trial's deadline.
//! 5. The release takes the sockets, sign-ins and questions, opens the database, recovers its
//!    jobs and serves; once it has served for [`SETTLE`] it records that it passed, installs
//!    itself over the installed binary's path, and the update is done.
//!
//! A release that does not get as far is ended by its alarm or its own failure; whatever
//! starts `vk-hub serve` then — a supervisor, `Restart=always` — starts the previous binary,
//! which hands over to the release again, at most [`MAX_ATTEMPTS`](vk_peer::trial::MAX_ATTEMPTS)
//! times in all, then rolls back. Those starts bind the listeners afresh: only the hand-over
//! keeps them open. A failure before the exec is recorded, and the hub serves on as before.
//!
//! The state is a file of its own, `update/state.json`, read before the database is opened: the
//! previous binary decides whether to hand over before anything else.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{Outcome, UpdatePhase, UpdateProgress};
use vk_peer::handoff::{Gate, Passing};
use vk_peer::trial::{self, Asked, Event, Keeper, Ledger, TRIAL_WINDOW, Trial};

use crate::config::UpdateConfig;
use crate::server::Hub;
use crate::store::{Program, Release};

/// How long the jobs queued have to start on a node once the hub takes no more.
#[cfg(not(test))]
const QUEUE_WAIT: Duration = Duration::from_secs(60);
#[cfg(test)]
const QUEUE_WAIT: Duration = Duration::from_secs(1);

/// How long the starts sent have to be answered once the hub places no more.
#[cfg(not(test))]
const START_WAIT: Duration = Duration::from_secs(30);
#[cfg(test)]
const START_WAIT: Duration = Duration::from_secs(1);

/// How long the job messages being handled have to be done with.
const QUIET_WAIT: Duration = Duration::from_secs(10);

/// How long the connections open have to end once asked.
pub const GRACE: Duration = Duration::from_secs(5);

/// How long a release serves before it counts as having passed.
pub const SETTLE: Duration = Duration::from_secs(10);

/// The environment variable naming the descriptor of the update directory's lock, which a
/// hub hands over with its listeners so that no other `serve` takes the data directory between
/// the exec and the release's start.
const LOCK_ENV: &str = "VK_HUB_LOCK_FD";

/// The lock file, under the update directory.
const LOCK_FILE: &str = "serve.lock";

/// The file the state is kept in, under the update directory.
const STATE_FILE: &str = "state.json";

/// Names the memory file carrying pending OIDC sign-ins and questions ([`Handed`]); empty
/// when there are none. Keep its original sign-in name for compatibility with older releases.
const HANDED_ENV: &str = "VK_HUB_LOGINS_FD";

/// In debug builds, hold hand-over after staging until the named file exists. The hub still
/// accepts, so a test can open a connection it must answer across hand-over.
#[cfg(debug_assertions)]
const HOLD_ENV: &str = "VK_HUB_TEST_HOLD_HANDOVER";

/// [`Handed`]'s format, which a release reads only if it knows it. Fields added since read as
/// empty from a hub that did not write them, and a release that does not know one ignores it.
const HANDED_FORMAT: u32 = 1;

/// The most of [`Handed`] a release reads: far more than the sign-ins a hub keeps under way.
/// Questions, which may each hold a capacity policy's edit, are handed over newest first within
/// it.
const MAX_HANDED: u64 = 4 << 20;

/// What `update/state.json` holds: the installed binary, the trial under way, the update in
/// progress or the last one's end, and the last one asked.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// The binary `serve` last started from outside the update directory.
    #[serde(default)]
    pub installed: Option<PathBuf>,
    #[serde(default)]
    pub trial: Option<Trial>,
    #[serde(default)]
    pub update: Option<UpdateProgress>,
    #[serde(default)]
    pub last: Option<Requested>,
    /// The update whose end was audited.
    #[serde(default)]
    pub audited: Option<String>,
}

/// An update asked of the hub: its ID, release, who asked and when, and how it ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requested {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub actor: String,
    pub at: u64,
    #[serde(default)]
    pub outcome: Option<Outcome>,
}

impl State {
    fn load_from(dir: &Path) -> Result<Self> {
        let path = dir.join(STATE_FILE);
        match vk_peer::net::read_nofollow(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if vk_peer::net::is_not_found(&e) => Ok(State::default()),
            Err(e) => Err(e),
        }
    }

    fn save_to(&self, dir: &Path) -> Result<()> {
        vk_peer::net::create_dir(dir)?;
        let path = dir.join(STATE_FILE);
        let bytes = serde_json::to_vec_pretty(self).context("encoding the update state")?;
        vk_fs::write_atomic_durable(&path, &bytes, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }
}

impl Ledger for State {
    const PROGRAM: &'static str = "vk-hub";
    const PEER: &'static str = "hub";
    const SUBCOMMAND: &'static str = "serve";
    const SETTINGS: &'static str = "[update]";

    fn load(dir: &Path) -> Result<Self> {
        Self::load_from(dir)
    }

    fn save(&self, dir: &Path) -> Result<()> {
        self.save_to(dir)
    }

    fn trial(&mut self) -> &mut Option<Trial> {
        &mut self.trial
    }

    fn set_progress(&mut self, progress: UpdateProgress) {
        self.update = Some(progress);
    }

    fn set_outcome(&mut self, id: &str, outcome: Outcome) {
        if let Some(last) = self.last.as_mut().filter(|l| l.id == id) {
            last.outcome = Some(outcome);
        }
    }

    fn log(event: Event<'_>) {
        match event {
            Event::Unreadable(e) | Event::Unwritable(e) => eprintln!("vk-hub: update: {e:#}"),
            Event::Starting { version, attempt } => {
                eprintln!("vk-hub: update: starting vk-hub {version} on trial, attempt {attempt}");
            }
            Event::RolledBack { version, why } => {
                eprintln!("vk-hub: update: rolled vk-hub {version} back: {why}");
            }
            Event::ConfirmFailed(e) => {
                eprintln!("vk-hub: update: recording that the release passed: {e:#}");
            }
            Event::Installed { version, path } => {
                eprintln!(
                    "vk-hub: update: installed vk-hub {version} at {}",
                    path.display()
                );
            }
            Event::InstallFailed(e) => eprintln!("vk-hub: update: installing: {e:#}"),
            Event::RunInstalledFailed(e) => {
                eprintln!("vk-hub: update: running the installed release: {e:#}");
            }
        }
    }
}

/// The previous binary's part in a trial, before anything else `serve` does
/// ([`trial::on_start`]).
pub fn on_start(dir: &Path) -> trial::Start {
    trial::on_start::<State>(dir, crate::now_secs())
}

/// What lets the hub hand over without losing a job or refusing a connection: the gate its
/// listeners accept through, and whether it takes jobs, places them, and handles node
/// sessions' job messages.
pub struct Handover {
    pub gate: Gate,
    /// Set while the client API takes no new job or reservation.
    intake_paused: AtomicBool,
    /// Set while no job is offered or started.
    placing_paused: AtomicBool,
    /// Held to read by each job message handled and each placing pass, to write by a
    /// hand-over once neither runs.
    turns: tokio::sync::RwLock<()>,
    /// Set from an update's start to its exec or failure: no long call starts.
    updating: AtomicBool,
    /// The long calls under way ([`Handover::long_call`]).
    long_calls: Arc<AtomicUsize>,
}

/// A long call under way — a release, tools or an install medium added, fetched or renamed —
/// until dropped.
pub struct LongCall(Arc<AtomicUsize>);

impl Drop for LongCall {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for Handover {
    fn default() -> Self {
        Handover {
            gate: Gate::new(),
            intake_paused: AtomicBool::new(false),
            placing_paused: AtomicBool::new(false),
            turns: tokio::sync::RwLock::new(()),
            updating: AtomicBool::new(false),
            long_calls: Arc::default(),
        }
    }
}

impl Handover {
    /// Whether the client API takes no new job or reservation.
    pub fn intake_paused(&self) -> bool {
        self.intake_paused.load(Ordering::SeqCst)
    }

    /// Whether no job is offered or started.
    pub fn placing_paused(&self) -> bool {
        self.placing_paused.load(Ordering::SeqCst)
    }

    /// Held while a job message is handled, or a placing pass runs: never across a hand-over.
    pub async fn turn(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.turns.read().await
    }

    /// [`Handover::turn`] now, or `None` while a hand-over holds or waits for them all.
    pub fn try_turn(&self) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        self.turns.try_read().ok()
    }

    /// Count a call that may run for minutes — a release or tools added, a release fetched, an
    /// install medium uploaded or renamed — until the guard drops: refused while the hub updates itself, which would cut it, and
    /// refusing an update meanwhile ([`Handover::hold_long_calls`]).
    pub fn long_call(&self) -> Result<LongCall> {
        // Counted before looking, as the update sets its flag before looking: one of the two
        // sees the other.
        self.long_calls.fetch_add(1, Ordering::SeqCst);
        let call = LongCall(self.long_calls.clone());
        if self.updating.load(Ordering::SeqCst) {
            bail!(
                "the hub is updating itself; try again once it serves the release (`vk-hub \
                 update` shows how the update went)"
            );
        }
        Ok(call)
    }

    /// Start no long call from now on, unless one is under way: then the update is refused.
    pub(crate) fn hold_long_calls(&self) -> Result<()> {
        self.updating.store(true, Ordering::SeqCst);
        if self.long_calls.load(Ordering::SeqCst) > 0 {
            self.updating.store(false, Ordering::SeqCst);
            bail!(
                "a release, tools or an install medium is being added, fetched or renamed, which \
                 the update would cut; update the hub once that has ended"
            );
        }
        Ok(())
    }

    /// Serve as before.
    pub(crate) fn resume(&self) {
        self.updating.store(false, Ordering::SeqCst);
        self.gate.open();
        self.placing_paused.store(false, Ordering::SeqCst);
        self.intake_paused.store(false, Ordering::SeqCst);
    }
}

/// The hub's own update: its state, kept in memory and in `update/state.json`, the listeners it
/// hands over, and what `[update]` allows.
pub struct SelfUpdate {
    dir: PathBuf,
    config: UpdateConfig,
    state: Mutex<State>,
    /// The update directory's lock, held for the data directory ([`lock_instance`]).
    lock: std::fs::File,
    pub passing: Passing,
    /// The web UI's OIDC sign-in, whose sign-ins under way are handed over.
    pub oidc: OnceLock<Arc<crate::ui::OidcSignIn>>,
    /// The web UI's questions asked first, handed over so that an answer the release gets
    /// counts.
    pub questions: Arc<crate::ui::Questions>,
    /// Set from an update's start to its exec or failure.
    busy: AtomicBool,
}

impl Keeper for SelfUpdate {
    type Ledger = State;

    fn dir(&self) -> &Path {
        &self.dir
    }

    fn trial(&self) -> Option<Trial> {
        self.state().trial.clone()
    }

    fn change<R>(&self, f: impl FnOnce(&mut State) -> R) -> Result<R> {
        let mut state = self.lock();
        let mut next = state.clone();
        let out = f(&mut next);
        next.save_to(&self.dir)?;
        *state = next;
        Ok(out)
    }
}

impl SelfUpdate {
    /// Open update state in `dir` under `[update]` policy with `lock` held. Record the running
    /// binary as installed when it is outside `dir`. Set unreadable state aside as
    /// `state.json.unreadable` so a requested update does not prevent startup. Mark an update
    /// interrupted before its trial was recorded as failed.
    pub fn open(dir: &Path, config: UpdateConfig, lock: std::fs::File) -> Result<Self> {
        vk_peer::net::create_dir(dir)?;
        let state = match State::load_from(dir) {
            Ok(state) => state,
            Err(e) => {
                eprintln!("vk-hub: update: {e:#}; setting it aside and starting afresh");
                std::fs::rename(dir.join(STATE_FILE), dir.join("state.json.unreadable"))
                    .with_context(|| format!("setting {} aside", dir.join(STATE_FILE).display()))?;
                State::default()
            }
        };
        let update = SelfUpdate {
            dir: dir.to_path_buf(),
            config,
            state: Mutex::new(state),
            lock,
            passing: Passing::new(),
            oidc: OnceLock::new(),
            questions: Arc::default(),
            busy: AtomicBool::new(false),
        };
        let cut_short = {
            let state = update.state();
            state
                .update
                .filter(|u| {
                    state.trial.is_none()
                        && matches!(
                            u.phase,
                            UpdatePhase::Downloading
                                | UpdatePhase::Draining
                                | UpdatePhase::Validating
                        )
                })
                .map(|u| (u.command, u.version, u.sha256))
        };
        if let Some((id, version, sha256)) = cut_short {
            trial::failed(
                &update,
                &id,
                &version,
                &sha256,
                "the hub stopped before it handed over to the release",
            )?;
        }
        if let Ok(exe) = std::fs::read_link("/proc/self/exe")
            && let Some(installed) =
                trial::installed_after(update.state().installed.as_deref(), exe, dir)
        {
            update.change(|s| s.installed = Some(installed))?;
        }
        Ok(update)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The state now.
    pub fn state(&self) -> State {
        self.lock().clone()
    }

    /// Whether `[update] allow` lets operators update the hub.
    pub fn allowed(&self) -> bool {
        self.config.allow
    }

    /// Whether a release must be signed.
    pub fn requires_signed(&self) -> bool {
        self.config.policy.required()
    }

    /// Whether an update is under way: from its start to its exec or failure, or its release
    /// on trial.
    pub fn under_way(&self) -> bool {
        self.busy.load(Ordering::SeqCst) || self.lock().trial.is_some()
    }
}

/// The hub's update, when it serves as `vk-hub serve`.
fn self_update(hub: &Hub) -> Result<&Arc<SelfUpdate>> {
    hub.self_update.get().ok_or_else(|| {
        anyhow!("this hub does not update itself: only `vk-hub serve` does, not `vk-hub local`")
    })
}

/// Why the hub refuses to update itself to `release`.
pub fn check(hub: &Hub, release: &Release) -> Result<()> {
    if !release.row.is(Program::Hub) {
        bail!(
            "release {} is {} {}, not a {} release",
            crate::store::short(&release.sha256),
            release.row.program(),
            release.row.version,
            Program::Hub
        );
    }
    let update = self_update(hub)?;
    if !update.allowed() {
        bail!("the hub's [update] allow is not set: it does not update itself");
    }
    if update.under_way() {
        bail!("an update of the hub is under way already");
    }
    let own = env!("CARGO_PKG_VERSION");
    let file = crate::releases::path(hub.releases_dir()?, &release.sha256);
    if !takes_over(&file)? {
        bail!(
            "vk-hub {} does not take over the listeners of the hub it replaces, so it could \
             not pass its trial: install it by hand",
            release.row.version
        );
    }
    let outcome = trial::check::<State>(
        &Asked {
            version: &release.row.version,
            sha256: &release.sha256,
            size: release.row.size,
            signature: release.row.signature.as_deref(),
        },
        own,
        update.config.allow_downgrade,
        &update.config.policy,
        update.state().installed.as_deref(),
        &update.dir,
    )
    .map_err(|why| anyhow!("{why}"))?;
    if outcome == Outcome::Done {
        bail!("the hub runs vk-hub {} already", release.row.version);
    }
    Ok(())
}

/// Whether the binary at `path` takes over the listeners handed to it: one built before
/// [`vk_peer::handoff`] holds no [`vk_peer::handoff::ENV`] to read them from. Releases from
/// then on all do; the version alone would not tell a development build from a release.
fn takes_over(path: &Path) -> Result<bool> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    takes_over_read(&mut file).with_context(|| format!("reading {}", path.display()))
}

/// [`takes_over`] for the binary `file` reads.
fn takes_over_read(file: &mut impl std::io::Read) -> std::io::Result<bool> {
    let needle = vk_peer::handoff::ENV.as_bytes();
    let mut window = Vec::with_capacity((1 << 20) + needle.len());
    let mut chunk = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut chunk)?;
        let Some(read) = chunk.get(..n).filter(|r| !r.is_empty()) else {
            return Ok(false);
        };
        window.extend_from_slice(read);
        if window.windows(needle.len()).any(|w| w == needle) {
            return Ok(true);
        }
        // What could start the needle, kept for the next chunk.
        window.drain(..window.len().saturating_sub(needle.len() - 1));
    }
}

/// Create and lock the update directory `dir`, or adopt the previous hub's lock. This rejects
/// a second `vk-hub serve` before it reads or writes update state; the database's lock is
/// acquired too late to protect that state.
pub fn lock_instance(dir: &Path) -> Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(LOCK_FILE);
    let handed = std::env::var(LOCK_ENV)
        .ok()
        .and_then(|fd| fd.parse::<std::os::fd::RawFd>().ok())
        .filter(|fd| *fd > 2)
        .filter(|fd| {
            // The lock file itself, open: a number left in the environment otherwise.
            // SAFETY: a zeroed `stat` is a valid value for fstat to overwrite.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fstat writes only into `st`; a closed descriptor fails with EBADF.
            let open = unsafe { libc::fstat(*fd, &mut st) } == 0;
            open && path
                .symlink_metadata()
                .is_ok_and(|m| m.dev() == st.st_dev && m.ino() == st.st_ino)
        });
    let file = match handed {
        // SAFETY: checked open, and the lock file's: the hub this one replaces passed it for
        // this process to own, once.
        Some(fd) => std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }),
        None => std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?,
    };
    inheritable(&file, false)?;
    // A lock handed over is held already, and taken again at once.
    // SAFETY: flock on an open descriptor touches no memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!(
            "another vk-hub is already serving {} — only one may use a data directory",
            dir.parent().unwrap_or(dir).display()
        );
    }
    Ok(file)
}

/// Make `file` survive an exec, or not: the lock, or the sign-ins under way.
fn inheritable(file: &std::fs::File, on: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: F_GETFD and F_SETFD read and set a descriptor's flags and touch no memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("handing a descriptor over");
    }
    let flags = if on {
        flags & !libc::FD_CLOEXEC
    } else {
        flags | libc::FD_CLOEXEC
    };
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(std::io::Error::last_os_error()).context("handing a descriptor over");
    }
    Ok(())
}

/// Execute `binary` as `on_start` asked, with the sockets a hand-over passed and the `lock`;
/// returns only on failure, the trial then ended: the hub serves on as this binary, and its
/// update must not stay under way.
pub fn exec_on_start(
    dir: &Path,
    lock: &std::fs::File,
    binary: &vk_peer::update::Binary,
    deadline: Option<u64>,
) {
    use std::os::fd::AsRawFd;
    let mut env: Vec<_> = std::env::var_os(vk_peer::handoff::ENV)
        .map(|v| (vk_peer::handoff::ENV.into(), v))
        .into_iter()
        .collect();
    // The sign-ins and questions handed over ([`HANDED_ENV`]) pass on as this process
    // inherited them: their file is still open, taken only once `serve` goes on.
    env.push((LOCK_ENV.into(), lock.as_raw_fd().to_string().into()));
    let e = match inheritable(lock, true) {
        Ok(()) => vk_peer::update::exec_with(binary, deadline, &env),
        Err(e) => e,
    };
    if let Err(e) = inheritable(lock, false) {
        eprintln!("vk-hub: update: {e:#}");
    }
    eprintln!("vk-hub: update: {e:#}; serving on as this binary");
    let ended = (|| -> Result<()> {
        let mut state = State::load_from(dir)?;
        let Some(trial) = state.trial.take() else {
            return Ok(());
        };
        let why = format!("rolled back: the binary could not be executed: {e:#}");
        state.update = Some(UpdateProgress {
            message: Some(why.clone()),
            ..progress(
                &trial.command,
                &trial.version,
                &trial.sha256,
                UpdatePhase::RolledBack,
            )
        });
        state.set_outcome(&trial.command, Outcome::Failed { message: why });
        state.save_to(dir)
    })();
    if let Err(e) = ended {
        eprintln!("vk-hub: update: ending the trial: {e:#}");
    }
}

/// Update the hub to the `vk-hub` release whose sha256 starts with `release`, as `actor`: the
/// update's ID, its hand-over under way.
pub fn start(hub: &Arc<Hub>, actor: &str, release: &str) -> Result<String> {
    let held = hub.releases_lock();
    let release = hub.db.resolve_release(release)?;
    begin(hub, actor, &release, held)
}

/// [`start`] with `shown`, the release an operator confirmed while the hub ran `running`:
/// refused unless the hub still holds it as shown and runs that version.
pub fn start_as_shown(
    hub: &Arc<Hub>,
    actor: &str,
    shown: &Release,
    running: Option<&str>,
) -> Result<String> {
    let held = hub.releases_lock();
    if hub.db.release(&shown.sha256)?.as_ref() != Some(&shown.row) {
        bail!(
            "release {} changed since it was shown; look again",
            crate::store::short(&shown.sha256)
        );
    }
    if running != Some(env!("CARGO_PKG_VERSION")) {
        bail!("the hub's version changed since it was shown; look again");
    }
    begin(hub, actor, shown, held)
}

/// Start updating to `release`, the releases lock `held` until its file is copied.
fn begin(
    hub: &Arc<Hub>,
    actor: &str,
    release: &Release,
    held: std::sync::MutexGuard<'_, ()>,
) -> Result<String> {
    check(hub, release)?;
    let update = self_update(hub)?.clone();
    if update.busy.swap(true, Ordering::SeqCst) {
        bail!("an update of the hub is under way already");
    }
    if let Err(e) = hub.handover.hold_long_calls() {
        update.busy.store(false, Ordering::SeqCst);
        return Err(e);
    }
    // The update's ID once it is recorded: a failure before is no update's to record.
    let mut recorded = None;
    let mut held = Some(held);
    let started = (|| -> Result<(String, Trial, vk_peer::update::Binary)> {
        let mut id = [0u8; 16];
        vk_peer::fill_random(&mut id)?;
        let id = vk_hub_proto::to_hex(&id);
        let now = crate::now_secs();
        update.change(|s| {
            s.last = Some(Requested {
                id: id.clone(),
                version: release.row.version.clone(),
                sha256: release.sha256.clone(),
                actor: actor.to_string(),
                at: now,
                outcome: Some(Outcome::Accepted),
            });
            s.update = Some(progress(
                &id,
                &release.row.version,
                &release.sha256,
                UpdatePhase::Downloading,
            ));
        })?;
        recorded = Some(id.clone());
        hub.db.audit(
            actor,
            &format!(
                "{actor} asked the hub to update itself to vk-hub {} ({})",
                release.row.version,
                crate::store::short(&release.sha256)
            ),
            now,
        )?;
        let from = crate::releases::path(hub.releases_dir()?, &release.sha256);
        let installed = update.state().installed.clone();
        let (trial, binary) = trial::stage_file::<State>(
            &update.dir,
            &from,
            &release.sha256,
            &id,
            &release.row.version,
            installed,
        )
        .map_err(|e| {
            // Recorded as the update's end, by `failed` below.
            e.context("staging the release")
        })?;
        drop(held.take());
        // The copy checked, through its own open file: the held file, read by `check`, could
        // have changed since.
        let staged = format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(binary.file())
        );
        let takes = std::fs::File::open(&staged)
            .and_then(|mut f| takes_over_read(&mut f))
            .context("reading the release staged");
        if !matches!(takes, Ok(true)) {
            // Best effort: a copy left behind costs space until the next trial ends.
            let _ = std::fs::remove_file(&trial.next);
            takes?;
            bail!(
                "vk-hub {} does not take over the listeners of the hub it replaces, so it could \
                 not pass its trial: install it by hand",
                release.row.version
            );
        }
        Ok((id, trial, binary))
    })();
    drop(held);
    match started {
        Ok((id, trial, binary)) => {
            eprintln!(
                "vk-hub: update: {actor} asked for vk-hub {}; handing over",
                release.row.version
            );
            hub.touch();
            tokio::spawn(hand_over(hub.clone(), update, trial, binary));
            Ok(id)
        }
        Err(e) => {
            let id = recorded.unwrap_or_default();
            fail(
                hub,
                &update,
                &id,
                (&release.row.version, &release.sha256),
                &format!("{e:#}"),
            );
            Err(e)
        }
    }
}

/// The progress of update `id` to `version`, hashing to `sha256`, at `phase`.
fn progress(id: &str, version: &str, sha256: &str, phase: UpdatePhase) -> UpdateProgress {
    UpdateProgress {
        command: id.to_string(),
        version: version.to_string(),
        sha256: sha256.to_string(),
        phase,
        message: None,
    }
}

/// Record that update `id` to `(version, sha256)` failed with `why`, and serve on.
fn fail(hub: &Hub, update: &SelfUpdate, id: &str, (version, sha256): (&str, &str), why: &str) {
    eprintln!("vk-hub: update: {why}");
    if !id.is_empty()
        && let Err(e) = trial::failed(update, id, version, sha256, why)
    {
        eprintln!("vk-hub: update: {e:#}");
    }
    update.busy.store(false, Ordering::SeqCst);
    hub.handover.resume();
    audit_end(hub);
    hub.touch();
}

/// Settle the jobs, close the gate and execute `binary`, the release of `trial`; on any
/// failure, serve on.
async fn hand_over(
    hub: Arc<Hub>,
    update: Arc<SelfUpdate>,
    trial: Trial,
    binary: vk_peer::update::Binary,
) {
    let (id, version, sha256) = (
        trial.command.clone(),
        trial.version.clone(),
        trial.sha256.clone(),
    );
    let release = (version.as_str(), sha256.as_str());
    #[cfg(debug_assertions)]
    if let Some(hold) = std::env::var_os(HOLD_ENV).map(std::path::PathBuf::from) {
        while !hold.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    if let Err(e) = update.change(|s| {
        s.update = Some(progress(&id, &version, &sha256, UpdatePhase::Draining));
    }) {
        return fail(&hub, &update, &id, release, &format!("{e:#}"));
    }
    hub.touch();
    let quiet = match settle(&hub).await {
        Ok(quiet) => quiet,
        Err(e) => return fail(&hub, &update, &id, release, &format!("{e:#}")),
    };
    hub.handover.gate.close();
    eprintln!(
        "vk-hub: update: stopped accepting; {} connections open",
        hub.handover.gate.live()
    );
    if !hub.handover.gate.drained(GRACE).await {
        eprintln!(
            "vk-hub: update: {} connections still open after {GRACE:?}; they are cut",
            hub.handover.gate.live()
        );
    }
    let (h, u) = (hub.clone(), update.clone());
    let exec = tokio::task::spawn_blocking(move || execute(&h, &u, trial, &binary)).await;
    drop(quiet);
    let why = match exec {
        Ok(e) => format!("{e:#}"),
        Err(e) => {
            // `execute` panicked, perhaps between sealing the database and unsealing it, or
            // with the sign-ins taken: writes and sign-ins resume, those taken lost.
            hub.db.unseal();
            if let Some(oidc) = update.oidc.get() {
                oidc.restore_pending(Vec::new());
            }
            if let Err(e) = inheritable(&update.lock, false) {
                eprintln!("vk-hub: update: {e:#}");
            }
            format!("executing the release: {e}")
        }
    };
    fail(&hub, &update, &id, release, &why);
}

/// Take no new job, wait for those queued to start, place no more and wait for the starts
/// sent to be answered, then hold off job messages and placing: the guard to drop to let them
/// run again.
pub(crate) async fn settle(hub: &Hub) -> Result<tokio::sync::RwLockWriteGuard<'_, ()>> {
    let handover = &hub.handover;
    handover.intake_paused.store(true, Ordering::SeqCst);
    let waiting = |starting: bool| {
        let state = hub.dispatch.waiting();
        if starting { state.1 } else { state.0 }
    };
    if !wait_for(hub, QUEUE_WAIT, || waiting(false) == 0).await {
        bail!(
            "jobs still waited for a node after {QUEUE_WAIT:?} ({}), and would have been lost; \
             nothing changed, update again once the fleet has room",
            waiting(false)
        );
    }
    handover.placing_paused.store(true, Ordering::SeqCst);
    if !wait_for(hub, START_WAIT, || waiting(true) == 0).await {
        bail!(
            "jobs sent to a node were still unanswered after {START_WAIT:?} ({}); nothing \
             changed",
            waiting(true)
        );
    }
    let quiet = tokio::time::timeout(QUIET_WAIT, handover.turns.write())
        .await
        .map_err(|_| anyhow!("job messages were still being handled after {QUIET_WAIT:?}"))?;
    // A start refused while the hub waited sends its job back to the queue.
    if waiting(false) + waiting(true) > 0 {
        bail!("a job went back to the queue meanwhile; nothing changed");
    }
    Ok(quiet)
}

/// Whether `done` holds within `within`, looked at as the jobs change.
async fn wait_for(hub: &Hub, within: Duration, done: impl Fn() -> bool) -> bool {
    tokio::time::timeout(within, async {
        loop {
            let mut changed = hub.dispatch.subscribe();
            if done() {
                return;
            }
            tokio::select! {
                _ = changed.changed() => {}
                () = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
        }
    })
    .await
    .is_ok()
}

/// Seal the database, record the trial and execute the release with the listening sockets;
/// returns only on failure, the database unsealed, for [`fail`] to undo the trial.
fn execute(
    hub: &Hub,
    update: &SelfUpdate,
    trial: Trial,
    binary: &vk_peer::update::Binary,
) -> anyhow::Error {
    if let Err(e) = hub.db.seal() {
        return e.context("sealing the database");
    }
    let trial = Trial {
        deadline: crate::now_secs() + TRIAL_WINDOW.as_secs(),
        ..trial
    };
    let (deadline, version) = (trial.deadline, trial.version.clone());
    let validating = progress(
        &trial.command,
        &trial.version,
        &trial.sha256,
        UpdatePhase::Validating,
    );
    if let Err(e) = update.change(|s| {
        s.trial = Some(trial);
        s.update = Some(validating);
    }) {
        hub.db.unseal();
        return e.context("recording the trial");
    }
    let names = update.passing.names().join(", ");
    let prepared = match update.passing.prepare() {
        Ok(prepared) => prepared,
        Err(e) => {
            hub.db.unseal();
            return e;
        }
    };
    let lock = (
        LOCK_ENV.into(),
        std::os::fd::AsRawFd::as_raw_fd(&update.lock)
            .to_string()
            .into(),
    );
    let oidc = update.oidc.get();
    // Newest first, so that those left behind are the oldest.
    let (mut handed, left_behind) = Handed::taken(
        oidc.map(|o| o.take_pending()).unwrap_or_default(),
        update.questions.take(),
    );
    // Without them the update goes on: a sign-in under way is started again at worst, and a
    // question asked again.
    let carried = match handed.carry() {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "vk-hub: update: the sign-ins under way and questions asked are not handed \
                 over: {e:#}"
            );
            None
        }
    };
    let logins_env = (
        HANDED_ENV.into(),
        carried.as_ref().map_or_else(Default::default, |f| {
            std::os::fd::AsRawFd::as_raw_fd(f).to_string().into()
        }),
    );
    eprintln!("vk-hub: update: executing vk-hub {version} on trial, handing over {names}");
    let e = match inheritable(&update.lock, true)
        .and_then(|()| carried.as_ref().map_or(Ok(()), |f| inheritable(f, true)))
    {
        Ok(()) => {
            vk_peer::update::exec_with(binary, Some(deadline), &[prepared.env(), lock, logins_env])
        }
        Err(e) => e,
    };
    if let Err(e) = inheritable(&update.lock, false) {
        eprintln!("vk-hub: update: {e:#}");
    }
    drop(carried);
    // Those left behind age with the rest.
    handed.questions.extend(left_behind);
    let (logins, questions) = handed.into_parts();
    if let Some(oidc) = oidc {
        oidc.restore_pending(logins);
    }
    update.questions.restore(questions);
    drop(prepared);
    hub.db.unseal();
    e
}

/// What the web UI has under way, as a hub hands it to the release it executes: its OIDC sign-ins
/// and its questions asked first ([`crate::ui::Questions`]), in a sealed memory file the release
/// inherits ([`HANDED_ENV`]), never on disk, as each sign-in holds a PKCE verifier and each
/// question the CSRF token of its session. A release from before sign-ins were handed over does
/// not take it, and keeps it open unread, as its children do: the verifiers of sign-ins it
/// cannot finish. One from before questions were handed over reads the sign-ins and ignores
/// the rest. No `Debug`, for the verifiers and tokens.
#[derive(Serialize, Deserialize)]
struct Handed {
    format: u32,
    /// When they were handed over, Unix milliseconds: the time the exec took is off each.
    at_ms: u64,
    logins: Vec<Login>,
    #[serde(default)]
    questions: Vec<crate::ui::HandedQuestion>,
}

/// A sign-in under way ([`vk_oidc::Pending`]).
#[derive(Serialize, Deserialize)]
struct Login {
    state: String,
    target: String,
    verifier: String,
    left_ms: u64,
}

/// Whether [`take_handed`] has run: the memory file is owned once.
static HANDED_TAKEN: AtomicBool = AtomicBool::new(false);

impl Handed {
    /// Take `pending` and as many `questions`, in order, as fit within [`MAX_HANDED`].
    /// Return the remaining questions for the hub to restore if hand-over fails.
    fn taken(
        pending: Vec<vk_oidc::Pending>,
        questions: Vec<crate::ui::HandedQuestion>,
    ) -> (Self, Vec<crate::ui::HandedQuestion>) {
        let mut handed = Handed {
            format: HANDED_FORMAT,
            at_ms: unix_ms(),
            logins: pending
                .into_iter()
                .map(|p| Login {
                    state: p.state,
                    target: p.target,
                    verifier: p.verifier,
                    left_ms: u64::try_from(p.left.as_millis()).unwrap_or(u64::MAX),
                })
                .collect(),
            questions: Vec::new(),
        };
        let mut room = MAX_HANDED.saturating_sub(json_len(&handed));
        let total = questions.len();
        let mut questions = questions.into_iter();
        while let Some(q) = questions.next() {
            // A comma between two.
            let need = json_len(&q).saturating_add(1);
            if need > room {
                let left: Vec<_> = std::iter::once(q).chain(questions).collect();
                eprintln!(
                    "vk-hub: update: handing over the newest {} of {total} questions asked: the \
                     rest do not fit",
                    total - left.len()
                );
                return (handed, left);
            }
            room -= need;
            handed.questions.push(q);
        }
        (handed, Vec::new())
    }

    /// The sign-ins and questions, each less the time since they were taken.
    fn into_parts(self) -> (Vec<vk_oidc::Pending>, Vec<crate::ui::HandedQuestion>) {
        let since = unix_ms().saturating_sub(self.at_ms);
        let logins = self
            .logins
            .into_iter()
            .map(|l| vk_oidc::Pending {
                state: l.state,
                target: l.target,
                verifier: l.verifier,
                left: Duration::from_millis(l.left_ms.saturating_sub(since)),
            })
            .collect();
        let questions = self
            .questions
            .into_iter()
            .filter(|q| q.left_ms > since)
            .map(|q| crate::ui::HandedQuestion {
                left_ms: q.left_ms - since,
                ..q
            })
            .collect();
        (logins, questions)
    }

    /// A sealed memory file holding them, close-on-exec until handed over; `None` for none.
    fn carry(&self) -> Result<Option<std::fs::File>> {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        if self.logins.is_empty() && self.questions.is_empty() {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(self).context("encoding them")?;
        // SAFETY: memfd_create takes a NUL-terminated name and returns a new descriptor.
        let raw = unsafe {
            libc::memfd_create(
                c"vk-hub-handed".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("creating a memory file");
        }
        // SAFETY: just created, owned by nothing else.
        let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        file.write_all(&bytes).context("writing them")?;
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        // SAFETY: F_ADD_SEALS sets a memory file's seals and touches no memory.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
            return Err(std::io::Error::last_os_error()).context("sealing the memory file");
        }
        Ok(Some(file))
    }

    /// What `file`, a memory file [`Handed::carry`] sealed, holds.
    fn read(file: &std::fs::File) -> Result<Self> {
        use std::io::Read;
        let mut bytes = Vec::new();
        // From its start, whatever read it before through the same open file.
        std::io::Seek::rewind(&mut &*file).context("reading it")?;
        file.take(MAX_HANDED + 1)
            .read_to_end(&mut bytes)
            .context("reading it")?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_HANDED {
            bail!("it is larger than {MAX_HANDED} bytes");
        }
        #[derive(Deserialize)]
        struct Format {
            format: u32,
        }
        let format: Format = serde_json::from_slice(&bytes).context("parsing it")?;
        if format.format != HANDED_FORMAT {
            bail!(
                "it is in format {}, and this release reads {HANDED_FORMAT}",
                format.format
            );
        }
        serde_json::from_slice(&bytes).context("parsing it")
    }
}

/// Whether `fd` is a memory file sealed against writes, as [`Handed::carry`] leaves one: not the
/// lock file, nor any other file a number left in the environment could name.
fn sealed(fd: std::os::fd::RawFd) -> bool {
    // SAFETY: F_GET_SEALS reads a descriptor's seals and touches no memory; it fails on a
    // descriptor not open, and on anything but a memory file.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    seals >= 0 && seals & libc::F_SEAL_WRITE != 0
}

/// JSON length in bytes, or `u64::MAX` if encoding fails.
fn json_len(v: &impl Serialize) -> u64 {
    serde_json::to_vec(v).map_or(u64::MAX, |b| u64::try_from(b.len()).unwrap_or(u64::MAX))
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Take the previous hub's OIDC sign-ins and questions ([`HANDED_ENV`]), subtracting elapsed
/// time from their remaining lifetimes. Only the first call takes them and closes the memory
/// file. Like [`vk_peer::handoff::ENV`], the variable stays in the environment but each
/// hand-over replaces it, so no release receives a stale descriptor. [`exec_on_start`] runs
/// first and passes it on while the file is still open.
pub fn take_handed() -> (Vec<vk_oidc::Pending>, Vec<crate::ui::HandedQuestion>) {
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    if HANDED_TAKEN.swap(true, Ordering::SeqCst) {
        return Default::default();
    }
    let Some(value) = std::env::var(HANDED_ENV).ok().filter(|v| !v.is_empty()) else {
        return Default::default();
    };
    let fd = match value.parse::<RawFd>() {
        Ok(fd) if fd > 2 => fd,
        _ => {
            eprintln!("vk-hub: update: {HANDED_ENV}={value:?} is not a descriptor; ignored");
            return Default::default();
        }
    };
    if !sealed(fd) {
        eprintln!(
            "vk-hub: update: {HANDED_ENV}: descriptor {fd} is not a sealed memory file; ignored"
        );
        return Default::default();
    }
    // SAFETY: open, and a sealed memory file, which neither a socket handed over nor the lock
    // is; the hub this one replaces passed it for this process to own, once.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    match Handed::read(&file) {
        Ok(handed) => handed.into_parts(),
        Err(e) => {
            eprintln!(
                "vk-hub: update: the sign-ins under way and questions asked handed over: {e:#}; \
                 dropped"
            );
            Default::default()
        }
    }
}

/// The release on trial has served for [`SETTLE`]: record that it passed, install it and end
/// the update ([`trial::confirm`]), unless `serving` ended first.
pub async fn confirm_after_settling(hub: Arc<Hub>, serving: tokio::sync::watch::Receiver<bool>) {
    let Ok(update) = self_update(&hub).cloned() else {
        return;
    };
    if update.trial().is_none() {
        return;
    }
    tokio::time::sleep(SETTLE).await;
    if !*serving.borrow() {
        return;
    }
    // A panic there is logged by the runtime and leaves the trial unconfirmed: the next start
    // takes it for a release that did not pass.
    let _ = tokio::task::spawn_blocking({
        let (hub, update) = (hub.clone(), update.clone());
        move || {
            trial::confirm(&*update);
            audit_end(&hub);
        }
    })
    .await;
    hub.touch();
}

/// Audit how the last update ended, once: done, rolled back or failed. The previous binary
/// rolled back before the database was open; the release confirmed after.
pub fn audit_end(hub: &Hub) {
    let Ok(update) = self_update(hub) else {
        return;
    };
    let state = update.state();
    let Some(progress) = state.update.as_ref().filter(|u| {
        matches!(
            u.phase,
            UpdatePhase::Done | UpdatePhase::RolledBack | UpdatePhase::Failed
        ) && state.audited.as_deref() != Some(u.command.as_str())
    }) else {
        return;
    };
    let event = match progress.phase {
        UpdatePhase::Done => format!("the hub updated itself to vk-hub {}", progress.version),
        UpdatePhase::RolledBack => format!(
            "the hub rolled vk-hub {} back: {}",
            progress.version,
            progress
                .message
                .as_deref()
                .unwrap_or("it did not pass its trial")
        ),
        _ => format!(
            "the hub's update to vk-hub {} failed: {}",
            progress.version,
            progress.message.as_deref().unwrap_or("no reason given")
        ),
    };
    let command = progress.command.clone();
    match hub.db.audit("vk-hub", &event, crate::now_secs()) {
        Ok(()) => {
            if let Err(e) = update.change(|s| s.audited = Some(command)) {
                eprintln!("vk-hub: update: {e:#}");
            }
        }
        Err(e) => eprintln!("vk-hub: update: auditing its end: {e:#}"),
    }
}

/// The hub's update as `/updates` and `vk-hub update` show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    /// Whether `[update] allow` is set; `None` for a hub that does not update itself.
    pub allowed: Option<bool>,
    pub requires_signed: bool,
    /// Whether `[update] allow_downgrade` is set.
    #[serde(default)]
    pub allows_downgrade: bool,
    pub update: Option<UpdateProgress>,
    pub last: Option<Requested>,
}

/// The hub's update now.
pub fn status(hub: &Hub) -> Status {
    let update = self_update(hub).ok();
    let state = update.map(|u| u.state()).unwrap_or_default();
    Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        allowed: update.map(|u| u.allowed()),
        requires_signed: update.is_some_and(|u| u.requires_signed()),
        allows_downgrade: update.is_some_and(|u| u.config.allow_downgrade),
        update: state.update,
        last: state.last,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An update is refused while a long call runs, and a long call while an update runs, until
    /// it has failed.
    #[test]
    fn a_long_call_and_an_update_do_not_overlap() {
        let handover = Handover::default();
        let call = handover.long_call().unwrap();
        let refused = handover.hold_long_calls().unwrap_err();
        assert!(
            format!("{refused:#}").contains("being added, fetched or renamed"),
            "{refused:#}"
        );
        drop(call);
        handover.hold_long_calls().unwrap();
        let Err(refused) = handover.long_call() else {
            panic!("a long call started while the hub updates itself");
        };
        assert!(
            format!("{refused:#}").contains("updating itself"),
            "{refused:#}"
        );
        assert_eq!(handover.long_calls.load(Ordering::SeqCst), 0);
        handover.resume();
        assert!(handover.long_call().is_ok());
    }

    /// The sign-ins under way and questions asked go in a sealed memory file, read back less
    /// the time since; a file that is not one is not read, and none goes when there are none.
    #[test]
    fn sign_ins_and_questions_are_handed_over_in_a_sealed_memory_file() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        assert!(
            Handed::taken(Vec::new(), Vec::new())
                .0
                .carry()
                .unwrap()
                .is_none()
        );
        let question = || crate::ui::HandedQuestion {
            nonce: "the-nonce".into(),
            session: "the-csrf".into(),
            path: "/rollouts".into(),
            op: "create".into(),
            asked: vec![("release".into(), "abc".into())],
            answered: false,
            left_ms: 60_000,
        };
        let (only_question, _) = Handed::taken(Vec::new(), vec![question()]);
        assert!(only_question.carry().unwrap().is_some());
        let (handed, _) = Handed::taken(
            vec![vk_oidc::Pending {
                state: "the-state".into(),
                target: "/".into(),
                verifier: "the-verifier".into(),
                left: Duration::from_secs(60),
            }],
            vec![question()],
        );
        let file = handed.carry().unwrap().unwrap();
        assert!(sealed(file.as_raw_fd()));
        assert!((&file).write_all(b"more").is_err());
        let (back, questions) = Handed::read(&file).unwrap().into_parts();
        assert_eq!(back.len(), 1);
        let (p, left) = (&back[0], back[0].left);
        assert_eq!(
            (p.state.as_str(), p.target.as_str(), p.verifier.as_str()),
            ("the-state", "/", "the-verifier")
        );
        assert!(left <= Duration::from_secs(60) && left > Duration::from_secs(50));
        assert_eq!(questions.len(), 1);
        assert!(questions[0].left_ms <= 60_000 && questions[0].left_ms > 50_000);
        let q = &questions[0];
        assert_eq!(
            (
                q.nonce.as_str(),
                q.session.as_str(),
                q.path.as_str(),
                q.op.as_str()
            ),
            ("the-nonce", "the-csrf", "/rollouts", "create")
        );
        assert_eq!(q.asked, question().asked);
        assert!(!q.answered);
        // Read again from its start.
        assert_eq!(Handed::read(&file).unwrap().logins.len(), 1);
        let plain = std::fs::File::open("/proc/self/exe").unwrap();
        assert!(!sealed(plain.as_raw_fd()));
        assert!(!sealed(-1));
    }

    /// What a hub from before questions were handed over writes reads with none; questions
    /// past what a release reads, in the order given, stay behind with the hub.
    #[test]
    fn questions_past_the_limit_stay_behind() {
        let old = br#"{"format":1,"at_ms":0,"logins":[]}"#;
        let handed: Handed = serde_json::from_slice(old).unwrap();
        assert!(handed.questions.is_empty());
        let big = |nonce: &str| crate::ui::HandedQuestion {
            nonce: nonce.into(),
            session: String::new(),
            path: String::new(),
            op: String::new(),
            asked: vec![("policy".into(), "x".repeat(1 << 20))],
            answered: false,
            left_ms: 1,
        };
        let questions: Vec<_> = (0..6).map(|i| big(&i.to_string())).collect();
        let (handed, left) = Handed::taken(Vec::new(), questions);
        let kept: Vec<_> = handed.questions.iter().map(|q| q.nonce.as_str()).collect();
        assert_eq!(kept, ["0", "1", "2"]);
        let left: Vec<_> = left.iter().map(|q| q.nonce.as_str()).collect();
        assert_eq!(left, ["3", "4", "5"]);
        assert!(json_len(&handed) <= MAX_HANDED);
    }

    /// A release takes over the listeners when it names where it reads them from, wherever
    /// that falls in the file, a read's edge included.
    #[test]
    fn a_release_takes_over_when_it_reads_the_listeners_handed_to_it() {
        let dir = std::env::temp_dir().join(format!("vk-hub-takes-over-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("vk-hub");
        let needle = vk_peer::handoff::ENV.as_bytes();
        for at in [0, 5, (1 << 20) - 3, 1 << 20] {
            let mut bytes = vec![0u8; at];
            bytes.extend_from_slice(needle);
            bytes.extend_from_slice(b"rest");
            std::fs::write(&file, &bytes).unwrap();
            assert!(takes_over(&file).unwrap(), "at {at}");
        }
        let mut bytes = vec![0u8; (1 << 20) + 7];
        bytes.extend_from_slice(&needle[..needle.len() - 1]);
        std::fs::write(&file, &bytes).unwrap();
        assert!(!takes_over(&file).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An update the hub stopped during, before it recorded a trial, is failed when it starts
    /// again, rather than shown under way for ever.
    #[test]
    fn an_update_cut_short_before_its_trial_is_failed() {
        let dir = std::env::temp_dir().join(format!("vk-hub-cut-short-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lock = lock_instance(&dir).unwrap();
        State {
            update: Some(progress(
                "a",
                "0.200.0",
                &"0".repeat(64),
                UpdatePhase::Draining,
            )),
            last: Some(Requested {
                id: "a".into(),
                version: "0.200.0".into(),
                sha256: "0".repeat(64),
                actor: "uid 0".into(),
                at: 1,
                outcome: Some(Outcome::Accepted),
            }),
            ..State::default()
        }
        .save_to(&dir)
        .unwrap();
        let update = SelfUpdate::open(&dir, UpdateConfig::default(), lock).unwrap();
        let state = update.state();
        assert_eq!(state.update.unwrap().phase, UpdatePhase::Failed);
        assert!(matches!(
            state.last.unwrap().outcome,
            Some(Outcome::Failed { .. })
        ));
        assert!(!update.under_way());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release the previous binary cannot execute as it starts ends the trial rolled back:
    /// the hub serves on, free to update again.
    #[test]
    fn a_release_that_cannot_be_executed_on_start_is_rolled_back() {
        let dir = std::env::temp_dir().join(format!("vk-hub-no-exec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lock = lock_instance(&dir).unwrap();
        // Not executable: the exec fails, whatever runs the test.
        let next = dir.join("next");
        std::fs::write(&next, b"not a binary").unwrap();
        State {
            trial: Some(Trial {
                command: "a".into(),
                version: "0.200.0".into(),
                sha256: "0".repeat(64),
                exe: dir.join("exe"),
                exe_id: (0, 0),
                next: next.clone(),
                previous: "1".repeat(64),
                attempts: 1,
                deadline: u64::MAX - 1,
                confirmed: false,
            }),
            ..State::default()
        }
        .save_to(&dir)
        .unwrap();
        let binary = vk_peer::update::Binary::open(&next, None).unwrap();
        exec_on_start(&dir, &lock, &binary, None);
        let state = State::load_from(&dir).unwrap();
        assert!(state.trial.is_none());
        assert_eq!(state.update.unwrap().phase, UpdatePhase::RolledBack);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release that cannot be executed leaves the hub as it was: its database writable, its
    /// lock close-on-exec again, the update failed and no trial left.
    #[test]
    fn a_release_that_cannot_be_executed_leaves_the_hub_serving() {
        use std::os::fd::AsRawFd;
        let dir = std::env::temp_dir().join(format!("vk-hub-exec-fails-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lock = lock_instance(&dir).unwrap();
        let update = SelfUpdate::open(&dir, UpdateConfig::default(), lock).unwrap();
        let db = crate::store::Db::open_memory().unwrap();
        let hub = Hub::new(Arc::new(db), None);
        // Not executable: the exec fails, whatever runs the test.
        let next = dir.join("next");
        std::fs::write(&next, b"not a binary").unwrap();
        let binary = vk_peer::update::Binary::open(&next, None).unwrap();
        let trial = Trial {
            command: "a".into(),
            version: "0.200.0".into(),
            sha256: "0".repeat(64),
            exe: dir.join("exe"),
            exe_id: (0, 0),
            next,
            previous: "1".repeat(64),
            attempts: 1,
            deadline: 0,
            confirmed: false,
        };
        update
            .change(|s| {
                s.last = Some(Requested {
                    id: "a".into(),
                    version: "0.200.0".into(),
                    sha256: "0".repeat(64),
                    actor: "uid 0".into(),
                    at: 1,
                    outcome: Some(Outcome::Accepted),
                });
            })
            .unwrap();
        let e = execute(&hub, &update, trial, &binary);
        fail(
            &hub,
            &update,
            "a",
            ("0.200.0", &"0".repeat(64)),
            &format!("{e:#}"),
        );
        hub.db.audit("uid 0", "written after", 1).unwrap();
        // SAFETY: F_GETFD reads a descriptor's flags and touches no memory.
        let flags = unsafe { libc::fcntl(update.lock.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        let state = update.state();
        assert!(state.trial.is_none());
        assert!(matches!(
            state.last.and_then(|l| l.outcome),
            Some(Outcome::Failed { .. })
        ));
        assert_eq!(state.update.unwrap().phase, UpdatePhase::Failed);
        assert!(!update.under_way());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sign-ins handed over are refused larger than the bound, or in another format.
    #[test]
    fn sign_ins_too_large_or_of_another_format_are_not_read() {
        let dir = std::env::temp_dir().join(format!("vk-hub-logins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = |bytes: &[u8]| {
            let path = dir.join("logins");
            std::fs::write(&path, bytes).unwrap();
            std::fs::File::open(&path).unwrap()
        };
        let large = vec![b' '; usize::try_from(MAX_HANDED).unwrap() + 1];
        let e = Handed::read(&file(&large)).err().unwrap();
        assert!(format!("{e:#}").contains("larger than"), "{e:#}");
        let other = format!(
            r#"{{"format":{},"at_ms":0,"logins":[]}}"#,
            HANDED_FORMAT + 1
        );
        let e = Handed::read(&file(other.as_bytes())).err().unwrap();
        assert!(format!("{e:#}").contains("in format"), "{e:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An older release is refused naming the hub's own setting.
    #[test]
    fn a_downgrade_is_refused_naming_the_hub_s_setting() {
        let e = trial::check_version::<State>("0.101.0", "0.100.0", false).unwrap_err();
        assert!(e.contains("[update] allow_downgrade = true"), "{e}");
    }

    /// The update directory is locked for one `serve`; the lock handed over is taken.
    #[test]
    fn one_serve_holds_the_update_directory() {
        let dir = std::env::temp_dir().join(format!("vk-hub-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let held = lock_instance(&dir).unwrap();
        let e = lock_instance(&dir).unwrap_err();
        assert!(format!("{e:#}").contains("already serving"), "{e:#}");
        drop(held);
        lock_instance(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A state written by a hub knows nothing it does not hold; one with every field reads
    /// back as written.
    #[test]
    fn the_state_reads_back_as_written() {
        let dir = std::env::temp_dir().join(format!("vk-hub-update-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(State::load_from(&dir).unwrap().trial.is_none());
        let state = State {
            installed: Some("/usr/local/bin/vk-hub".into()),
            last: Some(Requested {
                id: "a".into(),
                version: "0.102.0".into(),
                sha256: "0".repeat(64),
                actor: "uid 0".into(),
                at: 1,
                outcome: None,
            }),
            ..State::default()
        };
        state.save_to(&dir).unwrap();
        let mut read = State::load_from(&dir).unwrap();
        assert_eq!(read.installed, state.installed);
        assert_eq!(read.last, state.last);
        read.set_outcome("a", Outcome::Done);
        assert_eq!(read.last.unwrap().outcome, Some(Outcome::Done));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
