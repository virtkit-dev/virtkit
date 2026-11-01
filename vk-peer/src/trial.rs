//! Trial self-updates from a peer's hub, built on [`crate::update`].
//!
//! 1. [`check`] decides whether the peer takes an update command;
//! 2. [`stage`] downloads the release under the peer's signature into
//!    `<dir>/releases/<sha256>`, checks its digest, size and `--version`, and keeps the running
//!    binary beside it, by its own sha256, to go back to;
//! 3. the peer handles any prerequisites, such as ending work in flight, records the [`Trial`],
//!    and executes the release in its place with [`exec`](crate::update::exec), `alarm(2)`
//!    armed past the trial's deadline;
//! 4. the release, once it is in session with the hub, [`confirm`]s: it records that it passed,
//!    then installs itself over the installed binary's path, by rename, and reports the update
//!    done. A peer stopped in between finishes the install on its next start.
//!
//! Until then the installed binary is left as it is: whatever starts the peer — a supervisor
//! restarting a release that crashed or hung, or a person — starts the previous one, which
//! counts the attempt and hands over again ([`on_start`]), or, past [`MAX_ATTEMPTS`] or the
//! deadline, takes the peer back and reports the update rolled back. So the peer needs a
//! supervisor that restarts it: a release that cannot reach the hub is ended by its alarm, and
//! nothing else starts the peer again.
//!
//! The installed binary is the one the peer last started from outside its hub directory
//! ([`installed_after`]): a confirmed release goes on running from `releases/`, and the next
//! update still replaces the installed path.
//!
//! Each peer keeps the trial in a state of its own, written whole, through [`Ledger`], and
//! changes it while running through a [`Keeper`].

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{Outcome, UpdatePhase, UpdateProgress};

use crate::release_key::Policy;
use crate::update::{Binary, Download, keep_previous, own_sha256, running_is};

/// How many times a release on trial may be started before the previous binary takes the peer
/// back.
pub const MAX_ATTEMPTS: u32 = 3;

/// How long a release on trial has to reach the hub.
pub const TRIAL_WINDOW: Duration = Duration::from_secs(120);

/// The largest release a peer takes, whatever a command says.
const MAX_RELEASE: u64 = 1 << 30;

/// How long a download may take in all.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Where a peer keeps its releases, under its hub directory `dir`.
pub fn releases_dir(dir: &Path) -> PathBuf {
    dir.join("releases")
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
    /// The release, under the hub directory's `releases/`.
    pub next: PathBuf,
    /// The installed binary's sha256, kept there too to go back to.
    pub previous: String,
    /// Release starts, reset to zero on confirmation, and the deadline to reach the hub.
    pub attempts: u32,
    pub deadline: u64,
    /// The release reached the hub: what is left is installing it, which any start finishes.
    /// [`Trial::passed`] recognizes confirmation even if a previous binary drops this field.
    #[serde(default)]
    pub confirmed: bool,
}

/// No deadline: the passed marker survives saves by binaries that ignore `confirmed`.
const PASSED: u64 = u64::MAX;

impl Trial {
    /// Whether the release reached the hub, using the deadline if an older binary dropped
    /// `confirmed`.
    pub fn passed(&self) -> bool {
        self.confirmed || self.deadline == PASSED
    }
}

/// What [`on_start`] and [`confirm`] tell the peer's log.
#[derive(Debug)]
pub enum Event<'a> {
    /// The state could not be read: the peer runs on.
    Unreadable(&'a anyhow::Error),
    /// The state could not be written.
    Unwritable(&'a anyhow::Error),
    /// The release is started again, this being its `attempt`th start.
    Starting { version: &'a str, attempt: u32 },
    /// The trial ended, failed for `why`: the previous binary runs on.
    RolledBack { version: &'a str, why: &'a str },
    /// Recording the confirmation failed: the release is not installed, and stays on trial.
    ConfirmFailed(&'a anyhow::Error),
    /// The release replaced the installed binary at `path`.
    Installed { version: &'a str, path: &'a Path },
    /// The release could not be installed, or its end recorded.
    InstallFailed(&'a anyhow::Error),
    /// The release installed on start could not be started: the current binary runs on.
    RunInstalledFailed(&'a anyhow::Error),
}

/// A peer's persisted state, which holds its trial among the rest.
pub trait Ledger: Sized {
    /// The program, as releases name it: `vk-registry`.
    const PROGRAM: &'static str;
    /// What the peer is: `registry`.
    const PEER: &'static str;
    /// The subcommand that runs it: `serve`.
    const SUBCOMMAND: &'static str;

    /// The state in `dir`, empty when there is none.
    fn load(dir: &Path) -> Result<Self>;
    /// Write it whole into `dir`.
    fn save(&self, dir: &Path) -> Result<()>;
    /// The trial under way, if any.
    fn trial(&mut self) -> &mut Option<Trial>;
    /// The update in progress, or the last one's end.
    fn set_progress(&mut self, progress: UpdateProgress);
    /// Record command `id`'s new outcome.
    fn set_outcome(&mut self, id: &str, outcome: Outcome);
    fn log(event: Event<'_>);
}

/// Holds a running peer's [`Ledger`].
pub trait Keeper {
    type Ledger: Ledger;
    /// The hub directory.
    fn dir(&self) -> &Path;
    /// The trial recorded now.
    fn trial(&self) -> Option<Trial>;
    /// Change the state with `f` and save it. A failed save leaves memory unchanged,
    /// but may have published the new state on disk.
    fn change<R>(&self, f: impl FnOnce(&mut Self::Ledger) -> R) -> Result<R>;
}

/// What the peer does on starting.
pub enum Start {
    Run,
    /// Execute this binary in place of this one, `alarm(2)` armed for this deadline.
    Exec(Binary, Option<u64>),
}

/// Set the moment SIGTERM or SIGINT arrives, before any task handling them runs: what the last
/// check before an exec reads.
static SIGNALLED: AtomicBool = AtomicBool::new(false);

/// Note SIGTERM and SIGINT in [`signalled`] as they arrive, beside the peer's own handling;
/// once, before an update can start. Only for a peer that handles them: noting one replaces
/// its default action.
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

/// Whether SIGTERM or SIGINT arrived since [`note_signals`].
pub fn signalled() -> bool {
    SIGNALLED.load(Ordering::SeqCst)
}

/// The previous binary's part in a trial, run by the peer before anything else: count the
/// start and hand over to the release, or, past [`MAX_ATTEMPTS`] or the deadline, end the
/// trial and run on as the peer's binary. A confirmed trial is installed and its release run.
/// The release on trial arms its own deadline. A state that cannot be read or written is
/// logged and the peer runs: what the hub asked must never stop it.
pub fn on_start<L: Ledger>(dir: &Path, now: u64) -> Start {
    if !dir.is_dir() {
        return Start::Run;
    }
    let mut p = match L::load(dir) {
        Ok(p) => p,
        Err(e) => {
            L::log(Event::Unreadable(&e));
            return Start::Run;
        }
    };
    let save = |p: &L| {
        if let Err(e) = p.save(dir) {
            L::log(Event::Unwritable(&e));
        }
    };
    let Some(trial) = p.trial().clone() else {
        return Start::Run;
    };
    if trial.passed() {
        return finish_install(dir, &mut p, &trial);
    }
    if running_is(&trial.next) {
        crate::update::alarm(Some(trial.deadline), now);
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
            if let Some(t) = p.trial() {
                t.attempts += 1;
            }
            save(&p);
            L::log(Event::Starting {
                version: &trial.version,
                attempt: trial.attempts + 1,
            });
            Start::Exec(binary, Some(trial.deadline))
        }
        Err(why) => {
            L::log(Event::RolledBack {
                version: &trial.version,
                why: &why,
            });
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
            prune(dir, &[&trial.previous]);
            Start::Run
        }
    }
}

/// Install `trial`'s release, confirmed by the hub but not installed before the peer stopped,
/// and end the update; then run the release, if this is another binary. An end that could not
/// be saved leaves the trial to the release, which ends it on its next start or confirmation.
fn finish_install<L: Ledger>(dir: &Path, p: &mut L, trial: &Trial) -> Start {
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
    let saved = p.save(dir);
    if let Err(e) = &saved {
        L::log(Event::Unwritable(e));
    }
    if let Err(e) = installed {
        L::log(Event::InstallFailed(&e));
        return Start::Run;
    }
    // Unsaved, the trial is left to the release, which logs the install when it ends it.
    if saved.is_ok() {
        prune(dir, &[&trial.sha256, &trial.previous]);
        L::log(Event::Installed {
            version: &trial.version,
            path: &trial.exe,
        });
    }
    if own_sha256().as_deref() == Some(trial.sha256.as_str()) {
        return Start::Run;
    }
    match Binary::open(&trial.exe, Some(&trial.sha256)) {
        Ok(binary) => Start::Exec(binary, None),
        Err(e) => {
            L::log(Event::RunInstalledFailed(&e));
            Start::Run
        }
    }
}

/// The installed binary to record when the peer runs `exe`, `recorded` before; `None` to keep
/// what is recorded. A binary under the hub directory `dir` is a release, never the installed
/// one.
pub fn installed_after(recorded: Option<&Path>, exe: PathBuf, dir: &Path) -> Option<PathBuf> {
    (exe.is_file() && !crate::update::under(&exe, dir) && recorded != Some(exe.as_path()))
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
fn end<L: Ledger>(
    p: &mut L,
    trial: &Trial,
    phase: UpdatePhase,
    outcome: Outcome,
    why: Option<String>,
) {
    *p.trial() = None;
    p.set_progress(UpdateProgress {
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
    if crate::update::hash_file(&trial.exe).ok().as_deref() == Some(trial.sha256.as_str()) {
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
    crate::update::copy_published(&trial.next, &trial.exe, mode, Some(&trial.sha256))
}

/// Whether the peer may install over the installed binary `installed`: recorded, a file
/// outside `dir`, in a directory this user can write, since the release is renamed into it.
fn can_replace<L: Ledger>(installed: Option<&Path>, dir: &Path) -> Result<(), String> {
    let (program, peer) = (L::PROGRAM, L::PEER);
    let exe = installed.ok_or_else(|| {
        format!(
            "the installed {program} is not known yet: restart {program} {} from it",
            L::SUBCOMMAND
        )
    })?;
    if !exe.is_file() {
        return Err(format!("{} is gone", exe.display()));
    }
    if crate::update::under(exe, dir) {
        return Err(format!(
            "{} is inside the {peer}'s hub directory; run {program} from its installed path",
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
            "{program} cannot replace {}: {} is not writable by this user",
            exe.display(),
            parent.display()
        ));
    }
    Ok(())
}

/// Whether a peer running `own` may update to `candidate`: not to an older version unless
/// `allow_downgrade`. Versions are `MAJOR.MINOR.PATCH`.
pub fn check_version<L: Ledger>(
    own: &str,
    candidate: &str,
    allow_downgrade: bool,
) -> Result<(), String> {
    fn fields(v: &str) -> Option<Vec<u64>> {
        let v: Vec<u64> = v
            .split('.')
            .map(|f| f.parse().ok())
            .collect::<Option<_>>()?;
        (v.len() == 3).then_some(v)
    }
    let (program, peer) = (L::PROGRAM, L::PEER);
    match (fields(candidate), fields(own)) {
        (Some(c), Some(o)) if c >= o || allow_downgrade => Ok(()),
        (Some(_), Some(_)) => Err(format!(
            "{program} {candidate} is older than this {peer}'s {own}; [hub] allow_downgrade = \
             true lets an update install it"
        )),
        _ if candidate == own => Ok(()),
        _ => Err(format!(
            "{program} {candidate} cannot be ordered against {own}; versions are \
             MAJOR.MINOR.PATCH"
        )),
    }
}

/// An update a hub asks of a peer.
pub struct Asked<'a> {
    pub version: &'a str,
    pub sha256: &'a str,
    pub size: u64,
    pub signature: Option<&'a str>,
}

/// Whether the peer, running `own_version`, takes the update `asked`: `Ok` with its first
/// outcome — done already when it runs the release — or `Err` with why it refuses. Whether
/// another update is under way, or the peer stopping, is the peer's to check first.
pub fn check<L: Ledger>(
    asked: &Asked<'_>,
    own_version: &str,
    allow_downgrade: bool,
    policy: &Policy,
    installed: Option<&Path>,
    dir: &Path,
) -> Result<Outcome, String> {
    if !vk_hub_proto::valid_sha256(asked.sha256) {
        return Err(format!("{:?} is not a sha256", asked.sha256));
    }
    if asked.size > MAX_RELEASE {
        return Err(format!(
            "the release is {} bytes, past {MAX_RELEASE}",
            asked.size
        ));
    }
    if own_sha256().as_deref() == Some(asked.sha256) {
        return Ok(Outcome::Done);
    }
    check_version::<L>(own_version, asked.version, allow_downgrade)?;
    policy.check(asked.sha256, asked.version, asked.signature)?;
    can_replace::<L>(installed, dir)?;
    Ok(Outcome::Accepted)
}

/// Download `fetch` into `dir`'s releases unless already present, check it is `version` of the
/// peer's program, and keep the running binary beside it. Return command `command`'s trial
/// over `installed`, at its first start with no deadline yet, and the release opened to execute.
pub async fn stage<L: Ledger>(
    dir: &Path,
    fetch: &Download<'_>,
    command: &str,
    version: &str,
    installed: Option<PathBuf>,
) -> Result<(Trial, Binary)> {
    let releases = releases_dir(dir);
    crate::net::create_dir(&releases)?;
    crate::update::sweep_partial(&releases);
    let next = releases.join(fetch.sha256);
    if !next.is_file() {
        tokio::time::timeout(DOWNLOAD_TIMEOUT, crate::update::download(fetch, &next))
            .await
            .map_err(|_| anyhow!("the download took longer than {DOWNLOAD_TIMEOUT:?}"))??;
    }
    let (sha256, command, version) = (
        fetch.sha256.to_string(),
        command.to_string(),
        version.to_string(),
    );
    tokio::task::spawn_blocking(move || {
        check_release::<L>(&releases, next, sha256, command, version, installed)
    })
    .await
    .context("checking the release")?
}

/// Blocking [`stage`] for a local release at `from`. Copy into `dir`'s releases,
/// replacing any existing copy and verifying `sha256`, instead of downloading.
pub fn stage_file<L: Ledger>(
    dir: &Path,
    from: &Path,
    sha256: &str,
    command: &str,
    version: &str,
    installed: Option<PathBuf>,
) -> Result<(Trial, Binary)> {
    if !vk_hub_proto::valid_sha256(sha256) {
        return Err(anyhow!("{sha256:?} is not a sha256"));
    }
    let releases = releases_dir(dir);
    crate::net::create_dir(&releases)?;
    crate::update::sweep_partial(&releases);
    let next = releases.join(sha256);
    // Copied every time: checking a copy already there costs a full hash, as much as copying.
    crate::update::copy_published(from, &next, 0o700, Some(sha256))?;
    check_release::<L>(
        &releases,
        next,
        sha256.to_string(),
        command.to_string(),
        version.to_string(),
        installed,
    )
}

/// Command `command`'s trial of `next`, the release staged in `releases`, over `installed`,
/// and `next` opened to execute: once it hashes to `sha256` and says it is `version` of the
/// program, and the running binary is kept beside it.
fn check_release<L: Ledger>(
    releases: &Path,
    next: PathBuf,
    sha256: String,
    command: String,
    version: String,
    installed: Option<PathBuf>,
) -> Result<(Trial, Binary)> {
    let binary = Binary::open(&next, Some(&sha256))?;
    vk_selfupdate::smoke_test_file(L::PROGRAM, binary.file(), binary.path(), &version)?;
    let own = own_sha256().context("reading the running binary")?;
    keep_previous(releases, &own)?;
    let exe = installed.with_context(|| format!("the installed {} is not known", L::PROGRAM))?;
    let meta = std::fs::metadata(&exe).with_context(|| format!("reading {}", exe.display()))?;
    let trial = Trial {
        command,
        version,
        sha256,
        exe,
        exe_id: (meta.dev(), meta.ino()),
        next,
        previous: own,
        attempts: 1,
        deadline: 0,
        confirmed: false,
    };
    Ok((trial, binary))
}

/// Record that the update `command`, to `version` hashing to `sha256`, failed with `why`. A
/// trial recorded before an exec that failed is undone, and its release dropped: no release
/// runs on trial.
pub fn failed<K: Keeper>(
    keeper: &K,
    command: &str,
    version: &str,
    sha256: &str,
    why: &str,
) -> Result<()> {
    let undone = keeper.change(|p| {
        p.set_progress(UpdateProgress {
            command: command.to_string(),
            version: version.to_string(),
            sha256: sha256.to_string(),
            phase: UpdatePhase::Failed,
            message: Some(why.to_string()),
        });
        p.set_outcome(
            command,
            Outcome::Failed {
                message: why.to_string(),
            },
        );
        p.trial().take_if(|t| t.command == command)
    })?;
    if let Some(trial) = undone {
        prune(keeper.dir(), &[&trial.previous]);
    }
    Ok(())
}

/// The release on trial reached the hub: record that it passed, install it over the installed
/// binary and report the update done. Only the trial's release confirms, wherever it runs
/// from. Retry installation and completion if a confirmed trial's end could not be saved.
pub fn confirm<K: Keeper>(keeper: &K) {
    let Some(trial) = keeper.trial() else {
        return;
    };
    if running_is(&trial.next) || own_sha256().as_deref() == Some(trial.sha256.as_str()) {
        finish(keeper, &trial);
    }
}

/// [`confirm`] `trial`, which this binary runs.
fn finish<K: Keeper>(keeper: &K, trial: &Trial) {
    // Confirmed before it is installed: a peer stopped in between installs it on its next
    // start, rather than taking the installed binary for the previous one.
    if !trial.passed()
        && let Err(e) = keeper.change(|p| p.trial().as_mut().map(mark_passed))
    {
        K::Ledger::log(Event::ConfirmFailed(&e));
        return;
    }
    crate::update::alarm(None, 0);
    let installed = install(trial);
    let result = keeper.change(|p| match &installed {
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
    });
    match (installed, result) {
        (Ok(()), Ok(())) => {
            prune(keeper.dir(), &[&trial.sha256, &trial.previous]);
            K::Ledger::log(Event::Installed {
                version: &trial.version,
                path: &trial.exe,
            });
        }
        (Err(e), _) | (_, Err(e)) => K::Ledger::log(Event::InstallFailed(&e)),
    }
}

/// Confirm, clear attempts and remove the deadline so binaries that ignore `confirmed`
/// retry the release instead of rolling it back. Their saves preserve the passed marker.
fn mark_passed(trial: &mut Trial) {
    trial.confirmed = true;
    trial.attempts = 0;
    trial.deadline = PASSED;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A distant deadline distinct from the passed marker.
    const LATER: u64 = 1 << 40;

    /// A peer's state with nothing but its trial and its commands' outcomes.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    struct Fake {
        trial: Option<Trial>,
        update: Option<UpdateProgress>,
        outcomes: Vec<(String, Outcome)>,
    }

    impl Ledger for Fake {
        const PROGRAM: &'static str = "vk-fake";
        const PEER: &'static str = "fake";
        const SUBCOMMAND: &'static str = "run";

        fn load(dir: &Path) -> Result<Self> {
            match std::fs::read(dir.join("state.json")) {
                Ok(b) => Ok(serde_json::from_slice(&b)?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Fake::default()),
                Err(e) => Err(e.into()),
            }
        }
        fn save(&self, dir: &Path) -> Result<()> {
            if dir.join("fail-saves").exists() {
                return Err(anyhow!("the disk is full"));
            }
            Ok(std::fs::write(
                dir.join("state.json"),
                serde_json::to_vec(self)?,
            )?)
        }
        fn trial(&mut self) -> &mut Option<Trial> {
            &mut self.trial
        }
        fn set_progress(&mut self, progress: UpdateProgress) {
            self.update = Some(progress);
        }
        fn set_outcome(&mut self, id: &str, outcome: Outcome) {
            self.outcomes.retain(|(c, _)| c != id);
            self.outcomes.push((id.to_string(), outcome));
        }
        fn log(_: Event<'_>) {}
    }

    impl Fake {
        fn outcome(&self, id: &str) -> Option<&Outcome> {
            self.outcomes.iter().find(|(c, _)| c == id).map(|(_, o)| o)
        }
    }

    struct Kept {
        dir: PathBuf,
        state: Mutex<Fake>,
        /// Saves left before they fail.
        saves: std::sync::atomic::AtomicUsize,
    }

    impl Kept {
        fn new(dir: &Path, state: Fake) -> Self {
            Kept {
                dir: dir.to_path_buf(),
                state: Mutex::new(state),
                saves: usize::MAX.into(),
            }
        }
    }

    impl Keeper for Kept {
        type Ledger = Fake;
        fn dir(&self) -> &Path {
            &self.dir
        }
        fn trial(&self) -> Option<Trial> {
            self.state.lock().unwrap().trial.clone()
        }
        /// Failed saves here never publish. [`confirm`] reads memory, unchanged either way;
        /// only the next start reads disk and handles either state. [`on_start`] has no
        /// keeper, so `fail-saves` injects its save failures.
        fn change<R>(&self, f: impl FnOnce(&mut Fake) -> R) -> Result<R> {
            let left = self.saves.load(Ordering::SeqCst);
            if left == 0 {
                return Err(anyhow!("the disk is full"));
            }
            self.saves.store(left - 1, Ordering::SeqCst);
            let mut p = self.state.lock().unwrap();
            let mut next = p.clone();
            let out = f(&mut next);
            next.save(&self.dir)?;
            *p = next;
            Ok(out)
        }
    }

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-peer-trial-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        dir
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

    /// Copy `from` into the releases, replacing a mismatched copy, only if its sha256 matches.
    #[test]
    fn a_release_held_is_copied_into_the_releases() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("stage-file");
        let releases = releases_dir(&dir);
        std::fs::set_permissions(&releases, std::fs::Permissions::from_mode(0o700)).unwrap();
        let from = dir.join("held");
        std::fs::write(&from, b"not a release").unwrap();
        let sha256 = crate::update::hash_file(&from).unwrap();
        let next = releases.join(&sha256);
        let refused = |sha256: &str| {
            stage_file::<Fake>(&dir, &from, sha256, "c1", "9.9.9", None)
                .err()
                .expect("refused")
        };
        std::fs::write(&next, b"corrupt").unwrap();
        // Copied, then rejected: it cannot run as vk-peer.
        let e = refused(&sha256);
        assert!(!format!("{e:#}").contains("hashes to"), "{e:#}");
        assert_eq!(std::fs::read(&next).unwrap(), b"not a release", "{e:#}");
        let e = refused(&"0".repeat(64));
        assert!(format!("{e:#}").contains("not 0000"), "{e:#}");
        assert_eq!(kept(&dir), vec![std::ffi::OsString::from(&sha256)]);
        let e = refused("../x");
        assert!(format!("{e:#}").contains("not a sha256"), "{e:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn kept(dir: &Path) -> Vec<std::ffi::OsString> {
        let mut kept: Vec<_> = std::fs::read_dir(releases_dir(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        kept.sort();
        kept
    }

    #[test]
    fn versions_only_go_forward_unless_allowed() {
        assert!(check_version::<Fake>("0.101.0", "0.102.0", false).is_ok());
        assert!(check_version::<Fake>("0.101.0", "0.101.0", false).is_ok());
        let older = check_version::<Fake>("0.101.0", "0.100.0", false).unwrap_err();
        assert!(
            older.contains("vk-fake 0.100.0 is older than this fake's"),
            "{older}"
        );
        assert!(check_version::<Fake>("0.101.0", "0.100.0", true).is_ok());
        assert!(check_version::<Fake>("0.101.0", "nightly", true).is_err());
        assert!(check_version::<Fake>("nightly", "nightly", false).is_ok());
    }

    #[test]
    fn a_trial_past_its_attempts_or_deadline_is_rolled_back_on_start() {
        for (tag, attempts, deadline) in [("attempts", MAX_ATTEMPTS, LATER), ("late", 1, 0)] {
            let dir = temp(tag);
            let p = Fake {
                trial: Some(trial("c", &dir, attempts, deadline)),
                ..Fake::default()
            };
            p.save(&dir).unwrap();
            for release in ["0", "1", "2"] {
                std::fs::write(releases_dir(&dir).join(release.repeat(64)), b"r").unwrap();
            }
            assert!(matches!(on_start::<Fake>(&dir, 1), Start::Run), "{tag}");
            let p = Fake::load(&dir).unwrap();
            assert!(p.trial.is_none(), "{tag}");
            assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::RolledBack);
            assert!(matches!(p.outcome("c"), Some(Outcome::Failed { .. })));
            // Only the binary that runs again is kept.
            assert_eq!(
                kept(&dir),
                vec![std::ffi::OsString::from("1".repeat(64))],
                "{tag}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A release still within its attempts and deadline is started again, the attempt counted.
    #[test]
    fn a_trial_within_its_attempts_starts_the_release_again() {
        let dir = temp("again");
        let next = releases_dir(&dir).join("2".repeat(64));
        std::fs::write(&next, b"release").unwrap();
        let sha = crate::update::hash_file(&next).unwrap();
        let p = Fake {
            trial: Some(Trial {
                sha256: sha,
                next: next.clone(),
                ..trial("c", &dir, 1, LATER)
            }),
            ..Fake::default()
        };
        p.save(&dir).unwrap();
        let Start::Exec(binary, deadline) = on_start::<Fake>(&dir, 1) else {
            panic!("the release is not started again");
        };
        assert_eq!((binary.path(), deadline), (next.as_path(), Some(LATER)));
        assert_eq!(Fake::load(&dir).unwrap().trial.unwrap().attempts, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release whose file no longer hashes as recorded is rolled back, not run.
    #[test]
    fn a_release_that_changed_is_rolled_back() {
        let dir = temp("changed");
        let next = releases_dir(&dir).join("2".repeat(64));
        std::fs::write(&next, b"release").unwrap();
        let p = Fake {
            trial: Some(Trial {
                next,
                ..trial("c", &dir, 1, LATER)
            }),
            ..Fake::default()
        };
        p.save(&dir).unwrap();
        assert!(matches!(on_start::<Fake>(&dir, 1), Start::Run));
        let p = Fake::load(&dir).unwrap();
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::RolledBack);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release confirmed but stopped before it installed itself: the next start installs it,
    /// ends the update done, and runs it rather than the binary it replaced.
    #[test]
    fn a_confirmed_release_is_installed_on_the_next_start() {
        let dir = temp("confirmed");
        let exe = dir.join("vk-fake");
        std::fs::write(&exe, b"previous").unwrap();
        let next = releases_dir(&dir).join("2".repeat(64));
        std::fs::write(&next, b"release").unwrap();
        let sha = crate::update::hash_file(&next).unwrap();
        let meta = std::fs::metadata(&exe).unwrap();
        let p = Fake {
            trial: Some(Trial {
                sha256: sha.clone(),
                exe: exe.clone(),
                exe_id: (meta.dev(), meta.ino()),
                next,
                confirmed: true,
                ..trial("c", &dir, MAX_ATTEMPTS, 0)
            }),
            ..Fake::default()
        };
        p.save(&dir).unwrap();
        let Start::Exec(binary, deadline) = on_start::<Fake>(&dir, 1) else {
            panic!("the installed release is not run");
        };
        assert_eq!((binary.path(), deadline), (exe.as_path(), None));
        assert_eq!(crate::update::hash_file(&exe).unwrap(), sha);
        let p = Fake::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Done);
        assert_eq!(p.outcome("c"), Some(&Outcome::Done));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The installed binary replaced by another during the trial is left alone.
    #[test]
    fn a_binary_replaced_during_the_trial_is_not_installed_over() {
        let dir = temp("replaced");
        let exe = dir.join("vk-fake");
        std::fs::write(&exe, b"someone else's").unwrap();
        let next = releases_dir(&dir).join("2".repeat(64));
        std::fs::write(&next, b"release").unwrap();
        let p = Fake {
            trial: Some(Trial {
                sha256: crate::update::hash_file(&next).unwrap(),
                exe: exe.clone(),
                next,
                confirmed: true,
                ..trial("c", &dir, 1, LATER)
            }),
            ..Fake::default()
        };
        p.save(&dir).unwrap();
        assert!(matches!(on_start::<Fake>(&dir, 1), Start::Run));
        assert_eq!(std::fs::read(&exe).unwrap(), b"someone else's");
        let p = Fake::load(&dir).unwrap();
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Failed);
        assert!(matches!(p.outcome("c"), Some(Outcome::Failed { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_that_cannot_be_read_does_not_stop_the_peer() {
        let dir = temp("corrupt");
        std::fs::write(dir.join("state.json"), b"{ not json").unwrap();
        assert!(matches!(on_start::<Fake>(&dir, 1), Start::Run));
        assert!(matches!(
            on_start::<Fake>(&dir.join("absent"), 1),
            Start::Run
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed update undoes its own trial and drops its release, and no other's.
    #[test]
    fn a_failed_update_undoes_its_trial() {
        let dir = temp("failed");
        for release in ["0", "1"] {
            std::fs::write(releases_dir(&dir).join(release.repeat(64)), b"r").unwrap();
        }
        let keeper = Kept::new(
            &dir,
            Fake {
                trial: Some(trial("c", &dir, 1, LATER)),
                ..Fake::default()
            },
        );
        failed(&keeper, "other", "9.9.9", &"0".repeat(64), "no").unwrap();
        assert!(keeper.trial().is_some());
        failed(&keeper, "c", "9.9.9", &"0".repeat(64), "exec failed").unwrap();
        let p = Fake::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Failed);
        assert!(matches!(p.outcome("c"), Some(Outcome::Failed { .. })));
        assert_eq!(kept(&dir), vec![std::ffi::OsString::from("1".repeat(64))]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only the binary a trial runs confirms it.
    #[test]
    fn a_trial_another_binary_runs_is_not_confirmed() {
        let dir = temp("confirm");
        let keeper = Kept::new(
            &dir,
            Fake {
                trial: Some(trial("c", &dir, 1, LATER)),
                ..Fake::default()
            },
        );
        confirm(&keeper);
        let t = keeper.trial().unwrap();
        assert!(!t.confirmed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release running from the installed path, rather than from `releases/`, confirms its
    /// trial too: the install, refused over a binary replaced meanwhile, ends the update.
    #[test]
    fn a_release_run_from_the_installed_path_confirms() {
        let dir = temp("from-installed");
        let exe = dir.join("vk-fake");
        std::fs::write(&exe, b"another").unwrap();
        let keeper = Kept::new(
            &dir,
            Fake {
                trial: Some(Trial {
                    sha256: own_sha256().unwrap(),
                    exe,
                    ..trial("c", &dir, 1, LATER)
                }),
                ..Fake::default()
            },
        );
        confirm(&keeper);
        let p = Fake::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert!(matches!(p.outcome("c"), Some(Outcome::Failed { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The installed binary is the last one the peer started from outside the hub directory:
    /// a confirmed release running from `releases/` leaves it as recorded.
    #[test]
    fn the_installed_binary_is_never_a_release() {
        let root = temp("installed");
        let dir = root.join("hub");
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        let installed = root.join("vk-fake");
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

        let unknown = can_replace::<Fake>(None, &dir).unwrap_err();
        assert!(unknown.contains("restart vk-fake run"), "{unknown}");
        assert!(can_replace::<Fake>(Some(&release), &dir).is_err());
        can_replace::<Fake>(Some(&installed), &dir).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_trial_from_before_confirmation_is_read() {
        let old = r#"{"command":"c","version":"1.0.0","sha256":"00","exe":"/x","exe_id":[1,2],
            "next":"/y","previous":"11","attempts":1,"deadline":5}"#;
        let t: Trial = serde_json::from_str(old).unwrap();
        assert!(!t.confirmed);
    }

    /// A trial whose installed binary and release are real files: `exe` the installed one.
    fn installable(dir: &Path) -> Trial {
        let exe = dir.join("vk-fake");
        std::fs::write(&exe, b"previous").unwrap();
        let next = releases_dir(dir).join("2".repeat(64));
        std::fs::write(&next, b"release").unwrap();
        let meta = std::fs::metadata(&exe).unwrap();
        Trial {
            sha256: crate::update::hash_file(&next).unwrap(),
            exe,
            exe_id: (meta.dev(), meta.ino()),
            next,
            ..trial("c", dir, 1, 100)
        }
    }

    /// Confirmation installs the release and completes the update. If saving completion
    /// fails, the trial stays confirmed; the next confirmation retries installation and completion.
    #[test]
    fn a_confirmation_whose_end_was_not_saved_is_finished_again() {
        let dir = temp("unsaved");
        let t = installable(&dir);
        let keeper = Kept::new(
            &dir,
            Fake {
                trial: Some(t.clone()),
                ..Fake::default()
            },
        );
        // The confirmation is saved, the end not.
        keeper.saves.store(1, Ordering::SeqCst);
        finish(&keeper, &t);
        let kept = keeper.trial().unwrap();
        assert!(kept.confirmed);
        assert_eq!(crate::update::hash_file(&t.exe).unwrap(), t.sha256);
        keeper.saves.store(usize::MAX, Ordering::SeqCst);
        finish(&keeper, &kept);
        let p = Fake::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Done);
        assert_eq!(p.outcome("c"), Some(&Outcome::Done));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A confirmation that cannot be saved installs nothing: the trial goes on.
    #[test]
    fn a_confirmation_that_cannot_be_saved_installs_nothing() {
        let dir = temp("unconfirmed");
        let t = installable(&dir);
        let keeper = Kept::new(
            &dir,
            Fake {
                trial: Some(t.clone()),
                ..Fake::default()
            },
        );
        keeper.saves.store(0, Ordering::SeqCst);
        finish(&keeper, &t);
        assert!(!keeper.trial().unwrap().confirmed);
        assert_eq!(std::fs::read(&t.exe).unwrap(), b"previous");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A confirmed trial, read by a previous binary from before confirmations — the same trial
    /// with no `confirmed` — is one it hands over to the release, past its attempts and
    /// deadline both, rather than rolling it back; saved by it, `confirmed` dropped, it still
    /// reads as passed, and the next start installs the release.
    #[test]
    fn a_trial_a_previous_binary_saved_without_its_confirmation_still_passed() {
        let dir = temp("older");
        let mut t = Trial {
            attempts: MAX_ATTEMPTS,
            ..installable(&dir)
        };
        mark_passed(&mut t);
        // The previous binary's own test: hand over unless past its attempts or deadline.
        let now = 1 << 40;
        assert!(t.attempts < MAX_ATTEMPTS && now <= t.deadline);
        // It counts the start and saves the trial without the field it does not know.
        t.attempts += 1;
        let mut seen = serde_json::to_value(&t).unwrap();
        seen.as_object_mut().unwrap().remove("confirmed");
        let resaved: Trial = serde_json::from_value(seen).unwrap();
        assert!(!resaved.confirmed && resaved.passed());
        let p = Fake {
            trial: Some(resaved),
            ..Fake::default()
        };
        p.save(&dir).unwrap();
        let Start::Exec(binary, None) = on_start::<Fake>(&dir, now) else {
            panic!("the passed release is not installed and run");
        };
        assert_eq!(binary.path(), t.exe.as_path());
        assert_eq!(crate::update::hash_file(&t.exe).unwrap(), t.sha256);
        let p = Fake::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Done);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Startup runs an installed, confirmed release even if saving completion fails.
    /// The next start ends the remaining trial.
    #[test]
    fn an_install_whose_end_was_not_saved_runs_the_release() {
        let dir = temp("install-unsaved");
        let t = Trial {
            confirmed: true,
            ..installable(&dir)
        };
        let p = Fake {
            trial: Some(t.clone()),
            ..Fake::default()
        };
        p.save(&dir).unwrap();
        std::fs::write(dir.join("fail-saves"), b"").unwrap();
        let Start::Exec(binary, None) = on_start::<Fake>(&dir, 1) else {
            panic!("the installed release is not run");
        };
        assert_eq!(binary.path(), t.exe.as_path());
        assert_eq!(crate::update::hash_file(&t.exe).unwrap(), t.sha256);
        assert!(Fake::load(&dir).unwrap().trial.is_some());
        std::fs::remove_file(dir.join("fail-saves")).unwrap();
        assert!(matches!(on_start::<Fake>(&dir, 1), Start::Exec(_, None)));
        let p = Fake::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.outcome("c"), Some(&Outcome::Done));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
