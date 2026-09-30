//! Updating a node's `vk` to a release its hub holds: download it from the hub, check it,
//! run it on trial, and keep it only once it has passed — else go back to the binary it
//! replaced. See `docs/fleet-design.md`, "Updates".
//!
//! The update has drained the node before any of this ([`super::state`]), so no job has a
//! stage run by one `vk` and the next by another. Then, in `maintenance`:
//!
//! 1. the release is fetched into `<node dir>/releases/<sha256>` (`0700`, as the node dir is):
//!    streamed from the hub under the node's signature, into a private file that is renamed
//!    into place only once it hashes to the command's sha256 and is no longer than its size;
//! 2. its `--version` must name the command's version (`vk-selfupdate`'s smoke test);
//! 3. the running binary is copied beside it as the previous release, by its own sha256;
//! 4. the node records a [`Trial`] and `validating`, and executes the release in its place.
//!
//! The installed binary is left where it is until the trial is confirmed: whatever starts
//! `vk node run` — a supervisor restarting a release that crashed, or a person — starts the
//! previous `vk`, which counts the attempt and hands over again ([`on_start`]). Past
//! [`MAX_ATTEMPTS`], or past the trial's deadline, it takes the node back itself. A release
//! that dies before it can count anything is counted all the same.
//!
//! On trial the release runs `vk check`'s gate and `[node] validate`, then waits for a session
//! with the hub, and only then installs itself over the running `vk`'s path, by `rename`, and
//! returns the node to the state it was in. The previous binary reached the hub moments
//! before — it downloaded the release from it — so a release that cannot reach it by the
//! deadline is taken to be what is wrong, and rolled back: kept, it could leave the node on a
//! binary nothing can steer. A hub that is down for longer costs only a retried update.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use vk_fleet_proto::{NodeState, Outcome, UpdatePhase};

use super::core::Core;
use super::session::Node;
use super::state::{Job, Persisted, Trial};
use crate::config::Config;

/// How many times a release on trial may be started before the previous binary takes the
/// node back.
pub const MAX_ATTEMPTS: u32 = 3;

/// How long a trial has beyond `[node] validate`'s timeout: for `vk check`, the restart and
/// a session with the hub.
const TRIAL_GRACE: Duration = Duration::from_secs(600);

/// The largest release a node takes, whatever a command says.
const MAX_RELEASE: u64 = 1 << 30;

/// How long a download may go without a byte arriving.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a download may take in all.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The releases directory: the release on trial or installed, and the previous binary.
fn releases_dir(dir: &Path) -> PathBuf {
    dir.join("releases")
}

/// The first release whose `vk node run` takes part in a trial. Nothing older is installed,
/// even where downgrades are allowed: it would neither count its attempts nor confirm itself,
/// and the node would be left on it unchecked. Versions from this one on have it, so only a
/// downgrade can reach one without.
pub const TRIAL_SINCE: &str = "0.80.0";

/// What `vk node run` does on starting.
pub enum Start {
    Run,
    /// Execute this binary in place of this one, with the same arguments.
    Exec(PathBuf),
}

/// The previous binary's part in a trial, run by `vk node run` with the node's lock held and
/// before anything else: count the start and hand over to the release, or — past
/// [`MAX_ATTEMPTS`] or the deadline, or when the release on disk is no longer what was
/// downloaded — end the trial and run on as the node's binary. A trial confirmed and stopped
/// while it was being installed is finished here.
pub fn on_start(dir: &Path, now: u64) -> Result<Start> {
    let mut p = Persisted::load(dir)?;
    let Some(job) = p.job.clone() else {
        return Ok(Start::Run);
    };
    let Some(trial) = job.trial.clone() else {
        return Ok(Start::Run);
    };
    if running_is(&trial.next) {
        return Ok(Start::Run);
    }
    let roll_back = |p: &mut Persisted, why: &str| -> Result<Start> {
        eprintln!("vk node: rolling back the update: {why}");
        p.end_job(
            Outcome::Failed {
                message: format!("rolled back: {why}"),
            },
            UpdatePhase::RolledBack,
        );
        p.save_durable(dir)?;
        prune(dir, std::slice::from_ref(&trial.previous));
        Ok(Start::Run)
    };
    if trial.confirmed {
        match install(&trial.next, &job.release.sha256, &trial) {
            Ok(()) => {}
            Err(e) if e.is::<InstalledChanged>() => {
                return replaced_meanwhile(&mut p, dir, &trial, &e);
            }
            Err(e) => return roll_back(&mut p, &format!("installing it failed: {e:#}")),
        }
        p.end_job(Outcome::Done, UpdatePhase::Done);
        p.save_durable(dir)?;
        prune(
            dir,
            &[Some(job.release.sha256.clone()), trial.previous.clone()],
        );
        eprintln!("vk node: installed the release that passed its trial");
        return Ok(if running_is(&trial.exe) {
            Start::Run
        } else {
            Start::Exec(trial.exe)
        });
    }
    let attempts = trial.attempts.saturating_add(1);
    if now >= trial.deadline {
        return roll_back(&mut p, "it was not confirmed by its deadline");
    }
    if attempts > MAX_ATTEMPTS {
        return roll_back(
            &mut p,
            &format!("it was started {MAX_ATTEMPTS} times without passing its trial"),
        );
    }
    if hash_file(&trial.next).ok().as_deref() != Some(job.release.sha256.as_str()) {
        return roll_back(
            &mut p,
            "the release on disk no longer hashes to what was downloaded",
        );
    }
    if let Some(t) = p.job.as_mut().and_then(|j| j.trial.as_mut()) {
        t.attempts = attempts;
    }
    p.save_durable(dir)?;
    eprintln!(
        "vk node: starting the release on trial, {} (attempt {attempts} of {MAX_ATTEMPTS})",
        trial.next.display()
    );
    alarm_across_exec(trial.deadline);
    Ok(Start::Exec(trial.next))
}

/// The installed binary was replaced by something else during the trial: the release is not
/// installed over it, and the node runs what is there now.
fn replaced_meanwhile(
    p: &mut Persisted,
    dir: &Path,
    trial: &Trial,
    e: &anyhow::Error,
) -> Result<Start> {
    eprintln!("vk node: the update failed: {e:#}");
    p.end_job(
        Outcome::Failed {
            message: format!("{e:#}"),
        },
        UpdatePhase::Failed,
    );
    p.save_durable(dir)?;
    prune(dir, std::slice::from_ref(&trial.previous));
    Ok(if running_is(&trial.exe) {
        Start::Run
    } else {
        Start::Exec(trial.exe.clone())
    })
}

/// Record the installed `vk` for updates to replace: the binary this process runs, unless it
/// is a release under the node dir — then the path recorded before stays, whatever file
/// runs now. So a node updated twice without a restart installs both times where it was
/// installed, never into its own releases directory.
pub fn note_installed(dir: &Path) -> Result<()> {
    let Ok(exe) = std::env::current_exe() else {
        return Ok(());
    };
    let mut p = Persisted::load(dir)?;
    let installed = installed_after(p.installed.clone(), exe, dir);
    if p.installed != installed {
        p.installed = installed;
        p.save(dir)?;
    }
    Ok(())
}

/// The installed path to record, `recorded` before, for a `vk node run` executing `exe`.
fn installed_after(recorded: Option<PathBuf>, exe: PathBuf, dir: &Path) -> Option<PathBuf> {
    if !exe.is_file() || under(&exe, dir) {
        recorded
    } else {
        Some(exe)
    }
}

/// Whether `path` is inside `dir`, both resolved.
fn under(path: &Path, dir: &Path) -> bool {
    match (std::fs::canonicalize(path), std::fs::canonicalize(dir)) {
        (Ok(p), Ok(d)) => p.starts_with(d),
        // What cannot be resolved is not taken as outside.
        _ => true,
    }
}

/// A release on trial arms `alarm(2)` for its deadline before anything else runs — the
/// binary that executed it armed it too, across the exec — and the kernel ends it then — `SIGALRM`'s default action — whatever state it is in: hung, deadlocked
/// or waiting. The previous binary, restarted by whatever supervises `vk node run`, then finds
/// the deadline past and takes the node back. Disarmed before any exec, since an alarm
/// survives one.
pub fn arm_trial_deadline(dir: &Path, now: u64) -> Result<()> {
    let p = Persisted::load(dir)?;
    if let Some(trial) = p.job.and_then(|j| j.trial)
        && running_is(&trial.next)
        && !trial.confirmed
    {
        let secs = trial.deadline.saturating_sub(now).max(1);
        let secs = libc::c_uint::try_from(secs).unwrap_or(libc::c_uint::MAX);
        // SAFETY: `alarm` takes a count and touches no memory.
        unsafe { libc::alarm(secs) };
    }
    Ok(())
}

fn disarm() {
    // SAFETY: as in `arm_trial_deadline`.
    unsafe { libc::alarm(0) };
}

/// The deadline the next [`exec`] arms the alarm for, 0 for none.
static EXEC_ALARM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Have the next [`exec`] hand over with the alarm armed for `deadline`: an alarm survives an
/// exec, so a release that never gets as far as arming its own — one that hangs before, or
/// is not a `vk` at all — is ended at the deadline all the same.
fn alarm_across_exec(deadline: u64) {
    EXEC_ALARM.store(deadline, std::sync::atomic::Ordering::Relaxed);
}

/// Execute `path` in place of this process, with its arguments; returns only on failure. The
/// alarm is disarmed first, or armed for a release on trial ([`alarm_across_exec`]).
pub fn exec(path: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    match EXEC_ALARM.swap(0, std::sync::atomic::Ordering::Relaxed) {
        0 => disarm(),
        deadline => {
            let secs = deadline.saturating_sub(now_secs()).max(1);
            let secs = libc::c_uint::try_from(secs).unwrap_or(libc::c_uint::MAX);
            // SAFETY: `alarm` takes a count and touches no memory.
            unsafe { libc::alarm(secs) };
        }
    }
    let mut args = std::env::args_os();
    let mut cmd = std::process::Command::new(path);
    if let Some(arg0) = args.next() {
        cmd.arg0(arg0);
    }
    let e = cmd.args(args).exec();
    anyhow!(e).context(format!("executing {}", path.display()))
}

/// Whether this process runs the file at `path`: the same inode, not the same name.
fn running_is(path: &Path) -> bool {
    match (std::fs::metadata("/proc/self/exe"), std::fs::metadata(path)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Whether this node can replace its installed `vk` at `installed`, or why not: it must be
/// recorded, outside the node dir `dir`, a file, in a directory this user can write, since
/// the release is renamed into it.
pub fn can_replace(installed: Option<&Path>, dir: &Path) -> Result<(), String> {
    let exe = installed.ok_or_else(|| {
        "the installed vk is not known yet: restart vk node run from it".to_string()
    })?;
    if under(exe, dir) {
        return Err(format!(
            "{} is inside the node's own directory; run vk node run from the installed vk",
            exe.display()
        ));
    }
    if !exe.is_file() {
        return Err(format!("{} is gone", exe.display()));
    }
    let parent = exe
        .parent()
        .ok_or_else(|| format!("{} has no directory", exe.display()))?;
    let c_dir = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("{} has a NUL in it", parent.display()))?;
    // SAFETY: the path is NUL-terminated and outlives the call; `access` reads nothing else.
    if unsafe { libc::access(c_dir.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
        return Err(format!(
            "vk node cannot replace {}: {} is not writable by this user",
            exe.display(),
            parent.display()
        ));
    }
    Ok(())
}

/// Whether a node running `own` may update to `candidate`: not to an older version unless
/// `allow_downgrade`, and never to one older than [`TRIAL_SINCE`]. Versions are
/// `MAJOR.MINOR.PATCH`; an older one that cannot be ordered is refused.
pub fn check_version(own: &str, candidate: &str, allow_downgrade: bool) -> Result<(), String> {
    fn fields(v: &str) -> Option<Vec<u64>> {
        let v: Vec<u64> = v
            .split('.')
            .map(|f| f.parse().ok())
            .collect::<Option<_>>()?;
        (v.len() == 3).then_some(v)
    }
    let (Some(c), Some(o)) = (fields(candidate), fields(own)) else {
        return if candidate == own {
            Ok(())
        } else {
            Err(format!(
                "vk {candidate} cannot be ordered against this node's {own}, so it may be a \
                 downgrade; versions are MAJOR.MINOR.PATCH"
            ))
        };
    };
    if c >= o {
        return Ok(());
    }
    if !allow_downgrade {
        return Err(format!(
            "vk {candidate} is older than this node's {own}; [node] allow_downgrade = true lets \
             an update install it"
        ));
    }
    match fields(TRIAL_SINCE) {
        Some(floor) if c < floor => Err(format!(
            "vk {candidate} predates {TRIAL_SINCE}, the first release that takes part in an \
             update's trial"
        )),
        _ => Ok(()),
    }
}

static OWN_SHA256: OnceLock<Option<String>> = OnceLock::new();

/// The sha256 of the running binary, hex, read once: a few hundred megabytes, so `vk node
/// run` reads it before its first session rather than in the middle of one.
pub fn own_sha256() -> Option<String> {
    OWN_SHA256
        .get_or_init(|| hash_file(Path::new("/proc/self/exe")).ok())
        .clone()
}

/// [`own_sha256`] if it has been read, without reading it.
pub fn known_sha256() -> Option<String> {
    OWN_SHA256.get().cloned().flatten()
}

fn hash_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    hash_reader(file, None).with_context(|| format!("reading {}", path.display()))
}

/// The sha256 of what `from` reads, hex, written on to `to` as it goes when given.
fn hash_reader(mut from: impl std::io::Read, mut to: Option<&mut std::fs::File>) -> Result<String> {
    use std::io::Write;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = from.read(&mut buf)?;
        let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else {
            break;
        };
        hasher.update(chunk);
        if let Some(out) = to.as_mut() {
            out.write_all(chunk)?;
        }
    }
    Ok(vk_fleet_proto::to_hex(&hasher.finalize()))
}

/// Run `f` off the runtime: hashing and copying a few hundred megabytes.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .context("running a file operation")?
}

/// Follow the node's state, and carry out the update's maintenance and trial as they come.
/// Runs until `stop`; work cut short by it is taken up again by the next `vk node run`.
pub async fn maintain(
    core: Arc<Core>,
    cfg: Arc<Config>,
    node: Arc<Node>,
    mut stop: watch::Receiver<bool>,
) {
    let mut changes = core.subscribe();
    loop {
        changes.borrow_and_update();
        let p = core.persisted();
        if let Some(job) = p.job.clone() {
            let work = async {
                match (p.state, &job.trial) {
                    (NodeState::Maintenance, None) => {
                        if let Err(e) = prepare(&core, &cfg, &node, &job).await {
                            eprintln!("vk node: the update failed: {e:#}");
                            let message = format!("{e:#}");
                            let ended = core.change(|p| {
                                p.end_job(Outcome::Failed { message }, UpdatePhase::Failed)
                            });
                            if let Err(e) = ended {
                                eprintln!("vk node: {e:#}");
                            }
                        }
                    }
                    (NodeState::Validating, Some(trial)) if running_is(&trial.next) => {
                        let verdict = judge(&core, &cfg, trial).await;
                        conclude(&core, &job, trial, verdict).await;
                    }
                    _ => {}
                }
            };
            tokio::select! {
                () = work => {}
                _ = stop.wait_for(|&s| s) => return,
            }
        }
        tokio::select! {
            _ = changes.changed() => {}
            _ = stop.wait_for(|&s| s) => return,
        }
    }
}

/// Maintenance: fetch and check the release, keep the running binary beside it, and switch
/// to it on trial. Returns only on failure, with the binary unchanged.
async fn prepare(core: &Core, cfg: &Config, node: &Node, job: &Job) -> Result<()> {
    let dir = core.dir().to_path_buf();
    let release = job.release.clone();
    if own_sha256().as_deref() == Some(release.sha256.as_str()) {
        eprintln!("vk node: already running release {}", release.sha256);
        core.change(|p| p.end_job(Outcome::Done, UpdatePhase::Done))?;
        return Ok(());
    }
    if release.size > MAX_RELEASE {
        bail!(
            "the release is {} bytes, past the {MAX_RELEASE} a node takes",
            release.size
        );
    }
    let installed = core.persisted().installed;
    can_replace(installed.as_deref(), &dir).map_err(|e| anyhow!(e))?;
    check_version(
        env!("CARGO_PKG_VERSION"),
        &release.version,
        core.allow_downgrade(),
    )
    .map_err(|e| anyhow!(e))?;
    let exe = installed.context("the installed vk is not known")?;
    let releases = releases_dir(&dir);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&releases)
        .with_context(|| format!("creating {}", releases.display()))?;
    sweep_partial(&releases);
    let next = releases.join(&release.sha256);
    let held = {
        let (next, sha) = (next.clone(), release.sha256.clone());
        blocking(move || Ok(next.is_file() && hash_file(&next).ok() == Some(sha))).await?
    };
    if !held {
        eprintln!(
            "vk node: downloading vk {} ({})",
            release.version, release.sha256
        );
        tokio::time::timeout(DOWNLOAD_TIMEOUT, download(node, &release, &next))
            .await
            .map_err(|_| anyhow!("the download took longer than {DOWNLOAD_TIMEOUT:?}"))??;
    }
    let (path, version) = (next.clone(), release.version.clone());
    blocking(move || vk_selfupdate::smoke_test("vk", &path, &version)).await?;
    let previous = own_sha256();
    if let Some(previous) = previous.clone() {
        let releases = releases.clone();
        blocking(move || keep_previous(&releases, &previous)).await?;
    }
    let now = now_secs();
    let mut deadline = now
        .saturating_add(cfg.node.validate_timeout().as_secs())
        .saturating_add(TRIAL_GRACE.as_secs());
    if let Some(by) = job.deadline {
        if now >= by {
            bail!("the update's time ran out before the switch");
        }
        deadline = deadline.min(by);
    }
    let exe_id = std::fs::metadata(&exe)
        .map(|m| (m.dev(), m.ino()))
        .with_context(|| format!("reading {}", exe.display()))?;
    let trial = Trial {
        exe,
        next: next.clone(),
        previous,
        attempts: 1,
        deadline,
        confirmed: false,
        exe_id: Some(exe_id),
    };
    eprintln!(
        "vk node: switching to vk {} on trial, for at most {}s",
        release.version,
        deadline.saturating_sub(now)
    );
    alarm_across_exec(deadline);
    Err(core.leave(
        move |p| {
            if let Some(job) = p.job.as_mut() {
                job.trial = Some(trial);
            }
            p.set_phase(NodeState::Validating, UpdatePhase::Validating);
        },
        &next,
    ))
}

/// The release on trial: validate, then wait for a session with the hub, both by the
/// trial's deadline. `Err` says why it did not pass.
async fn judge(core: &Core, cfg: &Arc<Config>, trial: &Trial) -> Result<(), String> {
    let deadline = deadline_of(trial);
    eprintln!("vk node: on trial: validating");
    match tokio::time::timeout_at(deadline, validate(cfg)).await {
        Err(_) => return Err("validation did not finish by the trial's deadline".into()),
        Ok(Err(why)) => return Err(format!("validation failed: {why}")),
        Ok(Ok(())) => {}
    }
    eprintln!("vk node: on trial: validated; waiting for the hub");
    wait_for_hub(core, deadline).await
}

/// Wait for a session with the hub until `deadline`.
async fn wait_for_hub(core: &Core, deadline: tokio::time::Instant) -> Result<(), String> {
    let mut connected = core.connected();
    match tokio::time::timeout_at(deadline, connected.wait_for(|&up| up)).await {
        Ok(Ok(_)) => Ok(()),
        _ => Err("the hub was not reached by the trial's deadline".into()),
    }
}

fn deadline_of(trial: &Trial) -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(trial.deadline.saturating_sub(now_secs()))
}

/// End the trial by `verdict`: passed, install the release and execute it as the installed
/// binary; not, hand the node back to the binary it replaced.
async fn conclude(core: &Core, job: &Job, trial: &Trial, verdict: Result<(), String>) {
    if let Err(why) = verdict {
        roll_back(core, trial, &why).await;
        return;
    }
    let confirmed = core.change(|p| {
        if let Some(t) = p.job.as_mut().and_then(|j| j.trial.as_mut()) {
            t.confirmed = true;
        }
    });
    if let Err(e) = confirmed {
        roll_back(
            core,
            trial,
            &format!("recording its confirmation failed: {e:#}"),
        )
        .await;
        return;
    }
    let installed = {
        let (next, sha, trial) = (
            trial.next.clone(),
            job.release.sha256.clone(),
            trial.clone(),
        );
        blocking(move || install(&next, &sha, &trial)).await
    };
    match installed {
        Ok(()) => {}
        Err(e) if e.is::<InstalledChanged>() => {
            eprintln!("vk node: the update failed: {e:#}");
            let message = format!("{e:#}");
            let ended = |p: &mut Persisted| {
                p.end_job(
                    Outcome::Failed {
                        message: message.clone(),
                    },
                    UpdatePhase::Failed,
                );
            };
            let e = core.leave(ended, &trial.exe);
            eprintln!("vk node: {e:#}");
            if let Err(e) = core.change(ended) {
                eprintln!("vk node: {e:#}");
            }
            quarantine(core, "the installed vk could not be run after an update");
            return;
        }
        Err(e) => {
            roll_back(core, trial, &format!("installing it failed: {e:#}")).await;
            return;
        }
    }
    eprintln!(
        "vk node: updated to vk {}, installed as {}",
        job.release.version,
        trial.exe.display()
    );
    prune(
        core.dir(),
        &[Some(job.release.sha256.clone()), trial.previous.clone()],
    );
    // Installed: from here the update is done whatever else fails. It is recorded, and the
    // node goes on as the installed binary rather than from its releases directory; should
    // either step fail, the next start finds the trial confirmed and finishes it.
    let e = core.leave(
        |p| {
            p.end_job(Outcome::Done, UpdatePhase::Done);
        },
        &trial.exe,
    );
    eprintln!("vk node: {e:#}");
    for _ in 0..3 {
        match core.change(|p| p.end_job(Outcome::Done, UpdatePhase::Done)) {
            Ok(_) => break,
            Err(e) => {
                eprintln!("vk node: recording the update: {e:#}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    disarm();
}

/// Hand the node back to the binary the release replaced: the installed one, or the copy
/// kept of it, whichever still hashes to what it was — the update ended as rolled back only
/// once one of them is executing. With neither, the node is quarantined, for an operator:
/// it runs the release it just rejected.
async fn roll_back(core: &Core, trial: &Trial, why: &str) {
    eprintln!("vk node: rolling back the update: {why}");
    let message = format!("rolled back: {why}");
    let mut targets = vec![trial.exe.clone()];
    if let Some(previous) = &trial.previous {
        targets.push(releases_dir(core.dir()).join(previous));
    }
    for target in targets {
        let (path, want) = (target.clone(), trial.previous.clone());
        let usable = blocking(move || Ok(runnable(&path, want.as_deref()))).await;
        if !matches!(usable, Ok(true)) {
            eprintln!(
                "vk node: {} is not the binary the release replaced; not running it",
                target.display()
            );
            continue;
        }
        let keep = trial.previous.clone();
        let dir = core.dir().to_path_buf();
        let e = core.leave(
            |p| {
                p.end_job(
                    Outcome::Failed {
                        message: message.clone(),
                    },
                    UpdatePhase::RolledBack,
                );
                prune(&dir, &[keep]);
            },
            &target,
        );
        eprintln!("vk node: {e:#}");
    }
    let why = format!("{message}, but no binary it replaced could be run");
    let ended = core.change(|p| {
        p.end_job(
            Outcome::Failed {
                message: why.clone(),
            },
            UpdatePhase::RolledBack,
        );
    });
    if let Err(e) = ended {
        eprintln!("vk node: {e:#}");
    }
    quarantine(core, &why);
}

/// Take the node out of work, as a quarantine from its own hand: something about its `vk`
/// needs an operator.
fn quarantine(core: &Core, why: &str) {
    disarm();
    eprintln!("vk node: quarantining the node: {why}");
    let done = core.change(|p| {
        if p.state != NodeState::Quarantined {
            p.quarantined_from = Some(p.state);
            p.state = NodeState::Quarantined;
        }
    });
    if let Err(e) = done {
        eprintln!("vk node: {e:#}");
    }
}

/// Whether `path` is an executable file that hashes to `sha256`, when that is known.
fn runnable(path: &Path, sha256: Option<&str>) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: the path is NUL-terminated and outlives the call.
    let executable = path.is_file() && unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0;
    executable && sha256.is_none_or(|want| hash_file(path).ok().as_deref() == Some(want))
}

/// `vk check`'s gate, then `[node] validate` if there is one.
async fn validate(cfg: &Arc<Config>) -> Result<(), String> {
    let gate = cfg.clone();
    let failed: Vec<String> = tokio::task::spawn_blocking(move || super::inventory::checks(&gate))
        .await
        .map_err(|e| format!("running vk check: {e}"))?
        .into_iter()
        .filter(|c| !c.ok)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    if !failed.is_empty() {
        return Err(format!("vk check: {}", failed.join("; ")));
    }
    run_check(&cfg.node.validate, cfg.node.validate_timeout()).await
}

/// Run `argv`, if it is not empty, and require it to exit 0 within `timeout`; on failure, say
/// how, with the end of what it printed.
async fn run_check(argv: &[String], timeout: Duration) -> Result<(), String> {
    let Some((program, args)) = argv.split_first() else {
        return Ok(());
    };
    let shown = argv.join(" ");
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    if let Ok(exe) = std::env::current_exe() {
        cmd.env("VK_BINARY", exe);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("starting `{shown}`: {e}"))?;
    let pgid = child.id().and_then(|p| i32::try_from(p).ok());
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Err(_) => {
            if let Some(pgid) = pgid {
                // SAFETY: a kill of the process group this call started, `process_group(0)`.
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
            Err(format!(
                "`{shown}` did not finish within {}s",
                timeout.as_secs()
            ))
        }
        Ok(Err(e)) => Err(format!("waiting for `{shown}`: {e}")),
        Ok(Ok(out)) if out.status.success() => Ok(()),
        Ok(Ok(out)) => {
            let mut said = out.stderr;
            said.extend_from_slice(&out.stdout);
            let said = String::from_utf8_lossy(&said);
            let said = said.trim();
            // The end of it, where a failure says why.
            let tail = said
                .char_indices()
                .rev()
                .nth(299)
                .map_or(said, |(at, _)| &said[at..]);
            Err(format!("`{shown}` failed ({}): {tail}", out.status))
        }
    }
}

/// Fetch `release` from the hub into `dest`, published only once it checks out.
async fn download(node: &Node, release: &super::state::Release, dest: &Path) -> Result<()> {
    let dir = dest.parent().context("the release has no directory")?;
    let tmp = dir.join(format!(".{}.{}.tmp", release.sha256, std::process::id()));
    let outcome = download_into(node, release, &tmp).await.and_then(|()| {
        std::fs::rename(&tmp, dest).with_context(|| format!("publishing {}", dest.display()))?;
        if let Ok(d) = std::fs::File::open(dir) {
            // Best effort, as vk-selfupdate's publish: the rename has happened.
            let _ = d.sync_all();
        }
        Ok(())
    });
    if outcome.is_err() {
        // Best effort: the error is what matters, and `sweep_partial` takes what is left.
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}

async fn download_into(node: &Node, release: &super::state::Release, tmp: &Path) -> Result<()> {
    use http_body_util::BodyExt;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let (io, exported, authority) = super::session::dial(&node.enrollment.hub, &node.tls).await?;
    let channel = match &exported {
        Some(e) => vk_fleet_proto::Channel::Tls(e),
        None => vk_fleet_proto::Channel::Plaintext,
    };
    let at = now_secs();
    let node_id = &node.enrollment.node_id;
    let signature = node.identity.sign(&vk_fleet_proto::download_message(
        node_id,
        &release.sha256,
        at,
        channel,
    ));
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .context("opening the download")?;
    let driver = tokio::spawn(conn);
    let request = hyper::Request::get(format!(
        "{}{}",
        vk_fleet_proto::RELEASE_PATH,
        release.sha256
    ))
    .header(hyper::header::HOST, authority)
    .header(vk_fleet_proto::NODE_HEADER, node_id.as_str())
    .header(vk_fleet_proto::TIME_HEADER, at.to_string())
    .header(vk_fleet_proto::SIGNATURE_HEADER, signature)
    .body(http_body_util::Empty::<bytes::Bytes>::new())
    .context("building the download request")?;
    let resp = sender
        .send_request(request)
        .await
        .context("asking the hub for the release")?;
    let status = resp.status();
    let mut body = resp.into_body();
    if !status.is_success() {
        let mut said = Vec::new();
        while let Ok(Some(Ok(frame))) = tokio::time::timeout(READ_TIMEOUT, body.frame()).await {
            if let Ok(data) = frame.into_data() {
                said.extend_from_slice(&data);
            }
            if said.len() > 4096 {
                break;
            }
        }
        driver.abort();
        let why = serde_json::from_slice::<vk_fleet_proto::ErrorBody>(&said)
            .map(|e| vk_fleet_proto::display_safe(&e.error))
            .unwrap_or_else(|_| format!("HTTP {status}"));
        bail!("the hub refused the download: {why}");
    }
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    loop {
        let frame = tokio::time::timeout(READ_TIMEOUT, body.frame())
            .await
            .map_err(|_| anyhow!("the hub sent nothing for {READ_TIMEOUT:?}"))?;
        let Some(frame) = frame else { break };
        let frame = frame.context("downloading the release")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        written = written.saturating_add(data.len() as u64);
        if written > release.size {
            bail!(
                "the download is longer than the {} bytes the command named",
                release.size
            );
        }
        hasher.update(&data);
        file.write_all(&data)
            .with_context(|| format!("writing {}", tmp.display()))?;
    }
    driver.abort();
    let got = vk_fleet_proto::to_hex(&hasher.finalize());
    if got != release.sha256 {
        bail!(
            "the download hashes to {got}, not the {} the command named",
            release.sha256
        );
    }
    // Executable by this user alone, like everything under the node dir.
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting the mode on {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))?;
    Ok(())
}

/// Copy the running binary to `<releases>/<sha256>`, unless it is there already: the
/// previous release, kept to go back to.
fn keep_previous(releases: &Path, sha256: &str) -> Result<()> {
    let dest = releases.join(sha256);
    if dest.is_file() && hash_file(&dest).ok().as_deref() == Some(sha256) {
        return Ok(());
    }
    copy_published(Path::new("/proc/self/exe"), &dest, 0o700, Some(sha256))
}

/// The installed binary is not the one the trial started from.
#[derive(Debug)]
struct InstalledChanged(String);

impl std::fmt::Display for InstalledChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InstalledChanged {}

/// Install `release`, which must hash to `sha256`, as `trial.exe`: copied beside it — the
/// same filesystem, so publishing it is a rename — with `exe`'s mode, and renamed over it by
/// `vk-selfupdate`'s publish. Refused with [`InstalledChanged`] when `exe` is no longer the
/// file the trial started from.
fn install(release: &Path, sha256: &str, trial: &Trial) -> Result<()> {
    let exe = &trial.exe;
    let meta = std::fs::metadata(exe).with_context(|| format!("reading {}", exe.display()))?;
    if trial
        .exe_id
        .is_some_and(|id| id != (meta.dev(), meta.ino()))
    {
        return Err(anyhow::Error::new(InstalledChanged(format!(
            "{} was replaced by another vk during the trial; the release is not installed \
             over it",
            exe.display()
        ))));
    }
    let mode = (meta.permissions().mode() & 0o777) | 0o100;
    copy_published(release, exe, mode, Some(sha256))
}

/// Copy `from` to `to` through a private staging file beside it — named afresh, so nothing
/// a crash left can stand in the way — flushed, with `mode`, and published by rename, once
/// what was copied hashes to `sha256` when given.
fn copy_published(from: &Path, to: &Path, mode: u32, sha256: Option<&str>) -> Result<()> {
    let dir = to
        .parent()
        .with_context(|| format!("{} has no directory", to.display()))?;
    let src = std::fs::File::open(from).with_context(|| format!("opening {}", from.display()))?;
    let (tmp, mut out) = staging(dir, to)?;
    let copied = (|| {
        let got = hash_reader(src, Some(&mut out))
            .with_context(|| format!("copying {} to {}", from.display(), tmp.display()))?;
        if let Some(want) = sha256
            && got != want
        {
            bail!("{} hashes to {got}, not {want}", from.display());
        }
        out.set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode on {}", tmp.display()))?;
        out.sync_all()
            .with_context(|| format!("flushing {}", tmp.display()))?;
        vk_selfupdate::publish(&tmp, to, dir)
    })();
    if copied.is_err() {
        // Best effort: the error is what matters.
        let _ = std::fs::remove_file(&tmp);
    }
    copied
}

/// A new private file beside `to` to stage it in, `.<name>.<random>.tmp`.
fn staging(dir: &Path, to: &Path) -> Result<(PathBuf, std::fs::File)> {
    for _ in 0..8 {
        let mut name = std::ffi::OsString::from(".");
        name.push(to.file_name().unwrap_or_default());
        name.push(format!(
            ".{}.tmp",
            vk_fleet_proto::to_hex(&super::random_bytes(8)?)
        ));
        let tmp = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("creating {}", tmp.display())),
        }
    }
    bail!("no free staging name beside {}", to.display())
}

/// Remove what a download cut short left in the releases directory. Nothing else writes
/// there, and one `vk node` runs per node dir.
fn sweep_partial(releases: &Path) {
    let Ok(entries) = std::fs::read_dir(releases) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            // Best effort: a leftover costs space, not correctness.
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Keep only the releases named in `keep`: the installed one and the one before, or after a
/// rollback the one running.
fn prune(dir: &Path, keep: &[Option<String>]) {
    let releases = releases_dir(dir);
    let Ok(entries) = std::fs::read_dir(&releases) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if keep
            .iter()
            .flatten()
            .any(|k| name.as_encoded_bytes() == k.as_bytes())
        {
            continue;
        }
        // Best effort, as the sweep above.
        let _ = std::fs::remove_file(entry.path());
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::state::Issuer;
    use std::sync::Mutex;
    use vk_fleet_proto::{Command, Operation, RunnerState};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-update-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        dir
    }

    fn sha(bytes: &[u8]) -> String {
        vk_fleet_proto::to_hex(&Sha256::digest(bytes))
    }

    /// A node drained and switched to a release on trial, as `prepare` leaves it: the
    /// installed `bin/vk` holds "old", the release "new", and a copy of "old" is kept.
    fn on_trial(dir: &Path, attempts: u32, deadline: u64, confirmed: bool) -> Trial {
        let exe = dir.join("bin").join("vk");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let previous = releases_dir(dir).join(sha(b"old"));
        std::fs::write(&previous, b"old").unwrap();
        std::fs::set_permissions(&previous, std::fs::Permissions::from_mode(0o700)).unwrap();
        let next = releases_dir(dir).join(sha(b"new"));
        std::fs::write(&next, b"new").unwrap();
        let mut p = Persisted {
            issuer: Some(Issuer {
                hub: "https://hub".into(),
                node_id: "ab".repeat(16),
            }),
            ..Persisted::default()
        };
        p.command(
            Command {
                id: "u".into(),
                expires_at: u64::MAX,
                op: Operation::Update {
                    version: "0.81.0".into(),
                    sha256: sha(b"new"),
                    size: 3,
                    signature: None,
                    force: false,
                    within_secs: None,
                },
            },
            1,
            true,
        );
        assert!(p.finish_drain(1));
        let meta = std::fs::metadata(&exe).unwrap();
        let trial = Trial {
            exe,
            next,
            previous: Some(sha(b"old")),
            attempts,
            deadline,
            confirmed,
            exe_id: Some((meta.dev(), meta.ino())),
        };
        p.job.as_mut().unwrap().trial = Some(trial.clone());
        p.set_phase(NodeState::Validating, UpdatePhase::Validating);
        p.save(dir).unwrap();
        trial
    }

    fn outcome(dir: &Path) -> (Outcome, NodeState, Option<UpdatePhase>) {
        let p = Persisted::load(dir).unwrap();
        (
            p.journal[0].outcome.clone(),
            p.state,
            p.update.map(|u| u.phase),
        )
    }

    fn releases_left(dir: &Path) -> Vec<String> {
        let mut left: Vec<_> = std::fs::read_dir(releases_dir(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        left
    }

    #[test]
    fn the_previous_binary_hands_over_counting_attempts_then_takes_the_node_back() {
        let dir = scratch("attempts");
        let trial = on_trial(&dir, 1, u64::MAX, false);
        for attempt in 2..=MAX_ATTEMPTS {
            let Start::Exec(path) = on_start(&dir, 10).unwrap() else {
                panic!("expected a hand-over");
            };
            assert_eq!(path, trial.next);
            let p = Persisted::load(&dir).unwrap();
            assert_eq!(p.job.unwrap().trial.unwrap().attempts, attempt);
        }
        // One start too many: the node is back on the previous binary, the update failed.
        assert!(matches!(on_start(&dir, 10).unwrap(), Start::Run));
        let (o, state, phase) = outcome(&dir);
        assert!(
            matches!(&o, Outcome::Failed { message } if message.starts_with("rolled back")),
            "{o:?}"
        );
        let said = Persisted::load(&dir)
            .unwrap()
            .update
            .unwrap()
            .message
            .unwrap();
        assert!(said.starts_with("it was started"), "{said}");
        assert_eq!(state, NodeState::Ready);
        assert_eq!(phase, Some(UpdatePhase::RolledBack));
        assert_eq!(std::fs::read(&trial.exe).unwrap(), b"old");
        // The rejected release goes; the binary running stays.
        assert_eq!(releases_left(&dir), [sha(b"old")]);
        assert!(matches!(on_start(&dir, 10).unwrap(), Start::Run));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_trial_past_its_deadline_or_with_its_release_altered_is_rolled_back_at_start() {
        let dir = scratch("deadline");
        on_trial(&dir, 1, 100, false);
        assert!(matches!(on_start(&dir, 100).unwrap(), Start::Run));
        let (o, _, phase) = outcome(&dir);
        assert!(
            matches!(&o, Outcome::Failed { message } if message.contains("deadline")),
            "{o:?}"
        );
        assert_eq!(phase, Some(UpdatePhase::RolledBack));

        let trial = on_trial(&dir, 1, u64::MAX, false);
        std::fs::write(&trial.next, b"tampered").unwrap();
        assert!(matches!(on_start(&dir, 10).unwrap(), Start::Run));
        let (o, _, _) = outcome(&dir);
        assert!(
            matches!(&o, Outcome::Failed { message } if message.contains("no longer hashes")),
            "{o:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Validated and stopped while being installed: the next start finishes installing it
    /// and runs the binary now installed — unless someone replaced that binary meanwhile.
    #[test]
    fn a_confirmed_trial_is_installed_by_the_next_start_unless_the_binary_was_replaced() {
        let dir = scratch("confirmed");
        let trial = on_trial(&dir, 1, u64::MAX, true);
        std::fs::write(releases_dir(&dir).join("ef".repeat(32)), b"older").unwrap();
        // A staging file a crash left under a name of the old scheme is no obstacle.
        std::fs::write(dir.join("bin").join(".vk.1234.tmp"), b"junk").unwrap();
        let Start::Exec(path) = on_start(&dir, 10).unwrap() else {
            panic!("expected the installed binary to run");
        };
        assert_eq!(path, trial.exe);
        assert_eq!(std::fs::read(&trial.exe).unwrap(), b"new");
        assert_eq!(
            outcome(&dir),
            (Outcome::Done, NodeState::Ready, Some(UpdatePhase::Done))
        );
        assert_eq!(releases_left(&dir), [sha(b"new"), sha(b"old")]);

        let trial = on_trial(&dir, 1, u64::MAX, true);
        let other = dir.join("bin").join("other");
        std::fs::write(&other, b"someone else's vk").unwrap();
        std::fs::rename(&other, &trial.exe).unwrap();
        let Start::Exec(path) = on_start(&dir, 10).unwrap() else {
            panic!("expected the binary now installed to run");
        };
        assert_eq!(path, trial.exe);
        assert_eq!(std::fs::read(&trial.exe).unwrap(), b"someone else's vk");
        let (o, _, phase) = outcome(&dir);
        assert!(
            matches!(&o, Outcome::Failed { message } if message.contains("replaced")),
            "{o:?}"
        );
        assert_eq!(phase, Some(UpdatePhase::Failed));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_checks_what_it_copies_and_keeps_the_mode() {
        let dir = scratch("install");
        let trial = on_trial(&dir, 1, u64::MAX, true);
        std::fs::set_permissions(&trial.exe, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(install(&trial.next, &sha(b"other"), &trial).is_err());
        assert_eq!(std::fs::read(&trial.exe).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(dir.join("bin")).unwrap().count(), 1);
        install(&trial.next, &sha(b"new"), &trial).unwrap();
        assert_eq!(std::fs::read(&trial.exe).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&trial.exe).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(std::fs::read_dir(dir.join("bin")).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two updates without a restart: the second installs where the first did, not over
    /// the release the node runs from its releases directory.
    #[test]
    fn the_installed_path_is_never_a_release() {
        let dir = scratch("installed");
        let node = dir.join("node");
        std::fs::create_dir_all(releases_dir(&node)).unwrap();
        let exe = dir.join("bin").join("vk");
        std::fs::write(&exe, b"vk").unwrap();
        let release = releases_dir(&node).join(sha(b"new"));
        std::fs::write(&release, b"new").unwrap();
        let first = installed_after(None, exe.clone(), &node);
        assert_eq!(first.as_deref(), Some(exe.as_path()));
        let second = installed_after(first, release.clone(), &node);
        assert_eq!(second.as_deref(), Some(exe.as_path()));
        can_replace(second.as_deref(), &node).unwrap();
        let err = can_replace(Some(&release), &node).unwrap_err();
        assert!(err.contains("node's own directory"), "{err}");
        assert!(can_replace(None, &node).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_downgrade_needs_the_node_s_own_leave_and_never_goes_before_the_trial() {
        check_version("0.80.2", "0.80.2", false).unwrap();
        check_version("0.80.2", "0.81.0", false).unwrap();
        check_version("0.80.2", "1.0.0", false).unwrap();
        assert!(check_version("0.80.2", "0.80.1", false).is_err());
        check_version("0.80.2", "0.80.1", true).unwrap();
        let err = check_version("0.80.2", "0.79.3", true).unwrap_err();
        assert!(err.contains("predates"), "{err}");
        assert!(check_version("0.80.2", "0.80.2-rc1", true).is_err());
        assert!(check_version("0.80.2", "nightly", true).is_err());
    }

    static EXECUTED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Records the binary it was to execute, and fails as an exec would.
    fn fake_exec(path: &Path) -> anyhow::Error {
        EXECUTED.lock().unwrap().push(path.to_path_buf());
        anyhow!("not executing {} in a test", path.display())
    }

    fn executed(dir: &Path) -> Vec<PathBuf> {
        EXECUTED
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.starts_with(dir))
            .cloned()
            .collect()
    }

    fn core_on_trial(dir: &Path, deadline: u64) -> (Arc<Core>, Job, Trial) {
        let trial = on_trial(dir, 1, deadline, false);
        let (core, _) = Core::open(
            dir,
            true,
            Issuer {
                hub: "https://hub".into(),
                node_id: "ab".repeat(16),
            },
            watch::channel(RunnerState::Stopped).1,
        )
        .unwrap();
        let mut core = core;
        Arc::get_mut(&mut core).unwrap().set_exec(fake_exec);
        let job = core.persisted().job.unwrap();
        (core, job, trial)
    }

    #[tokio::test]
    async fn a_failed_trial_goes_back_to_the_installed_binary_then_to_its_copy() {
        let dir = scratch("rollback");
        let (core, job, trial) = core_on_trial(&dir, u64::MAX);
        conclude(&core, &job, &trial, Err("validation failed: kvm".into())).await;
        // Neither could be executed here: tried in order, and the node taken out of work.
        assert_eq!(
            executed(&dir),
            [trial.exe.clone(), releases_dir(&dir).join(sha(b"old"))]
        );
        let p = Persisted::load(&dir).unwrap();
        assert_eq!(p.state, NodeState::Quarantined);
        assert!(p.job.is_none());
        assert!(
            matches!(&p.journal[0].outcome, Outcome::Failed { message } if message.contains("validation failed")),
            "{:?}",
            p.journal
        );

        // The installed binary no longer the one replaced: only the kept copy is tried.
        let dir2 = scratch("rollback-copy");
        let (core, job, trial) = core_on_trial(&dir2, u64::MAX);
        std::fs::write(&trial.exe, b"something else").unwrap();
        conclude(&core, &job, &trial, Err("no hub".into())).await;
        assert_eq!(executed(&dir2), [releases_dir(&dir2).join(sha(b"old"))]);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[tokio::test]
    async fn a_passed_trial_is_installed_recorded_and_run_as_the_installed_binary() {
        let dir = scratch("passed");
        let (core, job, trial) = core_on_trial(&dir, u64::MAX);
        conclude(&core, &job, &trial, Ok(())).await;
        assert_eq!(executed(&dir), std::slice::from_ref(&trial.exe));
        assert_eq!(std::fs::read(&trial.exe).unwrap(), b"new");
        assert_eq!(
            outcome(&dir),
            (Outcome::Done, NodeState::Ready, Some(UpdatePhase::Done))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_hub_not_reached_by_the_deadline_fails_the_trial() {
        let dir = scratch("hub");
        let (core, _, _) = core_on_trial(&dir, u64::MAX);
        let soon = tokio::time::Instant::now() + Duration::from_millis(200);
        let err = wait_for_hub(&core, soon).await.unwrap_err();
        assert!(err.contains("hub was not reached"), "{err}");
        core.set_connected(true);
        wait_for_hub(&core, tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_validate_command_must_exit_0_in_time() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let t = Duration::from_secs(5);
        run_check(&[], t).await.unwrap();
        run_check(&argv(&["true"]), t).await.unwrap();
        let err = run_check(&argv(&["sh", "-c", "echo boot failed >&2; exit 3"]), t)
            .await
            .unwrap_err();
        assert!(err.contains("boot failed"), "{err}");
        let err = run_check(&argv(&["sleep", "30"]), Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(err.contains("did not finish"), "{err}");
        assert!(run_check(&argv(&["/nonexistent"]), t).await.is_err());
        // The release on trial is named for the command to use.
        run_check(&argv(&["sh", "-c", "test -n \"$VK_BINARY\""]), t)
            .await
            .unwrap();
    }

    #[test]
    fn the_running_binary_is_recognized_by_inode() {
        assert!(running_is(&std::env::current_exe().unwrap()));
        let dir = scratch("inode");
        let copy = dir.join("copy");
        std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
        assert!(!running_is(&copy));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release on trial is ended by the kernel at its deadline, hung or not: the child
    /// here arms the alarm as `vk node run` does and then waits for ever.
    #[test]
    fn the_trial_deadline_is_enforced_by_the_kernel() {
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        let mut child = std::process::Command::new("sh");
        child.args(["-c", "while :; do sleep 1; done"]);
        // SAFETY: the closure calls only `alarm`, async-signal-safe.
        unsafe {
            child.pre_exec(|| {
                libc::alarm(1);
                Ok(())
            });
        }
        let started = std::time::Instant::now();
        let status = child.status().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGALRM));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
