//! Updating the registry to a `vk-registry` release its hub holds, on trial:
//!
//! 1. the release is downloaded from the hub under the registry's signature into
//!    `<root>/hub/releases/<sha256>`, checked against the command's digest and size, its
//!    signature against `[hub] release_keys`, and its `--version` against the command's;
//! 2. the running binary is kept beside it, by its own sha256, to go back to;
//! 3. the registry records a trial and executes the release in its place, `alarm(2)` armed
//!    past the trial's deadline;
//! 4. the release, once it is in session with the hub, installs itself over the installed
//!    binary's path, by rename, and reports the update done.
//!
//! Until then the installed binary is left as it is: whatever starts `vk-registry serve` —
//! a supervisor restarting a release that crashed or hung, or a person — starts the previous
//! one, which counts the attempt and hands over again ([`on_start`]), or, past
//! [`MAX_ATTEMPTS`] or the deadline, takes the registry back and reports the update rolled
//! back. The connections open when the registry executes the release are dropped, as by a
//! manual restart. So `serve` needs a supervisor that restarts it: a release that cannot
//! reach the hub is ended by its alarm, and nothing else starts the registry again.
//!
//! The installed binary is the one `serve` last started from outside `<root>/hub/`, recorded
//! when it opens its hub link: a confirmed release goes on running from `releases/`, and the
//! next update still replaces the installed path.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use vk_hub_proto::registry::{Command, Operation};
use vk_hub_proto::{Outcome, UpdatePhase, UpdateProgress};
use vk_peer::update::{Binary, exec, keep_previous, own_sha256, running_is};

use super::Link;
use super::state::{Persisted, Trial};

/// How many times a release on trial may be started before the previous binary takes the
/// registry back.
pub const MAX_ATTEMPTS: u32 = 3;

/// How long a release on trial has to reach the hub.
const TRIAL_WINDOW: Duration = Duration::from_secs(120);

/// The largest release a registry takes, whatever a command says.
const MAX_RELEASE: u64 = 1 << 30;

/// How long a download may take in all.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

fn releases_dir(dir: &Path) -> PathBuf {
    dir.join("releases")
}

/// What `serve` does on starting.
pub enum Start {
    Run,
    /// Execute this binary in place of this one, `alarm(2)` armed for this deadline.
    Exec(Binary, Option<u64>),
}

/// The previous binary's part in a trial, run by `serve` before anything else: count the
/// start and hand over to the release, or, past [`MAX_ATTEMPTS`] or the deadline, end the
/// trial and serve on as the registry's binary. The release on trial arms its own deadline.
/// A state that cannot be read or written is logged and the registry serves: what the hub
/// asked must never stop it.
pub fn on_start(root: &Path, now: u64) -> Start {
    let dir = super::dir(root);
    if !dir.is_dir() {
        return Start::Run;
    }
    let mut p = match Persisted::load(&dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vk-registry: hub: {e:#}");
            return Start::Run;
        }
    };
    let save = |p: &Persisted| {
        if let Err(e) = p.save(&dir) {
            eprintln!("vk-registry: hub: {e:#}");
        }
    };
    let Some(trial) = p.trial.clone() else {
        return Start::Run;
    };
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
            eprintln!(
                "vk-registry: hub: starting vk-registry {} on trial (attempt {})",
                trial.version,
                trial.attempts + 1
            );
            Start::Exec(binary, Some(trial.deadline))
        }
        Err(why) => {
            eprintln!(
                "vk-registry: hub: update to {} rolled back: {why}",
                trial.version
            );
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

/// The installed binary to record when `serve` runs `exe`, `recorded` before; `None` to keep
/// what is recorded. A binary under the hub directory `dir` is a release, never the installed
/// one.
pub(super) fn installed_after(
    recorded: Option<&Path>,
    exe: PathBuf,
    dir: &Path,
) -> Option<PathBuf> {
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

/// The release on trial reached the hub: install it over the installed binary and report
/// the update done. Nothing to do when no trial runs this binary.
pub(super) fn confirm(link: &Link) {
    let trial = link.persisted().trial.clone();
    let Some(trial) = trial.filter(|t| running_is(&t.next)) else {
        return;
    };
    vk_peer::update::alarm(None, 0);
    let installed = install(&trial);
    let result = link.update(|p| match &installed {
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
            prune(&link.dir, &[&trial.sha256, &trial.previous]);
            eprintln!(
                "vk-registry: hub: vk-registry {} installed at {}",
                trial.version,
                trial.exe.display()
            )
        }
        (Err(e), _) | (_, Err(e)) => eprintln!("vk-registry: hub: installing the update: {e:#}"),
    }
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

/// Whether the registry takes `command`, an update: `Ok` with its first outcome, `Err` with
/// why it refuses.
pub(super) fn accept(link: &Link, command: &Command) -> Result<Outcome, String> {
    let Operation::Update {
        version,
        sha256,
        size,
        signature,
    } = &command.op
    else {
        return Err("not an update".to_string());
    };
    if link.persisted().update_under_way() {
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
    check_version(
        env!("CARGO_PKG_VERSION"),
        version,
        link.ctx.settings.allow_downgrade,
    )?;
    link.policy.check(sha256, version, signature.as_deref())?;
    can_replace(link.persisted().installed.as_deref(), &link.dir)?;
    Ok(Outcome::Accepted)
}

/// Whether the registry may install over the installed binary `installed`: recorded, a file
/// outside `dir`, in a directory this user can write, since the release is renamed into it.
fn can_replace(installed: Option<&Path>, dir: &Path) -> Result<(), String> {
    let exe = installed.ok_or_else(|| {
        "the installed vk-registry is not known yet: restart vk-registry serve from it".to_string()
    })?;
    if !exe.is_file() {
        return Err(format!("{} is gone", exe.display()));
    }
    if vk_peer::update::under(exe, dir) {
        return Err(format!(
            "{} is inside the registry's hub directory; run vk-registry from its installed path",
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
            "vk-registry cannot replace {}: {} is not writable by this user",
            exe.display(),
            parent.display()
        ));
    }
    Ok(())
}

/// Whether a registry running `own` may update to `candidate`: not to an older version
/// unless `allow_downgrade`. Versions are `MAJOR.MINOR.PATCH`.
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
            "vk-registry {candidate} is older than this registry's {own}; [hub] \
             allow_downgrade = true lets an update install it"
        )),
        _ if candidate == own => Ok(()),
        _ => Err(format!(
            "vk-registry {candidate} cannot be ordered against {own}; versions are \
             MAJOR.MINOR.PATCH"
        )),
    }
}

/// Carry out the update `command` was accepted for: download, check, keep the running binary,
/// record the trial and execute the release. Reports a failure and serves on.
pub(super) fn spawn(link: Arc<Link>, command: Command) {
    tokio::spawn(async move {
        if let Err(e) = prepare(&link, &command).await {
            eprintln!("vk-registry: hub: update failed: {e:#}");
            if let Err(e) = failed(&link, &command, &format!("{e:#}")) {
                eprintln!("vk-registry: hub: {e:#}");
            }
        }
    });
}

/// Record that the update `command` failed with `why`. A trial recorded before an exec that
/// failed is undone, and its release dropped: no release runs on trial.
pub(super) fn failed(link: &Link, command: &Command, why: &str) -> Result<()> {
    let Operation::Update {
        version, sha256, ..
    } = &command.op
    else {
        return Ok(());
    };
    let undone = link.update(|p| {
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
        prune(&link.dir, &[&trial.previous]);
    }
    Ok(())
}

async fn prepare(link: &Arc<Link>, command: &Command) -> Result<()> {
    let Operation::Update {
        version,
        sha256,
        size,
        ..
    } = &command.op
    else {
        return Ok(());
    };
    let progress = |phase| UpdateProgress {
        command: command.id.clone(),
        version: version.clone(),
        sha256: sha256.clone(),
        phase,
        message: None,
    };
    link.update(|p| p.update = Some(progress(UpdatePhase::Downloading)))?;
    let releases = releases_dir(&link.dir);
    vk_peer::net::create_dir(&releases)?;
    vk_peer::update::sweep_partial(&releases);
    let next = releases.join(sha256);
    if !next.is_file() {
        let fetch = vk_peer::update::Download {
            hub: &link.enrollment.hub,
            tls: &link.tls,
            identity: &link.identity,
            id: &link.enrollment.registry_id,
            id_header: vk_hub_proto::registry::REGISTRY_HEADER,
            path: vk_hub_proto::registry::RELEASE_PATH,
            sign: vk_hub_proto::download_message,
            sha256,
            size: *size,
            mode: 0o700,
        };
        tokio::time::timeout(DOWNLOAD_TIMEOUT, vk_peer::update::download(&fetch, &next))
            .await
            .map_err(|_| anyhow!("the download took longer than {DOWNLOAD_TIMEOUT:?}"))??;
    }
    let installed = link.persisted().installed.clone();
    let (dir, next2, version2, sha2, id) = (
        link.dir.clone(),
        next.clone(),
        version.clone(),
        sha256.clone(),
        command.id.clone(),
    );
    let trial = tokio::task::spawn_blocking(move || -> Result<(Trial, Binary)> {
        let binary = Binary::open(&next2, Some(&sha2))?;
        vk_selfupdate::smoke_test_file("vk-registry", binary.file(), binary.path(), &version2)?;
        let own = own_sha256().context("reading the running binary")?;
        keep_previous(&releases_dir(&dir), &own)?;
        let exe = installed.context("the installed vk-registry is not known")?;
        let meta = std::fs::metadata(&exe).with_context(|| format!("reading {}", exe.display()))?;
        let trial = Trial {
            command: id,
            version: version2,
            sha256: sha2,
            exe,
            exe_id: (meta.dev(), meta.ino()),
            next: next2,
            previous: own,
            attempts: 1,
            deadline: vk_peer::now_secs() + TRIAL_WINDOW.as_secs(),
        };
        Ok((trial, binary))
    })
    .await
    .context("checking the release")??;
    let (trial, binary) = trial;
    let deadline = trial.deadline;
    // Held across the exec: a gc under way finishes first, and none starts after.
    let _gc = link.gc_running.lock().await;
    link.update(|p| {
        p.trial = Some(trial);
        p.update = Some(progress(UpdatePhase::Validating));
    })?;
    eprintln!("vk-registry: hub: executing vk-registry {version} on trial");
    Err(exec(&binary, Some(deadline)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_only_go_forward_unless_allowed() {
        assert!(check_version("0.88.0", "0.89.0", false).is_ok());
        assert!(check_version("0.88.0", "0.88.0", false).is_ok());
        assert!(check_version("0.88.0", "0.87.0", false).is_err());
        assert!(check_version("0.88.0", "0.87.0", true).is_ok());
        assert!(check_version("0.88.0", "nightly", true).is_err());
    }

    #[test]
    fn a_trial_past_its_attempts_is_rolled_back_on_start() {
        let root = std::env::temp_dir().join(format!("vk-registry-trial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = super::super::dir(&root);
        std::fs::create_dir_all(&dir).unwrap();
        let mut p = Persisted::default();
        p.journal(
            "c",
            Operation::Update {
                version: "9.9.9".into(),
                sha256: "0".repeat(64),
                size: 1,
                signature: None,
            },
            u64::MAX,
            Outcome::Accepted,
        );
        p.trial = Some(Trial {
            command: "c".into(),
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            exe: dir.join("absent-exe"),
            exe_id: (0, 0),
            next: dir.join("absent-next"),
            previous: "1".repeat(64),
            attempts: MAX_ATTEMPTS,
            deadline: u64::MAX,
        });
        p.save(&dir).unwrap();
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        for release in ["0", "1", "2"] {
            std::fs::write(releases_dir(&dir).join(release.repeat(64)), b"r").unwrap();
        }
        assert!(matches!(on_start(&root, 1), Start::Run));
        let p = Persisted::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::RolledBack);
        assert!(matches!(
            p.entry("c").unwrap().outcome,
            Outcome::Failed { .. }
        ));
        // Only the binary that runs again is kept.
        let mut kept: Vec<_> = std::fs::read_dir(releases_dir(&dir))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        kept.sort();
        assert_eq!(kept, vec![std::ffi::OsString::from("1".repeat(64))]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_state_that_cannot_be_read_does_not_stop_serve() {
        let root = std::env::temp_dir().join(format!("vk-registry-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = super::super::dir(&root);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("state.json"), b"{ not json").unwrap();
        assert!(matches!(on_start(&root, 1), Start::Run));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The installed binary is the last one `serve` started from outside the hub directory:
    /// a confirmed release running from `releases/` leaves it as recorded.
    #[test]
    fn the_installed_binary_is_never_a_release() {
        let root =
            std::env::temp_dir().join(format!("vk-registry-installed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = super::super::dir(&root);
        std::fs::create_dir_all(releases_dir(&dir)).unwrap();
        let installed = root.join("vk-registry");
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
