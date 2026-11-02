//! Updating the registry to a `vk-registry` release its hub holds, on trial, through
//! [`vk_peer::trial`]:
//!
//! 1. the release is downloaded from the hub under the registry's signature into
//!    `<root>/hub/releases/<sha256>`, checked against the command's digest and size, its
//!    signature against `[hub] release_keys`, and its `--version` against the command's;
//! 2. the running binary is kept beside it, by its own sha256, to go back to;
//! 3. the registry records a trial and executes the release in its place, `alarm(2)` armed
//!    past the trial's deadline;
//! 4. the release, once in session with the hub, records confirmation, then installs itself
//!    over the installed binary's path, by rename, and reports the update done; a registry
//!    stopped in between finishes the install on its next start.
//!
//! Until then the installed binary is left as it is: whatever starts `vk-registry serve` —
//! a supervisor restarting a release that crashed or hung, or a person — starts the previous
//! one, which counts the attempt and hands over again ([`on_start`]), or, past
//! [`MAX_ATTEMPTS`](vk_peer::trial::MAX_ATTEMPTS) or the deadline, takes the registry back and
//! reports the update rolled back. The connections open when the registry executes the release
//! are dropped, as by a manual restart. So `serve` needs a supervisor that restarts it: a
//! release that cannot reach the hub is ended by its alarm, and nothing else starts the
//! registry again. The registry notes no signals, so a SIGTERM ends it at once, as it always
//! has: one arriving after the exec ends the release, which a supervisor told to stop does not
//! start again, and the next start hands over again.
//!
//! The installed binary is the one `serve` last started from outside `<root>/hub/`, recorded
//! when it opens its hub link: a confirmed release goes on running from `releases/`, and the
//! next update still replaces the installed path.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use vk_hub_proto::registry::{Command, Operation};
use vk_hub_proto::{Outcome, UpdatePhase, UpdateProgress};
use vk_peer::trial::{self, Asked, Keeper, TRIAL_WINDOW, Trial};
use vk_peer::update::exec;

pub use vk_peer::trial::Start;

use super::Link;
use super::state::Persisted;

/// The previous binary's part in a trial, run by `serve` before anything else
/// ([`trial::on_start`]).
pub fn on_start(root: &Path, now: u64) -> Start {
    trial::on_start::<Persisted>(&super::dir(root), now)
}

impl Keeper for Link {
    type Ledger = Persisted;

    fn dir(&self) -> &Path {
        &self.dir
    }

    fn trial(&self) -> Option<Trial> {
        self.persisted().trial.clone()
    }

    fn change<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> Result<R> {
        self.update(f)
    }
}

/// The release on trial reached the hub: record that it passed, install it over the installed
/// binary and report the update done ([`trial::confirm`]).
pub(super) fn confirm(link: &Link) {
    trial::confirm(link);
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
    trial::check::<Persisted>(
        &Asked {
            version,
            sha256,
            size: *size,
            signature: signature.as_deref(),
        },
        env!("CARGO_PKG_VERSION"),
        link.ctx.settings.allow_downgrade,
        &link.policy,
        link.persisted().installed.as_deref(),
        &link.dir,
    )
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
    trial::failed(link, &command.id, version, sha256, why)
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
    let installed = link.persisted().installed.clone();
    let (trial, binary) =
        trial::stage::<Persisted>(&link.dir, &fetch, &command.id, version, installed).await?;
    // Held across the exec: a gc under way finishes first, and none starts after.
    let _gc = link.gc_running.lock().await;
    // Start the window after gc: collection can take longer than the window.
    let trial = Trial {
        deadline: vk_peer::now_secs() + TRIAL_WINDOW.as_secs(),
        ..trial
    };
    let deadline = trial.deadline;
    link.update(|p| {
        p.trial = Some(trial);
        p.update = Some(progress(UpdatePhase::Validating));
    })?;
    eprintln!("vk-registry: hub: executing vk-registry {version} on trial");
    Err(exec(&binary, Some(deadline)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    use super::*;

    /// A distant deadline distinct from the passed marker.
    const LATER: u64 = 1 << 40;

    fn temp(tag: &str) -> (PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("vk-registry-trial-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = super::super::dir(&root);
        std::fs::create_dir_all(trial::releases_dir(&dir)).unwrap();
        (root, dir)
    }

    fn update() -> Operation {
        Operation::Update {
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            size: 1,
            signature: None,
        }
    }

    fn trial(dir: &Path, attempts: u32) -> Trial {
        Trial {
            command: "c".into(),
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            exe: dir.join("absent-exe"),
            exe_id: (0, 0),
            next: dir.join("absent-next"),
            previous: "1".repeat(64),
            attempts,
            deadline: LATER,
            confirmed: false,
        }
    }

    /// An exhausted trial is rolled back in the registry's state file, with its command
    /// failed in the journal.
    #[test]
    fn a_trial_past_its_attempts_is_rolled_back_on_start() {
        let (root, dir) = temp("attempts");
        let mut p = Persisted::default();
        p.journal("c", update(), u64::MAX, Outcome::Accepted, 0);
        p.trial = Some(trial(&dir, trial::MAX_ATTEMPTS));
        p.save(&dir).unwrap();
        assert!(matches!(on_start(&root, 1), Start::Run));
        let p = Persisted::load(&dir).unwrap();
        assert!(p.trial.is_none());
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::RolledBack);
        assert!(matches!(
            p.entry("c").unwrap().outcome,
            Outcome::Failed { .. }
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_state_that_cannot_be_read_does_not_stop_serve() {
        let (root, dir) = temp("corrupt");
        std::fs::write(dir.join("state.json"), b"{ not json").unwrap();
        assert!(matches!(on_start(&root, 1), Start::Run));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A confirmed release stopped before installation replaces the installed binary on
    /// the next start and completes the update.
    #[test]
    fn a_confirmed_release_is_installed_on_the_next_start() {
        let (root, dir) = temp("confirmed");
        let exe = root.join("vk-registry");
        std::fs::write(&exe, b"previous").unwrap();
        let next = trial::releases_dir(&dir).join("2".repeat(64));
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
            ..trial(&dir, 1)
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
}
