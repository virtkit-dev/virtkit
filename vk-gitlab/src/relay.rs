//! The relay's enrollment with its hub: `vk-gitlab join` generates the relay's key and
//! enrolls it with a single-use token from `vk-hub token create --kind gitlab`, and
//! `vk-gitlab leave` forgets it. See `docs/gitlab-relay-enrollment.md`.
//!
//! Everything kept for the hub is under `<state_dir>/hub/`, a `0700` directory: `key.pk8`
//! (the relay's private key), `enrollment.json` (the hub's URL and the relay's ID) and
//! `ca.pem` (the CA the hub is verified against, when `join` was given one). Jobs belong to
//! the relay that submitted them, so neither `join` nor `leave` runs while a runner's state
//! file still holds one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::EnrollRequest;
use vk_peer::identity::Identity;

use crate::state::StateFile;

const ENROLLMENT_FILE: &str = "enrollment.json";
/// Held by `run`, `join` and `leave`, in the state directory beside `hub/`.
const LOCK_FILE: &str = ".vk-gitlab.lock";
const CA_FILE: &str = "ca.pem";

/// `<state_dir>/hub`.
pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("hub")
}

/// What `join` leaves for `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub hub: String,
    pub relay_id: String,
    /// Whether the hub is verified against `ca.pem` alone rather than the system's roots.
    #[serde(default)]
    pub ca: bool,
}

/// An enrolled relay, as `run` reaches its hub.
pub struct Relay {
    pub enrollment: Enrollment,
    pub identity: Identity,
    pub tls: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("enrollment", &self.enrollment)
            .finish_non_exhaustive()
    }
}

/// `vk-gitlab join`: generate the relay's key under `<state_dir>/hub/` and enroll it with
/// `hub` using `token`. Refused on a relay already enrolled unless `replace`, which enrolls
/// it anew, the old enrollment moved aside, and put back if the new one fails. Returns the
/// relay's ID.
pub async fn join(
    state_dir: &Path,
    hub: &str,
    token: &vk_peer::net::TokenSource,
    ca: Option<&Path>,
    replace: bool,
) -> Result<String> {
    let hub = vk_peer::net::normalize_hub_url(hub)?;
    let _lock = lock(state_dir)?;
    let dir = dir(state_dir);
    let existing = match read_enrollment(&dir) {
        Ok(e) => Some(e),
        Err(e) if vk_peer::net::is_not_found(&e) => None,
        Err(e) => return Err(e.context("`vk-gitlab leave` removes an enrollment it cannot read")),
    };
    if let Some(existing) = &existing
        && !replace
    {
        bail!(
            "this relay is already enrolled with {} as {}: `vk-gitlab leave` first, or pass \
             --replace",
            existing.hub,
            existing.relay_id
        );
    }
    refuse_held_jobs(state_dir, "enrolling")?;
    if token.on_command_line() {
        log::warn!(
            "A token on the command line is visible to every local user in the process list; prefer `--token -` or --token-file"
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
            log::info!(kept = aside.display().to_string().as_str(); "The previous enrollment is kept aside");
            Ok(id)
        }
        (Err(e), Some(aside)) => {
            if let Err(e) = std::fs::remove_dir_all(&dir)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                log::error!(error = e.to_string().as_str(); "Removing {} failed", dir.display());
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
    let answer: vk_hub_proto::gitlab::EnrollResponse =
        vk_peer::net::enroll(hub, vk_hub_proto::gitlab::ENROLL_PATH, ca_pem, &ask).await?;
    if !vk_hub_proto::valid_id(&answer.relay_id) {
        bail!(
            "the hub assigned a malformed relay ID {:?}",
            vk_hub_proto::display_safe(&answer.relay_id)
        );
    }
    if let Some(pem) = ca_pem {
        vk_fs::write_atomic(&dir.join(CA_FILE), pem, 0o600).context("keeping the CA")?;
    }
    let enrollment = Enrollment {
        hub: hub.to_owned(),
        relay_id: answer.relay_id.clone(),
        ca: ca_pem.is_some(),
    };
    let json = serde_json::to_vec_pretty(&enrollment).context("encoding the enrollment")?;
    vk_fs::write_atomic(&dir.join(ENROLLMENT_FILE), &json, 0o600)
        .context("writing the enrollment")?;
    Ok(answer.relay_id)
}

/// `vk-gitlab leave`: forget the hub. Whether there was an enrollment to forget.
pub fn leave(state_dir: &Path) -> Result<bool> {
    let _lock = lock(state_dir)?;
    let dir = dir(state_dir);
    if std::fs::symlink_metadata(&dir).is_err() {
        return Ok(false);
    }
    refuse_held_jobs(state_dir, "leaving")?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", dir.display())),
    }
}

/// `enrollment.json`, checked as `join` writes it. A missing one is an `io::Error` of kind
/// `NotFound` at the root of the chain.
pub fn read_enrollment(dir: &Path) -> Result<Enrollment> {
    let path = dir.join(ENROLLMENT_FILE);
    let bytes = vk_peer::net::read_nofollow(&path)?;
    let mut e: Enrollment =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    e.hub = vk_peer::net::normalize_hub_url(&e.hub)?;
    if !vk_hub_proto::valid_id(&e.relay_id) {
        bail!("{} holds a malformed relay ID", path.display());
    }
    Ok(e)
}

/// The enrolled relay of `state_dir`, refused when it is not enrolled.
pub fn open(state_dir: &Path) -> Result<Relay> {
    let dir = dir(state_dir);
    let enrollment = match read_enrollment(&dir) {
        Ok(e) => e,
        Err(e) if vk_peer::net::is_not_found(&e) => bail!(
            "this relay is not enrolled with a hub: `vk-hub token create --kind gitlab | \
             vk-gitlab join <hub-url> --token -` (it keeps its enrollment in {})",
            dir.display()
        ),
        Err(e) => return Err(e),
    };
    vk_peer::net::check_private(&dir)?;
    let identity = Identity::load(&dir)?;
    let tls = vk_peer::net::client_tls(enrollment.ca.then(|| dir.join(CA_FILE)).as_deref())?;
    Ok(Relay {
        enrollment,
        identity,
        tls,
    })
}

/// Hold `state_dir` for as long as the returned file lives, creating it `0700` first and
/// refusing it unless it is private to this user: one `vk-gitlab run`, `join` or `leave` at a
/// time, so no job is recorded under an enrollment being replaced.
pub fn lock(state_dir: &Path) -> Result<std::fs::File> {
    vk_peer::net::create_dir(state_dir)?;
    vk_peer::net::lock_tries(state_dir, LOCK_FILE, 1, "vk-gitlab run, join or leave")
}

/// Refuse `what` while a runner's state file in `state_dir` holds a job: it belongs to the
/// relay that submitted it, which a new enrollment, or none, could not reach.
fn refuse_held_jobs(state_dir: &Path, what: &str) -> Result<()> {
    let entries = match std::fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", state_dir.display())),
    };
    let mut held = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", state_dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        let jobs = StateFile::read(&entry.path())?.len();
        if jobs > 0 {
            held.push(format!("{} ({jobs} job(s))", entry.path().display()));
        }
    }
    if !held.is_empty() {
        bail!(
            "{what} is refused while jobs are held, submitted as this relay: {}. Stop \
             `vk-gitlab run` with SIGTERM and let it drain, or remove the files to give the \
             jobs up (GitLab then times them out)",
            held.join(", ")
        );
    }
    Ok(())
}

/// The host's name, as the hub lists the relay.
pub fn hostname() -> String {
    // If unreadable, the relay is listed with an empty hostname.
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{JobRecord, Phase};

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vk-gitlab-relay-{}",
            crate::backoff::hex(&crate::backoff::random_bytes::<6>())
        ));
        vk_peer::net::create_dir(&dir).unwrap();
        dir
    }

    fn enrolled(state: &Path) {
        let dir = dir(state);
        vk_peer::net::create_dir(&dir).unwrap();
        Identity::load_or_create(&dir).unwrap();
        let e = Enrollment {
            hub: "https://hub.example.com".into(),
            relay_id: "0123456789abcdef0123456789abcdef".into(),
            ca: false,
        };
        std::fs::write(dir.join(ENROLLMENT_FILE), serde_json::to_vec(&e).unwrap()).unwrap();
    }

    #[test]
    fn an_enrollment_opens_and_leaves() {
        let state = temp();
        let err = open(&state).unwrap_err().to_string();
        assert!(err.contains("vk-gitlab join"), "{err}");
        assert!(!leave(&state).unwrap());
        enrolled(&state);
        let relay = open(&state).unwrap();
        assert_eq!(relay.enrollment.hub, "https://hub.example.com");
        assert!(leave(&state).unwrap());
        assert!(!dir(&state).exists());
        std::fs::remove_dir_all(&state).unwrap();
    }

    #[test]
    fn a_state_directory_others_reach_is_not_locked() {
        use std::os::unix::fs::PermissionsExt;
        let state = temp();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = format!("{:#}", lock(&state).unwrap_err());
        assert!(err.contains("private"), "{err}");
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(lock(&state).unwrap());
        std::fs::remove_dir_all(&state).unwrap();
    }

    #[tokio::test]
    async fn held_jobs_refuse_join_and_leave() {
        let state = temp();
        enrolled(&state);
        let file = StateFile::open(&state.join("ci.json")).unwrap();
        file.put(JobRecord {
            gitlab_job: 1,
            job_token: "jt".into(),
            request_id: "1".repeat(32),
            reservation: None,
            place_within_secs: 1,
            hub_job: None,
            phase: Phase::Committed,
            trace_offset: 0,
            failure_reasons: vec![],
            debug_trace: false,
            timestamps: true,
            placement: Default::default(),
            spec: None,
        })
        .unwrap();
        let err = leave(&state).unwrap_err().to_string();
        assert!(err.contains("ci.json (1 job(s))"), "{err}");
        let token = vk_peer::net::TokenSource::Literal("vkh_x".into());
        let err = join(&state, "https://hub.example.com", &token, None, true)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("while jobs are held"), "{err}");
        let err = join(&state, "https://hub.example.com", &token, None, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("already enrolled"), "{err}");
        file.remove(1).unwrap();
        // Not while `run` holds the state directory.
        let held = lock(&state).unwrap();
        let err = format!("{:#}", leave(&state).unwrap_err());
        assert!(err.contains("one at a time"), "{err}");
        drop(held);
        // An enrollment that does not read is not taken for none.
        let path = dir(&state).join(ENROLLMENT_FILE);
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"{").unwrap();
        let err = format!(
            "{:#}",
            join(&state, "https://hub.example.com", &token, None, true)
                .await
                .unwrap_err()
        );
        assert!(err.contains("parsing"), "{err}");
        std::fs::write(&path, good).unwrap();
        assert!(leave(&state).unwrap());
        std::fs::remove_dir_all(&state).unwrap();
    }
}
