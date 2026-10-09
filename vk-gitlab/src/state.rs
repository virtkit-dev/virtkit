//! The per-runner state file `docs/gitlab-dispatch.md` requires: every job the
//! runner has taken from GitLab, recorded before it is submitted to the hub or committed to
//! GitLab, so a restarted daemon resumes each — submits it again with the same
//! `request_id`, re-attaches to the hub job, continues its trace from the offset GitLab
//! acknowledged, and settles it.
//!
//! The file holds job tokens: it is created `0600` in a `0700` directory (a directory
//! others can enter is refused), and every write replaces it whole (written beside it,
//! synced, renamed, the directory synced). It also holds a fingerprint of the hub API key
//! its jobs were submitted with: the hub scopes jobs to the key that submitted them.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use vk_hub_proto::client::Placement;
use vk_hub_proto::job::JobSpec;

use crate::backoff::{hex, random_bytes};

/// A recorded job's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Taken from GitLab, not yet submitted to the hub (the spec is kept to submit it).
    Taken,
    /// Failed in GitLab before the hub confirmed its submission: submitted again with the
    /// same `request_id` only to learn the hub job, if any, and cancel and settle it.
    Abandoned,
    /// Submitted; not yet committed to GitLab.
    Submitted,
    /// Committed (`state=running`): its output is being copied into the trace.
    Committed,
    /// Its final state reached GitLab; only settling it with the hub is left.
    Reported,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct JobRecord {
    pub gitlab_job: i64,
    pub job_token: String,
    /// The hub `request_id` the job is (to be) submitted with.
    pub request_id: String,
    /// The original reservation and `place_within`: resubmitting the same `request_id`
    /// requires the same body, or the hub returns a conflict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation: Option<String>,
    pub place_within_secs: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_job: Option<String>,
    pub phase: Phase,
    /// The trace length GitLab acknowledged last.
    #[serde(default)]
    pub trace_offset: u64,
    /// The job's `features.failure_reasons`, to map its outcome.
    #[serde(default)]
    pub failure_reasons: Vec<String>,
    #[serde(default)]
    pub debug_trace: bool,
    /// The job's `FF_TIMESTAMPS`; older records default to on.
    #[serde(default = "timestamps_default")]
    pub timestamps: bool,
    pub placement: Placement,
    /// The spec, until the hub has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<JobSpec>,
}

impl std::fmt::Debug for JobRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobRecord")
            .field("gitlab_job", &self.gitlab_job)
            .field("hub_job", &self.hub_job)
            .field("phase", &self.phase)
            .field("trace_offset", &self.trace_offset)
            .finish_non_exhaustive()
    }
}

fn timestamps_default() -> bool {
    vk_hub_proto::stamp::DEFAULT
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct Contents {
    /// [`key_fingerprint`] of the hub API key the jobs were submitted with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hub_key: Option<String>,
    #[serde(default)]
    jobs: Vec<JobRecord>,
}

/// The first 8 bytes of the key's SHA-256, hex: tells keys apart without revealing them.
pub fn key_fingerprint(key: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
    hex(&digest.as_ref()[..8])
}

/// One runner's state file.
pub struct StateFile {
    path: PathBuf,
    contents: Mutex<Contents>,
}

impl std::fmt::Debug for StateFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl StateFile {
    /// Opens (or starts) the state file at `path`, creating its directory `0700`; a
    /// directory group or others can access is refused. Temporary files a crash left beside
    /// it are removed.
    pub fn open(path: &Path) -> Result<Self> {
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let mode = std::fs::metadata(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} is accessible to group or others (mode {:o}); the state files hold job tokens: `chmod 700` it",
                dir.display(),
                mode & 0o777
            );
        }
        let name = file_name(path);
        let stale = format!(".{name}.");
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&stale))
            {
                std::fs::remove_file(entry.path())
                    .with_context(|| format!("removing {}", entry.path().display()))?;
            }
        }
        Ok(Self {
            path: path.to_owned(),
            contents: Mutex::new(Self::read_contents(path)?),
        })
    }

    /// The records of the state file at `path`, read without touching it.
    pub fn read(path: &Path) -> Result<Vec<JobRecord>> {
        Ok(Self::read_contents(path)?.jobs)
    }

    fn read_contents(path: &Path) -> Result<Contents> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Contents>(&bytes)
                .with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Contents::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Contents> {
        self.contents.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn records(&self) -> Vec<JobRecord> {
        self.lock().jobs.clone()
    }

    pub fn get(&self, gitlab_job: i64) -> Option<JobRecord> {
        self.lock()
            .jobs
            .iter()
            .find(|r| r.gitlab_job == gitlab_job)
            .cloned()
    }

    /// The [`key_fingerprint`] the file records, if any.
    pub fn hub_key(&self) -> Option<String> {
        self.lock().hub_key.clone()
    }

    /// Records the hub API key's fingerprint, and writes the file.
    pub fn set_hub_key(&self, fingerprint: String) -> Result<()> {
        let mut c = self.lock();
        c.hub_key = Some(fingerprint);
        self.write(&c)
    }

    /// Adds `record`, or replaces the one of its job, and writes the file.
    pub fn put(&self, record: JobRecord) -> Result<()> {
        let mut c = self.lock();
        match c
            .jobs
            .iter_mut()
            .find(|r| r.gitlab_job == record.gitlab_job)
        {
            Some(r) => *r = record,
            None => c.jobs.push(record),
        }
        self.write(&c)
    }

    /// Changes the record of `gitlab_job`, if there is one, and writes the file.
    pub fn update(&self, gitlab_job: i64, f: impl FnOnce(&mut JobRecord)) -> Result<()> {
        let mut c = self.lock();
        let Some(r) = c.jobs.iter_mut().find(|r| r.gitlab_job == gitlab_job) else {
            return Ok(());
        };
        f(r);
        self.write(&c)
    }

    pub fn remove(&self, gitlab_job: i64) -> Result<()> {
        let mut c = self.lock();
        let before = c.jobs.len();
        c.jobs.retain(|r| r.gitlab_job != gitlab_job);
        if c.jobs.len() == before {
            return Ok(());
        }
        self.write(&c)
    }

    fn write(&self, contents: &Contents) -> Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        let tmp = dir.join(format!(
            ".{}.{}",
            file_name(&self.path),
            hex(&random_bytes::<6>())
        ));
        let body = serde_json::to_vec_pretty(contents)?;
        let written = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            std::fs::File::open(dir)?.sync_all()
        })();
        if let Err(e) = written {
            // Ours, and useless once the rename failed; nothing else depends on it.
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("writing {}", self.path.display()));
        }
        Ok(())
    }
}

fn file_name(path: &Path) -> &str {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("state")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: i64) -> JobRecord {
        JobRecord {
            gitlab_job: id,
            job_token: format!("tok-{id}"),
            request_id: "1".repeat(32),
            reservation: None,
            place_within_secs: 300,
            hub_job: None,
            phase: Phase::Taken,
            trace_offset: 0,
            failure_reasons: vec!["script_failure".to_owned()],
            debug_trace: false,
            timestamps: true,
            placement: Placement::default(),
            spec: None,
        }
    }

    #[test]
    fn a_record_from_before_timestamps_has_them_on() {
        let mut json = serde_json::to_value(JobRecord {
            timestamps: false,
            ..record(1)
        })
        .unwrap();
        json.as_object_mut().unwrap().remove("timestamps");
        let rec: JobRecord = serde_json::from_value(json).unwrap();
        assert!(rec.timestamps);
    }

    #[test]
    fn persists_privately_and_reloads() {
        let dir =
            std::env::temp_dir().join(format!("vk-gitlab-state-{}", hex(&random_bytes::<6>())));
        let path = dir.join("state").join("r1.json");
        let state = StateFile::open(&path).unwrap();
        state.put(record(1)).unwrap();
        state.put(record(2)).unwrap();
        state
            .update(1, |r| {
                r.phase = Phase::Committed;
                r.trace_offset = 42;
            })
            .unwrap();
        state.remove(2).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
        let again = StateFile::open(&path).unwrap();
        let records = again.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].phase, Phase::Committed);
        assert_eq!(records[0].trace_offset, 42);
        assert!(!format!("{:?}", records[0]).contains("tok-1"));
        // No temporary file is left behind.
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keeps_the_key_fingerprint_cleans_up_and_refuses_open_directories() {
        let dir =
            std::env::temp_dir().join(format!("vk-gitlab-state-{}", hex(&random_bytes::<6>())));
        let path = dir.join("r1.json");
        let state = StateFile::open(&path).unwrap();
        let fp = key_fingerprint("vkk_a");
        assert_eq!(fp.len(), 16);
        assert_ne!(fp, key_fingerprint("vkk_b"));
        state.set_hub_key(fp.clone()).unwrap();
        state.put(record(1)).unwrap();
        // A crash between writing the temporary file and renaming it.
        std::fs::write(dir.join(".r1.json.0123456789ab"), b"{").unwrap();
        std::fs::write(dir.join(".r2.json.0123456789ab"), b"{").unwrap();
        let again = StateFile::open(&path).unwrap();
        assert_eq!(again.hub_key(), Some(fp));
        assert_eq!(StateFile::read(&path).unwrap().len(), 1);
        assert!(!dir.join(".r1.json.0123456789ab").exists());
        assert!(
            dir.join(".r2.json.0123456789ab").exists(),
            "another runner's"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = StateFile::open(&path).err().unwrap().to_string();
        assert!(err.contains("chmod 700"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
