//! Runners added on the hub, when `[hub] allow` lists `runners`: GitLab created the runner,
//! the hub hands its token to the relay, and the relay keeps it in
//! `<state_dir>/runners/<name>.toml` (`0600`, written whole), its one stored copy, beside the
//! settings, the GitLab runner ID and the command that added it. See
//! `docs/gitlab-relay-enrollment.md`, "Runners added on the hub".
//!
//! `run` loads the config's runners, then these. [`Runners`] changes them at run time, under
//! one lock: an add checks the name and the count, verifies the token with GitLab, writes the
//! file and has the poll loop start the runner; a removal marks the file removed and has the
//! loop stop the runner's job requests. Once a removed runner's state file holds no job, both
//! files go, and the name with them.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use vk_hub_proto::gitlab::{MAX_RUNNERS, RunnerFailure, RunnerToken};

use crate::config::{Config, HubOrigin, RunnerConfig, valid_name};
use crate::dispatch::Placement;
use crate::secret::Secret;
use crate::session::{RunnerStatus, Status};
use crate::state::StateFile;

/// `<state_dir>/runners`.
pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("runners")
}

const EXTENSION: &str = "toml";

/// A runner file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerFile {
    name: String,
    token: String,
    runner_id: u64,
    command: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    removed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    request_concurrency: u32,
    placement: Placement,
}

impl RunnerFile {
    fn of(r: &RunnerConfig) -> Option<Self> {
        let hub = r.hub.as_ref()?;
        Some(RunnerFile {
            name: r.name.clone(),
            token: r.token().expose().to_owned(),
            runner_id: hub.runner_id,
            command: hub.command.clone(),
            removed: hub.removed,
            limit: (r.limit > 0).then(|| u32::try_from(r.limit).unwrap_or(u32::MAX)),
            request_concurrency: u32::try_from(r.request_concurrency()).unwrap_or(u32::MAX),
            placement: r.placement(),
        })
    }

    fn runner(&self) -> Result<RunnerConfig> {
        RunnerConfig::from_hub(
            &self.name,
            &self.token,
            &self.placement,
            self.limit,
            self.request_concurrency,
            HubOrigin {
                command: self.command.clone(),
                runner_id: self.runner_id,
                removed: self.removed,
            },
        )
    }
}

/// Parse runner file `path`, holding `bytes`. An error names the line at fault, never its
/// text: it may hold the token.
fn parse(path: &Path, bytes: Vec<u8>) -> Result<RunnerFile> {
    let text = String::from_utf8(bytes).map_err(|_| anyhow!("{}: not UTF-8", path.display()))?;
    toml::from_str(&text).map_err(|e| {
        let line = e
            .span()
            .map(|s| text[..s.start.min(text.len())].matches('\n').count() + 1);
        match line {
            Some(line) => anyhow!("parsing {}: malformed at line {line}", path.display()),
            None => anyhow!("parsing {}: malformed", path.display()),
        }
    })
}

fn file(state_dir: &Path, name: &str) -> PathBuf {
    dir(state_dir).join(format!("{name}.{EXTENSION}"))
}

/// Write runner `r`'s file, private, whole and durably: it holds the one copy of its token.
fn write(state_dir: &Path, r: &RunnerConfig) -> Result<()> {
    let dir = dir(state_dir);
    vk_peer::net::create_dir(&dir)?;
    let f = RunnerFile::of(r).context("not a runner added on the hub")?;
    let text = toml::to_string(&f).context("encoding the runner file")?;
    let path = file(state_dir, &r.name);
    vk_fs::write_atomic_durable(&path, text.as_bytes(), 0o600)
        .with_context(|| format!("writing {}", path.display()))
}

/// The runners added on the hub to the relay `cfg` configures, by name. A file that does not
/// parse, a name the config or another file has, or more than
/// [`MAX_RUNNERS`] runners in all, is an error: a removed runner's jobs resume only with its
/// settings.
pub fn load(cfg: &Config) -> Result<Vec<RunnerConfig>> {
    let state_dir = state_dir(cfg);
    let dir = dir(&state_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    vk_peer::net::check_private(&dir)?;
    let mut runners = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let Some(stem) = file_name
            .to_str()
            .and_then(|n| n.strip_suffix(&format!(".{EXTENSION}")))
        else {
            continue;
        };
        if stem.starts_with('.') {
            continue;
        }
        let f = parse(&path, vk_peer::net::read_nofollow(&path)?)?;
        if f.name != stem {
            bail!("{}: names runner {:?}", path.display(), f.name);
        }
        runners.push(
            f.runner()
                .with_context(|| format!("loading {}", path.display()))?,
        );
    }
    runners.sort_by(|a, b| a.name.cmp(&b.name));
    let config: Vec<&RunnerConfig> = cfg.runners.iter().filter(|c| c.hub.is_none()).collect();
    for r in &runners {
        if config.iter().any(|c| c.name == r.name) {
            bail!(
                "runner {:?} is both in the config and added on the hub ({})",
                r.name,
                file(&state_dir, &r.name).display()
            );
        }
    }
    if config.len() + runners.len() > MAX_RUNNERS {
        bail!("too many runners for the hub session: the config's and those added on the hub");
    }
    Ok(runners)
}

fn state_dir(cfg: &Config) -> PathBuf {
    cfg.state_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(crate::config::DEFAULT_STATE_DIR))
}

/// What the poll loop is told to do.
#[derive(Debug)]
pub enum Change {
    /// Start a runner just added.
    Start(Box<RunnerConfig>),
    /// Stop runner `name`'s job requests; it goes once its jobs have ended.
    Remove(String),
}

/// A runner added on the hub, as the relay runs it.
#[derive(Debug, Clone)]
struct Added {
    name: String,
    origin: HubOrigin,
    token: Secret,
}

#[derive(Debug, Default)]
struct Inner {
    /// The config's runners' names and tokens.
    config: Vec<(String, Secret)>,
    hub: Vec<Added>,
    /// Names of runners being added: verified with GitLab.
    adding: Vec<String>,
}

impl Inner {
    fn count(&self) -> usize {
        self.config.len() + self.hub.len() + self.adding.len()
    }

    fn taken(&self, name: &str) -> bool {
        self.config.iter().any(|(n, _)| n == name)
            || self.hub.iter().any(|a| a.name == name)
            || self.adding.iter().any(|n| n == name)
    }
}

/// The relay's runners, as the hub changes them.
pub struct Runners {
    state_dir: PathBuf,
    gitlab_url: String,
    system_id: String,
    status: Arc<Status>,
    inner: Mutex<Inner>,
    changes: mpsc::UnboundedSender<Change>,
}

impl std::fmt::Debug for Runners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runners")
            .field("state_dir", &self.state_dir)
            .finish_non_exhaustive()
    }
}

impl Runners {
    /// The runners of `cfg`, whose `runners` hold the config's and those [`load`]ed, and what
    /// the poll loop is to take changes from.
    pub fn new(
        cfg: &Config,
        system_id: &str,
        status: Arc<Status>,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Change>) {
        let (changes, rx) = mpsc::unbounded_channel();
        let mut inner = Inner::default();
        for r in &cfg.runners {
            match &r.hub {
                Some(origin) => inner.hub.push(Added {
                    name: r.name.clone(),
                    origin: origin.clone(),
                    token: r.token().clone(),
                }),
                None => inner.config.push((r.name.clone(), r.token().clone())),
            }
        }
        let runners = Arc::new(Runners {
            state_dir: state_dir(cfg),
            gitlab_url: cfg.gitlab_url().to_owned(),
            system_id: system_id.to_owned(),
            status,
            inner: Mutex::new(inner),
            changes,
        });
        (runners, rx)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the runner identified by `name`, `runner_id` and `command` is absent or
    /// marked removed.
    pub fn removed(&self, name: &str, runner_id: u64, command: &str) -> bool {
        !self.lock().hub.iter().any(|a| {
            a.name == name
                && a.origin.runner_id == runner_id
                && a.origin.command == command
                && !a.origin.removed
        })
    }

    /// Whether the runner added by command `command` is the relay's.
    pub fn added_by(&self, command: &str) -> bool {
        self.lock().hub.iter().any(|a| a.origin.command == command)
    }

    /// Add the runner GitLab knows by `token` as `name`, for command `command`: verify the
    /// token, write the runner's file and start it. Its GitLab runner ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn add(
        &self,
        command: &str,
        name: &str,
        token: &RunnerToken,
        placement: &Placement,
        limit: Option<u32>,
        request_concurrency: u32,
    ) -> Result<u64, RunnerFailure> {
        let origin = HubOrigin {
            command: command.to_owned(),
            runner_id: 0,
            removed: false,
        };
        let mut cfg = RunnerConfig::from_hub(
            name,
            token.expose(),
            placement,
            limit,
            request_concurrency,
            origin,
        )
        .map_err(|e| {
            log::warn!(runner = name, error = format!("{e:#}").as_str(); "The hub asked for a runner this relay cannot run");
            if valid_name(name) {
                RunnerFailure::Other
            } else {
                RunnerFailure::NameTaken
            }
        })?;
        {
            let mut inner = self.lock();
            if inner.taken(name) || self.holds_jobs(name) {
                return Err(RunnerFailure::NameTaken);
            }
            if inner.count() >= MAX_RUNNERS {
                return Err(RunnerFailure::TooManyRunners);
            }
            inner.adding.push(name.to_owned());
        }
        let verified = self.verify(&cfg).await;
        let mut inner = self.lock();
        inner.adding.retain(|n| n != name);
        let runner_id = verified?;
        // By ID, and by token for a config runner not verified yet: one token is one runner.
        if inner
            .hub
            .iter()
            .any(|a| a.origin.runner_id == runner_id || a.token == *cfg.token())
            || inner.config.iter().any(|(_, t)| t == cfg.token())
            || self.status.runner_ids().contains(&runner_id)
        {
            return Err(RunnerFailure::RunnerTaken);
        }
        if let Some(hub) = &mut cfg.hub {
            hub.runner_id = runner_id;
        }
        if let Err(e) = write(&self.state_dir, &cfg) {
            log::error!(runner = name, error = format!("{e:#}").as_str(); "Keeping the runner added on the hub failed");
            // Nothing kept, nothing run.
            return Err(RunnerFailure::Other);
        }
        inner.hub.push(Added {
            name: name.to_owned(),
            origin: cfg.hub.clone().unwrap_or(HubOrigin {
                command: command.to_owned(),
                runner_id,
                removed: false,
            }),
            token: cfg.token().clone(),
        });
        let mut status = RunnerStatus::new(&cfg);
        status.runner.verified = true;
        self.status.add_runner(status);
        log::info!(runner = name, runner_id; "Runner added on the hub");
        // A loop that has ended starts it on the next start, from its file.
        let _ = self.changes.send(Change::Start(Box::new(cfg)));
        Ok(runner_id)
    }

    /// Whether runner `name`'s state file holds a job: one from a runner of that name gone
    /// from the config, which a new runner must not take over.
    fn holds_jobs(&self, name: &str) -> bool {
        let path = self.state_dir.join(format!("{name}.json"));
        StateFile::read(&path).map_or(true, |jobs| !jobs.is_empty())
    }

    /// The GitLab runner ID `verify` gives runner `cfg`.
    async fn verify(&self, cfg: &RunnerConfig) -> Result<u64, RunnerFailure> {
        let client = crate::poll::client_for(
            &self.gitlab_url,
            cfg,
            &self.system_id,
            crate::poll::runner_info(),
            Default::default(),
        )
        .map_err(|e| {
            log::error!(runner = cfg.name.as_str(), error = format!("{e:#}").as_str(); "Reaching GitLab for a runner added on the hub failed");
            RunnerFailure::GitlabUnreachable
        })?;
        let answer = client.verify().await;
        self.status.set_spki(client.spki_sha256());
        match answer {
            Ok(Some(v)) => u64::try_from(v.id)
                .ok()
                .filter(|&id| id > 0)
                .ok_or(RunnerFailure::GitlabUnreachable),
            Ok(None) => Err(RunnerFailure::TokenRefused),
            Err(e) if e.refused() => Err(RunnerFailure::TokenRefused),
            Err(_) => Err(RunnerFailure::GitlabUnreachable),
        }
    }

    /// Remove runner `name`, which command `command` added as GitLab's `runner_id`: mark its
    /// file removed and stop its job requests.
    pub fn remove(&self, name: &str, runner_id: u64, command: &str) -> Result<(), RunnerFailure> {
        let mut inner = self.lock();
        let Some(added) = inner.hub.iter_mut().find(|a| {
            a.name == name
                && a.origin.runner_id == runner_id
                && a.origin.command == command
                && !a.origin.removed
        }) else {
            return Err(RunnerFailure::RunnerGone);
        };
        let path = file(&self.state_dir, name);
        let marked = (|| -> Result<()> {
            let mut f = parse(&path, vk_peer::net::read_nofollow(&path)?)?;
            f.removed = true;
            let text = toml::to_string(&f).context("encoding the runner file")?;
            vk_fs::write_atomic_durable(&path, text.as_bytes(), 0o600)
                .with_context(|| format!("writing {}", path.display()))
        })();
        if let Err(e) = marked {
            log::error!(runner = name, error = format!("{e:#}").as_str(); "Removing the runner added on the hub failed");
            // Not marked, so not stopped: the hub's removal fails, to be asked again.
            return Err(RunnerFailure::Other);
        }
        added.origin.removed = true;
        log::info!(runner = name, runner_id; "Runner removed on the hub; it asks for no more jobs and goes once its jobs have ended");
        let _ = self.changes.send(Change::Remove(name.to_owned()));
        Ok(())
    }

    /// Runner `name`, removed, holds no job any more: delete its state file and runner file,
    /// and free its name. Whether it is gone.
    pub fn drained(&self, name: &str) -> bool {
        let mut inner = self.lock();
        if !inner.hub.iter().any(|a| a.name == name && a.origin.removed) {
            return false;
        }
        if self.holds_jobs(name) {
            return false;
        }
        // The state file first: a runner file left alone is drained again on the next start.
        for path in [
            self.state_dir.join(format!("{name}.json")),
            file(&self.state_dir, name),
        ] {
            if let Err(e) = std::fs::remove_file(&path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                log::error!(runner = name, error = e.to_string().as_str(); "Deleting {} failed", path.display());
                return false;
            }
        }
        inner.hub.retain(|a| a.name != name);
        self.status.remove_runner(name);
        log::info!(runner = name; "Removed runner's jobs have ended; it is gone");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vk-gitlab-runners-{}",
            crate::backoff::hex(&crate::backoff::random_bytes::<6>())
        ));
        vk_peer::net::create_dir(&dir).unwrap();
        dir
    }

    fn config(state: &Path, runners: &str) -> Config {
        Config::parse(
            &format!(
                "state_dir = \"{}\"\n[gitlab]\nurl = \"https://gitlab.example.com\"\n\
                 [hub]\nallow = [\"runners\"]\n{runners}",
                state.display()
            ),
            Path::new("/"),
        )
        .unwrap()
    }

    fn hub_runner(name: &str, removed: bool) -> RunnerConfig {
        RunnerConfig::from_hub(
            name,
            "glrt-secret",
            &Placement {
                pool: "ci".into(),
                labels: vec!["big".into()],
                envelope: crate::dispatch::Envelope {
                    mem_mib: 2048,
                    cpus: 2,
                    disk_bytes: 1 << 30,
                },
            },
            Some(3),
            2,
            HubOrigin {
                command: "c".repeat(32),
                runner_id: 9,
                removed,
            },
        )
        .unwrap()
    }

    /// A runner file is written private and read back as it was written; one that does not
    /// parse, or that names a config runner, stops the relay.
    #[test]
    fn runner_files_round_trip_and_bad_ones_are_fatal() {
        use std::os::unix::fs::PermissionsExt;
        let state = temp();
        let cfg = config(&state, "");
        assert!(load(&cfg).unwrap().is_empty());
        let r = hub_runner("big", false);
        write(&state, &r).unwrap();
        let path = file(&state, "big");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let loaded = load(&cfg).unwrap();
        assert_eq!(loaded.len(), 1);
        let l = &loaded[0];
        assert_eq!(l.token().expose(), "glrt-secret");
        assert_eq!(l.hub, r.hub);
        assert_eq!(l.placement(), r.placement());
        assert_eq!((l.limit, l.request_concurrency()), (3, 2));
        // The config's name is refused.
        let both = config(&state, "[[runners]]\nname = \"big\"\ntoken = \"glrt-x\"\n");
        let e = format!("{:#}", load(&both).unwrap_err());
        assert!(e.contains("both in the config"), "{e}");
        // A file that does not parse, its text not in the error: it may hold the token.
        for bad in [
            "name = 1\n",
            "token = \"glrt-leaked\" junk\n",
            "runner_id = \"glrt-leaked\"\n",
        ] {
            std::fs::write(&path, bad).unwrap();
            let e = format!("{:#}", load(&cfg).unwrap_err());
            assert!(e.contains("parsing") && !e.contains("leaked"), "{e}");
        }
        // Nor one named after another runner.
        write(&state, &hub_runner("big", false)).unwrap();
        std::fs::rename(&path, file(&state, "other")).unwrap();
        let e = format!("{:#}", load(&cfg).unwrap_err());
        assert!(e.contains("names runner"), "{e}");
        std::fs::remove_dir_all(&state).unwrap();
    }

    /// More runners than a session carries, the config's and the hub's, stop the relay.
    #[test]
    fn too_many_runners_in_all_are_fatal() {
        let state = temp();
        let runners: String = (0..MAX_RUNNERS)
            .map(|i| format!("[[runners]]\nname = \"r{i}\"\ntoken = \"glrt-{i}\"\n"))
            .collect();
        let cfg = config(&state, &runners);
        assert!(load(&cfg).unwrap().is_empty());
        write(&state, &hub_runner("big", false)).unwrap();
        let e = format!("{:#}", load(&cfg).unwrap_err());
        assert!(e.contains("too many runners"), "{e}");
        std::fs::remove_dir_all(&state).unwrap();
    }

    /// A removal names the runner by name, GitLab ID and command; it marks the file, which
    /// goes, with the state file, once that holds no job.
    #[tokio::test]
    async fn a_removal_marks_the_file_and_the_drain_deletes_it() {
        let state = temp();
        let mut cfg = config(&state, "");
        write(&state, &hub_runner("big", false)).unwrap();
        cfg.runners.extend(load(&cfg).unwrap());
        let status = Status::new(&cfg, "s_test", "host");
        let (runners, mut rx) = Runners::new(&cfg, "s_test", Arc::clone(&status));
        assert!(runners.added_by(&"c".repeat(32)));
        assert_eq!(
            runners.remove("big", 8, &"c".repeat(32)),
            Err(RunnerFailure::RunnerGone)
        );
        assert_eq!(
            runners.remove("big", 9, &"d".repeat(32)),
            Err(RunnerFailure::RunnerGone)
        );
        runners.remove("big", 9, &"c".repeat(32)).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Change::Remove(n)) if n == "big"));
        // Once only.
        assert_eq!(
            runners.remove("big", 9, &"c".repeat(32)),
            Err(RunnerFailure::RunnerGone)
        );
        let loaded = load(&cfg).unwrap();
        assert!(loaded[0].hub.as_ref().unwrap().removed);
        // A job held keeps both files and the name.
        let jobs = StateFile::open(&state.join("big.json")).unwrap();
        jobs.put(crate::state::JobRecord {
            gitlab_job: 1,
            job_token: "jt".into(),
            request_id: "1".repeat(32),
            runner: None,
            reservation: None,
            admission: None,
            place_within_secs: 1,
            hub_job: None,
            phase: crate::state::Phase::Committed,
            trace_offset: 0,
            failure_reasons: vec![],
            debug_trace: false,
            timestamps: true,
            placement: Default::default(),
            spec: None,
        })
        .unwrap();
        assert!(!runners.drained("big"));
        assert!(file(&state, "big").exists() && runners.lock().taken("big"));
        jobs.remove(1).unwrap();
        assert!(runners.drained("big"));
        assert!(!file(&state, "big").exists() && !runners.lock().taken("big"));
        assert!(status.inventory().runners.is_empty());
        std::fs::remove_dir_all(&state).unwrap();
    }
}
