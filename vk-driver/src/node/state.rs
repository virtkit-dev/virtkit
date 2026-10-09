//! The node's last applied desired state, its own [`NodeState`], and its command journal.
//! All live in `<state_dir>/node/state.json`, rewritten whole on every change to preserve
//! them across restarts and hub outages.
//!
//! Each command's ID and state change are written together before the runner or concurrency
//! loop follows the new state. Redelivery after a reconnect returns the journaled outcome
//! without applying the command again. Desired-state generations no newer than the applied
//! one are ignored. Generations belong to one hub and enrollment, identified in the file;
//! re-enrollment or a different hub clears the applied generation but preserves node state.
//!
//! An update or a reset is a [`Job`] beside the state it moves the node through: accepted
//! from ready, draining or drained, it drains the node, holds it in `maintenance` while the
//! release is fetched or the node cleared, and in `validating` while the release runs on
//! [`Trial`] or the node is checked, then returns the node to where it started, or to
//! quarantine if one arrived meanwhile.
//!
//! A [`ToolsJob`] runs without changing node state: jobs keep the tools they started with.
//! Tools builds, updates and resets are mutually exclusive.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{
    Command, CommandAck, DesiredState, NodeState, Operation, Outcome, ToolsPhase, ToolsProgress,
    UpdatePhase, UpdateProgress,
};

const STATE_FILE: &str = "state.json";

/// The most settled journal entries kept, whatever their expiry. A settled entry is kept until
/// its command expires — until then the hub may redeliver it, and a node that had forgotten it
/// would run it twice; after that, a redelivery is refused as expired anyway. This bounds what
/// a hub issuing commands faster than they expire can make the file hold. Entries the hub has
/// not recorded, or still under way, are kept beyond it: dropping one would lose its ack.
const JOURNAL_MAX: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persisted {
    /// The hub and node ID the applied generation and the journal belong to.
    #[serde(default)]
    pub issuer: Option<Issuer>,
    #[serde(default)]
    pub applied: Option<DesiredState>,
    #[serde(default)]
    pub state: NodeState,
    /// The state a quarantine was entered from, which a release returns a drained node to.
    #[serde(default)]
    pub quarantined_from: Option<NodeState>,
    #[serde(default)]
    pub journal: Vec<Entry>,
    /// The update or reset under way.
    #[serde(default)]
    pub job: Option<Job>,
    /// How the update under way, or the last one, is going.
    #[serde(default)]
    pub update: Option<UpdateProgress>,
    /// The installed `vk`, which an update replaces: the file the last `vk node run` not
    /// started from a release executed, as the kernel names it — symlinks resolved.
    #[serde(default)]
    pub installed: Option<PathBuf>,
    /// The tools build under way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsJob>,
    /// How the tools build under way, or the last one, is going.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_progress: Option<ToolsProgress>,
}

/// A tools build under way ([`Operation::Tools`]): accepted, and not yet done or failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolsJob {
    /// The command's ID, whose journal entry says how it ended.
    pub command: String,
    pub version: String,
    pub sha256: String,
    pub size: u64,
}

/// An update or a reset under way: accepted, and not yet done, failed or rolled back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    /// The command's ID, whose journal entry says how it ended.
    pub command: String,
    /// Flattened: an update's job keeps its `release` at the top, as the binary it replaces
    /// reads it during the trial.
    #[serde(flatten)]
    pub work: Work,
    /// The state the node returns to: ready, or drained when it was drained or draining.
    pub resume: NodeState,
    /// A quarantine arrived during maintenance: the node enters it instead of `resume`.
    #[serde(default)]
    pub quarantine_after: bool,
    /// Set at the switch; the release runs on trial until it is confirmed or rolled back.
    #[serde(default)]
    pub trial: Option<Trial>,
    /// When the command expires: a drain still under way then calls the update off.
    pub expires_at: u64,
    /// How long the update may take once maintenance begins ([`Operation::Update`]).
    #[serde(default)]
    pub within_secs: Option<u64>,
    /// By when it must be confirmed, set as maintenance begins from `within_secs`.
    #[serde(default)]
    pub deadline: Option<u64>,
}

/// What a job does in maintenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Work {
    #[serde(rename = "release")]
    Update(Release),
    /// Clear what past jobs left, the materialized images too with `images`.
    Reset { images: bool },
}

impl Work {
    /// What it is called in what the node says of it.
    fn name(&self) -> &'static str {
        match self {
            Work::Update(_) => "update",
            Work::Reset { .. } => "reset",
        }
    }
}

impl Job {
    /// The release an update installs; `None` for a reset.
    pub fn release(&self) -> Option<&Release> {
        match &self.work {
            Work::Update(r) => Some(r),
            Work::Reset { .. } => None,
        }
    }
}

/// The release an update installs, as its command named it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub version: String,
    pub sha256: String,
    pub size: u64,
    /// A release key's signature, base64, which the node checks again before the release
    /// first runs.
    #[serde(default)]
    pub signature: Option<String>,
}

/// A release on trial. The installed binary stays in place until the trial is confirmed, so
/// whatever starts `vk node run` starts the previous binary, which counts the attempt and
/// hands over to the release — or, past the attempts allowed or the deadline, takes the node
/// back itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trial {
    /// The installed `vk`, which the release replaces once confirmed.
    pub exe: PathBuf,
    /// `exe`'s device and inode at the switch: a file put there meanwhile — by a package
    /// manager, by hand — is not replaced by the release.
    pub exe_id: (u64, u64),
    /// The release, `<node dir>/releases/<sha256>`.
    pub next: PathBuf,
    /// The sha256 of the binary it replaces, kept beside it in the releases directory.
    #[serde(default)]
    pub previous: Option<String>,
    /// How many times the release has been started.
    pub attempts: u32,
    /// When a trial not yet confirmed is rolled back, whatever else is happening.
    pub deadline: u64,
    /// Validated and back in touch with the hub: the release is being installed as `exe`.
    #[serde(default)]
    pub confirmed: bool,
}

/// What a node can do, which decides what commands it takes.
pub struct Abilities {
    /// The node can stop everything that takes jobs on the host — the runner it manages, or,
    /// with no runner, the hub's placed jobs — as reset and update without `force` require.
    /// Drain and quarantine also work with an external runner: they stop the hub-placed jobs
    /// the node runs itself.
    pub drainable: bool,
    /// Whether it can install the update a command names, or why not. Looked at only for an
    /// update.
    pub update: Result<(), String>,
}

/// Whose generations and commands these are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    pub hub: String,
    pub node_id: String,
}

/// One journaled command and what became of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub op: Operation,
    pub expires_at: u64,
    pub received_at: u64,
    pub outcome: Outcome,
    /// The outcome the hub last said it stored; the ack is repeated until this matches.
    #[serde(default)]
    pub recorded: Option<Outcome>,
}

impl Entry {
    fn ack(&self) -> CommandAck {
        CommandAck {
            id: self.id.clone(),
            outcome: self.outcome.clone(),
        }
    }
}

/// `<dir>/state.json`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE)
}

impl Persisted {
    /// The state in `dir`, or the initial one — ready, nothing applied — when there is none.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = path(dir);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Persisted::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write the state whole, `0600`, published by `rename`, and fsync the directory: a
    /// command is acked once it is saved, and the hub does not send an acked command again,
    /// so a quarantine whose rename a power cut undid would be lost for good.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self).context("encoding the node state")?;
        let path = path(dir);
        vk_fs::write_atomic(&path, &json, 0o600)
            .with_context(|| format!("writing {}", path.display()))?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("syncing {}", dir.display()))
    }

    /// Whether the runner is to take no jobs: the hub asked for that, or the node is not
    /// ready.
    pub fn acquisition_stopped(&self) -> bool {
        self.state != NodeState::Ready
            || self
                .applied
                .as_ref()
                .is_some_and(|d| d.acquisition == vk_hub_proto::Acquisition::Stop)
    }

    /// The hub's concurrency ceiling, from the applied desired state.
    pub fn hub_ceiling(&self) -> Option<u32> {
        self.applied.as_ref().and_then(|d| d.ceiling)
    }

    /// Adopt `issuer`, clearing the applied generation and journal if the hub or enrollment
    /// changed: both belong to the previous issuer. Preserve node state because a drain or
    /// quarantine belongs to the host, whoever requested it. Return whether anything was
    /// forgotten.
    pub fn adopt_issuer(&mut self, issuer: Issuer) -> bool {
        if self.issuer.as_ref() == Some(&issuer) {
            return false;
        }
        let forgot = self.issuer.is_some() || self.applied.is_some() || !self.journal.is_empty();
        self.issuer = Some(issuer);
        self.applied = None;
        self.journal.clear();
        forgot
    }

    /// Take `desired` unless a generation at least as new is already applied. Returns whether
    /// it changed anything.
    pub fn apply_desired(&mut self, desired: DesiredState) -> bool {
        if self
            .applied
            .as_ref()
            .is_some_and(|a| a.generation >= desired.generation)
        {
            return false;
        }
        self.applied = Some(desired);
        true
    }

    /// [`Persisted::command_as`] for a node that can install any update.
    #[cfg(test)]
    pub fn command(&mut self, command: Command, now: u64, drainable: bool) -> CommandAck {
        let can = Abilities {
            drainable,
            update: Ok(()),
        };
        self.command_as(command, now, &can)
    }

    /// Journal `command` and make the state change it asks for, answering with its outcome. A
    /// command already journaled is answered with what it came to then. `can` is what this
    /// node is able to do.
    pub fn command_as(&mut self, command: Command, now: u64, can: &Abilities) -> CommandAck {
        if let Some(entry) = self.journal.iter().find(|e| e.id == command.id) {
            return entry.ack();
        }
        let outcome = if now >= command.expires_at {
            Outcome::Expired
        } else {
            self.execute(&command, now, can)
        };
        let entry = Entry {
            id: command.id,
            op: command.op,
            expires_at: command.expires_at,
            received_at: now,
            outcome,
            recorded: None,
        };
        let ack = entry.ack();
        self.journal.push(entry);
        self.prune(now);
        ack
    }

    /// A drain, an update and a reset are `accepted` and settle later
    /// ([`Persisted::finish_drain`], [`Persisted::end_job`]); every other operation is done at
    /// once. A reset clears what the runner's jobs leave behind, and a runner this node does
    /// not run could still be using it; a drain and a quarantine stop only what the node runs
    /// itself, the jobs the hub places.
    fn execute(&mut self, command: &Command, now: u64, can: &Abilities) -> Outcome {
        let refused = |reason: &str| Outcome::Refused {
            reason: reason.to_string(),
        };
        let (op, drainable) = (&command.op, can.drainable);
        if let Some(outcome) = self.during_job(op) {
            return outcome;
        }
        if let (Operation::Update { .. } | Operation::Reset { .. }, Some(tools)) = (op, &self.tools)
        {
            return refused(&format!(
                "a tools build is under way (command {})",
                tools.command
            ));
        }
        match (op, self.state) {
            (Operation::Drain | Operation::Undrain, NodeState::Quarantined) => {
                refused("the node is quarantined; release it first")
            }
            (Operation::Drain, NodeState::Ready) => {
                self.state = NodeState::Draining;
                Outcome::Accepted
            }
            (Operation::Drain, NodeState::Draining) => Outcome::Accepted,
            (Operation::Drain, NodeState::Drained) => Outcome::Done,
            (Operation::Drain, NodeState::Maintenance | NodeState::Validating) => {
                refused("the node is under maintenance")
            }
            (Operation::Undrain, _) => {
                if self.state == NodeState::Draining {
                    self.settle_drains(Outcome::Failed {
                        message: "undrained before the drain finished".into(),
                    });
                }
                self.state = NodeState::Ready;
                Outcome::Done
            }
            (Operation::Quarantine, NodeState::Quarantined) => Outcome::Done,
            (Operation::Quarantine, from) => {
                if from == NodeState::Draining {
                    self.settle_drains(Outcome::Failed {
                        message: "quarantined before the drain finished".into(),
                    });
                }
                self.quarantined_from = Some(from);
                self.state = NodeState::Quarantined;
                Outcome::Done
            }
            // Release restores trust without undoing an operator's completed drain. Return
            // to drained if quarantined there; otherwise return to ready, including when
            // quarantine interrupted a drain.
            (Operation::Release, NodeState::Quarantined) => {
                self.state = match self.quarantined_from.take() {
                    Some(NodeState::Drained) => NodeState::Drained,
                    _ => NodeState::Ready,
                };
                Outcome::Done
            }
            (Operation::Release, _) => Outcome::Done,
            // The sha256 names files under the node's directory: refused before any path is
            // built from it.
            (Operation::Update { sha256, .. }, _) if !vk_hub_proto::valid_sha256(sha256) => {
                refused("the release's sha256 is not 64 lowercase hex digits")
            }
            (Operation::Update { .. }, NodeState::Quarantined) => {
                refused("the node is quarantined; release it first")
            }
            (Operation::Update { force: false, .. }, _) if !drainable => refused(
                "the runner is external, so vk node cannot drain it, and jobs running across the \
                 switch would run their stages with two vk versions; update with --force to \
                 accept that",
            ),
            (
                Operation::Update {
                    version,
                    sha256,
                    size,
                    signature,
                    within_secs,
                    ..
                },
                state,
            ) => {
                if let Err(why) = &can.update {
                    return refused(why);
                }
                let release = Release {
                    version: version.clone(),
                    sha256: sha256.clone(),
                    size: *size,
                    signature: signature.clone(),
                };
                let (resume, next) = match state {
                    // vk node cannot drain an external runner: straight to the download.
                    NodeState::Ready if !drainable => (NodeState::Ready, NodeState::Maintenance),
                    NodeState::Ready => (NodeState::Ready, NodeState::Draining),
                    NodeState::Draining => (NodeState::Drained, NodeState::Draining),
                    _ => (NodeState::Drained, NodeState::Maintenance),
                };
                self.state = next;
                self.update = Some(UpdateProgress {
                    command: command.id.clone(),
                    version: release.version.clone(),
                    sha256: release.sha256.clone(),
                    phase: if next == NodeState::Draining {
                        UpdatePhase::Draining
                    } else {
                        UpdatePhase::Downloading
                    },
                    message: None,
                });
                self.job = Some(Job {
                    command: command.id.clone(),
                    work: Work::Update(release),
                    resume,
                    quarantine_after: false,
                    trial: None,
                    expires_at: command.expires_at,
                    within_secs: *within_secs,
                    deadline: None,
                });
                if next == NodeState::Maintenance {
                    self.begin_maintenance(now);
                }
                Outcome::Accepted
            }
            (Operation::Reset { .. }, NodeState::Quarantined) => {
                refused("the node is quarantined; release it first")
            }
            (Operation::Reset { .. }, _) if !drainable => refused(
                "a reset drains the runner first, which vk node cannot do to a runner it does \
                 not run ([node] runner = \"external\")",
            ),
            (Operation::Reset { images }, state) => {
                let (resume, next) = match state {
                    NodeState::Ready => (NodeState::Ready, NodeState::Draining),
                    NodeState::Draining => (NodeState::Drained, NodeState::Draining),
                    _ => (NodeState::Drained, NodeState::Maintenance),
                };
                self.state = next;
                // The last update's outcome, news until now, would read beside a reset under
                // way as the reset's.
                self.update = None;
                self.job = Some(Job {
                    command: command.id.clone(),
                    work: Work::Reset { images: *images },
                    resume,
                    quarantine_after: false,
                    trial: None,
                    expires_at: command.expires_at,
                    within_secs: None,
                    deadline: None,
                });
                Outcome::Accepted
            }
            // The sha256 names files under the state dir: refused before any path is built
            // from it.
            (Operation::Tools { sha256, .. }, _) if !vk_hub_proto::valid_sha256(sha256) => {
                refused("the tools definition's sha256 is not 64 lowercase hex digits")
            }
            (Operation::Tools { size, .. }, _) if *size > vk_hub_proto::MAX_TOOLS_DEFINITION => {
                refused(&format!(
                    "the tools definition is {size} bytes, past the {} a node takes",
                    vk_hub_proto::MAX_TOOLS_DEFINITION
                ))
            }
            // A release on trial executes another binary, which would leave a build behind.
            (Operation::Tools { .. }, _) if self.job.is_some() => {
                refused("an update or a reset is under way")
            }
            (Operation::Tools { .. }, _) if self.tools.is_some() => refused(&format!(
                "a tools build is under way (command {})",
                self.tools.as_ref().map_or("", |t| t.command.as_str())
            )),
            (
                Operation::Tools {
                    version,
                    sha256,
                    size,
                },
                _,
            ) => {
                self.tools = Some(ToolsJob {
                    command: command.id.clone(),
                    version: version.clone(),
                    sha256: sha256.clone(),
                    size: *size,
                });
                self.tools_progress = Some(ToolsProgress {
                    command: command.id.clone(),
                    version: version.clone(),
                    sha256: sha256.clone(),
                    phase: ToolsPhase::Downloading,
                    message: None,
                    log: Vec::new(),
                });
                Outcome::Accepted
            }
        }
    }

    /// The tools build moved on to `phase`.
    pub fn tools_phase(&mut self, phase: ToolsPhase) {
        if let (Some(job), Some(progress)) = (&self.tools, self.tools_progress.as_mut())
            && progress.command == job.command
        {
            progress.phase = phase;
        }
    }

    /// End the tools build under way: done, or failed with `message` and the end of the
    /// build's output, `log`. Its journal entry takes the outcome. Returns whether there was
    /// one to end.
    pub fn end_tools(&mut self, failed: Option<(String, Vec<String>)>) -> bool {
        let Some(job) = self.tools.take() else {
            return false;
        };
        let (outcome, phase, message, log) = match failed {
            None => (Outcome::Done, ToolsPhase::Done, None, Vec::new()),
            Some((message, log)) => (
                Outcome::Failed {
                    message: message.clone(),
                },
                ToolsPhase::Failed,
                Some(message),
                log,
            ),
        };
        if let Some(entry) = self.journal.iter_mut().find(|e| e.id == job.command) {
            entry.outcome = outcome;
        }
        self.tools_progress = Some(ToolsProgress {
            command: job.command,
            version: job.version,
            sha256: job.sha256,
            phase,
            message,
            log,
        });
        true
    }

    /// What `op` comes to while an update or a reset is under way, or `None` to handle it as
    /// usual. While the node drains for it, the job can still be called off; once maintenance
    /// has begun, it runs to its end and what an operator asks meanwhile is kept for after.
    fn during_job(&mut self, op: &Operation) -> Option<Outcome> {
        let job = self.job.as_mut()?;
        let draining = self.state == NodeState::Draining;
        let busy = |job: &Job| Outcome::Refused {
            reason: format!(
                "{} is under way (command {})",
                match job.work {
                    Work::Update(_) => "an update",
                    Work::Reset { .. } => "a reset",
                },
                job.command
            ),
        };
        Some(match op {
            Operation::Update { .. } | Operation::Reset { .. } => busy(job),
            Operation::Drain if draining => {
                job.resume = NodeState::Drained;
                Outcome::Accepted
            }
            // The node takes no jobs now, and returns to drained once the update is over.
            Operation::Drain => {
                job.resume = NodeState::Drained;
                Outcome::Done
            }
            Operation::Undrain | Operation::Quarantine if draining => {
                let how = match op {
                    Operation::Undrain => "undrained",
                    _ => "quarantined",
                };
                let message = format!("{how} before the {} started", job.work.name());
                self.end_job(Outcome::Failed { message }, UpdatePhase::Failed);
                // Still draining, for what follows to end the drain as it would any other.
                self.state = NodeState::Draining;
                return None;
            }
            Operation::Undrain => busy(job),
            // In force already — maintenance takes no jobs — and entered when it ends.
            Operation::Quarantine => {
                job.quarantine_after = true;
                Outcome::Done
            }
            Operation::Release => {
                job.quarantine_after = false;
                Outcome::Done
            }
            Operation::Tools { .. } => return None,
        })
    }

    /// End the job under way with `outcome`, an update's reported as `phase`: its journal
    /// entry takes the outcome, and the node goes back to where it was, or into the quarantine
    /// that arrived meanwhile. Returns whether there was one to end.
    pub fn end_job(&mut self, outcome: Outcome, phase: UpdatePhase) -> bool {
        self.end_job_in(outcome, phase, None)
    }

    /// [`Persisted::end_job`], returning the node to `resume` rather than where it was, when
    /// given.
    pub fn end_job_in(
        &mut self,
        outcome: Outcome,
        phase: UpdatePhase,
        resume: Option<NodeState>,
    ) -> bool {
        let Some(mut job) = self.job.take() else {
            return false;
        };
        if let Some(resume) = resume {
            job.resume = resume;
        }
        // The phase already says it was rolled back; the progress says why in words of its
        // own.
        let message = match &outcome {
            Outcome::Failed { message } => Some(
                message
                    .strip_prefix("rolled back: ")
                    .unwrap_or(message)
                    .to_string(),
            ),
            _ => None,
        };
        if let Some(entry) = self.journal.iter_mut().find(|e| e.id == job.command) {
            entry.outcome = outcome;
        }
        if let Some(update) = self.update.as_mut().filter(|u| u.command == job.command) {
            update.phase = phase;
            update.message = message;
        }
        if job.quarantine_after {
            self.quarantined_from = Some(job.resume);
            self.state = NodeState::Quarantined;
        } else {
            self.state = job.resume;
        }
        true
    }

    /// The update moved on to `phase`, in state `state`.
    pub fn set_phase(&mut self, state: NodeState, phase: UpdatePhase) {
        self.state = state;
        if let Some(update) = self.update.as_mut() {
            update.phase = phase;
        }
    }

    /// The drain is complete: the node is drained, and every drain under way is done — or,
    /// draining for an update or a reset, on to its maintenance. Returns whether the node was
    /// draining.
    pub fn finish_drain(&mut self, now: u64) -> bool {
        if self.state != NodeState::Draining {
            return false;
        }
        if self.job.is_some() {
            // A reset has no update progress to move on: it cleared the last one's.
            self.set_phase(NodeState::Maintenance, UpdatePhase::Downloading);
            self.begin_maintenance(now);
        } else {
            self.state = NodeState::Drained;
        }
        self.settle_drains(Outcome::Done);
        true
    }

    /// Start the clock on the update's `within_secs`.
    fn begin_maintenance(&mut self, now: u64) {
        if let Some(job) = self.job.as_mut() {
            job.deadline = job.within_secs.map(|w| now.saturating_add(w));
        }
    }

    /// Call off an update or a reset whose command expired while the node was still draining
    /// for it: whoever issued it has given up on it. Returns whether it did.
    pub fn drain_expired(&mut self, now: u64) -> bool {
        let expired = self.state == NodeState::Draining
            && self.job.as_ref().is_some_and(|j| now >= j.expires_at);
        if expired {
            self.call_off_drain("the drain outlasted the command's expiry".into(), None);
        }
        expired
    }

    /// Call off a reset whose drain cannot end, as failed with `message`, the node left
    /// drained. Returns whether it did.
    pub fn reset_blocked(&mut self, message: String) -> bool {
        let blocked = self.state == NodeState::Draining
            && self
                .job
                .as_ref()
                .is_some_and(|j| matches!(j.work, Work::Reset { .. }));
        if blocked {
            self.call_off_drain(message, Some(NodeState::Drained));
        }
        blocked
    }

    /// End the job the node is draining for as failed with `message`, the node returned to
    /// `resume` when given. An operator's drain under way beside it goes on.
    fn call_off_drain(&mut self, message: String, resume: Option<NodeState>) {
        let drained_for_operator = self
            .journal
            .iter()
            .any(|e| e.op == Operation::Drain && e.outcome == Outcome::Accepted);
        self.end_job_in(Outcome::Failed { message }, UpdatePhase::Failed, resume);
        if drained_for_operator {
            self.state = NodeState::Draining;
        }
    }

    fn settle_drains(&mut self, outcome: Outcome) {
        for entry in &mut self.journal {
            if entry.op == Operation::Drain && entry.outcome == Outcome::Accepted {
                entry.outcome = outcome.clone();
            }
        }
    }

    /// Every ack whose current outcome the hub has not recorded.
    pub fn unrecorded(&self) -> Vec<CommandAck> {
        self.journal
            .iter()
            .filter(|e| e.recorded.as_ref() != Some(&e.outcome))
            .map(Entry::ack)
            .collect()
    }

    /// The hub stored `ack`. Returns whether that settled anything.
    pub fn recorded(&mut self, ack: &CommandAck, now: u64) -> bool {
        match self.journal.iter_mut().find(|e| e.id == ack.id) {
            Some(entry) if entry.recorded.as_ref() != Some(&ack.outcome) => {
                entry.recorded = Some(ack.outcome.clone());
                self.prune(now);
                true
            }
            _ => false,
        }
    }

    /// Drop settled entries whose commands have expired, and past [`JOURNAL_MAX`] the oldest
    /// settled ones. An entry the hub has not yet recorded, or one still under way, is never
    /// dropped.
    fn prune(&mut self, now: u64) {
        let settled =
            |e: &Entry| e.recorded.as_ref() == Some(&e.outcome) && e.outcome != Outcome::Accepted;
        self.journal
            .retain(|e| !(settled(e) && now >= e.expires_at));
        let mut excess = self
            .journal
            .iter()
            .filter(|e| settled(e))
            .count()
            .saturating_sub(JOURNAL_MAX);
        self.journal.retain(|e| {
            if excess > 0 && settled(e) {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::Acquisition;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn desired(generation: u64, ceiling: Option<u32>, acquisition: Acquisition) -> DesiredState {
        DesiredState {
            generation,
            ceiling,
            acquisition,
        }
    }

    fn command(id: &str, op: Operation) -> Command {
        Command {
            id: id.to_string(),
            expires_at: 1000,
            op,
        }
    }

    #[test]
    fn a_generation_is_applied_once_across_restarts() {
        let dir = scratch("apply");
        let mut p = Persisted::load(&dir).unwrap();
        assert_eq!(p, Persisted::default());
        assert!(p.apply_desired(desired(2, Some(4), Acquisition::Run)));
        p.save(&dir).unwrap();
        let mut p = Persisted::load(&dir).unwrap();
        assert_eq!(p.hub_ceiling(), Some(4));
        // The same generation again, or an older one, changes nothing.
        assert!(!p.apply_desired(desired(2, Some(9), Acquisition::Stop)));
        assert!(!p.apply_desired(desired(1, None, Acquisition::Stop)));
        assert_eq!(p.hub_ceiling(), Some(4));
        assert!(!p.acquisition_stopped());
        assert!(p.apply_desired(desired(3, None, Acquisition::Stop)));
        assert!(p.acquisition_stopped());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_redelivered_command_gets_its_recorded_outcome_not_a_second_run() {
        let dir = scratch("redeliver");
        let mut p = Persisted::default();
        let ack = p.command(command("a", Operation::Quarantine), 10, true);
        assert_eq!(ack.outcome, Outcome::Done);
        p.save(&dir).unwrap();
        // Released by an operator, then the quarantine is delivered again after a reconnect:
        // it is recognized, and the node stays released.
        let mut p = Persisted::load(&dir).unwrap();
        p.command(command("b", Operation::Release), 11, true);
        assert_eq!(p.state, NodeState::Ready);
        let journal = p.journal.clone();
        let again = p.command(command("a", Operation::Quarantine), 12, true);
        assert_eq!(again, ack);
        assert_eq!(p.state, NodeState::Ready);
        assert_eq!(p.journal, journal);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn acks_repeat_until_recorded_and_expired_commands_do_nothing() {
        let mut p = Persisted::default();
        p.command(command("a", Operation::Drain), 10, true);
        assert_eq!(p.unrecorded().len(), 1);
        let first = p.unrecorded().remove(0);
        assert_eq!(first.outcome, Outcome::Accepted);
        assert!(p.recorded(&first, 10));
        assert!(p.unrecorded().is_empty());
        // Its outcome moving on makes it unrecorded again.
        assert!(p.finish_drain(1));
        assert_eq!(p.state, NodeState::Drained);
        assert_eq!(p.unrecorded()[0].outcome, Outcome::Done);
        let late = p.command(command("b", Operation::Undrain), 1000, true);
        assert_eq!(late.outcome, Outcome::Expired);
        assert_eq!(p.state, NodeState::Drained);
        assert!(p.unrecorded().contains(&late));
    }

    #[test]
    fn an_external_runner_drains_and_quarantines_what_the_node_runs_but_refuses_a_reset() {
        let mut p = Persisted::default();
        let ack = p.command(command("d", Operation::Drain), 1, false);
        assert_eq!(ack.outcome, Outcome::Accepted);
        assert_eq!(p.state, NodeState::Draining);
        assert!(p.acquisition_stopped());
        assert_eq!(
            p.command(command("u", Operation::Undrain), 1, false)
                .outcome,
            Outcome::Done
        );
        assert_eq!(p.state, NodeState::Ready);
        assert_eq!(
            p.command(command("q", Operation::Quarantine), 1, false)
                .outcome,
            Outcome::Done
        );
        assert_eq!(p.state, NodeState::Quarantined);
        assert_eq!(
            p.command(command("r", Operation::Release), 1, false)
                .outcome,
            Outcome::Done
        );
        assert_eq!(p.state, NodeState::Ready);
        let reset = command("x", Operation::Reset { images: false });
        let ack = p.command(reset, 1, false);
        assert!(matches!(ack.outcome, Outcome::Refused { .. }), "{ack:?}");
        assert_eq!(p.state, NodeState::Ready);
    }

    #[test]
    fn a_quarantine_holds_until_released_and_survives_a_restart() {
        let dir = scratch("quarantine");
        let mut p = Persisted::default();
        p.command(command("q", Operation::Quarantine), 1, true);
        p.save(&dir).unwrap();
        let mut p = Persisted::load(&dir).unwrap();
        assert_eq!(p.state, NodeState::Quarantined);
        assert!(p.acquisition_stopped());
        for op in [Operation::Drain, Operation::Undrain] {
            let ack = p.command(command(&format!("{op:?}"), op), 2, true);
            assert!(matches!(ack.outcome, Outcome::Refused { .. }), "{ack:?}");
        }
        assert_eq!(p.state, NodeState::Quarantined);
        p.command(command("r", Operation::Release), 3, true);
        assert_eq!(p.state, NodeState::Ready);
        assert!(!p.acquisition_stopped());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn undrain_and_quarantine_end_a_drain_under_way() {
        let mut p = Persisted::default();
        let ack = p.command(command("a", Operation::Drain), 1, true);
        assert_eq!(ack.outcome, Outcome::Accepted);
        assert_eq!(p.state, NodeState::Draining);
        // A second drain joins the first.
        let joined = p.command(command("b", Operation::Drain), 1, true);
        assert_eq!(joined.outcome, Outcome::Accepted);
        p.command(command("c", Operation::Undrain), 2, true);
        assert_eq!(p.state, NodeState::Ready);
        for id in ["a", "b"] {
            let entry = p.journal.iter().find(|e| e.id == id).unwrap();
            assert!(matches!(entry.outcome, Outcome::Failed { .. }), "{entry:?}");
        }
        assert!(!p.finish_drain(1));

        p.command(command("d", Operation::Drain), 3, true);
        p.command(command("e", Operation::Quarantine), 3, true);
        let d = p.journal.iter().find(|e| e.id == "d").unwrap();
        assert!(matches!(d.outcome, Outcome::Failed { .. }), "{d:?}");
        // Released, a drain the quarantine cut short is not taken up again.
        p.command(command("f", Operation::Release), 3, true);
        assert_eq!(p.state, NodeState::Ready);
    }

    #[test]
    fn a_release_returns_a_drained_node_to_drained() {
        let mut p = Persisted::default();
        p.command(command("d", Operation::Drain), 1, true);
        assert!(p.finish_drain(1));
        p.command(command("q", Operation::Quarantine), 1, true);
        p.command(command("r", Operation::Release), 1, true);
        assert_eq!(p.state, NodeState::Drained);
        // A drain of a drained node is done at once.
        let again = p.command(command("d2", Operation::Drain), 1, true);
        assert_eq!(again.outcome, Outcome::Done);
        // From ready, back to ready.
        p.command(command("u", Operation::Undrain), 1, true);
        p.command(command("q2", Operation::Quarantine), 1, true);
        p.command(command("r2", Operation::Release), 1, true);
        assert_eq!(p.state, NodeState::Ready);
    }

    #[test]
    fn a_settled_entry_is_kept_until_its_command_expires() {
        let mut p = Persisted::default();
        let ack = p.command(command("a", Operation::Release), 1, true);
        p.recorded(&ack, 2);
        // Settled but not expired: a redelivery must still find it.
        assert_eq!(p.journal.len(), 1);
        let open = p.command(command("b", Operation::Release), 999, true);
        assert_eq!(p.journal.len(), 2);
        // Past its expiry (1000) the settled one goes; the one the hub has not recorded stays.
        let c = p.command(command("c", Operation::Release), 1000, true);
        assert_eq!(c.outcome, Outcome::Expired);
        assert!(!p.journal.iter().any(|e| e.id == "a"));
        assert!(p.journal.iter().any(|e| e.id == open.id));
        // And past the cap, the oldest settled entries go first.
        let mut p = Persisted::default();
        for i in 0..JOURNAL_MAX + 3 {
            let mut c = command(&i.to_string(), Operation::Release);
            c.expires_at = u64::MAX;
            let ack = p.command(c, 1, true);
            p.recorded(&ack, 1);
        }
        assert_eq!(p.journal.len(), JOURNAL_MAX);
        assert!(!p.journal.iter().any(|e| e.id == "0"));
    }

    #[test]
    fn another_issuer_forgets_the_applied_generation_but_not_the_node_state() {
        let issuer = |hub: &str| Issuer {
            hub: hub.into(),
            node_id: "ab".repeat(16),
        };
        let mut p = Persisted::default();
        assert!(!p.adopt_issuer(issuer("https://a")));
        p.apply_desired(desired(7, Some(2), Acquisition::Run));
        p.command(command("q", Operation::Quarantine), 1, true);
        assert!(!p.adopt_issuer(issuer("https://a")));
        assert_eq!(p.hub_ceiling(), Some(2));
        // Re-enrolled, or another hub: generation 1 is new again, and the quarantine holds.
        assert!(p.adopt_issuer(issuer("https://b")));
        assert_eq!(p.applied, None);
        assert!(p.journal.is_empty());
        assert_eq!(p.state, NodeState::Quarantined);
        assert!(p.apply_desired(desired(1, None, Acquisition::Run)));
    }

    fn update(id: &str) -> Command {
        command(
            id,
            Operation::Update {
                version: "0.84.0".into(),
                sha256: "ab".repeat(vk_hub_proto::SHA256_LEN),
                size: 1,
                signature: None,
                force: false,
                within_secs: None,
            },
        )
    }

    #[test]
    fn an_update_drains_then_returns_the_node_where_it_was() {
        let mut p = Persisted::default();
        assert_eq!(p.command(update("u"), 1, true).outcome, Outcome::Accepted);
        assert_eq!(p.state, NodeState::Draining);
        assert!(p.acquisition_stopped());
        // Another update meanwhile is refused; the drain becomes maintenance.
        assert!(matches!(
            p.command(update("v"), 1, true).outcome,
            Outcome::Refused { .. }
        ));
        assert!(p.finish_drain(1));
        assert_eq!(p.state, NodeState::Maintenance);
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Downloading);
        assert!(matches!(
            p.command(command("x", Operation::Undrain), 1, true).outcome,
            Outcome::Refused { .. }
        ));
        p.set_phase(NodeState::Validating, UpdatePhase::Validating);
        assert!(p.acquisition_stopped());
        assert!(p.end_job(Outcome::Done, UpdatePhase::Done));
        assert_eq!(p.state, NodeState::Ready);
        assert_eq!(p.journal[0].outcome, Outcome::Done);
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Done);
        assert!(!p.end_job(Outcome::Done, UpdatePhase::Done));

        // From drained, straight to maintenance, and back to drained.
        let mut p = Persisted::default();
        p.command(command("d", Operation::Drain), 1, true);
        assert!(p.finish_drain(1));
        p.command(update("u"), 1, true);
        assert_eq!(p.state, NodeState::Maintenance);
        p.end_job(
            Outcome::Failed {
                message: "rolled back: no".into(),
            },
            UpdatePhase::RolledBack,
        );
        assert_eq!(p.state, NodeState::Drained);
        assert_eq!(p.update.as_ref().unwrap().message.as_deref(), Some("no"));
    }

    #[test]
    fn an_update_is_called_off_while_draining_and_kept_to_its_end_after() {
        let mut p = Persisted::default();
        p.command(update("u"), 1, true);
        p.command(command("un", Operation::Undrain), 1, true);
        assert_eq!(p.state, NodeState::Ready);
        assert!(p.job.is_none());
        assert!(matches!(p.journal[0].outcome, Outcome::Failed { .. }));
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Failed);

        // A quarantine during maintenance waits for its end; a drain makes it end drained.
        let mut p = Persisted::default();
        p.command(update("u"), 1, true);
        p.finish_drain(1);
        assert_eq!(
            p.command(command("q", Operation::Quarantine), 1, true)
                .outcome,
            Outcome::Done
        );
        assert_eq!(p.state, NodeState::Maintenance);
        assert_eq!(
            p.command(command("d", Operation::Drain), 1, true).outcome,
            Outcome::Done
        );
        p.end_job(Outcome::Done, UpdatePhase::Done);
        assert_eq!(p.state, NodeState::Quarantined);
        p.command(command("r", Operation::Release), 1, true);
        assert_eq!(p.state, NodeState::Drained);

        // Quarantined while draining for it: the update is off, the quarantine on.
        let mut p = Persisted::default();
        p.command(update("u"), 1, true);
        p.command(command("q", Operation::Quarantine), 1, true);
        assert_eq!(p.state, NodeState::Quarantined);
        assert!(p.job.is_none());
        assert!(matches!(
            p.command(update("v"), 1, true).outcome,
            Outcome::Refused { .. }
        ));
    }

    #[test]
    fn an_update_naming_an_invalid_sha256_is_refused() {
        for bad in [
            "../../etc/passwd".to_string(),
            "AB".repeat(32),
            "ab".repeat(31),
        ] {
            let mut u = update("u");
            if let Operation::Update { sha256, .. } = &mut u.op {
                *sha256 = bad;
            }
            let mut p = Persisted::default();
            assert!(matches!(
                p.command(u, 1, true).outcome,
                Outcome::Refused { .. }
            ));
            assert_eq!(p.state, NodeState::Ready);
            assert!(p.job.is_none());
        }
    }

    #[test]
    fn an_update_needs_a_managed_runner_or_force_and_a_replaceable_binary() {
        let mut p = Persisted::default();
        assert!(matches!(
            p.command(update("u"), 1, false).outcome,
            Outcome::Refused { .. }
        ));
        let mut forced = update("f");
        if let Operation::Update { force, .. } = &mut forced.op {
            *force = true;
        }
        assert_eq!(p.command(forced, 1, false).outcome, Outcome::Accepted);
        // Not drained: an external runner cannot be.
        assert_eq!(p.state, NodeState::Maintenance);
        assert_eq!(p.job.as_ref().unwrap().resume, NodeState::Ready);
        // A quarantine meanwhile is entered after, for the jobs the hub places.
        assert_eq!(
            p.command(command("q", Operation::Quarantine), 1, false)
                .outcome,
            Outcome::Done
        );
        assert!(p.job.as_ref().unwrap().quarantine_after);

        let mut p = Persisted::default();
        let stuck = Abilities {
            drainable: true,
            update: Err("/usr/bin is not writable".into()),
        };
        let ack = p.command_as(update("u"), 1, &stuck);
        assert!(
            matches!(&ack.outcome, Outcome::Refused { reason } if reason.contains("writable")),
            "{ack:?}"
        );
        assert_eq!(p.state, NodeState::Ready);
        assert!(p.job.is_none() && p.update.is_none());
    }

    #[test]
    fn an_update_whose_command_expires_while_draining_is_called_off() {
        let mut p = Persisted::default();
        let mut u = update("u");
        u.expires_at = 100;
        p.command(u, 1, true);
        assert!(!p.drain_expired(99));
        assert!(p.drain_expired(100));
        assert_eq!(p.state, NodeState::Ready);
        assert!(p.job.is_none());
        assert!(matches!(p.journal[0].outcome, Outcome::Failed { .. }));
        // Beside an operator's drain, the drain goes on.
        let mut p = Persisted::default();
        p.command(command("d", Operation::Drain), 1, true);
        let mut u = update("u");
        u.expires_at = 100;
        p.command(u, 1, true);
        assert!(p.drain_expired(100));
        assert_eq!(p.state, NodeState::Draining);
        // Once maintenance has begun, the command's expiry is past caring; `within_secs` sets
        // the update's deadline from there.
        let mut p = Persisted::default();
        let mut u = update("u");
        u.expires_at = 100;
        if let Operation::Update { within_secs, .. } = &mut u.op {
            *within_secs = Some(50);
        }
        p.command(u, 1, true);
        assert!(p.finish_drain(10));
        assert!(!p.drain_expired(200));
        assert_eq!(p.job.as_ref().unwrap().deadline, Some(60));
    }

    #[test]
    fn a_reset_drains_and_excludes_an_update() {
        let mut p = Persisted::default();
        let reset = |id: &str| command(id, Operation::Reset { images: false });
        // A reset drains the runner first.
        assert!(matches!(
            p.command(reset("x"), 1, false).outcome,
            Outcome::Refused { .. }
        ));
        // The last update's outcome is not the reset's to show.
        p.update = Some(UpdateProgress {
            command: "old".into(),
            version: "0.84.0".into(),
            sha256: "ab".into(),
            phase: UpdatePhase::Done,
            message: None,
        });
        assert_eq!(p.command(reset("r"), 1, true).outcome, Outcome::Accepted);
        assert_eq!(p.state, NodeState::Draining);
        assert_eq!(p.update, None);
        let ack = p.command(update("u"), 1, true);
        assert!(
            matches!(&ack.outcome, Outcome::Refused { reason } if reason.contains("a reset")),
            "{ack:?}"
        );
        assert!(p.finish_drain(1));
        assert_eq!(p.state, NodeState::Maintenance);
        assert_eq!(p.update, None);
        p.set_phase(NodeState::Validating, UpdatePhase::Validating);
        // A node failing validation stays drained, whatever it was before.
        assert!(p.end_job_in(
            Outcome::Failed {
                message: "vk check: kvm".into(),
            },
            UpdatePhase::Failed,
            Some(NodeState::Drained),
        ));
        assert_eq!(p.state, NodeState::Drained);
        assert!(matches!(p.journal[0].outcome, Outcome::Refused { .. }));
        assert!(matches!(p.journal[1].outcome, Outcome::Failed { .. }));
        assert!(matches!(p.journal[2].outcome, Outcome::Refused { .. }));
        // An update under way refuses a reset; quarantined, a reset is refused too.
        let mut p = Persisted::default();
        p.command(update("u"), 1, true);
        let ack = p.command(reset("r"), 1, true);
        assert!(
            matches!(&ack.outcome, Outcome::Refused { reason } if reason.contains("an update")),
            "{ack:?}"
        );
        let mut p = Persisted::default();
        p.command(command("q", Operation::Quarantine), 1, true);
        assert!(matches!(
            p.command(reset("r"), 1, true).outcome,
            Outcome::Refused { .. }
        ));
    }

    #[test]
    fn a_reset_whose_drain_is_blocked_fails_and_leaves_the_node_drained() {
        let reset = command("r", Operation::Reset { images: false });
        // Only a reset's drain is called off so.
        let mut p = Persisted::default();
        p.command(update("u"), 1, true);
        assert!(!p.reset_blocked("stuck".into()));
        assert_eq!(p.state, NodeState::Draining);
        let mut p = Persisted::default();
        p.command(reset.clone(), 1, true);
        assert!(p.reset_blocked("stuck".into()));
        assert_eq!(p.state, NodeState::Drained);
        assert!(p.job.is_none());
        assert!(matches!(&p.journal[0].outcome, Outcome::Failed { message } if message == "stuck"));
        // Beside an operator's drain, the drain goes on.
        let mut p = Persisted::default();
        p.command(command("d", Operation::Drain), 1, true);
        p.command(reset, 1, true);
        assert!(p.reset_blocked("stuck".into()));
        assert_eq!(p.state, NodeState::Draining);
    }

    #[test]
    fn a_reset_called_off_while_draining_says_so_and_from_drained_returns_there() {
        let mut p = Persisted::default();
        p.command(command("r", Operation::Reset { images: true }), 1, true);
        p.command(command("un", Operation::Undrain), 1, true);
        assert_eq!(p.state, NodeState::Ready);
        assert!(
            matches!(&p.journal[0].outcome, Outcome::Failed { message } if message == "undrained before the reset started"),
            "{:?}",
            p.journal[0]
        );
        let mut p = Persisted::default();
        p.command(command("d", Operation::Drain), 1, true);
        assert!(p.finish_drain(1));
        p.command(command("r", Operation::Reset { images: true }), 1, true);
        assert_eq!(p.state, NodeState::Maintenance);
        assert_eq!(p.job.as_ref().unwrap().work, Work::Reset { images: true });
        assert!(p.end_job(Outcome::Done, UpdatePhase::Done));
        assert_eq!(p.state, NodeState::Drained);
    }

    /// An update's job keeps `release` at its top, where the binary on trial's predecessor
    /// reads it.
    #[test]
    fn a_job_says_what_it_does_beside_its_other_fields() {
        let mut p = Persisted::default();
        p.command(update("u"), 1, true);
        let job = serde_json::to_value(p.job.as_ref().unwrap()).unwrap();
        assert_eq!(job["release"]["version"], "0.84.0");
        assert_eq!(job["command"], "u");
        let mut p = Persisted::default();
        p.command(command("r", Operation::Reset { images: true }), 1, true);
        let job = p.job.clone().unwrap();
        let wire = serde_json::to_value(&job).unwrap();
        assert_eq!(wire["reset"], serde_json::json!({"images": true}));
        assert_eq!(serde_json::from_value::<Job>(wire).unwrap(), job);
    }

    fn tools(id: &str, sha256: &str) -> Command {
        command(
            id,
            Operation::Tools {
                version: "2026.10".into(),
                sha256: sha256.into(),
                size: 4096,
            },
        )
    }

    /// A tools build moves the node through no state, runs one at a time, excludes an update
    /// and a reset either way, and survives a restart; its end settles its journal entry.
    #[test]
    fn a_tools_build_runs_alone_beside_the_node_s_state() {
        let dir = scratch("tools");
        let sha = "ab".repeat(vk_hub_proto::SHA256_LEN);
        let mut p = Persisted::default();
        assert_eq!(
            p.command(tools("t", &sha), 1, false).outcome,
            Outcome::Accepted
        );
        assert_eq!(p.state, NodeState::Ready);
        assert_eq!(
            p.tools_progress.as_ref().map(|t| t.phase),
            Some(ToolsPhase::Downloading)
        );
        p.save(&dir).unwrap();
        let mut p = Persisted::load(&dir).unwrap();
        assert_eq!(p.tools.as_ref().unwrap().command, "t");
        let busy = |p: &mut Persisted, c| match p.command(c, 1, true).outcome {
            Outcome::Refused { reason } => reason,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(busy(&mut p, tools("t2", &sha)).contains("tools build is under way (command t)"));
        assert!(busy(&mut p, update("u")).contains("tools build is under way"));
        let reset = command("r", Operation::Reset { images: false });
        assert!(busy(&mut p, reset).contains("tools build is under way"));
        // A quarantine and a drain go ahead: the build takes no job.
        p.command(command("q", Operation::Quarantine), 1, true);
        assert_eq!(p.state, NodeState::Quarantined);
        p.tools_phase(ToolsPhase::Building);
        assert_eq!(
            p.tools_progress.as_ref().map(|t| t.phase),
            Some(ToolsPhase::Building)
        );
        assert!(p.end_tools(Some(("vk build failed".into(), vec!["e".into()]))));
        assert!(!p.end_tools(None));
        let entry = p.journal.iter().find(|e| e.id == "t").unwrap();
        assert_eq!(
            entry.outcome,
            Outcome::Failed {
                message: "vk build failed".into()
            }
        );
        let progress = p.tools_progress.clone().unwrap();
        assert_eq!(
            (progress.phase, progress.message.as_deref(), progress.log),
            (
                ToolsPhase::Failed,
                Some("vk build failed"),
                vec!["e".to_string()]
            )
        );

        // An update under way refuses a tools build in turn.
        let mut p = Persisted::default();
        p.command(update("u"), 1, true);
        assert!(busy(&mut p, tools("t", &sha)).contains("an update or a reset is under way"));
        // A malformed digest or an oversize definition is refused outright.
        let mut p = Persisted::default();
        assert!(busy(&mut p, tools("t", "AB")).contains("not 64 lowercase hex"));
        let big = command(
            "b",
            Operation::Tools {
                version: "v".into(),
                sha256: sha.clone(),
                size: vk_hub_proto::MAX_TOOLS_DEFINITION + 1,
            },
        );
        assert!(busy(&mut p, big).contains("past the"));
        assert!(p.tools.is_none());
        p.command(tools("t3", &sha), 1, true);
        assert!(p.end_tools(None));
        assert_eq!(
            p.journal.iter().find(|e| e.id == "t3").unwrap().outcome,
            Outcome::Done
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
