//! Job records and redacted submission specs. Successful create requests are keyed by
//! `request_id` so retries reuse the first answer. Full specs contain tokens and secrets;
//! the hub keeps them only in memory until a node accepts the job ([`crate::jobs`]).
//! Output is stored in separate files beside the database.
//!
//! The records are the hub's job history: the newest jobs, up to a count the operator sets,
//! in submission order ([`JOB_ORDER`]), so the oldest go first and a page of history is a
//! range read from the newest end.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError, RwLockReadGuard, RwLockWriteGuard};

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::{CancelMode, JobState, JobView, Placement};
use vk_hub_proto::job::{FailureClass, JobResult};

use super::approvals::Refusal;
use super::packed::{SPEC_DICTS, TAIL_LEVEL, pack, spec_to_store, unpack};
use super::{Db, append_audit, decode, encode};

/// Key: job ID. Value: JSON [`JobRow`].
pub(super) const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("jobs");
/// Key: (principal ID, admission ID). Value: job ID.
/// Reuse by another job returns [`Submitted::AdmissionTaken`].
pub(super) const JOB_BY_ADMISSION: TableDefinition<(&str, &str), &str> =
    TableDefinition::new("job_by_admission");
/// Key: job ID. Value: the job's spec as submitted, redacted, JSON, packed
/// ([`super::packed`]).
pub(super) const JOB_SPECS: TableDefinition<&str, &[u8]> = TableDefinition::new("job_specs");
/// Key: `<key id>/<request_id>`. Value: JSON [`RequestRow`].
pub(super) const REQUESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("requests");
/// Key: a sequence number, oldest submission first. Value: the job's ID.
pub(super) const JOB_ORDER: TableDefinition<u64, &str> = TableDefinition::new("job_order");
/// Key: job ID. Value: the end of a finished job's output, kept when its producer settled it
/// ([`crate::jobs::settle`]), as the node masked it, packed ([`super::packed`]). Goes with the
/// job's record; a job that did not fail keeps it only while [`JOB_CACHE`] does.
pub(super) const JOB_TAILS: TableDefinition<&str, &[u8]> = TableDefinition::new("job_tails_packed");
/// Key: job ID. Value: an unpacked output tail from an older hub. Read and removed like
/// [`JOB_TAILS`], and migrated there in the background by [`Db::pack_legacy_tails`].
/// Drop this table in a later release once hubs have migrated.
pub(super) const LEGACY_TAILS: TableDefinition<&str, &[u8]> = TableDefinition::new("job_tails");
/// Key: job ID. Value: its tail's stored length in [`JOB_TAILS`] or [`LEGACY_TAILS`].
/// Cache accounting, eviction and startup checks use this without reading the tails.
pub(super) const JOB_TAIL_LENS: TableDefinition<&str, u64> = TableDefinition::new("job_tail_lens");
/// The cache of the ends kept of jobs that did not fail. Key: a sequence number, oldest kept
/// first, the first evicted. Value: the job's ID. [`CACHED_BYTES`] is their total as stored.
pub(super) const JOB_CACHE: TableDefinition<u64, &str> = TableDefinition::new("job_cache");
/// Key: a key's ID. Value: how many of its jobs [`JOBS`] holds, kept in the writes that add and
/// drop records, so counting a key's jobs reads no record.
pub(super) const JOB_COUNTS: TableDefinition<&str, u64> = TableDefinition::new("job_counts");
/// The history's bookkeeping. Key: one of the names below. Value: as each says.
pub(super) const JOB_META: TableDefinition<&str, u64> = TableDefinition::new("job_meta");
/// A [`JOB_ORDER`] sequence: every job placed below it has finished and expired past
/// [`JOB_KEEP`].
const EXPIRED_BELOW: &str = "expired_below";
/// The bytes, as stored, of the ends that [`JOB_CACHE`] holds.
pub(super) const CACHED_BYTES: &str = "cached_bytes";
/// How many jobs' records the history keeps, as set from the web UI: over `job_history`.
const HISTORY: &str = "history";
/// Set once [`JOB_TAIL_LENS`] has every end kept: a database a build without it
/// wrote has them filled in once. An end a build without the lengths writes later (a dev
/// downgrade) has none, so orphan cleanup misses it; it is outside the cache, so nothing is
/// miscounted.
const TAIL_LENS: &str = "tail_lens";

/// How long a `request_id` keeps its answer.
pub const REQUEST_KEEP: u64 = 86_400;

/// How long after a job was settled or finished its redacted spec is kept, and its output when
/// its producer never settled it; its record stays in the history.
const JOB_KEEP: u64 = 30 * 86_400;

/// How many jobs past the excess one trim of the history examines at most: a history whose
/// oldest jobs cannot go yet is trimmed further on later passes, not read whole on each.
const TRIM_SCAN: u64 = 10_000;

/// How many jobs one trim of the history drops at most, so that lowering its count by far
/// trims it in many short writes ([`Pruned::more`]) rather than one long one.
const TRIM_DROP: u64 = 1_000;

/// How many jobs' records the history keeps by default (`job_history` in `hub.toml`).
pub const DEFAULT_JOB_HISTORY: usize = 100_000;

/// The most jobs' records the history may keep, however its count is set: each is a few
/// kilobytes in the database.
pub const MAX_JOB_HISTORY: u64 = 1_000_000;

/// How often, at most, requests past [`REQUEST_KEEP`] are swept.
const REQUEST_SWEEP_SECS: u64 = 600;

/// The stage a node prepares a job's executor in, as gitlab-runner names it.
pub const PREPARE_STAGE: &str = "prepare_executor";

/// The policy identity recorded when work is admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulingIdentity {
    /// The capacity tenant charged.
    pub tenant: String,
    /// The class it was admitted in.
    pub class: crate::policy::Class,
    /// The GitLab server and runner ID of the runner it was admitted for; an API-key client
    /// has neither.
    pub gitlab: Option<String>,
    pub runner_id: Option<u64>,
}

/// A job the hub has taken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRow {
    /// The submitting relay's or key's ID ([`super::ApiPrincipal::id`]).
    pub key: String,
    /// Its name, for display: a relay's hostname, a key's name.
    pub key_name: String,
    /// The client instance that submitted it ([`super::ApiPrincipal::instance`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    pub request_id: String,
    /// The identity it was admitted under, charged by capacity arbitration; `None` for a job
    /// admitted without one, or an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduling: Option<SchedulingIdentity>,
    /// The admission it took ([`valid_id`](vk_hub_proto::valid_id)), which takes no other
    /// job; `None` as for `scheduling`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
    pub placement: Placement,
    /// What the job is, for display: GitLab's job ID, project and name.
    #[serde(default)]
    pub title: String,
    /// Display-safe GitLab project (`group/project`); `None` for an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The job's name in its pipeline, display-safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The branch or tag it ran for, display-safe; `None` when the spec has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// GitLab's ID of its pipeline; `None` when the spec has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<u64>,
    /// The commit it ran, lowercase hex; `None` when the spec has no commit or the record
    /// comes from an older hub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// The job's GitLab page from its spec; `None` for an invalid URL or an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_url: Option<String>,
    pub created_at: u64,
    pub state: JobState,
    pub revision: u64,
    #[serde(default)]
    pub node: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    /// What its stage does, when the node says: building an image, waiting for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<vk_hub_proto::dispatch::Activity>,
    #[serde(default)]
    pub cancel: Option<CancelMode>,
    #[serde(default)]
    pub result: Option<JobResult>,
    /// The egress report of a job still running, as its node last sent it; the result's holds
    /// it once the job has ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<vk_hub_proto::egress::EgressReport>,
    /// The output's length: as stored while the job runs, final once it has finished.
    #[serde(default)]
    pub output_len: u64,
    /// When a node accepted it, on the hub's clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    /// Hub time when it learned the job left `prepare_executor` for a job stage.
    /// Reports received after an outage can lag the actual transition.
    /// `None` during preparation or for an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_at: Option<u64>,
    /// The size its node gave its VM, once its preparation sized it; `None` before, or from a
    /// node that does not say. A finished job's usage says it too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<vk_hub_proto::dispatch::GuestSize>,
    #[serde(default)]
    pub finished_at: Option<u64>,
    /// When its producer settled it and its output was dropped.
    #[serde(default)]
    pub settled_at: Option<u64>,
    /// When expiry past [`JOB_KEEP`] removed its redacted spec and any unsettled output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<u64>,
    /// Registry access recorded at placement, never the token itself.
    /// `None` before placement and for jobs placed by older hubs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_access: Option<RegistryAccess>,
    /// The GitLab instance its relay was bound to at submission, by name: the instance the
    /// approval gate checked its project against. `None` for an older hub's record of a key
    /// bound to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitlab: Option<String>,
    /// GitLab's ID of its project; `None` when the spec has none or for an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<u64>,
    /// Whether GitLab said its ref is protected, as the spec reports it: no ceiling checks it.
    /// `None` when GitLab did not say, or for an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
    /// The hub's egress rules its latest placement resolved for it; `None` before placement,
    /// with `[jobs] egress_rules` off, and for jobs placed by older hubs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_rules: Option<EgressRulesApplied>,
    /// The fingerprint of its node's egress caps ([`vk_hub_proto::egress::EgressCaps`]) as the
    /// hub knew them when it placed the job; `None` for a node that did not report them, or a
    /// job placed by an older hub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_caps: Option<String>,
}

/// The hub's egress rules a placed job's layer was resolved from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRulesApplied {
    /// The enforced rules, `default` when the Fallback alone applied; none when no rule
    /// selected the job and no Fallback is enforced, so that it could reach nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    /// The dry-run rules that selected it, the Fallback's included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dry_run: Vec<String>,
    /// The rules' generation it was resolved under.
    pub generation: u64,
}

/// What registry access a placed job got: its token's display data, or why it got none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegistryAccess {
    Issued {
        registry: String,
        grants: Vec<vk_hub_proto::token::Grant>,
        expires_at: u64,
        /// The token's ID, as audited.
        jti: String,
    },
    None {
        reason: NoAccess,
        /// The registry it concerns, when one is known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registry: Option<String>,
        /// The registry URL the node reported, when it concerns that.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    /// A kind from a later hub.
    #[serde(other)]
    Unknown,
}

/// Why a placed job got no registry token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoAccess {
    /// Its relay was removed, or its GitLab server is no longer approved; or, for an older
    /// hub's record, its jobs key was bound to no GitLab instance.
    UnboundKey,
    /// Its node does not announce job tokens: an older `vk`.
    NodeWithoutJobTokens,
    /// Its node reports no registry, or one bound to no registry the hub knows.
    UnknownRegistry,
    /// The registry it reaches does not take tokens (`[hub] tokens`).
    RegistryTakesNoTokens,
    /// The registry has applied no signing key yet.
    NoAppliedKey,
    /// Minting failed: the hub's log says why.
    MintFailed,
    /// A reason from a later hub.
    #[serde(other)]
    Other,
}

impl JobRow {
    /// The job as the client API shows it, with `output_len` the output held now.
    pub fn view(&self, id: &str, output_len: u64) -> JobView {
        JobView {
            id: id.to_string(),
            revision: self.revision,
            state: self.state,
            node: self.node.clone(),
            stage: self.stage.clone(),
            output_len,
            cancel: self.cancel,
            result: self.result.clone(),
        }
    }

    /// The job's own runtime in milliseconds, its preparation left out ([`JobRow::prepare_ms`]):
    /// the node's measurement when there is one, else the hub's time from its preparation's
    /// end — or its acceptance, for a record that does not say when that was — to its end, or
    /// to `now` while it runs. `None` for a job no node accepted, or one still preparing, or
    /// ended while it did.
    pub fn ran_ms(&self, now: u64) -> Option<u64> {
        if let Some(usage) = self.result.as_ref().and_then(|r| r.usage) {
            let prepare = self.prepare_ms(now).unwrap_or(0);
            return Some(usage.wall_ms.saturating_sub(prepare));
        }
        if self.preparing() || self.ended_preparing() {
            return None;
        }
        let end = match self.state {
            JobState::Finished => self.finished_at?,
            _ => now,
        };
        let start = self.prepared_at.or(self.started_at)?;
        Some(end.saturating_sub(start).saturating_mul(1000))
    }

    /// Preparation duration in milliseconds, through `now` if still preparing: admission,
    /// building or pulling the image, waiting for another job's build and VM boot.
    /// Uses the node's measurement, or hub stage times for older nodes without one.
    /// `None` when the record lacks the timing.
    pub fn prepare_ms(&self, now: u64) -> Option<u64> {
        let measured = self.result.as_ref().and_then(|r| r.usage?.prepare_ms);
        if measured.is_some() {
            return measured;
        }
        let started = self.started_at?;
        let end = match self.prepared_at {
            Some(at) => at,
            None if self.preparing() => now,
            None if self.ended_preparing() => self.finished_at?,
            None => return None,
        };
        Some(end.saturating_sub(started).saturating_mul(1000))
    }

    /// Whether a node took the job and is still preparing it, or cleaning up after preparing
    /// failed.
    pub fn preparing(&self) -> bool {
        self.state != JobState::Finished
            && self.result.is_none()
            && self.started_at.is_some()
            && self.prepared_at.is_none()
            && (self.stage.as_deref()).is_none_or(|s| s == PREPARE_STAGE || s == "cleanup")
    }

    /// Whether the hub ended it while it prepared — its node lost — with nothing measured: all
    /// of its time was preparing.
    fn ended_preparing(&self) -> bool {
        self.state == JobState::Finished
            && self.result.as_ref().is_some_and(|r| r.usage.is_none())
            && self.started_at.is_some()
            && self.prepared_at.is_none()
            && (self.stage.as_deref()).is_some_and(|s| s == PREPARE_STAGE || s == "cleanup")
    }

    /// Run start on the hub's clock, for the page's timer; `None` before the run,
    /// during preparation and after completion.
    pub fn running_since(&self) -> Option<u64> {
        self.prepared_at
            .or(self.started_at)
            .filter(|_| self.state != JobState::Finished && self.result.is_none())
            .filter(|_| !self.preparing())
    }

    /// The size its node gave its VM, in vCPUs and MiB: from its usage once it ended, from its
    /// stages once its preparation sized it, and unknown before or from a node that does not
    /// say. Not the reservation's envelope: what the producer asked to hold, not what the job
    /// got.
    pub fn vm_size(&self) -> Option<(u32, u64)> {
        let usage = self.result.as_ref().and_then(|r| r.usage);
        let size = match usage.map(|u| (u.cpus, u.mem_mib)) {
            Some((Some(cpus), Some(mem))) => Some((cpus, mem)),
            _ => self.guest.map(|g| (g.cpus, g.mem_mib)),
        };
        size.filter(|&(cpus, mem)| cpus > 0 && mem > 0)
    }

    /// When its preparation started, while it goes on.
    pub fn preparing_since(&self) -> Option<u64> {
        self.started_at.filter(|_| self.preparing())
    }

    /// The job's outcome for history filtering.
    pub fn outcome(&self) -> JobOutcome {
        match (self.state, &self.result) {
            (JobState::Finished, Some(r)) => match r.failure {
                None => JobOutcome::Success,
                Some(FailureClass::Canceled) => JobOutcome::Canceled,
                Some(_) => JobOutcome::Failed,
            },
            (JobState::Finished, None) => JobOutcome::Failed,
            _ => JobOutcome::Running,
        }
    }
}

/// Job outcome used by the history filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JobOutcome {
    /// Queued, starting or running.
    Running,
    Success,
    /// Ended by a failure of any class but a cancel.
    Failed,
    Canceled,
}

impl JobOutcome {
    pub const ALL: [JobOutcome; 4] = [
        JobOutcome::Running,
        JobOutcome::Success,
        JobOutcome::Failed,
        JobOutcome::Canceled,
    ];

    pub fn name(self) -> &'static str {
        match self {
            JobOutcome::Running => "running",
            JobOutcome::Success => "success",
            JobOutcome::Failed => "failed",
            JobOutcome::Canceled => "canceled",
        }
    }

    /// The label shown in the result filter.
    pub fn label(self) -> &'static str {
        match self {
            JobOutcome::Running => "Running",
            JobOutcome::Success => "Success",
            JobOutcome::Failed => "Failed",
            JobOutcome::Canceled => "Canceled",
        }
    }

    pub fn parse(s: &str) -> Option<JobOutcome> {
        JobOutcome::ALL.into_iter().find(|o| o.name() == s)
    }
}

/// Jobs matching every active filter. A missing field matches no filter value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct JobFilter {
    /// The ID of the key that submitted it ([`JobRow::key`]).
    pub key: Option<String>,
    /// The node it was sent to.
    pub node: Option<String>,
    /// Its GitLab project, exactly.
    pub project: Option<String>,
    pub outcome: Option<JobOutcome>,
    /// A substring of its job name, ignoring ASCII case.
    pub name: Option<String>,
    /// A substring of its branch or tag, ignoring ASCII case.
    pub git_ref: Option<String>,
    /// Its pipeline's ID.
    pub pipeline: Option<u64>,
    /// Only jobs that reported events (a virtio-fs stall, …).
    pub events: bool,
}

impl JobFilter {
    pub fn matches(&self, row: &JobRow) -> bool {
        self.matches_facets(&row.facets())
    }

    fn matches_facets(&self, job: &Facets<'_>) -> bool {
        let holds = |want: &Option<String>, have: Option<&str>| {
            want.as_deref()
                .is_none_or(|w| have.is_some_and(|h| contains_folded(h, w)))
        };
        self.key.as_ref().is_none_or(|k| job.key == k)
            && (self.node.as_deref()).is_none_or(|n| job.node == Some(n))
            && (self.project.as_deref()).is_none_or(|p| job.project == Some(p))
            && self.outcome.is_none_or(|o| job.outcome == o)
            && holds(&self.name, job.name)
            && holds(&self.git_ref, job.git_ref)
            && self.pipeline.is_none_or(|p| job.pipeline == Some(p))
            && (!self.events || job.events)
    }
}

/// What a [`JobFilter`] matches a job on.
struct Facets<'a> {
    key: &'a str,
    node: Option<&'a str>,
    project: Option<&'a str>,
    name: Option<&'a str>,
    git_ref: Option<&'a str>,
    pipeline: Option<u64>,
    outcome: JobOutcome,
    /// It reported events.
    events: bool,
}

impl JobRow {
    fn facets(&self) -> Facets<'_> {
        Facets {
            key: &self.key,
            node: self.node.as_deref(),
            project: self.project.as_deref(),
            name: self.name.as_deref(),
            git_ref: self.git_ref.as_deref(),
            pipeline: self.pipeline,
            outcome: self.outcome(),
            events: self.result.as_ref().is_some_and(|r| !r.events.is_empty()),
        }
    }
}

/// What a page of the history reads of a job that it does not show: its [`Facets`], and what
/// the summary counts.
#[derive(Debug, PartialEq, Eq)]
struct Brief {
    id: Arc<str>,
    revision: u64,
    key: Arc<str>,
    node: Option<Arc<str>>,
    project: Option<Arc<str>>,
    name: Option<Arc<str>>,
    git_ref: Option<Arc<str>>,
    pipeline: Option<u64>,
    outcome: JobOutcome,
    events: bool,
    /// How long it ran, once finished.
    ran_ms: Option<u64>,
}

impl Brief {
    fn facets(&self) -> Facets<'_> {
        Facets {
            key: &self.key,
            node: self.node.as_deref(),
            project: self.project.as_deref(),
            name: self.name.as_deref(),
            git_ref: self.git_ref.as_deref(),
            pipeline: self.pipeline,
            outcome: self.outcome,
            events: self.events,
        }
    }
}

/// Each job's [`Brief`], in history order, held in memory so pages decode only displayed
/// records. Loaded by [`Db::read_job_briefs`], then updated on additions, changes and
/// deletions by [`Db::commit_briefed`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Briefs {
    by_seq: BTreeMap<u64, Brief>,
    /// Each job's place in [`Briefs::by_seq`].
    seq_of: HashMap<Arc<str>, u64>,
    /// The strings the briefs share: keys, nodes, projects, names and branches repeat.
    strings: HashSet<Arc<str>>,
}

/// How far the history's [`Briefs`] are read.
#[derive(Debug, Default)]
pub(super) enum BriefState {
    /// Not yet, or lost to a panic that held them: [`Db::read_job_briefs`] reads them.
    #[default]
    Unread,
    /// Being read from a snapshot: the changes committed since, applied once it is read.
    Reading(Vec<BriefChange>),
    Read(Briefs),
}

/// A committed write's change to the history, as [`Briefs`] take it.
#[derive(Debug)]
pub(super) enum BriefChange {
    /// A job submitted, at its place in the history.
    Place(u64, String, JobRow),
    /// A job's record written.
    Update(String, JobRow),
    /// The jobs at these places dropped.
    Drop(Vec<u64>),
}

impl Briefs {
    fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some(s) = self.strings.get(s) {
            return s.clone();
        }
        let s: Arc<str> = Arc::from(s);
        self.strings.insert(s.clone());
        s
    }

    fn brief(&mut self, id: Arc<str>, row: &JobRow) -> Brief {
        let mut intern = |s: &Option<String>| s.as_deref().map(|s| self.intern(s));
        let (node, project, name, git_ref) = (
            intern(&row.node),
            intern(&row.project),
            intern(&row.name),
            intern(&row.git_ref),
        );
        Brief {
            id,
            revision: row.revision,
            key: self.intern(&row.key),
            node,
            project,
            name,
            git_ref,
            pipeline: row.pipeline,
            outcome: row.outcome(),
            events: row.facets().events,
            // A finished job's run does not depend on the clock.
            ran_ms: (row.state == JobState::Finished)
                .then(|| row.ran_ms(0))
                .flatten(),
        }
    }

    /// Job `id`, placed at `seq` in the history.
    fn place(&mut self, seq: u64, id: &str, row: &JobRow) {
        let id: Arc<str> = Arc::from(id);
        let brief = self.brief(id.clone(), row);
        self.by_seq.insert(seq, brief);
        self.seq_of.insert(id, seq);
    }

    fn apply(&mut self, change: BriefChange) {
        match change {
            BriefChange::Place(seq, id, row) => self.place(seq, &id, &row),
            BriefChange::Update(id, row) => {
                // [`Db::put_job`] writes only a job in the history, at a revision not older.
                let Some(&seq) = self.seq_of.get(id.as_str()) else {
                    return;
                };
                let Some(kept) = self.by_seq.get(&seq) else {
                    return;
                };
                let brief = self.brief(kept.id.clone(), &row);
                self.by_seq.insert(seq, brief);
            }
            BriefChange::Drop(seqs) => {
                for seq in &seqs {
                    if let Some(b) = self.by_seq.remove(seq)
                        && self.seq_of.get(&b.id) == Some(seq)
                    {
                        self.seq_of.remove(&b.id);
                    }
                }
                // Past a drop, the strings no brief holds number at most the jobs kept.
                if !seqs.is_empty() && self.strings.len() > self.by_seq.len() {
                    self.strings.retain(|s| Arc::strong_count(s) > 1);
                }
            }
        }
    }

    /// Every job in the history at `txn`.
    fn read(txn: &redb::ReadTransaction) -> Result<Self> {
        let table = txn.open_table(JOBS)?;
        let order = txn.open_table(JOB_ORDER)?;
        let mut briefs = Briefs::default();
        for entry in order.iter()? {
            let (seq, id) = entry?;
            let Some(row) = table.get(id.value())? else {
                continue;
            };
            // One that does not decode is left out rather than failing every page.
            if let Ok(row) = decode::<JobRow>(row.value()) {
                briefs.place(seq.value(), id.value(), &row);
            }
        }
        Ok(briefs)
    }
}

/// Whether `haystack` contains `needle`, ignoring ASCII case. Avoid allocations because
/// this runs on every record a page of history reads.
pub(super) fn contains_folded(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Summary of every job a filter matches.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobSummary {
    pub matched: usize,
    /// Those that ended, whichever way.
    pub finished: usize,
    pub succeeded: usize,
    /// The median of how long the finished ones ran, in milliseconds.
    pub median_ms: Option<u64>,
}

/// The median of `values`, the mean of the middle two for an even count.
fn median(values: &mut [u64]) -> Option<u64> {
    values.sort_unstable();
    let mid = values.len() / 2;
    match values.len() {
        0 => None,
        n if n % 2 == 1 => Some(values[mid]),
        _ => Some(values[mid - 1].midpoint(values[mid])),
    }
}

/// A page of the job history, newest first.
#[derive(Debug, Default)]
pub struct JobPage {
    /// Each job's place in the history ([`JOB_ORDER`]), ID and record.
    pub rows: Vec<(u64, String, JobRow)>,
    /// The last job's position, used as the next page's exclusive cursor when older jobs match.
    pub older: Option<u64>,
    pub summary: JobSummary,
    /// Every project in the history, sorted, for the filter's choices.
    pub projects: Vec<String>,
    /// The history is still being read since the hub started: the page is empty meanwhile.
    pub reading: bool,
}

/// A client request that created something, and what it was answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRow {
    pub at: u64,
    /// `sha256` of the request's body as parsed, hex: the same ID with another body is a
    /// conflict, not a retry.
    pub digest: String,
    /// The job created, the reservation granted, or the submission's refusal by the
    /// approval gate (`{"refused": `[`Refusal`]`}`).
    pub answer: serde_json::Value,
}

impl RequestRow {
    /// The approval gate's refusal of the job this request submitted, if it was refused.
    pub fn refusal(&self) -> Option<Refusal> {
        serde_json::from_value(self.answer.get("refused")?.clone()).ok()
    }
}

/// What a job submission came to.
#[derive(Debug)]
pub enum Submitted {
    New,
    /// The request was made before, with the same body: this job.
    Again(String),
    /// The request ID was used before with another body.
    Conflict,
    /// The job's admission is already another job's.
    AdmissionTaken,
}

/// A request's key in [`REQUESTS`].
pub(super) fn request_key(key: &str, request_id: &str) -> String {
    format!("{key}/{request_id}")
}

impl Db {
    /// Record job `id` for `row`, submitted as `request_id` with a body hashing to `digest`,
    /// and its redacted spec, audited as `actor`'s — or, for a request ID seen before, what
    /// that came to.
    pub fn submit_job(
        &self,
        id: &str,
        row: &JobRow,
        digest: &str,
        redacted_spec: &[u8],
        actor: &str,
        now: u64,
    ) -> Result<Submitted> {
        let request = request_key(&row.key, &row.request_id);
        let spec = self.pack_spec(redacted_spec)?;
        let txn = self.db.begin_write().context("starting a write")?;
        let spec = spec_to_store(&txn, redacted_spec, spec)?;
        let seq;
        {
            let mut requests = txn.open_table(REQUESTS)?;
            let mut index = txn.open_table(JOB_BY_ADMISSION)?;
            if let Some(previous) = requests
                .get(request.as_str())?
                .map(|g| decode::<RequestRow>(g.value()))
                .transpose()?
                .filter(|r| now.saturating_sub(r.at) < REQUEST_KEEP)
            {
                return Ok(if previous.digest == digest {
                    match previous.answer.as_str() {
                        Some(job) => Submitted::Again(job.to_string()),
                        None => Submitted::Conflict,
                    }
                } else {
                    Submitted::Conflict
                });
            }
            if let Some(admission) = &row.admission {
                let key = (row.key.as_str(), admission.as_str());
                if index.get(key)?.is_some() {
                    return Ok(Submitted::AdmissionTaken);
                }
                index.insert(key, id)?;
            }
            sweep_requests(self, &mut requests, now)?;
            let answer = RequestRow {
                at: now,
                digest: digest.to_string(),
                answer: serde_json::Value::String(id.to_string()),
            };
            requests.insert(request.as_str(), encode(&answer)?.as_slice())?;
            let replaced = txn
                .open_table(JOBS)?
                .insert(id, encode(row)?.as_slice())?
                .is_some();
            if !replaced {
                // A job submitted has no report; a record restored with one shares it.
                super::egress::reshare(&txn, id, None, Some(row))?;
                super::egress::confirm(&txn, id, row, now)?;
                super::observed::reshare(&txn, id, None, Some(row))?;
                let mut counts = txn.open_table(JOB_COUNTS)?;
                let n = counts.get(row.key.as_str())?.map_or(0, |g| g.value());
                counts.insert(row.key.as_str(), n.saturating_add(1))?;
            }
            txn.open_table(JOB_SPECS)?.insert(id, spec.as_slice())?;
            let mut order = txn.open_table(JOB_ORDER)?;
            seq = next_seq(&order, &txn.open_table(JOB_META)?)?;
            order.insert(seq, id)?;
        }
        let event = format!("{actor} submitted job {id}: {}", row.title);
        append_audit(&txn, None, actor, &event, now)?;
        self.commit_briefed(txn, BriefChange::Place(seq, id.to_string(), row.clone()))
            .context("recording a job")?;
        Ok(Submitted::New)
    }

    /// The answer a reservation request made as `request_id` by key `key` got, if it was made
    /// within [`REQUEST_KEEP`].
    pub fn request(&self, key: &str, request_id: &str, now: u64) -> Result<Option<RequestRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(REQUESTS)?;
        Ok(table
            .get(request_key(key, request_id).as_str())?
            .map(|g| decode::<RequestRow>(g.value()))
            .transpose()?
            .filter(|r| now.saturating_sub(r.at) < REQUEST_KEEP))
    }

    /// Record that the request `request_id` of key `key` was answered with `row`. Unaudited: a
    /// runner reserves before every poll, and the reservation a job uses is audited when the
    /// job is sent to its node.
    pub fn record_request(&self, key: &str, request_id: &str, row: &RequestRow) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut requests = txn.open_table(REQUESTS)?;
            sweep_requests(self, &mut requests, row.at)?;
            requests.insert(
                request_key(key, request_id).as_str(),
                encode(row)?.as_slice(),
            )?;
        }
        txn.commit().context("recording a request")
    }

    pub fn job(&self, id: &str) -> Result<Option<JobRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        table
            .get(id)?
            .map(|g| decode::<JobRow>(g.value()))
            .transpose()
    }

    /// Write `row` for job `id`, unless a later revision is already stored or the job is
    /// gone from the history: only [`Db::submit_job`] adds a job. Racing writes keep the
    /// newer revision. Audit each `(node, actor, event)` in `events` either way: they tell
    /// of changes already made, which a newer revision carries if this one loses.
    /// Return whether the row was written.
    pub fn put_job(
        &self,
        id: &str,
        row: &JobRow,
        events: &[(Option<String>, String, String)],
        now: u64,
    ) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let written = {
            let mut table = txn.open_table(JOBS)?;
            let stored = table
                .get(id)?
                .map(|g| decode::<JobRow>(g.value()))
                .transpose()?;
            match stored.filter(|s| s.revision <= row.revision) {
                None => false,
                Some(stored) => {
                    // A write prepared before the job expired keeps it expired.
                    let mut row = row.clone();
                    row.expired_at = row.expired_at.or(stored.expired_at);
                    table.insert(id, encode(&row)?.as_slice())?;
                    super::egress::reshare(&txn, id, Some(&stored), Some(&row))?;
                    super::egress::confirm(&txn, id, &row, now)?;
                    super::observed::reshare(&txn, id, Some(&stored), Some(&row))?;
                    true
                }
            }
        };
        if !written && events.is_empty() {
            return Ok(false);
        }
        for (node, actor, event) in events {
            append_audit(&txn, node.as_deref(), actor, event, now)?;
        }
        if written {
            self.commit_briefed(txn, BriefChange::Update(id.to_string(), row.clone()))
        } else {
            txn.commit().map_err(Into::into)
        }
        .context("updating a job")?;
        Ok(written)
    }

    /// Keep job `id`'s output `tail` for as long as its record. Return false without storing
    /// it if the job is no longer in the history.
    pub fn keep_job_tail(&self, id: &str, tail: &[u8]) -> Result<bool> {
        let tail = pack(tail, TAIL_LEVEL)?;
        let txn = self.db.begin_write().context("starting a write")?;
        {
            if txn.open_table(JOBS)?.get(id)?.is_none() {
                return Ok(false);
            }
            txn.open_table(JOB_TAILS)?.insert(id, tail.as_slice())?;
            txn.open_table(LEGACY_TAILS)?.remove(id)?;
            txn.open_table(JOB_TAIL_LENS)?
                .insert(id, tail.len() as u64)?;
        }
        txn.commit().context("keeping a job's output")?;
        Ok(true)
    }

    /// Cache job `id`'s output `tail` for a job that did not fail. Evict the oldest retained
    /// tails until it fits within `total` bytes as stored. Return false without storing it if
    /// the job is no longer in the history or `tail` alone, stored, exceeds `total`. Preserve
    /// an existing tail: a job's output is final once settled.
    pub fn cache_job_tail(&self, id: &str, tail: &[u8], total: u64) -> Result<bool> {
        let tail = pack(tail, TAIL_LEVEL)?;
        let len = tail.len() as u64;
        let txn = self.db.begin_write().context("starting a write")?;
        {
            if len > total || txn.open_table(JOBS)?.get(id)?.is_none() {
                return Ok(false);
            }
            let mut lens = txn.open_table(JOB_TAIL_LENS)?;
            if lens.get(id)?.is_some() {
                return Ok(true);
            }
            let mut tails = txn.open_table(JOB_TAILS)?;
            let mut cache = txn.open_table(JOB_CACHE)?;
            let mut meta = txn.open_table(JOB_META)?;
            let mut kept = Kept {
                cache: &mut cache,
                tails: &mut tails,
                legacy: &mut txn.open_table(LEGACY_TAILS)?,
                lens: &mut lens,
            };
            let cached = kept.evict(&mut meta, total.saturating_sub(len))?;
            let seq = cache
                .last()?
                .map_or(0, |(k, _)| k.value().saturating_add(1));
            cache.insert(seq, id)?;
            tails.insert(id, tail.as_slice())?;
            lens.insert(id, len)?;
            meta.insert(CACHED_BYTES, cached.saturating_add(len))?;
        }
        txn.commit().context("caching a job's output")?;
        Ok(true)
    }

    /// Evict the oldest retained tails from [`Db::cache_job_tail`]'s cache until it holds at
    /// most `total` bytes as stored, to apply a reduced configuration limit.
    pub fn fit_job_cache(&self, total: u64) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut meta = txn.open_table(JOB_META)?;
            if meta.get(CACHED_BYTES)?.map_or(0, |g| g.value()) <= total {
                return Ok(());
            }
            let mut kept = Kept {
                cache: &mut txn.open_table(JOB_CACHE)?,
                tails: &mut txn.open_table(JOB_TAILS)?,
                legacy: &mut txn.open_table(LEGACY_TAILS)?,
                lens: &mut txn.open_table(JOB_TAIL_LENS)?,
            };
            let cached = kept.evict(&mut meta, total)?;
            meta.insert(CACHED_BYTES, cached)?;
        }
        txn.commit().context("fitting the job output cache")?;
        Ok(())
    }

    /// The end of job `id`'s output kept by [`Db::keep_job_tail`] or [`Db::cache_job_tail`],
    /// unpacked.
    pub fn job_tail(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().context("starting a read")?;
        if let Some(tail) = txn.open_table(JOB_TAILS)?.get(id)? {
            // Kept output names no dictionary.
            let tail = unpack(tail.value(), |d| bail!("kept output names dictionary {d}"))?;
            return Ok(Some(tail));
        }
        let legacy = txn.open_table(LEGACY_TAILS)?;
        Ok(legacy.get(id)?.map(|g| g.value().to_vec()))
    }

    /// Every job not finished.
    pub fn unfinished_jobs(&self) -> Result<Vec<(String, JobRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let row = decode::<JobRow>(value.value())?;
            if row.state != JobState::Finished {
                out.push((key.value().to_string(), row));
            }
        }
        Ok(out)
    }

    /// The latest `limit` jobs, newest first.
    pub fn jobs(&self, limit: usize) -> Result<Vec<(String, JobRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        let order = txn.open_table(JOB_ORDER)?;
        let mut out = Vec::new();
        for entry in order.iter()?.rev() {
            if out.len() >= limit {
                break;
            }
            let id = entry?.1.value().to_string();
            if let Some(row) = table.get(id.as_str())? {
                let row = decode::<JobRow>(row.value())?;
                out.push((id, row));
            }
        }
        Ok(out)
    }

    /// Visit the latest `limit` jobs, newest first, decoding one record at a time: how many
    /// were visited.
    pub fn visit_jobs(&self, limit: usize, mut visit: impl FnMut(&str, &JobRow)) -> Result<usize> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        let order = txn.open_table(JOB_ORDER)?;
        let mut visited = 0usize;
        for entry in order.iter()?.rev() {
            if visited >= limit {
                break;
            }
            let id = entry?.1.value().to_string();
            if let Some(row) = table.get(id.as_str())? {
                visit(&id, &decode::<JobRow>(row.value())?);
                visited = visited.saturating_add(1);
            }
        }
        Ok(visited)
    }

    /// How many jobs the history holds of each key, by key ID: one read of [`JOB_COUNTS`].
    pub fn job_counts_by_key(&self) -> Result<HashMap<String, u64>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOB_COUNTS)?;
        let mut counts = HashMap::new();
        for entry in table.iter()? {
            let (key, n) = entry?;
            counts.insert(key.value().to_string(), n.value());
        }
        Ok(counts)
    }

    /// Visit the latest `limit` jobs, newest first, retaining only jobs a node accepted
    /// that finished at or after `since` or remain unfinished. Pass each redacted spec,
    /// unpacked, to `visit`, holding one spec at a time. Skip jobs whose specs expired, and
    /// those whose specs do not unpack.
    pub fn recent_job_specs(
        &self,
        since: u64,
        limit: usize,
        mut visit: impl FnMut(String, JobRow, &[u8]),
    ) -> Result<()> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        let specs = txn.open_table(JOB_SPECS)?;
        let dicts = txn.open_table(SPEC_DICTS)?;
        let order = txn.open_table(JOB_ORDER)?;
        for entry in order.iter()?.rev().take(limit) {
            let id = entry?.1.value().to_string();
            let Some(row) = table.get(id.as_str())? else {
                continue;
            };
            let row = decode::<JobRow>(row.value())?;
            if row.node.is_none()
                || row.started_at.is_none()
                || row.finished_at.is_some_and(|t| t < since)
            {
                continue;
            }
            let Some(spec) = specs.get(id.as_str())? else {
                continue;
            };
            match self.unpack_spec(&dicts, spec.value()) {
                Ok(spec) => visit(id, row, &spec),
                Err(e) => eprintln!("vk-hub: job {id}'s spec: {e:#}"),
            }
        }
        Ok(())
    }

    /// Up to `limit` matching jobs, newest first, submitted before the job at `before`, with
    /// a summary of every job `filter` matches and the projects of the whole history: the
    /// history is read whole.
    pub fn job_page(
        &self,
        filter: &JobFilter,
        before: Option<u64>,
        limit: usize,
    ) -> Result<JobPage> {
        let mut page = JobPage::default();
        let mut shown = Vec::new();
        {
            let held = self.read_briefs();
            let BriefState::Read(briefs) = &*held else {
                page.reading = true;
                return Ok(page);
            };
            #[cfg(test)]
            self.assert_briefs(briefs);
            let mut projects = std::collections::BTreeSet::new();
            let mut ran = Vec::new();
            for (&seq, job) in briefs.by_seq.iter().rev() {
                if let Some(p) = &job.project {
                    projects.insert(p.clone());
                }
                if !filter.matches_facets(&job.facets()) {
                    continue;
                }
                let summary = &mut page.summary;
                summary.matched += 1;
                if job.outcome != JobOutcome::Running {
                    summary.finished += 1;
                    summary.succeeded += usize::from(job.outcome == JobOutcome::Success);
                    ran.extend(job.ran_ms);
                }
                if before.is_some_and(|b| seq >= b) {
                    continue;
                }
                if shown.len() < limit {
                    shown.push((seq, job.id.clone()));
                } else if page.older.is_none() {
                    page.older = shown.last().map(|r| r.0);
                }
            }
            page.summary.median_ms = median(&mut ran);
            page.projects = projects.iter().map(|p| p.to_string()).collect();
        }
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        for (seq, id) in shown {
            // Dropped since, or one that does not decode: left out.
            let Some(row) = table.get(&*id)? else {
                continue;
            };
            if let Ok(row) = decode::<JobRow>(row.value()) {
                page.rows.push((seq, id.to_string(), row));
            }
        }
        Ok(page)
    }

    /// Read the history's [`Briefs`] from a snapshot unless already read or being read.
    /// Release their lock during the read and apply changes committed meanwhile afterward.
    /// Return whether they were read.
    pub fn read_job_briefs(&self) -> Result<bool> {
        // Checked under the read lock first: once read, a call does not hold up commits.
        if !matches!(*self.read_briefs(), BriefState::Unread) {
            return Ok(false);
        }
        let Some(txn) = self.start_reading_briefs()? else {
            return Ok(false);
        };
        let _unwound = ReadingBriefs(self);
        self.finish_reading_briefs(&txn)?;
        Ok(true)
    }

    /// The snapshot to read the history's briefs from, now marked as being read; `None` when
    /// they are read or being read.
    fn start_reading_briefs(&self) -> Result<Option<redb::ReadTransaction>> {
        let mut held = self.write_briefs();
        if !matches!(*held, BriefState::Unread) {
            return Ok(None);
        }
        // No write commits while they are held, so the snapshot misses none that is not kept.
        let txn = self.db.begin_read().context("starting a read")?;
        *held = BriefState::Reading(Vec::new());
        Ok(Some(txn))
    }

    /// Read the history's briefs from `txn`, then apply the changes committed since.
    fn finish_reading_briefs(&self, txn: &redb::ReadTransaction) -> Result<()> {
        let read = Briefs::read(txn);
        let mut held = self.write_briefs();
        match (read, std::mem::take(&mut *held)) {
            (Ok(mut briefs), BriefState::Reading(changes)) => {
                for change in changes {
                    briefs.apply(change);
                }
                *held = BriefState::Read(briefs);
                Ok(())
            }
            // Lost to a panic meanwhile: the next call reads them again.
            (Ok(_), _) => Ok(()),
            (Err(e), _) => Err(e.context("reading the job history")),
        }
    }

    /// Whether the history's briefs are read, and its pages served.
    pub fn job_briefs_read(&self) -> bool {
        matches!(*self.read_briefs(), BriefState::Read(_))
    }

    /// Forget the history's briefs, as a hub starting has none yet.
    #[cfg(test)]
    pub(crate) fn forget_job_briefs(&self) {
        *self.write_briefs() = BriefState::Unread;
    }

    /// The history's [`BriefState`] to read: briefly, as a write's commit waits.
    fn read_briefs(&self) -> RwLockReadGuard<'_, BriefState> {
        if let Ok(held) = self.job_briefs.read() {
            return held;
        }
        drop(self.write_briefs());
        self.job_briefs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The history's [`BriefState`] to change. A panic that held it may have left the
    /// briefs half-changed: they are dropped, for [`Db::read_job_briefs`] to read again.
    fn write_briefs(&self) -> RwLockWriteGuard<'_, BriefState> {
        self.job_briefs.write().unwrap_or_else(|poisoned| {
            let mut held = poisoned.into_inner();
            *held = BriefState::Unread;
            self.job_briefs.clear_poison();
            held
        })
    }

    /// Commit the history write `txn`, then apply its `change` to [`Briefs`] or queue it
    /// while they are being read. Hold their lock across the commit and change to preserve
    /// commit order and prevent pages from reading between them.
    fn commit_briefed(&self, txn: redb::WriteTransaction, change: BriefChange) -> Result<()> {
        let mut held = self.write_briefs();
        txn.commit()?;
        match &mut *held {
            BriefState::Unread => {}
            BriefState::Reading(changes) => changes.push(change),
            BriefState::Read(briefs) => {
                briefs.apply(change);
                #[cfg(test)]
                self.assert_briefs(briefs);
            }
        }
        Ok(())
    }

    /// Read the history's briefs again, as a hub does at start: after a test wrote the
    /// database as an older hub would have.
    #[cfg(test)]
    pub(super) fn reread_job_briefs(&self) {
        *self.write_briefs() = BriefState::Unread;
        self.read_job_briefs().unwrap();
    }

    /// The briefs kept are those the database holds now: checked on a test's history, not on
    /// a benchmark's, too long to read again at every page.
    #[cfg(test)]
    fn assert_briefs(&self, briefs: &Briefs) {
        if briefs.by_seq.len() > 10_000 {
            return;
        }
        let txn = self.db.begin_read().unwrap();
        let read = Briefs::read(&txn).unwrap();
        assert_eq!(
            read.by_seq, briefs.by_seq,
            "briefs out of step with the history"
        );
        assert_eq!(read.seq_of, briefs.seq_of);
    }

    /// Job `id`'s spec as submitted, redacted, unpacked; `None` once it has expired.
    pub fn job_spec(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOB_SPECS)?;
        let Some(spec) = table.get(id)? else {
            return Ok(None);
        };
        let dicts = txn.open_table(SPEC_DICTS)?;
        self.unpack_spec(&dicts, spec.value()).map(Some)
    }

    /// Keep the history to its newest `keep` jobs: past that count, the oldest finished jobs
    /// that were settled or expired go, record, spec and kept output ([`JOB_TAILS`]); a job
    /// its producer may still read stays. A finished job settled or finished more than
    /// [`JOB_KEEP`] before `now` expires: its spec goes, and so does its output file if it was
    /// never settled, but not its kept output. The IDs whose output files go: the jobs dropped
    /// and the jobs expired that still held output.
    ///
    /// Trimming drops at most [`TRIM_DROP`] jobs, and reads from the oldest job as far as
    /// that goes and at most [`TRIM_SCAN`] jobs past it; expiring, from
    /// [`EXPIRED_BELOW`] up to the first job submitted within [`JOB_KEEP`], since none
    /// submitted later can have ended before it.
    pub fn prune_jobs(&self, now: u64, keep: usize) -> Result<Pruned> {
        self.prune_jobs_scanning(now, keep, TRIM_DROP, TRIM_SCAN)
    }

    /// [`Db::prune_jobs`], dropping at most `drop` jobs and trimming past at most `scan`
    /// that cannot go yet.
    fn prune_jobs_scanning(&self, now: u64, keep: usize, drop: u64, scan: u64) -> Result<Pruned> {
        let past_keep = |t: u64| now.saturating_sub(t) > JOB_KEEP;
        let expires = |row: &JobRow| {
            row.state == JobState::Finished
                && row.settled_at.or(row.finished_at).is_some_and(past_keep)
        };
        let holds_output = |row: &JobRow| row.settled_at.is_none() && row.expired_at.is_none();
        let txn = self.db.begin_write().context("starting a write")?;
        let more;
        let mut unplaced = Vec::new();
        let outputs = {
            let mut table = txn.open_table(JOBS)?;
            let mut specs = txn.open_table(JOB_SPECS)?;
            let mut order = txn.open_table(JOB_ORDER)?;
            let mut meta = txn.open_table(JOB_META)?;
            let mut outputs = Vec::new();

            let over = order
                .len()?
                .saturating_sub(u64::try_from(keep).unwrap_or(u64::MAX));
            let mut excess = over.min(drop);
            let mut dropped = Vec::new();
            let mut budget = excess.saturating_add(scan);
            for entry in order.iter()? {
                if excess == 0 || budget == 0 {
                    break;
                }
                budget -= 1;
                let (seq, id) = entry?;
                let (seq, id) = (seq.value(), id.value().to_string());
                let Some(row) = table.get(id.as_str())? else {
                    excess = excess.saturating_sub(1);
                    unplaced.push(seq);
                    continue;
                };
                let row = decode::<JobRow>(row.value())?;
                if row.state == JobState::Finished && (row.settled_at.is_some() || expires(&row)) {
                    excess = excess.saturating_sub(1);
                    unplaced.push(seq);
                    if holds_output(&row) {
                        outputs.push(id.clone());
                    }
                    dropped.push((id, row));
                }
            }
            more = over > drop && excess == 0;
            for seq in &unplaced {
                order.remove(*seq)?;
            }
            let mut tails = txn.open_table(JOB_TAILS)?;
            let mut legacy = txn.open_table(LEGACY_TAILS)?;
            let mut lens = txn.open_table(JOB_TAIL_LENS)?;
            let mut uncached = HashMap::new();
            let mut uncounted: HashMap<&str, u64> = HashMap::new();
            let mut by_admission = txn.open_table(JOB_BY_ADMISSION)?;
            for (id, row) in &dropped {
                table.remove(id.as_str())?;
                if let Some(admission) = &row.admission {
                    by_admission.remove((row.key.as_str(), admission.as_str()))?;
                }
                super::egress::reshare(&txn, id, Some(row), None)?;
                super::observed::reshare(&txn, id, Some(row), None)?;
                let n = uncounted.entry(row.key.as_str()).or_default();
                *n = n.saturating_add(1);
                specs.remove(id.as_str())?;
                tails.remove(id.as_str())?;
                legacy.remove(id.as_str())?;
                if let Some(len) = lens.remove(id.as_str())? {
                    uncached.insert(id.as_str(), len.value());
                }
            }
            let mut counts = txn.open_table(JOB_COUNTS)?;
            for (key, gone) in uncounted {
                let left = (counts.get(key)?)
                    .map_or(0, |g| g.value())
                    .saturating_sub(gone);
                if left == 0 {
                    counts.remove(key)?;
                } else {
                    counts.insert(key, left)?;
                }
            }
            if !uncached.is_empty() {
                // A failed job's end is not in the cache: only what leaves it counts.
                let mut freed = 0u64;
                txn.open_table(JOB_CACHE)?
                    .retain(|_, id| match uncached.get(id) {
                        Some(len) => {
                            freed = freed.saturating_add(*len);
                            false
                        }
                        None => true,
                    })?;
                if freed > 0 {
                    let cached = meta.get(CACHED_BYTES)?.map_or(0, |g| g.value());
                    meta.insert(CACHED_BYTES, cached.saturating_sub(freed))?;
                }
            }

            let from = meta.get(EXPIRED_BELOW)?.map_or(0, |g| g.value());
            // `below` follows the expired jobs only up to the first that is not.
            let (mut below, mut contiguous, mut expired) = (from, true, Vec::new());
            for entry in order.range(from..)? {
                let (seq, id) = entry?;
                let (seq, id) = (seq.value(), id.value().to_string());
                let row = match table.get(id.as_str())? {
                    Some(row) => decode::<JobRow>(row.value())?,
                    // Its record is gone: nothing to expire.
                    None => {
                        if contiguous {
                            below = seq.saturating_add(1);
                        }
                        continue;
                    }
                };
                if !past_keep(row.created_at) {
                    break;
                }
                if row.expired_at.is_none() {
                    if !expires(&row) {
                        contiguous = false;
                        continue;
                    }
                    expired.push((id, row));
                }
                if contiguous {
                    below = seq.saturating_add(1);
                }
            }
            for (id, mut row) in expired {
                specs.remove(id.as_str())?;
                if holds_output(&row) {
                    outputs.push(id.clone());
                }
                row.expired_at = Some(now);
                table.insert(id.as_str(), encode(&row)?.as_slice())?;
            }
            if below != from {
                meta.insert(EXPIRED_BELOW, below)?;
            }
            outputs
        };
        self.commit_briefed(txn, BriefChange::Drop(unplaced))
            .context("pruning jobs")?;
        Ok(Pruned { outputs, more })
    }

    /// How many jobs' records the history keeps as set from the web UI; `None` when it was
    /// not, and `job_history` applies.
    pub fn job_history_set(&self) -> Result<Option<usize>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let meta = txn.open_table(JOB_META)?;
        let set = meta.get(HISTORY)?.map(|g| g.value());
        set.map(usize::try_from).transpose().map_err(Into::into)
    }

    /// Have the history keep `count` jobs' records, over `job_history`, or clear the count
    /// set (`None`), audited as `actor`'s; `cleared` says, for the audit, what then applies.
    pub fn set_job_history(
        &self,
        count: Option<usize>,
        cleared: &str,
        actor: &str,
        now: u64,
    ) -> Result<()> {
        let count = count.map(u64::try_from).transpose()?;
        if let Some(n) = count
            && !(1..=MAX_JOB_HISTORY).contains(&n)
        {
            bail!("the history keeps 1 to {MAX_JOB_HISTORY} jobs, not {n}");
        }
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut meta = txn.open_table(JOB_META)?;
            let event = match count {
                Some(n) => {
                    meta.insert(HISTORY, n)?;
                    format!("job history set to keep {n} jobs")
                }
                None => {
                    meta.remove(HISTORY)?;
                    format!("job history count cleared: {cleared}")
                }
            };
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("setting the job history")?;
        Ok(())
    }
}

#[cfg(test)]
impl Db {
    /// Write `rows` straight into the history, in order, each with its ID: a benchmark's
    /// fill, with no request, spec or count. The history's briefs are to read again.
    pub(crate) fn fill_history(
        &self,
        rows: impl IntoIterator<Item = (String, JobRow)>,
    ) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(JOBS)?;
            let mut order = txn.open_table(JOB_ORDER)?;
            let first = order.last()?.map_or(0, |(k, _)| k.value() + 1);
            for (seq, (id, row)) in (first..).zip(rows) {
                table.insert(id.as_str(), encode(&row)?.as_slice())?;
                order.insert(seq, id.as_str())?;
            }
        }
        txn.commit()?;
        *self.write_briefs() = BriefState::Unread;
        Ok(())
    }
}

/// The history's briefs being read ([`Db::read_job_briefs`]): a panic meanwhile would leave
/// them [`BriefState::Reading`] for good, so its unwinding marks them unread, to read again.
struct ReadingBriefs<'a>(&'a Db);

impl Drop for ReadingBriefs<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let mut held = self.0.write_briefs();
            if matches!(*held, BriefState::Reading(_)) {
                *held = BriefState::Unread;
            }
        }
    }
}

/// What a trim of the history ([`Db::prune_jobs`]) did.
#[derive(Debug, Default)]
pub struct Pruned {
    /// The IDs whose output files go.
    pub outputs: Vec<String>,
    /// It dropped as many jobs as one trim may and more are past the count: trim again.
    pub more: bool,
}

/// Retained tails and their bookkeeping within one write transaction.
struct Kept<'a, 't> {
    cache: &'a mut redb::Table<'t, u64, &'static str>,
    tails: &'a mut redb::Table<'t, &'static str, &'static [u8]>,
    legacy: &'a mut redb::Table<'t, &'static str, &'static [u8]>,
    lens: &'a mut redb::Table<'t, &'static str, u64>,
}

impl Kept<'_, '_> {
    /// Evict the oldest cache entries and their tails until their byte count, read from
    /// [`CACHED_BYTES`] in `meta`, is at most `total`. Return the remaining byte count.
    fn evict(&mut self, meta: &mut redb::Table<'_, &'static str, u64>, total: u64) -> Result<u64> {
        let mut cached = meta.get(CACHED_BYTES)?.map_or(0, |g| g.value());
        while cached > total {
            let Some(id) = (self.cache.pop_first()?).map(|(_, id)| id.value().to_string()) else {
                // [`index_job_cache`] keeps the count true; nothing is left to evict anyway.
                cached = 0;
                break;
            };
            self.tails.remove(id.as_str())?;
            self.legacy.remove(id.as_str())?;
            if let Some(len) = self.lens.remove(id.as_str())? {
                cached = cached.saturating_sub(len.value());
            }
        }
        Ok(cached)
    }
}

/// Rebuild [`JOB_CACHE`] and [`CACHED_BYTES`] from the ends kept, by their lengths as stored
/// ([`JOB_TAIL_LENS`]), packed or not, inside `txn`, after [`order_jobs`] dropped those of
/// missing records.
/// Run at every start: an older hub may have dropped records, and with them cached ends,
/// without knowing of the cache. An entry whose end is gone, or whose job failed, goes; an end
/// of a job that did not fail and is not in the cache joins its newest end.
pub(super) fn index_job_cache(txn: &redb::WriteTransaction) -> Result<()> {
    let mut cache = txn.open_table(JOB_CACHE)?;
    let lens = txn.open_table(JOB_TAIL_LENS)?;
    let table = txn.open_table(JOBS)?;
    // A record that does not decode is taken for failed: its end stays with it.
    let cacheable = |id: &str| -> Result<bool> {
        Ok(table.get(id)?.is_some_and(|row| {
            decode::<JobRow>(row.value()).is_ok_and(|r| r.outcome() != JobOutcome::Failed)
        }))
    };
    let (mut seen, mut gone, mut cached) = (HashSet::new(), Vec::new(), 0u64);
    for entry in cache.iter()? {
        let (seq, id) = entry?;
        let id = id.value().to_string();
        match lens.get(id.as_str())? {
            Some(len) if !seen.contains(&id) && cacheable(&id)? => {
                cached = cached.saturating_add(len.value());
                seen.insert(id);
            }
            _ => gone.push(seq.value()),
        }
    }
    for seq in gone {
        cache.remove(seq)?;
    }
    // In the order of their IDs: which of them was kept first is not known.
    let mut join = Vec::new();
    for entry in lens.iter()? {
        let (id, len) = entry?;
        if !seen.contains(id.value()) && cacheable(id.value())? {
            cached = cached.saturating_add(len.value());
            join.push(id.value().to_string());
        }
    }
    let next = cache
        .last()?
        .map_or(0, |(k, _)| k.value().saturating_add(1));
    for (seq, id) in (next..).zip(&join) {
        cache.insert(seq, id.as_str())?;
    }
    txn.open_table(JOB_META)?.insert(CACHED_BYTES, cached)?;
    Ok(())
}

/// Fill [`JOB_TAIL_LENS`] in from [`LEGACY_TAILS`] and [`JOB_TAILS`], once, inside `txn`: the
/// one start that reads every end kept.
fn fill_tail_lens(txn: &redb::WriteTransaction) -> Result<()> {
    let mut meta = txn.open_table(JOB_META)?;
    if meta.get(TAIL_LENS)?.is_some() {
        return Ok(());
    }
    let mut lens = txn.open_table(JOB_TAIL_LENS)?;
    // A packed end wins over a legacy one, as it does when read.
    for table in [LEGACY_TAILS, JOB_TAILS] {
        for entry in txn.open_table(table)?.iter()? {
            let (id, tail) = entry?;
            lens.insert(id.value(), tail.value().len() as u64)?;
        }
    }
    meta.insert(TAIL_LENS, 1)?;
    Ok(())
}

/// Fill [`JOB_COUNTS`] in from [`JOBS`], inside `txn`, when it is empty and the history is not:
/// a database a build without the counts wrote. Only each record's key is decoded; one that
/// does not decode is not counted, as the history's pages leave it out. A build without the
/// counts adding or dropping jobs later (a dev downgrade) leaves them off by as many.
pub(super) fn count_jobs(txn: &redb::WriteTransaction) -> Result<()> {
    /// A record's submitter alone: the rest is skipped, not decoded.
    #[derive(Deserialize)]
    struct Submitter {
        key: String,
    }
    let mut counts = txn.open_table(JOB_COUNTS)?;
    let table = txn.open_table(JOBS)?;
    if !counts.is_empty()? || table.is_empty()? {
        return Ok(());
    }
    let mut by_key: HashMap<String, u64> = HashMap::new();
    for entry in table.iter()? {
        let Ok(job) = decode::<Submitter>(entry?.1.value()) else {
            continue;
        };
        let n = by_key.entry(job.key).or_default();
        *n = n.saturating_add(1);
    }
    for (key, n) in &by_key {
        counts.insert(key.as_str(), *n)?;
    }
    Ok(())
}

/// The next sequence in `order`, past the newest and at least [`EXPIRED_BELOW`],
/// so jobs added after rebuilding the order are not mistaken for expired jobs.
fn next_seq(
    order: &impl ReadableTable<u64, &'static str>,
    meta: &impl ReadableTable<&'static str, u64>,
) -> Result<u64> {
    let next = order
        .last()?
        .map_or(0, |(k, _)| k.value().saturating_add(1));
    let floor = meta.get(EXPIRED_BELOW)?.map_or(0, |g| g.value());
    Ok(next.max(floor))
}

/// Append unindexed jobs in submission order and remove entries, and kept output, for
/// missing records, inside `txn`. Run at every start: an older hub may have added or removed
/// jobs, either before the index existed or since this hub last ran.
pub(super) fn order_jobs(txn: &redb::WriteTransaction) -> Result<()> {
    fill_tail_lens(txn)?;
    let mut order = txn.open_table(JOB_ORDER)?;
    let table = txn.open_table(JOBS)?;
    let mut tails = txn.open_table(JOB_TAILS)?;
    let mut legacy = txn.open_table(LEGACY_TAILS)?;
    let mut lens = txn.open_table(JOB_TAIL_LENS)?;
    // By their lengths alone: no end is read.
    let mut orphans = Vec::new();
    for entry in lens.iter()? {
        let id = entry?.0.value().to_string();
        if table.get(id.as_str())?.is_none() {
            orphans.push(id);
        }
    }
    for id in orphans {
        tails.remove(id.as_str())?;
        legacy.remove(id.as_str())?;
        lens.remove(id.as_str())?;
    }
    let (mut placed, mut gone) = (HashSet::new(), Vec::new());
    for entry in order.iter()? {
        let (seq, id) = entry?;
        if table.get(id.value())?.is_some() {
            placed.insert(id.value().to_string());
        } else {
            gone.push(seq.value());
        }
    }
    for seq in gone {
        order.remove(seq)?;
    }
    let mut jobs = Vec::new();
    for entry in table.iter()? {
        let (id, row) = entry?;
        if placed.contains(id.value()) {
            continue;
        }
        // One that does not decode is placed first among them, as the oldest, rather than
        // failing the hub's start.
        let at = decode::<JobRow>(row.value()).map_or(0, |r| r.created_at);
        jobs.push((at, id.value().to_string()));
    }
    jobs.sort();
    let next = next_seq(&order, &txn.open_table(JOB_META)?)?;
    for (seq, (_, id)) in (next..).zip(&jobs) {
        order.insert(seq, id.as_str())?;
    }
    Ok(())
}

/// Drop requests past [`REQUEST_KEEP`], at most once every [`REQUEST_SWEEP_SECS`].
pub(super) fn sweep_requests(
    db: &Db,
    requests: &mut redb::Table<'_, &str, &[u8]>,
    now: u64,
) -> Result<()> {
    let last = db.requests_swept_at.load(Ordering::Relaxed);
    if now.saturating_sub(last) < REQUEST_SWEEP_SECS {
        return Ok(());
    }
    db.requests_swept_at.store(now, Ordering::Relaxed);
    requests.retain(|_, value| {
        decode::<RequestRow>(value).is_ok_and(|r| now.saturating_sub(r.at) < REQUEST_KEEP)
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Older records decode without registry access; unknown kinds and reasons from later
    /// hubs decode to fallback variants.
    #[test]
    fn registry_access_decodes_from_older_and_later_hubs() {
        let mut row = serde_json::to_value(row(1)).unwrap();
        row.as_object_mut().unwrap().remove("registry_access");
        let old: JobRow = serde_json::from_value(row.clone()).unwrap();
        assert_eq!(old.registry_access, None);
        row["registry_access"] = serde_json::json!({"kind": "delegated", "to": "x"});
        let later: JobRow = serde_json::from_value(row.clone()).unwrap();
        assert_eq!(later.registry_access, Some(RegistryAccess::Unknown));
        row["registry_access"] = serde_json::json!({"kind": "none", "reason": "quota"});
        let later: JobRow = serde_json::from_value(row).unwrap();
        assert_eq!(
            later.registry_access,
            Some(RegistryAccess::None {
                reason: NoAccess::Other,
                registry: None,
                url: None,
            })
        );
    }
    use vk_hub_proto::job::{Envelope, FailureClass};

    fn row(revision: u64) -> JobRow {
        JobRow {
            key: "k".into(),
            key_name: "gitlab".into(),
            instance: None,
            request_id: "1".repeat(32),
            scheduling: None,
            admission: None,
            placement: Placement {
                pool: "ci".into(),
                labels: vec![],
                envelope: Envelope::default(),
            },
            title: "gitlab job 7".into(),
            job_url: None,
            project: None,
            name: None,
            git_ref: None,
            pipeline: None,
            created_at: 10,
            state: JobState::Queued,
            revision,
            node: None,
            stage: None,
            cancel: None,
            result: None,
            output_len: 0,
            started_at: None,
            finished_at: None,
            settled_at: None,
            expired_at: None,
            commit: None,
            activity: None,
            prepared_at: None,
            guest: None,
            registry_access: None,
            gitlab: None,
            project_id: None,
            protected: None,
            egress_rules: None,
            egress_caps: None,
            egress: None,
        }
    }

    #[test]
    fn scheduling_identity_survives_storage_and_older_jobs_decode_without_it() {
        let db = Db::open_memory().unwrap();
        let id = "a".repeat(32);
        let mut job = row(1);
        job.scheduling = Some(SchedulingIdentity {
            tenant: "project".into(),
            class: crate::policy::Class::Production,
            gitlab: Some("gl".into()),
            runner_id: Some(42),
        });
        job.admission = Some("b".repeat(32));
        db.submit_job(&id, &job, "digest", b"{}", "relay", 10)
            .unwrap();
        assert_eq!(db.job(&id).unwrap(), Some(job.clone()));
        let mut json = serde_json::to_value(&job).unwrap();
        json.as_object_mut().unwrap().remove("scheduling");
        json.as_object_mut().unwrap().remove("admission");
        let older: JobRow = serde_json::from_value(json).unwrap();
        assert_eq!(older.scheduling, None);
        assert_eq!(older.admission, None);
        assert_eq!(older.key, job.key);
    }

    #[test]
    fn an_admission_takes_one_job() {
        let db = Db::open_memory().unwrap();
        let mut first = job(1, JobState::Queued, None);
        first.admission = Some("admission".into());
        submit(&db, 1, &first);
        // Another job naming the same admission is refused, and recorded nowhere.
        let mut second = job(2, JobState::Queued, None);
        second.admission = first.admission.clone();
        let again = db.submit_job(&id(2), &second, "2", b"{}", "key gitlab", 2);
        assert!(matches!(again.unwrap(), Submitted::AdmissionTaken));
        assert!(db.job(&id(2)).unwrap().is_none());
        assert!(db.job_spec(&id(2)).unwrap().is_none());
        assert!(
            db.request(&second.key, &second.request_id, 2)
                .unwrap()
                .is_none()
        );
        assert_eq!(listed(&db), vec![id(1)]);
        // Another principal's admission of the same ID is its own.
        let mut other = job(3, JobState::Queued, None);
        other.key = "other".into();
        other.admission = first.admission.clone();
        submit(&db, 3, &other);
    }

    #[test]
    fn a_submission_is_recorded_once_and_a_reused_id_with_another_body_conflicts() {
        let db = Db::open_memory().unwrap();
        let id = "a".repeat(32);
        assert!(matches!(
            db.submit_job(&id, &row(1), "d1", b"{}", "key gitlab", 10)
                .unwrap(),
            Submitted::New
        ));
        match db
            .submit_job(&"b".repeat(32), &row(1), "d1", b"{}", "key gitlab", 11)
            .unwrap()
        {
            Submitted::Again(again) => assert_eq!(again, id),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            db.submit_job(&"b".repeat(32), &row(1), "d2", b"{}", "key gitlab", 11)
                .unwrap(),
            Submitted::Conflict
        ));
        // A day on, the ID is free again.
        assert!(matches!(
            db.submit_job(
                &"c".repeat(32),
                &row(1),
                "d2",
                b"{}",
                "key gitlab",
                10 + REQUEST_KEEP
            )
            .unwrap(),
            Submitted::New
        ));
        assert_eq!(db.job_spec(&id).unwrap().unwrap(), b"{}");
    }

    #[test]
    fn an_older_revision_does_not_overwrite_a_newer() {
        let db = Db::open_memory().unwrap();
        let id = "a".repeat(32);
        db.submit_job(&id, &row(1), "d", b"{}", "key gitlab", 10)
            .unwrap();
        assert!(db.put_job(&id, &row(3), &[], 11).unwrap());
        // Overtaken, it still audits what it carries.
        let event = (None, "hub".to_string(), format!("job {id} ended"));
        assert!(
            !db.put_job(&id, &row(2), std::slice::from_ref(&event), 12)
                .unwrap()
        );
        assert_eq!(db.job(&id).unwrap().unwrap().revision, 3);
        let audit = db.audits(None, 10).unwrap();
        assert_eq!(
            audit.iter().filter(|r| r.event == event.2).count(),
            1,
            "{audit:?}"
        );
        // Gone from the history, as well.
        let gone = "b".repeat(32);
        let event = (None, "hub".to_string(), format!("job {gone} ended"));
        assert!(
            !db.put_job(&gone, &row(2), std::slice::from_ref(&event), 13)
                .unwrap()
        );
        assert!(db.job(&gone).unwrap().is_none());
        assert!(
            db.audits(None, 10)
                .unwrap()
                .iter()
                .any(|r| r.event == event.2)
        );
        let mut finished = row(4);
        finished.state = JobState::Finished;
        finished.finished_at = Some(20);
        db.put_job(&id, &finished, &[], 20).unwrap();
        assert!(db.unfinished_jobs().unwrap().is_empty());
        assert!(db.prune_jobs(20 + JOB_KEEP, 10).unwrap().outputs.is_empty());
        // Unsettled past its keep: its output and spec go, its record stays in the history.
        assert_eq!(
            db.prune_jobs(21 + JOB_KEEP, 10).unwrap().outputs,
            std::slice::from_ref(&id)
        );
        let expired = db.job(&id).unwrap().unwrap();
        assert_eq!(
            (expired.revision, expired.expired_at),
            (4, Some(21 + JOB_KEEP))
        );
        assert!(db.job_spec(&id).unwrap().is_none());
    }

    /// Job `n` of a history in `state`: submitted at `n`, on node `a…` or `b…` by parity, of
    /// project `p<n % 3>`, started at once and, finished, ended by `failure` `n` seconds on.
    fn job(n: u64, state: JobState, failure: Option<FailureClass>) -> JobRow {
        let mut row = row(1);
        row.request_id = format!("{n:032}");
        row.created_at = n;
        row.project = Some(format!("p{}", n % 3));
        row.node = Some(if n.is_multiple_of(2) { "a" } else { "b" }.repeat(32));
        row.state = state;
        if state == JobState::Queued {
            return row;
        }
        row.started_at = Some(n);
        if state != JobState::Finished {
            row.stage = Some("step_script".into());
            return row;
        }
        row.finished_at = Some(n + n);
        row.result = Some(JobResult {
            failure,
            exit_code: None,
            message: None,
            output_len: 0,
            artifacts: Vec::new(),
            usage: None,
            events: Vec::new(),
            egress: None,
        });
        row
    }

    /// Job `n`, finished and settled by its producer as it finished.
    fn settled(n: u64) -> JobRow {
        let mut row = job(n, JobState::Finished, None);
        row.settled_at = row.finished_at;
        row
    }

    fn id(n: u64) -> String {
        format!("{n:032x}")
    }

    fn submit(db: &Db, n: u64, row: &JobRow) {
        let digest = n.to_string();
        let new = db.submit_job(&id(n), row, &digest, b"{}", "key gitlab", n);
        assert!(matches!(new.unwrap(), Submitted::New));
    }

    fn listed(db: &Db) -> Vec<String> {
        db.jobs(100).unwrap().into_iter().map(|j| j.0).collect()
    }

    fn placed(db: &Db) -> u64 {
        let txn = db.db.begin_read().unwrap();
        txn.open_table(JOB_ORDER).unwrap().len().unwrap()
    }

    fn expired_below(db: &Db) -> Option<u64> {
        let txn = db.db.begin_read().unwrap();
        let meta = txn.open_table(JOB_META).unwrap();
        meta.get(EXPIRED_BELOW).unwrap().map(|g| g.value())
    }

    /// A failed job's kept output lives as long as its record: past its keep it stays, dropped
    /// from the history it goes, and none is kept for a job not in it.
    #[test]
    fn kept_output_goes_with_its_record() {
        let db = Db::open_memory().unwrap();
        let mut failed = job(1, JobState::Finished, Some(FailureClass::Script));
        failed.settled_at = failed.finished_at;
        submit(&db, 1, &failed);
        submit(&db, 2, &settled(2));
        assert!(db.keep_job_tail(&id(1), b"error: boom\n").unwrap());
        assert!(!db.keep_job_tail(&id(9), b"x").unwrap());
        assert_eq!(db.job_tail(&id(9)).unwrap(), None);
        // Expired, the record stays and so does what was kept of its output.
        db.prune_jobs(3 + JOB_KEEP, 10).unwrap();
        assert!(db.job(&id(1)).unwrap().unwrap().expired_at.is_some());
        assert_eq!(
            db.job_tail(&id(1)).unwrap().as_deref(),
            Some(&b"error: boom\n"[..])
        );
        db.prune_jobs(3 + JOB_KEEP, 1).unwrap();
        assert_eq!(listed(&db), [id(2)]);
        assert_eq!(db.job_tail(&id(1)).unwrap(), None);
    }

    /// The jobs in the output cache, oldest first, and the bytes it counts.
    fn cache(db: &Db) -> (Vec<String>, u64) {
        let txn = db.db.begin_read().unwrap();
        let cache = txn.open_table(JOB_CACHE).unwrap();
        let ids = cache
            .iter()
            .unwrap()
            .map(|e| e.unwrap().1.value().to_string());
        let meta = txn.open_table(JOB_META).unwrap();
        let bytes = meta.get(CACHED_BYTES).unwrap().map_or(0, |g| g.value());
        (ids.collect(), bytes)
    }

    fn failed_settled(n: u64) -> JobRow {
        let mut row = job(n, JobState::Finished, Some(FailureClass::Script));
        row.settled_at = row.finished_at;
        row
    }

    /// The ends of jobs that did not fail are kept within the cache's total, the oldest kept
    /// evicted first; a failed job's end is outside it and stays. Each is counted as stored:
    /// too short to compress, with its format's byte.
    #[test]
    fn the_output_cache_keeps_within_its_total_evicting_the_oldest() {
        let db = Db::open_memory().unwrap();
        for n in 1..=4 {
            submit(&db, n, &settled(n));
        }
        submit(&db, 5, &failed_settled(5));
        assert!(db.keep_job_tail(&id(5), b"boom\n").unwrap());
        assert!(db.cache_job_tail(&id(1), b"one\n", 10).unwrap());
        assert!(db.cache_job_tail(&id(2), b"two\n", 10).unwrap());
        assert_eq!(cache(&db), (vec![id(1), id(2)], 10));
        assert!(db.cache_job_tail(&id(3), b"six\n", 10).unwrap());
        assert_eq!(cache(&db), (vec![id(2), id(3)], 10));
        assert_eq!(db.job_tail(&id(1)).unwrap(), None);
        // Over the total alone, or not in the history: not kept, and nothing evicted.
        assert!(!db.cache_job_tail(&id(4), b"elevenbytes", 10).unwrap());
        assert!(!db.cache_job_tail(&id(9), b"x", 10).unwrap());
        assert!(!db.cache_job_tail(&id(4), b"x", 0).unwrap());
        assert_eq!(db.job_tail(&id(4)).unwrap(), None);
        // Kept again, as a settle retried after a stop does: it stays as it was.
        assert!(db.cache_job_tail(&id(2), b"other\n", 10).unwrap());
        assert_eq!(db.job_tail(&id(2)).unwrap().as_deref(), Some(&b"two\n"[..]));
        assert_eq!(cache(&db), (vec![id(2), id(3)], 10));
        // A total lowered evicts down to it.
        db.fit_job_cache(5).unwrap();
        assert_eq!(cache(&db), (vec![id(3)], 5));
        db.fit_job_cache(0).unwrap();
        assert_eq!(cache(&db), (vec![], 0));
        assert_eq!(db.job_tail(&id(3)).unwrap(), None);
        assert_eq!(
            db.job_tail(&id(5)).unwrap().as_deref(),
            Some(&b"boom\n"[..])
        );
    }

    /// A job dropped from the history takes its cached end with it, and the cache counts it
    /// gone; a failed job's end dropped likewise leaves the count alone.
    #[test]
    fn a_cached_end_goes_with_its_record() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &settled(1));
        submit(&db, 2, &failed_settled(2));
        submit(&db, 3, &settled(3));
        assert!(db.cache_job_tail(&id(1), b"one\n", 100).unwrap());
        assert!(db.keep_job_tail(&id(2), b"boom\n").unwrap());
        assert!(db.cache_job_tail(&id(3), b"three\n", 100).unwrap());
        db.prune_jobs(4, 1).unwrap();
        assert_eq!(listed(&db), [id(3)]);
        assert_eq!(db.job_tail(&id(1)).unwrap(), None);
        assert_eq!(db.job_tail(&id(2)).unwrap(), None);
        assert_eq!(cache(&db), (vec![id(3)], 7));
        db.prune_jobs(4, 0).unwrap();
        assert_eq!(cache(&db), (vec![], 0));
    }

    /// At start the cache is rebuilt from the ends kept: entries whose end an older hub
    /// dropped with its record go, an end of a job that did not fail joins it, and the count
    /// is what is left, as stored, packed or not.
    #[test]
    fn the_output_cache_is_rebuilt_at_start() {
        let db = Db::open_memory().unwrap();
        for n in 1..=3 {
            submit(&db, n, &settled(n));
        }
        submit(&db, 4, &failed_settled(4));
        assert!(db.cache_job_tail(&id(1), b"one\n", 100).unwrap());
        assert!(db.cache_job_tail(&id(2), b"two!\n", 100).unwrap());
        assert!(db.keep_job_tail(&id(4), b"boom\n").unwrap());
        let txn = db.db.begin_write().unwrap();
        {
            // An older hub dropped job 1's record, unaware of its end and of the cache.
            txn.open_table(JOBS)
                .unwrap()
                .remove(id(1).as_str())
                .unwrap();
            // An uncached legacy tail and a duplicate cache entry.
            txn.open_table(LEGACY_TAILS)
                .unwrap()
                .insert(id(3).as_str(), &b"three\n"[..])
                .unwrap();
            txn.open_table(JOB_TAIL_LENS)
                .unwrap()
                .insert(id(3).as_str(), 6)
                .unwrap();
            txn.open_table(JOB_CACHE)
                .unwrap()
                .insert(9, id(2).as_str())
                .unwrap();
            txn.open_table(JOB_META)
                .unwrap()
                .insert(CACHED_BYTES, 999)
                .unwrap();
        }
        order_jobs(&txn).unwrap();
        index_job_cache(&txn).unwrap();
        txn.commit().unwrap();
        db.reread_job_briefs();
        assert_eq!(cache(&db), (vec![id(2), id(3)], 12));
        assert_eq!(db.job_tail(&id(1)).unwrap(), None);
        assert_eq!(
            db.job_tail(&id(3)).unwrap().as_deref(),
            Some(&b"three\n"[..])
        );
        assert_eq!(
            db.job_tail(&id(4)).unwrap().as_deref(),
            Some(&b"boom\n"[..])
        );

        // A database from before the cache: every end of a job that did not fail joins it.
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(JOB_CACHE).unwrap();
        index_job_cache(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(cache(&db), (vec![id(2), id(3)], 12));
        // Rebuilt, it evicts as before.
        submit(&db, 5, &settled(5));
        assert!(db.cache_job_tail(&id(5), b"five\n", 12).unwrap());
        assert_eq!(cache(&db), (vec![id(3), id(5)], 12));
        assert_eq!(db.job_tail(&id(2)).unwrap(), None);
    }

    /// The ends' lengths as stored, kept beside them, are what the cache reckons with; a
    /// database without them has them filled in once, from the ends, at start.
    #[test]
    fn the_ends_lengths_are_kept_beside_them() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &settled(1));
        submit(&db, 2, &failed_settled(2));
        assert!(db.cache_job_tail(&id(1), b"one\n", 100).unwrap());
        assert!(db.keep_job_tail(&id(2), b"boom!\n").unwrap());
        let lens = |db: &Db| -> Vec<(String, u64)> {
            let txn = db.db.begin_read().unwrap();
            let lens = txn.open_table(JOB_TAIL_LENS).unwrap();
            (lens.iter().unwrap())
                .map(|e| e.unwrap())
                .map(|(k, v)| (k.value().to_string(), v.value()))
                .collect()
        };
        assert_eq!(lens(&db), [(id(1), 5), (id(2), 7)]);
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(JOB_TAIL_LENS).unwrap();
        txn.open_table(JOB_META).unwrap().remove(TAIL_LENS).unwrap();
        order_jobs(&txn).unwrap();
        index_job_cache(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(lens(&db), [(id(1), 5), (id(2), 7)]);
        assert_eq!(cache(&db), (vec![id(1)], 5));
        // Pruned, an end goes with its length.
        db.prune_jobs(4, 0).unwrap();
        assert_eq!(lens(&db), []);
        assert_eq!(cache(&db), (vec![], 0));
    }

    /// The cache and its count outlast the hub: reopened, the database holds them as they were.
    #[test]
    fn the_output_cache_survives_a_reopen() {
        let dir = std::env::temp_dir().join(format!("vk-hub-cache-{}", std::process::id()));
        // Absent on a first run.
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("hub.db");
        let db = Db::open(&path).unwrap();
        for n in 1..=2 {
            submit(&db, n, &settled(n));
        }
        assert!(db.cache_job_tail(&id(1), b"one\n", 100).unwrap());
        assert!(db.cache_job_tail(&id(2), b"two\n", 100).unwrap());
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(cache(&db), (vec![id(1), id(2)], 10));
        assert!(db.cache_job_tail(&id(1), b"one\n", 10).unwrap());
        assert_eq!(cache(&db), (vec![id(1), id(2)], 10));
        drop(db);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Past its count, the history drops its oldest settled or expired jobs, record and spec,
    /// and keeps one still running, or one finished its producer may still read, however old.
    #[test]
    fn the_history_keeps_its_newest_jobs() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &job(1, JobState::Running, None));
        submit(&db, 2, &settled(2));
        submit(&db, 3, &job(3, JobState::Finished, None));
        for n in 4..=10 {
            submit(&db, n, &settled(n));
        }
        // Settled, the dropped jobs held no output.
        assert!(db.prune_jobs(11, 6).unwrap().outputs.is_empty());
        assert_eq!(listed(&db), [10, 9, 8, 7, 3, 1].map(id));
        assert!(db.job_spec(&id(2)).unwrap().is_none());
        assert!(db.job_spec(&id(7)).unwrap().is_some());
        assert!(db.prune_jobs(11, 6).unwrap().outputs.is_empty());
        assert_eq!(placed(&db), 6);
        // Past its keep, the unsettled one goes, its output with it.
        assert_eq!(db.prune_jobs(7 + JOB_KEEP, 5).unwrap().outputs, [id(3)]);
        assert_eq!(listed(&db), [10, 9, 8, 7, 1].map(id));
        // Once it finishes and is settled, the running one goes first.
        let mut done = settled(1);
        done.revision = 2;
        assert!(db.put_job(&id(1), &done, &[], 12).unwrap());
        assert!(db.prune_jobs(12, 4).unwrap().outputs.is_empty());
        assert_eq!(listed(&db), [10, 9, 8, 7].map(id));
    }

    /// A job's write that lands after the trim dropped it does not bring the job back.
    #[test]
    fn a_write_racing_the_trim_does_not_bring_a_job_back() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &settled(1));
        assert!(db.prune_jobs(3, 0).unwrap().outputs.is_empty());
        let mut late = settled(1);
        late.revision = 2;
        assert!(!db.put_job(&id(1), &late, &[], 4).unwrap());
        assert!(db.job(&id(1)).unwrap().is_none());
        assert!(listed(&db).is_empty());
        assert_eq!(placed(&db), 0);
    }

    /// A finished job expires once, past its keep: its spec goes, its output too if it was
    /// never settled, and later passes start past every job expired in a row.
    #[test]
    fn a_job_past_its_keep_expires_once() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &job(1, JobState::Finished, None));
        submit(&db, 2, &job(2, JobState::Running, None));
        submit(&db, 3, &settled(3));
        submit(&db, 4, &job(4, JobState::Finished, None));
        let now = 10 + JOB_KEEP;
        let mut outputs = db.prune_jobs(now, 100).unwrap().outputs;
        outputs.sort();
        assert_eq!(outputs, [id(1), id(4)]);
        for n in [1, 3, 4] {
            assert_eq!(db.job(&id(n)).unwrap().unwrap().expired_at, Some(now));
            assert!(db.job_spec(&id(n)).unwrap().is_none());
        }
        assert!(db.job_spec(&id(2)).unwrap().is_some());
        assert_eq!(expired_below(&db), Some(1));
        assert!(db.prune_jobs(now + 1, 100).unwrap().outputs.is_empty());
        // A write prepared before it expired leaves it expired.
        let mut late = job(1, JobState::Finished, None);
        late.revision = 2;
        assert!(db.put_job(&id(1), &late, &[], now + 1).unwrap());
        assert_eq!(db.job(&id(1)).unwrap().unwrap().expired_at, Some(now));
        // The running one ends; past its keep, it expires and the mark passes every job.
        let mut done = settled(2);
        done.revision = 2;
        done.finished_at = Some(now);
        done.settled_at = Some(now);
        assert!(db.put_job(&id(2), &done, &[], now).unwrap());
        assert!(
            db.prune_jobs(now + JOB_KEEP + 1, 100)
                .unwrap()
                .outputs
                .is_empty()
        );
        assert!(db.job_spec(&id(2)).unwrap().is_none());
        assert_eq!(expired_below(&db), Some(4));
        assert_eq!(listed(&db), [4, 3, 2, 1].map(id));
    }

    /// A page is newest first, filtered on every field set, continues before the last one
    /// shown, and sums up every job the filter matches.
    #[test]
    fn a_history_page_is_filtered_and_continues() {
        let db = Db::open_memory().unwrap();
        let failures = [
            None,
            Some(FailureClass::Script),
            Some(FailureClass::Canceled),
        ];
        for n in 1..=11 {
            let failure = failures[(n % 3) as usize];
            submit(&db, n, &job(n, JobState::Finished, failure));
        }
        submit(&db, 12, &job(12, JobState::Running, None));
        let all = JobFilter::default();
        let page = db.job_page(&all, None, 5).unwrap();
        let ids = |page: &JobPage| page.rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&page), [12, 11, 10, 9, 8].map(id));
        assert_eq!(page.older, Some(page.rows[4].0));
        assert_eq!(page.projects, ["p0", "p1", "p2"]);
        assert_eq!(
            page.summary,
            JobSummary {
                matched: 12,
                finished: 11,
                succeeded: 3,
                // n seconds each, 1 to 11.
                median_ms: Some(6000),
            }
        );
        let next = db.job_page(&all, Some(page.rows[4].0), 5).unwrap();
        assert_eq!(ids(&next), [7, 6, 5, 4, 3].map(id));
        let last = db.job_page(&all, Some(next.rows[4].0), 5).unwrap();
        assert_eq!(ids(&last), [2, 1].map(id));
        assert_eq!(last.older, None);

        // Project p0 is jobs 3, 6, 9 and 12; on node a…, 6 and 12.
        let filter = JobFilter {
            node: Some("a".repeat(32)),
            project: Some("p0".into()),
            ..JobFilter::default()
        };
        assert_eq!(
            ids(&db.job_page(&filter, None, 5).unwrap()),
            [12, 6].map(id)
        );
        let failed = JobFilter {
            outcome: Some(JobOutcome::Failed),
            ..JobFilter::default()
        };
        let page = db.job_page(&failed, None, 5).unwrap();
        assert_eq!(ids(&page), [10, 7, 4, 1].map(id));
        assert_eq!((page.summary.matched, page.summary.succeeded), (4, 0));
        let page = db.job_page(&failed, None, 2).unwrap();
        assert_eq!(ids(&page), [10, 7].map(id));
        let next = db.job_page(&failed, page.older, 2).unwrap();
        assert_eq!(ids(&next), [4, 1].map(id));
        assert_eq!((next.older, next.summary.matched), (None, 4));
        let past = db.job_page(&failed, Some(next.rows[1].0), 2).unwrap();
        assert!(past.rows.is_empty());
        assert_eq!((past.older, past.summary.matched), (None, 4));
        let running = JobFilter {
            outcome: Some(JobOutcome::Running),
            ..JobFilter::default()
        };
        let page = db.job_page(&running, None, 5).unwrap();
        assert_eq!(ids(&page), [id(12)]);
        assert_eq!(page.summary.median_ms, None);
        // Running for 88 seconds of the hub's clock.
        assert_eq!(page.rows[0].2.ran_ms(100), Some(88_000));

        // Prepared from 12 to 30: the job's own time starts there.
        let mut prepared = page.rows[0].2.clone();
        prepared.prepared_at = Some(30);
        assert_eq!(prepared.prepare_ms(100), Some(18_000));
        assert_eq!(prepared.ran_ms(100), Some(70_000));
        assert_eq!(prepared.running_since(), Some(30));
        assert_eq!(prepared.preparing_since(), None);
        // Still preparing: no run yet, its preparation counting on.
        let mut preparing = prepared.clone();
        preparing.prepared_at = None;
        preparing.stage = Some(PREPARE_STAGE.into());
        assert_eq!(preparing.ran_ms(100), None);
        assert_eq!(preparing.prepare_ms(100), Some(88_000));
        assert_eq!(
            (preparing.running_since(), preparing.preparing_since()),
            (None, Some(12))
        );
        // Cleaning up after preparing failed: preparing still.
        let mut cleaning = preparing.clone();
        cleaning.stage = Some("cleanup".into());
        assert_eq!(
            (cleaning.prepare_ms(100), cleaning.ran_ms(100)),
            (Some(88_000), None)
        );
        // Lost while preparing, nothing measured: all of its time was preparing.
        let mut lost = preparing.clone();
        lost.state = JobState::Finished;
        lost.finished_at = Some(50);
        lost.result = Some(JobResult {
            failure: Some(FailureClass::Lost),
            exit_code: None,
            message: None,
            output_len: 0,
            artifacts: Vec::new(),
            usage: None,
            events: Vec::new(),
            egress: None,
        });
        assert_eq!(
            (lost.prepare_ms(100), lost.ran_ms(100)),
            (Some(38_000), None)
        );
        // Ended: the node's measurement splits its wall time.
        let mut ended = prepared;
        ended.state = JobState::Finished;
        ended.result = Some(JobResult {
            failure: None,
            exit_code: Some(0),
            message: None,
            output_len: 0,
            artifacts: Vec::new(),
            usage: Some(vk_hub_proto::job::JobUsage {
                wall_ms: 90_000,
                prepare_ms: Some(20_000),
                ..Default::default()
            }),
            events: Vec::new(),
            egress: None,
        });
        assert_eq!(
            (ended.prepare_ms(100), ended.ran_ms(100)),
            (Some(20_000), Some(70_000))
        );
        // From an older node, none: the hub's, from the stages it was told, splits it.
        let older = |prepared_at| {
            let mut row = ended.clone();
            row.prepared_at = prepared_at;
            if let Some(usage) = row.result.as_mut().and_then(|r| r.usage.as_mut()) {
                usage.prepare_ms = None;
            }
            (row.prepare_ms(100), row.ran_ms(100))
        };
        assert_eq!(older(Some(30)), (Some(18_000), Some(72_000)));
        // Nor a stage past preparing seen: one time.
        assert_eq!(older(None), (None, Some(90_000)));

        // A row that does not decode is left out.
        let txn = db.db.begin_write().unwrap();
        txn.open_table(JOBS)
            .unwrap()
            .insert(id(5).as_str(), b"not json".as_slice())
            .unwrap();
        txn.commit().unwrap();
        db.reread_job_briefs();
        let page = db.job_page(&all, None, 20).unwrap();
        assert_eq!(page.rows.len(), 11);
        assert!(!ids(&page).contains(&id(5)));
    }

    /// Name and branch match substrings ignoring ASCII case; pipeline matches exactly.
    /// Older records without these fields match none of their filters.
    #[test]
    fn a_history_page_is_filtered_by_name_branch_and_pipeline() {
        let db = Db::open_memory().unwrap();
        let mut older = job(1, JobState::Finished, None);
        older.name = None;
        submit(&db, 1, &older);
        for (n, name, git_ref, pipeline) in [
            (2, "build-x86", "main", 40),
            (3, "Test:Unit", "feature/Main-menu", 41),
            (4, "test:e2e", "release-1", 41),
        ] {
            let mut row = job(n, JobState::Finished, None);
            row.name = Some(name.into());
            row.git_ref = Some(git_ref.into());
            row.pipeline = Some(pipeline);
            submit(&db, n, &row);
        }
        let ids = |filter: &JobFilter| {
            let page = db.job_page(filter, None, 10).unwrap();
            assert_eq!(page.summary.matched, page.rows.len());
            page.rows.into_iter().map(|r| r.1).collect::<Vec<_>>()
        };
        let by = |name: Option<&str>, git_ref: Option<&str>, pipeline: Option<u64>| JobFilter {
            name: name.map(str::to_string),
            git_ref: git_ref.map(str::to_string),
            pipeline,
            ..JobFilter::default()
        };
        assert_eq!(ids(&by(Some("TEST:"), None, None)), [4, 3].map(id));
        assert_eq!(ids(&by(Some("build-x86"), None, None)), [id(2)]);
        assert_eq!(ids(&by(None, Some("main"), None)), [3, 2].map(id));
        assert_eq!(ids(&by(None, None, Some(41))), [4, 3].map(id));
        assert_eq!(ids(&by(Some("unit"), Some("main"), Some(41))), [id(3)]);
        assert!(ids(&by(None, None, Some(4))).is_empty());
        assert!(ids(&by(Some("nothing"), None, None)).is_empty());
        // Job 1 has no name, branch or pipeline: only the unfiltered page has it.
        assert_eq!(ids(&JobFilter::default()).last(), Some(&id(1)));
        assert!(ids(&by(Some("b"), None, None)).iter().all(|j| *j != id(1)));
        assert!(contains_folded("é-Main", "MAIN") && !contains_folded("É", "é"));
    }

    /// The key filter matches the submitting key's ID exactly.
    #[test]
    fn a_history_page_is_filtered_by_key() {
        let db = Db::open_memory().unwrap();
        for n in 1..=4 {
            let mut row = job(n, JobState::Finished, None);
            row.key = if n.is_multiple_of(2) { "a" } else { "b" }.repeat(64);
            submit(&db, n, &row);
        }
        let by = |key: &str| {
            let filter = JobFilter {
                key: Some(key.into()),
                ..JobFilter::default()
            };
            let page = db.job_page(&filter, None, 10).unwrap();
            page.rows.into_iter().map(|r| r.1).collect::<Vec<_>>()
        };
        assert_eq!(by(&"a".repeat(64)), [4, 2].map(id));
        assert_eq!(by(&"b".repeat(64)), [3, 1].map(id));
        assert!(by(&"c".repeat(64)).is_empty());
    }

    /// Each key's count of jobs follows the records submitted and trimmed, and a database
    /// without the counts has them filled in from the records once.
    #[test]
    fn the_jobs_are_counted_by_key() {
        let db = Db::open_memory().unwrap();
        for n in 1..=5 {
            let mut row = settled(n);
            row.key = if n.is_multiple_of(2) { "a" } else { "b" }.repeat(64);
            submit(&db, n, &row);
        }
        let counts = |db: &Db| {
            let mut counts: Vec<_> = db.job_counts_by_key().unwrap().into_iter().collect();
            counts.sort();
            counts
        };
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        assert_eq!(counts(&db), [(a.clone(), 2), (b.clone(), 3)]);
        // Trimmed to its newest 2: 1, 2 and 3 go.
        db.prune_jobs(6, 2).unwrap();
        assert_eq!(counts(&db), [(a.clone(), 1), (b.clone(), 1)]);
        db.prune_jobs(6, 1).unwrap();
        assert_eq!(counts(&db), [(b.clone(), 1)]);

        // An older hub's database: the records, without their counts.
        submit(&db, 6, &settled(6));
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(JOB_COUNTS).unwrap();
        txn.open_table(JOBS)
            .unwrap()
            .insert(id(7).as_str(), b"not json".as_slice())
            .unwrap();
        count_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(counts(&db), [(b, 1), ("k".into(), 1)]);
        // Filled in once: counts held are not recounted.
        let txn = db.db.begin_write().unwrap();
        txn.open_table(JOBS)
            .unwrap()
            .remove(id(6).as_str())
            .unwrap();
        count_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(counts(&db).len(), 2);
    }

    /// A record from before jobs named their client instance still reads, naming none.
    #[test]
    fn a_job_recorded_without_its_instance_decodes() {
        let mut row = row(1);
        row.instance = Some("runner-1".into());
        let mut json = serde_json::to_value(&row).unwrap();
        json.as_object_mut().unwrap().remove("instance").unwrap();
        let older: JobRow = serde_json::from_value(json).unwrap();
        assert_eq!(
            older,
            JobRow {
                instance: None,
                ..row
            }
        );
    }

    /// A page deep in the history sums up every job the filter matches, as the newest does.
    #[test]
    fn a_history_page_sums_up_every_matching_job() {
        let db = Db::open_memory().unwrap();
        for n in 1..=11 {
            let failure = (n % 3 != 0).then_some(FailureClass::Script);
            submit(&db, n, &job(n, JobState::Finished, failure));
        }
        submit(&db, 12, &job(12, JobState::Running, None));
        let all = JobFilter::default();
        let ids = |page: &JobPage| page.rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>();
        let page = db.job_page(&all, None, 2).unwrap();
        assert_eq!(ids(&page), [12, 11].map(id));
        assert_eq!(page.older, Some(page.rows[1].0));
        assert_eq!(
            page.summary,
            JobSummary {
                matched: 12,
                finished: 11,
                succeeded: 3,
                // 1 to 11 seconds.
                median_ms: Some(6000),
            }
        );
        let deep = db.job_page(&all, Some(page.rows[1].0 - 4), 2).unwrap();
        assert_eq!(ids(&deep), [6, 5].map(id));
        assert_eq!(deep.older, Some(deep.rows[1].0));
        assert_eq!(deep.summary, page.summary);
    }

    /// While the briefs are read, a page says so, and a job submitted or changed meanwhile is
    /// in them once they are read.
    #[test]
    fn writes_made_while_the_briefs_are_read_are_kept() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &job(1, JobState::Running, None));
        submit(&db, 2, &job(2, JobState::Running, None));
        *db.write_briefs() = BriefState::Unread;
        let all = JobFilter::default();
        assert!(db.job_page(&all, None, 10).unwrap().reading);
        let txn = db.start_reading_briefs().unwrap().unwrap();
        assert!(db.start_reading_briefs().unwrap().is_none());
        submit(&db, 3, &job(3, JobState::Running, None));
        let mut done = job(2, JobState::Finished, None);
        done.revision = 2;
        assert!(db.put_job(&id(2), &done, &[], 5).unwrap());
        let mut settled = settled(1);
        settled.revision = 2;
        assert!(db.put_job(&id(1), &settled, &[], 5).unwrap());
        // Job 1 goes, settled; jobs 2 and 3 stay, not settled or not finished.
        db.prune_jobs(5, 0).unwrap();
        assert!(db.job_page(&all, None, 10).unwrap().reading);
        db.finish_reading_briefs(&txn).unwrap();
        // Read, it is checked against the database.
        let page = db.job_page(&all, None, 10).unwrap();
        assert!(!page.reading);
        assert_eq!(
            page.rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>(),
            [3, 2].map(id)
        );
        assert_eq!((page.summary.matched, page.summary.finished), (2, 1));
    }

    /// One trim drops a bounded number of jobs and says when more are past the count; the
    /// next goes on.
    #[test]
    fn a_trim_drops_a_bounded_number_of_jobs() {
        let db = Db::open_memory().unwrap();
        for n in 1..=5 {
            submit(&db, n, &settled(n));
        }
        let pruned = db.prune_jobs_scanning(11, 1, 2, TRIM_SCAN).unwrap();
        assert!(pruned.more);
        assert_eq!(listed(&db), [5, 4, 3].map(id));
        assert!(!db.prune_jobs_scanning(11, 1, 2, TRIM_SCAN).unwrap().more);
        assert_eq!(listed(&db), [5].map(id));
        assert!(!db.prune_jobs_scanning(11, 1, 2, TRIM_SCAN).unwrap().more);
    }

    /// The count set from the web UI is kept until cleared, within the history's bounds, and
    /// audited.
    #[test]
    fn the_history_count_is_set_and_cleared() {
        let db = Db::open_memory().unwrap();
        assert_eq!(db.job_history_set().unwrap(), None);
        db.set_job_history(Some(500), "", "admin", 1).unwrap();
        assert_eq!(db.job_history_set().unwrap(), Some(500));
        let max = usize::try_from(MAX_JOB_HISTORY).unwrap();
        for bad in [0, max + 1] {
            assert!(
                db.set_job_history(Some(bad), "", "admin", 2).is_err(),
                "{bad}"
            );
        }
        assert_eq!(db.job_history_set().unwrap(), Some(500));
        db.set_job_history(None, "the default applies", "admin", 3)
            .unwrap();
        assert_eq!(db.job_history_set().unwrap(), None);
        let events: Vec<String> = (db.audits(None, 10).unwrap().into_iter())
            .map(|r| r.event)
            .collect();
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(events.iter().any(|e| e.contains("500")), "{events:?}");
        assert!(
            events
                .iter()
                .any(|e| e.ends_with("cleared: the default applies")),
            "{events:?}"
        );
    }

    /// The node's own measure of a job's run wins over the hub's timestamps.
    #[test]
    fn a_jobs_run_is_the_nodes_measure_when_it_sent_one() {
        let mut row = job(5, JobState::Finished, None);
        assert_eq!(row.ran_ms(100), Some(5000));
        if let Some(r) = row.result.as_mut() {
            r.usage = Some(vk_hub_proto::job::JobUsage {
                wall_ms: 4321,
                ..Default::default()
            });
        }
        assert_eq!(row.ran_ms(100), Some(4321));
        assert_eq!(job(5, JobState::Queued, None).ran_ms(100), None);
    }

    /// Jobs a hub recorded before the history had an order get one, oldest submission first,
    /// when the database is next opened.
    #[test]
    fn jobs_recorded_before_the_order_are_ordered_by_submission() {
        let db = Db::open_memory().unwrap();
        for n in [3, 1, 2] {
            submit(&db, n, &job(n, JobState::Finished, None));
        }
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(JOB_ORDER).unwrap();
        order_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(listed(&db), [3, 2, 1].map(id));
    }

    /// A job an older hub recorded without placing it in the order joins its newest end, and
    /// places whose records an older hub dropped go, though as many were added as dropped.
    #[test]
    fn jobs_an_older_hub_recorded_join_the_order() {
        let db = Db::open_memory().unwrap();
        for n in 1..=3 {
            submit(&db, n, &job(n, JobState::Finished, None));
        }
        let txn = db.db.begin_write().unwrap();
        {
            let mut order = txn.open_table(JOB_ORDER).unwrap();
            order.remove(0).unwrap();
            order.insert(7, id(8).as_str()).unwrap();
        }
        order_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(listed(&db), [1, 3, 2].map(id));
        assert_eq!(placed(&db), 3);
    }

    fn seq_of(db: &Db, n: u64) -> u64 {
        let txn = db.db.begin_read().unwrap();
        let order = txn.open_table(JOB_ORDER).unwrap();
        let mut seqs = order.iter().unwrap().map(Result::unwrap);
        seqs.find(|(_, v)| v.value() == id(n)).unwrap().0.value()
    }

    /// A job placed once the order emptied, or rebuilt, is placed past every job expired: it
    /// is never taken for expired.
    #[test]
    fn a_job_placed_after_the_order_emptied_is_past_the_expired() {
        let db = Db::open_memory().unwrap();
        for n in 1..=2 {
            submit(&db, n, &settled(n));
        }
        assert!(
            db.prune_jobs(10 + JOB_KEEP, 100)
                .unwrap()
                .outputs
                .is_empty()
        );
        assert_eq!(expired_below(&db), Some(2));
        assert!(db.prune_jobs(10 + JOB_KEEP, 0).unwrap().outputs.is_empty());
        assert_eq!(placed(&db), 0);
        submit(&db, 3, &job(3, JobState::Finished, None));
        assert_eq!(seq_of(&db, 3), 2);
        // An older hub's job, placed when the order is rebuilt.
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(JOB_ORDER).unwrap();
        order_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(seq_of(&db, 3), 2);
        assert_eq!(
            db.prune_jobs(10 + JOB_KEEP, 100).unwrap().outputs,
            [id(3)],
            "expired, not skipped"
        );
    }

    /// One trim examines the excess and a bounded number of jobs past it; the next goes on.
    #[test]
    fn a_trim_reads_a_bounded_number_of_jobs() {
        let db = Db::open_memory().unwrap();
        for n in 1..=3 {
            submit(&db, n, &job(n, JobState::Running, None));
        }
        submit(&db, 4, &settled(4));
        assert!(
            db.prune_jobs_scanning(11, 1, TRIM_DROP, 0)
                .unwrap()
                .outputs
                .is_empty()
        );
        assert_eq!(placed(&db), 4);
        assert!(
            db.prune_jobs_scanning(11, 1, TRIM_DROP, 1)
                .unwrap()
                .outputs
                .is_empty()
        );
        assert_eq!(listed(&db), [3, 2, 1].map(id));
    }
}
