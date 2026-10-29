//! Placed jobs on the hub: reservations on nodes, placement, and each job's life from its
//! submission through the client API ([`crate::client`]) to its result, over protocol version
//! [`JOBS`] sessions. `docs/gitlab-dispatch.md` is the contract.
//!
//! **What is kept where.** Reservations, and a job's spec until a node has accepted it, live
//! in memory only: the spec carries the job's tokens and secrets. A job's record is in the
//! database ([`JobRow`]), written durably at each change of state, and its output in a file of
//! its own, synced before the node is told it is stored. A hub that restarts keeps records and
//! output and loses reservations and specs: a job no node had accepted ends
//! [`FailureClass::Lost`], and a reservation its node still holds is released when the node
//! says so in its [`Held`].
//!
//! **Placement.** A node takes placed work once its version-3 session has sent its `held`,
//! while it is connected, in the placement's pool, carries its labels and reports itself
//! ready. Its room is what its last heartbeat left — the admission ledger's budget less what
//! it has committed, or the memory available, and the jobs filesystem's free space — less
//! what the hub has asked of it since: reservations accepted after that heartbeat, offers
//! and starts not yet answered. Offers and starts go to the least loaded node first ([`load`]),
//! then the roomiest, then by ID.
//!
//! **Image affinity.** A job whose image a node builds from the job's checkout (`dockerfile:`
//! or `compose:`, as its own image or a service's) goes first to a node that ran a job of the
//! same project with the same such images within that node's image idle window, while that
//! node is lightly loaded ([`Affinity`]): its 1-minute load average, plus the vCPUs of the jobs
//! it was sent in the last minute and of this job, per CPU, below a maximum, and no more than
//! a margin above the least loaded candidate's. Such a node has the image built and boots
//! the job in seconds where another spends a minute or two building it. A job submitted on a
//! reservation on a node without the image starts on the warm node instead, without its
//! reservation, which is released. Busier, the job goes least loaded first as above; a node
//! that sends no load average is never preferred. Which node ran what is kept in memory and
//! read back from the job history after a restart.
//!
//! A node takes placed work only below its cap ([`placed_cap`]): the operator's ceiling or its
//! own executor limit, whichever is smaller, counted by [`placed`]. The node refuses past
//! either too ([`Refusal::Ceiling`], [`Refusal::Concurrency`]), should the hub's count fall
//! short of the node's. A node that reports a gitlab-runner of its own takes none
//! ([`Refusal::Runner`]).
//! The hub places a job again only while no node can have started it: after a refused start,
//! or a start that never went out; a start whose answer was lost waits for the node's `held`.
//!
//! **Lost nodes.** A node holding a job that stays unreachable for [`Dispatch::lost_after`]
//! loses it: the job ends [`FailureClass::Lost`], and the node is told to cancel it when it
//! comes back. A node's session ending ends its reservations at once; the node's `held`
//! names them when it is back, and the hub releases them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use hyper::StatusCode;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use vk_hub_proto::client::{
    AdmissionOutcome, CancelMode, Capacity, ErrorCode, JobState, JobView, Placement,
    ReservationGrant,
};
use vk_hub_proto::dispatch::{Activity, GuestSize};
use vk_hub_proto::dispatch::{
    Held, HubJobMsg, JobStart, LeaseEnd, LeaseState, MAX_LEASE_SECS, MAX_OUTPUT_CHUNK, NodeJobMsg,
    OfferReply, Refusal, RunState,
};
use vk_hub_proto::egress::{EgressReport, HubEgress};
use vk_hub_proto::job::{Envelope, FailureClass, JobResult, JobSpec};
use vk_hub_proto::{DesiredState, JOBS, NodeState, Report, StorageRole};

use crate::client::{ApiError, ResolvedIdentity};
use crate::server::{Hub, Reach};
use crate::store::{ApiPrincipal, JobFilter, JobOutcome, JobPage, JobRow, NodeRow};
use crate::ui::html::Style;

mod scheduler;
use scheduler::{Kept, ScheduleCtx, schedule_tickets};

/// How long a node may be unreachable while it holds a job before the job is lost, by
/// default.
pub const DEFAULT_LOST_AFTER: Duration = Duration::from_secs(300);

/// How long the hub waits for a node to answer an offer before it asks another. A node
/// answers from its ledger at once; one this slow has its offer released if it accepts later.
#[cfg(not(test))]
const OFFER_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const OFFER_TIMEOUT: Duration = Duration::from_secs(1);

pub fn offer_timeout() -> Duration {
    OFFER_TIMEOUT
}

/// How long a renew waits for the node's answer.
const RENEW_TIMEOUT: Duration = Duration::from_secs(10);

/// How many job messages wait for one session to send them. Far past what a node is asked at
/// once; a session that lets them pile up is not reading, and what does not fit is not sent.
const LINK_QUEUE: usize = 1024;

/// How long before a node that refused a job's start is asked to take it again.
const RETRY_PAUSE: Duration = Duration::from_secs(2);

/// The most envelopes counted on one node, however small the envelope.
const MAX_FITS: u64 = 1024;

/// What a job's stored output may run past its trace limit, for the notice a node writes
/// when it cuts the output there.
const OUTPUT_SLACK: u64 = 64 * 1024;

/// The most output the hub stores for one job, whatever its trace limit.
const MAX_OUTPUT: u64 = 64 << 20;

/// The most jobs not finished the hub holds; a submission past it is told to retry.
#[cfg(not(test))]
const MAX_LIVE_JOBS: usize = 4096;
#[cfg(test)]
const MAX_LIVE_JOBS: usize = 8;

/// What a submission past [`MAX_LIVE_JOBS`] is told to wait.
const BUSY_RETRY_SECS: u32 = 5;

/// The most placements whose capacity revision the hub keeps; the least recently asked goes.
const MAX_CAPACITY_ENTRIES: usize = 1024;

/// The trace limit a job without one is held to, as gitlab-runner's `output_limit`'s default.
const DEFAULT_OUTPUT_LIMIT: u64 = 4 << 20;

/// How much of a failed job's output is kept once it is settled, by default
/// (`kept_failure_output` in `hub.toml`).
pub const DEFAULT_KEPT_FAILURE_OUTPUT: u64 = 256 * 1024;

/// Default output tail size for settled jobs that did not fail
/// (`kept_output` in `hub.toml`).
pub const DEFAULT_KEPT_OUTPUT: u64 = 1 << 20;

/// Default total byte limit for retained output of jobs that did not fail, as stored,
/// compressed (`kept_output_total` in `hub.toml`); the oldest retained tails are evicted first.
pub const DEFAULT_KEPT_OUTPUT_TOTAL: u64 = 1 << 30;

/// How long a node keeps an image no job uses, when it does not say: `vk`'s default
/// `image_cache_idle_secs`.
const DEFAULT_IMAGE_IDLE_SECS: u64 = vk_hub_proto::DEFAULT_IMAGE_CACHE_IDLE_SECS;

/// The longest a node is counted as holding a job's image after the job, whatever it says.
const MAX_IMAGE_IDLE_SECS: u64 = 86_400;

/// The most image keys the hub remembers nodes for; the least recently used goes.
const MAX_IMAGE_KEYS: usize = 4096;

/// How long a job started on a node may not show in its 1-minute load average. A heuristic:
/// the average, an exponential one, shows about 63% of a step in load 60 seconds on.
const RECENT_START_SECS: u64 = 60;

/// When a node holding a job's image is preferred ([`prefer_warm`]): loads per CPU, in
/// millionths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Affinity {
    /// The node's load with the job must stay below it; 0 turns image affinity off
    /// (`image_affinity_max_load` in `hub.toml`).
    pub max_load: u64,
    /// The most the node's load may be above the least loaded candidate's
    /// (`image_affinity_max_extra_load`).
    pub max_extra_load: u64,
}

impl Default for Affinity {
    fn default() -> Self {
        Affinity {
            max_load: 700_000,
            max_extra_load: 250_000,
        }
    }
}

/// How often the job history is trimmed to its count and outputs past their keep are dropped.
const PRUNE_EVERY: Duration = Duration::from_secs(3600);

/// How often the database's job specs and kept output are packed ([`pack`]).
const PACK_EVERY: Duration = Duration::from_secs(3600);

/// Pause between packing or history-trimming steps so other hub writes do not queue behind them.
const PACK_PAUSE: Duration = Duration::from_millis(100);

/// How often at most a running job's record is written for a newer egress report alone, by
/// default: a hub restarting loses no more of it, and its node sends its latest again.
pub const DEFAULT_EGRESS_WRITE_EVERY: Duration = Duration::from_secs(30);

/// The hub's dispatch state.
pub struct Dispatch {
    state: Mutex<State>,
    /// Bumped at every change a long poll or the placement loop waits for.
    changes: watch::Sender<u64>,
    /// Where jobs' output is kept; `None` on a hub that places no jobs.
    output_dir: Option<PathBuf>,
    /// How long a node holding a job may be unreachable before the job is lost.
    pub lost_after: Duration,
    /// How many jobs' records the history keeps as `job_history` sets it; `None` when it does
    /// not. A count set from the web UI wins ([`history_count`]).
    history: Option<usize>,
    /// Wakes [`trim`] early: the history's count was set.
    trim_now: tokio::sync::Notify,
    /// How many bytes from the end of a failed job's output are kept when it is settled; 0
    /// keeps none.
    pub kept_failure_output: u64,
    /// Bytes retained from the end of a job's output on settlement if it did not fail.
    /// The cache stays within `kept_output_total`; 0 keeps none.
    pub kept_output: u64,
    /// Total byte limit for retained tails of jobs that did not fail, as stored, compressed;
    /// 0 keeps none.
    pub kept_output_total: u64,
    /// When a node holding a job's image is preferred.
    pub affinity: Affinity,
    /// How often at most a running job's record is written for a newer egress report alone.
    pub egress_write_every: Duration,
}

#[derive(Default)]
struct State {
    /// The version-3 sessions, by node.
    links: HashMap<String, Link>,
    /// Reservations offered or held, by ID.
    reservations: HashMap<String, Resv>,
    /// Reservation requests arbitrated, by ticket ID, which is also their admission's.
    tickets: HashMap<String, Ticket>,
    /// Admission rows to remove (`None`) or advance, written by the next pass of [`step`].
    admission_changes: Vec<(String, Option<AdmissionOutcome>)>,
    /// Admissions whose row is being written: arbitration leaves their tickets alone.
    pending_admissions: HashSet<String>,
    /// Jobs whose stored admission pruning retired, expired or dropped from the history, with
    /// their principal and admission: their tickets end once no write of the admission is
    /// pending ([`retire_finished_jobs`]).
    retired_jobs: HashMap<String, (String, Option<String>)>,
    /// What each mapped relay runner's admissions came to lately, by GitLab instance and
    /// runner ID: whether its next request probes for work or waits out a backoff.
    demand: HashMap<(String, u64), Demand>,
    /// When each tenant was last given a probe, so tenants take turns.
    tenant_probe: HashMap<String, Instant>,
    /// Probes whose offer was abandoned unanswered, by reservation: the runner probed and
    /// since when. They count against the probe budget until the node answers, or for
    /// [`scheduler::ABANDONED_PROBE_GRACE`].
    abandoned_probes: HashMap<String, ((String, u64), Instant)>,
    /// Whose turn it is between production probes and normal work.
    turns: scheduler::Turns,
    /// Jobs not finished.
    jobs: HashMap<String, LiveJob>,
    /// Jobs ended here whose final row the database may not hold yet: a reader is served
    /// from here until it does, never the older row stored before.
    finished: HashMap<String, JobRow>,
    /// Why each node refused its latest offer, until it accepts one.
    refusals: HashMap<String, String>,
    /// Jobs not finished that each node named in its `held` and the hub holds no live record
    /// of — ended here while the node was away, or never known — until their result comes:
    /// the node is stopping them, and they count against its ceiling meanwhile.
    disowned: HashMap<String, HashSet<String>>,
    /// Since when each node holding a job has been seen unreachable.
    unreachable_since: HashMap<String, Instant>,
    /// Each placement's last capacity, its revision and when it was last asked, by the
    /// placement's JSON; at most [`MAX_CAPACITY_ENTRIES`].
    capacity: HashMap<String, (u32, u64, Instant)>,
    /// The latest capacity revision given out. Each is at least the clock's seconds times
    /// 1000, so revisions keep rising across a restart, and the counter is shared by every
    /// placement so one forgotten and asked again still gets a revision past any it had.
    capacity_revision: u64,
    /// Requests being served, by `<key>/<request_id>`, so a retry racing its first attempt
    /// is told to wait rather than served twice.
    inflight: HashSet<String>,
    /// When each node last ran a job of each image key ([`image_key`]), on the hub's clock in
    /// seconds; at most [`MAX_IMAGE_KEYS`] keys.
    warm: HashMap<String, HashMap<String, u64>>,
}

#[derive(Default)]
struct Demand {
    busy_until: Option<Instant>,
    backoff_until: Option<Instant>,
    empty_count: u32,
    error_count: u32,
    last_probe: Option<Instant>,
}

#[cfg(test)]
#[derive(Default)]
pub struct ArbitrationView {
    pub waiting: usize,
    pub wait_secs: Option<u64>,
    pub offers: usize,
    pub holds: usize,
    pub jobs: usize,
    pub demand: &'static str,
    pub backoff_secs: Option<u64>,
    pub reason: Option<&'static str>,
}

#[cfg(test)]
pub fn arbitration_snapshot(hub: &Hub) -> Result<HashMap<(String, u64), ArbitrationView>> {
    let state = hub.dispatch.lock();
    let now = Instant::now();
    let mut views: HashMap<(String, u64), ArbitrationView> = HashMap::new();
    for ticket in state.tickets.values() {
        let Some(key) = ticket
            .identity
            .gitlab
            .clone()
            .zip(ticket.identity.runner_id)
        else {
            continue;
        };
        let demand = state.demand.get(&key);
        let view = views.entry(key).or_default();
        view.backoff_secs = demand
            .and_then(|d| d.backoff_until)
            .filter(|at| *at > now)
            .map(|at| at.duration_since(now).as_secs().saturating_add(1));
        view.demand = if view.backoff_secs.is_some() {
            if demand.is_some_and(|d| d.error_count > 0) {
                "unhealthy"
            } else {
                "recently empty"
            }
        } else if demand.and_then(|d| d.busy_until).is_some_and(|at| at > now) {
            "recently busy"
        } else {
            "unknown"
        };
        match ticket.phase {
            TicketPhase::Waiting => {
                view.waiting += 1;
                view.wait_secs = Some(
                    view.wait_secs
                        .unwrap_or(0)
                        .max(now.duration_since(ticket.created).as_secs()),
                );
                view.reason = ticket.blocked.or(Some("waiting for scheduling"));
            }
            TicketPhase::Offering { .. } => view.offers += 1,
            TicketPhase::Granted { .. } | TicketPhase::Claimed { .. } => view.holds += 1,
            TicketPhase::Job => view.jobs += 1,
            TicketPhase::Finished(_) => {}
        }
    }
    for job in state.jobs.values() {
        if job
            .row
            .admission
            .as_ref()
            .is_some_and(|id| state.tickets.contains_key(id))
        {
            continue;
        }
        if let Some(identity) = &job.row.scheduling
            && let Some(key) = identity.gitlab.clone().zip(identity.runner_id)
        {
            views.entry(key).or_default().jobs += 1;
        }
    }
    Ok(views)
}

/// The tenant charged for a job recorded without a scheduling identity, by a hub from before
/// capacity arbitration: the first tenant, by name, listing its project. A project several
/// tenants list is charged once.
fn legacy_tenant<'p>(policy: &'p crate::policy::Policy, row: &JobRow) -> Option<&'p str> {
    let (gitlab, project) = (row.gitlab.as_ref()?, row.project_id?);
    policy
        .tenants
        .iter()
        .find(|(_, tenant)| {
            tenant
                .projects
                .iter()
                .any(|p| p.gitlab == *gitlab && p.id == project)
        })
        .map(|(name, _)| name.as_str())
}

const MAX_TICKETS: usize = 4096;
const MAX_RETAINED_TICKETS: usize = 2 * MAX_TICKETS;
const MAX_PRINCIPAL_TICKETS: usize = 256;
const TICKET_IDLE: Duration = Duration::from_secs(2 * vk_hub_proto::client::MAX_WAIT_SECS as u64);

#[derive(Clone)]
struct Ticket {
    key: String,
    instance: Option<String>,
    queued: bool,
    request_id: String,
    digest: String,
    identity: ResolvedIdentity,
    placement: Placement,
    lease_secs: u32,
    created: Instant,
    polled: Instant,
    phase: TicketPhase,
    probe: bool,
    reservation: Option<String>,
    session: Option<u64>,
    /// When it was claimed in [`Ticket::session`]: a heartbeat of that session received well
    /// after that must list it.
    claimed_at: Option<Instant>,
    tried: HashSet<String>,
    round_ended: Option<Instant>,
    blocked: Option<&'static str>,
}

#[derive(Clone, PartialEq, Eq)]
enum TicketPhase {
    Waiting,
    Offering {
        reservation: String,
        since: Instant,
    },
    Granted {
        reservation: String,
        accepted: Instant,
    },
    Claimed {
        reservation: String,
    },
    Job,
    Finished(AdmissionOutcome),
}

/// A node's version-3 session.
struct Link {
    session: u64,
    tx: mpsc::Sender<HubJobMsg>,
    /// The node has said what it holds, and may be offered work.
    held: bool,
}

struct Resv {
    key: String,
    /// The client instance that asked for it ([`ApiPrincipal::instance`]).
    instance: Option<String>,
    node: String,
    envelope: Envelope,
    phase: ResvPhase,
    /// When the node accepted it, on the hub's clock in seconds: a heartbeat from before that
    /// does not count it yet.
    accepted_at: u64,
    /// Bumped at each lease the node reports, for a renew waiting on its answer.
    leases: u64,
    /// The ticket it was offered for, whose phase follows the node's answers.
    ticket: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ResvPhase {
    Offered,
    Held {
        lease_secs: u32,
    },
    Refused(Refusal),
    /// Its offer went unanswered in time: released if the node accepts it after all.
    Abandoned,
}

struct LiveJob {
    row: JobRow,
    /// Until a node accepts the job.
    spec: Option<Arc<JobSpec>>,
    /// The reservation the job was submitted on, while it may still start on it.
    reservation: Option<String>,
    /// Placed by then, or ended [`FailureClass::NoCapacity`].
    deadline: Instant,
    /// Nodes that refused it since the round of offers began.
    tried: HashSet<String>,
    /// When the last node it could go to refused it.
    round_ended: Option<Instant>,
    /// Why arbitration last passed it over while nodes may have had room for it: a limit of
    /// its tenant, relay or runner, production headroom, its project's delisting or its placement
    /// rules. Told when it ends at its deadline.
    blocked: Option<&'static str>,
    /// The most output stored for it.
    output_cap: u64,
    /// When the node accepted the reservation it was sent on, as [`Resv::accepted_at`]: until
    /// a heartbeat from after that, its start is counted against the node's room.
    reservation_accepted_at: u64,
    /// Its [`image_key`], from its spec; `None` for a job recovered after a restart whose
    /// spec expired.
    image_key: Option<String>,
    /// Its relay's ID ([`ApiPrincipal::id`]): its registry token is minted while the relay is
    /// enrolled and its server approved. `None` for a job recovered after a restart.
    mint_key: Option<String>,
    /// How far its record as written holds its egress report.
    egress: EgressWritten,
}

/// How far a running job's record as written holds its egress report, which its node sends
/// every few seconds while it changes: kept in memory at once, written at most every
/// [`Dispatch::egress_write_every`] unless another change writes the record first.
#[derive(Clone, Copy, Debug, Default)]
struct EgressWritten {
    /// The revision of the report the record was last written with; 0 for none.
    revision: u64,
    /// When a write of a newer report was last made or tried.
    at: Option<Instant>,
}

impl LiveJob {
    /// The node it has been sent to, accepted or not.
    fn node(&self) -> Option<&str> {
        self.row.node.as_deref()
    }

    /// Whether its record is to be written now for its egress report alone: the report held is
    /// newer than the one written, and no write of one was made or tried within `every`.
    fn egress_due(&self, now: Instant, every: Duration) -> bool {
        self.row
            .egress
            .as_ref()
            .is_some_and(|r| r.revision > self.egress.revision)
            && self
                .egress
                .at
                .is_none_or(|at| now.duration_since(at) >= every)
    }
}

/// An audit line: the node it is about, who, what.
type Event = (Option<String>, String, String);

/// What the hub does on a node's word, as `hub`.
const HUB: &str = "hub";

impl Dispatch {
    /// Swap a node's live session under the dispatch lock, so a pass never sees half a
    /// change.
    pub(crate) fn with_session_change<T>(&self, change: impl FnOnce() -> T) -> T {
        let _state = self.lock();
        change()
    }

    /// Dispatch keeping output in `output_dir`, or none at all, and the records of the newest
    /// `history` jobs, [`DEFAULT_JOB_HISTORY`](crate::store::DEFAULT_JOB_HISTORY) for `None`.
    pub fn new(output_dir: Option<PathBuf>, lost_after: Duration, history: Option<usize>) -> Self {
        Dispatch {
            changes: watch::Sender::new(0),
            output_dir,
            lost_after,
            history,
            trim_now: tokio::sync::Notify::new(),
            kept_failure_output: DEFAULT_KEPT_FAILURE_OUTPUT,
            kept_output: DEFAULT_KEPT_OUTPUT,
            kept_output_total: DEFAULT_KEPT_OUTPUT_TOTAL,
            affinity: Affinity::default(),
            egress_write_every: DEFAULT_EGRESS_WRITE_EVERY,
            state: Mutex::new(State {
                capacity_revision: crate::now_secs().saturating_mul(1000),
                ..State::default()
            }),
        }
    }

    /// A panic while the state was held leaves maps whose entries are each replaced whole, so
    /// poisoning is ignored.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn bump(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn output_dir(&self) -> Result<&Path, ApiError> {
        self.output_dir.as_deref().ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "this hub places no jobs",
            )
            .retry_after(60)
        })
    }
}

/// Create `dir`, private, for jobs' output.
pub fn output_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

fn output_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.out"))
}

/// Write `data` at `at` in job `id`'s output file and sync it — and, for the file's first
/// bytes, the directory that names it.
fn write_output(dir: &Path, id: &str, at: u64, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    let path = output_path(dir, id);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all_at(data, at)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("syncing {}", path.display()))?;
    if at == 0 {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("syncing {}", dir.display()))?;
    }
    Ok(())
}

/// Up to `max` bytes of job `id`'s output from `at`.
fn read_output(dir: &Path, id: &str, at: u64, max: usize) -> Result<Vec<u8>> {
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    let path = output_path(dir, id);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
    };
    let mut buf = vec![0u8; max];
    let mut filled = 0usize;
    while filled < max {
        let rest = buf.get_mut(filled..).unwrap_or_default();
        let n = file
            .read_at(rest, at.saturating_add(filled as u64))
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        filled = filled.saturating_add(n);
    }
    buf.truncate(filled);
    Ok(buf)
}

/// The last `max` bytes of job `id`'s output, `len` bytes long, from the start of a line:
/// what precedes the first newline is dropped when the cut fell inside a line.
fn output_tail(dir: &Path, id: &str, len: u64, max: u64) -> Result<Vec<u8>> {
    let from = len.saturating_sub(max);
    // From the byte before the cut, so a line starting right at it is kept whole.
    let start = from.saturating_sub(1);
    let want = usize::try_from(len.saturating_sub(start)).unwrap_or(usize::MAX);
    let mut tail = read_output(dir, id, start, want)?;
    if from > 0 {
        // With no newline, only that byte goes.
        let cut = tail.iter().position(|&b| b == b'\n').map_or(1, |nl| nl + 1);
        tail.drain(..cut.min(tail.len()));
    }
    Ok(tail)
}

/// The length of job `id`'s output file: what of it the hub stored.
fn stored_len(dir: &Path, id: &str) -> u64 {
    std::fs::symlink_metadata(output_path(dir, id)).map_or(0, |m| m.len())
}

/// Run `f` on the database off the runtime.
async fn blocking<T: Send + 'static>(
    hub: &Hub,
    f: impl FnOnce(&crate::store::Db) -> Result<T> + Send + 'static,
) -> Result<T> {
    let db = hub.db.clone();
    tokio::task::spawn_blocking(move || f(&db))
        .await
        .context("running a database operation")?
}

/// Write `row`, with `events` audited, and tell the web UI's pages.
async fn persist(hub: &Hub, id: &str, row: JobRow, events: Vec<Event>) -> Result<()> {
    let id = id.to_string();
    let (id, row, written) = blocking(hub, move |db| {
        let written = db.put_job(&id, &row, &events, crate::now_secs())?;
        Ok((id, row, written))
    })
    .await?;
    {
        let mut state = hub.dispatch.lock();
        if row.state == JobState::Finished
            && state
                .finished
                .get(&id)
                .is_some_and(|r| r.revision <= row.revision)
        {
            state.finished.remove(&id);
        }
        // Written with this report: [`write_egress`] leaves it, not one newer that came since.
        if let (true, Some(report), Some(job)) = (written, &row.egress, state.jobs.get_mut(&id))
            && report.revision > job.egress.revision
        {
            job.egress = EgressWritten {
                revision: report.revision,
                at: Some(Instant::now()),
            };
        }
    }
    hub.touch();
    hub.jobs_changed();
    hub.job_changed(&id);
    Ok(())
}

/// Write `row`, logging rather than failing: the change is made in memory, and the next
/// write of the job carries it. Its `events` are not carried, so they are written on their
/// own, and logged whole should that fail too.
async fn persist_logged(hub: &Hub, id: &str, row: JobRow, events: Vec<Event>) {
    let Err(e) = persist(hub, id, row, events.clone()).await else {
        return;
    };
    eprintln!("vk-hub: recording job {id}: {e:#}");
    if events.is_empty() {
        return;
    }
    let lines = events.clone();
    let audited = blocking(hub, move |db| db.audit_all(&lines, crate::now_secs())).await;
    if let Err(e) = audited {
        eprintln!("vk-hub: auditing job {id}: {e:#}");
        for (node, actor, event) in events {
            let node = node.map_or(String::new(), |n| format!(" (node {n})"));
            eprintln!("vk-hub: audit line not recorded{node}: {actor}: {event}");
        }
    }
}

/// End `job` with `failure` and `message`, moving it from the live jobs to those finished
/// until [`persist`] has written it, and giving back a reservation it was submitted on and
/// never started on. Return the row to persist and an audit line for non-cancel failures;
/// callers that do not audit the failure discard it.
fn finish(
    state: &mut State,
    id: &str,
    failure: Option<FailureClass>,
    message: Option<String>,
) -> Option<(JobRow, Vec<Event>)> {
    let mut job = state.jobs.remove(id)?;
    if let Some(reservation) = job.reservation.take()
        && let Some(r) = state.reservations.remove(&reservation)
    {
        send(state, &r.node, HubJobMsg::Release { reservation });
    }
    // Its node used its image until now.
    if job.row.started_at.is_some()
        && let (Some(key), Some(node)) = (job.image_key.take(), job.row.node.as_deref())
    {
        warm_touch(state, key, node, crate::now_secs());
    }
    let row = &mut job.row;
    // Ended while preparing, it keeps that stage: all of its time was preparing.
    if !row.preparing() {
        row.stage = None;
    }
    row.state = JobState::Finished;
    row.revision = row.revision.saturating_add(1);
    row.finished_at = Some(crate::now_secs());
    row.activity = None;
    let output_len = row.output_len;
    // Ended by the hub, or before its node sent its result: the last report its node sent,
    // as far as it went.
    let egress = row.egress.take().map(EgressReport::interrupted);
    let event = failure
        .filter(|f| *f != FailureClass::Canceled)
        .map(|f| match &message {
            Some(m) => format!("job {id} ended: {}: {m}", failure_name(f)),
            None => format!("job {id} ended: {}", failure_name(f)),
        });
    row.result = Some(JobResult {
        failure,
        exit_code: None,
        message,
        output_len,
        artifacts: Vec::new(),
        usage: None,
        events: Vec::new(),
        egress,
    });
    let events = event
        .map(|e| (row.node.clone(), HUB.to_string(), e))
        .into_iter()
        .collect();
    state.finished.insert(id.to_string(), job.row.clone());
    Some((job.row, events))
}

/// `activity`, as a node said it, with its strings made display-safe.
fn display_safe_activity(activity: Activity) -> Activity {
    use vk_hub_proto::display_safe as safe;
    match activity {
        Activity::Building { image } => Activity::Building {
            image: safe(&image),
        },
        Activity::Pulling { image } => Activity::Pulling {
            image: safe(&image),
        },
        Activity::Waiting {
            image,
            building,
            holder,
        } => Activity::Waiting {
            image: safe(&image),
            building,
            holder: holder.as_deref().map(safe),
        },
        Activity::Other => Activity::Other,
    }
}

/// Record the node's `stage` and `activity` at `now`; retain activity only during preparation.
/// Retain the VM size, `guest`, once reported by the node.
fn note_stage(
    row: &mut JobRow,
    stage: &str,
    activity: Option<Activity>,
    guest: Option<GuestSize>,
    now: u64,
) {
    use crate::store::PREPARE_STAGE;
    // A job's runtime starts after preparation. Exclude cleanup after failed preparation
    // and jobs already past preparation when the hub started recording this boundary.
    if stage != PREPARE_STAGE
        && stage != "cleanup"
        && (row.stage.as_deref()).is_none_or(|s| s == PREPARE_STAGE)
    {
        row.prepared_at.get_or_insert(now);
    }
    row.stage = Some(vk_hub_proto::display_safe(stage));
    row.activity = activity
        .filter(|_| stage == PREPARE_STAGE)
        .map(display_safe_activity);
    // Known once preparation sizes the VM; a node that has not yet says nothing.
    row.guest = guest.or(row.guest);
}

/// What `activity` is, in a few words, for a badge: the image it names is on the job's page.
fn activity_text(activity: &Activity) -> &'static str {
    match activity {
        Activity::Building { .. } => "building image",
        Activity::Pulling { .. } => "pulling image",
        Activity::Waiting { building: true, .. } => "waiting for build",
        Activity::Waiting {
            building: false, ..
        } => "waiting for pull",
        Activity::Other => "preparing",
    }
}

pub(crate) fn failure_name(f: FailureClass) -> &'static str {
    match f {
        FailureClass::Script => "script failure",
        FailureClass::Timeout => "timeout",
        FailureClass::Canceled => "canceled",
        FailureClass::ImagePull => "image pull failure",
        FailureClass::Configuration => "configuration error",
        FailureClass::ExternalDependency => "external dependency failure",
        FailureClass::System => "system failure",
        FailureClass::Interrupted => "interrupted",
        FailureClass::NoCapacity => "no capacity",
        FailureClass::Lost => "lost",
        FailureClass::Other => "other failure",
    }
}

/// How job `j` stands, as `vk-hub jobs` and the web UI show it.
pub(crate) fn state_text(j: &JobRow) -> String {
    let state = match (j.state, &j.result) {
        (JobState::Finished, Some(r)) => match r.failure {
            Some(f) => format!("failed: {}", failure_name(f)),
            None => "succeeded".to_string(),
        },
        (JobState::Running, _) => match (&j.stage, &j.activity) {
            // Only ever while preparing: the activity says it.
            (_, Some(activity)) => activity_text(activity).to_string(),
            (Some(stage), None) if stage == crate::store::PREPARE_STAGE => "preparing".to_string(),
            (Some(stage), None) => format!("running: {stage}"),
            // Accepted, no stage told yet: preparing still.
            (None, None) => "preparing".to_string(),
        },
        (JobState::Queued, _) => "queued".to_string(),
        (JobState::Starting, _) => "starting".to_string(),
        _ => "unknown".to_string(),
    };
    match j.cancel {
        Some(_) if j.state != JobState::Finished => format!("{state}, canceling"),
        _ => state,
    }
}

fn refusal_name(r: Refusal) -> &'static str {
    match r {
        Refusal::Memory => "memory",
        Refusal::Disk => "disk",
        Refusal::Cpus => "cpus",
        Refusal::NotReady => "not ready",
        Refusal::Policy => "policy",
        Refusal::NoReservation => "no reservation",
        Refusal::Invalid => "invalid",
        Refusal::Ceiling => "ceiling",
        Refusal::Runner => "runner",
        Refusal::Concurrency => "concurrency",
        Refusal::Other => "other",
    }
}

fn lease_end_name(e: LeaseEnd) -> &'static str {
    match e {
        LeaseEnd::Expired => "expired",
        LeaseEnd::Released => "released",
        LeaseEnd::Started => "taken over by a job",
        LeaseEnd::Unknown => "unknown to the node",
        LeaseEnd::Other => "ended",
    }
}

/// Queue `msg` for `node`'s session. Whether it was queued: a node with no version-3 session,
/// or one not reading, gets nothing.
fn send(state: &State, node: &str, msg: HubJobMsg) -> bool {
    state
        .links
        .get(node)
        .is_some_and(|l| l.tx.try_send(msg).is_ok())
}

// ---------------------------------------------------------------------------------------------
// Sessions.

/// Register `session`, at protocol `version`, as `node`'s link for job messages: the
/// receiver the session sends from, or `None` below [`JOBS`]. A session it supersedes ends
/// its reservations, as [`close_link`] would.
pub async fn open_link(
    hub: &Hub,
    node: &str,
    session: u64,
    version: u32,
) -> Option<mpsc::Receiver<HubJobMsg>> {
    if version < JOBS {
        return None;
    }
    let (tx, rx) = mpsc::channel(LINK_QUEUE);
    let dropped = {
        let mut state = hub.dispatch.lock();
        // A new session may be a node restarted with whatever refused its offers fixed.
        state.refusals.remove(node);
        let superseded = state.links.insert(
            node.to_string(),
            Link {
                session,
                tx,
                held: false,
            },
        );
        if superseded.is_some() {
            end_reservations(&mut state, node)
        } else {
            0
        }
    };
    if dropped > 0 {
        hub.dispatch.bump();
    }
    audit_ended(hub, node, dropped).await;
    Some(rx)
}

/// `session` of `node` ended. Its reservations end with it: the node names any it still
/// holds in its next session's `held`, and the hub releases them then.
pub async fn close_link(hub: &Hub, node: &str, session: u64) {
    let dropped = {
        let mut state = hub.dispatch.lock();
        if !state.links.get(node).is_some_and(|l| l.session == session) {
            return;
        }
        state.links.remove(node);
        // The node names those it still runs in its next session's `held`.
        state.disowned.remove(node);
        end_reservations(&mut state, node)
    };
    hub.dispatch.bump();
    audit_ended(hub, node, dropped).await;
}

/// Drop every reservation on `node`: how many.
fn end_reservations(state: &mut State, node: &str) -> usize {
    let before = state.reservations.len();
    state.reservations.retain(|_, r| r.node != node);
    state
        .abandoned_probes
        .retain(|id, _| state.reservations.contains_key(id));
    before.saturating_sub(state.reservations.len())
}

/// Audit that `dropped` reservations on `node` ended with its session.
async fn audit_ended(hub: &Hub, node: &str, dropped: usize) {
    if dropped == 0 {
        return;
    }
    let node = node.to_string();
    let event = format!("{dropped} reservation(s) on node {node} ended with its session");
    if let Err(e) = blocking(hub, move |db| {
        db.audit_node(Some(&node), HUB, &event, crate::now_secs())
    })
    .await
    {
        eprintln!("vk-hub: {e:#}");
    }
}

/// A node broke the job protocol: its session ends.
#[derive(Debug)]
pub struct Violation(pub String);

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Violation {}

/// Handle a job message from `node`'s `session`. The answers for the session to send; an
/// error that is a [`Violation`] ends the session as a protocol error.
pub async fn on_node(
    hub: &Hub,
    node: &str,
    session: u64,
    msg: NodeJobMsg,
) -> Result<Vec<HubJobMsg>> {
    {
        let state = hub.dispatch.lock();
        if !state.links.get(node).is_some_and(|l| l.session == session) {
            // Superseded: the newer session speaks for the node.
            return Ok(Vec::new());
        }
    }
    let out = match msg {
        NodeJobMsg::Held(held) => on_held(hub, node, held).await,
        NodeJobMsg::OfferReply { reservation, reply } => {
            Ok(on_offer_reply(hub, node, &reservation, reply))
        }
        NodeJobMsg::Lease { reservation, state } => on_lease(hub, node, &reservation, state).await,
        NodeJobMsg::Job { job, state } => on_job_state(hub, node, &job, state).await,
        NodeJobMsg::Output { job, offset, data } => on_output(hub, node, &job, offset, &data).await,
        NodeJobMsg::Result { job, result } => on_result(hub, node, &job, result).await,
        NodeJobMsg::Egress { job, report } => Ok(on_egress(hub, node, &job, report)),
    };
    hub.dispatch.bump();
    out
}

async fn on_held(hub: &Hub, node: &str, held: Held) -> Result<Vec<HubJobMsg>> {
    let mut out = Vec::new();
    let mut writes = Vec::new();
    let unknown: Vec<String> = {
        let mut state = hub.dispatch.lock();
        if let Some(link) = state.links.get_mut(node) {
            link.held = true;
        }
        // Reservations: the hub keeps none past a session, so each held one is released.
        for r in held.reservations {
            let ours = state
                .reservations
                .get(&r.reservation)
                .is_some_and(|x| x.node == node && matches!(x.phase, ResvPhase::Held { .. }));
            if !ours {
                out.push(HubJobMsg::Release {
                    reservation: r.reservation,
                });
            }
        }
        let named: HashSet<String> = held.jobs.iter().map(|j| j.job.clone()).collect();
        let mut unknown = Vec::new();
        let mut disowned = HashSet::new();
        for j in held.jobs {
            let Some(job) = (state.jobs.get_mut(&j.job)).filter(|x| x.node() == Some(node)) else {
                if !j.finished {
                    disowned.insert(j.job.clone());
                }
                unknown.push(j.job);
                continue;
            };
            let before = job.row.clone();
            let now = crate::now_secs();
            // Journaled: accepted, whatever answer was lost.
            if job.row.state != JobState::Running {
                job.row.state = JobState::Running;
                job.row.started_at.get_or_insert(now);
                job.spec = None;
            }
            // Where it is now: the node tells only what changes from here.
            if let RunState::Running {
                stage,
                activity,
                guest,
            } = j.state
            {
                note_stage(&mut job.row, &stage, activity, guest, now);
            }
            if job.row != before {
                job.row.revision = job.row.revision.saturating_add(1);
                writes.push((j.job.clone(), job.row.clone(), Vec::new()));
            }
            out.push(HubJobMsg::OutputAck {
                job: j.job.clone(),
                offset: job.row.output_len,
            });
            if let Some(mode) = job.row.cancel {
                out.push(HubJobMsg::Cancel { job: j.job, mode });
            }
        }
        // Jobs sent to this node that it does not hold: a start it never took goes back to
        // be placed, a job it had accepted is lost.
        let missing: Vec<String> = state
            .jobs
            .iter()
            .filter(|(id, j)| j.node() == Some(node) && !named.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in missing {
            let requeue = state
                .jobs
                .get(&id)
                .is_some_and(|j| j.row.state == JobState::Starting && j.spec.is_some());
            if let Some(job) = state.jobs.get_mut(&id).filter(|_| requeue) {
                job.row.state = JobState::Queued;
                job.row.node = None;
                job.row.registry_access = None;
                job.row.egress_rules = None;
                job.row.revision = job.row.revision.saturating_add(1);
                job.reservation = None;
                writes.push((id, job.row.clone(), Vec::new()));
            } else if let Some(w) = finish(
                &mut state,
                &id,
                Some(FailureClass::Lost),
                Some(format!("node {node} no longer holds it")),
            ) {
                writes.push((id, w.0, w.1));
            }
        }
        if disowned.is_empty() {
            state.disowned.remove(node);
        } else {
            state.disowned.insert(node.to_string(), disowned);
        }
        unknown
    };
    for (id, row, events) in writes {
        persist_logged(hub, &id, row, events).await;
    }
    // Jobs this hub has ended or never knew: the node stops them.
    for job in unknown {
        out.push(HubJobMsg::Cancel {
            job,
            mode: CancelMode::Immediate,
        });
    }
    Ok(out)
}

fn on_offer_reply(hub: &Hub, node: &str, id: &str, reply: OfferReply) -> Vec<HubJobMsg> {
    let mut state = hub.dispatch.lock();
    note_refusal(&mut state, node, &reply);
    let release = || {
        vec![HubJobMsg::Release {
            reservation: id.to_string(),
        }]
    };
    let Some(r) = state.reservations.get_mut(id).filter(|r| r.node == node) else {
        return match reply {
            OfferReply::Accepted { .. } => release(),
            OfferReply::Refused { .. } => Vec::new(),
        };
    };
    let accepted = matches!(
        (&r.phase, &reply),
        (ResvPhase::Offered, OfferReply::Accepted { .. })
    );
    let ticket = r.ticket.clone();
    let result = match (&r.phase, reply) {
        (ResvPhase::Offered, OfferReply::Accepted { lease_secs }) => {
            r.phase = ResvPhase::Held {
                lease_secs: lease_secs.min(MAX_LEASE_SECS),
            };
            r.accepted_at = crate::now_secs();
            Vec::new()
        }
        (ResvPhase::Offered, OfferReply::Refused { reason, .. }) => {
            r.phase = ResvPhase::Refused(reason);
            Vec::new()
        }
        (ResvPhase::Abandoned, reply) => {
            state.reservations.remove(id);
            state.abandoned_probes.remove(id);
            match reply {
                OfferReply::Accepted { .. } => release(),
                OfferReply::Refused { .. } => Vec::new(),
            }
        }
        // A second answer to one offer changes nothing.
        _ => Vec::new(),
    };
    if accepted
        && let Some(ticket) = ticket.and_then(|t| state.tickets.get_mut(&t))
        && let TicketPhase::Offering { reservation, since } = &ticket.phase
        && reservation == id
    {
        ticket.phase = TicketPhase::Granted {
            reservation: id.to_owned(),
            accepted: *since,
        };
    }
    result
}

/// Keep why `node` refused its latest offer, logged when that changes: a reservation waiting
/// for room is offered to the same node every few seconds.
fn note_refusal(state: &mut State, node: &str, reply: &OfferReply) {
    let OfferReply::Refused { reason, message } = reply else {
        if state.refusals.remove(node).is_some() {
            eprintln!("vk-hub: node {node} accepts offers again");
        }
        return;
    };
    let why = match message {
        Some(m) => format!(
            "{}: {}",
            refusal_name(*reason),
            vk_hub_proto::display_safe(m)
        ),
        None => refusal_name(*reason).to_string(),
    };
    if state.refusals.get(node) != Some(&why) {
        eprintln!("vk-hub: node {node} refuses offers: {why}");
        state.refusals.insert(node.to_string(), why);
    }
}

/// Why `node` refused its latest offer, while it accepts none.
pub fn last_refusal(hub: &Hub, node: &str) -> Option<String> {
    hub.dispatch.lock().refusals.get(node).cloned()
}

async fn on_lease(hub: &Hub, node: &str, id: &str, lease: LeaseState) -> Result<Vec<HubJobMsg>> {
    let ended = {
        let mut state = hub.dispatch.lock();
        let Some(r) = state.reservations.get_mut(id).filter(|r| r.node == node) else {
            return Ok(Vec::new());
        };
        match lease {
            LeaseState::Held { remaining_secs } => {
                if matches!(r.phase, ResvPhase::Held { .. }) {
                    r.phase = ResvPhase::Held {
                        lease_secs: remaining_secs.min(MAX_LEASE_SECS),
                    };
                }
                r.leases = r.leases.wrapping_add(1);
                let ticket = r.ticket.clone();
                if let Some(ticket) = ticket.and_then(|t| state.tickets.get_mut(&t))
                    && let TicketPhase::Granted {
                        reservation,
                        accepted,
                    } = &mut ticket.phase
                    && reservation == id
                {
                    *accepted = Instant::now();
                }
                return Ok(Vec::new());
            }
            LeaseState::Gone { why } => {
                let r = state.reservations.remove(id);
                state.abandoned_probes.remove(id);
                r.map(|r| (r.key, why))
            }
        }
    };
    if let Some((_, why)) = ended
        && why != LeaseEnd::Started
        && why != LeaseEnd::Released
    {
        let (node, event) = (
            node.to_string(),
            format!("reservation {id} on node {node} {}", lease_end_name(why)),
        );
        blocking(hub, move |db| {
            db.audit_node(Some(&node), HUB, &event, crate::now_secs())
        })
        .await?;
    }
    Ok(Vec::new())
}

async fn on_job_state(hub: &Hub, node: &str, id: &str, run: RunState) -> Result<Vec<HubJobMsg>> {
    let mut answers = Vec::new();
    let write = {
        let mut state = hub.dispatch.lock();
        let Some(job) = state.jobs.get_mut(id).filter(|j| j.node() == Some(node)) else {
            return Ok(Vec::new());
        };
        // Its node has its image, or is building it.
        let warmed = matches!(run, RunState::Accepted | RunState::Running { .. })
            .then(|| job.image_key.clone())
            .flatten();
        let row = &mut job.row;
        let mut events = Vec::new();
        match run {
            RunState::Accepted => {
                if row.state != JobState::Starting {
                    return Ok(Vec::new());
                }
                row.state = JobState::Running;
                row.started_at.get_or_insert_with(crate::now_secs);
                job.spec = None;
                job.reservation = None;
            }
            RunState::Refused { reason, message } => {
                if row.state != JobState::Starting {
                    return Ok(Vec::new());
                }
                // It ran nowhere: free to place again, elsewhere first. A reservation it was
                // sent on goes back.
                row.state = JobState::Queued;
                row.node = None;
                row.registry_access = None;
                row.egress_rules = None;
                if let Some(reservation) = job.reservation.take() {
                    answers.push(HubJobMsg::Release { reservation });
                }
                job.tried.insert(node.to_string());
                events.push((
                    Some(node.to_string()),
                    HUB.to_string(),
                    format!(
                        "node {node} refused job {id}: {}{}",
                        refusal_name(reason),
                        message.map(|m| format!(" ({m})")).unwrap_or_default()
                    ),
                ));
            }
            RunState::Running {
                stage,
                activity,
                guest,
            } => {
                row.state = JobState::Running;
                let now = crate::now_secs();
                row.started_at.get_or_insert(now);
                job.spec = None;
                job.reservation = None;
                note_stage(row, &stage, activity, guest, now);
            }
            RunState::Finished => return Ok(Vec::new()),
        }
        row.revision = row.revision.saturating_add(1);
        let write = (row.clone(), events);
        if let Some(key) = warmed {
            warm_touch(&mut state, key, node, crate::now_secs());
        }
        write
    };
    persist(hub, id, write.0, write.1).await?;
    Ok(answers)
}

async fn on_output(
    hub: &Hub,
    node: &str,
    id: &str,
    offset: u64,
    data: &str,
) -> Result<Vec<HubJobMsg>> {
    let bytes = vk_hub_proto::from_base64(data)
        .ok_or_else(|| Violation(format!("job {id}'s output is not base64")))?;
    if bytes.len() > MAX_OUTPUT_CHUNK {
        return Err(Violation(format!(
            "job {id}'s output came in a chunk of {} bytes, past {MAX_OUTPUT_CHUNK}",
            bytes.len()
        ))
        .into());
    }
    let end = offset.saturating_add(bytes.len() as u64);
    let (have, cap) = {
        let state = hub.dispatch.lock();
        match state.jobs.get(id) {
            Some(job) if job.node() == Some(node) => (job.row.output_len, job.output_cap),
            // A job the hub ended or never knew: it is being cancelled; what it still sends
            // is acked and dropped, so the node can drain its output and finish.
            _ => {
                return Ok(vec![HubJobMsg::OutputAck {
                    job: id.to_string(),
                    offset: end,
                }]);
            }
        }
    };
    // Past its cap, the hub acks output it does not store: a node continues from there.
    if offset > have && have < cap {
        return Err(Violation(format!("job {id}'s output skips from {have} to {offset}")).into());
    }
    let skip = usize::try_from(have.saturating_sub(offset)).unwrap_or(usize::MAX);
    let fresh = bytes.get(skip..).unwrap_or_default();
    // Past its cap, output is acked and dropped: a node holds a job to its trace limit, and
    // the hub's disk to a little past that.
    let room = usize::try_from(cap.saturating_sub(have)).unwrap_or(usize::MAX);
    let kept = fresh
        .get(..room.min(fresh.len()))
        .unwrap_or_default()
        .to_vec();
    if !kept.is_empty() {
        let dir = hub
            .dispatch
            .output_dir
            .clone()
            .context("this hub places no jobs")?;
        let (job, len) = (id.to_string(), kept.len() as u64);
        tokio::task::spawn_blocking(move || write_output(&dir, &job, have, &kept))
            .await
            .context("writing output")??;
        {
            let mut state = hub.dispatch.lock();
            if let Some(job) = state.jobs.get_mut(id) {
                job.row.output_len = have.saturating_add(len);
            }
        }
        // The job's page alone: its record is unchanged until written.
        hub.job_changed(id);
    }
    let acked = end.max(have);
    Ok(vec![HubJobMsg::OutputAck {
        job: id.to_string(),
        offset: acked,
    }])
}

/// A running job's egress report: kept when it is newer than the one held, for the job's page
/// and the job list to show at once. Its record is written by [`write_egress`], so the Egress
/// page's rows follow it within [`Dispatch::egress_write_every`].
fn on_egress(hub: &Hub, node: &str, id: &str, report: EgressReport) -> Vec<HubJobMsg> {
    {
        let mut state = hub.dispatch.lock();
        let Some(job) = state.jobs.get_mut(id).filter(|j| j.node() == Some(node)) else {
            // Ended, or never its: the result carries what counts.
            return Vec::new();
        };
        let row = &mut job.row;
        if row.state != JobState::Running {
            return Vec::new();
        }
        let stored = row.egress.take();
        let kept = crate::egress::newest(stored.clone(), Some(report));
        let changed = kept != stored;
        row.egress = kept;
        if !changed {
            return Vec::new();
        }
        row.revision = row.revision.saturating_add(1);
    }
    hub.live_jobs_changed();
    hub.job_changed(id);
    Vec::new()
}

/// Write the record of each running job whose egress report is due ([`LiveJob::egress_due`]),
/// checking every second, until the process ends.
async fn write_egress(hub: Arc<Hub>) {
    let mut every = tokio::time::interval(Duration::from_secs(1));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        let due: Vec<(String, JobRow)> = {
            let mut state = hub.dispatch.lock();
            let now = Instant::now();
            let write_every = hub.dispatch.egress_write_every;
            state
                .jobs
                .iter_mut()
                .filter(|(_, j)| j.egress_due(now, write_every))
                .map(|(id, j)| {
                    // Tried: a write that fails is tried again past the same wait.
                    j.egress.at = Some(now);
                    (id.clone(), j.row.clone())
                })
                .collect()
        };
        for (id, row) in due {
            persist_logged(&hub, &id, row, Vec::new()).await;
        }
    }
}

async fn on_result(
    hub: &Hub,
    node: &str,
    id: &str,
    mut result: JobResult,
) -> Result<Vec<HubJobMsg>> {
    let recorded = vec![HubJobMsg::Recorded {
        job: id.to_string(),
    }];
    let (row, events) = {
        let mut state = hub.dispatch.lock();
        let Some(job) = state.jobs.get_mut(id).filter(|j| j.node() == Some(node)) else {
            // Ended by the hub, or never its: recorded all the same, so the node stops.
            if let Some(d) = state.disowned.get_mut(node) {
                d.remove(id);
                if d.is_empty() {
                    state.disowned.remove(node);
                }
            }
            return Ok(recorded);
        };
        if result.output_len != job.row.output_len {
            eprintln!(
                "vk-hub: node {node}: job {id} ended with {} bytes of output, the hub holds {}",
                result.output_len, job.row.output_len
            );
        }
        result.output_len = job.row.output_len;
        if let Some(m) = result.message.as_mut() {
            *m = vk_hub_proto::display_safe(m);
        }
        // Enforce the node's bounds again and sanitize events for the web UI and CLI.
        result.events.truncate(vk_hub_proto::job::MAX_JOB_EVENTS);
        for event in &mut result.events {
            *event = vk_hub_proto::job::JobEvent::new(
                event.kind,
                event.count,
                &vk_hub_proto::display_safe_up_to(
                    &event.detail,
                    vk_hub_proto::job::MAX_JOB_EVENT_DETAIL,
                ),
            );
        }
        // Held to its bounds again, and never older than the report the hub already has.
        let stored = job.row.egress.take();
        result.egress = crate::egress::newest(stored, result.egress.take());
        // Audited only when the node or its images failed it, for an operator to see; its
        // record holds its node, result and events either way.
        let audited = matches!(
            result.failure,
            Some(FailureClass::System | FailureClass::ImagePull)
        );
        let message = result.message.clone().filter(|_| audited);
        let Some((mut row, events)) = finish(&mut state, id, result.failure, message) else {
            return Ok(recorded);
        };
        row.result = Some(result);
        state.finished.insert(id.to_string(), row.clone());
        (row, if audited { events } else { Vec::new() })
    };
    // Outside the lock: whoever waits on it does not wait on stderr.
    for event in row.result.iter().flat_map(|r| &r.events) {
        eprintln!("vk-hub: node {node}: job {id}: {event}");
    }
    persist(hub, id, row, events).await?;
    Ok(recorded)
}

/// A job's events in short, `virtio-fs stall ×2`, for its row in a table; `None` without any.
/// An uncounted event (count 0, from a peer that sent none) shows as once.
pub fn events_summary(events: &[vk_hub_proto::job::JobEvent]) -> Option<String> {
    if events.is_empty() {
        return None;
    }
    let named: Vec<String> = events
        .iter()
        .map(|e| format!("{} ×{}", e.kind.name(), e.count.max(1)))
        .collect();
    Some(named.join(", "))
}

// ---------------------------------------------------------------------------------------------
// Placement.

/// A node's room for `placement`'s envelope: how many it fits, `None` when it takes no
/// placed work now.
/// `placed` counts work as [`placed`] does; `extra` is additional work not in the heartbeat.
fn room(
    hub: &Hub,
    state: &State,
    node: &str,
    row: &NodeRow,
    placement: &Placement,
    placed: u64,
    extra: Option<Envelope>,
) -> Option<u64> {
    let link = state.links.get(node)?;
    if !link.held || hub.reach(node) != Reach::Connected {
        return None;
    }
    if !row.pools.contains(&placement.pool) {
        return None;
    }
    let inventory = row.inventory.as_ref()?;
    if !enforces_rules(hub, row) {
        return None;
    }
    if !placement
        .labels
        .iter()
        .all(|l| inventory.labels.contains(l))
    {
        return None;
    }
    let report = row.report.as_ref();
    if report
        .and_then(|r| r.state)
        .is_some_and(|s| s != NodeState::Ready)
    {
        return None;
    }
    // A host runs its own gitlab-runner or the hub's jobs, never both.
    if report
        .and_then(|r| r.placed.as_ref())
        .is_some_and(|p| p.runner.is_some())
    {
        return None;
    }
    let env = placement.envelope;
    if env.cpus > inventory.hardware.cpus {
        return None;
    }
    let below_cap = match placed_cap(row.desired.as_ref(), report) {
        Some(cap) => u64::from(cap).saturating_sub(placed),
        None => MAX_FITS,
    };
    let heartbeat = row.heartbeat.as_ref()?;
    let since = row.heartbeat_at.unwrap_or(0);
    // What the hub asked of it that its heartbeat does not show yet.
    let mut pending = Envelope::default();
    let mut add = |e: Envelope| {
        pending.mem_mib = pending.mem_mib.saturating_add(e.mem_mib);
        pending.disk_bytes = pending.disk_bytes.saturating_add(e.disk_bytes);
    };
    if let Some(e) = extra {
        add(e);
    }
    for r in state.reservations.values().filter(|r| r.node == node) {
        match r.phase {
            ResvPhase::Offered | ResvPhase::Abandoned => add(r.envelope),
            ResvPhase::Held { .. } if r.accepted_at >= since => add(r.envelope),
            _ => {}
        }
    }
    for j in state.jobs.values() {
        // On a reservation, the heartbeat counts it once it counts the reservation.
        if j.node() == Some(node)
            && j.row.state == JobState::Starting
            && (j.reservation.is_none() || j.reservation_accepted_at >= since)
        {
            add(j.row.placement.envelope);
        }
    }
    let mem_free = match heartbeat.admission.as_ref() {
        Some(a) if a.budget_mib.is_some() => {
            a.budget_mib.unwrap_or(0).saturating_sub(a.committed_mib)
        }
        _ => heartbeat.mem_available_mib?,
    }
    .saturating_sub(pending.mem_mib);
    let mut fits = below_cap.min(MAX_FITS);
    if let Some(n) = mem_free.checked_div(env.mem_mib) {
        fits = fits.min(n);
    }
    if let Some(free) = heartbeat
        .storage
        .iter()
        .filter(|f| f.role == StorageRole::Jobs)
        .map(|f| f.free_bytes)
        .max()
        && let Some(n) = free
            .saturating_sub(pending.disk_bytes)
            .checked_div(env.disk_bytes)
    {
        fits = fits.min(n);
    }
    (fits > 0).then_some(fits)
}

/// How much placed work `node` holds as the hub counts it against the node's ceiling, one
/// per job it will run: reservations offered and not refused (an offer abandoned is counted
/// until the node answers it), jobs sent to it and not finished, and jobs it named in its
/// `held` that the hub has disowned, until their result comes. A job submitted on a
/// reservation counts as the reservation until it is sent, as the job after.
fn placed(state: &State, node: &str) -> u64 {
    tallies(state).get(node).map_or(0, |t| t.placed)
}

/// A node's placed work, as [`placed`] counts it, and the vCPUs of that work: its reservations
/// not refused and the jobs sent to it and not finished. A disowned job's envelope is not known.
#[derive(Clone, Copy, Default)]
struct Tally {
    placed: u64,
    cpus: u64,
}

/// Every node's [`Tally`], in one pass over the dispatch state.
fn tallies(state: &State) -> HashMap<&str, Tally> {
    let mut by_node: HashMap<&str, Tally> = HashMap::new();
    let live = (state.reservations.values())
        .filter(|r| !matches!(r.phase, ResvPhase::Refused(_)))
        .map(|r| (r.node.as_str(), r.envelope.cpus));
    let sent =
        (state.jobs.values()).filter_map(|j| Some((j.node()?, j.row.placement.envelope.cpus)));
    for (node, cpus) in live.chain(sent) {
        let t = by_node.entry(node).or_default();
        t.placed = t.placed.saturating_add(1);
        t.cpus = t.cpus.saturating_add(u64::from(cpus));
    }
    for (node, jobs) in &state.disowned {
        let t = by_node.entry(node.as_str()).or_default();
        t.placed = t
            .placed
            .saturating_add(u64::try_from(jobs.len()).unwrap_or(u64::MAX));
    }
    by_node
}

/// How much placed work `node` holds as the hub counts it against its ceiling.
pub fn placed_on(hub: &Hub, node: &str) -> u64 {
    placed(&hub.dispatch.lock(), node)
}

/// A client instance's reservations and jobs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Reservations offered or held, not yet taken over by a job.
    pub reservations: usize,
    /// Jobs waiting to be placed.
    pub queued: usize,
    /// Jobs sent to a node and not finished.
    pub running: usize,
}

/// What each client instance holds, by key ID and instance: the empty instance for requests
/// that named none.
pub fn client_work(hub: &Hub) -> HashMap<(String, String), Work> {
    work_of(&hub.dispatch.lock())
}

/// [`client_work`] of `state`.
fn work_of(state: &State) -> HashMap<(String, String), Work> {
    fn of<'w>(
        work: &'w mut HashMap<(String, String), Work>,
        key: &str,
        instance: &Option<String>,
    ) -> &'w mut Work {
        let instance = instance.clone().unwrap_or_default();
        work.entry((key.to_string(), instance)).or_default()
    }
    let mut work = HashMap::new();
    // A reservation a job was submitted on counts as that job alone.
    let taken: HashSet<&str> = (state.jobs.values())
        .filter_map(|j| j.reservation.as_deref())
        .collect();
    for (id, r) in &state.reservations {
        if matches!(r.phase, ResvPhase::Offered | ResvPhase::Held { .. })
            && !taken.contains(id.as_str())
        {
            of(&mut work, &r.key, &r.instance).reservations += 1;
        }
    }
    for j in state.jobs.values() {
        let (key, instance) = (&j.row.key, &j.row.instance);
        match j.row.state {
            JobState::Queued => of(&mut work, key, instance).queued += 1,
            JobState::Starting | JobState::Running => of(&mut work, key, instance).running += 1,
            // A state from a newer hub's record says nothing of where the job stands.
            JobState::Finished | JobState::Other => {}
        }
    }
    work
}

/// Wake on the next [`Hub::changed`] of `node`, or change to what the hub has placed on it
/// ([`placed_on`]) or to why it refuses offers ([`last_refusal`]), which the hub notes only
/// as a change to dispatch at large: a task compares them on each such change, so a node's
/// page is not rendered for every other node's work.
pub fn subscribe_node_work(hub: &Arc<Hub>, node: &str) -> watch::Receiver<u64> {
    let mut changed = hub.subscribe_node(node);
    let mut dispatch = hub.dispatch.subscribe();
    let (tx, rx) = watch::channel(0u64);
    let (hub, node) = (hub.clone(), node.to_string());
    let work = move || {
        let state = hub.dispatch.lock();
        (placed(&state, &node), state.refusals.get(&node).cloned())
    };
    let mut shown = work();
    tokio::spawn(async move {
        loop {
            let ours = tokio::select! {
                () = tx.closed() => return,
                r = changed.changed() => match r {
                    Ok(()) => true,
                    Err(_) => return,
                },
                r = dispatch.changed() => match r {
                    Ok(()) => false,
                    Err(_) => return,
                },
            };
            let now = work();
            if !ours && now == shown {
                continue;
            }
            shown = now;
            tx.send_modify(|n| *n = n.wrapping_add(1));
        }
    });
    rx
}

/// The most placed work a node takes at once: the smaller of the operator's ceiling and the
/// node's own limit, which the node enforces too. A node older than reporting that limit has
/// it read from its runner's concurrency, the same `[executor.schedule] max_concurrency`.
pub fn placed_cap(desired: Option<&DesiredState>, report: Option<&Report>) -> Option<u32> {
    let own = report.and_then(|r| match &r.placed {
        Some(p) => p.limit,
        None => r.concurrency.and_then(|c| c.local_ceiling),
    });
    [desired.and_then(|d| d.ceiling), own]
        .into_iter()
        .flatten()
        .min()
}

/// Load for ordering candidates, in millionths: the maximum of `placed / (placed + room)`,
/// placed vCPUs per CPU, and the 1-minute load average per CPU. Omit the load average when
/// absent (older `vk`); CPU overcommit can put the ratio above one. The placed-work share
/// counts jobs of any size against room in this placement's envelopes, so mixed sizes make
/// it a heuristic, not the fraction of the node in use.
fn load(placed: u64, room: u64, placed_cpus: u64, cpus: u32, load1_hundredths: Option<u32>) -> u64 {
    const WHOLE: u64 = 1_000_000;
    let share = (placed.saturating_mul(WHOLE))
        .checked_div(placed.saturating_add(room))
        .unwrap_or(0);
    let cpus = u64::from(cpus);
    let committed = (placed_cpus.saturating_mul(WHOLE))
        .checked_div(cpus)
        .unwrap_or(0);
    let busy = load1_hundredths
        .and_then(|l| (u64::from(l).saturating_mul(WHOLE / 100)).checked_div(cpus))
        .unwrap_or(0);
    share.max(committed).max(busy)
}

/// Nodes with room for `placement`, excluding `skip`, with their room and [`Tally`].
fn rooms<'a>(
    hub: &Hub,
    state: &'a State,
    nodes: &'a [(String, NodeRow)],
    placement: &Placement,
    skip: &HashSet<String>,
) -> Vec<(&'a str, &'a NodeRow, u64, Tally)> {
    rooms_with(hub, state, nodes, placement, skip, &tallies(state))
}

/// [`rooms`], given the nodes' [`tallies`].
fn rooms_with<'a>(
    hub: &Hub,
    state: &'a State,
    nodes: &'a [(String, NodeRow)],
    placement: &Placement,
    skip: &HashSet<String>,
    tallies: &HashMap<&str, Tally>,
) -> Vec<(&'a str, &'a NodeRow, u64, Tally)> {
    nodes
        .iter()
        .filter(|(id, _)| !skip.contains(id))
        .filter_map(|(id, row)| {
            let tally = tallies.get(id.as_str()).copied().unwrap_or_default();
            let room = room(hub, state, id, row, placement, tally.placed, None)?;
            Some((id.as_str(), row, room, tally))
        })
        .collect()
}

/// Nodes with room for `placement`, excluding `skip`: least loaded first ([`load`]),
/// then most room, then by ID.
fn candidates(
    hub: &Hub,
    state: &State,
    nodes: &[(String, NodeRow)],
    placement: &Placement,
    skip: &HashSet<String>,
) -> Vec<(String, u64)> {
    let found = rooms(hub, state, nodes, placement, skip)
        .into_iter()
        .map(|(id, row, room, tally)| {
            let load = load(
                tally.placed,
                room,
                tally.cpus,
                row.inventory.as_ref().map_or(0, |i| i.hardware.cpus),
                row.heartbeat.as_ref().and_then(|h| h.load1_hundredths),
            );
            (id.to_string(), room, load)
        })
        .collect();
    least_loaded_first(found)
}

/// `(node, room, load)`s as `(node, room)`, least load first, then most room, then by node.
fn least_loaded_first(mut found: Vec<(String, u64, u64)>) -> Vec<(String, u64)> {
    found.sort_by(|(a, x, p), (b, y, q)| p.cmp(q).then_with(|| y.cmp(x)).then_with(|| a.cmp(b)));
    found.into_iter().map(|(id, room, _)| (id, room)).collect()
}

/// Placement key: the GitLab, project and checkout-built job and service image references
/// (`dockerfile:`, `compose:`). Used to prefer a node that last built those images;
/// `None` when all images are pulled.
fn image_key(spec: &JobSpec) -> Option<String> {
    let JobSpec::GitlabCi(ci) = spec;
    let built: Vec<&str> = std::iter::once(&ci.image)
        .chain(&ci.services)
        .map(|i| i.name.as_str())
        .filter(|n| n.starts_with("dockerfile:") || n.starts_with("compose:"))
        .collect();
    if built.is_empty() {
        return None;
    }
    Some(format!(
        "{}\n{}\n{}",
        ci.server_url,
        ci.job.project_path,
        built.join("\n")
    ))
}

/// Note that `node` used image `key` at `now`, forgetting the least recently used key past
/// [`MAX_IMAGE_KEYS`] and, under this key, nodes past [`MAX_IMAGE_IDLE_SECS`].
fn warm_touch(state: &mut State, key: String, node: &str, now: u64) {
    let nodes = state.warm.entry(key).or_default();
    nodes.retain(|_, at| now.saturating_sub(*at) < MAX_IMAGE_IDLE_SECS);
    warm_note(nodes, node, now);
    if state.warm.len() > MAX_IMAGE_KEYS
        && let Some(oldest) = (state.warm.iter())
            .min_by_key(|(_, nodes)| nodes.values().max().copied().unwrap_or(0))
            .map(|(k, _)| k.clone())
    {
        state.warm.remove(&oldest);
    }
}

/// Record `node`'s use of an image at `at` in `nodes`, preserving any later use.
fn warm_note(nodes: &mut HashMap<String, u64>, node: &str, at: u64) {
    let used = nodes.entry(node.to_string()).or_insert(at);
    *used = (*used).max(at);
}

/// Forget, as of `now`, uses past [`MAX_IMAGE_IDLE_SECS`] and, past [`MAX_IMAGE_KEYS`], the
/// keys used least recently: what [`warm_touch`] does for one key, for every key at once.
fn warm_prune(state: &mut State, now: u64) {
    state.warm.retain(|_, nodes| {
        nodes.retain(|_, at| now.saturating_sub(*at) < MAX_IMAGE_IDLE_SECS);
        !nodes.is_empty()
    });
    let excess = state.warm.len().saturating_sub(MAX_IMAGE_KEYS);
    if excess > 0 {
        let mut latest: Vec<(u64, String)> = (state.warm.iter())
            .map(|(k, nodes)| (nodes.values().max().copied().unwrap_or(0), k.clone()))
            .collect();
        latest.sort_unstable();
        for (_, key) in latest.into_iter().take(excess) {
            state.warm.remove(&key);
        }
    }
}

/// Whether a node that used an image at `used_at` still holds it at `now`, by its idle window
/// `idle_secs`.
fn still_warm(used_at: u64, idle_secs: u64, now: u64) -> bool {
    now.saturating_sub(used_at) < idle_secs.min(MAX_IMAGE_IDLE_SECS)
}

/// Sum vCPUs by node in one pass for jobs its 1-minute load average may not show yet:
/// those awaiting acceptance or accepted within [`RECENT_START_SECS`] of `now`.
fn recent_cpus(state: &State, now: u64) -> HashMap<&str, u64> {
    let mut by_node: HashMap<&str, u64> = HashMap::new();
    for j in state.jobs.values() {
        let recent = match j.row.state {
            JobState::Starting => true,
            JobState::Running => {
                (j.row.started_at).is_some_and(|t| now.saturating_sub(t) < RECENT_START_SECS)
            }
            _ => false,
        };
        if let Some(node) = j.node().filter(|_| recent) {
            let cpus = by_node.entry(node).or_default();
            *cpus = cpus.saturating_add(u64::from(j.row.placement.envelope.cpus));
        }
    }
    by_node
}

/// Load per CPU in millionths: the 1-minute load average plus `extra_cpus` busy CPUs,
/// divided by the node's CPU count. `None` without a load average or a CPU count.
fn load_per_cpu(load1_hundredths: Option<u32>, extra_cpus: u64, cpus: u32) -> Option<u64> {
    let load1 = u64::from(load1_hundredths?).saturating_mul(10_000);
    load1
        .saturating_add(extra_cpus.saturating_mul(1_000_000))
        .checked_div(u64::from(cpus))
}

/// Whether a node holding the image, at load `warm` per CPU (millionths, without the job), is
/// preferred for a job adding `job` per CPU, the least loaded candidate being at `least`.
fn prefer_warm(warm: u64, job: u64, least: u64, affinity: Affinity) -> bool {
    warm.saturating_add(job) < affinity.max_load
        && warm <= least.saturating_add(affinity.max_extra_load)
}

/// The nodes that still hold image `key` at `now`, by [`still_warm`] and their own idle
/// window.
fn warm_nodes(state: &State, nodes: &[(String, NodeRow)], key: &str, now: u64) -> HashSet<String> {
    let Some(used) = state.warm.get(key) else {
        return HashSet::new();
    };
    (nodes.iter())
        .filter(|(id, row)| {
            let idle = (row.report.as_ref())
                .and_then(|r| r.placed.as_ref())
                .and_then(|p| p.image_cache_idle_secs)
                .unwrap_or(DEFAULT_IMAGE_IDLE_SECS);
            used.get(id).is_some_and(|at| still_warm(*at, idle, now))
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// Of `warm`, the candidates in `found` preferred for a job of `cpus` vCPUs ([`prefer_warm`]):
/// each node's load being its load average plus [`recent_cpus`], per CPU; a node without a
/// load average is neither preferred nor counted as the least loaded.
fn preferred(
    state: &State,
    nodes: &[(String, NodeRow)],
    found: &[(String, u64)],
    warm: &HashSet<String>,
    cpus: u32,
    affinity: Affinity,
    now: u64,
) -> HashSet<String> {
    let rows: HashMap<&str, &NodeRow> = nodes.iter().map(|(id, r)| (id.as_str(), r)).collect();
    let recent = recent_cpus(state, now);
    let loads: Vec<(&str, u64, u64)> = (found.iter())
        .filter_map(|(id, _)| {
            let row = rows.get(id.as_str())?;
            let node_cpus = row.inventory.as_ref().map_or(0, |i| i.hardware.cpus);
            let load1 = row.heartbeat.as_ref().and_then(|h| h.load1_hundredths);
            let extra = recent.get(id.as_str()).copied().unwrap_or(0);
            let load = load_per_cpu(load1, extra, node_cpus)?;
            let job = load_per_cpu(Some(0), u64::from(cpus), node_cpus)?;
            Some((id.as_str(), load, job))
        })
        .collect();
    let Some(least) = loads.iter().map(|(_, load, _)| *load).min() else {
        return HashSet::new();
    };
    (loads.into_iter())
        .filter(|(id, load, job)| warm.contains(*id) && prefer_warm(*load, *job, least, affinity))
        .map(|(id, _, _)| id.to_string())
        .collect()
}

/// `found`, as [`candidates`] orders them, with the first node of `light` moved to the front.
fn warm_first(mut found: Vec<(String, u64)>, light: &HashSet<String>) -> Vec<(String, u64)> {
    if let Some(at) = found.iter().position(|(id, _)| light.contains(id)) {
        let warm = found.remove(at);
        found.insert(0, warm);
    }
    found
}

/// `POST /v1/capacity`'s answer for `placement`: the envelopes its nodes have room for, and
/// its revision, which moves when that does.
pub async fn capacity(hub: &Hub, placement: &Placement) -> Result<Capacity> {
    let nodes = blocking(hub, |db| db.nodes()).await?;
    let key = serde_json::to_string(placement).context("encoding a placement")?;
    let mut state = hub.dispatch.lock();
    let fits: u64 = rooms(hub, &state, &nodes, placement, &HashSet::new())
        .iter()
        .map(|(_, _, n, _)| n)
        .sum();
    let fits = u32::try_from(fits).unwrap_or(u32::MAX);
    let now = Instant::now();
    let revision = match state.capacity.get(&key) {
        Some(&(was, revision, _)) if was == fits => revision,
        _ => {
            state.capacity_revision = state
                .capacity_revision
                .saturating_add(1)
                .max(crate::now_secs().saturating_mul(1000));
            state.capacity_revision
        }
    };
    state.capacity.insert(key, (fits, revision, now));
    if state.capacity.len() > MAX_CAPACITY_ENTRIES
        && let Some(oldest) = (state.capacity.iter())
            .min_by_key(|(_, (_, _, asked))| *asked)
            .map(|(k, _)| k.clone())
    {
        state.capacity.remove(&oldest);
    }
    Ok(Capacity { revision, fits })
}

/// Refuse jobs on a hub that keeps no output for them.
pub fn accepting(hub: &Hub) -> Result<(), ApiError> {
    hub.dispatch.output_dir().map(|_| ())
}

/// Refuse a new job on a hub that holds [`MAX_LIVE_JOBS`] not finished.
pub fn room_for_job(hub: &Hub) -> Result<(), ApiError> {
    if hub.dispatch.lock().jobs.len() >= MAX_LIVE_JOBS {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            format!("the hub holds {MAX_LIVE_JOBS} jobs not finished"),
        )
        .retry_after(BUSY_RETRY_SECS));
    }
    Ok(())
}

/// Mark `request` as being served, or refuse a second attempt racing the first.
pub fn begin_request<'a>(hub: &'a Hub, request: &str) -> Result<InFlight<'a>, ApiError> {
    let mut state = hub.dispatch.lock();
    if !state.inflight.insert(request.to_string()) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "this request is already being served",
        )
        .retry_after(1));
    }
    Ok(InFlight {
        hub,
        request: request.to_string(),
    })
}

/// A request being served; it ends when this is dropped.
pub struct InFlight<'a> {
    hub: &'a Hub,
    request: String,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.hub.dispatch.lock().inflight.remove(&self.request);
    }
}

pub struct QueueRequest<'a> {
    pub request_id: &'a str,
    pub digest: &'a str,
    pub identity: ResolvedIdentity,
    pub placement: Placement,
    pub lease_secs: u32,
    pub queued: bool,
}

/// Make room for a new ticket without evicting a live admission or pending write.
fn evict_finished(state: &mut State, limit: usize) -> bool {
    while state.tickets.len() >= limit {
        if state.admission_changes.len() >= MAX_RETAINED_TICKETS {
            return false;
        }
        let oldest = state
            .tickets
            .iter()
            .filter(|(id, ticket)| {
                matches!(ticket.phase, TicketPhase::Finished(_))
                    && !state.pending_admissions.contains(*id)
            })
            .min_by_key(|(id, ticket)| (ticket.polled, *id))
            .map(|(id, _)| id.clone());
        let Some(id) = oldest else { return false };
        state.tickets.remove(&id);
        state.admission_changes.push((id, None));
    }
    true
}

pub fn queue_reservation(
    hub: &Hub,
    principal: &ApiPrincipal,
    ask: QueueRequest<'_>,
) -> Result<String, ApiError> {
    let QueueRequest {
        request_id,
        digest,
        identity,
        placement,
        lease_secs,
        queued,
    } = ask;
    hub.dispatch.output_dir()?;
    let session = if principal.is_relay() {
        Some(hub.current_session(&principal.id).ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "relay session is not connected",
            )
        })?)
    } else {
        None
    };
    let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
    let mut state = hub.dispatch.lock();
    if session.is_some_and(|session| !hub.is_current(&principal.id, session)) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "relay session changed",
        ));
    }
    if let Some((id, ticket)) = state
        .tickets
        .iter()
        .find(|(_, t)| t.key == principal.id && t.request_id == request_id)
    {
        return if ticket.digest == digest {
            Ok(id.clone())
        } else {
            Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "request ID already used",
            ))
        };
    }
    let waiting = state
        .tickets
        .values()
        .filter(|t| {
            t.key == principal.id
                && t.identity.runner == identity.runner
                && matches!(
                    t.phase,
                    TicketPhase::Waiting
                        | TicketPhase::Offering { .. }
                        | TicketPhase::Granted { .. }
                )
        })
        .count();
    let active = state
        .tickets
        .values()
        .filter(|t| !matches!(t.phase, TicketPhase::Finished(_)));
    let principal_active = active.clone().filter(|t| t.key == principal.id).count();
    let runner_limit = usize::try_from(identity.request_concurrency)
        .unwrap_or(usize::MAX)
        .min(MAX_PRINCIPAL_TICKETS);
    if active.count() >= MAX_TICKETS
        || principal_active >= MAX_PRINCIPAL_TICKETS
        || waiting >= runner_limit
        || !evict_finished(&mut state, MAX_RETAINED_TICKETS)
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "reservation queue is full",
        )
        .retry_after(1));
    }
    let now = Instant::now();
    state.tickets.insert(
        id.clone(),
        Ticket {
            key: principal.id.clone(),
            instance: principal.instance.clone(),
            queued,
            request_id: request_id.to_owned(),
            digest: digest.to_owned(),
            identity,
            placement,
            lease_secs: lease_secs.clamp(1, MAX_LEASE_SECS),
            created: now,
            polled: now,
            phase: TicketPhase::Waiting,
            probe: false,
            reservation: None,
            session,
            claimed_at: None,
            tried: HashSet::new(),
            round_ended: None,
            blocked: None,
        },
    );
    drop(state);
    hub.dispatch.bump();
    Ok(id)
}

pub fn poll_ticket(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
) -> Result<Option<ReservationGrant>, ApiError> {
    let mut state = hub.dispatch.lock();
    let ticket = state.tickets.get_mut(id).ok_or_else(|| gone(id))?;
    if ticket.key != principal.id {
        return Err(not_found("no such ticket"));
    }
    if matches!(
        ticket.phase,
        TicketPhase::Waiting | TicketPhase::Offering { .. } | TicketPhase::Granted { .. }
    ) {
        ticket.polled = Instant::now();
    }
    let queued = ticket.queued;
    let (reservation, accepted) = match &ticket.phase {
        TicketPhase::Waiting | TicketPhase::Offering { .. } => return Ok(None),
        TicketPhase::Granted {
            reservation,
            accepted,
        } => (reservation.clone(), *accepted),
        _ => return Err(gone(id)),
    };
    let r = state
        .reservations
        .get(&reservation)
        .ok_or_else(|| gone(&reservation))?;
    let ResvPhase::Held { lease_secs } = r.phase else {
        return Err(gone(&reservation));
    };
    let elapsed = u32::try_from(accepted.elapsed().as_secs())
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let remaining = lease_secs.saturating_sub(elapsed);
    if remaining == 0 {
        return Err(gone(&reservation));
    }
    Ok(Some(ReservationGrant {
        reservation,
        node: r.node.clone(),
        envelope: r.envelope,
        lease_secs: if queued { remaining } else { lease_secs },
        admission: Some(id.to_owned()),
    }))
}

pub fn cancel_ticket(hub: &Hub, principal: &ApiPrincipal, id: &str) -> Result<(), ApiError> {
    let mut state = hub.dispatch.lock();
    if state.pending_admissions.contains(id) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "admission is being updated",
        )
        .retry_after(1));
    }
    let Some(ticket) = state.tickets.get_mut(id) else {
        return Ok(());
    };
    if ticket.key != principal.id {
        return Err(not_found("no such ticket"));
    }
    let reservation = match &ticket.phase {
        TicketPhase::Offering { reservation, .. } | TicketPhase::Granted { reservation, .. } => {
            Some(reservation.clone())
        }
        TicketPhase::Claimed { .. } | TicketPhase::Job => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "admission has already been claimed",
            ));
        }
        _ => None,
    };
    let probe = ticket
        .probe
        .then(|| {
            ticket
                .identity
                .gitlab
                .clone()
                .zip(ticket.identity.runner_id)
        })
        .flatten();
    let retain = ticket.queued;
    ticket.phase = TicketPhase::Finished(AdmissionOutcome::Released);
    ticket.probe = false;
    if !retain {
        state.tickets.remove(id);
    }
    if let Some(id) = reservation {
        discard_ticket_reservation(&mut state, &id, probe);
    }
    drop(state);
    hub.dispatch.bump();
    Ok(())
}

fn discard_ticket_reservation(state: &mut State, id: &str, probe: Option<(String, u64)>) {
    let Some(reservation) = state.reservations.get_mut(id) else {
        return;
    };
    let node = reservation.node.clone();
    if matches!(reservation.phase, ResvPhase::Offered) {
        reservation.phase = ResvPhase::Abandoned;
        if let Some(probe) = probe {
            state
                .abandoned_probes
                .insert(id.to_owned(), (probe, Instant::now()));
        }
    } else {
        state.reservations.remove(id);
    }
    send(
        state,
        &node,
        HubJobMsg::Release {
            reservation: id.to_owned(),
        },
    );
}

/// End a relay's outstanding offers when its session ends. Claimed admissions remain
/// charged until the relay reports their outcome or reconciles on reconnect.
pub fn relay_disconnected(hub: &Hub, relay: &str, session: u64) {
    let mut state = hub.dispatch.lock();
    let mut reservations = Vec::new();
    for ticket in state.tickets.values_mut() {
        if ticket.key != relay || ticket.session != Some(session) {
            continue;
        }
        match &ticket.phase {
            TicketPhase::Waiting => {
                ticket.phase = TicketPhase::Finished(AdmissionOutcome::Released)
            }
            TicketPhase::Offering { reservation, .. }
            | TicketPhase::Granted { reservation, .. } => {
                let probe = ticket
                    .probe
                    .then(|| {
                        ticket
                            .identity
                            .gitlab
                            .clone()
                            .zip(ticket.identity.runner_id)
                    })
                    .flatten();
                reservations.push((reservation.clone(), probe));
                ticket.phase = TicketPhase::Finished(AdmissionOutcome::Released);
                ticket.probe = false;
            }
            TicketPhase::Claimed { reservation } => reservations.push((reservation.clone(), None)),
            _ => {}
        }
    }
    for (id, probe) in reservations {
        discard_ticket_reservation(&mut state, &id, probe);
    }
    drop(state);
    hub.dispatch.bump();
}

pub async fn claim(
    hub: &Arc<Hub>,
    principal: &ApiPrincipal,
    reservation: &str,
) -> Result<(), ApiError> {
    let (hub, principal, reservation) = (hub.clone(), principal.clone(), reservation.to_owned());
    tokio::task::spawn_blocking(move || claim_blocking(&hub, &principal, &reservation))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))?
}

fn claim_blocking(hub: &Hub, principal: &ApiPrincipal, reservation: &str) -> Result<(), ApiError> {
    let mut state = hub.dispatch.lock();
    if state.tickets.values().any(|t| {
        t.key == principal.id
            && matches!(&t.phase, TicketPhase::Claimed { reservation: r } if r == reservation)
    }) {
        return Ok(());
    }
    let live = state
        .reservations
        .get(reservation)
        .is_some_and(|r| r.key == principal.id && matches!(r.phase, ResvPhase::Held { .. }));
    let lease_deadline = state.tickets.values().find_map(|t| {
        if t.key != principal.id {
            return None;
        }
        let TicketPhase::Granted {
            reservation: r,
            accepted,
        } = &t.phase
        else {
            return None;
        };
        if r != reservation {
            return None;
        }
        let held = state.reservations.get(r)?;
        let ResvPhase::Held { lease_secs } = held.phase else {
            return None;
        };
        Some(*accepted + Duration::from_secs(u64::from(lease_secs.saturating_sub(1))))
    });
    if !live || lease_deadline.is_none_or(|deadline| Instant::now() >= deadline) {
        return Err(gone(reservation));
    }
    let (id, ticket) = state
        .tickets
        .iter_mut()
        .find(|(_, t)| {
            t.key == principal.id
                && match &t.phase {
                    TicketPhase::Granted { reservation: r, .. }
                    | TicketPhase::Claimed { reservation: r } => r == reservation,
                    _ => false,
                }
        })
        .ok_or_else(|| not_found("no such grant"))?;
    let id = id.clone();
    let stored = crate::store::StoredAdmission {
        principal: ticket.key.clone(),
        identity: crate::store::SchedulingIdentity {
            tenant: ticket.identity.tenant.clone(),
            class: ticket.identity.class,
            gitlab: ticket.identity.gitlab.clone(),
            runner_id: ticket.identity.runner_id,
        },
        runner: ticket.identity.runner.clone(),
        placement: ticket.placement.clone(),
        probe: ticket.probe,
        reservation: reservation.to_owned(),
        outcome: None,
    };
    if !state.pending_admissions.insert(id.clone()) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "admission is being updated",
        )
        .retry_after(1));
    }
    drop(state);
    let persisted = hub.db.put_admission(&id, &stored);
    let mut state = hub.dispatch.lock();
    if let Err(error) = persisted {
        state.pending_admissions.remove(&id);
        return Err(error.into());
    }
    let valid = lease_deadline.is_some_and(|deadline| Instant::now() < deadline)
        && state
            .reservations
            .get(reservation)
            .is_some_and(|r| r.key == principal.id && matches!(r.phase, ResvPhase::Held { .. }))
        && state.tickets.get(&id).is_some_and(
            |t| matches!(&t.phase, TicketPhase::Granted { reservation: r, .. } if r == reservation),
        );
    if !valid {
        let probe = state.tickets.get_mut(&id).and_then(|ticket| {
            let probe = ticket
                .probe
                .then(|| {
                    ticket
                        .identity
                        .gitlab
                        .clone()
                        .zip(ticket.identity.runner_id)
                })
                .flatten();
            ticket.phase = TicketPhase::Finished(AdmissionOutcome::Released);
            ticket.probe = false;
            probe
        });
        discard_ticket_reservation(&mut state, reservation, probe);
        drop(state);
        let removed = hub.db.remove_admission(&id);
        let mut state = hub.dispatch.lock();
        state.pending_admissions.remove(&id);
        if let Err(error) = removed {
            eprintln!("vk-hub: removing invalid claim {id}: {error:#}");
            state.admission_changes.push((id, None));
        }
        drop(state);
        hub.dispatch.bump();
        return Err(gone(reservation));
    }
    state.pending_admissions.remove(&id);
    // Validated under this lock just above.
    let Some(ticket) = state.tickets.get_mut(&id) else {
        return Err(gone(reservation));
    };
    ticket.phase = TicketPhase::Claimed {
        reservation: reservation.to_owned(),
    };
    // Claimed in the relay's current session, whose heartbeats must list it from now on.
    if principal.is_relay() {
        ticket.session = hub.current_session(&principal.id).or(ticket.session);
    }
    ticket.claimed_at = Some(Instant::now());
    Ok(())
}

pub fn check_admission(
    hub: &Hub,
    principal: &ApiPrincipal,
    admission: Option<&str>,
    reservation: Option<&str>,
    identity: &ResolvedIdentity,
    placement: &Placement,
) -> Result<(), ApiError> {
    let state = hub.dispatch.lock();
    if let Some(id) = admission {
        let ticket = state
            .tickets
            .get(id)
            .filter(|t| t.key == principal.id)
            .ok_or_else(|| not_found("no such admission"))?;
        if !(matches!(ticket.phase, TicketPhase::Claimed { .. } | TicketPhase::Job)
            || !ticket.queued
                && matches!(
                    ticket.phase,
                    TicketPhase::Granted { .. } | TicketPhase::Finished(_)
                ))
            || ticket.identity.tenant != identity.tenant
            || ticket.identity.class != identity.class
            || ticket.identity.gitlab != identity.gitlab
            || ticket.identity.runner_id != identity.runner_id
            || ticket.placement != *placement
            || reservation.is_some_and(|r| ticket.reservation.as_deref() != Some(r))
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                "job does not match its admission",
            ));
        }
    } else if reservation.is_some_and(|r| {
        state
            .tickets
            .values()
            .any(|t| t.queued && t.reservation.as_deref() == Some(r))
    }) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "queued reservation requires its admission",
        ));
    }
    Ok(())
}

pub fn admission_identity(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
) -> Result<ResolvedIdentity, ApiError> {
    let state = hub.dispatch.lock();
    let ticket = state
        .tickets
        .get(id)
        .filter(|t| {
            t.key == principal.id
                && (matches!(t.phase, TicketPhase::Claimed { .. } | TicketPhase::Job)
                    || !t.queued
                        && matches!(
                            t.phase,
                            TicketPhase::Granted { .. } | TicketPhase::Finished(_)
                        ))
        })
        .ok_or_else(|| not_found("no such admission"))?;
    Ok(ticket.identity.clone())
}

pub fn unqueued_admission(
    hub: &Hub,
    principal: &ApiPrincipal,
    reservation: Option<&str>,
) -> Option<String> {
    let state = hub.dispatch.lock();
    let reservation = reservation?;
    state
        .tickets
        .iter()
        .find(|(_, t)| {
            !t.queued && t.key == principal.id && t.reservation.as_deref() == Some(reservation)
        })
        .map(|(id, _)| id.clone())
}

pub async fn admission_took_job(
    hub: &Arc<Hub>,
    principal: &ApiPrincipal,
    id: &str,
) -> Result<(), ApiError> {
    let (hub, principal, id) = (hub.clone(), principal.clone(), id.to_owned());
    tokio::task::spawn_blocking(move || admission_took_job_blocking(&hub, &principal, &id))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))?
}

fn admission_took_job_blocking(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
) -> Result<(), ApiError> {
    let mut state = hub.dispatch.lock();
    let ticket = state.tickets.get(id).filter(|t| t.key == principal.id);
    let Some(ticket) = ticket else {
        return Ok(());
    };
    let previous = ticket.phase.clone();
    let eligible = matches!(
        ticket.phase,
        TicketPhase::Granted { .. } | TicketPhase::Claimed { .. }
    ) || !ticket.queued && matches!(ticket.phase, TicketPhase::Finished(_));
    if !eligible {
        return Ok(());
    }
    if !state.pending_admissions.insert(id.to_owned()) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "admission is being updated",
        )
        .retry_after(1));
    }
    drop(state);
    let result = hub.db.update_admission_outcome(id, AdmissionOutcome::Job);
    let mut state = hub.dispatch.lock();
    let stored = match result {
        Ok(stored) => stored,
        Err(error) => {
            state.pending_admissions.remove(id);
            return Err(error.into());
        }
    };
    let unchanged = state
        .tickets
        .get(id)
        .is_some_and(|t| t.key == principal.id && t.phase == previous)
        && match &previous {
            TicketPhase::Granted { reservation, .. } => {
                state.reservations.get(reservation).is_some_and(|r| {
                    r.key == principal.id && matches!(r.phase, ResvPhase::Held { .. })
                })
            }
            _ => true,
        };
    if !unchanged {
        drop(state);
        let restored = match stored {
            Some(stored) => hub.db.restore_admission_if_present(id, &stored),
            None => Ok(()),
        };
        let mut state = hub.dispatch.lock();
        state.pending_admissions.remove(id);
        restored?;
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "admission changed while saving",
        ));
    }
    state.pending_admissions.remove(id);
    // Found unchanged under this lock just above.
    let Some(ticket) = state.tickets.get_mut(id) else {
        return Err(not_found("no such admission"));
    };
    ticket.phase = TicketPhase::Job;
    ticket.probe = false;
    drop(state);
    hub.dispatch.bump();
    Ok(())
}

pub async fn outcome(
    hub: &Arc<Hub>,
    principal: &ApiPrincipal,
    id: &str,
    outcome: AdmissionOutcome,
) -> Result<(), ApiError> {
    let (hub, principal, id) = (hub.clone(), principal.clone(), id.to_owned());
    tokio::task::spawn_blocking(move || outcome_blocking(&hub, &principal, &id, outcome))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))?
}

fn outcome_blocking(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
    outcome: AdmissionOutcome,
) -> Result<(), ApiError> {
    let policy = hub.db.capacity_policy()?;
    let mut state = hub.dispatch.lock();
    let ticket = state
        .tickets
        .get_mut(id)
        .filter(|t| t.key == principal.id)
        .ok_or_else(|| not_found("no such admission"))?;
    let permitted = matches!(ticket.phase, TicketPhase::Claimed { .. })
        || matches!(ticket.phase, TicketPhase::Granted { .. })
            && outcome == AdmissionOutcome::Released
        || matches!(ticket.phase, TicketPhase::Job)
            && matches!(outcome, AdmissionOutcome::Job | AdmissionOutcome::Empty)
        || matches!(ticket.phase, TicketPhase::Finished(previous) if previous == outcome);
    if !permitted {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "admission outcome conflicts with its state",
        ));
    }
    if !state.pending_admissions.insert(id.to_owned()) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "admission is being updated",
        )
        .retry_after(1));
    }
    drop(state);
    let result = hub.db.update_admission_outcome(id, outcome);
    let mut state = hub.dispatch.lock();
    state.pending_admissions.remove(id);
    result?;
    let ticket = state
        .tickets
        .get_mut(id)
        .filter(|t| t.key == principal.id)
        .ok_or_else(|| not_found("no such admission"))?;
    let release = (outcome != AdmissionOutcome::Job)
        .then(|| ticket.reservation.clone())
        .flatten();
    match &ticket.phase {
        TicketPhase::Claimed { .. } => {
            ticket.phase = if outcome == AdmissionOutcome::Job {
                TicketPhase::Job
            } else {
                TicketPhase::Finished(outcome)
            }
        }
        TicketPhase::Granted { .. } if outcome == AdmissionOutcome::Released => {
            ticket.phase = TicketPhase::Finished(outcome);
        }
        TicketPhase::Job if outcome == AdmissionOutcome::Job => return Ok(()),
        TicketPhase::Job if outcome == AdmissionOutcome::Empty => {
            ticket.phase = TicketPhase::Finished(outcome)
        }
        TicketPhase::Finished(previous) if *previous == outcome => return Ok(()),
        _ => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "admission outcome conflicts with its state",
            ));
        }
    }
    let runner = ticket
        .identity
        .gitlab
        .clone()
        .zip(ticket.identity.runner_id);
    ticket.probe = false;
    if let Some(runner) = runner {
        let demand = state.demand.entry(runner).or_default();
        let now = Instant::now();
        match outcome {
            AdmissionOutcome::Job => {
                demand.empty_count = 0;
                demand.error_count = 0;
                demand.backoff_until = None;
                demand.busy_until = Some(now + Duration::from_secs(policy.busy_secs));
            }
            AdmissionOutcome::Empty | AdmissionOutcome::Error => {
                demand.busy_until = None;
                let count = match outcome {
                    AdmissionOutcome::Empty => {
                        demand.empty_count = demand.empty_count.saturating_add(1);
                        demand.error_count = 0;
                        demand.empty_count
                    }
                    AdmissionOutcome::Error => {
                        demand.error_count = demand.error_count.saturating_add(1);
                        demand.error_count
                    }
                    _ => 0,
                };
                // Admission IDs are random. Use all of their low 64 bits so the range
                // remains spread even when the exponential backoff reaches its cap.
                let sample = id
                    .get(id.len().saturating_sub(16)..)
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0);
                let delay = backoff_delay(
                    policy.backoff_initial_secs,
                    policy.backoff_max_secs,
                    count,
                    sample,
                );
                demand.backoff_until = Some(now + delay);
            }
            AdmissionOutcome::Released => {}
        }
    }
    if let Some(id) = release
        && let Some(r) = state.reservations.remove(&id)
    {
        send(&state, &r.node, HubJobMsg::Release { reservation: id });
    }
    drop(state);
    hub.dispatch.bump();
    Ok(())
}

/// The backoff after the `count`th empty or failed request in a row: `initial_secs` doubled
/// for each after the first, at most `max_secs`, then spread ±25% by `sample` without passing
/// `max_secs`.
fn backoff_delay(initial_secs: u64, max_secs: u64, count: u32, sample: u64) -> Duration {
    let factor = 1u64 << count.saturating_sub(1).min(31);
    let base = initial_secs.saturating_mul(factor).min(max_secs);
    let base_ms = base.saturating_mul(1000);
    let low = base_ms.saturating_sub(base_ms / 4);
    let high = base_ms
        .saturating_add(base_ms / 4)
        .min(max_secs.saturating_mul(1000))
        .max(low);
    Duration::from_millis(low + sample % (high - low + 1))
}

fn gone(id: &str) -> ApiError {
    ApiError::new(
        StatusCode::GONE,
        ErrorCode::ReservationGone,
        format!("reservation {id} lapsed, was released, or its node was lost"),
    )
}

fn not_found(what: &str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, what)
}

/// Extend `principal`'s reservation `id` to `lease_secs` from now: the lease the node
/// granted.
pub async fn renew(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
    lease_secs: u32,
) -> Result<ReservationGrant, ApiError> {
    let lease_secs = lease_secs.clamp(1, MAX_LEASE_SECS);
    let (seen, node, envelope) = {
        let state = hub.dispatch.lock();
        let Some(r) = state.reservations.get(id) else {
            return Err(gone(id));
        };
        if r.key != principal.id {
            return Err(not_found(&format!("no reservation {id}")));
        }
        if !matches!(r.phase, ResvPhase::Held { .. }) {
            return Err(gone(id));
        }
        let msg = HubJobMsg::Renew {
            reservation: id.to_string(),
            lease_secs,
        };
        if !send(&state, &r.node, msg) {
            return Err(gone(id));
        }
        (r.leases, r.node.clone(), r.envelope)
    };
    let deadline = Instant::now() + RENEW_TIMEOUT;
    loop {
        let mut changed = hub.dispatch.subscribe();
        {
            let state = hub.dispatch.lock();
            match state.reservations.get(id) {
                None => return Err(gone(id)),
                Some(r) if r.leases != seen => {
                    let ResvPhase::Held { lease_secs } = r.phase else {
                        return Err(gone(id));
                    };
                    return Ok(ReservationGrant {
                        reservation: id.to_string(),
                        node,
                        envelope,
                        lease_secs,
                        admission: None,
                    });
                }
                Some(_) if Instant::now() >= deadline => {
                    return Err(ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        ErrorCode::Unavailable,
                        "the node did not answer the renewal in time",
                    )
                    .retry_after(1));
                }
                Some(_) => {}
            }
        }
        tokio::select! {
            _ = changed.changed() => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
    }
}

/// Give back `principal`'s reservation `id`, if it is still held.
pub fn release(hub: &Hub, principal: &ApiPrincipal, id: &str) -> Result<(), ApiError> {
    let mut state = hub.dispatch.lock();
    let Some(r) = state.reservations.get(id) else {
        return Ok(());
    };
    if r.key != principal.id {
        return Err(not_found(&format!("no reservation {id}")));
    }
    let node = r.node.clone();
    state.reservations.remove(id);
    send(
        &state,
        &node,
        HubJobMsg::Release {
            reservation: id.to_string(),
        },
    );
    drop(state);
    hub.dispatch.bump();
    Ok(())
}

/// Take job `id`, recorded as `row`, with its `spec`, to start on `reservation` or be placed
/// within `place_within`; `mint_key` is its relay's ID. The caller has recorded it.
pub fn admit(
    hub: &Hub,
    id: &str,
    row: JobRow,
    spec: JobSpec,
    reservation: Option<String>,
    place_within: Duration,
    mint_key: Option<String>,
) {
    let limit = match &spec {
        JobSpec::GitlabCi(ci) => ci.trace.limit_bytes,
    };
    let limit = if limit == 0 {
        DEFAULT_OUTPUT_LIMIT
    } else {
        limit
    };
    let image_key = image_key(&spec);
    let mut state = hub.dispatch.lock();
    let reservation = reservation.filter(|r| {
        state
            .reservations
            .get(r)
            .is_some_and(|x| x.key == row.key && matches!(x.phase, ResvPhase::Held { .. }))
    });
    state.jobs.insert(
        id.to_string(),
        LiveJob {
            row,
            spec: Some(Arc::new(spec)),
            reservation,
            deadline: Instant::now() + place_within,
            tried: HashSet::new(),
            round_ended: None,
            blocked: None,
            output_cap: limit.saturating_add(OUTPUT_SLACK).min(MAX_OUTPUT),
            reservation_accepted_at: 0,
            image_key,
            mint_key,
            egress: EgressWritten::default(),
        },
    );
    drop(state);
    hub.dispatch.bump();
    hub.jobs_changed();
}

/// The view of `principal`'s job `id`, with the row, or 404.
pub async fn view(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
) -> Result<(JobView, JobRow), ApiError> {
    let live = {
        let state = hub.dispatch.lock();
        (state.jobs.get(id).map(|j| &j.row))
            .or_else(|| state.finished.get(id))
            .cloned()
    };
    let row = match live {
        Some(row) => row,
        None => {
            let job = id.to_string();
            blocking(hub, move |db| db.job(&job))
                .await?
                .ok_or_else(|| not_found(&format!("no job {id}")))?
        }
    };
    if row.key != principal.id {
        return Err(not_found(&format!("no job {id}")));
    }
    Ok((row.view(id, row.output_len), row))
}

/// Up to `max` bytes of `principal`'s job `id`'s output from `offset`, the output's length,
/// and whether the job has finished. An offset past the end is the length, as an error.
pub async fn output(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
    offset: u64,
    max: usize,
) -> Result<(Vec<u8>, u64, bool), OutputError> {
    let (_, row) = view(hub, principal, id).await?;
    if row.settled_at.is_some() {
        return Err(not_found(&format!("job {id} was settled; its output is gone")).into());
    }
    if row.expired_at.is_some() {
        let gone = format!("job {id} was never settled; its output is gone");
        return Err(not_found(&gone).into());
    }
    let len = row.output_len;
    if offset > len {
        return Err(OutputError::PastEnd(len));
    }
    let dir = hub.dispatch.output_dir()?.to_path_buf();
    let want = usize::try_from(len.saturating_sub(offset))
        .unwrap_or(usize::MAX)
        .min(max);
    let job = id.to_string();
    let bytes = tokio::task::spawn_blocking(move || read_output(&dir, &job, offset, want))
        .await
        .map_err(|e| ApiError::from(anyhow!(e)))?
        .map_err(ApiError::from)?;
    Ok((bytes, len, row.state == JobState::Finished))
}

/// Why an output read failed.
pub enum OutputError {
    Api(ApiError),
    /// The offset is past the output's end, this long.
    PastEnd(u64),
}

impl From<ApiError> for OutputError {
    fn from(e: ApiError) -> Self {
        OutputError::Api(e)
    }
}

/// Cancel `principal`'s job `id` with `mode`: its view after.
pub async fn cancel(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
    mode: CancelMode,
) -> Result<JobView, ApiError> {
    // A mode this hub does not know is immediate, so no other is stored or sent.
    let mode = match mode {
        CancelMode::Graceful => CancelMode::Graceful,
        _ => CancelMode::Immediate,
    };
    let actor = principal.actor();
    let write = {
        let mut state = hub.dispatch.lock();
        let queued = state
            .jobs
            .get(id)
            .is_some_and(|j| j.row.key == principal.id && j.row.state == JobState::Queued);
        if queued {
            // No node can have started it.
            if let Some(job) = state.jobs.get_mut(id) {
                job.row.cancel = Some(mode);
            }
        }
        match state.jobs.get_mut(id) {
            None => None,
            Some(job) if job.row.key != principal.id => {
                return Err(not_found(&format!("no job {id}")));
            }
            Some(_) if queued => {
                // A cancel's ending is unaudited: the actor's line stands for it.
                let (row, _) = finish(&mut state, id, Some(FailureClass::Canceled), None)
                    .ok_or_else(|| not_found(&format!("no job {id}")))?;
                let event = format!("{actor} canceled job {id} before it was placed");
                Some((row, vec![(None, actor.clone(), event)]))
            }
            Some(job) => {
                let stronger = matches!(
                    (job.row.cancel, mode),
                    (None, _) | (Some(CancelMode::Graceful), CancelMode::Immediate)
                );
                if stronger {
                    job.row.cancel = Some(mode);
                    job.row.revision = job.row.revision.saturating_add(1);
                    let node = job.row.node.clone();
                    let row = job.row.clone();
                    if let Some(node) = &node {
                        send(
                            &state,
                            node,
                            HubJobMsg::Cancel {
                                job: id.to_string(),
                                mode,
                            },
                        );
                    }
                    let how = match mode {
                        CancelMode::Graceful => "gracefully",
                        _ => "immediately",
                    };
                    Some((
                        row,
                        vec![(
                            node,
                            actor.clone(),
                            format!("{actor} canceled job {id} {how}"),
                        )],
                    ))
                } else {
                    None
                }
            }
        }
    };
    if let Some((row, events)) = write {
        persist(hub, id, row, events).await?;
        hub.dispatch.bump();
    }
    Ok(view(hub, principal, id).await?.0)
}

/// Settle `principal`'s finished job `id`: delete its output file and keep its record.
/// For failed jobs, retain the output tail ([`Dispatch::kept_failure_output`]) with the
/// record so the failure details remain readable; for others, a tail
/// ([`Dispatch::kept_output`]) in the hub's bounded cache of them.
pub async fn settle(hub: &Hub, principal: &ApiPrincipal, id: &str) -> Result<(), ApiError> {
    let (_, mut row) = view(hub, principal, id).await?;
    if row.state != JobState::Finished {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            format!("job {id} has not finished"),
        ));
    }
    if row.settled_at.is_some() {
        return Ok(());
    }
    let dir = hub.dispatch.output_dir()?.to_path_buf();
    // `None`: kept with the record, outside the cache.
    let (keep, cache) = match row.outcome() {
        JobOutcome::Failed => (hub.dispatch.kept_failure_output, None),
        _ => {
            // The total counts the tail as stored: one byte more than it reads, when it does
            // not compress.
            let total = hub.dispatch.kept_output_total;
            let keep = hub.dispatch.kept_output.min(total.saturating_sub(1));
            (keep, Some(total))
        }
    };
    if keep > 0 {
        // Kept before the file goes: a hub stopped in between keeps it when settled again.
        let (dir, job, len) = (dir.clone(), id.to_string(), row.output_len);
        blocking(hub, move |db| {
            let tail = output_tail(&dir, &job, len, keep)?;
            if !tail.is_empty() {
                match cache {
                    None => db.keep_job_tail(&job, &tail)?,
                    Some(total) => db.cache_job_tail(&job, &tail, total)?,
                };
            }
            Ok(())
        })
        .await?;
    }
    let path = output_path(&dir, id);
    tokio::task::spawn_blocking(move || match std::fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(anyhow!(e).context(format!("removing {}", path.display())))
        }
        _ => Ok(()),
    })
    .await
    .map_err(|e| ApiError::from(anyhow!(e)))??;
    row.settled_at = Some(crate::now_secs());
    row.revision = row.revision.saturating_add(1);
    let admission = row.admission.clone();
    // Unaudited: a producer settles every job it ran.
    persist(hub, id, row, Vec::new()).await?;
    if let Some(id) = admission
        && let Some(ticket) = hub.dispatch.lock().tickets.get_mut(&id)
        && matches!(ticket.phase, TicketPhase::Job)
    {
        ticket.phase = TicketPhase::Finished(AdmissionOutcome::Job);
    }
    hub.dispatch.bump();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The placement loop.

/// Keep every live admission and only as many finished outcomes as fit. The store's
/// admission rows have no completion timestamp, so its stable ID order picks the survivors.
fn limit_recovered_admissions(
    admissions: &mut Vec<(String, crate::store::StoredAdmission)>,
    limit: usize,
) -> Vec<(String, Option<AdmissionOutcome>)> {
    let live = admissions
        .iter()
        .filter(|(_, row)| matches!(row.outcome, None | Some(AdmissionOutcome::Job)))
        .count();
    if live > MAX_TICKETS {
        eprintln!(
            "vk-hub: {live} claimed or job admissions recovered, past the {MAX_TICKETS} \
             tickets the hub holds; new reservations are refused until they end"
        );
    }
    let mut room = limit.saturating_sub(live);
    let mut removed = Vec::new();
    admissions.retain(|(id, row)| {
        if matches!(row.outcome, None | Some(AdmissionOutcome::Job)) {
            true
        } else if room > 0 {
            room -= 1;
            true
        } else {
            removed.push((id.clone(), None));
            false
        }
    });
    removed
}

/// Pick the hub's jobs back up after a restart: a job no node had accepted ends lost; one
/// running carries on, its output as stored. Output no job may read again goes.
pub async fn recover(hub: &Hub) -> Result<()> {
    let Some(dir) = hub.dispatch.output_dir.clone() else {
        return Ok(());
    };
    let swept = dir.clone();
    blocking(hub, move |db| sweep_outputs(db, &swept)).await?;
    let mut admissions = blocking(hub, |db| db.admissions()).await?;
    let removed = limit_recovered_admissions(&mut admissions, MAX_RETAINED_TICKETS);
    if !removed.is_empty() {
        blocking(hub, move |db| db.reconcile_admissions(&removed)).await?;
    }
    {
        let mut state = hub.dispatch.lock();
        let now = Instant::now();
        for (id, admission) in admissions {
            let phase = match admission.outcome {
                None => TicketPhase::Claimed {
                    reservation: admission.reservation.clone(),
                },
                Some(AdmissionOutcome::Job) => TicketPhase::Job,
                Some(outcome) => TicketPhase::Finished(outcome),
            };
            let identity = ResolvedIdentity {
                tenant: admission.identity.tenant,
                class: admission.identity.class,
                gitlab: admission.identity.gitlab,
                runner_id: admission.identity.runner_id,
                runner: admission.runner,
                concurrent: 0,
                limit: None,
                request_concurrency: 0,
            };
            state.tickets.insert(
                id.clone(),
                Ticket {
                    key: admission.principal,
                    instance: None,
                    queued: true,
                    request_id: format!("recovered/{id}"),
                    digest: String::new(),
                    identity,
                    placement: admission.placement,
                    lease_secs: 0,
                    created: now,
                    polled: now,
                    phase,
                    probe: admission.probe && admission.outcome.is_none(),
                    reservation: Some(admission.reservation),
                    session: None,
                    claimed_at: None,
                    tried: HashSet::new(),
                    round_ended: None,
                    blocked: None,
                },
            );
        }
    }
    let rows = blocking(hub, |db| db.unfinished_jobs()).await?;
    for (id, mut row) in rows {
        row.output_len = stored_len(&dir, &id);
        if row.state == JobState::Running && row.node.is_some() {
            let limit = DEFAULT_OUTPUT_LIMIT.max(row.output_len);
            // As written: its node sends its latest report again once it is back.
            let egress_revision = row.egress.as_ref().map_or(0, |r| r.revision);
            hub.dispatch.lock().jobs.insert(
                id.clone(),
                LiveJob {
                    row,
                    spec: None,
                    reservation: None,
                    deadline: Instant::now(),
                    tried: HashSet::new(),
                    round_ended: None,
                    blocked: None,
                    // Its spec, and its limit, are gone: what it has stored, and the default
                    // limit's worth past it.
                    output_cap: limit.saturating_add(DEFAULT_OUTPUT_LIMIT).min(MAX_OUTPUT),
                    reservation_accepted_at: 0,
                    image_key: None,
                    mint_key: None,
                    egress: EgressWritten {
                        revision: egress_revision,
                        at: None,
                    },
                },
            );
            continue;
        }
        let mut state = State::default();
        state.jobs.insert(
            id.clone(),
            LiveJob {
                row,
                spec: None,
                reservation: None,
                deadline: Instant::now(),
                tried: HashSet::new(),
                round_ended: None,
                blocked: None,
                output_cap: 0,
                reservation_accepted_at: 0,
                image_key: None,
                mint_key: None,
                egress: EgressWritten::default(),
            },
        );
        if let Some((row, events)) = finish(
            &mut state,
            &id,
            Some(FailureClass::Lost),
            Some("the hub restarted before a node accepted it".into()),
        ) {
            persist(hub, &id, row, events).await?;
        }
    }
    recall_warm(hub).await
}

/// Rebuild which node last used each image key from the job history: the newest jobs, up to
/// the history's count, sent to a node and finished within [`MAX_IMAGE_IDLE_SECS`] or not
/// finished, whose spec is still kept. A job running carries its key, for its end to count.
/// Each node's own idle window applies when placing, once it has said it.
async fn recall_warm(hub: &Hub) -> Result<()> {
    let now = crate::now_secs();
    let since = now.saturating_sub(MAX_IMAGE_IDLE_SECS);
    let hub_history = hub.dispatch.history;
    // Each spec's key alone is kept, not the spec.
    let jobs = blocking(hub, move |db| {
        let limit = history_in(db, hub_history)?.0;
        let mut jobs = Vec::new();
        db.recent_job_specs(since, limit, |id, row, spec| {
            // A spec that no longer parses, from another version of the hub, has no key: its
            // job is not recalled, which costs no more than a node passed over once.
            let key = serde_json::from_slice::<JobSpec>(spec)
                .ok()
                .as_ref()
                .and_then(image_key);
            // One running holds its image now.
            if let (Some(key), Some(node)) = (key, row.node) {
                jobs.push((id, node, key, row.finished_at.unwrap_or(now)));
            }
        })?;
        Ok(jobs)
    })
    .await?;
    // Before the hub serves anyone: holding the lock over the replay delays nothing.
    let mut state = hub.dispatch.lock();
    // In any order: a node keeps its latest use.
    for (id, node, key, at) in jobs {
        warm_note(state.warm.entry(key.clone()).or_default(), &node, at);
        if let Some(job) = state.jobs.get_mut(&id) {
            job.image_key = Some(key);
        }
    }
    warm_prune(&mut state, now);
    Ok(())
}

/// Delete the output files in `dir` of jobs gone from the history, settled or expired: those
/// a hub stopped between recording that and deleting them left behind. A file that cannot
/// be deleted is logged and left, as when pruning.
fn sweep_outputs(db: &crate::store::Db, dir: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("vk-hub: reading {}: {e}", dir.display());
            return Ok(());
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("vk-hub: reading {}: {e}", dir.display());
                break;
            }
        };
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".out")) else {
            continue;
        };
        let readable =
            (db.job(id)?).is_some_and(|r| r.settled_at.is_none() && r.expired_at.is_none());
        if readable {
            continue;
        }
        let path = entry.path();
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("vk-hub: removing {}: {e}", path.display());
        }
    }
    Ok(())
}

/// Place queued jobs, end those past their deadline and those whose node was lost, until the
/// process ends.
pub async fn drive(hub: Arc<Hub>) {
    tokio::spawn(write_egress(hub.clone()));
    tokio::spawn(trim(hub.clone()));
    tokio::spawn(read_briefs(hub.clone()));
    loop {
        let mut changed = hub.dispatch.subscribe();
        let mut node_changed = hub.subscribe();
        if let Err(e) = step(&hub).await {
            eprintln!("vk-hub: placing jobs: {e:#}");
        }
        tokio::select! {
            _ = changed.changed() => {}
            _ = node_changed.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

/// At start and then every [`PACK_EVERY`], until the process ends: train the job specs' next
/// dictionary when it is due, pack what is stored unpacked — by a hub before packing, or
/// specs from before the first dictionary — and drop the dictionaries no spec names.
pub async fn pack(hub: Arc<Hub>) {
    loop {
        match blocking(&hub, |db| db.train_spec_dict()).await {
            Ok(Some(id)) => eprintln!("vk-hub: trained job spec dictionary {id}"),
            Ok(None) => {}
            Err(e) => eprintln!("vk-hub: {e:#}"),
        }
        if let Err(e) = pack_stored(&hub).await {
            eprintln!("vk-hub: packing stored jobs: {e:#}");
        }
        match blocking(&hub, |db| db.drop_unused_spec_dicts()).await {
            Ok(dropped) => {
                for id in dropped {
                    eprintln!("vk-hub: dropped job spec dictionary {id}, no spec uses it");
                }
            }
            Err(e) => eprintln!("vk-hub: dropping job spec dictionaries: {e:#}"),
        }
        tokio::time::sleep(PACK_EVERY).await;
    }
}

/// Pack the kept output and the specs stored unpacked, a bounded step at a time.
async fn pack_stored(hub: &Hub) -> Result<()> {
    let mut tails = 0usize;
    loop {
        let n = blocking(hub, |db| db.pack_legacy_tails()).await?;
        if n == 0 {
            break;
        }
        tails = tails.saturating_add(n);
        tokio::time::sleep(PACK_PAUSE).await;
    }
    if tails > 0 {
        // An end that did not compress takes a byte more packed.
        let total = hub.dispatch.kept_output_total;
        if let Err(e) = blocking(hub, move |db| db.fit_job_cache(total)).await {
            eprintln!("vk-hub: fitting the job output cache: {e:#}");
        }
    }
    let (mut specs, mut after) = (0usize, None);
    loop {
        let (n, next) = blocking(hub, move |db| db.pack_specs(after.as_deref())).await?;
        specs = specs.saturating_add(n);
        let Some(next) = next else {
            break;
        };
        after = Some(next);
        tokio::time::sleep(PACK_PAUSE).await;
    }
    if tails > 0 || specs > 0 {
        eprintln!(
            "vk-hub: moved {tails} kept job outputs to the packed table, packed {specs} job specs"
        );
    }
    Ok(())
}

/// Where the history's count comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistorySource {
    /// [`DEFAULT_JOB_HISTORY`](crate::store::DEFAULT_JOB_HISTORY): neither sets it.
    Default,
    /// `job_history` in `hub.toml`.
    Config,
    /// The web UI, over `job_history`.
    Ui,
}

/// How many jobs' records the history keeps, and where that comes from.
pub fn history_count(hub: &Hub) -> Result<(usize, HistorySource)> {
    history_in(&hub.db, hub.dispatch.history)
}

/// [`history_count`] from `db`, with `job_history` set to `configured`.
fn history_in(db: &crate::store::Db, configured: Option<usize>) -> Result<(usize, HistorySource)> {
    Ok(match db.job_history_set()? {
        Some(n) => (n, HistorySource::Ui),
        None => history_unset_in(configured),
    })
}

/// The history count and its source after clearing the web UI's override.
pub fn history_unset(hub: &Hub) -> (usize, HistorySource) {
    history_unset_in(hub.dispatch.history)
}

/// [`history_unset`], with `job_history` set to `configured`.
fn history_unset_in(configured: Option<usize>) -> (usize, HistorySource) {
    match configured {
        Some(n) => (n, HistorySource::Config),
        None => (crate::store::DEFAULT_JOB_HISTORY, HistorySource::Default),
    }
}

/// Have the history keep `count` jobs' records, or what `job_history` or the default sets
/// (`None`), as `actor`; a lower count is trimmed to in the background at once.
pub fn set_history(hub: &Hub, actor: &str, count: Option<usize>) -> Result<()> {
    let cleared = match history_unset(hub) {
        (n, HistorySource::Config) => format!("job_history in hub.toml applies, {n} jobs"),
        (n, _) => format!("the default applies, {n} jobs"),
    };
    hub.db
        .set_job_history(count, &cleared, actor, crate::now_secs())?;
    hub.dispatch.trim_now.notify_one();
    Ok(())
}

/// Every [`PRUNE_EVERY`], and as soon as the history's count is set, until the process ends:
/// trim the history to its count, one bounded step after another, and drop outputs past
/// their keep.
async fn trim(hub: Arc<Hub>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(PRUNE_EVERY) => {}
            () = hub.dispatch.trim_now.notified() => {}
        }
        while prune(&hub).await {
            tokio::time::sleep(PACK_PAUSE).await;
        }
    }
}

/// How often the history's briefs are read again once lost to a panic.
const BRIEFS_EVERY: Duration = Duration::from_secs(10);

/// Read the job history's briefs ([`crate::store::Db::read_job_briefs`]) in the background
/// at startup, since a long history takes seconds. Retry after panics until the process ends.
async fn read_briefs(hub: Arc<Hub>) {
    loop {
        let start = Instant::now();
        match blocking(&hub, |db| db.read_job_briefs()).await {
            // Read: pages served meanwhile said the history was being read. A long read is
            // worth a line.
            Ok(true) => {
                if start.elapsed() >= Duration::from_secs(1) {
                    eprintln!(
                        "vk-hub: read the job history in {:.1}s",
                        start.elapsed().as_secs_f64()
                    );
                }
                hub.jobs_changed();
            }
            Ok(false) => {}
            Err(e) => eprintln!("vk-hub: {e:#}"),
        }
        tokio::time::sleep(BRIEFS_EVERY).await;
    }
}

/// Trim the history once and report whether to trim again.
async fn prune(hub: &Hub) -> bool {
    let configured = hub.dispatch.history;
    let pruned = blocking(hub, move |db| {
        let keep = history_in(db, configured)?.0;
        db.prune_jobs(crate::now_secs(), keep)
    })
    .await;
    let pruned = match pruned {
        Ok(pruned) => pruned,
        Err(e) => {
            eprintln!("vk-hub: pruning jobs: {e:#}");
            return false;
        }
    };
    {
        let mut state = hub.dispatch.lock();
        for (job, principal, admission) in pruned.retired {
            state.retired_jobs.insert(job, (principal, admission));
        }
        retire_finished_jobs(&mut state);
    }
    hub.dispatch.bump();
    // `outputs` lists only jobs that held output; settled jobs are excluded.
    hub.jobs_changed();
    if let Some(dir) = hub.dispatch.output_dir.clone() {
        for id in pruned.outputs {
            // A dropped job's output, or an unsettled one's past its keep. Stopped before
            // this, the hub deletes them when it next starts.
            let path = output_path(&dir, &id);
            if let Err(e) = std::fs::remove_file(&path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("vk-hub: removing {}: {e}", path.display());
            }
        }
    }
    pruned.more
}

/// A pending admission write finishes before its retired ticket is removed from accounting.
fn retire_finished_jobs(state: &mut State) {
    let mut done = Vec::new();
    for (job, (principal, admission)) in &state.retired_jobs {
        if state.jobs.contains_key(job)
            || admission
                .as_ref()
                .is_some_and(|id| state.pending_admissions.contains(id))
        {
            continue;
        }
        if let Some(id) = admission
            && let Some(ticket) = state.tickets.get_mut(id)
            && ticket.key == *principal
            && matches!(ticket.phase, TicketPhase::Job)
        {
            ticket.phase = TicketPhase::Finished(AdmissionOutcome::Job);
            ticket.probe = false;
        }
        done.push(job.clone());
    }
    for job in done {
        state.retired_jobs.remove(&job);
    }
}

/// One pass of [`drive`].
async fn step(hub: &Hub) -> Result<()> {
    let queued = {
        let state = hub.dispatch.lock();
        state.jobs.values().any(|j| j.row.state == JobState::Queued) || !state.tickets.is_empty()
    };
    // Before the relay rows: a receipt is then never of a later heartbeat than a row holds.
    let heartbeats = hub.heartbeat_receipts();
    let (nodes, mint, rules, policy, relays) = if queued {
        let keys = hub.token_keys.clone();
        blocking(hub, move |db| {
            let rules = match db.egress_rules_on() {
                true => Some(db.egress_rules()?),
                false => None,
            };
            Ok((
                db.nodes()?,
                crate::tokens::MintCtx::read(db, &keys)?,
                rules,
                db.capacity_policy()?,
                db.relays_with_status()?,
            ))
        })
        .await?
    } else {
        (
            Vec::new(),
            crate::tokens::MintCtx::default(),
            None,
            crate::policy::Policy::default(),
            Vec::new(),
        )
    };
    let mut writes = Vec::new();
    let schedule_result;
    let mut moved = false;
    let admission_changes;
    {
        let mut state = hub.dispatch.lock();
        retire_finished_jobs(&mut state);
        let now = Instant::now();
        // Nodes lost while they hold a job.
        let held: HashSet<String> = state
            .jobs
            .values()
            .filter_map(|j| j.node().map(str::to_string))
            .collect();
        state.unreachable_since.retain(|n, _| held.contains(n));
        let mut lost = Vec::new();
        for node in &held {
            if hub.reach(node) == Reach::Connected {
                state.unreachable_since.remove(node);
                continue;
            }
            let since = *state.unreachable_since.entry(node.clone()).or_insert(now);
            if now.duration_since(since) >= hub.dispatch.lost_after {
                lost.push(node.clone());
            }
        }
        for node in lost {
            let ids: Vec<String> = state
                .jobs
                .iter()
                .filter(|(_, j)| j.node() == Some(node.as_str()))
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                let message = format!(
                    "node {node} was unreachable for {}s",
                    hub.dispatch.lost_after.as_secs()
                );
                if let Some(w) = finish(&mut state, &id, Some(FailureClass::Lost), Some(message)) {
                    writes.push((id, w.0, w.1));
                }
            }
        }
        // Canceled jobs do not enter arbitration.
        let mut ids: Vec<(Instant, String)> = state
            .jobs
            .iter()
            .filter(|(_, j)| j.row.state == JobState::Queued)
            .map(|(id, j)| (j.deadline, id.clone()))
            .collect();
        ids.sort();
        for (_, id) in &ids {
            // Canceled while its start was out, then refused or never taken: it ran nowhere.
            let canceled = state.jobs.get(id).is_some_and(|j| j.row.cancel.is_some());
            if canceled && let Some(w) = finish(&mut state, id, Some(FailureClass::Canceled), None)
            {
                writes.push((id.clone(), w.0, w.1));
            }
        }
        let ctx = ScheduleCtx {
            place: PlaceCtx {
                nodes: &nodes,
                mint: &mint,
                rules: rules.as_ref(),
                policy: &policy,
            },
            policy: &policy,
            relays: &relays,
            heartbeats: &heartbeats,
        };
        // With nothing queued when the pass began, nothing was read to arbitrate with: a
        // ticket queued since is the next pass's, which its queueing wakes.
        schedule_result = if queued {
            schedule_tickets(hub, &mut state, &ctx, &mut writes, now).map(|m| moved = m)
        } else {
            Ok(())
        };
        // Attempt placement at the deadline before ending the job.
        for (deadline, id) in ids {
            let Some(job) = state
                .jobs
                .get(&id)
                .filter(|j| now >= deadline && j.row.state == JobState::Queued)
            else {
                continue;
            };
            // Why arbitration last passed it over, when that was not the nodes' room.
            let message = match job.blocked {
                Some(why) => format!("no node took it within its placement window ({why})"),
                None => "no node took it within its placement window".to_string(),
            };
            if let Some(w) = finish(
                &mut state,
                &id,
                Some(FailureClass::NoCapacity),
                Some(message),
            ) {
                writes.push((id, w.0, w.1));
            }
        }
        admission_changes = state.admission_changes.clone();
    }
    if !admission_changes.is_empty() {
        let changes = admission_changes.clone();
        if let Err(error) = blocking(hub, move |db| db.reconcile_admissions(&changes)).await {
            eprintln!("vk-hub: reconciling admissions: {error:#}");
        } else {
            hub.dispatch
                .lock()
                .admission_changes
                .drain(..admission_changes.len());
        }
    }
    let changed = moved || !writes.is_empty();
    for (id, row, events) in writes {
        persist_logged(hub, &id, row, events).await;
    }
    if changed {
        hub.dispatch.bump();
    }
    schedule_result
}

/// What [`place`] reads of the database, once per pass of [`step`].
struct PlaceCtx<'a> {
    nodes: &'a [(String, NodeRow)],
    mint: &'a crate::tokens::MintCtx,
    /// The egress rules and their generation, with `[jobs] egress_rules` on.
    rules: Option<&'a (u64, Vec<crate::store::EgressRuleRow>)>,
    /// The capacity policy, for the node a job's admission may take ([`Kept`]).
    policy: &'a crate::policy::Policy,
}

/// The hub's egress layer for job `job` from `rules`, the claims of its spec under the GitLab
/// instance its relay is bound to, whose approval gate checked its project. `Err` says why the
/// layer resolved cannot be sent.
fn egress_for(
    job: &LiveJob,
    spec: &JobSpec,
    rules: &(u64, Vec<crate::store::EgressRuleRow>),
) -> Result<(HubEgress, crate::store::EgressRulesApplied), String> {
    let JobSpec::GitlabCi(ci) = spec;
    let claims = job
        .row
        .gitlab
        .as_deref()
        .map(|g| crate::subject::JobClaims::of(g, ci));
    let layer = crate::store::resolve_egress(&rules.1, claims.as_ref());
    layer.check()?;
    let applied = crate::store::EgressRulesApplied {
        rules: layer.rules.clone(),
        dry_run: layer.dry_run.iter().map(|d| d.rule.clone()).collect(),
        generation: rules.0,
    };
    Ok((layer, applied))
}

/// Whether `row`'s node may run a placed job of this hub: one enforcing the hub's egress rules
/// when `[jobs] egress_rules` is on, since an older node would ignore its layer and run the job
/// under its own cap alone.
pub fn enforces_rules(hub: &Hub, row: &NodeRow) -> bool {
    !hub.db.egress_rules_on() || row.inventory.as_ref().is_some_and(|i| i.egress_rules)
}

/// Nodes `job` may not go to under its project's placement rules: those of its tenant's
/// listing, or of any tenant's for a job recorded without a scheduling identity.
fn placement_exclusions(
    policy: &crate::policy::Policy,
    job: &LiveJob,
    nodes: &[(String, NodeRow)],
) -> HashSet<String> {
    let project = job
        .row
        .gitlab
        .as_deref()
        .zip(job.row.project_id)
        .and_then(|(gitlab, id)| match &job.row.scheduling {
            Some(identity) => policy.project(&identity.tenant, gitlab, id),
            None => policy.project_any(gitlab, id),
        });
    let Some(project) = project.filter(|p| !p.placement_rules.is_empty()) else {
        return HashSet::new();
    };
    let git_ref = job.spec.as_deref().map(|spec| {
        let JobSpec::GitlabCi(ci) = spec;
        ci.sources.git_ref.as_str()
    });
    nodes
        .iter()
        .filter(|(id, row)| !project.allows_placement(git_ref, id, &row.pools))
        .map(|(id, _)| id.clone())
        .collect()
}

/// Reservation `id`, if a job may start on it: held by a linked node outside `excluded` that
/// may run the hub's jobs.
fn usable_reservation<'s>(
    hub: &Hub,
    state: &'s State,
    nodes: &[(String, NodeRow)],
    excluded: &HashSet<String>,
    id: &str,
) -> Option<&'s Resv> {
    let x = state.reservations.get(id)?;
    let ok = matches!(x.phase, ResvPhase::Held { .. })
        && state.links.get(&x.node).is_some_and(|l| l.held)
        && !excluded.contains(&x.node)
        && (nodes.iter()).any(|(n, row)| *n == x.node && enforces_rules(hub, row));
    ok.then_some(x)
}

/// Send queued job `id` to its reservation's node while the reservation holds, else the
/// least loaded candidate that has not refused it ([`candidates`]). Prefer a lightly loaded
/// candidate holding its image unless the reservation's node also holds it ([`warm_nodes`]).
/// With egress rules on, a job whose layer cannot be sent fails, saying why. Return the row to
/// write if sent or failed.
fn place(
    hub: &Hub,
    state: &mut State,
    ctx: &PlaceCtx<'_>,
    id: &str,
    now: Instant,
    selected: Option<&str>,
) -> Option<(String, JobRow, Vec<Event>)> {
    let PlaceCtx {
        nodes,
        mint,
        rules,
        policy,
    } = *ctx;
    let job = state.jobs.get(id)?;
    let spec = job.spec.clone()?;
    let egress = match rules.map(|r| egress_for(job, &spec, r)) {
        None => None,
        Some(Ok(e)) => Some(e),
        Some(Err(why)) => {
            let message = format!("the hub's egress rules for this job cannot be sent: {why}");
            let (row, events) =
                finish(state, id, Some(FailureClass::Configuration), Some(message))?;
            return Some((id.to_string(), row, events));
        }
    };
    let mint_key = job.mint_key.clone();
    let placement = job.row.placement.clone();
    let class = job
        .row
        .scheduling
        .as_ref()
        .map_or(crate::policy::Class::Normal, |i| i.class);
    let mut tried = job.tried.clone();
    let excluded = placement_exclusions(policy, job, nodes);
    tried.extend(excluded.iter().cloned());
    let affinity = hub.dispatch.affinity;
    let clock = crate::now_secs();
    let warm = match &job.image_key {
        Some(key) if affinity.max_load > 0 => warm_nodes(state, nodes, key, clock),
        _ => HashSet::new(),
    };
    let preferred_among = |state: &State, found: &[(String, u64)]| {
        if warm.is_empty() {
            return HashSet::new();
        }
        let cpus = placement.envelope.cpus;
        preferred(state, nodes, found, &warm, cpus, affinity, clock)
    };
    let reserved = job.reservation.as_ref().and_then(|r| {
        let x = usable_reservation(hub, state, nodes, &excluded, r)?;
        Some((r.clone(), x.node.clone(), x.envelope, x.accepted_at))
    });
    let mut given_up = None;
    let mut selected = selected.map(str::to_owned);
    if let Some((reservation, node, _, _)) = &reserved
        && !warm.is_empty()
        && !warm.contains(node)
    {
        let found = candidates(hub, state, nodes, &placement, &tried);
        let light = preferred_among(state, &found);
        let kept = Kept::new(hub, nodes, policy);
        for (candidate, _) in warm_first(found, &light) {
            if !light.contains(&candidate) {
                break;
            }
            if kept.admits(state, (&placement, class), &candidate) {
                selected = Some(candidate);
                given_up = Some(reservation.clone());
                break;
            }
        }
    }
    let reserved = reserved.filter(|_| given_up.is_none());
    let mut accepted_at = 0;
    let (node, reservation, envelope) = match reserved {
        Some((r, node, envelope, at)) => {
            accepted_at = at;
            (node, Some(r), envelope)
        }
        None => {
            let mut found = candidates(hub, state, nodes, &placement, &tried);
            if found.is_empty() && !tried.is_empty() {
                // Every node with room refused it: after a pause, ask them all again.
                let job = state.jobs.get_mut(id)?;
                let ended = *job.round_ended.get_or_insert(now);
                if now.duration_since(ended) < RETRY_PAUSE {
                    return None;
                }
                job.tried.clear();
                job.round_ended = None;
                tried.clone_from(&excluded);
                found = candidates(hub, state, nodes, &placement, &tried);
            }
            // Arbitration chose a node unless it used a reservation. Both checks of whether
            // the reservation is usable hold the same lock.
            debug_assert!(selected.is_some(), "job {id} placed without a node chosen");
            if let Some(selected) = &selected {
                found.retain(|(node, _)| node == selected);
            }
            let light = preferred_among(state, &found);
            let (node, _) = warm_first(found, &light).into_iter().next()?;
            (node, None, placement.envelope)
        }
    };
    let minted = nodes.iter().find(|(n, _)| *n == node).map(|(n, row)| {
        crate::tokens::for_job(hub, mint, (n, row), id, &spec, mint_key.as_deref())
    });
    let (registry, events, shown) = match minted {
        Some(Ok(crate::tokens::Minted {
            access,
            audit: (index, event),
            shown,
        })) => (
            Some(access),
            vec![(index, HUB.to_string(), event)],
            Some(shown),
        ),
        Some(Err(shown)) => (None, Vec::new(), shown),
        None => (None, Vec::new(), None),
    };
    let start = HubJobMsg::Start(Box::new(JobStart {
        job: id.to_string(),
        reservation: reservation.clone(),
        envelope,
        spec: (*spec).clone(),
        registry,
        egress: egress.as_ref().map(|(layer, _)| layer.clone()),
    }));
    if !send(state, &node, start) {
        return None;
    }
    if let Some(r) = &reservation {
        // The job takes it over; the node says so with `lease gone started`.
        state.reservations.remove(r);
    }
    let job = state.jobs.get_mut(id)?;
    // Kept until the node answers, to release it should the node refuse the job.
    job.reservation = reservation;
    job.reservation_accepted_at = accepted_at;
    job.row.state = JobState::Starting;
    job.row.node = Some(node.clone());
    job.row.registry_access = shown;
    job.row.egress_rules = egress.map(|(_, applied)| applied);
    job.row.egress_caps = nodes.iter().find(|(n, _)| *n == node).and_then(|(_, row)| {
        match row.inventory.as_ref()?.egress_caps.as_ref()? {
            vk_hub_proto::egress::NodeEgressCaps::Listed(caps) => Some(caps.fingerprint.clone()),
            _ => None,
        }
    });
    job.row.revision = job.row.revision.saturating_add(1);
    let row = job.row.clone();
    if let Some(reservation) = given_up
        && let Some(old) = state.reservations.remove(&reservation)
    {
        send(state, &old.node, HubJobMsg::Release { reservation });
    }
    // Its node is in its record; only a registry token issued is audited.
    Some((id.to_string(), row, events))
}

/// The latest `limit` jobs, newest first, those under way as the hub holds them now.
pub fn listing(hub: &Hub, limit: usize) -> Result<Vec<(String, JobRow)>> {
    let mut rows = hub.db.jobs(limit)?;
    let state = hub.dispatch.lock();
    for (id, row) in &mut rows {
        if let Some(live) = live_row(&state, id) {
            *row = live.clone();
        }
    }
    Ok(rows)
}

/// A history page ([`crate::store::Db::job_page`]) updated with in-memory job state, excluding
/// jobs that no longer match `filter`. The summary uses stored rows and lags unwritten changes.
pub fn history(
    hub: &Hub,
    filter: &JobFilter,
    before: Option<u64>,
    limit: usize,
) -> Result<JobPage> {
    let mut page = hub.db.job_page(filter, before, limit)?;
    let state = hub.dispatch.lock();
    page.rows.retain_mut(|(_, id, row)| {
        if let Some(live) = live_row(&state, id) {
            *row = live.clone();
        }
        filter.matches(row)
    });
    Ok(page)
}

/// Job `id`'s record and, for a finished job, its node-masked output tail, while retained.
/// Before settlement, read as much stored output as settlement would retain.
/// Returns `None` if the job is not in the history.
pub fn detail(hub: &Hub, id: &str) -> Result<Option<(JobRow, Option<Vec<u8>>)>> {
    // An output file is named by the ID.
    if !vk_hub_proto::valid_id(id) {
        return Ok(None);
    }
    let live = live_row(&hub.dispatch.lock(), id).cloned();
    let Some(row) = live.map_or_else(|| hub.db.job(id), |r| Ok(Some(r)))? else {
        return Ok(None);
    };
    let keep = match row.outcome() {
        JobOutcome::Running => return Ok(Some((row, None))),
        JobOutcome::Failed => hub.dispatch.kept_failure_output,
        JobOutcome::Success | JobOutcome::Canceled => {
            hub.dispatch.kept_output.min(hub.dispatch.kept_output_total)
        }
    };
    let mut tail = hub.db.job_tail(id)?;
    if tail.is_none()
        && keep > 0
        && row.settled_at.is_none()
        && row.expired_at.is_none()
        && let Some(dir) = &hub.dispatch.output_dir
    {
        tail = Some(output_tail(dir, id, row.output_len, keep)?).filter(|t| !t.is_empty());
    }
    Ok(Some((row, tail)))
}

/// What a job's page reads of its stored output.
pub struct Stretch {
    /// Where it starts in the output.
    pub from: u64,
    pub bytes: Vec<u8>,
    /// How long the output was when it was read.
    pub len: u64,
}

/// Job `id`'s record as the hub holds it and, while the hub holds its output, up to `max`
/// bytes of it: from `from`, or for `None` its end, from the start of a line as
/// [`output_tail`] cuts it. `None` for a job not in the history.
pub fn output_stretch(
    hub: &Hub,
    id: &str,
    from: Option<u64>,
    max: u64,
) -> Result<Option<(JobRow, Option<Stretch>)>> {
    // An output file is named by the ID.
    if !vk_hub_proto::valid_id(id) {
        return Ok(None);
    }
    let live = live_row(&hub.dispatch.lock(), id).cloned();
    let Some(row) = live.map_or_else(|| hub.db.job(id), |r| Ok(Some(r)))? else {
        return Ok(None);
    };
    let Some(dir) = hub
        .dispatch
        .output_dir
        .as_deref()
        .filter(|_| row.settled_at.is_none() && row.expired_at.is_none())
    else {
        return Ok(Some((row, None)));
    };
    let len = row.output_len;
    let stretch = match from {
        None => {
            let bytes = output_tail(dir, id, len, max)?;
            Stretch {
                from: len.saturating_sub(bytes.len() as u64),
                bytes,
                len,
            }
        }
        Some(from) => {
            let want = len.saturating_sub(from).min(max);
            let want = usize::try_from(want).unwrap_or(usize::MAX);
            Stretch {
                from,
                bytes: read_output(dir, id, from, want)?,
                len,
            }
        }
    };
    Ok(Some((row, Some(stretch))))
}

/// One line of a job's output as [`readable`] makes it.
#[derive(Debug, PartialEq, Eq)]
pub struct TraceLine {
    /// When it came, from its stamp (`FF_TIMESTAMPS`): `2026-10-09T12:10:43.123456Z`.
    pub at: Option<String>,
    /// Its text as [`crate::ui::html::terminal_runs`] leaves it, styles aside.
    pub text: String,
    /// The same text in runs of the style its SGR sequences set.
    pub runs: Vec<crate::ui::html::Run>,
}

/// `output`, a job's trace, for reading: lines continued (`+` stamps) joined to the line they
/// continue, a line rewritten by carriage returns shown as it was left, GitLab's collapsible
/// section markers removed (a line that held nothing else with them), and the terminal's escape
/// sequences and other controls dropped.
pub fn readable(output: &[u8]) -> Vec<TraceLine> {
    // For display alone: an invalid sequence shows as U+FFFD.
    let mut trace = Trace::default();
    let mut lines = trace.push(&String::from_utf8_lossy(output));
    lines.extend(trace.finish());
    lines
}

/// The most of one line [`Trace`] keeps: a progress bar redrawn for hours is one line. Past
/// it, what precedes the line's last carriage return goes, as nothing shows it; with none to
/// cut at, its head is kept and the rest dropped, marked [`CUT_MARK`].
const MAX_HELD_LINE: usize = 64 * 1024;

/// What ends a line [`Trace`] cut short.
const CUT_MARK: &str = "…";

/// The most [`Trace`] holds back in all, each line counted as its text and [`HELD_LINE_COST`]:
/// past it the oldest line is taken as done, so a stream that leaves a line open while another
/// writes on holds neither memory nor the rest back without end.
const MAX_HELD: usize = 256 * 1024;

/// What a held line counts for besides its text.
const HELD_LINE_COST: usize = 64;

/// The longest escape sequence a cut line is kept from ending inside.
const MAX_ESCAPE: usize = 32;

/// A job's trace made [`readable`] as it arrives, a stretch at a time. A stamped line is
/// continued by the next `+` line of its stream (`O` or `E`), which may come after lines of
/// the other: lines are held back from the first one still open, and [`Trace::held`] is how
/// they read so far. What is held is bounded: [`MAX_HELD_LINE`] a line, [`MAX_HELD`] in all.
#[derive(Default)]
pub struct Trace {
    /// The lines not yet done, oldest first.
    held: VecDeque<HeldLine>,
    /// What `held` counts for against [`MAX_HELD`].
    cost: usize,
    /// The ID the next held line takes.
    next: u64,
    /// The held line the last stretch ended inside, before its newline.
    open: Option<u64>,
    /// SGR state after the completed lines, carried into the next line. A trace read from
    /// the middle of a log starts with the default style.
    style: Style,
}

/// A line [`Trace`] holds back.
struct HeldLine {
    id: u64,
    /// Its stream and `O`/`E` (header bytes 28..31); `None` for an unstamped line, which
    /// nothing continues.
    key: Option<String>,
    /// Its stamp's time.
    at: Option<String>,
    /// Its text as it came, continuations joined, kept under [`MAX_HELD_LINE`].
    text: String,
    /// Where its text ends, [`CUT_MARK`] included, once [`hold`] cut it short.
    cut: Option<usize>,
    /// Whether a later line of its stream has started, so nothing more continues it.
    done: bool,
}

impl HeldLine {
    fn cost(&self) -> usize {
        self.text.len().saturating_add(HELD_LINE_COST)
    }

    fn shown(self, style: &mut Style) -> Option<TraceLine> {
        shown((self.at, self.text), style)
    }
}

impl Trace {
    /// The lines the trace's next stretch, `text`, ends, in order. A stretch may end anywhere
    /// but inside a character.
    pub fn push(&mut self, text: &str) -> Vec<TraceLine> {
        use vk_hub_proto::stamp::HEADER_LEN;
        let mut done = Vec::new();
        let mut rest = text;
        if let Some(id) = self.open.take()
            && let Some(i) = self.held.iter().position(|l| l.id == id)
        {
            let (head, tail) = rest.split_once('\n').unwrap_or((rest, ""));
            self.extend(i, head);
            if !rest.contains('\n') {
                self.open = Some(id);
            }
            rest = tail;
        }
        for piece in rest.split_inclusive('\n') {
            let line = piece.strip_suffix('\n').unwrap_or(piece);
            let ends = piece.ends_with('\n');
            let Some(h) = line.get(..HEADER_LEN).filter(|h| stamped(h.as_bytes())) else {
                self.add(None, None, line, true, ends);
                self.settle(&mut done);
                continue;
            };
            let text = line.get(HEADER_LEN..).unwrap_or_default();
            let key = h.get(28..31).unwrap_or_default();
            let continued = h.as_bytes().get(HEADER_LEN - 1) == Some(&b'+');
            let last = (self.held.iter()).rposition(|l| !l.done && l.key.as_deref() == Some(key));
            match last {
                Some(i) if continued => {
                    self.extend(i, text);
                    if !ends {
                        self.open = self.held.get(i).map(|l| l.id);
                    }
                    self.settle(&mut done);
                    continue;
                }
                Some(i) => {
                    if let Some(l) = self.held.get_mut(i) {
                        l.done = true;
                    }
                }
                None => {}
            }
            let at = h.get(..HEADER_LEN - 5).map(str::to_string);
            self.add(Some(key.to_string()), at, text, false, ends);
            self.settle(&mut done);
        }
        done
    }

    /// Hold a new line, `done` when nothing can continue it, open when `!ends`.
    fn add(&mut self, key: Option<String>, at: Option<String>, text: &str, done: bool, ends: bool) {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let mut line = HeldLine {
            id,
            key,
            at,
            text: text.to_string(),
            cut: None,
            done,
        };
        hold(&mut line.text, &mut line.cut);
        self.cost = self.cost.saturating_add(line.cost());
        self.held.push_back(line);
        if !ends {
            self.open = Some(id);
        }
    }

    /// Continue held line `i` with `text`.
    fn extend(&mut self, i: usize, text: &str) {
        let Some(line) = self.held.get_mut(i) else {
            return;
        };
        self.cost = self.cost.saturating_sub(line.cost());
        line.text.push_str(text);
        hold(&mut line.text, &mut line.cut);
        self.cost = self.cost.saturating_add(line.cost());
    }

    /// Emit completed lines from the front into `done`. Above [`MAX_HELD`], also emit
    /// the oldest unfinished lines.
    fn settle(&mut self, done: &mut Vec<TraceLine>) {
        while let Some(front) = self.held.front()
            && (self.cost > MAX_HELD || (front.done && Some(front.id) != self.open))
        {
            let Some(line) = self.held.pop_front() else {
                break;
            };
            self.cost = self.cost.saturating_sub(line.cost());
            if Some(line.id) == self.open {
                // What continues it is read as a line of its own.
                self.open = None;
            }
            done.extend(line.shown(&mut self.style));
        }
    }

    /// The lines held back, as they read so far.
    pub fn held(&self) -> Vec<TraceLine> {
        // Preview from a copy: only completed lines advance the saved style.
        let mut style = self.style;
        self.held
            .iter()
            .filter_map(|l| shown((l.at.clone(), l.text.clone()), &mut style))
            .collect()
    }

    /// The lines held back, now that nothing can continue them.
    pub fn finish(&mut self) -> Vec<TraceLine> {
        self.open = None;
        self.cost = 0;
        let style = &mut self.style;
        self.held.drain(..).filter_map(|l| l.shown(style)).collect()
    }
}

/// Keep `line`, held while it may be continued, under [`MAX_HELD_LINE`]. `cut`: where it ends
/// once cut short, past which what is appended goes, but from a carriage return on.
fn hold(line: &mut String, cut: &mut Option<usize>) {
    if let Some(end) = *cut {
        // Appended after the mark: a carriage return starts a drawing anew, else it goes.
        let body = line.trim_end_matches('\r');
        match body.get(end..).and_then(|after| after.rfind('\r')) {
            Some(cr) => {
                line.drain(..end.saturating_add(cr).saturating_add(1));
                *cut = None;
            }
            None => {
                // A trailing carriage return stays, for the next drawing to restart from.
                let cr = line.ends_with('\r');
                line.truncate(end);
                if cr {
                    line.push('\r');
                }
                return;
            }
        }
    }
    if line.len() <= MAX_HELD_LINE {
        return;
    }
    // Nothing shows what precedes the last carriage return, but those it ends with.
    if let Some(cr) = line.trim_end_matches('\r').rfind('\r') {
        line.drain(..=cr);
        if line.len() <= MAX_HELD_LINE {
            return;
        }
    }
    let end = (0..=MAX_HELD_LINE)
        .rev()
        .find(|&i| line.is_char_boundary(i))
        .unwrap_or(0);
    line.truncate(before_escape(line, end));
    line.push_str(CUT_MARK);
    *cut = Some(line.len());
}

/// Where to end `line` cut at `end`: before an escape sequence `end` would split, if one
/// starts within [`MAX_ESCAPE`] bytes of it, so no half of one shows.
fn before_escape(line: &str, end: usize) -> usize {
    let from = end.saturating_sub(MAX_ESCAPE);
    let Some(esc) = line.get(from..end).and_then(|w| w.rfind('\x1b')) else {
        return end;
    };
    let esc = from.saturating_add(esc);
    let seq = line.get(esc.saturating_add(1)..end).unwrap_or_default();
    // A CSI sequence ends with its final byte; another escape with the character after it.
    let ended = match seq.strip_prefix('[') {
        Some(params) => params.bytes().any(|b| (0x40..=0x7e).contains(&b)),
        None => !seq.is_empty(),
    };
    if ended { end } else { esc }
}

/// Format a joined line with its timestamp: remove GitLab section markers, keep the final
/// carriage-return update, and draw it with [`crate::ui::html::terminal_runs`] from `style`,
/// the style the lines before it left, which it leaves as the line does. Return `None` for a
/// line containing only a section marker.
fn shown((at, text): (Option<String>, String), style: &mut Style) -> Option<TraceLine> {
    let (text, marked) = without_sections(&text);
    // What the terminal was left showing: the text after the last carriage return.
    let runs = crate::ui::html::terminal_runs(text.trim_end_matches('\r'), style);
    let text: String = runs.iter().map(|r| r.text.as_str()).collect();
    (!marked || !text.trim().is_empty()).then_some(TraceLine { at, text, runs })
}

/// Whether `h` is a stamp's header: `2026-10-09T12:10:43.123456Z 01O ` or `+` at its end.
fn stamped(h: &[u8]) -> bool {
    let digit = |i: usize| h.get(i).is_some_and(u8::is_ascii_digit);
    let is = |i: usize, c: u8| h.get(i) == Some(&c);
    h.len() == vk_hub_proto::stamp::HEADER_LEN
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .into_iter()
            .all(digit)
        && (20..26).all(digit)
        && is(4, b'-')
        && is(7, b'-')
        && is(10, b'T')
        && is(13, b':')
        && is(16, b':')
        && is(19, b'.')
        && is(26, b'Z')
        && is(27, b' ')
        && h.get(28..30)
            .is_some_and(|s| s.iter().all(u8::is_ascii_hexdigit))
        && (is(30, b'O') || is(30, b'E'))
        && (is(31, b' ') || is(31, b'+'))
}

/// `line` without GitLab's section markers — `section_start:<time>:<name>[<options>]` and
/// `section_end:<time>:<name>`, each up to the carriage return that ends it — and whether it
/// had one.
fn without_sections(line: &str) -> (String, bool) {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    let mut marked = false;
    loop {
        let at = ["section_start:", "section_end:"]
            .iter()
            .filter_map(|m| rest.find(m))
            .min();
        let Some(at) = at else {
            out.push_str(rest);
            return (out, marked);
        };
        marked = true;
        out.push_str(rest.get(..at).unwrap_or_default());
        let marker = rest.get(at..).unwrap_or_default();
        rest = match marker.find('\r') {
            Some(cr) => marker.get(cr + 1..).unwrap_or_default(),
            None => "",
        };
    }
}

/// Job `id`'s row as the hub holds it ahead of the database, if it does.
fn live_row<'s>(state: &'s State, id: &str) -> Option<&'s JobRow> {
    (state.jobs.get(id).map(|j| &j.row)).or_else(|| state.finished.get(id))
}

/// The size of job `j`'s VM ([`JobRow::vm_size`]), its memory written by `mem` from MiB:
/// `4 vCPUs, 8.0 GiB`.
pub(crate) fn size_text(j: &JobRow, mem: impl FnOnce(u64) -> String) -> Option<String> {
    j.vm_size().map(|(cpus, mib)| {
        let unit = if cpus == 1 { "vCPU" } else { "vCPUs" };
        format!("{cpus} {unit}, {}", mem(mib))
    })
}

/// A job's run or CPU time, `ms` milliseconds, to the second: `42s`, `3m05s`, `1h02m`.
pub(crate) fn run_text(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0 => "<1s".to_string(),
        1..60 => format!("{s}s"),
        60..3600 => format!("{}m{:02}s", s / 60, s % 60),
        _ => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backoff_doubles_up_to_its_cap_with_a_quarter_of_jitter() {
        let ms = |count, sample| backoff_delay(1, 60, count, sample).as_millis();
        // The lowest sample takes the bottom of the range, the range's width minus one its top.
        for (count, base) in [(0, 1000), (1, 1000), (2, 2000), (3, 4000), (6, 32_000)] {
            assert_eq!(ms(count, 0), base * 3 / 4, "{count}");
            let width = u64::try_from(base / 2).unwrap();
            assert_eq!(ms(count, width), base * 5 / 4, "{count}");
            assert_eq!(ms(count, width + 1), base * 3 / 4, "{count}");
        }
        // Capped at 60 s, the jitter too: 45 to 60 s.
        for count in [7, 31, 32, u32::MAX] {
            assert_eq!(ms(count, 0), 45_000, "{count}");
            assert_eq!(ms(count, 15_000), 60_000, "{count}");
            assert!(ms(count, u64::MAX) <= 60_000, "{count}");
        }
        assert_eq!(backoff_delay(5, 5, 9, 0), Duration::from_millis(3750));
        assert_eq!(backoff_delay(5, 5, 9, 1250), Duration::from_secs(5));
    }

    fn ticket(phase: TicketPhase, polled: Instant) -> Ticket {
        Ticket {
            key: "key".into(),
            instance: None,
            queued: true,
            request_id: String::new(),
            digest: String::new(),
            identity: ResolvedIdentity {
                tenant: "fallback".into(),
                class: crate::policy::Class::Normal,
                gitlab: None,
                runner_id: None,
                runner: None,
                concurrent: 1,
                limit: None,
                request_concurrency: 1,
            },
            placement: Placement::default(),
            lease_secs: 60,
            created: polled,
            polled,
            phase,
            probe: false,
            reservation: None,
            session: None,
            claimed_at: None,
            tried: HashSet::new(),
            round_ended: None,
            blocked: None,
        }
    }

    #[test]
    fn retained_limit_evicts_finished_without_extending_it_on_poll() {
        let hub = Hub::new(Arc::new(crate::store::Db::open_memory().unwrap()), None);
        let principal = ApiPrincipal {
            id: "key".into(),
            name: "key".into(),
            instance: None,
            kind: crate::store::PrincipalKind::Relay,
        };
        let old = Instant::now() - Duration::from_secs(10);
        {
            let mut state = hub.dispatch.lock();
            state.tickets.insert(
                "old".into(),
                ticket(TicketPhase::Finished(AdmissionOutcome::Empty), old),
            );
            state.tickets.insert(
                "pending".into(),
                ticket(TicketPhase::Finished(AdmissionOutcome::Empty), old),
            );
            state.pending_admissions.insert("pending".into());
            state
                .tickets
                .insert("live".into(), ticket(TicketPhase::Job, old));
        }
        assert!(poll_ticket(&hub, &principal, "old").is_err());
        let mut state = hub.dispatch.lock();
        assert_eq!(state.tickets["old"].polled, old);
        assert!(evict_finished(&mut state, 3));
        assert!(!state.tickets.contains_key("old"));
        assert!(state.tickets.contains_key("pending"));
        assert!(state.tickets.contains_key("live"));
        assert_eq!(state.admission_changes, vec![("old".into(), None)]);
        assert!(!evict_finished(&mut state, 2));
    }

    #[test]
    fn expired_job_waits_for_pending_admission_write_before_releasing_charge() {
        let mut state = State::default();
        state
            .tickets
            .insert("admission".into(), ticket(TicketPhase::Job, Instant::now()));
        state.pending_admissions.insert("admission".into());
        state
            .retired_jobs
            .insert("job".into(), ("key".into(), Some("admission".into())));
        retire_finished_jobs(&mut state);
        assert!(matches!(state.tickets["admission"].phase, TicketPhase::Job));
        assert!(state.retired_jobs.contains_key("job"));
        state.pending_admissions.remove("admission");
        retire_finished_jobs(&mut state);
        assert!(matches!(
            state.tickets["admission"].phase,
            TicketPhase::Finished(AdmissionOutcome::Job)
        ));
        assert!(state.retired_jobs.is_empty());
    }

    /// A job recorded before capacity arbitration is charged to one tenant listing its
    /// project, however many do, and to none when none does.
    #[test]
    fn a_legacy_job_is_charged_to_one_tenant() {
        let mut policy = crate::policy::Policy::default();
        let tenant = |id| crate::policy::Tenant {
            weight: 1,
            cap: None,
            projects: vec![crate::policy::Project {
                gitlab: "gl".into(),
                id,
                production_branches: Vec::new(),
                placement_rules: Vec::new(),
            }],
        };
        policy.tenants.insert("b".into(), tenant(7));
        policy.tenants.insert("a".into(), tenant(7));
        let row = |project_id| -> JobRow {
            serde_json::from_value(serde_json::json!({
                "key": "k", "key_name": "k", "request_id": "r", "created_at": 0,
                "revision": 1, "placement": Placement::default(), "state": "running",
                "gitlab": "gl", "project_id": project_id,
            }))
            .unwrap()
        };
        assert_eq!(legacy_tenant(&policy, &row(7)), Some("a"));
        assert_eq!(legacy_tenant(&policy, &row(8)), None);
    }

    #[test]
    fn recovery_limits_finished_without_dropping_claims_or_jobs() {
        let row = crate::store::StoredAdmission {
            principal: "relay".into(),
            identity: crate::store::SchedulingIdentity {
                tenant: "fallback".into(),
                class: crate::policy::Class::Normal,
                gitlab: Some("gl".into()),
                runner_id: Some(1),
            },
            runner: Some("runner".into()),
            placement: Placement::default(),
            probe: false,
            reservation: "reservation".into(),
            outcome: None,
        };
        let mut rows: Vec<_> = [
            ("a", Some(AdmissionOutcome::Empty)),
            ("b", None),
            ("c", Some(AdmissionOutcome::Job)),
            ("d", Some(AdmissionOutcome::Released)),
        ]
        .into_iter()
        .map(|(id, outcome)| {
            let mut row = row.clone();
            row.outcome = outcome;
            (id.to_owned(), row)
        })
        .collect();
        let removed = limit_recovered_admissions(&mut rows, 3);
        assert_eq!(removed, vec![("d".into(), None)]);
        assert_eq!(
            rows.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        let db = crate::store::Db::open_memory().unwrap();
        for (id, row) in &rows {
            db.put_admission(id, row).unwrap();
        }
        let mut dropped = row;
        dropped.outcome = Some(AdmissionOutcome::Released);
        db.put_admission("d", &dropped).unwrap();
        db.reconcile_admissions(&removed).unwrap();
        assert!(db.admission("d").unwrap().is_none());
        assert!(db.admission("b").unwrap().is_some());
        assert!(db.admission("c").unwrap().is_some());
    }

    #[tokio::test]
    async fn claim_does_not_hold_dispatch_lock_during_durable_write() {
        let hub = Arc::new(Hub::new(
            Arc::new(crate::store::Db::open_memory().unwrap()),
            None,
        ));
        let principal = ApiPrincipal {
            id: "relay".into(),
            name: "relay".into(),
            instance: None,
            kind: crate::store::PrincipalKind::Relay,
        };
        let now = Instant::now();
        let identity = ResolvedIdentity {
            tenant: "fallback".into(),
            class: crate::policy::Class::Normal,
            gitlab: Some("gl".into()),
            runner_id: Some(1),
            runner: Some("runner".into()),
            concurrent: 1,
            limit: None,
            request_concurrency: 1,
        };
        {
            let mut state = hub.dispatch.lock();
            state.tickets.insert(
                "ticket".into(),
                Ticket {
                    key: principal.id.clone(),
                    instance: None,
                    queued: true,
                    request_id: "request".into(),
                    digest: String::new(),
                    identity,
                    placement: Placement::default(),
                    lease_secs: 60,
                    created: now,
                    polled: now,
                    phase: TicketPhase::Granted {
                        reservation: "reservation".into(),
                        accepted: now,
                    },
                    probe: false,
                    reservation: Some("reservation".into()),
                    session: Some(1),
                    claimed_at: None,
                    tried: HashSet::new(),
                    round_ended: None,
                    blocked: None,
                },
            );
            state.reservations.insert(
                "reservation".into(),
                Resv {
                    key: principal.id.clone(),
                    instance: None,
                    node: "node".into(),
                    envelope: Envelope::default(),
                    phase: ResvPhase::Held { lease_secs: 60 },
                    accepted_at: 0,
                    leases: 0,
                    ticket: Some("ticket".into()),
                },
            );
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let db = hub.db.clone();
        let writer = std::thread::spawn(move || db.hold_admission_writer(ready_tx, release_rx));
        ready_rx.recv().unwrap();
        let (worker_hub, worker_principal) = (hub.clone(), principal.clone());
        let claim =
            tokio::spawn(async move { claim(&worker_hub, &worker_principal, "reservation").await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !hub.dispatch.lock().pending_admissions.contains("ticket") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Disconnect changes the grant while the write is blocked. The worker must be able
        // to observe it, retire the ticket and remove the durable claim before replying.
        relay_disconnected(&hub, "relay", 1);
        release_tx.send(()).unwrap();
        writer.join().unwrap();
        assert!(claim.await.unwrap().is_err());
        assert!(hub.db.admission("ticket").unwrap().is_none());
        assert!(matches!(
            hub.dispatch.lock().tickets["ticket"].phase,
            TicketPhase::Finished(_)
        ));
    }

    /// The lines still open show as the terminal would: continued, then overwritten.
    #[test]
    fn the_lines_still_open_show_as_they_read() {
        let stamp = |kind: char| format!("2026-10-09T12:10:43.123456Z 01O{kind}");
        let mut trace = Trace::default();
        assert!(trace.push(&format!("{}10%\r\n", stamp(' '))).is_empty());
        assert_eq!(texts(&trace.held()), ["10%"]);
        assert!(trace.push(&format!("{}20%\r\n", stamp('+'))).is_empty());
        assert_eq!(texts(&trace.held()), ["20%"]);
        let done = trace.push(&format!("{}next\n", stamp(' ')));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].text, "20%");
        assert_eq!(texts(&trace.held()), ["next"]);
        // A line redrawn without end is held to its last drawing, bounded.
        let mut trace = Trace::default();
        trace.push(&format!("{} start", stamp(' ')));
        for n in 0..20_000 {
            trace.push(&format!("\rprogress {n:05}"));
        }
        trace.push("\r");
        assert_eq!(texts(&trace.held()), ["progress 19999"]);
        assert_eq!(texts(&trace.finish()), ["progress 19999"]);
    }

    fn texts(lines: &[TraceLine]) -> Vec<&str> {
        lines.iter().map(|l| l.text.as_str()).collect()
    }

    /// A `+` line continues its own stream's last line, past lines of the other, which wait
    /// for it in order.
    #[test]
    fn a_continuation_joins_its_own_stream_s_line() {
        let stamp = |io: char, kind: char| format!("2026-10-09T12:10:43.123456Z 01{io}{kind}");
        let output = format!(
            "{}out a\n{}err\n{}out b\n{}err more\n{}last\n",
            stamp('O', ' '),
            stamp('E', ' '),
            stamp('O', '+'),
            stamp('E', '+'),
            stamp('O', ' '),
        );
        let whole = readable(output.as_bytes());
        assert_eq!(texts(&whole), ["out aout b", "errerr more", "last"]);
        let mut trace = Trace::default();
        let mut shown = Vec::new();
        for line in output.split_inclusive('\n') {
            shown.extend(trace.push(line));
        }
        // The error line waits for a later one of its stream; "last" waits behind it.
        assert_eq!(texts(&shown), ["out aout b"]);
        assert_eq!(texts(&trace.held()), ["errerr more", "last"]);
        shown.extend(trace.finish());
        assert_eq!(shown, whole);
    }

    /// An oversized line keeps its head and a cut marker without splitting an escape
    /// sequence. Continuations are dropped until a carriage return starts a new update.
    #[test]
    fn a_long_line_keeps_its_head_marked_cut() {
        let stamp = |kind: char| format!("2026-10-09T12:10:43.123456Z 01O{kind}");
        let head = "x".repeat(MAX_HELD_LINE - 2);
        let output = format!("{}{head}\x1b[31mred\x1b[0m and more\n", stamp(' '));
        let lines = readable(output.as_bytes());
        assert_eq!(texts(&lines), [format!("{head}{CUT_MARK}")]);
        let mut trace = Trace::default();
        trace.push(&format!("{}{head}yyyy\n", stamp(' ')));
        trace.push(&format!("{}more\n", stamp('+')));
        assert_eq!(texts(&trace.held()), [format!("{head}yy{CUT_MARK}")]);
        trace.push(&format!("{}\rprogress 1\r\n", stamp('+')));
        assert_eq!(texts(&trace.held()), ["progress 1"]);
        // Redraws ending in a carriage return, after a cut: the last drawing shows.
        let mut trace = Trace::default();
        trace.push(&format!("{}{head}yyyy\n", stamp(' ')));
        trace.push(&format!("{}50%\r\n", stamp('+')));
        trace.push(&format!("{}60%\r\n", stamp('+')));
        assert_eq!(texts(&trace.held()), ["60%"]);
        // A long last drawing is cut at its carriage return, then at its head.
        let mut trace = Trace::default();
        let long = "z".repeat(2 * MAX_HELD_LINE);
        trace.push(&format!("{}old\r{long}\r\n", stamp(' ')));
        let held = trace.finish();
        assert_eq!(held.len(), 1);
        assert!(held[0].text.ends_with(CUT_MARK), "{}", held[0].text.len());
        assert!(held[0].text.starts_with('z'));
        assert_eq!(held[0].text.len(), MAX_HELD_LINE + CUT_MARK.len());
    }

    /// Colours carry between lines and stream stretches. Previewing an open line uses
    /// the saved style without advancing it.
    #[test]
    fn a_colour_carries_from_line_to_line() {
        let stamp = |kind: char| format!("2026-10-09T12:10:43.123456Z 01O{kind}");
        let fg = |l: &TraceLine| l.runs.first().and_then(|r| r.style.fg);
        let output = format!(
            "{}\x1b[31mred\n{}still red\x1b[0m\n{}plain\n",
            stamp(' '),
            stamp(' '),
            stamp(' ')
        );
        let lines = readable(output.as_bytes());
        assert_eq!(
            lines.iter().map(fg).collect::<Vec<_>>(),
            [Some(1), Some(1), None]
        );
        let mut trace = Trace::default();
        assert!(
            trace
                .push(&format!("{}\x1b[32mgreen\n", stamp(' ')))
                .is_empty()
        );
        let done = trace.push(&format!("{}open \x1b[34mblue", stamp(' ')));
        assert_eq!(done.iter().map(fg).collect::<Vec<_>>(), [Some(2)]);
        // Held, open: drawn from green, again and again, the style unmoved by it.
        for _ in 0..2 {
            assert_eq!(trace.held().iter().map(fg).collect::<Vec<_>>(), [Some(2)]);
        }
        assert!(trace.push("\n").is_empty());
        // Done, it is drawn from green still, and leaves blue for the next.
        let done = trace.push(&format!("{}next\n", stamp(' ')));
        assert_eq!(done.iter().map(fg).collect::<Vec<_>>(), [Some(2)]);
        assert_eq!(trace.held().iter().map(fg).collect::<Vec<_>>(), [Some(4)]);
    }

    /// A line left open while the other stream writes on holds back no more than
    /// [`MAX_HELD`]: past it, the open line is taken as done, and the rest follow.
    #[test]
    fn what_is_held_back_is_bounded() {
        let stamp = |io: char| format!("2026-10-09T12:10:43.123456Z 01{io} ");
        let mut trace = Trace::default();
        assert!(trace.push(&format!("{}waiting\n", stamp('E'))).is_empty());
        let mut shown = Vec::new();
        for n in 0..10_000 {
            shown.extend(trace.push(&format!("{}line {n:05} {}\n", stamp('O'), "x".repeat(80))));
        }
        let held: usize = trace
            .held()
            .iter()
            .map(|l| l.text.len() + HELD_LINE_COST)
            .sum();
        assert!(held <= MAX_HELD, "{held}");
        assert_eq!(shown.first().map(|l| l.text.as_str()), Some("waiting"));
        shown.extend(trace.finish());
        assert_eq!(shown.len(), 10_001);
        assert!(shown[1].text.starts_with("line 00000 "));
        assert!(shown[10_000].text.starts_with("line 09999 "));
    }

    #[test]
    fn a_node_s_load_is_its_largest_share() {
        // Placed work against room, alone: an older node, no CPUs known.
        assert_eq!(load(0, 25, 0, 0, None), 0);
        assert_eq!(load(1, 24, 0, 0, None), 40_000);
        // The vCPUs placed, or the load average, per CPU, when larger.
        assert_eq!(load(1, 24, 4, 8, None), 500_000);
        assert_eq!(load(1, 24, 4, 8, Some(600)), 750_000);
        assert_eq!(load(1, 24, 0, 8, Some(1600)), 2_000_000);
        assert_eq!(load(3, 1, 2, 8, Some(100)), 750_000);
    }

    #[test]
    fn candidates_go_least_loaded_then_roomiest_then_by_id() {
        let found = vec![
            ("c".to_string(), 5, 100),
            ("b".to_string(), 9, 100),
            ("a".to_string(), 9, 100),
            ("d".to_string(), 1, 50),
            ("e".to_string(), 30, 900),
        ];
        let order: Vec<String> = least_loaded_first(found)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(order, ["d", "a", "b", "c", "e"]);
    }

    /// A job's preparation ends when it leaves `prepare_executor`, or a first stage past it;
    /// a job already past it when the hub started keeping the time is given none.
    #[test]
    fn a_job_is_prepared_when_it_leaves_prepare_executor() {
        let mut row = sent("n", 2, Some(60)).row;
        let waiting = Activity::Waiting {
            image: "img".into(),
            building: true,
            holder: None,
        };
        note_stage(
            &mut row,
            "prepare_executor",
            Some(waiting.clone()),
            None,
            NOW - 50,
        );
        assert_eq!(
            (row.prepared_at, state_text(&row).as_str()),
            (None, "waiting for build")
        );
        // What a stage of its own does is not said: the job's supervisor starting a service.
        note_stage(
            &mut row,
            "step_script",
            Some(waiting.clone()),
            None,
            NOW - 20,
        );
        assert_eq!(
            (&row.activity, state_text(&row).as_str()),
            (&None, "running: step_script")
        );
        note_stage(&mut row, "after_script", None, None, NOW);
        assert_eq!(row.prepared_at, Some(NOW - 20));
        // Accepted, then straight past it.
        let mut row = sent("n", 2, Some(60)).row;
        note_stage(&mut row, "get_sources", None, None, NOW);
        assert_eq!(row.prepared_at, Some(NOW));
        // Past it before: the next stage is not where its preparation ended.
        let mut row = sent("n", 2, Some(60)).row;
        row.stage = Some("step_script".into());
        note_stage(&mut row, "after_script", None, None, NOW);
        assert_eq!(row.prepared_at, None);
        // Nor is the cleanup after a failed prepare.
        let mut row = sent("n", 2, Some(60)).row;
        note_stage(&mut row, "prepare_executor", Some(waiting), None, NOW - 20);
        note_stage(&mut row, "cleanup", None, None, NOW);
        assert_eq!(row.prepared_at, None);
    }

    /// Retain the reported VM size and display it only when both dimensions are nonzero.
    #[test]
    fn a_job_keeps_its_vm_s_size_once_told() {
        let mut row = sent("n", 2, Some(60)).row;
        note_stage(&mut row, "prepare_executor", None, None, NOW - 50);
        assert_eq!(row.vm_size(), None);
        let size = GuestSize {
            cpus: 4,
            mem_mib: 8192,
        };
        note_stage(&mut row, "get_sources", None, Some(size), NOW - 20);
        assert_eq!(row.guest, Some(size));
        // A later stage that omits the size does not clear it.
        note_stage(&mut row, "step_script", None, None, NOW);
        assert_eq!(row.vm_size(), Some((4, 8192)));
        // A zero dimension makes the size unknown.
        row.guest = Some(GuestSize {
            cpus: 0,
            mem_mib: 8192,
        });
        assert_eq!(row.vm_size(), None);
    }

    /// A job lost while it prepares keeps that stage: all of its time was preparing.
    #[test]
    fn a_job_lost_while_preparing_keeps_its_stage() {
        let mut state = State::default();
        for (id, stage) in [("p", "prepare_executor"), ("s", "step_script")] {
            let mut job = sent("n", 2, Some(60));
            note_stage(&mut job.row, stage, None, None, NOW);
            state.jobs.insert(id.into(), job);
        }
        let mut lost = |id| {
            finish(&mut state, id, Some(FailureClass::Lost), None)
                .unwrap()
                .0
        };
        let (preparing, running) = (lost("p"), lost("s"));
        assert_eq!(
            (preparing.stage.as_deref(), running.stage),
            (Some("prepare_executor"), None)
        );
        assert_eq!(preparing.ran_ms(crate::now_secs()), None);
    }

    /// A node of 8 CPUs reporting `load1_hundredths`, and how long it keeps idle images.
    fn node_row(load1_hundredths: Option<u32>, idle_secs: Option<u64>) -> NodeRow {
        NodeRow {
            inventory: Some(vk_hub_proto::Inventory {
                hardware: vk_hub_proto::Hardware {
                    cpus: 8,
                    ..Default::default()
                },
                ..Default::default()
            }),
            heartbeat: Some(vk_hub_proto::Heartbeat {
                load1_hundredths,
                ..Default::default()
            }),
            report: Some(Report {
                placed: Some(vk_hub_proto::PlacedIntake {
                    image_cache_idle_secs: idle_secs,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    const NOW: u64 = 1_000_000;

    /// A job of `cpus` vCPUs sent to `node`, accepted `started` seconds before [`NOW`] or not
    /// yet.
    fn sent(node: &str, cpus: u32, started: Option<u64>) -> LiveJob {
        let placement = Placement {
            envelope: Envelope {
                cpus,
                ..Envelope::default()
            },
            ..Placement::default()
        };
        let row = serde_json::json!({
            "key": "k", "key_name": "k", "request_id": "r", "created_at": 0, "revision": 1,
            "placement": placement, "node": node,
            "state": if started.is_some() { "running" } else { "starting" },
            "started_at": started.map(|ago| NOW - ago),
        });
        LiveJob {
            row: serde_json::from_value(row).unwrap(),
            spec: None,
            reservation: None,
            deadline: Instant::now(),
            tried: HashSet::new(),
            round_ended: None,
            blocked: None,
            output_cap: 0,
            reservation_accepted_at: 0,
            image_key: None,
            mint_key: None,
            egress: EgressWritten::default(),
        }
    }

    /// A relay job whose tenant stopped listing its project is held; a job recorded without a
    /// scheduling identity, or an API key's, is not.
    #[test]
    fn only_a_relay_job_of_a_delisted_project_is_held() {
        let mut policy = crate::policy::Policy::default();
        let mut row = sent("n1", 1, None).row;
        row.gitlab = Some("gl".into());
        row.project_id = Some(7);
        assert!(!scheduler::delisted(&policy, &row));
        let relay = crate::store::SchedulingIdentity {
            tenant: "fallback".into(),
            class: crate::policy::Class::Normal,
            gitlab: Some("gl".into()),
            runner_id: Some(42),
        };
        row.scheduling = Some(crate::store::SchedulingIdentity {
            gitlab: None,
            runner_id: None,
            ..relay.clone()
        });
        assert!(!scheduler::delisted(&policy, &row));
        row.scheduling = Some(relay);
        assert!(scheduler::delisted(&policy, &row));
        policy.tenants.get_mut("fallback").unwrap().projects = vec![crate::policy::Project {
            gitlab: "gl".into(),
            id: 7,
            production_branches: Vec::new(),
            placement_rules: Vec::new(),
        }];
        assert!(!scheduler::delisted(&policy, &row));
    }

    /// A job recorded without a scheduling identity is held to the rules of the tenant that lists
    /// its project, whichever that is.
    #[test]
    fn a_legacy_job_is_held_to_its_project_s_placement_rules() {
        let mut policy = crate::policy::Policy::default();
        policy.tenants.get_mut("fallback").unwrap().projects = vec![crate::policy::Project {
            gitlab: "gl".into(),
            id: 7,
            production_branches: Vec::new(),
            placement_rules: vec![crate::policy::PlacementRule {
                branches: vec!["main".into()],
                nodes: vec!["n1".into()],
                pools: Vec::new(),
            }],
        }];
        let mut job = sent("n1", 1, None);
        job.row.gitlab = Some("gl".into());
        job.row.project_id = Some(7);
        let mut ci = vk_hub_proto::job::CiJob::default();
        ci.sources.git_ref = "main".into();
        job.spec = Some(Arc::new(JobSpec::GitlabCi(ci)));
        let nodes = [
            ("n1".to_string(), NodeRow::default()),
            ("n2".to_string(), NodeRow::default()),
        ];
        assert_eq!(
            placement_exclusions(&policy, &job, &nodes),
            HashSet::from(["n2".to_string()])
        );
    }

    /// A running job's record is due a write for its egress report once it holds one newer than
    /// the one written, and none was written or tried within the wait.
    #[test]
    fn a_job_s_egress_report_is_due_past_the_wait() {
        let every = Duration::from_secs(30);
        let now = Instant::now() + Duration::from_secs(60);
        let mut job = sent("n1", 2, Some(10));
        assert!(!job.egress_due(now, every), "no report");
        job.row.egress = Some(EgressReport {
            revision: 2,
            ..EgressReport::default()
        });
        assert!(job.egress_due(now, every), "never written");
        job.egress.at = Some(now - Duration::from_secs(5));
        assert!(!job.egress_due(now, every), "written or tried just now");
        job.egress.at = Some(now - every);
        assert!(job.egress_due(now, every));
        job.egress.revision = 2;
        assert!(!job.egress_due(now, every), "written as it is");
    }

    /// The node a job of 2 vCPUs goes to first among `found`, least loaded first, with `warm`
    /// the node that last ran its image `ago` seconds before, and `jobs` sent to nodes.
    fn first(
        warm: (&str, u64),
        nodes: &[(String, NodeRow)],
        found: &[&str],
        jobs: Vec<LiveJob>,
    ) -> String {
        let mut state = State::default();
        for (n, job) in jobs.into_iter().enumerate() {
            state.jobs.insert(n.to_string(), job);
        }
        let (node, ago) = warm;
        warm_touch(&mut state, "key".into(), node, NOW - ago);
        let warm = warm_nodes(&state, nodes, "key", NOW);
        let found: Vec<(String, u64)> = found.iter().map(|id| (id.to_string(), 1)).collect();
        let light = preferred(&state, nodes, &found, &warm, 2, Affinity::default(), NOW);
        warm_first(found, &light).remove(0).0
    }

    /// An instance holds the reservations offered or held, but not one a job took over, and
    /// its jobs queued or sent; a refused or abandoned reservation, a finished job and one in
    /// a state this hub does not know count for nothing. Requests naming no instance count
    /// under the empty one.
    #[test]
    fn an_instance_holds_its_live_reservations_and_jobs() {
        let mut state = State::default();
        let resv = |instance: Option<&str>, phase: ResvPhase| Resv {
            key: "k".into(),
            instance: instance.map(str::to_string),
            node: "n".into(),
            envelope: Envelope::default(),
            phase,
            accepted_at: 0,
            leases: 0,
            ticket: None,
        };
        let held = || ResvPhase::Held { lease_secs: 60 };
        for (id, instance, phase) in [
            ("offered", Some("a"), ResvPhase::Offered),
            ("held", Some("a"), held()),
            ("taken", Some("a"), held()),
            ("refused", Some("a"), ResvPhase::Refused(Refusal::Cpus)),
            ("abandoned", Some("a"), ResvPhase::Abandoned),
            ("anonymous", None, ResvPhase::Offered),
        ] {
            state.reservations.insert(id.into(), resv(instance, phase));
        }
        for (id, instance, job_state, reservation) in [
            ("q", Some("a"), JobState::Queued, Some("taken")),
            ("s", Some("a"), JobState::Starting, None),
            ("r", Some("a"), JobState::Running, None),
            ("f", Some("a"), JobState::Finished, None),
            ("o", Some("a"), JobState::Other, None),
            ("anon", None, JobState::Running, None),
        ] {
            let mut job = sent("n", 1, None);
            job.row.instance = instance.map(str::to_string);
            job.row.state = job_state;
            job.reservation = reservation.map(str::to_string);
            state.jobs.insert(id.into(), job);
        }
        let work = work_of(&state);
        let a = Work {
            reservations: 2,
            queued: 1,
            running: 2,
        };
        let anonymous = Work {
            reservations: 1,
            queued: 0,
            running: 1,
        };
        let want = HashMap::from([
            (("k".to_string(), "a".to_string()), a),
            (("k".to_string(), String::new()), anonymous),
        ]);
        assert_eq!(work, want);
    }

    /// A node keeps its latest use of an image, in whatever order uses are noted: replayed in
    /// submission order, a job still running is followed by one submitted later and finished
    /// earlier. Pruned, a use past a day goes, and its key with it once no node holds it.
    #[test]
    fn a_node_keeps_its_latest_use_of_an_image() {
        let mut state = State::default();
        for at in [NOW, NOW - 600] {
            warm_note(state.warm.entry("key".into()).or_default(), "n", at);
        }
        warm_note(
            state.warm.entry("old".into()).or_default(),
            "n",
            NOW - MAX_IMAGE_IDLE_SECS,
        );
        warm_prune(&mut state, NOW);
        assert_eq!(state.warm.get("key").and_then(|n| n.get("n")), Some(&NOW));
        assert!(!state.warm.contains_key("old"));
        warm_touch(&mut state, "key".into(), "n", NOW - 60);
        assert_eq!(state.warm.get("key").and_then(|n| n.get("n")), Some(&NOW));
    }

    #[test]
    fn a_lightly_loaded_node_holding_the_image_goes_first() {
        // 8 CPUs each; the job's 2 vCPUs add 0.25 per CPU.
        let nodes = |cold_load, warm_load, idle| {
            vec![
                ("cold".to_string(), node_row(cold_load, None)),
                ("warm".to_string(), node_row(warm_load, idle)),
            ]
        };
        let found = ["cold", "warm"];
        let pick = |cold, warm, ago| first(("warm", ago), &nodes(cold, warm, None), &found, vec![]);
        // 0.25 per CPU, 0.5 with the job, 0.25 above the other: the warm node.
        assert_eq!(pick(Some(0), Some(200), 60), "warm");
        // 0.375 above the other: least loaded first; 0.25 above it, the warm node again.
        assert_eq!(pick(Some(0), Some(300), 60), "cold");
        assert_eq!(pick(Some(100), Some(300), 60), "warm");
        // 0.5, 0.75 with the job, though only 0.125 above the other: least loaded first.
        assert_eq!(pick(Some(300), Some(400), 60), "cold");
        assert_eq!(pick(Some(300), Some(1200), 60), "cold");
        // No load average: not known to be lightly loaded.
        assert_eq!(pick(Some(0), None, 60), "cold");
        // The least loaded is one with a load average.
        assert_eq!(pick(None, Some(200), 60), "warm");
        // Jobs it was just sent, not in its load average yet, count: 2 vCPUs not yet accepted
        // put it 0.375 above the other, as do 2 accepted 30 seconds ago; not 2 accepted 90
        // seconds ago, nor 2 just sent to the other too.
        let run = |jobs| first(("warm", 60), &nodes(Some(0), Some(100), None), &found, jobs);
        assert_eq!(run(vec![]), "warm");
        assert_eq!(run(vec![sent("warm", 2, None)]), "cold");
        assert_eq!(run(vec![sent("warm", 2, Some(30))]), "cold");
        assert_eq!(run(vec![sent("warm", 2, Some(90))]), "warm");
        assert_eq!(
            run(vec![sent("warm", 2, None), sent("cold", 2, Some(10))]),
            "warm"
        );
        // Past the node's idle window, 30 minutes when it does not say: it evicted the image.
        assert_eq!(pick(Some(0), Some(200), 1800), "cold");
        assert_eq!(pick(Some(0), Some(200), 1799), "warm");
        let idle = |idle, ago| {
            first(
                ("warm", ago),
                &nodes(Some(0), Some(200), idle),
                &found,
                vec![],
            )
        };
        assert_eq!(idle(Some(3600), 1800), "warm");
        assert_eq!(idle(Some(300), 600), "cold");
        // Not a candidate, for room or caps: never placed on.
        let only_cold = first(
            ("warm", 60),
            &nodes(Some(0), Some(200), None),
            &["cold"],
            vec![],
        );
        assert_eq!(only_cold, "cold");
        // Already first, or no node holds it: unchanged.
        let order = ["warm", "cold"];
        let warm_first = first(("warm", 60), &nodes(Some(0), Some(0), None), &order, vec![]);
        assert_eq!(warm_first, "warm");
        let gone = first(
            ("gone", 60),
            &nodes(Some(0), Some(200), None),
            &found,
            vec![],
        );
        assert_eq!(gone, "cold");
    }

    #[test]
    fn a_node_s_load_per_cpu_adds_cpus_to_its_load_average() {
        assert_eq!(load_per_cpu(Some(200), 0, 8), Some(250_000));
        assert_eq!(load_per_cpu(Some(200), 4, 8), Some(750_000));
        assert_eq!(load_per_cpu(None, 4, 8), None);
        assert_eq!(load_per_cpu(Some(0), 4, 0), None);
    }

    #[test]
    fn only_a_job_whose_image_its_node_builds_has_an_image_key() {
        let on = |server: &str, project: &str, image: &str, services: &[&str]| {
            let mut ci = vk_hub_proto::job::CiJob {
                server_url: server.into(),
                ..Default::default()
            };
            ci.job.project_path = project.into();
            ci.image.name = image.into();
            for s in services {
                ci.services.push(vk_hub_proto::job::Image {
                    name: s.to_string(),
                    ..Default::default()
                });
            }
            image_key(&JobSpec::GitlabCi(ci))
        };
        let job = |project: &str, image: &str, services: &[&str]| {
            on("https://a.example", project, image, services)
        };
        assert_eq!(job("g/p", "alpine:3", &[]), None);
        assert_eq!(job("g/p", "", &["postgres:16"]), None);
        let built = job("g/p", "dockerfile:ci/Dockerfile", &["postgres:16"]);
        assert_eq!(
            built.as_deref(),
            Some("https://a.example\ng/p\ndockerfile:ci/Dockerfile")
        );
        assert_ne!(built, job("g/q", "dockerfile:ci/Dockerfile", &[]));
        // The same project path on another GitLab is another project.
        assert_ne!(
            built,
            on("https://b.example", "g/p", "dockerfile:ci/Dockerfile", &[])
        );
        assert_eq!(
            job("g/p", "alpine:3", &["dockerfile:db/Dockerfile"]).as_deref(),
            Some("https://a.example\ng/p\ndockerfile:db/Dockerfile")
        );
        assert_eq!(
            job("g/p", "compose:compose.yml#app", &[]).as_deref(),
            Some("https://a.example\ng/p\ncompose:compose.yml#app")
        );
    }

    /// Nodes of 25 and 22 envelopes take sequential work in turn.
    #[test]
    fn sequential_work_spreads_over_nodes_of_unequal_room() {
        let mut placed = [0_u64; 2];
        let room = [25_u64, 22];
        let mut took = String::new();
        for _ in 0..6 {
            let found = (0..2)
                .map(|n| {
                    let left = room[n] - placed[n];
                    (n.to_string(), left, load(placed[n], left, 0, 0, None))
                })
                .collect();
            let (first, _) = least_loaded_first(found).remove(0);
            placed[first.parse::<usize>().unwrap()] += 1;
            took.push_str(&first);
        }
        assert_eq!(took, "010101");
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! What tests see of the dispatch state.
    use super::*;

    /// Live job `id`'s [`image_key`], as the hub holds it.
    pub fn image_key(hub: &Hub, id: &str) -> Option<String> {
        (hub.dispatch.lock().jobs.get(id)).and_then(|j| j.image_key.clone())
    }

    /// When `node` last used image `key`, as the hub remembers it.
    pub fn warm_at(hub: &Hub, key: &str, node: &str) -> Option<u64> {
        (hub.dispatch.lock().warm.get(key)).and_then(|nodes| nodes.get(node).copied())
    }

    /// Why arbitration last passed live job `id` over, as [`LiveJob::blocked`] says.
    pub fn job_blocked(hub: &Hub, id: &str) -> Option<&'static str> {
        hub.dispatch.lock().jobs.get(id).and_then(|j| j.blocked)
    }

    /// How many reservations the hub holds.
    pub fn reservations(hub: &Hub) -> usize {
        hub.dispatch.lock().reservations.len()
    }

    /// Run one pass of the placement loop now, as [`drive`] does on a change.
    pub async fn step(hub: &Hub) {
        super::step(hub).await.unwrap();
    }

    /// Have the ticket offered `reservation` go unpolled past [`TICKET_IDLE`], then run a pass.
    pub async fn age_ticket_and_step(hub: &Hub, reservation: &str) {
        {
            let mut state = hub.dispatch.lock();
            let ticket = state
                .tickets
                .values_mut()
                .find(|t| t.reservation.as_deref() == Some(reservation))
                .unwrap();
            ticket.polled = Instant::now() - TICKET_IDLE - Duration::from_secs(1);
        }
        super::step(hub).await.unwrap();
    }

    /// Have the probe abandoned on `reservation` go unanswered past its grace, then run a pass.
    pub async fn age_abandoned_and_step(hub: &Hub, reservation: &str) {
        {
            let mut state = hub.dispatch.lock();
            let (_, since) = state.abandoned_probes.get_mut(reservation).unwrap();
            *since = Instant::now() - scheduler::ABANDONED_PROBE_GRACE;
        }
        super::step(hub).await.unwrap();
    }

    /// Have `node`'s link take no new work, as before it sends its `held`, keeping the
    /// reservations it holds.
    pub fn unhold(hub: &Hub, node: &str) {
        if let Some(link) = hub.dispatch.lock().links.get_mut(node) {
            link.held = false;
        }
    }

    /// Whether `node` has a version-3 link that has sent its `held`.
    pub fn linked(hub: &Hub, node: &str) -> bool {
        hub.dispatch.lock().links.get(node).is_some_and(|l| l.held)
    }

    /// Hold `row` as job `id`'s final row, as the hub does until it is written.
    pub fn hold_finished(hub: &Hub, id: &str, row: JobRow) {
        hub.dispatch.lock().finished.insert(id.to_string(), row);
    }

    /// End job `id` with success in memory only, as it stands before its row is written.
    pub fn finish_unwritten(hub: &Hub, id: &str) {
        let ended = finish(&mut hub.dispatch.lock(), id, None, None);
        assert!(ended.is_some(), "job {id} is not live");
    }

    /// End job `id` with `failure` in memory only: the row and audit events to write.
    pub fn fail_unwritten(
        hub: &Hub,
        id: &str,
        failure: FailureClass,
        message: &str,
    ) -> (JobRow, Vec<Event>) {
        let ended = finish(
            &mut hub.dispatch.lock(),
            id,
            Some(failure),
            Some(message.into()),
        );
        ended.unwrap_or_else(|| panic!("job {id} is not live"))
    }

    /// [`persist`], for tests.
    pub async fn persist(hub: &Hub, id: &str, row: JobRow, events: Vec<Event>) {
        super::persist(hub, id, row, events).await.unwrap();
    }

    /// The most output the hub stores for live job `id`.
    pub fn output_cap(hub: &Hub, id: &str) -> u64 {
        hub.dispatch
            .lock()
            .jobs
            .get(id)
            .map(|j| j.output_cap)
            .unwrap()
    }

    /// [`output_tail`], for tests.
    pub fn output_tail(dir: &Path, id: &str, len: u64, max: u64) -> Result<Vec<u8>> {
        super::output_tail(dir, id, len, max)
    }

    /// Offer `node` a reservation it has not answered, as the hub counts against its
    /// ceiling.
    pub fn offer_unanswered(hub: &Hub, node: &str) {
        let id = crate::random_hex(vk_hub_proto::ID_BYTES).unwrap();
        hub.dispatch.lock().reservations.insert(
            id,
            Resv {
                key: "k".into(),
                instance: None,
                node: node.to_string(),
                envelope: Envelope::default(),
                phase: ResvPhase::Offered,
                accepted_at: 0,
                leases: 0,
                ticket: None,
            },
        );
        hub.dispatch.bump();
    }

    /// Offer a reservation asked for by instance `instance` of key `key`, unanswered.
    pub fn offer_for(hub: &Hub, key: &str, instance: Option<&str>) {
        let id = crate::random_hex(vk_hub_proto::ID_BYTES).unwrap();
        hub.dispatch.lock().reservations.insert(
            id,
            Resv {
                key: key.to_string(),
                instance: instance.map(str::to_string),
                node: "n".into(),
                envelope: Envelope::default(),
                phase: ResvPhase::Offered,
                accepted_at: 0,
                leases: 0,
                ticket: None,
            },
        );
    }

    /// How many placements' capacity revisions the hub keeps.
    pub fn capacity_entries(hub: &Hub) -> usize {
        hub.dispatch.lock().capacity.len()
    }
}
