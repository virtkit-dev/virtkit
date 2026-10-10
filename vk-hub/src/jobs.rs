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
//! that sends no load average is never preferred. What each node ran is kept in memory only.
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
    CancelMode, Capacity, ErrorCode, JobState, JobView, Placement, ReservationGrant,
};
use vk_hub_proto::dispatch::{
    Held, HubJobMsg, JobStart, LeaseEnd, LeaseState, MAX_LEASE_SECS, MAX_OUTPUT_CHUNK, NodeJobMsg,
    OfferReply, Refusal, RunState,
};
use vk_hub_proto::job::{Envelope, FailureClass, JobResult, JobSpec};
use vk_hub_proto::{DesiredState, JOBS, NodeState, Report, StorageRole};

use crate::client::ApiError;
use crate::server::{Hub, Reach};
use crate::store::{ApiPrincipal, JobFilter, JobOutcome, JobPage, JobRow, NodeRow};
use crate::ui::html::Style;

/// How long a node may be unreachable while it holds a job before the job is lost, by
/// default.
pub const DEFAULT_LOST_AFTER: Duration = Duration::from_secs(300);

/// How long the hub waits for a node to answer an offer before it asks another. A node
/// answers from its ledger at once; one this slow has its offer released if it accepts later.
#[cfg(not(test))]
const OFFER_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const OFFER_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a renew waits for the node's answer.
const RENEW_TIMEOUT: Duration = Duration::from_secs(10);

/// How many job messages wait for one session to send them. Far past what a node is asked at
/// once; a session that lets them pile up is not reading, and what does not fit is not sent.
const LINK_QUEUE: usize = 1024;

/// How long before a node that refused a job's start is asked to take it again.
const RETRY_PAUSE: Duration = Duration::from_secs(2);

/// What a client is told to wait after no node accepted.
const NO_CAPACITY_RETRY_SECS: u32 = 5;

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

/// The hub's dispatch state.
pub struct Dispatch {
    state: Mutex<State>,
    /// Bumped at every change a long poll or the placement loop waits for.
    changes: watch::Sender<u64>,
    /// Where jobs' output is kept; `None` on a hub that places no jobs.
    output_dir: Option<PathBuf>,
    /// How long a node holding a job may be unreachable before the job is lost.
    pub lost_after: Duration,
    /// How many jobs' records the history keeps.
    history: usize,
    /// How many bytes from the end of a failed job's output are kept when it is settled; 0
    /// keeps none.
    pub kept_failure_output: u64,
    /// When a node holding a job's image is preferred.
    pub affinity: Affinity,
}

#[derive(Default)]
struct State {
    /// The version-3 sessions, by node.
    links: HashMap<String, Link>,
    reservations: HashMap<String, Resv>,
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

/// A node's version-3 session.
struct Link {
    session: u64,
    tx: mpsc::Sender<HubJobMsg>,
    /// The node has said what it holds, and may be offered work.
    held: bool,
}

struct Resv {
    key: String,
    node: String,
    envelope: Envelope,
    phase: ResvPhase,
    /// When the node accepted it, on the hub's clock in seconds: a heartbeat from before that
    /// does not count it yet.
    accepted_at: u64,
    /// Bumped at each lease the node reports, for a renew waiting on its answer.
    leases: u64,
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
    /// The most output stored for it.
    output_cap: u64,
    /// When the node accepted the reservation it was sent on, as [`Resv::accepted_at`]: until
    /// a heartbeat from after that, its start is counted against the node's room.
    reservation_accepted_at: u64,
    /// Its [`image_key`], from its spec; `None` for a job recovered after a restart.
    image_key: Option<String>,
}

impl LiveJob {
    /// The node it has been sent to, accepted or not.
    fn node(&self) -> Option<&str> {
        self.row.node.as_deref()
    }
}

/// An audit line: the node it is about, who, what.
type Event = (Option<String>, String, String);

/// What the hub does on a node's word, as `hub`.
const HUB: &str = "hub";

impl Dispatch {
    /// Dispatch keeping output in `output_dir`, or none at all, and the records of the newest
    /// `history` jobs.
    pub fn new(output_dir: Option<PathBuf>, lost_after: Duration, history: usize) -> Self {
        Dispatch {
            changes: watch::Sender::new(0),
            output_dir,
            lost_after,
            history,
            kept_failure_output: DEFAULT_KEPT_FAILURE_OUTPUT,
            affinity: Affinity::default(),
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
    let (id, row) = blocking(hub, move |db| {
        db.put_job(&id, &row, &events, crate::now_secs())?;
        Ok((id, row))
    })
    .await?;
    if row.state == JobState::Finished {
        let mut state = hub.dispatch.lock();
        if state
            .finished
            .get(&id)
            .is_some_and(|r| r.revision <= row.revision)
        {
            state.finished.remove(&id);
        }
    }
    hub.touch();
    hub.jobs_changed();
    hub.job_changed(&id);
    Ok(())
}

/// Write `row`, logging rather than failing: the change is made in memory, and the next
/// write of the job carries it.
async fn persist_logged(hub: &Hub, id: &str, row: JobRow, events: Vec<Event>) {
    if let Err(e) = persist(hub, id, row, events).await {
        eprintln!("vk-hub: recording job {id}: {e:#}");
    }
}

/// End `job` with `failure` and `message`, moving it from the live jobs to those finished
/// until [`persist`] has written it, and giving back a reservation it was submitted on and
/// never started on. The row to write and its audit line.
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
    row.state = JobState::Finished;
    row.revision = row.revision.saturating_add(1);
    row.finished_at = Some(crate::now_secs());
    row.stage = None;
    let output_len = row.output_len;
    let how = match failure {
        Some(f) => failure_name(f),
        None => "success",
    };
    let event = match &message {
        Some(m) => format!("job {id} ended: {how}: {m}"),
        None => format!("job {id} ended: {how}"),
    };
    row.result = Some(JobResult {
        failure,
        exit_code: None,
        message,
        output_len,
        artifacts: Vec::new(),
        usage: None,
    });
    let events = vec![(row.node.clone(), HUB.to_string(), event)];
    state.finished.insert(id.to_string(), job.row.clone());
    Some((job.row, events))
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
        (JobState::Running, _) => match &j.stage {
            Some(stage) => format!("running: {stage}"),
            None => "running".to_string(),
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
            // Journaled: accepted, whatever answer was lost.
            if job.row.state != JobState::Running {
                job.row.state = JobState::Running;
                job.row.started_at.get_or_insert_with(crate::now_secs);
                job.row.revision = job.row.revision.saturating_add(1);
                job.spec = None;
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
    match (&r.phase, reply) {
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
            match reply {
                OfferReply::Accepted { .. } => release(),
                OfferReply::Refused { .. } => Vec::new(),
            }
        }
        // A second answer to one offer changes nothing.
        _ => Vec::new(),
    }
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
                return Ok(Vec::new());
            }
            LeaseState::Gone { why } => {
                let r = state.reservations.remove(id);
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
                events.push((
                    Some(node.to_string()),
                    HUB.to_string(),
                    format!("node {node} accepted job {id}"),
                ));
            }
            RunState::Refused { reason, message } => {
                if row.state != JobState::Starting {
                    return Ok(Vec::new());
                }
                // It ran nowhere: free to place again, elsewhere first. A reservation it was
                // sent on goes back.
                row.state = JobState::Queued;
                row.node = None;
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
            RunState::Running { stage } => {
                row.state = JobState::Running;
                row.started_at.get_or_insert_with(crate::now_secs);
                job.spec = None;
                job.reservation = None;
                row.stage = Some(vk_hub_proto::display_safe(&stage));
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

async fn on_result(
    hub: &Hub,
    node: &str,
    id: &str,
    mut result: JobResult,
) -> Result<Vec<HubJobMsg>> {
    let recorded = vec![HubJobMsg::Recorded {
        job: id.to_string(),
    }];
    let write = {
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
        let failure = result.failure;
        let Some((mut row, mut events)) = finish(&mut state, id, failure, None) else {
            return Ok(recorded);
        };
        row.result = Some(result);
        state.finished.insert(id.to_string(), row.clone());
        events = events
            .into_iter()
            .map(|(n, a, _)| {
                let how = failure.map_or("success", failure_name);
                (n, a, format!("job {id} finished on node {node}: {how}"))
            })
            .collect();
        (row, events)
    };
    persist(hub, id, write.0, write.1).await?;
    Ok(recorded)
}

// ---------------------------------------------------------------------------------------------
// Placement.

/// A node's room for `placement`'s envelope: how many it fits, `None` when it takes no
/// placed work now.
/// `placed` is the node's placed work, as [`placed`] counts it.
fn room(
    hub: &Hub,
    state: &State,
    node: &str,
    row: &NodeRow,
    placement: &Placement,
    placed: u64,
) -> Option<u64> {
    let link = state.links.get(node)?;
    if !link.held || hub.reach(node) != Reach::Connected {
        return None;
    }
    if !row.pools.contains(&placement.pool) {
        return None;
    }
    let inventory = row.inventory.as_ref()?;
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
    let tallies = tallies(state);
    nodes
        .iter()
        .filter(|(id, _)| !skip.contains(id))
        .filter_map(|(id, row)| {
            let tally = tallies.get(id.as_str()).copied().unwrap_or_default();
            let room = room(hub, state, id, row, placement, tally.placed)?;
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
    nodes.insert(node.to_string(), now);
    if state.warm.len() > MAX_IMAGE_KEYS
        && let Some(oldest) = (state.warm.iter())
            .min_by_key(|(_, nodes)| nodes.values().max().copied().unwrap_or(0))
            .map(|(k, _)| k.clone())
    {
        state.warm.remove(&oldest);
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

/// Reserve `placement`'s envelope on a node for `principal`, for `lease_secs`, offering it to
/// one node after another for up to `wait`.
pub async fn reserve(
    hub: &Hub,
    principal: &ApiPrincipal,
    placement: &Placement,
    lease_secs: u32,
    wait: Duration,
) -> Result<ReservationGrant, ApiError> {
    hub.dispatch.output_dir()?;
    let started = Instant::now();
    let deadline = started + wait;
    // Each offer waits at most until then: the first gets its full time, and none outlasts
    // the request's wait by more.
    let offers_until = deadline.max(started + OFFER_TIMEOUT);
    let lease_secs = lease_secs.clamp(1, MAX_LEASE_SECS);
    let mut tried = HashSet::new();
    let mut offered = false;
    loop {
        let mut changed = hub.dispatch.subscribe();
        let mut node_changed = hub.subscribe();
        let nodes = blocking(hub, |db| db.nodes()).await?;
        // Ranked once a round: after a refusal or a timeout, the next offer follows this order.
        let found = {
            let state = hub.dispatch.lock();
            candidates(hub, &state, &nodes, placement, &tried)
        };
        for (node, _) in found {
            if offered && Instant::now() >= deadline {
                return Err(no_capacity());
            }
            tried.insert(node.clone());
            let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
            {
                let mut state = hub.dispatch.lock();
                state.reservations.insert(
                    id.clone(),
                    Resv {
                        key: principal.id.clone(),
                        node: node.clone(),
                        envelope: placement.envelope,
                        phase: ResvPhase::Offered,
                        accepted_at: 0,
                        leases: 0,
                    },
                );
                let offer = HubJobMsg::Offer {
                    reservation: id.clone(),
                    envelope: placement.envelope,
                    lease_secs,
                };
                if !send(&state, &node, offer) {
                    state.reservations.remove(&id);
                    continue;
                }
            }
            offered = true;
            match offer_answer(hub, &id, offers_until).await {
                Some(lease_secs) => {
                    return Ok(ReservationGrant {
                        reservation: id,
                        node,
                        envelope: placement.envelope,
                        lease_secs,
                    });
                }
                None => continue,
            }
        }
        if Instant::now() >= deadline {
            return Err(no_capacity());
        }
        // Every node with room was asked: after a pause, and a change, ask them all again.
        tokio::time::sleep_until(deadline.min(Instant::now() + RETRY_PAUSE)).await;
        tokio::select! {
            _ = changed.changed() => {}
            _ = node_changed.changed() => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
        if Instant::now() >= deadline {
            return Err(no_capacity());
        }
        tried.clear();
    }
}

fn no_capacity() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::NoCapacity,
        "no node accepted the reservation in time",
    )
    .retry_after(NO_CAPACITY_RETRY_SECS)
}

/// Wait for the node's answer to offer `id`, for [`OFFER_TIMEOUT`] and not past `until`: the
/// lease it granted, or `None` when it refused, went away or took too long — an offer then
/// abandoned, released if accepted later.
async fn offer_answer(hub: &Hub, id: &str, until: Instant) -> Option<u32> {
    let deadline = (Instant::now() + OFFER_TIMEOUT).min(until);
    loop {
        let mut changed = hub.dispatch.subscribe();
        {
            let mut state = hub.dispatch.lock();
            match state.reservations.get(id).map(|r| r.phase.clone()) {
                None => return None,
                Some(ResvPhase::Held { lease_secs }) => return Some(lease_secs),
                Some(ResvPhase::Refused(_)) | Some(ResvPhase::Abandoned) => {
                    state.reservations.remove(id);
                    return None;
                }
                Some(ResvPhase::Offered) if Instant::now() >= deadline => {
                    if let Some(r) = state.reservations.get_mut(id) {
                        r.phase = ResvPhase::Abandoned;
                    }
                    return None;
                }
                Some(ResvPhase::Offered) => {}
            }
        }
        tokio::select! {
            _ = changed.changed() => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
    }
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
/// within `place_within`. The caller has recorded it.
pub fn admit(
    hub: &Hub,
    id: &str,
    row: JobRow,
    spec: JobSpec,
    reservation: Option<String>,
    place_within: Duration,
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
            output_cap: limit.saturating_add(OUTPUT_SLACK).min(MAX_OUTPUT),
            reservation_accepted_at: 0,
            image_key,
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
                let (row, mut events) = finish(&mut state, id, Some(FailureClass::Canceled), None)
                    .ok_or_else(|| not_found(&format!("no job {id}")))?;
                events.insert(
                    0,
                    (
                        None,
                        actor.clone(),
                        format!("{actor} canceled job {id} before it was placed"),
                    ),
                );
                Some((row, events))
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
/// record so the failure details remain readable.
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
    let keep = hub.dispatch.kept_failure_output;
    if keep > 0 && row.outcome() == JobOutcome::Failed {
        // Kept before the file goes: a hub stopped in between keeps it when settled again.
        let (dir, job, len) = (dir.clone(), id.to_string(), row.output_len);
        blocking(hub, move |db| {
            let tail = output_tail(&dir, &job, len, keep)?;
            if !tail.is_empty() {
                db.keep_job_tail(&job, &tail)?;
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
    let actor = principal.actor();
    let event = format!("{actor} settled job {id}");
    persist(hub, id, row, vec![(None, actor, event)]).await?;
    hub.dispatch.bump();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The placement loop.

/// Pick the hub's jobs back up after a restart: a job no node had accepted ends lost; one
/// running carries on, its output as stored. Output no job may read again goes.
pub async fn recover(hub: &Hub) -> Result<()> {
    let Some(dir) = hub.dispatch.output_dir.clone() else {
        return Ok(());
    };
    let swept = dir.clone();
    blocking(hub, move |db| sweep_outputs(db, &swept)).await?;
    let rows = blocking(hub, |db| db.unfinished_jobs()).await?;
    for (id, mut row) in rows {
        row.output_len = stored_len(&dir, &id);
        if row.state == JobState::Running && row.node.is_some() {
            let limit = DEFAULT_OUTPUT_LIMIT.max(row.output_len);
            hub.dispatch.lock().jobs.insert(
                id.clone(),
                LiveJob {
                    row,
                    spec: None,
                    reservation: None,
                    deadline: Instant::now(),
                    tried: HashSet::new(),
                    round_ended: None,
                    // Its spec, and its limit, are gone: what it has stored, and the default
                    // limit's worth past it.
                    output_cap: limit.saturating_add(DEFAULT_OUTPUT_LIMIT).min(MAX_OUTPUT),
                    reservation_accepted_at: 0,
                    image_key: None,
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
                output_cap: 0,
                reservation_accepted_at: 0,
                image_key: None,
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
    let mut pruned = Instant::now();
    loop {
        let mut changed = hub.dispatch.subscribe();
        let mut node_changed = hub.subscribe();
        if let Err(e) = step(&hub).await {
            eprintln!("vk-hub: placing jobs: {e:#}");
        }
        if pruned.elapsed() >= PRUNE_EVERY {
            pruned = Instant::now();
            prune(&hub).await;
        }
        tokio::select! {
            _ = changed.changed() => {}
            _ = node_changed.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn prune(hub: &Hub) {
    let keep = hub.dispatch.history;
    let gone = match blocking(hub, move |db| db.prune_jobs(crate::now_secs(), keep)).await {
        Ok(gone) => gone,
        Err(e) => {
            eprintln!("vk-hub: pruning jobs: {e:#}");
            return;
        }
    };
    // `gone` names only the jobs that held output: a settled job trimmed is not in it.
    hub.jobs_changed();
    if let Some(dir) = hub.dispatch.output_dir.clone() {
        for id in gone {
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
}

/// One pass of [`drive`].
async fn step(hub: &Hub) -> Result<()> {
    let queued = {
        let state = hub.dispatch.lock();
        state.jobs.values().any(|j| j.row.state == JobState::Queued)
    };
    let nodes = if queued {
        blocking(hub, |db| db.nodes()).await?
    } else {
        Vec::new()
    };
    let mut writes = Vec::new();
    {
        let mut state = hub.dispatch.lock();
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
        // Queued jobs: placed, or ended past their deadline.
        let mut ids: Vec<(Instant, String)> = state
            .jobs
            .iter()
            .filter(|(_, j)| j.row.state == JobState::Queued)
            .map(|(id, j)| (j.deadline, id.clone()))
            .collect();
        ids.sort();
        for (deadline, id) in ids {
            // Canceled while its start was out, then refused or never taken: it ran nowhere.
            let canceled = state.jobs.get(&id).is_some_and(|j| j.row.cancel.is_some());
            if canceled {
                if let Some(w) = finish(&mut state, &id, Some(FailureClass::Canceled), None) {
                    writes.push((id, w.0, w.1));
                }
                continue;
            }
            // Placed if it can be, even at its deadline: a window of 0 takes a node now.
            if let Some(w) = place(hub, &mut state, &nodes, &id, now) {
                writes.push(w);
                continue;
            }
            if now >= deadline {
                let message = "no node took it within its placement window".to_string();
                if let Some(w) = finish(
                    &mut state,
                    &id,
                    Some(FailureClass::NoCapacity),
                    Some(message),
                ) {
                    writes.push((id, w.0, w.1));
                }
            }
        }
    }
    let changed = !writes.is_empty();
    for (id, row, events) in writes {
        persist_logged(hub, &id, row, events).await;
    }
    if changed {
        hub.dispatch.bump();
    }
    Ok(())
}

/// Send queued job `id` to its reservation's node while the reservation holds, else the
/// least loaded candidate that has not refused it ([`candidates`]). Prefer a lightly loaded
/// candidate holding its image unless the reservation's node also holds it ([`warm_nodes`]).
/// Return the row to write if sent.
fn place(
    hub: &Hub,
    state: &mut State,
    nodes: &[(String, NodeRow)],
    id: &str,
    now: Instant,
) -> Option<(String, JobRow, Vec<Event>)> {
    let job = state.jobs.get(id)?;
    let spec = job.spec.clone()?;
    let placement = job.row.placement.clone();
    let mut tried = job.tried.clone();
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
        let x = state.reservations.get(r)?;
        let ok = matches!(x.phase, ResvPhase::Held { .. })
            && state.links.get(&x.node).is_some_and(|l| l.held);
        ok.then(|| (r.clone(), x.node.clone(), x.envelope, x.accepted_at))
    });
    // A reservation on a node without the image gives way to a lightly loaded node with it.
    let given_up = reserved
        .as_ref()
        .filter(|(_, node, _, _)| {
            if warm.contains(node) || warm.is_empty() {
                return false;
            }
            let found = candidates(hub, state, nodes, &placement, &tried);
            !preferred_among(state, &found).is_empty()
        })
        .map(|(r, _, _, _)| r.clone());
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
                tried.clear();
                found = candidates(hub, state, nodes, &placement, &tried);
            }
            let light = preferred_among(state, &found);
            let (node, _) = warm_first(found, &light).into_iter().next()?;
            (node, None, placement.envelope)
        }
    };
    let start = HubJobMsg::Start(Box::new(JobStart {
        job: id.to_string(),
        reservation: reservation.clone(),
        envelope,
        spec: (*spec).clone(),
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
    job.reservation = reservation.clone();
    job.reservation_accepted_at = accepted_at;
    job.row.state = JobState::Starting;
    job.row.node = Some(node.clone());
    job.row.revision = job.row.revision.saturating_add(1);
    let row = job.row.clone();
    let mut how = match &reservation {
        Some(r) => format!("on reservation {r}"),
        None => "without a reservation".to_string(),
    };
    if warm.contains(&node) {
        how.push_str(", where its image is warm");
    }
    if let Some(r) = given_up
        && let Some(x) = state.reservations.remove(&r)
    {
        send(
            state,
            &x.node,
            HubJobMsg::Release {
                reservation: r.clone(),
            },
        );
        how.push_str(&format!(", giving back reservation {r} on node {}", x.node));
    }
    let event = format!("hub sent job {id} to node {node} {how}");
    Some((
        id.to_string(),
        row,
        vec![(Some(node), HUB.to_string(), event)],
    ))
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
    let mut page = hub.db.job_page(filter, before, limit, crate::now_secs())?;
    let state = hub.dispatch.lock();
    page.rows.retain_mut(|(_, id, row)| {
        if let Some(live) = live_row(&state, id) {
            *row = live.clone();
        }
        filter.matches(row)
    });
    Ok(page)
}

/// Job `id`'s record and, for a failed job, its node-masked output tail: retained at
/// settlement or read from the stored output before settlement. Returns `None` if the job
/// is not in the history.
pub fn detail(hub: &Hub, id: &str) -> Result<Option<(JobRow, Option<Vec<u8>>)>> {
    // An output file is named by the ID.
    if !vk_hub_proto::valid_id(id) {
        return Ok(None);
    }
    let live = live_row(&hub.dispatch.lock(), id).cloned();
    let Some(row) = live.map_or_else(|| hub.db.job(id), |r| Ok(Some(r)))? else {
        return Ok(None);
    };
    if row.outcome() != JobOutcome::Failed {
        return Ok(Some((row, None)));
    }
    let mut tail = hub.db.job_tail(id)?;
    let keep = hub.dispatch.kept_failure_output;
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
            output_cap: 0,
            reservation_accepted_at: 0,
            image_key: None,
        }
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

    /// How many reservations the hub holds.
    pub fn reservations(hub: &Hub) -> usize {
        hub.dispatch.lock().reservations.len()
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
                node: node.to_string(),
                envelope: Envelope::default(),
                phase: ResvPhase::Offered,
                accepted_at: 0,
                leases: 0,
            },
        );
        hub.dispatch.bump();
    }

    /// How many placements' capacity revisions the hub keeps.
    pub fn capacity_entries(hub: &Hub) -> usize {
        hub.dispatch.lock().capacity.len()
    }
}
