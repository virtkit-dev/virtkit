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
//! and starts not yet answered. Offers and starts go to the node with the most room first.
//! The hub places a job again only while no node can have started it: after a refused start,
//! or a start that never went out; a start whose answer was lost waits for the node's `held`.
//!
//! **Lost nodes.** A node holding a job that stays unreachable for [`Dispatch::lost_after`]
//! loses it: the job ends [`FailureClass::Lost`], and the node is told to cancel it when it
//! comes back. A node's session ending ends its reservations at once; the node's `held`
//! names them when it is back, and the hub releases them.

use std::collections::{HashMap, HashSet};
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
use vk_hub_proto::{JOBS, NodeState, StorageRole};

use crate::client::ApiError;
use crate::server::{Hub, Reach};
use crate::store::{ApiPrincipal, JobFilter, JobOutcome, JobPage, JobRow, NodeRow};

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
        for j in held.jobs {
            let Some(job) = state.jobs.get_mut(&j.job) else {
                unknown.push(j.job);
                continue;
            };
            if job.node() != Some(node) {
                unknown.push(j.job);
                continue;
            }
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
        (row.clone(), events)
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
        let mut state = hub.dispatch.lock();
        if let Some(job) = state.jobs.get_mut(id) {
            job.row.output_len = have.saturating_add(len);
        }
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
fn room(hub: &Hub, state: &State, node: &str, row: &NodeRow, placement: &Placement) -> Option<u64> {
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
    if row
        .report
        .as_ref()
        .and_then(|r| r.state)
        .is_some_and(|s| s != NodeState::Ready)
    {
        return None;
    }
    let env = placement.envelope;
    if env.cpus > inventory.hardware.cpus {
        return None;
    }
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
    let mut fits = MAX_FITS;
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

/// The nodes with room for `placement`, most room first, but those in `skip`.
fn candidates(
    hub: &Hub,
    state: &State,
    nodes: &[(String, NodeRow)],
    placement: &Placement,
    skip: &HashSet<String>,
) -> Vec<(String, u64)> {
    let mut found: Vec<(String, u64)> = nodes
        .iter()
        .filter(|(id, _)| !skip.contains(id))
        .filter_map(|(id, row)| Some((id.clone(), room(hub, state, id, row, placement)?)))
        .collect();
    found.sort_by(|(a, x), (b, y)| y.cmp(x).then_with(|| a.cmp(b)));
    found
}

/// `POST /v1/capacity`'s answer for `placement`: the envelopes its nodes have room for, and
/// its revision, which moves when that does.
pub async fn capacity(hub: &Hub, placement: &Placement) -> Result<Capacity> {
    let nodes = blocking(hub, |db| db.nodes()).await?;
    let key = serde_json::to_string(placement).context("encoding a placement")?;
    let mut state = hub.dispatch.lock();
    let fits: u64 = candidates(hub, &state, &nodes, placement, &HashSet::new())
        .iter()
        .map(|(_, n)| n)
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

/// Send queued job `id` to a node: the one its reservation is on while the reservation
/// holds, else the one with the most room it has not refused. The row to write, if it went.
fn place(
    hub: &Hub,
    state: &mut State,
    nodes: &[(String, NodeRow)],
    id: &str,
    now: Instant,
) -> Option<(String, JobRow, Vec<Event>)> {
    let job = state.jobs.get(id)?;
    let spec = job.spec.clone()?;
    let reserved = job.reservation.as_ref().and_then(|r| {
        let x = state.reservations.get(r)?;
        let ok = matches!(x.phase, ResvPhase::Held { .. })
            && state.links.get(&x.node).is_some_and(|l| l.held);
        ok.then(|| (r.clone(), x.node.clone(), x.envelope, x.accepted_at))
    });
    let mut accepted_at = 0;
    let (node, reservation, envelope) = match reserved {
        Some((r, node, envelope, at)) => {
            accepted_at = at;
            (node, Some(r), envelope)
        }
        None => {
            let placement = job.row.placement.clone();
            let mut tried = job.tried.clone();
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
            let (node, _) = found.into_iter().next()?;
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
    let how = match &reservation {
        Some(r) => format!("on reservation {r}"),
        None => "without a reservation".to_string(),
    };
    let event = format!("hub sent job {id} to node {node} {how}");
    Some((
        id.to_string(),
        job.row.clone(),
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

/// One line of a job's output as [`readable`] makes it.
#[derive(Debug, PartialEq, Eq)]
pub struct TraceLine {
    /// When it came, from its stamp (`FF_TIMESTAMPS`): `2026-10-09T12:10:43.123456Z`.
    pub at: Option<String>,
    /// Its text, [`crate::ui::html::terminal_safe`].
    pub text: String,
}

/// `output`, a job's trace, for reading: lines continued (`+` stamps) joined to the line they
/// continue, a line rewritten by carriage returns shown as it was left, GitLab's collapsible
/// section markers removed (a line that held nothing else with them), and the terminal's escape
/// sequences and other controls dropped.
pub fn readable(output: &[u8]) -> Vec<TraceLine> {
    use vk_hub_proto::stamp::HEADER_LEN;
    // For display alone: an invalid sequence shows as U+FFFD.
    let output = String::from_utf8_lossy(output);
    let mut joined: Vec<(Option<String>, String)> = Vec::new();
    // By stream and `O`/`E` (header bytes 28..31): the index of its last line, which a `+`
    // continues.
    let mut last: HashMap<&str, usize> = HashMap::new();
    for line in output.split_terminator('\n') {
        let Some(h) = line.get(..HEADER_LEN).filter(|h| stamped(h.as_bytes())) else {
            joined.push((None, line.to_string()));
            continue;
        };
        let text = line.get(HEADER_LEN..).unwrap_or_default();
        let key = h.get(28..31).unwrap_or_default();
        let continued = h.as_bytes().get(HEADER_LEN - 1) == Some(&b'+');
        match last.get(key).and_then(|&i| joined.get_mut(i)) {
            Some(prev) if continued => prev.1.push_str(text),
            _ => {
                last.insert(key, joined.len());
                joined.push((
                    h.get(..HEADER_LEN - 5).map(str::to_string),
                    text.to_string(),
                ));
            }
        }
    }
    let mut lines = Vec::new();
    for (at, text) in joined {
        let (text, marked) = without_sections(&text);
        // What the terminal was left showing: the text after the last carriage return.
        let shown = text
            .trim_end_matches('\r')
            .rsplit('\r')
            .next()
            .unwrap_or_default();
        let text = crate::ui::html::terminal_safe(shown);
        if marked && text.trim().is_empty() {
            continue;
        }
        lines.push(TraceLine { at, text });
    }
    lines
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

    /// How many placements' capacity revisions the hub keeps.
    pub fn capacity_entries(hub: &Hub) -> usize {
        hub.dispatch.lock().capacity.len()
    }
}
