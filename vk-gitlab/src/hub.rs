//! [`Dispatcher`] over vk-hub's client API, on the relay's one HTTP/2 connection to the hub.
//! Defined in `docs/gitlab-dispatch.md`, "Daemon ↔ hub", and vk-hub's `src/client.rs`.
//!
//! The session ([`crate::session`]) dials that connection and authenticates it; requests ride
//! it, unsigned, while the session is up, and wait for the next session while there is none.
//! The hub tells the session when a ticket or a job of the relay changes, and the [`Link`]
//! keeps its latest notice per ticket and job. Nothing long-polls: a wait for a ticket's
//! grant, a job's next revision or more of its output fetches at once the first time and in
//! each new session, which may have missed a notice; else it ends on a notice about its object,
//! or after [`MAX_WAIT_SECS`], and then fetches. At most
//! [`MAX_OUTPUTS`] output reads and [`MAX_SUBMISSIONS`] submissions, the only large bodies,
//! are in flight, so that the session's stream never waits behind more than the connection's
//! windows hold.
//!
//! Transport errors and the retryable codes (`unavailable`, `internal`, and `no_capacity`
//! outside a reservation) are retried with backoff from 1 to 30 seconds and jitter, honouring
//! `retry_after_secs` up to a minute; any other 4xx is not. A create carries the
//! caller's `request_id`, which the hub keeps for a day, so a retried create answers the
//! first answer: a submission is retried until its `place_within` is up. An answer whose
//! body is cut short is retried as a request without one is. A renewal is tried once, and
//! its caller retries it within the lease.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde::Serialize;
use serde::de::DeserializeOwned;
use vk_hub_proto::client::{
    CAPACITY_PATH, CancelMode, CancelRequest, Capacity, CapacityRequest, ClientError, ErrorCode,
    JOBS_PATH, JobSubmission, JobView, MAX_OUTPUT_READ, MAX_WAIT_SECS, OUTPUT_COMPLETE_HEADER,
    OUTPUT_LENGTH_HEADER, OUTPUT_OFFSET_HEADER, Placement, RESERVATIONS_PATH, RenewRequest,
    ReservationGrant, ReservationRequest, ReservationTicket, TICKETS_PATH,
};
use vk_hub_proto::dispatch::MAX_LEASE_SECS;
use vk_hub_proto::job::MAX_JOB_SPEC;
use vk_hub_proto::valid_id;

use crate::backoff::Backoff;
use crate::dispatch::{
    DispatchError, DispatchResult, Dispatcher, ErrorKind, OutputChunk, QueueAnswer, Reservation,
    Submission,
};

/// How long a request may take, its wait for a session included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest `retry_after_secs` (or `Retry-After`) honoured.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// The most an answer's body is read to: an output read, and room for its headers' worth.
const MAX_ANSWER: usize = MAX_OUTPUT_READ + (64 << 10);
/// How often the connection is pinged.
const PING_INTERVAL: Duration = Duration::from_secs(20);
/// Ping response deadline. A timeout closes the connection, and with it the session.
const PING_TIMEOUT: Duration = Duration::from_secs(10);
/// What the hub may send on the connection before the relay reads it: [`MAX_OUTPUTS`] output
/// reads, with room left for the session's stream.
const CONNECTION_WINDOW: u32 = 5 << 20;
/// What the hub may send on one stream before the relay reads it: an output read whole.
const STREAM_WINDOW: u32 = 2 << 20;
/// Output reads in flight at most: up to 4 MiB from the hub.
pub const MAX_OUTPUTS: usize = 4;
/// Submissions in flight at most: specs of up to 512 KiB each to the hub, whose connection
/// window is 4 MiB.
pub const MAX_SUBMISSIONS: usize = 4;
/// How long the latest notice about a ticket or a job is kept for an ID nothing waits on.
const UNCLAIMED: Duration = Duration::from_secs(120);

const _: () = assert!(MAX_OUTPUTS * MAX_ANSWER < CONNECTION_WINDOW as usize);
const _: () = assert!(MAX_ANSWER <= STREAM_WINDOW as usize);

/// The relay's HTTP/2 to the hub: pings that find a dead connection, and windows that let
/// [`MAX_OUTPUTS`] output reads arrive whole.
pub fn http2_builder() -> http2::Builder<TokioExecutor> {
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .keep_alive_interval(PING_INTERVAL)
        .keep_alive_timeout(PING_TIMEOUT)
        .keep_alive_while_idle(true)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .initial_stream_window_size(STREAM_WINDOW);
    builder
}

/// The relay's connection to the hub, as its session and its client share it: the request
/// sender of the session's connection while the session is up, and the hub's latest notice
/// about each ticket and job.
pub struct Link {
    state: Mutex<LinkState>,
    /// Moved on at every change of `state`, for the waiters.
    changed: watch::Sender<u64>,
}

#[derive(Default)]
struct LinkState {
    conn: Option<Conn>,
    /// Sessions up so far.
    sessions: u64,
    tickets: HashMap<String, Told>,
    jobs: HashMap<String, Told>,
}

/// A session's connection.
#[derive(Clone)]
struct Conn {
    sender: http2::SendRequest<Full<Bytes>>,
    /// `scheme://host:port`, which a request's URI starts with.
    base: String,
}

/// What the relay knows of a ticket or a job: the hub's notices, and its own fetches.
struct Told {
    /// Notices about it so far.
    count: u64,
    /// The highest revision and output length told or fetched in the current session: the
    /// hub has at least these. A restarted hub may have recovered less.
    revision: u64,
    output_len: u64,
    /// `count` and the session at the last fetch of a ticket, or of a job's output.
    fetched: Option<(u64, u64)>,
    /// The session at the last fetch of a job's view.
    viewed: Option<u64>,
    /// Waited on: kept until its ticket ends or its job is settled.
    claimed: bool,
    /// When it was first told.
    told_at: Instant,
}

impl Told {
    fn new() -> Self {
        Told {
            count: 0,
            revision: 0,
            output_len: 0,
            fetched: None,
            viewed: None,
            claimed: false,
            told_at: Instant::now(),
        }
    }
}

/// Shares a session's connection while it lives: dropped when the session ends.
pub struct Up<'a> {
    link: &'a Link,
    session: u64,
}

impl Drop for Up<'_> {
    fn drop(&mut self) {
        self.link.modify(|s| {
            if s.conn.is_some() && s.sessions == self.session {
                s.conn = None;
            }
        });
    }
}

impl Link {
    pub fn new() -> Arc<Self> {
        Arc::new(Link {
            state: Mutex::new(LinkState::default()),
            changed: watch::Sender::new(0),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LinkState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn modify<T>(&self, f: impl FnOnce(&mut LinkState) -> T) -> T {
        let out = f(&mut self.lock());
        self.changed.send_modify(|n| *n = n.wrapping_add(1));
        out
    }

    /// A session is up on the connection `sender` sends on, reached at `base`
    /// (`scheme://host:port`): requests go on it until the [`Up`] is dropped. A new session
    /// tells every waiter to fetch, as a notice about everything would.
    pub fn up(&self, sender: http2::SendRequest<Full<Bytes>>, base: String) -> Up<'_> {
        let session = self.modify(|s| {
            s.sessions = s.sessions.wrapping_add(1);
            s.conn = Some(Conn { sender, base });
            for t in s.tickets.values_mut().chain(s.jobs.values_mut()) {
                t.revision = 0;
                t.output_len = 0;
            }
            s.sessions
        });
        Up {
            link: self,
            session,
        }
    }

    /// The hub's notice that ticket `id` was granted or ended.
    pub fn told_ticket(&self, id: &str) {
        self.modify(|s| {
            forget_unclaimed(&mut s.tickets);
            let t = s.tickets.entry(id.to_owned()).or_insert_with(Told::new);
            t.count = t.count.wrapping_add(1);
        });
    }

    /// The hub's notice that job `id` is at `revision`, with `output_len` bytes of output.
    pub fn told_job(&self, id: &str, revision: u64, output_len: u64) {
        self.modify(|s| {
            forget_unclaimed(&mut s.jobs);
            let j = s.jobs.entry(id.to_owned()).or_insert_with(Told::new);
            j.count = j.count.wrapping_add(1);
            j.revision = j.revision.max(revision);
            j.output_len = j.output_len.max(output_len);
        });
    }

    /// The current session's connection, once there is one.
    async fn connection(&self) -> Conn {
        let mut rx = self.changed.subscribe();
        loop {
            if let Some(conn) = self.lock().conn.as_ref().filter(|c| !c.sender.is_closed()) {
                return conn.clone();
            }
            if rx.changed().await.is_err() {
                // Never: `self` holds the sender.
                return std::future::pending().await;
            }
        }
    }

    /// Wait until `ready` holds or `wait`, capped at [`MAX_WAIT_SECS`], passes; then run `fetching`.
    async fn wait(
        &self,
        wait: Duration,
        mut ready: impl FnMut(&mut LinkState) -> bool,
        fetching: impl FnOnce(&mut LinkState),
    ) {
        let deadline = Instant::now() + wait.min(Duration::from_secs(u64::from(MAX_WAIT_SECS)));
        let mut rx = self.changed.subscribe();
        loop {
            if ready(&mut self.lock()) {
                break;
            }
            tokio::select! {
                r = rx.changed() => if r.is_err() { break },
                () = tokio::time::sleep_until(deadline) => break,
            }
        }
        fetching(&mut self.lock());
    }

    /// Wait to fetch ticket `id`: at once the first time and in each new session, which may
    /// have missed a notice; else until the hub tells of it, or `wait`.
    async fn ticket(&self, id: &str, wait: Duration) {
        self.wait(
            wait,
            |s| {
                let session = s.sessions;
                let t = claim(&mut s.tickets, id);
                t.fetched != Some((t.count, session))
            },
            |s| {
                let session = s.sessions;
                let t = claim(&mut s.tickets, id);
                t.fetched = Some((t.count, session));
            },
        )
        .await;
    }

    /// Wait to fetch job `id`'s view: at once the first time and in each new session; else
    /// until the hub tells of a revision past `after`, or `wait`.
    async fn job(&self, id: &str, after: u64, wait: Duration) {
        self.wait(
            wait,
            |s| {
                let session = s.sessions;
                let j = claim(&mut s.jobs, id);
                j.revision > after || j.viewed != Some(session)
            },
            |s| {
                let session = s.sessions;
                claim(&mut s.jobs, id).viewed = Some(session);
            },
        )
        .await;
    }

    /// Wait to fetch job `id`'s output from `offset`: at once the first time and in each new
    /// session; else until the hub has output past it, or tells of anything since the last
    /// fetch (such as the job's end), or `wait`.
    async fn output(&self, id: &str, offset: u64, wait: Duration) {
        self.wait(
            wait,
            |s| {
                let session = s.sessions;
                let j = claim(&mut s.jobs, id);
                j.output_len > offset || j.fetched != Some((j.count, session))
            },
            |s| {
                let session = s.sessions;
                let j = claim(&mut s.jobs, id);
                j.fetched = Some((j.count, session));
            },
        )
        .await;
    }

    /// The current session's number, for [`Self::fetched_job`].
    fn session(&self) -> u64 {
        self.lock().sessions
    }

    /// A fetch of job `id` sent in `session` answered: the hub has at least `revision` and
    /// `output_len`. An answer from an earlier session's connection is ignored.
    fn fetched_job(&self, session: u64, id: &str, revision: u64, output_len: u64) {
        let mut s = self.lock();
        if s.sessions != session {
            return;
        }
        if let Some(j) = s.jobs.get_mut(id) {
            j.revision = j.revision.max(revision);
            j.output_len = j.output_len.max(output_len);
        }
    }

    fn forget_ticket(&self, id: &str) {
        self.lock().tickets.remove(id);
    }

    fn forget_job(&self, id: &str) {
        self.lock().jobs.remove(id);
    }
}

/// Drop the notices about IDs nothing has waited on within [`UNCLAIMED`].
fn forget_unclaimed(told: &mut HashMap<String, Told>) {
    let now = Instant::now();
    told.retain(|_, t| t.claimed || now.duration_since(t.told_at) < UNCLAIMED);
}

/// The entry of `id`, waited on.
fn claim<'a>(told: &'a mut HashMap<String, Told>, id: &str) -> &'a mut Told {
    let t = told.entry(id.to_owned()).or_insert_with(Told::new);
    t.claimed = true;
    t
}

/// How often a call is tried.
#[derive(Debug, Clone, Copy)]
enum Tries {
    /// Up to [`HubRetry::max_attempts`].
    Attempts,
    Once,
    /// Until a retry would start past the deadline.
    Until(Instant),
}

/// How hub calls are retried.
#[derive(Debug, Clone)]
pub struct HubRetry {
    /// Attempts in total, the first included.
    pub max_attempts: u32,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl Default for HubRetry {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
        }
    }
}

pub struct HubClient {
    link: Arc<Link>,
    retry: HubRetry,
    outputs: Semaphore,
    submissions: Semaphore,
}

impl std::fmt::Debug for HubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubClient").finish_non_exhaustive()
    }
}

/// A successful answer, read whole.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    /// When its request was sent.
    sent: Instant,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

impl HubClient {
    /// A client sending on `link`'s connection, which a session keeps.
    pub fn new(link: Arc<Link>, retry: HubRetry) -> Self {
        Self {
            link,
            retry,
            outputs: Semaphore::new(MAX_OUTPUTS),
            submissions: Semaphore::new(MAX_SUBMISSIONS),
        }
    }

    /// Send a request once `gate`, if any, lets it, and read its complete answer within
    /// [`REQUEST_TIMEOUT`]. Return a failed answer as `Err`, or [`ErrorKind::Transport`] for an
    /// incomplete answer.
    async fn send(
        &self,
        method: &Method,
        path_and_query: &str,
        body: &Bytes,
        gate: Option<&Semaphore>,
    ) -> DispatchResult<Answer> {
        // Queued behind the relay's own requests, not the hub: outside the timeout.
        let _permit = match gate {
            Some(gate) => Some(
                gate.acquire()
                    .await
                    .map_err(|e| transport("queueing", &e))?,
            ),
            None => None,
        };
        let exchange = async {
            let conn = self.link.connection().await;
            let request = request(method, &conn.base, path_and_query, body)?;
            let sent = Instant::now();
            let resp = conn
                .sender
                .clone()
                .send_request(request)
                .await
                .map_err(|e| transport("sending the request", &e))?;
            read_answer(resp, sent).await
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .unwrap_or_else(|_| {
                Err(DispatchError::new(
                    ErrorKind::Transport,
                    format!(
                        "the hub did not answer within {}s",
                        REQUEST_TIMEOUT.as_secs()
                    ),
                ))
            })
    }

    /// Retries a call according to `tries`, and decodes a successful answer with `read`.
    /// `retry_no_capacity` is false when the caller waits for capacity itself.
    #[allow(clippy::too_many_arguments)]
    async fn call<T>(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<Bytes>,
        gate: Option<&Semaphore>,
        retry_no_capacity: bool,
        tries: Tries,
        read: impl Fn(Answer) -> DispatchResult<T>,
    ) -> DispatchResult<T> {
        let path_and_query = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        let body = body.unwrap_or_default();
        let mut backoff = Backoff::new(self.retry.backoff_min, self.retry.backoff_max, 2.0, true);
        let mut attempt = 0u32;
        loop {
            attempt = attempt.saturating_add(1);
            let err = match self.send(&method, &path_and_query, &body, gate).await {
                Ok(answer) => return read(answer),
                Err(e) => e,
            };
            let retryable = match err.kind {
                ErrorKind::Transport | ErrorKind::Unavailable | ErrorKind::Internal => true,
                ErrorKind::NoCapacity => retry_no_capacity,
                _ => false,
            };
            let wait = err
                .retry_after
                .map_or_else(|| backoff.next_delay(), |d| d.min(MAX_RETRY_AFTER));
            let again = match tries {
                Tries::Attempts => attempt < self.retry.max_attempts,
                Tries::Once => false,
                Tries::Until(deadline) => Instant::now() + wait < deadline,
            };
            if !retryable || !again {
                return Err(err);
            }
            log::info!(
                path = path,
                attempt = attempt,
                wait_s = wait.as_secs_f64(),
                error = err.to_string().as_str();
                "Retrying the hub request"
            );
            tokio::time::sleep(wait).await;
        }
    }

    /// A call whose answer body does not matter.
    async fn call_empty(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        tries: Tries,
    ) -> DispatchResult<()> {
        self.call(method, path, "", body, None, true, tries, |_| Ok(()))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn call_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<&impl Serialize>,
        gate: Option<&Semaphore>,
        retry_no_capacity: bool,
        tries: Tries,
    ) -> DispatchResult<T> {
        let body = match body {
            Some(b) => {
                Some(Bytes::from(serde_json::to_vec(b).map_err(|e| {
                    DispatchError::new(ErrorKind::Invalid, e.to_string())
                })?))
            }
            None => None,
        };
        self.call(
            method,
            path,
            query,
            body,
            gate,
            retry_no_capacity,
            tries,
            |answer| {
                serde_json::from_slice(&answer.body).map_err(|e| {
                    DispatchError::new(
                        ErrorKind::Other,
                        format!("the hub's answer does not parse: {e}"),
                    )
                })
            },
        )
        .await
    }
}

fn transport(what: &str, e: &dyn std::fmt::Display) -> DispatchError {
    DispatchError::new(ErrorKind::Transport, format!("{what}: {e}"))
}

/// A request for `path_and_query` at `base` (`scheme://host:port`).
fn request(
    method: &Method,
    base: &str,
    path_and_query: &str,
    body: &Bytes,
) -> DispatchResult<hyper::Request<Full<Bytes>>> {
    let mut request = hyper::Request::builder()
        .method(method.clone())
        .uri(format!("{base}{path_and_query}"))
        .header(
            hyper::header::USER_AGENT,
            concat!("vk-gitlab ", env!("CARGO_PKG_VERSION")),
        );
    if !body.is_empty() {
        request = request.header(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    request
        .body(Full::new(body.clone()))
        .map_err(|e| DispatchError::new(ErrorKind::Invalid, e.to_string()))
}

/// `resp`, to a request sent at `sent`, read whole: an [`Answer`] when it succeeded, else its
/// error.
async fn read_answer(
    resp: hyper::Response<hyper::body::Incoming>,
    sent: Instant,
) -> DispatchResult<Answer> {
    let (parts, incoming) = resp.into_parts();
    let body = http_body_util::Limited::new(incoming, MAX_ANSWER)
        .collect()
        .await
        .map_err(|e| transport("reading the answer", &e))?
        .to_bytes();
    if parts.status.is_success() {
        Ok(Answer {
            status: parts.status,
            headers: parts.headers,
            body,
            sent,
        })
    } else {
        Err(error_of(parts.status, &parts.headers, &body))
    }
}

/// A failed answer as an error: the body's code when it has one, else the status's.
fn error_of(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> DispatchError {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
    };
    let retry_header = header("retry-after");
    let length = header(OUTPUT_LENGTH_HEADER);
    let parsed = serde_json::from_slice::<ClientError>(body).ok();
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        return DispatchError {
            status: Some(status.as_u16()),
            coded: parsed.is_some(),
            ..DispatchError::new(
                ErrorKind::OutputRange {
                    length: length.unwrap_or(0),
                },
                parsed.map_or_else(|| status.to_string(), |p| p.error),
            )
        };
    }
    let kind = match parsed.as_ref().map(|p| p.code) {
        Some(ErrorCode::Unauthorized) => ErrorKind::Unauthorized,
        Some(ErrorCode::Forbidden) => ErrorKind::Forbidden,
        Some(ErrorCode::ApprovalPending) => ErrorKind::ApprovalPending,
        Some(ErrorCode::ProjectRejected) => ErrorKind::ProjectRejected,
        Some(ErrorCode::NotFound) => ErrorKind::NotFound,
        Some(ErrorCode::Invalid) => ErrorKind::Invalid,
        Some(ErrorCode::Conflict) => ErrorKind::Conflict,
        Some(ErrorCode::NoCapacity) => ErrorKind::NoCapacity,
        Some(ErrorCode::ReservationGone) => ErrorKind::ReservationGone,
        Some(ErrorCode::TooLarge) => ErrorKind::TooLarge,
        Some(ErrorCode::Unavailable) => ErrorKind::Unavailable,
        Some(ErrorCode::Internal) => ErrorKind::Internal,
        Some(ErrorCode::Other) | None => match status.as_u16() {
            400 => ErrorKind::Invalid,
            401 => ErrorKind::Unauthorized,
            403 => ErrorKind::Forbidden,
            404 => ErrorKind::NotFound,
            409 => ErrorKind::Conflict,
            410 => ErrorKind::ReservationGone,
            413 => ErrorKind::TooLarge,
            503 => ErrorKind::Unavailable,
            500..=599 => ErrorKind::Internal,
            _ => ErrorKind::Other,
        },
    };
    let retry_after = parsed
        .as_ref()
        .and_then(|p| p.retry_after_secs)
        .map(u64::from)
        .or(retry_header)
        .map(Duration::from_secs);
    DispatchError {
        kind,
        coded: parsed.is_some(),
        approval_url: parsed.as_ref().and_then(|p| p.approval_url.clone()),
        message: parsed.map_or_else(|| status.to_string(), |p| p.error),
        retry_after,
        status: Some(status.as_u16()),
    }
}

fn checked_id(id: &str) -> DispatchResult<&str> {
    if valid_id(id) {
        Ok(id)
    } else {
        Err(DispatchError::new(
            ErrorKind::Invalid,
            format!("{id:?} is not a hub ID"),
        ))
    }
}

/// A queued reservation request's answer, told apart by its status as
/// `vk_hub_proto::client` defines it: 201 a grant, 202 a ticket.
fn queue_answer(answer: Answer) -> DispatchResult<QueueAnswer> {
    let parse = |e: serde_json::Error| {
        DispatchError::new(
            ErrorKind::Other,
            format!("the hub's answer does not parse: {e}"),
        )
    };
    match answer.status {
        StatusCode::CREATED => {
            let g: ReservationGrant = serde_json::from_slice(&answer.body).map_err(parse)?;
            Ok(QueueAnswer::Grant(Reservation {
                id: g.reservation,
                admission: g.admission,
                node: g.node,
                envelope: g.envelope,
                lease: Duration::from_secs(u64::from(g.lease_secs)),
                sent: answer.sent,
            }))
        }
        StatusCode::ACCEPTED => {
            let t: ReservationTicket = serde_json::from_slice(&answer.body).map_err(parse)?;
            Ok(QueueAnswer::Ticket(t.ticket))
        }
        status => Err(DispatchError {
            status: Some(status.as_u16()),
            ..DispatchError::new(
                ErrorKind::Other,
                format!("the hub answered a queued request {status}, neither a grant nor a ticket"),
            )
        }),
    }
}

impl Dispatcher for HubClient {
    async fn capacity(
        &self,
        runner: &str,
        placement: &Placement,
        after: Option<u64>,
        _wait: Duration,
    ) -> DispatchResult<Capacity> {
        // Not long-polled: no notice tells of capacity.
        let body = CapacityRequest {
            runner: Some(runner.to_owned()),
            placement: placement.clone(),
            after,
            wait_secs: 0,
        };
        self.call_json(
            Method::POST,
            CAPACITY_PATH,
            "",
            Some(&body),
            None,
            true,
            Tries::Attempts,
        )
        .await
    }

    async fn reserve(
        &self,
        runner: &str,
        request_id: &str,
        placement: &Placement,
        lease: Duration,
        _wait: Duration,
    ) -> DispatchResult<Reservation> {
        let body = ReservationRequest {
            runner: Some(runner.to_owned()),
            queue: false,
            request_id: request_id.to_owned(),
            placement: placement.clone(),
            lease_secs: lease_secs(lease),
            wait_secs: 0,
        };
        let body = Bytes::from(
            serde_json::to_vec(&body)
                .map_err(|e| DispatchError::new(ErrorKind::Invalid, e.to_string()))?,
        );
        self.call(
            Method::POST,
            RESERVATIONS_PATH,
            "",
            Some(body),
            None,
            false,
            Tries::Attempts,
            |answer| {
                let grant: ReservationGrant =
                    serde_json::from_slice(&answer.body).map_err(|e| {
                        DispatchError::new(
                            ErrorKind::Other,
                            format!("the hub's answer does not parse: {e}"),
                        )
                    })?;
                Ok(Reservation {
                    admission: grant.admission,
                    id: grant.reservation,
                    node: grant.node,
                    envelope: grant.envelope,
                    lease: Duration::from_secs(u64::from(grant.lease_secs)),
                    sent: answer.sent,
                })
            },
        )
        .await
    }

    async fn queue(
        &self,
        runner: &str,
        request_id: &str,
        placement: &Placement,
        lease: Duration,
        _wait: Duration,
    ) -> DispatchResult<QueueAnswer> {
        let body = ReservationRequest {
            runner: Some(runner.to_owned()),
            queue: true,
            request_id: request_id.to_owned(),
            placement: placement.clone(),
            lease_secs: lease_secs(lease),
            wait_secs: 0,
        };
        let body = Bytes::from(
            serde_json::to_vec(&body)
                .map_err(|e| DispatchError::new(ErrorKind::Invalid, e.to_string()))?,
        );
        self.call(
            Method::POST,
            RESERVATIONS_PATH,
            "",
            Some(body),
            None,
            false,
            Tries::Attempts,
            queue_answer,
        )
        .await
    }

    async fn poll_ticket(&self, ticket: &str, wait: Duration) -> DispatchResult<QueueAnswer> {
        let path = format!("{TICKETS_PATH}/{}", checked_id(ticket)?);
        self.link.ticket(ticket, wait).await;
        let answer = self
            .call(
                Method::GET,
                &path,
                "",
                None,
                None,
                false,
                Tries::Attempts,
                queue_answer,
            )
            .await;
        // A ticket granted or gone is not told of again.
        if matches!(
            &answer,
            Ok(QueueAnswer::Grant(_))
                | Err(DispatchError {
                    kind: ErrorKind::ReservationGone | ErrorKind::NotFound,
                    ..
                })
        ) {
            self.link.forget_ticket(ticket);
        }
        answer
    }

    async fn cancel_ticket(&self, ticket: &str) -> DispatchResult<()> {
        let path = format!("{TICKETS_PATH}/{}", checked_id(ticket)?);
        self.link.forget_ticket(ticket);
        self.call_empty(Method::DELETE, &path, None, Tries::Attempts)
            .await
    }

    async fn claim(&self, reservation: &str) -> DispatchResult<()> {
        let path = format!("{RESERVATIONS_PATH}/{}/claim", checked_id(reservation)?);
        self.call_empty(Method::POST, &path, None, Tries::Attempts)
            .await
    }

    async fn outcome(
        &self,
        admission: &str,
        outcome: vk_hub_proto::client::AdmissionOutcome,
    ) -> DispatchResult<()> {
        let path = format!("{RESERVATIONS_PATH}/{}/outcome", checked_id(admission)?);
        let body = vk_hub_proto::client::OutcomeRequest {
            admission: admission.to_owned(),
            outcome,
        };
        let body = Bytes::from(
            serde_json::to_vec(&body)
                .map_err(|e| DispatchError::new(ErrorKind::Invalid, e.to_string()))?,
        );
        self.call_empty(Method::POST, &path, Some(body), Tries::Attempts)
            .await
    }

    async fn renew(&self, reservation: &str, lease: Duration) -> DispatchResult<Duration> {
        let path = format!("{RESERVATIONS_PATH}/{}/renew", checked_id(reservation)?);
        let grant: ReservationGrant = self
            .call_json(
                Method::POST,
                &path,
                "",
                Some(&RenewRequest {
                    lease_secs: lease_secs(lease),
                }),
                None,
                true,
                Tries::Once,
            )
            .await?;
        Ok(Duration::from_secs(u64::from(grant.lease_secs)))
    }

    async fn release(&self, reservation: &str) -> DispatchResult<()> {
        let path = format!("{RESERVATIONS_PATH}/{}", checked_id(reservation)?);
        self.call_empty(Method::DELETE, &path, None, Tries::Attempts)
            .await
    }

    async fn submit(&self, submission: Submission) -> DispatchResult<JobView> {
        let spec_len = serde_json::to_vec(&submission.spec)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if spec_len > MAX_JOB_SPEC {
            return Err(DispatchError::new(
                ErrorKind::TooLarge,
                format!("the job spec is {spec_len} bytes, past {MAX_JOB_SPEC}"),
            ));
        }
        let body = JobSubmission {
            runner: submission.runner,
            admission: submission.admission,
            request_id: submission.request_id,
            placement: submission.placement,
            reservation: submission.reservation,
            place_within_secs: u32::try_from(submission.place_within.as_secs()).unwrap_or(u32::MAX),
            spec: submission.spec,
        };
        self.call_json(
            Method::POST,
            JOBS_PATH,
            "",
            Some(&body),
            Some(&self.submissions),
            true,
            Tries::Until(Instant::now() + submission.place_within),
        )
        .await
    }

    async fn job(&self, id: &str, after: Option<u64>, wait: Duration) -> DispatchResult<JobView> {
        let path = format!("{JOBS_PATH}/{}", checked_id(id)?);
        if let Some(after) = after {
            self.link.job(id, after, wait).await;
        }
        let session = self.link.session();
        let view: DispatchResult<JobView> = self
            .call_json(
                Method::GET,
                &path,
                "",
                None::<&()>,
                None,
                true,
                Tries::Attempts,
            )
            .await;
        match &view {
            Ok(v) => self.link.fetched_job(session, id, v.revision, v.output_len),
            Err(e) if e.kind == ErrorKind::NotFound => self.link.forget_job(id),
            Err(_) => {}
        }
        view
    }

    async fn output(&self, id: &str, offset: u64, wait: Duration) -> DispatchResult<OutputChunk> {
        let path = format!("{JOBS_PATH}/{}/output", checked_id(id)?);
        let query = format!("offset={offset}");
        self.link.output(id, offset, wait).await;
        let session = self.link.session();
        let chunk = self
            .call(
                Method::GET,
                &path,
                &query,
                None,
                Some(&self.outputs),
                true,
                Tries::Attempts,
                |answer| {
                    let chunk_offset = answer
                        .header(OUTPUT_OFFSET_HEADER)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(offset);
                    let length = answer
                        .header(OUTPUT_LENGTH_HEADER)
                        .and_then(|v| v.parse().ok());
                    let complete = answer.header(OUTPUT_COMPLETE_HEADER) == Some("true");
                    let data = answer.body;
                    Ok(OutputChunk {
                        offset: chunk_offset,
                        length: length.unwrap_or(chunk_offset.saturating_add(data.len() as u64)),
                        complete,
                        data,
                    })
                },
            )
            .await;
        match &chunk {
            // Output past this read is fetched again at once.
            Ok(c) => self.link.fetched_job(session, id, 0, c.length),
            Err(e) if e.kind == ErrorKind::NotFound => self.link.forget_job(id),
            Err(_) => {}
        }
        chunk
    }

    async fn cancel(&self, id: &str, mode: CancelMode) -> DispatchResult<JobView> {
        let path = format!("{JOBS_PATH}/{}/cancel", checked_id(id)?);
        self.call_json(
            Method::POST,
            &path,
            "",
            Some(&CancelRequest { mode }),
            None,
            true,
            Tries::Attempts,
        )
        .await
    }

    async fn settle(&self, id: &str) -> DispatchResult<()> {
        let path = format!("{JOBS_PATH}/{}/settle", checked_id(id)?);
        self.call_empty(Method::POST, &path, None, Tries::Attempts)
            .await?;
        // A settled job is not told of again.
        self.link.forget_job(id);
        Ok(())
    }
}

fn lease_secs(lease: Duration) -> u32 {
    u32::try_from(lease.as_secs())
        .unwrap_or(u32::MAX)
        .clamp(1, MAX_LEASE_SECS)
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use serde_json::json;

    fn answer(status: StatusCode, body: serde_json::Value) -> Answer {
        Answer {
            status,
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
            sent: Instant::now(),
        }
    }

    #[test]
    fn ticket_and_grant_answers_keep_admission_and_remaining_lease() {
        let ticket = "a".repeat(32);
        assert!(matches!(
            queue_answer(answer(StatusCode::ACCEPTED, json!({"ticket": ticket}))).unwrap(),
            QueueAnswer::Ticket(t) if t == ticket
        ));
        let grant = queue_answer(answer(
            StatusCode::CREATED,
            json!({
                "reservation": "b".repeat(32), "admission": "c".repeat(32),
                "node": "d".repeat(32), "lease_secs": 7,
                "envelope": {"mem_mib": 1, "cpus": 1, "disk_bytes": 1}
            }),
        ))
        .unwrap();
        let QueueAnswer::Grant(grant) = grant else {
            panic!("expected grant")
        };
        assert_eq!(grant.admission.as_deref(), Some("c".repeat(32).as_str()));
        assert_eq!(grant.lease, Duration::from_secs(7));
    }

    #[test]
    fn a_queue_answer_is_told_by_its_status_not_its_body() {
        // A grant's body under 202 is not taken for a grant, nor a ticket's under 201.
        let grant = json!({
            "reservation": "b".repeat(32), "node": "d".repeat(32), "lease_secs": 7,
            "envelope": {"mem_mib": 1, "cpus": 1, "disk_bytes": 1}
        });
        assert!(queue_answer(answer(StatusCode::ACCEPTED, grant.clone())).is_err());
        assert!(
            queue_answer(answer(
                StatusCode::CREATED,
                json!({"ticket": "a".repeat(32)})
            ))
            .is_err()
        );
        let e = queue_answer(answer(StatusCode::OK, grant)).unwrap_err();
        assert_eq!((e.kind, e.status), (ErrorKind::Other, Some(200)));
    }
}
