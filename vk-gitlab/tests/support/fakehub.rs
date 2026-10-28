//! vk-hub's client API over HTTP (`vk-hub/src/client.rs`: paths,
//! statuses, error bodies, output headers), served from the in-memory `FakeDispatcher`, so
//! the real hub client is tested on the wire. A relay enrolls at `/v1/gitlab/enroll`, and
//! every request after must carry its signature, checked as the hub checks it; a request
//! without one is answered 401.
//!
//! Queued requests get tickets of the fake's own, which name the admission of their grant;
//! the fake checks what the hub checks of an admission: claimed before a job is submitted
//! under it, its outcome reported under its own ID, and once (but for a job found empty).

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use vk_gitlab::dispatch::{DispatchError, Dispatcher, ErrorKind, FakeDispatcher, Submission};
use vk_hub_proto::client::{
    AdmissionOutcome, CancelRequest, CapacityRequest, ClientError, ErrorCode, JobSubmission,
    OutcomeRequest, RenewRequest, ReservationGrant, ReservationRequest, ReservationTicket,
};

/// The ID the fake hub gives the relay that enrolls.
pub const TEST_RELAY_ID: &str = "0123456789abcdef0123456789abcdef";

/// An injected failure: the next matching requests are answered this way.
#[derive(Clone, Debug)]
pub struct Fault {
    pub path_prefix: String,
    /// What the path ends with, `""` for any.
    pub path_suffix: String,
    pub status: u16,
    pub code: ErrorCode,
    pub retry_after_secs: Option<u32>,
}

/// A request as the fake hub received it.
#[derive(Clone, Debug)]
pub struct HubRequest {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub struct FakeHub {
    pub url: String,
    pub requests: Arc<Mutex<Vec<HubRequest>>>,
    /// The enrolled relay's public key.
    relay_key: Arc<Mutex<Option<Vec<u8>>>>,
    faults: Arc<Mutex<VecDeque<Fault>>>,
    queue_response_delay: Arc<Mutex<Option<Duration>>>,
    tickets: Arc<Mutex<Tickets>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeHub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Resp = Response<Full<Bytes>>;

#[derive(Clone)]
enum Ticket {
    Waiting(ReservationRequest),
    Granted(ReservationGrant),
    Cancelled,
}

/// The queued requests, and their admissions.
#[derive(Default)]
struct Tickets {
    next: u64,
    /// Request ID → ticket ID.
    by_request: HashMap<String, String>,
    tickets: HashMap<String, Ticket>,
    /// The admissions claimed, by their ID.
    claimed: HashSet<String>,
    /// The outcome reported of each admission.
    outcomes: HashMap<String, AdmissionOutcome>,
}

impl Tickets {
    /// The admission whose grant is on `reservation`.
    fn granted_on(&self, reservation: &str) -> Option<String> {
        self.tickets.iter().find_map(|(id, t)| match t {
            Ticket::Granted(g) if g.reservation == reservation => Some(id.clone()),
            _ => None,
        })
    }

    fn known(&self, admission: &str) -> bool {
        self.claimed.contains(admission)
            || matches!(self.tickets.get(admission), Some(Ticket::Granted(_)))
    }
}

fn json<T: serde::Serialize>(status: u16, value: &T) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(value).unwrap())))
        .unwrap()
}

fn empty(status: u16) -> Resp {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn error(status: u16, code: ErrorCode, msg: &str, retry_after_secs: Option<u32>) -> Resp {
    json(
        status,
        &ClientError {
            error: msg.to_owned(),
            code,
            retry_after_secs,
        },
    )
}

fn dispatch_error(e: DispatchError) -> Resp {
    let retry = e
        .retry_after
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(1));
    let (status, code) = match e.kind {
        ErrorKind::NotFound => (404, ErrorCode::NotFound),
        ErrorKind::Conflict => (409, ErrorCode::Conflict),
        ErrorKind::ReservationGone => (410, ErrorCode::ReservationGone),
        ErrorKind::TooLarge => (413, ErrorCode::TooLarge),
        ErrorKind::NoCapacity => (503, ErrorCode::NoCapacity),
        ErrorKind::Unavailable => (503, ErrorCode::Unavailable),
        ErrorKind::Forbidden => (403, ErrorCode::Forbidden),
        ErrorKind::ApprovalPending => (403, ErrorCode::ApprovalPending),
        ErrorKind::ProjectRejected => (403, ErrorCode::ProjectRejected),
        ErrorKind::OutputRange { length } => {
            let mut r = error(416, ErrorCode::Invalid, &e.message, None);
            r.headers_mut()
                .insert("vk-output-length", length.to_string().parse().unwrap());
            return r;
        }
        _ => (500, ErrorCode::Internal),
    };
    error(status, code, &e.message, retry)
}

fn query(q: &str, name: &str) -> Option<u64> {
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| v.parse().ok())
}

/// Whether the request is signed by the relay whose key is `key`, as `vk-hub/src/client.rs`
/// checks it (over plain TCP: no TLS exporter).
fn signed(
    key: &[u8],
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let (Some(relay), Some(at), Some(signature)) = (
        header("vk-relay"),
        header("vk-time").and_then(|t| t.parse::<u64>().ok()),
        header("vk-signature")
            .and_then(vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SIGNATURE_LEN }>),
    ) else {
        return false;
    };
    if relay != TEST_RELAY_ID || headers.contains_key("authorization") {
        return false;
    }
    let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, body)
        .as_ref()
        .try_into()
        .unwrap();
    let message = vk_hub_proto::client::client_request_message(
        relay,
        method,
        path_and_query,
        &digest,
        at,
        vk_hub_proto::Channel::Plaintext,
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&message, &signature)
        .is_ok()
}

async fn serve(
    hub: FakeDispatcher,
    method: hyper::Method,
    path: String,
    q: String,
    body: Bytes,
    tickets: Arc<Mutex<Tickets>>,
) -> Resp {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let wait = Duration::from_secs(query(&q, "wait").unwrap_or(0).min(60));
    macro_rules! parse {
        ($t:ty) => {
            match serde_json::from_slice::<$t>(&body) {
                Ok(v) => v,
                Err(e) => return error(400, ErrorCode::Invalid, &e.to_string(), None),
            }
        };
    }
    match (method.as_str(), segs.as_slice()) {
        ("POST", ["v1", "capacity"]) => {
            let ask = parse!(CapacityRequest);
            // As the hub: a relay names its runner.
            let Some(runner) = ask.runner.clone() else {
                return error(
                    403,
                    ErrorCode::Forbidden,
                    "a relay must name its runner",
                    None,
                );
            };
            let wait = Duration::from_secs(u64::from(ask.wait_secs.min(60)));
            match hub.capacity(&runner, &ask.placement, ask.after, wait).await {
                Ok(c) => json(200, &c),
                Err(e) => dispatch_error(e),
            }
        }
        ("POST", ["v1", "reservations"]) => {
            let ask = parse!(ReservationRequest);
            // As the hub: a relay names its runner.
            let Some(runner) = ask.runner.clone() else {
                return error(
                    403,
                    ErrorCode::Forbidden,
                    "a relay must name its runner",
                    None,
                );
            };
            if ask.queue {
                // A ticket of its own, not the request's ID; a retried request finds it.
                let mut t = tickets.lock().unwrap();
                let ticket = match t.by_request.get(&ask.request_id) {
                    Some(ticket) => ticket.clone(),
                    None => {
                        t.next += 1;
                        let ticket = format!("{:032x}", (0xa_u128 << 124) | u128::from(t.next));
                        t.by_request.insert(ask.request_id.clone(), ticket.clone());
                        t.tickets.insert(ticket.clone(), Ticket::Waiting(ask));
                        ticket
                    }
                };
                return json(202, &ReservationTicket { ticket });
            }
            let lease = Duration::from_secs(u64::from(ask.lease_secs));
            match hub
                .reserve(&runner, &ask.request_id, &ask.placement, lease, wait)
                .await
            {
                Ok(r) => json(
                    201,
                    &ReservationGrant {
                        admission: r.admission,
                        reservation: r.id,
                        node: r.node,
                        envelope: r.envelope,
                        lease_secs: u32::try_from(r.lease.as_secs()).unwrap(),
                    },
                ),
                Err(e) => dispatch_error(e),
            }
        }
        ("GET", ["v1", "reservations", "tickets", id]) => {
            // Long-polled as the hub's is: granted once a reservation fits, within `wait`.
            let deadline = tokio::time::Instant::now() + wait;
            loop {
                let ticket = tickets.lock().unwrap().tickets.get(*id).cloned();
                let ask = match ticket {
                    Some(Ticket::Waiting(ask)) => ask,
                    Some(Ticket::Granted(grant)) => return json(201, &grant),
                    Some(Ticket::Cancelled) | None => {
                        return error(410, ErrorCode::ReservationGone, "ticket cancelled", None);
                    }
                };
                let lease = Duration::from_secs(u64::from(ask.lease_secs));
                match hub
                    .reserve(
                        ask.runner.as_deref().unwrap_or(""),
                        &ask.request_id,
                        &ask.placement,
                        lease,
                        Duration::ZERO,
                    )
                    .await
                {
                    Ok(r) => {
                        let grant = ReservationGrant {
                            // The ticket names its grant's admission, as the hub's does.
                            admission: Some((*id).to_owned()),
                            reservation: r.id,
                            node: r.node,
                            envelope: r.envelope,
                            lease_secs: u32::try_from(r.lease.as_secs()).unwrap(),
                        };
                        let previous = {
                            let mut t = tickets.lock().unwrap();
                            match t.tickets.get_mut(*id) {
                                Some(ticket @ Ticket::Waiting(_)) => {
                                    *ticket = Ticket::Granted(grant.clone());
                                    None
                                }
                                Some(Ticket::Granted(existing)) => Some(Some(existing.clone())),
                                Some(Ticket::Cancelled) | None => Some(None),
                            }
                        };
                        if let Some(previous) = previous {
                            hub.release(&grant.reservation).await.unwrap();
                            return match previous {
                                Some(existing) => json(201, &existing),
                                None => {
                                    error(410, ErrorCode::ReservationGone, "ticket cancelled", None)
                                }
                            };
                        }
                        return json(201, &grant);
                    }
                    Err(e) if e.kind == ErrorKind::NoCapacity => {
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        if tokio::time::Instant::now() >= deadline {
                            return json(
                                202,
                                &ReservationTicket {
                                    ticket: (*id).to_owned(),
                                },
                            );
                        }
                    }
                    Err(e) => return dispatch_error(e),
                }
            }
        }
        ("DELETE", ["v1", "reservations", "tickets", id]) => {
            let previous = tickets
                .lock()
                .unwrap()
                .tickets
                .insert((*id).to_owned(), Ticket::Cancelled);
            if let Some(Ticket::Granted(grant)) = previous {
                hub.release(&grant.reservation).await.unwrap();
            }
            empty(204)
        }
        ("POST", ["v1", "reservations", reservation, "claim"]) => {
            {
                let mut t = tickets.lock().unwrap();
                let Some(admission) = t.granted_on(reservation) else {
                    return error(410, ErrorCode::ReservationGone, "no such grant", None);
                };
                t.claimed.insert(admission);
            }
            hub.claim(reservation).await.unwrap();
            empty(204)
        }
        ("POST", ["v1", "reservations", admission, "outcome"]) => {
            let ask = parse!(OutcomeRequest);
            if ask.admission != *admission {
                return error(
                    400,
                    ErrorCode::Invalid,
                    "admission ID does not match the path",
                    None,
                );
            }
            {
                let mut t = tickets.lock().unwrap();
                if !t.known(admission) {
                    return error(404, ErrorCode::NotFound, "no such admission", None);
                }
                let claimed = t.claimed.contains(*admission);
                let allowed = match t.outcomes.get(*admission) {
                    None => claimed || ask.outcome == AdmissionOutcome::Released,
                    Some(previous) => {
                        *previous == ask.outcome
                            || *previous == AdmissionOutcome::Job
                                && ask.outcome == AdmissionOutcome::Empty
                    }
                };
                if !allowed {
                    return error(
                        409,
                        ErrorCode::Conflict,
                        "admission outcome conflicts with its state",
                        None,
                    );
                }
                t.outcomes.insert((*admission).to_owned(), ask.outcome);
            }
            hub.outcome(admission, ask.outcome).await.unwrap();
            empty(204)
        }
        ("POST", ["v1", "reservations", id, "renew"]) => {
            let ask = parse!(RenewRequest);
            match hub
                .renew(id, Duration::from_secs(u64::from(ask.lease_secs)))
                .await
            {
                Ok(lease) => json(
                    200,
                    &ReservationGrant {
                        admission: None,
                        reservation: (*id).to_owned(),
                        node: "node-1".to_owned(),
                        envelope: Default::default(),
                        lease_secs: u32::try_from(lease.as_secs()).unwrap(),
                    },
                ),
                Err(e) => dispatch_error(e),
            }
        }
        ("DELETE", ["v1", "reservations", id]) => match hub.release(id).await {
            Ok(()) => empty(204),
            Err(e) => dispatch_error(e),
        },
        ("POST", ["v1", "jobs"]) => {
            let ask = parse!(JobSubmission);
            if let Some(admission) = &ask.admission
                && !tickets.lock().unwrap().claimed.contains(admission)
            {
                return error(
                    403,
                    ErrorCode::Forbidden,
                    "job does not match its admission",
                    None,
                );
            }
            let vk_hub_proto::job::JobSpec::GitlabCi(ci) = &ask.spec;
            let sub = Submission {
                request_id: ask.request_id,
                runner: ask.runner,
                admission: ask.admission,
                placement: ask.placement,
                reservation: ask.reservation,
                place_within: Duration::from_secs(u64::from(ask.place_within_secs)),
                gitlab_job: i64::try_from(ci.job.id).unwrap(),
                spec: ask.spec,
            };
            match hub.submit(sub).await {
                Ok(v) => json(201, &v),
                Err(e) => dispatch_error(e),
            }
        }
        ("GET", ["v1", "jobs", id]) => match hub.job(id, query(&q, "after"), wait).await {
            Ok(v) => json(200, &v),
            Err(e) => dispatch_error(e),
        },
        ("GET", ["v1", "jobs", id, "output"]) => {
            match hub.output(id, query(&q, "offset").unwrap_or(0), wait).await {
                Ok(c) => {
                    let mut r = Response::builder()
                        .status(200)
                        .header("content-type", "application/octet-stream")
                        .header("vk-output-offset", c.offset.to_string())
                        .header("vk-output-length", c.length.to_string());
                    if c.complete {
                        r = r.header("vk-output-complete", "true");
                    }
                    r.body(Full::new(c.data)).unwrap()
                }
                Err(e) => dispatch_error(e),
            }
        }
        ("POST", ["v1", "jobs", id, "cancel"]) => {
            let ask = parse!(CancelRequest);
            match hub.cancel(id, ask.mode).await {
                Ok(v) => json(202, &v),
                Err(e) => dispatch_error(e),
            }
        }
        ("POST", ["v1", "jobs", id, "settle"]) => match hub.settle(id).await {
            Ok(()) => empty(204),
            Err(e) => dispatch_error(e),
        },
        _ => error(404, ErrorCode::NotFound, "no such endpoint", None),
    }
}

impl FakeHub {
    pub async fn start(hub: FakeDispatcher) -> FakeHub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let relay_key = Arc::new(Mutex::new(None));
        let faults: Arc<Mutex<VecDeque<Fault>>> = Arc::new(Mutex::new(VecDeque::new()));
        let tickets = Arc::new(Mutex::new(Tickets::default()));
        let queue_response_delay = Arc::new(Mutex::new(None));
        let state = (
            Arc::clone(&requests),
            Arc::clone(&relay_key),
            Arc::clone(&faults),
            Arc::clone(&tickets),
            Arc::clone(&queue_response_delay),
        );
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (hub, state) = (hub.clone(), state.clone());
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let (hub, (recs, key, flts, tickets, delay)) = (hub.clone(), state.clone());
                        async move {
                            let (parts, body) = req.into_parts();
                            let path = parts.uri.path().to_owned();
                            let q = parts.uri.query().unwrap_or("").to_owned();
                            let body = body.collect().await.unwrap().to_bytes();
                            recs.lock().unwrap().push(HubRequest {
                                method: parts.method.to_string(),
                                path: path.clone(),
                                headers: parts.headers.clone(),
                                body: body.clone(),
                            });
                            if parts.method == "POST" && path == "/v1/gitlab/enroll" {
                                let ask: vk_hub_proto::EnrollRequest =
                                    serde_json::from_slice(&body).unwrap();
                                *key.lock().unwrap() =
                                    Some(vk_hub_proto::from_hex(&ask.public_key).unwrap());
                                return Ok::<_, Infallible>(json(
                                    200,
                                    &vk_hub_proto::gitlab::EnrollResponse {
                                        relay_id: TEST_RELAY_ID.to_owned(),
                                    },
                                ));
                            }
                            let path_and_query =
                                parts.uri.path_and_query().map_or("", |p| p.as_str());
                            let known = key.lock().unwrap().clone();
                            if !known.is_some_and(|k| {
                                signed(
                                    &k,
                                    &parts.headers,
                                    parts.method.as_str(),
                                    path_and_query,
                                    &body,
                                )
                            }) {
                                return Ok(error(
                                    401,
                                    ErrorCode::Unauthorized,
                                    "a request signed by an enrolled relay is required",
                                    None,
                                ));
                            }
                            let fault = {
                                let mut f = flts.lock().unwrap();
                                match f.front() {
                                    Some(fault)
                                        if path.starts_with(&fault.path_prefix)
                                            && path.ends_with(&fault.path_suffix) =>
                                    {
                                        f.pop_front()
                                    }
                                    _ => None,
                                }
                            };
                            if let Some(f) = fault {
                                let mut r = error(f.status, f.code, "injected", f.retry_after_secs);
                                if let Some(s) = f.retry_after_secs {
                                    r.headers_mut()
                                        .insert("retry-after", s.to_string().parse().unwrap());
                                }
                                return Ok(r);
                            }
                            let delay = if parts.method == "POST" && path == "/v1/reservations" {
                                delay.lock().unwrap().take()
                            } else {
                                None
                            };
                            let response = serve(hub, parts.method, path, q, body, tickets).await;
                            if let Some(delay) = delay {
                                tokio::time::sleep(delay).await;
                            }
                            Ok(response)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        FakeHub {
            url: format!("http://{addr}"),
            requests,
            relay_key,
            faults,
            queue_response_delay,
            tickets,
            task,
        }
    }

    /// The ticket a queued request with `request_id` got, once the fake has it.
    pub fn ticket_for(&self, request_id: &str) -> Option<String> {
        self.tickets
            .lock()
            .unwrap()
            .by_request
            .get(request_id)
            .cloned()
    }

    /// The ticket of the first request queued, once there is one: the admission of the
    /// first grant.
    pub fn first_ticket(&self) -> Option<String> {
        // Tickets are numbered in order, at a fixed width.
        self.tickets
            .lock()
            .unwrap()
            .by_request
            .values()
            .min()
            .cloned()
    }

    /// The outcome reported of admission `id`, if any.
    pub fn outcome_of(&self, id: &str) -> Option<AdmissionOutcome> {
        self.tickets.lock().unwrap().outcomes.get(id).copied()
    }

    /// How many admissions had an outcome reported.
    pub fn outcomes_reported(&self) -> usize {
        self.tickets.lock().unwrap().outcomes.len()
    }

    /// Has the fake hold admission `id` claimed, as a hub does across the relay's restart.
    pub fn hold_admission(&self, id: &str) {
        self.tickets.lock().unwrap().claimed.insert(id.to_owned());
    }

    pub fn delay_next_queue_response(&self, delay: Duration) {
        *self.queue_response_delay.lock().unwrap() = Some(delay);
    }

    /// Answers the next `n` requests under `path_prefix` with `status` and `code`.
    pub fn fail_next(
        &self,
        n: usize,
        path_prefix: &str,
        status: u16,
        code: ErrorCode,
        retry_after_secs: Option<u32>,
    ) {
        self.fail_next_ending(n, path_prefix, "", status, code, retry_after_secs);
    }

    /// Answers the next `n` requests under `path_prefix` whose path ends with `path_suffix`
    /// with `status` and `code`.
    pub fn fail_next_ending(
        &self,
        n: usize,
        path_prefix: &str,
        path_suffix: &str,
        status: u16,
        code: ErrorCode,
        retry_after_secs: Option<u32>,
    ) {
        let mut f = self.faults.lock().unwrap();
        for _ in 0..n {
            f.push_back(Fault {
                path_prefix: path_prefix.to_owned(),
                path_suffix: path_suffix.to_owned(),
                status,
                code,
                retry_after_secs,
            });
        }
    }

    /// Drops the failures not yet answered.
    pub fn clear_faults(&self) {
        self.faults.lock().unwrap().clear();
    }

    pub fn requests_to(&self, prefix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.starts_with(prefix))
            .count()
    }
}
