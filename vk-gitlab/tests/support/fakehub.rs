//! vk-hub's client API over HTTP (`vk-hub/src/client.rs`: paths,
//! statuses, error bodies, output headers), served from the in-memory `FakeDispatcher`, so
//! the real hub client is tested on the wire. A relay enrolls at `/v1/gitlab/enroll` over
//! HTTP/1.1, then dials its connection as the hub's listener serves it: HTTP/2 under the relay's
//! ALPN ID over TLS, told by its preface on plain TCP. Its session is checked against the
//! enrolled key, and the connection serves the relay's requests while the session is up, a
//! long poll refused; the session tells the relay of its tickets and jobs as the hub does.
//!
//! Queued requests get tickets of the fake's own, which name the admission of their grant,
//! granted once a reservation fits; the fake checks what the hub checks of an admission:
//! claimed before a job is submitted under it, its outcome reported under its own ID, and
//! once (but for a job found empty).
//!
//! It counts the connections it accepts and the sessions it welcomes, and can cut every
//! connection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

use super::relayconn::{self, Io, Ws};

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
    /// The answer's status; 0 resets the request's stream without one.
    pub status: u16,
    pub code: ErrorCode,
    pub retry_after_secs: Option<u32>,
}

/// A request as the fake hub received it.
#[derive(Clone, Debug)]
pub struct HubRequest {
    pub method: String,
    pub path: String,
    pub query: String,
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
    /// Connections accepted, and those closed since.
    connections: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    /// Sessions welcomed.
    sessions: Arc<AtomicUsize>,
    /// Bumped to cut every open connection.
    cut: tokio::sync::watch::Sender<u64>,
    /// The TLS config a connection is accepted with, its ALPN changeable.
    tls_config: Option<Arc<Mutex<Arc<rustls::ServerConfig>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeHub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Resp = Response<Full<Bytes>>;

/// Counts a connection closed once dropped.
struct Closing(Arc<AtomicUsize>);

impl Drop for Closing {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

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
            approval_url: None,
        },
    )
}

fn dispatch_error(e: DispatchError) -> Resp {
    let retry = e
        .retry_after
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(1));
    let (status, code) = match e.kind {
        ErrorKind::Invalid => (400, ErrorCode::Invalid),
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
    json(
        status,
        &ClientError {
            error: e.message,
            code,
            retry_after_secs: retry,
            approval_url: e.approval_url,
        },
    )
}

fn query(q: &str, name: &str) -> Option<u64> {
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| v.parse().ok())
}

/// Aborts its task once dropped.
struct Aborting(tokio::task::JoinHandle<()>);

impl Drop for Aborting {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A request on a relay's connection, served as the hub serves it: refused before the session
/// and after it, and refused for a long poll.
async fn request(
    req: Request<Incoming>,
    up: Arc<AtomicBool>,
    hub: FakeDispatcher,
    recs: Arc<Mutex<Vec<HubRequest>>>,
    flts: Arc<Mutex<VecDeque<Fault>>>,
    tickets: Arc<Mutex<Tickets>>,
    delay: Arc<Mutex<Option<Duration>>>,
) -> Result<Resp, std::io::Error> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_owned();
    let q = parts.uri.query().unwrap_or("").to_owned();
    let body = body
        .collect()
        .await
        .map_err(std::io::Error::other)?
        .to_bytes();
    recs.lock().unwrap().push(HubRequest {
        method: parts.method.to_string(),
        path: path.clone(),
        query: q.clone(),
        headers: parts.headers.clone(),
        body: body.clone(),
    });
    if !up.load(Ordering::SeqCst) {
        return Ok(error(
            503,
            ErrorCode::Unavailable,
            "the connection's session is not up",
            None,
        ));
    }
    if query(&q, "wait").is_some() {
        return Ok(error(
            400,
            ErrorCode::Invalid,
            "a relay's connection does not long-poll: wait is refused",
            None,
        ));
    }
    let fault = {
        let mut f = flts.lock().unwrap();
        match f.front() {
            Some(fault)
                if path.starts_with(&fault.path_prefix) && path.ends_with(&fault.path_suffix) =>
            {
                f.pop_front()
            }
            _ => None,
        }
    };
    if let Some(f) = fault {
        if f.status == 0 {
            // The request's stream reset, without an answer.
            return Err(std::io::Error::other("stream reset"));
        }
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

/// Grant each queued ticket once a reservation fits, as the hub's scheduler does.
async fn grant_tickets(hub: FakeDispatcher, tickets: Arc<Mutex<Tickets>>) {
    loop {
        let waiting: Vec<(String, ReservationRequest)> = tickets
            .lock()
            .unwrap()
            .tickets
            .iter()
            .filter_map(|(id, t)| match t {
                Ticket::Waiting(ask) => Some((id.clone(), ask.clone())),
                _ => None,
            })
            .collect();
        for (id, ask) in waiting {
            let lease = Duration::from_secs(u64::from(ask.lease_secs));
            let Ok(r) = hub
                .reserve(
                    ask.runner.as_deref().unwrap_or(""),
                    &ask.request_id,
                    &ask.placement,
                    lease,
                    Duration::ZERO,
                )
                .await
            else {
                continue;
            };
            let grant = ReservationGrant {
                // The ticket names its grant's admission, as the hub's does.
                admission: Some(id.clone()),
                reservation: r.id,
                node: r.node,
                envelope: r.envelope,
                lease_secs: u32::try_from(r.lease.as_secs()).unwrap(),
            };
            let taken = {
                let mut t = tickets.lock().unwrap();
                match t.tickets.get_mut(&id) {
                    Some(ticket @ Ticket::Waiting(_)) => {
                        *ticket = Ticket::Granted(grant.clone());
                        true
                    }
                    _ => false,
                }
            };
            if !taken {
                hub.release(&grant.reservation).await.unwrap();
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The heartbeat the fake hub welcomes a relay with.
pub const HEARTBEAT: Duration = Duration::from_secs(1);

/// A relay's session at version 5, as `vk-hub/src/relays.rs` holds it: the handshake, checked
/// against the enrolled `key`, then pings, and a notice per ticket and job that changed,
/// diffed every 20 ms; the session ends once the relay is silent for three heartbeats.
async fn session(
    mut ws: Ws,
    key: Option<Vec<u8>>,
    exported: Option<[u8; vk_hub_proto::TLS_EXPORTER_LEN]>,
    up: &AtomicBool,
    sessions: &AtomicUsize,
    hub: FakeDispatcher,
    tickets: Arc<Mutex<Tickets>>,
) {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use vk_hub_proto::gitlab::{HubRelayMsg, LANES};
    use vk_hub_proto::{HubMsg, NodeMsg, RefusalCode, VersionRange};

    async fn text(ws: &mut Ws) -> Option<String> {
        loop {
            match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => return Some(t.as_str().to_owned()),
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                _ => return None,
            }
        }
    }
    // A send is bounded by the heartbeat, as the hub's is.
    async fn send(ws: &mut Ws, msg: &impl serde::Serialize) -> bool {
        let frame = Message::text(serde_json::to_string(msg).unwrap());
        matches!(
            tokio::time::timeout(HEARTBEAT, ws.send(frame)).await,
            Ok(Ok(()))
        )
    }
    let Some(Ok(NodeMsg::Hello {
        versions,
        node_id,
        incarnation,
        ..
    })) = text(&mut ws).await.map(|t| serde_json::from_str(&t))
    else {
        return;
    };
    let offered = VersionRange {
        min: LANES,
        max: LANES,
    };
    let nonce = [9u8; vk_hub_proto::CHALLENGE_LEN];
    let challenge = HubMsg::Challenge {
        version: LANES,
        versions: offered,
        nonce: vk_hub_proto::to_hex(&nonce),
    };
    if !send(&mut ws, &challenge).await {
        return;
    }
    let Some(Ok(NodeMsg::Auth { signature })) =
        text(&mut ws).await.map(|t| serde_json::from_str(&t))
    else {
        return;
    };
    let message = vk_hub_proto::auth_message(
        &nonce,
        &node_id,
        &incarnation,
        versions,
        offered,
        LANES,
        match &exported {
            Some(e) => vk_hub_proto::Channel::Tls(e),
            None => vk_hub_proto::Channel::Plaintext,
        },
    );
    let signed = key.is_some_and(|k| {
        vk_hub_proto::from_hex(&signature).is_some_and(|s: Vec<u8>| {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &k)
                .verify(&message, &s)
                .is_ok()
        })
    });
    if node_id != TEST_RELAY_ID || !signed {
        let refused = HubMsg::Refused {
            code: RefusalCode::NotEnrolled,
            reason: "not an enrolled relay".to_owned(),
        };
        send(&mut ws, &refused).await;
        return;
    }
    up.store(true, Ordering::SeqCst);
    let welcome = HubMsg::Welcome {
        heartbeat_secs: u32::try_from(HEARTBEAT.as_secs()).unwrap(),
    };
    if !send(&mut ws, &welcome).await {
        return;
    }
    sessions.fetch_add(1, Ordering::SeqCst);
    let mut ping = tokio::time::interval(HEARTBEAT);
    let mut diff = tokio::time::interval(Duration::from_millis(20));
    let mut heard = tokio::time::Instant::now();
    // What this session last told of each ticket (granted or ended) and job.
    let mut told_tickets: HashMap<String, bool> = HashMap::new();
    let mut told_jobs: HashMap<String, (u64, u64)> = HashMap::new();
    loop {
        tokio::select! {
            _ = ping.tick() => {
                let ping = ws.send(Message::Ping(Vec::new().into()));
                if !matches!(tokio::time::timeout(HEARTBEAT, ping).await, Ok(Ok(()))) {
                    return;
                }
            }
            _ = diff.tick() => {
                let mut notices = Vec::new();
                for (id, ticket) in tickets.lock().unwrap().tickets.iter() {
                    let granted = match ticket {
                        Ticket::Waiting(_) => continue,
                        Ticket::Granted(_) => true,
                        Ticket::Cancelled => false,
                    };
                    if told_tickets.insert(id.clone(), granted) != Some(granted) {
                        notices.push(HubRelayMsg::Ticket { ticket: id.clone() });
                    }
                }
                for (job, revision, output_len) in hub.unsettled() {
                    if told_jobs.insert(job.clone(), (revision, output_len))
                        != Some((revision, output_len))
                    {
                        notices.push(HubRelayMsg::Job { job, revision, output_len });
                    }
                }
                for notice in notices {
                    if !send(&mut ws, &notice).await {
                        return;
                    }
                }
            }
            () = tokio::time::sleep_until(heard + HEARTBEAT * 3) => return,
            frame = ws.next() => match frame {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(_)) => heard = tokio::time::Instant::now(),
            },
        }
    }
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
            match tickets.lock().unwrap().tickets.get(*id) {
                Some(Ticket::Waiting(_)) => json(
                    202,
                    &ReservationTicket {
                        ticket: (*id).to_owned(),
                    },
                ),
                Some(Ticket::Granted(grant)) => json(201, grant),
                Some(Ticket::Cancelled) | None => {
                    error(410, ErrorCode::ReservationGone, "ticket cancelled", None)
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
        Self::start_on(hub, None).await
    }

    /// A fake hub over TLS with `tls/hub-cert.pem` for `localhost`, offering `alpn`. The
    /// fixtures are copies of vk-hub's `src/testdata/tls-*.pem`: regenerate both together.
    pub async fn start_tls(hub: FakeDispatcher, alpn: &[&[u8]]) -> FakeHub {
        use rustls::pki_types::pem::PemObject;
        let fixture = |name: &str| {
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/tls")
                    .join(name),
            )
            .unwrap()
        };
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&fixture("hub-cert.pem"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(&fixture("hub-key.pem")).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Self::start_on(hub, Some(Arc::new(Mutex::new(Arc::new(config))))).await
    }

    async fn start_on(
        hub: FakeDispatcher,
        tls: Option<Arc<Mutex<Arc<rustls::ServerConfig>>>>,
    ) -> FakeHub {
        let tls_config = tls.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = match tls {
            Some(_) => format!("https://localhost:{}", addr.port()),
            None => format!("http://{addr}"),
        };
        let connections = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let cut = tokio::sync::watch::Sender::new(0u64);
        let sessions = Arc::new(AtomicUsize::new(0));
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
        let accepted = Arc::clone(&connections);
        let closing = Arc::clone(&closed);
        let cutting = cut.subscribe();
        let in_session = Arc::clone(&sessions);
        // As the hub's scheduler: a queued request is granted once a reservation fits.
        let granter = tokio::spawn(grant_tickets(hub.clone(), Arc::clone(&tickets)));
        let task = tokio::spawn(async move {
            let _granter = Aborting(granter);
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                let open = Closing(Arc::clone(&closing));
                let (hub, state, tls) = (hub.clone(), state.clone(), tls.clone());
                let sessions = Arc::clone(&in_session);
                // Only future cut notifications affect this connection.
                let mut cutting = cutting.clone();
                cutting.borrow_and_update();
                tokio::spawn(async move {
                    let _open = open;
                    let (io, exported, h2): (Box<dyn Io>, _, _) = match tls {
                        Some(config) => {
                            let config = config.lock().unwrap().clone();
                            let acceptor = tokio_rustls::TlsAcceptor::from(config);
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            let mut exported = [0u8; vk_hub_proto::TLS_EXPORTER_LEN];
                            stream
                                .get_ref()
                                .1
                                .export_keying_material(
                                    &mut exported,
                                    vk_hub_proto::TLS_EXPORTER_LABEL,
                                    None,
                                )
                                .unwrap();
                            let h2 = stream.get_ref().1.alpn_protocol()
                                == Some(vk_hub_proto::gitlab::ALPN);
                            (Box::new(stream), Some(exported), h2)
                        }
                        None => {
                            let h2 = relayconn::is_h2(&stream).await;
                            (Box::new(stream), None, h2)
                        }
                    };
                    if !h2 {
                        // HTTP/1.1 serves the enrollment alone.
                        let key = state.1.clone();
                        let recs = state.0.clone();
                        let service = service_fn(move |req: Request<Incoming>| {
                            let (key, recs) = (key.clone(), recs.clone());
                            async move {
                                let (parts, body) = req.into_parts();
                                let body = body.collect().await.unwrap().to_bytes();
                                let path = parts.uri.path().to_owned();
                                recs.lock().unwrap().push(HubRequest {
                                    method: parts.method.to_string(),
                                    path: path.clone(),
                                    query: parts.uri.query().unwrap_or("").to_owned(),
                                    headers: parts.headers.clone(),
                                    body: body.clone(),
                                });
                                if parts.method == "POST" && path == "/v1/gitlab/enroll" {
                                    let ask: vk_hub_proto::EnrollRequest =
                                        serde_json::from_slice(&body).unwrap();
                                    *key.lock().unwrap() =
                                        Some(vk_hub_proto::from_hex(&ask.public_key).unwrap());
                                    return Ok::<_, std::io::Error>(json(
                                        200,
                                        &vk_hub_proto::gitlab::EnrollResponse {
                                            relay_id: TEST_RELAY_ID.to_owned(),
                                        },
                                    ));
                                }
                                Ok(error(
                                    401,
                                    ErrorCode::Unauthorized,
                                    "a relay's requests ride its session's connection",
                                    None,
                                ))
                            }
                        });
                        tokio::select! {
                            _ = http1::Builder::new().serve_connection(TokioIo::new(io), service) => {}
                            _ = cutting.changed() => {}
                        }
                        return;
                    }
                    // As the hub: the connection serves its relay's requests while its session
                    // is up, and closes with it.
                    let up = Arc::new(AtomicBool::new(false));
                    let ended = Arc::new(tokio::sync::Notify::new());
                    let serving = Arc::clone(&up);
                    let key = state.1.clone();
                    let (session_hub, tickets) = (hub.clone(), Arc::clone(&state.3));
                    let other = move |req: Request<Incoming>| {
                        let (hub, (recs, _, flts, tickets, delay)) = (hub.clone(), state.clone());
                        let up = Arc::clone(&serving);
                        async move { request(req, up, hub, recs, flts, tickets, delay).await }
                    };
                    let closed = Arc::clone(&ended);
                    let (conn, ws) =
                        relayconn::serve(io, other, async move { closed.notified().await });
                    let session = tokio::spawn(async move {
                        if let Ok(ws) = ws.await {
                            let key = key.lock().unwrap().clone();
                            session(ws, key, exported, &up, &sessions, session_hub, tickets).await;
                        }
                        up.store(false, Ordering::SeqCst);
                        ended.notify_one();
                    });
                    let _session = Aborting(session);
                    tokio::select! {
                        () = conn => {}
                        _ = cutting.changed() => {}
                    }
                });
            }
        });
        FakeHub {
            url,
            connections,
            closed,
            sessions,
            cut,
            tls_config,
            requests,
            relay_key,
            faults,
            queue_response_delay,
            tickets,
            task,
        }
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Cut every open connection, without an answer to the requests on it, and wait until
    /// they are closed.
    pub async fn cut_connections(&self) {
        let open = self.connections();
        self.cut.send_modify(|n| *n += 1);
        tokio::time::timeout(Duration::from_secs(20), async {
            while self.closed.load(Ordering::SeqCst) < open {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the connections cut close");
    }

    /// Sessions welcomed so far.
    pub fn sessions(&self) -> usize {
        self.sessions.load(Ordering::SeqCst)
    }

    /// Offer `alpn` on the connections accepted from now on.
    pub fn set_alpn(&self, alpn: &[&[u8]]) {
        let tls = self.tls_config.as_ref().expect("a fake hub over TLS");
        let mut config = tls.lock().unwrap();
        let mut next = (**config).clone();
        next.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        *config = Arc::new(next);
    }

    /// Take `public_key` for the enrolled relay's, as an enrollment would.
    pub fn enroll(&self, public_key: &[u8]) {
        *self.relay_key.lock().unwrap() = Some(public_key.to_vec());
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

    /// Answers the next `n` requests under `path_prefix` with `status` and `code`; status 0
    /// cuts their connection instead.
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
    /// with `status` and `code`; status 0 cuts their connection instead.
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
