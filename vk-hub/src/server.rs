//! What the hub's listeners share — its state, and the accept loop that holds every
//! connection to a bounded count — and the node-facing listener: `POST /v1/enroll` and the
//! `/v1/node` WebSocket, over hyper, with TLS when the config has a certificate — the shape of
//! `vk-registry`'s server.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, watch};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use vk_fleet_proto::{ENROLL_PATH, EnrollRequest, EnrollResponse, ErrorBody, NODE_PATH};

use crate::store::{Db, Enrollment};

type Body = Full<Bytes>;

/// How often a node heartbeats, told to it at the start of each session. Short under test,
/// so a quiet session is dropped within a test's patience.
#[cfg(not(test))]
pub const HEARTBEAT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const HEARTBEAT: Duration = Duration::from_secs(1);

/// A session whose node has sent nothing for this many heartbeats is dropped, and a node
/// that has not heartbeated for this many is shown as unreachable.
pub const MISSED_HEARTBEATS: u32 = 3;

/// Accept backlog: tens of nodes reconnecting at once after a hub restart must all fit.
const LISTEN_BACKLOG: u32 = 1024;

/// How long a client has for each step before it has authenticated: the TLS handshake, its
/// request headers, an enrollment body, a form's body. A node or a browser needs milliseconds
/// for any of them; a peer that holds a connection open without finishing one is only holding
/// it.
pub const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Connections at once that have not yet reached a session — in TLS, in HTTP, in an
/// enrollment. Far above what a fleet of tens of nodes reconnecting together needs, and what
/// bounds the descriptors and memory an unauthenticated peer can hold. One past it is closed
/// at once.
const MAX_PRE_AUTH: usize = 256;

/// What every connection shares: the database, the sessions currently open, and the bounds
/// on connections that have not authenticated.
pub struct Hub {
    pub db: Arc<Db>,
    live: Mutex<HashMap<String, Live>>,
    next_session: AtomicU64,
    /// Permits for connections before their WebSocket upgrade ([`MAX_PRE_AUTH`]).
    connections: Arc<Semaphore>,
    /// Permits for sessions still in their handshake, bounded the same way.
    pub(crate) handshakes: Arc<Semaphore>,
    /// The web UI's origin, which its sign-in links start with; `None` with the UI off.
    pub ui_url: Option<String>,
    /// Bumped whenever anything a page shows may have changed, for its live updates.
    changes: watch::Sender<u64>,
    /// Bumped when a web UI session opens or ends.
    sessions: watch::Sender<u64>,
}

/// One node's open session.
struct Live {
    session: u64,
    last_heard: Instant,
    ending: Arc<Ending>,
}

/// How a session is told something from outside it: to end, or that what the hub wants of
/// its node changed.
#[derive(Default)]
pub(crate) struct Ending {
    pub(crate) notify: Notify,
    /// Set before `notify` when the node was removed rather than superseded.
    pub(crate) revoked: AtomicBool,
    /// Notified when the node's desired state or commands changed.
    pub(crate) kick: Notify,
}

/// A node's session state, as `vk-hub nodes` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    Connected,
    /// No session, or one that has gone quiet: the node's state is unknown, not stopped.
    Unreachable,
}

impl Hub {
    pub fn new(db: Arc<Db>) -> Self {
        Hub {
            db,
            live: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(0),
            connections: Arc::new(Semaphore::new(MAX_PRE_AUTH)),
            handshakes: Arc::new(Semaphore::new(MAX_PRE_AUTH)),
            ui_url: None,
            changes: watch::Sender::new(0),
            sessions: watch::Sender::new(0),
        }
    }
    /// This hub with its web UI at `url`.
    pub fn with_ui_url(mut self, url: Option<String>) -> Self {
        self.ui_url = url;
        self
    }

    /// Note that something a page shows may have changed.
    pub(crate) fn touch(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next [`Hub::touch`].
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Note that a web UI session opened or ended.
    pub(crate) fn sessions_changed(&self) {
        self.sessions.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next [`Hub::sessions_changed`].
    pub(crate) fn subscribe_sessions(&self) -> watch::Receiver<u64> {
        self.sessions.subscribe()
    }

    /// Register `node_id`'s new session, ending any older one: a node runs one `vk node`, so
    /// a second session is either its restart or its reconnect racing the old socket's
    /// teardown, and the newer one is the node's current state either way.
    pub(crate) fn open_session(&self, node_id: &str) -> (u64, Arc<Ending>) {
        let session = self.next_session.fetch_add(1, Ordering::Relaxed);
        let ending = Arc::new(Ending::default());
        let old = self.lock_live().insert(
            node_id.to_string(),
            Live {
                session,
                last_heard: Instant::now(),
                ending: ending.clone(),
            },
        );
        if let Some(old) = old {
            // `notify_one` stores a permit, so an old session between two awaits still sees it.
            old.ending.notify.notify_one();
        }
        (session, ending)
    }

    /// Tell `node_id`'s session, if it has one, to send what changed. A node with none gets it
    /// when it next connects.
    pub(crate) fn kick(&self, node_id: &str) {
        if let Some(live) = self.lock_live().get(node_id) {
            live.ending.kick.notify_one();
        }
    }

    /// End `node_id`'s session, if it has one, as revoked. The caller has removed the node.
    pub(crate) fn revoke(&self, node_id: &str) {
        if let Some(live) = self.lock_live().remove(node_id) {
            live.ending.revoked.store(true, Ordering::Relaxed);
            live.ending.notify.notify_one();
        }
    }

    /// Note that `session` heard from its node.
    pub(crate) fn heard(&self, node_id: &str, session: u64) {
        if let Some(live) = self.lock_live().get_mut(node_id)
            && live.session == session
        {
            live.last_heard = Instant::now();
        }
    }

    /// Remove `session`, unless a newer one has already taken its place.
    pub(crate) fn close_session(&self, node_id: &str, session: u64) {
        let mut live = self.lock_live();
        if live.get(node_id).is_some_and(|l| l.session == session) {
            live.remove(node_id);
        }
    }

    /// Whether `node_id` has a session whose node is still heard from.
    pub fn reach(&self, node_id: &str) -> Reach {
        match self.lock_live().get(node_id) {
            Some(l) if l.last_heard.elapsed() <= HEARTBEAT * MISSED_HEARTBEATS => Reach::Connected,
            _ => Reach::Unreachable,
        }
    }

    /// The map of sessions. A panic while it was held left nothing half-written worth
    /// refusing over — each entry is replaced whole — so poisoning is ignored.
    fn lock_live(&self) -> std::sync::MutexGuard<'_, HashMap<String, Live>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Bind `addr` with a backlog sized for a fleet reconnecting at once.
pub fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

/// The TLS keying material a session's auth is bound to ([`vk_fleet_proto::Channel`]), or
/// `None` on plain TCP.
pub(crate) type Exported = Option<[u8; vk_fleet_proto::TLS_EXPORTER_LEN]>;

/// A connection's byte stream, TLS or plain, as one type, so one accept loop serves both.
pub(crate) trait Stream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}
pub(crate) type Io = TokioIo<Box<dyn Stream>>;

/// Serve nodes on `listener` until the process ends.
pub async fn serve(listener: TcpListener, tls: Option<TlsAcceptor>, hub: Arc<Hub>) -> Result<()> {
    let permits = hub.connections.clone();
    accept(listener, tls, permits, move |io, peer, exported| {
        serve_conn(io, hub.clone(), peer, exported)
    })
    .await
}

/// Accept on `listener` until the process ends, holding one of `permits` per connection for
/// its whole life, and hand each one to `conn` once through its TLS handshake, which gets
/// [`PRE_AUTH_TIMEOUT`]. One past the permits is closed at once.
pub(crate) async fn accept<F, Fut>(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    permits: Arc<Semaphore>,
    conn: F,
) -> Result<()>
where
    F: Fn(Io, SocketAddr, Exported) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let conn = Arc::new(conn);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // EMFILE and friends persist; a bare retry would spin.
                eprintln!("vk-hub: accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Dropped, not queued: a queue would be the same resource under another name.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let tls = tls.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            match tls {
                Some(acceptor) => {
                    match tokio::time::timeout(PRE_AUTH_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let mut exported = [0u8; vk_fleet_proto::TLS_EXPORTER_LEN];
                            if let Err(e) = stream.get_ref().1.export_keying_material(
                                &mut exported,
                                vk_fleet_proto::TLS_EXPORTER_LABEL,
                                None,
                            ) {
                                eprintln!("vk-hub: {peer}: exporting TLS keying material: {e}");
                                return;
                            }
                            let io: Box<dyn Stream> = Box::new(stream);
                            conn(TokioIo::new(io), peer, Some(exported)).await;
                        }
                        Ok(Err(e)) => eprintln!("vk-hub: {peer}: TLS handshake error: {e}"),
                        Err(_) => eprintln!("vk-hub: {peer}: TLS handshake timed out"),
                    }
                }
                None => {
                    let io: Box<dyn Stream> = Box::new(stream);
                    conn(TokioIo::new(io), peer, None).await;
                }
            }
            drop(permit);
        });
    }
}

async fn serve_conn(io: Io, hub: Arc<Hub>, peer: SocketAddr, exported: Exported) {
    let svc = service_fn(move |req| handle(req, hub.clone(), peer, exported));
    // `with_upgrades`: a WebSocket is an HTTP/1.1 upgrade, handed over once the 101 is out,
    // which is also when this future ends. The header timeout needs the timer — without one
    // hyper quietly applies none. The connection as a whole is bounded too: a node makes one
    // request on it, an enrollment or an upgrade, so one kept idle is only one held open.
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(PRE_AUTH_TIMEOUT)
        .serve_connection(io, svc)
        .with_upgrades();
    match tokio::time::timeout(PRE_AUTH_TIMEOUT * 3, conn).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("vk-hub: {peer}: connection error: {e}"),
        Err(_) => {}
    }
}

async fn handle(
    req: Request<Incoming>,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
) -> Result<Response<Body>, Infallible> {
    let resp = match (req.method(), req.uri().path()) {
        (&Method::POST, ENROLL_PATH) => enroll(req, &hub, peer).await,
        (&Method::GET, NODE_PATH) => Ok(upgrade(req, hub, peer, exported)),
        _ => Ok(error(StatusCode::NOT_FOUND, "no such endpoint")),
    };
    Ok(resp.unwrap_or_else(|e| {
        eprintln!("vk-hub: {peer}: {e:#}");
        error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }))
}

/// `POST /v1/enroll`: check the node's proof of its key, then spend the token on it.
async fn enroll(req: Request<Incoming>, hub: &Hub, peer: SocketAddr) -> Result<Response<Body>> {
    // Capped while reading: a chunked body declares no length to check up front. Timed,
    // since the header timeout ends with the headers.
    let body = match tokio::time::timeout(
        PRE_AUTH_TIMEOUT,
        http_body_util::Limited::new(req.into_body(), vk_fleet_proto::MAX_MESSAGE).collect(),
    )
    .await
    {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(_)) => return Ok(error(StatusCode::PAYLOAD_TOO_LARGE, "body too large")),
        Err(_) => return Ok(error(StatusCode::REQUEST_TIMEOUT, "body too slow")),
    };
    let Ok(ask) = serde_json::from_slice::<EnrollRequest>(&body) else {
        return Ok(error(StatusCode::BAD_REQUEST, "not an enrollment request"));
    };
    let Some(public_key) = vk_fleet_proto::from_hex(&ask.public_key)
        .filter(|k| k.len() == vk_fleet_proto::PUBLIC_KEY_LEN)
    else {
        return Ok(error(StatusCode::BAD_REQUEST, "malformed public key"));
    };
    if !crate::verify(
        &public_key,
        &vk_fleet_proto::enroll_message(&ask.token, &public_key),
        &ask.signature,
    ) {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "the signature does not match the key",
        ));
    }
    // Normalized, so the uniqueness check compares one spelling of each key.
    let public_key = vk_fleet_proto::to_hex(&public_key);
    let db = hub.db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        db.enroll(&ask.token, &public_key, &ask.hostname, crate::now_secs())
    })
    .await
    .context("running an enrollment")??;
    Ok(match outcome {
        Enrollment::Enrolled { node_id } => {
            eprintln!("vk-hub: {peer}: enrolled node {node_id}");
            json(StatusCode::OK, &EnrollResponse { node_id })
        }
        Enrollment::Reenrolled { node_id } => {
            eprintln!("vk-hub: {peer}: node {node_id} enrolled again with its pinned key");
            json(StatusCode::OK, &EnrollResponse { node_id })
        }
        Enrollment::BadToken => error(
            StatusCode::FORBIDDEN,
            "the enrollment token is unknown, used or expired",
        ),
    })
}

/// `GET /v1/node`: answer the WebSocket handshake and run the session on the upgraded
/// connection.
fn upgrade(
    mut req: Request<Incoming>,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
) -> Response<Body> {
    let headers = req.headers();
    let has = |name: header::HeaderName, token: &str| {
        headers.get_all(name).iter().any(|v| {
            v.to_str().is_ok_and(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(token))
            })
        })
    };
    if !has(header::UPGRADE, "websocket") || !has(header::CONNECTION, "upgrade") {
        return error(
            StatusCode::UPGRADE_REQUIRED,
            "a WebSocket upgrade is required",
        );
    }
    if headers
        .get(header::SEC_WEBSOCKET_VERSION)
        .is_none_or(|v| v != "13")
    {
        return error(
            StatusCode::BAD_REQUEST,
            "only WebSocket version 13 is spoken",
        );
    }
    let Some(key) = headers.get(header::SEC_WEBSOCKET_KEY) else {
        return error(StatusCode::BAD_REQUEST, "no Sec-WebSocket-Key");
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                eprintln!("vk-hub: {peer}: WebSocket upgrade failed: {e}");
                return;
            }
        };
        let config = WebSocketConfig::default()
            .max_message_size(Some(vk_fleet_proto::MAX_MESSAGE))
            .max_frame_size(Some(vk_fleet_proto::MAX_MESSAGE));
        let ws =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(config))
                .await;
        crate::session::run(ws, hub, peer, exported).await;
    });
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = resp.headers_mut();
    h.insert(
        header::UPGRADE,
        header::HeaderValue::from_static("websocket"),
    );
    h.insert(
        header::CONNECTION,
        header::HeaderValue::from_static("Upgrade"),
    );
    match header::HeaderValue::from_str(&accept) {
        Ok(v) => {
            h.insert(header::SEC_WEBSOCKET_ACCEPT, v);
            resp
        }
        // Base64 of a digest, so always a valid header value; answered rather than
        // unwrapped all the same.
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    // The protocol's own types, which always serialize; an empty body would be the only
    // outcome of a failure, and the status still says what happened.
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    resp
}

fn error(status: StatusCode, message: &str) -> Response<Body> {
    json(
        status,
        &ErrorBody {
            error: message.to_string(),
        },
    )
}
