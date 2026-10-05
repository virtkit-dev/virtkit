//! Shared hub state, a connection-limited accept loop, and the node listener:
//! `POST /v1/enroll` and the `/v1/node` WebSocket. Like `vk-registry`, it uses hyper with TLS
//! when the config supplies a certificate.

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
use vk_hub_proto::{
    ENROLL_PATH, EnrollRequest, EnrollResponse, ErrorBody, NODE_PATH, PUBLIC_KEY_LEN,
    SIGNATURE_LEN, from_hex_lower,
};

use crate::store::{Db, Enrollment};

type Body = Full<Bytes>;

/// How often a node heartbeats, in seconds, told to it at the start of each session. Short
/// under test, so a quiet session is dropped within a test's patience.
#[cfg(not(test))]
pub const HEARTBEAT_SECS: u32 = 5;
#[cfg(test)]
pub const HEARTBEAT_SECS: u32 = 1;
// The protocol promises a node at least 1.
const _: () = assert!(HEARTBEAT_SECS >= 1);

/// [`HEARTBEAT_SECS`] as a duration.
pub const HEARTBEAT: Duration = Duration::from_secs(HEARTBEAT_SECS as u64);

/// A session whose node has sent nothing for this many heartbeats is dropped, and a node not
/// heard from for this many — a message or a pong — is shown as unreachable.
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
    /// Permits for sessions still in their handshake, bounded the same way. Unauthenticated
    /// peers hold at most both caps' worth together: 2 × [`MAX_PRE_AUTH`].
    pub(crate) handshakes: Arc<Semaphore>,
    /// The web UI's origin, which its sign-in links start with; `None` with the UI off.
    pub ui_url: Option<String>,
    /// Bumped whenever anything a page shows may have changed, for its live updates.
    changes: watch::Sender<u64>,
    /// The same, for one node: what that node's page follows. An entry exists while someone
    /// follows it.
    node_changes: Mutex<HashMap<String, watch::Sender<u64>>>,
    /// Bumped when a web UI session ends.
    sessions: watch::Sender<u64>,
}

/// One node's open session.
struct Live {
    session: u64,
    last_heard: Instant,
    ending: Arc<Ending>,
}

/// External notifications to end a session or send changed desired state and commands.
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
    /// The hub keeping its state in `db`, with its web UI at `ui_url` if it serves one.
    pub fn new(db: Arc<Db>, ui_url: Option<String>) -> Self {
        Hub {
            db,
            live: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(0),
            connections: Arc::new(Semaphore::new(MAX_PRE_AUTH)),
            handshakes: Arc::new(Semaphore::new(MAX_PRE_AUTH)),
            ui_url,
            changes: watch::Sender::new(0),
            node_changes: Mutex::new(HashMap::new()),
            sessions: watch::Sender::new(0),
        }
    }

    /// Note that something a page shows of node `node_id` may have changed: its report,
    /// heartbeat or session.
    pub(crate) fn changed(&self, node_id: &str) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
        let mut followed = self
            .node_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = followed.get(node_id) {
            if tx.receiver_count() == 0 {
                followed.remove(node_id);
            } else {
                tx.send_modify(|n| *n = n.wrapping_add(1));
            }
        }
    }

    /// Note that something a page shows beyond one node's row may have changed: in local
    /// mode, the VMs listed.
    pub(crate) fn touch(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next [`Hub::changed`] of any node, or [`Hub::touch`].
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Wake on the next [`Hub::changed`] of node `node_id`. Entries no page follows any more
    /// are dropped first, so the map holds no more than the streams open, plus this one.
    pub(crate) fn subscribe_node(&self, node_id: &str) -> watch::Receiver<u64> {
        let mut followed = self
            .node_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        followed.retain(|_, tx| tx.receiver_count() > 0);
        followed
            .entry(node_id.to_string())
            .or_insert_with(|| watch::Sender::new(0))
            .subscribe()
    }

    /// How many nodes have an entry in the map [`Hub::subscribe_node`] fills.
    #[cfg(test)]
    pub(crate) fn followed_nodes(&self) -> usize {
        self.node_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Note that a web UI session ended.
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
        self.changed(node_id);
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
        self.changed(node_id);
    }

    /// Note that `session` heard from its node.
    pub(crate) fn heard(&self, node_id: &str, session: u64) {
        if let Some(live) = self.lock_live().get_mut(node_id)
            && live.session == session
        {
            live.last_heard = Instant::now();
        }
    }

    /// Whether `session` is still `node_id`'s: neither superseded nor revoked.
    pub(crate) fn is_current(&self, node_id: &str, session: u64) -> bool {
        self.lock_live()
            .get(node_id)
            .is_some_and(|l| l.session == session)
    }

    /// Remove `session`, unless a newer one has already taken its place.
    pub(crate) fn close_session(&self, node_id: &str, session: u64) {
        let removed = {
            let mut live = self.lock_live();
            let ours = live.get(node_id).is_some_and(|l| l.session == session);
            if ours {
                live.remove(node_id);
            }
            ours
        };
        if removed {
            self.changed(node_id);
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

/// The TLS keying material a session's auth is bound to ([`vk_hub_proto::Channel`]), or
/// `None` on plain TCP.
pub(crate) type Exported = Option<[u8; vk_hub_proto::TLS_EXPORTER_LEN]>;

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

/// Accept on `listener` until the process ends. Complete any TLS handshake within
/// [`PRE_AUTH_TIMEOUT`] before calling `conn`, holding a permit for the connection's
/// lifetime. Close excess connections immediately.
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
        // Queuing excess connections would still consume resources.
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
                            let mut exported = [0u8; vk_hub_proto::TLS_EXPORTER_LEN];
                            if let Err(e) = stream.get_ref().1.export_keying_material(
                                &mut exported,
                                vk_hub_proto::TLS_EXPORTER_LABEL,
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
        http_body_util::Limited::new(req.into_body(), vk_hub_proto::MAX_MESSAGE).collect(),
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
    // Lowercase only, so the uniqueness check compares the one spelling of each key.
    let Some(public_key) = from_hex_lower::<PUBLIC_KEY_LEN>(&ask.public_key) else {
        return Ok(error(StatusCode::BAD_REQUEST, "malformed public key"));
    };
    let Some(signature) = from_hex_lower::<SIGNATURE_LEN>(&ask.signature) else {
        return Ok(error(StatusCode::BAD_REQUEST, "malformed signature"));
    };
    if !crate::verify(
        &public_key,
        &vk_hub_proto::enroll_message(&ask.token, &public_key),
        &signature,
    ) {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "the signature does not match the key",
        ));
    }
    let db = hub.db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let actor = format!("peer {peer}");
        db.enroll(
            &ask.token,
            &ask.public_key,
            &ask.hostname,
            &actor,
            crate::now_secs(),
        )
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
/// connection, or 503 with every handshake permit taken.
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
    // Taken before the 101, which frees the connection's permit: an unauthenticated peer
    // holds one of these instead, until the node is welcomed or turned away, each step
    // bounded.
    let Ok(permit) = hub.handshakes.clone().try_acquire_owned() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many handshakes in progress",
        );
    };
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
            .max_message_size(Some(vk_hub_proto::MAX_MESSAGE))
            .max_frame_size(Some(vk_hub_proto::MAX_MESSAGE));
        let ws =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(config))
                .await;
        crate::session::run(ws, hub, peer, exported, permit).await;
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
