//! Shared hub state, a connection-limited accept loop, and the node listener:
//! `POST /v1/enroll`, the `/v1/node` WebSocket, release and tools downloads and the client API
//! ([`crate::client`]). Like `vk-registry`, it uses hyper with TLS when the config supplies a
//! certificate.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
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
    ENROLL_PATH, EnrollRequest, EnrollResponse, ErrorBody, NODE_PATH, PUBLIC_KEY_LEN, RELEASE_PATH,
    SHA256_LEN, SIGNATURE_LEN, TOOLS_PATH, from_hex_lower,
};

use crate::store::{Db, Enrollment};

/// A response body: whole, or a release binary streamed from its file.
pub(crate) type Body = BoxBody<Bytes, std::io::Error>;

pub(crate) fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

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

/// How much longer than any connection's first `3 * PRE_AUTH_TIMEOUT` a release download may
/// hold it: a few hundred megabytes over a slow link. A peer that stops reading holds it no
/// longer than this.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Connections at once that have not yet reached a session — in TLS, in HTTP, in an
/// enrollment. Far above what a fleet of tens of nodes reconnecting together needs, and what
/// bounds the descriptors and memory an unauthenticated peer can hold. One past it is closed
/// at once.
pub(crate) const MAX_PRE_AUTH: usize = 256;

/// Release and tools downloads at once. Each holds a descriptor, a TLS session and its
/// buffers for up to [`DOWNLOAD_TIMEOUT`], and a node with an update under way can sign as
/// many as it likes: this bounds them. A few for each node of a fleet of tens; one past it is
/// answered 503, to be retried.
pub(crate) const MAX_DOWNLOADS: usize = 64;

/// Client API connections at once, past their key's check. A `vk-gitlab` holds one per request
/// in flight, most of them long polls: each running job keeps two open (its view's and its
/// output's), so a daemon with a few hundred jobs needs about twice that many. An idle one costs a
/// descriptor, a task, and a TLS session with its buffers. The cap is shared by every key, not
/// counted per key. One past it is answered `unavailable`.
pub(crate) const MAX_CLIENT_CONNS: usize = 1024;

/// How long a client API connection may stay open. It then finishes the request it is serving
/// — a long poll at most, within [`CLIENT_DRAIN`] — and closes, and the client dials again.
const CLIENT_LIFETIME: Duration = Duration::from_secs(600);

/// How long a client connection asked to close has to finish its request.
const CLIENT_DRAIN: Duration = Duration::from_secs(120);

/// What every connection shares: the database, the sessions currently open, and the bounds
/// on connections that have not authenticated and on release downloads.
pub struct Hub {
    pub db: Arc<Db>,
    live: Mutex<HashMap<String, Live>>,
    next_session: AtomicU64,
    /// Permits for connections before their WebSocket upgrade ([`MAX_PRE_AUTH`]).
    pub(crate) connections: Arc<Semaphore>,
    /// Permits for sessions still in their handshake, bounded the same way. Unauthenticated
    /// peers hold at most both caps' worth together: 2 × [`MAX_PRE_AUTH`].
    pub(crate) handshakes: Arc<Semaphore>,
    /// Permits for release downloads under way ([`MAX_DOWNLOADS`]).
    pub(crate) downloads: Arc<Semaphore>,
    /// The web UI's origin, which its sign-in links start with; `None` with the UI off.
    pub ui_url: Option<String>,
    /// Whether the web UI signs people in through OIDC, with the roles granted in the
    /// database.
    pub oidc: bool,
    /// The enrollment and connection URL for `vk node join`, when known
    /// ([`crate::config::HubConfig::node_url`]).
    pub node_url: Option<String>,
    /// Where release binaries are kept; `None` for a hub that holds none.
    releases: Option<std::path::PathBuf>,
    /// Held by a release's add or remove, from its file to its row.
    releases_lock: Mutex<()>,
    /// Where tools definitions are kept; `None` for a hub that holds none.
    tools: Option<std::path::PathBuf>,
    /// Held by a tools definition's add or remove, from its file to its row.
    tools_lock: Mutex<()>,
    /// Where releases are fetched from, and the latest fetch.
    pub(crate) fetches: crate::fetch::Fetches,
    /// Bumped whenever anything a page shows may have changed, for its live updates.
    changes: watch::Sender<u64>,
    /// Per-node change counters followed by node pages.
    node_changes: Followed,
    /// Bumped for one placed job when its output grows or its record changes: what the job's
    /// page follows.
    job_changes: Followed,
    /// Bumped by [`Hub::touch`] alone, for pages that show nothing of a node's report or
    /// heartbeat.
    touched: watch::Sender<u64>,
    /// Bumped by [`Hub::jobs_changed`] alone, for the job history's pages.
    jobs: watch::Sender<u64>,
    /// Bumped when a web UI session ends.
    sessions: watch::Sender<u64>,
    /// Permits for client API connections past their key's check ([`MAX_CLIENT_CONNS`]).
    pub(crate) clients: Arc<Semaphore>,
    /// Reservations and placed jobs.
    pub(crate) dispatch: crate::jobs::Dispatch,
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
            downloads: Arc::new(Semaphore::new(MAX_DOWNLOADS)),
            ui_url,
            oidc: false,
            node_url: None,
            releases: None,
            releases_lock: Mutex::new(()),
            tools: None,
            tools_lock: Mutex::new(()),
            fetches: crate::fetch::Fetches::new(None),
            changes: watch::Sender::new(0),
            node_changes: Followed::default(),
            job_changes: Followed::default(),
            touched: watch::Sender::new(0),
            jobs: watch::Sender::new(0),
            sessions: watch::Sender::new(0),
            clients: Arc::new(Semaphore::new(MAX_CLIENT_CONNS)),
            dispatch: crate::jobs::Dispatch::new(
                None,
                crate::jobs::DEFAULT_LOST_AFTER,
                crate::store::DEFAULT_JOB_HISTORY,
            ),
        }
    }

    /// This hub, placing jobs and keeping their output in `dir`, losing a job whose node has
    /// been unreachable for `lost_after`, and keeping the records of the newest `history`.
    pub fn with_jobs(
        mut self,
        dir: std::path::PathBuf,
        lost_after: Duration,
        history: usize,
    ) -> Result<Self> {
        crate::jobs::output_dir(&dir)?;
        self.dispatch = crate::jobs::Dispatch::new(Some(dir), lost_after, history);
        Ok(self)
    }

    /// This hub, keeping the last `bytes` of a failed job's output when it is settled; 0 keeps
    /// none. After [`Hub::with_jobs`], which sets the default.
    pub fn keeping_failure_output(mut self, bytes: u64) -> Self {
        self.dispatch.kept_failure_output = bytes;
        self
    }

    /// Note that something a page shows of node `node_id` may have changed: its report,
    /// heartbeat or session.
    pub(crate) fn changed(&self, node_id: &str) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
        self.node_changes.bump(node_id);
    }

    /// Note that something a page shows beyond one node's row may have changed: a release, a
    /// rollout, or in local mode the VMs listed.
    pub(crate) fn touch(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
        self.touched.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next [`Hub::touch`] only.
    pub(crate) fn subscribe_touched(&self) -> watch::Receiver<u64> {
        self.touched.subscribe()
    }

    /// Note that a placed job's record may have changed: one submitted, placed, accepted,
    /// at a new stage, finished, canceled or settled, or records dropped from the history.
    /// Its output is not followed here, but by [`Hub::job_changed`].
    pub(crate) fn jobs_changed(&self) {
        self.jobs.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Note that placed job `id`'s output grew or its record changed.
    pub(crate) fn job_changed(&self, id: &str) {
        self.job_changes.bump(id);
    }

    /// Wake on the next [`Hub::job_changed`] of job `id`.
    pub(crate) fn subscribe_job(&self, id: &str) -> watch::Receiver<u64> {
        self.job_changes.subscribe(id)
    }

    /// Wake on the next [`Hub::jobs_changed`] only.
    pub(crate) fn subscribe_jobs(&self) -> watch::Receiver<u64> {
        self.jobs.subscribe()
    }

    /// How many times [`Hub::jobs_changed`] has been called, wrapping: a rendering of the
    /// history read at one count holds until the next.
    pub(crate) fn jobs_generation(&self) -> u64 {
        *self.jobs.borrow()
    }

    /// Wake on the next [`Hub::changed`] of any node, or [`Hub::touch`].
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Wake on the next [`Hub::changed`] of node `node_id`.
    pub(crate) fn subscribe_node(&self, node_id: &str) -> watch::Receiver<u64> {
        self.node_changes.subscribe(node_id)
    }

    /// How many nodes have an entry in the map [`Hub::subscribe_node`] fills.
    #[cfg(test)]
    pub(crate) fn followed_nodes(&self) -> usize {
        self.node_changes.len()
    }

    /// Note that a web UI session ended.
    pub(crate) fn sessions_changed(&self) {
        self.sessions.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next [`Hub::sessions_changed`].
    pub(crate) fn subscribe_sessions(&self) -> watch::Receiver<u64> {
        self.sessions.subscribe()
    }

    /// This hub, signing people in to its web UI through OIDC.
    pub fn with_oidc(mut self) -> Self {
        self.oidc = true;
        self
    }

    /// This hub, advertising `url` as its node endpoint.
    pub fn with_node_url(mut self, url: Option<String>) -> Self {
        self.node_url = url;
        self
    }

    /// This hub, keeping release binaries in `dir`.
    pub fn with_releases(mut self, dir: std::path::PathBuf) -> Self {
        self.releases = Some(dir);
        self
    }

    /// This hub, keeping tools definitions in `dir`.
    pub fn with_tools(mut self, dir: std::path::PathBuf) -> Self {
        self.tools = Some(dir);
        self
    }

    /// Where tools definitions are kept.
    pub fn tools_dir(&self) -> Result<&std::path::Path> {
        self.tools
            .as_deref()
            .context("this hub keeps no tools definitions")
    }

    /// One tools definition add or remove at a time, as [`Hub::releases_lock`] is for releases.
    pub(crate) fn tools_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.tools_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// This hub, fetching releases from `source`; `None` fetches none.
    pub fn with_release_source(mut self, source: Option<crate::fetch::Source>) -> Self {
        self.fetches = crate::fetch::Fetches::new(source);
        self
    }

    /// Where release binaries are kept.
    pub fn releases_dir(&self) -> Result<&std::path::Path> {
        self.releases
            .as_deref()
            .context("this hub keeps no releases")
    }

    /// One release add or remove at a time. A panic while it was held left nothing it guards
    /// half-changed that a later holder could trip on, so poisoning is ignored.
    pub(crate) fn releases_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.releases_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

/// A change counter for each of the things pages follow one at a time, by key. An entry
/// exists while someone follows it: those no page follows any more are dropped when one is
/// bumped or another is followed, so following one leaves the map no larger than the streams
/// open, plus that one.
#[derive(Default)]
struct Followed(Mutex<HashMap<String, watch::Sender<u64>>>);

impl Followed {
    /// Wake those following `key`, if any do.
    fn bump(&self, key: &str) {
        let mut followed = self.lock();
        if let Some(tx) = followed.get(key) {
            if tx.receiver_count() == 0 {
                followed.remove(key);
            } else {
                tx.send_modify(|n| *n = n.wrapping_add(1));
            }
        }
    }

    /// Wake on the next [`Followed::bump`] of `key`.
    fn subscribe(&self, key: &str) -> watch::Receiver<u64> {
        let mut followed = self.lock();
        followed.retain(|_, tx| tx.receiver_count() > 0);
        followed
            .entry(key.to_string())
            .or_insert_with(|| watch::Sender::new(0))
            .subscribe()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, watch::Sender<u64>>> {
        // Senders are inserted and removed whole, so a panic leaves no partial entry.
        self.0
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

/// A connection's place among the unauthenticated ones, which it gives up once it has proved
/// who it is and goes on to hold the connection for longer: a node downloading a release.
pub(crate) type PreAuth = Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>;

/// Serve nodes on `listener` until the process ends.
pub async fn serve(listener: TcpListener, tls: Option<TlsAcceptor>, hub: Arc<Hub>) -> Result<()> {
    let permits = hub.connections.clone();
    accept(listener, tls, permits, move |io, peer, exported, permit| {
        serve_conn(io, hub.clone(), peer, exported, permit)
    })
    .await
}

/// Accept on `listener` until the process ends. Complete any TLS handshake within
/// [`PRE_AUTH_TIMEOUT`] before calling `conn`, holding a permit for the connection's
/// lifetime unless `conn` gives it up ([`PreAuth`]). Close excess connections immediately.
pub(crate) async fn accept<F, Fut>(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    permits: Arc<Semaphore>,
    conn: F,
) -> Result<()>
where
    F: Fn(Io, SocketAddr, Exported, PreAuth) -> Fut + Send + Sync + 'static,
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
        let permit: PreAuth = Arc::new(Mutex::new(Some(permit)));
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
                            conn(TokioIo::new(io), peer, Some(exported), permit.clone()).await;
                        }
                        Ok(Err(e)) => eprintln!("vk-hub: {peer}: TLS handshake error: {e}"),
                        Err(_) => eprintln!("vk-hub: {peer}: TLS handshake timed out"),
                    }
                }
                None => {
                    let io: Box<dyn Stream> = Box::new(stream);
                    conn(TokioIo::new(io), peer, None, permit.clone()).await;
                }
            }
            drop(permit);
        });
    }
}

/// What a connection's requests share: whether it serves a download, its [`PreAuth`], and
/// once a client API key was checked on it, its place among the clients'.
#[derive(Clone)]
struct ConnState {
    downloading: Arc<AtomicBool>,
    permit: PreAuth,
    client: Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>,
}

impl ConnState {
    /// Count the connection among the clients', no longer among the unauthenticated: whether
    /// there was room for it.
    fn claim_client(&self, hub: &Hub) -> bool {
        let mut client = self
            .client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if client.is_none() {
            let Ok(permit) = hub.clients.clone().try_acquire_owned() else {
                return false;
            };
            *client = Some(permit);
            drop(
                self.permit
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take(),
            );
        }
        true
    }

    fn is_client(&self) -> bool {
        self.client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

async fn serve_conn(io: Io, hub: Arc<Hub>, peer: SocketAddr, exported: Exported, permit: PreAuth) {
    let state = ConnState {
        downloading: Arc::new(AtomicBool::new(false)),
        permit,
        client: Arc::new(Mutex::new(None)),
    };
    let downloading = state.downloading.clone();
    let conn_state = state.clone();
    let svc = service_fn(move |req| handle(req, hub.clone(), peer, exported, state.clone()));
    // `with_upgrades`: a WebSocket is an HTTP/1.1 upgrade, handed over once the 101 is out,
    // which is also when this future ends. The header timeout needs the timer — without one
    // hyper quietly applies none. The connection as a whole is bounded too: a node makes one
    // request on it, an enrollment, an upgrade or a download, so one kept idle is only one
    // held open. An authenticated download gets [`DOWNLOAD_TIMEOUT`] more, and a client
    // whose key was checked [`CLIENT_LIFETIME`]; between its requests, the header timeout
    // closes one left idle.
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(PRE_AUTH_TIMEOUT)
        .serve_connection(io, svc)
        .with_upgrades();
    tokio::pin!(conn);
    let ended = match tokio::time::timeout(PRE_AUTH_TIMEOUT * 3, &mut conn).await {
        Ok(ended) => Some(ended),
        Err(_) if downloading.load(Ordering::Relaxed) => {
            tokio::time::timeout(DOWNLOAD_TIMEOUT, conn).await.ok()
        }
        Err(_) if conn_state.is_client() => {
            match tokio::time::timeout(CLIENT_LIFETIME, &mut conn).await {
                Ok(ended) => Some(ended),
                Err(_) => {
                    conn.as_mut().graceful_shutdown();
                    tokio::time::timeout(CLIENT_DRAIN, conn).await.ok()
                }
            }
        }
        Err(_) => None,
    };
    match ended {
        // A client's connection left idle between its requests, closed as intended.
        Some(Err(e)) if e.is_timeout() && conn_state.is_client() => {}
        Some(Err(e)) => eprintln!("vk-hub: {peer}: connection error: {e}"),
        _ => {}
    }
}

async fn handle(
    req: Request<Incoming>,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
    state: ConnState,
) -> Result<Response<Body>, Infallible> {
    let resp = match (req.method(), req.uri().path()) {
        (&Method::POST, ENROLL_PATH) => enroll(req, &hub, peer).await,
        (&Method::GET, NODE_PATH) => Ok(upgrade(req, hub, peer, exported)),
        (&Method::GET, path) if path.starts_with(RELEASE_PATH) => {
            download(&req, &hub, peer, exported, &state, Download::Release).await
        }
        (&Method::GET, path) if path.starts_with(TOOLS_PATH) => {
            download(&req, &hub, peer, exported, &state, Download::Tools).await
        }
        (_, path) if crate::client::is_client_path(path) => Ok(client(req, &hub, &state).await),
        _ => Ok(error(StatusCode::NOT_FOUND, "no such endpoint")),
    };
    Ok(resp.unwrap_or_else(|e| {
        eprintln!("vk-hub: {peer}: {e:#}");
        error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }))
}

/// A client API request: its key checked before anything else is read.
async fn client(req: Request<Incoming>, hub: &Arc<Hub>, state: &ConnState) -> Response<Body> {
    let principal = match crate::client::authenticate(req.headers(), hub).await {
        Ok(p) => p,
        Err(e) => return e.response(),
    };
    if !state.claim_client(hub) {
        return crate::client::ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            vk_hub_proto::client::ErrorCode::Unavailable,
            "too many client connections",
        )
        .retry_after(1)
        .response();
    }
    crate::client::serve(req, hub, principal).await
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

/// What a node downloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Download {
    /// The `vk` binary an update names.
    Release,
    /// The tools definition a tools build names.
    Tools,
}

impl Download {
    fn prefix(self) -> &'static str {
        match self {
            Download::Release => RELEASE_PATH,
            Download::Tools => TOOLS_PATH,
        }
    }

    fn what(self) -> &'static str {
        match self {
            Download::Release => "release",
            Download::Tools => "tools definition",
        }
    }

    fn message(
        self,
        node_id: &str,
        digest: &[u8; SHA256_LEN],
        at: u64,
        channel: vk_hub_proto::Channel<'_>,
    ) -> Vec<u8> {
        match self {
            Download::Release => vk_hub_proto::download_message(node_id, digest, at, channel),
            Download::Tools => vk_hub_proto::tools_download_message(node_id, digest, at, channel),
        }
    }
}

/// `GET /v1/releases/<sha256>`: a release's binary, to a node that proves it is one — by a
/// signature over [`vk_hub_proto::download_message`] with its pinned key, bound to this
/// connection — and has an update to that release still to finish. Nothing else may fetch a
/// release: the hub is not a download site, and a node learns of a release only from the
/// command that names it. `GET /v1/tools/<sha256>` serves a tools definition the same way,
/// signed over [`vk_hub_proto::tools_download_message`], to a node with a tools build of it
/// still to finish.
async fn download(
    req: &Request<Incoming>,
    hub: &Hub,
    peer: SocketAddr,
    exported: Exported,
    state: &ConnState,
    kind: Download,
) -> Result<Response<Body>> {
    let what = kind.what();
    let sha256 = req
        .uri()
        .path()
        .strip_prefix(kind.prefix())
        .unwrap_or_default()
        .to_string();
    let Some(digest) = vk_hub_proto::valid_sha256(&sha256)
        .then(|| from_hex_lower::<SHA256_LEN>(&sha256))
        .flatten()
    else {
        return Ok(error(StatusCode::NOT_FOUND, &format!("no such {what}")));
    };
    let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());
    let (Some(node_id), Some(at), Some(signature)) = (
        header(vk_hub_proto::NODE_HEADER).filter(|id| vk_hub_proto::valid_id(id)),
        header(vk_hub_proto::TIME_HEADER).and_then(|t| t.parse::<u64>().ok()),
        header(vk_hub_proto::SIGNATURE_HEADER).and_then(from_hex_lower::<SIGNATURE_LEN>),
    ) else {
        return Ok(error(
            StatusCode::UNAUTHORIZED,
            &format!("a {what} is downloaded by a node, signing for it"),
        ));
    };
    let node_id = node_id.to_string();
    let now = crate::now_secs();
    if now.abs_diff(at) > vk_hub_proto::DOWNLOAD_SKEW_SECS {
        return Ok(error(
            StatusCode::UNAUTHORIZED,
            "the signed time is too far from the hub's clock",
        ));
    }
    let db = hub.db.clone();
    let (id, sha) = (node_id.clone(), sha256.clone());
    // The node, whether it has a command under way that this download is for, and the size
    // the file is recorded at.
    let (row, wanted, size) = tokio::task::spawn_blocking(move || match kind {
        Download::Release => anyhow::Ok((
            db.node(&id)?,
            db.updating_to(&id, &sha, now)?,
            db.release(&sha)?.map(|r| r.size),
        )),
        Download::Tools => anyhow::Ok((
            db.node(&id)?,
            db.building_tools(&id, &sha, now)?,
            db.tools(&sha)?.map(|t| t.size),
        )),
    })
    .await
    .context("looking a download up")??;
    let Some(row) = row else {
        return Ok(error(StatusCode::FORBIDDEN, "no such node"));
    };
    let Some(public_key) = from_hex_lower::<PUBLIC_KEY_LEN>(&row.public_key) else {
        anyhow::bail!("node {node_id} has a corrupt pinned key");
    };
    let channel = match &exported {
        Some(exported) => vk_hub_proto::Channel::Tls(exported),
        None => vk_hub_proto::Channel::Plaintext,
    };
    let message = kind.message(&node_id, &digest, at, channel);
    if !crate::verify(&public_key, &message, &signature) {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "the signature does not match the node's pinned key; a proxy terminating TLS in \
             front of the hub breaks its binding to the connection: pass TLS through",
        ));
    }
    let (Some(recorded), true) = (size, wanted) else {
        return Ok(error(
            StatusCode::FORBIDDEN,
            match kind {
                Download::Release => "this node has no update to that release under way",
                Download::Tools => "this node has no tools build of that definition under way",
            },
        ));
    };
    let path = match kind {
        Download::Release => crate::releases::path(hub.releases_dir()?, &sha256),
        Download::Tools => crate::tools::path(hub.tools_dir()?, &sha256),
    };
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "vk-hub: {what} {sha256} is recorded but {} is missing",
                path.display()
            );
            return Ok(error(
                StatusCode::NOT_FOUND,
                &format!("the {what}'s file is missing"),
            ));
        }
        Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
    };
    let size = file
        .metadata()
        .await
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if size != recorded {
        eprintln!(
            "vk-hub: {what} {sha256} is recorded as {recorded} bytes but {} holds {size}",
            path.display()
        );
        return Ok(error(
            StatusCode::NOT_FOUND,
            &format!("the {what}'s file is the wrong size"),
        ));
    }
    let Ok(slot) = hub.downloads.clone().try_acquire_owned() else {
        return Ok(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many downloads at once; retry",
        ));
    };
    state.downloading.store(true, Ordering::Relaxed);
    // Authenticated: the connection no longer counts against the ones that are not.
    drop(
        state
            .permit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(),
    );
    eprintln!(
        "vk-hub: {peer}: node {node_id} is downloading {what} {}",
        crate::store::short(&sha256)
    );
    // The slot goes with the body, which hyper drops once it is sent or the peer is gone.
    let chunks = futures::stream::try_unfold((file, slot), |(mut file, slot)| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256 * 1024];
        let n = file.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some((
            hyper::body::Frame::data(Bytes::from(buf)),
            (file, slot),
        )))
    });
    let mut resp = Response::new(StreamBody::new(chunks).boxed());
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, header::HeaderValue::from(recorded));
    // One download per connection: what [`DOWNLOAD_TIMEOUT`] bounds is this one.
    h.insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    Ok(resp)
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
    let mut resp = Response::new(full(Bytes::new()));
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
    let mut resp = Response::new(full(body));
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
