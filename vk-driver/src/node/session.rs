//! One session with the hub: dial, authenticate, then inventory and heartbeats until the
//! connection fails or the process is told to stop. [`super::run`] redials.
//!
//! Nothing in the session loop waits on the host: the inventory, heartbeat and workloads are
//! gathered by a [`Gatherer`] task of their own, since a hung mount's `statvfs` or a held
//! ledger lock would otherwise stop the loop from noticing that the hub has gone quiet. Every
//! send has a deadline, and the socket carries keepalives and a `TCP_USER_TIMEOUT`, so a peer
//! that vanished without a word ends the session rather than wedging it.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, mpsc, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use vk_hub_proto::{
    Channel, Heartbeat, HubMsg, Inventory, NodeMsg, PROTOCOL, Report, TLS_EXPORTER_LEN,
};

use super::Enrollment;
use super::identity::Identity;
use crate::config::Config;
use crate::workloads::Listed;

/// How long dialing, TLS and the WebSocket handshake may take together, and how long each
/// handshake message may take to arrive.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the inventory is gathered again, to be sent if it changed. Its facts change
/// with the host or its configuration, which minutes resolve well enough.
const INVENTORY_EVERY: Duration = Duration::from_secs(60);

/// The heartbeat interval a hub may ask for, clamped for the heartbeats the node sends:
/// faster is load for nothing, slower leaves a node looking unreachable to a hub that asked
/// for less.
const HEARTBEAT_RANGE: (u64, u64) = (1, 300);

/// Heartbeats' worth of silence from the hub, which pings at the interval it asked for,
/// unclamped, after which the session is given up as dead.
const MISSED_HEARTBEATS: u32 = 3;

/// How long a stopping node waits for the hub to take its close.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long unacknowledged data may sit on the socket before the kernel gives the
/// connection up, and when an idle one starts being probed. At the hub's 5s heartbeat both
/// fall well inside the silence that ends a session, so the socket fails first and says why.
const TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(10);

/// The transport under the WebSocket: TCP, or TLS over it.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Ws = WebSocketStream<Box<dyn Io>>;

/// A refusal no redial can fix: the node's enrollment is gone or not its own.
#[derive(Debug)]
pub struct Permanent(pub String);

impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Permanent {}

/// A newer session of this node took over at the hub.
#[derive(Debug)]
pub struct Superseded(pub String);

impl std::fmt::Display for Superseded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Superseded {}

/// What a session needs and keeps across reconnects.
pub struct Node {
    /// `<state_dir>/node`, for the messages that send the operator there.
    pub dir: PathBuf,
    pub enrollment: Enrollment,
    pub identity: Identity,
    pub incarnation: String,
    pub tls: Arc<rustls::ClientConfig>,
}

/// What the gatherer is asked for.
enum Ask {
    Inventory,
    Heartbeat,
}

/// What it answers with.
pub enum Gathered {
    Inventory(Box<Inventory>),
    /// The heartbeat, and the workloads its memory readings are for.
    Heartbeat(Heartbeat, Listed),
}

/// What is asked and not yet taken up: one flag per kind, so asking again while the gatherer
/// is busy costs nothing, and no number of heartbeats asked can crowd out an inventory.
#[derive(Default)]
struct Asked {
    inventory: AtomicBool,
    heartbeat: AtomicBool,
    wake: Notify,
}

/// The task that reads the host for the session, for the life of `vk node run`. Asked
/// without waiting and answered through a channel, so a read that hangs stalls the reports,
/// never the session loop.
pub struct Gatherer {
    asked: Arc<Asked>,
    answers: mpsc::Receiver<Gathered>,
}

impl Gatherer {
    pub fn spawn(cfg: Arc<Config>) -> Self {
        Gatherer::spawn_in(cfg, None)
    }

    /// [`Gatherer::spawn`], reading the VMs from `registry`, or the user's own registry when
    /// `None`.
    fn spawn_in(cfg: Arc<Config>, registry: Option<PathBuf>) -> Self {
        let asked = Arc::new(Asked::default());
        let (answer, answers) = mpsc::channel(4);
        let pending = asked.clone();
        tokio::spawn(async move {
            let fresh = || super::inventory::Readings::new(registry.clone());
            let mut readings = fresh();
            loop {
                let what = if pending.inventory.swap(false, Ordering::AcqRel) {
                    Ask::Inventory
                } else if pending.heartbeat.swap(false, Ordering::AcqRel) {
                    Ask::Heartbeat
                } else {
                    // A wake given since the flags were read is kept for this wait.
                    tokio::select! {
                        () = pending.wake.notified() => continue,
                        () = answer.closed() => return,
                    }
                };
                let cfg = cfg.clone();
                // Handed to the read and back, so a lasting complaint is said once; a read
                // that panicked starts it over.
                let held = std::mem::replace(&mut readings, fresh());
                let gathered = tokio::task::spawn_blocking(move || {
                    let mut readings = held;
                    let g = match what {
                        Ask::Inventory => {
                            Gathered::Inventory(Box::new(super::inventory::inventory(&cfg)))
                        }
                        Ask::Heartbeat => {
                            let (heartbeat, workloads) =
                                super::inventory::heartbeat(&cfg, &mut readings);
                            Gathered::Heartbeat(heartbeat, workloads)
                        }
                    };
                    (g, readings)
                })
                .await;
                match gathered {
                    Ok((g, kept)) => {
                        readings = kept;
                        if answer.send(g).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => say!("gathering the node's state: {e}"),
                }
            }
        });
        Gatherer { asked, answers }
    }

    /// Ask, unless the same kind is already asked and not yet taken up: asks of a kind
    /// coalesce into one.
    fn request(&self, what: Ask) {
        let flag = match what {
            Ask::Inventory => &self.asked.inventory,
            Ask::Heartbeat => &self.asked.heartbeat,
        };
        flag.store(true, Ordering::Release);
        self.asked.wake.notify_one();
    }

    /// Drop answers gathered for a session that has ended.
    fn drain(&mut self) {
        while self.answers.try_recv().is_ok() {}
    }
}

/// Run one session to its end. `Ok` means `stop` asked for it, and the hub was told unless a
/// message was on its way; otherwise the error says why it ended, and is a [`Permanent`] when
/// redialing cannot help.
pub async fn run(
    node: &Node,
    gatherer: &mut Gatherer,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let opened = async {
        let (mut ws, exported) =
            tokio::time::timeout(CONNECT_TIMEOUT, connect(&node.enrollment.hub, &node.tls))
                .await
                .map_err(|_| anyhow!("connecting took longer than {CONNECT_TIMEOUT:?}"))??;
        let heartbeat = handshake(&mut ws, node, exported.as_ref()).await?;
        anyhow::Ok((ws, heartbeat))
    };
    let (mut ws, asked) = tokio::select! {
        opened = opened => opened?,
        () = stopped(stop) => return Ok(()),
    };
    // The hub pings at the interval it asked for, so its silence is judged by that one; the
    // node's own heartbeats keep to the clamped one.
    let quiet = Duration::from_secs(u64::from(asked.max(1))) * MISSED_HEARTBEATS;
    let heartbeat =
        Duration::from_secs(u64::from(asked).clamp(HEARTBEAT_RANGE.0, HEARTBEAT_RANGE.1));
    say!(
        "connected to {} (heartbeat every {}s)",
        node.enrollment.hub,
        heartbeat.as_secs()
    );

    gatherer.drain();
    gatherer.request(Ask::Inventory);
    let mut sent_inventory: Option<Inventory> = None;
    // The workloads this session has reported: the first heartbeat's go out on a report.
    let mut sent_workloads: Option<Listed> = None;
    let mut deadline = tokio::time::Instant::now() + quiet;
    let mut beat = tokio::time::interval(heartbeat);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut recheck = tokio::time::interval_at(
        tokio::time::Instant::now() + INVENTORY_EVERY,
        INVENTORY_EVERY,
    );
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stopped(stop) => {
                // Best effort: the process is leaving either way, and the hub treats a
                // vanished node as unknown rather than stopped.
                let _ = tokio::time::timeout(CLOSE_TIMEOUT, ws.close(None)).await;
                return Ok(());
            }
            _ = beat.tick() => gatherer.request(Ask::Heartbeat),
            _ = recheck.tick() => gatherer.request(Ask::Inventory),
            Some(gathered) = gatherer.answers.recv() => {
                let mut msgs = Vec::with_capacity(2);
                match gathered {
                    Gathered::Heartbeat(hb, workloads) => {
                        // The report first, so the heartbeat's readings land on the list
                        // they are for.
                        if sent_workloads.as_ref() != Some(&workloads) {
                            msgs.push(NodeMsg::Report(Report {
                                workloads: Some(workloads.workloads.clone()),
                                workloads_omitted: workloads.omitted,
                            }));
                            sent_workloads = Some(workloads);
                        }
                        msgs.push(NodeMsg::Heartbeat(hb));
                    }
                    Gathered::Inventory(inventory)
                        if sent_inventory.as_ref() == Some(&*inventory) => continue,
                    Gathered::Inventory(inventory) => {
                        sent_inventory = Some((*inventory).clone());
                        msgs.push(NodeMsg::Inventory(*inventory));
                    }
                }
                for msg in &msgs {
                    if !send_unless_stopped(&mut ws, msg, heartbeat, stop).await? {
                        return Ok(());
                    }
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                bail!("the hub has been silent for {}s", quiet.as_secs());
            }
            frame = ws.next() => {
                deadline = tokio::time::Instant::now() + quiet;
                match frame {
                    None => bail!("the hub closed the connection"),
                    // tungstenite's error names its own cause: formatted once, not through a
                    // context chain that would repeat it.
                    Some(Err(e)) => bail!("reading from the hub: {e}"),
                    Some(Ok(Message::Close(_))) => bail!("the hub closed the session"),
                    Some(Ok(Message::Text(text))) => handle(parse(text.as_str())?, &node.dir)?,
                    // tungstenite answers pings itself; each one shows the hub is alive.
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}

/// Once `stop` is raised. Its `Ref` is dropped here, so a `select!` can wait on it again
/// inside another branch's handler. A dropped sender counts too: nothing is left to say
/// otherwise.
pub async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|&s| s).await;
}

/// Send `msg` within `within`, or give it up once `stop` is raised: `false` when stopped. A
/// hub slow to take the message does not hold up a stop; a close cannot follow a frame cut
/// off midway, so none is sent.
async fn send_unless_stopped(
    ws: &mut Ws,
    msg: &NodeMsg,
    within: Duration,
    stop: &mut watch::Receiver<bool>,
) -> Result<bool> {
    tokio::select! {
        sent = send(ws, msg, within) => sent.map(|()| true),
        () = stopped(stop) => Ok(false),
    }
}

/// A message from the hub inside a session.
fn handle(msg: HubMsg, dir: &Path) -> Result<()> {
    match msg {
        HubMsg::Refused { code, reason } => Err(refusal(code, &reason, dir)),
        HubMsg::Challenge { .. } | HubMsg::Welcome { .. } => {
            bail!("the hub repeated its handshake inside a session")
        }
    }
}

/// A message from the hub, its parse error cut to what is safe to print.
fn parse(text: &str) -> Result<HubMsg> {
    serde_json::from_str(text).map_err(|e| {
        anyhow!(
            "the hub sent a message this vk does not understand: {}",
            vk_hub_proto::display_safe(&e.to_string())
        )
    })
}

/// A hub message by kind, for an error that names one out of place.
fn kind(msg: &HubMsg) -> &'static str {
    match msg {
        HubMsg::Challenge { .. } => "a challenge",
        HubMsg::Welcome { .. } => "a welcome",
        HubMsg::Refused { .. } => "a refusal",
    }
}

/// A refusal from the hub as an error: [`Permanent`] when its code says so, [`Superseded`]
/// when another session of this node took over. `dir` is the node's, which a node the hub
/// has forgotten must be enrolled again without.
fn refusal(code: vk_hub_proto::RefusalCode, reason: &str, dir: &Path) -> anyhow::Error {
    use vk_hub_proto::RefusalCode;
    let mut message = format!(
        "the hub refused the session: {}",
        vk_hub_proto::display_safe(reason)
    );
    let gone = match code {
        RefusalCode::NotEnrolled => Some("the hub does not know this node"),
        RefusalCode::Revoked => Some("the hub has removed this node"),
        _ => None,
    };
    if let Some(gone) = gone {
        message.push_str(&format!(
            " — {gone}: remove {} and enroll again with `vk node join`",
            dir.display()
        ));
    }
    if code.is_permanent() {
        anyhow::Error::new(Permanent(message))
    } else if code == RefusalCode::Superseded {
        anyhow::Error::new(Superseded(message))
    } else {
        anyhow!(message)
    }
}

/// Hello → challenge → auth → welcome. Returns the heartbeat interval the hub asked for, in
/// seconds.
async fn handshake(
    ws: &mut Ws,
    node: &Node,
    exported: Option<&[u8; TLS_EXPORTER_LEN]>,
) -> Result<u32> {
    let node_id = &node.enrollment.node_id;
    send(
        ws,
        &NodeMsg::Hello {
            versions: PROTOCOL,
            node_id: node_id.clone(),
            incarnation: node.incarnation.clone(),
            vk_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        CONNECT_TIMEOUT,
    )
    .await?;
    let (version, hub_versions, nonce) = match receive(ws).await? {
        HubMsg::Challenge {
            version,
            versions,
            nonce,
        } => {
            // The highest version both sides speak, and nothing else: a hub — or something
            // between the two — picking a lower one is refused, not followed.
            if !PROTOCOL.accepts_pick(versions, version) {
                bail!(
                    "the hub chose protocol version {version} of {}–{}, not the highest this vk \
                     ({}–{}) shares with it",
                    versions.min,
                    versions.max,
                    PROTOCOL.min,
                    PROTOCOL.max
                );
            }
            let nonce = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::CHALLENGE_LEN }>(&nonce)
                .context("the hub's challenge is malformed")?;
            (version, versions, nonce)
        }
        HubMsg::Refused { code, reason } => return Err(refusal(code, &reason, &node.dir)),
        other => bail!("the hub answered the hello with {}", kind(&other)),
    };
    let channel = match exported {
        Some(exported) => Channel::Tls(exported),
        None => Channel::Plaintext,
    };
    let signature = node.identity.sign(&vk_hub_proto::auth_message(
        &nonce,
        node_id,
        &node.incarnation,
        PROTOCOL,
        hub_versions,
        version,
        channel,
    ));
    send(ws, &NodeMsg::Auth { signature }, CONNECT_TIMEOUT).await?;
    match receive(ws).await? {
        HubMsg::Welcome { heartbeat_secs } => Ok(heartbeat_secs),
        HubMsg::Refused { code, reason } => Err(refusal(code, &reason, &node.dir)),
        other => bail!("the hub answered the auth with {}", kind(&other)),
    }
}

/// Dial the hub's node endpoint: TCP, TLS for an `https` hub, then the WebSocket upgrade.
/// Returns the TLS keying material the auth is bound to, `None` on plain TCP.
async fn connect(
    hub: &str,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<(Ws, Option<[u8; TLS_EXPORTER_LEN]>)> {
    let (io, exported, authority) = dial(hub, tls).await?;
    let scheme = if exported.is_some() { "wss" } else { "ws" };
    let config = WebSocketConfig::default()
        .max_message_size(Some(vk_hub_proto::MAX_MESSAGE))
        .max_frame_size(Some(vk_hub_proto::MAX_MESSAGE));
    let ws_url = format!("{scheme}://{authority}{}", vk_hub_proto::NODE_PATH);
    let (ws, _) = tokio_tungstenite::client_async_with_config(ws_url, io, Some(config))
        .await
        .map_err(|e| match e {
            // The hub's bound on handshakes in flight: transient by design.
            tokio_tungstenite::tungstenite::Error::Http(resp)
                if resp.status()
                    == tokio_tungstenite::tungstenite::http::StatusCode::SERVICE_UNAVAILABLE =>
            {
                anyhow!("{hub} is busy with other nodes' handshakes (HTTP 503)")
            }
            e => anyhow!("opening the WebSocket to {hub}: {e}"),
        })?;
    Ok((ws, exported))
}

/// A connection to the hub's node listener: TCP, and TLS for an `https` hub. Returns it
/// with the TLS keying material a signature on it is bound to — `None` on plain TCP — and
/// the `host:port` it reached.
pub async fn dial(
    hub: &str,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<(Box<dyn Io>, Option<[u8; TLS_EXPORTER_LEN]>, String)> {
    let url = reqwest::Url::parse(hub).with_context(|| format!("parsing the hub URL {hub:?}"))?;
    // Bracketed for an IPv6 literal, which is the form both the socket address and the
    // WebSocket URL want.
    let host = url.host_str().context("the hub URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("the hub URL has no port")?;
    let authority = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&authority)
        .await
        .with_context(|| format!("connecting to {authority}"))?;
    // Heartbeats are small and latency is what a session is judged on.
    tcp.set_nodelay(true).context("setting TCP_NODELAY")?;
    keepalive(&tcp).context("setting TCP keepalives")?;
    let (io, exported): (Box<dyn Io>, _) = match url.scheme() {
        "https" => {
            // An IP literal is verified against the certificate's IP addresses, a name
            // against its DNS names.
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            let name = match bare.parse::<std::net::IpAddr>() {
                Ok(ip) => ip.into(),
                Err(_) => rustls::pki_types::ServerName::try_from(bare.to_string())
                    .with_context(|| format!("{bare:?} is not a valid TLS server name"))?,
            };
            let stream = tokio_rustls::TlsConnector::from(tls.clone())
                .connect(name, tcp)
                .await
                .with_context(|| format!("TLS handshake with {authority}"))?;
            let mut exported = [0u8; TLS_EXPORTER_LEN];
            stream
                .get_ref()
                .1
                .export_keying_material(&mut exported, vk_hub_proto::TLS_EXPORTER_LABEL, None)
                .context("exporting TLS keying material")?;
            (Box::new(stream), Some(exported))
        }
        "http" => (Box::new(tcp), None),
        other => bail!("the hub URL has scheme {other:?}; expected https (or http on loopback)"),
    };
    Ok((io, exported, authority))
}

/// Keepalives on an idle socket and a bound on unacknowledged data on a busy one, so a hub
/// that disappeared behind a dead route is noticed by the kernel too.
fn keepalive(tcp: &tokio::net::TcpStream) -> std::io::Result<()> {
    let fd = tcp.as_raw_fd();
    let secs = |d: Duration| libc::c_int::try_from(d.as_secs()).unwrap_or(libc::c_int::MAX);
    let millis = libc::c_int::try_from(TCP_USER_TIMEOUT.as_millis()).unwrap_or(libc::c_int::MAX);
    for (level, name, value) in [
        (libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1),
        (
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            secs(TCP_KEEPALIVE_IDLE),
        ),
        (
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            secs(TCP_KEEPALIVE_IDLE),
        ),
        (libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 2),
        (libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, millis),
    ] {
        // SAFETY: `fd` is the live socket `tcp` owns; the option value is a c_int that outlives
        // the call, and its size is passed with it.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&raw const value).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

async fn send(ws: &mut Ws, msg: &NodeMsg, within: Duration) -> Result<()> {
    let text = serde_json::to_string(msg).context("encoding a message")?;
    tokio::time::timeout(within, ws.send(Message::text(text)))
        .await
        .map_err(|_| anyhow!("the hub has not taken a message for {}s", within.as_secs()))?
        .map_err(|e| anyhow!("sending to the hub: {e}"))
}

/// The next message of the handshake, within [`CONNECT_TIMEOUT`].
async fn receive(ws: &mut Ws) -> Result<HubMsg> {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            match ws.next().await {
                None => bail!("the hub closed the connection"),
                Some(Err(e)) => bail!("reading from the hub: {e}"),
                Some(Ok(Message::Text(text))) => return parse(text.as_str()),
                Some(Ok(Message::Close(_))) => bail!("the hub closed the session"),
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow!("the hub sent nothing for {CONNECT_TIMEOUT:?}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::WebSocketStream;
    use vk_hub_proto::{RefusalCode, VersionRange};

    type HubSide = WebSocketStream<tokio::net::TcpStream>;

    /// A node enrolled with a hub on a loopback port, with a state dir of its own.
    struct Fixture {
        node: Node,
        gatherer: Gatherer,
        stop: watch::Sender<bool>,
        stopped: watch::Receiver<bool>,
        listener: tokio::net::TcpListener,
        dir: std::path::PathBuf,
    }

    impl Fixture {
        /// Each part on its own, so the hub side and the node side can hold theirs at once.
        #[allow(clippy::type_complexity)]
        fn parts(
            &mut self,
        ) -> (
            &Node,
            &mut Gatherer,
            &mut watch::Receiver<bool>,
            &tokio::net::TcpListener,
            &watch::Sender<bool>,
        ) {
            (
                &self.node,
                &mut self.gatherer,
                &mut self.stopped,
                &self.listener,
                &self.stop,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn fixture(tag: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("vk-node-session-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", dir.display().to_string())).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let (stop, stopped) = watch::channel(false);
        Fixture {
            node: Node {
                dir: dir.clone(),
                enrollment: Enrollment {
                    hub: format!("http://{addr}"),
                    node_id: "ab".repeat(16),
                    ca: false,
                },
                identity: Identity::load_or_create(&dir).unwrap(),
                incarnation: "cd".repeat(16),
                tls: Arc::new(tls),
            },
            // A registry of its own, with no VM in it, not this host's.
            gatherer: Gatherer::spawn_in(Arc::new(cfg), Some(dir.join("vms"))),
            stop,
            stopped,
            listener,
            dir,
        }
    }

    async fn accept(listener: &tokio::net::TcpListener) -> HubSide {
        let (stream, _) = listener.accept().await.unwrap();
        tokio_tungstenite::accept_async(stream).await.unwrap()
    }

    async fn hub_send(ws: &mut HubSide, msg: &HubMsg) {
        ws.send(Message::text(serde_json::to_string(msg).unwrap()))
            .await
            .unwrap();
    }

    async fn hub_receive(ws: &mut HubSide) -> Option<NodeMsg> {
        loop {
            match ws.next().await? {
                Ok(Message::Text(t)) => return Some(serde_json::from_str(t.as_str()).unwrap()),
                Ok(Message::Close(_)) | Err(_) => return None,
                Ok(_) => {}
            }
        }
    }

    /// The hub's half of the handshake, offering `versions` and choosing `version`, checking
    /// the node's auth against its key as a hub would. Returns whether it verified.
    async fn challenge(
        ws: &mut HubSide,
        public_key: &[u8],
        versions: VersionRange,
        version: u32,
    ) -> bool {
        let Some(NodeMsg::Hello {
            versions: node_versions,
            node_id,
            incarnation,
            ..
        }) = hub_receive(ws).await
        else {
            panic!("expected a hello");
        };
        let nonce = [9u8; vk_hub_proto::CHALLENGE_LEN];
        hub_send(
            ws,
            &HubMsg::Challenge {
                version,
                versions,
                nonce: vk_hub_proto::to_hex(&nonce),
            },
        )
        .await;
        let Some(NodeMsg::Auth { signature }) = hub_receive(ws).await else {
            return false;
        };
        let message = vk_hub_proto::auth_message(
            &nonce,
            &node_id,
            &incarnation,
            node_versions,
            versions,
            version,
            Channel::Plaintext,
        );
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
            .verify(&message, &vk_hub_proto::from_hex(&signature).unwrap())
            .is_ok()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_authenticates_reports_and_closes_cleanly_on_stop() {
        let mut f = fixture("ok").await;
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, PROTOCOL.max).await);
            // The first heartbeat goes out at once, the next not for a minute: none is
            // being sent when the stop comes.
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            let (mut inventory, mut heartbeat, mut workloads) = (false, false, false);
            while !(inventory && heartbeat) {
                match hub_receive(&mut ws).await.unwrap() {
                    NodeMsg::Inventory(_) => inventory = true,
                    NodeMsg::Heartbeat(_) => heartbeat = true,
                    NodeMsg::Report(r) => workloads |= r.workloads.is_some(),
                    other => panic!("unexpected {other:?}"),
                }
            }
            // The first heartbeat's workloads went out on a report ahead of it.
            assert!(workloads);
            stop.send(true).unwrap();
            // A close frame, not a dropped socket.
            loop {
                match ws.next().await {
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                    other => panic!("expected a close frame, got {other:?}"),
                }
            }
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        ended.unwrap();
    }

    /// A hub that stops reading leaves a send stuck on a full socket; a stop still ends the
    /// session at once rather than when the send's deadline runs out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stop_is_honored_while_a_send_is_stuck() {
        let mut f = fixture("stuck").await;
        let (node, _, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        // Reports fed by hand, each large and new, so they fill the socket fast.
        let (feed, answers) = mpsc::channel(4);
        let mut gatherer = Gatherer {
            asked: Arc::new(Asked::default()),
            answers,
        };
        let feeder = tokio::spawn(async move {
            for i in 0u32.. {
                let inventory = Inventory {
                    hostname: format!("{i}-{}", "x".repeat(256 * 1024)),
                    ..Default::default()
                };
                if feed
                    .send(Gathered::Inventory(Box::new(inventory)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, PROTOCOL.max).await);
            // A minute's deadline on each send, and nothing read from here on.
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            let _ = done_rx.await;
            drop(ws);
        };
        let node = async {
            let session = run(node, &mut gatherer, stopped);
            tokio::pin!(session);
            tokio::select! {
                ended = &mut session => panic!("the session ended early: {:?}", ended.err()),
                () = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
            stop.send(true).unwrap();
            // Well short of the stuck send's 60s deadline.
            let ended = tokio::time::timeout(Duration::from_secs(10), session).await;
            let _ = done_tx.send(());
            ended
        };
        let (_, ended) = tokio::join!(hub, node);
        feeder.abort();
        ended.expect("the session outlived its stop").unwrap();
    }

    /// The workloads go out on a report once, and not again with every heartbeat while
    /// they stay the same.
    #[tokio::test(flavor = "multi_thread")]
    async fn workloads_are_reported_once_while_they_stay_the_same() {
        let mut f = fixture("workloads").await;
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, PROTOCOL.max).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            let (mut heartbeats, mut with_workloads) = (0, 0);
            while heartbeats < 4 {
                match next_of(&mut ws, Some).await {
                    NodeMsg::Heartbeat(_) => {
                        heartbeats += 1;
                        // As a hub pings, so the node does not give the session up as silent.
                        ws.send(Message::Ping(Vec::new().into())).await.unwrap();
                    }
                    NodeMsg::Report(r) if r.workloads.is_some() => with_workloads += 1,
                    _ => {}
                }
            }
            assert_eq!(with_workloads, 1);
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        ended.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_version_other_than_the_highest_common_one_is_refused() {
        let mut f = fixture("version").await;
        let (node, gatherer, stopped, listener, _) = f.parts();
        let key = node.identity.public_key().to_vec();
        let hub = async {
            let mut ws = accept(listener).await;
            // The hub claims a range the node shares only version 1 of, and picks another.
            let offered = VersionRange {
                min: PROTOCOL.min,
                max: PROTOCOL.max + 1,
            };
            assert!(!challenge(&mut ws, &key, offered, PROTOCOL.max + 1).await);
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        let err = ended.unwrap_err();
        assert!(format!("{err:#}").contains("not the highest"), "{err:#}");
        assert!(!err.is::<Permanent>());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_permanent_refusal_is_reported_as_one_and_a_transient_one_is_not() {
        for (code, permanent) in [
            (RefusalCode::NotEnrolled, true),
            (RefusalCode::BadSignature, true),
            (RefusalCode::Internal, false),
            (RefusalCode::Superseded, false),
        ] {
            let mut f = fixture("refused").await;
            let (node, gatherer, stopped, listener, _) = f.parts();
            let hub = async {
                let mut ws = accept(listener).await;
                hub_receive(&mut ws).await.unwrap();
                hub_send(
                    &mut ws,
                    &HubMsg::Refused {
                        code,
                        reason: "no\u{1b}[2J".into(),
                    },
                )
                .await;
            };
            let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
            let err = ended.unwrap_err();
            assert_eq!(err.is::<Permanent>(), permanent, "{code:?}");
            assert_eq!(
                err.is::<Superseded>(),
                code == RefusalCode::Superseded,
                "{code:?}"
            );
            assert_eq!(
                format!("{err:#}").contains("vk node join"),
                code == RefusalCode::NotEnrolled,
                "{err:#}"
            );
            assert!(!format!("{err:#}").contains('\u{1b}'));
        }
    }

    /// The hub answers 503 to an upgrade with every handshake permit taken: a busy hub, to
    /// be dialed again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hub_answering_503_is_dialed_again() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut f = fixture("busy").await;
        let (node, gatherer, stopped, listener, _) = f.parts();
        let hub = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "the node hung up mid-request");
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        let err = ended.unwrap_err();
        assert!(!err.is::<Permanent>());
        assert!(format!("{err:#}").contains("busy"), "{err:#}");
    }

    /// The next message of a kind `pick` accepts, skipping the rest.
    async fn next_of<T>(ws: &mut HubSide, pick: impl Fn(NodeMsg) -> Option<T>) -> T {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), hub_receive(ws))
                .await
                .expect("the node went quiet")
                .expect("the node closed the session");
            if let Some(t) = pick(msg) {
                return t;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_silent_hub_ends_the_session() {
        let mut f = fixture("silent").await;
        let (node, gatherer, stopped, listener, _) = f.parts();
        let key = node.identity.public_key().to_vec();
        let (quiet_tx, quiet_rx) = tokio::sync::oneshot::channel::<()>();
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, PROTOCOL.max).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            // Holds the socket without reading or pinging until the node gives up.
            let _ = quiet_rx.await;
            drop(ws);
        };
        let node = async {
            let started = std::time::Instant::now();
            let ended = run(node, gatherer, stopped).await;
            let _ = quiet_tx.send(());
            (ended, started.elapsed())
        };
        let (_, (ended, took)) = tokio::join!(hub, node);
        let err = ended.unwrap_err();
        assert!(format!("{err:#}").contains("silent"), "{err:#}");
        assert!(took < Duration::from_secs(10), "{took:?}");
    }
}
