//! One session with the hub: dial, authenticate, then inventory, heartbeats and reports — and
//! from [`STEERING`] on, the hub's desired state and commands, each command acked — until the
//! connection fails or the process is told to stop. [`super::run`] redials.
//!
//! Nothing in the session loop waits on the host: the inventory, heartbeat and workloads are
//! gathered by a [`Gatherer`] task of their own, since a hung mount's `statvfs` or a held
//! ledger lock would otherwise stop the loop from noticing that the hub has gone quiet. The
//! one exception is the node's own state file under `<state_dir>/node`, written before a
//! change the hub asks for is acted on or acked. Every send has a deadline, and the socket
//! carries keepalives and a `TCP_USER_TIMEOUT`, so a peer that vanished without a word ends
//! the session rather than wedging it.

use std::collections::HashMap;
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
    Channel, CommandAck, Heartbeat, HubMsg, Inventory, JOBS, NodeMsg, Outcome, PROTOCOL, Report,
    STEERING, TLS_EXPORTER_LEN, VersionRange,
};

use super::Enrollment;
use super::core::Core;
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

/// The protocol versions this node speaks: placed jobs, tools builds and `[node] runner =
/// "none"` on top of what every peer shares.
pub const NODE_PROTOCOL: VersionRange = VersionRange {
    min: PROTOCOL.min,
    max: vk_hub_proto::RUNNER_NONE,
};

/// How often the node looks at its placed jobs for news: output, stages, results, leases.
const JOBS_EVERY: Duration = Duration::from_millis(250);

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
    /// What the hub asked and the node's own state, which every session reports.
    pub core: Arc<Core>,
    /// Reservations and placed jobs, from protocol version [`JOBS`].
    pub jobs: Arc<super::jobs::Jobs>,
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
        let welcomed = handshake(&mut ws, node, exported.as_ref()).await?;
        anyhow::Ok((ws, welcomed))
    };
    let (mut ws, (asked, version)) = tokio::select! {
        opened = opened => opened?,
        () = stopped(stop) => return Ok(()),
    };
    let _up = Connected::mark(&node.core);
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

    // The node's own state and its unrecorded acks first, so a hub deciding what to resend
    // decides on them.
    let steering = version >= STEERING;
    let mut changes = node.core.subscribe();
    let mut told = Told::default();
    if steering {
        for msg in told.news(&node.core, None, version) {
            if !send_unless_stopped(&mut ws, &msg, heartbeat, stop).await? {
                return Ok(());
            }
        }
    }
    // Placed jobs: everything held, once per session, before the hub places anything here.
    let placing = version >= JOBS;
    if placing {
        let jobs = node.jobs.clone();
        let held = tokio::task::spawn_blocking(move || jobs.held(std::time::Instant::now()))
            .await
            .context("reading the placed jobs")?;
        if !send_unless_stopped(&mut ws, &NodeMsg::Job(held), heartbeat, stop).await? {
            return Ok(());
        }
    }
    let mut job_tick = tokio::time::interval(JOBS_EVERY);
    job_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    gatherer.drain();
    gatherer.request(Ask::Inventory);
    let mut sent_inventory: Option<Inventory> = None;
    // The workloads last gathered, which every report from the first heartbeat on carries;
    // the hub keeps its previous list through the reports before it.
    let mut workloads: Option<Listed> = None;
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
            _ = job_tick.tick(), if placing => {
                for msg in poll_jobs(node).await? {
                    if !send_unless_stopped(&mut ws, &msg, heartbeat, stop).await? {
                        return Ok(());
                    }
                }
            }
            _ = recheck.tick() => gatherer.request(Ask::Inventory),
            Ok(()) = changes.changed(), if steering => {
                for msg in told.news(&node.core, workloads.as_ref(), version) {
                    if !send_unless_stopped(&mut ws, &msg, heartbeat, stop).await? {
                        return Ok(());
                    }
                }
            }
            Some(gathered) = gatherer.answers.recv() => {
                let mut msgs = Vec::with_capacity(2);
                match gathered {
                    Gathered::Heartbeat(hb, listed) => {
                        // The report first, so the heartbeat's readings land on the list
                        // they are for.
                        workloads = Some(listed);
                        msgs.extend(told.news(&node.core, workloads.as_ref(), version));
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
                    Some(Ok(Message::Text(text))) => {
                        let msg = parse(text.as_str())?;
                        if let HubMsg::Job(job) = msg {
                            if !placing {
                                bail!("the hub sent a job message in a version-{version} session");
                            }
                            let mut replies = handle_job(node, job).await?;
                            replies.extend(poll_jobs(node).await?);
                            for reply in &replies {
                                if !send_unless_stopped(&mut ws, reply, heartbeat, stop).await? {
                                    return Ok(());
                                }
                            }
                            continue;
                        }
                        // A command is answered on every delivery, from the journal when it
                        // came before.
                        if let Some(ack) = handle(msg, node, version).await? {
                            told.acks.insert(ack.id.clone(), ack.outcome.clone());
                            if !send_unless_stopped(&mut ws, &NodeMsg::Ack(ack), heartbeat, stop)
                                .await?
                            {
                                return Ok(());
                            }
                        }
                    }
                    // tungstenite answers pings itself; each one shows the hub is alive.
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}

/// A job message from the hub, answered from the node's ledger and job journal.
async fn handle_job(node: &Node, msg: vk_hub_proto::dispatch::HubJobMsg) -> Result<Vec<NodeMsg>> {
    let placed = node.core.placed();
    let intake = super::jobs::Intake {
        ready: super::jobs::ready(node.core.state(), *node.core.acquire().borrow()),
        ceiling: node.core.hub_ceiling(),
        runner: placed.runner.is_some(),
        limit: placed.limit,
    };
    let jobs = node.jobs.clone();
    let replies =
        tokio::task::spawn_blocking(move || jobs.handle(msg, intake, std::time::Instant::now()))
            .await
            .context("handling a job message")?;
    Ok(replies.into_iter().map(NodeMsg::Job).collect())
}

/// What the placed jobs have to tell the hub now.
async fn poll_jobs(node: &Node) -> Result<Vec<NodeMsg>> {
    let quarantined = node.core.state() == vk_hub_proto::NodeState::Quarantined;
    let jobs = node.jobs.clone();
    let msgs =
        tokio::task::spawn_blocking(move || jobs.poll(std::time::Instant::now(), quarantined))
            .await
            .context("following the placed jobs")?;
    Ok(msgs.into_iter().map(NodeMsg::Job).collect())
}

/// Marks the hub reached for as long as it lives: from the welcome to the session's end.
struct Connected<'a>(&'a Core);

impl<'a> Connected<'a> {
    fn mark(core: &'a Core) -> Self {
        core.set_connected(true);
        Connected(core)
    }
}

impl Drop for Connected<'_> {
    fn drop(&mut self) {
        self.0.set_connected(false);
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

/// What this session has told the hub, so a change goes out once and an ack again only when
/// its outcome moved on or a new session starts.
#[derive(Default)]
struct Told {
    report: Option<Report>,
    acks: HashMap<String, Outcome>,
}

impl Told {
    /// Return and mark as sent a changed report (`workloads` and steering state), followed
    /// by unrecorded acks whose current outcomes this session has not sent. Below [`STEERING`],
    /// include only workloads and no acks; below the later versions, leave out what their hubs
    /// cannot read. Omit empty reports.
    fn news(&mut self, core: &Core, workloads: Option<&Listed>, version: u32) -> Vec<NodeMsg> {
        let mut report = Report {
            workloads: workloads.map(|w| w.workloads.clone()),
            workloads_omitted: workloads.map_or(0, |w| w.omitted),
            ..core.report()
        };
        if version < STEERING {
            report = report.without_steering();
        } else {
            if version < vk_hub_proto::TOOLS {
                report = report.without_tools();
            }
            if version < vk_hub_proto::RUNNER_NONE {
                report = report.without_runner_none();
            }
        }
        let mut msgs = Vec::new();
        if report != Report::default() && self.report.as_ref() != Some(&report) {
            self.report = Some(report.clone());
            msgs.push(NodeMsg::Report(report));
        }
        if version >= STEERING {
            for ack in core.unrecorded() {
                if self.acks.get(&ack.id) != Some(&ack.outcome) {
                    self.acks.insert(ack.id.clone(), ack.outcome.clone());
                    msgs.push(NodeMsg::Ack(ack));
                }
            }
        }
        msgs
    }
}

/// A message from the hub inside a session at `version`. Desired state and commands go through
/// the node's persisted state before anything follows them. Returns a command's ack, to be
/// sent at once; the report the change makes goes out through [`Told::news`].
async fn handle(msg: HubMsg, node: &Node, version: u32) -> Result<Option<CommandAck>> {
    match msg {
        HubMsg::Refused { code, reason } => Err(refusal(code, &reason, &node.dir)),
        HubMsg::Challenge { .. } | HubMsg::Welcome { .. } => {
            bail!("the hub repeated its handshake inside a session")
        }
        HubMsg::Desired(_) | HubMsg::Command(_) | HubMsg::Recorded(_) if version < STEERING => {
            bail!("the hub sent {} in a version-{version} session", kind(&msg))
        }
        HubMsg::Job(_) => bail!("the hub sent {} in a version-{version} session", kind(&msg)),
        HubMsg::Desired(desired) => {
            let generation = desired.generation;
            if persist(&node.core, move |core| core.apply_desired(desired)).await? {
                say!("applied desired state generation {generation}");
            }
            Ok(None)
        }
        HubMsg::Command(command) => {
            if !vk_hub_proto::valid_id(&command.id) {
                bail!("the hub sent a command with a malformed ID");
            }
            let op = format!("{:?}", command.op);
            let now = now_secs();
            let ack = persist(&node.core, move |core| core.command(command, now)).await?;
            say!("command {} ({op}): {:?}", ack.id, ack.outcome);
            Ok(Some(ack))
        }
        HubMsg::Recorded(ack) => {
            let now = now_secs();
            persist(&node.core, move |core| core.recorded(&ack, now)).await?;
            Ok(None)
        }
    }
}

/// Seconds since the Unix epoch, which command expiries count in.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Run `f` on the core off the runtime: it writes the node's state file.
async fn persist<T: Send + 'static>(
    core: &Arc<Core>,
    f: impl FnOnce(&Core) -> Result<T> + Send + 'static,
) -> Result<T> {
    let core = core.clone();
    tokio::task::spawn_blocking(move || f(&core))
        .await
        .context("persisting the node state")?
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
        HubMsg::Desired(_) => "desired state",
        HubMsg::Command(_) => "a command",
        HubMsg::Recorded(_) => "a record of an ack",
        HubMsg::Job(_) => "a job message",
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
/// seconds, and the protocol version of the session.
async fn handshake(
    ws: &mut Ws,
    node: &Node,
    exported: Option<&[u8; TLS_EXPORTER_LEN]>,
) -> Result<(u32, u32)> {
    let node_id = &node.enrollment.node_id;
    send(
        ws,
        &NodeMsg::Hello {
            versions: NODE_PROTOCOL,
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
            if !NODE_PROTOCOL.accepts_pick(versions, version) {
                bail!(
                    "the hub chose protocol version {version} of {}–{}, not the highest this vk \
                     ({}–{}) shares with it",
                    versions.min,
                    versions.max,
                    NODE_PROTOCOL.min,
                    NODE_PROTOCOL.max
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
        NODE_PROTOCOL,
        hub_versions,
        version,
        channel,
    ));
    send(ws, &NodeMsg::Auth { signature }, CONNECT_TIMEOUT).await?;
    match receive(ws).await? {
        HubMsg::Welcome { heartbeat_secs } => Ok((heartbeat_secs, version)),
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
    use vk_hub_proto::{Operation, RefusalCode, VersionRange};

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
        let state = format!("state_dir = {:?}\n", dir.display().to_string());
        let cfg: Config = toml::from_str(&state).unwrap();
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
                core: Core::open(
                    &dir,
                    super::super::state::Issuer {
                        hub: format!("http://{addr}"),
                        node_id: "ab".repeat(16),
                    },
                    super::super::core::Runner::External,
                )
                .unwrap(),
                jobs: super::super::jobs::for_test(
                    &dir,
                    toml::from_str(&state).unwrap(),
                    Some(8192),
                ),
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

    /// A node with no runner says so to a hub from [`vk_hub_proto::RUNNER_NONE`], and to an
    /// older one, which could not read that, says its runner is external.
    #[test]
    fn a_node_with_no_runner_tells_an_older_hub_its_runner_is_external() {
        let dir = std::env::temp_dir().join(format!("vk-node-told-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let issuer = super::super::state::Issuer {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
        };
        let core = Core::open(&dir, issuer, super::super::core::Runner::None).unwrap();
        let told = |version| match Told::default().news(&core, None, version).as_slice() {
            [NodeMsg::Report(r)] => r.runner,
            other => panic!("{other:?}"),
        };
        assert_eq!(NODE_PROTOCOL.max, vk_hub_proto::RUNNER_NONE);
        assert_eq!(
            told(vk_hub_proto::RUNNER_NONE),
            Some(vk_hub_proto::RunnerMode::None)
        );
        for older in [STEERING, JOBS, vk_hub_proto::TOOLS] {
            assert_eq!(told(older), Some(vk_hub_proto::RunnerMode::External));
        }
        let _ = std::fs::remove_dir_all(&dir);
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

    /// Workloads are reported once, then again only when they change, not on every heartbeat.
    #[tokio::test(flavor = "multi_thread")]
    async fn workloads_are_reported_once_while_they_stay_the_same() {
        let mut f = fixture("workloads").await;
        let (node, _, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        // Feed heartbeats manually, one at a time, so deadlines do not depend on host read speed.
        let (feed, answers) = mpsc::channel(1);
        let asked = Arc::new(Asked::default());
        let mut gatherer = Gatherer {
            asked: asked.clone(),
            answers,
        };
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, PROTOCOL.max).await);
            // Allow minutes of silence so the session stays open without hub pings.
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            // Feed after the inventory request: the session first drains earlier answers
            // as belonging to a past session.
            asked.wake.notified().await;
            let same = Listed::default();
            let changed = Listed {
                omitted: 1,
                ..Listed::default()
            };
            for (workloads, reported) in [
                (&same, true),
                (&same, false),
                (&same, false),
                (&changed, true),
            ] {
                let beat = Gathered::Heartbeat(Heartbeat::default(), workloads.clone());
                feed.send(beat).await.unwrap();
                // Reports may also carry the node's runner state; count only those with workloads.
                let mut with_workloads = Vec::new();
                loop {
                    match next_of(&mut ws, Some).await {
                        NodeMsg::Heartbeat(_) => break,
                        NodeMsg::Report(r) if r.workloads.is_some() => with_workloads.push(r),
                        _ => {}
                    }
                }
                assert_eq!(with_workloads.len(), usize::from(reported));
                if let Some(r) = with_workloads.first() {
                    assert_eq!(r.workloads_omitted, workloads.omitted);
                }
            }
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, &mut gatherer, stopped));
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
                min: NODE_PROTOCOL.min,
                max: NODE_PROTOCOL.max + 1,
            };
            assert!(!challenge(&mut ws, &key, offered, NODE_PROTOCOL.max + 1).await);
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        let err = ended.unwrap_err();
        assert!(format!("{err:#}").contains("not the highest"), "{err:#}");
        assert!(!err.is::<Permanent>());
    }

    const V1: VersionRange = VersionRange { min: 1, max: 1 };

    /// A hub speaking only version 1 gets a version-1 session: reports without steering, and
    /// no ack, whatever the node has applied and journaled.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_version_1_hub_gets_a_version_1_session() {
        let mut f = fixture("v1").await;
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        let HubMsg::Desired(desired) = desired() else {
            unreachable!()
        };
        node.core.apply_desired(desired).unwrap();
        node.core.command(command(Operation::Undrain), 1).unwrap();
        assert_eq!(node.core.unrecorded().len(), 1);
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, V1, 1).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            let (mut report, mut heartbeat) = (None, false);
            while !(report.is_some() && heartbeat) {
                match next_of(&mut ws, Some).await {
                    NodeMsg::Report(r) => report = Some(r),
                    NodeMsg::Heartbeat(_) => heartbeat = true,
                    NodeMsg::Inventory(_) => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
            let report = report.unwrap();
            assert!(report.workloads.is_some());
            assert_eq!(report.clone().without_steering(), report);
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        ended.unwrap();
    }

    /// Steering in a version-1 session breaks the protocol, and ends the session.
    #[tokio::test(flavor = "multi_thread")]
    async fn desired_state_in_a_version_1_session_ends_it() {
        let mut f = fixture("v1-desired").await;
        let (node, gatherer, stopped, listener, _) = f.parts();
        let key = node.identity.public_key().to_vec();
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, V1, 1).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            hub_send(&mut ws, &desired()).await;
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        let err = ended.unwrap_err();
        assert!(
            format!("{err:#}").contains("desired state in a version-1 session"),
            "{err:#}"
        );
        assert!(!err.is::<Permanent>());
    }

    /// A second handshake inside a session breaks the protocol, and ends the session.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_repeated_handshake_ends_the_session() {
        let mut f = fixture("rehandshake").await;
        let (node, gatherer, stopped, listener, _) = f.parts();
        let key = node.identity.public_key().to_vec();
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, STEERING).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        let err = ended.unwrap_err();
        assert!(
            format!("{err:#}").contains("repeated its handshake inside a session"),
            "{err:#}"
        );
    }

    fn command(op: Operation) -> vk_hub_proto::Command {
        vk_hub_proto::Command {
            id: "ef".repeat(16),
            expires_at: u64::MAX,
            op,
        }
    }

    fn ack_of(msg: NodeMsg) -> Option<CommandAck> {
        match msg {
            NodeMsg::Ack(ack) => Some(ack),
            _ => None,
        }
    }

    fn report_of(msg: NodeMsg) -> Option<Report> {
        match msg {
            NodeMsg::Report(r) => Some(r),
            _ => None,
        }
    }

    /// At version 2, desired state is applied and shown on the report, and a command is
    /// journaled and acked; the ack comes again in the next session until the hub records
    /// it, and the command delivered again is answered from the journal, not run again.
    #[tokio::test(flavor = "multi_thread")]
    async fn commands_are_applied_once_and_acked_until_recorded() {
        let mut f = fixture("steer").await;
        // An external runner of its own: it may go on taking jobs past a stop.
        f.node.core.set_placed(vk_hub_proto::PlacedIntake {
            runner: Some("gitlab-runner.service runs the vk custom executor".into()),
            ..vk_hub_proto::PlacedIntake::default()
        });
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        // A reset, refused with an external runner: still journaled, and its outcome still
        // repeated until recorded.
        let reset = command(Operation::Reset { images: false });
        let hub = async {
            // First session: desired state and a reset; the hub records nothing.
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, STEERING).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            let first = next_of(&mut ws, report_of).await;
            assert_eq!(first.applied_generation(), None);
            assert_eq!(first.state, Some(vk_hub_proto::NodeState::Ready));
            hub_send(&mut ws, &desired()).await;
            let applied = next_of(&mut ws, |m| report_of(m).filter(|r| r.applied.is_some())).await;
            assert_eq!(applied.applied_generation(), Some(1));
            // A stop of acquisition this node cannot carry out, said so.
            assert_eq!(applied.unsupported.len(), 1);
            hub_send(&mut ws, &HubMsg::Command(reset.clone())).await;
            let ack = next_of(&mut ws, ack_of).await;
            assert!(matches!(ack.outcome, Outcome::Refused { .. }), "{ack:?}");
            drop(ws);

            // Second session: the unrecorded ack comes again unasked, and the command
            // redelivered is answered with it, not run again.
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, STEERING).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            let report = next_of(&mut ws, report_of).await;
            assert_eq!(report.applied_generation(), Some(1));
            assert_eq!(next_of(&mut ws, ack_of).await, ack);
            hub_send(&mut ws, &HubMsg::Command(reset.clone())).await;
            assert_eq!(next_of(&mut ws, ack_of).await, ack);
            hub_send(&mut ws, &HubMsg::Recorded(ack.clone())).await;
            for _ in 0..100 {
                if node.core.unrecorded().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let node_side = async {
            let first = run(node, gatherer, stopped).await;
            assert!(first.is_err(), "the hub dropped the first session");
            run(node, gatherer, stopped).await
        };
        let (_, ended) = tokio::join!(hub, node_side);
        ended.unwrap();
        // Recorded, so a third session would have nothing to repeat; journaled once.
        assert!(node.core.unrecorded().is_empty());
        assert_eq!(node.core.hub_ceiling(), Some(2));
        let journal = super::super::state::Persisted::load(&node.dir)
            .unwrap()
            .journal;
        assert_eq!(journal.len(), 1);
    }

    /// An update the node could not install is refused with the reason, and the node stays
    /// ready; the hub counts as reached for as long as the session lasts, which is what a
    /// release on trial waits for.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_update_the_node_cannot_install_is_refused_and_the_session_marks_the_hub_reached() {
        let mut f = fixture("update").await;
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        let connected = node.core.connected();
        assert!(!*connected.borrow());
        let update = command(Operation::Update {
            version: "0.84.0".into(),
            sha256: "ab".repeat(vk_hub_proto::SHA256_LEN),
            size: 1,
            signature: None,
            force: true,
            within_secs: None,
        });
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, STEERING).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            next_of(&mut ws, report_of).await;
            assert!(*connected.borrow());
            hub_send(&mut ws, &HubMsg::Command(update)).await;
            let ack = next_of(&mut ws, ack_of).await;
            assert!(
                matches!(&ack.outcome, Outcome::Refused { reason } if reason.contains("installed vk")),
                "{ack:?}"
            );
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        ended.unwrap();
        assert!(!*connected.borrow());
        let report = node.core.report();
        assert_eq!(report.state, Some(vk_hub_proto::NodeState::Ready));
        assert_eq!(report.update, None);
    }

    /// A tools build is accepted in a version-4 session and its progress reported there; a
    /// session below it gets the report without the progress.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tools_build_is_taken_and_reported_from_version_4_only() {
        let mut f = fixture("tools").await;
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        let build = command(Operation::Tools {
            version: "2026.10".into(),
            sha256: "ab".repeat(vk_hub_proto::SHA256_LEN),
            size: 4096,
        });
        let v4 = VersionRange {
            min: 1,
            max: vk_hub_proto::TOOLS,
        };
        let v3 = VersionRange { min: 1, max: JOBS };
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, v4, vk_hub_proto::TOOLS).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            next_of(&mut ws, report_of).await;
            hub_send(&mut ws, &HubMsg::Command(build.clone())).await;
            assert_eq!(next_of(&mut ws, ack_of).await.outcome, Outcome::Accepted);
            let report = next_of(&mut ws, |m| report_of(m).filter(|r| r.tools.is_some())).await;
            let progress = report.tools.unwrap();
            assert_eq!(
                (progress.command.as_str(), progress.phase),
                (build.id.as_str(), vk_hub_proto::ToolsPhase::Downloading)
            );
            drop(ws);

            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, v3, JOBS).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            let report = next_of(&mut ws, report_of).await;
            assert_eq!(report.state, Some(vk_hub_proto::NodeState::Ready));
            assert_eq!(report.tools, None);
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let node_side = async {
            let first = run(node, gatherer, stopped).await;
            assert!(first.is_err(), "the hub dropped the first session");
            run(node, gatherer, stopped).await
        };
        let (_, ended) = tokio::join!(hub, node_side);
        ended.unwrap();
        assert!(node.core.persisted().tools.is_some());
    }

    /// With a managed runner, a drain stops it and is reported draining until the runner has
    /// exited, then drained, and its ack moves from accepted to done.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_drain_with_a_managed_runner_is_reported_until_drained() {
        use vk_hub_proto::{Acquisition, NodeState, RunnerState};
        let mut f = fixture("managed").await;
        let spec = super::super::runner::stub("session-drain");
        let (runner_tx, runner) = watch::channel(RunnerState::Stopped);
        f.node.core = Core::open(
            &f.dir,
            super::super::state::Issuer {
                hub: f.node.enrollment.hub.clone(),
                node_id: f.node.enrollment.node_id.clone(),
            },
            super::super::core::Runner::Managed(runner),
        )
        .unwrap();
        let (halt, halted) = watch::channel(false);
        let (_abort, aborted) = watch::channel(false);
        let supervisor = tokio::spawn(super::super::runner::supervise(
            spec.clone(),
            super::super::runner::Signals {
                allowed: f.node.core.acquire(),
                halt: halted,
                abort: aborted,
            },
            runner_tx,
        ));
        let cfg: Arc<Config> = Arc::new(
            toml::from_str(&format!(
                "state_dir = {:?}\n[executor.schedule]\nmax_concurrency = 2\n",
                f.dir.display().to_string()
            ))
            .unwrap(),
        );
        let control = tokio::spawn(f.node.core.clone().control(
            cfg,
            Duration::from_secs(3600),
            f.stopped.clone(),
        ));
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        let drain = command(Operation::Drain);
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, STEERING).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
            let running = next_of(&mut ws, |m| {
                report_of(m).filter(|r| r.runner_state == Some(RunnerState::Running))
            })
            .await;
            assert_eq!(running.state, Some(NodeState::Ready));
            assert_eq!(running.runner, Some(vk_hub_proto::RunnerMode::Managed));
            assert_eq!(running.acquisition, Some(Acquisition::Run));
            // Not before the stub handles SIGQUIT.
            let log = super::super::runner::started_log(&spec);
            for _ in 0..200 {
                if log.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            hub_send(&mut ws, &HubMsg::Command(drain.clone())).await;
            assert_eq!(next_of(&mut ws, ack_of).await.outcome, Outcome::Accepted);
            // The stub holds on to its jobs until told to finish: draining, the runner
            // quitting, acquisition still running.
            let draining = next_of(&mut ws, |m| {
                report_of(m)
                    .filter(|r| r.drain.is_some() && r.runner_state == Some(RunnerState::Quitting))
            })
            .await;
            assert_eq!(draining.state, Some(NodeState::Draining));
            assert!(!draining.drain.unwrap().runner_stopped);
            assert_eq!(draining.acquisition, Some(Acquisition::Run));
            super::super::runner::finish(&spec);
            // The drained report and the done ack, in whichever order a report read as the
            // drain finished puts them.
            let (mut drained, mut done) = (None, None);
            while drained.is_none() || done.is_none() {
                match next_of(&mut ws, Some).await {
                    NodeMsg::Report(r) if r.state == Some(NodeState::Drained) => drained = Some(r),
                    NodeMsg::Ack(ack) if ack.outcome != Outcome::Accepted => done = Some(ack),
                    _ => {}
                }
            }
            let drained = drained.unwrap();
            assert_eq!(drained.drain, None);
            assert_eq!(drained.runner_state, Some(RunnerState::Stopped));
            assert_eq!(drained.acquisition, Some(Acquisition::Stop));
            let done = done.unwrap();
            assert_eq!(done.id, drain.id);
            assert_eq!(done.outcome, Outcome::Done);
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        ended.unwrap();
        control.await.unwrap();
        halt.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), supervisor)
            .await
            .unwrap()
            .unwrap();
        let _ = std::fs::remove_dir_all(&spec.dir);
    }

    fn desired() -> HubMsg {
        HubMsg::Desired(vk_hub_proto::DesiredState {
            generation: 1,
            ceiling: Some(2),
            acquisition: vk_hub_proto::Acquisition::Stop,
        })
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

    /// A version-3 hub, as the contract has it: `held` first; an offer granted from the
    /// ledger; a job started on it, its output streamed and acked, its result repeated until
    /// recorded. A version-2 hub meanwhile gets no job message at all (the tests above).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_version_3_hub_places_a_job_and_gets_its_output_and_result() {
        use super::super::jobs::tests::{envelope, hex, spec};
        use vk_hub_proto::dispatch::{HubJobMsg, JobStart, NodeJobMsg, OfferReply};
        let mut f = fixture("v3").await;
        let (node, gatherer, stopped, listener, stop) = f.parts();
        let key = node.identity.public_key().to_vec();
        let jobs_dir = node.dir.join("jobs").join(hex("b"));
        let hub = async {
            let mut ws = accept(listener).await;
            let v3 = VersionRange { min: 1, max: JOBS };
            assert!(challenge(&mut ws, &key, v3, JOBS).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            let held = next_of(&mut ws, |m| match m {
                NodeMsg::Job(NodeJobMsg::Held(h)) => Some(h),
                _ => None,
            })
            .await;
            assert!(held.jobs.is_empty() && held.reservations.is_empty());
            let job = |m: HubJobMsg| HubMsg::Job(m);
            hub_send(
                &mut ws,
                &job(HubJobMsg::Offer {
                    reservation: hex("a"),
                    envelope: envelope(4096),
                    lease_secs: 90,
                }),
            )
            .await;
            let reply = next_of(&mut ws, |m| match m {
                NodeMsg::Job(NodeJobMsg::OfferReply { reply, .. }) => Some(reply),
                _ => None,
            })
            .await;
            assert_eq!(reply, OfferReply::Accepted { lease_secs: 90 });
            hub_send(
                &mut ws,
                &job(HubJobMsg::Start(Box::new(JobStart {
                    job: hex("b"),
                    reservation: Some(hex("a")),
                    envelope: envelope(4096),
                    spec: spec(4242),
                }))),
            )
            .await;
            let mut output = Vec::new();
            let result = loop {
                match next_of(&mut ws, |m| match m {
                    NodeMsg::Job(j) => Some(j),
                    _ => None,
                })
                .await
                {
                    NodeJobMsg::Output { offset, data, .. } => {
                        assert_eq!(offset, output.len() as u64, "a gap in the output");
                        output.extend(vk_hub_proto::from_base64(&data).unwrap());
                        hub_send(
                            &mut ws,
                            &job(HubJobMsg::OutputAck {
                                job: hex("b"),
                                offset: output.len() as u64,
                            }),
                        )
                        .await;
                    }
                    NodeJobMsg::Result { result, .. } => break result,
                    _ => {}
                }
            };
            assert_eq!(result.output_len, output.len() as u64);
            assert!(result.failure.is_none());
            assert!(
                String::from_utf8(output)
                    .unwrap()
                    .contains("GitLab job 4242")
            );
            hub_send(&mut ws, &job(HubJobMsg::Recorded { job: hex("b") })).await;
            // Recorded: the job's journal goes.
            for _ in 0..100 {
                if !jobs_dir.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(!jobs_dir.exists());
            stop.send(true).unwrap();
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        ended.unwrap();
    }

    /// A job message in a session below version 3 breaks the protocol.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_job_message_below_version_3_ends_the_session() {
        let mut f = fixture("v2-job").await;
        let (node, gatherer, stopped, listener, _) = f.parts();
        let key = node.identity.public_key().to_vec();
        let hub = async {
            let mut ws = accept(listener).await;
            assert!(challenge(&mut ws, &key, PROTOCOL, STEERING).await);
            hub_send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 60 }).await;
            hub_send(
                &mut ws,
                &HubMsg::Job(vk_hub_proto::dispatch::HubJobMsg::Recorded {
                    job: "ab".repeat(16),
                }),
            )
            .await;
            while hub_receive(&mut ws).await.is_some() {}
        };
        let (_, ended) = tokio::join!(hub, run(node, gatherer, stopped));
        let err = ended.unwrap_err();
        assert!(format!("{err:#}").contains("version-2"), "{err:#}");
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
