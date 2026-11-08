//! One node's WebSocket session: authenticate against the key pinned at enrollment with
//! hello/challenge/auth, then store inventory, heartbeats and reports until it disconnects.
//! From version [`STEERING`], also send desired state and commands; from version [`JOBS`],
//! reservations and jobs ([`crate::jobs`]); from version [`vk_hub_proto::TOOLS`], tools builds;
//! from version [`vk_hub_proto::RUNNER_NONE`], reports of nodes that run no gitlab-runner; from
//! version [`LIVE_EGRESS`], running jobs' egress reports; from version [`REGISTRY_ACCESS`], the
//! node's own registry token, renewed before it expires.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::dispatch::NodeJobMsg;
use vk_hub_proto::{
    CHALLENGE_LEN, Channel, Heartbeat, HubMsg, Inventory, JOBS, LIVE_EGRESS, NodeMsg,
    PUBLIC_KEY_LEN, REGISTRY_ACCESS, RefusalCode, Report, SIGNATURE_LEN, STEERING, VersionRange,
    from_hex_lower,
};

use crate::server::{Ending, Exported, HEARTBEAT, HEARTBEAT_SECS, Hub};
use crate::store::NotEnrolled;

pub(crate) type Ws = WebSocketStream<TokioIo<Upgraded>>;

/// How long a node has for each handshake step. Signing a nonce takes microseconds; a peer
/// this slow is not a node doing its job, and holding the socket for it costs a descriptor.
/// Short under test, so the timeout itself can be tested.
#[cfg(not(test))]
pub(crate) const HANDSHAKE_STEP: Duration = crate::server::PRE_AUTH_TIMEOUT;
#[cfg(test)]
pub(crate) const HANDSHAKE_STEP: Duration = Duration::from_secs(1);

/// The protocol versions this hub speaks: [`vk_hub_proto::PROTOCOL`]'s, [`JOBS`],
/// [`vk_hub_proto::TOOLS`], [`vk_hub_proto::RUNNER_NONE`], [`LIVE_EGRESS`] and
/// [`REGISTRY_ACCESS`]. A node offering less negotiates the highest version both speak.
pub const PROTOCOL: VersionRange = VersionRange {
    min: vk_hub_proto::PROTOCOL.min,
    max: REGISTRY_ACCESS,
};

/// When a node's own registry token is renewed: this far into its life, give or take
/// [`RENEW_JITTER`], so that nodes connected together do not all renew together.
const RENEW_AFTER: Duration = Duration::from_secs(45 * 60);
const RENEW_JITTER: Duration = Duration::from_secs(5 * 60);

/// How soon access the hub could not mint, or that waits on a registry, is looked at again.
const ACCESS_RETRY: Duration = Duration::from_secs(60);

/// How often a node's access is looked at again with nothing said to have changed: a registry
/// that stopped taking nodes' tokens tells no session.
const ACCESS_RECHECK: Duration = Duration::from_secs(5 * 60);

/// The versions of a relay's session over HTTP/1.1: every one but
/// [`CONNECTION`](vk_hub_proto::gitlab::CONNECTION), which only HTTP/2 carries.
pub(crate) const RELAY_HTTP1: VersionRange = VersionRange {
    min: vk_hub_proto::gitlab::PROTOCOL.min,
    max: vk_hub_proto::gitlab::RUNNERS,
};

/// The version of a relay's session over its HTTP/2 connection: that one alone, so a relay there
/// speaks version 5's notices instead of long polls, and one served unsigned has authenticated
/// its connection.
pub(crate) const RELAY_HTTP2: VersionRange = VersionRange {
    min: vk_hub_proto::gitlab::CONNECTION,
    max: vk_hub_proto::gitlab::CONNECTION,
};

/// What a node removed from the hub is told.
const REMOVED: &str = "this node was removed from the hub";

/// Run the session on `ws` to its end, logging why it ended. `permit` is the handshake's
/// place among those in progress, given back once the node is welcomed or turned away.
pub async fn run(
    mut ws: Ws,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
    permit: OwnedSemaphorePermit,
) {
    let node = match handshake(&mut ws, &hub, exported, PeerKind::Node, PROTOCOL).await {
        Ok(node) => node,
        Err(r) => return turn_away(&mut ws, peer, r).await,
    };
    // Registered before it is recorded: a removal from here on either finds the session to
    // revoke or leaves no row to record it in.
    let (session, ending) = hub.open_session(&node.id);
    let welcomed = welcome(&mut ws, &hub, &node, session).await;
    drop(permit);
    if let Err(r) = welcomed {
        hub.close_session(&node.id, session);
        return turn_away(&mut ws, peer, r).await;
    }
    eprintln!(
        "vk-hub: {peer}: node {} ({}) connected at protocol version {}, {}",
        node.id,
        node.hostname,
        node.version,
        match &node.previous_incarnation {
            Some(prev) if *prev == node.incarnation => "reconnected".to_string(),
            Some(_) => format!("restarted as incarnation {}", node.incarnation),
            None => format!("first session, incarnation {}", node.incarnation),
        }
    );
    let jobs = crate::jobs::open_link(&hub, &node.id, session, node.version).await;
    let ended = serve(&mut ws, &hub, &node, session, &ending, jobs).await;
    hub.close_session(&node.id, session);
    crate::jobs::close_link(&hub, &node.id, session).await;
    match ended {
        Ok(why) => eprintln!("vk-hub: {peer}: node {} disconnected: {why}", node.id),
        Err(e) => {
            eprintln!("vk-hub: {peer}: node {} session ended: {e:#}", node.id);
            // Bounded: a peer that stopped reading would hold the close forever. Best effort,
            // like `refuse`.
            let _ = tokio::time::timeout(HANDSHAKE_STEP, ws.close(None)).await;
        }
    }
}

/// Log why a handshake ended and, unless the peer is gone, tell it.
pub(crate) async fn turn_away(ws: &mut Ws, peer: SocketAddr, r: Refusal) {
    let why = r.detail.as_deref().unwrap_or(&r.reason);
    if r.gone {
        eprintln!("vk-hub: {peer}: handshake ended: {why}");
        return;
    }
    eprintln!("vk-hub: {peer}: refused a session: {why}");
    refuse(ws, r.code, &r.reason).await;
}

/// End the stream of a session over once what was sent on it is on its way. On a relay's
/// HTTP/2 connection a stream dropped while still open is reset, which discards the data it
/// still buffers — a refusal, or the close after it — so the peer would read an error instead.
/// Ending it first sends that data, then the end. Best effort, bounded as a step.
pub(crate) async fn finish(mut ws: Ws) {
    use tokio::io::AsyncWriteExt;
    let _ = tokio::time::timeout(HANDSHAKE_STEP, ws.get_mut().shutdown()).await;
}

/// Tell the peer why and close. Best effort: the peer is being turned away, and a failure to
/// tell it so leaves nothing to clean up.
async fn refuse(ws: &mut Ws, code: RefusalCode, reason: &str) {
    let msg = HubMsg::Refused {
        code,
        reason: reason.to_string(),
    };
    let _ = tokio::time::timeout(HANDSHAKE_STEP, async {
        let _ = send(ws, &msg).await;
        let _ = ws.close(None).await;
    })
    .await;
}

/// An authenticated peer: a node, or a registry ([`crate::registries`]).
pub(crate) struct Peer {
    pub(crate) id: String,
    pub(crate) incarnation: String,
    pub(crate) hostname: String,
    /// The incarnation of its previous session, to tell a reconnect from a restart.
    pub(crate) previous_incarnation: Option<String>,
    /// The session's protocol version. Nodes below [`STEERING`] are monitored only.
    pub(crate) version: u32,
}

/// Which kind of peer a session is for: each has its own endpoint, protocol versions and
/// table of pinned keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerKind {
    Node,
    Registry,
    Relay,
}

impl PeerKind {
    fn noun(self) -> &'static str {
        match self {
            PeerKind::Node => "node",
            PeerKind::Registry => "registry",
            PeerKind::Relay => "relay",
        }
    }
}

/// A peer's pinned key, hostname and last incarnation, `None` when it is not enrolled.
type Pinned = Option<(String, String, Option<String>)>;

/// A handshake refusal, with a public reason and private log detail.
pub(crate) struct Refusal {
    code: RefusalCode,
    reason: String,
    detail: Option<String>,
    /// Writing to the peer failed: there is no one left to tell.
    gone: bool,
}

impl Refusal {
    pub(crate) fn new(code: RefusalCode, reason: impl Into<String>) -> Self {
        Refusal {
            code,
            reason: reason.into(),
            detail: None,
            gone: false,
        }
    }

    /// A send to the peer failed with `e`.
    pub(crate) fn gone(e: anyhow::Error) -> Self {
        Refusal {
            gone: true,
            ..Refusal::from(e)
        }
    }
}

/// A failure on the hub's side. The peer has not authenticated, so it learns only that
/// something failed; the log gets the error.
impl<E: std::fmt::Display> From<E> for Refusal {
    fn from(e: E) -> Self {
        Refusal {
            code: RefusalCode::Internal,
            reason: "internal error".into(),
            detail: Some(format!("{e:#}")),
            gone: false,
        }
    }
}

/// Authenticate the `kind` of peer opening a session on `ws`, speaking `protocol_range`.
pub(crate) async fn handshake(
    ws: &mut Ws,
    hub: &Hub,
    exported: Exported,
    kind: PeerKind,
    protocol_range: VersionRange,
) -> Result<Peer, Refusal> {
    let noun = kind.noun();
    let protocol = |e: anyhow::Error| Refusal {
        code: RefusalCode::Protocol,
        reason: format!("{e:#}"),
        detail: None,
        gone: false,
    };
    let NodeMsg::Hello {
        versions,
        node_id,
        incarnation,
        vk_version,
    } = receive(ws, HANDSHAKE_STEP).await.map_err(protocol)?
    else {
        return Err(Refusal::new(
            RefusalCode::Protocol,
            "a session opens with a hello",
        ));
    };
    let Some(version) = protocol_range.negotiate(versions) else {
        return Err(Refusal::new(
            RefusalCode::Version,
            format!(
                "no common protocol version: this hub speaks {}–{}, version {} speaks {}–{}",
                protocol_range.min,
                protocol_range.max,
                vk_hub_proto::display_safe(&vk_version),
                versions.min,
                versions.max
            ),
        ));
    };
    if !vk_hub_proto::valid_id(&node_id) || !vk_hub_proto::valid_id(&incarnation) {
        return Err(Refusal::new(
            RefusalCode::Protocol,
            format!("malformed {noun} or incarnation ID"),
        ));
    }
    let db = hub.db.clone();
    let id = node_id.clone();
    let pinned: Pinned = tokio::task::spawn_blocking(move || {
        anyhow::Ok(match kind {
            PeerKind::Node => db
                .node(&id)?
                .map(|r| (r.public_key, r.hostname, r.incarnation)),
            PeerKind::Registry => db
                .registry(&id)?
                .map(|r| (r.public_key, r.hostname, r.incarnation)),
            PeerKind::Relay => db
                .relay(&id)?
                .map(|r| (r.public_key, r.hostname, r.incarnation)),
        })
    })
    .await??;
    let Some((pinned_key, hostname, previous_incarnation)) = pinned else {
        return Err(Refusal::new(
            RefusalCode::NotEnrolled,
            format!("{noun} {node_id} is not enrolled"),
        ));
    };
    let nonce = crate::random_bytes(CHALLENGE_LEN)?;
    send(
        ws,
        &HubMsg::Challenge {
            version,
            versions: protocol_range,
            nonce: vk_hub_proto::to_hex(&nonce),
        },
    )
    .await
    .map_err(Refusal::gone)?;
    let NodeMsg::Auth { signature } = receive(ws, HANDSHAKE_STEP).await.map_err(protocol)? else {
        return Err(Refusal::new(
            RefusalCode::Protocol,
            "a challenge is answered with an auth",
        ));
    };
    let Some(signature) = from_hex_lower::<SIGNATURE_LEN>(&signature) else {
        return Err(Refusal::new(RefusalCode::Protocol, "malformed signature"));
    };
    let Some(public_key) = from_hex_lower::<PUBLIC_KEY_LEN>(&pinned_key) else {
        return Err(anyhow!("{noun} {node_id} has a corrupt pinned key").into());
    };
    let channel = match &exported {
        Some(exported) => Channel::Tls(exported),
        None => Channel::Plaintext,
    };
    let message = vk_hub_proto::auth_message(
        &nonce,
        &node_id,
        &incarnation,
        versions,
        protocol_range,
        version,
        channel,
    );
    if !crate::verify(&public_key, &message, &signature) {
        return Err(Refusal::new(
            RefusalCode::BadSignature,
            format!(
                "{noun} {node_id}: the signature does not match its pinned key; a proxy \
                 terminating TLS in front of the hub breaks the session's binding to the \
                 connection: pass TLS through"
            ),
        ));
    }
    Ok(Peer {
        id: node_id,
        incarnation,
        hostname,
        previous_incarnation,
        version,
    })
}

/// Record `session` of the authenticated `node` and welcome it, unless the node was removed
/// or a newer session took over meanwhile.
async fn welcome(ws: &mut Ws, hub: &Arc<Hub>, node: &Peer, session: u64) -> Result<(), Refusal> {
    let (db, live) = (hub.db.clone(), hub.clone());
    let (id, incarnation, version) = (node.id.clone(), node.incarnation.clone(), node.version);
    let recorded = tokio::task::spawn_blocking(move || {
        db.record_session(&id, &incarnation, version, crate::now_secs(), || {
            live.is_current(&id, session)
        })
    })
    .await?;
    match recorded {
        Ok(true) => {}
        Ok(false) => {
            return Err(Refusal::new(
                RefusalCode::Superseded,
                "superseded by a newer session of this node",
            ));
        }
        Err(e) if e.is::<NotEnrolled>() => return Err(Refusal::new(RefusalCode::Revoked, REMOVED)),
        Err(e) => return Err(e.into()),
    }
    send(
        ws,
        &HubMsg::Welcome {
            heartbeat_secs: HEARTBEAT_SECS,
        },
    )
    .await
    .map_err(Refusal::gone)
}

/// The authenticated part: store what the node reports, send it what the hub wants of it,
/// ping it every heartbeat so it can tell a dead hub from a quiet one, and end when it goes
/// quiet itself. `Ok` carries why the session ended normally.
async fn serve(
    ws: &mut Ws,
    hub: &Hub,
    node: &Peer,
    session: u64,
    ending: &Ending,
    mut jobs: Option<tokio::sync::mpsc::Receiver<vk_hub_proto::dispatch::HubJobMsg>>,
) -> Result<&'static str> {
    let quiet = hub.quiet;
    let mut ping = tokio::time::interval(HEARTBEAT);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = tokio::time::Instant::now() + quiet;
    let mut pace = Pace::default();
    let mut steer = Steer::default();
    let mut access = Access::new(node.version);
    let mut access_changed = hub.token_keys.subscribe_node_access();
    loop {
        let access_due = access.due;
        tokio::select! {
            () = ending.notify.notified() => {
                let (code, reason, why) = if ending.revoked.load(Ordering::Relaxed) {
                    (RefusalCode::Revoked, REMOVED, "removed")
                } else if ending.unanswered.load(Ordering::Relaxed) {
                    // Every node recognizes this non-permanent code and redials.
                    (
                        RefusalCode::Protocol,
                        "an offer was left unanswered; reconnect and report what is held",
                        "an offer left unanswered",
                    )
                } else {
                    (
                        RefusalCode::Superseded,
                        "superseded by a newer session of this node",
                        "superseded by a newer session",
                    )
                };
                refuse(ws, code, reason).await;
                return Ok(why);
            }
            () = ending.kick.notified() => steer.sync(ws, hub, node).await?,
            () = sleep_until_some(access_due) => access.sync(ws, hub, node).await?,
            Ok(()) = access_changed.changed() => access.sync(ws, hub, node).await?,
            Some(msg) = next_job(&mut jobs) => send(ws, &HubMsg::Job(msg)).await?,
            _ = ping.tick() => {
                tokio::time::timeout(HEARTBEAT, ws.send(Message::Ping(Default::default())))
                    .await
                    .map_err(|_| anyhow!("the node is not reading"))?
                    .map_err(|e| anyhow!("pinging: {e}"))?;
                let now = Instant::now();
                let held = [
                    pace.held_report(now).map(Write::Report),
                    pace.held(now).map(|(h, arrived)| Write::Heartbeat(h, arrived)),
                ];
                for write in held.into_iter().flatten() {
                    let report = matches!(write, Write::Report(_));
                    if let Some(why) = store(ws, hub, node, write).await? {
                        return Ok(why);
                    }
                    // A report held back may have moved the desired state past the node's.
                    if report {
                        steer.sync(ws, hub, node).await?;
                    }
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                bail!("nothing heard for {}s", quiet.as_secs());
            }
            frame = ws.next() => {
                let text = match frame {
                    None => return Ok("connection closed"),
                    // tungstenite's error names its own cause, so it is formatted once rather
                    // than through a context chain that would repeat it.
                    Some(Err(e)) => bail!("reading: {e}"),
                    Some(Ok(Message::Close(_))) => return Ok("closed by the node"),
                    Some(Ok(Message::Text(text))) => text,
                    // Pings are answered by tungstenite itself; a pong or a ping still shows
                    // the node is alive.
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        deadline = tokio::time::Instant::now() + quiet;
                        hub.heard(&node.id, session);
                        continue;
                    }
                    Some(Ok(_)) => bail!("the node sent a frame that is not text"),
                };
                deadline = tokio::time::Instant::now() + quiet;
                hub.heard(&node.id, session);
                let msg: NodeMsg = serde_json::from_str(text.as_str())
                    .context("the node sent a message this hub does not understand")?;
                let now = Instant::now();
                let mut report = false;
                let mut names_registry = false;
                let write = match msg {
                    NodeMsg::Inventory(inventory) => {
                        // What it enforces may move the Fallback in its desired state.
                        report = true;
                        names_registry = true;
                        Some(Write::Inventory(inventory, pace.inventory_durable(now)))
                    }
                    NodeMsg::Heartbeat(heartbeat) => pace.heartbeat(heartbeat, now).map(|h| Write::Heartbeat(h, now)),
                    NodeMsg::Report(r) if node.version < STEERING => {
                        pace.report(r.without_steering(), now).map(Write::Report)
                    }
                    NodeMsg::Report(r) => {
                        steer.applied = Some(r.applied_generation());
                        report = true;
                        pace.report(r, now).map(Write::Report)
                    }
                    NodeMsg::Ack(_) if node.version < STEERING => {
                        let reason = format!("an ack in a version-{} session", node.version);
                        refuse(ws, RefusalCode::Protocol, &reason).await;
                        bail!("the node sent {reason}");
                    }
                    NodeMsg::Ack(ack) => {
                        acknowledge(ws, hub, node, ack).await?;
                        None
                    }
                    NodeMsg::Job(_) if node.version < JOBS => {
                        let reason = format!("a job message in a version-{} session", node.version);
                        refuse(ws, RefusalCode::Protocol, &reason).await;
                        bail!("the node sent {reason}");
                    }
                    NodeMsg::Job(NodeJobMsg::Egress { .. }) if node.version < LIVE_EGRESS => {
                        let reason =
                            format!("an egress report in a version-{} session", node.version);
                        refuse(ws, RefusalCode::Protocol, &reason).await;
                        bail!("the node sent {reason}");
                    }
                    NodeMsg::Job(msg) => {
                        match crate::jobs::on_node(hub, &node.id, session, msg).await {
                            Ok(answers) => {
                                for answer in answers {
                                    send(ws, &HubMsg::Job(answer)).await?;
                                }
                            }
                            Err(e) if e.is::<crate::jobs::Violation>() => {
                                let reason = format!("{e:#}");
                                refuse(ws, RefusalCode::Protocol, &reason).await;
                                bail!("the node broke the job protocol: {reason}");
                            }
                            Err(e) => return Err(e),
                        }
                        None
                    }
                    NodeMsg::Hello { .. } | NodeMsg::Auth { .. } => {
                        bail!("the node repeated its handshake inside a session")
                    }
                };
                if let Some(write) = write
                    && let Some(why) = store(ws, hub, node, write).await?
                {
                    return Ok(why);
                }
                // Even one held back: the generation it shows is what the node lacks.
                if report {
                    steer.sync(ws, hub, node).await?;
                }
                // An inventory names the registry the node uses.
                if names_registry {
                    access.known = true;
                    access.sync(ws, hub, node).await?;
                }
            }
        }
    }
}

/// The next job message for the session to send; never, in a session below [`JOBS`].
async fn next_job(
    jobs: &mut Option<tokio::sync::mpsc::Receiver<vk_hub_proto::dispatch::HubJobMsg>>,
) -> Option<vk_hub_proto::dispatch::HubJobMsg> {
    match jobs {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Track reported and sent state: send desired state to a lagging node once per generation,
/// and each pending command once per session. Wait for the first report to learn what the
/// node lacks. Sessions below [`STEERING`] never set [`Steer::applied`] and receive neither.
#[derive(Default)]
struct Steer {
    /// The generation the node last reported applying; `Some` once it has reported at all.
    applied: Option<Option<u64>>,
    sent_generation: Option<u64>,
    sent_commands: HashSet<String>,
}

impl Steer {
    /// Send what the node lacks and this session has not sent it yet.
    async fn sync(&mut self, ws: &mut Ws, hub: &Hub, node: &Peer) -> Result<()> {
        let Some(applied) = self.applied else {
            return Ok(());
        };
        let db = hub.db.clone();
        let id = node.id.clone();
        let (row, pending) = tokio::task::spawn_blocking(move || {
            anyhow::Ok((db.node(&id)?, db.pending_commands(&id, crate::now_secs())?))
        })
        .await??;
        if let Some(desired) = row.and_then(|r| r.desired)
            && applied < Some(desired.generation)
            && self.sent_generation != Some(desired.generation)
        {
            self.sent_generation = Some(desired.generation);
            send(ws, &HubMsg::Desired(desired)).await?;
        }
        for command in pending {
            // A node below it could not read one: the command waits for a session that can
            // carry it, or expires.
            if matches!(command.op, vk_hub_proto::Operation::Tools { .. })
                && node.version < vk_hub_proto::TOOLS
            {
                continue;
            }
            if self.sent_commands.insert(command.id.clone()) {
                send(ws, &HubMsg::Command(command)).await?;
            }
        }
        Ok(())
    }
}

/// A fraction from 0 to 1 drawn at random; one half when no randomness can be had.
fn jitter() -> f64 {
    let mut b = [0u8; 2];
    match vk_peer::fill_random(&mut b) {
        Ok(()) => f64::from(u16::from_le_bytes(b)) / f64::from(u16::MAX),
        Err(_) => 0.5,
    }
}

/// Until `at`, or never with `None`.
async fn sleep_until_some(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The node's own registry access, in a session from [`REGISTRY_ACCESS`]: what this session
/// sent it, and when to look again. Nothing is sent before the session's first inventory, which
/// names the registry the node uses; then access or an explicit clear, so that a node holding
/// access from before learns whether it still may. Minted again when its binding changes or it
/// is due for renewal; a failure to mint leaves what the node holds, and is retried.
struct Access {
    /// Whether the session carries it at all.
    on: bool,
    /// Whether an inventory arrived in this session.
    known: bool,
    sent: Option<Sent>,
    /// When the access sent is to be renewed.
    renew_at: Option<Instant>,
    /// When to look again; `None` until the session carries it and knows the registry.
    due: Option<Instant>,
}

/// What a session last sent of a node's access.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Cleared,
    Granted(crate::tokens::NodeBinding),
}

/// What [`Access::plan`] decides.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Nothing,
    Mint(crate::tokens::NodeBinding),
    Clear(&'static str),
}

impl Access {
    fn new(version: u32) -> Self {
        Access {
            on: version >= REGISTRY_ACCESS,
            known: false,
            sent: None,
            renew_at: None,
            due: None,
        }
    }

    /// What to do at `now` for `target`, the next look scheduled for nothing sent.
    fn plan(&mut self, target: crate::tokens::NodeTarget, now: Instant) -> Plan {
        use crate::tokens::NodeTarget;
        self.due = Some(now + ACCESS_RECHECK);
        match target {
            NodeTarget::Grant(binding) => {
                let current = self.sent.as_ref() == Some(&Sent::Granted(binding.clone()));
                if current && self.renew_at.is_some_and(|at| now < at) {
                    self.due = self.renew_at.map(|at| at.min(now + ACCESS_RECHECK));
                    Plan::Nothing
                } else {
                    Plan::Mint(binding)
                }
            }
            NodeTarget::Clear(_) if self.sent == Some(Sent::Cleared) => Plan::Nothing,
            NodeTarget::Clear(why) => Plan::Clear(why),
            NodeTarget::Wait(_) => {
                self.due = Some(now + ACCESS_RETRY);
                Plan::Nothing
            }
        }
    }

    /// `binding` was sent at `now`; it renews after [`RENEW_AFTER`] shifted by `jitter`, from
    /// 0 to 1 across [`RENEW_JITTER`] either way.
    fn minted(&mut self, binding: crate::tokens::NodeBinding, now: Instant, jitter: f64) {
        let renew = RENEW_AFTER - RENEW_JITTER + (RENEW_JITTER * 2).mul_f64(jitter.clamp(0.0, 1.0));
        self.sent = Some(Sent::Granted(binding));
        self.renew_at = Some(now + renew);
        self.due = self.renew_at.map(|at| at.min(now + ACCESS_RECHECK));
    }

    fn cleared(&mut self) {
        self.sent = Some(Sent::Cleared);
        self.renew_at = None;
    }

    /// Minting failed at `now`: retried soon, the node keeping what it holds meanwhile.
    fn failed(&mut self, now: Instant) {
        self.due = Some(now + ACCESS_RETRY);
    }

    /// Look at the node's access and send what changed.
    async fn sync(&mut self, ws: &mut Ws, hub: &Hub, node: &Peer) -> Result<()> {
        if !self.on || !self.known {
            return Ok(());
        }
        let (db, keys) = (hub.db.clone(), hub.token_keys.clone());
        let id = node.id.clone();
        let read = tokio::task::spawn_blocking(move || {
            let ctx = crate::tokens::MintCtx::read(&db, &keys)?;
            let target = db
                .node(&id)?
                .map(|row| crate::tokens::node_target(&ctx, &id, &row));
            anyhow::Ok((ctx, target))
        })
        .await?;
        let now = Instant::now();
        let (ctx, target) = match read {
            Ok((ctx, Some(target))) => (ctx, target),
            // Removed: its session is being revoked.
            Ok((_, None)) => return Ok(()),
            Err(e) => {
                eprintln!(
                    "vk-hub: node {}: reading its registry access: {e:#}",
                    node.id
                );
                self.failed(now);
                return Ok(());
            }
        };
        match self.plan(target, now) {
            Plan::Nothing => Ok(()),
            Plan::Clear(why) => {
                send(ws, &HubMsg::RegistryAccess { access: None }).await?;
                // Audited when it takes away what this session granted, not on every connect.
                if let Some(Sent::Granted(was)) = &self.sent {
                    let (db, registry, id) =
                        (hub.db.clone(), was.registry.clone(), node.id.clone());
                    let audited = tokio::task::spawn_blocking(move || {
                        crate::tokens::cleared_node(&db, &registry, &id, why)
                    })
                    .await?;
                    if let Err(e) = audited {
                        eprintln!(
                            "vk-hub: node {}: auditing its registry access: {e:#}",
                            node.id
                        );
                    }
                }
                self.cleared();
                Ok(())
            }
            Plan::Mint(binding) => {
                let (db, keys) = (hub.db.clone(), hub.token_keys.clone());
                let (id, bound) = (node.id.clone(), binding.clone());
                let renewal = self.sent.as_ref() == Some(&Sent::Granted(binding.clone()));
                let minted = tokio::task::spawn_blocking(move || {
                    crate::tokens::for_node(&db, &keys, &ctx, &id, &bound, renewal)
                })
                .await?;
                match minted {
                    Ok(access) => {
                        send(
                            ws,
                            &HubMsg::RegistryAccess {
                                access: Some(access),
                            },
                        )
                        .await?;
                        self.minted(binding, now, jitter());
                    }
                    Err(e) => {
                        eprintln!("vk-hub: node {}: no registry token: {e:#}", node.id);
                        self.failed(now);
                    }
                }
                Ok(())
            }
        }
    }
}

/// Record the node's command outcome and reply with [`HubMsg::Recorded`].
async fn acknowledge(
    ws: &mut Ws,
    hub: &Hub,
    node: &Peer,
    ack: vk_hub_proto::CommandAck,
) -> Result<()> {
    let db = hub.db.clone();
    let id = node.id.clone();
    let recorded = ack.clone();
    let news =
        tokio::task::spawn_blocking(move || db.record_ack(&id, &ack, crate::now_secs())).await??;
    if news {
        hub.changed(&node.id);
    }
    // Answered whether or not the command is one this hub issued: an ack for an unknown one
    // would otherwise be repeated for ever.
    send(ws, &HubMsg::Recorded(recorded)).await
}

/// How much of what its node reports a session writes. A node heartbeats every
/// [`HEARTBEAT`], and sends an inventory or a report when something changed; one doing any
/// of it faster only costs writes. Heartbeats and reports are each stored at most one per
/// half heartbeat, the latest of those held back stored at the next ping, so the stored one
/// is never staler than that. An inventory is durable at most once a heartbeat; one sooner
/// is stored all the same, and made durable by the next durable write.
#[derive(Default)]
struct Pace {
    heartbeat: Paced<Heartbeat>,
    report: Paced<Report>,
    durable_inventory_at: Option<Instant>,
}

/// One kind of message stored at most once per half heartbeat.
struct Paced<T> {
    stored_at: Option<Instant>,
    /// The one held back, and when it arrived.
    held: Option<(T, Instant)>,
}

impl<T> Default for Paced<T> {
    fn default() -> Self {
        Paced {
            stored_at: None,
            held: None,
        }
    }
}

impl<T> Paced<T> {
    /// `msg` arrived at `now`: it, to store now, or `None` with it held back.
    fn offer(&mut self, msg: T, now: Instant) -> Option<T> {
        if self
            .stored_at
            .is_some_and(|t| now.duration_since(t) < HEARTBEAT / 2)
        {
            self.held = Some((msg, now));
            return None;
        }
        self.held = None;
        self.stored_at = Some(now);
        Some(msg)
    }

    /// The one held back, to store at `now`, and when it arrived.
    fn held(&mut self, now: Instant) -> Option<(T, Instant)> {
        let held = self.held.take()?;
        self.stored_at = Some(now);
        Some(held)
    }
}

impl Pace {
    /// `heartbeat` arrived at `now`: it, to store now, or `None` with it held back.
    fn heartbeat(&mut self, heartbeat: Heartbeat, now: Instant) -> Option<Heartbeat> {
        self.heartbeat.offer(heartbeat, now)
    }

    /// The heartbeat held back, to store at `now`, and when it arrived.
    fn held(&mut self, now: Instant) -> Option<(Heartbeat, Instant)> {
        self.heartbeat.held(now)
    }

    /// `report` arrived at `now`: it, to store now, or `None` with it held back.
    fn report(&mut self, report: Report, now: Instant) -> Option<Report> {
        self.report.offer(report, now)
    }

    /// The report held back, to store at `now`.
    fn held_report(&mut self, now: Instant) -> Option<Report> {
        self.report.held(now).map(|(report, _)| report)
    }

    /// Whether an inventory arriving at `now` is written durably.
    fn inventory_durable(&mut self, now: Instant) -> bool {
        let durable = self
            .durable_inventory_at
            .is_none_or(|t| now.duration_since(t) >= HEARTBEAT);
        if durable {
            self.durable_inventory_at = Some(now);
        }
        durable
    }
}

/// A write of an authenticated session.
enum Write {
    /// An inventory, and whether to write it durably.
    Inventory(Inventory, bool),
    /// A heartbeat, and when it arrived.
    Heartbeat(Heartbeat, Instant),
    Report(Report),
}

/// Add `waited` since arrival to the admission age: the hub timestamps heartbeats at storage.
/// Leave older nodes' heartbeats unchanged when they omit the age.
fn aged(mut heartbeat: Heartbeat, waited: Duration) -> Heartbeat {
    if let Some(age) = heartbeat.admission_age_ms.as_mut() {
        let waited = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX);
        *age = age.saturating_add(waited);
    }
    heartbeat
}

/// Write `write` for `node`. `Some` carries why the session ends: the node was removed since
/// its last message, before its revocation reached the session loop, and has been told.
async fn store(ws: &mut Ws, hub: &Hub, node: &Peer, write: Write) -> Result<Option<&'static str>> {
    let db = hub.db.clone();
    let id = node.id.clone();
    let now = crate::now_secs();
    // Whether the node was renamed, which pages beyond its row show.
    // The Egress page shows the nodes' caps from their inventories.
    let inventory = matches!(write, Write::Inventory(..));
    let written = tokio::task::spawn_blocking(move || match write {
        Write::Inventory(inventory, durable) => db.record_inventory(&id, inventory, durable, now),
        Write::Heartbeat(heartbeat, arrived) => db
            .record_heartbeat(&id, aged(heartbeat, arrived.elapsed()), now)
            .map(|()| false),
        Write::Report(report) => db.record_report(&id, report, now).map(|()| false),
    })
    .await?;
    match written {
        Ok(renamed) => {
            hub.changed(&node.id);
            if renamed {
                hub.touch();
            }
            if inventory {
                hub.egress_changed();
            }
            Ok(None)
        }
        Err(e) if e.is::<NotEnrolled>() => {
            refuse(ws, RefusalCode::Revoked, REMOVED).await;
            Ok(Some("removed"))
        }
        Err(e) => Err(e),
    }
}

async fn send(ws: &mut Ws, msg: &HubMsg) -> Result<()> {
    let text = serde_json::to_string(msg).context("encoding a message")?;
    tokio::time::timeout(HEARTBEAT, ws.send(Message::text(text)))
        .await
        .map_err(|_| anyhow!("the node is not reading"))?
        .map_err(|e| anyhow!("sending: {e}"))
}

/// The next text message, as a [`NodeMsg`], within `timeout`. Pings and pongs are skipped.
async fn receive(ws: &mut Ws, timeout: Duration) -> Result<NodeMsg> {
    tokio::time::timeout(timeout, async {
        loop {
            match ws.next().await {
                None => bail!("the node closed the connection"),
                Some(Err(e)) => bail!("reading: {e}"),
                Some(Ok(Message::Text(text))) => {
                    return serde_json::from_str(text.as_str())
                        .context("the node sent a message this hub does not understand");
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(_)) => bail!("the node sent a frame that is not text"),
            }
        }
    })
    .await
    .map_err(|_| anyhow!("the node sent nothing for {}s", timeout.as_secs()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beat(n: u32) -> Heartbeat {
        Heartbeat {
            desired_concurrency: Some(n),
            ..Heartbeat::default()
        }
    }

    #[test]
    fn a_heartbeat_too_soon_is_held_and_the_latest_stored_at_the_next_ping() {
        let mut pace = Pace::default();
        let t = Instant::now();
        assert_eq!(pace.heartbeat(beat(1), t), Some(beat(1)));
        assert_eq!(pace.heartbeat(beat(2), t + HEARTBEAT / 4), None);
        assert_eq!(pace.heartbeat(beat(3), t + HEARTBEAT / 3), None);
        assert_eq!(pace.held(t + HEARTBEAT), Some((beat(3), t + HEARTBEAT / 3)));
        assert_eq!(pace.held(t + HEARTBEAT), None);
        // Storing the held one counts as a store.
        assert_eq!(pace.heartbeat(beat(4), t + HEARTBEAT * 5 / 4), None);
        // One on time is stored, and replaces any held back.
        assert_eq!(pace.heartbeat(beat(5), t + HEARTBEAT * 2), Some(beat(5)));
        assert_eq!(pace.held(t + HEARTBEAT * 3), None);
    }

    /// Admission age includes storage delays, including time held back by pacing.
    #[test]
    fn a_heartbeat_stored_late_ages_its_admission() {
        let mut pace = Pace::default();
        let t = Instant::now();
        let read = |age_ms| Heartbeat {
            admission: Some(vk_hub_proto::Admission::default()),
            admission_age_ms: age_ms,
            ..Heartbeat::default()
        };
        assert_eq!(pace.heartbeat(read(Some(100)), t), Some(read(Some(100))));
        assert_eq!(pace.heartbeat(read(Some(200)), t + HEARTBEAT / 4), None);
        assert_eq!(
            pace.held(t + HEARTBEAT),
            Some((read(Some(200)), t + HEARTBEAT / 4))
        );
        let waited = Duration::from_millis(750);
        assert_eq!(aged(read(Some(200)), waited), read(Some(950)));
        // An older node's, as it came.
        assert_eq!(aged(read(None), waited), read(None));
    }

    #[test]
    fn reports_are_paced_apart_from_heartbeats() {
        let mut pace = Pace::default();
        let t = Instant::now();
        let report = |n| Report {
            workloads_omitted: n,
            ..Report::default()
        };
        assert_eq!(pace.heartbeat(beat(1), t), Some(beat(1)));
        // A heartbeat just stored does not hold a report back, nor the other way round.
        assert_eq!(pace.report(report(1), t), Some(report(1)));
        assert_eq!(pace.report(report(2), t + HEARTBEAT / 4), None);
        assert_eq!(pace.held(t + HEARTBEAT), None);
        assert_eq!(pace.held_report(t + HEARTBEAT), Some(report(2)));
        assert_eq!(pace.held_report(t + HEARTBEAT), None);
    }

    fn binding(registry: &str) -> crate::tokens::NodeBinding {
        crate::tokens::NodeBinding {
            registry: registry.into(),
            origin: "https://reg.example.com".into(),
            ca_sha256: None,
            grants: Vec::new(),
            guest_grants: Vec::new(),
        }
    }

    /// A node's access is minted once, renewed when due and not before, minted again when its
    /// binding changes, cleared once, and left alone while it waits on its registry.
    #[test]
    fn a_node_s_access_is_renewed_when_due_and_sent_again_only_when_it_changes() {
        use crate::tokens::NodeTarget;
        let mut access = Access::new(REGISTRY_ACCESS);
        let t = Instant::now();
        let grant = |r: &str| NodeTarget::Grant(binding(r));
        assert_eq!(access.plan(grant("a"), t), Plan::Mint(binding("a")));
        access.minted(binding("a"), t, 0.0);
        let renew = t + RENEW_AFTER - RENEW_JITTER;
        assert_eq!(access.renew_at, Some(renew));
        // Looked at again within the recheck, and not renewed before it is due.
        assert_eq!(access.due, Some(t + ACCESS_RECHECK));
        assert_eq!(access.plan(grant("a"), t + ACCESS_RECHECK), Plan::Nothing);
        assert!(access.due.is_some_and(|d| d <= renew));
        assert_eq!(access.plan(grant("a"), renew), Plan::Mint(binding("a")));
        // The latest jitter renews the latest.
        access.minted(binding("a"), t, 1.0);
        assert_eq!(access.renew_at, Some(t + RENEW_AFTER + RENEW_JITTER));
        // Another binding is minted at once.
        assert_eq!(access.plan(grant("b"), t), Plan::Mint(binding("b")));
        // Waiting keeps what the node holds, and looks again soon.
        assert_eq!(access.plan(NodeTarget::Wait("w"), t), Plan::Nothing);
        assert_eq!(access.due, Some(t + ACCESS_RETRY));
        assert_eq!(access.plan(NodeTarget::Clear("c"), t), Plan::Clear("c"));
        access.cleared();
        assert_eq!(access.plan(NodeTarget::Clear("c"), t), Plan::Nothing);
        assert_eq!(access.renew_at, None);
        // A failed mint is retried soon.
        assert_eq!(access.plan(grant("a"), t), Plan::Mint(binding("a")));
        access.failed(t);
        assert_eq!(access.due, Some(t + ACCESS_RETRY));
        assert!(!Access::new(LIVE_EGRESS).on);
    }

    #[test]
    fn an_inventory_is_durable_at_most_once_a_heartbeat() {
        let mut pace = Pace::default();
        let t = Instant::now();
        assert!(pace.inventory_durable(t));
        assert!(!pace.inventory_durable(t + HEARTBEAT / 2));
        assert!(pace.inventory_durable(t + HEARTBEAT));
        assert!(!pace.inventory_durable(t + HEARTBEAT * 3 / 2));
    }
}
