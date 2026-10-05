//! One node's WebSocket session: the hello/challenge/auth handshake against the key pinned at
//! enrollment, then inventory, heartbeats and reports into the database until the node goes
//! away.

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
use vk_hub_proto::{
    CHALLENGE_LEN, Channel, Heartbeat, HubMsg, Inventory, NodeMsg, PROTOCOL, PUBLIC_KEY_LEN,
    RefusalCode, Report, SIGNATURE_LEN, STEERING, from_hex_lower,
};

use crate::server::{Ending, Exported, HEARTBEAT, HEARTBEAT_SECS, Hub, MISSED_HEARTBEATS};
use crate::store::NotEnrolled;

type Ws = WebSocketStream<TokioIo<Upgraded>>;

/// How long a node has for each handshake step. Signing a nonce takes microseconds; a peer
/// this slow is not a node doing its job, and holding the socket for it costs a descriptor.
/// Short under test, so the timeout itself can be tested.
#[cfg(not(test))]
const HANDSHAKE_STEP: Duration = crate::server::PRE_AUTH_TIMEOUT;
#[cfg(test)]
const HANDSHAKE_STEP: Duration = Duration::from_secs(1);

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
    let node = match handshake(&mut ws, &hub, exported).await {
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
    let ended = serve(&mut ws, &hub, &node, session, &ending).await;
    hub.close_session(&node.id, session);
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
async fn turn_away(ws: &mut Ws, peer: SocketAddr, r: Refusal) {
    let why = r.detail.as_deref().unwrap_or(&r.reason);
    if r.gone {
        eprintln!("vk-hub: {peer}: handshake ended: {why}");
        return;
    }
    eprintln!("vk-hub: {peer}: refused a session: {why}");
    refuse(ws, r.code, &r.reason).await;
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

/// An authenticated node.
struct Node {
    id: String,
    incarnation: String,
    hostname: String,
    /// The incarnation of its previous session, to tell a reconnect from a restart.
    previous_incarnation: Option<String>,
    /// The protocol version of the session: below [`STEERING`], it is monitored only.
    version: u32,
}

/// A handshake refusal, with a public reason and private log detail.
struct Refusal {
    code: RefusalCode,
    reason: String,
    detail: Option<String>,
    /// Writing to the peer failed: there is no one left to tell.
    gone: bool,
}

impl Refusal {
    fn new(code: RefusalCode, reason: impl Into<String>) -> Self {
        Refusal {
            code,
            reason: reason.into(),
            detail: None,
            gone: false,
        }
    }

    /// A send to the peer failed with `e`.
    fn gone(e: anyhow::Error) -> Self {
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

async fn handshake(ws: &mut Ws, hub: &Hub, exported: Exported) -> Result<Node, Refusal> {
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
    let Some(version) = PROTOCOL.negotiate(versions) else {
        return Err(Refusal::new(
            RefusalCode::Version,
            format!(
                "no common protocol version: this hub speaks {}–{}, vk {} speaks {}–{}",
                PROTOCOL.min,
                PROTOCOL.max,
                vk_hub_proto::display_safe(&vk_version),
                versions.min,
                versions.max
            ),
        ));
    };
    if !vk_hub_proto::valid_id(&node_id) || !vk_hub_proto::valid_id(&incarnation) {
        return Err(Refusal::new(
            RefusalCode::Protocol,
            "malformed node or incarnation ID",
        ));
    }
    let db = hub.db.clone();
    let id = node_id.clone();
    let Some(row) = tokio::task::spawn_blocking(move || db.node(&id)).await?? else {
        return Err(Refusal::new(
            RefusalCode::NotEnrolled,
            format!("node {node_id} is not enrolled"),
        ));
    };
    let nonce = crate::random_bytes(CHALLENGE_LEN)?;
    send(
        ws,
        &HubMsg::Challenge {
            version,
            versions: PROTOCOL,
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
    let Some(public_key) = from_hex_lower::<PUBLIC_KEY_LEN>(&row.public_key) else {
        return Err(anyhow!("node {node_id} has a corrupt pinned key").into());
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
        PROTOCOL,
        version,
        channel,
    );
    if !crate::verify(&public_key, &message, &signature) {
        return Err(Refusal::new(
            RefusalCode::BadSignature,
            format!(
                "node {node_id}: the signature does not match its pinned key; a proxy \
                 terminating TLS in front of the hub breaks the session's binding to the \
                 connection: pass TLS through"
            ),
        ));
    }
    Ok(Node {
        id: node_id,
        incarnation,
        hostname: row.hostname,
        previous_incarnation: row.incarnation,
        version,
    })
}

/// Record `session` of the authenticated `node` and welcome it, unless the node was removed
/// or a newer session took over meanwhile.
async fn welcome(ws: &mut Ws, hub: &Arc<Hub>, node: &Node, session: u64) -> Result<(), Refusal> {
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

/// The authenticated part: store what the node reports, ping it every heartbeat so it can
/// tell a dead hub from a quiet one, and end when it goes quiet itself. `Ok` carries why the
/// session ended normally.
async fn serve(
    ws: &mut Ws,
    hub: &Hub,
    node: &Node,
    session: u64,
    ending: &Ending,
) -> Result<&'static str> {
    let quiet = HEARTBEAT * MISSED_HEARTBEATS;
    let mut ping = tokio::time::interval(HEARTBEAT);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = tokio::time::Instant::now() + quiet;
    let mut pace = Pace::default();
    loop {
        tokio::select! {
            () = ending.notify.notified() => {
                let (code, reason, why) = if ending.revoked.load(Ordering::Relaxed) {
                    (RefusalCode::Revoked, REMOVED, "removed")
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
            _ = ping.tick() => {
                tokio::time::timeout(HEARTBEAT, ws.send(Message::Ping(Default::default())))
                    .await
                    .map_err(|_| anyhow!("the node is not reading"))?
                    .map_err(|e| anyhow!("pinging: {e}"))?;
                let now = Instant::now();
                let held = [
                    pace.held_report(now).map(Write::Report),
                    pace.held(now).map(Write::Heartbeat),
                ];
                for write in held.into_iter().flatten() {
                    if let Some(why) = store(ws, hub, node, write).await? {
                        return Ok(why);
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
                let write = match msg {
                    NodeMsg::Inventory(inventory) => {
                        Some(Write::Inventory(inventory, pace.inventory_durable(now)))
                    }
                    NodeMsg::Heartbeat(heartbeat) => pace.heartbeat(heartbeat, now).map(Write::Heartbeat),
                    NodeMsg::Report(report) if node.version < STEERING => {
                        pace.report(report.without_steering(), now).map(Write::Report)
                    }
                    NodeMsg::Report(report) => pace.report(report, now).map(Write::Report),
                    NodeMsg::Ack(_) if node.version < STEERING => {
                        let reason = format!("an ack in a version-{} session", node.version);
                        refuse(ws, RefusalCode::Protocol, &reason).await;
                        bail!("the node sent {reason}");
                    }
                    // No command is sent yet, so no ack has anything to settle.
                    NodeMsg::Ack(_) => None,
                    NodeMsg::Hello { .. } | NodeMsg::Auth { .. } => {
                        bail!("the node repeated its handshake inside a session")
                    }
                };
                if let Some(write) = write
                    && let Some(why) = store(ws, hub, node, write).await?
                {
                    return Ok(why);
                }
            }
        }
    }
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
    held: Option<T>,
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
            self.held = Some(msg);
            return None;
        }
        self.held = None;
        self.stored_at = Some(now);
        Some(msg)
    }

    /// The one held back, to store at `now`.
    fn held(&mut self, now: Instant) -> Option<T> {
        let msg = self.held.take()?;
        self.stored_at = Some(now);
        Some(msg)
    }
}

impl Pace {
    /// `heartbeat` arrived at `now`: it, to store now, or `None` with it held back.
    fn heartbeat(&mut self, heartbeat: Heartbeat, now: Instant) -> Option<Heartbeat> {
        self.heartbeat.offer(heartbeat, now)
    }

    /// The heartbeat held back, to store at `now`.
    fn held(&mut self, now: Instant) -> Option<Heartbeat> {
        self.heartbeat.held(now)
    }

    /// `report` arrived at `now`: it, to store now, or `None` with it held back.
    fn report(&mut self, report: Report, now: Instant) -> Option<Report> {
        self.report.offer(report, now)
    }

    /// The report held back, to store at `now`.
    fn held_report(&mut self, now: Instant) -> Option<Report> {
        self.report.held(now)
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
    Heartbeat(Heartbeat),
    Report(Report),
}

/// Write `write` for `node`. `Some` carries why the session ends: the node was removed since
/// its last message, before its revocation reached the session loop, and has been told.
async fn store(ws: &mut Ws, hub: &Hub, node: &Node, write: Write) -> Result<Option<&'static str>> {
    let db = hub.db.clone();
    let id = node.id.clone();
    let now = crate::now_secs();
    let written = tokio::task::spawn_blocking(move || match write {
        Write::Inventory(inventory, durable) => db.record_inventory(&id, inventory, durable, now),
        Write::Heartbeat(heartbeat) => db.record_heartbeat(&id, heartbeat, now),
        Write::Report(report) => db.record_report(&id, report, now),
    })
    .await?;
    match written {
        Ok(()) => {
            hub.changed(&node.id);
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
        assert_eq!(pace.held(t + HEARTBEAT), Some(beat(3)));
        assert_eq!(pace.held(t + HEARTBEAT), None);
        // Storing the held one counts as a store.
        assert_eq!(pace.heartbeat(beat(4), t + HEARTBEAT * 5 / 4), None);
        // One on time is stored, and replaces any held back.
        assert_eq!(pace.heartbeat(beat(5), t + HEARTBEAT * 2), Some(beat(5)));
        assert_eq!(pace.held(t + HEARTBEAT * 3), None);
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
