//! One node's WebSocket session: the hello/challenge/auth handshake against the key pinned at
//! enrollment, then inventory and heartbeats into the database until the node goes away.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use vk_fleet_proto::{CHALLENGE_LEN, Channel, HubMsg, NodeMsg, PROTOCOL, RefusalCode};

use crate::server::{Ending, Exported, HEARTBEAT, Hub, MISSED_HEARTBEATS};

type Ws = WebSocketStream<TokioIo<Upgraded>>;

/// How long a node has for each handshake step. Signing a nonce takes microseconds; a peer
/// this slow is not a node doing its job, and holding the socket for it costs a descriptor.
/// Short under test, so the timeout itself can be tested.
#[cfg(not(test))]
const HANDSHAKE_STEP: Duration = crate::server::PRE_AUTH_TIMEOUT;
#[cfg(test)]
const HANDSHAKE_STEP: Duration = Duration::from_secs(1);

/// Run the session on `ws` to its end, logging why it ended.
pub async fn run(mut ws: Ws, hub: Arc<Hub>, peer: SocketAddr, exported: Exported) {
    let node = {
        // Bounded like the connections before them: an unauthenticated peer holds one of
        // these for at most two handshake steps.
        let Ok(_permit) = hub.handshakes.clone().try_acquire_owned() else {
            refuse(
                &mut ws,
                RefusalCode::Busy,
                "too many handshakes in progress",
            )
            .await;
            return;
        };
        match handshake(&mut ws, &hub, exported).await {
            Ok(node) => node,
            Err(r) => {
                eprintln!(
                    "vk-hub: {peer}: refused a session: {}",
                    r.detail.as_deref().unwrap_or(&r.reason)
                );
                refuse(&mut ws, r.code, &r.reason).await;
                return;
            }
        }
    };
    let (session, ending) = hub.open_session(&node.id);
    eprintln!(
        "vk-hub: {peer}: node {} ({}) connected, {}",
        node.id,
        node.hostname,
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
            let _ = ws.close(None).await;
        }
    }
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
}

/// Why a handshake was refused: what the node is told, and for the log what it is not.
struct Refusal {
    code: RefusalCode,
    reason: String,
    detail: Option<String>,
}

impl Refusal {
    fn new(code: RefusalCode, reason: impl Into<String>) -> Self {
        Refusal {
            code,
            reason: reason.into(),
            detail: None,
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
        }
    }
}

async fn handshake(ws: &mut Ws, hub: &Hub, exported: Exported) -> Result<Node, Refusal> {
    let protocol = |e: anyhow::Error| Refusal {
        code: RefusalCode::Protocol,
        reason: format!("{e:#}"),
        detail: None,
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
                vk_fleet_proto::display_safe(&vk_version),
                versions.min,
                versions.max
            ),
        ));
    };
    if !vk_fleet_proto::valid_id(&node_id) || !vk_fleet_proto::valid_id(&incarnation) {
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
            nonce: vk_fleet_proto::to_hex(&nonce),
        },
    )
    .await?;
    let NodeMsg::Auth { signature } = receive(ws, HANDSHAKE_STEP).await.map_err(protocol)? else {
        return Err(Refusal::new(
            RefusalCode::Protocol,
            "a challenge is answered with an auth",
        ));
    };
    let public_key = vk_fleet_proto::from_hex(&row.public_key)
        .ok_or_else(|| anyhow!("node {node_id} has a corrupt pinned key"))?;
    let channel = match &exported {
        Some(exported) => Channel::Tls(exported),
        None => Channel::Plaintext,
    };
    let message = vk_fleet_proto::auth_message(
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
            format!("node {node_id}: the signature does not match its pinned key"),
        ));
    }
    let db = hub.db.clone();
    let (id, inc) = (node_id.clone(), incarnation.clone());
    tokio::task::spawn_blocking(move || db.record_session(&id, &inc, crate::now_secs())).await??;
    send(
        ws,
        &HubMsg::Welcome {
            heartbeat_secs: u32::try_from(HEARTBEAT.as_secs()).unwrap_or(u32::MAX),
        },
    )
    .await?;
    Ok(Node {
        id: node_id,
        incarnation,
        hostname: row.hostname,
        previous_incarnation: row.incarnation,
    })
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
    loop {
        tokio::select! {
            () = ending.notify.notified() => {
                let (code, reason, why) = if ending.revoked.load(Ordering::Relaxed) {
                    (RefusalCode::Revoked, "this node was removed from the hub", "removed")
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
                record(hub, node, msg).await?;
            }
        }
    }
}

/// Store one message of an authenticated session.
async fn record(hub: &Hub, node: &Node, msg: NodeMsg) -> Result<()> {
    let db = hub.db.clone();
    let id = node.id.clone();
    let now = crate::now_secs();
    match msg {
        NodeMsg::Inventory(inventory) => {
            tokio::task::spawn_blocking(move || db.record_inventory(&id, inventory, now)).await?
        }
        NodeMsg::Heartbeat(heartbeat) => {
            tokio::task::spawn_blocking(move || db.record_heartbeat(&id, heartbeat, now)).await?
        }
        // No command is sent yet, so an ack answers nothing; noted rather than refused, since
        // a newer node may acknowledge what an older hub never tracked.
        NodeMsg::Ack(ack) => {
            eprintln!(
                "vk-hub: node {}: acknowledged command {} ({:?})",
                node.id,
                vk_fleet_proto::display_safe(&ack.id),
                ack.outcome
            );
            Ok(())
        }
        // Nothing is steered yet, so there is nothing a report answers.
        NodeMsg::Report(_) => Ok(()),
        NodeMsg::Hello { .. } | NodeMsg::Auth { .. } => {
            bail!("the node repeated its handshake inside a session")
        }
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
