//! GitLab relay sessions, and the relay operations the admin socket serves. A session uses the
//! shared peer handshake, stores inventory, heartbeats and reports, and tells the relay the
//! status of the GitLab server it is bound to, again whenever an operator changes it. See
//! `docs/gitlab-relay-enrollment.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::OwnedSemaphorePermit;
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::gitlab::{HubRelayMsg, RelayMsg, ServerState, ServerStatus};
use vk_hub_proto::{HubMsg, RefusalCode};

use crate::server::{Ending, Exported, HEARTBEAT, HEARTBEAT_SECS, Hub, MISSED_HEARTBEATS, Reach};
use crate::session::{HANDSHAKE_STEP, Peer, PeerKind, Refusal, Ws, turn_away};
use crate::store::{NotEnrolled, RelayRow, RelayWrite, normalize_gitlab_url};

/// What a relay removed from the hub is told.
const REMOVED: &str = "this relay was removed from the hub";

/// What a relay superseded by a newer session of its own is told.
const SUPERSEDED: &str = "superseded by a newer session of this relay";

/// Run a relay's session on `ws` to its end, logging why it ended.
pub async fn run(
    mut ws: Ws,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
    permit: OwnedSemaphorePermit,
) {
    let relay = match crate::session::handshake(&mut ws, &hub, exported, PeerKind::Relay).await {
        Ok(r) => r,
        Err(r) => return turn_away(&mut ws, peer, r).await,
    };
    let (session, ending) = hub.open_session(&relay.id);
    let welcomed = welcome(&mut ws, &hub, &relay, session).await;
    drop(permit);
    if let Err(r) = welcomed {
        hub.close_session(&relay.id, session);
        crate::jobs::relay_disconnected(&hub, &relay.id, session);
        return turn_away(&mut ws, peer, r).await;
    }
    eprintln!(
        "vk-hub: {peer}: relay {} ({}) connected",
        relay.id, relay.hostname
    );
    hub.changed(&relay.id);
    hub.clients_changed();
    let ended = serve(&mut ws, &hub, &relay, session, &ending).await;
    hub.close_session(&relay.id, session);
    crate::jobs::relay_disconnected(&hub, &relay.id, session);
    hub.changed(&relay.id);
    hub.clients_changed();
    match ended {
        Ok(why) => eprintln!("vk-hub: {peer}: relay {} disconnected: {why}", relay.id),
        Err(e) => {
            eprintln!("vk-hub: {peer}: relay {} session ended: {e:#}", relay.id);
            let _ = tokio::time::timeout(HANDSHAKE_STEP, ws.close(None)).await;
        }
    }
}

/// Record the session and welcome the relay, unless it was removed or superseded.
async fn welcome(ws: &mut Ws, hub: &Arc<Hub>, relay: &Peer, session: u64) -> Result<(), Refusal> {
    let (db, live) = (hub.db.clone(), hub.clone());
    let (id, incarnation, version) = (relay.id.clone(), relay.incarnation.clone(), relay.version);
    let recorded = tokio::task::spawn_blocking(move || {
        db.record_relay_session(&id, &incarnation, version, crate::now_secs(), || {
            live.is_current(&id, session)
        })
    })
    .await?;
    match recorded {
        Ok(true) => {}
        Ok(false) => return Err(Refusal::new(RefusalCode::Superseded, SUPERSEDED)),
        Err(e) if e.is::<NotEnrolled>() => return Err(Refusal::new(RefusalCode::Revoked, REMOVED)),
        Err(e) => return Err(e.into()),
    }
    let text = serde_json::to_string(&HubMsg::Welcome {
        heartbeat_secs: HEARTBEAT_SECS,
    })
    .map_err(anyhow::Error::from)?;
    send_text(ws, text).await.map_err(Refusal::gone)
}

/// Store what the relay reports, tell it its server's status once it is bound to one and
/// whenever that changes, ping it every heartbeat, and end when it goes quiet. `Ok` carries
/// why the session ended normally.
async fn serve(
    ws: &mut Ws,
    hub: &Arc<Hub>,
    relay: &Peer,
    session: u64,
    ending: &Ending,
) -> Result<&'static str> {
    let quiet = HEARTBEAT * MISSED_HEARTBEATS;
    let mut ping = tokio::time::interval(HEARTBEAT);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = tokio::time::Instant::now() + quiet;
    let mut told: Option<ServerStatus> = None;
    loop {
        tokio::select! {
            () = ending.notify.notified() => {
                let (code, reason, why) = if ending.revoked.load(Ordering::Relaxed) {
                    (RefusalCode::Revoked, REMOVED, "removed")
                } else {
                    (RefusalCode::Superseded, SUPERSEDED, "superseded by a newer session")
                };
                refuse(ws, code, reason).await;
                return Ok(why);
            }
            () = ending.kick.notified() => tell_status(ws, hub, relay, &mut told).await?,
            _ = ping.tick() => {
                tokio::time::timeout(HEARTBEAT, ws.send(Message::Ping(Default::default())))
                    .await
                    .map_err(|_| anyhow!("the relay is not reading"))?
                    .map_err(|e| anyhow!("pinging: {e}"))?;
            }
            () = tokio::time::sleep_until(deadline) => {
                bail!("nothing heard for {}s", quiet.as_secs());
            }
            frame = ws.next() => {
                let text = match frame {
                    None => return Ok("connection closed"),
                    Some(Err(e)) => bail!("reading: {e}"),
                    Some(Ok(Message::Close(_))) => return Ok("closed by the relay"),
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        deadline = tokio::time::Instant::now() + quiet;
                        hub.heard(&relay.id, session);
                        continue;
                    }
                    Some(Ok(_)) => bail!("the relay sent a frame that is not text"),
                };
                deadline = tokio::time::Instant::now() + quiet;
                hub.heard(&relay.id, session);
                let msg: RelayMsg = serde_json::from_str(text.as_str())
                    .context("the relay sent a message this hub does not understand")?;
                let mut inventory = false;
                let write = match msg {
                    RelayMsg::Inventory(mut i) => {
                        // Refused rather than made display-safe: the URL is the server's
                        // identity, which no cut or dropped character may change.
                        if normalize_gitlab_url(&i.server.url).is_none()
                            || vk_hub_proto::display_safe(&i.server.url) != i.server.url
                        {
                            let reason = "its GitLab server's URL is not a printable http(s) URL \
                                          of at most 256 characters";
                            refuse(ws, RefusalCode::Protocol, reason).await;
                            bail!("{reason}");
                        }
                        let over = |n: u32| {
                            usize::try_from(n)
                                .map_or(true, |n| n > vk_hub_proto::gitlab::MAX_ADMISSIONS)
                        };
                        if i.runners.len() > vk_hub_proto::gitlab::MAX_RUNNERS
                            || i.runners.iter().any(|r| over(r.request_concurrency))
                        {
                            let reason = "relay inventory exceeds the hub's runner or request limit";
                            refuse(ws, RefusalCode::Protocol, reason).await;
                            bail!("{reason}");
                        }
                        i.make_display_safe();
                        inventory = true;
                        RelayWrite::Inventory(i)
                    }
                    RelayMsg::Heartbeat(mut h) => {
                        h.make_display_safe();
                        RelayWrite::Heartbeat(h)
                    }
                    RelayMsg::Report(mut r) => {
                        r.make_display_safe();
                        RelayWrite::Report(r)
                    }
                };
                if let Some(why) = store(ws, hub, relay, session, write).await? {
                    return Ok(why);
                }
                if inventory {
                    tell_status(ws, hub, relay, &mut told).await?;
                }
            }
        }
    }
}

/// Send the relay its server's status if it is bound to one and `told` is not it already.
async fn tell_status(
    ws: &mut Ws,
    hub: &Hub,
    relay: &Peer,
    told: &mut Option<ServerStatus>,
) -> Result<()> {
    let db = hub.db.clone();
    let id = relay.id.clone();
    let status = tokio::task::spawn_blocking(move || db.relay_with_status(&id))
        .await??
        .and_then(|(_, status)| status);
    if let Some(status) = status
        && told.as_ref() != Some(&status)
    {
        send(ws, &HubRelayMsg::Server(status.clone())).await?;
        *told = Some(status);
    }
    Ok(())
}

/// Store `write`; `Some` carries why the session ends, the relay having been removed.
async fn store(
    ws: &mut Ws,
    hub: &Arc<Hub>,
    relay: &Peer,
    session: u64,
    write: RelayWrite,
) -> Result<Option<&'static str>> {
    let db = hub.db.clone();
    let id = relay.id.clone();
    let now = crate::now_secs();
    // The adapters and server pages follow relay changes.
    // Load refreshes every heartbeat interval.
    let shown = !matches!(write, RelayWrite::Heartbeat(_));
    let received = tokio::time::Instant::now();
    let live = hub.clone();
    let written = tokio::task::spawn_blocking(move || {
        db.record_relay_from_session(&id, write, now, Some(session), || {
            live.is_current(&id, session)
        })
    })
    .await?;
    match written {
        // Superseded by a newer session: nothing was stored.
        Ok(false) => Ok(None),
        Ok(true) => {
            if !shown {
                hub.heartbeat_stored(&relay.id, session, received);
            }
            hub.changed(&relay.id);
            if shown {
                hub.clients_changed();
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

/// End the session with [`HubRelayMsg::Refused`], then close.
async fn refuse(ws: &mut Ws, code: RefusalCode, reason: &str) {
    let msg = HubRelayMsg::Refused {
        code,
        reason: reason.to_string(),
    };
    let _ = tokio::time::timeout(HANDSHAKE_STEP, async {
        let _ = send(ws, &msg).await;
        let _ = ws.close(None).await;
    })
    .await;
}

async fn send(ws: &mut Ws, msg: &HubRelayMsg) -> Result<()> {
    send_text(
        ws,
        serde_json::to_string(msg).context("encoding a message")?,
    )
    .await
}

async fn send_text(ws: &mut Ws, text: String) -> Result<()> {
    tokio::time::timeout(HEARTBEAT, ws.send(Message::text(text)))
        .await
        .map_err(|_| anyhow!("the relay is not reading"))?
        .map_err(|e| anyhow!("sending: {e}"))
}

/// A relay as `vk-hub relays` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayView {
    pub id: String,
    pub connected: bool,
    /// Its server's status, once it is bound to one.
    #[serde(default)]
    pub server: Option<ServerStatus>,
    #[serde(flatten)]
    pub row: RelayRow,
}

/// Every relay, with whether it has a session now.
pub fn views(hub: &Hub) -> Result<Vec<RelayView>> {
    let mut views: Vec<RelayView> = hub
        .db
        .relays_with_status()?
        .into_iter()
        .map(|(id, row, server)| view(hub, id, row, server))
        .collect();
    views.sort_by(|a, b| a.row.hostname.cmp(&b.row.hostname).then(a.id.cmp(&b.id)));
    Ok(views)
}

/// Relay `id`; `None` when there is none.
pub fn detail(hub: &Hub, id: &str) -> Result<Option<RelayView>> {
    Ok(hub
        .db
        .relay_with_status(id)?
        .map(|(row, server)| view(hub, id.to_string(), row, server)))
}

fn view(hub: &Hub, id: String, row: RelayRow, server: Option<ServerStatus>) -> RelayView {
    RelayView {
        connected: hub.reach(&id) == Reach::Connected,
        id,
        server,
        row,
    }
}

/// Remove relay `id` as `actor` and end its session; whether there was one.
pub fn remove(hub: &Hub, actor: &str, id: &str) -> Result<bool> {
    let removed = hub.db.remove_relay(id, actor, crate::now_secs())?;
    if removed {
        hub.revoke(id);
        hub.touch();
        hub.clients_changed();
    }
    Ok(removed)
}

/// Have the sessions of the relays bound to the server at `url` tell them its status anew,
/// after an operator approved, rejected or forgot it.
pub fn server_changed(hub: &Hub, url: &str) -> Result<()> {
    for id in hub.db.relays_of(url)? {
        hub.kick(&id);
        hub.changed(&id);
    }
    hub.clients_changed();
    Ok(())
}

/// The columns of `vk-hub relays`.
pub const COLUMNS: [&str; 7] = [
    "ID",
    "NAME",
    "REACH",
    "VERSION",
    "GITLAB",
    "RUNNERS",
    "LAST SEEN",
];

/// A relay's row in [`COLUMNS`] at `now`. Its strings are the relay's own, made safe to print
/// when they were stored.
pub fn cells(r: &RelayView, now: u64) -> [String; 7] {
    let inventory = r.row.inventory.as_ref();
    [
        r.id.clone(),
        r.row.hostname.clone(),
        if r.connected {
            "connected"
        } else {
            "unreachable"
        }
        .to_string(),
        inventory.map_or("-".to_string(), |i| i.version.clone()),
        r.server.as_ref().map_or("-".to_string(), server_text),
        inventory.map_or("-".to_string(), |i| i.runners.len().to_string()),
        r.row.last_seen.map_or("never".to_string(), |at| {
            format!(
                "{} ago",
                crate::human_duration(crate::ago(now, at)).trim_end()
            )
        }),
    ]
}

/// A server's status in a word or two: its name once approved, else its URL and state.
pub fn server_text(s: &ServerStatus) -> String {
    match (s.state, &s.name) {
        (ServerState::Approved, Some(name)) => name.clone(),
        (ServerState::Approved, None) => format!("{} (approved)", s.url),
        (ServerState::Pending, _) => format!("{} (pending)", s.url),
        (ServerState::Rejected, _) => format!("{} (rejected)", s.url),
        (ServerState::Rebound, _) => format!("{} (reports another server)", s.url),
        (ServerState::Other, _) => s.url.clone(),
    }
}

/// Lines to print under the table: what a column cannot say.
pub fn notes(r: &RelayView) -> Vec<String> {
    let mut notes = Vec::new();
    let name = &r.row.hostname;
    if let Some(s) = &r.server {
        match s.state {
            ServerState::Pending => notes.push(format!(
                "{name}: GitLab {} waits for approval: `vk-hub gitlabs approve {} --name <name>`",
                s.url, s.url
            )),
            ServerState::Rejected => notes.push(format!(
                "{name}: GitLab {} was rejected: `vk-hub gitlabs approve {} --name <name>` \
                 approves it",
                s.url, s.url
            )),
            ServerState::Rebound => {
                let reported = r
                    .row
                    .inventory
                    .as_ref()
                    .map_or("-", |i| i.server.url.as_str());
                notes.push(format!(
                    "{name}: reports GitLab {reported}, but is bound to {}: enroll it again",
                    s.url
                ));
            }
            _ => {}
        }
    }
    notes
}
