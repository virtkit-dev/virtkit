//! GitLab relay sessions, and the relay operations the admin socket serves. A session uses the
//! shared peer handshake, stores inventory, heartbeats and reports, and tells the relay the
//! status of the GitLab server it is bound to, again whenever an operator changes it. See
//! `docs/gitlab-relay-enrollment.md`.
//!
//! The hub issues an update only to a relay whose inventory says its `[hub] allow` lists
//! `update`. A relay in a session at version [`UPDATES`](vk_hub_proto::gitlab::UPDATES) is sent
//! the hub's pending commands, each once a session from its first report on, until it settles
//! them; it downloads the release from
//! [`vk_hub_proto::gitlab::RELEASE_PATH`] while the update is live. One from before updates is
//! sent none.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::OwnedSemaphorePermit;
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::gitlab::{
    ALLOW_UPDATE, Command, HubRelayMsg, Operation, RelayMsg, Report, ServerState, ServerStatus,
};
use vk_hub_proto::{CommandAck, HubMsg, RefusalCode};

use crate::server::{Ending, Exported, HEARTBEAT, HEARTBEAT_SECS, Hub, MISSED_HEARTBEATS, Reach};
use crate::session::{HANDSHAKE_STEP, Peer, PeerKind, Refusal, Ws, turn_away};
use crate::store::{NotEnrolled, Program, RelayRow, RelayWrite, Release, normalize_gitlab_url};

/// How long a command waits for its relay to take it.
pub(crate) const COMMAND_TTL: Duration = Duration::from_secs(86_400);

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
    // `/updates` shows whether each relay is connected.
    hub.touch();
    let ended = serve(&mut ws, &hub, &relay, session, &ending).await;
    hub.close_session(&relay.id, session);
    crate::jobs::relay_disconnected(&hub, &relay.id, session);
    hub.changed(&relay.id);
    hub.clients_changed();
    hub.touch();
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
    let mut steer = Steer {
        // A relay from before updates could not read a command.
        speaks_updates: relay.version >= vk_hub_proto::gitlab::UPDATES,
        ..Steer::default()
    };
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
            () = ending.kick.notified() => {
                tell_status(ws, hub, relay, &mut told).await?;
                steer.sync(ws, hub, relay).await?;
            }
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
                let mut first_report = None;
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
                        if !steer.reported {
                            steer.reported = true;
                            first_report = Some(r.clone());
                        }
                        RelayWrite::Report(r)
                    }
                    RelayMsg::Ack(ack) => {
                        acknowledge(ws, hub, relay, ack).await?;
                        continue;
                    }
                };
                if let Some(why) = store(ws, hub, relay, session, write).await? {
                    return Ok(why);
                }
                if inventory {
                    tell_status(ws, hub, relay, &mut told).await?;
                    steer.sync(ws, hub, relay).await?;
                }
                if let Some(report) = first_report {
                    settle_unreported_updates(hub, relay, session, report).await?;
                    steer.sync(ws, hub, relay).await?;
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

/// What a session has sent its relay of the hub's commands.
#[derive(Default)]
struct Steer {
    /// Whether the session's version has commands.
    speaks_updates: bool,
    /// Whether its first report came, which settles the updates it lost track of.
    reported: bool,
    sent_commands: HashSet<String>,
}

impl Steer {
    /// Send the relay each pending command once a session, after its first report, if its
    /// session's version takes them. A relay whose `[hub] allow` no longer lists what one
    /// needs is sent it all the same, and refuses it, rather than leave it to expire.
    async fn sync(&mut self, ws: &mut Ws, hub: &Hub, relay: &Peer) -> Result<()> {
        if !(self.speaks_updates && self.reported) {
            return Ok(());
        }
        let db = hub.db.clone();
        let id = relay.id.clone();
        let pending =
            tokio::task::spawn_blocking(move || db.pending_relay_commands(&id, crate::now_secs()))
                .await??;
        for command in pending {
            if self.sent_commands.insert(command.id.clone()) {
                send(ws, &HubRelayMsg::Command(command)).await?;
            }
        }
        Ok(())
    }
}

/// Settle the accepted updates `report`, the first of session `session`, does not name, while
/// that session is the relay's current one.
async fn settle_unreported_updates(
    hub: &Arc<Hub>,
    relay: &Peer,
    session: u64,
    report: Report,
) -> Result<()> {
    let (db, live) = (hub.db.clone(), hub.clone());
    let id = relay.id.clone();
    let settled = tokio::task::spawn_blocking(move || {
        db.settle_unreported_relay_updates(&id, &report, crate::now_secs(), || {
            live.is_current(&id, session)
        })
    })
    .await??;
    if settled {
        hub.changed(&relay.id);
        hub.touch();
    }
    Ok(())
}

/// Record the relay's command outcome and reply with [`HubRelayMsg::Recorded`].
async fn acknowledge(ws: &mut Ws, hub: &Hub, relay: &Peer, ack: CommandAck) -> Result<()> {
    let db = hub.db.clone();
    let id = relay.id.clone();
    let recorded = ack.clone();
    let news =
        tokio::task::spawn_blocking(move || db.record_relay_ack(&id, &ack, crate::now_secs()))
            .await??;
    if news {
        hub.changed(&relay.id);
        // A command's outcome: `/updates` shows an update's.
        hub.touch();
    }
    send(ws, &HubRelayMsg::Recorded(recorded)).await
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
                // `/updates` shows a relay's version and update from these.
                hub.touch();
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

/// Whether relay `row` lets the hub update it, as it last reported: `None` until it reports
/// its inventory.
pub fn takes_updates(row: &RelayRow) -> Option<bool> {
    let inventory = row.inventory.as_ref()?;
    Some(inventory.allow.iter().any(|a| a == ALLOW_UPDATE))
}

/// Why relay `row` would refuse to update to `release`, going by what it last reported: its
/// `[hub] allow` lacks `update`, or it takes only signed releases and this one is not. The
/// relay checks again, with what the hub cannot see: its keys, its version and its binary.
pub fn update_refusal(row: &RelayRow, release: &Release) -> Option<String> {
    if takes_updates(row) == Some(false) {
        return Some(format!(
            "relay {} does not let the hub update it: its [hub] allow lacks {ALLOW_UPDATE}",
            row.hostname
        ));
    }
    if row.inventory.as_ref().is_some_and(|i| i.requires_signed) && release.row.signature.is_none()
    {
        return Some(format!(
            "relay {} takes only signed releases, and {} {} is unsigned: add it with the \
             signature `vk release-key sign --program {}` makes",
            row.hostname,
            release.row.program(),
            release.row.version,
            Program::Gitlab
        ));
    }
    None
}

/// Refuse to update relay `row` to `release` when it is not a `vk-gitlab` release, or when
/// [`update_refusal`] says the relay would refuse it.
pub fn check_update(row: &RelayRow, release: &Release) -> Result<()> {
    let gitlab = Program::Gitlab;
    if !release.row.is(gitlab) {
        bail!(
            "release {} is {} {}, not a {gitlab} release: add one with `vk-hub release add \
             --program {gitlab}`",
            crate::store::short(&release.sha256),
            release.row.program(),
            release.row.version
        );
    }
    if let Some(why) = update_refusal(row, release) {
        bail!("{why}");
    }
    Ok(())
}

/// Update relay `id` to the `vk-gitlab` release whose sha256 starts with `release`.
pub fn update(hub: &Hub, actor: &str, id: &str, release: &str) -> Result<Command> {
    // Held from the lookup to the command, so the release cannot be removed between them.
    let _held = hub.releases_lock();
    let release = hub.db.resolve_release(release)?;
    issue_update(hub, actor, id, &release, None)
}

/// [`update`] relay `id` to `shown`, the release an operator confirmed for a relay running
/// `running` (`None`: not reported): refused unless the hub still holds the release as shown —
/// the same version and signature, not removed and added again otherwise — and the relay
/// still reports that version.
pub fn update_as_shown(
    hub: &Hub,
    actor: &str,
    id: &str,
    shown: &Release,
    running: Option<&str>,
) -> Result<Command> {
    let _held = hub.releases_lock();
    let held = hub.db.release(&shown.sha256)?;
    if held.as_ref() != Some(&shown.row) {
        bail!(
            "release {} changed since it was shown; look again",
            crate::store::short(&shown.sha256)
        );
    }
    issue_update(hub, actor, id, shown, Some(running))
}

/// Send relay `id` the update to `release`, the releases lock held; with `running`, only while
/// the relay reports that version.
fn issue_update(
    hub: &Hub,
    actor: &str,
    id: &str,
    release: &Release,
    running: Option<Option<&str>>,
) -> Result<Command> {
    let row = hub
        .db
        .relay(id)?
        .ok_or_else(|| NotEnrolled(id.to_string()))?;
    if let Some(running) = running
        && row.inventory.as_ref().map(|i| i.version.as_str()) != running
    {
        bail!(
            "relay {} changed version since it was shown; look again",
            row.hostname
        );
    }
    check_update(&row, release)?;
    let op = Operation::Update {
        version: release.row.version.clone(),
        sha256: release.sha256.clone(),
        size: release.row.size,
        signature: release.row.signature.clone(),
    };
    let command = hub
        .db
        .issue_relay_command(id, op, COMMAND_TTL, actor, crate::now_secs())?;
    eprintln!(
        "vk-hub: relay {id}: {actor} issued {} (command {})",
        crate::store::relay_operation_name(&command.op),
        command.id
    );
    hub.kick(id);
    hub.changed(id);
    hub.touch();
    Ok(command)
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
