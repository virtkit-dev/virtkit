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
//!
//! Likewise it adds a runner to, or removes one from, only a relay whose `[hub] allow` lists
//! `runners`, at version [`RUNNERS`](vk_hub_proto::gitlab::RUNNERS) or later — adds one only at
//! [`LANES`](vk_hub_proto::gitlab::LANES) or later, an older relay wanting a pool. An added
//! runner's token stays in memory, never stored, until the relay answers: a hub restarted
//! before then has lost it, and fails the add `token_lost` at the relay's next first report.
//!
//! A relay at version [`CONNECTION`](vk_hub_proto::gitlab::CONNECTION) holds its session on
//! its HTTP/2 connection, which the session authenticates for the relay's client API requests
//! and which ends with it. Every relay session is closed when the hub hands over to a release,
//! so that such a connection drains rather than holds the hand-over. Such a session tells its
//! relay when one of its tickets is granted or ends, and when one of its jobs not settled has a
//! new revision or more output ([`HubRelayMsg::Ticket`], [`HubRelayMsg::Job`]): it diffs the
//! dispatch state against what it last told, [`NOTICE_COALESCE`] after a change, so notices
//! never queue up beyond one per object.

use std::collections::{HashMap, HashSet};
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
    ALLOW_RUNNERS, ALLOW_UPDATE, Command, HubRelayMsg, LANES, MAX_ADMISSIONS, MAX_LABELS,
    MAX_RUNNERS, Operation, RUNNERS, RelayMsg, Report, Runner, RunnerPlacement, RunnerSource,
    RunnerToken, ServerState, ServerStatus,
};
use vk_hub_proto::{CommandAck, HubMsg, Outcome, RefusalCode};

use crate::jobs::TicketNotice;
use crate::server::{
    Ending, Exported, HEARTBEAT, HEARTBEAT_SECS, Hub, MISSED_HEARTBEATS, Reach, RelayConn,
};
use crate::session::{
    HANDSHAKE_STEP, Peer, PeerKind, RELAY_HTTP1, RELAY_HTTP2, Refusal, Ws, turn_away,
};
use crate::store::{
    NotEnrolled, Program, RelayCommandRow, RelayRow, RelayWrite, Release, normalize_gitlab_url,
};

/// How long a command waits for its relay to take it.
pub(crate) const COMMAND_TTL: Duration = Duration::from_secs(86_400);

/// What a relay removed from the hub is told.
const REMOVED: &str = "this relay was removed from the hub";

/// What a relay superseded by a newer session of its own is told.
const SUPERSEDED: &str = "superseded by a newer session of this relay";

/// How long a session waits after a change of the dispatch state before it tells its relay what
/// moved, so that a burst of changes, such as a job's output arriving, makes one notice.
const NOTICE_COALESCE: Duration = Duration::from_millis(50);

/// Run a relay's session on `ws`, log why it ended, then end its stream. `conn` is the HTTP/2
/// connection carrying the session, bound to the relay before its welcome; `None` for HTTP/1.1.
pub(crate) async fn run(
    mut ws: Ws,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
    permit: OwnedSemaphorePermit,
    conn: Option<RelayConn>,
) {
    session(&mut ws, hub, peer, exported, permit, conn).await;
    crate::session::finish(ws).await;
}

/// [`run`]'s session, up to its stream's end.
async fn session(
    ws: &mut Ws,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
    permit: OwnedSemaphorePermit,
    conn: Option<RelayConn>,
) {
    let versions = if conn.is_some() {
        RELAY_HTTP2
    } else {
        RELAY_HTTP1
    };
    let handshake = crate::session::handshake(ws, &hub, exported, PeerKind::Relay, versions).await;
    let relay = match handshake {
        Ok(r) => r,
        Err(r) => return turn_away(ws, peer, r).await,
    };
    let (session, ending) = hub.open_session(&relay.id);
    let welcomed = welcome(ws, &hub, &relay, session, conn.as_ref()).await;
    drop(permit);
    if let Err(r) = welcomed {
        hub.close_session(&relay.id, session);
        crate::jobs::relay_disconnected(&hub, &relay.id, session);
        return turn_away(ws, peer, r).await;
    }
    eprintln!(
        "vk-hub: {peer}: relay {} ({}) connected at protocol version {}",
        relay.id, relay.hostname, relay.version
    );
    hub.changed(&relay.id);
    hub.clients_changed();
    // `/updates` shows whether each relay is connected.
    hub.touch();
    let ended = serve(ws, &hub, &relay, session, &ending).await;
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

/// Record the session and welcome the relay, unless it was removed or superseded. Once
/// recorded, and before the welcome, mark `conn`, the relay's HTTP/2 connection, as the
/// session's.
async fn welcome(
    ws: &mut Ws,
    hub: &Arc<Hub>,
    relay: &Peer,
    session: u64,
    conn: Option<&RelayConn>,
) -> Result<(), Refusal> {
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
    if let Some(conn) = conn {
        conn.bind(&relay.id, &relay.hostname, session);
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
        version: relay.version,
        ..Steer::default()
    };
    let handover = hub.handover.gate.closing();
    tokio::pin!(handover);
    // Notices, at version 5: the first diff at once, from nothing, then one after each change.
    let notices = relay.version >= vk_hub_proto::gitlab::CONNECTION;
    let mut changes = hub.dispatch.subscribe();
    let mut noticed = Told::default();
    let mut due = notices.then(tokio::time::Instant::now);
    loop {
        tokio::select! {
            changed = changes.changed(), if notices && due.is_none() => {
                // The sender lives as long as the hub.
                if changed.is_ok() {
                    due = Some(tokio::time::Instant::now() + NOTICE_COALESCE);
                }
            }
            () = sleep_until_due(due) => {
                due = None;
                tell_notices(ws, hub, relay, &mut noticed).await?;
            }
            () = &mut handover => {
                // The relay redials into the listener's backlog, which the release accepts.
                // Best effort, bounded: a relay that does not read the close is cut with the
                // rest.
                let _ = tokio::time::timeout(HANDSHAKE_STEP, ws.close(None)).await;
                return Ok("closed for the hub's hand-over");
            }
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
                    record_added_runners(hub, relay).await?;
                    tell_status(ws, hub, relay, &mut told).await?;
                    steer.sync(ws, hub, relay).await?;
                }
                if let Some(report) = first_report {
                    settle_lost_commands(hub, relay, session, report).await?;
                    steer.sync(ws, hub, relay).await?;
                }
            }
        }
    }
}

/// Once `due`, never if `None`.
async fn sleep_until_due(due: Option<tokio::time::Instant>) {
    match due {
        Some(due) => tokio::time::sleep_until(due).await,
        None => std::future::pending().await,
    }
}

/// What a session last told its relay of each of its tickets and jobs.
#[derive(Default)]
struct Told {
    tickets: HashMap<String, TicketNotice>,
    jobs: HashMap<String, (u64, u64)>,
}

/// Tell the relay of each ticket and job that moved since `told`, read from the dispatch state
/// before sending: a ticket granted or ended (gone from the state, it ended too), unless the
/// relay claimed it; a job at a new revision or output length. Forget what left the state.
async fn tell_notices(ws: &mut Ws, hub: &Hub, relay: &Peer, told: &mut Told) -> Result<()> {
    let now = crate::jobs::notices(hub, &relay.id);
    let mut out = Vec::new();
    for (ticket, notice) in &now.tickets {
        let before = told.tickets.get(ticket);
        if before != Some(notice)
            && before != Some(&TicketNotice::Claimed)
            && matches!(notice, TicketNotice::Granted | TicketNotice::Ended)
        {
            out.push(HubRelayMsg::Ticket {
                ticket: ticket.clone(),
            });
        }
    }
    for (ticket, before) in &told.tickets {
        if !now.tickets.contains_key(ticket)
            && matches!(before, TicketNotice::Queued | TicketNotice::Granted)
        {
            out.push(HubRelayMsg::Ticket {
                ticket: ticket.clone(),
            });
        }
    }
    for (job, &(revision, output_len)) in &now.jobs {
        if told.jobs.get(job) != Some(&(revision, output_len)) {
            out.push(HubRelayMsg::Job {
                job: job.clone(),
                revision,
                output_len,
            });
        }
    }
    *told = Told {
        tickets: now.tickets,
        jobs: now.jobs,
    };
    if out.is_empty() {
        return Ok(());
    }
    // One batch, bounded by the heartbeat as one send is: a relay reading slowly cannot hold
    // the session's loop for longer by having it send many.
    let texts = (out.iter())
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .context("encoding a notice")?;
    tokio::time::timeout(HEARTBEAT, async {
        for text in texts {
            ws.feed(Message::text(text)).await?;
        }
        ws.flush().await
    })
    .await
    .map_err(|_| anyhow!("the relay is not reading"))?
    .map_err(|e| anyhow!("sending: {e}"))
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
    /// The session's protocol version.
    version: u32,
    /// Whether its first report came, which settles the commands the hub lost track of.
    reported: bool,
    sent_commands: HashSet<String>,
}

impl Steer {
    /// Send each pending command once per session, after its first report, if the protocol
    /// version supports it. Include the token for an added runner. Send commands even if
    /// `[hub] allow` no longer permits them, so the relay refuses them rather than leave
    /// them to expire.
    async fn sync(&mut self, ws: &mut Ws, hub: &Hub, relay: &Peer) -> Result<()> {
        // A relay from before updates could not read a command.
        if !(self.version >= vk_hub_proto::gitlab::UPDATES && self.reported) {
            return Ok(());
        }
        let db = hub.db.clone();
        let id = relay.id.clone();
        let now = crate::now_secs();
        let pending =
            tokio::task::spawn_blocking(move || db.pending_relay_commands(&id, now)).await??;
        for mut command in pending {
            if command.op.min_version() > self.version || self.sent_commands.contains(&command.id) {
                continue;
            }
            if let Operation::AddRunner { token, .. } = &mut command.op {
                // Lost with a restart: settled at the first report.
                let Some(held) = hub.runner_tokens.get(&command.id, now) else {
                    continue;
                };
                *token = held;
            }
            self.sent_commands.insert(command.id.clone());
            send(ws, &HubRelayMsg::Command(command)).await?;
        }
        Ok(())
    }
}

/// The tokens of runners added on the hub, by the command adding each, until the relay
/// answers it or it expires. Never stored, logged or shown.
#[derive(Default)]
pub(crate) struct RunnerTokens(Arc<std::sync::Mutex<TokenMap>>);

type TokenMap = HashMap<String, (RunnerToken, u64)>;

fn lock_tokens(tokens: &std::sync::Mutex<TokenMap>) -> std::sync::MutexGuard<'_, TokenMap> {
    tokens
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl RunnerTokens {
    fn lock(&self) -> std::sync::MutexGuard<'_, TokenMap> {
        lock_tokens(&self.0)
    }

    /// Hold `token` for command `command` until `expires_at`, when it is dropped unanswered.
    fn hold(&self, command: &str, token: RunnerToken, expires_at: u64, now: u64) {
        let mut tokens = self.lock();
        tokens.retain(|_, (_, at)| *at > now);
        tokens.insert(command.to_string(), (token, expires_at));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let (tokens, command) = (self.0.clone(), command.to_string());
            let wait = Duration::from_secs(expires_at.saturating_sub(now));
            runtime.spawn(async move {
                tokio::time::sleep(wait).await;
                lock_tokens(&tokens).remove(&command);
            });
        }
    }

    /// Command `command`'s token, unless lost or expired by `now`.
    fn get(&self, command: &str, now: u64) -> Option<RunnerToken> {
        self.lock()
            .get(command)
            .filter(|(_, at)| *at > now)
            .map(|(t, _)| t.clone())
    }

    /// Whether the hub has command `command`'s token.
    pub(crate) fn holds(&self, command: &str) -> bool {
        self.lock().contains_key(command)
    }

    /// Drop command `command`'s token: the relay answered it.
    pub(crate) fn forget(&self, command: &str) {
        self.lock().remove(command);
    }
}

/// Settle what `report`, the first of session `session`, shows the hub lost track of, while
/// that session is the relay's current one.
async fn settle_lost_commands(
    hub: &Arc<Hub>,
    relay: &Peer,
    session: u64,
    report: Report,
) -> Result<()> {
    let (db, live, tokens) = (hub.db.clone(), hub.clone(), hub.clone());
    let id = relay.id.clone();
    let settled = tokio::task::spawn_blocking(move || {
        db.settle_lost_relay_commands(
            &id,
            &report,
            crate::now_secs(),
            |command| tokens.runner_tokens.holds(command),
            || live.is_current(&id, session),
        )
    })
    .await??;
    if settled {
        hub.changed(&relay.id);
        // GitLab's Overview shows a runner command's outcome; `/updates` an update's.
        hub.clients_changed();
        hub.touch();
    }
    Ok(())
}

/// Take the GitLab IDs of the runners the relay added from its new inventory, for the adds it
/// acked done before.
async fn record_added_runners(hub: &Hub, relay: &Peer) -> Result<()> {
    let db = hub.db.clone();
    let id = relay.id.clone();
    let taken =
        tokio::task::spawn_blocking(move || db.record_added_runners(&id, crate::now_secs()))
            .await??;
    if taken {
        hub.changed(&relay.id);
        hub.clients_changed();
    }
    Ok(())
}

/// Record the relay's command outcome and reply with [`HubRelayMsg::Recorded`]. An answered
/// add's token is dropped: the relay journaled the command, and answers it again from there.
async fn acknowledge(ws: &mut Ws, hub: &Hub, relay: &Peer, ack: CommandAck) -> Result<()> {
    hub.runner_tokens.forget(&ack.id);
    let db = hub.db.clone();
    let id = relay.id.clone();
    let recorded = ack.clone();
    let news =
        tokio::task::spawn_blocking(move || db.record_relay_ack(&id, &ack, crate::now_secs()))
            .await??;
    if news {
        hub.changed(&relay.id);
        // A command's outcome: GitLab's Overview shows a runner command's, `/updates` an
        // update's.
        hub.clients_changed();
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

/// A runner a relay reports, by its approved instance's name and GitLab ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportedRunner {
    pub gitlab: String,
    pub id: u64,
    /// Its name in the relay's config, display-safe.
    pub name: String,
}

/// Runners reported in `views` with a GitLab ID under an approved instance, sorted and
/// deduplicated by instance and ID. The first relay reporting each supplies its name.
pub fn reported_runners(views: &[RelayView]) -> Vec<ReportedRunner> {
    let mut runners = Vec::new();
    for relay in views {
        let Some(gitlab) = relay.server.as_ref().and_then(|s| s.name.as_ref()) else {
            continue;
        };
        for runner in relay.row.inventory.iter().flat_map(|i| &i.runners) {
            if let Some(id) = runner.runner_id {
                runners.push(ReportedRunner {
                    gitlab: gitlab.clone(),
                    id,
                    name: vk_hub_proto::display_safe(&runner.name),
                });
            }
        }
    }
    // Stable sorting preserves the first report's name through deduplication.
    runners.sort_by(|a, b| (&a.gitlab, a.id).cmp(&(&b.gitlab, b.id)));
    runners.dedup_by(|a, b| (&a.gitlab, a.id) == (&b.gitlab, b.id));
    runners
}

/// Page label for runner `id` of `gitlab`, e.g. "Runner 42 app-main".
/// Include the name from `runners` when reported and the instance when `gitlabs` exceeds one.
pub fn runner_lane_label(
    runners: &[ReportedRunner],
    gitlabs: usize,
    gitlab: &str,
    id: u64,
) -> String {
    let mut label = format!("Runner {id}");
    if let Some(r) = (runners.iter()).find(|r| r.gitlab == gitlab && r.id == id) {
        label.push(' ');
        label.push_str(&r.name);
    }
    if gitlabs > 1 {
        label.push_str(&format!(" ({gitlab})"));
    }
    label
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
    let command =
        hub.db
            .issue_relay_command(id, op, COMMAND_TTL, actor, crate::now_secs(), |_| {})?;
    issued(hub, actor, id, &command);
    Ok(command)
}

/// Log `command`, just issued, and have relay `id`'s session send it.
fn issued(hub: &Hub, actor: &str, id: &str, command: &Command) {
    eprintln!(
        "vk-hub: relay {id}: {actor} issued {} (command {})",
        crate::store::relay_operation_name(&command.op),
        command.id
    );
    hub.kick(id);
    hub.changed(id);
    hub.clients_changed();
    hub.touch();
}

/// How a runner added on the hub is set up: a `[[runners]]` table's settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerSettings {
    pub placement: RunnerPlacement,
    /// Its `limit`, when limited.
    pub limit: Option<u32>,
    /// Its `request_concurrency`, at least 1.
    pub request_concurrency: u32,
}

/// The longest runner name the hub takes: it names files on the relay.
pub const MAX_RUNNER_NAME: usize = 64;

/// Refuse what the relay would: a runner name that is not letters, digits, `-`, `_` and `.`
/// (not first), and settings a `[[runners]]` table may not have, as `vk-gitlab` checks them.
pub fn check_runner(name: &str, token: &RunnerToken, settings: &RunnerSettings) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_RUNNER_NAME
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!(
            "a runner name is 1 to {MAX_RUNNER_NAME} letters, digits, `-`, `_` and `.`, not \
             starting with `.`"
        );
    }
    let t = token.expose();
    if t.is_empty() || t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("the runner token is empty or has spaces in it");
    }
    let p = &settings.placement;
    let printable = |s: &str| vk_hub_proto::display_safe(s) == s;
    if p.labels.len() > MAX_LABELS {
        bail!("a runner has at most {MAX_LABELS} labels");
    }
    let mut labels = HashSet::new();
    for l in &p.labels {
        if l.trim().is_empty() || !printable(l) {
            bail!("labels must be printable and not empty");
        }
        if !labels.insert(l.as_str()) {
            bail!("label {l:?} is listed twice");
        }
    }
    let e = p.envelope;
    if e.mem_mib == 0 || e.cpus == 0 || e.disk_bytes == 0 {
        bail!("the envelope's mem (at least 1M), cpus and disk must be set");
    }
    if settings.limit == Some(0) {
        bail!("limit must be at least 1");
    }
    let most = u32::try_from(MAX_ADMISSIONS).unwrap_or(u32::MAX);
    if !(1..=most).contains(&settings.request_concurrency) {
        bail!("request_concurrency must be 1 to {most}");
    }
    Ok(())
}

/// Why relay `row` would refuse runner commands, going by what it last reported: no
/// inventory yet, a `[hub] allow` lacking `runners`, or a protocol below [`RUNNERS`].
pub fn runners_refusal(row: &RelayRow) -> Option<String> {
    let name = &row.hostname;
    let Some(inventory) = &row.inventory else {
        return Some(format!("relay {name} has not reported its runners yet"));
    };
    if !inventory.allow.iter().any(|a| a == ALLOW_RUNNERS) {
        return Some(format!(
            "relay {name} does not let the hub add or remove its runners: its [hub] allow \
             lacks {ALLOW_RUNNERS}"
        ));
    }
    if row.protocol.unwrap_or(0) < RUNNERS {
        return Some(format!(
            "relay {name} runs a vk-gitlab that cannot take runners from the hub: update it"
        ));
    }
    None
}

/// Why relay `row` would refuse a runner added from the hub: [`runners_refusal`], or a protocol
/// below [`LANES`], which reads an added runner only with a pool.
pub fn add_runner_refusal(row: &RelayRow) -> Option<String> {
    if let Some(why) = runners_refusal(row) {
        return Some(why);
    }
    if row.protocol.unwrap_or(0) < LANES {
        return Some(format!(
            "relay {} runs an older vk-gitlab: update it to add runners from the hub",
            row.hostname
        ));
    }
    None
}

/// Relay `id`, unless `refusal` rejects its last reported state.
fn taking_runners(
    hub: &Hub,
    id: &str,
    refusal: fn(&RelayRow) -> Option<String>,
) -> Result<RelayRow> {
    let row = hub
        .db
        .relay(id)?
        .ok_or_else(|| NotEnrolled(id.to_string()))?;
    if let Some(why) = refusal(&row) {
        bail!(why);
    }
    Ok(row)
}

/// Add runner `name` to relay `id` with the runner authentication token `token`, GitLab
/// created, and `settings`. The token goes to the relay and nowhere else.
pub fn add_runner(
    hub: &Hub,
    actor: &str,
    id: &str,
    name: &str,
    token: RunnerToken,
    settings: RunnerSettings,
) -> Result<Command> {
    check_runner(name, &token, &settings)?;
    let row = taking_runners(hub, id, add_runner_refusal)?;
    let runners = row.inventory.as_ref().map_or(&[][..], |i| &i.runners[..]);
    if runners.iter().any(|r| r.name == name) {
        bail!("relay {} has a runner named {name} already", row.hostname);
    }
    if runners.len() >= MAX_RUNNERS {
        bail!("relay {} runs {MAX_RUNNERS} runners already", row.hostname);
    }
    let op = Operation::AddRunner {
        name: name.to_string(),
        token: RunnerToken::default(),
        placement: settings.placement,
        limit: settings.limit,
        request_concurrency: settings.request_concurrency,
    };
    let now = crate::now_secs();
    let command = hub
        .db
        .issue_relay_command(id, op, COMMAND_TTL, actor, now, |c| {
            hub.runner_tokens.hold(&c.id, token, c.expires_at, now);
        })?;
    issued(hub, actor, id, &command);
    Ok(command)
}

/// Remove runner `name`, added on the hub, from relay `id`: it takes no new job, and goes once
/// its jobs end. With `added_by`, only the runner that command added.
pub fn remove_runner(
    hub: &Hub,
    actor: &str,
    id: &str,
    name: &str,
    added_by: Option<&str>,
) -> Result<Command> {
    let row = taking_runners(hub, id, runners_refusal)?;
    let Some(runner) = row
        .inventory
        .as_ref()
        .and_then(|i| i.runners.iter().find(|r| r.name == name))
    else {
        bail!("relay {} reports no runner {name}", row.hostname);
    };
    let (RunnerSource::Hub, Some(runner_id), Some(command)) =
        (runner.source, runner.runner_id, runner.command.clone())
    else {
        bail!(
            "runner {name} was not added on the hub: remove it from relay {}'s config",
            row.hostname
        );
    };
    if added_by.is_some_and(|added_by| added_by != command) {
        bail!("runner {name} was added again since: look at it again");
    }
    let op = Operation::RemoveRunner {
        name: name.to_string(),
        runner_id,
        command,
    };
    let command =
        hub.db
            .issue_relay_command(id, op, COMMAND_TTL, actor, crate::now_secs(), |_| {})?;
    issued(hub, actor, id, &command);
    Ok(command)
}

/// Where a relay's runner comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerOrigin<'a> {
    Config,
    /// Added on the hub by command `added_by`, when the relay names it; `removing` once a
    /// removal of it is under way or done.
    Hub {
        added_by: Option<&'a str>,
        removing: bool,
    },
    /// A source from a later relay.
    Other,
}

/// Where runner `r` comes from, its removal looked up in `commands` as of `now`.
pub fn runner_origin<'a>(
    r: &'a Runner,
    commands: &[RelayCommandRow],
    now: u64,
) -> RunnerOrigin<'a> {
    match r.source {
        RunnerSource::Config => RunnerOrigin::Config,
        RunnerSource::Hub => {
            let added_by = r.command.as_deref();
            let removing = added_by.is_some_and(|added_by| {
                commands.iter().any(|c| {
                    matches!(&c.command.op, Operation::RemoveRunner { command, .. } if command == added_by)
                        && match c.outcome {
                            None => c.command.expires_at > now,
                            Some(Outcome::Accepted | Outcome::Done) => true,
                            Some(_) => false,
                        }
                })
            });
            RunnerOrigin::Hub { added_by, removing }
        }
        RunnerSource::Other => RunnerOrigin::Other,
    }
}

/// Where runner `r` comes from, as `vk-hub relays show` says it: `config`, or `hub` and the
/// command that added it, `being removed` once `commands` hold its removal not failed by
/// `now`.
pub fn runner_source(r: &Runner, commands: &[RelayCommandRow], now: u64) -> String {
    match runner_origin(r, commands, now) {
        RunnerOrigin::Config => "config".to_string(),
        RunnerOrigin::Hub {
            added_by: Some(added_by),
            removing,
        } => {
            if removing {
                format!("hub ({added_by}), being removed")
            } else {
                format!("hub ({added_by})")
            }
        }
        RunnerOrigin::Hub { added_by: None, .. } => "hub".to_string(),
        RunnerOrigin::Other => "other".to_string(),
    }
}

/// The latest runner command in a relay's `commands`.
pub fn last_runner_command(commands: &[RelayCommandRow]) -> Option<&RelayCommandRow> {
    commands
        .iter()
        .filter(|c| {
            matches!(
                c.command.op,
                Operation::AddRunner { .. } | Operation::RemoveRunner { .. }
            )
        })
        .max_by_key(|c| c.seq)
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
