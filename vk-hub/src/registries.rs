//! Registry sessions and operations shared by the admin socket and web UI.
//! Sessions use the shared peer handshake, store inventory, heartbeats, usage and reports,
//! and send desired state and commands. See `docs/registry-hub.md`.

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
use vk_hub_proto::registry::{
    Command, DesiredState, GcPolicy, HubRegistryMsg, Operation, RegistryMsg, Report,
};
use vk_hub_proto::{HubMsg, RefusalCode};

use crate::server::{Ending, Exported, HEARTBEAT, HEARTBEAT_SECS, Hub, MISSED_HEARTBEATS, Reach};
use crate::session::{HANDSHAKE_STEP, Peer, PeerKind, Refusal, Ws, turn_away};
use crate::store::{
    NotEnrolled, REGISTRY_PROGRAM, RegistryChange, RegistryCommandRow, RegistryRow, RegistryWrite,
};

/// The gc windows `vk-hub registries gc` and `gc-schedule`, and the web UI's forms, default to.
pub const GC_RETENTION_DAYS: u64 = 30;
pub const GC_GRACE_DAYS: u64 = 1;

/// How long a command waits for its registry to take it.
const COMMAND_TTL: Duration = Duration::from_secs(86_400);

/// What a registry removed from the hub is told.
const REMOVED: &str = "this registry was removed from the hub";

/// Run a registry's session on `ws` to its end, logging why it ended.
pub async fn run(
    mut ws: Ws,
    hub: Arc<Hub>,
    peer: SocketAddr,
    exported: Exported,
    permit: OwnedSemaphorePermit,
) {
    let registry =
        match crate::session::handshake(&mut ws, &hub, exported, PeerKind::Registry).await {
            Ok(r) => r,
            Err(r) => return turn_away(&mut ws, peer, r).await,
        };
    let (session, ending) = hub.open_session(&registry.id);
    let welcomed = welcome(&mut ws, &hub, &registry, session).await;
    drop(permit);
    if let Err(r) = welcomed {
        hub.close_session(&registry.id, session);
        return turn_away(&mut ws, peer, r).await;
    }
    eprintln!(
        "vk-hub: {peer}: registry {} ({}) connected",
        registry.id, registry.hostname
    );
    hub.changed(&registry.id);
    let ended = serve(&mut ws, &hub, &registry, session, &ending).await;
    hub.close_session(&registry.id, session);
    hub.changed(&registry.id);
    match ended {
        Ok(why) => eprintln!(
            "vk-hub: {peer}: registry {} disconnected: {why}",
            registry.id
        ),
        Err(e) => {
            eprintln!(
                "vk-hub: {peer}: registry {} session ended: {e:#}",
                registry.id
            );
            let _ = tokio::time::timeout(HANDSHAKE_STEP, ws.close(None)).await;
        }
    }
}

/// Record the session and welcome the registry, unless it was removed or superseded.
async fn welcome(
    ws: &mut Ws,
    hub: &Arc<Hub>,
    registry: &Peer,
    session: u64,
) -> Result<(), Refusal> {
    let (db, live) = (hub.db.clone(), hub.clone());
    let (id, incarnation, version) = (
        registry.id.clone(),
        registry.incarnation.clone(),
        registry.version,
    );
    let recorded = tokio::task::spawn_blocking(move || {
        db.record_registry_session(&id, &incarnation, version, crate::now_secs(), || {
            live.is_current(&id, session)
        })
    })
    .await?;
    match recorded {
        Ok(true) => {}
        Ok(false) => {
            return Err(Refusal::new(
                RefusalCode::Superseded,
                "superseded by a newer session of this registry",
            ));
        }
        Err(e) if e.is::<NotEnrolled>() => return Err(Refusal::new(RefusalCode::Revoked, REMOVED)),
        Err(e) => return Err(e.into()),
    }
    let text = serde_json::to_string(&HubMsg::Welcome {
        heartbeat_secs: HEARTBEAT_SECS,
    })
    .map_err(anyhow::Error::from)?;
    send_text(ws, text).await.map_err(Refusal::gone)
}

/// Store what the registry reports, send it what the hub wants of it, ping it every
/// heartbeat, and end when it goes quiet. `Ok` carries why the session ended normally.
async fn serve(
    ws: &mut Ws,
    hub: &Arc<Hub>,
    registry: &Peer,
    session: u64,
    ending: &Ending,
) -> Result<&'static str> {
    let quiet = HEARTBEAT * MISSED_HEARTBEATS;
    let mut ping = tokio::time::interval(HEARTBEAT);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = tokio::time::Instant::now() + quiet;
    let mut steer = Steer::default();
    loop {
        tokio::select! {
            () = ending.notify.notified() => {
                let (code, reason, why) = if ending.revoked.load(Ordering::Relaxed) {
                    (RefusalCode::Revoked, REMOVED, "removed")
                } else {
                    (
                        RefusalCode::Superseded,
                        "superseded by a newer session of this registry",
                        "superseded by a newer session",
                    )
                };
                refuse(ws, code, reason).await;
                return Ok(why);
            }
            () = ending.kick.notified() => steer.sync(ws, hub, registry).await?,
            _ = ping.tick() => {
                tokio::time::timeout(HEARTBEAT, ws.send(Message::Ping(Default::default())))
                    .await
                    .map_err(|_| anyhow!("the registry is not reading"))?
                    .map_err(|e| anyhow!("pinging: {e}"))?;
            }
            () = tokio::time::sleep_until(deadline) => {
                bail!("nothing heard for {}s", quiet.as_secs());
            }
            frame = ws.next() => {
                let text = match frame {
                    None => return Ok("connection closed"),
                    Some(Err(e)) => bail!("reading: {e}"),
                    Some(Ok(Message::Close(_))) => return Ok("closed by the registry"),
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        deadline = tokio::time::Instant::now() + quiet;
                        hub.heard(&registry.id, session);
                        continue;
                    }
                    Some(Ok(_)) => bail!("the registry sent a frame that is not text"),
                };
                deadline = tokio::time::Instant::now() + quiet;
                hub.heard(&registry.id, session);
                let msg: RegistryMsg = serde_json::from_str(text.as_str())
                    .context("the registry sent a message this hub does not understand")?;
                let mut report = None;
                let mut inventory = false;
                let write = match msg {
                    RegistryMsg::Inventory(mut i) => {
                        i.make_display_safe();
                        inventory = true;
                        RegistryWrite::Inventory(i)
                    }
                    RegistryMsg::Heartbeat(h) => RegistryWrite::Heartbeat(h),
                    RegistryMsg::Usage(mut u) => {
                        u.make_display_safe();
                        RegistryWrite::Usage(u)
                    }
                    RegistryMsg::Report(mut r) => {
                        r.make_display_safe();
                        let first = steer.applied.replace(r.applied).is_none();
                        report = Some(first.then(|| r.clone()));
                        RegistryWrite::Report(r)
                    }
                    RegistryMsg::Ack(ack) => {
                        acknowledge(ws, hub, registry, ack).await?;
                        continue;
                    }
                };
                if let Some(why) = store(ws, hub, registry, write).await? {
                    return Ok(why);
                }
                if inventory {
                    // A key that cannot be read or written must not cost the registry its
                    // session: it is still steered, and takes tokens once the hub can sync.
                    if let Err(e) = sync_tokens(hub, registry).await {
                        eprintln!(
                            "vk-hub: registry {}: syncing its token keys: {e:#}",
                            registry.id
                        );
                    }
                    steer.sync(ws, hub, registry).await?;
                }
                if let Some(first) = report {
                    if let Some(r) = first {
                        settle_unreported_updates(hub, registry, r).await?;
                    }
                    steer.sync(ws, hub, registry).await?;
                }
            }
        }
    }
}

/// Track applied and sent state. Send each missing desired generation and pending command
/// once per session, after the first report.
#[derive(Default)]
struct Steer {
    applied: Option<Option<u64>>,
    sent_generation: Option<u64>,
    sent_commands: HashSet<String>,
}

impl Steer {
    async fn sync(&mut self, ws: &mut Ws, hub: &Hub, registry: &Peer) -> Result<()> {
        let Some(applied) = self.applied else {
            return Ok(());
        };
        let db = hub.db.clone();
        let id = registry.id.clone();
        let (row, pending) = tokio::task::spawn_blocking(move || {
            anyhow::Ok((
                db.registry(&id)?,
                db.pending_registry_commands(&id, crate::now_secs())?,
            ))
        })
        .await??;
        if let Some(desired) = row.and_then(|r| r.desired)
            && applied < Some(desired.generation)
            && self.sent_generation != Some(desired.generation)
        {
            self.sent_generation = Some(desired.generation);
            send(ws, &HubRegistryMsg::Desired(desired)).await?;
        }
        for command in pending {
            if self.sent_commands.insert(command.id.clone()) {
                send(ws, &HubRegistryMsg::Command(command)).await?;
            }
        }
        Ok(())
    }
}

/// Bring the registry's token state up to date after its inventory: one that announces it
/// takes tokens gets its default namespaces and the signing keys.
async fn sync_tokens(hub: &Arc<Hub>, registry: &Peer) -> Result<()> {
    let hub = hub.clone();
    let id = registry.id.clone();
    tokio::task::spawn_blocking(move || crate::tokens::sync_registry(&hub, &id)).await?
}

/// Settle the accepted updates `report`, the session's first, does not name.
async fn settle_unreported_updates(hub: &Hub, registry: &Peer, report: Report) -> Result<()> {
    let db = hub.db.clone();
    let id = registry.id.clone();
    let settled = tokio::task::spawn_blocking(move || {
        db.settle_unreported_updates(&id, &report, crate::now_secs())
    })
    .await??;
    if settled {
        hub.changed(&registry.id);
    }
    Ok(())
}

/// Record the registry's command outcome and reply with [`HubRegistryMsg::Recorded`].
async fn acknowledge(
    ws: &mut Ws,
    hub: &Hub,
    registry: &Peer,
    ack: vk_hub_proto::CommandAck,
) -> Result<()> {
    let db = hub.db.clone();
    let id = registry.id.clone();
    let recorded = ack.clone();
    let news =
        tokio::task::spawn_blocking(move || db.record_registry_ack(&id, &ack, crate::now_secs()))
            .await??;
    if news {
        hub.changed(&registry.id);
    }
    send(ws, &HubRegistryMsg::Recorded(recorded)).await
}

/// Store `write`; `Some` carries why the session ends, the registry having been removed.
async fn store(
    ws: &mut Ws,
    hub: &Hub,
    registry: &Peer,
    write: RegistryWrite,
) -> Result<Option<&'static str>> {
    let db = hub.db.clone();
    let id = registry.id.clone();
    let now = crate::now_secs();
    let written = tokio::task::spawn_blocking(move || db.record_registry(&id, write, now)).await?;
    match written {
        Ok(()) => {
            hub.changed(&registry.id);
            Ok(None)
        }
        Err(e) if e.is::<NotEnrolled>() => {
            refuse(ws, RefusalCode::Revoked, REMOVED).await;
            Ok(Some("removed"))
        }
        Err(e) => Err(e),
    }
}

/// End the session with [`HubRegistryMsg::Refused`], then close.
async fn refuse(ws: &mut Ws, code: RefusalCode, reason: &str) {
    let msg = HubRegistryMsg::Refused {
        code,
        reason: reason.to_string(),
    };
    let _ = tokio::time::timeout(HANDSHAKE_STEP, async {
        let _ = send(ws, &msg).await;
        let _ = ws.close(None).await;
    })
    .await;
}

async fn send(ws: &mut Ws, msg: &HubRegistryMsg) -> Result<()> {
    send_text(
        ws,
        serde_json::to_string(msg).context("encoding a message")?,
    )
    .await
}

async fn send_text(ws: &mut Ws, text: String) -> Result<()> {
    tokio::time::timeout(HEARTBEAT, ws.send(Message::text(text)))
        .await
        .map_err(|_| anyhow!("the registry is not reading"))?
        .map_err(|e| anyhow!("sending: {e}"))
}

/// A registry as `vk-hub registries` lists it and its page shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryView {
    pub id: String,
    pub connected: bool,
    #[serde(flatten)]
    pub row: RegistryRow,
}

/// Every registry, with whether it has a session now.
pub fn views(hub: &Hub) -> Result<Vec<RegistryView>> {
    let mut views: Vec<RegistryView> = hub
        .db
        .registries()?
        .into_iter()
        .map(|(id, row)| view(hub, id, row))
        .collect();
    views.sort_by(|a, b| a.row.hostname.cmp(&b.row.hostname).then(a.id.cmp(&b.id)));
    Ok(views)
}

/// Registry `id`, and the commands kept for it; `None` when there is none.
pub fn detail(hub: &Hub, id: &str) -> Result<Option<(RegistryView, Vec<RegistryCommandRow>)>> {
    let Some(row) = hub.db.registry(id)? else {
        return Ok(None);
    };
    let commands = hub.db.registry_commands(id)?;
    Ok(Some((view(hub, id.to_string(), row), commands)))
}

fn view(hub: &Hub, id: String, row: RegistryRow) -> RegistryView {
    RegistryView {
        connected: hub.reach(&id) == Reach::Connected,
        id,
        row,
    }
}

/// Change registry `id`'s desired state as `actor`, and have its session send it; `None` when
/// it was already so.
pub fn set(
    hub: &Hub,
    actor: &str,
    id: &str,
    change: RegistryChange,
) -> Result<Option<DesiredState>> {
    let desired = hub
        .db
        .set_registry_desired(id, change, actor, crate::now_secs())?;
    if desired.is_some() {
        hub.kick(id);
        hub.changed(id);
    }
    Ok(desired)
}

/// Have registry `id` make itself read-only, writable, or as its config has it (`None`).
pub fn read_only(
    hub: &Hub,
    actor: &str,
    id: &str,
    read_only: Option<bool>,
) -> Result<Option<DesiredState>> {
    set(
        hub,
        actor,
        id,
        RegistryChange {
            read_only: Some(read_only),
            ..RegistryChange::default()
        },
    )
}

/// Have registry `id` run gc on `schedule`, or not at all (`None`).
pub fn gc_schedule(
    hub: &Hub,
    actor: &str,
    id: &str,
    schedule: Option<GcPolicy>,
) -> Result<Option<DesiredState>> {
    if let Some(gc) = schedule {
        check_gc(gc.retention_days, gc.grace_days)?;
        if gc.every_secs < 600 {
            bail!("a gc runs at most every 10 minutes");
        }
    }
    set(
        hub,
        actor,
        id,
        RegistryChange {
            gc: Some(schedule),
            ..RegistryChange::default()
        },
    )
}

fn check_gc(retention_days: u64, grace_days: u64) -> Result<()> {
    if retention_days == 0 {
        bail!("a retention of 0 days would drop every tag");
    }
    if grace_days == 0 {
        bail!("a grace of 0 days would sweep pushes in flight");
    }
    Ok(())
}

/// Have registry `id` run gc now.
pub fn gc(
    hub: &Hub,
    actor: &str,
    id: &str,
    retention_days: u64,
    grace_days: u64,
    dry_run: bool,
) -> Result<Command> {
    check_gc(retention_days, grace_days)?;
    issue(
        hub,
        actor,
        id,
        Operation::Gc {
            retention_days,
            grace_days,
            dry_run,
        },
    )
}

/// Update registry `id` to the `vk-registry` release whose sha256 starts with `release`.
pub fn update(hub: &Hub, actor: &str, id: &str, release: &str) -> Result<Command> {
    // Held from the lookup to the command, so the release cannot be removed between them.
    let _held = hub.releases_lock();
    let release = hub.db.resolve_release(release)?;
    if release.row.program() != REGISTRY_PROGRAM {
        bail!(
            "release {} is {} {}, not a {REGISTRY_PROGRAM} release: add one with `vk-hub release \
             add --program {REGISTRY_PROGRAM}`",
            crate::store::short(&release.sha256),
            release.row.program(),
            release.row.version
        );
    }
    issue(
        hub,
        actor,
        id,
        Operation::Update {
            version: release.row.version.clone(),
            sha256: release.sha256.clone(),
            size: release.row.size,
            signature: release.row.signature.clone(),
        },
    )
}

fn issue(hub: &Hub, actor: &str, id: &str, op: Operation) -> Result<Command> {
    let command = hub
        .db
        .issue_registry_command(id, op, COMMAND_TTL, actor, crate::now_secs())?;
    eprintln!(
        "vk-hub: registry {id}: {actor} issued {} (command {})",
        crate::store::registry_operation_name(&command.op),
        command.id
    );
    hub.kick(id);
    hub.changed(id);
    Ok(command)
}

/// Bind registry `id` to `url`, or unbind it, as `actor`; whether it changed.
pub fn set_url(hub: &Hub, actor: &str, id: &str, url: Option<&str>) -> Result<bool> {
    let changed = hub.db.set_registry_url(id, url, actor, crate::now_secs())?;
    if changed {
        hub.changed(id);
    }
    Ok(changed)
}

/// Store namespace `ns` on registry `id` as `actor`, and send the retention it sets.
pub fn put_namespace(
    hub: &Hub,
    actor: &str,
    id: &str,
    ns: &crate::store::NamespaceRow,
) -> Result<()> {
    hub.db.put_namespace(id, ns, actor, crate::now_secs())?;
    sync_after_namespaces(hub, id);
    hub.changed(id);
    Ok(())
}

/// Remove namespace `name` of registry `id` as `actor`; whether there was one.
pub fn remove_namespace(hub: &Hub, actor: &str, id: &str, name: &str) -> Result<bool> {
    let removed = hub
        .db
        .remove_namespace(id, name, actor, crate::now_secs())?;
    if removed {
        sync_after_namespaces(hub, id);
        hub.changed(id);
    }
    Ok(removed)
}

/// Send registry `id` the retention its namespaces now set. The namespaces are stored
/// whatever happens here; a failure is logged, and the next sync sends them.
fn sync_after_namespaces(hub: &Hub, id: &str) {
    if let Err(e) = crate::tokens::sync_registry(hub, id) {
        eprintln!("vk-hub: registry {id}: syncing after a namespace change: {e:#}");
    }
}

/// Remove registry `id` as `actor` and end its session; whether there was one.
pub fn remove(hub: &Hub, actor: &str, id: &str) -> Result<bool> {
    let removed = hub.db.remove_registry(id, actor, crate::now_secs())?;
    if removed {
        hub.revoke(id);
        hub.touch();
    }
    Ok(removed)
}

/// The columns of `vk-hub registries`, and of the web UI's registries table.
pub const COLUMNS: [&str; 9] = [
    "ID",
    "NAME",
    "REACH",
    "VERSION",
    "MODE",
    "STORE FREE",
    "WRITES",
    "GC",
    "LAST SEEN",
];

/// A registry's row in [`COLUMNS`] at `now`. Its strings are the registry's own, made safe
/// to print when they were stored.
pub fn cells(r: &RegistryView, now: u64) -> [String; 9] {
    let inventory = r.row.inventory.as_ref();
    let report = r.row.report.as_ref();
    let free = free(r);
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
        inventory.map_or("-".to_string(), |i| i.mode.clone()),
        free,
        match report {
            Some(rep) if rep.read_only => "read-only".to_string(),
            Some(_) => "open".to_string(),
            None => "-".to_string(),
        },
        report.and_then(|rep| rep.gc).map_or("-".to_string(), |gc| {
            format!(
                "every {}",
                crate::human_duration(Duration::from_secs(gc.every_secs))
            )
        }),
        r.row.last_seen.map_or("never".to_string(), |at| {
            format!(
                "{} ago",
                crate::human_duration(crate::ago(now, at)).trim_end()
            )
        }),
    ]
}

/// `STORE FREE`: free storage, including the total store size when reported.
pub fn free(r: &RegistryView) -> String {
    match (
        r.row.heartbeat.as_ref().map(|h| h.store_free_bytes),
        r.row.inventory.as_ref(),
    ) {
        (Some(free), Some(i)) if i.store_size_bytes > 0 => {
            format!("{} of {}", gib(free), gib(i.store_size_bytes))
        }
        (Some(free), _) => gib(free),
        _ => "-".to_string(),
    }
}

/// Lines to print under the table: what each registry is doing or did that a column cannot
/// say.
pub fn notes(r: &RegistryView) -> Vec<String> {
    let mut notes = Vec::new();
    let name = &r.row.hostname;
    if let Some(report) = &r.row.report {
        if let Some(u) = &report.update {
            let mut line = format!(
                "{name}: update to {} {}",
                u.version,
                crate::store::update_phase_name(u.phase)
            );
            if let Some(m) = &u.message {
                line.push_str(&format!(": {m}"));
            }
            notes.push(line);
        }
        if let Some(gc) = &report.last_gc {
            let by = gc
                .command
                .as_ref()
                .map_or(String::new(), |c| format!(" (command {c})"));
            notes.push(match &gc.error {
                Some(e) => format!("{name}: last gc{by} failed: {e}"),
                None => format!(
                    "{name}: last gc{by}{} dropped {} tags and {} blobs, {} freed",
                    if gc.dry_run { " (dry run)" } else { "" },
                    gc.tags_dropped,
                    gc.blobs_dropped,
                    gib(gc.bytes_freed)
                ),
            });
        }
        if !report.refused.is_empty() {
            notes.push(format!(
                "{name}: its config does not let the hub set {}",
                report.refused.join(", ")
            ));
        }
    }
    notes
}

/// `bytes` in GiB, one decimal.
pub fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / f64::from(1u32 << 30))
}
