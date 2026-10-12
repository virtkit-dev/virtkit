//! The registry's session with its hub: dial, the handshake every peer shares, then its
//! inventory, heartbeats, usage and reports, and the hub's desired state and commands, until
//! the connection is lost — and dial again, backing off, unless the hub refused the registry
//! for good.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::RefusalCode;
use vk_hub_proto::registry::{HubRegistryMsg, RegistryMsg};
use vk_peer::session::{Permanent, Superseded, Ws};

use super::Link;

/// How long each step of a connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the inventory is looked at for a change.
const INVENTORY_EVERY: Duration = Duration::from_secs(60);

/// Redial delays: from the first to the longest, doubled in between.
const BACKOFF: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));

/// A session that lasted this long starts the backoff over.
const STABLE_SESSION: Duration = Duration::from_secs(60);

/// Keep a session with the hub for as long as `serve` runs.
pub(super) async fn hold(link: Arc<Link>) {
    let mut backoff = BACKOFF.0;
    loop {
        let started = tokio::time::Instant::now();
        match run(&link).await {
            Ok(()) => {}
            Err(e) if e.is::<Permanent>() => {
                eprintln!("vk-registry: hub: {e:#}; no longer reporting to it");
                return;
            }
            Err(e) => eprintln!("vk-registry: hub: session lost: {e:#}"),
        }
        if started.elapsed() >= STABLE_SESSION {
            backoff = BACKOFF.0;
        }
        tokio::time::sleep(vk_peer::jittered(backoff)).await;
        backoff = (backoff * 2).min(BACKOFF.1);
    }
}

/// A refusal from the hub as an error: [`Permanent`] when its code says so.
fn refusal(code: RefusalCode, reason: &str, dir: &std::path::Path) -> anyhow::Error {
    let mut message = format!(
        "the hub refused the session: {}",
        vk_hub_proto::display_safe(reason)
    );
    if matches!(code, RefusalCode::NotEnrolled | RefusalCode::Revoked) {
        message.push_str(&format!(
            " — the hub does not know this registry any more: `vk-registry leave` (removes {}) \
             and enroll again with `vk-registry join`",
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

/// One session, from dial to its end.
async fn run(link: &Arc<Link>) -> Result<()> {
    let hub = &link.enrollment.hub;
    let (mut ws, exported) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        vk_peer::session::connect(hub, &link.tls, vk_hub_proto::registry::SESSION_PATH),
    )
    .await
    .map_err(|_| anyhow!("connecting to {hub} timed out"))??;
    let hello = vk_peer::session::Hello {
        versions: vk_hub_proto::registry::PROTOCOL,
        id: &link.enrollment.registry_id,
        identity: &link.identity,
        incarnation: &link.incarnation,
        version: env!("CARGO_PKG_VERSION"),
    };
    let (heartbeat_secs, _version) = vk_peer::session::handshake(
        &mut ws,
        &hello,
        exported.as_ref(),
        CONNECT_TIMEOUT,
        |code, reason| refusal(code, reason, &link.dir),
    )
    .await?;
    // In session with the hub: an update on trial has passed.
    let confirming = link.clone();
    tokio::task::spawn_blocking(move || super::update::confirm(&confirming))
        .await
        .context("confirming the update")?;

    let beat = Duration::from_secs(u64::from(heartbeat_secs.clamp(1, 300)));
    let quiet = beat * 3;
    send(&mut ws, &RegistryMsg::Inventory(link.inventory()), beat).await?;
    let mut sent_inventory = link.inventory();
    send(&mut ws, &RegistryMsg::Report(link.report()), beat).await?;
    if let Some(usage) = link.usage() {
        send(&mut ws, &RegistryMsg::Usage(usage), beat).await?;
    }
    let unrecorded = link.persisted().unrecorded();
    for ack in unrecorded {
        send(&mut ws, &RegistryMsg::Ack(ack), beat).await?;
    }
    let mut sent_report = link.report();
    let mut sent_usage_at = link.usage().map(|u| u.at);
    let mut heartbeat = tokio::time::interval(beat);
    let mut inventory = tokio::time::interval(INVENTORY_EVERY);
    let mut deadline = tokio::time::Instant::now() + quiet;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                send(&mut ws, &RegistryMsg::Heartbeat(link.heartbeat()), beat).await?;
            }
            _ = inventory.tick() => {
                let now = link.inventory();
                if now != sent_inventory {
                    send(&mut ws, &RegistryMsg::Inventory(now.clone()), beat).await?;
                    sent_inventory = now;
                }
            }
            () = link.changed.notified() => {
                let report = link.report();
                if report != sent_report {
                    send(&mut ws, &RegistryMsg::Report(report.clone()), beat).await?;
                    sent_report = report;
                }
                if let Some(u) = link.usage()
                    && Some(u.at) != sent_usage_at
                {
                    sent_usage_at = Some(u.at);
                    send(&mut ws, &RegistryMsg::Usage(u), beat).await?;
                }
                let unrecorded = link.persisted().unrecorded();
                for ack in unrecorded {
                    send(&mut ws, &RegistryMsg::Ack(ack), beat).await?;
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                bail!("nothing heard from the hub for {}s", quiet.as_secs());
            }
            frame = ws.next() => {
                let text = match frame {
                    None => bail!("the hub closed the connection"),
                    Some(Err(e)) => bail!("reading from the hub: {e}"),
                    Some(Ok(Message::Close(_))) => bail!("the hub closed the session"),
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(_)) => {
                        deadline = tokio::time::Instant::now() + quiet;
                        continue;
                    }
                };
                deadline = tokio::time::Instant::now() + quiet;
                match vk_peer::session::parse::<HubRegistryMsg>(text.as_str())? {
                    HubRegistryMsg::Desired(desired) => {
                        let link = link.clone();
                        tokio::task::spawn_blocking(move || link.apply_desired(desired))
                            .await
                            .context("applying desired state")??;
                    }
                    HubRegistryMsg::Command(command) => {
                        if !vk_hub_proto::valid_id(&command.id) {
                            bail!("the hub sent a command with a malformed ID");
                        }
                        let ack = link.command(command)?;
                        send(&mut ws, &RegistryMsg::Ack(ack), beat).await?;
                    }
                    HubRegistryMsg::Recorded(ack) => {
                        link.update(|p| p.recorded(&ack))?;
                    }
                    HubRegistryMsg::Refused { code, reason } => {
                        return Err(refusal(code, &reason, &link.dir));
                    }
                }
            }
        }
    }
}

async fn send(ws: &mut Ws, msg: &RegistryMsg, within: Duration) -> Result<()> {
    vk_peer::session::send(ws, msg, within).await
}
