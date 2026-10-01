//! What an operator does to the fleet, whichever way they reach the hub. Each operation takes
//! the actor it is done as — `uid <n>` on the admin socket, `ui session <id> (<role>)` in the
//! web UI — which the store writes into the audit log beside the change, so every front end
//! runs the same code and is audited alike.

use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_fleet_proto::{Acquisition, Command, DesiredState, Operation, Report};

use crate::server::{Hub, Reach};
use crate::store::NodeRow;

/// How long an operator's command waits for its node to come and take it. A day covers a
/// node rebooting or a hub outage; a drain found a week later is not what anyone meant.
const COMMAND_TTL: Duration = Duration::from_secs(86_400);

/// One row of `vk-hub nodes`: what the database holds about a node, joined with whether it
/// has a session open now.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeView {
    pub id: String,
    pub hostname: String,
    pub connected: bool,
    pub last_seen: Option<u64>,
    pub vk: Option<String>,
    pub cpus: Option<u32>,
    pub mem_total_mib: Option<u64>,
    pub committed_mib: Option<u64>,
    pub budget_mib: Option<u64>,
    /// What the hub wants: `None` until an operator asked for anything.
    pub desired: Option<DesiredState>,
    /// What the node last reported of itself.
    pub report: Option<Report>,
    /// Commands still to deliver or finish.
    pub pending_commands: usize,
}

/// Every enrolled node, as `vk-hub nodes` shows it, ordered by hostname.
pub fn node_views(hub: &Hub) -> Result<Vec<NodeView>> {
    let mut views: Vec<NodeView> = hub
        .db
        .nodes()?
        .into_iter()
        .map(|(id, row)| node_view(hub, id, &row))
        .collect();
    views.sort_by(|a, b| (&a.hostname, &a.id).cmp(&(&b.hostname, &b.id)));
    Ok(views)
}

/// Node `id`'s row as `vk-hub nodes` shows it.
pub fn node_view(hub: &Hub, id: String, row: &NodeRow) -> NodeView {
    let inventory = row.inventory.as_ref();
    let admission = row.heartbeat.as_ref().and_then(|h| h.admission.as_ref());
    NodeView {
        connected: hub.reach(&id) == Reach::Connected,
        hostname: row.hostname.clone(),
        last_seen: row.last_seen,
        vk: inventory.map(|i| i.versions.vk.clone()),
        cpus: inventory.map(|i| i.hardware.cpus),
        mem_total_mib: inventory.and_then(|i| i.hardware.mem_total_mib),
        committed_mib: admission.map(|a| a.committed_mib),
        budget_mib: admission.and_then(|a| a.budget_mib),
        desired: row.desired.clone(),
        report: row.report.clone(),
        pending_commands: hub
            .db
            .pending_commands(&id, crate::now_secs())
            .map_or(0, |c| c.len()),
        id,
    }
}

/// Cap node `id`'s concurrency at `ceiling`, or lift the cap with `None`. The new desired
/// state, or `None` when it was already so.
pub fn set_ceiling(
    hub: &Hub,
    actor: &str,
    id: &str,
    ceiling: Option<u32>,
) -> Result<Option<DesiredState>> {
    // Every front end refuses these too; checked here all the same, since this is the
    // operation.
    if ceiling == Some(0) {
        bail!("a ceiling of 0 is not one gitlab-runner has; stop acquisition instead");
    }
    let what = match ceiling {
        Some(n) => format!("set the concurrency ceiling to {n}"),
        None => "lifted the concurrency ceiling".to_string(),
    };
    let changed =
        hub.db
            .set_desired(id, |d| d.ceiling = ceiling, actor, &what, crate::now_secs())?;
    desired_changed(hub, actor, id, &what, changed.as_ref());
    Ok(changed)
}

/// Stop or resume node `id`'s acquisition. The new desired state, or `None` when it was
/// already so.
pub fn set_acquisition(
    hub: &Hub,
    actor: &str,
    id: &str,
    acquisition: Acquisition,
) -> Result<Option<DesiredState>> {
    let what = match acquisition {
        Acquisition::Run => "resumed acquisition",
        Acquisition::Stop => "stopped acquisition",
    };
    let changed = hub.db.set_desired(
        id,
        |d| d.acquisition = acquisition,
        actor,
        what,
        crate::now_secs(),
    )?;
    desired_changed(hub, actor, id, what, changed.as_ref());
    Ok(changed)
}

/// Issue `operation` to node `id`.
pub fn command(hub: &Hub, actor: &str, id: &str, operation: Operation) -> Result<Command> {
    if matches!(operation, Operation::Update { .. } | Operation::Reset) {
        bail!(
            "{} is not implemented yet",
            crate::store::operation_name(&operation)
        );
    }
    let command = hub
        .db
        .issue_command(id, operation, COMMAND_TTL, actor, crate::now_secs())?;
    eprintln!(
        "vk-hub: node {id}: {actor} issued {} (command {})",
        crate::store::operation_name(&command.op),
        command.id
    );
    hub.kick(id);
    hub.changed(id);
    Ok(command)
}

/// Tell the node's session a desired-state change happened, or say it changed nothing. The
/// store has audited it with the change.
fn desired_changed(hub: &Hub, actor: &str, id: &str, what: &str, changed: Option<&DesiredState>) {
    match changed {
        Some(desired) => {
            eprintln!(
                "vk-hub: node {id}: {actor} {what} (generation {})",
                desired.generation
            );
            hub.kick(id);
            hub.changed(id);
        }
        None => eprintln!("vk-hub: node {id}: {actor} {what}: already so"),
    }
}
