//! What an operator does to the fleet, whichever way they reach the hub. Each operation takes
//! the actor it is done as — `uid <n>` on the admin socket, `ui session <id> (<role>)` in the
//! web UI — which the store writes into the audit log beside the change, so every front end
//! runs the same code and is audited alike.

use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_fleet_proto::{Acquisition, Command, DesiredState, Operation, Report};

use crate::rollout::{NodeStatus, Rollout, RolloutNode, RolloutRow, RolloutState};
use crate::server::{Hub, Reach};
use crate::store::{NodeRow, Release, RolloutAction};

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

/// Issue `operation` to node `id`. An update is issued by [`update`], which names the release.
pub fn command(hub: &Hub, actor: &str, id: &str, operation: Operation) -> Result<Command> {
    match operation {
        Operation::Update { .. } => bail!("an update names a release; see `vk-hub nodes update`"),
        Operation::Reset => bail!("reset is not implemented yet"),
        _ => issue(hub, actor, id, operation),
    }
}

/// Update node `id` to the release whose sha256 starts with `release`. `force` lets a node
/// whose runner is external update without draining it.
///
/// A node a rollout still has to update is the rollout's: an update of an operator's on the
/// side would race the one the rollout issues, so it is refused until the rollout is over.
pub fn update(hub: &Hub, actor: &str, id: &str, release: &str, force: bool) -> Result<Command> {
    let release = hub.db.resolve_release(release)?;
    for (rollout, row) in hub.db.rollouts()? {
        if row.state.active()
            && row.nodes.iter().any(|n| {
                n.id == id && matches!(n.status, NodeStatus::Pending | NodeStatus::Updating { .. })
            })
        {
            bail!(
                "node {id} is in rollout {}, still {}; abort it first, or let it finish",
                crate::rollout::short_id(&rollout),
                row.state.name()
            );
        }
    }
    issue(hub, actor, id, update_operation(&release, force))
}

/// The command that updates a node to `release`.
pub fn update_operation(release: &Release, force: bool) -> Operation {
    Operation::Update {
        version: release.row.version.clone(),
        sha256: release.sha256.clone(),
        size: release.row.size,
        signature: release.row.signature.clone(),
        force,
        within_secs: None,
    }
}

fn issue(hub: &Hub, actor: &str, id: &str, operation: Operation) -> Result<Command> {
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

/// Which nodes a rollout goes to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    All,
    /// Node IDs, or prefixes of at least 8 digits naming one each.
    Nodes(Vec<String>),
}

/// How a rollout goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPlan {
    pub release: String,
    pub nodes: Selection,
    pub batch: u32,
    pub canary_per_profile: bool,
    pub max_failures: u32,
    pub node_timeout_secs: u64,
    pub drain_timeout_secs: u64,
    /// Include nodes whose runner is external, updated without a drain.
    pub force: bool,
}

/// Start rolling a release out, as `actor`. Nodes already running it are skipped from the
/// start, so canaries are picked among those that are not.
pub fn create_rollout(hub: &Hub, actor: &str, plan: &RolloutPlan) -> Result<Rollout> {
    if plan.batch == 0 {
        bail!("a batch is at least one node");
    }
    if plan.node_timeout_secs < 60 || plan.drain_timeout_secs < 60 {
        bail!("a node's drain and its update need at least a minute each");
    }
    let release = hub.db.resolve_release(&plan.release)?;
    let nodes = hub.db.nodes()?;
    let chosen: Vec<(String, NodeRow)> = match &plan.nodes {
        Selection::All => nodes,
        Selection::Nodes(wanted) => {
            let mut chosen: Vec<(String, NodeRow)> = Vec::new();
            for want in wanted {
                let mut found = nodes
                    .iter()
                    .filter(|(id, _)| want.len() >= 8 && id.starts_with(want.as_str()));
                match (found.next(), found.next()) {
                    (Some(n), None) => {
                        if !chosen.iter().any(|(id, _)| *id == n.0) {
                            chosen.push(n.clone());
                        }
                    }
                    (None, _) => bail!("there is no node {want}"),
                    (Some(_), Some(_)) => bail!("{want} names more than one node"),
                }
            }
            chosen
        }
    };
    if chosen.is_empty() {
        bail!("there is no node to roll out to");
    }
    let (mut already, mut to_do) = (Vec::new(), Vec::new());
    for (id, row) in chosen {
        let versions = row.inventory.as_ref().map(|i| &i.versions);
        let on = match versions.and_then(|v| v.vk_sha256.as_deref()) {
            Some(sha) => sha == release.sha256,
            None => versions.is_some_and(|v| v.vk == release.row.version),
        };
        let profile = crate::rollout::profile(row.inventory.as_ref());
        if on {
            already.push((id, row.hostname, profile));
        } else {
            to_do.push((id, row.hostname, profile));
        }
    }
    let mut nodes = crate::rollout::plan(to_do, plan.batch, plan.canary_per_profile);
    nodes.extend(
        already
            .into_iter()
            .map(|(id, hostname, profile)| RolloutNode {
                id,
                hostname,
                profile,
                wave: 0,
                status: NodeStatus::Skipped {
                    reason: "already runs the release".into(),
                },
            }),
    );
    let now = crate::now_secs();
    let row = RolloutRow {
        release: release.sha256.clone(),
        version: release.row.version.clone(),
        created_at: now,
        created_by: actor.to_string(),
        batch: plan.batch,
        canary_per_profile: plan.canary_per_profile,
        max_failures: plan.max_failures,
        node_timeout_secs: plan.node_timeout_secs,
        drain_timeout_secs: plan.drain_timeout_secs,
        force: plan.force,
        state: RolloutState::Running,
        failures: 0,
        nodes,
    };
    let id = crate::random_hex(vk_fleet_proto::ID_BYTES)?;
    hub.db.create_rollout(&id, &row, actor)?;
    eprintln!(
        "vk-hub: {actor} started rollout {} of vk {}",
        crate::rollout::short_id(&id),
        row.version
    );
    hub.touch();
    Ok(Rollout { id, row })
}

/// Pause, resume or abort the rollout whose ID starts with `id`, as `actor`.
pub fn steer_rollout(hub: &Hub, actor: &str, id: &str, action: RolloutAction) -> Result<Rollout> {
    let (id, _) = hub.db.resolve_rollout(id)?;
    let row = hub
        .db
        .steer_rollout(&id, action, actor, crate::now_secs())?;
    eprintln!(
        "vk-hub: {actor}: rollout {} is now {}",
        crate::rollout::short_id(&id),
        row.state.name()
    );
    hub.touch();
    Ok(Rollout { id, row })
}
