//! Shared fleet operations for every front end. Mutations take an actor (`uid <n>` on the
//! admin socket), which the store audits with the change.

use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{Acquisition, Command, DesiredState, Operation, Report};

use crate::rollout::{NodeStatus, Rollout, RolloutAction, RolloutNode, RolloutRow, RolloutState};
use crate::server::{Hub, Reach};
use crate::store::{DesiredChange, NodeRow, Release};

/// Command delivery window. One day allows for a node reboot or hub outage without applying
/// a stale request, such as a week-old drain.
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
    /// How many VMs the node last said it runs; `None` until it has said.
    #[serde(default)]
    pub workloads: Option<u32>,
    /// The fleet protocol version of the node's latest session; `None` before its first. Below
    /// [`vk_hub_proto::STEERING`], the node is monitored only.
    #[serde(default)]
    pub protocol: Option<u32>,
    /// What the hub wants: `None` until an operator asked for anything.
    #[serde(default)]
    pub desired: Option<DesiredState>,
    /// What the node last reported of itself, without its workloads.
    #[serde(default)]
    pub report: Option<Report>,
    /// Commands still to deliver or finish.
    #[serde(default)]
    pub pending_commands: usize,
}

impl NodeView {
    /// Whether the node's latest session could not carry steering: it is monitored only.
    pub fn monitoring_only(&self) -> bool {
        self.protocol.is_some_and(|v| v < vk_hub_proto::STEERING)
    }
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
        workloads: row.workloads,
        protocol: row.protocol,
        desired: row.desired.clone(),
        report: row.report.clone(),
        // A count that cannot be read is shown as none rather than failing the listing.
        pending_commands: hub
            .db
            .pending_commands(&id, crate::now_secs())
            .map_or(0, |c| c.len()),
        id,
    }
}

/// Cap node `id`'s concurrency at `ceiling`, or lift the cap with `None`, as `actor`.
/// Return the new desired state, or `None` if unchanged.
pub fn set_ceiling(
    hub: &Hub,
    actor: &str,
    id: &str,
    ceiling: Option<u32>,
) -> Result<Option<DesiredState>> {
    // Enforce this at the operation boundary as well as in each front end.
    if ceiling == Some(0) {
        bail!("a ceiling of 0 is not one gitlab-runner has; stop acquisition instead");
    }
    let what = match ceiling {
        Some(n) => format!("set the concurrency ceiling to {n}"),
        None => "lifted the concurrency ceiling".to_string(),
    };
    let changed = hub.db.set_desired(
        id,
        DesiredChange::Ceiling(ceiling),
        actor,
        &what,
        crate::now_secs(),
    )?;
    desired_changed(hub, actor, id, &what, changed.as_ref());
    Ok(changed)
}

/// Stop or resume node `id`'s acquisition as `actor`.
/// Return the new desired state, or `None` if unchanged.
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
        DesiredChange::Acquisition(acquisition),
        actor,
        what,
        crate::now_secs(),
    )?;
    desired_changed(hub, actor, id, what, changed.as_ref());
    Ok(changed)
}

/// Issue `operation` to node `id`, as `actor`, valid for [`COMMAND_TTL`]. An update is issued
/// by [`update`], which names a release the hub holds.
pub fn command(hub: &Hub, actor: &str, id: &str, operation: Operation) -> Result<Command> {
    if matches!(operation, Operation::Update { .. }) {
        bail!("an update names a release; see `vk-hub nodes update`");
    }
    issue(hub, actor, id, operation)
}

/// Update node `id` to the release whose sha256 starts with `release`, as `actor`. `force`
/// asks a node whose runner is external to update without draining. A node a rollout still
/// has to update is refused until the rollout is over.
pub fn update(hub: &Hub, actor: &str, id: &str, release: &str, force: bool) -> Result<Command> {
    // Held from the lookup to the command, so the release cannot be removed between them.
    let _held = hub.releases_lock();
    let release = hub.db.resolve_release(release)?;
    issue(hub, actor, id, update_operation(&release, force, None))
}

/// The command that updates a node to `release`, to be over within `within_secs` of its drain.
pub(crate) fn update_operation(
    release: &Release,
    force: bool,
    within_secs: Option<u64>,
) -> Operation {
    Operation::Update {
        version: release.row.version.clone(),
        sha256: release.sha256.clone(),
        size: release.row.size,
        signature: release.row.signature.clone(),
        force,
        within_secs,
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
    /// The release's sha256, or a prefix of at least 8 hex digits.
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

/// Start rolling a release out, as `actor`. Nodes already running it, nodes only monitored and
/// nodes [`crate::rollout::ineligible`] are skipped from the start, so canaries are picked
/// among the rest.
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
                if want.len() < 8 {
                    bail!(
                        "{}: name a node by its ID, or at least its first 8 hex digits",
                        vk_hub_proto::display_safe(want)
                    );
                }
                let mut found = nodes.iter().filter(|(id, _)| id.starts_with(want.as_str()));
                match (found.next(), found.next()) {
                    (Some(n), None) => {
                        if !chosen.iter().any(|(id, _)| *id == n.0) {
                            chosen.push(n.clone());
                        }
                    }
                    (None, _) => bail!("there is no node {}", vk_hub_proto::display_safe(want)),
                    (Some(_), Some(_)) => bail!(
                        "{} names more than one node",
                        vk_hub_proto::display_safe(want)
                    ),
                }
            }
            chosen
        }
    };
    if chosen.is_empty() {
        bail!("there is no node to roll out to");
    }
    let (mut skipped, mut to_do) = (Vec::new(), Vec::new());
    for (id, row) in chosen {
        let facts = crate::rollout::Facts::of(&row);
        let profile = crate::rollout::profile(row.inventory.as_ref());
        let skip = match row.protocol {
            Some(v) if v < vk_hub_proto::STEERING => Some(crate::rollout::monitoring_only(v)),
            _ if facts.runs(&release.sha256, &release.row.version) => {
                Some("already runs the release".to_string())
            }
            _ => crate::rollout::ineligible(&facts, plan.force).map(str::to_string),
        };
        match skip {
            Some(reason) => skipped.push((id, row.hostname, profile, reason)),
            None => to_do.push((id, row.hostname, profile)),
        }
    }
    let mut nodes = crate::rollout::plan(to_do, plan.batch, plan.canary_per_profile);
    nodes.extend(
        skipped
            .into_iter()
            .map(|(id, hostname, profile, reason)| RolloutNode {
                id,
                hostname,
                profile,
                wave: 0,
                status: NodeStatus::Skipped { reason },
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
    let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
    hub.db.create_rollout(&id, &row, actor)?;
    eprintln!(
        "vk-hub: {actor} started rollout {} of vk {}",
        crate::rollout::short_id(&id),
        row.version
    );
    hub.touch();
    Ok(Rollout { id, row })
}

/// Every rollout, newest first.
pub fn rollouts(hub: &Hub) -> Result<Vec<Rollout>> {
    Ok(hub
        .db
        .rollouts()?
        .into_iter()
        .map(|(id, row)| Rollout { id, row })
        .collect())
}

/// Pause, resume or abort the rollout whose ID starts with `id`, as `actor`.
pub fn steer_rollout(hub: &Hub, actor: &str, id: &str, action: RolloutAction) -> Result<Rollout> {
    let (id, _) = hub.db.resolve_rollout(id)?;
    let row = hub
        .db
        .steer_rollout(&id, action, actor, crate::now_secs())?;
    eprintln!(
        "vk-hub: {actor} {} rollout {}",
        action.done(),
        crate::rollout::short_id(&id)
    );
    hub.touch();
    Ok(Rollout { id, row })
}

/// One node's workloads, as `vk-hub workloads` lists them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeWorkloads {
    pub id: String,
    pub hostname: String,
    /// Whether it has a session open now: a list from one that has not is as of `last_seen`.
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub last_seen: Option<u64>,
    /// `None` until the node has listed any.
    pub workloads: Option<crate::store::Workloads>,
    /// How many it listed that this reply leaves out, to stay within `limit`: asked for by
    /// node, its list is sent whole.
    #[serde(default)]
    pub withheld: u32,
}

/// Every node's workloads, ordered by hostname, or only those of `node`: a node ID, or a
/// hostname only one node has. Every node's together that would take more than `limit`
/// bytes, as JSON, comes as each node's count instead.
pub fn workloads(hub: &Hub, node: Option<&str>, limit: usize) -> Result<Vec<NodeWorkloads>> {
    let mut nodes: Vec<NodeWorkloads> = hub
        .db
        .nodes_with_workloads(|mut rows| {
            if let Some(want) = node {
                let by_id = rows.iter().any(|(id, _)| id == want);
                let by_name = rows.iter().filter(|(_, row)| row.hostname == want).count();
                match (by_id, by_name) {
                    (true, _) => rows.retain(|(id, _)| id == want),
                    (false, 1) => rows.retain(|(_, row)| row.hostname == want),
                    (false, 0) => bail!("there is no node {want}"),
                    (false, _) => bail!("{want} names several nodes: give its ID (`vk-hub nodes`)"),
                }
            }
            Ok(rows)
        })?
        .into_iter()
        .map(|(id, row, workloads)| NodeWorkloads {
            connected: hub.reach(&id) == Reach::Connected,
            last_seen: row.last_seen,
            hostname: row.hostname,
            workloads,
            withheld: 0,
            id,
        })
        .collect();
    nodes.sort_by(|a, b| (&a.hostname, &a.id).cmp(&(&b.hostname, &b.id)));
    // One node's list is bounded well under the admin reply's limit; the whole fleet's is
    // not. As a JSON array: its brackets, each node, and a comma before every one but the
    // first.
    if node.is_none() {
        let mut bytes = 1usize;
        let over = nodes.iter().any(|n| {
            let size = serde_json::to_vec(n).map_or(usize::MAX, |j| j.len().saturating_add(1));
            bytes = bytes.saturating_add(size);
            bytes > limit
        });
        if over {
            for n in &mut nodes {
                if let Some(w) = &mut n.workloads {
                    n.withheld = u32::try_from(w.listed.len()).unwrap_or(u32::MAX);
                    w.listed = Vec::new();
                    w.mem_bytes.clear();
                }
            }
        }
    }
    Ok(nodes)
}
