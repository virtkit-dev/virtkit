//! Shared fleet operations for every front end. Mutations take an actor (`uid <n>` on the
//! admin socket), which the store audits with the change.

use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{Acquisition, Command, DesiredState, Operation, Report};

use crate::server::{Hub, Reach};
use crate::store::NodeRow;

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
    let changed =
        hub.db
            .set_desired(id, |d| d.ceiling = ceiling, actor, &what, crate::now_secs())?;
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
        |d| d.acquisition = acquisition,
        actor,
        what,
        crate::now_secs(),
    )?;
    desired_changed(hub, actor, id, what, changed.as_ref());
    Ok(changed)
}

/// Issue `operation` to node `id`, as `actor`, valid for [`COMMAND_TTL`].
pub fn command(hub: &Hub, actor: &str, id: &str, operation: Operation) -> Result<Command> {
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
