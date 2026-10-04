use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::server::{Hub, Reach};
use crate::store::NodeRow;

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
        id,
    }
}

/// One node's workloads, as `vk-hub workloads` lists them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeWorkloads {
    pub id: String,
    pub hostname: String,
    /// `None` until the node has listed any.
    pub workloads: Option<crate::store::Workloads>,
}

/// Every node's workloads, ordered by hostname, or only those of `node`: a node ID, or a
/// hostname only one node has.
pub fn workloads(hub: &Hub, node: Option<&str>) -> Result<Vec<NodeWorkloads>> {
    let mut nodes: Vec<(String, String)> = hub
        .db
        .nodes()?
        .into_iter()
        .map(|(id, row)| (id, row.hostname))
        .collect();
    if let Some(want) = node {
        let by_id: Vec<_> = nodes.iter().filter(|(id, _)| id == want).cloned().collect();
        let by_name: Vec<_> = nodes.iter().filter(|(_, h)| h == want).cloned().collect();
        nodes = match (by_id.is_empty(), by_name.len()) {
            (false, _) => by_id,
            (true, 1) => by_name,
            (true, 0) => bail!("there is no node {want}"),
            (true, _) => bail!("{want} names several nodes: give its ID (`vk-hub nodes`)"),
        };
    }
    nodes.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
    nodes
        .into_iter()
        .map(|(id, hostname)| {
            Ok(NodeWorkloads {
                workloads: hub.db.workloads(&id)?,
                id,
                hostname,
            })
        })
        .collect()
}
