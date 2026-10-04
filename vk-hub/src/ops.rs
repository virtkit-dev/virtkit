use anyhow::Result;
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
        id,
    }
}
