//! The nodes' own egress caps, as their inventories report them.

use vk_hub_proto::egress::{EgressCaps, NodeEgressCaps};

use crate::store::NodeRow;

/// The caps `n` reports, when it lists them.
pub fn listed(n: &NodeRow) -> Option<&EgressCaps> {
    match n.inventory.as_ref()?.egress_caps.as_ref()? {
        NodeEgressCaps::Listed(c) => Some(c),
        _ => None,
    }
}
