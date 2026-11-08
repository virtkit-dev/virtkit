//! The hub's settings for its nodes, for every front end (`docs/fleet-design.md`, *Hub
//! settings*): set and unset fleet-wide or for one node, audited as the actor's, and sent to
//! every node a change reaches.

use anyhow::{Result, anyhow};
use serde_json::Value;
use vk_hub_proto::settings::Kind;

use crate::server::Hub;

/// Parse operator input `text` for `key`: a registry ID, the tools to keep nodes on, or a value
/// of the key's kind. The store rechecks it and verifies the registry or the tools exist.
pub fn parse(key: &str, text: &str) -> Result<Value> {
    if key == crate::deploy::KEY {
        return Ok(Value::from(text.trim()));
    }
    let kind = vk_hub_proto::settings::kind(key)
        .ok_or_else(|| anyhow!("{key} is not a setting the hub may set"))?;
    match kind {
        Kind::Registry => Ok(Value::from(text.trim())),
        kind => kind.parse(text).map_err(|e| anyhow!("{key}: {e}")),
    }
}

/// Set `key` to `value`, or unset it with `None`, fleet-wide or for `node`, as `actor`, and
/// send the nodes it reaches their new desired state. Whether it changed.
pub fn set(
    hub: &Hub,
    actor: &str,
    node: Option<&str>,
    key: &str,
    value: Option<Value>,
) -> Result<bool> {
    let (changed, steered) = hub
        .db
        .set_setting(node, key, value, actor, crate::now_secs())?;
    if changed {
        let scope = node.map_or("fleet-wide".to_string(), |id| format!("for node {id}"));
        eprintln!("vk-hub: {actor} changed hub setting {key} {scope}");
        hub.touch();
    }
    sent(hub, &steered);
    Ok(changed)
}

/// Send every node the settings the hub's make now, after a change they name but do not hold:
/// a registry's URL, CA or namespaces, and have every session look at the node's own registry
/// access again. A failure is logged; the hub's next start sends them.
pub fn steer(hub: &Hub) {
    match hub.db.steer_settings(crate::now_secs()) {
        Ok(steered) => sent(hub, &steered),
        Err(e) => eprintln!("vk-hub: sending the nodes the hub's settings: {e:#}"),
    }
    // What nodes' own registry tokens are bound to and grant moves with the same changes.
    hub.token_keys.node_access_changed();
}

/// Send `nodes` the desired state the store just steered them to.
fn sent(hub: &Hub, nodes: &[String]) {
    for id in nodes {
        eprintln!("vk-hub: node {id}: the hub's settings for it changed");
        hub.kick(id);
        hub.changed(id);
    }
    if !nodes.is_empty() {
        hub.touch();
    }
}
