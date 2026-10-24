//! Managing the hub's egress rules ([`crate::store::EgressRuleRow`]), from `vk-hub egress`.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use vk_hub_proto::egress::HubPhase;

use crate::server::Hub;
use crate::store::{EgressRuleRow, RuleChange, RuleMode};
use crate::subject::Subject;

/// The rules as `vk-hub egress list` shows them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rules {
    pub generation: u64,
    pub rules: Vec<EgressRuleRow>,
    /// `[jobs] egress_rules`: whether they restrict anything.
    #[serde(default)]
    pub enabled: bool,
}

impl Rules {
    /// What to warn of, if anything: rules that restrict nothing, or rules on with no enforced
    /// Fallback, under which every job no rule selects, gitlab-runner's all, reaches nothing.
    pub fn warning(&self) -> Option<&'static str> {
        let fallback = self
            .rules
            .iter()
            .any(|r| r.name == crate::store::DEFAULT_RULE && r.mode == RuleMode::Enforce);
        match (self.enabled, fallback) {
            (false, _) if !self.rules.is_empty() => {
                Some("these rules restrict nothing until hub.toml sets [jobs] egress_rules = true")
            }
            (true, false) => Some(
                "no Fallback is enforced: every job no enforced rule selects, gitlab-runner's \
                 all, may reach nothing",
            ),
            _ => None,
        }
    }
}

/// A change as the admin socket carries it: the subject as text, as `vk-hub egress set` takes
/// it, parsed by the hub.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Change {
    pub name: String,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub run: Option<HubPhase>,
    #[serde(default)]
    pub build: Option<HubPhase>,
    #[serde(default)]
    pub mode: Option<RuleMode>,
}

pub fn list(hub: &Hub) -> Result<Rules> {
    let (generation, rules) = hub.db.egress_rules()?;
    Ok(Rules {
        generation,
        rules,
        enabled: hub.db.egress_rules_on(),
    })
}

/// Add or change a rule as `actor`; `exists` refuses one not stored yet. Returns the rule as
/// stored, and whether it changed.
pub fn put(hub: &Hub, actor: &str, change: Change, exists: bool) -> Result<(EgressRuleRow, bool)> {
    let subject = match change.subject.as_deref() {
        Some(text) => Some(Subject::parse(text).map_err(|e| anyhow::anyhow!(e))?),
        None => None,
    };
    let change = RuleChange {
        name: change.name,
        subject,
        run: change.run,
        build: change.build,
        mode: change.mode,
    };
    let (row, changed, steered) =
        hub.db
            .put_egress_rule(&change, exists, actor, crate::now_secs())?;
    steered_fallback(hub, &steered);
    Ok((row, changed))
}

/// Remove rule `name` as `actor`; whether there was one.
pub fn remove(hub: &Hub, actor: &str, name: &str) -> Result<bool> {
    let (removed, steered) = hub.db.remove_egress_rule(name, actor, crate::now_secs())?;
    steered_fallback(hub, &steered);
    Ok(removed)
}

/// Send `nodes` the Fallback the store just steered them to.
fn steered_fallback(hub: &Hub, nodes: &[String]) {
    for id in nodes {
        eprintln!("vk-hub: node {id}: the egress Fallback for its gitlab-runner jobs changed");
        hub.kick(id);
        hub.changed(id);
    }
}
