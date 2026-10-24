//! Managing the hub's egress rules ([`crate::store::EgressRuleRow`]), from `vk-hub egress` and
//! the Egress page's Rules tab, and resolving a job's layer from them.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::egress::{EgressLayer, EgressOutcome, HubEgress, HubPhase};

use crate::server::Hub;
use crate::store::{EgressRuleRow, JobRow, RuleChange, RuleMode};
use crate::subject::{JobClaims, Subject};

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

/// A job's claims as `vk-hub egress resolve` gives them; no GitLab instance for a job whose key
/// is bound to none.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Claims {
    #[serde(default)]
    pub gitlab: Option<String>,
    #[serde(default)]
    pub project_id: u64,
    #[serde(default)]
    pub project_path: String,
    #[serde(default)]
    pub git_ref: String,
    #[serde(default)]
    pub protected: bool,
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

/// The layer a job claiming `c` would get from the rules now.
pub fn resolve(hub: &Hub, c: &Claims) -> Result<HubEgress> {
    let claims = match &c.gitlab {
        Some(gitlab) => Some(JobClaims {
            gitlab: gitlab.clone(),
            project_id: c.project_id,
            project_path: c.project_path.clone(),
            git_ref: c.git_ref.clone(),
            protected: c.protected,
            pipeline_id: 0,
        }),
        None if c.project_id != 0 || !c.project_path.is_empty() => bail!(
            "a job's project counts only under a key bound to its GitLab instance: name the \
             instance too"
        ),
        None => None,
    };
    let (_, rules) = hub.db.egress_rules()?;
    Ok(crate::store::resolve_egress(&rules, claims.as_ref()))
}

/// The claims a placed job's record holds, as its placement resolved it from its spec: its
/// project and ref count only under a key bound to its GitLab instance. A protection GitLab
/// did not report reads as unprotected, as at placement. The record's project path and ref
/// are display-safe copies of the spec's, the same for any path or ref a rule can name.
pub fn claims_of(j: &JobRow) -> Option<JobClaims> {
    let gitlab = j.gitlab.as_ref()?;
    Some(JobClaims {
        gitlab: gitlab.clone(),
        project_id: j.project_id.unwrap_or_default(),
        project_path: j.project.clone().unwrap_or_default(),
        git_ref: j.git_ref.clone().unwrap_or_default(),
        protected: j.protected == Some(true),
        pipeline_id: j.pipeline.unwrap_or_default(),
    })
}

/// Add or change a rule as `actor`, as [`put`] does, from a page's preview of it made against
/// the rules' `generation`: refused with [`crate::store::RulesChanged`] if they have changed
/// since. `exists` refuses a rule not stored yet.
pub fn save(
    hub: &Hub,
    actor: &str,
    change: &RuleChange,
    exists: bool,
    generation: u64,
) -> Result<(EgressRuleRow, bool)> {
    let (row, changed, steered) =
        hub.db
            .put_egress_rule_at(change, exists, Some(generation), actor, crate::now_secs())?;
    steered_fallback(hub, &steered);
    Ok((row, changed))
}

/// Remove rule `name` as `actor`, as [`remove`] does, from a page's preview made against the
/// rules' `generation`: refused with [`crate::store::RulesChanged`] if they have changed since.
pub fn remove_at(hub: &Hub, actor: &str, name: &str, generation: u64) -> Result<bool> {
    let (removed, steered) =
        hub.db
            .remove_egress_rule_at(name, Some(generation), actor, crate::now_secs())?;
    steered_fallback(hub, &steered);
    Ok(removed)
}

/// The latest jobs of the history [`RecentScan`] reads.
pub const RECENT_SCAN: usize = 1000;

/// How long ago a job may have been placed to count as recent, in seconds.
pub const RECENT_SECS: u64 = 7 * 86_400;

/// What one rule did to the recent jobs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleJobs {
    /// Jobs placed under it, enforced: the Fallback's when it alone applied.
    pub enforced: u64,
    /// Jobs it selected in dry-run.
    pub dry_run: u64,
    /// Of those, the jobs whose node reported a destination it would have blocked.
    pub would_block: u64,
}

/// The rules the recent jobs were placed under, from their records ([`crate::store::EgressRulesApplied`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recent {
    pub rules: BTreeMap<String, RuleJobs>,
    /// The jobs read, and whether the history holds more within [`RECENT_SECS`] than were.
    pub read: usize,
    pub capped: bool,
}

/// What the latest [`RECENT_SCAN`] jobs placed within [`RECENT_SECS`] of `now` were placed
/// under, as they are visited, newest first, one at a time.
pub struct RecentScan {
    since: u64,
    seen: usize,
    last_created: Option<u64>,
    out: Recent,
}

impl RecentScan {
    pub fn new(now: u64) -> Self {
        RecentScan {
            since: now.saturating_sub(RECENT_SECS),
            seen: 0,
            last_created: None,
            out: Recent::default(),
        }
    }

    /// Count job `j`, the next newest-first; past [`RECENT_SCAN`] of them, none.
    pub fn visit(&mut self, j: &JobRow) {
        if self.seen >= RECENT_SCAN {
            return;
        }
        self.seen = self.seen.saturating_add(1);
        self.last_created = Some(j.created_at);
        if j.created_at < self.since {
            return;
        }
        let out = &mut self.out;
        out.read = out.read.saturating_add(1);
        let Some(applied) = &j.egress_rules else {
            return;
        };
        for rule in &applied.rules {
            let n = out.rules.entry(rule.clone()).or_default();
            n.enforced = n.enforced.saturating_add(1);
        }
        let entries = super::report(j)
            .map(|r| r.entries.as_slice())
            .unwrap_or_default();
        for rule in &applied.dry_run {
            let n = out.rules.entry(rule.clone()).or_default();
            n.dry_run = n.dry_run.saturating_add(1);
            let blocked = entries.iter().any(|e| {
                e.outcome == EgressOutcome::WouldBlock
                    && e.layer == Some(EgressLayer::HubRule)
                    && e.rule.as_ref() == Some(rule)
            });
            if blocked {
                n.would_block = n.would_block.saturating_add(1);
            }
        }
    }

    pub fn finish(mut self) -> Recent {
        self.out.capped =
            self.seen >= RECENT_SCAN && self.last_created.is_some_and(|c| c >= self.since);
        self.out
    }
}
