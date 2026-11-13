//! The earlier policy format, of tenants and project placement rules, read only to convert it
//! to lanes: once, when a hub of this format first opens a database storing one, and when an
//! operator sets a policy in that format.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{Class, Headroom, Lane, LaneId, LaneProject, Policy, VERSION};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    gitlab: String,
    id: u64,
    #[serde(default)]
    production_branches: Vec<String>,
    #[serde(default)]
    placement_rules: Vec<PlacementRule>,
}

/// Its project's jobs whose ref matches one of `branches`, or all when it names none, go only
/// to a node listed in `nodes` (any when empty) and in one of `pools` (any when empty).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct PlacementRule {
    #[serde(default)]
    branches: Vec<String>,
    #[serde(default)]
    nodes: Vec<String>,
    #[serde(default)]
    pools: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tenant {
    weight: u32,
    #[serde(default)]
    cap: Option<u32>,
    #[serde(default)]
    projects: Vec<Project>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerMapping {
    gitlab: String,
    runner_id: u64,
    tenant: String,
    class: Class,
    #[serde(default)]
    nodes: Vec<String>,
    #[serde(default)]
    pools: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1 {
    #[serde(default)]
    tenants: BTreeMap<String, Tenant>,
    #[serde(default)]
    runners: Vec<RunnerMapping>,
    #[serde(default)]
    clients: BTreeMap<String, String>,
    #[serde(default = "fallback")]
    fallback: String,
    #[serde(default)]
    headroom: Vec<Headroom>,
    #[serde(default = "super::default_probe")]
    probe_limit: u32,
    #[serde(default = "super::default_probe")]
    production_probe_burst: u32,
    #[serde(default = "super::default_backoff_initial")]
    backoff_initial_secs: u64,
    #[serde(default = "super::default_secs")]
    backoff_max_secs: u64,
    #[serde(default = "super::default_secs")]
    busy_secs: u64,
}

fn fallback() -> String {
    "fallback".into()
}

/// An earlier policy as lanes, with what an operator must review.
#[derive(Debug)]
pub struct Converted {
    pub policy: Policy,
    /// Lanes given the whole weight and cap of a tenant other lanes share, each telling which.
    pub shared: Vec<(LaneId, String)>,
    /// Placement rules no lane can express exactly, each with the lanes it applies to: the
    /// policy must not take effect before an operator sets those lanes' pools.
    pub unconverted: Vec<String>,
}

impl Converted {
    /// Whether it restricts work as the earlier policy did.
    pub fn exact(&self) -> bool {
        self.unconverted.is_empty()
    }

    /// What an operator must review, one line each.
    pub fn warnings(&self) -> Vec<String> {
        let shared = self.shared.iter().map(|(id, tenant)| {
            format!(
                "{id} takes the whole weight and max slots of tenant {tenant:?}, which other \
                 lanes also take: lower them"
            )
        });
        let rules = (self.unconverted.iter())
            .map(|rule| format!("{rule}: set its lanes' pools before activating"));
        shared.chain(rules).collect()
    }
}

/// Node IDs and pool names as a lane selects them: a node as its implicit pool.
fn targets<'a>(list: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    list.into_iter()
        .map(|t| {
            if vk_hub_proto::valid_id(t) {
                crate::policy::node_pool(t)
            } else {
                t.clone()
            }
        })
        .collect()
}

/// Convert `bytes`, a policy of the earlier format: one lane per runner mapped, copying its
/// tenant's weight, cap and projects on the runner's GitLab (a production runner's, those with
/// production branches, as its branch filter), one per API key mapped and the default lane
/// from the fallback tenant. A placement rule applying to every job a runner lane can take
/// narrows its nodes; any other is listed as unconverted.
pub fn convert(bytes: &[u8]) -> Result<Converted> {
    let v1: V1 = serde_json::from_slice(bytes).context("reading a capacity policy")?;
    let tenant = |name: &str| {
        v1.tenants
            .get(name)
            .with_context(|| format!("tenant {name:?} does not exist"))
    };
    // How many lanes take each tenant's share.
    let mut takers: BTreeMap<&str, usize> = BTreeMap::new();
    let names = (v1.runners.iter().map(|r| r.tenant.as_str()))
        .chain(v1.clients.values().map(String::as_str))
        .chain([v1.fallback.as_str()]);
    for name in names {
        *takers.entry(name).or_default() += 1;
    }
    let mut lanes = Vec::new();
    let mut shared = Vec::new();
    let mut unconverted = Vec::new();
    let mut take = |id: LaneId, name: &str, t: &Tenant| -> Lane {
        if takers.get(name).copied().unwrap_or(0) > 1 {
            shared.push((id.clone(), name.to_owned()));
        }
        Lane {
            weight: t.weight,
            max_slots: t.cap,
            ..Lane::new(&id)
        }
    };
    for r in &v1.runners {
        let t = tenant(&r.tenant)?;
        let id = LaneId::Runner {
            gitlab: r.gitlab.clone(),
            id: r.runner_id,
        };
        let mut lane = take(id.clone(), &r.tenant, t);
        lane.class = r.class;
        lane.pools = targets(r.nodes.iter().chain(&r.pools));
        let mut projects = Vec::new();
        let mut ruled = Vec::new();
        for p in t.projects.iter().filter(|p| p.gitlab == r.gitlab) {
            let branches = match r.class {
                Class::Normal => None,
                // No production branch: no production job of it today.
                Class::Production if p.production_branches.is_empty() => continue,
                Class::Production => Some(p.production_branches.clone()),
            };
            ruled.push((p, branches.clone()));
            projects.push(LaneProject {
                gitlab: p.gitlab.clone(),
                id: p.id,
                branches,
            });
        }
        lane.projects = Some(projects);
        // A pool named as a node ID would read as that node.
        if let Some(pool) = r.pools.iter().find(|p| vk_hub_proto::valid_id(p)) {
            unconverted.push(format!("pool {pool} of {id}, named as a node ID"));
        }
        match narrowed(r, &ruled) {
            Ok(Some(nodes)) => lane.pools = targets(&nodes),
            Ok(None) => {}
            Err(rules) => {
                unconverted.extend(rules.into_iter().map(|rule| format!("{rule} ({id})")))
            }
        }
        lanes.push(lane);
    }
    for (principal, name) in &v1.clients {
        let lane = take(LaneId::Key(principal.clone()), name, tenant(name)?);
        lanes.push(lane);
    }
    let lane = take(LaneId::Default, &v1.fallback, tenant(&v1.fallback)?);
    lanes.push(lane);
    let policy = Policy {
        version: VERSION,
        lanes,
        headroom: v1.headroom,
        probe_limit: v1.probe_limit,
        production_probe_burst: v1.production_probe_burst,
        backoff_initial_secs: v1.backoff_initial_secs,
        backoff_max_secs: v1.backoff_max_secs,
        busy_secs: v1.busy_secs,
    };
    policy
        .validate()
        .context("the capacity policy converts to an invalid one")?;
    Ok(Converted {
        policy,
        shared,
        unconverted,
    })
}

/// How a placement rule bears on the jobs of a lane's project with branch filter `branches`.
#[derive(PartialEq)]
enum Reach {
    All,
    None,
    Some,
}

fn reach(rule: &PlacementRule, branches: Option<&[String]>) -> Reach {
    if rule.branches.is_empty() {
        return Reach::All;
    }
    // Any ref: the rule's branches are some of them.
    let Some(branches) = branches else {
        return Reach::Some;
    };
    let matched = |b: &String| {
        rule.branches.contains(b)
            || !b.contains('*')
                && rule
                    .branches
                    .iter()
                    .any(|p| crate::subject::glob_match(p, b))
    };
    let unmatched = |b: &String| {
        !b.contains('*')
            && !rule
                .branches
                .iter()
                .any(|p| crate::subject::glob_match(p, b))
    };
    if branches.iter().all(matched) {
        Reach::All
    } else if branches.iter().all(unmatched) {
        Reach::None
    } else {
        Reach::Some
    }
}

fn rule_text(gitlab: &str, id: u64, rule: &PlacementRule) -> String {
    let list = |v: &[String]| v.join(", ");
    let mut text = format!("placement rule of project {gitlab}/{id}");
    if !rule.branches.is_empty() {
        text.push_str(&format!(" for branches {}", list(&rule.branches)));
    }
    if !rule.nodes.is_empty() {
        text.push_str(&format!(" to nodes {}", list(&rule.nodes)));
    }
    if !rule.pools.is_empty() {
        text.push_str(&format!(" in pools {}", list(&rule.pools)));
    }
    text
}

/// The nodes runner `r`'s lane must be narrowed to for the placement rules of its `projects`,
/// each with its branch filter: `None` when no rule applies, `Err` with the rules that cannot
/// be expressed as the lane's pools. Exact when every project is held to the same rules, each
/// applying to all of its jobs, and those rules with the runner's own nodes come to one list:
/// one list alone, or lists of node IDs alone, intersected.
fn narrowed(
    r: &RunnerMapping,
    projects: &[(&Project, Option<Vec<String>>)],
) -> std::result::Result<Option<Vec<String>>, Vec<String>> {
    let mut partial = Vec::new();
    let mut applying: Vec<BTreeSet<&PlacementRule>> = Vec::new();
    for (p, branches) in projects {
        let mut all = BTreeSet::new();
        for rule in &p.placement_rules {
            match reach(rule, branches.as_deref()) {
                Reach::All => {
                    all.insert(rule);
                }
                Reach::None => {}
                Reach::Some => partial.push(rule_text(&p.gitlab, p.id, rule)),
            }
        }
        applying.push(all);
    }
    let every = |projects: &[(&Project, Option<Vec<String>>)]| -> Vec<String> {
        projects
            .iter()
            .flat_map(|(p, _)| {
                p.placement_rules
                    .iter()
                    .map(|r| rule_text(&p.gitlab, p.id, r))
            })
            .collect()
    };
    // The lane keeps no rule of a project it cannot hold to all of them: review every one.
    if !partial.is_empty() {
        return Err(every(projects));
    }
    // Different projects held to different nodes: the lane cannot tell them apart.
    let Some(first) = applying.first() else {
        return Ok(None);
    };
    if applying.iter().any(|a| a != first) {
        return Err(every(projects));
    }
    if first.is_empty() {
        return Ok(None);
    }
    let mut lists: Vec<(Vec<String>, bool)> = Vec::new();
    if !r.nodes.is_empty() || !r.pools.is_empty() {
        let own = r.nodes.iter().chain(&r.pools).cloned().collect();
        lists.push((own, r.pools.is_empty()));
    }
    for rule in first {
        // Both nodes and pools: a node must be in both, which a lane's one list cannot say.
        if !rule.nodes.is_empty() && !rule.pools.is_empty() {
            return Err(every(projects));
        }
        let list = rule.nodes.iter().chain(&rule.pools).cloned().collect();
        lists.push((list, rule.pools.is_empty()));
    }
    // A pool named as a node ID would read as that node.
    if lists
        .iter()
        .any(|(l, ids)| !ids && l.iter().any(|t| vk_hub_proto::valid_id(t)))
    {
        return Err(every(projects));
    }
    let mut lists = lists.into_iter();
    let Some((mut nodes, mut ids)) = lists.next() else {
        return Ok(None);
    };
    for (list, list_ids) in lists {
        if !(ids && list_ids) {
            return Err(every(projects));
        }
        nodes.retain(|n| list.contains(n));
        ids = true;
    }
    nodes.sort();
    nodes.dedup();
    if nodes.is_empty() {
        return Err(every(projects));
    }
    Ok(Some(nodes))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "fedcba9876543210fedcba9876543210";

    fn convert_json(v: serde_json::Value) -> Converted {
        convert(&serde_json::to_vec(&v).unwrap()).unwrap()
    }

    fn lane<'a>(c: &'a Converted, id: &LaneId) -> &'a Lane {
        c.policy.lane(id).unwrap()
    }

    fn runner(id: u64) -> LaneId {
        LaneId::Runner {
            gitlab: "gl".into(),
            id,
        }
    }

    #[test]
    fn each_runner_key_and_the_fallback_become_a_lane() {
        let c = convert_json(json!({
            "tenants": {
                "fallback": { "weight": 1 },
                "web": { "weight": 2, "cap": 8, "projects": [
                    { "gitlab": "gl", "id": 7, "production_branches": ["main"] },
                    { "gitlab": "gl", "id": 8 },
                    { "gitlab": "other", "id": 9, "production_branches": ["main"] }
                ] },
                "empty": { "weight": 3 },
                "unused": { "weight": 5 }
            },
            "runners": [
                { "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": "normal" },
                { "gitlab": "gl", "runner_id": 43, "tenant": "web", "class": "production",
                  "nodes": [A], "pools": ["trusted"] },
                { "gitlab": "gl", "runner_id": 44, "tenant": "empty", "class": "normal" }
            ],
            "clients": { "ci-bot": "empty" },
            "probe_limit": 3
        }));
        assert!(c.exact());
        assert_eq!(c.policy.lanes.len(), 5);
        assert_eq!(c.policy.probe_limit, 3);
        let normal = lane(&c, &runner(42));
        assert_eq!((normal.weight, normal.max_slots), (2, Some(8)));
        let ids: Vec<_> = (normal.projects.iter().flatten())
            .map(|p| (p.id, p.branches.clone()))
            .collect();
        assert_eq!(ids, [(7, None), (8, None)]);
        let production = lane(&c, &runner(43));
        assert_eq!(production.class, Class::Production);
        assert_eq!(
            production.pools,
            [crate::policy::node_pool(A), "trusted".to_owned()]
        );
        // Only the project with production branches, as its filter.
        let ids: Vec<_> = (production.projects.iter().flatten())
            .map(|p| (p.id, p.branches.clone()))
            .collect();
        assert_eq!(ids, [(7, Some(vec!["main".to_owned()]))]);
        // An empty list stays empty: none, never any.
        assert_eq!(lane(&c, &runner(44)).projects, Some(vec![]));
        assert_eq!(lane(&c, &LaneId::Key("ci-bot".into())).weight, 3);
        assert_eq!(lane(&c, &LaneId::Default).weight, 1);
        // Tenants shared: each lane flagged.
        let shared: Vec<_> = c.shared.iter().map(|(id, _)| id.clone()).collect();
        assert_eq!(
            shared,
            [
                runner(42),
                runner(43),
                runner(44),
                LaneId::Key("ci-bot".into())
            ]
        );
        assert_eq!(c.warnings().len(), 4);
    }

    #[test]
    fn a_production_runner_without_production_branches_is_allowed_nothing() {
        let c = convert_json(json!({
            "tenants": {
                "fallback": { "weight": 1 },
                "web": { "weight": 1, "projects": [{ "gitlab": "gl", "id": 7 }] }
            },
            "runners": [
                { "gitlab": "gl", "runner_id": 43, "tenant": "web", "class": "production" }
            ]
        }));
        assert_eq!(lane(&c, &runner(43)).projects, Some(vec![]));
        assert!(c.shared.is_empty());
    }

    fn ruled(rules: serde_json::Value, class: &str, own: serde_json::Value) -> Converted {
        convert_json(json!({
            "tenants": {
                "fallback": { "weight": 1 },
                "web": { "weight": 1, "projects": [
                    { "gitlab": "gl", "id": 7, "production_branches": ["main", "release/1"],
                      "placement_rules": rules }
                ] }
            },
            "runners": [
                { "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": class,
                  "nodes": own }
            ]
        }))
    }

    #[test]
    fn a_rule_applying_to_every_job_of_a_lane_narrows_its_nodes() {
        let c = ruled(json!([{ "nodes": [A] }]), "normal", json!([]));
        assert!(c.exact(), "{:?}", c.unconverted);
        assert_eq!(lane(&c, &runner(42)).pools, [crate::policy::node_pool(A)]);
        let c = ruled(json!([{ "pools": ["trusted"] }]), "normal", json!([]));
        assert_eq!(lane(&c, &runner(42)).pools, ["trusted".to_owned()]);
        // Node lists intersect.
        let c = ruled(json!([{ "nodes": [A, B] }]), "normal", json!([B]));
        assert_eq!(lane(&c, &runner(42)).pools, [crate::policy::node_pool(B)]);
        // A production lane's branches all matched by the rule's.
        let c = ruled(
            json!([{ "branches": ["main", "release/*"], "nodes": [A] }]),
            "production",
            json!([]),
        );
        assert!(c.exact(), "{:?}", c.unconverted);
        assert_eq!(lane(&c, &runner(42)).pools, [crate::policy::node_pool(A)]);
        // None of its branches: the rule bears on none of its jobs.
        let c = ruled(
            json!([{ "branches": ["dev"], "nodes": [A] }]),
            "production",
            json!([]),
        );
        assert!(c.exact());
        assert!(lane(&c, &runner(42)).pools.is_empty());
    }

    #[test]
    fn any_other_rule_is_left_unconverted() {
        for (rules, class, own) in [
            // Some of a normal lane's refs.
            (
                json!([{ "branches": ["main"], "nodes": [A] }]),
                "normal",
                json!([]),
            ),
            // Some of a production lane's branches.
            (
                json!([{ "branches": ["main"], "nodes": [A] }]),
                "production",
                json!([]),
            ),
            // Nodes and pools at once.
            (
                json!([{ "nodes": [A], "pools": ["p"] }]),
                "normal",
                json!([]),
            ),
            // A pool list with the runner's own.
            (json!([{ "pools": ["p"] }]), "normal", json!([A])),
            // Nowhere left.
            (json!([{ "nodes": [A] }]), "normal", json!([B])),
            // An unconditional rule beside a partial one: both listed.
            (
                json!([{ "nodes": [A] }, { "branches": ["main"], "nodes": [B] }]),
                "normal",
                json!([]),
            ),
        ] {
            let c = ruled(rules.clone(), class, own);
            assert!(!c.exact(), "{rules}");
            assert!(
                c.unconverted[0].contains("project gl/7"),
                "{:?}",
                c.unconverted
            );
            assert!(
                c.unconverted[0].contains("runner gl/42"),
                "{:?}",
                c.unconverted
            );
        }
    }

    #[test]
    fn a_pool_named_as_a_node_id_is_left_unconverted() {
        let c = convert_json(json!({
            "tenants": { "fallback": { "weight": 1 }, "web": { "weight": 1 } },
            "runners": [
                { "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": "normal",
                  "pools": [A] }
            ]
        }));
        assert!(!c.exact());
    }

    #[test]
    fn projects_held_to_different_rules_are_left_unconverted() {
        let c = convert_json(json!({
            "tenants": {
                "fallback": { "weight": 1 },
                "web": { "weight": 1, "projects": [
                    { "gitlab": "gl", "id": 7, "placement_rules": [{ "nodes": [A] }] },
                    { "gitlab": "gl", "id": 8 }
                ] }
            },
            "runners": [
                { "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": "normal" }
            ]
        }));
        assert!(!c.exact());
    }

    #[test]
    fn an_invalid_earlier_policy_is_refused() {
        for v in [
            json!({ "tenants": {} }),
            json!({ "tenants": { "fallback": { "weight": 1 } },
                    "runners": [{ "gitlab": "gl", "runner_id": 1, "tenant": "x",
                                  "class": "normal" }] }),
            json!({ "tenants": { "fallback": { "weight": 0 } } }),
            json!({ "tenants": { "fallback": { "weight": 1, "x": 1 } } }),
        ] {
            assert!(convert(&serde_json::to_vec(&v).unwrap()).is_err(), "{v}");
        }
    }
}
