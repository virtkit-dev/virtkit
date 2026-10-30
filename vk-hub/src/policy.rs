//! Durable capacity arbitration policy: tenant shares, runner and API-key assignments,
//! and scheduler settings. Relay runners are identified by GitLab instance and runner ID,
//! never by name.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::Placement;

const MAX_TENANTS: usize = 4096;
const MAX_RUNNERS: usize = 16384;
const MAX_CLIENTS: usize = 16384;
const MAX_HEADROOMS: usize = 64;
const MAX_PROJECTS: usize = 16384;
const MAX_BRANCHES: usize = 1024;
/// The most placement rules of a project.
const MAX_PLACEMENT_RULES: usize = 64;
/// The most nodes, and pools, of one placement rule.
const MAX_RULE_TARGETS: usize = 256;
/// The longest production branch pattern and client principal, in bytes.
const MAX_TEXT: usize = 255;
/// The longest backoff or busy timeout.
const MAX_SECS: u64 = 365 * 24 * 3600;
/// The most slots one headroom entry reserves.
const MAX_HEADROOM_SLOTS: u32 = 4096;
/// Bounds on a headroom envelope, past any one machine: a typo is refused, not reserved.
const MAX_MEM_MIB: u64 = 16 << 20;
const MAX_CPUS: u32 = 4096;
const MAX_DISK_BYTES: u64 = 1 << 50;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    #[default]
    Normal,
    Production,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub gitlab: String,
    pub id: u64,
    #[serde(default)]
    pub production_branches: Vec<String>,
    /// Where its jobs may be placed: on nodes every rule that applies allows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement_rules: Vec<PlacementRule>,
}

/// A restriction of a project's jobs to some nodes or node pools: for jobs whose ref, as the
/// relay reports it, matches one of `branches` (globs), or for every job when it names none.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementRule {
    #[serde(default)]
    pub branches: Vec<String>,
    /// Node IDs allowed, any when empty.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Pools a node must be in one of, any when empty.
    #[serde(default)]
    pub pools: Vec<String>,
}

impl PlacementRule {
    /// Whether it restricts to some nodes or pools, within the policy's bounds.
    fn valid(&self) -> bool {
        (!self.nodes.is_empty() || !self.pools.is_empty())
            && self.branches.len() <= MAX_BRANCHES
            && self.nodes.len() <= MAX_RULE_TARGETS
            && self.pools.len() <= MAX_RULE_TARGETS
            && self
                .branches
                .iter()
                .all(|s| !s.is_empty() && s.len() <= MAX_TEXT && !s.chars().any(char::is_control))
            && self.nodes.iter().all(|s| vk_hub_proto::valid_id(s))
            && self.pools.iter().all(|s| crate::store::valid_name(s))
    }

    /// Whether it applies to a job of `git_ref`, as the relay reports it: every rule
    /// applies when the job's sources are unknown.
    fn applies(&self, git_ref: Option<&str>) -> bool {
        self.branches.is_empty()
            || git_ref.is_none_or(|r| {
                self.branches
                    .iter()
                    .any(|p| crate::subject::glob_match(p, r))
            })
    }

    /// Whether it restricts as `other` does, each list compared as a set.
    pub fn same_as(&self, other: &PlacementRule) -> bool {
        canonical(std::slice::from_ref(self)) == canonical(std::slice::from_ref(other))
    }

    /// Whether it lets a job go to `node`, in `pools`.
    fn allows(&self, node: &str, pools: &[String]) -> bool {
        (self.nodes.is_empty() || self.nodes.iter().any(|n| n == node))
            && (self.pools.is_empty() || self.pools.iter().any(|p| pools.contains(p)))
    }
}

/// Whether `a` and `b` restrict as each other, regardless of order.
pub fn same_rules(a: &[PlacementRule], b: &[PlacementRule]) -> bool {
    canonical(a) == canonical(b)
}

/// `rules`, each list sorted and deduplicated, for comparing two lists regardless of order.
fn canonical(rules: &[PlacementRule]) -> Vec<PlacementRule> {
    let mut rules: Vec<PlacementRule> = rules
        .iter()
        .map(|r| {
            let sorted = |v: &[String]| {
                let mut v = v.to_vec();
                v.sort();
                v.dedup();
                v
            };
            PlacementRule {
                branches: sorted(&r.branches),
                nodes: sorted(&r.nodes),
                pools: sorted(&r.pools),
            }
        })
        .collect();
    rules.sort();
    rules.dedup();
    rules
}

/// The branch a job's pipeline runs for, when its sources fetch that branch and nothing
/// else: the branch's own refspec once, and at most its pipeline's ref at the job's commit.
/// `None` for a tag, a merge request, or any other refspec.
pub fn branch_name(sources: &vk_hub_proto::job::Sources) -> Option<&str> {
    if sources.ref_type != vk_hub_proto::job::RefType::Branch {
        return None;
    }
    let branch = &sources.git_ref;
    let refspec = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
    let mut branches = 0;
    let mut commits = 0;
    for spec in &sources.refspecs {
        if spec == &refspec {
            branches += 1;
        } else if let Some((sha, pipeline)) = spec
            .strip_prefix('+')
            .and_then(|s| s.split_once(":refs/pipelines/"))
            && sha == sources.sha
            && matches!(sha.len(), 40 | 64)
            && sha.bytes().all(|b| b.is_ascii_hexdigit())
            && decimal_id(pipeline)
        {
            commits += 1;
        } else {
            return None;
        }
    }
    (branches == 1 && commits <= 1).then_some(branch)
}

fn decimal_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
}

impl Project {
    /// Whether a job of `git_ref`, `None` when its sources are unknown, may
    /// go to `node`, in `pools`: every rule that applies to it allows it.
    pub fn allows_placement(&self, git_ref: Option<&str>, node: &str, pools: &[String]) -> bool {
        self.placement_rules
            .iter()
            .all(|rule| !rule.applies(git_ref) || rule.allows(node, pools))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
    pub weight: u32,
    #[serde(default)]
    pub cap: Option<u32>,
    #[serde(default)]
    pub projects: Vec<Project>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerMapping {
    pub gitlab: String,
    pub runner_id: u64,
    pub tenant: String,
    pub class: Class,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Headroom {
    #[serde(deserialize_with = "deserialize_placement")]
    pub placement: Placement,
    pub slots: u32,
}

fn deserialize_placement<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Placement, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictPlacement {
        pool: String,
        #[serde(default)]
        labels: Vec<String>,
        envelope: StrictEnvelope,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictEnvelope {
        mem_mib: u64,
        cpus: u32,
        disk_bytes: u64,
    }
    let p = StrictPlacement::deserialize(deserializer)?;
    Ok(Placement {
        pool: p.pool,
        labels: p.labels,
        envelope: vk_hub_proto::job::Envelope {
            mem_mib: p.envelope.mem_mib,
            cpus: p.envelope.cpus,
            disk_bytes: p.envelope.disk_bytes,
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub tenants: BTreeMap<String, Tenant>,
    pub runners: Vec<RunnerMapping>,
    pub clients: BTreeMap<String, String>,
    pub fallback: String,
    pub headroom: Vec<Headroom>,
    pub probe_limit: u32,
    pub production_probe_burst: u32,
    pub backoff_initial_secs: u64,
    pub backoff_max_secs: u64,
    pub busy_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            tenants: BTreeMap::from([(
                "fallback".into(),
                Tenant {
                    weight: 1,
                    cap: None,
                    projects: Vec::new(),
                },
            )]),
            runners: Vec::new(),
            clients: BTreeMap::new(),
            fallback: "fallback".into(),
            headroom: Vec::new(),
            probe_limit: 1,
            production_probe_burst: 1,
            backoff_initial_secs: 1,
            backoff_max_secs: 60,
            busy_secs: 60,
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::Production => "production",
        })
    }
}

impl Policy {
    /// What `set` compares against: the sha256 of the policy as stored.
    pub fn digest(&self) -> Result<String> {
        Ok(digest_bytes(&serde_json::to_vec(self)?))
    }

    /// The mapping of the runner with GitLab runner ID `id` on instance `gitlab`, if any.
    pub fn runner(&self, gitlab: &str, id: u64) -> Option<&RunnerMapping> {
        self.runners
            .iter()
            .find(|r| r.gitlab == gitlab && r.runner_id == id)
    }

    /// Tenant `name`, if the policy has it.
    pub fn tenant(&self, name: &str) -> Option<&Tenant> {
        self.tenants.get(name)
    }

    /// The tenant an API client `principal` is charged to, and its name: the one `clients`
    /// maps it to, else the fallback.
    pub fn client(&self, principal: &str) -> Option<(&str, &Tenant)> {
        let name = self.clients.get(principal).unwrap_or(&self.fallback);
        self.tenant(name).map(|tenant| (name.as_str(), tenant))
    }

    /// Project `id` of instance `gitlab`, if tenant `tenant` lists it.
    pub fn project(&self, tenant: &str, gitlab: &str, id: u64) -> Option<&Project> {
        self.tenant(tenant)?
            .projects
            .iter()
            .find(|p| p.gitlab == gitlab && p.id == id)
    }

    /// Project `id` of instance `gitlab`, in whichever tenant lists it: for a job recorded
    /// without a scheduling identity. Placement rules are the same in every tenant listing it.
    pub fn project_any(&self, gitlab: &str, id: u64) -> Option<&Project> {
        self.tenants
            .values()
            .flat_map(|t| &t.projects)
            .find(|p| p.gitlab == gitlab && p.id == id)
    }

    /// This policy with `edit` applied to project `id` of instance `gitlab` in every tenant
    /// listing it, so its production branches and placement rules stay the same in each.
    /// Refused unless tenant `tenant` lists it.
    pub fn with_project(
        &self,
        tenant: &str,
        gitlab: &str,
        id: u64,
        edit: impl Fn(&mut Project),
    ) -> Result<Policy> {
        if self.project(tenant, gitlab, id).is_none() {
            bail!("tenant {tenant:?} does not list project {gitlab}/{id}");
        }
        let mut policy = self.clone();
        (policy.tenants.values_mut())
            .flat_map(|t| &mut t.projects)
            .filter(|p| p.gitlab == gitlab && p.id == id)
            .for_each(edit);
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.tenants.len() > MAX_TENANTS
            || self.runners.len() > MAX_RUNNERS
            || self.clients.len() > MAX_CLIENTS
            || self.headroom.len() > MAX_HEADROOMS
        {
            bail!("capacity policy exceeds its size limit");
        }
        if !self.tenants.contains_key(&self.fallback) {
            bail!("fallback tenant does not exist");
        }
        if self.probe_limit == 0
            || self.production_probe_burst == 0
            || self.backoff_initial_secs == 0
            || self.backoff_max_secs < self.backoff_initial_secs
            || self.busy_secs == 0
            || self.backoff_max_secs > MAX_SECS
            || self.busy_secs > MAX_SECS
        {
            bail!(
                "probe_limit, production_probe_burst, backoff_initial_secs and busy_secs must \
                 be positive, busy_secs and backoff_max_secs at most {MAX_SECS}, and \
                 backoff_max_secs at least backoff_initial_secs"
            );
        }
        for (i, headroom) in self.headroom.iter().enumerate() {
            let p = &headroom.placement;
            if !(1..=MAX_HEADROOM_SLOTS).contains(&headroom.slots)
                || !crate::store::valid_name(&p.pool)
                || p.labels.len() > 32
                || p.labels.iter().any(|l| !crate::store::valid_name(l))
                || !(1..=MAX_MEM_MIB).contains(&p.envelope.mem_mib)
                || !(1..=MAX_CPUS).contains(&p.envelope.cpus)
                || p.envelope.disk_bytes > MAX_DISK_BYTES
            {
                bail!(
                    "invalid headroom #{} (pool {:?}): slots must be 1 to {MAX_HEADROOM_SLOTS}, \
                     with a valid pool and labels, and an envelope of 1 to {MAX_MEM_MIB} MiB, \
                     1 to {MAX_CPUS} cpus and at most {MAX_DISK_BYTES} disk bytes",
                    i + 1,
                    p.pool
                );
            }
        }
        let mut branch_lists = BTreeMap::new();
        let mut placement_lists = BTreeMap::new();
        for (name, tenant) in &self.tenants {
            if !crate::store::valid_name(name)
                || tenant.weight == 0
                || tenant.cap == Some(0)
                || tenant.projects.len() > MAX_PROJECTS
            {
                bail!(
                    "invalid tenant {name:?}: it needs a valid name, a positive weight and cap, \
                     and at most {MAX_PROJECTS} projects"
                );
            }
            let mut projects = BTreeSet::new();
            for p in &tenant.projects {
                if !crate::store::valid_gitlab_name(&p.gitlab)
                    || p.id == 0
                    || !projects.insert((&p.gitlab, p.id))
                    || p.placement_rules.len() > MAX_PLACEMENT_RULES
                    || p.placement_rules.iter().any(|r| !r.valid())
                    || p.production_branches.len() > MAX_BRANCHES
                    || p.production_branches.iter().any(|s| {
                        s.is_empty() || s.len() > MAX_TEXT || s.chars().any(char::is_control)
                    })
                {
                    bail!(
                        "invalid or duplicate project {}/{} in tenant {name:?}",
                        p.gitlab,
                        p.id
                    );
                }
                if let Some(previous) =
                    branch_lists.insert((&p.gitlab, p.id), &p.production_branches)
                    && previous != &p.production_branches
                {
                    bail!(
                        "project {}/{}'s production branches differ across tenants",
                        p.gitlab,
                        p.id
                    );
                }
                if let Some(previous) =
                    placement_lists.insert((&p.gitlab, p.id), canonical(&p.placement_rules))
                    && previous != canonical(&p.placement_rules)
                {
                    bail!(
                        "project {}/{}'s placement rules differ across tenants",
                        p.gitlab,
                        p.id
                    );
                }
            }
        }
        let mut runners = BTreeSet::new();
        for r in &self.runners {
            if !crate::store::valid_gitlab_name(&r.gitlab)
                || r.runner_id == 0
                || !self.tenants.contains_key(&r.tenant)
                || !runners.insert((&r.gitlab, r.runner_id))
            {
                bail!(
                    "invalid or duplicate runner mapping {}/{} (tenant {:?})",
                    r.gitlab,
                    r.runner_id,
                    r.tenant
                );
            }
        }
        for (principal, tenant) in &self.clients {
            if principal.is_empty()
                || principal.len() > MAX_TEXT
                || principal.chars().any(char::is_control)
                || !self.tenants.contains_key(tenant)
            {
                bail!("invalid client assignment {principal:?} (tenant {tenant:?})");
            }
        }
        Ok(())
    }
}

/// [`Policy::digest`] of a stored row, readable or not.
pub fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    vk_hub_proto::to_hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_unknown_fields_and_invalid_headroom() {
        for json in [
            r#"{"probe_limt":1}"#,
            r#"{"tenants":{"fallback":{"weight":1,"wieght":2}}}"#,
            r#"{"runners":[{"gitlab":"gl","runner_id":1,"tenant":"fallback","class":"normal","clas":"normal"}]}"#,
            r#"{"headroom":[{"placement":{"pool":"p","labels":[],"envelope":{"mem_mib":1,"cpus":1,"disk_bytes":0,"cpu":1}},"slots":1}]}"#,
        ] {
            assert!(serde_json::from_str::<Policy>(json).is_err(), "{json}");
        }
        let mut policy = Policy::default();
        policy.headroom.push(Headroom {
            placement: Placement::default(),
            slots: 1,
        });
        assert!(policy.validate().is_err());
    }

    fn rule(branches: &[&str], nodes: &[&str], pools: &[&str]) -> PlacementRule {
        let strings = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        PlacementRule {
            branches: strings(branches),
            nodes: strings(nodes),
            pools: strings(pools),
        }
    }

    fn ruled(rules: Vec<PlacementRule>) -> Project {
        Project {
            gitlab: "gl".into(),
            id: 1,
            production_branches: vec![],
            placement_rules: rules,
        }
    }

    #[test]
    fn placement_rules_intersect_and_branch_rules_apply_to_matching_refs() {
        let project = ruled(vec![
            rule(&[], &["a", "b"], &["linux"]),
            rule(&["release/*"], &["b"], &[]),
        ]);
        let pools = vec!["linux".into()];
        assert!(project.allows_placement(Some("main"), "a", &pools));
        assert!(!project.allows_placement(Some("release/1"), "a", &pools));
        assert!(project.allows_placement(Some("release/1"), "b", &pools));
        // A pools rule: a node outside the pool, though listed, may not take it.
        assert!(!project.allows_placement(Some("main"), "b", &[]));
        assert!(!project.allows_placement(Some("main"), "c", &pools));
        // Sources unknown: held to every rule.
        assert!(!project.allows_placement(None, "a", &pools));
        assert!(project.allows_placement(None, "b", &pools));
    }

    #[test]
    fn a_branch_pipeline_is_named_and_anything_else_is_not() {
        use vk_hub_proto::job::{RefType, Sources};
        let sha = "a".repeat(40);
        let branch = "+refs/heads/main:refs/remotes/origin/main".to_owned();
        let pipeline = |sha: &str, id: &str| format!("+{sha}:refs/pipelines/{id}");
        let sources = |ref_type, sha: &str, refspecs: Vec<String>| Sources {
            git_ref: "main".into(),
            ref_type,
            sha: sha.into(),
            refspecs,
            ..Sources::default()
        };
        let sha256 = "b".repeat(64);
        for (refspecs, sha, ref_type, named) in [
            (vec![branch.clone()], sha.as_str(), RefType::Branch, true),
            (
                vec![branch.clone(), pipeline(&sha, "12")],
                &sha,
                RefType::Branch,
                true,
            ),
            (
                vec![branch.clone(), pipeline(&sha256, "12")],
                &sha256,
                RefType::Branch,
                true,
            ),
            (vec![branch.clone()], &sha, RefType::Tag, false),
            (
                vec![branch.clone(), branch.clone()],
                &sha,
                RefType::Branch,
                false,
            ),
            (vec![pipeline(&sha, "12")], &sha, RefType::Branch, false),
            (
                vec![branch.clone(), pipeline(&"c".repeat(40), "12")],
                &sha,
                RefType::Branch,
                false,
            ),
            (
                vec![branch.clone(), pipeline(&sha[..12], "12")],
                &sha[..12],
                RefType::Branch,
                false,
            ),
            (
                vec![branch.clone(), pipeline(&sha, "1x")],
                &sha,
                RefType::Branch,
                false,
            ),
            (
                vec![branch.clone(), pipeline(&sha, "1"), pipeline(&sha, "2")],
                &sha,
                RefType::Branch,
                false,
            ),
            (
                vec![
                    branch.clone(),
                    "+refs/merge-requests/1/head:refs/merge-requests/1/head".into(),
                ],
                &sha,
                RefType::Branch,
                false,
            ),
        ] {
            let s = sources(ref_type, sha, refspecs.clone());
            assert_eq!(branch_name(&s), named.then_some("main"), "{refspecs:?}");
        }
    }

    #[test]
    fn validation_bounds_headroom_and_caps_and_names_the_entry() {
        let headroom = |slots, mem_mib| Headroom {
            placement: Placement {
                pool: "ci".into(),
                labels: vec![],
                envelope: vk_hub_proto::job::Envelope {
                    mem_mib,
                    cpus: 1,
                    disk_bytes: 0,
                },
            },
            slots,
        };
        let mut policy = Policy::default();
        policy
            .headroom
            .push(headroom(MAX_HEADROOM_SLOTS, MAX_MEM_MIB));
        policy.validate().unwrap();
        for bad in [
            headroom(MAX_HEADROOM_SLOTS + 1, 1),
            headroom(1, MAX_MEM_MIB + 1),
        ] {
            let mut policy = Policy::default();
            policy.headroom.push(bad);
            let err = policy.validate().unwrap_err().to_string();
            assert!(err.contains("headroom #1 (pool \"ci\")"), "{err}");
        }
        let mut policy = Policy {
            headroom: vec![headroom(1, 1); MAX_HEADROOMS],
            ..Policy::default()
        };
        policy.validate().unwrap();
        policy.headroom.push(headroom(1, 1));
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("size limit"), "{err}");

        let mut policy = Policy::default();
        policy.tenants.get_mut("fallback").unwrap().cap = Some(0);
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("tenant \"fallback\""), "{err}");

        let mut policy = Policy::default();
        policy.runners.push(RunnerMapping {
            gitlab: "gl".into(),
            runner_id: 7,
            tenant: "nobody".into(),
            class: Class::Normal,
        });
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("gl/7"), "{err}");
    }

    #[test]
    fn tags_and_merge_requests_are_held_to_the_rules_their_ref_matches() {
        use vk_hub_proto::job::{RefType, Sources};
        let project = ruled(vec![rule(&["main", "v*"], &["allowed"], &[])]);
        let allows = |sources: &Sources, node: &str| {
            project.allows_placement(Some(&sources.git_ref), node, &[])
        };
        let sha = "a".repeat(40);
        let mut sources = Sources {
            git_ref: "main".into(),
            sha: sha.clone(),
            ..Sources::default()
        };
        // A verified branch.
        sources.refspecs = vec![
            "+refs/heads/main:refs/remotes/origin/main".into(),
            format!("+{sha}:refs/pipelines/42"),
        ];
        assert_eq!(branch_name(&sources), Some("main"));
        assert!(allows(&sources, "allowed"));
        assert!(!allows(&sources, "other"));
        // Whatever else it fetches: held to the rules its ref matches.
        for refspecs in [
            vec![],
            vec![format!("+{}:refs/pipelines/42", "b".repeat(40))],
            vec!["+refs/pipelines/42:refs/pipelines/42".to_owned()],
            vec!["+refs/heads/*:refs/remotes/origin/*".to_owned()],
            vec!["+refs/tags/*:refs/tags/*".to_owned()],
            vec!["+refs/merge-requests/7/head:refs/merge-requests/7/head".to_owned()],
            vec!["+refs/merge-requests/7/merge:refs/merge-requests/7/merge".to_owned()],
        ] {
            sources.refspecs = refspecs;
            assert!(allows(&sources, "allowed"), "{:?}", sources.refspecs);
            assert!(!allows(&sources, "other"), "{:?}", sources.refspecs);
        }
        // A tag, with a branch's refspecs or none: held to the rules its ref matches.
        sources.ref_type = RefType::Tag;
        sources.git_ref = "v1".into();
        for refspecs in [
            vec![],
            vec!["+refs/heads/v1:refs/remotes/origin/v1".to_owned()],
        ] {
            sources.refspecs = refspecs;
            assert!(!allows(&sources, "other"), "{:?}", sources.refspecs);
        }
        // A ref no rule's globs match: no branch rule applies.
        sources.git_ref = "feature".into();
        assert!(allows(&sources, "other"));
    }

    #[test]
    fn placement_validation_and_legacy_decode() {
        assert!(
            serde_json::from_str::<PlacementRule>(
                r#"{"pools":["trusted"],"node":["ignored-typo"]}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Project>(r#"{"gitlab":"gl","id":1,"placement_rule":[]}"#)
                .is_err()
        );
        let project: Project = serde_json::from_str(r#"{"gitlab":"gl","id":1}"#).unwrap();
        assert!(project.placement_rules.is_empty());
        assert!(
            !serde_json::to_string(&project)
                .unwrap()
                .contains("placement_rules")
        );

        let node = "0123456789abcdef0123456789abcdef";
        let with = |rules: Vec<PlacementRule>| {
            let mut policy = Policy::default();
            policy.tenants.get_mut("fallback").unwrap().projects = vec![ruled(rules)];
            policy
        };
        with(vec![rule(&["main"], &[node], &["ci"])])
            .validate()
            .unwrap();
        fn many(n: usize, s: &str) -> Vec<&str> {
            vec![s; n]
        }
        let long = "x".repeat(MAX_TEXT + 1);
        for bad in [
            vec![rule(&[], &[node], &[]); MAX_PLACEMENT_RULES + 1],
            vec![rule(&[], &many(MAX_RULE_TARGETS + 1, node), &[])],
            vec![rule(&[], &[], &many(MAX_RULE_TARGETS + 1, "ci"))],
            vec![rule(&many(MAX_BRANCHES + 1, "main"), &[node], &[])],
            vec![rule(&[""], &[node], &[])],
            vec![rule(&[&long], &[node], &[])],
            vec![rule(&["ma\nin"], &[node], &[])],
            vec![rule(&[], &["not-an-id"], &[])],
            vec![rule(&[], &[], &["not a pool"])],
            // Neither nodes nor pools: it would restrict nothing.
            vec![rule(&["main"], &[], &[])],
        ] {
            let err = with(bad.clone()).validate().unwrap_err().to_string();
            assert!(err.contains("project gl/1"), "{bad:?}: {err}");
        }
        assert!(
            with(vec![rule(&[], &[node], &[]); MAX_PLACEMENT_RULES])
                .validate()
                .is_ok()
        );

        // A project listed by two tenants has the same rules in both, in any order.
        let a = rule(&[], &[node], &[]);
        let b = rule(&["main"], &[], &["ci", "trusted"]);
        let mut policy = with(vec![a.clone(), b.clone()]);
        let reordered = rule(&["main"], &[], &["trusted", "ci"]);
        policy.tenants.insert(
            "other".into(),
            Tenant {
                weight: 1,
                cap: None,
                projects: vec![ruled(vec![reordered, a.clone()])],
            },
        );
        policy.validate().unwrap();
        policy.tenants.get_mut("other").unwrap().projects[0].placement_rules = vec![a];
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("placement rules differ"), "{err}");
    }

    #[test]
    fn a_project_is_edited_in_every_tenant_listing_it() {
        let mut policy = Policy::default();
        policy.tenants.get_mut("fallback").unwrap().projects = vec![ruled(vec![])];
        let group = policy.tenants["fallback"].clone();
        policy.tenants.insert("group".into(), group);
        let node = "0123456789abcdef0123456789abcdef";
        let edited = policy
            .with_project("group", "gl", 1, |p| {
                p.production_branches = vec!["main".into()];
                p.placement_rules = vec![rule(&[], &[node], &[])];
            })
            .unwrap();
        edited.validate().unwrap();
        for tenant in ["fallback", "group"] {
            let project = edited.project(tenant, "gl", 1).unwrap();
            assert_eq!(project.production_branches, ["main"]);
            assert_eq!(project.placement_rules[0].nodes, [node]);
        }
        // Only through a tenant listing it.
        let mut other = edited.clone();
        other.tenants.insert(
            "other".into(),
            Tenant {
                weight: 1,
                cap: None,
                projects: vec![],
            },
        );
        assert!(other.with_project("other", "gl", 1, |_| {}).is_err());
        assert!(edited.with_project("group", "gl", 2, |_| {}).is_err());
    }
}
