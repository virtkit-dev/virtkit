//! Durable capacity arbitration policy: one lane per input — a relay runner, an API key, or
//! the default lane of API keys no lane names — with its weight, slot limit, the nodes it may
//! use and the projects it may run, and the scheduler settings. Relay runners are identified by
//! GitLab instance and runner ID, never by name.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::Placement;

mod v1;

pub use v1::{Converted, convert as convert_v1};

/// The policy format this hub stores and shows.
pub const VERSION: u32 = 2;

/// The most lanes: a runner lane per runner and a key lane per API key a v1 policy could map.
const MAX_LANES: usize = 2 * 16384 + 1;
const MAX_HEADROOMS: usize = 64;
const MAX_PROJECTS: usize = 16384;
const MAX_BRANCHES: usize = 1024;
/// The most nodes and pools one lane names.
const MAX_NODES: usize = 256;
/// The longest branch pattern and API key principal, in bytes.
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

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::Production => "production",
        })
    }
}

/// Which input a lane schedules: work is charged to it, and held to its settings.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneId {
    /// A relay runner, by its GitLab instance's name on the hub and GitLab's runner ID.
    Runner { gitlab: String, id: u64 },
    /// An API key, by principal ID.
    Key(String),
    /// Every API key no lane of its own names.
    Default,
}

impl std::fmt::Display for LaneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runner { gitlab, id } => write!(f, "runner {gitlab}/{id}"),
            Self::Key(principal) => write!(f, "API key {principal}"),
            Self::Default => f.write_str("other API keys"),
        }
    }
}

/// A relay runner, as a lane names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRef {
    pub gitlab: String,
    pub id: u64,
}

/// A project a runner lane may run, on the runner's GitLab instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneProject {
    pub gitlab: String,
    pub id: u64,
    /// Branch patterns (globs) its jobs' pipelines must be of; any ref when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branches: Option<Vec<String>>,
}

/// One input's share of the fleet, and what it may run where. Exactly one of `runner`, `key`
/// and `default` names its source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<RunnerRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default: bool,
    /// Runner lanes only; API key lanes are always normal.
    #[serde(default)]
    pub class: Class,
    #[serde(default = "one")]
    pub weight: u32,
    /// The most slots it holds at once; unbounded when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_slots: Option<u32>,
    /// Node IDs and pool names its work may go to: a node listed, or in a pool listed. Any node
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<String>>,
    /// Runner lanes only: the projects its jobs may be of; any when absent, none when empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projects: Option<Vec<LaneProject>>,
}

fn one() -> u32 {
    1
}

impl Lane {
    /// A lane of `id`, weight 1, any node, any project.
    pub fn new(id: &LaneId) -> Self {
        let (runner, key, default) = match id {
            LaneId::Runner { gitlab, id } => (
                Some(RunnerRef {
                    gitlab: gitlab.clone(),
                    id: *id,
                }),
                None,
                false,
            ),
            LaneId::Key(principal) => (None, Some(principal.clone()), false),
            LaneId::Default => (None, None, true),
        };
        Lane {
            runner,
            key,
            default,
            class: Class::Normal,
            weight: 1,
            max_slots: None,
            nodes: None,
            projects: None,
        }
    }

    /// Which input it schedules; `None` unless it names exactly one source.
    pub fn id(&self) -> Option<LaneId> {
        match (&self.runner, &self.key, self.default) {
            (Some(r), None, false) => Some(LaneId::Runner {
                gitlab: r.gitlab.clone(),
                id: r.id,
            }),
            (None, Some(k), false) => Some(LaneId::Key(k.clone())),
            (None, None, true) => Some(LaneId::Default),
            _ => None,
        }
    }

    /// Whether its work may go to `node`, in `pools`.
    pub fn allows_node(&self, node: &str, pools: &[String]) -> bool {
        self.nodes.as_ref().is_none_or(|targets| {
            targets.iter().any(|t| {
                if vk_hub_proto::valid_id(t) {
                    t == node
                } else {
                    pools.contains(t)
                }
            })
        })
    }

    /// Whether it limits its work to some nodes.
    pub fn confined(&self) -> bool {
        self.nodes.is_some()
    }

    /// Project `id` of instance `gitlab`, as it lists it; `Ok(None)` when it lists every
    /// project, `Err` when not this one.
    fn project(&self, gitlab: &str, id: u64) -> std::result::Result<Option<&LaneProject>, ()> {
        match &self.projects {
            None => Ok(None),
            Some(projects) => projects
                .iter()
                .find(|p| p.gitlab == gitlab && p.id == id)
                .map(Some)
                .ok_or(()),
        }
    }

    /// Why a job of project `id` of instance `gitlab`, with `sources`, may not run on it, if it
    /// may not. Without its sources, its project alone is checked. A branch filter admits only
    /// a branch pipeline ([`branch_name`]) of a matching branch.
    pub fn refuses_job(
        &self,
        gitlab: &str,
        id: u64,
        sources: Option<&vk_hub_proto::job::Sources>,
    ) -> Option<String> {
        if self.runner.as_ref().is_none_or(|r| r.gitlab != gitlab) {
            return Some(format!("{gitlab} is not this lane's GitLab"));
        }
        let Ok(project) = self.project(gitlab, id) else {
            return Some(format!(
                "project {gitlab}/{id} is not one of its lane's projects"
            ));
        };
        let branches = project.and_then(|p| p.branches.as_ref());
        if let (Some(branches), Some(sources)) = (branches, sources)
            && !branch_name(sources)
                .is_some_and(|b| branches.iter().any(|p| crate::subject::glob_match(p, b)))
        {
            return Some("job is not a pipeline of a branch its lane allows".to_owned());
        }
        None
    }
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

fn default_probe() -> u32 {
    1
}

fn default_backoff_initial() -> u64 {
    1
}

fn default_secs() -> u64 {
    60
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// [`VERSION`]; required, so a policy of the earlier format is never read as this one.
    pub version: u32,
    #[serde(default)]
    pub lanes: Vec<Lane>,
    #[serde(default)]
    pub headroom: Vec<Headroom>,
    #[serde(default = "default_probe")]
    pub probe_limit: u32,
    #[serde(default = "default_probe")]
    pub production_probe_burst: u32,
    #[serde(default = "default_backoff_initial")]
    pub backoff_initial_secs: u64,
    #[serde(default = "default_secs")]
    pub backoff_max_secs: u64,
    #[serde(default = "default_secs")]
    pub busy_secs: u64,
}

impl Default for Policy {
    /// Every API key in the default lane; no runner mapped.
    fn default() -> Self {
        Self {
            version: VERSION,
            lanes: vec![Lane::new(&LaneId::Default)],
            headroom: Vec::new(),
            probe_limit: default_probe(),
            production_probe_burst: default_probe(),
            backoff_initial_secs: default_backoff_initial(),
            backoff_max_secs: default_secs(),
            busy_secs: default_secs(),
        }
    }
}

/// A policy file as operators write it: this format, or the earlier one, converted.
pub enum Parsed {
    Current(Policy),
    Converted(Converted),
}

/// Parse `bytes` as a policy: one naming a `version` as this format, any other as the earlier
/// format of tenants, converted ([`v1::convert`]).
pub fn parse(bytes: &[u8]) -> Result<Parsed> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value.get("version").is_some() {
        let policy: Policy = serde_json::from_value(value)?;
        return Ok(Parsed::Current(policy));
    }
    Ok(Parsed::Converted(convert_v1(bytes)?))
}

impl Policy {
    /// What `set` compares against: the sha256 of the policy as stored.
    pub fn digest(&self) -> Result<String> {
        Ok(digest_bytes(&serde_json::to_vec(self)?))
    }

    /// Lane `id`, if the policy has it.
    pub fn lane(&self, id: &LaneId) -> Option<&Lane> {
        self.lanes.iter().find(|l| l.id().as_ref() == Some(id))
    }

    /// The lane of the runner with GitLab runner ID `id` on instance `gitlab`, if mapped.
    pub fn runner(&self, gitlab: &str, id: u64) -> Option<&Lane> {
        self.lane(&LaneId::Runner {
            gitlab: gitlab.to_owned(),
            id,
        })
    }

    /// The lane an API key `principal` is charged to, and its ID: its own, else the default.
    pub fn client(&self, principal: &str) -> Option<(LaneId, &Lane)> {
        let own = LaneId::Key(principal.to_owned());
        if let Some(lane) = self.lane(&own) {
            return Some((own, lane));
        }
        self.lane(&LaneId::Default).map(|l| (LaneId::Default, l))
    }

    /// Whether some runner lane may run project `id` of instance `gitlab`, by listing it.
    pub fn lists_project(&self, gitlab: &str, id: u64) -> bool {
        self.lanes.iter().any(|l| {
            l.projects
                .iter()
                .flatten()
                .any(|p| p.gitlab == gitlab && p.id == id)
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            bail!("this hub reads capacity policy version {VERSION}");
        }
        if self.lanes.len() > MAX_LANES || self.headroom.len() > MAX_HEADROOMS {
            bail!("capacity policy exceeds its size limit");
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
        let mut sources = BTreeSet::new();
        for (i, lane) in self.lanes.iter().enumerate() {
            let Some(id) = lane.id() else {
                bail!(
                    "lane #{}: name exactly one of runner, key and default: true",
                    i + 1
                );
            };
            validate_lane(lane, &id).map_err(|e| anyhow::anyhow!("{id}: {e}"))?;
            if !sources.insert(id.clone()) {
                bail!("{id}: more than one lane");
            }
        }
        Ok(())
    }
}

fn valid_text(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TEXT && !s.chars().any(char::is_control)
}

fn validate_lane(lane: &Lane, id: &LaneId) -> Result<()> {
    match id {
        LaneId::Runner { gitlab, id } => {
            if !crate::store::valid_gitlab_name(gitlab) || *id == 0 {
                bail!("invalid GitLab instance name or runner ID");
            }
        }
        LaneId::Key(principal) => {
            if !valid_text(principal) {
                bail!("invalid API key principal");
            }
        }
        LaneId::Default => {}
    }
    if lane.weight == 0 || lane.max_slots == Some(0) {
        bail!("weight and max_slots must be positive");
    }
    if lane.runner.is_none() {
        if lane.class != Class::Normal {
            bail!("only a runner's lane may be production");
        }
        if lane.projects.is_some() {
            bail!("only a runner's lane lists projects");
        }
    }
    if let Some(nodes) = &lane.nodes {
        if nodes.is_empty() || nodes.len() > MAX_NODES {
            bail!("nodes must name 1 to {MAX_NODES} nodes or pools; omit it for any node");
        }
        let mut seen = BTreeSet::new();
        for n in nodes {
            if !vk_hub_proto::valid_id(n) && !crate::store::valid_name(n) {
                bail!("invalid node ID or pool name {n:?}");
            }
            if !seen.insert(n) {
                bail!("{n:?} listed twice");
            }
        }
    }
    if let Some(projects) = &lane.projects {
        if projects.len() > MAX_PROJECTS {
            bail!("more than {MAX_PROJECTS} projects");
        }
        let gitlab = lane.runner.as_ref().map(|r| r.gitlab.as_str());
        let mut seen = BTreeSet::new();
        for p in projects {
            if Some(p.gitlab.as_str()) != gitlab || p.id == 0 || !seen.insert(p.id) {
                bail!(
                    "invalid or duplicate project {}/{}: each must be on the runner's GitLab",
                    p.gitlab,
                    p.id
                );
            }
            if let Some(branches) = &p.branches
                && (branches.is_empty()
                    || branches.len() > MAX_BRANCHES
                    || branches.iter().any(|b| !valid_text(b)))
            {
                bail!(
                    "project {}/{}: branches must list 1 to {MAX_BRANCHES} patterns; omit it \
                     for any ref",
                    p.gitlab,
                    p.id
                );
            }
        }
    }
    if lane.class == Class::Production
        && lane
            .projects
            .as_ref()
            .is_none_or(|ps| ps.iter().any(|p| p.branches.is_none()))
    {
        bail!("a production lane must list its projects, each with its branches");
    }
    Ok(())
}

/// [`Policy::digest`] of a stored row, readable or not.
pub fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    vk_hub_proto::to_hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "0123456789abcdef0123456789abcdef";

    fn runner(id: u64) -> Lane {
        Lane::new(&LaneId::Runner {
            gitlab: "gl".into(),
            id,
        })
    }

    fn project(id: u64, branches: Option<&[&str]>) -> LaneProject {
        LaneProject {
            gitlab: "gl".into(),
            id,
            branches: branches.map(|b| b.iter().map(|s| (*s).to_owned()).collect()),
        }
    }

    fn with(lanes: Vec<Lane>) -> Policy {
        Policy {
            lanes,
            ..Policy::default()
        }
    }

    /// A lane given nodes may use a node listed or in a pool listed; without, any node.
    #[test]
    fn a_lane_may_use_its_nodes_and_its_pools_nodes() {
        let mut lane = runner(1);
        assert!(!lane.confined() && lane.allows_node(NODE, &[]));
        lane.nodes = Some(vec![NODE.into(), "trusted".into()]);
        let trusted = ["ci".to_string(), "trusted".to_string()];
        assert!(lane.allows_node(NODE, &[]));
        assert!(lane.allows_node("b", &trusted));
        assert!(!lane.allows_node("b", &["ci".into()]));
        // A node ID never names a pool.
        assert!(!lane.allows_node("c", &[NODE.into()]));
        with(vec![lane.clone()]).validate().unwrap();
        for (nodes, why) in [
            (vec![], "omit it for any node"),
            (vec!["not an id".to_owned()], "invalid node ID or pool name"),
            (vec!["a".into(), "a".into()], "\"a\" listed twice"),
            (vec![NODE.to_owned(); MAX_NODES + 1], "1 to 256"),
        ] {
            lane.nodes = Some(nodes);
            let err = with(vec![lane.clone()]).validate().unwrap_err().to_string();
            assert!(err.contains("runner gl/1") && err.contains(why), "{err}");
        }
    }

    #[test]
    fn policy_rejects_unknown_fields_another_version_and_invalid_headroom() {
        for json in [
            r#"{"version":2,"probe_limt":1}"#,
            r#"{"version":2,"lanes":[{"default":true,"wieght":2}]}"#,
            r#"{"version":2,"lanes":[{"runner":{"gitlab":"gl","id":1,"x":1}}]}"#,
            r#"{"version":2,"headroom":[{"placement":{"pool":"p","labels":[],"envelope":{"mem_mib":1,"cpus":1,"disk_bytes":0,"cpu":1}},"slots":1}]}"#,
            r#"{"lanes":[]}"#,
        ] {
            assert!(serde_json::from_str::<Policy>(json).is_err(), "{json}");
        }
        let policy: Policy = serde_json::from_str(r#"{"version":3}"#).unwrap();
        assert!(policy.validate().is_err());
        let mut policy = Policy::default();
        policy.headroom.push(Headroom {
            placement: Placement::default(),
            slots: 1,
        });
        assert!(policy.validate().is_err());
    }

    #[test]
    fn each_lane_names_one_source_once() {
        let mut both = runner(1);
        both.key = Some("k".into());
        let err = with(vec![both]).validate().unwrap_err().to_string();
        assert!(err.contains("lane #1"), "{err}");
        let err = with(vec![runner(1), runner(1)])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("runner gl/1: more than one lane"), "{err}");
        let mut policy = Policy::default();
        policy.lanes.push(Lane::new(&LaneId::Default));
        assert!(policy.validate().is_err());
    }

    #[test]
    fn key_lanes_are_normal_and_list_no_projects() {
        let mut key = Lane::new(&LaneId::Key("ci-bot".into()));
        with(vec![key.clone()]).validate().unwrap();
        key.class = Class::Production;
        assert!(with(vec![key.clone()]).validate().is_err());
        key.class = Class::Normal;
        key.projects = Some(vec![]);
        assert!(with(vec![key]).validate().is_err());
    }

    #[test]
    fn production_lanes_list_projects_with_branches() {
        let mut lane = runner(1);
        lane.class = Class::Production;
        assert!(with(vec![lane.clone()]).validate().is_err());
        lane.projects = Some(vec![]);
        with(vec![lane.clone()]).validate().unwrap();
        lane.projects = Some(vec![project(7, None)]);
        assert!(with(vec![lane.clone()]).validate().is_err());
        lane.projects = Some(vec![project(7, Some(&[]))]);
        assert!(with(vec![lane.clone()]).validate().is_err());
        lane.projects = Some(vec![project(7, Some(&["main"]))]);
        with(vec![lane]).validate().unwrap();
    }

    #[test]
    fn lane_projects_are_on_the_runner_s_gitlab_once() {
        let mut lane = runner(1);
        lane.projects = Some(vec![LaneProject {
            gitlab: "other".into(),
            id: 7,
            branches: None,
        }]);
        assert!(with(vec![lane.clone()]).validate().is_err());
        lane.projects = Some(vec![project(7, None), project(7, None)]);
        assert!(with(vec![lane.clone()]).validate().is_err());
        lane.weight = 0;
        lane.projects = None;
        assert!(with(vec![lane]).validate().is_err());
    }

    #[test]
    fn a_lane_refuses_jobs_of_other_projects_and_branches() {
        use vk_hub_proto::job::Sources;
        let sha = "a".repeat(40);
        let on = |branch: &str| Sources {
            git_ref: branch.into(),
            sha: sha.clone(),
            refspecs: vec![format!("+refs/heads/{branch}:refs/remotes/origin/{branch}")],
            ..Sources::default()
        };
        let mut lane = runner(1);
        assert_eq!(lane.refuses_job("gl", 7, Some(&on("x"))), None);
        assert!(lane.refuses_job("other", 7, None).is_some());
        lane.projects = Some(vec![]);
        assert!(lane.refuses_job("gl", 7, None).is_some());
        lane.projects = Some(vec![project(7, Some(&["main", "release/*"]))]);
        assert_eq!(lane.refuses_job("gl", 7, Some(&on("release/1"))), None);
        assert!(lane.refuses_job("gl", 7, Some(&on("feature"))).is_some());
        assert!(lane.refuses_job("gl", 8, None).is_some());
        // A merge request's pipeline, though of a matching ref.
        let mut mr = on("main");
        mr.refspecs = vec!["+refs/merge-requests/1/head:refs/merge-requests/1/head".into()];
        assert!(lane.refuses_job("gl", 7, Some(&mr)).is_some());
        // Its sources unknown: its project alone.
        assert_eq!(lane.refuses_job("gl", 7, None), None);
    }

    #[test]
    fn a_lane_is_found_by_its_source() {
        let mut policy = with(vec![runner(42), Lane::new(&LaneId::Key("ci-bot".into()))]);
        assert!(policy.runner("gl", 42).is_some());
        assert!(policy.runner("gl", 43).is_none());
        assert_eq!(
            policy.client("ci-bot").map(|(id, _)| id),
            Some(LaneId::Key("ci-bot".into()))
        );
        assert!(policy.client("other").is_none());
        policy.lanes.push(Lane::new(&LaneId::Default));
        assert_eq!(
            policy.client("other").map(|(id, _)| id),
            Some(LaneId::Default)
        );
    }

    #[test]
    fn validation_bounds_headroom_and_names_the_entry() {
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
    }

    #[test]
    fn the_default_policy_round_trips_and_lists_the_default_lane() {
        let policy = Policy::default();
        policy.validate().unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains(r#""lanes":[{"default":true,"class":"normal","weight":1}]"#));
        assert_eq!(serde_json::from_str::<Policy>(&json).unwrap(), policy);
        let Parsed::Current(parsed) = parse(json.as_bytes()).unwrap() else {
            panic!("read as the earlier format");
        };
        assert_eq!(parsed, policy);
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
}
