//! Shared fleet operations for every front end. Mutations take an actor (`uid <n>` on the
//! admin socket), which the store audits with the change.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{Acquisition, Command, DesiredState, Operation, Report};

use crate::rollout::{
    DeleteRule, NodeStatus, Rollout, RolloutAction, RolloutNode, RolloutRow, RolloutState,
};
use crate::server::{Hub, Reach};
use crate::store::{
    AccountChange, DesiredChange, MonitoringOnly, NodeRow, NotEnrolled, Release, Role, Tools,
    ToolsUnsupported,
};
use crate::target::{Standing, TargetRow};

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
    /// The IP address its latest session came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<std::net::IpAddr>,
    /// The account its `vk node run` runs as, from its inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub vk: Option<String>,
    pub cpus: Option<u32>,
    pub mem_total_mib: Option<u64>,
    pub committed_mib: Option<u64>,
    pub budget_mib: Option<u64>,
    /// The vCPUs its admitted jobs have; `None` from a node that does not count them.
    #[serde(default)]
    pub committed_cpus: Option<u32>,
    /// What its jobs' vCPUs together may reach; `None` without a vCPU budget.
    #[serde(default)]
    pub cpu_budget: Option<u32>,
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
    /// The pools placed jobs may name it by.
    #[serde(default)]
    pub pools: Vec<String>,
    /// The labels it declares.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Why it refused the hub's latest offer of a reservation, while it accepts none.
    #[serde(default)]
    pub last_refusal: Option<String>,
    /// The CI tools it built from a definition of the hub's and made current.
    #[serde(default)]
    pub tools: Option<vk_hub_proto::ToolsInstalled>,
    /// The reservations and jobs not finished the hub has placed on it, as counted against its
    /// cap (the smaller of its ceiling and its own max_concurrency); `None` from a hub that
    /// places no jobs.
    #[serde(default)]
    pub placed: Option<u64>,
    /// It takes none of the hub's jobs: `[jobs] egress_rules` is on and it does not enforce
    /// the hub's egress rules.
    #[serde(default)]
    pub without_egress_rules: bool,
    /// It takes none of the hub's jobs: `[jobs] require_job_build_cache` is on and it does not
    /// announce `job_build_cache`.
    #[serde(default)]
    pub without_job_build_cache: bool,
    /// Where it stands against the hub's target release, in words, when there is anything to
    /// say: behind it, being updated, failed, or left alone and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<String>,
    /// Where it stands against the CI tools the hub's `tools` setting keeps it on, in words,
    /// when it does not have them: being built, failed, or not asked for yet and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_deploy: Option<String>,
    /// How the files of its CI tools compare with those other nodes installed from the same
    /// definition; `None` when it reports none, or no other node does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_peers: Option<crate::outputs::Peers>,
}

impl NodeView {
    /// Whether the node's latest session could not carry steering: it is monitored only.
    pub fn monitoring_only(&self) -> bool {
        self.protocol.is_some_and(|v| v < vk_hub_proto::STEERING)
    }
}

/// Every enrolled node, as `vk-hub nodes` shows it, ordered by hostname.
pub fn node_views(hub: &Hub) -> Result<Vec<NodeView>> {
    let target = hub.db.target()?;
    let nodes = hub.db.nodes()?;
    let outputs = tools_outputs(&nodes);
    let mut views: Vec<NodeView> = nodes
        .iter()
        .map(|(id, row)| node_view_among(hub, id.clone(), row, target.as_ref(), &nodes, &outputs))
        .collect();
    views.sort_by(|a, b| (&a.hostname, &a.id).cmp(&(&b.hostname, &b.id)));
    Ok(views)
}

/// What every node of `nodes` installed, by definition ([`crate::outputs`]).
pub fn tools_outputs(
    nodes: &[(String, NodeRow)],
) -> std::collections::BTreeMap<String, crate::outputs::DefinitionOutputs> {
    crate::outputs::by_definition(nodes.iter().filter_map(|(id, row)| {
        Some((
            id.as_str(),
            row.inventory.as_ref()?.versions.tools.as_ref()?,
        ))
    }))
}

/// Node `id`'s row as `vk-hub nodes` shows it, against the hub's `target` release if one is set.
pub fn node_view(hub: &Hub, id: String, row: &NodeRow, target: Option<&TargetRow>) -> NodeView {
    // Without the other nodes, nothing to compare its tools with, rather than no view.
    let nodes = hub.db.nodes().unwrap_or_default();
    let outputs = tools_outputs(&nodes);
    node_view_among(hub, id, row, target, &nodes, &outputs)
}

/// [`node_view`], its tools compared with what the `nodes` installed, `outputs`.
fn node_view_among(
    hub: &Hub,
    id: String,
    row: &NodeRow,
    target: Option<&TargetRow>,
    nodes: &[(String, NodeRow)],
    outputs: &std::collections::BTreeMap<String, crate::outputs::DefinitionOutputs>,
) -> NodeView {
    let inventory = row.inventory.as_ref();
    let tools_peers = inventory
        .and_then(|i| i.versions.tools.as_ref())
        .and_then(|t| {
            crate::outputs::peers(&id, t, outputs, |n| {
                nodes
                    .iter()
                    .find(|(id, _)| id == n)
                    .map_or_else(|| n.to_string(), |(_, row)| row.hostname.clone())
            })
        });
    let admission = row.heartbeat.as_ref().and_then(|h| h.admission.as_ref());
    NodeView {
        connected: hub.reach(&id) == Reach::Connected,
        hostname: row.hostname.clone(),
        last_seen: row.last_seen,
        address: row.address,
        user: inventory.and_then(|i| i.user.clone()),
        vk: inventory.map(|i| i.versions.vk.clone()),
        cpus: inventory.map(|i| i.hardware.cpus),
        mem_total_mib: inventory.and_then(|i| i.hardware.mem_total_mib),
        committed_mib: admission.map(|a| a.committed_mib),
        budget_mib: admission.and_then(|a| a.budget_mib),
        committed_cpus: admission.and_then(|a| a.committed_cpus),
        cpu_budget: admission.and_then(|a| a.cpu_budget),
        workloads: row.workloads,
        protocol: row.protocol,
        desired: row.desired.clone(),
        report: row.report.clone(),
        // A count that cannot be read is shown as none rather than failing the listing.
        pending_commands: hub
            .db
            .pending_commands(&id, crate::now_secs())
            .map_or(0, |c| c.len()),
        pools: row.pools.clone(),
        labels: inventory.map(|i| i.labels.clone()).unwrap_or_default(),
        last_refusal: crate::jobs::last_refusal(hub, &id),
        tools: inventory.and_then(|i| i.versions.tools.clone()),
        placed: crate::jobs::accepting(hub)
            .is_ok()
            .then(|| crate::jobs::placed_on(hub, &id)),
        without_egress_rules: crate::jobs::accepting(hub).is_ok()
            && !crate::jobs::enforces_rules(hub, row),
        without_job_build_cache: crate::jobs::accepting(hub).is_ok()
            && !crate::jobs::caches_builds_as_required(hub, row),
        auto_update: target.and_then(|t| crate::target::standing(t, &id, row).note(t)),
        // A note that cannot be read is left out rather than failing the listing.
        tools_deploy: tools_note(hub, &id, row).ok().flatten(),
        tools_peers,
        id,
    }
}

/// [`NodeView::tools_deploy`] for node `id` of row `row`.
fn tools_note(hub: &Hub, id: &str, row: &NodeRow) -> Result<Option<String>> {
    let builtin = &crate::tools::builtin().packed.sha256;
    let named =
        crate::deploy::Named::of(hub.db.settings_layers()?.merged(id).get(crate::deploy::KEY));
    let wanted = hub.db.tools_wanted(id, builtin)?;
    let wanted = match &wanted {
        None => return Ok(None),
        Some(Ok((sha, row))) => Ok((sha.as_str(), row.version.as_str())),
        Some(Err(why)) => Err(why.as_str()),
    };
    let deploys = hub.db.tools_deploys()?;
    let connected = hub.reach(id) == Reach::Connected;
    Ok(crate::deploy::note(
        &named,
        wanted,
        deploys.get(id),
        row,
        connected,
        crate::now_secs(),
    ))
}

/// Replace node `id`'s pools as `actor`. Log even if unchanged; notify the hub's watchers
/// only on change. Return whether the pools changed.
pub fn set_pools(hub: &Hub, actor: &str, id: &str, pools: &[String]) -> Result<bool> {
    let changed = hub.db.set_pools(id, pools, actor, crate::now_secs())?;
    let what = if pools.is_empty() {
        "took it out of every pool".to_string()
    } else {
        // Sorted and deduplicated as the store keeps and audits them.
        let mut sorted = pools.to_vec();
        sorted.sort();
        sorted.dedup();
        format!("put it in pools {}", sorted.join(", "))
    };
    if changed {
        eprintln!("vk-hub: node {id}: {actor} {what}");
        hub.changed(id);
    } else {
        eprintln!("vk-hub: node {id}: {actor} {what}: already so");
    }
    Ok(changed)
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
    let changed = hub.db.set_desired(
        id,
        DesiredChange::Ceiling(ceiling),
        actor,
        &what,
        crate::now_secs(),
    )?;
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
        DesiredChange::Acquisition(acquisition),
        actor,
        what,
        crate::now_secs(),
    )?;
    desired_changed(hub, actor, id, what, changed.as_ref());
    Ok(changed)
}

/// Remove node `id` as `actor`: unpin its key, end its session and withdraw its registry
/// access. Return whether the node existed.
pub fn remove_node(hub: &Hub, actor: &str, id: &str) -> Result<bool> {
    let removed = crate::tokens::remove_node(hub, id, actor)?;
    if removed {
        hub.revoke(id);
        hub.touch();
        // The revocation is recorded; the hourly sync sends it if this fails.
        if let Err(e) = crate::tokens::sync_all(hub) {
            eprintln!(
                "vk-hub: sending node {}'s revocation to registries: {e:#}",
                vk_hub_proto::display_safe(id)
            );
        }
    }
    Ok(removed)
}

/// Issue `operation` to node `id`, as `actor`, valid for [`COMMAND_TTL`]. An update is issued
/// by [`update`], which names a release the hub holds, and a tools build by [`tools`].
pub fn command(hub: &Hub, actor: &str, id: &str, operation: Operation) -> Result<Command> {
    match operation {
        Operation::Update { .. } => bail!("an update names a release; see `vk-hub nodes update`"),
        Operation::Tools { .. } => {
            bail!("a tools build names a definition the hub holds; see `vk-hub nodes tools`")
        }
        operation => issue(hub, actor, id, operation),
    }
}

/// The definition `name` names: `builtin`, or a sha256 or a prefix of at least 8 hex digits.
fn resolve_tools(hub: &Hub, name: &str) -> Result<Tools> {
    if name != crate::deploy::BUILTIN {
        return hub.db.resolve_tools(name);
    }
    let sha256 = crate::tools::builtin().packed.sha256.clone();
    match hub.db.tools(&sha256)? {
        Some(row) => Ok(Tools { sha256, row }),
        None => bail!("the hub does not hold its built-in tools; its log says why"),
    }
}

/// The tools node `id` is to build, as an operator asked for `tools` (or, with `None`, those
/// the hub's `tools` setting keeps it on), and whether they are the setting's: refused when
/// the setting keeps it on others.
fn tools_for(hub: &Hub, id: &str, tools: Option<&Tools>) -> Result<(Tools, bool)> {
    let builtin = &crate::tools::builtin().packed.sha256;
    let wanted = hub.db.tools_wanted(id, builtin)?;
    match (tools, wanted) {
        (Some(t), Some(Ok((sha, row)))) if t.sha256 != sha => bail!(
            "the hub's `tools` setting keeps it on the CI tools {} ({}); `vk-hub settings set \
             tools <sha256> --node {id}` names others",
            row.version,
            crate::store::short(&sha)
        ),
        (Some(t), Some(Ok(_))) => Ok((t.clone(), true)),
        (Some(t), _) => Ok((t.clone(), false)),
        (None, Some(Ok((sha256, row)))) => Ok((Tools { sha256, row }, true)),
        (None, Some(Err(why))) => bail!("{why}"),
        (None, None) => {
            bail!("the hub's `tools` setting leaves its CI tools alone; name the tools to build")
        }
    }
}

/// Issue node `id` the build of `tools`, as `actor`; followed as an automatic one when they
/// are what its `tools` setting names (`kept`).
fn issue_tools(hub: &Hub, actor: &str, id: &str, tools: &Tools, kept: bool) -> Result<Command> {
    let command = issue(hub, actor, id, tools_operation(tools))?;
    if kept {
        hub.db
            .follow_tools(id, &tools.sha256, &command.id, actor, crate::now_secs())?;
    }
    Ok(command)
}

/// Have node `id` build the tools definition `tools` names ([`resolve_tools`]), or with `None`
/// those the hub's `tools` setting keeps it on, and make the tools current, as `actor`. Tools
/// other than the setting's are refused unless it is `none`; the setting's are followed as an
/// automatic build, a failed one of them forgotten. A node whose latest session ran below [`vk_hub_proto::TOOLS`] is refused, as
/// is one building them already.
pub fn tools(hub: &Hub, actor: &str, id: &str, tools: Option<&str>) -> Result<Command> {
    // Held from the lookup to the command, so the definition cannot be removed between them.
    let _held = hub.tools_lock();
    let named = tools.map(|t| resolve_tools(hub, t)).transpose()?;
    let (tools, kept) = tools_for(hub, id, named.as_ref())?;
    // One that cannot take a build at all hears why from the issue.
    let takes = hub
        .db
        .node(id)?
        .is_some_and(|n| n.protocol.is_none_or(|v| v >= vk_hub_proto::TOOLS));
    if takes
        && hub
            .db
            .building_tools(id, &tools.sha256, crate::now_secs())?
    {
        bail!("it is building these tools already");
    }
    issue_tools(hub, actor, id, &tools, kept)
}

/// What became of one node in [`tools_all`]: the command issued to it, or why it was skipped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolsIssued {
    pub id: String,
    pub hostname: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub skipped: Option<String>,
}

/// [`tools`] for every node, as `actor`, but those that cannot take it or have no need to:
/// a node monitored only or whose latest session ran below [`vk_hub_proto::TOOLS`], one the
/// hub's `tools` setting keeps on other tools (or, without `tools`, leaves alone), one that has
/// the tools current already, and one with a build of them still under way. Ordered by
/// hostname. Any other error ends it, leaving the commands already issued.
pub fn tools_all(hub: &Hub, actor: &str, tools: Option<&str>) -> Result<Vec<ToolsIssued>> {
    let _held = hub.tools_lock();
    let named = tools.map(|t| resolve_tools(hub, t)).transpose()?;
    let mut nodes = hub.db.nodes()?;
    nodes.sort_by(|a, b| (&a.1.hostname, &a.0).cmp(&(&b.1.hostname, &b.0)));
    let now = crate::now_secs();
    let mut out = Vec::new();
    for (id, row) in nodes {
        let skipped = |why: String| ToolsIssued {
            id: id.clone(),
            hostname: row.hostname.clone(),
            command: None,
            skipped: Some(why),
        };
        let (tools, kept) = match tools_for(hub, &id, named.as_ref()) {
            Ok(t) => t,
            Err(e) => {
                out.push(skipped(format!("{e:#}")));
                continue;
            }
        };
        let has = crate::deploy::current(&row) == Some(tools.sha256.as_str());
        let skip = match row.protocol {
            Some(v) if v < vk_hub_proto::TOOLS => Some(format!(
                "speaks protocol version {v}, and tools take version {}: update its vk",
                vk_hub_proto::TOOLS
            )),
            _ if has => Some("has these tools current already".to_string()),
            _ if hub.db.building_tools(&id, &tools.sha256, now)? => {
                Some("is building these tools already".to_string())
            }
            _ => None,
        };
        if let Some(why) = skip {
            out.push(skipped(why));
            continue;
        }
        // The node may have changed since the lookup. Skip the same refusals at issue
        // time; any other error ends the run.
        let (command, skipped) = match issue_tools(hub, actor, &id, &tools, kept) {
            Ok(c) => (Some(c.id), None),
            Err(e)
                if e.is::<MonitoringOnly>()
                    || e.is::<ToolsUnsupported>()
                    || e.is::<NotEnrolled>() =>
            {
                (None, Some(format!("{e:#}")))
            }
            Err(e) => return Err(e),
        };
        out.push(ToolsIssued {
            id,
            hostname: row.hostname,
            command,
            skipped,
        });
    }
    Ok(out)
}

/// The command that has a node build and install `tools`.
fn tools_operation(tools: &Tools) -> Operation {
    Operation::Tools {
        version: tools.row.version.clone(),
        sha256: tools.sha256.clone(),
        size: tools.row.size,
    }
}

/// Update node `id` to the release whose sha256 starts with `release`, as `actor`. `force`
/// asks a node whose runner is external to update without draining. A node a rollout still
/// has to update is refused until the rollout is over.
pub fn update(hub: &Hub, actor: &str, id: &str, release: &str, force: bool) -> Result<Command> {
    // Held from the lookup to the command, so the release cannot be removed between them.
    let _held = hub.releases_lock();
    let release = hub.db.resolve_release(release)?;
    nodes_release(&release)?;
    issue(hub, actor, id, update_operation(&release, force, None))
}

/// Refuse a release of another program than `vk`: a node runs nothing else.
fn nodes_release(release: &Release) -> Result<()> {
    if !release.row.is(crate::store::Program::Vk) {
        bail!(
            "release {} is {} {}, not a vk a node updates to",
            crate::store::short(&release.sha256),
            release.row.program(),
            release.row.version
        );
    }
    Ok(())
}

/// The command that updates a node to `release`, to be over within `within_secs` of its drain.
pub(crate) fn update_operation(
    release: &Release,
    force: bool,
    within_secs: Option<u64>,
) -> Operation {
    Operation::Update {
        version: release.row.version.clone(),
        sha256: release.sha256.clone(),
        size: release.row.size,
        signature: release.row.signature.clone(),
        force,
        within_secs,
    }
}

fn issue(hub: &Hub, actor: &str, id: &str, operation: Operation) -> Result<Command> {
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

/// Which nodes a rollout goes to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    All,
    /// Node IDs, or prefixes of at least 8 digits naming one each.
    Nodes(Vec<String>),
}

/// How a rollout goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPlan {
    /// The release's sha256, or a prefix of at least 8 hex digits.
    pub release: String,
    pub nodes: Selection,
    pub batch: u32,
    pub canary_per_profile: bool,
    pub max_failures: u32,
    pub node_timeout_secs: u64,
    pub drain_timeout_secs: u64,
    /// Include nodes whose runner is external, updated without a drain.
    pub force: bool,
}

/// Start rolling a release out, as `actor`. Nodes already running it, nodes only monitored and
/// nodes [`crate::rollout::ineligible`] are skipped from the start, so canaries are picked
/// among the rest.
pub fn create_rollout(hub: &Hub, actor: &str, plan: &RolloutPlan) -> Result<Rollout> {
    let (release, nodes) = plan_rollout(hub, plan)?;
    start_rollout(hub, actor, plan, &release, nodes)
}

/// What [`create_rollout`] would start, without starting it: the release, and its nodes by
/// wave, with those it skips and why.
pub fn plan_rollout(hub: &Hub, plan: &RolloutPlan) -> Result<(Release, Vec<RolloutNode>)> {
    if plan.batch == 0 {
        bail!("a batch is at least one node");
    }
    if plan.node_timeout_secs < 60 || plan.drain_timeout_secs < 60 {
        bail!("a node's drain and its update need at least a minute each");
    }
    let release = hub.db.resolve_release(&plan.release)?;
    nodes_release(&release)?;
    let nodes = hub.db.nodes()?;
    let chosen: Vec<(String, NodeRow)> = match &plan.nodes {
        Selection::All => nodes,
        Selection::Nodes(wanted) => {
            let mut chosen: Vec<(String, NodeRow)> = Vec::new();
            for want in wanted {
                if want.len() < 8 {
                    bail!(
                        "{}: name a node by its ID, or at least its first 8 hex digits",
                        vk_hub_proto::display_safe(want)
                    );
                }
                let mut found = nodes.iter().filter(|(id, _)| id.starts_with(want.as_str()));
                match (found.next(), found.next()) {
                    (Some(n), None) => {
                        if !chosen.iter().any(|(id, _)| *id == n.0) {
                            chosen.push(n.clone());
                        }
                    }
                    (None, _) => bail!("there is no node {}", vk_hub_proto::display_safe(want)),
                    (Some(_), Some(_)) => bail!(
                        "{} names more than one node",
                        vk_hub_proto::display_safe(want)
                    ),
                }
            }
            chosen
        }
    };
    if chosen.is_empty() {
        bail!("there is no node to roll out to");
    }
    let (mut skipped, mut to_do) = (Vec::new(), Vec::new());
    let mut planned_vk = HashMap::new();
    for (id, row) in chosen {
        let facts = crate::rollout::Facts::of(&row);
        let profile = crate::rollout::profile(row.inventory.as_ref());
        let skip = match row.protocol {
            Some(v) if v < vk_hub_proto::STEERING => Some(crate::rollout::monitoring_only(v)),
            _ if facts.runs(&release.sha256, &release.row.version) => {
                Some("already runs the release".to_string())
            }
            _ => crate::rollout::ineligible(&facts, plan.force).map(str::to_string),
        };
        match skip {
            Some(reason) => skipped.push((id, row.hostname, profile, reason)),
            None => {
                planned_vk.insert(id.clone(), facts.vk);
                to_do.push((id, row.hostname, profile));
            }
        }
    }
    let mut nodes = crate::rollout::plan(to_do, plan.batch, plan.canary_per_profile);
    for node in &mut nodes {
        node.planned_vk = planned_vk.remove(&node.id).flatten();
    }
    nodes.extend(
        skipped
            .into_iter()
            .map(|(id, hostname, profile, reason)| RolloutNode {
                id,
                hostname,
                profile,
                wave: 0,
                status: NodeStatus::Skipped { reason },
                planned_vk: None,
            }),
    );
    Ok((release, nodes))
}

/// The rollout [`plan_rollout`] planned, started by `actor` at `now`.
fn rollout_row(
    actor: &str,
    plan: &RolloutPlan,
    release: &Release,
    nodes: Vec<RolloutNode>,
    now: u64,
) -> RolloutRow {
    RolloutRow {
        release: release.sha256.clone(),
        version: release.row.version.clone(),
        created_at: now,
        created_by: actor.to_string(),
        batch: plan.batch,
        canary_per_profile: plan.canary_per_profile,
        max_failures: plan.max_failures,
        node_timeout_secs: plan.node_timeout_secs,
        drain_timeout_secs: plan.drain_timeout_secs,
        force: plan.force,
        state: RolloutState::Running,
        failures: 0,
        nodes,
    }
}

/// Start the rollout [`plan_rollout`] planned, as `actor`.
pub fn start_rollout(
    hub: &Hub,
    actor: &str,
    plan: &RolloutPlan,
    release: &Release,
    nodes: Vec<RolloutNode>,
) -> Result<Rollout> {
    let row = rollout_row(actor, plan, release, nodes, crate::now_secs());
    let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
    hub.db.create_rollout(&id, &row, actor)?;
    eprintln!(
        "vk-hub: {actor} started rollout {} of vk {}",
        crate::rollout::short_id(&id),
        row.version
    );
    hub.touch();
    Ok(Rollout { id, row })
}

/// The target, as `vk-hub release target` shows it: where each node stands against it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetView {
    pub target: TargetRow,
    /// Each node's ID, hostname and standing, by hostname.
    pub nodes: Vec<(String, String, Standing)>,
}

/// The target and any rollout it started over nodes running an older version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSet {
    pub target: TargetRow,
    pub rollout: Option<Rollout>,
}

/// The target and where each node stands against it, or `None` when none is set.
pub fn target_view(hub: &Hub) -> Result<Option<TargetView>> {
    let Some(target) = hub.db.target()? else {
        return Ok(None);
    };
    let mut nodes: Vec<(String, String, Standing)> = hub
        .db
        .nodes()?
        .into_iter()
        .map(|(id, row)| {
            let standing = crate::target::standing(&target, &id, &row);
            (id, row.hostname, standing)
        })
        .collect();
    nodes.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
    Ok(Some(TargetView { target, nodes }))
}

/// Make the release whose sha256 starts with `release` the target, as `actor`, and start a
/// rollout of it, with `vk-hub rollout create`'s defaults, over the nodes behind it. The
/// release must be a `vk` of `MAJOR.MINOR.PATCH`, signed by one of `[nodes] release_keys`
/// when any is set.
pub fn set_target(hub: &Hub, actor: &str, release: &str) -> Result<TargetSet> {
    // Held from the lookup to the write, so the release cannot be removed between them.
    let _held = hub.releases_lock();
    let release = hub.db.resolve_release(release)?;
    nodes_release(&release)?;
    if !crate::target::orderable(&release.row.version) {
        bail!(
            "vk {} is not MAJOR.MINOR.PATCH, which nodes are ordered against",
            release.row.version
        );
    }
    if !hub.node_release_keys().is_empty() {
        vk_peer::release_key::Policy::from_config_in(
            "[nodes]",
            vk_peer::release_key::Program::Vk,
            hub.node_release_keys(),
            None,
        )?
        .check(
            &release.sha256,
            &release.row.version,
            release.row.signature.as_deref(),
        )
        .map_err(|e| anyhow!("{e}; a target must be signed by one of them"))?;
    }
    let now = crate::now_secs();
    let mut target = TargetRow {
        release: release.sha256.clone(),
        version: release.row.version.clone(),
        signature: release.row.signature.clone(),
        set_at: now,
        set_by: actor.to_string(),
        rollout: None,
        held: None,
        nodes: Default::default(),
    };
    let behind: Vec<String> = hub
        .db
        .nodes()?
        .into_iter()
        .filter(|(id, row)| crate::target::standing(&target, id, row) == Standing::Due)
        .map(|(id, _)| id)
        .collect();
    let mut rollout = None;
    if !behind.is_empty() {
        let plan = RolloutPlan {
            release: release.sha256.clone(),
            nodes: Selection::Nodes(behind),
            batch: 1,
            canary_per_profile: false,
            max_failures: 0,
            node_timeout_secs: crate::rollout::NODE_TIMEOUT_SECS,
            drain_timeout_secs: crate::rollout::DRAIN_TIMEOUT_SECS,
            force: false,
        };
        let (release, nodes) = plan_rollout(hub, &plan)?;
        if nodes.iter().any(|n| n.status == NodeStatus::Pending) {
            let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
            target.rollout = Some(id.clone());
            rollout = Some(Rollout {
                id,
                row: rollout_row(actor, &plan, &release, nodes, now),
            });
        }
    }
    hub.db.set_target(
        &target,
        rollout.as_ref().map(|r| (r.id.as_str(), &r.row)),
        actor,
    )?;
    eprintln!(
        "vk-hub: {actor} set the target to vk {}{}",
        target.version,
        match &rollout {
            Some(r) => format!(", rollout {}", crate::rollout::short_id(&r.id)),
            None => String::new(),
        }
    );
    hub.touch();
    Ok(TargetSet { target, rollout })
}

/// Clear the target, as `actor`; the target it was, or `None` when none was set.
pub fn clear_target(hub: &Hub, actor: &str) -> Result<Option<TargetRow>> {
    let cleared = hub.db.clear_target(actor, crate::now_secs())?;
    if let Some(t) = &cleared {
        eprintln!("vk-hub: {actor} cleared the target, vk {}", t.version);
        hub.touch();
    }
    Ok(cleared)
}

/// Allow failed target updates to be retried for IDs starting with `node`, or all with
/// `None`, and lift any automatic-update hold, as `actor`. Return the nodes allowed to retry
/// and whether a hold was lifted.
pub fn retry_target(hub: &Hub, actor: &str, node: Option<&str>) -> Result<(Vec<String>, bool)> {
    if let Some(node) = node
        && node.len() < 8
    {
        bail!(
            "{}: name a node by its ID, or at least its first 8 hex digits",
            vk_hub_proto::display_safe(node)
        );
    }
    let (retried, lifted) = hub.db.retry_target(node, actor, crate::now_secs())?;
    if !retried.is_empty() || lifted {
        eprintln!(
            "vk-hub: {actor} let {} node(s) be updated to the target again",
            retried.len()
        );
        hub.touch();
    }
    Ok((retried, lifted))
}

/// Every rollout, newest first.
pub fn rollouts(hub: &Hub) -> Result<Vec<Rollout>> {
    Ok(hub
        .db
        .rollouts()?
        .into_iter()
        .map(|(id, row)| Rollout { id, row })
        .collect())
}

/// Pause, resume or abort the rollout whose ID starts with `id`, as `actor`.
pub fn steer_rollout(hub: &Hub, actor: &str, id: &str, action: RolloutAction) -> Result<Rollout> {
    let (id, _) = hub.db.resolve_rollout(id)?;
    let row = hub
        .db
        .steer_rollout(&id, action, actor, crate::now_secs())?;
    eprintln!(
        "vk-hub: {actor} {} rollout {}",
        action.done(),
        crate::rollout::short_id(&id)
    );
    hub.touch();
    Ok(Rollout { id, row })
}

/// Delete the rollout whose ID starts with `id`, as `actor`, if `rule` lets it. Returns it as
/// it was, or `None` when there is no such rollout, or it was deleted meanwhile.
pub fn delete_rollout(
    hub: &Hub,
    actor: &str,
    id: &str,
    rule: DeleteRule,
) -> Result<Option<Rollout>> {
    let Some((id, _)) = hub.db.find_rollout(id)? else {
        return Ok(None);
    };
    let Some(row) = hub.db.delete_rollout(&id, rule, actor, crate::now_secs())? else {
        return Ok(None);
    };
    eprintln!(
        "vk-hub: {actor} deleted rollout {} of vk {}",
        crate::rollout::short_id(&id),
        row.version
    );
    hub.touch();
    Ok(Some(Rollout { id, row }))
}

/// The result of granting or revoking a role.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountOutcome {
    /// The address, normalized, or `*`.
    pub email: String,
    pub change: AccountChange,
    /// Whether the running hub has `[oidc]`.
    pub oidc: bool,
}

/// Grant `email` — an address or `*` — `role`, or revoke its grant with `None`, as `actor`,
/// ending the web UI sessions that now hold more than a sign-in gets. With
/// `keep_an_operator`, refused with [`crate::store::LastOperator`] where it would take the
/// operator role from the last address granted it.
pub fn set_account(
    hub: &Hub,
    actor: &str,
    email: &str,
    role: Option<Role>,
    keep_an_operator: bool,
) -> Result<AccountOutcome> {
    let email = crate::store::account_key(email)
        .ok_or_else(|| anyhow!("{email:?} is neither an email address nor *"))?;
    let now = crate::now_secs();
    let change = hub
        .db
        .change_account(&email, role, keep_an_operator, actor, now)?;
    if change.previous != role {
        let what = match role {
            Some(role) => format!("granted {email} the {} role", role.name()),
            None => format!("revoked {email}'s grant"),
        };
        eprintln!(
            "vk-hub: {actor} {what}, ending {} web UI session(s)",
            change.ended
        );
    }
    if change.ended > 0 {
        // Their pages' live updates end on it.
        hub.sessions_changed();
    }
    Ok(AccountOutcome {
        email,
        change,
        oidc: hub.oidc,
    })
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
