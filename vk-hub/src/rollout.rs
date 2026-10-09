//! Rollouts: one release to many nodes, a wave at a time — one canary per hardware profile
//! first when asked, then batches — each wave's nodes updated and back where they were before
//! the next wave starts. A failure pauses the rollout for an operator to look at; past
//! `max_failures` it aborts it instead.
//!
//! A rollout is a row in the hub's database, and [`step`] is a pure function of that row and
//! what the database says of its nodes: the hub's [`drive`] task applies it inside one write
//! transaction per rollout, with the commands it issues and the audit lines it writes, so a
//! restarted hub picks every rollout up where its database left it.
//!
//! **Profiles.** A node's hardware profile is its CPU model, its RAM rounded to the nearest
//! power of two in GiB, and the speed classes its operator declared for its job and checkout
//! filesystems — what makes one host behave unlike another under the same `vk`, and nothing
//! that moves from one heartbeat to the next.
//!
//! **A node's update** counts as done once its command is `done`, the node reports running
//! the release (by sha256, or by version for a node that reports none), and it is back ready
//! or drained — the state it was in when the update was issued, unless an operator changed it
//! meanwhile. The drain has a window of its own, the command's expiry, past
//! which a node still draining calls the update off; the update proper has the node timeout
//! from the end of the drain, which the node enforces as its own deadline, rolling back past
//! it. The hub counts a failure in either window only [`GIVE_UP_GRACE_SECS`] after it ends, so
//! an update it has given up on is never kept. A node unreachable all along times out in its
//! drain window. A hub that has just started judges no window before its nodes have had that
//! grace to reconnect and report: what its database says of them predates its downtime.
//!
//! A node whose latest session ran a protocol version below [`vk_hub_proto::STEERING`] is
//! monitored only: it takes no command, so a rollout skips it rather than wait on it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vk_hub_proto::{Inventory, NodeState, Outcome, SpeedClass, StorageRole};

use crate::server::Hub;
use crate::store::NodeRow;

/// A rollout, as the database keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutRow {
    /// The release's sha256.
    pub release: String,
    pub version: String,
    pub created_at: u64,
    pub created_by: String,
    /// Nodes per wave after the canaries.
    pub batch: u32,
    pub canary_per_profile: bool,
    /// Failures a rollout absorbs, pausing at each, before it aborts.
    pub max_failures: u32,
    /// How long a node's update may take once its drain is over; the node rolls it back by
    /// then itself, and the hub counts it failed [`GIVE_UP_GRACE_SECS`] later.
    pub node_timeout_secs: u64,
    /// How long a node may take to drain for its update; its command expires then, a node
    /// still draining calls the update off, and the hub counts it failed
    /// [`GIVE_UP_GRACE_SECS`] later.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
    /// Update nodes whose runner is external, without draining them.
    #[serde(default)]
    pub force: bool,
    pub state: RolloutState,
    pub failures: u32,
    pub nodes: Vec<RolloutNode>,
}

/// How long a drain may take unless a rollout says otherwise: a long CI job's worth.
pub const DRAIN_TIMEOUT_SECS: u64 = 4 * 3600;

fn default_drain_timeout() -> u64 {
    DRAIN_TIMEOUT_SECS
}

/// How much later than the node the hub gives up on an update, in either window: the node
/// calls off a drain at the command's expiry, and rolls back an update at the deadline it
/// starts when its drain is over, and only then does the hub — which learns of either from a
/// report, and whose clock may lead the node's — count the failure. An update the hub has given
/// up on can then no longer be kept. It is also how long a restarted hub lets its nodes
/// reconnect before it judges a window.
pub const GIVE_UP_GRACE_SECS: u64 = 120;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RolloutState {
    Running,
    Paused { reason: String },
    Aborted { reason: String },
    Done,
}

impl RolloutState {
    /// Still to finish: running or paused.
    pub fn active(&self) -> bool {
        matches!(self, RolloutState::Running | RolloutState::Paused { .. })
    }

    pub fn name(&self) -> &'static str {
        match self {
            RolloutState::Running => "running",
            RolloutState::Paused { .. } => "paused",
            RolloutState::Aborted { .. } => "aborted",
            RolloutState::Done => "done",
        }
    }
}

/// One node of a rollout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutNode {
    pub id: String,
    pub hostname: String,
    pub profile: String,
    /// Waves go in order; with canaries, wave 0 holds one node of each profile.
    pub wave: u32,
    pub status: NodeStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NodeStatus {
    Pending,
    Skipped {
        reason: String,
    },
    Updating {
        command: String,
        since: u64,
        /// The state it was in, and is to return to.
        resume: NodeState,
        /// When the node was first seen past its drain.
        #[serde(default)]
        drained_at: Option<u64>,
    },
    Succeeded {
        at: u64,
    },
    Failed {
        reason: String,
        at: u64,
    },
}

impl NodeStatus {
    pub fn name(&self) -> &'static str {
        match self {
            NodeStatus::Pending => "pending",
            NodeStatus::Skipped { .. } => "skipped",
            NodeStatus::Updating { .. } => "updating",
            NodeStatus::Succeeded { .. } => "succeeded",
            NodeStatus::Failed { .. } => "failed",
        }
    }

    fn open(&self) -> bool {
        matches!(self, NodeStatus::Pending | NodeStatus::Updating { .. })
    }
}

/// What an operator does to a rollout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutAction {
    /// Issue no more updates; those under way finish.
    Pause,
    Resume,
    /// End it: nothing more is issued, and it cannot be resumed.
    Abort,
}

impl RolloutAction {
    pub fn done(self) -> &'static str {
        match self {
            RolloutAction::Pause => "paused",
            RolloutAction::Resume => "resumed",
            RolloutAction::Abort => "aborted",
        }
    }
}

/// A rollout as `vk-hub rollout status` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rollout {
    pub id: String,
    #[serde(flatten)]
    pub row: RolloutRow,
}

impl Rollout {
    /// How many of its nodes are in each status, in this order: pending, updating, succeeded,
    /// skipped, failed.
    pub fn counts(&self) -> [(&'static str, usize); 5] {
        let mut out = [
            ("pending", 0),
            ("updating", 0),
            ("succeeded", 0),
            ("skipped", 0),
            ("failed", 0),
        ];
        for n in &self.row.nodes {
            if let Some(slot) = out.iter_mut().find(|(name, _)| *name == n.status.name()) {
                slot.1 += 1;
            }
        }
        out
    }

    /// The wave under way: the first with a node still to finish.
    pub fn wave(&self) -> Option<u32> {
        current_wave(&self.row)
    }
}

/// What the database says of a rollout's node when a step runs.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub state: Option<NodeState>,
    pub vk: Option<String>,
    pub vk_sha256: Option<String>,
    /// The outcome of its rollout command, if it has one.
    pub outcome: Option<Outcome>,
    /// The phase the node reports its rollout update in, if it reports that one.
    pub phase: Option<vk_hub_proto::UpdatePhase>,
    /// Whether it runs its gitlab-runner itself, so it can be drained.
    pub managed: bool,
    /// The protocol version of its latest session.
    pub protocol: Option<u32>,
    /// Whether it has an update of its own under way, not the rollout's: an operator's,
    /// issued before the rollout reached it.
    pub own_update: bool,
}

impl Facts {
    /// What `node`'s row says of it, short of its commands.
    pub fn of(node: &NodeRow) -> Facts {
        let versions = node.inventory.as_ref().map(|i| &i.versions);
        let report = node.report.as_ref();
        Facts {
            state: report.and_then(|r| r.state),
            vk: versions.map(|v| v.vk.clone()),
            vk_sha256: versions.and_then(|v| v.vk_sha256.clone()),
            managed: report.and_then(|r| r.runner) == Some(vk_hub_proto::RunnerMode::Managed),
            protocol: node.protocol,
            ..Facts::default()
        }
    }

    /// Whether it runs the release `sha256`, of `version`: by sha256, or by version for a node
    /// that reports none.
    pub fn runs(&self, sha256: &str, version: &str) -> bool {
        match &self.vk_sha256 {
            Some(sha) => sha == sha256,
            None => self.vk.as_deref() == Some(version),
        }
    }
}

/// Why a node is left out of a rollout for good whenever it is looked at, at the rollout's
/// creation or when its wave comes: it has never said what state it is in, it is quarantined,
/// or its runner is external and the rollout is not forced.
pub fn ineligible(f: &Facts, force: bool) -> Option<&'static str> {
    match f.state {
        None => Some("it has not reported its state"),
        Some(NodeState::Quarantined) => Some("quarantined"),
        Some(_) if !f.managed && !force => {
            Some("vk node cannot drain its external runner; --force includes it")
        }
        Some(_) => None,
    }
}

/// What a step asks of the store.
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    /// Issue the update to `nodes[index]`, and set it updating with that command.
    Issue { index: usize, resume: NodeState },
    /// An audit line, of a node or of the rollout as a whole.
    Audit { node: Option<String>, event: String },
}

/// Whether `f` shows the node running `row`'s release.
fn on_target(row: &RolloutRow, f: &Facts) -> bool {
    f.runs(&row.release, &row.version)
}

fn current_wave(row: &RolloutRow) -> Option<u32> {
    row.nodes
        .iter()
        .filter(|n| n.status.open())
        .map(|n| n.wave)
        .min()
}

/// Advance `row` in place using `facts` at `now`, returning effects for the store.
/// Removed nodes have no facts. Do not judge timeouts before `not_before`.
pub fn step(
    row: &mut RolloutRow,
    facts: &HashMap<String, Facts>,
    now: u64,
    not_before: u64,
) -> Vec<Effect> {
    let mut effects = Vec::new();
    let mut failed = Vec::new();
    let version = row.version.clone();
    let (timeout, drain_timeout) = (row.node_timeout_secs, row.drain_timeout_secs);
    let target = row.clone();
    for node in &mut row.nodes {
        let NodeStatus::Updating {
            command,
            since,
            resume,
            drained_at,
        } = &mut node.status
        else {
            continue;
        };
        let f = facts.get(&node.id);
        if drained_at.is_none()
            && f.and_then(|f| f.phase)
                .is_some_and(|p| p != vk_hub_proto::UpdatePhase::Draining)
        {
            *drained_at = Some(now);
        }
        // An operator may drain or undrain a node during its update, so it may end either way.
        let back = |f: &Facts| matches!(f.state, Some(NodeState::Ready | NodeState::Drained));
        let verdict = match f.and_then(|f| f.outcome.as_ref()) {
            _ if f.is_none() => Some(Err("the node was removed from the hub".to_string())),
            Some(Outcome::Done) if f.is_some_and(|f| on_target(&target, f) && back(f)) => {
                Some(Ok(()))
            }
            Some(Outcome::Done) if f.is_some_and(|f| f.state == Some(NodeState::Quarantined)) => {
                Some(Err("quarantined during its update".into()))
            }
            Some(Outcome::Failed { message }) => Some(Err(message.clone())),
            Some(Outcome::Refused { reason }) => Some(Err(format!("refused: {reason}"))),
            Some(Outcome::Expired) => Some(Err("the update expired before it ran".into())),
            _ if now < not_before => None,
            _ => match *drained_at {
                None if now.saturating_sub(*since)
                    >= drain_timeout.saturating_add(GIVE_UP_GRACE_SECS) =>
                {
                    Some(Err(format!(
                        "still draining after {}",
                        crate::human_duration(Duration::from_secs(drain_timeout))
                    )))
                }
                Some(at)
                    if now.saturating_sub(at) >= timeout.saturating_add(GIVE_UP_GRACE_SECS) =>
                {
                    Some(Err(format!(
                        "not updated and back {} within {} of its drain",
                        crate::store::state_name(*resume),
                        crate::human_duration(Duration::from_secs(timeout))
                    )))
                }
                _ => None,
            },
        };
        let command = command.clone();
        match verdict {
            None => {}
            Some(Ok(())) => {
                node.status = NodeStatus::Succeeded { at: now };
                effects.push(Effect::Audit {
                    node: Some(node.id.clone()),
                    event: format!("updated to vk {version} (command {command})"),
                });
            }
            Some(Err(reason)) => {
                let reason = vk_hub_proto::display_safe(&reason);
                effects.push(Effect::Audit {
                    node: Some(node.id.clone()),
                    event: format!("failed to update to vk {version}: {reason}"),
                });
                failed.push(format!(
                    "{} ({}): {reason}",
                    node.hostname,
                    short_id(&node.id)
                ));
                node.status = NodeStatus::Failed { reason, at: now };
            }
        }
    }
    for what in failed {
        // An aborted rollout's stragglers are recorded, not counted against it.
        if !row.state.active() {
            continue;
        }
        row.failures = row.failures.saturating_add(1);
        if row.failures > row.max_failures {
            let reason = format!(
                "{} failure(s), past --max-failures {}; the last: {what}",
                row.failures, row.max_failures
            );
            effects.push(Effect::Audit {
                node: None,
                event: format!("aborted: {reason}"),
            });
            row.state = RolloutState::Aborted { reason };
        } else if row.state == RolloutState::Running {
            let reason = format!("a node failed: {what}");
            effects.push(Effect::Audit {
                node: None,
                event: format!("paused: {reason}"),
            });
            row.state = RolloutState::Paused { reason };
        }
    }
    if row.state != RolloutState::Running {
        return effects;
    }
    loop {
        let Some(wave) = current_wave(row) else {
            row.state = RolloutState::Done;
            let count = |name| row.nodes.iter().filter(|n| n.status.name() == name).count();
            effects.push(Effect::Audit {
                node: None,
                event: format!(
                    "done: vk {version} on {} node(s), {} failed, {} skipped",
                    count("succeeded"),
                    count("failed"),
                    count("skipped")
                ),
            });
            return effects;
        };
        let in_wave = |n: &RolloutNode| n.wave == wave;
        if row
            .nodes
            .iter()
            .any(|n| in_wave(n) && matches!(n.status, NodeStatus::Updating { .. }))
        {
            return effects;
        }
        for (index, node) in row.nodes.iter_mut().enumerate() {
            if !in_wave(node) || node.status != NodeStatus::Pending {
                continue;
            }
            let skip = match facts.get(&node.id) {
                None => Some("removed from the hub".to_string()),
                Some(Facts {
                    protocol: Some(v), ..
                }) if *v < vk_hub_proto::STEERING => Some(monitoring_only(*v)),
                Some(f) if on_target(&target, f) => Some("already runs the release".to_string()),
                Some(f) => ineligible(f, target.force)
                    .or(match f.state {
                        Some(
                            NodeState::Draining | NodeState::Maintenance | NodeState::Validating,
                        ) => Some("busy with a drain or maintenance of its own"),
                        _ if f.own_update => Some("an update of its own is under way"),
                        _ => None,
                    })
                    .map(str::to_string),
            };
            if let Some(reason) = skip {
                effects.push(Effect::Audit {
                    node: Some(node.id.clone()),
                    event: format!("skipped: {reason}"),
                });
                node.status = NodeStatus::Skipped { reason };
                continue;
            }
            let resume = match facts.get(&node.id).and_then(|f| f.state) {
                Some(NodeState::Drained) => NodeState::Drained,
                _ => NodeState::Ready,
            };
            // The store sets the node updating once it has the command's ID.
            effects.push(Effect::Issue { index, resume });
        }
        if effects.iter().any(|e| matches!(e, Effect::Issue { .. })) {
            return effects;
        }
    }
}

/// Why a node at protocol `version` is skipped: it can be monitored, not updated.
pub fn monitoring_only(version: u32) -> String {
    format!("monitored only: its vk speaks fleet protocol version {version}, which takes no update")
}

/// Group `nodes` (`id`, `hostname`, `profile`, in any order) into waves sorted by profile
/// and hostname: optionally one canary per profile in wave 0, then batches of `batch`.
pub fn plan(
    mut nodes: Vec<(String, String, String)>,
    batch: u32,
    canaries: bool,
) -> Vec<RolloutNode> {
    nodes.sort_by(|a, b| (&a.2, &a.1, &a.0).cmp(&(&b.2, &b.1, &b.0)));
    let mut out = Vec::with_capacity(nodes.len());
    let mut rest = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (id, hostname, profile) in nodes {
        if canaries && seen.insert(profile.clone()) {
            out.push(RolloutNode {
                id,
                hostname,
                profile,
                wave: 0,
                status: NodeStatus::Pending,
            });
        } else {
            rest.push((id, hostname, profile));
        }
    }
    let first = u32::from(canaries && !out.is_empty());
    let batch = usize::try_from(batch.max(1)).unwrap_or(1);
    for (i, (id, hostname, profile)) in rest.into_iter().enumerate() {
        let wave = first.saturating_add(u32::try_from(i / batch).unwrap_or(u32::MAX));
        out.push(RolloutNode {
            id,
            hostname,
            profile,
            wave,
            status: NodeStatus::Pending,
        });
    }
    out
}

/// A node's hardware profile (see the module docs); `unknown` before it sent an inventory.
pub fn profile(inventory: Option<&Inventory>) -> String {
    let Some(inv) = inventory else {
        return "unknown".to_string();
    };
    let cpu = inv
        .hardware
        .cpu_model
        .as_deref()
        .map(|m| m.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "unknown CPU".to_string());
    let ram = inv
        .hardware
        .mem_total_mib
        .map_or_else(|| "?G".to_string(), |mib| format!("{}G", ram_bucket(mib)));
    let mut storage: Vec<String> = inv
        .storage
        .iter()
        .map(|fs| {
            format!(
                "{} {}",
                match fs.role {
                    StorageRole::Jobs => "jobs",
                    StorageRole::Checkouts => "checkouts",
                },
                match fs.speed {
                    Some(SpeedClass::Fast) => "fast",
                    Some(SpeedClass::Slow) => "slow",
                    None => "undeclared",
                }
            )
        })
        .collect();
    storage.sort();
    format!("{cpu} · {ram} · {}", storage.join(", "))
}

/// RAM in GiB rounded to the nearest power of two: 503 GiB of usable memory on a 512 GiB
/// host is the 512 bucket, and 48 GiB rounds to 64.
fn ram_bucket(mib: u64) -> u64 {
    let gib = (mib as f64 / 1024.0).max(1.0);
    let exp = gib.log2().round();
    2f64.powf(exp) as u64
}

/// Refuse `prefix` as the name of a rollout unless it is at least 4 lowercase hex digits.
pub fn check_prefix(prefix: &str) -> anyhow::Result<()> {
    if prefix.len() < 4
        || !prefix
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        anyhow::bail!(
            "{}: name a rollout by its ID, or at least its first 4 hex digits",
            vk_hub_proto::display_safe(prefix)
        );
    }
    Ok(())
}

/// An ID's first eight digits, as rollouts and nodes are named in lines people read.
pub fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

/// How often the driver looks at its rollouts when nothing else wakes it.
const TICK: Duration = Duration::from_secs(5);

/// Drive every active rollout for as long as the hub runs: at start — so a restarted hub
/// carries on — whenever a node reports or an operator acts, and every [`TICK`] regardless,
/// for the timeouts. Its nodes get [`GIVE_UP_GRACE_SECS`] from the start to reconnect before
/// any window is judged.
pub async fn drive(hub: Arc<Hub>) {
    let mut changes = hub.subscribe();
    let not_before = crate::now_secs().saturating_add(GIVE_UP_GRACE_SECS);
    loop {
        let db = hub.db.clone();
        let advanced = tokio::task::spawn_blocking(move || {
            let mut issued = Vec::new();
            let mut any = false;
            for (id, row) in db.rollouts()? {
                if row.state != RolloutState::Running
                    && !row
                        .nodes
                        .iter()
                        .any(|n| matches!(n.status, NodeStatus::Updating { .. }))
                {
                    continue;
                }
                // One rollout that cannot advance holds none of the others back.
                match db.advance_rollout(&id, crate::now_secs(), not_before) {
                    Ok((changed, nodes)) => {
                        any |= changed;
                        issued.extend(nodes);
                    }
                    Err(e) => eprintln!("vk-hub: advancing rollout {}: {e:#}", short_id(&id)),
                }
            }
            anyhow::Ok((any, issued))
        })
        .await;
        match advanced {
            Ok(Ok((changed, issued))) => {
                for node in &issued {
                    hub.kick(node);
                    hub.changed(node);
                }
                if changed {
                    hub.touch();
                }
            }
            Ok(Err(e)) => eprintln!("vk-hub: driving rollouts: {e:#}"),
            Err(e) => eprintln!("vk-hub: driving rollouts: {e}"),
        }
        tokio::select! {
            _ = changes.changed() => {
                // A fleet's heartbeats arrive every few seconds: one pass a second is plenty.
                tokio::time::sleep(Duration::from_secs(1)).await;
                changes.borrow_and_update();
            }
            () = tokio::time::sleep(TICK) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "abababababababababababababababababababababababababababababababab";

    fn row(nodes: Vec<RolloutNode>, max_failures: u32) -> RolloutRow {
        RolloutRow {
            release: SHA.into(),
            version: "0.85.0".into(),
            created_at: 0,
            created_by: "uid 0".into(),
            batch: 1,
            canary_per_profile: true,
            max_failures,
            node_timeout_secs: 100,
            drain_timeout_secs: 50,
            force: false,
            state: RolloutState::Running,
            failures: 0,
            nodes,
        }
    }

    fn ready(on: bool) -> Facts {
        Facts {
            state: Some(NodeState::Ready),
            vk: Some("0.84.0".into()),
            vk_sha256: Some(if on { SHA.into() } else { "cd".repeat(32) }),
            outcome: None,
            phase: None,
            managed: true,
            protocol: Some(vk_hub_proto::STEERING),
            own_update: false,
        }
    }

    fn nodes() -> Vec<(String, String, String)> {
        vec![
            ("n3".into(), "c".into(), "big".into()),
            ("n1".into(), "a".into(), "big".into()),
            ("n2".into(), "b".into(), "small".into()),
            ("n4".into(), "d".into(), "big".into()),
        ]
    }

    #[test]
    fn a_canary_of_each_profile_goes_first_then_batches() {
        let plan = plan(nodes(), 2, true);
        let waves: Vec<(&str, u32)> = plan.iter().map(|n| (n.id.as_str(), n.wave)).collect();
        assert_eq!(waves, [("n1", 0), ("n2", 0), ("n3", 1), ("n4", 1)]);
        let plain = super::plan(nodes(), 1, false);
        let waves: Vec<u32> = plain.iter().map(|n| n.wave).collect();
        assert_eq!(waves, [0, 1, 2, 3]);
    }

    fn issued(effects: &[Effect]) -> Vec<usize> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Issue { index, .. } => Some(*index),
                _ => None,
            })
            .collect()
    }

    /// What the store does with an issue: the node is updating under a command.
    fn apply(row: &mut RolloutRow, effects: &[Effect], now: u64) {
        for e in effects {
            if let Effect::Issue { index, resume } = e {
                row.nodes[*index].status = NodeStatus::Updating {
                    command: format!("c{index}"),
                    since: now,
                    resume: *resume,
                    drained_at: None,
                };
            }
        }
    }

    #[test]
    fn a_wave_starts_only_once_the_last_is_done_and_nodes_on_the_release_are_skipped() {
        let mut r = row(plan(nodes(), 1, true), 0);
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        facts.insert("n2".into(), ready(true));
        let e = step(&mut r, &facts, 1, 0);
        // n1 is the big canary; small's canary already runs it.
        assert_eq!(issued(&e), [0]);
        assert!(matches!(r.nodes[1].status, NodeStatus::Skipped { .. }));
        apply(&mut r, &e, 1);
        // Done, but not yet showing the release: wait.
        facts.get_mut("n1").unwrap().outcome = Some(Outcome::Done);
        assert!(issued(&step(&mut r, &facts, 2, 0)).is_empty());
        facts.insert(
            "n1".into(),
            Facts {
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        let e = step(&mut r, &facts, 3, 0);
        assert!(matches!(r.nodes[0].status, NodeStatus::Succeeded { .. }));
        assert_eq!(issued(&e), [2]);
        apply(&mut r, &e, 3);
        facts.insert(
            "n3".into(),
            Facts {
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        let e = step(&mut r, &facts, 4, 0);
        assert_eq!(issued(&e), [3]);
        apply(&mut r, &e, 4);
        facts.insert(
            "n4".into(),
            Facts {
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        step(&mut r, &facts, 5, 0);
        assert_eq!(r.state, RolloutState::Done);
    }

    #[test]
    fn a_failure_pauses_and_one_past_the_limit_aborts() {
        let mut r = row(plan(nodes(), 1, false), 1);
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        let e = step(&mut r, &facts, 1, 0);
        apply(&mut r, &e, 1);
        facts.get_mut("n1").unwrap().outcome = Some(Outcome::Failed {
            message: "rolled back: validation failed".into(),
        });
        step(&mut r, &facts, 2, 0);
        assert!(
            matches!(&r.state, RolloutState::Paused { reason } if reason.contains("rolled back"))
        );
        // Paused: nothing more is issued until an operator resumes.
        assert!(issued(&step(&mut r, &facts, 3, 0)).is_empty());
        r.state = RolloutState::Running;
        let e = step(&mut r, &facts, 4, 0);
        assert_eq!(issued(&e), [1]);
        apply(&mut r, &e, 4);
        // Its drain over at 10, a node that never gets further times out a grace after the
        // node's own deadline: the second failure, past the one allowed.
        facts.get_mut("n3").unwrap().phase = Some(vk_hub_proto::UpdatePhase::Downloading);
        step(&mut r, &facts, 10, 0);
        step(&mut r, &facts, 10 + 100, 0);
        assert_eq!(r.state, RolloutState::Running);
        step(&mut r, &facts, 10 + 100 + GIVE_UP_GRACE_SECS, 0);
        assert!(matches!(&r.state, RolloutState::Aborted { reason } if reason.contains("within")));
        assert_eq!(r.failures, 2);
        // Stragglers after the abort are recorded, not counted.
        let mut rest = r.clone();
        rest.nodes[2].status = NodeStatus::Updating {
            command: "c2".into(),
            since: 0,
            resume: NodeState::Ready,
            drained_at: None,
        };
        step(&mut rest, &facts, 10_000, 0);
        assert!(matches!(rest.nodes[2].status, NodeStatus::Failed { .. }));
        assert_eq!(rest.failures, 2);
    }

    #[test]
    fn a_long_drain_has_its_own_window_and_an_operator_drain_still_succeeds() {
        let mut r = row(plan(nodes(), 1, false), 5);
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        let e = step(&mut r, &facts, 0, 0);
        apply(&mut r, &e, 0);
        facts.get_mut("n1").unwrap().phase = Some(vk_hub_proto::UpdatePhase::Draining);
        // Past the node timeout but within the drain's window: still waited for, and at its
        // end too, until the grace the node has to report calling the update off is over.
        step(&mut r, &facts, 49, 0);
        assert!(matches!(r.nodes[0].status, NodeStatus::Updating { .. }));
        step(&mut r, &facts, 50, 0);
        assert!(matches!(r.nodes[0].status, NodeStatus::Updating { .. }));
        let late = 50 + GIVE_UP_GRACE_SECS;
        step(&mut r, &facts, late, 0);
        assert!(
            matches!(&r.nodes[0].status, NodeStatus::Failed { reason, .. } if reason.contains("still draining"))
        );
        // Drained by an operator during its update, it ends drained: a success.
        r.state = RolloutState::Running;
        let e = step(&mut r, &facts, late + 10, 0);
        apply(&mut r, &e, late + 10);
        facts.insert(
            "n3".into(),
            Facts {
                state: Some(NodeState::Drained),
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        step(&mut r, &facts, late + 11, 0);
        assert!(matches!(r.nodes[1].status, NodeStatus::Succeeded { .. }));
    }

    #[test]
    fn a_node_undrained_by_an_operator_during_its_update_still_succeeds() {
        let mut r = row(plan(nodes(), 4, false), 0);
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        facts.get_mut("n1").unwrap().state = Some(NodeState::Drained);
        let e = step(&mut r, &facts, 0, 0);
        apply(&mut r, &e, 0);
        assert!(matches!(
            r.nodes[0].status,
            NodeStatus::Updating {
                resume: NodeState::Drained,
                ..
            }
        ));
        facts.insert(
            "n1".into(),
            Facts {
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        step(&mut r, &facts, 1, 0);
        assert!(matches!(r.nodes[0].status, NodeStatus::Succeeded { .. }));
    }

    #[test]
    fn no_window_runs_out_before_not_before() {
        let mut r = row(plan(nodes(), 4, false), 5);
        let facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        let e = step(&mut r, &facts, 0, 0);
        apply(&mut r, &e, 0);
        let late = 50 + GIVE_UP_GRACE_SECS;
        step(&mut r, &facts, late, late + 1);
        assert!(matches!(r.nodes[0].status, NodeStatus::Updating { .. }));
        step(&mut r, &facts, late + 1, late + 1);
        assert!(matches!(r.nodes[0].status, NodeStatus::Failed { .. }));
    }

    #[test]
    fn a_node_with_an_update_of_its_own_under_way_is_skipped() {
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        facts.get_mut("n1").unwrap().own_update = true;
        let mut r = row(plan(nodes(), 4, false), 5);
        // n1, n3, n4, n2 in plan order.
        assert_eq!(issued(&step(&mut r, &facts, 0, 0)), [1, 2, 3]);
        assert!(
            matches!(&r.nodes[0].status, NodeStatus::Skipped { reason } if reason.contains("of its own")),
            "{:?}",
            r.nodes[0].status
        );
    }

    #[test]
    fn busy_unreported_and_unmanaged_nodes_are_skipped_unless_forced() {
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        facts.get_mut("n1").unwrap().managed = false;
        facts.get_mut("n2").unwrap().state = None;
        facts.get_mut("n3").unwrap().state = Some(NodeState::Maintenance);
        let mut r = row(plan(nodes(), 4, false), 5);
        let e = step(&mut r, &facts, 0, 0);
        // n1, n3, n4, n2 in plan order: only n4 is updated.
        assert_eq!(issued(&e), [2]);
        let reasons: Vec<String> = r
            .nodes
            .iter()
            .filter_map(|n| match &n.status {
                NodeStatus::Skipped { reason } => Some(reason.clone()),
                _ => None,
            })
            .collect();
        assert!(reasons[0].contains("external"), "{reasons:?}");
        assert!(reasons[1].contains("busy"), "{reasons:?}");
        assert!(reasons[2].contains("not reported"), "{reasons:?}");
        let mut forced = row(plan(nodes(), 4, false), 5);
        forced.force = true;
        assert_eq!(issued(&step(&mut forced, &facts, 0, 0)), [0, 2]);
    }

    #[test]
    fn a_node_monitored_only_is_skipped_even_when_forced() {
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        facts.get_mut("n1").unwrap().protocol = Some(1);
        let mut r = row(plan(nodes(), 4, false), 5);
        r.force = true;
        // n1, n3, n4, n2 in plan order.
        assert_eq!(issued(&step(&mut r, &facts, 0, 0)), [1, 2, 3]);
        assert!(
            matches!(&r.nodes[0].status, NodeStatus::Skipped { reason } if reason.contains("protocol version 1")),
            "{:?}",
            r.nodes[0].status
        );
    }

    #[test]
    fn a_removed_node_fails_while_updating_and_is_skipped_before() {
        let mut r = row(plan(nodes(), 4, false), 5);
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        facts.get_mut("n3").unwrap().state = Some(NodeState::Quarantined);
        let e = step(&mut r, &facts, 1, 0);
        // In profile order: n1, n3, n4 (big), then n2 (small).
        assert_eq!(issued(&e), [0, 3]);
        let skipped: Vec<&str> = r
            .nodes
            .iter()
            .filter(|n| matches!(n.status, NodeStatus::Skipped { .. }))
            .map(|n| n.id.as_str())
            .collect();
        assert_eq!(skipped, ["n3", "n4"]);
        apply(&mut r, &e, 1);
        facts.remove("n1");
        step(&mut r, &facts, 2, 0);
        assert!(
            matches!(&r.nodes[0].status, NodeStatus::Failed { reason, .. } if reason.contains("removed"))
        );
    }

    #[test]
    fn a_profile_is_the_cpu_the_ram_bucket_and_the_declared_speeds() {
        let inv = Inventory {
            hardware: vk_hub_proto::Hardware {
                cpu_model: Some("AMD  EPYC 7543".into()),
                mem_total_mib: Some(515_000),
                ..Default::default()
            },
            storage: vec![
                vk_hub_proto::Filesystem {
                    role: StorageRole::Jobs,
                    path: "/j".into(),
                    device: "0:1".into(),
                    size_bytes: 1,
                    tmpfs: false,
                    speed: Some(SpeedClass::Slow),
                },
                vk_hub_proto::Filesystem {
                    role: StorageRole::Checkouts,
                    path: "/c".into(),
                    device: "0:2".into(),
                    size_bytes: 1,
                    tmpfs: true,
                    speed: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            profile(Some(&inv)),
            "AMD EPYC 7543 · 512G · checkouts undeclared, jobs slow"
        );
        assert_eq!(profile(None), "unknown");
        assert_eq!(ram_bucket(48 * 1024), 64);
        assert_eq!(ram_bucket(30 * 1024), 32);
        assert_eq!(ram_bucket(100), 1);
    }
}
