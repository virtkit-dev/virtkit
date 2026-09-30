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
//! the release (by sha256, or by version for a node that reports none), and it is back in the
//! state it was in when the update was issued — or drained, if an operator drained it
//! meanwhile. The drain has a window of its own, the command's expiry, past which a node
//! still draining calls the update off; the update proper has the node timeout from the end
//! of the drain, which the node enforces as its own deadline, rolling back past it. The hub
//! counts a failure only [`GIVE_UP_GRACE_SECS`] after that, so an update it has given up on
//! is never kept. A node unreachable all along times out in its drain window.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vk_fleet_proto::{Inventory, NodeState, Outcome, SpeedClass, StorageRole};

use crate::server::Hub;

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
    /// How long a node's update may take once its drain is over before it counts as failed;
    /// the node rolls it back by then itself.
    pub node_timeout_secs: u64,
    /// How long a node may take to drain for its update; its command expires then, and a node
    /// still draining calls the update off.
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

/// How much later than the node the hub gives up on an update: the node, which starts its
/// clock when its drain is over, rolls back first, and only then does the hub — which learns
/// of the drain's end from a report — count the failure. An update the hub has given up on can
/// then no longer be kept.
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

/// A rollout as `vk-hub rollout status` and the operations page show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rollout {
    pub id: String,
    #[serde(flatten)]
    pub row: RolloutRow,
}

impl Rollout {
    /// How many of its nodes are in each status, in [`NodeStatus::name`] order of first
    /// appearance: pending, updating, succeeded, skipped, failed.
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
    pub phase: Option<vk_fleet_proto::UpdatePhase>,
    /// Whether it runs its gitlab-runner itself, so it can be drained.
    pub managed: bool,
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
    match &f.vk_sha256 {
        Some(sha) => *sha == row.release,
        None => f.vk.as_deref() == Some(row.version.as_str()),
    }
}

fn current_wave(row: &RolloutRow) -> Option<u32> {
    row.nodes
        .iter()
        .filter(|n| n.status.open())
        .map(|n| n.wave)
        .min()
}

/// Advance `row` by what `facts` say — nodes removed from the hub have none — at `now`.
/// Returns what the store is to do; `row` is changed in place.
pub fn step(row: &mut RolloutRow, facts: &HashMap<String, Facts>, now: u64) -> Vec<Effect> {
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
                .is_some_and(|p| p != vk_fleet_proto::UpdatePhase::Draining)
        {
            *drained_at = Some(now);
        }
        // An operator may drain a node during its update; it then ends drained.
        let back = |f: &Facts| f.state == Some(*resume) || f.state == Some(NodeState::Drained);
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
            _ => match *drained_at {
                None if now.saturating_sub(*since) >= drain_timeout => Some(Err(format!(
                    "still draining after {}",
                    crate::human_duration(Duration::from_secs(drain_timeout))
                ))),
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
                let reason = vk_fleet_proto::display_safe(&reason);
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
                None => Some("removed from the hub"),
                Some(f) if on_target(&target, f) => Some("already runs the release"),
                Some(f) => match f.state {
                    None => Some("it has not reported its state"),
                    Some(NodeState::Quarantined) => Some("quarantined"),
                    Some(NodeState::Draining | NodeState::Maintenance | NodeState::Validating) => {
                        Some("busy with a drain or maintenance of its own")
                    }
                    Some(_) if !f.managed && !target.force => {
                        Some("its runner is external, so it cannot be drained; --force includes it")
                    }
                    Some(_) => None,
                },
            };
            if let Some(reason) = skip {
                node.status = NodeStatus::Skipped {
                    reason: reason.to_string(),
                };
                effects.push(Effect::Audit {
                    node: Some(node.id.clone()),
                    event: format!("skipped: {reason}"),
                });
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

/// The waves `nodes` — `(id, hostname, profile)`, in any order — fall into: sorted by profile
/// and hostname, one canary of each profile in wave 0 if asked for, then batches of `batch`.
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

/// An ID's first eight digits, as rollouts and nodes are named in lines people read.
pub fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

/// How often the driver looks at its rollouts when nothing else wakes it.
const TICK: Duration = Duration::from_secs(5);

/// Drive every active rollout for as long as the hub runs: at start — so a restarted hub
/// carries on — whenever a node reports or an operator acts, and every [`TICK`] regardless,
/// for the timeouts.
pub async fn drive(hub: Arc<Hub>) {
    let mut changes = hub.subscribe();
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
                let (changed, nodes) = db.advance_rollout(&id, crate::now_secs())?;
                any |= changed;
                issued.extend(nodes);
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
            version: "0.81.0".into(),
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
            vk: Some("0.80.0".into()),
            vk_sha256: Some(if on { SHA.into() } else { "cd".repeat(32) }),
            outcome: None,
            phase: None,
            managed: true,
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
        let e = step(&mut r, &facts, 1);
        // n1 is the big canary; small's canary already runs it.
        assert_eq!(issued(&e), [0]);
        assert!(matches!(r.nodes[1].status, NodeStatus::Skipped { .. }));
        apply(&mut r, &e, 1);
        // Done, but not yet showing the release: wait.
        facts.get_mut("n1").unwrap().outcome = Some(Outcome::Done);
        assert!(issued(&step(&mut r, &facts, 2)).is_empty());
        facts.insert(
            "n1".into(),
            Facts {
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        let e = step(&mut r, &facts, 3);
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
        let e = step(&mut r, &facts, 4);
        assert_eq!(issued(&e), [3]);
        apply(&mut r, &e, 4);
        facts.insert(
            "n4".into(),
            Facts {
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        step(&mut r, &facts, 5);
        assert_eq!(r.state, RolloutState::Done);
    }

    #[test]
    fn a_failure_pauses_and_one_past_the_limit_aborts() {
        let mut r = row(plan(nodes(), 1, false), 1);
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3", "n4"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        let e = step(&mut r, &facts, 1);
        apply(&mut r, &e, 1);
        facts.get_mut("n1").unwrap().outcome = Some(Outcome::Failed {
            message: "rolled back: validation failed".into(),
        });
        step(&mut r, &facts, 2);
        assert!(
            matches!(&r.state, RolloutState::Paused { reason } if reason.contains("rolled back"))
        );
        // Paused: nothing more is issued until an operator resumes.
        assert!(issued(&step(&mut r, &facts, 3)).is_empty());
        r.state = RolloutState::Running;
        let e = step(&mut r, &facts, 4);
        assert_eq!(issued(&e), [1]);
        apply(&mut r, &e, 4);
        // Its drain over at 10, a node that never gets further times out a grace after the
        // node's own deadline: the second failure, past the one allowed.
        facts.get_mut("n3").unwrap().phase = Some(vk_fleet_proto::UpdatePhase::Downloading);
        step(&mut r, &facts, 10);
        step(&mut r, &facts, 10 + 100);
        assert_eq!(r.state, RolloutState::Running);
        step(&mut r, &facts, 10 + 100 + GIVE_UP_GRACE_SECS);
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
        step(&mut rest, &facts, 10_000);
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
        let e = step(&mut r, &facts, 0);
        apply(&mut r, &e, 0);
        facts.get_mut("n1").unwrap().phase = Some(vk_fleet_proto::UpdatePhase::Draining);
        // Past the node timeout but within the drain's window: still waited for.
        step(&mut r, &facts, 49);
        assert!(matches!(r.nodes[0].status, NodeStatus::Updating { .. }));
        step(&mut r, &facts, 50);
        assert!(
            matches!(&r.nodes[0].status, NodeStatus::Failed { reason, .. } if reason.contains("still draining"))
        );
        // Drained by an operator during its update, it ends drained: a success.
        r.state = RolloutState::Running;
        let e = step(&mut r, &facts, 60);
        apply(&mut r, &e, 60);
        facts.insert(
            "n3".into(),
            Facts {
                state: Some(NodeState::Drained),
                outcome: Some(Outcome::Done),
                ..ready(true)
            },
        );
        step(&mut r, &facts, 61);
        assert!(matches!(r.nodes[1].status, NodeStatus::Succeeded { .. }));
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
        let e = step(&mut r, &facts, 0);
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
        assert_eq!(issued(&step(&mut forced, &facts, 0)), [0, 2]);
    }

    #[test]
    fn a_removed_node_fails_while_updating_and_is_skipped_before() {
        let mut r = row(plan(nodes(), 4, false), 5);
        let mut facts: HashMap<String, Facts> = ["n1", "n2", "n3"]
            .iter()
            .map(|n| (n.to_string(), ready(false)))
            .collect();
        facts.get_mut("n3").unwrap().state = Some(NodeState::Quarantined);
        let e = step(&mut r, &facts, 1);
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
        step(&mut r, &facts, 2);
        assert!(
            matches!(&r.nodes[0].status, NodeStatus::Failed { reason, .. } if reason.contains("removed"))
        );
    }

    #[test]
    fn a_profile_is_the_cpu_the_ram_bucket_and_the_declared_speeds() {
        let inv = Inventory {
            hardware: vk_fleet_proto::Hardware {
                cpu_model: Some("AMD  EPYC 7543".into()),
                mem_total_mib: Some(515_000),
                ..Default::default()
            },
            storage: vec![
                vk_fleet_proto::Filesystem {
                    role: StorageRole::Jobs,
                    path: "/j".into(),
                    device: "0:1".into(),
                    size_bytes: 1,
                    tmpfs: false,
                    speed: Some(SpeedClass::Slow),
                },
                vk_fleet_proto::Filesystem {
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
