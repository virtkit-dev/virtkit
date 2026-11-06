//! The hub's target `vk` release, and the automatic updates that bring nodes to it.
//!
//! Setting a target starts a rollout of it over the nodes running an older version, with
//! [`crate::rollout`]'s defaults. Afterwards a node that reports an older version — one that
//! joined since, or was taken back by hand — is updated alone, by an ordinary update command,
//! once it is ready and no rollout is running or paused: one node at a time, judged as a
//! rollout judges its nodes ([`crate::rollout::judge`]). A node running a newer version is left
//! alone; one running a version that is not `MAJOR.MINOR.PATCH`, such as a pre-release, is
//! never updated automatically, and shown as such; one whose runner is external is skipped, never forced; one whose release keys would
//! refuse the target's signature is skipped and flagged; and one whose automatic update failed,
//! in the rollout or alone, is not tried again for that target until an operator says so. An
//! aborted rollout of the target holds every automatic update until an operator says so.
//!
//! Versions are ordered as `MAJOR.MINOR.PATCH`, as a node orders them before it updates.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use vk_hub_proto::{ReleaseKeySource, ReleaseKeys};

use crate::rollout::{Facts, NodeStatus};
use crate::store::NodeRow;

/// Who the audit log says issues and judges the automatic updates.
pub const ACTOR: &str = "auto-update";

/// The target, as the database keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRow {
    /// The release's sha256.
    pub release: String,
    pub version: String,
    /// The release's signature, as the update carries it; a release held never changes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub set_at: u64,
    pub set_by: String,
    /// The rollout setting it started, until that rollout is over and the nodes it failed to
    /// update have been taken in as failed here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout: Option<String>,
    /// Why the automatic updates are held: the rollout setting it started was aborted. An
    /// operator's `--retry` lifts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
    /// Nodes by ID: the one being updated alone, and those whose update to it failed, not
    /// tried again until an operator says so. Only [`NodeStatus::Updating`] and
    /// [`NodeStatus::Failed`] are kept.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nodes: BTreeMap<String, NodeStatus>,
}

/// Where a node stands against the target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "standing", rename_all = "snake_case")]
pub enum Standing {
    /// It runs the target, or another build of its version.
    Current,
    /// It runs a newer version, and is left alone.
    Newer { vk: String },
    /// Its automatic update is under way.
    Updating { command: String },
    /// Its update to the target failed; it is not tried again until an operator says so.
    Failed { reason: String },
    /// Its release keys would refuse the target's signature: never tried.
    Flagged { reason: String },
    /// It runs a version that is not `MAJOR.MINOR.PATCH`, which neither the hub nor the node
    /// orders against the target: never updated automatically while it runs it.
    Unorderable { vk: String },
    /// It is not updated automatically, for now or for good.
    Held { reason: String },
    /// Behind the target: it is updated once it is ready, connected and no rollout runs.
    Due,
}

impl Standing {
    /// A line about the node, for `vk-hub nodes`; `None` when there is nothing to say.
    pub fn note(&self, target: &TargetRow) -> Option<String> {
        let version = &target.version;
        Some(match self {
            Standing::Current => return None,
            Standing::Newer { vk } => {
                format!("runs vk {vk}, newer than the target {version}: left alone")
            }
            Standing::Updating { command } => {
                format!("updating to the target vk {version} (command {command})")
            }
            Standing::Failed { reason } => format!(
                "its update to the target vk {version} failed: {reason}; `vk-hub release target \
                 --retry <id>` tries it again"
            ),
            Standing::Flagged { reason } => {
                format!("not updated to the target vk {version}: {reason}")
            }
            Standing::Held { reason } => {
                format!("not updated to the target vk {version}: {reason}")
            }
            Standing::Unorderable { vk } => format!(
                "not updated automatically: its vk {vk} is not MAJOR.MINOR.PATCH; install a \
                 release on it by hand to bring it back to the target vk {version}"
            ),
            Standing::Due => match &target.held {
                Some(why) => format!(
                    "behind the target vk {version}, whose automatic updates are held: {why}"
                ),
                None => format!(
                    "behind the target vk {version}: updated once ready and no rollout runs"
                ),
            },
        })
    }
}

/// `MAJOR.MINOR.PATCH`'s fields, or `None` for any other shape.
fn fields(version: &str) -> Option<[u64; 3]> {
    let mut it = version.split('.').map(|f| f.parse::<u64>().ok());
    let out = [it.next()??, it.next()??, it.next()??];
    it.next().is_none().then_some(out)
}

/// Whether `version` is `MAJOR.MINOR.PATCH`, so nodes can be ordered against it.
pub fn orderable(version: &str) -> bool {
    fields(version).is_some()
}

/// How `a` orders against `b`, both `MAJOR.MINOR.PATCH`; `None` when either is not.
fn order(a: &str, b: &str) -> Option<Ordering> {
    Some(fields(a)?.cmp(&fields(b)?))
}

/// Why a node whose release keys are `keys` would refuse release `sha256` of `version`
/// signed with `signature`, if it would: the check it makes on receipt.
pub fn keys_refuse(
    keys: &ReleaseKeys,
    sha256: &str,
    version: &str,
    signature: Option<&str>,
) -> Option<String> {
    let section = match keys.source {
        Some(ReleaseKeySource::Enrollment) => "pinned",
        Some(ReleaseKeySource::Local) => "[node]",
        _ => "reported",
    };
    let policy = vk_peer::release_key::Policy::from_config_in(
        section,
        vk_peer::release_key::Program::Vk,
        &keys.keys,
        Some(keys.required),
    );
    match policy {
        Ok(policy) => policy.check(sha256, version, signature).err(),
        Err(e) => Some(format!("{e:#}")),
    }
}

/// Where node `id`, of row `node`, stands against `target`.
pub fn standing(target: &TargetRow, id: &str, node: &NodeRow) -> Standing {
    let f = Facts::of(node);
    if f.runs(&target.release, &target.version) {
        return Standing::Current;
    }
    if let Some(NodeStatus::Updating { command, .. }) = target.nodes.get(id) {
        return Standing::Updating {
            command: command.clone(),
        };
    }
    let Some(vk) = f.vk.as_deref() else {
        return Standing::Held {
            reason: "it has not reported its vk version".into(),
        };
    };
    match order(vk, &target.version) {
        Some(Ordering::Less) => {}
        Some(Ordering::Equal) => return Standing::Current,
        Some(Ordering::Greater) => return Standing::Newer { vk: vk.to_string() },
        None => return Standing::Unorderable { vk: vk.to_string() },
    }
    if let Some(NodeStatus::Failed { reason, .. }) = target.nodes.get(id) {
        return Standing::Failed {
            reason: reason.clone(),
        };
    }
    if let Some(v) = node.protocol.filter(|v| *v < vk_hub_proto::STEERING) {
        return Standing::Held {
            reason: crate::rollout::monitoring_only(v),
        };
    }
    if f.state.is_some() && !f.drainable {
        return Standing::Held {
            reason: "vk node cannot drain its external runner; `vk-hub nodes update --force` \
                     updates it"
                .into(),
        };
    }
    if let Some(keys) = node.report.as_ref().and_then(|r| r.release_keys.as_ref())
        && let Some(why) = keys_refuse(
            keys,
            &target.release,
            &target.version,
            target.signature.as_deref(),
        )
    {
        return Standing::Flagged {
            reason: vk_hub_proto::display_safe(&why),
        };
    }
    Standing::Due
}

/// Which of `nodes` (ID, row, and whether it is connected and has no update of its own under
/// way) to update alone now: one [`Standing::Due`] and ready, the first by hostname.
pub fn pick<'a>(
    target: &TargetRow,
    nodes: impl IntoIterator<Item = (&'a str, &'a NodeRow, bool)>,
) -> Option<&'a str> {
    nodes
        .into_iter()
        .filter(|(id, node, free)| {
            *free
                && Facts::of(node).state == Some(vk_hub_proto::NodeState::Ready)
                && standing(target, id, node) == Standing::Due
        })
        .min_by(|a, b| (&a.1.hostname, a.0).cmp(&(&b.1.hostname, b.0)))
        .map(|(id, _, _)| id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::{Inventory, NodeState, Report, RunnerMode};

    const SHA: &str = "abababababababababababababababababababababababababababababababab";

    fn target() -> TargetRow {
        TargetRow {
            release: SHA.into(),
            version: "0.90.0".into(),
            signature: None,
            set_at: 0,
            set_by: "uid 0".into(),
            rollout: None,
            held: None,
            nodes: BTreeMap::new(),
        }
    }

    fn node(host: &str, vk: &str, state: NodeState, runner: RunnerMode) -> NodeRow {
        let mut inventory = Inventory::default();
        inventory.versions.vk = vk.into();
        NodeRow {
            hostname: host.into(),
            protocol: Some(vk_hub_proto::STEERING),
            inventory: Some(inventory),
            report: Some(Report {
                state: Some(state),
                runner: Some(runner),
                ..Report::default()
            }),
            ..NodeRow::default()
        }
    }

    #[test]
    fn only_an_older_node_with_a_drainable_runner_is_due() {
        let t = target();
        let of = |vk, runner| standing(&t, "n", &node("h", vk, NodeState::Ready, runner));
        assert_eq!(of("0.89.3", RunnerMode::Managed), Standing::Due);
        assert_eq!(of("0.89.3", RunnerMode::None), Standing::Due);
        assert_eq!(of("0.90.0", RunnerMode::Managed), Standing::Current);
        assert_eq!(
            of("0.91.0", RunnerMode::Managed),
            Standing::Newer {
                vk: "0.91.0".into()
            }
        );
        assert!(
            matches!(of("0.89.3", RunnerMode::External), Standing::Held { reason } if reason.contains("external"))
        );
        for vk in ["nightly", "0.91.0-rc1", "0.91.0+dev"] {
            assert_eq!(
                of(vk, RunnerMode::Managed),
                Standing::Unorderable { vk: vk.into() }
            );
        }
        let mut old = node("h", "0.80.0", NodeState::Ready, RunnerMode::Managed);
        old.protocol = Some(1);
        assert!(matches!(standing(&t, "n", &old), Standing::Held { .. }));
    }

    #[test]
    fn a_failed_node_waits_for_an_operator_and_one_under_way_is_shown() {
        let mut t = target();
        let n = node("h", "0.89.0", NodeState::Ready, RunnerMode::Managed);
        t.nodes.insert(
            "n".into(),
            NodeStatus::Failed {
                reason: "rolled back".into(),
                at: 1,
                ran: true,
            },
        );
        assert_eq!(
            standing(&t, "n", &n),
            Standing::Failed {
                reason: "rolled back".into()
            }
        );
        assert_eq!(pick(&t, [("n", &n, true)]), None);
        t.nodes.insert(
            "n".into(),
            NodeStatus::Updating {
                command: "c".into(),
                since: 1,
                resume: NodeState::Ready,
                drained_at: None,
            },
        );
        assert_eq!(
            standing(&t, "n", &n),
            Standing::Updating {
                command: "c".into()
            }
        );
    }

    #[test]
    fn a_node_whose_keys_refuse_the_signature_is_flagged() {
        let t = target();
        let mut n = node("h", "0.89.0", NodeState::Ready, RunnerMode::Managed);
        n.report.as_mut().unwrap().release_keys = Some(ReleaseKeys {
            keys: vec![vk_hub_proto::to_base64(&[7; vk_hub_proto::PUBLIC_KEY_LEN])],
            source: Some(ReleaseKeySource::Enrollment),
            required: true,
        });
        assert!(
            matches!(standing(&t, "n", &n), Standing::Flagged { reason } if reason.contains("unsigned"))
        );
        // Keys that require nothing take an unsigned release.
        n.report.as_mut().unwrap().release_keys = Some(ReleaseKeys::default());
        assert_eq!(standing(&t, "n", &n), Standing::Due);
    }

    #[test]
    fn the_first_ready_free_node_by_hostname_is_picked() {
        let t = target();
        let a = node("a", "0.89.0", NodeState::Draining, RunnerMode::Managed);
        let b = node("b", "0.89.0", NodeState::Ready, RunnerMode::Managed);
        let c = node("c", "0.89.0", NodeState::Ready, RunnerMode::Managed);
        let d = node("d", "0.90.0", NodeState::Ready, RunnerMode::Managed);
        assert_eq!(
            pick(
                &t,
                [
                    ("d", &d, true),
                    ("c", &c, true),
                    ("b", &b, false),
                    ("a", &a, true)
                ]
            ),
            Some("c")
        );
        assert_eq!(pick(&t, [("d", &d, true), ("a", &a, true)]), None);
    }

    #[test]
    fn versions_order_as_major_minor_patch_only() {
        assert_eq!(order("0.9.0", "0.10.0"), Some(Ordering::Less));
        assert_eq!(order("1.0", "1.0.0"), None);
        assert_eq!(order("1.0.0-rc1", "1.0.0"), None);
        assert!(orderable("0.106.0") && !orderable("0.106.0.1"));
    }
}
