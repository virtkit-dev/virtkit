//! The hub's `tools` setting, and the automatic builds that keep nodes on the CI tools it names
//! ([`crate::tools`]).
//!
//! **The setting.** A hub-side key of the hub's settings, fleet-wide or per node, the node's
//! winning as for any other; it is never sent to a node. Unset, it is [`BUILTIN`]: the
//! definition built into this hub, which moves with the hub's version. [`NONE`] leaves the
//! node's tools to the operator. Any other value is a definition the hub holds, by its full
//! sha256, which it keeps from being removed.
//!
//! **The builds.** A node the setting reaches is asked to build its definition once it is
//! connected, speaks [`vk_hub_proto::TOOLS`] and reports other tools current, unless it is
//! quarantined or has a tools build, an update or a reset still to finish. Every such node is
//! asked at once: a build runs in the background and drains nothing. A build that ends well is
//! followed until the node reports the tools current; one that still reports others a while
//! later counts as failed.
//!
//! **Retries.** A build that fails, is refused or is never taken is asked for again after
//! [`RETRY_DELAYS_SECS`] — each delay give or take a fifth, set per node so a fleet that failed
//! together does not retry together — up to [`ATTEMPTS`] attempts in all; then not until an
//! operator asks for those tools on the node (`vk-hub nodes tools`), which starts the count
//! afresh, as does the setting naming others. A retry that falls due waits, as a first build
//! does, for the node to be reachable and free. Every failure is retried alike: whether a build
//! failed for good cannot be told from why. A manual build of other tools than the setting names is refused,
//! unless the setting is [`NONE`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::NodeRow;

/// Who the audit log says issues and judges the automatic builds.
pub const ACTOR: &str = "auto-deploy";

/// The setting's key.
pub const KEY: &str = "tools";

/// The setting's value, and its default, for the definition built into the hub.
pub const BUILTIN: &str = "builtin";

/// The setting's value that leaves a node's tools alone.
pub const NONE: &str = "none";

/// What the setting takes, in words.
pub const DESCRIBE: &str = "builtin (the default), none, or a tools definition's sha256, or at \
                            least its first 8 hex digits";

/// How long a node that built its tools has to report them current.
pub const REPORT_GRACE_SECS: u64 = 300;

/// How long after each failed attempt the next one is due, before [`retry_at`]'s jitter.
pub const RETRY_DELAYS_SECS: [u64; 4] = [300, 1800, 7200, 21_600];

/// How many attempts an automatic build gets before it waits for an operator.
pub const ATTEMPTS: u32 = RETRY_DELAYS_SECS.len() as u32 + 1;

/// When the attempt after `attempt` (from 1) is due, `attempt` having failed at `at` on node
/// `id` building `sha256`: `None` once it was the last. The delay is spread over ±20%, the same
/// for the same node, tools and attempt.
pub fn retry_at(id: &str, sha256: &str, attempt: u32, at: u64) -> Option<u64> {
    let delay = *RETRY_DELAYS_SECS.get(usize::try_from(attempt.checked_sub(1)?).ok()?)?;
    // FNV-1a: stable across builds and platforms, unlike std's hasher.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in id
        .bytes()
        .chain([0])
        .chain(sha256.bytes())
        .chain(attempt.to_le_bytes())
    {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    let spread = delay / 5;
    Some(at + delay - spread + hash % (2 * spread + 1))
}

/// How long an automatic build is offered to a node: as a manual one.
pub const COMMAND_TTL: std::time::Duration = std::time::Duration::from_secs(86_400);

/// What a node's `tools` setting names, read from its merged layers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Named {
    Builtin,
    None,
    /// A definition, by its full sha256.
    Sha256(String),
}

impl Named {
    /// The setting's value as stored, `None` when unset.
    pub fn of(value: Option<&Value>) -> Named {
        match value.and_then(Value::as_str) {
            None | Some(BUILTIN) => Named::Builtin,
            Some(NONE) => Named::None,
            Some(sha) => Named::Sha256(sha.to_string()),
        }
    }

    /// The definition it names, `builtin` being `builtin_sha`; `None` for [`Named::None`].
    pub fn sha256<'a>(&'a self, builtin_sha: &'a str) -> Option<&'a str> {
        match self {
            Named::Builtin => Some(builtin_sha),
            Named::None => None,
            Named::Sha256(sha) => Some(sha),
        }
    }
}

/// Where a node's automatic build stands, as the database keeps it. A node with none is either
/// on its tools or due. `attempt` counts from 1 since the count last started afresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Deploy {
    /// Asked to build `sha256` by `command`, not answered yet.
    Building {
        sha256: String,
        command: String,
        since: u64,
        #[serde(default = "first")]
        attempt: u32,
    },
    /// Its build of `sha256` ended well at `at`; waiting for its inventory to say so.
    Built {
        sha256: String,
        at: u64,
        #[serde(default = "first")]
        attempt: u32,
    },
    /// Its build of `sha256` failed at `at`: asked for again once `retry_at` is past, and with
    /// none, not until an operator says so.
    Failed {
        sha256: String,
        reason: String,
        at: u64,
        #[serde(default = "first")]
        attempt: u32,
        #[serde(default)]
        retry_at: Option<u64>,
    },
}

fn first() -> u32 {
    1
}

impl Deploy {
    pub fn sha256(&self) -> &str {
        match self {
            Deploy::Building { sha256, .. }
            | Deploy::Built { sha256, .. }
            | Deploy::Failed { sha256, .. } => sha256,
        }
    }
}

/// The sha256 of the tools node `row` reports current, if any, unless it reports them changed
/// since it installed them, or installed with nothing recorded to check them against: those
/// are built anew. A node that checks nothing is taken at its word.
pub fn current(row: &NodeRow) -> Option<&str> {
    use vk_hub_proto::ToolsCheck;
    row.inventory
        .as_ref()?
        .versions
        .tools
        .as_ref()
        .filter(|t| matches!(t.check, None | Some(ToolsCheck::Intact)))
        .map(|t| t.sha256.as_str())
}

/// Why node `row`, which `connected` says whether a session is open for, is not asked for
/// tools now, beyond its own build state: `None` when it can be.
pub fn held(row: &NodeRow, connected: bool) -> Option<String> {
    match row.protocol {
        None => return Some("it has not connected yet".into()),
        Some(v) if v < vk_hub_proto::TOOLS => {
            return Some(format!(
                "it speaks protocol version {v}, and tools take version {}: update its vk",
                vk_hub_proto::TOOLS
            ));
        }
        Some(_) => {}
    }
    if row.inventory.is_none() {
        return Some("it has not reported its inventory yet".into());
    }
    if row.report.as_ref().and_then(|r| r.state) == Some(vk_hub_proto::NodeState::Quarantined) {
        return Some("it is quarantined".into());
    }
    if !connected {
        return Some("it is not connected".into());
    }
    None
}

/// Where node `row` stands against the tools the setting names, beyond having them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// It has them, or the setting leaves its tools alone.
    Settled,
    /// The setting names tools it cannot be given: why.
    Unavailable(String),
    /// Asked to build them by `command`, the `attempt`th time, `since` then.
    Building {
        command: String,
        attempt: u32,
        since: u64,
    },
    /// Its build ended well at `at`; the node is yet to report them current.
    Built { at: u64 },
    /// Attempt `attempt` failed at `at`; the next is due at `retry_at`, or with none waits for
    /// an operator. `held` says why a due one waits.
    Failed {
        reason: String,
        attempt: u32,
        at: u64,
        retry_at: Option<u64>,
        held: Option<String>,
    },
    /// Due to be asked for them.
    Due,
    /// Not asked for them yet: why.
    Held(String),
}

/// Where node `row`, which `connected` says whether a session is open for, stands against
/// the tools the setting `named` names: `wanted`, the definition with its label or why there
/// is none, `deploy` its automatic build's state.
pub fn standing(
    named: &Named,
    wanted: Result<(&str, &str), &str>,
    deploy: Option<&Deploy>,
    row: &NodeRow,
    connected: bool,
) -> Standing {
    if *named == Named::None {
        return Standing::Settled;
    }
    let sha = match wanted {
        Ok((sha, _)) => sha,
        Err(why) => return Standing::Unavailable(why.to_string()),
    };
    if current(row) == Some(sha) {
        return Standing::Settled;
    }
    match deploy.filter(|d| d.sha256() == sha) {
        Some(Deploy::Building {
            command,
            attempt,
            since,
            ..
        }) => Standing::Building {
            command: command.clone(),
            attempt: *attempt,
            since: *since,
        },
        Some(Deploy::Built { at, .. }) => Standing::Built { at: *at },
        Some(Deploy::Failed {
            reason,
            attempt,
            at,
            retry_at,
            ..
        }) => Standing::Failed {
            reason: reason.clone(),
            attempt: *attempt,
            at: *at,
            retry_at: *retry_at,
            held: held(row, connected),
        },
        None => match held(row, connected) {
            Some(why) => Standing::Held(why),
            None => Standing::Due,
        },
    }
}

/// A line about node `row`'s tools against the setting, for `vk-hub nodes` and its page;
/// `None` when it has them, or the setting leaves them alone. `wanted` is the definition the
/// setting names with its label, or why there is none; `deploy` its automatic build's state.
pub fn note(
    named: &Named,
    wanted: Result<(&str, &str), &str>,
    deploy: Option<&Deploy>,
    row: &NodeRow,
    connected: bool,
    now: u64,
) -> Option<String> {
    let shown = match wanted {
        Ok((sha, label)) => format!("{label} ({})", crate::store::short(sha)),
        Err(_) => String::new(),
    };
    Some(match standing(named, wanted, deploy, row, connected) {
        Standing::Settled => return None,
        Standing::Unavailable(why) => format!("not given CI tools automatically: {why}"),
        Standing::Building {
            command, attempt, ..
        } if attempt > 1 => {
            format!(
                "building the CI tools {shown} (command {command}, attempt {attempt} of {ATTEMPTS})"
            )
        }
        Standing::Building { command, .. } => {
            format!("building the CI tools {shown} (command {command})")
        }
        Standing::Built { .. } => format!("installed the CI tools {shown}"),
        Standing::Failed {
            reason,
            attempt,
            retry_at,
            held,
            ..
        } => {
            let failed = format!(
                "attempt {attempt} of {ATTEMPTS} to build the CI tools {shown} failed: {reason}"
            );
            match (retry_at, held) {
                (Some(t), _) if t > now => format!(
                    "{failed}; the next is due after {}; `vk-hub nodes tools <id>` tries now",
                    crate::utc(t)
                ),
                (Some(_), Some(why)) => format!("{failed}; the next is due, but waits: {why}"),
                (Some(_), None) => format!("{failed}; the next is due"),
                (None, _) => format!(
                    "{failed}; no more are made automatically: `vk-hub nodes tools <id>` tries \
                     again"
                ),
            }
        }
        Standing::Held(why) => format!("not given the CI tools {shown} yet: {why}"),
        Standing::Due => format!("due to build the CI tools {shown}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vk_hub_proto::{Inventory, NodeState, Report, ToolsInstalled};

    fn node(tools: Option<&str>, protocol: u32) -> NodeRow {
        let mut inventory = Inventory::default();
        inventory.versions.tools = tools.map(|sha| ToolsInstalled {
            sha256: sha.into(),
            version: "git-2".into(),
            tools: Default::default(),
            in_use: true,
            files: Default::default(),
            egress: None,
            check: None,
        });
        NodeRow {
            hostname: "h".into(),
            protocol: Some(protocol),
            inventory: Some(inventory),
            report: Some(Report {
                state: Some(NodeState::Ready),
                ..Report::default()
            }),
            ..NodeRow::default()
        }
    }

    #[test]
    fn unset_is_the_builtin_definition() {
        assert_eq!(Named::of(None), Named::Builtin);
        assert_eq!(Named::of(Some(&json!("builtin"))), Named::Builtin);
        assert_eq!(Named::of(Some(&json!("none"))), Named::None);
        let sha = "ab".repeat(32);
        assert_eq!(Named::of(Some(&json!(sha))), Named::Sha256(sha.clone()));
        assert_eq!(Named::Builtin.sha256("cd"), Some("cd"));
        assert_eq!(Named::None.sha256("cd"), None);
        assert_eq!(Named::Sha256(sha.clone()).sha256("cd"), Some(sha.as_str()));
    }

    #[test]
    fn a_node_is_noted_until_it_has_its_tools() {
        let sha = "ab".repeat(32);
        let wanted = Ok((sha.as_str(), "git-2"));
        let note = |deploy: Option<&Deploy>, row: &NodeRow, connected| {
            note(&Named::Builtin, wanted, deploy, row, connected, 100)
        };
        assert_eq!(note(None, &node(Some(&sha), 4), true), None);
        assert_eq!(
            note(None, &node(None, 4), true).unwrap(),
            "due to build the CI tools git-2 (abababababab)"
        );
        assert!(
            note(None, &node(None, 3), true)
                .unwrap()
                .contains("protocol version 3")
        );
        assert!(
            note(None, &node(None, 4), false)
                .unwrap()
                .contains("not connected")
        );
        let failed = |retry_at| Deploy::Failed {
            sha256: sha.clone(),
            reason: "vk build failed".into(),
            at: 1,
            attempt: 2,
            retry_at,
        };
        let shown =
            |retry_at, connected| note(Some(&failed(retry_at)), &node(None, 4), connected).unwrap();
        assert_eq!(
            shown(Some(400), true),
            "attempt 2 of 5 to build the CI tools git-2 (abababababab) failed: vk build failed; \
             the next is due after 1970-01-01T00:06:40Z; `vk-hub nodes tools <id>` tries now"
        );
        assert!(shown(Some(100), true).ends_with("failed: vk build failed; the next is due"));
        assert!(
            shown(Some(100), false).ends_with("the next is due, but waits: it is not connected")
        );
        assert!(
            shown(None, true)
                .ends_with("no more are made automatically: `vk-hub nodes tools <id>` tries again")
        );
        let retrying = Deploy::Building {
            sha256: sha.clone(),
            command: "c1".into(),
            since: 1,
            attempt: 3,
        };
        assert_eq!(
            note(Some(&retrying), &node(None, 4), true).unwrap(),
            "building the CI tools git-2 (abababababab) (command c1, attempt 3 of 5)"
        );
        // The setting leaves the node alone: nothing to say.
        assert_eq!(
            super::note(&Named::None, wanted, None, &node(None, 4), true, 0),
            None
        );
        assert!(
            super::note(&Named::Builtin, Err("gone"), None, &node(None, 4), true, 0)
                .unwrap()
                .contains("gone")
        );
    }

    #[test]
    fn retries_back_off_then_stop() {
        let sha = "ab".repeat(32);
        let mut at = 1_000_000;
        for (attempt, delay) in (1..).zip(RETRY_DELAYS_SECS) {
            let due = retry_at("n1", &sha, attempt, at).unwrap();
            assert!(
                (delay * 4 / 5..=delay * 6 / 5).contains(&(due - at)),
                "attempt {attempt}: {}s after, not about {delay}s",
                due - at
            );
            assert_eq!(
                retry_at("n1", &sha, attempt, at),
                Some(due),
                "the same each time"
            );
            at = due;
        }
        assert_eq!(ATTEMPTS, 5);
        assert_eq!(retry_at("n1", &sha, ATTEMPTS, at), None, "the last attempt");
        assert_eq!(retry_at("n1", &sha, 0, at), None);
        // Spread across nodes: a fleet that failed together does not retry together.
        let dues: std::collections::BTreeSet<u64> = (0..20)
            .map(|n| retry_at(&format!("n{n}"), &sha, 1, 0).unwrap())
            .collect();
        assert!(dues.len() > 10, "{dues:?}");
    }

    #[test]
    fn a_failure_kept_before_retries_waits_for_an_operator() {
        let old: Deploy = serde_json::from_value(json!({
            "status": "failed", "sha256": "ab", "reason": "r", "at": 1
        }))
        .unwrap();
        assert!(matches!(
            old,
            Deploy::Failed {
                attempt: 1,
                retry_at: None,
                ..
            }
        ));
    }
}
