//! The automatic builds that keep nodes on the CI tools the hub's `tools` setting names
//! ([`crate::deploy`]): where each node's stands, advanced by the hub's rollout task.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::Value;
use vk_hub_proto::{Operation, Outcome};

use super::settings::{Layers, SETTINGS, layers_in};
use super::tools::{TOOLS, ToolsRow};
use super::{
    COMMANDS, CommandRow, Db, MonitoringOnly, NODES, NodeRow, NotEnrolled, ToolsUnsupported,
    append_audit, command_range, decode, encode, insert_command, short,
};
use crate::deploy::{ACTOR, ATTEMPTS, COMMAND_TTL, Deploy, KEY, Named, REPORT_GRACE_SECS};

/// Key: [`KEY_NODES`]. Value: JSON map of node ID to [`Deploy`].
pub(super) const DEPLOY: TableDefinition<&str, &[u8]> = TableDefinition::new("tools_deploy");

/// The one key of [`DEPLOY`].
const KEY_NODES: &str = "nodes";

/// Each node's automatic build, by ID.
pub type Deploys = BTreeMap<String, Deploy>;

fn deploys_in(table: &impl ReadableTable<&'static str, &'static [u8]>) -> Result<Deploys> {
    table
        .get(KEY_NODES)?
        .map(|g| decode::<Deploys>(g.value()))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn save(txn: &redb::WriteTransaction, deploys: &Deploys) -> Result<()> {
    let mut table = txn.open_table(DEPLOY)?;
    if deploys.is_empty() {
        table.remove(KEY_NODES)?;
    } else {
        table.insert(KEY_NODES, encode(deploys)?.as_slice())?;
    }
    Ok(())
}

/// What the `tools` setting in `layers` names for node `id`.
pub(super) fn named(layers: &Layers, id: &str) -> Named {
    Named::of(layers.merged(id).get(KEY))
}

/// The definition node `id` is kept on, by `layers` with `builtin` the built-in definition's
/// sha256, and its row in `tools`: `None` when the setting leaves it alone, `Err` with why it
/// names none the hub holds.
fn wanted_in(
    layers: &Layers,
    id: &str,
    builtin: &str,
    tools: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Option<Result<(String, ToolsRow), String>>> {
    let named = named(layers, id);
    let Some(sha) = named.sha256(builtin) else {
        return Ok(None);
    };
    let row = tools
        .get(sha)?
        .map(|g| decode::<ToolsRow>(g.value()))
        .transpose()?;
    Ok(Some(match row {
        Some(row) => Ok((sha.to_string(), row)),
        None if named == Named::Builtin => {
            Err("the hub does not hold its built-in tools; its log says why".to_string())
        }
        None => Err(format!("the hub no longer holds the tools {}", short(sha))),
    }))
}

/// Whether node `id` has a command still to finish that a tools build cannot run beside: a
/// tools build, an update or a reset.
pub(super) fn busy(
    commands: &impl ReadableTable<&'static str, &'static [u8]>,
    id: &str,
    now: u64,
) -> Result<bool> {
    let (start, end) = command_range(id);
    for entry in commands.range(start.as_str()..end.as_str())? {
        let c = decode::<CommandRow>(entry?.1.value())?;
        if c.live(now)
            && matches!(
                c.command.op,
                Operation::Tools { .. } | Operation::Update { .. } | Operation::Reset { .. }
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Why command `row` ended a build badly, or `None` while it may still end well; `Ok` once it
/// did.
fn judged(row: &CommandRow, now: u64) -> Option<Result<(), String>> {
    match &row.outcome {
        Some(Outcome::Done) => Some(Ok(())),
        Some(Outcome::Failed { message }) => Some(Err(vk_hub_proto::display_safe(message))),
        Some(Outcome::Refused { reason }) => Some(Err(format!(
            "refused: {}",
            vk_hub_proto::display_safe(reason)
        ))),
        Some(Outcome::Expired) => Some(Err("it was not taken in time".into())),
        Some(Outcome::Accepted) => None,
        None if row.live(now) => None,
        None => Some(Err("it was not taken in time".into())),
    }
}

/// Node `id`'s attempt `attempt` to build `sha256` failed at `now` for `reason`: where it
/// stands now, with its audit event pushed onto `audits`.
fn failed(
    id: &str,
    sha256: &str,
    attempt: u32,
    reason: String,
    now: u64,
    audits: &mut Vec<(String, String)>,
) -> Deploy {
    let retry_at = crate::deploy::retry_at(id, sha256, attempt, now);
    let next = match retry_at {
        Some(t) => format!("the next is due after {}", crate::utc(t)),
        None => "no more are made automatically: `vk-hub nodes tools` tries again".into(),
    };
    audits.push((
        id.to_string(),
        format!(
            "attempt {attempt} of {ATTEMPTS} to build the CI tools {} failed: {reason}; {next}",
            short(sha256)
        ),
    ));
    Deploy::Failed {
        sha256: sha256.to_string(),
        reason,
        at: now,
        attempt,
        retry_at,
    }
}

impl Db {
    /// Each node's automatic build.
    pub fn tools_deploys(&self) -> Result<Deploys> {
        let txn = self.db.begin_read().context("starting a read")?;
        deploys_in(&txn.open_table(DEPLOY)?)
    }

    /// The definition node `id` is kept on, `builtin` being the built-in one's sha256: `None`
    /// when its `tools` setting leaves it alone, `Err` with why it names none the hub holds.
    pub fn tools_wanted(
        &self,
        id: &str,
        builtin: &str,
    ) -> Result<Option<Result<(String, ToolsRow), String>>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let layers = layers_in(&txn.open_table(SETTINGS)?)?;
        wanted_in(&layers, id, builtin, &txn.open_table(TOOLS)?)
    }

    /// Follow node `id`'s build of `sha256` by `command`, which an operator asked for, as an
    /// automatic one, its first attempt: the tools its `tools` setting names. A failed
    /// automatic build of them is forgotten, audited as `actor`'s.
    pub fn follow_tools(
        &self,
        id: &str,
        sha256: &str,
        command: &str,
        actor: &str,
        now: u64,
    ) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut deploys = deploys_in(&txn.open_table(DEPLOY)?)?;
        let next = Deploy::Building {
            sha256: sha256.to_string(),
            command: command.to_string(),
            since: now,
            attempt: 1,
        };
        if let Some(Deploy::Failed { sha256: s, .. }) = deploys.insert(id.to_string(), next)
            && s == sha256
        {
            let event = format!(
                "{actor} let the CI tools {} be built automatically again",
                short(sha256)
            );
            append_audit(&txn, Some(id), actor, &event, now)?;
        }
        save(&txn, &deploys)?;
        txn.commit().context("following a tools build")
    }

    /// Advance the automatic builds at `now`, `builtin` being the built-in definition's sha256:
    /// judge those under way and those built, then ask every node `connected` says has a session
    /// for the tools its setting names, where [`crate::deploy`] says it should be. Whether
    /// anything changed, and the nodes asked.
    pub fn advance_tools(
        &self,
        now: u64,
        builtin: &str,
        connected: &dyn Fn(&str) -> bool,
    ) -> Result<(bool, Vec<String>)> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut deploys = deploys_in(&txn.open_table(DEPLOY)?)?;
        let before = deploys.clone();
        let nodes: BTreeMap<String, NodeRow> = {
            let table = txn.open_table(NODES)?;
            let mut out = BTreeMap::new();
            for entry in table.iter()? {
                let (id, value) = entry?;
                // A row that does not decode is left out, not a reason to stop.
                if let Ok(node) = decode::<NodeRow>(value.value()) {
                    out.insert(id.value().to_string(), node);
                }
            }
            out
        };
        let mut audits = Vec::new();
        {
            let commands = txn.open_table(COMMANDS)?;
            let mut judged_all = Vec::new();
            for (id, deploy) in &deploys {
                // A node removed from the hub is forgotten here too; its removal is audited.
                let Some(node) = nodes.get(id) else {
                    judged_all.push((id.clone(), None));
                    continue;
                };
                let next = match deploy {
                    Deploy::Building {
                        sha256,
                        command,
                        attempt,
                        ..
                    } => {
                        let row = commands
                            .get(format!("{id}/{command}").as_str())?
                            .map(|g| decode::<CommandRow>(g.value()))
                            .transpose()?;
                        match row.as_ref().map(|r| judged(r, now)) {
                            // Its command is gone, past what the hub keeps.
                            None => Some(failed(
                                id,
                                sha256,
                                *attempt,
                                "the hub no longer knows how it ended".into(),
                                now,
                                &mut audits,
                            )),
                            Some(None) => continue,
                            Some(Some(Ok(()))) => Some(Deploy::Built {
                                sha256: sha256.clone(),
                                at: now,
                                attempt: *attempt,
                            }),
                            Some(Some(Err(reason))) => {
                                Some(failed(id, sha256, *attempt, reason, now, &mut audits))
                            }
                        }
                    }
                    // Installed, even after its build was judged failed.
                    Deploy::Built { sha256, .. } | Deploy::Failed { sha256, .. }
                        if crate::deploy::current(node) == Some(sha256.as_str()) =>
                    {
                        audits.push((
                            id.clone(),
                            format!("installed the CI tools {}", short(sha256)),
                        ));
                        None
                    }
                    Deploy::Built {
                        sha256,
                        at,
                        attempt,
                    } => {
                        if now.saturating_sub(*at) > REPORT_GRACE_SECS {
                            let reason =
                                "its build ended, but it reports other tools current".to_string();
                            Some(failed(id, sha256, *attempt, reason, now, &mut audits))
                        } else {
                            continue;
                        }
                    }
                    Deploy::Failed { .. } => continue,
                };
                judged_all.push((id.clone(), next));
            }
            for (id, next) in judged_all {
                match next {
                    Some(d) => deploys.insert(id, d),
                    None => deploys.remove(&id),
                };
            }
        }
        let layers = layers_in(&txn.open_table(SETTINGS)?)?;
        let mut due = Vec::new();
        {
            let tools = txn.open_table(TOOLS)?;
            let commands = txn.open_table(COMMANDS)?;
            for (id, node) in &nodes {
                let Some(Ok((sha256, row))) = wanted_in(&layers, id, builtin, &tools)? else {
                    continue;
                };
                let attempt = match deploys.get(id) {
                    Some(Deploy::Building { .. } | Deploy::Built { .. }) => continue,
                    Some(Deploy::Failed {
                        sha256: failed,
                        attempt,
                        retry_at,
                        ..
                    }) if *failed == sha256 => match retry_at {
                        Some(t) if *t <= now => attempt + 1,
                        _ => continue,
                    },
                    // A failure of other tools than those named now holds nothing back.
                    Some(Deploy::Failed { .. }) => {
                        deploys.remove(id);
                        1
                    }
                    None => 1,
                };
                if crate::deploy::current(node) == Some(sha256.as_str())
                    || crate::deploy::held(node, connected(id)).is_some()
                    || busy(&commands, id, now)?
                {
                    continue;
                }
                due.push((id.clone(), sha256, row, attempt));
            }
        }
        let mut issued = Vec::new();
        for (id, sha256, row, attempt) in due {
            let op = Operation::Tools {
                version: row.version.clone(),
                sha256: sha256.clone(),
                size: row.size,
            };
            match insert_command(&txn, &id, op, COMMAND_TTL, ACTOR, now) {
                Ok(command) => {
                    deploys.insert(
                        id.clone(),
                        Deploy::Building {
                            sha256,
                            command: command.id,
                            since: now,
                            attempt,
                        },
                    );
                    issued.push(id);
                }
                // What the node's row says since it was read: it is not asked.
                Err(e)
                    if e.is::<MonitoringOnly>()
                        || e.is::<ToolsUnsupported>()
                        || e.is::<NotEnrolled>() => {}
                Err(e) => return Err(e),
            }
        }
        for (id, event) in audits {
            append_audit(&txn, Some(&id), ACTOR, &event, now)?;
        }
        if deploys == before && issued.is_empty() {
            txn.abort().context("ending the tools' read")?;
            return Ok((false, Vec::new()));
        }
        save(&txn, &deploys)?;
        txn.commit().context("advancing the tools builds")?;
        Ok((true, issued))
    }
}

/// Why definition `sha256` is kept for the `tools` setting in `txn`, if it is: any layer that
/// names it, whether another masks it or not.
pub(super) fn keeps(txn: &redb::WriteTransaction, sha256: &str) -> Result<Option<String>> {
    let layers = layers_in(&txn.open_table(SETTINGS)?)?;
    let names =
        |layer: &BTreeMap<String, Value>| layer.get(KEY).and_then(Value::as_str) == Some(sha256);
    if names(&layers.fleet) {
        return Ok(Some(
            "the `tools` setting names it fleet-wide; set it to others first".into(),
        ));
    }
    if let Some((id, _)) = layers.nodes.iter().find(|(_, l)| names(l)) {
        return Ok(Some(format!(
            "the `tools` setting names it for node {id}; set it to others first"
        )));
    }
    Ok(None)
}
