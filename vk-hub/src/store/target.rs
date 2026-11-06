//! The hub's target `vk` release ([`crate::target`]): set and cleared by an operator, and
//! advanced by the hub's rollout task one automatic update at a time.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use vk_hub_proto::{NodeState, Operation};

use super::{
    COMMANDS, CommandRow, Db, NODES, NodeRow, ROLLOUTS, append_audit, command_range, decode,
    encode, insert_command, insert_rollout, node_facts, refuse_active_rollout, release_in, short,
};
use crate::rollout::{self, NodeStatus, RolloutRow, Update};
use crate::target::{ACTOR, TargetRow};

/// Key: [`KEY`]. Value: JSON [`TargetRow`].
pub(super) const TARGET: TableDefinition<&str, &[u8]> = TableDefinition::new("target");

/// The one key of [`TARGET`]: the target of the nodes' program.
const KEY: &str = "vk";

/// Read the target inside `txn`.
fn target_in(txn: &redb::WriteTransaction) -> Result<Option<TargetRow>> {
    txn.open_table(TARGET)?
        .get(KEY)?
        .map(|g| decode::<TargetRow>(g.value()))
        .transpose()
}

/// Whether `id` has a command still to finish that updates it, whatever the release.
fn updating(
    commands: &impl ReadableTable<&'static str, &'static [u8]>,
    id: &str,
    now: u64,
) -> Result<bool> {
    let (start, end) = command_range(id);
    for entry in commands.range(start.as_str()..end.as_str())? {
        let c = decode::<CommandRow>(entry?.1.value())?;
        if c.live(now) && matches!(c.command.op, Operation::Update { .. }) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Db {
    /// The target, if one is set.
    pub fn target(&self) -> Result<Option<TargetRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        txn.open_table(TARGET)?
            .get(KEY)?
            .map(|g| decode::<TargetRow>(g.value()))
            .transpose()
    }

    /// Replace the target with `row` and start `rollout` by ID in the same transaction,
    /// audited as `actor`. Refuse while a rollout runs or is paused, or an automatic update
    /// to the previous target is under way.
    pub fn set_target(
        &self,
        row: &TargetRow,
        rollout: Option<(&str, &RolloutRow)>,
        actor: &str,
    ) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        // Checked here, in the write: a release removed since it was looked up is gone.
        if release_in(&txn, &row.release)?.is_none() {
            bail!("there is no release {}", row.release);
        }
        let before = target_in(&txn)?;
        if let Some(b) = &before
            && let Some(node) = b
                .nodes
                .iter()
                .find_map(|(n, s)| matches!(s, NodeStatus::Updating { .. }).then_some(n))
        {
            bail!(
                "node {node} is being updated to the target vk {}; let it finish first",
                b.version
            );
        }
        match rollout {
            Some((id, rollout)) => insert_rollout(&txn, id, rollout, actor)?,
            None => refuse_active_rollout(&txn)?,
        }
        txn.open_table(TARGET)?
            .insert(KEY, encode(row)?.as_slice())?;
        let mut event = format!(
            "{actor} set the target to vk {} ({})",
            row.version,
            short(&row.release)
        );
        if let Some(before) = before.filter(|b| b.release != row.release) {
            event.push_str(&format!(
                ", was vk {} ({})",
                before.version,
                short(&before.release)
            ));
        }
        append_audit(&txn, None, actor, &event, row.set_at)?;
        txn.commit().context("setting the target")
    }

    /// Clear the target, audited as `actor`'s; the target cleared, or `None` when none was set.
    /// An automatic update under way finishes; a rollout it started goes on.
    pub fn clear_target(&self, actor: &str, now: u64) -> Result<Option<TargetRow>> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = txn
            .open_table(TARGET)?
            .remove(KEY)?
            .map(|g| decode::<TargetRow>(g.value()))
            .transpose()?;
        let Some(row) = removed else {
            txn.abort().context("dropping a write")?;
            return Ok(None);
        };
        let event = format!(
            "{actor} cleared the target, vk {} ({})",
            row.version,
            short(&row.release)
        );
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("clearing the target")?;
        Ok(Some(row))
    }

    /// Allow failed target updates to be retried for IDs starting with `id`, or all with
    /// `None`, and lift any automatic-update hold, audited as `actor`. Return the nodes allowed
    /// to retry and whether a hold was lifted.
    pub fn retry_target(
        &self,
        id: Option<&str>,
        actor: &str,
        now: u64,
    ) -> Result<(Vec<String>, bool)> {
        let txn = self.db.begin_write().context("starting a write")?;
        let Some(mut row) = target_in(&txn)? else {
            bail!("no target is set");
        };
        let retried: Vec<String> = row
            .nodes
            .iter()
            .filter(|(n, s)| {
                matches!(s, NodeStatus::Failed { .. }) && id.is_none_or(|id| n.starts_with(id))
            })
            .map(|(n, _)| n.clone())
            .collect();
        let lifted = row.held.take().is_some();
        if retried.is_empty() && !lifted {
            txn.abort().context("dropping a write")?;
            return Ok((retried, false));
        }
        if lifted {
            let event = format!(
                "{actor} resumed the automatic updates to the target vk {}",
                row.version
            );
            append_audit(&txn, None, actor, &event, now)?;
        }
        for n in &retried {
            row.nodes.remove(n);
            let event = format!(
                "{actor} let the update to the target vk {} be tried again",
                row.version
            );
            append_audit(&txn, Some(n), actor, &event, now)?;
        }
        txn.open_table(TARGET)?
            .insert(KEY, encode(&row)?.as_slice())?;
        txn.commit().context("retrying the target")?;
        Ok((retried, lifted))
    }

    /// Advance the target's automatic updates at `now`: judge the one under way, take in the
    /// failures of the rollout setting it started once that is over, and, with no update under
    /// way and no rollout running or paused, issue one to a node behind it, ready, and
    /// `connected`. Do not judge windows before `not_before`. Returns whether anything changed
    /// and the node issued an update, if any.
    pub fn advance_target(
        &self,
        now: u64,
        not_before: u64,
        connected: &dyn Fn(&str) -> bool,
    ) -> Result<(bool, Option<String>)> {
        let txn = self.db.begin_write().context("starting a write")?;
        let Some(mut row) = target_in(&txn)? else {
            txn.abort().context("ending a read")?;
            return Ok((false, None));
        };
        let before = row.clone();
        let update = Update {
            release: &before.release,
            version: &before.version,
            node_timeout_secs: rollout::NODE_TIMEOUT_SECS,
            drain_timeout_secs: rollout::DRAIN_TIMEOUT_SECS,
        };
        let facts = node_facts(&txn, row.nodes.iter().map(|(id, s)| (id.as_str(), s)), now)?;
        let mut audits = Vec::new();
        row.nodes.retain(|id, status| {
            // A node removed from the hub is forgotten here too; its removal is audited.
            if !facts.contains_key(id) {
                return false;
            }
            let NodeStatus::Updating { command, .. } = status else {
                return true;
            };
            let command = command.clone();
            match rollout::judge(&update, status, facts.get(id), now, not_before) {
                None => true,
                Some(Ok(())) => {
                    audits.push((
                        id.clone(),
                        format!(
                            "updated to the target vk {} (command {command})",
                            before.version
                        ),
                    ));
                    false
                }
                Some(Err((reason, ran))) => {
                    let reason = vk_hub_proto::display_safe(&reason);
                    audits.push((
                        id.clone(),
                        format!(
                            "failed to update to the target vk {}: {reason}; not tried again \
                             until `vk-hub release target --retry`",
                            before.version
                        ),
                    ));
                    *status = NodeStatus::Failed {
                        reason,
                        at: now,
                        ran,
                    };
                    true
                }
            }
        });
        // Ahead of the next update issued, which follows them.
        for (node, event) in audits {
            append_audit(&txn, Some(&node), ACTOR, &event, now)?;
        }
        // Any rollout running or paused holds the automatic updates back; once the target's is
        // over, the nodes it failed to update count as failed here.
        let mut rollout_active = false;
        let mut audits_held = Vec::new();
        for entry in txn.open_table(ROLLOUTS)?.iter()? {
            let (id, value) = entry?;
            let r = decode::<RolloutRow>(value.value())?;
            let ours = row.rollout.as_deref() == Some(id.value());
            let settling = r.state.active()
                || r.nodes
                    .iter()
                    .any(|n| matches!(n.status, NodeStatus::Updating { .. }));
            rollout_active |= settling;
            if ours && !settling {
                if let rollout::RolloutState::Aborted { reason } = &r.state {
                    let why = format!(
                        "its rollout {} was aborted: {reason}",
                        rollout::short_id(id.value())
                    );
                    audits_held.push(format!(
                        "held the automatic updates to the target vk {}: {why}",
                        before.version
                    ));
                    row.held = Some(why);
                }
                for n in &r.nodes {
                    if let NodeStatus::Failed { reason, at, ran } = &n.status {
                        row.nodes.entry(n.id.clone()).or_insert(NodeStatus::Failed {
                            reason: reason.clone(),
                            at: *at,
                            ran: *ran,
                        });
                    }
                }
                row.rollout = None;
            }
        }
        if row.rollout.is_some() && !rollout_active {
            // Deleted before it was looked at: nothing to take in.
            row.rollout = None;
        }
        for event in audits_held {
            append_audit(&txn, None, ACTOR, &event, now)?;
        }
        let mut issued = None;
        let busy = row.held.is_some()
            || rollout_active
            || row
                .nodes
                .values()
                .any(|s| matches!(s, NodeStatus::Updating { .. }));
        if !busy {
            let nodes: Vec<(String, NodeRow)> = {
                let table = txn.open_table(NODES)?;
                let mut out = Vec::new();
                for entry in table.iter()? {
                    let (id, value) = entry?;
                    // A row that does not decode is left out, not a reason to stop.
                    if let Ok(node) = decode::<NodeRow>(value.value()) {
                        out.push((id.value().to_string(), node));
                    }
                }
                out
            };
            let commands = txn.open_table(COMMANDS)?;
            let mut candidates = Vec::new();
            for (id, node) in &nodes {
                let free = connected(id) && !updating(&commands, id, now)?;
                candidates.push((id.as_str(), node, free));
            }
            drop(commands);
            if let Some(id) = crate::target::pick(&row, candidates) {
                let Some(release) = release_in(&txn, &row.release)? else {
                    bail!("the target's release {} is gone", row.release);
                };
                let op =
                    crate::ops::update_operation(&release, false, Some(rollout::NODE_TIMEOUT_SECS));
                let ttl = Duration::from_secs(rollout::DRAIN_TIMEOUT_SECS);
                let command = insert_command(&txn, id, op, ttl, ACTOR, now)?;
                row.nodes.insert(
                    id.to_string(),
                    NodeStatus::Updating {
                        command: command.id,
                        since: now,
                        resume: NodeState::Ready,
                        drained_at: None,
                    },
                );
                issued = Some(id.to_string());
            }
        }
        if row == before {
            txn.abort().context("ending the target's read")?;
            return Ok((false, None));
        }
        txn.open_table(TARGET)?
            .insert(KEY, encode(&row)?.as_slice())?;
        txn.commit().context("advancing the target")?;
        Ok((true, issued))
    }
}

/// Whether the target still has to take in how rollout `id`, which setting it started, ended.
pub(super) fn awaits(txn: &redb::WriteTransaction, id: &str) -> Result<bool> {
    Ok(target_in(txn)?.is_some_and(|t| t.rollout.as_deref() == Some(id)))
}

/// Why release `sha256` is kept as the target inside `txn`, if it is.
pub(super) fn keeps(txn: &redb::WriteTransaction, sha256: &str) -> Result<Option<String>> {
    Ok(target_in(txn)?
        .filter(|t| t.release == sha256)
        .map(|_| "it is the target; `vk-hub release target --clear` first".to_string()))
}
