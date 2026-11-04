//! GitLab relay commands — updates, runner additions and removals — and their outcomes,
//! stored like registry commands ([`super::registries`]). Commands are sent once per session
//! until answered and kept a month after settling. [`Operation::without_token`] removes
//! runner tokens before storage.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::gitlab::{Command, Inventory, Operation, Report, RunnerFailure, RunnerSource};
use vk_hub_proto::{CommandAck, Outcome, UpdatePhase};

use super::relays::{RELAYS, RelayRow};
use super::{
    COMMAND_KEEP, Db, NotEnrolled, append_audit, decode, display_safe_outcome, encode, outcome_text,
};

/// Key: `<relay ID>/<command ID>`. Value: JSON [`RelayCommandRow`].
pub(super) const RELAY_COMMANDS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("relay_commands");

/// A command issued to a relay, and what the relay last said it came to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayCommandRow {
    pub command: Command,
    pub issued_at: u64,
    /// Issue order among the relay's commands, whatever the clock did.
    pub seq: u64,
    #[serde(default)]
    pub outcome: Option<Outcome>,
    #[serde(default)]
    pub outcome_at: Option<u64>,
    /// For an [`Operation::AddRunner`] done, the runner's GitLab ID, as the relay's inventory
    /// gave it when the relay acked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<u64>,
}

impl RelayCommandRow {
    /// Still to be delivered or finished.
    fn pending(&self) -> bool {
        matches!(self.outcome, None | Some(Outcome::Accepted))
    }

    /// Still to deliver or finish, and not past an expiry the relay never answered.
    fn live(&self, now: u64) -> bool {
        self.pending() && (self.outcome.is_some() || self.command.expires_at > now)
    }

    /// What the hub set, not the relay: [`RunnerFailure::TokenLost`]. A relay's ack replaces it.
    fn token_lost(&self) -> bool {
        self.outcome
            .as_ref()
            .and_then(RunnerFailure::of)
            .is_some_and(|f| f == RunnerFailure::TokenLost)
    }

    /// [`RelayCommandRow::live`], and an update to release `sha256`.
    pub(super) fn updates_to(&self, sha256: &str, now: u64) -> bool {
        self.live(now)
            && matches!(&self.command.op, Operation::Update { sha256: s, .. } if s == sha256)
    }

    /// An update is under way if unaccepted and unexpired, or accepted and running in the
    /// relay's last report: one it no longer reports after a restart does not block another.
    fn updating(&self, report: Option<&Report>, now: u64) -> bool {
        if !self.live(now) || !matches!(self.command.op, Operation::Update { .. }) {
            return false;
        }
        match self.outcome {
            Some(Outcome::Accepted) => report.and_then(|r| r.update.as_ref()).is_some_and(|u| {
                u.command == self.command.id
                    && matches!(
                        u.phase,
                        UpdatePhase::Draining | UpdatePhase::Downloading | UpdatePhase::Validating
                    )
            }),
            _ => true,
        }
    }

    /// Why `op`, a runner command, cannot be issued beside this one: a runner command for the
    /// same name still under way, or for a removal, a removal of the same runner not failed.
    fn blocks(&self, op: &Operation, now: u64) -> Option<String> {
        let name_of = |op: &Operation| match op {
            Operation::AddRunner { name, .. } | Operation::RemoveRunner { name, .. } => {
                Some(name.clone())
            }
            Operation::Update { .. } => None,
        };
        let (Some(ours), Some(theirs)) = (name_of(op), name_of(&self.command.op)) else {
            return None;
        };
        if ours == theirs && self.live(now) {
            return Some(format!(
                "runner {ours} has a command in progress (command {}); wait for it to end",
                self.command.id
            ));
        }
        if let (
            Operation::RemoveRunner { command: ours, .. },
            Operation::RemoveRunner {
                command: theirs, ..
            },
        ) = (op, &self.command.op)
            && ours == theirs
            && matches!(self.outcome, Some(Outcome::Done))
        {
            return Some(format!(
                "runner {} is being removed already (command {})",
                name_of(op).unwrap_or_default(),
                self.command.id
            ));
        }
        None
    }

    /// Settled more than `keep` before `now`.
    fn settled_before(&self, now: u64, keep: u64) -> bool {
        let settled_at = match &self.outcome {
            Some(Outcome::Accepted) => return false,
            Some(_) => self.outcome_at.unwrap_or(self.issued_at),
            None => self.command.expires_at,
        };
        now.saturating_sub(settled_at) > keep
    }
}

/// `(start, end)` of relay `id`'s commands' keys.
pub(super) fn command_range(id: &str) -> (String, String) {
    (format!("{id}/"), format!("{id}0"))
}

/// A short name for an operation, for the audit log and listings.
pub fn relay_operation_name(op: &Operation) -> String {
    match op {
        Operation::Update { version, .. } => format!("update to vk-gitlab {version}"),
        Operation::AddRunner { name, .. } => format!("add runner {name}"),
        Operation::RemoveRunner {
            name, runner_id, ..
        } => format!("remove runner {name} (GitLab runner {runner_id})"),
    }
}

impl Db {
    /// Issue `op` to relay `id`, valid for `ttl`, audited as `actor`'s, and kept without its
    /// token; `issued` sees the command before the write commits. An update is refused while
    /// another is under way, a runner command while another for the same name is, and a
    /// removal of a runner already being removed. Settled commands older than a month go in
    /// the same write.
    pub fn issue_relay_command(
        &self,
        id: &str,
        op: Operation,
        ttl: Duration,
        actor: &str,
        now: u64,
        issued: impl FnOnce(&Command),
    ) -> Result<Command> {
        let txn = self.db.begin_write().context("starting a write")?;
        let Some(relay) = txn
            .open_table(RELAYS)?
            .get(id)?
            .map(|g| decode::<RelayRow>(g.value()))
            .transpose()?
        else {
            return Err(NotEnrolled(id.to_string()).into());
        };
        let command = Command {
            id: crate::random_hex(vk_hub_proto::ID_BYTES)?,
            expires_at: now.saturating_add(ttl.as_secs()),
            op: op.without_token(),
        };
        {
            let mut table = txn.open_table(RELAY_COMMANDS)?;
            let (start, end) = command_range(id);
            table.retain_in(start.as_str()..end.as_str(), |_, value| {
                decode::<RelayCommandRow>(value)
                    .map_or(true, |r| !r.settled_before(now, COMMAND_KEEP))
            })?;
            let mut seq = 0;
            for entry in table.range(start.as_str()..end.as_str())? {
                let row = decode::<RelayCommandRow>(entry?.1.value())?;
                seq = seq.max(row.seq.saturating_add(1));
                if matches!(command.op, Operation::Update { .. })
                    && row.updating(relay.report.as_ref(), now)
                {
                    bail!(
                        "relay {id} has an update in progress (command {}); wait for it to end",
                        row.command.id
                    );
                }
                if let Some(why) = row.blocks(&command.op, now) {
                    bail!("{why}");
                }
            }
            let row = RelayCommandRow {
                command: command.clone(),
                issued_at: now,
                seq,
                outcome: None,
                outcome_at: None,
                runner_id: None,
            };
            let key = format!("{id}/{}", command.id);
            table.insert(key.as_str(), encode(&row)?.as_slice())?;
        }
        let event = format!(
            "{actor} issued {} to relay {id} (command {})",
            relay_operation_name(&command.op),
            command.id
        );
        append_audit(&txn, Some(id), actor, &event, now)?;
        issued(&command);
        txn.commit().context("issuing a command")?;
        Ok(command)
    }

    /// Relay `id`'s commands still to deliver or finish, in issue order.
    pub fn pending_relay_commands(&self, id: &str, now: u64) -> Result<Vec<Command>> {
        Ok(self
            .relay_commands(id)?
            .into_iter()
            .filter(|r| r.live(now))
            .map(|r| r.command)
            .collect())
    }

    /// Every command kept for relay `id`, oldest first.
    pub fn relay_commands(&self, id: &str) -> Result<Vec<RelayCommandRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(RELAY_COMMANDS)?;
        let (start, end) = command_range(id);
        let mut rows = Vec::new();
        for entry in table.range(start.as_str()..end.as_str())? {
            rows.push(decode::<RelayCommandRow>(entry?.1.value())?);
        }
        rows.sort_by_key(|r| (r.seq, r.issued_at));
        Ok(rows)
    }

    /// Store and audit relay `id`'s outcome for command `ack.id`, with an added runner's
    /// GitLab ID from its inventory. Return `false` for duplicates, unknown commands and
    /// acknowledgements after a final outcome, except [`RunnerFailure::TokenLost`]:
    /// the relay's ack overrides the hub's conclusion.
    pub fn record_relay_ack(&self, id: &str, ack: &CommandAck, now: u64) -> Result<bool> {
        let key = format!("{id}/{}", ack.id);
        let outcome = display_safe_outcome(ack.outcome.clone());
        let txn = self.db.begin_write().context("starting a write")?;
        let inventory = txn
            .open_table(RELAYS)?
            .get(id)?
            .map(|g| decode::<RelayRow>(g.value()))
            .transpose()?
            .and_then(|r| r.inventory);
        let news = {
            let mut table = txn.open_table(RELAY_COMMANDS)?;
            let row = table
                .get(key.as_str())?
                .map(|g| decode::<RelayCommandRow>(g.value()))
                .transpose()?;
            match row {
                Some(mut row)
                    if (row.pending() || row.token_lost())
                        && row.outcome.as_ref() != Some(&outcome) =>
                {
                    row.outcome = Some(outcome.clone());
                    row.outcome_at = Some(now);
                    if outcome == Outcome::Done
                        && matches!(row.command.op, Operation::AddRunner { .. })
                    {
                        row.runner_id = added_runner(inventory.as_ref(), &row.command.id);
                    }
                    table.insert(key.as_str(), encode(&row)?.as_slice())?;
                    Some(row)
                }
                _ => None,
            }
        };
        let Some(row) = news else {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        };
        let command = row.command;
        let mut event = format!(
            "command {} ({}): {}",
            command.id,
            relay_operation_name(&command.op),
            outcome_text(&outcome)
        );
        if let Some(runner_id) = row.runner_id {
            event.push_str(&format!(", GitLab runner {runner_id}"));
        }
        append_audit(&txn, Some(id), "relay", &event, now)?;
        txn.commit().context("recording an ack")?;
        Ok(true)
    }

    /// Settle what relay `id`'s session's first `report` shows the hub lost track of. An
    /// accepted update it does not name failed: no final ack will come, and leaving it live
    /// would resend it every session and retain its release; later reports can arrive between
    /// acceptance and start, so only the first establishes that. A runner added on the hub the
    /// relay never accepted, whose token `holds` says the hub no longer has, failed
    /// [`RunnerFailure::TokenLost`], unless the relay's `inventory` names it; the relay's ack
    /// of it, if it took it after all, replaces that. Check `current` inside the write to
    /// reject a superseded session's report. Return whether anything was settled.
    pub fn settle_lost_relay_commands(
        &self,
        id: &str,
        report: &Report,
        now: u64,
        holds: impl Fn(&str) -> bool,
        current: impl FnOnce() -> bool,
    ) -> Result<bool> {
        let named = report.update.as_ref().map(|u| u.command.as_str());
        let unreported = Outcome::Failed {
            message: "the relay no longer reports this update".to_string(),
        };
        let txn = self.db.begin_write().context("starting a write")?;
        if !current() {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        }
        let inventory = txn
            .open_table(RELAYS)?
            .get(id)?
            .map(|g| decode::<RelayRow>(g.value()))
            .transpose()?
            .and_then(|r| r.inventory);
        let mut settled = Vec::new();
        {
            let mut table = txn.open_table(RELAY_COMMANDS)?;
            let (start, end) = command_range(id);
            for entry in table.range(start.as_str()..end.as_str())? {
                let (key, value) = entry?;
                let row = decode::<RelayCommandRow>(value.value())?;
                let lost = match &row.command.op {
                    Operation::Update { .. } => (row.outcome == Some(Outcome::Accepted)
                        && named != Some(row.command.id.as_str()))
                    .then(|| unreported.clone()),
                    Operation::AddRunner { .. } => (row.outcome.is_none()
                        && row.live(now)
                        && !holds(&row.command.id)
                        && added_runner(inventory.as_ref(), &row.command.id).is_none())
                    .then(|| RunnerFailure::TokenLost.outcome()),
                    Operation::RemoveRunner { .. } => None,
                };
                if let Some(outcome) = lost {
                    settled.push((key.value().to_string(), row, outcome));
                }
            }
            for (key, row, outcome) in &mut settled {
                row.outcome = Some(outcome.clone());
                row.outcome_at = Some(now);
                table.insert(key.as_str(), encode(row)?.as_slice())?;
            }
        }
        if settled.is_empty() {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        }
        for (_, row, outcome) in &settled {
            let event = format!(
                "command {} ({}): {}",
                row.command.id,
                relay_operation_name(&row.command.op),
                outcome_text(outcome)
            );
            append_audit(&txn, Some(id), "hub", &event, now)?;
        }
        txn.commit().context("settling lost commands")?;
        Ok(true)
    }

    /// Record and audit GitLab IDs from relay `id`'s inventory for adds acknowledged done
    /// before the inventory named them. Return whether any ID was recorded.
    pub fn record_added_runners(&self, id: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let inventory = txn
            .open_table(RELAYS)?
            .get(id)?
            .map(|g| decode::<RelayRow>(g.value()))
            .transpose()?
            .and_then(|r| r.inventory);
        let mut taken = Vec::new();
        {
            let mut table = txn.open_table(RELAY_COMMANDS)?;
            let (start, end) = command_range(id);
            for entry in table.range(start.as_str()..end.as_str())? {
                let (key, value) = entry?;
                let mut row = decode::<RelayCommandRow>(value.value())?;
                if matches!(row.command.op, Operation::AddRunner { .. })
                    && row.outcome == Some(Outcome::Done)
                    && row.runner_id.is_none()
                    && let Some(runner_id) = added_runner(inventory.as_ref(), &row.command.id)
                {
                    row.runner_id = Some(runner_id);
                    taken.push((key.value().to_string(), row));
                }
            }
            for (key, row) in &taken {
                table.insert(key.as_str(), encode(row)?.as_slice())?;
            }
        }
        if taken.is_empty() {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        }
        for (_, row) in &taken {
            let event = format!(
                "command {} ({}): GitLab runner {}",
                row.command.id,
                relay_operation_name(&row.command.op),
                row.runner_id.unwrap_or_default()
            );
            append_audit(&txn, Some(id), "relay", &event, now)?;
        }
        txn.commit().context("recording added runners")?;
        Ok(true)
    }

    /// Whether relay `id` has a live update to release `sha256`: what its download is
    /// allowed for.
    pub fn relay_updating_to(&self, id: &str, sha256: &str, now: u64) -> Result<bool> {
        Ok(self
            .relay_commands(id)?
            .iter()
            .any(|r| r.updates_to(sha256, now)))
    }
}

/// The GitLab ID of the runner `inventory` says command `command` added.
fn added_runner(inventory: Option<&Inventory>, command: &str) -> Option<u64> {
    inventory?
        .runners
        .iter()
        .find(|r| r.source == RunnerSource::Hub && r.command.as_deref() == Some(command))?
        .runner_id
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::UpdateProgress;

    use super::*;
    use crate::store::{RelayEnrollment, RelayWrite, TokenKind};

    fn relay(db: &Db) -> String {
        let (token, _) = db
            .create_token_for(TokenKind::Gitlab, Duration::from_secs(60), None, "u", 1)
            .unwrap();
        let RelayEnrollment::Enrolled { id } = db
            .enroll_relay(&token, &"ab".repeat(32), "relay-1", "peer p", 1)
            .unwrap()
        else {
            panic!("not enrolled");
        };
        id
    }

    fn update(sha256: &str) -> Operation {
        Operation::Update {
            version: "0.102.0".into(),
            sha256: sha256.into(),
            size: 1,
            signature: None,
        }
    }

    const DAY: Duration = Duration::from_secs(86_400);

    /// An update is issued once at a time, delivered until the relay settles it, its download
    /// allowed meanwhile, and audited at each step; one the relay no longer reports is failed
    /// when its next session starts.
    #[test]
    fn a_relay_update_is_issued_answered_and_settled() {
        let db = Db::open_memory().unwrap();
        let id = relay(&db);
        let sha = "cd".repeat(32);
        let command = db
            .issue_relay_command(&id, update(&sha), DAY, "alice", 10, |_| {})
            .unwrap();
        assert!(db.relay_updating_to(&id, &sha, 11).unwrap());
        assert!(!db.relay_updating_to(&id, &"ef".repeat(32), 11).unwrap());
        assert_eq!(
            db.pending_relay_commands(&id, 11).unwrap(),
            vec![command.clone()]
        );
        let err = db
            .issue_relay_command(&id, update(&sha), DAY, "alice", 12, |_| {})
            .unwrap_err();
        assert!(format!("{err:#}").contains("update in progress"), "{err:#}");

        let accepted = CommandAck {
            id: command.id.clone(),
            outcome: Outcome::Accepted,
        };
        assert!(db.record_relay_ack(&id, &accepted, 13).unwrap());
        assert!(
            !db.record_relay_ack(&id, &accepted, 14).unwrap(),
            "a duplicate"
        );
        // Accepted and reported under way: it blocks another.
        let report = Report {
            runners: vec![],
            update: Some(UpdateProgress {
                command: command.id.clone(),
                version: "0.102.0".into(),
                sha256: sha.clone(),
                phase: UpdatePhase::Draining,
                message: None,
            }),
        };
        db.record_relay(&id, RelayWrite::Report(report.clone()), 15)
            .unwrap();
        assert!(
            db.issue_relay_command(&id, update(&sha), DAY, "alice", 16, |_| {})
                .is_err()
        );
        // The session's first report names it: nothing to settle.
        let settle = |report: &Report, current| {
            db.settle_lost_relay_commands(&id, report, 18, |_| true, || current)
                .unwrap()
        };
        assert!(!settle(&report, true));
        // A superseded session's report settles nothing.
        assert!(!settle(&Report::default(), false));
        assert!(db.relay_updating_to(&id, &sha, 18).unwrap());
        // A restart lost it: it is failed, and its release no longer downloadable.
        assert!(settle(&Report::default(), true));
        let rows = db.relay_commands(&id).unwrap();
        assert!(matches!(rows[0].outcome, Some(Outcome::Failed { .. })));
        assert!(!db.relay_updating_to(&id, &sha, 19).unwrap());
        let done = CommandAck {
            id: command.id.clone(),
            outcome: Outcome::Done,
        };
        assert!(
            !db.record_relay_ack(&id, &done, 20).unwrap(),
            "after a final outcome"
        );
        let audit: Vec<String> = db
            .audit_page(Some(&id), None, 100)
            .unwrap()
            .into_iter()
            .map(|(_, a)| a.event)
            .collect();
        assert!(
            audit
                .iter()
                .any(|e| e.contains("alice issued update to vk-gitlab 0.102.0")),
            "{audit:?}"
        );
        assert!(
            audit.iter().any(|e| e.contains("no longer reports")),
            "{audit:?}"
        );

        // An unanswered command lapses at its expiry; removing the relay drops its commands.
        let lapsing = db
            .issue_relay_command(&id, update(&sha), DAY, "alice", 21, |_| {})
            .unwrap();
        assert!(db.relay_updating_to(&id, &sha, 22).unwrap());
        assert!(!db.relay_updating_to(&id, &sha, lapsing.expires_at).unwrap());
        assert!(db.remove_relay(&id, "alice", 23).unwrap());
        assert!(db.relay_commands(&id).unwrap().is_empty());
        let err = db
            .issue_relay_command(&id, update(&sha), DAY, "alice", 24, |_| {})
            .unwrap_err();
        assert!(err.is::<NotEnrolled>(), "{err:#}");
    }
}
