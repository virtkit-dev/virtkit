//! The commands the hub issues to GitLab relays — updates — and what each relay said they came
//! to, kept as a registry's are ([`super::registries`]): a command is sent once per session
//! until the relay answers it, and kept a month after it settles.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::gitlab::{Command, Operation, Report};
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

    /// [`RelayCommandRow::live`], and an update to release `sha256`.
    pub(super) fn updates_to(&self, sha256: &str, now: u64) -> bool {
        self.live(now)
            && matches!(&self.command.op, Operation::Update { sha256: s, .. } if s == sha256)
    }

    /// An update is under way if unaccepted and unexpired, or accepted and running in the
    /// relay's last report: one it no longer reports after a restart does not block another.
    fn updating(&self, report: Option<&Report>, now: u64) -> bool {
        if !self.live(now) {
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
        Operation::RemoveRunner { name, .. } => format!("remove runner {name}"),
    }
}

impl Db {
    /// Issue `op` to relay `id`, valid for `ttl`, audited as `actor`'s. Refused while another
    /// update is under way. Settled commands older than a month go in the same write.
    pub fn issue_relay_command(
        &self,
        id: &str,
        op: Operation,
        ttl: Duration,
        actor: &str,
        now: u64,
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
            op,
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
                if row.updating(relay.report.as_ref(), now) {
                    bail!(
                        "relay {id} has an update in progress (command {}); wait for it to end",
                        row.command.id
                    );
                }
            }
            let row = RelayCommandRow {
                command: command.clone(),
                issued_at: now,
                seq,
                outcome: None,
                outcome_at: None,
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

    /// Store and audit relay `id`'s outcome for command `ack.id`. `false` for a duplicate, an
    /// unknown command, or anything after a final outcome.
    pub fn record_relay_ack(&self, id: &str, ack: &CommandAck, now: u64) -> Result<bool> {
        let key = format!("{id}/{}", ack.id);
        let outcome = display_safe_outcome(ack.outcome.clone());
        let txn = self.db.begin_write().context("starting a write")?;
        let news = {
            let mut table = txn.open_table(RELAY_COMMANDS)?;
            let row = table
                .get(key.as_str())?
                .map(|g| decode::<RelayCommandRow>(g.value()))
                .transpose()?;
            match row {
                Some(mut row) if row.pending() && row.outcome.as_ref() != Some(&outcome) => {
                    row.outcome = Some(outcome.clone());
                    row.outcome_at = Some(now);
                    table.insert(key.as_str(), encode(&row)?.as_slice())?;
                    Some(row.command)
                }
                _ => None,
            }
        };
        let Some(command) = news else {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        };
        let event = format!(
            "command {} ({}): {}",
            command.id,
            relay_operation_name(&command.op),
            outcome_text(&outcome)
        );
        append_audit(&txn, Some(id), "relay", &event, now)?;
        txn.commit().context("recording an ack")?;
        Ok(true)
    }

    /// Fail relay `id`'s accepted updates absent from its session's first `report`: no final
    /// ack will come, and leaving them live would resend them every session and retain their
    /// releases. Later reports can arrive between acceptance and start, so only the first
    /// establishes that an update was lost. Check `current` inside the write to reject a
    /// superseded session's report. Return whether any update was settled.
    pub fn settle_unreported_relay_updates(
        &self,
        id: &str,
        report: &Report,
        now: u64,
        current: impl FnOnce() -> bool,
    ) -> Result<bool> {
        let named = report.update.as_ref().map(|u| u.command.as_str());
        let outcome = Outcome::Failed {
            message: "the relay no longer reports this update".to_string(),
        };
        let txn = self.db.begin_write().context("starting a write")?;
        if !current() {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        }
        let mut settled = Vec::new();
        {
            let mut table = txn.open_table(RELAY_COMMANDS)?;
            let (start, end) = command_range(id);
            for entry in table.range(start.as_str()..end.as_str())? {
                let (key, value) = entry?;
                let row = decode::<RelayCommandRow>(value.value())?;
                if row.outcome == Some(Outcome::Accepted) && named != Some(row.command.id.as_str())
                {
                    settled.push((key.value().to_string(), row));
                }
            }
            for (key, row) in &mut settled {
                row.outcome = Some(outcome.clone());
                row.outcome_at = Some(now);
                table.insert(key.as_str(), encode(row)?.as_slice())?;
            }
        }
        if settled.is_empty() {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        }
        for (_, row) in &settled {
            let event = format!(
                "command {} ({}): {}",
                row.command.id,
                relay_operation_name(&row.command.op),
                outcome_text(&outcome)
            );
            append_audit(&txn, Some(id), "hub", &event, now)?;
        }
        txn.commit().context("settling lost updates")?;
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
            .issue_relay_command(&id, update(&sha), DAY, "alice", 10)
            .unwrap();
        assert!(db.relay_updating_to(&id, &sha, 11).unwrap());
        assert!(!db.relay_updating_to(&id, &"ef".repeat(32), 11).unwrap());
        assert_eq!(
            db.pending_relay_commands(&id, 11).unwrap(),
            vec![command.clone()]
        );
        let err = db
            .issue_relay_command(&id, update(&sha), DAY, "alice", 12)
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
            db.issue_relay_command(&id, update(&sha), DAY, "alice", 16)
                .is_err()
        );
        // The session's first report names it: nothing to settle.
        let settle = |report: &Report, current| {
            db.settle_unreported_relay_updates(&id, report, 18, || current)
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
            .issue_relay_command(&id, update(&sha), DAY, "alice", 21)
            .unwrap();
        assert!(db.relay_updating_to(&id, &sha, 22).unwrap());
        assert!(!db.relay_updating_to(&id, &sha, lapsing.expires_at).unwrap());
        assert!(db.remove_relay(&id, "alice", 23).unwrap());
        assert!(db.relay_commands(&id).unwrap().is_empty());
        let err = db
            .issue_relay_command(&id, update(&sha), DAY, "alice", 24)
            .unwrap_err();
        assert!(err.is::<NotEnrolled>(), "{err:#}");
    }
}
