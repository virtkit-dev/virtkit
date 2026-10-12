//! Registry enrollment, pinned keys, reports, desired state and commands.
//! Separate tables and token kinds prevent confusion with nodes. Audit rows are indexed
//! by registry ID, as node audit rows are by node ID.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::registry::{
    Command, DesiredState, GcPolicy, Heartbeat, Inventory, Operation, Report, Usage,
};
use vk_hub_proto::{CommandAck, Outcome, UpdatePhase};

use super::{
    COMMAND_KEEP, Db, NotEnrolled, TokenKind, append_audit, decode, display_safe_outcome, encode,
    outcome_text, spend_token, token_key,
};

/// Key: registry ID. Value: JSON [`RegistryRow`].
pub(super) const REGISTRIES: TableDefinition<&str, &[u8]> = TableDefinition::new("registries");

/// Key: `<registry ID>/<command ID>`. Value: JSON [`RegistryCommandRow`].
pub(super) const REGISTRY_COMMANDS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("registry_commands");

/// A registry as the hub knows it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryRow {
    /// Its pinned ed25519 key, hex.
    pub public_key: String,
    pub hostname: String,
    pub enrolled_at: u64,
    #[serde(default)]
    pub incarnation: Option<String>,
    #[serde(default)]
    pub protocol: Option<u32>,
    #[serde(default)]
    pub last_seen: Option<u64>,
    #[serde(default)]
    pub inventory: Option<Inventory>,
    #[serde(default)]
    pub heartbeat: Option<Heartbeat>,
    #[serde(default)]
    pub heartbeat_at: Option<u64>,
    #[serde(default)]
    pub usage: Option<Usage>,
    #[serde(default)]
    pub report: Option<Report>,
    /// What the hub wants of it; `None` until an operator sets anything.
    #[serde(default)]
    pub desired: Option<DesiredState>,
}

/// A command issued to a registry, and what the registry last said it came to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryCommandRow {
    pub command: Command,
    pub issued_at: u64,
    /// Issue order among the registry's commands, whatever the clock did: one more than the
    /// highest of its commands kept when this one was issued.
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub outcome: Option<Outcome>,
    #[serde(default)]
    pub outcome_at: Option<u64>,
}

impl RegistryCommandRow {
    /// Still to be delivered or finished.
    fn pending(&self) -> bool {
        matches!(self.outcome, None | Some(Outcome::Accepted))
    }

    /// Still to deliver or finish, and not past an expiry the registry never answered.
    fn live(&self, now: u64) -> bool {
        self.pending() && (self.outcome.is_some() || self.command.expires_at > now)
    }

    /// [`RegistryCommandRow::live`], and an update to release `sha256`.
    pub(super) fn updates_to(&self, sha256: &str, now: u64) -> bool {
        self.live(now)
            && matches!(&self.command.op, Operation::Update { sha256: s, .. } if s == sha256)
    }

    /// An update is under way if unaccepted and unexpired, or accepted and running in the
    /// registry's last report. An accepted update no longer reported running after a restart
    /// or lost tracking does not block another update.
    fn updating(&self, report: Option<&Report>, now: u64) -> bool {
        if !matches!(self.command.op, Operation::Update { .. }) || !self.live(now) {
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

/// What a registry's enrollment came to.
#[derive(Debug, PartialEq, Eq)]
pub enum RegistryEnrollment {
    Enrolled {
        id: String,
    },
    /// The registry already pinned to this key, after a lost enrollment answer.
    Reenrolled {
        id: String,
    },
    /// Unknown, spent, expired, or issued for a node.
    BadToken,
}

/// A change an operator makes to a registry's desired state: `None` leaves a field alone,
/// `Some(None)` gives read-only back to the registry's own config, and schedules no gc.
#[derive(Clone, Debug, Default)]
pub struct RegistryChange {
    pub read_only: Option<Option<bool>>,
    pub gc: Option<Option<GcPolicy>>,
}

/// What a registry's session writes.
pub enum RegistryWrite {
    Inventory(Inventory),
    Heartbeat(Heartbeat),
    Usage(Usage),
    Report(Report),
}

/// `(start, end)` of registry `id`'s commands' keys.
fn command_range(id: &str) -> (String, String) {
    (format!("{id}/"), format!("{id}0"))
}

/// A short name for an operation, for the audit log and listings.
pub fn operation_name(op: &Operation) -> String {
    match op {
        Operation::Gc { dry_run: true, .. } => "gc (dry run)".to_string(),
        Operation::Gc { .. } => "gc".to_string(),
        Operation::Update { version, .. } => format!("update to vk-registry {version}"),
    }
}

impl Db {
    /// Consume `token`, issued for a registry, and pin `public_key` (hex) as a new registry, or
    /// answer with the one it is already pinned to, audited as `actor`'s. The caller has
    /// checked the registry's signature.
    pub fn enroll_registry(
        &self,
        token: &str,
        public_key: &str,
        hostname: &str,
        actor: &str,
        now: u64,
    ) -> Result<RegistryEnrollment> {
        let key = token_key(token);
        if !self.token_live(&key, TokenKind::Registry, now)? {
            return Ok(RegistryEnrollment::BadToken);
        }
        let txn = self.db.begin_write().context("starting a write")?;
        let outcome = if spend_token(&txn, &key, TokenKind::Registry, now)? {
            let mut table = txn.open_table(REGISTRIES)?;
            let mut pinned = None;
            for entry in table.iter()? {
                let (id, value) = entry?;
                if decode::<RegistryRow>(value.value())?.public_key == public_key {
                    pinned = Some(id.value().to_string());
                    break;
                }
            }
            if let Some(id) = pinned {
                let event = format!("registry {id} enrolled again with its pinned key");
                append_audit(&txn, Some(&id), actor, &event, now)?;
                RegistryEnrollment::Reenrolled { id }
            } else {
                let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
                let row = RegistryRow {
                    public_key: public_key.to_string(),
                    hostname: vk_hub_proto::display_safe(hostname),
                    enrolled_at: now,
                    ..RegistryRow::default()
                };
                table.insert(id.as_str(), encode(&row)?.as_slice())?;
                let event = format!("registry {id} enrolled as {}", row.hostname);
                append_audit(&txn, Some(&id), actor, &event, now)?;
                RegistryEnrollment::Enrolled { id }
            }
        } else {
            RegistryEnrollment::BadToken
        };
        txn.commit().context("recording an enrollment")?;
        Ok(outcome)
    }

    pub fn registry(&self, id: &str) -> Result<Option<RegistryRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        txn.open_table(REGISTRIES)?
            .get(id)?
            .map(|g| decode(g.value()))
            .transpose()
    }

    /// Every registry, by ID.
    pub fn registries(&self) -> Result<Vec<(String, RegistryRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(REGISTRIES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (id, value) = entry?;
            out.push((id.value().to_string(), decode(value.value())?));
        }
        Ok(out)
    }

    /// Remove a registry, audited as `actor`'s: its key is no longer pinned and its commands
    /// go. `Ok(false)` when there was no such registry.
    pub fn remove_registry(&self, id: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = txn.open_table(REGISTRIES)?.remove(id)?.is_some();
        if removed {
            let (start, end) = command_range(id);
            txn.open_table(REGISTRY_COMMANDS)?
                .retain_in(start.as_str()..end.as_str(), |_, _| false)?;
            append_audit(
                &txn,
                Some(id),
                actor,
                &format!("{actor} removed registry {id}"),
                now,
            )?;
        }
        txn.commit().context("removing a registry")?;
        Ok(removed)
    }

    /// Record an authenticated session's `incarnation` and protocol `version` if `current`
    /// holds inside the write; whether it was recorded.
    pub fn record_registry_session(
        &self,
        id: &str,
        incarnation: &str,
        version: u32,
        now: u64,
        current: impl FnOnce() -> bool,
    ) -> Result<bool> {
        self.update_registry(now, id, Durability::Immediate, |row| {
            let current = current();
            if current {
                row.incarnation = Some(incarnation.to_string());
                row.protocol = Some(version);
                row.last_seen = Some(now);
            }
            Ok((current, Vec::new()))
        })
    }

    /// Store what a registry's session reported, which the session made display-safe on
    /// receipt. A heartbeat is made durable only as a node's is (see
    /// [`Db::heartbeat_syncs`]): losing the last few in a crash costs nothing.
    pub fn record_registry(&self, id: &str, write: RegistryWrite, now: u64) -> Result<()> {
        let durability = match write {
            RegistryWrite::Heartbeat(_) if !self.heartbeat_syncs(now) => Durability::None,
            _ => Durability::Immediate,
        };
        self.update_registry(now, id, durability, |row| {
            row.last_seen = Some(now);
            let mut events = Vec::new();
            match write {
                RegistryWrite::Inventory(inventory) => {
                    if let Some(old) = &row.inventory
                        && old.version != inventory.version
                    {
                        events.push((
                            "registry".to_string(),
                            format!(
                                "runs vk-registry {} (was {})",
                                inventory.version, old.version
                            ),
                        ));
                    }
                    row.hostname.clone_from(&inventory.hostname);
                    row.inventory = Some(inventory);
                }
                RegistryWrite::Heartbeat(heartbeat) => {
                    row.heartbeat = Some(heartbeat);
                    row.heartbeat_at = Some(now);
                }
                RegistryWrite::Usage(usage) => row.usage = Some(usage),
                RegistryWrite::Report(report) => row.report = Some(report),
            }
            Ok(((), events))
        })
    }

    /// Change registry `id`'s desired state, audited as `actor`'s; the new state, under a
    /// generation past both the hub's last and what the registry reported applying, or `None`
    /// when it was already so.
    pub fn set_registry_desired(
        &self,
        id: &str,
        change: RegistryChange,
        actor: &str,
        now: u64,
    ) -> Result<Option<DesiredState>> {
        self.update_registry(now, id, Durability::Immediate, |row| {
            let before = row.desired.clone().unwrap_or_default();
            let mut desired = before.clone();
            let mut said = Vec::new();
            if let Some(read_only) = change.read_only {
                desired.read_only = read_only;
                said.push(match read_only {
                    Some(true) => "read-only".to_string(),
                    Some(false) => "writable".to_string(),
                    None => "read-only as its config has it".to_string(),
                });
            }
            if let Some(gc) = change.gc {
                desired.gc = gc;
                said.push(match gc {
                    Some(gc) => format!(
                        "gc every {}s, retention {} days, grace {} days",
                        gc.every_secs, gc.retention_days, gc.grace_days
                    ),
                    None => "no scheduled gc".to_string(),
                });
            }
            if desired == before {
                return Ok((None, Vec::new()));
            }
            let applied = row.report.as_ref().and_then(|r| r.applied).unwrap_or(0);
            desired.generation = before.generation.max(applied).saturating_add(1);
            row.desired = Some(desired.clone());
            let event = format!(
                "{actor} set registry {id}: {} (generation {})",
                said.join(", "),
                desired.generation
            );
            Ok((Some(desired), vec![(actor.to_string(), event)]))
        })
    }

    /// Issue `op` to registry `id`, valid for `ttl`, audited as `actor`'s. Settled commands
    /// older than a month go in the same write.
    pub fn issue_registry_command(
        &self,
        id: &str,
        op: Operation,
        ttl: Duration,
        actor: &str,
        now: u64,
    ) -> Result<Command> {
        let txn = self.db.begin_write().context("starting a write")?;
        let Some(registry) = txn
            .open_table(REGISTRIES)?
            .get(id)?
            .map(|g| decode::<RegistryRow>(g.value()))
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
            let mut table = txn.open_table(REGISTRY_COMMANDS)?;
            let (start, end) = command_range(id);
            table.retain_in(start.as_str()..end.as_str(), |_, value| {
                decode::<RegistryCommandRow>(value)
                    .map_or(true, |r| !r.settled_before(now, COMMAND_KEEP))
            })?;
            let mut seq = 0;
            for entry in table.range(start.as_str()..end.as_str())? {
                let row = decode::<RegistryCommandRow>(entry?.1.value())?;
                seq = seq.max(row.seq.saturating_add(1));
                if matches!(command.op, Operation::Update { .. })
                    && row.updating(registry.report.as_ref(), now)
                {
                    bail!(
                        "registry {id} has an update in progress (command {}); wait for it \
                         to end",
                        row.command.id
                    );
                }
            }
            let row = RegistryCommandRow {
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
            "{actor} issued {} to registry {id} (command {})",
            operation_name(&command.op),
            command.id
        );
        append_audit(&txn, Some(id), actor, &event, now)?;
        txn.commit().context("issuing a command")?;
        Ok(command)
    }

    /// Registry `id`'s commands still to deliver or finish, in issue order.
    pub fn pending_registry_commands(&self, id: &str, now: u64) -> Result<Vec<Command>> {
        Ok(self
            .registry_commands(id)?
            .into_iter()
            .filter(|r| r.live(now))
            .map(|r| r.command)
            .collect())
    }

    /// Every command kept for registry `id`, oldest first.
    pub fn registry_commands(&self, id: &str) -> Result<Vec<RegistryCommandRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(REGISTRY_COMMANDS)?;
        let (start, end) = command_range(id);
        let mut rows = Vec::new();
        for entry in table.range(start.as_str()..end.as_str())? {
            rows.push(decode::<RegistryCommandRow>(entry?.1.value())?);
        }
        rows.sort_by_key(|r| (r.seq, r.issued_at));
        Ok(rows)
    }

    /// Store and audit registry `id`'s outcome for command `ack.id`. `false` for a duplicate,
    /// an unknown command, or anything after a final outcome.
    pub fn record_registry_ack(&self, id: &str, ack: &CommandAck, now: u64) -> Result<bool> {
        let key = format!("{id}/{}", ack.id);
        let outcome = display_safe_outcome(ack.outcome.clone());
        let txn = self.db.begin_write().context("starting a write")?;
        let news = {
            let mut table = txn.open_table(REGISTRY_COMMANDS)?;
            let row = table
                .get(key.as_str())?
                .map(|g| decode::<RegistryCommandRow>(g.value()))
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
            operation_name(&command.op),
            outcome_text(&outcome)
        );
        append_audit(&txn, Some(id), "registry", &event, now)?;
        txn.commit().context("recording an ack")?;
        Ok(true)
    }

    /// Settle as failed registry `id`'s accepted updates that `report`, the first of a
    /// session, does not name: the registry lost track of them, so no final ack will come, and
    /// left live they would go again every session and keep their release on the hub. Only a
    /// session's first report tells: a later one can be sent between an update's acceptance
    /// and its start. Whether any was settled.
    pub fn settle_unreported_updates(&self, id: &str, report: &Report, now: u64) -> Result<bool> {
        let named = report.update.as_ref().map(|u| u.command.as_str());
        let outcome = Outcome::Failed {
            message: "the registry no longer reports this update".to_string(),
        };
        let txn = self.db.begin_write().context("starting a write")?;
        let mut settled = Vec::new();
        {
            let mut table = txn.open_table(REGISTRY_COMMANDS)?;
            let (start, end) = command_range(id);
            for entry in table.range(start.as_str()..end.as_str())? {
                let (key, value) = entry?;
                let row = decode::<RegistryCommandRow>(value.value())?;
                if row.outcome == Some(Outcome::Accepted)
                    && matches!(row.command.op, Operation::Update { .. })
                    && named != Some(row.command.id.as_str())
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
                operation_name(&row.command.op),
                outcome_text(&outcome)
            );
            append_audit(&txn, Some(id), "hub", &event, now)?;
        }
        txn.commit().context("settling lost updates")?;
        Ok(true)
    }

    /// Whether registry `id` has a live update to release `sha256`: what its download is
    /// allowed for.
    pub fn registry_updating_to(&self, id: &str, sha256: &str, now: u64) -> Result<bool> {
        Ok(self
            .registry_commands(id)?
            .iter()
            .any(|r| r.updates_to(sha256, now)))
    }

    /// Read-modify-write registry `id`'s row and append the audit pairs `change` returns, in
    /// one transaction at `durability`. [`NotEnrolled`] when the registry was removed.
    fn update_registry<R>(
        &self,
        now: u64,
        id: &str,
        durability: Durability,
        change: impl FnOnce(&mut RegistryRow) -> Result<(R, Vec<(String, String)>)>,
    ) -> Result<R> {
        let mut txn = self.db.begin_write().context("starting a write")?;
        let out = {
            let mut table = txn.open_table(REGISTRIES)?;
            let mut row = match table.get(id)? {
                Some(g) => decode::<RegistryRow>(g.value())?,
                None => return Err(NotEnrolled(id.to_string()).into()),
            };
            let (out, events) = change(&mut row)?;
            table.insert(id, encode(&row)?.as_slice())?;
            for (actor, event) in events {
                append_audit(&txn, Some(id), &actor, &event, now)?;
            }
            out
        };
        txn.set_durability(durability)
            .context("setting a write's durability")?;
        txn.commit().context("updating a registry")?;
        Ok(out)
    }
}
