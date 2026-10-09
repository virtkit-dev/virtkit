//! The CI tools definitions the hub holds ([`crate::tools`]), and which nodes are building one.

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::Operation;

use super::{COMMANDS, CommandRow, Db, append_audit, decode, encode, short};

/// Key: the definition's sha256, hex. Value: JSON [`ToolsRow`].
pub(super) const TOOLS: TableDefinition<&str, &[u8]> = TableDefinition::new("tools");

/// A tools definition the hub holds for its nodes to build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolsRow {
    /// The label the operator gave it.
    pub version: String,
    /// The tar's size in bytes.
    pub size: u64,
    /// How many files it holds.
    pub files: u32,
    pub added_at: u64,
    pub added_by: String,
}

/// A definition as `vk-hub tools list` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tools {
    pub sha256: String,
    #[serde(flatten)]
    pub row: ToolsRow,
}

impl CommandRow {
    /// [`CommandRow::live`], and a tools build from definition `sha256`: what keeps the
    /// definition on the hub, and what a node's download of it is allowed for.
    pub(super) fn builds_tools(&self, sha256: &str, now: u64) -> bool {
        self.live(now)
            && matches!(&self.command.op, Operation::Tools { sha256: s, .. } if s == sha256)
    }
}

impl Db {
    /// Record definition `sha256`, whose tar is already in place, audited as `actor`'s. One
    /// already recorded is refused: its version is what nodes were told.
    pub fn add_tools(&self, sha256: &str, row: &ToolsRow, actor: &str) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(TOOLS)?;
            if let Some(existing) = table.get(sha256)? {
                let existing = decode::<ToolsRow>(existing.value())?;
                bail!(
                    "tools {} are already held, as version {}",
                    short(sha256),
                    existing.version
                );
            }
            table.insert(sha256, encode(row)?.as_slice())?;
            let event = format!(
                "{actor} added tools {} as version {} ({} file{})",
                short(sha256),
                row.version,
                row.files,
                if row.files == 1 { "" } else { "s" }
            );
            append_audit(&txn, None, actor, &event, row.added_at)?;
        }
        txn.commit().context("recording tools")
    }

    pub fn tools(&self, sha256: &str) -> Result<Option<ToolsRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        txn.open_table(TOOLS)?
            .get(sha256)?
            .map(|g| decode::<ToolsRow>(g.value()))
            .transpose()
    }

    /// Every definition, newest first.
    pub fn tools_list(&self) -> Result<Vec<Tools>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(TOOLS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            out.push(Tools {
                sha256: key.value().to_string(),
                row: decode(value.value())?,
            });
        }
        out.sort_by(|a, b| (b.row.added_at, &b.sha256).cmp(&(a.row.added_at, &a.sha256)));
        Ok(out)
    }

    /// The one definition whose sha256 starts with `prefix`, of at least 8 lowercase hex
    /// digits.
    pub fn resolve_tools(&self, prefix: &str) -> Result<Tools> {
        if prefix.len() < 8
            || !prefix
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            bail!(
                "{}: name tools by their sha256, or at least its first 8 hex digits",
                vk_hub_proto::display_safe(prefix)
            );
        }
        let mut found = self
            .tools_list()?
            .into_iter()
            .filter(|t| t.sha256.starts_with(prefix));
        match (found.next(), found.next()) {
            (Some(t), None) => Ok(t),
            (None, _) => bail!("there are no tools {prefix}"),
            (Some(_), Some(_)) => {
                bail!("{prefix} names more than one definition; give more digits")
            }
        }
    }

    /// Forget definition `sha256`, audited as `actor`'s, unless a node still has to build it.
    /// `Ok(false)` when there was none.
    pub fn remove_tools(&self, sha256: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = {
            for entry in txn.open_table(COMMANDS)?.iter()? {
                let (key, value) = entry?;
                let row = decode::<CommandRow>(value.value())?;
                if row.builds_tools(sha256, now) {
                    let key = key.value();
                    bail!(
                        "node {} still has to build these tools (command {})",
                        key.split_once('/').map_or(key, |(node, _)| node),
                        row.command.id
                    );
                }
            }
            let removed = txn.open_table(TOOLS)?.remove(sha256)?.is_some();
            if removed {
                let event = format!("{actor} removed tools {}", short(sha256));
                append_audit(&txn, None, actor, &event, now)?;
            }
            removed
        };
        txn.commit().context("removing tools")?;
        Ok(removed)
    }

    /// Whether node `id` has a command still to finish that builds definition `sha256`: the
    /// one thing a node's download of it is allowed for.
    pub fn building_tools(&self, id: &str, sha256: &str, now: u64) -> Result<bool> {
        Ok(self
            .node_commands(id)?
            .iter()
            .any(|c| c.builds_tools(sha256, now)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Enrollment;

    fn row(version: &str) -> ToolsRow {
        ToolsRow {
            version: version.into(),
            size: 10240,
            files: 3,
            added_at: 5,
            added_by: "uid 0".into(),
        }
    }

    #[test]
    fn a_definition_is_kept_while_a_node_has_to_build_it_and_audited() {
        let db = Db::open_memory().unwrap();
        let sha = "ab".repeat(32);
        db.add_tools(&sha, &row("2026.10"), "uid 0").unwrap();
        let again = db.add_tools(&sha, &row("2026.11"), "uid 0").unwrap_err();
        assert!(format!("{again:#}").contains("already held"), "{again:#}");
        assert_eq!(db.resolve_tools("abababab").unwrap().row, row("2026.10"));
        assert!(db.resolve_tools("abab").is_err());
        assert!(db.resolve_tools("cdcdcdcd").is_err());

        let (token, _) = db
            .create_token(std::time::Duration::from_secs(60), "uid 0", 1)
            .unwrap();
        let Enrollment::Enrolled { node_id } = db
            .enroll(&token, &"11".repeat(32), "ci-1", "peer", 1)
            .unwrap()
        else {
            panic!("expected an enrollment");
        };
        let op = Operation::Tools {
            version: "2026.10".into(),
            sha256: sha.clone(),
            size: 10240,
        };
        let ttl = std::time::Duration::from_secs(100);
        let command = db.issue_command(&node_id, op, ttl, "uid 0", 10).unwrap();
        assert!(db.building_tools(&node_id, &sha, 20).unwrap());
        assert!(!db.building_tools(&node_id, &"cd".repeat(32), 20).unwrap());
        // Never taken, and past its expiry: nothing to download for.
        assert!(!db.building_tools(&node_id, &sha, 200).unwrap());
        let held = db.remove_tools(&sha, "uid 0", 20).unwrap_err();
        assert!(format!("{held:#}").contains(&command.id), "{held:#}");
        db.record_ack(
            &node_id,
            &vk_hub_proto::CommandAck {
                id: command.id.clone(),
                outcome: vk_hub_proto::Outcome::Done,
            },
            30,
        )
        .unwrap();
        assert!(!db.building_tools(&node_id, &sha, 40).unwrap());
        assert!(db.remove_tools(&sha, "uid 0", 40).unwrap());
        assert!(!db.remove_tools(&sha, "uid 0", 40).unwrap());
        let events: Vec<String> = db
            .audits(None, 50)
            .unwrap()
            .into_iter()
            .map(|a| a.event)
            .collect();
        for want in [
            "uid 0 added tools abababababab as version 2026.10 (3 files)",
            "uid 0 issued tools 2026.10 (abababababab)",
            "uid 0 removed tools abababababab",
        ] {
            assert!(
                events.iter().any(|e| e.starts_with(want)),
                "{want}: {events:?}"
            );
        }
    }
}
