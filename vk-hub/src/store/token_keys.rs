//! The keys the hub signs registry tokens with: which exist, which one signs, and since when
//! the others no longer do. The private keys are files in the hub's `token-keys` directory;
//! a row names its file and carries the public half registries get.

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::token::TokenKey;

use super::{Db, append_audit, decode, encode};

/// Key: the key's ID. Value: JSON [`TokenKeyRow`].
pub(super) const TOKEN_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("token_keys");

/// A token-signing key as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenKeyRow {
    /// Its private key's file name in the `token-keys` directory.
    pub file: String,
    pub public: TokenKey,
    pub created_at: u64,
    /// Its place among the keys, oldest first, whatever the clock did.
    #[serde(default)]
    pub seq: u64,
    /// When a newer key took over signing; `None` for the newest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at: Option<u64>,
}

impl Db {
    /// Every token-signing key, oldest first.
    pub fn token_keys(&self) -> Result<Vec<TokenKeyRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(TOKEN_KEYS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            out.push(decode::<TokenKeyRow>(entry?.1.value())?);
        }
        out.sort_by_key(|r| r.seq);
        Ok(out)
    }

    /// Record `row` as the newest key, superseding the others, audited as `actor`'s.
    pub fn add_token_key(&self, row: &TokenKeyRow, actor: &str, now: u64) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(TOKEN_KEYS)?;
            let mut current = Vec::new();
            let mut seq = 0;
            for entry in table.iter()? {
                let (kid, value) = entry?;
                let old = decode::<TokenKeyRow>(value.value())?;
                seq = seq.max(old.seq.saturating_add(1));
                if old.superseded_at.is_none() {
                    current.push((kid.value().to_string(), old));
                }
            }
            for (kid, mut old) in current {
                old.superseded_at = Some(now);
                table.insert(kid.as_str(), encode(&old)?.as_slice())?;
            }
            let row = TokenKeyRow { seq, ..row.clone() };
            table.insert(row.public.kid.as_str(), encode(&row)?.as_slice())?;
        }
        let event = format!(
            "{actor} made token-signing key {} the signer",
            row.public.kid
        );
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("adding a token-signing key")?;
        Ok(())
    }

    /// Forget the keys superseded before `before`: no token they signed is live any more.
    /// Their rows, so the caller removes their files.
    pub fn retire_token_keys(&self, before: u64, now: u64) -> Result<Vec<TokenKeyRow>> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut retired = Vec::new();
        {
            let mut table = txn.open_table(TOKEN_KEYS)?;
            let mut gone = Vec::new();
            for entry in table.iter()? {
                let (kid, value) = entry?;
                let row = decode::<TokenKeyRow>(value.value())?;
                if row.superseded_at.is_some_and(|at| at < before) {
                    gone.push((kid.value().to_string(), row));
                }
            }
            for (kid, row) in gone {
                table.remove(kid.as_str())?;
                retired.push(row);
            }
        }
        if retired.is_empty() {
            txn.abort().context("dropping a write")?;
            return Ok(retired);
        }
        for row in &retired {
            let event = format!("token-signing key {} retired", row.public.kid);
            append_audit(&txn, None, "hub", &event, now)?;
        }
        txn.commit().context("retiring token-signing keys")?;
        Ok(retired)
    }
}
