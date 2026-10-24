//! The keys the hub signs registry tokens with: which exist, which one signs, and since when
//! the others no longer do. The private keys are files in the hub's `token-keys` directory;
//! a row names its file and carries the public half registries get.

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::token::TokenKey;

use std::collections::BTreeMap;

use super::keys::{API_KEYS, KeyRow};
use super::namespaces::{NAMESPACES, NamespaceRow};
use super::registries::{REGISTRIES, RegistryRow};
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
    /// When the hub first found it superseded and signing for no registry: a registry that
    /// has not applied a newer key yet still gets tokens signed with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unused_since: Option<u64>,
}

/// The key to sign registry `row`'s tokens with: the newest whose generation it has applied.
/// This takes a registry that applied a generation to hold its keys; one that pins a fleet
/// root may refuse a key the root did not certify, which the trust model makes the hub check.
pub fn signing_key<'a>(keys: &'a [TokenKeyRow], row: &RegistryRow) -> Option<&'a TokenKeyRow> {
    let applied = row.applied();
    keys.iter().rev().find(|key| {
        row.key_generations
            .get(&key.public.kid)
            .is_some_and(|g| *g <= applied)
    })
}

/// What minting reads, in one snapshot: the registries that take tokens and are bound to a
/// URL, with their namespaces; the signing keys, oldest first; and, per jobs key bound to a
/// GitLab instance and still working, that instance's name. Registries bound to a URL that
/// take no tokens are kept by URL, to say why a job got none.
pub struct MintSnapshot {
    pub registries: Vec<(String, RegistryRow, Vec<NamespaceRow>)>,
    pub keys: Vec<TokenKeyRow>,
    pub bound: BTreeMap<String, String>,
    pub untokened: BTreeMap<String, String>,
}

impl Db {
    /// [`MintSnapshot`] as of one read, at `now`.
    pub fn mint_snapshot(&self, now: u64) -> Result<MintSnapshot> {
        let txn = self.db.begin_read().context("starting a read")?;
        let namespaces = txn.open_table(NAMESPACES)?;
        let mut registries = Vec::new();
        let mut untokened = BTreeMap::new();
        for entry in txn.open_table(REGISTRIES)?.iter()? {
            let (id, value) = entry?;
            let id = id.value().to_string();
            let row = decode::<RegistryRow>(value.value())?;
            let Some(url) = &row.url else {
                continue;
            };
            if !row.takes_tokens() {
                untokened.insert(url.clone(), id);
                continue;
            }
            let (start, end) = (format!("{id}/"), format!("{id}0"));
            let mut ns = Vec::new();
            for entry in namespaces.range(start.as_str()..end.as_str())? {
                ns.push(decode::<NamespaceRow>(entry?.1.value())?);
            }
            registries.push((id, row, ns));
        }
        let mut keys = Vec::new();
        for entry in txn.open_table(TOKEN_KEYS)?.iter()? {
            keys.push(decode::<TokenKeyRow>(entry?.1.value())?);
        }
        keys.sort_by_key(|r| r.seq);
        let mut bound = BTreeMap::new();
        for entry in txn.open_table(API_KEYS)?.iter()? {
            let (id, value) = entry?;
            let row = decode::<KeyRow>(value.value())?;
            if let Some(gitlab) = row
                .gitlab
                .filter(|_| row.revoked_at.is_none() && row.expires_at > now)
            {
                bound.insert(id.value().to_string(), gitlab);
            }
        }
        Ok(MintSnapshot {
            registries,
            keys,
            bound,
            untokened,
        })
    }

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

    /// Mark the superseded keys no registry that takes tokens signs with any more as unused
    /// since `now`, then forget those unused since before `before`: no token they signed is
    /// live any more. Their rows, so the caller removes their files.
    pub fn retire_token_keys(&self, before: u64, now: u64) -> Result<Vec<TokenKeyRow>> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut retired = Vec::new();
        let mut changed = false;
        {
            let mut keys = Vec::new();
            for entry in txn.open_table(TOKEN_KEYS)?.iter()? {
                keys.push(decode::<TokenKeyRow>(entry?.1.value())?);
            }
            keys.sort_by_key(|r| r.seq);
            let mut signing = std::collections::BTreeSet::new();
            for entry in txn.open_table(REGISTRIES)?.iter()? {
                let row = decode::<RegistryRow>(entry?.1.value())?;
                if let Some(key) = signing_key(&keys, &row).filter(|_| row.takes_tokens()) {
                    signing.insert(key.public.kid.clone());
                }
            }
            let mut table = txn.open_table(TOKEN_KEYS)?;
            for mut row in keys {
                let unused = row.superseded_at.is_some() && !signing.contains(&row.public.kid);
                match (unused, row.unused_since) {
                    (true, Some(at)) if at < before => {
                        table.remove(row.public.kid.as_str())?;
                        retired.push(row);
                    }
                    (true, None) | (false, Some(_)) => {
                        row.unused_since = unused.then_some(now);
                        table.insert(row.public.kid.as_str(), encode(&row)?.as_slice())?;
                    }
                    _ => continue,
                }
                changed = true;
            }
        }
        if !changed {
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
