//! API keys: the credentials automation — `vk-gitlab` first — holds for the hub's client API.
//! A key is `vkk_` and 32 random bytes in hex, shown once at creation and stored only as its
//! `sha256`, as `vk-registry` stores its keys; a row records the key's name, its scopes, the
//! pools it may place work in and the largest envelope it may ask for, when it expires and
//! whether it was revoked. Checking a key is a read: a guess costs no write.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::Placement;
use vk_hub_proto::job::Envelope;

use super::{Db, append_audit, decode, encode, token_key};

/// Key: `sha256(key)`, hex. Value: JSON [`KeyRow`].
pub(super) const API_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("api_keys");

/// Every API key starts with this, so one pasted into the wrong place is recognizable.
const KEY_PREFIX: &str = "vkk_";

/// How many characters of a key's random half a listing shows to tell keys apart: 32 of its
/// 256 bits, which leaves guessing the rest no easier.
const SHOWN_PREFIX: usize = 8;

/// The longest-lived key: a year, then a new one.
pub const MAX_KEY_TTL: Duration = Duration::from_secs(365 * 86_400);

/// The most keys kept, revoked and expired ones included; past it, creating one is refused
/// until the oldest that no longer work are removed with a revoke.
const MAX_KEYS: usize = 256;

/// The longest a key's, pool's or label's name may be.
pub const MAX_NAME: usize = 64;

/// The pool a key may name to place work in any pool.
pub const ANY_POOL: &str = "*";

/// What a key may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// The whole client API: capacity, reservations, jobs.
    Jobs,
    /// Only `POST /v1/capacity`: watching the fleet's room, holding nothing.
    Capacity,
}

impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Scope::Jobs => "jobs",
            Scope::Capacity => "capacity",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "jobs" => Some(Scope::Jobs),
            "capacity" => Some(Scope::Capacity),
            _ => None,
        }
    }
}

/// A key as stored, and as `vk-hub keys list` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRow {
    pub name: String,
    /// The first characters of the key's random half.
    pub prefix: String,
    pub scopes: Vec<Scope>,
    /// The pools it may place work in; [`ANY_POOL`] for any.
    pub pools: Vec<String>,
    /// The largest envelope it may ask for; `None` for no limit.
    #[serde(default)]
    pub max_envelope: Option<Envelope>,
    pub created_at: u64,
    pub created_by: String,
    pub expires_at: u64,
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

impl KeyRow {
    /// Neither revoked nor expired at `now`.
    pub fn live(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// The policy a key's holder asked for a key with.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPolicy {
    pub scopes: Vec<Scope>,
    pub pools: Vec<String>,
    pub max_envelope: Option<Envelope>,
}

/// Who a client request authenticated as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiPrincipal {
    /// `sha256(key)`, hex: what the key's jobs and reservations are recorded under, so a new
    /// key of the same name does not inherit them.
    pub id: String,
    pub row: KeyRow,
}

impl ApiPrincipal {
    /// The principal as the audit log names it.
    pub fn actor(&self) -> String {
        format!("key {}", self.row.name)
    }

    pub fn has(&self, scope: Scope) -> bool {
        self.row.scopes.contains(&scope)
    }

    /// Why `placement` is outside this key's policy, if it is.
    pub fn refuses(&self, placement: &Placement) -> Option<String> {
        if !self
            .row
            .pools
            .iter()
            .any(|p| p == ANY_POOL || *p == placement.pool)
        {
            return Some(format!(
                "this key may not place work in pool {:?}",
                placement.pool
            ));
        }
        if let Some(max) = self.row.max_envelope
            && !placement.envelope.fits_in(max)
        {
            return Some(format!(
                "the envelope is larger than this key's limit of {}",
                envelope_text(max)
            ));
        }
        None
    }
}

/// An envelope as the CLI and the audit log print it. A key's limit left unset is the
/// largest value, printed `any`.
pub fn envelope_text(e: Envelope) -> String {
    let mem = match e.mem_mib {
        u64::MAX => "any memory".to_string(),
        n => format!("{n} MiB"),
    };
    let cpus = match e.cpus {
        u32::MAX => "any CPUs".to_string(),
        n => format!("{n} CPUs"),
    };
    let disk = match e.disk_bytes {
        u64::MAX => "any disk".to_string(),
        n => format!("{} GiB disk", n >> 30),
    };
    format!("{mem}, {cpus}, {disk}")
}

/// Whether `s` may name a key, a pool or a label: 1 to [`MAX_NAME`] of ASCII letters, digits,
/// `.`, `_` and `-`, starting with a letter or digit.
pub fn valid_name(s: &str) -> bool {
    s.len() <= MAX_NAME
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Db {
    /// Issue an API key named `name` with `policy`, valid for `ttl`, audited as `actor`'s.
    /// Returns the key — shown once, stored only as its hash — and its row. A name is unique
    /// among the keys that still work.
    pub fn create_api_key(
        &self,
        name: &str,
        policy: &KeyPolicy,
        ttl: Duration,
        actor: &str,
        now: u64,
    ) -> Result<(String, KeyRow)> {
        if !valid_name(name) {
            bail!(
                "{name:?}: a key's name is 1 to {MAX_NAME} letters, digits, '.', '_' or '-', \
                 starting with a letter or digit"
            );
        }
        if ttl.is_zero() || ttl > MAX_KEY_TTL {
            bail!(
                "a key's lifetime must be between 1s and {} days",
                MAX_KEY_TTL.as_secs() / 86_400
            );
        }
        if policy.scopes.is_empty() {
            bail!("a key needs at least one scope");
        }
        if policy.pools.is_empty() {
            bail!("a key needs at least one pool, or {ANY_POOL} for any");
        }
        if let Some(bad) = policy
            .pools
            .iter()
            .find(|p| *p != ANY_POOL && !valid_name(p))
        {
            bail!("{bad:?} is not a pool's name");
        }
        let mut scopes = policy.scopes.clone();
        scopes.sort();
        scopes.dedup();
        let mut pools = policy.pools.clone();
        pools.sort();
        pools.dedup();
        let secret = crate::random_hex(32)?;
        let key = format!("{KEY_PREFIX}{secret}");
        let row = KeyRow {
            name: name.to_string(),
            prefix: secret.chars().take(SHOWN_PREFIX).collect(),
            scopes,
            pools,
            max_envelope: policy.max_envelope,
            created_at: now,
            created_by: actor.to_string(),
            expires_at: now.saturating_add(ttl.as_secs()),
            revoked_at: None,
        };
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(API_KEYS)?;
            let mut count = 0usize;
            for entry in table.iter()? {
                let (_, value) = entry?;
                let other = decode::<KeyRow>(value.value())?;
                if other.name == name && other.live(now) {
                    bail!("a key named {name:?} already works; revoke it first");
                }
                count = count.saturating_add(1);
            }
            if count >= MAX_KEYS {
                bail!("the hub holds {MAX_KEYS} keys already");
            }
            table.insert(token_key(&key).as_str(), encode(&row)?.as_slice())?;
        }
        let scopes: Vec<&str> = row.scopes.iter().map(|s| s.name()).collect();
        let limit = row
            .max_envelope
            .map_or_else(|| "no limit".to_string(), envelope_text);
        let event = format!(
            "{actor} created API key {name} ({}; pools {}; envelope {limit}), valid for {}s",
            scopes.join(", "),
            row.pools.join(", "),
            ttl.as_secs()
        );
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("storing an API key")?;
        Ok((key, row))
    }

    /// The principal `key` authenticates, or `None` for one that is unknown, revoked or
    /// expired: a caller tells them apart no more than it tells a guess from them.
    pub fn api_key(&self, key: &str, now: u64) -> Result<Option<ApiPrincipal>> {
        // Bounded before it is hashed: anything longer is no key of ours.
        if !key.starts_with(KEY_PREFIX) || key.len() > KEY_PREFIX.len() + 64 {
            return Ok(None);
        }
        let id = token_key(key);
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(API_KEYS)?;
        let Some(row) = table
            .get(id.as_str())?
            .map(|g| decode::<KeyRow>(g.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        Ok(row.live(now).then_some(ApiPrincipal { id, row }))
    }

    /// Every key, revoked and expired ones included, oldest first.
    pub fn api_keys(&self) -> Result<Vec<KeyRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(API_KEYS)?;
        let mut keys = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            keys.push(decode::<KeyRow>(value.value())?);
        }
        keys.sort_by(|a, b| (a.created_at, &a.name).cmp(&(b.created_at, &b.name)));
        Ok(keys)
    }

    /// Revoke the working key named `name`, audited as `actor`'s; with none working, remove
    /// the keys of that name that no longer work, so their names and slots are free. Whether
    /// anything changed.
    pub fn revoke_api_key(&self, name: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let event = {
            let mut table = txn.open_table(API_KEYS)?;
            let mut live = None;
            let mut dead = Vec::new();
            for entry in table.iter()? {
                let (key, value) = entry?;
                let row = decode::<KeyRow>(value.value())?;
                if row.name != name {
                    continue;
                }
                if row.live(now) {
                    live = Some((key.value().to_string(), row));
                } else {
                    dead.push(key.value().to_string());
                }
            }
            if let Some((id, mut row)) = live {
                row.revoked_at = Some(now);
                table.insert(id.as_str(), encode(&row)?.as_slice())?;
                Some(format!("{actor} revoked API key {name}"))
            } else if dead.is_empty() {
                None
            } else {
                for id in &dead {
                    table.remove(id.as_str())?;
                }
                Some(format!(
                    "{actor} removed {} revoked or expired API key(s) named {name}",
                    dead.len()
                ))
            }
        };
        let Some(event) = event else {
            return Ok(false);
        };
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("revoking an API key")?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    fn policy() -> KeyPolicy {
        KeyPolicy {
            scopes: vec![Scope::Jobs],
            pools: vec!["ci".into()],
            max_envelope: Some(Envelope {
                mem_mib: 16384,
                cpus: 8,
                disk_bytes: 16 << 30,
            }),
        }
    }

    #[test]
    fn a_key_works_until_it_expires_or_is_revoked() {
        let db = Db::open_memory().unwrap();
        let (key, row) = db
            .create_api_key("gitlab", &policy(), DAY, "uid 0", 100)
            .unwrap();
        assert!(key.starts_with(KEY_PREFIX));
        assert!(key.contains(&row.prefix));
        let found = db.api_key(&key, 101).unwrap().unwrap();
        assert_eq!(found.row.name, "gitlab");
        assert_eq!(found.actor(), "key gitlab");
        // Expired, then a guess and the bare prefix.
        assert!(db.api_key(&key, 100 + DAY.as_secs()).unwrap().is_none());
        assert!(db.api_key("vkk_00", 101).unwrap().is_none());
        assert!(db.api_key("", 101).unwrap().is_none());
        // A second working key of the same name is refused; a revoked one frees it.
        assert!(
            db.create_api_key("gitlab", &policy(), DAY, "uid 0", 102)
                .is_err()
        );
        assert!(db.revoke_api_key("gitlab", "uid 0", 103).unwrap());
        assert!(db.api_key(&key, 104).unwrap().is_none());
        let (again, _) = db
            .create_api_key("gitlab", &policy(), DAY, "uid 0", 105)
            .unwrap();
        assert!(db.api_key(&again, 106).unwrap().is_some());
        assert_eq!(db.api_keys().unwrap().len(), 2);
        // Revoking the working one, then removing both that no longer work.
        assert!(db.revoke_api_key("gitlab", "uid 0", 107).unwrap());
        assert!(db.revoke_api_key("gitlab", "uid 0", 108).unwrap());
        assert!(db.api_keys().unwrap().is_empty());
        assert!(!db.revoke_api_key("gitlab", "uid 0", 109).unwrap());
        let audit: Vec<String> = db
            .audits(None, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            audit[0].starts_with("uid 0 created API key gitlab (jobs; pools ci; envelope"),
            "{audit:?}"
        );
        assert_eq!(audit[1], "uid 0 revoked API key gitlab");
        assert_eq!(
            audit[4],
            "uid 0 removed 2 revoked or expired API key(s) named gitlab"
        );
    }

    #[test]
    fn a_key_is_held_to_its_pools_and_envelope() {
        let db = Db::open_memory().unwrap();
        let (key, _) = db
            .create_api_key("gitlab", &policy(), DAY, "uid 0", 100)
            .unwrap();
        let principal = db.api_key(&key, 100).unwrap().unwrap();
        let mut placement = Placement {
            pool: "ci".into(),
            labels: vec![],
            envelope: Envelope {
                mem_mib: 8192,
                cpus: 4,
                disk_bytes: 8 << 30,
            },
        };
        assert_eq!(principal.refuses(&placement), None);
        placement.envelope.cpus = 9;
        assert!(principal.refuses(&placement).unwrap().contains("limit"));
        placement.envelope.cpus = 4;
        placement.pool = "prod".into();
        assert!(principal.refuses(&placement).unwrap().contains("pool"));
        assert!(principal.has(Scope::Jobs) && !principal.has(Scope::Capacity));
    }

    #[test]
    fn bad_names_lifetimes_and_policies_are_refused() {
        let db = Db::open_memory().unwrap();
        for name in ["", "-x", "a b", &"a".repeat(MAX_NAME + 1)] {
            assert!(
                db.create_api_key(name, &policy(), DAY, "uid 0", 1).is_err(),
                "{name:?}"
            );
        }
        assert!(
            db.create_api_key("k", &policy(), Duration::ZERO, "uid 0", 1)
                .is_err()
        );
        assert!(
            db.create_api_key("k", &policy(), MAX_KEY_TTL + DAY, "uid 0", 1)
                .is_err()
        );
        let mut p = policy();
        p.pools = vec!["bad pool".into()];
        assert!(db.create_api_key("k", &p, DAY, "uid 0", 1).is_err());
        p.pools = vec![];
        assert!(db.create_api_key("k", &p, DAY, "uid 0", 1).is_err());
        let mut p = policy();
        p.scopes.clear();
        assert!(db.create_api_key("k", &p, DAY, "uid 0", 1).is_err());
        assert!(db.api_keys().unwrap().is_empty());
    }
}
