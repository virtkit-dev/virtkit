//! API keys: the credentials automation — `vk-gitlab` first — holds for the hub's client API.
//! A key is `vkk_` and 32 random bytes in hex, shown once at creation and stored only as its
//! `sha256`, as `vk-registry` stores its keys; a row records the key's name, its scopes, the
//! pools it may place work in and the largest envelope it may ask for, when it expires and
//! whether it was revoked. Checking a key is a read: a guess costs no write.

use std::time::Duration;

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::Placement;
use vk_hub_proto::job::Envelope;

use super::clients::remove_clients_of;
use super::gitlabs::{GITLABS, ProjectCeiling};
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
    /// The client API but job submission, which only an enrolled relay makes: capacity,
    /// reservations, existing jobs.
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
    /// The GitLab instance whose jobs it submits, by the hub's name for it: its jobs must come
    /// from that instance, and only a bound key's jobs get registry tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitlab: Option<String>,
    /// The projects of [`KeyRow::gitlab`] it may submit jobs of; empty for the whole instance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<ProjectCeiling>,
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
    #[serde(default)]
    pub gitlab: Option<String>,
    #[serde(default)]
    pub projects: Vec<ProjectCeiling>,
}

impl KeyPolicy {
    /// Build a policy from limits in bytes and CPUs. With no limits, omit the envelope;
    /// otherwise, use the type's maximum for each unset limit.
    pub fn with_limits(
        scopes: Vec<Scope>,
        pools: Vec<String>,
        max_mem: Option<u64>,
        max_cpus: Option<u32>,
        max_disk: Option<u64>,
    ) -> Self {
        let max_envelope =
            (max_mem.is_some() || max_cpus.is_some() || max_disk.is_some()).then(|| Envelope {
                mem_mib: max_mem.map_or(u64::MAX, |b| b >> 20),
                cpus: max_cpus.unwrap_or(u32::MAX),
                disk_bytes: max_disk.unwrap_or(u64::MAX),
            });
        KeyPolicy {
            scopes,
            pools,
            max_envelope,
            gitlab: None,
            projects: Vec::new(),
        }
    }
}

/// Revoke a name's working key, or remove its inactive keys when none works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOp {
    Revoke,
    Remove,
}

impl KeyOp {
    pub fn name(self) -> &'static str {
        match self {
            KeyOp::Revoke => "revoke",
            KeyOp::Remove => "remove",
        }
    }
}

/// [`Db::revoke_api_keys_as_seen`] refused because the keys or action changed.
#[derive(Debug)]
pub struct KeysChanged;

impl std::fmt::Display for KeysChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the keys of that name changed")
    }
}

impl std::error::Error for KeysChanged {}

/// A refusal from [`Db::create_api_key`]: invalid name, lifetime or policy, a name taken
/// by a live key, or no room for another key. Its message can be shown to the user.
#[derive(Debug)]
pub struct KeyRefused(pub String);

impl std::fmt::Display for KeyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyRefused {}

fn refused(why: impl Into<String>) -> anyhow::Error {
    KeyRefused(why.into()).into()
}

/// Who a client request authenticated as: an API key, or an enrolled GitLab relay signing
/// its requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiPrincipal {
    /// What its jobs and reservations are recorded under: a key's `sha256(key)`, hex, so a new
    /// key of the same name does not inherit them; a relay's ID, shorter, so neither is taken
    /// for the other.
    pub id: String,
    /// Its name, for display: a key's name, a relay's hostname.
    pub name: String,
    /// The client instance the request named in
    /// [`INSTANCE_HEADER`](vk_hub_proto::client::INSTANCE_HEADER); `None` when it named
    /// none, or a malformed one, and for a relay.
    pub instance: Option<String>,
    pub kind: PrincipalKind,
}

/// What authenticated a client request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    Key(Box<KeyRow>),
    /// An enrolled relay: trusted as a node is, with no policy of its own.
    Relay,
}

impl ApiPrincipal {
    /// The principal as the audit log names it.
    pub fn actor(&self) -> String {
        match self.kind {
            PrincipalKind::Key(_) => format!("key {}", self.name),
            PrincipalKind::Relay => format!("relay {}", self.id),
        }
    }

    /// Whether it is a relay.
    pub fn is_relay(&self) -> bool {
        self.kind == PrincipalKind::Relay
    }

    pub fn has(&self, scope: Scope) -> bool {
        match &self.kind {
            PrincipalKind::Key(row) => row.scopes.contains(&scope),
            PrincipalKind::Relay => true,
        }
    }

    /// Why `placement` is outside this key's policy, if it is.
    pub fn refuses(&self, placement: &Placement) -> Option<String> {
        let PrincipalKind::Key(row) = &self.kind else {
            return None;
        };
        if !row
            .pools
            .iter()
            .any(|p| p == ANY_POOL || *p == placement.pool)
        {
            return Some(format!(
                "this key may not place work in pool {:?}",
                placement.pool
            ));
        }
        if let Some(max) = row.max_envelope
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
            return Err(refused(format!(
                "{name:?}: a key's name is 1 to {MAX_NAME} letters, digits, '.', '_' or '-', \
                 starting with a letter or digit"
            )));
        }
        if ttl.is_zero() || ttl > MAX_KEY_TTL {
            return Err(refused(format!(
                "a key's lifetime must be between 1s and {} days",
                MAX_KEY_TTL.as_secs() / 86_400
            )));
        }
        if policy.scopes.is_empty() {
            return Err(refused("a key needs at least one scope"));
        }
        if policy.pools.is_empty() {
            return Err(refused(format!(
                "a key needs at least one pool, or {ANY_POOL} for any"
            )));
        }
        if let Some(bad) = policy
            .pools
            .iter()
            .find(|p| *p != ANY_POOL && !valid_name(p))
        {
            return Err(refused(format!("{bad:?} is not a pool's name")));
        }
        if policy.gitlab.is_none() && !policy.projects.is_empty() {
            return Err(refused(
                "a key's projects are those of the GitLab instance it is bound to",
            ));
        }
        if let Some(dup) = policy
            .projects
            .iter()
            .enumerate()
            .find(|(i, p)| policy.projects.iter().skip(i + 1).any(|q| q.id == p.id))
        {
            return Err(refused(format!("project {} is listed twice", dup.1.id)));
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
            gitlab: policy.gitlab.clone(),
            projects: policy.projects.clone(),
        };
        let txn = self.db.begin_write().context("starting a write")?;
        if let Some(gitlab) = &row.gitlab
            && txn.open_table(GITLABS)?.get(gitlab.as_str())?.is_none()
        {
            return Err(refused(format!("there is no GitLab instance {gitlab}")));
        }
        {
            let mut table = txn.open_table(API_KEYS)?;
            let mut count = 0usize;
            for entry in table.iter()? {
                let (_, value) = entry?;
                let other = decode::<KeyRow>(value.value())?;
                if other.name == name && other.live(now) {
                    return Err(refused(format!(
                        "a key named {name:?} already works; revoke it first"
                    )));
                }
                count = count.saturating_add(1);
            }
            if count >= MAX_KEYS {
                return Err(refused(format!("the hub holds {MAX_KEYS} keys already")));
            }
            table.insert(token_key(&key).as_str(), encode(&row)?.as_slice())?;
        }
        let scopes: Vec<&str> = row.scopes.iter().map(|s| s.name()).collect();
        let limit = row
            .max_envelope
            .map_or_else(|| "no limit".to_string(), envelope_text);
        let bound = match &row.gitlab {
            None => String::new(),
            Some(g) if row.projects.is_empty() => format!("; GitLab {g}"),
            Some(g) => format!(
                "; GitLab {g}, projects {}",
                row.projects
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let event = format!(
            "{actor} created API key {name} ({}; pools {}; envelope {limit}{bound}), valid for \
             {}s",
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
        Ok(row.live(now).then(|| ApiPrincipal {
            id,
            name: row.name.clone(),
            instance: None,
            kind: PrincipalKind::Key(Box::new(row)),
        }))
    }

    /// Every key, revoked and expired ones included, oldest first.
    pub fn api_keys(&self) -> Result<Vec<KeyRow>> {
        Ok(self
            .api_keys_with_ids()?
            .into_iter()
            .map(|(_, row)| row)
            .collect())
    }

    /// [`api_keys`](Self::api_keys) with each key's [`ApiPrincipal::id`].
    pub fn api_keys_with_ids(&self) -> Result<Vec<(String, KeyRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(API_KEYS)?;
        let mut keys = Vec::new();
        for entry in table.iter()? {
            let (id, value) = entry?;
            keys.push((id.value().to_string(), decode::<KeyRow>(value.value())?));
        }
        keys.sort_by(|(_, a), (_, b)| (a.created_at, &a.name).cmp(&(b.created_at, &b.name)));
        Ok(keys)
    }

    /// Revoke the working key named `name`, audited as `actor`'s; with none working, remove
    /// the keys of that name that no longer work, and their client instances, so their names
    /// and slots are free. Whether anything changed.
    pub fn revoke_api_key(&self, name: &str, actor: &str, now: u64) -> Result<bool> {
        self.revoke_keys(name, None, actor, now)
    }

    /// [`Db::revoke_api_key`], provided it would still `op` exactly the keys `ids` — checked in
    /// the same transaction, so what was confirmed is what changes. [`KeysChanged`] if not;
    /// `false` with no key of that name left.
    pub fn revoke_api_keys_as_seen(
        &self,
        name: &str,
        op: KeyOp,
        ids: &[String],
        actor: &str,
        now: u64,
    ) -> Result<bool> {
        self.revoke_keys(name, Some((op, ids)), actor, now)
    }

    fn revoke_keys(
        &self,
        name: &str,
        seen: Option<(KeyOp, &[String])>,
        actor: &str,
        now: u64,
    ) -> Result<bool> {
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
            if let Some((op, ids)) = seen {
                let (want, mut found) = match &live {
                    Some((id, _)) => (KeyOp::Revoke, vec![id.as_str()]),
                    None => (KeyOp::Remove, dead.iter().map(String::as_str).collect()),
                };
                let mut asked: Vec<&str> = ids.iter().map(String::as_str).collect();
                found.sort_unstable();
                asked.sort_unstable();
                if !found.is_empty() && (want != op || found != asked) {
                    return Err(KeysChanged.into());
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
                    remove_clients_of(&txn, id)?;
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
            gitlab: None,
            projects: Vec::new(),
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
        assert_eq!(found.name, "gitlab");
        assert_eq!(found.actor(), "key gitlab");
        // Expired, then a guess and the bare prefix.
        assert!(db.api_key(&key, 100 + DAY.as_secs()).unwrap().is_none());
        assert!(db.api_key("vkk_00", 101).unwrap().is_none());
        assert!(db.api_key("", 101).unwrap().is_none());
        // A second working key of the same name is refused; a revoked one frees it.
        let taken = db
            .create_api_key("gitlab", &policy(), DAY, "uid 0", 102)
            .unwrap_err();
        assert!(taken.is::<KeyRefused>(), "{taken:#}");
        assert!(db.revoke_api_key("gitlab", "uid 0", 103).unwrap());
        assert!(db.api_key(&key, 104).unwrap().is_none());
        let (again, _) = db
            .create_api_key("gitlab", &policy(), DAY, "uid 0", 105)
            .unwrap();
        assert!(db.api_key(&again, 106).unwrap().is_some());
        assert_eq!(db.api_keys().unwrap().len(), 2);
        let ids: Vec<String> = db
            .api_keys_with_ids()
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(ids, [token_key(&key), token_key(&again)]);
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

    /// Revoking or removing keys as seen acts only when the keys of that name are still the
    /// ones seen and would still be treated so; anything else is refused and changes nothing.
    #[test]
    fn keys_revoked_as_seen_must_be_as_seen() {
        let db = Db::open_memory().unwrap();
        let (old, _) = db
            .create_api_key("gitlab", &policy(), DAY, "uid 0", 100)
            .unwrap();
        let old = [token_key(&old)];
        let as_seen =
            |op, ids: &[String], now| db.revoke_api_keys_as_seen("gitlab", op, ids, "uid 0", now);
        let changed = |op, ids: &[String]| as_seen(op, ids, 200).unwrap_err().is::<KeysChanged>();
        assert!(changed(KeyOp::Remove, &old));
        assert!(changed(KeyOp::Revoke, &[]));
        assert!(changed(KeyOp::Revoke, &["ab".repeat(32)]));
        assert!(as_seen(KeyOp::Revoke, &old, 102).unwrap());
        // Revoked and replaced since seen: the new key is not the one seen.
        let (new, _) = db
            .create_api_key("gitlab", &policy(), DAY, "uid 0", 103)
            .unwrap();
        assert!(changed(KeyOp::Revoke, &old));
        // A working key under the name: none is removed.
        assert!(changed(KeyOp::Remove, &old));
        assert!(db.api_key(&new, 104).unwrap().is_some());
        // Another key no longer working since seen: removing only the first is refused.
        db.revoke_api_key("gitlab", "uid 0", 105).unwrap();
        assert!(changed(KeyOp::Remove, &old));
        assert_eq!(db.api_keys().unwrap().len(), 2);
        let both = [token_key(&new), old[0].clone()];
        assert!(as_seen(KeyOp::Remove, &both, 106).unwrap());
        assert!(db.api_keys().unwrap().is_empty());
        assert!(!as_seen(KeyOp::Remove, &both, 107).unwrap());
    }

    #[test]
    fn a_policy_s_unset_limits_are_unbounded() {
        let p = |mem, cpus, disk| KeyPolicy::with_limits(vec![], vec![], mem, cpus, disk);
        assert_eq!(p(None, None, None).max_envelope, None);
        assert_eq!(
            p(Some(16 << 30), None, Some(1 << 30)).max_envelope,
            Some(Envelope {
                mem_mib: 16 << 10,
                cpus: u32::MAX,
                disk_bytes: 1 << 30,
            })
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
        let is_refused = |name: &str, p: &KeyPolicy, ttl: Duration| {
            db.create_api_key(name, p, ttl, "uid 0", 1)
                .unwrap_err()
                .is::<KeyRefused>()
        };
        for name in ["", "-x", "a b", &"a".repeat(MAX_NAME + 1)] {
            assert!(is_refused(name, &policy(), DAY), "{name:?}");
        }
        assert!(is_refused("k", &policy(), Duration::ZERO));
        assert!(is_refused("k", &policy(), MAX_KEY_TTL + DAY));
        let mut p = policy();
        p.pools = vec!["bad pool".into()];
        assert!(is_refused("k", &p, DAY));
        p.pools = vec![];
        assert!(is_refused("k", &p, DAY));
        let mut p = policy();
        p.scopes.clear();
        assert!(is_refused("k", &p, DAY));
        assert!(db.api_keys().unwrap().is_empty());
    }

    #[test]
    fn a_full_hub_refuses_another_key() {
        let db = Db::open_memory().unwrap();
        for i in 0..MAX_KEYS {
            db.create_api_key(&format!("k{i}"), &policy(), DAY, "uid 0", 1)
                .unwrap();
        }
        let full = db
            .create_api_key("one-more", &policy(), DAY, "uid 0", 1)
            .unwrap_err();
        assert!(full.is::<KeyRefused>(), "{full:#}");
    }
}
