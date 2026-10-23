//! The client instances using API keys: one row per key and instance, the instance as its
//! requests name it ([`vk_hub_proto::client::INSTANCE_HEADER`]) or empty for requests that
//! name none, with when it was first and last heard from and what its latest hello said
//! ([`ClientHello`]). Everything a client said is made display-safe before it is stored.

use std::collections::HashSet;

use anyhow::{Context, Result};
use redb::{Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::{
    ClientHello, ClientRunner, MAX_CLIENT_RUNNER_LABELS, MAX_CLIENT_RUNNERS,
};
use vk_hub_proto::display_safe;

use super::keys::{API_KEYS, KeyRow};
use super::{Db, decode, encode};

/// Key: `<key ID>/<instance>`. Value: JSON [`ClientRow`].
pub(super) const CLIENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("clients");

/// How long an instance unheard from is kept: a month.
const CLIENT_KEEP: u64 = 30 * 86_400;

/// The most instances kept per key; past it, the one heard from least recently goes, the
/// lowest instance name first among those heard from at the same second.
pub const MAX_INSTANCES_PER_KEY: usize = 32;

/// How stale a row may be before a contact that changes nothing else still rewrites it.
const CLIENT_REFRESH_SECS: u64 = 60;

/// How recently an instance must have been heard from to count as connected: three times
/// the minute between a client's hellos.
pub const CLIENT_ACTIVE_SECS: u64 = 180;

/// One instance of a key's client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRow {
    /// The key's name, for display.
    pub key_name: String,
    /// Empty for requests that named no instance, or a malformed one.
    pub instance: String,
    pub first_seen: u64,
    pub last_seen: u64,
    /// When its latest hello arrived; `None` for an instance that never sent one. The fields
    /// below are that hello's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hello_at: Option<u64>,
    #[serde(default)]
    pub program: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent: Option<u32>,
    #[serde(default)]
    pub runners: Vec<ClientRunner>,
}

impl ClientRow {
    /// Instance `instance` of key `key_name`, first heard from at `now`, with no hello.
    fn new(key_name: String, instance: &str, now: u64) -> Self {
        ClientRow {
            key_name,
            instance: instance.to_string(),
            first_seen: now,
            last_seen: now,
            hello_at: None,
            program: String::new(),
            version: String::new(),
            hostname: String::new(),
            concurrent: None,
            runners: Vec::new(),
        }
    }

    /// Take `hello`'s fields, made display-safe.
    fn say(&mut self, hello: &ClientHello, now: u64) {
        self.hello_at = Some(now);
        self.program = display_safe(&hello.program);
        self.version = display_safe(&hello.version);
        self.hostname = display_safe(&hello.hostname);
        self.concurrent = hello.concurrent;
        self.runners = hello
            .runners
            .iter()
            .take(MAX_CLIENT_RUNNERS)
            .map(|r| ClientRunner {
                name: display_safe(&r.name),
                url: display_safe(&clean_url(&r.url)),
                pool: display_safe(&r.pool),
                labels: r
                    .labels
                    .iter()
                    .take(MAX_CLIENT_RUNNER_LABELS)
                    .map(|l| display_safe(l))
                    .collect(),
                limit: r.limit,
            })
            .collect();
    }

    /// Whether `other` differs from this row in more than when either was last heard from.
    fn differs(&self, other: &ClientRow) -> bool {
        let heard = |r: &ClientRow| ClientRow {
            last_seen: 0,
            hello_at: r.hello_at.map(|_| 0),
            ..r.clone()
        };
        heard(self) != heard(other)
    }
}

/// `url` without its userinfo, query and fragment, or empty unless it starts with `http://`
/// or `https://`. Empty too when an `@` follows the host: a malformed URL's password may hold
/// a `/`, `?` or `#`, and there is no telling it from a path or query that holds an `@`.
fn clean_url(url: &str) -> String {
    let Some((scheme, rest)) = ["https://", "http://"]
        .into_iter()
        .find_map(|s| url.strip_prefix(s).map(|rest| (s, rest)))
    else {
        return String::new();
    };
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if tail.contains('@') {
        return String::new();
    }
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let path = tail.split(['?', '#']).next().unwrap_or_default();
    format!("{scheme}{host}{path}")
}

/// The range of key `key`'s rows.
fn key_range(key: &str) -> (String, String) {
    // `0` is the character after `/`.
    (format!("{key}/"), format!("{key}0"))
}

/// Remove key `key`'s rows in `txn`.
pub(super) fn remove_clients_of(txn: &redb::WriteTransaction, key: &str) -> Result<()> {
    let (start, end) = key_range(key);
    txn.open_table(CLIENTS)?
        .retain_in(start.as_str()..end.as_str(), |_, _| false)?;
    Ok(())
}

/// Write `row` as `id`, of key `key`, removing the key's instance heard from least recently
/// past [`MAX_INSTANCES_PER_KEY`]: by last contact, then by instance, the order
/// `crate::clients` evicts from memory in, so the two keep the same instances.
fn record(
    table: &mut redb::Table<'_, &str, &[u8]>,
    key: &str,
    id: &str,
    row: &ClientRow,
) -> Result<()> {
    table.insert(id, encode(row)?.as_slice())?;
    let (start, end) = key_range(key);
    let mut others = Vec::new();
    for entry in table.range(start.as_str()..end.as_str())? {
        let (other, value) = entry?;
        if other.value() != id {
            let seen = decode::<ClientRow>(value.value())?.last_seen;
            others.push((seen, other.value().to_string()));
        }
    }
    others.sort();
    let over = others
        .len()
        .saturating_add(1)
        .saturating_sub(MAX_INSTANCES_PER_KEY);
    for (_, other) in others.iter().take(over) {
        table.remove(other.as_str())?;
    }
    Ok(())
}

impl Db {
    /// Record that instance `instance` of key `key`, named `key_name`, was heard from at
    /// `now`, saying `hello` if it sent one, at `durability`. Past [`MAX_INSTANCES_PER_KEY`],
    /// the key's instance heard from least recently is removed. A contact that changes
    /// nothing but the last contact of a row written within [`CLIENT_REFRESH_SECS`] writes
    /// nothing. Whether anything was written.
    pub fn record_client(
        &self,
        key: &str,
        key_name: &str,
        instance: &str,
        hello: Option<&ClientHello>,
        now: u64,
        durability: Durability,
    ) -> Result<bool> {
        let id = format!("{key}/{instance}");
        // One transaction prevents a racing contact from overwriting the hello.
        let mut txn = self.db.begin_write().context("starting a write")?;
        txn.set_durability(durability)
            .context("setting a write's durability")?;
        let unchanged = {
            let mut table = txn.open_table(CLIENTS)?;
            let before = table
                .get(id.as_str())?
                .map(|g| decode::<ClientRow>(g.value()))
                .transpose()?;
            let mut row = before
                .clone()
                .unwrap_or_else(|| ClientRow::new(String::new(), instance, now));
            row.key_name = key_name.to_string();
            row.last_seen = row.last_seen.max(now);
            if let Some(hello) = hello {
                row.say(hello, now);
            }
            let unchanged = before.as_ref().is_some_and(|before| {
                !before.differs(&row) && now.saturating_sub(before.last_seen) < CLIENT_REFRESH_SECS
            });
            if !unchanged {
                record(&mut table, key, &id, &row)?;
            }
            unchanged
        };
        if unchanged {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        }
        txn.commit().context("recording a client instance")?;
        Ok(true)
    }

    /// Move each `(key, instance, at)`'s row's last contact up to `at`, in one write at
    /// `durability`. An instance with no row gets one, first heard from at `at`, unless its key is
    /// gone; past [`MAX_INSTANCES_PER_KEY`], the key's instance heard from least recently
    /// is removed.
    pub fn flush_clients(
        &self,
        seen: &[(String, String, u64)],
        durability: Durability,
    ) -> Result<()> {
        let mut txn = self.db.begin_write().context("starting a write")?;
        txn.set_durability(durability)
            .context("setting a write's durability")?;
        {
            let keys = txn.open_table(API_KEYS)?;
            let mut table = txn.open_table(CLIENTS)?;
            // Every row moved before any is created, so eviction weighs current contacts.
            let mut missing = Vec::new();
            for (key, instance, at) in seen {
                let id = format!("{key}/{instance}");
                let before = table
                    .get(id.as_str())?
                    .map(|g| decode::<ClientRow>(g.value()))
                    .transpose()?;
                match before {
                    Some(mut row) if *at > row.last_seen => {
                        row.last_seen = *at;
                        table.insert(id.as_str(), encode(&row)?.as_slice())?;
                    }
                    Some(_) => {}
                    None => missing.push((key, instance, at, id)),
                }
            }
            // Oldest first, so eviction among the newcomers does not depend on `seen`'s order.
            missing.sort_by(|a, b| (a.2, &a.3).cmp(&(b.2, &b.3)));
            for (key, instance, at, id) in missing {
                let Some(key_row) = keys
                    .get(key.as_str())?
                    .map(|g| decode::<KeyRow>(g.value()))
                    .transpose()?
                else {
                    continue;
                };
                let row = ClientRow::new(key_row.name, instance, *at);
                record(&mut table, key, &id, &row)?;
            }
        }
        txn.commit().context("recording client contacts")
    }

    /// Remove the instances unheard from for [`CLIENT_KEEP`], and those of keys the hub no
    /// longer holds. How many went.
    pub fn prune_clients(&self, now: u64) -> Result<usize> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut gone = 0usize;
        {
            let keys = txn.open_table(API_KEYS)?;
            let mut held = HashSet::new();
            for entry in keys.iter()? {
                held.insert(entry?.0.value().to_string());
            }
            txn.open_table(CLIENTS)?.retain(|id, value| {
                let key = id.split_once('/').map_or(id, |(key, _)| key);
                // A row that no longer decodes goes too: it shows nothing, and its
                // instance's next contact writes it afresh.
                let keep = held.contains(key)
                    && decode::<ClientRow>(value)
                        .is_ok_and(|r| now.saturating_sub(r.last_seen) < CLIENT_KEEP);
                if !keep {
                    gone = gone.saturating_add(1);
                }
                keep
            })?;
        }
        txn.commit().context("pruning client instances")?;
        Ok(gone)
    }

    /// Every instance, with its key's ID, by key and instance.
    pub fn clients(&self) -> Result<Vec<(String, ClientRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(CLIENTS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (id, value) = entry?;
            let key = id.value().split_once('/').map_or("", |(key, _)| key);
            out.push((key.to_string(), decode::<ClientRow>(value.value())?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::store::{KeyPolicy, Scope};

    const DAY: Duration = Duration::from_secs(86_400);

    fn key(db: &Db, name: &str, at: u64) -> String {
        let policy = KeyPolicy {
            scopes: vec![Scope::Jobs],
            pools: vec!["ci".into()],
            max_envelope: None,
            gitlab: None,
            projects: Vec::new(),
        };
        let (key, _) = db.create_api_key(name, &policy, DAY, "uid 0", at).unwrap();
        crate::store::token_key(&key)
    }

    fn hello(instance: &str) -> ClientHello {
        ClientHello {
            instance: instance.into(),
            program: "vk-gitlab".into(),
            version: "0.91.1".into(),
            hostname: "ci-1".into(),
            concurrent: Some(4),
            runners: vec![ClientRunner {
                name: "docker".into(),
                url: "https://gitlab.example.com".into(),
                pool: "ci".into(),
                labels: vec![],
                limit: None,
            }],
        }
    }

    #[test]
    fn a_hello_fills_the_row_that_a_request_made() {
        let db = Db::open_memory().unwrap();
        let k = key(&db, "gitlab", 100);
        assert!(
            db.record_client(&k, "gitlab", "s_1", None, 100, Durability::Immediate)
                .unwrap()
        );
        assert!(
            db.record_client(&k, "gitlab", "", None, 100, Durability::Immediate)
                .unwrap()
        );
        // Unchanged and fresh: nothing written. Changed, or stale: written.
        assert!(
            !db.record_client(&k, "gitlab", "s_1", None, 110, Durability::Immediate)
                .unwrap()
        );
        assert!(
            db.record_client(
                &k,
                "gitlab",
                "s_1",
                Some(&hello("s_1")),
                120,
                Durability::Immediate
            )
            .unwrap()
        );
        assert!(
            !db.record_client(
                &k,
                "gitlab",
                "s_1",
                Some(&hello("s_1")),
                130,
                Durability::Immediate
            )
            .unwrap()
        );
        assert!(
            db.record_client(
                &k,
                "gitlab",
                "s_1",
                Some(&hello("s_1")),
                200,
                Durability::Immediate
            )
            .unwrap()
        );
        // A request after the hello keeps what it said.
        assert!(
            db.record_client(&k, "gitlab", "s_1", None, 300, Durability::Immediate)
                .unwrap()
        );
        let rows = db.clients().unwrap();
        assert_eq!(rows.len(), 2);
        let (owner, row) = &rows[1];
        assert_eq!(owner, &k);
        assert_eq!(row.instance, "s_1");
        assert_eq!((row.first_seen, row.last_seen), (100, 300));
        assert_eq!(row.hello_at, Some(200));
        assert_eq!(row.hostname, "ci-1");
        assert_eq!(row.runners.len(), 1);
        assert_eq!(rows[0].1.instance, "");
        assert_eq!(rows[0].1.hello_at, None);
    }

    #[test]
    fn what_a_client_says_is_stored_display_safe() {
        let db = Db::open_memory().unwrap();
        let k = key(&db, "gitlab", 100);
        let mut h = hello("s_1");
        h.hostname = "ci\u{1b}[2J-1\u{202e}".into();
        h.runners[0].url = "https://user:pass@gitlab.example.com/g?private_token=t#f".into();
        h.runners[0].name = "x".repeat(1000);
        h.runners[0].labels = vec!["l".into(); 100];
        h.runners = std::iter::repeat_n(h.runners[0].clone(), 100).collect();
        db.record_client(&k, "gitlab", "s_1", Some(&h), 100, Durability::Immediate)
            .unwrap();
        let row = &db.clients().unwrap()[0].1;
        assert_eq!(row.hostname, "ci[2J-1");
        assert_eq!(row.runners.len(), vk_hub_proto::client::MAX_CLIENT_RUNNERS);
        assert_eq!(row.runners[0].name.len(), vk_hub_proto::MAX_DISPLAY);
        assert_eq!(row.runners[0].labels.len(), MAX_CLIENT_RUNNER_LABELS);
        assert_eq!(row.runners[0].url, "https://gitlab.example.com/g");
    }

    #[test]
    fn runner_urls_lose_their_credentials() {
        for (url, clean) in [
            ("https://gitlab.example.com", "https://gitlab.example.com"),
            ("https://u:p@h:8443/x?q=1#f", "https://h:8443/x"),
            ("https://u@h/x", "https://h/x"),
            // An `@` past the host could be a password's or a path's: dropped.
            ("https://u:p?x@h/y", ""),
            ("https://u:p#x@h", ""),
            ("https://u:pa/ss@h/x", ""),
            ("https://u:p\\x@h", ""),
            ("http://h/a@b", ""),
            ("https://h/x?a=u@b", ""),
            // Anything but http(s), from the first byte, is dropped.
            ("u:p@host/x", ""),
            (" https://u:p@h", ""),
            ("1x://u:p@h", ""),
            ("HTTPS://u:p@h", ""),
            ("gitlab.example.com", ""),
        ] {
            assert_eq!(clean_url(url), clean, "{url}");
        }
    }

    #[test]
    fn a_key_keeps_its_most_recent_instances() {
        let db = Db::open_memory().unwrap();
        let k = key(&db, "gitlab", 100);
        let other = key(&db, "other", 100);
        db.record_client(&other, "other", "s_0", None, 100, Durability::Immediate)
            .unwrap();
        for i in 0..MAX_INSTANCES_PER_KEY {
            let at = 100 + u64::try_from(i).unwrap();
            db.record_client(
                &k,
                "gitlab",
                &format!("s_{i}"),
                None,
                at,
                Durability::Immediate,
            )
            .unwrap();
        }
        // Heard from again, the first is no longer the least recent.
        db.flush_clients(&[(k.clone(), "s_0".into(), 1000)], Durability::Immediate)
            .unwrap();
        db.record_client(&k, "gitlab", "new", None, 1001, Durability::Immediate)
            .unwrap();
        let rows = db.clients().unwrap();
        let mine: Vec<&str> = rows
            .iter()
            .filter(|(owner, _)| *owner == k)
            .map(|(_, r)| r.instance.as_str())
            .collect();
        assert_eq!(mine.len(), MAX_INSTANCES_PER_KEY);
        assert!(mine.contains(&"s_0") && mine.contains(&"new") && !mine.contains(&"s_1"));
        assert!(rows.iter().any(|(owner, _)| *owner == other));
    }

    #[test]
    fn a_flush_moves_last_contact_and_recreates_missing_rows() {
        let db = Db::open_memory().unwrap();
        let k = key(&db, "gitlab", 100);
        db.record_client(
            &k,
            "gitlab",
            "s_1",
            Some(&hello("s_1")),
            100,
            Durability::Immediate,
        )
        .unwrap();
        // `s_2`'s row was never written, or the database evicted it; the gone key's
        // instance is not recreated.
        db.flush_clients(
            &[
                (k.clone(), "s_1".into(), 150),
                (k.clone(), "s_2".into(), 150),
                ("f".repeat(64), "s_1".into(), 150),
            ],
            Durability::Immediate,
        )
        .unwrap();
        db.flush_clients(&[(k.clone(), "s_1".into(), 120)], Durability::Immediate)
            .unwrap();
        let rows = db.clients().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].1.first_seen, rows[0].1.last_seen), (100, 150));
        assert_eq!(rows[0].1.hostname, "ci-1");
        assert_eq!(rows[1].1.instance, "s_2");
        assert_eq!(rows[1].1.key_name, "gitlab");
        assert_eq!((rows[1].1.first_seen, rows[1].1.last_seen), (150, 150));
    }

    #[test]
    fn a_flush_evicts_as_memory_does() {
        let db = Db::open_memory().unwrap();
        let k = key(&db, "gitlab", 100);
        // Full, with `b` and `a` tied for the least recent: `a` goes first.
        let mut seen: Vec<(String, String, u64)> = (2..MAX_INSTANCES_PER_KEY)
            .map(|i| (k.clone(), format!("s_{i:02}"), 200))
            .collect();
        seen.push((k.clone(), "b".into(), 100));
        seen.push((k.clone(), "a".into(), 100));
        db.flush_clients(&seen, Durability::Immediate).unwrap();
        db.flush_clients(&[(k.clone(), "new".into(), 300)], Durability::Immediate)
            .unwrap();
        let mine: Vec<String> = db
            .clients()
            .unwrap()
            .into_iter()
            .map(|(_, r)| r.instance)
            .collect();
        assert_eq!(mine.len(), MAX_INSTANCES_PER_KEY);
        assert!(!mine.contains(&"a".to_string()) && mine.contains(&"b".to_string()));
    }

    #[test]
    fn a_flush_moves_contacts_before_it_evicts() {
        let db = Db::open_memory().unwrap();
        let k = key(&db, "gitlab", 100);
        // Full, `lag` the least recent in the database but heard from since.
        db.record_client(
            &k,
            "gitlab",
            "lag",
            Some(&hello("lag")),
            100,
            Durability::Immediate,
        )
        .unwrap();
        for i in 1..MAX_INSTANCES_PER_KEY {
            let at = 200 + u64::try_from(i).unwrap();
            db.record_client(
                &k,
                "gitlab",
                &format!("s_{i:02}"),
                None,
                at,
                Durability::Immediate,
            )
            .unwrap();
        }
        db.flush_clients(
            &[
                (k.clone(), "new".into(), 400),
                (k.clone(), "lag".into(), 500),
            ],
            Durability::Immediate,
        )
        .unwrap();
        let rows = db.clients().unwrap();
        let find = |i: &str| rows.iter().find(|(_, r)| r.instance == i).map(|(_, r)| r);
        assert_eq!(rows.len(), MAX_INSTANCES_PER_KEY);
        let lag = find("lag").unwrap();
        assert_eq!((lag.last_seen, lag.hostname.as_str()), (500, "ci-1"));
        assert!(find("new").is_some() && find("s_01").is_none());
    }

    #[test]
    fn instances_go_when_stale_or_their_key_does() {
        let db = Db::open_memory().unwrap();
        let k = key(&db, "gitlab", 100);
        let gone = key(&db, "gone", 100);
        db.record_client(&k, "gitlab", "old", None, 100, Durability::Immediate)
            .unwrap();
        db.record_client(
            &k,
            "gitlab",
            "new",
            None,
            100 + CLIENT_KEEP,
            Durability::Immediate,
        )
        .unwrap();
        db.record_client(
            &gone,
            "gone",
            "s_1",
            None,
            100 + CLIENT_KEEP,
            Durability::Immediate,
        )
        .unwrap();
        // Revoked, its instances stay; removed, they go with it.
        db.revoke_api_key("gone", "uid 0", 200).unwrap();
        assert_eq!(db.prune_clients(100 + CLIENT_KEEP).unwrap(), 1);
        assert_eq!(db.clients().unwrap().len(), 2);
        db.revoke_api_key("gone", "uid 0", 300).unwrap();
        let rows = db.clients().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.instance, "new");
        // A key gone without its rows, as one removed by an older hub.
        db.record_client(
            "f".repeat(64).as_str(),
            "x",
            "s_1",
            None,
            100 + CLIENT_KEEP,
            Durability::Immediate,
        )
        .unwrap();
        assert_eq!(db.prune_clients(100 + CLIENT_KEEP).unwrap(), 1);
    }
}
