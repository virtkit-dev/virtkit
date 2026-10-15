//! The client instances using the hub's API keys (`crate::store`'s `clients` table): which
//! were heard from when, and what each said in its hello.
//!
//! Every client API request past its key's check and the connection cap is a contact, one
//! then refused for its scope (403) or path (404) included — but a hello without a
//! well-formed [`INSTANCE_HEADER`](vk_hub_proto::client::INSTANCE_HEADER) is a contact of the
//! instance its body names alone, not of the key's unknown instance. Contacts come at request
//! rate, so a request only updates memory, and [`drive`] writes every contact changed since
//! its last pass every [`CLIENT_FLUSH_SECS`], durably and in one transaction, recreating any
//! row the database lacks. An instance's first contact since the hub started also writes
//! every pending contact at once, in the background and at [`Durability::None`] — as
//! `crate::store` writes heartbeats — while its key holds fewer than
//! [`MAX_INSTANCES_PER_KEY`] instances in memory; past that it waits for the flush. A crash
//! loses up to a minute of last contacts. [`views`] is what the clients page shows of them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use redb::Durability;
use vk_hub_proto::client::ClientHello;

use crate::jobs::Work;
use crate::server::Hub;
use crate::store::{ApiPrincipal, ClientRow, KeyRow, MAX_INSTANCES_PER_KEY};

/// How often the contacts noted in memory are written.
pub const CLIENT_FLUSH_SECS: u64 = 60;

/// How often stale instances are pruned from the database and memory.
const PRUNE_EVERY: Duration = Duration::from_secs(3600);

/// How long memory keeps an instance unheard from. One heard from again after that is
/// recorded afresh.
const FORGET_SECS: u64 = 3600;

/// The contacts of each instance, by key ID, then instance.
#[derive(Default)]
pub struct Instances {
    seen: Mutex<HashMap<String, HashMap<String, Seen>>>,
}

struct Seen {
    at: u64,
    /// The latest durable contact; `at > flushed` means a flush is pending.
    flushed: u64,
    /// Written at all, and the clients page woken for it.
    shown: bool,
}

impl Instances {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, HashMap<String, Seen>>> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Note a contact from `instance` of key `key` at `now`. Whether to write it at once: it
    /// is the first since the hub started, and the key held fewer than
    /// [`MAX_INSTANCES_PER_KEY`]. Past that many, the key's instance heard from least
    /// recently is forgotten, the lowest name first among ties, as the database evicts.
    pub(crate) fn note(&self, key: &str, instance: &str, now: u64) -> bool {
        let mut seen = self.lock();
        if let Some(s) = seen.get_mut(key).and_then(|m| m.get_mut(instance)) {
            s.at = s.at.max(now);
            return false;
        }
        let mine = seen.entry(key.to_string()).or_default();
        let room = mine.len() < MAX_INSTANCES_PER_KEY;
        if !room {
            // A contact of the evicted instance awaiting the flush goes with it; the
            // database evicts that instance too once the newcomer is written.
            let oldest = mine
                .iter()
                .min_by(|a, b| (a.1.at, a.0).cmp(&(b.1.at, b.0)))
                .map(|(i, _)| i.clone());
            if let Some(oldest) = oldest {
                mine.remove(&oldest);
            }
        }
        mine.insert(
            instance.to_string(),
            Seen {
                at: now,
                flushed: 0,
                shown: false,
            },
        );
        room
    }

    /// Note that the database durably holds `instance` of key `key` as heard from at `at`.
    fn flushed(&self, key: &str, instance: &str, at: u64) {
        if let Some(s) = self.lock().get_mut(key).and_then(|m| m.get_mut(instance)) {
            s.flushed = s.flushed.max(at);
        }
    }

    /// Mark `instance` of key `key` as written, durably or not. Return true on the first
    /// write since it was noted in memory, so the clients page can be notified.
    fn shown(&self, key: &str, instance: &str) -> bool {
        let mut seen = self.lock();
        let Some(s) = seen.get_mut(key).and_then(|m| m.get_mut(instance)) else {
            return false;
        };
        !std::mem::replace(&mut s.shown, true)
    }

    /// The contacts awaiting the flush.
    fn unflushed(&self) -> Vec<(String, String, u64)> {
        self.lock()
            .iter()
            .flat_map(|(k, m)| {
                m.iter()
                    .filter(|(_, s)| s.at > s.flushed)
                    .map(|(i, s)| (k.clone(), i.clone(), s.at))
            })
            .collect()
    }

    /// Last contact times in memory, indexed by key ID and instance.
    fn heard(&self) -> HashMap<(String, String), u64> {
        self.lock()
            .iter()
            .flat_map(|(k, m)| m.iter().map(|(i, s)| ((k.clone(), i.clone()), s.at)))
            .collect()
    }

    /// Forget the instances unheard from since `before` that await no flush.
    fn forget(&self, before: u64) {
        let mut seen = self.lock();
        for m in seen.values_mut() {
            m.retain(|_, s| s.at >= before || s.at > s.flushed);
        }
        seen.retain(|_, m| !m.is_empty());
    }
}

/// The instance `principal` named, or the empty name of requests naming none.
fn instance_of(principal: &ApiPrincipal) -> &str {
    principal.instance.as_deref().unwrap_or_default()
}

/// Note that `principal` made a request at `now`.
pub fn seen(hub: &Arc<Hub>, principal: &ApiPrincipal, now: u64) {
    if !hub
        .instances
        .note(&principal.id, instance_of(principal), now)
    {
        return;
    }
    // Write all pending contacts so database eviction uses memory's timestamps. Keep them
    // pending: the flush makes this write durable or retries it.
    let hub = hub.clone();
    tokio::spawn(async move {
        if let Err(e) = write(&hub, Durability::None).await {
            eprintln!("vk-hub: recording a client instance: {e:#}");
        }
    });
}

/// Record `hello`, from `principal`, under the instance it names.
pub async fn hello(hub: &Hub, principal: &ApiPrincipal, hello: ClientHello) -> Result<()> {
    let now = crate::now_secs();
    let instance = hello.instance.clone();
    hub.instances.note(&principal.id, &instance, now);
    // The database evicts by the contacts it holds: brought up to memory's, it evicts the
    // instance memory just did.
    flush(hub).await?;
    let (db, key, name, i) = (
        hub.db.clone(),
        principal.id.clone(),
        principal.row.name.clone(),
        instance.clone(),
    );
    let written = tokio::task::spawn_blocking(move || {
        db.record_client(&key, &name, &i, Some(&hello), now, Durability::Immediate)
    })
    .await
    .context("recording a client's hello")??;
    if written {
        hub.instances.flushed(&principal.id, &instance, now);
        hub.instances.shown(&principal.id, &instance);
        hub.clients_changed();
    }
    Ok(())
}

/// Write the contacts noted in memory every [`CLIENT_FLUSH_SECS`], and prune instances
/// unheard from for long, or whose key is gone, at once and every [`PRUNE_EVERY`].
pub async fn drive(hub: Arc<Hub>) {
    let mut sync = tokio::time::interval(Duration::from_secs(CLIENT_FLUSH_SECS));
    sync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pruned: Option<tokio::time::Instant> = None;
    loop {
        sync.tick().await;
        if let Err(e) = flush(&hub).await {
            eprintln!("vk-hub: recording client contacts: {e:#}");
        }
        if pruned.is_none_or(|p| p.elapsed() >= PRUNE_EVERY) {
            pruned = Some(tokio::time::Instant::now());
            let now = crate::now_secs();
            hub.instances.forget(now.saturating_sub(FORGET_SECS));
            let db = hub.db.clone();
            match tokio::task::spawn_blocking(move || db.prune_clients(now)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(_)) => hub.clients_changed(),
                Ok(Err(e)) => eprintln!("vk-hub: pruning client instances: {e:#}"),
                Err(e) => eprintln!("vk-hub: pruning client instances: {e}"),
            }
        }
    }
}

/// Write every contact awaiting the flush, durably, in one transaction.
pub(crate) async fn flush(hub: &Hub) -> Result<()> {
    write(hub, Durability::Immediate).await
}

/// Write every contact awaiting the flush, in one transaction at `durability`. Only a durable
/// write settles them. Wake the clients page for an instance written for the first time.
async fn write(hub: &Hub, durability: Durability) -> Result<()> {
    let contacts = hub.instances.unflushed();
    if contacts.is_empty() {
        return Ok(());
    }
    let db = hub.db.clone();
    let written = contacts.clone();
    tokio::task::spawn_blocking(move || db.flush_clients(&written, durability))
        .await
        .context("recording client contacts")??;
    let durable = matches!(durability, Durability::Immediate);
    let mut first = false;
    for (key, instance, at) in &contacts {
        if durable {
            hub.instances.flushed(key, instance, *at);
        }
        first |= hub.instances.shown(key, instance);
    }
    // An instance is first written by [`seen`]'s write while its key has room, by the flush
    // past that: whichever comes first wakes the page, the other finds it shown.
    if first {
        hub.clients_changed();
    }
    Ok(())
}

/// An API key and the client instances using it, as the clients page shows them.
#[derive(Debug)]
pub struct KeyView {
    /// Its ID ([`ApiPrincipal::id`]).
    pub id: String,
    pub row: KeyRow,
    /// Its instances, the most recently heard from first.
    pub instances: Vec<InstanceView>,
    /// How many of its jobs the history holds.
    pub jobs: u64,
}

impl KeyView {
    /// When any of its instances was last heard from.
    pub fn last_seen(&self) -> Option<u64> {
        (self.instances.iter().map(|i| i.row.last_seen))
            .filter(|&t| t > 0)
            .max()
    }
}

/// One instance of a key's client, and what it holds.
#[derive(Debug)]
pub struct InstanceView {
    /// As recorded, its last contact the later of the row's and memory's; for an instance the
    /// database holds no row of, empty but for that contact, 0 when memory holds none either.
    pub row: ClientRow,
    pub work: Work,
}

/// Every API key, oldest first, with its instances and how many of its jobs the history
/// holds. Reads the database: call off the runtime.
pub fn views(hub: &Hub) -> Result<Vec<KeyView>> {
    let keys = hub.db.api_keys_with_ids()?;
    let clients = hub.db.clients()?;
    let counts = hub.db.job_counts_by_key()?;
    let heard = hub.instances.heard();
    let mut work = crate::jobs::client_work(hub);
    let mut views: Vec<KeyView> = keys
        .into_iter()
        .map(|(id, row)| KeyView {
            jobs: counts.get(&id).copied().unwrap_or_default(),
            id,
            row,
            instances: Vec::new(),
        })
        .collect();
    let at: HashMap<String, usize> = (views.iter().enumerate())
        .map(|(i, v)| (v.id.clone(), i))
        .collect();
    for (key, mut row) in clients {
        // A removed key's, until pruned.
        let Some(view) = at.get(&key).and_then(|&i| views.get_mut(i)) else {
            continue;
        };
        let id = (key, row.instance.clone());
        if let Some(&t) = heard.get(&id) {
            row.last_seen = row.last_seen.max(t);
        }
        let work = work.remove(&id).unwrap_or_default();
        view.instances.push(InstanceView { row, work });
    }
    // Instances the database holds no row of, yet or any longer, shown for what they hold:
    // one awaiting the flush, or one evicted or pruned with its jobs still live.
    for ((key, instance), work) in work {
        let Some(view) = at.get(&key).and_then(|&i| views.get_mut(i)) else {
            continue;
        };
        let last_seen = heard.get(&(key, instance.clone())).copied().unwrap_or(0);
        let row = ClientRow {
            key_name: view.row.name.clone(),
            instance,
            first_seen: last_seen,
            last_seen,
            hello_at: None,
            program: String::new(),
            version: String::new(),
            hostname: String::new(),
            concurrent: None,
            runners: Vec::new(),
        };
        view.instances.push(InstanceView { row, work });
    }
    for view in &mut views {
        view.instances.sort_by(|a, b| {
            (b.row.last_seen, &a.row.instance).cmp(&(a.row.last_seen, &b.row.instance))
        });
    }
    Ok(views)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Db, KeyPolicy, Scope, token_key};

    #[test]
    fn a_key_holds_a_bounded_set_of_instances() {
        let instances = Instances::default();
        assert!(instances.note("k", "a", 100));
        for i in 1..MAX_INSTANCES_PER_KEY {
            assert!(instances.note("k", &format!("i{i:02}"), 100 + i as u64));
        }
        assert!(instances.note("other", "a", 100));
        // Full: the least recent, `a` at 100, goes for the newcomer, written by the flush
        // alone.
        assert!(!instances.note("k", "new", 500));
        assert!(!instances.note("k", "a", 501));
        let unflushed = instances.unflushed();
        assert_eq!(unflushed.len(), MAX_INSTANCES_PER_KEY + 1);
        assert!(!unflushed.iter().any(|c| c.1 == "i01"));
        instances.flushed("k", "new", 500);
        assert_eq!(instances.unflushed().len(), unflushed.len() - 1);
        // Only what the flush wrote is forgotten.
        for (k, i, at) in instances.unflushed() {
            if (k.as_str(), i.as_str()) != ("k", "a") {
                instances.flushed(&k, &i, at);
            }
        }
        instances.forget(1000);
        let left: Vec<String> = instances.unflushed().into_iter().map(|c| c.1).collect();
        assert_eq!(left, ["a"]);
        assert_eq!(instances.lock().len(), 1);
    }

    #[test]
    fn a_contact_refreshes_its_instance() {
        let instances = Instances::default();
        assert!(instances.note("k", "a", 100));
        instances.flushed("k", "a", 100);
        assert!(instances.unflushed().is_empty());
        assert!(!instances.note("k", "a", 150));
        // An older contact, come late, moves nothing.
        assert!(!instances.note("k", "a", 120));
        assert_eq!(instances.unflushed(), [("k".into(), "a".into(), 150)]);
    }

    #[test]
    fn ties_are_evicted_by_name() {
        let instances = Instances::default();
        for i in 0..MAX_INSTANCES_PER_KEY {
            instances.note("k", &format!("i{i:02}"), 100);
        }
        instances.note("k", "new", 100);
        let gone: Vec<String> = instances.unflushed().into_iter().map(|c| c.1).collect();
        assert!(!gone.contains(&"i00".to_string()) && gone.contains(&"i01".to_string()));
    }

    fn policy() -> KeyPolicy {
        KeyPolicy {
            scopes: vec![Scope::Jobs],
            pools: vec!["ci".into()],
            max_envelope: None,
        }
    }

    /// A hub holding API key `gitlab`, and its ID.
    fn hub_with_key() -> (Arc<Hub>, String, String) {
        let db = Arc::new(Db::open_memory().unwrap());
        let ttl = Duration::from_secs(3600);
        let (key, _) =
            (db.create_api_key("gitlab", &policy(), ttl, "uid 0", crate::now_secs())).unwrap();
        let id = token_key(&key);
        (Arc::new(Hub::new(db, None)), key, id)
    }

    /// An instance's last contact is the later of its row's and memory's; a removed key's
    /// instances are left out; an instance the database has no row of shows for what it
    /// holds; and the latest heard from come first, then by name.
    #[test]
    fn views_merge_memory_with_the_database() {
        let (hub, _, id) = hub_with_key();
        for (instance, at) in [("old", 150), ("b", 200), ("a", 200)] {
            let written =
                hub.db
                    .record_client(&id, "gitlab", instance, None, at, Durability::Immediate);
            assert!(written.unwrap());
        }
        let removed = "f".repeat(64);
        let written = hub
            .db
            .record_client(&removed, "gone", "x", None, 300, Durability::Immediate);
        assert!(written.unwrap());
        hub.instances.note(&id, "old", 400);
        hub.instances.note(&id, "a", 100);
        // Awaiting the flush, and gone from memory and the database: rows for what they hold.
        hub.instances.note(&id, "new", 250);
        crate::jobs::testing::offer_for(&hub, &id, Some("new"));
        crate::jobs::testing::offer_for(&hub, &id, Some("lost"));
        crate::jobs::testing::offer_for(&hub, &removed, Some("x"));

        let views = views(&hub).unwrap();
        assert_eq!(views.len(), 1);
        let shown: Vec<(&str, u64, usize)> = (views[0].instances.iter())
            .map(|i| {
                (
                    i.row.instance.as_str(),
                    i.row.last_seen,
                    i.work.reservations,
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                ("old", 400, 0),
                ("new", 250, 1),
                ("a", 200, 0),
                ("b", 200, 0),
                ("lost", 0, 1)
            ]
        );
        assert_eq!(views[0].instances[1].row.key_name, "gitlab");
        assert_eq!(views[0].last_seen(), Some(400));
    }

    /// The clients page is woken by a key created or revoked through `vk-hub keys`, an
    /// instance's first contact, and instances pruned; not again by the flush of an instance
    /// already shown.
    #[tokio::test]
    async fn the_clients_page_is_woken_by_what_it_shows() {
        let (hub, key, id) = hub_with_key();
        let mut changes = hub.subscribe_clients();
        let woken = |changes: &mut tokio::sync::watch::Receiver<u64>| {
            let woken = changes.has_changed().unwrap();
            changes.mark_unchanged();
            woken
        };
        let call = |call: serde_json::Value| {
            let body = serde_json::json!({"v": 1, "call": call});
            crate::admin::dispatch(&serde_json::to_vec(&body).unwrap(), &hub, 0).unwrap()
        };
        call(serde_json::json!({
            "op": "create-key", "name": "other", "policy": policy(), "ttl_secs": 3600,
        }));
        assert!(woken(&mut changes));
        let revoked = call(serde_json::json!({"op": "revoke-key", "name": "other"}));
        assert_eq!(revoked, serde_json::json!(true));
        assert!(woken(&mut changes));

        let mut principal = hub.db.api_key(&key, crate::now_secs()).unwrap().unwrap();
        principal.instance = Some("s_1".into());
        seen(&hub, &principal, crate::now_secs());
        tokio::time::timeout(Duration::from_secs(10), changes.changed())
            .await
            .unwrap()
            .unwrap();
        changes.mark_unchanged();
        assert_eq!(hub.db.clients().unwrap().len(), 1);
        // Made durable, it is not shown anew.
        flush(&hub).await.unwrap();
        assert!(!woken(&mut changes));
        // Nor by a contact past the first.
        seen(&hub, &principal, crate::now_secs());
        flush(&hub).await.unwrap();
        assert!(!woken(&mut changes));

        // A removed key's instance goes at the first pass.
        let removed = "f".repeat(64);
        let now = crate::now_secs();
        hub.db
            .record_client(&removed, "gone", "x", None, now, Durability::Immediate)
            .unwrap();
        let driver = tokio::spawn(drive(hub.clone()));
        tokio::time::timeout(Duration::from_secs(10), changes.changed())
            .await
            .unwrap()
            .unwrap();
        driver.abort();
        let left: Vec<String> = hub.db.clients().unwrap().into_iter().map(|c| c.0).collect();
        assert_eq!(left, [id]);
    }
}
