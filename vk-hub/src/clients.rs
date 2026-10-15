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
//! loses up to a minute of last contacts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use redb::Durability;
use vk_hub_proto::client::ClientHello;

use crate::server::Hub;
use crate::store::{ApiPrincipal, MAX_INSTANCES_PER_KEY};

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
                Ok(Ok(_)) => {}
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
/// write settles them.
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
    if matches!(durability, Durability::Immediate) {
        for (key, instance, at) in &contacts {
            hub.instances.flushed(key, instance, *at);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
