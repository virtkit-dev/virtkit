//! Capacity policy, stored atomically with its audit entry.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use serde::{Deserialize, Serialize};

use super::{Db, StoredAdmission, append_audit, decode, encode};
use crate::policy::{Lane, LaneId, Policy, digest_bytes};

pub(super) const CAPACITY_POLICY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("capacity_policy");

#[derive(Debug)]
pub enum PolicyRefused {
    Invalid(String),
    Conflict,
}

impl std::fmt::Display for PolicyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::Conflict => f.write_str(
                "the capacity policy changed since its digest was read; show it again and retry",
            ),
        }
    }
}

impl std::error::Error for PolicyRefused {}

fn validate(policy: &Policy) -> Result<()> {
    policy
        .validate()
        .map_err(|e| PolicyRefused::Invalid(e.to_string()).into())
}

/// The most names an audit entry lists of each kind; the rest are counted.
const AUDIT_NAMES: usize = 20;

fn listed(names: &[String]) -> String {
    let mut out = names
        .iter()
        .take(AUDIT_NAMES)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > AUDIT_NAMES {
        out.push_str(&format!(" and {} more", names.len() - AUDIT_NAMES));
    }
    out
}

/// The keys whose entries differ between `before` and `after`.
fn changed<K: Ord + Clone, V: PartialEq>(
    before: &BTreeMap<K, V>,
    after: &BTreeMap<K, V>,
) -> Vec<K> {
    before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect()
}

/// Changes between `before` and `after` for the replacement audit: lanes and scheduling
/// settings. Empty when they are the same.
pub fn policy_changes(before: &Policy, after: &Policy) -> Vec<String> {
    let by_id = |p: &Policy| -> BTreeMap<String, Lane> {
        (p.lanes.iter())
            .filter_map(|l| Some((l.id()?.to_string(), l.clone())))
            .collect()
    };
    let lanes = changed(&by_id(before), &by_id(after));
    let mut settings = Vec::new();
    for (name, differs) in [
        ("headroom", before.headroom != after.headroom),
        ("probe_limit", before.probe_limit != after.probe_limit),
        (
            "production_probe_burst",
            before.production_probe_burst != after.production_probe_burst,
        ),
        (
            "backoff_initial_secs",
            before.backoff_initial_secs != after.backoff_initial_secs,
        ),
        (
            "backoff_max_secs",
            before.backoff_max_secs != after.backoff_max_secs,
        ),
        ("busy_secs", before.busy_secs != after.busy_secs),
    ] {
        if differs {
            settings.push(name.to_owned());
        }
    }
    let mut out = Vec::new();
    for (what, names) in [("lanes", &lanes), ("settings", &settings)] {
        if !names.is_empty() {
            out.push(format!("{what}: {}", listed(names)));
        }
    }
    out
}

fn policy_audit(before: &Policy, after: &Policy, from: &str, to: &str) -> String {
    let mut event = format!(
        "changed capacity policy {} to {}",
        crate::store::short(from),
        crate::store::short(to)
    );
    for change in policy_changes(before, after) {
        event.push_str("; ");
        event.push_str(&change);
    }
    event
}

/// The row of the policy stored before the conversion to lanes, kept as it was for a rollback.
const V1_BACKUP: &str = "policy.v1.bak";
/// The row of the [`ConversionNote`] left by that conversion.
const CONVERSION: &str = "conversion";

/// What converting the stored policy to lanes left for an operator to review.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionNote {
    /// The digests of the policy converted, kept as [`V1_BACKUP`], and of the conversion.
    pub from: String,
    pub to: String,
    /// Lanes each given the whole share of a tenant several lanes took, with its name: until
    /// the lane is next changed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<(LaneId, String)>,
    /// Placement rules the lanes could not express, with the lanes they applied to: while
    /// any is listed, the policy is held, granting no new capacity, until an operator sets a
    /// policy again, unchanged or not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unconverted: Vec<String>,
}

impl ConversionNote {
    /// Whether the policy is proposed, not active: no new capacity is granted.
    pub fn held(&self) -> bool {
        !self.unconverted.is_empty()
    }
}

/// Convert a policy stored in the earlier format of tenants to lanes, once: keep the original
/// as [`V1_BACKUP`], store the lanes with a [`ConversionNote`], and rewrite the scheduling
/// identity of admissions and jobs not finished to name their lane. A policy that does not
/// convert is left as it is: the hub reports it unreadable until an operator replaces it.
pub(super) fn convert_stored(txn: &redb::WriteTransaction, now: u64) -> Result<()> {
    let mut table = txn.open_table(CAPACITY_POLICY)?;
    let Some(bytes) = table.get("policy")?.map(|row| row.value().to_vec()) else {
        return Ok(());
    };
    let earlier = serde_json::from_slice::<serde_json::Value>(&bytes)
        .is_ok_and(|v| v.is_object() && v.get("version").is_none());
    if !earlier {
        return Ok(());
    }
    let converted = match crate::policy::convert_v1(&bytes) {
        Ok(converted) => converted,
        Err(e) => {
            eprintln!("vk-hub: the stored capacity policy does not convert to lanes: {e:#}");
            return Ok(());
        }
    };
    let (from, to) = (digest_bytes(&bytes), converted.policy.digest()?);
    let note = ConversionNote {
        from: from.clone(),
        to: to.clone(),
        shared: converted.shared.clone(),
        unconverted: converted.unconverted.clone(),
    };
    table.insert(V1_BACKUP, bytes.as_slice())?;
    table.insert("policy", encode(&converted.policy)?.as_slice())?;
    table.insert(CONVERSION, encode(&note)?.as_slice())?;
    drop(table);
    rewrite_identities(txn, &converted.policy)?;
    let mut event = format!(
        "converted capacity policy {} to lanes {}",
        crate::store::short(&from),
        crate::store::short(&to)
    );
    if note.held() {
        event.push_str(&format!(
            "; held until activated: {} placement rules do not convert",
            note.unconverted.len()
        ));
    }
    append_audit(txn, None, "hub", &event, now)?;
    for warning in converted.warnings() {
        eprintln!("vk-hub: capacity policy conversion: {warning}");
    }
    Ok(())
}

/// The row marking that the stored policy was rewritten for lanes that select pools, once.
const POOLS_SELECTED: &str = "pools.selected";

/// Have each runner lane select where its work runs, once, on the first start of a hub whose
/// lanes do: a lane selecting nothing gets the pool its relay last reported for the runner,
/// as placement went by it before, and the policy is written back as this hub writes it,
/// `nodes` read into `pools`. A runner whose relay reported no pool is left selecting nothing,
/// and gets no work until an operator selects some; the hub says so at each start.
pub(super) fn select_reported_pools(txn: &redb::WriteTransaction, now: u64) -> Result<()> {
    let mut table = txn.open_table(CAPACITY_POLICY)?;
    if table.get(POOLS_SELECTED)?.is_some() {
        return Ok(());
    }
    let Some(bytes) = table.get("policy")?.map(|row| row.value().to_vec()) else {
        table.insert(POOLS_SELECTED, &b"1"[..])?;
        return Ok(());
    };
    let mut policy: Policy = match decode(&bytes) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!(
                "vk-hub: the stored capacity policy is unreadable, so its runner lanes were not \
                 given the pools their relays reported: {e:#}"
            );
            return Ok(());
        }
    };
    let reported = reported_pools(txn)?;
    let mut given = Vec::new();
    for lane in &mut policy.lanes {
        let Some(LaneId::Runner { gitlab, id }) = lane.id() else {
            continue;
        };
        if !lane.pools.is_empty() {
            continue;
        }
        match reported.get(&(gitlab.clone(), id)) {
            Some(pool) => {
                lane.pools = vec![pool.clone()];
                given.push(format!("runner {gitlab}/{id} {pool}"));
            }
            None => eprintln!(
                "vk-hub: capacity policy: runner {gitlab}/{id}'s lane selects no pool or node \
                 and its relay reported none: it gets no work until its lane selects some"
            ),
        }
    }
    let encoded = encode(&policy)?;
    if encoded != bytes {
        let (from, to) = (digest_bytes(&bytes), digest_bytes(&encoded));
        table.insert("policy", encoded.as_slice())?;
        let mut event = format!(
            "rewrote capacity policy {} as {}: lanes select pools and nodes",
            crate::store::short(&from),
            crate::store::short(&to)
        );
        if !given.is_empty() {
            event.push_str(&format!(
                "; runner lanes given the pool their relay reported: {}",
                listed(&given)
            ));
        }
        append_audit(txn, None, "hub", &event, now)?;
        eprintln!("vk-hub: {event}");
    }
    table.insert(POOLS_SELECTED, &b"1"[..])?;
    Ok(())
}

/// The pool each runner's relay last reported, by the runner's instance name and GitLab ID,
/// read from the relay rows as a hub before 0.111 wrote them, from relays of then:
/// `inventory.runners[].placement.pool`, which this hub's rows and relays no longer carry.
fn reported_pools(txn: &redb::WriteTransaction) -> Result<BTreeMap<(String, u64), String>> {
    let gitlabs = txn.open_table(super::gitlabs::GITLABS)?;
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for entry in gitlabs.iter()? {
        let (name, row) = entry?;
        let row: super::gitlabs::GitlabRow = decode(row.value())?;
        names.insert(row.url, name.value().to_owned());
    }
    let relays = txn.open_table(super::relays::RELAYS)?;
    let mut pools = BTreeMap::new();
    for entry in relays.iter()? {
        let (_, row) = entry?;
        let row: serde_json::Value = decode(row.value())?;
        let Some(gitlab) =
            (row.get("server_url").and_then(|u| u.as_str())).and_then(|u| names.get(u))
        else {
            continue;
        };
        let runners = (row.pointer("/inventory/runners").and_then(|r| r.as_array()))
            .into_iter()
            .flatten();
        for runner in runners {
            let id = runner.get("runner_id").and_then(|id| id.as_u64());
            let pool = runner.pointer("/placement/pool").and_then(|p| p.as_str());
            if let (Some(id), Some(pool)) = (id, pool)
                && crate::store::valid_name(pool)
            {
                pools
                    .entry((gitlab.clone(), id))
                    .or_insert_with(|| pool.to_owned());
            }
        }
    }
    Ok(pools)
}

/// Have each admission and job not finished name its lane: a runner's, an API key's own or
/// the default lane.
fn rewrite_identities(txn: &redb::WriteTransaction, policy: &Policy) -> Result<()> {
    let mut admissions = txn.open_table(super::admissions::ADMISSIONS)?;
    let mut rows = Vec::new();
    for entry in admissions.iter()? {
        let (id, row) = entry?;
        rows.push((
            id.value().to_owned(),
            decode::<StoredAdmission>(row.value())?,
        ));
    }
    for (id, mut row) in rows {
        let identity = &mut row.identity;
        if identity.gitlab.is_none() && identity.runner_id.is_none() {
            identity.lane = (policy.client(&row.principal)).map_or(LaneId::Default, |(id, _)| id);
        }
        admissions.insert(id.as_str(), encode(&row)?.as_slice())?;
    }
    let mut jobs = txn.open_table(super::jobs::JOBS)?;
    let mut rows = Vec::new();
    for entry in jobs.iter()? {
        let (id, row) = entry?;
        let row = decode::<super::JobRow>(row.value())?;
        if row.state != vk_hub_proto::client::JobState::Finished && row.scheduling.is_some() {
            rows.push((id.value().to_owned(), row));
        }
    }
    // Decoded, a job's identity names its runner's lane; only a relay submits jobs.
    for (id, row) in rows {
        jobs.insert(id.as_str(), encode(&row)?.as_slice())?;
    }
    Ok(())
}

impl Db {
    /// The stored policy, or the default before one is set. Decoding is as strict as for
    /// operator input: a rollback rejects unknown fields rather than dropping rules.
    /// Decoding errors include the digest needed to replace an unreadable policy.
    pub fn capacity_policy(&self) -> Result<Policy> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CAPACITY_POLICY)?;
        match table.get("policy")? {
            Some(row) => decode(row.value()).with_context(|| {
                let digest = digest_bytes(row.value());
                format!(
                    "this hub cannot read the stored capacity policy (digest {digest}); \
                     `set --expected {digest}` replaces it"
                )
            }),
            None => Ok(Policy::default()),
        }
    }

    /// What converting the stored policy to lanes left to review, until an operator has.
    pub fn capacity_conversion(&self) -> Result<Option<ConversionNote>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CAPACITY_POLICY)?;
        table
            .get(CONVERSION)?
            .map(|row| decode(row.value()))
            .transpose()
    }

    /// The policy and whether it is held, granting no new capacity ([`ConversionNote::held`]),
    /// read together.
    pub fn capacity_policy_state(&self) -> Result<(Policy, bool)> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CAPACITY_POLICY)?;
        let held = match table.get(CONVERSION)? {
            Some(row) => decode::<ConversionNote>(row.value())?.held(),
            None => false,
        };
        drop(table);
        drop(txn);
        Ok((self.capacity_policy()?, held))
    }

    /// Replace the policy unconditionally, audited as `actor`'s.
    #[cfg(test)]
    pub fn set_capacity_policy(&self, policy: &Policy, actor: &str, now: u64) -> Result<()> {
        validate(policy)?;
        let bytes = encode(policy)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CAPACITY_POLICY)?;
            table.insert("policy", bytes.as_slice())?;
            table.remove(CONVERSION)?;
        }
        append_audit(&txn, None, actor, "changed capacity policy", now)?;
        txn.commit()?;
        Ok(())
    }

    /// Store `bytes` as the policy row, as a later or earlier hub may have left it: one whose
    /// lanes were not yet given the pools their relays reported.
    #[cfg(test)]
    pub fn set_raw_capacity_policy(&self, bytes: &[u8]) {
        let txn = self.db.begin_write().unwrap();
        let mut table = txn.open_table(CAPACITY_POLICY).unwrap();
        table.insert("policy", bytes).unwrap();
        table.remove(POOLS_SELECTED).unwrap();
        drop(table);
        txn.commit().unwrap();
    }

    /// Store `note` as what converting the policy left to review.
    #[cfg(test)]
    pub fn set_capacity_conversion(&self, note: &ConversionNote) {
        let txn = self.db.begin_write().unwrap();
        txn.open_table(CAPACITY_POLICY)
            .unwrap()
            .insert(CONVERSION, encode(note).unwrap().as_slice())
            .unwrap();
        txn.commit().unwrap();
    }

    /// The policy row as stored.
    #[cfg(test)]
    pub fn capacity_policy_raw(&self) -> String {
        let txn = self.db.begin_read().unwrap();
        let table = txn.open_table(CAPACITY_POLICY).unwrap();
        let row = table.get("policy").unwrap().unwrap();
        String::from_utf8(row.value().to_vec()).unwrap()
    }

    /// The policy row kept from before the conversion to lanes.
    #[cfg(test)]
    pub fn capacity_policy_backup(&self) -> Option<Vec<u8>> {
        let txn = self.db.begin_read().unwrap();
        let table = txn.open_table(CAPACITY_POLICY).unwrap();
        table.get(V1_BACKUP).unwrap().map(|r| r.value().to_vec())
    }

    /// Replace the policy if its digest is still `expected`, audited in the same transaction.
    /// Returns whether it changed: the same policy again writes nothing, unless it activates a
    /// policy held since its conversion. A lane changed is no longer flagged as sharing a
    /// tenant's share.
    pub fn replace_capacity_policy_if(
        &self,
        policy: &Policy,
        expected: &str,
        actor: &str,
        now: u64,
    ) -> Result<bool> {
        self.replace_policy_if(policy, expected, actor, now, true)
    }

    /// [`Db::replace_capacity_policy_if`], leaving a policy held since its conversion held:
    /// an edit of part of it, made while the rest is still under review.
    pub fn edit_capacity_policy_if(
        &self,
        policy: &Policy,
        expected: &str,
        actor: &str,
        now: u64,
    ) -> Result<bool> {
        self.replace_policy_if(policy, expected, actor, now, false)
    }

    fn replace_policy_if(
        &self,
        policy: &Policy,
        expected: &str,
        actor: &str,
        now: u64,
        activate: bool,
    ) -> Result<bool> {
        validate(policy)?;
        let txn = self.db.begin_write()?;
        let audit;
        {
            let mut table = txn.open_table(CAPACITY_POLICY)?;
            // `expected` is what `show` printed: the digest of the policy as decoded, or of
            // the row as stored when this hub cannot decode it.
            let (digest, current) = match table.get("policy")? {
                Some(row) => (
                    digest_bytes(row.value()),
                    decode::<Policy>(row.value()).ok(),
                ),
                None => {
                    let policy = Policy::default();
                    (policy.digest()?, Some(policy))
                }
            };
            let shown = current.as_ref().map(Policy::digest).transpose()?;
            if digest != expected && shown.as_deref() != Some(expected) {
                return Err(PolicyRefused::Conflict.into());
            }
            let note = table
                .get(CONVERSION)?
                .map(|row| decode::<ConversionNote>(row.value()))
                .transpose()?;
            let held = activate && note.as_ref().is_some_and(ConversionNote::held);
            let next = policy.digest()?;
            audit = match current {
                Some(current) if current == *policy && !held => return Ok(false),
                Some(current) if current == *policy => {
                    format!("activated capacity policy {}", crate::store::short(&next))
                }
                Some(current) => {
                    let mut event = policy_audit(&current, policy, &digest, &next);
                    if held {
                        event.push_str("; activated");
                    }
                    event
                }
                None => format!(
                    "replaced unreadable capacity policy {} with {}",
                    crate::store::short(&digest),
                    crate::store::short(&next)
                ),
            };
            let before = current_lanes(&table)?;
            match note.map(|mut note| {
                if activate {
                    note.unconverted.clear();
                }
                note.shared
                    .retain(|(id, _)| before.as_ref().and_then(|b| b.lane(id)) == policy.lane(id));
                note
            }) {
                Some(note) if !note.shared.is_empty() || note.held() => {
                    table.insert(CONVERSION, encode(&note)?.as_slice())?;
                }
                _ => {
                    table.remove(CONVERSION)?;
                }
            }
            let bytes = encode(policy)?;
            table.insert("policy", bytes.as_slice())?;
        }
        append_audit(&txn, None, actor, &audit, now)?;
        txn.commit()?;
        Ok(true)
    }
}

/// The policy `table` stores, if readable.
fn current_lanes(table: &redb::Table<&str, &[u8]>) -> Result<Option<Policy>> {
    Ok(table
        .get("policy")?
        .and_then(|row| decode::<Policy>(row.value()).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Class, LaneProject};

    fn runner(id: u64) -> Lane {
        Lane::new(&LaneId::Runner {
            gitlab: "gl".into(),
            id,
        })
    }

    #[test]
    fn audit_names_changed_scheduling_settings() {
        let before = Policy::default();
        let mut after = before.clone();
        after.probe_limit = 2;
        after.headroom.push(crate::policy::Headroom {
            placement: vk_hub_proto::client::Placement::default(),
            slots: 1,
        });
        let event = policy_audit(&before, &after, &"a".repeat(64), &"b".repeat(64));
        assert!(event.contains("headroom"));
        assert!(event.contains("probe_limit"));
        assert!(!event.contains("busy_secs"));
        assert!(!event.contains("lanes"), "{event}");
    }

    #[test]
    fn policy_replacement_is_validated_audited_and_compared_atomically() {
        let db = Db::open_memory().unwrap();
        let initial = db.capacity_policy().unwrap();
        let expected = initial.digest().unwrap();
        let mut policy = initial.clone();
        policy.lanes.push(Lane {
            class: Class::Production,
            weight: 2,
            max_slots: Some(4),
            projects: Some(vec![]),
            ..runner(42)
        });
        assert!(
            db.replace_capacity_policy_if(&policy, &expected, "operator", 1)
                .unwrap()
        );
        assert_eq!(db.capacity_policy().unwrap(), policy);
        // The same policy again: nothing written, nothing audited.
        assert!(
            !db.replace_capacity_policy_if(&policy, &policy.digest().unwrap(), "operator", 2)
                .unwrap()
        );
        let error = db
            .replace_capacity_policy_if(&initial, &expected, "operator", 2)
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<PolicyRefused>(),
            Some(PolicyRefused::Conflict)
        ));
        let mut invalid = policy.clone();
        invalid.lanes.push(invalid.lanes[1].clone());
        let error = db
            .replace_capacity_policy_if(&invalid, &policy.digest().unwrap(), "operator", 3)
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<PolicyRefused>(),
            Some(PolicyRefused::Invalid(_))
        ));
        assert_eq!(db.capacity_policy().unwrap(), policy);
        let audits = db.audits(None, 100).unwrap();
        assert_eq!(audits.len(), 1);
        assert!(audits[0].event.contains("runner gl/42"), "{audits:?}");
    }

    #[test]
    fn a_policy_stored_before_a_field_existed_is_replaced_against_its_shown_digest() {
        let db = Db::open_memory().unwrap();
        // Without `busy_secs`: decoded with its default, so it shows a digest of its own.
        let mut stored = serde_json::to_value(Policy::default()).unwrap();
        stored.as_object_mut().unwrap().remove("busy_secs");
        let stored = serde_json::to_vec(&stored).unwrap();
        db.set_raw_capacity_policy(stored.as_slice());
        let shown = db.capacity_policy().unwrap().digest().unwrap();
        assert_ne!(shown, digest_bytes(&stored));
        let policy = Policy {
            probe_limit: 2,
            ..Policy::default()
        };
        assert!(
            db.replace_capacity_policy_if(&policy, &shown, "operator", 1)
                .unwrap()
        );
    }

    #[test]
    fn audit_lists_are_bounded() {
        let before = Policy::default();
        let mut after = before.clone();
        for i in 0..AUDIT_NAMES + 5 {
            after
                .lanes
                .push(Lane::new(&LaneId::Key(format!("key-{i:02}"))));
        }
        let event = policy_audit(&before, &after, &"a".repeat(64), &"b".repeat(64));
        assert!(event.contains("and 5 more"), "{event}");
        assert!(!event.contains(&format!("key-{AUDIT_NAMES}")), "{event}");
    }

    #[test]
    fn an_unreadable_policy_names_its_digest_and_can_be_replaced() {
        let db = Db::open_memory().unwrap();
        let stored = br#"{"version":3,"from_a_later_hub":true}"#;
        db.set_raw_capacity_policy(stored.as_slice());
        let digest = digest_bytes(stored);
        let err = format!("{:#}", db.capacity_policy().unwrap_err());
        assert!(err.contains(&format!("--expected {digest}")), "{err}");
        let policy = Policy::default();
        assert!(
            db.replace_capacity_policy_if(&policy, &digest, "operator", 1)
                .unwrap()
        );
        assert_eq!(db.capacity_policy().unwrap(), policy);
        let audits = db.audits(None, 10).unwrap();
        assert!(
            audits[0].event.contains("replaced unreadable"),
            "{audits:?}"
        );
    }

    /// A database whose policy row is `v1`, reopened by this hub, with its path.
    fn reopened(
        v1: serde_json::Value,
        setup: impl FnOnce(&Db),
    ) -> (Db, Vec<u8>, std::path::PathBuf, impl Drop) {
        struct Gone(std::path::PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vk-hub-lanes-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.redb");
        let bytes = serde_json::to_vec(&v1).unwrap();
        let db = Db::open(&path).unwrap();
        db.set_raw_capacity_policy(&bytes);
        setup(&db);
        drop(db);
        (Db::open(&path).unwrap(), bytes, path, Gone(dir))
    }

    #[test]
    fn a_stored_earlier_policy_is_converted_once_and_kept() {
        let v1 = serde_json::json!({
            "tenants": {
                "fallback": { "weight": 1 },
                "web": { "weight": 2, "projects": [{ "gitlab": "gl", "id": 7 }] }
            },
            "runners": [{ "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": "normal" }],
            "clients": { "ci-bot": "web" }
        });
        let (db, bytes, _, _dir) = reopened(v1, |_| {});
        let policy = db.capacity_policy().unwrap();
        let lane = policy.runner("gl", 42).unwrap();
        assert_eq!(lane.weight, 2);
        assert_eq!(
            lane.projects,
            Some(vec![LaneProject {
                gitlab: "gl".into(),
                id: 7,
                branches: None
            }])
        );
        assert_eq!(db.capacity_policy_backup(), Some(bytes.clone()));
        let note = db.capacity_conversion().unwrap().unwrap();
        assert!(!note.held());
        assert_eq!(note.from, digest_bytes(&bytes));
        assert_eq!(note.to, policy.digest().unwrap());
        assert_eq!(note.shared.len(), 2, "{note:?}");
        assert!(!db.capacity_policy_state().unwrap().1);
        let audits = db.audits(None, 10).unwrap();
        assert!(
            audits[0].event.contains(crate::store::short(&note.from))
                && audits[0].event.contains(crate::store::short(&note.to)),
            "{audits:?}"
        );
        // Saving the policy with one shared lane changed clears that lane's flag alone.
        let mut changed = policy.clone();
        changed
            .lanes
            .iter_mut()
            .find(|l| l.key.is_some())
            .unwrap()
            .weight = 1;
        db.replace_capacity_policy_if(&changed, &note.to, "operator", 2)
            .unwrap();
        let note = db.capacity_conversion().unwrap().unwrap();
        assert_eq!(note.shared.len(), 1, "{note:?}");
    }

    /// On the first start of a hub whose lanes select pools, each runner lane selecting nothing
    /// gets the pool its relay last reported, `nodes` is read as `pools`, and the policy is
    /// written back; once, so a lane emptied since stays empty.
    #[test]
    fn runner_lanes_are_given_the_pools_their_relays_reported_once() {
        use vk_hub_proto::gitlab::{Inventory, Runner, Server};
        let node = "0123456789abcdef0123456789abcdef";
        let stored = serde_json::json!({ "version": 2, "lanes": [
            { "runner": { "gitlab": "gl", "id": 42 } },
            { "runner": { "gitlab": "gl", "id": 43 }, "nodes": [node, "trusted"] },
            { "runner": { "gitlab": "gl", "id": 44 } },
            { "runner": { "gitlab": "other", "id": 1 } },
            { "default": true }
        ]});
        let runner = |name: &str, id: Option<u64>| Runner {
            name: name.into(),
            runner_id: id,
            verified: true,
            ..Runner::default()
        };
        let (db, bytes, path, _dir) = reopened(stored, |db| {
            db.add_gitlab("gl", "https://gitlab.example.com", "u", 1)
                .unwrap();
            let (token, _) = db
                .create_token_for(
                    crate::store::TokenKind::Gitlab,
                    std::time::Duration::from_secs(60),
                    None,
                    "u",
                    1,
                )
                .unwrap();
            let crate::store::RelayEnrollment::Enrolled { id } =
                db.enroll_relay(&token, "aa", "relay-1", "p", 1).unwrap()
            else {
                panic!("not enrolled");
            };
            let inventory = Inventory {
                hostname: "relay-1".into(),
                concurrent: 4,
                server: Server {
                    url: "https://gitlab.example.com".into(),
                    ..Server::default()
                },
                runners: vec![
                    runner("ci", Some(42)),
                    runner("big", Some(43)),
                    runner("new", None),
                    runner("odd", Some(44)),
                ],
                ..Inventory::default()
            };
            db.record_relay(&id, crate::store::RelayWrite::Inventory(inventory), 1)
                .unwrap();
            // As a relay of before 0.111 reported it: each runner with its pool.
            let mut row = serde_json::to_value(db.relay(&id).unwrap().unwrap()).unwrap();
            for (i, pool) in ["ci", "big", "ci", "no pool"].into_iter().enumerate() {
                row["inventory"]["runners"][i]["placement"]["pool"] = serde_json::json!(pool);
            }
            db.set_raw_relay(&id, &serde_json::to_vec(&row).unwrap());
        });
        let policy = db.capacity_policy().unwrap();
        assert_eq!(policy.runner("gl", 42).unwrap().pools, ["ci"]);
        assert_eq!(
            policy.runner("gl", 43).unwrap().pools,
            [crate::policy::node_pool(node), "trusted".to_owned()]
        );
        // No valid pool reported for 44, no relay of `other`: left selecting nothing.
        assert!(policy.runner("gl", 44).unwrap().pools.is_empty());
        assert!(policy.runner("other", 1).unwrap().pools.is_empty());
        let digest = policy.digest().unwrap();
        assert_ne!(digest, digest_bytes(&bytes));
        let audits = db.audits(None, 10).unwrap();
        let last = audits.last().unwrap();
        assert!(
            last.actor == "hub"
                && last.event.contains("rewrote capacity policy")
                && last.event.contains(crate::store::short(&digest))
                && last.event.ends_with("reported: runner gl/42 ci"),
            "{audits:?}"
        );
        // Stored as this hub writes it: `pools`, never `nodes`.
        let raw = db.capacity_policy_raw();
        assert!(
            !raw.contains("\"nodes\"") && raw.contains("\"pools\":[\"ci\"]"),
            "{raw}"
        );
        // Emptied by an operator, the lane stays empty across a restart.
        let mut emptied = policy.clone();
        emptied
            .lanes
            .iter_mut()
            .find(|l| {
                l.id()
                    == Some(LaneId::Runner {
                        gitlab: "gl".into(),
                        id: 42,
                    })
            })
            .unwrap()
            .pools = Vec::new();
        db.replace_capacity_policy_if(&emptied, &digest, "operator", 2)
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(
            db.capacity_policy()
                .unwrap()
                .runner("gl", 42)
                .unwrap()
                .pools
                .is_empty()
        );
        assert_eq!(
            db.audits(None, 10).unwrap().last().unwrap().actor,
            "operator"
        );
    }

    #[test]
    fn a_conversion_with_rules_left_over_is_held_until_set_again() {
        let node = "0123456789abcdef0123456789abcdef";
        let v1 = serde_json::json!({
            "tenants": {
                "fallback": { "weight": 1 },
                "web": { "weight": 1, "projects": [{ "gitlab": "gl", "id": 7,
                    "placement_rules": [{ "branches": ["main"], "nodes": [node] }] }] }
            },
            "runners": [{ "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": "normal" }]
        });
        let (db, _, _, _dir) = reopened(v1, |_| {});
        let (policy, held) = db.capacity_policy_state().unwrap();
        assert!(held);
        let note = db.capacity_conversion().unwrap().unwrap();
        assert!(note.unconverted[0].contains("project gl/7"), "{note:?}");
        // Edited, unchanged: nothing written. Changed: still held.
        assert!(
            !db.edit_capacity_policy_if(&policy, &note.to, "operator", 2)
                .unwrap()
        );
        let mut edited = policy.clone();
        edited.lanes[0].weight = 2;
        assert!(
            db.edit_capacity_policy_if(&edited, &note.to, "operator", 2)
                .unwrap()
        );
        assert!(db.capacity_policy_state().unwrap().1);
        let note = db.capacity_conversion().unwrap().unwrap();
        assert!(!note.unconverted.is_empty(), "{note:?}");
        let audits = db.audits(None, 10).unwrap();
        assert!(
            audits
                .iter()
                .any(|a| a.event.contains("lanes: runner gl/42") && !a.event.contains("activated")),
            "{audits:?}"
        );
        let policy = edited;
        let current = policy.digest().unwrap();
        // Set again, unchanged: activated, audited.
        assert!(
            db.replace_capacity_policy_if(&policy, &current, "operator", 2)
                .unwrap()
        );
        assert!(!db.capacity_policy_state().unwrap().1);
        assert!(db.capacity_conversion().unwrap().is_none());
        let audits = db.audits(None, 10).unwrap();
        assert!(audits[0].event.contains("activated"), "{audits:?}");
    }

    #[test]
    fn in_flight_identities_are_rewritten_to_their_lanes() {
        let v1 = serde_json::json!({
            "tenants": { "fallback": { "weight": 1 }, "web": { "weight": 1 } },
            "runners": [{ "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": "normal" }],
            "clients": { "ci-bot": "web" }
        });
        let admission = |principal: &str, runner: Option<u64>| {
            serde_json::json!({
                "principal": principal,
                "identity": { "tenant": "web", "class": "normal",
                              "gitlab": runner.map(|_| "gl"), "runner_id": runner },
                "runner": runner.map(|_| "r"),
                "placement": vk_hub_proto::client::Placement::default(),
                "probe": false,
                "reservation": "b".repeat(32)
            })
        };
        let rows = [
            ("a".repeat(32), admission("relay", Some(42))),
            ("c".repeat(32), admission("ci-bot", None)),
            ("d".repeat(32), admission("other", None)),
        ];
        let (db, _, _, _dir) = reopened(v1, |db| {
            let txn = db.db.begin_write().unwrap();
            {
                let mut table = txn
                    .open_table(super::super::admissions::ADMISSIONS)
                    .unwrap();
                for (id, row) in &rows {
                    let bytes = serde_json::to_vec(row).unwrap();
                    table.insert(id.as_str(), bytes.as_slice()).unwrap();
                }
            }
            txn.commit().unwrap();
        });
        let lanes: Vec<_> = (db.admissions().unwrap().into_iter())
            .map(|(_, a)| a.identity.lane)
            .collect();
        assert_eq!(
            lanes,
            [
                LaneId::Runner {
                    gitlab: "gl".into(),
                    id: 42
                },
                LaneId::Key("ci-bot".into()),
                LaneId::Default
            ]
        );
    }
}
