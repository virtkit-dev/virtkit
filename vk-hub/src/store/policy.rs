//! Capacity policy, stored atomically with its audit entry.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::{Db, append_audit, decode, encode};
use crate::policy::{Policy, digest_bytes};

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

fn policy_audit(before: &Policy, after: &Policy, from: &str, to: &str) -> String {
    let tenants = changed(&before.tenants, &after.tenants);
    let by_runner = |p: &Policy| -> BTreeMap<String, crate::policy::RunnerMapping> {
        p.runners
            .iter()
            .map(|r| (format!("{}/{}", r.gitlab, r.runner_id), r.clone()))
            .collect()
    };
    let runners = changed(&by_runner(before), &by_runner(after));
    let clients = changed(&before.clients, &after.clients);
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
    let mut event = format!(
        "changed capacity policy {} to {}",
        crate::store::short(from),
        crate::store::short(to)
    );
    for (what, names) in [
        ("tenants", &tenants),
        ("runners", &runners),
        ("clients", &clients),
        ("settings", &settings),
    ] {
        if !names.is_empty() {
            event.push_str(&format!("; {what}: {}", listed(names)));
        }
    }
    if before.fallback != after.fallback {
        event.push_str(&format!(
            "; fallback: {} to {}",
            before.fallback, after.fallback
        ));
    }
    event
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

    /// Replace the policy unconditionally, audited as `actor`'s.
    #[cfg(test)]
    pub fn set_capacity_policy(&self, policy: &Policy, actor: &str, now: u64) -> Result<()> {
        validate(policy)?;
        let bytes = encode(policy)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CAPACITY_POLICY)?;
            table.insert("policy", bytes.as_slice())?;
        }
        append_audit(&txn, None, actor, "changed capacity policy", now)?;
        txn.commit()?;
        Ok(())
    }

    /// Replace the policy if its digest is still `expected`, audited in the same transaction.
    /// Returns whether it changed: the same policy again writes nothing.
    pub fn replace_capacity_policy_if(
        &self,
        policy: &Policy,
        expected: &str,
        actor: &str,
        now: u64,
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
            let next = policy.digest()?;
            audit = match current {
                Some(current) if current == *policy => return Ok(false),
                Some(current) => policy_audit(&current, policy, &digest, &next),
                None => format!(
                    "replaced unreadable capacity policy {} with {}",
                    crate::store::short(&digest),
                    crate::store::short(&next)
                ),
            };
            let bytes = encode(policy)?;
            table.insert("policy", bytes.as_slice())?;
        }
        append_audit(&txn, None, actor, &audit, now)?;
        txn.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Class, RunnerMapping, Tenant};

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
        assert!(
            !event.contains("tenants") && !event.contains("fallback"),
            "{event}"
        );
    }

    #[test]
    fn policy_replacement_is_validated_audited_and_compared_atomically() {
        let db = Db::open_memory().unwrap();
        let initial = db.capacity_policy().unwrap();
        let expected = initial.digest().unwrap();
        let mut policy = initial.clone();
        policy.tenants.insert(
            "web".into(),
            Tenant {
                weight: 2,
                cap: Some(4),
                projects: vec![],
            },
        );
        policy.runners.push(RunnerMapping {
            gitlab: "gl".into(),
            runner_id: 42,
            tenant: "web".into(),
            class: Class::Production,
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
        invalid.runners.push(invalid.runners[0].clone());
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
        assert!(audits[0].event.contains("web") && audits[0].event.contains("gl/42"));
    }

    #[test]
    fn a_policy_stored_before_a_field_existed_is_replaced_against_its_shown_digest() {
        let db = Db::open_memory().unwrap();
        // Without `busy_secs`: decoded with its default, so it shows a digest of its own.
        let mut stored = serde_json::to_value(Policy::default()).unwrap();
        stored.as_object_mut().unwrap().remove("busy_secs");
        let stored = serde_json::to_vec(&stored).unwrap();
        {
            let txn = db.db.begin_write().unwrap();
            txn.open_table(CAPACITY_POLICY)
                .unwrap()
                .insert("policy", stored.as_slice())
                .unwrap();
            txn.commit().unwrap();
        }
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
                .clients
                .insert(format!("key-{i:02}"), "fallback".into());
        }
        let event = policy_audit(&before, &after, &"a".repeat(64), &"b".repeat(64));
        assert!(event.contains("and 5 more"), "{event}");
        assert!(!event.contains(&format!("key-{AUDIT_NAMES}")), "{event}");
    }

    #[test]
    fn an_unreadable_policy_names_its_digest_and_can_be_replaced() {
        let db = Db::open_memory().unwrap();
        let stored = br#"{"from_a_later_hub":true}"#;
        {
            let txn = db.db.begin_write().unwrap();
            txn.open_table(CAPACITY_POLICY)
                .unwrap()
                .insert("policy", stored.as_slice())
                .unwrap();
            txn.commit().unwrap();
        }
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
}
