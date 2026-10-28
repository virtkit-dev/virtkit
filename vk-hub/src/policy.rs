//! Durable capacity arbitration policy: tenant shares, runner and API-key assignments,
//! and scheduler settings. Relay runners are identified by GitLab instance and runner ID,
//! never by name.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::Placement;

const MAX_TENANTS: usize = 4096;
const MAX_RUNNERS: usize = 16384;
const MAX_CLIENTS: usize = 16384;
const MAX_HEADROOMS: usize = 1024;
const MAX_PROJECTS: usize = 16384;
const MAX_BRANCHES: usize = 1024;
/// The longest production branch pattern and client principal, in bytes.
const MAX_TEXT: usize = 255;
/// The longest backoff or busy timeout.
const MAX_SECS: u64 = 365 * 24 * 3600;
/// The most slots one headroom entry reserves.
const MAX_HEADROOM_SLOTS: u32 = 4096;
/// Bounds on a headroom envelope, past any one machine: a typo is refused, not reserved.
const MAX_MEM_MIB: u64 = 16 << 20;
const MAX_CPUS: u32 = 4096;
const MAX_DISK_BYTES: u64 = 1 << 50;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    #[default]
    Normal,
    Production,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub gitlab: String,
    pub id: u64,
    #[serde(default)]
    pub production_branches: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
    pub weight: u32,
    #[serde(default)]
    pub cap: Option<u32>,
    #[serde(default)]
    pub projects: Vec<Project>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerMapping {
    pub gitlab: String,
    pub runner_id: u64,
    pub tenant: String,
    pub class: Class,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Headroom {
    #[serde(deserialize_with = "deserialize_placement")]
    pub placement: Placement,
    pub slots: u32,
}

fn deserialize_placement<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Placement, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictPlacement {
        pool: String,
        #[serde(default)]
        labels: Vec<String>,
        envelope: StrictEnvelope,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictEnvelope {
        mem_mib: u64,
        cpus: u32,
        disk_bytes: u64,
    }
    let p = StrictPlacement::deserialize(deserializer)?;
    Ok(Placement {
        pool: p.pool,
        labels: p.labels,
        envelope: vk_hub_proto::job::Envelope {
            mem_mib: p.envelope.mem_mib,
            cpus: p.envelope.cpus,
            disk_bytes: p.envelope.disk_bytes,
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub tenants: BTreeMap<String, Tenant>,
    pub runners: Vec<RunnerMapping>,
    pub clients: BTreeMap<String, String>,
    pub fallback: String,
    pub headroom: Vec<Headroom>,
    pub probe_limit: u32,
    pub production_probe_burst: u32,
    pub backoff_initial_secs: u64,
    pub backoff_max_secs: u64,
    pub busy_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            tenants: BTreeMap::from([(
                "fallback".into(),
                Tenant {
                    weight: 1,
                    cap: None,
                    projects: Vec::new(),
                },
            )]),
            runners: Vec::new(),
            clients: BTreeMap::new(),
            fallback: "fallback".into(),
            headroom: Vec::new(),
            probe_limit: 1,
            production_probe_burst: 1,
            backoff_initial_secs: 1,
            backoff_max_secs: 60,
            busy_secs: 60,
        }
    }
}

impl Policy {
    /// What `set` compares against: the sha256 of the policy as stored.
    pub fn digest(&self) -> Result<String> {
        Ok(digest_bytes(&serde_json::to_vec(self)?))
    }

    pub fn validate(&self) -> Result<()> {
        if self.tenants.len() > MAX_TENANTS
            || self.runners.len() > MAX_RUNNERS
            || self.clients.len() > MAX_CLIENTS
            || self.headroom.len() > MAX_HEADROOMS
        {
            bail!("capacity policy exceeds its size limit");
        }
        if !self.tenants.contains_key(&self.fallback) {
            bail!("fallback tenant does not exist");
        }
        if self.probe_limit == 0
            || self.production_probe_burst == 0
            || self.backoff_initial_secs == 0
            || self.backoff_max_secs < self.backoff_initial_secs
            || self.busy_secs == 0
            || self.backoff_max_secs > MAX_SECS
            || self.busy_secs > MAX_SECS
        {
            bail!(
                "probe_limit, production_probe_burst, backoff_initial_secs and busy_secs must \
                 be positive, busy_secs and backoff_max_secs at most {MAX_SECS}, and \
                 backoff_max_secs at least backoff_initial_secs"
            );
        }
        for (i, headroom) in self.headroom.iter().enumerate() {
            let p = &headroom.placement;
            if !(1..=MAX_HEADROOM_SLOTS).contains(&headroom.slots)
                || !crate::store::valid_name(&p.pool)
                || p.labels.len() > 32
                || p.labels.iter().any(|l| !crate::store::valid_name(l))
                || !(1..=MAX_MEM_MIB).contains(&p.envelope.mem_mib)
                || !(1..=MAX_CPUS).contains(&p.envelope.cpus)
                || p.envelope.disk_bytes > MAX_DISK_BYTES
            {
                bail!(
                    "invalid headroom #{} (pool {:?}): slots must be 1 to {MAX_HEADROOM_SLOTS}, \
                     with a valid pool and labels, and an envelope of 1 to {MAX_MEM_MIB} MiB, \
                     1 to {MAX_CPUS} cpus and at most {MAX_DISK_BYTES} disk bytes",
                    i + 1,
                    p.pool
                );
            }
        }
        let mut branch_lists = BTreeMap::new();
        for (name, tenant) in &self.tenants {
            if !crate::store::valid_name(name)
                || tenant.weight == 0
                || tenant.cap == Some(0)
                || tenant.projects.len() > MAX_PROJECTS
            {
                bail!(
                    "invalid tenant {name:?}: it needs a valid name, a positive weight and cap, \
                     and at most {MAX_PROJECTS} projects"
                );
            }
            let mut projects = BTreeSet::new();
            for p in &tenant.projects {
                if !crate::store::valid_gitlab_name(&p.gitlab)
                    || p.id == 0
                    || !projects.insert((&p.gitlab, p.id))
                    || p.production_branches.len() > MAX_BRANCHES
                    || p.production_branches.iter().any(|s| {
                        s.is_empty() || s.len() > MAX_TEXT || s.chars().any(char::is_control)
                    })
                {
                    bail!(
                        "invalid or duplicate project {}/{} in tenant {name:?}",
                        p.gitlab,
                        p.id
                    );
                }
                if let Some(previous) =
                    branch_lists.insert((&p.gitlab, p.id), &p.production_branches)
                    && previous != &p.production_branches
                {
                    bail!(
                        "project {}/{}'s production branches differ across tenants",
                        p.gitlab,
                        p.id
                    );
                }
            }
        }
        let mut runners = BTreeSet::new();
        for r in &self.runners {
            if !crate::store::valid_gitlab_name(&r.gitlab)
                || r.runner_id == 0
                || !self.tenants.contains_key(&r.tenant)
                || !runners.insert((&r.gitlab, r.runner_id))
            {
                bail!(
                    "invalid or duplicate runner mapping {}/{} (tenant {:?})",
                    r.gitlab,
                    r.runner_id,
                    r.tenant
                );
            }
        }
        for (principal, tenant) in &self.clients {
            if principal.is_empty()
                || principal.len() > MAX_TEXT
                || principal.chars().any(char::is_control)
                || !self.tenants.contains_key(tenant)
            {
                bail!("invalid client assignment {principal:?} (tenant {tenant:?})");
            }
        }
        Ok(())
    }
}

/// [`Policy::digest`] of a stored row, readable or not.
pub fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    vk_hub_proto::to_hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_unknown_fields_and_invalid_headroom() {
        for json in [
            r#"{"probe_limt":1}"#,
            r#"{"tenants":{"fallback":{"weight":1,"wieght":2}}}"#,
            r#"{"runners":[{"gitlab":"gl","runner_id":1,"tenant":"fallback","class":"normal","clas":"normal"}]}"#,
            r#"{"headroom":[{"placement":{"pool":"p","labels":[],"envelope":{"mem_mib":1,"cpus":1,"disk_bytes":0,"cpu":1}},"slots":1}]}"#,
        ] {
            assert!(serde_json::from_str::<Policy>(json).is_err(), "{json}");
        }
        let mut policy = Policy::default();
        policy.headroom.push(Headroom {
            placement: Placement::default(),
            slots: 1,
        });
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validation_bounds_headroom_and_caps_and_names_the_entry() {
        let headroom = |slots, mem_mib| Headroom {
            placement: Placement {
                pool: "ci".into(),
                labels: vec![],
                envelope: vk_hub_proto::job::Envelope {
                    mem_mib,
                    cpus: 1,
                    disk_bytes: 0,
                },
            },
            slots,
        };
        let mut policy = Policy::default();
        policy
            .headroom
            .push(headroom(MAX_HEADROOM_SLOTS, MAX_MEM_MIB));
        policy.validate().unwrap();
        for bad in [
            headroom(MAX_HEADROOM_SLOTS + 1, 1),
            headroom(1, MAX_MEM_MIB + 1),
        ] {
            let mut policy = Policy::default();
            policy.headroom.push(bad);
            let err = policy.validate().unwrap_err().to_string();
            assert!(err.contains("headroom #1 (pool \"ci\")"), "{err}");
        }

        let mut policy = Policy::default();
        policy.tenants.get_mut("fallback").unwrap().cap = Some(0);
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("tenant \"fallback\""), "{err}");

        let mut policy = Policy::default();
        policy.runners.push(RunnerMapping {
            gitlab: "gl".into(),
            runner_id: 7,
            tenant: "nobody".into(),
            class: Class::Normal,
        });
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("gl/7"), "{err}");
    }
}
