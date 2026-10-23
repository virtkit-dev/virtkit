//! Registry namespaces: per registry, a path prefix, who may read, write or lock under it, and
//! how long its idle tags are kept. A job's registry token carries what the namespaces that
//! select it grant; the registry enforces the token and never sees this policy.
//!
//! A path is a template: `{gitlab}` (the hub's name for the job's GitLab instance),
//! `{project_id}`, `{pipeline_id}` and `{protection}` (`protected` or `unprotected`) are
//! filled from the job's claims when its token is minted. Only identifiers fill it, so two
//! namespaces never collide on a project's path.

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::token::valid_prefix;

use super::registries::REGISTRIES;
use super::{Db, NotEnrolled, append_audit, decode, encode};
use crate::subject::{Projects, Subject};

/// Key: `<registry ID>/<name>`. Value: JSON [`NamespaceRow`].
pub(super) const NAMESPACES: TableDefinition<&str, &[u8]> = TableDefinition::new("namespaces");

/// The most namespaces a registry has: a job's token carries at most one grant per
/// namespace, and a token holds [`vk_hub_proto::token::MAX_GRANTS`].
const MAX_NAMESPACES: usize = vk_hub_proto::token::MAX_GRANTS;
/// The most grant lines a namespace has.
const MAX_GRANTS: usize = 32;
/// The longest retention a namespace may ask for: ten years.
pub const MAX_RETENTION_DAYS: u64 = 3650;

/// The placeholders a path may hold.
const PLACEHOLDERS: [&str; 4] = ["{gitlab}", "{project_id}", "{pipeline_id}", "{protection}"];

/// A namespace as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceRow {
    pub name: String,
    /// The path template.
    pub path: String,
    /// Idle tags under it go after this many days; `None` for the registry's own window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u64>,
    pub grants: Vec<NsGrant>,
    pub created_at: u64,
    pub created_by: String,
}

/// A grant line: rights, and the jobs that get them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsGrant {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub lock: bool,
    pub subject: Subject,
}

impl NsGrant {
    /// `<rights>:<subject>`, rights a non-empty subset of `rwl`: `rw:own project`.
    pub fn parse(line: &str) -> Result<Self, String> {
        let (rights, subject) = line
            .split_once(':')
            .ok_or_else(|| format!("{line:?}: expected <rights>:<subject>, as rw:own project"))?;
        let rights = rights.trim();
        if rights.is_empty() || !rights.chars().all(|c| matches!(c, 'r' | 'w' | 'l')) {
            return Err(format!("{rights:?}: rights are some of r, w and l"));
        }
        Ok(NsGrant {
            read: rights.contains('r'),
            write: rights.contains('w'),
            lock: rights.contains('l'),
            subject: Subject::parse(subject.trim())?,
        })
    }

    fn rights(&self) -> String {
        [(self.read, 'r'), (self.write, 'w'), (self.lock, 'l')]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, c)| *c)
            .collect()
    }
}

impl std::fmt::Display for NsGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.rights(), self.subject)
    }
}

impl NamespaceRow {
    /// Why this namespace may not be stored, if it may not.
    pub fn check(&self) -> Result<(), String> {
        if !super::keys::valid_name(&self.name) {
            return Err(format!("{:?} is not a namespace's name", self.name));
        }
        let sample = sample_path(&self.path).ok_or_else(|| {
            format!(
                "{:?}: a path is a repository name, whose components may be {}",
                self.path,
                PLACEHOLDERS.join(", ")
            )
        })?;
        if !valid_prefix(&sample) {
            return Err(format!("{:?} is not a repository name", self.path));
        }
        if self.path.starts_with('{') {
            return Err(format!(
                "{:?}: a path starts with a fixed component, which keeps namespaces apart",
                self.path
            ));
        }
        match self.retention_days {
            Some(0) => return Err("a retention of 0 days would drop every tag".to_string()),
            Some(d) if d > MAX_RETENTION_DAYS => {
                return Err(format!("a retention is at most {MAX_RETENTION_DAYS} days"));
            }
            Some(_) if self.fixed_after_placeholder() => {
                return Err(format!(
                    "{:?}: a retention covers the path's leading fixed components, so it needs \
                     a path with no fixed component after a placeholder",
                    self.path
                ));
            }
            _ => {}
        }
        if self.grants.is_empty() || self.grants.len() > MAX_GRANTS {
            return Err(format!("a namespace has 1 to {MAX_GRANTS} grant lines"));
        }
        for g in &self.grants {
            g.subject.check_grant(g.write || g.lock)?;
            let has = |p: &str| self.path.split('/').any(|c| c == p);
            if g.subject.projects == Projects::Own && !(has("{gitlab}") && has("{project_id}")) {
                return Err("`own project` needs {gitlab} and {project_id} in the path".to_string());
            }
            if g.subject.own_pipeline && !(has("{gitlab}") && has("{pipeline_id}")) {
                return Err(
                    "`own pipeline` needs {gitlab} and {pipeline_id} in the path".to_string(),
                );
            }
        }
        Ok(())
    }

    /// Whether a fixed component follows a placeholder: `p/{gitlab}/dev`.
    fn fixed_after_placeholder(&self) -> bool {
        self.path
            .split('/')
            .skip_while(|c| !c.contains('{'))
            .any(|c| !c.contains('{'))
    }

    /// The leading components of the path before any placeholder, which a retention covers;
    /// `None` when the path starts with one.
    pub fn static_prefix(&self) -> Option<String> {
        let fixed: Vec<&str> = self
            .path
            .split('/')
            .take_while(|c| !c.contains('{'))
            .collect();
        (!fixed.is_empty()).then(|| fixed.join("/"))
    }
}

/// Why `ns` may not sit beside `others`, if it may not: a retention window covers its static
/// prefix whole, so it must not reach into another namespace that asks for another window.
fn check_retention_overlap(ns: &NamespaceRow, others: &[NamespaceRow]) -> Result<(), String> {
    let covers = |a: &NamespaceRow, b: &NamespaceRow| {
        a.retention_days.is_some()
            && a.retention_days != b.retention_days
            && a.static_prefix()
                .zip(b.static_prefix())
                .is_some_and(|(pa, pb)| vk_hub_proto::token::under(&pa, &pb))
    };
    for other in others {
        if covers(ns, other) || covers(other, ns) {
            return Err(format!(
                "namespaces {} and {} ask for different retentions under one prefix: a \
                 retention covers its namespace's leading fixed components whole",
                ns.name, other.name
            ));
        }
    }
    Ok(())
}

/// `path` with each placeholder filled by a sample value, to check it makes a repository
/// name; `None` when a component holds anything but one whole placeholder or none.
fn sample_path(path: &str) -> Option<String> {
    let mut out = Vec::new();
    for component in path.split('/') {
        out.push(match component {
            "{gitlab}" => "gl",
            "{project_id}" | "{pipeline_id}" => "1",
            "{protection}" => "protected",
            other if other.contains(['{', '}']) => return None,
            other => other,
        });
    }
    Some(out.join("/"))
}

fn ns_range(registry: &str) -> (String, String) {
    (format!("{registry}/"), format!("{registry}0"))
}

impl Db {
    /// Store namespace `ns` on registry `registry`, replacing one of its name, audited as
    /// `actor`'s.
    pub fn put_namespace(
        &self,
        registry: &str,
        ns: &NamespaceRow,
        actor: &str,
        now: u64,
    ) -> Result<()> {
        if let Err(why) = ns.check() {
            bail!("{why}");
        }
        let txn = self.db.begin_write().context("starting a write")?;
        if txn.open_table(REGISTRIES)?.get(registry)?.is_none() {
            return Err(NotEnrolled(registry.to_string()).into());
        }
        let replaced = {
            let mut table = txn.open_table(NAMESPACES)?;
            let (start, end) = ns_range(registry);
            let key = format!("{registry}/{}", ns.name);
            let replaced = table.get(key.as_str())?.is_some();
            if !replaced && table.range(start.as_str()..end.as_str())?.count() >= MAX_NAMESPACES {
                bail!("registry {registry} has {MAX_NAMESPACES} namespaces already");
            }
            let mut others = Vec::new();
            for entry in table.range(start.as_str()..end.as_str())? {
                let other = decode::<NamespaceRow>(entry?.1.value())?;
                if other.name != ns.name {
                    others.push(other);
                }
            }
            if let Err(why) = check_retention_overlap(ns, &others) {
                bail!("{why}");
            }
            table.insert(key.as_str(), encode(ns)?.as_slice())?;
            replaced
        };
        let grants: Vec<String> = ns.grants.iter().map(ToString::to_string).collect();
        let event = format!(
            "{actor} {} namespace {} at {}{} granting {}",
            if replaced { "replaced" } else { "added" },
            ns.name,
            ns.path,
            ns.retention_days
                .map_or(String::new(), |d| format!(", retention {d} days,")),
            grants.join("; ")
        );
        append_audit(&txn, Some(registry), actor, &event, now)?;
        txn.commit().context("storing a namespace")?;
        Ok(())
    }

    /// Registry `registry`'s namespaces, by name.
    pub fn namespaces(&self, registry: &str) -> Result<Vec<NamespaceRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(NAMESPACES)?;
        let (start, end) = ns_range(registry);
        let mut out = Vec::new();
        for entry in table.range(start.as_str()..end.as_str())? {
            out.push(decode::<NamespaceRow>(entry?.1.value())?);
        }
        Ok(out)
    }

    /// Remove namespace `name` of registry `registry`, audited as `actor`'s; whether there was
    /// one.
    pub fn remove_namespace(
        &self,
        registry: &str,
        name: &str,
        actor: &str,
        now: u64,
    ) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let key = format!("{registry}/{name}");
        let removed = txn.open_table(NAMESPACES)?.remove(key.as_str())?.is_some();
        if removed {
            let event = format!("{actor} removed namespace {name}");
            append_audit(&txn, Some(registry), actor, &event, now)?;
        }
        txn.commit().context("removing a namespace")?;
        Ok(removed)
    }
}

/// Remove every namespace of registry `registry` in `txn`, as its removal does.
pub(super) fn remove_namespaces_of(txn: &redb::WriteTransaction, registry: &str) -> Result<()> {
    let (start, end) = ns_range(registry);
    txn.open_table(NAMESPACES)?
        .retain_in(start.as_str()..end.as_str(), |_, _| false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(name: &str, path: &str, grants: &[&str], retention_days: Option<u64>) -> NamespaceRow {
        NamespaceRow {
            name: name.into(),
            path: path.into(),
            retention_days,
            grants: grants.iter().map(|g| NsGrant::parse(g).unwrap()).collect(),
            created_at: 0,
            created_by: "t".into(),
        }
    }

    #[test]
    fn a_namespace_is_checked_before_it_is_stored() {
        assert!(
            ns("x", "p/{gitlab}/{project_id}", &["rw:own project"], None)
                .check()
                .is_ok()
        );
        for bad in [
            ns("x", "p", &["rw:own project"], None),
            ns("x", "p/{project_id}", &["rw:own project"], None),
            ns("x", "p/{gitlab}/{pipeline_id}", &["rw:own project"], None),
            ns("x", "p/{pipeline_id}", &["rw:own pipeline"], None),
            ns("x", "{gitlab}/p", &["r:*"], None),
            ns("x", "p/{gitlab}/dev", &["r:*"], Some(3)),
            ns("x", "p", &["r:*"], Some(MAX_RETENTION_DAYS + 1)),
            ns("x", "P/{project_id}", &["r:*"], None),
            ns("x", "p/{nope}", &["r:*"], None),
            ns("x", "files/a", &["r:*"], None),
            ns("x", "p", &["w:ref release/*"], None),
            ns("x", "p", &["r:*"], Some(0)),
            ns("x", "p", &[], None),
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_retention_never_reaches_into_another_namespace() {
        let project = ns("project", "p/{gitlab}/{project_id}", &["r:*"], None);
        let pipelines = ns("pl", "p/{gitlab}/{pipeline_id}", &["r:*"], Some(3));
        assert!(check_retention_overlap(&pipelines, std::slice::from_ref(&project)).is_err());
        assert!(check_retention_overlap(&project, std::slice::from_ref(&pipelines)).is_err());
        let same = ns("pl2", "p/{pipeline_id}/{gitlab}", &["r:*"], Some(3));
        assert!(check_retention_overlap(&pipelines, std::slice::from_ref(&same)).is_ok());
        let apart = ns("images", "images", &["r:*"], None);
        assert!(check_retention_overlap(&pipelines, std::slice::from_ref(&apart)).is_ok());
        let narrower = ns("deep", "p/x", &["r:*"], Some(9));
        assert!(check_retention_overlap(&pipelines, std::slice::from_ref(&narrower)).is_err());
    }
}
