//! Registry namespaces: per registry, a path prefix, who may read, write or lock under it, and
//! how long its idle tags are kept. A job's registry token carries what the namespaces that
//! select it grant ([`resolve`]); the registry enforces the token and never sees this policy.
//!
//! A path is a template: `{gitlab}` (the hub's name for the job's GitLab instance),
//! `{project_id}`, `{pipeline_id}` and `{protection}` (`protected` or `unprotected`) are
//! filled from the job's claims when its token is minted. Only identifiers fill it, so two
//! namespaces never collide on a project's path.

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::dispatch::Area;
use vk_hub_proto::registry::PrefixRetention;
use vk_hub_proto::token::{ALIAS_ROOT, Grant, valid_component, valid_prefix};

use super::registries::REGISTRIES;
use super::{Db, NotEnrolled, append_audit, decode, encode};
use crate::subject::{JobClaims, Projects, Subject};

/// Key: `<registry ID>/<name>`. Value: JSON [`NamespaceRow`].
pub(super) const NAMESPACES: TableDefinition<&str, &[u8]> = TableDefinition::new("namespaces");

/// The namespace a job's CI caches go to: its path is the job's cache repository.
pub const CI_CACHE: &str = "ci-cache";
/// The namespace a pipeline's jobs share: its path is the job's pipeline prefix.
pub const CI_PIPELINE: &str = "ci-pipeline";

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
    /// What a job reaches the path by on its guest registry proxy, as `job/<alias>`: one
    /// repository name component, unique on the registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
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
        if self.under_alias_root() {
            return Err(format!(
                "{:?}: {ALIAS_ROOT}/ is where jobs reach aliases, so no path starts there",
                self.path
            ));
        }
        if let Some(alias) = &self.alias
            && !valid_component(alias)
        {
            return Err(format!(
                "{alias:?}: an alias is one repository name component, as task-cache"
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

    /// Whether the path starts at [`ALIAS_ROOT`], which [`NamespaceRow::check`] refuses for a
    /// namespace stored now; one stored before still may.
    fn under_alias_root(&self) -> bool {
        self.path.split('/').next() == Some(ALIAS_ROOT)
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

/// Why `ns`'s alias may not sit beside `others`, if it may not: another namespace has it, or
/// one stored before paths under [`ALIAS_ROOT`] were refused has such a path, which the alias
/// could hide.
fn check_alias(ns: &NamespaceRow, others: &[NamespaceRow]) -> Option<String> {
    let alias = ns.alias.as_ref()?;
    if let Some(other) = others.iter().find(|o| o.alias.as_ref() == Some(alias)) {
        return Some(format!(
            "namespace {} has the alias {alias} already",
            other.name
        ));
    }
    others.iter().find(|o| o.under_alias_root()).map(|o| {
        format!(
            "namespace {}'s path {} starts at {ALIAS_ROOT}/, where jobs reach aliases: move it \
             before giving any namespace an alias",
            o.name, o.path
        )
    })
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

/// `path` filled from `c`; `None` when a component holds anything but one whole placeholder
/// or none, or a value is missing (no pipeline) or does not fit a repository name.
pub fn render(path: &str, c: &JobClaims) -> Option<String> {
    let mut out = Vec::new();
    for component in path.split('/') {
        let value = match component {
            "{gitlab}" => c.gitlab.clone(),
            "{project_id}" => c.project_id.to_string(),
            "{pipeline_id}" if c.pipeline_id > 0 => c.pipeline_id.to_string(),
            "{pipeline_id}" => return None,
            "{protection}" => if c.protected {
                "protected"
            } else {
                "unprotected"
            }
            .to_string(),
            other if other.contains(['{', '}']) => return None,
            other => other.to_string(),
        };
        out.push(value);
    }
    let path = out.join("/");
    valid_prefix(&path).then_some(path)
}

/// What a job's token carries, from the namespaces of its registry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub grants: Vec<Grant>,
    /// [`CI_CACHE`]'s path for the job, when it selects the job.
    pub cache_repo: Option<String>,
    /// [`CI_PIPELINE`]'s path for the job, when it selects the job.
    pub pipeline_prefix: Option<String>,
    /// The aliases of the namespaces selecting the job, with the prefix each stands for.
    pub areas: Vec<Area>,
}

/// The grants the namespaces `ns` give the job claiming `c`: per namespace whose path fills,
/// the rights of every grant line selecting it, merged by prefix.
pub fn resolve(ns: &[NamespaceRow], c: &JobClaims) -> Resolved {
    let mut out = Resolved::default();
    for n in ns {
        let Some(prefix) = render(&n.path, c) else {
            continue;
        };
        let mut grant = Grant {
            prefix: prefix.clone(),
            ..Grant::default()
        };
        for g in n.grants.iter().filter(|g| g.subject.matches(c)) {
            grant.read |= g.read;
            grant.write |= g.write;
            grant.lock |= g.lock;
        }
        if !(grant.read || grant.write || grant.lock) {
            continue;
        }
        match n.name.as_str() {
            CI_CACHE => out.cache_repo = Some(prefix.clone()),
            CI_PIPELINE => out.pipeline_prefix = Some(prefix.clone()),
            _ => {}
        }
        if let Some(alias) = &n.alias {
            out.areas.push(Area {
                alias: alias.clone(),
                prefix: prefix.clone(),
            });
        }
        match out.grants.iter_mut().find(|g| g.prefix == prefix) {
            Some(g) => {
                g.read |= grant.read;
                g.write |= grant.write;
                g.lock |= grant.lock;
            }
            None => out.grants.push(grant),
        }
    }
    // One grant per namespace at most, and a registry holds at most a token's worth.
    debug_assert!(out.grants.len() <= vk_hub_proto::token::MAX_GRANTS);
    // A path under the alias root, stored before such paths were refused, could be hidden by
    // an alias: none are lent until it moves.
    if ns.iter().any(NamespaceRow::under_alias_root) {
        out.areas.clear();
    }
    out
}

/// The retention windows `ns` set, by static prefix: the longest where several share one.
pub fn prefix_retention(ns: &[NamespaceRow]) -> Vec<PrefixRetention> {
    let mut out: Vec<PrefixRetention> = Vec::new();
    for n in ns {
        let (Some(days), Some(prefix)) = (n.retention_days, n.static_prefix()) else {
            continue;
        };
        match out.iter_mut().find(|r| r.prefix == prefix) {
            Some(r) => r.retention_days = r.retention_days.max(days),
            None => out.push(PrefixRetention {
                prefix,
                retention_days: days,
            }),
        }
    }
    out.sort_by(|a, b| a.prefix.cmp(&b.prefix));
    out
}

/// The namespaces a registry starts with when it first takes tokens.
pub fn defaults(now: u64) -> Vec<NamespaceRow> {
    let grant = |line: &str| NsGrant::parse(line).unwrap_or_else(|e| unreachable!("{e}"));
    vec![
        NamespaceRow {
            name: CI_CACHE.into(),
            path: "ci-cache/{gitlab}/{project_id}/{protection}".into(),
            retention_days: None,
            alias: None,
            grants: vec![grant("rw:own project")],
            created_at: now,
            created_by: "hub".into(),
        },
        NamespaceRow {
            name: CI_PIPELINE.into(),
            path: "ci-pipeline/{gitlab}/{project_id}/{pipeline_id}".into(),
            retention_days: Some(2),
            alias: None,
            grants: vec![grant("rwl:own project, own pipeline")],
            created_at: now,
            created_by: "hub".into(),
        },
    ]
}

fn ns_range(registry: &str) -> (String, String) {
    (format!("{registry}/"), format!("{registry}0"))
}

/// Why `ns` may not be stored on registry `registry` beside the namespaces in `table`, if it
/// may not: the registry has [`MAX_NAMESPACES`] already, unless `ns` `replaces` one, or a
/// retention would reach into another namespace.
fn refusal(
    table: &redb::Table<&str, &[u8]>,
    registry: &str,
    ns: &NamespaceRow,
    replaces: bool,
) -> Result<Option<String>> {
    let (start, end) = ns_range(registry);
    if !replaces && table.range(start.as_str()..end.as_str())?.count() >= MAX_NAMESPACES {
        return Ok(Some(format!(
            "registry {registry} has {MAX_NAMESPACES} namespaces already"
        )));
    }
    let mut others = Vec::new();
    for entry in table.range(start.as_str()..end.as_str())? {
        let other = decode::<NamespaceRow>(entry?.1.value())?;
        if other.name != ns.name {
            others.push(other);
        }
    }
    if let Some(why) = check_alias(ns, &others) {
        return Ok(Some(why));
    }
    Ok(check_retention_overlap(ns, &others).err())
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
            let key = format!("{registry}/{}", ns.name);
            let replaced = table.get(key.as_str())?.is_some();
            if let Some(why) = refusal(&table, registry, ns, replaced)? {
                bail!("{why}");
            }
            table.insert(key.as_str(), encode(ns)?.as_slice())?;
            replaced
        };
        let grants: Vec<String> = ns.grants.iter().map(ToString::to_string).collect();
        let event = format!(
            "{actor} {} namespace {} at {}{}{} granting {}",
            if replaced { "replaced" } else { "added" },
            ns.name,
            ns.path,
            ns.alias
                .as_ref()
                .map_or(String::new(), |a| format!(", alias {a},")),
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

    /// Give registry `registry` the [`defaults`] it lacks, once, each held to the checks
    /// [`Db::put_namespace`] makes: one refused is skipped, and the audit log says why.
    /// Whether it got them now.
    pub fn seed_namespaces(&self, registry: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut events = Vec::new();
        let seeded = {
            let mut registries = txn.open_table(REGISTRIES)?;
            let Some(mut row) = registries
                .get(registry)?
                .map(|g| decode::<super::RegistryRow>(g.value()))
                .transpose()?
            else {
                return Err(NotEnrolled(registry.to_string()).into());
            };
            if row.namespaces_seeded {
                false
            } else {
                row.namespaces_seeded = true;
                registries.insert(registry, encode(&row)?.as_slice())?;
                let mut table = txn.open_table(NAMESPACES)?;
                for ns in defaults(now) {
                    let key = format!("{registry}/{}", ns.name);
                    if table.get(key.as_str())?.is_some() {
                        continue;
                    }
                    if let Some(why) = refusal(&table, registry, &ns, false)? {
                        events.push(format!("namespace {} not added by default: {why}", ns.name));
                        continue;
                    }
                    table.insert(key.as_str(), encode(&ns)?.as_slice())?;
                    events.push(format!("namespace {} added by default", ns.name));
                }
                true
            }
        };
        for event in &events {
            append_audit(&txn, Some(registry), "hub", event, now)?;
        }
        txn.commit().context("seeding namespaces")?;
        Ok(seeded)
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

    fn claims(protected: bool, pipeline_id: u64) -> JobClaims {
        JobClaims {
            gitlab: "gl".into(),
            project_id: 42,
            project_path: "wab/core".into(),
            git_ref: "main".into(),
            protected,
            pipeline_id,
        }
    }

    fn ns(name: &str, path: &str, grants: &[&str], retention_days: Option<u64>) -> NamespaceRow {
        NamespaceRow {
            name: name.into(),
            path: path.into(),
            retention_days,
            alias: None,
            grants: grants.iter().map(|g| NsGrant::parse(g).unwrap()).collect(),
            created_at: 0,
            created_by: "t".into(),
        }
    }

    #[test]
    fn paths_fill_from_identifiers_only() {
        let c = claims(true, 7);
        assert_eq!(
            render("ci-cache/{gitlab}/{project_id}/{protection}", &c).as_deref(),
            Some("ci-cache/gl/42/protected")
        );
        assert_eq!(render("p/{pipeline_id}", &claims(false, 0)), None);
        assert_eq!(render("p/x{project_id}", &c), None);
        assert_eq!(render("p/{project_path}", &c), None);
        assert_eq!(render("images", &c).as_deref(), Some("images"));
    }

    #[test]
    fn defaults_resolve_to_the_cache_and_pipeline() {
        let r = resolve(&defaults(0), &claims(false, 7));
        assert_eq!(r.cache_repo.as_deref(), Some("ci-cache/gl/42/unprotected"));
        assert_eq!(r.pipeline_prefix.as_deref(), Some("ci-pipeline/gl/42/7"));
        assert_eq!(r.grants.len(), 2);
        assert_eq!(r.grants[0].rights(), "rw");
        assert_eq!(r.grants[1].rights(), "rwl");
        let no_pipeline = resolve(&defaults(0), &claims(true, 0));
        assert_eq!(no_pipeline.pipeline_prefix, None);
        assert_eq!(no_pipeline.grants.len(), 1);
        for d in defaults(0) {
            d.check().unwrap();
        }
    }

    #[test]
    fn grants_add_up_and_select_by_subject() {
        let all = [
            ns(
                "images",
                "images",
                &["r:*", "w:gitlab gl, projects infra/images, protected"],
                None,
            ),
            ns(
                "wab",
                "wab",
                &[
                    "rwl:gitlab gl, projects wab/**, protected",
                    "r:gitlab gl, projects wab/**",
                ],
                None,
            ),
            ns("wab-ro", "wab", &["r:*"], None),
        ];
        let r = resolve(&all, &claims(false, 7));
        let got: Vec<(String, String)> = r
            .grants
            .iter()
            .map(|g| (g.prefix.clone(), g.rights()))
            .collect();
        assert_eq!(
            got,
            vec![("images".into(), "r".into()), ("wab".into(), "r".into())]
        );
        let r = resolve(&all, &claims(true, 7));
        assert_eq!(r.grants[1].rights(), "rwl");
        // Another instance's project of the same path gets what any job gets, no more.
        let other = JobClaims {
            gitlab: "gl2".into(),
            ..claims(true, 7)
        };
        let r = resolve(&all, &other);
        let got: Vec<(String, String)> = r
            .grants
            .iter()
            .map(|g| (g.prefix.clone(), g.rights()))
            .collect();
        assert_eq!(
            got,
            vec![("images".into(), "r".into()), ("wab".into(), "r".into())]
        );
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
    fn seeding_holds_the_defaults_to_the_same_checks() {
        use crate::store::{AuditFilter, RegistryEnrollment, TokenKind};
        let db = Db::open_memory().unwrap();
        let enroll = |key: &str| {
            let ttl = std::time::Duration::from_secs(60);
            let (token, _) = db
                .create_token_for(TokenKind::Registry, ttl, None, "u", 1)
                .unwrap();
            let RegistryEnrollment::Enrolled { id } =
                db.enroll_registry(&token, key, "reg", "p", 1).unwrap()
            else {
                panic!("not enrolled");
            };
            id
        };
        let (full, overlapping) = (enroll("aa"), enroll("bb"));
        for i in 0..MAX_NAMESPACES {
            let n = ns(&format!("n{i}"), &format!("p{i}"), &["r:*"], None);
            db.put_namespace(&full, &n, "u", 1).unwrap();
        }
        let wider = ns("wider", "ci-pipeline", &["r:*"], Some(9));
        db.put_namespace(&overlapping, &wider, "u", 1).unwrap();
        assert!(db.seed_namespaces(&full, 2).unwrap());
        assert!(db.seed_namespaces(&overlapping, 2).unwrap());
        assert_eq!(db.namespaces(&full).unwrap().len(), MAX_NAMESPACES);
        let names: Vec<String> = db
            .namespaces(&overlapping)
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .collect();
        assert_eq!(names, [CI_CACHE, "wider"]);
        let events: Vec<String> = db
            .audit_search(&AuditFilter::default(), None, 100)
            .unwrap()
            .rows
            .into_iter()
            .map(|(_, r)| r.event)
            .collect();
        assert!(
            events
                .iter()
                .any(|e| e.starts_with("namespace ci-pipeline not added by default: ")),
            "{events:?}"
        );
        assert!(!db.seed_namespaces(&overlapping, 3).unwrap());
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

    #[test]
    fn retention_covers_the_static_prefix() {
        let all = [
            ns("a", "ci-pipeline/{gitlab}/{project_id}", &["r:*"], Some(2)),
            ns("b", "ci-pipeline/x", &["r:*"], Some(5)),
            ns("c", "x/{gitlab}", &["r:*"], None),
            ns("d", "images", &["r:*"], None),
        ];
        assert_eq!(
            prefix_retention(&all),
            vec![
                PrefixRetention {
                    prefix: "ci-pipeline".into(),
                    retention_days: 2
                },
                PrefixRetention {
                    prefix: "ci-pipeline/x".into(),
                    retention_days: 5
                },
            ]
        );
    }

    fn aliased(name: &str, path: &str, alias: &str) -> NamespaceRow {
        NamespaceRow {
            alias: Some(alias.into()),
            ..ns(name, path, &["rwl:own project"], None)
        }
    }

    #[test]
    fn an_alias_is_one_component_and_no_path_starts_at_the_alias_root() {
        aliased(
            "tc",
            "task-cache/{gitlab}/{project_id}/{protection}",
            "task-cache",
        )
        .check()
        .unwrap();
        for bad in ["Task", "a/b", "", "-a", "job x"] {
            let n = aliased("tc", "task-cache/{gitlab}/{project_id}", bad);
            assert!(n.check().is_err(), "{bad:?}");
        }
        assert!(
            ns("j", "job/{gitlab}/{project_id}", &["r:*"], None)
                .check()
                .is_err()
        );
        ns("j", "jobs/{gitlab}/{project_id}", &["r:*"], None)
            .check()
            .unwrap();
    }

    #[test]
    fn a_job_gets_the_areas_selecting_it() {
        let all = [
            aliased(
                "tc",
                "task-cache/{gitlab}/{project_id}/{protection}",
                "task-cache",
            ),
            aliased("other", "other/{gitlab}/{project_id}", "other"),
            ns(
                "plain",
                "plain/{gitlab}/{project_id}",
                &["r:own project"],
                None,
            ),
        ];
        let r = resolve(&all, &claims(false, 7));
        assert_eq!(
            r.areas,
            vec![
                Area {
                    alias: "task-cache".into(),
                    prefix: "task-cache/gl/42/unprotected".into(),
                },
                Area {
                    alias: "other".into(),
                    prefix: "other/gl/42".into(),
                },
            ]
        );
        // A path under the alias root, stored before it was refused, withholds every area.
        let mut legacy = all.to_vec();
        legacy.push(ns("old", "job/x", &["r:*"], None));
        assert!(resolve(&legacy, &claims(false, 7)).areas.is_empty());
    }

    #[test]
    fn aliases_are_unique_and_wait_for_paths_under_the_alias_root_to_move() {
        use crate::store::{RegistryEnrollment, TokenKind};
        let db = Db::open_memory().unwrap();
        let ttl = std::time::Duration::from_secs(60);
        let (token, _) = db
            .create_token_for(TokenKind::Registry, ttl, None, "u", 1)
            .unwrap();
        let RegistryEnrollment::Enrolled { id } =
            db.enroll_registry(&token, "aa", "reg", "p", 1).unwrap()
        else {
            panic!("not enrolled");
        };
        let tc = aliased("tc", "task-cache/{gitlab}/{project_id}", "task-cache");
        db.put_namespace(&id, &tc, "u", 1).unwrap();
        // Replacing itself keeps its alias.
        db.put_namespace(&id, &tc, "u", 2).unwrap();
        let dup = aliased("tc2", "tc2/{gitlab}/{project_id}", "task-cache");
        let err = db.put_namespace(&id, &dup, "u", 3).unwrap_err().to_string();
        assert!(err.contains("has the alias task-cache already"), "{err}");

        // A namespace under `job/` from before the check, written as an older hub stored it.
        let legacy = ns("old", "job/x", &["r:*"], None);
        let txn = db.db.begin_write().unwrap();
        txn.open_table(NAMESPACES)
            .unwrap()
            .insert(
                format!("{id}/old").as_str(),
                encode(&legacy).unwrap().as_slice(),
            )
            .unwrap();
        txn.commit().unwrap();
        let other = aliased("o", "o/{gitlab}/{project_id}", "o");
        let err = db
            .put_namespace(&id, &other, "u", 4)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("move it before giving any namespace an alias"),
            "{err}"
        );
    }
}
