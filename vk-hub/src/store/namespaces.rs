//! Registry namespaces: per registry, a path prefix, who may read, write or lock under it, and
//! how long its idle tags are kept. A job's registry token carries what the namespaces that
//! select it grant ([`resolve`]), a node's what they grant nodes ([`resolve_node`]); the
//! registry enforces the token and never sees this policy.
//!
//! A path is a template: `{gitlab}` (the hub's name for the job's GitLab instance),
//! `{project_id}`, `{pipeline_id}`, `{protection}` (`protected` or `unprotected`) and
//! `{scope}` ([`scope`]) are filled from the job's claims when its token is minted. Only
//! identifiers fill it, so two namespaces never collide on a project's path.

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vk_hub_proto::dispatch::Area;
use vk_hub_proto::job::RefType;
use vk_hub_proto::registry::PrefixRetention;
use vk_hub_proto::token::{
    ALIAS_ROOT, Grant, MAX_PREFIX_COMPONENTS, MAX_PREFIX_LEN, RESERVED_COMPONENTS, servable_prefix,
    under, valid_component,
};

use super::registries::REGISTRIES;
use super::{Db, NotEnrolled, append_audit, decode, encode};
use crate::subject::{JobClaims, Projects, Subject};

/// Key: `<registry ID>/<name>`. Value: JSON [`NamespaceRow`].
pub(super) const NAMESPACES: TableDefinition<&str, &[u8]> = TableDefinition::new("namespaces");

/// The namespace a job's CI caches go to: its path is the job's cache repository.
pub const CI_CACHE: &str = "ci-cache";
/// The namespace a pipeline's jobs share: its path is the job's pipeline prefix.
pub const CI_PIPELINE: &str = "ci-pipeline";
/// The job's build-cache namespace: its path is the build prefix, with layers under
/// [`BUILD_CACHE_REPO`].
pub const CI_BUILD: &str = "ci-build";
/// The repository under a job's build prefix that holds its build cache.
pub const BUILD_CACHE_REPO: &str = "build-cache";
/// The placeholders a [`CI_BUILD`] path must hold, so a job's build cache is its project's,
/// protection's and scope's alone.
const CI_BUILD_PLACEHOLDERS: [&str; 4] = ["{gitlab}", "{project_id}", "{protection}", "{scope}"];

/// The most namespaces a registry has: a job's token carries at most one grant per
/// namespace, and a token holds [`vk_hub_proto::token::MAX_GRANTS`].
const MAX_NAMESPACES: usize = vk_hub_proto::token::MAX_GRANTS;
/// The most grant lines a namespace has.
const MAX_GRANTS: usize = 32;
/// The longest retention a namespace may ask for: ten years.
pub const MAX_RETENTION_DAYS: u64 = 3650;

/// The placeholders a path may hold.
pub const PLACEHOLDERS: [&str; 5] = [
    "{gitlab}",
    "{project_id}",
    "{pipeline_id}",
    "{protection}",
    "{scope}",
];

/// The most isolated ref globs a namespace takes.
const MAX_ISOLATE: usize = 32;

/// How many characters of a ref [`scope`] keeps, and how many hex digits of its hash.
const SCOPE_SLUG: usize = 32;
const SCOPE_HASH: usize = 32;

/// `{scope}` for a job whose ref no isolated glob matches.
const SHARED_SCOPE: &str = "all";

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
    /// Ref globs whose jobs get a `{scope}` of their own ([`scope`]); none fills `all` for
    /// every job.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub isolate: Vec<String>,
    /// The grant lines selecting jobs; always written, even empty, as older hubs require it.
    pub grants: Vec<NsGrant>,
    /// The grant lines selecting nodes, kept apart from [`NamespaceRow::grants`] so that a
    /// hub that does not know them ignores them rather than reading them as job grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_grants: Vec<NodeGrant>,
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

/// A grant line's rights and subject text: `<rights>:<subject>`, rights a non-empty subset of
/// `rwl`, as `(read, write, lock)`.
fn split_line(line: &str) -> Result<((bool, bool, bool), &str), String> {
    let (rights, subject) = line
        .split_once(':')
        .ok_or_else(|| format!("{line:?}: expected <rights>:<subject>, as rw:own project"))?;
    let rights = rights.trim();
    if rights.is_empty() || !rights.chars().all(|c| matches!(c, 'r' | 'w' | 'l')) {
        return Err(format!("{rights:?}: rights are some of r, w and l"));
    }
    Ok((
        (
            rights.contains('r'),
            rights.contains('w'),
            rights.contains('l'),
        ),
        subject.trim(),
    ))
}

fn rights_text(read: bool, write: bool, lock: bool) -> String {
    [(read, 'r'), (write, 'w'), (lock, 'l')]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, c)| *c)
        .collect()
}

impl NsGrant {
    /// `<rights>:<subject>`, rights a non-empty subset of `rwl`: `rw:own project`.
    pub fn parse(line: &str) -> Result<Self, String> {
        let ((read, write, lock), subject) = split_line(line)?;
        Ok(NsGrant {
            read,
            write,
            lock,
            subject: Subject::parse(subject)?,
        })
    }
}

impl std::fmt::Display for NsGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rights = rights_text(self.read, self.write, self.lock);
        write!(f, "{rights}:{}", self.subject)
    }
}

/// The nodes a node grant selects, or the guests of the jobs nodes run for their own runners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nodes {
    /// `nodes`: every node.
    All,
    /// `node <id>`: the node enrolled under that ID.
    One(String),
    /// `guests`: the guests of jobs no hub placed, which nodes run for a gitlab-runner of their
    /// own, within what their node is granted ([`resolve_guest`]). Selects no node.
    Guests,
}

impl Nodes {
    /// `nodes`, `node <id>` or `guests`; `None` for any other subject, which may be a job's.
    fn parse(text: &str) -> Option<Result<Self, String>> {
        let words: Vec<&str> = text.split_whitespace().collect();
        match words.as_slice() {
            ["nodes"] => Some(Ok(Nodes::All)),
            ["guests"] => Some(Ok(Nodes::Guests)),
            ["node", id] if vk_hub_proto::valid_id(id) => Some(Ok(Nodes::One((*id).to_string()))),
            ["node", id] => Some(Err(format!(
                "{id:?} is not a node's ID: 32 lowercase hex digits, as `vk-hub nodes` lists them"
            ))),
            ["node" | "nodes" | "guests", ..] => Some(Err(format!(
                "{text:?}: a node subject is `nodes`, `node <id>` or `guests`, alone"
            ))),
            _ => None,
        }
    }

    /// Whether it selects node `id`.
    pub fn matches(&self, id: &str) -> bool {
        match self {
            Nodes::All => true,
            Nodes::One(one) => one == id,
            Nodes::Guests => false,
        }
    }
}

impl std::fmt::Display for Nodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Nodes::All => f.write_str("nodes"),
            Nodes::One(id) => write!(f, "node {id}"),
            Nodes::Guests => f.write_str("guests"),
        }
    }
}

/// A grant line for nodes: rights, and the nodes that get them in their own tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeGrant {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub lock: bool,
    pub nodes: Nodes,
}

impl std::fmt::Display for NodeGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rights = rights_text(self.read, self.write, self.lock);
        write!(f, "{rights}:{}", self.nodes)
    }
}

/// Grant lines as `vk-hub namespaces add --grant` takes them, `<rights>:<subject>`, split into
/// those selecting jobs and those selecting nodes (`nodes`, `node <id>`).
pub fn parse_grants<S: AsRef<str>>(lines: &[S]) -> Result<(Vec<NsGrant>, Vec<NodeGrant>), String> {
    let (mut jobs, mut nodes) = (Vec::new(), Vec::new());
    for line in lines {
        let line = line.as_ref();
        let ((read, write, lock), subject) = split_line(line)?;
        match Nodes::parse(subject) {
            Some(n) => nodes.push(NodeGrant {
                read,
                write,
                lock,
                nodes: n?,
            }),
            None => jobs.push(NsGrant::parse(line)?),
        }
    }
    Ok((jobs, nodes))
}

impl NamespaceRow {
    /// Why this namespace may not be stored, if it may not.
    pub fn check(&self) -> Result<(), String> {
        if !super::keys::valid_name(&self.name) {
            return Err(format!("{:?} is not a namespace's name", self.name));
        }
        let longest = longest_path(&self.path).ok_or_else(|| {
            format!(
                "{:?}: a path is a repository name, whose components may be {}",
                self.path,
                PLACEHOLDERS.join(", ")
            )
        })?;
        let longest = match self.name.as_str() {
            CI_BUILD => format!("{longest}/{BUILD_CACHE_REPO}"),
            _ => longest,
        };
        if !servable_prefix(&longest) {
            return Err(format!(
                "{:?} is not a repository name for every job: at its longest, {longest:?}, it \
                 must be at most {MAX_PREFIX_LEN} characters and {MAX_PREFIX_COMPONENTS} \
                 components of lowercase letters, digits and . _ -, none of them {}",
                self.path,
                RESERVED_COMPONENTS.join(", ")
            ));
        }
        if self.isolate.len() > MAX_ISOLATE {
            return Err(format!(
                "a namespace takes at most {MAX_ISOLATE} isolated ref globs"
            ));
        }
        for glob in &self.isolate {
            crate::subject::check_glob(glob)?;
        }
        if !self.isolate.is_empty() && !self.has_scope() {
            return Err(format!(
                "{:?}: isolating refs needs {{scope}} in the path, which their jobs fill apart",
                self.path
            ));
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
        let lines = self.grants.len().saturating_add(self.node_grants.len());
        if lines == 0 || lines > MAX_GRANTS {
            return Err(format!("a namespace has 1 to {MAX_GRANTS} grant lines"));
        }
        if !self.node_grants.is_empty() && !self.literal() {
            return Err(format!(
                "{:?}: nodes are granted only paths without placeholders: a node has no \
                 project, pipeline, protection or scope to fill one with",
                self.path
            ));
        }
        if self.name == CI_BUILD {
            self.check_ci_build()?;
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

    /// Why this [`CI_BUILD`] namespace may not be stored, if it may not: its path must name
    /// the job's instance, project, protection and scope, and its grants select only by `own
    /// project`, so no job reaches another's build cache through it.
    fn check_ci_build(&self) -> Result<(), String> {
        let components: Vec<&str> = self.path.split('/').collect();
        if let Some(missing) = CI_BUILD_PLACEHOLDERS
            .iter()
            .find(|p| !components.contains(p))
        {
            return Err(format!(
                "{:?}: a {CI_BUILD} path must hold {}; it lacks {missing}",
                self.path,
                CI_BUILD_PLACEHOLDERS.join(", ")
            ));
        }
        if let Some(g) = self.node_grants.first() {
            return Err(format!(
                "{g}: {CI_BUILD} grants only to `own project`, so no job reaches another's \
                 build cache"
            ));
        }
        let own = Subject {
            projects: Projects::Own,
            ..Subject::default()
        };
        if let Some(g) = self.grants.iter().find(|g| g.subject != own) {
            return Err(format!(
                "{g}: {CI_BUILD} grants only to `own project`, so no job reaches another's \
                 build cache"
            ));
        }
        Ok(())
    }

    /// Whether the path has no placeholder, the only kind of path nodes are granted.
    fn literal(&self) -> bool {
        !self.path.contains(['{', '}'])
    }

    /// Whether the path holds `{scope}`.
    pub fn has_scope(&self) -> bool {
        self.path.split('/').any(|c| c == "{scope}")
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

/// A namespace whose path holds `{scope}` reserves its root, its path's leading fixed
/// components, and no other namespace's path may, at any filling, lie above, at or under it.
/// Grants add up across namespaces and a prefix covers what is beneath it, so another
/// namespace reaching there could hand a job every protection and scope of it.
fn check_reserved_root(ns: &NamespaceRow, others: &[NamespaceRow]) -> Option<String> {
    for other in others {
        for (scoped, beside) in [(ns, other), (other, ns)] {
            if !scoped.has_scope() {
                continue;
            }
            // A path starting with a placeholder has no root to reserve; one is refused when
            // stored, and a legacy row keeps its place.
            let Some(root) = scoped.static_prefix() else {
                continue;
            };
            if may_meet(&root, &beside.path) {
                return Some(format!(
                    "namespace {}'s path {} could reach {root}, which namespace {} reserves for \
                     its scopes: grants add up, so it would reach scopes there",
                    beside.name, beside.path, scoped.name
                ));
            }
        }
    }
    None
}

/// Whether some filling of the templates `a` and `b` makes one at or under the other: every
/// component they both have may fill alike ([`may_fill`]).
fn may_meet(a: &str, b: &str) -> bool {
    a.split('/')
        .zip(b.split('/'))
        .all(|(x, y)| match (x.starts_with('{'), y.starts_with('{')) {
            (false, false) => x == y,
            (true, false) => may_fill(x, y),
            (false, true) => may_fill(y, x),
            // Two placeholders may fill alike: an instance name may be all digits, say.
            (true, true) => true,
        })
}

/// Whether `placeholder` may fill as the fixed component `fixed` for some job; it errs toward
/// yes: any value of the placeholder's shape counts.
fn may_fill(placeholder: &str, fixed: &str) -> bool {
    match placeholder {
        "{gitlab}" => super::gitlabs::valid_gitlab_name(fixed),
        "{project_id}" | "{pipeline_id}" => {
            fixed.bytes().all(|b| b.is_ascii_digit()) && fixed.parse::<u64>().is_ok()
        }
        "{protection}" => fixed == "protected" || fixed == "unprotected",
        "{scope}" => fixed == SHARED_SCOPE || fixed.starts_with("ref-"),
        _ => true,
    }
}

/// Refuse `ns`'s alias if another namespace has it or a legacy path under [`ALIAS_ROOT`]
/// could be hidden by it.
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

/// Expand each placeholder to its maximum length to validate every job's path.
/// `None` unless each component contains one whole placeholder or none.
/// Placeholder values are valid components; only length, component count and fixed components
/// can make the expanded path invalid.
fn longest_path(path: &str) -> Option<String> {
    let mut out = Vec::new();
    for component in path.split('/') {
        out.push(match component {
            "{gitlab}" => "a".repeat(super::gitlabs::MAX_GITLAB_NAME),
            "{project_id}" | "{pipeline_id}" => u64::MAX.to_string(),
            "{protection}" => "unprotected".to_string(),
            "{scope}" => format!("ref-{}-{}", "a".repeat(SCOPE_SLUG), "0".repeat(SCOPE_HASH)),
            other if other.contains(['{', '}']) => return None,
            other => other.to_string(),
        });
    }
    Some(out.join("/"))
}

/// `{scope}` for the job claiming `c`, in a namespace isolating the refs `isolate`:
/// - `all` when none of the globs matches its ref;
/// - when one does, `ref-`, the ref lowercased with each run of characters outside `[a-z0-9]`
///   turned into `-`, cut to 32 characters and trimmed of `-` (`x` if nothing is left), then
///   `-` and the first 32 hex digits of the SHA-256 of `<kind>:<ref>`, so two refs, or a
///   branch and a tag of one name, do not share one in practice;
/// - `None`, giving the job nothing, when one does but GitLab named no ref kind the hub
///   knows, or the job has no ref while the namespace isolates any.
///
/// `all` and `ref-…` never coincide and neither is under the other, so no grant on one covers
/// another.
pub fn scope(isolate: &[String], c: &JobClaims) -> Option<String> {
    if isolate.is_empty() {
        return Some(SHARED_SCOPE.to_string());
    }
    if c.git_ref.is_empty() {
        return None;
    }
    if !isolate
        .iter()
        .any(|g| crate::subject::glob_match(g, &c.git_ref))
    {
        return Some(SHARED_SCOPE.to_string());
    }
    let kind = match c.ref_type? {
        RefType::Branch => "branch",
        RefType::Tag => "tag",
    };
    let mut slug = String::new();
    for ch in c.git_ref.chars().map(|ch| ch.to_ascii_lowercase()) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            slug.push(ch);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.truncate(SCOPE_SLUG);
    let slug = match slug.trim_end_matches('-') {
        "" => "x",
        s => s,
    };
    let hash = vk_hub_proto::to_hex(&Sha256::digest(format!("{kind}:{}", c.git_ref).as_bytes()));
    Some(format!("ref-{slug}-{}", &hash[..SCOPE_HASH]))
}

/// `ns`'s path filled from `c`; `None` when a component holds anything but one whole
/// placeholder or none, or a value is missing (no pipeline, no [`scope`]) or does not fit a
/// repository name.
pub fn render(ns: &NamespaceRow, c: &JobClaims) -> Option<String> {
    let mut out = Vec::new();
    for component in ns.path.split('/') {
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
            "{scope}" => scope(&ns.isolate, c)?,
            other if other.contains(['{', '}']) => return None,
            other => other.to_string(),
        };
        out.push(value);
    }
    let path = out.join("/");
    servable_prefix(&path).then_some(path)
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
    /// [`CI_BUILD`]'s path for the job, when it selects the job.
    pub build_prefix: Option<String>,
}

/// The grants the namespaces `ns` give the job claiming `c`: per namespace whose path fills,
/// the rights of every grant line selecting it, merged by prefix.
pub fn resolve(ns: &[NamespaceRow], c: &JobClaims) -> Resolved {
    let mut out = Resolved::default();
    for n in ns {
        let Some(prefix) = render(n, c) else {
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
            // Legacy namespaces keep their grants but supply a build prefix only if they pass
            // the checks, so no job's builds land where another project's may.
            CI_BUILD if n.check_ci_build().is_ok() => out.build_prefix = Some(prefix.clone()),
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

/// The grants the namespaces `ns` give node `node` in its own token: per namespace with a
/// literal path, the rights of every node grant line selecting it, merged by prefix. A path
/// reaching a root another namespace reserves for its scopes, which the hub refuses to store
/// beside node grants, gives nothing all the same: nodes never reach jobs' scopes.
pub fn resolve_node(ns: &[NamespaceRow], node: &str) -> Vec<Grant> {
    resolve_lines(ns, |n| n.matches(node))
}

/// The grants the namespaces `ns` give the guests of node `node`'s own runner's jobs, in the
/// token it lends them: what lines for `guests` grant, within what node `node` is granted.
/// Where one grant's prefix lies under the other's, the deeper prefix gets the rights both
/// hold. None unless namespaces grant guests.
pub fn resolve_guest(ns: &[NamespaceRow], node: &str) -> Vec<Grant> {
    let guests = resolve_lines(ns, |n| *n == Nodes::Guests);
    if guests.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<Grant> = Vec::new();
    for host in resolve_node(ns, node) {
        for guest in &guests {
            let prefix = if under(&host.prefix, &guest.prefix) {
                &guest.prefix
            } else if under(&guest.prefix, &host.prefix) {
                &host.prefix
            } else {
                continue;
            };
            let grant = Grant {
                prefix: prefix.clone(),
                read: host.read && guest.read,
                write: host.write && guest.write,
                lock: host.lock && guest.lock,
            };
            merge(&mut out, grant);
        }
    }
    out
}

/// Add `grant` to `out`, merging its rights into a grant of the same prefix; nothing for a
/// grant of no rights.
fn merge(out: &mut Vec<Grant>, grant: Grant) {
    if !(grant.read || grant.write || grant.lock) {
        return;
    }
    match out.iter_mut().find(|g| g.prefix == grant.prefix) {
        Some(g) => {
            g.read |= grant.read;
            g.write |= grant.write;
            g.lock |= grant.lock;
        }
        None => out.push(grant),
    }
}

/// The grants of the node grant lines in `ns` whose subject `select` takes, as
/// [`resolve_node`] gathers them.
fn resolve_lines(ns: &[NamespaceRow], select: impl Fn(&Nodes) -> bool) -> Vec<Grant> {
    let mut out: Vec<Grant> = Vec::new();
    for (i, n) in ns.iter().enumerate() {
        if !n.literal() || !servable_prefix(&n.path) {
            continue;
        }
        let mut grant = Grant {
            prefix: n.path.clone(),
            ..Grant::default()
        };
        for g in n.node_grants.iter().filter(|g| select(&g.nodes)) {
            grant.read |= g.read;
            grant.write |= g.write;
            grant.lock |= g.lock;
        }
        if !(grant.read || grant.write || grant.lock) {
            continue;
        }
        let others: Vec<NamespaceRow> = ns
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, o)| o.clone())
            .collect();
        if check_reserved_root(n, &others).is_some() {
            continue;
        }
        merge(&mut out, grant);
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

/// The namespaces a registry starts with when it first takes tokens; a registry that took
/// them before [`CI_BUILD`] was one gets that one later, once.
pub fn defaults(now: u64) -> Vec<NamespaceRow> {
    let grant = |line: &str| NsGrant::parse(line).unwrap_or_else(|e| unreachable!("{e}"));
    vec![
        NamespaceRow {
            name: CI_CACHE.into(),
            path: "ci-cache/{gitlab}/{project_id}/{protection}".into(),
            retention_days: None,
            alias: None,
            isolate: Vec::new(),
            grants: vec![grant("rw:own project")],
            node_grants: Vec::new(),
            created_at: now,
            created_by: "hub".into(),
        },
        NamespaceRow {
            name: CI_PIPELINE.into(),
            path: "ci-pipeline/{gitlab}/{project_id}/{pipeline_id}".into(),
            retention_days: Some(2),
            alias: None,
            isolate: Vec::new(),
            grants: vec![grant("rwl:own project, own pipeline")],
            node_grants: Vec::new(),
            created_at: now,
            created_by: "hub".into(),
        },
        NamespaceRow {
            name: CI_BUILD.into(),
            path: "ci-build/{gitlab}/{project_id}/{protection}/{scope}".into(),
            retention_days: Some(14),
            alias: None,
            isolate: Vec::new(),
            grants: vec![grant("rwl:own project")],
            node_grants: Vec::new(),
            created_at: now,
            created_by: "hub".into(),
        },
    ]
}

pub(super) fn ns_range(registry: &str) -> (String, String) {
    (format!("{registry}/"), format!("{registry}0"))
}

/// Why `ns` may not be stored on registry `registry` beside the namespaces in `table`, if it
/// may not: the registry has [`MAX_NAMESPACES`] already, unless `ns` `replaces` one; another
/// namespace has `ns`'s alias, or `ns` has one while another's path lies under [`ALIAS_ROOT`]
/// ([`check_alias`]); a path would reach a root another reserves for its scopes
/// ([`check_reserved_root`]); or a retention would reach into another namespace.
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
    if let Some(why) = check_reserved_root(ns, &others) {
        return Ok(Some(why));
    }
    Ok(check_retention_overlap(ns, &others).err())
}

impl Db {
    /// Store namespace `ns` on registry `registry`, replacing one of its name, audited as
    /// `actor`'s.
    #[cfg(test)]
    pub fn put_namespace(
        &self,
        registry: &str,
        ns: &NamespaceRow,
        actor: &str,
        now: u64,
    ) -> Result<()> {
        self.put_namespace_with(registry, ns.clone(), false, actor, now)
            .map(drop)
    }

    /// Like [`Db::put_namespace`], but preserves existing isolated refs when `keep_isolate`:
    /// older CLIs omit them. Reads them in the same transaction; returns the stored namespace.
    pub fn put_namespace_with(
        &self,
        registry: &str,
        mut ns: NamespaceRow,
        keep_isolate: bool,
        actor: &str,
        now: u64,
    ) -> Result<NamespaceRow> {
        let txn = self.db.begin_write().context("starting a write")?;
        if txn.open_table(REGISTRIES)?.get(registry)?.is_none() {
            return Err(NotEnrolled(registry.to_string()).into());
        }
        let replaced = {
            let mut table = txn.open_table(NAMESPACES)?;
            let key = format!("{registry}/{}", ns.name);
            let old = table
                .get(key.as_str())?
                .map(|g| decode::<NamespaceRow>(g.value()))
                .transpose()?;
            if keep_isolate && let Some(old) = &old {
                ns.isolate.clone_from(&old.isolate);
            }
            if let Err(why) = ns.check() {
                bail!("{why}");
            }
            if let Some(why) = refusal(&table, registry, &ns, old.is_some())? {
                bail!("{why}");
            }
            table.insert(key.as_str(), encode(&ns)?.as_slice())?;
            old.is_some()
        };
        let grants: Vec<String> = ns
            .grants
            .iter()
            .map(ToString::to_string)
            .chain(ns.node_grants.iter().map(ToString::to_string))
            .collect();
        let event = format!(
            "{actor} {} namespace {} at {}{}{}{} granting {}",
            if replaced { "replaced" } else { "added" },
            ns.name,
            ns.path,
            ns.alias
                .as_ref()
                .map_or(String::new(), |a| format!(", alias {a},")),
            ns.retention_days
                .map_or(String::new(), |d| format!(", retention {d} days,")),
            if ns.isolate.is_empty() {
                String::new()
            } else {
                format!(", isolating {},", ns.isolate.join(" "))
            },
            grants.join("; ")
        );
        append_audit(&txn, Some(registry), actor, &event, now)?;
        txn.commit().context("storing a namespace")?;
        Ok(ns)
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
    /// [`Db::put_namespace`] makes: one refused is skipped, and the audit log says why. A
    /// registry seeded before [`CI_BUILD`] was a default gets that one alone, once. Whether it
    /// ran now.
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
            if row.namespaces_seeded && row.build_cache_seeded {
                false
            } else {
                let only_build = row.namespaces_seeded;
                row.namespaces_seeded = true;
                row.build_cache_seeded = true;
                registries.insert(registry, encode(&row)?.as_slice())?;
                let mut table = txn.open_table(NAMESPACES)?;
                for ns in defaults(now) {
                    if only_build && ns.name != CI_BUILD {
                        continue;
                    }
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
            ref_type: Some(RefType::Branch),
            protected,
            pipeline_id,
        }
    }

    fn ns(name: &str, path: &str, grants: &[&str], retention_days: Option<u64>) -> NamespaceRow {
        let (grants, node_grants) = parse_grants(grants).unwrap();
        NamespaceRow {
            name: name.into(),
            path: path.into(),
            retention_days,
            alias: None,
            isolate: Vec::new(),
            grants,
            node_grants,
            created_at: 0,
            created_by: "t".into(),
        }
    }

    #[test]
    fn paths_fill_from_identifiers_only() {
        let c = claims(true, 7);
        let render = |path: &str, c: &JobClaims| render(&ns("n", path, &["r:*"], None), c);
        assert_eq!(
            render("ci-cache/{gitlab}/{project_id}/{protection}", &c).as_deref(),
            Some("ci-cache/gl/42/protected")
        );
        assert_eq!(render("p/{pipeline_id}", &claims(false, 0)), None);
        assert_eq!(render("p/x{project_id}", &c), None);
        assert_eq!(render("p/{project_path}", &c), None);
        assert_eq!(render("images", &c).as_deref(), Some("images"));
        assert_eq!(render("p/{scope}", &c).as_deref(), Some("p/all"));
    }

    fn on_ref(git_ref: &str, ref_type: Option<RefType>) -> JobClaims {
        JobClaims {
            git_ref: git_ref.into(),
            ref_type,
            ..claims(true, 7)
        }
    }

    #[test]
    fn isolated_refs_fill_a_scope_of_their_own() {
        let isolate = vec!["main".to_string(), "release/*".to_string()];
        let branch = |r: &str| scope(&isolate, &on_ref(r, Some(RefType::Branch)));
        assert_eq!(branch("dev").as_deref(), Some("all"));
        assert_eq!(branch("release/1/x").as_deref(), Some("all"));
        // The filling names repositories: it must not change.
        let main = branch("main").unwrap();
        assert_eq!(main, "ref-main-982786bd3f22691354ce8cf977cf260a");
        let release = branch("Release/1.2_rc").unwrap_or_default();
        assert_eq!(release, "all", "globs match the ref as it is");
        let release = branch("release/1.2_RC").unwrap();
        assert!(release.starts_with("ref-release-1-2-rc-"), "{release}");
        // Refs slugging alike, and a branch and a tag of one name, never share a scope.
        assert_ne!(branch("release/1.2"), branch("release/1-2"));
        let tag = scope(&isolate, &on_ref("main", Some(RefType::Tag))).unwrap();
        assert!(tag.starts_with("ref-main-") && tag != main, "{tag}");
        // Nothing for an isolated ref of unknown kind, or no ref at all; a ref no glob
        // matches shares `all` whatever its kind.
        assert_eq!(scope(&isolate, &on_ref("main", None)), None);
        assert_eq!(scope(&isolate, &on_ref("", Some(RefType::Branch))), None);
        assert_eq!(
            scope(&isolate, &on_ref("dev", None)).as_deref(),
            Some("all")
        );
        assert_eq!(scope(&[], &on_ref("", None)).as_deref(), Some("all"));
        // A slug keeps letters and digits only, at most 32 of them, `x` when none is left.
        let only = vec!["**".to_string()];
        let s = scope(&only, &on_ref("é/€", Some(RefType::Branch))).unwrap();
        assert!(s.starts_with("ref-x-"), "{s}");
        let s = scope(
            &only,
            &on_ref(&format!("{}-b", "a".repeat(31)), Some(RefType::Branch)),
        )
        .unwrap();
        assert!(s.starts_with(&format!("ref-{}-", "a".repeat(31))), "{s}");
        assert!(!s.contains("--"), "{s}");
        let long = scope(&only, &on_ref(&"Ab".repeat(100), Some(RefType::Branch))).unwrap();
        assert_eq!(long.len(), 4 + SCOPE_SLUG + 1 + SCOPE_HASH);
        assert!(valid_component(&long));
        let n = NamespaceRow {
            isolate: only,
            ..ns(
                "n",
                "p/{gitlab}/{project_id}/{scope}",
                &["rwl:own project"],
                None,
            )
        };
        assert_eq!(
            render(&n, &on_ref("main", Some(RefType::Branch))),
            Some(format!(
                "p/gl/42/{}",
                scope(&n.isolate, &on_ref("main", Some(RefType::Branch))).unwrap()
            ))
        );
        assert_eq!(render(&n, &on_ref("main", None)), None);
    }

    #[test]
    fn a_path_is_checked_at_its_longest() {
        use super::super::gitlabs::MAX_GITLAB_NAME;
        // At their longest: {gitlab} 32 characters, {project_id} 20 digits, {protection} 11
        // (`unprotected`), with the 3 slashes between them and the fixed part.
        let tail = "{gitlab}/{project_id}/{protection}";
        let fixed = "a".repeat(MAX_PREFIX_LEN - 3 - MAX_GITLAB_NAME - 20 - 11);
        ns("x", &format!("{fixed}/{tail}"), &["r:*"], None)
            .check()
            .unwrap();
        let deep = format!("{}/{{gitlab}}", vec!["a"; MAX_PREFIX_COMPONENTS].join("/"));
        for path in [
            format!("{fixed}a/{tail}"),
            deep,
            "p/tags/{gitlab}".to_string(),
        ] {
            let err = ns("x", &path, &["r:*"], None).check().unwrap_err();
            assert!(err.contains("at its longest"), "{path}: {err}");
        }
    }

    #[test]
    fn a_scoped_namespace_is_checked_with_its_isolated_refs() {
        use super::super::gitlabs::MAX_GITLAB_NAME;
        let ok = ns(
            "x",
            "p/{gitlab}/{project_id}/{protection}/{scope}",
            &["r:*"],
            None,
        );
        ok.check().unwrap();
        let isolating = |isolate: Vec<String>| NamespaceRow {
            isolate,
            ..ok.clone()
        };
        isolating(vec!["main".into()]).check().unwrap();
        let unscoped = NamespaceRow {
            isolate: vec!["main".into()],
            ..ns("x", "p/{gitlab}/{project_id}", &["r:*"], None)
        };
        assert!(unscoped.check().unwrap_err().contains("needs {scope}"));
        assert!(isolating(vec!["a b".into()]).check().is_err());
        let many = (0..=MAX_ISOLATE).map(|i| format!("r{i}")).collect();
        assert!(
            isolating(many)
                .check()
                .unwrap_err()
                .contains("at most 32 isolated ref globs")
        );
        // {scope} at its longest is 69 characters, with a fourth slash before it.
        let tail = "{gitlab}/{project_id}/{protection}/{scope}";
        let fixed = "a".repeat(MAX_PREFIX_LEN - 4 - MAX_GITLAB_NAME - 20 - 11 - 69);
        ns("x", &format!("{fixed}/{tail}"), &["r:*"], None)
            .check()
            .unwrap();
        let err = ns("x", &format!("{fixed}a/{tail}"), &["r:*"], None)
            .check()
            .unwrap_err();
        assert!(err.contains("at its longest"), "{err}");
    }

    #[test]
    fn defaults_resolve_to_the_cache_pipeline_and_build_cache() {
        let r = resolve(&defaults(0), &claims(false, 7));
        assert_eq!(r.cache_repo.as_deref(), Some("ci-cache/gl/42/unprotected"));
        assert_eq!(r.pipeline_prefix.as_deref(), Some("ci-pipeline/gl/42/7"));
        assert_eq!(
            r.build_prefix.as_deref(),
            Some("ci-build/gl/42/unprotected/all")
        );
        assert_eq!(r.grants.len(), 3);
        assert_eq!(r.grants[0].rights(), "rw");
        assert_eq!(r.grants[1].rights(), "rwl");
        assert_eq!(r.grants[2].rights(), "rwl");
        let no_pipeline = resolve(&defaults(0), &claims(true, 0));
        assert_eq!(no_pipeline.pipeline_prefix, None);
        assert_eq!(no_pipeline.grants.len(), 2);
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

    const NODE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn grant_lines_split_into_jobs_and_nodes() {
        let lines = [
            "r:*",
            "rwl:nodes",
            &format!("r:node {NODE}"),
            "r:guests",
            "w:gitlab gl, projects wab/**, protected",
        ];
        let (jobs, nodes) = parse_grants(&lines).unwrap();
        let jobs: Vec<String> = jobs.iter().map(ToString::to_string).collect();
        let nodes: Vec<String> = nodes.iter().map(ToString::to_string).collect();
        assert_eq!(jobs, ["r:*", "w:gitlab gl, projects wab/**, protected"]);
        assert_eq!(
            nodes,
            [
                "rwl:nodes".to_string(),
                format!("r:node {NODE}"),
                "r:guests".to_string()
            ]
        );
        // `*` keeps selecting every job, never a node.
        let (jobs, nodes) = parse_grants(&["r:*"]).unwrap();
        assert_eq!(jobs[0].subject, Subject::default());
        assert!(nodes.is_empty());
        for bad in [
            "r:node",
            "r:node 0123",
            &format!("r:node {}", NODE.to_uppercase()),
            &format!("r:node {NODE} x"),
            "r:nodes, protected",
            "r:nodes x",
            "r:guests x",
            "r:guests, protected",
            ":nodes",
            "x:nodes",
        ] {
            assert!(parse_grants(&[bad]).is_err(), "{bad}");
        }
    }

    #[test]
    fn nodes_are_granted_literal_paths_only() {
        ns("images", "images/base", &["r:nodes"], Some(30))
            .check()
            .unwrap();
        ns(
            "mixed",
            "images",
            &["r:*", &format!("rwl:node {NODE}")],
            None,
        )
        .check()
        .unwrap();
        for path in [
            "p/{gitlab}/{project_id}",
            "ci-pipeline/{gitlab}/{project_id}/{pipeline_id}",
            "c/{protection}",
            "c/{scope}",
        ] {
            let err = ns("x", path, &["r:nodes"], None).check().unwrap_err();
            assert!(
                err.contains("only paths without placeholders"),
                "{path}: {err}"
            );
        }
        let ci_build = defaults(0)
            .into_iter()
            .find(|n| n.name == CI_BUILD)
            .unwrap();
        let (_, node_grants) = parse_grants(&["r:nodes"]).unwrap();
        assert!(
            NamespaceRow {
                node_grants,
                ..ci_build
            }
            .check()
            .is_err()
        );
        // Job and node lines count together.
        let many: Vec<String> = (0..MAX_GRANTS).map(|_| "r:*".to_string()).collect();
        let mut over = many.clone();
        over.push("r:nodes".into());
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let over: Vec<&str> = over.iter().map(String::as_str).collect();
        ns("x", "p", &many, None).check().unwrap();
        assert!(ns("x", "p", &over, None).check().is_err());
    }

    #[test]
    fn a_node_gets_what_node_grants_select() {
        let other = "f".repeat(32);
        let all = [
            ns("images", "images", &["r:*", "r:nodes"], None),
            ns("cache", "build-cache", &[&format!("rwl:node {NODE}")], None),
            ns("cache-ro", "build-cache", &["r:nodes"], None),
            ns("other", "other", &[&format!("r:node {other}")], None),
            ns("jobs-only", "jobs-only", &["rwl:*"], None),
            ns(
                "project",
                "p/{gitlab}/{project_id}",
                &["rw:own project"],
                None,
            ),
        ];
        let got = |node: &str| -> Vec<(String, String)> {
            resolve_node(&all, node)
                .iter()
                .map(|g| (g.prefix.clone(), g.rights()))
                .collect()
        };
        assert_eq!(
            got(NODE),
            [
                ("images".to_string(), "r".to_string()),
                ("build-cache".to_string(), "rwl".to_string())
            ]
        );
        assert_eq!(
            got(&"e".repeat(32)),
            [
                ("images".to_string(), "r".to_string()),
                ("build-cache".to_string(), "r".to_string())
            ]
        );
        // Node grants give a job nothing, and none means no access.
        let job = resolve(&all, &claims(true, 7));
        assert!(job.grants.iter().all(|g| g.prefix != "build-cache"));
        assert!(resolve_node(&defaults(0), NODE).is_empty());
    }

    /// Guests get what lines for `guests` grant within their node's grants, the deeper prefix
    /// where one lies under the other; a guest line alone gives a node nothing.
    #[test]
    fn guests_get_their_nodes_grants_narrowed() {
        let all = [
            ns("images", "images", &["r:nodes", "rw:guests"], None),
            ns(
                "cache",
                "build-cache",
                &[&format!("rwl:node {NODE}"), "rw:guests"],
                None,
            ),
            ns("tools", "tools", &["rwl:nodes"], None),
            ns("guests-only", "guests-only", &["rwl:guests"], None),
        ];
        let got = |grants: Vec<Grant>| -> Vec<(String, String)> {
            grants
                .iter()
                .map(|g| (g.prefix.clone(), g.rights()))
                .collect()
        };
        assert_eq!(
            got(resolve_guest(&all, NODE)),
            [
                ("images".to_string(), "r".to_string()),
                ("build-cache".to_string(), "rw".to_string())
            ]
        );
        // Another node, granted no cache, lends its guests none.
        assert_eq!(
            got(resolve_guest(&all, &"e".repeat(32))),
            [("images".to_string(), "r".to_string())]
        );
        // `guests` selects no node.
        assert!(
            resolve_node(&all, NODE)
                .iter()
                .all(|g| g.prefix != "guests-only")
        );
        // A guest line under a node's grant narrows to its own prefix.
        let nested = [
            ns("images", "images", &["rw:nodes"], None),
            ns("base", "images/base", &["rwl:guests"], None),
        ];
        assert_eq!(
            got(resolve_guest(&nested, NODE)),
            [("images/base".to_string(), "rw".to_string())]
        );
        // None without lines for guests.
        let none = [ns("images", "images", &["rwl:nodes"], None)];
        assert!(resolve_guest(&none, NODE).is_empty());
    }

    /// A namespace granting nodes is held to the scoped roots as any other is; one reaching a
    /// root anyway, as stored before, gives nodes nothing there.
    #[test]
    fn node_grants_never_reach_a_reserved_root() {
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
        let scoped = ns(
            "tc",
            "tc/{gitlab}/{project_id}/{scope}",
            &["rwl:own project"],
            None,
        );
        db.put_namespace(&id, &scoped, "u", 1).unwrap();
        let err = db
            .put_namespace(&id, &ns("n", "tc/gl", &["r:nodes"], None), "u", 2)
            .unwrap_err()
            .to_string();
        assert!(err.contains("which namespace tc reserves"), "{err}");
        let legacy = ns("n", "tc/gl", &["r:nodes"], None);
        assert!(resolve_node(&[scoped, legacy], NODE).is_empty());
        // Stored and read back, node grants keep their place; an older reader sees the job
        // grants alone.
        let images = ns("images", "images", &["r:*", "r:nodes"], None);
        db.put_namespace(&id, &images, "u", 3).unwrap();
        let back = db.namespaces(&id).unwrap();
        assert!(back.contains(&images));
        let json = serde_json::to_value(&images).unwrap();
        assert_eq!(json["grants"].as_array().unwrap().len(), 1);
        assert_eq!(json["node_grants"][0]["nodes"], "all");
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
            ns("x", "p/blobs", &["r:*"], None),
            ns("x", &vec!["p"; 17].join("/"), &["r:*"], None),
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
        assert_eq!(names, [CI_BUILD, CI_CACHE, "wider"]);
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
    fn a_registry_seeded_before_gets_the_build_cache_once() {
        use crate::store::{RegistryEnrollment, TokenKind};
        let db = Db::open_memory().unwrap();
        let ttl = std::time::Duration::from_secs(60);
        let enroll = |key: &str| {
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
        let (old, held) = (enroll("aa"), enroll("bb"));
        // As an older hub left them: seeded, without ci-build, ci-cache removed since.
        for id in [&old, &held] {
            let txn = db.db.begin_write().unwrap();
            {
                let mut registries = txn.open_table(REGISTRIES).unwrap();
                let mut row: super::super::RegistryRow =
                    decode(registries.get(id.as_str()).unwrap().unwrap().value()).unwrap();
                row.namespaces_seeded = true;
                registries
                    .insert(id.as_str(), encode(&row).unwrap().as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        // A namespace on ci-build's root keeps it from being added.
        let mine = ns("mine", "ci-build/{gitlab}", &["r:*"], None);
        db.put_namespace(&held, &mine, "u", 1).unwrap();
        let names = |id: &str| -> Vec<String> {
            db.namespaces(id)
                .unwrap()
                .into_iter()
                .map(|n| n.name)
                .collect()
        };
        assert!(db.seed_namespaces(&old, 2).unwrap());
        assert_eq!(names(&old), [CI_BUILD]);
        assert!(db.seed_namespaces(&held, 2).unwrap());
        assert_eq!(names(&held), ["mine"]);
        // Once: removed, it does not come back.
        assert!(db.remove_namespace(&old, CI_BUILD, "u", 3).unwrap());
        assert!(!db.seed_namespaces(&old, 4).unwrap());
        assert!(names(&old).is_empty());
    }

    /// A ci-build stored before its checks, too wide, keeps its grant but gives no job a build
    /// prefix.
    #[test]
    fn a_ci_build_failing_its_checks_gives_no_build_prefix() {
        let wide = ns(CI_BUILD, "ci-build/{gitlab}", &["r:*"], None);
        let r = resolve(std::slice::from_ref(&wide), &claims(false, 7));
        assert_eq!(r.build_prefix, None);
        assert_eq!(r.grants.len(), 1);
        let ok = defaults(0)
            .into_iter()
            .find(|n| n.name == CI_BUILD)
            .unwrap();
        let r = resolve(std::slice::from_ref(&ok), &claims(false, 7));
        assert_eq!(
            r.build_prefix.as_deref(),
            Some("ci-build/gl/42/unprotected/all")
        );
    }

    #[test]
    fn ci_build_is_its_projects_protections_and_scopes_alone() {
        let ci_build = defaults(0)
            .into_iter()
            .find(|n| n.name == CI_BUILD)
            .unwrap();
        ci_build.check().unwrap();
        NamespaceRow {
            isolate: vec!["main".into()],
            ..ci_build.clone()
        }
        .check()
        .unwrap();
        for path in [
            "ci-build/{gitlab}/{project_id}/{protection}",
            "ci-build/{gitlab}/{project_id}/{scope}",
            "ci-build/{gitlab}/{protection}/{scope}",
            "ci-build/{project_id}/{protection}/{scope}",
        ] {
            let bad = NamespaceRow {
                path: path.into(),
                ..ci_build.clone()
            };
            assert!(bad.check().unwrap_err().contains("lacks {"), "{path}");
        }
        for grant in [
            "r:*",
            "rwl:own project, protected",
            "r:gitlab gl",
            "rwl:own project, own pipeline",
        ] {
            let bad = NamespaceRow {
                grants: vec![NsGrant::parse(grant).unwrap()],
                ..ci_build.clone()
            };
            assert!(bad.check().is_err(), "{grant}");
        }
        // Room for /build-cache is part of the length checked.
        // Slashes, {gitlab}, {project_id}, {protection} and {scope} at their longest.
        let fixed =
            "a".repeat(MAX_PREFIX_LEN - 4 - super::super::gitlabs::MAX_GITLAB_NAME - 20 - 11 - 69);
        let path = format!("{fixed}/{{gitlab}}/{{project_id}}/{{protection}}/{{scope}}");
        ns("x", &path, &["rwl:own project"], None).check().unwrap();
        let as_build = NamespaceRow {
            path,
            ..ci_build.clone()
        };
        assert!(as_build.check().unwrap_err().contains("at its longest"));
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
    fn a_scoped_namespace_reserves_its_root() {
        let tc = ns(
            "tc",
            "task-cache/{gitlab}/{project_id}/{protection}/{scope}",
            &["rwl:own project"],
            None,
        );
        for (path, refused) in [
            ("task-cache/{gitlab}/{project_id}", true),
            ("task-cache", true),
            ("task-cache/x/y/z/w/v", true),
            ("task-cache2/{gitlab}", false),
            ("images", false),
            ("p/task-cache", false),
        ] {
            let other = ns("o", path, &["r:*"], None);
            for (a, b) in [(&tc, &other), (&other, &tc)] {
                let got = check_reserved_root(a, std::slice::from_ref(b));
                assert_eq!(got.is_some(), refused, "{path}: {got:?}");
            }
        }
        // A root deeper than a placeholder elsewhere is reached through it.
        let deep = ns("d", "a/b/{gitlab}/{scope}", &["r:*"], None);
        let wide = ns("w", "a/{gitlab}", &["r:*"], None);
        assert!(check_reserved_root(&wide, std::slice::from_ref(&deep)).is_some());
        let apart = ns("w", "a/c/{gitlab}", &["r:*"], None);
        assert!(check_reserved_root(&apart, std::slice::from_ref(&deep)).is_none());
        // Two unscoped namespaces may nest.
        let unscoped = ns("u", "task-cache/{gitlab}/{project_id}", &["r:*"], None);
        let nested = ns("n", "task-cache/{gitlab}", &["r:*"], None);
        assert!(check_reserved_root(&unscoped, std::slice::from_ref(&nested)).is_none());
        // A placeholder reaches a fixed component only where a job could fill it so.
        for (root, path, meets) in [
            ("a/b", "a/{protection}", false),
            ("a/protected", "a/{protection}", true),
            ("a/x", "a/{project_id}", false),
            ("a/42", "a/{pipeline_id}", true),
            ("a/Upper", "a/{gitlab}", false),
            ("a/gl", "a/{gitlab}", true),
            ("a/b", "a/{scope}", false),
            ("a/all", "a/{scope}", true),
        ] {
            assert_eq!(may_meet(root, path), meets, "{root} {path}");
        }
    }

    /// A namespace may add `{scope}` under its own name. A legacy namespace reaching the root
    /// stays listed, but neither it nor a new conflicting namespace can be stored.
    #[test]
    fn a_reserved_root_is_held_when_namespaces_are_stored() {
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
        let tc = |path: &str| ns("tc", path, &["rwl:own project"], None);
        db.put_namespace(&id, &tc("tc/{gitlab}/{project_id}"), "u", 1)
            .unwrap();
        db.put_namespace(&id, &tc("tc/{gitlab}/{project_id}/{scope}"), "u", 2)
            .unwrap();
        // As an older hub stored it, beside the scoped one.
        let legacy = ns("wide", "tc/{gitlab}", &["r:*"], None);
        let txn = db.db.begin_write().unwrap();
        txn.open_table(NAMESPACES)
            .unwrap()
            .insert(
                format!("{id}/wide").as_str(),
                encode(&legacy).unwrap().as_slice(),
            )
            .unwrap();
        txn.commit().unwrap();
        let names: Vec<String> = db
            .namespaces(&id)
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .collect();
        assert_eq!(names, ["tc", "wide"]);
        for again in [legacy, ns("new", "tc/x", &["r:*"], None)] {
            let err = db
                .put_namespace(&id, &again, "u", 3)
                .unwrap_err()
                .to_string();
            assert!(err.contains("which namespace tc reserves"), "{err}");
        }
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
