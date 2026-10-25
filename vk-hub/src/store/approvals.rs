//! What an operator decided of what relays bring: the GitLab projects approved, pending and
//! rejected for each instance, and the GitLab servers rejected. A server relays report and no
//! instance has is pending until approved ([`Db::add_gitlab`]) or rejected here; a project is
//! keyed by its instance's name and GitLab's ID for it, so removing the instance forgets them.
//! Every decision is audited.

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::gitlabs::{GITLABS, GitlabRow, normalize_gitlab_url, valid_project_path};
use super::{Db, append_audit, decode, encode};

/// Key: `(instance name, project ID)`. Value: JSON [`ProjectRow`].
pub(super) const GITLAB_PROJECTS: TableDefinition<(&str, u64), &[u8]> =
    TableDefinition::new("gitlab_projects");

/// Key: a rejected server's URL, as [`normalize_gitlab_url`] writes it. Value: JSON
/// [`RejectedGitlab`].
pub(super) const REJECTED_GITLABS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("rejected_gitlabs");

/// The most projects kept per instance: past it, a new project's job is refused without
/// being recorded, until an operator forgets some.
pub const MAX_PROJECTS: usize = 10_000;

/// Where a project stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectState {
    /// A job of it was refused; waiting for an operator.
    Pending,
    Approved,
    Rejected,
}

impl ProjectState {
    pub fn name(self) -> &'static str {
        match self {
            ProjectState::Pending => "pending",
            ProjectState::Approved => "approved",
            ProjectState::Rejected => "rejected",
        }
    }
}

/// A project of an instance, as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRow {
    pub state: ProjectState,
    /// Its path, display-safe, as last seen on a job or given on approval; empty when it was
    /// approved by ID alone and no job has said it since.
    #[serde(default)]
    pub path: String,
    /// When the hub first heard of it.
    pub since: u64,
    /// The first of its jobs refused: GitLab's job ID and its page, and the relay that
    /// submitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_job: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_job_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// How many of its jobs were refused while it was pending or rejected.
    #[serde(default)]
    pub refused: u64,
    /// Who last approved or rejected it, and when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<u64>,
}

/// A project as `vk-hub gitlabs projects` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectView {
    pub gitlab: String,
    pub id: u64,
    #[serde(flatten)]
    pub row: ProjectRow,
}

/// A server an operator rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedGitlab {
    pub rejected_at: u64,
    pub rejected_by: String,
}

/// A project an operator approves or rejects: by ID, with its path when known.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRef {
    pub id: u64,
    #[serde(default)]
    pub path: Option<String>,
}

impl ProjectRef {
    /// `<id>` or `<id>:<path>`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (id, path) = match s.split_once(':') {
            Some((id, path)) => (id, Some(path)),
            None => (s, None),
        };
        let id: u64 = id
            .parse()
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| format!("{id:?} is not a project ID"))?;
        if let Some(path) = path
            && !valid_project_path(path)
        {
            return Err(format!("{path:?} is not a project path"));
        }
        Ok(ProjectRef {
            id,
            path: path.map(str::to_string),
        })
    }
}

/// Approve or reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Reject,
}

impl Decision {
    fn state(self) -> ProjectState {
        match self {
            Decision::Approve => ProjectState::Approved,
            Decision::Reject => ProjectState::Rejected,
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Decision::Approve => "approved",
            Decision::Reject => "rejected",
        }
    }
}

/// The rejected servers' URLs.
pub(super) fn rejected_in(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in table.iter()? {
        out.push(entry?.0.value().to_string());
    }
    Ok(out)
}

/// The URL of instance `name`, refused when there is none.
fn instance_url(txn: &redb::WriteTransaction, name: &str) -> Result<String> {
    match txn.open_table(GITLABS)?.get(name)? {
        Some(g) => Ok(decode::<GitlabRow>(g.value())?.url),
        None => bail!("there is no GitLab instance {name}"),
    }
}

/// Forget every project of instance `name`, in `txn`: its removal. How many there were.
pub(super) fn forget_projects_of(txn: &redb::WriteTransaction, name: &str) -> Result<usize> {
    let mut table = txn.open_table(GITLAB_PROJECTS)?;
    let ids: Vec<u64> = table
        .range((name, 0)..=(name, u64::MAX))?
        .map(|e| e.map(|(k, _)| k.value().1))
        .collect::<Result<_, _>>()?;
    for id in &ids {
        table.remove((name, *id))?;
    }
    Ok(ids.len())
}

impl Db {
    /// The projects of instance `gitlab`, or of every instance, by instance and ID.
    pub fn gitlab_projects(&self, gitlab: Option<&str>) -> Result<Vec<ProjectView>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(GITLAB_PROJECTS)?;
        let range = match gitlab {
            Some(g) => table.range((g, 0)..=(g, u64::MAX))?,
            None => table.range::<(&str, u64)>(..)?,
        };
        let mut out = Vec::new();
        for entry in range {
            let (key, value) = entry?;
            let (gitlab, id) = key.value();
            out.push(ProjectView {
                gitlab: gitlab.to_string(),
                id,
                row: decode(value.value())?,
            });
        }
        Ok(out)
    }

    /// Approve or reject `projects` of instance `gitlab`, audited as `actor`'s: those not
    /// known yet are added so. A path given replaces the one recorded. How many changed.
    pub fn decide_projects(
        &self,
        gitlab: &str,
        projects: &[ProjectRef],
        decision: Decision,
        actor: &str,
        now: u64,
    ) -> Result<usize> {
        if projects.is_empty() {
            bail!("name at least one project");
        }
        let txn = self.db.begin_write().context("starting a write")?;
        instance_url(&txn, gitlab)?;
        let mut changed = Vec::new();
        {
            let mut table = txn.open_table(GITLAB_PROJECTS)?;
            let mut count = table.range((gitlab, 0)..=(gitlab, u64::MAX))?.count();
            for p in projects {
                let old = table
                    .get((gitlab, p.id))?
                    .map(|g| decode::<ProjectRow>(g.value()))
                    .transpose()?;
                if old.is_none() {
                    if count >= MAX_PROJECTS {
                        bail!("instance {gitlab} has {MAX_PROJECTS} projects already");
                    }
                    count = count.saturating_add(1);
                }
                let path = p.path.as_deref().map(vk_hub_proto::display_safe);
                if old.as_ref().is_some_and(|o| {
                    o.state == decision.state() && path.as_ref().is_none_or(|path| *path == o.path)
                }) {
                    continue;
                }
                let mut row = old.unwrap_or(ProjectRow {
                    state: decision.state(),
                    path: String::new(),
                    since: now,
                    first_job: None,
                    first_job_url: None,
                    relay: None,
                    refused: 0,
                    decided_by: None,
                    decided_at: None,
                });
                row.state = decision.state();
                if let Some(path) = path {
                    row.path = path;
                }
                row.decided_by = Some(actor.to_string());
                row.decided_at = Some(now);
                table.insert((gitlab, p.id), encode(&row)?.as_slice())?;
                changed.push(project_text(p.id, &row.path));
            }
        }
        if !changed.is_empty() {
            let event = format!(
                "{actor} {} project(s) {} of GitLab instance {gitlab}",
                decision.verb(),
                changed.join(", ")
            );
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("deciding on GitLab projects")?;
        Ok(changed.len())
    }

    /// Forget `ids` of instance `gitlab`, audited as `actor`'s: a project's next job makes it
    /// pending again. How many there were.
    pub fn forget_projects(
        &self,
        gitlab: &str,
        ids: &[u64],
        actor: &str,
        now: u64,
    ) -> Result<usize> {
        let txn = self.db.begin_write().context("starting a write")?;
        instance_url(&txn, gitlab)?;
        let mut forgotten = Vec::new();
        {
            let mut table = txn.open_table(GITLAB_PROJECTS)?;
            for id in ids {
                if let Some(old) = table.remove((gitlab, *id))? {
                    let row = decode::<ProjectRow>(old.value())?;
                    forgotten.push(project_text(*id, &row.path));
                }
            }
        }
        if !forgotten.is_empty() {
            let event = format!(
                "{actor} forgot project(s) {} of GitLab instance {gitlab}",
                forgotten.join(", ")
            );
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("forgetting GitLab projects")?;
        Ok(forgotten.len())
    }

    /// Reject the server at `url`, audited as `actor`'s: its relays are refused jobs, and it
    /// is no longer listed as pending. Refused for a server approved as an instance, which is
    /// removed instead. Its URL as normalized, and whether it was not rejected already.
    pub fn reject_gitlab(&self, url: &str, actor: &str, now: u64) -> Result<(String, bool)> {
        let Some(url) = normalize_gitlab_url(url) else {
            bail!("{url:?} is not an http(s) URL");
        };
        let txn = self.db.begin_write().context("starting a write")?;
        for entry in txn.open_table(GITLABS)?.iter()? {
            let (name, value) = entry?;
            if decode::<GitlabRow>(value.value())?.url == url {
                bail!(
                    "{url} is approved as instance {}: remove its relays, then the instance",
                    name.value()
                );
            }
        }
        let added = {
            let mut table = txn.open_table(REJECTED_GITLABS)?;
            let added = table.get(url.as_str())?.is_none();
            if added {
                let row = RejectedGitlab {
                    rejected_at: now,
                    rejected_by: actor.to_string(),
                };
                table.insert(url.as_str(), encode(&row)?.as_slice())?;
            }
            added
        };
        if added {
            let event = format!("{actor} rejected GitLab server {url}");
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("rejecting a GitLab server")?;
        Ok((url, added))
    }

    /// Forget that the server at `url` was rejected, audited as `actor`'s: it is pending again
    /// while a relay reports it. Its URL as normalized, and whether it was rejected.
    pub fn forget_gitlab(&self, url: &str, actor: &str, now: u64) -> Result<(String, bool)> {
        let Some(url) = normalize_gitlab_url(url) else {
            bail!("{url:?} is not an http(s) URL");
        };
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = txn
            .open_table(REJECTED_GITLABS)?
            .remove(url.as_str())?
            .is_some();
        if removed {
            let event = format!("{actor} forgot rejected GitLab server {url}");
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("forgetting a GitLab server")?;
        Ok((url, removed))
    }

    /// The servers rejected, by URL.
    pub fn rejected_gitlabs(&self) -> Result<Vec<(String, RejectedGitlab)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(REJECTED_GITLABS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (url, value) = entry?;
            out.push((url.value().to_string(), decode(value.value())?));
        }
        Ok(out)
    }
}

/// `<id> (<path>)`, or the ID alone with no path known.
fn project_text(id: u64, path: &str) -> String {
    if path.is_empty() {
        id.to_string()
    } else {
        format!("{id} ({path})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(s: &[&str]) -> Vec<ProjectRef> {
        s.iter().map(|s| ProjectRef::parse(s).unwrap()).collect()
    }

    #[test]
    fn projects_are_approved_rejected_and_forgotten_per_instance() {
        let db = Db::open_memory().unwrap();
        let err = db
            .decide_projects("gl", &refs(&["4"]), Decision::Approve, "u", 1)
            .unwrap_err();
        assert!(err.to_string().contains("no GitLab instance gl"), "{err:#}");
        db.add_gitlab("gl", "https://gl.example", "u", 1).unwrap();
        db.add_gitlab("other", "https://other.example", "u", 1)
            .unwrap();
        let n = db
            .decide_projects("gl", &refs(&["4:acme/web", "9"]), Decision::Approve, "u", 2)
            .unwrap();
        assert_eq!(n, 2);
        // Again, the same: nothing changes.
        let n = db
            .decide_projects("gl", &refs(&["4", "9"]), Decision::Approve, "u", 3)
            .unwrap();
        assert_eq!(n, 0);
        db.decide_projects("other", &refs(&["4"]), Decision::Reject, "v", 3)
            .unwrap();
        let listed = db.gitlab_projects(Some("gl")).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|p| (p.id, p.row.path.as_str(), p.row.state))
                .collect::<Vec<_>>(),
            [
                (4, "acme/web", ProjectState::Approved),
                (9, "", ProjectState::Approved)
            ]
        );
        assert_eq!(listed[0].row.decided_by.as_deref(), Some("u"));
        assert_eq!(db.gitlab_projects(None).unwrap().len(), 3);
        // Rejecting an approved one keeps its path.
        db.decide_projects("gl", &refs(&["4"]), Decision::Reject, "u", 4)
            .unwrap();
        let p = &db.gitlab_projects(Some("gl")).unwrap()[0];
        assert_eq!(
            (p.row.state, p.row.path.as_str()),
            (ProjectState::Rejected, "acme/web")
        );
        assert_eq!(db.forget_projects("gl", &[4, 5], "u", 5).unwrap(), 1);
        assert_eq!(db.gitlab_projects(Some("gl")).unwrap().len(), 1);
        // Removing the instance forgets its projects, not another's.
        db.remove_gitlab("gl", "u", 6).unwrap();
        db.add_gitlab("gl", "https://gl.example", "u", 7).unwrap();
        assert!(db.gitlab_projects(Some("gl")).unwrap().is_empty());
        assert_eq!(db.gitlab_projects(Some("other")).unwrap().len(), 1);
        let audit: Vec<String> = db
            .audits(None, 20)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            audit.contains(&"u approved project(s) 4 (acme/web), 9 of GitLab instance gl".into()),
            "{audit:?}"
        );
        assert!(audit.contains(&"u forgot project(s) 4 (acme/web) of GitLab instance gl".into()));
    }

    #[test]
    fn a_rejected_server_is_forgotten_or_approved_later() {
        let db = Db::open_memory().unwrap();
        let (url, added) = db.reject_gitlab("https://GL.example/", "u", 1).unwrap();
        assert_eq!((url.as_str(), added), ("https://gl.example", true));
        assert!(!db.reject_gitlab("https://gl.example", "u", 2).unwrap().1);
        assert_eq!(db.rejected_gitlabs().unwrap().len(), 1);
        assert!(db.forget_gitlab("https://gl.example", "u", 3).unwrap().1);
        assert!(!db.forget_gitlab("https://gl.example", "u", 3).unwrap().1);
        db.reject_gitlab("https://gl.example", "u", 4).unwrap();
        // Approving it later ends the rejection.
        db.add_gitlab("gl", "https://gl.example", "u", 5).unwrap();
        assert!(db.rejected_gitlabs().unwrap().is_empty());
        let err = db.reject_gitlab("https://gl.example", "u", 6).unwrap_err();
        assert!(err.to_string().contains("instance gl"), "{err:#}");
        assert!(db.reject_gitlab("not a url", "u", 6).is_err());
    }

    #[test]
    fn project_refs_parse() {
        let p = ProjectRef::parse("42:wab/core").unwrap();
        assert_eq!((p.id, p.path.as_deref()), (42, Some("wab/core")));
        assert_eq!(ProjectRef::parse("42").unwrap().path, None);
        for bad in [
            "x:wab",
            "0:wab",
            "42:",
            "42:wab/\u{7}x",
            "42:wab//x",
            "42:wab/ x",
            "",
        ] {
            assert!(ProjectRef::parse(bad).is_err(), "{bad:?}");
        }
    }
}
