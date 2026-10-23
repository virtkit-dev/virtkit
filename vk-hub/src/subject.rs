//! Which jobs a rule selects: a registry namespace's grant today, an egress rule later.
//!
//! A subject is a list of terms, all of which must hold, written comma-separated:
//! - `*`: any project;
//! - `own project`, `own pipeline`: any job, whose own project or pipeline the rule's path
//!   names through `{gitlab}` and `{project_id}` or `{pipeline_id}`;
//! - `gitlab <name>`: jobs from that GitLab instance, as the hub names it;
//! - `projects <glob>`: a project path, where `*` stays within a path component and `**`
//!   crosses them;
//! - `project-id <n>`;
//! - `ref <glob>`;
//! - `protected`, `unprotected`.
//!
//! Project paths and IDs repeat across GitLab instances, so `projects` and `project-id` need
//! `gitlab <name>` beside them.
//!
//! Selecting by ref name means little unless the ref is protected: anyone who can push to a
//! project can name a branch anything. A rule that grants writes or locks by ref name must
//! therefore also say `protected` ([`Subject::check_grant`]).

use serde::{Deserialize, Serialize};

/// Which projects a subject selects.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projects {
    #[default]
    Any,
    /// Any, with the rule's path naming the job's own project.
    Own,
    Path(String),
    Id(u64),
}

/// The jobs a rule selects.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    #[serde(default)]
    pub projects: Projects,
    /// The GitLab instance, by the hub's name for it; `None` for any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitlab: Option<String>,
    /// Any job, with the rule's path naming its own pipeline.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub own_pipeline: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// `Some(true)` for protected refs only, `Some(false)` for unprotected ones only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
}

/// The longest a subject's text may be.
const MAX_SUBJECT: usize = 512;

impl Subject {
    /// Parse a subject's text; `Err` says why it does not parse.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_SUBJECT {
            return Err(format!("a subject is at most {MAX_SUBJECT} characters"));
        }
        let mut s = Subject::default();
        let mut projects_set = false;
        let mut set_projects = |s: &mut Subject, p: Projects| {
            if projects_set {
                return Err("a subject names its projects once".to_string());
            }
            projects_set = true;
            s.projects = p;
            Ok(())
        };
        for term in text.split(',').map(str::trim) {
            let words: Vec<&str> = term.split_whitespace().collect();
            match words.as_slice() {
                ["*"] => set_projects(&mut s, Projects::Any)?,
                ["own", "project"] => set_projects(&mut s, Projects::Own)?,
                ["own", "pipeline"] if !s.own_pipeline => s.own_pipeline = true,
                ["gitlab", name] if s.gitlab.is_none() => {
                    if !crate::store::valid_gitlab_name(name) {
                        return Err(format!("{name:?} is not a GitLab instance's name"));
                    }
                    s.gitlab = Some((*name).to_string());
                }
                ["project" | "projects", glob] => {
                    check_glob(glob)?;
                    set_projects(&mut s, Projects::Path((*glob).to_string()))?;
                }
                ["project-id", n] => set_projects(
                    &mut s,
                    Projects::Id(
                        n.parse()
                            .map_err(|_| format!("{n:?} is not a project ID"))?,
                    ),
                )?,
                ["ref", glob] if s.git_ref.is_none() => {
                    check_glob(glob)?;
                    s.git_ref = Some((*glob).to_string());
                }
                ["protected"] if s.protected.is_none() => s.protected = Some(true),
                ["unprotected"] if s.protected.is_none() => s.protected = Some(false),
                _ => return Err(format!("{term:?} is not a subject's term")),
            }
        }
        if matches!(s.projects, Projects::Path(_) | Projects::Id(_)) && s.gitlab.is_none() {
            return Err(
                "`projects` and `project-id` need `gitlab <name>`: project paths and IDs \
                 repeat across GitLab instances"
                    .to_string(),
            );
        }
        Ok(s)
    }

    /// Why the subject may not be granted writes or locks, if it may not: selecting by ref
    /// name without `protected`.
    pub fn check_grant(&self, write_or_lock: bool) -> Result<(), String> {
        if write_or_lock && self.git_ref.is_some() && self.protected != Some(true) {
            return Err(
                "a subject that grants writes or locks by ref name must also say `protected`: \
                 anyone who can push can name a branch anything"
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut terms = Vec::new();
        if let Some(g) = &self.gitlab {
            terms.push(format!("gitlab {g}"));
        }
        match &self.projects {
            Projects::Any => {}
            Projects::Own => terms.push("own project".to_string()),
            Projects::Path(g) => terms.push(format!("projects {g}")),
            Projects::Id(id) => terms.push(format!("project-id {id}")),
        }
        if self.own_pipeline {
            terms.push("own pipeline".to_string());
        }
        if let Some(g) = &self.git_ref {
            terms.push(format!("ref {g}"));
        }
        match self.protected {
            Some(true) => terms.push("protected".to_string()),
            Some(false) => terms.push("unprotected".to_string()),
            None => {}
        }
        if terms.is_empty() {
            terms.push("*".to_string());
        }
        f.write_str(&terms.join(", "))
    }
}

fn check_glob(glob: &str) -> Result<(), String> {
    if glob.is_empty() || glob.len() > 255 || glob.contains(char::is_whitespace) {
        return Err(format!("{glob:?} is not a glob"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_by_ref_name_need_protected() {
        let by_ref = Subject::parse("gitlab gl, projects wab/**, ref release/*").unwrap();
        assert!(by_ref.check_grant(false).is_ok());
        assert!(by_ref.check_grant(true).is_err());
        let protected = Subject::parse("ref release/*, protected").unwrap();
        assert!(protected.check_grant(true).is_ok());
    }
}
