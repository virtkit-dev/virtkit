//! Registry access in plain words: what a namespace's grants and subjects mean to someone
//! reading a page, in the UI's vocabulary. A namespace is a storage area, a grant an access
//! rule; `read`, `write` and `lock` are Read, Publish and Coordinate builds.

use crate::store::{CI_CACHE, CI_PIPELINE, NamespaceRow, NsGrant};
use crate::subject::{Projects, Subject};

/// The jobs a subject selects, in plain words: `Every job`, `Each project from gl, its own`,
/// `Projects under wab/ on gl, protected branches and tags only`. The GitLab instance is named
/// whenever the subject names one.
pub(super) fn who(s: &Subject) -> String {
    let on = |g: &Option<String>| g.as_ref().map(|g| format!(" on {g}")).unwrap_or_default();
    let from = |g: &Option<String>| g.as_ref().map(|g| format!(" from {g}")).unwrap_or_default();
    let mut text = match &s.projects {
        Projects::Own | Projects::Any if s.own_pipeline => {
            format!("Each pipeline{}, its own", from(&s.gitlab))
        }
        Projects::Own => format!("Each project{}, its own", from(&s.gitlab)),
        Projects::Any => match &s.gitlab {
            Some(g) => format!("Every job from {g}"),
            None => "Every job".to_string(),
        },
        Projects::Path(glob) => match glob.strip_suffix("/**") {
            Some(under) if !under.contains('*') => {
                format!("Projects under {under}/{}", on(&s.gitlab))
            }
            _ if glob.contains('*') => format!("Projects matching {glob}{}", on(&s.gitlab)),
            _ => format!("{glob}{}", on(&s.gitlab)),
        },
        Projects::Id(id) => format!("Project {id}{}", on(&s.gitlab)),
    };
    if s.own_pipeline && matches!(s.projects, Projects::Path(_) | Projects::Id(_)) {
        text.push_str(", its own pipeline");
    }
    if let Some(r) = &s.git_ref {
        text.push_str(&format!(", refs matching {r}"));
    }
    match s.protected {
        Some(true) => text.push_str(", protected branches and tags only"),
        Some(false) => text.push_str(", unprotected branches and tags only"),
        None => {}
    }
    text
}

/// A storage area as a page lists it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Area {
    /// The namespace's name.
    pub name: String,
    /// What the page calls it.
    pub label: String,
    pub path: String,
    /// Who may read, one line per access rule.
    pub readers: Vec<String>,
    /// Who may publish, one line per access rule, saying when they also coordinate builds;
    /// rules that only coordinate builds say so.
    pub publishers: Vec<String>,
    /// One of the areas the hub keeps for CI: caches and per-pipeline storage.
    pub managed: bool,
}

/// What a page calls namespace `name`.
pub(super) fn label(name: &str) -> String {
    match name {
        CI_CACHE => "CI caches".to_string(),
        CI_PIPELINE => "Pipeline storage".to_string(),
        other => other.to_string(),
    }
}

/// Namespace `ns` as a storage area.
pub(super) fn area(ns: &NamespaceRow) -> Area {
    let line = |g: &NsGrant| who(&g.subject);
    Area {
        name: ns.name.clone(),
        label: label(&ns.name),
        path: ns.path.clone(),
        readers: ns.grants.iter().filter(|g| g.read).map(line).collect(),
        publishers: ns
            .grants
            .iter()
            .filter(|g| g.write || g.lock)
            .map(|g| match (g.write, g.lock) {
                (true, true) => format!("{} · can coordinate builds", line(g)),
                (true, false) => line(g),
                _ => format!("{} · coordinate builds only", line(g)),
            })
            .collect(),
        managed: ns.name == CI_CACHE || ns.name == CI_PIPELINE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(text: &str) -> Subject {
        Subject::parse(text).unwrap()
    }

    #[test]
    fn subjects_read_as_who_they_select() {
        for (text, want) in [
            ("*", "Every job"),
            ("gitlab gl", "Every job from gl"),
            ("own project", "Each project, its own"),
            ("own project, own pipeline", "Each pipeline, its own"),
            ("gitlab gl, own project", "Each project from gl, its own"),
            (
                "gitlab gl, own project, own pipeline",
                "Each pipeline from gl, its own",
            ),
            ("gitlab gl, own pipeline", "Each pipeline from gl, its own"),
            (
                "gitlab gl, projects wab/**, own pipeline",
                "Projects under wab/ on gl, its own pipeline",
            ),
            (
                "gitlab gl, project-id 7, own pipeline",
                "Project 7 on gl, its own pipeline",
            ),
            (
                "own project, protected",
                "Each project, its own, protected branches and tags only",
            ),
            ("gitlab gl, projects wab/**", "Projects under wab/ on gl"),
            (
                "gitlab gl, projects wab/*-ci",
                "Projects matching wab/*-ci on gl",
            ),
            (
                "gitlab gl, projects infra/images, protected",
                "infra/images on gl, protected branches and tags only",
            ),
            ("gitlab gl, project-id 1172", "Project 1172 on gl"),
            (
                "gitlab gl, projects wab/**, ref release/*, protected",
                "Projects under wab/ on gl, refs matching release/*, protected branches and \
                 tags only",
            ),
            (
                "unprotected",
                "Every job, unprotected branches and tags only",
            ),
        ] {
            assert_eq!(who(&subject(text)), want, "{text}");
        }
    }

    fn ns(name: &str, path: &str, grants: &[&str]) -> NamespaceRow {
        NamespaceRow {
            name: name.into(),
            path: path.into(),
            retention_days: None,
            grants: grants.iter().map(|g| NsGrant::parse(g).unwrap()).collect(),
            created_at: 0,
            created_by: "uid 0".into(),
        }
    }

    #[test]
    fn a_namespace_reads_as_a_storage_area() {
        let wab = ns(
            "wab",
            "wab",
            &[
                "rwl:gitlab gl, projects wab/**, protected",
                "r:gitlab gl, projects wab/**",
                "l:gitlab gl, project-id 7",
            ],
        );
        let a = area(&wab);
        assert_eq!(a.label, "wab");
        assert!(!a.managed);
        assert_eq!(
            a.readers,
            [
                "Projects under wab/ on gl, protected branches and tags only",
                "Projects under wab/ on gl"
            ]
        );
        assert_eq!(
            a.publishers,
            [
                "Projects under wab/ on gl, protected branches and tags only · can coordinate \
                 builds",
                "Project 7 on gl · coordinate builds only"
            ]
        );
        let cache = area(&ns(
            CI_CACHE,
            "ci-cache/{gitlab}/{project_id}/{protection}",
            &["rw:own project"],
        ));
        assert_eq!(cache.label, "CI caches");
        assert!(cache.managed);
    }
}
