//! Registry access in plain words: what a namespace's grants and subjects mean to someone
//! reading a page, in the UI's vocabulary. A namespace is a storage area, a grant an access
//! rule; `read`, `write` and `lock` are Read, Publish and Coordinate builds.

use vk_hub_proto::token::Grant;

use crate::egress::blocked::{Instances, instance_tag};
use crate::store::{CI_CACHE, CI_PIPELINE, NamespaceRow, NsGrant};
use crate::subject::{Projects, Subject};

/// The placeholders a namespace's path may hold.
const PLACEHOLDERS: [&str; 4] = ["{gitlab}", "{project_id}", "{pipeline_id}", "{protection}"];

/// Rights in plain words: `Read, Publish, Coordinate builds`, or `No access`.
pub(super) fn rights(read: bool, write: bool, lock: bool) -> String {
    let words: Vec<&str> = [
        (read, "Read"),
        (write, "Publish"),
        (lock, "Coordinate builds"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, w)| *w)
    .collect();
    if words.is_empty() {
        "No access".to_string()
    } else {
        words.join(", ")
    }
}

/// The jobs a subject selects, in plain words, its GitLab instance named as projects name it
/// ([`instance_tag`]) by the hub's `instances`: `Every job`, `Each project [gl], its own`,
/// `Projects under wab/ [gl], protected branches and tags only`, `Every job [every server]`.
pub(super) fn who(s: &Subject, instances: Instances<&str>) -> String {
    let tag = instance_tag(s.gitlab.as_deref(), instances);
    let mut text = match &s.projects {
        Projects::Own | Projects::Any if s.own_pipeline => format!("Each pipeline{tag}, its own"),
        Projects::Own => format!("Each project{tag}, its own"),
        Projects::Any => format!("Every job{tag}"),
        Projects::Path(glob) => match glob.strip_suffix("/**") {
            Some(under) if !under.contains('*') => format!("Projects under {under}/{tag}"),
            _ if glob.contains('*') => format!("Projects matching {glob}{tag}"),
            _ => format!("{glob}{tag}"),
        },
        Projects::Id(id) => format!("Project {id}{tag}"),
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

/// Namespace `ns` as a storage area, its rules' instance named by the hub's `instances`
/// ([`who`]).
pub(super) fn area(ns: &NamespaceRow, instances: Instances<&str>) -> Area {
    let line = |g: &NsGrant| who(&g.subject, instances);
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

/// The grant's source namespace, matched by its path with placeholders filled. `None` unless
/// exactly one namespace matches: none after a namespace change, several where paths overlap
/// (`p/{project_id}` and `p/{pipeline_id}`), which the prefix alone cannot tell apart.
pub(super) fn source<'a>(
    namespaces: &'a [NamespaceRow],
    grant: &Grant,
) -> Option<&'a NamespaceRow> {
    let prefix: Vec<&str> = grant.prefix.split('/').collect();
    let mut matching = namespaces.iter().filter(|ns| {
        let template: Vec<&str> = ns.path.split('/').collect();
        template.len() == prefix.len()
            && template
                .iter()
                .zip(&prefix)
                .all(|(t, p)| t == p || PLACEHOLDERS.contains(t))
    });
    let found = matching.next()?;
    matching.next().is_none().then_some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(text: &str) -> Subject {
        Subject::parse(text).unwrap()
    }

    #[test]
    fn rights_read_as_words() {
        assert_eq!(rights(true, false, false), "Read");
        assert_eq!(rights(true, true, true), "Read, Publish, Coordinate builds");
        assert_eq!(rights(false, false, true), "Coordinate builds");
        assert_eq!(rights(false, false, false), "No access");
    }

    /// With the hub's only instance, a rule names none; with several, its own or every server;
    /// with none, its own.
    #[test]
    fn subjects_read_as_who_they_select() {
        for (text, alone, several) in [
            ("*", "Every job", "Every job [every server]"),
            ("gitlab gl", "Every job", "Every job [gl]"),
            (
                "own project",
                "Each project, its own",
                "Each project [every server], its own",
            ),
            (
                "own project, own pipeline",
                "Each pipeline, its own",
                "Each pipeline [every server], its own",
            ),
            (
                "gitlab gl, own project",
                "Each project, its own",
                "Each project [gl], its own",
            ),
            (
                "gitlab gl, own project, own pipeline",
                "Each pipeline, its own",
                "Each pipeline [gl], its own",
            ),
            (
                "gitlab gl, own pipeline",
                "Each pipeline, its own",
                "Each pipeline [gl], its own",
            ),
            (
                "gitlab gl, projects wab/**, own pipeline",
                "Projects under wab/, its own pipeline",
                "Projects under wab/ [gl], its own pipeline",
            ),
            (
                "gitlab gl, project-id 7, own pipeline",
                "Project 7, its own pipeline",
                "Project 7 [gl], its own pipeline",
            ),
            (
                "own project, protected",
                "Each project, its own, protected branches and tags only",
                "Each project [every server], its own, protected branches and tags only",
            ),
            (
                "gitlab gl, projects wab/**",
                "Projects under wab/",
                "Projects under wab/ [gl]",
            ),
            (
                "gitlab gl, projects wab/*-ci",
                "Projects matching wab/*-ci",
                "Projects matching wab/*-ci [gl]",
            ),
            (
                "gitlab gl, projects infra/images, protected",
                "infra/images, protected branches and tags only",
                "infra/images [gl], protected branches and tags only",
            ),
            (
                "gitlab gl, project-id 1172",
                "Project 1172",
                "Project 1172 [gl]",
            ),
            (
                "gitlab gl, projects wab/**, ref release/*, protected",
                "Projects under wab/, refs matching release/*, protected branches and tags only",
                "Projects under wab/ [gl], refs matching release/*, protected branches and tags \
                 only",
            ),
            (
                "unprotected",
                "Every job, unprotected branches and tags only",
                "Every job [every server], unprotected branches and tags only",
            ),
        ] {
            let rule = subject(text);
            assert_eq!(who(&rule, Instances::Sole("gl")), alone, "{text}");
            assert_eq!(who(&rule, Instances::Several), several, "{text}");
            let none = several.replace(" [every server]", "");
            assert_eq!(who(&rule, Instances::None), none, "{text}");
        }
        // A rule of an instance the hub no longer has still names it.
        assert_eq!(
            who(
                &subject("gitlab old, projects wab/**"),
                Instances::Sole("gl")
            ),
            "Projects under wab/ [old]"
        );
    }

    fn ns(name: &str, path: &str, grants: &[&str]) -> NamespaceRow {
        NamespaceRow {
            name: name.into(),
            path: path.into(),
            retention_days: None,
            alias: None,
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
        let a = area(&wab, Instances::Several);
        assert_eq!(a.label, "wab");
        assert!(!a.managed);
        assert_eq!(
            a.readers,
            [
                "Projects under wab/ [gl], protected branches and tags only",
                "Projects under wab/ [gl]"
            ]
        );
        assert_eq!(
            a.publishers,
            [
                "Projects under wab/ [gl], protected branches and tags only · can coordinate \
                 builds",
                "Project 7 [gl] · coordinate builds only"
            ]
        );
        assert_eq!(
            area(&wab, Instances::Sole("gl")).readers[1],
            "Projects under wab/"
        );
        let cache = area(
            &ns(
                CI_CACHE,
                "ci-cache/{gitlab}/{project_id}/{protection}",
                &["rw:own project"],
            ),
            Instances::Several,
        );
        assert_eq!(cache.label, "CI caches");
        assert!(cache.managed);
    }

    #[test]
    fn a_grant_is_traced_to_the_namespace_it_came_from() {
        let all = [
            ns("images", "images", &["r:*"]),
            ns(
                "project",
                "p/{gitlab}/{project_id}",
                &["rw:gitlab gl, own project"],
            ),
            ns(
                CI_PIPELINE,
                "ci-pipeline/{gitlab}/{project_id}/{pipeline_id}",
                &["rwl:own project, own pipeline"],
            ),
        ];
        let grant = |prefix: &str| Grant {
            prefix: prefix.into(),
            read: true,
            ..Grant::default()
        };
        let name = |prefix| source(&all, &grant(prefix)).map(|n| n.name.as_str());
        assert_eq!(name("images"), Some("images"));
        assert_eq!(name("p/gl/1172"), Some("project"));
        assert_eq!(name("ci-pipeline/gl/1172/30551"), Some(CI_PIPELINE));
        assert_eq!(name("p/gl"), None);
        assert_eq!(name("other"), None);
        let overlapping = [
            ns("by-project", "q/{gitlab}/{project_id}", &["r:own project"]),
            ns(
                "by-pipeline",
                "q/{gitlab}/{pipeline_id}",
                &["r:own pipeline"],
            ),
        ];
        assert!(source(&overlapping, &grant("q/gl/7")).is_none());
    }
}
