//! Registry tokens: GitLab instances and keys' ceilings.

use super::*;
use crate::store::{KeyPolicy, ProjectCeiling, Scope};

fn policy(gitlab: Option<&str>, projects: Vec<ProjectCeiling>) -> KeyPolicy {
    KeyPolicy {
        scopes: vec![Scope::Jobs],
        pools: vec!["ci".into()],
        max_envelope: None,
        gitlab: gitlab.map(str::to_string),
        projects,
    }
}

#[test]
fn a_bound_key_submits_its_instance_s_listed_projects_only() {
    let db = Db::open_memory().unwrap();
    let ttl = Duration::from_secs(3600);
    assert!(
        db.create_api_key("a", &policy(Some("gl"), Vec::new()), ttl, "u", 1)
            .is_err(),
        "an unknown instance"
    );
    db.add_gitlab("gl", "https://GitLab.example.com/", "u", 1)
        .unwrap();
    assert!(
        db.add_gitlab("gl2", "https://gitlab.example.com", "u", 1)
            .is_err()
    );
    let listed = vec![ProjectCeiling::parse("42:wab/core").unwrap()];
    assert!(
        db.create_api_key("b", &policy(None, listed.clone()), ttl, "u", 1)
            .is_err(),
        "projects without an instance"
    );
    let (key, _) = db
        .create_api_key("c", &policy(Some("gl"), listed), ttl, "u", 1)
        .unwrap();
    let principal = db.api_key(&key, 2).unwrap().unwrap();
    let url = db.gitlab("gl").unwrap().unwrap().url;
    let mut ci = vk_hub_proto::job::CiJob {
        server_url: "https://gitlab.example.com:443".into(),
        ..vk_hub_proto::job::CiJob::default()
    };
    ci.job.project_id = 42;
    ci.job.project_path = "wab/core".into();
    assert_eq!(principal.refuses_job(&ci, Some(&url)), None);
    let mut other_path = ci.clone();
    other_path.job.project_path = "wab/other".into();
    assert!(principal.refuses_job(&other_path, Some(&url)).is_some());
    let mut other_id = ci.clone();
    other_id.job.project_id = 43;
    assert!(principal.refuses_job(&other_id, Some(&url)).is_some());
    let mut other_gitlab = ci.clone();
    other_gitlab.server_url = "https://evil.example.com".into();
    assert!(principal.refuses_job(&other_gitlab, Some(&url)).is_some());
    assert!(
        principal.refuses_job(&ci, None).is_some(),
        "instance removed"
    );
    assert!(db.remove_gitlab("gl", "u", 2).is_err(), "a key is bound");
    db.revoke_api_key("c", "u", 3).unwrap();
    assert!(db.remove_gitlab("gl", "u", 3).unwrap());
}

#[test]
fn the_token_commands_parse() {
    use clap::Parser;
    for args in [
        &["vk-hub", "gitlabs"][..],
        &[
            "vk-hub",
            "gitlabs",
            "add",
            "gl",
            "https://gitlab.example.com",
        ],
        &[
            "vk-hub",
            "keys",
            "create",
            "--name",
            "k",
            "--pool",
            "ci",
            "--gitlab",
            "gl",
            "--projects",
            "1:a/b,2:c/d",
        ],
    ] {
        crate::Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
    }
    let bad = [
        "vk-hub",
        "keys",
        "create",
        "--name",
        "k",
        "--pool",
        "ci",
        "--projects",
        "1:a",
    ];
    assert!(crate::Cli::try_parse_from(bad).is_err(), "{bad:?}");
}
