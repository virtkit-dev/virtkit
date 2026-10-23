//! Registry tokens: GitLab instances and keys' ceilings, a registry's URL.

use super::*;
use crate::store::{KeyPolicy, ProjectCeiling, RegistryEnrollment, Scope, TokenKind};

pub(super) const REGISTRY_URL: &str = "https://reg.example.com";

fn test_hub() -> Hub {
    Hub::new(Arc::new(Db::open_memory().unwrap()), None)
}

/// A registry enrolled at `url` with key `key`.
pub(crate) fn url_registry(hub: &Hub, url: &str, key: &str) -> String {
    let now = now_secs();
    let (token, _) = hub
        .db
        .create_token_for(
            TokenKind::Registry,
            Duration::from_secs(60),
            Some(url),
            "uid 0",
            now,
        )
        .unwrap();
    let RegistryEnrollment::Enrolled { id } = hub
        .db
        .enroll_registry(&token, key, "reg-1", "peer p", now)
        .unwrap()
    else {
        panic!("not enrolled");
    };
    id
}

#[test]
fn a_registry_url_is_bound_once() {
    let hub = test_hub();
    let a = url_registry(&hub, REGISTRY_URL, "aa");
    let err = hub
        .db
        .create_token_for(
            TokenKind::Registry,
            Duration::from_secs(60),
            Some("https://REG.example.com:443"),
            "u",
            1,
        )
        .unwrap_err();
    assert!(err.to_string().contains(&a), "{err:#}");
    assert!(
        hub.db
            .create_token_for(
                TokenKind::Node,
                Duration::from_secs(60),
                Some(REGISTRY_URL),
                "u",
                1
            )
            .is_err()
    );
    let b = url_registry(&hub, "https://reg-2.example.com", "bb");
    for taken in [REGISTRY_URL, "http://reg.example.com:443"] {
        assert!(
            hub.db.set_registry_url(&b, Some(taken), "u", 1).is_err(),
            "{taken}"
        );
    }
    assert!(
        hub.db
            .set_registry_url(&b, Some("https://x/path"), "u", 1)
            .is_err()
    );
    assert!(
        hub.db
            .set_registry_url(&b, Some("https://reg-3.example.com/"), "u", 1)
            .unwrap()
    );
    assert_eq!(
        hub.db.registry(&b).unwrap().unwrap().url.as_deref(),
        Some("https://reg-3.example.com")
    );
    assert!(hub.db.set_registry_url(&a, None, "u", 1).unwrap());
}

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
        &["vk-hub", "registries", "set-url", "r", "https://reg"],
        &["vk-hub", "registries", "set-url", "r", "--none"],
        &[
            "vk-hub",
            "token",
            "create",
            "--kind",
            "registry",
            "--url",
            "https://reg",
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
    for bad in [
        &["vk-hub", "registries", "set-url", "r"][..],
        &[
            "vk-hub",
            "keys",
            "create",
            "--name",
            "k",
            "--pool",
            "ci",
            "--projects",
            "1:a",
        ],
    ] {
        assert!(crate::Cli::try_parse_from(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_url_taken_since_the_token_was_issued_is_not_bound() {
    let hub = test_hub();
    let a = url_registry(&hub, REGISTRY_URL, "aa");
    // A token issued for a URL, which another registry takes before it is spent.
    let (token, _) = hub
        .db
        .create_token_for(
            TokenKind::Registry,
            Duration::from_secs(60),
            Some("https://reg-2.example.com"),
            "u",
            now_secs(),
        )
        .unwrap();
    let b = url_registry(&hub, "https://reg-3.example.com", "bb");
    hub.db
        .set_registry_url(&b, Some("http://reg-2.example.com:443"), "u", 1)
        .unwrap();
    let RegistryEnrollment::Reenrolled { id } = hub
        .db
        .enroll_registry(&token, "aa", "reg", "p", now_secs())
        .unwrap()
    else {
        panic!("not enrolled again");
    };
    assert_eq!(id, a);
    assert_eq!(
        hub.db.registry(&a).unwrap().unwrap().url.as_deref(),
        Some(REGISTRY_URL)
    );
    let audit = hub.db.audits(Some(&a), 20).unwrap();
    assert!(
        audit.iter().any(|e| e.event.contains("so it is not bound")),
        "{audit:?}"
    );
}
