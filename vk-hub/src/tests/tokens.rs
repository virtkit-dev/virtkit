//! Registry tokens: GitLab instances and keys' ceilings, a registry's URL, its token keys and
//! their rotation barrier, operator-minted tokens.

use vk_hub_proto::registry::{Inventory as RegistryInventory, Report as RegistryReport};
use vk_hub_proto::token::Grant;

use super::*;
use crate::store::{
    KeyPolicy, ProjectCeiling, RegistryEnrollment, RegistryWrite, Scope, TokenKind,
};
use crate::tokens::Keys;

pub(super) const REGISTRY_URL: &str = "https://reg.example.com";

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vk-hub-tokens-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_hub() -> Hub {
    Hub::new(Arc::new(Db::open_memory().unwrap()), None)
}

fn hub_with_keys(tag: &str) -> Hub {
    Hub::new(Arc::new(Db::open_memory().unwrap()), None).with_token_keys(
        scratch(tag).join("token-keys"),
        crate::tokens::DEFAULT_MAX_JOB_TOKEN,
    )
}

/// A registry enrolled with key `key`, bound to no URL.
pub(crate) fn enrolled_registry(hub: &Hub, key: &str) -> String {
    let now = now_secs();
    let (token, _) = hub
        .db
        .create_token_for(TokenKind::Registry, Duration::from_secs(60), None, "u", now)
        .unwrap();
    let RegistryEnrollment::Enrolled { id } = hub
        .db
        .enroll_registry(&token, key, "reg", "p", now)
        .unwrap()
    else {
        panic!("not enrolled");
    };
    id
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

/// A registry enrolled at `url`, taking tokens, that applied what the hub sent it.
pub(crate) fn token_registry(hub: &Hub, url: &str, key: &str) -> String {
    let now = now_secs();
    let id = url_registry(hub, url, key);
    let inventory = RegistryInventory {
        hostname: "reg-1".into(),
        tokens: true,
        allow: vec![vk_hub_proto::registry::ALLOW_GC.into()],
        ..RegistryInventory::default()
    };
    hub.db
        .record_registry(&id, RegistryWrite::Inventory(inventory), now)
        .unwrap();
    crate::tokens::sync_registry(hub, &id).unwrap();
    apply(hub, &id);
    id
}

/// Have registry `id` report applying the hub's desired state.
pub(crate) fn apply(hub: &Hub, id: &str) {
    let generation = hub
        .db
        .registry(id)
        .unwrap()
        .unwrap()
        .desired
        .unwrap()
        .generation;
    let report = RegistryReport {
        applied: Some(generation),
        ..RegistryReport::default()
    };
    hub.db
        .record_registry(id, RegistryWrite::Report(report), now_secs())
        .unwrap();
}

fn kid(token: &str) -> String {
    vk_hub_proto::token::parse(token).unwrap().claims.kid
}

#[test]
fn a_registry_taking_tokens_gets_keys_namespaces_and_retention() {
    let hub = hub_with_keys("sync");
    let id = token_registry(&hub, REGISTRY_URL, "aa");
    let row = hub.db.registry(&id).unwrap().unwrap();
    assert_eq!(row.url.as_deref(), Some(REGISTRY_URL));
    let desired = row.desired.unwrap();
    let keys = desired.token_keys.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        desired.prefix_retention.unwrap(),
        vec![vk_hub_proto::registry::PrefixRetention {
            prefix: "ci-pipeline".into(),
            retention_days: 2
        }]
    );
    let names: Vec<String> = hub
        .db
        .namespaces(&id)
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect();
    assert_eq!(names, ["ci-cache", "ci-pipeline"]);
    // Removing the defaults does not bring them back.
    hub.db
        .remove_namespace(&id, "ci-cache", "uid 0", 1)
        .unwrap();
    crate::tokens::sync_registry(&hub, &id).unwrap();
    assert_eq!(hub.db.namespaces(&id).unwrap().len(), 1);
}

#[test]
fn a_new_key_signs_only_once_the_registry_applied_it() {
    let hub = hub_with_keys("rotate");
    let id = token_registry(&hub, REGISTRY_URL, "aa");
    let grants = || {
        vec![Grant {
            prefix: "images".into(),
            read: true,
            ..Grant::default()
        }]
    };
    let mint = |hub: &Hub| {
        crate::tokens::mint(hub, "uid 0", &id, grants(), None, Duration::from_secs(60)).unwrap()
    };
    let first = mint(&hub);
    let k1 = kid(&first);
    let keys = hub
        .db
        .registry(&id)
        .unwrap()
        .unwrap()
        .desired
        .unwrap()
        .token_keys
        .unwrap();
    let claims = vk_peer::token::verify(&first, &keys, &id, now_secs()).unwrap();
    assert_eq!(claims.grants, grants());
    assert!(claims.sub.starts_with("operator:"));
    let k2 = crate::tokens::rotate(&hub, "uid 0").unwrap().public.kid;
    assert_ne!(k1, k2);
    let desired = hub.db.registry(&id).unwrap().unwrap().desired.unwrap();
    assert_eq!(desired.token_keys.unwrap().len(), 2);
    assert_eq!(
        kid(&mint(&hub)),
        k1,
        "signed before the registry applied the new key"
    );
    apply(&hub, &id);
    assert_eq!(kid(&mint(&hub)), k2);
    let audit = hub.db.audits(Some(&id), 50).unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.event.contains("minted registry token"))
    );
    assert!(
        audit.iter().all(|a| !a.event.contains("vkt_")),
        "a token reached the audit log"
    );
}

#[test]
fn a_registry_not_taking_tokens_gets_none() {
    let hub = hub_with_keys("none");
    let (token, _) = hub
        .db
        .create_token_for(TokenKind::Registry, Duration::from_secs(60), None, "u", 1)
        .unwrap();
    let RegistryEnrollment::Enrolled { id } =
        hub.db.enroll_registry(&token, "bb", "reg", "p", 1).unwrap()
    else {
        panic!("not enrolled");
    };
    crate::tokens::sync_registry(&hub, &id).unwrap();
    assert!(hub.db.registry(&id).unwrap().unwrap().desired.is_none());
    assert!(hub.db.namespaces(&id).unwrap().is_empty());
    let err =
        crate::tokens::mint(&hub, "u", &id, Vec::new(), None, Duration::from_secs(60)).unwrap_err();
    assert!(err.to_string().contains("does not take tokens"), "{err:#}");
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
        &["vk-hub", "token-keys", "rotate"],
        &["vk-hub", "namespaces", "list", "r"],
        &[
            "vk-hub",
            "namespaces",
            "add",
            "r",
            "images",
            "--path",
            "images",
            "--grant",
            "r:*",
        ],
        &["vk-hub", "registries", "set-url", "r", "https://reg"],
        &["vk-hub", "registries", "set-url", "r", "--none"],
        &[
            "vk-hub",
            "registries",
            "token",
            "r",
            "--grant",
            "images=r",
            "--ttl",
            "10m",
        ],
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
        &["vk-hub", "namespaces", "add", "r", "n", "--path", "p"],
    ] {
        assert!(crate::Cli::try_parse_from(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_key_retires_once_no_token_it_signed_can_live() {
    let dir = scratch("retire");
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None)
        .with_token_keys(dir.join("token-keys"), crate::tokens::DEFAULT_MAX_JOB_TOKEN);
    let id = token_registry(&hub, REGISTRY_URL, "aa");
    let old = hub.db.token_keys().unwrap().remove(0);
    // A newer key took over longer ago than any token lives.
    let long_ago =
        now_secs() - vk_hub_proto::token::MAX_TTL_SECS - vk_hub_proto::token::SKEW_SECS - 10;
    let new = hub.token_keys.generate().unwrap();
    hub.db.add_token_key(&new, "uid 0", long_ago).unwrap();
    let file = dir.join("token-keys").join(&old.file);
    assert!(file.exists());
    crate::tokens::sync_registry(&hub, &id).unwrap();
    let kids: Vec<String> = hub
        .db
        .token_keys()
        .unwrap()
        .into_iter()
        .map(|k| k.public.kid)
        .collect();
    assert_eq!(kids, std::slice::from_ref(&new.public.kid));
    assert!(!file.exists(), "the retired key's file is still there");
    let sent = hub
        .db
        .registry(&id)
        .unwrap()
        .unwrap()
        .desired
        .unwrap()
        .token_keys
        .unwrap();
    assert_eq!(sent, [new.public]);
}

#[test]
fn a_key_file_must_hold_its_row_s_key() {
    let dir = scratch("swap").join("token-keys");
    let keys = Keys::new(Some(dir.clone()), crate::tokens::DEFAULT_MAX_JOB_TOKEN);
    let a = keys.generate().unwrap();
    let b = keys.generate().unwrap();
    // Another hub process reads them from disk, with b's file under a's row.
    let fresh = Keys::new(Some(dir.clone()), crate::tokens::DEFAULT_MAX_JOB_TOKEN);
    let swapped = crate::store::TokenKeyRow {
        file: b.file.clone(),
        ..a.clone()
    };
    let err = fresh.signer(&swapped).err().expect("a mismatched file");
    assert!(
        err.to_string().contains("is not token-signing key"),
        "{err:#}"
    );
    assert!(fresh.signer(&a).is_ok());
}

#[test]
fn retention_goes_only_to_a_registry_allowing_gc_and_follows_namespaces() {
    let hub = hub_with_keys("retention");
    let (token, _) = hub
        .db
        .create_token_for(
            TokenKind::Registry,
            Duration::from_secs(60),
            Some(REGISTRY_URL),
            "u",
            1,
        )
        .unwrap();
    let RegistryEnrollment::Enrolled { id } =
        hub.db.enroll_registry(&token, "dd", "reg", "p", 1).unwrap()
    else {
        panic!("not enrolled");
    };
    let inventory = |allow: Vec<String>| RegistryInventory {
        tokens: true,
        allow,
        ..RegistryInventory::default()
    };
    hub.db
        .record_registry(
            &id,
            RegistryWrite::Inventory(inventory(Vec::new())),
            now_secs(),
        )
        .unwrap();
    crate::tokens::sync_registry(&hub, &id).unwrap();
    let desired = || hub.db.registry(&id).unwrap().unwrap().desired.unwrap();
    assert!(desired().token_keys.is_some());
    assert_eq!(desired().prefix_retention, None, "gc is not allowed");
    hub.db
        .record_registry(
            &id,
            RegistryWrite::Inventory(inventory(vec![vk_hub_proto::registry::ALLOW_GC.into()])),
            now_secs(),
        )
        .unwrap();
    crate::tokens::sync_registry(&hub, &id).unwrap();
    assert_eq!(desired().prefix_retention.unwrap().len(), 1);
    let images = crate::store::NamespaceRow {
        name: "images".into(),
        path: "images".into(),
        retention_days: Some(30),
        grants: vec![crate::store::NsGrant::parse("r:*").unwrap()],
        created_at: 1,
        created_by: "u".into(),
    };
    crate::registries::put_namespace(&hub, "u", &id, &images).unwrap();
    let windows: Vec<String> = desired()
        .prefix_retention
        .unwrap()
        .into_iter()
        .map(|r| format!("{}={}", r.prefix, r.retention_days))
        .collect();
    assert_eq!(windows, ["ci-pipeline=2", "images=30"]);
}

#[test]
fn a_removed_registry_takes_its_namespaces() {
    let hub = test_hub();
    let a = enrolled_registry(&hub, "aa");
    let images = crate::store::NamespaceRow {
        name: "images".into(),
        path: "images".into(),
        retention_days: None,
        grants: vec![crate::store::NsGrant::parse("r:*").unwrap()],
        created_at: 1,
        created_by: "u".into(),
    };
    hub.db.put_namespace(&a, &images, "u", 1).unwrap();
    assert!(!hub.db.namespaces(&a).unwrap().is_empty());
    assert!(hub.db.remove_registry(&a, "u", now_secs()).unwrap());
    assert!(hub.db.namespaces(&a).unwrap().is_empty());
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

#[test]
fn only_working_bound_keys_have_their_jobs_minted_for() {
    let db = Db::open_memory().unwrap();
    db.add_gitlab("gl", "https://gitlab.example.com", "u", 1)
        .unwrap();
    let ttl = Duration::from_secs(3600);
    let now = now_secs();
    db.create_api_key("bound", &policy(Some("gl"), Vec::new()), ttl, "u", now)
        .unwrap();
    db.create_api_key("plain", &policy(None, Vec::new()), ttl, "u", now)
        .unwrap();
    db.create_api_key("gone", &policy(Some("gl"), Vec::new()), ttl, "u", now)
        .unwrap();
    db.revoke_api_key("gone", "u", now).unwrap();
    let ids: std::collections::BTreeMap<String, String> = db
        .api_keys_with_ids()
        .unwrap()
        .into_iter()
        .map(|(id, row)| (row.name, id))
        .collect();
    let bound = db.mint_snapshot(now).unwrap().bound;
    assert_eq!(bound.len(), 1);
    assert_eq!(bound.get(&ids["bound"]).map(String::as_str), Some("gl"));
}
