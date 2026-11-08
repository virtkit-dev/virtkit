//! Registry tokens: GitLab instances and keys' ceilings, a registry's URL, its token keys and
//! their rotation barrier, operator-minted tokens.

use vk_hub_proto::registry::{Inventory as RegistryInventory, Report as RegistryReport};
use vk_hub_proto::token::Grant;

use super::*;
use crate::store::{RegistryEnrollment, RegistryWrite, TokenKind};
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
        vec![
            vk_hub_proto::registry::PrefixRetention {
                prefix: "ci-build".into(),
                retention_days: 14
            },
            vk_hub_proto::registry::PrefixRetention {
                prefix: "ci-pipeline".into(),
                retention_days: 2
            }
        ]
    );
    let names: Vec<String> = hub
        .db
        .namespaces(&id)
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect();
    assert_eq!(names, ["ci-build", "ci-cache", "ci-pipeline"]);
    // Removing the defaults does not bring them back.
    hub.db
        .remove_namespace(&id, "ci-cache", "uid 0", 1)
        .unwrap();
    crate::tokens::sync_registry(&hub, &id).unwrap();
    assert_eq!(hub.db.namespaces(&id).unwrap().len(), 2);
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
            hub.db
                .set_registry_url(&b, Some(taken), None, "u", 1)
                .is_err(),
            "{taken}"
        );
    }
    assert!(
        hub.db
            .set_registry_url(&b, Some("https://x/path"), None, "u", 1)
            .is_err()
    );
    assert!(
        hub.db
            .set_registry_url(&b, Some("https://reg-3.example.com/"), None, "u", 1)
            .unwrap()
    );
    assert_eq!(
        hub.db.registry(&b).unwrap().unwrap().url.as_deref(),
        Some("https://reg-3.example.com")
    );
    // A CA is taken with its URL, holding certificates, and goes when it is unbound.
    let ca = std::str::from_utf8(include_bytes!("../testdata/tls-ca.pem")).unwrap();
    let url = Some("https://reg-3.example.com");
    assert!(crate::registries::set_url(&hub, "u", &b, url, Some("not a CA")).is_err());
    assert!(crate::registries::set_url(&hub, "u", &b, url, Some(ca)).unwrap());
    assert_eq!(
        hub.db.registry(&b).unwrap().unwrap().ca_pem.as_deref(),
        Some(ca)
    );
    assert!(crate::registries::set_url(&hub, "u", &b, None, Some(ca)).unwrap());
    assert_eq!(hub.db.registry(&b).unwrap().unwrap().ca_pem, None);
    assert!(hub.db.set_registry_url(&a, None, None, "u", 1).unwrap());
}

#[test]
fn an_instance_s_url_names_one_instance() {
    let db = Db::open_memory().unwrap();
    db.add_gitlab("gl", "https://GitLab.example.com/", "u", 1)
        .unwrap();
    // Refusals the web UI may show, as their own type.
    for (name, url) in [
        ("gl2", "https://gitlab.example.com:443"),
        ("gl", "https://other.example.com"),
        ("GL", "https://other.example.com"),
        ("gl3", "ftp://other.example.com"),
    ] {
        let err = db.add_gitlab(name, url, "u", 1).unwrap_err();
        assert!(err.is::<crate::store::GitlabRefused>(), "{name}: {err:#}");
    }
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
        &["vk-hub", "keys", "create", "--name", "k", "--pool", "ci"],
        &["vk-hub", "gitlabs", "reject", "https://gitlab.example.com"],
        &["vk-hub", "gitlabs", "forget", "https://gitlab.example.com"],
        &["vk-hub", "gitlabs", "projects"],
        &["vk-hub", "gitlabs", "projects", "list", "gl", "--pending"],
        &[
            "vk-hub", "gitlabs", "projects", "approve", "gl", "1:a/b", "2",
        ],
        &["vk-hub", "gitlabs", "projects", "reject", "gl", "3"],
        &["vk-hub", "gitlabs", "projects", "forget", "gl", "1", "2"],
    ] {
        crate::Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
    }
    for bad in [
        &["vk-hub", "registries", "set-url", "r"][..],
        &[
            "vk-hub", "keys", "create", "--name", "k", "--pool", "ci", "--gitlab", "gl",
        ],
        &["vk-hub", "namespaces", "add", "r", "n", "--path", "p"],
        &["vk-hub", "gitlabs", "projects", "approve", "gl"],
        &["vk-hub", "gitlabs", "projects", "approve", "gl", "0:a"],
        &["vk-hub", "gitlabs", "projects", "forget", "gl", "x"],
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
    let kids = || -> Vec<String> {
        hub.db
            .token_keys()
            .unwrap()
            .into_iter()
            .map(|k| k.public.kid)
            .collect()
    };
    // The registry has not applied the new key: the old one still signs its tokens.
    crate::tokens::sync_registry(&hub, &id).unwrap();
    assert_eq!(kids(), [old.public.kid.clone(), new.public.kid.clone()]);
    assert!(file.exists());
    // It applies the new key; the old one counts as unused only from then.
    apply(&hub, &id);
    hub.db.retire_token_keys(0, long_ago).unwrap();
    crate::tokens::sync_registry(&hub, &id).unwrap();
    assert_eq!(kids(), std::slice::from_ref(&new.public.kid));
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
fn a_key_unused_only_lately_is_kept() {
    let hub = hub_with_keys("unused-lately");
    let id = token_registry(&hub, REGISTRY_URL, "aa");
    let long_ago =
        now_secs() - vk_hub_proto::token::MAX_TTL_SECS - vk_hub_proto::token::SKEW_SECS - 10;
    let new = hub.token_keys.generate().unwrap();
    hub.db.add_token_key(&new, "uid 0", long_ago).unwrap();
    crate::tokens::sync_registry(&hub, &id).unwrap();
    apply(&hub, &id);
    // Superseded long ago, but signing until the registry applied the new key just now.
    crate::tokens::sync_registry(&hub, &id).unwrap();
    let keys = hub.db.token_keys().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys[0].unused_since.is_some_and(|at| at > long_ago));
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
    assert_eq!(desired().prefix_retention.unwrap().len(), 2);
    let images = crate::store::NamespaceRow {
        name: "images".into(),
        path: "images".into(),
        retention_days: Some(30),
        alias: None,
        isolate: Vec::new(),
        grants: vec![crate::store::NsGrant::parse("r:*").unwrap()],
        node_grants: Vec::new(),
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
    assert_eq!(windows, ["ci-build=14", "ci-pipeline=2", "images=30"]);
}

/// A CLI that knows no isolated refs leaves out `isolate` when it replaces a namespace: the
/// namespace keeps the refs it isolated rather than letting them fall back into `all`.
#[test]
fn an_older_cli_replacing_a_namespace_keeps_its_isolated_refs() {
    let hub = test_hub();
    let id = enrolled_registry(&hub, "aa");
    let put = |isolate: Option<&[&str]>| {
        let mut call = serde_json::json!({
            "op": "put-namespace", "id": id, "name": "tc",
            "path": "tc/{gitlab}/{project_id}/{protection}/{scope}",
            "retention_days": null, "grants": ["rwl:own project"],
        });
        if let Some(isolate) = isolate {
            call["isolate"] = serde_json::json!(isolate);
        }
        let body = serde_json::json!({"v": 1, "call": call});
        crate::admin::dispatch(&serde_json::to_vec(&body).unwrap(), &hub, 0).unwrap();
        let stored = hub.db.namespaces(&id).unwrap();
        stored.into_iter().find(|n| n.name == "tc").unwrap().isolate
    };
    assert_eq!(put(Some(&["main"])), ["main"]);
    assert_eq!(put(None), ["main"]);
    assert!(put(Some(&[])).is_empty());
}

#[test]
fn a_removed_registry_takes_its_namespaces() {
    let hub = test_hub();
    let a = enrolled_registry(&hub, "aa");
    let images = crate::store::NamespaceRow {
        name: "images".into(),
        path: "images".into(),
        retention_days: None,
        alias: None,
        isolate: Vec::new(),
        grants: vec![crate::store::NsGrant::parse("r:*").unwrap()],
        node_grants: Vec::new(),
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
        .set_registry_url(&b, Some("http://reg-2.example.com:443"), None, "u", 1)
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
fn only_relays_of_approved_servers_have_their_jobs_minted_for() {
    let db = Db::open_memory().unwrap();
    db.add_gitlab("gl", "https://gitlab.example.com", "u", 1)
        .unwrap();
    let relay = |key: &str, url: &str| {
        let (token, _) = db
            .create_token_for(TokenKind::Gitlab, Duration::from_secs(60), None, "u", 1)
            .unwrap();
        let crate::store::RelayEnrollment::Enrolled { id } =
            db.enroll_relay(&token, key, "h", "p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        let mut inventory = vk_hub_proto::gitlab::Inventory::default();
        inventory.server.url = url.into();
        db.record_relay(&id, crate::store::RelayWrite::Inventory(inventory), 1)
            .unwrap();
        id
    };
    let approved = relay("aa", "https://gitlab.example.com/");
    relay("bb", "https://pending.example.com");
    relay("cc", "https://rejected.example.com");
    db.reject_gitlab("https://rejected.example.com", "u", 2)
        .unwrap();
    let bound = db.mint_snapshot().unwrap().bound;
    assert_eq!(bound.len(), 1);
    assert_eq!(bound.get(&approved).map(String::as_str), Some("gl"));
}

/// Removing a node revokes its tokens' subject in the same write, and the registries that
/// refuse revoked subjects get it at once; one that does not is sent none. The subject goes
/// once no token for it can be live.
#[test]
fn a_removed_node_s_subject_is_revoked_on_registries_that_take_it() {
    let hub = hub_with_keys("revoked");
    let capable = token_registry(&hub, REGISTRY_URL, "aa");
    let older = token_registry(&hub, "https://older.example.com", "bb");
    let inventory = RegistryInventory {
        hostname: "reg-1".into(),
        tokens: true,
        revokes_subjects: true,
        ..RegistryInventory::default()
    };
    hub.db
        .record_registry(&capable, RegistryWrite::Inventory(inventory), now_secs())
        .unwrap();
    crate::tokens::sync_registry(&hub, &capable).unwrap();
    let revoked = |id: &str| {
        let row = hub.db.registry(id).unwrap().unwrap();
        assert!(row.takes_tokens());
        row.desired.unwrap().revoked_subjects
    };
    assert_eq!(revoked(&capable), Some(Vec::new()));
    assert_eq!(revoked(&older), None);

    let node = enroll_as(&hub, "n1");
    let kept = enroll_as(&hub, "n2");
    let remove = |id: &str| {
        let body = serde_json::json!({"v": 1, "call": {"op": "remove-node", "id": id}});
        crate::admin::dispatch(&serde_json::to_vec(&body).unwrap(), &hub, 0).unwrap()
    };
    assert_eq!(remove(&node), serde_json::json!(true));
    let subject = vk_hub_proto::token::node_subject(&node);
    assert_eq!(revoked(&capable), Some(vec![subject.clone()]));
    assert_eq!(revoked(&older), None);
    assert!(hub.db.node(&kept).unwrap().is_some());
    // No node, nothing revoked.
    assert_eq!(remove(&"0".repeat(32)), serde_json::json!(false));
    assert_eq!(hub.db.revoked_subjects(now_secs()).unwrap(), [subject]);

    // Past any token's life, it is pruned and the registry sent an empty list.
    let later = now_secs() + vk_hub_proto::token::MAX_TTL_SECS + vk_hub_proto::token::SKEW_SECS + 1;
    assert!(hub.db.revoked_subjects(later).unwrap().is_empty());
    hub.db.prune_revoked_subjects(later).unwrap();
    assert!(hub.db.revoked_subjects(now_secs()).unwrap().is_empty());
    crate::tokens::sync_registry(&hub, &capable).unwrap();
    assert_eq!(revoked(&capable), Some(Vec::new()));
}

/// Node `id` reporting `registry` as the one its `[registry]` names.
fn uses_registry(hub: &Hub, id: &str, registry: Option<&str>) {
    let inventory = vk_hub_proto::Inventory {
        hostname: "n".into(),
        registry: registry.map(String::from),
        ..vk_hub_proto::Inventory::default()
    };
    hub.db
        .record_inventory(id, inventory, true, now_secs())
        .unwrap();
}

/// Registry `id` announcing that it refuses revoked subjects.
fn revokes(hub: &Hub, id: &str) {
    let inventory = RegistryInventory {
        hostname: "reg-1".into(),
        tokens: true,
        revokes_subjects: true,
        ..RegistryInventory::default()
    };
    hub.db
        .record_registry(id, RegistryWrite::Inventory(inventory), now_secs())
        .unwrap();
    crate::tokens::sync_registry(hub, id).unwrap();
}

/// Namespace `name` at literal `path` on registry `id`, with grant lines `grants`.
fn grant(hub: &Hub, id: &str, name: &str, path: &str, grants: &[&str]) {
    let (grants, node_grants) = crate::store::parse_grants(grants).unwrap();
    let ns = crate::store::NamespaceRow {
        name: name.into(),
        path: path.into(),
        retention_days: None,
        alias: None,
        isolate: Vec::new(),
        grants,
        node_grants,
        created_at: 1,
        created_by: "u".into(),
    };
    crate::registries::put_namespace(hub, "u", id, &ns).unwrap();
}

fn target(hub: &Hub, node: &str) -> crate::tokens::NodeTarget {
    let ctx = crate::tokens::MintCtx::read(&hub.db, &hub.token_keys).unwrap();
    let row = hub.db.node(node).unwrap().unwrap();
    crate::tokens::node_target(&ctx, node, &row)
}

/// A node's own access needs, in turn: a registry named, bound and taking tokens, refusing a
/// removed node's, granting the node something, and a key it applied; what it is minted with.
#[test]
fn a_node_gets_access_where_its_registry_takes_and_grants_it() {
    use crate::tokens::NodeTarget;
    let hub = hub_with_keys("node-access");
    let id = token_registry(&hub, REGISTRY_URL, "aa");
    let node = enroll_as(&hub, "n1");
    let clear = |hub: &Hub| matches!(target(hub, &node), NodeTarget::Clear(_));
    assert!(clear(&hub));
    uses_registry(&hub, &node, Some("https://elsewhere.example.com"));
    assert!(clear(&hub));
    uses_registry(&hub, &node, Some(REGISTRY_URL));
    // A registry that would accept a removed node's token gets none.
    grant(&hub, &id, "images", "images", &["r:nodes"]);
    assert_eq!(
        target(&hub, &node),
        NodeTarget::Clear("the node's registry does not refuse a removed node's tokens")
    );
    revokes(&hub, &id);
    apply(&hub, &id);
    let NodeTarget::Grant(binding) = target(&hub, &node) else {
        panic!("expected a grant, got {:?}", target(&hub, &node));
    };
    assert_eq!(binding.registry, id);
    assert_eq!(binding.origin, REGISTRY_URL);
    assert_eq!(binding.ca_sha256, None);
    assert_eq!(crate::tokens::grants_text(&binding.grants), "images=r");
    // Job grant lines give nodes nothing.
    grant(&hub, &id, "images", "images", &["r:*"]);
    assert_eq!(
        target(&hub, &node),
        NodeTarget::Clear("no namespace grants the node anything")
    );
    grant(&hub, &id, "images", "images", &[&format!("rw:node {node}")]);
    let NodeTarget::Grant(binding) = target(&hub, &node) else {
        panic!("expected a grant");
    };
    assert_eq!(crate::tokens::grants_text(&binding.grants), "images=rw");

    let ctx = crate::tokens::MintCtx::read(&hub.db, &hub.token_keys).unwrap();
    let access =
        crate::tokens::for_node(&hub.db, &hub.token_keys, &ctx, &node, &binding, false).unwrap();
    assert_eq!(
        (access.registry_id.as_str(), access.origin.as_str()),
        (id.as_str(), REGISTRY_URL)
    );
    assert_eq!(
        access.expires_at - access.issued_at,
        crate::tokens::NODE_TOKEN_TTL
    );
    assert_eq!(access.guest_token, None);
    let claims = vk_hub_proto::token::parse(&access.token).unwrap().claims;
    assert_eq!(claims.sub, vk_hub_proto::token::node_subject(&node));
    assert_eq!(claims.aud, id);
    assert_eq!(claims.pipeline, None);
    assert_eq!(
        (claims.iat, claims.exp),
        (access.issued_at, access.expires_at)
    );
    assert_eq!(claims.grants, binding.grants);
    // Audited under the registry by jti, never the token; a renewal is not.
    let issued = |hub: &Hub| {
        hub.db
            .audits(Some(&id), 50)
            .unwrap()
            .into_iter()
            .filter(|a| a.event.contains(&format!("for node {node}")))
            .inspect(|a| assert!(!a.event.contains("vkt_")))
            .count()
    };
    assert_eq!(issued(&hub), 1);
    crate::tokens::for_node(&hub.db, &hub.token_keys, &ctx, &node, &binding, true).unwrap();
    assert_eq!(issued(&hub), 1);

    // Removed, it gets none: removal and minting are serialized, the row read under the lock.
    assert!(crate::tokens::remove_node(&hub, &node, "uid 0").unwrap());
    let e = crate::tokens::for_node(&hub.db, &hub.token_keys, &ctx, &node, &binding, false)
        .unwrap_err();
    assert!(e.is::<crate::store::NotEnrolled>(), "{e:#}");
}

/// Namespaces granting guests give a node a second token for its runner's guests: its own jti,
/// the same subject and lifetime, its node's grants narrowed to the guests'; none without.
#[test]
fn a_node_s_guests_get_a_narrower_token_of_their_own() {
    use crate::tokens::NodeTarget;
    let hub = hub_with_keys("node-guest-access");
    let id = token_registry(&hub, REGISTRY_URL, "aa");
    revokes(&hub, &id);
    apply(&hub, &id);
    let node = enroll_as(&hub, "n1");
    uses_registry(&hub, &node, Some(REGISTRY_URL));
    grant(&hub, &id, "images", "images", &["r:nodes"]);
    grant(
        &hub,
        &id,
        "cache",
        "build-cache",
        &["rwl:nodes", "rw:guests"],
    );
    let NodeTarget::Grant(binding) = target(&hub, &node) else {
        panic!("expected a grant");
    };
    assert_eq!(
        crate::tokens::grants_text(&binding.guest_grants),
        "build-cache=rw"
    );
    let ctx = crate::tokens::MintCtx::read(&hub.db, &hub.token_keys).unwrap();
    let access =
        crate::tokens::for_node(&hub.db, &hub.token_keys, &ctx, &node, &binding, false).unwrap();
    let host = vk_hub_proto::token::parse(&access.token).unwrap().claims;
    let guest = vk_hub_proto::token::parse(access.guest_token.as_deref().unwrap())
        .unwrap()
        .claims;
    assert_eq!(guest.grants, binding.guest_grants);
    assert_eq!(access.guest_grants, binding.guest_grants);
    assert_eq!(
        (guest.sub.as_str(), guest.aud.as_str(), guest.exp),
        (host.sub.as_str(), host.aud.as_str(), host.exp)
    );
    assert_ne!(guest.jti, host.jti);
    let audited = hub.db.audits(Some(&id), 50).unwrap();
    assert!(audited.iter().any(|a| a.event.contains(&guest.jti)));
    // Without lines for guests, none.
    grant(&hub, &id, "cache", "build-cache", &["rwl:nodes"]);
    let NodeTarget::Grant(binding) = target(&hub, &node) else {
        panic!("expected a grant");
    };
    assert!(binding.guest_grants.is_empty());
    let access =
        crate::tokens::for_node(&hub.db, &hub.token_keys, &ctx, &node, &binding, false).unwrap();
    assert_eq!(access.guest_token, None);
}

/// Until its registry applies a signing key, a node's access waits rather than clears; the CA
/// the hub names the registry with binds it.
#[test]
fn a_node_s_access_waits_for_an_applied_key() {
    use crate::tokens::NodeTarget;
    let hub = hub_with_keys("node-access-wait");
    let id = url_registry(&hub, REGISTRY_URL, "aa");
    revokes(&hub, &id);
    grant(&hub, &id, "images", "images", &["r:nodes"]);
    let node = enroll_as(&hub, "n1");
    uses_registry(&hub, &node, Some(REGISTRY_URL));
    assert!(matches!(target(&hub, &node), NodeTarget::Wait(_)));
    apply(&hub, &id);
    let NodeTarget::Grant(binding) = target(&hub, &node) else {
        panic!("expected a grant");
    };
    assert_eq!(binding.ca_sha256, None);
    let ca = String::from_utf8(super::TLS_CA.to_vec()).unwrap();
    crate::registries::set_url(&hub, "u", &id, Some(REGISTRY_URL), Some(&ca)).unwrap();
    let NodeTarget::Grant(bound) = target(&hub, &node) else {
        panic!("expected a grant");
    };
    use sha2::Digest;
    assert_eq!(
        bound.ca_sha256,
        Some(vk_hub_proto::to_hex(&sha2::Sha256::digest(ca.as_bytes())))
    );
}

/// Over a session: a node speaking [`vk_hub_proto::REGISTRY_ACCESS`] gets its access once its
/// inventory names the registry, and a clear once nothing grants it; an older one gets
/// neither.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_delivers_and_clears_a_node_s_access() {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Arc::new(hub_with_keys("node-access-session"));
    tokio::spawn(crate::server::serve(listener, None, hub.clone()));
    let id = token_registry(&hub, REGISTRY_URL, "aa");
    revokes(&hub, &id);
    apply(&hub, &id);
    grant(&hub, &id, "images", "images", &["r:nodes"]);

    let key = keypair();
    let node = enrolled(addr, &hub, &key).await;
    let inventory = NodeMsg::Inventory(vk_hub_proto::Inventory {
        hostname: "n".into(),
        registry: Some(REGISTRY_URL.into()),
        ..vk_hub_proto::Inventory::default()
    });

    // Version 6: nothing of it, while the session carries on.
    let v6 = VersionRange {
        min: 1,
        max: vk_hub_proto::LIVE_EGRESS,
    };
    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(v6),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &node, &"31".repeat(16), &key, twist).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &inventory).await;
    send(&mut ws, &NodeMsg::Report(vk_hub_proto::Report::default())).await;
    let quiet = tokio::time::timeout(Duration::from_millis(500), receive(&mut ws)).await;
    assert!(
        !matches!(quiet, Ok(HubMsg::RegistryAccess { .. })),
        "{quiet:?}"
    );

    let v7 = VersionRange {
        min: 1,
        max: vk_hub_proto::REGISTRY_ACCESS,
    };
    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(v7),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &node, &"32".repeat(16), &key, twist).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &inventory).await;
    let HubMsg::RegistryAccess {
        access: Some(access),
    } = receive(&mut ws).await
    else {
        panic!("expected access");
    };
    assert_eq!(access.registry_id, id);
    let claims = vk_hub_proto::token::parse(&access.token).unwrap().claims;
    assert_eq!(claims.sub, vk_hub_proto::token::node_subject(&node));

    // No longer granted: cleared at once.
    grant(&hub, &id, "images", "images", &["r:*"]);
    assert_eq!(
        receive(&mut ws).await,
        HubMsg::RegistryAccess { access: None }
    );
    // Granted again: minted again.
    grant(&hub, &id, "images", "images", &["r:nodes"]);
    assert!(matches!(
        receive(&mut ws).await,
        HubMsg::RegistryAccess { access: Some(_) }
    ));
}
