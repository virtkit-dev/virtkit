//! End-to-end accounts-mode test: a real server, real HTTP, seeded sessions/API keys
//! (bypassing the OIDC network round-trip, which `oidc.rs`'s own tests already cover
//! against a fake IdP) — proves the `Principal` → `authorize()` wiring actually gates
//! `/v2/*` and `/browse` over the wire, not just as isolated unit calls.

use std::sync::Arc;
use std::time::Duration;

use vk_registry::accounts::{Action, Db, Scope};
use vk_registry::config::{AuthMode, OidcSpec};
use vk_registry::{Authenticator, ServerConfig, ServerState};

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-accounts-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn spawn(state: Arc<ServerState>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(listener).unwrap();
            let _ = vk_registry::serve_on(l, state).await;
        });
    });
    format!("http://{addr}")
}

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Accounts-mode state built the way `serve` builds it — see the identical helper in
/// `relay_e2e.rs`. Discovery is deferred to the first login, so naming a provider costs
/// no network.
fn accounts_state(dir: &std::path::Path) -> Arc<ServerState> {
    std::fs::create_dir_all(dir).unwrap();
    let secret = dir.join("oidc-secret");
    std::fs::write(&secret, "s3cr3t\n").unwrap();
    let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    cfg.mode = AuthMode::Accounts;
    cfg.oidc = Some(OidcSpec {
        issuer: "https://login.example.com".to_string(),
        client_id: "vk-registry".to_string(),
        client_secret_file: secret,
        public_url: "https://registry.internal".to_string(),
    });
    Arc::new(cfg.into_state().expect("a valid accounts config starts"))
}

/// The accounts db that server opened, for seeding users and keys into.
fn accounts_db(state: &ServerState) -> &Db {
    match &state.auth {
        Authenticator::Accounts { db, .. } => db,
        _ => panic!("not accounts mode"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accounts_mode_gates_v2_and_browse_by_scope() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("main");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);

    let admin = db
        .upsert_user("https://issuer", "admin", None, None)
        .unwrap();
    db.set_admin(&admin.id, true).unwrap();
    let admin_session = db
        .create_session(&admin.id, Duration::from_secs(3600))
        .unwrap();

    let plain_user = db
        .upsert_user("https://issuer", "plain", None, None)
        .unwrap();
    let plain_session = db
        .create_session(&plain_user.id, Duration::from_secs(3600))
        .unwrap();

    let (_, team_a_key) = db
        .create_api_key(
            Some(&plain_user.id),
            "ci",
            &[Scope {
                action: Action::Write,
                repo_pattern: "team-a/*".to_string(),
            }],
            None,
        )
        .unwrap();

    // a key that may only read, and only under team-a
    let (_, read_only_key) = db
        .create_api_key(
            Some(&plain_user.id),
            "ci-read",
            &[Scope {
                action: Action::Read,
                repo_pattern: "team-a/*".to_string(),
            }],
            None,
        )
        .unwrap();

    let url = spawn(state.clone());
    let client = no_redirect_client();

    // No credentials at all: /v2/ is the plain 401 an OCI client expects.
    let resp = client.get(format!("{url}/v2/")).send().await.unwrap();
    assert_eq!(resp.status(), 401);

    // No credentials, a browser page: redirected to /login instead — for every path a
    // person reaches, not just /browse.
    for p in ["/browse", "/browse/team-a/app", "/settings/keys"] {
        let resp = client.get(format!("{url}{p}")).send().await.unwrap();
        assert_eq!(resp.status(), 302, "{p}");
        assert!(
            resp.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("/login?target="),
            "{p}"
        );
    }

    // Any signed-in session can read.
    let resp = client
        .get(format!("{url}/v2/team-a/app/tags/list"))
        .header("Cookie", format!("__Host-vk_session={plain_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A plain (non-admin) session cannot write.
    let resp = client
        .put(format!("{url}/v2/team-a/app/manifests/v1"))
        .header("Cookie", format!("__Host-vk_session={plain_session}"))
        .body(r#"{"schemaVersion":2,"config":{"digest":"sha256:00","size":0},"layers":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // An admin session can write anywhere.
    let resp = client
        .put(format!("{url}/v2/team-a/app/manifests/v1"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .body(r#"{"schemaVersion":2,"config":{"digest":"sha256:00","size":0},"layers":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // A key scoped to team-a/* can push to team-a/... ...
    let resp = client
        .put(format!("{url}/v2/team-a/other/manifests/v1"))
        .bearer_auth(&team_a_key)
        .body(r#"{"schemaVersion":2,"config":{"digest":"sha256:00","size":0},"layers":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // ... but not to team-b/... .
    let resp = client
        .put(format!("{url}/v2/team-b/app/manifests/v1"))
        .bearer_auth(&team_a_key)
        .body(r#"{"schemaVersion":2,"config":{"digest":"sha256:00","size":0},"layers":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // A read-only key reads where it is scoped and writes nowhere: `Write` implies `Read`,
    // never the other way round, and the route has to enforce the direction the matcher
    // does.
    let resp = client
        .get(format!("{url}/v2/team-a/app/tags/list"))
        .bearer_auth(&read_only_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{url}/v2/team-a/app/blobs/uploads/"))
        .bearer_auth(&read_only_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a read scope opens no upload session");
    let resp = client
        .put(format!("{url}/v2/team-a/app/manifests/v2"))
        .bearer_auth(&read_only_key)
        .body(r#"{"schemaVersion":2,"config":{"digest":"sha256:00","size":0},"layers":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "nor pushes a manifest");

    // A tag listing is a per-repo read like any other: outside the scope it is refused,
    // and refused before the store is consulted, so it is no existence oracle either.
    let resp = client
        .get(format!("{url}/v2/team-b/app/tags/list"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = client
        .get(format!("{url}/v2/team-b/never-pushed/tags/list"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a repo that does not exist answers the same as one that does"
    );

    // A write scope also satisfies a read of the same repo.
    let resp = client
        .get(format!("{url}/v2/team-a/other/manifests/v1"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // ... but still not a read of an out-of-scope repo.
    let resp = client
        .get(format!("{url}/v2/team-b/app/manifests/v1"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // HEAD is the dedup probe a push leans on, and it takes the same read gate.
    let resp = client
        .head(format!("{url}/v2/team-b/app/manifests/v1"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // The blob branches are gated too — starting an upload and reading a blob.
    let resp = client
        .post(format!("{url}/v2/team-b/app/blobs/uploads/"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = client
        .post(format!("{url}/v2/team-a/app/blobs/uploads/"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let absent = format!("sha256:{}", "0".repeat(64));
    let resp = client
        .get(format!("{url}/v2/team-b/app/blobs/{absent}"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "denied before the store is consulted");
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{absent}"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // An upload started in one repo cannot be finished in another.
    let resp = client
        .post(format!("{url}/v2/team-a/app/blobs/uploads/"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    let upload = resp.headers()["location"].to_str().unwrap().to_string();
    let id = upload.rsplit('/').next().unwrap();
    let body = b"layer bytes".to_vec();
    let digest = format!(
        "sha256:{}",
        <sha2::Sha256 as sha2::Digest>::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let resp = client
        .put(format!(
            "{url}/v2/team-b/app/blobs/uploads/{id}?digest={}",
            digest.replace(':', "%3A")
        ))
        .bearer_auth(&team_a_key)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "team-b is not this key's to write");

    // ... and finishing it with a digest that is not the digest of the bytes is refused.
    let resp = client
        .put(format!(
            "{url}/v2/team-a/app/blobs/uploads/{id}?digest={}",
            absent.replace(':', "%3A")
        ))
        .bearer_auth(&team_a_key)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Give team-b a repository to be excluded from, written by the admin session (the
    // team-a key is refused there, as asserted above).
    let resp = client
        .put(format!("{url}/v2/team-b/app/manifests/v1"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .body(r#"{"schemaVersion":2,"config":{"digest":"sha256:00","size":0},"layers":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // /browse shows a principal only what it may read, and an out-of-scope repo reads
    // as absent rather than as forbidden.
    let listing = client
        .get(format!("{url}/browse"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(listing.contains("team-a/app"), "{listing}");
    assert!(!listing.contains("team-b"), "{listing}");
    let resp = client
        .get(format!("{url}/browse/team-b/app"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    // the manifest page too — it is the one that reveals a repo's layer digests
    let resp = client
        .get(format!("{url}/browse/team-b/app/manifests/v1"))
        .bearer_auth(&team_a_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "404, not 403: no existence oracle");

    // and a plain session sees everything, because *any* session reads everything — this
    // is the case that shows read-all is not gated on being an admin
    let listing = client
        .get(format!("{url}/browse"))
        .header("Cookie", format!("__Host-vk_session={plain_session}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        listing.contains("team-a/app") && listing.contains("team-b"),
        "{listing}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_keys_round_trips_create_and_revoke_with_csrf() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("keys");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let user = db.upsert_user("https://issuer", "u", None, None).unwrap();
    // this test mints a write-scoped key on purpose, which only an admin session may do
    assert!(db.set_admin(&user.id, true).unwrap());
    let user = db.get_user(&user.id).unwrap().unwrap();
    let session = db
        .create_session(&user.id, Duration::from_secs(3600))
        .unwrap();
    let csrf = db.session_csrf(&session).unwrap().unwrap();

    let url = spawn(state.clone());
    let client = no_redirect_client();
    let cookie = format!("__Host-vk_session={session}");

    // Wrong CSRF token: rejected.
    let resp = client
        .post(format!("{url}/settings/keys"))
        .header("Cookie", &cookie)
        .body("name=ci&repo_pattern=team-a/*&action=write&csrf=wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(db.list_api_keys(&user.id).unwrap().is_empty());

    // Correct CSRF token: the key is created.
    let resp = client
        .post(format!("{url}/settings/keys"))
        .header("Cookie", &cookie)
        .body(format!(
            "name=ci&repo_pattern=team-a/*&action=write&csrf={csrf}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let keys = db.list_api_keys(&user.id).unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].revoked_at.is_none());

    // An API key cannot manage keys, even authenticated.
    let (_, token) = db
        .create_api_key(Some(&user.id), "second", &[], None)
        .unwrap();
    let resp = client
        .get(format!("{url}/settings/keys"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Revoking someone else's key is refused — and answered the same way a key that does
    // not exist is, so a listing's ids tell a caller nothing about other people's keys.
    let other = db
        .upsert_user("https://issuer", "other", None, None)
        .unwrap();
    let other_session = db
        .create_session(&other.id, Duration::from_secs(3600))
        .unwrap();
    let other_csrf = db.session_csrf(&other_session).unwrap().unwrap();
    let id = &keys[0].id;
    let resp = client
        .post(format!("{url}/settings/keys/{id}/revoke"))
        .header("Cookie", format!("__Host-vk_session={other_session}"))
        .body(format!("csrf={other_csrf}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(
        db.get_api_key(&keys[0].id)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none(),
        "a stranger's revoke must not have taken effect"
    );

    // An id that exists for nobody is answered identically.
    let resp = client
        .post(format!("{url}/settings/keys/{}/revoke", "0".repeat(64)))
        .header("Cookie", &cookie)
        .body(format!("csrf={csrf}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // The owner can revoke it — answered 303 so a refresh re-fetches the listing rather
    // than re-submitting the form.
    let resp = client
        .post(format!("{url}/settings/keys/{id}/revoke"))
        .header("Cookie", &cookie)
        .body(format!("csrf={csrf}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/settings/keys")
    );
    assert!(db.get_api_key(id).unwrap().unwrap().revoked_at.is_some());

    // A POST with no CSRF field at all — the shape a cross-site form actually takes.
    let resp = client
        .post(format!("{url}/settings/keys"))
        .header("Cookie", &cookie)
        .body("name=forged&repo_pattern=team-a/*&action=write")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // A token minted for another session does not carry over to this one.
    let resp = client
        .post(format!("{url}/settings/keys"))
        .header("Cookie", &cookie)
        .body(format!(
            "name=forged&repo_pattern=team-a/*&action=write&csrf={other_csrf}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // An API key is refused on the state-changing routes too, not only the listing.
    let resp = client
        .post(format!("{url}/settings/keys"))
        .bearer_auth(&token)
        .body(format!(
            "name=byakey&repo_pattern=team-a/*&action=write&csrf={csrf}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // A GET never changes anything, whatever it carries.
    let before = db.list_api_keys(&user.id).unwrap().len();
    let resp = client
        .get(format!(
            "{url}/settings/keys?name=byget&repo_pattern=*&action=write&csrf={csrf}"
        ))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "a page listing credentials must not be cached"
    );
    assert_eq!(db.list_api_keys(&user.id).unwrap().len(), before);

    // The path that used to be sliced by offset arithmetic.
    let resp = client
        .post(format!("{url}/settings/keys/revoke"))
        .header("Cookie", &cookie)
        .body(format!("csrf={csrf}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // An expiry a form is free to send, which used to overflow into a panic.
    let resp = client
        .post(format!("{url}/settings/keys"))
        .header("Cookie", &cookie)
        .body(format!(
            "name=huge&repo_pattern=team-a/*&action=read&expires_days=18446744073709551615&csrf={csrf}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The self-escalation this closes: a plain session cannot write, so it must not be able
/// to mint itself a key that can.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_admin_session_cannot_mint_a_write_scoped_key() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("noadmin");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "plain", None, None)
        .unwrap();
    assert!(!user.is_admin);
    let session = db
        .create_session(&user.id, Duration::from_secs(3600))
        .unwrap();
    let csrf = db.session_csrf(&session).unwrap().unwrap();
    let url = spawn(state.clone());
    let client = no_redirect_client();
    let cookie = format!("__Host-vk_session={session}");

    let resp = client
        .post(format!("{url}/settings/keys"))
        .header("Cookie", &cookie)
        .body(format!(
            "name=escalate&repo_pattern=team-a/*&action=write&csrf={csrf}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(
        db.list_api_keys(&user.id).unwrap().is_empty(),
        "no key may have been created"
    );

    // a read-only key is still theirs to create
    let resp = client
        .post(format!("{url}/settings/keys"))
        .header("Cookie", &cookie)
        .body(format!(
            "name=ci-read&repo_pattern=team-a/*&action=read&csrf={csrf}"
        ))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(db.list_api_keys(&user.id).unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}
