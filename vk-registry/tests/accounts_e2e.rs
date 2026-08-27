//! End-to-end accounts-mode test: a real server, real HTTP, seeded sessions/API keys
//! (bypassing the OIDC network round-trip, which `oidc.rs`'s own tests already cover
//! against a fake IdP) — proves the `Principal` → `authorize()` wiring actually gates
//! `/v2/*` and `/browse` over the wire, not just as isolated unit calls.

use std::sync::Arc;
use std::time::Duration;

use vk_registry::accounts::{Action, Db, Scope};
use vk_registry::admin;
use vk_registry::config::{AuthMode, OidcSpec, UpstreamSpec};
use vk_registry::lock::LockManager;
use vk_registry::{Authenticator, ServerConfig, ServerState, Store};

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
    accounts_state_relaying(dir, vec![])
}

/// [`accounts_state`] with relay upstreams, built the same way — through `UpstreamSpec`,
/// so the client behind each one is the one `serve` would have built.
fn accounts_state_relaying(
    dir: &std::path::Path,
    upstreams: Vec<UpstreamSpec>,
) -> Arc<ServerState> {
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
    cfg.upstreams = upstreams;
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

/// The cross-tenant read this scoping exists to close: a key scoped to one team must not
/// be able to fetch another team's layers by naming their digests through a repository it
/// *can* read, nor to smuggle them in by referencing them from a manifest of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scoped_key_cannot_read_another_teams_blobs_by_digest() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("scoped-blobs");
    let state = accounts_state(&dir);
    let store = state.store.clone();
    let db = accounts_db(&state);

    let admin = db
        .upsert_user("https://issuer", "admin", None, None)
        .unwrap();
    assert!(db.set_admin(&admin.id, true).unwrap());
    let admin_session = db
        .create_session(&admin.id, Duration::from_secs(3600))
        .unwrap();
    let user = db.upsert_user("https://issuer", "ci", None, None).unwrap();
    let team_a = Scope {
        action: Action::Write,
        repo_pattern: "team-a/*".to_string(),
    };
    let (_, key) = db
        .create_api_key(
            Some(&user.id),
            "team-a ci",
            std::slice::from_ref(&team_a),
            None,
        )
        .unwrap();

    // team-b's secret layer, pushed by the admin, referenced by a team-b manifest.
    let secret = b"team-b's private layer";
    let secret_digest = store.put_blob(secret).unwrap();
    // Seeded as a push would leave it: bytes in the pool *and* the membership the upload
    // would have recorded. `put_blob` alone records nothing, by design.
    store
        .record_blob("team-b/app", secret_digest.trim_start_matches("sha256:"))
        .unwrap();
    let team_b_manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"digest":"{secret_digest}","size":{}}},"layers":[]}}"#,
        secret.len()
    );
    let team_b_mdigest = store
        .put_manifest(
            "team-b/app",
            "v1",
            "application/vnd.oci.image.manifest.v1+json",
            team_b_manifest.as_bytes(),
        )
        .unwrap();
    // and team-a has a repository of its own, so its key has somewhere legitimate to look
    let own = store.put_blob(b"team-a's own layer").unwrap();
    store
        .record_blob("team-a/app", own.trim_start_matches("sha256:"))
        .unwrap();
    let own_manifest =
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{own}","size":18}},"layers":[]}}"#);
    store
        .put_manifest(
            "team-a/app",
            "v1",
            "application/vnd.oci.image.manifest.v1+json",
            own_manifest.as_bytes(),
        )
        .unwrap();

    let url = spawn(state.clone());
    let client = no_redirect_client();

    // Its own repository's blob: readable, as before.
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{own}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // team-b's blob, named through the repo it *can* read: refused as absent, because it
    // is not a member of team-a/app and the key may not read any repo that holds it.
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{secret_digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a digest is not a key to the whole store"
    );
    // the dedup probe answers the same way, so HEAD and GET cannot disagree
    let resp = client
        .head(format!("{url}/v2/team-a/app/blobs/{secret_digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // team-b's *manifest* by digest is refused too — that is where the layer digests
    // would have come from.
    let resp = client
        .get(format!("{url}/v2/team-a/app/manifests/{team_b_mdigest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // And it cannot smuggle the blob in by referencing it from a manifest of its own:
    // the push is refused, and the blob does not become readable.
    let smuggle = format!(
        r#"{{"schemaVersion":2,"config":{{"digest":"{secret_digest}","size":{}}},"layers":[]}}"#,
        secret.len()
    );
    let resp = client
        .put(format!("{url}/v2/team-a/app/manifests/smuggled"))
        .bearer_auth(&key)
        .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
        .body(smuggle)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("MANIFEST_BLOB_UNKNOWN"), "{body}");
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{secret_digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "the refused push granted nothing");

    // An admin session reads every repo, so scoping costs it nothing — the blob is
    // reachable through the repo that holds it and through one it may read.
    for path in [
        format!("/v2/team-b/app/blobs/{secret_digest}"),
        format!("/v2/team-a/app/blobs/{secret_digest}"),
    ] {
        let resp = client
            .get(format!("{url}{path}"))
            .header("Cookie", format!("__Host-vk_session={admin_session}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{path}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Dedup across a key's own repositories must keep working: a blob it can already read
/// in one is mountable into another by naming it, with no re-upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dedup_still_works_within_a_keys_own_scope() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("scoped-dedup");
    let state = accounts_state(&dir);
    let store = state.store.clone();
    let db = accounts_db(&state);
    let user = db.upsert_user("https://issuer", "ci", None, None).unwrap();
    let scope = Scope {
        action: Action::Write,
        repo_pattern: "team-a/*".to_string(),
    };
    let (_, key) = db
        .create_api_key(Some(&user.id), "ci", std::slice::from_ref(&scope), None)
        .unwrap();

    let shared = b"a layer both images share";
    let digest = store.put_blob(shared).unwrap();
    // a member of the first repo, as its own push would have left it
    store
        .record_blob("team-a/first", digest.trim_start_matches("sha256:"))
        .unwrap();
    let manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"digest":"{digest}","size":{}}},"layers":[]}}"#,
        shared.len()
    );
    // it is already a member of one repo in the key's scope
    store
        .put_manifest(
            "team-a/first",
            "v1",
            "application/vnd.oci.image.manifest.v1+json",
            manifest.as_bytes(),
        )
        .unwrap();

    let url = spawn(state.clone());
    let client = no_redirect_client();

    // The dedup probe against the *other* repo says "already here" — the key may read
    // the repo that holds it, so there is nothing to re-upload.
    let resp = client
        .head(format!("{url}/v2/team-a/second/blobs/{digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "cross-repo dedup within scope");

    // So the manifest push into the second repo succeeds without the layer being sent
    // again, and the blob is then a member of both.
    let resp = client
        .put(format!("{url}/v2/team-a/second/manifests/v1"))
        .bearer_auth(&key)
        .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
        .body(manifest)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let hex = digest.trim_start_matches("sha256:");
    assert!(store.repo_has_blob("team-a/first", hex));
    assert!(store.repo_has_blob("team-a/second", hex));
    // one copy on disk, as always
    assert_eq!(store.stats().unwrap().identity_blobs, 2, "layer + manifest");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The plain push path, over HTTP, end to end: a blob uploaded through an upload session
/// is readable through the repository it was pushed to, and a manifest naming it is
/// accepted. Seeding the store directly, as the tests above do, would not catch a
/// membership record the *upload* path forgot to write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_blob_is_readable_through_the_repo_it_was_pushed_to() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("pushed");
    let state = accounts_state(&dir);
    let store = state.store.clone();
    let db = accounts_db(&state);
    let user = db.upsert_user("https://issuer", "ci", None, None).unwrap();
    let scope = Scope {
        action: Action::Write,
        repo_pattern: "team-a/*".to_string(),
    };
    let (_, key) = db
        .create_api_key(Some(&user.id), "ci", std::slice::from_ref(&scope), None)
        .unwrap();
    let url = spawn(state.clone());
    let client = no_redirect_client();

    let layer = b"a genuinely uploaded layer";
    let hex = <sha2::Sha256 as sha2::Digest>::digest(layer)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let digest = format!("sha256:{hex}");

    // Nothing holds it yet, so it is not readable anywhere.
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // POST a session, PUT the bytes.
    let resp = client
        .post(format!("{url}/v2/team-a/app/blobs/uploads/"))
        .bearer_auth(&key)
        .header("Content-Length", "0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let resp = client
        .put(format!(
            "{url}{location}?digest={}",
            digest.replace(':', "%3A")
        ))
        .bearer_auth(&key)
        .body(layer.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Now it is readable through that repository, and the bytes come back intact.
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "an uploaded blob must be readable");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), layer);
    assert!(store.repo_has_blob("team-a/app", &hex));

    // ... and a manifest naming it is accepted, since it is already a member.
    let manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"digest":"{digest}","size":{}}},"layers":[]}}"#,
        layer.len()
    );
    let resp = client
        .put(format!("{url}/v2/team-a/app/manifests/v1"))
        .bearer_auth(&key)
        .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
        .body(manifest)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // The pull path a client actually takes: tag -> manifest -> blob.
    let resp = client
        .get(format!("{url}/v2/team-a/app/manifests/v1"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fetched["config"]["digest"], digest);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `/browse` renders a manifest's layer digests, so it has to apply the same gate `/v2/`
/// does — otherwise the enumeration this scoping exists to stop is available one URL over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browse_cannot_show_another_teams_manifest_by_digest() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("browse-scoped");
    let state = accounts_state(&dir);
    let store = state.store.clone();
    let db = accounts_db(&state);
    let user = db.upsert_user("https://issuer", "ci", None, None).unwrap();
    let scope = Scope {
        action: Action::Read,
        repo_pattern: "team-a/*".to_string(),
    };
    let (_, key) = db
        .create_api_key(Some(&user.id), "team-a", std::slice::from_ref(&scope), None)
        .unwrap();

    // team-b's manifest, naming a layer only team-b holds.
    let secret = store.put_blob(b"team-b layer").unwrap();
    store
        .record_blob("team-b/app", secret.trim_start_matches("sha256:"))
        .unwrap();
    let team_b =
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{secret}","size":12}},"layers":[]}}"#);
    let team_b_digest = store
        .put_manifest(
            "team-b/app",
            "v1",
            "application/vnd.oci.image.manifest.v1+json",
            team_b.as_bytes(),
        )
        .unwrap();
    // and team-a has one of its own, so the page works at all
    let own = store.put_blob(b"team-a layer").unwrap();
    store
        .record_blob("team-a/app", own.trim_start_matches("sha256:"))
        .unwrap();
    let team_a =
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{own}","size":12}},"layers":[]}}"#);
    let team_a_digest = store
        .put_manifest(
            "team-a/app",
            "v1",
            "application/vnd.oci.image.manifest.v1+json",
            team_a.as_bytes(),
        )
        .unwrap();

    let url = spawn(state.clone());
    let client = no_redirect_client();

    // its own manifest by digest renders
    let resp = client
        .get(format!("{url}/browse/team-a/app/manifests/{team_a_digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // team-b's, named through the repo it may read, does not — and the layer digest is
    // nowhere in the response.
    let resp = client
        .get(format!("{url}/browse/team-a/app/manifests/{team_b_digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains(secret.trim_start_matches("sha256:")),
        "the page must not disclose another repo's layer digest"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A manifest only proves its author *named* a digest, never that they hold it. Storing
/// one must therefore grant nothing — otherwise anything that writes a manifest on a
/// caller's behalf (the relay's manifest cache) becomes a way to read local content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storing_a_manifest_grants_nothing_it_merely_references() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("manifest-grants");
    let store = Store::new(dir.join("store")).unwrap();

    // A private layer belonging to one repo.
    let secret = store.put_blob(b"someone else's bytes").unwrap();
    let hex = secret.trim_start_matches("sha256:").to_string();
    store.record_blob("team-b/app", &hex).unwrap();

    // A manifest stored into a different repo that merely names it — as the relay would
    // cache one it fetched upstream.
    let naming =
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{secret}","size":20}},"layers":[]}}"#);
    store
        .put_manifest(
            "team-a/app",
            "cached",
            "application/vnd.oci.image.manifest.v1+json",
            naming.as_bytes(),
        )
        .unwrap();

    assert!(
        !store.repo_has_blob("team-a/app", &hex),
        "naming a digest must not make it a member"
    );
    assert!(store.repo_has_blob("team-b/app", &hex));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A relayed blob is content this registry fetched and hashed *for* the repository the
/// caller named, so it becomes readable through it — otherwise the very cache that just
/// filled would refuse the next request for it. Every other relay test runs in
/// shared-secret mode, where `readable_through` short-circuits and none of this is
/// exercised.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_blob_becomes_a_member_of_the_repo_it_was_fetched_for() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Upstream: an ordinary shared-secret registry holding team-a's layer.
    let up_dir = tmp("relay-up");
    let up_store = Store::new(up_dir.join("store")).unwrap();
    let layer = b"upstream layer bytes".to_vec();
    let digest = up_store.put_blob(&layer).unwrap();
    up_store
        .record_blob("team-a/app", digest.trim_start_matches("sha256:"))
        .unwrap();
    let up_url = spawn(Arc::new(ServerState {
        store: Arc::new(up_store),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: Authenticator::Shared(vk_registry::auth::Auth::None),
        tls: None,
    }));

    // Mirror: accounts mode, empty store, everything routed upstream.
    let dir = tmp("relay-mirror");
    let state = accounts_state_relaying(
        &dir,
        vec![UpstreamSpec {
            prefix: String::new(),
            url: up_url.clone(),
            username: None,
            password_file: None,
            ca_file: None,
        }],
    );
    let store = state.store.clone();
    let db = accounts_db(&state);
    let user = db.upsert_user("https://issuer", "ci", None, None).unwrap();
    let (_, key) = db
        .create_api_key(
            Some(&user.id),
            "team-a ci",
            &[Scope {
                action: Action::Read,
                repo_pattern: "team-a/*".to_string(),
            }],
            None,
        )
        .unwrap();
    let url = spawn(state.clone());
    let client = no_redirect_client();
    let hex = digest.trim_start_matches("sha256:").to_string();

    // Nothing local yet, so this is served by the relay — and recorded on the way through.
    assert!(!store.repo_has_blob("team-a/app", &hex));
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), layer.as_slice());
    assert!(
        store.repo_has_blob("team-a/app", &hex),
        "the relay must record what it fetched, or the cache refuses its own content"
    );
    // Recorded in the repository the fetch was authorized for, not in the store at large:
    // a sibling the key may also read is not made a member by someone else's fetch.
    assert!(!store.repo_has_blob("team-a/other", &hex));

    // The second request is served locally, by membership, with the relay unused.
    let resp = client
        .get(format!("{url}/v2/team-a/app/blobs/{digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), layer.as_slice());

    // A key with no read on the repository is refused before the relay is consulted, so
    // fronting an upstream never widens what a scope reaches.
    let resp = client
        .get(format!("{url}/v2/team-b/app/blobs/{digest}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(
        !store.repo_has_blob("team-b/app", &hex),
        "a refused request must not cache, nor record"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&up_dir);
}

/// A registry on the older shared-secret setting is unchanged by any of this: one token is
/// the whole authorization model, so a blob is readable by digest through any repository
/// and a manifest may name content the store does not hold. The membership machinery must
/// stay invisible there — and must not quietly pre-seed itself, which would hand a later
/// switch to accounts mode the reference-derived graph the write rule refuses to build.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_secret_mode_is_unchanged_by_repo_scoping() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("shared-secret");
    let store = Arc::new(Store::new(dir.join("store")).unwrap());
    // In the pool, recorded nowhere — exactly what a pre-existing store looks like.
    let layer = b"a layer nobody recorded".to_vec();
    let digest = store.put_blob(&layer).unwrap();
    let hex = digest.trim_start_matches("sha256:").to_string();

    let url = spawn(Arc::new(ServerState {
        store: store.clone(),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: Authenticator::Shared(vk_registry::auth::Auth::None),
        tls: None,
    }));
    let client = no_redirect_client();

    // Readable by digest through a repository that holds nothing at all.
    let resp = client
        .get(format!("{url}/v2/any/repo/blobs/{digest}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), layer.as_slice());

    // A manifest naming a digest the store does not hold is still accepted here.
    let absent = format!("sha256:{}", "b".repeat(64));
    let manifest =
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{absent}","size":1}},"layers":[]}}"#);
    let resp = client
        .put(format!("{url}/v2/any/repo/manifests/v1"))
        .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
        .body(manifest.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // And storing it recorded nothing it merely referenced — not even the digest that is
    // in the pool, had the manifest named it.
    let referencing = format!(
        r#"{{"schemaVersion":2,"config":{{"digest":"{digest}","size":{}}},"layers":[]}}"#,
        layer.len()
    );
    let resp = client
        .put(format!("{url}/v2/any/repo/manifests/v2"))
        .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
        .body(referencing)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert!(
        !store.repo_has_blob("any/repo", &hex),
        "a reference is not evidence in shared-secret mode either"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The admin socket of a server built by [`accounts_state`], serving the very db that
/// server holds — the wiring `serve_config` does, done here so the test can also drive the
/// HTTP surface on an ephemeral port.
fn spawn_admin_socket(state: &Arc<ServerState>, dir: &std::path::Path) -> std::path::PathBuf {
    let db = match &state.auth {
        Authenticator::Accounts { db, .. } => db.clone(),
        _ => panic!("not accounts mode"),
    };
    let socket = vk_registry::config::default_admin_socket(
        &vk_registry::config::default_accounts_db(&dir.join("store")),
    );
    let listener = admin::bind(&socket).unwrap();
    tokio::spawn(admin::serve_admin(listener, db));
    socket
}

/// The point of the socket: an operator changes accounts while the registry serves, and
/// the very next request is decided by the change. Nothing here stops or restarts the
/// server, and nothing here opens the accounts db — that file is the server's for as long
/// as it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_socket_changes_decide_the_next_request() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("adminsock");
    let state = accounts_state(&dir);
    let seeded = accounts_db(&state)
        .upsert_user("https://issuer", "u", Some("u@example.com"), None)
        .unwrap();
    let session = accounts_db(&state)
        .create_session(&seeded.id, Duration::from_secs(3600))
        .unwrap();
    let socket = spawn_admin_socket(&state, &dir);
    let url = spawn(state.clone());
    let http = no_redirect_client();
    let manifest = r#"{"schemaVersion":2,"config":{"digest":"sha256:00","size":0},"layers":[]}"#;

    // A second process cannot open the db: without the socket, this is where an operator
    // would have had to stop the server.
    assert!(
        Db::open(&vk_registry::config::default_accounts_db(
            &dir.join("store")
        ))
        .is_err(),
        "the running server must still hold the db, or this test proves nothing"
    );
    let ops = admin::Client::connect(&socket).expect("the running server answers");

    // What the CLI reads is what the server has.
    let users = ops.list_users().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email.as_deref(), Some("u@example.com"));
    assert!(!users[0].is_admin);

    // A key minted through the socket authenticates on the next request, with the scope it
    // was given and no other.
    let (key, token) = ops
        .create_api_key(
            None,
            "ci",
            &[Scope {
                action: Action::Write,
                repo_pattern: "team-a/*".to_string(),
            }],
            None,
        )
        .unwrap();
    let push = |repo: &str, token: String| {
        let http = http.clone();
        let url = url.clone();
        let repo = repo.to_string();
        async move {
            http.put(format!("{url}/v2/{repo}/manifests/v1"))
                .bearer_auth(token)
                .body(manifest)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(push("team-a/app", token.clone()).await, 201);
    assert_eq!(push("team-b/app", token.clone()).await, 403);

    // And revoking it stops the next one — the case that used to cost an outage, because
    // an ownerless key has no owner-side page to revoke it from.
    assert!(ops.revoke_api_key_unchecked(&key.id).unwrap());
    assert_eq!(push("team-a/other", token.clone()).await, 401);

    // A grant lands the same way: this session could not write a moment ago.
    assert_eq!(
        http.put(format!("{url}/v2/team-c/app/manifests/v1"))
            .header("Cookie", format!("__Host-vk_session={session}"))
            .body(manifest)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert!(ops.set_admin(&users[0].id, true).unwrap());
    assert_eq!(
        http.put(format!("{url}/v2/team-c/app/manifests/v1"))
            .header("Cookie", format!("__Host-vk_session={session}"))
            .body(manifest)
            .send()
            .await
            .unwrap()
            .status(),
        201
    );

    // And a session ended over the socket stops being one, on the request after.
    assert_eq!(ops.delete_sessions_for_user(&users[0].id).unwrap(), 1);
    assert_eq!(
        http.get(format!("{url}/v2/team-c/app/manifests/v1"))
            .header("Cookie", format!("__Host-vk_session={session}"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "the cookie was admin's a moment ago; now it is nobody's"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The admin operations are not on the HTTP surface, and adding one must not put them
/// there: nothing off the machine may grant admin or mint a key, which is the whole reason
/// the channel is a unix socket in an owner-only directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_admin_operations_are_not_reachable_over_http() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("nohttp");
    let state = accounts_state(&dir);
    let admin_user = accounts_db(&state)
        .upsert_user("https://issuer", "admin", None, None)
        .unwrap();
    assert!(accounts_db(&state).set_admin(&admin_user.id, true).unwrap());
    let session = accounts_db(&state)
        .create_session(&admin_user.id, Duration::from_secs(3600))
        .unwrap();
    let url = spawn(state.clone());
    let http = no_redirect_client();

    // Even an admin session: there is no route, so this is a 404 and not a 403.
    for path in ["/admin", "/admin/v1", "/admin/v1/set-admin"] {
        let resp = http
            .post(format!("{url}{path}"))
            .header("Cookie", format!("__Host-vk_session={session}"))
            .body(r#"{"v":1,"call":{"op":"list-users"}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "POST {path}");
        let resp = http
            .get(format!("{url}{path}"))
            .header("Cookie", format!("__Host-vk_session={session}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "GET {path}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `serve` itself binds the socket the CLI dials, at the path the CLI resolves — the two
/// halves of `ServerConfig::admin_socket_of` agreeing in a running server rather than only
/// in a unit test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_binds_the_admin_socket_the_cli_resolves() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("servecfg");
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("oidc-secret");
    std::fs::write(&secret, "s3cr3t\n").unwrap();
    let root = dir.join("store");
    let mut cfg = ServerConfig::local("127.0.0.1:0".parse().unwrap(), root.clone());
    cfg.mode = AuthMode::Accounts;
    cfg.oidc = Some(OidcSpec {
        issuer: "https://login.example.com".to_string(),
        client_id: "vk-registry".to_string(),
        client_secret_file: secret,
        public_url: "https://registry.internal".to_string(),
    });
    tokio::spawn(async move {
        let _ = vk_registry::serve_config(cfg).await;
    });

    // What the CLI would dial: the db the store selector resolves to, then the socket
    // beside it — the same two steps `open_accounts_ops` takes.
    let db_path = ServerConfig::accounts_db_of(None, Some(root), None).unwrap();
    let socket = ServerConfig::admin_socket_of(None, &db_path, None)
        .unwrap()
        .expect("accounts mode binds one by default");
    // Bounded: `serve_config`'s error is discarded above, and cargo has no per-test
    // timeout, so an unbounded wait on a bind that never happens is a hung suite with
    // nothing to read.
    let mut client = None;
    for _ in 0..250 {
        match admin::Client::connect(&socket) {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let client = client.unwrap_or_else(|| panic!("nothing listening at {}", socket.display()));
    assert!(
        client.list_users().unwrap().is_empty(),
        "a fresh registry has no users, and saying so is not the same as failing"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
