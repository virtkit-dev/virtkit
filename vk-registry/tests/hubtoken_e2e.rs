//! Hub tokens over real HTTP: a registry taking them answers a token by its grants alone,
//! beside the mode's own credentials, in both modes, and confines its locks and failure
//! memos to them.

use std::sync::Arc;

use vk_hub_proto::token::{Claims, Grant};
use vk_peer::token::Signer;
use vk_registry::lock::LockManager;
use vk_registry::{ServerState, Store};

const AUD: &str = "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708";

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-token-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Each server on a thread and runtime of its own, as `relay_e2e` does.
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

fn grant(prefix: &str, rights: &str) -> Grant {
    Grant {
        prefix: prefix.into(),
        read: rights.contains('r'),
        write: rights.contains('w'),
        lock: rights.contains('l'),
    }
}

fn claims(aud: &str, ttl: u64, pipeline: Option<&str>) -> Claims {
    let now = vk_peer::now_secs();
    Claims {
        kid: String::new(),
        aud: aud.into(),
        sub: "job:j1".into(),
        jti: vk_peer::token::new_jti().unwrap(),
        pipeline: pipeline.map(str::to_string),
        iat: now - 1,
        exp: now + ttl,
        grants: vec![grant("p/gl/42", "rwl"), grant("images", "r")],
    }
}

/// A shared-secret registry with a bearer secret, taking tokens signed by a fresh key.
fn shared(dir: &std::path::Path) -> (Arc<ServerState>, Signer) {
    shared_with(
        dir,
        vk_registry::auth::Auth::Bearer {
            token: "s3cret".to_string(),
        },
        true,
    )
}

/// A shared-secret registry with `auth`, taking tokens signed by a fresh key when `tokens`.
fn shared_with(
    dir: &std::path::Path,
    auth: vk_registry::auth::Auth,
    tokens: bool,
) -> (Arc<ServerState>, Signer) {
    let signer = Signer::generate(&dir.join("token-key")).unwrap();
    let state = Arc::new(ServerState {
        store: Arc::new(Store::new(dir.join("store")).unwrap()),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::Authenticator::Shared(auth),
        tls: None,
        webdav: true,
        tokens: Default::default(),
    });
    if tokens {
        state.tokens.open(AUD, vec![signer.public().clone()]);
    }
    (state, signer)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_is_answered_by_its_grants_alone() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("grants");
    std::fs::create_dir_all(&dir).unwrap();
    let (state, signer) = shared(&dir);
    let url = spawn(state);
    let http = reqwest::Client::new();
    let token = signer.sign(claims(AUD, 600, Some("gl/7"))).unwrap();
    let get = |path: &str, token: &str| {
        http.get(format!("{url}{path}"))
            .bearer_auth(token.to_string())
            .send()
    };

    assert_eq!(get("/v2/", &token).await.unwrap().status(), 200);
    // Readable under its grants (an empty store: 404), forbidden elsewhere.
    assert_eq!(
        get("/v2/images/debian/manifests/v1", &token)
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        get("/v2/p/gl/42/app/manifests/v1", &token)
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        get("/v2/p/gl/43/app/manifests/v1", &token)
            .await
            .unwrap()
            .status(),
        403
    );
    let upload = |name: &str| {
        http.post(format!("{url}/v2/{name}/blobs/uploads/"))
            .bearer_auth(&token)
            .send()
    };
    assert_eq!(upload("p/gl/42/app").await.unwrap().status(), 202);
    assert_eq!(upload("images/debian").await.unwrap().status(), 403);
    // Also as the password of a Basic pair, as docker-style clients send it.
    let r = http
        .get(format!("{url}/v2/p/gl/43/app/manifests/v1"))
        .basic_auth("job", Some(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Expired, for another registry, signed by a key it does not know, or tampered with:
    // refused as any bad credential is, with the mode's challenge.
    let expired = {
        let mut c = claims(AUD, 1, None);
        c.iat = c.exp - 600;
        c.exp -= 400;
        signer.sign(c).unwrap()
    };
    let other_aud = signer
        .sign(claims("00000000000000000000000000000000", 600, None))
        .unwrap();
    let stranger = Signer::generate(&dir.join("other-key"))
        .unwrap()
        .sign(claims(AUD, 600, None))
        .unwrap();
    for bad in [expired, other_aud, stranger, format!("{token}x")] {
        let r = get("/v2/", &bad).await.unwrap();
        assert_eq!(r.status(), 401, "{bad}");
        assert!(r.headers().contains_key("www-authenticate"));
    }
    // The mode's own secret goes on working, unscoped.
    assert_eq!(
        get("/v2/p/gl/43/app/manifests/v1", "s3cret")
            .await
            .unwrap()
            .status(),
        404
    );

    // The batched probe answers only for a repository the grants let it read.
    let exists = |name: &str| {
        http.post(format!("{url}{}", vk_registry::EXISTS_PATH))
            .query(&[("name", name)])
            .bearer_auth(&token)
            .json(&serde_json::json!({ "tags": ["v1"] }))
            .send()
    };
    let r = exists("p/gl/42/app").await.unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["present"], serde_json::json!([false]));
    assert_eq!(exists("p/gl/43/app").await.unwrap().status(), 403);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Under `/dav/files/`, a token writes and reads only under its grants, and a listing shows
/// only what it may read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_reaches_only_its_grants_files() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("dav");
    std::fs::create_dir_all(&dir).unwrap();
    let (state, signer) = shared(&dir);
    let url = spawn(state);
    let http = reqwest::Client::new();
    let token = signer.sign(claims(AUD, 600, None)).unwrap();
    let put = |path: &str, auth: &str, body: &'static str| {
        http.put(format!("{url}/dav/files/{path}"))
            .bearer_auth(auth.to_string())
            .body(body)
            .send()
    };
    // Seeded with the mode's secret: one file the token may read, one it may not.
    assert!(
        put("images/notes.txt", "s3cret", "shared")
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert!(
        put("p/gl/43/secret.txt", "s3cret", "other project")
            .await
            .unwrap()
            .status()
            .is_success()
    );

    let r = put("p/gl/42/out.txt", &token, "mine").await.unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    let r = http
        .get(format!("{url}/dav/files/p/gl/42/out.txt"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "mine");
    assert_eq!(
        put("p/gl/43/out.txt", &token, "not mine")
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        put("images/out.txt", &token, "read only")
            .await
            .unwrap()
            .status(),
        403
    );
    let r = http
        .get(format!("{url}/dav/files/p/gl/43/secret.txt"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    let propfind = |path: &str| {
        http.request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{url}/dav/files/{path}"),
        )
        .bearer_auth(&token)
        .header("depth", "1")
        .send()
    };
    let r = propfind("").await.unwrap();
    assert_eq!(r.status(), 207);
    let listing = r.text().await.unwrap();
    assert!(listing.contains("/dav/files/images/"), "{listing}");
    assert!(!listing.contains("/dav/files/p/"), "{listing}");
    let r = propfind("p/gl/42/").await.unwrap();
    assert_eq!(r.status(), 207);
    assert!(r.text().await.unwrap().contains("out.txt"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// With tokens off, a `vkt_` credential is a credential the mode does not know: 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_tokens_off_a_token_is_an_unknown_bearer() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("off");
    std::fs::create_dir_all(&dir).unwrap();
    let (state, signer) = shared_with(
        &dir,
        vk_registry::auth::Auth::Bearer {
            token: "s3cret".to_string(),
        },
        false,
    );
    let url = spawn(state);
    let token = signer.sign(claims(AUD, 600, None)).unwrap();
    let r = reqwest::Client::new()
        .get(format!("{url}/v2/"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers().contains_key("www-authenticate"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Only a Basic password is taken for a token: as the user half, it is a wrong user, and the
/// Basic secret refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_as_a_basic_user_is_not_taken() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("basic");
    std::fs::create_dir_all(&dir).unwrap();
    let (state, signer) = shared_with(
        &dir,
        vk_registry::auth::Auth::Basic {
            user: "ci".to_string(),
            pass: "s3cret".to_string(),
        },
        true,
    );
    let url = spawn(state);
    let http = reqwest::Client::new();
    let token = signer.sign(claims(AUD, 600, None)).unwrap();
    let get = |user: &str, pass: &str| {
        http.get(format!("{url}/v2/p/gl/42/app/manifests/v1"))
            .basic_auth(user, Some(pass))
            .send()
    };
    let r = get(&token, "x").await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers().contains_key("www-authenticate"));
    assert_eq!(get("job", &token).await.unwrap().status(), 404);
    assert_eq!(get("ci", "s3cret").await.unwrap().status(), 404);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tokens_locks_and_memos_stay_within_its_grants_and_pipeline() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("locks");
    std::fs::create_dir_all(&dir).unwrap();
    let (state, signer) = shared(&dir);
    let url = spawn(state);
    let http = reqwest::Client::new();
    let token = signer.sign(claims(AUD, 600, Some("gl/7"))).unwrap();
    let post = |path: &str, auth: &str, pipeline: Option<&str>| {
        let mut r = http
            .post(format!("{url}{path}"))
            .bearer_auth(auth.to_string());
        if let Some(p) = pipeline {
            r = r.header("x-vk-lock-pipeline", p);
        }
        r.send()
    };

    let r = post(
        "/lock/acquire?name=p%2Fgl%2F42%3Ak&wait=0&ttl=100000",
        &token,
        None,
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body["ttl"].as_u64().unwrap() <= 600,
        "a lease never outlives the token: {body}"
    );
    let r = post("/lock/acquire?name=other%3Ak&wait=0", &token, None)
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = post(
        "/lock/acquire?name=p%2Fgl%2F42%3Aa&name=images%3Ab&wait=0",
        &token,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        r.status(),
        403,
        "one name outside its grants refuses the batch"
    );

    // A memo is recorded as the token's own pipeline, never another's.
    let r = post("/lock/fail?name=p%2Fgl%2F42%3Ak", &token, Some("gl/8"))
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = post("/lock/fail?name=p%2Fgl%2F42%3Ak", &token, None)
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let status = |pipeline: &'static str| async move {
        let r = post(
            "/lock/fail-status?name=p%2Fgl%2F42%3Ak",
            "s3cret",
            Some(pipeline),
        )
        .await
        .unwrap();
        r.json::<serde_json::Value>().await.unwrap()["failed"]
            .as_bool()
            .unwrap()
    };
    assert!(status("gl/7").await);
    assert!(!status("gl/8").await);
    // Another pipeline's record leaves this one's.
    let r = post("/lock/fail?name=p%2Fgl%2F42%3Ak", "s3cret", Some("gl/8"))
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(status("gl/7").await);

    // A token naming no pipeline takes locks but records no memo.
    let anonymous = signer.sign(claims(AUD, 600, None)).unwrap();
    let r = post("/lock/fail?name=p%2Fgl%2F42%3Ak", &anonymous, Some("gl/7"))
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // After `exp`, no lifetime remains for a lease. Reject with the mode's challenge
    // even within the clock skew accepted elsewhere.
    let lapsed = {
        let mut c = claims(AUD, 600, Some("gl/7"));
        c.exp = vk_peer::now_secs() - 5;
        c.iat = c.exp - 600;
        signer.sign(c).unwrap()
    };
    let r = post("/lock/acquire?name=p%2Fgl%2F42%3Az&wait=0", &lapsed, None)
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers().contains_key("www-authenticate"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accounts_mode_takes_a_token_and_keeps_it_off_the_pages() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("accounts");
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("oidc-secret");
    std::fs::write(&secret, "s3cr3t\n").unwrap();
    let mut cfg =
        vk_registry::ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    cfg.mode = vk_registry::config::AuthMode::Accounts;
    cfg.oidc = Some(vk_registry::config::OidcSpec {
        issuer: "https://login.example.com".to_string(),
        client_id: "vk-registry".to_string(),
        client_secret_file: secret,
        public_url: "https://registry.internal".to_string(),
    });
    let state = Arc::new(cfg.into_state().unwrap());
    let signer = Signer::generate(&dir.join("token-key")).unwrap();
    state.tokens.open(AUD, vec![signer.public().clone()]);
    let url = spawn(state);
    let http = reqwest::Client::new();
    let token = signer.sign(claims(AUD, 600, None)).unwrap();

    let r = http
        .get(format!("{url}/v2/p/gl/42/app/manifests/v1"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = http
        .get(format!("{url}/v2/p/gl/43/app/manifests/v1"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    for page in ["/browse", "/settings/keys", "/upload"] {
        let r = http
            .get(format!("{url}{page}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{page}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
