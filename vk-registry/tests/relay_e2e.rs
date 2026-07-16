//! End-to-end relay test: stand up one server as the "upstream" and a second as a
//! "mirror" pointing at it, then pull through the mirror over real HTTP. Proves that a
//! digest-addressed pull caches into the mirror while a tag pull is relayed but not
//! persisted. No external network — the server is its own upstream.

use std::sync::Arc;

use vk_registry::lock::LockManager;
use vk_registry::relay::Upstream;
use vk_registry::{ServerState, Store};

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

// Run each test server on its own dedicated thread + runtime, so its accept loop never
// competes with the test's runtime threads (which caused acceptance stalls when several
// of these tests ran concurrently).
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

const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_caches_digest_not_tag() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Upstream: a blob plus a manifest that references it, tagged `latest`.
    let up_dir = tmp("up");
    let up_store = Store::new(up_dir.clone()).unwrap();
    let blob = vec![42u8; 20_000];
    let bdigest = up_store.put_blob(&blob).unwrap();
    let manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{bdigest}","size":{}}},"layers":[]}}"#,
        blob.len()
    );
    let mdigest = up_store
        .put_manifest("app", "latest", MANIFEST_TYPE, manifest.as_bytes())
        .unwrap();
    let up_state = Arc::new(ServerState {
        store: Arc::new(up_store),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::None,
        tls: None,
    });
    let up_url = spawn(up_state);

    // Mirror: empty store, all repos routed to the upstream.
    let mirror_dir = tmp("mirror");
    let mirror_store = Arc::new(Store::new(mirror_dir.clone()).unwrap());
    let mirror_state = Arc::new(ServerState {
        store: mirror_store.clone(),
        upstreams: vec![Upstream {
            prefix: String::new(),
            base: up_url.clone(),
            username: None,
            password: None,
            client: reqwest::Client::new(),
        }],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::None,
        tls: None,
    });
    let mirror_url = spawn(mirror_state);
    let http = reqwest::Client::new();

    // 1) blob by digest through the mirror → 200, exact bytes, and now cached.
    let r = http
        .get(format!("{mirror_url}/v2/app/blobs/{bdigest}"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "blob relay status: {}", r.status());
    assert_eq!(r.bytes().await.unwrap().as_ref(), &blob[..]);
    let bhex = bdigest.trim_start_matches("sha256:");
    assert!(
        mirror_store.get_blob(bhex).unwrap().is_some(),
        "a digest blob pull must be cached in the mirror"
    );

    // 2) manifest by digest through the mirror → cached (no tag created).
    let r = http
        .get(format!("{mirror_url}/v2/app/manifests/{mdigest}"))
        .header(reqwest::header::ACCEPT, MANIFEST_TYPE)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(
        mirror_store
            .get_manifest("app", &mdigest)
            .unwrap()
            .is_some(),
        "a digest manifest pull must be cached"
    );

    // 3) manifest by TAG through the mirror → served live but NOT persisted.
    let r = http
        .get(format!("{mirror_url}/v2/app/manifests/latest"))
        .header(reqwest::header::ACCEPT, MANIFEST_TYPE)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(
        r.bytes().await.unwrap().as_ref(),
        manifest.as_bytes(),
        "the relayed tag body must match upstream"
    );
    assert!(
        mirror_store
            .get_manifest("app", "latest")
            .unwrap()
            .is_none(),
        "a relayed tag must never be cached in the mirror"
    );

    let _ = std::fs::remove_dir_all(&up_dir);
    let _ = std::fs::remove_dir_all(&mirror_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_lock_is_atomic_all_or_nothing() {
    use std::time::Duration;
    use vk_registry::LockClient;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("multilock");
    let state = Arc::new(ServerState {
        store: Arc::new(Store::new(dir.clone()).unwrap()),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::None,
        tls: None,
    });
    let url = spawn(state);
    let c = LockClient::new(url, None, reqwest::Client::new());
    let ttl = Duration::from_secs(30);
    let zero = Duration::from_secs(0);
    let ab = vec!["img/a".to_string(), "img/b".to_string()];
    let bc = vec!["img/b".to_string(), "img/c".to_string()];

    // acquire {a,b} as one batch.
    let owner = c
        .acquire_all(&ab, ttl, zero, "pipeline-1")
        .await
        .unwrap()
        .expect("batch {a,b} acquired");

    // {b,c} overlaps on b ⇒ all-or-nothing: the whole batch is refused, c stays free.
    assert!(
        c.acquire_all(&bc, ttl, zero, "pipeline-2")
            .await
            .unwrap()
            .is_none(),
        "an overlapping batch must be refused atomically"
    );
    // c was not taken by the failed batch: a solo acquire of c succeeds.
    let c_owner = c
        .acquire_all(&["img/c".to_string()], ttl, zero, "pipeline-3")
        .await
        .unwrap()
        .expect("c must remain free after the failed overlapping batch");

    // renew + release the whole {a,b} batch by its owner.
    assert_eq!(c.renew_all(&ab, &owner, ttl).await.unwrap(), 2);
    assert_eq!(c.release_all(&ab, &owner).await.unwrap(), 2);
    // now {a,b} is free; {b,c} still blocked by c until we free it.
    assert!(
        c.acquire_all(&bc, ttl, zero, "pipeline-4")
            .await
            .unwrap()
            .is_none(),
        "b is free but c is still held"
    );
    assert_eq!(
        c.release_all(&["img/c".to_string()], &c_owner)
            .await
            .unwrap(),
        1
    );
    assert!(
        c.acquire_all(&bc, ttl, zero, "pipeline-5")
            .await
            .unwrap()
            .is_some(),
        "with a, b, c all free the batch acquires"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_client_round_trips_against_the_server() {
    use std::time::Duration;
    use vk_registry::LockClient;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("client");
    let state = Arc::new(ServerState {
        store: Arc::new(Store::new(dir.clone()).unwrap()),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::None,
        tls: None,
    });
    let url = spawn(state);
    let c = LockClient::new(url, None, reqwest::Client::new());

    let held = c
        .acquire(
            "build/x",
            Duration::from_secs(30),
            Duration::from_secs(0),
            "runner-1",
        )
        .await
        .unwrap()
        .expect("first acquire wins");
    // held ⇒ a wait=0 acquire returns None (409), the owner can renew, then release.
    assert!(
        c.acquire(
            "build/x",
            Duration::from_secs(30),
            Duration::from_secs(0),
            "runner-2"
        )
        .await
        .unwrap()
        .is_none(),
        "a held lock must refuse a second acquirer"
    );
    assert!(c.renew(&held, Duration::from_secs(30)).await.unwrap());
    c.release(&held).await.unwrap();
    // after release, acquire succeeds again.
    let again = c
        .acquire(
            "build/x",
            Duration::from_secs(30),
            Duration::from_secs(0),
            "runner-2",
        )
        .await
        .unwrap();
    assert!(again.is_some(), "released lock must be re-acquirable");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bearer_auth_gates_everything_but_the_probe() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("auth");
    let state = Arc::new(ServerState {
        store: Arc::new(Store::new(dir.clone()).unwrap()),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::Bearer {
            token: "s3cret".to_string(),
        },
        tls: None,
    });
    let url = spawn(state);
    let http = reqwest::Client::new();

    // the /v2/ version probe is open (capability detection).
    let r = http.get(format!("{url}/v2/")).send().await.unwrap();
    assert!(
        r.status().is_success(),
        "probe should be open, got {}",
        r.status()
    );

    // a protected route without credentials → 401 + WWW-Authenticate.
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert!(r.headers().contains_key("www-authenticate"));

    // wrong token → still 401; correct token → authorized (404, empty store).
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // the lock API is protected too.
    let r = http
        .post(format!("{url}/lock/acquire?name=k&wait=0"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // a blob upload (write path) without credentials is refused too.
    let r = http
        .post(format!("{url}/v2/app/blobs/uploads/"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_auth_gates_and_challenges() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("basicauth");
    let state = Arc::new(ServerState {
        store: Arc::new(Store::new(dir.clone()).unwrap()),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::Basic {
            user: "u".to_string(),
            pass: "p".to_string(),
        },
        tls: None,
    });
    let url = spawn(state);
    let http = reqwest::Client::new();

    // the /v2/ version probe is open.
    assert!(
        http.get(format!("{url}/v2/"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );

    // no credentials → 401 with a Basic challenge.
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert!(
        r.headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .starts_with("Basic"),
        "a Basic scheme must issue a Basic challenge"
    );

    // wrong password and wrong user → 401.
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .basic_auth("u", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .basic_auth("nope", Some("p"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // malformed base64 in the Basic header → 401, not a panic/bypass.
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .header("authorization", "Basic !!!not-base64!!!")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // correct credentials → authorized (404 against the empty store).
    let r = http
        .get(format!("{url}/v2/app/manifests/latest"))
        .basic_auth("u", Some("p"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_does_not_leak_upstream_credentials_to_the_client() {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use sha2::{Digest, Sha256};

    let _ = rustls::crypto::ring::default_provider().install_default();

    let blob = vec![7u8; 12_000];
    let hex: String = Sha256::digest(&blob)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let bdigest = format!("sha256:{hex}");

    // A mock upstream that requires the Docker bearer-token dance: an unauthenticated blob
    // request is challenged; the token endpoint hands out a token only to a Basic-authed
    // caller; the authed blob response also carries a Set-Cookie + WWW-Authenticate that the
    // relay must NOT forward downstream.
    let up_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    up_listener.set_nonblocking(true).unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    let up_url = format!("http://{up_addr}");
    let realm = format!("{up_url}/token");
    let blob_path = format!("/v2/app/blobs/{bdigest}");
    {
        let (blob, bdigest, realm, blob_path) = (
            blob.clone(),
            bdigest.clone(),
            realm.clone(),
            blob_path.clone(),
        );
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let l = tokio::net::TcpListener::from_std(up_listener).unwrap();
                loop {
                    let Ok((stream, _)) = l.accept().await else {
                        continue;
                    };
                    let (blob, bdigest, realm, blob_path) = (
                        blob.clone(),
                        bdigest.clone(),
                        realm.clone(),
                        blob_path.clone(),
                    );
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let (blob, bdigest, realm, blob_path) = (
                                blob.clone(),
                                bdigest.clone(),
                                realm.clone(),
                                blob_path.clone(),
                            );
                            async move {
                                let auth = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_string);
                                let path = req.uri().path().to_string();
                                let resp: Response<Full<Bytes>> = if path == "/token" {
                                    // hand out a token only when the relay presents Basic creds.
                                    if auth.as_deref().is_some_and(|a| a.starts_with("Basic ")) {
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from(r#"{"token":"good"}"#)))
                                            .unwrap()
                                    } else {
                                        Response::builder()
                                            .status(StatusCode::UNAUTHORIZED)
                                            .body(Full::new(Bytes::new()))
                                            .unwrap()
                                    }
                                } else if path == blob_path {
                                    if auth.as_deref() == Some("Bearer good") {
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header("Docker-Content-Digest", &bdigest)
                                            .header("content-type", "application/octet-stream")
                                            .header("content-length", blob.len().to_string())
                                            .header("set-cookie", "up-secret=leak; Path=/")
                                            .header(
                                                "www-authenticate",
                                                format!("Bearer realm=\"{realm}\""),
                                            )
                                            .body(Full::new(Bytes::from(blob.clone())))
                                            .unwrap()
                                    } else {
                                        Response::builder()
                                            .status(StatusCode::UNAUTHORIZED)
                                            .header(
                                                "www-authenticate",
                                                format!("Bearer realm=\"{realm}\",service=\"reg\""),
                                            )
                                            .body(Full::new(Bytes::new()))
                                            .unwrap()
                                    }
                                } else {
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                };
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
        });
    }

    // Mirror configured with the upstream credentials; its own clients are unauthenticated.
    let mirror_dir = tmp("leak-mirror");
    let mirror_store = Arc::new(Store::new(mirror_dir.clone()).unwrap());
    let mirror_state = Arc::new(ServerState {
        store: mirror_store.clone(),
        upstreams: vec![Upstream {
            prefix: String::new(),
            base: up_url.clone(),
            username: Some("robot".to_string()),
            password: Some("s3cret".to_string()),
            client: reqwest::Client::new(),
        }],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::None,
        tls: None,
    });
    let mirror_url = spawn(mirror_state);
    let http = reqwest::Client::new();

    // Pull the blob by digest through the mirror (no downstream creds).
    let r = http
        .get(format!("{mirror_url}/v2/app/blobs/{bdigest}"))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "the credentialed relay must serve the blob, got {}",
        r.status()
    );
    // No upstream secret must reach the client: not the token, cookie, or challenge.
    for h in ["set-cookie", "www-authenticate", "authorization"] {
        assert!(
            !r.headers().contains_key(h),
            "upstream header {h:?} must not be forwarded to the client"
        );
    }
    assert_eq!(
        r.bytes().await.unwrap().as_ref(),
        &blob[..],
        "the relayed body must be the exact upstream blob"
    );

    let _ = std::fs::remove_dir_all(&mirror_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_api_build_once_over_http() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("lock");
    let state = Arc::new(ServerState {
        store: Arc::new(Store::new(dir.clone()).unwrap()),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::auth::Auth::None,
        tls: None,
    });
    let url = spawn(state);
    let http = reqwest::Client::new();

    // acquire → returns the opaque owner token.
    let r = http
        .post(format!("{url}/lock/acquire?name=build-key"))
        .header("x-vk-lock-holder", "runner-1")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let body: serde_json::Value = r.json().await.unwrap();
    let owner = body["owner"].as_str().unwrap().to_string();

    // a second acquirer with a short wait is refused (409).
    let r = http
        .post(format!("{url}/lock/acquire?name=build-key&wait=0"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);

    // holder identity is visible via status.
    let r = http
        .post(format!("{url}/lock/status?name=build-key"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    let holders = body["holders"].as_array().unwrap();
    assert_eq!(holders.len(), 1);
    assert!(holders[0]["holder"].as_str().unwrap().contains("runner-1"));

    // release-if-owner: a wrong owner releases nothing, the right one releases it.
    let r = http
        .post(format!("{url}/lock/release?name=build-key"))
        .header("x-vk-lock-owner", "bogus")
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<serde_json::Value>().await.unwrap()["released"], 0);
    let r = http
        .post(format!("{url}/lock/release?name=build-key"))
        .header("x-vk-lock-owner", &owner)
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<serde_json::Value>().await.unwrap()["released"], 1);

    // now free: a fresh acquire succeeds.
    let r = http
        .post(format!("{url}/lock/acquire?name=build-key&wait=0"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());

    let _ = std::fs::remove_dir_all(&dir);
}
