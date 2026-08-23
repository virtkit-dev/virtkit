//! End-to-end `/upload` test: a real multipart/form-data POST over real HTTP against an
//! accounts-mode server, proving the dropped file round-trips through the same CAS store
//! the OCI API serves — fetched back over `/v2/*`, deduped against an identical second
//! upload — and that CSRF and the write gate actually refuse what they should.

use std::sync::Arc;
use std::time::Duration;

use vk_registry::accounts::Db;
use vk_registry::config::{AuthMode, OidcSpec};
use vk_registry::{Authenticator, ServerConfig, ServerState};

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-upload-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Accounts-mode state built the way `serve` builds it — the same helper as in
/// `accounts_e2e.rs` and `relay_e2e.rs`. Discovery is deferred to the first login, so
/// naming a provider costs no network.
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

/// A hand-built `multipart/form-data` body, so this test needs no reqwest `multipart`
/// feature of its own.
fn multipart_body(boundary: &str, fields: &[(&str, &str)], file: (&str, &str, &[u8])) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    let (field_name, file_name, content) = file;
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_round_trips_through_the_shared_store_and_dedups() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("main");
    let state = accounts_state(&dir);
    let store = state.store.clone();
    let db = accounts_db(&state);
    let admin = db
        .upsert_user("https://issuer", "admin", None, None)
        .unwrap();
    db.set_admin(&admin.id, true).unwrap();
    let admin_session = db
        .create_session(&admin.id, Duration::from_secs(3600))
        .unwrap();
    let csrf = db.session_csrf(&admin_session).unwrap().unwrap();

    let plain = db
        .upsert_user("https://issuer", "plain", None, None)
        .unwrap();
    let plain_session = db
        .create_session(&plain.id, Duration::from_secs(3600))
        .unwrap();
    let plain_csrf = db.session_csrf(&plain_session).unwrap().unwrap();

    let url = spawn(state.clone());
    // No redirect following: the success path answers 303, and that is what is asserted.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let boundary = "vk-upload-e2e-boundary";
    let content_type = format!("multipart/form-data; boundary={boundary}");

    // A non-admin session is refused (sessions get write only when is_admin).
    let body = multipart_body(
        boundary,
        &[
            ("csrf", &plain_csrf),
            ("name", "team-a/doc"),
            ("tag", "denied-1"),
        ],
        ("file", "hello.txt", b"hello world"),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={plain_session}"))
        .header("Content-Type", &content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(
        store
            .get_manifest("team-a/doc", "denied-1")
            .unwrap()
            .is_none(),
        "a refused upload stores nothing"
    );

    // A wrong CSRF token is refused even for an admin session.
    let body = multipart_body(
        boundary,
        &[
            ("csrf", "wrong"),
            ("name", "team-a/doc"),
            ("tag", "denied-2"),
        ],
        ("file", "hello.txt", b"hello world"),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(
        store
            .get_manifest("team-a/doc", "denied-2")
            .unwrap()
            .is_none(),
        "a refused upload stores nothing"
    );

    // The real thing: an admin session with the right CSRF token succeeds.
    let body = multipart_body(
        boundary,
        &[("csrf", &csrf), ("name", "team-a/doc"), ("tag", "v1")],
        ("file", "hello.txt", b"hello world"),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/browse/team-a/doc/manifests/v1")
    );

    // Fetchable straight back over the ordinary OCI API.
    let (digest, data, _ctype) = store.get_manifest("team-a/doc", "v1").unwrap().unwrap();
    assert!(digest.starts_with("sha256:"));
    let manifest: serde_json::Value = serde_json::from_slice(&data).unwrap();
    let layer_digest = manifest["layers"][0]["digest"].as_str().unwrap();
    let expected_digest = format!("sha256:{}", sha256_hex(b"hello world"));
    assert_eq!(layer_digest, expected_digest);
    let blob = store
        .get_blob(layer_digest.trim_start_matches("sha256:"))
        .unwrap()
        .unwrap();
    assert_eq!(blob, b"hello world");

    // ... and over real HTTP, which is the property that matters to a client.
    let over_http = client
        .get(format!("{url}/v2/team-a/doc/manifests/v1"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(over_http.status(), 200);
    let fetched: serde_json::Value = over_http.json().await.unwrap();
    assert_eq!(fetched["layers"][0]["digest"], expected_digest);
    assert_eq!(
        fetched["layers"][0]["annotations"]["org.opencontainers.image.title"],
        "hello.txt"
    );
    let bytes = client
        .get(format!("{url}/v2/team-a/doc/blobs/{expected_digest}"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(bytes.status(), 200);
    assert_eq!(bytes.bytes().await.unwrap().as_ref(), b"hello world");

    // A second upload of byte-identical content (same file bytes *and* filename, so
    // the constructed manifest is byte-identical too — the manifest carries no
    // repo/tag of its own) under a different repo name dedups all the way down:
    // config, layer, and manifest all resolve to blobs already on disk.
    let before = store.stats().unwrap();
    let body = multipart_body(
        boundary,
        &[("csrf", &csrf), ("name", "team-b/other"), ("tag", "v1")],
        ("file", "hello.txt", b"hello world"),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    let after = store.stats().unwrap();
    assert_eq!(
        before.identity_blobs + before.zstd_blobs,
        after.identity_blobs + after.zstd_blobs,
        "a byte-identical upload (content and filename) must not create a new blob"
    );
    // The new repo's manifest resolves to the very same manifest digest.
    let (digest2, _, _) = store.get_manifest("team-b/other", "v1").unwrap().unwrap();
    assert_eq!(
        digest2, digest,
        "identical manifests dedup to the same digest"
    );

    // An API key is never allowed here, whatever else it carries.
    let (_, key_token) = db.create_api_key(Some(&admin.id), "ci", &[], None).unwrap();
    let body = multipart_body(
        boundary,
        &[("csrf", &csrf), ("name", "team-a/doc"), ("tag", "v2")],
        ("file", "hello.txt", b"hello world"),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .bearer_auth(&key_token)
        .header("Content-Type", &content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(
        store.get_manifest("team-a/doc", "v2").unwrap().is_none(),
        "a refused upload stores nothing"
    );

    // A body that puts the file before the fields that authorize it is refused: the file
    // is read before `name` says where it would go, so there is no repository to check —
    // being refused at all is the property.
    let mut out_of_order = Vec::new();
    out_of_order.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n\r\nbytes\r\n"
        )
        .as_bytes(),
    );
    out_of_order.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n--{boundary}--\r\n")
            .as_bytes(),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(out_of_order)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // A field twice is refused rather than last-wins: which occurrence the checks ran
    // against would otherwise be an open question, and repeating the file is a way to make
    // the server buffer many times over the ceiling.
    let mut duplicated = multipart_body(
        boundary,
        &[("csrf", &csrf), ("name", "team-a/doc"), ("tag", "dup")],
        ("file", "a.txt", b"first"),
    );
    // drop the closing delimiter, append a second file part, close again
    let close = format!("--{boundary}--\r\n");
    let keep = duplicated.len() - close.len();
    duplicated.truncate(keep);
    duplicated.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b.txt\"\r\n\r\nsecond\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(duplicated)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(
        store.get_manifest("team-a/doc", "dup").unwrap().is_none(),
        "a refused upload stores nothing"
    );

    // A body that is not multipart at all, and an empty file, are both 400s rather than
    // 500s with an error chain in them.
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = multipart_body(
        boundary,
        &[("csrf", &csrf), ("name", "team-a/doc"), ("tag", "v3")],
        ("file", "empty.txt", b""),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(store.get_manifest("team-a/doc", "v3").unwrap().is_none());

    // A file bigger than one hyper frame: the pre-authorization residue cap must bound
    // only what is still unparsed, not the frame that carried csrf and name with it.
    let big = vec![b'z'; 512 * 1024];
    let body = multipart_body(
        boundary,
        &[("csrf", &csrf), ("name", "team-a/big"), ("tag", "v1")],
        ("file", "big.bin", &big),
    );
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303, "a 512 KiB upload must be accepted");
    let (_, data, _) = store.get_manifest("team-a/big", "v1").unwrap().unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(
        manifest["layers"][0]["size"].as_u64(),
        Some(big.len() as u64)
    );

    // ... and a caller who sends bulk *before* those fields is still refused early.
    let mut file_first = Vec::new();
    file_first.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"pad\"\r\n\r\n").as_bytes(),
    );
    file_first.extend_from_slice(&vec![b'p'; 64 * 1024]);
    file_first.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let resp = client
        .post(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .header("Content-Type", &content_type)
        .body(file_first)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // The GET form carries the same headers every other page does.
    let form = client
        .get(format!("{url}/upload"))
        .header("Cookie", format!("__Host-vk_session={admin_session}"))
        .send()
        .await
        .unwrap();
    assert!(form.status().is_success());
    assert_eq!(
        form.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert!(form.headers().get("content-security-policy").is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
