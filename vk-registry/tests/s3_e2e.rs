//! The S3 view over real HTTP, as sccache uses it: an object written and read back under a
//! SigV4 signature whose secret is the registry credential, a missing key a 404, the same
//! object seen by WebDAV, and anything but GetObject, HeadObject and PutObject refused.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vk_registry::accounts::{Action, EmailUpdate, Scope};
use vk_registry::config::{AuthMode, OidcSpec};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use vk_hub_proto::token::{Claims, Grant};
use vk_peer::token::Signer;
use vk_registry::lock::LockManager;
use vk_registry::{Authenticator, ServerConfig, ServerState, Store};

const AUD: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
const BEARER: &str = "s3cret-bearer";

fn tmp(tag: &str) -> std::path::PathBuf {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let p = std::env::temp_dir().join(format!(
        "vk-registry-s3-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Start a shared-bearer registry that also accepts hub tokens.
async fn serve(dir: &std::path::Path, webdav: bool, s3: bool) -> (String, Signer, Arc<Store>) {
    let signer = Signer::generate(&dir.join("token-key")).unwrap();
    let store = Arc::new(Store::new(dir.join("store")).unwrap());
    let state = Arc::new(ServerState {
        store: Arc::clone(&store),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::Authenticator::Shared(vk_registry::auth::Auth::Bearer {
            token: BEARER.to_string(),
        }),
        tls: None,
        webdav,
        s3,
        tokens: Default::default(),
        handover: Default::default(),
    });
    state.tokens.open(AUD, vec![signer.public().clone()], &[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(vk_registry::serve_on(listener, state));
    (base, signer, store)
}

/// A hub token writing under `prefix`.
fn token(signer: &Signer, prefix: &str) -> String {
    let now = vk_peer::now_secs();
    signer
        .sign(Claims {
            kid: String::new(),
            aud: AUD.into(),
            sub: "hub:media".into(),
            jti: vk_peer::token::new_jti().unwrap(),
            pipeline: None,
            iat: now - 1,
            exp: now + 600,
            grants: vec![Grant {
                prefix: prefix.to_string(),
                write: true,
                ..Grant::default()
            }],
        })
        .unwrap()
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sign the request using `key` as both AWS keys and `payload` as `x-amz-content-sha256`.
fn signed(
    client: &reqwest::Client,
    method: reqwest::Method,
    base: &str,
    path: &str,
    key: &str,
    payload: &str,
) -> reqwest::RequestBuilder {
    let host = base.trim_start_matches("http://");
    let amz_date = amz_date(vk_peer::now_secs());
    let day = &amz_date[..8];
    // `path` is already canonical, its query (if any) one name, or names in sorted order.
    let (canonical_path, query) = path.split_once('?').unwrap_or((path, ""));
    let canonical = format!(
        "{method}\n{canonical_path}\n{query}\nhost:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{amz_date}\n\
         \nhost;x-amz-content-sha256;x-amz-date\n{payload}"
    );
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut k = hmac(format!("AWS4{key}").as_bytes(), day);
    for part in ["us-east-1", "s3", "aws4_request"] {
        k = hmac(&k, part);
    }
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={key}/{scope},SignedHeaders=host;x-amz-content-sha256;\
         x-amz-date,Signature={}",
        hex(&hmac(&k, &to_sign))
    );
    client
        .request(method, format!("{base}{path}"))
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload)
        .header("authorization", auth)
}

/// Unix seconds as `YYYYMMDDTHHMMSSZ`.
fn amz_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

const UNSIGNED: &str = "UNSIGNED-PAYLOAD";

#[tokio::test]
async fn sccache_reads_and_writes_through_the_s3_view() {
    let dir = tmp("rw");
    // WebDAV off: the S3 view still reaches the files area, `/dav/` does not.
    let (base, _, store) = serve(&dir, false, true).await;
    let c = reqwest::Client::new();
    let put = |path: &'static str, body: &'static [u8], payload: String| {
        signed(&c, reqwest::Method::PUT, &base, path, BEARER, &payload).body(body)
    };

    // sccache's startup probe: a read of a missing key is a 404, then a write.
    let probe = "/s3/cache/sub/.sccache_check";
    let got = signed(&c, reqwest::Method::GET, &base, probe, BEARER, UNSIGNED)
        .send()
        .await
        .unwrap();
    assert_eq!(got.status(), 404);
    assert!(got.text().await.unwrap().contains("<Code>NoSuchKey</Code>"));
    let resp = put(probe, b"Hello, World!", UNSIGNED.into())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let got = signed(&c, reqwest::Method::GET, &base, probe, BEARER, UNSIGNED)
        .send()
        .await
        .unwrap();
    assert_eq!(got.status(), 200);
    assert_eq!(got.bytes().await.unwrap(), &b"Hello, World!"[..]);
    let head = signed(&c, reqwest::Method::HEAD, &base, probe, BEARER, UNSIGNED)
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["content-length"], "13");

    // A body signed by its SHA-256 is held to it.
    let body: &[u8] = b"cache entry";
    let sha = hex(&Sha256::digest(body));
    let ok = put("/s3/cache/a/b/c/0123abcd", body, sha.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let other = hex(&Sha256::digest(b"something else"));
    let bad = put("/s3/cache/a/b/c/4567ef", body, other)
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    assert!(
        bad.text()
            .await
            .unwrap()
            .contains("<Code>XAmzContentSHA256Mismatch</Code>")
    );
    let gone = signed(
        &c,
        reqwest::Method::GET,
        &base,
        "/s3/cache/a/b/c/4567ef",
        BEARER,
        UNSIGNED,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(gone.status(), 404, "a refused body leaves nothing");

    let again = put(probe, b"Hello again", UNSIGNED.into())
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);

    let dav = c
        .get(format!("{base}/dav/files/cache/sub/.sccache_check"))
        .bearer_auth(BEARER)
        .send()
        .await
        .unwrap();
    assert_eq!(dav.status(), 404, "WebDAV is off");

    // A read-only store refuses the write as S3 does, with WebDAV's retry hint kept.
    store.set_read_only(true);
    let busy = put(probe, b"later", UNSIGNED.into()).send().await.unwrap();
    assert_eq!(busy.status(), 503);
    assert_eq!(busy.headers()["retry-after"], "60");
    assert!(
        busy.text()
            .await
            .unwrap()
            .contains("<Code>ServiceUnavailable</Code>")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_s3_view_refuses_what_it_does_not_serve() {
    let dir = tmp("refuse");
    let (base, signer, _) = serve(&dir, true, true).await;
    let c = reqwest::Client::new();
    let path = "/s3/cache/k";

    // WebDAV checks a bearer supplied on an unsigned request.
    let plain = format!("{base}/s3/cache/plain");
    let put = c
        .put(&plain)
        .bearer_auth(BEARER)
        .body("p")
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    let got = c.get(&plain).bearer_auth(BEARER).send().await.unwrap();
    assert_eq!(got.text().await.unwrap(), "p");
    let wrong = c.get(&plain).bearer_auth("nope").send().await.unwrap();
    assert_eq!(wrong.status(), 403);
    assert!(
        wrong
            .text()
            .await
            .unwrap()
            .contains("<Code>AccessDenied</Code>")
    );

    // No credential, a wrong one, a signature over another path.
    let anon = c.get(format!("{base}{path}")).send().await.unwrap();
    assert_eq!(anon.status(), 403);
    assert!(
        anon.text()
            .await
            .unwrap()
            .contains("<Code>AccessDenied</Code>")
    );
    let wrong = signed(&c, reqwest::Method::GET, &base, path, "vkr_nope", UNSIGNED)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 403);
    let mut moved = signed(
        &c,
        reqwest::Method::GET,
        &base,
        "/s3/cache/other",
        BEARER,
        UNSIGNED,
    )
    .build()
    .unwrap();
    *moved.url_mut() = format!("{base}{path}").parse().unwrap();
    let moved = c.execute(moved).await.unwrap();
    assert_eq!(moved.status(), 403);
    assert!(
        moved
            .text()
            .await
            .unwrap()
            .contains("<Code>SignatureDoesNotMatch</Code>")
    );

    // A hub token reaches only what it is granted.
    let tok = token(&signer, "cache");
    let mine = signed(&c, reqwest::Method::PUT, &base, path, &tok, UNSIGNED)
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(mine.status(), 200);
    let theirs = signed(
        &c,
        reqwest::Method::PUT,
        &base,
        "/s3/other/k",
        &tok,
        UNSIGNED,
    )
    .body("x")
    .send()
    .await
    .unwrap();
    assert_eq!(theirs.status(), 403);

    // Listings, bucket operations and deletes are not served.
    for (method, p) in [
        (reqwest::Method::GET, "/s3/"),
        (reqwest::Method::GET, "/s3/cache"),
        (reqwest::Method::PUT, "/s3/newbucket"),
        (reqwest::Method::DELETE, "/s3/cache/k"),
    ] {
        let resp = signed(&c, method, &base, p, BEARER, UNSIGNED)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 501, "{p}");
        assert!(resp.text().await.unwrap().contains("NotImplemented"));
    }
    for p in ["/s3/cache?list-type=2", "/s3/cache/k?uploads="] {
        let anon = c.get(format!("{base}{p}")).send().await.unwrap();
        assert_eq!(anon.status(), 501, "{p}");
        let signed = signed(&c, reqwest::Method::GET, &base, p, BEARER, UNSIGNED)
            .send()
            .await
            .unwrap();
        assert_eq!(signed.status(), 501, "{p}");
        assert!(signed.text().await.unwrap().contains("NotImplemented"));
    }

    // Drain a refused signed upload within the size cap so the client receives the error.
    // Close the connection on an unsigned upload.
    let big = vec![0u8; 8 << 20];
    let refused = signed(&c, reqwest::Method::PUT, &base, path, BEARER, UNSIGNED)
        .header("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")
        .body(big.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 501);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("<Code>NotImplemented</Code>")
    );
    let anon = c
        .put(format!("{base}{path}"))
        .header("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 501);
    assert_eq!(anon.headers()["connection"], "close");

    // A body past the object cap is refused by its length alone, before it is sent.
    let req = signed(&c, reqwest::Method::PUT, &base, path, BEARER, UNSIGNED)
        .build()
        .unwrap();
    let mut head = format!("PUT {path} HTTP/1.1\r\ncontent-length: 5000000000\r\n");
    for (k, v) in req.headers() {
        head.push_str(&format!("{k}: {}\r\n", v.to_str().unwrap()));
    }
    head.push_str(&format!(
        "host: {}\r\n\r\n",
        base.trim_start_matches("http://")
    ));
    let mut tcp = tokio::net::TcpStream::connect(base.trim_start_matches("http://"))
        .await
        .unwrap();
    tcp.write_all(head.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut answer)).await;
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 413"), "{answer}");
    assert!(answer.contains("<Code>EntityTooLarge</Code>"), "{answer}");

    // WebDAV reads the object written through S3.
    let dav = c
        .get(format!("{base}/dav/files/cache/k"))
        .bearer_auth(BEARER)
        .send()
        .await
        .unwrap();
    assert_eq!(dav.status(), 200);
    assert_eq!(dav.text().await.unwrap(), "x");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_s3_view_can_be_turned_off() {
    let dir = tmp("off");
    let (base, _, _) = serve(&dir, true, false).await;
    let c = reqwest::Client::new();
    let resp = signed(
        &c,
        reqwest::Method::GET,
        &base,
        "/s3/cache/k",
        BEARER,
        UNSIGNED,
    )
    .send()
    .await
    .unwrap();
    // With S3 disabled, the ordinary registry handles this request.
    assert_ne!(
        resp.headers().get("content-type").unwrap(),
        "application/xml"
    );
    assert!(resp.status().is_client_error());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An accounts-mode registry, built as `serve` builds one, on loopback: its URL and state.
async fn serve_accounts(dir: &std::path::Path) -> (String, Arc<ServerState>) {
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
    assert!(cfg.s3);
    let state = Arc::new(cfg.into_state().unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(vk_registry::serve_on(listener, Arc::clone(&state)));
    (base, state)
}

#[tokio::test]
async fn an_api_key_signs_and_a_session_cookie_does_not() {
    let dir = tmp("accounts");
    let (base, state) = serve_accounts(&dir).await;
    let Authenticator::Accounts { db, .. } = &state.auth else {
        panic!("not accounts mode");
    };
    let user = db
        .upsert_user("https://issuer", "u", EmailUpdate::Keep, None)
        .unwrap();
    assert!(db.set_admin(&user.id, true).unwrap());
    let (_, key) = db
        .create_api_key(
            Some(&user.id),
            "sccache",
            &[Scope {
                action: Action::Write,
                repo_pattern: "files/cache/*".to_string(),
            }],
            None,
        )
        .unwrap();
    let session = db
        .create_session(&user.id, Duration::from_secs(3600))
        .unwrap();
    let c = reqwest::Client::new();
    let path = "/s3/cache/k";

    let put = signed(&c, reqwest::Method::PUT, &base, path, &key, UNSIGNED)
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    let got = signed(&c, reqwest::Method::GET, &base, path, &key, UNSIGNED)
        .send()
        .await
        .unwrap();
    assert_eq!(got.text().await.unwrap(), "x");
    let elsewhere = signed(
        &c,
        reqwest::Method::PUT,
        &base,
        "/s3/other/k",
        &key,
        UNSIGNED,
    )
    .body("x")
    .send()
    .await
    .unwrap();
    assert_eq!(elsewhere.status(), 403, "the key's scope still applies");

    // An admin's session cookie authorizes the WebDAV view, never the S3 one.
    let cookie = format!("__Host-vk_session={session}");
    let dav = c
        .get(format!("{base}/dav/files/cache/k"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(dav.status(), 200);
    let s3 = c
        .get(format!("{base}{path}"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(s3.status(), 403);
    assert!(
        s3.text()
            .await
            .unwrap()
            .contains("<Code>AccessDenied</Code>")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
