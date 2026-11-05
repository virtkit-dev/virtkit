//! S3 over real HTTP: the gate `/s3/` requests pass, under every authentication mode the
//! server has. SigV4 requests are signed here by a signer of the tests' own, checked against
//! AWS's published example; responses are read off a raw socket, so a test sees exactly what
//! a connection carries and can send a second request on it.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hmac::{KeyInit as _, Mac as _};
use sha2::Digest as _;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use vk_hub_proto::token::{Claims, Grant};
use vk_peer::token::Signer;
use vk_registry::accounts::{Action, Db, EmailUpdate, Scope};
use vk_registry::auth::Auth;
use vk_registry::config::{AuthMode, OidcSpec};
use vk_registry::lock::LockManager;
use vk_registry::{Authenticator, ServerConfig, ServerState, Store};

const AUD: &str = "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708";
const UNSIGNED: &str = "UNSIGNED-PAYLOAD";

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-s3-e2e-{tag}-{}-{:?}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Run serve_on in a separate thread with an ephemeral listener; the address it took.
fn spawn(state: Arc<ServerState>) -> String {
    let _ = rustls::crypto::ring::default_provider().install_default();
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
    addr.to_string()
}

/// A server with no credential configured; `s3` as given.
fn open_state(dir: &std::path::Path, s3: bool) -> Arc<ServerState> {
    let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    cfg.s3 = s3;
    Arc::new(cfg.into_state().expect("a local config starts"))
}

/// A shared-secret server with `auth`, taking hub tokens signed by a fresh key.
fn shared(dir: &std::path::Path, auth: Auth, s3: bool) -> (Arc<ServerState>, Signer) {
    let signer = Signer::generate(&dir.join("token-key")).unwrap();
    let state = Arc::new(ServerState {
        store: Arc::new(Store::new(dir.join("store")).unwrap()),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: Authenticator::Shared(auth),
        tls: None,
        webdav: true,
        s3,
        tokens: Default::default(),
        handover: Default::default(),
    });
    state.tokens.open(AUD, vec![signer.public().clone()]);
    (state, signer)
}

/// Accounts-mode state built the way `serve` builds it, as in `dav_e2e.rs`.
fn accounts_state(dir: &std::path::Path) -> Arc<ServerState> {
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

fn accounts_db(state: &ServerState) -> &Db {
    match &state.auth {
        Authenticator::Accounts { db, .. } => db,
        _ => panic!("not accounts mode"),
    }
}

fn hub_claims(aud: &str, iat: u64, exp: u64) -> Claims {
    Claims {
        kid: String::new(),
        aud: aud.into(),
        sub: "job:j1".into(),
        jti: vk_peer::token::new_jti().unwrap(),
        pipeline: None,
        iat,
        exp,
        grants: vec![Grant {
            prefix: "p/gl/42".into(),
            read: true,
            write: true,
            lock: false,
        }],
    }
}

// ---- the test-side SigV4 signer ----

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// `secs` since the epoch as SigV4's `YYYYMMDDTHHMMSSZ`.
fn stamp(secs: u64) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let (h, mi, s) = (rem / 3600, rem / 60 % 60, rem % 60);
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// The `Authorization` value for a request with an already canonical `query` and `headers`
/// (lowercase names, sorted, every one signed), signed by `id` with `secret` at `at`.
fn authorization(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload: &str,
    (id, secret): (&str, &str),
    at: &str,
) -> String {
    let date = &at[..8];
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    let names: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
    let mut canonical = format!("{method}\n{path}\n{query}\n");
    for (n, v) in headers {
        canonical.push_str(&format!("{n}:{}\n", v.trim()));
    }
    canonical.push_str(&format!("\n{}\n{payload}", names.join(";")));
    let sts = format!(
        "AWS4-HMAC-SHA256\n{at}\n{scope}\n{}",
        hex(&sha2::Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), date);
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac(&key, part);
    }
    format!(
        "AWS4-HMAC-SHA256 Credential={id}/{scope}, SignedHeaders={}, Signature={}",
        names.join(";"),
        hex(&hmac(&key, &sts))
    )
}

/// The signer reproduces AWS's GET Object example, signature and all.
#[test]
fn the_test_signer_reproduces_the_aws_get_object_example() {
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let at = "20130524T000000Z";
    let auth = authorization(
        "GET",
        "/test.txt",
        "",
        &[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", empty),
            ("x-amz-date", at),
        ],
        empty,
        (
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        at,
    );
    assert_eq!(
        auth,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
         SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
         Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert_eq!(stamp(1_369_353_600), at);
}

// ---- requests over a raw connection ----

/// One request: its line, its headers beyond `Host`, its body.
struct Req {
    method: &'static str,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn new(method: &'static str, path: &str) -> Self {
        Req {
            method,
            path: path.to_string(),
            query: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn query(mut self, q: &str) -> Self {
        self.query = q.to_string();
        self
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Signed for `host` by `key` (id, secret), `skew` seconds off now (UNSIGNED-PAYLOAD).
    fn signed(self, host: &str, key: (&str, &str), skew: i64) -> Self {
        let at = stamp(vk_peer::now_secs().saturating_add_signed(skew));
        let auth = authorization(
            self.method,
            &self.path,
            &self.query,
            &[
                ("host", host),
                ("x-amz-content-sha256", UNSIGNED),
                ("x-amz-date", &at),
            ],
            UNSIGNED,
            key,
            &at,
        );
        self.header("x-amz-content-sha256", UNSIGNED)
            .header("x-amz-date", &at)
            .header("Authorization", &auth)
    }

    fn head(&self, host: &str) -> String {
        let target = if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        };
        let mut head = format!("{} {target} HTTP/1.1\r\nHost: {host}\r\n", self.method);
        for (n, v) in &self.headers {
            head.push_str(&format!("{n}: {v}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n\r\n", self.body.len()));
        head
    }
}

/// A response: its status, headers (names lowercase) and body.
#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The status, the S3 headers every `/s3/` answer carries, and for an error its XML
    /// `Code` and the request id the header names.
    #[track_caller]
    fn is(&self, status: u16, code: &str) -> &Self {
        assert_eq!(self.status, status, "{self:?}");
        let id = self.header("x-amz-request-id").expect("a request id");
        assert!(
            id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "{id}"
        );
        assert_eq!(self.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(self.header("content-type"), Some("application/xml"));
        assert!(
            self.body
                .starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>"),
            "{}",
            self.body
        );
        assert!(
            self.body.contains(&format!("<Code>{code}</Code>")),
            "{}",
            self.body
        );
        assert!(
            self.body
                .contains(&format!("<RequestId>{id}</RequestId></Error>")),
            "{}",
            self.body
        );
        self
    }
}

/// A kept-alive connection to the server.
struct Conn {
    host: String,
    read: BufReader<OwnedReadHalf>,
    write: Option<OwnedWriteHalf>,
}

impl Conn {
    async fn open(host: &str) -> Self {
        let sock = tokio::net::TcpStream::connect(host).await.unwrap();
        let (read, write) = sock.into_split();
        Conn {
            host: host.to_string(),
            read: BufReader::new(read),
            write: Some(write),
        }
    }

    async fn send(&mut self, req: &Req) -> Resp {
        let write = self.write.as_mut().expect("the connection's writing half");
        write
            .write_all(req.head(&self.host).as_bytes())
            .await
            .unwrap();
        write.write_all(&req.body).await.unwrap();
        self.response().await
    }

    async fn response(&mut self) -> Resp {
        let mut line = String::new();
        self.read.read_line(&mut line).await.unwrap();
        let status = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status in {line:?}"));
        let mut headers = Vec::new();
        loop {
            line.clear();
            self.read.read_line(&mut line).await.unwrap();
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            let (n, v) = l.split_once(':').unwrap();
            headers.push((n.to_ascii_lowercase(), v.trim().to_string()));
        }
        let len: usize = headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .map_or(0, |(_, v)| v.parse().unwrap());
        let mut body = vec![0; len];
        self.read.read_exact(&mut body).await.unwrap();
        Resp {
            status,
            headers,
            body: String::from_utf8(body).unwrap(),
        }
    }

    /// Whether the server closed the connection: end of stream, or a reset.
    async fn closed(&mut self) -> bool {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), self.read.read(&mut byte))
            .await
            .expect("the server closes or answers")
        {
            Ok(n) => n == 0,
            Err(_) => true,
        }
    }
}

/// One request on a connection of its own.
async fn send(host: &str, req: Req) -> Resp {
    Conn::open(host).await.send(&req).await
}

/// Every SigV4 refusal a server with credentials answers before knowing the caller, with
/// the key it takes as `good`: each one's answer, over a mode's `host`.
async fn sigv4_refusals(host: &str, good: (&str, &str)) {
    let get = || Req::new("GET", "/s3/b/k");
    // An id it does not know, whose signature is consistent with it.
    send(host, get().signed(host, ("AKIDNOTAKEY", "AKIDNOTAKEY"), 0))
        .await
        .is(403, "InvalidAccessKeyId");
    // A good id, signed with another secret.
    let resp = send(host, get().signed(host, (good.0, "not-the-secret"), 0)).await;
    resp.is(403, "SignatureDoesNotMatch");
    assert!(
        resp.body.contains("<CanonicalRequest>GET\n/s3/b/k\n"),
        "{}",
        resp.body
    );
    // A clock 15 minutes and a second off, either way.
    for skew in [-15 * 60 - 1, 15 * 60 + 1] {
        let resp = send(host, get().signed(host, good, skew)).await;
        resp.is(403, "RequestTimeTooSkewed");
        assert!(resp.body.contains("<ServerTime>"), "{}", resp.body);
    }
    // Presigned, and temporary credentials.
    send(
        host,
        get()
            .query("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=00")
            .signed(host, good, 0),
    )
    .await
    .is(400, "AuthorizationQueryParametersError");
    send(
        host,
        get()
            .header("x-amz-security-token", "t")
            .signed(host, good, 0),
    )
    .await
    .is(400, "InvalidToken");
    // A signature that does not bind the payload.
    let at = stamp(vk_peer::now_secs());
    let auth = authorization(
        "GET",
        "/s3/b/k",
        "",
        &[("host", host), ("x-amz-date", &at)],
        UNSIGNED,
        good,
        &at,
    );
    send(
        host,
        get()
            .header("x-amz-content-sha256", UNSIGNED)
            .header("x-amz-date", &at)
            .header("Authorization", &auth),
    )
    .await
    .is(400, "AuthorizationHeaderMalformed");
    // And the good key passes the gate, to find nothing yet.
    send(host, get().signed(host, good, 0))
        .await
        .is(404, "NoSuchKey");
}

#[tokio::test]
async fn an_open_server_checks_no_signature_but_refuses_presigned_and_tokens() {
    let dir = tmp("open");
    let host = spawn(open_state(&dir, true));
    let get = |path: &str| Req::new("GET", path);
    send(&host, get("/s3/b/k")).await.is(404, "NoSuchKey");
    send(&host, get("/s3/b/k/deeper"))
        .await
        .is(404, "NoSuchKey");
    send(&host, get("/s3/b")).await.is(404, "NoSuchBucket");
    send(&host, get("/s3/b/")).await.is(404, "NoSuchBucket");
    send(&host, get("/s3/")).await.is(501, "NotImplemented");
    send(&host, get("/s3")).await.is(501, "NotImplemented");
    send(
        &host,
        Req::new("PUT", "/s3/b/k").body(b"Hello, World!".to_vec()),
    )
    .await
    .is(501, "NotImplemented");
    // Any key will do, its signature unchecked.
    send(
        &host,
        get("/s3/b/k").signed(&host, ("anyone", "anything"), 0),
    )
    .await
    .is(404, "NoSuchKey");
    // The clock still is, and what is refused everywhere is refused here.
    send(
        &host,
        get("/s3/b/k").signed(&host, ("anyone", "anything"), 3600),
    )
    .await
    .is(403, "RequestTimeTooSkewed");
    send(&host, get("/s3/b/k").query("X-Amz-Credential=a"))
        .await
        .is(400, "AuthorizationQueryParametersError");
    send(&host, get("/s3/b/k").header("X-Amz-Security-Token", "t"))
        .await
        .is(400, "InvalidToken");
}

#[tokio::test]
async fn a_shared_bearer_is_the_access_key_and_its_secret() {
    let dir = tmp("bearer");
    let (state, signer) = shared(
        &dir,
        Auth::Bearer {
            token: "s3cret".into(),
        },
        true,
    );
    let host = spawn(state);
    let get = || Req::new("GET", "/s3/b/k");
    // No credential, or a refused one: S3's 403, not the 401 challenge.
    let resp = send(&host, get()).await;
    resp.is(403, "AccessDenied");
    assert_eq!(resp.header("www-authenticate"), None);
    send(&host, get().header("Authorization", "Bearer nope"))
        .await
        .is(403, "AccessDenied");
    send(&host, get().header("Authorization", "AWS AKID:sig"))
        .await
        .is(403, "AccessDenied");
    // The bearer itself still works, as on `/dav/`.
    send(&host, get().header("Authorization", "Bearer s3cret"))
        .await
        .is(404, "NoSuchKey");
    sigv4_refusals(&host, ("s3cret", "s3cret")).await;

    // A hub token is a key too, signed or as a bearer; an expired one, or one for another
    // registry, is not.
    let now = vk_peer::now_secs();
    let token = signer.sign(hub_claims(AUD, now - 1, now + 600)).unwrap();
    send(&host, get().signed(&host, (&token, &token), 0))
        .await
        .is(404, "NoSuchKey");
    send(
        &host,
        get().header("Authorization", &format!("Bearer {token}")),
    )
    .await
    .is(404, "NoSuchKey");
    send(&host, get().signed(&host, (&token, "other"), 0))
        .await
        .is(403, "SignatureDoesNotMatch");
    for bad in [
        signer
            .sign(hub_claims(AUD, now - 7200, now - 3600))
            .unwrap(),
        signer
            .sign(hub_claims(
                "0123456789abcdef0123456789abcdef",
                now - 1,
                now + 600,
            ))
            .unwrap(),
    ] {
        send(&host, get().signed(&host, (&bad, &bad), 0))
            .await
            .is(403, "InvalidAccessKeyId");
        send(
            &host,
            get().header("Authorization", &format!("Bearer {bad}")),
        )
        .await
        .is(403, "AccessDenied");
    }
}

#[tokio::test]
async fn the_shared_basic_user_is_the_access_key_and_the_password_its_secret() {
    let dir = tmp("basic");
    let (state, _) = shared(
        &dir,
        Auth::Basic {
            user: "ci".into(),
            pass: "pa55".into(),
        },
        true,
    );
    let host = spawn(state);
    let get = || Req::new("GET", "/s3/b/k");
    send(&host, get()).await.is(403, "AccessDenied");
    sigv4_refusals(&host, ("ci", "pa55")).await;
    // The password is no access key, alone or as its own secret.
    send(&host, get().signed(&host, ("pa55", "pa55"), 0))
        .await
        .is(403, "InvalidAccessKeyId");
    // Basic credentials still work.
    send(&host, get().header("Authorization", "Basic Y2k6cGE1NQ=="))
        .await
        .is(404, "NoSuchKey");
    send(&host, get().header("Authorization", "Basic Y2k6bm9wZQ=="))
        .await
        .is(403, "AccessDenied");
}

#[tokio::test]
async fn an_api_key_is_the_access_key_and_its_secret_until_revoked_or_expired() {
    let dir = tmp("accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let scopes = [Scope {
        action: Action::Read,
        repo_pattern: "files/*".to_string(),
    }];
    let (_, key) = db
        .create_api_key(Some(&user.id), "s3", &scopes, None)
        .unwrap();
    let (revoked, revoked_key) = db
        .create_api_key(Some(&user.id), "gone", &scopes, None)
        .unwrap();
    assert!(db.revoke_api_key(&user.id, &revoked.id).unwrap());
    let past = SystemTime::now() - Duration::from_secs(60);
    let (_, expired_key) = db
        .create_api_key(Some(&user.id), "old", &scopes, Some(past))
        .unwrap();
    let host = spawn(state.clone());
    let get = || Req::new("GET", "/s3/b/k");

    send(&host, get()).await.is(403, "AccessDenied");
    send(&host, get().header("Authorization", "Bearer vkr_nope"))
        .await
        .is(403, "AccessDenied");
    send(
        &host,
        get().header("Authorization", &format!("Bearer {key}")),
    )
    .await
    .is(404, "NoSuchKey");
    sigv4_refusals(&host, (&key, &key)).await;
    send(&host, get().signed(&host, ("vkr_0123", "vkr_0123"), 0))
        .await
        .is(403, "InvalidAccessKeyId");
    for gone in [&revoked_key, &expired_key] {
        send(&host, get().signed(&host, (gone, gone), 0))
            .await
            .is(403, "InvalidAccessKeyId");
        send(
            &host,
            get().header("Authorization", &format!("Bearer {gone}")),
        )
        .await
        .is(403, "AccessDenied");
    }
}

/// A refusal before authentication reads up to 64 KiB of the body, so a write sees its answer
/// rather than a reset, a large one while it is still sending; the connection then closes,
/// as after any refusal of a request with a body, rather than the server reading the rest.
/// Without a body, the connection goes on.
#[tokio::test]
async fn a_refused_body_is_read_up_to_64_kib() {
    let dir = tmp("drain");
    let (state, _) = shared(
        &dir,
        Auth::Bearer {
            token: "s3cret".into(),
        },
        true,
    );
    let host = spawn(state);
    let put = |body: Vec<u8>| Req::new("PUT", "/s3/b/k").body(body);
    type Refusal<'a> = (Box<dyn Fn(Vec<u8>) -> Req + 'a>, u16, &'a str);
    let refusals: Vec<Refusal<'_>> = vec![
        (Box::new(put), 403, "AccessDenied"),
        (
            Box::new(|b| put(b).header("Authorization", "Bearer nope")),
            403,
            "AccessDenied",
        ),
        (
            Box::new(|b| put(b).signed(&host, ("AKIDNOTAKEY", "AKIDNOTAKEY"), 0)),
            403,
            "InvalidAccessKeyId",
        ),
        (
            Box::new(|b| put(b).signed(&host, ("s3cret", "wrong"), 0)),
            403,
            "SignatureDoesNotMatch",
        ),
        (
            Box::new(|b| put(b).signed(&host, ("s3cret", "s3cret"), 3600)),
            403,
            "RequestTimeTooSkewed",
        ),
        (
            Box::new(|b| put(b).query("X-Amz-Signature=00")),
            400,
            "AuthorizationQueryParametersError",
        ),
        (
            Box::new(|b| put(b).header("x-amz-security-token", "t")),
            400,
            "InvalidToken",
        ),
    ];
    for (req, status, code) in &refusals {
        let mut conn = Conn::open(&host).await;
        let resp = conn.send(&req(Vec::new())).await;
        resp.is(*status, code);
        assert_eq!(resp.header("connection"), None, "{code}");
        conn.send(&Req::new("GET", "/s3/b/k").signed(&host, ("s3cret", "s3cret"), 0))
            .await
            .is(404, "NoSuchKey");

        // sccache's probe: 13 bytes, answered.
        let mut conn = Conn::open(&host).await;
        let resp = conn.send(&req(b"Hello, World!".to_vec())).await;
        resp.is(*status, code);
        assert_eq!(resp.header("connection"), Some("close"), "{code}");
        assert!(conn.closed().await, "{code}");

        // A MiB of a body declared 64 MiB long, the rest never sent: the answer comes all
        // the same, so the server did not wait for the body's end.
        let req = req(vec![b'x'; 1 << 20]);
        let mut conn = Conn::open(&host).await;
        let head = req.head(&host).replace(
            &format!("Content-Length: {}", 1 << 20),
            &format!("Content-Length: {}", 64 << 20),
        );
        let mut write = conn.write.take().unwrap();
        let writer = tokio::spawn(async move {
            // The server stops reading: the write may fail once it closes. The writing half
            // is kept open until then.
            let _ = write.write_all(head.as_bytes()).await;
            let _ = write.write_all(&req.body).await;
            write
        });
        let resp = tokio::time::timeout(Duration::from_secs(10), conn.response())
            .await
            .expect("answered before the body ends");
        resp.is(*status, code);
        assert_eq!(resp.header("connection"), Some("close"), "{code}");
        assert!(conn.closed().await, "{code}");
        drop(writer.await.unwrap());
    }
}

/// `s3 = false`: `/s3/` is the 404 any unknown path is, after the usual gate.
#[tokio::test]
async fn s3_off_is_the_catch_all_404_after_authentication() {
    let dir = tmp("off");
    let host = spawn(open_state(&dir, false));
    let off = send(&host, Req::new("GET", "/s3/b/k")).await;
    let unknown = send(&host, Req::new("GET", "/nowhere")).await;
    assert_eq!(off.status, 404);
    assert_eq!(off.header("x-amz-request-id"), None);
    assert_eq!(off.body, unknown.body);
    assert_eq!(off.header("content-type"), unknown.header("content-type"));

    let dir = tmp("off-bearer");
    let (state, _) = shared(
        &dir,
        Auth::Bearer {
            token: "s3cret".into(),
        },
        false,
    );
    let host = spawn(state);
    let resp = send(&host, Req::new("GET", "/s3/b/k")).await;
    assert_eq!(resp.status, 401, "the mode's own challenge");
    let resp = send(
        &host,
        Req::new("GET", "/s3/b/k").header("Authorization", "Bearer s3cret"),
    )
    .await;
    assert_eq!(resp.status, 404);
    assert_eq!(resp.body, unknown.body);
}

/// A registry its hub made read-only refuses S3 writes in S3's form, and reads go on.
#[tokio::test]
async fn a_read_only_registry_refuses_writes_with_retry_after() {
    let dir = tmp("ro");
    let state = open_state(&dir, true);
    state.store.set_read_only(true);
    let host = spawn(state);
    for method in ["PUT", "DELETE", "POST"] {
        let resp = send(&host, Req::new(method, "/s3/b/k").body(b"x".to_vec())).await;
        resp.is(503, "ServiceUnavailable");
        assert_eq!(resp.header("retry-after"), Some("60"));
    }
    send(&host, Req::new("GET", "/s3/b/k"))
        .await
        .is(404, "NoSuchKey");
}
