//! S3 over real HTTP: the gate `/s3/` requests pass, under every authentication mode the
//! server has, and the operations on buckets and objects behind it. SigV4 requests are signed
//! here by a signer of the tests' own, checked against AWS's published example; responses are
//! read off a raw socket, so a test sees exactly what a connection carries and can send a
//! second request on it.

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
    format!(
        "AWS4-HMAC-SHA256 Credential={id}/{scope}, SignedHeaders={}, Signature={}",
        names.join(";"),
        hex(&hmac(&signing_key(secret, date), &sts))
    )
}

/// The key `secret` signs with on `date`, in the tests' region.
fn signing_key(secret: &str, date: &str) -> Vec<u8> {
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), date);
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac(&key, part);
    }
    key
}

/// How a test's `aws-chunked` body is signed and ended.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Chunked {
    Signed,
    SignedTrailer,
    UnsignedTrailer,
}

impl Chunked {
    fn content_sha256(self) -> &'static str {
        match self {
            Chunked::Signed => "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            Chunked::SignedTrailer => "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            Chunked::UnsignedTrailer => "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        }
    }
}

/// `data` framed as `aws-chunked` in chunks of `chunk` bytes, as AWS's SDKs frame it: each
/// chunk signed from `seed` (the request's signature) with `key` at `at` in a signed mode,
/// then the `trailer` line and, in the signed trailer mode, its signature.
fn aws_chunked(
    mode: Chunked,
    data: &[u8],
    chunk: usize,
    (key, at, seed): (&[u8], &str, &str),
    trailer: Option<(&str, &str)>,
) -> Vec<u8> {
    let scope = format!("{}/us-east-1/s3/aws4_request", &at[..8]);
    let empty = sha256_hex(b"");
    let mut previous = seed.to_string();
    let mut out = Vec::new();
    for piece in data.chunks(chunk).chain([&b""[..]]) {
        out.extend_from_slice(format!("{:x}", piece.len()).as_bytes());
        if mode != Chunked::UnsignedTrailer {
            let sts = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{at}\n{scope}\n{previous}\n{empty}\n{}",
                sha256_hex(piece)
            );
            previous = hex(&hmac(key, &sts));
            out.extend_from_slice(format!(";chunk-signature={previous}").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(piece);
        if !piece.is_empty() {
            out.extend_from_slice(b"\r\n");
        }
    }
    if mode != Chunked::Signed {
        let lines = trailer.map_or(String::new(), |(n, v)| format!("{n}:{v}\n"));
        out.extend_from_slice(lines.replace('\n', "\r\n").as_bytes());
        if mode == Chunked::SignedTrailer {
            let sts = format!(
                "AWS4-HMAC-SHA256-TRAILER\n{at}\n{scope}\n{previous}\n{}",
                sha256_hex(lines.as_bytes())
            );
            let signature = hex(&hmac(key, &sts));
            out.extend_from_slice(format!("x-amz-trailer-signature:{signature}\r\n").as_bytes());
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The encoder frames AWS's chunked PutObject example as AWS does, signatures and all.
#[test]
fn the_test_encoder_reproduces_the_aws_chunked_example() {
    let key = signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524");
    let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
    let body = aws_chunked(
        Chunked::Signed,
        &[b'a'; 66_560],
        65_536,
        (&key, "20130524T000000Z", seed),
        None,
    );
    assert_eq!(body.len(), 66_824);
    let text = String::from_utf8(body).unwrap();
    for signature in [
        "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
        "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
        "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
    ] {
        assert!(text.contains(&format!(";chunk-signature={signature}\r\n")));
    }
    assert!(text.ends_with("\r\n\r\n"));
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
        self.signed_payload(host, key, skew, UNSIGNED)
    }

    /// [`Req::signed`] with `payload` as the `x-amz-content-sha256` the signature binds.
    fn signed_payload(self, host: &str, key: (&str, &str), skew: i64, payload: &str) -> Self {
        let at = stamp(vk_peer::now_secs().saturating_add_signed(skew));
        let auth = authorization(
            self.method,
            &self.path,
            &self.query,
            &[
                ("host", host),
                ("x-amz-content-sha256", payload),
                ("x-amz-date", &at),
            ],
            payload,
            key,
            &at,
        );
        self.header("x-amz-content-sha256", payload)
            .header("x-amz-date", &at)
            .header("Authorization", &auth)
    }

    /// `data` sent as an `aws-chunked` body framed by `mode` in 64 KiB chunks, signed for
    /// `host` by `key` now, with `trailer` as the trailer's checksum when given.
    fn chunked(
        self,
        host: &str,
        key: (&str, &str),
        mode: Chunked,
        data: &[u8],
        trailer: Option<(&str, &str)>,
    ) -> Self {
        let at = stamp(vk_peer::now_secs());
        let payload = mode.content_sha256();
        let auth = authorization(
            self.method,
            &self.path,
            &self.query,
            &[
                ("host", host),
                ("x-amz-content-sha256", payload),
                ("x-amz-date", &at),
            ],
            payload,
            key,
            &at,
        );
        let seed = auth.rsplit("Signature=").next().unwrap().to_string();
        let signing = signing_key(key.1, &at[..8]);
        let body = aws_chunked(mode, data, 64 * 1024, (&signing, &at, &seed), trailer);
        let mut req = self
            .header("x-amz-content-sha256", payload)
            .header("x-amz-date", &at)
            .header("Authorization", &auth)
            .header("Content-Encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", &data.len().to_string());
        if let Some((name, _)) = trailer {
            req = req.header("x-amz-trailer", name);
        }
        req.body(body)
    }

    /// This request with `name` sent as `value` instead of as it was.
    fn replace(mut self, name: &str, value: &str) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.header(name, value)
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

/// A response: its status, headers (names lowercase) and body, also as text.
#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    bytes: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The status and the S3 headers every `/s3/` answer carries.
    #[track_caller]
    fn ok(&self, status: u16) -> &Self {
        assert_eq!(self.status, status, "{self:?}");
        let id = self.header("x-amz-request-id").expect("a request id");
        assert!(
            id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "{id}"
        );
        assert_eq!(self.header("x-content-type-options"), Some("nosniff"));
        self
    }

    /// [`Resp::ok`], and for an error its XML `Code` and the request id the header names.
    #[track_caller]
    fn is(&self, status: u16, code: &str) -> &Self {
        self.ok(status);
        let id = self.header("x-amz-request-id").expect("a request id");
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
        self.response_to(req.method == "HEAD").await
    }

    async fn response(&mut self) -> Resp {
        self.response_to(false).await
    }

    /// The next response; `head` when it answers a HEAD, which has no body whatever its
    /// `Content-Length` says.
    async fn response_to(&mut self, head: bool) -> Resp {
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
            .filter(|_| !head)
            .map_or(0, |(_, v)| v.parse().unwrap());
        let mut bytes = vec![0; len];
        self.read.read_exact(&mut bytes).await.unwrap();
        Resp {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
            bytes,
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
    // A bucket that is not there; listing the buckets is not on an open server.
    send(&host, get("/s3/b")).await.is(404, "NoSuchBucket");
    send(&host, get("/s3/b/")).await.is(404, "NoSuchBucket");
    send(&host, get("/s3/")).await.is(403, "AccessDenied");
    send(&host, get("/s3")).await.is(403, "AccessDenied");
    send(
        &host,
        Req::new("PUT", "/s3/b/k").body(b"Hello, World!".to_vec()),
    )
    .await
    .ok(200);
    let resp = send(&host, get("/s3/b/k")).await;
    resp.ok(200);
    assert_eq!(resp.body, "Hello, World!");
    // Any key will do, its signature unchecked.
    send(
        &host,
        get("/s3/b/absent").signed(&host, ("anyone", "anything"), 0),
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

    // A hub token is a key too, signed or as a bearer, for what its grants cover; an expired
    // one, or one for another registry, is not.
    let now = vk_peer::now_secs();
    let token = signer.sign(hub_claims(AUD, now - 1, now + 600)).unwrap();
    let granted = || Req::new("GET", "/s3/p/gl/42/k");
    send(&host, granted().signed(&host, (&token, &token), 0))
        .await
        .is(404, "NoSuchKey");
    send(
        &host,
        granted().header("Authorization", &format!("Bearer {token}")),
    )
    .await
    .is(404, "NoSuchKey");
    send(&host, get().signed(&host, (&token, &token), 0))
        .await
        .is(403, "AccessDenied");
    send(&host, granted().signed(&host, (&token, "other"), 0))
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
    let list = send(&host, Req::new("GET", "/s3/b").query("list-type=2")).await;
    assert_eq!((list.status, list.body), (404, unknown.body.clone()));

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

// ---- objects and buckets ----

const HELLO: &[u8] = b"Hello, World!";
const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

fn md5_hex(b: &[u8]) -> String {
    hex(&md5::compute(b).0)
}

fn sha256_hex(b: &[u8]) -> String {
    hex(&sha2::Sha256::digest(b))
}

fn b64(b: &[u8]) -> String {
    vk_hub_proto::to_base64(b)
}

/// Files in `uploads/`, where a PUT stages its object.
fn staging_left(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir.join("store/uploads")).map_or(0, |d| {
        d.filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .count()
    })
}

/// How a test's requests are authenticated: a function from a request to the signed one.
type Sign<'a> = &'a dyn Fn(Req) -> Req;

/// What every served object carries, beside its bytes.
#[track_caller]
fn is_object(resp: &Resp, body: &[u8]) {
    resp.ok(200);
    assert_eq!(resp.bytes, body);
    assert_eq!(
        resp.header("content-length"),
        Some(&*body.len().to_string())
    );
    assert_eq!(
        resp.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(resp.header("content-disposition"), Some("attachment"));
    assert!(resp.header("last-modified").is_some(), "{resp:?}");
    assert_eq!(resp.header("accept-ranges"), Some("bytes"));
    assert_eq!(resp.header("docker-content-digest"), None);
}

/// What `sccache` does with its S3 backend, OpenDAL's requests: its startup probe of
/// `.sccache_check`, the probe written, a cache entry written and read back, and the HEAD
/// OpenDAL's `stat` sends.
async fn sccache_sequence(host: &str, sign: Sign<'_>, prefix: &str) {
    let check = format!("/s3/sccache/{prefix}.sccache_check");
    send(host, sign(Req::new("GET", &check)))
        .await
        .is(404, "NoSuchKey");
    let resp = send(host, sign(Req::new("PUT", &check).body(HELLO.to_vec()))).await;
    resp.ok(200);
    let etag = format!("\"{}\"", md5_hex(HELLO));
    assert_eq!(resp.header("etag"), Some(&*etag));
    let resp = send(host, sign(Req::new("GET", &check))).await;
    is_object(&resp, HELLO);
    assert_eq!(resp.header("etag"), Some(&*etag));

    let entry: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let key = format!(
        "/s3/sccache/{prefix}a/b/c/{}",
        sha256_hex(b"an entry's key")
    );
    send(host, sign(Req::new("PUT", &key).body(entry.clone())))
        .await
        .ok(200);
    let resp = send(host, sign(Req::new("GET", &key))).await;
    is_object(&resp, &entry);
    assert_eq!(
        resp.header("etag"),
        Some(&*format!("\"{}\"", md5_hex(&entry)))
    );
    let resp = send(host, sign(Req::new("HEAD", &key))).await;
    resp.ok(200);
    assert!(resp.bytes.is_empty());
    assert_eq!(
        resp.header("content-length"),
        Some(&*entry.len().to_string())
    );
    assert_eq!(resp.header("content-disposition"), Some("attachment"));
}

#[tokio::test]
async fn the_sccache_sequence_round_trips_on_an_open_server() {
    let dir = tmp("sccache-open");
    let host = spawn(open_state(&dir, true));
    sccache_sequence(&host, &|r| r, "").await;
    let signed = |r: Req| r.signed(&host, ("anyone", "anything"), 0);
    sccache_sequence(&host, &signed, "ci/").await;
    assert_eq!(staging_left(&dir), 0);
}

#[tokio::test]
async fn the_sccache_sequence_round_trips_with_an_api_key() {
    let dir = tmp("sccache-accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let scopes = [Scope {
        action: Action::Write,
        repo_pattern: "files/*".to_string(),
    }];
    let (_, key) = db
        .create_api_key(Some(&user.id), "s3", &scopes, None)
        .unwrap();
    let host = spawn(state.clone());
    let signed = |r: Req| r.signed(&host, (&key, &key), 0);
    sccache_sequence(&host, &signed, "ci/").await;
    // The bearer on the same paths still works.
    let bearer = |r: Req| r.header("Authorization", &format!("Bearer {key}"));
    sccache_sequence(&host, &bearer, "other/").await;
}

/// The payload modes: unsigned, or the body's SHA-256, which the body must then have. A
/// streaming mode this registry does not decode is refused, so its framing never becomes an
/// object.
#[tokio::test]
async fn a_put_body_is_unsigned_or_its_signed_sha256() {
    let dir = tmp("payload");
    let (state, _) = shared(
        &dir,
        Auth::Bearer {
            token: "s3cret".into(),
        },
        true,
    );
    let host = spawn(state);
    let key = ("s3cret", "s3cret");
    let put = |path: &str, body: &[u8]| Req::new("PUT", path).body(body.to_vec());
    let get = |path: &str| Req::new("GET", path).signed(&host, key, 0);

    send(&host, put("/s3/b/unsigned", HELLO).signed(&host, key, 0))
        .await
        .ok(200);
    is_object(&send(&host, get("/s3/b/unsigned")).await, HELLO);

    // The body's own digest, any case.
    let hex = sha256_hex(HELLO);
    for (path, digest) in [
        ("/s3/b/hex", hex.clone()),
        ("/s3/b/HEX", hex.to_uppercase()),
    ] {
        let req = put(path, HELLO).signed_payload(&host, key, 0, &digest);
        send(&host, req).await.ok(200);
        is_object(&send(&host, get(path)).await, HELLO);
    }
    // Another body's: refused, and nothing tagged.
    let req = put("/s3/b/mismatch", b"Hello, World?").signed_payload(&host, key, 0, &hex);
    send(&host, req).await.is(400, "XAmzContentSHA256Mismatch");
    send(&host, get("/s3/b/mismatch"))
        .await
        .is(404, "NoSuchKey");
    let req = put("/s3/b/garbage", HELLO).signed_payload(&host, key, 0, "not-a-digest");
    send(&host, req).await.is(400, "InvalidArgument");

    // A streaming mode not decoded here, or an encoding beside aws-chunked.
    let framed = b"d\r\nHello, World!\r\n0\r\n\r\n";
    let ecdsa = put("/s3/b/ecdsa", framed)
        .header("Content-Encoding", "aws-chunked")
        .header("x-amz-decoded-content-length", "13")
        .signed_payload(&host, key, 0, "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD");
    send(&host, ecdsa).await.is(501, "NotImplemented");
    let gzip = put("/s3/b/gzip", framed)
        .header("Content-Encoding", "aws-chunked, gzip")
        .header("x-amz-decoded-content-length", "13")
        .signed(&host, key, 0);
    send(&host, gzip).await.is(501, "NotImplemented");
    for path in ["/s3/b/ecdsa", "/s3/b/gzip"] {
        send(&host, get(path)).await.is(404, "NoSuchKey");
    }
    assert_eq!(staging_left(&dir), 0);

    // A declared length past 4 GiB is refused before a byte is read.
    let req = put("/s3/b/big", b"").signed(&host, key, 0);
    let head = req.head(&host).replace(
        "Content-Length: 0",
        &format!("Content-Length: {}", (4u64 << 30) + 1),
    );
    let mut conn = Conn::open(&host).await;
    conn.write
        .as_mut()
        .unwrap()
        .write_all(head.as_bytes())
        .await
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), conn.response())
        .await
        .expect("answered unread");
    resp.is(413, "EntityTooLarge");
    assert_eq!(staging_left(&dir), 0);
}

#[tokio::test]
async fn a_put_checks_the_digests_it_is_sent() {
    let dir = tmp("digests");
    let host = spawn(open_state(&dir, true));
    let put = |path: &str, (name, value): (&str, &str)| {
        Req::new("PUT", path)
            .header(name, value)
            .body(HELLO.to_vec())
    };
    let get = |path: &str| Req::new("GET", path);
    let other = b"Hello, World?";
    let sha1 = |b: &[u8]| {
        use sha1::Digest as _;
        sha1::Sha1::digest(b).to_vec()
    };
    let crc = |b: &[u8]| crc32fast::hash(b).to_be_bytes().to_vec();
    let good: Vec<(&str, String)> = vec![
        ("Content-MD5", b64(&md5::compute(HELLO).0)),
        ("x-amz-checksum-sha256", b64(&sha2::Sha256::digest(HELLO))),
        ("x-amz-checksum-sha1", b64(&sha1(HELLO))),
        ("x-amz-checksum-crc32", b64(&crc(HELLO))),
    ];
    let bad: Vec<(&str, String)> = vec![
        ("Content-MD5", b64(&md5::compute(other).0)),
        ("x-amz-checksum-sha256", b64(&sha2::Sha256::digest(other))),
        ("x-amz-checksum-sha1", b64(&sha1(other))),
        ("x-amz-checksum-crc32", b64(&crc(other))),
    ];
    for (i, (name, value)) in good.iter().enumerate() {
        let path = format!("/s3/b/good{i}");
        let resp = send(&host, put(&path, (name, value))).await;
        resp.ok(200);
        if name.starts_with("x-amz-checksum") {
            assert_eq!(resp.header(name), Some(value.as_str()), "{name}");
        }
        is_object(&send(&host, get(&path)).await, HELLO);
    }
    for (i, (name, value)) in bad.iter().enumerate() {
        let path = format!("/s3/b/bad{i}");
        send(&host, put(&path, (name, value)))
            .await
            .is(400, "BadDigest");
        send(&host, get(&path)).await.is(404, "NoSuchKey");
    }
    send(&host, put("/s3/b/x", ("Content-MD5", "AAAA")))
        .await
        .is(400, "InvalidDigest");
    send(&host, put("/s3/b/x", ("x-amz-checksum-sha256", "AAAA")))
        .await
        .is(400, "InvalidRequest");
    // Not checked, so taken.
    send(&host, put("/s3/b/c", ("x-amz-checksum-crc32c", "AAAAAA==")))
        .await
        .ok(200);
    assert_eq!(staging_left(&dir), 0);

    // On a read, the SHA-256 the store has, when asked.
    let resp = send(&host, get("/s3/b/good0")).await;
    assert_eq!(resp.header("x-amz-checksum-sha256"), None);
    let asked = get("/s3/b/good0").header("x-amz-checksum-mode", "ENABLED");
    let resp = send(&host, asked).await;
    is_object(&resp, HELLO);
    assert_eq!(
        resp.header("x-amz-checksum-sha256"),
        Some(&*b64(&sha2::Sha256::digest(HELLO)))
    );
    let asked = Req::new("HEAD", "/s3/b/good0").header("x-amz-checksum-mode", "enabled");
    let resp = send(&host, asked).await;
    resp.ok(200);
    assert_eq!(
        resp.header("x-amz-checksum-sha256"),
        Some(&*b64(&sha2::Sha256::digest(HELLO)))
    );
}

/// The shared bearer of [`bearer_server`], which is also its access key and secret.
const BEARER: (&str, &str) = ("s3cret", "s3cret");

/// A shared-bearer server: its directory and address.
fn bearer_server(tag: &str) -> (std::path::PathBuf, String) {
    let dir = tmp(tag);
    let auth = Auth::Bearer {
        token: BEARER.0.into(),
    };
    let (state, _) = shared(&dir, auth, true);
    (dir, spawn(state))
}

fn bytes_of_len(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 % 251) as u8).collect()
}

fn sha1_b64(b: &[u8]) -> String {
    use sha1::Digest as _;
    b64(&sha1::Sha1::digest(b))
}

fn crc32_b64(b: &[u8]) -> String {
    b64(&crc32fast::hash(b).to_be_bytes())
}

/// One request whose body the server may stop reading, refusing it: the body is written
/// beside the wait for the answer, and a write failing once the server closes is expected.
async fn send_refused(host: &str, req: Req) -> Resp {
    let mut conn = Conn::open(host).await;
    let mut write = conn.write.take().unwrap();
    let head = req.head(host);
    let writer = tokio::spawn(async move {
        let _ = write.write_all(head.as_bytes()).await;
        let _ = write.write_all(&req.body).await;
        write
    });
    let resp = tokio::time::timeout(Duration::from_secs(10), conn.response())
        .await
        .expect("answered");
    drop(writer.await.unwrap());
    resp
}

/// Change the byte after the last `marker` in `body`, a hex digit, to another one.
fn flip_after_last(body: &mut [u8], marker: &[u8]) {
    let at = body
        .windows(marker.len())
        .rposition(|w| w == marker)
        .unwrap()
        + marker.len();
    body[at] = if body[at] == b'0' { b'1' } else { b'0' };
}

/// `aws-chunked` bodies in the three streaming modes, from one byte to many chunks, decoded on
/// the way in: read back, each is the bytes sent, its ETag their MD5, and the trailer's
/// checksum is echoed as a header's would be.
#[tokio::test]
async fn aws_chunked_uploads_are_decoded_in_every_mode() {
    let (dir, host) = bearer_server("chunked");
    let get = |path: &str| Req::new("GET", path).signed(&host, BEARER, 0);
    for size in [1, 1024, 64 * 1024 + 1, 1 << 20] {
        let data = bytes_of_len(size);
        let (crc, sha) = (crc32_b64(&data), b64(&sha2::Sha256::digest(&data)));
        for (mode, trailer) in [
            (Chunked::Signed, None),
            (
                Chunked::SignedTrailer,
                Some(("x-amz-checksum-sha256", sha.as_str())),
            ),
            (
                Chunked::UnsignedTrailer,
                Some(("x-amz-checksum-crc32", crc.as_str())),
            ),
        ] {
            let path = format!("/s3/b/{mode:?}-{size}");
            let req = Req::new("PUT", &path).chunked(&host, BEARER, mode, &data, trailer);
            let resp = send(&host, req).await;
            resp.ok(200);
            let etag = format!("\"{}\"", md5_hex(&data));
            assert_eq!(resp.header("etag"), Some(&*etag), "{path}");
            if let Some((name, value)) = trailer {
                assert_eq!(resp.header(name), Some(value), "{path}");
            }
            is_object(&send(&host, get(&path)).await, &data);
        }
    }
    // A checksum not computed here is taken unchecked, and not echoed.
    let crc32c = Some(("x-amz-checksum-crc32c", "AAAAAA=="));
    let req = Req::new("PUT", "/s3/b/crc32c").chunked(
        &host,
        BEARER,
        Chunked::UnsignedTrailer,
        HELLO,
        crc32c,
    );
    let resp = send(&host, req).await;
    resp.ok(200);
    assert_eq!(resp.header("x-amz-checksum-crc32c"), None);
    is_object(&send(&host, get("/s3/b/crc32c")).await, HELLO);

    // An aws-chunked body under its own SHA-256: the decoded bytes must have it.
    let framed = b"d\r\nHello, World!\r\n0\r\n\r\n".to_vec();
    let chunked = |path: &str, digest: &str| {
        Req::new("PUT", path)
            .header("Content-Encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", "13")
            .body(framed.clone())
            .signed_payload(&host, BEARER, 0, digest)
    };
    send(&host, chunked("/s3/b/hex", &sha256_hex(HELLO)))
        .await
        .ok(200);
    is_object(&send(&host, get("/s3/b/hex")).await, HELLO);
    let other = sha256_hex(b"Hello, World?");
    send(&host, chunked("/s3/b/hex-other", &other))
        .await
        .is(400, "XAmzContentSHA256Mismatch");
    send(&host, get("/s3/b/hex-other"))
        .await
        .is(404, "NoSuchKey");
    assert_eq!(staging_left(&dir), 0);
}

/// A chunked body whose signatures or framing do not hold is refused, wherever in the body it
/// goes wrong, and leaves neither an object nor a staging file behind.
#[tokio::test]
async fn a_chunked_body_that_does_not_hold_leaves_nothing() {
    let (dir, host) = bearer_server("chunked-refused");
    let data = bytes_of_len(200_000);
    let crc = crc32_b64(&data);
    let put = |path: &str, mode| {
        let trailer = (mode != Chunked::Signed).then_some(("x-amz-checksum-crc32", crc.as_str()));
        Req::new("PUT", path).chunked(&host, BEARER, mode, &data, trailer)
    };
    let mut cases = Vec::new();
    // The last chunk's signature, read once every byte of data has been staged.
    let mut req = put("/s3/b/last-chunk", Chunked::Signed);
    flip_after_last(&mut req.body, b";chunk-signature=");
    cases.push(("/s3/b/last-chunk", req, 403, "SignatureDoesNotMatch"));
    // The first chunk's data.
    let mut req = put("/s3/b/data", Chunked::Signed);
    req.body[1000] ^= 1;
    cases.push(("/s3/b/data", req, 403, "SignatureDoesNotMatch"));
    let mut req = put("/s3/b/trailer-sig", Chunked::SignedTrailer);
    flip_after_last(&mut req.body, b"x-amz-trailer-signature:");
    cases.push(("/s3/b/trailer-sig", req, 403, "SignatureDoesNotMatch"));
    // The length the chunks hold, and what follows their end.
    let short = (data.len() - 1).to_string();
    let req = put("/s3/b/short", Chunked::Signed).replace("x-amz-decoded-content-length", &short);
    cases.push(("/s3/b/short", req, 400, "InvalidChunkSizeError"));
    let long = (data.len() + 1).to_string();
    let req =
        put("/s3/b/long", Chunked::UnsignedTrailer).replace("x-amz-decoded-content-length", &long);
    cases.push(("/s3/b/long", req, 400, "IncompleteBody"));
    let mut req = put("/s3/b/garbage", Chunked::Signed);
    req.body.extend_from_slice(b"\r\n");
    cases.push(("/s3/b/garbage", req, 400, "MalformedTrailerError"));
    let mut req = put("/s3/b/header", Chunked::UnsignedTrailer);
    req.body.splice(0..0, std::iter::repeat_n(b'0', 300));
    cases.push(("/s3/b/header", req, 400, "InvalidChunkSizeError"));
    let mut req = put("/s3/b/truncated", Chunked::Signed);
    req.body.truncate(req.body.len() - 50);
    cases.push(("/s3/b/truncated", req, 400, "IncompleteBody"));
    // No decoded length at all.
    let mut req = put("/s3/b/no-length", Chunked::Signed);
    req.headers
        .retain(|(n, _)| n != "x-amz-decoded-content-length");
    cases.push(("/s3/b/no-length", req, 400, "InvalidRequest"));

    for (path, req, status, code) in cases {
        send_refused(&host, req).await.is(status, code);
        let get = Req::new("GET", path).signed(&host, BEARER, 0);
        send(&host, get).await.is(404, "NoSuchKey");
    }
    assert!(!dir.join("store/repos/files/b/tags").exists());
    assert_eq!(staging_left(&dir), 0);
}

/// Under the bearer rather than SigV4, as the guest proxy will send it, a signed chunked body
/// has no seed to check its signatures against: its framing is decoded, its signatures not
/// checked.
#[tokio::test]
async fn a_bearer_chunked_put_is_decoded_with_its_signatures_unchecked() {
    let (dir, host) = bearer_server("chunked-bearer");
    let data = bytes_of_len(100_000);
    let crc = crc32_b64(&data);
    let bearer = format!("Bearer {}", BEARER.0);
    let stranger = ("anyone", "not-this-registry's-secret");
    for mode in [
        Chunked::Signed,
        Chunked::SignedTrailer,
        Chunked::UnsignedTrailer,
    ] {
        let path = format!("/s3/b/{mode:?}");
        let trailer = (mode != Chunked::Signed).then_some(("x-amz-checksum-crc32", crc.as_str()));
        let req = Req::new("PUT", &path)
            .chunked(&host, stranger, mode, &data, trailer)
            .replace("Authorization", &bearer);
        send(&host, req).await.ok(200);
        let get = Req::new("GET", &path).header("Authorization", &bearer);
        is_object(&send(&host, get).await, &data);
    }
    // Its framing and its trailer's checksum still are.
    let mut req = Req::new("PUT", "/s3/b/garbage")
        .chunked(&host, stranger, Chunked::Signed, &data, None)
        .replace("Authorization", &bearer);
    req.body.push(b'x');
    send(&host, req).await.is(400, "MalformedTrailerError");
    let wrong = crc32_b64(b"other");
    let req = Req::new("PUT", "/s3/b/crc")
        .chunked(
            &host,
            stranger,
            Chunked::SignedTrailer,
            &data,
            Some(("x-amz-checksum-crc32", wrong.as_str())),
        )
        .replace("Authorization", &bearer);
    send(&host, req).await.is(400, "BadDigest");
    assert_eq!(staging_left(&dir), 0);
}

/// A trailer's checksum is checked against the decoded bytes, as the header's would be.
#[tokio::test]
async fn a_trailer_checksum_must_be_the_body_s() {
    let (dir, host) = bearer_server("chunked-trailer");
    let data = bytes_of_len(70_000);
    let other = b"other";
    let get = |path: &str| Req::new("GET", path).signed(&host, BEARER, 0);
    let mut n = 0;
    for mode in [Chunked::SignedTrailer, Chunked::UnsignedTrailer] {
        for (name, value) in [
            ("x-amz-checksum-crc32", crc32_b64(other)),
            ("x-amz-checksum-sha1", sha1_b64(other)),
            ("x-amz-checksum-sha256", b64(&sha2::Sha256::digest(other))),
        ] {
            n += 1;
            let path = format!("/s3/b/bad{n}");
            let req = Req::new("PUT", &path).chunked(
                &host,
                BEARER,
                mode,
                &data,
                Some((name, value.as_str())),
            );
            send(&host, req).await.is(400, "BadDigest");
            send(&host, get(&path)).await.is(404, "NoSuchKey");
        }
        let sha1 = sha1_b64(&data);
        let req = Req::new("PUT", "/s3/b/sha1").chunked(
            &host,
            BEARER,
            mode,
            &data,
            Some(("x-amz-checksum-sha1", sha1.as_str())),
        );
        let resp = send(&host, req).await;
        resp.ok(200);
        assert_eq!(resp.header("x-amz-checksum-sha1"), Some(sha1.as_str()));

        // Not base64 of its length; announced and not sent; sent as a header too.
        let crc = ("x-amz-checksum-crc32", "!!");
        let req = Req::new("PUT", "/s3/b/x").chunked(&host, BEARER, mode, &data, Some(crc));
        send(&host, req).await.is(400, "InvalidRequest");
        let req = Req::new("PUT", "/s3/b/x")
            .chunked(&host, BEARER, mode, &data, None)
            .header("x-amz-trailer", "x-amz-checksum-crc32");
        send(&host, req).await.is(400, "MalformedTrailerError");
        let crc = crc32_b64(&data);
        let req = Req::new("PUT", "/s3/b/x")
            .chunked(
                &host,
                BEARER,
                mode,
                &data,
                Some(("x-amz-checksum-crc32", crc.as_str())),
            )
            .header("x-amz-checksum-crc32", &crc);
        send(&host, req).await.is(400, "InvalidRequest");
        send(&host, get("/s3/b/x")).await.is(404, "NoSuchKey");
    }
    assert_eq!(staging_left(&dir), 0);
}

/// A decoded length past 4 GiB is refused before a byte of the body is read.
#[tokio::test]
async fn a_decoded_length_past_the_cap_is_refused_unread() {
    let (dir, host) = bearer_server("chunked-big");
    let req = Req::new("PUT", "/s3/b/big")
        .header("Content-Encoding", "aws-chunked")
        .header(
            "x-amz-decoded-content-length",
            &((4u64 << 30) + 1).to_string(),
        )
        .signed_payload(&host, BEARER, 0, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
    let head = req
        .head(&host)
        .replace("Content-Length: 0", "Content-Length: 1000000");
    let mut conn = Conn::open(&host).await;
    conn.write
        .as_mut()
        .unwrap()
        .write_all(head.as_bytes())
        .await
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), conn.response())
        .await
        .expect("answered unread");
    resp.is(413, "EntityTooLarge");
    assert_eq!(staging_left(&dir), 0);
}

#[tokio::test]
async fn user_metadata_round_trips_and_no_content_type_is_kept() {
    let dir = tmp("meta");
    let host = spawn(open_state(&dir, true));
    let resp = send(
        &host,
        Req::new("PUT", "/s3/b/m")
            .header("Content-Type", "text/html")
            .header("x-amz-meta-mtime", "1700000000")
            .header("X-Amz-Meta-Foo-Bar", "baz qux")
            .body(b"<script>".to_vec()),
    )
    .await;
    resp.ok(200);
    for method in ["GET", "HEAD"] {
        let resp = send(&host, Req::new(method, "/s3/b/m")).await;
        resp.ok(200);
        assert_eq!(resp.header("x-amz-meta-mtime"), Some("1700000000"));
        assert_eq!(resp.header("x-amz-meta-foo-bar"), Some("baz qux"));
        assert_eq!(
            resp.header("content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(resp.header("content-disposition"), Some("attachment"));
    }
    // Replaced whole: metadata not sent again is gone.
    send(&host, Req::new("PUT", "/s3/b/m").body(HELLO.to_vec()))
        .await
        .ok(200);
    let resp = send(&host, Req::new("GET", "/s3/b/m")).await;
    assert_eq!(resp.header("x-amz-meta-mtime"), None);

    let put = |name: &str, value: &str| {
        Req::new("PUT", "/s3/b/refused")
            .header(name, value)
            .body(HELLO.to_vec())
    };
    send(&host, put("x-amz-meta-big", &"v".repeat(2048)))
        .await
        .is(400, "MetadataTooLarge");
    send(&host, put("x-amz-meta-a_b", "v"))
        .await
        .is(400, "InvalidArgument");
    send(&host, Req::new("GET", "/s3/b/refused"))
        .await
        .is(404, "NoSuchKey");
}

#[tokio::test]
async fn conditional_headers_decide_reads_and_writes() {
    let dir = tmp("conditional");
    let host = spawn(open_state(&dir, true));
    let put = |path: &str, body: &[u8]| Req::new("PUT", path).body(body.to_vec());
    // Create only.
    let create = |path: &str, body: &[u8]| put(path, body).header("If-None-Match", "*");
    send(&host, create("/s3/b/k", HELLO)).await.ok(200);
    send(&host, create("/s3/b/k", b"again"))
        .await
        .is(412, "PreconditionFailed");
    let etag = format!("\"{}\"", md5_hex(HELLO));
    // Compare and swap.
    send(
        &host,
        put("/s3/b/k", b"swapped").header("If-Match", "\"0000\""),
    )
    .await
    .is(412, "PreconditionFailed");
    send(&host, put("/s3/b/absent", HELLO).header("If-Match", &etag))
        .await
        .is(412, "PreconditionFailed");
    let resp = send(&host, put("/s3/b/k", b"swapped").header("If-Match", &etag)).await;
    resp.ok(200);
    let etag = format!("\"{}\"", md5_hex(b"swapped"));
    assert_eq!(resp.header("etag"), Some(&*etag));
    send(&host, put("/s3/b/k", HELLO).header("If-None-Match", &etag))
        .await
        .is(501, "NotImplemented");
    assert_eq!(staging_left(&dir), 0);

    let modified = send(&host, Req::new("GET", "/s3/b/k"))
        .await
        .header("last-modified")
        .unwrap()
        .to_string();
    let past = "Mon, 01 Jan 2001 00:00:00 GMT";
    let future = "Fri, 01 Jan 2100 00:00:00 GMT";
    for method in ["GET", "HEAD"] {
        let read = |name: &str, value: &str| Req::new(method, "/s3/b/k").header(name, value);
        let served = |r: &Resp| {
            r.ok(200);
            assert_eq!(r.header("etag"), Some(&*etag));
        };
        let not_modified = |r: &Resp| {
            r.ok(304);
            assert_eq!(r.header("etag"), Some(&*etag));
            assert!(r.bytes.is_empty());
        };
        let failed = |r: &Resp| {
            r.ok(412);
            if method == "GET" {
                r.is(412, "PreconditionFailed");
            }
        };
        served(&send(&host, read("If-Match", &etag)).await);
        failed(&send(&host, read("If-Match", "\"other\"")).await);
        not_modified(&send(&host, read("If-None-Match", &etag)).await);
        served(&send(&host, read("If-None-Match", "\"other\"")).await);
        not_modified(&send(&host, read("If-Modified-Since", &modified)).await);
        not_modified(&send(&host, read("If-Modified-Since", future)).await);
        served(&send(&host, read("If-Modified-Since", past)).await);
        served(&send(&host, read("If-Unmodified-Since", &modified)).await);
        failed(&send(&host, read("If-Unmodified-Since", past)).await);
        // If-Match outranks a failing If-Unmodified-Since.
        let both = read("If-Match", &etag).header("If-Unmodified-Since", past);
        served(&send(&host, both).await);
    }
}

#[tokio::test]
async fn attributes_deletes_and_the_paths_a_key_cannot_take() {
    let dir = tmp("objects");
    let state = open_state(&dir, true);
    let store = state.store.clone();
    let host = spawn(state);
    let put = |path: &str| Req::new("PUT", path).body(HELLO.to_vec());
    send(&host, put("/s3/b/k")).await.ok(200);
    send(&host, put("/s3/b/d/x")).await.ok(200);

    // GetObjectAttributes.
    let attrs = |which: &str| {
        Req::new("GET", "/s3/b/k")
            .query("attributes")
            .header("x-amz-object-attributes", which)
    };
    let resp = send(&host, attrs("ETag,ObjectSize, Checksum")).await;
    resp.ok(200);
    assert!(resp.header("last-modified").is_some());
    assert_eq!(
        resp.body,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><GetObjectAttributesResponse \
             xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ETag>{}</ETag><Checksum>\
             <ChecksumSHA256>{}</ChecksumSHA256></Checksum><ObjectSize>13</ObjectSize>\
             </GetObjectAttributesResponse>",
            md5_hex(HELLO),
            b64(&sha2::Sha256::digest(HELLO))
        )
    );
    send(&host, attrs("Nonsense"))
        .await
        .is(400, "InvalidArgument");
    send(&host, Req::new("GET", "/s3/b/k").query("attributes"))
        .await
        .is(400, "InvalidArgument");
    send(&host, attrs("ETag").path_of("/s3/b/absent"))
        .await
        .is(404, "NoSuchKey");

    // Not served yet: other subresources, other verbs, copies.
    for req in [
        Req::new("GET", "/s3/b/k").query("tagging"),
        Req::new("GET", "/s3/b/k").query("partNumber=1"),
        Req::new("POST", "/s3/b/k").query("uploads"),
        Req::new("GET", "/s3/b").query("versioning"),
        put("/s3/b/copy").header("x-amz-copy-source", "/b/k"),
    ] {
        send(&host, req).await.is(501, "NotImplemented");
    }
    send(&host, Req::new("GET", "/s3/b/copy"))
        .await
        .is(404, "NoSuchKey");
    // The SDK's operation hint is no subresource.
    let resp = send(&host, Req::new("GET", "/s3/b/k").query("x-id=GetObject")).await;
    is_object(&resp, HELLO);

    // Keys the store cannot name.
    for (path, code) in [
        ("/s3/b/a%2Fb", "InvalidArgument"),
        ("/s3/b/a%20b", "InvalidArgument"),
        ("/s3/b/k/", "InvalidArgument"),
        ("/s3/b/tags/x", "InvalidArgument"),
        ("/s3/b/%2E%2E/x", "InvalidArgument"),
        ("/s3/b/a+b", "InvalidArgument"),
        ("/s3/tags/x", "InvalidBucketName"),
    ] {
        send(&host, put(path)).await.is(400, code);
    }
    let long = format!("/s3/b/{}", "x".repeat(256));
    send(&host, put(&long)).await.is(400, "KeyTooLongError");

    // Where an object cannot go: a directory, below an object, over a foreign tag.
    store
        .put_manifest(
            "files/b/img",
            "v1",
            MANIFEST_TYPE,
            br#"{"schemaVersion":2}"#,
        )
        .unwrap();
    for path in ["/s3/b/d", "/s3/b/k/below", "/s3/b/img/v1"] {
        let resp = send(&host, put(path)).await;
        resp.is(409, "OperationAborted");
    }
    send(&host, Req::new("GET", "/s3/b/img/v1"))
        .await
        .is(404, "NoSuchKey");
    send(&host, Req::new("GET", "/s3/b/d"))
        .await
        .is(404, "NoSuchKey");

    // DeleteObject: 204 there or not; a directory has no object to delete; a foreign tag is
    // not this view's.
    send(&host, Req::new("DELETE", "/s3/b/k")).await.ok(204);
    send(&host, Req::new("GET", "/s3/b/k"))
        .await
        .is(404, "NoSuchKey");
    send(&host, Req::new("DELETE", "/s3/b/k")).await.ok(204);
    send(&host, Req::new("DELETE", "/s3/nobucket/k"))
        .await
        .ok(204);
    send(&host, Req::new("DELETE", "/s3/b/d")).await.ok(204);
    is_object(&send(&host, Req::new("GET", "/s3/b/d/x")).await, HELLO);
    send(&host, Req::new("DELETE", "/s3/b/img/v1"))
        .await
        .is(409, "OperationAborted");
    assert!(dir.join("store/repos/files/b/img/tags/v1").is_file());
    assert_eq!(staging_left(&dir), 0);
}

impl Req {
    /// The same request at another path.
    fn path_of(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }
}

#[tokio::test]
async fn buckets_are_the_top_level_directories() {
    let dir = tmp("buckets");
    let host = spawn(open_state(&dir, true));
    send(&host, Req::new("PUT", "/s3/b/k").body(HELLO.to_vec()))
        .await
        .ok(200);
    send(&host, Req::new("HEAD", "/s3/b")).await.ok(200);
    send(&host, Req::new("HEAD", "/s3/b/")).await.ok(200);
    send(&host, Req::new("HEAD", "/s3/none")).await.ok(404);
    let location = |path: &str| Req::new("GET", path).query("location");
    let resp = send(&host, location("/s3/b")).await;
    resp.ok(200);
    assert_eq!(
        resp.body,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>"
    );
    let resp = send(&host, location("/s3/b").signed(&host, ("any", "any"), 0)).await;
    assert!(
        resp.body.ends_with(">us-east-1</LocationConstraint>"),
        "{}",
        resp.body
    );
    send(&host, location("/s3/none"))
        .await
        .is(404, "NoSuchBucket");
}

/// Accounts mode: what each key may do follows its scopes, as on `/dav/files/`.
#[tokio::test]
async fn api_keys_reach_what_their_scopes_cover() {
    let dir = tmp("scopes");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let key = |action, pattern: &str| {
        let scopes = [Scope {
            action,
            repo_pattern: pattern.to_string(),
        }];
        db.create_api_key(Some(&user.id), pattern, &scopes, None)
            .unwrap()
            .1
    };
    let writer = key(Action::Write, "files/*");
    let reader = key(Action::Read, "files/*");
    let prefix = key(Action::Read, "files/b/p/*");
    let on_key = key(Action::Read, "files/b/k/*");
    let bucket_b = key(Action::Read, "files/b/*");
    let host = spawn(state.clone());
    let as_ = |k: &str, r: Req| r.signed(&host, (k, k), 0);
    let put = |path: &str| Req::new("PUT", path).body(HELLO.to_vec());
    let get = |path: &str| Req::new("GET", path);
    for path in ["/s3/b/p/x", "/s3/b/q/y", "/s3/b/k", "/s3/c/z"] {
        send(&host, as_(&writer, put(path))).await.ok(200);
    }

    // A read-only key's write is refused, its body read through first.
    let resp = send(
        &host,
        as_(&reader, put("/s3/b/p/new").body(vec![7; 1 << 20])),
    )
    .await;
    resp.is(403, "AccessDenied");
    send(&host, as_(&reader, Req::new("DELETE", "/s3/b/k")))
        .await
        .is(403, "AccessDenied");
    is_object(&send(&host, as_(&reader, get("/s3/b/k"))).await, HELLO);

    // A prefix-scoped key reads its prefix and nothing beside it.
    is_object(&send(&host, as_(&prefix, get("/s3/b/p/x"))).await, HELLO);
    send(&host, as_(&prefix, get("/s3/b/p/absent")))
        .await
        .is(404, "NoSuchKey");
    send(&host, as_(&prefix, get("/s3/b/q/y")))
        .await
        .is(403, "AccessDenied");
    // It may probe the bucket its prefix is in, as clients do before listing, and no other.
    send(&host, as_(&prefix, Req::new("HEAD", "/s3/b")))
        .await
        .ok(200);
    send(&host, as_(&prefix, Req::new("HEAD", "/s3/c")))
        .await
        .ok(403);
    send(&host, as_(&prefix, get("/s3/b").query("location=")))
        .await
        .ok(200);
    // Holding the key's own path but not the bucket it is in: absent, not refused.
    send(&host, as_(&on_key, get("/s3/b/k")))
        .await
        .is(404, "NoSuchKey");

    // The buckets listed are those the key may read.
    let buckets = |k: &str| {
        let k = k.to_string();
        let host = host.clone();
        async move {
            let resp = send(&host, get("/s3/").signed(&host, (&k, &k), 0)).await;
            resp.ok(200);
            assert!(
                resp.body.contains(
                    "<Owner><ID>vk-registry</ID><DisplayName>vk-registry</DisplayName></Owner>"
                ),
                "{}",
                resp.body
            );
            resp.body
                .split("<Name>")
                .skip(1)
                .map(|s| s.split('<').next().unwrap().to_string())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(buckets(&writer).await, ["b", "c"]);
    assert_eq!(buckets(&bucket_b).await, ["b"]);
    assert!(buckets(&prefix).await.is_empty());
    let resp = send(&host, as_(&writer, get("/s3/"))).await;
    assert!(resp.body.contains("<CreationDate>"), "{}", resp.body);

    // Listings: admitted on the bucket or on the directory the prefix names, and showing
    // what the key may read.
    let list = |k: &str, q: &str| {
        let (k, q, host) = (k.to_string(), q.to_string(), host.clone());
        async move { send(&host, get("/s3/b").query(&q).signed(&host, (&k, &k), 0)).await }
    };
    let resp = list(&prefix, "list-type=2&prefix=p%2F").await;
    resp.ok(200);
    assert_eq!(keys(&resp.body), ["p/x"]);
    assert_eq!(keys(&list(&prefix, "prefix=p%2F").await.body), ["p/x"]);
    assert_eq!(
        keys(&list(&prefix, "list-type=2&prefix=p%2Fx").await.body),
        ["p/x"]
    );
    for refused in [
        "list-type=2",
        "list-type=2&prefix=p",
        "list-type=2&prefix=q%2F",
    ] {
        list(&prefix, refused).await.is(403, "AccessDenied");
    }
    assert_eq!(
        keys(&list(&bucket_b, "list-type=2").await.body),
        ["k", "p/x", "q/y"]
    );
    let resp = list(&writer, "delimiter=%2F&list-type=2").await;
    assert_eq!(keys(&resp.body), ["k"]);
    assert_eq!(prefixes(&resp.body), ["p/", "q/"]);
    send(&host, as_(&writer, get("/s3/none").query("list-type=2")))
        .await
        .is(404, "NoSuchBucket");

    // A tag in the prefix whose bytes only bucket `c` holds: listed to a key that may read
    // them there, absent to the others, as a read of it is.
    send(
        &host,
        as_(&writer, put("/s3/c/secret").body(b"only in c".to_vec())),
    )
    .await
    .ok(200);
    let resp = send(
        &host,
        get("/v2/files/c/manifests/secret").header("Authorization", &format!("Bearer {writer}")),
    )
    .await;
    assert_eq!(resp.status, 200);
    state
        .store
        .put_manifest("files/b/p", "stolen", MANIFEST_TYPE, &resp.bytes)
        .unwrap();
    assert_eq!(
        keys(&list(&writer, "list-type=2&prefix=p%2F").await.body),
        ["p/stolen", "p/x"]
    );
    assert_eq!(
        keys(&list(&prefix, "list-type=2&prefix=p%2F").await.body),
        ["p/x"]
    );
    assert_eq!(
        keys(&list(&bucket_b, "list-type=2").await.body),
        ["k", "p/x", "q/y"]
    );
    send(&host, as_(&prefix, get("/s3/b/p/stolen")))
        .await
        .is(404, "NoSuchKey");
}

/// The text of each `<name>` element of a document, in order.
fn elements(body: &str, name: &str) -> Vec<String> {
    let open = format!("<{name}>");
    body.split(&open)
        .skip(1)
        .map(|s| s.split(&format!("</{name}>")).next().unwrap().to_string())
        .collect()
}

/// A listing's keys.
fn keys(body: &str) -> Vec<String> {
    elements(body, "Key")
}

/// A listing's common prefixes.
fn prefixes(body: &str) -> Vec<String> {
    elements(body, "CommonPrefixes")
        .iter()
        .flat_map(|p| elements(p, "Prefix"))
        .collect()
}

/// The text of a document's one `<name>` element.
#[track_caller]
fn element(body: &str, name: &str) -> String {
    let all = elements(body, name);
    assert_eq!(all.len(), 1, "{name} in {body}");
    all.into_iter().next().unwrap()
}

/// What `sccache` leaves in its bucket, sharded `a/b/c/<key>`, listed the ways the AWS CLI
/// and rclone list it: whole, by directory, by pages of two, and by the first version's
/// markers.
async fn sharded_listing(host: &str, sign: Sign<'_>) {
    let mut written: Vec<String> = [".sccache_check"].map(String::from).to_vec();
    for i in 0..6u8 {
        let hex = sha256_hex(&[i]);
        let (a, b, c) = (&hex[..1], &hex[1..2], &hex[2..3]);
        written.push(format!("ci/{a}/{b}/{c}/{hex}"));
    }
    for key in &written {
        let put = Req::new("PUT", &format!("/s3/sccache/{key}")).body(key.as_bytes().to_vec());
        send(host, sign(put)).await.ok(200);
    }
    written.sort();
    let list = |q: &str| sign(Req::new("GET", "/s3/sccache").query(q));

    let resp = send(host, list("list-type=2")).await;
    resp.ok(200);
    assert_eq!(resp.header("content-type"), Some("application/xml"));
    assert!(
        resp.body.starts_with(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>sccache</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys><KeyCount>7</KeyCount>\
             <IsTruncated>false</IsTruncated><Contents>"
        ),
        "{}",
        resp.body
    );
    assert_eq!(keys(&resp.body), written);
    assert_eq!(
        elements(&resp.body, "ETag").first().unwrap(),
        &format!("&quot;{}&quot;", md5_hex(b".sccache_check"))
    );
    assert_eq!(elements(&resp.body, "Size").first().unwrap(), "14");
    let modified = elements(&resp.body, "LastModified");
    assert!(
        modified
            .iter()
            .all(|m| m.len() == 24 && m.ends_with(".000Z")),
        "{modified:?}"
    );
    assert_eq!(elements(&resp.body, "StorageClass").len(), 7);
    assert!(!resp.body.contains("<Owner>"));

    // By directory, as `aws s3 ls` and rclone walk it.
    let resp = send(host, list("delimiter=%2F&list-type=2")).await;
    assert_eq!(keys(&resp.body), [".sccache_check"]);
    assert_eq!(prefixes(&resp.body), ["ci/"]);
    assert_eq!(element(&resp.body, "KeyCount"), "2");
    let first = &written[1];
    let shard = format!("ci/{}/", &first[3..4]);
    let resp = send(
        host,
        list(&format!(
            "delimiter=%2F&list-type=2&prefix={}",
            shard.replace('/', "%2F")
        )),
    )
    .await;
    assert!(keys(&resp.body).is_empty());
    assert!(
        prefixes(&resp.body)
            .iter()
            .all(|p| p.starts_with(&shard) && p.len() == shard.len() + 2),
        "{}",
        resp.body
    );
    assert_eq!(element(&resp.body, "Delimiter"), "/");

    // By pages of two: each token resumes where the last page ended.
    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    let mut pages = 0;
    loop {
        let q = match &token {
            Some(t) => format!("continuation-token={t}&list-type=2&max-keys=2"),
            None => "list-type=2&max-keys=2".to_string(),
        };
        let resp = send(host, list(&q)).await;
        resp.ok(200);
        pages += 1;
        let page = keys(&resp.body);
        assert_eq!(element(&resp.body, "KeyCount"), page.len().to_string());
        assert_eq!(element(&resp.body, "MaxKeys"), "2");
        if let Some(t) = &token {
            assert_eq!(&element(&resp.body, "ContinuationToken"), t);
        }
        seen.extend(page);
        if element(&resp.body, "IsTruncated") == "false" {
            assert!(!resp.body.contains("NextContinuationToken"));
            break;
        }
        token = Some(element(&resp.body, "NextContinuationToken"));
    }
    assert_eq!((pages, seen.as_slice()), (4, written.as_slice()));

    // The first version: markers, and every object's owner.
    let mut seen = Vec::new();
    let mut marker = String::new();
    loop {
        let q = if marker.is_empty() {
            "max-keys=3".to_string()
        } else {
            format!("marker={}&max-keys=3", marker.replace('/', "%2F"))
        };
        let resp = send(host, list(&q)).await;
        resp.ok(200);
        assert_eq!(element(&resp.body, "Marker"), marker);
        assert!(!resp.body.contains("KeyCount"));
        let page = keys(&resp.body);
        assert_eq!(elements(&resp.body, "Owner").len(), page.len());
        seen.extend(page);
        if element(&resp.body, "IsTruncated") == "false" {
            break;
        }
        marker = element(&resp.body, "NextMarker");
        assert_eq!(&marker, seen.last().unwrap());
    }
    assert_eq!(seen, written);

    // The other parameters.
    let start = &written[3];
    let resp = send(
        host,
        list(&format!(
            "list-type=2&start-after={}",
            start.replace('/', "%2F")
        )),
    )
    .await;
    assert_eq!(keys(&resp.body), &written[4..]);
    assert_eq!(&element(&resp.body, "StartAfter"), start);
    let resp = send(host, list("fetch-owner=true&list-type=2&max-keys=1")).await;
    assert!(
        resp.body.contains(
            "<Size>14</Size><Owner><ID>vk-registry</ID><DisplayName>vk-registry</DisplayName>\
             </Owner><StorageClass>STANDARD</StorageClass>"
        ),
        "{}",
        resp.body
    );
    let resp = send(host, list("list-type=2&max-keys=0")).await;
    assert!(keys(&resp.body).is_empty());
    assert_eq!(element(&resp.body, "IsTruncated"), "false");
    assert_eq!(element(&resp.body, "KeyCount"), "0");
    let resp = send(host, list("list-type=2&max-keys=5000")).await;
    assert_eq!(element(&resp.body, "MaxKeys"), "1000");
    let resp = send(
        host,
        list("delimiter=%2F&encoding-type=url&list-type=2&prefix=x%20y"),
    )
    .await;
    resp.ok(200);
    assert_eq!(element(&resp.body, "Prefix"), "x%20y");
    assert_eq!(element(&resp.body, "EncodingType"), "url");
    let resp = send(host, list("encoding-type=url&list-type=2&max-keys=1")).await;
    assert_eq!(keys(&resp.body), [".sccache_check"]);

    // Refused: a token this registry did not give, a malformed parameter.
    for bad in [
        "continuation-token=bm90IGEga2V5&list-type=2",
        "continuation-token=%21%21&list-type=2",
        "list-type=2&max-keys=-1",
        "encoding-type=base64&list-type=2",
        "list-type=3",
    ] {
        send(host, list(bad)).await.is(400, "InvalidArgument");
    }
    send(host, sign(Req::new("GET", "/s3/none").query("list-type=2")))
        .await
        .is(404, "NoSuchBucket");
    // A query naming something else is not a listing.
    send(host, list("acl=")).await.is(501, "NotImplemented");
    send(host, list("acl=&list-type=2"))
        .await
        .is(501, "NotImplemented");
}

#[tokio::test]
async fn a_sharded_bucket_lists_on_an_open_server() {
    let dir = tmp("list-open");
    let host = spawn(open_state(&dir, true));
    sharded_listing(&host, &|r| r).await;
}

#[tokio::test]
async fn a_sharded_bucket_lists_with_an_api_key() {
    let dir = tmp("list-accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let scopes = [Scope {
        action: Action::Write,
        repo_pattern: "files/*".to_string(),
    }];
    let (_, key) = db
        .create_api_key(Some(&user.id), "s3", &scopes, None)
        .unwrap();
    let host = spawn(state.clone());
    let signed = |r: Req| r.signed(&host, (&key, &key), 0);
    sharded_listing(&host, &signed).await;
}

/// A hub token's grants cover `files/<prefix>`.
#[tokio::test]
async fn a_hub_token_writes_and_reads_below_its_grant() {
    let dir = tmp("hub");
    let (state, signer) = shared(
        &dir,
        Auth::Bearer {
            token: "s3cret".into(),
        },
        true,
    );
    let host = spawn(state);
    let now = vk_peer::now_secs();
    let token = signer.sign(hub_claims(AUD, now - 1, now + 600)).unwrap();
    let as_token = |r: Req| r.signed(&host, (&token, &token), 0);
    send(
        &host,
        as_token(Req::new("PUT", "/s3/p/gl/42/k").body(HELLO.to_vec())),
    )
    .await
    .ok(200);
    is_object(
        &send(&host, as_token(Req::new("GET", "/s3/p/gl/42/k"))).await,
        HELLO,
    );
    // The bucket its grant is in, probed and listed down its grant.
    send(&host, as_token(Req::new("HEAD", "/s3/p")))
        .await
        .ok(200);
    let resp = send(
        &host,
        as_token(Req::new("GET", "/s3/p").query("list-type=2&prefix=gl%2F42%2F")),
    )
    .await;
    resp.ok(200);
    assert_eq!(keys(&resp.body), ["gl/42/k"]);
    send(
        &host,
        as_token(Req::new("GET", "/s3/p").query("list-type=2")),
    )
    .await
    .is(403, "AccessDenied");
    send(
        &host,
        as_token(Req::new("PUT", "/s3/p/gl/43/k").body(HELLO.to_vec())),
    )
    .await
    .is(403, "AccessDenied");
}

/// One object, three views: what S3 writes WebDAV and `/v2/` read, and the other way round.
#[tokio::test]
async fn s3_dav_and_v2_see_the_same_objects() {
    let dir = tmp("views");
    let host = spawn(open_state(&dir, true));
    send(&host, Req::new("PUT", "/s3/b/d/k").body(HELLO.to_vec()))
        .await
        .ok(200);
    let resp = send(
        &host,
        Req::new("PROPFIND", "/dav/files/b/d/").header("Depth", "1"),
    )
    .await;
    assert_eq!(resp.status, 207);
    assert!(
        resp.body.contains("<D:href>/dav/files/b/d/k</D:href>"),
        "{}",
        resp.body
    );
    let resp = send(&host, Req::new("GET", "/dav/files/b/d/k")).await;
    assert_eq!((resp.status, resp.bytes.as_slice()), (200, HELLO));
    let resp = send(&host, Req::new("GET", "/v2/files/b/d/manifests/k")).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body
            .contains(&format!("\"org.virtkit.md5\":\"{}\"", md5_hex(HELLO))),
        "{}",
        resp.body
    );

    // Written over WebDAV: the SHA-256 is its ETag.
    let resp = send(
        &host,
        Req::new("PUT", "/dav/files/b/dav").body(HELLO.to_vec()),
    )
    .await;
    assert_eq!(resp.status, 201);
    let resp = send(&host, Req::new("GET", "/s3/b/dav")).await;
    is_object(&resp, HELLO);
    assert_eq!(
        resp.header("etag"),
        Some(&*format!("\"{}\"", sha256_hex(HELLO)))
    );
    let resp = send(&host, Req::new("DELETE", "/dav/files/b/dav")).await;
    assert_eq!(resp.status, 204);
    send(&host, Req::new("GET", "/s3/b/dav"))
        .await
        .is(404, "NoSuchKey");
}

/// What a ranged answer carries: 206, `Content-Range` and the part's length, and the whole
/// object's headers.
#[track_caller]
fn is_part(resp: &Resp, data: &[u8], start: usize, len: usize, etag: &str) {
    resp.ok(206);
    let last = start + len - 1;
    assert_eq!(
        resp.header("content-range"),
        Some(&*format!("bytes {start}-{last}/{}", data.len()))
    );
    assert_eq!(resp.header("content-length"), Some(&*len.to_string()));
    assert_eq!(resp.header("etag"), Some(etag));
    assert_eq!(resp.header("accept-ranges"), Some("bytes"));
    assert_eq!(resp.header("content-disposition"), Some("attachment"));
    assert_eq!(
        resp.header("content-type"),
        Some("application/octet-stream")
    );
    assert!(resp.header("last-modified").is_some(), "{resp:?}");
    assert_eq!(resp.header("docker-content-digest"), None);
}

/// Bytes zstd shrinks well, varying enough that a misplaced range shows.
fn compressible(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i / 300 % 251) as u8).collect()
}

/// Ranges of an object stored compressed (a small S3 write) and of one stored plain (an S3
/// write of 8 MiB or more, so the AWS CLI's parallel 8 MiB ranges each cost a seek): every
/// form, cut to the end, a HEAD, 416, and what is ignored.
#[tokio::test]
async fn ranges_of_plain_and_zstd_stored_objects() {
    let dir = tmp("ranges");
    let host = spawn(open_state(&dir, true));
    let blobs = dir.join("store/blobs");
    let small = compressible(300_000);
    let big = compressible(8 << 20);
    for (key, data) in [("small", &small), ("big", &big)] {
        let path = format!("/s3/b/{key}");
        send(&host, Req::new("PUT", &path).body(data.clone()))
            .await
            .ok(200);
        let hex = sha256_hex(data);
        let zstd = blobs.join("zstd").join(&hex).is_file();
        let plain = blobs.join("sha256").join(&hex).is_file();
        assert_eq!((zstd, plain), (key == "small", key == "big"), "{key}");

        let whole = send(&host, Req::new("GET", &path)).await;
        is_object(&whole, data);
        let etag = whole.header("etag").unwrap().to_string();
        let n = data.len();
        let ranged = |value: &str| Req::new("GET", &path).header("Range", value);
        for (value, start, len) in [
            ("bytes=0-0".to_string(), 0, 1),
            ("bytes=0-99".to_string(), 0, 100),
            (format!("bytes={}-{}", n / 2, n / 2 + 70_000), n / 2, 70_001),
            ("bytes=1000-".to_string(), 1000, n - 1000),
            ("bytes=-500".to_string(), n - 500, 500),
            (format!("bytes={}-", n - 1), n - 1, 1),
            (format!("bytes=-{}", n + 10), 0, n),
            (format!("bytes=10-{}", n * 2), 10, n - 10),
            ("bytes=7-9,".to_string(), 7, 3),
        ] {
            let resp = send(&host, ranged(&value)).await;
            is_part(&resp, data, start, len, &etag);
            assert!(resp.bytes == data[start..start + len], "{key} {value}");
        }
        // The whole object again, from consecutive ranges as a transfer manager reads it.
        let step = 3 << 20;
        let mut joined = Vec::new();
        for start in (0..n).step_by(step) {
            let value = format!("bytes={start}-{}", start + step - 1);
            joined.extend(send(&host, ranged(&value)).await.bytes);
        }
        assert!(joined == *data, "{key}: the parts are the whole");

        // The checksum is the whole object's, and only when asked.
        let resp = send(&host, ranged("bytes=0-9")).await;
        assert_eq!(resp.header("x-amz-checksum-sha256"), None);
        let resp = send(
            &host,
            ranged("bytes=0-9").header("x-amz-checksum-mode", "ENABLED"),
        )
        .await;
        is_part(&resp, data, 0, 10, &etag);
        let sha = b64(&sha2::Sha256::digest(data));
        assert_eq!(resp.header("x-amz-checksum-sha256"), Some(&*sha));

        // A HEAD answers what the GET would.
        let resp = send(
            &host,
            Req::new("HEAD", &path).header("Range", "bytes=100-199"),
        )
        .await;
        is_part(&resp, data, 100, 100, &etag);
        assert!(resp.bytes.is_empty());
        let resp = send(&host, Req::new("HEAD", &path)).await;
        resp.ok(200);
        assert_eq!(resp.header("accept-ranges"), Some("bytes"));
        assert_eq!(resp.header("content-length"), Some(&*n.to_string()));

        // No byte of the object.
        for value in [format!("bytes={n}-"), "bytes=-0".into()] {
            let resp = send(&host, ranged(&value)).await;
            resp.is(416, "InvalidRange");
            assert_eq!(resp.header("content-range"), Some(&*format!("bytes */{n}")));
            assert!(
                resp.body
                    .contains(&format!("<ActualObjectSize>{n}</ActualObjectSize>")),
                "{}",
                resp.body
            );
        }
        let head = Req::new("HEAD", &path).header("Range", &format!("bytes={n}-"));
        assert_eq!(send(&host, head).await.status, 416);
        // Several ranges, or one that does not parse: the whole object.
        for value in [
            "bytes=0-1,5-6",
            "bytes=x-y",
            "lines=0-1",
            "bytes=5-2",
            "bytes= -1",
        ] {
            is_object(&send(&host, ranged(value)).await, data);
        }

        // If-Range: the part while the object is the one it names, else the whole.
        let modified = whole.header("last-modified").unwrap().to_string();
        let resp = send(&host, ranged("bytes=0-9").header("If-Range", &etag)).await;
        is_part(&resp, data, 0, 10, &etag);
        let resp = send(&host, ranged("bytes=0-9").header("If-Range", &modified)).await;
        is_part(&resp, data, 0, 10, &etag);
        for stale in ["\"0000\"", "Mon, 01 Jan 2001 00:00:00 GMT"] {
            let resp = send(&host, ranged("bytes=0-9").header("If-Range", stale)).await;
            is_object(&resp, data);
        }
        // The preconditions come first.
        let resp = send(&host, ranged("bytes=0-9").header("If-None-Match", &etag)).await;
        resp.ok(304);
    }

    // An empty object has no first byte, but a suffix of it is the whole of it.
    send(&host, Req::new("PUT", "/s3/b/empty")).await.ok(200);
    for method in ["GET", "HEAD"] {
        let ranged = |value: &str| Req::new(method, "/s3/b/empty").header("Range", value);
        let resp = send(&host, ranged("bytes=-1")).await;
        resp.ok(200);
        assert_eq!(resp.header("content-length"), Some("0"));
        assert_eq!(resp.header("content-range"), None);
        for value in ["bytes=0-", "bytes=0-0", "bytes=-0"] {
            assert_eq!(
                send(&host, ranged(value)).await.status,
                416,
                "{method} {value}"
            );
        }
    }
}

/// An object written over WebDAV is stored compressed when that pays, whatever its size, and
/// is served in ranges all the same. A ranged GET is a read, so it refreshes an idle tag as a
/// whole one does; a ranged HEAD does not.
#[tokio::test]
async fn a_dav_written_object_is_served_in_ranges_and_a_ranged_get_refreshes_it() {
    let dir = tmp("dav-ranges");
    let host = spawn(open_state(&dir, true));
    let data = compressible(100_000);
    for name in ["got", "headed"] {
        let path = format!("/dav/files/b/{name}");
        let resp = send(&host, Req::new("PUT", &path).body(data.clone())).await;
        assert_eq!(resp.status, 201);
    }
    let hex = sha256_hex(&data);
    assert!(dir.join("store/blobs/zstd").join(&hex).is_file());
    let etag = format!("\"{hex}\"");

    let tag = |name: &str| dir.join(format!("store/repos/files/b/tags/{name}"));
    let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(784_887_151);
    for name in ["got", "headed"] {
        std::fs::File::open(tag(name))
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
    }
    let mtime = |name: &str| std::fs::metadata(tag(name)).unwrap().modified().unwrap();

    let ranged = |method, name: &str| {
        Req::new(method, &format!("/s3/b/{name}")).header("Range", "bytes=-1000")
    };
    let resp = send(&host, ranged("GET", "got")).await;
    is_part(&resp, &data, data.len() - 1000, 1000, &etag);
    assert!(resp.bytes == data[data.len() - 1000..]);
    // The header is the pre-touch time.
    assert_eq!(
        resp.header("last-modified"),
        Some("Tue, 15 Nov 1994 08:12:31 GMT")
    );
    assert!(mtime("got") > SystemTime::now() - Duration::from_secs(60));

    let resp = send(&host, ranged("HEAD", "headed")).await;
    is_part(&resp, &data, data.len() - 1000, 1000, &etag);
    assert_eq!(mtime("headed"), long_ago);
}
