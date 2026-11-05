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
        s3_host: None,
        tokens: Default::default(),
        handover: Default::default(),
    });
    state.tokens.open(AUD, vec![signer.public().clone()]);
    (state, signer)
}

/// Accounts-mode state built the way `serve` builds it, as in `dav_e2e.rs`.
fn accounts_state(dir: &std::path::Path) -> Arc<ServerState> {
    Arc::new(
        accounts_config(dir)
            .into_state()
            .expect("a valid accounts config starts"),
    )
}

/// The accounts-mode config [`accounts_state`] starts.
fn accounts_config(dir: &std::path::Path) -> ServerConfig {
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
    cfg
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
        let req = self
            .header("x-amz-content-sha256", payload)
            .header("x-amz-date", &at);
        let auth = req.authorization(host, payload, key, &at);
        req.header("Authorization", &auth)
    }

    /// The `Authorization` for this request as it is, signing `host` and every `x-amz-*`
    /// header it carries, as S3 requires and SDKs do.
    fn authorization(&self, host: &str, payload: &str, key: (&str, &str), at: &str) -> String {
        let mut signed: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v.clone()))
            .filter(|(n, _)| n.starts_with("x-amz-"))
            .chain([("host".to_string(), host.to_string())])
            .collect();
        signed.sort();
        let signed: Vec<(&str, &str)> = signed
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        authorization(
            self.method,
            &self.path,
            &self.query,
            &signed,
            payload,
            key,
            at,
        )
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
        self.chunked_declaring(host, key, mode, data, trailer, Some(data.len()))
    }

    /// [`Req::chunked`] declaring `decoded` as its `x-amz-decoded-content-length`, or none.
    fn chunked_declaring(
        self,
        host: &str,
        key: (&str, &str),
        mode: Chunked,
        data: &[u8],
        trailer: Option<(&str, &str)>,
        decoded: Option<usize>,
    ) -> Self {
        let at = stamp(vk_peer::now_secs());
        let payload = mode.content_sha256();
        let mut req = self
            .header("x-amz-content-sha256", payload)
            .header("x-amz-date", &at)
            .header("Content-Encoding", "aws-chunked");
        if let Some(decoded) = decoded {
            req = req.header("x-amz-decoded-content-length", &decoded.to_string());
        }
        if let Some((name, _)) = trailer {
            req = req.header("x-amz-trailer", name);
        }
        let auth = req.authorization(host, payload, key, &at);
        let seed = auth.rsplit("Signature=").next().unwrap().to_string();
        let signing = signing_key(key.1, &at[..8]);
        let body = aws_chunked(mode, data, 64 * 1024, (&signing, &at, &seed), trailer);
        req.header("Authorization", &auth).body(body)
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
        Conn::open_as(host, host).await
    }

    /// A connection to `addr` whose requests say they are for `host`.
    async fn open_as(addr: &str, host: &str) -> Self {
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
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
    // An x-amz-* header the signature does not cover; signed, it passes.
    let resp = send(
        host,
        get().signed(host, good, 0).header("X-Amz-Meta-X", "1"),
    )
    .await;
    resp.is(403, "AccessDenied");
    assert!(
        resp.body
            .contains("<HeadersNotSigned>x-amz-meta-x</HeadersNotSigned>"),
        "{}",
        resp.body
    );
    send(
        host,
        get().header("X-Amz-Meta-X", "1").signed(host, good, 0),
    )
    .await
    .is(404, "NoSuchKey");
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

/// With `s3_host` set, a host `<bucket>.<s3_host>` names the bucket and the whole path the
/// key, signed over the host and path as sent; path-style goes on working beside it, and a
/// host that names no bucket is left to the other routes.
#[tokio::test]
async fn a_bucket_is_named_by_its_host_under_s3_host() {
    let dir = tmp("virtual-host");
    let mut cfg = accounts_config(&dir);
    cfg.s3_host = Some("s3.example.com".to_string());
    let state = Arc::new(cfg.into_state().unwrap());
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
    let addr = spawn(state.clone());
    let port = addr.rsplit(':').next().unwrap();
    let send_to = |host: String, req: Req| {
        let addr = addr.clone();
        async move { Conn::open_as(&addr, &host).await.send(&req).await }
    };
    let signed = |host: &str, req: Req| req.signed(host, (&key, &key), 0);
    // the port a client sends is ignored, and the signature covers the host with it
    for vhost in [
        "b.s3.example.com".to_string(),
        format!("b.s3.example.com:{port}"),
    ] {
        let put = signed(&vhost, Req::new("PUT", "/dir/k").body(HELLO.to_vec()));
        send_to(vhost.clone(), put).await.ok(200);
        let get = signed(&vhost, Req::new("GET", "/dir/k"));
        is_object(&send_to(vhost.clone(), get).await, HELLO);
    }
    // the same object, path-style, on the registry's own host
    let get = signed(&addr, Req::new("GET", "/s3/b/dir/k"));
    is_object(&send_to(addr.clone(), get).await, HELLO);
    // and on `s3_host` itself, where only `/s3/` is S3
    let get = signed("s3.example.com", Req::new("GET", "/s3/b/dir/k"));
    is_object(&send_to("s3.example.com".into(), get).await, HELLO);

    let vhost = "b.s3.example.com".to_string();
    // `/` is the bucket: its listing
    let list = signed(&vhost, Req::new("GET", "/").query("list-type=2"));
    let resp = send_to(vhost.clone(), list).await;
    resp.ok(200);
    assert!(resp.body.contains("<Name>b</Name>"), "{}", resp.body);
    assert!(resp.body.contains("<Key>dir/k</Key>"), "{}", resp.body);
    // the whole path is the key, even one another route would take
    for path in ["/login", "/s3/k", "/v2/k"] {
        let put = signed(&vhost, Req::new("PUT", path).body(HELLO.to_vec()));
        send_to(vhost.clone(), put).await.ok(200);
    }
    let get = signed(&addr, Req::new("GET", "/s3/b/s3/k"));
    is_object(&send_to(addr.clone(), get).await, HELLO);
    let del = signed(&vhost, Req::new("DELETE", "/dir/k"));
    send_to(vhost.clone(), del).await.ok(204);
    let get = signed(&vhost, Req::new("GET", "/dir/k"));
    send_to(vhost.clone(), get).await.is(404, "NoSuchKey");

    // A label that cannot be a bucket, `s3_host` itself and another domain are the
    // registry's other routes, as for any host.
    let bearer = format!("Bearer {key}");
    let unknown = send_to(
        addr.clone(),
        Req::new("GET", "/nowhere").header("Authorization", &bearer),
    )
    .await;
    assert_eq!(unknown.status, 404);
    for host in [
        "tags.s3.example.com",
        "s3.example.com",
        "b.s3.example.org",
        "b.s4.example.com",
    ] {
        let resp = send_to(
            host.to_string(),
            Req::new("GET", "/nowhere").header("Authorization", &bearer),
        )
        .await;
        assert_eq!(resp.status, 404, "{host}: {resp:?}");
        assert_eq!(resp.header("x-amz-request-id"), None, "{host}");
        assert_eq!(resp.body, unknown.body, "{host}");
    }
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
    let declaring = |path: &str, mode: Chunked, decoded: Option<usize>| {
        let trailer = (mode != Chunked::Signed).then_some(("x-amz-checksum-crc32", crc.as_str()));
        Req::new("PUT", path).chunked_declaring(&host, BEARER, mode, &data, trailer, decoded)
    };
    let req = declaring("/s3/b/short", Chunked::Signed, Some(data.len() - 1));
    cases.push(("/s3/b/short", req, 400, "InvalidChunkSizeError"));
    let req = declaring("/s3/b/long", Chunked::UnsignedTrailer, Some(data.len() + 1));
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
    let req = declaring("/s3/b/no-length", Chunked::Signed, None);
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
            .header("x-amz-trailer", "x-amz-checksum-crc32")
            .chunked(&host, BEARER, mode, &data, None);
        send(&host, req).await.is(400, "MalformedTrailerError");
        let crc = crc32_b64(&data);
        let req = Req::new("PUT", "/s3/b/x")
            .header("x-amz-checksum-crc32", &crc)
            .chunked(
                &host,
                BEARER,
                mode,
                &data,
                Some(("x-amz-checksum-crc32", crc.as_str())),
            );
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

    // Not served: other subresources and verbs, and parameters an operation does not take.
    for req in [
        Req::new("GET", "/s3/b/k").query("partNumber=1"),
        Req::new("GET", "/s3/b/k").query("retention"),
        Req::new("POST", "/s3/b/k").query("uploads&acl"),
        put("/s3/b/k").query("tagging"),
        put("/s3/b/copy")
            .query("partNumber=1&uploadId=0&acl")
            .header("x-amz-copy-source", "/b/k"),
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
    let resp = send(host, list("acl=")).await;
    resp.ok(200);
    assert!(
        resp.body.contains("<Permission>FULL_CONTROL</Permission>"),
        "{}",
        resp.body
    );
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
    // A grant to write and not read deletes, one key or a batch; nothing beyond it.
    let mut claims = hub_claims(AUD, now - 1, now + 600);
    claims.grants[0].read = false;
    let writer = signer.sign(claims).unwrap();
    let as_writer = |r: Req| r.signed(&host, (&writer, &writer), 0);
    send(&host, as_writer(Req::new("GET", "/s3/p/gl/42/k")))
        .await
        .is(403, "AccessDenied");
    send(&host, as_writer(Req::new("DELETE", "/s3/p/gl/42/k")))
        .await
        .ok(204);
    send(&host, as_token(Req::new("GET", "/s3/p/gl/42/k")))
        .await
        .is(404, "NoSuchKey");
    send(
        &host,
        as_token(Req::new("PUT", "/s3/p/gl/42/b").body(HELLO.to_vec())),
    )
    .await
    .ok(200);
    let (deleted, errors) = delete_result(
        &send(
            &host,
            as_writer(delete_objects(
                "p",
                delete_doc(&[&key_of("gl/42/b"), &key_of("gl/43/k")], false),
            )),
        )
        .await,
    );
    assert_eq!(deleted, ["gl/42/b"]);
    assert_eq!(
        errors,
        [("gl/43/k".to_string(), "AccessDenied".to_string())]
    );
    send(&host, as_token(Req::new("GET", "/s3/p/gl/42/b")))
        .await
        .is(404, "NoSuchKey");
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

        // The checksum is the whole object's, so a part carries none even when asked: the
        // AWS CLI checks one against each part it fetches.
        let asked = |value: &str| ranged(value).header("x-amz-checksum-mode", "ENABLED");
        let resp = send(&host, asked("bytes=0-9")).await;
        is_part(&resp, data, 0, 10, &etag);
        assert_eq!(resp.header("x-amz-checksum-sha256"), None);
        let resp = send(&host, asked(&format!("bytes=0-{}", n - 1))).await;
        is_part(&resp, data, 0, n, &etag);
        assert_eq!(resp.header("x-amz-checksum-sha256"), None);
        let resp = send(
            &host,
            Req::new("GET", &path).header("x-amz-checksum-mode", "ENABLED"),
        )
        .await;
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

// ---- buckets made and removed, copies, batch deletes, configurations ----

/// A key of `db`'s user `ci` holding `scopes`, each an action on a pattern.
fn api_key(db: &Db, name: &str, scopes: &[(Action, &str)]) -> String {
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let scopes: Vec<Scope> = scopes
        .iter()
        .map(|(action, pattern)| Scope {
            action: *action,
            repo_pattern: pattern.to_string(),
        })
        .collect();
    db.create_api_key(Some(&user.id), name, &scopes, None)
        .unwrap()
        .1
}

/// A request signed by `key` as its access key and secret.
fn as_key<'a>(host: &'a str, key: &'a str) -> impl Fn(Req) -> Req + 'a {
    move |r: Req| r.signed(host, (key, key), 0)
}

/// CreateBucket and DeleteBucket, as `aws s3 mb` and `rb` send them: a bucket is made,
/// refused twice, and removed once its keys are deleted, however deep they were.
async fn buckets_are_made_and_removed(host: &str, sign: Sign<'_>) {
    let req = |method, path: &str| sign(Req::new(method, path));
    let resp = send(host, req("PUT", "/s3/made")).await;
    resp.ok(200);
    assert_eq!(resp.header("location"), Some("/s3/made"));
    send(host, req("HEAD", "/s3/made")).await.ok(200);
    send(host, req("PUT", "/s3/made"))
        .await
        .is(409, "BucketAlreadyOwnedByYou");

    // A configuration and a canned ACL are taken and ignored; object lock is not served.
    let config = "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                  <LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>";
    let configured = Req::new("PUT", "/s3/configured")
        .header("x-amz-acl", "private")
        .body(config.as_bytes().to_vec());
    send(host, sign(configured)).await.ok(200);
    for (path, body) in [
        ("/s3/large", vec![b' '; 1025]),
        ("/s3/garbled", b"<CreateBucketConfiguration>".to_vec()),
        ("/s3/other", b"<Delete/>".to_vec()),
    ] {
        let resp = send(host, sign(Req::new("PUT", path).body(body))).await;
        resp.is(400, "MalformedXML");
    }
    let locked = Req::new("PUT", "/s3/locked").header("x-amz-bucket-object-lock-enabled", "true");
    send(host, sign(locked)).await.is(501, "NotImplemented");
    for absent in ["/s3/large", "/s3/garbled", "/s3/other", "/s3/locked"] {
        send(host, req("HEAD", absent)).await.ok(404);
    }

    // Not empty while it holds a key; empty once they are deleted, the directories they were
    // in going with it.
    for path in ["/s3/made/a/b/k", "/s3/made/top"] {
        let put = Req::new("PUT", path).body(HELLO.to_vec());
        send(host, sign(put)).await.ok(200);
    }
    send(host, req("DELETE", "/s3/made"))
        .await
        .is(409, "BucketNotEmpty");
    send(host, req("DELETE", "/s3/made/top")).await.ok(204);
    send(host, req("DELETE", "/s3/made"))
        .await
        .is(409, "BucketNotEmpty");
    is_object(&send(host, req("GET", "/s3/made/a/b/k")).await, HELLO);
    send(host, req("DELETE", "/s3/made/a/b/k")).await.ok(204);
    send(host, req("DELETE", "/s3/made")).await.ok(204);
    send(host, req("HEAD", "/s3/made")).await.ok(404);
    send(host, req("DELETE", "/s3/made"))
        .await
        .is(404, "NoSuchBucket");
    send(host, req("DELETE", "/s3/configured")).await.ok(204);
    let resp = send(host, req("GET", "/s3/made/a/b/k")).await;
    resp.is(404, "NoSuchKey");
}

#[tokio::test]
async fn buckets_are_made_and_removed_on_an_open_server() {
    let dir = tmp("mb-open");
    let state = open_state(&dir, true);
    let store = state.store.clone();
    let host = spawn(state);
    buckets_are_made_and_removed(&host, &|r| r).await;

    // A bucket holding records a deleted object does not account for: an image's manifest
    // pushed over /v2/, its tag since deleted.
    store
        .put_manifest("files/rec", "v1", MANIFEST_TYPE, br#"{"schemaVersion":2}"#)
        .unwrap();
    send(&host, Req::new("DELETE", "/s3/rec"))
        .await
        .is(409, "BucketNotEmpty");
    store.delete_tag("files/rec", "v1").unwrap();
    let resp = send(&host, Req::new("DELETE", "/s3/rec")).await;
    resp.is(409, "BucketNotEmpty");
    assert!(resp.body.contains("/v2/"), "{}", resp.body);
    // The name taken in the store by something that is not a directory.
    std::fs::write(dir.join("store/repos/files/plain"), b"").unwrap();
    send(&host, Req::new("PUT", "/s3/plain"))
        .await
        .is(409, "OperationAborted");
    assert_eq!(staging_left(&dir), 0);
}

#[tokio::test]
async fn buckets_are_made_and_removed_with_an_api_key() {
    let dir = tmp("mb-accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let writer = api_key(db, "writer", &[(Action::Write, "files/*")]);
    let reader = api_key(db, "reader", &[(Action::Read, "files/*")]);
    let inside = api_key(db, "inside", &[(Action::Write, "files/made/sub/*")]);
    let host = spawn(state.clone());
    buckets_are_made_and_removed(&host, &as_key(&host, &writer)).await;

    // A bucket is made and removed by a key that may write the bucket itself.
    let (reader, inside) = (as_key(&host, &reader), as_key(&host, &inside));
    let body = vec![b'x'; 1 << 20];
    let resp = send(&host, reader(Req::new("PUT", "/s3/new").body(body))).await;
    resp.is(403, "AccessDenied");
    send(&host, inside(Req::new("PUT", "/s3/made")))
        .await
        .is(403, "AccessDenied");
    send(&host, as_key(&host, &writer)(Req::new("PUT", "/s3/made")))
        .await
        .ok(200);
    send(&host, reader(Req::new("DELETE", "/s3/made")))
        .await
        .is(403, "AccessDenied");
    send(&host, inside(Req::new("DELETE", "/s3/made")))
        .await
        .is(403, "AccessDenied");
    send(&host, reader(Req::new("HEAD", "/s3/made")))
        .await
        .ok(200);
}

/// A copy's `CopyObjectResult`: its `ETag` element, unescaped.
#[track_caller]
fn copied(resp: &Resp) -> String {
    resp.ok(200);
    assert!(
        resp.body.starts_with(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult \
             xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LastModified>"
        ),
        "{}",
        resp.body
    );
    assert!(element(&resp.body, "LastModified").ends_with(".000Z"));
    element(&resp.body, "ETag").replace("&quot;", "\"")
}

/// CopyObject within and across buckets: the bytes, ETag and metadata carried or replaced,
/// the source's four conditions and the destination's two, and what cannot be copied.
async fn objects_are_copied(host: &str, sign: Sign<'_>) -> Vec<u8> {
    let data = bytes_of_len(70_000);
    let etag = format!("\"{}\"", md5_hex(&data));
    let put = Req::new("PUT", "/s3/src/d/k")
        .header("x-amz-meta-mtime", "1700000000")
        .body(data.clone());
    send(host, sign(put)).await.ok(200);
    let copy = |to: &str, from: &str| Req::new("PUT", to).header("x-amz-copy-source", from);
    let got = async |path: &str| {
        let resp = send(host, sign(Req::new("GET", path))).await;
        is_object(&resp, &data);
        assert_eq!(resp.header("etag"), Some(&*etag));
        resp
    };

    // Within the bucket, then across buckets in the spellings clients send.
    let resp = send(host, sign(copy("/s3/src/e/copy", "/src/d/k"))).await;
    assert_eq!(copied(&resp), etag);
    let resp = got("/s3/src/e/copy").await;
    assert_eq!(resp.header("x-amz-meta-mtime"), Some("1700000000"));
    for (to, from) in [
        ("/s3/dst/copy", "src/d/k"),
        ("/s3/dst/escaped", "%2Fsrc%2Fd%2Fk"),
    ] {
        assert_eq!(copied(&send(host, sign(copy(to, from))).await), etag);
        let resp = got(to).await;
        assert_eq!(resp.header("x-amz-meta-mtime"), Some("1700000000"));
    }

    // REPLACE takes the request's metadata and keeps the bytes' MD5; onto itself, only so.
    let replace = |to: &str| {
        copy(to, "/src/d/k")
            .header("x-amz-metadata-directive", "REPLACE")
            .header("x-amz-meta-other", "x")
    };
    assert_eq!(
        copied(&send(host, sign(replace("/s3/dst/replaced"))).await),
        etag
    );
    let resp = got("/s3/dst/replaced").await;
    assert_eq!(resp.header("x-amz-meta-other"), Some("x"));
    assert_eq!(resp.header("x-amz-meta-mtime"), None);
    send(host, sign(copy("/s3/src/d/k", "/src/d/k")))
        .await
        .is(400, "InvalidRequest");
    let directive = copy("/s3/src/d/k", "/src/d/k").header("x-amz-metadata-directive", "COPY");
    send(host, sign(directive)).await.is(400, "InvalidRequest");
    assert_eq!(
        copied(&send(host, sign(replace("/s3/src/d/k"))).await),
        etag
    );
    let resp = got("/s3/src/d/k").await;
    assert_eq!(resp.header("x-amz-meta-other"), Some("x"));
    assert_eq!(resp.header("x-amz-meta-mtime"), None);
    let bad = copy("/s3/dst/x", "/src/d/k").header("x-amz-metadata-directive", "MOVE");
    send(host, sign(bad)).await.is(400, "InvalidArgument");

    // The source's conditions, each met and failed.
    let past = "Mon, 01 Jan 2001 00:00:00 GMT";
    let future = "Fri, 01 Jan 2100 00:00:00 GMT";
    for (name, met, failed) in [
        ("x-amz-copy-source-if-match", etag.as_str(), "\"other\""),
        (
            "x-amz-copy-source-if-none-match",
            "\"other\"",
            etag.as_str(),
        ),
        ("x-amz-copy-source-if-modified-since", past, future),
        ("x-amz-copy-source-if-unmodified-since", future, past),
    ] {
        let req = copy("/s3/dst/conditional", "/src/d/k").header(name, met);
        assert_eq!(copied(&send(host, sign(req)).await), etag, "{name}");
        let req = copy("/s3/dst/conditional", "/src/d/k").header(name, failed);
        send(host, sign(req)).await.is(412, "PreconditionFailed");
    }
    // The destination's: create only, or replace only what it names.
    let req = copy("/s3/dst/copy", "/src/d/k").header("If-None-Match", "*");
    send(host, sign(req)).await.is(412, "PreconditionFailed");
    let req = copy("/s3/dst/copy", "/src/d/k").header("If-Match", "\"other\"");
    send(host, sign(req)).await.is(412, "PreconditionFailed");
    let req = copy("/s3/dst/copy", "/src/d/k").header("If-Match", &etag);
    assert_eq!(copied(&send(host, sign(req)).await), etag);
    let req = copy("/s3/dst/fresh", "/src/d/k").header("If-None-Match", "*");
    assert_eq!(copied(&send(host, sign(req)).await), etag);

    // What names no object, or no place for one.
    for (to, from, status, code) in [
        ("/s3/dst/x", "/src/absent", 404, "NoSuchKey"),
        ("/s3/dst/x", "/src/d", 404, "NoSuchKey"),
        ("/s3/dst/x", "/nobucket/k", 404, "NoSuchBucket"),
        (
            "/s3/dst/x",
            "/src/d/k?versionId=null",
            501,
            "NotImplemented",
        ),
        ("/s3/dst/x", "/src", 400, "InvalidArgument"),
        ("/s3/dst/x", "/src/a%20b", 400, "InvalidArgument"),
        ("/s3/src/d", "/src/d/k", 409, "OperationAborted"),
        ("/s3/src/d/k/below", "/src/e/copy", 409, "OperationAborted"),
    ] {
        let resp = send(host, sign(copy(to, from))).await;
        resp.is(status, code);
    }
    send(host, sign(Req::new("GET", "/s3/dst/x")))
        .await
        .is(404, "NoSuchKey");
    data
}

/// A copy is a second tag on the same layer: `/v2/` names one digest for both.
async fn one_layer_two_tags(host: &str, data: &[u8], bearer: Option<&str>) {
    let layer = format!("sha256:{}", sha256_hex(data));
    for path in [
        "/v2/files/src/d/manifests/k",
        "/v2/files/dst/manifests/copy",
    ] {
        let mut req = Req::new("GET", path).header("Accept", MANIFEST_TYPE);
        if let Some(key) = bearer {
            req = req.header("Authorization", &format!("Bearer {key}"));
        }
        let resp = send(host, req).await;
        assert_eq!(resp.status, 200, "{path}: {}", resp.body);
        let manifest: serde_json::Value = serde_json::from_slice(&resp.bytes).unwrap();
        assert_eq!(manifest["layers"][0]["digest"], layer.as_str(), "{path}");
        assert_eq!(
            manifest["annotations"]["org.virtkit.md5"],
            md5_hex(data).as_str()
        );
    }
}

#[tokio::test]
async fn objects_are_copied_on_an_open_server() {
    let dir = tmp("copy-open");
    let host = spawn(open_state(&dir, true));
    let data = objects_are_copied(&host, &|r| r).await;
    one_layer_two_tags(&host, &data, None).await;
    let blobs = std::fs::read_dir(dir.join("store/repos/files/dst/blobs"))
        .unwrap()
        .count();
    assert_eq!(
        blobs, 2,
        "the destination holds the layer and the empty config"
    );
    assert_eq!(staging_left(&dir), 0);
}

#[tokio::test]
async fn objects_are_copied_with_an_api_key() {
    let dir = tmp("copy-accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let writer = api_key(db, "writer", &[(Action::Write, "files/*")]);
    let reader = api_key(db, "reader", &[(Action::Read, "files/*")]);
    let dst_reader = api_key(db, "dst-reader", &[(Action::Read, "files/dst/*")]);
    let blind = api_key(
        db,
        "blind",
        &[
            (Action::Write, "files/dst/*"),
            (Action::Read, "files/src/d/k/*"),
        ],
    );
    let host = spawn(state.clone());
    let data = objects_are_copied(&host, &as_key(&host, &writer)).await;
    one_layer_two_tags(&host, &data, Some(&writer)).await;

    let copy = |to: &str, from: &str| Req::new("PUT", to).header("x-amz-copy-source", from);
    // A key that may read the copy only, reads its bytes through the copy.
    let resp = send(
        &host,
        as_key(&host, &dst_reader)(Req::new("GET", "/s3/dst/copy")),
    )
    .await;
    is_object(&resp, &data);
    send(
        &host,
        as_key(&host, &dst_reader)(Req::new("GET", "/s3/src/d/k")),
    )
    .await
    .is(403, "AccessDenied");
    // A read-only key may not write the destination; a source the key may not read is absent.
    let resp = send(
        &host,
        as_key(&host, &reader)(copy("/s3/dst/new", "/src/d/k")),
    )
    .await;
    resp.is(403, "AccessDenied");
    let resp = send(
        &host,
        as_key(&host, &blind)(copy("/s3/dst/new", "/src/d/k")),
    )
    .await;
    resp.is(404, "NoSuchKey");
    let resp = send(
        &host,
        as_key(&host, &blind)(copy("/s3/dst/new", "/src/e/copy")),
    )
    .await;
    resp.is(403, "AccessDenied");
    send(
        &host,
        as_key(&host, &writer)(Req::new("GET", "/s3/dst/new")),
    )
    .await
    .is(404, "NoSuchKey");
}

/// A `Delete` document of `objects` (each an `<Object>`'s content), quiet when asked.
fn delete_doc(objects: &[&str], quiet: bool) -> Vec<u8> {
    let mut doc = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for o in objects {
        doc.push_str(&format!("<Object>{o}</Object>"));
    }
    if quiet {
        doc.push_str("<Quiet>true</Quiet>");
    }
    doc.push_str("</Delete>");
    doc.into_bytes()
}

fn key_of(k: &str) -> String {
    format!("<Key>{k}</Key>")
}

/// A `DeleteResult`: the keys deleted, and each error's key and code.
#[track_caller]
fn delete_result(resp: &Resp) -> (Vec<String>, Vec<(String, String)>) {
    resp.ok(200);
    assert!(
        resp.body.starts_with(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult \
             xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""
        ),
        "{}",
        resp.body
    );
    let deleted = elements(&resp.body, "Deleted")
        .iter()
        .map(|d| element(d, "Key"))
        .collect();
    let errors = elements(&resp.body, "Error")
        .iter()
        .map(|e| {
            assert_eq!(elements(e, "Message").len(), 1, "{e}");
            (element(e, "Key"), element(e, "Code"))
        })
        .collect();
    (deleted, errors)
}

/// The request deleting `doc` from `bucket`, with its `Content-MD5`.
fn delete_objects(bucket: &str, doc: Vec<u8>) -> Req {
    Req::new("POST", &format!("/s3/{bucket}"))
        .query("delete=")
        .header("Content-MD5", &b64(&md5::compute(&doc).0))
        .body(doc)
}

/// DeleteObjects with every outcome a key can have, verbose and quiet, and the documents and
/// digests that are refused whole.
async fn objects_are_deleted_in_batches(host: &str, sign: Sign<'_>, store: &Store) {
    for path in [
        "/s3/batch/a",
        "/s3/batch/d/b",
        "/s3/batch/c",
        "/s3/batch/kept",
    ] {
        let put = Req::new("PUT", path).body(HELLO.to_vec());
        send(host, sign(put)).await.ok(200);
    }
    store
        .put_manifest(
            "files/batch/img",
            "v1",
            MANIFEST_TYPE,
            br#"{"schemaVersion":2}"#,
        )
        .unwrap();
    let pair = |k: &str, code: &str| (k.to_string(), code.to_string());

    // A digest that does not hold, or a document that is none, deletes nothing.
    let doc = delete_doc(&[&key_of("kept")], false);
    let wrong = delete_objects("batch", doc.clone()).replace("Content-MD5", &b64(&[0; 16]));
    send(host, sign(wrong)).await.is(400, "BadDigest");
    let crc = Req::new("POST", "/s3/batch")
        .query("delete=")
        .header("x-amz-checksum-crc32", &b64(&[0; 4]))
        .body(doc.clone());
    send(host, sign(crc)).await.is(400, "BadDigest");
    let too_many: Vec<String> = (0..1001).map(|i| key_of(&format!("k{i}"))).collect();
    let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
    let mut over = delete_doc(&[&key_of("kept")], false);
    over.extend(std::iter::repeat_n(b' ', 1 << 20));
    for bad in [
        delete_doc(&too_many, false),
        delete_doc(&["<Key>&ent;</Key>"], false),
        delete_doc(&[], false),
        b"<?xml version=\"1.0\"?><!DOCTYPE d><Delete/>".to_vec(),
        over,
    ] {
        let resp = send_refused(host, sign(delete_objects("batch", bad))).await;
        resp.is(400, "MalformedXML");
    }
    is_object(
        &send(host, sign(Req::new("GET", "/s3/batch/kept"))).await,
        HELLO,
    );

    // Every outcome, in the order asked.
    let doc = delete_doc(
        &[
            &key_of("a"),
            &key_of("absent"),
            &key_of("a&amp;b"),
            &key_of("d"),
            &key_of("img/v1"),
            "<Key>c</Key><VersionId>null</VersionId>",
            &key_of("d/b"),
            &key_of("x/../y"),
        ],
        false,
    );
    let (deleted, errors) = delete_result(&send(host, sign(delete_objects("batch", doc))).await);
    assert_eq!(deleted, ["a", "absent", "d", "d/b"]);
    assert_eq!(
        errors,
        [
            pair("a&amp;b", "InvalidArgument"),
            pair("img/v1", "OperationAborted"),
            pair("c", "NotImplemented"),
            pair("x/../y", "InvalidArgument"),
        ]
    );
    for gone in ["/s3/batch/a", "/s3/batch/d/b"] {
        send(host, sign(Req::new("GET", gone)))
            .await
            .is(404, "NoSuchKey");
    }
    is_object(
        &send(host, sign(Req::new("GET", "/s3/batch/c"))).await,
        HELLO,
    );
    assert_eq!(
        store.has_manifests("files/batch/img", &["v1"]).unwrap(),
        [true]
    );

    // Quiet: only the errors.
    let doc = delete_doc(&[&key_of("c"), &key_of("img/v1")], true);
    let resp = send(host, sign(delete_objects("batch", doc))).await;
    let (deleted, errors) = delete_result(&resp);
    assert!(deleted.is_empty(), "{}", resp.body);
    assert_eq!(errors, [pair("img/v1", "OperationAborted")]);
    let doc = delete_doc(&[&key_of("kept")], true);
    let resp = send(host, sign(delete_objects("batch", doc))).await;
    assert!(
        resp.body.ends_with(
            "<DeleteResult \
         xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>"
        ),
        "{}",
        resp.body
    );
    // A correct checksum header, and none at all.
    send(
        host,
        sign(Req::new("PUT", "/s3/batch/c").body(HELLO.to_vec())),
    )
    .await
    .ok(200);
    let doc = delete_doc(&[&key_of("c")], false);
    let crc = Req::new("POST", "/s3/batch")
        .query("delete=")
        .header("x-amz-checksum-crc32", &crc32_b64(&doc))
        .body(doc.clone());
    assert_eq!(delete_result(&send(host, sign(crc)).await).0, ["c"]);
    let plain = Req::new("POST", "/s3/batch").query("delete=").body(doc);
    assert_eq!(delete_result(&send(host, sign(plain)).await).0, ["c"]);
    // A bucket that is not there holds none of the keys.
    let doc = delete_doc(&[&key_of("k")], false);
    let resp = send(host, sign(delete_objects("nobucket", doc))).await;
    assert_eq!(delete_result(&resp).0, ["k"]);
}

#[tokio::test]
async fn objects_are_deleted_in_batches_on_an_open_server() {
    let dir = tmp("batch-open");
    let state = open_state(&dir, true);
    let store = state.store.clone();
    let host = spawn(state);
    objects_are_deleted_in_batches(&host, &|r| r, &store).await;
    // The signed payload hash binds the document.
    let doc = delete_doc(&[&key_of("k")], false);
    let signed = |payload: &str| {
        delete_objects("batch", doc.clone()).signed_payload(&host, ("any", "any"), 0, payload)
    };
    assert_eq!(
        delete_result(&send(&host, signed(&sha256_hex(&doc))).await).0,
        ["k"]
    );
    send(&host, signed(&sha256_hex(b"another")))
        .await
        .is(400, "XAmzContentSHA256Mismatch");
    // The subresource as SDKs write it, with no `=`.
    let bare = Req::new("POST", "/s3/batch").query("delete").body(doc);
    assert_eq!(delete_result(&send(&host, bare).await).0, ["k"]);
    let resp = send(&host, Req::new("GET", "/s3/batch").query("versioning")).await;
    resp.ok(200);
}

#[tokio::test]
async fn objects_are_deleted_in_batches_with_an_api_key() {
    let dir = tmp("batch-accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let writer = api_key(db, "writer", &[(Action::Write, "files/*")]);
    let reader = api_key(db, "reader", &[(Action::Read, "files/*")]);
    let inside = api_key(db, "inside", &[(Action::Write, "files/batch/w/*")]);
    let host = spawn(state.clone());
    objects_are_deleted_in_batches(&host, &as_key(&host, &writer), &state.store).await;

    for path in ["/s3/batch/w/x", "/s3/batch/y"] {
        let put = Req::new("PUT", path).body(HELLO.to_vec());
        send(&host, as_key(&host, &writer)(put)).await.ok(200);
    }
    let doc = || delete_doc(&[&key_of("w/x"), &key_of("y")], false);
    // The keys a credential may not delete are reported, the others deleted.
    let resp = send(
        &host,
        as_key(&host, &reader)(delete_objects("batch", doc())),
    )
    .await;
    let (deleted, errors) = delete_result(&resp);
    assert!(deleted.is_empty());
    let codes: Vec<&str> = errors.iter().map(|(_, c)| c.as_str()).collect();
    assert_eq!(codes, ["AccessDenied", "AccessDenied"]);
    let resp = send(
        &host,
        as_key(&host, &inside)(delete_objects("batch", doc())),
    )
    .await;
    let (deleted, errors) = delete_result(&resp);
    assert_eq!(deleted, ["w/x"]);
    assert_eq!(errors, [("y".to_string(), "AccessDenied".to_string())]);
    let get = |path: &str| as_key(&host, &writer)(Req::new("GET", path));
    send(&host, get("/s3/batch/w/x")).await.is(404, "NoSuchKey");
    is_object(&send(&host, get("/s3/batch/y")).await, HELLO);
}

/// The configurations tools probe, on a bucket and an object that exist and on ones that do
/// not, and their writes refused.
async fn configurations_are_canned(host: &str, sign: Sign<'_>) {
    send(
        host,
        sign(Req::new("PUT", "/s3/conf/k").body(HELLO.to_vec())),
    )
    .await
    .ok(200);
    let get = |path: &str, q: &str| sign(Req::new("GET", path).query(&format!("{q}=")));
    let doc = |root: &str, inner: &str| {
        let open = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{root} \
             xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""
        );
        if inner.is_empty() {
            format!("{open}/>")
        } else {
            format!("{open}>{inner}</{root}>")
        }
    };
    for (q, root, inner) in [
        ("versioning", "VersioningConfiguration", ""),
        ("tagging", "Tagging", "<TagSet/>"),
        ("logging", "BucketLoggingStatus", ""),
        ("notification", "NotificationConfiguration", ""),
        (
            "requestPayment",
            "RequestPaymentConfiguration",
            "<Payer>BucketOwner</Payer>",
        ),
        ("accelerate", "AccelerateConfiguration", ""),
    ] {
        let resp = send(host, get("/s3/conf", q)).await;
        resp.ok(200);
        assert_eq!(resp.body, doc(root, inner), "{q}");
        send(host, get("/s3/none", q)).await.is(404, "NoSuchBucket");
    }
    for path in ["/s3/conf", "/s3/conf/k"] {
        let resp = send(host, get(path, "acl")).await;
        resp.ok(200);
        assert!(
            resp.body.contains(
                "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
             xsi:type=\"CanonicalUser\"><ID>vk-registry</ID><DisplayName>vk-registry\
             </DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>"
            ),
            "{}",
            resp.body
        );
        assert!(
            resp.body.contains(
                "<Owner><ID>vk-registry</ID><DisplayName>vk-registry</DisplayName></Owner>"
            )
        );
    }
    let resp = send(host, get("/s3/conf/k", "tagging")).await;
    resp.ok(200);
    assert_eq!(resp.body, doc("Tagging", "<TagSet/>"));
    for q in ["tagging", "acl"] {
        send(host, get("/s3/conf/absent", q))
            .await
            .is(404, "NoSuchKey");
    }
    for (q, code) in [
        ("lifecycle", "NoSuchLifecycleConfiguration"),
        ("policy", "NoSuchBucketPolicy"),
        ("policyStatus", "NoSuchBucketPolicy"),
        ("cors", "NoSuchCORSConfiguration"),
        (
            "encryption",
            "ServerSideEncryptionConfigurationNotFoundError",
        ),
        ("object-lock", "ObjectLockConfigurationNotFoundError"),
        ("replication", "ReplicationConfigurationNotFoundError"),
        ("website", "NoSuchWebsiteConfiguration"),
        ("publicAccessBlock", "NoSuchPublicAccessBlockConfiguration"),
        ("ownershipControls", "OwnershipControlsNotFoundError"),
    ] {
        send(host, get("/s3/conf", q)).await.is(404, code);
        send(host, get("/s3/none", q)).await.is(404, "NoSuchBucket");
    }
    // Nothing of it is written.
    for (method, path, q) in [
        ("PUT", "/s3/conf", "versioning"),
        ("PUT", "/s3/conf", "policy"),
        ("PUT", "/s3/conf", "acl"),
        ("DELETE", "/s3/conf", "tagging"),
        ("DELETE", "/s3/conf", "lifecycle"),
        ("PUT", "/s3/conf/k", "acl"),
        ("PUT", "/s3/conf/k", "tagging"),
        ("DELETE", "/s3/conf/k", "tagging"),
    ] {
        let req = Req::new(method, path)
            .query(&format!("{q}="))
            .body(b"<Tagging/>".to_vec());
        send(host, sign(req)).await.is(501, "NotImplemented");
    }
    is_object(
        &send(host, sign(Req::new("GET", "/s3/conf/k"))).await,
        HELLO,
    );
}

#[tokio::test]
async fn configurations_are_canned_on_an_open_server() {
    let dir = tmp("canned-open");
    let host = spawn(open_state(&dir, true));
    configurations_are_canned(&host, &|r| r).await;
}

#[tokio::test]
async fn configurations_are_canned_with_an_api_key() {
    let dir = tmp("canned-accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let writer = api_key(db, "writer", &[(Action::Write, "files/*")]);
    let other = api_key(db, "other", &[(Action::Read, "files/other/*")]);
    let host = spawn(state.clone());
    configurations_are_canned(&host, &as_key(&host, &writer)).await;
    // Read on neither the bucket nor anything in it: refused, as HeadBucket is.
    let other = as_key(&host, &other);
    send(
        &host,
        other(Req::new("GET", "/s3/conf").query("versioning=")),
    )
    .await
    .is(403, "AccessDenied");
    send(&host, other(Req::new("GET", "/s3/conf/k").query("acl=")))
        .await
        .is(403, "AccessDenied");
}

// ---- multipart uploads ----

/// `?uploadId=<id>` and, for a part, `partNumber=<n>` before it, as SigV4 sorts them.
fn part_query(id: &str, n: u32) -> String {
    format!("partNumber={n}&uploadId={id}")
}

/// A `CompleteMultipartUpload` document naming `parts` (number, ETag as sent).
fn complete_doc(parts: &[(u32, &str)]) -> Vec<u8> {
    let mut doc = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for (n, etag) in parts {
        doc.push_str(&format!(
            "<Part><ETag>{etag}</ETag><PartNumber>{n}</PartNumber></Part>"
        ));
    }
    doc.push_str("</CompleteMultipartUpload>");
    doc.into_bytes()
}

/// The ETag S3 gives an object made of `parts`: the MD5 of their MD5s, and their count.
fn multipart_etag(parts: &[&[u8]]) -> String {
    let md5s: Vec<u8> = parts.iter().flat_map(|p| md5::compute(p).0).collect();
    format!("\"{}-{}\"", md5_hex(&md5s), parts.len())
}

/// Start an upload of the object at `path`: its id.
async fn create_upload(host: &str, sign: Sign<'_>, path: &str) -> String {
    let resp = send(host, sign(Req::new("POST", path).query("uploads="))).await;
    resp.ok(200);
    element(&resp.body, "UploadId")
}

/// Send part `n` of upload `id` of `path`: its ETag.
async fn upload_part(
    host: &str,
    sign: Sign<'_>,
    path: &str,
    id: &str,
    n: u32,
    data: &[u8],
) -> String {
    let req = Req::new("PUT", path)
        .query(&part_query(id, n))
        .body(data.to_vec());
    let resp = send(host, sign(req)).await;
    resp.ok(200);
    let etag = format!("\"{}\"", md5_hex(data));
    assert_eq!(resp.header("etag"), Some(&*etag));
    etag
}

/// Complete upload `id` of `path` with `parts`.
fn complete(path: &str, id: &str, parts: &[(u32, &str)]) -> Req {
    Req::new("POST", path)
        .query(&format!("uploadId={id}"))
        .body(complete_doc(parts))
}

/// The S3 multipart uploads left in the store, by id.
fn multipart_left(dir: &std::path::Path) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(dir.join("store/uploads/s3"))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

/// An upload in three parts, as the AWS CLI sends a large file (the first part SigV4-signed
/// `aws-chunked`, the second with its `Content-MD5`, the last with its SHA-256 signed and an
/// `x-amz-checksum-sha256`), one part replaced, listed, refused when completed wrong, then
/// completed and read back as the object the parts make, under the multipart ETag; and what
/// becomes of the upload.
#[tokio::test]
async fn a_multipart_upload_is_assembled_from_its_parts() {
    let (dir, host) = bearer_server("multipart");
    let sign = |r: Req| r.signed(&host, BEARER, 0);
    send(&host, sign(Req::new("PUT", "/s3/b"))).await.ok(200);
    let path = "/s3/b/big/obj";
    let create = Req::new("POST", path)
        .query("uploads=")
        .header("x-amz-meta-mtime", "1700000000")
        .header("x-amz-checksum-algorithm", "sha256");
    let resp = send(&host, sign(create)).await;
    resp.ok(200);
    assert_eq!(element(&resp.body, "Bucket"), "b");
    assert_eq!(element(&resp.body, "Key"), "big/obj");
    assert_eq!(resp.header("x-amz-checksum-algorithm"), Some("SHA256"));
    let id = element(&resp.body, "UploadId");
    assert!(
        id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "{id}"
    );
    assert_eq!(multipart_left(&dir), std::slice::from_ref(&id));

    let listed = send(&host, sign(Req::new("GET", "/s3/b").query("uploads="))).await;
    listed.ok(200);
    assert_eq!(
        elements(&listed.body, "UploadId"),
        std::slice::from_ref(&id)
    );
    assert_eq!(keys(&listed.body), ["big/obj"]);
    assert!(element(&listed.body, "Initiated").ends_with(".000Z"));

    let one = bytes_of_len(5 << 20);
    let two: Vec<u8> = (0..5usize << 20).map(|i| (i * 13 % 241) as u8).collect();
    let three = bytes_of_len(1024);
    let query = part_query(&id, 1);
    let req =
        Req::new("PUT", path)
            .query(&query)
            .chunked(&host, BEARER, Chunked::Signed, &one, None);
    let resp = send(&host, req).await;
    resp.ok(200);
    let etag1 = format!("\"{}\"", md5_hex(&one));
    assert_eq!(resp.header("etag"), Some(&*etag1));
    // Part 2 sent wrong first, then replaced.
    let wrong = upload_part(&host, &sign, path, &id, 2, b"not this").await;
    let req = Req::new("PUT", path)
        .query(&part_query(&id, 2))
        .header("content-md5", &b64(&md5::compute(&two).0))
        .body(two.clone());
    let resp = send(&host, sign(req)).await;
    resp.ok(200);
    let etag2 = format!("\"{}\"", md5_hex(&two));
    assert_eq!(resp.header("etag"), Some(&*etag2));
    let sha = b64(&sha2::Sha256::digest(&three));
    let req = Req::new("PUT", path)
        .query(&part_query(&id, 3))
        .header("x-amz-checksum-sha256", &sha)
        .body(three.clone())
        .signed_payload(&host, BEARER, 0, &sha256_hex(&three));
    let resp = send(&host, req).await;
    resp.ok(200);
    assert_eq!(resp.header("x-amz-checksum-sha256"), Some(&*sha));
    let etag3 = format!("\"{}\"", md5_hex(&three));
    // A part whose digest does not hold is refused, and the part it would replace kept.
    let req = Req::new("PUT", path)
        .query(&part_query(&id, 3))
        .header("content-md5", &b64(&md5::compute(b"other").0))
        .body(three.clone());
    send(&host, sign(req)).await.is(400, "BadDigest");

    // The parts, two to a page.
    let page = |q: &str| sign(Req::new("GET", path).query(q));
    let resp = send(&host, page(&format!("max-parts=2&uploadId={id}"))).await;
    resp.ok(200);
    assert_eq!(elements(&resp.body, "PartNumber"), ["1", "2"]);
    assert_eq!(
        elements(&resp.body, "ETag"),
        [etag1.replace('"', "&quot;"), etag2.replace('"', "&quot;")]
    );
    assert_eq!(
        elements(&resp.body, "Size"),
        [(5 << 20).to_string(), (5 << 20).to_string()]
    );
    assert_eq!(element(&resp.body, "IsTruncated"), "true");
    assert_eq!(element(&resp.body, "NextPartNumberMarker"), "2");
    assert_eq!(element(&resp.body, "UploadId"), id);
    let resp = send(&host, page(&format!("part-number-marker=2&uploadId={id}"))).await;
    resp.ok(200);
    assert_eq!(elements(&resp.body, "PartNumber"), ["3"]);
    assert_eq!(element(&resp.body, "IsTruncated"), "false");

    // Completions that name the parts wrong leave the upload as it was.
    let (e1, e2, e3) = (etag1.as_str(), etag2.as_str(), etag3.as_str());
    for (parts, status, code) in [
        (vec![(2, e2), (1, e1), (3, e3)], 400, "InvalidPartOrder"),
        (vec![(1, e1), (1, e1)], 400, "InvalidPartOrder"),
        (
            vec![(1, e1), (2, wrong.as_str()), (3, e3)],
            400,
            "InvalidPart",
        ),
        (vec![(1, e1), (2, e2), (4, e3)], 400, "InvalidPart"),
        (vec![], 400, "MalformedXML"),
    ] {
        let resp = send(&host, sign(complete(path, &id, &parts))).await;
        resp.is(status, code);
    }
    let resp = send(
        &host,
        sign(complete(path, &id, &[(1, e1), (2, e2), (3, e3)])),
    )
    .await;
    resp.ok(200);
    let etag = multipart_etag(&[&one, &two, &three]);
    assert!(etag.ends_with("-3\""), "{etag}");
    assert_eq!(element(&resp.body, "ETag"), etag.replace('"', "&quot;"));
    assert_eq!(element(&resp.body, "Key"), "big/obj");
    // An absolute URL, as S3 answers: the scheme and host the request was sent to.
    assert_eq!(
        element(&resp.body, "Location"),
        format!("http://{host}{path}")
    );

    let whole = [one.as_slice(), &two, &three].concat();
    let resp = send(&host, sign(Req::new("GET", path))).await;
    is_object(&resp, &whole);
    assert_eq!(resp.header("etag"), Some(&*etag));
    assert_eq!(resp.header("x-amz-meta-mtime"), Some("1700000000"));
    let resp = send(&host, sign(Req::new("HEAD", path))).await;
    resp.ok(200);
    assert_eq!(resp.header("etag"), Some(&*etag));
    let resp = send(&host, sign(Req::new("GET", "/s3/b").query("list-type=2"))).await;
    resp.ok(200);
    assert_eq!(keys(&resp.body), ["big/obj"]);
    assert_eq!(element(&resp.body, "ETag"), etag.replace('"', "&quot;"));
    // Past 8 MiB, stored plain, as a PutObject of that size is.
    assert!(
        dir.join("store/blobs/sha256")
            .join(sha256_hex(&whole))
            .is_file()
    );

    // The upload is gone with its parts, and nothing is left staged.
    assert!(multipart_left(&dir).is_empty());
    assert_eq!(staging_left(&dir), 0);
    let listed = send(&host, sign(Req::new("GET", "/s3/b").query("uploads="))).await;
    listed.ok(200);
    assert!(
        elements(&listed.body, "Upload").is_empty(),
        "{}",
        listed.body
    );
    let req = Req::new("PUT", path)
        .query(&part_query(&id, 1))
        .body(b"late".to_vec());
    send(&host, sign(req)).await.is(404, "NoSuchUpload");
    send(&host, sign(complete(path, &id, &[(1, e1)])))
        .await
        .is(404, "NoSuchUpload");
}

/// A one-part upload, an aborted one, part copies, an upload's id used for another key, a
/// total past the object cap, and the gc's sweep of the uploads left idle.
#[tokio::test]
async fn multipart_uploads_are_aborted_copied_bounded_and_swept() {
    let (dir, host) = bearer_server("multipart-more");
    let sign = |r: Req| r.signed(&host, BEARER, 0);
    let path = "/s3/b/k";

    // One part.
    let id = create_upload(&host, &sign, path).await;
    let data = bytes_of_len(1024);
    let etag = upload_part(&host, &sign, path, &id, 1, &data).await;
    let resp = send(&host, sign(complete(path, &id, &[(1, &etag)]))).await;
    resp.ok(200);
    let whole = multipart_etag(&[&data]);
    assert!(whole.ends_with("-1\""), "{whole}");
    assert_eq!(element(&resp.body, "ETag"), whole.replace('"', "&quot;"));
    is_object(&send(&host, sign(Req::new("GET", path))).await, &data);

    // Aborted: gone, and gone again.
    let id = create_upload(&host, &sign, path).await;
    upload_part(&host, &sign, path, &id, 1, &data).await;
    let abort = || sign(Req::new("DELETE", path).query(&format!("uploadId={id}")));
    send(&host, abort()).await.ok(204);
    let list = Req::new("GET", path).query(&format!("uploadId={id}"));
    send(&host, sign(list)).await.is(404, "NoSuchUpload");
    send(&host, abort()).await.is(404, "NoSuchUpload");

    // An id names its own key's upload only, and an id this server cannot mint nothing.
    let id = create_upload(&host, &sign, path).await;
    for other in ["/s3/b/other", "/s3/c/k"] {
        let req = Req::new("PUT", other)
            .query(&part_query(&id, 1))
            .body(data.clone());
        send(&host, sign(req)).await.is(404, "NoSuchUpload");
    }
    for bad in ["..", "0-0-zz", "s3"] {
        let req = Req::new("PUT", path)
            .query(&part_query(bad, 1))
            .body(data.clone());
        send(&host, sign(req)).await.is(404, "NoSuchUpload");
    }
    for n in ["0", "10001", "x"] {
        let req = Req::new("PUT", path)
            .query(&format!("partNumber={n}&uploadId={id}"))
            .body(data.clone());
        send(&host, sign(req)).await.is(400, "InvalidArgument");
    }
    // A copy source on a creation is no part copy.
    let req = Req::new("POST", "/s3/b/x")
        .query("uploads=")
        .header("x-amz-copy-source", "/b/k");
    send(&host, sign(req)).await.is(400, "InvalidArgument");
    // Nor can an upload be made where no object can be.
    let req = Req::new("POST", "/s3/b/k/below").query("uploads=");
    send(&host, sign(req)).await.is(409, "OperationAborted");

    // Parts copied from an object: whole, then a range of it.
    let src = bytes_of_len(70_000);
    send(&host, sign(Req::new("PUT", "/s3/b/src").body(src.clone())))
        .await
        .ok(200);
    let copied = "/s3/b/copied";
    let id = create_upload(&host, &sign, copied).await;
    let copy = |n: u32| {
        Req::new("PUT", copied)
            .query(&part_query(&id, n))
            .header("x-amz-copy-source", "/b/src")
    };
    let resp = send(&host, sign(copy(1))).await;
    resp.ok(200);
    assert!(resp.body.contains("<CopyPartResult"), "{}", resp.body);
    let e1 = element(&resp.body, "ETag").replace("&quot;", "\"");
    assert_eq!(e1, format!("\"{}\"", md5_hex(&src)));
    let resp = send(
        &host,
        sign(copy(2).header("x-amz-copy-source-range", "bytes=100-1099")),
    )
    .await;
    resp.ok(200);
    let e2 = element(&resp.body, "ETag").replace("&quot;", "\"");
    assert_eq!(e2, format!("\"{}\"", md5_hex(&src[100..1100])));
    let past = copy(3).header("x-amz-copy-source-range", "bytes=69000-70000");
    send(&host, sign(past)).await.is(416, "InvalidRange");
    let backwards = copy(3).header("x-amz-copy-source-range", "bytes=5-2");
    send(&host, sign(backwards))
        .await
        .is(400, "InvalidArgument");
    let failed = copy(3).header("x-amz-copy-source-if-match", "\"other\"");
    send(&host, sign(failed))
        .await
        .is(412, "PreconditionFailed");
    let absent = Req::new("PUT", copied)
        .query(&part_query(&id, 3))
        .header("x-amz-copy-source", "/b/absent");
    send(&host, sign(absent)).await.is(404, "NoSuchKey");
    let resp = send(&host, sign(complete(copied, &id, &[(1, &e1), (2, &e2)]))).await;
    resp.ok(200);
    let both = [src.as_slice(), &src[100..1100]].concat();
    is_object(&send(&host, sign(Req::new("GET", copied))).await, &both);

    // A total past the object cap is refused, as the parts' records say before any is read.
    let id = create_upload(&host, &sign, "/s3/b/huge").await;
    let e1 = upload_part(&host, &sign, "/s3/b/huge", &id, 1, &data).await;
    let e2 = upload_part(&host, &sign, "/s3/b/huge", &id, 2, &data).await;
    let record = dir.join(format!("store/uploads/s3/{id}/part-1.json"));
    let swollen = format!("{{\"size\":{},\"md5\":\"{}\"}}", 4u64 << 30, md5_hex(&data));
    std::fs::write(&record, swollen).unwrap();
    let resp = send(
        &host,
        sign(complete("/s3/b/huge", &id, &[(1, &e1), (2, &e2)])),
    )
    .await;
    resp.is(413, "EntityTooLarge");
    send(&host, sign(Req::new("GET", "/s3/b/huge")))
        .await
        .is(404, "NoSuchKey");

    // The gc sweeps an upload nothing was written into for its grace window, and keeps one
    // a part was written into lately.
    let fresh = create_upload(&host, &sign, "/s3/b/fresh").await;
    let old = SystemTime::now() - Duration::from_secs(3 * 86_400);
    for id in multipart_left(&dir).iter().filter(|id| **id != fresh) {
        let up = dir.join(format!("store/uploads/s3/{id}"));
        for e in std::fs::read_dir(&up).unwrap() {
            std::fs::File::open(e.unwrap().path())
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        std::fs::File::open(&up).unwrap().set_modified(old).unwrap();
    }
    assert_eq!(multipart_left(&dir).len(), 3);
    let store = Store::new(dir.join("store")).unwrap();
    let day = Duration::from_secs(86_400);
    let report = store.gc(day * 30, day, false).unwrap();
    assert_eq!(report.uploads_dropped, 2);
    assert_eq!(multipart_left(&dir), std::slice::from_ref(&fresh));
    upload_part(&host, &sign, "/s3/b/fresh", &fresh, 1, &data).await;
    assert_eq!(staging_left(&dir), 0);
}

/// A key that may only read a directory can list its uploads and parts, and can neither
/// start an upload there nor send a part to one.
#[tokio::test]
async fn a_read_only_key_cannot_upload_parts() {
    let dir = tmp("multipart-accounts");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let writer = api_key(db, "writer", &[(Action::Write, "files/*")]);
    let reader = api_key(db, "reader", &[(Action::Read, "files/*")]);
    let host = spawn(state.clone());
    let (writer, reader) = (as_key(&host, &writer), as_key(&host, &reader));
    send(&host, writer(Req::new("PUT", "/s3/b"))).await.ok(200);
    let path = "/s3/b/d/k";
    let id = create_upload(&host, &writer, path).await;
    let data = bytes_of_len(1024);
    let etag = upload_part(&host, &writer, path, &id, 1, &data).await;

    let body = vec![b'x'; 1 << 20];
    let req = Req::new("PUT", path).query(&part_query(&id, 2)).body(body);
    send(&host, reader(req)).await.is(403, "AccessDenied");
    let req = Req::new("POST", "/s3/b/d/other").query("uploads=");
    send(&host, reader(req)).await.is(403, "AccessDenied");
    send(&host, reader(complete(path, &id, &[(1, &etag)])))
        .await
        .is(403, "AccessDenied");
    let abort = Req::new("DELETE", path).query(&format!("uploadId={id}"));
    send(&host, reader(abort)).await.is(403, "AccessDenied");
    let resp = send(
        &host,
        reader(Req::new("GET", path).query(&format!("uploadId={id}"))),
    )
    .await;
    resp.ok(200);
    assert_eq!(elements(&resp.body, "PartNumber"), ["1"]);
    let resp = send(&host, reader(Req::new("GET", "/s3/b").query("uploads="))).await;
    resp.ok(200);
    assert_eq!(elements(&resp.body, "UploadId"), std::slice::from_ref(&id));

    send(&host, writer(complete(path, &id, &[(1, &etag)])))
        .await
        .ok(200);
    is_object(&send(&host, reader(Req::new("GET", path))).await, &data);
    assert!(multipart_left(&dir).is_empty());
    assert_eq!(staging_left(&dir), 0);
}
