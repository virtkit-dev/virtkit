//! Per-VM credential-injecting registry proxy.
//!
//! When enabled (per-VM `vk run --registry-proxy`, or runner-wide `[registry] proxy_guests`
//! for the executor), `vk` runs this HTTP reverse proxy on the host loopback and forwards
//! the guest to it (the switch redirects a sentinel address — `registry.vk` — to it; see
//! switch.rs). The guest's registry client talks plain, credential-free HTTP to it; the
//! proxy adds the runner's registry credential on the way to the real (central) registry.
//! So the job never holds the secret, and the proxy is never exposed on a network
//! interface — only reachable through the switch's per-VM redirect.
//!
//! Bodies stream both ways (`bytes_stream`), so pushing/pulling multi-GB layers through
//! the proxy never buffers a whole blob in memory, and no response has a deadline: a lock
//! acquire long-polls for as long as the registry holds it.
//!
//! What the proxy lends decides what it forwards ([`Scope`]). The node's own credential is
//! not scoped, so it reaches the OCI API only (`/v2/`). A job's registry token, which the hub
//! scoped to the job's namespaces (`[registry] guest_credential = "job"`), also reaches the
//! lock API (`/lock/`) and plain files (`/dav/files/`): the registry enforces the token's
//! grants on each. A job meant to have a token and given none gets a proxy that forwards
//! nothing.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::oci::Creds;

/// The streaming response body the proxy returns.
type ProxyBody = BoxBody<Bytes, std::io::Error>;

/// The name the guest reaches the proxy at.
pub const GUEST_HOST: &str = "registry.vk";

/// The plain files' path, and the methods forwarded under it: vk-registry's for `/dav/files/`.
const DAV_FILES: &str = "/dav/files/";
const DAV_FILES_METHODS: &[&str] = &[
    "GET", "HEAD", "PROPFIND", "PUT", "MKCOL", "DELETE", "OPTIONS",
];

/// Which of the registry's paths the proxy forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The OCI API only, `/v2/`: what an unscoped credential may be lent for.
    Oci,
    /// `/v2/`, `/lock/` and `/dav/files/`: a job token's, whose grants the registry enforces.
    Job,
    /// Nothing: a job that should have had a token and has none.
    Deny,
}

impl Scope {
    /// The path prefixes forwarded, below the upstream's own path.
    fn paths(self) -> &'static [&'static str] {
        match self {
            Scope::Oci => &["/v2/"],
            Scope::Job => &["/v2/", "/lock/", DAV_FILES],
            Scope::Deny => &[],
        }
    }
}

/// What the proxy forwards to and injects.
pub struct ProxyCfg {
    /// The upstream's base URL, optionally with a path prefix (no trailing slash).
    upstream: String,
    /// The parsed upstream, whose origin every forwarded request must keep
    base: reqwest::Url,
    /// `base`'s path, without a trailing `/`: what every forwarded path starts with, before
    /// one of the scope's paths
    root: String,
    scope: Scope,
    /// The credential injected into every forwarded request, so the job stays
    /// credential-free — and the trust anchor `client` was built against.
    pub creds: Creds,
    pub client: reqwest::Client,
}

impl ProxyCfg {
    /// Build from the `vk run --registry-proxy` flags: `upstream` is the base URL,
    /// optionally with a path prefix, `creds` both what to inject and what TLS to trust.
    pub fn from_parts(upstream: &str, creds: Creds) -> Result<Self> {
        Self::build(upstream.trim_end_matches('/').to_string(), creds)
    }

    /// Build from the runner's `[registry]` config (the executor path): the central
    /// registry's base URL, and the credential every other `[registry]` client resolves —
    /// a bearer token when one is configured, else the Basic pair.
    pub fn from_registry(rg: &crate::config::Registry) -> Result<Self> {
        Self::build(Self::upstream_of(rg)?, Creds::from_registry(rg)?)
    }

    fn upstream_of(rg: &crate::config::Registry) -> Result<String> {
        Ok(rg
            .base_url()
            .context("the registry proxy needs a remote [registry]")?
            .0)
    }

    /// Build for a placed job under `[registry] guest_credential = "job"`: the runner's
    /// `[registry]` as upstream and trust anchor, injecting the job's `token` and nothing of
    /// the section's own credential; with no token, a proxy that forwards nothing.
    pub fn for_job(rg: &crate::config::Registry, token: Option<&str>) -> Result<Self> {
        // Built field by field, so no credential the section holds, now or later, is lent.
        let creds = Creds {
            username: None,
            password: None,
            token: token.map(str::to_string),
            ca_pem: None,
            insecure: rg.insecure,
        }
        .with_ca_file(rg.ca_file.as_deref())?;
        let mut cfg = Self::build(Self::upstream_of(rg)?, creds)?;
        cfg.scope = match token {
            Some(_) => Scope::Job,
            None => Scope::Deny,
        };
        Ok(cfg)
    }

    fn build(upstream: String, creds: Creds) -> Result<Self> {
        let base = reqwest::Url::parse(&upstream)
            .with_context(|| format!("parsing the registry proxy upstream {upstream:?}"))?;
        anyhow::ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.has_host()
                && base.query().is_none()
                && base.fragment().is_none(),
            "the registry proxy upstream {upstream:?} is not an http(s) URL"
        );
        // `--insecure` means plain HTTP on every OCI path, never "accept any certificate":
        // that would hand the injected credential to whoever can terminate the TLS link. A
        // private CA goes through `--ca`.
        if creds.insecure && base.scheme() == "https" {
            bail!(
                "--registry-proxy {upstream} with --insecure: --insecure means a plain HTTP \
                 registry, so give an http:// upstream, or --ca for a TLS one signed by a \
                 private CA"
            );
        }
        let root = base.path().trim_end_matches('/').to_string();
        let mut b = reqwest::Client::builder();
        if let Some(pem) = &creds.ca_pem {
            b = b.add_root_certificate(
                reqwest::Certificate::from_pem(pem).context("parsing the registry CA")?,
            );
        }
        Ok(ProxyCfg {
            upstream,
            base,
            root,
            scope: Scope::Oci,
            creds,
            client: b.build().context("building the registry proxy client")?,
        })
    }
}

/// Bind an ephemeral loopback port and serve the proxy on the current runtime, returning
/// the bound address (handed to the switch as the redirect target).
pub async fn spawn(cfg: ProxyCfg) -> Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("binding the registry proxy")?;
    let addr = listener.local_addr()?;
    tokio::spawn(serve_on(listener, Arc::new(cfg)));
    Ok(addr)
}

/// Like [`spawn`], but from a synchronous context (the executor's `spawn_switch`): binds
/// synchronously and serves on a dedicated thread + runtime for the process's lifetime.
pub fn spawn_blocking(cfg: ProxyCfg) -> Result<SocketAddr> {
    // A loopback TCP port: any process on the host can use the credential through it, as it
    // could the node's own. A 0600 unix socket would confine it to this user.
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).context("binding the registry proxy")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building the registry proxy runtime");
        rt.block_on(async move {
            match TcpListener::from_std(listener) {
                Ok(l) => serve_on(l, Arc::new(cfg)).await,
                Err(e) => eprintln!("registry proxy: adopting the listener: {e}"),
            }
        });
    });
    Ok(addr)
}

async fn serve_on(listener: TcpListener, cfg: Arc<ProxyCfg>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, cfg.clone()));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    cfg: Arc<ProxyCfg>,
) -> Result<Response<ProxyBody>, Infallible> {
    Ok(forward(req, &cfg).await.unwrap_or_else(|e| {
        // Keep the detail host-side; the guest is untrusted and must not learn the
        // upstream URL / internal error chain.
        eprintln!("virtkit: registry proxy: {e:#}");
        let body = Full::new(Bytes::from_static(b"registry proxy: upstream error"))
            .map_err(|never| match never {})
            .boxed();
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(body)
            .expect("building the proxy error response")
    }))
}

/// The upstream URL a guest's request target names, or `None` when, once resolved, it is not
/// under one of the scope's paths below the upstream's own. Checked after resolving, not on
/// the text: the URL parser resolves `..` and its percent-encoded spellings (`%2e%2e`), so
/// `/v2/../lock/acquire` starts with `/v2/` and still reaches `/lock/acquire`, carrying the
/// credential.
fn upstream_url(cfg: &ProxyCfg, path_and_query: &str) -> Option<reqwest::Url> {
    let scoped = |p: &str| {
        cfg.scope
            .paths()
            .iter()
            .find(|s| p.starts_with(*s))
            .copied()
    };
    let prefix = scoped(path_and_query)?;
    // An encoded separator stays encoded through the parser, so `/v2/..%2Flock` passes the
    // check below — and reaches `/lock` through a front proxy that decodes `%2F`/`%5C` once
    // before normalizing. No repository or reference has one, so the path may not carry it.
    // A raw `\` is already read as `/` for http(s) and caught below; refusing it here too is
    // belt-and-braces for a front proxy that sees the text before that.
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(p, _)| p);
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || path.contains('\\') {
        return None;
    }
    let url = reqwest::Url::parse(&format!("{}{path_and_query}", cfg.upstream)).ok()?;
    let resolved = url.path().strip_prefix(cfg.root.as_str())?;
    (url.origin() == cfg.base.origin() && resolved.starts_with(prefix)).then_some(url)
}

/// Headers that must not be copied across the proxy (connection-scoped, credential-bearing,
/// or ones we set ourselves).
fn is_skipped(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "authorization"
            | "proxy-authorization"
            | "cookie"
            | "content-length"
            | "connection"
            | "transfer-encoding"
    )
}

async fn forward(req: Request<Incoming>, cfg: &ProxyCfg) -> Result<Response<ProxyBody>> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    // The proxy signs requests with a credential, so confine it to the paths its scope lends
    // that credential for: the OCI distribution API surface (`/v2/…`) for the host's own,
    // the lock API and plain files too for a job's token. A guest-chosen path outside them —
    // a foreign authority smuggled via `//host`, or the `/lock/` control plane under the
    // host's credential — is refused rather than authenticated on the guest's behalf.
    let Some(url) = upstream_url(cfg, &path_and_query) else {
        let body = Full::new(Bytes::from_static(match cfg.scope {
            Scope::Oci => b"registry proxy: only /v2/ registry paths are proxied",
            Scope::Job => b"registry proxy: only /v2/, /lock/ and /dav/files/ are proxied",
            Scope::Deny => b"registry proxy: this job has no registry credential",
        }))
        .map_err(|never| match never {})
        .boxed();
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(body)?);
    };
    let method = req.method().clone();
    // Plain files take the verbs vk-registry serves there, and no MOVE or COPY, whose
    // `Destination` names the proxy rather than the registry.
    if path_and_query.starts_with(DAV_FILES) && !DAV_FILES_METHODS.contains(&method.as_str()) {
        let body = Full::new(Bytes::from_static(
            b"registry proxy: this method is not proxied under /dav/files/",
        ))
        .map_err(|never| match never {})
        .boxed();
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(body)?);
    }
    // OCI writes and WebDAV PROPFIND always stream a body upstream, even when empty.
    // Forward other bodies for the registry to validate: dropping a MKCOL body
    // would create the collection instead of rejecting the request (RFC 4918 §9.3).
    let (parts, incoming) = req.into_parts();
    let bodyful = matches!(method, Method::POST | Method::PUT | Method::PATCH)
        || method.as_str() == "PROPFIND"
        || !hyper::body::Body::is_end_stream(&incoming);

    let mut rb = cfg.client.request(method, url);
    for (k, v) in parts.headers.iter() {
        if !is_skipped(&k.as_str().to_ascii_lowercase()) {
            rb = rb.header(k, v);
        }
    }
    rb = cfg.creds.apply(rb);
    if bodyful {
        // stream the guest's request body upstream without buffering (blob uploads).
        let stream = incoming
            .into_data_stream()
            .map_err(|e| std::io::Error::other(e.to_string()));
        rb = rb.body(reqwest::Body::wrap_stream(stream));
    }

    let resp = rb
        .send()
        .await
        .context("forwarding to the upstream registry")?;
    let status = resp.status();
    let headers = resp.headers().clone();
    // stream the upstream response back without buffering (blob pulls).
    let body = StreamBody::new(
        resp.bytes_stream()
            .map_ok(Frame::data)
            .map_err(|e| std::io::Error::other(e.to_string())),
    )
    .boxed();

    let mut out = Response::builder().status(status);
    for (k, v) in headers.iter() {
        if !is_skipped(&k.as_str().to_ascii_lowercase()) {
            out = out.header(k, v);
        }
    }
    out.body(body).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fake upstream that records the Authorization header + path of the last request
    // and replies 200 with a marker body. It runs on its own dedicated thread + runtime
    // (like the proxy's `spawn_blocking` and the vk-registry e2e servers) so its accept
    // loop never competes with the test's runtime threads — which caused acceptance stalls
    // and flakes when many of these servers ran concurrently under `cargo test`.
    fn fake_upstream() -> (SocketAddr, Arc<std::sync::Mutex<(String, String)>>) {
        let seen = Arc::new(std::sync::Mutex::new((String::new(), String::new())));
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let s = seen.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let s = s.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let s = s.clone();
                            async move {
                                let auth = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let path = req.uri().path().to_string();
                                *s.lock().unwrap() = (auth, path);
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"ok",
                                ))))
                            }
                        });
                        let _ = http1::Builder::new().serve_connection(io, svc).await;
                    });
                }
            });
        });
        (addr, seen)
    }

    /// A proxy to the upstream at `up_addr` that injects the Basic pair `robot:s3cret`.
    fn basic_cfg(up_addr: SocketAddr) -> ProxyCfg {
        ProxyCfg::build(
            format!("http://{up_addr}"),
            Creds {
                username: Some("robot".to_string()),
                password: Some("s3cret".to_string()),
                ..Creds::anonymous()
            },
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn injects_basic_auth_and_forwards_path() {
        // reqwest (rustls-no-provider) needs a crypto provider before a client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();

        // the "guest" hits the proxy with NO credentials.
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/manifests/latest"))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
        assert_eq!(r.text().await.unwrap(), "ok");

        let (auth, path) = seen.lock().unwrap().clone();
        assert_eq!(
            path, "/v2/app/manifests/latest",
            "path must be forwarded as resolved"
        );
        // Basic base64("robot:s3cret") = cm9ib3Q6czNjcmV0
        assert_eq!(
            auth, "Basic cm9ib3Q6czNjcmV0",
            "the proxy must inject Basic auth"
        );
    }

    /// A `[registry]` gated by a bearer token — a vk-registry in `mode = "accounts"`, whose
    /// API keys are exactly that — is what the proxy has to lend the guest. It used to
    /// inject nothing at all for one, since it only ever knew about the Basic pair.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn injects_a_bearer_token_ahead_of_the_basic_pair() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::build(
            format!("http://{up_addr}"),
            Creds {
                // Both set: the token wins, as it does on every other client path.
                username: Some("robot".to_string()),
                password: Some("s3cret".to_string()),
                token: Some("vkr_x".to_string()),
                ..Creds::anonymous()
            },
        )
        .unwrap();
        let proxy = spawn_blocking(cfg).unwrap();

        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/manifests/latest"))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());

        let (auth, _) = seen.lock().unwrap().clone();
        assert_eq!(
            auth, "Bearer vkr_x",
            "the proxy must inject the bearer token"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_paths_outside_v2() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();

        // a path outside /v2/ (here the lock control plane) is refused with 403 and never
        // reaches the upstream — the host credential is never lent to it.
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/lock/acquire?name=x"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 403);
        assert_eq!(
            seen.lock().unwrap().0,
            "",
            "a non-/v2/ request must not be forwarded upstream"
        );
    }

    fn registry(up_addr: SocketAddr) -> crate::config::Registry {
        crate::config::Registry {
            repo: format!("{up_addr}/team"),
            username: "robot".into(),
            password_file: Some("/nonexistent/password".into()),
            insecure: true,
            ..crate::config::Registry::for_share(
                String::new(),
                true,
                None,
                String::new(),
                None,
                None,
                None,
            )
        }
    }

    async fn status_and_auth(
        proxy: SocketAddr,
        method: &str,
        target: &str,
        seen: &std::sync::Mutex<(String, String)>,
    ) -> (u16, String, String) {
        *seen.lock().unwrap() = (String::new(), String::new());
        let r = reqwest::Client::new()
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("http://{proxy}{target}"),
            )
            .header("authorization", "Bearer guest-forged")
            .send()
            .await
            .unwrap();
        let (auth, path) = seen.lock().unwrap().clone();
        (r.status().as_u16(), auth, path)
    }

    /// A job's token reaches the lock API and plain files as well as `/v2/`, injected in
    /// place of whatever the guest sent; the section's own credential is never read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_token_reaches_locks_and_files_too() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap();
        assert_eq!(cfg.scope, Scope::Job);
        let proxy = spawn_blocking(cfg).unwrap();
        for (method, target) in [
            ("GET", "/v2/p/gl/42/app/manifests/latest"),
            ("POST", "/lock/acquire?name=p/gl/42:k"),
            ("PROPFIND", "/dav/files/p/gl/42/x"),
            ("PUT", "/dav/files/p/gl/42/x"),
        ] {
            let (status, auth, path) = status_and_auth(proxy, method, target, &seen).await;
            assert_eq!(status, 200, "{method} {target}");
            assert_eq!(auth, "Bearer vkt_job", "{method} {target}");
            assert_eq!(path, target.split('?').next().unwrap());
        }
        for target in [
            "/dav/repos/p",
            "/settings/keys",
            "/dav/files/../../settings/keys",
            "/dav/files/%2e%2e/%2e%2e/browse",
        ] {
            let (status, _, path) = status_and_auth(proxy, "GET", target, &seen).await;
            assert_eq!(status, 403, "{target}");
            assert_eq!(path, "", "{target} must not be forwarded");
        }
    }

    /// A job meant to have a token and given none gets a proxy that lends nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_without_a_token_gets_nothing() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::for_job(&registry(up_addr), None).unwrap();
        assert_eq!(cfg.scope, Scope::Deny);
        let proxy = spawn_blocking(cfg).unwrap();
        let (status, _, path) =
            status_and_auth(proxy, "GET", "/v2/app/manifests/latest", &seen).await;
        assert_eq!(status, 403);
        assert_eq!(path, "");
    }

    #[test]
    fn a_target_is_checked_once_resolved() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = |up: &str| ProxyCfg::build(up.to_string(), Creds::anonymous()).unwrap();
        let up = cfg("http://reg.example:5000");
        let ok = |t: &str| upstream_url(&up, t).map(|u| u.to_string());
        assert_eq!(
            ok("/v2/app/manifests/latest").as_deref(),
            Some("http://reg.example:5000/v2/app/manifests/latest")
        );
        for escape in [
            "/v2/../lock/acquire?name=x",
            "/v2/%2e%2e/lock/acquire",
            "/v2/.%2E/lock/acquire",
            "/v2/a/../../lock/release",
            "/v2/..%2Flock/acquire",
            "/v2/..%2flock/acquire",
            "/v2/..%5Clock/acquire",
            "/v2/..\\lock/acquire",
            "//evil.example/v2/x",
            "/lock/acquire",
        ] {
            assert_eq!(ok(escape), None, "{escape}");
        }
        // An upstream mounted under a prefix keeps the guest beneath that prefix's /v2/.
        let reg = cfg("https://h.example/reg");
        let prefixed = |t: &str| upstream_url(&reg, t);
        assert!(prefixed("/v2/app/tags/list").is_some());
        assert!(prefixed("/v2/../admin").is_none());
        // The node's credential reaches neither the locks nor the files.
        assert_eq!(ok("/dav/files/x"), None);
        // A job token's paths are checked once resolved as well, each against its own.
        let mut job = cfg("http://reg.example:5000");
        job.scope = Scope::Job;
        let ok = |t: &str| upstream_url(&job, t).map(|u| u.to_string());
        for fine in [
            "/lock/acquire?name=p:k",
            "/dav/files/p/x",
            "/v2/p/tags/list",
        ] {
            assert!(ok(fine).is_some(), "{fine}");
        }
        for escape in [
            "/lock/../settings",
            "/dav/files/..%2fx",
            "/v2/../dav/repos/x",
            "/dav/files/../../x",
            "/dav/files/../repos/x",
            "/lock/%2e%2e/browse",
        ] {
            assert_eq!(ok(escape), None, "{escape}");
        }
    }

    #[test]
    fn a_bad_upstream_fails_at_construction() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for bad in [
            "reg.example:5000",
            "ftp://reg.example",
            "unix:/run/reg.sock",
            "http://reg.example/reg?x=1",
            "http://reg.example/reg#x",
        ] {
            assert!(
                ProxyCfg::build(bad.to_string(), Creds::anonymous()).is_err(),
                "{bad}"
            );
        }
    }

    /// Send the guest's raw request target without client-side normalization.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_target_that_resolves_outside_v2() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
        for target in [
            "/v2/../lock/acquire?name=x",
            "/v2/%2e%2e/lock/acquire?name=x",
        ] {
            let mut conn = tokio::net::TcpStream::connect(proxy).await.unwrap();
            conn.write_all(
                format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let mut reply = Vec::new();
            conn.read_to_end(&mut reply).await.unwrap();
            assert!(
                reply.starts_with(b"HTTP/1.1 403"),
                "{target}: {:?}",
                String::from_utf8_lossy(&reply)
            );
        }
        assert_eq!(
            seen.lock().unwrap().0,
            "",
            "a target resolving outside /v2/ must not be forwarded upstream"
        );
    }

    /// Raw request targets cannot escape their scope through URL resolution.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_token_refuses_a_raw_target_resolving_elsewhere() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let proxy = spawn_blocking(ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap())
            .unwrap();
        for target in [
            "/lock/../settings/keys",
            "/dav/files/../../browse",
            "/dav/files/%2e%2e/%2e%2e/browse",
            "/v2/../dav/repos/x",
        ] {
            let mut conn = tokio::net::TcpStream::connect(proxy).await.unwrap();
            conn.write_all(
                format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let mut reply = Vec::new();
            conn.read_to_end(&mut reply).await.unwrap();
            assert!(
                reply.starts_with(b"HTTP/1.1 403"),
                "{target}: {:?}",
                String::from_utf8_lossy(&reply)
            );
        }
        assert_eq!(seen.lock().unwrap().0, "", "nothing forwarded");
    }

    /// Under /dav/files/ only the verbs the registry serves there pass, and a PROPFIND's or a
    /// MKCOL's body reaches the registry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_files_take_the_registrys_verbs_and_their_bodies() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = body_upstream();
        let proxy = spawn_blocking(ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap())
            .unwrap();
        let client = reqwest::Client::new();
        for method in ["MOVE", "COPY", "PROPPATCH", "LOCK", "POST"] {
            let r = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{proxy}/dav/files/p/x"),
                )
                .header("destination", "http://registry.vk/dav/files/p/y")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 405, "{method}");
        }
        assert_eq!(*seen.lock().unwrap(), Vec::<u8>::new(), "nothing forwarded");
        let r = client
            .request(
                reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
                format!("http://{proxy}/dav/files/p/x"),
            )
            .header("depth", "1")
            .body("<propfind/>")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(*seen.lock().unwrap(), b"<propfind/>".to_vec());
        let r = client
            .request(
                reqwest::Method::from_bytes(b"MKCOL").unwrap(),
                format!("http://{proxy}/dav/files/p/x"),
            )
            .body("<mkcol/>")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(*seen.lock().unwrap(), b"<mkcol/>".to_vec());
    }

    /// An upstream that records the body of the last request it took.
    fn body_upstream() -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let s = seen.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                while let Ok((stream, _)) = listener.accept().await {
                    let s = s.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let s = s.clone();
                            async move {
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                *s.lock().unwrap() = body.to_vec();
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"ok",
                                ))))
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
        });
        (addr, seen)
    }

    /// `--insecure` is plain HTTP, as everywhere else: it never turns certificate checks off.
    #[test]
    fn insecure_is_plain_http_and_never_unverified_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let insecure = Creds {
            insecure: true,
            ..Creds::anonymous()
        };
        for upstream in ["https://reg.example", "HTTPS://reg.example"] {
            let err = ProxyCfg::from_parts(upstream, insecure.clone())
                .err()
                .expect("an https upstream with --insecure is refused")
                .to_string();
            assert!(err.contains("--ca"), "{upstream}: {err}");
        }
        assert!(ProxyCfg::from_parts("http://reg.example:5000", insecure).is_ok());
    }
}
