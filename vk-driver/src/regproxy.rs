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
//! the proxy never buffers a whole blob in memory.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
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

/// What the proxy forwards to and injects.
pub struct ProxyCfg {
    /// upstream base URL, `scheme://authority` (no trailing slash)
    pub upstream: String,
    /// The credential injected into every forwarded request, so the job stays
    /// credential-free — and the trust anchor `client` was built against.
    pub creds: Creds,
    pub client: reqwest::Client,
}

impl ProxyCfg {
    /// Build from the `vk run --registry-proxy` flags: `upstream` is the full base URL
    /// (`scheme://host`), `creds` both what to inject and what TLS to trust.
    pub fn from_parts(upstream: &str, creds: Creds) -> Result<Self> {
        Self::build(upstream.trim_end_matches('/').to_string(), creds)
    }

    /// Build from the runner's `[registry]` config (the executor path): the central
    /// registry's base URL, and the credential every other `[registry]` client resolves —
    /// a bearer token when one is configured, else the Basic pair.
    pub fn from_registry(rg: &crate::config::Registry) -> Result<Self> {
        let repo = rg
            .repo
            .strip_prefix("http://")
            .or_else(|| rg.repo.strip_prefix("https://"))
            .unwrap_or(&rg.repo);
        let authority = repo.split('/').next().unwrap_or(repo);
        let scheme = if rg.insecure { "http" } else { "https" };
        Self::build(format!("{scheme}://{authority}"), Creds::from_registry(rg)?)
    }

    fn build(upstream: String, creds: Creds) -> Result<Self> {
        let mut b = reqwest::Client::builder();
        if let Some(pem) = &creds.ca_pem {
            b = b.add_root_certificate(
                reqwest::Certificate::from_pem(pem).context("parsing the registry CA")?,
            );
        }
        if creds.insecure {
            // match the other OCI paths' `--insecure`: accept the upstream's cert as-is.
            b = b.danger_accept_invalid_certs(true);
        }
        Ok(ProxyCfg {
            upstream,
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
    // The proxy signs requests with the host's registry credential, so confine it to the
    // OCI distribution API surface (`/v2/…`). A guest-chosen path outside it — a foreign
    // authority smuggled via `//host`, or the `/lock/` control plane — is refused rather
    // than authenticated on the guest's behalf.
    if !path_and_query.starts_with("/v2/") {
        let body = Full::new(Bytes::from_static(
            b"registry proxy: only /v2/ registry paths are proxied",
        ))
        .map_err(|never| match never {})
        .boxed();
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(body)?);
    }
    let url = format!("{}{path_and_query}", cfg.upstream);
    let method = req.method().clone();
    let bodyful = matches!(method, Method::POST | Method::PUT | Method::PATCH);
    let (parts, incoming) = req.into_parts();

    let mut rb = cfg.client.request(method, &url);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn injects_basic_auth_and_forwards_path() {
        // reqwest (rustls-no-provider) needs a crypto provider before a client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg {
            upstream: format!("http://{up_addr}"),
            creds: Creds {
                username: Some("robot".to_string()),
                password: Some("s3cret".to_string()),
                ..Creds::anonymous()
            },
            client: reqwest::Client::new(),
        };
        let proxy = spawn_blocking(cfg).unwrap();

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
            "path must be forwarded verbatim"
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
        let cfg = ProxyCfg {
            upstream: format!("http://{up_addr}"),
            creds: Creds {
                // Both set: the token wins, as it does on every other client path.
                username: Some("robot".to_string()),
                password: Some("s3cret".to_string()),
                token: Some("vkr_x".to_string()),
                ..Creds::anonymous()
            },
            client: reqwest::Client::new(),
        };
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
        let cfg = ProxyCfg {
            upstream: format!("http://{up_addr}"),
            creds: Creds {
                username: Some("robot".to_string()),
                password: Some("s3cret".to_string()),
                ..Creds::anonymous()
            },
            client: reqwest::Client::new(),
        };
        let proxy = spawn_blocking(cfg).unwrap();

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
}
