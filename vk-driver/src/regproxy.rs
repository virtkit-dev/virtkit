//! Per-VM credential-injecting registry proxy.
//!
//! When `vk run --registry-proxy` is set, `vk` runs this HTTP reverse proxy on the host
//! loopback and forwards the guest to it (the switch redirects a sentinel address —
//! `registry.vk` — to it; see switch.rs). The guest's registry client talks plain,
//! credential-free HTTP to it; the proxy adds the runner's `[registry]` credential on the
//! way to the real (central) registry. So the job never holds the secret, and the proxy
//! is never exposed on a network interface — only reachable through the switch's per-VM
//! redirect.
//!
//! NOTE: request/response bodies are buffered in memory; a streaming pass-through is a
//! follow-up for pushing/pulling large layers through the proxy.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// What the proxy forwards to and injects.
pub struct ProxyCfg {
    /// upstream base URL, `scheme://authority` (no path)
    pub upstream: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub client: reqwest::Client,
}

impl ProxyCfg {
    /// Build from explicit parts (the `vk run --registry-proxy` path): `upstream` is the
    /// full base URL (`scheme://host`), with optional Basic credentials + CA to inject.
    pub fn from_parts(
        upstream: &str,
        username: Option<String>,
        password: Option<String>,
        ca_file: Option<std::path::PathBuf>,
        insecure: bool,
    ) -> Result<Self> {
        let mut b = reqwest::Client::builder();
        if let Some(ca) = &ca_file {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            b = b.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("parsing the registry CA")?,
            );
        }
        if insecure {
            // match the other OCI paths' `--insecure`: accept the upstream's cert as-is.
            b = b.danger_accept_invalid_certs(true);
        }
        Ok(ProxyCfg {
            upstream: upstream.trim_end_matches('/').to_string(),
            username: username.filter(|u| !u.is_empty()),
            password,
            client: b.build().context("building the registry proxy client")?,
        })
    }
}

/// Bind an ephemeral loopback port, serve the proxy on it, and return the bound address
/// (handed to the switch as the redirect target).
pub async fn spawn(cfg: ProxyCfg) -> Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("binding the registry proxy")?;
    let addr = listener.local_addr()?;
    let cfg = Arc::new(cfg);
    tokio::spawn(async move {
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
    });
    Ok(addr)
}

async fn handle(
    req: Request<Incoming>,
    cfg: Arc<ProxyCfg>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(forward(req, &cfg).await.unwrap_or_else(|e| {
        // Keep the detail host-side; the guest is untrusted and must not learn the
        // upstream URL / internal error chain.
        eprintln!("virtkit: registry proxy: {e:#}");
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from_static(
                b"registry proxy: upstream error",
            )))
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

async fn forward(req: Request<Incoming>, cfg: &ProxyCfg) -> Result<Response<Full<Bytes>>> {
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
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from_static(
                b"registry proxy: only /v2/ registry paths are proxied",
            )))?);
    }
    let url = format!("{}{path_and_query}", cfg.upstream.trim_end_matches('/'));
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .context("reading the guest request body")?
        .to_bytes();

    let mut rb = cfg.client.request(method, &url);
    for (k, v) in parts.headers.iter() {
        if !is_skipped(&k.as_str().to_ascii_lowercase()) {
            rb = rb.header(k, v);
        }
    }
    if let Some(user) = &cfg.username {
        rb = rb.basic_auth(user, cfg.password.as_ref());
    }
    if !body.is_empty() {
        rb = rb.body(body.to_vec());
    }

    let resp = rb
        .send()
        .await
        .context("forwarding to the upstream registry")?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .bytes()
        .await
        .context("reading the upstream response")?;

    let mut out = Response::builder().status(status);
    for (k, v) in headers.iter() {
        if !is_skipped(&k.as_str().to_ascii_lowercase()) {
            out = out.header(k, v);
        }
    }
    out.body(Full::new(Bytes::from(bytes.to_vec())))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fake upstream that records the Authorization header + path of the last request
    // and replies 200 with a marker body.
    async fn fake_upstream() -> (SocketAddr, Arc<std::sync::Mutex<(String, String)>>) {
        let seen = Arc::new(std::sync::Mutex::new((String::new(), String::new())));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let s = seen.clone();
        tokio::spawn(async move {
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
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        (addr, seen)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn injects_basic_auth_and_forwards_path() {
        // reqwest (rustls-no-provider) needs a crypto provider before a client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream().await;
        let cfg = ProxyCfg {
            upstream: format!("http://{up_addr}"),
            username: Some("robot".to_string()),
            password: Some("s3cret".to_string()),
            client: reqwest::Client::new(),
        };
        let proxy = spawn(cfg).await.unwrap();

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refuses_paths_outside_v2() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream().await;
        let cfg = ProxyCfg {
            upstream: format!("http://{up_addr}"),
            username: Some("robot".to_string()),
            password: Some("s3cret".to_string()),
            client: reqwest::Client::new(),
        };
        let proxy = spawn(cfg).await.unwrap();

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
