//! A minimal fake OIDC provider for tests: discovery, token and UserInfo in one in-process
//! hyper server on an ephemeral loopback port. Its issuer is `http://<addr>`, which the
//! loopback exception admits. It accepts any authorization code, from a client that
//! authenticates as [`CLIENT_ID`] with [`CLIENT_SECRET`] and sends a PKCE verifier, and
//! answers UserInfo with [`Options::claims`].

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

pub const CLIENT_ID: &str = "vk-client";
pub const CLIENT_SECRET: &str = "s3cr3t";

/// `Basic base64("vk-client:s3cr3t")`.
const BASIC: &str = "Basic dmstY2xpZW50OnMzY3IzdA==";

/// What the fake provider says.
#[derive(Clone)]
pub struct Options {
    /// Advertise `client_secret_basic`, else only `client_secret_post`.
    pub basic_auth: bool,
    /// The issuer its discovery document claims, where it differs from the truth.
    pub issuer: Option<String>,
    /// The token endpoint its discovery document names, where it differs from the truth.
    pub token_endpoint: Option<String>,
    /// What UserInfo answers.
    pub claims: serde_json::Value,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            basic_auth: true,
            issuer: None,
            token_endpoint: None,
            claims: serde_json::json!({
                "sub": "user-42",
                "email": "alice@example.com",
                "name": "Alice"
            }),
        }
    }
}

/// Start a fake provider, return its address, and serve until the runtime ends.
pub async fn start(opts: Options) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let opts = opts.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let opts = opts.clone();
                    async move { Ok::<_, Infallible>(respond(req, addr, opts).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

/// A failure here answers with a 400 and a reason rather than asserting: this runs in
/// a spawned connection task, where a panic would reach the test as an opaque
/// connection error instead of a named failure.
async fn respond(req: Request<Incoming>, addr: SocketAddr, opts: Options) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let issuer = opts.issuer.unwrap_or_else(|| format!("http://{addr}"));
    let token_endpoint = opts
        .token_endpoint
        .unwrap_or_else(|| format!("http://{addr}/token"));
    let json = |v: serde_json::Value| {
        Response::builder()
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(v.to_string())))
            .unwrap()
    };
    let refuse = |why: &str| {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from(format!("fake idp: {why}"))))
            .unwrap()
    };
    match path.as_str() {
        "/.well-known/openid-configuration" => json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("http://{addr}/authorize"),
            "token_endpoint": token_endpoint,
            "userinfo_endpoint": format!("http://{addr}/userinfo"),
            "end_session_endpoint": format!("http://{addr}/logout"),
            "token_endpoint_auth_methods_supported":
                if opts.basic_auth { ["client_secret_basic"] } else { ["client_secret_post"] },
        })),
        "/token" => {
            let header_secret = req
                .headers()
                .get(hyper::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string());
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let form = String::from_utf8_lossy(&body).to_string();
            if !form.contains("grant_type=authorization_code") {
                return refuse("no authorization_code grant");
            }
            // PKCE is not optional in this flow
            if !form.contains("code_verifier=") {
                return refuse("no code_verifier");
            }
            let authed = if opts.basic_auth {
                header_secret.as_deref() == Some(BASIC)
            } else {
                header_secret.is_none() && form.contains(&format!("client_secret={CLIENT_SECRET}"))
            };
            if !authed {
                return refuse("the client did not authenticate as configured");
            }
            json(serde_json::json!({ "access_token": "at-123", "token_type": "Bearer" }))
        }
        "/userinfo" => {
            if req
                .headers()
                .get(hyper::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                != Some("Bearer at-123")
            {
                return refuse("bad access token");
            }
            json(opts.claims)
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap(),
    }
}
