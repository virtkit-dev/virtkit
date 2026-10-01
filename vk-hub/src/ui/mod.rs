//! The web UI: server-rendered pages on a listener of their own.
//!
//! **Sign-in.** Single-use tokens are issued over the admin socket or printed by
//! `vk-hub local` at startup. Opening a link shows a button that posts the token to create
//! a session, setting its secret as an `HttpOnly`, `SameSite=Strict` cookie. The database
//! stores only its hash. Only this `POST` spends the token; link scanners and chat previews
//! leave it unused. Sessions have a viewer or operator role and last [`store::UI_SESSION_TTL`].
//!
//! **State-changing requests** are `POST`s, and each must come from this UI's own pages —
//! its `Origin` is the UI's own, or `Sec-Fetch-Site` says `same-origin` — and carry the
//! session's CSRF token, derived from its secret, in a form field or header.
//!
//! **A page** (`GET`) goes only to a request the UI's own pages made (`same-origin`) or no
//! page made (`none`: the address bar, a bookmark, a link opened from a terminal).
//! `SameSite=Strict` alone would not do: it sends the cookie with requests from another port
//! of the same name, another origin but the same site.
//!
//! **Every request** must name the UI's host in its `Host`, so a page on another name
//! resolved to this address (DNS rebinding) reaches nothing. **Every response** carries a
//! strict Content-Security-Policy: pages show strings the host's `vk` reports, and the policy
//! is what keeps an escaping mistake from running as script in an operator's session. The
//! pages themselves escape by construction ([`html`]). It is also for this origin alone to
//! embed or open a window on (`Cross-Origin-Resource-Policy`, `-Opener-Policy`).
//!
//! **No per-address cap** on connections: the people using the UI are few, often behind one
//! address. The global cap and the timeouts before a request is read bound what any peer
//! holds.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioTimer;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::local::Local;
use crate::server::{Hub, Io, PRE_AUTH_TIMEOUT};
use crate::store::{self, Role, UiSession};

mod assets;
pub mod html;
mod local;
mod pages;

type Body = Full<Bytes>;

/// Where a sign-in link points.
pub const LOGIN_PATH: &str = "/login";

/// The policy on every response. `form-action 'self'` and `frame-ancestors 'none'` too: a
/// form cannot be pointed elsewhere, nor a page framed to be clicked through.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'none'";

/// Connections at once. Far past what the few people using the UI keep open, and what bounds
/// what an unauthenticated peer can hold.
const MAX_CONNECTIONS: usize = 128;

/// The largest form a page posts: a few short fields.
const MAX_FORM: usize = 16 * 1024;

/// How long a form's body has to arrive once its headers have.
#[cfg(not(test))]
const FORM_TIMEOUT: Duration = PRE_AUTH_TIMEOUT;
#[cfg(test)]
const FORM_TIMEOUT: Duration = Duration::from_secs(1);

/// The web UI's shared state.
pub struct Ui {
    hub: Arc<Hub>,
    /// This machine's VMs.
    local: Arc<Local>,
    /// The UI's origin: what a state-changing request's `Origin` must be.
    origin: String,
    /// The origin without its scheme: what every request's `Host` must be.
    authority: String,
    connections: Arc<Semaphore>,
}

impl Ui {
    /// The UI at `origin`, `http://host[:port]`, showing `local`'s VMs.
    pub fn new(hub: Arc<Hub>, origin: &str, local: Arc<Local>) -> Self {
        let authority = origin
            .split_once("://")
            .map_or(origin, |(_, rest)| rest)
            .to_string();
        Ui {
            hub,
            local,
            origin: origin.to_string(),
            authority,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }
}

const COOKIE: &str = "vk-hub";

/// Serve the web UI on `listener` until the process ends.
pub async fn serve(listener: TcpListener, ui: Arc<Ui>) -> Result<()> {
    let permits = ui.connections.clone();
    crate::server::accept(listener, permits, move |io, peer| {
        serve_conn(io, ui.clone(), peer)
    })
    .await
}

async fn serve_conn(io: Io, ui: Arc<Ui>, peer: SocketAddr) {
    let svc = service_fn(move |req| handle(req, ui.clone(), peer));
    // The header timeout also closes a kept-alive connection gone idle, since hyper runs it
    // while waiting for the next request.
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(PRE_AUTH_TIMEOUT)
        .serve_connection(io, svc);
    if let Err(e) = conn.await
        && !e.is_timeout()
        && !e.is_incomplete_message()
    {
        eprintln!("vk-hub: ui: {peer}: connection error: {e}");
    }
}

async fn handle(
    req: Request<Incoming>,
    ui: Arc<Ui>,
    peer: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let mut resp = route(req, &ui).await.unwrap_or_else(|e| {
        eprintln!("vk-hub: ui: {peer}: {e:#}");
        message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something failed on the hub; its log says what.",
        )
    });
    secure_headers(resp.headers_mut());
    Ok(resp)
}

/// The headers every response carries. `no-store` unless the response says otherwise, as
/// only the assets do: a page holds what the session may see, and its CSRF token.
/// `Referrer-Policy: same-origin` rather than `no-referrer`, so the pages' own form posts
/// carry their real `Origin`; nothing crosses to another origin either way.
fn secure_headers(h: &mut HeaderMap) {
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

async fn route(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    if !host_is(&req, &ui.authority) {
        return Ok(message(
            StatusCode::MISDIRECTED_REQUEST,
            "This is not the address the hub's web UI is served at.",
        ));
    }
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    if method == Method::GET
        && let Some(resp) = assets::serve(&path, req.headers())
    {
        return Ok(resp);
    }
    match (method, path.as_str()) {
        (Method::GET, LOGIN_PATH) => Ok(login_page(&req)),
        (Method::POST, LOGIN_PATH) => login(req, ui).await,
        // Asked for by every browser whatever the page says; there is none.
        (Method::GET, "/favicon.ico") => {
            let mut resp = Response::new(Body::default());
            *resp.status_mut() = StatusCode::NO_CONTENT;
            Ok(resp)
        }
        (Method::POST, "/logout") => logout(req, ui).await,
        (Method::GET, _) => {
            if from_another_site(req.headers()) {
                return Ok(message(StatusCode::FORBIDDEN, ANOTHER_SITE));
            }
            let auth = match authenticate(req.headers(), ui).await? {
                Ok(auth) => auth,
                Err(why) => return Ok(message(StatusCode::UNAUTHORIZED, why)),
            };
            get(&path, req.uri().query(), &auth, ui).await
        }
        (Method::POST, _) => Ok(message(StatusCode::NOT_FOUND, "No such action.")),
        _ => Ok(message(
            StatusCode::METHOD_NOT_ALLOWED,
            "Pages are read with GET and changed with POST.",
        )),
    }
}

/// Whether the request names `authority` as its host: its `Host` header under HTTP/1.1, the
/// URI's authority if it has one.
fn host_is(req: &Request<Incoming>, authority: &str) -> bool {
    let host = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        });
    host.is_some_and(|h| h.eq_ignore_ascii_case(authority))
}

/// Whether the browser says another site's page asked for this — or a page of another port
/// of this name, the same site — rather than one of this UI's, or none at all.
fn from_another_site(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .is_some_and(|s| s.as_bytes() == b"same-site" || s.as_bytes() == b"cross-site")
}

/// A page: read-only, for any session.
async fn get(path: &str, query: Option<&str>, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    if path == "/audit" {
        let query = decode_form(query.unwrap_or("").as_bytes());
        let before = field(&query, "before").and_then(|b| b.parse().ok());
        let hub = ui.hub.clone();
        let rows = blocking(move || hub.db.audit_page(before, pages::AUDIT_PAGE)).await?;
        return Ok(page(pages::audit(auth, &rows)));
    }
    if let Some(resp) = local::get(path, auth, ui) {
        return Ok(resp);
    }
    Ok(message(StatusCode::NOT_FOUND, "There is no such page."))
}

/// Whether `token` looks like a sign-in token, before the database is asked.
fn well_formed_login(token: &str) -> bool {
    token
        .strip_prefix(store::LOGIN_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && crate::hex::from_hex(hex).is_some())
}

/// `GET /login?t=<token>`: a button that posts the token back. Nothing is spent here, so
/// whatever fetches a link without a person behind it — a mail scanner, a chat's preview, a
/// browser's prerender — leaves it for the person.
fn login_page(req: &Request<Incoming>) -> Response<Body> {
    let query = decode_form(req.uri().query().unwrap_or("").as_bytes());
    let token = field(&query, "t").unwrap_or("");
    if !well_formed_login(token) {
        return message(StatusCode::FORBIDDEN, NOT_A_LINK);
    }
    page(pages::sign_in(token))
}

/// `POST /login`: spend a sign-in token on a session.
///
/// Only from the sign-in page itself — `Sec-Fetch-Site` `same-origin`, or `none` for a post
/// no page made — so no other site can sign a browser in to a session of its choosing.
/// Answered with a page that moves on to `/` rather than with a redirect: the token, in the
/// form, never reaches the address bar, and the next request is one the page itself makes.
async fn login(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    if !from_own_page(req.headers(), &ui.origin, true) {
        return Ok(message(StatusCode::FORBIDDEN, CROSS_ORIGIN));
    }
    let form = match read_form(req).await {
        Ok(form) => form,
        Err((status, text)) => return Ok(message(status, text)),
    };
    let token = field(&form, "t").unwrap_or("").to_string();
    if !well_formed_login(&token) {
        return Ok(message(StatusCode::FORBIDDEN, NOT_A_LINK));
    }
    let hub = ui.hub.clone();
    let now = crate::now_secs();
    let Some((secret, session)) = blocking(move || hub.db.redeem_login(&token, now)).await? else {
        return Ok(message(StatusCode::FORBIDDEN, SPENT_LINK));
    };
    eprintln!("vk-hub: ui: {} signed in", session.principal());
    let mut resp = html_response(StatusCode::OK, pages::signed_in());
    let cookie = format!(
        "{COOKIE}={secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        session.expires_at.saturating_sub(now)
    );
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).context("building the session cookie")?,
    );
    Ok(resp)
}

/// `POST /logout`: end this session.
async fn logout(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let (auth, _) = match check_post(req, ui, Role::Viewer).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(message(status, text)),
    };
    let hub = ui.hub.clone();
    let (secret, principal) = (auth.secret.clone(), auth.session.principal());
    blocking(move || {
        hub.db
            .end_ui_session(&secret, &principal, crate::now_secs())
    })
    .await?;
    eprintln!("vk-hub: ui: {} signed out", auth.session.principal());
    let mut resp = message(StatusCode::OK, "Signed out.");
    let cookie = format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).context("building the session cookie")?,
    );
    Ok(resp)
}

/// A signed-in request's session.
pub struct Auth {
    pub session: UiSession,
    /// The session's CSRF token, for the forms its pages carry.
    pub csrf: String,
    /// The cookie: what a sign-out ends the session by, rather than its ID, which another
    /// may share.
    secret: String,
}

/// The session the request's cookie names if it is live, or why there is none.
async fn authenticate(headers: &HeaderMap, ui: &Ui) -> Result<Result<Auth, &'static str>> {
    let secret = match session_cookie(headers) {
        Ok(Some(s)) if s.len() == 64 && crate::hex::from_hex(s).is_some() => s.to_string(),
        Ok(_) => return Ok(Err(SIGNED_OUT)),
        Err(()) => return Ok(Err(CONFLICTING_COOKIES)),
    };
    let hub = ui.hub.clone();
    let csrf = csrf_token(&secret);
    let key = secret.clone();
    let session = blocking(move || hub.db.ui_session(&key, crate::now_secs())).await?;
    Ok(session
        .map(|session| Auth {
            session,
            csrf,
            secret,
        })
        .ok_or(SIGNED_OUT))
}

/// The session cookie's value, if the request has one — or `Err` when it has more than one.
/// Cookies are not kept apart by port: another service on the same host can set one of this
/// name, with a narrower path so the browser sends it first. Picking one would let it choose
/// the session; neither is taken instead.
fn session_cookie(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let mut found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(k, _)| *k == COOKIE);
    match (found.next(), found.next()) {
        (None, _) => Ok(None),
        (Some((_, v)), None) => Ok(Some(v)),
        (Some(_), Some(_)) => Err(()),
    }
}

/// Read a form of at most [`MAX_FORM`] bytes within [`FORM_TIMEOUT`], or say why not.
async fn read_form(
    req: Request<Incoming>,
) -> Result<Vec<(String, String)>, (StatusCode, &'static str)> {
    // Capped while reading: a chunked body declares no length to check up front.
    match tokio::time::timeout(
        FORM_TIMEOUT,
        http_body_util::Limited::new(req.into_body(), MAX_FORM).collect(),
    )
    .await
    {
        Ok(Ok(b)) => Ok(decode_form(&b.to_bytes())),
        Ok(Err(_)) => Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Refused: the form is too large.",
        )),
        Err(_) => Err((
            StatusCode::REQUEST_TIMEOUT,
            "Refused: the form was too slow to arrive.",
        )),
    }
}

/// Check a state-changing request: from this UI's own pages, by a live session with at least
/// `need`, carrying its CSRF token. Its form, or the status and reason that refuse it.
async fn check_post(
    req: Request<Incoming>,
    ui: &Ui,
    need: Role,
) -> Result<Result<(Auth, Vec<(String, String)>), (StatusCode, &'static str)>> {
    if !from_own_page(req.headers(), &ui.origin, false) {
        return Ok(Err((StatusCode::FORBIDDEN, CROSS_ORIGIN)));
    }
    let auth = match authenticate(req.headers(), ui).await? {
        Ok(auth) => auth,
        Err(why) => return Ok(Err((StatusCode::UNAUTHORIZED, why))),
    };
    if auth.session.role < need {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "Refused: this needs the operator role.",
        )));
    }
    let header_token = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let form = match read_form(req).await {
        Ok(form) => form,
        Err(refused) => return Ok(Err(refused)),
    };
    let presented = field(&form, "_csrf").map(str::to_string).or(header_token);
    if !presented.is_some_and(|t| constant_time_eq(t.as_bytes(), auth.csrf.as_bytes())) {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "Refused: the form's CSRF token is missing or not this session's. Reload the page.",
        )));
    }
    Ok(Ok((auth, form)))
}

/// Whether a request comes from a page of `origin`: its `Origin` is that, or it names none
/// and `Sec-Fetch-Site` says `same-origin` — or `none`, a request no page made, where
/// `allow_none`. A browser sends one or the other on every `POST`, so a request with neither
/// is refused too. `Origin: null` names none: an opaque origin, such as a plain form post's
/// under `Referrer-Policy: no-referrer`.
fn from_own_page(headers: &HeaderMap, origin: &str, allow_none: bool) -> bool {
    let site = headers.get("sec-fetch-site").map(HeaderValue::as_bytes);
    if site.is_some_and(|s| s != b"same-origin" && !(allow_none && s == b"none")) {
        return false;
    }
    match headers
        .get(header::ORIGIN)
        .filter(|o| o.as_bytes() != b"null")
    {
        Some(o) => o.as_bytes().eq_ignore_ascii_case(origin.as_bytes()),
        None => site.is_some(),
    }
}

/// The CSRF token of the session whose secret is `secret`. Derived rather than stored, so
/// the database — which holds only the secret's hash — cannot yield it.
fn csrf_token(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"vk-hub ui csrf\0");
    h.update(secret.as_bytes());
    crate::hex::to_hex(&h.finalize())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// An `application/x-www-form-urlencoded` body or query string, as pairs in order; [`field`]
/// takes the first of a name. A pair that does not decode to UTF-8 is dropped: every field a
/// page sends is ASCII.
fn decode_form(bytes: &[u8]) -> Vec<(String, String)> {
    bytes
        .split(|&b| b == b'&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let mut kv = pair.splitn(2, |&b| b == b'=');
            let k = percent_decode(kv.next().unwrap_or_default())?;
            let v = percent_decode(kv.next().unwrap_or_default())?;
            Some((k, v))
        })
        .collect()
}

fn percent_decode(s: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while let Some(&b) = s.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// The first value of `name` in `form`.
fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Run `f`, a database call, off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .context("running a database call")?
}

fn html_response(status: StatusCode, html: html::Html) -> Response<Body> {
    let mut resp = Response::new(Body::from(html.into_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

fn page(html: html::Html) -> Response<Body> {
    html_response(StatusCode::OK, html)
}

/// A page saying `text`, and nothing else.
fn message(status: StatusCode, text: &'static str) -> Response<Body> {
    html_response(status, pages::message(text))
}

const NOT_A_LINK: &str = "This is not a sign-in link. `vk-hub local login` prints one.";

const SPENT_LINK: &str =
    "This sign-in link is unknown, used or expired. `vk-hub local login` prints a new one.";

const SIGNED_OUT: &str =
    "Not signed in. On this machine, `vk-hub local login` prints a link that signs you in.";

const CONFLICTING_COOKIES: &str = "Not signed in: this browser sent more than one vk-hub \
     session cookie, which is what a cookie planted by another site on this host looks like. \
     Clear this site's cookies and sign in again.";

const CROSS_ORIGIN: &str = "Refused: this request did not come from the hub's own pages.";

const ANOTHER_SITE: &str = "Refused: another site's page asked for this one. Open the hub's \
     address yourself, or follow its own links.";

#[cfg(test)]
mod tests;
