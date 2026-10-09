//! The web UI: server-rendered pages on a listener of their own, apart from the nodes'. Its
//! core — sign-in, sessions, the checks below, live updates — serves two sites: the fleet's
//! pages for `vk-hub serve` ([`fleet`]), and this machine's VMs for `vk-hub local` ([`local`]).
//!
//! **Sign-in.** Single-use tokens are issued over the admin socket — `vk-hub ui login`,
//! `vk-hub local login` — or printed by `vk-hub local` at startup. Opening a link shows a
//! button that posts the token to create a session, setting its secret as an `HttpOnly`,
//! `SameSite=Strict` cookie, also `Secure` and `__Host-` when the UI is reached over https.
//! The database stores only its hash. Only this `POST` spends the token; link scanners and
//! chat previews leave it unused. Sessions have a viewer or operator role and last
//! [`store::UI_SESSION_TTL`]. A fleet hub with `[oidc]` also signs people in through an OIDC
//! provider ([`oidc`]), with the role a grant in the database gives them; links remain, for
//! whom the provider cannot sign in.
//!
//! **State-changing requests** are `POST`s, and each must come from this UI's own pages —
//! its `Origin` is the UI's own (a fleet hub's `ui_url`), or `Sec-Fetch-Site` says
//! `same-origin` — and carry the session's CSRF token, derived from its secret, in a form
//! field or header. A fleet hub's are the admin socket's steering operations, of nodes and of
//! rollouts ([`fleet`]), its releases and rollouts added and started ([`operations`]), and its
//! OIDC grants given, changed and revoked ([`users`]); local mode's are `vk` commands
//! ([`actions`]). A release's upload is the one post whose body
//! is not a small form: [`operations`] reads it as it arrives, under limits of its own.
//!
//! **A page** (`GET`) goes only to a request the UI's own pages made (`same-origin`) or no
//! page made (`none`: the address bar, a bookmark, a link opened from a terminal);
//! `/auth/login` also goes to another site's top-level navigation ([`oidc`]).
//! `SameSite=Strict` alone would not do: it sends the cookie with requests from another port
//! of the same name, another origin but the same site.
//!
//! **Every request** must name the UI's host in its `Host`, so a page on another name
//! resolved to this address (DNS rebinding) reaches nothing. **Every response** carries a
//! strict Content-Security-Policy: pages show strings nodes and the host's `vk` send, and the
//! policy is what keeps an escaping mistake from running as script in an operator's session.
//! The pages themselves escape by construction ([`html`]). It is also for this origin alone to
//! embed or open a window on (`Cross-Origin-Resource-Policy`, `-Opener-Policy`).
//!
//! **No per-address cap** on connections: the people using the UI are few, often behind one
//! reverse proxy or NAT address, where such a cap would lock them all out at once. The global
//! cap and the timeouts before a request is read bound what any peer holds.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioTimer;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::local::Local;
use crate::server::{Hub, Io, PRE_AUTH_TIMEOUT};
use crate::store::{self, Role, UiSession};

mod actions;
mod assets;
mod body;
mod dev;
mod fleet;
pub mod html;
mod job_output;
mod jobs;
mod local;
mod multipart;
mod oidc;
mod operations;
mod pages;
mod sse;
mod users;

use body::Body;
pub use oidc::{CALLBACK_PATH as OIDC_CALLBACK_PATH, OidcSignIn};

/// Where a sign-in link points.
pub const LOGIN_PATH: &str = "/login";

/// The policy on every response. `form-action 'self'` and `frame-ancestors 'none'` too: a
/// form cannot be pointed elsewhere, nor a page framed to be clicked through.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'none'";

/// Connections at once. Far past what the few people using the UI keep open, and what bounds
/// what an unauthenticated peer can hold. Shared by the UI's listeners. Live pages' streams
/// take at most [`sse::MAX_STREAMS`] of them, leaving the rest to pages and posts — on the
/// hub's side: a browser has its own few per host for every tab ([`sse::MAX_SESSION_STREAMS`]).
const MAX_CONNECTIONS: usize = 128;

const _: () = assert!(sse::MAX_STREAMS < MAX_CONNECTIONS);

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
    /// The UI's origin: what a state-changing request's `Origin` must be.
    origin: String,
    /// The origin without its scheme: what every request's `Host` must be.
    authority: String,
    /// Whether browsers reach the UI over https, so its cookie may say `Secure`: a fleet
    /// hub's UI off loopback.
    secure: bool,
    connections: Arc<Semaphore>,
    /// The live pages' streams open.
    streams: sse::Streams,
    site: Site,
    /// Sign-in through an OIDC provider, besides the links.
    oidc: Option<OidcSignIn>,
}

/// What the pages show.
enum Site {
    /// `vk-hub serve`: the fleet.
    Fleet(fleet::FleetSite),
    /// `vk-hub local`: this machine's VMs.
    Local(Box<local::LocalSite>),
}

impl Ui {
    /// The fleet's UI at `origin`, a `ui_url` as the config normalizes it.
    pub fn new(hub: Arc<Hub>, origin: &str) -> Self {
        let site = Site::Fleet(fleet::FleetSite::new(&hub));
        Self::with_site(hub, origin, site)
    }

    /// Local mode's UI at `origin`, `http://host[:port]`, showing `local`'s VMs.
    pub fn local(hub: Arc<Hub>, origin: &str, local: Arc<Local>) -> Self {
        let site = Site::Local(Box::new(local::LocalSite::new(&hub, local)));
        Self::with_site(hub, origin, site)
    }

    fn with_site(hub: Arc<Hub>, origin: &str, site: Site) -> Self {
        let authority = origin
            .split_once("://")
            .map_or(origin, |(_, rest)| rest)
            .to_string();
        Ui {
            hub,
            origin: origin.to_string(),
            authority,
            secure: origin.starts_with("https://"),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            streams: sse::Streams::new(),
            site,
            oidc: None,
        }
    }

    /// The UI, also signing people in through `oidc`.
    pub fn with_oidc(mut self, oidc: OidcSignIn) -> Self {
        self.oidc = Some(oidc);
        self
    }

    /// What this UI's pages say of signing in.
    fn texts(&self) -> &'static Texts {
        match (&self.site, &self.oidc) {
            (Site::Fleet(_), None) => &FLEET_TEXTS,
            (Site::Fleet(_), Some(_)) => &FLEET_OIDC_TEXTS,
            (Site::Local(_), _) => &LOCAL_TEXTS,
        }
    }

    /// A page saying `text` to someone not signed in: with a button to sign in through the
    /// provider, where there is one.
    fn signed_out_page(&self, status: StatusCode, text: &'static str) -> Response<Body> {
        match &self.oidc {
            Some(oidc) => html_response(status, pages::sign_in_with(text, oidc.provider())),
            None => message(status, text),
        }
    }

    /// The session cookie's name. `__Host-` holds a browser to what makes it safe — `Secure`,
    /// `Path=/`, no `Domain` — but is refused on plain http.
    fn cookie_name(&self) -> &'static str {
        if self.secure { SECURE_COOKIE } else { COOKIE }
    }

    /// The attributes every session cookie this UI sets carries.
    fn cookie_attributes(&self) -> &'static str {
        if self.secure {
            "Path=/; HttpOnly; SameSite=Strict; Secure"
        } else {
            "Path=/; HttpOnly; SameSite=Strict"
        }
    }
}

const COOKIE: &str = "vk-hub";
const SECURE_COOKIE: &str = "__Host-vk-hub";

/// Serve the web UI on `listener` until the process ends, over TLS with `tls`.
pub async fn serve(listener: TcpListener, tls: Option<TlsAcceptor>, ui: Arc<Ui>) -> Result<()> {
    let permits = ui.connections.clone();
    crate::server::accept(listener, tls, permits, move |io, peer, _, _| {
        serve_conn(io, ui.clone(), peer)
    })
    .await
}

async fn serve_conn(io: Io, ui: Arc<Ui>, peer: SocketAddr) {
    let give_up = Arc::new(Notify::new());
    let svc = {
        let give_up = give_up.clone();
        service_fn(move |req| sse::GIVE_UP.scope(give_up.clone(), handle(req, ui.clone(), peer)))
    };
    // The header timeout also closes a kept-alive connection gone idle, since hyper runs it
    // while waiting for the next request. Nothing bounds the connection as a whole: a page's
    // live updates are one response that lasts as long as the page is open.
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(PRE_AUTH_TIMEOUT)
        .serve_connection(io, svc);
    let result = tokio::select! {
        result = conn => result,
        () = give_up.notified() => {
            eprintln!("vk-hub: ui: {peer}: dropped a live page that stopped reading");
            return;
        }
    };
    // A browser leaving a live page closes its stream mid-response, reset or broken under the
    // write; one closing before a whole request is incomplete. Nothing to report.
    if let Err(e) = result
        && !e.is_timeout()
        && !e.is_incomplete_message()
        && !peer_left(&e)
    {
        eprintln!("vk-hub: ui: {peer}: connection error: {e}");
    }
}

/// Whether `e` is the peer having closed the connection under a write.
fn peer_left(e: &hyper::Error) -> bool {
    std::iter::successors(std::error::Error::source(e), |e| e.source()).any(|e| {
        e.downcast_ref::<std::io::Error>().is_some_and(|e| {
            matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )
        })
    })
}

async fn handle(
    req: Request<Incoming>,
    ui: Arc<Ui>,
    peer: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    // The Jobs page's filter form, which needs the whole page when it gets no jobs.
    let reload = (req.method() == Method::GET
        && req.uri().path() == jobs::PATH
        && jobs::filter_swap(req.headers()))
    .then(|| req.uri().path_and_query().map(|p| p.as_str().to_string()))
    .flatten();
    let mut resp = route(req, &ui).await.unwrap_or_else(|e| {
        eprintln!("vk-hub: ui: {peer}: {e:#}");
        message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something failed on the hub; its log says what.",
        )
    });
    if let Some(uri) = reload
        && !resp.status().is_success()
    {
        resp = jobs::reload(&uri, resp);
    }
    secure_headers(resp.headers_mut(), ui.secure);
    Ok(resp)
}

/// The headers every response carries. `no-store` unless the response says otherwise, as
/// only the assets do: a page holds what the session may see, and its CSRF token.
/// `Referrer-Policy: same-origin` rather than `no-referrer`, so the pages' own form posts
/// carry their real `Origin`; nothing crosses to another origin either way.
fn secure_headers(h: &mut HeaderMap, secure: bool) {
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
    if secure {
        // Without includeSubDomains, but HSTS has no port: it covers every port of the host.
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

async fn route(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    if !host_is(&req, &ui.authority) {
        return Ok(message(
            StatusCode::MISDIRECTED_REQUEST,
            ui.texts().misdirected,
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
        (Method::GET, LOGIN_PATH) => Ok(login_page(&req, ui)),
        (Method::POST, LOGIN_PATH) => login(req, ui).await,
        // Checks navigation headers itself to allow a provider's portal.
        (Method::GET, oidc::LOGIN_PATH) => oidc::start(&req, ui).await,
        // Exempt from the check below: the provider's page is another site's.
        (Method::GET, oidc::CALLBACK_PATH) => oidc::callback(&req, ui).await,
        // Still probed by browsers that skip the pages' SVG icon link; there is no `.ico`.
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
                Err(why) => {
                    return Ok(signed_out_stream(&path, req.headers(), ui)
                        .unwrap_or_else(|| ui.signed_out_page(StatusCode::UNAUTHORIZED, why)));
                }
            };
            let swap = jobs::filter_swap(req.headers());
            get(&path, req.uri().query(), &auth, ui, swap).await
        }
        (Method::POST, _) => match &ui.site {
            Site::Fleet(site) => {
                if path == operations::UPLOAD_PATH {
                    operations::upload(req, ui, site).await
                } else if path == operations::FETCH_PATH {
                    operations::fetch_action(req, ui).await
                } else if path == users::PATH {
                    users::action(req, ui, site).await
                } else if path == fleet::TOKEN_PATH {
                    fleet::create_token(req, ui).await
                } else if path == operations::ROLLOUT_PATH {
                    operations::create_rollout(req, ui, site).await
                } else if let Some(id) = fleet::action_node(&path) {
                    fleet::node_action(req, ui, site, id).await
                } else if let Some(id) = fleet::action_rollout(&path) {
                    fleet::rollout_action(req, ui, id).await
                } else {
                    Ok(message(StatusCode::NOT_FOUND, "No such action."))
                }
            }
            Site::Local(site) => match local::action_target(&path) {
                Some(local::Target::Vm(id)) => actions::vm_action(req, ui, site, &id).await,
                Some(local::Target::Dev(name)) => actions::dev_action(req, ui, site, &name).await,
                None => Ok(message(StatusCode::NOT_FOUND, "No such action.")),
            },
        },
        _ => Ok(message(
            StatusCode::METHOD_NOT_ALLOWED,
            "Pages are read with GET and changed with POST.",
        )),
    }
}

/// A live page's stream asked for with a session cookie that names no live session: its page
/// was signed in, and is told it no longer is, as an open stream is when its session ends. A
/// 401 would only have the SSE extension retry it for as long as the page stays open. More
/// than one session cookie is refused with a 401 as any request is.
fn signed_out_stream(path: &str, headers: &HeaderMap, ui: &Ui) -> Option<Response<Body>> {
    if !matches!(session_cookie(headers, ui.cookie_name()), Ok(Some(_))) {
        return None;
    }
    let name = path
        .strip_prefix("/events/")
        .and_then(|e| event_name(e, ui))?;
    Some(sse::signed_out(name, ui.texts().sign_in_again))
}

/// The event `/events/<event>` swaps its fragment in on, if it is one of this site's: what a
/// signed-out page is told, without following anything for it.
fn event_name(event: &str, ui: &Ui) -> Option<&'static str> {
    match &ui.site {
        Site::Fleet(_) => fleet::event_name(event),
        Site::Local(_) => local::event_name(event),
    }
}

/// What `/events/<event>[?<query>]` streams, if it is one of this site's, for `auth`'s page.
fn source(event: &str, query: Option<&str>, ui: &Ui, auth: &Auth) -> Option<sse::Source> {
    match &ui.site {
        Site::Fleet(site) => fleet::source(event, query, &ui.hub, site, auth),
        Site::Local(site) => local::source(event, &ui.hub, site),
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
/// `swap`: the Jobs page's filter form asks ([`jobs::filter_swap`]).
async fn get(
    path: &str,
    query: Option<&str>,
    auth: &Auth,
    ui: &Ui,
    swap: bool,
) -> Result<Response<Body>> {
    if let Some(source) = path
        .strip_prefix("/events/")
        .and_then(|e| source(e, query, ui, auth))
    {
        return Ok(stream(ui, auth, source));
    }
    let found = match &ui.site {
        Site::Fleet(site) => fleet::get(path, query, auth, ui, site, swap).await?,
        Site::Local(site) => local::get(path, query, auth, ui, site).await?,
    };
    Ok(found.unwrap_or_else(|| message(StatusCode::NOT_FOUND, "There is no such page.")))
}

/// A stream of `source` for `auth`'s page, or the refusal when there are too many.
fn stream(ui: &Ui, auth: &Auth, source: sse::Source) -> Response<Body> {
    match ui.streams.take(&store::token_key(&auth.secret)) {
        Ok(slot) => sse::stream(ui.hub.clone(), auth, source, slot, ui.texts().sign_in_again),
        Err((status, text)) => {
            let mut resp = message(status, text);
            // For what reads it; the SSE extension retries on a backoff of its own.
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            resp
        }
    }
}

/// Whether `token` looks like a sign-in token, before the database is asked.
fn well_formed_login(token: &str) -> bool {
    token
        .strip_prefix(store::LOGIN_PREFIX)
        .is_some_and(|hex| vk_hub_proto::from_hex_lower::<32>(hex).is_some())
}

/// `GET /login?t=<token>`: a button that posts the token back. Nothing is spent here, so
/// whatever fetches a link without a person behind it — a mail scanner, a chat's preview, a
/// browser's prerender — leaves it for the person. With no token, the button to sign in
/// through the provider, where there is one.
fn login_page(req: &Request<Incoming>, ui: &Ui) -> Response<Body> {
    let query = decode_form(req.uri().query().unwrap_or("").as_bytes());
    let token = match field(&query, "t") {
        Some(token) => token,
        None if ui.oidc.is_some() => {
            return ui.signed_out_page(StatusCode::OK, ui.texts().signed_out);
        }
        None => "",
    };
    if !well_formed_login(token) {
        return message(StatusCode::FORBIDDEN, ui.texts().not_a_link);
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
        return Ok(message(StatusCode::FORBIDDEN, ui.texts().not_a_link));
    }
    let hub = ui.hub.clone();
    let now = crate::now_secs();
    let Some((secret, session)) = blocking(move || hub.db.redeem_login(&token, now)).await? else {
        return Ok(message(StatusCode::FORBIDDEN, ui.texts().spent_link));
    };
    eprintln!("vk-hub: ui: {} signed in", session.principal());
    let mut resp = html_response(StatusCode::OK, pages::signed_in());
    set_session_cookie(
        &mut resp,
        ui,
        &secret,
        session.expires_at.saturating_sub(now),
    )?;
    Ok(resp)
}

/// Set the cookie of the session whose secret is `secret`, for `max_age` seconds.
fn set_session_cookie(
    resp: &mut Response<Body>,
    ui: &Ui,
    secret: &str,
    max_age: u64,
) -> Result<()> {
    let cookie = format!(
        "{}={secret}; {}; Max-Age={max_age}",
        ui.cookie_name(),
        ui.cookie_attributes(),
    );
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).context("building the session cookie")?,
    );
    Ok(())
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
    // Its pages' live updates end on it.
    ui.hub.sessions_changed();
    let mut resp = message(StatusCode::OK, "Signed out.");
    let cookie = format!(
        "{}=; {}; Max-Age=0",
        ui.cookie_name(),
        ui.cookie_attributes()
    );
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
    /// may share, and what a live update checks the session by on every render.
    secret: String,
}

/// The session the request's cookie names if it is live, or why there is none.
async fn authenticate(headers: &HeaderMap, ui: &Ui) -> Result<Result<Auth, &'static str>> {
    let secret = match session_cookie(headers, ui.cookie_name()) {
        Ok(Some(s)) if vk_hub_proto::from_hex_lower::<32>(s).is_some() => s.to_string(),
        Ok(_) => return Ok(Err(ui.texts().signed_out)),
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
        .ok_or(ui.texts().signed_out))
}

/// The session cookie `name`'s value, if the request has one — or `Err` when it has more
/// than one session cookie. Cookies are not kept apart by port: another service on the same
/// host can set one of this name, with a narrower path so the browser sends it first. Picking
/// one would let it choose the session; neither is taken instead. Over https only the
/// `__Host-` cookie counts: plain http on the same host can plant an unprefixed one, which
/// must not lock anyone out; over http either name does.
fn session_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(k, _)| *k == name || (name == COOKIE && *k == SECURE_COOKIE));
    match (found.next(), found.next()) {
        (None, _) => Ok(None),
        (Some((k, v)), None) => Ok((k == name).then_some(v)),
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
    let auth = match check_caller(req.headers(), ui, need).await? {
        Ok(auth) => auth,
        Err(refused) => return Ok(Err(refused)),
    };
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
    if !csrf_ok(presented, &auth) {
        return Ok(Err((StatusCode::FORBIDDEN, CSRF_REFUSED)));
    }
    Ok(Ok((auth, form)))
}

/// The checks of [`check_post`] that need only the request's headers: from this UI's own
/// pages, by a live session with at least `need`. The session, or the status and reason that
/// refuse it.
async fn check_caller(
    headers: &HeaderMap,
    ui: &Ui,
    need: Role,
) -> Result<Result<Auth, (StatusCode, &'static str)>> {
    if !from_own_page(headers, &ui.origin, false) {
        return Ok(Err((StatusCode::FORBIDDEN, CROSS_ORIGIN)));
    }
    let auth = match authenticate(headers, ui).await? {
        Ok(auth) => auth,
        Err(why) => return Ok(Err((StatusCode::UNAUTHORIZED, why))),
    };
    if auth.session.role < need {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "Refused: this needs the operator role.",
        )));
    }
    Ok(Ok(auth))
}

/// Whether `presented` is `auth`'s session's CSRF token.
fn csrf_ok(presented: Option<String>, auth: &Auth) -> bool {
    presented.is_some_and(|t| constant_time_eq(t.as_bytes(), auth.csrf.as_bytes()))
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
    vk_hub_proto::to_hex(&h.finalize())
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

/// Run a blocking database or filesystem call off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .context("running a blocking call")?
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
fn message(status: StatusCode, text: &str) -> Response<Body> {
    html_response(status, pages::message(text))
}

/// What the pages say that differs between the sites: how to sign in.
struct Texts {
    misdirected: &'static str,
    not_a_link: &'static str,
    spent_link: &'static str,
    signed_out: &'static str,
    /// Markup: how a page whose session ended signs in again.
    sign_in_again: &'static str,
}

const FLEET_TEXTS: Texts = Texts {
    misdirected: "This is not the address the hub's web UI is configured at (its ui_url, or \
                  ui_addr when that is unset).",
    not_a_link: "This is not a sign-in link. `vk-hub ui login` prints one.",
    spent_link: "This sign-in link is unknown, used or expired. `vk-hub ui login` prints a new \
                 one.",
    signed_out: "Not signed in. On the hub's host, `vk-hub ui login` prints a link that signs \
                 you in.",
    sign_in_again: "<code>vk-hub ui login</code> prints a link to sign in again.",
};

const FLEET_OIDC_TEXTS: Texts = Texts {
    signed_out: "Not signed in.",
    sign_in_again: "<a href=\"/auth/login\">Sign in again</a>, or <code>vk-hub ui login</code> \
                    prints a link.",
    ..FLEET_TEXTS
};

const LOCAL_TEXTS: Texts = Texts {
    misdirected: "This is not the address the hub's web UI is served at.",
    not_a_link: "This is not a sign-in link. `vk-hub local login` prints one.",
    spent_link: "This sign-in link is unknown, used or expired. `vk-hub local login` prints a \
                 new one.",
    signed_out: "Not signed in. On this machine, `vk-hub local login` prints a link that signs \
                 you in.",
    sign_in_again: "<code>vk-hub local login</code> prints a link to sign in again.",
};

const CONFLICTING_COOKIES: &str = "Not signed in: this browser sent more than one vk-hub \
     session cookie, which is what a cookie planted by another site on this host looks like. \
     Clear this site's cookies and sign in again.";

const CROSS_ORIGIN: &str = "Refused: this request did not come from the hub's own pages.";
const CSRF_REFUSED: &str =
    "Refused: the form's CSRF token is missing or not this session's. Reload the page.";

const ANOTHER_SITE: &str = "Refused: another site's page asked for this one. Open the hub's \
     address yourself, or follow its own links.";

#[cfg(test)]
mod tests;
