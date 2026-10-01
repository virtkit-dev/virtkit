//! The web UI: server-rendered pages on a listener of their own, apart from the nodes'. Its
//! core — sign-in, sessions, the checks below, live updates — serves two sites: the fleet's
//! pages for `vk-hub serve`, and this machine's VMs for `vk-hub local` ([`local`]).
//!
//! **Sign-in.** `vk-hub ui login` mints a single-use link over the admin socket, and `vk-hub
//! local` prints one as it starts and mints more with `vk-hub local login`. Opening it
//! shows a button; pressing it posts the token back, which spends it on a session and sets
//! its secret as a cookie — `HttpOnly`, `SameSite=Strict`, `Secure` and `__Host-` when the UI
//! is reached over https — whose hash alone the database keeps. Only that `POST` spends a
//! token, so a link scanner or a chat's preview fetching the link leaves it unused. A session
//! has a role, viewer or operator, and lasts [`store::UI_SESSION_TTL`]. Links stand in for a
//! login: people will sign in through OIDC, with the identity layer the hub is to share with
//! `vk-registry` (`docs/fleet-design.md`, "Authentication for submitted jobs"), which then
//! replaces them.
//!
//! **State-changing requests** are `POST`s, and each must come from this UI's own pages —
//! its `Origin` is the configured `ui_url`, or `Sec-Fetch-Site` says `same-origin` — and carry
//! the session's CSRF token, derived from its secret, in a form field or header. The fleet's
//! operations are [`crate::ops`]', the admin socket's, done as the session's principal;
//! removing a node and issuing tokens stay on the admin socket. Local mode's are `vk`
//! commands ([`actions`]).
//!
//! **Every request** must name `ui_url`'s host in its `Host`, so a page on another name
//! resolved to this address (DNS rebinding) reaches nothing. **Every response** carries a
//! strict Content-Security-Policy: pages show strings nodes and the host's `vk` send, and the
//! policy is what keeps an escaping mistake from running as script in an operator's session. The pages themselves
//! escape by construction ([`html`]).
//!
//! **No per-address cap** on connections: the UI is for the few people running a fleet, often
//! behind one reverse proxy or NAT address, where such a cap would lock them all out at
//! once. The global cap and the timeouts before a request is read bound what any peer holds.

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
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::local::Local;
use crate::server::{Hub, Io, PRE_AUTH_TIMEOUT};
use crate::store::{self, Role, UiSession};

mod actions;
mod assets;
pub mod html;
mod local;
mod pages;
mod sse;

use sse::Body;

/// Where a sign-in link points.
pub const LOGIN_PATH: &str = "/login";

/// The policy on every response. `form-action 'self'` and `frame-ancestors 'none'` too: a
/// form cannot be pointed elsewhere, nor a page framed to be clicked through.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'none'";

/// Connections at once. Far past what the few people running a fleet keep open, and what
/// bounds what an unauthenticated peer can hold. Live pages' streams take at most
/// [`sse::MAX_STREAMS`] of them, so pages and posts always find one.
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
    /// `ui_url`: what a state-changing request's `Origin` must be.
    origin: String,
    /// `ui_url` without its scheme: what every request's `Host` must be.
    authority: String,
    /// Whether browsers reach the UI over https, so its cookie may say `Secure`.
    secure: bool,
    connections: Arc<Semaphore>,
    /// The live pages' streams open.
    streams: sse::Streams,
    site: Site,
}

/// What the pages show.
enum Site {
    /// `vk-hub serve`: the fleet.
    Fleet {
        /// The nodes table, rendered once for every nodes page ([`sse::feed`]).
        nodes_feed: tokio::sync::watch::Sender<Option<bytes::Bytes>>,
    },
    /// `vk-hub local`: this machine's VMs.
    Local {
        local: Arc<Local>,
        /// The VMs table, rendered once for every page listing it.
        vms_feed: tokio::sync::watch::Sender<Option<bytes::Bytes>>,
    },
}

impl Ui {
    /// The fleet's UI at `origin`, a `ui_url` as the config normalizes it.
    pub fn new(hub: Arc<Hub>, origin: &str) -> Self {
        let site = Site::Fleet {
            nodes_feed: sse::feed(hub.subscribe(), "nodes", render_nodes(hub.clone())),
        };
        Self::with_site(hub, origin, site)
    }

    /// Local mode's UI at `origin`, `scheme://host[:port]`, showing `local`'s VMs.
    pub fn local(hub: Arc<Hub>, origin: &str, local: Arc<Local>) -> Self {
        let site = Site::Local {
            vms_feed: local::feed(&hub, &local),
            local,
        };
        Self::with_site(hub, origin, site)
    }

    fn with_site(hub: Arc<Hub>, origin: &str, site: Site) -> Self {
        let authority = origin
            .split_once("://")
            .map_or(origin, |(_, rest)| rest)
            .to_string();
        Ui {
            origin: origin.to_string(),
            authority,
            secure: origin.starts_with("https://"),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            streams: sse::Streams::new(),
            site,
            hub,
        }
    }

    /// The command that prints a sign-in link for this UI, in what its pages say.
    fn texts(&self) -> &'static Texts {
        match self.site {
            Site::Fleet { .. } => &FLEET_TEXTS,
            Site::Local { .. } => &LOCAL_TEXTS,
        }
    }

    /// The session cookie's name. `__Host-` holds a browser to what makes it safe — `Secure`,
    /// `Path=/`, no `Domain` — but is refused on plain http.
    fn cookie_name(&self) -> &'static str {
        if self.secure { SECURE_COOKIE } else { COOKIE }
    }
}

const COOKIE: &str = "vk-hub";
const SECURE_COOKIE: &str = "__Host-vk-hub";

/// Serve the web UI on `listener` until the process ends.
pub async fn serve(listener: TcpListener, tls: Option<TlsAcceptor>, ui: Arc<Ui>) -> Result<()> {
    let permits = ui.connections.clone();
    crate::server::accept(listener, tls, permits, move |io, peer, _| {
        serve_conn(io, ui.clone(), peer)
    })
    .await
}

async fn serve_conn(io: Io, ui: Arc<Ui>, peer: SocketAddr) {
    let svc = service_fn(move |req| handle(req, ui.clone(), peer));
    // The header timeout also closes a kept-alive connection gone idle, since hyper runs it
    // while waiting for the next request. Nothing bounds the connection as a whole: a page's
    // live updates are one response that lasts as long as the page is open.
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(PRE_AUTH_TIMEOUT)
        .serve_connection(io, svc);
    // A browser leaving a live page closes its stream mid-response: nothing to report.
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
    if secure {
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
        // Asked for by every browser whatever the page says; there is none.
        (Method::GET, "/favicon.ico") => {
            let mut resp = Response::new(Body::default());
            *resp.status_mut() = StatusCode::NO_CONTENT;
            Ok(resp)
        }
        (Method::POST, "/logout") => logout(req, ui).await,
        (Method::GET, _) => {
            let auth = match authenticate(req.headers(), ui).await? {
                Ok(auth) => auth,
                Err(why) => return Ok(message(StatusCode::UNAUTHORIZED, why)),
            };
            match &ui.site {
                Site::Fleet { .. } => get(&path, req.uri().query(), &auth, ui).await,
                Site::Local { local, vms_feed } => {
                    local::get(&path, req.uri().query(), &auth, ui, local, vms_feed).await
                }
            }
        }
        (Method::POST, _) => match &ui.site {
            Site::Fleet { .. } => match action_node(&path) {
                Some(id) => action(req, ui, id.to_string()).await,
                None => Ok(message(StatusCode::NOT_FOUND, "No such action.")),
            },
            Site::Local { local, .. } => match local::action_target(&path) {
                Some(local::Target::Vm(id)) => actions::vm_action(req, ui, local, &id).await,
                Some(local::Target::Dev(name)) => actions::dev_action(req, ui, local, &name).await,
                None => Ok(message(StatusCode::NOT_FOUND, "No such action.")),
            },
        },
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

/// A fleet page: read-only, for any session.
async fn get(path: &str, query: Option<&str>, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let now = crate::now_secs();
    if path == "/" {
        let nodes = blocking(move || crate::ops::node_views(&hub)).await?;
        return Ok(page(pages::nodes(auth, &nodes, now)));
    }
    let source = match (&ui.site, path.strip_prefix("/events/")) {
        (Site::Fleet { nodes_feed }, Some("nodes")) => Some(sse::Source::Shared {
            name: "nodes",
            feed: nodes_feed.subscribe(),
            render: render_nodes(hub.clone()),
        }),
        (_, Some(rest)) => rest
            .strip_prefix("node/")
            .filter(|id| vk_fleet_proto::valid_id(id))
            .map(|id| {
                let (hub, id) = (hub.clone(), id.to_string());
                sse::Source::Own {
                    name: "node",
                    changes: hub.subscribe_node(&id),
                    render: Arc::new(move || render_node(&hub, &id)),
                }
            }),
        _ => None,
    };
    if let Some(source) = source {
        return Ok(stream(ui, auth, source));
    }
    if path == "/audit" {
        let query = decode_form(query.unwrap_or("").as_bytes());
        let node = field(&query, "node")
            .filter(|n| vk_fleet_proto::valid_id(n))
            .map(str::to_string);
        let before = field(&query, "before").and_then(|b| b.parse().ok());
        let (rows, names) = blocking(move || {
            let rows = hub
                .db
                .audit_page(node.as_deref(), before, pages::AUDIT_PAGE)?;
            let names: Vec<(String, String)> = hub
                .db
                .nodes()?
                .into_iter()
                .map(|(id, row)| (id, row.hostname))
                .collect();
            anyhow::Ok((pages::AuditPage { node, rows }, names))
        })
        .await?;
        return Ok(page(pages::audit(auth, &rows, &names, pages::FLEET_NAV)));
    }
    if let Some(id) = path.strip_prefix("/node/")
        && vk_fleet_proto::valid_id(id)
    {
        let id = id.to_string();
        let detail = blocking(move || node_detail(&hub, &id)).await?;
        return Ok(match detail {
            Some(detail) => page(pages::node(auth, &detail, now)),
            None => message(StatusCode::NOT_FOUND, "There is no such node."),
        });
    }
    Ok(message(StatusCode::NOT_FOUND, "There is no such page."))
}

/// A stream of `source` for `auth`'s page, or the refusal when there are too many.
fn stream(ui: &Ui, auth: &Auth, source: sse::Source) -> Response<Body> {
    match ui.streams.take(&auth.session.id) {
        Ok(slot) => sse::stream(ui.hub.clone(), auth, source, slot),
        Err((status, text)) => {
            let mut resp = message(status, text);
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            resp
        }
    }
}

/// The nodes table, as one rendering for every nodes page.
fn render_nodes(hub: Arc<Hub>) -> sse::Render {
    Arc::new(move || {
        let nodes = crate::ops::node_views(&hub)?;
        Ok(pages::nodes_table(&nodes, crate::now_secs()).into_string())
    })
}

/// Node `id`'s page fragment, or the line saying it has gone.
fn render_node(hub: &Hub, id: &str) -> Result<String> {
    Ok(match node_detail(hub, id)? {
        Some(detail) => pages::node_detail(&detail, crate::now_secs()).into_string(),
        None => pages::gone().into_string(),
    })
}

/// What the node page shows of node `id`, or `None` for no such node.
fn node_detail(hub: &Hub, id: &str) -> Result<Option<pages::NodeDetail>> {
    let Some(row) = hub.db.node(id)? else {
        return Ok(None);
    };
    let mut commands = hub.db.node_commands(id)?;
    commands.sort_by_key(|c| std::cmp::Reverse(c.issued_at));
    commands.truncate(pages::NODE_COMMANDS);
    Ok(Some(pages::NodeDetail {
        view: crate::ops::node_view(hub, id.to_string(), &row),
        audit: hub.db.audit_page(Some(id), None, pages::NODE_AUDIT)?,
        commands,
        row,
    }))
}

/// Whether `token` looks like a sign-in token, before the database is asked.
fn well_formed_login(token: &str) -> bool {
    token
        .strip_prefix(store::LOGIN_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && vk_fleet_proto::from_hex(hex).is_some())
}

/// `GET /login?t=<token>`: a button that posts the token back. Nothing is spent here, so
/// whatever fetches a link without a person behind it — a mail scanner, a chat's preview, a
/// browser's prerender — leaves it for the person.
fn login_page(req: &Request<Incoming>, ui: &Ui) -> Response<Body> {
    let query = decode_form(req.uri().query().unwrap_or("").as_bytes());
    let token = field(&query, "t").unwrap_or("");
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
    ui.hub.sessions_changed();
    let mut resp = html_response(StatusCode::OK, pages::signed_in());
    let cookie = format!(
        "{}={secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        ui.cookie_name(),
        session.expires_at.saturating_sub(now),
        if ui.secure { "; Secure" } else { "" }
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
    let (id, principal) = (auth.session.id.clone(), auth.session.principal());
    blocking(move || {
        hub.db
            .end_ui_sessions(Some(&id), &principal, crate::now_secs())
    })
    .await?;
    eprintln!("vk-hub: ui: {} signed out", auth.session.principal());
    // Its pages' live updates end on it.
    ui.hub.sessions_changed();
    let mut resp = message(StatusCode::OK, "Signed out.");
    let cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        ui.cookie_name(),
        if ui.secure { "; Secure" } else { "" }
    );
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).context("building the session cookie")?,
    );
    Ok(resp)
}

/// `/node/<id>/action`'s node, if `path` is that for a well-formed ID.
fn action_node(path: &str) -> Option<&str> {
    path.strip_prefix("/node/")?
        .strip_suffix("/action")
        .filter(|id| vk_fleet_proto::valid_id(id))
}

/// `POST /node/<id>/action`: an operator steering a node, through the operations the admin
/// socket runs, as the session's principal.
///
/// An htmx request is answered with the node's fragment re-rendered and a line saying what
/// came of it, swapped in out of band, or with that line alone when it was refused; a plain
/// form post with the node's page, or a page saying why not.
async fn action(req: Request<Incoming>, ui: &Ui, id: String) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(refused(htmx, status, text)),
    };
    let op = field(&form, "op").unwrap_or("").to_string();
    let ceiling = match op.as_str() {
        "ceiling" => match field(&form, "ceiling").map(|c| c.trim().parse::<u32>()) {
            Some(Ok(n)) => Some(n),
            _ => {
                return Ok(refused(
                    htmx,
                    StatusCode::BAD_REQUEST,
                    "A ceiling is a number of jobs.",
                ));
            }
        },
        _ => None,
    };
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    let node = id.clone();
    let outcome = blocking(move || {
        use crate::ops;
        use vk_fleet_proto::{Acquisition, Operation};
        let desired = |d: Option<vk_fleet_proto::DesiredState>| match d {
            Some(d) => format!(
                "Desired state is now generation {}: ceiling {}, acquisition {}.",
                d.generation,
                d.ceiling
                    .map_or_else(|| "none".to_string(), |n| n.to_string()),
                crate::acquisition_name(d.acquisition)
            ),
            None => "Already so; nothing changed.".to_string(),
        };
        let command = |op: Operation| -> Result<String> {
            let c = ops::command(&hub, &principal, &node, op)?;
            Ok(format!(
                "Issued {} (command {}); the node's answer shows below.",
                crate::store::operation_name(&c.op),
                c.id
            ))
        };
        let result = match op.as_str() {
            "ceiling" => ops::set_ceiling(&hub, &principal, &node, ceiling).map(desired),
            "lift-ceiling" => ops::set_ceiling(&hub, &principal, &node, None).map(desired),
            "stop" => ops::set_acquisition(&hub, &principal, &node, Acquisition::Stop).map(desired),
            "resume" => {
                ops::set_acquisition(&hub, &principal, &node, Acquisition::Run).map(desired)
            }
            "drain" => command(Operation::Drain),
            "undrain" => command(Operation::Undrain),
            "quarantine" => command(Operation::Quarantine),
            "release" => command(Operation::Release),
            _ => return Ok(None),
        };
        // The operation's own refusal, such as a ceiling of 0, is the operator's to read.
        let said = result.map_err(|e| format!("{e:#}"));
        let detail = node_detail(&hub, &node)?;
        Ok(Some((said, detail)))
    })
    .await?;
    let Some((said, detail)) = outcome else {
        return Ok(refused(htmx, StatusCode::BAD_REQUEST, "No such action."));
    };
    let Some(detail) = detail else {
        return Ok(refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such node.",
        ));
    };
    if !htmx {
        return Ok(match said {
            Ok(_) => {
                let mut resp = Response::new(Body::default());
                *resp.status_mut() = StatusCode::SEE_OTHER;
                resp.headers_mut().insert(
                    header::LOCATION,
                    HeaderValue::from_str(&format!("/node/{id}")).context("building a redirect")?,
                );
                resp
            }
            Err(e) => html_response(StatusCode::BAD_REQUEST, pages::message(&e)),
        });
    }
    let (status, text, error) = match &said {
        Ok(text) => (StatusCode::OK, text.as_str(), false),
        Err(e) => (StatusCode::BAD_REQUEST, e.as_str(), true),
    };
    let mut body = pages::flash(text, error);
    if !error {
        body.html(&pages::node_detail(&detail, crate::now_secs()));
    }
    let mut resp = html_response(status, body);
    if error {
        // Only the line: the fragment stays as it is.
        resp.headers_mut()
            .insert("hx-reswap", HeaderValue::from_static("none"));
    }
    Ok(resp)
}

/// A refused action: for htmx, the line saying why, swapped in on its own.
fn refused(htmx: bool, status: StatusCode, text: &'static str) -> Response<Body> {
    if !htmx {
        return message(status, text);
    }
    let mut resp = html_response(status, pages::flash(text, true));
    resp.headers_mut()
        .insert("hx-reswap", HeaderValue::from_static("none"));
    resp
}

/// A signed-in request's session.
pub struct Auth {
    pub session: UiSession,
    /// The session's CSRF token, for the forms its pages carry.
    pub csrf: String,
    /// The cookie: what a live update checks the session by on every render.
    secret: String,
}

/// The session the request's cookie names if it is live, or why there is none.
async fn authenticate(headers: &HeaderMap, ui: &Ui) -> Result<Result<Auth, &'static str>> {
    let secret = match session_cookie(headers, ui.cookie_name()) {
        Ok(Some(s)) if s.len() == 64 && vk_fleet_proto::from_hex(s).is_some() => s.to_string(),
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
/// than one session cookie, of either name. Cookies are not kept apart by port: on plain
/// http another service on the same host can set one of this name, with a narrower path so
/// the browser sends it first. Picking one would let it choose the session; neither is
/// taken instead.
fn session_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(k, _)| *k == COOKIE || *k == SECURE_COOKIE);
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
    vk_fleet_proto::to_hex(&h.finalize())
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

/// What the pages say that differs between the sites: how to sign in.
struct Texts {
    misdirected: &'static str,
    not_a_link: &'static str,
    spent_link: &'static str,
    signed_out: &'static str,
}

const FLEET_TEXTS: Texts = Texts {
    misdirected: "This is not the address the hub's web UI is configured at (its ui_url).",
    not_a_link: "This is not a sign-in link. `vk-hub ui login` prints one.",
    spent_link: "This sign-in link is unknown, used or expired. `vk-hub ui login` prints a new                  one.",
    signed_out: "Not signed in. On the hub's host, `vk-hub ui login` prints a link that signs                  you in.",
};

const LOCAL_TEXTS: Texts = Texts {
    misdirected: "This is not the address the hub's web UI is served at.",
    not_a_link: "This is not a sign-in link. `vk-hub local login` prints one.",
    spent_link: "This sign-in link is unknown, used or expired. `vk-hub local login` prints a                  new one.",
    signed_out: "Not signed in. On this machine, `vk-hub local login` prints a link that signs                  you in.",
};

const CONFLICTING_COOKIES: &str = "Not signed in: this browser sent more than one vk-hub \
     session cookie, which is what a cookie planted by another site on this host looks like. \
     Clear this site's cookies and sign in again.";

const CROSS_ORIGIN: &str = "Refused: this request did not come from the hub's own pages. If \
     it did, the hub's ui_url is not the address this browser reached it at.";

#[cfg(test)]
mod tests;
