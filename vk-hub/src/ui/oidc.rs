//! OIDC sign-in for a fleet hub with `[oidc]`, using `vk-oidc` like `vk-registry`.
//! See `vk-oidc`'s documentation for the flow's assumptions. Sign-in links remain available
//! for people the provider cannot sign in.
//!
//! `GET /auth/login` sends the browser to the provider, with the login's `state` in a
//! `__Host-` cookie that binds it to this browser; `GET /auth/callback` is where the provider
//! sends it back, the redirect URI registered with the provider. The cookie is
//! `SameSite=Lax`, as it has to arrive on that cross-site navigation, and the callback is
//! exempt from the check that refuses another site's page for that reason. The callback opens
//! a session for whom a grant in the database lets in
//! ([`crate::store::Db::create_oidc_session`]), answering, as a link's sign-in does, with a
//! page that moves on to `/` itself: the session cookie is `SameSite=Strict`, and a redirect
//! would carry on the navigation the provider's page started. Anyone else is refused. Refusals,
//! and sign-ins only the `*` grant admits, are audited within [`SignInAudit`]'s bounds.
//!
//! Who signed in is their email, when the provider gives an address it does not mark
//! unverified, else `sub <subject>`; only an email is looked up, so a sign-in without one is
//! let in only by the `*` grant.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::{ANOTHER_SITE, Ui, blocking, decode_form, field, from_another_site, message, pages};
use super::{body::Body, html_response};
use crate::store;

/// Where a sign-in through the provider starts.
pub const LOGIN_PATH: &str = "/auth/login";

/// Where the provider sends the browser back: `<ui_url>/auth/callback`, the redirect URI to
/// register with it.
pub const CALLBACK_PATH: &str = "/auth/callback";

/// The cookie binding a login's `state` to this browser. A name of its own: browsers keep
/// cookies apart by host, not port, and `vk-registry`'s is `__Host-vk_login`.
const LOGIN_COOKIE: &str = "__Host-vk-hub-login";

/// The longest identity kept: an email address is at most 254 characters.
const MAX_IDENTITY: usize = 256;

/// How often one identity's sign-in of a [`SignInAudit`] kind is audited, in seconds.
const SIGN_IN_AUDIT_EVERY: u64 = 10 * 60;

/// How many sign-ins of a [`SignInAudit`] kind are audited per [`SIGN_IN_AUDIT_WINDOW`], in
/// all.
const SIGN_IN_AUDIT_MAX: u32 = 60;

/// The window [`SIGN_IN_AUDIT_MAX`] counts over, in seconds.
const SIGN_IN_AUDIT_WINDOW: u64 = 60 * 60;

/// Which sign-ins of a kind anyone the provider signs in can repeat at will — refusals, and
/// sign-ins only the `*` grant admits — reach the audit log. The log keeps a bounded number
/// of rows, so unbounded ones would push the fleet's history out of it: one per identity per
/// [`SIGN_IN_AUDIT_EVERY`], and [`SIGN_IN_AUDIT_MAX`] per [`SIGN_IN_AUDIT_WINDOW`] in all.
/// The rest go to stderr only.
#[derive(Default)]
struct SignInAudit {
    /// When each identity's last audited sign-in was, while within [`SIGN_IN_AUDIT_EVERY`]:
    /// at most [`SIGN_IN_AUDIT_MAX`] of them.
    last: HashMap<String, u64>,
    window_start: u64,
    in_window: u32,
}

impl SignInAudit {
    /// Whether `identity`'s sign-in at `now` is audited, counting it if so. A window that
    /// starts after `now`, as it does once the clock steps back, ends there.
    fn admit(&mut self, identity: &str, now: u64) -> bool {
        self.last
            .retain(|_, at| now < at.saturating_add(SIGN_IN_AUDIT_EVERY));
        if self.last.contains_key(identity) {
            return false;
        }
        if now < self.window_start || now >= self.window_start.saturating_add(SIGN_IN_AUDIT_WINDOW)
        {
            self.window_start = now;
            self.in_window = 0;
        }
        if self.in_window >= SIGN_IN_AUDIT_MAX {
            return false;
        }
        self.in_window += 1;
        self.last.insert(identity.to_string(), now);
        true
    }
}

/// Whether `audit` admits `identity`'s sign-in at `now`.
fn admit(audit: &Mutex<SignInAudit>, identity: &str, now: u64) -> bool {
    audit
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .admit(identity, now)
}

/// A fleet hub's OIDC sign-in.
pub struct OidcSignIn {
    client: vk_oidc::Client,
    /// The issuer's host, for the sign-in button.
    provider: String,
    refusals: Mutex<SignInAudit>,
    /// Sign-ins only the `*` grant admits.
    anyones: Arc<Mutex<SignInAudit>>,
}

impl OidcSignIn {
    /// Sign-in at `issuer` as `client_id`, for the UI at `origin`.
    pub fn new(origin: &str, issuer: String, client_id: String, client_secret: String) -> Self {
        let provider = issuer
            .split_once("://")
            .map_or(issuer.as_str(), |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let client = vk_oidc::Client::new(
            vk_oidc::Config {
                issuer,
                client_id,
                client_secret,
                redirect_uri: format!("{origin}{CALLBACK_PATH}"),
                post_logout_redirect_uri: format!("{origin}/"),
            },
            // Every sign-in lands on `/`.
            vk_oidc::Landing {
                default: "/",
                is_safe: |t| t == "/",
            },
        );
        OidcSignIn {
            client,
            provider,
            refusals: Mutex::default(),
            anyones: Arc::default(),
        }
    }

    /// What the sign-in button names: the provider's host.
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

/// `GET /auth/login`: on to the provider. Not for another site's page, as no page is.
pub async fn start(req: &Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let Some(oidc) = &ui.oidc else {
        return Ok(message(StatusCode::NOT_FOUND, NOT_CONFIGURED));
    };
    if from_another_site(req.headers()) {
        return Ok(message(StatusCode::FORBIDDEN, ANOTHER_SITE));
    }
    let (url, state) = match oidc.client.login_url("/").await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vk-hub: ui: starting an OIDC sign-in failed: {e:#}");
            return Ok(message(StatusCode::BAD_GATEWAY, UNREACHABLE));
        }
    };
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::FOUND;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&url).context("building the provider's address")?,
    );
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&login_cookie(&state)).context("building the login cookie")?,
    );
    Ok(resp)
}

/// `GET /auth/callback`: redeem the provider's code for who signed in, and open a session for
/// them if a grant lets them in ([`crate::store::Db::create_oidc_session`]). Every answer
/// expires the login cookie: the login it named is over either way.
pub async fn callback(req: &Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let Some(oidc) = &ui.oidc else {
        return Ok(message(StatusCode::NOT_FOUND, NOT_CONFIGURED));
    };
    let mut resp = finish(req, ui, oidc).await?;
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&login_cookie("")).context("building the login cookie")?,
    );
    Ok(resp)
}

async fn finish(req: &Request<Incoming>, ui: &Ui, oidc: &OidcSignIn) -> Result<Response<Body>> {
    let query = decode_form(req.uri().query().unwrap_or("").as_bytes());
    let cookie_state = login_state(req.headers());
    // A person who declines consent comes back with an `error`, not a `code`. Both are
    // unauthenticated query input, so they reach the log bounded and without control
    // characters.
    if let Some(err) = field(&query, "error") {
        eprintln!(
            "vk-hub: ui: the OIDC provider refused a sign-in: {} {}",
            vk_oidc::loggable(err),
            vk_oidc::loggable(field(&query, "error_description").unwrap_or(""))
        );
        if let Some(state) = field(&query, "state") {
            oidc.client.abandon(state, cookie_state);
        }
        return Ok(message(
            StatusCode::BAD_REQUEST,
            "The identity provider did not complete this sign-in.",
        ));
    }
    let (Some(code), Some(state)) = (field(&query, "code"), field(&query, "state")) else {
        return Ok(message(
            StatusCode::BAD_REQUEST,
            "This callback is missing its code or state.",
        ));
    };
    let claims = match oidc.client.exchange(code, state, cookie_state).await {
        Ok((_, claims)) => claims,
        Err(e) => {
            // The chain names endpoints and quotes the provider; it is for the log.
            eprintln!("vk-hub: ui: an OIDC sign-in failed: {e:#}");
            return Ok(message(
                StatusCode::BAD_REQUEST,
                "This sign-in could not be completed. Start again from the sign-in page.",
            ));
        }
    };
    let (email, unverified) = match vk_oidc::email(&claims) {
        vk_oidc::Email::Asserted(e) => (store::normalize_email(e), false),
        vk_oidc::Email::Unverified => (None, true),
        vk_oidc::Email::Absent => (None, false),
    };
    let subject = claims.get("sub").and_then(|v| v.as_str());
    let identity = match (&email, subject) {
        (Some(e), _) => e.clone(),
        (None, Some(sub)) => format!("sub {sub}"),
        (None, None) => {
            eprintln!("vk-hub: ui: the OIDC provider's UserInfo carried no sub claim");
            return Ok(message(
                StatusCode::BAD_GATEWAY,
                "The identity provider did not say who you are.",
            ));
        }
    };
    // Shown on pages, in `vk-hub ui sessions` and in the audit log, and the provider's to
    // choose: refused unless it is already what a page would show.
    if identity.chars().count() > MAX_IDENTITY || vk_hub_proto::display_safe(&identity) != identity
    {
        eprintln!(
            "vk-hub: ui: refusing an OIDC identity that cannot be shown as is: {}",
            vk_oidc::loggable(&identity)
        );
        return Ok(message(
            StatusCode::BAD_GATEWAY,
            "The identity provider's answer was not usable.",
        ));
    }
    let issuer = oidc.client.issuer().to_string();
    let now = crate::now_secs();
    let hub = ui.hub.clone();
    let (who, by) = (identity.clone(), issuer.clone());
    let anyones = oidc.anyones.clone();
    let opened = blocking(move || {
        hub.db
            .create_oidc_session(email.as_deref(), &who, &by, now, || {
                admit(&anyones, &who, now)
            })
    })
    .await?;
    let Some((secret, session)) = opened else {
        let why = if unverified {
            "its email is marked unverified"
        } else {
            "granted no role"
        };
        let event = format!("{identity} was refused sign-in through {issuer}: {why}");
        if admit(&oidc.refusals, &identity, now) {
            eprintln!("vk-hub: ui: {event}");
            let hub = ui.hub.clone();
            let actor = identity.clone();
            blocking(move || hub.db.audit(&actor, &event, now)).await?;
        } else {
            eprintln!("vk-hub: ui: {event} (not audited: rate limit)");
        }
        return Ok(html_response(
            StatusCode::FORBIDDEN,
            pages::refused(&identity, unverified),
        ));
    };
    eprintln!("vk-hub: ui: {} signed in through OIDC", session.principal());
    let mut resp = html_response(StatusCode::OK, pages::signed_in());
    super::set_session_cookie(
        &mut resp,
        ui,
        &secret,
        session.expires_at.saturating_sub(now),
    )?;
    Ok(resp)
}

/// The `Set-Cookie` for the login cookie; an empty `state` expires it. `Secure` and
/// `__Host-`: `[oidc]` is only for a UI reached over https.
fn login_cookie(state: &str) -> String {
    let max_age = if state.is_empty() {
        0
    } else {
        vk_oidc::LOGIN_TTL.as_secs()
    };
    format!("{LOGIN_COOKIE}={state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}")
}

/// The login `state` this browser holds, if it holds exactly one: two are taken as none, as
/// two session cookies are.
fn login_state(headers: &HeaderMap) -> Option<&str> {
    let mut found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(k, _)| *k == LOGIN_COOKIE)
        .map(|(_, v)| v);
    match (found.next(), found.next()) {
        (Some(v), None) => Some(v),
        _ => None,
    }
}

const NOT_CONFIGURED: &str = "This hub has no OIDC provider to sign in with.";

const UNREACHABLE: &str = "The identity provider could not be reached. Try again shortly.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_login_cookie_is_host_prefixed_and_crosses_the_providers_redirect() {
        let set = login_cookie("abc");
        assert!(set.starts_with("__Host-vk-hub-login=abc;"), "{set}");
        for attr in ["; Path=/;", "; HttpOnly;", "; Secure;", "; SameSite=Lax;"] {
            assert!(set.contains(attr), "{set}");
        }
        assert!(!set.contains("Domain="), "{set}");
        assert!(login_cookie("").ends_with("Max-Age=0"));
    }

    #[test]
    fn sign_ins_are_audited_once_per_identity_and_up_to_a_cap() {
        let mut audit = SignInAudit::default();
        assert!(audit.admit("a@x", 1000));
        assert!(!audit.admit("a@x", 1000 + SIGN_IN_AUDIT_EVERY - 1));
        assert!(audit.admit("a@x", 1000 + SIGN_IN_AUDIT_EVERY));
        // Past the cap, none is audited until the window ends.
        let mut audit = SignInAudit::default();
        let t = 5000;
        for n in 0..SIGN_IN_AUDIT_MAX {
            assert!(audit.admit(&format!("sub {n}"), t), "{n}");
        }
        assert!(!audit.admit("sub new", t + 1));
        assert!(!audit.admit("sub newer", t + SIGN_IN_AUDIT_WINDOW - 1));
        assert!(audit.admit("sub newer", t + SIGN_IN_AUDIT_WINDOW));
        assert!(audit.last.len() <= SIGN_IN_AUDIT_MAX as usize);
    }

    /// A clock stepped back ends the window, rather than leave the cap reached until the clock
    /// catches up.
    #[test]
    fn a_clock_stepped_back_starts_a_new_window() {
        let mut audit = SignInAudit::default();
        let t = 5000;
        for n in 0..SIGN_IN_AUDIT_MAX {
            assert!(audit.admit(&format!("sub {n}"), t), "{n}");
        }
        assert!(!audit.admit("sub new", t));
        assert!(audit.admit("sub new", t - 1));
    }

    #[test]
    fn only_one_login_cookie_is_read() {
        let headers = |v: &str| {
            let mut h = HeaderMap::new();
            h.append(header::COOKIE, v.parse().unwrap());
            h
        };
        assert_eq!(
            login_state(&headers("a=b; __Host-vk-hub-login=s")),
            Some("s")
        );
        assert_eq!(
            login_state(&headers("__Host-vk-hub-login=s; __Host-vk-hub-login=t")),
            None
        );
        assert_eq!(login_state(&headers("vk-hub-login=s")), None);
        assert_eq!(login_state(&headers("__Host-vk_login=s")), None);
    }
}
