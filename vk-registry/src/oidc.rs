//! OIDC routes `/login`, `/auth/callback` and `/logout`, backed by `vk-oidc`.
//! See that crate's documentation for the flow's security assumptions. This module owns
//! the registry's routes, sessions, landing pages and login-state cookie, which binds a
//! login to the browser that started it.
//!
//! That cookie is `__Host-`-prefixed, so no sibling or parent host can toss a `state` of its
//! own in; the prefix is dropped only on the loopback-plaintext deployment, where its
//! mandatory `Secure` is impossible (see [`login_cookie`]).

use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use vk_oidc::loggable;

use crate::accounts::EmailUpdate;
use crate::html;
use crate::{Body, body_of};
use crate::{ServerState, accounts, query_param};

/// Cap on a form POSTed to one of these routes. The only field is a CSRF token.
const MAX_FORM_BODY: usize = 4 * 1024;

/// The cookie that binds a login's `state` to the browser that started it, in its
/// `__Host-`-prefixed form: unwritable by any other host, at the price of the prefix's
/// mandatory `Path=/` (a sibling host tossing a cookie in is the attack that matters,
/// path scoping is not).
const LOGIN_COOKIE_HOST: &str = "__Host-vk_login";

/// The same cookie without the prefix, for the loopback-plaintext deployment: `__Host-`
/// requires `Secure`, which a browser will not store over plain HTTP.
const LOGIN_COOKIE: &str = "vk_login";

/// Where a browser lands when it has nowhere better to go — after a login with no
/// `?target=`, and after a logout.
const DEFAULT_TARGET: &str = "/browse";

/// `[oidc]` config, resolved (secret already read from its file).
pub struct OidcConfig {
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) public_url: String,
}

/// A configured provider, with the registry's callback and landing pages.
pub struct OidcClient {
    inner: vk_oidc::Client,
    public_url: String,
}

impl OidcClient {
    /// Build the client without network access or a tokio runtime. Discovery waits until
    /// the first login, keeping `into_state` synchronous and letting `vk-registry serve`
    /// start while the IdP is unreachable, so `/v2/` clients that do not use OIDC can work.
    pub fn new(cfg: OidcConfig) -> Self {
        let public_url = cfg.public_url.trim_end_matches('/').to_string();
        let inner = vk_oidc::Client::new(
            vk_oidc::Config {
                issuer: cfg.issuer,
                client_id: cfg.client_id,
                client_secret: cfg.client_secret,
                redirect_uri: format!("{public_url}/auth/callback"),
                post_logout_redirect_uri: format!("{public_url}{DEFAULT_TARGET}"),
            },
            vk_oidc::Landing {
                default: DEFAULT_TARGET,
                is_safe: is_safe_redirect_target,
            },
        );
        OidcClient {
            inner,
            public_url: cfg.public_url,
        }
    }

    pub fn issuer(&self) -> &str {
        self.inner.issuer()
    }

    pub(crate) fn public_url(&self) -> &str {
        &self.public_url
    }
}

/// `/login`, `/auth/callback`, `/logout` — reachable without a principal (a login page
/// gated on being logged in already would be unreachable). 404s if accounts mode is off
/// or `[oidc]` was never configured.
pub async fn route(state: &Arc<ServerState>, req: Request<Incoming>) -> Result<Response<Body>> {
    let crate::Authenticator::Accounts { db, oidc: client } = &state.auth else {
        return Ok(html_error(
            StatusCode::NOT_FOUND,
            "Accounts mode is not configured on this server.",
        ));
    };
    // `Secure` iff the browser's connection is TLS — which also decides both cookie
    // names, so it has to be the one answer the whole server uses.
    let secure = state.cookies_are_secure();
    let method = req.method().clone();
    match (req.uri().path(), &method) {
        ("/login", &Method::GET) => login(client, req.uri().query().unwrap_or(""), secure).await,
        ("/auth/callback", &Method::GET) => callback(client, db, &req, secure).await,
        // Logout changes state, so it is POST + CSRF-guarded: a `GET` would let any page
        // on the internet end a visitor's session with an `<img src>`.
        ("/logout", &Method::POST) => logout(client, db, req, secure).await,
        ("/login" | "/auth/callback" | "/logout", _) => Ok(html_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "That address does not accept this method.",
        )),
        _ => Ok(html_error(StatusCode::NOT_FOUND, "No such auth route.")),
    }
}

async fn login(client: &OidcClient, query: &str, secure: bool) -> Result<Response<Body>> {
    // Anything unsafe is replaced with [`DEFAULT_TARGET`] inside `login_url`, which is
    // where a `PendingLogin`'s target invariant is enforced.
    let target = query_param(query, "target").unwrap_or_default();
    let (url, state) = match client.inner.login_url(&target).await {
        Ok(v) => v,
        Err(e) => return Ok(upstream_failure("starting a login", &e)),
    };
    let mut res = redirect(&url)?;
    res.headers_mut().append(
        hyper::header::SET_COOKIE,
        login_cookie(&state, secure).parse()?,
    );
    Ok(res)
}

async fn callback(
    client: &OidcClient,
    db: &accounts::Db,
    req: &Request<Incoming>,
    secure: bool,
) -> Result<Response<Body>> {
    let query = req.uri().query().unwrap_or("");
    let cookie_state = login_cookie_value(req.headers(), secure);
    // A user who declines consent gets an `error`, not a `code`; say which. Both fields
    // are unauthenticated query input, so they are bounded and stripped of the control
    // characters that would otherwise forge whole log lines.
    if let Some(err) = query_param(query, "error") {
        let detail = query_param(query, "error_description").unwrap_or_default();
        eprintln!(
            "vk-registry: OIDC login refused by the provider: {} {}",
            loggable(&err),
            loggable(&detail)
        );
        // The login is over; do not leave it holding a slot until LOGIN_TTL.
        if let Some(state) = query_param(query, "state") {
            client.inner.abandon(&state, cookie_state.as_deref());
        }
        return done_with_login(
            html_error(
                StatusCode::BAD_REQUEST,
                "The identity provider did not complete this login.",
            ),
            secure,
        );
    }
    let (Some(code), Some(state_param)) = (query_param(query, "code"), query_param(query, "state"))
    else {
        return done_with_login(
            html_error(
                StatusCode::BAD_REQUEST,
                "This callback is missing its code or state.",
            ),
            secure,
        );
    };
    let (target, claims) = match client
        .inner
        .exchange(&code, &state_param, cookie_state.as_deref())
        .await
    {
        Ok(v) => v,
        Err(e) => {
            // The chain names endpoints and quotes provider text; it goes to the log,
            // not to an unauthenticated caller.
            eprintln!("vk-registry: OIDC login failed: {e:#}");
            return done_with_login(
                html_error(
                    StatusCode::BAD_REQUEST,
                    "This login could not be completed. Start again from the sign-in page.",
                ),
                secure,
            );
        }
    };
    let Some(subject) = claims.get("sub").and_then(|v| v.as_str()) else {
        eprintln!("vk-registry: the OIDC UserInfo response carried no sub claim");
        return done_with_login(
            html_error(
                StatusCode::BAD_GATEWAY,
                "The identity provider did not say who you are.",
            ),
            secure,
        );
    };
    // Claims are provider-supplied, stored, and rendered back into a page. `upsert_user`
    // bounds them, the way an API key's name is bounded where it enters the store — so
    // every caller gets that, not just this one.
    let email = email_claim(&claims);
    let name = claims.get("name").and_then(|v| v.as_str());
    let session = db
        .upsert_user(client.issuer(), subject, email, name)
        .and_then(|user| db.create_session(&user.id, accounts::SESSION_TTL));
    let session_id = match session {
        Ok(id) => id,
        Err(e) => {
            eprintln!("vk-registry: refusing an OIDC identity: {e:#}");
            return done_with_login(
                html_error(
                    StatusCode::BAD_GATEWAY,
                    "The identity provider's answer was not usable.",
                ),
                secure,
            );
        }
    };
    // A login supersedes whatever session this browser held: leaving the old one live
    // for up to SESSION_TTL is a credential nobody is watching.
    if let Some(old) = accounts::session_cookie(req.headers(), secure)
        && let Err(e) = db.delete_session(&old)
    {
        // The new session is already minted; failing to drop the old one is worth a log,
        // not a refusal to sign in.
        eprintln!("vk-registry: could not drop a superseded session: {e:#}");
    }
    let mut res = redirect(&target)?;
    res.headers_mut().append(
        hyper::header::SET_COOKIE,
        accounts::set_cookie_header(&session_id, secure).parse()?,
    );
    done_with_login(res, secure)
}

/// Every exit from the callback expires the login cookie: the login it named is over,
/// successfully or not, and leaving it set is a value the next attempt would trip over.
fn done_with_login(mut res: Response<Body>, secure: bool) -> Result<Response<Body>> {
    res.headers_mut()
        .append(hyper::header::SET_COOKIE, login_cookie("", secure).parse()?);
    Ok(res)
}

async fn logout(
    client: &OidcClient,
    db: &accounts::Db,
    req: Request<Incoming>,
    secure: bool,
) -> Result<Response<Body>> {
    let Some(id) = accounts::session_cookie(req.headers(), secure) else {
        // No cookie at all — and a `SameSite=Lax` cookie is sent with no cross-site POST,
        // so this is the branch every cross-site sign-out attempt lands in. It gets a bare
        // redirect: clearing a cookie here would let any page on the internet force a
        // visitor to sign in again, which is what the CSRF guard below exists to stop.
        // There is nothing to clear either way — the request presented no cookie.
        return redirect(DEFAULT_TARGET);
    };
    // The CSRF guard: only a page this server rendered for *this* session knows the
    // secret, so a cross-site POST cannot end the session. Everything below answers a
    // browser, so no `?` may escape to `handle`'s JSON 500 with an error chain in it.
    let expected = match db.session_csrf(&id) {
        Ok(v) => v,
        Err(e) => return Ok(internal_failure("reading a session's CSRF secret", &e)),
    };
    // The session is already gone — expired, or ended in another tab. There is nothing
    // left to protect, so this succeeds instead of answering 403 and leaving the browser
    // holding a cookie it can never use. Safe to clear without the CSRF check: the cookie
    // reached us on a POST, and an explicit `SameSite=Lax` one only does that same-site.
    let Some(expected) = expected else {
        return already_signed_out(secure);
    };
    let body = match crate::collect_capped(req, MAX_FORM_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(html_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "That sign-out request was too large.",
            ));
        }
    };
    if !csrf_ok(&expected, &body) {
        return Ok(html_error(
            StatusCode::FORBIDDEN,
            "This sign-out request did not come from a page this server rendered.",
        ));
    }
    if let Err(e) = db.delete_session(&id) {
        return Ok(internal_failure("ending a session", &e));
    }
    let target = client
        .inner
        .logout_url()
        .await
        // Not `/`: in accounts mode that is a bare JSON 401, which is a poor page to
        // land a person on after signing out.
        .unwrap_or_else(|| DEFAULT_TARGET.to_string());
    // `target` is a discovery endpoint `vk-oidc` already vetted, so this
    // cannot fail; fall back rather than let a `?` escape as a JSON 500 (see above).
    let mut res = redirect(&target).or_else(|_| redirect(DEFAULT_TARGET))?;
    res.headers_mut().append(
        hyper::header::SET_COOKIE,
        accounts::clear_cookie_header(secure).parse()?,
    );
    Ok(res)
}

/// The browser holds a cookie for a session that no longer exists. Clear it and land the
/// browser somewhere sensible — deliberately *not* the provider's `end_session_endpoint`:
/// bouncing an unauthenticated POST there would let any page sign a visitor out of their
/// identity provider. Only for a request that actually presented the cookie (see
/// [`logout`]); a request with none gets a redirect and no `Set-Cookie`.
fn already_signed_out(secure: bool) -> Result<Response<Body>> {
    let mut res = redirect(DEFAULT_TARGET)?;
    res.headers_mut().append(
        hyper::header::SET_COOKIE,
        accounts::clear_cookie_header(secure).parse()?,
    );
    Ok(res)
}

/// Whether a sign-out form body carries `expected`, this session's CSRF secret. Not
/// `from_utf8_lossy`: a body that is not UTF-8 carries no token this could match, and
/// replacement characters would be inventing bytes the client never sent.
fn csrf_ok(expected: &str, body: &[u8]) -> bool {
    std::str::from_utf8(body)
        .ok()
        .and_then(|b| form_field(b, "csrf"))
        .is_some_and(|p| crate::auth::constant_eq(expected.as_bytes(), p.as_bytes()))
}

fn redirect(location: &str) -> Result<Response<Body>> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, location)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        // Belt and braces: a 302's `Location` navigation carries the *original* request's
        // referrer, not this URL, so the callback's `code`/`state` would not have leaked
        // here anyway.
        .header(hyper::header::REFERRER_POLICY, "no-referrer")
        .body(body_of(Bytes::new()))
        .map_err(Into::into)
}

/// The `Set-Cookie` for the login-state cookie; an empty `state` expires it.
///
/// Over TLS it is `__Host-`-prefixed, which a browser accepts only with `Secure` and
/// `Path=/` and — the point — refuses to let any other host write. That trades the
/// callback-path scoping for tossing resistance: a sibling host planting a `state` of its
/// own is what breaks the browser binding, a cookie sent on more of this origin's paths
/// is not. On plain HTTP `Secure` is impossible, so the unprefixed name keeps its narrow
/// path instead.
fn login_cookie(state: &str, secure: bool) -> String {
    let max_age = if state.is_empty() {
        0
    } else {
        vk_oidc::LOGIN_TTL.as_secs()
    };
    let name = login_cookie_name(secure);
    if secure {
        format!("{name}={state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}")
    } else {
        format!("{name}={state}; Path=/auth/callback; HttpOnly; SameSite=Lax; Max-Age={max_age}")
    }
}

/// The login `state` this browser holds, under *only* the name [`login_cookie`] would
/// have written on this deployment. Reading both would give the `__Host-` prefix away: on
/// a TLS deployment the bare name is never set, so a bare cookie can only be one another
/// host tossed in — and accepting it restores exactly the login-CSRF this module's
/// browser binding exists to stop.
fn login_cookie_value(headers: &hyper::HeaderMap, secure: bool) -> Option<String> {
    accounts::cookie(headers, login_cookie_name(secure))
}

/// Which of the two names [`login_cookie`] writes on this deployment — and so the only
/// one [`login_cookie_value`] reads.
fn login_cookie_name(secure: bool) -> &'static str {
    if secure {
        LOGIN_COOKIE_HOST
    } else {
        LOGIN_COOKIE
    }
}

/// One field out of an `application/x-www-form-urlencoded` body — the same shape as a
/// query string, which is why [`query_param`] does the work.
fn form_field(body: &str, key: &str) -> Option<String> {
    query_param(body, key)
}

/// This server failed, not the caller — log the detail, say nothing about it.
fn internal_failure(what: &str, e: &anyhow::Error) -> Response<Body> {
    eprintln!("vk-registry: {what} failed: {e:#}");
    html_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong on the server. Try again shortly.",
    )
}

/// An error page for a caller who is, by definition, not signed in yet — so it renders
/// without the signed-in chrome, but with the same headers every other page here sets.
fn html_error(status: StatusCode, message: &str) -> Response<Body> {
    html::error(status, None, None, status.as_str(), message)
}

/// The provider, or the network to it, failed us — log the detail, tell the caller only
/// that it was not their fault.
fn upstream_failure(what: &str, e: &anyhow::Error) -> Response<Body> {
    eprintln!("vk-registry: {what} failed: {e:#}");
    html_error(
        StatusCode::BAD_GATEWAY,
        "The identity provider could not be reached. Try again shortly.",
    )
}

/// A `target` is safe to redirect a browser to after login only if it cannot leave this
/// origin. An allowlist, not a denylist: the only targets this server ever produces are
/// its own browser-facing pages, and a denylist has to anticipate every form a browser
/// treats as off-origin — `//host`, `/\host` (browsers read `\` as `/`), a tab or newline
/// before either, an embedded scheme. Enumerating what is allowed does not — so a page
/// added later has to be added here too, or it is simply not a landing target.
fn is_safe_redirect_target(t: &str) -> bool {
    let known = t == DEFAULT_TARGET || t.starts_with("/browse/") || t == "/settings/keys";
    known
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b':'))
        && !t.contains("..")
}

/// What a sign-in says of the user's email. Operators promote a user by email (`accounts
/// grant-admin`), so an address the provider marks unverified (`email_verified: false`, or
/// `"false"` as some spell it) clears the stored one: where anyone can claim an address
/// before proving it, the first to sign in as `admin@corp` would otherwise be the one
/// promoted. A provider that sends no `email_verified` at all is taken at its word, so
/// providers that never send the claim keep working; that also means one that lets users
/// change their address unverified without saying so (the "nOAuth" pattern) is trusted,
/// which is why the promotion commands name the issuer and subject they act on.
fn email_claim(claims: &serde_json::Value) -> EmailUpdate<'_> {
    match vk_oidc::email(claims) {
        vk_oidc::Email::Unverified => EmailUpdate::Clear,
        vk_oidc::Email::Asserted(e) => EmailUpdate::Set(e),
        vk_oidc::Email::Absent => EmailUpdate::Keep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unverified_email_is_not_kept() {
        use serde_json::json;
        let email = "admin@corp.example";
        let set = EmailUpdate::Set(email);
        assert_eq!(email_claim(&json!({"email": email})), set);
        assert_eq!(
            email_claim(&json!({"email": email, "email_verified": true})),
            set
        );
        // Neither a bool nor a string: not a "false", so the address is kept.
        assert_eq!(
            email_claim(&json!({"email": email, "email_verified": null})),
            set
        );
        assert_eq!(
            email_claim(&json!({"email": email, "email_verified": 0})),
            set
        );
        let clear = EmailUpdate::Clear;
        assert_eq!(
            email_claim(&json!({"email": email, "email_verified": false})),
            clear
        );
        assert_eq!(
            email_claim(&json!({"email": email, "email_verified": "false"})),
            clear
        );
        assert_eq!(email_claim(&json!({"email_verified": false})), clear);
        assert_eq!(email_claim(&json!({})), EmailUpdate::Keep);
    }

    /// The validator is what stands between `?target=` and an open redirect, so the
    /// bypasses a denylist would have let through are the point of this test.
    #[test]
    fn redirect_target_safety() {
        assert!(is_safe_redirect_target("/browse"));
        assert!(is_safe_redirect_target("/settings/keys"));
        // only the page itself: the revoke sub-path is POST-only, so landing a browser
        // there after login would land it on a 404
        assert!(!is_safe_redirect_target("/settings/keys/abc/revoke"));
        assert!(!is_safe_redirect_target("/settings/keysevil"));
        assert!(!is_safe_redirect_target("/settings"));
        assert!(is_safe_redirect_target("/browse/team-a"));
        assert!(is_safe_redirect_target(
            "/browse/team-a/app/manifests/sha256:abc"
        ));

        // off-origin, in every form a browser accepts
        assert!(!is_safe_redirect_target("//evil.example/x"));
        assert!(!is_safe_redirect_target("/\\evil.example/x"));
        assert!(!is_safe_redirect_target("/\t//evil.example"));
        assert!(!is_safe_redirect_target("/\n/evil.example"));
        assert!(!is_safe_redirect_target("https://evil.example"));
        assert!(!is_safe_redirect_target("/browse/../../evil"));
        assert!(!is_safe_redirect_target("evil.example"));
        assert!(!is_safe_redirect_target("/"));
        assert!(!is_safe_redirect_target(""));
        // and nothing that `HeaderValue` would refuse, which would 500 after login
        assert!(!is_safe_redirect_target("/browse/a\rb"));
        assert!(!is_safe_redirect_target("/browse/a b"));
    }

    /// Over TLS the login cookie is `__Host-`-prefixed, which is what stops a sibling
    /// host from tossing in a `state` of its own and defeating the browser binding; the
    /// prefix mandates `Secure` + `Path=/`. On plain HTTP — the loopback deployment the
    /// config permits — `Secure` is impossible, so the bare name keeps its narrow path
    /// instead; marking it `Secure` anyway would make the browser drop it and every
    /// login would then fail at the callback with no cookie to match.
    #[test]
    fn the_login_cookie_is_host_prefixed_wherever_secure_is_possible() {
        let set = login_cookie("abc", true);
        assert!(set.starts_with("__Host-vk_login=abc;"), "{set}");
        assert!(set.contains("; Secure"), "{set}");
        assert!(set.contains("HttpOnly"), "{set}");
        // the prefix is only honoured with Path=/ and no Domain
        assert!(set.contains("Path=/"), "{set}");
        assert!(!set.contains("Domain="), "{set}");
        assert!(set.contains("SameSite=Lax"), "{set}");
        assert!(!set.contains("Max-Age=0"), "{set}");

        let plain = login_cookie("abc", false);
        assert!(plain.starts_with("vk_login=abc;"), "{plain}");
        assert!(!plain.contains("Secure"), "{plain}");
        assert!(plain.contains("Path=/auth/callback"), "{plain}");

        // an empty state expires the cookie, keeping the rest of the attributes so the
        // browser matches the one it holds
        for secure in [true, false] {
            let cleared = login_cookie("", secure);
            assert!(cleared.contains("Max-Age=0"), "{cleared}");
            assert_eq!(
                cleared.split('=').next(),
                login_cookie("abc", secure).split('=').next(),
                "the same name, or the browser keeps the one it holds"
            );
        }
    }

    /// Only the name this deployment would have *written* is read. On a TLS deployment
    /// the bare `vk_login` is never set, so a bare cookie can only be one another host
    /// tossed in — reading it as a fallback would hand back the login CSRF the prefix is
    /// there to stop, whether or not the real cookie is present alongside it.
    #[test]
    fn a_login_cookie_under_the_other_name_is_not_read() {
        let headers = |v: &str| {
            let mut h = hyper::HeaderMap::new();
            h.append(hyper::header::COOKIE, v.parse().unwrap());
            h
        };
        assert_eq!(
            login_cookie_value(&headers("__Host-vk_login=ours"), true).as_deref(),
            Some("ours")
        );
        assert_eq!(
            login_cookie_value(&headers("__Host-vk_login=ours; vk_login=tossed"), true).as_deref(),
            Some("ours"),
            "the tossed one does not win"
        );
        assert_eq!(
            login_cookie_value(&headers("vk_login=tossed"), true),
            None,
            "and it is not a fallback either"
        );

        // on the loopback-plaintext deployment the bare name is the one written, and the
        // prefixed one is what this server could not have set
        assert_eq!(
            login_cookie_value(&headers("vk_login=ours"), false).as_deref(),
            Some("ours")
        );
        assert_eq!(
            login_cookie_value(&headers("__Host-vk_login=other"), false),
            None
        );
        assert_eq!(login_cookie_value(&headers("other=x"), true), None);
    }

    /// The CSRF guard on `/logout`: only a form this server rendered for *this* session
    /// carries the secret, so a cross-site POST cannot end the session.
    #[test]
    fn a_sign_out_body_without_this_sessions_csrf_secret_is_refused() {
        assert!(csrf_ok("s3cr3t", b"csrf=s3cr3t"));
        assert!(csrf_ok("s3cr3t", b"other=x&csrf=s3cr3t"));

        assert!(!csrf_ok("s3cr3t", b"csrf=wrong"), "another session's token");
        assert!(!csrf_ok("s3cr3t", b""), "no token at all");
        assert!(!csrf_ok("s3cr3t", b"csrf="), "an empty token");
        assert!(!csrf_ok("s3cr3t", b"csrf=s3cr3"), "a prefix of the token");
        assert!(!csrf_ok("s3cr3t", b"csrf=s3cr3t\xff"), "not even close");
        assert!(
            !csrf_ok("s3cr3t", &[0xff, 0xfe]),
            "a body that is not UTF-8"
        );
    }

    /// A sign-out with nothing to sign out of clears the browser's stale cookie and lands
    /// it locally — never at the provider, or any page could sign a visitor out of their
    /// IdP with a cross-site POST.
    #[test]
    fn signing_out_of_nothing_clears_the_cookie_locally() {
        let res = already_signed_out(true).expect("a response");
        assert_eq!(res.status(), StatusCode::FOUND);
        let location = res.headers().get(hyper::header::LOCATION).unwrap();
        assert_eq!(location, DEFAULT_TARGET);
        let cleared = res
            .headers()
            .get(hyper::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(
            cleared.starts_with(accounts::SESSION_COOKIE_HOST),
            "{cleared}"
        );
    }
}
