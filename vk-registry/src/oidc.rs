//! OIDC login: `/login`, `/auth/callback`, `/logout`. Hand-rolled against the
//! Authorization Code flow with PKCE (no OIDC crate) — deliberately, not for lack of
//! one: it keeps this on the same TLS backend (`reqwest` + rustls) the rest of the crate
//! already links, instead of risking a second TLS stack (openssl/aws-lc-rs) pulled in by
//! an OIDC crate's own HTTP-client feature flags (see `Cargo.toml`'s comments on
//! `reqwest`/`rustls`), and the flow is short: discover, redirect, exchange a code for a
//! token, call UserInfo for claims.
//!
//! What the flow does and does not rely on:
//!
//! - **`state` is bound to the browser.** `/login` stores it in an `HttpOnly`
//!   `__Host-`-prefixed cookie *and* server-side; the callback requires both to agree.
//!   The prefix is what makes the cookie unwritable by a sibling or parent host, so a
//!   neighbour on the same registrable domain cannot *toss* a state of its own in and
//!   defeat the binding; it is dropped only on the loopback-plaintext deployment, where
//!   the prefix's mandatory `Secure` is impossible (see [`login_cookie`]). The
//!   server-side entry alone would only prove "some login started on this server
//!   recently", which lets an attacker who completes a login at the provider hand the
//!   victim a callback URL and log the victim in *as the attacker*. Single-use and a TTL
//!   are replay protection; the cookie is what makes it CSRF protection.
//! - **PKCE (S256) is sent even though this is a confidential client.** The client secret
//!   protects the exchange, but not against code *injection*: a code that leaks (a
//!   provider-side open redirect, a `Referer`, a proxy log) is otherwise redeemable
//!   against a victim's callback. RFC 9700 asks for PKCE here for that reason.
//! - **The id_token's JWT is not parsed or verified, and does not need to be.** Claims
//!   come from UserInfo over a bearer token this server obtained itself, in a TLS
//!   request authenticated with the `client_secret`; the identity namespace is the
//!   *configured* issuer, never one the provider asserts. What id_token verification
//!   would add — binding the token to this client and this nonce — PKCE plus the
//!   cookie-bound state already cover for the code path.
//! - **The provider's discovery document is checked against the configured issuer**, and
//!   the issuer must be `https` unless it is loopback: every endpoint below is taken from
//!   that document, so an attacker who can substitute it chooses who logs in.
//!
//! One browser runs one login at a time: the state cookie has a single name, so starting
//! a second login abandons the first, and that first tab has to start over.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};

use crate::html;
use crate::{ServerState, accounts, percent_encode, query_param};

/// How long an in-flight login (redirected to the provider, not yet back) stays valid.
/// Generous next to a human's login time, tight next to a session's lifetime.
const LOGIN_TTL: Duration = Duration::from_secs(5 * 60);

/// Ceiling on in-flight logins. `/login` is necessarily unauthenticated, so without a
/// cap anyone who can reach the port can grow this map for [`LOGIN_TTL`] at will. At the
/// cap the oldest entries are evicted rather than the new login refused — refusing would
/// let one flood close sign-in for everybody, including the admin who would fix it.
const MAX_PENDING_LOGINS: usize = 4096;

/// Cap on a document read from the provider. A discovery or UserInfo document is a few
/// KiB; anything near this is a provider trying to exhaust us.
const MAX_IDP_BODY: usize = 256 * 1024;

/// Cap on a provider- or query-supplied string reproduced in a log line. Claims are
/// bounded where they enter the store instead (`accounts::clamp_claim`).
const MAX_LOG_FIELD_LEN: usize = 256;

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

/// The provider as this flow needs it: an HTTP client and the endpoints its discovery
/// document names. Built together, on the first login — see [`OidcClient::provider`].
struct Provider {
    http: reqwest::Client,
    endpoints: Discovered,
}

/// What `{issuer}/.well-known/openid-configuration` states, the fields this flow needs.
struct Discovered {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    /// RP-initiated logout target, if the provider advertises one (not all do).
    end_session_endpoint: Option<String>,
    /// True if the provider advertises `client_secret_basic` (the OIDC default) — some
    /// are registered for it exclusively and reject a secret in the body.
    secret_in_header: bool,
}

struct PendingLogin {
    /// where to send the browser back once login completes — always a `/browse` path,
    /// because [`OidcClient::login_url`] is the only thing that builds this and replaces
    /// anything [`is_safe_redirect_target`] rejects.
    target: String,
    /// the PKCE verifier whose S256 challenge went to the provider
    verifier: String,
    /// when this login stops being redeemable — [`LOGIN_TTL`] after it started. Stored as
    /// the deadline rather than the start so there is one place the TTL is applied.
    expires_at: Instant,
}

/// A configured provider, ready to redirect logins to and exchange codes against.
/// Discovery is lazy and cached: a provider that is briefly unreachable must not stop the
/// server from starting, because the `/v2/` clients that never touch OIDC depend on it.
pub struct OidcClient {
    cfg: OidcConfig,
    provider: tokio::sync::OnceCell<Provider>,
    /// state → pending login. Swept opportunistically (on the next `login_url` call)
    /// rather than by a background task — login volume is human-scale.
    pending: Mutex<HashMap<String, PendingLogin>>,
}

impl OidcClient {
    /// Build the client. No network, and no tokio runtime needed: both the HTTP client
    /// and the discovery round-trip are deferred to the first login, so `into_state` can
    /// stay synchronous and a `vk-registry serve` whose IdP is briefly unreachable still
    /// starts — the `/v2/` clients that never touch OIDC depend on it starting.
    pub fn new(cfg: OidcConfig) -> Self {
        OidcClient {
            cfg,
            provider: tokio::sync::OnceCell::new(),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
    }

    pub(crate) fn public_url(&self) -> &str {
        &self.cfg.public_url
    }

    /// The provider's HTTP client and endpoints, built once and cached. A failed attempt
    /// is not cached, so a provider that comes back later works without a restart.
    async fn provider(&self) -> Result<&Provider> {
        self.provider
            .get_or_try_init(|| async {
                let http = reqwest::Client::builder()
                    // A provider that accepts a connection and then says nothing must not
                    // pin a request task, or the login route, forever.
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(10))
                    // No OIDC endpoint has any business redirecting, and a 307/308 from
                    // the token endpoint would replay the request *body* — which on the
                    // `client_secret_post` branch carries the client secret — to whatever
                    // host the redirect names. A redirect surfaces as an error status.
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .context("building the OIDC HTTP client")?;
                let url = format!(
                    "{}/.well-known/openid-configuration",
                    self.cfg.issuer.trim_end_matches('/')
                );
                let doc = get_json(&http, &url, None).await?;
                // The document defines every endpoint used below, so it has to be the
                // one this server was configured to trust. OIDC Discovery requires this
                // comparison for exactly that reason.
                let stated = doc
                    .get("issuer")
                    .and_then(|v| v.as_str())
                    .context("discovery document is missing \"issuer\"")?;
                if stated.trim_end_matches('/') != self.cfg.issuer.trim_end_matches('/') {
                    bail!(
                        "discovery document states issuer {stated:?}, but this server is \
                         configured for {:?}",
                        self.cfg.issuer
                    );
                }
                // Every endpoint below is fetched, or handed to a browser as a
                // `Location`, so each has to clear the same bar the issuer did: an
                // absolute `https` (or loopback `http`) URL with nothing in it a header
                // would refuse. The issuer check pins the document, not what it names.
                let field = |k: &str| -> Result<String> {
                    let v = doc
                        .get(k)
                        .and_then(|v| v.as_str())
                        .with_context(|| format!("discovery document is missing {k:?}"))?;
                    if !is_usable_endpoint(v) {
                        bail!("discovery document's {k:?} is not an https (or loopback) URL");
                    }
                    Ok(v.to_string())
                };
                let methods = doc
                    .get("token_endpoint_auth_methods_supported")
                    .and_then(|v| v.as_array());
                let endpoints = Discovered {
                    authorization_endpoint: field("authorization_endpoint")?,
                    token_endpoint: field("token_endpoint")?,
                    userinfo_endpoint: field("userinfo_endpoint")?,
                    // Optional, and a browser is redirected to it: one that does not
                    // clear the bar is dropped, leaving logout local-only, rather than
                    // failing discovery and with it every login.
                    end_session_endpoint: doc
                        .get("end_session_endpoint")
                        .and_then(|v| v.as_str())
                        .filter(|v| is_usable_endpoint(v))
                        .map(str::to_string),
                    // `client_secret_basic` is the default a provider must support, so
                    // prefer it and fall back to the body only when the provider says it
                    // takes `client_secret_post` and not basic.
                    secret_in_header: match methods {
                        Some(m) => {
                            let has = |name: &str| m.iter().any(|v| v.as_str() == Some(name));
                            has("client_secret_basic") || !has("client_secret_post")
                        }
                        None => true,
                    },
                };
                Ok(Provider { http, endpoints })
            })
            .await
    }

    fn redirect_uri(&self) -> String {
        format!(
            "{}/auth/callback",
            self.cfg.public_url.trim_end_matches('/')
        )
    }

    /// Start a login: mint a single-use `state` and a PKCE verifier, remember where to
    /// land the browser afterwards, and return the provider's authorization URL together
    /// with the `state` the caller must put in the browser's login cookie. A `target`
    /// that is not a safe same-origin one is replaced here, not rejected — this is the
    /// one place a `PendingLogin` is built, so it is where that invariant belongs.
    async fn login_url(&self, target: &str) -> Result<(String, String)> {
        let provider = self.provider().await?;
        let state = accounts::random_token(24);
        let verifier = accounts::random_token(32);
        let challenge = b64url(Sha256::digest(verifier.as_bytes()).as_slice());
        let target = if is_safe_redirect_target(target) {
            target
        } else {
            DEFAULT_TARGET
        };
        {
            let now = Instant::now();
            let mut pending = self.pending.lock().unwrap();
            pending.retain(|_, p| p.expires_at > now);
            // Evict the soonest to expire — the oldest, while `LOGIN_TTL` is one constant
            // — rather than refuse the new login: see [`MAX_PENDING_LOGINS`]. Only reached
            // once the map is full, so the sort is not on the normal path.
            if pending.len() >= MAX_PENDING_LOGINS {
                let mut by_age: Vec<(Instant, String)> = pending
                    .iter()
                    .map(|(k, p)| (p.expires_at, k.clone()))
                    .collect();
                by_age.sort_unstable_by_key(|(t, _)| *t);
                let excess = pending.len() + 1 - MAX_PENDING_LOGINS;
                for (_, k) in by_age.into_iter().take(excess) {
                    pending.remove(&k);
                }
            }
            pending.insert(
                state.clone(),
                PendingLogin {
                    target: target.to_string(),
                    verifier,
                    expires_at: now + LOGIN_TTL,
                },
            );
        }
        let url = format!(
            "{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}\
             &code_challenge={}&code_challenge_method=S256",
            query_prefix(&provider.endpoints.authorization_endpoint),
            percent_encode(&self.cfg.client_id),
            percent_encode(&self.redirect_uri()),
            percent_encode("openid email profile"),
            percent_encode(&state),
            percent_encode(&challenge),
        );
        Ok((url, state))
    }

    /// Redeem an authorization `code` for the caller's claims: require the browser's
    /// cookie to name the same login as the query's `state`, consume it, exchange the
    /// code (with the PKCE verifier), then call UserInfo. Returns the original login's
    /// `target` alongside the claims.
    async fn exchange(
        &self,
        code: &str,
        state: &str,
        cookie_state: Option<&str>,
    ) -> Result<(String, serde_json::Value)> {
        // The cookie is what makes `state` a CSRF defence rather than mere replay
        // protection: without it, a callback URL an attacker completed at the provider
        // would log the victim in as the attacker.
        let cookie_state = cookie_state.context("this browser did not start a login here")?;
        if !crate::auth::constant_eq(cookie_state.as_bytes(), state.as_bytes()) {
            bail!("the login state does not match this browser's");
        }
        let provider = self.provider().await?;
        // A `remove` — the state is a 192-bit random lookup key, not a secret compared
        // byte-wise, so a map lookup leaks nothing worth timing.
        let pending = self
            .pending
            .lock()
            .unwrap()
            .remove(state)
            .context("unknown or already-used login state")?;
        if Instant::now() >= pending.expires_at {
            bail!("login state expired");
        }
        let redirect_uri = self.redirect_uri();
        // Hand-built `application/x-www-form-urlencoded` body — avoids needing
        // reqwest's `form`/`multipart` feature on top of what the workspace already
        // enables (`rustls-no-provider`, `json`, `query`, `stream`; see `Cargo.toml`).
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", self.cfg.client_id.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        let mut req = provider.http.post(&provider.endpoints.token_endpoint);
        if provider.endpoints.secret_in_header {
            req = req.basic_auth(&self.cfg.client_id, Some(&self.cfg.client_secret));
        } else {
            fields.push(("client_secret", self.cfg.client_secret.as_str()));
        }
        let body = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let res = req
            .header(
                hyper::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .context("exchanging the authorization code")?;
        let res =
            ok_or_provider_error(res, "the token endpoint rejected the authorization code").await?;
        let token = json_capped(res, "the token response").await?;
        let access_token = token
            .get("access_token")
            .and_then(|v| v.as_str())
            .context("token response is missing access_token")?;
        let claims = get_json(
            &provider.http,
            &provider.endpoints.userinfo_endpoint,
            Some(access_token),
        )
        .await
        .context("calling the UserInfo endpoint")?;
        Ok((pending.target, claims))
    }

    /// Drop a pending login the provider has already refused, rather than leaving it to
    /// [`LOGIN_TTL`]. Requires the browser's cookie to name it, for the same reason
    /// [`OidcClient::exchange`] does: nobody else gets to cancel a login.
    fn abandon(&self, state: &str, cookie_state: Option<&str>) {
        if cookie_state.is_some_and(|c| crate::auth::constant_eq(c.as_bytes(), state.as_bytes())) {
            self.pending.lock().unwrap().remove(state);
        }
    }

    /// The RP-initiated logout URL, if the provider advertises `end_session_endpoint`;
    /// `None` leaves logout local-only (still safe — the session is deleted either way).
    /// `client_id` is sent because a provider that validates the post-logout redirect
    /// against a registered client needs it (or an `id_token_hint`, which this flow does
    /// not keep) and rejects the request without either.
    async fn logout_url(&self) -> Option<String> {
        let provider = self.provider().await.ok()?;
        let endpoint = provider.endpoints.end_session_endpoint.as_ref()?;
        Some(format!(
            "{}client_id={}&post_logout_redirect_uri={}",
            query_prefix(endpoint),
            percent_encode(&self.cfg.client_id),
            percent_encode(&format!(
                "{}{DEFAULT_TARGET}",
                self.cfg.public_url.trim_end_matches('/')
            )),
        ))
    }
}

/// GET a JSON document from the provider, refusing one too large to be a discovery or
/// UserInfo response.
async fn get_json(
    http: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> Result<serde_json::Value> {
    let mut req = http.get(url);
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    let res = req
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let res = ok_or_provider_error(res, &format!("{url} returned an error status")).await?;
    json_capped(res, url).await
}

/// Pass a 2xx through; turn anything else into an error carrying the (capped, log-safe)
/// body the provider explained itself with. `error_for_status` discards that body, and on
/// the token endpoint it is the whole diagnosis — `invalid_grant` (the code is stale) and
/// `invalid_client` (the secret is wrong) are the same status otherwise.
async fn ok_or_provider_error(res: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    let status = res.status();
    if status.is_success() {
        return Ok(res);
    }
    let body = bytes_capped(res, what).await.unwrap_or_default();
    let detail = loggable(std::str::from_utf8(&body).unwrap_or("<non-utf8 body>"));
    bail!("{what} ({status}): {detail}");
}

/// A provider's response body, refused past [`MAX_IDP_BODY`]. Nothing this flow reads is
/// more than a few KiB, so an unbounded read is only a way for the provider to exhaust
/// this server's memory.
async fn json_capped(res: reqwest::Response, what: &str) -> Result<serde_json::Value> {
    let buf = bytes_capped(res, what).await?;
    serde_json::from_slice(&buf).with_context(|| format!("parsing {what}"))
}

/// The bytes of a provider's response, refused past [`MAX_IDP_BODY`].
async fn bytes_capped(mut res: reqwest::Response, what: &str) -> Result<Vec<u8>> {
    if let Some(len) = res.content_length()
        && len > MAX_IDP_BODY as u64
    {
        bail!("{what} returned {len} bytes, over the {MAX_IDP_BODY}-byte cap");
    }
    // Read to the cap rather than past it: a chunked response declares no length, so the
    // check above sees nothing and `bytes()` would buffer whatever the provider sends.
    let mut buf = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .with_context(|| format!("reading {what}"))?
    {
        if buf.len() + chunk.len() > MAX_IDP_BODY {
            bail!("{what} returned more than the {MAX_IDP_BODY}-byte cap");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// `/login`, `/auth/callback`, `/logout` — reachable without a principal (a login page
/// gated on being logged in already would be unreachable). 404s if accounts mode is off
/// or `[oidc]` was never configured.
pub async fn route(
    state: &Arc<ServerState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
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

async fn login(client: &OidcClient, query: &str, secure: bool) -> Result<Response<Full<Bytes>>> {
    // Anything unsafe is replaced with [`DEFAULT_TARGET`] inside `login_url`, which is
    // where a `PendingLogin`'s target invariant is enforced.
    let target = query_param(query, "target").unwrap_or_default();
    let (url, state) = match client.login_url(&target).await {
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
) -> Result<Response<Full<Bytes>>> {
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
            client.abandon(&state, cookie_state.as_deref());
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
    let email = claims.get("email").and_then(|v| v.as_str());
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
fn done_with_login(mut res: Response<Full<Bytes>>, secure: bool) -> Result<Response<Full<Bytes>>> {
    res.headers_mut()
        .append(hyper::header::SET_COOKIE, login_cookie("", secure).parse()?);
    Ok(res)
}

async fn logout(
    client: &OidcClient,
    db: &accounts::Db,
    req: Request<Incoming>,
    secure: bool,
) -> Result<Response<Full<Bytes>>> {
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
        .logout_url()
        .await
        // Not `/`: in accounts mode that is a bare JSON 401, which is a poor page to
        // land a person on after signing out.
        .unwrap_or_else(|| DEFAULT_TARGET.to_string());
    // `target` is a discovery endpoint `is_usable_endpoint` already vetted, so this
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
fn already_signed_out(secure: bool) -> Result<Response<Full<Bytes>>> {
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

fn redirect(location: &str) -> Result<Response<Full<Bytes>>> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, location)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        // Belt and braces: a 302's `Location` navigation carries the *original* request's
        // referrer, not this URL, so the callback's `code`/`state` would not have leaked
        // here anyway.
        .header(hyper::header::REFERRER_POLICY, "no-referrer")
        .body(Full::new(Bytes::new()))
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
        LOGIN_TTL.as_secs()
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

/// A URL prefix ready for the first parameter: the endpoint plus `?` or `&`, since a
/// provider's endpoint may already carry a query string.
fn query_prefix(endpoint: &str) -> String {
    let sep = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{sep}")
}

/// A provider- or query-supplied string as it may appear in a log line: bounded, and
/// with control characters replaced — an embedded newline would otherwise forge whole
/// `vk-registry: …` lines in the log.
fn loggable(s: &str) -> String {
    s.chars()
        .take(MAX_LOG_FIELD_LEN)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// An endpoint out of a discovery document is usable only if it is an absolute URL that
/// clears the same bar the configured issuer did — `https`, or `http` on loopback — and
/// carries nothing a `Location` header would refuse. The issuer comparison authenticates
/// the *document*, not the URLs inside it.
fn is_usable_endpoint(u: &str) -> bool {
    (u.starts_with("https://") || crate::config::is_local_url(u))
        && !u.chars().any(char::is_control)
}

/// One field out of an `application/x-www-form-urlencoded` body — the same shape as a
/// query string, which is why [`query_param`] does the work.
fn form_field(body: &str, key: &str) -> Option<String> {
    query_param(body, key)
}

/// This server failed, not the caller — log the detail, say nothing about it.
fn internal_failure(what: &str, e: &anyhow::Error) -> Response<Full<Bytes>> {
    eprintln!("vk-registry: {what} failed: {e:#}");
    html_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong on the server. Try again shortly.",
    )
}

/// An error page for a caller who is, by definition, not signed in yet — so it renders
/// without the signed-in chrome, but with the same headers every other page here sets.
fn html_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    html::error(status, None, None, status.as_str(), message)
}

/// The provider, or the network to it, failed us — log the detail, tell the caller only
/// that it was not their fault.
fn upstream_failure(what: &str, e: &anyhow::Error) -> Response<Full<Bytes>> {
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

/// Unpadded base64url, for the PKCE `code_challenge` (RFC 7636 §4.2).
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b = |i: usize| *chunk.get(i).unwrap_or(&0) as u32;
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        let take = chunk.len() + 1;
        for i in 0..take {
            let idx = ((n >> (18 - 6 * i)) & 0x3f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::net::SocketAddr;

    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

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

    #[test]
    fn pkce_challenge_matches_the_rfc_7636_example() {
        // RFC 7636 appendix B's verifier/challenge pair
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            b64url(Sha256::digest(verifier.as_bytes()).as_slice()),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
    }

    #[test]
    fn a_query_prefix_respects_an_endpoint_that_already_has_parameters() {
        assert_eq!(
            query_prefix("https://idp/authorize"),
            "https://idp/authorize?"
        );
        assert_eq!(
            query_prefix("https://idp/authorize?tenant=a"),
            "https://idp/authorize?tenant=a&"
        );
    }

    /// A minimal fake OIDC provider: discovery + token + userinfo, all in one
    /// in-process hyper server — the same "spin up a real server on an ephemeral port"
    /// pattern `tests/relay_e2e.rs` uses for its fake upstream. Gives this module real
    /// end-to-end coverage of discovery, the authorization-URL shape, and the code→
    /// token→claims exchange, without a live external IdP.
    async fn fake_idp(basic_auth: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        fake_idp_stating(basic_auth, DocOverride::default()).await
    }

    /// What a test wants the fake IdP's discovery document to *claim*, where that differs
    /// from the truth. All-`None` is an honest document.
    #[derive(Clone, Default)]
    struct DocOverride {
        issuer: Option<String>,
        token_endpoint: Option<String>,
    }

    impl DocOverride {
        fn issuer(v: &str) -> Self {
            DocOverride {
                issuer: Some(v.to_string()),
                ..Default::default()
            }
        }

        fn token_endpoint(v: &str) -> Self {
            DocOverride {
                token_endpoint: Some(v.to_string()),
                ..Default::default()
            }
        }
    }

    /// [`fake_idp`], but its discovery document claims what `doc` says instead of the
    /// truth — a substituted document, in other words.
    async fn fake_idp_stating(
        basic_auth: bool,
        doc: DocOverride,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let stated = doc;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let stated = stated.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let stated = stated.clone();
                        async move {
                            Ok::<_, Infallible>(
                                fake_idp_respond(req, addr, basic_auth, stated).await,
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    /// A failure here answers with a 400 and a reason rather than asserting: this runs in
    /// a spawned connection task, where a panic would reach the test as an opaque
    /// connection error instead of a named failure.
    async fn fake_idp_respond(
        req: Request<Incoming>,
        addr: SocketAddr,
        basic_auth: bool,
        doc: DocOverride,
    ) -> Response<Full<Bytes>> {
        let path = req.uri().path().to_string();
        let issuer = doc.issuer.unwrap_or_else(|| format!("http://{addr}"));
        let token_endpoint = doc
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
                    if basic_auth { ["client_secret_basic"] } else { ["client_secret_post"] },
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
                let authed = if basic_auth {
                    // base64("vk-registry:s3cr3t")
                    header_secret.as_deref() == Some("Basic dmstcmVnaXN0cnk6czNjcjN0")
                } else {
                    header_secret.is_none() && form.contains("client_secret=s3cr3t")
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
                json(serde_json::json!({
                    "sub": "user-42",
                    "email": "alice@example.com",
                    "name": "Alice"
                }))
            }
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        }
    }

    fn client_for(addr: SocketAddr) -> OidcClient {
        let _ = rustls::crypto::ring::default_provider().install_default();
        OidcClient::new(OidcConfig {
            issuer: format!("http://{addr}"),
            client_id: "vk-registry".to_string(),
            client_secret: "s3cr3t".to_string(),
            public_url: "https://registry.internal".to_string(),
        })
    }

    /// The state out of a login URL, which is also what the browser's cookie must carry.
    fn state_of(url: &str) -> String {
        url.split("state=")
            .nth(1)
            .expect("a state param")
            .split('&')
            .next()
            .expect("a value")
            .to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_login_and_exchange_round_trip_against_a_fake_provider() {
        let (addr, _server) = fake_idp(true).await;
        let client = client_for(addr);

        let (url, state) = client
            .login_url("/browse/team-a")
            .await
            .expect("a login url");
        assert!(url.starts_with(&format!("http://{addr}/authorize?")));
        assert!(url.contains("client_id=vk-registry"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains(&percent_encode("https://registry.internal/auth/callback")));
        assert_eq!(state_of(&url), state, "the cookie's state is the URL's");

        let (target, claims) = client
            .exchange("the-code", &state, Some(&state))
            .await
            .expect("the exchange succeeds");
        assert_eq!(target, "/browse/team-a");
        assert_eq!(claims["sub"], "user-42");
        assert_eq!(claims["email"], "alice@example.com");

        // single-use: the same state cannot be redeemed twice
        assert!(
            client
                .exchange("the-code", &state, Some(&state))
                .await
                .is_err()
        );
    }

    /// A provider registered for `client_secret_post` must still work — the secret moves
    /// from the header into the body, and nowhere else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_secret_goes_where_the_provider_says_it_should() {
        let (addr, _server) = fake_idp(false).await;
        let client = client_for(addr);
        let (_, state) = client.login_url("/browse").await.expect("a login url");
        client
            .exchange("the-code", &state, Some(&state))
            .await
            .expect("post-authenticated exchange succeeds");
    }

    /// The property `state` exists for: a callback the victim's browser never started
    /// must not log the victim in. Without the cookie check, an attacker who completes a
    /// login at the provider can hand over the callback URL and own the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_callback_without_this_browsers_cookie_is_refused() {
        let (addr, _server) = fake_idp(true).await;
        let client = client_for(addr);
        let (_, state) = client.login_url("/browse").await.expect("a login url");

        assert!(
            client.exchange("the-code", &state, None).await.is_err(),
            "no cookie must not authenticate"
        );
        assert!(
            client
                .exchange("the-code", &state, Some("some-other-login"))
                .await
                .is_err(),
            "another browser's cookie must not authenticate"
        );
        // and the refusals did not consume the state, so the real browser still can
        client
            .exchange("the-code", &state, Some(&state))
            .await
            .expect("the browser that started the login still completes it");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exchange_rejects_an_unknown_state() {
        let (addr, _server) = fake_idp(true).await;
        let client = client_for(addr);
        assert!(
            client
                .exchange("code", "not-a-real-state", Some("not-a-real-state"))
                .await
                .is_err()
        );
    }

    /// Every endpoint this flow uses comes out of the discovery document, so a document
    /// that names an issuer other than the configured one is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_discovery_document_for_another_issuer_is_refused() {
        // served from 127.0.0.1, but claiming to be somebody else entirely
        let (addr, _server) =
            fake_idp_stating(true, DocOverride::issuer("https://idp.evil.example")).await;
        let client = client_for(addr);
        let e = client
            .login_url("/browse")
            .await
            .expect_err("a mismatched issuer is refused")
            .to_string();
        assert!(e.contains("issuer"), "{e}");
    }

    /// The issuer comparison authenticates the document's *origin*, not the URLs inside
    /// it — so an otherwise-honest provider naming a cleartext `token_endpoint`, which is
    /// where the client secret and the code would go, fails discovery outright rather
    /// than at the first exchange.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_discovery_document_naming_a_cleartext_endpoint_is_refused() {
        let (addr, _server) = fake_idp_stating(
            true,
            DocOverride::token_endpoint("http://idp.example/token"),
        )
        .await;
        let client = client_for(addr);
        let e = client
            .login_url("/browse")
            .await
            .expect_err("a cleartext endpoint is refused")
            .to_string();
        assert!(e.contains("token_endpoint"), "{e}");
    }

    #[test]
    fn a_usable_endpoint_is_absolute_https_or_loopback_and_header_safe() {
        assert!(is_usable_endpoint("https://idp.example/token"));
        assert!(is_usable_endpoint("http://127.0.0.1:9000/token"));
        assert!(!is_usable_endpoint("http://idp.example/token"));
        assert!(!is_usable_endpoint("/token"));
        // and nothing a `Location` header would refuse, which would 500 mid-flow
        assert!(!is_usable_endpoint("https://idp.example/token\r\nX: y"));
    }

    /// A login in flight costs memory until it expires, and `/login` needs no
    /// credential, so the map that holds them is capped — and at the cap it *evicts*
    /// rather than refuses. Refusing would let 4096 unauthenticated GETs close sign-in
    /// for everyone until the TTL ran out, including for whoever would fix it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flood_of_logins_is_evicted_not_allowed_to_close_sign_in() {
        let (addr, _server) = fake_idp(true).await;
        let client = client_for(addr);
        {
            let mut pending = client.pending.lock().unwrap();
            for i in 0..MAX_PENDING_LOGINS {
                pending.insert(
                    format!("state-{i}"),
                    PendingLogin {
                        target: DEFAULT_TARGET.to_string(),
                        verifier: "v".to_string(),
                        expires_at: Instant::now() + LOGIN_TTL,
                    },
                );
            }
        }
        let (_, state) = client
            .login_url("/browse")
            .await
            .expect("a login still starts at the cap");
        let pending = client.pending.lock().unwrap();
        assert_eq!(pending.len(), MAX_PENDING_LOGINS, "the cap still holds");
        assert!(
            pending.contains_key(&state),
            "the new login is the one kept"
        );
    }

    /// An in-flight login is redeemable for [`LOGIN_TTL`] and no longer: a code the
    /// browser sits on for an hour must not still open a session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_login_past_its_ttl_is_refused_and_swept() {
        let (addr, _server) = fake_idp(true).await;
        let client = client_for(addr);
        let stale = || PendingLogin {
            target: DEFAULT_TARGET.to_string(),
            verifier: "v".to_string(),
            // due now, so it is expired by the time anything compares against it
            expires_at: Instant::now(),
        };
        client
            .pending
            .lock()
            .unwrap()
            .insert("stale".to_string(), stale());

        let e = client
            .exchange("the-code", "stale", Some("stale"))
            .await
            .expect_err("an expired login is refused")
            .to_string();
        assert!(e.contains("expired"), "{e}");

        // and the opportunistic sweep on the next /login drops it rather than leaving it
        client
            .pending
            .lock()
            .unwrap()
            .insert("stale".to_string(), stale());
        client.login_url("/browse").await.expect("a login url");
        assert!(!client.pending.lock().unwrap().contains_key("stale"));
    }

    /// A refused login does not sit in the map until its TTL — but only the browser that
    /// started it gets to cancel it, or anyone who learned a `state` could.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_refusal_releases_the_login_only_for_its_own_browser() {
        let (addr, _server) = fake_idp(true).await;
        let client = client_for(addr);
        let (_, state) = client.login_url("/browse").await.expect("a login url");

        client.abandon(&state, None);
        client.abandon(&state, Some("another-browsers-login"));
        assert!(
            client.pending.lock().unwrap().contains_key(&state),
            "nobody else may cancel this login"
        );

        client.abandon(&state, Some(&state));
        assert!(client.pending.lock().unwrap().is_empty(), "its own may");
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

    /// A log line is not a place an identity provider gets to write: a newline in an
    /// `error_description` would otherwise forge whole `vk-registry: …` entries.
    #[test]
    fn a_logged_provider_string_cannot_forge_a_log_line() {
        assert_eq!(loggable("access_denied"), "access_denied");
        assert_eq!(
            loggable("a\nvk-registry: all good\r\tb"),
            "a\u{fffd}vk-registry: all good\u{fffd}\u{fffd}b"
        );
        assert_eq!(
            loggable(&"x".repeat(MAX_LOG_FIELD_LEN + 10))
                .chars()
                .count(),
            MAX_LOG_FIELD_LEN
        );
    }
}
