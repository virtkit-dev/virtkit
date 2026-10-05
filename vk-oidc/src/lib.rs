//! The OIDC relying party `vk-registry` and `vk-hub` sign people in with: the Authorization
//! Code flow with PKCE, hand-rolled (no OIDC crate) — deliberately, not for lack of one: it
//! keeps this on the same TLS backend (`reqwest` + rustls) the workspace already links,
//! instead of risking a second TLS stack (openssl/aws-lc-rs) pulled in by an OIDC crate's own
//! HTTP-client feature flags (see the workspace `Cargo.toml`'s comments on
//! `reqwest`/`rustls`), and the flow is short: discover, redirect, exchange a code for a
//! token, call UserInfo for claims. Each caller keeps its own routes, cookies and sessions.
//!
//! What the flow does and does not rely on:
//!
//! - **`state` is bound to the browser.** The caller stores the `state` [`Client::login_url`]
//!   returns in an `HttpOnly`, `__Host-`-prefixed cookie, and [`Client::exchange`] requires
//!   that cookie to agree with the callback's `state`, which is also kept here. The prefix is
//!   what makes the cookie unwritable by a sibling or parent host, so a neighbour on the same
//!   registrable domain cannot *toss* a state of its own in and defeat the binding. The
//!   server-side entry alone would only prove "some login started on this server
//!   recently", which lets an attacker who completes a login at the provider hand the
//!   victim a callback URL and log the victim in *as the attacker*. Single-use and a TTL
//!   are replay protection; the cookie is what makes it CSRF protection.
//! - **PKCE (S256) is sent even though this is a confidential client.** The client secret
//!   protects the exchange, but not against code *injection*: a code that leaks (a
//!   provider-side open redirect, a `Referer`, a proxy log) is otherwise redeemable
//!   against a victim's callback. RFC 9700 asks for PKCE here for that reason.
//! - **The id_token's JWT is not parsed or verified, and does not need to be.** Claims
//!   come from UserInfo over a bearer token this client obtained itself, in a TLS
//!   request authenticated with the `client_secret`; the identity namespace is the
//!   *configured* issuer, never one the provider asserts. What id_token verification
//!   would add — binding the token to this client and this nonce — PKCE plus the
//!   cookie-bound state already cover for the code path.
//! - **The provider's discovery document is checked against the configured issuer**, and
//!   the issuer must be `https` unless it is loopback: every endpoint below is taken from
//!   that document, so an attacker who can substitute it chooses who logs in.
//!
//! One browser runs one login at a time per caller: the state cookie has a single name, so
//! starting a second login abandons the first, and that first tab has to start over.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rand::Rng;
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "fake-idp"))]
pub mod fake_idp;

/// How long an in-flight login (redirected to the provider, not yet back) stays valid.
/// Generous next to a human's login time, tight next to a session's lifetime. Also the
/// lifetime of the caller's login cookie.
pub const LOGIN_TTL: Duration = Duration::from_secs(5 * 60);

/// Ceiling on in-flight logins. A login route is necessarily unauthenticated, so without a
/// cap anyone who can reach the port can grow this map for [`LOGIN_TTL`] at will. At the
/// cap the oldest entries are evicted rather than the new login refused — refusing would
/// let one flood close sign-in for everybody, including the admin who would fix it.
const MAX_PENDING_LOGINS: usize = 4096;

/// Cap on a document read from the provider. A discovery or UserInfo document is a few
/// KiB; anything near this is a provider trying to exhaust us.
const MAX_IDP_BODY: usize = 256 * 1024;

/// Cap on a provider- or query-supplied string reproduced in a log line.
const MAX_LOG_FIELD_LEN: usize = 256;

/// Ceiling on a client-secret file, trailing newline included — it is checked against the
/// bytes on disk, before the value is trimmed.
pub const MAX_CLIENT_SECRET_LEN: u64 = 4096;

/// Provider configuration with the client secret already read from its file.
pub struct Config {
    /// Without a trailing slash.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Where the provider sends the browser back with a code; the operator registers it
    /// with the provider.
    pub redirect_uri: String,
    /// Where an RP-initiated logout at the provider lands the browser.
    pub post_logout_redirect_uri: String,
}

/// The caller's landing pages after sign-in.
pub struct Landing {
    /// Where a login with no acceptable target lands.
    pub default: &'static str,
    /// Whether a requested target is a same-origin page of the caller's. An allowlist: it is
    /// all that stands between a login's `?target=` and an open redirect.
    pub is_safe: fn(&str) -> bool,
}

/// The provider as this flow needs it: an HTTP client and the endpoints its discovery
/// document names. Built together, on the first login — see [`Client::provider`].
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
    /// where to send the browser back once login completes — always one
    /// [`Landing::is_safe`] accepts, or [`Landing::default`], because [`Client::login_url`]
    /// is the only thing that builds this.
    target: String,
    /// the PKCE verifier whose S256 challenge went to the provider
    verifier: String,
    /// when this login stops being redeemable — [`LOGIN_TTL`] after it started. Stored as
    /// the deadline rather than the start so there is one place the TTL is applied.
    expires_at: Instant,
}

/// A configured provider, ready to redirect logins to and exchange codes against.
/// Discovery is lazy and cached: a provider that is briefly unreachable must not stop the
/// caller's server from starting.
pub struct Client {
    cfg: Config,
    landing: Landing,
    provider: tokio::sync::OnceCell<Provider>,
    /// state → pending login. Swept opportunistically (on the next `login_url` call)
    /// rather than by a background task — login volume is human-scale.
    pending: Mutex<HashMap<String, PendingLogin>>,
}

impl Client {
    /// Build the client. No network, and no tokio runtime needed: both the HTTP client
    /// and the discovery round-trip are deferred to the first login. The HTTP client is
    /// built on the process's default rustls crypto provider, which the caller installs.
    pub fn new(cfg: Config, landing: Landing) -> Self {
        Client {
            cfg,
            landing,
            provider: tokio::sync::OnceCell::new(),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
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
                // one this client was configured to trust. OIDC Discovery requires this
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

    /// Start a login: mint a single-use `state` and a PKCE verifier, remember where to
    /// land the browser afterwards, and return the provider's authorization URL together
    /// with the `state` the caller must put in the browser's login cookie. A `target`
    /// that [`Landing::is_safe`] rejects is replaced here, not refused — this is the one
    /// place a `PendingLogin` is built, so it is where that invariant belongs.
    pub async fn login_url(&self, target: &str) -> Result<(String, String)> {
        let provider = self.provider().await?;
        let state = random_token(24);
        let verifier = random_token(32);
        let challenge = b64url(Sha256::digest(verifier.as_bytes()).as_slice());
        let target = if (self.landing.is_safe)(target) {
            target
        } else {
            self.landing.default
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
            percent_encode(&self.cfg.redirect_uri),
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
    pub async fn exchange(
        &self,
        code: &str,
        state: &str,
        cookie_state: Option<&str>,
    ) -> Result<(String, serde_json::Value)> {
        // The cookie is what makes `state` a CSRF defence rather than mere replay
        // protection: without it, a callback URL an attacker completed at the provider
        // would log the victim in as the attacker.
        let cookie_state = cookie_state.context("this browser did not start a login here")?;
        if !constant_eq(cookie_state.as_bytes(), state.as_bytes()) {
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
        // Hand-built `application/x-www-form-urlencoded` body — avoids needing
        // reqwest's `form`/`multipart` feature on top of what the workspace already
        // enables (`rustls-no-provider`, `json`, `query`, `stream`; see `Cargo.toml`).
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.cfg.redirect_uri.as_str()),
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
            .header("content-type", "application/x-www-form-urlencoded")
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
    /// [`Client::exchange`] does: nobody else gets to cancel a login.
    pub fn abandon(&self, state: &str, cookie_state: Option<&str>) {
        if cookie_state.is_some_and(|c| constant_eq(c.as_bytes(), state.as_bytes())) {
            self.pending.lock().unwrap().remove(state);
        }
    }

    /// The RP-initiated logout URL, if the provider advertises `end_session_endpoint`;
    /// `None` leaves logout local-only (still safe — the session is deleted either way).
    /// `client_id` is sent because a provider that validates the post-logout redirect
    /// against a registered client needs it (or an `id_token_hint`, which this flow does
    /// not keep) and rejects the request without either.
    pub async fn logout_url(&self) -> Option<String> {
        let provider = self.provider().await.ok()?;
        let endpoint = provider.endpoints.end_session_endpoint.as_ref()?;
        Some(format!(
            "{}client_id={}&post_logout_redirect_uri={}",
            query_prefix(endpoint),
            percent_encode(&self.cfg.client_id),
            percent_encode(&self.cfg.post_logout_redirect_uri),
        ))
    }
}

/// What a sign-in's claims say of the user's email.
#[derive(Debug, PartialEq, Eq)]
pub enum Email<'a> {
    /// An address the provider did not mark unverified.
    Asserted(&'a str),
    /// The provider marks the address unverified (`email_verified: false`, or `"false"` as
    /// some spell it), or says only that: no address may be taken from this sign-in.
    Unverified,
    /// No address, and nothing said of one.
    Absent,
}

/// What `claims` say of the user's email. An address the provider marks unverified is not
/// one: where anyone can claim an address before proving it, the first to sign in as
/// `admin@corp` would otherwise be taken for admin. A provider that sends no
/// `email_verified` at all is taken at its word, so providers that never send the claim
/// keep working; that also means one that lets users change their address unverified
/// without saying so (the "nOAuth" pattern) is trusted.
pub fn email(claims: &serde_json::Value) -> Email<'_> {
    let unverified = match claims.get("email_verified") {
        Some(serde_json::Value::Bool(b)) => !b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("false"),
        _ => false,
    };
    match claims.get("email").and_then(|v| v.as_str()) {
        _ if unverified => Email::Unverified,
        Some(e) => Email::Asserted(e),
        None => Email::Absent,
    }
}

/// Check a configured base URL — an issuer, or where the caller is reached: no control
/// characters (it ends up in a URL fetched or handed to a browser as a `Location`), `https`
/// unless loopback, and no query or fragment, since paths are appended to it. `what` names
/// the key in the error, e.g. `"[oidc] issuer"`.
pub fn check_base_url(what: &str, url: &str) -> Result<()> {
    if url.chars().any(char::is_control) {
        bail!("{what} may not contain control characters: {url:?}");
    }
    if !url.starts_with("https://") && !is_local_url(url) {
        bail!(
            "{what} must be https (or a loopback address): {url:?} would put the client \
             secret and the session cookie on the wire in cleartext"
        );
    }
    if url.contains('?') || url.contains('#') {
        bail!("{what} is a base URL, with no query or fragment: {url:?}");
    }
    Ok(())
}

/// Read a client secret from `path`: not through a symlink, at most
/// [`MAX_CLIENT_SECRET_LEN`] bytes, text, trimmed, and not empty. `check_mode` is handed the
/// opened file, for the caller's warning about a secret others can read: checked on *that*
/// descriptor, so the file it reports on is the one read.
pub fn read_client_secret(path: &Path, check_mode: impl FnOnce(&std::fs::File)) -> Result<String> {
    // `O_NOFOLLOW`: a credential is not read through someone else's symlink.
    let file = {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        opts.open(path)
            .with_context(|| format!("opening {}", path.display()))?
    };
    check_mode(&file);
    // Bounded: a client secret is tens of bytes, and a file that is not one at all (a
    // device, a log) must not be read into memory unbounded. One byte over the cap is an
    // error rather than a silent truncation, which would otherwise show up as an
    // unexplained rejection at the token endpoint. Read as bytes and length-checked before
    // the UTF-8 decode, so an oversize file is reported as oversize rather than as a decode
    // failure at a cut codepoint.
    let mut raw = Vec::new();
    file.take(MAX_CLIENT_SECRET_LEN + 1)
        .read_to_end(&mut raw)
        .with_context(|| format!("reading {}", path.display()))?;
    if raw.len() as u64 > MAX_CLIENT_SECRET_LEN {
        bail!(
            "{} is over {MAX_CLIENT_SECRET_LEN} bytes; that is not a client secret",
            path.display()
        );
    }
    let secret = std::str::from_utf8(&raw)
        .with_context(|| format!("{} is not text", path.display()))?
        .trim()
        .to_string();
    if secret.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(secret)
}

/// True for an `http://` URL whose host is loopback: plain HTTP does not leave the
/// machine there, so it is the one case accepted without TLS.
pub fn is_local_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // `http://[::1]@evil.example/` has host `evil.example`, not `::1`: a guard that can be
    // fooled by its own parsing is worse than none, so userinfo is simply refused.
    if authority.contains('@') {
        return false;
    }
    // A bracketed IPv6 literal keeps its colons; everything else splits on the port's.
    let host = match authority.strip_prefix('[') {
        // …and it must actually end at the bracket, with only a port after it.
        Some(v6) => match v6.split_once(']') {
            Some((host, after)) if after.is_empty() || after.starts_with(':') => host,
            _ => return false,
        },
        None => authority.split(':').next().unwrap_or(""),
    };
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

/// A provider- or query-supplied string as it may appear in a log line: bounded, and
/// with control characters replaced — an embedded newline would otherwise forge whole
/// lines in the log.
pub fn loggable(s: &str) -> String {
    s.chars()
        .take(MAX_LOG_FIELD_LEN)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
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

/// A URL prefix ready for the first parameter: the endpoint plus `?` or `&`, since a
/// provider's endpoint may already carry a query string.
fn query_prefix(endpoint: &str) -> String {
    let sep = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{sep}")
}

/// An endpoint out of a discovery document is usable only if it is an absolute URL that
/// clears the same bar the configured issuer did — `https`, or `http` on loopback — and
/// carries nothing a `Location` header would refuse. The issuer comparison authenticates
/// the *document*, not the URLs inside it.
fn is_usable_endpoint(u: &str) -> bool {
    (u.starts_with("https://") || is_local_url(u)) && !u.chars().any(char::is_control)
}

/// `n` random bytes, hex: a login's `state` and PKCE verifier.
fn random_token(n: usize) -> String {
    use std::fmt::Write;
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    let mut s = String::with_capacity(n * 2);
    for b in buf {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Percent-encode one query-parameter value: everything but the unreserved set
/// (`A-Za-z0-9-._~`) becomes `%XX`.
fn percent_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => write!(out, "%{b:02X}").expect("writing to a String cannot fail"),
        }
    }
    out
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
mod tests;
