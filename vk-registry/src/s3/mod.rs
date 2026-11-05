//! S3 under `/s3/`, path-style: the gate S3 clients are answered by. A request is
//! authenticated by a SigV4 `Authorization` header whose access key id is a credential this
//! registry already takes (an API key, a hub token, the shared bearer, or the shared Basic
//! user) and whose signing secret is that same string (the Basic password for the user), so
//! nothing new is stored; or by the bearer, Basic or session credential the other routes
//! take. Every answer carries an `x-amz-request-id`, and refusals are S3's XML `Error`.
//! Presigned URLs and temporary credentials are refused.
//!
//! Past the gate, a bucket is a top-level directory of `files/` and an object a key below
//! one, served over the object layer the WebDAV view shares ([`crate::files`]): [`bucket`]
//! answers the service and its buckets, [`list`] a bucket's listings, [`object`] the
//! objects, with [`chunked`] decoding the `aws-chunked` bodies SDKs upload them in.
//! Operations not served yet answer `NotImplemented`.

mod bucket;
mod chunked;
mod conditional;
mod list;
mod meta;
mod object;
mod path;
mod range;
mod sigv4;
mod xml;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{
    AUTHORIZATION, DATE, HeaderMap, HeaderValue, RETRY_AFTER, X_CONTENT_TYPE_OPTIONS,
};
use hyper::{Method, Request, Response, StatusCode};
use vk_hub_proto::token::Claims;

use crate::files::{MAX_OBJECT, PutError};
use crate::{Authenticator, Authz, Body, ServerState, accounts, hubtoken};

/// Whether `path` is one this module answers.
pub(crate) fn is_path(path: &str) -> bool {
    path == "/s3" || path.starts_with("/s3/")
}

/// How much of a request body is read before answering a refusal decided before the caller
/// is known: enough for a small write to see its answer rather than a reset, not so much
/// that anyone who can reach the port can make the server read a large upload for nothing.
const PRE_AUTH_DRAIN: u64 = 64 * 1024;

/// The header naming each request, for a client's report to be matched to a server line.
const REQUEST_ID: &str = "x-amz-request-id";

/// Serve one `/s3/…` request, from its credentials on: [`crate::route`] hands every such
/// request here before its own gate when S3 is on.
pub(crate) async fn route(state: &ServerState, req: Request<Incoming>) -> Result<Response<Body>> {
    let ctx = Ctx {
        id: accounts::random_token(8),
        path: req.uri().path().to_string(),
    };
    let id = &ctx.id;
    let mut resp = match serve(state, req, &ctx).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("vk-registry: S3 request {id} failed: {e:#}");
            internal_error(&ctx)
        }
    };
    let headers = resp.headers_mut();
    headers.insert(REQUEST_ID, HeaderValue::from_str(id)?);
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(resp)
}

/// What every answer to a request names: its id and the path it asked for.
#[derive(Clone)]
struct Ctx {
    id: String,
    path: String,
}

impl Ctx {
    fn error(&self, status: StatusCode, code: &str, message: &str) -> Response<Body> {
        xml::error(status, code, message, &[], &self.path, &self.id)
    }

    fn not_implemented(&self) -> Response<Body> {
        self.error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "this registry does not serve that operation",
        )
    }

    fn access_denied(&self) -> Response<Body> {
        self.error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the credential grants nothing for this bucket or key",
        )
    }

    fn too_large(&self) -> Response<Body> {
        self.error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "EntityTooLarge",
            "an object is at most 4 GiB",
        )
    }
}

fn internal_error(ctx: &Ctx) -> Response<Body> {
    ctx.error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        "the server could not answer; its log names this request id",
    )
}

/// Who a request was authenticated as: what [`Authz`] borrows from.
enum Who {
    /// Shared-secret or open mode, where the gate is the whole authorization model.
    NoScopes,
    Principal(accounts::Principal),
    Token(Claims),
}

impl Who {
    fn authz(&self) -> Authz<'_> {
        match self {
            Who::NoScopes => Authz::NoScopes,
            Who::Principal(p) => Authz::Accounts(p),
            Who::Token(c) => Authz::Token(c),
        }
    }
}

async fn serve(state: &ServerState, req: Request<Incoming>, ctx: &Ctx) -> Result<Response<Body>> {
    let headers = req.headers();
    // Browsers attach cookies or Basic credentials to cross-site requests, as on every
    // other machine route.
    if !matches!(req.method(), &Method::GET | &Method::HEAD) && crate::cross_site(headers) {
        let resp = ctx.error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "a write to this registry cannot come from another site's page",
        );
        return before_auth(req, resp).await;
    }
    // A credential in a URL ends up in logs, proxies' included.
    if is_presigned(req.uri().query().unwrap_or("")) {
        let resp = ctx.error(
            StatusCode::BAD_REQUEST,
            "AuthorizationQueryParametersError",
            "presigned URLs are not accepted: sign the Authorization header",
        );
        return before_auth(req, resp).await;
    }
    if headers.contains_key("x-amz-security-token") {
        let resp = ctx.error(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "temporary credentials are not accepted: sign with a key of this registry",
        );
        return before_auth(req, resp).await;
    }
    let signed = headers
        .get(AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(b"AWS4-HMAC-SHA256 "));
    let who = if signed {
        signed_by(state, &req, ctx)
    } else {
        presented(state, &req, ctx).map(|who| (who, None))
    };
    let (who, seed) = match who {
        Ok(who) => who,
        Err(resp) => return before_auth(req, *resp).await,
    };

    // A hub managing the registry may make it refuse writes for a while.
    if state.store.read_only() && crate::is_store_write(req.method(), &ctx.path) {
        let mut resp = ctx.error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "the registry is read-only for now",
        );
        resp.headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("60"));
        return refuse(req, resp, ctx).await;
    }
    operate(state, &who.authz(), seed, req, ctx).await
}

/// The query parameter an AWS SDK adds to name the operation it calls, which says nothing
/// the method and path do not.
const OPERATION_HINT: &str = "x-id";

/// The subresource a query names (`location`, `attributes`, `uploads`…): `None` for a query
/// of [`OPERATION_HINT`] at most, `Some("")` when it names more than one parameter or names
/// one with a value — which nothing served here takes.
fn subresource(query: &str) -> Option<&str> {
    let mut names = query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter(|p| p.split_once('=').map_or(*p, |(n, _)| n) != OPERATION_HINT);
    let first = names.next()?;
    Some(match (first.split_once('='), names.next()) {
        (None | Some((_, "")), None) => first.trim_end_matches('='),
        _ => "",
    })
}

/// An authenticated request, to the operation its method, path and query name. What is not
/// served answers `NotImplemented` once the body is read, as every refusal past the gate does.
/// `seed` is what a signed `aws-chunked` body's signatures are checked against.
async fn operate(
    state: &ServerState,
    authz: &Authz<'_>,
    seed: Option<chunked::Seed>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    let target = match path::parse(&ctx.path) {
        Ok(target) => target,
        Err(why) => {
            let resp = ctx.error(StatusCode::BAD_REQUEST, why.code, why.message);
            return refuse(req, resp, ctx).await;
        }
    };
    let query = req.uri().query().unwrap_or("").to_string();
    let sub = subresource(&query);
    let method = req.method().clone();
    match (target, &method, sub) {
        (path::Target::Service, &Method::GET, None) => bucket::list(state, authz, req, ctx).await,
        (path::Target::Bucket(b), &Method::HEAD, None) => {
            bucket::head(state, authz, b, req, ctx).await
        }
        (path::Target::Bucket(b), &Method::GET, Some("location")) => {
            bucket::location(state, authz, b, req, ctx).await
        }
        (path::Target::Bucket(b), &Method::GET, _) if list::is_listing(&query) => {
            list::list(state, authz, b, &query, req, ctx).await
        }
        (path::Target::Object { segs, .. }, &Method::GET | &Method::HEAD, None) => {
            object::get(state, authz, segs, method == Method::HEAD, req, ctx).await
        }
        (path::Target::Object { segs, .. }, &Method::GET, Some("attributes")) => {
            object::attributes(state, authz, segs, req, ctx).await
        }
        (path::Target::Object { segs, .. }, &Method::PUT, None) => {
            object::put(state, authz, segs, seed, req, ctx).await
        }
        (path::Target::Object { segs, .. }, &Method::DELETE, None) => {
            object::delete(state, authz, segs, req, ctx).await
        }
        _ => refuse(req, ctx.not_implemented(), ctx).await,
    }
}

/// Answer `resp` once the request body has been read through, as after every refusal of an
/// authenticated request: a status sent with request bytes unread resets the connection,
/// which a client sees instead of the answer. A body past the object cap is refused with 413
/// instead.
async fn refuse(req: Request<Incoming>, resp: Response<Body>, ctx: &Ctx) -> Result<Response<Body>> {
    Ok(drain(req, ctx).await?.unwrap_or(resp))
}

/// Read a request's body through and discard it: `Some(413)` if it crosses the object cap.
async fn drain(req: Request<Incoming>, ctx: &Ctx) -> Result<Option<Response<Body>>> {
    let sink = &mut tokio::io::sink();
    match crate::files::drain_into(sink, req.into_body(), MAX_OBJECT, &mut |_| {}).await {
        Ok(_) => Ok(None),
        Err(PutError::TooLarge) => Ok(Some(ctx.too_large())),
        Err(PutError::Failed(e)) => Err(e),
    }
}

/// Answer `resp` to a request refused before it was authenticated, having read at most
/// [`PRE_AUTH_DRAIN`] of its body (and the frame that crossed it).
async fn before_auth(req: Request<Incoming>, resp: Response<Body>) -> Result<Response<Body>> {
    crate::files::drain_up_to(req.into_body(), PRE_AUTH_DRAIN).await;
    Ok(resp)
}

/// Whether the query carries SigV4's query-string authentication.
fn is_presigned(query: &str) -> bool {
    query.split('&').any(|pair| {
        let name = pair.split_once('=').map_or(pair, |(n, _)| n);
        matches!(
            name,
            "X-Amz-Algorithm" | "X-Amz-Credential" | "X-Amz-Signature"
        )
    })
}

/// A request without a SigV4 header, authenticated as the other routes authenticate it: a
/// hub token, then the mode's own bearer, Basic or session credential. Refused with S3's 403
/// rather than the 401 challenge, which an S3 client does not answer.
fn presented(
    state: &ServerState,
    req: &Request<Incoming>,
    ctx: &Ctx,
) -> std::result::Result<Who, Box<Response<Body>>> {
    let denied = || {
        let message = if req.headers().contains_key(AUTHORIZATION) {
            "the credential was refused"
        } else {
            "this registry needs a credential: sign the request with a key of this registry"
        };
        Box::new(ctx.error(StatusCode::FORBIDDEN, "AccessDenied", message))
    };
    if let Some(claims) = token(state, req.headers(), denied)? {
        return Ok(Who::Token(claims));
    }
    match &state.auth {
        Authenticator::Accounts { db, .. } => {
            match accounts::resolve_principal(db, req, state.cookies_are_secure()) {
                Ok(Some(p)) => Ok(Who::Principal(p)),
                Ok(None) => Err(denied()),
                Err(e) => Err(resolve_failed(e, ctx)),
            }
        }
        Authenticator::Shared(auth) if auth.allows(req.headers()) => Ok(Who::NoScopes),
        Authenticator::Shared(_) => Err(denied()),
    }
}

/// The hub token `headers` present, checked: `None` when they present none or tokens are
/// not taken (the mode then decides), `refused` when the token is not good.
fn token(
    state: &ServerState,
    headers: &HeaderMap,
    refused: impl FnOnce() -> Box<Response<Body>>,
) -> std::result::Result<Option<Claims>, Box<Response<Body>>> {
    let Some(t) = hubtoken::presented(headers) else {
        return Ok(None);
    };
    match state.tokens.check(&t, vk_peer::now_secs()) {
        Some(Ok(claims)) => Ok(Some(claims)),
        Some(Err(why)) => {
            state.tokens.log_refusal(&why);
            Err(refused())
        }
        None => Ok(None),
    }
}

/// The answer when the accounts database could not be read: the release taking over is
/// asked again, anything else is logged under the request's id.
fn resolve_failed(e: anyhow::Error, ctx: &Ctx) -> Box<Response<Body>> {
    if accounts::is_handed_over_error(&e) {
        return Box::new(crate::ask_again(ctx.error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "this registry is updating; retry",
        )));
    }
    eprintln!(
        "vk-registry: S3 request {}: resolving a credential: {e:#}",
        ctx.id
    );
    Box::new(internal_error(ctx))
}

/// A request with a SigV4 header. In order: the header parses and names S3's scope; the
/// request's time is on the scope's day and within [`sigv4::MAX_SKEW_SECS`] of the server's;
/// the access key id is authenticated exactly as a bearer would be, by the resolvers the
/// other routes use; only then is the secret it maps to used as a key, to check the
/// signature. On a server with no credential configured, an id that is not a hub token is
/// taken with its signature unchecked, as nothing else is checked there. A request whose
/// body is a signed `aws-chunked` stream also gets the seed its chunks' signatures chain
/// from, which holds the signing key until the body has been read.
fn signed_by(
    state: &ServerState,
    req: &Request<Incoming>,
    ctx: &Ctx,
) -> std::result::Result<(Who, Option<chunked::Seed>), Box<Response<Body>>> {
    let headers = req.headers();
    let malformed = |why: &str| {
        Box::new(ctx.error(StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed", why))
    };
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| malformed("the Authorization header is not text"))?;
    let credential = sigv4::parse_authorization(value).map_err(malformed)?;
    if let Some(why) = sigv4::s3_refusal(&credential) {
        return Err(malformed(why));
    }

    let now = vk_peer::now_secs();
    let stamp = headers
        .get("x-amz-date")
        .or_else(|| headers.get(DATE))
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    match sigv4::check_clock(stamp, credential.date, now) {
        Ok(()) => {}
        Err(sigv4::Clock::Unreadable) => {
            return Err(Box::new(ctx.error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "a signed request needs an x-amz-date header as YYYYMMDDTHHMMSSZ",
            )));
        }
        Err(sigv4::Clock::OtherDay) => {
            return Err(malformed(
                "the credential's date is not the day of x-amz-date",
            ));
        }
        Err(sigv4::Clock::Skewed) => {
            let server_time = sigv4::format_time(now);
            let skew = (sigv4::MAX_SKEW_SECS * 1000).to_string();
            return Err(Box::new(xml::error(
                StatusCode::FORBIDDEN,
                "RequestTimeTooSkewed",
                "the difference between the request time and the server's time is too large",
                &[
                    ("RequestTime", stamp),
                    ("ServerTime", &server_time),
                    ("MaxAllowedSkewMilliseconds", &skew),
                ],
                &ctx.path,
                &ctx.id,
            )));
        }
    }

    // The id, authenticated as the bearer it would be: the one header map built here holds
    // nothing else, so no resolver can accept through it what it would not accept as sent.
    let unknown = || {
        Box::new(ctx.error(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            "the access key id is not a credential of this registry",
        ))
    };
    let as_bearer = bearer_of(credential.id).ok_or_else(unknown)?;
    let (who, secret) = match (token(state, &as_bearer, unknown)?, &state.auth) {
        (Some(claims), _) => (Who::Token(claims), Some(credential.id)),
        (None, Authenticator::Accounts { db, .. }) => {
            match accounts::resolve_headers(db, &as_bearer, state.cookies_are_secure()) {
                Ok(Some(p)) => (Who::Principal(p), Some(credential.id)),
                Ok(None) => return Err(unknown()),
                Err(e) => return Err(resolve_failed(e, ctx)),
            }
        }
        (None, Authenticator::Shared(auth)) if !auth.enabled() => (Who::NoScopes, None),
        (None, Authenticator::Shared(auth)) => match auth.secret_for(credential.id) {
            Some(password) => (Who::NoScopes, Some(password)),
            None if auth.allows(&as_bearer) => (Who::NoScopes, Some(credential.id)),
            None => return Err(unknown()),
        },
    };
    let Some(secret) = secret else {
        return Ok((who, None));
    };

    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| malformed("the signed x-amz-content-sha256 header is missing"))?;
    let canonical = sigv4::canonical_request(
        req.method().as_str(),
        req.uri().path(),
        req.uri().query().unwrap_or(""),
        headers,
        &credential.signed_headers,
        payload_hash,
    )
    .map_err(|why| match why {
        sigv4::Canon::Path | sigv4::Canon::Query => Box::new(ctx.error(
            StatusCode::BAD_REQUEST,
            "InvalidURI",
            "the request's URI has a malformed escape or is not UTF-8",
        )),
        sigv4::Canon::Missing(name) => malformed(&format!("the signed header {name} is missing")),
        sigv4::Canon::NotText(name) => malformed(&format!("the signed header {name} is not text")),
    })?;
    if !sigv4::signature_matches(secret, &credential, stamp, &canonical) {
        let sts = sigv4::string_to_sign(stamp, &credential.scope(), &canonical);
        return Err(Box::new(xml::error(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature does not match the one computed with the key's secret",
            &[("StringToSign", &sts), ("CanonicalRequest", &canonical)],
            &ctx.path,
            &ctx.id,
        )));
    }
    if !chunked::Mode::of(payload_hash).is_some_and(chunked::Mode::signed) {
        return Ok((who, None));
    }
    // Never a signed body whose signatures go unchecked for want of a key.
    match chunked::Seed::of(secret, &credential, stamp) {
        Some(seed) => Ok((who, Some(seed))),
        None => Err(Box::new(internal_error(ctx))),
    }
}

/// `Authorization: Bearer <id>`, alone; `None` when `id` cannot be a header value.
fn bearer_of(id: &str) -> Option<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {id}")).ok()?,
    );
    Some(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_s3_paths_are_s3() {
        for p in ["/s3", "/s3/", "/s3/b", "/s3/b/k"] {
            assert!(is_path(p), "{p}");
        }
        for p in ["/s3x", "/s", "/dav/s3", "/S3/"] {
            assert!(!is_path(p), "{p}");
        }
    }

    #[test]
    fn a_presigned_query_is_recognised() {
        assert!(is_presigned(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=00"
        ));
        assert!(is_presigned("list-type=2&X-Amz-Credential=a%2Fb"));
        assert!(is_presigned("X-Amz-Signature"));
        assert!(!is_presigned("list-type=2&prefix=X-Amz-Algorithm"));
        assert!(!is_presigned("x-amz-algorithm=1"));
        assert!(!is_presigned(""));
    }

    #[test]
    fn a_query_names_one_subresource_or_none() {
        assert_eq!(subresource(""), None);
        assert_eq!(subresource("x-id=GetObject"), None);
        assert_eq!(subresource("location"), Some("location"));
        assert_eq!(subresource("location="), Some("location"));
        assert_eq!(
            subresource("attributes&x-id=GetObjectAttributes"),
            Some("attributes")
        );
        assert_eq!(subresource("x-id=PutObject&tagging"), Some("tagging"));
        assert_eq!(subresource("list-type=2"), Some(""));
        assert_eq!(subresource("partNumber=1&uploadId=a"), Some(""));
        assert_eq!(subresource("location&acl"), Some(""));
        assert_eq!(subresource("versionId=null"), Some(""));
    }

    #[test]
    fn the_id_becomes_one_bearer_header_or_nothing() {
        let h = bearer_of("vkr_abc").unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(h[AUTHORIZATION], "Bearer vkr_abc");
        assert!(bearer_of("a\nb").is_none());
    }
}
