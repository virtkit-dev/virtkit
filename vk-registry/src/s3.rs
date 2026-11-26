//! sccache reads, stats and writes the [`crate::objects`] file `<bucket>/<key>` at
//! `/s3/<bucket>/<key>`. Listings, bucket operations, nonempty queries, multipart uploads,
//! SigV4 streaming payloads, nonidentity content codings, partial writes and unsupported
//! checksum or encryption headers return `NotImplemented`. So do `If-Match`, `If-None-Match`,
//! `If-Modified-Since` and `If-Unmodified-Since`. Reads ignore `Range` and `If-Range`.
//!
//! SigV4 uses the registry credential (API key, hub token or shared bearer) as both AWS
//! keys. [`admit`] checks the signature first and sets `Authorization: Bearer <access key>`
//! for registry authentication. Unsigned requests keep their Bearer or Basic credentials.
//! Access without credentials requires an open registry. [`route`] applies the shared object
//! grants, naming rules and write path. [`respond`] preserves successful reads, returns 200
//! for a successful `PUT` and maps errors to S3 XML.

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::BodyExt;
use hyper::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};

use crate::Body;

/// The prefix every S3 path is under.
const PREFIX: &str = "/s3/";

/// How far a request's `x-amz-date` may be from this server's clock, as S3 allows.
const MAX_SKEW_SECS: u64 = 15 * 60;

/// The `x-amz-content-sha256` of a request whose body is not signed.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The headers named `x-amz-*` a request may carry; any other asks for something not served.
const AMZ_HEADERS: &[&str] = &["x-amz-content-sha256", "x-amz-date"];

/// Whether `path` is one this view answers, once enabled.
pub(crate) fn is_s3_path(path: &str) -> bool {
    path == "/s3" || path.starts_with(PREFIX)
}

/// A `PUT`'s declared SHA-256, checked after staging and before publication.
#[derive(Clone)]
pub(crate) struct PayloadSha256(pub(crate) String);

/// The original encoded object path below [`PREFIX`] for a request accepted by [`admit`].
#[derive(Clone)]
pub(crate) struct Admitted(pub(crate) String);

/// A request refused before it reaches the store: its status, S3 error code and message.
#[derive(Debug, PartialEq)]
struct Refusal(StatusCode, &'static str, &'static str);

const NOT_IMPLEMENTED: Refusal = Refusal(
    StatusCode::NOT_IMPLEMENTED,
    "NotImplemented",
    "this S3 view serves GetObject, HeadObject and PutObject only",
);

/// A refused request and its response. Only a verified signature permits draining the body.
pub(crate) struct Refused {
    pub(crate) req: Request<hyper::body::Incoming>,
    pub(crate) resp: Response<Body>,
    pub(crate) signed: bool,
}

/// Check the request and mark it [`Admitted`] for [`route`]. For signed requests,
/// check the signature date against `now` in Unix seconds.
pub(crate) fn admit(
    mut req: Request<hyper::body::Incoming>,
    now: u64,
) -> Result<Request<hyper::body::Incoming>, Box<Refused>> {
    // S3 clients authenticate explicitly. Ignore browser session cookies.
    req.headers_mut().remove(hyper::header::COOKIE);
    let access_key = match authenticate(&req, now) {
        Ok(access_key) => access_key,
        Err(r) => return Err(refuse(req, r, false)),
    };
    let signed = access_key.is_some();
    let rest = match check_request(req.method(), req.uri(), req.headers()) {
        Ok(rest) => rest,
        Err(r) => return Err(refuse(req, r, signed)),
    };
    if let Some(sha) = req
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .filter(|v| *v != UNSIGNED_PAYLOAD)
    {
        let sha = sha.to_string();
        req.extensions_mut().insert(PayloadSha256(sha));
    }
    if let Some(access_key) = access_key {
        let Ok(bearer) = HeaderValue::from_str(&format!("Bearer {access_key}")) else {
            let r = Refusal(
                StatusCode::FORBIDDEN,
                "InvalidAccessKeyId",
                "the access key is not a registry credential",
            );
            return Err(refuse(req, r, signed));
        };
        req.headers_mut().insert(AUTHORIZATION, bearer);
    }
    req.extensions_mut().insert(Admitted(rest));
    Ok(req)
}

fn refuse(req: Request<hyper::body::Incoming>, r: Refusal, signed: bool) -> Box<Refused> {
    let resp = error(r.0, r.1, r.2, req.uri().path());
    Box::new(Refused { req, resp, signed })
}

/// Serve `GET`, `HEAD` or `PUT` for an [`Admitted`] request after registry authentication.
pub(crate) async fn route(
    state: &crate::ServerState,
    authz: &crate::Authz<'_>,
    rest: &str,
    req: Request<hyper::body::Incoming>,
) -> anyhow::Result<Response<Body>> {
    use crate::objects;
    let href = req.uri().path().to_string();
    let Some((segs, collection)) =
        objects::split(rest).filter(|(segs, _)| objects::valid_plain_file(&segs.join("/")))
    else {
        let resp = crate::error_response(StatusCode::BAD_REQUEST, "NAME_INVALID", &href);
        return objects::drain_then(req, resp, &href).await;
    };
    let put = *req.method() == Method::PUT;
    let action = if put {
        crate::accounts::Action::Write
    } else {
        crate::accounts::Action::Read
    };
    if !objects::admits(authz, action, &segs, put) {
        return objects::drain_then(req, crate::accounts::forbidden(), &href).await;
    }
    if put {
        let expected = req.extensions().get::<PayloadSha256>().map(|p| p.0.clone());
        return objects::put(state, segs, collection, &href, expected, req).await;
    }
    let head = *req.method() == Method::HEAD;
    objects::blocking(state, authz, move |store, authz| {
        objects::get(authz, store, &segs, collection, &href, head)
    })
    .await
}

/// Return the verified SigV4 access key, or `None` for unsigned requests.
/// The server handles unsigned credentials and anonymous access.
fn authenticate<B>(req: &Request<B>, now: u64) -> Result<Option<String>, Refusal> {
    let sigv4 = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 "));
    if !sigv4 {
        return Ok(None);
    }
    let authority = req.uri().authority().map(|a| a.as_str());
    let target = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
    let own = |ak: &str| ak.to_string();
    verify(
        req.method().as_str(),
        target,
        req.headers(),
        authority,
        now,
        &own,
    )
    .map(Some)
}

/// Check the method, path, query and headers after any SigV4 check. Return the object path
/// below [`PREFIX`] on success.
fn check_request(
    method: &Method,
    uri: &hyper::Uri,
    headers: &HeaderMap,
) -> Result<String, Refusal> {
    if !matches!(*method, Method::GET | Method::HEAD | Method::PUT) {
        return Err(NOT_IMPLEMENTED);
    }
    // Presigned URLs, sub-resources and listings all live in the query.
    if uri.query().is_some_and(|q| !q.is_empty()) {
        return Err(NOT_IMPLEMENTED);
    }
    // A bucket alone, or the service root, is a bucket or listing operation.
    let rest = uri.path().strip_prefix(PREFIX).ok_or(NOT_IMPLEMENTED)?;
    match rest.split_once('/') {
        Some((bucket, key)) if !bucket.is_empty() && !key.is_empty() => {}
        _ => return Err(NOT_IMPLEMENTED),
    }
    check_headers(headers)?;
    Ok(rest.to_string())
}

/// The store ignores preconditions and treats a partial write as a whole-object replacement.
const UNSERVED_HEADERS: &[&str] = &[
    "content-md5",
    "content-range",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
];

/// Whether these headers pass the registry's S3 object header check. A forwarding proxy can
/// check them before attaching credentials.
pub fn admissible_headers(headers: &HeaderMap) -> bool {
    check_headers(headers).is_ok()
}

fn check_headers(headers: &HeaderMap) -> Result<(), Refusal> {
    for name in headers.keys() {
        let name = name.as_str();
        if (name.starts_with("x-amz-") && !AMZ_HEADERS.contains(&name))
            || UNSERVED_HEADERS.contains(&name)
        {
            return Err(NOT_IMPLEMENTED);
        }
    }
    // The store keeps the body verbatim and no coding to return on a read: aws-chunked
    // framing would become object data, and a gzip object would read back unlabelled.
    let encoded = headers
        .get_all(hyper::header::CONTENT_ENCODING)
        .iter()
        .any(|v| {
            v.to_str().map_or(true, |v| {
                v.split(',').any(|c| {
                    let c = c.trim();
                    !c.is_empty() && !c.eq_ignore_ascii_case("identity")
                })
            })
        });
    if encoded {
        return Err(NOT_IMPLEMENTED);
    }
    let mut sha = headers.get_all("x-amz-content-sha256").iter();
    match (sha.next().map(|v| v.to_str()), sha.next()) {
        (None, _) => Ok(()),
        (Some(Ok(v)), None)
            if v == UNSIGNED_PAYLOAD || vk_hub_proto::from_hex_lower::<32>(v).is_some() =>
        {
            Ok(())
        }
        // aws-chunked bodies (`STREAMING-…`) are not decoded here.
        (Some(Ok(v)), None) if v.starts_with("STREAMING-") => Err(NOT_IMPLEMENTED),
        _ => Err(Refusal(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-content-sha256 must be UNSIGNED-PAYLOAD or a SHA-256",
        )),
    }
}

/// Verify a SigV4 `Authorization` header (AWS4-HMAC-SHA256, header form) over `method`,
/// `target` (path and query, as sent) and `headers`, with `secret` giving an access key's
/// signing secret; the access key on success. `authority` stands in for a missing `Host`
/// header (HTTP/2).
fn verify(
    method: &str,
    target: &str,
    headers: &HeaderMap,
    authority: Option<&str>,
    now: u64,
    secret: &dyn Fn(&str) -> String,
) -> Result<String, Refusal> {
    const MALFORMED: Refusal = Refusal(
        StatusCode::BAD_REQUEST,
        "AuthorizationHeaderMalformed",
        "the Authorization header is not a SigV4 header signature",
    );
    let mut auth = headers.get_all(AUTHORIZATION).iter();
    let (Some(auth), None) = (auth.next(), auth.next()) else {
        return Err(MALFORMED);
    };
    let fields = auth
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("AWS4-HMAC-SHA256 "))
        .ok_or(MALFORMED)?;
    let (mut credential, mut signed, mut signature) = (None, None, None);
    for field in fields.split(',') {
        let (k, v) = field.trim().split_once('=').ok_or(MALFORMED)?;
        let slot = match k {
            "Credential" => &mut credential,
            "SignedHeaders" => &mut signed,
            "Signature" => &mut signature,
            _ => return Err(MALFORMED),
        };
        if slot.replace(v).is_some() {
            return Err(MALFORMED);
        }
    }
    let (Some(credential), Some(signed), Some(signature)) = (credential, signed, signature) else {
        return Err(MALFORMED);
    };

    // `<access key>/<YYYYMMDD>/<region>/s3/aws4_request`, read from the right.
    let mut scope = credential.rsplitn(5, '/');
    let (Some("aws4_request"), Some("s3"), Some(region), Some(day), Some(access_key)) = (
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
    ) else {
        return Err(MALFORMED);
    };
    let region_ok = !region.is_empty()
        && region
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if access_key.is_empty() || !region_ok || day.len() != 8 {
        return Err(MALFORMED);
    }

    // Lowercase names in strictly ascending order, which also makes them unique; `host` and
    // `x-amz-date` among them, and every `x-amz-*` header the request carries.
    let names: Vec<&str> = signed.split(';').collect();
    let well_formed = names.iter().all(|n| {
        !n.is_empty()
            && n.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) && names.windows(2).all(|w| w[0] < w[1]);
    if !well_formed {
        return Err(MALFORMED);
    }
    let unsigned_amz = headers
        .keys()
        .any(|k| k.as_str().starts_with("x-amz-") && !names.contains(&k.as_str()));
    if !names.contains(&"host") || !names.contains(&"x-amz-date") || unsigned_amz {
        return Err(Refusal(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "host, x-amz-date and every x-amz-* header must be signed",
        ));
    }

    let amz_date = single(headers, "x-amz-date").ok_or(MALFORMED)?;
    let when = parse_amz_date(amz_date).ok_or(MALFORMED)?;
    if !amz_date.starts_with(day) {
        return Err(MALFORMED);
    }
    if when.abs_diff(now) > MAX_SKEW_SECS {
        return Err(Refusal(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "the request's x-amz-date is too far from the server's time",
        ));
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut canonical = format!(
        "{method}\n{}\n{}\n",
        canonical_uri(path).ok_or(MALFORMED)?,
        canonical_query(query).ok_or(MALFORMED)?
    );
    for name in &names {
        let values: Vec<String> = headers
            .get_all(*name)
            .iter()
            .map(|v| v.to_str().map(canonical_value))
            .collect::<Result<_, _>>()
            .map_err(|_| MALFORMED)?;
        let value = match (values.is_empty(), *name, authority) {
            (false, _, _) => values.join(","),
            (true, "host", Some(authority)) => authority.to_string(),
            _ => return Err(MALFORMED),
        };
        canonical.push_str(&format!("{name}:{value}\n"));
    }
    // S3 requires an explicit payload hash or UNSIGNED-PAYLOAD on signed requests.
    let payload = single(headers, "x-amz-content-sha256").ok_or(Refusal(
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "Missing required header for this request: x-amz-content-sha256",
    ))?;
    canonical.push_str(&format!("\n{signed}\n{payload}"));

    let scope = format!("{day}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        crate::hex_of(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(format!("AWS4{}", secret(access_key)).as_bytes(), day);
    for part in [region, "s3", "aws4_request"] {
        key = hmac(&key, part);
    }
    let given = vk_hub_proto::from_hex_lower::<32>(signature).ok_or(MALFORMED)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes any key length");
    mac.update(to_sign.as_bytes());
    mac.verify_slice(&given).map_err(|_| {
        Refusal(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature does not match",
        )
    })?;
    Ok(access_key.to_string())
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// The one value of header `name`, if it has exactly one and it is text.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok(),
        _ => None,
    }
}

/// Trim surrounding whitespace and collapse each internal run to one space for signing.
fn canonical_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The path as S3's SigV4 signs it: each component percent-decoded, then encoded again with
/// everything but the unreserved characters escaped. S3 does not normalize `.` or `//`.
fn canonical_uri(path: &str) -> Option<String> {
    let mut out = String::with_capacity(path.len());
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&crate::percent_encode_bytes(&percent_decode(seg)?));
    }
    Some(out)
}

/// The query as SigV4 signs it: each name and value decoded and encoded again as in
/// [`canonical_uri`], a name without `=` given an empty value, the pairs sorted.
fn canonical_query(query: &str) -> Option<String> {
    let encode = |s: &str| Some(crate::percent_encode_bytes(&percent_decode(s)?));
    let mut pairs = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((encode(k)?, encode(v)?))
        })
        .collect::<Option<Vec<_>>>()?;
    pairs.sort();
    let pairs: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    Some(pairs.join("&"))
}

/// Strict `%XX` decoding of one path segment, `None` on a malformed escape. Not
/// [`crate::percent_decode`], which reads `+` as a space as a form body does.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    Some(out)
}

/// `YYYYMMDDTHHMMSSZ` as Unix seconds.
fn parse_amz_date(v: &str) -> Option<u64> {
    let b = v.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        let s = v.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (y, m, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hh, mm, ss) = (num(9..11)?, num(11..13)?, num(13..15)?);
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = match m {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=month_days).contains(&d) {
        return None;
    }
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm), for years from 1970.
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Return an empty 200 for a successful PUT, preserve successful reads and translate
/// registry errors to S3 status codes and XML.
pub(crate) async fn respond(resp: Response<Body>, method: &Method, path: &str) -> Response<Body> {
    let status = resp.status();
    if status.is_success() && *method == Method::PUT {
        return Response::new(crate::body_of(Bytes::new()));
    }
    if status.as_u16() < 400 || resp.extensions().get::<S3Error>().is_some() {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let (status, code, message) = match status {
        StatusCode::BAD_REQUEST => match refusal_code(body).await.as_deref() {
            Some("DIGEST_INVALID") => (
                status,
                "XAmzContentSHA256Mismatch",
                "the body does not match its x-amz-content-sha256",
            ),
            Some("NAME_INVALID") => (status, "InvalidArgument", "the key is not a valid name"),
            _ => (status, "InvalidArgument", "the request was refused"),
        },
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the credential is missing, unknown, or not granted this key",
        ),
        StatusCode::NOT_FOUND => (status, "NoSuchKey", "the specified key does not exist"),
        StatusCode::METHOD_NOT_ALLOWED | StatusCode::CONFLICT => (
            StatusCode::CONFLICT,
            "InvalidRequest",
            "the key is a directory, or below an object",
        ),
        StatusCode::LENGTH_REQUIRED => (status, "MissingContentLength", "Content-Length needed"),
        StatusCode::PAYLOAD_TOO_LARGE => (status, "EntityTooLarge", "the object is too large"),
        StatusCode::NOT_IMPLEMENTED => (status, "NotImplemented", "not served"),
        StatusCode::SERVICE_UNAVAILABLE => (status, "ServiceUnavailable", "try again later"),
        s if s.is_server_error() => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "internal error (details in the server log)",
        ),
        _ => (status, "InvalidRequest", "the request was refused"),
    };
    let mut out = error(status, code, message, path);
    // What the refusal said about the connection and when to retry still holds.
    for name in [hyper::header::CONNECTION, hyper::header::RETRY_AFTER] {
        if let Some(v) = parts.headers.get(&name) {
            out.headers_mut().insert(name, v.clone());
        }
    }
    out
}

/// The `code` of a JSON refusal ([`crate::error_response`]), which this server built and
/// holds in memory.
async fn refusal_code(body: Body) -> Option<String> {
    let bytes = body.collect().await.ok()?.to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(json["errors"][0]["code"].as_str()?.to_string())
}

/// Marks a response [`error`] built, already S3's.
#[derive(Clone)]
struct S3Error;

/// S3's XML error document.
fn error(status: StatusCode, code: &str, message: &str, resource: &str) -> Response<Body> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
         <Message>{}</Message><Resource>{}</Resource></Error>",
        xml_escape(message),
        xml_escape(resource)
    );
    let mut resp = Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/xml")
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(crate::body_of(Bytes::from(body)))
        .expect("building an S3 error");
    resp.extensions_mut().insert(S3Error);
    resp
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if c.is_control() => out.push_str(&format!("&#{};", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    /// AWS's worked example for a signed GetObject (S3 API reference, "Signature
    /// Calculations for the Authorization Header", GET Object).
    #[test]
    fn verifies_aws_get_object_example() {
        let h = headers(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            (
                "x-amz-content-sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            ("x-amz-date", "20130524T000000Z"),
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/\
                 aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,\
                 Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            ),
        ]);
        let now = parse_amz_date("20130524T000500Z").unwrap();
        let secret = |_: &str| "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string();
        let ak = verify("GET", "/test.txt", &h, None, now, &secret).unwrap();
        assert_eq!(ak, "AKIAIOSFODNN7EXAMPLE");
        // Any change to what was signed breaks it.
        assert_eq!(
            verify("PUT", "/test.txt", &h, None, now, &secret)
                .unwrap_err()
                .1,
            "SignatureDoesNotMatch"
        );
        assert_eq!(
            verify("GET", "/other.txt", &h, None, now, &secret)
                .unwrap_err()
                .1,
            "SignatureDoesNotMatch"
        );
        let wrong = |_: &str| "another secret".to_string();
        assert!(verify("GET", "/test.txt", &h, None, now, &wrong).is_err());
        // Outside the clock window.
        let late = now + MAX_SKEW_SECS + 1;
        assert_eq!(
            verify("GET", "/test.txt", &h, None, late, &secret)
                .unwrap_err()
                .1,
            "RequestTimeTooSkewed"
        );
    }

    /// Sign as a client would, with the access key as its own secret.
    fn sign(method: &str, path: &str, extra: &[(&str, &str)], ak: &str) -> HeaderMap {
        let mut pairs = vec![
            ("host", "registry.example"),
            ("x-amz-content-sha256", UNSIGNED_PAYLOAD),
            ("x-amz-date", "20261116T120000Z"),
        ];
        pairs.extend_from_slice(extra);
        sign_headers(method, path, pairs, ak)
    }

    /// [`sign`] over exactly `pairs`, all of them signed.
    fn sign_headers(method: &str, path: &str, mut pairs: Vec<(&str, &str)>, ak: &str) -> HeaderMap {
        pairs.sort();
        let names: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let mut canonical = format!(
            "{method}\n{}\n{}\n",
            canonical_uri(path).unwrap(),
            canonical_query(query).unwrap()
        );
        for (k, v) in &pairs {
            canonical.push_str(&format!("{k}:{v}\n"));
        }
        canonical.push_str(&format!("\n{}\n{UNSIGNED_PAYLOAD}", names.join(";")));
        let scope = "20261116/auto/s3/aws4_request";
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n20261116T120000Z\n{scope}\n{}",
            crate::hex_of(&Sha256::digest(canonical.as_bytes()))
        );
        let mut key = hmac(format!("AWS4{ak}").as_bytes(), "20261116");
        for part in ["auto", "s3", "aws4_request"] {
            key = hmac(&key, part);
        }
        let sig = crate::hex_of(&hmac(&key, &to_sign));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={}, Signature={sig}",
            names.join(";")
        );
        let mut h = headers(&pairs);
        h.insert(AUTHORIZATION, HeaderValue::from_str(&auth).unwrap());
        h
    }

    const NOW: u64 = 1_794_830_400; // 2026-11-16T12:00:00Z

    #[test]
    fn the_access_key_is_its_own_secret() {
        assert_eq!(parse_amz_date("20261116T120000Z"), Some(NOW));
        let own = |ak: &str| ak.to_string();
        let path = "/s3/cache/a/b/.sccache_check";
        let h = sign("PUT", path, &[], "vkr_secret");
        assert_eq!(
            verify("PUT", path, &h, None, NOW, &own).unwrap(),
            "vkr_secret"
        );
        // Percent-encoding an unreserved character preserves the signature.
        let h = sign("GET", "/s3/cache/a%2Db", &[], "vkr_secret");
        assert!(verify("GET", "/s3/cache/a-b", &h, None, NOW, &own).is_ok());
    }

    #[test]
    fn the_query_is_signed() {
        assert_eq!(canonical_query("").unwrap(), "");
        assert_eq!(canonical_query("uploads").unwrap(), "uploads=");
        assert_eq!(
            canonical_query("prefix=a%20b&list-type=2&").unwrap(),
            "list-type=2&prefix=a%20b"
        );
        assert_eq!(canonical_query("a=%zz"), None);
        let own = |ak: &str| ak.to_string();
        let h = sign("GET", "/s3/b?list-type=2&prefix=a%20b", &[], "vkr_x");
        assert!(verify("GET", "/s3/b?prefix=a%20b&list-type=2", &h, None, NOW, &own).is_ok());
        for other in ["/s3/b", "/s3/b?list-type=3&prefix=a%20b"] {
            assert_eq!(
                verify("GET", other, &h, None, NOW, &own).unwrap_err().1,
                "SignatureDoesNotMatch",
                "{other}"
            );
        }
    }

    #[test]
    fn an_unsigned_amz_header_or_a_missing_host_is_refused() {
        let own = |ak: &str| ak.to_string();
        let mut h = sign("GET", "/s3/b/k", &[], "vkr_x");
        h.insert("x-amz-meta-a", HeaderValue::from_static("1"));
        assert_eq!(
            verify("GET", "/s3/b/k", &h, None, NOW, &own).unwrap_err().1,
            "AccessDenied"
        );
        // Without a Host header, HTTP/2's authority stands in for it.
        let mut h = sign("GET", "/s3/b/k", &[], "vkr_x");
        h.remove("host");
        assert!(verify("GET", "/s3/b/k", &h, None, NOW, &own).is_err());
        assert!(verify("GET", "/s3/b/k", &h, Some("registry.example"), NOW, &own).is_ok());
    }

    #[test]
    fn a_malformed_authorization_is_refused() {
        let own = |ak: &str| ak.to_string();
        let good = sign("GET", "/s3/b/k", &[], "vkr_x");
        let auth = good[AUTHORIZATION].to_str().unwrap().to_string();
        for bad in [
            auth.replace("/s3/aws4_request", "/iam/aws4_request"),
            auth.replace("SignedHeaders=host;", "SignedHeaders=x-amz-date;host;"),
            format!("{auth}, Signature=00"),
            auth.replace("Credential=vkr_x/20261116", "Credential=vkr_x/20261117"),
        ] {
            let mut h = good.clone();
            h.insert(AUTHORIZATION, HeaderValue::from_str(&bad).unwrap());
            assert!(
                verify("GET", "/s3/b/k", &h, None, NOW, &own).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn only_object_operations_are_served() {
        let check = |m: Method, uri: &str, h: &[(&str, &str)]| {
            check_request(&m, &uri.parse().unwrap(), &headers(h))
        };
        assert_eq!(check(Method::GET, "/s3/b/a/k", &[]).unwrap(), "b/a/k");
        assert_eq!(check(Method::PUT, "/s3/b/k", &[]).unwrap(), "b/k");
        for (m, uri) in [
            (Method::GET, "/s3/"),
            (Method::GET, "/s3/b"),
            (Method::GET, "/s3/b/"),
            (Method::DELETE, "/s3/b/k"),
            (Method::POST, "/s3/b/k?uploads"),
            (Method::GET, "/s3/b?list-type=2"),
            (Method::GET, "/s3/b/k?X-Amz-Signature=00"),
        ] {
            assert_eq!(check(m, uri, &[]), Err(NOT_IMPLEMENTED), "{uri}");
        }
        for h in [
            ("x-amz-checksum-crc32", "AAAAAA=="),
            ("x-amz-server-side-encryption", "AES256"),
            ("x-amz-security-token", "t"),
            ("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg=="),
            ("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
            ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
            ("if-match", "\"0\""),
            ("if-none-match", "*"),
            ("if-modified-since", "Thu, 26 Nov 2026 00:00:00 GMT"),
            ("if-unmodified-since", "Thu, 26 Nov 2026 00:00:00 GMT"),
            ("content-range", "bytes 0-1/2"),
            ("content-encoding", "aws-chunked"),
            ("content-encoding", "gzip, AWS-Chunked"),
            ("content-encoding", "gzip"),
        ] {
            assert_eq!(
                check(Method::PUT, "/s3/b/k", &[h]),
                Err(NOT_IMPLEMENTED),
                "{h:?}"
            );
            assert!(!admissible_headers(&headers(&[h])), "{h:?}");
        }
        let sha = "c".repeat(64);
        for h in [
            &[("x-amz-content-sha256", "nope")][..],
            &[("x-amz-content-sha256", &sha.to_uppercase())],
            &[
                ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
                ("x-amz-content-sha256", &sha),
            ],
            &[
                ("x-amz-content-sha256", &sha),
                ("x-amz-content-sha256", &sha),
            ],
        ] {
            assert_eq!(
                check(Method::PUT, "/s3/b/k", h).unwrap_err().1,
                "InvalidArgument"
            );
            assert!(!admissible_headers(&headers(h)), "{h:?}");
        }
        for h in [
            &[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")][..],
            &[
                ("x-amz-content-sha256", &sha),
                ("x-amz-date", "20261126T000000Z"),
            ],
            &[("transfer-encoding", "chunked")],
            &[("content-encoding", "identity")],
            &[("range", "bytes=0-1"), ("if-range", "\"0\"")],
        ] {
            assert!(check(Method::PUT, "/s3/b/k", h).is_ok(), "{h:?}");
            assert!(admissible_headers(&headers(h)), "{h:?}");
        }
    }

    #[tokio::test]
    async fn refusals_become_s3_errors() {
        let json = crate::error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "x");
        let resp = respond(json, &Method::GET, "/s3/b/<k>").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()[hyper::header::CONTENT_TYPE],
            "application/xml"
        );
        let created = Response::builder()
            .status(StatusCode::CREATED)
            .body(crate::body_of(Bytes::new()))
            .unwrap();
        assert_eq!(
            respond(created, &Method::PUT, "/s3/b/k").await.status(),
            StatusCode::OK
        );
        assert_eq!(xml_escape("/s3/b/<k>&"), "/s3/b/&lt;k&gt;&amp;");
    }

    #[test]
    fn a_bad_amz_date_is_refused() {
        assert_eq!(parse_amz_date("20240229T000000Z"), Some(1_709_164_800));
        for bad in [
            "20261316T120000Z", // month 13
            "20261100T120000Z", // day 0
            "20260231T120000Z", // 31 February
            "20250229T120000Z", // 29 February, not a leap year
            "20261116T240000Z", // hour 24
            "20261116T126000Z", // minute 60
            "2026111aT120000Z", // not a digit
            "20261116T120000",  // too short
            "20261116T120000ZZ",
            "20261116 120000Z",
            "19691231T235959Z", // before 1970
        ] {
            assert_eq!(parse_amz_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_path_signs_as_its_decoded_bytes() {
        assert_eq!(canonical_uri("/s3/b/a b").unwrap(), "/s3/b/a%20b");
        assert_eq!(canonical_uri("/s3/b/%7e%2f").unwrap(), "/s3/b/~%2F");
        assert_eq!(canonical_uri("/s3/b/é").unwrap(), "/s3/b/%C3%A9");
        assert_eq!(canonical_uri("/s3/b/%ff").unwrap(), "/s3/b/%FF");
        assert_eq!(canonical_uri("/s3/b/a+b").unwrap(), "/s3/b/a%2Bb");
        for bad in ["/s3/b/%", "/s3/b/%4", "/s3/b/%zz", "/s3/b/%é", "/s3/b/%4é"] {
            assert_eq!(canonical_uri(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_repeated_signed_header_is_refused() {
        let own = |ak: &str| ak.to_string();
        for name in ["x-amz-date", "authorization"] {
            let mut h = sign("GET", "/s3/b/k", &[], "vkr_x");
            let v = h[name].clone();
            h.append(hyper::header::HeaderName::from_static(name), v);
            assert_eq!(
                verify("GET", "/s3/b/k", &h, None, NOW, &own).unwrap_err().1,
                "AuthorizationHeaderMalformed",
                "{name}"
            );
        }
    }

    #[test]
    fn a_signed_request_must_name_its_payload_hash() {
        let own = |ak: &str| ak.to_string();
        let pairs = vec![
            ("host", "registry.example"),
            ("x-amz-date", "20261116T120000Z"),
        ];
        let h = sign_headers("GET", "/s3/b/k", pairs, "vkr_x");
        let refusal = verify("GET", "/s3/b/k", &h, None, NOW, &own).unwrap_err();
        assert_eq!(
            (refusal.0, refusal.1),
            (StatusCode::BAD_REQUEST, "InvalidRequest")
        );
    }

    fn request(uri: &str, headers: HeaderMap) -> Request<()> {
        let mut req = Request::get(uri).body(()).unwrap();
        *req.headers_mut() = headers;
        req
    }

    #[test]
    fn a_sigv4_signature_is_verified_and_other_credentials_go_on() {
        let path = "/s3/b/k";
        let req = request(path, HeaderMap::new());
        assert_eq!(authenticate(&req, NOW).unwrap(), None);
        for auth in ["Bearer vkr_x", "Basic dTpw"] {
            let req = request(path, headers(&[("authorization", auth)]));
            assert_eq!(authenticate(&req, NOW).unwrap(), None, "{auth}");
        }
        // HTTP/2 may supply the signed host through the URI authority.
        let mut h = sign("GET", path, &[], "vkr_x");
        h.remove("host");
        let req = request(&format!("http://registry.example{path}"), h.clone());
        assert_eq!(authenticate(&req, NOW).unwrap().as_deref(), Some("vkr_x"));
        let req = request(&format!("http://elsewhere.example{path}"), h);
        assert_eq!(
            authenticate(&req, NOW).unwrap_err().1,
            "SignatureDoesNotMatch"
        );
    }

    #[tokio::test]
    async fn a_refusal_keeps_its_cause() {
        for (code, s3_code) in [
            ("DIGEST_INVALID", "XAmzContentSHA256Mismatch"),
            ("NAME_INVALID", "InvalidArgument"),
            ("SOMETHING_ELSE", "InvalidArgument"),
        ] {
            let json = crate::error_response(StatusCode::BAD_REQUEST, code, "x");
            let resp = respond(json, &Method::PUT, "/s3/b/k").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(body.contains(&format!("<Code>{s3_code}</Code>")), "{body}");
        }
        let mut busy = crate::error_response(StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE", "x");
        busy.headers_mut()
            .insert(hyper::header::RETRY_AFTER, HeaderValue::from_static("5"));
        let resp = respond(busy, &Method::PUT, "/s3/b/k").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[hyper::header::RETRY_AFTER], "5");
    }
}
