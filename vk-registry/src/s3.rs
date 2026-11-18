//! A minimal S3 view of the WebDAV plain-file area, for sccache's S3 cache backend: GetObject,
//! HeadObject and PutObject at `/s3/<bucket>/<key>`, where the bucket is a top-level directory
//! of `/dav/files/` and the key the path below it. Nothing else is served: a listing, a bucket
//! operation, a query string, multipart, chunked uploads or a header asking for what is not
//! kept (checksums, encryption) answer `NotImplemented`.
//!
//! A request is admitted in front of the server's usual checks ([`admit`]): a SigV4 header
//! signature is verified with the access key as its own secret — the registry credential
//! (an API key, a hub token or the shared bearer) is both — and the request then goes on as
//! `Authorization: Bearer <access key>` to `/dav/files/<bucket>/<key>`, so the credential,
//! its grants, the name rules and the write path are the WebDAV view's. [`respond`] turns
//! the answer into what an S3 client expects: 200 for a write, S3's XML error otherwise.

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
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

/// The SHA-256 a `PUT`'s signature binds its body to, checked once the body is staged.
#[derive(Clone)]
pub(crate) struct PayloadSha256(pub(crate) String);

/// Marks a request [`admit`] rewrote onto `/dav/files/`, which reaches it with WebDAV off.
#[derive(Clone)]
pub(crate) struct Admitted;

/// A request refused before it reaches the store: its status, S3 error code and message.
#[derive(Debug, PartialEq)]
struct Refusal(StatusCode, &'static str, &'static str);

const NOT_IMPLEMENTED: Refusal = Refusal(
    StatusCode::NOT_IMPLEMENTED,
    "NotImplemented",
    "this S3 view serves GetObject, HeadObject and PutObject only",
);

/// Check an S3 request and rewrite it onto `/dav/files/`, or refuse it. `now` is the clock
/// the signature's date is held to, in Unix seconds.
#[allow(clippy::result_large_err)]
pub(crate) fn admit(
    mut req: Request<hyper::body::Incoming>,
    now: u64,
) -> Result<Request<hyper::body::Incoming>, Response<Body>> {
    let path = req.uri().path().to_string();
    let refused = |r: Refusal| error(r.0, r.1, r.2, &path);
    let rest = check_request(req.method(), req.uri(), req.headers()).map_err(refused)?;
    let headers = req.headers_mut();
    // Only the signature, or a credential the client chose to send, may authenticate: never
    // a browser's ambient session cookie.
    headers.remove(hyper::header::COOKIE);
    if let Some(sha) = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .filter(|v| *v != UNSIGNED_PAYLOAD)
    {
        let sha = sha.to_string();
        req.extensions_mut().insert(PayloadSha256(sha));
    }
    let signed = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 "));
    if signed {
        let authority = req.uri().authority().map(|a| a.as_str().to_string());
        let access_key = verify(
            req.method().as_str(),
            &path,
            req.headers(),
            authority.as_deref(),
            now,
            &|ak| ak.to_string(),
        )
        .map_err(refused)?;
        let bearer = HeaderValue::from_str(&format!("Bearer {access_key}")).map_err(|_| {
            refused(Refusal(
                StatusCode::FORBIDDEN,
                "InvalidAccessKeyId",
                "the access key is not a registry credential",
            ))
        })?;
        req.headers_mut().insert(AUTHORIZATION, bearer);
    }
    let uri = format!("/dav/files/{rest}")
        .parse()
        .map_err(|_| refused(Refusal(StatusCode::BAD_REQUEST, "InvalidURI", "bad path")))?;
    *req.uri_mut() = uri;
    req.extensions_mut().insert(Admitted);
    Ok(req)
}

/// What this view serves of a request, before its signature: an object operation with no
/// query and no header asking for what is not kept. The path below [`PREFIX`] on success.
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
    for name in headers.keys() {
        let name = name.as_str();
        if (name.starts_with("x-amz-") && !AMZ_HEADERS.contains(&name)) || name == "content-md5" {
            return Err(NOT_IMPLEMENTED);
        }
    }
    let mut sha = headers.get_all("x-amz-content-sha256").iter();
    match (sha.next().map(|v| v.to_str()), sha.next()) {
        (None, _) => {}
        (Some(Ok(v)), None) if v == UNSIGNED_PAYLOAD || is_sha256_hex(v) => {}
        // aws-chunked bodies (`STREAMING-…`) are not decoded here.
        (Some(Ok(v)), None) if v.starts_with("STREAMING-") => return Err(NOT_IMPLEMENTED),
        _ => {
            return Err(Refusal(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-content-sha256 must be UNSIGNED-PAYLOAD or a SHA-256",
            ));
        }
    }
    Ok(rest.to_string())
}

/// Verify a SigV4 `Authorization` header (AWS4-HMAC-SHA256, header form) over `method`,
/// `path` (as sent) and `headers`, with `secret` giving an access key's signing secret. The
/// access key on success. `authority` stands in for a missing `Host` header (HTTP/2).
fn verify(
    method: &str,
    path: &str,
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

    let mut canonical = format!("{method}\n{}\n\n", canonical_uri(path).ok_or(MALFORMED)?);
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
    let payload = single(headers, "x-amz-content-sha256").unwrap_or(UNSIGNED_PAYLOAD);
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
    let given = decode_hex(signature).ok_or(MALFORMED)?;
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

/// A header value as SigV4 signs it: trimmed, inner runs of spaces collapsed to one.
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
        for b in percent_decode(seg)? {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

fn is_sha256_hex(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_hex(v: &str) -> Option<Vec<u8>> {
    if !is_sha256_hex(v) {
        return None;
    }
    (0..32)
        .map(|i| u8::from_str_radix(&v[2 * i..2 * i + 2], 16).ok())
        .collect()
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
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
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

/// The answer an S3 client gets for `resp`, the server's answer to an admitted request (or
/// to one refused on its way there): a write's success as 200 with no body, a read's as is,
/// and any refusal as S3's XML error with the status S3 would give it.
pub(crate) fn respond(resp: Response<Body>, method: &Method, path: &str) -> Response<Body> {
    let status = resp.status();
    if status.is_success() && *method == Method::PUT {
        let mut ok = Response::new(crate::body_of(Bytes::new()));
        if let Some(etag) = resp.headers().get(hyper::header::ETAG) {
            ok.headers_mut().insert(hyper::header::ETAG, etag.clone());
        }
        return ok;
    }
    if status.as_u16() < 400
        || resp.headers().get(hyper::header::CONTENT_TYPE)
            == Some(&HeaderValue::from_static("application/xml"))
    {
        return resp;
    }
    let (status, code, message) = match status {
        StatusCode::BAD_REQUEST => (status, "InvalidArgument", "the request was refused"),
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
        if let Some(v) = resp.headers().get(&name) {
            out.headers_mut().insert(name, v.clone());
        }
    }
    out
}

/// S3's XML error document.
fn error(status: StatusCode, code: &str, message: &str, resource: &str) -> Response<Body> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
         <Message>{}</Message><Resource>{}</Resource></Error>",
        xml_escape(message),
        xml_escape(resource)
    );
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/xml")
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(crate::body_of(Bytes::from(body)))
        .expect("building an S3 error")
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
        pairs.sort();
        let names: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        let mut canonical = format!("{method}\n{}\n\n", canonical_uri(path).unwrap());
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
        // Escaped and unescaped spellings of a path sign the same.
        let h = sign("GET", "/s3/cache/a%2Db", &[], "vkr_secret");
        assert!(verify("GET", "/s3/cache/a-b", &h, None, NOW, &own).is_ok());
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
        ] {
            assert_eq!(check(Method::PUT, "/s3/b/k", &[h]), Err(NOT_IMPLEMENTED));
        }
        assert_eq!(
            check(Method::PUT, "/s3/b/k", &[("x-amz-content-sha256", "nope")])
                .unwrap_err()
                .1,
            "InvalidArgument"
        );
    }

    #[test]
    fn refusals_become_s3_errors() {
        let json = crate::error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "x");
        let resp = respond(json, &Method::GET, "/s3/b/<k>");
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
            respond(created, &Method::PUT, "/s3/b/k").status(),
            StatusCode::OK
        );
        assert_eq!(xml_escape("/s3/b/<k>&"), "/s3/b/&lt;k&gt;&amp;");
    }
}
