//! Objects: PutObject, GetObject and HeadObject, GetObjectAttributes, an object's canned
//! configurations and DeleteObject, over the object layer the WebDAV view shares. Authorized as that view authorizes: a write needs
//! `Write` on the key's parent repository, a read `Read` on the repository the key resolves
//! to; a caller holding the action on neither the key's path nor its parent is refused before
//! any lookup, and what it may not read is absent (`NoSuchKey`).
//!
//! An object is served as bytes and nothing else: `application/octet-stream`, `attachment`
//! and `nosniff` whatever its writer said, since this origin also serves `/browse` and holds
//! the session cookie. Its ETag is the MD5 its S3 write recorded, or its SHA-256 (see
//! [`conditional::etag`]).

use std::sync::Arc;

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::header::{
    ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, ETAG, HeaderMap, HeaderValue, LAST_MODIFIED,
};
use hyper::{Request, Response, StatusCode};
use sha2::Digest as _;

use super::conditional::{self, Conditions, MD5_ANNOTATION, Outcome, WriteConditions};
use super::range::{self, Range};
use super::{Ctx, UNCOMPRESSED_FROM, checksum, chunked, drain, meta, multipart, refuse, xml};
use crate::dav::http_date;
use crate::files::{
    self, Commit, MAX_OBJECT, Node, Object, PutError, Unwritable, Written, allowed, object_of,
    repo_name,
};
use crate::{Authz, Body, ServerState, Store, accounts, body_of};

/// The header asking a read for the object's checksum.
const CHECKSUM_MODE: &str = "x-amz-checksum-mode";

/// The header a read of one part carries: how many parts the object was uploaded in.
const PARTS_COUNT: &str = "x-amz-mp-parts-count";

/// The checksum a read answers with, when asked, for an object whose write kept none: the
/// SHA-256 the store names the bytes by.
const CHECKSUM_SHA256: &str = "x-amz-checksum-sha256";

/// Whether this caller may `action` on the key at `segs` or on its parent: what admits a
/// request to the lookup that then decides on the repository the key resolves to.
pub(super) fn admitted(authz: &Authz<'_>, action: accounts::Action, segs: &[String]) -> bool {
    allowed(authz, action, &repo_name(segs))
        || object_of(segs).is_some_and(|(parent, _)| allowed(authz, action, &parent))
}

pub(super) fn no_such_key(ctx: &Ctx) -> Response<Body> {
    ctx.error(
        StatusCode::NOT_FOUND,
        "NoSuchKey",
        "the specified key does not exist",
    )
}

/// The object at `segs` as this caller may read it: `None` when nothing is there, when a
/// directory or a foreign tag is, or when the caller may not read the repository it is in or
/// its bytes through it.
pub(super) fn readable(
    store: &Store,
    authz: &Authz<'_>,
    segs: &[String],
) -> Result<Option<Object>> {
    Ok(match files::resolve(store, segs)? {
        Some(Node::Object(obj))
            if allowed(authz, accounts::Action::Read, &obj.repo)
                && crate::readable_through(authz, store, &obj.repo, &obj.layer) =>
        {
            Some(obj)
        }
        _ => None,
    })
}

/// The SHA-256 of an object, as S3's checksum headers and elements carry it: base64.
fn sha256_base64(layer: &str) -> String {
    vk_hub_proto::to_base64(&hex_bytes(layer).unwrap_or_default())
}

fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    let b = hex.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

fn insert(headers: &mut HeaderMap, name: hyper::header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// The `Content-Range` of `len` bytes from `start` of an object `total` bytes long.
fn content_range(start: u64, len: u64, total: u64) -> String {
    let last = start.saturating_add(len).saturating_sub(1);
    format!("bytes {start}-{last}/{total}")
}

/// `GET`/`HEAD /s3/<bucket>/<key>`: the object's bytes, after its conditional headers, or
/// the one byte range `Range` asks for (206) when `If-Range`, if sent, still holds, or
/// `?partNumber=<part>`: the bytes of that part of the object as it was uploaded (206 with
/// its `Content-Range`, and `x-amz-mp-parts-count` for an object made of parts; an object
/// written whole is its one part, and a part of no bytes is the whole object, 200); a HEAD
/// answers what the GET would. A GET served, whole or in part, refreshes an idle object's tag
/// as a WebDAV GET does; a HEAD touches nothing.
pub(super) async fn get(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    head: bool,
    part: Option<u32>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !admitted(authz, accounts::Action::Read, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let conditions = Conditions::of(req.headers());
    let asked = range::Asked::of(req.headers());
    if part.is_some() && req.headers().contains_key(hyper::header::RANGE) {
        let resp = ctx.error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Cannot specify both Range header and partNumber query parameter",
        );
        return refuse(req, resp, ctx).await;
    }
    let checksum = req
        .headers()
        .get(CHECKSUM_MODE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"ENABLED"));
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        let Some(obj) = readable(store, authz, &segs)? else {
            return Ok(no_such_key(&ctx));
        };
        let etag = conditional::etag_of(&obj);
        let modified = http_date(obj.modified);
        match conditions.evaluate(&etag, obj.modified) {
            Outcome::Serve => {}
            Outcome::NotModified => {
                let mut resp = Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(body_of(bytes::Bytes::new()))?;
                insert(resp.headers_mut(), ETAG, &etag);
                insert(resp.headers_mut(), LAST_MODIFIED, &modified);
                return Ok(resp);
            }
            Outcome::Failed(condition) => {
                return Ok(xml::error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "at least one of the preconditions you specified did not hold",
                    &[("Condition", condition)],
                    &ctx.path,
                    &ctx.id,
                ));
            }
        }
        let sizes = multipart::part_sizes(&obj.annotations);
        let range = match part {
            None => asked.resolve(&etag, obj.modified, obj.size),
            Some(n) => {
                let lies = match &sizes {
                    Some(sizes) => multipart::part_range(sizes, n),
                    None => (n == 1).then_some((0, obj.size)),
                };
                let Some((start, len)) = lies else {
                    let count = sizes.as_ref().map_or(1, Vec::len).to_string();
                    return Ok(xml::error(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        "InvalidPartNumber",
                        "The requested partnumber is not satisfiable.",
                        &[
                            ("ActualPartCount", &count),
                            ("PartNumberRequested", &n.to_string()),
                        ],
                        &ctx.path,
                        &ctx.id,
                    ));
                };
                if len == 0 {
                    Range::Whole
                } else {
                    Range::Part { start, len }
                }
            }
        };
        let mut resp = match range {
            Range::Whole => {
                let digest = format!("sha256:{}", obj.layer);
                let mut resp = crate::serve_blob(store, &digest, head, false, false)?;
                // The layer gone under the tag (a gc between the two reads) is no object
                // either.
                if resp.status() != StatusCode::OK {
                    return Ok(no_such_key(&ctx));
                }
                resp.headers_mut().remove("docker-content-digest");
                resp
            }
            Range::Part { start, len } => {
                let Some(part) = store.serve_blob_range(&obj.layer, start, len, head)? else {
                    return Ok(no_such_key(&ctx));
                };
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(CONTENT_LENGTH, len.to_string())
                    .header(CONTENT_RANGE, content_range(start, len, part.total))
                    .body(part.body)?
            }
            Range::Unsatisfiable => {
                let total = obj.size.to_string();
                let mut resp = xml::error(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "InvalidRange",
                    "the requested range is not satisfiable",
                    &[
                        ("RangeRequested", asked.range()),
                        ("ActualObjectSize", &total),
                    ],
                    &ctx.path,
                    &ctx.id,
                );
                insert(
                    resp.headers_mut(),
                    CONTENT_RANGE,
                    &format!("bytes */{total}"),
                );
                insert(resp.headers_mut(), ACCEPT_RANGES, "bytes");
                return Ok(resp);
            }
        };
        if !head {
            files::touch_if_idle(store, &obj);
        }
        let partial = resp.status() == StatusCode::PARTIAL_CONTENT;
        let headers = resp.headers_mut();
        headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
        insert(headers, ETAG, &etag);
        insert(headers, LAST_MODIFIED, &modified);
        if let (Some(_), Some(sizes)) = (part, &sizes) {
            insert(
                headers,
                hyper::header::HeaderName::from_static(PARTS_COUNT),
                &sizes.len().to_string(),
            );
        }
        // The whole object's checksum, on the whole object only: S3 sends none with a part,
        // and the AWS CLI checks what it is sent against the bytes of each part it fetches.
        if checksum && !partial {
            match checksum::stored(&obj.annotations) {
                Some(kept) => headers.extend(kept.headers()),
                None => insert(
                    headers,
                    hyper::header::HeaderName::from_static(CHECKSUM_SHA256),
                    &sha256_base64(&obj.layer),
                ),
            }
        }
        for (name, value) in meta::headers(&obj.annotations) {
            headers.append(name, value);
        }
        Ok(resp)
    })
    .await
}

/// `GET /s3/<bucket>/<key>?attributes`: what `x-amz-object-attributes` asks of `ETag`,
/// `Checksum`, `ObjectParts` (the parts an object was uploaded in, `x-amz-max-parts` of
/// them from after `x-amz-part-number-marker`; an object written whole has none),
/// `ObjectSize` and `StorageClass`, with `Last-Modified`. A metadata read, so it touches
/// nothing.
pub(super) async fn attributes(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !admitted(authz, accounts::Action::Read, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let count = |name: &str, default: u64, most: u64| -> Option<u64> {
        match req.headers().get(name) {
            None => Some(default),
            Some(v) => v
                .to_str()
                .ok()
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|n| n.min(most)),
        }
    };
    let (Some(max_parts), Some(marker)) = (
        count("x-amz-max-parts", 1000, 1000),
        count("x-amz-part-number-marker", 0, u64::from(u32::MAX)),
    ) else {
        let resp = ctx.error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-max-parts and x-amz-part-number-marker are whole numbers",
        );
        return refuse(req, resp, ctx).await;
    };
    let mut asked = Vec::new();
    for value in req.headers().get_all("x-amz-object-attributes") {
        let Ok(value) = value.to_str() else {
            asked.clear();
            break;
        };
        asked.extend(value.split(',').map(|a| a.trim().to_string()));
    }
    let known = [
        "ETag",
        "Checksum",
        "ObjectParts",
        "StorageClass",
        "ObjectSize",
    ];
    if asked.is_empty() || asked.iter().any(|a| !known.contains(&a.as_str())) {
        let resp = ctx.error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-object-attributes names some of ETag, Checksum, ObjectParts, StorageClass \
             and ObjectSize",
        );
        return refuse(req, resp, ctx).await;
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        let Some(obj) = readable(store, authz, &segs)? else {
            return Ok(no_such_key(&ctx));
        };
        let has = |a: &str| asked.iter().any(|x| x == a);
        let mut inner = String::new();
        if has("ETag") {
            // Unquoted here, as S3 writes it in this document.
            inner.push_str(&xml::element(
                "ETag",
                conditional::etag_of(&obj).trim_matches('"'),
            ));
        }
        if has("Checksum") {
            let kept = match checksum::stored(&obj.annotations) {
                Some(kept) => kept.elements(),
                None => xml::element("ChecksumSHA256", &sha256_base64(&obj.layer)),
            };
            inner.push_str(&format!("<Checksum>{kept}</Checksum>"));
        }
        if has("ObjectParts")
            && let Some(sizes) = multipart::part_sizes(&obj.annotations)
        {
            let max = usize::try_from(max_parts).unwrap_or(1000);
            let marker = u32::try_from(marker).unwrap_or(u32::MAX);
            inner.push_str(&multipart::object_parts(&sizes, max, marker));
        }
        if has("StorageClass") {
            inner.push_str(&xml::element("StorageClass", "STANDARD"));
        }
        if has("ObjectSize") {
            inner.push_str(&xml::element("ObjectSize", &obj.size.to_string()));
        }
        let mut resp = xml::document("GetObjectAttributesResponse", &inner);
        insert(resp.headers_mut(), LAST_MODIFIED, &http_date(obj.modified));
        Ok(resp)
    })
    .await
}

/// `GET /s3/<bucket>/<key>?tagging|acl`: the configuration `canned` says an object has, once
/// the object is one the caller may read.
pub(super) async fn configuration(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    canned: super::canned::Canned,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !admitted(authz, accounts::Action::Read, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        Ok(match readable(store, authz, &segs)? {
            Some(_) => canned.answer(&ctx),
            None => no_such_key(&ctx),
        })
    })
    .await
}

/// How a PutObject's body is bound to its signature, by `x-amz-content-sha256`, and how it is
/// framed.
struct Payload {
    /// the (decoded) body's SHA-256, lowercase hex, when the header names one rather than
    /// `UNSIGNED-PAYLOAD` or a streaming mode
    sha256: Option<String>,
    /// how the body is framed when it is `aws-chunked`
    framing: Option<chunked::Framing>,
}

/// The header naming how long an `aws-chunked` body is once decoded.
const DECODED_LENGTH: &str = "x-amz-decoded-content-length";

/// The digests a PutObject asks to be checked against what arrives, each as bytes.
#[derive(Default)]
struct Expected {
    md5: Option<Vec<u8>>,
    /// the one `x-amz-checksum-*` it carries, as a header or in the trailer
    checksum: Option<Claim>,
}

/// An `x-amz-checksum-*` a request carries: its header, its text (to echo and keep once it
/// held) and the bytes the text decodes to.
struct Claim {
    header: &'static str,
    text: String,
    bytes: Vec<u8>,
}

/// The refusal of a second `x-amz-checksum-*`, as S3 words it.
const ONE_CHECKSUM: Refused = (
    StatusCode::BAD_REQUEST,
    "InvalidRequest",
    "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.",
);

/// What a PutObject's headers ask that cannot be served, or are malformed: a status, a code
/// and a message.
pub(super) type Refused = (StatusCode, &'static str, &'static str);

/// What `x-amz-content-sha256`, `Content-Encoding`, `x-amz-decoded-content-length` and
/// `x-amz-trailer` say of a PutObject's body. A streaming mode, or `aws-chunked` named among
/// the encodings, makes it an `aws-chunked` body; no other encoding is decoded, so none is
/// taken beside it.
fn payload(headers: &HeaderMap) -> std::result::Result<Payload, Refused> {
    let invalid = |message| (StatusCode::BAD_REQUEST, "InvalidRequest", message);
    let mut sent = headers.get_all("x-amz-content-sha256").iter();
    let value = sent.next().map(|v| v.to_str().unwrap_or_default());
    if sent.next().is_some() {
        return Err(invalid("x-amz-content-sha256 is sent once"));
    }
    let (sha256, streaming) = match value {
        None | Some("UNSIGNED-PAYLOAD") => (None, None),
        Some(v) if v.starts_with("STREAMING-") => match chunked::Mode::of(v) {
            Some(mode) => (None, Some(mode)),
            None => {
                return Err((
                    StatusCode::NOT_IMPLEMENTED,
                    "NotImplemented",
                    "the streaming payloads taken are STREAMING-AWS4-HMAC-SHA256-PAYLOAD, its \
                     -TRAILER form and STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                ));
            }
        },
        Some(v) if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) => {
            (Some(v.to_ascii_lowercase()), None)
        }
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-content-sha256 is UNSIGNED-PAYLOAD, the body's SHA-256 in hex, or a \
                 streaming mode",
            ));
        }
    };
    let (mut chunked, mut other) = (false, false);
    for encoding in headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .flat_map(|v| v.to_str().unwrap_or("?").split(','))
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        if encoding.eq_ignore_ascii_case("aws-chunked") {
            chunked = true;
        } else if !encoding.eq_ignore_ascii_case("identity") {
            other = true;
        }
    }
    let Some(mode) = streaming.or(chunked.then_some(chunked::Mode::Unsigned)) else {
        if headers.contains_key("x-amz-trailer") {
            return Err(invalid("x-amz-trailer is for a -TRAILER streaming payload"));
        }
        return Ok(Payload {
            sha256,
            framing: None,
        });
    };
    if other {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "an aws-chunked body is decoded, and no other content encoding with it",
        ));
    }
    let declared = headers
        .get(DECODED_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or(invalid(
            "an aws-chunked body needs x-amz-decoded-content-length, its decoded length",
        ))?;
    let trailer = match headers.get("x-amz-trailer") {
        None => None,
        Some(_) if !mode.trailer() => {
            return Err(invalid("x-amz-trailer is for a -TRAILER streaming payload"));
        }
        Some(v) => {
            let name = v.to_str().unwrap_or_default().trim();
            let known = checksum::ALGORITHMS
                .into_iter()
                .map(|(header, _, _)| header)
                .find(|c| c.eq_ignore_ascii_case(name));
            match known {
                Some(header) => Some(header),
                None if !name.contains(',')
                    && name
                        .to_ascii_lowercase()
                        .starts_with(checksum::HEADER_PREFIX) =>
                {
                    return Err(checksum::NOT_COMPUTED);
                }
                None => return Err(invalid("x-amz-trailer names one x-amz-checksum header")),
            }
        }
    };
    Ok(Payload {
        sha256,
        framing: Some(chunked::Framing {
            mode,
            declared,
            trailer,
        }),
    })
}

/// Header `name`'s text and the bytes it decodes to from base64, `len` of them: `Ok(None)`
/// when it is not sent, `Err` when it is not that.
pub(super) fn base64_header(
    headers: &HeaderMap,
    name: &str,
    len: usize,
) -> std::result::Result<Option<(String, Vec<u8>)>, ()> {
    let Some(v) = headers.get(name) else {
        return Ok(None);
    };
    let text = v.to_str().map_err(|_| ())?.trim();
    let bytes = crate::auth::base64_decode(text)
        .filter(|b| b.len() == len)
        .ok_or(())?;
    Ok(Some((text.to_string(), bytes)))
}

/// The `Content-MD5` a request sends, as bytes.
fn content_md5(headers: &HeaderMap) -> std::result::Result<Option<Vec<u8>>, Refused> {
    let md5 = base64_header(headers, "content-md5", 16).map_err(|()| {
        (
            StatusCode::BAD_REQUEST,
            "InvalidDigest",
            "Content-MD5 is the body's MD5 in base64",
        )
    })?;
    Ok(md5.map(|(_, b)| b))
}

/// What a request's headers ask to be checked: its `Content-MD5` and the one
/// `x-amz-checksum-*` it carries, in an algorithm computed here; a second one is refused as
/// S3 refuses it, and one in another algorithm as not implemented.
fn expected(headers: &HeaderMap) -> std::result::Result<Expected, Refused> {
    if checksum::not_computed(headers) {
        return Err(checksum::NOT_COMPUTED);
    }
    let mut out = Expected {
        md5: content_md5(headers)?,
        ..Expected::default()
    };
    for (name, _, len) in checksum::ALGORITHMS {
        let value = base64_header(headers, name, len).map_err(|()| {
            (
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "an x-amz-checksum header is the checksum of the body in base64",
            )
        })?;
        if let Some((text, bytes)) = value {
            if out.checksum.is_some() {
                return Err(ONE_CHECKSUM);
            }
            out.checksum = Some(Claim {
                header: name,
                text,
                bytes,
            });
        }
    }
    // An SDK names the algorithm of the checksum it sends: one naming another is refused as
    // S3 refuses it, so the checksum is checked in the algorithm the client meant.
    if let (Some(named), Some(claim)) = (headers.get(checksum::SDK_ALGORITHM), &out.checksum)
        && !checksum::algorithm(claim.header)
            .is_some_and(|a| named.as_bytes().eq_ignore_ascii_case(a.as_bytes()))
    {
        return Err(checksum::ALGORITHM_MISMATCH);
    }
    Ok(out)
}

impl Expected {
    /// The trailer's checksum `name`d, as sent: base64 of the checksum's length.
    fn trailer(&mut self, name: &'static str, text: &str) -> std::result::Result<(), Refused> {
        let bytes = crate::auth::base64_decode(text)
            .filter(|b| Some(b.len()) == checksum::len(name))
            .ok_or((
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "the trailer's x-amz-checksum is the checksum of the body in base64",
            ))?;
        self.checksum = Some(Claim {
            header: name,
            text: text.to_string(),
            bytes,
        });
        Ok(())
    }
}

/// The digests computed while a body streams: MD5 always (the ETag), and the checksum the
/// request asks to be checked against, in its algorithm, when that is not the SHA-256 the
/// store computes anyway.
struct Digests {
    md5: md5::Context,
    checksum: Option<checksum::Hasher>,
}

impl Digests {
    /// The digests `expected` asks for, or the one a trailer announced as `trailer`.
    fn for_(expected: &Expected, trailer: Option<&str>) -> Self {
        let header = expected.checksum.as_ref().map(|c| c.header).or(trailer);
        Digests {
            md5: md5::Context::new(),
            checksum: header.and_then(checksum::Hasher::for_),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.md5.consume(data);
        if let Some(h) = &mut self.checksum {
            h.update(data);
        }
    }
}

/// Check what arrived against what the request said of it: its `md5`, and its checksum,
/// which is `sha256` for that algorithm and `computed` for any other.
fn verify(
    expected: &Expected,
    md5: &[u8],
    sha256: Option<&[u8]>,
    computed: Option<Vec<u8>>,
) -> std::result::Result<(), Refused> {
    if expected.md5.as_deref().is_some_and(|m| m != md5) {
        return Err((
            StatusCode::BAD_REQUEST,
            "BadDigest",
            "the Content-MD5 you specified did not match what was received",
        ));
    }
    if let Some(claim) = &expected.checksum {
        let got = if claim.header == CHECKSUM_SHA256 {
            sha256
        } else {
            computed.as_deref()
        };
        if got != Some(claim.bytes.as_slice()) {
            return Err(checksum::mismatch(claim.header));
        }
    }
    Ok(())
}

/// Check a request document read whole (a `Delete`) against what its headers say of it, as a
/// PutObject's body is checked: the signed `x-amz-content-sha256`, `Content-MD5` and the
/// `x-amz-checksum-*` header. A document is sent whole, not `aws-chunked`.
pub(super) fn check_body(headers: &HeaderMap, body: &[u8]) -> std::result::Result<(), Refused> {
    check_document(headers, body)?;
    let expected = expected(headers)?;
    let computed = expected
        .checksum
        .as_ref()
        .and_then(|c| checksum::of(c.header, body));
    verify(
        &expected,
        &md5::compute(body).0,
        Some(&sha2::Sha256::digest(body)),
        computed,
    )
}

/// [`check_body`] for a document whose `x-amz-checksum-*` headers are not its own (a
/// `CompleteMultipartUpload`'s are the object's): the signed `x-amz-content-sha256` and
/// `Content-MD5` only.
pub(super) fn check_document(headers: &HeaderMap, body: &[u8]) -> std::result::Result<(), Refused> {
    let payload = payload(headers)?;
    if payload.framing.is_some() {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "a request document is sent whole, not aws-chunked",
        ));
    }
    if payload
        .sha256
        .is_some_and(|signed| signed != crate::hex_of(&sha2::Sha256::digest(body)))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
            "the body's SHA-256 is not the x-amz-content-sha256 the request was signed with",
        ));
    }
    let expected = Expected {
        md5: content_md5(headers)?,
        ..Expected::default()
    };
    verify(&expected, &md5::compute(body).0, None, None)
}

/// Why a write at a path that takes no object is refused: what is in the way.
pub(super) fn unwritable_message(why: Unwritable) -> &'static str {
    match why {
        Unwritable::TopLevel => "a bucket takes no object of its own name",
        Unwritable::Directory => "this key is a prefix of other keys, and cannot be an object",
        Unwritable::Foreign => "this key holds content that is not a file, pushed over /v2/",
        Unwritable::UnderObject => "a prefix of this key is an object, which cannot hold keys",
    }
}

/// The answer to a write at a path that takes no object, with what is in the way.
pub(super) fn unwritable(why: Unwritable, ctx: &Ctx) -> Response<Body> {
    ctx.error(
        StatusCode::CONFLICT,
        "OperationAborted",
        unwritable_message(why),
    )
}

/// Whether a write's declared length, `Content-Length` or `x-amz-decoded-content-length`, is
/// past the object cap: refused unread, and the connection then closes.
pub(super) fn declared_too_large(headers: &HeaderMap) -> bool {
    let over = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > MAX_OBJECT)
    };
    over(CONTENT_LENGTH.as_str()) || over(DECODED_LENGTH)
}

/// What a write's headers say of its body, checked before it is read: how it is framed and
/// bound to the signature, and the digests it is to be checked against.
pub(super) struct Plan {
    payload: Payload,
    expected: Expected,
}

/// The [`Plan`] of a write's body, or why its headers are refused.
pub(super) fn plan(headers: &HeaderMap) -> std::result::Result<Plan, Refused> {
    let payload = payload(headers)?;
    let expected = expected(headers)?;
    if payload.framing.is_some_and(|f| f.trailer.is_some()) && expected.checksum.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "a checksum is sent as a header or in the trailer, not both",
        ));
    }
    // As beside a checksum header: the trailer's checksum is in the algorithm the SDK names.
    if let (Some(named), Some(trailer)) = (
        headers.get(checksum::SDK_ALGORITHM),
        payload.framing.and_then(|f| f.trailer),
    ) && !checksum::algorithm(trailer)
        .is_some_and(|a| named.as_bytes().eq_ignore_ascii_case(a.as_bytes()))
    {
        return Err(checksum::ALGORITHM_MISMATCH);
    }
    Ok(Plan { payload, expected })
}

/// A write's body, received whole and checked against what its request said of it.
pub(super) struct Received {
    /// the bytes, staged
    pub(super) staged: files::Staged,
    pub(super) md5: [u8; 16],
    /// the `x-amz-checksum-*` that held, its header and text: to echo, and to keep
    pub(super) echo: Option<(&'static str, String)>,
}

/// Stream `body` into `staging` (a private file just created, and its path) while hashing it,
/// as `plan` says it is framed, then check it against what `plan` says of it. An
/// `aws-chunked` body is decoded on the way, its chunk signatures checked against `seed` when
/// there is one, and its trailer's checksum checked as a header's would be. `Ok(Err(answer))`
/// for a body refused, whose staging file is then gone; a body refused part way is not read
/// past where it went wrong, and the answer closes the connection.
pub(super) async fn receive(
    plan: Plan,
    body: Incoming,
    seed: Option<chunked::Seed>,
    (path, file): (std::path::PathBuf, std::fs::File),
    ctx: &Ctx,
) -> Result<std::result::Result<Received, Response<Body>>> {
    let Plan {
        payload,
        mut expected,
    } = plan;
    let mut digests = Digests::for_(&expected, payload.framing.and_then(|f| f.trailer));
    let mut tap = |d: &[u8]| digests.update(d);
    let (staged, trailer) = match payload.framing {
        None => (files::stage_into(path, file, body, &mut tap).await, None),
        Some(framing) => {
            let mut body = chunked::Decoder::new(body, framing, seed);
            let staged = files::stage_into(path, file, &mut body, &mut tap).await;
            let trailer = body
                .trailer()
                .map(|(name, value)| (name, value.to_string()));
            (staged, trailer)
        }
    };
    let staged = match staged {
        Ok(staged) => staged,
        Err(PutError::TooLarge) => return Ok(Err(ctx.too_large())),
        Err(PutError::Failed(e)) => match e.downcast_ref::<chunked::Error>() {
            Some(chunked::Error::Refused(why)) => {
                return Ok(Err(ctx.error(why.status, why.code, why.message)));
            }
            _ => return Err(e),
        },
    };
    // A refusal from here on drops `staged`, which unlinks it.
    if let Some((name, value)) = trailer
        && let Err((status, code, message)) = expected.trailer(name, &value)
    {
        return Ok(Err(ctx.error(status, code, message)));
    }
    if let Some(signed) = &payload.sha256
        && *signed != staged.hex
    {
        return Ok(Err(ctx.error(
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
            "the body's SHA-256 is not the x-amz-content-sha256 the request was signed with",
        )));
    }
    let md5 = digests.md5.finalize().0;
    let computed = digests.checksum.map(checksum::Hasher::finalize);
    let sha256 = hex_bytes(&staged.hex);
    if let Err((status, code, message)) = verify(&expected, &md5, sha256.as_deref(), computed) {
        return Ok(Err(ctx.error(status, code, message)));
    }
    Ok(Ok(Received {
        staged,
        md5,
        echo: expected.checksum.map(|c| (c.header, c.text)),
    }))
}

/// The 200 a write answers: its `etag` (quoted) and the checksum that held.
pub(super) fn written(etag: &str, echo: Option<(&'static str, String)>) -> Result<Response<Body>> {
    written_of(etag, echo, None)
}

/// [`written`] for an object of `size` bytes, which the answer names (`x-amz-object-size`),
/// as S3's PutObject does; a part's answer names none.
fn written_of(
    etag: &str,
    echo: Option<(&'static str, String)>,
    size: Option<u64>,
) -> Result<Response<Body>> {
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, "0")
        .body(body_of(bytes::Bytes::new()))?;
    let headers = resp.headers_mut();
    insert(headers, ETAG, etag);
    if let Some((name, value)) = echo {
        insert(
            headers,
            hyper::header::HeaderName::from_static(name),
            &value,
        );
    }
    if let Some(size) = size {
        insert(
            headers,
            hyper::header::HeaderName::from_static(OBJECT_SIZE),
            &size.to_string(),
        );
    }
    Ok(resp)
}

/// The header a PutObject's answer names the object's size in, which SDKs read back.
const OBJECT_SIZE: &str = "x-amz-object-size";

/// `PUT /s3/<bucket>/<key>`: stream the body into staging while hashing it, check it against
/// what the request said of it ([`receive`]), then tag it under the namespace lock, with its
/// MD5, the checksum that held and its user metadata on the manifest and the request's
/// `If-None-Match: *`/`If-Match` checked there. Its `Content-Type` is not kept: every object
/// is served as bytes.
pub(super) async fn put(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    seed: Option<chunked::Seed>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    let parent = object_of(&segs).map(|(parent, _)| parent);
    if !parent.is_some_and(|p| allowed(authz, accounts::Action::Write, &p)) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let headers = req.headers();
    if declared_too_large(headers) {
        return Ok(ctx.too_large());
    }
    let plan = match plan(headers) {
        Ok(plan) => plan,
        Err((status, code, message)) => {
            return refuse(req, ctx.error(status, code, message), ctx).await;
        }
    };
    let mut annotations = match meta::annotations(headers) {
        Ok(a) => a,
        Err(why) => {
            let resp = ctx.error(StatusCode::BAD_REQUEST, why.code, why.message);
            return refuse(req, resp, ctx).await;
        }
    };
    let Ok(conditions) = WriteConditions::of(headers) else {
        let resp = ctx.error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "a write's If-None-Match is * or nothing",
        );
        return refuse(req, resp, ctx).await;
    };
    // Refused before the body is staged when the answer is already known; checked again
    // once it is, under the namespace lock.
    let early = {
        let (store, segs) = (Arc::clone(&state.store), segs.clone());
        tokio::task::spawn_blocking(move || files::unwritable(&store, &segs))
            .await
            .context("checking a PUT panicked")??
    };
    if let Some(why) = early {
        return refuse(req, unwritable(why, ctx), ctx).await;
    }

    let staging = state.store.stage_file()?;
    let received = match receive(plan, req.into_body(), seed, staging, ctx).await? {
        Ok(received) => received,
        Err(resp) => return Ok(resp),
    };
    let md5_hex = crate::hex_of(&received.md5);
    annotations.insert(MD5_ANNOTATION.to_string(), md5_hex.clone());
    let kept = received
        .echo
        .as_ref()
        .and_then(|(header, text)| checksum::annotation(header, text));
    if let Some((name, value)) = kept.clone() {
        annotations.insert(name, value);
    }
    let size = received.staged.size;
    let how = Commit {
        annotations,
        precondition: conditions.precondition(),
        uncompressed: size >= UNCOMPRESSED_FROM,
    };
    let written = files::commit(Arc::clone(&state.store), segs, received.staged, how).await?;
    match written {
        Written::Created | Written::Replaced => {}
        Written::Refused(why) => return Ok(unwritable(why, ctx)),
        Written::PreconditionFailed => {
            return Ok(ctx.error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "at least one of the preconditions you specified did not hold",
            ));
        }
    }
    let mut resp = written_of(&format!("\"{md5_hex}\""), received.echo, Some(size))?;
    if kept.is_some() {
        resp.headers_mut().insert(
            checksum::TYPE_HEADER,
            HeaderValue::from_static(checksum::FULL_OBJECT),
        );
    }
    Ok(resp)
}

/// `DELETE /s3/<bucket>/<key>`: 204 whether or not the key held an object, as S3 answers;
/// a key that is a directory has no object to delete, and is 204 too. A foreign tag is not
/// this view's to delete (409), and a caller that may read the object but not write it is
/// refused (403). Under the namespace lock, as every change of `files/` is.
pub(super) async fn delete(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !admitted(authz, accounts::Action::Write, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    if let Some(resp) = drain(req, ctx).await? {
        return Ok(resp);
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        let namespace = files::namespace(store)?;
        Ok(match delete_one(store, &namespace, authz, &segs)? {
            Deleted::Gone => no_content(),
            Deleted::Denied => ctx.access_denied(),
            Deleted::Foreign => unwritable(Unwritable::Foreign, &ctx),
        })
    })
    .await
}

/// What [`delete_one`] did.
pub(super) enum Deleted {
    /// no object is at the key now, whether or not one was, as far as the caller can tell
    Gone,
    /// the caller may read the object but not write it
    Denied,
    /// a foreign tag is there, which is not this view's to delete
    Foreign,
}

/// Delete the object at `segs` for this caller, the namespace held (`_namespace`): a key
/// that is a directory holds no object to delete. Writing the repository it is in is what
/// deletes it, reading it or not; one the caller may neither read nor write is absent.
pub(super) fn delete_one(
    store: &Store,
    _namespace: &files::Namespace,
    authz: &Authz<'_>,
    segs: &[String],
) -> Result<Deleted> {
    let Some(node) = files::resolve(store, segs)? else {
        return Ok(Deleted::Gone);
    };
    if !allowed(authz, accounts::Action::Write, node.repo()) {
        return Ok(match allowed(authz, accounts::Action::Read, node.repo()) {
            true => Deleted::Denied,
            false => Deleted::Gone,
        });
    }
    match node {
        Node::Object(obj) => {
            store.delete_tag(&obj.repo, &obj.tag)?;
        }
        Node::Foreign(_) => return Ok(Deleted::Foreign),
        Node::Dir(_) => {}
    }
    Ok(Deleted::Gone)
}

fn no_content() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(body_of(bytes::Bytes::new()))
        .expect("building a 204")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn a_payload_is_unsigned_its_sha256_or_chunked() {
        let code = |pairs: &[(&str, &str)]| payload(&headers(pairs)).err().map(|e| e.1);
        let plain = |pairs: &[(&str, &str)]| {
            let p = payload(&headers(pairs)).ok().unwrap();
            assert!(p.framing.is_none());
            p.sha256
        };
        assert_eq!(plain(&[]), None);
        assert_eq!(plain(&[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")]), None);
        let hex = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let lower = Some(hex.to_ascii_lowercase());
        assert_eq!(plain(&[("x-amz-content-sha256", hex)]), lower);
        // Another encoding alone is not ours to decode, and is kept as it was sent.
        assert_eq!(plain(&[("content-encoding", "gzip")]), None);
        assert_eq!(
            code(&[("x-amz-content-sha256", "abc")]),
            Some("InvalidArgument")
        );
        assert_eq!(
            code(&[
                ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
                ("x-amz-content-sha256", hex)
            ]),
            Some("InvalidRequest")
        );

        let length = ("x-amz-decoded-content-length", "13");
        let framing = |pairs: &[(&str, &str)]| {
            let p = payload(&headers(pairs)).ok().unwrap();
            (p.sha256, p.framing.unwrap())
        };
        for (value, mode) in [
            ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", chunked::Mode::Signed),
            (
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
                chunked::Mode::SignedTrailer,
            ),
            (
                "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                chunked::Mode::UnsignedTrailer,
            ),
        ] {
            let (sha256, f) = framing(&[("x-amz-content-sha256", value), length]);
            assert_eq!(
                (sha256, f.mode, f.declared, f.trailer),
                (None, mode, 13, None)
            );
            assert_eq!(
                code(&[("x-amz-content-sha256", value)]),
                Some("InvalidRequest"),
                "{value} without its decoded length"
            );
        }
        // aws-chunked named among the encodings, with any other payload hash.
        let (sha256, f) = framing(&[
            ("content-encoding", "aws-chunked"),
            ("x-amz-content-sha256", hex),
            length,
        ]);
        assert_eq!((sha256, f.mode), (lower, chunked::Mode::Unsigned));
        let (_, f) = framing(&[("content-encoding", "identity, AWS-Chunked"), length]);
        assert_eq!(f.mode, chunked::Mode::Unsigned);
        assert_eq!(
            code(&[("content-encoding", "aws-chunked,gzip"), length]),
            Some("NotImplemented")
        );
        assert_eq!(
            code(&[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", "-1")
            ]),
            Some("InvalidRequest")
        );
        assert_eq!(
            code(&[(
                "x-amz-content-sha256",
                "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
            )]),
            Some("NotImplemented")
        );

        // The trailer's checksum, in the trailer modes only.
        let trailer = ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        let (_, f) = framing(&[trailer, length, ("x-amz-trailer", "X-Amz-Checksum-CRC32")]);
        assert_eq!(f.trailer, Some("x-amz-checksum-crc32"));
        for bad in ["x-amz-checksum-crc32,x-amz-checksum-sha1", ""] {
            assert_eq!(
                code(&[trailer, length, ("x-amz-trailer", bad)]),
                Some("InvalidRequest"),
                "{bad}"
            );
        }
        assert_eq!(
            code(&[trailer, length, ("x-amz-trailer", "x-amz-checksum-xxhash3")]),
            Some("NotImplemented")
        );
        let signed = ("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        let crc = ("x-amz-trailer", "x-amz-checksum-crc32");
        assert_eq!(code(&[signed, length, crc]), Some("InvalidRequest"));
        assert_eq!(code(&[crc]), Some("InvalidRequest"));
    }

    #[test]
    fn a_trailer_checksum_is_checked_as_a_header_is() {
        let mut e = Expected::default();
        let crc = vk_hub_proto::to_base64(&[1, 2, 3, 4]);
        e.trailer("x-amz-checksum-crc32", &crc).ok().unwrap();
        let claim = e.checksum.as_ref().unwrap();
        assert_eq!(claim.bytes, [1, 2, 3, 4]);
        assert_eq!(
            (claim.header, claim.text.as_str()),
            ("x-amz-checksum-crc32", crc.as_str())
        );
        let nvme = vk_hub_proto::to_base64(&[0; 8]);
        e.trailer("x-amz-checksum-crc64nvme", &nvme).ok().unwrap();
        let claim = e.checksum.as_ref().unwrap();
        assert_eq!(
            (claim.header, claim.bytes.len()),
            ("x-amz-checksum-crc64nvme", 8)
        );
        assert!(e.trailer("x-amz-checksum-sha256", &crc).is_err());
        assert!(e.trailer("x-amz-checksum-crc32c", "!!").is_err());
        assert!(e.trailer("x-amz-checksum-md5", &crc).is_err());
    }

    #[test]
    fn checksums_are_base64_of_their_length_and_one_at_most() {
        let md5 = vk_hub_proto::to_base64(&[0u8; 16]);
        let sha = vk_hub_proto::to_base64(&[1u8; 32]);
        let e = expected(&headers(&[
            ("content-md5", &md5),
            ("x-amz-checksum-sha256", &sha),
        ]))
        .ok()
        .unwrap();
        assert_eq!(e.md5, Some(vec![0u8; 16]));
        let claim = e.checksum.unwrap();
        assert_eq!(
            (claim.header, claim.text.as_str()),
            ("x-amz-checksum-sha256", sha.as_str())
        );
        assert_eq!(claim.bytes, vec![1u8; 32]);
        for (name, len) in [
            ("x-amz-checksum-crc32", 4),
            ("x-amz-checksum-crc32c", 4),
            ("x-amz-checksum-sha1", 20),
            ("x-amz-checksum-crc64nvme", 8),
        ] {
            let value = vk_hub_proto::to_base64(&vec![2u8; len]);
            let e = expected(&headers(&[(name, &value)])).ok().unwrap();
            assert_eq!(e.checksum.unwrap().header, name);
        }
        let code = |pairs: &[(&str, &str)]| expected(&headers(pairs)).err().map(|e| e.1);
        assert_eq!(code(&[("content-md5", "AAAA")]), Some("InvalidDigest"));
        assert_eq!(code(&[("content-md5", "!!")]), Some("InvalidDigest"));
        assert_eq!(
            code(&[("x-amz-checksum-sha256", &md5)]),
            Some("InvalidRequest")
        );
        assert_eq!(
            code(&[("x-amz-checksum-crc32", &md5)]),
            Some("InvalidRequest")
        );
        assert_eq!(
            code(&[("x-amz-checksum-crc64nvme", "AAAAAA==")]),
            Some("InvalidRequest")
        );
        assert_eq!(
            code(&[("x-amz-checksum-xxhash64", "AAAAAAAAAAA=")]),
            Some("NotImplemented")
        );
        assert_eq!(
            code(&[("x-amz-sdk-checksum-algorithm", "XXHASH128")]),
            Some("NotImplemented")
        );
        assert_eq!(
            code(&[
                ("x-amz-sdk-checksum-algorithm", "CRC32"),
                ("x-amz-checksum-sha256", &sha)
            ]),
            Some("InvalidRequest")
        );
        assert!(
            expected(&headers(&[
                ("x-amz-sdk-checksum-algorithm", "sha256"),
                ("x-amz-checksum-sha256", &sha)
            ]))
            .is_ok()
        );
        assert_eq!(
            code(&[
                ("x-amz-checksum-sha256", &sha),
                ("x-amz-checksum-crc32", "AAAAAA==")
            ]),
            Some("InvalidRequest")
        );
        // A header beside a trailer, of any algorithm.
        let crc = ("x-amz-trailer", "x-amz-checksum-crc32");
        let streaming = ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
        let length = ("x-amz-decoded-content-length", "13");
        assert_eq!(
            plan(&headers(&[
                streaming,
                length,
                crc,
                ("x-amz-checksum-sha256", &sha)
            ]))
            .err()
            .map(|e| e.1),
            Some("InvalidRequest")
        );
        assert!(plan(&headers(&[streaming, length, crc])).is_ok());
        // The trailer is in the algorithm the SDK names, in any case.
        let sdk = |name| ("x-amz-sdk-checksum-algorithm", name);
        assert!(plan(&headers(&[streaming, length, crc, sdk("crc32")])).is_ok());
        assert_eq!(
            plan(&headers(&[streaming, length, crc, sdk("SHA1")])).err(),
            Some(checksum::ALGORITHM_MISMATCH)
        );
    }

    #[test]
    fn hex_decodes_whole_bytes_only() {
        assert_eq!(hex_bytes("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(hex_bytes("0"), None);
        assert_eq!(hex_bytes("zz"), None);
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            sha256_base64(sha),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
    }
}
