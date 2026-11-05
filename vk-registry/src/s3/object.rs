//! Objects: PutObject, GetObject and HeadObject, GetObjectAttributes and DeleteObject, over
//! the object layer the WebDAV view shares. Authorized as that view authorizes: a write needs
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
use sha1::Digest as _;

use super::conditional::{self, Conditions, MD5_ANNOTATION, Outcome, WriteConditions};
use super::range::{self, Range};
use super::{Ctx, chunked, drain, meta, refuse, xml};
use crate::dav::http_date;
use crate::files::{
    self, Commit, MAX_OBJECT, Node, Object, PutError, Unwritable, Written, allowed, object_of,
    repo_name,
};
use crate::{Authz, Body, ServerState, Store, accounts, body_of};

/// The header asking a read for the object's checksum.
const CHECKSUM_MODE: &str = "x-amz-checksum-mode";

/// The checksum a read answers with, when asked: the SHA-256 the store names the bytes by.
const CHECKSUM_SHA256: &str = "x-amz-checksum-sha256";

/// Whether this caller may `action` on the key at `segs` or on its parent: what admits a
/// request to the lookup that then decides on the repository the key resolves to.
fn admitted(authz: &Authz<'_>, action: accounts::Action, segs: &[String]) -> bool {
    allowed(authz, action, &repo_name(segs))
        || object_of(segs).is_some_and(|(parent, _)| allowed(authz, action, &parent))
}

fn no_such_key(ctx: &Ctx) -> Response<Body> {
    ctx.error(
        StatusCode::NOT_FOUND,
        "NoSuchKey",
        "the specified key does not exist",
    )
}

/// The object at `segs` as this caller may read it: `None` when nothing is there, when a
/// directory or a foreign tag is, or when the caller may not read the repository it is in or
/// its bytes through it.
fn readable(store: &Store, authz: &Authz<'_>, segs: &[String]) -> Result<Option<Object>> {
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
/// the one byte range `Range` asks for (206) when `If-Range`, if sent, still holds; a HEAD
/// answers what the GET would. A GET served, whole or in part, refreshes an idle object's tag
/// as a WebDAV GET does; a HEAD touches nothing.
pub(super) async fn get(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    head: bool,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !admitted(authz, accounts::Action::Read, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let conditions = Conditions::of(req.headers());
    let asked = range::Asked::of(req.headers());
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
        let mut resp = match asked.resolve(&etag, obj.modified, obj.size) {
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
        let headers = resp.headers_mut();
        headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
        insert(headers, ETAG, &etag);
        insert(headers, LAST_MODIFIED, &modified);
        if checksum {
            insert(
                headers,
                hyper::header::HeaderName::from_static(CHECKSUM_SHA256),
                &sha256_base64(&obj.layer),
            );
        }
        for (name, value) in meta::headers(&obj.annotations) {
            headers.append(name, value);
        }
        Ok(resp)
    })
    .await
}

/// `GET /s3/<bucket>/<key>?attributes`: what `x-amz-object-attributes` asks of `ETag`,
/// `Checksum`, `ObjectSize` and `StorageClass` (`ObjectParts` has nothing to say of an object
/// written whole), with `Last-Modified`. A metadata read, so it touches nothing.
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
            inner.push_str(&format!(
                "<Checksum>{}</Checksum>",
                xml::element("ChecksumSHA256", &sha256_base64(&obj.layer))
            ));
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

/// How a PutObject's body is bound to its signature, by `x-amz-content-sha256`, and how it is
/// framed.
struct Payload {
    /// the (decoded) body's SHA-256, lowercase hex, when the header names one rather than
    /// `UNSIGNED-PAYLOAD` or a streaming mode
    sha256: Option<String>,
    /// how the body is framed when it is `aws-chunked`
    framing: Option<chunked::Framing>,
}

/// The size from which a written object is stored uncompressed. The AWS CLI and SDK transfer
/// managers download an object past 8 MiB as parallel 8 MiB ranges, and a range of a
/// zstd-stored blob is decoded from the blob's start ([`Store::serve_blob_range`]): stored
/// compressed, an object of N bytes would cost about N²/16 MiB of decoding to download, where
/// stored plain each range is a seek. Below it, a range costs at most this much decoding.
const UNCOMPRESSED_FROM: u64 = 8 << 20;

/// The header naming how long an `aws-chunked` body is once decoded.
const DECODED_LENGTH: &str = "x-amz-decoded-content-length";

/// The digests a PutObject asks to be checked against what arrives, each as bytes.
#[derive(Default)]
struct Expected {
    md5: Option<Vec<u8>>,
    sha256: Option<Vec<u8>>,
    sha1: Option<Vec<u8>>,
    crc32: Option<Vec<u8>>,
    /// the `x-amz-checksum-*` headers to echo once they held
    echo: Vec<(&'static str, String)>,
}

/// What a PutObject's headers ask that cannot be served, or are malformed: a status, a code
/// and a message.
type Refused = (StatusCode, &'static str, &'static str);

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
            let known = chunked::CHECKSUMS
                .into_iter()
                .find(|c| c.eq_ignore_ascii_case(name));
            Some(known.ok_or(invalid("x-amz-trailer names one x-amz-checksum header"))?)
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

/// How many bytes the checksum a header or trailer `name`s is.
fn checksum_len(name: &str) -> usize {
    match name {
        "x-amz-checksum-sha256" => 32,
        "x-amz-checksum-sha1" => 20,
        "x-amz-checksum-crc64nvme" => 8,
        _ => 4,
    }
}

fn expected(headers: &HeaderMap) -> std::result::Result<Expected, Refused> {
    // The header's text and the bytes it decodes to, `len` of them.
    let decoded = |name: &str, len: usize| -> std::result::Result<Option<(String, Vec<u8>)>, ()> {
        let Some(v) = headers.get(name) else {
            return Ok(None);
        };
        let text = v.to_str().map_err(|_| ())?.trim();
        let bytes = crate::auth::base64_decode(text)
            .filter(|b| b.len() == len)
            .ok_or(())?;
        Ok(Some((text.to_string(), bytes)))
    };
    let md5 = decoded("content-md5", 16).map_err(|()| {
        (
            StatusCode::BAD_REQUEST,
            "InvalidDigest",
            "Content-MD5 is the body's MD5 in base64",
        )
    })?;
    let mut out = Expected {
        md5: md5.map(|(_, b)| b),
        ..Expected::default()
    };
    for (name, len) in [
        ("x-amz-checksum-sha256", 32),
        ("x-amz-checksum-sha1", 20),
        ("x-amz-checksum-crc32", 4),
    ] {
        let value = decoded(name, len).map_err(|()| {
            (
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "an x-amz-checksum header is the checksum of the body in base64",
            )
        })?;
        if let Some((text, value)) = value {
            out.expect(name, text, value);
        }
    }
    Ok(out)
}

impl Expected {
    /// Check the body against `value`, the checksum `name`s, and echo its `text` once it
    /// held: for the checksums this registry computes; any other is taken unchecked.
    fn expect(&mut self, name: &'static str, text: String, value: Vec<u8>) {
        let slot = match name {
            "x-amz-checksum-sha256" => &mut self.sha256,
            "x-amz-checksum-sha1" => &mut self.sha1,
            "x-amz-checksum-crc32" => &mut self.crc32,
            _ => return,
        };
        *slot = Some(value);
        self.echo.push((name, text));
    }

    /// The trailer's checksum `name`d, as sent: base64 of the checksum's length.
    fn trailer(&mut self, name: &'static str, text: &str) -> std::result::Result<(), Refused> {
        let value = crate::auth::base64_decode(text)
            .filter(|b| b.len() == checksum_len(name))
            .ok_or((
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "the trailer's x-amz-checksum is the checksum of the body in base64",
            ))?;
        self.expect(name, text.to_string(), value);
        Ok(())
    }
}

/// The digests computed while a body streams: MD5 always (the ETag), SHA-1 and CRC32 only
/// when the request asks to be checked against them.
struct Digests {
    md5: md5::Context,
    sha1: Option<sha1::Sha1>,
    crc32: Option<crc32fast::Hasher>,
}

impl Digests {
    /// The digests `expected` asks for, and the one a trailer announced as `trailer`.
    fn for_(expected: &Expected, trailer: Option<&str>) -> Self {
        let wanted = |set: bool, name| set || trailer == Some(name);
        Digests {
            md5: md5::Context::new(),
            sha1: wanted(expected.sha1.is_some(), "x-amz-checksum-sha1").then(sha1::Sha1::new),
            crc32: wanted(expected.crc32.is_some(), "x-amz-checksum-crc32")
                .then(crc32fast::Hasher::new),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.md5.consume(data);
        if let Some(h) = &mut self.sha1 {
            h.update(data);
        }
        if let Some(h) = &mut self.crc32 {
            h.update(data);
        }
    }
}

/// The answer to a write at a path that takes no object, with what is in the way.
fn unwritable(why: Unwritable, ctx: &Ctx) -> Response<Body> {
    let message = match why {
        Unwritable::TopLevel => "a bucket takes no object of its own name",
        Unwritable::Directory => "this key is a prefix of other keys, and cannot be an object",
        Unwritable::Foreign => "this key holds content that is not a file, pushed over /v2/",
        Unwritable::UnderObject => "a prefix of this key is an object, which cannot hold keys",
    };
    ctx.error(StatusCode::CONFLICT, "OperationAborted", message)
}

/// `PUT /s3/<bucket>/<key>`: stream the body into staging while hashing it, check it against
/// what the request said of it, then tag it under the namespace lock, with its MD5 and user
/// metadata on the manifest and the request's `If-None-Match: *`/`If-Match` checked there.
/// Its `Content-Type` is not kept: every object is served as bytes. An `aws-chunked` body is
/// decoded on the way, its chunk signatures checked against `seed` when there is one, and
/// its trailer's checksum checked as a header's would be.
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
    // A declared length over the cap is refused unread; the connection then closes.
    let over = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > MAX_OBJECT)
    };
    if over(CONTENT_LENGTH.as_str()) || over(DECODED_LENGTH) {
        return Ok(ctx.too_large());
    }
    if headers.contains_key("x-amz-copy-source") {
        return refuse(req, ctx.not_implemented(), ctx).await;
    }
    let checked = payload(headers).and_then(|p| {
        let trailer = p.framing.and_then(|f| f.trailer);
        if trailer.is_some_and(|name| headers.contains_key(name)) {
            return Err((
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "a checksum is sent as a header or in the trailer, not both",
            ));
        }
        Ok((p, expected(headers)?))
    });
    let (payload, mut expected) = match checked {
        Ok(checked) => checked,
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

    let mut digests = Digests::for_(&expected, payload.framing.and_then(|f| f.trailer));
    let mut tap = |d: &[u8]| digests.update(d);
    let (staged, trailer) = match payload.framing {
        None => (
            files::stage(&state.store, req.into_body(), &mut tap).await,
            None,
        ),
        Some(framing) => {
            let mut body = chunked::Decoder::new(req.into_body(), framing, seed);
            let staged = files::stage(&state.store, &mut body, &mut tap).await;
            let trailer = body
                .trailer()
                .map(|(name, value)| (name, value.to_string()));
            (staged, trailer)
        }
    };
    let staged = match staged {
        Ok(staged) => staged,
        Err(PutError::TooLarge) => return Ok(ctx.too_large()),
        // A body whose framing was refused is answered, unread past where it went wrong; the
        // answer closes the connection.
        Err(PutError::Failed(e)) => match e.downcast_ref::<chunked::Error>() {
            Some(chunked::Error::Refused(why)) => {
                return Ok(ctx.error(why.status, why.code, why.message));
            }
            _ => return Err(e),
        },
    };
    // A refusal from here on drops `staged`, which unlinks it: nothing is tagged.
    if let Some((name, value)) = trailer
        && let Err((status, code, message)) = expected.trailer(name, &value)
    {
        return Ok(ctx.error(status, code, message));
    }
    if let Some(signed) = &payload.sha256
        && *signed != staged.hex
    {
        return Ok(ctx.error(
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
            "the body's SHA-256 is not the x-amz-content-sha256 the request was signed with",
        ));
    }
    let md5 = digests.md5.finalize().0;
    let sha1 = digests.sha1.map(|h| h.finalize().to_vec());
    let crc32 = digests.crc32.map(|h| h.finalize().to_be_bytes().to_vec());
    if expected.md5.as_deref().is_some_and(|m| m != md5) {
        return Ok(ctx.error(
            StatusCode::BAD_REQUEST,
            "BadDigest",
            "the Content-MD5 you specified did not match what was received",
        ));
    }
    let sha256 = hex_bytes(&staged.hex);
    let mismatch = |expected: &Option<Vec<u8>>, got: &Option<Vec<u8>>| {
        expected.as_ref().is_some_and(|e| Some(e) != got.as_ref())
    };
    if mismatch(&expected.sha256, &sha256)
        || mismatch(&expected.sha1, &sha1)
        || mismatch(&expected.crc32, &crc32)
    {
        return Ok(ctx.error(
            StatusCode::BAD_REQUEST,
            "BadDigest",
            "the x-amz-checksum you specified did not match the checksum of what was received",
        ));
    }
    let md5_hex = crate::hex_of(&md5);
    annotations.insert(MD5_ANNOTATION.to_string(), md5_hex.clone());
    let how = Commit {
        annotations,
        precondition: conditions.precondition(),
        uncompressed: staged.size >= UNCOMPRESSED_FROM,
    };
    let written = files::commit(Arc::clone(&state.store), segs, staged, how).await?;
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
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, "0")
        .body(body_of(bytes::Bytes::new()))?;
    let headers = resp.headers_mut();
    insert(headers, ETAG, &format!("\"{md5_hex}\""));
    for (name, value) in expected.echo {
        insert(
            headers,
            hyper::header::HeaderName::from_static(name),
            &value,
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
        let _namespace = files::namespace(store)?;
        let node = match files::resolve(store, &segs)? {
            Some(node) if allowed(authz, accounts::Action::Read, node.repo()) => node,
            // Nothing there, as far as this caller can tell.
            _ => return Ok(no_content()),
        };
        if !allowed(authz, accounts::Action::Write, node.repo()) {
            return Ok(ctx.access_denied());
        }
        match node {
            Node::Object(obj) => {
                store.delete_tag(&obj.repo, &obj.tag)?;
            }
            Node::Foreign(_) => {
                return Ok(unwritable(Unwritable::Foreign, &ctx));
            }
            Node::Dir(_) => {}
        }
        Ok(no_content())
    })
    .await
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
        for bad in [
            "x-amz-checksum-md5",
            "x-amz-checksum-crc32,x-amz-checksum-sha1",
            "",
        ] {
            assert_eq!(
                code(&[trailer, length, ("x-amz-trailer", bad)]),
                Some("InvalidRequest"),
                "{bad}"
            );
        }
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
        assert_eq!(e.crc32, Some(vec![1, 2, 3, 4]));
        assert_eq!(e.echo, [("x-amz-checksum-crc32", crc.clone())]);
        // Taken unchecked, and not echoed.
        e.trailer(
            "x-amz-checksum-crc64nvme",
            &vk_hub_proto::to_base64(&[0; 8]),
        )
        .ok()
        .unwrap();
        assert_eq!(e.echo.len(), 1);
        assert!(e.trailer("x-amz-checksum-sha256", &crc).is_err());
        assert!(e.trailer("x-amz-checksum-crc32c", "!!").is_err());
    }

    #[test]
    fn checksums_are_base64_of_their_length() {
        let md5 = vk_hub_proto::to_base64(&[0u8; 16]);
        let sha = vk_hub_proto::to_base64(&[1u8; 32]);
        let e = expected(&headers(&[
            ("content-md5", &md5),
            ("x-amz-checksum-sha256", &sha),
            ("x-amz-checksum-crc32c", "AAAAAA=="),
        ]))
        .ok()
        .unwrap();
        assert_eq!(e.md5, Some(vec![0u8; 16]));
        assert_eq!(e.sha256, Some(vec![1u8; 32]));
        assert_eq!(e.echo, [("x-amz-checksum-sha256", sha.clone())]);
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
