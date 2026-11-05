//! Multipart uploads: CreateMultipartUpload, UploadPart and UploadPartCopy,
//! CompleteMultipartUpload, AbortMultipartUpload, ListParts and ListMultipartUploads.
//!
//! An upload is a private directory of the store, `uploads/s3/<id>/`, holding `meta.json`
//! (the bucket, the key, when it was created and the user metadata the object will carry)
//! and, for each part, `part-<n>` (its bytes) and `part-<n>.json` (their size and MD5). Each
//! file is written under a private temporary name and renamed over its own, so a part sent
//! again replaces the earlier one whole. Completing an upload concatenates the parts it names
//! into one staging file in a single pass off the runtime, hashing on the way, then promotes
//! and tags it as a PutObject's body is, its ETag `"<MD5 of the parts' MD5s>-<parts>"`; the
//! directory then goes. The gc sweeps an upload nothing has been written into for its grace
//! window, as it sweeps an idle OCI upload.
//!
//! Authorized as a PutObject is: `Write` on the key's parent repository, `Read` there for
//! ListParts, and ListMultipartUploads as a listing of the bucket. The upload id must name an
//! upload recorded for the request's own bucket and key, or it is `NoSuchUpload`; an id is
//! held to what this server mints (hex digits and dashes), so it never names a path.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::header::HeaderMap;
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use sha1::Digest as _;

use super::conditional::{self, Conditions, MD5_ANNOTATION, Outcome, WriteConditions};
use super::copy::{self, COPY_SOURCE, Source};
use super::object::{self, Refused, admitted, no_such_key, readable, unwritable};
use super::xml::scan::{self, Malformed};
use super::{
    Ctx, OPERATION_HINT, Params, UNCOMPRESSED_FROM, bucket, chunked, drain, list, meta, read_small,
    refuse, xml,
};
use crate::files::{self, Commit, FILES_REPO, MAX_OBJECT, Staged, Written, allowed, object_of};
use crate::{Authz, Body, STREAM_CHUNK, ServerState, Store, accounts, body_of};

/// Most parts an upload has, and the highest part number: S3's bound.
const MAX_PARTS: u32 = 10_000;

/// Longest `CompleteMultipartUpload` document taken.
const MAX_DOCUMENT: usize = 1 << 20;

/// Most elements a `CompleteMultipartUpload` document may hold: a `Part` and the five fields
/// S3 defines in it, for each part, and a few more around them.
const MAX_ELEMENTS: usize = 6 * MAX_PARTS as usize + 16;

/// Most entries a ListParts or ListMultipartUploads page holds: S3's bound.
const MAX_LISTED: usize = 1000;

/// What an upload records of itself, in its directory.
const META: &str = "meta.json";

/// Longest `meta.json` or part record read: far above what one can hold (a key, and at most
/// 2 KiB of user metadata).
const MAX_RECORD: u64 = 64 * 1024;

/// What an upload records of itself at its creation.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Meta {
    bucket: String,
    /// the key's components joined by `/`
    key: String,
    /// seconds since the epoch
    created: u64,
    /// the user metadata the object will carry, as [`meta::annotations`] made it
    annotations: BTreeMap<String, String>,
}

/// What a part's record says of it.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Part {
    size: u64,
    /// lowercase hex
    md5: String,
}

/// An upload this request may act on: its directory and what it recorded.
struct Upload {
    id: String,
    dir: PathBuf,
    meta: Meta,
}

/// The key a run of object components names below its bucket.
fn key_of(segs: &[String]) -> String {
    segs.get(1..).unwrap_or_default().join("/")
}

/// The bucket a run of object components names.
fn bucket_of(segs: &[String]) -> &str {
    segs.first().map_or("", String::as_str)
}

/// A query's parameters, already decoded ([`super::parse_query`]), the SDK's operation hint
/// left out.
fn params(query: &Params) -> Vec<(&str, &str)> {
    query
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .filter(|(n, _)| *n != OPERATION_HINT)
        .collect()
}

/// The value of the first parameter named `name`.
fn param<'a>(params: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    params.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// Whether `query` names a parameter `name`: what dispatches a request here.
pub(super) fn names(query: &Params, name: &str) -> bool {
    query.iter().any(|(n, _)| n == name)
}

/// Whether every parameter is one of `taken`.
fn only(params: &[(&str, &str)], taken: &[&str]) -> bool {
    params.iter().all(|(n, _)| taken.contains(n))
}

/// A part number as a query or a document gives it: 1 to [`MAX_PARTS`], in decimal.
fn part_number(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || s.len() > 5 {
        return None;
    }
    s.parse().ok().filter(|n| (1..=MAX_PARTS).contains(n))
}

/// The number of the part `name` records (`part-<n>.json`), with no leading zero.
fn recorded_part(name: &str) -> Option<u32> {
    let n = name.strip_prefix("part-")?.strip_suffix(".json")?;
    (!n.starts_with('0')).then(|| part_number(n)).flatten()
}

fn part_path(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("part-{n}"))
}

fn record_path(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("part-{n}.json"))
}

/// A record of at most [`MAX_RECORD`] bytes at `path`: `None` when it is absent or cannot be
/// read as one, which every caller takes as no upload or no part — failing closed, since
/// what a record says decides what an upload is for.
fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_RECORD)
        .read_to_end(&mut bytes)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The upload `id` names, when it is one recorded for the object at `segs`.
fn open(store: &Store, id: &str, segs: &[String]) -> Option<Upload> {
    let dir = store.multipart_dir(id)?;
    let meta: Meta = read_record(&dir.join(META))?;
    (meta.bucket == bucket_of(segs) && meta.key == key_of(segs)).then(|| Upload {
        id: id.to_string(),
        dir,
        meta,
    })
}

fn no_such_upload(ctx: &Ctx) -> Response<Body> {
    ctx.error(
        StatusCode::NOT_FOUND,
        "NoSuchUpload",
        "the specified multipart upload does not exist: its id may be wrong, or it was \
         completed or aborted",
    )
}

fn invalid(ctx: &Ctx, message: &str) -> Response<Body> {
    ctx.error(StatusCode::BAD_REQUEST, "InvalidArgument", message)
}

/// Whether this caller may `action` on the repository the object at `segs` would be in.
fn on_parent(authz: &Authz<'_>, action: accounts::Action, segs: &[String]) -> bool {
    object_of(segs).is_some_and(|(parent, _)| allowed(authz, action, &parent))
}

/// A private file to write into `dir` under a name of its own, `.<what>.<random>`, to be
/// renamed over the name it stands for once whole.
fn temp_in(dir: &Path, what: &str) -> Result<(PathBuf, std::fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(format!(".{what}.{}", accounts::random_token(8)));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok((path, file))
}

/// Install part `n` of the upload in `dir`: its bytes, staged in `dir`, renamed over the
/// part's, then its record. Each rename replaces its file whole, but the two are not one
/// step: a reader between them sees new bytes beside the old record, which is why Complete
/// checks every part's MD5 as it reads it.
fn install_part(dir: &Path, n: u32, staged: Staged, md5: &str) -> Result<()> {
    let size = staged.size;
    staged.rename_to(&part_path(dir, n))?;
    let record = serde_json::to_vec(&Part {
        size,
        md5: md5.to_string(),
    })?;
    vk_fs::write_atomic_unsynced(&record_path(dir, n), &record, 0o600)
}

/// `POST /s3/<bucket>/<key>?uploads`: a new upload of the key, its user metadata recorded for
/// the object. The key is checked now as a PutObject's would be (409 `OperationAborted`), and
/// again when the upload is completed.
pub(super) async fn create(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    query: &Params,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !on_parent(authz, accounts::Action::Write, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    if !only(&params(query), &["uploads"]) {
        return refuse(req, ctx.not_implemented(), ctx).await;
    }
    let headers = req.headers();
    if headers.contains_key(COPY_SOURCE) {
        let resp = invalid(
            ctx,
            "a multipart upload's parts are copied by UploadPartCopy, not named at its creation",
        );
        return refuse(req, resp, ctx).await;
    }
    let annotations = match meta::annotations(headers) {
        Ok(a) => a,
        Err(why) => {
            let resp = ctx.error(StatusCode::BAD_REQUEST, why.code, why.message);
            return refuse(req, resp, ctx).await;
        }
    };
    let algorithm = match checksum_algorithm(headers) {
        Ok(a) => a,
        Err(message) => {
            let resp = ctx.error(StatusCode::BAD_REQUEST, "InvalidRequest", message);
            return refuse(req, resp, ctx).await;
        }
    };
    if let Some(resp) = drain(req, ctx).await? {
        return Ok(resp);
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, _| {
        if let Some(why) = files::unwritable(store, &segs)? {
            return Ok(unwritable(why, &ctx));
        }
        let meta = Meta {
            bucket: bucket_of(&segs).to_string(),
            key: key_of(&segs),
            created: vk_peer::now_secs(),
            annotations,
        };
        let (id, dir) = store.create_multipart()?;
        let recorded = serde_json::to_vec(&meta)
            .map_err(anyhow::Error::from)
            .and_then(|json| vk_fs::write_atomic_unsynced(&dir.join(META), &json, 0o600));
        if let Err(e) = recorded {
            // An upload with no record is no upload; the gc would sweep it anyway.
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        let mut resp = xml::document(
            "InitiateMultipartUploadResult",
            &format!(
                "{}{}{}",
                xml::element("Bucket", &meta.bucket),
                xml::element("Key", &meta.key),
                xml::element("UploadId", &id)
            ),
        );
        if let Some(algorithm) = algorithm
            && let Ok(v) = hyper::header::HeaderValue::from_str(algorithm)
        {
            resp.headers_mut().insert("x-amz-checksum-algorithm", v);
        }
        Ok(resp)
    })
    .await
}

/// The `x-amz-checksum-algorithm` a creation names, as S3 spells it: the algorithm the
/// parts' checksums will be in, which each part's request then carries and is checked by.
fn checksum_algorithm(
    headers: &HeaderMap,
) -> std::result::Result<Option<&'static str>, &'static str> {
    let Some(v) = headers.get("x-amz-checksum-algorithm") else {
        return Ok(None);
    };
    ["CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"]
        .into_iter()
        .find(|a| v.as_bytes().eq_ignore_ascii_case(a.as_bytes()))
        .map(Some)
        .ok_or("x-amz-checksum-algorithm is CRC32, CRC32C, CRC64NVME, SHA1 or SHA256")
}

/// A request naming `uploadId` on an object, to the operation its method names.
pub(super) async fn upload(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    seed: Option<chunked::Seed>,
    query: &Params,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    let params = params(query);
    let id = param(&params, "uploadId").unwrap_or_default().to_string();
    let method = req.method().clone();
    let taken: &[&str] = match method {
        Method::PUT => &["uploadId", "partNumber"],
        Method::GET => &[
            "uploadId",
            "max-parts",
            "part-number-marker",
            "encoding-type",
        ],
        _ => &["uploadId"],
    };
    if !only(&params, taken) {
        return refuse(req, ctx.not_implemented(), ctx).await;
    }
    match method {
        Method::PUT => {
            let Some(n) = param(&params, "partNumber").and_then(part_number) else {
                let resp = invalid(ctx, "partNumber is a part's number, 1 to 10000");
                return refuse(req, resp, ctx).await;
            };
            if req.headers().contains_key(COPY_SOURCE) {
                copy_part(state, authz, segs, n, id, req, ctx).await
            } else {
                upload_part(state, authz, segs, n, id, seed, req, ctx).await
            }
        }
        Method::POST => complete(state, authz, segs, id, req, ctx).await,
        Method::DELETE => abort(state, authz, segs, id, req, ctx).await,
        Method::GET => list_parts(state, authz, segs, id, &params, req, ctx).await,
        _ => refuse(req, ctx.not_implemented(), ctx).await,
    }
}

/// The upload `id` names for the object at `segs`, looked up off the runtime.
async fn open_async(state: &ServerState, id: &str, segs: &[String]) -> Result<Option<Upload>> {
    let (store, id, segs) = (Arc::clone(&state.store), id.to_string(), segs.to_vec());
    tokio::task::spawn_blocking(move || open(&store, &id, &segs))
        .await
        .context("looking up an upload panicked")
}

/// `PUT /s3/<bucket>/<key>?partNumber=<n>&uploadId=<id>`: part `n`'s bytes, received as a
/// PutObject's body is (its payload modes, digests and checksums, an `aws-chunked` body
/// decoded) into the upload's directory, and installed over any earlier part `n`. 200 with
/// the part's ETag, its MD5.
#[allow(clippy::too_many_arguments)]
async fn upload_part(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    n: u32,
    id: String,
    seed: Option<chunked::Seed>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !on_parent(authz, accounts::Action::Write, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let headers = req.headers();
    if object::declared_too_large(headers) {
        return Ok(ctx.too_large());
    }
    let plan = match object::plan(headers) {
        Ok(plan) => plan,
        Err((status, code, message)) => {
            return refuse(req, ctx.error(status, code, message), ctx).await;
        }
    };
    let Some(up) = open_async(state, &id, &segs).await? else {
        return refuse(req, no_such_upload(ctx), ctx).await;
    };
    let staging = match temp_in(&up.dir, &format!("part-{n}")) {
        Ok(staging) => staging,
        // Completed or aborted since it was looked up.
        Err(_) if !up.dir.is_dir() => return refuse(req, no_such_upload(ctx), ctx).await,
        Err(e) => return Err(e),
    };
    let received = match object::receive(plan, req.into_body(), seed, staging, ctx).await? {
        Ok(received) => received,
        Err(resp) => return Ok(resp),
    };
    let md5 = crate::hex_of(&received.md5);
    let installed = {
        let (dir, md5) = (up.dir.clone(), md5.clone());
        tokio::task::spawn_blocking(move || install_part(&dir, n, received.staged, &md5))
            .await
            .context("installing a part panicked")?
    };
    match installed {
        Ok(()) => {}
        Err(_) if !up.dir.is_dir() => return Ok(no_such_upload(ctx)),
        Err(e) => return Err(e),
    }
    object::written(&format!("\"{md5}\""), received.echo)
}

/// The header naming the bytes of a part's source to copy.
const COPY_SOURCE_RANGE: &str = "x-amz-copy-source-range";

/// What `x-amz-copy-source-range` names: `bytes=<first>-<last>`, both given, first ≤ last.
fn copy_range(value: &str) -> Option<(u64, u64)> {
    let (first, last) = value.trim().strip_prefix("bytes=")?.split_once('-')?;
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    let (first, last) = (number(first)?, number(last)?);
    (first <= last).then_some((first, last))
}

/// `PUT …?partNumber=<n>&uploadId=<id>` with `x-amz-copy-source`: part `n` copied from an
/// object, whole or the bytes `x-amz-copy-source-range` names, read as CopyObject reads its
/// source and checked against the same `x-amz-copy-source-if-*` conditions. The bytes are
/// copied into the upload (a part is the upload's own until it completes), off the runtime,
/// hashed on the way. 200 with `CopyPartResult`.
async fn copy_part(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    n: u32,
    id: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !on_parent(authz, accounts::Action::Write, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let headers = req.headers();
    let value = headers
        .get(COPY_SOURCE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let src = match copy::source(value) {
        Source::Object(src) => src,
        Source::Versioned => {
            let resp = ctx.error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "this registry keeps no versions to copy from",
            );
            return refuse(req, resp, ctx).await;
        }
        Source::Invalid(code, message) => {
            let resp = ctx.error(StatusCode::BAD_REQUEST, code, message);
            return refuse(req, resp, ctx).await;
        }
    };
    if !admitted(authz, accounts::Action::Read, &src) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let range = match headers.get(COPY_SOURCE_RANGE) {
        None => None,
        Some(v) => match v.to_str().ok().and_then(copy_range) {
            Some(range) => Some(range),
            None => {
                let resp = invalid(
                    ctx,
                    "x-amz-copy-source-range is bytes=<first>-<last>, the zero-based offsets \
                     of the first and last bytes to copy",
                );
                return refuse(req, resp, ctx).await;
            }
        },
    };
    let conditions = Conditions::of_copy_source(headers);
    // A part copy has no body of its own; whatever came is read through first.
    if let Some(resp) = drain(req, ctx).await? {
        return Ok(resp);
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        let Some(up) = open(store, &id, &segs) else {
            return Ok(no_such_upload(&ctx));
        };
        let Some(obj) = readable(store, authz, &src)? else {
            return Ok(copy::absent(store, authz, &src, &ctx));
        };
        if conditions.evaluate(&conditional::etag_of(&obj), obj.modified) != Outcome::Serve {
            return Ok(copy::failed(&ctx));
        }
        let (start, len) = match range {
            None => (0, obj.size),
            Some((first, last)) if last < obj.size => (first, last - first + 1),
            Some(_) => {
                let size = obj.size.to_string();
                return Ok(xml::error(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "InvalidRange",
                    "x-amz-copy-source-range reaches past the source object's end",
                    &[("ActualObjectSize", &size)],
                    &ctx.path,
                    &ctx.id,
                ));
            }
        };
        let Some((_, mut reader)) = store.read_blob_range(&obj.layer, start, len)? else {
            return Ok(no_such_key(&ctx));
        };
        let (path, mut file) = match temp_in(&up.dir, &format!("part-{n}")) {
            Ok(staging) => staging,
            Err(_) if !up.dir.is_dir() => return Ok(no_such_upload(&ctx)),
            Err(e) => return Err(e),
        };
        let mut staged = Staged::written(path, 0, String::new());
        let mut md5 = md5::Context::new();
        let mut buf = vec![0u8; STREAM_CHUNK];
        loop {
            let got = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(got) => got,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(anyhow::Error::from(e).context("reading a part's source")),
            };
            let data = buf.get(..got).unwrap_or_default();
            md5.consume(data);
            file.write_all(data).context("writing a copied part")?;
            staged.size = staged.size.saturating_add(got as u64);
        }
        drop(file);
        let md5 = crate::hex_of(&md5.finalize().0);
        match install_part(&up.dir, n, staged, &md5) {
            Ok(()) => {}
            Err(_) if !up.dir.is_dir() => return Ok(no_such_upload(&ctx)),
            Err(e) => return Err(e),
        }
        Ok(xml::document(
            "CopyPartResult",
            &format!(
                "{}{}",
                xml::element("LastModified", &list::iso8601(SystemTime::now())),
                xml::element("ETag", &format!("\"{md5}\""))
            ),
        ))
    })
    .await
}

/// Why a `CompleteMultipartUpload` document is refused.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// 400 `MalformedXML`
    Malformed(&'static str),
    /// 400 `InvalidPartOrder`: the part numbers do not ascend
    Order,
}

/// The parts a `CompleteMultipartUpload` document names, in order: each part's number and
/// the ETag it is expected to have, unquoted and lowercase. Fields beside `PartNumber` and
/// `ETag` (the parts' checksums) are passed over.
fn document(body: &[u8]) -> std::result::Result<Vec<(u32, String)>, Refusal> {
    let root = scan::parse(body, MAX_ELEMENTS).map_err(|Malformed(why)| Refusal::Malformed(why))?;
    if root.name != "CompleteMultipartUpload" {
        return Err(Refusal::Malformed(
            "the document is not a CompleteMultipartUpload",
        ));
    }
    let mut parts: Vec<(u32, String)> = Vec::new();
    for p in root.all("Part") {
        let field = |name| {
            p.one(name)
                .map_err(|Malformed(why)| Refusal::Malformed(why))?
                .map(|e| e.text.trim().to_string())
                .ok_or(Refusal::Malformed(
                    "each Part names its PartNumber and ETag",
                ))
        };
        let n = part_number(&field("PartNumber")?)
            .ok_or(Refusal::Malformed("a PartNumber is 1 to 10000"))?;
        let etag = field("ETag")?;
        let etag = etag
            .strip_prefix('"')
            .and_then(|e| e.strip_suffix('"'))
            .unwrap_or(&etag)
            .to_ascii_lowercase();
        if parts.last().is_some_and(|(last, _)| *last >= n) {
            return Err(Refusal::Order);
        }
        parts.push((n, etag));
    }
    if parts.is_empty() {
        return Err(Refusal::Malformed(
            "a CompleteMultipartUpload names at least one Part",
        ));
    }
    Ok(parts)
}

/// The ETag of an object made of parts whose MD5s are `md5s`, unquoted: the MD5 of their
/// concatenated MD5s, then `-` and how many there are, as S3 makes it.
fn multipart_etag(md5s: &[[u8; 16]]) -> String {
    let mut all = md5::Context::new();
    for m in md5s {
        all.consume(m);
    }
    format!("{}-{}", crate::hex_of(&all.finalize().0), md5s.len())
}

/// The whole-object checksums a completion's headers name, as bytes: those of the
/// algorithms this registry computes, sent as a full object's. A composite checksum (a
/// checksum of the parts' checksums, `<base64>-<parts>`) or one of another algorithm is
/// passed over, since the parts were checked as they came.
#[derive(Default)]
struct WholeChecksums {
    sha256: Option<Vec<u8>>,
    sha1: Option<Vec<u8>>,
    crc32: Option<Vec<u8>>,
}

impl WholeChecksums {
    fn of(headers: &HeaderMap) -> Self {
        let full = |name, len| {
            object::base64_header(headers, name, len)
                .ok()
                .flatten()
                .map(|(_, bytes)| bytes)
        };
        WholeChecksums {
            sha256: full("x-amz-checksum-sha256", 32),
            sha1: full("x-amz-checksum-sha1", 20),
            crc32: full("x-amz-checksum-crc32", 4),
        }
    }
}

/// What [`assemble`] made: the object staged, and its ETag, unquoted.
struct Assembled {
    staged: Staged,
    etag: String,
}

/// Concatenate the `parts` of `up`, in order, into a staging file, in one pass, hashing on
/// the way: each part's MD5, checked against both the ETag asked and the part's record, so a
/// part replaced while this reads it is noticed rather than built in; the whole object's
/// SHA-256, and its SHA-1 and CRC32 when `whole` asks to be checked against them.
fn assemble(
    store: &Store,
    up: &Upload,
    parts: &[(u32, String)],
    whole: &WholeChecksums,
) -> Result<std::result::Result<Assembled, Refused>> {
    let invalid_part: Refused = (
        StatusCode::BAD_REQUEST,
        "InvalidPart",
        "one or more of the specified parts could not be found, or its ETag is not the one \
         given",
    );
    // Written into, so the gc takes the upload as in use while it is read.
    if let Ok(meta) = std::fs::File::open(up.dir.join(META)) {
        // A failure only leaves the upload as fresh as its last write.
        let _ = meta.set_modified(SystemTime::now());
    }
    let mut total: u64 = 0;
    for (n, etag) in parts {
        let Some(part) = read_record::<Part>(&record_path(&up.dir, *n)) else {
            return Ok(Err(invalid_part));
        };
        if part.md5 != *etag {
            return Ok(Err(invalid_part));
        }
        total = total.saturating_add(part.size);
    }
    let too_large: Refused = (
        StatusCode::PAYLOAD_TOO_LARGE,
        "EntityTooLarge",
        "an object is at most 4 GiB, its parts together",
    );
    if total > MAX_OBJECT {
        return Ok(Err(too_large));
    }

    let (path, mut out) = store.stage_file()?;
    let mut staged = Staged::written(path, 0, String::new());
    let mut sha256 = sha2::Sha256::new();
    let mut sha1 = whole.sha1.as_ref().map(|_| sha1::Sha1::new());
    let mut crc32 = whole.crc32.as_ref().map(|_| crc32fast::Hasher::new());
    let mut md5s = Vec::with_capacity(parts.len());
    let mut buf = vec![0u8; STREAM_CHUNK];
    for (n, etag) in parts {
        let mut file = match std::fs::File::open(part_path(&up.dir, *n)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Err(invalid_part)),
            Err(e) => return Err(anyhow::Error::from(e).context("opening a part")),
        };
        let mut md5 = md5::Context::new();
        loop {
            let got = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(got) => got,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(anyhow::Error::from(e).context("reading a part")),
            };
            staged.size = staged.size.saturating_add(got as u64);
            if staged.size > MAX_OBJECT {
                return Ok(Err(too_large));
            }
            let data = buf.get(..got).unwrap_or_default();
            md5.consume(data);
            sha256.update(data);
            if let Some(h) = &mut sha1 {
                h.update(data);
            }
            if let Some(h) = &mut crc32 {
                h.update(data);
            }
            out.write_all(data).context("writing an object")?;
        }
        let md5 = md5.finalize().0;
        if crate::hex_of(&md5) != *etag {
            return Ok(Err(invalid_part));
        }
        md5s.push(md5);
    }
    drop(out);
    let mismatch = |expected: &Option<Vec<u8>>, got: Option<Vec<u8>>| {
        expected.as_ref().is_some_and(|e| Some(e) != got.as_ref())
    };
    let sha256 = sha256.finalize().to_vec();
    if mismatch(&whole.sha256, Some(sha256.clone()))
        || mismatch(&whole.sha1, sha1.map(|h| h.finalize().to_vec()))
        || mismatch(
            &whole.crc32,
            crc32.map(|h| h.finalize().to_be_bytes().to_vec()),
        )
    {
        return Ok(Err((
            StatusCode::BAD_REQUEST,
            "BadDigest",
            "the x-amz-checksum you specified did not match the checksum of the object the \
             parts make",
        )));
    }
    staged.hex = crate::hex_of(&sha256);
    Ok(Ok(Assembled {
        staged,
        etag: multipart_etag(&md5s),
    }))
}

/// `POST /s3/<bucket>/<key>?uploadId=<id>`: the object the `CompleteMultipartUpload`
/// document's parts make, in the order given, tagged at the key as a PutObject's body is
/// (the key checked again, `If-None-Match: *`/`If-Match` checked where the tag is written),
/// with the user metadata recorded at the upload's creation and the multipart ETag; the
/// upload then goes. A refusal leaves the upload as it was, to be completed again.
async fn complete(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    id: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !on_parent(authz, accounts::Action::Write, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let Ok(conditions) = WriteConditions::of(req.headers()) else {
        let resp = ctx.error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "a write's If-None-Match is * or nothing",
        );
        return refuse(req, resp, ctx).await;
    };
    let whole = WholeChecksums::of(req.headers());
    let (head, body) = req.into_parts();
    let too_long = ctx.error(
        StatusCode::BAD_REQUEST,
        "MalformedXML",
        "a CompleteMultipartUpload document is at most 1 MiB",
    );
    let body = match read_small(body, MAX_DOCUMENT, too_long, ctx).await? {
        Ok(body) => body,
        Err(resp) => return Ok(resp),
    };
    if let Err((status, code, message)) = object::check_document(&head.headers, &body) {
        return Ok(ctx.error(status, code, message));
    }
    let parts = match document(&body) {
        Ok(parts) => parts,
        Err(Refusal::Malformed(why)) => {
            return Ok(ctx.error(StatusCode::BAD_REQUEST, "MalformedXML", why));
        }
        Err(Refusal::Order) => {
            return Ok(ctx.error(
                StatusCode::BAD_REQUEST,
                "InvalidPartOrder",
                "the list of parts was not in ascending order of part number",
            ));
        }
    };
    let assembled = {
        let (store, segs) = (Arc::clone(&state.store), segs.clone());
        tokio::task::spawn_blocking(move || -> Result<_> {
            let Some(up) = open(&store, &id, &segs) else {
                return Ok(None);
            };
            let assembled = assemble(&store, &up, &parts, &whole)?;
            Ok(Some((up, assembled)))
        })
        .await
        .context("assembling an upload panicked")??
    };
    let (up, assembled) = match assembled {
        None => return Ok(no_such_upload(ctx)),
        Some((_, Err((status, code, message)))) => return Ok(ctx.error(status, code, message)),
        Some((up, Ok(assembled))) => (up, assembled),
    };
    let Assembled { staged, etag } = assembled;
    let mut annotations = up.meta.annotations;
    annotations.insert(MD5_ANNOTATION.to_string(), etag.clone());
    let how = Commit {
        annotations,
        precondition: conditions.precondition(),
        uncompressed: staged.size >= UNCOMPRESSED_FROM,
    };
    match files::commit(Arc::clone(&state.store), segs, staged, how).await? {
        Written::Created | Written::Replaced => {}
        Written::Refused(why) => return Ok(unwritable(why, ctx)),
        Written::PreconditionFailed => return Ok(copy::failed(ctx)),
    }
    remove(up.dir).await?;
    Ok(xml::document(
        "CompleteMultipartUploadResult",
        &format!(
            "{}{}{}{}",
            xml::element("Location", &ctx.url),
            xml::element("Bucket", &up.meta.bucket),
            xml::element("Key", &up.meta.key),
            xml::element("ETag", &format!("\"{etag}\""))
        ),
    ))
}

/// Remove an upload's directory, off the runtime; one already gone is gone.
async fn remove(dir: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("removing {}", dir.display()))),
    })
    .await
    .context("removing an upload panicked")?
}

/// `DELETE /s3/<bucket>/<key>?uploadId=<id>`: the upload and its parts removed; 204.
async fn abort(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    id: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !on_parent(authz, accounts::Action::Write, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    if let Some(resp) = drain(req, ctx).await? {
        return Ok(resp);
    }
    let Some(up) = open_async(state, &id, &segs).await? else {
        return Ok(no_such_upload(ctx));
    };
    remove(up.dir).await?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(body_of(bytes::Bytes::new()))?)
}

/// A page size as a query gives it: a count, clamped to [`MAX_LISTED`]; absent, the bound.
fn page_size(value: Option<&str>) -> Option<usize> {
    match value {
        None => Some(MAX_LISTED),
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            Some(v.parse::<usize>().map_or(MAX_LISTED, |n| n.min(MAX_LISTED)))
        }
        Some(_) => None,
    }
}

/// `<Initiator>` and `<Owner>`, as S3's upload listings carry them.
fn initiator_and_owner() -> String {
    format!(
        "<Initiator>{}{}</Initiator>{}",
        xml::element("ID", bucket::OWNER),
        xml::element("DisplayName", bucket::OWNER),
        bucket::owner()
    )
}

/// The parts recorded in `dir` after part `marker`, ascending: at most `limit` of them.
fn parts_after(dir: &Path, marker: u32, limit: usize) -> Result<Vec<u32>> {
    let mut numbers: Vec<u32> = std::fs::read_dir(dir)
        .with_context(|| format!("listing {}", dir.display()))?
        .filter_map(|e| recorded_part(e.ok()?.file_name().to_str()?))
        .filter(|n| *n > marker)
        .collect();
    numbers.sort_unstable();
    numbers.truncate(limit);
    Ok(numbers)
}

/// `GET /s3/<bucket>/<key>?uploadId=<id>`: the upload's parts, ascending, from after
/// `part-number-marker`, `max-parts` of them (at most and by default 1000), each with its
/// number, ETag, size and when it was written.
#[allow(clippy::too_many_arguments)]
async fn list_parts(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    id: String,
    params: &[(&str, &str)],
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    if !on_parent(authz, accounts::Action::Read, &segs) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let Some(max) = page_size(param(params, "max-parts")) else {
        return refuse(req, invalid(ctx, "max-parts is a count of parts"), ctx).await;
    };
    let marker = match param(params, "part-number-marker") {
        None => 0,
        Some(m) => match m.parse::<u32>() {
            Ok(m) => m,
            Err(_) => {
                let resp = invalid(ctx, "part-number-marker is a part's number");
                return refuse(req, resp, ctx).await;
            }
        },
    };
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, _| {
        let Some(up) = open(store, &id, &segs) else {
            return Ok(no_such_upload(&ctx));
        };
        let mut numbers = if max == 0 {
            Vec::new()
        } else {
            parts_after(&up.dir, marker, max.saturating_add(1))?
        };
        let truncated = numbers.len() > max;
        numbers.truncate(max);
        let mut out = format!(
            "{}{}{}{}{}{}",
            xml::element("Bucket", &up.meta.bucket),
            xml::element("Key", &up.meta.key),
            xml::element("UploadId", &up.id),
            initiator_and_owner(),
            xml::element("StorageClass", "STANDARD"),
            xml::element("PartNumberMarker", &marker.to_string()),
        );
        if let Some(last) = numbers.last() {
            out.push_str(&xml::element("NextPartNumberMarker", &last.to_string()));
        }
        out.push_str(&xml::element("MaxParts", &max.to_string()));
        out.push_str(&xml::element(
            "IsTruncated",
            if truncated { "true" } else { "false" },
        ));
        for n in numbers {
            let path = record_path(&up.dir, n);
            // Gone since the listing: replaced this moment, or the upload completed.
            let Some(part) = read_record::<Part>(&path) else {
                continue;
            };
            let written = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| SystemTime::now());
            out.push_str(&format!(
                "<Part>{}{}{}{}</Part>",
                xml::element("PartNumber", &n.to_string()),
                xml::element("LastModified", &list::iso8601(written)),
                xml::element("ETag", &format!("\"{}\"", part.md5)),
                xml::element("Size", &part.size.to_string())
            ));
        }
        Ok(xml::document("ListPartsResult", &out))
    })
    .await
}

/// One upload a ListMultipartUploads lists.
struct Listed {
    key: String,
    id: String,
    created: u64,
}

/// `GET /s3/<bucket>?uploads`: the uploads in progress into the bucket whose key starts with
/// `prefix`, by key then id, after `key-marker` (and, for that key, `upload-id-marker`),
/// `max-uploads` of them (at most and by default 1000). Admitted as a listing of the bucket
/// with that prefix is, and shows only the uploads whose key the caller may read. Every
/// upload's record is read: the cost is the store's uploads in progress, not the bucket's.
pub(super) async fn list_uploads(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    query: &Params,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    let params = params(query);
    let taken = [
        "uploads",
        "prefix",
        "max-uploads",
        "key-marker",
        "upload-id-marker",
        "encoding-type",
    ];
    if !only(&params, &taken) {
        return refuse(req, ctx.not_implemented(), ctx).await;
    }
    let url = match param(&params, "encoding-type") {
        None => false,
        Some("url") => true,
        Some(_) => return refuse(req, invalid(ctx, "encoding-type is url"), ctx).await,
    };
    let Some(max) = page_size(param(&params, "max-uploads")) else {
        return refuse(req, invalid(ctx, "max-uploads is a count of uploads"), ctx).await;
    };
    let prefix = param(&params, "prefix").unwrap_or_default().to_string();
    let key_marker = param(&params, "key-marker").unwrap_or_default().to_string();
    let id_marker = param(&params, "upload-id-marker")
        .unwrap_or_default()
        .to_string();
    if !list::admitted(authz, &bucket, &prefix) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        if !store.repo_dir_exists(&format!("{FILES_REPO}/{bucket}")) {
            return Ok(ctx.error(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
            ));
        }
        let mut uploads: Vec<Listed> = Vec::new();
        for (id, dir) in store.multipart_uploads() {
            let Some(meta) = read_record::<Meta>(&dir.join(META)) else {
                continue;
            };
            let after = meta.key > key_marker
                || (meta.key == key_marker && !id_marker.is_empty() && id > id_marker);
            let segs: Vec<String> = std::iter::once(bucket.clone())
                .chain(meta.key.split('/').map(str::to_string))
                .collect();
            if meta.bucket == bucket
                && meta.key.starts_with(&prefix)
                && (key_marker.is_empty() || after)
                && on_parent(authz, accounts::Action::Read, &segs)
            {
                uploads.push(Listed {
                    key: meta.key,
                    id,
                    created: meta.created,
                });
            }
        }
        uploads.sort_by(|a, b| (&a.key, &a.id).cmp(&(&b.key, &b.id)));
        let truncated = uploads.len() > max;
        uploads.truncate(max);
        let enc = |s: &str| {
            if url {
                list::url_encode(s)
            } else {
                s.to_string()
            }
        };
        let mut out = format!(
            "{}{}{}",
            xml::element("Bucket", &bucket),
            xml::element("KeyMarker", &enc(&key_marker)),
            xml::element("UploadIdMarker", &id_marker),
        );
        if let (true, Some(last)) = (truncated, uploads.last()) {
            out.push_str(&xml::element("NextKeyMarker", &enc(&last.key)));
            out.push_str(&xml::element("NextUploadIdMarker", &last.id));
        }
        out.push_str(&xml::element("Prefix", &enc(&prefix)));
        if url {
            out.push_str(&xml::element("EncodingType", "url"));
        }
        out.push_str(&xml::element("MaxUploads", &max.to_string()));
        out.push_str(&xml::element(
            "IsTruncated",
            if truncated { "true" } else { "false" },
        ));
        for u in &uploads {
            let created = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(u.created);
            out.push_str(&format!(
                "<Upload>{}{}{}{}{}</Upload>",
                xml::element("Key", &enc(&u.key)),
                xml::element("UploadId", &u.id),
                initiator_and_owner(),
                xml::element("StorageClass", "STANDARD"),
                xml::element("Initiated", &list::iso8601(created))
            ));
        }
        Ok(xml::document("ListMultipartUploadsResult", &out))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(parts: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             {parts}</CompleteMultipartUpload>"
        )
        .into_bytes()
    }

    fn part(n: &str, etag: &str) -> String {
        format!("<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>")
    }

    const MD5: &str = "65a8e27d8879283831b664bd8b7f0ad4";

    #[test]
    fn a_completion_names_its_parts_in_ascending_order() {
        let parts = document(&body(&format!(
            "{}<Part><ChecksumCRC32>AAAAAA==</ChecksumCRC32><ETag>{MD5}</ETag>\
             <PartNumber> 3 </PartNumber></Part>{}",
            part("1", &format!("&quot;{}&quot;", MD5.to_ascii_uppercase())),
            part("10000", &format!("\"{MD5}\"")),
        )))
        .unwrap();
        assert_eq!(
            parts,
            [
                (1, MD5.to_string()),
                (3, MD5.to_string()),
                (10_000, MD5.to_string())
            ]
        );
        for unordered in [
            format!("{}{}", part("2", MD5), part("1", MD5)),
            format!("{}{}", part("2", MD5), part("2", MD5)),
        ] {
            assert_eq!(document(&body(&unordered)), Err(Refusal::Order));
        }
    }

    #[test]
    fn a_completion_that_is_not_one_is_malformed() {
        for bad in [
            body(""),
            body("<Part><PartNumber>1</PartNumber></Part>"),
            body("<Part><ETag>x</ETag></Part>"),
            body(&part("0", MD5)),
            body(&part("10001", MD5)),
            body(&part("-1", MD5)),
            body(&part("one", MD5)),
            body(&part("", MD5)),
            body("<Part><PartNumber>1</PartNumber><PartNumber>2</PartNumber><ETag>x</ETag></Part>"),
            body(&part("1", "&ent;")),
            b"<Other><Part><PartNumber>1</PartNumber><ETag>x</ETag></Part></Other>".to_vec(),
            b"".to_vec(),
        ] {
            assert!(
                matches!(document(&bad), Err(Refusal::Malformed(_))),
                "{}",
                String::from_utf8_lossy(&bad)
            );
        }
        // The most parts there can be fit in the bound; past it, the scan stops.
        let max = (1..=MAX_PARTS)
            .map(|n| part(&n.to_string(), MD5))
            .collect::<String>();
        assert_eq!(document(&body(&max)).unwrap().len(), MAX_PARTS as usize);
        let elements = (0..MAX_ELEMENTS).map(|_| "<x/>").collect::<String>();
        assert!(matches!(
            document(&body(&elements)),
            Err(Refusal::Malformed(_))
        ));
        let big = vec![b' '; MAX_DOCUMENT + 1];
        assert!(document(&big).is_err());
    }

    #[test]
    fn a_multipart_etag_is_the_md5_of_the_parts_md5s_and_their_count() {
        let a = md5::compute(b"a").0;
        let b = md5::compute(b"b").0;
        let mut both = a.to_vec();
        both.extend_from_slice(&b);
        assert_eq!(
            multipart_etag(&[a, b]),
            format!("{}-2", crate::hex_of(&md5::compute(&both).0))
        );
        assert_eq!(
            multipart_etag(&[a]),
            format!("{}-1", crate::hex_of(&md5::compute(a).0))
        );
    }

    #[test]
    fn part_numbers_and_records_are_strict() {
        assert_eq!(part_number("1"), Some(1));
        assert_eq!(part_number("10000"), Some(10_000));
        for bad in ["0", "10001", "", "+1", "1 ", "99999999999", "1e3"] {
            assert_eq!(part_number(bad), None, "{bad}");
        }
        assert_eq!(recorded_part("part-7.json"), Some(7));
        for name in [
            "part-07.json",
            "part-7",
            ".part-7.json",
            "part-7.json.x",
            "meta.json",
        ] {
            assert_eq!(recorded_part(name), None, "{name}");
        }
    }

    #[test]
    fn a_copy_range_names_both_ends_in_order() {
        assert_eq!(copy_range("bytes=0-0"), Some((0, 0)));
        assert_eq!(copy_range(" bytes=5-10 "), Some((5, 10)));
        for bad in [
            "bytes=5-",
            "bytes=-5",
            "bytes=10-5",
            "items=0-1",
            "bytes=a-b",
            "0-1",
        ] {
            assert_eq!(copy_range(bad), None, "{bad}");
        }
    }

    #[test]
    fn queries_name_their_parameters_decoded() {
        let query = |q: &str| crate::s3::parse_query(q).unwrap();
        let q = query("uploadId=1-2-ab&partNumber=3&x-id=UploadPart");
        let p = params(&q);
        assert_eq!(param(&p, "uploadId"), Some("1-2-ab"));
        assert_eq!(param(&p, "partNumber"), Some("3"));
        assert!(only(&p, &["uploadId", "partNumber"]));
        assert!(!only(&p, &["uploadId"]));
        assert!(names(&query("uploads"), "uploads"));
        assert!(names(&query("uploads=&prefix=a%2Fb"), "uploads"));
        assert!(names(&query("upload%49d=u"), "uploadId"));
        let q = query("prefix=a%2Fb+c");
        assert_eq!(param(&params(&q), "prefix"), Some("a/b+c"));
        assert!(!names(&query("uploadIds=1"), "uploadId"));
        assert_eq!(page_size(None), Some(MAX_LISTED));
        assert_eq!(page_size(Some("5")), Some(5));
        assert_eq!(
            page_size(Some("100000000000000000000000")),
            Some(MAX_LISTED)
        );
        assert_eq!(page_size(Some("-1")), None);
    }

    /// An upload is found only for the bucket and key it was created for, and never through an
    /// id that is not one this server mints.
    #[test]
    fn an_upload_answers_only_for_its_own_key() {
        let dir = std::env::temp_dir().join(format!("vk-reg-s3-mp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let (id, up) = store.create_multipart().unwrap();
        let meta = Meta {
            bucket: "b".into(),
            key: "a/k".into(),
            created: 1,
            annotations: BTreeMap::new(),
        };
        std::fs::write(up.join(META), serde_json::to_vec(&meta).unwrap()).unwrap();
        let segs = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            open(&store, &id, &segs(&["b", "a", "k"])).unwrap().meta,
            meta
        );
        for other in [
            segs(&["b", "a", "x"]),
            segs(&["c", "a", "k"]),
            segs(&["b", "a"]),
        ] {
            assert!(open(&store, &id, &other).is_none(), "{other:?}");
        }
        for id in ["../s3", "", "a/b", "owners"] {
            assert!(open(&store, id, &segs(&["b", "a", "k"])).is_none(), "{id}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
