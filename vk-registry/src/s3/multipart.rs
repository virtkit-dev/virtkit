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
//! directory then goes, and the parts' sizes stay on the manifest ([`PARTS_ANNOTATION`]),
//! so a read may ask for one part of the object as it was uploaded (`?partNumber=<n>`) and
//! GetObjectAttributes may list them. The gc sweeps an upload nothing has been written into
//! for its grace window, as it sweeps an idle OCI upload. A completion or an abort holds
//! the upload's directory locked until it is done ([`open_held`]), so two of them at once run
//! one after the other. A completed upload's directory keeps only `completed.json`, what the
//! completion made ([`Completed`]), until the gc sweeps it as an idle upload: the same
//! completion sent again is answered as it was while the key holds that object.
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
use super::error::{Code, Refusal};
use super::object::{self, admitted, no_such_key, readable, unwritable};
use super::xml::scan::{self, Malformed};
use super::{
    Ctx, OPERATION_HINT, Params, UNCOMPRESSED_FROM, bucket, checksum, chunked, drain, list, meta,
    read_small, refuse, xml,
};
use crate::files::{self, Commit, FILES_REPO, MAX_OBJECT, Staged, Written, allowed, object_of};
use crate::{Authz, Body, STREAM_CHUNK, ServerState, Store, accounts, body_of};

/// Most parts an upload has, and the highest part number: S3's bound.
const MAX_PARTS: u32 = 10_000;

/// The fewest bytes a part holds when it is not the last one an upload completes with:
/// S3's minimum.
const MIN_PART: u64 = 5 << 20;

/// Longest `CompleteMultipartUpload` document taken.
const MAX_DOCUMENT: usize = 1 << 20;

/// Most elements a `CompleteMultipartUpload` document may hold: a `Part` and the five fields
/// S3 defines in it, for each part, and a few more around them.
const MAX_ELEMENTS: usize = 6 * MAX_PARTS as usize + 16;

/// Most entries a ListParts or ListMultipartUploads page holds: S3's bound.
const MAX_LISTED: usize = 1000;

/// What an upload records of itself, in its directory.
const META: &str = crate::MULTIPART_RECORD;

/// The manifest annotation holding the sizes of the parts an object was completed from, in
/// order: each in decimal, a run of equal sizes as `<size>x<count>`, joined by commas, so an
/// upload in equal parts is one run whatever their number.
pub(crate) const PARTS_ANNOTATION: &str = "org.virtkit.s3-parts";

/// The manifest annotation holding the checksums of the parts an object was completed from,
/// in order, for an upload created with a checksum: each in base64, in the algorithm of the
/// object's own checksum, joined by commas.
pub(crate) const PART_CHECKSUMS_ANNOTATION: &str = "org.virtkit.s3-part-checksums";

/// The checksums of its `count` parts `annotations` keep, and their algorithm, by S3's name:
/// `None` unless there is one for each, in base64 of the length of the algorithm of the
/// object's checksum.
pub(super) fn part_checksums(
    annotations: &BTreeMap<String, String>,
    count: usize,
) -> Option<(&'static str, Vec<String>)> {
    let algorithm = checksum::stored(annotations)?.algorithm;
    let len = checksum::header(algorithm).and_then(checksum::len)?;
    let values: Vec<String> = annotations
        .get(PART_CHECKSUMS_ANNOTATION)?
        .split(',')
        .map(str::to_string)
        .collect();
    let fit = values.len() == count
        && values
            .iter()
            .all(|v| crate::auth::base64_decode(v).is_some_and(|b| b.len() == len));
    fit.then_some((algorithm, values))
}

/// The [`PARTS_ANNOTATION`] for parts of `sizes`.
fn parts_annotation(sizes: &[u64]) -> String {
    let mut runs: Vec<(u64, usize)> = Vec::new();
    for size in sizes {
        match runs.last_mut() {
            Some((s, n)) if s == size => *n = n.saturating_add(1),
            _ => runs.push((*size, 1)),
        }
    }
    runs.iter()
        .map(|(size, n)| {
            if *n == 1 {
                size.to_string()
            } else {
                format!("{size}x{n}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The sizes of the parts `annotations` say an object was completed from, in order: 1 to
/// [`MAX_PARTS`] of them, summing to at most the object cap. `None` for an object not made
/// of parts, or an annotation this registry did not write.
pub(super) fn part_sizes(annotations: &BTreeMap<String, String>) -> Option<Vec<u64>> {
    let text = annotations.get(PARTS_ANNOTATION)?;
    let mut sizes = Vec::new();
    let mut total: u64 = 0;
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.len() <= 20)
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    for run in text.split(',') {
        let (size, count) = match run.split_once('x') {
            Some((size, count)) => (number(size)?, number(count)?),
            None => (number(run)?, 1),
        };
        let count = usize::try_from(count).ok()?;
        if count == 0 || sizes.len().saturating_add(count) > MAX_PARTS as usize {
            return None;
        }
        total = total.checked_add(size.checked_mul(count as u64)?)?;
        if total > MAX_OBJECT {
            return None;
        }
        sizes.extend(std::iter::repeat_n(size, count));
    }
    (!sizes.is_empty()).then_some(sizes)
}

/// Where part `n` (from 1) of an object of parts `sizes` lies: its first byte and its
/// length; `None` past the last part.
pub(super) fn part_range(sizes: &[u64], n: u32) -> Option<(u64, u64)> {
    let at = usize::try_from(n).ok()?.checked_sub(1)?;
    let len = *sizes.get(at)?;
    let start = sizes
        .get(..at)?
        .iter()
        .try_fold(0u64, |a, s| a.checked_add(*s))?;
    Some((start, len))
}

/// The `ObjectParts` of GetObjectAttributes for an object of parts `sizes`: `max` of them
/// from after part `marker`, each with its number and size, and its checksum when the
/// object keeps them (`checksums`, by algorithm), with the paging S3 writes around them and
/// the count of them all.
pub(super) fn object_parts(
    sizes: &[u64],
    checksums: Option<&(&'static str, Vec<String>)>,
    max: usize,
    marker: u32,
) -> String {
    let after: Vec<(usize, &u64)> = sizes
        .iter()
        .enumerate()
        .filter(|(i, _)| i.saturating_add(1) > marker as usize)
        .collect();
    let truncated = after.len() > max;
    let page = after.get(..max).unwrap_or(&after);
    let mut out = format!(
        "<ObjectParts>{}{}",
        xml::element("IsTruncated", if truncated { "true" } else { "false" }),
        xml::element("MaxParts", &max.to_string())
    );
    if let (true, Some((last, _))) = (truncated, page.last()) {
        out.push_str(&xml::element(
            "NextPartNumberMarker",
            &last.saturating_add(1).to_string(),
        ));
    }
    out.push_str(&xml::element("PartNumberMarker", &marker.to_string()));
    for (i, size) in page {
        let checksum = checksums
            .and_then(|(algorithm, values)| {
                let value = values.get(*i)?;
                Some(xml::element(&format!("Checksum{algorithm}"), value))
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "<Part>{checksum}{}{}</Part>",
            xml::element("PartNumber", &i.saturating_add(1).to_string()),
            xml::element("Size", &size.to_string())
        ));
    }
    out.push_str(&xml::element("PartsCount", &sizes.len().to_string()));
    out.push_str("</ObjectParts>");
    out
}

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
    /// the checksum the upload was created with, which its parts are held to; absent from
    /// the record of an upload created without one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checksum: Option<Asked>,
}

/// The checksum a CreateMultipartUpload asks for: S3's name of its algorithm, and its kind.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Asked {
    algorithm: String,
    kind: checksum::Kind,
}

impl Asked {
    /// The checksum header of its algorithm; `None` for a record this server did not write.
    fn header(&self) -> Option<&'static str> {
        checksum::header(&self.algorithm)
    }

    /// The elements ListParts and ListMultipartUploads name it with.
    fn listed(&self) -> String {
        xml::element("ChecksumAlgorithm", &self.algorithm)
            + &xml::element("ChecksumType", self.kind.name())
    }
}

/// What a part's record says of it.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Part {
    size: u64,
    /// lowercase hex
    md5: String,
    /// the checksum the part carried, or was given for its upload's, as an object's
    /// annotation keeps one (`<ALGORITHM>:<base64>`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checksum: Option<String>,
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

/// What S3 says of a `partNumber` that is not one.
pub(super) const PART_NUMBER: &str =
    "Part number must be an integer between 1 and 10000, inclusive.";

/// A part number as a query or a document gives it: 1 to [`MAX_PARTS`], in decimal.
pub(super) fn part_number(s: &str) -> Option<u32> {
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

/// An upload held for its end: [`open`]'s, once the lock on its directory is had.
struct Held {
    /// the directory, open and locked exclusive (`flock`) until dropped
    _lock: std::fs::File,
    up: Upload,
}

/// The upload `id` names for the object at `segs`, held so no other completion or abort of
/// it, in this process or another on the store, runs until the hold is dropped: blocks
/// while one does, then looks the upload up afresh, so the one that waited finds it as
/// that one left it. Only completions and aborts take the hold; a part written meanwhile is
/// caught by the MD5 a completion checks as it reads it.
fn open_held(store: &Store, id: &str, segs: &[String]) -> Result<Option<Held>> {
    let Some((lock, _)) = hold(store, id)? else {
        return Ok(None);
    };
    Ok(open(store, id, segs).map(|up| Held { _lock: lock, up }))
}

/// The directory of upload `id`, open and locked exclusive, with its path: [`open_held`]'s
/// hold, before anything in the directory is read.
fn hold(store: &Store, id: &str) -> Result<Option<(std::fs::File, PathBuf)>> {
    let Some(dir) = store.multipart_dir(id) else {
        return Ok(None);
    };
    let lock = match std::fs::File::open(&dir) {
        Ok(lock) => lock,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("opening {}", dir.display()))),
    };
    lock.lock()
        .with_context(|| format!("locking {}", dir.display()))?;
    Ok(Some((lock, dir)))
}

/// [`open_held`], off the runtime.
async fn open_held_async(state: &ServerState, id: &str, segs: &[String]) -> Result<Option<Held>> {
    let (store, id, segs) = (Arc::clone(&state.store), id.to_string(), segs.to_vec());
    tokio::task::spawn_blocking(move || open_held(&store, &id, &segs))
        .await
        .context("holding an upload panicked")?
}

/// `NoSuchUpload`, naming upload `id`.
fn no_such_upload(ctx: &Ctx, id: &str) -> Response<Body> {
    ctx.error(Refusal::new(Code::NoSuchUpload).with("UploadId", id))
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
fn install_part(
    dir: &Path,
    n: u32,
    staged: Staged,
    md5: &str,
    checksum: Option<String>,
) -> Result<()> {
    let size = staged.size;
    staged.rename_to(&part_path(dir, n))?;
    let record = serde_json::to_vec(&Part {
        size,
        md5: md5.to_string(),
        checksum,
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
        let resp = ctx.error(Refusal::argument(
            "You can only specify a copy source header for copy requests.",
            "x-amz-copy-source",
            String::from_utf8_lossy(headers[COPY_SOURCE].as_bytes()),
        ));
        return refuse(req, resp, ctx).await;
    }
    let annotations = match meta::annotations(headers) {
        Ok(a) => a,
        Err(why) => return refuse(req, ctx.error(why), ctx).await,
    };
    let asked = match asked(headers) {
        Ok(asked) => asked,
        Err(why) => return refuse(req, ctx.error(why), ctx).await,
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
            checksum: asked,
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
        if let Some(asked) = &meta.checksum
            && let Ok(v) = hyper::header::HeaderValue::from_str(&asked.algorithm)
        {
            let headers = resp.headers_mut();
            headers.insert(CHECKSUM_ALGORITHM, v);
            headers.insert(
                checksum::TYPE_HEADER,
                hyper::header::HeaderValue::from_static(asked.kind.name()),
            );
        }
        Ok(resp)
    })
    .await
}

/// The header a CreateMultipartUpload names its parts' checksum algorithm in.
const CHECKSUM_ALGORITHM: &str = "x-amz-checksum-algorithm";

/// The checksum a creation asks for: the algorithm `x-amz-checksum-algorithm` names, as S3
/// spells it, which each part is then held to, and the kind `x-amz-checksum-type` names, by
/// default a full object's for CRC64NVME and a composite one otherwise. Refused as S3
/// refuses them: an algorithm or a kind S3 does not have, a kind without an algorithm, and
/// a kind the algorithm cannot make.
fn asked(headers: &HeaderMap) -> std::result::Result<Option<Asked>, Refusal> {
    let algorithm = match headers.get(CHECKSUM_ALGORITHM) {
        None => None,
        Some(v) => Some(checksum::named(v.as_bytes()).ok_or(checksum::UNKNOWN_ALGORITHM)?),
    };
    let kind = match headers.get(checksum::TYPE_HEADER) {
        None => None,
        Some(v) => Some(
            checksum::Kind::of(v.as_bytes())
                .ok_or_else(|| checksum::invalid(checksum::TYPE_HEADER))?,
        ),
    };
    let Some(algorithm) = algorithm else {
        return match kind {
            None => Ok(None),
            Some(_) => Err(checksum::TYPE_WITHOUT_ALGORITHM),
        };
    };
    let kind = kind.unwrap_or(checksum::Kind::default_for(algorithm));
    if !kind.fits(algorithm) {
        return Err(checksum::unfit(kind, algorithm));
    }
    Ok(Some(Asked {
        algorithm: algorithm.to_string(),
        kind,
    }))
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
    // A bucket that is not there is said first, when the upload is not there either: an
    // upload is made before its bucket is, at its completion.
    if let Some(resp) = bucket::missing(state, authz, bucket_of(&segs), ctx).await?
        && open_async(state, &id, &segs).await?.is_none()
    {
        return refuse(req, resp, ctx).await;
    }
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
            // The upload is looked up before anything asked of it is, as S3 looks it up.
            if !on_parent(authz, accounts::Action::Write, &segs) {
                return refuse(req, ctx.access_denied(), ctx).await;
            }
            if open_async(state, &id, &segs).await?.is_none() {
                return refuse(req, no_such_upload(ctx, &id), ctx).await;
            }
            let Some(n) = param(&params, "partNumber").and_then(part_number) else {
                let resp = ctx.error(Refusal::argument(
                    PART_NUMBER,
                    "partNumber",
                    param(&params, "partNumber").unwrap_or_default(),
                ));
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
    let mut plan = match object::plan(headers) {
        Ok(plan) => plan,
        Err(why) => return refuse(req, ctx.error(why), ctx).await,
    };
    let Some(up) = open_async(state, &id, &segs).await? else {
        return refuse(req, no_such_upload(ctx, &id), ctx).await;
    };
    // A part of an upload created with a checksum carries one in its algorithm; a full
    // object's is computed for a part that carries none, as S3 combines it from the parts'.
    if let Some(asked) = &up.meta.checksum
        && let Some(want) = asked.header()
    {
        match plan.claimed() {
            Some(header) if header == want => {}
            None if asked.kind == checksum::Kind::FullObject => plan.compute(want),
            claimed => {
                let why = checksum::part_mismatch(
                    &asked.algorithm,
                    claimed.and_then(checksum::algorithm),
                );
                return refuse(req, ctx.error(why), ctx).await;
            }
        }
    }
    let staging = match temp_in(&up.dir, &format!("part-{n}")) {
        Ok(staging) => staging,
        // Completed or aborted since it was looked up.
        Err(_) if !up.dir.is_dir() => return refuse(req, no_such_upload(ctx, &id), ctx).await,
        Err(e) => return Err(e),
    };
    let received = match object::receive(plan, req.into_body(), seed, staging, ctx).await? {
        Ok(received) => received,
        Err(resp) => return Ok(resp),
    };
    let md5 = crate::hex_of(&received.md5);
    let kept = received
        .echo
        .as_ref()
        .and_then(|(header, text)| checksum::annotation(header, text))
        .map(|(_, value)| value);
    let installed = {
        let (dir, md5) = (up.dir.clone(), md5.clone());
        tokio::task::spawn_blocking(move || install_part(&dir, n, received.staged, &md5, kept))
            .await
            .context("installing a part panicked")?
    };
    match installed {
        Ok(()) => {}
        Err(_) if !up.dir.is_dir() => return Ok(no_such_upload(ctx, &id)),
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
/// hashed on the way: their MD5, and the checksum of the upload's algorithm, which the part
/// is recorded with and the answer names. 200 with `CopyPartResult`.
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
            let resp = ctx.error(Refusal::new(Code::NotImplemented).with("Header", COPY_SOURCE));
            return refuse(req, resp, ctx).await;
        }
        Source::Absent { bucket, key } => {
            let resp = copy::absent_source(state, authz, &bucket, &key, ctx).await?;
            return refuse(req, resp, ctx).await;
        }
        Source::Invalid(why) => return refuse(req, ctx.error(why), ctx).await,
    };
    if !admitted(authz, accounts::Action::Read, &src) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let range = match headers.get(COPY_SOURCE_RANGE) {
        None => None,
        Some(v) => match v.to_str().ok().and_then(copy_range) {
            Some(range) => Some(range),
            None => {
                let resp = ctx.error(Refusal::argument(
                    "The x-amz-copy-source-range value must be of the form bytes=first-last \
                     where first and last are the zero-based offsets of the first and last \
                     bytes to copy",
                    COPY_SOURCE_RANGE,
                    String::from_utf8_lossy(v.as_bytes()),
                ));
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
            return Ok(no_such_upload(&ctx, &id));
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
                return Ok(ctx.error(Refusal::argument(
                    format!(
                        "Range specified is not valid for source object of size: {}",
                        obj.size
                    ),
                    COPY_SOURCE_RANGE,
                    obj.size.to_string(),
                )));
            }
        };
        let Some((_, mut reader)) = store.read_blob_range(&obj.layer, start, len)? else {
            return Ok(no_such_key(&ctx, &src));
        };
        let (path, mut file) = match temp_in(&up.dir, &format!("part-{n}")) {
            Ok(staging) => staging,
            Err(_) if !up.dir.is_dir() => return Ok(no_such_upload(&ctx, &id)),
            Err(e) => return Err(e),
        };
        let mut staged = Staged::written(path, 0, String::new());
        let mut md5 = md5::Context::new();
        // The checksum of the upload's algorithm, which the part is recorded with.
        let header = up.meta.checksum.as_ref().and_then(Asked::header);
        let mut hasher = header.and_then(checksum::Hasher::any);
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
            if let Some(h) = &mut hasher {
                h.update(data);
            }
            file.write_all(data).context("writing a copied part")?;
            staged.size = staged.size.saturating_add(got as u64);
        }
        drop(file);
        let md5 = crate::hex_of(&md5.finalize().0);
        let made = header.zip(hasher).and_then(|(header, h)| {
            checksum::annotation(header, &vk_hub_proto::to_base64(&h.finalize()))
        });
        let element = made.as_ref().map_or(String::new(), |(_, kept)| {
            let (algorithm, value) = kept.split_once(':').unwrap_or_default();
            xml::element(&format!("Checksum{algorithm}"), value)
        });
        match install_part(&up.dir, n, staged, &md5, made.map(|(_, kept)| kept)) {
            Ok(()) => {}
            Err(_) if !up.dir.is_dir() => return Ok(no_such_upload(&ctx, &id)),
            Err(e) => return Err(e),
        }
        Ok(xml::document(
            "CopyPartResult",
            &format!(
                "{}{}{element}",
                xml::element("LastModified", &list::iso8601(SystemTime::now())),
                xml::element("ETag", &format!("\"{md5}\""))
            ),
        ))
    })
    .await
}

/// Why a `CompleteMultipartUpload` document is refused.
#[derive(Debug, PartialEq, Eq)]
enum Unfit {
    /// 400 `MalformedXML`
    Malformed(&'static str),
    /// 400 `InvalidPartOrder`: the part numbers do not ascend
    Order,
    /// 400 `InvalidArgument`: a `PartNumber` below 1, as sent
    Number(String),
}

/// The checksums a `Part` of a `CompleteMultipartUpload` names (`ChecksumCRC32`…), each its
/// algorithm's header and its text, trimmed, as sent.
type Sent = Vec<(&'static str, String)>;

/// What [`document`] reads: each part's number and ETag, and the checksums each names.
type Named = (Vec<(u32, String)>, Vec<Sent>);

/// The parts a `CompleteMultipartUpload` document names, in order: each part's number and
/// the ETag it is expected to have, unquoted and lowercase; and beside them the checksums
/// each names. Other fields are passed over.
fn document(body: &[u8]) -> std::result::Result<Named, Unfit> {
    let root = scan::parse(body, MAX_ELEMENTS).map_err(|Malformed(why)| Unfit::Malformed(why))?;
    if root.name != "CompleteMultipartUpload" {
        return Err(Unfit::Malformed(
            "the document is not a CompleteMultipartUpload",
        ));
    }
    let mut parts: Vec<(u32, String)> = Vec::new();
    let mut checksums_of = Vec::new();
    for p in root.all("Part") {
        let field = |name| {
            p.one(name)
                .map_err(|Malformed(why)| Unfit::Malformed(why))?
                .map(|e| e.text.trim().to_string())
                .ok_or(Unfit::Malformed("each Part names its PartNumber and ETag"))
        };
        let sent = field("PartNumber")?;
        if sent.parse::<i64>().is_ok_and(|n| n < 1) {
            return Err(Unfit::Number(sent));
        }
        let n = part_number(&sent).ok_or(Unfit::Malformed("a PartNumber is 1 to 10000"))?;
        let etag = field("ETag")?;
        let etag = etag
            .strip_prefix('"')
            .and_then(|e| e.strip_suffix('"'))
            .unwrap_or(&etag)
            .to_ascii_lowercase();
        if parts.last().is_some_and(|(last, _)| *last >= n) {
            return Err(Unfit::Order);
        }
        parts.push((n, etag));
        let mut checksums = Sent::new();
        for (header, name, _) in checksum::ALGORITHMS {
            let element = p
                .one(&format!("Checksum{name}"))
                .map_err(|Malformed(why)| Unfit::Malformed(why))?;
            if let Some(e) = element.filter(|e| !e.text.trim().is_empty()) {
                checksums.push((header, e.text.trim().to_string()));
            }
        }
        checksums_of.push(checksums);
    }
    if parts.is_empty() {
        return Err(Unfit::Malformed(
            "a CompleteMultipartUpload names at least one Part",
        ));
    }
    Ok((parts, checksums_of))
}

/// Check the checksums a completion names for part `n` (`sent`) against the one the part
/// was stored with (`kept`, `<ALGORITHM>:<base64>`), as S3 checks them: one at most, in
/// base64 of its algorithm's length (400 `InvalidArgument`); none for a part stored with
/// none, and that one for a part stored with one (`InvalidPart` when it differs, `BadDigest`
/// when it is in another algorithm); and one for every part of an upload `asked` for a
/// checksum (400 `InvalidRequest`).
fn check_part(
    n: u32,
    sent: &[(&'static str, String)],
    kept: Option<&str>,
    asked: Option<&Asked>,
    invalid_part: Refusal,
) -> std::result::Result<(), Refusal> {
    let argument = |value: String| {
        Refusal::argument(
            "Invalid Base64 or multiple checksums present in request",
            "Checksum",
            value,
        )
    };
    if sent.len() > 1 {
        let all: String = sent
            .iter()
            .map(|(header, text)| format!("{}:{text};", checksum::algorithm(header).unwrap_or("")))
            .collect();
        return Err(argument(all));
    }
    let kept = kept.and_then(|k| k.split_once(':'));
    match (kept, sent.first()) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(invalid_part),
        (Some((algorithm, _)), None) => match asked {
            None => Ok(()),
            Some(_) => Err(Refusal::saying(
                Code::InvalidRequest,
                format!(
                    "The upload was created using a {} checksum. The complete request must \
                     include the checksum for each part. It was missing for part {n} in the \
                     request.",
                    algorithm.to_ascii_lowercase()
                ),
            )),
        },
        (Some((algorithm, value)), Some((header, text))) => {
            let fits = crate::auth::base64_decode(text)
                .is_some_and(|b| Some(b.len()) == checksum::len(header));
            if !fits {
                return Err(argument(text.clone()));
            }
            if text == value {
                return Ok(());
            }
            let named = checksum::algorithm(header).unwrap_or("");
            if named == algorithm {
                return Err(invalid_part);
            }
            Err(Refusal::saying(
                Code::BadDigest,
                format!(
                    "The {} you specified for part {n} did not match what we received.",
                    named.to_ascii_lowercase()
                ),
            ))
        }
    }
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

/// The checksum a completion's headers name for the object: one `x-amz-checksum-*` of S3's
/// algorithms at most, its header and bytes, either a whole object's (base64 of the
/// algorithm's length) or a composite one, a checksum of the parts' checksums
/// (`<base64>-<parts>`, never for CRC64NVME, whose checksum is a full object's). Two, or one
/// that is neither, or in an algorithm S3 does not have, are refused as S3 refuses them.
struct Whole {
    header: &'static str,
    bytes: Vec<u8>,
    /// how many parts a composite checksum says it was made of
    composite: Option<u32>,
}

impl Whole {
    fn of(headers: &HeaderMap) -> std::result::Result<Option<Self>, Refusal> {
        if let Some(why) = checksum::unknown(headers) {
            return Err(why);
        }
        let sent = checksum::ALGORITHMS
            .iter()
            .filter(|(h, _, _)| headers.contains_key(*h));
        if sent.count() > 1 {
            return Err(object::ONE_CHECKSUM);
        }
        let mut found = None;
        for (header, _, len) in checksum::ALGORITHMS {
            let Some(value) = headers.get(header) else {
                continue;
            };
            let text = value.to_str().unwrap_or_default().trim();
            let decoded = |sum: &str| crate::auth::base64_decode(sum).filter(|b| b.len() == len);
            let (bytes, composite) = match decoded(text) {
                Some(bytes) => (bytes, None),
                None => text
                    .rsplit_once('-')
                    .filter(|_| header != CRC64NVME)
                    .and_then(|(sum, parts)| Some((decoded(sum)?, Some(part_number(parts)?))))
                    .ok_or_else(|| checksum::invalid(header))?,
            };
            found = Some(Whole {
                header,
                bytes,
                composite,
            });
        }
        Ok(found)
    }
}

/// The header of S3's one checksum that is only ever a full object's.
const CRC64NVME: &str = "x-amz-checksum-crc64nvme";

/// The kind of checksum a completion's `x-amz-checksum-type` names, which must be its
/// upload's: 400 `InvalidRequest` for anything else.
fn completion_kind(headers: &HeaderMap) -> std::result::Result<Option<checksum::Kind>, Refusal> {
    match headers.get(checksum::TYPE_HEADER) {
        None => Ok(None),
        Some(v) => checksum::Kind::of(v.as_bytes())
            .map(Some)
            .ok_or_else(|| checksum::invalid(checksum::TYPE_HEADER)),
    }
}

/// What [`assemble`] made: the object staged, its ETag, unquoted, the whole-object checksum
/// that held, its header and text, to keep, and the sizes of its parts in order.
struct Assembled {
    staged: Staged,
    etag: String,
    checksum: Option<(&'static str, String)>,
    sizes: Vec<u64>,
    /// the parts' checksums in the upload's algorithm, base64, for an upload created with one
    part_checksums: Option<Vec<String>>,
}

/// Concatenate the `parts` of `up`, in order, into a staging file, in one pass, hashing on
/// the way: each part's MD5, checked against both the ETag asked and the part's record, so a
/// part replaced while this reads it is noticed rather than built in; the whole object's
/// SHA-256; and its checksum: the full object's of an upload created with one, checked
/// against what `whole` names in its algorithm, or for an upload created with none, S3's
/// default CRC64NVME; or the composite one, made of the parts' checksums, of an upload
/// created with one, checked against what `whole` names in its algorithm, with or without
/// its count of parts. First, the completion's `kind` must be the upload's, and the
/// checksums `sent` for each part what [`check_part`] takes.
fn assemble(
    store: &Store,
    up: &Upload,
    parts: &[(u32, String)],
    sent: &[Sent],
    (whole, kind): (Option<&Whole>, Option<checksum::Kind>),
) -> Result<std::result::Result<Assembled, Refusal>> {
    let invalid_part = |n: &u32, etag: &str| {
        Refusal::new(Code::InvalidPart)
            .with("UploadId", up.id.as_str())
            .with("PartNumber", n.to_string())
            .with("ETag", etag)
    };
    let asked = up.meta.checksum.as_ref();
    if let Some(kind) = kind
        && asked.map(|a| a.kind) != Some(kind)
    {
        return Ok(Err(Refusal::saying(
            Code::InvalidRequest,
            format!(
                "The upload was created using the {} checksum mode. The complete request must \
                 use the same checksum mode.",
                asked.map_or("null", |a| a.kind.name())
            ),
        )));
    }
    // The checksum the object will have, and the one sent to check it against. An upload
    // created with none has S3's default, of the whole object; what it is sent is passed
    // over, as S3 passes it over.
    let (target, check) = match asked {
        None => (Some(checksum::DEFAULT), None),
        Some(a) if a.kind == checksum::Kind::FullObject => {
            let named = whole.filter(|w| Some(w.header) == a.header());
            if let Some(w) = named
                && w.composite.is_some()
            {
                return Ok(Err(checksum::mismatch(w.header)));
            }
            (a.header(), named)
        }
        Some(_) => (None, None),
    };
    // Written into, so the gc takes the upload as in use while it is read.
    if let Ok(meta) = std::fs::File::open(up.dir.join(META)) {
        // A failure only leaves the upload as fresh as its last write.
        let _ = meta.set_modified(SystemTime::now());
    }
    let mut total: u64 = 0;
    // The parts' checksums in the upload's algorithm, which every part of it has.
    let mut part_checksums = asked.map(|_| Vec::with_capacity(parts.len()));
    for (i, ((n, etag), sent)) in parts.iter().zip(sent).enumerate() {
        let Some(part) = read_record::<Part>(&record_path(&up.dir, *n)) else {
            return Ok(Err(invalid_part(n, etag)));
        };
        if part.md5 != *etag {
            return Ok(Err(invalid_part(n, etag)));
        }
        let checked = check_part(
            *n,
            sent,
            part.checksum.as_deref(),
            asked,
            invalid_part(n, etag),
        );
        if let Err(why) = checked {
            return Ok(Err(why));
        }
        if part.size < MIN_PART && i.saturating_add(1) < parts.len() {
            return Ok(Err(Refusal::new(Code::EntityTooSmall)
                .with("ProposedSize", part.size.to_string())
                .with("MinSizeAllowed", MIN_PART.to_string())
                .with("PartNumber", n.to_string())
                .with("ETag", etag)));
        }
        let own = asked.and_then(|a| {
            let (algorithm, value) = part.checksum.as_deref()?.split_once(':')?;
            (algorithm == a.algorithm).then(|| value.to_string())
        });
        match own {
            Some(value) => part_checksums
                .iter_mut()
                .for_each(|c| c.push(value.clone())),
            // A part recorded before its upload's checksum was: none made of them.
            None => part_checksums = None,
        }
        total = total.saturating_add(part.size);
    }
    let too_large = |size: u64| {
        Refusal::new(Code::EntityTooLarge)
            .with("ProposedSize", size.to_string())
            .with("MaxSizeAllowed", MAX_OBJECT.to_string())
    };
    if total > MAX_OBJECT {
        return Ok(Err(too_large(total)));
    }

    let (path, mut out) = store.stage_file()?;
    let mut staged = Staged::written(path, 0, String::new());
    let mut sha256 = sha2::Sha256::new();
    let mut hasher = target.and_then(checksum::Hasher::for_);
    let mut md5s = Vec::with_capacity(parts.len());
    let mut sizes = Vec::with_capacity(parts.len());
    let mut buf = vec![0u8; STREAM_CHUNK];
    for (n, etag) in parts {
        let mut file = match std::fs::File::open(part_path(&up.dir, *n)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Err(invalid_part(n, etag)));
            }
            Err(e) => return Err(anyhow::Error::from(e).context("opening a part")),
        };
        let mut md5 = md5::Context::new();
        let before = staged.size;
        loop {
            let got = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(got) => got,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(anyhow::Error::from(e).context("reading a part")),
            };
            staged.size = staged.size.saturating_add(got as u64);
            if staged.size > MAX_OBJECT {
                return Ok(Err(too_large(staged.size)));
            }
            let data = buf.get(..got).unwrap_or_default();
            md5.consume(data);
            sha256.update(data);
            if let Some(h) = &mut hasher {
                h.update(data);
            }
            out.write_all(data).context("writing an object")?;
        }
        let md5 = md5.finalize().0;
        if crate::hex_of(&md5) != *etag {
            return Ok(Err(invalid_part(n, etag)));
        }
        md5s.push(md5);
        sizes.push(staged.size.saturating_sub(before));
    }
    drop(out);
    let sha256 = sha256.finalize().to_vec();
    let mut kept = None;
    if let Some(header) = target {
        let got = match hasher {
            Some(h) => h.finalize(),
            None => sha256.clone(),
        };
        if check.is_some_and(|w| got != w.bytes) {
            return Ok(Err(checksum::mismatch(header)));
        }
        kept = Some((header, vk_hub_proto::to_base64(&got)));
    }
    if let Some(a) = asked.filter(|a| a.kind == checksum::Kind::Composite)
        && let (Some(header), Some(values)) = (a.header(), &part_checksums)
    {
        let decoded: Option<Vec<Vec<u8>>> = values
            .iter()
            .map(|v| crate::auth::base64_decode(v))
            .collect();
        if let Some(digest) = decoded.and_then(|d| checksum::composite(header, &d)) {
            // Sent with its count of parts or without, as S3 takes it.
            if let Some(w) = whole.filter(|w| w.header == header)
                && (w.bytes != digest || w.composite.is_some_and(|n| n as usize != parts.len()))
            {
                return Ok(Err(checksum::mismatch(header)));
            }
            let made = format!("{}-{}", vk_hub_proto::to_base64(&digest), parts.len());
            kept = Some((header, made));
        }
    }
    staged.hex = crate::hex_of(&sha256);
    Ok(Ok(Assembled {
        staged,
        etag: multipart_etag(&md5s),
        checksum: kept,
        sizes,
        part_checksums,
    }))
}

/// `POST /s3/<bucket>/<key>?uploadId=<id>`: the object the `CompleteMultipartUpload`
/// document's parts make, in the order given, tagged at the key as a PutObject's body is
/// (the key checked again, `If-None-Match: *`/`If-Match` checked where the tag is written),
/// with the user metadata recorded at the upload's creation, the multipart ETag, the
/// whole-object checksum that held and the parts' sizes; the upload then goes, leaving what
/// it made ([`settle`]). A refusal leaves the upload as it was, to be completed again. A
/// completed upload is answered as it was when the same parts are named again and the key
/// still holds the object it made ([`completed`]), and is `NoSuchUpload` otherwise.
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
    let conditions = match WriteConditions::of(req.headers()) {
        Ok(conditions) => conditions,
        Err(why) => return refuse(req, ctx.error(why), ctx).await,
    };
    // An upload no id names, in progress or completed, before its document is read.
    let known = {
        let (store, id) = (Arc::clone(&state.store), id.clone());
        tokio::task::spawn_blocking(move || store.multipart_dir(&id).is_some_and(|d| d.is_dir()))
            .await
            .context("looking up an upload panicked")?
    };
    if !known {
        return refuse(req, no_such_upload(ctx, &id), ctx).await;
    }
    let whole =
        match Whole::of(req.headers()).and_then(|w| Ok((w, completion_kind(req.headers())?))) {
            Ok(whole) => whole,
            Err(why) => return refuse(req, ctx.error(why), ctx).await,
        };
    let (head, body) = req.into_parts();
    let too_long = ctx.error(Code::MalformedXML);
    let body = match read_small(body, MAX_DOCUMENT, too_long, ctx).await? {
        Ok(body) => body,
        Err(resp) => return Ok(resp),
    };
    if let Err(why) = object::check_document(&head.headers, &body) {
        return Ok(ctx.error(why));
    }
    let (parts, sent) = match document(&body) {
        Ok(parts) => parts,
        // What is wrong with it is S3's to say in its own words.
        Err(Unfit::Malformed(_)) => return Ok(ctx.error(Code::MalformedXML)),
        Err(Unfit::Order) => {
            return Ok(ctx.error(Refusal::new(Code::InvalidPartOrder).with("UploadId", id)));
        }
        Err(Unfit::Number(sent)) => {
            return Ok(ctx.error(Refusal::argument(
                "PartNumber must be >= 1",
                "PartNumber",
                sent,
            )));
        }
    };
    let found = {
        let (store, segs, id) = (Arc::clone(&state.store), segs.clone(), id.clone());
        tokio::task::spawn_blocking(move || -> Result<_> {
            let Some((lock, dir)) = hold(&store, &id)? else {
                return Ok(Found::Gone);
            };
            let Some(up) = open(&store, &id, &segs) else {
                return Ok(match completed(&store, &dir, &segs, &parts)? {
                    Some(done) => Found::Completed(done),
                    None => Found::Gone,
                });
            };
            let (whole, kind) = &whole;
            let assembled = assemble(&store, &up, &parts, &sent, (whole.as_ref(), *kind))?;
            let held = Held { _lock: lock, up };
            Ok(Found::Assembled(held, parts, Box::new(assembled)))
        })
        .await
        .context("assembling an upload panicked")??
    };
    // Held until the upload is completed, so a completion racing this one waits, then finds
    // it completed rather than its parts going from under it.
    let (Held { _lock, up }, parts, assembled) = match found {
        Found::Gone => return Ok(no_such_upload(ctx, &id)),
        Found::Completed(done) => return Ok(done.result(ctx)),
        Found::Assembled(held, parts, assembled) => match *assembled {
            Err(why) => return Ok(ctx.error(why)),
            Ok(assembled) => (held, parts, assembled),
        },
    };
    let Assembled {
        staged,
        etag,
        checksum,
        sizes,
        part_checksums,
    } = assembled;
    let mut annotations = up.meta.annotations;
    annotations.insert(MD5_ANNOTATION.to_string(), etag.clone());
    annotations.insert(PARTS_ANNOTATION.to_string(), parts_annotation(&sizes));
    if let Some(values) = part_checksums {
        annotations.insert(PART_CHECKSUMS_ANNOTATION.to_string(), values.join(","));
    }
    if let Some((name, value)) =
        checksum.and_then(|(header, text)| checksum::annotation(header, &text))
    {
        annotations.insert(name, value);
    }
    let kept = checksum::stored(&annotations).map_or(String::new(), |kept| kept.elements());
    let done = Completed {
        bucket: up.meta.bucket,
        key: up.meta.key,
        parts,
        etag,
        layer: staged.hex.clone(),
        kept,
    };
    let how = Commit {
        annotations,
        precondition: conditions.clone().precondition(),
        uncompressed: staged.size >= UNCOMPRESSED_FROM,
    };
    match files::commit(Arc::clone(&state.store), segs, staged, how).await? {
        Written::Created | Written::Replaced => {}
        Written::Refused(why) => return Ok(unwritable(why, ctx)),
        Written::PreconditionFailed { found } => return Ok(ctx.error(conditions.refusal(found))),
    }
    let resp = done.result(ctx);
    let dir = up.dir;
    let settled = {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || settle(&dir, &done))
            .await
            .context("recording a completion panicked")?
    };
    if settled.is_err() {
        // The object is made; an upload that could not be remembered as completed only
        // answers a retry of its completion 404, as one completed before this did.
        remove(dir).await?;
    }
    Ok(resp)
}

/// What [`complete`] found of an upload, held.
enum Found {
    /// no upload of the key by that id, or one completed otherwise than asked
    Gone,
    /// completed as asked, into the object still at the key
    Completed(Completed),
    /// in progress: its parts assembled as asked, or why not
    Assembled(
        Held,
        Vec<(u32, String)>,
        Box<std::result::Result<Assembled, Refusal>>,
    ),
}

/// What a completed upload leaves in its directory, in place of its record and parts.
const COMPLETED: &str = "completed.json";

/// What an upload's completion made, remembered so that the same completion sent again (an
/// SDK retrying one whose answer it lost) is answered as it was.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Completed {
    bucket: String,
    key: String,
    /// the parts the completion named, as [`document`] reads them
    parts: Vec<(u32, String)>,
    /// the object's ETag, unquoted
    etag: String,
    /// the object's bytes, by the hex of their SHA-256
    layer: String,
    /// the checksum elements of the answer
    kept: String,
}

impl Completed {
    /// The `CompleteMultipartUploadResult` of this completion.
    fn result(&self, ctx: &Ctx) -> Response<Body> {
        xml::document(
            "CompleteMultipartUploadResult",
            &format!(
                "{}{}{}{}{}",
                xml::element("Location", &ctx.url),
                xml::element("Bucket", &self.bucket),
                xml::element("Key", &self.key),
                xml::element("ETag", &format!("\"{}\"", self.etag)),
                self.kept
            ),
        )
    }
}

/// The completion `dir` remembers, when it named `parts` for the object at `segs` and that
/// object is still the one it made: the same bytes under the same multipart ETag. An object
/// written over or deleted since, or another list of parts, finds none.
fn completed(
    store: &Store,
    dir: &Path,
    segs: &[String],
    parts: &[(u32, String)],
) -> Result<Option<Completed>> {
    let Some(done) = read_record::<Completed>(&dir.join(COMPLETED)) else {
        return Ok(None);
    };
    if done.bucket != bucket_of(segs) || done.key != key_of(segs) || done.parts != parts {
        return Ok(None);
    }
    let same = match files::resolve(store, segs)? {
        Some(files::Node::Object(obj)) => {
            obj.layer == done.layer && obj.annotations.get(MD5_ANNOTATION) == Some(&done.etag)
        }
        _ => false,
    };
    Ok(same.then_some(done))
}

/// Leave the completed upload in `dir` as `done` only: its record removed first, so it is no
/// upload in progress from then on, then `done` written, then its parts and whatever else is
/// there removed. The directory then goes as an idle upload's does, once the gc's grace
/// window has passed.
fn settle(dir: &Path, done: &Completed) -> Result<()> {
    std::fs::remove_file(dir.join(META))
        .with_context(|| format!("removing {}", dir.join(META).display()))?;
    vk_fs::write_atomic_unsynced(&dir.join(COMPLETED), &serde_json::to_vec(done)?, 0o600)?;
    for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry?;
        if entry.file_name() != COMPLETED {
            let path = entry.path();
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(
                        anyhow::Error::from(e).context(format!("removing {}", path.display()))
                    );
                }
            }
        }
    }
    Ok(())
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

/// `DELETE /s3/<bucket>/<key>?uploadId=<id>`: the upload and its parts removed; 204. With
/// `x-amz-if-match-initiated-time`, only an upload initiated in that second is: 412 for
/// another, 400 for a value that is not a date. A time still to come is no condition, as S3
/// takes it.
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
    let initiated = match req.headers().get(conditional::IF_MATCH_INITIATED) {
        None => None,
        Some(v) => match v.to_str().ok().and_then(conditional::parse_time) {
            Some(t) if t > SystemTime::now() => None,
            Some(t) => Some(conditional::whole_seconds(t)),
            None => {
                let resp = ctx.error(Refusal::argument(
                    "x-amz-if-match-initiated-time is an HTTP date",
                    conditional::IF_MATCH_INITIATED,
                    String::from_utf8_lossy(v.as_bytes()),
                ));
                return refuse(req, resp, ctx).await;
            }
        },
    };
    if let Some(resp) = drain(req, ctx).await? {
        return Ok(resp);
    }
    // Held until the upload is gone: an abort racing a completion waits for it to end.
    let Some(Held { _lock, up }) = open_held_async(state, &id, &segs).await? else {
        return Ok(no_such_upload(ctx, &id));
    };
    if initiated.is_some_and(|t| t != up.meta.created) {
        return Ok(ctx.error(
            Refusal::new(Code::PreconditionFailed).with("Condition", "If-Match-Initiated-Time"),
        ));
    }
    remove(up.dir).await?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(body_of(bytes::Bytes::new()))?)
}

/// A page size as query parameter `name` gives it ([`list::count`]), clamped to
/// [`MAX_LISTED`]; absent, the bound.
fn page_size(name: &'static str, value: Option<&str>) -> std::result::Result<usize, Refusal> {
    match value {
        None => Ok(MAX_LISTED),
        Some(v) => Ok(usize::try_from(list::count(name, v)?)
            .unwrap_or(MAX_LISTED)
            .min(MAX_LISTED)),
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
    // S3 refuses a count that is no number first, then looks the upload up, then refuses
    // one that is negative.
    let negative =
        |name| param(params, name).is_some_and(|v| v.parse::<i64>().is_ok_and(|n| n < 0));
    let max = page_size("max-parts", param(params, "max-parts"));
    let marker =
        param(params, "part-number-marker").map_or(Ok(0), |m| list::count("part-number-marker", m));
    for (sent, name) in [
        (max.as_ref().err(), "max-parts"),
        (marker.as_ref().err(), "part-number-marker"),
    ] {
        if let Some(why) = sent
            && !negative(name)
        {
            return refuse(req, ctx.error(why.clone()), ctx).await;
        }
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, _| {
        let Some(up) = open(store, &id, &segs) else {
            return Ok(no_such_upload(&ctx, &id));
        };
        let (max, marker) = match (max, marker) {
            (Ok(max), Ok(marker)) => (max, marker),
            (Err(why), _) | (_, Err(why)) => return Ok(ctx.error(why)),
        };
        let mut numbers = if max == 0 {
            Vec::new()
        } else {
            parts_after(&up.dir, marker, max.saturating_add(1))?
        };
        let truncated = numbers.len() > max;
        numbers.truncate(max);
        let mut out = format!(
            "{}{}{}{}{}{}{}",
            xml::element("Bucket", &up.meta.bucket),
            xml::element("Key", &up.meta.key),
            xml::element("UploadId", &up.id),
            initiator_and_owner(),
            xml::element("StorageClass", "STANDARD"),
            up.meta
                .checksum
                .as_ref()
                .map_or(String::new(), Asked::listed),
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
            let checksum = part
                .checksum
                .as_deref()
                .and_then(|kept| kept.split_once(':'))
                .map_or(String::new(), |(algorithm, value)| {
                    xml::element(&format!("Checksum{algorithm}"), value)
                });
            out.push_str(&format!(
                "<Part>{}{}{}{}{checksum}</Part>",
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
    checksum: Option<Asked>,
}

impl Listed {
    /// Where the upload is listed: by key, then as S3 lists a key's uploads, by when each was
    /// initiated, which the counter in its id (`<pid>-<n>-<random>`) orders within the second
    /// for the uploads one server made.
    fn order(&self) -> (&str, u64, u64, u64, &str) {
        let mut n = self
            .id
            .splitn(3, '-')
            .map(|n| n.parse().unwrap_or(u64::MAX));
        let (pid, count) = (n.next().unwrap_or(u64::MAX), n.next().unwrap_or(u64::MAX));
        (&self.key, self.created, pid, count, &self.id)
    }
}

/// `GET /s3/<bucket>?uploads`: the uploads in progress into the bucket whose key starts with
/// `prefix`, in [`Listed::order`], after `key-marker`, `max-uploads` of them (at most and by
/// default 1000). With `upload-id-marker` too, after that upload, which has to be one of the
/// first key from `key-marker` on, as S3 takes it; without `key-marker` it is ignored.
/// Admitted as a listing of the bucket with that prefix is, and shows only the uploads whose
/// key the caller may read. Every upload's record is read: the cost is the store's uploads
/// in progress, not the bucket's.
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
        Some(v) => {
            let resp = ctx.error(Refusal::argument(
                "Invalid Encoding Method specified in Request",
                "encoding-type",
                v,
            ));
            return refuse(req, resp, ctx).await;
        }
    };
    let max = match page_size("max-uploads", param(&params, "max-uploads")) {
        Ok(max) => max,
        Err(why) => return refuse(req, ctx.error(why), ctx).await,
    };
    // Each is echoed in the listing, so held to what a bucket listing's prefix is.
    let echoed = |name| list::text(name, param(&params, name).unwrap_or_default().to_string());
    let (prefix, key_marker, mut id_marker) = match (
        echoed("prefix"),
        echoed("key-marker"),
        echoed("upload-id-marker"),
    ) {
        (Ok(prefix), Ok(key), Ok(id)) => (prefix, key, id),
        (Err(why), _, _) | (_, Err(why), _) | (_, _, Err(why)) => {
            return refuse(req, ctx.error(why), ctx).await;
        }
    };
    if key_marker.is_empty() {
        id_marker.clear();
    }
    let prefix_sent = param(&params, "prefix").is_some();
    if !list::admitted(authz, &bucket, &prefix) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        if !store.repo_dir_exists(&format!("{FILES_REPO}/{bucket}")) {
            return Ok(ctx.error(bucket::no_such_bucket(&bucket)));
        }
        let mut uploads: Vec<Listed> = Vec::new();
        for (id, dir) in store.multipart_uploads() {
            let Some(meta) = read_record::<Meta>(&dir.join(META)) else {
                continue;
            };
            // Past the key marker; at it too when an upload of the first key is to be found.
            let after = meta.key > key_marker || (meta.key == key_marker && !id_marker.is_empty());
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
                    checksum: meta.checksum,
                });
            }
        }
        uploads.sort_by(|a, b| a.order().cmp(&b.order()));
        if !id_marker.is_empty() {
            let first = uploads.first().map(|u| u.key.clone());
            let Some(at) = uploads
                .iter()
                .take_while(|u| Some(&u.key) == first.as_ref())
                .position(|u| u.id == id_marker)
            else {
                return Ok(ctx.error(Refusal::argument(
                    "Invalid uploadId marker",
                    "upload-id-marker",
                    id_marker,
                )));
            };
            uploads.drain(..=at);
        }
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
        // S3 names the page's last upload whether or not more follow.
        if let Some(last) = uploads.last() {
            out.push_str(&xml::element("NextKeyMarker", &enc(&last.key)));
            out.push_str(&xml::element("NextUploadIdMarker", &last.id));
        }
        if prefix_sent {
            out.push_str(&xml::element("Prefix", &enc(&prefix)));
        }
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
                "<Upload>{}{}{}{}{}{}</Upload>",
                xml::element("Key", &enc(&u.key)),
                xml::element("UploadId", &u.id),
                initiator_and_owner(),
                xml::element("StorageClass", "STANDARD"),
                xml::element("Initiated", &list::iso8601(created)),
                u.checksum.as_ref().map_or(String::new(), Asked::listed),
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
            parts.0,
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
            assert_eq!(document(&body(&unordered)), Err(Unfit::Order));
        }
    }

    #[test]
    fn a_completion_that_is_not_one_is_malformed() {
        for bad in [
            body(""),
            body("<Part><PartNumber>1</PartNumber></Part>"),
            body("<Part><ETag>x</ETag></Part>"),
            body(&part("10001", MD5)),
            body(&part("one", MD5)),
            body(&part("", MD5)),
            body("<Part><PartNumber>1</PartNumber><PartNumber>2</PartNumber><ETag>x</ETag></Part>"),
            body(&part("1", "&ent;")),
            b"<Other><Part><PartNumber>1</PartNumber><ETag>x</ETag></Part></Other>".to_vec(),
            b"".to_vec(),
        ] {
            assert!(
                matches!(document(&bad), Err(Unfit::Malformed(_))),
                "{}",
                String::from_utf8_lossy(&bad)
            );
        }
        // A number below 1 is S3's InvalidArgument, naming it as sent.
        for low in ["0", "-1"] {
            assert_eq!(
                document(&body(&part(low, MD5))),
                Err(Unfit::Number(low.to_string()))
            );
        }
        // The most parts there can be fit in the bound; past it, the scan stops.
        let max = (1..=MAX_PARTS)
            .map(|n| part(&n.to_string(), MD5))
            .collect::<String>();
        assert_eq!(document(&body(&max)).unwrap().0.len(), MAX_PARTS as usize);
        let elements = (0..MAX_ELEMENTS).map(|_| "<x/>").collect::<String>();
        assert!(matches!(
            document(&body(&elements)),
            Err(Unfit::Malformed(_))
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
    fn part_sizes_round_trip_through_their_annotation() {
        let of = |text: &str| {
            part_sizes(&BTreeMap::from([(
                PARTS_ANNOTATION.to_string(),
                text.to_string(),
            )]))
        };
        for sizes in [
            vec![5],
            vec![8 << 20, 8 << 20, 8 << 20, 1024],
            vec![1, 2, 2, 3, 3, 3, 1],
            vec![0, 0],
            vec![7; 10_000],
        ] {
            let text = parts_annotation(&sizes);
            assert_eq!(of(&text), Some(sizes.clone()), "{text}");
        }
        assert_eq!(
            parts_annotation(&[8 << 20, 8 << 20, 8 << 20, 1024]),
            "8388608x3,1024"
        );
        assert_eq!(parts_annotation(&[1, 2, 2, 3, 3, 3, 1]), "1,2x2,3x3,1");
        assert_eq!(of("3x2"), Some(vec![3, 3]));
        for bad in [
            "",
            "x",
            "3x",
            "x3",
            "3x0",
            "-1",
            "1,,2",
            "1x10001",
            "4294967296x1024",
            "99999999999999999999999",
        ] {
            assert_eq!(of(bad), None, "{bad:?}");
        }
        assert_eq!(part_sizes(&BTreeMap::new()), None);

        let sizes = [5, 7, 0, 3];
        assert_eq!(part_range(&sizes, 1), Some((0, 5)));
        assert_eq!(part_range(&sizes, 2), Some((5, 7)));
        assert_eq!(part_range(&sizes, 3), Some((12, 0)));
        assert_eq!(part_range(&sizes, 4), Some((12, 3)));
        assert_eq!(part_range(&sizes, 5), None);
        assert_eq!(part_range(&sizes, 0), None);
    }

    #[test]
    fn object_parts_are_paged_as_s3_pages_them() {
        let sizes = [5, 7, 3];
        assert_eq!(
            object_parts(&sizes, None, 1000, 0),
            "<ObjectParts><IsTruncated>false</IsTruncated><MaxParts>1000</MaxParts>\
             <PartNumberMarker>0</PartNumberMarker><Part><PartNumber>1</PartNumber><Size>5</Size>\
             </Part><Part><PartNumber>2</PartNumber><Size>7</Size></Part><Part><PartNumber>3\
             </PartNumber><Size>3</Size></Part><PartsCount>3</PartsCount></ObjectParts>"
        );
        assert_eq!(
            object_parts(&sizes, None, 2, 0),
            "<ObjectParts><IsTruncated>true</IsTruncated><MaxParts>2</MaxParts>\
             <NextPartNumberMarker>2</NextPartNumberMarker><PartNumberMarker>0</PartNumberMarker>\
             <Part><PartNumber>1</PartNumber><Size>5</Size></Part><Part><PartNumber>2</PartNumber>\
             <Size>7</Size></Part><PartsCount>3</PartsCount></ObjectParts>"
        );
        assert_eq!(
            object_parts(&sizes, None, 2, 2),
            "<ObjectParts><IsTruncated>false</IsTruncated><MaxParts>2</MaxParts>\
             <PartNumberMarker>2</PartNumberMarker><Part><PartNumber>3</PartNumber><Size>3</Size>\
             </Part><PartsCount>3</PartsCount></ObjectParts>"
        );
        let none = object_parts(&sizes, None, 0, 0);
        assert!(none.contains("<IsTruncated>true</IsTruncated><MaxParts>0</MaxParts>"));
        assert!(!none.contains("<Part>") && !none.contains("NextPartNumberMarker"));
        assert!(!object_parts(&sizes, None, 5, 3).contains("<Part>"));
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
        assert_eq!(page_size("max-parts", None), Ok(MAX_LISTED));
        assert_eq!(page_size("max-parts", Some("5")), Ok(5));
        assert_eq!(page_size("max-parts", Some("2147483647")), Ok(MAX_LISTED));
        // Past what S3 takes, in its words.
        let refused = |v| page_size("max-parts", Some(v)).unwrap_err();
        assert_eq!(
            refused("100000000000000000000000").message(),
            "Provided 100000000000000000000000 not an integer or within integer range"
        );
        let r = refused("-1");
        assert_eq!(
            r.message(),
            "Argument -1 must be an integer between 0 and 2147483647"
        );
        assert_eq!(r.element("ArgumentName"), Some("max-parts"));
        assert_eq!(r.element("ArgumentValue"), Some("-1"));
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
            checksum: None,
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
