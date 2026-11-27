//! Named plain files: the objects `/files/` and `/s3/` serve, stored in the OCI pool. An
//! object's path is `<dir…>/<leaf>`; it lives in the repository `files/<dir…>` as the tag
//! `<leaf>` on a single-layer raw-file manifest, as `/upload` and `PUT /files/` write one,
//! whose layer holds the file's bytes. A path is authorized as the repository it names, so
//! `files/<dir>/*` covers a whole tree. Objects expire under gc's tag retention and
//! blob grace windows.
//!
//! This module holds what every view of the objects shares: the path rules, the lookup, a
//! read (including byte ranges), single-request writes and deletions under the namespace
//! lock, and bounded draining of refused request bodies. Each view uses the parts it needs.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::header::{
    ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, IF_RANGE, LAST_MODIFIED,
    RANGE,
};
use hyper::{Request, Response, StatusCode};
use tokio::io::AsyncWriteExt;

use crate::staging::{DrainError, Staging, drain_into};
use crate::{Authz, Body, ServerState, Store, accounts, error_response};

/// The repository every object lives under.
const FILES_REPO: &str = "files";

/// Maximum object size, checked both against Content-Length and while streaming.
const MAX_OBJECT: u64 = 4 << 30;

/// Maximum decoded component length in bytes.
const MAX_SEGMENT: usize = 255;

/// A `GET` refreshes the tag mtime used by GC only if the observed mtime is over an hour old.
/// Concurrent reads can observe the same mtime.
const TOUCH_AFTER: Duration = Duration::from_secs(3600);

/// Serialize namespace checks and changes so competing writes cannot make one path both
/// a directory and an object. Acquire before the store lock. `/v2/` writes into `files/`
/// bypass this lock.
static NAMESPACE: Mutex<()> = Mutex::new(());

/// The namespace held, in this process and against any other serving the store: a registry
/// and the release it hands over to serve it together for a while.
struct Namespace {
    _process: std::sync::MutexGuard<'static, ()>,
    _store: crate::LockGuard,
}

/// Hold [`NAMESPACE`], then the store's namespace lock. Accept a poisoned mutex: it guards
/// no data that a panic could leave inconsistent.
fn namespace(store: &Store) -> Result<Namespace> {
    let process = NAMESPACE.lock().unwrap_or_else(PoisonError::into_inner);
    Ok(Namespace {
        _process: process,
        _store: store.lock_namespace()?,
    })
}

/// What an object path names once the store has been looked at.
enum Node {
    /// A repository under `files/`, or a path component above one: a directory.
    Dir(String),
    /// A tag on a raw-file manifest: an object.
    Object(Object),
    /// A tag with a missing or non-file manifest, such as an image pushed through `/v2/`.
    /// Reads hide it. `PUT` and `DELETE` refuse it with 409. `MKCOL` sees an existing
    /// path and returns 405.
    Foreign(String),
}

/// An object's tag and what its manifest says about the layer.
struct Object {
    repo: String,
    tag: String,
    /// the layer blob's hex
    layer: String,
    /// the tag's mtime
    modified: SystemTime,
}

impl Node {
    /// The repository this node authorizes as.
    fn repo(&self) -> &str {
        match self {
            Node::Dir(r) | Node::Foreign(r) => r,
            Node::Object(o) => &o.repo,
        }
    }
}

/// Split `rest`, a path below a view's root, into its decoded components and whether it
/// ended in a slash, splitting before percent-decoding. Reject decoded separators, control
/// bytes, `.`, `..`, empty or oversized components, malformed escapes and invalid UTF-8. An
/// empty path is the root: no components.
pub(crate) fn split(rest: &str) -> Option<(Vec<String>, bool)> {
    if rest.is_empty() {
        return Some((Vec::new(), true));
    }
    let (rest, trailing_slash) = match rest.strip_suffix('/') {
        Some(r) => (r, true),
        None => (rest, false),
    };
    if rest.is_empty() {
        return None;
    }
    let segments = rest
        .split('/')
        .map(|raw| decode_segment(raw).filter(|s| valid_segment(s)))
        .collect::<Option<Vec<_>>>()?;
    Some((segments, trailing_slash))
}

/// Percent-decode one path component: `%XX` escapes only, `+` being itself in a path, and
/// the decoded bytes must be UTF-8. `None` for a malformed escape or invalid UTF-8.
fn decode_segment(raw: &str) -> Option<String> {
    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hi = hex(*b.get(i + 1)?)?;
            let lo = hex(*b.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// One decoded path component: non-empty, not a directory traversal, short enough to be a
/// filename, and free of anything that could make it more than one component.
fn valid_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg.len() <= MAX_SEGMENT
        && !seg.contains(['/', '\\'])
        && !seg.chars().any(char::is_control)
}

/// A decoded object path (S3's `<bucket>/<key>`) must pass [`split`]'s component checks.
/// The full `files/<path>`, including the leaf, must satisfy the store's repository name
/// and depth limits. `tags`, `manifests` and `blobs` are reserved components.
pub fn valid_plain_file(path: &str) -> bool {
    path.split('/').all(valid_segment) && crate::valid_name(&format!("{FILES_REPO}/{path}"))
}

/// Each component must pass [`split`]'s checks and the parent must name a repository
/// under `files/`. The leaf follows tag rules, so `tags` is valid here even though
/// [`valid_plain_file`] rejects it. S3 leaves may exceed the file PUT tag limit.
pub(crate) fn valid_file(segs: &[String]) -> bool {
    let Some((leaf, parents)) = segs.split_last() else {
        return false;
    };
    segs.iter().all(|s| valid_segment(s))
        && crate::valid_tag(leaf)
        && crate::valid_name(&repo_name(parents))
}

/// The repository a run of path components names: `files/<segs…>`.
fn repo_name(segs: &[String]) -> String {
    let mut name = String::from(FILES_REPO);
    for s in segs {
        name.push('/');
        name.push_str(s);
    }
    name
}

/// The repository and tag an object at `segs` would have: the last component is the tag.
fn object_of(segs: &[String]) -> Option<(String, &str)> {
    let (leaf, parents) = segs.split_last()?;
    (!parents.is_empty()).then(|| (repo_name(parents), leaf.as_str()))
}

/// What is at `segs`: a directory, an object, a foreign tag, or nothing. A directory is any
/// path under `repos/files/` that is one — a repository, or the parent a nested repository's
/// name created — so the tree reads as the client wrote it.
fn resolve(store: &Store, segs: &[String]) -> Result<Option<Node>> {
    let dir = repo_name(segs);
    if store.repo_dir_exists(&dir) {
        return Ok(Some(Node::Dir(dir)));
    }
    let Some((repo, tag)) = object_of(segs) else {
        return Ok(None);
    };
    let Some((manifest_hex, modified)) = store.tag_target(&repo, tag) else {
        return Ok(None);
    };
    let layer = match store.get_blob(&manifest_hex)? {
        Some(manifest) => crate::raw_file_layer(&manifest),
        None => None,
    };
    Ok(Some(match layer {
        Some((layer, _)) => Node::Object(Object {
            repo,
            tag: tag.to_string(),
            layer,
            modified,
        }),
        None => Node::Foreign(repo),
    }))
}

/// Whether an ancestor of `segs` is a tag. Writing below one would make its path a directory
/// too, and [`resolve`] would then find the directory and hide the tag. A top-level name is
/// always a directory.
fn under_object(store: &Store, segs: &[String]) -> Result<bool> {
    for n in 2..segs.len() {
        if matches!(
            resolve(store, &segs[..n])?,
            Some(Node::Object(_) | Node::Foreign(_))
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether this caller may `action` on `repo`.
fn allowed(authz: &Authz<'_>, action: accounts::Action, repo: &str) -> bool {
    crate::authorize_or_forbidden(authz, action, repo).is_none()
}

/// A `PUT` writes a tag in the parent repository. For other requests checked here, a grant
/// on either the path or its parent permits lookup. The resolved repository determines access.
pub(crate) fn admits(
    authz: &Authz<'_>,
    action: accounts::Action,
    segs: &[String],
    put: bool,
) -> bool {
    let own = repo_name(segs);
    let parent = object_of(segs).map(|(repo, _)| repo);
    if put {
        allowed(authz, action, parent.as_deref().unwrap_or(&own))
    } else {
        allowed(authz, action, &own) || parent.as_deref().is_some_and(|p| allowed(authz, action, p))
    }
}

/// Resolve `segs` for a caller that may act on it: `None` when nothing is there, when the
/// path ends in a slash but names an object, or when the caller may not `action` on the
/// repository it resolved to — absent, as far as that caller can tell.
fn resolve_for(
    store: &Store,
    authz: &Authz<'_>,
    action: accounts::Action,
    segs: &[String],
    trailing_slash: bool,
) -> Result<Option<Node>> {
    Ok(resolve(store, segs)?.filter(|node| {
        !(trailing_slash && !matches!(node, Node::Dir(_))) && allowed(authz, action, node.repo())
    }))
}

/// [`crate::blocking`], labelled as a plain-file request.
pub(crate) async fn blocking<F>(
    state: &ServerState,
    authz: &Authz<'_>,
    f: F,
) -> Result<Response<Body>>
where
    F: FnOnce(&Store, &Authz<'_>) -> Result<Response<Body>> + Send + 'static,
{
    crate::blocking(&state.store, authz, "a plain-file request", f).await
}

/// Options for an object read.
#[derive(Default)]
pub(crate) struct Read<'a> {
    /// A `HEAD`: the headers only, and no use recorded.
    pub(crate) head: bool,
    /// The `Range` asked for ([`range_asked`]).
    pub(crate) range: Option<&'a str>,
    /// Required layer digest for a digest URL.
    pub(crate) layer: Option<&'a str>,
}

/// `GET`/`HEAD` an object: the layer blob, through the `/v2/` handler, under this
/// repository's membership for whole-object reads. Ranged reads use the same membership
/// check. An unsatisfiable range returns 416. A mismatched required layer returns 404.
pub(crate) fn get(
    authz: &Authz<'_>,
    store: &Store,
    segs: &[String],
    trailing_slash: bool,
    href: &str,
    read: Read<'_>,
) -> Result<Response<Body>> {
    let Read { head, range, layer } = read;
    // A directory has no body to serve.
    let Some(Node::Object(obj)) =
        resolve_for(store, authz, accounts::Action::Read, segs, trailing_slash)?
    else {
        return Ok(not_found(href));
    };
    // `PUT` records the layer in this repository. A scoped caller can also read it
    // through another repository that holds it and that the caller may read.
    if !crate::readable_through(authz, store, &obj.repo, &obj.layer) {
        return Ok(not_found(href));
    }
    // A name that is a digest serves only the bytes it names.
    if layer.is_some_and(|hex| hex != obj.layer) {
        return Ok(not_found(href));
    }
    // A HEAD is a client checking that something exists, so it refreshes nothing, the layer
    // blob included.
    let mut resp = match range {
        Some(range) => serve_range(store, &obj.layer, range, head)?,
        None => crate::serve_blob(store, &format!("sha256:{}", obj.layer), head, None, false)?,
    };
    if resp.status().is_success() {
        // A GET served is a use, which is what keeps the tag from the gc's retention.
        // Refreshed only once idle, so a hot entry is not a metadata write per hit.
        if !head
            && SystemTime::now()
                .duration_since(obj.modified)
                .is_ok_and(|idle| idle > TOUCH_AFTER)
        {
            store.touch_tag(&obj.repo, &obj.tag);
        }
        let headers = resp.headers_mut();
        // Prevent uploaded content from rendering on the `/browse` origin.
        headers.insert(
            CONTENT_DISPOSITION,
            hyper::header::HeaderValue::from_static("attachment"),
        );
        headers.insert(
            ACCEPT_RANGES,
            hyper::header::HeaderValue::from_static("bytes"),
        );
        if let Ok(v) = hyper::header::HeaderValue::from_str(&http_date(obj.modified)) {
            headers.insert(LAST_MODIFIED, v);
        }
    }
    Ok(resp)
}

/// Return a single `Range` header for parsing. Multiple headers or an unchecked
/// `If-Range` validator permit a whole-object response.
pub(crate) fn range_asked(headers: &hyper::HeaderMap) -> Option<String> {
    if headers.contains_key(IF_RANGE) {
        return None;
    }
    let mut ranges = headers.get_all(RANGE).iter();
    match (ranges.next(), ranges.next()) {
        (Some(v), None) => v.to_str().ok().map(str::to_string),
        _ => None,
    }
}

/// What a `Range` value asks of `len` bytes.
#[derive(Debug, PartialEq, Eq)]
enum Part {
    /// The whole: no single byte range, or one this server ignores, as RFC 9110 allows.
    Whole,
    /// Bytes `first..=last`.
    Bytes(u64, u64),
    /// A valid range that selects no bytes.
    Unsatisfiable,
}

/// Read `range` against `len` bytes: `bytes=<first>-[<last>]` or `bytes=-<suffix length>`.
/// Several ranges, another unit or a malformed spec are served whole.
fn part(range: &str, len: u64) -> Part {
    let Some((first, last)) = range
        .trim()
        .strip_prefix("bytes=")
        .and_then(|spec| spec.split_once('-'))
    else {
        return Part::Whole;
    };
    let (first, last) = (first.trim(), last.trim());
    let num = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    let (Some(first), last) = (num(first), last) else {
        // `-<n>`: the last n bytes.
        return match (first.is_empty(), num(last)) {
            (true, Some(n)) if n > 0 && len > 0 => Part::Bytes(len.saturating_sub(n), len - 1),
            (true, Some(_)) => Part::Unsatisfiable,
            _ => Part::Whole,
        };
    };
    let last = match (last.is_empty(), num(last)) {
        (true, _) => u64::MAX,
        (false, Some(last)) => last,
        (false, None) => return Part::Whole,
    };
    if first > last {
        Part::Whole
    } else if first >= len {
        Part::Unsatisfiable
    } else {
        Part::Bytes(first, last.min(len - 1))
    }
}

/// Serve a range of canonical bytes with 206 and `Content-Range`, or return 416 for an
/// unsatisfiable range. Delegate whole-object reads to [`crate::serve_blob`].
fn serve_range(store: &Store, hex: &str, range: &str, head: bool) -> Result<Response<Body>> {
    use std::io::{Read, Seek, SeekFrom};
    let digest = format!("sha256:{hex}");
    let Some((path, is_zstd)) = store.find_blob(hex) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            &digest,
        ));
    };
    // As in `serve_blob`, measure and stream the same open file even if its path is replaced.
    let mut file =
        std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let len = if is_zstd {
        crate::zstd_canonical_len(&mut file)
            .with_context(|| format!("measuring the stored blob {digest}"))?
    } else {
        file.metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len()
    };
    let (first, last) = match part(range, len) {
        Part::Whole => return crate::serve_blob(store, &digest, head, None, false),
        Part::Unsatisfiable => {
            let mut resp = error_response(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "RANGE_INVALID",
                &format!("the object has {len} bytes"),
            );
            if let Ok(v) = hyper::header::HeaderValue::from_str(&format!("bytes */{len}")) {
                resp.headers_mut().insert(CONTENT_RANGE, v);
            }
            return Ok(resp);
        }
        Part::Bytes(first, last) => (first, last),
    };
    let count = last - first + 1;
    let builder = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_RANGE, format!("bytes {first}-{last}/{len}"))
        .header(CONTENT_LENGTH, count.to_string());
    if head {
        return builder
            .body(crate::body_of(bytes::Bytes::new()))
            .map_err(Into::into);
    }
    let body = if is_zstd {
        // The zstd frame has no seek index. Decode from the start and discard the prefix.
        let decoder = crate::zctx::decoder(file).context("opening a stored blob")?;
        crate::stream_body(Skip::new(decoder, first).take(count), &digest)
    } else {
        file.seek(SeekFrom::Start(first))
            .with_context(|| format!("seeking in {}", path.display()))?;
        crate::stream_body(file.take(count), &digest)
    };
    builder.body(body).map_err(Into::into)
}

/// A reader that drops its first `skip` bytes, on its first read.
struct Skip<R> {
    inner: R,
    skip: u64,
}

impl<R> Skip<R> {
    fn new(inner: R, skip: u64) -> Self {
        Skip { inner, skip }
    }
}

impl<R: std::io::Read> std::io::Read for Skip<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.skip > 0 {
            let skipped =
                std::io::copy(&mut (&mut self.inner).take(self.skip), &mut std::io::sink())?;
            if skipped < self.skip {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.skip = 0;
        }
        self.inner.read(buf)
    }
}

/// Why `segs` cannot take an object, re-checked under [`NAMESPACE`] before the tag is
/// written: a top-level name or a directory is 405, a foreign tag there or any tag above
/// it 409. `None` when the `PUT` may proceed.
fn put_refusal(store: &Store, segs: &[String], href: &str) -> Result<Option<Response<Body>>> {
    if object_of(segs).is_none() {
        return Ok(Some(not_an_object(href)));
    }
    Ok(match resolve(store, segs)? {
        Some(Node::Dir(_)) => Some(not_an_object(href)),
        Some(Node::Foreign(_)) => Some(parent_is_object(href)),
        _ if under_object(store, segs)? => Some(parent_is_object(href)),
        _ => None,
    })
}

/// Stream and hash the body in staging. Verify the SHA-256 if `expected` is supplied, then
/// publish the blob, raw-file manifest and tag. Return 201 on creation or 204 on replacement.
/// Drain refused uploads so `sccache` sees the response. A connection reset during its startup
/// probe marks the store unwritable. Return 413 as soon as the declared or streamed size
/// exceeds the cap.
pub(crate) async fn put(
    state: &ServerState,
    segs: Vec<String>,
    trailing_slash: bool,
    href: &str,
    expected: Option<String>,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    // Streaming checks also cover chunked bodies.
    if declared_over_cap(&req) {
        return Ok(too_big(href));
    }
    // A path ending in a slash names a directory, which takes no object.
    if trailing_slash {
        return drain_then(req, not_an_object(href), href).await;
    }
    // Refused before the body is staged when the answer is already known; checked again
    // once it is, under the namespace lock.
    let early = {
        let (store, segs, href) = (Arc::clone(&state.store), segs.clone(), href.to_string());
        tokio::task::spawn_blocking(move || put_refusal(&store, &segs, &href))
            .await
            .context("checking a PUT panicked")??
    };
    if let Some(resp) = early {
        return drain_then(req, resp, href).await;
    }

    // Stream uploads to bound memory use; the digest falls out of the same pass.
    let (path, file) = state.store.stage_file()?;
    let staging = Staging::new(path);
    let mut file = tokio::fs::File::from_std(file);
    let written = drain_into(&mut file, req.into_body(), MAX_OBJECT).await;
    let flushed = file
        .flush()
        .await
        .map_err(|e| DrainError::Failed(anyhow::Error::from(e).context("writing an object")));
    drop(file);
    let (size, hex) = match written.and_then(|w| flushed.map(|()| w)) {
        Ok(w) => w,
        Err(DrainError::OverCap) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                href,
            ));
        }
        Err(DrainError::Failed(e)) => return Err(e),
    };
    if expected.is_some_and(|e| e != hex) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "the body does not match its x-amz-content-sha256",
        ));
    }

    // Off the runtime: staging compresses, and a large object would otherwise block a tokio
    // worker for seconds. The locks are taken inside, after that pass — the store lock as
    // the relay takes it.
    let store = Arc::clone(&state.store);
    let href = href.to_string();
    let waiter = store.lock_waiter().await?;
    tokio::task::spawn_blocking(move || -> Result<Response<Body>> {
        let _waiter = waiter;
        let mut staging = staging;
        let staged = store.stage_promotion(&hex, staging.path())?;
        let _namespace = namespace(&store)?;
        // Hold the shared store lock through promotion and manifest publication to exclude
        // exclusive GC work (see Store::lock_shared). Recheck the path because another
        // write may have changed it during streaming.
        let checked = store.lock_shared().and_then(|lock| {
            let existed = matches!(resolve(&store, &segs)?, Some(Node::Object(_)));
            Ok((lock, put_refusal(&store, &segs, &href)?, existed))
        });
        let (_lock, existed) = match checked {
            Ok((lock, None, existed)) => (lock, existed),
            Ok((_, Some(resp), _)) => {
                staged.discard();
                return Ok(resp);
            }
            Err(e) => {
                staged.discard();
                return Err(e);
            }
        };
        store.promote_staged(&hex, staged)?;
        staging.disarm();
        let (repo, tag) = object_of(&segs).context("a PUT past its checks names an object")?;
        store.put_raw_file(&repo, tag, &hex, size, None)?;
        Ok(if existed { no_content() } else { created() })
    })
    .await
    .context("the object's promotion panicked")?
}

/// Check and remove the tag under [`NAMESPACE`]. Return 204 on deletion. Other names
/// retain their references to the bytes, which remain subject to gc. Return 404 for a
/// missing or unreadable node, 403 for a readable node without write access, and 409
/// for a directory or a tag that does not name a raw file.
pub(crate) fn delete(
    store: &Store,
    authz: &Authz<'_>,
    segs: &[String],
    trailing_slash: bool,
    href: &str,
) -> Result<Response<Body>> {
    let _namespace = namespace(store)?;
    let Some(node) = resolve_for(store, authz, accounts::Action::Read, segs, trailing_slash)?
    else {
        return Ok(not_found(href));
    };
    if !allowed(authz, accounts::Action::Write, node.repo()) {
        return Ok(accounts::forbidden());
    }
    Ok(match node {
        Node::Object(obj) if store.delete_tag(&obj.repo, &obj.tag)? => no_content(),
        Node::Object(_) => not_found(href),
        Node::Foreign(_) => parent_is_object(href),
        Node::Dir(_) => {
            error_response(StatusCode::CONFLICT, "DENIED", "a directory is not deleted")
        }
    })
}

/// Read a request's body through and discard it: a status sent with request bytes unread
/// resets the connection. `Some(413)` if the body declares a length over the object cap,
/// unread, or crosses the cap on the way.
pub(crate) async fn drain(req: Request<Incoming>, href: &str) -> Result<Option<Response<Body>>> {
    if declared_over_cap(&req) {
        return Ok(Some(too_big(href)));
    }
    match drain_into(&mut tokio::io::sink(), req.into_body(), MAX_OBJECT).await {
        Ok(_) => Ok(None),
        Err(DrainError::OverCap) => Ok(Some(too_big(href))),
        Err(DrainError::Failed(e)) => Err(e),
    }
}

/// Whether `Content-Length` declares a body over the object cap.
fn declared_over_cap(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_OBJECT)
}

fn too_big(href: &str) -> Response<Body> {
    error_response(StatusCode::PAYLOAD_TOO_LARGE, "TOOBIG", href)
}

/// Drain the body before sending `refusal` so a connection reset cannot hide the response.
/// [`drain`] takes precedence if the body exceeds the cap (413).
pub(crate) async fn drain_then(
    req: Request<Incoming>,
    refusal: Response<Body>,
    href: &str,
) -> Result<Response<Body>> {
    Ok(drain(req, href).await?.unwrap_or(refusal))
}

/// 409 for a write below an object, or onto a tag this view does not serve: its parent is
/// not a directory, or the resource is not a plain file.
fn parent_is_object(href: &str) -> Response<Body> {
    error_response(StatusCode::CONFLICT, "DENIED", href)
}

/// 405 for a write onto a directory, or onto a top-level name, which is always one.
fn not_an_object(href: &str) -> Response<Body> {
    error_response(StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED", href)
}

fn not_found(href: &str) -> Response<Body> {
    error_response(StatusCode::NOT_FOUND, "NOT_FOUND", href)
}

fn created() -> Response<Body> {
    Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_LENGTH, "0")
        .body(crate::body_of(bytes::Bytes::new()))
        .expect("building a 201")
}

fn no_content() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(crate::body_of(bytes::Bytes::new()))
        .expect("building a 204")
}

/// Format an RFC 1123 HTTP date. `httpdate` panics outside 1970 to 9999, so a time outside
/// that range is clamped into it.
fn http_date(t: SystemTime) -> String {
    const LAST: Duration = Duration::from_secs(253_402_300_799);
    let since = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    httpdate::fmt_http_date(SystemTime::UNIX_EPOCH + since.min(LAST))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test valid paths and rejection of unsafe components.
    #[test]
    fn the_path_splitter_refuses_everything_but_a_plain_relative_path() {
        let segs = |p: &str| split(p).map(|(s, _)| s);
        let v = |s: &[&str]| Some(s.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // the root
        assert_eq!(split(""), Some((vec![], true)));
        // `sccache`'s own two shapes: the startup probe, and a sharded key
        assert_eq!(
            segs("sccache/.sccache_check"),
            v(&["sccache", ".sccache_check"])
        );
        assert_eq!(
            segs("sccache/a/b/c/abcdef"),
            v(&["sccache", "a", "b", "c", "abcdef"])
        );
        // a directory, with and without a trailing slash, which is reported
        assert_eq!(split("sccache"), Some((v(&["sccache"]).unwrap(), false)));
        assert_eq!(split("sccache/"), Some((v(&["sccache"]).unwrap(), true)));
        // percent-decoding is per component and a path's own: `%2D` is `-`, `+` is itself
        assert_eq!(segs("x/a%2Db"), v(&["x", "a-b"]));
        assert_eq!(segs("x/a+b"), v(&["x", "a+b"]));
        assert_eq!(segs("x/%C3%A9"), v(&["x", "\u{e9}"]));

        for bad in [
            // traversal, encoded and not
            "sccache/..",
            "sccache/../../etc/passwd",
            "sccache/a/../../b",
            "sccache/%2E%2E/x",
            "..",
            // a leading slash is an empty first component
            "/sccache/x",
            // a decoded separator is a name that would become a path
            "sccache/a%2Fb",
            "sccache/a%2f%2e%2e%2fb",
            "sccache/a%5Cb",
            // control bytes, NUL included
            "sccache/a%00b",
            "sccache/a%0Ab",
            // empty components
            "sccache//x",
            "sccache/x//y",
            "sccache//",
            "/",
            "//",
            // malformed escapes and bytes that are not UTF-8
            "sccache/a%2",
            "sccache/a%G0",
            "sccache/%FF",
            "sccache/%C3",
        ] {
            assert!(split(bad).is_none(), "accepted {bad:?}");
        }

        // over-long
        let long = "x".repeat(MAX_SEGMENT + 1);
        assert!(split(&long).is_none());
        assert!(split(&"x".repeat(MAX_SEGMENT)).is_some());
    }

    /// A served name is a repository name below `files/`, leaf included, so the store's
    /// layout names and depth bound hold for it.
    #[test]
    fn plain_file_names_are_repository_names() {
        assert!(valid_plain_file("sccache/.sccache_check"));
        assert!(valid_plain_file("repo.git/HEAD"));
        for bad in ["a/tags", "a/blobs/x", "a/b c", "a/../b", "a//b", "a/"] {
            assert!(!valid_plain_file(bad), "{bad}");
        }
        let deepest = vec!["x"; crate::MAX_NAME_SEGMENTS - 1].join("/");
        assert!(valid_plain_file(&deepest));
        assert!(!valid_plain_file(&format!("{deepest}/x")));
    }

    /// Clamp a single range to the last byte. An unsatisfiable range selects no bytes.
    /// An ignored range gets the whole object.
    #[test]
    fn a_range_asks_for_one_part_or_the_whole() {
        assert_eq!(part("bytes=0-0", 10), Part::Bytes(0, 0));
        assert_eq!(part("bytes=2-5", 10), Part::Bytes(2, 5));
        assert_eq!(part("bytes=2-", 10), Part::Bytes(2, 9));
        assert_eq!(part("bytes=8-100", 10), Part::Bytes(8, 9));
        assert_eq!(part("bytes=-3", 10), Part::Bytes(7, 9));
        assert_eq!(part("bytes=-30", 10), Part::Bytes(0, 9));
        assert_eq!(part(" bytes= 1 - 2 ", 10), Part::Bytes(1, 2));
        for unsatisfiable in ["bytes=10-", "bytes=10-20", "bytes=-0"] {
            assert_eq!(
                part(unsatisfiable, 10),
                Part::Unsatisfiable,
                "{unsatisfiable}"
            );
        }
        assert_eq!(part("bytes=0-", 0), Part::Unsatisfiable);
        assert_eq!(part("bytes=-1", 0), Part::Unsatisfiable);
        for whole in [
            "bytes=5-2",
            "bytes=0-1,3-4",
            "bytes=-",
            "bytes=a-b",
            "bytes=+1-2",
            "items=0-1",
            "bytes 0-1",
            "bytes=99999999999999999999-",
        ] {
            assert_eq!(part(whole, 10), Part::Whole, "{whole}");
        }
    }

    /// The part starts after the skipped prefix. EOF inside the prefix is an error.
    #[test]
    fn skipping_drops_the_bytes_before_a_part() {
        use std::io::Read;
        let mut out = String::new();
        Skip::new(&b"0123456789"[..], 4)
            .take(3)
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "456");
        let mut short = Skip::new(&b"01"[..], 4);
        assert!(short.read(&mut [0; 4]).is_err());
    }

    /// The leaf follows tag rules. The parent follows repository name and depth limits.
    #[test]
    fn file_names_are_a_repository_and_a_tag() {
        let v = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(valid_file(&v(&["media", "tags"])));
        assert!(valid_file(&v(&["repo.git", "HEAD"])));
        assert!(valid_file(&v(&["media"])));
        let deepest = vec!["x"; crate::MAX_NAME_SEGMENTS];
        assert!(valid_file(&v(&deepest)));
        let deeper = vec!["x"; crate::MAX_NAME_SEGMENTS + 1];
        assert!(!valid_file(&v(&deeper)));
        for bad in [
            &["a b", "x"][..],
            &["tags", "x"],
            &["a", "x y"],
            &["a", ".."],
            &[],
        ] {
            assert!(!valid_file(&v(bad)), "{bad:?}");
        }
        // An S3 leaf may use the full component length.
        assert!(valid_file(&v(&["a", &"t".repeat(MAX_SEGMENT)])));
        assert!(!valid_file(&v(&["a", &"t".repeat(MAX_SEGMENT + 1)])));
    }

    /// HTTP dates are IMF-fixdate, and a time `httpdate` cannot format is clamped rather
    /// than failing a response.
    #[test]
    fn http_dates_are_rfc_1123_and_clamped() {
        let at = |secs| http_date(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(784_887_151), "Tue, 15 Nov 1994 08:12:31 GMT");
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(http_date(before), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            at(u64::from(u32::MAX) * 1000),
            "Fri, 31 Dec 9999 23:59:59 GMT"
        );
    }

    /// The namespace held here is held against another process's open of the store: the
    /// lock file another descriptor cannot take until it is released.
    #[test]
    fn the_namespace_is_held_against_other_processes() {
        use std::os::fd::AsRawFd;
        let dir = std::env::temp_dir().join(format!("vk-reg-files-ns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        // Release the probe's lock on return even if another test's child inherited the descriptor.
        let try_lock = || {
            let file = vk_fs::LockFile::new(std::fs::File::open(dir.join(".files.lock")).unwrap());
            // SAFETY: flock on a descriptor `file` owns.
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
        };
        let held = namespace(&store).unwrap();
        assert!(!try_lock());
        drop(held);
        assert!(try_lock());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn paths_map_onto_repositories_and_tags() {
        let segs = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(repo_name(&segs(&[])), "files");
        assert_eq!(
            repo_name(&segs(&["sccache", "a", "b"])),
            "files/sccache/a/b"
        );
        assert!(
            object_of(&segs(&["sccache"])).is_none(),
            "a top-level name is a directory"
        );
        let key = segs(&["sccache", "a", "b", "abcdef"]);
        let (repo, tag) = object_of(&key).unwrap();
        assert_eq!((repo.as_str(), tag), ("files/sccache/a/b", "abcdef"));
    }
}
