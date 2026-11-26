//! `/s3/` and `/dav/files/` serve named plain files from the OCI pool. An object at
//! `<dir…>/<leaf>` is the tag `<leaf>` in `files/<dir…>`. Its single-layer raw-file
//! manifest points to the file bytes, the same format used by `/upload` and `PUT /files/`.
//! Grants apply to the repository, so `files/<dir>/*` covers the tree. GC applies tag
//! retention and blob grace windows.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, LAST_MODIFIED};
use hyper::{Request, Response, StatusCode};
use tokio::io::AsyncWriteExt;

use crate::staging::{DrainError, Staging, drain_into};
use crate::{Authz, Body, ServerState, Store, accounts, error_response};

/// The repository every object lives under.
pub(crate) const FILES_REPO: &str = "files";

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
pub(crate) struct Namespace {
    _process: std::sync::MutexGuard<'static, ()>,
    _store: crate::LockGuard,
}

/// Hold [`NAMESPACE`], then the store's namespace lock. Accept a poisoned mutex: it guards
/// no data that a panic could leave inconsistent.
pub(crate) fn namespace(store: &Store) -> Result<Namespace> {
    let process = NAMESPACE.lock().unwrap_or_else(PoisonError::into_inner);
    Ok(Namespace {
        _process: process,
        _store: store.lock_namespace()?,
    })
}

/// What an object path names once the store has been looked at.
pub(crate) enum Node {
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
pub(crate) struct Object {
    pub(crate) repo: String,
    pub(crate) tag: String,
    /// the layer blob's hex
    pub(crate) layer: String,
    /// the layer's canonical length
    pub(crate) size: u64,
    /// the tag's mtime
    pub(crate) modified: SystemTime,
}

impl Node {
    /// The repository this node authorizes as.
    pub(crate) fn repo(&self) -> &str {
        match self {
            Node::Dir(r) | Node::Foreign(r) => r,
            Node::Object(o) => &o.repo,
        }
    }
}

/// Split the path below a view's root before percent-decoding. Return the decoded components
/// and trailing-slash flag. Both the empty path and `/` return no components and a true flag.
/// Reject decoded separators, control characters, `.`, `..`, empty or oversized components,
/// malformed escapes and invalid UTF-8.
pub(crate) fn split(rest: &str) -> Option<(Vec<String>, bool)> {
    // `//` contains an empty component.
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Some((Vec::new(), true));
    }
    let (rest, collection) = match rest.strip_suffix('/') {
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
    Some((segments, collection))
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

/// The repository a run of path components names: `files/<segs…>`.
pub(crate) fn repo_name(segs: &[String]) -> String {
    let mut name = String::from(FILES_REPO);
    for s in segs {
        name.push('/');
        name.push_str(s);
    }
    name
}

/// The repository and tag an object at `segs` would have: the last component is the tag.
pub(crate) fn object_of(segs: &[String]) -> Option<(String, &str)> {
    let (leaf, parents) = segs.split_last()?;
    (!parents.is_empty()).then(|| (repo_name(parents), leaf.as_str()))
}

/// What is at `segs`: a directory, an object, a foreign tag, or nothing. A directory is any
/// path under `repos/files/` that is one — a repository, or the parent a nested repository's
/// name created — so the tree reads as the client wrote it.
pub(crate) fn resolve(store: &Store, segs: &[String]) -> Result<Option<Node>> {
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
        Some((layer, size)) => Node::Object(Object {
            repo,
            tag: tag.to_string(),
            layer,
            size,
            modified,
        }),
        None => Node::Foreign(repo),
    }))
}

/// Writing below a tag would create a directory that hides the tag in [`resolve`].
/// Top-level names are reserved for directories.
pub(crate) fn under_object(store: &Store, segs: &[String]) -> Result<bool> {
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
pub(crate) fn allowed(authz: &Authz<'_>, action: accounts::Action, repo: &str) -> bool {
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
pub(crate) fn resolve_for(
    store: &Store,
    authz: &Authz<'_>,
    action: accounts::Action,
    segs: &[String],
    collection: bool,
) -> Result<Option<Node>> {
    Ok(resolve(store, segs)?.filter(|node| {
        !(collection && !matches!(node, Node::Dir(_))) && allowed(authz, action, node.repo())
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

/// Serve `GET` and `HEAD` through the `/v2/` blob handler after checking read access.
/// A range request receives the full 200 response.
pub(crate) fn get(
    authz: &Authz<'_>,
    store: &Store,
    segs: &[String],
    collection: bool,
    href: &str,
    head: bool,
) -> Result<Response<Body>> {
    // A directory has no body to serve.
    let Some(Node::Object(obj)) =
        resolve_for(store, authz, accounts::Action::Read, segs, collection)?
    else {
        return Ok(not_found(href));
    };
    // `PUT` records the layer in this repository. A scoped caller can also read it
    // through another repository that holds it and that the caller may read.
    if !crate::readable_through(authz, store, &obj.repo, &obj.layer) {
        return Ok(not_found(href));
    }
    // An existence probe (`HEAD`) refreshes neither the tag nor the layer blob.
    let mut resp = crate::serve_blob(store, &format!("sha256:{}", obj.layer), head, None, false)?;
    if resp.status() == StatusCode::OK {
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
        if let Ok(v) = hyper::header::HeaderValue::from_str(&http_date(obj.modified)) {
            headers.insert(LAST_MODIFIED, v);
        }
    }
    Ok(resp)
}

/// Why `segs` cannot take an object, re-checked under [`NAMESPACE`] before the tag is
/// written: a top-level name or a directory is 405, a foreign tag there or any tag above
/// it 409. `None` when the `PUT` may proceed.
pub(crate) fn put_refusal(
    store: &Store,
    segs: &[String],
    href: &str,
) -> Result<Option<Response<Body>>> {
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
    collection: bool,
    href: &str,
    expected: Option<String>,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    // Streaming checks also cover chunked bodies.
    if declared_over_cap(&req) {
        return Ok(too_big(href));
    }
    // A path ending in a slash names a directory, which takes no object.
    if collection {
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
pub(crate) fn parent_is_object(href: &str) -> Response<Body> {
    error_response(StatusCode::CONFLICT, "DENIED", href)
}

/// 405 for a write onto a directory, or onto a top-level name, which is always one.
fn not_an_object(href: &str) -> Response<Body> {
    error_response(StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED", href)
}

pub(crate) fn not_found(href: &str) -> Response<Body> {
    error_response(StatusCode::NOT_FOUND, "NOT_FOUND", href)
}

pub(crate) fn created() -> Response<Body> {
    Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_LENGTH, "0")
        .body(crate::body_of(bytes::Bytes::new()))
        .expect("building a 201")
}

pub(crate) fn no_content() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(crate::body_of(bytes::Bytes::new()))
        .expect("building a 204")
}

/// Format an RFC 1123 HTTP date. `httpdate` panics outside 1970 to 9999, so a time outside
/// that range is clamped into it.
pub(crate) fn http_date(t: SystemTime) -> String {
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
        // the root, both spellings
        assert_eq!(split(""), Some((vec![], true)));
        assert_eq!(split("/"), Some((vec![], true)));
        // `sccache`'s own two shapes: the startup probe, and a sharded key
        assert_eq!(
            segs("/sccache/.sccache_check"),
            v(&["sccache", ".sccache_check"])
        );
        assert_eq!(
            segs("/sccache/a/b/c/abcdef"),
            v(&["sccache", "a", "b", "c", "abcdef"])
        );
        // a directory, with and without a trailing slash, which is reported
        assert_eq!(split("/sccache"), Some((v(&["sccache"]).unwrap(), false)));
        assert_eq!(split("/sccache/"), Some((v(&["sccache"]).unwrap(), true)));
        // percent-decoding is per component and a path's own: `%2D` is `-`, `+` is itself
        assert_eq!(segs("/x/a%2Db"), v(&["x", "a-b"]));
        assert_eq!(segs("/x/a+b"), v(&["x", "a+b"]));
        assert_eq!(segs("/x/%C3%A9"), v(&["x", "\u{e9}"]));

        for bad in [
            // traversal, encoded and not
            "/sccache/..",
            "/sccache/../../etc/passwd",
            "/sccache/a/../../b",
            "/sccache/%2E%2E/x",
            "/..",
            // a decoded separator is a name that would become a path
            "/sccache/a%2Fb",
            "/sccache/a%2f%2e%2e%2fb",
            "/sccache/a%5Cb",
            // control bytes, NUL included
            "/sccache/a%00b",
            "/sccache/a%0Ab",
            // empty components
            "/sccache//x",
            "/sccache/x//y",
            "/sccache//",
            "//",
            // malformed escapes and bytes that are not UTF-8
            "/sccache/a%2",
            "/sccache/a%G0",
            "/sccache/%FF",
            "/sccache/%C3",
        ] {
            assert!(split(bad).is_none(), "accepted {bad:?}");
        }

        // over-long
        let long = "x".repeat(MAX_SEGMENT + 1);
        assert!(split(&format!("/{long}")).is_none());
        assert!(split(&format!("/{}", "x".repeat(MAX_SEGMENT))).is_some());
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
