//! Plain files under `/dav/files/<dir>/` share the OCI pool. Directories map to repositories
//! under `files/`; each leaf is a tag on a single-layer raw-file manifest, as written by
//! `/upload`, whose layer holds the file bytes. `PUT` streams to `uploads/` while hashing,
//! promotes the blob, then writes the manifest and tag. `MKCOL` creates an empty repository;
//! `DELETE` removes a tag or an empty repository. Authorization uses the resource's repository,
//! so `files/<dir>/*` covers a whole tree. Entries expire under gc's tag retention and blob
//! grace windows.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, LAST_MODIFIED};
use hyper::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{
    ALLOWED_FILES, ALLOWED_READ, Depth, Entry, blocking, created, href, http_date,
    method_not_allowed, multistatus, no_content, not_found, options, propfind_depth, refuse,
};
use crate::{Authz, Body, RepoRemoval, STREAM_CHUNK, ServerState, Store, accounts, error_response};

/// The repository every `/dav/files/` path lives under.
pub(super) const FILES_REPO: &str = "files";

/// Maximum object size, checked both against Content-Length and while streaming.
const MAX_OBJECT: u64 = 4 << 30;

/// What every object is served as, matching `/v2/` blobs.
const OBJECT_TYPE: &str = "application/octet-stream";

/// Minimum idle age before a `GET` refreshes the tag's mtime — the "last used" record the
/// gc's retention keys on — so a cache read is a metadata write at most once an hour.
const TOUCH_AFTER: Duration = Duration::from_secs(3600);

/// Serialize `files/` checks and namespace changes (`PUT` tags, `MKCOL`, `DELETE`) in this
/// server so a `PUT` and `MKCOL` of the same path cannot both succeed. Acquire before the
/// store lock, never while holding it. `/v2/` writes into `files/` do not take this lock.
static NAMESPACE: Mutex<()> = Mutex::new(());

/// Hold [`NAMESPACE`]. It guards no data, so a holder that panicked left nothing
/// inconsistent behind and a poisoned lock is taken as it is.
fn namespace() -> std::sync::MutexGuard<'static, ()> {
    NAMESPACE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a `files/` path names once the store has been looked at.
enum Node {
    /// A repository under `files/`, or a path component above one: a directory.
    Dir(String),
    /// A tag on a raw-file manifest: an object.
    Object(Object),
    /// A tag on any other manifest — an image pushed over `/v2/` into a `files/`
    /// repository. Absent to reads; a write there is 409, so nothing here replaces or
    /// deletes it.
    Foreign(String),
}

/// An object's tag and what its manifest says about the layer.
struct Object {
    repo: String,
    tag: String,
    /// the layer blob's hex
    layer: String,
    /// the layer's canonical length
    size: u64,
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

/// Whether an ancestor of `segs` is a tag. Writing below one would make its path a directory
/// too, and [`resolve`] would then find the directory and hide the tag: RFC 4918 wants a 409
/// for a parent that is not a collection. A top-level name is always a directory.
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

/// Serve one `files/` request; `segs` are the decoded components after `/dav/files/`, and
/// `collection` whether the path ended in a slash — which an object's path never does.
pub(super) async fn route(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: &[String],
    collection: bool,
    method: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let mut parts: Vec<&str> = Vec::with_capacity(segs.len() + 1);
    parts.push(FILES_REPO);
    parts.extend(segs.iter().map(String::as_str));
    let this = href(&parts, false);
    if segs.is_empty() {
        return root(state, authz, method, req).await;
    }
    // The path as a repository name is what every component has to pass, the leaf
    // included: the OCI name rules, which also keep `tags`, `manifests` and `blobs` out of it.
    if !crate::valid_name(&repo_name(segs)) {
        let resp = error_response(StatusCode::BAD_REQUEST, "NAME_INVALID", &this);
        return refuse(req, resp, &this).await;
    }
    let action = match method {
        "OPTIONS" => return Ok(options(ALLOWED_FILES)),
        "GET" | "HEAD" | "PROPFIND" => accounts::Action::Read,
        "PUT" | "MKCOL" | "DELETE" => accounts::Action::Write,
        _ => return refuse(req, method_not_allowed(&this, ALLOWED_FILES), &this).await,
    };
    // Authorized on the name the resource has: a `PUT` writes a tag of the parent, a `MKCOL`
    // makes the path's own repository, and the rest act on whichever the path resolves to —
    // for which holding the action on either name admits the lookup, and the resolved one
    // decides.
    let own = repo_name(segs);
    let parent = object_of(segs).map(|(repo, _)| repo);
    let admitted = match method {
        "PUT" => allowed(authz, action, parent.as_deref().unwrap_or(&own)),
        "MKCOL" => allowed(authz, action, &own),
        _ => {
            allowed(authz, action, &own)
                || parent.as_deref().is_some_and(|p| allowed(authz, action, p))
        }
    };
    if !admitted {
        return refuse(req, accounts::forbidden(), &this).await;
    }
    let segs = segs.to_vec();
    match method {
        "PUT" => put(state, segs, collection, &this, req).await,
        "MKCOL" => {
            // RFC 4918 §9.3: a body this server does not understand, which is any.
            if !hyper::body::Body::is_end_stream(req.body()) {
                let resp = error_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "UNSUPPORTED",
                    "MKCOL takes no body",
                );
                return refuse(req, resp, &this).await;
            }
            let this = href(&parts, true);
            blocking(state, authz, move |store, _| mkcol(store, &segs, &this)).await
        }
        "PROPFIND" => {
            let depth = match propfind_depth(req).await {
                Ok(d) => d,
                Err(resp) => return Ok(*resp),
            };
            blocking(state, authz, move |store, authz| {
                propfind(store, authz, &segs, collection, depth)
            })
            .await
        }
        "DELETE" => {
            if let Some(resp) = drain(req, &this).await? {
                return Ok(resp);
            }
            blocking(state, authz, move |store, authz| {
                delete(store, authz, &segs, collection, &this)
            })
            .await
        }
        // GET and HEAD, on the runtime like `/v2/`'s blob reads.
        _ => get(
            authz,
            &state.store,
            &segs,
            collection,
            &this,
            method == "HEAD",
        ),
    }
}

/// `/dav/files/` itself: a collection of the directories this caller may read. Nothing is
/// written at this level — a directory comes into being through `MKCOL` or `PUT` below it.
async fn root(
    state: &ServerState,
    authz: &Authz<'_>,
    method: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let this = href(&[FILES_REPO], true);
    match method {
        "OPTIONS" => Ok(options(ALLOWED_READ)),
        "PROPFIND" => {
            let depth = match propfind_depth(req).await {
                Ok(d) => d,
                Err(resp) => return Ok(*resp),
            };
            if depth == Depth::One && !super::may_enumerate(state) {
                return Ok(super::enumeration_refused());
            }
            blocking(state, authz, move |store, authz| {
                let mut entries = vec![Entry::collection(
                    this,
                    store.repos_path_modified(FILES_REPO),
                )];
                if depth == Depth::One {
                    for name in store.repo_children(FILES_REPO)? {
                        let repo = format!("{FILES_REPO}/{name}");
                        if authz.may_read(&repo) {
                            entries.push(Entry::collection(
                                href(&[FILES_REPO, &name], true),
                                store.repos_path_modified(&repo),
                            ));
                        }
                    }
                }
                Ok(multistatus(&entries))
            })
            .await
        }
        "GET" | "HEAD" => Ok(not_found(&this)),
        _ => refuse(req, method_not_allowed(&this, ALLOWED_READ), &this).await,
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
    collection: bool,
) -> Result<Option<Node>> {
    Ok(resolve(store, segs)?.filter(|node| {
        !(collection && !matches!(node, Node::Dir(_))) && allowed(authz, action, node.repo())
    }))
}

/// `GET`/`HEAD` an object: the layer blob, through the `/v2/` handler, under this
/// repository's membership. `Range` is ignored, a full 200 being a legal answer to it.
fn get(
    authz: &Authz<'_>,
    store: &Store,
    segs: &[String],
    collection: bool,
    href: &str,
    head: bool,
) -> Result<Response<Body>> {
    // A collection has no body to serve: listings are `PROPFIND`'s.
    let Some(Node::Object(obj)) =
        resolve_for(store, authz, accounts::Action::Read, segs, collection)?
    else {
        return Ok(not_found(href));
    };
    // A digest is not an entitlement to its bytes: the blob has to be this repository's,
    // which the `PUT` that stored it recorded.
    if !crate::readable_through(authz, store, &obj.repo, &obj.layer) {
        return Ok(not_found(href));
    }
    // A HEAD is opendal checking that something exists, so it refreshes nothing, the layer
    // blob included.
    let mut resp = crate::serve_blob(store, &format!("sha256:{}", obj.layer), head, false, false)?;
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

/// An object as a `PROPFIND` entry.
fn object_entry(obj: &Object, href: String) -> Entry {
    Entry::file(href, obj.size, OBJECT_TYPE, obj.modified)
}

/// `PROPFIND` a directory or an object; at `Depth: 1` a directory lists its members — the
/// directories below it the caller may read, and its objects. Built in memory: a listing is
/// O(members of that one directory), which for `sccache`'s sharded layout is a few thousand
/// entries at most.
fn propfind(
    store: &Store,
    authz: &Authz<'_>,
    segs: &[String],
    collection: bool,
    depth: Depth,
) -> Result<Response<Body>> {
    let mut parts: Vec<&str> = vec![FILES_REPO];
    parts.extend(segs.iter().map(String::as_str));
    let child = |name: &str, collection: bool| {
        let mut c: Vec<&str> = parts.clone();
        c.push(name);
        href(&c, collection)
    };
    match resolve_for(store, authz, accounts::Action::Read, segs, collection)? {
        None | Some(Node::Foreign(_)) => Ok(not_found(&href(&parts, false))),
        Some(Node::Object(obj)) if crate::readable_through(authz, store, &obj.repo, &obj.layer) => {
            Ok(multistatus(&[object_entry(&obj, href(&parts, false))]))
        }
        Some(Node::Object(_)) => Ok(not_found(&href(&parts, false))),
        Some(Node::Dir(repo)) => {
            let mut entries = vec![Entry::collection(
                href(&parts, true),
                store.repos_path_modified(&repo),
            )];
            if depth == Depth::One {
                for name in store.repo_children(&repo)? {
                    let sub = format!("{repo}/{name}");
                    if authz.may_read(&sub) {
                        entries.push(Entry::collection(
                            child(&name, true),
                            store.repos_path_modified(&sub),
                        ));
                    }
                }
                for tag in store.list_tags(&repo) {
                    let mut path = segs.to_vec();
                    path.push(tag.clone());
                    // Listed only when a `GET` would serve it.
                    if let Some(Node::Object(obj)) = resolve(store, &path)?
                        && crate::readable_through(authz, store, &obj.repo, &obj.layer)
                    {
                        entries.push(object_entry(&obj, child(&tag, false)));
                    }
                }
            }
            Ok(multistatus(&entries))
        }
    }
}

/// Why a streamed `PUT` stopped short.
enum PutError {
    /// the body crossed [`MAX_OBJECT`] — a 413, decided while reading
    TooLarge,
    /// the read or the write failed — a 500
    Failed(anyhow::Error),
}

/// A staging file under `uploads/`, unlinked when dropped unless its bytes were promoted —
/// including when the handler's future is dropped with the connection mid-body.
struct Staging {
    path: PathBuf,
    armed: bool,
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.armed {
            // Gone already (a promotion that renamed it, or a discard) is the goal; any
            // other failure leaves it to the gc's sweep of idle uploads.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Why `segs` cannot take an object, re-checked under [`NAMESPACE`] before the tag is
/// written: a top-level name or a directory is 405, a foreign tag there or any tag above
/// it 409. `None` when the `PUT` may proceed.
fn put_refusal(store: &Store, segs: &[String], href: &str) -> Result<Option<Response<Body>>> {
    if object_of(segs).is_none() {
        return Ok(Some(method_not_allowed(href, ALLOWED_FILES)));
    }
    Ok(match resolve(store, segs)? {
        Some(Node::Dir(_)) => Some(method_not_allowed(href, ALLOWED_FILES)),
        Some(Node::Foreign(_)) => Some(parent_is_object(href)),
        _ if under_object(store, segs)? => Some(parent_is_object(href)),
        _ => None,
    })
}

/// Stream an object into staging, hashing it on the way, then promote the blob and write the
/// raw-file manifest and tag: 201 for a creation, 204 for a replacement. Every refusal but a
/// declared length over the cap reads the body through first: a status sent with request
/// bytes unread resets the connection, which `sccache` takes as an unwritable store.
async fn put(
    state: &ServerState,
    segs: Vec<String>,
    collection: bool,
    href: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    // Reject oversized Content-Length before reading; streaming checks also cover chunked
    // bodies.
    if req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_OBJECT)
    {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "TOOBIG",
            href,
        ));
    }
    // A path ending in a slash names a collection, which takes no object.
    if collection {
        return refuse(req, method_not_allowed(href, ALLOWED_FILES), href).await;
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
        return refuse(req, resp, href).await;
    }

    // Stream uploads to bound memory use; the digest falls out of the same pass.
    let (path, file) = state.store.stage_file()?;
    let staging = Staging { path, armed: true };
    let mut file = tokio::fs::File::from_std(file);
    let written = drain_into(&mut file, req.into_body(), MAX_OBJECT).await;
    let flushed = file
        .flush()
        .await
        .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("writing an object")));
    drop(file);
    let (size, hex) = match written.and_then(|w| flushed.map(|()| w)) {
        Ok(w) => w,
        Err(PutError::TooLarge) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                href,
            ));
        }
        Err(PutError::Failed(e)) => return Err(e),
    };

    // Off the runtime: staging compresses, and a large object would otherwise block a tokio
    // worker for seconds. The locks are taken inside, after that pass — the store lock as
    // the relay takes it.
    let store = Arc::clone(&state.store);
    let href = href.to_string();
    tokio::task::spawn_blocking(move || -> Result<Response<Body>> {
        let mut staging = staging;
        let staged = store.stage_promotion(&hex, &staging.path)?;
        let _namespace = namespace();
        // shared store lock (vs. an exclusive gc) across the promote and the manifest that
        // references it; see Store::lock_shared. A `MKCOL` or another `PUT` may have changed
        // the path while the body streamed, so it is checked again.
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
        staging.armed = false;
        let (repo, tag) = object_of(&segs).context("a PUT past its checks names an object")?;
        store.put_raw_file(&repo, tag, &hex, size, None)?;
        Ok(if existed { no_content() } else { created() })
    })
    .await
    .context("the object's promotion panicked")?
}

/// Read a request's body through and discard it: a status sent with request bytes unread
/// resets the connection. `Some(413)` if the body crosses the object cap on the way.
pub(super) async fn drain(req: Request<Incoming>, href: &str) -> Result<Option<Response<Body>>> {
    match drain_into(&mut tokio::io::sink(), req.into_body(), MAX_OBJECT).await {
        Ok(_) => Ok(None),
        Err(PutError::TooLarge) => Ok(Some(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "TOOBIG",
            href,
        ))),
        Err(PutError::Failed(e)) => Err(e),
    }
}

/// [`drain`] a refused request, then answer `refusal`, or the 413.
pub(super) async fn drain_then(
    req: Request<Incoming>,
    refusal: Response<Body>,
    href: &str,
) -> Result<Response<Body>> {
    Ok(drain(req, href).await?.unwrap_or(refusal))
}

/// 409 for a write below an object, or onto a tag this view does not serve: its parent is
/// not a collection, or the resource is not a plain file.
fn parent_is_object(href: &str) -> Response<Body> {
    error_response(StatusCode::CONFLICT, "DENIED", href)
}

/// Stream `body` to `out`, coalescing small frames and enforcing `cap`, including for chunked
/// bodies; `(bytes written, sha256 hex)` on success. `out` may be a sink when draining a
/// rejected PUT. The generic body allows tests with a small cap.
async fn drain_into<B>(
    out: &mut (impl AsyncWrite + Unpin),
    mut body: B,
    cap: u64,
) -> std::result::Result<(u64, String), PutError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut buf: Vec<u8> = Vec::with_capacity(STREAM_CHUNK);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let io = |e: std::io::Error| PutError::Failed(anyhow::Error::from(e).context("writing"));
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("reading a PUT body")))?;
        // Trailers carry no content; a body that has them simply ends after them.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total = total.saturating_add(data.len() as u64);
        if total > cap {
            return Err(PutError::TooLarge);
        }
        hasher.update(&data);
        // A frame already worth a write goes straight out rather than through the
        // coalescing buffer, which is there for the small ones.
        if buf.is_empty() && data.len() >= STREAM_CHUNK {
            out.write_all(&data).await.map_err(io)?;
            continue;
        }
        buf.extend_from_slice(&data);
        if buf.len() >= STREAM_CHUNK {
            out.write_all(&buf).await.map_err(io)?;
            buf.clear();
        }
    }
    if !buf.is_empty() {
        out.write_all(&buf).await.map_err(io)?;
    }
    Ok((total, crate::hex_of(&hasher.finalize())))
}

/// Create a directory — an empty repository — and its missing ancestors: 201, 405 when the
/// path is already mapped (a directory or a tag), or 409 when a tag is above it. Checked and
/// created under [`NAMESPACE`].
fn mkcol(store: &Store, segs: &[String], href: &str) -> Result<Response<Body>> {
    let _namespace = namespace();
    match resolve(store, segs)? {
        Some(_) => Ok(method_not_allowed(href, ALLOWED_FILES)),
        None if under_object(store, segs)? => Ok(parent_is_object(href)),
        None => {
            store.create_repo(&repo_name(segs))?;
            Ok(created())
        }
    }
}

/// Longest a directory `DELETE` waits for the exclusive store lock before answering 503.
const DELETE_LOCK_WAIT: Duration = Duration::from_secs(30);

/// Delete an object, or a directory with nothing in it (204); 403 for a directory with
/// members or for a caller that may read the resource but not write it, 409 for a directory
/// still holding fresh records a deleted object does not account for (see
/// [`Store::remove_empty_repo`]) or for a foreign tag; 404 when absent or unreadable to the
/// caller. Recursive deletion is unsupported. An object's bytes stay in the pool until the
/// gc finds them unreferenced.
///
/// A directory's removal needs the store lock exclusive. It is tried under [`NAMESPACE`],
/// which is released between attempts so other `files/` writes proceed; past
/// [`DELETE_LOCK_WAIT`] of shared holders or a gc, the answer is 503.
fn delete(
    store: &Store,
    authz: &Authz<'_>,
    segs: &[String],
    collection: bool,
    href: &str,
) -> Result<Response<Body>> {
    let deadline = std::time::Instant::now() + DELETE_LOCK_WAIT;
    let mut backoff = Duration::from_millis(10);
    loop {
        let namespace = namespace();
        let Some(node) = resolve_for(store, authz, accounts::Action::Read, segs, collection)?
        else {
            return Ok(not_found(href));
        };
        if !allowed(authz, accounts::Action::Write, node.repo()) {
            return Ok(accounts::forbidden());
        }
        let removal = match node {
            Node::Object(obj) => {
                return Ok(if store.delete_tag(&obj.repo, &obj.tag)? {
                    no_content()
                } else {
                    not_found(href)
                });
            }
            Node::Foreign(_) => return Ok(parent_is_object(href)),
            Node::Dir(repo) => store.remove_empty_repo(&repo, crate::DEFAULT_GC_GRACE)?,
        };
        let resp = match removal {
            RepoRemoval::Removed => no_content(),
            RepoRemoval::HasMembers => error_response(
                StatusCode::FORBIDDEN,
                "DENIED",
                "a directory with members is not deleted",
            ),
            RepoRemoval::HasRecords => error_response(
                StatusCode::CONFLICT,
                "DENIED",
                "the directory holds content other than deleted files",
            ),
            RepoRemoval::Busy if std::time::Instant::now() >= deadline => error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "UNAVAILABLE",
                "the store stayed locked; retry the DELETE",
            ),
            RepoRemoval::Busy => {
                drop(namespace);
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_millis(500));
                continue;
            }
        };
        return Ok(resp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the streaming size cap with a small limit and multiple frames, and the digest
    /// of what went through.
    #[tokio::test]
    async fn a_body_over_the_cap_stops_being_written() {
        let dir = std::env::temp_dir().join(format!("vk-reg-files-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("staged");

        // Several frames, so the cap is crossed part way through rather than at the first.
        let frames = || {
            let chunks: Vec<std::result::Result<hyper::body::Frame<Bytes>, std::io::Error>> = (0
                ..4)
                .map(|_| Ok(hyper::body::Frame::data(Bytes::from(vec![1u8; 100]))))
                .collect();
            http_body_util::StreamBody::new(futures::stream::iter(chunks))
        };

        let mut file = tokio::fs::File::create(&path).await.unwrap();
        assert!(matches!(
            drain_into(&mut file, frames(), 250).await,
            Err(PutError::TooLarge)
        ));
        drop(file);
        // Refused where the count crossed, so the partial file is bounded by the cap plus
        // the frame that crossed it — never the whole body.
        let staged = std::fs::metadata(&path).unwrap().len();
        assert!(staged <= 300, "wrote {staged} bytes past a 250-byte cap");

        // Exactly at the cap is not over it, and the digest is the body's.
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        let (n, hex) = drain_into(&mut file, frames(), 400).await.ok().unwrap();
        file.flush().await.unwrap();
        drop(file);
        assert_eq!(n, 400);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 400);
        assert_eq!(hex, crate::sha256_hex_raw(&vec![1u8; 400]));

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
