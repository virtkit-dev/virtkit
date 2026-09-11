//! Plain files under `/dav/files/<dir>/`, stored in the OCI pool. A path's directories are a
//! repository under `files/` and its leaf a tag on a single-layer raw-file manifest — the shape
//! `/upload` writes — whose layer is the object's bytes. `PUT` streams to `uploads/`, hashes as
//! it goes, promotes the blob and writes the manifest and tag; `MKCOL` creates an empty
//! repository; `DELETE` drops a tag, or a repository with nothing in it. The whole tree under a
//! top-level directory authorizes as the repository `files/<dir>`. There is no store of its own
//! here: the gc's tag retention and blob grace are what expire an entry.

use std::sync::Arc;
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
    ALLOWED_FILES, ALLOWED_READ, Depth, Entry, created, href, http_date, method_not_allowed,
    multistatus, no_content, not_found, propfind_depth,
};
use crate::{Authz, Body, STREAM_CHUNK, ServerState, Store, accounts, error_response};

/// The repository every `/dav/files/` path lives under.
pub(super) const FILES_REPO: &str = "files";

/// Maximum object size, checked both against Content-Length and while streaming.
const MAX_OBJECT: u64 = 4 << 30;

/// What every object is served as, matching `/v2/` blobs.
const OBJECT_TYPE: &str = "application/octet-stream";

/// Minimum idle age before a `GET` refreshes the tag's mtime — the "last used" record the
/// gc's retention keys on — so a cache read is a metadata write at most once an hour.
const TOUCH_AFTER: Duration = Duration::from_secs(3600);

/// What a `files/` path names once the store has been looked at.
enum Node {
    /// A repository under `files/`: a directory.
    Dir(String),
    /// A tag in a repository under `files/`: `(repository, tag)`, an object.
    Object(String, String),
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

/// What is at `segs`: a directory, an object, or nothing. A directory is any path under
/// `repos/files/` that is one — a repository, or the parent a nested repository's name
/// created — so the tree reads as the client wrote it.
fn resolve(store: &Store, segs: &[String]) -> Option<Node> {
    let dir = repo_name(segs);
    if store.repo_dir_exists(&dir) {
        return Some(Node::Dir(dir));
    }
    let (repo, tag) = object_of(segs)?;
    store
        .tag_target(&repo, tag)
        .map(|_| Node::Object(repo, tag.to_string()))
}

/// Serve one `files/` request; `segs` are the decoded components after `/dav/files/`.
pub(super) async fn route(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: &[String],
    method: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let mut parts: Vec<&str> = Vec::with_capacity(segs.len() + 1);
    parts.push(FILES_REPO);
    parts.extend(segs.iter().map(String::as_str));
    let this = href(&parts, false);
    let action = match method {
        "GET" | "HEAD" | "PROPFIND" => accounts::Action::Read,
        "PUT" | "MKCOL" | "DELETE" => accounts::Action::Write,
        _ => return Ok(method_not_allowed(&this, ALLOWED_FILES)),
    };
    let store = &state.store;
    let Some((dir, _)) = segs.split_first() else {
        return root(state, authz, method, req).await;
    };
    // The path as a repository name is what every component has to pass, the leaf
    // included: the OCI name rules, which also keep `tags`, `manifests` and `blobs` out of it.
    if !crate::valid_name(&repo_name(segs)) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            &this,
        ));
    }
    // The whole tree under a top-level directory authorizes as one repository.
    let repo = format!("{FILES_REPO}/{dir}");
    if let Some(resp) = crate::authorize_or_forbidden(authz, action, &repo) {
        return Ok(resp);
    }
    match method {
        "PUT" => put(store, segs, &this, req).await,
        "MKCOL" => mkcol(store, segs, &href(&parts, true)),
        "PROPFIND" => propfind(store, segs, &parts, req).await,
        "GET" | "HEAD" => match resolve(store, segs) {
            Some(Node::Object(repo, tag)) => {
                get(authz, store, &repo, &tag, &this, method == "HEAD")
            }
            // A collection has no body to serve: listings are `PROPFIND`'s.
            _ => Ok(not_found(&this)),
        },
        "DELETE" => delete(store, segs, &this),
        _ => Ok(method_not_allowed(&this, ALLOWED_FILES)),
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
        "PROPFIND" => {
            let depth = match propfind_depth(req).await {
                Ok(d) => d,
                Err(resp) => return Ok(*resp),
            };
            let store = &state.store;
            let mut entries = vec![Entry::collection(
                this,
                store.repos_path_modified(FILES_REPO),
            )];
            if depth == Depth::One {
                if !super::may_enumerate(state) {
                    return Ok(super::enumeration_refused());
                }
                for name in store.repo_children(FILES_REPO) {
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
        }
        "GET" | "HEAD" => Ok(not_found(&this)),
        _ => Ok(method_not_allowed(&this, ALLOWED_READ)),
    }
}

/// An object's layer and the tag's mtime: `(layer hex, canonical size, modified)`. `None`
/// for a tag that is absent, or whose manifest is not a raw file — an image pushed over
/// `/v2/` into a `files/` repository is not something this view serves.
fn object_meta(store: &Store, repo: &str, tag: &str) -> Result<Option<(String, u64, SystemTime)>> {
    let Some((manifest_hex, modified)) = store.tag_target(repo, tag) else {
        return Ok(None);
    };
    let Some(manifest) = store.get_blob(&manifest_hex)? else {
        return Ok(None);
    };
    Ok(crate::raw_file_layer(&manifest).map(|(hex, size)| (hex, size, modified)))
}

/// `GET`/`HEAD` an object: the layer blob, through the `/v2/` handler, under this
/// repository's membership. `Range` is ignored, a full 200 being a legal answer to it.
fn get(
    authz: &Authz<'_>,
    store: &Store,
    repo: &str,
    tag: &str,
    href: &str,
    head: bool,
) -> Result<Response<Body>> {
    let Some((hex, _, modified)) = object_meta(store, repo, tag)? else {
        return Ok(not_found(href));
    };
    // A digest is not an entitlement to its bytes: the blob has to be this repository's,
    // which the `PUT` that stored it recorded.
    if !crate::readable_through(authz, store, repo, &hex) {
        return Ok(not_found(href));
    }
    // A GET is a use, which is what keeps the tag from the gc's retention; a HEAD is opendal
    // checking that something exists. Refreshed only once idle, so a hot entry is not a
    // metadata write per hit.
    if !head
        && SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|idle| idle > TOUCH_AFTER)
    {
        store.touch_tag(repo, tag);
    }
    let mut resp = crate::get_blob(store, &format!("sha256:{hex}"), head, false)?;
    if resp.status() == StatusCode::OK {
        let headers = resp.headers_mut();
        // Prevent uploaded content from rendering on the `/browse` origin.
        headers.insert(
            CONTENT_DISPOSITION,
            hyper::header::HeaderValue::from_static("attachment"),
        );
        if let Ok(v) = hyper::header::HeaderValue::from_str(&http_date(modified)) {
            headers.insert(LAST_MODIFIED, v);
        }
    }
    Ok(resp)
}

/// An object as a `PROPFIND` entry, or `None` when the tag is not a raw file.
fn object_entry(store: &Store, repo: &str, tag: &str, href: String) -> Result<Option<Entry>> {
    Ok(object_meta(store, repo, tag)?
        .map(|(_, size, modified)| Entry::file(href, size, OBJECT_TYPE, modified)))
}

/// `PROPFIND` a directory or an object; at `Depth: 1` a directory lists its members — the
/// repositories below it and its tags.
async fn propfind(
    store: &Store,
    segs: &[String],
    parts: &[&str],
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let depth = match propfind_depth(req).await {
        Ok(d) => d,
        Err(resp) => return Ok(*resp),
    };
    let child = |name: &str, collection: bool| {
        let mut c: Vec<&str> = parts.to_vec();
        c.push(name);
        href(&c, collection)
    };
    match resolve(store, segs) {
        None => Ok(not_found(&href(parts, false))),
        Some(Node::Object(repo, tag)) => {
            match object_entry(store, &repo, &tag, href(parts, false))? {
                Some(e) => Ok(multistatus(&[e])),
                None => Ok(not_found(&href(parts, false))),
            }
        }
        Some(Node::Dir(repo)) => {
            let mut entries = vec![Entry::collection(
                href(parts, true),
                store.repos_path_modified(&repo),
            )];
            if depth == Depth::One {
                for name in store.repo_children(&repo) {
                    entries.push(Entry::collection(
                        child(&name, true),
                        store.repos_path_modified(&format!("{repo}/{name}")),
                    ));
                }
                for tag in store.list_tags(&repo) {
                    if let Some(e) = object_entry(store, &repo, &tag, child(&tag, false))? {
                        entries.push(e);
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

/// Stream an object into staging, hashing it on the way, then promote the blob and write the
/// raw-file manifest and tag: 201 for a creation, 204 for a replacement. The body is read
/// through before any answer but a declared length over the cap: a status sent with request
/// bytes unread resets the connection, which `sccache` takes as an unwritable store.
async fn put(
    store: &Arc<Store>,
    segs: &[String],
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
    // A top-level name is a directory, and so is anything that already is one: neither
    // takes an object. Drain the body before returning 405.
    let target = match object_of(segs) {
        Some(target) if !store.repo_dir_exists(&repo_name(segs)) => Some(target),
        _ => None,
    };
    let Some((repo, tag)) = target else {
        return match drain_into(&mut tokio::io::sink(), req.into_body(), MAX_OBJECT).await {
            Ok(_) => Ok(method_not_allowed(href, ALLOWED_FILES)),
            Err(PutError::TooLarge) => Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                href,
            )),
            Err(PutError::Failed(e)) => Err(e),
        };
    };
    let existed = store.tag_target(&repo, tag).is_some();

    // Stream uploads to bound memory use; the digest falls out of the same pass.
    let (staging, file) = store.stage_file()?;
    let mut file = tokio::fs::File::from_std(file);
    let written = drain_into(&mut file, req.into_body(), MAX_OBJECT).await;
    let flushed = file
        .flush()
        .await
        .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("writing an object")));
    drop(file);
    let (size, hex) = match written.and_then(|w| flushed.map(|()| w)) {
        Ok(w) => w,
        Err(e) => {
            // Nothing else will ever consume it; gc would, but not for a day.
            let _ = std::fs::remove_file(&staging);
            return match e {
                PutError::TooLarge => Ok(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "TOOBIG",
                    href,
                )),
                PutError::Failed(e) => Err(e),
            };
        }
    };

    // Off the runtime: staging compresses, and a large object would otherwise block a tokio
    // worker for seconds. The store lock is taken inside, after that pass — the same
    // sequence as the relay's.
    let store = Arc::clone(store);
    let tag = tag.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let staged = store.stage_promotion(&hex, &staging)?;
        // shared store lock (vs. an exclusive gc) across the promote and the manifest that
        // references it; see Store::lock_shared.
        let _lock = match store.lock_shared() {
            Ok(lock) => lock,
            Err(e) => {
                staged.discard();
                return Err(e);
            }
        };
        store.promote_staged(&hex, staged)?;
        store.put_raw_file(&repo, &tag, &hex, size, None)?;
        Ok(())
    })
    .await
    .context("the object's promotion panicked")??;
    Ok(if existed { no_content() } else { created() })
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

/// Create a directory — an empty repository — and its missing ancestors: 201, or 405 when a
/// directory is already there, or 409 when an object is.
fn mkcol(store: &Store, segs: &[String], href: &str) -> Result<Response<Body>> {
    match resolve(store, segs) {
        Some(Node::Dir(_)) => Ok(method_not_allowed(href, ALLOWED_FILES)),
        Some(Node::Object(..)) => Ok(error_response(StatusCode::CONFLICT, "DENIED", href)),
        None => {
            store.create_repo(&repo_name(segs))?;
            Ok(created())
        }
    }
}

/// Delete an object, or a directory with nothing in it (204); 403 for a directory with
/// members; 404 when absent. Recursive deletion is unsupported. An object's bytes stay in
/// the pool until the gc finds them unreferenced.
fn delete(store: &Store, segs: &[String], href: &str) -> Result<Response<Body>> {
    match resolve(store, segs) {
        None => Ok(not_found(href)),
        Some(Node::Object(repo, tag)) => {
            if store.delete_tag(&repo, &tag)? {
                Ok(no_content())
            } else {
                Ok(not_found(href))
            }
        }
        Some(Node::Dir(repo)) => {
            if store.remove_empty_repo(&repo)? {
                Ok(no_content())
            } else {
                Ok(error_response(
                    StatusCode::FORBIDDEN,
                    "DENIED",
                    "a directory with members is not deleted",
                ))
            }
        }
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
