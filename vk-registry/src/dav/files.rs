//! The WebDAV view of the plain-file area, under `/dav/files/<dir>/`, over the object layer in
//! [`crate::files`]: this module maps WebDAV verbs, statuses and bodies onto it. `PUT` stages
//! and commits an object; `MKCOL` creates an empty repository; `DELETE` removes a tag or an
//! empty repository. Authorization uses the resource's repository, so `files/<dir>/*` covers
//! a whole tree.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, LAST_MODIFIED};
use hyper::{Request, Response, StatusCode};

use super::{
    ALLOWED_FILES, ALLOWED_READ, Depth, Entry, blocking, created, href, http_date,
    method_not_allowed, multistatus, no_content, not_found, options, propfind_depth, refuse,
};
use crate::files::{
    FILES_REPO, MAX_OBJECT, Node, Object, PutError, Unwritable, Written, allowed, drain_into,
    namespace, object_of, repo_name, resolve, under_object,
};
use crate::{Authz, Body, RepoRemoval, ServerState, Store, accounts, error_response};

/// What every object is served as, matching `/v2/` blobs.
const OBJECT_TYPE: &str = "application/octet-stream";

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
        if !head {
            crate::files::touch_if_idle(store, &obj);
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

/// The answer to a `PUT` at a path that takes no object: a top-level name or a directory is
/// 405, a foreign tag there or any tag above it 409.
fn put_refusal(why: Unwritable, href: &str) -> Response<Body> {
    match why {
        Unwritable::TopLevel | Unwritable::Directory => method_not_allowed(href, ALLOWED_FILES),
        Unwritable::Foreign | Unwritable::UnderObject => parent_is_object(href),
    }
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
        let (store, segs) = (Arc::clone(&state.store), segs.clone());
        tokio::task::spawn_blocking(move || crate::files::unwritable(&store, &segs))
            .await
            .context("checking a PUT panicked")??
    };
    if let Some(why) = early {
        return refuse(req, put_refusal(why, href), href).await;
    }

    // Stream uploads to bound memory use; the digest falls out of the same pass.
    let staged = match crate::files::stage(&state.store, req.into_body(), &mut |_| {}).await {
        Ok(staged) => staged,
        Err(PutError::TooLarge) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                href,
            ));
        }
        Err(PutError::Failed(e)) => return Err(e),
    };
    Ok(
        match crate::files::commit(Arc::clone(&state.store), segs, staged, Default::default())
            .await?
        {
            Written::Created => created(),
            Written::Replaced => no_content(),
            Written::Refused(why) => put_refusal(why, href),
            // Unreachable: no precondition was asked for.
            Written::PreconditionFailed => no_content(),
        },
    )
}

/// Read a request's body through and discard it: a status sent with request bytes unread
/// resets the connection. `Some(413)` if the body crosses the object cap on the way.
pub(super) async fn drain(req: Request<Incoming>, href: &str) -> Result<Option<Response<Body>>> {
    match drain_into(
        &mut tokio::io::sink(),
        req.into_body(),
        MAX_OBJECT,
        &mut |_| {},
    )
    .await
    {
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

/// Create a directory — an empty repository — and its missing ancestors: 201, 405 when the
/// path is already mapped (a directory or a tag), or 409 when a tag is above it. Checked and
/// created under the [`namespace`] lock.
fn mkcol(store: &Store, segs: &[String], href: &str) -> Result<Response<Body>> {
    let _namespace = namespace(store)?;
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
/// A directory's removal needs the store lock exclusive. It is tried under the
/// [`namespace`] lock, which is released between attempts so other `files/` writes proceed;
/// past [`DELETE_LOCK_WAIT`] of shared holders or a gc, the answer is 503.
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
        let namespace = namespace(store)?;
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
