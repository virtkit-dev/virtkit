//! WebDAV serves the named objects in [`crate::objects`] under `/dav/files/<dir>/`.
//! Directories map to repositories under `files/`. `MKCOL` creates an empty repository.
//! `DELETE` removes a tag or an empty repository.

use std::time::Duration;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::ALLOW;
use hyper::{Request, Response, StatusCode};

use super::{
    ALLOWED_FILES, ALLOWED_READ, Depth, Entry, blocking, blocking_locked, created, href,
    method_not_allowed, multistatus, no_content, not_found, options, propfind_depth, refuse,
};
use crate::objects::{
    FILES_REPO, Node, Object, allowed, namespace, parent_is_object, repo_name, resolve,
    resolve_for, under_object, valid_plain_file,
};
use crate::{Authz, Body, RepoRemoval, ServerState, Store, accounts, error_response, objects};

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
    if !valid_plain_file(&segs.join("/")) {
        let resp = error_response(StatusCode::BAD_REQUEST, "NAME_INVALID", &this);
        return refuse(req, resp, &this).await;
    }
    let action = match method {
        "OPTIONS" => return Ok(options(ALLOWED_FILES)),
        "GET" | "HEAD" | "PROPFIND" => accounts::Action::Read,
        "PUT" | "MKCOL" | "DELETE" => accounts::Action::Write,
        _ => return refuse(req, method_not_allowed(&this, ALLOWED_FILES), &this).await,
    };
    // `MKCOL` needs write access to the repository it creates.
    let admitted = match method {
        "MKCOL" => allowed(authz, action, &repo_name(segs)),
        _ => objects::admits(authz, action, segs, method == "PUT"),
    };
    if !admitted {
        return refuse(req, accounts::forbidden(), &this).await;
    }
    let segs = segs.to_vec();
    match method {
        "PUT" => {
            let mut resp = objects::put(state, segs, collection, &this, None, req).await?;
            if resp.status() == StatusCode::METHOD_NOT_ALLOWED {
                resp.headers_mut().insert(
                    ALLOW,
                    hyper::header::HeaderValue::from_static(ALLOWED_FILES),
                );
            }
            Ok(resp)
        }
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
            blocking_locked(state, authz, move |store, _| mkcol(store, &segs, &this)).await
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
            if let Some(resp) = objects::drain(req, &this).await? {
                return Ok(resp);
            }
            blocking_locked(state, authz, move |store, authz| {
                delete(store, authz, &segs, collection, &this)
            })
            .await
        }
        // GET and HEAD.
        _ => {
            let head = method == "HEAD";
            blocking(state, authz, move |store, authz| {
                objects::get(
                    authz,
                    store,
                    &segs,
                    collection,
                    &this,
                    objects::Read {
                        head,
                        ..Default::default()
                    },
                )
                .map(|mut resp| {
                    // WebDAV reads ignore `Range`: advertise none.
                    resp.headers_mut().remove(hyper::header::ACCEPT_RANGES);
                    resp
                })
            })
            .await
        }
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
/// Create a directory — an empty repository — and its missing ancestors: 201, 405 when the
/// path is already mapped (a directory or a tag), or 409 when a tag is above it. Checked and
/// created under [`namespace`].
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
/// A directory's removal needs the store lock exclusive. It is tried under [`namespace`],
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
