//! The service and its buckets: ListBuckets, HeadBucket, GetBucketLocation, CreateBucket,
//! DeleteBucket and the configuration reads [`super::canned`] answers. A bucket is a
//! top-level directory of `files/`, authorized as the repository `files/<bucket>`; one the
//! caller may read nothing in is absent to it, as in the WebDAV view.

use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, HeaderValue, LOCATION, RETRY_AFTER};
use hyper::{Request, Response, StatusCode};

use super::canned::Canned;
use super::xml::scan;
use super::{Ctx, drain, read_small, refuse, sigv4, xml};
use crate::files::{self, DELETE_LOCK_WAIT, FILES_REPO, allowed};
use crate::{Authz, Body, RepoRemoval, ServerState, Store, accounts, body_of};

/// The owner every listing names: the registry, whoever wrote what it holds.
pub(super) const OWNER: &str = "vk-registry";

/// `<Owner>` as S3's listings carry it.
pub(super) fn owner() -> String {
    format!(
        "<Owner>{}{}</Owner>",
        xml::element("ID", OWNER),
        xml::element("DisplayName", OWNER)
    )
}

/// `GET /s3/`: the top-level directories the caller may read. Refused, as `/dav/`'s root
/// listing is, on a server without a credential, where it would list for anyone.
pub(super) async fn list(
    state: &ServerState,
    authz: &Authz<'_>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> anyhow::Result<Response<Body>> {
    if !crate::dav::may_enumerate(state) {
        let resp = ctx.error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "listing the buckets needs a configured credential",
        );
        return refuse(req, resp, ctx).await;
    }
    crate::dav::blocking(state, authz, move |store, authz| {
        let mut buckets = String::new();
        for name in store.repo_children(FILES_REPO)? {
            let repo = format!("{FILES_REPO}/{name}");
            if !authz.may_read(&repo) {
                continue;
            }
            let created = store
                .repos_path_modified(&repo)
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            buckets.push_str(&format!(
                "<Bucket>{}{}</Bucket>",
                xml::element("Name", &name),
                xml::element("CreationDate", &sigv4::format_time(created))
            ));
        }
        Ok(xml::document(
            "ListAllMyBucketsResult",
            &format!("{}<Buckets>{buckets}</Buckets>", owner()),
        ))
    })
    .await
}

/// Whether `bucket` is there for this caller: `Err` with the answer when it is not — 403 when
/// the caller may read nothing in the bucket, 404 `NoSuchBucket` when it may but no such
/// directory exists. A caller that may read only a directory inside the bucket passes, since
/// clients probe the bucket before they list the prefix they were given.
async fn check(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: &str,
    ctx: &Ctx,
) -> anyhow::Result<Option<Response<Body>>> {
    let repo = format!("{FILES_REPO}/{bucket}");
    if !authz.may_read_below(&repo) {
        return Ok(Some(ctx.access_denied()));
    }
    let store = std::sync::Arc::clone(&state.store);
    let exists = tokio::task::spawn_blocking(move || store.repo_dir_exists(&repo)).await?;
    Ok((!exists).then(|| {
        ctx.error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        )
    }))
}

/// `HEAD /s3/<bucket>`.
pub(super) async fn head(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> anyhow::Result<Response<Body>> {
    if let Some(resp) = check(state, authz, &bucket, ctx).await? {
        return refuse(req, resp, ctx).await;
    }
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, "0")
        .body(body_of(bytes::Bytes::new()))?)
}

/// `GET /s3/<bucket>?location`: the region the request was signed for, which is any the
/// client chose; empty when it was not signed.
pub(super) async fn location(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> anyhow::Result<Response<Body>> {
    if let Some(resp) = check(state, authz, &bucket, ctx).await? {
        return refuse(req, resp, ctx).await;
    }
    // The gate parsed this header already; a request it let through without one parsing is
    // one that was not signed.
    let region = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| sigv4::parse_authorization(v).ok())
        .map_or(String::new(), |c| xml::escape(c.region));
    Ok(xml::document("LocationConstraint", &region))
}

/// `GET /s3/<bucket>?<configuration>`: what `canned` says a bucket has, after HeadBucket's
/// checks.
pub(super) async fn configuration(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    canned: Canned,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> anyhow::Result<Response<Body>> {
    if let Some(resp) = check(state, authz, &bucket, ctx).await? {
        return refuse(req, resp, ctx).await;
    }
    refuse(req, canned.answer(ctx), ctx).await
}

/// Longest `CreateBucketConfiguration` body taken: it names a region, which is ignored.
const MAX_CONFIGURATION: usize = 1024;

/// `PUT /s3/<bucket>`: the directory `files/<bucket>`, made as WebDAV's `MKCOL` makes it,
/// under the namespace lock. 200 with its `Location`; 409 `BucketAlreadyOwnedByYou` when it
/// is a directory already, which every bucket's owner is. A `CreateBucketConfiguration` body
/// and `x-amz-acl` are taken and ignored; asking for object lock is `NotImplemented`.
pub(super) async fn create(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> anyhow::Result<Response<Body>> {
    let repo = format!("{FILES_REPO}/{bucket}");
    if !allowed(authz, accounts::Action::Write, &repo) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    if req
        .headers()
        .get("x-amz-bucket-object-lock-enabled")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"true"))
    {
        let resp = ctx.error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "this registry keeps no object lock",
        );
        return refuse(req, resp, ctx).await;
    }
    let malformed = |message| ctx.error(StatusCode::BAD_REQUEST, "MalformedXML", message);
    let too_long = malformed("a CreateBucketConfiguration is at most 1 KiB");
    let body = match read_small(req.into_body(), MAX_CONFIGURATION, too_long, ctx).await? {
        Ok(body) => body,
        Err(resp) => return Ok(resp),
    };
    if !body.iter().all(u8::is_ascii_whitespace)
        && !scan::parse(&body, 16).is_ok_and(|el| el.name == "CreateBucketConfiguration")
    {
        return Ok(malformed("the body is not a CreateBucketConfiguration"));
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, _| {
        let _namespace = files::namespace(store)?;
        if store.repo_dir_exists(&repo) {
            return Ok(ctx.error(
                StatusCode::CONFLICT,
                "BucketAlreadyOwnedByYou",
                "the bucket you tried to create exists, and is yours",
            ));
        }
        if store.repo_path_taken(&repo) {
            return Ok(ctx.error(
                StatusCode::CONFLICT,
                "OperationAborted",
                "something that is not a directory has the bucket's name in the store",
            ));
        }
        store.create_repo(&repo)?;
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(LOCATION, format!("/s3/{bucket}"))
            .header(CONTENT_LENGTH, "0")
            .body(body_of(bytes::Bytes::new()))?)
    })
    .await
}

/// Remove `repo` and the directories below it, deepest first, each as WebDAV's `DELETE`
/// removes an empty one: a bucket whose keys are all deleted is empty to S3, though the
/// directories they were in are left. Stops at the first one that is not removed, whose
/// answer it is; those removed before it held nothing.
fn remove_tree(store: &Store, repo: &str) -> anyhow::Result<RepoRemoval> {
    for child in store.repo_children(repo)? {
        let removal = remove_tree(store, &format!("{repo}/{child}"))?;
        if removal != RepoRemoval::Removed {
            return Ok(removal);
        }
    }
    store.remove_empty_repo(repo, crate::DEFAULT_GC_GRACE)
}

/// `DELETE /s3/<bucket>`: the bucket's directory tree removed when it holds no key: 204; 409
/// `BucketNotEmpty` when it holds keys, or records too fresh to be a deleted object's
/// leftovers; 404 `NoSuchBucket`. The removal needs the store lock
/// exclusive, tried under the namespace lock and retried, the namespace released between
/// attempts, for up to [`DELETE_LOCK_WAIT`]; then 503 `ServiceUnavailable`.
pub(super) async fn delete(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> anyhow::Result<Response<Body>> {
    let repo = format!("{FILES_REPO}/{bucket}");
    if !allowed(authz, accounts::Action::Write, &repo) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    if let Some(resp) = drain(req, ctx).await? {
        return Ok(resp);
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, _| {
        let deadline = Instant::now() + DELETE_LOCK_WAIT;
        let mut backoff = Duration::from_millis(10);
        loop {
            let namespace = files::namespace(store)?;
            if !store.repo_dir_exists(&repo) {
                return Ok(ctx.error(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "the specified bucket does not exist",
                ));
            }
            let not_empty = |message| ctx.error(StatusCode::CONFLICT, "BucketNotEmpty", message);
            return Ok(match remove_tree(store, &repo)? {
                RepoRemoval::Removed => Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(body_of(bytes::Bytes::new()))?,
                RepoRemoval::HasMembers => not_empty("the bucket you tried to delete is not empty"),
                RepoRemoval::HasRecords => not_empty(
                    "the bucket holds content written lately that is not a deleted object's, \
                     such as an image pushed over /v2/; it can go once the gc's grace has passed",
                ),
                RepoRemoval::Busy if Instant::now() >= deadline => {
                    let mut resp = ctx.error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "ServiceUnavailable",
                        "the store stayed locked; retry the DeleteBucket",
                    );
                    resp.headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("5"));
                    resp
                }
                RepoRemoval::Busy => {
                    drop(namespace);
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_millis(500));
                    continue;
                }
            });
        }
    })
    .await
}
