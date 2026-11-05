//! The service and its buckets: ListBuckets, HeadBucket and GetBucketLocation. A bucket is a
//! top-level directory of `files/`, authorized as the repository `files/<bucket>`; one the
//! caller may read nothing in is absent to it, as in the WebDAV view.

use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH};
use hyper::{Request, Response, StatusCode};

use super::{Ctx, refuse, sigv4, xml};
use crate::files::FILES_REPO;
use crate::{Authz, Body, ServerState, body_of};

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
