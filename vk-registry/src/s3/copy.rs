//! CopyObject: `PUT /s3/<bucket>/<key>` with `x-amz-copy-source`. A copy is a new tag on the
//! source's layer, written as a PutObject's tag is but with no byte moved, so it costs a
//! manifest whatever the size and the pool still holds the bytes once. The source is read
//! as GetObject reads it and its conditions are its `x-amz-copy-source-if-*` headers; the
//! destination is written as PutObject writes, its `If-None-Match: *`/`If-Match` checked
//! where the tag is written. The source's MD5, and so its ETag, comes along; its user
//! metadata too, unless `x-amz-metadata-directive: REPLACE` gives the request's instead.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::conditional::{self, Conditions, MD5_ANNOTATION, Outcome, WriteConditions};
use super::object::{admitted, no_such_key, readable, unwritable};
use super::{Ctx, NULL_VERSION, drain, list, meta, path, refuse, xml};
use crate::files::{self, Commit, FILES_REPO, Written, allowed, object_of};
use crate::{Authz, Body, ServerState, Store, accounts};

/// The header naming a copy's source.
pub(super) const COPY_SOURCE: &str = "x-amz-copy-source";

/// What `x-amz-copy-source` names.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Source {
    /// an object: the bucket then the key's components, as [`path::Target::Object`]'s
    Object(Vec<String>),
    /// one version of an object other than its [`NULL_VERSION`], which this registry does
    /// not keep
    Versioned,
    /// nothing this view serves: an S3 error code and the rule
    Invalid(&'static str, &'static str),
}

/// What a copy source `value` names: `<bucket>/<key>`, with or without a leading slash, its
/// escapes decoded as a whole — a key's characters need none, so a client that escapes the
/// `/` between components names the same object as one that does not. What is decoded is
/// then held to the key rules a request path is, and an escape that decodes to a `%`, which
/// no key holds, is refused rather than decoded twice.
pub(super) fn source(value: &str) -> Source {
    let (raw, query) = match value.split_once('?') {
        Some((raw, query)) => (raw, Some(query)),
        None => (value, None),
    };
    // The null version is the object; the query names nothing else.
    if let Some(query) = query.filter(|q| q.strip_prefix("versionId=") != Some(NULL_VERSION)) {
        let versioned = query
            .split('&')
            .any(|p| p.split_once('=').map_or(p, |(n, _)| n) == "versionId");
        return if versioned {
            Source::Versioned
        } else {
            Source::Invalid(
                "InvalidArgument",
                "x-amz-copy-source is <bucket>/<key>, with no query but a versionId",
            )
        };
    }
    let Some(decoded) = crate::dav::decode_segment(raw) else {
        return Source::Invalid(
            "InvalidArgument",
            "x-amz-copy-source has a malformed percent escape or is not UTF-8",
        );
    };
    if decoded.contains('%') {
        return Source::Invalid(
            "InvalidArgument",
            "a key's components are runs of A-Z a-z 0-9 . _ - only",
        );
    }
    let decoded = decoded.strip_prefix('/').unwrap_or(&decoded);
    match path::parse(&format!("/s3/{decoded}")) {
        Ok(path::Target::Object { segs, .. }) => Source::Object(segs),
        Ok(_) => Source::Invalid(
            "InvalidArgument",
            "x-amz-copy-source names a bucket and a key",
        ),
        Err(why) => Source::Invalid(why.code, why.message),
    }
}

pub(super) fn failed(ctx: &Ctx) -> Response<Body> {
    ctx.error(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "at least one of the preconditions you specified did not hold",
    )
}

/// The answer for a source the caller cannot read: `NoSuchBucket` when its bucket is no
/// directory and the caller may read in it, otherwise `NoSuchKey`, as a read of it answers.
pub(super) fn absent(
    store: &Store,
    authz: &Authz<'_>,
    src: &[String],
    ctx: &Ctx,
) -> Response<Body> {
    let bucket = format!("{FILES_REPO}/{}", src.first().map_or("", String::as_str));
    if authz.may_read_below(&bucket) && !store.repo_dir_exists(&bucket) {
        return ctx.error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        );
    }
    no_such_key(ctx)
}

/// `PUT /s3/<bucket>/<key>` with `x-amz-copy-source`: the source object tagged again at the
/// key, under the namespace and shared store lock across the read of the source and the
/// write, so neither changes between the two. 200 with `CopyObjectResult`.
pub(super) async fn copy(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: Vec<String>,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    let parent = object_of(&segs).map(|(parent, _)| parent);
    if !parent.is_some_and(|p| allowed(authz, accounts::Action::Write, &p)) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let headers = req.headers();
    let value = headers
        .get(COPY_SOURCE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let src = match source(value) {
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
    let replace = match headers
        .get("x-amz-metadata-directive")
        .map(|v| v.as_bytes())
    {
        None | Some(b"COPY") => false,
        Some(b"REPLACE") => true,
        Some(_) => {
            let resp = ctx.error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-metadata-directive is COPY or REPLACE",
            );
            return refuse(req, resp, ctx).await;
        }
    };
    if src == segs && !replace {
        let resp = ctx.error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "this copy request is illegal because it is trying to copy an object to itself \
             without changing the object's metadata",
        );
        return refuse(req, resp, ctx).await;
    }
    let replaced = if replace {
        match meta::annotations(headers) {
            Ok(a) => Some(a),
            Err(why) => {
                let resp = ctx.error(StatusCode::BAD_REQUEST, why.code, why.message);
                return refuse(req, resp, ctx).await;
            }
        }
    } else {
        None
    };
    let conditions = Conditions::of_copy_source(headers);
    let Ok(written) = WriteConditions::of(headers) else {
        let resp = ctx.error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "a write's If-None-Match is * or nothing",
        );
        return refuse(req, resp, ctx).await;
    };
    let precondition = written.precondition();
    // A copy has no body of its own; whatever came is read through first.
    if let Some(resp) = drain(req, ctx).await? {
        return Ok(resp);
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        let held = files::hold(store)?;
        let Some(obj) = readable(store, authz, &src)? else {
            return Ok(absent(store, authz, &src, &ctx));
        };
        if conditions.evaluate(&conditional::etag_of(&obj), obj.modified) != Outcome::Serve {
            return Ok(failed(&ctx));
        }
        // The layer gone under the tag (pruned by hand) is no object either; present, it is
        // now referenced again, which keeps it from the gc's grace window.
        if !store.has_blob(&obj.layer) {
            return Ok(no_such_key(&ctx));
        }
        let mut annotations = replaced.unwrap_or_else(|| meta::carried(&obj.annotations));
        if let Some(md5) = obj.annotations.get(MD5_ANNOTATION) {
            annotations.insert(MD5_ANNOTATION.to_string(), md5.clone());
        }
        let etag = conditional::etag(&obj.layer, &annotations);
        let how = Commit {
            annotations,
            precondition,
            uncompressed: false,
        };
        match files::link(store, &held, &segs, &obj.layer, obj.size, how)? {
            Written::Created | Written::Replaced => {}
            Written::Refused(why) => return Ok(unwritable(why, &ctx)),
            Written::PreconditionFailed => return Ok(failed(&ctx)),
        }
        let modified = object_of(&segs)
            .and_then(|(repo, tag)| store.tag_target(&repo, tag))
            .map_or_else(std::time::SystemTime::now, |(_, t)| t);
        Ok(xml::document(
            "CopyObjectResult",
            &format!(
                "{}{}",
                xml::element("LastModified", &list::iso8601(modified)),
                xml::element("ETag", &etag)
            ),
        ))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(parts: &[&str]) -> Source {
        Source::Object(parts.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn a_copy_source_is_a_bucket_and_a_key_in_any_spelling() {
        for spelling in [
            "/b/a/k",
            "b/a/k",
            "/b%2Fa%2Fk",
            "b%2Fa/k",
            "%2Fb/a/k",
            "/b/a/%6B",
            "/b/a/k?versionId=null",
        ] {
            assert_eq!(source(spelling), object(&["b", "a", "k"]), "{spelling}");
        }
        assert_eq!(
            source("/b/.sccache_check"),
            object(&["b", ".sccache_check"])
        );
        for versioned in [
            "/b/k?versionId=1",
            "b/k?versionId=3&x=1",
            "b/k?versionId=null&x=1",
            "b/k?versionId=NULL",
        ] {
            assert_eq!(source(versioned), Source::Versioned, "{versioned}");
        }
    }

    #[test]
    fn a_copy_source_that_names_no_object_is_refused_with_the_rule() {
        let code = |value: &str| match source(value) {
            Source::Invalid(code, _) => code,
            other => panic!("{value}: {other:?}"),
        };
        for bad in [
            "",
            "/",
            "/b",
            "b/",
            "/b/",
            "/b/k?acl",
            "/b/a%2",
            "/b/%FF",
            "/b/a%2541",
            "/b/a//k",
            "/b/a b",
            "/b/../k",
            "/b/tags/k",
            "//b/k",
        ] {
            assert!(
                ["InvalidArgument", "InvalidBucketName"].contains(&code(bad)),
                "{bad}: {}",
                code(bad)
            );
        }
        assert_eq!(code(&format!("/b/{}", "x".repeat(256))), "KeyTooLongError");
    }
}
