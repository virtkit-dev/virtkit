//! CopyObject: `PUT /s3/<bucket>/<key>` with `x-amz-copy-source`. A copy is a new tag on the
//! source's layer, written as a PutObject's tag is but with no byte moved, so it costs a
//! manifest whatever the size and the pool still holds the bytes once. The source is read
//! as GetObject reads it and its conditions are its `x-amz-copy-source-if-*` headers; the
//! destination is written as PutObject writes, its `If-None-Match: *`/`If-Match` checked
//! where the tag is written. The source's MD5, and so its ETag, comes along, with the
//! checksum its write kept and its parts; its user metadata too, unless
//! `x-amz-metadata-directive: REPLACE` gives the request's instead. A copy that asks for a
//! checksum algorithm (`x-amz-checksum-algorithm`) other than the one the source kept has
//! it computed from the source's bytes, read once.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response};

use super::bucket::no_such_bucket;
use super::conditional::{self, Conditions, MD5_ANNOTATION, Outcome, WriteConditions};
use super::error::{Code, Refusal};
use super::object::{admitted, no_such_key, readable, unwritable};
use super::{Ctx, NULL_VERSION, checksum, drain, list, meta, path, refuse, xml};
use crate::files::{self, Commit, FILES_REPO, Written, allowed, object_of};
use crate::{Authz, Body, ServerState, Store, accounts};

/// The header naming a copy's source.
pub(super) const COPY_SOURCE: &str = "x-amz-copy-source";

/// The header a copy names the algorithm of the checksum its object is to have in.
const CHECKSUM_ALGORITHM: &str = "x-amz-checksum-algorithm";

/// What `x-amz-copy-source` names.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Source {
    /// an object: the bucket then the key's components, as [`path::Target::Object`]'s
    Object(Vec<String>),
    /// one version of an object other than its [`NULL_VERSION`], which this registry does
    /// not keep
    Versioned,
    /// a key of a bucket the store cannot name (`x-amz-copy-source` decoded), which holds no
    /// object: a copy of it is a miss
    Absent { bucket: String, key: String },
    /// nothing this view serves, and why
    Invalid(Refusal),
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
            invalid(
                "x-amz-copy-source is <bucket>/<key>, with no query but a versionId",
                value,
            )
        };
    }
    let Some(decoded) = crate::dav::decode_segment(raw) else {
        return invalid("Invalid copy source encoding", value);
    };
    let decoded = decoded.strip_prefix('/').unwrap_or(&decoded);
    let absent = || match decoded.split_once('/') {
        Some((bucket, key)) if path::is_bucket(bucket) => Source::Absent {
            bucket: bucket.to_string(),
            key: key.to_string(),
        },
        _ => invalid("Invalid copy source bucket name", value),
    };
    // No key holds a `%`: it is not decoded twice.
    if decoded.contains('%') {
        return absent();
    }
    match path::parse(&format!("/s3/{decoded}")) {
        Ok(path::Target::Object { segs, .. }) => Source::Object(segs),
        Ok(_) => invalid("Invalid copy source object key", value),
        Err(why) if why.code == Code::InvalidBucketName => {
            invalid("Invalid copy source bucket name", value)
        }
        Err(why) if matches!(why.code, Code::InvalidArgument | Code::BadRequest) => absent(),
        Err(why) => Source::Invalid(why),
    }
}

/// The answer to a copy from `bucket`'s `key`, which the store cannot name: `NoSuchBucket` when
/// the bucket is not there ([`super::bucket::missing`]), else `NoSuchKey`.
pub(super) async fn absent_source(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: &str,
    key: &str,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    Ok(
        match super::bucket::missing(state, authz, bucket, ctx).await? {
            Some(resp) => resp,
            None => ctx.error(Refusal::new(Code::NoSuchKey).with("Key", key)),
        },
    )
}

/// A copy source refused as S3 refuses one: `InvalidArgument` on `x-amz-copy-source`.
fn invalid(message: &'static str, value: &str) -> Source {
    Source::Invalid(Refusal::argument(message, COPY_SOURCE, value))
}

pub(super) fn failed(ctx: &Ctx) -> Response<Body> {
    ctx.error(Code::PreconditionFailed)
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
        return ctx.error(no_such_bucket(src.first().map_or("", String::as_str)));
    }
    no_such_key(ctx, src)
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
            let resp = ctx.error(Refusal::new(Code::NotImplemented).with("Header", COPY_SOURCE));
            return refuse(req, resp, ctx).await;
        }
        Source::Absent { bucket, key } => {
            let resp = absent_source(state, authz, &bucket, &key, ctx).await?;
            return refuse(req, resp, ctx).await;
        }
        Source::Invalid(why) => return refuse(req, ctx.error(why), ctx).await,
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
        Some(v) => {
            let resp = ctx.error(Refusal::argument(
                "Unknown metadata directive.",
                "x-amz-metadata-directive",
                String::from_utf8_lossy(v),
            ));
            return refuse(req, resp, ctx).await;
        }
    };
    // Tags are none either way, which is what every object has; another value is no
    // directive.
    if let Some(v) = headers
        .get("x-amz-tagging-directive")
        .filter(|v| !matches!(v.as_bytes(), b"COPY" | b"REPLACE"))
    {
        let resp = ctx.error(Refusal::argument(
            "Unknown tagging directive.",
            "x-amz-tagging-directive",
            String::from_utf8_lossy(v.as_bytes()),
        ));
        return refuse(req, resp, ctx).await;
    }
    let algorithm = match headers.get(CHECKSUM_ALGORITHM) {
        None => None,
        Some(v) => match checksum::named(v.as_bytes()).and_then(checksum::header) {
            Some(header) => Some(header),
            None => return refuse(req, ctx.error(checksum::UNKNOWN_ALGORITHM), ctx).await,
        },
    };
    if src == segs && !replace {
        let resp = ctx.error(Refusal::said(
            Code::InvalidRequest,
            "This copy request is illegal because it is trying to copy an object to itself \
             without changing the object's metadata, storage class, website redirect location \
             or encryption attributes.",
        ));
        return refuse(req, resp, ctx).await;
    }
    let replaced = if replace {
        match meta::annotations(headers) {
            Ok(a) => Some(a),
            Err(why) => return refuse(req, ctx.error(why), ctx).await,
        }
    } else {
        None
    };
    let conditions = Conditions::of_copy_source(headers);
    let written = match WriteConditions::of(headers) {
        Ok(written) => written,
        Err(why) => return refuse(req, ctx.error(why), ctx).await,
    };
    let precondition = written.clone().precondition();
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
            return Ok(no_such_key(&ctx, &src));
        }
        let mut annotations = replaced.unwrap_or_else(|| meta::carried(&obj.annotations));
        // Of the bytes, which are the same: the ETag, the checksum and the parts.
        for name in [
            MD5_ANNOTATION,
            checksum::ANNOTATION,
            super::multipart::PARTS_ANNOTATION,
            super::multipart::PART_CHECKSUMS_ANNOTATION,
        ] {
            if let Some(value) = obj.annotations.get(name) {
                annotations.insert(name.to_string(), value.clone());
            }
        }
        // Another algorithm than the one kept: computed, in place of it.
        let kept = checksum::stored(&obj.annotations);
        if let Some(header) = algorithm
            && kept.is_none_or(|k| checksum::header(k.algorithm) != Some(header))
        {
            let Some(value) = checksum::of_blob(store, &obj.layer, obj.size, header)? else {
                return Ok(no_such_key(&ctx, &src));
            };
            if let Some((name, value)) = checksum::annotation(header, &value) {
                annotations.insert(name, value);
            }
            // The parts' are in the algorithm it replaces.
            annotations.remove(super::multipart::PART_CHECKSUMS_ANNOTATION);
        }
        let checksum = checksum::stored(&annotations).map_or(String::new(), |k| k.elements());
        let etag = conditional::etag(&obj.layer, &annotations);
        let how = Commit {
            annotations,
            precondition,
            uncompressed: false,
        };
        match files::link(store, &held, &segs, &obj.layer, obj.size, how)? {
            Written::Created | Written::Replaced => {}
            Written::Refused(why) => return Ok(unwritable(why, &ctx)),
            Written::PreconditionFailed { found } => return Ok(ctx.error(written.refusal(found))),
        }
        let modified = object_of(&segs)
            .and_then(|(repo, tag)| store.tag_target(&repo, tag))
            .map_or_else(std::time::SystemTime::now, |(_, t)| t);
        Ok(xml::document(
            "CopyObjectResult",
            &format!(
                "{}{}{checksum}",
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
        let refusal = |value: &str| match source(value) {
            Source::Invalid(why) => why,
            other => panic!("{value}: {other:?}"),
        };
        for bad in [
            "", "/", "/b", "b/", "/b/", "/b/k?acl", "/b/a%2", "/b/%FF", "//b/k",
        ] {
            assert_eq!(refusal(bad).code, Code::InvalidArgument, "{bad}");
        }
        // A key the store cannot name holds no object, as S3 finds none there.
        for (missing, key) in [
            ("/b/a%2541", "a%41"),
            ("/b/a//k", "a//k"),
            ("/b/a b", "a b"),
            ("/b/../k", "../k"),
            ("/b/tags/k", "tags/k"),
            ("b/d/", "d/"),
            ("b//", "/"),
        ] {
            assert_eq!(
                source(missing),
                Source::Absent {
                    bucket: "b".into(),
                    key: key.into()
                },
                "{missing}"
            );
        }
        // In S3's words, naming the header and its value.
        let r = refusal("/b/a%2");
        assert_eq!(r.message(), "Invalid copy source encoding");
        assert_eq!(r.element("ArgumentName"), Some(COPY_SOURCE));
        assert_eq!(r.element("ArgumentValue"), Some("/b/a%2"));
        assert_eq!(refusal("/b").message(), "Invalid copy source object key");
        assert_eq!(
            refusal("//b/k").message(),
            "Invalid copy source bucket name"
        );
        assert_eq!(
            refusal(&format!("/b/{}", "x".repeat(256))).code,
            Code::KeyTooLongError
        );
    }
}
