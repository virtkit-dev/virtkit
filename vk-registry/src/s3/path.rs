//! The path of an `/s3/` request as what it names in `files/`: the service, a bucket (a
//! top-level directory) or an object (a key below one). Split before percent-decoding, so an
//! escaped `/` cannot make one component two, and decoded as the WebDAV view decodes its
//! paths. A key maps onto the store's names as they are, so it has to be one: each component
//! a repository name's component, the leaf a tag, no empty component and no trailing slash.
//! Arbitrary keys would need an escaping scheme, which this view deliberately does not have.

use crate::dav::decode_segment;

/// Most components a key may have: a repository name's bound less `files` and the bucket.
pub(crate) const MAX_KEY_COMPONENTS: usize = crate::MAX_NAME_SEGMENTS - 2;

/// Longest key, in bytes once decoded: S3's own bound.
pub(crate) const MAX_KEY: usize = 1024;

/// Longest key component, in bytes: a filename's.
const MAX_COMPONENT: usize = 255;

/// What a path names.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// `/s3` or `/s3/`
    Service,
    /// `/s3/<bucket>`, with or without a trailing slash
    Bucket(String),
    /// `/s3/<bucket>/<key>`: `segs` are the bucket then the key's components, the path below
    /// `files/` the object layer takes
    Object { key: String, segs: Vec<String> },
}

/// Why a path names nothing this view serves: an S3 error code and the rule it broke.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

const fn refusal(code: &'static str, message: &'static str) -> Refusal {
    Refusal { code, message }
}

const BAD_BUCKET: Refusal = refusal(
    "InvalidBucketName",
    "a bucket name is one run of A-Z a-z 0-9 . _ - and not tags, manifests or blobs",
);
const BAD_ESCAPE: Refusal = refusal(
    "InvalidArgument",
    "the key has a malformed percent escape or is not UTF-8",
);
const EMPTY_COMPONENT: Refusal = refusal(
    "InvalidArgument",
    "a key has no empty component and does not end in a slash",
);
const BAD_CHARACTER: Refusal = refusal(
    "InvalidArgument",
    "a key's components are runs of A-Z a-z 0-9 . _ - only",
);
const DOT_COMPONENT: Refusal = refusal("InvalidArgument", "a key component cannot be . or ..");
const RESERVED_COMPONENT: Refusal = refusal(
    "InvalidArgument",
    "a key component cannot be tags, manifests or blobs",
);
const TOO_DEEP: Refusal = refusal("InvalidArgument", "a key has at most 14 components");
const COMPONENT_TOO_LONG: Refusal =
    refusal("KeyTooLongError", "a key component is at most 255 bytes");
const KEY_TOO_LONG: Refusal = refusal("KeyTooLongError", "a key is at most 1024 bytes");

/// Why S3 could not parse a request's path at all, which it answers 400 `InvalidURI` before
/// looking at the credential: a component with a malformed percent escape, not UTF-8 once
/// decoded or holding a control character (as ceph's suite has S3 refuse `\u{8a}`), or `..`
/// components that climb above the root, `\` separating them as `/` does.
/// `rel` is the path below the S3 root: what follows `/s3` path-style, the whole path of a
/// request whose host names the bucket. A `.` or `..` that stays below the root is a key's
/// component, which [`parse`] refuses as such.
pub(crate) fn unparsable(rel: &str) -> Option<&'static str> {
    let mut depth = 0usize;
    for raw in rel.split('/') {
        let Some(seg) = decode_segment(raw).filter(|s| !s.chars().any(char::is_control)) else {
            return Some(
                "the request's path has a malformed percent escape, is not UTF-8 or holds a control character",
            );
        };
        for part in seg.split('\\') {
            match part {
                "" | "." => {}
                ".." => match depth.checked_sub(1) {
                    Some(up) => depth = up,
                    None => return Some("the request's path climbs above its root"),
                },
                _ => depth += 1,
            }
        }
    }
    None
}

/// What the path of a request under `/s3` names; the caller dispatches only `/s3` paths here.
pub(crate) fn parse(path: &str) -> Result<Target, Refusal> {
    let rest = path.strip_prefix("/s3").unwrap_or(path);
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Ok(Target::Service);
    }
    let (raw_bucket, raw_key) = match rest.split_once('/') {
        Some((b, k)) => (b, Some(k)),
        None => (rest, None),
    };
    let bucket = decode_segment(raw_bucket)
        .filter(|b| is_bucket(b))
        .ok_or(BAD_BUCKET)?;
    let raw_key = match raw_key {
        None | Some("") => return Ok(Target::Bucket(bucket)),
        Some(k) => k,
    };
    let mut segs = vec![bucket];
    for raw in raw_key.split('/') {
        if segs.len() > MAX_KEY_COMPONENTS {
            return Err(TOO_DEEP);
        }
        segs.push(component(raw)?);
    }
    let key = segs.get(1..).unwrap_or_default().join("/");
    if key.len() > MAX_KEY {
        return Err(KEY_TOO_LONG);
    }
    Ok(Target::Object { key, segs })
}

/// Whether `name`, decoded, can name a bucket: one top-level component of `files/`.
pub(crate) fn is_bucket(name: &str) -> bool {
    crate::valid_name(name) && !name.contains('/') && name.len() <= MAX_COMPONENT
}

/// One key component, decoded and held to a repository name's component rule (which the
/// leaf, as a tag, also passes).
fn component(raw: &str) -> Result<String, Refusal> {
    if raw.is_empty() {
        return Err(EMPTY_COMPONENT);
    }
    let seg = decode_segment(raw).ok_or(BAD_ESCAPE)?;
    if seg.len() > MAX_COMPONENT {
        return Err(COMPONENT_TOO_LONG);
    }
    if seg.is_empty() {
        return Err(EMPTY_COMPONENT);
    }
    if !seg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(BAD_CHARACTER);
    }
    if seg == "." || seg == ".." {
        return Err(DOT_COMPONENT);
    }
    if !crate::valid_name(&seg) {
        return Err(RESERVED_COMPONENT);
    }
    Ok(seg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(key: &str) -> Result<Target, Refusal> {
        parse(&format!("/s3/b/{key}"))
    }

    #[track_caller]
    fn refused(key: &str, code: &str) -> &'static str {
        match object(key) {
            Err(r) => {
                assert_eq!(r.code, code, "{key:?}: {}", r.message);
                r.message
            }
            Ok(t) => panic!("accepted {key:?} as {t:?}"),
        }
    }

    #[test]
    fn a_path_is_unparsable_with_a_bad_escape_or_climbing_above_its_root() {
        for bad in [
            "/b/(*&^%&())",
            "/b/a%zz",
            "/b/a%",
            "/b/%FF",
            "/b/%C2%AE%C2%8A-",
            "/b/a%0Ab",
            "/b%2",
            "/b/../../x",
            "/b/a/a/../../../../x",
            "/b//a/../../b/../../c",
            "/b/x//../../../y",
            "/b/x%5C..%5C..%5C..%5Cy",
            "/../x",
            "/..",
        ] {
            assert!(unparsable(bad).is_some(), "{bad}");
        }
        for good in [
            "",
            "/",
            "/b",
            "/b/k",
            "/b/..",
            "/b/a/../b",
            "/b/x/y/../..",
            "/b/./k",
            "/b/a%2F..%2F..%2F..",
        ] {
            assert_eq!(unparsable(good), None, "{good}");
        }
    }

    #[test]
    fn the_service_and_buckets_are_named_by_one_component() {
        assert_eq!(parse("/s3"), Ok(Target::Service));
        assert_eq!(parse("/s3/"), Ok(Target::Service));
        assert_eq!(parse("/s3/sccache"), Ok(Target::Bucket("sccache".into())));
        assert_eq!(parse("/s3/sccache/"), Ok(Target::Bucket("sccache".into())));
        assert_eq!(parse("/s3/a%2Db"), Ok(Target::Bucket("a-b".into())));
        for bad in [
            "/s3//",
            "/s3//k",
            "/s3/a%2Fb",
            "/s3/..",
            "/s3/.",
            "/s3/tags",
            "/s3/blobs/k",
            "/s3/a b",
            "/s3/a%20b",
            "/s3/%C3%A9",
            "/s3/a%2",
        ] {
            let r = parse(bad).unwrap_err();
            assert_eq!(r.code, "InvalidBucketName", "{bad}");
        }
    }

    #[test]
    fn sccache_keys_map_onto_the_files_tree() {
        assert_eq!(
            object(".sccache_check"),
            Ok(Target::Object {
                key: ".sccache_check".into(),
                segs: vec!["b".into(), ".sccache_check".into()],
            })
        );
        let hex = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let Ok(Target::Object { key, segs }) = object(&format!("a/b/c/{hex}")) else {
            panic!("a sharded key");
        };
        assert_eq!(key, format!("a/b/c/{hex}"));
        assert_eq!(segs, ["b", "a", "b", "c", hex]);
        let (repo, tag) = crate::files::object_of(&segs).unwrap();
        assert_eq!((repo.as_str(), tag), ("files/b/a/b/c", hex));
        assert!(crate::valid_name(&crate::files::repo_name(&segs)));
        // An escape of an allowed character is that character.
        assert!(matches!(object("a%2Db"), Ok(Target::Object { key, .. }) if key == "a-b"));
    }

    #[test]
    fn the_deepest_and_longest_keys_pass() {
        let deepest = vec!["x"; MAX_KEY_COMPONENTS].join("/");
        let Ok(Target::Object { segs, .. }) = object(&deepest) else {
            panic!("14 components");
        };
        assert_eq!(segs.len(), crate::MAX_NAME_SEGMENTS - 1);
        assert!(crate::valid_name(&crate::files::repo_name(&segs)));
        assert!(object(&"x".repeat(255)).is_ok());
        assert_eq!(longest().len(), MAX_KEY);
        assert!(object(&longest()).is_ok());
    }

    /// A key of exactly [`MAX_KEY`] bytes, no component over 255.
    fn longest() -> String {
        format!("{0}/{0}/{0}/{1}/y", "x".repeat(255), "x".repeat(254))
    }

    #[test]
    fn keys_outside_the_store_s_names_are_refused_naming_the_rule() {
        let too_deep = vec!["x"; MAX_KEY_COMPONENTS + 1].join("/");
        assert!(refused(&too_deep, "InvalidArgument").contains("14"));
        assert!(refused(&"x".repeat(256), "KeyTooLongError").contains("255"));
        let over = format!("{}y", longest());
        assert_eq!(over.len(), MAX_KEY + 1);
        assert!(refused(&over, "KeyTooLongError").contains("1024"));
        for empty in ["a//b", "a/", "a/b/", "/a"] {
            assert!(
                refused(empty, "InvalidArgument").contains("empty"),
                "{empty}"
            );
        }
        for dot in [".", "..", "a/./b", "a/../b", "%2E%2E/x"] {
            assert!(refused(dot, "InvalidArgument").contains(". or .."), "{dot}");
        }
        for reserved in ["tags", "a/manifests/b", "blobs/x", "a/blobs"] {
            assert!(
                refused(reserved, "InvalidArgument").contains("tags, manifests or blobs"),
                "{reserved}"
            );
        }
        for bad in [
            "a%2Fb",
            "a%5Cb",
            "%C3%A9",
            "caf\u{e9}",
            "a b",
            "a%20b",
            "a%00b",
            "a%0Ab",
            "a%7F",
            "a+b",
            "a~b",
            "a:b",
            "a*b",
        ] {
            assert!(
                refused(bad, "InvalidArgument").contains("A-Z a-z 0-9 . _ -"),
                "{bad}"
            );
        }
        for bad in ["a%2", "a%G0", "%FF", "%C3"] {
            assert!(refused(bad, "InvalidArgument").contains("escape"), "{bad}");
        }
    }
}
