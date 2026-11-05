//! ETags and the conditional headers S3 takes on them: on a read, `If-Match`,
//! `If-Unmodified-Since`, `If-None-Match` and `If-Modified-Since`, in RFC 9110's order (S3's
//! too); on a write, `If-None-Match: *` (create only) and `If-Match` (replace only that
//! object), checked where the tag is written.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use hyper::header::{HeaderMap, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE};

use crate::files::{Object, Precondition};

/// The manifest annotation holding an S3-written object's MD5, as lowercase hex.
pub(crate) const MD5_ANNOTATION: &str = "org.virtkit.md5";

/// An object's ETag, quoted: the MD5 an S3 write recorded, or the SHA-256 of its bytes for
/// one written otherwise (WebDAV, `vk registry put`). 64 hex digits, so a client that checks
/// an ETag as an MD5 sees it is not one rather than a mismatch.
pub(crate) fn etag(layer: &str, annotations: &BTreeMap<String, String>) -> String {
    match annotations.get(MD5_ANNOTATION) {
        Some(md5)
            if md5.len() == 32
                && md5
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            format!("\"{md5}\"")
        }
        _ => format!("\"{layer}\""),
    }
}

/// [`etag`] of an object.
pub(crate) fn etag_of(obj: &Object) -> String {
    etag(&obj.layer, &obj.annotations)
}

/// Whether an `If-Match`/`If-None-Match` list names `etag` (quoted): `*` names any, a weak
/// `W/` tag compares as its strong form, and an unquoted entry as if it were quoted.
pub(crate) fn names(list: &str, etag: &str) -> bool {
    list.split(',').map(str::trim).any(|entry| {
        let entry = entry.strip_prefix("W/").unwrap_or(entry);
        entry == "*"
            || entry == etag
            || etag.strip_prefix('"').and_then(|e| e.strip_suffix('"')) == Some(entry)
    })
}

/// A read's conditional headers. A date that does not parse is ignored, as RFC 9110 has it.
#[derive(Debug, Default)]
pub(crate) struct Conditions {
    if_match: Option<String>,
    if_none_match: Option<String>,
    if_modified_since: Option<SystemTime>,
    if_unmodified_since: Option<SystemTime>,
}

/// What a read's [`Conditions`] decide.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Serve,
    /// 304
    NotModified,
    /// 412, naming the header that failed
    Failed(&'static str),
}

impl Conditions {
    pub(crate) fn of(headers: &HeaderMap) -> Self {
        let text = |name| {
            let values: Vec<&str> = headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            (!values.is_empty()).then(|| values.join(","))
        };
        let date = |name| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| httpdate::parse_http_date(v.trim()).ok())
        };
        Conditions {
            if_match: text(IF_MATCH),
            if_none_match: text(IF_NONE_MATCH),
            if_modified_since: date(IF_MODIFIED_SINCE),
            if_unmodified_since: date(IF_UNMODIFIED_SINCE),
        }
    }

    /// Decide on an object with this `etag` (quoted) last modified at `modified`. Times
    /// compare to the second, the precision an HTTP date has. `If-Unmodified-Since` counts
    /// only without `If-Match`, `If-Modified-Since` only without `If-None-Match`.
    pub(crate) fn evaluate(&self, etag: &str, modified: SystemTime) -> Outcome {
        let modified = whole_seconds(modified);
        match (&self.if_match, self.if_unmodified_since) {
            (Some(list), _) if !names(list, etag) => return Outcome::Failed("If-Match"),
            (None, Some(t)) if modified > whole_seconds(t) => {
                return Outcome::Failed("If-Unmodified-Since");
            }
            _ => {}
        }
        match (&self.if_none_match, self.if_modified_since) {
            (Some(list), _) if names(list, etag) => Outcome::NotModified,
            (None, Some(t)) if modified <= whole_seconds(t) => Outcome::NotModified,
            _ => Outcome::Serve,
        }
    }
}

fn whole_seconds(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// A write's conditional headers.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct WriteConditions {
    /// `If-None-Match: *`: only where no object is
    pub(crate) absent: bool,
    /// `If-Match`: only over an object it names
    pub(crate) if_match: Option<String>,
}

/// Why a write's conditional headers are not served: an `If-None-Match` other than `*`.
pub(crate) struct Unsupported;

impl WriteConditions {
    pub(crate) fn of(headers: &HeaderMap) -> Result<Self, Unsupported> {
        let text = |name| {
            let values: Vec<&str> = headers
                .get_all(name)
                .iter()
                .map(|v| v.to_str().map_err(|_| Unsupported))
                .collect::<Result<_, _>>()?;
            Ok((!values.is_empty()).then(|| values.join(",")))
        };
        let absent = match text(IF_NONE_MATCH)? {
            None => false,
            Some(v) if v.trim() == "*" => true,
            Some(_) => return Err(Unsupported),
        };
        Ok(WriteConditions {
            absent,
            if_match: text(IF_MATCH)?,
        })
    }

    /// What [`crate::files::commit`] checks, or `None` when nothing is asked.
    pub(crate) fn precondition(self) -> Option<Precondition> {
        if !self.absent && self.if_match.is_none() {
            return None;
        }
        Some(Box::new(move |existing: Option<&Object>| {
            (!self.absent || existing.is_none())
                && self
                    .if_match
                    .as_deref()
                    .is_none_or(|list| existing.is_some_and(|o| names(list, &etag_of(o))))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    const SHA: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const MD5: &str = "65a8e27d8879283831b664bd8b7f0ad4";

    fn object(annotations: &[(&str, &str)]) -> Object {
        Object {
            repo: "files/b".into(),
            tag: "k".into(),
            layer: SHA.into(),
            size: 13,
            modified: at(1_000_000),
            annotations: annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn headers(pairs: &[(hyper::header::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(n.clone(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn an_etag_is_the_recorded_md5_or_the_sha256() {
        assert_eq!(
            etag_of(&object(&[(MD5_ANNOTATION, MD5)])),
            format!("\"{MD5}\"")
        );
        assert_eq!(etag_of(&object(&[])), format!("\"{SHA}\""));
        assert_eq!(
            etag_of(&object(&[(MD5_ANNOTATION, "\"x\"")])),
            format!("\"{SHA}\"")
        );
        let upper = MD5.to_ascii_uppercase();
        assert_eq!(
            etag_of(&object(&[(MD5_ANNOTATION, &upper)])),
            format!("\"{SHA}\"")
        );
        assert_eq!(
            etag_of(&object(&[(MD5_ANNOTATION, &MD5[1..])])),
            format!("\"{SHA}\"")
        );
    }

    #[test]
    fn a_list_names_an_etag_quoted_weak_or_bare() {
        let e = format!("\"{MD5}\"");
        assert!(names("*", &e));
        assert!(names(&e, &e));
        assert!(names(&format!("W/{e}"), &e));
        assert!(names(MD5, &e));
        assert!(names(&format!("\"other\", {e}"), &e));
        assert!(!names("\"other\"", &e));
        assert!(!names("", &e));
        assert!(!names(&format!("\"{MD5}"), &e));
    }

    /// The eight combinations a read's headers can take on one object, and the order they
    /// are weighed in.
    #[test]
    fn reads_are_decided_in_rfc_order() {
        let e = format!("\"{MD5}\"");
        let modified = at(1_000_000) + Duration::from_millis(700);
        let before = httpdate::fmt_http_date(at(999_999));
        let same = httpdate::fmt_http_date(at(1_000_000));
        let decide = |pairs: &[(hyper::header::HeaderName, &str)]| {
            Conditions::of(&headers(pairs)).evaluate(&e, modified)
        };
        assert_eq!(decide(&[]), Outcome::Serve);
        // If-Match
        assert_eq!(decide(&[(IF_MATCH, &e)]), Outcome::Serve);
        assert_eq!(decide(&[(IF_MATCH, "\"x\"")]), Outcome::Failed("If-Match"));
        // If-Unmodified-Since, to the second
        assert_eq!(decide(&[(IF_UNMODIFIED_SINCE, &same)]), Outcome::Serve);
        assert_eq!(
            decide(&[(IF_UNMODIFIED_SINCE, &before)]),
            Outcome::Failed("If-Unmodified-Since")
        );
        // a matching If-Match overrides a failing If-Unmodified-Since
        assert_eq!(
            decide(&[(IF_MATCH, &e), (IF_UNMODIFIED_SINCE, &before)]),
            Outcome::Serve
        );
        // If-None-Match
        assert_eq!(decide(&[(IF_NONE_MATCH, &e)]), Outcome::NotModified);
        assert_eq!(decide(&[(IF_NONE_MATCH, "*")]), Outcome::NotModified);
        assert_eq!(decide(&[(IF_NONE_MATCH, "\"x\"")]), Outcome::Serve);
        // If-Modified-Since, to the second
        assert_eq!(decide(&[(IF_MODIFIED_SINCE, &same)]), Outcome::NotModified);
        assert_eq!(decide(&[(IF_MODIFIED_SINCE, &before)]), Outcome::Serve);
        // a non-matching If-None-Match overrides a met If-Modified-Since; a matching one
        // answers 304 whatever the date says
        assert_eq!(
            decide(&[(IF_NONE_MATCH, "\"x\""), (IF_MODIFIED_SINCE, &same)]),
            Outcome::Serve
        );
        assert_eq!(
            decide(&[(IF_NONE_MATCH, &e), (IF_MODIFIED_SINCE, &before)]),
            Outcome::NotModified
        );
        // a failed precondition outranks a 304
        assert_eq!(
            decide(&[(IF_MATCH, "\"x\""), (IF_NONE_MATCH, &e)]),
            Outcome::Failed("If-Match")
        );
        // a date that does not parse is no condition
        assert_eq!(decide(&[(IF_MODIFIED_SINCE, "yesterday")]), Outcome::Serve);
        assert_eq!(
            decide(&[(IF_UNMODIFIED_SINCE, "yesterday")]),
            Outcome::Serve
        );
    }

    #[test]
    fn writes_create_only_or_replace_only_what_they_name() {
        let md5 = object(&[(MD5_ANNOTATION, MD5)]);
        let sha = object(&[]);
        let check = |pairs: &[(hyper::header::HeaderName, &str)], existing: Option<&Object>| {
            WriteConditions::of(&headers(pairs))
                .ok()
                .unwrap()
                .precondition()
                .is_none_or(|p| p(existing))
        };
        assert!(
            WriteConditions::of(&headers(&[]))
                .ok()
                .unwrap()
                .precondition()
                .is_none()
        );
        assert!(check(&[], Some(&md5)));
        // create only
        assert!(check(&[(IF_NONE_MATCH, "*")], None));
        assert!(!check(&[(IF_NONE_MATCH, "*")], Some(&md5)));
        // compare and swap, on either ETag form
        let e = format!("\"{MD5}\"");
        assert!(check(&[(IF_MATCH, &e)], Some(&md5)));
        assert!(!check(&[(IF_MATCH, &e)], Some(&sha)));
        assert!(check(&[(IF_MATCH, &format!("\"{SHA}\""))], Some(&sha)));
        assert!(!check(&[(IF_MATCH, &e)], None));
        assert!(check(&[(IF_MATCH, "*")], Some(&sha)));
        assert!(!check(&[(IF_MATCH, "*")], None));
        // only `*` is served for If-None-Match
        assert!(WriteConditions::of(&headers(&[(IF_NONE_MATCH, &e)])).is_err());
    }
}
