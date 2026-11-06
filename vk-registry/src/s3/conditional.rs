//! ETags and the conditional headers S3 takes on them: on a read, `If-Match`,
//! `If-Unmodified-Since`, `If-None-Match` and `If-Modified-Since`, in RFC 9110's order (S3's
//! too); on a write, `If-None-Match: *` (create only) and `If-Match` (replace only that
//! object), checked where the tag is written; on a delete, the object's ETag, modification
//! time and size, checked where the tag is deleted.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use hyper::header::{HeaderMap, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE};

use crate::files::{Object, Precondition};

/// The manifest annotation holding an S3-written object's MD5, as lowercase hex; for an
/// object a multipart upload made, its multipart ETag, `<md5>-<parts>`.
pub(crate) const MD5_ANNOTATION: &str = "org.virtkit.md5";

/// An object's ETag, quoted: the MD5 an S3 write recorded (or the multipart ETag a completed
/// upload did), or the SHA-256 of its bytes for one written otherwise (WebDAV, `vk registry
/// put`). 64 hex digits, so a client that checks an ETag as an MD5 sees it is not one rather
/// than a mismatch.
pub(crate) fn etag(layer: &str, annotations: &BTreeMap<String, String>) -> String {
    match annotations.get(MD5_ANNOTATION) {
        Some(md5) if is_md5_etag(md5) => format!("\"{md5}\""),
        _ => format!("\"{layer}\""),
    }
}

/// Whether `s` is an ETag an S3 write records: 32 lowercase hex digits, then for a multipart
/// upload's `-` and its count of parts, 1 to 10000.
fn is_md5_etag(s: &str) -> bool {
    let (md5, parts) = match s.split_once('-') {
        Some((md5, parts)) => (md5, Some(parts)),
        None => (s, None),
    };
    md5.len() == 32
        && md5
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && parts.is_none_or(|p| {
            !p.starts_with('0')
                && p.len() <= 5
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u32>().is_ok_and(|n| (1..=10_000).contains(&n))
        })
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
        Self::named(
            headers,
            [
                IF_MATCH.as_str(),
                IF_NONE_MATCH.as_str(),
                IF_MODIFIED_SINCE.as_str(),
                IF_UNMODIFIED_SINCE.as_str(),
            ],
        )
    }

    /// A CopyObject's conditions on its source: the same four, each `x-amz-copy-source-`
    /// prefixed, weighed in the same order. What a read would answer 304 fails the copy.
    pub(crate) fn of_copy_source(headers: &HeaderMap) -> Self {
        Self::named(
            headers,
            [
                "x-amz-copy-source-if-match",
                "x-amz-copy-source-if-none-match",
                "x-amz-copy-source-if-modified-since",
                "x-amz-copy-source-if-unmodified-since",
            ],
        )
    }

    /// The conditions the headers `names` (`If-Match`, `If-None-Match`, `If-Modified-Since`
    /// and `If-Unmodified-Since`, or what stands for them) carry.
    fn named(headers: &HeaderMap, names: [&str; 4]) -> Self {
        let [
            if_match,
            if_none_match,
            if_modified_since,
            if_unmodified_since,
        ] = names;
        let text = |name: &str| {
            let values: Vec<&str> = headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            (!values.is_empty()).then(|| values.join(","))
        };
        let date = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| httpdate::parse_http_date(v.trim()).ok())
        };
        Conditions {
            if_match: text(if_match),
            if_none_match: text(if_none_match),
            if_modified_since: date(if_modified_since),
            if_unmodified_since: date(if_unmodified_since),
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

pub(crate) fn whole_seconds(t: SystemTime) -> u64 {
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

/// What S3 says when a precondition does not hold.
pub(crate) const PRECONDITION_FAILED: &str =
    "At least one of the pre-conditions you specified did not hold";

/// The header a DeleteObject names the object's modification time in.
pub(crate) const IF_MATCH_LAST_MODIFIED: &str = "x-amz-if-match-last-modified-time";

/// The header a DeleteObject names the object's size in.
pub(crate) const IF_MATCH_SIZE: &str = "x-amz-if-match-size";

/// The header an AbortMultipartUpload names its upload's initiation time in.
pub(crate) const IF_MATCH_INITIATED: &str = "x-amz-if-match-initiated-time";

/// A delete's conditions: DeleteObject's `If-Match`, `x-amz-if-match-last-modified-time` and
/// `x-amz-if-match-size`, or the `ETag`, `LastModifiedTime` and `Size` of an `<Object>` of a
/// `Delete` document. Each one given must hold of the object for it to be deleted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DeleteConditions {
    /// an ETag, quoted or not, or `*` (also quoted) for any object
    pub(crate) etag: Option<String>,
    /// seconds since the epoch
    pub(crate) modified: Option<u64>,
    pub(crate) size: Option<u64>,
}

impl DeleteConditions {
    /// The conditions DeleteObject's headers carry; the reason for a 400 when one is not a
    /// value its header takes.
    pub(crate) fn of(headers: &HeaderMap) -> Result<Self, &'static str> {
        let text = |name: &str| match headers.get(name) {
            None => Ok(None),
            Some(v) => v
                .to_str()
                .map(|v| Some(v.to_string()))
                .map_err(|_| "a conditional header is not text"),
        };
        let modified = match text(IF_MATCH_LAST_MODIFIED)? {
            None => None,
            Some(v) => Some(
                parse_time(&v)
                    .map(whole_seconds)
                    .ok_or("x-amz-if-match-last-modified-time is an HTTP date")?,
            ),
        };
        let size = match text(IF_MATCH_SIZE)? {
            None => None,
            Some(v) => Some(parse_size(&v).ok_or("x-amz-if-match-size is a count of bytes")?),
        };
        Ok(DeleteConditions {
            etag: text(IF_MATCH.as_str())?,
            modified,
            size,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.etag.is_none() && self.modified.is_none() && self.size.is_none()
    }

    /// Whether every condition holds of `obj`: its ETag named (`*` naming any), its
    /// modification time to the second, its size.
    pub(crate) fn hold(&self, obj: &Object) -> bool {
        self.etag.as_deref().is_none_or(|list| {
            let list = if list.trim() == "\"*\"" { "*" } else { list };
            names(list, &etag_of(obj))
        }) && self
            .modified
            .is_none_or(|t| t == whole_seconds(obj.modified))
            && self.size.is_none_or(|s| s == obj.size)
    }
}

/// A count of bytes as a condition gives it: decimal digits only.
pub(crate) fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// A time as a delete's condition gives it: an HTTP date in any of RFC 9110's three forms,
/// or, as S3 takes it, the IMF form with a numeric zone (`+0200`) in place of `GMT`;
/// surrounding blanks are passed over.
pub(crate) fn parse_time(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    if let Ok(t) = httpdate::parse_http_date(text) {
        return Some(t);
    }
    let (local, zone) = text.rsplit_once(' ')?;
    let (sign, digits) = match zone.as_bytes().first()? {
        b'+' => (1i64, &zone[1..]),
        b'-' => (-1i64, &zone[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (hours, minutes): (i64, i64) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
    if minutes > 59 {
        return None;
    }
    let as_gmt = httpdate::parse_http_date(&format!("{local} GMT")).ok()?;
    let offset = sign * (hours * 3600 + minutes * 60);
    let secs = i64::try_from(whole_seconds(as_gmt)).ok()? - offset;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).ok()?))
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
        // A multipart upload's: the MD5 of its parts' MD5s and their count.
        for parts in ["1", "3", "10000"] {
            let multipart = format!("{MD5}-{parts}");
            assert_eq!(
                etag_of(&object(&[(MD5_ANNOTATION, &multipart)])),
                format!("\"{multipart}\"")
            );
        }
        for bad in ["-", "-0", "-01", "-10001", "-x", "-1-2", "- 1"] {
            assert_eq!(
                etag_of(&object(&[(MD5_ANNOTATION, &format!("{MD5}{bad}"))])),
                format!("\"{SHA}\""),
                "{bad}"
            );
        }
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

    /// A copy's conditions on its source are the same four under their own names, and the
    /// read's own headers say nothing to them.
    #[test]
    fn a_copy_source_s_conditions_are_its_own_headers() {
        let e = format!("\"{MD5}\"");
        let modified = at(1_000_000);
        let before = httpdate::fmt_http_date(at(999_999));
        let named = |n: &'static str| hyper::header::HeaderName::from_static(n);
        let decide = |pairs: &[(hyper::header::HeaderName, &str)]| {
            Conditions::of_copy_source(&headers(pairs)).evaluate(&e, modified)
        };
        assert_eq!(decide(&[(IF_MATCH, "\"x\"")]), Outcome::Serve);
        let if_match = named("x-amz-copy-source-if-match");
        let unmodified = named("x-amz-copy-source-if-unmodified-since");
        assert_eq!(
            decide(&[(if_match.clone(), "\"x\"")]),
            Outcome::Failed("If-Match")
        );
        // S3's rule for the copy: a matching If-Match carries a failing If-Unmodified-Since.
        assert_eq!(
            decide(&[(if_match, &e), (unmodified.clone(), &before)]),
            Outcome::Serve
        );
        assert_eq!(
            decide(&[(unmodified, &before)]),
            Outcome::Failed("If-Unmodified-Since")
        );
        assert_eq!(
            decide(&[(named("x-amz-copy-source-if-none-match"), &e)]),
            Outcome::NotModified
        );
        let since = httpdate::fmt_http_date(at(1_000_000));
        assert_eq!(
            decide(&[(named("x-amz-copy-source-if-modified-since"), &since)]),
            Outcome::NotModified
        );
    }

    #[test]
    fn a_delete_s_time_is_an_http_date_or_one_with_a_numeric_zone() {
        let t = Some(at(784_111_777));
        assert_eq!(parse_time("Sun, 06 Nov 1994 08:49:37 GMT"), t);
        assert_eq!(parse_time("Sunday, 06-Nov-94 08:49:37 GMT"), t);
        assert_eq!(parse_time("Sun Nov  6 08:49:37 1994"), t);
        assert_eq!(parse_time("Sun, 06 Nov 1994 10:49:37 +0200"), t);
        assert_eq!(parse_time("Sun, 06 Nov 1994 07:19:37 -0130"), t);
        assert_eq!(parse_time("  Sun, 06 Nov 1994 08:49:37 GMT  "), t);
        for bad in [
            "",
            "1994-11-06T08:49:37Z",
            "Sun, 06 Nov 1994 08:49:37 +02",
            "Sun, 06 Nov 1994 08:49:37 +0260",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "not a date",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_delete_s_conditions_all_hold_or_it_keeps_the_object() {
        let obj = object(&[(MD5_ANNOTATION, MD5)]);
        let e = format!("\"{MD5}\"");
        let date = httpdate::fmt_http_date(at(1_000_000));
        let named = |n: &'static str| hyper::header::HeaderName::from_static(n);
        let check = |pairs: &[(hyper::header::HeaderName, &str)]| {
            DeleteConditions::of(&headers(pairs)).map(|c| (c.is_empty(), c.hold(&obj)))
        };
        let size = named(IF_MATCH_SIZE);
        let time = named(IF_MATCH_LAST_MODIFIED);
        assert_eq!(check(&[]), Ok((true, true)));
        for etag in [e.as_str(), MD5, "*", "\"*\""] {
            assert_eq!(check(&[(IF_MATCH, etag)]), Ok((false, true)), "{etag}");
        }
        assert_eq!(check(&[(IF_MATCH, "\"x\"")]), Ok((false, false)));
        assert_eq!(check(&[(IF_MATCH, "")]), Ok((false, false)));
        assert_eq!(check(&[(size.clone(), "13")]), Ok((false, true)));
        assert_eq!(check(&[(size.clone(), "14")]), Ok((false, false)));
        assert_eq!(check(&[(time.clone(), &date)]), Ok((false, true)));
        let before = httpdate::fmt_http_date(at(999_999));
        assert_eq!(check(&[(time.clone(), &before)]), Ok((false, false)));
        // every one must hold
        assert_eq!(
            check(&[
                (IF_MATCH, &e),
                (size.clone(), "13"),
                (time.clone(), &before)
            ]),
            Ok((false, false))
        );
        // a value its header does not take is refused, not passed over
        for bad in ["-1", "13 bytes", ""] {
            assert!(check(&[(size.clone(), bad)]).is_err(), "{bad}");
        }
        assert!(check(&[(time, "yesterday")]).is_err());
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
