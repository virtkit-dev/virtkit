//! `Range` on a GetObject or HeadObject, and the `If-Range` that makes it conditional. One
//! byte range is served, in any of RFC 9110's three forms (`bytes=a-b`, `bytes=a-`,
//! `bytes=-n`), as S3 serves it. Anything else is ignored and the whole object served, which
//! RFC 9110 allows: several ranges, another unit, a header that does not parse (whitespace
//! in the range or a last byte before the first included, as S3 takes them), or an
//! `If-Range` the object no longer matches.

use std::time::SystemTime;

use hyper::header::{HeaderMap, IF_RANGE, RANGE};

use super::conditional;

/// What a read's `Range` asks of an object.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Range {
    /// the whole object, 200
    Whole,
    /// `len` bytes from `start`, 206; `len` is at least one
    Part { start: u64, len: u64 },
    /// no byte of the object, 416
    Unsatisfiable,
}

/// A read's `Range` and `If-Range`, as sent.
#[derive(Debug)]
pub(super) struct Asked {
    range: Option<String>,
    if_range: Option<String>,
}

impl Asked {
    /// The headers, if each is sent once and is text; a `Range` sent twice is no single
    /// range, and an `If-Range` sent twice no single validator.
    pub(super) fn of(headers: &HeaderMap) -> Self {
        let once = |name| {
            let mut values = headers.get_all(name).iter();
            match (values.next(), values.next()) {
                (Some(v), None) => Some(v.to_str().map_or_else(|_| "?".into(), str::to_string)),
                (None, _) => None,
                (Some(_), Some(_)) => Some("?".into()),
            }
        };
        Asked {
            range: once(RANGE),
            if_range: once(IF_RANGE),
        }
    }

    /// The `Range` header as sent, for the error that refuses it.
    pub(super) fn range(&self) -> &str {
        self.range.as_deref().unwrap_or_default()
    }

    /// What is served of an object `total` bytes long, whose ETag is `etag` (quoted) and
    /// which was last modified at `modified`. `If-Range` counts only beside a `Range`.
    pub(super) fn resolve(&self, etag: &str, modified: SystemTime, total: u64) -> Range {
        let Some(range) = &self.range else {
            return Range::Whole;
        };
        if let Some(validator) = &self.if_range
            && !holds(validator, etag, modified)
        {
            return Range::Whole;
        }
        parse(range, total)
    }
}

/// Whether `If-Range`'s `validator` still names the object: its ETag compared strongly (a
/// weak tag never matches), or a date its `Last-Modified` equals to the second. Anything
/// else does not.
fn holds(validator: &str, etag: &str, modified: SystemTime) -> bool {
    let validator = validator.trim();
    if validator.starts_with('"') {
        return validator == etag;
    }
    if validator.starts_with("W/") {
        return false;
    }
    httpdate::parse_http_date(validator)
        .is_ok_and(|t| conditional::whole_seconds(t) == conditional::whole_seconds(modified))
}

/// `value` as a byte range of an object `total` bytes long. A range whose first byte is past
/// the end, or a suffix of none, is unsatisfiable; a last byte past the end, or a suffix
/// longer than the object, is cut to it, and a suffix of an empty object is all of it, as S3
/// serves them. A last byte before the first does not parse.
fn parse(value: &str, total: u64) -> Range {
    let Some((unit, set)) = value.split_once('=') else {
        return Range::Whole;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return Range::Whole;
    }
    // A list, so empty elements are passed over (RFC 9110 5.6.1); S3 takes none padded.
    let mut specs = set.split(',').filter(|s| !s.is_empty());
    let (Some(spec), None) = (specs.next(), specs.next()) else {
        return Range::Whole;
    };
    let Some((first, last)) = spec.split_once('-') else {
        return Range::Whole;
    };
    match (number(first), number(last)) {
        (Some(first), Some(last)) if first > last => Range::Whole,
        (Some(first), Some(_)) if first >= total => Range::Unsatisfiable,
        (Some(first), Some(last)) => Range::Part {
            start: first,
            len: last.min(total.saturating_sub(1)).saturating_sub(first) + 1,
        },
        (Some(first), None) if last.is_empty() => match total.checked_sub(first) {
            Some(len) if len > 0 => Range::Part { start: first, len },
            _ => Range::Unsatisfiable,
        },
        (None, Some(suffix)) if first.is_empty() => match (suffix, suffix.min(total)) {
            (0, _) => Range::Unsatisfiable,
            (_, 0) => Range::Whole,
            (_, len) => Range::Part {
                start: total - len,
                len,
            },
        },
        _ => Range::Whole,
    }
}

/// A run of decimal digits, a number too large for a `u64` being the largest one (still past
/// any object's end).
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s.parse().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn part(start: u64, len: u64) -> Range {
        Range::Part { start, len }
    }

    #[test]
    fn every_form_of_one_byte_range() {
        assert_eq!(parse("bytes=0-0", 10), part(0, 1));
        assert_eq!(parse("bytes=2-5", 10), part(2, 4));
        assert_eq!(parse("bytes=0-9", 10), part(0, 10));
        assert_eq!(parse("bytes=9-9", 10), part(9, 1));
        assert_eq!(parse("bytes=3-", 10), part(3, 7));
        assert_eq!(parse("bytes=9-", 10), part(9, 1));
        assert_eq!(parse("bytes=-3", 10), part(7, 3));
        assert_eq!(parse("bytes=-10", 10), part(0, 10));
        // The unit is case-insensitive.
        assert_eq!(parse("Bytes=1-1", 10), part(1, 1));
    }

    #[test]
    fn a_range_past_the_end_is_cut_to_it() {
        assert_eq!(parse("bytes=5-100", 10), part(5, 5));
        assert_eq!(parse("bytes=0-18446744073709551615", 10), part(0, 10));
        assert_eq!(parse("bytes=0-99999999999999999999999", 10), part(0, 10));
        // A suffix longer than the object is all of it.
        assert_eq!(parse("bytes=-11", 10), part(0, 10));
        assert_eq!(parse("bytes=-99999999999999999999999", 10), part(0, 10));
    }

    #[test]
    fn no_byte_of_the_object_is_unsatisfiable() {
        for value in [
            "bytes=10-",
            "bytes=10-20",
            "bytes=11-",
            "bytes=99999999999999999999999-",
            "bytes=-0",
        ] {
            assert_eq!(parse(value, 10), Range::Unsatisfiable, "{value}");
        }
        // An empty object has no first byte to serve, but a suffix of it is all of it.
        for value in ["bytes=0-0", "bytes=0-", "bytes=-0"] {
            assert_eq!(parse(value, 0), Range::Unsatisfiable, "{value}");
        }
        assert_eq!(parse("bytes=-1", 0), Range::Whole);
    }

    #[test]
    fn several_ranges_or_none_are_ignored() {
        for value in [
            "bytes=0-1,3-4",
            "bytes=0-1, -2",
            "bytes=",
            "bytes=,",
            "bytes",
            "items=0-1",
            "bytes=a-b",
            "bytes=-",
            "bytes=1",
            "bytes=+1-2",
            "bytes=1-+2",
            "bytes=-+2",
            "bytes=1 - 2",
            "bytes=0x1-2",
            "bytes=5-2",
            "bytes=102-0",
            "bytes= -1",
            "bytes=0 -1",
            "bytes= 1-2 ",
            "bytes=\t-3",
            "",
        ] {
            assert_eq!(parse(value, 10), Range::Whole, "{value:?}");
        }
    }

    #[test]
    fn empty_list_elements_are_passed_over() {
        assert_eq!(parse("bytes=,4-,", 10), part(4, 6));
        assert_eq!(parse("bytes =1-2", 10), part(1, 2));
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn if_range_holds_on_the_etag_or_the_date() {
        let etag = "\"65a8e27d8879283831b664bd8b7f0ad4\"";
        // 1994-11-06T08:49:37Z
        let modified = at(784_111_777);
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert!(holds(etag, etag, modified));
        assert!(holds(&format!(" {etag} "), etag, modified));
        assert!(!holds("\"other\"", etag, modified));
        assert!(!holds(&format!("W/{etag}"), etag, modified));
        assert!(!holds("65a8e27d8879283831b664bd8b7f0ad4", etag, modified));
        assert!(holds(date, etag, modified));
        // To the second, as an HTTP date has it.
        assert!(holds(date, etag, modified + Duration::from_millis(500)));
        assert!(!holds(date, etag, at(784_111_778)));
        assert!(!holds("Sun, 06 Nov 1994 08:49:36 GMT", etag, modified));
        assert!(!holds("yesterday", etag, modified));
    }

    fn asked(pairs: &[(hyper::header::HeaderName, &str)]) -> Asked {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(n.clone(), hyper::header::HeaderValue::from_str(v).unwrap());
        }
        Asked::of(&h)
    }

    #[test]
    fn if_range_decides_between_the_part_and_the_whole() {
        let etag = "\"abc\"";
        let modified = at(1_000_000);
        let resolve = |a: Asked| a.resolve(etag, modified, 10);
        assert_eq!(resolve(asked(&[])), Range::Whole);
        assert_eq!(resolve(asked(&[(RANGE, "bytes=1-2")])), part(1, 2));
        assert_eq!(
            resolve(asked(&[(RANGE, "bytes=1-2"), (IF_RANGE, etag)])),
            part(1, 2)
        );
        assert_eq!(
            resolve(asked(&[(RANGE, "bytes=1-2"), (IF_RANGE, "\"old\"")])),
            Range::Whole
        );
        // A mismatch serves the whole object rather than refusing the range.
        assert_eq!(
            resolve(asked(&[(RANGE, "bytes=20-"), (IF_RANGE, "\"old\"")])),
            Range::Whole
        );
        assert_eq!(
            resolve(asked(&[(RANGE, "bytes=20-"), (IF_RANGE, etag)])),
            Range::Unsatisfiable
        );
        // Without a Range, If-Range asks nothing.
        assert_eq!(resolve(asked(&[(IF_RANGE, "\"old\"")])), Range::Whole);
        // Two Range headers are no single range.
        assert_eq!(
            resolve(asked(&[(RANGE, "bytes=1-2"), (RANGE, "bytes=3-4")])),
            Range::Whole
        );
        assert_eq!(asked(&[(RANGE, "bytes=1-2")]).range(), "bytes=1-2");
    }
}
