//! User metadata: the `x-amz-meta-<name>` headers of a write, kept as manifest annotations
//! `org.virtkit.s3-meta.<name>` and sent back on reads. Sync tools keep a file's own
//! modification time there.

use std::collections::BTreeMap;

use hyper::header::{HeaderMap, HeaderName, HeaderValue};

/// The prefix of a user metadata header.
const HEADER_PREFIX: &str = "x-amz-meta-";

/// The prefix of the annotation each one is kept as.
const ANNOTATION_PREFIX: &str = "org.virtkit.s3-meta.";

/// Most bytes of user metadata, names and values together: S3's own bound.
pub(crate) const MAX_METADATA: usize = 2048;

/// Why a write's metadata is refused: an S3 error code and the rule.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

/// The annotations a write's `x-amz-meta-*` headers become. A name is `[a-z0-9-]`, matched
/// without regard to case (header names arrive lowercase) and kept lowercase; a value is text;
/// a name sent twice is one value, the two joined by a comma, as HTTP joins them.
pub(crate) fn annotations(headers: &HeaderMap) -> Result<BTreeMap<String, String>, Refusal> {
    let mut out = BTreeMap::new();
    let mut total = 0usize;
    for name in headers.keys() {
        let Some(short) = name.as_str().strip_prefix(HEADER_PREFIX) else {
            continue;
        };
        let short = short.to_ascii_lowercase();
        if short.is_empty()
            || !short
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Refusal {
                code: "InvalidArgument",
                message: "a metadata name is x-amz-meta- then a run of a-z 0-9 -",
            });
        }
        let values = headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Refusal {
                code: "InvalidArgument",
                message: "a metadata value is printable ASCII",
            })?;
        let value = values.join(",");
        total = total
            .saturating_add(short.len())
            .saturating_add(value.len());
        if total > MAX_METADATA {
            return Err(Refusal {
                code: "MetadataTooLarge",
                message: "user metadata is at most 2 KiB, names and values together",
            });
        }
        out.insert(format!("{ANNOTATION_PREFIX}{short}"), value);
    }
    Ok(out)
}

/// The user metadata among an object's annotations, as [`annotations`] made them: what a
/// copy carries over.
pub(crate) fn carried(annotations: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    annotations
        .iter()
        .filter(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The `x-amz-meta-*` headers an object's annotations hold; one that cannot be a header any
/// more is left out.
pub(crate) fn headers(
    annotations: &BTreeMap<String, String>,
) -> impl Iterator<Item = (HeaderName, HeaderValue)> + '_ {
    annotations.iter().filter_map(|(k, v)| {
        let short = k.strip_prefix(ANNOTATION_PREFIX)?;
        let name = HeaderName::from_bytes(format!("{HEADER_PREFIX}{short}").as_bytes()).ok()?;
        Some((name, HeaderValue::from_str(v).ok()?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(pairs: &[(&str, &str)]) -> Result<BTreeMap<String, String>, Refusal> {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        annotations(&h)
    }

    #[test]
    fn metadata_round_trips_through_annotations() {
        let a = of(&[
            ("X-Amz-Meta-Mtime", "1700000000"),
            ("x-amz-meta-a-1", "x"),
            ("x-amz-meta-a-1", "y"),
            ("content-type", "text/html"),
            ("x-amz-date", "20260101T000000Z"),
        ])
        .unwrap();
        assert_eq!(
            a,
            BTreeMap::from([
                ("org.virtkit.s3-meta.a-1".to_string(), "x,y".to_string()),
                (
                    "org.virtkit.s3-meta.mtime".to_string(),
                    "1700000000".to_string()
                ),
            ])
        );
        let mut all = a.clone();
        all.insert("org.virtkit.md5".into(), "00".into());
        all.insert("org.virtkit.retention".into(), "keep".into());
        assert_eq!(carried(&all), a);
        let back: Vec<(String, String)> = headers(&all)
            .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
            .collect();
        assert_eq!(
            back,
            [
                ("x-amz-meta-a-1".to_string(), "x,y".to_string()),
                ("x-amz-meta-mtime".to_string(), "1700000000".to_string()),
            ]
        );
        assert_eq!(of(&[]).unwrap(), BTreeMap::new());
    }

    #[test]
    fn names_and_sizes_are_bounded() {
        for bad in ["x-amz-meta-", "x-amz-meta-a_b", "x-amz-meta-a.b"] {
            assert_eq!(
                of(&[(bad, "v")]).unwrap_err().code,
                "InvalidArgument",
                "{bad}"
            );
        }
        let mut h = HeaderMap::new();
        h.insert("x-amz-meta-v", HeaderValue::from_bytes(b"caf\xe9").unwrap());
        assert_eq!(annotations(&h).unwrap_err().code, "InvalidArgument");
        // 2 KiB exactly, names counted without their prefix
        let fill = "v".repeat(MAX_METADATA - 2);
        assert!(of(&[("x-amz-meta-ab", &fill)]).is_ok());
        let over = "v".repeat(MAX_METADATA - 1);
        assert_eq!(
            of(&[("x-amz-meta-ab", &over)]).unwrap_err().code,
            "MetadataTooLarge"
        );
        let half = "v".repeat(MAX_METADATA / 2);
        assert_eq!(
            of(&[("x-amz-meta-a", &half), ("x-amz-meta-b", &half)])
                .unwrap_err()
                .code,
            "MetadataTooLarge"
        );
    }
}
