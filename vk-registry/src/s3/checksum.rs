//! The checksum a write may carry of its body, `x-amz-checksum-<algorithm>` as a header or
//! as an `aws-chunked` body's trailer, in any of S3's algorithms (CRC32, CRC32C, SHA1,
//! SHA256, CRC64NVME, SHA512, MD5, XXHASH64, XXHASH3, XXHASH128): one at most, checked
//! against what arrived, echoed once it held,
//! kept on the manifest as `org.virtkit.s3-checksum` (`<ALGORITHM>:<base64>`) and from there
//! sent back on reads asking for it, listed with the object and reported among its
//! attributes, as the checksum of the whole object (`FULL_OBJECT`).

use std::collections::BTreeMap;

use hyper::header::{HeaderName, HeaderValue};
use sha2::Digest as _;

use super::error::{Code, Refusal};
use super::xml;

/// The manifest annotation holding an object's checksum: S3's name of the algorithm, a
/// colon, the checksum in base64.
pub(crate) const ANNOTATION: &str = "org.virtkit.s3-checksum";

/// S3's name for how a kept checksum was made: of the whole object in one pass.
pub(super) const FULL_OBJECT: &str = "FULL_OBJECT";

/// The header announcing or answering with that.
pub(super) const TYPE_HEADER: &str = "x-amz-checksum-type";

/// How a multipart upload's checksum is made, as `x-amz-checksum-type` names it: of the
/// whole object, or of its parts' checksums (`<base64>-<parts>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum Kind {
    FullObject,
    Composite,
}

impl Kind {
    /// The kind `value` names, in any case.
    pub(super) fn of(value: &[u8]) -> Option<Self> {
        [Kind::FullObject, Kind::Composite]
            .into_iter()
            .find(|k| value.eq_ignore_ascii_case(k.name().as_bytes()))
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Kind::FullObject => FULL_OBJECT,
            Kind::Composite => "COMPOSITE",
        }
    }

    /// Whether a checksum of this kind may be made with `algorithm`, as S3 has them: the
    /// whole object's with a CRC only, the parts' with anything but CRC64NVME.
    pub(super) fn fits(self, algorithm: &str) -> bool {
        match self {
            Kind::FullObject => matches!(algorithm, "CRC32" | "CRC32C" | "CRC64NVME"),
            Kind::Composite => algorithm != "CRC64NVME",
        }
    }

    /// The kind an upload created with `algorithm` and no `x-amz-checksum-type` has.
    pub(super) fn default_for(algorithm: &str) -> Self {
        if algorithm == "CRC64NVME" {
            Kind::FullObject
        } else {
            Kind::Composite
        }
    }
}

/// The refusal of a checksum type `kind` that cannot be made with `algorithm`, as S3 words it.
pub(super) fn unfit(kind: Kind, algorithm: &str) -> Refusal {
    Refusal::saying(
        Code::InvalidRequest,
        format!(
            "The {} checksum type cannot be used with the {} checksum algorithm.",
            kind.name(),
            algorithm.to_ascii_lowercase()
        ),
    )
}

/// The refusal of an `x-amz-checksum-type` sent without the algorithm, as S3 words it.
pub(super) const TYPE_WITHOUT_ALGORITHM: Refusal = Refusal::said(
    Code::InvalidRequest,
    "The x-amz-checksum-type header can only be used with the x-amz-checksum-algorithm header.",
);

/// The refusal of a part whose checksum is in `actual`, or in none, when its upload was
/// created with `expected`, as S3 words it.
pub(super) fn part_mismatch(expected: &str, actual: Option<&str>) -> Refusal {
    Refusal::saying(
        Code::InvalidRequest,
        format!(
            "Checksum Type mismatch occurred, expected checksum Type: {expected}, actual \
             checksum Type: {}",
            actual.unwrap_or("null")
        ),
    )
}

/// S3's algorithms, every one computed here: the header carrying each, S3's name for it, and its length
/// in bytes.
pub(super) const ALGORITHMS: [(&str, &str, usize); 10] = [
    ("x-amz-checksum-crc32", "CRC32", 4),
    ("x-amz-checksum-crc32c", "CRC32C", 4),
    ("x-amz-checksum-sha1", "SHA1", 20),
    ("x-amz-checksum-sha256", "SHA256", 32),
    ("x-amz-checksum-crc64nvme", "CRC64NVME", 8),
    ("x-amz-checksum-sha512", "SHA512", 64),
    ("x-amz-checksum-md5", "MD5", 16),
    ("x-amz-checksum-xxhash64", "XXHASH64", 8),
    ("x-amz-checksum-xxhash3", "XXHASH3", 8),
    ("x-amz-checksum-xxhash128", "XXHASH128", 16),
];

/// The header of the checksum every write is given when it carries none, as S3 gives it.
pub(super) const DEFAULT: &str = "x-amz-checksum-crc64nvme";

/// The prefix of every checksum header, S3's and any it may add.
pub(super) const HEADER_PREFIX: &str = "x-amz-checksum-";

/// The header an SDK names the algorithm of its checksum in, beside the checksum itself.
pub(super) const SDK_ALGORITHM: &str = "x-amz-sdk-checksum-algorithm";

/// The refusal of an `x-amz-checksum-*` header naming no algorithm S3 has, as S3 words it.
pub(super) const UNKNOWN_HEADER: Refusal = Refusal::said(
    Code::InvalidRequest,
    "The algorithm type you specified in x-amz-checksum- header is invalid.",
);

/// The refusal of an algorithm, named by its own header (`x-amz-sdk-checksum-algorithm`,
/// `x-amz-checksum-algorithm`), that S3 does not have, as S3 words it.
pub(super) const UNKNOWN_ALGORITHM: Refusal = Refusal::said(
    Code::InvalidRequest,
    "Checksum algorithm provided is unsupported. Please try again with any of the valid types: \
     [CRC32, CRC32C, CRC64NVME, MD5, SHA1, SHA256, SHA512, XXHASH128, XXHASH3, XXHASH64]",
);

/// The refusal of an `x-amz-trailer` naming no checksum S3 has, as S3 words it.
pub(super) const UNKNOWN_TRAILER: Refusal = Refusal::said(
    Code::InvalidRequest,
    "The value specified in the x-amz-trailer header is not supported",
);

/// The headers beginning with [`HEADER_PREFIX`] that carry no checksum: they name an
/// algorithm, a type or a mode.
const NOT_CHECKSUMS: [&str; 3] = [
    "x-amz-checksum-algorithm",
    "x-amz-checksum-type",
    "x-amz-checksum-mode",
];

/// The refusal of a checksum that did not hold, as S3 words it, naming the algorithm.
pub(super) fn mismatch(header: &str) -> Refusal {
    Refusal::saying(
        Code::BadDigest,
        format!(
            "The {} you specified did not match the calculated checksum.",
            algorithm(header).unwrap_or("MD5")
        ),
    )
}

/// The refusal of a [`SDK_ALGORITHM`] naming an algorithm other than the checksum header's.
pub(super) const ALGORITHM_MISMATCH: Refusal = Refusal::said(
    Code::InvalidRequest,
    "Value for x-amz-sdk-checksum-algorithm header is invalid.",
);

/// The refusal of checksum header `name` when it is not a checksum in base64, as S3 words it.
pub(super) fn invalid(name: &str) -> Refusal {
    Refusal::saying(
        Code::InvalidRequest,
        format!("Value for {name} header is invalid."),
    )
}

/// [`invalid`] for the checksum `name` a trailer carries.
pub(super) fn invalid_trailing(name: &str) -> Refusal {
    Refusal::saying(
        Code::InvalidRequest,
        format!("Value for {name} trailing header is invalid."),
    )
}

/// Why `headers` are refused when they name a checksum, by header or by [`SDK_ALGORITHM`],
/// in an algorithm S3 does not have.
pub(super) fn unknown(headers: &hyper::header::HeaderMap) -> Option<Refusal> {
    let known =
        |name: &str| ALGORITHMS.iter().any(|(h, _, _)| *h == name) || NOT_CHECKSUMS.contains(&name);
    if headers
        .keys()
        .any(|k| k.as_str().starts_with(HEADER_PREFIX) && !known(k.as_str()))
    {
        return Some(UNKNOWN_HEADER);
    }
    headers
        .get_all(SDK_ALGORITHM)
        .iter()
        .any(|v| named(v.as_bytes()).is_none())
        .then_some(UNKNOWN_ALGORITHM)
}

/// S3's name of the algorithm `value` names, in any case.
pub(super) fn named(value: &[u8]) -> Option<&'static str> {
    ALGORITHMS
        .iter()
        .find(|(_, name, _)| value.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, name, _)| *name)
}

/// CRC-32C (Castagnoli), as S3's `CRC32C`.
/// Sixteen lanes of tables (16 KiB, built at compile time) rather than the default one: every
/// write computes a CRC, CRC64NVME by default, as it streams.
static CRC32C: crc::Crc<u32, crc::Table<16>> =
    crc::Crc::<u32, crc::Table<16>>::new(&crc::CRC_32_ISCSI);

/// CRC-64/NVME, as S3's `CRC64NVME`.
/// As [`CRC32C`], with 32 KiB of tables.
static CRC64NVME: crc::Crc<u64, crc::Table<16>> =
    crc::Crc::<u64, crc::Table<16>>::new(&crc::CRC_64_NVME);

/// How many bytes the checksum `header` carries is, for one of [`ALGORITHMS`].
pub(super) fn len(header: &str) -> Option<usize> {
    ALGORITHMS
        .iter()
        .find(|(h, _, _)| *h == header)
        .map(|(_, _, len)| *len)
}

/// S3's name of the algorithm `header` carries.
pub(super) fn algorithm(header: &str) -> Option<&'static str> {
    ALGORITHMS
        .iter()
        .find(|(h, _, _)| *h == header)
        .map(|(_, name, _)| *name)
}

/// The header carrying `algorithm`'s checksum, by S3's name of it.
pub(super) fn header(algorithm: &str) -> Option<&'static str> {
    ALGORITHMS
        .iter()
        .find(|(_, name, _)| *name == algorithm)
        .map(|(h, _, _)| *h)
}

/// A digest of a body as it streams, in the algorithm `header` names: SHA-256 is left to
/// the store, which names every blob by it, but where bytes are read back ([`Hasher::any`]).
pub(super) enum Hasher {
    Sha256(sha2::Sha256),
    Crc32(crc32fast::Hasher),
    Crc32c(crc::Digest<'static, u32, crc::Table<16>>),
    Sha1(sha1::Sha1),
    Crc64nvme(crc::Digest<'static, u64, crc::Table<16>>),
    Sha512(sha2::Sha512),
    Md5(md5::Context),
    Xxhash64(xxhash_rust::xxh64::Xxh64),
    // XXH3's state holds a 256-byte buffer: boxed, so every other hasher stays small.
    Xxhash3(Box<xxhash_rust::xxh3::Xxh3Default>),
    Xxhash128(Box<xxhash_rust::xxh3::Xxh3Default>),
}

impl Hasher {
    /// The hasher for `header`'s algorithm: `None` for SHA-256, and for no algorithm.
    pub(super) fn for_(header: &str) -> Option<Self> {
        Some(match header {
            "x-amz-checksum-crc32" => Hasher::Crc32(crc32fast::Hasher::new()),
            "x-amz-checksum-crc32c" => Hasher::Crc32c(CRC32C.digest()),
            "x-amz-checksum-sha1" => Hasher::Sha1(sha1::Sha1::new()),
            "x-amz-checksum-crc64nvme" => Hasher::Crc64nvme(CRC64NVME.digest()),
            "x-amz-checksum-sha512" => Hasher::Sha512(sha2::Sha512::new()),
            "x-amz-checksum-md5" => Hasher::Md5(md5::Context::new()),
            // S3's XXHASH checksums are unseeded.
            "x-amz-checksum-xxhash64" => Hasher::Xxhash64(xxhash_rust::xxh64::Xxh64::new(0)),
            "x-amz-checksum-xxhash3" => {
                Hasher::Xxhash3(Box::new(xxhash_rust::xxh3::Xxh3Default::new()))
            }
            "x-amz-checksum-xxhash128" => {
                Hasher::Xxhash128(Box::new(xxhash_rust::xxh3::Xxh3Default::new()))
            }
            _ => return None,
        })
    }

    /// [`Hasher::for_`], SHA-256 included.
    pub(super) fn any(header: &str) -> Option<Self> {
        if header == "x-amz-checksum-sha256" {
            return Some(Hasher::Sha256(sha2::Sha256::new()));
        }
        Self::for_(header)
    }

    pub(super) fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Crc32(h) => h.update(data),
            Hasher::Crc32c(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Crc64nvme(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
            Hasher::Md5(h) => h.consume(data),
            Hasher::Xxhash64(h) => h.update(data),
            Hasher::Xxhash3(h) | Hasher::Xxhash128(h) => h.update(data),
        }
    }

    /// The checksum, as the bytes S3 encodes in base64: big-endian for the CRCs and the
    /// XXHASHes (XXH128's high half first), as xxHash's canonical form is.
    pub(super) fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Crc32(h) => h.finalize().to_be_bytes().to_vec(),
            Hasher::Crc32c(h) => h.finalize().to_be_bytes().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Crc64nvme(h) => h.finalize().to_be_bytes().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
            Hasher::Md5(h) => h.finalize().0.to_vec(),
            Hasher::Xxhash64(h) => h.digest().to_be_bytes().to_vec(),
            Hasher::Xxhash3(h) => h.digest().to_be_bytes().to_vec(),
            Hasher::Xxhash128(h) => h.digest128().to_be_bytes().to_vec(),
        }
    }
}

/// The checksum of `data` in the algorithm `header` names, SHA-256 included; `None` for a
/// header that names none.
pub(super) fn of(header: &str, data: &[u8]) -> Option<Vec<u8>> {
    let mut hasher = Hasher::any(header)?;
    hasher.update(data);
    Some(hasher.finalize())
}

/// The checksum, in base64, of the `size` bytes of the blob `layer` (their SHA-256, in hex)
/// in the algorithm `header` names: SHA-256's is the blob's name, any other's is read off it.
/// `None` when the blob is gone.
pub(super) fn of_blob(
    store: &crate::Store,
    layer: &str,
    size: u64,
    header: &str,
) -> anyhow::Result<Option<String>> {
    use std::io::Read as _;
    if header == "x-amz-checksum-sha256" {
        return Ok(super::object::hex_bytes(layer).map(|b| vk_hub_proto::to_base64(&b)));
    }
    let Some(mut hasher) = Hasher::for_(header) else {
        return Ok(None);
    };
    let Some((_, mut reader)) = store.read_blob_range(layer, 0, size)? else {
        return Ok(None);
    };
    let mut buf = vec![0u8; crate::STREAM_CHUNK];
    loop {
        let got = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(got) => got,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(anyhow::Error::from(e).context("reading an object to hash it")),
        };
        hasher.update(buf.get(..got).unwrap_or_default());
    }
    Ok(Some(vk_hub_proto::to_base64(&hasher.finalize())))
}

/// What an object's annotation keeps: the algorithm, by S3's name, and the checksum in
/// base64.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Stored {
    pub(super) algorithm: &'static str,
    pub(super) value: String,
}

/// The annotation keeping `value`, the checksum `header` carried once it held.
pub(super) fn annotation(header: &str, value: &str) -> Option<(String, String)> {
    let algorithm = algorithm(header)?;
    Some((ANNOTATION.to_string(), format!("{algorithm}:{value}")))
}

/// The checksum `annotations` keep, when they keep one this registry wrote: an algorithm it
/// has, and base64 of that algorithm's length.
pub(super) fn stored(annotations: &BTreeMap<String, String>) -> Option<Stored> {
    let (algorithm, value) = annotations.get(ANNOTATION)?.split_once(':')?;
    let header = header(algorithm)?;
    let decoded = crate::auth::base64_decode(value)?;
    (Some(decoded.len()) == len(header)).then(|| Stored {
        algorithm: algorithm_static(algorithm),
        value: value.to_string(),
    })
}

/// `name` as the static S3 name it is, once [`header`] found it.
fn algorithm_static(name: &str) -> &'static str {
    ALGORITHMS
        .iter()
        .find(|(_, n, _)| *n == name)
        .map_or("", |(_, n, _)| *n)
}

impl Stored {
    /// The headers a read asked for the checksum answers with: `x-amz-checksum-<algorithm>`
    /// and the checksum's type.
    pub(super) fn headers(&self) -> impl Iterator<Item = (HeaderName, HeaderValue)> {
        let name = header(self.algorithm).and_then(|h| HeaderName::from_bytes(h.as_bytes()).ok());
        let value = HeaderValue::from_str(&self.value).ok();
        name.zip(value).into_iter().chain([(
            HeaderName::from_static(TYPE_HEADER),
            HeaderValue::from_static(FULL_OBJECT),
        )])
    }

    /// The elements a listing adds to an object: its algorithm and the checksum's type.
    pub(super) fn listed(&self) -> String {
        xml::element("ChecksumAlgorithm", self.algorithm)
            + &xml::element("ChecksumType", FULL_OBJECT)
    }

    /// The elements a `Checksum` attribute or a completed upload's result holds: the
    /// checksum itself, named by its algorithm, and its type.
    pub(super) fn elements(&self) -> String {
        xml::element(&format!("Checksum{}", self.algorithm), &self.value)
            + &xml::element("ChecksumType", FULL_OBJECT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check values of the catalog's algorithms over `123456789`, and SHA-1's.
    #[test]
    fn every_algorithm_is_the_one_s3_names() {
        let b64 = |bytes: &[u8]| vk_hub_proto::to_base64(bytes);
        let of = |header| b64(&of(header, b"123456789").unwrap());
        assert_eq!(
            of("x-amz-checksum-crc32"),
            b64(&0xCBF4_3926u32.to_be_bytes())
        );
        assert_eq!(
            of("x-amz-checksum-crc32c"),
            b64(&0xE306_9283u32.to_be_bytes())
        );
        assert_eq!(
            of("x-amz-checksum-crc64nvme"),
            b64(&0xAE8B_1486_0A79_9888u64.to_be_bytes())
        );
        assert_eq!(
            of("x-amz-checksum-sha1"),
            b64(&sha1::Sha1::digest(b"123456789"))
        );
        assert_eq!(
            of("x-amz-checksum-sha256"),
            b64(&sha2::Sha256::digest(b"123456789"))
        );
        assert_eq!(
            of("x-amz-checksum-sha512"),
            b64(&sha2::Sha512::digest(b"123456789"))
        );
        assert_eq!(of("x-amz-checksum-md5"), b64(&md5::compute(b"123456789").0));
        // xxHash's own values for no input, unseeded.
        let empty = |header| b64(&super::of(header, b"").unwrap());
        assert_eq!(
            empty("x-amz-checksum-xxhash64"),
            b64(&0xEF46_DB37_51D8_E999u64.to_be_bytes())
        );
        assert_eq!(
            empty("x-amz-checksum-xxhash3"),
            b64(&0x2D06_8005_38D3_94C2u64.to_be_bytes())
        );
        assert_eq!(
            empty("x-amz-checksum-xxhash128"),
            b64(&0x99AA_06D3_0147_98D8_6001_C324_468D_497Fu128.to_be_bytes())
        );
        assert_eq!(super::of("x-amz-checksum-xxhash", b""), None);
        // Streamed in pieces, the same.
        let mut h = Hasher::for_("x-amz-checksum-crc64nvme").unwrap();
        h.update(b"1234");
        h.update(b"56789");
        assert_eq!(h.finalize(), 0xAE8B_1486_0A79_9888u64.to_be_bytes());
        for (header, name, len) in ALGORITHMS {
            assert_eq!(super::len(header), Some(len));
            assert_eq!(algorithm(header), Some(name));
            assert_eq!(super::header(name), Some(header));
        }
        assert_eq!(super::len("x-amz-checksum-xxhash"), None);
        let of = |pairs: &[(&str, &str)]| {
            let mut h = hyper::header::HeaderMap::new();
            for (n, v) in pairs {
                h.append(
                    HeaderName::from_bytes(n.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            unknown(&h)
        };
        assert_eq!(of(&[]), None);
        assert_eq!(
            of(&[
                ("x-amz-checksum-crc32c", "AAAAAA=="),
                (SDK_ALGORITHM, "crc32c")
            ]),
            None
        );
        assert_eq!(of(&[("x-amz-checksum-xxhash128", "x")]), None);
        assert_eq!(of(&[(SDK_ALGORITHM, "XXHASH3")]), None);
        assert_eq!(of(&[("x-amz-checksum-type", "COMPOSITE")]), None);
        assert_eq!(of(&[("x-amz-checksum-xxhash", "x")]), Some(UNKNOWN_HEADER));
        assert_eq!(of(&[("x-amz-checksum-", "x")]), Some(UNKNOWN_HEADER));
        assert_eq!(of(&[(SDK_ALGORITHM, "")]), Some(UNKNOWN_ALGORITHM));
        assert_eq!(of(&[(SDK_ALGORITHM, "XXHASH")]), Some(UNKNOWN_ALGORITHM));
        for (header, name, _) in ALGORITHMS {
            assert!(
                mismatch(header)
                    .message()
                    .starts_with(&format!("The {name} you"))
            );
        }
    }

    #[test]
    fn a_kept_checksum_round_trips_through_its_annotation() {
        let value = vk_hub_proto::to_base64(&[1, 2, 3, 4]);
        let (name, text) = annotation("x-amz-checksum-crc32c", &value).unwrap();
        assert_eq!(
            (name.as_str(), text.as_str()),
            (ANNOTATION, "CRC32C:AQIDBA==")
        );
        let annotations = BTreeMap::from([(name, text)]);
        let kept = stored(&annotations).unwrap();
        assert_eq!(kept.algorithm, "CRC32C");
        assert_eq!(kept.value, value);
        let headers: Vec<(String, String)> = kept
            .headers()
            .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
            .collect();
        assert_eq!(
            headers,
            [
                ("x-amz-checksum-crc32c".to_string(), value.clone()),
                ("x-amz-checksum-type".to_string(), "FULL_OBJECT".to_string()),
            ]
        );
        assert_eq!(
            kept.listed(),
            "<ChecksumAlgorithm>CRC32C</ChecksumAlgorithm><ChecksumType>FULL_OBJECT</ChecksumType>"
        );
        assert_eq!(
            kept.elements(),
            "<ChecksumCRC32C>AQIDBA==</ChecksumCRC32C><ChecksumType>FULL_OBJECT</ChecksumType>"
        );
        assert_eq!(annotation("x-amz-checksum-xxhash", &value), None);
        // Nothing kept, or something this registry did not write.
        let of = |text: &str| {
            stored(&BTreeMap::from([(
                ANNOTATION.to_string(),
                text.to_string(),
            )]))
        };
        assert_eq!(of("CRC32C:AQID"), None);
        assert_eq!(of("XXHASH64:AQIDBA=="), None);
        assert_eq!(of("XXHASH:AQIDBA=="), None);
        assert_eq!(of("MD5:AQIDBA=="), None);
        assert_eq!(of("AQIDBA=="), None);
        assert_eq!(of("CRC32C:!!"), None);
        assert_eq!(stored(&BTreeMap::new()), None);
    }
}
