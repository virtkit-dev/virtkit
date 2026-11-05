//! AWS Signature Version 4 over the `Authorization` header: parsing the header, the clock
//! check, the canonical request, the string to sign and the signature. Pure functions: the
//! region, the service and the payload hash are parameters, so AWS's generic signing suite
//! (service `service`, no `x-amz-content-sha256`) drives them as it is; what S3 requires of a
//! request on top of that is [`s3_refusal`], which the gate applies.
//!
//! The canonical request is S3's: the path is never normalised (`.`, `..` and `//` are part
//! of a key), each segment is percent-decoded once and re-encoded with the unreserved set.

use hmac::{Hmac, KeyInit, Mac};
use hyper::HeaderMap;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The one algorithm taken, which is also the scheme of the `Authorization` header.
pub(crate) const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// How far a request's time may be from the server's, either way: AWS's window.
pub(crate) const MAX_SKEW_SECS: u64 = 15 * 60;

/// The scope's last field, and the last HMAC of the signing key's chain.
const TERMINATOR: &str = "aws4_request";

/// A parsed `Authorization: AWS4-HMAC-SHA256 …` header, borrowing from its value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Credential<'a> {
    /// The access key id: everything before the scope's four fields, `/` included.
    pub(crate) id: &'a str,
    /// The scope's date, `YYYYMMDD`.
    pub(crate) date: &'a str,
    pub(crate) region: &'a str,
    pub(crate) service: &'a str,
    pub(crate) terminator: &'a str,
    /// The signed header names, lowercase, sorted and without duplicates.
    pub(crate) signed_headers: Vec<&'a str>,
    /// The presented signature, 64 lowercase hex digits.
    pub(crate) signature: &'a str,
}

impl Credential<'_> {
    /// `date/region/service/terminator`, as the string to sign carries it.
    pub(crate) fn scope(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.date, self.region, self.service, self.terminator
        )
    }
}

/// Parse an `Authorization` value: `AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/<service>/
/// <terminator>, SignedHeaders=<a;b;…>, Signature=<hex>`, the fields in any order, separated
/// by commas with or without spaces. The scope is split from the right, so an id may hold a
/// `/` and a scope field may not. The reason a value is malformed otherwise.
pub(crate) fn parse_authorization(value: &str) -> Result<Credential<'_>, &'static str> {
    let fields = value
        .strip_prefix(ALGORITHM)
        .and_then(|r| r.strip_prefix(' '))
        .ok_or("the algorithm must be AWS4-HMAC-SHA256")?;
    let (mut credential, mut signed, mut signature) = (None, None, None);
    for field in fields.split(',') {
        let (name, v) = field
            .trim()
            .split_once('=')
            .ok_or("each field must be Name=value")?;
        let slot = match name {
            "Credential" => &mut credential,
            "SignedHeaders" => &mut signed,
            "Signature" => &mut signature,
            _ => return Err("unknown field: only Credential, SignedHeaders and Signature"),
        };
        if slot.replace(v).is_some() {
            return Err("a field is given twice");
        }
    }
    let credential = credential.ok_or("Credential is missing")?;
    let signed = signed.ok_or("SignedHeaders is missing")?;
    let signature = signature.ok_or("Signature is missing")?;

    let mut scope = credential.rsplitn(5, '/');
    let (Some(terminator), Some(service), Some(region), Some(date), Some(id)) = (
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
    ) else {
        return Err("Credential must be <id>/<date>/<region>/<service>/aws4_request");
    };
    if id.is_empty() || region.is_empty() || service.is_empty() || terminator.is_empty() {
        return Err("Credential has an empty field");
    }
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the credential's date must be YYYYMMDD");
    }
    let mut signed_headers = Vec::new();
    for name in signed.split(';') {
        if name.is_empty() || !name.bytes().all(is_lowercase_token) {
            return Err("SignedHeaders must be lowercase header names separated by ';'");
        }
        signed_headers.push(name);
    }
    signed_headers.sort_unstable();
    signed_headers.dedup();
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Signature must be 64 lowercase hex digits");
    }
    Ok(Credential {
        id,
        date,
        region,
        service,
        terminator,
        signed_headers,
        signature,
    })
}

/// A header-name byte (RFC 9110 `tchar`), lowercase.
fn is_lowercase_token(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// What S3 requires of a SigV4 request beyond the signature: its scope names the service
/// `s3` and ends in `aws4_request`, and it signs `host` (what it was sent to) and
/// `x-amz-content-sha256` (what it carries). The reason, when it does not.
pub(crate) fn s3_refusal(credential: &Credential<'_>) -> Option<&'static str> {
    if credential.service != "s3" {
        return Some("the credential's service must be s3");
    }
    if credential.terminator != TERMINATOR {
        return Some("the credential must end in aws4_request");
    }
    for required in ["host", "x-amz-content-sha256"] {
        if !credential.signed_headers.contains(&required) {
            return Some(if required == "host" {
                "SignedHeaders must include host"
            } else {
                "SignedHeaders must include x-amz-content-sha256"
            });
        }
    }
    None
}

/// The first `x-amz-*` header of `headers` the signature does not cover: S3 refuses a request
/// carrying one, as anything on its way could have added it.
pub(crate) fn unsigned_amz_header<'h>(
    credential: &Credential<'_>,
    headers: &'h HeaderMap,
) -> Option<&'h str> {
    headers
        .keys()
        .map(|name| name.as_str())
        .find(|name| name.starts_with("x-amz-") && !credential.signed_headers.contains(name))
}

/// Why a request's time is refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Clock {
    /// Not ISO 8601 basic (`YYYYMMDDTHHMMSSZ`), or before 1970.
    Unreadable,
    /// Not on the credential scope's date.
    OtherDay,
    /// More than [`MAX_SKEW_SECS`] from `now`.
    Skewed,
}

/// Check the request's time `stamp` against the scope's `date` and the server's `now`.
pub(crate) fn check_clock(stamp: &str, date: &str, now: u64) -> Result<(), Clock> {
    let at = parse_stamp(stamp).ok_or(Clock::Unreadable)?;
    if stamp.get(..8) != Some(date) {
        return Err(Clock::OtherDay);
    }
    if at.abs_diff(now) > MAX_SKEW_SECS {
        return Err(Clock::Skewed);
    }
    Ok(())
}

/// Seconds since the epoch of an ISO 8601 basic UTC time, `YYYYMMDDTHHMMSSZ`.
pub(crate) fn parse_stamp(stamp: &str) -> Option<u64> {
    let b = stamp.as_bytes();
    if b.len() != 16 || b.get(8) != Some(&b'T') || b.get(15) != Some(&b'Z') {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<u32> {
        let digits = stamp.get(from..to)?;
        digits
            .bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| digits.parse().ok())?
    };
    let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (h, mi, s) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
    if !(1..=12).contains(&mo) || d == 0 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 59
    {
        return None;
    }
    let days = u64::try_from(days_from_civil(i64::from(y), mo, d)).ok()?;
    Some(days * 86_400 + u64::from(h) * 3600 + u64::from(mi) * 60 + u64::from(s))
}

/// `secs` since the epoch as ISO 8601 extended UTC, `YYYY-MM-DDTHH:MM:SSZ`: how S3 writes
/// its `ServerTime`.
pub(crate) fn format_time(secs: u64) -> String {
    // `u64::MAX / 86_400` fits an `i64`: this never falls back.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (y, m, d) = civil_from_days(days);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        2 if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let (m, d) = (i64::from(m), i64::from(d));
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Why a request has no canonical form.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Canon<'a> {
    /// A path segment with a malformed escape, or not UTF-8 once decoded.
    Path,
    /// The same, in a query name or value.
    Query,
    /// A signed header the request does not carry.
    Missing(&'a str),
    /// A signed header whose value is not text.
    NotText(&'a str),
}

/// The canonical request: method, canonical URI, canonical query, canonical headers, signed
/// header list and payload hash, one per line. `raw_path` and `raw_query` are as the request
/// line carries them; `payload_hash` is what the string to sign binds the body by (for S3,
/// the `x-amz-content-sha256` value as sent).
pub(crate) fn canonical_request<'s>(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    headers: &HeaderMap,
    signed: &[&'s str],
    payload_hash: &str,
) -> Result<String, Canon<'s>> {
    let uri = canonical_uri(raw_path).ok_or(Canon::Path)?;
    let query = canonical_query(raw_query).ok_or(Canon::Query)?;
    let mut out = format!("{method}\n{uri}\n{query}\n");
    for &name in signed {
        let mut values = headers.get_all(name).iter().peekable();
        if values.peek().is_none() {
            return Err(Canon::Missing(name));
        }
        out.push_str(name);
        out.push(':');
        for (i, v) in values.enumerate() {
            let v = std::str::from_utf8(v.as_bytes()).map_err(|_| Canon::NotText(name))?;
            if i > 0 {
                out.push(',');
            }
            push_collapsed(&mut out, v);
        }
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&signed.join(";"));
    out.push('\n');
    out.push_str(payload_hash);
    Ok(out)
}

/// `value` trimmed, each inner run of spaces and tabs written as one space.
fn push_collapsed(out: &mut String, value: &str) {
    for (i, word) in value
        .split([' ', '\t'])
        .filter(|w| !w.is_empty())
        .enumerate()
    {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(word);
    }
}

/// The path, each `/`-separated segment percent-decoded then re-encoded, never normalised.
/// Splitting before decoding keeps an encoded `%2F` inside its segment.
pub(crate) fn canonical_uri(raw_path: &str) -> Option<String> {
    let mut out = String::with_capacity(raw_path.len());
    for (i, segment) in raw_path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&reencode(segment)?);
    }
    Some(out)
}

/// The query's pairs, each name and value decoded then re-encoded, a bare name as `name=`,
/// sorted by name then value.
pub(crate) fn canonical_query(raw_query: &str) -> Option<String> {
    let mut pairs = Vec::new();
    for pair in raw_query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        pairs.push((reencode(name)?, reencode(value)?));
    }
    pairs.sort_unstable();
    let mut out = String::with_capacity(raw_query.len());
    for (i, (name, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(name);
        out.push('=');
        out.push_str(value);
    }
    Some(out)
}

/// One URI component in SigV4's encoding: `%XX` escapes decoded (a `+` is itself), the
/// result encoded again with everything but the unreserved set escaped.
fn reencode(raw: &str) -> Option<String> {
    Some(crate::percent_encode(&crate::dav::decode_segment(raw)?))
}

/// The string to sign for a request made at `stamp` under `scope`.
pub(crate) fn string_to_sign(stamp: &str, scope: &str, canonical_request: &str) -> String {
    let hashed = crate::hex_of(&Sha256::digest(canonical_request.as_bytes()));
    format!("{ALGORITHM}\n{stamp}\n{scope}\n{hashed}")
}

/// HMAC-SHA256 of `data` under `key`, in a buffer wiped on drop. `None` never happens for
/// HMAC, which takes a key of any length; it is not turned into a key of zeros instead.
fn hmac(key: &[u8], data: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).ok()?;
    mac.update(data);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Some(out)
}

/// The key a scope's signatures are made with, derived from a secret and wiped when dropped.
/// A request's own signature needs it only for the call that checks it ([`signature`]); the
/// chunk signatures of an `aws-chunked` body need it for as long as the body streams.
pub(crate) struct SigningKey(Zeroizing<[u8; 32]>);

impl SigningKey {
    /// The key `secret` gives the scope `date/region/service/aws4_request`; the keys derived
    /// on the way are wiped as they are dropped.
    pub(crate) fn derive(secret: &str, date: &str, region: &str, service: &str) -> Option<Self> {
        let seed = Zeroizing::new(format!("AWS4{secret}").into_bytes());
        let k_date = hmac(&seed, date.as_bytes())?;
        let k_region = hmac(&*k_date, region.as_bytes())?;
        let k_service = hmac(&*k_region, service.as_bytes())?;
        Some(SigningKey(hmac(&*k_service, TERMINATOR.as_bytes())?))
    }

    /// The hex signature of `string_to_sign` under this key.
    pub(crate) fn sign(&self, string_to_sign: &str) -> Option<String> {
        let signed = hmac(&*self.0, string_to_sign.as_bytes())?;
        Some(crate::hex_of(&*signed))
    }
}

/// The hex signature of `string_to_sign` under the key derived from `secret` for the scope
/// `date/region/service/aws4_request`. The derived keys live in this call only, each wiped
/// when dropped; nothing but the signature leaves it.
pub(crate) fn signature(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> Option<String> {
    SigningKey::derive(secret, date, region, service)?.sign(string_to_sign)
}

/// Whether `credential`'s signature is the one `secret` gives `canonical_request` made at
/// `stamp`, compared in constant time.
pub(crate) fn signature_matches(
    secret: &str,
    credential: &Credential<'_>,
    stamp: &str,
    canonical_request: &str,
) -> bool {
    let sts = string_to_sign(stamp, &credential.scope(), canonical_request);
    signature(
        secret,
        credential.date,
        credential.region,
        credential.service,
        &sts,
    )
    .is_some_and(|ours| crate::auth::constant_eq(ours.as_bytes(), credential.signature.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// A request as the suite writes one: the request line, `Name:value` headers (a line
    /// starting with whitespace continues the one above), a blank line, the body.
    struct Request {
        method: String,
        path: String,
        query: String,
        headers: HeaderMap,
        body: String,
    }

    fn parse_request(text: &str) -> Request {
        let (head, body) = text.split_once("\n\n").unwrap_or((text, ""));
        let mut lines = head.lines();
        let line = lines.next().unwrap();
        let (method, target) = line.split_once(' ').unwrap();
        let target = target.strip_suffix(" HTTP/1.1").unwrap();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut fields: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.starts_with([' ', '\t']) {
                let last = fields.last_mut().unwrap();
                last.1.push(' ');
                last.1.push_str(line.trim());
            } else {
                // As an HTTP parser does, the value without its surrounding whitespace.
                let (name, value) = line.split_once(':').unwrap();
                fields.push((name.to_string(), value.trim().to_string()));
            }
        }
        let mut headers = HeaderMap::new();
        for (name, value) in fields {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(&value).unwrap(),
            );
        }
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: query.to_string(),
            headers,
            body: body.to_string(),
        }
    }

    /// Everything a header-signed request yields: its canonical request, string to sign and
    /// signature under `secret`, and whether the signature it carries verifies.
    struct Signed {
        canonical: String,
        string_to_sign: String,
        signature: String,
        verifies: bool,
    }

    fn sign(req: &Request, secret: &str, payload_hash: &str) -> Signed {
        let auth = req.headers["authorization"].to_str().unwrap();
        let cred = parse_authorization(auth).unwrap();
        let stamp = req.headers["x-amz-date"].to_str().unwrap();
        let canonical = canonical_request(
            &req.method,
            &req.path,
            &req.query,
            &req.headers,
            &cred.signed_headers,
            payload_hash,
        )
        .unwrap();
        let string_to_sign = string_to_sign(stamp, &cred.scope(), &canonical);
        let signature = signature(
            secret,
            cred.date,
            cred.region,
            cred.service,
            &string_to_sign,
        )
        .unwrap();
        let verifies = signature_matches(secret, &cred, stamp, &canonical);
        Signed {
            canonical,
            string_to_sign,
            signature,
            verifies,
        }
    }

    /// Every case of AWS's signing suite (see `testdata/sigv4/README`) reproduces its
    /// canonical request, string to sign and signature, and its signed request verifies. A
    /// `-normalized` case is the request its `-unnormalized` twin signs, with the path
    /// normalised as services other than S3 do: S3 does not, so its canonical request must be
    /// the twin's.
    #[test]
    fn the_aws_signing_suite_verifies() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/s3/testdata/sigv4");
        let mut cases: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_dir())
            .collect();
        cases.sort();
        assert_eq!(cases.len(), 38, "the vendored suite is whole");
        let read = |case: &std::path::Path, file: &str| {
            std::fs::read_to_string(case.join(file))
                .unwrap_or_else(|e| panic!("{}/{file}: {e}", case.display()))
        };
        let mut twinned = 0;
        for case in &cases {
            let name = case.file_name().unwrap().to_str().unwrap();
            let context: serde_json::Value =
                serde_json::from_str(&read(case, "context.json")).unwrap();
            let secret = context["credentials"]["secret_access_key"]
                .as_str()
                .unwrap();
            let req = parse_request(&read(case, "header-signed-request.txt"));
            let payload_hash = match req.headers.get("x-amz-content-sha256") {
                Some(v) => v.to_str().unwrap().to_string(),
                None if context["sign_body"] == true => {
                    crate::hex_of(&Sha256::digest(req.body.as_bytes()))
                }
                None => EMPTY_SHA256.to_string(),
            };
            let signed = sign(&req, secret, &payload_hash);
            if let Some(stem) = name.strip_suffix("-normalized") {
                assert_eq!(context["normalize"], true, "{name}");
                let twin = root.join(format!("{stem}-unnormalized"));
                assert_eq!(
                    signed.canonical,
                    read(&twin, "header-canonical-request.txt"),
                    "{name}: S3 signs the path as sent"
                );
                twinned += 1;
                continue;
            }
            assert_eq!(
                signed.canonical,
                read(case, "header-canonical-request.txt"),
                "{name}"
            );
            assert_eq!(
                signed.string_to_sign,
                read(case, "header-string-to-sign.txt"),
                "{name}"
            );
            assert_eq!(
                signed.signature,
                read(case, "header-signature.txt").trim(),
                "{name}"
            );
            assert!(signed.verifies, "{name}");
        }
        assert_eq!(twinned, 7, "every -normalized case has its twin");
    }

    const S3_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    /// AWS's S3 examples ("Signature Calculations for the Authorization Header: Transferring
    /// Payload in a Single Chunk"): each request, as written there with its Authorization
    /// header, parses, passes S3's policy, and verifies to the documented canonical request
    /// and signature. Virtual-hosted, as AWS signs them, which changes nothing here: the
    /// signature covers the `Host` and path as sent.
    #[test]
    fn the_aws_s3_examples_verify() {
        let date = "x-amz-date:20130524T000000Z";
        let empty = format!("x-amz-content-sha256:{EMPTY_SHA256}");
        let put_hash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
        let cases: [(&str, &str, Vec<String>, &str, &str); 4] = [
            (
                "GET /test.txt",
                "host;range;x-amz-content-sha256;x-amz-date",
                vec!["range:bytes=0-9".into(), empty.clone(), date.into()],
                "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n\
                 x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                 x-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\n\
                 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            ),
            (
                "PUT /test$file.text",
                "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
                vec![
                    "date:Fri, 24 May 2013 00:00:00 GMT".into(),
                    date.into(),
                    "x-amz-storage-class:REDUCED_REDUNDANCY".into(),
                    format!("x-amz-content-sha256:{put_hash}"),
                ],
                "PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\n\
                 host:examplebucket.s3.amazonaws.com\n\
                 x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\n\
                 x-amz-date:20130524T000000Z\nx-amz-storage-class:REDUCED_REDUNDANCY\n\n\
                 date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n\
                 44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
                "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
            ),
            (
                "GET /?lifecycle",
                "host;x-amz-content-sha256;x-amz-date",
                vec![date.into(), empty.clone()],
                "GET\n/\nlifecycle=\nhost:examplebucket.s3.amazonaws.com\n\
                 x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                 x-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\n\
                 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
            ),
            (
                "GET /?max-keys=2&prefix=J",
                "host;x-amz-content-sha256;x-amz-date",
                vec![date.into(), empty.clone()],
                "GET\n/\nmax-keys=2&prefix=J\nhost:examplebucket.s3.amazonaws.com\n\
                 x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                 x-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\n\
                 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
            ),
        ];
        for (line, signed, extra, canonical, sig) in cases {
            let mut text = format!(
                "{line} HTTP/1.1\nHost: examplebucket.s3.amazonaws.com\nAuthorization: \
                 AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/\
                 aws4_request,SignedHeaders={signed},Signature={sig}\n"
            );
            for h in &extra {
                text.push_str(h);
                text.push('\n');
            }
            let req = parse_request(&text);
            let cred = parse_authorization(req.headers["authorization"].to_str().unwrap()).unwrap();
            assert_eq!(cred.id, "AKIAIOSFODNN7EXAMPLE");
            assert_eq!(s3_refusal(&cred), None, "{line}");
            let payload = req.headers["x-amz-content-sha256"].to_str().unwrap();
            let signed = sign(&req, S3_SECRET, payload);
            assert_eq!(signed.canonical, canonical, "{line}");
            assert_eq!(signed.signature, sig, "{line}");
            assert!(signed.verifies, "{line}");
            // Another secret, or one byte of the request changed, and it no longer does.
            assert!(!sign(&req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEz", payload).verifies);
            let moved = parse_request(&text.replacen(" /", " /x", 1));
            assert!(!sign(&moved, S3_SECRET, payload).verifies, "{line}");
        }
    }

    fn header(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn a_query_is_canonical_whatever_its_order_and_encoding() {
        let want = "%E1%88%B4=v&a=1&a=2&b=x%20y&c=&d=%2B";
        for q in [
            "b=x%20y&a=2&a=1&c=&d=%2B&%E1%88%B4=v",
            "a=1&%e1%88%b4=v&b=x%20y&a=2&c&d=%2b",
            "d=%2B&c&&b=x%20y&a=%32&a=%31&ሴ=v",
        ] {
            assert_eq!(canonical_query(q).as_deref(), Some(want), "{q}");
        }
        // A `+` is itself, encoded, not a space; a bare key and an empty value are the same.
        assert_eq!(canonical_query("k=a+b").as_deref(), Some("k=a%2Bb"));
        assert_eq!(canonical_query("uploads").as_deref(), Some("uploads="));
        assert_eq!(canonical_query("uploads=").as_deref(), Some("uploads="));
        assert_eq!(canonical_query("").as_deref(), Some(""));
        // Sorted by name, then by value, on the encoded bytes.
        assert_eq!(
            canonical_query("x=b&x=a&X=c").as_deref(),
            Some("X=c&x=a&x=b")
        );
        assert_eq!(canonical_query("a=%zz"), None);
        assert_eq!(canonical_query("a=%ff"), None, "not UTF-8 once decoded");
    }

    #[test]
    fn a_path_is_encoded_once_and_never_normalised() {
        for (raw, want) in [
            ("/", "/"),
            ("/b/a%20b/c", "/b/a%20b/c"),
            ("/b/a b", "/b/a%20b"),
            ("/b/%7Ex~", "/b/~x~"),
            ("/b/a%2Fb", "/b/a%2Fb"),
            ("/b//./../k/", "/b//./../k/"),
            ("/b/a+b$", "/b/a%2Bb%24"),
        ] {
            assert_eq!(canonical_uri(raw).as_deref(), Some(want), "{raw}");
        }
        assert_eq!(canonical_uri("/b/%2"), None);
        assert_eq!(canonical_uri("/b/%C3%28"), None);
    }

    #[test]
    fn header_values_are_trimmed_collapsed_and_joined() {
        let h = header(&[
            ("host", "h"),
            ("x-amz-meta-a", "  one \t two   three  "),
            ("x-amz-meta-b", "1"),
            ("x-amz-meta-b", " 2 "),
            ("x-amz-meta-b", "3"),
            ("x-amz-meta-unsigned", "ignored"),
        ]);
        let creq = canonical_request(
            "GET",
            "/",
            "",
            &h,
            &["host", "x-amz-meta-a", "x-amz-meta-b"],
            "UNSIGNED-PAYLOAD",
        )
        .unwrap();
        assert_eq!(
            creq,
            "GET\n/\n\nhost:h\nx-amz-meta-a:one two three\nx-amz-meta-b:1,2,3\n\n\
             host;x-amz-meta-a;x-amz-meta-b\nUNSIGNED-PAYLOAD"
        );
        assert_eq!(
            canonical_request("GET", "/", "", &h, &["host", "x-amz-date"], "-"),
            Err(Canon::Missing("x-amz-date"))
        );
        let mut binary = HeaderMap::new();
        binary.insert("x-b", HeaderValue::from_bytes(&[0xff, b'a']).unwrap());
        assert_eq!(
            canonical_request("GET", "/", "", &binary, &["x-b"], "-"),
            Err(Canon::NotText("x-b"))
        );
    }

    const SIG: &str = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";

    fn authorization(credential: &str, signed: &str) -> String {
        format!("AWS4-HMAC-SHA256 Credential={credential}, SignedHeaders={signed}, Signature={SIG}")
    }

    #[test]
    fn the_scope_is_split_from_the_right() {
        let value = authorization(
            "team/ci/key/20130524/auto/s3/aws4_request",
            "x-amz-date;host;x-amz-content-sha256",
        );
        let cred = parse_authorization(&value).unwrap();
        assert_eq!(cred.id, "team/ci/key");
        assert_eq!(cred.date, "20130524");
        assert_eq!(cred.region, "auto");
        assert_eq!(cred.service, "s3");
        assert_eq!(cred.terminator, "aws4_request");
        assert_eq!(cred.scope(), "20130524/auto/s3/aws4_request");
        assert_eq!(
            cred.signed_headers,
            ["host", "x-amz-content-sha256", "x-amz-date"],
            "sorted"
        );
        assert_eq!(cred.signature, SIG);
        assert_eq!(s3_refusal(&cred), None);
    }

    #[test]
    fn a_malformed_authorization_is_refused() {
        let ok = "id/20130524/us-east-1/s3/aws4_request";
        let signed = "host;x-amz-content-sha256";
        for bad in [
            format!("AWS4-HMAC-SHA1 Credential={ok}, SignedHeaders={signed}, Signature={SIG}"),
            format!("AWS4-HMAC-SHA256 Credential={ok}, SignedHeaders={signed}"),
            format!("AWS4-HMAC-SHA256 Credential={ok}, Signature={SIG}"),
            format!("AWS4-HMAC-SHA256 SignedHeaders={signed}, Signature={SIG}"),
            format!("{}, Signature={SIG}", authorization(ok, signed)),
            format!("{}, Other=1", authorization(ok, signed)),
            format!("{} junk", authorization(ok, signed)),
            authorization("20130524/us-east-1/s3/aws4_request", signed),
            authorization("/20130524/us-east-1/s3/aws4_request", signed),
            authorization("id/2013052/us-east-1/s3/aws4_request", signed),
            authorization("id/2013O524/us-east-1/s3/aws4_request", signed),
            authorization("id/20130524//s3/aws4_request", signed),
            authorization(ok, "Host;x-amz-content-sha256"),
            authorization(ok, "host;;x-amz-content-sha256"),
            authorization(ok, "host x-amz-content-sha256"),
            authorization(ok, signed).replace(SIG, &SIG.to_uppercase()),
            authorization(ok, signed).replace(SIG, &SIG[1..]),
            String::new(),
            "AWS4-HMAC-SHA256".to_string(),
            "AWS4-HMAC-SHA256 ".to_string(),
        ] {
            assert!(parse_authorization(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_x_amz_header_is_signed() {
        let header = authorization(
            "id/20130524/us-east-1/s3/aws4_request",
            "host;x-amz-content-sha256;x-amz-date;x-amz-meta-x",
        );
        let cred = parse_authorization(&header).unwrap();
        let mut headers = HeaderMap::new();
        for name in [
            "x-amz-content-sha256",
            "x-amz-date",
            "x-amz-meta-x",
            "range",
        ] {
            headers.insert(
                hyper::header::HeaderName::from_static(name),
                hyper::header::HeaderValue::from_static("v"),
            );
        }
        assert_eq!(unsigned_amz_header(&cred, &headers), None);
        headers.insert(
            hyper::header::HeaderName::from_static("x-amz-meta-y"),
            hyper::header::HeaderValue::from_static("v"),
        );
        assert_eq!(unsigned_amz_header(&cred, &headers), Some("x-amz-meta-y"));
    }

    #[test]
    fn s3_requires_its_service_and_both_headers_signed() {
        let refusal = |credential: &str, signed: &str| {
            s3_refusal(&parse_authorization(&authorization(credential, signed)).unwrap())
        };
        let ok = "id/20130524/us-east-1/s3/aws4_request";
        assert_eq!(refusal(ok, "host;x-amz-content-sha256;x-amz-date"), None);
        assert!(refusal(ok, "x-amz-content-sha256;x-amz-date").is_some());
        assert!(refusal(ok, "host;x-amz-date").is_some());
        assert!(
            refusal(
                "id/20130524/us-east-1/service/aws4_request",
                "host;x-amz-content-sha256"
            )
            .is_some()
        );
        assert!(
            refusal(
                "id/20130524/us-east-1/s3/aws4_requesT",
                "host;x-amz-content-sha256"
            )
            .is_some()
        );
    }

    #[test]
    fn the_clock_must_be_on_the_scope_day_and_within_fifteen_minutes() {
        let at = parse_stamp("20130524T120000Z").unwrap();
        assert_eq!(at, 1_369_396_800);
        assert_eq!(format_time(at), "2013-05-24T12:00:00Z");
        assert_eq!(check_clock("20130524T120000Z", "20130524", at), Ok(()));
        for ok in [14 * 60 + 59, 15 * 60] {
            assert_eq!(check_clock("20130524T120000Z", "20130524", at + ok), Ok(()));
            assert_eq!(check_clock("20130524T120000Z", "20130524", at - ok), Ok(()));
        }
        assert_eq!(
            check_clock("20130524T120000Z", "20130524", at + 15 * 60 + 1),
            Err(Clock::Skewed)
        );
        assert_eq!(
            check_clock("20130524T120000Z", "20130524", at - 15 * 60 - 1),
            Err(Clock::Skewed)
        );
        // On the day after the scope's, even within the window.
        assert_eq!(
            check_clock("20130525T000100Z", "20130524", at + 12 * 3600),
            Err(Clock::OtherDay)
        );
        for bad in [
            "",
            "20130524T120000",
            "20130524 120000Z",
            "2013-05-24T12:00:00Z",
            "20131324T120000Z",
            "20130230T120000Z",
            "20130524T240000Z",
            "20130524T126000Z",
            "+0130524T120000Z",
            "Fri, 24 May 2013 12:00:00 GMT",
        ] {
            assert_eq!(
                check_clock(bad, "20130524", at),
                Err(Clock::Unreadable),
                "{bad}"
            );
        }
        assert_eq!(parse_stamp("19700101T000000Z"), Some(0));
        assert_eq!(parse_stamp("20000229T235959Z"), Some(951_868_799));
        assert_eq!(format_time(951_868_799), "2000-02-29T23:59:59Z");
    }

    /// What signing hands back is the hex signature and nothing else: no derived key is
    /// returned or kept, so none outlives the call.
    #[test]
    fn signing_returns_the_signature_only() {
        let f: fn(&str, &str, &str, &str, &str) -> Option<String> = signature;
        let sig = f(S3_SECRET, "20130524", "us-east-1", "s3", "x").unwrap();
        assert_eq!(sig.len(), 64);
        assert_ne!(
            sig,
            f(S3_SECRET, "20130525", "us-east-1", "s3", "x").unwrap()
        );
        assert_ne!(sig, f(S3_SECRET, "20130524", "auto", "s3", "x").unwrap());
    }
}
