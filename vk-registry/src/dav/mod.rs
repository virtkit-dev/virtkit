//! WebDAV under `/dav/`: writable plain files in `files/` and a read-only OCI view in `repos/`.
//! OCI downloads reuse `/v2/` handlers and authorization; OCI writes remain on `/v2/`. Supports
//! `PROPFIND` (Depth 0/1), `GET`, `HEAD`, `PUT`, `MKCOL`, `DELETE` and `OPTIONS`. PROPFIND
//! bodies are drained without parsing XML. Listings are scope-filtered; root enumeration
//! requires configured credentials. See `DESIGN.md`.

mod files;
mod repos;

use std::fmt::Write as _;
use std::time::SystemTime;

use anyhow::Result;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{ALLOW, CONTENT_LENGTH, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use hyper::{Request, Response, StatusCode};

use crate::{Authenticator, Authz, Body, ServerState, body_of, error_response};

/// Maximum path depth below `/dav/<area>/`.
pub(crate) const MAX_DEPTH: usize = 32;

/// Maximum decoded component length in bytes.
const MAX_SEGMENT: usize = 255;

/// Maximum PROPFIND body size; the body is drained and ignored.
const MAX_PROPFIND_BODY: usize = 64 * 1024;

/// The verbs `files/` answers, for `OPTIONS` and for the `Allow` on a 405.
const ALLOWED_FILES: &str = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL";

/// The verbs a read-only resource answers: the root, `repos/`, and the `files/` root.
const ALLOWED_READ: &str = "OPTIONS, GET, HEAD, PROPFIND";

/// Top-level dot-names in `files/` are reserved for store metadata and hidden from DAV.
/// Dot-names inside a directory, such as `.sccache_check`, are allowed.
pub(crate) fn reserved(name: &str) -> bool {
    name.starts_with('.')
}

/// Serve one `/dav/…` request. The client-auth gate in [`crate::route`] has already run,
/// so a caller here is authenticated; each subtree authorizes per resource.
pub(crate) async fn route(
    state: &ServerState,
    authz: &Authz<'_>,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    // The caller dispatches only `/dav` paths here.
    let rest = path.strip_prefix("/dav").unwrap_or("");
    let Some(segments) = parse(rest) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            &path,
        ));
    };
    let method = req.method().as_str().to_string();
    // Advertise the supported DAV class and verbs; individual resources may allow fewer.
    if method == "OPTIONS" {
        return Ok(options(ALLOWED_FILES));
    }
    match segments.split_first() {
        None => root(state, &method, req).await,
        Some((area, rest)) if area == "files" => {
            files::route(state, authz, rest, &method, req).await
        }
        Some((area, rest)) if area == "repos" => {
            repos::route(state, authz, rest, &method, req).await
        }
        Some(_) => Ok(not_found(&path)),
    }
}

/// The root collection: `repos/` and `files/`, nothing else.
async fn root(state: &ServerState, method: &str, req: Request<Incoming>) -> Result<Response<Body>> {
    match method {
        "PROPFIND" => {
            let depth = match propfind_depth(req).await {
                Ok(d) => d,
                Err(resp) => return Ok(*resp),
            };
            let now = SystemTime::now();
            let mut entries = vec![Entry::collection(href(&[], true), now)];
            if depth == Depth::One {
                if !may_enumerate(state) {
                    return Ok(enumeration_refused());
                }
                entries.push(Entry::collection(href(&["repos"], true), now));
                entries.push(Entry::collection(
                    href(&["files"], true),
                    modified_of(&state.store.files_dir()),
                ));
            }
            Ok(multistatus(&entries))
        }
        // A collection has no body to serve: this server serves no listings on `GET`.
        "GET" | "HEAD" => Ok(not_found("/dav/")),
        _ => Ok(method_not_allowed("/dav/", ALLOWED_READ)),
    }
}

/// Decode the path after `/dav`, splitting before percent-decoding. Reject decoded separators,
/// control bytes, `.`, `..`, empty or oversized components, and excessive depth. Allow one
/// trailing slash for collections.
pub(crate) fn parse(rest: &str) -> Option<Vec<String>> {
    // `/dav` and `/dav/` are both the root; `/dav//` is an empty component, refused with
    // the rest of them below rather than read as a second spelling of the root.
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }
    let mut segments = Vec::new();
    for raw in rest.split('/') {
        let seg = crate::percent_decode(raw);
        if !valid_segment(&seg) {
            return None;
        }
        segments.push(seg);
    }
    // The area (`files`, `repos`) sits above the depth bound.
    (segments.len() <= MAX_DEPTH + 1).then_some(segments)
}

/// One decoded path component: non-empty, not a directory traversal, short enough to be a
/// filename, and free of anything that could make it more than one component.
fn valid_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg.len() <= MAX_SEGMENT
        && !seg.contains(['/', '\\'])
        && !seg.chars().any(char::is_control)
}

/// Build an href from decoded components, percent-encoding each and appending a slash for
/// collections.
pub(crate) fn href(segments: &[&str], collection: bool) -> String {
    let mut out = String::from("/dav");
    for seg in segments {
        out.push('/');
        out.push_str(&crate::percent_encode(seg));
    }
    if collection {
        out.push('/');
    }
    out
}

/// Root enumeration requires configured credentials. Accounts-mode listings also filter by
/// scope.
fn may_enumerate(state: &ServerState) -> bool {
    match &state.auth {
        Authenticator::Accounts { .. } => true,
        Authenticator::Shared(auth) => auth.enabled(),
    }
}

fn enumeration_refused() -> Response<Body> {
    error_response(
        StatusCode::FORBIDDEN,
        "DENIED",
        "listing the store's roots needs a configured credential",
    )
}

/// What a `PROPFIND` asks about: the resource, the resource and its members, or the whole
/// subtree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Depth {
    Zero,
    One,
    Infinity,
}

/// Read Depth and drain the PROPFIND body. Missing Depth defaults to 0; infinity returns 403.
/// The body is ignored and all supported properties are returned.
pub(crate) async fn propfind_depth(
    req: Request<Incoming>,
) -> std::result::Result<Depth, Box<Response<Body>>> {
    let depth = match req
        .headers()
        .get("depth")
        .map(|v| v.to_str().map(str::trim).map(str::to_ascii_lowercase))
    {
        None => Depth::Zero,
        Some(Ok(d)) if d == "0" => Depth::Zero,
        Some(Ok(d)) if d == "1" => Depth::One,
        Some(Ok(d)) if d == "infinity" => Depth::Infinity,
        Some(_) => {
            return Err(Box::new(error_response(
                StatusCode::BAD_REQUEST,
                "UNSUPPORTED",
                "Depth must be 0, 1 or infinity",
            )));
        }
    };
    if depth == Depth::Infinity {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "DENIED",
            "Depth: infinity is not served here",
        )));
    }
    if crate::collect_capped(req, MAX_PROPFIND_BODY).await.is_err() {
        return Err(Box::new(error_response(
            StatusCode::BAD_REQUEST,
            "SIZE_INVALID",
            "PROPFIND body is too large",
        )));
    }
    Ok(depth)
}

/// Properties of one resource in a 207 response.
pub(crate) struct Entry {
    href: String,
    kind: Kind,
    modified: SystemTime,
}

enum Kind {
    Collection,
    File { len: u64, ctype: String },
}

impl Entry {
    pub(crate) fn collection(href: String, modified: SystemTime) -> Self {
        Entry {
            href,
            kind: Kind::Collection,
            modified,
        }
    }

    pub(crate) fn file(href: String, len: u64, ctype: &str, modified: SystemTime) -> Self {
        Entry {
            href,
            kind: Kind::File {
                len,
                ctype: ctype.to_string(),
            },
            modified,
        }
    }
}

/// Collection mtime, falling back to the epoch if unavailable.
pub(crate) fn modified_of(path: &std::path::Path) -> SystemTime {
    std::fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Build a 207 response with the requested resource first. Each entry has a 200 propstat,
/// resource type and modification time; files also have a length.
pub(crate) fn multistatus(entries: &[Entry]) -> Response<Body> {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
    );
    for e in entries {
        // Escape hrefs even though they are already percent-encoded.
        let _ = write!(
            xml,
            "  <D:response>\n    <D:href>{}</D:href>\n    <D:propstat>\n      <D:prop>\n",
            crate::html_escape(&e.href)
        );
        match &e.kind {
            Kind::File { len, ctype } => {
                let _ = write!(
                    xml,
                    "        <D:resourcetype/>\n        \
                     <D:getcontentlength>{len}</D:getcontentlength>\n        \
                     <D:getcontenttype>{}</D:getcontenttype>\n",
                    crate::html_escape(ctype)
                );
            }
            Kind::Collection => {
                xml.push_str("        <D:resourcetype><D:collection/></D:resourcetype>\n");
            }
        }
        let _ = write!(
            xml,
            "        <D:getlastmodified>{}</D:getlastmodified>\n      </D:prop>\n      \
             <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n",
            http_date(e.modified)
        );
    }
    xml.push_str("</D:multistatus>\n");
    Response::builder()
        .status(StatusCode::MULTI_STATUS)
        .header(CONTENT_TYPE, "application/xml; charset=utf-8")
        .header(CONTENT_LENGTH, xml.len().to_string())
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(body_of(Bytes::from(xml)))
        .expect("building a 207")
}

/// Format an RFC 1123 HTTP date. Times before the epoch render as the epoch.
pub(crate) fn http_date(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, which is why `DAYS` starts there.
    let weekday = DAYS[days.rem_euclid(7) as usize];
    // `civil_from_days` yields a month in 1..=12, so this is in range by construction.
    let month = MONTHS[(month - 1) as usize];
    format!(
        "{weekday}, {day:02} {month} {year} {:02}:{:02}:{:02} GMT",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60,
    )
}

/// Howard Hinnant's `civil_from_days`: convert days since 1970-01-01 to Gregorian `(year,
/// month, day)`. Month is 1..=12 and day 1..=31.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    // Shift the epoch to 0000-03-01, which puts the leap day at the end of the era.
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era, 0..=146_096
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // 0..=399
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of the March-based year
    let mp = (5 * doy + 2) / 153; // March-based month, 0..=11
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `OPTIONS`: the DAV compliance class opendal looks for, and the verbs served.
fn options(allow: &'static str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("DAV", "1")
        .header(ALLOW, allow)
        .header(CONTENT_LENGTH, "0")
        .body(body_of(Bytes::new()))
        .expect("building an OPTIONS response")
}

fn created() -> Response<Body> {
    Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_LENGTH, "0")
        .body(body_of(Bytes::new()))
        .expect("building a 201")
}

fn no_content() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(body_of(Bytes::new()))
        .expect("building a 204")
}

fn not_found(href: &str) -> Response<Body> {
    error_response(StatusCode::NOT_FOUND, "NOT_FOUND", href)
}

/// Include supported methods in the 405 response.
fn method_not_allowed(href: &str, allow: &'static str) -> Response<Body> {
    let mut resp = error_response(StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED", href);
    resp.headers_mut()
        .insert(ALLOW, hyper::header::HeaderValue::from_static(allow));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Test valid paths and rejection of unsafe components.
    #[test]
    fn the_path_parser_refuses_everything_but_a_plain_relative_path() {
        let strs = |v: Option<Vec<String>>| v;
        // the root, both spellings
        assert_eq!(strs(parse("")), Some(vec![]));
        assert_eq!(strs(parse("/")), Some(vec![]));
        // `sccache`'s own two shapes: the startup probe, and a sharded key
        assert_eq!(
            parse("/files/sccache/.sccache_check"),
            Some(vec![
                "files".into(),
                "sccache".into(),
                ".sccache_check".into()
            ])
        );
        assert_eq!(
            parse("/files/sccache/a/b/c/abcdef"),
            Some(vec![
                "files".into(),
                "sccache".into(),
                "a".into(),
                "b".into(),
                "c".into(),
                "abcdef".into()
            ])
        );
        // a collection, with and without the trailing slash a DAV client may send
        assert_eq!(
            parse("/files/sccache"),
            Some(vec!["files".into(), "sccache".into()])
        );
        assert_eq!(
            parse("/files/sccache/"),
            Some(vec!["files".into(), "sccache".into()])
        );
        // percent-decoding is per component, so an encoded separator stays in the name
        assert_eq!(
            parse("/files/x/a%2Db"),
            Some(vec!["files".into(), "x".into(), "a-b".into()])
        );

        for bad in [
            // traversal, encoded and not
            "/files/sccache/..",
            "/files/sccache/../../etc/passwd",
            "/files/sccache/a/../../b",
            "/files/sccache/%2E%2E/x",
            "/..",
            // a decoded separator is a name that would become a path
            "/files/sccache/a%2Fb",
            "/files/sccache/a%2f%2e%2e%2fb",
            "/files/sccache/a%5Cb",
            // control bytes, NUL included
            "/files/sccache/a%00b",
            "/files/sccache/a%0Ab",
            // empty components
            "/files/sccache//x",
            "/files/sccache/x//y",
            "/files/sccache//",
            "//",
        ] {
            assert!(parse(bad).is_none(), "accepted {bad:?}");
        }

        // over-long and over-deep
        let long = "x".repeat(MAX_SEGMENT + 1);
        assert!(parse(&format!("/files/{long}")).is_none());
        assert!(parse(&format!("/files/{}", "x".repeat(MAX_SEGMENT))).is_some());
        let deep = vec!["x"; MAX_DEPTH + 1].join("/");
        assert!(parse(&format!("/files/{deep}")).is_none());
        let deepest = vec!["x"; MAX_DEPTH].join("/");
        assert!(parse(&format!("/files/{deepest}")).is_some());
    }

    /// Hrefs encode decoded components and add a slash for collections.
    #[test]
    fn hrefs_are_encoded_and_collections_end_in_a_slash() {
        assert_eq!(href(&[], true), "/dav/");
        assert_eq!(href(&["files"], true), "/dav/files/");
        assert_eq!(href(&["files", "x", "a b"], false), "/dav/files/x/a%20b");
        assert_eq!(
            href(&["repos", "team-a", "app"], true),
            "/dav/repos/team-a/app/"
        );
    }

    /// Verify response properties, entry order and XML escaping.
    #[tokio::test]
    async fn a_multistatus_carries_what_the_client_parses() {
        use http_body_util::BodyExt as _;
        let body = async |resp: Response<Body>| {
            String::from_utf8(
                resp.into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap()
        };
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(784_887_151);

        let resp = multistatus(&[Entry::file(
            "/dav/files/sccache/a/b/c/key".into(),
            4096,
            "application/octet-stream",
            t,
        )]);
        assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
        assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
        let file = body(resp).await;
        assert!(
            file.contains("<D:href>/dav/files/sccache/a/b/c/key</D:href>"),
            "{file}"
        );
        assert!(file.contains("<D:resourcetype/>"), "{file}");
        assert!(
            file.contains("<D:getcontentlength>4096</D:getcontentlength>"),
            "{file}"
        );
        assert!(
            file.contains("<D:getcontenttype>application/octet-stream</D:getcontenttype>"),
            "{file}"
        );
        assert!(
            file.contains("<D:getlastmodified>Tue, 15 Nov 1994 08:12:31 GMT</D:getlastmodified>"),
            "{file}"
        );
        assert!(
            file.contains("<D:status>HTTP/1.1 200 OK</D:status>"),
            "{file}"
        );
        assert!(
            file.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"),
            "{file}"
        );

        // A listing: the collection first, then its members, each a response of its own.
        let listing = body(multistatus(&[
            Entry::collection("/dav/files/sccache/a/".into(), t),
            Entry::collection("/dav/files/sccache/a/b/".into(), t),
            Entry::file(
                "/dav/files/sccache/a/f".into(),
                1,
                "application/octet-stream",
                t,
            ),
        ]))
        .await;
        assert_eq!(listing.matches("<D:response>").count(), 3, "{listing}");
        assert_eq!(
            listing.matches("<D:getlastmodified>").count(),
            3,
            "{listing}"
        );
        assert_eq!(
            listing.matches("<D:getcontentlength>").count(),
            1,
            "{listing}"
        );
        assert_eq!(
            listing
                .matches("<D:resourcetype><D:collection/></D:resourcetype>")
                .count(),
            2,
            "{listing}"
        );
        let first = listing.find("/dav/files/sccache/a/</D:href>").unwrap();
        let second = listing.find("/dav/files/sccache/a/b/").unwrap();
        assert!(
            first < second,
            "the requested resource comes first: {listing}"
        );

        // Nothing in an href or a type may close an element.
        let escaped = body(multistatus(&[Entry::file(
            "/dav/b/<&\"'>".into(),
            0,
            "a/<b>",
            t,
        )]))
        .await;
        assert!(escaped.contains("&lt;&amp;&quot;&#39;&gt;"), "{escaped}");
        assert!(escaped.contains("a/&lt;b&gt;"), "{escaped}");
        assert!(!escaped.contains("<&"), "{escaped}");
    }

    /// Check HTTP dates across leap years, century boundaries and weekdays.
    #[test]
    fn http_dates_are_rfc_1123() {
        for (secs, want) in [
            (0u64, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (784_887_151, "Tue, 15 Nov 1994 08:12:31 GMT"),
            // 2000-02-29: a leap year a century rule would get wrong
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            // 1900 was not one, and 2100 will not be
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 GMT"),
            (2_147_483_647, "Tue, 19 Jan 2038 03:14:07 GMT"),
            (86_399, "Thu, 01 Jan 1970 23:59:59 GMT"),
        ] {
            let got = http_date(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
            assert_eq!(got, want, "at {secs}");
        }
        // Before the epoch renders as the epoch rather than failing a response.
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(http_date(before), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}
