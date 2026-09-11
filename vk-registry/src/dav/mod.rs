//! WebDAV under `/dav/`: writable plain files in `files/`, stored in the OCI pool as raw-file
//! manifests, and a read-only OCI view in `repos/`.
//! OCI downloads reuse `/v2/` handlers and authorization; OCI writes remain on `/v2/`. Supports
//! `PROPFIND` (Depth 0/1), `GET`, `HEAD`, `PUT`, `MKCOL`, `DELETE` and `OPTIONS`. PROPFIND
//! bodies are drained, up to 64 KiB, without parsing XML. Listings are scope-filtered; root
//! enumeration requires configured credentials. See `DESIGN.md`.

mod files;
mod repos;

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{ALLOW, CONTENT_LENGTH, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use hyper::{Request, Response, StatusCode};

use crate::{Authenticator, Authz, Body, ServerState, Store, body_of, error_response};

/// Maximum path depth below `/dav/<area>/`: the deepest `repos/` path, a full-length
/// repository name and then `blobs/<hex>`. Under `files/` the repository name bound refuses
/// a path first, past 15 components.
pub(crate) const MAX_DEPTH: usize = crate::MAX_NAME_SEGMENTS + 2;

/// Maximum decoded component length in bytes.
const MAX_SEGMENT: usize = 255;

/// Maximum PROPFIND body size; the body is drained and ignored.
const MAX_PROPFIND_BODY: usize = 64 * 1024;

/// The verbs a `files/` directory or object answers, for `OPTIONS` and for the `Allow` on a
/// 405.
const ALLOWED_FILES: &str = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL";

/// The verbs a read-only resource answers: the root, `repos/`, and the `files/` root.
const ALLOWED_READ: &str = "OPTIONS, GET, HEAD, PROPFIND";

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
    let Some((segments, collection)) = parse(rest) else {
        let resp = error_response(StatusCode::BAD_REQUEST, "NAME_INVALID", &path);
        return refuse(req, resp, &path).await;
    };
    let method = req.method().as_str().to_string();
    match segments.split_first() {
        None => root(state, authz, &method, req).await,
        Some((area, rest)) if area == "files" => {
            files::route(state, authz, rest, collection, &method, req).await
        }
        Some((area, rest)) if area == "repos" => {
            repos::route(state, authz, rest, collection, &method, req).await
        }
        Some(_) => refuse(req, not_found(&path), &path).await,
    }
}

/// The root collection: `repos/` and `files/`, nothing else, both dated by `repos/`.
async fn root(
    state: &ServerState,
    authz: &Authz<'_>,
    method: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let this = href(&[], true);
    match method {
        "OPTIONS" => Ok(options(ALLOWED_READ)),
        "PROPFIND" => {
            let depth = match propfind_depth(req).await {
                Ok(d) => d,
                Err(resp) => return Ok(*resp),
            };
            if depth == Depth::One && !may_enumerate(state) {
                return Ok(enumeration_refused());
            }
            blocking(state, authz, move |store, _| {
                let repos = store.repos_path_modified("");
                let mut entries = vec![Entry::collection(this, repos)];
                if depth == Depth::One {
                    entries.push(Entry::collection(href(&["repos"], true), repos));
                    entries.push(Entry::collection(
                        href(&["files"], true),
                        store.repos_path_modified(files::FILES_REPO),
                    ));
                }
                Ok(multistatus(&entries))
            })
            .await
        }
        // A collection has no body to serve: this server serves no listings on `GET`.
        "GET" | "HEAD" => Ok(not_found(&this)),
        _ => refuse(req, method_not_allowed(&this, ALLOWED_READ), &this).await,
    }
}

/// Answer `resp` once the request body has been read through: a status sent with request
/// bytes unread resets the connection, and a client then sees the reset instead of the
/// answer. A body past the object cap is refused with 413 instead.
pub(crate) async fn refuse(
    req: Request<Incoming>,
    resp: Response<Body>,
    href: &str,
) -> Result<Response<Body>> {
    files::drain_then(req, resp, href).await
}

/// Run `f` on the blocking pool with the store and the caller's authorization: filesystem
/// walks, reads per listed member and the store lock stay off the tokio workers.
pub(crate) async fn blocking<F>(
    state: &ServerState,
    authz: &Authz<'_>,
    f: F,
) -> Result<Response<Body>>
where
    F: FnOnce(&Store, &Authz<'_>) -> Result<Response<Body>> + Send + 'static,
{
    let store = Arc::clone(&state.store);
    let principal = match authz {
        Authz::NoScopes => None,
        Authz::Accounts(p) => Some((*p).clone()),
    };
    tokio::task::spawn_blocking(move || {
        let authz = match &principal {
            None => Authz::NoScopes,
            Some(p) => Authz::Accounts(p),
        };
        f(&store, &authz)
    })
    .await
    .context("a WebDAV request panicked")?
}

/// Decode the path after `/dav` into its components and whether it ended in a slash,
/// splitting before percent-decoding. Reject decoded separators, control bytes, `.`, `..`,
/// empty or oversized components, malformed escapes, invalid UTF-8, and excessive depth.
pub(crate) fn parse(rest: &str) -> Option<(Vec<String>, bool)> {
    // `/dav` and `/dav/` are both the root; `/dav//` is an empty component, refused with
    // the rest of them below rather than read as a second spelling of the root.
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Some((Vec::new(), true));
    }
    let (rest, collection) = match rest.strip_suffix('/') {
        Some(r) => (r, true),
        None => (rest, false),
    };
    if rest.is_empty() {
        return None;
    }
    let mut segments = Vec::new();
    for raw in rest.split('/') {
        let seg = decode_segment(raw).filter(|s| valid_segment(s))?;
        segments.push(seg);
    }
    // The area (`files`, `repos`) sits above the depth bound.
    (segments.len() <= MAX_DEPTH + 1).then_some((segments, collection))
}

/// Percent-decode one path component: `%XX` escapes only, `+` being itself in a path, and
/// the decoded bytes must be UTF-8. `None` for a malformed escape or invalid UTF-8.
fn decode_segment(raw: &str) -> Option<String> {
    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hi = hex(*b.get(i + 1)?)?;
            let lo = hex(*b.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
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

/// What a served `PROPFIND` asks about: the resource, or the resource and its members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Depth {
    Zero,
    One,
}

/// Drain the PROPFIND body, then read Depth. A missing Depth is served as 0 — what opendal
/// means by omitting it, where RFC 4918 reads it as infinity — and infinity is 403. The body
/// is ignored and all supported properties are returned; one past 64 KiB is 413.
pub(crate) async fn propfind_depth(
    req: Request<Incoming>,
) -> std::result::Result<Depth, Box<Response<Body>>> {
    let depth = match req
        .headers()
        .get("depth")
        .map(|v| v.to_str().map(str::trim).map(str::to_ascii_lowercase))
    {
        None => Ok(Depth::Zero),
        Some(Ok(d)) if d == "0" => Ok(Depth::Zero),
        Some(Ok(d)) if d == "1" => Ok(Depth::One),
        Some(Ok(d)) if d == "infinity" => Err(error_response(
            StatusCode::FORBIDDEN,
            "DENIED",
            "Depth: infinity is not served here",
        )),
        Some(_) => Err(error_response(
            StatusCode::BAD_REQUEST,
            "UNSUPPORTED",
            "Depth must be 0, 1 or infinity",
        )),
    };
    if crate::collect_capped(req, MAX_PROPFIND_BODY).await.is_err() {
        return Err(Box::new(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SIZE_INVALID",
            "PROPFIND body is too large",
        )));
    }
    depth.map_err(Box::new)
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

/// Format an RFC 1123 HTTP date. `httpdate` panics outside 1970 to 9999, so a time outside
/// that range is clamped into it.
pub(crate) fn http_date(t: SystemTime) -> String {
    const LAST: Duration = Duration::from_secs(253_402_300_799);
    let since = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    httpdate::fmt_http_date(SystemTime::UNIX_EPOCH + since.min(LAST))
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
        let segs = |p: &str| parse(p).map(|(s, _)| s);
        let v = |s: &[&str]| Some(s.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // the root, both spellings
        assert_eq!(parse(""), Some((vec![], true)));
        assert_eq!(parse("/"), Some((vec![], true)));
        // `sccache`'s own two shapes: the startup probe, and a sharded key
        assert_eq!(
            segs("/files/sccache/.sccache_check"),
            v(&["files", "sccache", ".sccache_check"])
        );
        assert_eq!(
            segs("/files/sccache/a/b/c/abcdef"),
            v(&["files", "sccache", "a", "b", "c", "abcdef"])
        );
        // a collection, with and without the trailing slash a DAV client may send, which
        // is reported
        assert_eq!(
            parse("/files/sccache"),
            Some((v(&["files", "sccache"]).unwrap(), false))
        );
        assert_eq!(
            parse("/files/sccache/"),
            Some((v(&["files", "sccache"]).unwrap(), true))
        );
        // percent-decoding is per component and a path's own: `%2D` is `-`, `+` is itself
        assert_eq!(segs("/files/x/a%2Db"), v(&["files", "x", "a-b"]));
        assert_eq!(segs("/files/x/a+b"), v(&["files", "x", "a+b"]));
        assert_eq!(segs("/files/x/%C3%A9"), v(&["files", "x", "\u{e9}"]));

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
            // malformed escapes and bytes that are not UTF-8
            "/files/sccache/a%2",
            "/files/sccache/a%G0",
            "/files/sccache/%FF",
            "/files/sccache/%C3",
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

    /// HTTP dates are IMF-fixdate, and a time `httpdate` cannot format is clamped rather
    /// than failing a response.
    #[test]
    fn http_dates_are_rfc_1123_and_clamped() {
        let at = |secs| http_date(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(784_887_151), "Tue, 15 Nov 1994 08:12:31 GMT");
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(http_date(before), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            at(u64::from(u32::MAX) * 1000),
            "Fri, 31 Dec 9999 23:59:59 GMT"
        );
    }
}
