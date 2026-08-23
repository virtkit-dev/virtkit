//! `/upload`: a browser-facing form for dropping a file straight into the CAS store.
//!
//! Session-only, like `/settings/keys` — an API key already has a purpose-built path
//! (`vk registry push` over the OCI API), so this form is deliberately the human one,
//! CSRF token included: a cookie-authenticated POST is exactly what a cross-site form
//! can forge.
//!
//! **The upload shares the dedup store natively.** A dropped file becomes one blob
//! (`Store::put_blob`, digest = sha256 of its bytes) plus a small single-layer manifest
//! (`Store::put_manifest`; the layer's media type is `application/vnd.virtkit.raw-file`)
//! tagged with the given `name`/`tag`. The bytes are readable straight back over the
//! ordinary OCI API — `GET /v2/<name>/manifests/<reference>` then
//! `GET /v2/<name>/blobs/<digest>` — and re-uploading content the store already holds
//! costs no new disk however many names it is given. That is the point of routing this
//! through `Store` instead of a parallel raw-file tree.
//!
//! It is not a `vk` bundle: `vk registry pull` wants a `BundleConfig` and chunk layers
//! and refuses this shape. A raw file here is for fetching, not for booting.
//!
//! The body is parsed as it arrives and each part is acted on before the next byte is
//! read. The form emits `csrf`, `name`, `tag`, then `file`, so a caller who fails the
//! CSRF check or the write check is refused after a few hundred bytes rather than after
//! the whole upload; a body that puts `file` first is refused for that reason.

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};

use crate::accounts::{self, Db, Principal};
use crate::html::{self, page, respond};
use crate::{DEFAULT_MANIFEST_TYPE, Store, html_escape, valid_name, valid_tag};

/// The manifest's config blob: fixed, empty content — a raw-file upload has no build
/// config, but the OCI manifest schema requires a config descriptor. Every upload
/// therefore references the *same* config blob, which dedups after the first one.
const EMPTY_CONFIG: &[u8] = b"{}";
const RAW_FILE_MEDIA_TYPE: &str = "application/vnd.virtkit.raw-file";
const RAW_FILE_CONFIG_MEDIA_TYPE: &str = "application/vnd.virtkit.raw-file.config.v1+json";

/// The largest file this form accepts. The bytes are held in memory to hash them, so
/// this is a real ceiling and not a formality; anything bigger belongs in
/// `vk registry push`, which streams.
const MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;

/// How much *unparsed* body may be left over while the caller is still unauthorized.
/// `csrf` and `name` are short and come first, so a legitimate form clears both checks
/// well inside this. It bounds the residue, not the frame that carried it: one hyper read
/// buffer (a few hundred KiB) can arrive before anything in it has been parsed, and that
/// much an unauthorized caller can always make this hold once.
const MAX_PREAUTH_RESIDUE: usize = 4 * 1024;

/// The longest filename, in bytes, kept in the manifest annotation. Client-supplied and
/// stored permanently, so it is bounded where it enters the store, as an API key's name
/// and an identity claim both are.
const MAX_FILE_NAME_BYTES: usize = 255;

/// `secure` is `ServerState::cookies_are_secure()` — it decides which of the two names the
/// session cookie was written under, so it has to be the same answer the rest of the
/// server uses (see [`accounts::session_cookie`]).
pub(crate) async fn route(
    store: &Store,
    db: &Db,
    principal: &Principal,
    secure: bool,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let Principal::Session(user) = principal else {
        return Ok(html::error(
            StatusCode::FORBIDDEN,
            Some(principal),
            None,
            "Not available to an API key",
            "Manual upload is for a signed-in person; CI pushes with `vk registry push` \
             over the OCI API instead.",
        ));
    };
    let session_id = accounts::session_cookie(req.headers(), secure);
    match *req.method() {
        Method::GET | Method::HEAD => {
            form_page(db, user, session_id.as_deref(), StatusCode::OK, None)
        }
        Method::POST => submit(store, db, principal, user, session_id, req).await,
        _ => Ok(html::error(
            StatusCode::METHOD_NOT_ALLOWED,
            Some(principal),
            csrf_of(db, session_id.as_deref()).as_deref(),
            "That address does not accept this method",
            "Open /upload in a browser to use the form.",
        )),
    }
}

async fn submit(
    store: &Store,
    db: &Db,
    principal: &Principal,
    user: &accounts::User,
    session_id: Option<String>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let Some(boundary) = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(multipart_boundary)
    else {
        return form_page(
            db,
            user,
            session_id.as_deref(),
            StatusCode::BAD_REQUEST,
            Some("expected a multipart/form-data body"),
        );
    };

    let mut scanner = Scanner::new(&boundary);
    let mut body = req.into_body();
    let mut csrf_ok = false;
    let mut name: Option<String> = None;
    let mut tag: Option<String> = None;
    let mut file_name: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;

    'read: loop {
        loop {
            let part = match scanner.next_part() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => return bad(db, user, session_id.as_deref(), StatusCode::BAD_REQUEST, e),
            };
            // Exactly one of each: a repeat would leave "which occurrence was the one the
            // checks ran against?" open, and repeating the file part is a way to make the
            // server buffer many times the ceiling.
            let seen = match part.name.as_str() {
                "csrf" => csrf_ok,
                "name" => name.is_some(),
                "tag" => tag.is_some(),
                "file" => file_bytes.is_some(),
                _ => false,
            };
            if seen {
                return bad(
                    db,
                    user,
                    session_id.as_deref(),
                    StatusCode::BAD_REQUEST,
                    "that form field appears more than once",
                );
            }
            match part.name.as_str() {
                "csrf" => {
                    let Ok(presented) = std::str::from_utf8(&part.body) else {
                        return Ok(csrf_rejected(db, principal, session_id.as_deref()));
                    };
                    if !csrf_matches(db, session_id.as_deref(), presented) {
                        return Ok(csrf_rejected(db, principal, session_id.as_deref()));
                    }
                    csrf_ok = true;
                }
                "name" => {
                    // Strict, not `from_utf8_lossy`: a replacement character would fail
                    // `valid_name` anyway, but inventing bytes the client never sent is
                    // not how a validated field should be read.
                    let n = String::from_utf8(part.body).unwrap_or_default();
                    if !valid_name(&n) {
                        return bad(
                            db,
                            user,
                            session_id.as_deref(),
                            StatusCode::BAD_REQUEST,
                            "invalid repository name",
                        );
                    }
                    // The gate `/v2/` applies to a push, applied before a single byte of
                    // the file has been read.
                    if !accounts::authorize(principal, accounts::Action::Write, &n) {
                        return Ok(html::error(
                            StatusCode::FORBIDDEN,
                            Some(principal),
                            csrf_of(db, session_id.as_deref()).as_deref(),
                            "You cannot write to that repository",
                            "Uploading needs an administrator session.",
                        ));
                    }
                    name = Some(n);
                }
                "tag" => {
                    let t = String::from_utf8(part.body).unwrap_or_default();
                    if !valid_tag(&t) {
                        return bad(
                            db,
                            user,
                            session_id.as_deref(),
                            StatusCode::BAD_REQUEST,
                            "invalid tag",
                        );
                    }
                    tag = Some(t);
                }
                "file" => {
                    if !csrf_ok || name.is_none() {
                        return bad(
                            db,
                            user,
                            session_id.as_deref(),
                            StatusCode::BAD_REQUEST,
                            "the file field must come after the csrf and name fields",
                        );
                    }
                    file_name = part.file_name;
                    file_bytes = Some(part.body);
                }
                _ => {
                    return bad(
                        db,
                        user,
                        session_id.as_deref(),
                        StatusCode::BAD_REQUEST,
                        "unexpected form field",
                    );
                }
            }
        }
        if scanner.finished() {
            break 'read;
        }
        // Measured after the parts above were taken out, and before another frame is read.
        // It cannot be measured on the frame instead: hyper hands over the first several
        // hundred kilobytes in one go, and `csrf` and `name` arrive inside that frame
        // together with the start of the file, so capping the frame would refuse every
        // upload bigger than one frame. What stays bounded is the *residue* — plus,
        // unavoidably, the single frame that carried it (see [`MAX_PREAUTH_RESIDUE`]).
        if !(csrf_ok && name.is_some()) && scanner.pending() > MAX_PREAUTH_RESIDUE {
            return bad(
                db,
                user,
                session_id.as_deref(),
                StatusCode::BAD_REQUEST,
                "the csrf and name fields must come first, and be short",
            );
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(chunk) = frame.into_data()
                    && let Err(e) = scanner.push(&chunk, MAX_UPLOAD_BYTES)
                {
                    return bad(
                        db,
                        user,
                        session_id.as_deref(),
                        StatusCode::PAYLOAD_TOO_LARGE,
                        e,
                    );
                }
            }
            Some(Err(_)) => {
                return bad(
                    db,
                    user,
                    session_id.as_deref(),
                    StatusCode::BAD_REQUEST,
                    "that upload did not finish",
                );
            }
            None => break 'read,
        }
    }

    if !csrf_ok {
        return Ok(csrf_rejected(db, principal, session_id.as_deref()));
    }
    let (Some(name), Some(tag)) = (name, tag) else {
        return bad(
            db,
            user,
            session_id.as_deref(),
            StatusCode::BAD_REQUEST,
            "a repository and a tag are required",
        );
    };
    let Some(file_bytes) = file_bytes.filter(|b| !b.is_empty()) else {
        return bad(
            db,
            user,
            session_id.as_deref(),
            StatusCode::BAD_REQUEST,
            "no file selected",
        );
    };

    if let Err(e) = store_upload(store, &name, &tag, &file_bytes, file_name.as_deref()) {
        // The chain names store paths; it goes to the log, not to the browser.
        eprintln!("vk-registry: storing an upload of {name}:{tag}: {e:#}");
        return Ok(html::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(principal),
            csrf_of(db, session_id.as_deref()).as_deref(),
            "That upload could not be stored",
            "Try again, or ask an operator to check the server log.",
        ));
    }
    // 303 to the page that shows what landed, so a refresh re-reads it rather than
    // uploading the file a second time.
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(
            hyper::header::LOCATION,
            format!("/browse/{name}/manifests/{tag}"),
        )
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// The blob, the shared empty config, and the single-layer manifest tying them together
/// — the same three writes a `/v2/` push makes.
fn store_upload(
    store: &Store,
    name: &str,
    tag: &str,
    file_bytes: &[u8],
    file_name: Option<&str>,
) -> Result<()> {
    let _lock = store.lock_shared()?;
    let config_digest = store.put_blob(EMPTY_CONFIG)?;
    let layer_digest = store.put_blob(file_bytes)?;
    let mut layer = serde_json::json!({
        "mediaType": RAW_FILE_MEDIA_TYPE,
        "digest": layer_digest,
        "size": file_bytes.len(),
    });
    // Only when the browser actually sent one: an empty title is worse than none.
    if let Some(title) = file_name.map(clamp_name).filter(|t| !t.is_empty()) {
        layer["annotations"] = serde_json::json!({
            "org.opencontainers.image.title": title,
        });
    }
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": DEFAULT_MANIFEST_TYPE,
        "config": {
            "mediaType": RAW_FILE_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": EMPTY_CONFIG.len(),
        },
        "layers": [layer],
    });
    store.put_manifest(
        name,
        tag,
        DEFAULT_MANIFEST_TYPE,
        serde_json::to_vec(&manifest)?.as_slice(),
    )?;
    Ok(())
}

fn bad(
    db: &Db,
    user: &accounts::User,
    session_id: Option<&str>,
    status: StatusCode,
    msg: &str,
) -> Result<Response<Full<Bytes>>> {
    form_page(db, user, session_id, status, Some(msg))
}

/// `s` cut to [`MAX_FILE_NAME_BYTES`] on a character boundary.
fn clamp_name(s: &str) -> String {
    if s.len() <= MAX_FILE_NAME_BYTES {
        return s.to_string();
    }
    let mut end = MAX_FILE_NAME_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// The `boundary=` of a `multipart/form-data` Content-Type, if it is one. RFC 7578 allows
/// the value to be quoted; anything outside the boundary character set is refused rather
/// than sanitised, since the value becomes a delimiter this parser searches for.
fn multipart_boundary(ctype: &str) -> Option<String> {
    let (kind, params) = ctype.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let raw = params.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("boundary")
            .then_some(v.trim())
    })?;
    let b = raw
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(raw);
    let ok = !b.is_empty()
        && b.len() <= 70
        && b.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&c));
    ok.then(|| b.to_string())
}

/// One completed `multipart/form-data` part.
struct Part {
    name: String,
    file_name: Option<String>,
    body: Vec<u8>,
}

/// An incremental `multipart/form-data` reader.
///
/// Hand-rolled rather than taken from a crate: what this route needs is "hand me the next
/// complete part", which is a boundary search plus a header split, and the crates on offer
/// bring a charset-transcoding dependency for a `text_with_charset` this never calls. The
/// same reasoning the cookie and query parsing elsewhere in this crate follow.
struct Scanner {
    /// `\r\n--<boundary>`, the delimiter that ends every part.
    delim: Vec<u8>,
    buf: Vec<u8>,
    /// how far into `buf` the delimiter search has already looked
    searched: usize,
    /// whether the opening delimiter has been consumed
    started: bool,
    finished: bool,
    /// every byte pushed, ever — see [`Scanner::push`]
    total: usize,
}

impl Scanner {
    /// Allowance over the cap for the framing a part carries besides its bytes: the
    /// delimiter, its CRLFs, and the `Content-Disposition`/`Content-Type` header block a
    /// browser sends. Without it a file of exactly the advertised size would be refused
    /// for its own headers.
    const HEADER_BUDGET: usize = 512;

    fn new(boundary: &str) -> Self {
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary.as_bytes());
        Scanner {
            delim,
            // The body's first delimiter has no leading CRLF; pretending it does lets one
            // search find every delimiter, the opening one included.
            buf: b"\r\n".to_vec(),
            searched: 0,
            started: false,
            finished: false,
            total: 0,
        }
    }

    /// Unparsed bytes still held — what [`MAX_PREAUTH_RESIDUE`] bounds.
    fn pending(&self) -> usize {
        self.buf.len()
    }

    fn finished(&self) -> bool {
        self.finished
    }

    /// Append received bytes, refusing to hold more than `cap` of them at once.
    /// Take another frame, refusing it if it would put either the buffer or the *whole
    /// body so far* past `cap`.
    ///
    /// Both bounds are needed. The buffer one alone resets on every completed part, so a
    /// caller could stream unboundedly many small well-formed parts — or repeat the file
    /// part — and never trip it: the total is what makes the ceiling a ceiling. The buffer
    /// one still earns its place because it is what refuses an over-large part before the
    /// whole body has been read.
    fn push(&mut self, chunk: &[u8], cap: usize) -> Result<(), &'static str> {
        let ceiling = cap.saturating_add(self.delim.len() + Self::HEADER_BUDGET);
        self.total = self.total.saturating_add(chunk.len());
        if self.total > ceiling || self.buf.len().saturating_add(chunk.len()) > ceiling {
            return Err("that upload is larger than this form accepts");
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// The delimiter's offset in `buf`, resuming where the previous search stopped so a
    /// large body is scanned once rather than once per chunk.
    fn find_delim(&mut self) -> Option<usize> {
        let n = self.delim.len();
        if self.buf.len() < n {
            return None;
        }
        let from = self.searched.min(self.buf.len() - n);
        let found = self.buf[from..]
            .windows(n)
            .position(|w| w == self.delim)
            .map(|i| from + i);
        // Keep the last n-1 bytes in play: a delimiter may straddle two chunks.
        self.searched = match found {
            Some(i) => i,
            None => self.buf.len().saturating_sub(n - 1),
        };
        found
    }

    /// The next complete part, or `None` while one is still arriving.
    fn next_part(&mut self) -> Result<Option<Part>, &'static str> {
        if self.finished {
            return Ok(None);
        }
        if !self.started {
            let Some(i) = self.find_delim() else {
                return Ok(None);
            };
            let Some(closing) = self.take_through_delim(i) else {
                return Ok(None);
            };
            if closing {
                self.finished = true;
                return Ok(None);
            }
            self.started = true;
        }
        let Some(i) = self.find_delim() else {
            return Ok(None);
        };
        let raw = self.buf[..i].to_vec();
        let Some(closing) = self.take_through_delim(i) else {
            return Ok(None);
        };
        if closing {
            self.finished = true;
        }
        parse_part(&raw).map(Some)
    }

    /// Drop everything through the delimiter at `at` and the two bytes after it.
    /// `Some(true)` if those bytes were `--`, i.e. this was the closing delimiter;
    /// `None` if they have not arrived yet.
    ///
    /// Those two bytes are dropped whatever they are: RFC 2046 allows transport padding
    /// before the CRLF, so requiring exactly CRLF would refuse a legal body, and the
    /// boundary is the client's own choice — there is nothing to gain by lying to itself
    /// about it. Anything other than `--` therefore reads as "another part follows".
    fn take_through_delim(&mut self, at: usize) -> Option<bool> {
        let end = at + self.delim.len();
        if self.buf.len() < end + 2 {
            return None;
        }
        let closing = &self.buf[end..end + 2] == b"--";
        self.buf.drain(..end + 2);
        self.searched = 0;
        Some(closing)
    }
}

/// Split a raw part into headers and body, and read `name`/`filename` out of its
/// `Content-Disposition`.
fn parse_part(raw: &[u8]) -> Result<Part, &'static str> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("a form part had no header block")?;
    let headers =
        std::str::from_utf8(&raw[..split]).map_err(|_| "a form part's headers were not text")?;
    let body = raw[split + 4..].to_vec();
    let disposition = headers
        .lines()
        .find(|l| {
            l.split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("content-disposition"))
        })
        .ok_or("a form part had no Content-Disposition")?;
    let name = quoted_param(disposition, "name").ok_or("a form part had no name")?;
    Ok(Part {
        name,
        file_name: quoted_param(disposition, "filename"),
        body,
    })
}

/// `…; key="value"` out of a header line. Quoted form only — that is what every browser
/// sends, and the unquoted form would mean guessing where the value ends.
fn quoted_param(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let mut from = 0;
    while let Some(i) = header[from..].find(&needle) {
        let start = from + i;
        // `name` must not match the tail of `filename`: require a delimiter before it.
        let delimited = header[..start]
            .chars()
            .next_back()
            .is_none_or(|c| c == ';' || c == ' ');
        let value_at = start + needle.len();
        let end = header[value_at..].find('"')? + value_at;
        if delimited {
            return Some(header[value_at..end].to_string());
        }
        from = end;
    }
    None
}

/// The submitted token must equal the session's own `csrf_secret`, compared in constant
/// time — a form served from another origin cannot read that value, so it cannot forge
/// this POST.
fn csrf_matches(db: &Db, session_id: Option<&str>, submitted: &str) -> bool {
    let Some(expected) = csrf_of(db, session_id) else {
        return false;
    };
    crate::auth::constant_eq(expected.as_bytes(), submitted.as_bytes())
}

/// The session's CSRF secret, for the form this module renders.
fn csrf_of(db: &Db, session_id: Option<&str>) -> Option<String> {
    let id = session_id?;
    match db.session_csrf(id) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vk-registry: reading a session's CSRF secret: {e:#}");
            None
        }
    }
}

fn csrf_rejected(
    db: &Db,
    principal: &Principal,
    session_id: Option<&str>,
) -> Response<Full<Bytes>> {
    html::error(
        StatusCode::FORBIDDEN,
        Some(principal),
        csrf_of(db, session_id).as_deref(),
        "That request did not come from this page",
        "Its security token was missing or stale. Reload the page and try again.",
    )
}

fn form_page(
    db: &Db,
    user: &accounts::User,
    session_id: Option<&str>,
    status: StatusCode,
    error: Option<&str>,
) -> Result<Response<Full<Bytes>>> {
    let csrf = csrf_of(db, session_id).unwrap_or_default();
    let error_html = error
        .map(|e| format!("<p class=\"error\">{}</p>\n", html_escape(e)))
        .unwrap_or_default();
    // Say so up front rather than after the file has been sent.
    let note = if user.is_admin {
        ""
    } else {
        "<p class=\"error\">Uploading needs an administrator session; this form will \
         refuse the upload.</p>\n"
    };
    Ok(respond(
        status,
        &page(
            "vk-registry: upload",
            &Principal::Session(user.clone()),
            Some(&csrf),
            &format!(
                "<h1>Upload a file</h1>\n{error_html}{note}\
                 <p>Up to {mib} MiB. The file field comes last.</p>\n\
                 <form method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\">\n\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\n\
                 <label>Repository <input name=\"name\" placeholder=\"team-a/myfile\" required></label>\n\
                 <label>Tag <input name=\"tag\" value=\"latest\" required></label>\n\
                 <label>File <input type=\"file\" name=\"file\" required></label>\n\
                 <button type=\"submit\">Upload</button>\n\
                 </form>",
                mib = MAX_UPLOAD_BYTES / (1024 * 1024),
                csrf = html_escape(&csrf),
            ),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn memdb() -> Db {
        let dir = std::env::temp_dir().join(format!("vk-upload-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Db::open(&dir.join("registry.db")).unwrap()
    }

    #[test]
    fn csrf_requires_a_live_session_and_a_matching_token() {
        let db = memdb();
        let user = db
            .upsert_user("https://issuer", "sub-1", None, None)
            .unwrap();
        let session = db
            .create_session(&user.id, Duration::from_secs(3600))
            .unwrap();
        let real = db.session_csrf(&session).unwrap().unwrap();

        assert!(csrf_matches(&db, Some(&session), &real));
        assert!(!csrf_matches(&db, Some(&session), "wrong"));
        assert!(!csrf_matches(&db, Some(&session), ""));
        assert!(!csrf_matches(&db, None, &real));
        assert!(!csrf_matches(&db, Some("no-such-session"), &real));
    }

    #[test]
    fn a_boundary_is_read_only_from_a_multipart_content_type() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            multipart_boundary("Multipart/Form-Data; charset=utf-8; BOUNDARY=\"a-b_c\"").as_deref(),
            Some("a-b_c")
        );
        assert_eq!(multipart_boundary("application/json"), None);
        assert_eq!(multipart_boundary("multipart/form-data"), None);
        assert_eq!(multipart_boundary("multipart/form-data; boundary="), None);
        // nothing that could smuggle a delimiter or escape the header
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=a\rb"),
            None
        );
        assert_eq!(
            multipart_boundary(&format!("multipart/form-data; boundary={}", "a".repeat(71))),
            None
        );
    }

    fn body(boundary: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, filename, data) in parts {
            out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            let disp = match filename {
                Some(f) => format!("form-data; name=\"{name}\"; filename=\"{f}\""),
                None => format!("form-data; name=\"{name}\""),
            };
            out.extend_from_slice(format!("Content-Disposition: {disp}\r\n\r\n").as_bytes());
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        out
    }

    /// Feed the body one byte at a time: every part must still come out whole, which is
    /// the property that lets a caller be refused before the file arrives.
    #[test]
    fn parts_come_out_whole_however_the_body_is_chunked() {
        let raw = body(
            "X",
            &[
                ("csrf", None, b"token"),
                ("name", None, b"team-a/doc"),
                ("tag", None, b"v1"),
                ("file", Some("notes.txt"), b"hello\r\nworld"),
            ],
        );
        for chunk in [1usize, 3, 7, raw.len()] {
            let mut s = Scanner::new("X");
            let mut got = Vec::new();
            for piece in raw.chunks(chunk) {
                s.push(piece, MAX_UPLOAD_BYTES).unwrap();
                while let Some(p) = s.next_part().unwrap() {
                    got.push((p.name, p.file_name, p.body));
                }
            }
            assert_eq!(got.len(), 4, "chunk size {chunk}");
            assert_eq!(got[0].0, "csrf");
            assert_eq!(got[0].2, b"token");
            assert_eq!(got[1].2, b"team-a/doc");
            assert_eq!(got[3].0, "file");
            assert_eq!(got[3].1.as_deref(), Some("notes.txt"));
            // a body containing CRLF is not truncated at it
            assert_eq!(got[3].2, b"hello\r\nworld");
            assert!(s.finished());
        }
    }

    #[test]
    fn a_malformed_part_is_an_error_not_a_panic() {
        let mut s = Scanner::new("X");
        s.push(b"--X\r\nno headers here\r\n--X--\r\n", MAX_UPLOAD_BYTES)
            .unwrap();
        assert!(s.next_part().is_err());

        let mut s = Scanner::new("X");
        s.push(
            b"--X\r\nContent-Disposition: form-data\r\n\r\nbody\r\n--X--\r\n",
            MAX_UPLOAD_BYTES,
        )
        .unwrap();
        assert!(s.next_part().is_err(), "a part with no name is refused");

        // a truncated body yields no part, rather than a partial one
        let mut s = Scanner::new("X");
        s.push(
            b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhal",
            MAX_UPLOAD_BYTES,
        )
        .unwrap();
        assert!(s.next_part().unwrap().is_none());
        assert!(!s.finished());
    }

    /// One over-large frame is refused, and so is a *drip* that adds up to more than the
    /// cap — the buffer empties as parts are taken out of it, so without a running total a
    /// caller could stream unboundedly many small parts and never trip the ceiling.
    #[test]
    fn the_scanner_refuses_both_a_large_frame_and_a_long_drip() {
        let cap = 4096;

        let mut s = Scanner::new("X");
        assert!(s.push(&vec![b'a'; cap * 2], cap).is_err(), "one big frame");

        // a well-formed part per frame, so the buffer is drained every time round
        let mut s = Scanner::new("X");
        let part = b"--X\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\nv1\r\n".to_vec();
        let mut pushed = 0usize;
        let refused = loop {
            if s.push(&part, cap).is_err() {
                break true;
            }
            while s.next_part().unwrap().is_some() {}
            pushed += part.len();
            // far past the cap: without the running total this never ends
            if pushed > cap * 8 {
                break false;
            }
        };
        assert!(refused, "a drip that adds up past the cap must be refused");
    }

    #[test]
    fn a_filename_is_read_without_being_confused_for_the_field_name() {
        let h = "form-data; name=\"file\"; filename=\"notes.txt\"";
        assert_eq!(quoted_param(h, "name").as_deref(), Some("file"));
        assert_eq!(quoted_param(h, "filename").as_deref(), Some("notes.txt"));
        assert_eq!(
            quoted_param("form-data; name=\"tag\"", "filename"),
            None,
            "no filename on a plain field"
        );
        // `name` must not be read out of `filename`'s tail
        assert_eq!(
            quoted_param("form-data; filename=\"x\"; name=\"file\"", "name").as_deref(),
            Some("file")
        );
    }

    #[test]
    fn a_stored_filename_is_bounded() {
        assert_eq!(clamp_name("short.txt"), "short.txt");
        assert_eq!(clamp_name(&"a".repeat(1000)).len(), MAX_FILE_NAME_BYTES);
        // a byte bound, cut on a char boundary — never mid-character
        let wide = "é".repeat(1000);
        let cut = clamp_name(&wide);
        assert!(cut.len() <= MAX_FILE_NAME_BYTES);
        assert_eq!(cut.chars().count(), MAX_FILE_NAME_BYTES / 2);
    }
}
