//! `PUT /files/<dir>/<name>` ([`vk_hub_proto::registry::FILES_PATH`]): a file streamed in
//! whole and stored as `vk registry put --dir <dir>` stores one — one blob, tagged
//! `files/sha256:<its sha256>` and `files/<dir>:<name>` on a raw-file manifest whose layer is
//! titled `<name>` — with the annotations and retention the request asks for. With
//! `?under=<path>`, the repositories are `<path>/files/…`, where a client whose registry
//! repository is `<path>` looks for its files. Any writer of both repositories may use it.
//!
//! The body streams to a staging file under `uploads/`, hashed on the way, and is installed
//! as it arrived, uncompressed, sparing a second pass over gigabytes. Where the filesystem
//! can, the staging file is given the whole declared size up front, so no other writer can
//! take the space it was admitted for. Nothing is tagged until
//! every byte the `Content-Length` declared has arrived and hashes to the sha256 asked for, if
//! one was; a body cut short or gone idle leaves no staging file. The answer, a [`FilePut`],
//! comes once both tags are written.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::AsyncWriteExt;
use vk_hub_proto::registry::{
    FILE_ANNOTATIONS_HEADER, FILE_RETENTION_HEADER, FILE_SHA256_HEADER, FILES_PATH, FilePut,
    MAX_FILE_ANNOTATIONS, RETENTION_KEEP,
};

use crate::staging::{DrainError, Idle, Staging, drain_into, went_idle};
use crate::{
    Authz, Body, EXPIRES_ANNOTATION, FILE_PUTS, RETENTION_ANNOTATION, ServerState, accounts,
    body_of, error_response, valid_name, valid_tag,
};

/// Where every file is also tagged, by its sha256, under [`FILES`].
const BY_DIGEST: &str = "sha256";

/// The repository files are named in.
const FILES: &str = "files";

/// Free space a put leaves on the store's filesystem, past its own bytes.
const HEADROOM: u64 = 1 << 30;

/// How long a put's body may send nothing before the put is dropped and its slot freed.
const IDLE: Duration = Duration::from_secs(300);

/// The longest tag, as the OCI distribution spec bounds it.
const MAX_TAG: usize = 128;

/// The longest repository name, as clients bound it with the registry's host.
const MAX_NAME: usize = 255;

/// Whether `path` is a file put's.
pub(crate) fn is_files_path(path: &str) -> bool {
    path.starts_with(FILES_PATH)
}

/// Parse `rest` after [`FILES_PATH`] into `[<under>/]files/sha256`,
/// `[<under>/]files/<dir>` and `<name>`. Return `None` for invalid targets, including
/// the digest namespace: only a file's own hash may tag it there.
fn target<'a>(rest: &'a str, under: Option<&str>) -> Option<(String, String, &'a str)> {
    let (dir, name) = rest.rsplit_once('/')?;
    let files = match under {
        Some(u) => format!("{u}/{FILES}"),
        None => FILES.to_string(),
    };
    let digests = format!("{files}/{BY_DIGEST}");
    let repo = format!("{files}/{dir}");
    let ok = valid_name(&repo)
        && valid_name(&digests)
        && repo.len() <= MAX_NAME
        && digests.len() <= MAX_NAME
        && valid_tag(name)
        && name.len() <= MAX_TAG
        && dir != BY_DIGEST
        && !dir.starts_with(&format!("{BY_DIGEST}/"));
    ok.then_some((digests, repo, name))
}

/// Why a put's headers are refused.
#[derive(Debug, PartialEq, Eq)]
enum BadHeader {
    /// The header is not visible ASCII.
    NotText(&'static str),
    /// [`FILE_ANNOTATIONS_HEADER`] is not base64url, or decodes past
    /// [`MAX_FILE_ANNOTATIONS`].
    AnnotationsEncoding,
    /// [`FILE_ANNOTATIONS_HEADER`] decodes to something else than a JSON object of strings.
    AnnotationsJson,
    /// [`FILE_ANNOTATIONS_HEADER`] sets a key that is not its to set.
    AnnotationKey(String),
    /// [`FILE_RETENTION_HEADER`] is not [`RETENTION_KEEP`].
    Retention(String),
}

impl fmt::Display for BadHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BadHeader::NotText(name) => write!(f, "{name} is not text"),
            BadHeader::AnnotationsEncoding => write!(
                f,
                "{FILE_ANNOTATIONS_HEADER} is not base64url of at most {MAX_FILE_ANNOTATIONS} \
                 bytes"
            ),
            BadHeader::AnnotationsJson => {
                write!(
                    f,
                    "{FILE_ANNOTATIONS_HEADER} is not a JSON object of strings"
                )
            }
            BadHeader::AnnotationKey(k) => write!(
                f,
                "{FILE_ANNOTATIONS_HEADER} may not set {k:?}: retention is \
                 {FILE_RETENTION_HEADER}'s"
            ),
            BadHeader::Retention(v) => write!(
                f,
                "{FILE_RETENTION_HEADER} may only be {RETENTION_KEEP}, not {v:?}"
            ),
        }
    }
}

/// The manifest annotations a put's headers ask for.
fn annotations(headers: &hyper::HeaderMap) -> Result<BTreeMap<String, String>, BadHeader> {
    let header = |name: &'static str| {
        headers
            .get(name)
            .map(|v| v.to_str().map_err(|_| BadHeader::NotText(name)))
            .transpose()
    };
    let mut out = BTreeMap::new();
    if let Some(encoded) = header(FILE_ANNOTATIONS_HEADER)? {
        let decoded = vk_hub_proto::token::from_base64url(encoded)
            .filter(|d| d.len() <= MAX_FILE_ANNOTATIONS)
            .ok_or(BadHeader::AnnotationsEncoding)?;
        out = serde_json::from_slice::<BTreeMap<String, String>>(&decoded)
            .map_err(|_| BadHeader::AnnotationsJson)?;
        if let Some(k) = out
            .keys()
            .find(|k| k.is_empty() || *k == RETENTION_ANNOTATION || *k == EXPIRES_ANNOTATION)
        {
            return Err(BadHeader::AnnotationKey(k.clone()));
        }
    }
    match header(FILE_RETENTION_HEADER)? {
        None => {}
        Some(RETENTION_KEEP) => {
            out.insert(RETENTION_ANNOTATION.to_string(), RETENTION_KEEP.to_string());
        }
        Some(other) => {
            return Err(BadHeader::Retention(
                vk_hub_proto::display_safe(other).to_string(),
            ));
        }
    }
    Ok(out)
}

/// Give `file` `size` bytes of disk past its end now, without changing its length, so the
/// writes that fill it cannot run out of space: `Ok(false)` where the filesystem cannot.
fn preallocate(file: &std::fs::File, size: u64) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    if size == 0 {
        return Ok(true);
    }
    let len =
        libc::off_t::try_from(size).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    loop {
        // SAFETY: fallocate on a descriptor `file` owns, for the duration of the call.
        if unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, len) } == 0 {
            return Ok(true);
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EOPNOTSUPP) => return Ok(false),
            _ => return Err(e),
        }
    }
}

/// 507 for a put of `size` bytes the store's `free` bytes cannot take with [`HEADROOM`].
fn no_room(size: u64, free: u64) -> Response<Body> {
    error_response(
        StatusCode::INSUFFICIENT_STORAGE,
        "INSUFFICIENT_STORAGE",
        &format!(
            "the store has {free} bytes free, short of the {size} put and {HEADROOM} to spare"
        ),
    )
}

/// A put's bytes counted against the store's free space, with every other put's not yet
/// claimed on disk, until dropped.
struct Pending<'a> {
    unclaimed: &'a Mutex<u64>,
    size: u64,
}

impl<'a> Pending<'a> {
    /// Count `size` in `unclaimed` if `free` covers it, existing reservations and
    /// [`HEADROOM`]. Otherwise return the existing reservation total.
    fn admit(unclaimed: &'a Mutex<u64>, size: u64, free: u64) -> Result<Self, u64> {
        let mut counted = unclaimed.lock().unwrap_or_else(PoisonError::into_inner);
        if size.saturating_add(*counted).saturating_add(HEADROOM) > free {
            return Err(*counted);
        }
        *counted = counted.saturating_add(size);
        Ok(Pending { unclaimed, size })
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        let mut counted = self
            .unclaimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *counted = counted.saturating_sub(self.size);
    }
}

/// Why a put's space could not be claimed on disk.
#[derive(Debug)]
enum Unclaimed {
    /// The filesystem is short of it, with this much free before the claim, if known.
    NoRoom(Option<u64>),
    Failed(std::io::Error),
}

/// `claim` reports free space after preallocation, or `None` if unsupported.
/// Keep the reservation only when preallocation is unsupported; allocated bytes already
/// reduce the filesystem's free space.
fn hold<'a>(
    pending: Pending<'a>,
    claim: std::io::Result<Option<u64>>,
) -> Result<Option<Pending<'a>>, Unclaimed> {
    let size = pending.size;
    match claim {
        Ok(None) => Ok(Some(pending)),
        Ok(Some(free)) if free < HEADROOM => {
            Err(Unclaimed::NoRoom(Some(free.saturating_add(size))))
        }
        Ok(Some(_)) => Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => Err(Unclaimed::NoRoom(None)),
        Err(e) => Err(Unclaimed::Failed(e)),
    }
}

/// Answer a file put at `path`.
pub(crate) async fn route(
    state: &Arc<ServerState>,
    authz: &Authz<'_>,
    path: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    if req.method() != Method::PUT {
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            path,
        ));
    }
    let query = req.uri().query().unwrap_or_default();
    let under = crate::query_param(query, "under");
    let Some((digests, repo, name)) = path
        .strip_prefix(FILES_PATH)
        .and_then(|rest| target(rest, under.as_deref()))
    else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            &format!(
                "expected /files/<dir>/<name>[?under=<path>], repository paths of at most \
                 {MAX_NAME} characters and a tag of at most {MAX_TAG}, outside files/sha256"
            ),
        ));
    };
    for r in [digests.as_str(), repo.as_str()] {
        if let Some(resp) = crate::authorize_or_forbidden(authz, accounts::Action::Write, r) {
            return Ok(resp);
        }
    }
    // What hyper read of the framing: the `Content-Length`, none for a chunked body, and 0
    // for a request that declares neither, which has no body.
    let Some(size) = hyper::body::Body::size_hint(req.body()).exact() else {
        return Ok(error_response(
            StatusCode::LENGTH_REQUIRED,
            "SIZE_INVALID",
            "a file put must say its length",
        ));
    };
    let want = match req.headers().get(FILE_SHA256_HEADER) {
        None => None,
        Some(v) => match v.to_str().ok().filter(|s| vk_hub_proto::valid_sha256(s)) {
            Some(s) => Some(s.to_string()),
            None => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "DIGEST_INVALID",
                    &format!("{FILE_SHA256_HEADER} is not a sha256 in lowercase hex"),
                ));
            }
        },
    };
    let annotations = match annotations(req.headers()) {
        Ok(a) => a,
        Err(why) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "INVALID",
                &why.to_string(),
            ));
        }
    };
    let Some(_slot) = state.store.file_put_slot() else {
        let mut resp = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "UNAVAILABLE",
            &format!("{FILE_PUTS} file puts are under way already"),
        );
        resp.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("60"),
        );
        return Ok(resp);
    };
    let free = state.store.space().1;
    let pending = match Pending::admit(&state.store.unclaimed_puts, size, free) {
        Ok(p) => p,
        Err(unclaimed) => return Ok(no_room(size, free.saturating_sub(unclaimed))),
    };

    let (staging, file) = state.store.stage_file()?;
    let mut staging = Staging::new(staging);
    // Claimed on disk before a byte is read, off the runtime: the space admitted for may
    // since have gone to another writer, here or in another process, so it is checked again
    // once claimed. Where the filesystem cannot claim it, it stays counted until the put
    // ends.
    let store = state.store.clone();
    let (file, claimed) = tokio::task::spawn_blocking(move || {
        let claimed = preallocate(&file, size).map(|done| done.then(|| store.space().1));
        (file, claimed)
    })
    .await
    .context("claiming a file put's space panicked")?;
    let _pending = match hold(pending, claimed) {
        Ok(p) => p,
        Err(Unclaimed::NoRoom(left)) => return Ok(no_room(size, left.unwrap_or(free))),
        Err(Unclaimed::Failed(e)) => {
            return Err(anyhow::Error::from(e).context("claiming a file put's space"));
        }
    };
    let mut file = tokio::fs::File::from_std(file);
    let written = drain_into(&mut file, Idle::new(req.into_body(), IDLE), size).await;
    let (got, hex) = match written {
        Ok(w) => w,
        Err(DrainError::OverCap) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "SIZE_INVALID",
                "the body is longer than its Content-Length",
            ));
        }
        Err(DrainError::Failed(e)) if went_idle(&e) => {
            return Ok(error_response(
                StatusCode::REQUEST_TIMEOUT,
                "TIMEOUT",
                &format!("the body sent nothing for {}s", IDLE.as_secs()),
            ));
        }
        Err(DrainError::Failed(e)) => return Err(e),
    };
    if got != size {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "SIZE_INVALID",
            &format!("{got} bytes arrived of the {size} declared"),
        ));
    }
    if let Some(want) = want
        && want != hex
    {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("the file hashes to {hex}, not {want}"),
        ));
    }
    file.flush().await.context("writing a file put")?;
    file.sync_all().await.context("writing a file put")?;
    drop(file);

    let store = state.store.clone();
    let name = name.to_string();
    let put = tokio::task::spawn_blocking(move || {
        // Consumed from here, installed or not.
        staging.disarm();
        let tags = [
            (digests.as_str(), hex.as_str()),
            (repo.as_str(), name.as_str()),
        ];
        let manifest =
            store.put_staged_file(&tags, staging.path(), &hex, size, Some(&name), &annotations)?;
        eprintln!("vk-registry: stored {repo}:{name} ({size} bytes, sha256:{hex})");
        Ok::<_, anyhow::Error>(FilePut {
            sha256: hex,
            size,
            manifest,
        })
    })
    .await
    .context("storing a file put panicked")??;
    Response::builder()
        .status(StatusCode::CREATED)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body_of(Bytes::from(serde_json::to_vec(&put)?)))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_put_names_a_files_repository_and_a_tag() {
        let t = |rest, under| target(rest, under).map(|(d, r, n)| (d, r, n.to_string()));
        let want = |d: &str, r: &str, n: &str| Some((d.to_string(), r.to_string(), n.to_string()));
        assert_eq!(
            t("win-media/ws2025.iso", None),
            want("files/sha256", "files/win-media", "ws2025.iso")
        );
        assert_eq!(
            t("a/b/c.iso", None),
            want("files/sha256", "files/a/b", "c.iso")
        );
        assert_eq!(
            t("win-media/ws2025.iso", Some("build-cache")),
            want(
                "build-cache/files/sha256",
                "build-cache/files/win-media",
                "ws2025.iso"
            )
        );
        for bad in ["ws2025.iso", "sha256/x", "sha256/a/x", "/x", "d/", "d/a b"] {
            assert_eq!(t(bad, None), None, "{bad}");
        }
        assert_eq!(t("d/x", Some("Bad Path")), None);
        assert_eq!(t("d/x", Some("")), None);

        // Bounded before a byte is staged, not once the tags are written.
        let fits = |rest: &str, under: Option<&str>| target(rest, under).is_some();
        let tag = "t".repeat(MAX_TAG);
        assert!(fits(&format!("d/{tag}"), None));
        assert!(!fits(&format!("d/{tag}x"), None));
        let dir = "d".repeat(MAX_NAME - "files/".len());
        assert!(fits(&format!("{dir}/x"), None));
        assert!(!fits(&format!("{dir}d/x"), None));
        assert!(!fits("d/x", Some(&"u".repeat(MAX_NAME))));
    }

    #[test]
    fn annotation_headers_are_checked() {
        let headers = |pairs: &[(&'static str, &str)]| {
            let mut h = hyper::HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, hyper::header::HeaderValue::from_str(v).unwrap());
            }
            h
        };
        let b64 = |s: &str| vk_hub_proto::token::to_base64url(s.as_bytes());
        assert_eq!(annotations(&headers(&[])), Ok(BTreeMap::new()));
        assert_eq!(
            annotations(&headers(&[
                (FILE_ANNOTATIONS_HEADER, &b64(r#"{"a":"b"}"#)),
                (FILE_RETENTION_HEADER, RETENTION_KEEP),
            ])),
            Ok(BTreeMap::from([
                ("a".to_string(), "b".to_string()),
                (RETENTION_ANNOTATION.to_string(), RETENTION_KEEP.to_string()),
            ]))
        );
        assert_eq!(
            annotations(&headers(&[(FILE_ANNOTATIONS_HEADER, "not base64!")])),
            Err(BadHeader::AnnotationsEncoding)
        );
        let big = format!(r#"{{"a":"{}"}}"#, "x".repeat(MAX_FILE_ANNOTATIONS));
        assert_eq!(
            annotations(&headers(&[(FILE_ANNOTATIONS_HEADER, &b64(&big))])),
            Err(BadHeader::AnnotationsEncoding)
        );
        for bad in [r#"["a"]"#, r#"{"a":1}"#, "{"] {
            assert_eq!(
                annotations(&headers(&[(FILE_ANNOTATIONS_HEADER, &b64(bad))])),
                Err(BadHeader::AnnotationsJson),
                "{bad}"
            );
        }
        for key in ["", RETENTION_ANNOTATION, EXPIRES_ANNOTATION] {
            let json = serde_json::json!({ key: "x" }).to_string();
            assert_eq!(
                annotations(&headers(&[(FILE_ANNOTATIONS_HEADER, &b64(&json))])),
                Err(BadHeader::AnnotationKey(key.to_string()))
            );
        }
        assert!(matches!(
            annotations(&headers(&[(FILE_RETENTION_HEADER, "forever")])),
            Err(BadHeader::Retention(_))
        ));
    }

    /// Puts not claimed on disk count against the free space of the next, until they end.
    #[test]
    fn unclaimed_puts_count_against_the_next() {
        let unclaimed = Mutex::new(0);
        let free = 3 * HEADROOM;
        let first = Pending::admit(&unclaimed, HEADROOM, free).unwrap();
        assert!(
            Pending::admit(&unclaimed, HEADROOM, free).is_ok(),
            "fits beside the first"
        );
        assert_eq!(
            *unclaimed.lock().unwrap(),
            HEADROOM,
            "the second gave its count back"
        );
        assert_eq!(
            Pending::admit(&unclaimed, HEADROOM + 1, free).err(),
            Some(HEADROOM)
        );
        drop(first);
        assert!(Pending::admit(&unclaimed, 2 * HEADROOM, free).is_ok());
        assert_eq!(*unclaimed.lock().unwrap(), 0);
    }

    /// A put whose space was claimed on disk stops counting against the next puts' free
    /// space; one whose space could not be keeps counting until it ends.
    #[test]
    fn a_claimed_put_stops_counting() {
        let unclaimed = Mutex::new(0);
        let free = 3 * HEADROOM;
        let claimed = Pending::admit(&unclaimed, HEADROOM, free).unwrap();
        assert!(hold(claimed, Ok(Some(free - HEADROOM))).unwrap().is_none());
        assert_eq!(*unclaimed.lock().unwrap(), 0);

        let held = Pending::admit(&unclaimed, HEADROOM, free).unwrap();
        let held = hold(held, Ok(None)).unwrap();
        assert_eq!(*unclaimed.lock().unwrap(), HEADROOM);
        drop(held);
        assert_eq!(*unclaimed.lock().unwrap(), 0);

        let short = Pending::admit(&unclaimed, HEADROOM, free).unwrap();
        assert!(matches!(
            hold(short, Ok(Some(HEADROOM - 1))),
            Err(Unclaimed::NoRoom(_))
        ));
        let full = Pending::admit(&unclaimed, HEADROOM, free).unwrap();
        let enospc = std::io::Error::from_raw_os_error(libc::ENOSPC);
        assert!(matches!(
            hold(full, Err(enospc)),
            Err(Unclaimed::NoRoom(None))
        ));
        assert_eq!(*unclaimed.lock().unwrap(), 0);
    }

    /// Preallocated space is the file's on disk, its length unchanged, where the filesystem
    /// can preallocate at all.
    #[test]
    fn preallocating_claims_the_space_not_the_length() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("vk-reg-prealloc-{}", std::process::id()));
        // Left over from an earlier run, if anything; absent is the usual case.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = std::fs::File::create(dir.join("f")).unwrap();
        assert!(preallocate(&file, 0).unwrap());
        if preallocate(&file, 4 << 20).unwrap() {
            let meta = file.metadata().unwrap();
            assert_eq!(meta.len(), 0);
            assert!(meta.blocks() * 512 >= 4 << 20, "{} blocks", meta.blocks());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
