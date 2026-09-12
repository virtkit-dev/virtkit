//! Plain files under `/dav/files/<dir>/`, authorized as `files/<dir>`. PUT creates or replaces
//! objects, MKCOL creates directories, and DELETE removes files or empty directories. Writes
//! stream into `.staging/` and publish by rename. This area is separate from the OCI blob pool
//! and its garbage collector.

use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{
    CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LAST_MODIFIED, X_CONTENT_TYPE_OPTIONS,
};
use hyper::{Request, Response, StatusCode};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{
    ALLOWED_FILES, ALLOWED_READ, Depth, Entry, created, href, http_date, method_not_allowed,
    modified_of, multistatus, no_content, not_found, propfind_depth,
};
use crate::files_policy::valid_dir;
use crate::{Authz, Body, STREAM_CHUNK, ServerState, Store, accounts, body_of, error_response};

/// Maximum object size, checked both against Content-Length and while streaming.
const MAX_OBJECT: u64 = 4 << 30;

/// Serve uploads as binary attachments to prevent rendering on the `/browse` origin.
const OBJECT_TYPE: &str = "application/octet-stream";

/// Minimum age before GET refreshes mtime for eviction, limiting metadata writes.
const TOUCH_AFTER: Duration = Duration::from_secs(3600);

/// Serve one `files/` request; `segs` are the decoded components after `/dav/files/`.
pub(super) async fn route(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: &[String],
    method: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let mut parts: Vec<&str> = Vec::with_capacity(segs.len() + 1);
    parts.push("files");
    parts.extend(segs.iter().map(String::as_str));
    let action = match method {
        "GET" | "HEAD" | "PROPFIND" => accounts::Action::Read,
        "PUT" | "MKCOL" | "DELETE" => accounts::Action::Write,
        _ => return Ok(method_not_allowed(&href(&parts, false), ALLOWED_FILES)),
    };
    let store = &state.store;
    let Some((dir, rel)) = segs.split_first() else {
        return root(state, authz, method, req).await;
    };
    if !valid_dir(dir) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            &href(&parts, false),
        ));
    }
    // A directory authorizes as the repository `files/<dir>`.
    let repo = format!("files/{dir}");
    if let Some(resp) = crate::authorize_or_forbidden(authz, action, &repo) {
        return Ok(resp);
    }
    // Check the joined path before accessing the filesystem.
    let Some(path) = store.files_object_path(dir, rel) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            &href(&parts, false),
        ));
    };
    match method {
        "GET" | "HEAD" => get(&path, &href(&parts, false), method == "HEAD"),
        "PROPFIND" => propfind(&path, &parts, req).await,
        "PUT" => put(store, &path, rel.is_empty(), &href(&parts, false), req).await,
        "MKCOL" => mkcol(&path, &href(&parts, true)),
        "DELETE" => delete(&path, &href(&parts, false)),
        _ => Ok(method_not_allowed(&href(&parts, false), ALLOWED_FILES)),
    }
}

/// `/dav/files/` itself: a collection of the directories this caller may read. Nothing is
/// written at this level — a directory comes into being through `MKCOL` or `PUT` below it.
async fn root(
    state: &ServerState,
    authz: &Authz<'_>,
    method: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let this = href(&["files"], true);
    match method {
        "PROPFIND" => {
            let depth = match propfind_depth(req).await {
                Ok(d) => d,
                Err(resp) => return Ok(*resp),
            };
            let dir = state.store.files_dir();
            let mut entries = vec![Entry::collection(this, modified_of(&dir))];
            if depth == Depth::One {
                if !super::may_enumerate(state) {
                    return Ok(super::enumeration_refused());
                }
                let mut names: Vec<String> = std::fs::read_dir(&dir)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| valid_dir(n) && authz.may_read(&format!("files/{n}")))
                    .collect();
                names.sort();
                for name in names {
                    entries.push(Entry::collection(
                        href(&["files", &name], true),
                        modified_of(&dir.join(&name)),
                    ));
                }
            }
            Ok(multistatus(&entries))
        }
        "GET" | "HEAD" => Ok(not_found(&this)),
        _ => Ok(method_not_allowed(&this, ALLOWED_READ)),
    }
}

/// `GET`/`HEAD` an object. A directory or a missing path is a 404 — listings are
/// `PROPFIND`'s — and `Range` is ignored, a full 200 being a legal answer to it.
fn get(path: &Path, href: &str, head: bool) -> Result<Response<Body>> {
    // Read metadata through the open descriptor so it matches the served bytes. O_NOFOLLOW
    // rejects a symlink at the final component.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return Ok(not_found(href)),
    };
    let meta = file
        .metadata()
        .with_context(|| format!("stat of {}", path.display()))?;
    if !meta.is_file() {
        return Ok(not_found(href));
    }
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    // GET refreshes stale mtimes for eviction; HEAD does not. A failed touch may cause early
    // eviction but should not fail the read.
    if !head
        && SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|idle| idle > TOUCH_AFTER)
    {
        let _ = file.set_modified(SystemTime::now());
    }
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, OBJECT_TYPE)
        .header(CONTENT_LENGTH, meta.len().to_string())
        .header(LAST_MODIFIED, http_date(modified))
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(CONTENT_DISPOSITION, "attachment");
    if head {
        return builder.body(body_of(Bytes::new())).map_err(Into::into);
    }
    builder
        .body(crate::stream_body(file, href))
        .map_err(Into::into)
}

/// `PROPFIND` a file or a directory; at `Depth: 1` a directory lists its members — regular
/// files and directories, by `lstat`, so a symlink is neither followed nor shown.
async fn propfind(path: &Path, parts: &[&str], req: Request<Incoming>) -> Result<Response<Body>> {
    let depth = match propfind_depth(req).await {
        Ok(d) => d,
        Err(resp) => return Ok(*resp),
    };
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(not_found(&href(parts, false)));
    };
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    if meta.is_file() {
        return Ok(multistatus(&[Entry::file(
            href(parts, false),
            meta.len(),
            OBJECT_TYPE,
            modified,
        )]));
    }
    if !meta.is_dir() {
        return Ok(not_found(&href(parts, false)));
    }
    let mut entries = vec![Entry::collection(href(parts, true), modified)];
    if depth == Depth::One {
        let mut children: Vec<(String, std::fs::Metadata)> = std::fs::read_dir(path)
            .with_context(|| format!("listing {}", path.display()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let meta = e.metadata().ok()?;
                (meta.is_file() || meta.is_dir()).then_some((name, meta))
            })
            .collect();
        children.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, meta) in children {
            let mut child: Vec<&str> = parts.to_vec();
            child.push(&name);
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            entries.push(if meta.is_dir() {
                Entry::collection(href(&child, true), modified)
            } else {
                Entry::file(href(&child, false), meta.len(), OBJECT_TYPE, modified)
            });
        }
    }
    Ok(multistatus(&entries))
}

/// Why a streamed `PUT` stopped short.
enum PutError {
    /// the body crossed [`MAX_OBJECT`] — a 413, decided while reading
    TooLarge,
    /// the read or the write failed — a 500
    Failed(anyhow::Error),
}

/// Stream an object to staging, then rename: 201 for creation, 204 for replacement. No fsync: a
/// crash may lose a cache entry. Drain the body before responding, except for a declared length
/// over the cap, to avoid a connection reset during upload.
async fn put(
    store: &Store,
    path: &Path,
    top_level: bool,
    href: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    // Reject oversized Content-Length before reading; streaming checks also cover chunked
    // bodies.
    if req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_OBJECT)
    {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "TOOBIG",
            href,
        ));
    }
    // Reserve top-level names for directories. Drain the body before returning 405.
    let existing = std::fs::symlink_metadata(path).ok();
    if top_level || existing.as_ref().is_some_and(|m| m.is_dir()) {
        return match drain_into(&mut tokio::io::sink(), req.into_body(), MAX_OBJECT).await {
            Ok(()) => Ok(method_not_allowed(href, ALLOWED_FILES)),
            Err(PutError::TooLarge) => Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                href,
            )),
            Err(PutError::Failed(e)) => Err(e),
        };
    }
    // Stream uploads to bound memory use.
    let (staging, file) = store.new_files_staging()?;
    let mut file = tokio::fs::File::from_std(file);
    let written = drain_into(&mut file, req.into_body(), MAX_OBJECT).await;
    let flushed = file
        .flush()
        .await
        .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("writing an object")));
    drop(file);
    if let Err(e) = written.and(flushed) {
        // Nothing else will ever consume it, and nothing else removes it.
        let _ = std::fs::remove_file(&staging);
        return match e {
            PutError::TooLarge => Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                href,
            )),
            PutError::Failed(e) => Err(e),
        };
    }
    // Avoid recreating existing parents. A non-directory ancestor is a client conflict.
    let parent = path.parent().unwrap_or(path);
    if let Err(e) = tokio::fs::create_dir_all(parent).await {
        let _ = std::fs::remove_file(&staging);
        return match e.kind() {
            std::io::ErrorKind::NotADirectory | std::io::ErrorKind::AlreadyExists => {
                Ok(error_response(StatusCode::CONFLICT, "DENIED", href))
            }
            _ => Err(anyhow::Error::from(e).context(format!("creating {}", parent.display()))),
        };
    }
    // Published by rename — over whatever file was there, so a replace is atomic too.
    if let Err(e) = tokio::fs::rename(&staging, path).await {
        let _ = std::fs::remove_file(&staging);
        // A directory arrived at the name between the stat above and here.
        if e.kind() == std::io::ErrorKind::IsADirectory {
            return Ok(method_not_allowed(href, ALLOWED_FILES));
        }
        return Err(anyhow::Error::from(e).context(format!("publishing {}", path.display())));
    }
    Ok(if existing.is_some() {
        no_content()
    } else {
        created()
    })
}

/// Stream `body` to `out`, coalescing small frames and enforcing `cap`, including for chunked
/// bodies. `out` may be a sink when draining a rejected PUT. The generic body allows tests with
/// a small cap.
async fn drain_into<B>(
    out: &mut (impl AsyncWrite + Unpin),
    mut body: B,
    cap: u64,
) -> std::result::Result<(), PutError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut buf: Vec<u8> = Vec::with_capacity(STREAM_CHUNK);
    let mut total: u64 = 0;
    let io = |e: std::io::Error| PutError::Failed(anyhow::Error::from(e).context("writing"));
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("reading a PUT body")))?;
        // Trailers carry no content; a body that has them simply ends after them.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total = total.saturating_add(data.len() as u64);
        if total > cap {
            return Err(PutError::TooLarge);
        }
        // A frame already worth a write goes straight out rather than through the
        // coalescing buffer, which is there for the small ones.
        if buf.is_empty() && data.len() >= STREAM_CHUNK {
            out.write_all(&data).await.map_err(io)?;
            continue;
        }
        buf.extend_from_slice(&data);
        if buf.len() >= STREAM_CHUNK {
            out.write_all(&buf).await.map_err(io)?;
            buf.clear();
        }
    }
    if !buf.is_empty() {
        out.write_all(&buf).await.map_err(io)?;
    }
    Ok(())
}

/// Create a directory and missing ancestors. Return 201 on success, 405 if the target exists,
/// or 409 for a non-directory ancestor.
fn mkcol(path: &Path, href: &str) -> Result<Response<Body>> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Ok(method_not_allowed(href, ALLOWED_FILES));
    }
    match std::fs::create_dir_all(path) {
        Ok(()) => Ok(created()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotADirectory | std::io::ErrorKind::AlreadyExists
            ) =>
        {
            Ok(error_response(StatusCode::CONFLICT, "DENIED", href))
        }
        Err(e) => Err(anyhow::Error::from(e).context(format!("creating {}", path.display()))),
    }
}

/// Delete a file or empty directory (204); return 404 if absent. Recursive deletion is
/// unsupported.
fn delete(path: &Path, href: &str) -> Result<Response<Body>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => match std::fs::remove_dir(path) {
            Ok(()) => Ok(no_content()),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(error_response(
                StatusCode::FORBIDDEN,
                "DENIED",
                "a directory with members is not deleted",
            )),
            Err(e) => Err(anyhow::Error::from(e).context(format!("removing {}", path.display()))),
        },
        Ok(_) => {
            std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
            Ok(no_content())
        }
        Err(_) => Ok(not_found(href)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the streaming size cap with a small limit and multiple frames.
    #[tokio::test]
    async fn a_body_over_the_cap_stops_being_written() {
        let dir = std::env::temp_dir().join(format!("vk-reg-files-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("staged");

        // Several frames, so the cap is crossed part way through rather than at the first.
        let frames = || {
            let chunks: Vec<std::result::Result<hyper::body::Frame<Bytes>, std::io::Error>> = (0
                ..4)
                .map(|_| Ok(hyper::body::Frame::data(Bytes::from(vec![1u8; 100]))))
                .collect();
            http_body_util::StreamBody::new(futures::stream::iter(chunks))
        };

        let mut file = tokio::fs::File::create(&path).await.unwrap();
        assert!(matches!(
            drain_into(&mut file, frames(), 250).await,
            Err(PutError::TooLarge)
        ));
        drop(file);
        // Refused where the count crossed, so the partial file is bounded by the cap plus
        // the frame that crossed it — never the whole body.
        let staged = std::fs::metadata(&path).unwrap().len();
        assert!(staged <= 300, "wrote {staged} bytes past a 250-byte cap");

        // Exactly at the cap is not over it.
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        assert!(drain_into(&mut file, frames(), 400).await.is_ok());
        file.flush().await.unwrap();
        drop(file);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 400);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
