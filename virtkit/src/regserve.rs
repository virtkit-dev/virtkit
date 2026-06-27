//! `virtkit registry serve` — an embedded, local OCI registry server.
//!
//! A minimal implementation of the OCI distribution v2 API, just enough for the
//! `virtkit registry push`/`pull` client (registry.rs) and the executor's pull
//! path: blob existence/upload (chunked + monolithic) and manifest put/get. It
//! backs a **content-addressed store on the local filesystem**, so every worktree
//! that points its `[registry]` at this server shares one blob pool — a chunk
//! pushed from one worktree is instantly reused by the others (the FastCDC+zstd
//! dedup the client already does, now shared host-wide).
//!
//! Intended for a single user on loopback (`127.0.0.1`): no auth, no TLS (pair it
//! with `[registry] insecure = true`). Install it as a `systemd --user` service
//! with `virtkit registry install-service`.
//!
//! Store layout under `--root` (default `$XDG_DATA_HOME/virtkit/registry`):
//!   blobs/sha256/<hex>            content-addressed blobs (chunks, configs,
//!                                 manifests, any kernel/initrd) — shared by all repos
//!   repos/<name>/tags/<tag>       file holding the tagged manifest's digest
//!   repos/<name>/manifests/<hex>  sidecar: that manifest's Content-Type
//!   uploads/<id>                  in-progress blob uploads (this process only)

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

/// Default content type for a manifest whose Content-Type sidecar is missing.
const DEFAULT_MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The on-disk content-addressed store. Cheap to clone-share via `Arc`.
struct Store {
    root: PathBuf,
    /// monotonic upload-id source (unique within this server process)
    next_upload: AtomicU64,
}

impl Store {
    fn new(root: PathBuf) -> Result<Arc<Self>> {
        for sub in ["blobs/sha256", "blobs/zstd", "uploads", "repos"] {
            let p = root.join(sub);
            std::fs::create_dir_all(&p).with_context(|| format!("creating {}", p.display()))?;
        }
        Ok(Arc::new(Store {
            root,
            next_upload: AtomicU64::new(0),
        }))
    }
    /// Identity blob: the stored bytes ARE the canonical (digested) bytes.
    fn blob_path(&self, hex: &str) -> PathBuf {
        self.root.join("blobs/sha256").join(hex)
    }
    /// Transparently-compressed blob: the stored bytes are a zstd frame; the canonical
    /// (digested) bytes are its decompression (hex = sha256 of the decompressed form).
    fn zstd_blob_path(&self, hex: &str) -> PathBuf {
        self.root.join("blobs/zstd").join(hex)
    }
    /// Locate a blob by digest hex: `(path, stored_as_zstd)`. Checks the zstd store
    /// then the identity store.
    fn find_blob(&self, hex: &str) -> Option<(PathBuf, bool)> {
        let z = self.zstd_blob_path(hex);
        if z.is_file() {
            return Some((z, true));
        }
        let p = self.blob_path(hex);
        p.is_file().then_some((p, false))
    }
    fn upload_path(&self, id: &str) -> PathBuf {
        self.root.join("uploads").join(id)
    }
    fn tag_path(&self, name: &str, tag: &str) -> PathBuf {
        self.root.join("repos").join(name).join("tags").join(tag)
    }
    fn manifest_type_path(&self, name: &str, hex: &str) -> PathBuf {
        self.root
            .join("repos")
            .join(name)
            .join("manifests")
            .join(hex)
    }
}

/// Run the registry until the process is stopped. `addr` is the listen address
/// (loopback for single-user use); `root` is the store directory.
pub async fn serve(addr: SocketAddr, root: PathBuf) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    serve_on(listener, root).await
}

/// Serve on an already-bound listener (so the caller can pick an ephemeral port and
/// learn it first — see [`start_inline`]). The store is content-addressed and written
/// atomically, so several servers may serve the same `root` concurrently.
pub async fn serve_on(listener: TcpListener, root: PathBuf) -> Result<()> {
    let store = Store::new(root)?;
    if let Ok(addr) = listener.local_addr() {
        eprintln!(
            "virtkit registry: serving {} on http://{addr}",
            store.root.display()
        );
    }
    loop {
        let (stream, _peer) = listener.accept().await.context("accept")?;
        let store = store.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, store.clone()));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                eprintln!("virtkit registry: connection error: {e}");
            }
        });
    }
}

/// Start an inline registry over `root` on an ephemeral loopback port and return its
/// address, running as a background task for the life of the process. This is the
/// on-demand local-dev path (`fleet --registry-serve`): no daemon — each build spins
/// one up over the shared store and it dies with the process. Multiple inline servers
/// may serve the same `root` at once (atomic, content-addressed writes).
pub async fn start_inline(root: PathBuf) -> Result<SocketAddr> {
    let std_listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).context("binding the inline registry")?;
    let addr = std_listener
        .local_addr()
        .context("inline registry local_addr")?;
    std_listener
        .set_nonblocking(true)
        .context("inline registry set_nonblocking")?;
    let listener =
        TcpListener::from_std(std_listener).context("adopting the inline registry listener")?;
    tokio::spawn(async move {
        if let Err(e) = serve_on(listener, root).await {
            eprintln!("virtkit: inline registry exited: {e:#}");
        }
    });
    Ok(addr)
}

/// Wrap `route`, turning any internal error into a 500 (a handler never fails the
/// connection).
async fn handle(
    req: Request<Incoming>,
    store: Arc<Store>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(route(req, store).await.unwrap_or_else(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            &format!("{e:#}"),
        )
    }))
}

async fn route(req: Request<Incoming>, store: Arc<Store>) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    // transparent-zstd negotiation: a PUT body may already be a zstd frame
    // (`Content-Encoding: zstd`), and a GET may accept the stored frame verbatim
    // (`Accept-Encoding: …zstd…`).
    let put_is_zstd = header_has(&req, hyper::header::CONTENT_ENCODING, "zstd");
    let accept_zstd = header_has(&req, hyper::header::ACCEPT_ENCODING, "zstd");

    // GET /v2/ — the API version probe. We also advertise transparent-zstd support
    // so an auto-mode client uploads uncompressed-digest chunks (this store stores
    // them compressed and serves canonical bytes to plain clients).
    if path == "/v2" || path == "/v2/" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Distribution-Api-Version", "registry/2.0")
            .header(crate::registry::TRANSPARENT_ZSTD_HEADER, "1")
            .body(Full::new(Bytes::from_static(b"{}")))
            .map_err(Into::into);
    }
    let Some(rest) = path.strip_prefix("/v2/") else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "not a v2 path",
        ));
    };

    // <name>/blobs/uploads[/<id>] — checked before the bare /blobs/ form, which it
    // also contains. POST starts a session; PATCH appends; PUT?digest finalizes.
    if let Some(idx) = rest.rfind("/blobs/uploads") {
        let name = &rest[..idx];
        let after = rest[idx + "/blobs/uploads".len()..].trim_matches('/');
        if !valid_name(name) {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                name,
            ));
        }
        return match method {
            Method::POST => start_upload(&store, name),
            Method::PATCH => {
                let body = collect(req).await?;
                patch_upload(&store, name, after, &body)
            }
            Method::PUT => {
                let body = collect(req).await?;
                finish_upload(&store, name, after, &query, &body, put_is_zstd)
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "",
            )),
        };
    }

    // <name>/blobs/<digest> — HEAD (exists) / GET (fetch).
    if let Some(idx) = rest.rfind("/blobs/") {
        let name = &rest[..idx];
        let digest = &rest[idx + "/blobs/".len()..];
        if !valid_name(name) || !valid_digest(digest) {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                digest,
            ));
        }
        let head = method == Method::HEAD;
        return match method {
            Method::GET | Method::HEAD => get_blob(&store, digest, head, accept_zstd),
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "",
            )),
        };
    }

    // <name>/manifests/<tag|digest> — PUT (store) / GET / HEAD.
    if let Some(idx) = rest.rfind("/manifests/") {
        let name = &rest[..idx];
        let reference = &rest[idx + "/manifests/".len()..];
        if !valid_name(name) || !valid_reference(reference) {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                reference,
            ));
        }
        return match method {
            Method::PUT => {
                let ctype = req
                    .headers()
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(DEFAULT_MANIFEST_TYPE)
                    .to_string();
                let body = collect(req).await?;
                put_manifest(&store, name, reference, &ctype, &body)
            }
            Method::GET | Method::HEAD => {
                get_manifest(&store, name, reference, method == Method::HEAD)
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "",
            )),
        };
    }

    // <name>/tags/list — best-effort tag listing (not used by the pull path).
    if let Some(name) = rest.strip_suffix("/tags/list")
        && valid_name(name)
    {
        return list_tags(&store, name);
    }

    Ok(error_response(StatusCode::NOT_FOUND, "NOT_FOUND", &path))
}

/// POST /v2/<name>/blobs/uploads/ — open an upload session (an empty temp file).
fn start_upload(store: &Store, name: &str) -> Result<Response<Full<Bytes>>> {
    let id = format!(
        "{}-{}",
        std::process::id(),
        store.next_upload.fetch_add(1, Ordering::Relaxed)
    );
    std::fs::write(store.upload_path(&id), b"").context("creating the upload file")?;
    accepted_upload(name, &id, 0)
}

/// PATCH /v2/<name>/blobs/uploads/<id> — append a chunk to the session file.
fn patch_upload(store: &Store, name: &str, id: &str, body: &[u8]) -> Result<Response<Full<Bytes>>> {
    if !valid_upload_id(id) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            id,
        ));
    }
    let path = store.upload_path(id);
    if !path.is_file() {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            id,
        ));
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    use std::io::Write;
    f.write_all(body).context("appending to the upload")?;
    let size = f.metadata()?.len();
    accepted_upload(name, id, size)
}

/// PUT /v2/<name>/blobs/uploads/<id>?digest=<d> — append the final bytes (if any) and
/// promote the session file to the store under the client's digest. The digest is
/// trusted (local single-user registry; oci-client re-verifies on pull). Storage is
/// transparently compressed: if the body is already a zstd frame (`Content-Encoding:
/// zstd`, an aware client) it is stored verbatim in the zstd store; otherwise the raw
/// body is zstd'd and stored compressed when that's actually smaller (so an
/// already-compressed blob — a compressed-digest chunk — is kept as-is). Either way
/// the digest indexes the *canonical* (decompressed) bytes.
fn finish_upload(
    store: &Store,
    name: &str,
    id: &str,
    query: &str,
    body: &[u8],
    body_is_zstd: bool,
) -> Result<Response<Full<Bytes>>> {
    if !valid_upload_id(id) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            id,
        ));
    }
    let Some(digest) = query_param(query, "digest") else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "missing digest",
        ));
    };
    if !valid_digest(&digest) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &digest,
        ));
    }
    let hex = digest.trim_start_matches("sha256:").to_string();
    let upload = store.upload_path(id);
    if !body.is_empty() {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&upload)
            .with_context(|| format!("opening {}", upload.display()))?;
        f.write_all(body).context("appending the final chunk")?;
    }

    // already stored (either form)? idempotent — drop the upload.
    if store.find_blob(&hex).is_some() {
        let _ = std::fs::remove_file(&upload);
    } else if body_is_zstd {
        // the upload is a zstd frame whose decompression hashes to the digest: store
        // it verbatim in the zstd store (no re-compression).
        std::fs::rename(&upload, store.zstd_blob_path(&hex))
            .with_context(|| format!("promoting zstd upload {hex}"))?;
    } else {
        // raw canonical bytes: compress; keep compressed only if it actually shrinks
        // (a compressed-digest chunk won't, and stays identity — no double-compress).
        let raw =
            std::fs::read(&upload).with_context(|| format!("reading {}", upload.display()))?;
        let z = crate::registry::zstd_with_size(&raw)?;
        if z.len() < raw.len() {
            atomic_write(&store.zstd_blob_path(&hex), &z)?;
            let _ = std::fs::remove_file(&upload);
        } else {
            std::fs::rename(&upload, store.blob_path(&hex))
                .with_context(|| format!("promoting blob {hex}"))?;
        }
    }

    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/{name}/blobs/{digest}"))
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// GET/HEAD /v2/<name>/blobs/<digest>. The digest names the *canonical* bytes. An
/// identity blob is served verbatim. A zstd-stored blob is served verbatim (with
/// `Content-Encoding: zstd`) when the client accepts zstd, else decompressed — so a
/// plain OCI client always gets the canonical bytes and verifies the digest.
fn get_blob(
    store: &Store,
    digest: &str,
    head: bool,
    accept_zstd: bool,
) -> Result<Response<Full<Bytes>>> {
    let hex = digest.trim_start_matches("sha256:");
    let Some((path, is_zstd)) = store.find_blob(hex) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            digest,
        ));
    };

    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream");

    // serve the stored frame as-is; the client decodes it back to canonical. The
    // wire length is the stored (compressed) size — `stat` it; HEAD reads nothing.
    if is_zstd && accept_zstd {
        let builder = builder.header(hyper::header::CONTENT_ENCODING, "zstd");
        if head {
            return builder
                .header(hyper::header::CONTENT_LENGTH, blob_len(&path)?.to_string())
                .body(Full::new(Bytes::new()))
                .map_err(Into::into);
        }
        let stored = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        return builder
            .header(hyper::header::CONTENT_LENGTH, stored.len().to_string())
            .body(Full::new(Bytes::from(stored)))
            .map_err(Into::into);
    }

    // serve the canonical (decompressed, for a zstd blob) bytes.
    if is_zstd {
        // HEAD only needs the canonical length, read from the frame header (a handful
        // of bytes) without touching the rest; GET decompresses the whole body.
        if head {
            return builder
                .header(
                    hyper::header::CONTENT_LENGTH,
                    zstd_canonical_len(&path)?.to_string(),
                )
                .body(Full::new(Bytes::new()))
                .map_err(Into::into);
        }
        let stored = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let raw = zstd::decode_all(&stored[..]).context("decompressing a stored blob")?;
        return builder
            .header(hyper::header::CONTENT_LENGTH, raw.len().to_string())
            .body(Full::new(Bytes::from(raw)))
            .map_err(Into::into);
    }

    // identity blob: HEAD needs only the size (`stat`); GET serves the bytes.
    if head {
        return builder
            .header(hyper::header::CONTENT_LENGTH, blob_len(&path)?.to_string())
            .body(Full::new(Bytes::new()))
            .map_err(Into::into);
    }
    let stored = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    builder
        .header(hyper::header::CONTENT_LENGTH, stored.len().to_string())
        .body(Full::new(Bytes::from(stored)))
        .map_err(Into::into)
}

/// PUT /v2/<name>/manifests/<tag|digest> — store the manifest bytes (content
/// addressed) + its Content-Type sidecar, and point the tag at it (if a tag).
fn put_manifest(
    store: &Store,
    name: &str,
    reference: &str,
    ctype: &str,
    body: &[u8],
) -> Result<Response<Full<Bytes>>> {
    let digest = format!("sha256:{}", sha256_hex_raw(body));
    let hex = &digest[7..];
    let dest = store.blob_path(hex);
    if !dest.exists() {
        atomic_write(&dest, body)?;
    }
    atomic_write(&store.manifest_type_path(name, hex), ctype.as_bytes())?;
    // a tag reference also gets a tag -> digest pointer (a digest reference is
    // already self-describing).
    if !reference.starts_with("sha256:") {
        atomic_write(&store.tag_path(name, reference), digest.as_bytes())?;
    }
    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/{name}/manifests/{digest}"))
        .header("Docker-Content-Digest", &digest)
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// GET/HEAD /v2/<name>/manifests/<tag|digest>.
fn get_manifest(
    store: &Store,
    name: &str,
    reference: &str,
    head: bool,
) -> Result<Response<Full<Bytes>>> {
    // resolve the reference to a digest (a tag is a pointer file; a digest is itself)
    let digest = if reference.starts_with("sha256:") {
        reference.to_string()
    } else {
        match std::fs::read_to_string(store.tag_path(name, reference)) {
            Ok(d) => d.trim().to_string(),
            Err(_) => {
                return Ok(error_response(
                    StatusCode::NOT_FOUND,
                    "MANIFEST_UNKNOWN",
                    reference,
                ));
            }
        }
    };
    let hex = digest.trim_start_matches("sha256:");
    let Ok(data) = std::fs::read(store.blob_path(hex)) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            &digest,
        ));
    };
    let ctype = std::fs::read_to_string(store.manifest_type_path(name, hex))
        .unwrap_or_else(|_| DEFAULT_MANIFEST_TYPE.to_string());
    let len = data.len();
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::CONTENT_TYPE, ctype.trim())
        .header(hyper::header::CONTENT_LENGTH, len.to_string())
        .body(Full::new(if head {
            Bytes::new()
        } else {
            Bytes::from(data)
        }))
        .map_err(Into::into)
}

/// GET /v2/<name>/tags/list.
fn list_tags(store: &Store, name: &str) -> Result<Response<Full<Bytes>>> {
    let dir = store.root.join("repos").join(name).join("tags");
    let mut tags: Vec<String> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    tags.sort();
    let body = serde_json::json!({ "name": name, "tags": tags }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(Into::into)
}

/// A 202 Accepted upload-progress response (POST/PATCH), carrying the session
/// Location the client uses for the next request.
fn accepted_upload(name: &str, id: &str, size: u64) -> Result<Response<Full<Bytes>>> {
    let range_end = size.saturating_sub(1);
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", format!("/v2/{name}/blobs/uploads/{id}"))
        .header("Range", format!("0-{range_end}"))
        .header("Docker-Upload-UUID", id)
        .header(hyper::header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// An OCI error response: the documented `{ "errors": [ { code, message } ] }` body.
fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    let body =
        serde_json::json!({ "errors": [ { "code": code, "message": message } ] }).to_string();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("building an error response")
}

/// Collect a request body fully into memory. Bodies here are bounded by the
/// client's chunk size (≤ one FastCDC chunk, ≤16 MiB) plus small manifests.
async fn collect(req: Request<Incoming>) -> Result<Bytes> {
    Ok(req.into_body().collect().await?.to_bytes())
}

/// True if request header `name` lists `needle` (e.g. `Accept-Encoding: zstd`).
/// Substring match — fine for the single token we negotiate.
fn header_has(req: &Request<Incoming>, name: hyper::header::HeaderName, needle: &str) -> bool {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains(needle))
}

/// The decompressed length of a zstd frame, read from its header (no full decode);
/// `None` if the frame doesn't record it (see [`crate::registry::zstd_with_size`]).
fn zstd_frame_len(frame: &[u8]) -> Option<u64> {
    zstd::zstd_safe::get_frame_content_size(frame)
        .ok()
        .flatten()
}

/// A zstd frame header is at most 18 bytes (4-byte magic + ≤14-byte header), enough
/// for [`zstd_frame_len`] to read the embedded content size.
const ZSTD_HEADER_MAX: usize = 18;

/// Size of a stored blob on disk, from `stat` — no read.
fn blob_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

/// Canonical (decompressed) length of a stored zstd blob, read from the frame header
/// alone. Our encoder always records the content size, so the full-decode fallback
/// (for a frame that omits it) is only a correctness backstop.
fn zstd_canonical_len(path: &Path) -> Result<u64> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut head = Vec::with_capacity(ZSTD_HEADER_MAX);
    f.by_ref()
        .take(ZSTD_HEADER_MAX as u64)
        .read_to_end(&mut head)
        .with_context(|| format!("reading the zstd header of {}", path.display()))?;
    if let Some(len) = zstd_frame_len(&head) {
        return Ok(len);
    }
    let stored = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(zstd::decode_all(&stored[..])
        .context("decompressing a stored blob")?
        .len() as u64)
}

/// Monotonic suffix source for [`atomic_write`] temp files (unique within a process;
/// the pid disambiguates across the concurrent servers sharing a store).
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` atomically (temp sibling + rename), so a concurrent reader
/// — or another server sharing this store — never observes a partial file.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".tmp.{}.{seq}", std::process::id()));
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

fn sha256_hex_raw(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// A repository name: one or more `/`-separated path components, each a non-empty
/// run of `[A-Za-z0-9._-]` and not `.`/`..` — so it never escapes the store dir.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// `sha256:<64 lowercase hex>`.
fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A manifest reference: a digest, or a single safe tag component.
fn valid_reference(r: &str) -> bool {
    valid_digest(r) || valid_tag(r)
}

fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t != "."
        && t != ".."
        && !t.contains('/')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An upload id is one this server minted (`<pid>-<n>`): digits and a single dash,
/// no path separators.
fn valid_upload_id(id: &str) -> bool {
    !id.is_empty() && !id.contains('/') && id.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

/// Look up a query parameter (percent-decoding the value, since the client encodes
/// the `sha256:` digest's colon as `%3A`).
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Minimal application/x-www-form-urlencoded decode: `%XX` hex escapes and `+`.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Default store root: `$XDG_DATA_HOME/virtkit/registry`, else `~/.local/share/...`.
pub fn default_root() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("virtkit/registry"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_DATA_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/share/virtkit/registry"))
}

/// Install + start a `systemd --user` unit running `registry serve` with this
/// `addr`/`root`, so the shared store survives logout and reboots.
pub fn install_service(addr: SocketAddr, root: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let cfg_home = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(c) => PathBuf::from(c),
        None => {
            let home = std::env::var_os("HOME").context("HOME is not set")?;
            PathBuf::from(home).join(".config")
        }
    };
    let unit_dir = cfg_home.join("systemd/user");
    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("creating {}", unit_dir.display()))?;
    let unit_path = unit_dir.join("virtkit-registry.service");
    let unit = format!(
        "[Unit]\n\
         Description=virtkit local OCI registry (shared microVM bundle store)\n\
         After=network.target\n\
         \n\
         [Service]\n\
         ExecStart={exe} registry serve --addr {addr} --root {root}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = exe.display(),
        root = root.display(),
    );
    std::fs::write(&unit_path, unit).with_context(|| format!("writing {}", unit_path.display()))?;
    println!("virtkit: wrote {}", unit_path.display());

    let run = |args: &[&str]| -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .arg("--user")
            .args(args)
            .status()
            .context("running systemctl --user (is systemd available?)")?;
        if !status.success() {
            bail!("systemctl --user {} failed ({status})", args.join(" "));
        }
        Ok(())
    };
    run(&["daemon-reload"])?;
    run(&["enable", "--now", "virtkit-registry.service"])?;
    println!(
        "virtkit: virtkit-registry.service enabled + started (http://{addr}, store {})",
        root.display()
    );
    println!(
        "virtkit: point each worktree's [registry] at it:\n\
         \n    [registry]\n    repo = \"{addr}/bundles\"\n    insecure = true\n\
         \nvirtkit: for it to run without an active login session: loginctl enable-linger $USER"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// finish_upload stores a compressible raw blob zstd-compressed (smaller, in the
    /// zstd store) and an incompressible one verbatim (identity store), and find_blob
    /// resolves both with the canonical bytes recoverable. Exercises the transparent
    /// adaptive storage without an HTTP round-trip.
    #[test]
    fn adaptive_store_compresses_then_serves_canonical() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // compressible raw blob -> stored zstd, smaller, canonical decompresses back.
        let raw = vec![7u8; 100_000];
        let digest = format!("sha256:{}", sha256_hex_raw(&raw));
        let hex = digest.trim_start_matches("sha256:");
        std::fs::write(store.upload_path("1-0"), b"").unwrap();
        let resp = finish_upload(
            &store,
            "img",
            "1-0",
            &format!("digest={digest}"),
            &raw,
            false,
        )
        .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let (path, is_zstd) = store.find_blob(hex).expect("blob stored");
        assert!(is_zstd, "a compressible blob should be stored zstd");
        assert!(std::fs::metadata(&path).unwrap().len() < raw.len() as u64);
        assert_eq!(
            zstd::decode_all(&std::fs::read(&path).unwrap()[..]).unwrap(),
            raw
        );

        // incompressible blob -> stored verbatim (identity), no zstd dir entry.
        // a high-entropy splitmix64 stream — zstd cannot shrink it.
        let mut state = 0x9e3779b97f4a7c15u64;
        let rnd: Vec<u8> = (0..50_000)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                (z ^ (z >> 31)) as u8
            })
            .collect();
        let rdigest = format!("sha256:{}", sha256_hex_raw(&rnd));
        let rhex = rdigest.trim_start_matches("sha256:");
        std::fs::write(store.upload_path("1-1"), b"").unwrap();
        finish_upload(
            &store,
            "img",
            "1-1",
            &format!("digest={rdigest}"),
            &rnd,
            false,
        )
        .unwrap();
        let (rpath, ris_zstd) = store.find_blob(rhex).expect("blob stored");
        assert!(!ris_zstd, "an incompressible blob should stay identity");
        assert_eq!(std::fs::read(&rpath).unwrap(), rnd);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_validation_blocks_traversal() {
        assert!(valid_name("bundles/wabbuilder"));
        assert!(valid_name("redis"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name("a//b"));
        assert!(!valid_name("a/../b"));
        assert!(!valid_name(""));
        assert!(!valid_name("bad name"));
    }

    #[test]
    fn digest_and_reference_validation() {
        let good = format!("sha256:{}", "a".repeat(64));
        assert!(valid_digest(&good));
        assert!(!valid_digest("sha256:zz"));
        assert!(!valid_digest("md5:abc"));
        assert!(valid_reference(&good));
        assert!(valid_reference("20260627-abc"));
        assert!(!valid_reference("../x"));
        assert!(!valid_reference("a/b"));
    }

    #[test]
    fn upload_id_validation() {
        assert!(valid_upload_id("12345-7"));
        assert!(!valid_upload_id("../escape"));
        assert!(!valid_upload_id("a/b"));
        assert!(!valid_upload_id("abc")); // letters are not minted ids
    }

    #[test]
    fn zstd_frame_len_reads_embedded_content_size() {
        // the shared encoder embeds the content size (encode_all does not), so HEAD can
        // read the canonical length from the frame header without decompressing.
        let raw = vec![7u8; 50_000];
        let frame = crate::registry::zstd_with_size(&raw).unwrap();
        assert_eq!(zstd_frame_len(&frame), Some(50_000));
        assert_eq!(zstd::decode_all(&frame[..]).unwrap(), raw);
        // encode_all (no pledged size) omits it — the reason that helper exists.
        assert_eq!(
            zstd_frame_len(&zstd::encode_all(&raw[..], crate::registry::ZSTD_LEVEL).unwrap()),
            None
        );
    }

    #[test]
    fn percent_decode_handles_digest_colon() {
        assert_eq!(percent_decode("sha256%3Aabc"), "sha256:abc");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("trailing%"), "trailing%");
    }

    #[test]
    fn query_param_extracts_and_decodes() {
        assert_eq!(
            query_param("digest=sha256%3Adead", "digest").as_deref(),
            Some("sha256:dead")
        );
        assert_eq!(query_param("a=1&digest=x", "digest").as_deref(), Some("x"));
        assert_eq!(query_param("a=1", "digest"), None);
    }

    #[test]
    fn sha256_hex_raw_matches_known_vector() {
        assert_eq!(
            sha256_hex_raw(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
