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
        for sub in ["blobs/sha256", "uploads", "repos"] {
            let p = root.join(sub);
            std::fs::create_dir_all(&p).with_context(|| format!("creating {}", p.display()))?;
        }
        Ok(Arc::new(Store {
            root,
            next_upload: AtomicU64::new(0),
        }))
    }
    fn blob_path(&self, hex: &str) -> PathBuf {
        self.root.join("blobs/sha256").join(hex)
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
/// learn it first). The store is content-addressed and written atomically, so several
/// servers may serve the same `root` concurrently.
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

    // GET /v2/ — the API version probe.
    if path == "/v2" || path == "/v2/" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Distribution-Api-Version", "registry/2.0")
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
                finish_upload(&store, name, after, &query, &body)
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
            Method::GET | Method::HEAD => get_blob(&store, digest, head),
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

/// PUT /v2/<name>/blobs/uploads/<id>?digest=<d> — append the final bytes (if any),
/// verify the digest, and promote the session file to the content-addressed store.
fn finish_upload(
    store: &Store,
    name: &str,
    id: &str,
    query: &str,
    body: &[u8],
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
    let upload = store.upload_path(id);
    if !body.is_empty() {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&upload)
            .with_context(|| format!("opening {}", upload.display()))?;
        f.write_all(body).context("appending the final chunk")?;
    }
    let data = std::fs::read(&upload).with_context(|| format!("reading {}", upload.display()))?;
    let actual = sha256_hex(&data);
    if actual != digest {
        let _ = std::fs::remove_file(&upload);
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("computed {actual}, expected {digest}"),
        ));
    }
    let hex = digest.trim_start_matches("sha256:");
    let dest = store.blob_path(hex);
    // promote into the shared store (idempotent: a concurrent push may have landed it)
    if dest.exists() {
        let _ = std::fs::remove_file(&upload);
    } else {
        std::fs::rename(&upload, &dest)
            .with_context(|| format!("promoting upload to {}", dest.display()))?;
    }
    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/{name}/blobs/{digest}"))
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// GET/HEAD /v2/<name>/blobs/<digest>.
fn get_blob(store: &Store, digest: &str, head: bool) -> Result<Response<Full<Bytes>>> {
    let hex = digest.trim_start_matches("sha256:");
    let path = store.blob_path(hex);
    let Ok(data) = std::fs::read(&path) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            digest,
        ));
    };
    let len = data.len();
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .header(hyper::header::CONTENT_LENGTH, len.to_string())
        .body(Full::new(if head {
            Bytes::new()
        } else {
            Bytes::from(data)
        }))
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

fn sha256_hex(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex_raw(data))
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
    fn sha256_hex_has_prefix() {
        assert_eq!(
            sha256_hex(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
