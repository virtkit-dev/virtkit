//! Plain files over HTTP. Tests write objects over S3 as sccache does, read them through
//! both interfaces and delete them at `/files/`. They cover authorization, invalid paths,
//! namespace conflicts and upload limits.

use std::sync::Arc;
use std::time::SystemTime;

use sha2::Digest as _;
use vk_registry::accounts::{Action, Db, EmailUpdate, Scope};
use vk_registry::config::{AuthMode, OidcSpec};
use vk_registry::{Authenticator, ServerConfig, ServerState};

const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-objects-e2e-{tag}-{}-{:?}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Run serve_on in a separate thread with an ephemeral listener.
fn spawn(state: Arc<ServerState>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(listener).unwrap();
            let _ = vk_registry::serve_on(l, state).await;
        });
    });
    format!("http://{addr}")
}

/// Server without credentials for protocol tests.
fn open_state(dir: &std::path::Path) -> Arc<ServerState> {
    let cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    Arc::new(cfg.into_state().expect("a local config starts"))
}

/// Accounts-mode state built the way `serve` builds it — the same helper as in
/// `accounts_e2e.rs` and `upload_e2e.rs`.
fn accounts_state(dir: &std::path::Path) -> Arc<ServerState> {
    std::fs::create_dir_all(dir).unwrap();
    let secret = dir.join("oidc-secret");
    std::fs::write(&secret, "s3cr3t\n").unwrap();
    let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    cfg.mode = AuthMode::Accounts;
    cfg.oidc = Some(OidcSpec {
        issuer: "https://login.example.com".to_string(),
        client_id: "vk-registry".to_string(),
        client_secret_file: secret,
        public_url: "https://registry.internal".to_string(),
    });
    Arc::new(cfg.into_state().expect("a valid accounts config starts"))
}

fn accounts_db(state: &ServerState) -> &Db {
    match &state.auth {
        Authenticator::Accounts { db, .. } => db,
        _ => panic!("not accounts mode"),
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn method(name: &str) -> reqwest::Method {
    reqwest::Method::from_bytes(name.as_bytes()).unwrap()
}

/// Send a raw HTTP request and return its status and response. Raw sockets preserve traversal
/// paths that URL parsers normalize. `extra` contains headers; the body is empty.
async fn raw(addr: &str, request_line: &str, extra: &str) -> (u16, String) {
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request =
        format!("{request_line} HTTP/1.1\r\nHost: {addr}\r\n{extra}Connection: close\r\n\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut sock, request.as_bytes())
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut sock, &mut answer)
        .await
        .unwrap();
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let status = answer
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status in {answer}"));
    (status, answer)
}

/// Files in `uploads/`, where an S3 `PUT` stages its object: what is in flight, and what a
/// failed one left behind.
fn staging_left(root: &std::path::Path) -> usize {
    std::fs::read_dir(root.join("uploads")).map_or(0, |d| {
        d.filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .count()
    })
}

/// Where an object's tag lives: `repos/files/<dir…>/tags/<leaf>` under the store root.
fn tag_path(root: &std::path::Path, key: &str) -> std::path::PathBuf {
    let (dirs, leaf) = key.rsplit_once('/').unwrap();
    root.join("repos/files").join(dirs).join("tags").join(leaf)
}

/// Bytes zstd cannot shrink, so a blob made of them is stored in identity form.
fn incompressible(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Poll `cond` until it holds, failing after ten seconds.
async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Start a raw `PUT` with a declared length of `len` and send only `first`.
/// Callers wait for the staging file before continuing.
async fn start_put(addr: &str, path: &str, len: usize, first: &[u8]) -> tokio::net::TcpStream {
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "PUT {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
    );
    tokio::io::AsyncWriteExt::write_all(&mut sock, head.as_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut sock, first)
        .await
        .unwrap();
    sock
}

/// An unsigned single-request S3 `PUT` of `body` at `/s3/<path>`, with `key` as a bearer.
async fn put(
    c: &reqwest::Client,
    url: &str,
    path: &str,
    key: Option<&str>,
    body: impl Into<reqwest::Body>,
) -> u16 {
    let req = c.put(format!("{url}/s3/{path}")).body(body);
    let req = match key {
        Some(k) => req.bearer_auth(k),
        None => req,
    };
    req.send().await.unwrap().status().as_u16()
}

/// The startup probe, a sharded key and its replacement round-trip: read back at `/files/`
/// with the headers that keep uploaded content from rendering, and over S3.
#[tokio::test]
async fn a_written_object_reads_back_with_its_metadata() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("sequence");
    let state = open_state(&dir);
    let root = dir.join("store");
    let url = spawn(state);
    let c = client();
    // The startup probe can miss on its first read. Its write creates the directory.
    let probe = format!("{url}/files/sccache/.sccache_check");
    assert_eq!(c.get(&probe).send().await.unwrap().status(), 404);
    assert_eq!(
        put(&c, &url, "sccache/.sccache_check", None, "probe").await,
        200
    );
    assert_eq!(c.get(&probe).send().await.unwrap().status(), 200);

    let key = "other/a/b/abc123";
    let payload = vec![7u8; 300_000];
    assert_eq!(put(&c, &url, key, None, payload.clone()).await, 200);
    assert!(
        tag_path(&root, key).is_file(),
        "the object is a tag of the repository its directories name"
    );
    assert_eq!(
        staging_left(&root),
        0,
        "a completed PUT leaves no staging file"
    );
    let resp = c.get(format!("{url}/files/{key}")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/octet-stream");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    assert_eq!(resp.headers()["content-disposition"], "attachment");
    assert!(resp.headers().contains_key("last-modified"));
    assert_eq!(resp.headers()["content-length"], payload.len().to_string());
    assert_eq!(resp.bytes().await.unwrap().as_ref(), payload.as_slice());
    // HEAD is the same answer without the body.
    let resp = c.head(format!("{url}/files/{key}")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-length"], payload.len().to_string());
    assert!(resp.bytes().await.unwrap().is_empty());
    // A replacement, large enough to catch an answer sent before the body is drained.
    let replacement = incompressible(8 << 20);
    assert_eq!(put(&c, &url, key, None, replacement.clone()).await, 200);
    for read in [format!("{url}/files/{key}"), format!("{url}/s3/{key}")] {
        let resp = c.get(&read).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{read}");
        assert_eq!(
            resp.headers()["content-length"],
            replacement.len().to_string()
        );
        assert_eq!(resp.bytes().await.unwrap().as_ref(), replacement.as_slice());
    }
    // A PUT onto a directory still reads the body through before it is refused.
    let resp = c
        .put(format!("{url}/s3/other/a"))
        .body(vec![9u8; 8 << 20])
        .send()
        .await
        .expect("a PUT onto a directory is answered, not reset");
    assert_eq!(resp.status(), 409);
    // A directory is not readable.
    assert_eq!(
        c.get(format!("{url}/files/other/a"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reject unsafe paths, reserved names, unsupported verbs and refused bodies, reading the
/// body through first.
#[tokio::test]
async fn plain_files_refuse_what_they_do_not_serve() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("refusals");
    let state = open_state(&dir);
    let root = dir.join("store");
    let url = spawn(state);
    let c = client();
    assert_eq!(put(&c, &url, "sccache/x", None, "x").await, 200);

    // Reject encoded separators, control bytes, empty components, and what the OCI name
    // rules refuse: characters outside `[A-Za-z0-9._-]`, and the layout's own names.
    for p in [
        "sccache/a%2F..%2Fb",
        "sccache/a%5C..%5Cb",
        "sccache/a%00b",
        "sccache//x",
        "sccache/x//y",
        "bad%20dir/x",
        "sccache/tags/x",
    ] {
        for read in ["files", "s3"] {
            let resp = c.get(format!("{url}/{read}/{p}")).send().await.unwrap();
            assert_eq!(resp.status(), 400, "GET /{read}/{p}");
        }
        assert_eq!(put(&c, &url, p, None, "x").await, 400, "PUT /s3/{p}");
        let resp = c.delete(format!("{url}/files/{p}")).send().await.unwrap();
        assert_eq!(resp.status(), 400, "DELETE /files/{p}");
    }

    // A leaf named like the layout is a tag a file put may write, but no S3 key.
    assert_eq!(put(&c, &url, "sccache/a/blobs", None, "x").await, 400);
    let resp = c
        .get(format!("{url}/files/sccache/a/blobs"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Send literal and encoded traversal over raw sockets to bypass client URL normalization.
    let addr = url.trim_start_matches("http://");
    for p in [
        "/files/sccache/../../etc/passwd",
        "/files/sccache/%2E%2E/%2E%2E/etc/passwd",
        "/files/sccache/a/%2E%2E/%2E%2E/%2E%2E/root",
    ] {
        for verb in ["GET", "HEAD", "DELETE"] {
            let (status, answer) = raw(addr, &format!("{verb} {p}"), "").await;
            assert_eq!(status, 400, "{verb} {p}: {answer}");
        }
        let s3 = p.replacen("/files/", "/s3/", 1);
        for verb in ["GET", "PUT"] {
            let (status, answer) = raw(addr, &format!("{verb} {s3}"), "").await;
            assert_eq!(status, 400, "{verb} {s3}: {answer}");
        }
    }

    // A verb plain files do not speak names the ones they do, its body read through.
    for verb in [
        "PROPFIND",
        "MKCOL",
        "PROPPATCH",
        "COPY",
        "MOVE",
        "LOCK",
        "OPTIONS",
        "POST",
    ] {
        let resp = c
            .request(method(verb), format!("{url}/files/sccache/x"))
            .body(vec![0u8; 8 << 20])
            .send()
            .await
            .unwrap_or_else(|e| panic!("{verb} was reset: {e}"));
        assert_eq!(resp.status(), 405, "{verb}");
        assert_eq!(resp.headers()["allow"], "GET, HEAD, PUT, DELETE", "{verb}");
    }
    // A refusal before the handler reads a PUT body still reads it through: answered, not
    // reset.
    for p in ["bad%20dir/x", "sccache/a%00b"] {
        let resp = c
            .put(format!("{url}/s3/{p}"))
            .body(vec![0u8; 8 << 20])
            .send()
            .await
            .unwrap_or_else(|e| panic!("PUT {p} was reset: {e}"));
        assert_eq!(resp.status(), 400, "PUT {p}");
    }
    // A DELETE's body is read through before the answer.
    let resp = c
        .delete(format!("{url}/files/sccache/absent"))
        .body(vec![0u8; 8 << 20])
        .send()
        .await
        .expect("a DELETE with a body is answered, not reset");
    assert_eq!(resp.status(), 404);

    assert_eq!(
        staging_left(&root),
        0,
        "no refusal left a staging file behind"
    );
    assert!(
        !root.join("repos/files/bad dir").exists()
            && !root.join("repos/files/sccache/tags/tags").exists(),
        "a refused request created nothing"
    );
    let seeded = c
        .get(format!("{url}/files/sccache/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        seeded.text().await.unwrap(),
        "x",
        "the seeded object is untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reject Content-Length over the object cap before reading the body, leaving no staging file.
/// Use a raw request to avoid sending 4 GiB; unit tests cover the streaming cap with smaller
/// bodies.
#[tokio::test]
async fn an_object_over_the_cap_is_refused_and_leaves_no_staging_file() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("cap");
    let state = open_state(&dir);
    let root = dir.join("store");
    let url = spawn(state);
    let over = (4u64 << 30) + 1;
    let (status, answer) = raw(
        url.trim_start_matches("http://"),
        "PUT /s3/sccache/x/y/big",
        &format!("Content-Length: {over}\r\n"),
    )
    .await;
    assert_eq!(status, 413, "an over-cap PUT is refused: {answer}");

    // Verify an object below the cap succeeds.
    assert_eq!(
        put(&client(), &url, "sccache/x/y/ok", None, vec![0u8; 8 << 20]).await,
        200
    );
    assert!(!tag_path(&root, "sccache/x/y/big").exists());
    assert!(tag_path(&root, "sccache/x/y/ok").is_file());
    assert_eq!(
        staging_left(&root),
        0,
        "neither the refusal nor the upload left a staging file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Verify 401 challenges in both auth modes and read-only file access.
#[tokio::test]
async fn plain_files_are_gated_like_every_other_family() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("authz");

    // Shared-secret mode with a token configured.
    let token = dir.join("token");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&token, "s3cr3t\n").unwrap();
    let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("shared"));
    cfg.token_file = Some(token);
    let shared_url = spawn(Arc::new(cfg.into_state().unwrap()));

    // Accounts mode, with a key that may only read `files/`, and one that writes one
    // directory.
    let adir = dir.join("accounts");
    let state = accounts_state(&adir);
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let key = |name: &str, action: Action, pattern: &str| {
        db.create_api_key(
            Some(&user.id),
            name,
            &[Scope {
                action,
                repo_pattern: pattern.to_string(),
            }],
            None,
        )
        .unwrap()
        .1
    };
    let read_key = key("ci-read", Action::Read, "files/*");
    let write_key = key("ci-write", Action::Write, "files/sccache");
    let accounts_url = spawn(state.clone());
    let c = client();

    // Unauthenticated, in both modes: the bare 401 with a challenge on it, not a redirect.
    for url in [&shared_url, &accounts_url] {
        for verb in ["GET", "HEAD", "DELETE"] {
            let resp = c
                .request(method(verb), format!("{url}/files/x/y"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 401, "{verb} at {url}");
            assert!(
                resp.headers().contains_key("www-authenticate"),
                "no challenge for {verb} at {url}"
            );
        }
    }

    // The write key seeds an object; then the read-only key may read it and not write.
    assert_eq!(
        put(
            &c,
            &accounts_url,
            "sccache/probe",
            Some(&write_key),
            "cached"
        )
        .await,
        200,
        "a write grant writes"
    );
    let resp = c
        .get(format!("{accounts_url}/files/sccache/probe"))
        .bearer_auth(&read_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "a read grant reads");
    assert_eq!(resp.text().await.unwrap(), "cached");
    // A read-only key can fetch the cached object but gets 403 on the probe write.
    assert_eq!(
        put(
            &c,
            &accounts_url,
            "sccache/.sccache_check",
            Some(&read_key),
            "probe"
        )
        .await,
        403,
        "a read grant does not write"
    );
    // Answered, not reset, with a body larger than the socket buffers hold.
    assert_eq!(
        put(
            &c,
            &accounts_url,
            "sccache/big",
            Some(&read_key),
            vec![0u8; 8 << 20]
        )
        .await,
        403
    );
    let resp = c
        .delete(format!("{accounts_url}/files/sccache/probe"))
        .bearer_auth(&read_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a read grant does not delete");
    // Nor may the write key touch another directory: its grant names one.
    assert_eq!(
        put(&c, &accounts_url, "other/x", Some(&write_key), "x").await,
        403
    );
    let resp = c
        .delete(format!("{accounts_url}/files/sccache/probe"))
        .bearer_auth(&write_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "a write grant deletes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// GET refreshes mtimes older than an hour; HEAD does not. Last-Modified reports the pre-touch
/// value.
#[tokio::test]
async fn a_get_refreshes_an_idle_objects_mtime_and_a_head_does_not() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("touch");
    let state = open_state(&dir);
    let root = dir.join("store");
    let url = spawn(state);
    let c = client();

    for name in ["got", "headed", "fresh"] {
        assert_eq!(
            put(&c, &url, &format!("cache/{name}"), None, "x").await,
            200
        );
    }
    // Idle since 1994 — an instant with a known RFC 1123 spelling. The record is the
    // tag's mtime, what the gc's retention reads.
    let long_ago = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(784_887_151);
    for name in ["got", "headed"] {
        std::fs::File::open(tag_path(&root, &format!("cache/{name}")))
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
    }
    let mtime = |name: &str| {
        std::fs::metadata(tag_path(&root, &format!("cache/{name}")))
            .unwrap()
            .modified()
            .unwrap()
    };
    let fresh_before = mtime("fresh");

    let resp = c
        .get(format!("{url}/files/cache/got"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let reported = resp.headers()["last-modified"]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(resp.text().await.unwrap(), "x");
    assert!(
        mtime("got") > SystemTime::now() - std::time::Duration::from_secs(60),
        "a hit on an idle object refreshes it"
    );
    // The header is the pre-touch time.
    assert_eq!(reported, "Tue, 15 Nov 1994 08:12:31 GMT");

    // Every object here is the same one-byte layer, stored as is.
    let layer: String = sha2::Sha256::digest(b"x")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let blob = root.join("blobs/sha256").join(layer);
    std::fs::File::open(&blob)
        .unwrap()
        .set_modified(long_ago)
        .unwrap();
    let resp = c
        .head(format!("{url}/files/cache/headed"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(mtime("headed"), long_ago, "a HEAD is not a use");
    assert_eq!(
        std::fs::metadata(&blob).unwrap().modified().unwrap(),
        long_ago,
        "nor of the layer blob"
    );

    let resp = c
        .get(format!("{url}/files/cache/fresh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        mtime("fresh"),
        fresh_before,
        "a fresh record is not rewritten"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An object is a tag, so the gc's retention is what expires it; a PUT after that starts
/// over, and a shared blob is what the two objects have in common.
#[tokio::test]
async fn an_idle_object_goes_with_the_gc_and_a_put_starts_over() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("gc");
    let state = open_state(&dir);
    let store = state.store.clone();
    let root = dir.join("store");
    let url = spawn(state);
    let c = client();

    for key in ["cache/ab/cd/key1", "cache/ab/cd/key2"] {
        assert_eq!(put(&c, &url, key, None, "the same bytes").await, 200);
    }
    // Two objects, one blob: the pool dedups them.
    let hex: String = sha2::Sha256::digest(b"the same bytes")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(store.has_blob(&hex));
    assert!(store.repo_has_blob("files/cache/ab/cd", &hex));

    std::fs::File::open(tag_path(&root, "cache/ab/cd/key1"))
        .unwrap()
        .set_modified(SystemTime::now() - std::time::Duration::from_secs(40 * 86_400))
        .unwrap();
    let day = std::time::Duration::from_secs(86_400);
    let r = store.gc(30 * day, day, false).unwrap();
    assert_eq!(r.tags_dropped, 1);
    assert_eq!(r.blobs_dropped, 0, "key2 still references the bytes");
    assert!(!tag_path(&root, "cache/ab/cd/key1").exists());
    assert_eq!(
        c.get(format!("{url}/files/cache/ab/cd/key1"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let resp = c
        .get(format!("{url}/files/cache/ab/cd/key2"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "the same bytes");

    assert_eq!(put(&c, &url, "cache/ab/cd/key1", None, "v2").await, 200);
    assert!(tag_path(&root, "cache/ab/cd/key1").is_file());

    // A deleted object's bytes wait for the gc, which drops them once nothing holds them.
    for key in ["cache/ab/cd/key1", "cache/ab/cd/key2"] {
        let resp = c.delete(format!("{url}/files/{key}")).send().await.unwrap();
        assert_eq!(resp.status(), 204, "{key}");
    }
    assert!(store.has_blob(&hex), "kept until the gc");
    let r = store
        .gc(30 * day, std::time::Duration::ZERO, false)
        .unwrap();
    assert!(r.blobs_dropped >= 1, "{}", r.blobs_dropped);
    assert!(!store.has_blob(&hex));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A top-level name is a directory, which takes no object.
#[tokio::test]
async fn a_put_at_a_top_level_name_is_refused() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("toplevel");
    let state = open_state(&dir);
    let root = dir.join("store").join("repos/files");
    let staging = dir.join("store");
    let url = spawn(state);
    let c = client();

    for p in ["cache", "cache/"] {
        assert_eq!(
            put(&c, &url, p, None, "payload".repeat(1024)).await,
            501,
            "PUT /s3/{p} is a bucket operation"
        );
        assert!(
            std::fs::symlink_metadata(root.join("cache")).is_err(),
            "PUT {p} created nothing at the directory's name"
        );
    }
    assert_eq!(
        staging_left(&staging),
        0,
        "a refused top-level PUT left nothing in staging"
    );
    // Writing a child creates the directory implicitly.
    assert_eq!(put(&c, &url, "cache/key", None, "payload").await, 200);
    assert!(root.join("cache/tags/key").is_file());
    let resp = c.delete(format!("{url}/files/cache")).send().await.unwrap();
    assert_eq!(resp.status(), 409, "a directory is not deleted");
    assert_eq!(staging_left(&staging), 0, "the upload left no staging file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A write below an object is a conflict: making its path a directory too would hide the
/// object behind it.
#[tokio::test]
async fn a_write_below_an_object_is_refused_and_leaves_the_object_reachable() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("below-object");
    let state = open_state(&dir);
    let root = dir.join("store").join("repos/files");
    let staging = dir.join("store");
    let url = spawn(state);
    let c = client();

    assert_eq!(put(&c, &url, "cache/obj", None, "the object").await, 200);
    for p in ["cache/obj/key", "cache/obj/sub/key"] {
        let resp = c
            .put(format!("{url}/s3/{p}"))
            .body("payload".repeat(1024))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 409, "PUT {p}");
        let body = resp.text().await.unwrap();
        assert!(body.contains("<Code>InvalidRequest</Code>"), "{body}");
    }
    // A trailing slash does not name the object.
    let slashed = format!("{url}/files/cache/obj/");
    assert_eq!(c.get(&slashed).send().await.unwrap().status(), 404);
    assert_eq!(c.delete(&slashed).send().await.unwrap().status(), 404);
    assert!(
        std::fs::symlink_metadata(root.join("cache/obj")).is_err(),
        "no directory was made at the object's path"
    );
    assert_eq!(
        staging_left(&staging),
        0,
        "a refused PUT left nothing in staging"
    );

    let resp = c
        .get(format!("{url}/files/cache/obj"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "the object");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A nested key authorizes as the repository it is a tag of, as it does on `/v2/`: an exact
/// `files/sccache` grant covers only the objects directly in it, and `files/sccache/*` the
/// whole tree — over S3, at `/files/` and over `/v2/` alike.
#[tokio::test]
async fn a_nested_key_needs_a_grant_on_its_own_repository() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("nested-scope");
    let state = accounts_state(&dir);
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let key = |name: &str, action: Action, pattern: &str| {
        db.create_api_key(
            Some(&user.id),
            name,
            &[Scope {
                action,
                repo_pattern: pattern.to_string(),
            }],
            None,
        )
        .unwrap()
        .1
    };
    let exact_w = key("exact-w", Action::Write, "files/sccache");
    let tree_w = key("tree-w", Action::Write, "files/sccache/*");
    let exact_r = key("exact-r", Action::Read, "files/sccache");
    let tree_r = key("tree-r", Action::Read, "files/sccache/*");
    let url = spawn(state.clone());
    let c = client();
    let status = async |verb: &str, p: &str, key: &str| {
        let req = c
            .request(method(verb), format!("{url}{p}"))
            .bearer_auth(key);
        let req = if verb == "PUT" {
            req.body("bytes")
        } else {
            req
        };
        req.send().await.unwrap().status().as_u16()
    };

    // The tree grant writes the sharded layout.
    assert_eq!(status("PUT", "/s3/sccache/a/b/key", &tree_w).await, 200);
    assert_eq!(status("PUT", "/s3/sccache/top", &tree_w).await, 200);
    // The exact grant writes directly in `files/sccache` and nowhere below it.
    assert_eq!(status("PUT", "/s3/sccache/top2", &exact_w).await, 200);
    assert_eq!(status("PUT", "/s3/sccache/a/b/other", &exact_w).await, 403);
    assert_eq!(
        status("DELETE", "/files/sccache/a/b/key", &exact_w).await,
        403
    );
    assert!(tag_path(&dir.join("store"), "sccache/a/b/key").is_file());
    // A directory the key cannot read is as absent to its DELETE as a missing one.
    assert_eq!(status("DELETE", "/files/sccache/a", &exact_w).await, 404);
    assert_eq!(status("DELETE", "/files/sccache/nope", &exact_w).await, 404);

    // Reads, likewise.
    assert_eq!(status("GET", "/files/sccache/top", &exact_r).await, 200);
    assert_eq!(status("GET", "/files/sccache/a/b/key", &exact_r).await, 403);
    assert_eq!(status("GET", "/files/sccache/a/b/key", &tree_r).await, 200);
    // The same object under the same name over `/v2/`.
    let v2 = "/v2/files/sccache/a/b/manifests/key";
    assert_eq!(status("GET", v2, &tree_r).await, 200);
    assert_eq!(status("GET", v2, &exact_r).await, 403);

    // An object whose layer no repository the caller may read holds is not served.
    let resp = c
        .put(format!("{url}/s3/sccache/a/b/lone"))
        .bearer_auth(&tree_w)
        .body("only here")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let layer: String = sha2::Sha256::digest(b"only here")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::remove_file(dir.join("store/repos/files/sccache/a/b/blobs").join(&layer)).unwrap();
    assert_eq!(status("GET", "/files/sccache/a/b/lone", &tree_r).await, 404);
    assert_eq!(status("GET", "/s3/sccache/a/b/lone", &tree_r).await, 404);

    let _ = std::fs::remove_dir_all(&dir);
}

/// An S3 `PUT` rechecks its path after staging. If another `PUT` created a child meanwhile,
/// the parent upload returns 409 and the child stays accessible.
#[tokio::test]
async fn a_put_overtaken_by_one_below_its_path_is_refused_when_it_lands() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("race");
    let state = open_state(&dir);
    let root = dir.join("store");
    let url = spawn(state);
    let addr = url.trim_start_matches("http://").to_string();
    let c = client();

    let mut sock = start_put(&addr, "/s3/race/x/k", 10, b"12345").await;
    wait_until("the PUT is staged", || staging_left(&root) == 1).await;
    assert_eq!(put(&c, &url, "race/x/k/below", None, "x").await, 200);
    tokio::io::AsyncWriteExt::write_all(&mut sock, b"67890")
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut sock, &mut answer)
        .await
        .unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 409"), "{answer}");
    assert!(
        !tag_path(&root, "race/x/k").exists(),
        "no tag beside the directory"
    );
    assert!(tag_path(&root, "race/x/k/below").is_file());
    assert_eq!(
        staging_left(&root),
        0,
        "the refused PUT discarded its staging"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A client that disconnects part way through a body leaves nothing in `uploads/`.
#[tokio::test]
async fn a_client_gone_mid_put_leaves_no_staging_file() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("gone");
    let state = open_state(&dir);
    let root = dir.join("store");
    let url = spawn(state);
    let addr = url.trim_start_matches("http://").to_string();

    let sock = start_put(&addr, "/s3/cache/key", 1 << 20, &[0u8; 4096]).await;
    wait_until("the PUT is staged", || staging_left(&root) == 1).await;
    drop(sock);
    wait_until("the staging file is removed", || staging_left(&root) == 0).await;
    assert!(!tag_path(&root, "cache/key").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An image pushed into `files/` over `/v2/` is absent to file reads. An S3 `PUT` or
/// `/files/` `DELETE` returns 409 and preserves the image.
#[tokio::test]
async fn a_tag_that_is_not_a_file_is_left_alone() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("foreign");
    let state = open_state(&dir);
    let store = state.store.clone();
    let root = dir.join("store");
    let url = spawn(state);
    let c = client();
    store
        .put_manifest("files/img", "v1", MANIFEST_TYPE, br#"{"schemaVersion":2}"#)
        .unwrap();

    let at = format!("{url}/files/img/v1");
    assert_eq!(c.get(&at).send().await.unwrap().status(), 404);
    assert_eq!(
        c.get(format!("{url}/s3/img/v1"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(put(&c, &url, "img/v1", None, "x").await, 409);
    assert_eq!(c.delete(&at).send().await.unwrap().status(), 409);
    assert_eq!(put(&c, &url, "img/v1/below", None, "x").await, 409);
    assert!(tag_path(&root, "img/v1").is_file());
    assert_eq!(
        c.get(format!("{url}/v2/files/img/manifests/v1"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The server requests `TCP_NODELAY` on accepted connections. On a persistent connection,
/// Nagle can delay a small streamed body until the client acknowledges the response headers
/// (about 40 ms on Linux).
#[tokio::test]
async fn accepted_connections_have_nagle_off() {
    let dir = tmp("nodelay");
    let url = spawn(open_state(&dir));
    let server: std::net::SocketAddr = url.strip_prefix("http://").unwrap().parse().unwrap();
    let client = tokio::net::TcpStream::connect(server).await.unwrap();
    let me = client.local_addr().unwrap();
    // Until the accept loop reaches the connection; the deadline only bounds a failure.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while server_nodelay(server, me) != Some(true) {
        assert!(
            std::time::Instant::now() < deadline,
            "the server's end of the connection has Nagle on"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Find an IPv4 descriptor with local port `server.port()` and peer port `client.port()`.
/// Return its `TCP_NODELAY` setting, or `None` if the lookup fails.
fn server_nodelay(server: std::net::SocketAddr, client: std::net::SocketAddr) -> Option<bool> {
    type Name =
        unsafe extern "C" fn(libc::c_int, *mut libc::sockaddr, *mut libc::socklen_t) -> libc::c_int;
    // The IPv4 port `name` gives `fd`, if `fd` is an IPv4 socket that has one.
    fn port(fd: libc::c_int, name: Name) -> Option<u16> {
        // SAFETY: all-zero is a valid `sockaddr_in`.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `addr` and `len` are valid for writes and `len` is `addr`'s size; a stale or
        // non-socket `fd` only makes the call fail.
        let r = unsafe { name(fd, (&raw mut addr).cast(), &mut len) };
        (r == 0 && i32::from(addr.sin_family) == libc::AF_INET).then(|| u16::from_be(addr.sin_port))
    }
    for entry in std::fs::read_dir("/proc/self/fd").ok()?.flatten() {
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<libc::c_int>() else {
            continue;
        };
        if port(fd, libc::getsockname) != Some(server.port())
            || port(fd, libc::getpeername) != Some(client.port())
        {
            continue;
        }
        let mut on: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `on` and `len` are valid for writes and `len` is `on`'s size.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                (&raw mut on).cast(),
                &mut len,
            )
        };
        return (r == 0).then_some(on != 0);
    }
    None
}

/// On-disk path of `key` in the flat store bound to `prefix`.
fn flat_object(root: &std::path::Path, prefix: &str, key: &str) -> std::path::PathBuf {
    let hash: String = sha2::Sha256::digest(key.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    root.join("flat")
        .join(prefix.replace('/', "+"))
        .join("objects")
        .join(&hash[..2])
        .join(hash)
}

/// A server whose `sccache` directory is a flat store capped at `cap`.
fn flat_state(dir: &std::path::Path, cap: u64) -> Arc<ServerState> {
    let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    cfg.flat = vec![vk_registry::flat::FlatBinding::new("sccache", cap)];
    Arc::new(cfg.into_state().expect("a flat config starts"))
}

/// S3 uploads flat objects. Both routes serve byte ranges. `/files/` deletes objects
/// and refuses uploads. Keys can share a path prefix, and other prefixes still use tags.
#[tokio::test]
async fn a_bound_prefix_keeps_its_objects_in_a_flat_store() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("flat");
    let root = dir.join("store");
    // Binding the prefix hides its existing tag from S3.
    {
        let url = spawn(open_state(&dir));
        assert_eq!(put(&client(), &url, "sccache/old", None, "old").await, 200);
        assert!(tag_path(&root, "sccache/old").is_file());
    }
    let url = spawn(flat_state(&dir, 1 << 30));
    let c = client();
    assert_eq!(
        c.get(format!("{url}/s3/sccache/old"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let key = "sccache/a/b/c/0123abcd";
    let resp = c.get(format!("{url}/s3/{key}")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
    assert!(resp.text().await.unwrap().contains("NoSuchKey"));
    assert_eq!(put(&c, &url, key, None, "0123456789").await, 200);
    assert!(flat_object(&root, "sccache", key).is_file());
    assert!(!root.join("repos/files/sccache/a").exists(), "no tag");
    assert_eq!(staging_left(&root), 0);
    for read in ["files", "s3"] {
        let resp = c.get(format!("{url}/{read}/{key}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{read}");
        assert_eq!(resp.headers()["content-type"], "application/octet-stream");
        assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
        assert_eq!(resp.headers()["content-disposition"], "attachment");
        assert_eq!(resp.headers()["content-length"], "10");
        assert!(!resp.headers().contains_key("last-modified"));
        assert!(!resp.headers().contains_key("etag"));
        assert_eq!(resp.text().await.unwrap(), "0123456789");
        let resp = c
            .get(format!("{url}/{read}/{key}"))
            .header("range", "bytes=2-5")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 206, "{read}");
        assert_eq!(resp.headers()["content-range"], "bytes 2-5/10");
        assert_eq!(resp.text().await.unwrap(), "2345");
        let resp = c
            .get(format!("{url}/{read}/{key}"))
            .header("range", "bytes=10-")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 416, "{read}");
        assert_eq!(resp.headers()["content-range"], "bytes */10");
        let resp = c.head(format!("{url}/{read}/{key}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{read}");
        assert_eq!(resp.headers()["content-length"], "10");
        // A trailing slash names no object.
        let resp = c.get(format!("{url}/{read}/{key}/")).send().await.unwrap();
        assert_eq!(resp.status(), 404, "{read}");
    }
    // No directories: a key and one below it are both objects.
    assert_eq!(put(&c, &url, "sccache/a/b", None, "ab").await, 200);
    assert_eq!(put(&c, &url, "sccache/a/b/c", None, "abc").await, 200);
    for (k, body) in [("sccache/a/b", "ab"), ("sccache/a/b/c", "abc")] {
        let resp = c.get(format!("{url}/s3/{k}")).send().await.unwrap();
        assert_eq!(resp.text().await.unwrap(), body);
    }
    // A digest mismatch leaves the last successful replacement intact.
    assert_eq!(put(&c, &url, key, None, "replaced").await, 200);
    let resp = c
        .put(format!("{url}/s3/{key}"))
        .header("x-amz-content-sha256", "0".repeat(64))
        .body("corrupt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("XAmzContentSHA256Mismatch")
    );
    let resp = c.get(format!("{url}/files/{key}")).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "replaced");
    // Files are put over S3 only.
    let resp = c
        .put(format!("{url}/files/sccache/x"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
    assert_eq!(resp.headers()["allow"], "GET, HEAD, DELETE");
    // Flat file names can exceed the 128-character upload limit.
    let long = format!("sccache/{}", "l".repeat(129));
    assert_eq!(put(&c, &url, &long, None, "l").await, 200);
    let resp = c
        .put(format!("{url}/files/{long}"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
    assert_eq!(resp.headers()["allow"], "GET, HEAD, DELETE");
    let resp = c.get(format!("{url}/files/{long}")).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "l");
    // A decoded space makes the file name invalid.
    let resp = c
        .put(format!("{url}/files/sccache/a%20b"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = c.delete(format!("{url}/files/{key}")).send().await.unwrap();
    assert_eq!(resp.status(), 204);
    assert!(!flat_object(&root, "sccache", key).exists());
    let resp = c.delete(format!("{url}/files/{key}")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(
        c.get(format!("{url}/s3/{key}"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // Outside the prefix, objects are tags as before.
    assert_eq!(put(&c, &url, "other/x", None, "x").await, 200);
    assert!(tag_path(&root, "other/x").is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A flat store over its cap loses its least recently used objects in the background.
#[tokio::test]
async fn a_flat_store_over_its_cap_evicts_the_oldest() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("flat-cap");
    let root = dir.join("store");
    let url = spawn(flat_state(&dir, 1 << 20));
    let c = client();
    let keys: Vec<String> = (0..4).map(|i| format!("sccache/k/{i}")).collect();
    for k in &keys {
        assert_eq!(put(&c, &url, k, None, vec![1u8; 400 << 10]).await, 200);
        // Space the writes so their mtimes fall in different seconds.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }
    wait_until("the store fits its cap", || {
        keys.iter()
            .filter(|k| flat_object(&root, "sccache", k).exists())
            .count()
            <= 2
    })
    .await;
    assert!(!flat_object(&root, "sccache", &keys[0]).exists());
    assert!(flat_object(&root, "sccache", &keys[3]).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Below a bound prefix, grants apply to an object's parent repository as they do to a tag.
#[tokio::test]
async fn a_flat_object_is_gated_by_its_parent_repository() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("flat-authz");
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("oidc-secret");
    std::fs::write(&secret, "s3cr3t\n").unwrap();
    let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    cfg.mode = AuthMode::Accounts;
    cfg.oidc = Some(OidcSpec {
        issuer: "https://login.example.com".to_string(),
        client_id: "vk-registry".to_string(),
        client_secret_file: secret,
        public_url: "https://registry.internal".to_string(),
    });
    cfg.flat = vec![vk_registry::flat::FlatBinding::new("sccache", 1 << 30)];
    let state = Arc::new(cfg.into_state().unwrap());
    let db = accounts_db(&state);
    let user = db
        .upsert_user("https://issuer", "ci", EmailUpdate::Keep, None)
        .unwrap();
    let key = |name: &str, action: Action, pattern: &str| {
        db.create_api_key(
            Some(&user.id),
            name,
            &[Scope {
                action,
                repo_pattern: pattern.to_string(),
            }],
            None,
        )
        .unwrap()
        .1
    };
    let read_key = key("read", Action::Read, "files/*");
    let write_key = key("write", Action::Write, "files/sccache");
    let other_key = key("other", Action::Write, "files/other/*");
    let url = spawn(state.clone());
    let c = client();
    assert_eq!(put(&c, &url, "sccache/k", Some(&write_key), "v").await, 200);
    // The exact grant covers objects directly in its repository only.
    assert_eq!(
        put(&c, &url, "sccache/a/k", Some(&write_key), "v").await,
        403
    );
    assert_eq!(put(&c, &url, "sccache/k", Some(&read_key), "v").await, 403);
    assert_eq!(put(&c, &url, "sccache/k", Some(&other_key), "v").await, 403);
    let get = |k: &str| {
        c.get(format!("{url}/s3/sccache/k"))
            .bearer_auth(k.to_string())
            .send()
    };
    assert_eq!(get(&read_key).await.unwrap().text().await.unwrap(), "v");
    assert_eq!(get(&other_key).await.unwrap().status(), 403);
    let delete = |k: &str| {
        c.delete(format!("{url}/files/sccache/k"))
            .bearer_auth(k.to_string())
            .send()
    };
    assert_eq!(delete(&read_key).await.unwrap().status(), 403);
    assert_eq!(delete(&other_key).await.unwrap().status(), 403);
    assert_eq!(delete(&write_key).await.unwrap().status(), 204);
    assert_eq!(get(&read_key).await.unwrap().status(), 404);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Changing the cap preserves existing objects until eviction. Removing the binding restores
/// tag routing and leaves the flat store on disk.
#[tokio::test]
async fn flat_stores_rebind_at_runtime() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("flat-rebind");
    let root = dir.join("store");
    let state = flat_state(&dir, 1 << 30);
    let url = spawn(state.clone());
    let c = client();
    assert_eq!(put(&c, &url, "sccache/k", None, "flat").await, 200);
    let bind = |cap| {
        state
            .store
            .bind_flat(
                vec![vk_registry::flat::FlatBinding::new("sccache", cap)],
                vk_registry::flat::Use::Serve,
            )
            .unwrap()
    };
    bind(1 << 20);
    assert_eq!(state.store.flat().usage()[0].cap, 1 << 20);
    let resp = c.get(format!("{url}/s3/sccache/k")).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "flat");
    // The background evictor picks up the lower cap.
    bind(1);
    wait_until("the store fits its new cap", || {
        !flat_object(&root, "sccache", "sccache/k").exists()
    })
    .await;
    assert_eq!(put(&c, &url, "sccache/k", None, "flat").await, 200);
    state
        .store
        .bind_flat(Vec::new(), vk_registry::flat::Use::Serve)
        .unwrap();
    assert_eq!(
        c.get(format!("{url}/s3/sccache/k"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(put(&c, &url, "sccache/k", None, "tag").await, 200);
    assert!(tag_path(&root, "sccache/k").is_file());
    assert!(root.join("flat/sccache/objects").is_dir());
    let _ = std::fs::remove_dir_all(&dir);
}
