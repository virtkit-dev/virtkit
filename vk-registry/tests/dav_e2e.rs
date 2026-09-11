//! WebDAV tests over real HTTP: the sccache/opendal request sequence, listings, OCI downloads,
//! authorization, invalid paths and upload limits. Requests are constructed directly without an
//! opendal dependency.

use std::sync::Arc;
use std::time::SystemTime;

use vk_registry::accounts::{Action, Db, Scope};
use vk_registry::config::{AuthMode, OidcSpec};
use vk_registry::{Authenticator, ServerConfig, ServerState};

const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const FILES_ALLOW: &str = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL";
const READ_ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND";

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-dav-e2e-{tag}-{}-{:?}",
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

/// A `PROPFIND` as opendal sends it: the `Depth` header and the `allprop` body.
async fn propfind(c: &reqwest::Client, url: &str, depth: &str) -> reqwest::Response {
    c.request(method("PROPFIND"), url)
        .header("Depth", depth)
        .header("Content-Type", "application/xml")
        .body("<?xml version=\"1.0\" encoding=\"utf-8\" ?><D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>")
        .send()
        .await
        .unwrap()
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

/// Test the initial opendal upload sequence: missing-parent PROPFINDs, MKCOLs, PUT, properties
/// and GET.
#[tokio::test]
async fn the_opendal_write_then_read_sequence_round_trips() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("sequence");
    let state = open_state(&dir);
    let root = state.store.files_dir();
    let url = spawn(state);
    let c = client();

    // The startup probe: a GET that is allowed to 404, then a PUT that decides whether
    // sccache runs read-write or read-only. The PUT is also what brings the directory
    // into being.
    let resp = c
        .get(format!("{url}/dav/files/sccache/.sccache_check"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = c
        .put(format!("{url}/dav/files/sccache/.sccache_check"))
        .body("probe")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "a writable directory accepts the probe");

    // opendal's writer: PROPFIND the parent, walking up while it 404s. No directory is
    // special: the walk climbs to `files/`, which is what answers.
    for p in [
        "/dav/files/other/a/b",
        "/dav/files/other/a",
        "/dav/files/other",
    ] {
        assert_eq!(
            propfind(&c, &format!("{url}{p}"), "0").await.status(),
            404,
            "{p}"
        );
    }
    let resp = propfind(&c, &format!("{url}/dav/files"), "0").await;
    assert_eq!(resp.status(), 207, "files/ itself answers");
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<D:resourcetype><D:collection/></D:resourcetype>"),
        "{body}"
    );
    assert!(body.contains("<D:href>/dav/files/</D:href>"), "{body}");

    // then MKCOL back down, the top-level directory included
    for p in [
        "/dav/files/other",
        "/dav/files/other/a",
        "/dav/files/other/a/b",
    ] {
        let resp = c
            .request(method("MKCOL"), format!("{url}{p}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "MKCOL {p}");
    }
    // a directory that is already there is 405, not an error the writer retries on
    let resp = c
        .request(method("MKCOL"), format!("{url}/dav/files/other/a"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
    assert_eq!(resp.headers()["allow"], FILES_ALLOW);

    // the object itself
    let key = "/dav/files/other/a/b/abc123";
    let payload = vec![7u8; 300_000];
    let resp = c
        .put(format!("{url}{key}"))
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert!(root.join("other/a/b/abc123").is_file());
    assert_eq!(
        std::fs::read_dir(root.join(".staging")).unwrap().count(),
        0,
        "a completed PUT leaves no staging file"
    );

    // PROPFIND it: the fields opendal's Multistatus deserializer reads.
    let resp = propfind(&c, &format!("{url}{key}"), "0").await;
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<D:status>HTTP/1.1 200 OK</D:status>"),
        "{body}"
    );
    assert!(body.contains("<D:resourcetype/>"), "{body}");
    assert!(
        body.contains(&format!(
            "<D:getcontentlength>{}</D:getcontentlength>",
            payload.len()
        )),
        "{body}"
    );
    assert!(body.contains("<D:getlastmodified>"), "{body}");
    assert!(
        body.contains(" GMT</D:getlastmodified>"),
        "RFC 1123: {body}"
    );
    assert!(body.contains(&format!("<D:href>{key}</D:href>")), "{body}");

    // Verify download bytes and headers that prevent uploaded content from rendering.
    let resp = c.get(format!("{url}{key}")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/octet-stream");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    assert_eq!(resp.headers()["content-disposition"], "attachment");
    assert!(resp.headers().contains_key("last-modified"));
    assert_eq!(resp.headers()["content-length"], payload.len().to_string());
    assert_eq!(resp.bytes().await.unwrap().as_ref(), payload.as_slice());

    // HEAD is the same answer without the body.
    let resp = c.head(format!("{url}{key}")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-length"], payload.len().to_string());
    assert!(resp.bytes().await.unwrap().is_empty());

    // OPTIONS advertises the DAV class opendal looks for.
    let resp = c
        .request(reqwest::Method::OPTIONS, format!("{url}/dav/files/other"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["dav"], "1");

    // Replacement returns 204. Use a larger body to catch responses sent before the upload
    // drains, which can reset the connection.
    let replacement = vec![9u8; 8 << 20];
    let resp = c
        .put(format!("{url}{key}"))
        .body(replacement.clone())
        .send()
        .await
        .expect("a repeated PUT is answered, not reset");
    assert_eq!(resp.status(), 204);
    let resp = c.get(format!("{url}{key}")).send().await.unwrap();
    assert_eq!(
        resp.headers()["content-length"],
        replacement.len().to_string()
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), replacement.as_slice());
    // The one early answer left, a PUT onto a directory, still reads the body through.
    let resp = c
        .put(format!("{url}/dav/files/other/a"))
        .body(vec![9u8; 8 << 20])
        .send()
        .await
        .expect("a PUT onto a directory is answered, not reset");
    assert_eq!(resp.status(), 405);

    // A directory is not readable: listings are PROPFIND's.
    assert_eq!(
        c.get(format!("{url}/dav/files/other/a"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Depth 1 lists the collection and its children. DELETE removes files and empty directories.
#[tokio::test]
async fn a_directory_lists_its_members_and_is_deleted_only_when_empty() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("listing");
    let state = open_state(&dir);
    let url = spawn(state);
    let c = client();

    for (p, n) in [("/dav/files/d/x/one", 10), ("/dav/files/d/x/two", 20)] {
        let resp = c
            .put(format!("{url}{p}"))
            .body(vec![1u8; n])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{p}");
    }
    assert_eq!(
        c.request(method("MKCOL"), format!("{url}/dav/files/d/x/sub"))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );

    let resp = propfind(&c, &format!("{url}/dav/files/d/x/"), "1").await;
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert_eq!(body.matches("<D:response>").count(), 4, "{body}");
    assert_eq!(body.matches("<D:getlastmodified>").count(), 4, "{body}");
    assert!(body.contains("<D:href>/dav/files/d/x/</D:href>"), "{body}");
    assert!(
        body.contains("<D:href>/dav/files/d/x/sub/</D:href>"),
        "{body}"
    );
    assert!(
        body.contains("<D:href>/dav/files/d/x/one</D:href>"),
        "{body}"
    );
    assert!(
        body.contains("<D:getcontentlength>10</D:getcontentlength>"),
        "{body}"
    );
    assert!(
        body.contains("<D:getcontentlength>20</D:getcontentlength>"),
        "{body}"
    );
    assert_eq!(
        body.matches("<D:collection/>").count(),
        2,
        "the directory and its subdirectory: {body}"
    );
    let first = body.find("/dav/files/d/x/</D:href>").unwrap();
    let member = body.find("/dav/files/d/x/one").unwrap();
    assert!(first < member, "the collection itself comes first: {body}");

    // Depth 1 on a file is the file.
    let resp = propfind(&c, &format!("{url}/dav/files/d/x/one"), "1").await;
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert_eq!(body.matches("<D:response>").count(), 1, "{body}");

    // Listing the top level, on an open server, is the one enumeration refused.
    assert_eq!(
        propfind(&c, &format!("{url}/dav/files/"), "1")
            .await
            .status(),
        403
    );
    assert_eq!(
        propfind(&c, &format!("{url}/dav/"), "1").await.status(),
        403
    );
    // Depth 0 there is fine: it is what opendal's parent walk asks.
    assert_eq!(
        propfind(&c, &format!("{url}/dav/"), "0").await.status(),
        207
    );

    // DELETE: a directory with members is refused, an empty one and an object go.
    let del = async |p: &str| c.delete(format!("{url}{p}")).send().await.unwrap().status();
    assert_eq!(del("/dav/files/d/x").await, 403);
    assert_eq!(del("/dav/files/d/x/sub").await, 204);
    assert_eq!(del("/dav/files/d/x/one").await, 204);
    assert_eq!(del("/dav/files/d/x/one").await, 404);
    assert_eq!(del("/dav/files/d/x/two").await, 204);
    assert_eq!(del("/dav/files/d/x").await, 204);
    assert_eq!(del("/dav/files/d").await, 204, "a top-level directory too");
    assert_eq!(
        propfind(&c, &format!("{url}/dav/files/d"), "0")
            .await
            .status(),
        404
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Reject unsupported depth, unsafe paths, reserved names, unsupported verbs and oversized
/// bodies.
#[tokio::test]
async fn the_files_tree_refuses_what_it_does_not_serve() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("refusals");
    let state = open_state(&dir);
    let root = state.store.files_dir();
    let url = spawn(state);
    let c = client();

    assert_eq!(
        c.request(method("MKCOL"), format!("{url}/dav/files/sccache"))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );

    // Depth infinity is refused; an absent Depth is the RFC's `infinity` but opendal's
    // `0`, and it is served as 0; a malformed one is a bad request.
    let resp = propfind(&c, &format!("{url}/dav/files/sccache"), "infinity").await;
    assert_eq!(resp.status(), 403);
    let resp = c
        .request(method("PROPFIND"), format!("{url}/dav/files/sccache"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 207);
    assert_eq!(
        propfind(&c, &format!("{url}/dav/files/sccache"), "2")
            .await
            .status(),
        400
    );

    // Reject encoded separators, control bytes, empty components and invalid directory names.
    for p in [
        "/dav/files/sccache/a%2F..%2Fb",
        "/dav/files/sccache/a%5C..%5Cb",
        "/dav/files/sccache/a%00b",
        "/dav/files/sccache//x",
        "/dav/files/sccache/x//y",
        "/dav/files/.staging/x",
        "/dav/files/.policy/x",
        "/dav/files/bad%20dir/x",
    ] {
        let resp = c.get(format!("{url}{p}")).send().await.unwrap();
        assert_eq!(resp.status(), 400, "GET {p}");
        let resp = c.put(format!("{url}{p}")).body("x").send().await.unwrap();
        assert_eq!(resp.status(), 400, "PUT {p}");
    }
    // An area that is not one of the two.
    assert_eq!(
        c.get(format!("{url}/dav/nope/x"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Send literal and encoded traversal over raw sockets to bypass client URL normalization.
    let addr = url.trim_start_matches("http://");
    for p in [
        "/dav/files/sccache/../../etc/passwd",
        "/dav/files/sccache/%2E%2E/%2E%2E/etc/passwd",
        "/dav/files/sccache/a/%2E%2E/%2E%2E/%2E%2E/root",
        "/dav/../v2/",
    ] {
        for verb in ["GET", "PUT", "PROPFIND", "MKCOL", "DELETE"] {
            let (status, answer) = raw(addr, &format!("{verb} {p}"), "").await;
            assert_eq!(status, 400, "{verb} {p}: {answer}");
        }
    }

    // A verb this tree does not speak names the ones it does.
    for verb in ["PROPPATCH", "COPY", "MOVE", "LOCK"] {
        let resp = c
            .request(method(verb), format!("{url}/dav/files/sccache/x"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 405, "{verb}");
        assert_eq!(resp.headers()["allow"], FILES_ALLOW, "{verb}");
    }
    // The roots take no writes at all.
    for p in ["/dav/files", "/dav/"] {
        let resp = c
            .request(method("MKCOL"), format!("{url}{p}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 405, "{p}");
        assert_eq!(resp.headers()["allow"], READ_ALLOW, "{p}");
    }

    // A PROPFIND body far past the drain cap is refused rather than buffered.
    let resp = c
        .request(method("PROPFIND"), format!("{url}/dav/files/sccache"))
        .body("x".repeat(128 * 1024))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // A PUT onto a directory is not an overwrite.
    let resp = c
        .put(format!("{url}/dav/files/sccache"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);

    assert_eq!(
        std::fs::read_dir(root.join(".staging")).unwrap().count(),
        0,
        "no refusal left a staging file behind"
    );
    assert!(
        !root.join("bad dir").exists() && !root.join(".policy").exists(),
        "a refused request created nothing"
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
    let root = state.store.files_dir();
    let url = spawn(state);
    let over = (4u64 << 30) + 1;
    let (status, answer) = raw(
        url.trim_start_matches("http://"),
        "PUT /dav/files/sccache/x/y/big",
        &format!("Content-Length: {over}\r\n"),
    )
    .await;
    assert_eq!(status, 413, "an over-cap PUT is refused: {answer}");

    // Verify an object below the cap succeeds.
    let resp = client()
        .put(format!("{url}/dav/files/sccache/x/y/ok"))
        .body(vec![0u8; 8 << 20])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert!(!root.join("sccache/x/y/big").exists());
    assert_eq!(
        std::fs::read_dir(root.join(".staging")).unwrap().count(),
        0,
        "neither the refusal nor the upload left a staging file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Verify 401 challenges in both auth modes, read-only file access and repository-scoped
/// listings.
#[tokio::test]
async fn the_dav_tree_is_gated_and_scoped_like_every_other_family() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("authz");

    // Shared-secret mode with a token configured.
    let token = dir.join("token");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&token, "s3cr3t\n").unwrap();
    let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("shared"));
    cfg.token_file = Some(token);
    let shared_url = spawn(Arc::new(cfg.into_state().unwrap()));

    // Accounts mode, with a key that may only read `files/`, one that writes one
    // directory, and one that reads one team's repositories.
    let adir = dir.join("accounts");
    let state = accounts_state(&adir);
    let db = accounts_db(&state);
    let user = db.upsert_user("https://issuer", "ci", None, None).unwrap();
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
    let team_key = key("team-a", Action::Read, "team-a/*");
    // Two teams' repositories, stored the way `/v2/` stores them.
    let store = state.store.clone();
    let blob_a = store.put_blob(b"layer of team a").unwrap();
    let blob_b = store.put_blob(b"layer of team b").unwrap();
    let hex_a = blob_a.trim_start_matches("sha256:").to_string();
    let hex_b = blob_b.trim_start_matches("sha256:").to_string();
    store.record_blob("team-a/app", &hex_a).unwrap();
    store.record_blob("team-b/app", &hex_b).unwrap();
    for name in ["team-a/app", "team-b/app"] {
        store
            .put_manifest(name, "v1", MANIFEST_TYPE, br#"{"schemaVersion":2}"#)
            .unwrap();
    }
    let accounts_url = spawn(state.clone());
    let c = client();

    // Unauthenticated, in both modes: the bare 401 with a challenge on it, not a redirect.
    for url in [&shared_url, &accounts_url] {
        for p in ["/dav/files/x/y", "/dav/repos/team-a/app/tags/v1", "/dav/"] {
            let resp = c.get(format!("{url}{p}")).send().await.unwrap();
            assert_eq!(resp.status(), 401, "GET {p} at {url}");
            assert!(
                resp.headers().contains_key("www-authenticate"),
                "no challenge for {p} at {url}"
            );
            let resp = propfind(&c, &format!("{url}{p}"), "0").await;
            assert_eq!(resp.status(), 401, "PROPFIND {p} at {url}");
        }
        let resp = c
            .put(format!("{url}/dav/files/x/y"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "at {url}");
    }

    // A configured shared credential is trusted with the whole store, roots included.
    let resp = c
        .request(method("PROPFIND"), format!("{shared_url}/dav/"))
        .header("Depth", "1")
        .bearer_auth("s3cr3t")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<D:href>/dav/repos/</D:href>"), "{body}");
    assert!(body.contains("<D:href>/dav/files/</D:href>"), "{body}");

    // The write key seeds an object; then the read-only key may read it and not write.
    let resp = c
        .put(format!("{accounts_url}/dav/files/sccache/probe"))
        .bearer_auth(&write_key)
        .body("cached")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "a write grant writes");
    let resp = c
        .get(format!("{accounts_url}/dav/files/sccache/probe"))
        .bearer_auth(&read_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "a read grant reads");
    assert_eq!(resp.text().await.unwrap(), "cached");
    // The startup probe a read-only pipeline sends: refused, which is what puts sccache
    // in read-only mode instead of failing the job.
    let resp = c
        .put(format!("{accounts_url}/dav/files/sccache/.sccache_check"))
        .bearer_auth(&read_key)
        .body("probe")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a read grant does not write");
    // Nor may the write key touch another directory: its grant names one.
    let resp = c
        .put(format!("{accounts_url}/dav/files/other/x"))
        .bearer_auth(&write_key)
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    // The `files/` listing shows the read key what it may read.
    let resp = c
        .request(method("PROPFIND"), format!("{accounts_url}/dav/files/"))
        .header("Depth", "1")
        .bearer_auth(&read_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<D:href>/dav/files/sccache/</D:href>"),
        "{body}"
    );

    // The `repos/` view, scope-filtered: the team key lists its team and nothing else.
    let listing = async |key: &str, path: &str| {
        let resp = c
            .request(method("PROPFIND"), format!("{accounts_url}{path}"))
            .header("Depth", "1")
            .bearer_auth(key)
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    };
    let (status, body) = listing(&team_key, "/dav/repos/").await;
    assert_eq!(status, 207);
    assert!(
        body.contains("<D:href>/dav/repos/team-a/</D:href>"),
        "{body}"
    );
    assert!(!body.contains("team-b"), "{body}");
    let (status, body) = listing(&team_key, "/dav/repos/team-a/").await;
    assert_eq!(status, 207);
    assert!(
        body.contains("<D:href>/dav/repos/team-a/app/</D:href>"),
        "{body}"
    );
    let (status, body) = listing(&team_key, "/dav/repos/team-a/app/tags/").await;
    assert_eq!(status, 207);
    assert!(
        body.contains("<D:href>/dav/repos/team-a/app/tags/v1</D:href>"),
        "{body}"
    );
    // The other team's repository does not exist, as far as this key can tell.
    let (status, _) = listing(&team_key, "/dav/repos/team-b/").await;
    assert_eq!(status, 404);
    let resp = c
        .get(format!("{accounts_url}/dav/repos/team-b/app/tags/v1"))
        .bearer_auth(&team_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    // A key with no repository scope at all sees an empty catalog.
    let (status, body) = listing(&write_key, "/dav/repos/").await;
    assert_eq!(status, 207);
    assert_eq!(body.matches("<D:response>").count(), 1, "{body}");

    // A blob is readable through a repository only when that repository holds it.
    let resp = c
        .get(format!("{accounts_url}/dav/repos/team-a/app/blobs/{hex_a}"))
        .bearer_auth(&team_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"layer of team a");
    let resp = c
        .get(format!("{accounts_url}/dav/repos/team-a/app/blobs/{hex_b}"))
        .bearer_auth(&team_key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a digest team-a does not hold is not there"
    );
    let resp = propfind(
        &c,
        &format!("{accounts_url}/dav/repos/team-a/app/blobs/{hex_b}"),
        "0",
    )
    .await;
    assert_eq!(resp.status(), 401, "no key, no view");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Verify OCI tags, manifests and blobs download correctly, including decoded zstd blobs and
/// canonical lengths. Reject all writes.
#[tokio::test]
async fn the_repos_view_reads_back_what_v2_stored() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("repos");
    let state = open_state(&dir);
    let store = state.store.clone();
    let url = spawn(state);
    let c = client();

    // Two blobs: one zstd shrinks (stored as a frame), one it cannot (stored as is).
    let packed = vec![7u8; 100_000];
    let plain = incompressible(50_000);
    let packed_hex = store
        .put_blob(&packed)
        .unwrap()
        .trim_start_matches("sha256:")
        .to_string();
    let plain_hex = store
        .put_blob(&plain)
        .unwrap()
        .trim_start_matches("sha256:")
        .to_string();
    assert!(
        dir.join("store/blobs/zstd").join(&packed_hex).is_file(),
        "the compressible blob is stored as a frame"
    );
    assert!(
        dir.join("store/blobs/sha256").join(&plain_hex).is_file(),
        "the incompressible one as itself"
    );
    store.record_blob("demo", &packed_hex).unwrap();
    store.record_blob("demo", &plain_hex).unwrap();
    let manifest = format!(
        r#"{{"schemaVersion":2,"layers":[{{"digest":"sha256:{packed_hex}","size":{}}},{{"digest":"sha256:{plain_hex}","size":{}}}]}}"#,
        packed.len(),
        plain.len()
    );
    let digest = store
        .put_manifest("demo", "v1", MANIFEST_TYPE, manifest.as_bytes())
        .unwrap();
    let manifest_hex = digest.trim_start_matches("sha256:").to_string();

    // The repository, and what is under it.
    let resp = propfind(&c, &format!("{url}/dav/repos/demo/"), "1").await;
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    for sub in ["tags", "manifests", "blobs"] {
        assert!(
            body.contains(&format!("<D:href>/dav/repos/demo/{sub}/</D:href>")),
            "{sub}: {body}"
        );
    }
    // Tags: the manifest's length and type on the entry.
    let resp = propfind(&c, &format!("{url}/dav/repos/demo/tags/"), "1").await;
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<D:href>/dav/repos/demo/tags/v1</D:href>"),
        "{body}"
    );
    assert!(
        body.contains(&format!(
            "<D:getcontentlength>{}</D:getcontentlength>",
            manifest.len()
        )),
        "{body}"
    );
    assert!(
        body.contains(&format!(
            "<D:getcontenttype>{MANIFEST_TYPE}</D:getcontenttype>"
        )),
        "{body}"
    );
    // Manifests by digest.
    let resp = propfind(&c, &format!("{url}/dav/repos/demo/manifests/"), "1").await;
    let body = resp.text().await.unwrap();
    assert!(
        body.contains(&format!(
            "<D:href>/dav/repos/demo/manifests/{manifest_hex}</D:href>"
        )),
        "{body}"
    );
    // Blobs: the canonical length for both, the frame header read for the packed one.
    let resp = propfind(&c, &format!("{url}/dav/repos/demo/blobs/"), "1").await;
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert_eq!(body.matches("<D:response>").count(), 3, "{body}");
    assert!(
        body.contains(&format!(
            "<D:getcontentlength>{}</D:getcontentlength>",
            packed.len()
        )),
        "{body}"
    );
    assert!(
        body.contains(&format!(
            "<D:getcontentlength>{}</D:getcontentlength>",
            plain.len()
        )),
        "{body}"
    );
    assert_eq!(body.matches("<D:getlastmodified>").count(), 3, "{body}");

    // Downloads: the tag and the manifest are the same bytes with the stored type.
    for p in [
        "/dav/repos/demo/tags/v1".to_string(),
        format!("/dav/repos/demo/manifests/{manifest_hex}"),
    ] {
        let resp = c.get(format!("{url}{p}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{p}");
        assert_eq!(resp.headers()["content-type"], MANIFEST_TYPE, "{p}");
        assert_eq!(resp.headers()["docker-content-digest"], digest, "{p}");
        assert_eq!(resp.headers()["x-content-type-options"], "nosniff", "{p}");
        assert_eq!(resp.text().await.unwrap(), manifest, "{p}");
    }
    // The packed blob comes back decoded, its length exact and known before the body.
    let resp = c
        .get(format!("{url}/dav/repos/demo/blobs/{packed_hex}"))
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-length"], packed.len().to_string());
    assert!(!resp.headers().contains_key("content-encoding"));
    assert_eq!(resp.bytes().await.unwrap().as_ref(), packed.as_slice());
    let resp = c
        .head(format!("{url}/dav/repos/demo/blobs/{packed_hex}"))
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["content-length"], packed.len().to_string());
    let resp = c
        .get(format!("{url}/dav/repos/demo/blobs/{plain_hex}"))
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), plain.as_slice());
    // A single resource's PROPFIND says the same length.
    let resp = propfind(&c, &format!("{url}/dav/repos/demo/blobs/{packed_hex}"), "0").await;
    assert_eq!(resp.status(), 207);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains(&format!(
            "<D:getcontentlength>{}</D:getcontentlength>",
            packed.len()
        )),
        "{body}"
    );

    // Absent things are absent; collections have no body.
    for p in [
        "/dav/repos/nope/",
        "/dav/repos/demo/tags/v2",
        &format!("/dav/repos/demo/blobs/{}", "0".repeat(64)),
        "/dav/repos/demo/blobs/notahex",
        "/dav/repos/tags/",
    ] {
        assert_eq!(
            propfind(&c, &format!("{url}{p}"), "0").await.status(),
            404,
            "PROPFIND {p}"
        );
    }
    for p in ["/dav/repos/demo/", "/dav/repos/demo/tags/", "/dav/repos/"] {
        assert_eq!(
            c.get(format!("{url}{p}")).send().await.unwrap().status(),
            404,
            "GET {p}"
        );
    }
    // Enumerating repositories on an open server is refused; naming one is not.
    assert_eq!(
        propfind(&c, &format!("{url}/dav/repos/"), "1")
            .await
            .status(),
        403
    );
    assert_eq!(
        propfind(&c, &format!("{url}/dav/repos/"), "0")
            .await
            .status(),
        207
    );

    // Nothing under `repos/` takes a write.
    for (verb, p) in [
        ("PUT", "/dav/repos/demo/tags/v2"),
        ("MKCOL", "/dav/repos/new"),
        ("DELETE", "/dav/repos/demo/tags/v1"),
        ("PUT", &format!("/dav/repos/demo/blobs/{plain_hex}")),
        ("PROPPATCH", "/dav/repos/demo/"),
    ] {
        let resp = c
            .request(method(verb), format!("{url}{p}"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 405, "{verb} {p}");
        assert_eq!(resp.headers()["allow"], READ_ALLOW, "{verb} {p}");
    }
    // and the tag is still there
    assert_eq!(
        c.get(format!("{url}/dav/repos/demo/tags/v1"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let _ = std::fs::remove_dir_all(&dir);
}
