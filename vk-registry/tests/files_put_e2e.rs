//! A file streamed to `PUT /files/<dir>/<name>` over real HTTP: stored as `vk registry put
//! --dir` stores it, with the annotations asked for, only once all of it arrived and hashes
//! to what was asked; a put cut short or refused leaves no staging file behind, and one
//! refused on its headers is refused before its body is read.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use sha2::Digest;
use vk_hub_proto::registry::{
    FILE_ANNOTATIONS_HEADER, FILE_RETENTION_HEADER, FILE_SHA256_HEADER, FilePut,
};
use vk_hub_proto::token::{Claims, Grant};
use vk_peer::token::Signer;
use vk_registry::lock::LockManager;
use vk_registry::{ServerState, Store};

const AUD: &str = "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708";

fn tmp(tag: &str) -> std::path::PathBuf {
    // Already installed by another test of this binary, which is as good.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let p = std::env::temp_dir().join(format!(
        "vk-registry-files-put-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    // Left over from an earlier run, if anything; absent is the usual case.
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A shared-secret registry taking tokens signed by a fresh key, served on a thread of its
/// own; its URL, store and signer.
fn serve(dir: &std::path::Path) -> (String, Arc<Store>, Signer) {
    let signer = Signer::generate(&dir.join("token-key")).unwrap();
    let store = Arc::new(Store::new(dir.join("store")).unwrap());
    let state = Arc::new(ServerState {
        store: store.clone(),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::Authenticator::Shared(vk_registry::auth::Auth::Bearer {
            token: "s3cret".to_string(),
        }),
        tls: None,
        webdav: false,
        tokens: Default::default(),
        handover: Default::default(),
    });
    state.tokens.open(AUD, vec![signer.public().clone()], &[]);
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
            vk_registry::serve_on(l, state).await.expect("serving");
        });
    });
    (format!("http://{addr}"), store, signer)
}

fn token(signer: &Signer, prefixes: &[&str]) -> String {
    let now = vk_peer::now_secs();
    signer
        .sign(Claims {
            kid: String::new(),
            aud: AUD.into(),
            sub: "hub:media".into(),
            jti: vk_peer::token::new_jti().unwrap(),
            pipeline: None,
            iat: now - 1,
            exp: now + 600,
            grants: prefixes
                .iter()
                .map(|p| Grant {
                    prefix: p.to_string(),
                    write: true,
                    ..Grant::default()
                })
                .collect(),
        })
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    vk_hub_proto::to_hex(&sha2::Sha256::digest(bytes))
}

/// The staging files under `uploads/`.
fn staged(store: &Store) -> usize {
    std::fs::read_dir(store.uploads_dir())
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_file())
        .count()
}

/// Wait until `staged(store)` is `n`, for up to ten seconds.
async fn staged_becomes(store: &Store, n: usize) {
    for _ in 0..500 {
        if staged(store) == n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(staged(store), n);
}

/// A put of `path` declaring `length` bytes (chunked when `None`), of which `body` is sent,
/// on a connection of its own, left open.
fn open(url: &str, path: &str, token: Option<&str>, length: Option<u64>, body: &[u8]) -> TcpStream {
    let mut s = TcpStream::connect(url.trim_start_matches("http://")).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut head = format!("PUT /files/{path} HTTP/1.1\r\nHost: x\r\n");
    if let Some(t) = token {
        head += &format!("Authorization: Bearer {t}\r\n");
    }
    match length {
        Some(n) => head += &format!("Content-Length: {n}\r\n\r\n"),
        None => head += "Transfer-Encoding: chunked\r\n\r\n",
    }
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    s
}

/// The status of the answer on `s`.
fn status(s: &mut TcpStream) -> u16 {
    let mut line = Vec::new();
    let mut byte = [0u8];
    while !line.ends_with(b"\r\n") {
        s.read_exact(&mut byte).unwrap();
        line.push(byte[0]);
    }
    let line = String::from_utf8(line).unwrap();
    line.split(' ').nth(1).unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_file_is_tagged_by_digest_and_name_with_its_annotations() {
    let dir = tmp("ok");
    let (url, store, signer) = serve(&dir);
    let http = reqwest::Client::new();
    let body = vec![7u8; 300_000];
    let sha = hex(&body);
    let annotations = serde_json::json!({"org.virtkit.media.kind": "windows"}).to_string();
    let r = http
        .put(format!("{url}/files/win-media/ws2025.iso"))
        .bearer_auth(token(&signer, &["sha256", "win-media"]))
        .header(FILE_SHA256_HEADER, &sha)
        .header(FILE_RETENTION_HEADER, "keep")
        .header(
            FILE_ANNOTATIONS_HEADER,
            vk_hub_proto::token::to_base64url(annotations.as_bytes()),
        )
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let put: FilePut = r.json().await.unwrap();
    assert_eq!((put.sha256.as_str(), put.size), (sha.as_str(), 300_000));

    for (repo, tag) in [
        ("files/sha256", sha.as_str()),
        ("files/win-media", "ws2025.iso"),
    ] {
        let (digest, manifest, _) = store.get_manifest(repo, tag).unwrap().unwrap();
        assert_eq!(digest, put.manifest);
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        assert_eq!(manifest["annotations"]["org.virtkit.retention"], "keep");
        assert_eq!(manifest["annotations"]["org.virtkit.media.kind"], "windows");
        let mut file = store.open_file(repo, tag).unwrap().unwrap();
        assert_eq!(file.title.as_deref(), Some("ws2025.iso"));
        let mut got = Vec::new();
        file.reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
    }
    assert_eq!(staged(&store), 0);

    // Under a path, as a client whose registry repository is that path finds it.
    let r = http
        .put(format!(
            "{url}/files/win-media/ws2025.iso?under=build-cache"
        ))
        .bearer_auth(token(
            &signer,
            &["build-cache/files/sha256", "build-cache/files/win-media"],
        ))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    for (repo, tag) in [
        ("build-cache/files/sha256", sha.as_str()),
        ("build-cache/files/win-media", "ws2025.iso"),
    ] {
        assert!(
            store.open_file(repo, tag).unwrap().is_some(),
            "{repo}:{tag}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_put_leaves_nothing() {
    let dir = tmp("refused");
    let (url, store, signer) = serve(&dir);
    let http = reqwest::Client::new();
    let both = token(&signer, &["sha256", "win-media"]);
    let put = |path: &str, token: &str| {
        http.put(format!("{url}/files/{path}"))
            .bearer_auth(token.to_string())
            .body(vec![1u8; 1000])
    };
    let status = |r: reqwest::Response| r.status().as_u16();

    // Not the sha256 asked for.
    let r = put("win-media/a.iso", &both)
        .header(FILE_SHA256_HEADER, "0".repeat(64))
        .send()
        .await
        .unwrap();
    assert_eq!(status(r), 400);
    // Without write on the digest repository, or the name's.
    let r = put("win-media/a.iso", &token(&signer, &["win-media"]))
        .send()
        .await
        .unwrap();
    assert_eq!(status(r), 403);
    let r = put("other/a.iso", &both).send().await.unwrap();
    assert_eq!(status(r), 403);
    // The digest repository is named by the bytes alone.
    let r = put(&format!("sha256/{}", "0".repeat(64)), &both)
        .send()
        .await
        .unwrap();
    assert_eq!(status(r), 400);
    // Retention is the header's to set.
    let r = put("win-media/a.iso", &both)
        .header(
            FILE_ANNOTATIONS_HEADER,
            vk_hub_proto::token::to_base64url(br#"{"org.virtkit.retention":"keep"}"#),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(status(r), 400);
    let r = put("win-media/a.iso", &both)
        .header(FILE_RETENTION_HEADER, "forever")
        .send()
        .await
        .unwrap();
    assert_eq!(status(r), 400);

    // A body cut short, once it is being staged.
    let cut = open(
        &url,
        "win-media/a.iso",
        Some(&both),
        Some(1_000_000),
        &[2u8; 4096],
    );
    staged_becomes(&store, 1).await;
    cut.shutdown(std::net::Shutdown::Both).unwrap();
    drop(cut);
    staged_becomes(&store, 0).await;
    assert!(
        store
            .get_manifest("files/win-media", "a.iso")
            .unwrap()
            .is_none()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A put refused on its headers is answered before its body is read, nothing staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_is_refused_before_its_body() {
    let dir = tmp("early");
    let (url, store, signer) = serve(&dir);
    let both = token(&signer, &["sha256", "win-media"]);
    let huge = Some(10u64 << 30);
    let long = format!("win-media/{}", "t".repeat(129));
    for (path, token, length, want) in [
        // Unauthenticated, then without write on the digest repository.
        ("win-media/a.iso", None, huge, 401),
        (
            "win-media/a.iso",
            Some(token(&signer, &["win-media"])),
            huge,
            403,
        ),
        // Of no length, an overlong tag, more than the store has room for.
        ("win-media/a.iso", Some(both.clone()), None, 411),
        (long.as_str(), Some(both.clone()), huge, 400),
        ("win-media/a.iso", Some(both.clone()), Some(1u64 << 60), 507),
    ] {
        let mut s = open(&url, path, token.as_deref(), length, b"");
        assert_eq!(status(&mut s), want, "{path} {length:?}");
        assert_eq!(staged(&store), 0);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Two puts stream at once; a third is told to come back, and taken once one is done. An
/// empty file is a file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn puts_beyond_the_slots_wait_their_turn() {
    let dir = tmp("slots");
    let (url, store, signer) = serve(&dir);
    let both = token(&signer, &["sha256", "win-media"]);
    let first = open(
        &url,
        "win-media/a.iso",
        Some(&both),
        Some(1 << 20),
        &[1u8; 10],
    );
    let _second = open(
        &url,
        "win-media/b.iso",
        Some(&both),
        Some(1 << 20),
        &[1u8; 10],
    );
    staged_becomes(&store, 2).await;

    let http = reqwest::Client::new();
    let put = || {
        http.put(format!("{url}/files/win-media/empty"))
            .bearer_auth(&both)
            .body(Vec::new())
            .send()
    };
    let r = put().await.unwrap();
    assert_eq!(r.status(), 503);
    assert!(r.headers().contains_key("retry-after"));

    first.shutdown(std::net::Shutdown::Both).unwrap();
    drop(first);
    staged_becomes(&store, 1).await;
    let r = put().await.unwrap();
    assert_eq!(r.status(), 201);
    let put: FilePut = r.json().await.unwrap();
    assert_eq!((put.sha256, put.size), (hex(b""), 0));
    assert_eq!(
        store
            .open_file("files/win-media", "empty")
            .unwrap()
            .unwrap()
            .size,
        0
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
