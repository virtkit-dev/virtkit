//! Chunked, whole and zstd pushes round-trip the canonical bytes over HTTP.
//! After an interrupted PATCH, retrying extends the upload by exactly one chunk.
//! A push to an unknown upload is refused before its body is read.
//! A manifest push waiting on the store lock leaves the server answering other requests.

use std::sync::Arc;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use vk_registry::{ServerConfig, ServerState};

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-push-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

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

fn digest_of(bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// Serve a fresh local store and return its parent directory and URL.
fn serve(tag: &str) -> (std::path::PathBuf, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp(tag);
    let cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    let state = Arc::new(cfg.into_state().expect("a local config starts"));
    (dir, spawn(state))
}

/// The session and staging files directly in the store's `uploads/`.
fn upload_files(dir: &std::path::Path) -> Vec<std::ffi::OsString> {
    std::fs::read_dir(dir.join("store").join("uploads"))
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| e.file_name())
        .collect()
}

/// Stream `parts` with chunked transfer encoding. An `Err` interrupts the request body.
fn chunked(parts: Vec<Result<Vec<u8>, std::io::Error>>) -> reqwest::Body {
    reqwest::Body::wrap_stream(futures::stream::iter(
        parts.into_iter().map(|p| p.map(Bytes::from)),
    ))
}

/// Open an upload session in `app` and return its URL.
async fn start(http: &reqwest::Client, url: &str) -> String {
    let r = http
        .post(format!("{url}/v2/app/blobs/uploads/"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    format!("{url}{}", r.headers()["location"].to_str().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blob_pushed_in_chunks_whole_or_as_zstd_comes_back_intact() {
    let (dir, url) = serve("push");
    let http = reqwest::Client::new();
    let fetch = |digest: String| {
        let (http, url) = (http.clone(), url.clone());
        async move {
            let r = http
                .get(format!("{url}/v2/app/blobs/{digest}"))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 200, "{digest}");
            r.bytes().await.unwrap().to_vec()
        }
    };

    // Send the first PATCH in two parts, then interrupt the next PATCH.
    let raw: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
    let digest = digest_of(&raw);
    let session = start(&http, &url).await;
    let r = http
        .patch(&session)
        .body(chunked(vec![
            Ok(raw[..1000].to_vec()),
            Ok(raw[1000..300_000].to_vec()),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    assert_eq!(r.headers()["range"], "0-299999");

    let cut = http
        .patch(&session)
        .body(chunked(vec![
            Ok(raw[300_000..400_000].to_vec()),
            Err(std::io::Error::other("the client went away")),
        ]))
        .send()
        .await;
    assert!(cut.is_err(), "a body cut short was answered: {cut:?}");

    // Retry the whole chunk. The accepted range must advance exactly once.
    let r = http
        .patch(&session)
        .body(raw[300_000..600_000].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    assert_eq!(r.headers()["range"], "0-599999");
    let r = http
        .put(format!("{session}?digest={digest}"))
        .body(chunked(vec![Ok(raw[600_000..].to_vec())]))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    assert_eq!(fetch(digest).await, raw);

    // Whole, in one PUT.
    let whole: Vec<u8> = raw.iter().rev().copied().collect();
    let digest = digest_of(&whole);
    let session = start(&http, &url).await;
    let r = http
        .put(format!("{session}?digest={digest}"))
        .body(whole.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    assert_eq!(fetch(digest).await, whole);

    // As a zstd frame, under the digest of what it decodes to.
    let canonical = vec![9u8; 500_000];
    let digest = digest_of(&canonical);
    let session = start(&http, &url).await;
    let r = http
        .put(format!("{session}?digest={digest}"))
        .header("Content-Encoding", "zstd")
        .body(vk_registry::zstd_with_size(&canonical).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    assert_eq!(fetch(digest).await, canonical);

    // A digest mismatch rejects the PUT and invalidates its session.
    let session = start(&http, &url).await;
    let r = http
        .put(format!("{session}?digest={}", digest_of(b"promised")))
        .body("delivered")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let r = http.patch(&session).body("more").send().await.unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // The server may detect the interrupted PATCH after the client returns. Wait for
    // it to remove the staged body before checking that uploads/ has no files.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !upload_files(&dir).is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(upload_files(&dir).is_empty(), "{:?}", upload_files(&dir));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A request that will be refused whatever it holds is answered before its body is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_to_an_unknown_upload_is_refused_before_its_body() {
    let (dir, url) = serve("refused");
    let http = reqwest::Client::new();

    // These bodies never end.
    let endless = || {
        use futures::StreamExt;
        reqwest::Body::wrap_stream(
            futures::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"some"))])
                .chain(futures::stream::pending()),
        )
    };
    let unknown = format!("{url}/v2/app/blobs/uploads/aa-0");
    let session = start(&http, &url).await;
    let digest = digest_of(b"some");
    for (request, status) in [
        (http.patch(&unknown), 404),
        (http.put(format!("{unknown}?digest={digest}")), 404),
        (http.put(&session), 400),
        (http.put(format!("{session}?digest=sha256:short")), 400),
    ] {
        let sent = request.body(endless()).send();
        let r = tokio::time::timeout(std::time::Duration::from_secs(30), sent)
            .await
            .expect("an answer without the body")
            .unwrap();
        assert_eq!(r.status().as_u16(), status);
    }
    // A rejected finalization leaves the session usable.
    let r = http
        .put(format!("{session}?digest={digest}"))
        .body("some")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    assert!(upload_files(&dir).is_empty(), "{:?}", upload_files(&dir));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The single-threaded server answers other requests while a manifest push waits on the
/// store lock held exclusively as in a gc batch. Releasing the lock lets the push finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_waiting_on_the_store_lock_stalls_no_other_request() {
    let (dir, url) = serve("lock-wait");
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    assert_eq!(
        http.get(format!("{url}/v2/"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let store = vk_registry::Store::new(dir.join("store")).unwrap();
    let gc = store.lock_exclusive().unwrap();

    let push = tokio::spawn({
        let (http, url) = (http.clone(), url.clone());
        async move {
            http.put(format!("{url}/v2/app/manifests/v1"))
                .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .body(r#"{"schemaVersion":2,"layers":[]}"#)
                .send()
                .await
                .unwrap()
                .status()
        }
    });
    // Wait for the push to block in `flock` so the probes cannot finish before it stalls.
    let lock = std::os::unix::fs::MetadataExt::ino(
        &std::fs::metadata(dir.join("store").join(".lock")).unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !blocked_on(lock) {
        assert!(
            std::time::Instant::now() < deadline,
            "the push never waited for the lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(!push.is_finished(), "the push waits for the lock");
    let probe = format!("{url}/v2/app/blobs/{}", digest_of(b"absent"));
    assert_eq!(http.head(&probe).send().await.unwrap().status(), 404);
    assert_eq!(
        http.get(format!("{url}/v2/"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    drop(gc);
    assert_eq!(push.await.unwrap(), 201);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A blocked `flock` appears in `/proc/locks` as
/// `N: -> FLOCK ADVISORY MODE PID MAJOR:MINOR:INODE START END`. Matching this process and
/// `ino` requires `stat` and `/proc/locks` to report the same inode, which overlayfs may hide.
fn blocked_on(ino: u64) -> bool {
    let locks = std::fs::read_to_string("/proc/locks").expect("reading /proc/locks");
    let pid = std::process::id().to_string();
    locks.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.get(1) == Some(&"->")
            && f.get(2) == Some(&"FLOCK")
            && f.get(5) == Some(&pid.as_str())
            && f.get(6)
                .and_then(|id| id.rsplit(':').next())
                .is_some_and(|i| i.parse() == Ok(ino))
    })
}
