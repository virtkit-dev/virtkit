//! Chunked, whole and zstd pushes round-trip the canonical bytes over HTTP.
//! After an interrupted PATCH, retrying extends the upload by exactly one chunk.

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
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tmp("push");
    let cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
    let state = Arc::new(cfg.into_state().expect("a local config starts"));
    let url = spawn(state);
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

    // No session or staging files remain directly in uploads/.
    let left: Vec<_> = std::fs::read_dir(dir.join("store").join("uploads"))
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| e.file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");

    let _ = std::fs::remove_dir_all(&dir);
}
