//! A push to an unknown upload is refused before its body is read.

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
