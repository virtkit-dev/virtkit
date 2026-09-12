//! End-to-end test of `POST /vk/manifests/exists`, the batched manifest probe `vk build`
//! uses to find where a stage resumes: one request answers for every tag, in order, and
//! says nothing about a tag it does not hold. Over real HTTP against a shared-mode server.

use std::sync::Arc;

use vk_registry::lock::LockManager;
use vk_registry::{ServerState, Store};

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vk-registry-exists-{tag}-{}-{:?}",
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

const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_probe_answers_every_tag_in_order() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tmp("store");
    let store = Store::new(dir.clone()).unwrap();
    let blob = store.put_blob(&[7u8; 1000]).unwrap();
    let manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{blob}","size":1000}},"layers":[]}}"#
    );
    for tag in ["snap-a", "snap-c"] {
        store
            .put_manifest("build-cache", tag, MANIFEST_TYPE, manifest.as_bytes())
            .unwrap();
    }
    let url = spawn(Arc::new(ServerState {
        store: Arc::new(store),
        upstreams: vec![],
        locks: LockManager::new(),
        auth: vk_registry::Authenticator::Shared(vk_registry::auth::Auth::None),
        tls: None,
        webdav: true,
    }));
    let http = reqwest::Client::new();
    let exists = format!("{url}{}", vk_registry::EXISTS_PATH);

    // Held, missing, held, and one that is not even a valid tag: answered in order,
    // the invalid one as absent rather than as an error.
    let resp = http
        .post(&exists)
        .query(&[("name", "build-cache")])
        .json(&serde_json::json!({ "tags": ["snap-a", "snap-b", "snap-c", "not a tag"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["present"],
        serde_json::json!([true, false, true, false])
    );

    // Another repository holds none of them.
    let resp = http
        .post(&exists)
        .query(&[("name", "other")])
        .json(&serde_json::json!({ "tags": ["snap-a"] }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["present"], serde_json::json!([false]));

    // The shape is enforced: a body without `tags`, a name that is not one, a GET.
    let resp = http
        .post(&exists)
        .query(&[("name", "build-cache")])
        .json(&serde_json::json!({ "names": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = http
        .post(&exists)
        .query(&[("name", "a//b")])
        .json(&serde_json::json!({ "tags": ["snap-a"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = http.get(&exists).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);

    // Both caps refuse rather than truncate or read unboundedly: too many tags, and a body
    // over the read cap (refused before it is even parsed).
    let many: Vec<String> = (0..=4096).map(|i| format!("t{i}")).collect();
    let resp = http
        .post(&exists)
        .query(&[("name", "build-cache")])
        .json(&serde_json::json!({ "tags": many }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let huge = "a".repeat(2 << 20);
    let resp = http
        .post(&exists)
        .query(&[("name", "build-cache")])
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(format!(r#"{{"tags":["{huge}"]}}"#))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    let _ = std::fs::remove_dir_all(&dir);
}
