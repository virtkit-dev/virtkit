//! Pull-through relay to upstream registries.
//!
//! On a local miss the server routes the request to an upstream (longest-prefix match
//! on the repo name), fetches it, and streams it back. Only content addressed by an
//! immutable `sha256:` digest is persisted into the store (all blobs, digest-pinned
//! manifests); a `:tag` manifest is relayed live and never cached, since a tag can move.
//! A client warms the cache by pinning the digest.
//!
//! A blob `HEAD` is the exception: it is answered locally and never relayed, because it is
//! a pusher's dedup probe and an upstream's answer to it is not about this store. See
//! [`get_blob`].
//!
//! Upstream auth (the Docker-registry bearer-token dance) is handled here, so a client
//! of this server never needs the upstream credentials — the reason a central
//! `vk-registry` can front a private registry for many runners.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures::StreamExt;
use hyper::{Response, StatusCode};
use reqwest::Method as RMethod;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::{
    Body, ServerState, body_of, error_response, get_blob as serve_blob_local,
    get_manifest as serve_manifest_local,
};

/// Unique suffix source for a relay's staging temp file (per process).
static RELAY_TMP: AtomicU64 = AtomicU64::new(0);

/// Manifest media types we accept from upstream (OCI + Docker, image + index) — the same
/// four as `crate::MANIFEST_MEDIA_TYPES`, which is what we will serve them as — a test
/// holds the two together, because asking for a type we then relabel is the one drift that
/// would go unnoticed.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json,\
application/vnd.docker.distribution.manifest.v2+json,\
application/vnd.oci.image.index.v1+json,\
application/vnd.docker.distribution.manifest.list.v2+json";

/// A configured upstream registry this server mirrors.
pub struct Upstream {
    /// repo-name prefix selecting this upstream (`""` = catch-all)
    pub prefix: String,
    /// base URL, scheme included, no trailing slash (e.g. `https://registry-1.docker.io`)
    pub base: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub client: reqwest::Client,
}

/// Longest-prefix match of the repo `name` against the upstreams, returning the chosen
/// upstream and the repo path to use against it (its prefix stripped).
pub fn route<'a>(ups: &'a [Upstream], name: &str) -> Option<(&'a Upstream, String)> {
    ups.iter()
        .filter_map(|u| {
            if u.prefix.is_empty() {
                Some((u, name.to_string(), 0))
            } else if let Some(rest) = name.strip_prefix(&format!("{}/", u.prefix)) {
                Some((u, rest.to_string(), u.prefix.len() + 1))
            } else {
                None
            }
        })
        .max_by_key(|&(_, _, plen)| plen)
        .map(|(u, repo, _)| (u, repo))
}

/// Relay a blob GET: download, verify against `digest`, persist to the store, and serve
/// it back canonically.
///
/// GET only — a blob `HEAD` is answered from the local store and never reaches here. A
/// `HEAD` is a dedup probe a client issues before pushing, and an upstream's answer to it
/// is about the upstream, not about what this registry holds; reporting it would make the
/// client skip an upload whose blob the following manifest `PUT` then cannot find.
pub async fn get_blob(
    state: &ServerState,
    name: &str,
    digest: &str,
    accept_zstd: bool,
) -> Result<Response<Body>> {
    let Some((u, repo)) = route(&state.upstreams, name) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            digest,
        ));
    };
    let url = format!("{}/v2/{repo}/blobs/{digest}", u.base);

    let resp = authed(u, RMethod::GET, &url, None).await?;
    if !resp.status().is_success() {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            digest,
        ));
    }
    // Stream the upstream blob to a temp file (bounded memory — layers can be GBs),
    // hashing as we go; verify it matches the requested digest, then promote it into the
    // blob store and serve it back from there. `Store::stage_promotion` decides on the
    // bytes how it is stored: a `tar+gzip` layer arrives compressed and is kept as it came,
    // while an image config, an attestation or an uncompressed `tar` layer is stored as a
    // zstd frame instead of at full size.
    let hex = digest.trim_start_matches("sha256:");
    let uploads = state.store.uploads_dir();
    tokio::fs::create_dir_all(&uploads)
        .await
        .with_context(|| format!("creating {}", uploads.display()))?;
    let tmp = uploads.join(format!(
        ".relay-{}-{}",
        std::process::id(),
        RELAY_TMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .with_context(|| format!("creating {}", tmp.display()))?;
    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();
    let mut write_result = Ok(());
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => {
                hasher.update(&chunk);
                if let Err(e) = file.write_all(&chunk).await {
                    write_result = Err(anyhow::Error::from(e).context("writing the relayed blob"));
                    break;
                }
            }
            Err(e) => {
                write_result = Err(anyhow::Error::from(e).context("reading the upstream blob"));
                break;
            }
        }
    }
    let flush = file.flush().await;
    drop(file);
    if let Err(e) = write_result.and(flush.map_err(Into::into)) {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    let got = format!("sha256:{}", crate::hex_of(&hasher.finalize()));
    if got != digest {
        let _ = tokio::fs::remove_file(&tmp).await;
        bail!("upstream blob digest mismatch for {name}: got {got}, want {digest}");
    }
    // Off the runtime: staging compresses, and a multi-gigabyte layer would otherwise
    // block a tokio worker for seconds. The store lock is taken inside, after that pass.
    let store = state.store.clone();
    let (hex, name_owned) = (hex.to_string(), name.to_string());
    tokio::task::spawn_blocking(move || -> Result<()> {
        let staged = store.stage_promotion(&hex, &tmp)?;
        // shared store lock (vs. an exclusive gc) across the promote; see Store::lock_shared.
        let _lock = match store.lock_shared() {
            Ok(lock) => lock,
            // Nothing else will consume what staging produced; `uploads/` is swept by gc,
            // but not leaving it there is one line.
            Err(e) => {
                staged.discard();
                return Err(e);
            }
        };
        store.promote_staged(&hex, staged)?;
        // The caller was authorized to read `name`, the upstream for `name` served this
        // digest, and the bytes were hashed against it above — so the cached copy is
        // readable through `name`. Record that, or the next request for it would be
        // refused by the very cache that just fetched it.
        //
        // Note this is the *blob* path, where upstream vouched for the content. The
        // manifest path deliberately records nothing but the manifest itself: a relayed
        // manifest naming a digest this store happens to hold must not hand that local
        // blob to the caller — each layer earns its own membership by being fetched here.
        store.record_blob(&name_owned, &hex)
    })
    .await
    .context("joining the promotion of a relayed blob")?
    .with_context(|| format!("promoting the relayed blob {digest}"))?;
    serve_blob_local(&state.store, digest, /* head */ false, accept_zstd)
}

/// Relay a manifest GET/HEAD. A digest reference is immutable, so it is persisted (a
/// digest-referenced put creates no tag) and then served from the store; a tag is
/// relayed live and never cached.
pub async fn get_manifest(
    state: &ServerState,
    name: &str,
    reference: &str,
    head: bool,
) -> Result<Response<Body>> {
    let Some((u, repo)) = route(&state.upstreams, name) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            reference,
        ));
    };
    let url = format!("{}/v2/{repo}/manifests/{reference}", u.base);
    let method = if head { RMethod::HEAD } else { RMethod::GET };
    let resp = authed(u, method, &url, Some(MANIFEST_ACCEPT)).await?;
    if !resp.status().is_success() {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            reference,
        ));
    }
    // Held to the same allowlist a locally stored manifest is: an upstream's
    // `Content-Type` is no more trustworthy than a pusher's, and this response comes from
    // the origin that serves `/browse` and holds the session cookie.
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|t| crate::manifest_media_type(t))
        .unwrap_or(crate::DEFAULT_MANIFEST_TYPE)
        .to_string();
    let up_digest = resp
        .headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if head {
        let digest = up_digest.unwrap_or_else(|| reference.to_string());
        return manifest_head_response(&digest, &ctype);
    }

    let body = resp
        .bytes()
        .await
        .context("reading the upstream manifest")?;

    if reference.starts_with("sha256:") {
        // immutable: persist (a digest reference writes no tag) and serve canonically.
        // Under the shared store lock, as the blob path is: the write puts the bytes and
        // the sidecar that makes them readable here, and an exclusive `gc` in between
        // would leave the one without the other.
        let _lock = state.store.lock_shared()?;
        let got = state.store.put_manifest(name, reference, &ctype, &body)?;
        if got != reference {
            bail!("upstream manifest digest mismatch for {name}: got {got}, want {reference}");
        }
        return serve_manifest_local(&state.store, name, reference, head);
    }

    // a tag is mutable: relay live, never persist.
    let digest = up_digest.unwrap_or_else(|| format!("sha256:{}", crate::sha256_hex_raw(&body)));
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(hyper::header::CONTENT_TYPE, &ctype)
        .header(hyper::header::CONTENT_LENGTH, body.len().to_string())
        .body(body_of(Bytes::from(body.to_vec())))
        .map_err(Into::into)
}

/// Issue a request, transparently doing the Docker bearer-token dance on a 401: parse
/// the `WWW-Authenticate` challenge, fetch a token from its realm (with this upstream's
/// Basic credentials, if any), and retry once with the bearer token.
async fn authed(
    u: &Upstream,
    method: RMethod,
    url: &str,
    accept: Option<&str>,
) -> Result<reqwest::Response> {
    let build = |bearer: Option<&str>| {
        let mut r = u.client.request(method.clone(), url);
        if let Some(a) = accept {
            r = r.header(reqwest::header::ACCEPT, a);
        }
        match bearer {
            Some(t) => r.bearer_auth(t),
            None => r,
        }
    };
    let first = build(None)
        .send()
        .await
        .with_context(|| format!("{method} {url}"))?;
    if first.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(first);
    }
    let challenge = first
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let Some(challenge) = challenge else {
        return Ok(first);
    };
    let Some(token) = obtain_token(u, &challenge).await? else {
        return Ok(first);
    };
    build(Some(&token))
        .send()
        .await
        .with_context(|| format!("{method} {url} (authenticated)"))
}

/// Fetch a bearer token for a `Bearer realm="…",service="…",scope="…"` challenge.
/// Returns `None` for a non-Bearer scheme or a token endpoint that declines.
async fn obtain_token(u: &Upstream, challenge: &str) -> Result<Option<String>> {
    let Some(rest) = challenge.trim().strip_prefix("Bearer ") else {
        return Ok(None);
    };
    let mut realm = None;
    let mut params: Vec<(String, String)> = Vec::new();
    for part in rest.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "realm" => realm = Some(v),
                "service" => params.push(("service".into(), v)),
                "scope" => params.push(("scope".into(), v)),
                _ => {}
            }
        }
    }
    let Some(realm) = realm else {
        return Ok(None);
    };
    let mut req = u.client.get(&realm).query(&params);
    if let (Some(user), Some(pass)) = (&u.username, &u.password) {
        req = req.basic_auth(user, Some(pass));
    }
    let resp = req.send().await.context("fetching an upstream token")?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    #[derive(serde::Deserialize)]
    struct Tok {
        token: Option<String>,
        access_token: Option<String>,
    }
    let t: Tok = resp.json().await.context("parsing the token response")?;
    Ok(t.token.or(t.access_token))
}

fn manifest_head_response(digest: &str, ctype: &str) -> Result<Response<Body>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(hyper::header::CONTENT_TYPE, ctype)
        .body(body_of(Bytes::new()))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asking upstream for a type we would then relabel is the one drift between these two
    /// lists that nothing else would catch: the request succeeds, and every response of that
    /// type is quietly served as something else. Compared as sets — the orders differ, and
    /// the `Accept` order is a preference this does not constrain.
    #[test]
    fn the_accept_list_is_exactly_what_we_will_serve() {
        let mut asked: Vec<&str> = MANIFEST_ACCEPT.split(',').collect();
        let mut served: Vec<&str> = crate::MANIFEST_MEDIA_TYPES.to_vec();
        asked.sort_unstable();
        served.sort_unstable();
        assert_eq!(asked, served);
    }

    fn up(prefix: &str) -> Upstream {
        // reqwest (rustls-no-provider) needs a crypto provider before a client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Upstream {
            prefix: prefix.to_string(),
            base: format!("https://{prefix}"),
            username: None,
            password: None,
            client: reqwest::Client::new(),
        }
    }

    #[test]
    fn longest_prefix_routing() {
        let ups = vec![up("docker.io"), up("ghcr.io"), {
            let mut c = up("");
            c.base = "https://fallback".into();
            c
        }];
        let (u, repo) = route(&ups, "docker.io/library/alpine").unwrap();
        assert_eq!(u.prefix, "docker.io");
        assert_eq!(repo, "library/alpine");

        let (u, repo) = route(&ups, "ghcr.io/wallix/tool").unwrap();
        assert_eq!(u.prefix, "ghcr.io");
        assert_eq!(repo, "wallix/tool");

        // no matching prefix falls to the catch-all, repo = the whole name.
        let (u, repo) = route(&ups, "quay.io/coreos/etcd").unwrap();
        assert_eq!(u.prefix, "");
        assert_eq!(repo, "quay.io/coreos/etcd");
    }

    #[test]
    fn no_upstreams_no_route() {
        assert!(route(&[], "docker.io/library/alpine").is_none());
    }
}
