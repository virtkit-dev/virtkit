//! Pull-through relay to upstream registries.
//!
//! On a local miss the server routes the request to an upstream (longest-prefix match
//! on the repo name), fetches it, and streams it back. Only content addressed by an
//! immutable `sha256:` digest is persisted into the store (all blobs, digest-pinned
//! manifests); a `:tag` manifest is relayed live and never cached, since a tag can move.
//! A client warms the cache by pinning the digest.
//!
//! Upstream auth (the Docker-registry bearer-token dance) is handled here, so a client
//! of this server never needs the upstream credentials — the reason a central
//! `vk-registry` can front a private registry for many runners.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use reqwest::Method as RMethod;

use crate::{
    ServerState, error_response, get_blob as serve_blob_local, get_manifest as serve_manifest_local,
};

/// Manifest media types we accept from upstream (OCI + Docker, image + index).
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json,\
application/vnd.docker.distribution.manifest.v2+json,\
application/vnd.oci.image.index.v1+json,\
application/vnd.docker.distribution.manifest.list.v2+json";

const DEFAULT_MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

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

/// Relay a blob GET/HEAD. GET downloads, verifies against `digest`, persists to the
/// store, and serves it back canonically; HEAD probes upstream existence without
/// persisting (a blob is only cached once it is actually pulled).
pub async fn get_blob(
    state: &ServerState,
    name: &str,
    digest: &str,
    head: bool,
    accept_zstd: bool,
) -> Result<Response<Full<Bytes>>> {
    let Some((u, repo)) = route(&state.upstreams, name) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            digest,
        ));
    };
    let url = format!("{}/v2/{repo}/blobs/{digest}", u.base);

    if head {
        let resp = authed(u, RMethod::HEAD, &url, None).await?;
        if !resp.status().is_success() {
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                "BLOB_UNKNOWN",
                digest,
            ));
        }
        let len = content_length(&resp);
        return blob_head_response(digest, len);
    }

    let resp = authed(u, RMethod::GET, &url, None).await?;
    if !resp.status().is_success() {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            digest,
        ));
    }
    // NOTE: buffered in memory then stored; a streaming tee (upstream → client + store)
    // is the planned optimization for multi-GB layers. See DESIGN.md.
    let bytes = resp.bytes().await.context("reading the upstream blob")?;
    let got = state.store.put_blob(&bytes)?;
    if got != digest {
        bail!("upstream blob digest mismatch for {name}: got {got}, want {digest}");
    }
    serve_blob_local(&state.store, digest, head, accept_zstd)
}

/// Relay a manifest GET/HEAD. A digest reference is immutable, so it is persisted (a
/// digest-referenced put creates no tag) and then served from the store; a tag is
/// relayed live and never cached.
pub async fn get_manifest(
    state: &ServerState,
    name: &str,
    reference: &str,
    head: bool,
) -> Result<Response<Full<Bytes>>> {
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
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_MANIFEST_TYPE)
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
        .header(hyper::header::CONTENT_TYPE, &ctype)
        .header(hyper::header::CONTENT_LENGTH, body.len().to_string())
        .body(Full::new(Bytes::from(body.to_vec())))
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

fn content_length(resp: &reqwest::Response) -> Option<u64> {
    resp.headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

/// A blob HEAD response mirroring the store's own (200, digest, octet-stream, length).
fn blob_head_response(digest: &str, len: Option<u64>) -> Result<Response<Full<Bytes>>> {
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream");
    if let Some(len) = len {
        b = b.header(hyper::header::CONTENT_LENGTH, len.to_string());
    }
    b.body(Full::new(Bytes::new())).map_err(Into::into)
}

fn manifest_head_response(digest: &str, ctype: &str) -> Result<Response<Full<Bytes>>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(hyper::header::CONTENT_TYPE, ctype)
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

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
