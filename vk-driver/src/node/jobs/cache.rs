//! A placed job's caches, kept in the registry the node uses: one OCI artifact per key, with
//! one `tar+zstd` layer, in repository `ci-cache/<gitlab host>/<project id>`, tagged with the
//! sha256 of the key and the protection of the job's ref. See `docs/gitlab-dispatch.md`,
//! "Artifacts and caches".
//!
//! Which caches a stage restores or saves, and what it says about each, follow gitlab-runner
//! v19.5's `shells/abstract.go` (`cacheExtractor`, `extractCacheOrFallbackCachesWrapper`,
//! `archiveCache`; MIT, see [`super::mask`] for the notice). The archive itself is made and
//! unpacked by `vk-agent` in the guest ([`super::guest`]); the node compresses it and moves it,
//! with its own registry credential.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use vk_hub_proto::job::{CachePolicy, CacheSpec};

use super::StageCtx;
use super::guest::{self, Selection};
use super::transfer::{self, Capped, MAX_STAGED, create, too_large};

/// The layer's media type: a tar of the cached paths, zstd-compressed.
pub const LAYER_MEDIA_TYPE: &str = "application/vnd.vk.ci-cache.layer.v1.tar+zstd";
/// The manifest's `artifactType`.
pub const ARTIFACT_TYPE: &str = "application/vnd.vk.ci-cache.v1";
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI's empty config, `{}`.
const EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
const EMPTY_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// The most a manifest read back may hold.
const MAX_MANIFEST: usize = 64 * 1024;

/// gitlab-runner's `DefaultCacheRequestTimeout`, in minutes: how long one request to the
/// cache's store may take, its body included, unless `CACHE_REQUEST_TIMEOUT` says otherwise.
const REQUEST_TIMEOUT_MINUTES: u64 = 10;

/// `CACHE_REQUEST_TIMEOUT`, minutes, as gitlab-runner reads it: a positive integer, else the
/// default.
fn request_timeout(raw: &str) -> Duration {
    let minutes = raw
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|&m| m > 0)
        .unwrap_or(REQUEST_TIMEOUT_MINUTES);
    Duration::from_secs(minutes.saturating_mul(60))
}

/// Whether `restore_cache` has anything to do: a cache with paths or `untracked`.
pub fn restore_applies(ctx: &StageCtx<'_>) -> bool {
    ctx.job.caches.iter().any(selects)
}

/// Whether `archive_cache` (`succeeded`) or `archive_cache_on_failure` has anything to do.
pub fn archive_applies(ctx: &StageCtx<'_>, succeeded: bool) -> bool {
    ctx.job
        .caches
        .iter()
        .any(|c| selects(c) && c.when.applies(succeeded))
}

fn selects(c: &CacheSpec) -> bool {
    !c.paths.is_empty() || c.untracked
}

/// The repository a project's caches live in, under the registry's own prefix:
/// `ci-cache/<gitlab host>[/<gitlab path>]/<project id>`, lowercased, a port joined to the
/// host by `-`, as OCI repository names allow; the path keeps apart two GitLabs served under
/// one host.
pub fn repository(server_url: &str, project_id: u64) -> Result<String> {
    let rest = server_url
        .split_once("://")
        .map_or(server_url, |(_, rest)| rest);
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let mut parts = rest.split('/');
    let authority = parts.next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let mut name = vec![host.to_ascii_lowercase().replace(':', "-")];
    name.extend(
        parts
            .filter(|p| !p.is_empty())
            .map(|p| p.to_ascii_lowercase()),
    );
    let valid = name.iter().all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
            && part.starts_with(|c: char| c.is_ascii_alphanumeric())
            && part.ends_with(|c: char| c.is_ascii_alphanumeric())
            && !part.contains("..")
    });
    if !valid {
        bail!("GitLab's URL {server_url:?} cannot name a repository");
    }
    Ok(format!("ci-cache/{}/{project_id}", name.join("/")))
}

/// The tag a cache is kept under: the sha256 of its key and its ref's protection, so a
/// protected and an unprotected job never share one.
pub fn tag(key: &str, protected: bool) -> String {
    let protection = if protected {
        "protected"
    } else {
        "unprotected"
    };
    hex(&Sha256::digest(format!("{key}\n{protection}").as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// What `restore_cache` does with one cache.
#[derive(Debug, PartialEq, Eq)]
pub enum Restore {
    /// Nothing selected.
    Skip,
    /// `push` only.
    NotByPolicy(String),
    /// Try these keys in order; the first found wins.
    Keys(Vec<String>),
}

/// What `archive_cache` does with one cache.
#[derive(Debug, PartialEq, Eq)]
pub enum Save {
    Skip,
    NotByPolicy(String),
    Key(String),
}

/// A cache's key, defaulted as gitlab-runner defaults an empty one: `<job name>/<ref>`.
fn key_of(c: &CacheSpec, job_name: &str, git_ref: &str) -> String {
    match c.key.is_empty() {
        true => format!("{job_name}/{git_ref}"),
        false => c.key.clone(),
    }
}

/// `cacheExtractor` for one cache: its key, its fallbacks, then `CACHE_FALLBACK_KEY` unless
/// that ends in `-protected` (`warnings` says so).
pub fn plan_restore(
    c: &CacheSpec,
    job_name: &str,
    git_ref: &str,
    fallback: &str,
    warnings: &mut Vec<String>,
) -> Restore {
    if !selects(c) {
        return Restore::Skip;
    }
    let key = key_of(c, job_name, git_ref);
    if c.policy == CachePolicy::Push {
        return Restore::NotByPolicy(key);
    }
    let mut keys = vec![key];
    keys.extend(c.fallback_keys.iter().filter(|k| !k.is_empty()).cloned());
    if !fallback.is_empty() {
        if fallback
            .trim_end_matches(['.', ' '])
            .ends_with("-protected")
        {
            warnings.push(format!(
                "CACHE_FALLBACK_KEY {fallback:?} not allowed to end in \"-protected\""
            ));
        } else {
            keys.push(fallback.to_string());
        }
    }
    Restore::Keys(keys)
}

/// `archiveCache` for one cache.
pub fn plan_save(c: &CacheSpec, succeeded: bool, job_name: &str, git_ref: &str) -> Save {
    if !selects(c) || !c.when.applies(succeeded) {
        return Save::Skip;
    }
    let key = key_of(c, job_name, git_ref);
    match c.policy {
        CachePolicy::Pull => Save::NotByPolicy(key),
        CachePolicy::Push | CachePolicy::PullPush => Save::Key(key),
    }
}

struct Store {
    http: reqwest::Client,
    cred: crate::registry::Cred,
    /// `<scheme>://<registry>/v2/<repository>`.
    base: String,
}

impl Store {
    fn req(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.cred.apply(self.http.request(method, url))
    }

    /// `<scheme>://<registry>`, for a relative `Location`.
    fn origin(&self) -> &str {
        self.base
            .find("/v2/")
            .map_or(self.base.as_str(), |at| &self.base[..at])
    }
}

/// Where the caches go, or `None` (said in the trace) when they cannot go anywhere.
fn store(ctx: &StageCtx<'_>) -> Option<Store> {
    let Some(rg) = ctx.cfg.registry.as_ref() else {
        ctx.trace
            .warning("caches need a [registry] on this node; skipping");
        return None;
    };
    if rg.local_root().is_some() {
        ctx.trace
            .warning("caches need a remote [registry] on this node; skipping");
        return None;
    }
    let made = (|| {
        let repo = repository(&ctx.job.server_url, ctx.job.job.project_id)?;
        let (host, prefix) = rg.repo.split_once('/').unwrap_or((rg.repo.as_str(), ""));
        let path = match prefix.trim_matches('/') {
            "" => repo,
            prefix => format!("{prefix}/{repo}"),
        };
        let scheme = if rg.insecure { "http" } else { "https" };
        Ok::<_, anyhow::Error>(Store {
            http: crate::registry::http_client_builder(rg)?
                .connect_timeout(Duration::from_secs(30))
                .timeout(request_timeout(&ctx.vars.value("CACHE_REQUEST_TIMEOUT")))
                .build()
                .context("building the registry's client")?,
            cred: crate::registry::cred(rg)?,
            base: format!("{scheme}://{host}/v2/{path}"),
        })
    })();
    match made {
        Ok(store) => Some(store),
        Err(e) => {
            ctx.trace.warning(&format!("caches are unavailable: {e:#}"));
            None
        }
    }
}

/// `restore_cache`. A cache that cannot be fetched is a warning, as with gitlab-runner.
pub async fn restore(ctx: &StageCtx<'_>) -> Result<()> {
    let Some(store) = store(ctx) else {
        return Ok(());
    };
    let protected = ctx.job.sources.protected.unwrap_or(false);
    let fallback = ctx.vars.value("CACHE_FALLBACK_KEY");
    for c in &ctx.job.caches {
        let mut warnings = Vec::new();
        let plan = plan_restore(
            c,
            &ctx.job.job.name,
            &ctx.job.sources.git_ref,
            &fallback,
            &mut warnings,
        );
        for w in &warnings {
            ctx.trace.warning(w);
        }
        let keys = match plan {
            Restore::Skip => continue,
            Restore::NotByPolicy(key) => {
                ctx.trace
                    .notice(&format!("Not downloading cache {key} due to policy"));
                continue;
            }
            Restore::Keys(keys) => keys,
        };
        for key in keys {
            ctx.trace.notice(&format!("Checking cache for {key}..."));
            let tag = tag(&key, protected);
            let fetched = tokio::select! {
                r = fetch(ctx, &store, &tag) => r,
                () = ctx.cancel.cancelled() => bail!("canceled"),
            };
            match fetched {
                Ok(true) => {
                    ctx.trace.notice("Successfully extracted cache");
                    break;
                }
                Ok(false) => {
                    ctx.trace.warning(&format!("No cache found for {key}"));
                    ctx.trace.warning("Failed to extract cache");
                }
                Err(e) => {
                    ctx.trace.warning(&format!("{e:#}"));
                    ctx.trace.warning("Failed to extract cache");
                }
            }
        }
    }
    Ok(())
}

/// `archive_cache` or `archive_cache_on_failure`. A cache that cannot be saved is a warning.
pub async fn archive(ctx: &StageCtx<'_>, succeeded: bool) -> Result<()> {
    let Some(store) = store(ctx) else {
        return Ok(());
    };
    let protected = ctx.job.sources.protected.unwrap_or(false);
    for c in &ctx.job.caches {
        let key = match plan_save(c, succeeded, &ctx.job.job.name, &ctx.job.sources.git_ref) {
            Save::Skip => continue,
            Save::NotByPolicy(key) => {
                ctx.trace
                    .notice(&format!("Not uploading cache {key} due to policy"));
                continue;
            }
            Save::Key(key) => key,
        };
        ctx.trace.notice(&format!("Creating cache {key}..."));
        let sel = Selection {
            paths: c.paths.clone(),
            exclude: Vec::new(),
            untracked: c.untracked,
        };
        let tag = tag(&key, protected);
        let saved = tokio::select! {
            r = save(ctx, &store, &sel, &key, &tag) => r,
            () = ctx.cancel.cancelled() => bail!("canceled"),
        };
        match saved {
            Ok(()) => ctx.trace.notice("Created cache"),
            Err(e) => {
                ctx.trace.warning(&format!("{e:#}"));
                ctx.trace.warning("Failed to create cache");
            }
        }
    }
    Ok(())
}

/// Fetch the cache tagged `tag` and unpack it into the project dir: `false` when there is
/// none.
async fn fetch(ctx: &StageCtx<'_>, store: &Store, tag: &str) -> Result<bool> {
    let url = format!("{}/manifests/{tag}", store.base);
    let resp = store
        .req(reqwest::Method::GET, &url)
        .header(reqwest::header::ACCEPT, MANIFEST_MEDIA_TYPE)
        .send()
        .await
        .context("asking the registry for the cache")?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    if !resp.status().is_success() {
        bail!("the registry answered {} for the cache", resp.status());
    }
    let body = read_capped(resp, MAX_MANIFEST).await?;
    let (digest, size) = layer_of(&body)?;
    if size > MAX_STAGED {
        bail!(
            "the cache's layer of {size} bytes is {}",
            too_large(MAX_STAGED)
        );
    }
    let packed = ctx.scratch.join("cache.tar.zst");
    let fetched = async {
        download(store, &digest, size, &packed).await?;
        // Checked whole, then decompressed on its way to the guest.
        let from = packed.clone();
        let (mut tar, unpacked) = transfer::from_blocking(move |out| unzstd(&from, out));
        let extracted =
            guest::extract(&ctx.addr, ctx.user.as_deref(), &ctx.project_dir, &mut tar).await;
        transfer::drain(&mut tar, &extracted).await;
        drop(tar);
        let unpacked = transfer::joined(unpacked)
            .await
            .context("decompressing the cache");
        transfer::both(unpacked, extracted)?;
        Ok(true)
    }
    .await;
    // Scratch: the job's dir goes with the job either way.
    let _ = std::fs::remove_file(&packed);
    fetched
}

/// The blob `digest` into `dest`, refused past the `size` its manifest gives.
async fn download(store: &Store, digest: &str, size: u64, dest: &Path) -> Result<()> {
    let url = format!("{}/blobs/{digest}", store.base);
    let mut resp = store
        .req(reqwest::Method::GET, &url)
        .send()
        .await
        .context("downloading the cache")?;
    if !resp.status().is_success() {
        bail!(
            "the registry answered {} for the cache's layer",
            resp.status()
        );
    }
    let mut file = tokio::fs::File::from_std(create(dest)?);
    let mut hasher = Sha256::new();
    let mut got = 0u64;
    while let Some(chunk) = resp.chunk().await.context("downloading the cache")? {
        got = got.saturating_add(chunk.len() as u64);
        if got > size {
            bail!("the cache's layer is larger than the {size} bytes its manifest gives");
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing {}", dest.display()))?;
    }
    file.flush()
        .await
        .with_context(|| format!("writing {}", dest.display()))?;
    if got != size || format!("sha256:{}", hex(&hasher.finalize())) != digest {
        bail!("the cache's layer does not match its digest");
    }
    Ok(())
}

/// Archive what `sel` selects in the guest and push it under `tag`.
async fn save(
    ctx: &StageCtx<'_>,
    store: &Store,
    sel: &Selection,
    key: &str,
    tag: &str,
) -> Result<()> {
    // The guest's tar is compressed as it comes; the layer is kept, as it is pushed under
    // its digest.
    let packed = ctx.scratch.join("cache.tar.zst");
    let saved = async {
        let to = packed.clone();
        let (mut tar, compressed) = transfer::into_blocking(move |input| zstd_hashed(input, &to));
        let produced = guest::archive(
            &ctx.addr,
            ctx.user.as_deref(),
            &ctx.project_dir,
            sel,
            &mut tar,
            ctx.trace,
        )
        .await;
        drop(tar);
        let compressed = transfer::joined(compressed)
            .await
            .context("compressing the cache");
        let (_, (digest, size)) = transfer::both(produced, compressed)?;
        push(store, &packed, &digest, size, key, tag).await
    }
    .await;
    let _ = std::fs::remove_file(&packed);
    saved
}

async fn push(
    store: &Store,
    packed: &Path,
    digest: &str,
    size: u64,
    key: &str,
    tag: &str,
) -> Result<()> {
    put_blob(store, EMPTY_DIGEST, Body::Bytes(b"{}".to_vec())).await?;
    put_blob(store, digest, Body::File(packed)).await?;
    let url = format!("{}/manifests/{tag}", store.base);
    let resp = store
        .req(reqwest::Method::PUT, &url)
        .header(reqwest::header::CONTENT_TYPE, MANIFEST_MEDIA_TYPE)
        .body(manifest(digest, size, key))
        .send()
        .await
        .context("pushing the cache's manifest")?;
    if !resp.status().is_success() {
        bail!(
            "the registry answered {} for the cache's manifest",
            resp.status()
        );
    }
    Ok(())
}

enum Body<'a> {
    Bytes(Vec<u8>),
    File(&'a Path),
}

/// Upload a blob unless the registry has it already: an unchanged cache costs a probe.
async fn put_blob(store: &Store, digest: &str, body: Body<'_>) -> Result<()> {
    let probe = store
        .req(
            reqwest::Method::HEAD,
            &format!("{}/blobs/{digest}", store.base),
        )
        .send()
        .await
        .context("probing the registry for the cache")?;
    if probe.status().is_success() {
        return Ok(());
    }
    let resp = store
        .req(
            reqwest::Method::POST,
            &format!("{}/blobs/uploads/", store.base),
        )
        .header(reqwest::header::CONTENT_LENGTH, "0")
        .send()
        .await
        .context("starting the cache's upload")?;
    if resp.status() != reqwest::StatusCode::ACCEPTED {
        bail!(
            "the registry answered {} to the cache's upload",
            resp.status()
        );
    }
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .context("the registry gave the upload no Location")?;
    let location = match location.starts_with('/') {
        true => format!("{}{location}", store.origin()),
        false => location.to_string(),
    };
    let req = store
        .req(reqwest::Method::PUT, &location)
        .query(&[("digest", digest)])
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream");
    let req = match body {
        Body::Bytes(b) => req.body(b),
        Body::File(path) => {
            let file = tokio::fs::File::open(path)
                .await
                .with_context(|| format!("opening {}", path.display()))?;
            let len = file.metadata().await?.len();
            req.header(reqwest::header::CONTENT_LENGTH, len.to_string())
                .body(reqwest::Body::wrap_stream(
                    tokio_util::io::ReaderStream::new(file),
                ))
        }
    };
    let resp = req.send().await.context("uploading the cache")?;
    if resp.status() != reqwest::StatusCode::CREATED {
        bail!(
            "the registry answered {} to the cache's layer",
            resp.status()
        );
    }
    Ok(())
}

/// The cache's manifest: an OCI artifact with the empty config and one layer.
pub fn manifest(digest: &str, size: u64, key: &str) -> Vec<u8> {
    let m = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": ARTIFACT_TYPE,
        "config": {"mediaType": EMPTY_MEDIA_TYPE, "digest": EMPTY_DIGEST, "size": 2},
        "layers": [{"mediaType": LAYER_MEDIA_TYPE, "digest": digest, "size": size}],
        "annotations": {"dev.virtkit.ci-cache.key": key},
    });
    m.to_string().into_bytes()
}

/// The digest and size of a cache manifest's one layer, checked.
pub fn layer_of(manifest: &[u8]) -> Result<(String, u64)> {
    #[derive(serde::Deserialize)]
    struct Layer {
        #[serde(rename = "mediaType")]
        media_type: String,
        digest: String,
        size: u64,
    }
    #[derive(serde::Deserialize)]
    struct Manifest {
        layers: Vec<Layer>,
    }
    let m: Manifest = serde_json::from_slice(manifest).context("reading the cache's manifest")?;
    let [layer] = m.layers.as_slice() else {
        bail!("the cache's manifest does not have one layer");
    };
    let hex = layer.digest.strip_prefix("sha256:").unwrap_or_default();
    if layer.media_type != LAYER_MEDIA_TYPE
        || hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("the cache's manifest names no cache layer");
    }
    Ok((layer.digest.clone(), layer.size))
}

async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len().saturating_add(chunk.len()) > max {
            bail!("the registry's answer is larger than {max} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Compress `input` into `to`, returning the compressed bytes' digest and size.
fn zstd_hashed(input: &mut dyn Read, to: &Path) -> Result<(String, u64)> {
    struct Hashing<W> {
        inner: W,
        hasher: Sha256,
        size: u64,
    }
    impl<W: Write> Write for Hashing<W> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            let written = buf.get(..n).unwrap_or(buf);
            self.hasher.update(written);
            self.size = self.size.saturating_add(written.len() as u64);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    let out = Hashing {
        inner: Capped::new(std::io::BufWriter::new(create(to)?), MAX_STAGED),
        hasher: Sha256::new(),
        size: 0,
    };
    let mut enc = zstd::stream::write::Encoder::new(out, 3)?;
    std::io::copy(input, &mut enc).context("compressing the cache")?;
    let mut out = enc.finish()?;
    out.flush()?;
    Ok((format!("sha256:{}", hex(&out.hasher.finalize())), out.size))
}

/// Decompress `from` onto `out`.
fn unzstd(from: &Path, out: &mut dyn Write) -> Result<()> {
    let input = std::fs::File::open(from).with_context(|| format!("opening {}", from.display()))?;
    let mut dec = zstd::stream::read::Decoder::new(input)?;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = dec.read(&mut buf).context("decompressing the cache")?;
        if n == 0 {
            break;
        }
        out.write_all(buf.get(..n).unwrap_or_default())?;
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::jobs::testkit::{Fixture, answer, gitlab};
    use vk_hub_proto::job::When;

    fn cache(policy: CachePolicy, when: When) -> CacheSpec {
        CacheSpec {
            key: "deps-main".into(),
            fallback_keys: vec!["deps-default".into()],
            untracked: false,
            paths: vec!["target/".into()],
            policy,
            when,
        }
    }

    #[test]
    fn a_cache_is_tagged_by_key_and_protection() {
        let p = tag("deps-main", true);
        assert_eq!(p.len(), 64);
        assert_ne!(p, tag("deps-main", false));
        assert_ne!(p, tag("deps-main2", true));
        // What `printf 'deps-main\nprotected' | sha256sum` prints.
        assert_eq!(p, hex(&Sha256::digest(b"deps-main\nprotected")));
    }

    #[test]
    fn the_repository_is_named_after_gitlab_and_the_project() {
        assert_eq!(
            repository("https://GitLab.Example.com", 12).unwrap(),
            "ci-cache/gitlab.example.com/12"
        );
        assert_eq!(
            repository("https://gitlab.example.com:8443/gitlab/", 7).unwrap(),
            "ci-cache/gitlab.example.com-8443/gitlab/7"
        );
        assert_eq!(
            repository("https://gl.example/Team/gitlab?x=1", 3).unwrap(),
            "ci-cache/gl.example/team/gitlab/3"
        );
        assert!(repository("https://gl.example/a..b", 1).is_err());
        assert!(repository("https://", 1).is_err());
        assert!(repository("https://bad_host", 1).is_err());
    }

    #[test]
    fn restore_follows_policy_and_fallbacks() {
        let mut w = Vec::new();
        let pull_push = cache(CachePolicy::PullPush, When::OnSuccess);
        assert_eq!(
            plan_restore(&pull_push, "j", "main", "", &mut w),
            Restore::Keys(vec!["deps-main".into(), "deps-default".into()])
        );
        let push = cache(CachePolicy::Push, When::OnSuccess);
        assert_eq!(
            plan_restore(&push, "j", "main", "", &mut w),
            Restore::NotByPolicy("deps-main".into())
        );
        let pull = cache(CachePolicy::Pull, When::OnSuccess);
        assert_eq!(
            plan_restore(&pull, "j", "main", "fb", &mut w),
            Restore::Keys(vec!["deps-main".into(), "deps-default".into(), "fb".into()])
        );
        assert!(w.is_empty());
        plan_restore(&pull, "j", "main", "x-protected", &mut w);
        assert_eq!(w.len(), 1);
        let mut nothing = pull.clone();
        nothing.paths.clear();
        assert_eq!(
            plan_restore(&nothing, "j", "main", "", &mut w),
            Restore::Skip
        );
        let mut unkeyed = pull;
        unkeyed.key.clear();
        unkeyed.fallback_keys.clear();
        assert_eq!(
            plan_restore(&unkeyed, "test", "main", "", &mut w),
            Restore::Keys(vec!["test/main".into()])
        );
    }

    #[test]
    fn save_follows_when_and_policy() {
        let on_success = cache(CachePolicy::PullPush, When::OnSuccess);
        assert_eq!(
            plan_save(&on_success, true, "j", "m"),
            Save::Key("deps-main".into())
        );
        assert_eq!(plan_save(&on_success, false, "j", "m"), Save::Skip);
        assert_eq!(
            plan_save(&cache(CachePolicy::Push, When::Always), false, "j", "m"),
            Save::Key("deps-main".into())
        );
        assert_eq!(
            plan_save(&cache(CachePolicy::Pull, When::OnFailure), false, "j", "m"),
            Save::NotByPolicy("deps-main".into())
        );
    }

    #[test]
    fn a_manifest_reads_back_its_layer() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let m = manifest(&digest, 42, "k");
        assert_eq!(layer_of(&m).unwrap(), (digest, 42));
        assert!(layer_of(br#"{"layers":[]}"#).is_err());
        let foreign = br#"{"layers":[{"mediaType":"x","digest":"sha256:00","size":1}]}"#;
        assert!(layer_of(foreign).is_err());
    }

    fn test_store(url: &str) -> Store {
        Store {
            http: reqwest::Client::new(),
            cred: crate::registry::Cred::None,
            base: format!("{url}/v2/ci-cache/h/1"),
        }
    }

    #[tokio::test]
    async fn a_blob_goes_where_a_relative_location_says() {
        let (url, seen) = gitlab(vec![
            answer("404 Not Found", &[], b""),
            answer(
                "202 Accepted",
                &[("Location", "/v2/ci-cache/h/1/blobs/uploads/u1?_state=s")],
                b"",
            ),
            answer("201 Created", &[], b""),
        ])
        .await;
        let _f = Fixture::new("cache-put", "https://gitlab.example");
        put_blob(&test_store(&url), EMPTY_DIGEST, Body::Bytes(b"{}".to_vec()))
            .await
            .unwrap();
        let reqs = seen.lock().unwrap().clone();
        assert_eq!(
            reqs[0].line,
            format!("HEAD /v2/ci-cache/h/1/blobs/{EMPTY_DIGEST} HTTP/1.1")
        );
        assert_eq!(
            reqs[1].line,
            "POST /v2/ci-cache/h/1/blobs/uploads/ HTTP/1.1"
        );
        let hex = EMPTY_DIGEST.strip_prefix("sha256:").unwrap();
        assert_eq!(
            reqs[2].line,
            format!(
                "PUT /v2/ci-cache/h/1/blobs/uploads/u1?_state=s&digest=sha256%3A{hex} HTTP/1.1"
            )
        );
        assert_eq!(reqs[2].body, b"{}");
    }

    /// The manifest of a layer `digest` of `size` bytes, then the layer `blob`.
    async fn registry_with(digest: &str, size: u64, blob: &[u8]) -> String {
        let (url, _) = gitlab(vec![
            answer("200 OK", &[], &manifest(digest, size, "k")),
            answer("200 OK", &[], blob),
        ])
        .await;
        url
    }

    #[tokio::test]
    async fn a_layer_that_is_not_what_its_manifest_says_is_refused() {
        let f = Fixture::new("cache-digest", "https://gitlab.example");
        let blob = b"some layer";
        let wrong = format!("sha256:{}", "ab".repeat(32));
        let url = registry_with(&wrong, blob.len() as u64, blob).await;
        let err = fetch(&f.ctx(), &test_store(&url), "t").await.unwrap_err();
        assert!(
            err.to_string().contains("does not match its digest"),
            "{err}"
        );
        assert!(!f.dir.join("cache.tar.zst").exists());

        let right = format!("sha256:{}", hex(&Sha256::digest(blob)));
        let url = registry_with(&right, 4, blob).await;
        let err = fetch(&f.ctx(), &test_store(&url), "t").await.unwrap_err();
        assert!(err.to_string().contains("larger than the 4 bytes"), "{err}");

        let url = registry_with(&right, MAX_STAGED + 1, blob).await;
        let err = fetch(&f.ctx(), &test_store(&url), "t").await.unwrap_err();
        assert!(err.to_string().contains("MiB a job may stage"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_cache_is_a_warning() {
        let (url, seen) = gitlab(vec![answer("404 Not Found", &[], b"")]).await;
        let mut f = Fixture::new("cache-missing", "https://gitlab.example");
        let host = url.strip_prefix("http://").unwrap();
        f.cfg.registry =
            Some(toml::from_str(&format!("repo = \"{host}/vk\"\ninsecure = true")).unwrap());
        f.job.job.project_id = 12;
        let mut c = cache(CachePolicy::PullPush, When::OnSuccess);
        c.fallback_keys.clear();
        f.job.caches = vec![c];
        restore(&f.ctx()).await.unwrap();
        let reqs = seen.lock().unwrap().clone();
        assert!(
            reqs[0]
                .line
                .starts_with("GET /v2/vk/ci-cache/gitlab.example/12/manifests/"),
            "{}",
            reqs[0].line
        );
        let out = f.output();
        assert!(out.contains("No cache found for deps-main"), "{out}");
        assert!(out.contains("Failed to extract cache"), "{out}");
    }

    #[test]
    fn the_request_timeout_is_read_in_minutes() {
        assert_eq!(request_timeout(""), Duration::from_secs(600));
        assert_eq!(request_timeout("0"), Duration::from_secs(600));
        assert_eq!(request_timeout(" 2 "), Duration::from_secs(120));
    }

    #[test]
    fn compression_round_trips_with_its_digest() {
        let dir = std::env::temp_dir().join(format!("vk-cache-zstd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&a, b"some tar bytes".repeat(1000)).unwrap();
        let (digest, size) = zstd_hashed(&mut std::fs::File::open(&a).unwrap(), &b).unwrap();
        let packed = std::fs::read(&b).unwrap();
        assert_eq!(size, packed.len() as u64);
        assert_eq!(digest, format!("sha256:{}", hex(&Sha256::digest(&packed))));
        let mut out = Vec::new();
        unzstd(&b, &mut out).unwrap();
        assert_eq!(out, std::fs::read(&a).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
