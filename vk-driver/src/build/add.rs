//! `ADD` downloads HTTP(S) sources and unpacks local tar archives by default, as in BuildKit.
//!
//! When keying the step, the host caches each download by digest. If a local source pattern
//! matches an archive to unpack, it caches every regular file in that match. Other local
//! sources use the normal `COPY` path, even alongside staged sources.
//!
//! On first use, the host turns those cached bytes into a named build context for the guest.
//! Downloads and plain files are copied as files. Each unpacked archive becomes a directory
//! whose contents merge into the destination. Even `FROM scratch` needs no `tar` binary.
//!
//! Downloads and redirects must pass every egress allowlist enforced by the stage's switch.
//! `--build-net none` disables network access. Loopback, link-local and other unroutable
//! destinations are always blocked.
//!
//! As in other build contexts, unpacked entries belong to root unless `--chown` overrides
//! ownership. The image preserves neither archive timestamps nor download timestamps. Builds
//! fetch unpinned URLs again when they key the step.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use super::parser::{Copy, StageEgress, is_url};
use super::{BuildNet, hex};
use crate::switch::{Cap, Egress};

/// Staging names take precedence over stages, named contexts and images. The prefix must
/// work in guest mountpoints and host filenames without spaces.
const STAGED_PREFIX: &str = "vk-add+";

/// The most redirects a download follows, each checked against the egress policy.
const MAX_REDIRECTS: usize = 10;

/// The egress policy and downloads shared by the stages of one build plan. Reusing a
/// download keeps its bytes stable within the plan. A new plan can see updated URLs.
#[derive(Debug, Clone)]
pub struct Fetch {
    net: BuildNet,
    /// The hub's build-phase layer a placed job's stage switch also enforces.
    hub: Option<crate::switch::HubLayer>,
    /// A placed job's private cache prevents reuse of another job's bytes by digest.
    /// `None` selects the user's cache ([`default_cache_dir`]).
    cache: Option<PathBuf>,
    /// Cache local inputs when keying a build. [`Fetch::offline`] only hashes them.
    keeps: bool,
    /// Download digest and redirect chain by URL. Each stage rechecks the hosts before reuse.
    downloads: Arc<Mutex<BTreeMap<String, Downloaded>>>,
}

/// A download's digest and redirect chain, including the original URL.
type Downloaded = (String, Vec<String>);

impl Default for Fetch {
    /// The default network policy for `vk build` and `docker-hash`. Image freshness checks
    /// use [`Fetch::offline`].
    fn default() -> Self {
        Self::new(BuildNet::All, None)
    }
}

impl Fetch {
    pub(crate) fn new(net: BuildNet, hub: Option<crate::switch::HubLayer>) -> Self {
        Fetch {
            net,
            hub,
            cache: None,
            keeps: true,
            downloads: Arc::default(),
        }
    }

    /// Apply the build network policy. A placed job also uses its hub rules and record-local cache.
    pub(crate) fn for_build(net: BuildNet, record: Option<&super::EgressRecord>) -> Self {
        let mut f = Self::new(net, record.and_then(|r| r.hub.clone()));
        f.cache = record.map(|r| r.dir.join("add-cache"));
        f
    }

    /// Resolve the cache path without creating it. Only writers create the directory.
    fn cache(&self) -> Result<PathBuf> {
        match &self.cache {
            Some(d) => Ok(d.clone()),
            None => default_cache_dir(),
        }
    }

    /// Image freshness checks hash local inputs without caching them. Only URLs with a
    /// verified checksum already in the cache can be keyed offline.
    pub(crate) fn offline() -> Self {
        let mut f = Self::new(BuildNet::None, None);
        f.keeps = false;
        f
    }

    /// A download must pass every layer enforced by the stage's switch. `None` disables networking.
    fn layers(&self, declared: Option<&StageEgress>) -> Result<Option<Vec<Egress>>> {
        if self.net == BuildNet::None {
            return Ok(None);
        }
        let of = |cap: &Cap| match cap {
            Cap::Unrestricted => Ok(Egress::AllowAll),
            Cap::Allow { ips, names } => Egress::restricted(ips, names),
        };
        let mut layers = Vec::new();
        let (ips, names, restrict) = self.net.switch_policy();
        if restrict {
            layers.push(Egress::restricted(ips, names)?);
        }
        if let Some(cap) = self.net.cap() {
            layers.push(of(cap)?);
        }
        if let Some(cap) = self.net.declared(declared) {
            layers.push(of(&cap)?);
        }
        if let Some(enforce) = self.hub.as_ref().and_then(|h| h.enforce.as_ref()) {
            layers.push(Egress::restricted(&enforce.ips, &enforce.names)?);
        }
        Ok(Some(layers))
    }
}

/// One ADD source, classified when the step is keyed.
#[derive(Debug, Clone, PartialEq)]
enum Source {
    /// Context sources with no archive to unpack follow the normal `COPY` path.
    Local,
    /// Stage the downloaded file as `name`, or unpack it if it is an archive and `--unpack=true`.
    Url {
        name: String,
        digest: String,
        unpack: bool,
    },
    /// Files matched by one context source, including at least one archive to unpack.
    Matches(Vec<Match>),
}

/// A context file an ADD source matched, its bytes cached by digest.
#[derive(Debug, Clone, PartialEq)]
struct Match {
    name: String,
    digest: String,
    mode: u32,
    archive: bool,
}

/// How to copy a run of sources from [`batches`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Batch {
    /// From the build context, as a COPY.
    Context,
    /// Files from the staging context.
    Staged,
    /// Unpacked entries keep their archive modes even with `--chmod`, as in BuildKit.
    Unpacked,
}

/// Staged sources indexed by their position in the `ADD` instruction.
#[derive(Debug)]
struct Recipe {
    cache: PathBuf,
    sources: Vec<(usize, Source)>,
}

/// Process-wide staging contexts indexed by content-derived name. A name always identifies
/// the same recipe.
static STAGED: Mutex<BTreeMap<String, Staged>> = Mutex::new(BTreeMap::new());

/// Recipe and directory, once materialized.
type Staged = (Arc<Recipe>, Option<PathBuf>);

/// Serialize materialization per context so concurrent stages share one build.
static BUILDING: Mutex<BTreeMap<String, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

/// Distinguish temporary paths created concurrently by this process.
static TEMP: AtomicU64 = AtomicU64::new(0);

pub(crate) fn is_staged(name: &str) -> bool {
    name.starts_with(STAGED_PREFIX)
}

/// Key expanded sources under the stage's declared egress policy. Record the staging
/// context on `c` when downloads or archive matches need one. `local_hash` keys ordinary
/// context sources as `COPY` does. Return `None` when all sources follow the `COPY` path.
pub(crate) fn key(
    fetch: &Fetch,
    declared: Option<&StageEgress>,
    context: &Path,
    c: &mut Copy,
    local_hash: impl Fn(&[String]) -> String,
) -> Result<Option<String>> {
    let Some(add) = &c.add else {
        return Ok(None);
    };
    super::parser::check_add_sources(&c.sources, add.checksum.as_deref())?;
    let ign = vk_core::dockerignore::Ignore::load(context);
    let mut sources = Vec::new();
    for src in &c.sources {
        let source = if is_url(src) {
            let digest = download(fetch, declared, src, add.checksum.as_deref())?;
            let unpack = add.unpack == Some(true)
                && archive_codec(&cached(&fetch.cache()?, &digest))?.is_some();
            Source::Url {
                name: url_file_name(src),
                digest,
                unpack,
            }
        } else {
            classify(fetch, context, &ign, src, add.unpack.unwrap_or(true))?
        };
        sources.push(source);
    }
    if sources.iter().all(|s| *s == Source::Local) {
        return Ok(None);
    }
    let mut key = String::new();
    let mut staged = String::new();
    for (i, (src, source)) in c.sources.iter().zip(&sources).enumerate() {
        let line = match source {
            Source::Local => {
                key.push_str(&format!(
                    "local {}\n",
                    local_hash(std::slice::from_ref(src))
                ));
                continue;
            }
            Source::Url {
                name,
                digest,
                unpack,
            } => format!("{i} url {src} {name} {digest} unpack={unpack}\n"),
            Source::Matches(matches) => matches
                .iter()
                .map(|m| {
                    format!(
                        "{i} file {} {} {:o} archive={}\n",
                        m.name, m.digest, m.mode, m.archive
                    )
                })
                .collect(),
        };
        key.push_str(&line);
        staged.push_str(&line);
    }
    // Only staged sources affect the staging name, so edits to other context inputs reuse it.
    // Include the layout version and cache path to separate incompatible layouts and job caches.
    let cache = fetch.cache()?;
    let name = format!(
        "{STAGED_PREFIX}{}",
        hex(&Sha256::digest(
            format!("layout 1\n{}\n{staged}", cache.display()).as_bytes()
        ))
    );
    let recipe = Recipe {
        cache,
        sources: sources
            .into_iter()
            .enumerate()
            .filter(|(_, s)| *s != Source::Local)
            .collect(),
    };
    STAGED
        .lock()
        .unwrap()
        .entry(name.clone())
        .or_insert((Arc::new(recipe), None));
    if let Some(add) = &mut c.add {
        add.staged = Some(name);
    }
    Ok(Some(key))
}

/// Apply wildcard and `.dockerignore` rules. If the source matches an archive to unpack,
/// record all matched files by digest. Otherwise leave the source for `COPY`.
fn classify(
    fetch: &Fetch,
    context: &Path,
    ign: &vk_core::dockerignore::Ignore,
    src: &str,
    unpack: bool,
) -> Result<Source> {
    if !unpack {
        return Ok(Source::Local);
    }
    let matched = matches(context, ign, src);
    let mut archives = false;
    let mut files = Vec::new();
    for path in &matched {
        let is_file = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file());
        if !is_file {
            // Leave these entries to `COPY` unless the same source also matches an archive.
            files.push(None);
            continue;
        }
        let archive = archive_codec(path)?.is_some();
        archives |= archive;
        files.push(Some((path, archive)));
    }
    if !archives {
        return Ok(Source::Local);
    }
    let mut out = Vec::new();
    for file in files {
        let Some((path, archive)) = file else {
            bail!(
                "ADD {src}: it matches directories or symlinks as well as archives, which vk \
                 does not unpack together; give the archives a source of their own"
            );
        };
        let (digest, mode) = store(fetch, path)?;
        out.push(Match {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            digest,
            mode,
            archive,
        });
    }
    Ok(Source::Matches(out))
}

/// Match a literal path or a wildcard in the last component. Enforce the context boundary
/// and `.dockerignore`.
fn matches(context: &Path, ign: &vk_core::dockerignore::Ignore, src: &str) -> Vec<PathBuf> {
    let rel = super::beneath_context(src);
    let start = context.join(&rel);
    let candidates = if std::fs::symlink_metadata(&start).is_ok() {
        vec![start]
    } else {
        let rel = rel.to_string_lossy().into_owned();
        let (dir, pat) = match rel.rsplit_once('/') {
            Some((d, p)) => (context.join(d), p.to_string()),
            None => (context.to_path_buf(), rel),
        };
        let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| super::glob_seg(&pat, n))
                    })
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found
    };
    let root = context.canonicalize().ok();
    let within = |p: &Path| match (&root, p.canonicalize()) {
        (Some(root), Ok(c)) => c.starts_with(root),
        _ => false,
    };
    candidates
        .into_iter()
        // Check a symlink's parent. The link itself can point outside the context.
        .filter(|p| {
            if std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
                p.parent().is_some_and(within)
            } else {
                within(p)
            }
        })
        .filter(|p| !ign.included_entries(p, false).is_empty())
        .collect()
}

/// Use the last segment of the decoded URL path, ignoring trailing slashes, or `__unnamed__`.
fn url_file_name(url: &str) -> String {
    let path = reqwest::Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    let decoded = percent_decode(&path);
    match decoded.trim_end_matches('/').rsplit('/').next() {
        Some(last) if !last.is_empty() && last != "." => last.to_string(),
        _ => "__unnamed__".into(),
    }
}

/// Decode `%XX` escapes, keeping the original path if the result is invalid UTF-8.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex_at = |j: usize| b.get(j).and_then(|c| (*c as char).to_digit(16));
        match (b[i], hex_at(i + 1), hex_at(i + 2)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Process-wide so worker threads use the test cache too.
#[cfg(test)]
static TEST_CACHE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Seed the URL and digest to simulate a completed download without a loopback server.
#[cfg(test)]
pub(super) fn seed_download(fetch: &Fetch, url: &str, body: &[u8]) {
    let digest = keep(&fetch.cache().unwrap(), |w| Ok(w.write_all(body)?)).unwrap();
    fetch
        .downloads
        .lock()
        .unwrap()
        .insert(url.into(), (digest, vec![url.into()]));
}

/// All callers share the first test cache for the lifetime of the process.
#[cfg(test)]
pub(super) fn use_test_cache() -> PathBuf {
    TEST_CACHE
        .lock()
        .unwrap()
        .get_or_insert_with(|| {
            std::env::temp_dir().join(format!("vk-add-cache-{}", std::process::id()))
        })
        .clone()
}

/// Under [`crate::run::default_scratch_base`], `add/<sha256>` holds cached bytes and
/// `add/staged/<digest>` holds staging directories. The user cache has no eviction.
fn default_cache_dir() -> Result<PathBuf> {
    #[cfg(test)]
    let dir = use_test_cache();
    #[cfg(not(test))]
    let dir = crate::run::default_scratch_base()?.join("add");
    Ok(dir)
}

fn cached(cache: &Path, digest: &str) -> PathBuf {
    cache.join(digest)
}

/// Use a PID and process-local counter to distinguish concurrent writers.
fn temp_path(dir: &Path) -> PathBuf {
    dir.join(format!(
        ".part-{}-{}",
        std::process::id(),
        TEMP.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Publish the temporary file under its SHA-256 only after the write completes.
struct Keeper {
    dir: PathBuf,
    tmp: PathBuf,
    file: std::fs::File,
    hash: Sha256,
}

impl Keeper {
    fn new(cache: &Path) -> Result<Self> {
        let dir = cache.to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let tmp = temp_path(&dir);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        Ok(Keeper {
            dir,
            tmp,
            file,
            hash: Sha256::new(),
        })
    }

    /// Publish the file and return its digest.
    fn finish(mut self) -> Result<String> {
        self.file.sync_all().context("writing it")?;
        let digest = hex(&std::mem::take(&mut self.hash).finalize());
        std::fs::rename(&self.tmp, self.dir.join(&digest)).context("keeping it in the cache")?;
        Ok(digest)
    }
}

impl Write for Keeper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Drop for Keeper {
    /// After publication the temporary name is gone. A failed cleanup only wastes space.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// Cache the bytes written by `fill` and return their digest.
fn keep(cache: &Path, fill: impl FnOnce(&mut Keeper) -> Result<()>) -> Result<String> {
    let mut k = Keeper::new(cache)?;
    fill(&mut k)?;
    k.finish()
}

/// Return the file's digest and mode. Offline checks only hash the file. On a cache miss,
/// hash again while copying so a concurrent edit cannot mislabel the cached bytes.
fn store(fetch: &Fetch, path: &Path) -> Result<(String, u32)> {
    use std::os::unix::fs::MetadataExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .mode()
        & 0o7777;
    let digest = sha256_of(path)?;
    if !fetch.keeps {
        return Ok((digest, mode));
    }
    let cache = fetch.cache()?;
    if cached(&cache, &digest).is_file() {
        return Ok((digest, mode));
    }
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let digest = keep(&cache, |w| {
        std::io::copy(&mut f, w).with_context(|| format!("reading {}", path.display()))?;
        Ok(())
    })?;
    Ok((digest, mode))
}

/// Validate `sha256:<64 hex digits>` and return the lowercase hex digest.
fn checksum_hex(checksum: &str) -> Result<String> {
    match checksum.strip_prefix("sha256:") {
        Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(h.to_ascii_lowercase())
        }
        _ => bail!("ADD --checksum={checksum}: vk takes sha256:<64 hex digits> only"),
    }
}

fn sha256_of(path: &Path) -> Result<String> {
    let digest = super::sha256_file(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex(&digest))
}

/// Reuse the plan's download for `url`. With `--checksum`, verify a cached copy before
/// using it offline and reject a download whose digest differs.
fn download(
    fetch: &Fetch,
    declared: Option<&StageEgress>,
    url: &str,
    checksum: Option<&str>,
) -> Result<String> {
    let want = checksum.map(checksum_hex).transpose()?;
    let cache = fetch.cache()?;
    if let Some(want) = &want
        && let path = cached(&cache, want)
        && path.is_file()
        && sha256_of(&path).is_ok_and(|d| d == *want)
    {
        return Ok(want.clone());
    }
    let Some(layers) = fetch.layers(declared)? else {
        bail!(
            "ADD {url}: this build has no network (--build-net none); pin the file with \
             --checksum once it is in the cache, or allow the build network"
        );
    };
    // Held to this stage's policy even when another stage of the build fetched it already.
    let parsed = reqwest::Url::parse(url).with_context(|| format!("ADD {url}: parsing it"))?;
    host_allowed(&parsed, &layers).with_context(|| format!("ADD {url}"))?;
    let known = fetch.downloads.lock().unwrap().get(url).cloned();
    let digest = match known {
        Some((d, hops)) => {
            // Recheck every redirect against the stage reusing the download.
            for hop in &hops {
                let hop = reqwest::Url::parse(hop).context("a redirect it followed")?;
                host_allowed(&hop, &layers).with_context(|| format!("ADD {url}: via {hop}"))?;
            }
            d
        }
        None => {
            let (d, hops) = crate::blockrt::block_on(get(url, &layers, false, &cache))
                .with_context(|| format!("ADD {url}"))?;
            fetch
                .downloads
                .lock()
                .unwrap()
                .insert(url.to_string(), (d.clone(), hops));
            d
        }
    };
    if let Some(want) = want
        && want != digest
    {
        bail!("ADD {url}: its sha256 is {digest}, not the --checksum's {want}");
    }
    Ok(digest)
}

/// Fetch `url` into `cache`, checking `layers` at each redirect. Return the digest and
/// visited URLs. Only tests enable `loopback` for their local server.
async fn get(
    url: &str,
    layers: &[Egress],
    loopback: bool,
    cache: &Path,
) -> Result<(String, Vec<String>)> {
    let mut url = reqwest::Url::parse(url).context("parsing the URL")?;
    let mut hops = Vec::new();
    for _ in 0..=MAX_REDIRECTS {
        if !matches!(url.scheme(), "http" | "https") {
            bail!("{url}: only http and https are fetched");
        }
        let (host, port) = host_allowed(&url, layers)?;
        hops.push(url.to_string());
        let addrs = routable_addrs(&host, port, loopback).await?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(120))
            // A proxy could resolve the name again. Use the same direct connection as the guest switch.
            .no_proxy()
            // Connect only to the addresses already checked.
            .resolve_to_addrs(&host, &addrs)
            .build()
            .context("building the HTTP client")?;
        let resp = client
            .get(url.clone())
            .send()
            .await
            .context("requesting it")?;
        if resp.status().is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .with_context(|| format!("{url}: a redirect without a location"))?;
            url = url.join(to).context("following its redirect")?;
            continue;
        }
        let mut resp = resp.error_for_status().context("downloading it")?;
        // `block_on` drives this download on a dedicated thread, so streaming writes can block here.
        let mut kept = Keeper::new(cache)?;
        while let Some(chunk) = resp.chunk().await.context("downloading it")? {
            kept.write_all(&chunk).context("writing it")?;
        }
        return Ok((kept.finish()?, hops));
    }
    bail!("more than {MAX_REDIRECTS} redirects")
}

/// Return the unbracketed host and port after every layer allows the name or literal
/// address. Check names before DNS so a rejected name never reaches the resolver.
fn host_allowed(url: &reqwest::Url, layers: &[Egress]) -> Result<(String, u16)> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("{url}: only http and https are fetched");
    }
    let host = url
        .host_str()
        .context("the URL names no host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url
        .port_or_known_default()
        .context("the URL names no port")?;
    let allowed = match host.parse::<IpAddr>() {
        Ok(ip) => layers.iter().all(|l| l.allows_ip(ip, port)),
        Err(_) => layers.iter().all(|l| l.allows_host(&host)),
    };
    if !allowed {
        bail!("{host}:{port} is not allowed by the build's egress policy");
    }
    Ok((host, port))
}

/// Return routable IPv4 addresses for `host` and `port`, as required by guest egress.
/// Only tests allow loopback to reach a local server.
async fn routable_addrs(host: &str, port: u16, loopback: bool) -> Result<Vec<SocketAddr>> {
    let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("resolving {host}"))?
            .map(|a| a.ip())
            .collect(),
    };
    let addrs: Vec<SocketAddr> = ips
        .into_iter()
        .filter(|ip| ip.is_ipv4())
        .filter(|ip| !crate::switch::unroutable_ip(*ip) || (loopback && ip.is_loopback()))
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if addrs.is_empty() {
        bail!("{host} has no routable IPv4 address (loopback and link-local are refused)");
    }
    Ok(addrs)
}

/// The compression of a tar archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Codec {
    Plain,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

/// Detect tar and its compression from the file contents. Other files follow `COPY` rules.
fn archive_codec(path: &Path) -> Result<Option<Codec>> {
    let mut magic = [0u8; 6];
    let n = read_up_to(
        &mut std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?,
        &mut magic,
    )?;
    let magic = &magic[..n];
    let codec = if magic.starts_with(&[0x1f, 0x8b]) {
        Codec::Gzip
    } else if magic.starts_with(b"BZh") {
        Codec::Bzip2
    } else if magic.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        Codec::Xz
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Codec::Zstd
    } else {
        Codec::Plain
    };
    // A valid first tar header distinguishes compressed archives from files such as gzipped
    // logs. An unreadable header leaves the file on the `COPY` path.
    let mut header = [0u8; 512];
    let filled = match decoder(path, codec) {
        Ok(mut r) => read_up_to(&mut r, &mut header).unwrap_or(0),
        Err(_) => 0,
    };
    Ok((filled == 512 && is_tar_header(&header)).then_some(codec))
}

/// Fill `buf` up to EOF and return the byte count.
fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}

/// The octal checksum can have spaces or NULs on either side. Sum the header with the
/// checksum field treated as spaces. An all-zero end block is not a header.
fn is_tar_header(h: &[u8; 512]) -> bool {
    let field = String::from_utf8_lossy(&h[148..156]);
    let Ok(stored) = u32::from_str_radix(field.trim_matches(|c| c == ' ' || c == '\0'), 8) else {
        return false;
    };
    let sum: u32 = h
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u32::from(*b)
            }
        })
        .sum();
    sum == stored && h.iter().any(|b| *b != 0)
}

/// The decompressed stream of `path`.
fn decoder(path: &Path, codec: Codec) -> Result<Box<dyn Read>> {
    let f = std::io::BufReader::new(
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?,
    );
    Ok(match codec {
        Codec::Plain => Box::new(f),
        Codec::Gzip => Box::new(flate2::read::MultiGzDecoder::new(f)),
        Codec::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(f)),
        Codec::Xz => Box::new(lzma_rust2::XzReader::new(f, true)),
        Codec::Zstd => Box::new(zstd::stream::read::Decoder::new(f).context("reading zstd")?),
    })
}

/// Extract within `dir` and preserve entry modes. Build contexts cannot carry device
/// nodes or FIFOs, so reject archives containing either.
fn unpack(path: &Path, dir: &Path) -> Result<()> {
    let codec = archive_codec(path)?.context("not an archive any more")?;
    let mut check = tar::Archive::new(decoder(path, codec)?);
    for entry in check.entries().context("reading the archive")? {
        let entry = entry.context("reading the archive")?;
        let kind = entry.header().entry_type();
        if kind.is_block_special() || kind.is_character_special() || kind.is_fifo() {
            bail!(
                "its entry {} is a device node or FIFO, which vk cannot put in an image",
                entry
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
        }
    }
    let mut archive = tar::Archive::new(decoder(path, codec)?);
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    archive.set_unpack_xattrs(false);
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    archive.unpack(dir).context("unpacking it")
}

/// Materialize the context on first use. Downloads go in `<i>/<name>`, matched files in
/// `<i>/<j>/<name>`. Archives unpack into the corresponding parent directory. Build in a
/// temporary directory and rename it into place so other builds can reuse a complete context.
pub(crate) fn materialize(name: &str) -> Result<PathBuf> {
    let lock = Arc::clone(
        BUILDING
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default(),
    );
    let _building = lock.lock().unwrap();
    let recipe = {
        let staged = STAGED.lock().unwrap();
        let (recipe, dir) = staged
            .get(name)
            .with_context(|| format!("internal: ADD staging context {name:?} was never keyed"))?;
        if let Some(dir) = dir {
            return Ok(dir.clone());
        }
        Arc::clone(recipe)
    };
    let root = recipe.cache.join("staged");
    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
    let dir = root.join(name.strip_prefix(STAGED_PREFIX).unwrap_or(name));
    if !dir.is_dir() {
        let part = temp_path(&root);
        let built = stage(&recipe, &part);
        if let Err(e) = built {
            // Best-effort: a leftover partial staging directory is only wasted space.
            let _ = std::fs::remove_dir_all(&part);
            return Err(e);
        }
        if std::fs::rename(&part, &dir).is_err() {
            // A concurrent publisher may have won. A leftover temporary directory only wastes space.
            let _ = std::fs::remove_dir_all(&part);
            if !dir.is_dir() {
                bail!(
                    "ADD: could not keep its staging directory {}",
                    dir.display()
                );
            }
        }
    }
    if let Some((_, d)) = STAGED.lock().unwrap().get_mut(name) {
        *d = Some(dir.clone());
    }
    Ok(dir)
}

fn stage(recipe: &Recipe, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for (i, src) in &recipe.sources {
        let at = dir.join(i.to_string());
        match src {
            Source::Url { digest, unpack, .. } if *unpack => {
                unpack_cached(&recipe.cache, digest, &at)?
            }
            Source::Url { name, digest, .. } => place(&recipe.cache, digest, &at, name, 0o600)?,
            Source::Matches(matches) => {
                for (j, m) in matches.iter().enumerate() {
                    let at = at.join(j.to_string());
                    if m.archive {
                        unpack_cached(&recipe.cache, &m.digest, &at)?;
                    } else {
                        place(&recipe.cache, &m.digest, &at, &m.name, m.mode)?;
                    }
                }
            }
            Source::Local => {}
        }
    }
    Ok(())
}

fn unpack_cached(cache: &Path, digest: &str, at: &Path) -> Result<()> {
    let path = cached(cache, digest);
    unpack(&path, at).with_context(|| format!("ADD: unpacking {}", path.display()))
}

/// Copy `digest` from the cache to `at/name`, requesting `mode` at creation.
fn place(cache: &Path, digest: &str, at: &Path, name: &str, mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(at).with_context(|| format!("creating {}", at.display()))?;
    let file = at.join(name);
    let mut src = std::fs::File::open(cached(cache, digest)).context("opening the cached file")?;
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&file)
        .with_context(|| format!("creating {}", file.display()))?;
    std::io::copy(&mut src, &mut dst).with_context(|| format!("staging {}", file.display()))?;
    // Restore any bits masked by the umask at creation.
    use std::os::unix::fs::PermissionsExt;
    dst.set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of {}", file.display()))
}

/// Group adjacent sources by copy mode, preserving source order. Staged batches use paths
/// relative to the staging context. Context batches use the original paths and `None`.
pub(crate) fn batches(c: &Copy) -> Vec<(Batch, Option<String>, Vec<String>)> {
    let staged = c.add.as_ref().and_then(|a| a.staged.clone());
    let recipe = staged
        .as_ref()
        .and_then(|name| STAGED.lock().unwrap().get(name).map(|(r, _)| Arc::clone(r)));
    let mut out: Vec<(Batch, Option<String>, Vec<String>)> = Vec::new();
    let mut push = |batch: Batch, path: String| {
        let from = (batch != Batch::Context).then(|| staged.clone()).flatten();
        match out.last_mut() {
            Some((b, _, paths)) if *b == batch => paths.push(path),
            _ => out.push((batch, from, vec![path])),
        }
    };
    for (i, src) in c.sources.iter().enumerate() {
        let source = recipe
            .as_ref()
            .and_then(|r| r.sources.iter().find(|(j, _)| *j == i))
            .map(|(_, s)| s);
        match source {
            None | Some(Source::Local) => push(Batch::Context, src.clone()),
            Some(Source::Url { unpack: true, .. }) => push(Batch::Unpacked, i.to_string()),
            Some(Source::Url { name, .. }) => push(Batch::Staged, format!("{i}/{name}")),
            Some(Source::Matches(matches)) => {
                for (j, m) in matches.iter().enumerate() {
                    if m.archive {
                        push(Batch::Unpacked, format!("{i}/{j}"));
                    } else {
                        push(Batch::Staged, format!("{i}/{j}/{}", m.name));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory for `tag`, under the test cache's parent.
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vk-add-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A tar of `files` (`(path, body)`), mode 0644.
    fn tar_of(files: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, path, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// Parse `src` (one ADD) after a `FROM`.
    fn parse_add(src: &str) -> Copy {
        let mut df = super::super::parser::parse(&format!("FROM x\n{src}\n")).unwrap();
        let super::super::parser::Instruction::Copy(c) = df.instructions.remove(1) else {
            unreachable!()
        };
        c
    }

    #[test]
    fn archives_are_found_by_content_in_every_codec() {
        let dir = tmp("codecs");
        let plain = tar_of(&[("a/b.txt", "hello")]);
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&plain).unwrap();
            e.finish().unwrap()
        };
        let bz = {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
            e.write_all(&plain).unwrap();
            e.finish().unwrap()
        };
        let xz = {
            let mut w =
                lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))
                    .unwrap();
            w.write_all(&plain).unwrap();
            w.finish().unwrap()
        };
        let zst = zstd::encode_all(&plain[..], 1).unwrap();
        for (name, bytes, codec) in [
            ("p.tar", plain.clone(), Codec::Plain),
            ("g.tgz", gz, Codec::Gzip),
            ("b.tar.bz2", bz, Codec::Bzip2),
            ("x.txz", xz, Codec::Xz),
            ("z.tar.zst", zst, Codec::Zstd),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(archive_codec(&path).unwrap(), Some(codec), "{name}");
            let out = dir.join(format!("out-{name}"));
            unpack(&path, &out).unwrap();
            assert_eq!(
                std::fs::read_to_string(out.join("a/b.txt")).unwrap(),
                "hello",
                "{name}"
            );
        }
        let log = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&[b'x'; 2000]).unwrap();
            e.finish().unwrap()
        };
        for (name, bytes) in [
            ("log.gz", log),
            ("t.txt", b"just text".to_vec()),
            ("e", vec![]),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(archive_codec(&path).unwrap(), None, "{name}");
        }
        // a checksum field padded with spaces on both sides, as older tars write it
        let mut h = [0u8; 512];
        h[..1].copy_from_slice(b"a");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum::<u32>() + 8 * 32;
        h[148..156].copy_from_slice(format!(" {sum:06o} ").as_bytes());
        assert!(is_tar_header(&h));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_archive_cannot_unpack_outside_its_directory_nor_hold_devices() {
        let dir = tmp("escape");
        let raw = |name: &[u8], kind: tar::EntryType, link: Option<&[u8]>| {
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_mode(0o644);
            h.set_entry_type(kind);
            // `append_data` refuses `..`: write the names into the header by hand.
            h.as_old_mut().name[..name.len()].copy_from_slice(name);
            if let Some(l) = link {
                h.as_old_mut().linkname[..l.len()].copy_from_slice(l);
            }
            h.set_cksum();
            h
        };
        let archive = |headers: &[tar::Header]| {
            let mut b = tar::Builder::new(Vec::new());
            for h in headers {
                b.append(h, &b""[..]).unwrap();
            }
            b.into_inner().unwrap()
        };
        let out = dir.join("out");
        for (tag, headers) in [
            (
                "dotdot",
                vec![raw(b"../escape", tar::EntryType::Regular, None)],
            ),
            (
                "symlink",
                vec![
                    raw(
                        b"l",
                        tar::EntryType::Symlink,
                        Some(dir.to_str().unwrap().as_bytes()),
                    ),
                    raw(b"l/escape", tar::EntryType::Regular, None),
                ],
            ),
            (
                "hardlink",
                vec![raw(b"h", tar::EntryType::Link, Some(b"/etc/passwd"))],
            ),
        ] {
            let path = dir.join(format!("{tag}.tar"));
            std::fs::write(&path, archive(&headers)).unwrap();
            let _ = unpack(&path, &out);
            assert!(!dir.join("escape").exists(), "{tag}");
            assert!(!out.join("h").exists() || tag != "hardlink", "{tag}");
        }
        let path = dir.join("dev.tar");
        std::fs::write(
            &path,
            archive(&[raw(b"dev/null", tar::EntryType::Char, None)]),
        )
        .unwrap();
        let err = format!("{:#}", unpack(&path, &out).unwrap_err());
        assert!(err.contains("device node"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_url_downloads_as_buildkit_names_it() {
        assert_eq!(url_file_name("https://x.org/a/b.tar.gz?x=1#f"), "b.tar.gz");
        assert_eq!(url_file_name("https://x.org/a/"), "a");
        assert_eq!(url_file_name("https://x.org/my%20file"), "my file");
        assert_eq!(url_file_name("https://x.org"), "__unnamed__");
    }

    #[test]
    fn a_checksum_is_a_sha256() {
        let h = "a".repeat(64);
        assert_eq!(checksum_hex(&format!("sha256:{h}")).unwrap(), h);
        assert!(checksum_hex("sha256:abc").is_err());
        let err = format!("{:#}", checksum_hex(&format!("sha512:{h}")).unwrap_err());
        assert!(err.contains("sha256"), "{err}");
    }

    /// Serve one raw HTTP response per connection in order. Return the loopback port.
    fn serve(responses: Vec<Vec<u8>>) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut s, _)) = listener.accept() else {
                    return;
                };
                let mut req = [0u8; 2048];
                let _ = s.read(&mut req);
                let _ = s.write_all(&response);
            }
        });
        port
    }

    fn ok(body: &[u8]) -> Vec<u8> {
        let mut r = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        r.extend_from_slice(body);
        r
    }

    fn test_cache() -> PathBuf {
        Fetch::default().cache().unwrap()
    }

    fn local() -> Fetch {
        Fetch::new(BuildNet::All, None)
    }

    /// Return the policy error for `url`, if any, before DNS lookup.
    fn refused(fetch: &Fetch, url: &str) -> Option<String> {
        let layers = fetch.layers(None).unwrap().unwrap();
        host_allowed(&reqwest::Url::parse(url).unwrap(), &layers)
            .err()
            .map(|e| format!("{e:#}"))
    }

    #[test]
    fn a_download_is_refused_where_the_guest_could_not_reach() {
        let none = Fetch::offline();
        let err = format!(
            "{:#}",
            download(&none, None, "http://x.org/f", None).unwrap_err()
        );
        assert!(err.contains("no network"), "{err}");
        // loopback, the metadata endpoint and IPv6, whatever the policy
        for host in ["127.0.0.1", "169.254.169.254", "::1", "2001:db8::1"] {
            let err = crate::blockrt::block_on(routable_addrs(host, 80, false)).unwrap_err();
            assert!(
                format!("{err:#}").contains("no routable IPv4"),
                "{host}: {err:#}"
            );
        }
        // an allowlist: a name only by name, an address only by its range
        let allow = Fetch::new(
            BuildNet::Allow {
                ips: vec!["10.0.0.0/8".into()],
                names: vec!["example.org".into()],
            },
            None,
        );
        assert!(
            refused(&allow, "http://1.1.1.1/f")
                .unwrap()
                .contains("not allowed")
        );
        assert_eq!(refused(&allow, "http://10.1.2.3/f"), None);
        assert_eq!(refused(&allow, "https://dl.example.org/f"), None);
        // refused before any lookup, so the name reaches no resolver
        assert!(refused(&allow, "https://leak.attacker.test/f").is_some());
        // a stage that declares nothing under --build-net declared has no egress at all
        let declared = Fetch::new(
            BuildNet::Declared {
                cap: Cap::Unrestricted,
            },
            None,
        );
        assert!(refused(&declared, "http://example.org/f").is_some());
        // the hub's layer holds a placed job's download as its stage switch would
        let hub = crate::switch::HubLayer {
            enforce: Some(crate::switch::HubList {
                ips: vec![],
                names: vec!["mirror.example".into()],
            }),
            dry_run: vec![],
        };
        let job = Fetch::new(
            BuildNet::Filtered {
                cap: Cap::Unrestricted,
                job: Cap::Unrestricted,
            },
            Some(hub),
        );
        assert!(refused(&job, "https://example.org/f").is_some());
        assert_eq!(refused(&job, "https://dl.mirror.example/f"), None);
        // the build's memo answers no stage its own policy refuses
        let shared = Fetch::new(
            BuildNet::Declared {
                cap: Cap::Unrestricted,
            },
            None,
        );
        seed_download(&shared, "http://example.org/f", b"x");
        assert!(download(&shared, None, "http://example.org/f", None).is_err());
        let declares = StageEgress {
            ips: vec![],
            names: vec!["example.org".into()],
        };
        assert!(download(&shared, Some(&declares), "http://example.org/f", None).is_ok());
    }

    #[test]
    fn a_download_another_stage_made_is_held_to_its_redirects() {
        let fetch = Fetch::new(
            BuildNet::Declared {
                cap: Cap::Unrestricted,
            },
            None,
        );
        let digest = keep(&test_cache(), |w| Ok(w.write_all(b"x")?)).unwrap();
        fetch.downloads.lock().unwrap().insert(
            "http://a.example/x".into(),
            (
                digest,
                vec!["http://a.example/x".into(), "http://b.example/x".into()],
            ),
        );
        let only_a = StageEgress {
            ips: vec![],
            names: vec!["a.example".into()],
        };
        let err = download(&fetch, Some(&only_a), "http://a.example/x", None).unwrap_err();
        assert!(format!("{err:#}").contains("b.example"), "{err:#}");
        let both = StageEgress {
            ips: vec![],
            names: vec!["a.example".into(), "b.example".into()],
        };
        assert!(download(&fetch, Some(&both), "http://a.example/x", None).is_ok());
    }

    #[test]
    fn a_job_keys_into_a_cache_of_its_own_and_a_look_writes_none() {
        let job = tmp("job-record");
        let record = super::super::EgressRecord {
            dir: job.clone(),
            source: None,
            hub: None,
        };
        let fetch = Fetch::for_build(BuildNet::All, Some(&record));
        assert_eq!(fetch.cache().unwrap(), job.join("add-cache"));
        // a digest another tenant's build cached is not this job's to take
        let digest = keep(&test_cache(), |w| Ok(w.write_all(b"theirs")?)).unwrap();
        let none = Fetch::for_build(BuildNet::None, Some(&record));
        let sum = format!("sha256:{digest}");
        assert!(download(&none, None, "http://x.org/y", Some(&sum)).is_err());
        // an offline look hashes the context's archives without copying them
        let context = tmp("look");
        let tar = tar_of(&[("f", "look")]);
        std::fs::write(context.join("t.tar"), &tar).unwrap();
        let mut c = parse_add("ADD t.tar /d/");
        assert!(
            key(&Fetch::offline(), None, &context, &mut c, |_| String::new())
                .unwrap()
                .is_some()
        );
        let digest = hex(&Sha256::digest(&tar));
        assert!(!cached(&test_cache(), &digest).exists());
        // nor makes a cache directory
        let mut look = Fetch::offline();
        look.cache = Some(job.join("never-made"));
        let mut c = parse_add("ADD t.tar /d/");
        key(&look, None, &context, &mut c, |_| String::new()).unwrap();
        assert!(!job.join("never-made").exists());
        let _ = std::fs::remove_dir_all(&job);
        let _ = std::fs::remove_dir_all(&context);
    }

    #[test]
    fn a_cached_checksum_needs_no_network_and_is_rehashed() {
        let digest = keep(&test_cache(), |w| Ok(w.write_all(b"pinned")?)).unwrap();
        let sum = format!("sha256:{digest}");
        let none = Fetch::offline();
        assert_eq!(
            download(&none, None, "http://x.org/p", Some(&sum)).unwrap(),
            digest
        );
        // a cached copy that no longer hashes to its name is not trusted
        let bad = "b".repeat(64);
        std::fs::write(cached(&test_cache(), &bad), b"tampered").unwrap();
        assert!(
            download(
                &none,
                None,
                "http://x.org/p",
                Some(&format!("sha256:{bad}"))
            )
            .is_err()
        );
    }

    #[test]
    fn a_download_is_kept_by_its_digest_and_staged_mode_0600() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = serve(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /files/tool.bin\r\nContent-Length: 0\r\n\
              Connection: close\r\n\r\n"
                .to_vec(),
            ok(b"payload"),
        ]);
        let layers = [Egress::AllowAll];
        let (digest, hops) = crate::blockrt::block_on(get(
            &format!("http://127.0.0.1:{port}/latest"),
            &layers,
            true,
            &test_cache(),
        ))
        .unwrap();
        assert_eq!(digest, hex(&Sha256::digest(b"payload")));
        assert_eq!(hops.len(), 2, "{hops:?}");
        let fetch = local();
        let url = format!("http://127.0.0.1:{port}/files/tool.bin");
        fetch
            .downloads
            .lock()
            .unwrap()
            .insert(url.clone(), (digest.clone(), vec![url.clone()]));
        let context = tmp("url-ctx");
        let mut c = parse_add(&format!("ADD {url} /opt/"));
        let keyed = key(&fetch, None, &context, &mut c, |_| unreachable!())
            .unwrap()
            .unwrap();
        assert!(keyed.contains(&digest), "{keyed}");
        let name = c.add.as_ref().unwrap().staged.clone().unwrap();
        assert_eq!(
            batches(&c),
            [(Batch::Staged, Some(name.clone()), vec!["0/tool.bin".into()])]
        );
        let dir = materialize(&name).unwrap();
        let file = dir.join("0/tool.bin");
        assert_eq!(std::fs::read(&file).unwrap(), b"payload");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // a checksum that does not match the bytes fails
        let wrong = format!("sha256:{}", "0".repeat(64));
        assert!(download(&fetch, None, &url, Some(&wrong)).is_err());
        let _ = std::fs::remove_dir_all(&context);
    }

    #[test]
    fn a_url_is_unpacked_only_when_asked() {
        let tar = tar_of(&[("x", "1")]);
        let digest = keep(&test_cache(), |w| Ok(w.write_all(&tar)?)).unwrap();
        let fetch = local();
        let url = "http://x.org/t.tar";
        fetch
            .downloads
            .lock()
            .unwrap()
            .insert(url.into(), (digest.clone(), vec![url.into()]));
        let context = tmp("url-unpack");
        let mut copied = parse_add(&format!("ADD {url} /d/"));
        let mut unpacked = parse_add(&format!("ADD --unpack=true {url} /d/"));
        let k1 = key(&fetch, None, &context, &mut copied, |_| unreachable!()).unwrap();
        let k2 = key(&fetch, None, &context, &mut unpacked, |_| unreachable!()).unwrap();
        assert_ne!(k1, k2);
        assert_eq!(batches(&copied)[0].0, Batch::Staged);
        assert_eq!(batches(&unpacked)[0].0, Batch::Unpacked);
        let name = unpacked.add.as_ref().unwrap().staged.clone().unwrap();
        let dir = materialize(&name).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("0/x")).unwrap(), "1");
        let _ = std::fs::remove_dir_all(&context);
    }

    #[test]
    fn local_sources_follow_dockerignore_wildcards_and_source_order() {
        let context = tmp("order");
        std::fs::write(context.join("a.txt"), "a").unwrap();
        std::fs::write(context.join("t1.tar"), tar_of(&[("x", "1")])).unwrap();
        std::fs::write(context.join("t2.tar"), tar_of(&[("y", "2")])).unwrap();
        std::fs::write(context.join("b.txt"), "b").unwrap();
        std::fs::write(context.join("hidden.tar"), tar_of(&[("z", "3")])).unwrap();
        std::fs::write(context.join(".dockerignore"), "hidden.tar\n").unwrap();
        let fetch = local();
        let hash = |s: &[String]| format!("h{}", s.join(","));
        let mut c = parse_add("ADD a.txt t*.tar b.txt /d/");
        assert!(key(&fetch, None, &context, &mut c, hash).unwrap().is_some());
        let name = c.add.as_ref().unwrap().staged.clone().unwrap();
        assert_eq!(
            batches(&c),
            [
                (Batch::Context, None, vec!["a.txt".to_string()]),
                (
                    Batch::Unpacked,
                    Some(name.clone()),
                    vec!["1/0".to_string(), "1/1".to_string()]
                ),
                (Batch::Context, None, vec!["b.txt".to_string()]),
            ]
        );
        let dir = materialize(&name).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("1/0/x")).unwrap(), "1");
        assert_eq!(std::fs::read_to_string(dir.join("1/1/y")).unwrap(), "2");
        // An ignored archive falls back to ordinary `COPY` handling.
        let mut ignored = parse_add("ADD hidden.tar /d/");
        assert_eq!(
            key(&fetch, None, &context, &mut ignored, hash).unwrap(),
            None
        );
        // --unpack=false, or no archive at all: a COPY
        let mut plain = parse_add("ADD --unpack=false t1.tar /d/");
        assert_eq!(key(&fetch, None, &context, &mut plain, hash).unwrap(), None);
        let mut files = parse_add("ADD a.txt b.txt /d/");
        assert_eq!(key(&fetch, None, &context, &mut files, hash).unwrap(), None);
        // the key follows an archive's bytes, which are fixed when keyed
        let mut again = parse_add("ADD t1.tar /d/");
        let before = key(&fetch, None, &context, &mut again, hash).unwrap();
        std::fs::write(context.join("t1.tar"), tar_of(&[("x", "changed")])).unwrap();
        let mut edited = parse_add("ADD t1.tar /d/");
        assert_ne!(
            before,
            key(&fetch, None, &context, &mut edited, hash).unwrap()
        );
        let dir = materialize(again.add.as_ref().unwrap().staged.as_ref().unwrap()).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("0/0/x")).unwrap(), "1");
        let _ = std::fs::remove_dir_all(&context);
    }

    #[test]
    fn concurrent_stages_build_one_staging_directory() {
        let context = tmp("concurrent");
        std::fs::write(context.join("t.tar"), tar_of(&[("f", "x")])).unwrap();
        let mut c = parse_add("ADD t.tar /d/");
        key(&local(), None, &context, &mut c, |_| String::new()).unwrap();
        let name = c.add.as_ref().unwrap().staged.clone().unwrap();
        let dirs: Vec<PathBuf> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| materialize(&name).unwrap()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(dirs.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(std::fs::read_to_string(dirs[0].join("0/0/f")).unwrap(), "x");
        let _ = std::fs::remove_dir_all(&context);
    }
}
