//! Native OCI bundle registry with content-defined chunk deduplication, backing the
//! `MICROVM_IMAGE: registry/<name>[:tag|@sha256:…]` form.
//!
//! A guest bundle (a `runner.ext4`, a `boot.kind`, and OPTIONALLY a `vmlinuz` +
//! `initrd.img`) is pushed/pulled to/from an OCI registry directly — no `oras`,
//! no docker. `runner.ext4` is split with content-defined chunking (FastCDC) and
//! each chunk is zstd-compressed and stored as its own blob, keyed by the sha256
//! of the COMPRESSED bytes. Identical raw chunks compress to identical bytes (a
//! fixed zstd level), so two bundles that share data share blobs: a `blob_exists`
//! check skips re-uploading them, and on pull a content-addressed local chunk
//! cache skips re-downloading them.
//!
//! Reassembly is sparse: chunks carry their offset (and length) as annotations, the
//! rootfs is created at its full size, each chunk is decompressed and written at its
//! offset, and an all-zero chunk is skipped so its region stays a hole — the ext4
//! sparse file is never densified.
//!
//! Same caching model as the `[convert]` path: digest-keyed bundle dir under
//! `state_dir`, the abstract-socket pull lock + mtime GC shared via image.rs, and
//! a `ResolvedImage` returned from the cached dir keyed on `boot.kind`.

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use oci_client::Reference as OciReference;
use oci_client::client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol};
use oci_client::manifest::{OCI_IMAGE_MEDIA_TYPE, OciDescriptor, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Config, Registry};
use crate::image::{self, Reference, ResolvedImage};
use crate::jobctx::JobCtx;

// CDC parameters for runner.ext4 (FastCDC v2020): min 1 MiB, avg 4 MiB, max 16 MiB.
const CDC_MIN: u32 = 1 << 20;
const CDC_AVG: u32 = 4 << 20;
const CDC_MAX: u32 = 16 << 20;
// Fixed zstd level: identical raw chunks must compress to identical bytes for the
// blob digest (sha256 of the compressed bytes) to dedup.
const ZSTD_LEVEL: i32 = 3;

// Media types for the bundle artifact.
const ARTIFACT_TYPE: &str = "application/vnd.wallix.microvm.bundle";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.bundle.config.v1+json";
const CHUNK_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.ext4.chunk.zstd";
const KERNEL_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.kernel";
const INITRD_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.initrd";

// Descriptor annotation keys carrying the placement of a chunk inside runner.ext4.
const ANN_OFFSET: &str = "vnd.wallix.microvm.chunk.offset";
const ANN_LENGTH: &str = "vnd.wallix.microvm.chunk.length";

/// The config blob (`CONFIG_MEDIA_TYPE`): just enough to reassemble the bundle and
/// pick a boot path without re-reading every layer's annotations.
#[derive(Serialize, Deserialize)]
struct BundleConfig {
    /// Uncompressed size of runner.ext4 (the file is created at this size, chunks
    /// written at their offsets, the rest left as holes).
    total_size: u64,
    chunk_count: usize,
    /// One of systemd|generic-disk|generic-cpio (the boot.kind string).
    boot_kind: String,
    compression: String,
    has_kernel: bool,
    has_initrd: bool,
}

/// Push a local bundle dir to `<registry.repo>/<name>:<tag>`. Returns the manifest
/// digest. `image_ref` must be a tag (a registry push needs a writable tag).
pub fn push(cfg: &Config, dir: &Path, image_ref: &str) -> Result<String> {
    let rg = cfg
        .registry
        .as_ref()
        .context("`registry push` needs a [registry] section in the config")?;
    let (name, reference) = image::parse_ref(image_ref)?;
    let tag = match reference {
        Reference::Tag(t) => t,
        Reference::Digest(_) => {
            bail!("`registry push` needs a :tag, not an @digest ({image_ref:?})")
        }
    };
    block_on(push_async(rg, dir, &name, &tag))
}

/// Pull+cache a registry bundle for a job, returning a `ResolvedImage` exactly like
/// `convert::resolve` does. `image_ref` is what followed `registry/` in MICROVM_IMAGE.
pub fn resolve(ctx: &JobCtx, image_ref: &str) -> Result<ResolvedImage> {
    let rg = ctx.cfg.registry.as_ref().context(
        "MICROVM_IMAGE uses the registry/ form but the host has no [registry] configured",
    )?;
    let (name, reference) = image::parse_ref(image_ref)?;
    let (resolved, _dir) = block_on(resolve_async(ctx, rg, &name, reference))?;
    Ok(resolved)
}

/// Thin CLI counterpart of `resolve`: pull+cache the bundle and return its cache
/// dir (the resolved bundle directory), printed by `main`.
pub fn pull(cfg: Config, image_ref: &str) -> Result<std::path::PathBuf> {
    let (name, reference) = {
        cfg.registry
            .as_ref()
            .context("`registry pull` needs a [registry] section in the config")?;
        image::parse_ref(image_ref)?
    };
    // resolve caches under the JobCtx's state_dir; a CLI pull builds a throwaway
    // JobCtx so it shares the exact same cache layout as a job's pull.
    let ctx = JobCtx::new_for_job(cfg, "registry-pull".into())?;
    let rg = ctx
        .cfg
        .registry
        .as_ref()
        .expect("registry presence checked above");
    let (_resolved, dir) = block_on(resolve_async(&ctx, rg, &name, reference))?;
    Ok(dir)
}

/// Try to pull a bundle tagged `<name>:<tag>` (a content fingerprint) and place its
/// `runner.ext4` at `dest`, for the build-sharing path (`fleet --registry`): a
/// worktree reuses a bundle another already built+pushed instead of rebuilding.
/// Returns `Ok(false)` when the tag is absent (or the registry is unreachable) — the
/// caller then builds. The sparse reassembly is byte-exact, so the placed ext4 keeps
/// its fingerprint UUID and reads as fresh on the next run.
pub fn try_pull_ext4(rg: &Registry, name: &str, tag: &str, dest: &Path) -> Result<bool> {
    block_on(try_pull_ext4_async(rg, name, tag, dest))
}

async fn try_pull_ext4_async(rg: &Registry, name: &str, tag: &str, dest: &Path) -> Result<bool> {
    let (client, auth) = client(rg)?;
    let image = make_ref(rg, name, tag)?;
    // Absent tag (or an unreachable registry) -> build locally; only a *found* bundle
    // that then fails to pull is a hard error.
    let Ok(digest) = client.fetch_manifest_digest(&image, &auth).await else {
        return Ok(false);
    };
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let bundle = parent.join(format!(".vkpull-{}", sanitize_component(name)));
    let _ = std::fs::remove_dir_all(&bundle);
    let dref = make_digest_ref(rg, name, &digest)?;
    pull_into(&client, &auth, &dref, name, &digest, &bundle).await?;
    let runner = bundle.join("runner.ext4");
    let _ = std::fs::remove_file(dest);
    std::fs::rename(&runner, dest)
        .with_context(|| format!("placing pulled ext4 at {}", dest.display()))?;
    let _ = std::fs::remove_dir_all(&bundle);
    Ok(true)
}

/// Push a built `ext4` to the registry as a bundle tagged `<name>:<tag>` (its content
/// fingerprint), so other worktrees can pull it instead of rebuilding. Best-effort:
/// the caller treats a failure as non-fatal (the image was built locally regardless).
pub fn push_ext4(rg: &Registry, name: &str, tag: &str, ext4: &Path, boot_kind: &str) -> Result<()> {
    block_on(push_ext4_async(rg, name, tag, ext4, boot_kind))
}

async fn push_ext4_async(
    rg: &Registry,
    name: &str,
    tag: &str,
    ext4: &Path,
    boot_kind: &str,
) -> Result<()> {
    let parent = ext4.parent().unwrap_or_else(|| Path::new("."));
    let bundle = parent.join(format!(".vkpush-{}", sanitize_component(name)));
    let _ = std::fs::remove_dir_all(&bundle);
    std::fs::create_dir_all(&bundle).with_context(|| format!("creating {}", bundle.display()))?;
    let runner = bundle.join("runner.ext4");
    // hardlink the ext4 into the staging bundle to avoid copying a multi-GB file;
    // fall back to a copy if hardlinking is not possible (different filesystem).
    if std::fs::hard_link(ext4, &runner).is_err() {
        std::fs::copy(ext4, &runner).with_context(|| format!("copying {}", ext4.display()))?;
    }
    std::fs::write(bundle.join("boot.kind"), boot_kind).context("writing boot.kind")?;
    let r = push_async(rg, &bundle, name, tag).await;
    let _ = std::fs::remove_dir_all(&bundle);
    r.map(|_digest| ())
}

/// Flatten a name to a safe single path component for a scratch dir (no separators).
fn sanitize_component(name: &str) -> String {
    name.replace(['/', '\\'], "_")
}

/// Drive a registry future to completion from a sync entry point. The executor's
/// prepare/run path (and `main`) already run inside a tokio runtime, so this runs
/// the future on a dedicated OS thread with its own current-thread runtime — a
/// nested `Runtime::block_on` on the calling thread would panic.
fn block_on<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building the registry tokio runtime")
                .block_on(fut)
        })
        .join()
        .expect("the registry runtime thread panicked")
    })
}

/// Build an oci-client `Client` + `RegistryAuth` from a `[registry]` section, the same
/// construction `oci.rs` uses for the convert/launch paths (rustls, optional PEM CA,
/// Basic vs Anonymous auth).
fn client(rg: &Registry) -> Result<(oci_client::Client, RegistryAuth)> {
    let mut cfg = ClientConfig::default();
    if let Some(ca) = &rg.ca_file {
        let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
        cfg.extra_root_certificates.push(Certificate {
            encoding: CertificateEncoding::Pem,
            data: pem,
        });
    }
    if rg.insecure {
        cfg.protocol = ClientProtocol::Http;
    }
    let client = oci_client::Client::new(cfg);
    let auth = if rg.username.is_empty() {
        RegistryAuth::Anonymous
    } else {
        let file = rg
            .password_file
            .as_ref()
            .context("registry.username set but no registry.password_file")?;
        let password =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        RegistryAuth::Basic(rg.username.clone(), password.trim_end().to_string())
    };
    Ok((client, auth))
}

/// `<registry.repo>/<name>` parsed into an oci-client `Reference` at `tag`/`digest`.
fn make_ref(rg: &Registry, name: &str, refr: &str) -> Result<OciReference> {
    let whole = format!("{}/{name}:{refr}", rg.repo);
    whole
        .parse()
        .with_context(|| format!("parsing OCI reference {whole:?}"))
}

/// `<registry.repo>/<name>@<digest>` (digest keeps its `sha256:` prefix), so the
/// manifest is fetched by digest — not as a tag named the bare hex.
fn make_digest_ref(rg: &Registry, name: &str, digest: &str) -> Result<OciReference> {
    let whole = format!("{}/{name}@{digest}", rg.repo);
    whole
        .parse()
        .with_context(|| format!("parsing OCI reference {whole:?}"))
}

async fn push_async(rg: &Registry, dir: &Path, name: &str, tag: &str) -> Result<String> {
    let (client, auth) = client(rg)?;
    let image = make_ref(rg, name, tag)?;
    // The granular blob_exists/push_blob/push_manifest calls apply the cached token
    // per request; seed it once (the high-level push() does this for us, we don't
    // use it because we drive dedup with blob_exists ourselves).
    client
        .store_auth_if_needed(image.resolve_registry(), &auth)
        .await;

    let ext4 = dir.join("runner.ext4");
    let total_size = std::fs::metadata(&ext4)
        .with_context(|| format!("stat {}", ext4.display()))?
        .len();

    // CDC + per-chunk zstd, STREAMED from the file: StreamCDC buffers at most ~CDC_MAX
    // at a time, so a multi-GB rootfs is never held in RAM. Sequential is fine for now
    // (the registry round-trip is serialized too); concurrent uploads are a future
    // optimization.
    let mut layers: Vec<OciDescriptor> = Vec::new();
    let (mut uploaded, mut skipped) = (0usize, 0usize);
    let file = std::fs::File::open(&ext4).with_context(|| format!("opening {}", ext4.display()))?;
    let chunker =
        fastcdc::v2020::StreamCDC::new(std::io::BufReader::new(file), CDC_MIN, CDC_AVG, CDC_MAX);
    let mut chunk_count = 0usize;
    for chunk in chunker {
        let chunk = chunk.with_context(|| format!("chunking {}", ext4.display()))?;
        chunk_count += 1;
        let compressed =
            zstd::encode_all(&chunk.data[..], ZSTD_LEVEL).context("zstd-compressing a chunk")?;
        let digest = sha256_hex(&compressed);
        let mut annotations = BTreeMap::new();
        annotations.insert(ANN_OFFSET.to_string(), chunk.offset.to_string());
        annotations.insert(ANN_LENGTH.to_string(), chunk.length.to_string());
        let desc = OciDescriptor {
            media_type: CHUNK_MEDIA_TYPE.to_string(),
            digest: digest.clone(),
            size: compressed.len() as i64,
            annotations: Some(annotations),
            ..Default::default()
        };
        if client.blob_exists(&image, &digest).await? {
            skipped += 1;
        } else {
            client
                .push_blob(&image, compressed, &digest)
                .await
                .with_context(|| format!("pushing chunk {digest}"))?;
            uploaded += 1;
        }
        layers.push(desc);
    }
    println!(
        "virtkit: registry: {chunk_count} ext4 chunks ({uploaded} uploaded, {skipped} deduped)"
    );

    // kernel/initrd, when present, as their own raw blobs (small; no chunking).
    let has_kernel = dir.join("vmlinuz").is_file();
    let has_initrd = dir.join("initrd.img").is_file();
    if has_kernel {
        layers.push(push_file(&client, &image, &dir.join("vmlinuz"), KERNEL_MEDIA_TYPE).await?);
    }
    if has_initrd {
        layers.push(push_file(&client, &image, &dir.join("initrd.img"), INITRD_MEDIA_TYPE).await?);
    }

    let boot_kind = image::read_boot_kind(dir);
    let config = BundleConfig {
        total_size,
        chunk_count,
        boot_kind: image::boot_kind_tag(boot_kind).to_string(),
        compression: "zstd".to_string(),
        has_kernel,
        has_initrd,
    };
    let config_json = serde_json::to_vec(&config).context("serializing the bundle config")?;
    let config_digest = sha256_hex(&config_json);
    let config_desc = OciDescriptor {
        media_type: CONFIG_MEDIA_TYPE.to_string(),
        digest: config_digest.clone(),
        size: config_json.len() as i64,
        ..Default::default()
    };
    if !client.blob_exists(&image, &config_digest).await? {
        client
            .push_blob(&image, config_json, &config_digest)
            .await
            .context("pushing the bundle config blob")?;
    }

    let manifest = OciManifest::Image(OciImageManifest {
        schema_version: 2,
        media_type: Some(OCI_IMAGE_MEDIA_TYPE.to_string()),
        artifact_type: Some(ARTIFACT_TYPE.to_string()),
        config: config_desc,
        layers,
        subject: None,
        annotations: None,
    });
    let digest = client
        .push_manifest(&image, &manifest)
        .await
        .with_context(|| format!("pushing the bundle manifest to {}", image))?;
    println!(
        "virtkit: registry: pushed {}/{name}:{tag} -> {digest}",
        rg.repo
    );
    Ok(digest)
}

/// Push a small file (kernel/initrd) as a single raw blob, returning its layer
/// descriptor. The digest is the sha256 of the raw bytes.
async fn push_file(
    client: &oci_client::Client,
    image: &OciReference,
    path: &Path,
    media_type: &str,
) -> Result<OciDescriptor> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let digest = sha256_hex(&data);
    let size = data.len() as i64;
    if !client.blob_exists(image, &digest).await? {
        client
            .push_blob(image, data, &digest)
            .await
            .with_context(|| format!("pushing {}", path.display()))?;
    }
    Ok(OciDescriptor {
        media_type: media_type.to_string(),
        digest,
        size,
        ..Default::default()
    })
}

async fn resolve_async(
    ctx: &JobCtx,
    rg: &Registry,
    name: &str,
    reference: Reference,
) -> Result<(ResolvedImage, std::path::PathBuf)> {
    let (client, auth) = client(rg)?;

    // tag -> digest (or the @digest verbatim), so the cache is content-addressed.
    let digest = match &reference {
        Reference::Digest(d) => d.clone(),
        Reference::Tag(tag) => {
            let image = make_ref(rg, name, tag)?;
            client
                .fetch_manifest_digest(&image, &auth)
                .await
                .with_context(|| format!("resolving {name}:{tag} against {}", rg.repo))?
        }
    };
    let dir = bundle_dir(&ctx.cfg, name, &digest);

    if !bundle_present(&dir) {
        let image = make_digest_ref(rg, name, &digest)?;
        pull_into(&client, &auth, &image, name, &digest, &dir).await?;
        let images_dir = ctx.cfg.state_dir().join("registry").join(name);
        image::gc(&images_dir, &dir, rg.keep);
    }

    let boot_kind = image::read_boot_kind(&dir);
    println!("virtkit: image {name}@{digest} (registry bundle, {boot_kind:?})");
    Ok((
        image::resolved_from_dir(&rg.generic_kernel, &dir, boot_kind),
        dir,
    ))
}

/// Pull the manifest + config + every blob into `dir`, under the shared pull lock,
/// promoting a tmp sibling on success (a killed pull never leaves a half-bundle).
async fn pull_into(
    client: &oci_client::Client,
    auth: &RegistryAuth,
    image: &OciReference,
    name: &str,
    digest: &str,
    dir: &Path,
) -> Result<()> {
    let _lock = image::acquire_pull_lock(dir, name, digest)?;
    if bundle_present(dir) {
        return Ok(());
    }
    println!("virtkit: registry: pulling {name}@{digest} ...");
    let (manifest, _) = client
        .pull_manifest(image, auth)
        .await
        .with_context(|| format!("pulling the manifest of {name}@{digest}"))?;
    let manifest = match manifest {
        OciManifest::Image(m) => m,
        OciManifest::ImageIndex(_) => bail!("{name}@{digest} is an image index, not a bundle"),
    };

    let config = pull_blob_bytes(client, image, &manifest.config).await?;
    let config: BundleConfig =
        serde_json::from_slice(&config).context("parsing the bundle config blob")?;

    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;

    // runner.ext4: create at total_size (a sparse hole), then write each chunk at
    // its offset so the zero gaps between chunks stay holes.
    let ext4 = tmp.join("runner.ext4");
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&ext4)
        .with_context(|| format!("creating {}", ext4.display()))?;
    out.set_len(config.total_size)
        .with_context(|| format!("sizing {}", ext4.display()))?;

    let chunks_cache = chunks_cache_dir(dir);
    let (mut fetched, mut reused) = (0usize, 0usize);
    for layer in &manifest.layers {
        if layer.media_type != CHUNK_MEDIA_TYPE {
            continue;
        }
        let (offset, _len) = chunk_placement(layer)?;
        let compressed = pull_chunk(
            client,
            image,
            layer,
            &chunks_cache,
            &mut fetched,
            &mut reused,
        )
        .await?;
        let raw = zstd::decode_all(&compressed[..])
            .with_context(|| format!("zstd-decompressing chunk {}", layer.digest))?;
        write_chunk_sparse(&mut out, offset, &raw)
            .with_context(|| format!("writing a chunk into {}", ext4.display()))?;
    }
    out.flush()?;
    drop(out);
    println!(
        "virtkit: registry: {} ext4 chunks ({fetched} fetched, {reused} cached)",
        fetched + reused
    );

    // kernel/initrd (raw blobs), by media type.
    for layer in &manifest.layers {
        match layer.media_type.as_str() {
            KERNEL_MEDIA_TYPE => {
                let data = pull_blob_bytes(client, image, layer).await?;
                std::fs::write(tmp.join("vmlinuz"), data)
                    .with_context(|| format!("writing {}", tmp.join("vmlinuz").display()))?;
            }
            INITRD_MEDIA_TYPE => {
                let data = pull_blob_bytes(client, image, layer).await?;
                std::fs::write(tmp.join("initrd.img"), data)
                    .with_context(|| format!("writing {}", tmp.join("initrd.img").display()))?;
            }
            _ => {}
        }
    }

    write_boot_kind(&tmp, &config.boot_kind)?;
    if !bundle_present(&tmp) {
        bail!("pull of {name}@{digest} produced an incomplete bundle");
    }
    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&tmp, dir)
        .with_context(|| format!("promoting {} to {}", tmp.display(), dir.display()))?;
    Ok(())
}

/// Content-addressed local chunk cache: `state_dir/registry/chunks/`. Shared across
/// images so two bundles that share a chunk download it once. `dir` is the bundle's
/// `state_dir/registry/<name>/<digest>/`, so the cache is two levels up.
fn chunks_cache_dir(dir: &Path) -> std::path::PathBuf {
    dir.parent()
        .and_then(Path::parent)
        .unwrap_or(dir)
        .join("chunks")
}

/// Fetch one chunk, preferring the content-addressed local cache. A cache hit is
/// trusted (the file name IS the verified digest); a miss pulls (oci-client
/// verifies the blob against the descriptor digest) and stores it.
async fn pull_chunk(
    client: &oci_client::Client,
    image: &OciReference,
    layer: &OciDescriptor,
    cache: &Path,
    fetched: &mut usize,
    reused: &mut usize,
) -> Result<Vec<u8>> {
    let hex = layer.digest.trim_start_matches("sha256:");
    let cached = cache.join(hex);
    if let Ok(bytes) = std::fs::read(&cached) {
        *reused += 1;
        return Ok(bytes);
    }
    let bytes = pull_blob_bytes(client, image, layer).await?;
    std::fs::create_dir_all(cache).with_context(|| format!("creating {}", cache.display()))?;
    // atomic-ish: write to a tmp sibling then rename, so a killed pull never leaves
    // a truncated file under the digest name (which would then be trusted blindly).
    let tmp = cache.join(format!("{hex}.tmp"));
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
    let _ = std::fs::rename(&tmp, &cached);
    *fetched += 1;
    Ok(bytes)
}

/// Pull a blob fully into memory. oci-client verifies the bytes against the
/// descriptor digest while streaming, so the returned buffer is digest-checked.
async fn pull_blob_bytes(
    client: &oci_client::Client,
    image: &OciReference,
    layer: &OciDescriptor,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(layer.size.max(0) as usize);
    client
        .pull_blob(image, layer, &mut buf)
        .await
        .with_context(|| format!("pulling blob {}", layer.digest))?;
    Ok(buf)
}

/// Write a decompressed chunk into the rootfs at `offset`, preserving sparsity: an
/// all-zero chunk is skipped so the file keeps the hole `set_len` left there. CDC
/// tiles the whole file (chunks are contiguous, no gaps), so a zero region surfaces
/// as all-zero chunks — without this skip they'd be written back as real zeros and
/// densify the cached ext4 (a 16 GiB sparse image would land as 16 GiB on disk).
fn write_chunk_sparse(out: &mut std::fs::File, offset: u64, raw: &[u8]) -> std::io::Result<()> {
    if raw.iter().all(|&b| b == 0) {
        return Ok(());
    }
    out.seek(SeekFrom::Start(offset))?;
    out.write_all(raw)
}

/// A chunk descriptor's (offset, length) inside runner.ext4, from its annotations.
fn chunk_placement(layer: &OciDescriptor) -> Result<(u64, u64)> {
    let ann = layer
        .annotations
        .as_ref()
        .with_context(|| format!("chunk {} has no annotations", layer.digest))?;
    let parse = |key: &str| -> Result<u64> {
        ann.get(key)
            .with_context(|| format!("chunk {} missing annotation {key}", layer.digest))?
            .parse()
            .with_context(|| format!("chunk {} has a non-numeric {key}", layer.digest))
    };
    Ok((parse(ANN_OFFSET)?, parse(ANN_LENGTH)?))
}

/// The digest-keyed cache dir for a bundle: `state_dir/registry/<name>/<digest-hex>/`.
fn bundle_dir(cfg: &Config, name: &str, digest: &str) -> std::path::PathBuf {
    cfg.state_dir()
        .join("registry")
        .join(name)
        .join(digest.trim_start_matches("sha256:"))
}

/// A cached bundle is present and usable: runner.ext4 plus the boot marker (which
/// also records how to boot it). Mirrors `convert::bundle_complete`.
fn bundle_present(dir: &Path) -> bool {
    dir.join("runner.ext4").is_file() && dir.join("boot.kind").is_file()
}

/// Record the boot flavour in the bundle (the convert path's marker), so a cache
/// hit knows how to boot it. The string is the one stored in the config blob.
fn write_boot_kind(dir: &Path, tag: &str) -> Result<()> {
    std::fs::write(dir.join("boot.kind"), tag)
        .with_context(|| format!("writing the boot marker in {}", dir.display()))
}

fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in d {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// High-entropy pseudo-random bytes (a splitmix64 stream) so the CDC gear-hash
    /// hits cut points like real ext4 content would — a low-entropy/periodic buffer
    /// can refuse to split at all.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut out = vec![0u8; len];
        for word in out.chunks_mut(8) {
            state = state.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^= z >> 31;
            for (i, b) in word.iter_mut().enumerate() {
                *b = (z >> (8 * i)) as u8;
            }
        }
        out
    }

    /// The chunk digests of a buffer (sha256 of each chunk's zstd-compressed bytes),
    /// the exact dedup key push/pull use.
    fn chunk_digests(buf: &[u8]) -> Vec<String> {
        // the exact streaming path push uses (StreamCDC over a reader).
        fastcdc::v2020::StreamCDC::new(std::io::Cursor::new(buf), CDC_MIN, CDC_AVG, CDC_MAX)
            .map(|c| {
                let comp = zstd::encode_all(&c.unwrap().data[..], ZSTD_LEVEL).unwrap();
                sha256_hex(&comp)
            })
            .collect()
    }

    /// The production streaming path round-trips through the REAL sparse reassembly:
    /// StreamCDC + per-chunk zstd on push, then `set_len` + `write_chunk_sparse` on
    /// pull. A buffer with a large zero region comes back byte-identical AND stays
    /// sparse on disk — the all-zero chunks are skipped so their holes survive, i.e.
    /// the cached ext4 is never densified.
    #[test]
    fn stream_roundtrip_is_sparse() {
        // 16 MiB data | 32 MiB zeros | 16 MiB data
        let mut data = pseudo_random(16 << 20, 0xc0ffee);
        data.resize(data.len() + (32 << 20), 0);
        data.extend(pseudo_random(16 << 20, 0xbeef));
        let total = data.len() as u64;

        let path = std::env::temp_dir().join(format!(
            "virtkit-registry-roundtrip-{}.ext4",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        out.set_len(total).unwrap();
        let mut count = 0;
        for chunk in
            fastcdc::v2020::StreamCDC::new(std::io::Cursor::new(&data), CDC_MIN, CDC_AVG, CDC_MAX)
        {
            let chunk = chunk.unwrap();
            count += 1;
            let comp = zstd::encode_all(&chunk.data[..], ZSTD_LEVEL).unwrap();
            let back = zstd::decode_all(&comp[..]).unwrap();
            write_chunk_sparse(&mut out, chunk.offset, &back).unwrap();
        }
        out.flush().unwrap();
        drop(out);
        assert!(count > 1, "should split into several chunks");

        // content round-trips exactly
        assert_eq!(
            std::fs::read(&path).unwrap(),
            data,
            "reassembly must match input"
        );

        // the 32 MiB zero region stayed a hole: allocated blocks are well below total.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let on_disk = std::fs::metadata(&path).unwrap().blocks() * 512;
            assert!(
                on_disk + (8 << 20) < total,
                "expected a preserved hole: {on_disk} bytes on disk vs {total} logical"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A single-byte change re-chunks only locally: most chunk digests stay the
    /// same, which is what makes the dedup worthwhile.
    #[test]
    fn local_edit_preserves_most_chunks() {
        let mut data = pseudo_random(64 << 20, 0x1234);
        let before = chunk_digests(&data);
        assert!(before.len() > 4, "need several chunks to test locality");
        // flip a byte deep in the middle.
        data[32 << 20] ^= 0xff;
        let after = chunk_digests(&data);
        let unchanged = before.iter().filter(|d| after.contains(d)).count();
        // a local edit should leave the vast majority of chunk digests intact.
        assert!(
            unchanged * 2 > before.len(),
            "expected most of {} chunks unchanged, only {unchanged} were",
            before.len()
        );
    }
}
