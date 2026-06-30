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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
// blob digest (sha256 of the compressed bytes) to dedup. Shared with regserve's
// transparent storage compression.
pub(crate) const ZSTD_LEVEL: i32 = 3;

// Media types for the bundle artifact.
const ARTIFACT_TYPE: &str = "application/vnd.wallix.microvm.bundle";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.bundle.config.v1+json";
// Compressed-digest chunk: the blob IS the zstd bytes, digest over them (any OCI
// registry stores it compactly). `transparent_zstd` mode instead uses the raw
// chunk: digest over the *uncompressed* bytes, the registry stores them zstd.
const CHUNK_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.ext4.chunk.zstd";
const CHUNK_MEDIA_TYPE_RAW: &str = "application/vnd.wallix.microvm.ext4.chunk";
// Capability header a cooperating `regserve` sets on its `GET /v2/` probe response,
// so an auto-mode client knows it can push transparent-zstd (uncompressed-digest)
// chunks. Absent on any dumb OCI registry.
pub(crate) const TRANSPARENT_ZSTD_HEADER: &str = "x-virtkit-transparent-zstd";
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

/// Resolve a reference to its manifest digest without pulling any blobs — the CLI
/// existence check (`registry inspect`). CI uses it to skip rebuilding a bundle
/// already in the store. Returns the manifest digest; errors (non-zero exit) when
/// the reference is absent or the registry is unreachable.
pub fn inspect(cfg: &Config, image_ref: &str) -> Result<String> {
    let rg = cfg
        .registry
        .as_ref()
        .context("`registry inspect` needs a [registry] section in the config")?;
    let (name, reference) = image::parse_ref(image_ref)?;
    block_on(inspect_async(rg, &name, &reference))
}

async fn inspect_async(rg: &Registry, name: &str, reference: &Reference) -> Result<String> {
    let (client, auth) = client(rg)?;
    let image = match reference {
        Reference::Tag(t) => make_ref(rg, name, t)?,
        Reference::Digest(d) => make_digest_ref(rg, name, d)?,
    };
    client
        .fetch_manifest_digest(&image, &auth)
        .await
        .with_context(|| format!("{}/{name}: reference not found in the registry", rg.repo))
}

/// Drive a registry future to completion from a sync entry point. The executor's
/// prepare/run path (and `main`) already run inside a tokio runtime, so this runs
/// the future on a dedicated OS thread with its own runtime — a nested
/// `Runtime::block_on` on the calling thread would panic. A multi-thread runtime
/// (+ its blocking pool) lets the push fan out chunk compression and uploads.
fn block_on<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
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
    // at a time, so a multi-GB rootfs is never held in RAM. Chunking is sequential
    // (it has to scan the file for cut points), but each chunk's zstd compression
    // (spawn_blocking, so it spreads over cores) and upload run concurrently, up to
    // CHUNK_CONCURRENCY in flight — so at most that many chunks are buffered. Layer
    // order is irrelevant (reassembly uses each chunk's offset annotation), so the
    // results are collected as they complete.
    use futures::StreamExt;
    const CHUNK_CONCURRENCY: usize = 16;
    // Host-global cache mapping a raw chunk's sha256 -> the (digest, size) of its
    // zstd blob, so an unchanged chunk on a re-push needs no recompression: we hash
    // the raw bytes (cheaper than compressing), and if the mapped blob is already in
    // the registry we emit its descriptor directly. A miss (or an evicted blob)
    // falls back to compress + record. zstd at a fixed level is deterministic, so the
    // mapping is stable; an entry pointing at an evicted blob just triggers a rebuild.
    // `transparent_zstd`: the registry stores chunks compressed and indexes them by
    // the *uncompressed* digest, so the client uploads raw (no client-side compress,
    // no chunkmap) and dedup is compression-independent. Otherwise the client
    // compresses and the blob is the zstd bytes (the chunkmap skips recompression).
    // Unset = auto: probe the registry's capability (a cooperating regserve), falling
    // back to the compressed-digest path any dumb OCI registry accepts.
    let transparent = match rg.transparent_zstd {
        Some(b) => b,
        None => detect_transparent_zstd(rg, &image).await,
    };
    let chunkmap = if transparent { None } else { chunkmap_dir() };
    // transparent mode uploads zstd frames tagged `Content-Encoding: zstd` via a
    // direct HTTP client (oci-client can't set per-request encodings).
    let http = if transparent {
        Some(http_client(rg)?)
    } else {
        None
    };
    let file = std::fs::File::open(&ext4).with_context(|| format!("opening {}", ext4.display()))?;
    let chunker =
        fastcdc::v2020::StreamCDC::new(std::io::BufReader::new(file), CDC_MIN, CDC_AVG, CDC_MAX);
    let results: Vec<Result<(OciDescriptor, bool)>> = futures::stream::iter(chunker)
        .map(|chunk| {
            let client = &client;
            let image = &image;
            let ext4 = &ext4;
            let chunkmap = &chunkmap;
            let http = &http;
            async move {
                let chunk = chunk.with_context(|| format!("chunking {}", ext4.display()))?;
                let (offset, length) = (chunk.offset, chunk.length as u64);
                let data = chunk.data;
                // hash the raw chunk (blocking pool, spread over cores); hand the
                // buffer back for a possible compress/upload.
                let (raw_hex, data) = tokio::task::spawn_blocking(move || {
                    let h = sha256_hex_raw(&data);
                    (h, data)
                })
                .await
                .context("joining the hash task")?;

                // transparent mode: digest = raw chunk. Dedup on the raw digest, so a
                // re-push skips both compression and upload. A new chunk is compressed
                // (content-size embedded) and uploaded with `Content-Encoding: zstd` —
                // compressed on the wire; the registry stores the frame verbatim.
                if transparent {
                    let digest = format!("sha256:{raw_hex}");
                    let size = data.len() as i64;
                    let uploaded = if client.blob_exists(image, &digest).await? {
                        false
                    } else {
                        let frame = tokio::task::spawn_blocking(move || zstd_with_size(&data))
                            .await
                            .context("joining the compress task")??;
                        push_blob_zstd(
                            http.as_ref().expect("http client"),
                            rg,
                            image,
                            &digest,
                            frame,
                        )
                        .await
                        .with_context(|| format!("pushing chunk {digest}"))?;
                        true
                    };
                    return Ok((
                        chunk_descriptor(CHUNK_MEDIA_TYPE_RAW, &digest, size, offset, length),
                        uploaded,
                    ));
                }

                // compressed-digest mode — fast path: a known blob already in the
                // registry -> no recompression (via the chunkmap).
                let mut cached = None;
                if let Some(dir) = chunkmap.as_deref()
                    && let Some((digest, size)) = chunkmap_get(dir, &raw_hex)
                    && client.blob_exists(image, &digest).await?
                {
                    cached = Some((digest, size));
                }
                if let Some((digest, size)) = cached {
                    return Ok((
                        chunk_descriptor(CHUNK_MEDIA_TYPE, &digest, size, offset, length),
                        false,
                    ));
                }

                // miss: compress, record the mapping, upload if absent.
                let compressed =
                    tokio::task::spawn_blocking(move || zstd::encode_all(&data[..], ZSTD_LEVEL))
                        .await
                        .context("joining the compress task")?
                        .context("zstd-compressing a chunk")?;
                let digest = sha256_hex(&compressed);
                let size = compressed.len() as i64;
                if let Some(dir) = chunkmap.as_deref() {
                    chunkmap_put(dir, &raw_hex, &digest, size);
                }
                let uploaded = if client.blob_exists(image, &digest).await? {
                    false
                } else {
                    client
                        .push_blob(image, compressed, &digest)
                        .await
                        .with_context(|| format!("pushing chunk {digest}"))?;
                    true
                };
                Ok((
                    chunk_descriptor(CHUNK_MEDIA_TYPE, &digest, size, offset, length),
                    uploaded,
                ))
            }
        })
        .buffer_unordered(CHUNK_CONCURRENCY)
        .collect()
        .await;

    let mut layers: Vec<OciDescriptor> = Vec::with_capacity(results.len());
    let (mut uploaded, mut skipped) = (0usize, 0usize);
    for r in results {
        let (desc, was_uploaded) = r?;
        if was_uploaded {
            uploaded += 1;
        } else {
            skipped += 1;
        }
        layers.push(desc);
    }
    let chunk_count = layers.len();
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
        // A chunk is either compressed-digest (blob = zstd, decode here) or raw
        // (`transparent_zstd`: blob is the canonical raw bytes — the registry already
        // served them decompressed, so write as-is). Self-describing via media type.
        let compressed = match layer.media_type.as_str() {
            CHUNK_MEDIA_TYPE => true,
            CHUNK_MEDIA_TYPE_RAW => false,
            _ => continue,
        };
        let (offset, _len) = chunk_placement(layer)?;
        let bytes = pull_chunk(
            client,
            image,
            layer,
            &chunks_cache,
            &mut fetched,
            &mut reused,
        )
        .await?;
        let raw = if compressed {
            zstd::decode_all(&bytes[..])
                .with_context(|| format!("zstd-decompressing chunk {}", layer.digest))?
        } else {
            bytes
        };
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

/// zstd-compress `raw`, embedding the decompressed size in the frame header so the
/// registry can report a canonical `Content-Length` on HEAD without decompressing
/// (`zstd::encode_all` omits the content size). Shared by the transparent-zstd client
/// push and regserve's storage compression.
pub(crate) fn zstd_with_size(raw: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)
        .context("creating the zstd encoder")?;
    enc.set_pledged_src_size(Some(raw.len() as u64))
        .context("setting the zstd pledged size")?;
    enc.include_contentsize(true)
        .context("enabling the zstd content size")?;
    enc.write_all(raw).context("zstd-compressing")?;
    enc.finish().context("finishing the zstd frame")
}

/// Probe `GET /v2/` for the [`TRANSPARENT_ZSTD_HEADER`] a cooperating `regserve`
/// advertises. Any failure — a dumb registry, a network/TLS error, a missing CA —
/// yields `false`: fall back to the compressed-digest path. Only called in auto mode
/// (`transparent_zstd` unset); the probe needs no auth (we only read our own header).
async fn detect_transparent_zstd(rg: &Registry, image: &OciReference) -> bool {
    let Ok(http) = http_client(rg) else {
        return false;
    };
    let scheme = if rg.insecure { "http" } else { "https" };
    let url = format!("{scheme}://{}/v2/", image.resolve_registry());
    match http.get(&url).send().await {
        Ok(resp) => resp.headers().contains_key(TRANSPARENT_ZSTD_HEADER),
        Err(_) => false,
    }
}

/// A reqwest client honoring the registry's TLS settings (rustls + optional PEM CA),
/// for the transparent-zstd blob push that needs a per-request `Content-Encoding`.
fn http_client(rg: &Registry) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder();
    if let Some(ca) = &rg.ca_file {
        let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
        b = b.add_root_certificate(
            reqwest::Certificate::from_pem(&pem).context("parsing the registry CA")?,
        );
    }
    b.build().context("building the registry HTTP client")
}

/// Optional HTTP Basic credentials from the registry config (username + password
/// file). None when no username is set (anonymous).
fn basic_auth(rg: &Registry) -> Result<Option<(String, String)>> {
    if rg.username.is_empty() {
        return Ok(None);
    }
    let file = rg
        .password_file
        .as_ref()
        .context("registry.username set but no registry.password_file")?;
    let pw = std::fs::read_to_string(file)
        .with_context(|| format!("reading {}", file.display()))?
        .trim_end()
        .to_string();
    Ok(Some((rg.username.clone(), pw)))
}

/// Upload an already-zstd-compressed blob under `digest` (the digest of its
/// *decompressed* form) with `Content-Encoding: zstd`, so the wire stays compressed
/// and the registry stores the frame verbatim. Monolithic OCI upload: POST a session,
/// then PUT the frame. Used only in `transparent_zstd` mode (a registry that
/// understands the encoding — virtkit's `regserve`).
async fn push_blob_zstd(
    http: &reqwest::Client,
    rg: &Registry,
    image: &OciReference,
    digest: &str,
    frame: Vec<u8>,
) -> Result<()> {
    let scheme = if rg.insecure { "http" } else { "https" };
    let registry = image.resolve_registry();
    let repo = image.repository();
    let auth = basic_auth(rg)?;
    let with_auth = |req: reqwest::RequestBuilder| match &auth {
        Some((u, p)) => req.basic_auth(u, Some(p)),
        None => req,
    };

    // 1. begin an upload session.
    let uploads = format!("{scheme}://{registry}/v2/{repo}/blobs/uploads/");
    let resp = with_auth(
        http.post(&uploads)
            .header(reqwest::header::CONTENT_LENGTH, "0"),
    )
    .send()
    .await
    .context("POST blob upload")?;
    if resp.status() != reqwest::StatusCode::ACCEPTED {
        bail!("begin blob upload: HTTP {}", resp.status());
    }
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .context("upload session returned no Location")?;
    // Location may be relative to the registry root.
    let location = if location.starts_with('/') {
        format!("{scheme}://{registry}{location}")
    } else {
        location.to_string()
    };

    // 2. PUT the compressed frame, tagged with its encoding and the canonical digest.
    let resp = with_auth(
        http.put(location)
            .query(&[("digest", digest)])
            .header(reqwest::header::CONTENT_ENCODING, "zstd")
            .body(frame),
    )
    .send()
    .await
    .context("PUT blob")?;
    if resp.status() != reqwest::StatusCode::CREATED {
        bail!("blob PUT: HTTP {}", resp.status());
    }
    Ok(())
}

/// Bare lowercase-hex sha256 (no `sha256:` prefix) — the raw-chunk cache key.
fn sha256_hex_raw(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// One ext4-chunk layer descriptor: its blob digest/size plus the offset+length
/// annotations the pull path reassembles from. `media_type` distinguishes a
/// compressed-digest chunk from a raw (`transparent_zstd`) one.
fn chunk_descriptor(
    media_type: &str,
    digest: &str,
    size: i64,
    offset: u64,
    length: u64,
) -> OciDescriptor {
    let mut annotations = BTreeMap::new();
    annotations.insert(ANN_OFFSET.to_string(), offset.to_string());
    annotations.insert(ANN_LENGTH.to_string(), length.to_string());
    OciDescriptor {
        media_type: media_type.to_string(),
        digest: digest.to_string(),
        size,
        annotations: Some(annotations),
        ..Default::default()
    }
}

/// Host-global raw-chunk cache dir (`$XDG_CACHE_HOME/virtkit/chunkmap`, else
/// `~/.cache/...`). None if neither is set (caching then disabled). Shared across all
/// worktrees/pushes: a chunk compressed once is never recompressed on the host again.
fn chunkmap_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("virtkit/chunkmap"))
}

/// Path of a raw-chunk cache entry, sharded by the first two hex chars so the dir
/// never holds a flat pile of entries.
fn chunkmap_path(dir: &Path, raw_hex: &str) -> PathBuf {
    let (shard, rest) = raw_hex.split_at(2.min(raw_hex.len()));
    dir.join(shard).join(rest)
}

/// Look up a raw chunk's cached blob (digest, size); None on any miss/parse failure.
fn chunkmap_get(dir: &Path, raw_hex: &str) -> Option<(String, i64)> {
    let text = std::fs::read_to_string(chunkmap_path(dir, raw_hex)).ok()?;
    let (digest, size) = text.trim().split_once(' ')?;
    Some((digest.to_string(), size.parse().ok()?))
}

/// Record a raw chunk -> (blob digest, size). Best-effort + atomic (tmp + rename),
/// safe for the concurrent push tasks and for several pushes sharing the cache.
fn chunkmap_put(dir: &Path, raw_hex: &str, digest: &str, size: i64) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let path = chunkmap_path(dir, raw_hex);
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let tmp = parent.join(format!(
        ".tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    if std::fs::write(&tmp, format!("{digest} {size}")).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_without_registry_section_errs() {
        // The existence-check CLI fails clearly (before any network) when the
        // host config carries no [registry] section.
        let cfg = crate::config::Config::default();
        let err = inspect(&cfg, "appbuilder:latest").unwrap_err();
        assert!(
            err.to_string().contains("[registry]"),
            "expected a missing-[registry] error, got: {err}"
        );
    }

    #[test]
    fn chunkmap_round_trip_and_sharding() {
        let dir = std::env::temp_dir().join(format!("virtkit-chunkmap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hex = format!("ab{}", "c".repeat(62)); // 64 hex chars
        assert_eq!(chunkmap_get(&dir, &hex), None); // miss before any write
        chunkmap_put(&dir, &hex, "sha256:deadbeef", 1234);
        assert_eq!(
            chunkmap_get(&dir, &hex),
            Some(("sha256:deadbeef".to_string(), 1234))
        );
        // sharded by the first two hex chars (no flat pile of entries)
        assert!(dir.join("ab").join(&hex[2..]).is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
