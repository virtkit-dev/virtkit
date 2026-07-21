//! Native OCI bundle registry with content-defined chunk deduplication, backing the
//! `MICROVM_IMAGE: virtkit/<name>[:tag|@sha256:…]` form.
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
//! Same caching model as the `docker/` path: digest-keyed bundle dir under
//! `state_dir`, the abstract-socket pull lock + mtime GC shared via image.rs, and
//! a `ResolvedImage` returned from the cached dir keyed on `boot.kind`.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use oci_client::Reference as OciReference;
use oci_client::client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol};
use oci_client::manifest::{OCI_IMAGE_MEDIA_TYPE, OciDescriptor, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Config, Registry};
use crate::image::{self, Reference, ResolvedImage};
// The content-addressed store lives in the standalone vk-registry crate; the client
// paths here share its digest/compression conventions (ZSTD_LEVEL so re-pushed chunks
// dedup, the transparent-zstd capability header, and the size-embedding zstd encoder).
use vk_registry::{TRANSPARENT_ZSTD_HEADER, ZSTD_LEVEL, zstd_with_size};

// CDC parameters for runner.ext4 (FastCDC v2020): min 1 MiB, avg 4 MiB, max 16 MiB.
const CDC_MIN: usize = 1 << 20;
const CDC_AVG: usize = 4 << 20;
const CDC_MAX: usize = 16 << 20;

// Media types for the bundle artifact.
const ARTIFACT_TYPE: &str = "application/vnd.wallix.microvm.bundle";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.bundle.config.v1+json";
// Compressed-digest chunk: the blob IS the zstd bytes, digest over them (any OCI
// registry stores it compactly). `transparent_zstd` mode instead uses the raw
// chunk: digest over the *uncompressed* bytes, the registry stores them zstd.
const CHUNK_MEDIA_TYPE: &str = "application/vnd.wallix.microvm.ext4.chunk.zstd";
const CHUNK_MEDIA_TYPE_RAW: &str = "application/vnd.wallix.microvm.ext4.chunk";
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
    /// The image's runtime config (Env/User/Workdir/Cmd) — what a `vk build` writes as
    /// the `<out>.json` sidecar. Carried so the guest boots as the image intends (e.g.
    /// drops to its `User`); the rootfs itself stays byte-clean (config applied at boot,
    /// not baked). Absent for older bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_config: Option<vk_core::runcfg::RunConfig>,
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
/// `dockerimg::resolve` does. `image_ref` is what followed `virtkit/` in MICROVM_IMAGE.
pub fn resolve(cfg: &Config, state_dir: &Path, image_ref: &str) -> Result<ResolvedImage> {
    let rg = cfg.registry.as_ref().context(
        "MICROVM_IMAGE uses the virtkit/ form but the host has no [registry] configured",
    )?;
    let (name, reference) = image::parse_ref(image_ref)?;
    let (resolved, _dir) = block_on(resolve_async(cfg, state_dir, rg, &name, reference))?;
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
    // A CLI pull caches under the config's own state_dir, sharing the exact same
    // cache layout as a job's pull.
    let rg = cfg
        .registry
        .as_ref()
        .expect("registry presence checked above");
    let (_resolved, dir) = block_on(resolve_async(&cfg, cfg.state_dir(), rg, &name, reference))?;
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

/// True if `<name>:<tag>` resolves in the registry — a cheap manifest HEAD, no pull.
/// The build instruction-cache existence check; a registry error reads as "absent".
pub fn exists(rg: &Registry, name: &str, tag: &str) -> bool {
    if let Some(root) = rg.local_root() {
        return local::exists(&root, name, tag);
    }
    block_on(async {
        let Ok((client, auth)) = client(rg) else {
            return false;
        };
        let Ok(image) = make_ref(rg, name, tag) else {
            return false;
        };
        client.fetch_manifest_digest(&image, &auth).await.is_ok()
    })
}

/// Try to pull a bundle tagged `<name>:<tag>` (a content fingerprint) and place its
/// `runner.ext4` at `dest`, for the build-sharing path: a
/// worktree reuses a bundle another already built+pushed instead of rebuilding.
/// Returns `Ok(false)` when the tag is absent (or the registry is unreachable) — the
/// caller then builds. The sparse reassembly is byte-exact, so the placed ext4 keeps
/// its fingerprint UUID and reads as fresh on the next run.
/// Reassemble a cached bundle's ext4 at `dest`, returning the manifest digest it resolved
/// the tag to (`None` if the tag is absent). The caller pins that digest so a later diff
/// push re-chunks against *exactly* this content, even if a concurrent build clobbers the
/// tag with byte-different (equivalent) bytes in between.
pub fn try_pull_ext4(rg: &Registry, name: &str, tag: &str, dest: &Path) -> Result<Option<String>> {
    if let Some(root) = rg.local_root() {
        return local::try_pull_ext4(&root, name, tag, dest);
    }
    block_on(try_pull_ext4_async(rg, name, tag, dest))
}

async fn try_pull_ext4_async(
    rg: &Registry,
    name: &str,
    tag: &str,
    dest: &Path,
) -> Result<Option<String>> {
    let (client, auth) = client(rg)?;
    let image = make_ref(rg, name, tag)?;
    // Absent tag (or an unreachable registry) -> build locally; only a *found* bundle
    // that then fails to pull is a hard error.
    let Ok(digest) = client.fetch_manifest_digest(&image, &auth).await else {
        return Ok(None);
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
    Ok(Some(digest))
}

/// Push a built `ext4` to the registry as a bundle tagged `<name>:<tag>` (its content
/// fingerprint), so other worktrees can pull it instead of rebuilding. Best-effort:
/// the caller treats a failure as non-fatal (the image was built locally regardless).
pub fn push_ext4(
    rg: &Registry,
    name: &str,
    tag: &str,
    ext4: &Path,
    boot_kind: &str,
) -> Result<String> {
    if let Some(root) = rg.local_root() {
        return local::push_ext4(&root, name, tag, ext4, boot_kind);
    }
    block_on(push_ext4_async(rg, name, tag, ext4, boot_kind))
}

async fn push_ext4_async(
    rg: &Registry,
    name: &str,
    tag: &str,
    ext4: &Path,
    boot_kind: &str,
) -> Result<String> {
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
    r
}

/// Fetch a cached bundle's chunk layer descriptors (with their offset/length
/// annotations) plus its total size, *without* reassembling the image — the parent
/// state a diff push builds on. Returns `None` if the tag is absent.
pub fn fetch_chunks(
    rg: &Registry,
    name: &str,
    tag: &str,
) -> Result<Option<(Vec<OciDescriptor>, u64)>> {
    if let Some(root) = rg.local_root() {
        return local::fetch_chunks(&root, name, tag);
    }
    block_on(fetch_chunks_async(rg, name, tag))
}

async fn fetch_chunks_async(
    rg: &Registry,
    name: &str,
    tag: &str,
) -> Result<Option<(Vec<OciDescriptor>, u64)>> {
    let (client, auth) = client(rg)?;
    // A pinned parent is passed by immutable digest (`sha256:…`), which must be resolved
    // as a digest reference — `make_ref` would build an unparseable `:sha256:…` tag. A
    // plain tag is resolved to its current digest first.
    let image = if tag.starts_with("sha256:") {
        make_digest_ref(rg, name, tag)?
    } else {
        make_ref(rg, name, tag)?
    };
    let Ok(digest) = client.fetch_manifest_digest(&image, &auth).await else {
        return Ok(None);
    };
    let dref = make_digest_ref(rg, name, &digest)?;
    let (manifest, _) = client
        .pull_manifest(&dref, &auth)
        .await
        .with_context(|| format!("pulling the manifest of {name}@{digest}"))?;
    let manifest = match manifest {
        OciManifest::Image(m) => m,
        OciManifest::ImageIndex(_) => bail!("{name}@{digest} is an image index, not a bundle"),
    };
    let config = pull_blob_bytes(&client, &dref, &manifest.config).await?;
    let config: BundleConfig =
        serde_json::from_slice(&config).context("parsing the bundle config blob")?;
    let chunks: Vec<OciDescriptor> = manifest
        .layers
        .into_iter()
        .filter(|l| {
            matches!(
                l.media_type.as_str(),
                CHUNK_MEDIA_TYPE | CHUNK_MEDIA_TYPE_RAW
            )
        })
        .collect();
    Ok(Some((chunks, config.total_size)))
}

/// Push `ext4` as a new bundle tagged `<name>:<tag>`, reusing `parent_layers` for every
/// chunk whose byte range is untouched by `dirty` and re-chunking only the dirty ranges.
/// A parent chunk that overlaps a dirty extent is regenerated whole (one chunk, same
/// offset/length) and the rest are reused verbatim — only the dirty bytes are read,
/// hashed and (if new) compressed/uploaded. When `parent_layers` is empty there is no
/// safe parent to reuse, so the whole qcow2 backing chain is re-chunked. `dirty` is the set
/// of cluster ranges the guest wrote (read from the overlay and pushed as data); `holes` is
/// the set it freed (discard/trim) since the parent — represented as gaps that clear the
/// parent's bytes there, never read. `total_size` is the parent's (the ext4 size is fixed
/// across RUNs).
#[allow(clippy::too_many_arguments)]
pub fn push_ext4_diff(
    rg: &Registry,
    name: &str,
    tag: &str,
    ext4: &Path,
    boot_kind: &str,
    total_size: u64,
    dirty: &[(u64, u64)],
    holes: &[(u64, u64)],
    parent_layers: &[OciDescriptor],
) -> Result<(Vec<OciDescriptor>, u64, String)> {
    if let Some(root) = rg.local_root() {
        return local::push_ext4_diff(
            &root,
            name,
            tag,
            ext4,
            boot_kind,
            total_size,
            dirty,
            holes,
            parent_layers,
        );
    }
    block_on(push_ext4_diff_async(
        rg,
        name,
        tag,
        ext4,
        boot_kind,
        total_size,
        dirty,
        holes,
        parent_layers,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn push_ext4_diff_async(
    rg: &Registry,
    name: &str,
    tag: &str,
    ext4: &Path,
    boot_kind: &str,
    total_size: u64,
    dirty: &[(u64, u64)],
    holes: &[(u64, u64)],
    parent_layers: &[OciDescriptor],
) -> Result<(Vec<OciDescriptor>, u64, String)> {
    let (client, auth) = client(rg)?;
    let image = make_ref(rg, name, tag)?;
    client
        .store_auth_if_needed(image.resolve_registry(), &auth)
        .await;
    let transparent = match rg.transparent_zstd {
        Some(b) => b,
        None => detect_transparent_zstd(rg, &image).await,
    };
    let chunkmap = if transparent { None } else { chunkmap_dir() };
    let http = if transparent {
        Some(http_client(rg)?)
    } else {
        None
    };

    // `ext4` is the stage's captured overlay (a qcow2 over the stage image); read changed
    // regions from it directly via the native reader — no flat-raw `qemu-img convert`. A
    // parent chunk straddling a dirty extent still reads correctly: `read_at` resolves the
    // unchanged part through the backing chain.
    let mut q = crate::qcow2::Qcow2::open(ext4)?;
    let mut layers: Vec<OciDescriptor> = Vec::with_capacity(parent_layers.len());
    let (mut uploaded, mut reused, mut regened, mut added) = (0usize, 0usize, 0usize, 0usize);
    let mut covered: Vec<(u64, u64)> = Vec::with_capacity(parent_layers.len());
    for layer in parent_layers {
        let (offset, length) = chunk_placement(layer)?;
        covered.push((offset, length));
        // overlap test against a cluster-range set (half-open intervals).
        let overlaps = |ranges: &[(u64, u64)]| {
            ranges
                .iter()
                .any(|&(ds, dl)| offset < ds + dl && ds < offset + length)
        };
        let is_dirty = overlaps(dirty);
        let is_hole = overlaps(holes);
        if !is_dirty && !is_hole {
            layers.push(layer.clone());
            reused += 1;
            continue;
        }
        // Written and/or partly freed (a content-defined chunk can straddle both): regenerate
        // from the overlay — the read resolves written bytes as data and untouched bytes through
        // the backing chain — then force the fully-freed sub-ranges to zero so a hole never
        // keeps the parent's stale bytes. Freed clusters read safely: imago maps them to zero.
        let mut buf = vec![0u8; length as usize];
        q.read_at(offset, &mut buf).with_context(|| {
            format!("reading {length} bytes at {offset} from {}", ext4.display())
        })?;
        zero_ranges(&mut buf, offset, holes);
        regened += 1;
        if buf.iter().all(|&b| b == 0) {
            continue; // fully freed/zeroed since the parent — drop it, the pull leaves a hole
        }
        let (desc, was_uploaded) = put_raw_chunk(
            &client,
            http.as_ref(),
            rg,
            &image,
            transparent,
            chunkmap.as_deref(),
            buf,
            offset,
            length,
        )
        .await?;
        if was_uploaded {
            uploaded += 1;
        }
        layers.push(desc);
    }
    // Writes into regions that were holes in the parent (e.g. new files in former free
    // space): dirty and covered by no parent chunk. With no parent at all, this must become
    // a full chain re-chunk; otherwise a FROM-scratch stage (or a push after a missed
    // parent) would cache only the dirty overlay clusters and omit untouched ext4 metadata
    // inherited from its backing image.
    let new_regions = if parent_layers.is_empty() {
        q.chain_data_extents()?
    } else {
        covered.sort_unstable();
        let mut dirty_sorted = dirty.to_vec();
        dirty_sorted.sort_unstable();
        subtract_extents(&dirty_sorted, &covered)
    };
    for (start, len) in new_regions {
        // stream this region from the captured overlay (qcow2) via the native reader.
        let reader: Box<dyn std::io::Read + Send> = Box::new(crate::qcow2::RegionReader::new(
            crate::qcow2::Qcow2::open(ext4)?,
            start,
            len,
        ));
        for (desc, was_uploaded) in chunk_region(
            &client,
            http.as_ref(),
            rg,
            &image,
            transparent,
            chunkmap.as_deref(),
            reader,
            start,
            ext4,
        )
        .await?
        {
            if was_uploaded {
                uploaded += 1;
            }
            layers.push(desc);
            added += 1;
        }
    }
    println!(
        "virtkit: registry: {} ext4 chunks ({reused} reused, {regened} re-chunked, {added} added, {uploaded} uploaded)",
        layers.len()
    );

    let config = BundleConfig {
        total_size,
        chunk_count: layers.len(),
        boot_kind: boot_kind.to_string(),
        compression: "zstd".to_string(),
        has_kernel: false,
        has_initrd: false,
        // The build-sharing path pushes an ext4 by fingerprint; no runtime config rides it.
        run_config: None,
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
    // Keep the layer list to hand back: the next instruction's diff push uses it as its
    // parent in-memory, skipping a re-fetch of this manifest from the registry.
    let ret_layers = layers.clone();
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
        .with_context(|| format!("pushing the bundle manifest to {image}"))?;
    println!(
        "virtkit: registry: pushed {}/{name}:{tag} -> {digest}",
        rg.repo
    );
    Ok((ret_layers, total_size, digest))
}

/// Process one raw chunk for a push: dedup on its content (raw digest in transparent
/// mode, else the chunkmap over the compressed-digest path), uploading the blob only if
/// absent. Returns the layer descriptor (carrying `offset`/`length`) and whether a blob
/// was uploaded. The single-chunk counterpart of `push_async`'s streaming loop, used by
/// the diff push.
#[allow(clippy::too_many_arguments)]
async fn put_raw_chunk(
    client: &oci_client::Client,
    http: Option<&reqwest::Client>,
    rg: &Registry,
    image: &OciReference,
    transparent: bool,
    chunkmap: Option<&Path>,
    raw: Vec<u8>,
    offset: u64,
    length: u64,
) -> Result<(OciDescriptor, bool)> {
    let raw_hex = sha256_hex_raw(&raw);
    if transparent {
        let digest = format!("sha256:{raw_hex}");
        let size = raw.len() as i64;
        let uploaded = if client.blob_exists(image, &digest).await? {
            false
        } else {
            let frame = zstd_with_size(&raw)?;
            push_blob_zstd(http.expect("http client"), rg, image, &digest, frame)
                .await
                .with_context(|| format!("pushing chunk {digest}"))?;
            true
        };
        return Ok((
            chunk_descriptor(CHUNK_MEDIA_TYPE_RAW, &digest, size, offset, length),
            uploaded,
        ));
    }
    if let Some(dir) = chunkmap
        && let Some((digest, size)) = chunkmap_get(dir, &raw_hex)
        && client.blob_exists(image, &digest).await?
    {
        return Ok((
            chunk_descriptor(CHUNK_MEDIA_TYPE, &digest, size, offset, length),
            false,
        ));
    }
    let compressed = zstd::encode_all(&raw[..], ZSTD_LEVEL).context("zstd-compressing a chunk")?;
    let digest = sha256_hex(&compressed);
    let size = compressed.len() as i64;
    if let Some(dir) = chunkmap {
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

/// The `(start, len)` byte ranges of `path` that hold data (not holes), via
/// `SEEK_DATA`/`SEEK_HOLE`. The ext4 images are sparse — their free space is a hole —
/// so chunking only these extents skips reading/hashing/compressing the (often
/// gigabyte-scale) free region entirely; the pull recreates the gaps as holes.
fn file_data_extents(path: &Path, total_size: u64) -> Result<Vec<(u64, u64)>> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let fd = f.as_raw_fd();
    let mut extents = Vec::new();
    let mut pos: libc::off_t = 0;
    let total = total_size as libc::off_t;
    while pos < total {
        // next data at/after pos; ENXIO (or -1) => no more data before EOF.
        let data = unsafe { libc::lseek(fd, pos, libc::SEEK_DATA) };
        if data < 0 {
            break;
        }
        // end of that data run = the next hole (clamped to EOF).
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        let end = if hole < 0 { total } else { hole.min(total) };
        if end > data {
            extents.push((data as u64, (end - data) as u64));
        }
        pos = end;
    }
    Ok(extents)
}

/// `a − b` over half-open `(start, len)` interval lists (inputs sorted, disjoint).
fn subtract_extents(a: &[(u64, u64)], b: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(s, l) in a {
        let mut cur = s;
        let end = s + l;
        for &(bs, bl) in b {
            let (bs, be) = (bs, bs + bl);
            if be <= cur || bs >= end {
                continue;
            }
            if bs > cur {
                out.push((cur, bs - cur));
            }
            cur = cur.max(be);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            out.push((cur, end - cur));
        }
    }
    out
}

/// Zero the parts of `buf` (logical bytes starting at `base`) that fall inside any `hole`
/// range. Used when regenerating a parent chunk that straddles freed and live regions: the
/// live bytes stay as read from the overlay, the freed ones become an explicit zero hole.
fn zero_ranges(buf: &mut [u8], base: u64, holes: &[(u64, u64)]) {
    let end = base + buf.len() as u64;
    for &(hs, hl) in holes {
        let (s, e) = (hs.max(base), (hs + hl).min(end));
        if s < e {
            buf[(s - base) as usize..(e - base) as usize].fill(0);
        }
    }
}

/// Content-defined-chunk a `[start, start+len)` region streamed from `reader` (a raw file
/// slice for a full push, or a qcow2 region reader for a diff push), uploading each new
/// chunk. `label` is only for error context.
#[allow(clippy::too_many_arguments)]
async fn chunk_region(
    client: &oci_client::Client,
    http: Option<&reqwest::Client>,
    rg: &Registry,
    image: &OciReference,
    transparent: bool,
    chunkmap: Option<&Path>,
    reader: Box<dyn std::io::Read + Send>,
    start: u64,
    label: &Path,
) -> Result<Vec<(OciDescriptor, bool)>> {
    use futures::StreamExt;
    const CHUNK_CONCURRENCY: usize = 16;
    let chunker =
        fastcdc::v2020::StreamCDC::new(std::io::BufReader::new(reader), CDC_MIN, CDC_AVG, CDC_MAX);
    let results: Vec<Result<Option<(OciDescriptor, bool)>>> = futures::stream::iter(chunker)
        .map(|chunk| async move {
            let chunk = chunk.with_context(|| format!("chunking {}", label.display()))?;
            if chunk.data.iter().all(|&b| b == 0) {
                return Ok(None); // hole — leave a gap, the pull fills it with zeros
            }
            let offset = start + chunk.offset;
            let length = chunk.length as u64;
            let r = put_raw_chunk(
                client,
                http,
                rg,
                image,
                transparent,
                chunkmap,
                chunk.data,
                offset,
                length,
            )
            .await?;
            Ok(Some(r))
        })
        .buffer_unordered(CHUNK_CONCURRENCY)
        .collect()
        .await;
    results.into_iter().filter_map(Result::transpose).collect()
}

/// Flatten a name to a safe single path component for a scratch dir (no separators).
fn sanitize_component(name: &str) -> String {
    name.replace(['/', '\\'], "_")
}

/// Drive a registry future to completion from a sync entry point. The executor's
/// prepare/run path (and `main`) already run inside a tokio runtime, so this runs
/// the future on a dedicated OS thread with its own runtime — a nested
/// `Runtime::block_on` on the calling thread would panic. A multi-thread runtime
/// (+ its blocking pool) lets the push fan out chunk compression and uploads.
pub(crate) fn block_on<F>(fut: F) -> F::Output
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
/// construction `oci.rs` uses for the docker and launch paths (rustls, optional PEM CA,
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

    // CDC + per-chunk zstd, hole-aware: only the file's data extents are read and
    // chunked (the sparse free region — often most of the image — is skipped, the pull
    // recreates it as holes). Each extent's chunks compress + upload concurrently; layer
    // order is irrelevant (reassembly uses each chunk's offset annotation).
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
    let mut layers: Vec<OciDescriptor> = Vec::new();
    let (mut uploaded, mut skipped) = (0usize, 0usize);
    for (start, len) in file_data_extents(&ext4, total_size)? {
        // stream this data extent from the raw image file.
        let reader: Box<dyn std::io::Read + Send> = {
            let mut f = std::fs::File::open(&ext4)
                .with_context(|| format!("opening {}", ext4.display()))?;
            f.seek(SeekFrom::Start(start))?;
            Box::new(f.take(len))
        };
        for (desc, was_uploaded) in chunk_region(
            &client,
            http.as_ref(),
            rg,
            &image,
            transparent,
            chunkmap.as_deref(),
            reader,
            start,
            &ext4,
        )
        .await?
        {
            if was_uploaded {
                uploaded += 1;
            } else {
                skipped += 1;
            }
            layers.push(desc);
        }
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

    let boot_kind = image::read_boot_kind(dir).with_context(|| {
        format!(
            "bundle {}: unsupported boot.kind marker — re-push it",
            dir.display()
        )
    })?;
    // The image's runtime config, if the bundle dir carries the `runner.ext4.json` sidecar
    // a `vk build` writes next to its ext4. Carried in the manifest so the guest applies it
    // at boot without baking anything into the (byte-clean, dedup-friendly) rootfs.
    let run_config = std::fs::read(dir.join("runner.ext4.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let config = BundleConfig {
        total_size,
        chunk_count,
        boot_kind: image::boot_kind_tag(boot_kind).to_string(),
        compression: "zstd".to_string(),
        has_kernel,
        has_initrd,
        run_config,
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

/// Resolve `reference` to its manifest digest and ensure the bundle is present in its
/// digest-keyed cache dir (`state_dir/registry/<name>/<digest>/`), pulling it if absent.
/// Returns the cache dir, the resolved digest, and whether this call performed the pull (so
/// the caller GCs only after a fresh pull). Called by `resolve_async`, which now serves both
/// the primary `virtkit/` job image and a `virtkit/` service unit from one cache entry.
async fn ensure_bundle_pulled(
    client: &oci_client::Client,
    auth: &RegistryAuth,
    rg: &Registry,
    state_dir: &Path,
    name: &str,
    reference: &Reference,
) -> Result<(PathBuf, String, bool)> {
    // tag -> digest (or the @digest verbatim), so the cache is content-addressed.
    let digest = match reference {
        Reference::Digest(d) => d.clone(),
        Reference::Tag(tag) => {
            let image = make_ref(rg, name, tag)?;
            client
                .fetch_manifest_digest(&image, auth)
                .await
                .with_context(|| format!("resolving {name}:{tag} against {}", rg.repo))?
        }
    };
    let dir = state_dir
        .join("registry")
        .join(name)
        .join(digest.trim_start_matches("sha256:"));
    let pulled = if bundle_present(&dir) {
        false
    } else {
        let image = make_digest_ref(rg, name, &digest)?;
        pull_into(client, auth, &image, name, &digest, &dir).await?;
        true
    };
    Ok((dir, digest, pulled))
}

async fn resolve_async(
    cfg: &Config,
    state_dir: &Path,
    rg: &Registry,
    name: &str,
    reference: Reference,
) -> Result<(ResolvedImage, std::path::PathBuf)> {
    let (client, auth) = client(rg)?;
    let (dir, digest, pulled) =
        ensure_bundle_pulled(&client, &auth, rg, state_dir, name, &reference).await?;
    image::mark_used(&dir);
    if pulled {
        let registry_root = state_dir.join("registry");
        image::gc_idle(&registry_root, cfg.image_cache_idle());
        image::sweep_chunks(&registry_root);
    }
    let boot_kind = image::read_boot_kind(&dir).with_context(|| {
        format!("registry bundle {name}@{digest}: unsupported boot.kind marker — re-push it")
    })?;
    println!("virtkit: image {name}@{digest} (registry bundle, {boot_kind:?})");
    Ok((image::resolved_from_dir(&dir, boot_kind), dir))
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
    let out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&ext4)
        .with_context(|| format!("creating {}", ext4.display()))?;
    out.set_len(config.total_size)
        .with_context(|| format!("sizing {}", ext4.display()))?;

    // Reassemble the chunks concurrently: each in-flight chunk fetches (network or the
    // local cache), then decompresses + writes into its own disjoint slot on a blocking
    // thread. The per-chunk zstd decode is CPU-bound, so overlapping it with the other
    // fetches and decodes is the win. Writes use `pwrite`, so a shared `File` is safe.
    // A chunk is either compressed-digest (blob = zstd, decode here) or raw
    // (`transparent_zstd`: blob is the canonical raw bytes — the registry already
    // served them decompressed, so write as-is). Self-describing via media type; other
    // layers (kernel/initrd) are handled below.
    use futures::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const RESTORE_CONCURRENCY: usize = 16;
    let chunk_layers: Vec<OciDescriptor> = manifest
        .layers
        .iter()
        .filter(|l| {
            matches!(
                l.media_type.as_str(),
                CHUNK_MEDIA_TYPE | CHUNK_MEDIA_TYPE_RAW
            )
        })
        .cloned()
        .collect();
    // The chunk digests this bundle is made of. Record them into the staging bundle *now*,
    // before any chunk is fetched into the shared store, so a concurrent `sweep_chunks`
    // (which keys the live set off each present bundle's `chunks.list`) counts this in-flight
    // pull as live and never reclaims a chunk it is still reassembling from. `runner.ext4`
    // already exists, so the staging dir is a `base_dirs` entry from here on. A later cache
    // GC uses the same list to drop chunk blobs no cached bundle references any more.
    let chunk_hexes: Vec<String> = chunk_layers
        .iter()
        .map(|l| l.digest.trim_start_matches("sha256:").to_string())
        .collect();
    std::fs::write(tmp.join("chunks.list"), chunk_hexes.join("\n"))
        .context("writing the chunk manifest")?;
    let chunks_cache = chunks_cache_dir(dir);
    let out = std::sync::Arc::new(out);
    let fetched = AtomicUsize::new(0);
    let reused = AtomicUsize::new(0);
    let results: Vec<Result<()>> = futures::stream::iter(chunk_layers)
        .map(|layer| {
            let compressed = layer.media_type == CHUNK_MEDIA_TYPE;
            let out = std::sync::Arc::clone(&out);
            let ext4 = ext4.clone();
            let (fetched, reused, chunks_cache) = (&fetched, &reused, &chunks_cache);
            async move {
                let (offset, _len) = chunk_placement(&layer)?;
                let bytes =
                    pull_chunk(client, image, &layer, chunks_cache, fetched, reused).await?;
                let digest = layer.digest;
                tokio::task::spawn_blocking(move || -> Result<()> {
                    let raw = if compressed {
                        zstd::decode_all(&bytes[..])
                            .with_context(|| format!("zstd-decompressing chunk {digest}"))?
                    } else {
                        bytes
                    };
                    write_chunk_sparse(&out, offset, &raw)
                        .with_context(|| format!("writing a chunk into {}", ext4.display()))
                })
                .await
                .context("a chunk-reassembly worker panicked")?
            }
        })
        .buffer_unordered(RESTORE_CONCURRENCY)
        .collect()
        .await;
    for r in results {
        r?;
    }
    drop(out);
    let (fetched, reused) = (
        fetched.load(Ordering::Relaxed),
        reused.load(Ordering::Relaxed),
    );
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
    // Restore the runtime-config sidecar next to runner.ext4, so the boot applies the
    // image's Env/User without baking them into the rootfs (`image::resolved_from_dir`
    // reads it).
    if let Some(rc) = &config.run_config {
        std::fs::write(
            tmp.join("runner.ext4.json"),
            serde_json::to_vec_pretty(rc).context("serializing the bundle run config")?,
        )
        .context("writing the run-config sidecar")?;
    }
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
    fetched: &std::sync::atomic::AtomicUsize,
    reused: &std::sync::atomic::AtomicUsize,
) -> Result<Vec<u8>> {
    use std::sync::atomic::Ordering;
    let hex = layer.digest.trim_start_matches("sha256:");
    let cached = cache.join(hex);
    if let Ok(bytes) = std::fs::read(&cached) {
        reused.fetch_add(1, Ordering::Relaxed);
        return Ok(bytes);
    }
    let bytes = pull_blob_bytes(client, image, layer).await?;
    std::fs::create_dir_all(cache).with_context(|| format!("creating {}", cache.display()))?;
    // atomic-ish: write to a tmp sibling then rename, so a killed pull never leaves
    // a truncated file under the digest name (which would then be trusted blindly).
    let tmp = cache.join(format!("{hex}.tmp"));
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
    let _ = std::fs::rename(&tmp, &cached);
    fetched.fetch_add(1, Ordering::Relaxed);
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
///
/// A positioned write (`pwrite`, no shared file cursor), so parallel reassembly
/// workers can each fill their own chunk's disjoint slot concurrently.
fn write_chunk_sparse(out: &std::fs::File, offset: u64, raw: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    if raw.iter().all(|&b| b == 0) {
        return Ok(());
    }
    out.write_all_at(raw, offset)
}

/// Reassemble a bundle's chunks into their (disjoint) slots in parallel: each worker
/// claims the next layer and runs `place` on it, which decompresses the chunk and
/// writes it at its offset. The per-chunk zstd decode is the bottleneck, so this
/// scales with cores. Returns the first worker error, if any.
fn reassemble_parallel<F>(layers: &[OciDescriptor], place: F) -> Result<()>
where
    F: Fn(&OciDescriptor) -> Result<()> + Sync,
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let err: std::sync::Mutex<Option<anyhow::Error>> = std::sync::Mutex::new(None);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(layers.len().max(1));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= layers.len() {
                        break;
                    }
                    if let Err(e) = place(&layers[i]) {
                        let mut slot = err.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(e);
                        }
                        // stop the other workers from starting new chunks.
                        next.store(layers.len(), Ordering::Relaxed);
                        break;
                    }
                }
            });
        }
    });
    match err.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
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

/// A cached bundle is present and usable: runner.ext4 plus the boot marker (which
/// also records how to boot it).
fn bundle_present(dir: &Path) -> bool {
    dir.join("runner.ext4").is_file() && dir.join("boot.kind").is_file()
}

/// Record the boot flavour in the bundle (the `boot.kind` marker), so a cache
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

/// Probe `GET /v2/` for the [`TRANSPARENT_ZSTD_HEADER`] a cooperating `regserve`
/// advertises. Any failure — a dumb registry, a network/TLS error, a missing CA —
/// yields `false`: fall back to the compressed-digest path. Only called in auto mode
/// (`transparent_zstd` unset). Sends Basic auth: an authenticated vk-registry challenges
/// `/v2/` (401) like every other path, so an anonymous probe would just 401 and mis-detect
/// as `false`.
async fn detect_transparent_zstd(rg: &Registry, image: &OciReference) -> bool {
    let Ok(http) = http_client(rg) else {
        return false;
    };
    let scheme = if rg.insecure { "http" } else { "https" };
    let url = format!("{scheme}://{}/v2/", image.resolve_registry());
    let req = http.get(&url);
    let req = match basic_auth(rg) {
        Ok(Some((u, p))) => req.basic_auth(u, Some(p)),
        _ => req,
    };
    match req.send().await {
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

// ---- build-once lock (client of the vk-registry /lock API) ----

/// Lease TTL requested for a build-once lock; renewed by the heartbeat below.
const BUILD_LOCK_TTL: Duration = Duration::from_secs(30);
/// How long an acquire blocks for a peer to finish before giving up (then we build
/// uncoordinated rather than stall the build forever).
const BUILD_LOCK_WAIT: Duration = Duration::from_secs(3600);

/// The base URL (`scheme://authority`) of a remote vk-registry's lock endpoint, or
/// `None` for a local filesystem store (no lock server) — the authority is the repo
/// prefix up to its first `/`, scheme from `insecure`.
fn lock_base(rg: &Registry) -> Option<String> {
    if rg.local_root().is_some() {
        return None;
    }
    let repo = rg
        .repo
        .strip_prefix("http://")
        .or_else(|| rg.repo.strip_prefix("https://"))
        .unwrap_or(&rg.repo);
    let authority = repo.split('/').next().unwrap_or(repo);
    let scheme = if rg.insecure { "http" } else { "https" };
    Some(format!("{scheme}://{authority}"))
}

/// A held cross-runner build-once lock. Renews the lease on a background heartbeat until
/// dropped; `Drop` stops the heartbeat and releases the lock (best-effort).
pub struct BuildLock {
    inner: Option<BuildLockInner>,
}

struct BuildLockInner {
    client: Arc<vk_registry::LockClient>,
    held: vk_registry::Held,
    /// `(stopped, condvar)`: a Condvar (not a bare flag) so `Drop` wakes the heartbeat out
    /// of its wait at once instead of blocking a whole renew interval on `join`.
    stop: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    heartbeat: Option<std::thread::JoinHandle<()>>,
}

/// One acquire attempt on `key`, long-polling up to `wait` (`Duration::ZERO` tries once and
/// returns immediately). `None` if the wait elapsed with the key still held, or on any
/// transport error — the caller treats both as "not acquired".
fn acquire_once(
    client: &Arc<vk_registry::LockClient>,
    key: &str,
    holder: &str,
    wait: Duration,
) -> Option<vk_registry::Held> {
    let client = client.clone();
    let key = key.to_string();
    let holder = holder.to_string();
    block_on(async move { client.acquire(&key, BUILD_LOCK_TTL, wait, &holder).await })
        .ok()
        .flatten()
}

/// Acquire a build-once lock on `key` against the (remote) cache registry `rg`, so peers
/// building the same content-key don't duplicate the work. Returns `None` for a local
/// store (no lock server) or if acquisition fails/times out — the caller then builds
/// uncoordinated. Blocks until acquired or [`BUILD_LOCK_WAIT`].
///
/// The lease records this job's identity (`jobctx::job_identity`) as the holder, so a
/// peer waiting on the same key can name who owns the build. When the first (non-blocking)
/// attempt finds the key already held, `on_wait` is called once with that holder's identity
/// before parking — the caller uses it to show a "waiting for a concurrent build" message.
pub fn build_lock(rg: &Registry, key: &str, on_wait: &mut dyn FnMut(&str)) -> Option<BuildLock> {
    let base = lock_base(rg)?;
    let http = http_client(rg).ok()?;
    // Authenticate the lock API with the cache registry's own credentials — the /lock/
    // endpoint is gated like every other path, so a tokenless client 401s against an
    // auth-gated registry (no fleet-wide build-once serialization).
    let auth = match basic_auth(rg).ok().flatten() {
        Some((user, pass)) => vk_registry::ClientAuth::Basic { user, pass },
        None => vk_registry::ClientAuth::None,
    };
    let client = Arc::new(vk_registry::LockClient::new(base, auth, http));
    let identity = crate::jobctx::job_identity();

    // Try once without blocking; on contention, name the holder before we park on the wait.
    let held = match acquire_once(&client, key, &identity, Duration::ZERO) {
        Some(h) => h,
        None => {
            let who = block_on(client.holder(key));
            on_wait(who.as_deref().unwrap_or("another runner"));
            acquire_once(&client, key, &identity, BUILD_LOCK_WAIT)?
        }
    };

    // heartbeat: renew the lease on its own thread + runtime until stopped. The stop signal
    // is a Condvar so Drop wakes the wait immediately rather than blocking `join` for up to
    // a full renew interval.
    let stop = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let hb_client = client.clone();
    let hb_stop = stop.clone();
    let hb_held = vk_registry::Held {
        name: held.name.clone(),
        owner: held.owner.clone(),
    };
    let heartbeat = std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        let (lock, cvar) = &*hb_stop;
        loop {
            let mut stopped = lock.lock().unwrap();
            if !*stopped {
                // wait up to a third of the TTL, or until Drop signals stop.
                let (g, _) = cvar.wait_timeout(stopped, BUILD_LOCK_TTL / 3).unwrap();
                stopped = g;
            }
            if *stopped {
                break;
            }
            drop(stopped);
            // Best-effort: a lost lease (renew returns Ok(false)/Err — e.g. a pause exceeded
            // the TTL and a peer reacquired) just means the build proceeds uncoordinated;
            // correctness is unaffected, only cross-runner dedup. Not surfaced here to keep
            // the live build dashboard's terminal clean.
            let _ = rt.block_on(hb_client.renew(&hb_held, BUILD_LOCK_TTL));
        }
    });

    Some(BuildLock {
        inner: Some(BuildLockInner {
            client,
            held,
            stop,
            heartbeat: Some(heartbeat),
        }),
    })
}

impl Drop for BuildLock {
    fn drop(&mut self) {
        let Some(mut inner) = self.inner.take() else {
            return;
        };
        {
            let (lock, cvar) = &*inner.stop;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        if let Some(hb) = inner.heartbeat.take() {
            let _ = hb.join();
        }
        let client = inner.client;
        let held = inner.held;
        let _ = block_on(async move { client.release(&held).await });
    }
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

/// The builtin cache backend: the regserve content-addressed store accessed
/// in-process — no server, no port, no auth. Selected by `Registry::local_root`
/// (a path/`file://` repo).
/// Writes the exact on-disk state the HTTP server writes (transparent-zstd-form
/// manifests, adaptively compressed blobs), so a `vk registry serve` on the same
/// root serves what local builds pushed and vice versa. Every operation holds the
/// store lock shared for its whole check→reference window; `vk registry gc` takes
/// it exclusive (see `vk_registry::Store::lock_shared`).
mod local {
    use super::*;
    use vk_registry::Store;

    pub(super) fn exists(root: &Path, name: &str, tag: &str) -> bool {
        let inner = || -> Result<bool> {
            let store = Store::new(root.to_path_buf())?;
            let _lock = store.lock_shared()?;
            Ok(store.get_manifest(name, tag)?.is_some())
        };
        inner().unwrap_or(false)
    }

    pub(super) fn fetch_chunks(
        root: &Path,
        name: &str,
        tag: &str,
    ) -> Result<Option<(Vec<OciDescriptor>, u64)>> {
        let store = Store::new(root.to_path_buf())?;
        let _lock = store.lock_shared()?;
        let Some((_digest, manifest, config)) = manifest_and_config(&store, name, tag)? else {
            return Ok(None);
        };
        let chunks: Vec<OciDescriptor> = manifest
            .layers
            .into_iter()
            .filter(|l| {
                matches!(
                    l.media_type.as_str(),
                    CHUNK_MEDIA_TYPE | CHUNK_MEDIA_TYPE_RAW
                )
            })
            .collect();
        Ok(Some((chunks, config.total_size)))
    }

    pub(super) fn try_pull_ext4(
        root: &Path,
        name: &str,
        tag: &str,
        dest: &Path,
    ) -> Result<Option<String>> {
        let store = Store::new(root.to_path_buf())?;
        let _lock = store.lock_shared()?;
        let Some((digest, manifest, config)) = manifest_and_config(&store, name, tag)? else {
            return Ok(None);
        };
        // tmp sibling + rename: a failed reassembly never leaves a partial file at
        // `dest` (which the caller would boot). On a fully-cached build nothing has
        // created the destination dir yet.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp = dest.with_extension("pull.tmp");
        let out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        out.set_len(config.total_size)
            .with_context(|| format!("sizing {}", tmp.display()))?;
        reassemble_parallel(&manifest.layers, |layer| {
            // self-describing via media type: a raw-digest chunk's canonical bytes ARE
            // the data; a compressed-digest chunk's canonical bytes are a zstd frame.
            let compressed = match layer.media_type.as_str() {
                CHUNK_MEDIA_TYPE => true,
                CHUNK_MEDIA_TYPE_RAW => false,
                _ => return Ok(()),
            };
            let (offset, _len) = chunk_placement(layer)?;
            let hex = layer.digest.trim_start_matches("sha256:");
            let bytes = store.get_blob(hex)?.with_context(|| {
                format!(
                    "cached chunk {} missing from {}",
                    layer.digest,
                    root.display()
                )
            })?;
            let raw = if compressed {
                zstd::decode_all(&bytes[..])
                    .with_context(|| format!("zstd-decompressing chunk {}", layer.digest))?
            } else {
                bytes
            };
            write_chunk_sparse(&out, offset, &raw)
                .with_context(|| format!("writing a chunk into {}", tmp.display()))
        })?;
        drop(out);
        let _ = std::fs::remove_file(dest);
        std::fs::rename(&tmp, dest)
            .with_context(|| format!("placing pulled ext4 at {}", dest.display()))?;
        Ok(Some(digest))
    }

    pub(super) fn push_ext4(
        root: &Path,
        name: &str,
        tag: &str,
        ext4: &Path,
        boot_kind: &str,
    ) -> Result<String> {
        let store = Store::new(root.to_path_buf())?;
        let _lock = store.lock_shared()?;
        let total_size = std::fs::metadata(ext4)
            .with_context(|| format!("stat {}", ext4.display()))?
            .len();
        let mut layers: Vec<OciDescriptor> = Vec::new();
        // hole-aware like the HTTP push: only the data extents are read and chunked.
        for (start, len) in file_data_extents(ext4, total_size)? {
            let mut f =
                std::fs::File::open(ext4).with_context(|| format!("opening {}", ext4.display()))?;
            f.seek(SeekFrom::Start(start))?;
            chunk_region_into(&store, f.take(len), start, ext4, &mut layers)?;
        }
        put_bundle_manifest(&store, name, tag, layers, total_size, boot_kind)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn push_ext4_diff(
        root: &Path,
        name: &str,
        tag: &str,
        ext4: &Path,
        boot_kind: &str,
        total_size: u64,
        dirty: &[(u64, u64)],
        holes: &[(u64, u64)],
        parent_layers: &[OciDescriptor],
    ) -> Result<(Vec<OciDescriptor>, u64, String)> {
        let store = Store::new(root.to_path_buf())?;
        let _lock = store.lock_shared()?;
        // same shape as push_ext4_diff_async: reuse clean parent chunks, drop freed ones as
        // holes, re-chunk the dirty ones from the captured overlay, then chunk writes into
        // former holes.
        let mut q = crate::qcow2::Qcow2::open(ext4)?;
        let mut layers: Vec<OciDescriptor> = Vec::with_capacity(parent_layers.len());
        let mut covered: Vec<(u64, u64)> = Vec::with_capacity(parent_layers.len());
        for layer in parent_layers {
            let (offset, length) = chunk_placement(layer)?;
            covered.push((offset, length));
            let overlaps = |ranges: &[(u64, u64)]| {
                ranges
                    .iter()
                    .any(|&(ds, dl)| offset < ds + dl && ds < offset + length)
            };
            let is_dirty = overlaps(dirty);
            let is_hole = overlaps(holes);
            if !is_dirty && !is_hole {
                layers.push(layer.clone());
                continue;
            }
            // Written and/or partly freed: regenerate from the overlay, then force the
            // fully-freed sub-ranges to zero so a straddling chunk keeps its live bytes while a
            // hole never reassembles as the parent's stale data.
            let mut buf = vec![0u8; length as usize];
            q.read_at(offset, &mut buf).with_context(|| {
                format!("reading {length} bytes at {offset} from {}", ext4.display())
            })?;
            zero_ranges(&mut buf, offset, holes);
            if buf.iter().all(|&b| b == 0) {
                continue; // fully freed/zeroed since the parent — the pull leaves a hole
            }
            let digest = store.put_blob(&buf)?;
            layers.push(chunk_descriptor(
                CHUNK_MEDIA_TYPE_RAW,
                &digest,
                buf.len() as i64,
                offset,
                length,
            ));
        }
        let new_regions = if parent_layers.is_empty() {
            q.chain_data_extents()?
        } else {
            covered.sort_unstable();
            let mut dirty_sorted = dirty.to_vec();
            dirty_sorted.sort_unstable();
            subtract_extents(&dirty_sorted, &covered)
        };
        for (start, len) in new_regions {
            let reader =
                crate::qcow2::RegionReader::new(crate::qcow2::Qcow2::open(ext4)?, start, len);
            chunk_region_into(&store, reader, start, ext4, &mut layers)?;
        }
        let ret = layers.clone();
        let digest = put_bundle_manifest(&store, name, tag, layers, total_size, boot_kind)?;
        Ok((ret, total_size, digest))
    }

    /// FastCDC-chunk `reader` (a data region starting at `start`) into the store,
    /// appending a raw-digest descriptor per non-zero chunk — the local counterpart
    /// of `chunk_region` (the store handles compression and dedup).
    fn chunk_region_into(
        store: &Store,
        reader: impl Read,
        start: u64,
        label: &Path,
        layers: &mut Vec<OciDescriptor>,
    ) -> Result<()> {
        let chunker = fastcdc::v2020::StreamCDC::new(
            std::io::BufReader::new(reader),
            CDC_MIN,
            CDC_AVG,
            CDC_MAX,
        );
        for chunk in chunker {
            let chunk = chunk.with_context(|| format!("chunking {}", label.display()))?;
            if chunk.data.iter().all(|&b| b == 0) {
                continue; // hole — leave a gap, the pull fills it with zeros
            }
            let digest = store.put_blob(&chunk.data)?;
            layers.push(chunk_descriptor(
                CHUNK_MEDIA_TYPE_RAW,
                &digest,
                chunk.data.len() as i64,
                start + chunk.offset,
                chunk.length as u64,
            ));
        }
        Ok(())
    }

    /// Store the config blob + the bundle manifest and tag it — the local counterpart
    /// of the config/manifest tail of `push_async`/`push_ext4_diff_async`, producing
    /// the identical manifest JSON. Returns the manifest digest.
    fn put_bundle_manifest(
        store: &Store,
        name: &str,
        tag: &str,
        layers: Vec<OciDescriptor>,
        total_size: u64,
        boot_kind: &str,
    ) -> Result<String> {
        let config = BundleConfig {
            total_size,
            chunk_count: layers.len(),
            boot_kind: boot_kind.to_string(),
            compression: "zstd".to_string(),
            has_kernel: false,
            has_initrd: false,
            run_config: None,
        };
        let config_json = serde_json::to_vec(&config).context("serializing the bundle config")?;
        let config_digest = store.put_blob(&config_json)?;
        let config_desc = OciDescriptor {
            media_type: CONFIG_MEDIA_TYPE.to_string(),
            digest: config_digest,
            size: config_json.len() as i64,
            ..Default::default()
        };
        let manifest = OciImageManifest {
            schema_version: 2,
            media_type: Some(OCI_IMAGE_MEDIA_TYPE.to_string()),
            artifact_type: Some(ARTIFACT_TYPE.to_string()),
            config: config_desc,
            layers,
            subject: None,
            annotations: None,
        };
        let body = serde_json::to_vec(&manifest).context("serializing the bundle manifest")?;
        store.put_manifest(name, tag, OCI_IMAGE_MEDIA_TYPE, &body)
    }

    /// Resolve `<name>:<tag>` to its parsed manifest + bundle config, `None` when the
    /// tag is absent. A hit bumps the tag's mtime (the gc retention record).
    fn manifest_and_config(
        store: &Store,
        name: &str,
        tag: &str,
    ) -> Result<Option<(String, OciImageManifest, BundleConfig)>> {
        let Some((digest, bytes, _ctype)) = store.get_manifest(name, tag)? else {
            return Ok(None);
        };
        let manifest: OciImageManifest =
            serde_json::from_slice(&bytes).context("parsing the bundle manifest")?;
        let hex = manifest
            .config
            .digest
            .trim_start_matches("sha256:")
            .to_string();
        let config = store
            .get_blob(&hex)?
            .with_context(|| format!("bundle config blob {} missing", manifest.config.digest))?;
        let config: BundleConfig =
            serde_json::from_slice(&config).context("parsing the bundle config blob")?;
        Ok(Some((digest, manifest, config)))
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

    #[test]
    fn bundle_config_round_trips_run_config() {
        use vk_core::runcfg::RunConfig;
        let rc = RunConfig {
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            user: "app".into(),
            ..Default::default()
        };
        let cfg = BundleConfig {
            total_size: 4096,
            chunk_count: 2,
            boot_kind: "generic-disk".into(),
            compression: "zstd".into(),
            has_kernel: false,
            has_initrd: false,
            run_config: Some(rc.clone()),
        };
        // the config blob push writes and pull reads must preserve run_config verbatim.
        let json = serde_json::to_vec(&cfg).unwrap();
        let back: BundleConfig = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.run_config, Some(rc));

        // an older bundle's config (no run_config key) still decodes, as None.
        let legacy = serde_json::json!({
            "total_size": 4096, "chunk_count": 2, "boot_kind": "generic-disk",
            "compression": "zstd", "has_kernel": false, "has_initrd": false,
        });
        let back: BundleConfig = serde_json::from_value(legacy).unwrap();
        assert_eq!(back.run_config, None);
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

    /// A `Registry` whose repo is a path routes to the local store backend.
    fn local_registry(root: &Path) -> Registry {
        Registry::for_share(
            root.display().to_string(),
            false,
            None,
            String::new(),
            None,
            None,
        )
    }

    /// Full local-backend round-trip through the PUBLIC dispatch: push a sparse
    /// image into a store-dir `Registry`, then exists → fetch_chunks → pull. The
    /// reassembly is byte-identical and the hole survives (never densified), all
    /// in-process — no server.
    #[test]
    fn local_store_roundtrip_is_sparse_and_byte_exact() {
        let root = std::env::temp_dir().join(format!("vk-localreg-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rg = local_registry(&root);
        assert!(rg.local_root().is_some(), "a path repo must route local");

        // 8 MiB data | 32 MiB hole | 8 MiB data, written sparsely.
        let head = pseudo_random(8 << 20, 0xc0ffee);
        let tail = pseudo_random(8 << 20, 0xbeef);
        let total = (48u64) << 20;
        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.ext4");
        {
            use std::os::unix::fs::FileExt;
            let f = std::fs::File::create(&src).unwrap();
            f.set_len(total).unwrap();
            f.write_all_at(&head, 0).unwrap();
            f.write_all_at(&tail, 40 << 20).unwrap();
        }

        assert!(!exists(&rg, "dfcache", "k1"), "empty store has no tag");
        push_ext4(&rg, "dfcache", "k1", &src, "generic-disk").unwrap();
        assert!(exists(&rg, "dfcache", "k1"));
        let (chunks, size) = fetch_chunks(&rg, "dfcache", "k1").unwrap().expect("tagged");
        assert_eq!(size, total);
        assert!(chunks.len() > 1, "should split into several chunks");

        let dest = dir.join("dest.ext4");
        assert!(
            try_pull_ext4(&rg, "dfcache", "k1", &dest)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            std::fs::read(&src).unwrap(),
            "reassembly must match the source"
        );
        {
            use std::os::unix::fs::MetadataExt;
            let on_disk = std::fs::metadata(&dest).unwrap().blocks() * 512;
            assert!(
                on_disk + (8 << 20) < total,
                "expected a preserved hole: {on_disk} bytes on disk vs {total} logical"
            );
        }
        // an absent tag pulls nothing and reports false
        assert!(
            try_pull_ext4(&rg, "dfcache", "missing", &dir.join("no.ext4"))
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A local diff push over an untouched overlay reuses the clean parent chunk
    /// descriptors verbatim and still reassembles byte-exactly under the new tag.
    #[test]
    fn local_diff_push_reuses_clean_chunks() {
        let root = std::env::temp_dir().join(format!("vk-localreg-diff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rg = local_registry(&root);
        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();

        // dense 16 MiB base, pushed as the parent.
        let base = dir.join("base.ext4");
        std::fs::write(&base, pseudo_random(16 << 20, 0x1234)).unwrap();
        push_ext4(&rg, "dfcache", "parent", &base, "generic-disk").unwrap();
        let (parent_layers, total) = fetch_chunks(&rg, "dfcache", "parent").unwrap().unwrap();
        assert!(parent_layers.len() > 2, "need several chunks to test reuse");

        // an empty qcow2 overlay (no writes) with a small dirty range: the dirty
        // chunk re-reads identical bytes (dedup hit), the rest reuse verbatim.
        let overlay = dir.join("ovl.qcow2");
        crate::qcow2::create_overlay(&overlay, &base).unwrap();
        let dirty = [(0u64, 1u64 << 20)];
        let (layers, size, _digest) = push_ext4_diff(
            &rg,
            "dfcache",
            "child",
            &overlay,
            "generic-disk",
            total,
            &dirty,
            &[],
            &parent_layers,
        )
        .unwrap();
        assert_eq!(size, total);
        let reused = layers
            .iter()
            .filter(|l| parent_layers.iter().any(|p| p.digest == l.digest))
            .count();
        assert!(
            reused >= parent_layers.len() - 2,
            "clean chunks must be reused ({reused}/{})",
            parent_layers.len()
        );
        let dest = dir.join("child.ext4");
        assert!(
            try_pull_ext4(&rg, "dfcache", "child", &dest)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            std::fs::read(&base).unwrap(),
            "an untouched overlay's child must equal the base"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A hole (a discarded/trimmed region) must clear the parent's bytes there, not reuse
    /// them: even though the overlay still reads the base's data through its backing and the
    /// region is not dirty, passing it as a hole drops the covering parent chunks so the
    /// region reassembles as zeros.
    #[test]
    fn local_diff_push_holes_clear_parent_bytes() {
        let root = std::env::temp_dir().join(format!("vk-localreg-holes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rg = local_registry(&root);
        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();

        // dense 16 MiB base, pushed as the parent.
        let base = dir.join("base.ext4");
        std::fs::write(&base, pseudo_random(16 << 20, 0x51de)).unwrap();
        push_ext4(&rg, "hc", "parent", &base, "generic-disk").unwrap();
        let (parent_layers, total) = fetch_chunks(&rg, "hc", "parent").unwrap().unwrap();

        // an untouched overlay (reads base's bytes through its backing) with no dirty writes,
        // but one 64 KiB cluster freed at 4 MiB. That cluster lands inside a content-defined
        // parent chunk that also holds live bytes, so the chunk must be regenerated (not
        // dropped) with only the freed cluster zeroed — the whole rest of the image is unchanged.
        let overlay = dir.join("ovl.qcow2");
        crate::qcow2::create_overlay(&overlay, &base).unwrap();
        let hole = (4u64 << 20, 64u64 << 10);
        push_ext4_diff(
            &rg,
            "hc",
            "child",
            &overlay,
            "generic-disk",
            total,
            &[],     // nothing written
            &[hole], // freed since the parent
            &parent_layers,
        )
        .unwrap();

        let dest = dir.join("child.ext4");
        try_pull_ext4(&rg, "hc", "child", &dest).unwrap().unwrap();
        let child = std::fs::read(&dest).unwrap();
        let mut expected = std::fs::read(&base).unwrap();
        let (hs, hl) = (hole.0 as usize, hole.1 as usize);
        // The base was non-zero there, so zeroing the hole genuinely changes it...
        assert!(expected[hs..hs + hl].iter().any(|&b| b != 0));
        expected[hs..hs + hl].fill(0);
        // ...and the child equals the base with exactly the freed cluster zeroed: a straddling
        // chunk kept its live bytes (dropping it would have zeroed data around the hole too).
        assert_eq!(
            child, expected,
            "a hole must clear only the freed cluster, leaving every live byte intact"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// With no reusable parent manifest, a diff push must become a full qcow2-chain
    /// re-chunk. A dirty-only fallback would publish a partial image: the first
    /// FROM-scratch COPY/RUN would omit untouched ext4 metadata from its backing image.
    #[test]
    fn local_diff_push_without_parent_rechunks_full_chain() {
        let root =
            std::env::temp_dir().join(format!("vk-localreg-noparent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rg = local_registry(&root);
        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();

        let total = 8u64 << 20;
        let base = dir.join("base.ext4");
        {
            use std::os::unix::fs::FileExt;
            let f = std::fs::File::create(&base).unwrap();
            f.set_len(total).unwrap();
            f.write_all_at(&pseudo_random(128 << 10, 0x1111), 0)
                .unwrap();
            f.write_all_at(&pseudo_random(128 << 10, 0x2222), 4 << 20)
                .unwrap();
        }

        let overlay = dir.join("ovl.qcow2");
        crate::qcow2::create_overlay(&overlay, &base).unwrap();
        let (layers, size, _digest) = push_ext4_diff(
            &rg,
            "dfcache",
            "child",
            &overlay,
            "generic-disk",
            total,
            &[(0, 64 << 10)], // must not limit the no-parent fallback
            &[],              // no holes
            &[],              // no parent
        )
        .unwrap();
        assert_eq!(size, total);
        assert!(
            layers.iter().any(|l| {
                chunk_placement(l)
                    .map(|(off, _)| off >= 4 << 20)
                    .unwrap_or(false)
            }),
            "the no-parent fallback must include backing data outside dirty ranges"
        );

        let dest = dir.join("child.ext4");
        assert!(
            try_pull_ext4(&rg, "dfcache", "child", &dest)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            std::fs::read(&base).unwrap(),
            "a no-parent diff push must publish the full chain, not only dirty clusters"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Concurrent local-backend pushes and pulls against one store: several threads
    /// push the SAME image under distinct tags (every chunk blob collides), while
    /// puller threads grab each tag as soon as `exists` reports it. The write
    /// ordering (chunks → config → manifest → tag) means a visible tag is always
    /// fully materialized: every pull must succeed byte-exactly, mid-push or not.
    #[test]
    fn local_concurrent_push_pull_is_consistent() {
        let root = std::env::temp_dir().join(format!("vk-localreg-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rg = local_registry(&root);
        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.ext4");
        std::fs::write(&src, pseudo_random(6 << 20, 0xfeed)).unwrap();
        let want = std::fs::read(&src).unwrap();

        const PUSHERS: usize = 4;
        std::thread::scope(|s| {
            for t in 0..PUSHERS {
                let (rg, src) = (&rg, &src);
                s.spawn(move || {
                    push_ext4(rg, "dfcache", &format!("conc{t}"), src, "generic-disk").unwrap();
                });
            }
            for t in 0..PUSHERS {
                let (rg, dir, want) = (&rg, &dir, &want);
                s.spawn(move || {
                    let tag = format!("conc{t}");
                    // poll until the pusher publishes the tag, then pull immediately
                    // (racing the other pushers' blob/tag writes). Bounded so a dead
                    // pusher fails the test instead of hanging it.
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                    while !exists(rg, "dfcache", &tag) {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "tag {tag} never appeared"
                        );
                        std::thread::yield_now();
                    }
                    let dest = dir.join(format!("pull{t}.ext4"));
                    assert!(try_pull_ext4(rg, "dfcache", &tag, &dest).unwrap().is_some());
                    assert_eq!(
                        &std::fs::read(&dest).unwrap(),
                        want,
                        "a visible tag must pull back byte-exact"
                    );
                });
            }
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Concurrent DIFF-pushes and pulls against one store, with heterogeneous content that
    /// forces chunk sharing — the pattern a parallel multi-stage build hits: many stages
    /// forked from a common base, each diff-pushed and pulled while siblings race the same
    /// content-addressed blobs. Each image shares a prefix (chunks that dedup to the same
    /// blobs, so pushers collide on those same blob writes) and carries a distinct suffix
    /// (distinct blobs). A child is a diff over its base that reuses every parent chunk, so
    /// it must reconstruct the base exactly. Asserts the store stays consistent under the
    /// colliding writes — no torn or lost blob, every visible tag fully materialized — and
    /// that every pull comes back byte-exact.
    #[test]
    fn local_concurrent_diff_push_pull_is_byte_exact() {
        let root =
            std::env::temp_dir().join(format!("vk-localreg-diffconc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rg = local_registry(&root);
        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();

        const N: usize = 8;
        // shared 4 MiB prefix (identical chunks across all images) + a distinct 2 MiB suffix.
        let prefix = pseudo_random(4 << 20, 0x5eed);
        let bases: Vec<(std::path::PathBuf, Vec<u8>)> = (0..N)
            .map(|t| {
                let mut bytes = prefix.clone();
                bytes.extend_from_slice(&pseudo_random(2 << 20, 0x100 + t as u64));
                let p = dir.join(format!("base{t}.ext4"));
                std::fs::write(&p, &bytes).unwrap();
                (p, bytes)
            })
            .collect();

        std::thread::scope(|s| {
            // Pushers: publish each base, then diff-push an (empty) overlay child that reuses
            // all of its parent's chunks — so the child reconstructs the base verbatim.
            for (t, (base, _)) in bases.iter().enumerate() {
                let (rg, dir) = (&rg, &dir);
                s.spawn(move || {
                    push_ext4(rg, "dc", &format!("base{t}"), base, "generic-disk").unwrap();
                    let (parent, total) = fetch_chunks(rg, "dc", &format!("base{t}"))
                        .unwrap()
                        .unwrap();
                    let ovl = dir.join(format!("child{t}.qcow2"));
                    crate::qcow2::create_overlay(&ovl, base).unwrap();
                    let (layers, size, _d) = push_ext4_diff(
                        rg,
                        "dc",
                        &format!("child{t}"),
                        &ovl,
                        "generic-disk",
                        total,
                        &[], // untouched overlay: no dirty chunks, reuse the whole parent
                        &[], // no holes
                        &parent,
                    )
                    .unwrap();
                    assert_eq!(size, total);
                    assert!(
                        layers
                            .iter()
                            .all(|l| parent.iter().any(|p| p.digest == l.digest)),
                        "child{t}: a clean diff must reuse only parent chunks"
                    );
                });
            }
            // Pullers: grab each base and its child as they appear, asserting byte-exactness.
            for (t, (_, want)) in bases.iter().enumerate() {
                let (rg, dir) = (&rg, &dir);
                s.spawn(move || {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
                    for tag in [format!("base{t}"), format!("child{t}")] {
                        while !exists(rg, "dc", &tag) {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "tag {tag} never appeared"
                            );
                            std::thread::yield_now();
                        }
                        let dest = dir.join(format!("pull-{tag}.ext4"));
                        assert!(try_pull_ext4(rg, "dc", &tag, &dest).unwrap().is_some());
                        assert_eq!(
                            &std::fs::read(&dest).unwrap(),
                            want,
                            "{tag} must pull back byte-exact under concurrent diff-pushes"
                        );
                    }
                });
            }
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `vk registry gc` over a local-backend store: after one image's tag expires,
    /// gc sweeps its manifest/config/chunks but keeps the other image fully
    /// pullable — the mark phase walking the REAL manifests the backend writes.
    /// (The gc semantics themselves are covered in regserve tests; this guards the
    /// registry↔store manifest contract.)
    #[test]
    fn local_store_gc_keeps_live_image_pullable() {
        let day = std::time::Duration::from_secs(86_400);
        let root = std::env::temp_dir().join(format!("vk-localreg-gc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rg = local_registry(&root);
        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let live_src = dir.join("live.ext4");
        let dead_src = dir.join("dead.ext4");
        std::fs::write(&live_src, pseudo_random(6 << 20, 0xaaaa)).unwrap();
        std::fs::write(&dead_src, pseudo_random(6 << 20, 0xbbbb)).unwrap();
        push_ext4(&rg, "dfcache", "live", &live_src, "generic-disk").unwrap();
        push_ext4(&rg, "dfcache", "dead", &dead_src, "generic-disk").unwrap();

        // age the whole store past retention, then refresh only the live tag
        // (`exists` resolves it, which bumps its mtime — the retention record).
        let old = std::time::SystemTime::now() - day * 100;
        let mut stack = vec![root.join("blobs"), root.join("repos")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    std::fs::File::open(&p).unwrap().set_modified(old).unwrap();
                }
            }
        }
        assert!(exists(&rg, "dfcache", "live"));

        let store = vk_registry::Store::new(root.clone()).unwrap();
        let report = store.gc(day * 30, day, false).unwrap();
        assert_eq!(report.tags_dropped, 1);
        assert!(
            report.blobs_dropped > 0,
            "the dead image's chunks must free"
        );

        assert!(!exists(&rg, "dfcache", "dead"));
        let dest = dir.join("live-after-gc.ext4");
        assert!(
            try_pull_ext4(&rg, "dfcache", "live", &dest)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            std::fs::read(&live_src).unwrap(),
            "a gc must never break a live image"
        );
        let _ = std::fs::remove_dir_all(&root);
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
        let out = std::fs::OpenOptions::new()
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
            write_chunk_sparse(&out, chunk.offset, &back).unwrap();
        }
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

    /// `reassemble_parallel` fills disjoint chunk slots concurrently and comes back
    /// byte-for-byte identical to the source; a failing placer surfaces as the Err.
    #[test]
    fn reassemble_parallel_is_byte_exact_and_propagates_errors() {
        use std::collections::HashMap;

        // Tile a buffer into fixed 64 KiB chunks at contiguous, disjoint offsets.
        let data = pseudo_random(4 << 20, 0xfeed);
        let chunk = 64 << 10;
        let mut layers = Vec::new();
        let mut raw_by_digest: HashMap<String, Vec<u8>> = HashMap::new();
        for (i, slice) in data.chunks(chunk).enumerate() {
            let digest = format!("sha256:{i:064x}");
            raw_by_digest.insert(digest.clone(), slice.to_vec());
            layers.push(chunk_descriptor(
                "application/octet-stream",
                &digest,
                slice.len() as i64,
                (i * chunk) as u64,
                slice.len() as u64,
            ));
        }
        assert!(
            layers.len() > 4,
            "need several chunks to exercise the workers"
        );

        let path = std::env::temp_dir().join(format!(
            "virtkit-reassemble-parallel-{}.ext4",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        out.set_len(data.len() as u64).unwrap();

        reassemble_parallel(&layers, |layer| {
            let (offset, _len) = chunk_placement(layer)?;
            write_chunk_sparse(&out, offset, &raw_by_digest[&layer.digest])?;
            Ok(())
        })
        .unwrap();
        drop(out);

        assert_eq!(
            std::fs::read(&path).unwrap(),
            data,
            "parallel reassembly must match the input byte-for-byte"
        );
        let _ = std::fs::remove_file(&path);

        // A failing placer surfaces as the returned Err (the first error wins).
        let err = reassemble_parallel(&layers, |layer| anyhow::bail!("boom at {}", layer.digest))
            .unwrap_err();
        assert!(
            err.to_string().contains("boom at"),
            "expected the worker error to propagate, got: {err}"
        );
    }
}
