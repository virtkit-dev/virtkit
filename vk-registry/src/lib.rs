//! The `vk-registry` server library: a content-addressed OCI-distribution store plus the
//! HTTP server, pull-through relay, build-once lock, and client auth built on it.
//!
//! A minimal implementation of the OCI distribution v2 API — blob existence/upload
//! (chunked + monolithic) and manifest put/get — over a **content-addressed store on the
//! local filesystem**, so every client that points its `[registry]` at this server shares
//! one blob pool (the FastCDC+zstd dedup the client already does, now shared). `vk` links
//! this crate for its in-process `Store`; the `vk-registry` binary runs the server.
//!
//! Meant to run centrally and be shared by many runners: optional TLS (`tls_cert`/
//! `tls_key`) and client auth (a bearer token file, or HTTP Basic) gate it on a shared
//! network, and a loopback deployment can still run open. Install it as a `systemd --user`
//! service with `vk-registry install-service`. See `DESIGN.md` and the `config` module.
//!
//! Store layout under `--root` (default `$XDG_DATA_HOME/virtkit/registry`):
//!   blobs/sha256/<hex>            content-addressed blobs (chunks, configs,
//!                                 manifests, any kernel/initrd) — shared by all repos
//!   repos/<name>/tags/<tag>       file holding the tagged manifest's digest
//!   repos/<name>/manifests/<hex>  sidecar: that manifest's Content-Type
//!   uploads/<id>                  in-progress blob uploads (this process only)

use std::collections::{BTreeSet, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

pub mod auth;
pub mod client;
pub mod config;
pub mod lock;
pub mod relay;

pub use client::{ClientAuth, Held, LockClient};
pub use config::ServerConfig;

/// Everything a connection handler needs: the content-addressed store, the relay
/// upstreams (empty ⇒ a plain local registry, no mirroring), the build-once lock
/// authority, the client-auth scheme, and the optional TLS acceptor. Cheap to
/// clone-share via `Arc`.
pub struct ServerState {
    pub store: Arc<Store>,
    pub upstreams: Vec<relay::Upstream>,
    pub locks: lock::LockManager,
    pub auth: auth::Auth,
    pub tls: Option<tokio_rustls::TlsAcceptor>,
}

/// Default content type for a manifest whose Content-Type sidecar is missing.
const DEFAULT_MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Fixed zstd level: identical raw chunks must compress to identical bytes for a
/// compressed-digest chunk to dedup. Shared by the client push path (registry.rs),
/// the transparent-zstd upload, and this store's adaptive storage compression.
pub const ZSTD_LEVEL: i32 = 1;

/// Capability header a cooperating server sets on its `GET /v2/` response, so an
/// auto-mode client knows it may push transparent-zstd (uncompressed-digest) chunks.
/// Absent on any dumb OCI registry.
pub const TRANSPARENT_ZSTD_HEADER: &str = "x-virtkit-transparent-zstd";

/// zstd-compress `raw`, embedding the decompressed size in the frame header so the
/// registry can report a canonical `Content-Length` on HEAD without decompressing
/// (`zstd::encode_all` omits the content size). Shared by the transparent-zstd client
/// push and this store's storage compression.
pub fn zstd_with_size(raw: &[u8]) -> Result<Vec<u8>> {
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

/// The on-disk content-addressed store. Shared by the HTTP handlers below and the
/// in-process build-cache backend (`registry::local`), so both write identical
/// on-disk state. Cheap to clone-share via `Arc`.
pub struct Store {
    root: PathBuf,
    /// monotonic upload-id source (unique within this server process)
    next_upload: AtomicU64,
}

impl Store {
    /// The store at `root`, its layout created if this is the first use — for the write
    /// paths, and for the in-process build cache, whose reads share the root it pushes to.
    /// Looking at a store without bringing one into being is [`Store::open`].
    pub fn new(root: PathBuf) -> Result<Self> {
        for sub in ["blobs/sha256", "blobs/zstd", "uploads", "repos"] {
            let p = root.join(sub);
            std::fs::create_dir_all(&p).with_context(|| format!("creating {}", p.display()))?;
        }
        Ok(Store::at(root))
    }

    /// The store at `root` if there is one, creating nothing — for [`status`] and [`gc`],
    /// which look at a store rather than start one. Asking a host what it has cached must
    /// not be what gives it a store: a directory tree conjured by a report is one nothing
    /// will ever write to, under a path the user may only have mistyped. `Ok(None)` when
    /// nothing is there, which the caller reports as the absence it is; a root that cannot
    /// be read at all is an error, since reporting it as absent is the same silence.
    ///
    /// A store is recognized by `blobs/sha256/`, the first directory [`Store::new`] makes
    /// and so one every store has — rather than by `root` being a directory, which any
    /// mistyped `--root` also is, or by `blobs/` alone, which something else may happen to
    /// carry. What the marker decides is whether this store's lockfile is dropped into a
    /// directory that is not one.
    pub fn open(root: &Path) -> Result<Option<Self>> {
        let marker = root.join("blobs/sha256");
        match std::fs::metadata(&marker) {
            // There but not a directory is not a store either.
            Ok(m) => Ok(m.is_dir().then(|| Store::at(root.to_path_buf()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => {
                Err(e).with_context(|| format!("looking for a store at {}", marker.display()))
            }
        }
    }

    /// A handle on the store at `root`, whose layout is [`Store::new`]'s to create and
    /// [`Store::open`]'s to have found.
    fn at(root: PathBuf) -> Self {
        Store {
            root,
            next_upload: AtomicU64::new(0),
        }
    }

    /// Identity blob: the stored bytes ARE the canonical (digested) bytes.
    fn blob_path(&self, hex: &str) -> PathBuf {
        self.root.join("blobs/sha256").join(hex)
    }
    /// The identity-store destination for a blob, and the temp/uploads directory to
    /// stage it in — for the relay, which streams a pulled blob to disk (bounded memory)
    /// then promotes it here. Both are under the store root, so a rename is atomic.
    pub fn identity_blob_path(&self, hex: &str) -> PathBuf {
        self.blob_path(hex)
    }
    pub fn uploads_dir(&self) -> PathBuf {
        self.root.join("uploads")
    }
    /// Transparently-compressed blob: the stored bytes are a zstd frame; the canonical
    /// (digested) bytes are its decompression (hex = sha256 of the decompressed form).
    fn zstd_blob_path(&self, hex: &str) -> PathBuf {
        self.root.join("blobs/zstd").join(hex)
    }
    /// Locate a blob by digest hex: `(path, stored_as_zstd)`. Checks the zstd store
    /// then the identity store.
    fn find_blob(&self, hex: &str) -> Option<(PathBuf, bool)> {
        let z = self.zstd_blob_path(hex);
        if z.is_file() {
            return Some((z, true));
        }
        let p = self.blob_path(hex);
        p.is_file().then_some((p, false))
    }
    fn upload_path(&self, id: &str) -> PathBuf {
        self.root.join("uploads").join(id)
    }
    fn tag_path(&self, name: &str, tag: &str) -> PathBuf {
        self.root.join("repos").join(name).join("tags").join(tag)
    }
    fn manifest_type_path(&self, name: &str, hex: &str) -> PathBuf {
        self.root
            .join("repos")
            .join(name)
            .join("manifests")
            .join(hex)
    }

    /// Whether the blob (either form) is present. A hit bumps the blob's mtime: the
    /// caller is about to *reference* it without rewriting it (the dedup fast path),
    /// and that mtime is what the [`Store::gc`] sweep honours.
    pub fn has_blob(&self, hex: &str) -> bool {
        match self.find_blob(hex) {
            Some((path, _)) => {
                touch(&path);
                true
            }
            None => false,
        }
    }

    /// Store raw canonical bytes content-addressed, adaptively compressed (the zstd
    /// form only when it actually shrinks). Idempotent: a present blob is only
    /// touched, and the compression is skipped. Returns the `sha256:<hex>` digest.
    pub fn put_blob(&self, raw: &[u8]) -> Result<String> {
        let hex = sha256_hex_raw(raw);
        self.put_blob_at(&hex, raw)?;
        Ok(format!("sha256:{hex}"))
    }

    /// [`Store::put_blob`] under an already-known digest hex — the HTTP push path,
    /// where the client's digest is trusted (see `finish_upload`).
    fn put_blob_at(&self, hex: &str, raw: &[u8]) -> Result<()> {
        if !self.has_blob(hex) {
            let z = zstd_with_size(raw)?;
            if z.len() < raw.len() {
                atomic_write(&self.zstd_blob_path(hex), &z)?;
            } else {
                atomic_write(&self.blob_path(hex), raw)?;
            }
        }
        Ok(())
    }

    /// The canonical bytes of a blob (decompressing the zstd form), `None` if absent.
    pub fn get_blob(&self, hex: &str) -> Result<Option<Vec<u8>>> {
        let Some((path, is_zstd)) = self.find_blob(hex) else {
            return Ok(None);
        };
        let stored = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if is_zstd {
            return Ok(Some(
                zstd::decode_all(&stored[..]).context("decompressing a stored blob")?,
            ));
        }
        Ok(Some(stored))
    }

    /// Store manifest bytes (content-addressed) + the Content-Type sidecar, and point
    /// the tag at it (a digest reference is already self-describing). Returns the
    /// manifest digest.
    pub fn put_manifest(
        &self,
        name: &str,
        reference: &str,
        ctype: &str,
        body: &[u8],
    ) -> Result<String> {
        if !valid_name(name) || !valid_reference(reference) {
            bail!("invalid manifest reference {name}:{reference}");
        }
        let digest = format!("sha256:{}", sha256_hex_raw(body));
        let hex = &digest[7..];
        let dest = self.blob_path(hex);
        if dest.exists() {
            // a re-push is a dedup reference — the usage record the gc grace keys on
            touch(&dest);
        } else {
            atomic_write(&dest, body)?;
        }
        atomic_write(&self.manifest_type_path(name, hex), ctype.as_bytes())?;
        if !reference.starts_with("sha256:") {
            atomic_write(&self.tag_path(name, reference), digest.as_bytes())?;
        }
        Ok(digest)
    }

    /// Resolve a tag or digest reference to `(digest, manifest bytes, content type)`,
    /// `None` if absent. A tag hit bumps the tag file's mtime — the "last used"
    /// record [`Store::gc`] keys its tag retention on.
    pub fn get_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<Option<(String, Vec<u8>, String)>> {
        if !valid_name(name) || !valid_reference(reference) {
            return Ok(None);
        }
        let digest = if reference.starts_with("sha256:") {
            reference.to_string()
        } else {
            let tag = self.tag_path(name, reference);
            match std::fs::read_to_string(&tag) {
                Ok(d) => {
                    touch(&tag);
                    d.trim().to_string()
                }
                Err(_) => return Ok(None),
            }
        };
        let hex = digest.trim_start_matches("sha256:");
        let Ok(data) = std::fs::read(self.blob_path(hex)) else {
            return Ok(None);
        };
        let ctype = std::fs::read_to_string(self.manifest_type_path(name, hex))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| DEFAULT_MANIFEST_TYPE.to_string());
        Ok(Some((digest, data, ctype)))
    }

    /// Take the store lock shared — held by every writer/reader across its whole
    /// check→reference window (a local push: first `has_blob` through
    /// `put_manifest`), so a `vk registry gc` holding it *exclusive* can never
    /// delete a blob between a dedup check and the manifest that references it.
    /// Shared holders never block each other. flock is advisory and
    /// filesystem-local — fine for `$XDG_DATA_HOME`; a store root on NFS is
    /// unsupported.
    pub fn lock_shared(&self) -> Result<LockGuard> {
        self.flock(libc::LOCK_SH)
    }

    /// Take the store lock exclusive (blocks until all shared holders drop) — the
    /// [`Store::gc`] lock; see [`Store::lock_shared`].
    pub fn lock_exclusive(&self) -> Result<LockGuard> {
        self.flock(libc::LOCK_EX)
    }

    fn flock(&self, op: libc::c_int) -> Result<LockGuard> {
        use std::os::unix::io::AsRawFd;
        let path = self.root.join(".lock");
        let f =
            std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        // SAFETY: the fd is owned by `f`, which the guard keeps alive; flock returns
        // 0 or -1/errno and blocks until the lock is granted.
        if unsafe { libc::flock(f.as_raw_fd(), op) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("locking {}", path.display()));
        }
        Ok(LockGuard { _file: f })
    }

    /// Garbage-collect the store, holding the lock exclusive (pushers briefly
    /// block; see [`Store::lock_shared`]). Tags idle past `retention` are dropped
    /// (tag mtime = last use). The surviving tags' manifests — plus digest-pinned
    /// manifests (a sidecar with no tag) whose blob is younger than `grace` —
    /// root the mark: their manifest, config and layer blobs are live. Everything
    /// else idle past `grace` is swept: unmarked blobs (the grace window protects
    /// multi-request HTTP pushes, whose HEAD hits bump blob mtimes but which hold
    /// no lock across requests), unrooted manifest sidecars, and stale `uploads/`
    /// (an alive push keeps appending, so its session file stays fresh). Orphaned
    /// `.tmp.*` files from a crashed `atomic_write` age out with the blob sweep.
    /// `dry_run` reports without removing anything.
    pub fn gc(&self, retention: Duration, grace: Duration, dry_run: bool) -> Result<GcReport> {
        let _lock = self.lock_exclusive()?;
        let now = SystemTime::now();
        // Idle = mtime older than the window. An unreadable mtime — or one in the
        // future — reads as fresh: never delete on uncertain evidence.
        let idle = |path: &Path, window: Duration| {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > window)
        };
        let remove = |path: &Path| -> Result<()> {
            if !dry_run {
                std::fs::remove_file(path)
                    .with_context(|| format!("removing {}", path.display()))?;
            }
            Ok(())
        };
        let mut report = GcReport::default();

        // drop idle tags; the survivors' manifest hexes root the mark phase.
        let mut roots: HashSet<String> = HashSet::new();
        for tags_dir in self.repo_dirs("tags") {
            for tag in dir_files(&tags_dir) {
                if idle(&tag, retention) {
                    remove(&tag)?;
                    report.tags_dropped += 1;
                } else if let Ok(d) = std::fs::read_to_string(&tag) {
                    roots.insert(d.trim().trim_start_matches("sha256:").to_string());
                }
            }
        }

        // manifest sidecars: rooted by a surviving tag, or by their own freshness
        // (digest-pinned); the rest drop, their manifest blob falling to the sweep.
        for man_dir in self.repo_dirs("manifests") {
            for sidecar in dir_files(&man_dir) {
                let Some(hex) = sidecar.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if roots.contains(hex) {
                    continue;
                }
                if let Some((blob, _)) = self.find_blob(hex)
                    && !idle(&blob, grace)
                {
                    roots.insert(hex.to_string());
                    continue;
                }
                remove(&sidecar)?;
                report.manifests_dropped += 1;
            }
        }

        // mark every blob a root manifest references. A parse failure aborts:
        // sweeping with incomplete marks would delete live data.
        let mut marked: HashSet<String> = HashSet::new();
        for hex in &roots {
            let Some(bytes) = self.get_blob(hex)? else {
                continue; // dangling tag: nothing left to keep alive
            };
            for child in manifest_digest_hexes(&bytes)
                .with_context(|| format!("parsing manifest {hex} for the gc mark"))?
            {
                marked.insert(child);
            }
            marked.insert(hex.clone());
        }

        // sweep unmarked blobs idle past the grace window, in both storage forms.
        for sub in ["blobs/sha256", "blobs/zstd"] {
            for blob in dir_files(&self.root.join(sub)) {
                let is_marked = blob
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| marked.contains(n));
                if is_marked || !idle(&blob, grace) {
                    continue;
                }
                report.bytes_freed += std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
                remove(&blob)?;
                report.blobs_dropped += 1;
            }
        }

        for upload in dir_files(&self.root.join("uploads")) {
            if idle(&upload, grace) {
                remove(&upload)?;
                report.uploads_dropped += 1;
            }
        }
        Ok(report)
    }

    /// Read-only usage snapshot: on-disk blob totals (both storage forms), in-flight
    /// uploads, and a per-repository breakdown — each repo's tag count, latest tag (by
    /// mtime), and logical size (the blobs its tagged manifests reference, counted once
    /// per repo). `logical_naive` (every reference, no dedup) over `referenced_ondisk`
    /// (the distinct referenced blobs' actual on-disk bytes) is the combined dedup+zstd
    /// packing factor. The size and packing figures cover tag-reachable manifests only;
    /// `total_manifests` counts every manifest sidecar, tagged or digest-pinned. Taken
    /// under the shared lock, so it never reads a store a gc is mid-sweep on.
    pub fn stats(&self) -> Result<StoreStats> {
        let _lock = self.lock_shared()?;
        let mut s = StoreStats::default();

        // physical: every stored blob, split by storage form.
        for (sub, count, bytes) in [
            ("blobs/sha256", &mut s.identity_blobs, &mut s.identity_bytes),
            ("blobs/zstd", &mut s.zstd_blobs, &mut s.zstd_bytes),
        ] {
            for blob in dir_files(&self.root.join(sub)) {
                *count += 1;
                *bytes += std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
            }
        }
        for up in dir_files(&self.root.join("uploads")) {
            s.uploads += 1;
            s.upload_bytes += std::fs::metadata(&up).map(|m| m.len()).unwrap_or(0);
        }

        // per-repo content: a repo is a dir under repos/ holding a tags/ + manifests/.
        let base = self.root.join("repos");
        let mut repo_dirs: BTreeSet<PathBuf> = BTreeSet::new();
        for kind in ["tags", "manifests"] {
            for d in self.repo_dirs(kind) {
                if let Some(p) = d.parent() {
                    repo_dirs.insert(p.to_path_buf());
                }
            }
        }
        // distinct blobs referenced by any manifest, so `referenced_ondisk` counts each
        // one's real on-disk size once (the manifest blob itself included — it is live too).
        let mut referenced: HashSet<String> = HashSet::new();
        let ondisk = |hex: &str, s: &mut StoreStats, seen: &mut HashSet<String>| {
            if seen.insert(hex.to_string())
                && let Some((path, _)) = self.find_blob(hex)
            {
                s.referenced_ondisk += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            }
        };
        for repo_dir in repo_dirs {
            let name = repo_dir
                .strip_prefix(&base)
                .unwrap_or(repo_dir.as_path())
                .to_string_lossy()
                .into_owned();
            let mut r = RepoStat {
                name,
                ..Default::default()
            };
            r.manifests = dir_files(&repo_dir.join("manifests")).len();
            // distinct manifests reachable from this repo's tags, and the latest tag.
            let mut manifest_hexes: BTreeSet<String> = BTreeSet::new();
            let mut latest: Option<(SystemTime, String)> = None;
            for tag in dir_files(&repo_dir.join("tags")) {
                r.tags += 1;
                if let Ok(digest) = std::fs::read_to_string(&tag) {
                    manifest_hexes.insert(digest.trim().trim_start_matches("sha256:").to_string());
                }
                if let Some(n) = tag.file_name().and_then(|n| n.to_str()) {
                    let m = std::fs::metadata(&tag)
                        .and_then(|m| m.modified())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    if latest.as_ref().is_none_or(|(t, _)| m > *t) {
                        latest = Some((m, n.to_string()));
                    }
                }
            }
            r.latest_tag = latest.map(|(_, n)| n);
            // logical (uncompressed) size of the blobs those manifests reference, deduped
            // within the repo; `logical_naive`/`referenced_ondisk` accumulate globally.
            let mut repo_seen: HashSet<String> = HashSet::new();
            for hex in &manifest_hexes {
                ondisk(hex, &mut s, &mut referenced);
                let Some(bytes) = self.get_blob(hex)? else {
                    continue;
                };
                // the manifest blob is in `referenced_ondisk` (above), so its own bytes
                // count toward the logical total too — keeps the packing ratio symmetric.
                s.logical_naive += bytes.len() as u64;
                for (dhex, size) in manifest_blob_sizes(&bytes) {
                    s.logical_naive += size;
                    ondisk(&dhex, &mut s, &mut referenced);
                    if repo_seen.insert(dhex) {
                        r.logical_bytes += size;
                    }
                }
            }
            s.total_tags += r.tags;
            s.total_manifests += r.manifests;
            s.repos.push(r);
        }
        Ok(s)
    }

    /// Every `tags/` or `manifests/` directory under `repos/` — repo names may be
    /// nested (`bundles/appbuilder`), so walk down to the layout dirs. A repo path
    /// *component* itself named `tags`/`manifests` would be indistinguishable from
    /// the layout and is not supported by the gc.
    fn repo_dirs(&self, kind: &str) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.join("repos")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if !p.is_dir() {
                    continue;
                }
                if p.file_name().is_some_and(|n| n == kind) {
                    out.push(p);
                } else {
                    stack.push(p);
                }
            }
        }
        out
    }
}

/// What a [`Store::gc`] pass removed (or, on a dry run, would remove).
#[derive(Default)]
pub struct GcReport {
    pub tags_dropped: usize,
    pub manifests_dropped: usize,
    pub blobs_dropped: usize,
    /// stored (on-disk) bytes of the dropped blobs
    pub bytes_freed: u64,
    pub uploads_dropped: usize,
}

/// A [`Store::stats`] snapshot: on-disk totals plus a per-repo breakdown.
#[derive(Default)]
pub struct StoreStats {
    pub identity_blobs: usize,
    pub identity_bytes: u64,
    pub zstd_blobs: usize,
    pub zstd_bytes: u64,
    pub uploads: usize,
    pub upload_bytes: u64,
    pub total_tags: usize,
    pub total_manifests: usize,
    /// each tagged manifest plus its config/layer references, summed with no dedup — the
    /// logical (uncompressed) content the store stands in for
    pub logical_naive: u64,
    /// the distinct referenced blobs' actual on-disk bytes (compressed, deduped);
    /// `logical_naive` over this is the combined dedup+zstd packing factor
    pub referenced_ondisk: u64,
    pub repos: Vec<RepoStat>,
}

/// One repository's line in a [`StoreStats`].
#[derive(Default)]
pub struct RepoStat {
    pub name: String,
    pub tags: usize,
    pub manifests: usize,
    pub latest_tag: Option<String>,
    /// size of the blobs this repo's tagged manifests reference, deduped within the repo
    pub logical_bytes: u64,
}

/// The digest hexes a manifest references: its config and every layer, read
/// structurally (`config.digest`, `layers[].digest`) so the gc mark needs no OCI
/// types and tolerates media types it doesn't know. An image index (`manifests[]`)
/// is an error: its children live behind another level of manifests the mark
/// doesn't walk, so the gc must refuse rather than sweep them.
fn manifest_digest_hexes(manifest: &[u8]) -> Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_slice(manifest).context("not JSON")?;
    if v.pointer("/manifests").is_some() {
        bail!("image indexes are not supported");
    }
    let layers = v.pointer("/layers").and_then(|l| l.as_array());
    Ok(std::iter::once(v.pointer("/config/digest"))
        .chain(layers.into_iter().flatten().map(|l| l.pointer("/digest")))
        .filter_map(|d| d?.as_str())
        .map(|d| d.trim_start_matches("sha256:").to_string())
        .collect())
}

/// `(digest hex, descriptor size)` for a manifest's config and every layer, read
/// structurally like [`manifest_digest_hexes`]. Tolerant: an unparseable blob yields
/// nothing (a status read must not fail on one odd manifest), and a missing `size`
/// counts as 0.
fn manifest_blob_sizes(manifest: &[u8]) -> Vec<(String, u64)> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(manifest) else {
        return Vec::new();
    };
    let layers = v.pointer("/layers").and_then(|l| l.as_array());
    std::iter::once(v.pointer("/config"))
        .chain(layers.into_iter().flatten().map(Some))
        .flatten()
        .filter_map(|d| {
            let hex = d.pointer("/digest").and_then(|x| x.as_str())?;
            let size = d
                .pointer("/size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            Some((hex.trim_start_matches("sha256:").to_string(), size))
        })
        .collect()
}

/// The files directly inside `dir` (a missing dir reads as empty; subdirectories
/// are skipped).
fn dir_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect()
}

/// A held store lock (see [`Store::lock_shared`]); released when dropped (flock
/// releases on the last close of the fd).
pub struct LockGuard {
    _file: std::fs::File,
}

/// Bump a file's mtime to now — the usage record [`Store::gc`] reads (blob: last
/// written or dedup-referenced; tag: last used). Best-effort: a failed touch only
/// ages the entry early.
fn touch(path: &Path) {
    let _ = std::fs::File::open(path).and_then(|f| f.set_modified(std::time::SystemTime::now()));
}

/// Run a plain local registry until the process is stopped (no relay upstreams).
/// `addr` is the listen address; `root` is the store directory.
pub async fn serve(addr: SocketAddr, root: PathBuf) -> Result<()> {
    serve_config(ServerConfig::local(addr, root)).await
}

/// Run the registry from a full [`ServerConfig`] (relay upstreams, listen address,
/// store root).
pub async fn serve_config(cfg: ServerConfig) -> Result<()> {
    let addr = cfg.addr;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    let tls = cfg.build_tls()?;
    let mut state = cfg.into_state()?;
    state.tls = tls;
    serve_on(listener, Arc::new(state)).await
}

/// The line a server announces itself with: the store it serves, whether it mirrors, and
/// the URL to reach it at. Built as a string, and from the facts rather than the state, so
/// a test can hold the scheme to whether there is TLS — this line is what an operator reads
/// to confirm TLS came up, and naming the wrong scheme is worse than naming none.
fn banner(root: &Path, upstreams: usize, tls: bool, addr: SocketAddr) -> String {
    let mode = match upstreams {
        0 => "local".to_string(),
        n => format!("mirror ({n} upstream(s))"),
    };
    format!(
        "vk-registry: serving {} [{mode}] on {}://{addr}",
        root.display(),
        scheme(tls)
    )
}

/// The URL scheme a server with (or without) TLS is reached over. One place, because every
/// line that prints a virtkit registry's own URL has to agree with the acceptor it has.
fn scheme(tls: bool) -> &'static str {
    if tls { "https" } else { "http" }
}

/// Serve on an already-bound listener (so the caller can pick an ephemeral port and
/// learn it first). The store is content-addressed and written atomically, so several
/// servers may serve the same `root` concurrently.
pub async fn serve_on(listener: TcpListener, state: Arc<ServerState>) -> Result<()> {
    if let Ok(addr) = listener.local_addr() {
        eprintln!(
            "{}",
            banner(
                &state.store.root,
                state.upstreams.len(),
                state.tls.is_some(),
                addr
            )
        );
    }
    loop {
        let (stream, _peer) = listener.accept().await.context("accept")?;
        let state = state.clone();
        tokio::spawn(async move {
            match &state.tls {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls) => serve_conn(TokioIo::new(tls), state.clone()).await,
                    Err(e) => eprintln!("vk-registry: TLS handshake error: {e}"),
                },
                None => serve_conn(TokioIo::new(stream), state.clone()).await,
            }
        });
    }
}

/// Serve one HTTP/1 connection over any transport (plain TCP or TLS).
async fn serve_conn<I>(io: I, state: Arc<ServerState>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| handle(req, state.clone()));
    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
        eprintln!("vk-registry: connection error: {e}");
    }
}

/// Wrap `route`, turning any internal error into a 500 (a handler never fails the
/// connection).
async fn handle(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(route(req, state).await.unwrap_or_else(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            &format!("{e:#}"),
        )
    }))
}

async fn route(req: Request<Incoming>, state: Arc<ServerState>) -> Result<Response<Full<Bytes>>> {
    // Client auth (when configured) on every path, including the `/v2/` version probe.
    // Returning 401 + WWW-Authenticate on `/v2/` is exactly how OCI clients discover they
    // must authenticate (oci_client's store_auth_if_needed probes `/v2/`): leaving it open
    // (200) makes the client assume no auth is needed and then 401 on the real blob
    // requests. Capability detection (transparent-zstd) authenticates its own `/v2/` probe.
    if state.auth.enabled() && !state.auth.allows(&req) {
        return Ok(state.auth.challenge());
    }

    // The build-once lock API lives under `/lock/<action>` (all POST), outside the
    // `/v2/` OCI namespace; names are `?name=` params.
    if req.uri().path().starts_with("/lock/") {
        return lock::route(&state.locks, req).await;
    }
    let store = state.store.clone();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    // transparent-zstd negotiation: a PUT body may already be a zstd frame
    // (`Content-Encoding: zstd`), and a GET may accept the stored frame verbatim
    // (`Accept-Encoding: …zstd…`).
    let put_is_zstd = header_has(&req, hyper::header::CONTENT_ENCODING, "zstd");
    let accept_zstd = header_has(&req, hyper::header::ACCEPT_ENCODING, "zstd");

    // GET /v2/ — the API version probe. We also advertise transparent-zstd support
    // so an auto-mode client uploads uncompressed-digest chunks (this store stores
    // them compressed and serves canonical bytes to plain clients).
    if path == "/v2" || path == "/v2/" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Distribution-Api-Version", "registry/2.0")
            .header(TRANSPARENT_ZSTD_HEADER, "1")
            .body(Full::new(Bytes::from_static(b"{}")))
            .map_err(Into::into);
    }
    let Some(rest) = path.strip_prefix("/v2/") else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "not a v2 path",
        ));
    };

    // <name>/blobs/uploads[/<id>] — checked before the bare /blobs/ form, which it
    // also contains. POST starts a session; PATCH appends; PUT?digest finalizes.
    if let Some(idx) = rest.rfind("/blobs/uploads") {
        let name = &rest[..idx];
        let after = rest[idx + "/blobs/uploads".len()..].trim_matches('/');
        if !valid_name(name) {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                name,
            ));
        }
        return match method {
            Method::POST => start_upload(&store, name),
            Method::PATCH => {
                let body = collect(req).await?;
                patch_upload(&store, name, after, &body)
            }
            Method::PUT => {
                let body = collect(req).await?;
                finish_upload(&store, name, after, &query, &body, put_is_zstd)
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "",
            )),
        };
    }

    // <name>/blobs/<digest> — HEAD (exists) / GET (fetch).
    if let Some(idx) = rest.rfind("/blobs/") {
        let name = &rest[..idx];
        let digest = &rest[idx + "/blobs/".len()..];
        if !valid_name(name) || !valid_digest(digest) {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                digest,
            ));
        }
        let head = method == Method::HEAD;
        return match method {
            Method::GET | Method::HEAD => {
                let local = get_blob(&store, digest, head, accept_zstd)?;
                if local.status() == StatusCode::NOT_FOUND && !state.upstreams.is_empty() {
                    relay::get_blob(&state, name, digest, head, accept_zstd).await
                } else {
                    Ok(local)
                }
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "",
            )),
        };
    }

    // <name>/manifests/<tag|digest> — PUT (store) / GET / HEAD.
    if let Some(idx) = rest.rfind("/manifests/") {
        let name = &rest[..idx];
        let reference = &rest[idx + "/manifests/".len()..];
        if !valid_name(name) || !valid_reference(reference) {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                reference,
            ));
        }
        return match method {
            Method::PUT => {
                let ctype = req
                    .headers()
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(DEFAULT_MANIFEST_TYPE)
                    .to_string();
                let body = collect(req).await?;
                put_manifest(&store, name, reference, &ctype, &body)
            }
            Method::GET | Method::HEAD => {
                let head = method == Method::HEAD;
                let local = get_manifest(&store, name, reference, head)?;
                if local.status() == StatusCode::NOT_FOUND && !state.upstreams.is_empty() {
                    relay::get_manifest(&state, name, reference, head).await
                } else {
                    Ok(local)
                }
            }
            _ => Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "",
            )),
        };
    }

    // <name>/tags/list — best-effort tag listing (not used by the pull path).
    if let Some(name) = rest.strip_suffix("/tags/list")
        && valid_name(name)
    {
        return list_tags(&store, name);
    }

    Ok(error_response(StatusCode::NOT_FOUND, "NOT_FOUND", &path))
}

/// POST /v2/<name>/blobs/uploads/ — open an upload session (an empty temp file).
fn start_upload(store: &Store, name: &str) -> Result<Response<Full<Bytes>>> {
    let id = format!(
        "{}-{}",
        std::process::id(),
        store.next_upload.fetch_add(1, Ordering::Relaxed)
    );
    std::fs::write(store.upload_path(&id), b"").context("creating the upload file")?;
    accepted_upload(name, &id, 0)
}

/// PATCH /v2/<name>/blobs/uploads/<id> — append a chunk to the session file.
fn patch_upload(store: &Store, name: &str, id: &str, body: &[u8]) -> Result<Response<Full<Bytes>>> {
    if !valid_upload_id(id) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            id,
        ));
    }
    let path = store.upload_path(id);
    if !path.is_file() {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            id,
        ));
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    use std::io::Write;
    f.write_all(body).context("appending to the upload")?;
    let size = f.metadata()?.len();
    accepted_upload(name, id, size)
}

/// PUT /v2/<name>/blobs/uploads/<id>?digest=<d> — append the final bytes (if any) and
/// promote the session file to the store under the client's digest. The digest is
/// trusted (local single-user registry; oci-client re-verifies on pull). Storage is
/// transparently compressed: if the body is already a zstd frame (`Content-Encoding:
/// zstd`, an aware client) it is stored verbatim in the zstd store; otherwise the raw
/// body is zstd'd and stored compressed when that's actually smaller (so an
/// already-compressed blob — a compressed-digest chunk — is kept as-is). Either way
/// the digest indexes the *canonical* (decompressed) bytes.
fn finish_upload(
    store: &Store,
    name: &str,
    id: &str,
    query: &str,
    body: &[u8],
    body_is_zstd: bool,
) -> Result<Response<Full<Bytes>>> {
    if !valid_upload_id(id) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            id,
        ));
    }
    let Some(digest) = query_param(query, "digest") else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "missing digest",
        ));
    };
    if !valid_digest(&digest) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &digest,
        ));
    }
    // shared store lock for the promotion (vs. an exclusive gc); see lock_shared.
    let _lock = store.lock_shared()?;
    let hex = digest.trim_start_matches("sha256:").to_string();
    let upload = store.upload_path(id);
    if !body.is_empty() {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&upload)
            .with_context(|| format!("opening {}", upload.display()))?;
        f.write_all(body).context("appending the final chunk")?;
    }

    // already stored (either form)? idempotent — drop the upload.
    if store.has_blob(&hex) {
        let _ = std::fs::remove_file(&upload);
    } else if body_is_zstd {
        // the upload is a zstd frame whose decompression hashes to the digest: store
        // it verbatim in the zstd store (no re-compression).
        std::fs::rename(&upload, store.zstd_blob_path(&hex))
            .with_context(|| format!("promoting zstd upload {hex}"))?;
    } else {
        // raw canonical bytes: put_blob_at compresses adaptively (compressed form
        // only if it actually shrinks — a compressed-digest chunk stays identity).
        let raw =
            std::fs::read(&upload).with_context(|| format!("reading {}", upload.display()))?;
        store.put_blob_at(&hex, &raw)?;
        let _ = std::fs::remove_file(&upload);
    }

    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/{name}/blobs/{digest}"))
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// GET/HEAD /v2/<name>/blobs/<digest>. The digest names the *canonical* bytes. An
/// identity blob is served verbatim. A zstd-stored blob is served verbatim (with
/// `Content-Encoding: zstd`) when the client accepts zstd, else decompressed — so a
/// plain OCI client always gets the canonical bytes and verifies the digest.
pub(crate) fn get_blob(
    store: &Store,
    digest: &str,
    head: bool,
    accept_zstd: bool,
) -> Result<Response<Full<Bytes>>> {
    let hex = digest.trim_start_matches("sha256:");
    let Some((path, is_zstd)) = store.find_blob(hex) else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            digest,
        ));
    };
    // A HEAD hit is a remote pusher's dedup probe — about to reference this blob
    // without re-uploading it. Record the use for the gc sweep.
    if head {
        touch(&path);
    }

    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream");

    // serve the stored frame as-is; the client decodes it back to canonical. The
    // wire length is the stored (compressed) size — `stat` it; HEAD reads nothing.
    if is_zstd && accept_zstd {
        let builder = builder.header(hyper::header::CONTENT_ENCODING, "zstd");
        if head {
            return builder
                .header(hyper::header::CONTENT_LENGTH, blob_len(&path)?.to_string())
                .body(Full::new(Bytes::new()))
                .map_err(Into::into);
        }
        let stored = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        return builder
            .header(hyper::header::CONTENT_LENGTH, stored.len().to_string())
            .body(Full::new(Bytes::from(stored)))
            .map_err(Into::into);
    }

    // serve the canonical (decompressed, for a zstd blob) bytes.
    if is_zstd {
        // HEAD only needs the canonical length, read from the frame header (a handful
        // of bytes) without touching the rest; GET decompresses the whole body.
        if head {
            return builder
                .header(
                    hyper::header::CONTENT_LENGTH,
                    zstd_canonical_len(&path)?.to_string(),
                )
                .body(Full::new(Bytes::new()))
                .map_err(Into::into);
        }
        let stored = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let raw = zstd::decode_all(&stored[..]).context("decompressing a stored blob")?;
        return builder
            .header(hyper::header::CONTENT_LENGTH, raw.len().to_string())
            .body(Full::new(Bytes::from(raw)))
            .map_err(Into::into);
    }

    // identity blob: HEAD needs only the size (`stat`); GET serves the bytes.
    if head {
        return builder
            .header(hyper::header::CONTENT_LENGTH, blob_len(&path)?.to_string())
            .body(Full::new(Bytes::new()))
            .map_err(Into::into);
    }
    let stored = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    builder
        .header(hyper::header::CONTENT_LENGTH, stored.len().to_string())
        .body(Full::new(Bytes::from(stored)))
        .map_err(Into::into)
}

/// PUT /v2/<name>/manifests/<tag|digest> — store the manifest bytes (content
/// addressed) + its Content-Type sidecar, and point the tag at it (if a tag).
fn put_manifest(
    store: &Store,
    name: &str,
    reference: &str,
    ctype: &str,
    body: &[u8],
) -> Result<Response<Full<Bytes>>> {
    // shared store lock for the write (vs. an exclusive gc); see lock_shared.
    let _lock = store.lock_shared()?;
    let digest = store.put_manifest(name, reference, ctype, body)?;
    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/{name}/manifests/{digest}"))
        .header("Docker-Content-Digest", &digest)
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// GET/HEAD /v2/<name>/manifests/<tag|digest>.
pub(crate) fn get_manifest(
    store: &Store,
    name: &str,
    reference: &str,
    head: bool,
) -> Result<Response<Full<Bytes>>> {
    let Some((digest, data, ctype)) = store.get_manifest(name, reference)? else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            reference,
        ));
    };
    let len = data.len();
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::CONTENT_TYPE, &ctype)
        .header(hyper::header::CONTENT_LENGTH, len.to_string())
        .body(Full::new(if head {
            Bytes::new()
        } else {
            Bytes::from(data)
        }))
        .map_err(Into::into)
}

/// GET /v2/<name>/tags/list.
fn list_tags(store: &Store, name: &str) -> Result<Response<Full<Bytes>>> {
    let dir = store.root.join("repos").join(name).join("tags");
    let mut tags: Vec<String> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    tags.sort();
    let body = serde_json::json!({ "name": name, "tags": tags }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(Into::into)
}

/// A 202 Accepted upload-progress response (POST/PATCH), carrying the session
/// Location the client uses for the next request.
fn accepted_upload(name: &str, id: &str, size: u64) -> Result<Response<Full<Bytes>>> {
    let range_end = size.saturating_sub(1);
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", format!("/v2/{name}/blobs/uploads/{id}"))
        .header("Range", format!("0-{range_end}"))
        .header("Docker-Upload-UUID", id)
        .header(hyper::header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()))
        .map_err(Into::into)
}

/// An OCI error response: the documented `{ "errors": [ { code, message } ] }` body.
pub(crate) fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response<Full<Bytes>> {
    let body =
        serde_json::json!({ "errors": [ { "code": code, "message": message } ] }).to_string();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("building an error response")
}

/// Collect a request body fully into memory. Bodies here are bounded by the
/// client's chunk size (≤ one FastCDC chunk, ≤16 MiB) plus small manifests.
async fn collect(req: Request<Incoming>) -> Result<Bytes> {
    Ok(req.into_body().collect().await?.to_bytes())
}

/// True if request header `name` lists `needle` (e.g. `Accept-Encoding: zstd`).
/// Substring match — fine for the single token we negotiate.
fn header_has(req: &Request<Incoming>, name: hyper::header::HeaderName, needle: &str) -> bool {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains(needle))
}

/// The decompressed length of a zstd frame, read from its header (no full decode);
/// `None` if the frame doesn't record it (see [`zstd_with_size`]).
fn zstd_frame_len(frame: &[u8]) -> Option<u64> {
    zstd::zstd_safe::get_frame_content_size(frame)
        .ok()
        .flatten()
}

/// A zstd frame header is at most 18 bytes (4-byte magic + ≤14-byte header), enough
/// for [`zstd_frame_len`] to read the embedded content size.
const ZSTD_HEADER_MAX: usize = 18;

/// Size of a stored blob on disk, from `stat` — no read.
fn blob_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

/// Canonical (decompressed) length of a stored zstd blob, read from the frame header
/// alone. Our encoder always records the content size, so the full-decode fallback
/// (for a frame that omits it) is only a correctness backstop.
fn zstd_canonical_len(path: &Path) -> Result<u64> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut head = Vec::with_capacity(ZSTD_HEADER_MAX);
    f.by_ref()
        .take(ZSTD_HEADER_MAX as u64)
        .read_to_end(&mut head)
        .with_context(|| format!("reading the zstd header of {}", path.display()))?;
    if let Some(len) = zstd_frame_len(&head) {
        return Ok(len);
    }
    let stored = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(zstd::decode_all(&stored[..])
        .context("decompressing a stored blob")?
        .len() as u64)
}

/// Monotonic suffix source for [`atomic_write`] temp files (unique within a process;
/// the pid disambiguates across the concurrent servers sharing a store).
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` atomically (temp sibling + rename), so a concurrent reader
/// — or another server sharing this store — never observes a partial file.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".tmp.{}.{seq}", std::process::id()));
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// Lowercase hex of a byte slice.
pub(crate) fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

pub(crate) fn sha256_hex_raw(data: &[u8]) -> String {
    hex_of(&Sha256::digest(data))
}

/// A repository name: one or more `/`-separated path components, each a non-empty
/// run of `[A-Za-z0-9._-]` and not `.`/`..` — so it never escapes the store dir.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// `sha256:<64 lowercase hex>`.
fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A manifest reference: a digest, or a single safe tag component.
fn valid_reference(r: &str) -> bool {
    valid_digest(r) || valid_tag(r)
}

fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t != "."
        && t != ".."
        && !t.contains('/')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An upload id is one this server minted (`<pid>-<n>`): digits and a single dash,
/// no path separators.
fn valid_upload_id(id: &str) -> bool {
    !id.is_empty() && !id.contains('/') && id.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

/// Look up a query parameter (percent-decoding the value, since the client encodes
/// the `sha256:` digest's colon as `%3A`).
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Minimal application/x-www-form-urlencoded decode: `%XX` hex escapes and `+`.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `vk registry gc` — collect `root` and print a one-line summary; see
/// [`Store::gc`] for the retention model.
pub fn gc(root: PathBuf, retention: Duration, grace: Duration, dry_run: bool) -> Result<()> {
    let Some(store) = Store::open(&root)? else {
        println!(
            "vk registry: gc {}: no store here, nothing to collect",
            root.display()
        );
        return Ok(());
    };
    let r = store.gc(retention, grace, dry_run)?;
    println!(
        "vk registry: gc {}: {} {} tag(s), {} manifest(s), {} blob(s) ({:.1} MiB), {} upload(s)",
        store.root.display(),
        if dry_run { "would drop" } else { "dropped" },
        r.tags_dropped,
        r.manifests_dropped,
        r.blobs_dropped,
        r.bytes_freed as f64 / f64::from(1u32 << 20),
        r.uploads_dropped,
    );
    Ok(())
}

/// `vk registry status` — print a read-only usage + content report for the store at
/// `root`: on-disk size, dedup savings, and a per-repository breakdown; see
/// [`Store::stats`].
pub fn status(root: PathBuf) -> Result<()> {
    let Some(store) = Store::open(&root)? else {
        // Not an error: a host that has cached nothing has an empty store by definition,
        // and `--root` pointed at the wrong place reads as this too — which is why the
        // path is named rather than the counts printed as zeroes.
        println!("vk registry: {} — no store here", root.display());
        return Ok(());
    };
    let s = store.stats()?;
    let blobs = s.identity_blobs + s.zstd_blobs;
    let blob_bytes = s.identity_bytes + s.zstd_bytes;
    println!("vk registry: {}", store.root.display());
    println!(
        "  on disk:  {} in {} blob(s) ({} zstd + {} identity)",
        human_bytes(blob_bytes),
        blobs,
        human_bytes(s.zstd_bytes),
        human_bytes(s.identity_bytes),
    );
    if s.uploads > 0 {
        println!(
            "  uploads:  {} in flight ({})",
            s.uploads,
            human_bytes(s.upload_bytes),
        );
    }
    println!(
        "  content:  {} repo(s), {} tag(s), {} manifest(s)",
        s.repos.len(),
        s.total_tags,
        s.total_manifests,
    );
    if s.referenced_ondisk > 0 {
        println!(
            "  packing:  {} of content in {} on disk ({:.1}x by dedup + zstd)",
            human_bytes(s.logical_naive),
            human_bytes(s.referenced_ondisk),
            s.logical_naive as f64 / s.referenced_ondisk as f64,
        );
    }
    let reclaimable = blob_bytes.saturating_sub(s.referenced_ondisk);
    if reclaimable > 1 << 20 {
        println!(
            "  gc:       {} in blobs no tag references (vk registry gc)",
            human_bytes(reclaimable),
        );
    }
    if !s.repos.is_empty() {
        println!();
        println!(
            "  {:<40} {:>5} {:>10}  LATEST",
            "REPOSITORY", "TAGS", "SIZE"
        );
        for r in &s.repos {
            println!(
                "  {:<40} {:>5} {:>10}  {}",
                r.name,
                r.tags,
                human_bytes(r.logical_bytes),
                r.latest_tag.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

/// A byte count in binary units (`B`, `KiB`, ... `PiB`), one decimal past `B`.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Default store root: `$XDG_DATA_HOME/virtkit/registry`, else `~/.local/share/...`.
pub fn default_root() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("virtkit/registry"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_DATA_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/share/virtkit/registry"))
}

/// The `systemd --user` unit [`install_service`] writes. Named here because whoever
/// replaces the binary has to point at the same unit to have the new one served.
pub const SERVICE_UNIT: &str = "virtkit-registry.service";

/// What a unit needs to know to run `serve`: the arguments it will pass, and what they mean
/// once the config file they may name has been read — read once, so the address a unit is
/// built for and the store it is granted cannot come from two different reads of it.
pub struct UnitFacts {
    /// the config file the unit hands `serve`, which then carries addr/root/TLS/auth
    config: Option<PathBuf>,
    /// where the server will listen
    addr: SocketAddr,
    /// the store it will open — `None` when nothing named one, leaving the per-user default
    /// that a machine-wide unit must not inherit
    root: Option<PathBuf>,
    /// whether the config file turns TLS on
    tls: bool,
}

impl UnitFacts {
    /// Resolve the arguments a unit will carry. A config file supersedes `--addr`/`--root`
    /// rather than joining them — the file is what an operator edits afterwards, and a
    /// baked-in flag would quietly outrank what they change in it — so the CLI refuses the
    /// two together and only one of them is read here.
    pub fn resolve(config: Option<&Path>, addr: SocketAddr, root: Option<PathBuf>) -> Result<Self> {
        let Some(path) = config else {
            return Ok(UnitFacts {
                config: None,
                addr,
                root,
                tls: false,
            });
        };
        let v = ServerConfig::file_view(path)?;
        Ok(UnitFacts {
            config: Some(path.to_path_buf()),
            // The file's address wins, as it does for `serve`: `--addr` carries a default,
            // so an explicit one cannot be told from it.
            addr: v.addr.unwrap_or(addr),
            root: v.root,
            tls: v.tls,
        })
    }

    /// Where the server will listen.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether it will serve TLS, so a caller naming its URL names the right scheme.
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// The store the server will open, the per-user default included — right for a `--user`
    /// unit, which runs as the user whose default that is.
    pub fn store(&self) -> Result<PathBuf> {
        match &self.root {
            Some(r) => Ok(r.clone()),
            None => default_root(),
        }
    }

    /// The `serve` arguments a unit's `ExecStart` passes.
    fn exec_args(&self) -> Result<String> {
        if let Some(cfg) = &self.config {
            return Ok(format!("--config {}", unit_path("the config file", cfg)?));
        }
        Ok(format!(
            "--addr {} --root {}",
            self.addr,
            unit_path("the store", &self.store()?)?
        ))
    }
}

/// A path as one quoted systemd argument. systemd splits `Exec*` and `ReadWritePaths=` on
/// whitespace, unescapes `\` and expands `%` specifiers *inside* the quotes, so a path
/// carrying any of those means something other than itself — and a `"` or a newline ends the
/// argument early, which in a file installed as root is how a store path becomes an extra
/// directive. None of it is worth escaping around: refuse, and say which path it was.
fn unit_path(what: &str, p: &Path) -> Result<String> {
    let s = p.to_string_lossy();
    if let Some(c) = s
        .chars()
        .find(|c| matches!(c, '"' | '\\' | '%' | '\'' | '$') || c.is_control())
    {
        bail!(
            "{what} {} contains {c:?}, which does not survive a systemd unit as itself",
            p.display()
        );
    }
    Ok(format!("\"{s}\""))
}

/// Install + start a `systemd --user` unit running `serve`, so the store comes back with
/// the session — and, with `loginctl enable-linger`, without one.
pub fn install_service(facts: &UnitFacts) -> Result<()> {
    let addr = facts.addr();
    let root = facts.store()?;
    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let cfg_home = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(c) => PathBuf::from(c),
        None => {
            let home = std::env::var_os("HOME").context("HOME is not set")?;
            PathBuf::from(home).join(".config")
        }
    };
    let unit_dir = cfg_home.join("systemd/user");
    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("creating {}", unit_dir.display()))?;
    let unit_file = unit_dir.join(SERVICE_UNIT);
    let unit = format!(
        "[Unit]\n\
         Description=virtkit local OCI registry (shared microVM bundle store)\n\
         After=network.target\n\
         \n\
         [Service]\n\
         ExecStart={exe} serve {args}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = unit_path("the binary", &exe)?,
        args = facts.exec_args()?,
    );
    std::fs::write(&unit_file, unit).with_context(|| format!("writing {}", unit_file.display()))?;
    println!("virtkit: wrote {}", unit_file.display());

    let run = |args: &[&str]| -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .arg("--user")
            .args(args)
            .status()
            .context("running systemctl --user (is systemd available?)")?;
        if !status.success() {
            bail!("systemctl --user {} failed ({status})", args.join(" "));
        }
        Ok(())
    };
    run(&["daemon-reload"])?;
    run(&["enable", "--now", SERVICE_UNIT])?;
    // The unit may now carry a config file, so the URL and the client snippet both follow
    // whether that file turns TLS on — `insecure` says the registry is plain HTTP, which is
    // the wrong advice, not just an untidy one, for a unit serving TLS.
    let tls = facts.tls();
    println!(
        "virtkit: {SERVICE_UNIT} enabled + started ({}://{addr}, store {})",
        scheme(tls),
        root.display()
    );
    let client_key = if tls {
        "    # ca_file = \"…\"   # when the cert is from a private CA"
    } else {
        "    insecure = true"
    };
    println!(
        "virtkit: point each worktree's [registry] at it:\n\
         \n    [registry]\n    repo = \"{addr}/bundles\"\n{client_key}\n\
         \nvirtkit: for it to run without an active login session: loginctl enable-linger $USER"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The URL a server prints is the URL that reaches it: a TLS-configured server says
    /// `https`, a plain one `http`. The scheme is the only part of the line an operator
    /// cannot check by reading the config, so it has to follow the acceptor rather than
    /// be assumed.
    #[test]
    fn the_banner_names_the_scheme_the_server_actually_speaks() {
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let root = Path::new("/srv/vk-registry");
        assert_eq!(
            banner(root, 0, true, addr),
            "vk-registry: serving /srv/vk-registry [local] on https://0.0.0.0:443"
        );
        assert_eq!(
            banner(root, 0, false, addr),
            "vk-registry: serving /srv/vk-registry [local] on http://0.0.0.0:443"
        );
        // and a relay says how many upstreams it fronts, either way
        assert_eq!(
            banner(root, 2, true, addr),
            "vk-registry: serving /srv/vk-registry [mirror (2 upstream(s))] on https://0.0.0.0:443"
        );
        assert_eq!(
            banner(root, 2, false, addr),
            "vk-registry: serving /srv/vk-registry [mirror (2 upstream(s))] on http://0.0.0.0:443"
        );
    }

    /// What the unit runs: a config file supersedes the flags rather than joining them, so
    /// a baked-in `--addr` cannot outrank the `addr` an operator later edits into the file.
    /// Paths are quoted, since systemd splits `ExecStart` on whitespace.
    #[test]
    fn a_units_exec_args_follow_the_config_file_when_there_is_one() {
        let flags = UnitFacts::resolve(
            None,
            "127.0.0.1:5000".parse().unwrap(),
            Some(PathBuf::from("/srv/a store")),
        )
        .unwrap();
        assert_eq!(
            flags.exec_args().unwrap(),
            "--addr 127.0.0.1:5000 --root \"/srv/a store\""
        );

        let dir = std::env::temp_dir().join(format!("vk-regserve-exec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        std::fs::write(&cfg, "root = \"/srv/store\"\n").unwrap();
        let configured =
            UnitFacts::resolve(Some(&cfg), "127.0.0.1:5000".parse().unwrap(), None).unwrap();
        assert_eq!(
            configured.exec_args().unwrap(),
            format!("--config \"{}\"", cfg.display())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `status` and `gc` look at a store; they do not bring one into being. A root with no
    /// store — a fresh host, or a `--root`/`root =` that names the wrong path — has to come
    /// back reported and still untouched: a tree conjured by a report is one nothing will
    /// ever write to, and it hides the mistake that produced it. A directory that is not a
    /// store counts as no store, down to not leaving the lockfile in it.
    #[test]
    fn reading_a_store_that_is_not_there_creates_nothing() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The retention window is zero throughout: on an absent store neither entry point
        // gets as far as collecting anything, and the one present-store leg is a dry run.
        let zero = Duration::from_secs(0);

        assert!(Store::open(&dir).unwrap().is_none());
        status(dir.clone()).unwrap();
        gc(dir.clone(), zero, zero, false).unwrap();
        assert!(!dir.exists(), "{} was created by reading it", dir.display());

        // Someone else's directory, named by a mistyped root: reported as no store, and
        // left exactly as empty as it was.
        std::fs::create_dir_all(&dir).unwrap();
        assert!(Store::open(&dir).unwrap().is_none());
        status(dir.clone()).unwrap();
        gc(dir.clone(), zero, zero, false).unwrap();
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "{} was written to",
            dir.display()
        );

        // A directory that carries a `blobs/` of its own is still not a store, and a marker
        // that is not a directory is not one either.
        std::fs::create_dir_all(dir.join("blobs")).unwrap();
        assert!(Store::open(&dir).unwrap().is_none());
        std::fs::write(dir.join("blobs/sha256"), b"not a store").unwrap();
        assert!(Store::open(&dir).unwrap().is_none());
        std::fs::remove_dir_all(dir.join("blobs")).unwrap();

        // A root that cannot be read at all is an error, not one more absence: reporting it
        // as "no store here" is the silence this distinction exists to remove.
        std::fs::write(dir.join("a-file"), b"").unwrap();
        assert!(Store::open(&dir.join("a-file")).is_err());
        assert!(status(dir.join("a-file")).is_err());
        std::fs::remove_file(dir.join("a-file")).unwrap();

        // A store that is there is opened as usual — the report is skipped for absence,
        // not for being empty.
        let store = Store::new(dir.clone()).unwrap();
        assert!(Store::open(&store.root).unwrap().is_some());
        status(dir.clone()).unwrap();
        gc(dir.clone(), zero, zero, true).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// finish_upload stores a compressible raw blob zstd-compressed (smaller, in the
    /// zstd store) and an incompressible one verbatim (identity store), and find_blob
    /// resolves both with the canonical bytes recoverable. Exercises the transparent
    /// adaptive storage without an HTTP round-trip.
    #[test]
    fn adaptive_store_compresses_then_serves_canonical() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // compressible raw blob -> stored zstd, smaller, canonical decompresses back.
        let raw = vec![7u8; 100_000];
        let digest = format!("sha256:{}", sha256_hex_raw(&raw));
        let hex = digest.trim_start_matches("sha256:");
        std::fs::write(store.upload_path("1-0"), b"").unwrap();
        let resp = finish_upload(
            &store,
            "img",
            "1-0",
            &format!("digest={digest}"),
            &raw,
            false,
        )
        .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let (path, is_zstd) = store.find_blob(hex).expect("blob stored");
        assert!(is_zstd, "a compressible blob should be stored zstd");
        assert!(std::fs::metadata(&path).unwrap().len() < raw.len() as u64);
        assert_eq!(
            zstd::decode_all(&std::fs::read(&path).unwrap()[..]).unwrap(),
            raw
        );

        // incompressible blob -> stored verbatim (identity), no zstd dir entry.
        // a high-entropy splitmix64 stream — zstd cannot shrink it.
        let mut state = 0x9e3779b97f4a7c15u64;
        let rnd: Vec<u8> = (0..50_000)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                (z ^ (z >> 31)) as u8
            })
            .collect();
        let rdigest = format!("sha256:{}", sha256_hex_raw(&rnd));
        let rhex = rdigest.trim_start_matches("sha256:");
        std::fs::write(store.upload_path("1-1"), b"").unwrap();
        finish_upload(
            &store,
            "img",
            "1-1",
            &format!("digest={rdigest}"),
            &rnd,
            false,
        )
        .unwrap();
        let (rpath, ris_zstd) = store.find_blob(rhex).expect("blob stored");
        assert!(!ris_zstd, "an incompressible blob should stay identity");
        assert_eq!(std::fs::read(&rpath).unwrap(), rnd);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// GC readiness: a dedup hit (has_blob / a second put_blob) bumps the blob's
    /// mtime and a tag hit bumps the tag file's mtime — the usage records the
    /// `Store::gc` retention keys on.
    #[test]
    fn usage_mtimes_bump() {
        use std::time::{Duration, SystemTime};
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcprep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let old = SystemTime::now() - Duration::from_secs(3600);
        let backdate = |p: &Path| {
            std::fs::File::open(p).unwrap().set_modified(old).unwrap();
            assert!(std::fs::metadata(p).unwrap().modified().unwrap() <= old);
        };
        let raw = vec![9u8; 10_000];
        let digest = store.put_blob(&raw).unwrap();
        let hex = digest.trim_start_matches("sha256:");
        let (blob, _) = store.find_blob(hex).unwrap();
        backdate(&blob);
        assert!(store.has_blob(hex), "blob just stored");
        assert!(
            std::fs::metadata(&blob).unwrap().modified().unwrap() > old,
            "a dedup hit must bump the blob mtime"
        );

        store
            .put_manifest("repo", "tag1", DEFAULT_MANIFEST_TYPE, b"{}")
            .unwrap();
        let tag = store.tag_path("repo", "tag1");
        backdate(&tag);
        assert!(store.get_manifest("repo", "tag1").unwrap().is_some());
        assert!(
            std::fs::metadata(&tag).unwrap().modified().unwrap() > old,
            "a tag hit must bump the tag mtime"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `sha256:<hex>` → `<hex>`.
    fn hex(digest: &str) -> String {
        digest.trim_start_matches("sha256:").to_string()
    }

    /// A minimal OCI-shaped manifest body referencing `config` and `layers`
    /// (`sha256:` digests) — the structure `manifest_digest_hexes` marks from.
    fn manifest_body(config: &str, layers: &[&str]) -> Vec<u8> {
        let layers: Vec<_> = layers
            .iter()
            .map(|d| {
                serde_json::json!({
                    "mediaType": "application/vnd.wallix.microvm.ext4.chunk",
                    "digest": d,
                    "size": 1,
                })
            })
            .collect();
        serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config,
                "size": 1,
            },
            "layers": layers,
        })
        .to_string()
        .into_bytes()
    }

    /// Backdate every file under `root` to `t`.
    fn backdate_all(root: &Path, t: SystemTime) {
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    std::fs::File::open(&p).unwrap().set_modified(t).unwrap();
                }
            }
        }
    }

    const DAY: Duration = Duration::from_secs(86_400);

    /// gc drops an idle tag and sweeps everything only it referenced (sidecar,
    /// manifest, config and chunk blobs), while a live tag's whole graph survives
    /// even with blob mtimes far past the grace window — reachability, not age,
    /// keeps referenced data. A blob shared by both manifests stays.
    #[test]
    fn gc_sweeps_expired_unreferenced_state_only() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let shared = store.put_blob(&[1u8; 4096]).unwrap();
        let cfg_live = store.put_blob(b"cfg-live").unwrap();
        let cfg_dead = store.put_blob(b"cfg-dead").unwrap();
        let only_live = store.put_blob(&[2u8; 4096]).unwrap();
        let only_dead = store.put_blob(&[3u8; 4096]).unwrap();
        let live_manifest = store
            .put_manifest(
                "repo",
                "live",
                DEFAULT_MANIFEST_TYPE,
                &manifest_body(&cfg_live, &[&shared, &only_live]),
            )
            .unwrap();
        let dead_manifest = store
            .put_manifest(
                "repo",
                "dead",
                DEFAULT_MANIFEST_TYPE,
                &manifest_body(&cfg_dead, &[&shared, &only_dead]),
            )
            .unwrap();

        // age the whole store past retention, then refresh only the live tag.
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.tag_path("repo", "live"));

        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.tags_dropped, 1);
        assert_eq!(report.manifests_dropped, 1);
        // the dead manifest + its config + its exclusive chunk
        assert_eq!(report.blobs_dropped, 3);
        assert!(report.bytes_freed > 0);
        assert_eq!(report.uploads_dropped, 0);

        assert!(store.get_manifest("repo", "live").unwrap().is_some());
        assert!(store.get_manifest("repo", "dead").unwrap().is_none());
        for d in [&shared, &cfg_live, &only_live, &live_manifest] {
            assert!(store.has_blob(&hex(d)), "live data must survive: {d}");
        }
        for d in [&cfg_dead, &only_dead, &dead_manifest] {
            assert!(!store.has_blob(&hex(d)), "dead data must sweep: {d}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The grace window: an unreferenced-but-fresh blob (a multi-request HTTP push
    /// in flight) survives the sweep, and a fresh digest-pinned manifest (sidecar,
    /// no tag) roots the old chunks it references. Once everything ages past the
    /// grace window, a second pass sweeps it all. Stale upload sessions age out;
    /// a live one stays.
    #[test]
    fn gc_grace_protects_inflight_pushes_and_digest_pins() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcgrace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let chunk = store.put_blob(&[5u8; 4096]).unwrap();
        let inflight = store.put_blob(&[6u8; 4096]).unwrap();
        let body = manifest_body(&format!("sha256:{}", hex(&chunk)), &[&chunk]);
        let pin = format!("sha256:{}", sha256_hex_raw(&body));
        let pinned = store
            .put_manifest("repo", &pin, DEFAULT_MANIFEST_TYPE, &body)
            .unwrap();
        std::fs::write(store.upload_path("9-0"), b"stale").unwrap();
        std::fs::write(store.upload_path("9-1"), b"live").unwrap();

        // age everything, then refresh what should count as in-flight: the
        // unreferenced blob, the digest-pinned manifest, one upload session.
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.find_blob(&hex(&inflight)).unwrap().0);
        touch(&store.find_blob(&hex(&pinned)).unwrap().0);
        touch(&store.upload_path("9-1"));

        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.tags_dropped, 0);
        assert_eq!(report.manifests_dropped, 0, "a fresh pin must stay rooted");
        assert_eq!(
            report.blobs_dropped, 0,
            "grace + pin must protect all blobs"
        );
        assert_eq!(report.uploads_dropped, 1);
        assert!(store.has_blob(&hex(&inflight)));
        assert!(
            store.has_blob(&hex(&chunk)),
            "the pin must root its old chunk"
        );
        assert!(!store.upload_path("9-0").exists());
        assert!(store.upload_path("9-1").exists());

        // has_blob above re-bumped the mtimes — age everything out again and the
        // pin, its chunk, the in-flight blob and the last upload all sweep.
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.manifests_dropped, 1);
        assert_eq!(report.blobs_dropped, 3);
        assert_eq!(report.uploads_dropped, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A dry run reports exactly what the real pass then drops, and removes
    /// nothing itself.
    #[test]
    fn gc_dry_run_removes_nothing() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcdry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let cfg = store.put_blob(b"cfg").unwrap();
        let chunk = store.put_blob(&[7u8; 4096]).unwrap();
        store
            .put_manifest(
                "repo",
                "dead",
                DEFAULT_MANIFEST_TYPE,
                &manifest_body(&cfg, &[&chunk]),
            )
            .unwrap();
        std::fs::write(store.upload_path("3-0"), b"stale").unwrap();
        backdate_all(&dir, SystemTime::now() - DAY * 100);

        let dry = store.gc(DAY * 30, DAY, true).unwrap();
        assert_eq!(dry.tags_dropped, 1);
        assert_eq!(dry.manifests_dropped, 1);
        assert_eq!(dry.blobs_dropped, 3);
        assert_eq!(dry.uploads_dropped, 1);
        // still all present — probe via paths only (has_blob/get_manifest would
        // bump the mtimes the real pass below keys on).
        assert!(store.tag_path("repo", "dead").exists());
        assert!(store.find_blob(&hex(&chunk)).is_some());
        assert!(store.upload_path("3-0").exists());

        let real = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(real.tags_dropped, dry.tags_dropped);
        assert_eq!(real.manifests_dropped, dry.manifests_dropped);
        assert_eq!(real.blobs_dropped, dry.blobs_dropped);
        assert_eq!(real.bytes_freed, dry.bytes_freed);
        assert_eq!(real.uploads_dropped, dry.uploads_dropped);
        assert!(!store.tag_path("repo", "dead").exists());
        assert!(store.find_blob(&hex(&chunk)).is_none());
        assert!(!store.upload_path("3-0").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gc mark refuses image indexes (`manifests[]`): their blobs live behind
    /// nested manifests the mark doesn't walk, so a rooted index aborts the pass
    /// — nothing sweeps — instead of collecting data the index still references.
    #[test]
    fn gc_refuses_image_indexes() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcidx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let child = store.put_blob(&[8u8; 4096]).unwrap();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": DEFAULT_MANIFEST_TYPE,
                "digest": child,
                "size": 1,
            }],
        })
        .to_string()
        .into_bytes();
        store
            .put_manifest(
                "repo",
                "multi",
                "application/vnd.oci.image.index.v1+json",
                &index,
            )
            .unwrap();

        // age everything past retention, then keep only the index's tag live: the
        // rooted index must abort the mark before the sweep reaches the old blob.
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.tag_path("repo", "multi"));

        assert!(
            store.gc(DAY * 30, DAY, false).is_err(),
            "a rooted index must abort the gc"
        );
        assert!(
            store.find_blob(&hex(&child)).is_some(),
            "an aborted pass must sweep nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A byte-identical digest-pinned re-push refreshes the manifest blob's mtime
    /// (`put_manifest` touches an existing blob), so the grace window keeps the pin
    /// — and everything it references — rooted until the follow-up tag arrives.
    #[test]
    fn gc_repushed_digest_pin_stays_rooted() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcrepush-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let cfg = store.put_blob(b"cfg-pin").unwrap();
        let chunk = store.put_blob(&[9u8; 4096]).unwrap();
        let body = manifest_body(&cfg, &[&chunk]);
        let pin = format!("sha256:{}", sha256_hex_raw(&body));
        store
            .put_manifest("repo", &pin, DEFAULT_MANIFEST_TYPE, &body)
            .unwrap();

        // age everything past retention, then re-push the identical pinned
        // manifest — the push-manifests-then-tag flow re-hitting an old store.
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        store
            .put_manifest("repo", &pin, DEFAULT_MANIFEST_TYPE, &body)
            .unwrap();

        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(
            report.manifests_dropped, 0,
            "a fresh re-push must stay rooted"
        );
        assert_eq!(
            report.blobs_dropped, 0,
            "the pin must root its old config and chunk"
        );
        assert!(store.find_blob(&hex(&cfg)).is_some());
        assert!(store.find_blob(&hex(&chunk)).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real mutual exclusion, probed non-blockingly: each `lock_*` call opens the
    /// lock file anew (its own open file description), so guards conflict like
    /// separate processes even within this test. Shared coexists with shared;
    /// exclusive is denied while any shared guard lives and granted once dropped;
    /// shared is denied while exclusive is held (a gc blocks pushes).
    #[test]
    fn store_lock_excludes_writers_from_gc() {
        use std::os::unix::io::AsRawFd;
        let dir = std::env::temp_dir().join(format!("vk-regserve-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        // non-blocking probe with its own open file description; `f` drops on
        // return, releasing any lock the probe took.
        let try_lock = |op: libc::c_int| -> bool {
            let f = std::fs::File::create(dir.join(".lock")).unwrap();
            // SAFETY: fd valid for f's lifetime; LOCK_NB makes a denial return -1.
            unsafe { libc::flock(f.as_raw_fd(), op | libc::LOCK_NB) == 0 }
        };

        let s1 = store.lock_shared().unwrap();
        let s2 = store.lock_shared().unwrap();
        assert!(try_lock(libc::LOCK_SH), "shared must coexist with shared");
        assert!(
            !try_lock(libc::LOCK_EX),
            "exclusive (gc) must be denied while shared holders live"
        );
        drop(s1);
        assert!(!try_lock(libc::LOCK_EX), "one shared holder still lives");
        drop(s2);
        assert!(try_lock(libc::LOCK_EX), "exclusive acquires once all drop");

        let gc = store.lock_exclusive().unwrap();
        assert!(
            !try_lock(libc::LOCK_SH),
            "a pusher must be denied while gc holds exclusive"
        );
        drop(gc);
        assert!(try_lock(libc::LOCK_SH));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Hammer one store from many threads: concurrent `put_blob` of the SAME chunks
    /// (same-name atomic-rename races), interleaved `put_manifest` to one shared tag
    /// plus per-thread tags, and readers resolving tags/blobs throughout. Everything
    /// must succeed, and the final state must be fully consistent: every blob's
    /// canonical bytes intact, every tag resolving to a readable manifest.
    #[test]
    fn concurrent_store_writers_and_readers_stay_consistent() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // a small pool of shared payloads so every thread collides on the same blob
        // names (rename races), plus the manifest body each tag points at.
        let payloads: Vec<Vec<u8>> = (0..4u8)
            .map(|i| {
                let mut v = vec![i; 60_000];
                v.extend_from_slice(&[i, 1, 2, 3]);
                v
            })
            .collect();
        let manifest_body = br#"{"schemaVersion":2}"#.to_vec();

        const THREADS: usize = 8;
        const ITERS: usize = 30;
        std::thread::scope(|s| {
            for t in 0..THREADS {
                let store = &store;
                let payloads = &payloads;
                let manifest_body = &manifest_body;
                s.spawn(move || {
                    for i in 0..ITERS {
                        let _lock = store.lock_shared().unwrap();
                        let p = &payloads[(t + i) % payloads.len()];
                        let digest = store.put_blob(p).unwrap();
                        assert!(store.has_blob(digest.trim_start_matches("sha256:")));
                        // everyone fights over "shared"; each thread also owns a tag.
                        store
                            .put_manifest("conc", "shared", DEFAULT_MANIFEST_TYPE, manifest_body)
                            .unwrap();
                        store
                            .put_manifest(
                                "conc",
                                &format!("t{t}"),
                                DEFAULT_MANIFEST_TYPE,
                                manifest_body,
                            )
                            .unwrap();
                        // reader side: whatever the tag resolves to must be readable.
                        let (_d, bytes, _ct) =
                            store.get_manifest("conc", "shared").unwrap().unwrap();
                        assert_eq!(&bytes, manifest_body);
                    }
                });
            }
        });

        // final state: every payload's blob present with intact canonical bytes,
        // every tag resolving, and no leftover atomic-write temp files.
        for p in &payloads {
            let hex = sha256_hex_raw(p);
            assert_eq!(store.get_blob(&hex).unwrap().as_deref(), Some(&p[..]));
        }
        for t in 0..THREADS {
            assert!(
                store
                    .get_manifest("conc", &format!("t{t}"))
                    .unwrap()
                    .is_some()
            );
        }
        let stray_tmp = walkdir_count_tmp(&dir);
        assert_eq!(stray_tmp, 0, "no .tmp.* files may survive the races");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Count `.tmp.*` files (atomic_write temporaries) left anywhere under `root`.
    fn walkdir_count_tmp(root: &Path) -> usize {
        let mut n = 0;
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".tmp."))
                {
                    n += 1;
                }
            }
        }
        n
    }

    #[test]
    fn name_validation_blocks_traversal() {
        assert!(valid_name("bundles/appbuilder"));
        assert!(valid_name("redis"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name("a//b"));
        assert!(!valid_name("a/../b"));
        assert!(!valid_name(""));
        assert!(!valid_name("bad name"));
    }

    #[test]
    fn digest_and_reference_validation() {
        let good = format!("sha256:{}", "a".repeat(64));
        assert!(valid_digest(&good));
        assert!(!valid_digest("sha256:zz"));
        assert!(!valid_digest("md5:abc"));
        assert!(valid_reference(&good));
        assert!(valid_reference("20260627-abc"));
        assert!(!valid_reference("../x"));
        assert!(!valid_reference("a/b"));
    }

    #[test]
    fn upload_id_validation() {
        assert!(valid_upload_id("12345-7"));
        assert!(!valid_upload_id("../escape"));
        assert!(!valid_upload_id("a/b"));
        assert!(!valid_upload_id("abc")); // letters are not minted ids
    }

    #[test]
    fn zstd_frame_len_reads_embedded_content_size() {
        // the shared encoder embeds the content size (encode_all does not), so HEAD can
        // read the canonical length from the frame header without decompressing.
        let raw = vec![7u8; 50_000];
        let frame = zstd_with_size(&raw).unwrap();
        assert_eq!(zstd_frame_len(&frame), Some(50_000));
        assert_eq!(zstd::decode_all(&frame[..]).unwrap(), raw);
        // encode_all (no pledged size) omits it — the reason that helper exists.
        assert_eq!(
            zstd_frame_len(&zstd::encode_all(&raw[..], ZSTD_LEVEL).unwrap()),
            None
        );
    }

    #[test]
    fn percent_decode_handles_digest_colon() {
        assert_eq!(percent_decode("sha256%3Aabc"), "sha256:abc");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("trailing%"), "trailing%");
    }

    #[test]
    fn query_param_extracts_and_decodes() {
        assert_eq!(
            query_param("digest=sha256%3Adead", "digest").as_deref(),
            Some("sha256:dead")
        );
        assert_eq!(query_param("a=1&digest=x", "digest").as_deref(), Some("x"));
        assert_eq!(query_param("a=1", "digest"), None);
    }

    #[test]
    fn sha256_hex_raw_matches_known_vector() {
        assert_eq!(
            sha256_hex_raw(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn human_bytes_scales_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(1 << 30), "1.0 GiB");
    }

    #[test]
    fn manifest_blob_sizes_reads_config_and_layers() {
        let m = br#"{"config":{"digest":"sha256:aa","size":10},
                     "layers":[{"digest":"sha256:bb","size":20},
                               {"digest":"sha256:cc","size":30}]}"#;
        assert_eq!(
            manifest_blob_sizes(m),
            vec![("aa".into(), 10), ("bb".into(), 20), ("cc".into(), 30),]
        );
        assert!(manifest_blob_sizes(b"not json").is_empty());
    }

    /// stats() over a store with one repo and one manifest reachable from two tags: the
    /// manifest is counted once (both tags resolve to it), logical_naive sums the manifest
    /// plus its config and layers, and referenced_ondisk sums each distinct blob's real
    /// (compressed) size, strictly below the raw content since the layers are stored zstd.
    #[test]
    fn stats_reports_packing_and_repo() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // distinct, highly-compressible blobs (stored zstd, so on-disk << raw).
        let cfg = vec![3u8; 1_000];
        let a = vec![1u8; 40_000];
        let b = vec![2u8; 60_000];
        let dc = store.put_blob(&cfg).unwrap();
        let da = store.put_blob(&a).unwrap();
        let db = store.put_blob(&b).unwrap();
        let manifest = format!(
            r#"{{"config":{{"digest":"{dc}","size":{}}},
                 "layers":[{{"digest":"{da}","size":{}}},
                           {{"digest":"{db}","size":{}}}]}}"#,
            cfg.len(),
            a.len(),
            b.len(),
        );
        // one manifest under two tags — both resolve to the same digest.
        store
            .put_manifest(
                "bundles/app",
                "v1",
                DEFAULT_MANIFEST_TYPE,
                manifest.as_bytes(),
            )
            .unwrap();
        store
            .put_manifest(
                "bundles/app",
                "v2",
                DEFAULT_MANIFEST_TYPE,
                manifest.as_bytes(),
            )
            .unwrap();

        let s = store.stats().unwrap();
        let raw = (cfg.len() + a.len() + b.len()) as u64;
        assert_eq!(s.repos.len(), 1);
        assert_eq!(s.repos[0].name, "bundles/app");
        assert_eq!(s.repos[0].tags, 2);
        assert_eq!(s.total_manifests, 1);
        // the manifest counts once (deduped across the two tags): its own bytes plus
        // config + both layers. the per-repo SIZE covers only what it references.
        assert_eq!(s.logical_naive, raw + manifest.len() as u64);
        assert_eq!(s.repos[0].logical_bytes, raw);
        // on disk: the three distinct blobs (compressed) + the manifest, each once.
        assert!(s.referenced_ondisk > 0 && s.referenced_ondisk < raw);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
