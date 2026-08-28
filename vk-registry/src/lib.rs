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
//!   repos/<name>/blobs/<hex>      empty marker: this blob is a member of this repo,
//!                                 which is what makes a blob read repo-scoped
//!   uploads/<id>                  in-progress blob uploads (this process only)
//!   uploads/owners/<id>           the repository that upload session was opened for

use std::collections::{BTreeSet, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

pub mod accounts;
pub mod admin;
pub mod auth;
pub(crate) mod browse;
pub(crate) mod captions;
pub mod client;
pub mod config;
pub(crate) mod forms;
pub(crate) mod html;
pub(crate) mod keys;
pub mod lock;
pub mod oidc;
pub mod relay;
pub(crate) mod upload;

pub use client::{ClientAuth, FailInfo, Held, LockClient};
pub use config::{DEFAULT_ADDR, ServerConfig};

/// The client-auth model in force, resolved once at startup from [`config::AuthMode`].
/// One field rather than a shared-secret/accounts pair, so "one or the other, never both"
/// is what the type says instead of what a comment promises.
pub enum Authenticator {
    /// One shared secret for every client (`token_file`/`username`+`password_file`), or
    /// none at all.
    Shared(auth::Auth),
    /// Per-user sessions and scoped API keys — see [`accounts::resolve_principal`].
    /// The OIDC provider comes with the store rather than beside it: it is accounts mode's
    /// only login path, so [`config::ServerConfig::into_state`] can never produce one
    /// without the other.
    Accounts {
        db: Arc<accounts::Db>,
        oidc: Arc<oidc::OidcClient>,
    },
}

/// Everything a connection handler needs: the content-addressed store, the relay
/// upstreams (empty ⇒ a plain local registry, no mirroring), the build-once lock
/// authority, the client-auth scheme, and the optional TLS acceptor. Cheap to
/// clone-share via `Arc`.
pub struct ServerState {
    pub store: Arc<Store>,
    pub upstreams: Vec<relay::Upstream>,
    pub locks: lock::LockManager,
    pub auth: Authenticator,
    pub tls: Option<tokio_rustls::TlsAcceptor>,
}

impl ServerState {
    /// Whether a browser reaches this server over TLS — terminated here, or at a proxy,
    /// which is what the configured `public_url` says. It decides `Secure`, and with it
    /// the cookie names: a `__Host-` prefix is honoured only alongside `Secure`, so this
    /// is what both the writer and the reader of a cookie have to agree on. A deployment
    /// constant, deliberately: it must not vary per request, or a cookie set under one
    /// name would be read under the other.
    pub(crate) fn cookies_are_secure(&self) -> bool {
        self.tls.is_some()
            || matches!(
                &self.auth,
                Authenticator::Accounts { oidc, .. } if oidc.public_url().starts_with("https://")
            )
    }
}

/// Default content type for a manifest whose Content-Type sidecar is missing.
pub(crate) const DEFAULT_MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The media types a stored manifest may be *served* as.
///
/// The Content-Type a pusher sends is kept beside the manifest and handed back on a read,
/// and an upstream's is handed back by the relay — both caller-supplied strings, labelling
/// a response from the origin that also serves `/browse` and `/settings/keys` and holds the
/// session cookie. Anyone who may write one repository could therefore have stored bytes
/// served as `text/html` from this origin, which is a script on it. Serving only these four
/// keeps that shut; anything else is served as [`DEFAULT_MANIFEST_TYPE`], and the manifest,
/// blob and error responses set `nosniff`. `relay::MANIFEST_ACCEPT` asks upstream for exactly
/// this set, and a test holds the two together.
pub(crate) const MANIFEST_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// Which of [`MANIFEST_MEDIA_TYPES`] a caller-supplied `Content-Type` is, else
/// [`DEFAULT_MANIFEST_TYPE`].
///
/// A media type is matched the way HTTP defines one, not by string equality: parameters are
/// dropped (`…index.v1+json; charset=utf-8` is that index) and the comparison is
/// ASCII-case-insensitive. Exact equality would relabel a spec-legal variant as a
/// *different kind* of manifest — an index served as an image manifest — and the
/// distribution spec tells a client to reject a manifest whose `Content-Type` disagrees
/// with the `mediaType` in its body, so that would turn a lenient push into an unpullable
/// image. The return is always one of the four literals, so the stored label is canonical.
pub(crate) fn manifest_media_type(ctype: &str) -> &'static str {
    let base = ctype.split(';').next().unwrap_or("").trim();
    MANIFEST_MEDIA_TYPES
        .iter()
        .find(|t| t.eq_ignore_ascii_case(base))
        .copied()
        .unwrap_or(DEFAULT_MANIFEST_TYPE)
}

/// Fixed zstd level: identical raw chunks must compress to identical bytes for a
/// compressed-digest chunk to dedup. Shared by the client push path (registry.rs),
/// the transparent-zstd upload, and this store's adaptive storage compression.
pub const ZSTD_LEVEL: i32 = 1;

/// The body every handler in this server returns.
///
/// Boxed rather than `Full<Bytes>`, so one signature covers both shapes a response can
/// take: a small one already in memory (every page, every error, every manifest) and a
/// blob streamed off disk — a layer can be gigabytes, and buffering one per in-flight
/// request is how a registry gets killed by its own cache. Its error type is
/// `io::Error` because that is what a body read off disk can fail with, mid-response.
pub type Body = BoxBody<Bytes, std::io::Error>;

/// A body that is already entirely in memory.
pub(crate) fn body_of(bytes: Bytes) -> Body {
    // `Full`'s error is `Infallible`, so the map is a proof that it never runs, not a
    // conversion.
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

/// How much of a streamed blob is read per chunk — a default, not a measured optimum:
/// big enough that a multi-GB layer is not millions of wakeups, small enough that the
/// peak per in-flight response is a rounding error next to the layer itself.
const STREAM_CHUNK: usize = 256 * 1024;

/// A body that pulls from a blocking reader — a file, or a zstd decoder over one.
fn stream_body(reader: impl std::io::Read + Send + Sync + 'static, what: &str) -> Body {
    // Refcounted, not re-allocated: the label outlives every chunk but is only read on the
    // error path.
    let what: std::sync::Arc<str> = what.into();
    let stream = futures::stream::unfold(Some(reader), move |state| {
        let what = what.clone();
        async move {
            let mut reader = state?;
            // A fresh buffer per chunk: the `Bytes` handed out lives as long as the client
            // takes to read it, so it cannot be one this reader keeps writing into.
            let read = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; STREAM_CHUNK];
                let mut filled = 0;
                // Filled rather than one `read`: `Read` may return short at any time (a
                // zstd decoder returns as soon as one block is out), and `Interrupted` is
                // a retry, not the end of the blob.
                while filled < buf.len() {
                    match reader.read(&mut buf[filled..]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
                if filled == 0 {
                    return Ok(None);
                }
                buf.truncate(filled);
                Ok(Some((Bytes::from(buf), reader)))
            })
            .await;
            // A mid-response error reaches the log as the connection's, where a bad disk and a
            // client hangup look alike — so say which blob it was while that is still known.
            let named = |e: std::io::Error| std::io::Error::new(e.kind(), format!("{what}: {e}"));
            match read {
                Ok(Ok(None)) => None,
                Ok(Ok(Some((chunk, reader)))) => {
                    Some((Ok(hyper::body::Frame::data(chunk)), Some(reader)))
                }
                // Either way the body ends here, so there is no reader left to carry.
                Ok(Err(e)) => Some((Err(named(e)), None)),
                Err(e) => Some((Err(named(std::io::Error::other(e))), None)),
            }
        }
    });
    StreamBody::new(stream).boxed()
}

/// Capability header a cooperating server sets on its `GET /v2/` response, so an
/// auto-mode client knows it may push transparent-zstd (uncompressed-digest) chunks.
/// Absent on any dumb OCI registry.
pub const TRANSPARENT_ZSTD_HEADER: &str = "x-virtkit-transparent-zstd";

/// Detect gzip, zstd, xz, and bzip2 containers by magic number to avoid recompressing them.
///
/// Files shorter than the longest magic are treated as uncompressed; I/O errors propagate.
fn already_compressed(path: &Path) -> Result<bool> {
    use std::io::Read;
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    // `read_to_end` on a `take`, not one `read`: a single read may return short even on a
    // longer file, and a truncated header would drop the six-byte xz magic.
    let mut head = Vec::with_capacity(6);
    f.take(6)
        .read_to_end(&mut head)
        .with_context(|| format!("reading the header of {}", path.display()))?;
    Ok(
        head.starts_with(&[0x1f, 0x8b])                       // gzip
        || head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])       // zstd
        || head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) // xz
        || head.starts_with(b"BZh"),
    ) // bzip2
}

/// zstd `tmp` into a sibling temp file, returning its path — or `None`, having removed it,
/// when the frame did not come out smaller than the `raw_len` bytes it encodes. Streamed
/// both ways: this runs on blobs that can be gigabytes.
fn compress_beside(tmp: &Path, raw_len: u64) -> Result<Option<PathBuf>> {
    // Appended, not `with_extension`, which would replace one: two staged blobs whose
    // names differ only past a dot must not race for the same output file. Kept as an
    // `OsString` — a staged name is a file name, not necessarily UTF-8, and a lossy
    // rewrite would point `out` at a different file than `tmp`.
    let mut name = tmp
        .file_name()
        .context("the staged blob has no file name")?
        .to_os_string();
    name.push(".zst");
    let out = tmp.with_file_name(name);
    let src = std::fs::File::open(tmp).with_context(|| format!("opening {}", tmp.display()))?;
    // Buffered: `io::copy` from a raw `File` would feed the encoder 8 KiB at a time for a
    // blob that can be gigabytes (`hash_zstd_frame` reads the other direction the same way).
    let mut src = std::io::BufReader::new(src);
    let dst = std::fs::File::create(&out).with_context(|| format!("creating {}", out.display()))?;
    // The pledged size is what puts the decompressed length in the frame header, which is
    // how a HEAD answers with the canonical Content-Length without decompressing (see
    // `zstd_canonical_len`) — the same reason `zstd_with_size` sets it.
    let mut enc =
        zstd::stream::write::Encoder::new(dst, ZSTD_LEVEL).context("creating the encoder")?;
    enc.set_pledged_src_size(Some(raw_len))
        .context("setting the zstd pledged size")?;
    enc.include_contentsize(true)
        .context("enabling the zstd content size")?;
    let copied = std::io::copy(&mut src, &mut enc).context("zstd-compressing a blob");
    let finished = copied.and_then(|_| enc.finish().context("finishing the zstd frame"));
    let z_len = match finished {
        Ok(f) => f.metadata().context("stat of the compressed blob")?.len(),
        Err(e) => {
            // A half-written frame is of no use to anyone; the error is what the caller
            // acts on, so a failure to unlink it is not worth masking that with.
            let _ = std::fs::remove_file(&out);
            return Err(e);
        }
    };
    if z_len < raw_len {
        return Ok(Some(out));
    }
    // It did not pay. Same reasoning as above for the unlink.
    let _ = std::fs::remove_file(&out);
    Ok(None)
}

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

/// A digest-verified blob [`Store::stage_promotion`] has decided the storage form of, ready
/// for [`Store::promote_staged`] to rename into place.
pub(crate) struct StagedBlob {
    /// The file to rename into the store.
    install: PathBuf,
    /// The other staged file the decision left behind, to remove.
    discard: Option<PathBuf>,
    /// Whether `install` is a zstd frame rather than the canonical bytes.
    zstd: bool,
}

impl StagedBlob {
    /// Drop the staged files without installing anything — for a caller that gives up
    /// between staging and promoting. `gc` would sweep `uploads/` eventually anyway, so an
    /// unlink that fails is not worth reporting over whatever made the caller give up.
    pub(crate) fn discard(self) {
        let _ = std::fs::remove_file(&self.install);
        if let Some(p) = &self.discard {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Store {
    /// The store at `root`, its layout created if this is the first use — for the write
    /// paths, and for the in-process build cache, whose reads share the root it pushes to.
    /// Looking at a store without bringing one into being is [`Store::open`].
    pub fn new(root: PathBuf) -> Result<Self> {
        for sub in ["blobs/sha256", "blobs/zstd", "uploads/owners", "repos"] {
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
    /// Where the relay stages a blob it streams in (bounded memory — layers can be GBs)
    /// before [`Store::stage_promotion`] and [`Store::promote_staged`] install it. Under
    /// the store root, so that rename is atomic.
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
    /// Where an upload session's repository is recorded. A subdirectory, not a sidecar
    /// beside the session file: `dir_files` walks only the files directly inside a
    /// directory, so `gc` and `stats` keep counting one entry per upload rather than two.
    fn upload_owner_path(&self, id: &str) -> PathBuf {
        self.root.join("uploads").join("owners").join(id)
    }
    fn tag_path(&self, name: &str, tag: &str) -> PathBuf {
        self.root.join("repos").join(name).join("tags").join(tag)
    }
    /// Marker recording that blob `hex` belongs to repository `name`. The store is one
    /// content-addressed pool shared by every repo, so holding a digest is not the same
    /// as being entitled to it: this is the record that says which repos a blob may be
    /// read through.
    fn repo_blob_path(&self, name: &str, hex: &str) -> PathBuf {
        self.root.join("repos").join(name).join("blobs").join(hex)
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

    /// [`Store::put_blob`] under an already-known digest hex — the HTTP push path, where
    /// `finish_upload` has already hashed `raw` and checked it against `hex`.
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

    /// Work out how a fully-written, digest-verified file will be stored, doing everything that
    /// needs no lock — [`Store::put_blob_at`]'s streaming counterpart, for the relay, which never
    /// holds a whole layer in memory. [`Store::promote_staged`] installs the result.
    pub(crate) fn stage_promotion(&self, hex: &str, tmp: &Path) -> Result<StagedBlob> {
        let raw_len = std::fs::metadata(tmp)
            .with_context(|| format!("stat {}", tmp.display()))?
            .len();
        // Racy on purpose — `promote_staged` looks again under the lock. Losing the race
        // only costs a compression pass whose output is then dropped.
        if !self.has_blob(hex)
            && !already_compressed(tmp)?
            && let Some(z) = compress_beside(tmp, raw_len)?
        {
            return Ok(StagedBlob {
                install: z,
                discard: Some(tmp.to_path_buf()),
                zstd: true,
            });
        }
        Ok(StagedBlob {
            install: tmp.to_path_buf(),
            discard: None,
            zstd: false,
        })
    }

    /// Rename a [`Store::stage_promotion`] result into the blob store. Renames and a
    /// `has_blob` check only, so it is safe to hold [`Store::lock_shared`] across it and
    /// the reference that follows. The staged files are consumed either way.
    pub(crate) fn promote_staged(&self, hex: &str, staged: StagedBlob) -> Result<()> {
        let StagedBlob {
            install,
            discard,
            zstd,
        } = staged;
        // Whatever happens to `install`, the other staged file has no further use and the
        // caller acts on the rename, not on the cleanup.
        let drop_discard = || {
            if let Some(p) = &discard {
                let _ = std::fs::remove_file(p);
            }
        };
        if self.has_blob(hex) {
            let _ = std::fs::remove_file(&install);
            drop_discard();
            return Ok(());
        }
        let dest = if zstd {
            self.zstd_blob_path(hex)
        } else {
            self.blob_path(hex)
        };
        std::fs::create_dir_all(dest.parent().unwrap_or_else(|| Path::new(".")))
            .context("creating the blob directory")?;
        std::fs::rename(&install, &dest).with_context(|| format!("promoting the blob {hex}"))?;
        drop_discard();
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
        // A digest reference is a claim about the body, so it is checked rather than
        // ignored. Storing under the *computed* digest instead would answer 201 for a
        // manifest the client cannot then fetch under the reference it pushed, and would
        // persist content it never asked to store. Before any write, so a refusal leaves
        // nothing behind — the relay's upstream-manifest caching depends on that too.
        if reference.starts_with("sha256:") && reference != digest {
            bail!("manifest body hashes to {digest}, not the requested {reference}");
        }
        let hex = &digest[7..];
        let dest = self.blob_path(hex);
        if dest.exists() {
            // a re-push is a dedup reference — the usage record the gc grace keys on
            touch(&dest);
        } else {
            atomic_write(&dest, body)?;
        }
        // The sidecar just written *is* this manifest's membership record — its own bytes
        // are ours, so it becomes readable through this repository, and `repo_has_manifest`
        // reads exactly that file. No second marker under `blobs/`: it would double the
        // inode cost and the reported count, and let the two disagree once the gc sweeps
        // one of them.
        //
        // Deliberately nothing for its children: a manifest is the one thing a caller can
        // write without holding the content it names, so inferring membership from a
        // reference would make "write here" mean "read anything whose digest I can name".
        // The children are recorded by whatever actually produced them — an upload, a
        // relay fetch, or an authorized mount in `authorize_and_mount_manifest_blobs`.
        //
        // Normalized on the way in as well as on the way out. Not because the two could
        // otherwise disagree — every reader goes through `get_manifest`, which filters too —
        // but so a caller-supplied string is never what is persisted, and so a future reader
        // that skips the filter still cannot serve one.
        atomic_write(
            &self.manifest_type_path(name, hex),
            manifest_media_type(ctype).as_bytes(),
        )?;
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
        // Also filtered on read: a sidecar written before this rule existed still holds
        // whatever it was pushed as.
        //
        // A manifest readable through a repository that was never pushed it — a mounted
        // index child, or the cross-repo clause of `readable_through` — has no sidecar
        // here, and answering `DEFAULT_MANIFEST_TYPE` would hand a client an
        // image-manifest type for a manifest list. The bytes say what they are, so ask
        // them before falling back; the filter keeps that answer honest too.
        let ctype = std::fs::read_to_string(self.manifest_type_path(name, hex))
            .ok()
            .map(|s| s.trim().to_string())
            .or_else(|| declared_media_type(&data))
            .map(|t| manifest_media_type(&t).to_string())
            .unwrap_or_else(|| DEFAULT_MANIFEST_TYPE.to_string());
        Ok(Some((digest, data, ctype)))
    }

    /// Record that `hex` belongs to repository `name` — an empty marker, so membership
    /// costs one inode per (repo, blob) pair. Idempotent.
    ///
    /// Only ever called for content this registry received or verified: bytes uploaded
    /// into this repository, a blob the relay fetched and hashed for it, a manifest whose
    /// bytes we hold, or a digest an authorized caller mounted. Nothing infers membership
    /// from a manifest merely *naming* a digest — that is the whole point, since a
    /// manifest is the one thing a caller can write without holding the content.
    ///
    /// Public alongside [`Store::repo_has_blob`] so the crate's integration tests can seed
    /// a store the way a push would leave it — `#[doc(hidden)]` because that is the only
    /// caller outside this crate, and a membership *mutator* is not part of the library's
    /// intended surface. `vk-driver` embeds this store as a purely local build cache that
    /// it reads through `Store` directly and never serves, so the sidecar its
    /// `put_manifest` writes is all the membership it has, and all it needs.
    #[doc(hidden)]
    pub fn record_blob(&self, name: &str, hex: &str) -> Result<()> {
        if !valid_name(name) || !is_blob_hex(hex) {
            bail!("cannot record blob {hex} in {name}: invalid name or digest");
        }
        let path = self.repo_blob_path(name, hex);
        if path.is_file() {
            return Ok(());
        }
        // Created directly rather than through `atomic_write`: there is no content to
        // tear, and a `.tmp.*` left behind in this directory would never be swept — the
        // gc only recognises 64-hex names here.
        let Some(dir) = path.parent() else {
            // Unreachable: `repo_blob_path` always joins at least `repos/<name>/blobs`.
            // Refuse rather than fall back to a relative path and create it in the cwd.
            bail!("no parent for the membership marker {}", path.display());
        };
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        match std::fs::File::create_new(&path) {
            Ok(_) => Ok(()),
            // Another request recorded it first, which is the same outcome.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e).with_context(|| format!("recording {}", path.display())),
        }
    }

    /// Whether `name` holds `hex` — one `stat`, and the answer on every read's hot path.
    ///
    /// Public because it is the store's half of the repo-scoping contract: what a caller
    /// may read through a repository is exactly what that repository holds. Out of the
    /// crate, only the tests use it, hence `#[doc(hidden)]`.
    #[doc(hidden)]
    pub fn repo_has_blob(&self, name: &str, hex: &str) -> bool {
        valid_name(name) && is_blob_hex(hex) && self.repo_blob_path(name, hex).is_file()
    }

    /// Whether `name` holds the manifest `hex`. The `manifests/<hex>` sidecar
    /// [`Store::put_manifest`] already writes per repository *is* this record — a
    /// manifest read by digest is repo-scoped by the same reasoning as a blob read.
    pub(crate) fn repo_has_manifest(&self, name: &str, hex: &str) -> bool {
        valid_name(name) && is_blob_hex(hex) && self.manifest_type_path(name, hex).is_file()
    }

    /// Whether `hex` is held by any repository in `candidates`, stopping at the first.
    /// The caller filters `candidates` to what it may read *before* calling, so this
    /// touches the filesystem only for repositories whose answer it is entitled to.
    pub(crate) fn any_holds(&self, candidates: &[String], hex: &str) -> bool {
        candidates
            .iter()
            .any(|r| self.repo_has_blob(r, hex) || self.repo_has_manifest(r, hex))
    }

    /// Every repository in the store — one with manifests but no tags counts, unlike
    /// [`Store::repo_names`], which answers the browse listing. One walk: `repo_dirs`
    /// stops at a repository's own subdirectories, so this is O(repositories) and does
    /// not pay a `stat` per membership marker.
    pub(crate) fn all_repo_names(&self) -> BTreeSet<String> {
        let repos = self.root.join("repos");
        self.repo_dirs_any(REPO_SUBDIRS)
            .0
            .into_iter()
            .filter_map(|d| {
                let name = d.parent()?.strip_prefix(&repos).ok()?.to_str()?;
                // Only a name this store could have written itself, as `repo_names` does:
                // this feeds `accounts::authorize`, and a directory left there by anything
                // else is not a repository to ask about.
                valid_name(name).then(|| name.to_string())
            })
            .collect()
    }

    /// Every tag under `repos/<name>/tags`, sorted — shared by the OCI `tags/list`
    /// handler and both `/browse` pages (the repo list calls it once per repository).
    /// Best-effort: an invalid name, an absent repo, an unreadable directory and a
    /// non-UTF-8 entry all just yield fewer tags. No caller is on the pull path, so this
    /// never fails one.
    pub(crate) fn list_tags(&self, name: &str) -> Vec<String> {
        if !valid_name(name) {
            return Vec::new();
        }
        let dir = self.root.join("repos").join(name).join("tags");
        let mut tags: Vec<String> = std::fs::read_dir(&dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        tags.sort();
        tags
    }

    /// Every repository that has a `tags` directory, as its `/`-joined name. The cheap
    /// half of what [`Store::stats`] computes: no blob walk, no manifest parsing — what a
    /// listing needs.
    ///
    /// Filtered through [`valid_name`]: only a name this store could have written itself
    /// is a repository. A directory left in `repos/` by anything else is not one, and
    /// `/browse` renders these, so they do not get to be a row with a link.
    pub(crate) fn repo_names(&self) -> Vec<String> {
        let repos = self.root.join("repos");
        self.repo_dirs("tags")
            .0
            .iter()
            .filter_map(|d| d.parent()?.strip_prefix(&repos).ok()?.to_str())
            .filter(|n| valid_name(n))
            .map(str::to_string)
            .collect()
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

        // Everything the mark phase roots in is read strictly, and nothing is deleted
        // before all of it is: a root this pass fails to see is a blob it goes on to sweep
        // out from under a live tag. Same reason a manifest that will not parse aborts
        // below — only here the omission would be silent.
        let (tags_dirs, tags_unseen) = self.repo_dirs("tags");
        let (man_dirs, man_unseen) = self.repo_dirs("manifests");
        if let Some(p) = tags_unseen.or(man_unseen) {
            bail!(
                "{} is a symlink, unreadable, or nested deeper than {MAX_NAME_SEGMENTS} \
                 repository name components; refusing to sweep on marks that would be \
                 incomplete. Remove it from the store, then run the gc again",
                p.display()
            );
        }

        // drop idle tags; the survivors' manifest hexes root the mark phase.
        let mut roots: HashSet<String> = HashSet::new();
        for tags_dir in tags_dirs {
            for tag in root_dir_files(&tags_dir)? {
                if idle(&tag, retention) {
                    remove(&tag)?;
                    report.tags_dropped += 1;
                } else {
                    // A tag being kept has to be readable: leaving it unrooted would mean
                    // sweeping the blobs it still references.
                    let d = std::fs::read_to_string(&tag)
                        .with_context(|| format!("reading the tag {}", tag.display()))?;
                    roots.insert(d.trim().trim_start_matches("sha256:").to_string());
                }
            }
        }

        // manifest sidecars: rooted by a surviving tag, or by their own freshness
        // (digest-pinned). The rest are *candidates*, not casualties — the removal waits
        // until after the blob sweep below, because a sidecar is a manifest's membership
        // record: dropping one whose blob the same pass then decides to keep would make a
        // live manifest permanently unreadable through its repository, with nothing left to
        // rebuild it from. (An image index does exactly that: the mark aborts on it, so
        // anything removed before the mark is removed on a pass that never sweeps.)
        let mut sidecar_candidates: Vec<(PathBuf, String)> = Vec::new();
        for man_dir in man_dirs {
            for sidecar in root_dir_files(&man_dir)? {
                let Some(hex) = sidecar.file_name().and_then(|n| n.to_str()) else {
                    bail!(
                        "{} is not named for a manifest digest; refusing to sweep on marks \
                         that would be incomplete",
                        sidecar.display()
                    );
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
                sidecar_candidates.push((sidecar.clone(), hex.to_string()));
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

        // sweep unmarked blobs idle past the grace window, in both storage forms, noting
        // every hex that keeps at least one form: that — not what is still on disk — is
        // what the membership sweep below has to consult, since `remove` is a no-op on a
        // dry run and would otherwise make it report nothing.
        //
        // Read strictly, like the tag and manifest listings above. This listing used to be
        // lenient because a missed entry only left a blob unswept; it is now what the two
        // sweeps below *delete* against, so an unreadable blob directory would produce an
        // empty `survivors` and take every membership record and every held-back sidecar
        // with it — while keeping the blobs, leaving live content unreachable and nothing
        // to rebuild the records from.
        let mut survivors: HashSet<String> = HashSet::new();
        for sub in ["blobs/sha256", "blobs/zstd"] {
            for blob in root_dir_files_opt(&self.root.join(sub))? {
                let Some(hex) = blob.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if marked.contains(hex) || !idle(&blob, grace) {
                    survivors.insert(hex.to_string());
                    continue;
                }
                report.bytes_freed += std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
                remove(&blob)?;
                report.blobs_dropped += 1;
            }
        }

        // Now the sidecars held back above: drop one exactly when its manifest blob is
        // gone. A candidate whose blob survived — an index child the mark kept — keeps the
        // record that makes it readable.
        for (sidecar, hex) in &sidecar_candidates {
            if survivors.contains(hex) {
                continue;
            }
            remove(sidecar)?;
            report.manifests_dropped += 1;
        }

        // Membership markers whose blob is gone — including the ones this run just
        // orphaned, which is why it runs after the blob sweep and reads `survivors`. A
        // marker is never a gc *root*: what keeps a blob alive is a tag or a fresh
        // manifest, not a record of which repo may read it.
        // The walk's completeness answer is discarded here only because it does not depend
        // on `kind`: the `bail!` above already refused this pass if any of `repos/` was
        // unreadable, so by now there is nothing left for it to report.
        for blobs_dir in self.repo_dirs("blobs").0 {
            for marker in dir_files(&blobs_dir) {
                let Some(hex) = marker.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                // Anything not named like a blob is not a marker; leave it alone.
                if !is_blob_hex(hex) || survivors.contains(hex) {
                    continue;
                }
                remove(&marker)?;
                report.blob_markers_dropped += 1;
            }
        }

        for upload in dir_files(&self.root.join("uploads")) {
            if idle(&upload, grace) {
                if let Some(id) = upload.file_name().and_then(|n| n.to_str()) {
                    // One syscall, not `exists()` then `remove`: the same path resolved
                    // twice is a race, and a binding already gone is success here.
                    remove_if_present(&self.upload_owner_path(id))?;
                }
                remove(&upload)?;
                report.uploads_dropped += 1;
            }
        }
        // An owner record whose session is already gone (dropped by an earlier sweep, or by
        // a finish that could not clean up) is not an upload and is not counted as one.
        // Gated on `grace` like every other removal here: `start_upload` writes the binding
        // *before* the session, so a binding with no session may simply be a push that
        // started moments ago, and deleting it would leave a session nothing can finish.
        for owner in dir_files(&self.root.join("uploads").join("owners")) {
            let orphaned = owner
                .file_name()
                .and_then(|n| n.to_str())
                .is_none_or(|id| !self.upload_path(id).is_file());
            if orphaned && idle(&owner, grace) {
                remove(&owner)?;
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

        // per-repo content: a repo is a dir under repos/ holding any of its own
        // subdirectories. `blobs/` counts — a pull-through cache serving tag pulls holds
        // membership records and nothing else (a relayed tag manifest is never persisted),
        // and reporting it as no repositories at all would hide every one of those inodes.
        let base = self.root.join("repos");
        let mut repo_dirs: BTreeSet<PathBuf> = BTreeSet::new();
        // `stats` reports; it deletes nothing, so an incomplete walk here only
        // under-reports and is not worth failing the command for.
        let (dirs, _unseen) = self.repo_dirs_any(REPO_SUBDIRS);
        for d in dirs {
            if let Some(p) = d.parent() {
                repo_dirs.insert(p.to_path_buf());
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
            // Filtered like the membership count below, so a stray `.tmp.*` from a torn
            // write cannot inflate one and not the other.
            r.manifests = dir_files(&repo_dir.join("manifests"))
                .iter()
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(is_blob_hex)
                })
                .count();
            r.members = dir_files(&repo_dir.join("blobs"))
                .iter()
                .filter(|m| {
                    m.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(is_blob_hex)
                })
                .count();
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
            s.total_members += r.members;
            s.repos.push(r);
        }
        Ok(s)
    }

    /// One kind of layout directory under `repos/`, and the first path the walk could not
    /// see through — see [`Store::repo_dirs_any`] for the walk's rules, for why it stops at
    /// every one of [`REPO_SUBDIRS`], and for what that second element obliges `gc` to do.
    fn repo_dirs(&self, kind: &str) -> (Vec<PathBuf>, Option<PathBuf>) {
        self.repo_dirs_any(&[kind])
    }

    /// Every directory under `repos/` whose name is one of `kinds`, and the first path the
    /// walk could not see through.
    ///
    /// The descent is `lstat`-based (`DirEntry::file_type`, not `Path::is_dir`), so a
    /// symlink is never followed — it could point back up its own tree, and `/browse`
    /// reaches this once per page load — and depth-bounded by [`MAX_NAME_SEGMENTS`], the
    /// same bound `valid_name` puts on a name, so no name this store accepted is out of
    /// reach.
    ///
    /// It stops at any of [`REPO_SUBDIRS`], not only at `kinds`: a repository's `blobs/`
    /// holds one marker per member, and descending into it to look for a `tags/` that
    /// cannot be there would cost a `stat` per marker on every gc, `stats` and repository
    /// listing. Stopping there makes this O(repositories).
    fn repo_dirs_any(&self, kinds: &[&str]) -> (Vec<PathBuf>, Option<PathBuf>) {
        let mut out = Vec::new();
        let mut unseen: Option<PathBuf> = None;
        let mut stack = vec![(self.root.join("repos"), 0usize)];
        while let Some((d, depth)) = stack.pop() {
            let entries = match std::fs::read_dir(&d) {
                Ok(e) => e,
                // `repos/` itself absent is an empty store, not an incomplete walk
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && depth == 0 => continue,
                Err(_) => {
                    unseen = unseen.or(Some(d));
                    continue;
                }
            };
            for e in entries {
                let Ok(e) = e.and_then(|e| e.file_type().map(|t| (e.path(), t))) else {
                    unseen = unseen.or_else(|| Some(d.clone()));
                    continue;
                };
                let (p, ft) = e;
                if ft.is_symlink() {
                    // Not followed, and not silently ignored either: nothing this store
                    // writes is a symlink, so one means the tree is not what gc assumes.
                    unseen = unseen.or(Some(p));
                    continue;
                }
                if !ft.is_dir() {
                    continue;
                }
                // Every layout dir terminates the descent, not just the ones asked for: a
                // repo path component named like one is unsupported either way (see above),
                // so a sibling is never a repo to descend into. Descending one would also
                // spend the depth budget a full-length name needs — and then report the
                // store's own tree as unseen. It is what keeps this O(repositories) rather
                // than one `stat` per membership marker under `blobs/`.
                let base = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                if REPO_SUBDIRS.contains(&base) {
                    if kinds.contains(&base) {
                        out.push(p);
                    }
                } else if depth < MAX_NAME_SEGMENTS {
                    stack.push((p, depth + 1));
                } else {
                    unseen = unseen.or(Some(p));
                }
            }
        }
        (out, unseen)
    }
}

/// The directories a repository keeps its own state in. The walk in
/// [`Store::repo_dirs_any`] stops at these, so they are also the names a repository path
/// component may not have — a pre-existing limitation of this layout, now shared by
/// `blobs` as it always was by `tags` and `manifests`.
const REPO_SUBDIRS: &[&str] = &["tags", "manifests", "blobs"];

/// Ceiling on a manifest `PUT` body. An OCI manifest is kilobytes — the OCI spec suggests
/// 4 MiB as an upper bound — and every digest inside one costs authorization work under
/// the store lock, so this is a limit on that work as much as on memory.
const MAX_MANIFEST_BYTES: usize = 4 << 20;

/// Ceiling on the distinct digests one manifest may reference. Real images have tens of
/// layers; this is far above that, and it is what bounds the `stat`s a single `PUT` can
/// ask for (references × repositories the caller may read).
const MAX_MANIFEST_REFERENCES: usize = 4096;

/// What a [`Store::gc`] pass removed (or, on a dry run, would remove).
#[derive(Default)]
pub struct GcReport {
    pub tags_dropped: usize,
    pub manifests_dropped: usize,
    pub blobs_dropped: usize,
    /// stored (on-disk) bytes of the dropped blobs
    pub bytes_freed: u64,
    pub uploads_dropped: usize,
    /// membership markers removed because the blob they named is gone
    pub blob_markers_dropped: usize,
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
    /// membership markers across every repo, summed — the inode cost of repo-scoping
    pub total_members: usize,
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
    /// membership markers this repo holds — one inode per blob it may serve, which is the
    /// only on-disk cost repo-scoping adds
    pub members: usize,
}

/// A manifest's referenced descriptors, in order: its config (if any) then each layer,
/// as `(label, descriptor)`. Structural, so it needs no OCI types and tolerates media
/// types it does not know — the one walk [`manifest_blob_sizes`] and `/browse`'s detail
/// page both read the referenced blobs out of.
pub(crate) fn manifest_descriptors(
    manifest: &serde_json::Value,
) -> Vec<(&'static str, &serde_json::Value)> {
    let mut out = Vec::new();
    if let Some(c) = manifest.pointer("/config") {
        out.push(("config", c));
    }
    if let Some(layers) = manifest.pointer("/layers").and_then(|l| l.as_array()) {
        out.extend(layers.iter().map(|l| ("layer", l)));
    }
    out
}

/// A manifest's own declared `mediaType`, when it declares one. OCI requires the field and
/// Docker's schema 2 has always sent it, so it is the honest answer for a manifest read
/// through a repository that holds no Content-Type sidecar for it. The caller holds it to
/// [`MANIFEST_MEDIA_TYPES`], which is what makes an arbitrary string here harmless.
fn declared_media_type(manifest: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    Some(v.pointer("/mediaType")?.as_str()?.to_string())
}

/// A lowercase 64-char sha256 hex — what names a blob on disk, and therefore what may be
/// a membership marker, or the hash half of a content-keyed tag.
fn is_blob_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Every digest a manifest references, tolerantly: its config and layers, *and* an image
/// index's child manifests. Unlike [`manifest_digest_hexes`] — whose caller is the gc
/// mark, which must refuse what it cannot fully walk — this is for recording membership,
/// where an unparseable or unfamiliar manifest should contribute what it can rather than
/// fail a push.
///
/// Failing open (an empty result for bytes that are not JSON) is deliberate and grants
/// nothing: contributing no digests records no membership, so the only thing readable
/// through the repository afterwards is the manifest's own bytes, which the caller
/// supplied. A digest in an algorithm this store does not use, or in uppercase hex, is
/// dropped for the same reason — nothing here can serve it either.
fn manifest_child_hexes(manifest: &[u8]) -> Vec<String> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(manifest) else {
        return Vec::new();
    };
    let children = v
        .pointer("/manifests")
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
        .map(|m| m.pointer("/digest"));
    // `subject` is a reference like any other: a referrers manifest that named one and did
    // not mount it would push fine and then 404 on the subject it points at.
    manifest_descriptors(&v)
        .into_iter()
        .map(|(_, d)| d.pointer("/digest"))
        .chain(children)
        .chain(std::iter::once(v.pointer("/subject/digest")))
        .filter_map(|d| d?.as_str())
        // `strip_prefix`, not `trim_start_matches`: exactly one `sha256:`, and a digest in
        // another algorithm — or with no algorithm at all — is dropped rather than
        // half-parsed. Dropping one means it is not checked, which grants nothing: this
        // store names blobs by `sha256:<lowercase hex>` and `valid_digest` refuses any
        // other spelling, so there is no way to read back what was skipped.
        .filter_map(|d| d.strip_prefix("sha256:"))
        .filter(|h| is_blob_hex(h))
        .map(str::to_string)
        .collect()
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
    manifest_descriptors(&v)
        .into_iter()
        .filter_map(|(_, d)| {
            let hex = d.pointer("/digest").and_then(|x| x.as_str())?;
            let size = d
                .pointer("/size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            Some((hex.trim_start_matches("sha256:").to_string(), size))
        })
        .collect()
}

/// [`dir_files`] for the directories [`Store::gc`] decides removals against, where a
/// listing it could not complete is a set it must not sweep against: an unreadable `tags/`
/// yields no tags, which unroots every blob that repo's tags reference, and an unreadable
/// `blobs/sha256` yields no survivors, which unroots every membership record. The lenient
/// version stays right for `uploads/`, where a missed entry only leaves something unswept.
fn root_dir_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let e = e.with_context(|| format!("reading an entry of {}", dir.display()))?;
        let ft = e
            .file_type()
            .with_context(|| format!("stat-ing {}", e.path().display()))?;
        if !ft.is_file() {
            bail!(
                "{} is not a plain file; refusing to sweep on marks that would be incomplete",
                e.path().display()
            );
        }
        out.push(e.path());
    }
    Ok(out)
}

/// [`root_dir_files`] where the directory may legitimately not exist yet — `blobs/zstd`
/// is created on the first compressed blob, so its absence is an empty pool rather than a
/// listing that failed.
fn root_dir_files_opt(dir: &Path) -> Result<Vec<PathBuf>> {
    match std::fs::metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        _ => root_dir_files(dir),
    }
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
    // Resolved before `into_state` consumes the config; bound after it, because the
    // listener is only worth having once the db behind it is open.
    let admin_socket = cfg.resolved_admin_socket();
    let mut state = cfg.into_state()?;
    state.tls = tls;
    let state = Arc::new(state);
    // Accounts mode only, and the db the socket administers is the one this server holds —
    // `Authenticator` is what says whether there is one at all.
    if let (Some(path), Authenticator::Accounts { db, .. }) = (admin_socket, &state.auth) {
        // A warning, not a failure: the registry's job is serving the store, and this
        // channel is a convenience for the operator CLI, which still works with the server
        // stopped. Refusing to start over a socket path — a read-only directory, a file
        // somebody left at the name, another process listening there — would let the
        // convenience take the service down, which is the one thing it must not do.
        match admin::bind(&path) {
            Ok(listener) => {
                eprintln!(
                    "vk-registry: accounts admin socket on {} — `vk-registry accounts` \
                     needs no downtime",
                    path.display()
                );
                tokio::spawn(admin::serve_admin(listener, db.clone()));
            }
            Err(e) => eprintln!(
                "vk-registry: warning: no accounts admin socket: {e:#}; `vk-registry \
                 accounts` will need this server stopped"
            ),
        }
    }
    serve_on(listener, state).await
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
) -> Result<Response<Body>, Infallible> {
    Ok(route(req, state).await.unwrap_or_else(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            &format!("{e:#}"),
        )
    }))
}

async fn route(req: Request<Incoming>, state: Arc<ServerState>) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();

    // OIDC login/callback/logout must be reachable without a principal — gating the
    // sign-in page on being signed in already would make it unreachable. Exempt from
    // the auth gate below, the same way `/lock/` is exempt from `/v2/` routing.
    if matches!(path.as_str(), "/login" | "/auth/callback" | "/logout") {
        return oidc::route(&state, req).await;
    }

    // Client auth on every other path, including the `/v2/` version probe. Returning
    // 401 + WWW-Authenticate on `/v2/` is exactly how OCI clients discover they must
    // authenticate (oci_client's store_auth_if_needed probes `/v2/`): leaving it open
    // (200) makes the client assume no auth is needed and then 401 on the real blob
    // requests. Capability detection (transparent-zstd) authenticates its own `/v2/` probe.
    //
    // Accounts mode resolves a `Principal` instead: authentication only here (is there
    // *anyone* valid) — the `/v2/*` branches below each call `authorize_or_forbidden` once
    // they know the repo name and whether the request reads or writes (see DESIGN.md's
    // "Accounts, OIDC, and scoped API keys").
    let is_browse = is_browse_path(&path);
    // Both browser-facing families, for the answers that differ by *audience* rather than
    // by route: an HTML page and a login redirect for a person, the JSON envelope and a
    // bare 401 for an OCI/CI client.
    let is_human = is_human_path(&path);
    let principal = match &state.auth {
        Authenticator::Accounts { db, .. } => {
            let resolved = match accounts::resolve_principal(db, &req, state.cookies_are_secure()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vk-registry: resolving a credential: {e:#}");
                    return Ok(if is_human {
                        html::error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            None,
                            None,
                            "Something went wrong",
                            "The server could not check your credentials. Try again shortly.",
                        )
                    } else {
                        error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL",
                            "could not check the request's credentials",
                        )
                    });
                }
            };
            if resolved.is_none() {
                // A browser on a human-facing page is sent to sign in and back to where
                // it started; an API path (`/v2/*`, `/lock/*`) gets the 401 an OCI/CI
                // client already knows how to react to.
                if is_human {
                    return Ok(redirect_to_login(&path));
                }
                return Ok(accounts::challenge());
            }
            resolved
        }
        Authenticator::Shared(auth) => {
            if auth.enabled() && !auth.allows(&req) {
                return Ok(auth.challenge());
            }
            None
        }
    };

    // Derived from `state.auth`, not from whether a principal happens to be present: in
    // accounts mode a missing one is refused above, and reading its absence as `NoScopes`
    // here would be a path that silently skips every per-repo check.
    let authz = match (&state.auth, &principal) {
        (Authenticator::Accounts { .. }, Some(p)) => Authz::Accounts(p),
        (Authenticator::Accounts { .. }, None) => return Ok(accounts::challenge()),
        (Authenticator::Shared(_), _) => Authz::NoScopes,
    };

    if is_browse {
        // `/browse` is part of accounts mode and nothing else. It is the only surface
        // that *enumerates* repository names (there is no `/v2/_catalog` here), so
        // serving it in shared-secret mode — where `Auth::None` is an ordinary local
        // configuration — would hand the store's inventory to anyone who can reach the
        // port. In that mode the route does not exist at all, rather than existing
        // unauthenticated.
        let (Authenticator::Accounts { db, .. }, Some(principal)) = (&state.auth, &principal)
        else {
            // Byte-identical to the catch-all 404 below, deliberately: the other pages
            // here answer a browser with HTML, but this one has to be indistinguishable
            // from any unknown path. An HTML page where a random path gets JSON would
            // tell an unauthenticated caller that `/browse` is a route this server knows,
            // which is the one thing this branch exists not to say.
            return Ok(error_response(StatusCode::NOT_FOUND, "NOT_FOUND", &path));
        };
        // Read-only pages: they answer the two methods a browser reads with and nothing
        // else, like every other route here. A page that carries a session's CSRF secret
        // has no business also answering the verbs that change state.
        if !matches!(req.method(), &Method::GET | &Method::HEAD) {
            return Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                &path,
            ));
        }
        // The session's CSRF secret, for the sign-out control the page renders. It is
        // session state rather than user state, so it travels beside the principal
        // instead of inside it.
        let csrf = match principal {
            accounts::Principal::Session(_) => {
                let secure = state.cookies_are_secure();
                accounts::session_cookie(req.headers(), secure).and_then(|id| {
                    match db.session_csrf(&id) {
                        Ok(v) => v,
                        // Not worth a 500 on a page that renders fine without it: the
                        // sign-out control is simply left unarmed, and it says so in the
                        // log.
                        Err(e) => {
                            eprintln!("vk-registry: reading a session's CSRF secret: {e:#}");
                            None
                        }
                    }
                })
            }
            accounts::Principal::ApiKey(_) => None,
        };
        // The prefix `is_browse` matched, stripped once here rather than re-derived there.
        let rest = path
            .strip_prefix("/browse")
            .unwrap_or_default()
            .trim_start_matches('/');
        return browse::route(&state.store, db, rest, &authz, principal, csrf.as_deref());
    }
    if is_settings_path(&path) {
        let (Authenticator::Accounts { db, .. }, Some(p)) = (&state.auth, &principal) else {
            // Byte-identical to the catch-all 404, for the reason the `/browse` branch
            // above gives: in shared-secret mode this route does not exist, rather than
            // existing and saying so.
            return Ok(error_response(StatusCode::NOT_FOUND, "NOT_FOUND", &path));
        };
        if path == "/settings/captions" {
            return captions::route(db, p, state.cookies_are_secure(), req).await;
        }
        return keys::route(db, p, state.cookies_are_secure(), req).await;
    }
    if is_upload_path(&path) {
        let (Authenticator::Accounts { db, .. }, Some(p)) = (&state.auth, &principal) else {
            // Byte-identical to the catch-all 404, as its two siblings above are: in
            // shared-secret mode this route does not exist, rather than existing and
            // saying so to an unauthenticated caller.
            return Ok(error_response(StatusCode::NOT_FOUND, "NOT_FOUND", &path));
        };
        return upload::route(&state.store, db, p, state.cookies_are_secure(), req).await;
    }

    // The build-once lock API lives under `/lock/<action>` (all POST), outside the
    // `/v2/` OCI namespace; names are `?name=` params.
    if path.starts_with("/lock/") {
        return lock::route(&state.locks, req).await;
    }
    let store = state.store.clone();
    let method = req.method().clone();
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
            .body(body_of(Bytes::from_static(b"{}")))
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
        if let Some(resp) = authorize_or_forbidden(&authz, accounts::Action::Write, name) {
            return Ok(resp);
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
        if let Some(resp) = authorize_or_forbidden(&authz, accounts::Action::Read, name) {
            return Ok(resp);
        }
        let head = method == Method::HEAD;
        return match method {
            Method::GET | Method::HEAD => {
                // Repo-scoped: the digest has to be one this repository holds, or one the
                // caller could fetch from a repository it may read anyway. A digest it
                // merely *knows* is not a key to the whole store.
                let hex = digest.trim_start_matches("sha256:");
                let local = if readable_through(&authz, &store, name, hex) {
                    get_blob(&store, digest, head, accept_zstd)?
                } else {
                    error_response(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", digest)
                };
                // A blob this repository does not hold falls through to the relay
                // exactly as an absent one does — which is the point: "not a member" and
                // "not here" must be indistinguishable to the caller. The upstream fetch
                // is authorized by the `Read` on `name` checked above, and the relay maps
                // `name` to its own upstream repository, so what comes back belongs to
                // this repository and is recorded as such.
                //
                // A `HEAD` never relays. It is a client's dedup probe before a push, and
                // relaying it answers for the upstream a question the client asked about
                // *this* registry: it would report a blob this store does not hold, the
                // client would skip the upload, and the manifest naming it would then be
                // refused. A puller loses nothing — a 404 here is followed by the `GET`,
                // which does relay.
                if !head && local.status() == StatusCode::NOT_FOUND && !state.upstreams.is_empty() {
                    relay::get_blob(&state, name, digest, accept_zstd).await
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
        let action = if method == Method::PUT {
            accounts::Action::Write
        } else {
            accounts::Action::Read
        };
        if let Some(resp) = authorize_or_forbidden(&authz, action, name) {
            return Ok(resp);
        }
        return match method {
            Method::PUT => {
                let ctype = req
                    .headers()
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(DEFAULT_MANIFEST_TYPE)
                    .to_string();
                // Capped, because the authorization below is per referenced digest and
                // runs while holding the store lock: an unbounded body would be an
                // unbounded amount of work a single write-scoped caller can ask for.
                match collect_capped(req, MAX_MANIFEST_BYTES).await {
                    // Every digest this manifest names has to be one the caller may
                    // already read; otherwise write access to one repository would be a
                    // way to pull anything whose digest you can guess or overhear.
                    // Checked under the store lock, inside `put_manifest`.
                    Ok(body) => put_manifest(&authz, &store, name, reference, &ctype, &body),
                    // A body that failed mid-read lands here too; it gets the same answer
                    // because there is no longer a connection to give it a better one.
                    Err(_) => Ok(error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "MANIFEST_INVALID",
                        reference,
                    )),
                }
            }
            Method::GET | Method::HEAD => {
                let head = method == Method::HEAD;
                // A tag lives in the repository, so it is already scoped; a digest
                // reference is not, and gets the same treatment as a blob — a manifest
                // read by digest is how one would otherwise enumerate another repo's
                // layers.
                let scoped = match reference.strip_prefix("sha256:") {
                    Some(hex) => readable_through(&authz, &store, name, hex),
                    None => true,
                };
                let local = if scoped {
                    get_manifest(&store, name, reference, head)?
                } else {
                    error_response(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", reference)
                };
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
        if let Some(resp) = authorize_or_forbidden(&authz, accounts::Action::Read, name) {
            return Ok(resp);
        }
        return list_tags(&store, name);
    }

    Ok(error_response(StatusCode::NOT_FOUND, "NOT_FOUND", &path))
}

/// POST /v2/<name>/blobs/uploads/ — open an upload session (an empty temp file).
fn start_upload(store: &Store, name: &str) -> Result<Response<Body>> {
    // The counter keeps ids unique within a process; the random tail keeps them
    // unguessable, so one client cannot append to another's in-flight upload by
    // enumerating session ids.
    let id = format!(
        "{}-{}-{}",
        std::process::id(),
        store.next_upload.fetch_add(1, Ordering::Relaxed),
        accounts::random_token(16),
    );
    // The binding first, the session second: `upload_is_for` fails closed, so a session
    // file that existed before its binding would be a session nothing could finish — and,
    // worse, the gc's orphaned-binding sweep keys on "a binding whose session is absent".
    // Written with `create_new` so a colliding id is an error rather than an overwrite of
    // somebody else's session, and owner-only from creation.
    //
    // Remember which repository this session was authorized for: the caller is checked
    // against `name` at every step, so a session started in a repo the caller may write
    // must not be finishable into one it may not.
    create_private(&store.upload_owner_path(&id), name.as_bytes())
        .context("recording the upload's repository")?;
    create_private(&store.upload_path(&id), b"").context("creating the upload file")?;
    accepted_upload(name, &id, 0)
}

/// Whether `id` is an upload session opened for `name`.
///
/// Fails closed: this is the check that keeps a session from being finished into a
/// repository it was not opened in, and an authorization question whose answer on a read
/// error is "yes" is not a check. A binding that cannot be read — absent, unreadable,
/// truncated — therefore means "no", and the client re-POSTs the session, which is what
/// every OCI client already does with a `BLOB_UPLOAD_UNKNOWN`. `start_upload` writes the
/// binding before the session, so there is no window in which a live session has none.
fn upload_is_for(store: &Store, id: &str, name: &str) -> bool {
    std::fs::read(store.upload_owner_path(id)).is_ok_and(|recorded| recorded == name.as_bytes())
}

/// PATCH /v2/<name>/blobs/uploads/<id> — append a chunk to the session file.
fn patch_upload(store: &Store, name: &str, id: &str, body: &[u8]) -> Result<Response<Body>> {
    if !valid_upload_id(id) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            id,
        ));
    }
    let path = store.upload_path(id);
    if !path.is_file() || !upload_is_for(store, id, name) {
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
/// promote the session file to the store under the client's digest — which is verified
/// against the bytes, and only for the repository the session was opened in. Storage is
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
) -> Result<Response<Body>> {
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
    if !upload.is_file() || !upload_is_for(store, id, name) {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            id,
        ));
    }
    if !body.is_empty() {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&upload)
            .with_context(|| format!("opening {}", upload.display()))?;
        f.write_all(body).context("appending the final chunk")?;
    }

    // Check the digest against the canonical bytes before anything is promoted: the store
    // is content-addressed, so a blob filed under a digest it does not hash to is a lie
    // every later pull repeats. A zstd upload is hashed by streaming its decode
    // ([`hash_zstd_frame`]) rather than reading the canonical form into memory — the frame
    // is client-controlled and expands without bound, so materialising it is a one-request
    // memory exhaustion. A raw upload *is* its canonical form, so it is read once and
    // reused for the adaptive store below.
    let mut raw: Option<Vec<u8>> = None;
    let hashed = if body_is_zstd {
        hash_zstd_frame(&upload)?.map(|(hex, _)| hex)
    } else {
        let bytes =
            std::fs::read(&upload).with_context(|| format!("reading {}", upload.display()))?;
        let hex = sha256_hex_raw(&bytes);
        raw = Some(bytes);
        Some(hex)
    };
    // A frame this server will not store, or bytes that hash to something else: either way
    // the client's request is wrong, not this server, so it is a 400 rather than a 500 —
    // and the session goes, so a retry cannot append onto a body already found bad.
    if hashed.as_deref() != Some(hex.as_str()) {
        let _ = std::fs::remove_file(&upload);
        let _ = std::fs::remove_file(store.upload_owner_path(id));
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("the uploaded bytes are not a storable frame hashing to {digest}"),
        ));
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
        store.put_blob_at(&hex, raw.as_deref().unwrap_or_default())?;
        let _ = std::fs::remove_file(&upload);
    }
    // The upload was authorized for, and bound to, this repository, and the bytes hashed
    // to the digest above — so this is where the blob becomes readable through it. After
    // the promotion, so a membership record never names a blob that is not there.
    store.record_blob(name, &hex)?;
    let _ = std::fs::remove_file(store.upload_owner_path(id));

    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/{name}/blobs/{digest}"))
        .header("Docker-Content-Digest", &digest)
        .header(hyper::header::CONTENT_LENGTH, "0")
        .body(body_of(Bytes::new()))
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
) -> Result<Response<Body>> {
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
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream");

    // The wire length, and what the body has to produce to match it: the stored frame
    // verbatim when the client takes zstd, the canonical bytes otherwise. Both are known
    // without reading the blob — a zstd frame carries its decompressed size in the header
    // — so `Content-Length` is exact on a streamed response, as a HEAD needs it to be.
    let serve_frame = is_zstd && accept_zstd;
    let decode = is_zstd && !serve_frame;
    let builder = if serve_frame {
        builder.header(hyper::header::CONTENT_ENCODING, "zstd")
    } else {
        builder
    };
    // Opened once, and the length taken from that same descriptor rather than from the path again:
    // a `gc` can unlink the stored form, and a re-push can rename a different encoding of the same
    // content over it, between two resolutions of one path. The fd also pins the inode for the
    // whole response — every writer here reaches a blob path by `rename`, never by truncating in
    // place, so an in-flight stream keeps serving what it opened even once `gc` has swept the name.
    let mut file =
        std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let len = if decode {
        zstd_canonical_len(&mut file)
            .with_context(|| format!("measuring the stored blob {digest}"))?
    } else {
        file.metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len()
    };
    let builder = builder.header(hyper::header::CONTENT_LENGTH, len.to_string());
    if head {
        return builder.body(body_of(Bytes::new())).map_err(Into::into);
    }

    // Streamed, never read whole: a layer can be gigabytes, and one buffered per
    // in-flight request is how a registry runs its host out of memory. The decode for a
    // client that does not take zstd rides the same stream — `zstd::stream::read::Decoder`
    // is just another reader, and it is decompressing on the blocking pool either way.
    let body = if decode {
        stream_body(
            zstd::stream::read::Decoder::new(file).context("opening a stored blob")?,
            digest,
        )
    } else {
        stream_body(file, digest)
    };
    builder.body(body).map_err(Into::into)
}

/// PUT /v2/<name>/manifests/<tag|digest> — store the manifest bytes (content
/// addressed) + its Content-Type sidecar, and point the tag at it (if a tag).
///
/// The membership check on the referenced digests happens here, inside the same shared
/// lock as the write: checking it outside would leave a window for a `gc` to sweep a
/// layer between "the caller may reference this" and the manifest that references it.
fn put_manifest(
    authz: &Authz<'_>,
    store: &Store,
    name: &str,
    reference: &str,
    ctype: &str,
    body: &[u8],
) -> Result<Response<Body>> {
    // shared store lock for the write (vs. an exclusive gc); see lock_shared.
    let _lock = store.lock_shared()?;
    // A digest reference that does not match the body is the client's error, not this
    // server's, so it is the spec's 400 rather than `handle`'s JSON 500.
    if reference.starts_with("sha256:") && reference != format!("sha256:{}", sha256_hex_raw(body)) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("the manifest body does not hash to {reference}"),
        ));
    }
    match authorize_and_mount_manifest_blobs(authz, store, name, body)? {
        Mount::Done => {}
        Mount::Unreadable(hex) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "MANIFEST_BLOB_UNKNOWN",
                &format!("sha256:{hex}"),
            ));
        }
        Mount::TooManyReferences => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "MANIFEST_INVALID",
                &format!("over {MAX_MANIFEST_REFERENCES} referenced digests"),
            ));
        }
    }
    let digest = store.put_manifest(name, reference, ctype, body)?;
    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", format!("/v2/{name}/manifests/{digest}"))
        .header("Docker-Content-Digest", &digest)
        .body(body_of(Bytes::new()))
        .map_err(Into::into)
}

/// GET/HEAD /v2/<name>/manifests/<tag|digest>.
pub(crate) fn get_manifest(
    store: &Store,
    name: &str,
    reference: &str,
    head: bool,
) -> Result<Response<Body>> {
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
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(hyper::header::CONTENT_TYPE, &ctype)
        .header(hyper::header::CONTENT_LENGTH, len.to_string())
        .body(body_of(if head {
            Bytes::new()
        } else {
            Bytes::from(data)
        }))
        .map_err(Into::into)
}

/// GET /v2/<name>/tags/list.
fn list_tags(store: &Store, name: &str) -> Result<Response<Body>> {
    let tags = store.list_tags(name);
    let body = serde_json::json!({ "name": name, "tags": tags }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body_of(Bytes::from(body)))
        .map_err(Into::into)
}

/// A 202 Accepted upload-progress response (POST/PATCH), carrying the session
/// Location the client uses for the next request.
fn accepted_upload(name: &str, id: &str, size: u64) -> Result<Response<Body>> {
    let range_end = size.saturating_sub(1);
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", format!("/v2/{name}/blobs/uploads/{id}"))
        .header("Range", format!("0-{range_end}"))
        .header("Docker-Upload-UUID", id)
        .header(hyper::header::CONTENT_LENGTH, "0")
        .body(body_of(Bytes::new()))
        .map_err(Into::into)
}

/// An OCI error response: the documented `{ "errors": [ { code, message } ] }` body.
pub(crate) fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Body> {
    let body =
        serde_json::json!({ "errors": [ { "code": code, "message": message } ] }).to_string();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        // `message` echoes caller-supplied bytes (a path, a reference) on every `/v2` error,
        // from the origin that also serves `/browse`; one header here covers all of them.
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(body_of(Bytes::from(body)))
        .expect("building an error response")
}

/// The 401 an unauthenticated protected request gets. `challenge` is the whole
/// `WWW-Authenticate` value, and it is load-bearing rather than decoration: an OCI client
/// that probes `/v2/` and gets a 401 without it concludes no credential is wanted and then
/// fails on the real blob requests (see `route`'s auth gate).
pub(crate) fn unauthorized(challenge: &'static str, message: &str) -> Response<Body> {
    let mut response = error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message);
    response.headers_mut().insert(
        hyper::header::WWW_AUTHENTICATE,
        hyper::header::HeaderValue::from_static(challenge),
    );
    response
}

/// Which authorization model this request is being served under — built from
/// `ServerState::auth`, so "which model" is never inferred from whether a principal turned
/// up. Passing this rather than an `Option<Principal>` keeps [`authorize_or_forbidden`]
/// from having to read "no principal" as "allow"; in accounts mode a request without one
/// is refused before this is built, and a future path that reached here without one is a
/// refusal rather than a check silently skipped.
pub(crate) enum Authz<'a> {
    /// Shared-secret (or open) mode: the single gate at the top of `route` is the whole
    /// authorization model, and there is nothing per-repo to check.
    NoScopes,
    Accounts(&'a accounts::Principal),
}

impl Authz<'_> {
    /// Whether this caller may read `repo`.
    fn may_read(&self, repo: &str) -> bool {
        match self {
            Authz::NoScopes => true,
            Authz::Accounts(p) => accounts::authorize(p, accounts::Action::Read, repo),
        }
    }
}

/// Whether `hex` may be read through repository `name` by this caller.
///
/// The store is one content-addressed pool, so holding a digest is not an entitlement to
/// it: the blob has to be a member of `name`. The second clause is what keeps that from
/// being needlessly strict — if the caller may read *some* repository that holds the
/// blob, it could fetch the same bytes there, so serving them here discloses nothing new
/// and cross-repo dedup keeps working. In shared-secret mode every repo is readable, so
/// no read is ever refused that was served before.
///
/// The `any_holds` walk is O(readable repositories) and runs only on a miss in `name`,
/// so a pull — every digest a member of the repository it is pulled from — pays one
/// `stat`. A caller naming digests it does not hold pays the walk per request; see
/// DESIGN.md.
pub(crate) fn readable_through(authz: &Authz<'_>, store: &Store, name: &str, hex: &str) -> bool {
    // Shared-secret (or open) mode has no per-repo scopes to enforce: every repository is
    // readable, so this is unconditionally true and no read is refused that was not
    // refused before.
    if matches!(authz, Authz::NoScopes) {
        return true;
    }
    if store.repo_has_blob(name, hex) || store.repo_has_manifest(name, hex) {
        return true;
    }
    store.any_holds(&readable_repos(authz, store, name), hex)
}

/// The other repositories this caller may read — computed before any per-digest work, so
/// a manifest with hundreds of layers walks `repos/` once rather than once per layer, and
/// so no repository the caller may not read is ever consulted on disk.
fn readable_repos(authz: &Authz<'_>, store: &Store, name: &str) -> Vec<String> {
    store
        .all_repo_names()
        .into_iter()
        .filter(|r| r != name && authz.may_read(r))
        .collect()
}

/// What [`authorize_and_mount_manifest_blobs`] decided about a manifest's references.
enum Mount {
    /// Every referenced digest was readable by the caller; membership is now recorded in
    /// this repository for the ones that were not already members of it.
    Done,
    /// This digest is readable by the caller nowhere, so the manifest is refused. It is
    /// the first such digest in the manifest's own order, which is the one a client
    /// author reading the error will look for.
    Unreadable(String),
    /// More distinct references than [`MAX_MANIFEST_REFERENCES`], so the manifest is
    /// refused before doing the work: each reference costs a `stat` per repository the
    /// caller may read.
    TooManyReferences,
}

/// Authorize a manifest's references and record, in `name`, the ones it accepts —
/// refusing the whole manifest if the caller cannot already read one of them somewhere.
///
/// This is the check that stops a caller with write access to one repository from naming a
/// digest it learned elsewhere and reading the content back through its own repo. It is
/// also the OCI cross-repo mount, arrived at from the other end: a push whose layers are
/// already in the store and already readable by this caller does not re-upload them.
///
/// Membership granted here is permanent, where the read that justified it was not: later
/// revoking this caller's read scope on the repository a digest was mounted from does not
/// un-mount it. That is deliberate — the caller could have downloaded the bytes and
/// re-uploaded them while it still had the scope, so mounting grants it nothing it could
/// not already have taken. See DESIGN.md.
fn authorize_and_mount_manifest_blobs(
    authz: &Authz<'_>,
    store: &Store,
    name: &str,
    body: &[u8],
) -> Result<Mount> {
    // Manifest order, deduped — so the refusal names the first offending digest as the
    // manifest lists it, not the lexicographically smallest one. Counted before any
    // filesystem work, so the cap bounds the `stat`s below whatever order the digests
    // happen to resolve in — and before the shared-secret shortcut below, so the cap is
    // one rule rather than one that only some deployments get.
    let mut seen = HashSet::new();
    let references: Vec<String> = manifest_child_hexes(body)
        .into_iter()
        .filter(|hex| seen.insert(hex.clone()))
        .collect();
    if references.len() > MAX_MANIFEST_REFERENCES {
        return Ok(Mount::TooManyReferences);
    }
    // Without per-repo scopes there is nothing to authorize, and nothing to record: a
    // reference is not evidence that whoever wrote it holds the content, in this mode as
    // in any other. Pre-seeding membership here would hand a later switch to accounts
    // mode exactly the reference-derived graph the write rule refuses to build.
    if matches!(authz, Authz::NoScopes) {
        return Ok(Mount::Done);
    }
    let elsewhere = readable_repos(authz, store, name);
    let mut to_mount = Vec::new();
    for hex in references {
        if store.repo_has_blob(name, &hex) || store.repo_has_manifest(name, &hex) {
            continue;
        }
        // One `stat` settles a digest this store does not hold at all — which is what a
        // caller guessing digests produces — before paying a walk per readable repository.
        // `find_blob` rather than `has_blob`: a probe must not refresh the gc clock on
        // content the caller has no claim to.
        //
        // The two refusals are the same answer, but not the same *latency*: "not here at
        // all" costs two `stat`s where "here but not yours" costs a walk. That is a noisy
        // timing probe for "this store holds D", which is a weaker leak than the ordering
        // is worth — a caller guessing digests would otherwise walk every readable
        // repository per guess.
        if store.find_blob(&hex).is_none() || !store.any_holds(&elsewhere, &hex) {
            return Ok(Mount::Unreadable(hex));
        }
        // Readable elsewhere, so mounting it here grants nothing new.
        to_mount.push(hex);
    }
    for hex in &to_mount {
        store.record_blob(name, hex)?;
    }
    Ok(Mount::Done)
}

/// Enforce [`accounts::authorize`] for `action` on `name`. `Some(response)` ⇒ refuse and
/// return it; `None` ⇒ the caller may proceed.
fn authorize_or_forbidden(
    authz: &Authz<'_>,
    action: accounts::Action,
    name: &str,
) -> Option<Response<Body>> {
    match authz {
        Authz::NoScopes => None,
        Authz::Accounts(p) if accounts::authorize(p, action, name) => None,
        Authz::Accounts(_) => Some(accounts::forbidden()),
    }
}

/// The paths a browser hits rather than an OCI/CI client — so an unauthenticated request
/// there is sent to `/login` instead of getting the bare 401 `/v2/*`/`/lock/*` clients
/// expect, and so shared-secret mode can refuse them outright.
fn is_human_path(path: &str) -> bool {
    is_browse_path(path) || is_settings_path(path) || is_upload_path(path)
}

fn is_browse_path(path: &str) -> bool {
    path == "/browse" || path.starts_with("/browse/")
}

fn is_settings_path(path: &str) -> bool {
    path == "/settings/keys" || path.starts_with("/settings/keys/") || path == "/settings/captions"
}

fn is_upload_path(path: &str) -> bool {
    path == "/upload"
}

/// Send an unauthenticated browser to `/login`, remembering `target` so it lands back
/// where it started once signed in (`oidc::login`'s `?target=` handling).
///
/// The path only, never its query: `oidc::is_safe_redirect_target` is a charset allowlist
/// a `?a=b` would fail anyway, so carrying one through would only produce a target
/// silently replaced by the default. Nothing under `/browse` reads a query; the day one
/// does, both ends move together. Same reason a `/browse/a..b` — which `valid_name`
/// permits and that allowlist does not — lands on `/browse` rather than the page asked
/// for: fail closed, and keep the allowlist the narrower of the two.
fn redirect_to_login(target: &str) -> Response<Body> {
    let url = format!("/login?target={}", percent_encode(target));
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, url)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(body_of(Bytes::new()))
        .expect("building a login redirect")
}

/// Collect a request body fully into memory. Bodies here are bounded by the
/// client's chunk size (≤ one FastCDC chunk, ≤16 MiB) plus small manifests.
async fn collect(req: Request<Incoming>) -> Result<Bytes> {
    Ok(req.into_body().collect().await?.to_bytes())
}

/// Collect a body that has a small, known ceiling — a browser form or a manifest, not a
/// blob. The cap
/// is enforced *while* reading, not after: a `Transfer-Encoding: chunked` request
/// declares no length, so a check on the size hint alone would buffer the whole thing
/// first and cap nothing.
pub(crate) async fn collect_capped(req: Request<Incoming>, cap: usize) -> Result<Bytes> {
    http_body_util::Limited::new(req.into_body(), cap)
        .collect()
        .await
        .map(|b| b.to_bytes())
        .map_err(|_| anyhow::anyhow!("request body is over the {cap}-byte cap"))
}

/// Escape the five HTML-significant characters. Every *string* a browser-facing page
/// interpolates goes through this, unconditionally — some of them (repo and tag names) are
/// already restricted by `valid_name`/`valid_reference`, others (manifest JSON fields,
/// identity-provider claims) are not restricted at all, and a page is not the place to be
/// keeping track of which is which. Counts and sizes are rendered as the integers they
/// are.
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// True if request header `name` lists `needle` (e.g. `Accept-Encoding: zstd`).
/// Substring match — fine for the single token we negotiate.
fn header_has(req: &Request<Incoming>, name: hyper::header::HeaderName, needle: &str) -> bool {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains(needle))
}

/// Remove `path`, treating "it was not there" as success — one resolution, where an
/// `exists()` test followed by a `remove` would be two and could lose the race between
/// them.
fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Create `path` with `data`, failing if it already exists — `create_new` rather than
/// `write`, so a path that is already a file (or a symlink to one) is an error instead of
/// something this server writes through, and the mode is set at creation rather than in a
/// second call with a window in between.
fn create_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("creating {}", path.display()))?
        .write_all(data)
        .with_context(|| format!("writing {}", path.display()))
}

/// Ceiling on the canonical (decompressed) size of a *pushed* blob. A zstd frame is a
/// client-controlled input that expands without bound — tens of KiB of zeros become tens
/// of GB — so the push path will not decompress one that does not declare a size up front,
/// and will not read past the size it declared. Far above any real layer.
const MAX_CANONICAL_BLOB: u64 = 64 << 30;

/// `(sha256 hex, byte count)` of a zstd frame's decompressed content, or `None` if the
/// frame is not one this server will store.
///
/// The content is streamed through the hasher, never materialised: it is the digest that
/// is wanted, and the bytes stored are the frame itself. Refused unless the header declares
/// a content size within [`MAX_CANONICAL_BLOB`] *and* the decode produces exactly that many
/// bytes — the header is what a later `HEAD` answers `Content-Length` from (see
/// [`zstd_canonical_len`]), so a frame whose header and body disagree, or a concatenation
/// of frames whose first header speaks only for itself, would make `HEAD` and `GET`
/// contradict each other about a blob this server had certified.
fn hash_zstd_frame(path: &Path) -> Result<Option<(String, u64)>> {
    use std::io::Read;

    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut head = Vec::with_capacity(ZSTD_HEADER_MAX);
    f.by_ref()
        .take(ZSTD_HEADER_MAX as u64)
        .read_to_end(&mut head)
        .with_context(|| format!("reading the zstd header of {}", path.display()))?;
    let Some(declared) = zstd_frame_len(&head).filter(|n| *n <= MAX_CANONICAL_BLOB) else {
        return Ok(None);
    };
    std::io::Seek::rewind(&mut f).with_context(|| format!("rewinding {}", path.display()))?;

    // Multi-frame, like the `decode_all` the read path serves with, so `total` counts what
    // a reader would actually get.
    let mut dec = zstd::stream::read::Decoder::new(std::io::BufReader::new(f))
        .context("starting a zstd decode")?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        // A malformed frame is invalid client input, not a server fault: `None`, not `Err`.
        let Ok(n) = dec.read(&mut buf) else {
            return Ok(None);
        };
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > declared {
            return Ok(None);
        }
        hasher.update(buf.get(..n).unwrap_or_default());
    }
    if total != declared {
        return Ok(None);
    }
    Ok(Some((hex_of(&hasher.finalize()), total)))
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

/// Canonical (decompressed) length of a stored zstd blob, read from the frame header
/// alone. Our encoder always records the content size, so the full-decode fallback (for a
/// frame that omits it) is only a correctness backstop — and it counts the decoded bytes
/// through a sink rather than collecting them, so no path here holds a blob in memory.
///
/// `f` is left rewound to the start, so the caller can go on to stream the same
/// descriptor. Only the *first* frame's header is read, while a decoder consumes every
/// concatenated frame; the two agree because every writer of `blobs/zstd` makes them —
/// [`hash_zstd_frame`] refuses an upload whose declared size does not match what the whole
/// decode produced, and `compress_beside`/[`zstd_with_size`] pledge the size to the
/// encoder, which then fails the frame itself on a mismatch.
fn zstd_canonical_len(f: &mut std::fs::File) -> Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut head = Vec::with_capacity(ZSTD_HEADER_MAX);
    f.by_ref()
        .take(ZSTD_HEADER_MAX as u64)
        .read_to_end(&mut head)
        .context("reading a stored blob's zstd header")?;
    f.seek(SeekFrom::Start(0))
        .context("rewinding a stored blob")?;
    if let Some(len) = zstd_frame_len(&head) {
        return Ok(len);
    }
    let counted = std::io::copy(
        &mut zstd::stream::read::Decoder::new(&mut *f).context("decompressing a stored blob")?,
        &mut std::io::sink(),
    )
    .context("decompressing a stored blob")?;
    f.seek(SeekFrom::Start(0))
        .context("rewinding a stored blob")?;
    Ok(counted)
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

/// Warn when `path` is reachable in a way it should not be — `forbidden` is the mode bits
/// that must be clear (`0o077` for "owner only", `0o022` for "nobody else may write").
/// A warning, not an error: the operator may have a reason, and refusing to start would be
/// a worse answer than saying so.
///
/// For a file that is about to be opened anyway, prefer [`warn_if_file_mode`]: this
/// resolves the path a second time, so the mode it reports is not necessarily the file the
/// caller goes on to open.
#[cfg(unix)]
pub(crate) fn warn_if_mode(path: &Path, forbidden: u32, what: &str, advice: &str) {
    if let Ok(meta) = std::fs::metadata(path) {
        warn_mode(&meta, path, forbidden, what, advice);
    }
}

/// [`warn_if_mode`] against an open descriptor — one path resolution, so the mode reported
/// is the file that got opened.
#[cfg(unix)]
pub(crate) fn warn_if_file_mode(
    file: &std::fs::File,
    path: &Path,
    forbidden: u32,
    what: &str,
    advice: &str,
) {
    if let Ok(meta) = file.metadata() {
        warn_mode(&meta, path, forbidden, what, advice);
    }
}

#[cfg(unix)]
fn warn_mode(meta: &std::fs::Metadata, path: &Path, forbidden: u32, what: &str, advice: &str) {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    if mode & forbidden != 0 {
        eprintln!(
            "vk-registry: warning: {what} {} has mode {:o}; {advice}",
            path.display(),
            mode & 0o7777
        );
    }
}

#[cfg(not(unix))]
pub(crate) fn warn_if_mode(_path: &Path, _forbidden: u32, _what: &str, _advice: &str) {}

#[cfg(not(unix))]
pub(crate) fn warn_if_file_mode(
    _file: &std::fs::File,
    _path: &Path,
    _forbidden: u32,
    _what: &str,
    _advice: &str,
) {
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

/// Ceiling on a repository name's `/`-separated components. A name *is* a directory path
/// under `repos/`, so its depth is what [`Store::repo_dirs`]' walk has to descend — and
/// `gc` marks from that walk. Bounding it here, where a name is accepted, is what keeps
/// the walk's own bound unreachable: a name gc could not reach is a name whose blobs it
/// would sweep. Far past any real name (`bundles/appbuilder` is two).
const MAX_NAME_SEGMENTS: usize = 16;

/// A repository name: one to [`MAX_NAME_SEGMENTS`] `/`-separated path components, each a
/// non-empty run of `[A-Za-z0-9._-]` and not `.`/`..` — so it never escapes the store dir.
/// Shared with `/browse`, whose repo segment is just as untrusted as the OCI API's
/// `<name>`.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').count() <= MAX_NAME_SEGMENTS
        && name.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                // A component named like one of a repository's own subdirectories would be
                // indistinguishable from the layout: `repos/a/blobs` would be both a
                // repository and `a`'s membership directory, and the walk in
                // `repo_dirs_any` — which stops at those names — would never reach its
                // tags, so the gc mark would miss its roots and sweep its content. Refuse
                // the name instead of losing the data.
                && !REPO_SUBDIRS.contains(&seg)
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// `sha256:<64 lowercase hex>` — lowercase as the spec mandates, and as
/// [`sha256_hex_raw`] produces, so a digest that passes here is one the store can
/// actually compare against and find.
fn valid_digest(d: &str) -> bool {
    // Lowercase only, matching [`is_blob_hex`]: blobs are named by lowercase hex on disk,
    // so accepting uppercase here would let the read predicate and the write predicate
    // disagree about the same digest.
    d.strip_prefix("sha256:").is_some_and(is_blob_hex)
}

/// A manifest reference: a digest, or a single safe tag component. Shared with
/// `/browse`'s manifest-detail page.
pub(crate) fn valid_reference(r: &str) -> bool {
    valid_digest(r) || valid_tag(r)
}

/// Shared with `/upload`, whose tag field must be a tag, not a digest — a digest-shaped
/// value there would silently skip the tag-pointer write ([`Store::put_manifest`]'s
/// digest-reference rule) instead of erroring, which would confuse rather than help.
pub(crate) fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t != "."
        && t != ".."
        && !t.contains('/')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An upload id is one this server minted (`<pid>-<n>-<random hex>`): hex digits and
/// dashes, nothing else — no path separator, and no `.`, so an id can never name the
/// `owners/` record that sits in a subdirectory of its own.
fn valid_upload_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// Look up a query parameter (percent-decoding the value, since the client encodes
/// the `sha256:` digest's colon as `%3A`).
pub(crate) fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Percent-encode a string for use as one query-parameter value: everything but the
/// unreserved set (`A-Za-z0-9-._~`) becomes `%XX`. Its callers build URLs — the OIDC
/// endpoints and the `?target=` on a login redirect — never HTML, so this needs no
/// HTML-escaping counterpart; that is [`html_escape`].
pub(crate) fn percent_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => write!(out, "%{b:02X}").expect("writing to a String cannot fail"),
        }
    }
    out
}

/// Minimal application/x-www-form-urlencoded decode: `%XX` hex escapes and `+`.
///
/// Bytes throughout, and never a `&str` slice: a byte-length guard is not a char-boundary
/// guard, so slicing `s[i + 1..i + 3]` after checking `i + 3 <= s.len()` panics whenever a
/// `%` is followed by a multi-byte character (`"%€"`). Every caller here feeds it a query
/// string or a form body, which is exactly where an attacker chooses the bytes.
fn percent_decode(s: &str) -> String {
    /// One hex digit's value, or `None` — including for a byte that is not one.
    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'%' => {
                let pair = b
                    .get(i + 1)
                    .copied()
                    .and_then(hex)
                    .zip(b.get(i + 2).copied().and_then(hex));
                match pair {
                    Some((h, l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    // not an escape after all: the `%` is literal
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
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
        "vk registry: gc {}: {} {} tag(s), {} manifest(s), {} blob(s) ({:.1} MiB), \
         {} upload(s), {} membership record(s)",
        store.root.display(),
        if dry_run { "would drop" } else { "dropped" },
        r.tags_dropped,
        r.manifests_dropped,
        r.blobs_dropped,
        r.bytes_freed as f64 / f64::from(1u32 << 20),
        r.uploads_dropped,
        r.blob_markers_dropped,
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
        "  content:  {} repo(s), {} tag(s), {} manifest(s), {} membership record(s)",
        s.repos.len(),
        s.total_tags,
        s.total_manifests,
        s.total_members,
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
            "  {:<40} {:>5} {:>7} {:>10}  LATEST",
            "REPOSITORY", "TAGS", "MEMBERS", "SIZE"
        );
        for r in &s.repos {
            println!(
                "  {:<40} {:>5} {:>7} {:>10}  {}",
                r.name,
                r.tags,
                r.members,
                human_bytes(r.logical_bytes),
                r.latest_tag.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

/// A byte count in binary units (`B`, `KiB`, ... `PiB`), one decimal past `B`. Shared
/// with `/browse`'s pages.
pub(crate) fn human_bytes(n: u64) -> String {
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

/// The unit name both shapes use — the one [`install_service`] writes, and the one an admin
/// installs [`system_unit`]'s output as. Named here because whoever replaces the binary has
/// to point at the same unit to have the new one served, whichever shape it is.
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
            // `--addr` and `--config` are mutually exclusive, so the only address that can
            // reach this arm is the file's; the default stands in when it names none.
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

    /// The store something named, or `None` for the per-user default.
    pub fn named_store(&self) -> Option<&Path> {
        self.root.as_deref()
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

/// A hardened **system** unit running `serve` as `account`, for the deployment a `--user`
/// unit cannot express: machine-wide, started at boot before anyone logs in, and — when the
/// port needs it — allowed to bind a privileged one.
///
/// Returned rather than installed: writing under `/etc` and owning the store are the
/// admin's, and this binary stays free of any privileged step. The unit it hands back is
/// the point — the server it starts holds one capability and can write one directory.
/// `exe` is the installed `vk-registry` the unit should run — the caller's `current_exe`
/// in practice, a parameter so the check below is exercisable.
pub fn system_unit(facts: &UnitFacts, account: &str, exe: &Path) -> Result<String> {
    // The per-user default store is not available to this shape at all: `ProtectHome=`
    // below hides it, and the installer's home is not the service account's anyway. Ask
    // for one rather than emitting a unit that cannot start.
    let store = facts.named_store().context(
        "a --system unit needs a store of its own: pass --root, or --config naming a file \
         that sets `root`",
    )?;
    // Both paths are reached from inside the namespace `ProtectHome=` sets up, where these
    // trees are gone — a binary under one fails to exec, and a store under one silently
    // becomes an empty read-only mount that `Restart=on-failure` then loops on.
    for (what, p) in [("the binary", exe), ("the store", store)] {
        if ["/home/", "/root/", "/run/user/"]
            .iter()
            .any(|d| p.starts_with(d))
        {
            bail!(
                "{what} is at {} — ProtectHome= puts that out of a system unit's reach; \
                 install it outside /home, /root and /run/user",
                p.display()
            );
        }
    }
    // Binding below 1024 is the one thing an ordinary account cannot do. Granting the
    // capability only when the port actually needs it keeps the common case at none, and
    // the bounding set stops any other from ever being acquired either way.
    let privileged_port = if facts.addr().port() < 1024 {
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
    } else {
        "CapabilityBoundingSet=\n"
    };
    Ok(format!(
        "[Unit]\n\
         Description=virtkit OCI registry (shared microVM bundle store)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={exe} serve {args}\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         LimitNOFILE=1048576\n\
         \n\
         User={account}\n\
         {privileged_port}\
         NoNewPrivileges=yes\n\
         \n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         ReadWritePaths={store}\n\
         PrivateTmp=yes\n\
         PrivateDevices=yes\n\
         ProtectClock=yes\n\
         ProtectControlGroups=yes\n\
         ProtectHostname=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectKernelModules=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectProc=invisible\n\
         RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\
         RestrictNamespaces=yes\n\
         RestrictRealtime=yes\n\
         RestrictSUIDSGID=yes\n\
         LockPersonality=yes\n\
         MemoryDenyWriteExecute=yes\n\
         SystemCallArchitectures=native\n\
         SystemCallFilter=@system-service\n\
         SystemCallErrorNumber=EPERM\n\
         UMask=0077\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = unit_path("the binary", exe)?,
        args = facts.exec_args()?,
        store = unit_path("the store", store)?,
    ))
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

    /// A system unit runs the server as an account of its own, may write only the store,
    /// and is allowed to bind a privileged port only when the port it was given is one —
    /// the capability is what the `--user` unit could never grant, so it must not be
    /// handed out by default either.
    #[test]
    fn a_system_unit_grants_the_port_capability_only_when_the_port_needs_it() {
        let installed = Path::new("/usr/local/bin/vk-registry");
        let facts = |addr: &str| {
            UnitFacts::resolve(
                None,
                addr.parse().unwrap(),
                Some(PathBuf::from("/srv/vk-registry")),
            )
            .unwrap()
        };

        let privileged = system_unit(&facts("0.0.0.0:443"), "vk-registry", installed).unwrap();
        assert!(
            privileged.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE\n")
                && privileged.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"),
            "{privileged}"
        );

        // a high port needs none, and the bounding set is emptied rather than left default
        let plain = system_unit(&facts("127.0.0.1:5000"), "vk-registry", installed).unwrap();
        assert!(!plain.contains("Ambient"), "{plain}");
        assert!(plain.contains("CapabilityBoundingSet=\n"), "{plain}");

        // the account is the one asked for, and the store is the only writable path. No
        // `Group=`: the account's own primary group is whatever `useradd` gave it.
        let unit = system_unit(&facts("127.0.0.1:5000"), "registry-svc", installed).unwrap();
        assert!(unit.contains("User=registry-svc\n"), "{unit}");
        assert!(!unit.contains("Group="), "{unit}");
        assert!(
            unit.contains("ReadWritePaths=\"/srv/vk-registry\"\n")
                && unit.contains("ProtectSystem=strict\n"),
            "{unit}"
        );
        assert!(unit.contains("NoNewPrivileges=yes\n"), "{unit}");
        // machine-wide, so it is up before anyone logs in
        assert!(unit.contains("WantedBy=multi-user.target\n"), "{unit}");
    }

    /// The unit grants exactly the store the server it starts will open. These are two
    /// separate resolutions, and a unit whose `ReadWritePaths` names anything else is one
    /// whose store is read-only at runtime — a restart loop rather than an error.
    #[test]
    fn a_system_units_writable_path_is_the_store_its_own_exec_line_resolves() {
        let installed = Path::new("/usr/local/bin/vk-registry");
        let dir = std::env::temp_dir().join(format!("vk-regserve-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // the flags case: the root in `ExecStart` is the granted one
        let flags = UnitFacts::resolve(None, "0.0.0.0:443".parse().unwrap(), Some("/srv/a".into()))
            .unwrap();
        let unit = system_unit(&flags, "vk-registry", installed).unwrap();
        assert!(unit.contains("--root \"/srv/a\"\n"), "{unit}");
        assert!(unit.contains("ReadWritePaths=\"/srv/a\"\n"), "{unit}");

        // the config case: `ExecStart` names only the file, so the granted path has to be
        // the one that file sets — and the port for the capability comes from it too
        let cfg = dir.join("registry.toml");
        std::fs::write(&cfg, "addr = \"0.0.0.0:443\"\nroot = \"/srv/from-file\"\n").unwrap();
        let configured =
            UnitFacts::resolve(Some(&cfg), "127.0.0.1:5000".parse().unwrap(), None).unwrap();
        let unit = system_unit(&configured, "vk-registry", installed).unwrap();
        assert!(
            unit.contains(&format!("serve --config \"{}\"\n", cfg.display())),
            "{unit}"
        );
        assert!(
            unit.contains("ReadWritePaths=\"/srv/from-file\"\n"),
            "{unit}"
        );
        assert!(
            unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE\n"),
            "{unit}"
        );

        // a file naming no store leaves the per-user default, which this shape refuses
        let bare = dir.join("bare.toml");
        std::fs::write(&bare, "addr = \"0.0.0.0:443\"\n").unwrap();
        let bare_facts =
            UnitFacts::resolve(Some(&bare), "127.0.0.1:5000".parse().unwrap(), None).unwrap();
        let err = format!(
            "{:#}",
            system_unit(&bare_facts, "vk-registry", installed).unwrap_err()
        );
        assert!(err.contains("--root") && err.contains("`root`"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store or a binary under a home directory cannot be reached from inside the
    /// namespace `ProtectHome=` sets up, and a path that systemd rewrites -- a `%`
    /// specifier -- or that ends the argument early -- a quote -- is refused rather than
    /// written into a file destined for /etc as root.
    #[test]
    fn a_system_unit_refuses_what_it_cannot_faithfully_describe() {
        let installed = Path::new("/usr/local/bin/vk-registry");
        let port: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let with_root = |r: &str| UnitFacts::resolve(None, port, Some(PathBuf::from(r))).unwrap();

        for home in ["/home/vince/store", "/root/store", "/run/user/1000/store"] {
            let err = format!(
                "{:#}",
                system_unit(&with_root(home), "vk-registry", installed).unwrap_err()
            );
            assert!(err.contains("ProtectHome"), "{home}: {err}");
        }
        // the binary too, not just the store
        let err = format!(
            "{:#}",
            system_unit(
                &with_root("/srv/store"),
                "vk-registry",
                Path::new("/home/vince/bin/vk-registry")
            )
            .unwrap_err()
        );
        assert!(
            err.contains("the binary") && err.contains("ProtectHome"),
            "{err}"
        );

        // and what a unit file would read as something other than the path given
        for bad in [
            "/srv/100%store",
            "/srv/a\"b",
            "/srv/back\\slash",
            "/srv/it's",
        ] {
            let err = format!(
                "{:#}",
                system_unit(&with_root(bad), "vk-registry", installed).unwrap_err()
            );
            assert!(err.contains("systemd unit"), "{bad}: {err}");
        }
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
        open_session(&store, "img", "1-0");
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
        open_session(&store, "img", "1-1");
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

    /// Tag listing is sorted, ignores the digest references a push also records, and
    /// stays best-effort: an unknown repo and a name that could escape the store dir
    /// both come back empty rather than erroring or reading outside `repos/`.
    #[test]
    fn list_tags_sorts_known_tags_and_stays_empty_otherwise() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-tags-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let mut digest = String::new();
        for reference in ["v2", "v1", "latest"] {
            digest = store
                .put_manifest("repo", reference, DEFAULT_MANIFEST_TYPE, b"{}")
                .unwrap();
        }
        // a digest reference is self-describing: it writes no tag file
        store
            .put_manifest("repo", &digest, DEFAULT_MANIFEST_TYPE, b"{}")
            .unwrap();

        assert_eq!(store.list_tags("repo"), ["latest", "v1", "v2"]);
        assert!(store.list_tags("other").is_empty(), "unknown repo");
        assert!(store.list_tags("").is_empty(), "empty name");

        // a directory an unguarded `repos/<name>` join would escape into and read
        let escaped = dir.join("escape-target").join("tags");
        std::fs::create_dir_all(&escaped).unwrap();
        std::fs::write(escaped.join("leaked"), b"").unwrap();
        assert!(
            store.list_tags("../escape-target").is_empty(),
            "a traversing name must never be joined into a store path"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The store is content-addressed and shared by every repository, so a digest a
    /// client names has to be the digest of what it sent.
    #[test]
    fn finishing_an_upload_verifies_the_clients_digest() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-updig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let lie = format!("sha256:{}", "0".repeat(64));

        let res = start_upload(&store, "team-a/app").unwrap();
        let location = res.headers().get("Location").unwrap().to_str().unwrap();
        let id = location.rsplit('/').next().unwrap().to_string();
        let refused = finish_upload(
            &store,
            "team-a/app",
            &id,
            &format!("digest={}", percent_encode(&lie)),
            b"not those bytes",
            false,
        )
        .unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(store.find_blob(&"0".repeat(64)).is_none());

        // the truthful push still works
        let body = b"the real bytes";
        let digest = format!("sha256:{}", sha256_hex_raw(body));
        let res = start_upload(&store, "team-a/app").unwrap();
        let location = res.headers().get("Location").unwrap().to_str().unwrap();
        let id = location.rsplit('/').next().unwrap().to_string();
        let ok = finish_upload(
            &store,
            "team-a/app",
            &id,
            &format!("digest={}", percent_encode(&digest)),
            body,
            false,
        )
        .unwrap();
        assert_eq!(ok.status(), StatusCode::CREATED);
        assert!(store.has_blob(&sha256_hex_raw(body)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A transparent-zstd push stores the frame it was sent, verbatim, and only after
    /// checking that the frame decompresses to the digest claimed for it. The frame is
    /// client-controlled and expands without bound, so it is verified by streaming — never
    /// by materialising the canonical bytes — and a frame whose declared content size does
    /// not match what it actually produces is refused, because that size is what a later
    /// `HEAD` answers with.
    #[test]
    fn a_zstd_push_is_verified_by_streaming_and_stored_verbatim() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-zpush-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let raw = vec![3u8; 80_000];
        let frame = zstd_with_size(&raw).unwrap();
        let digest = format!("sha256:{}", sha256_hex_raw(&raw));

        // an honest frame: verified, then renamed into the zstd store as-is
        open_session(&store, "img", "aa-0");
        let res = finish_upload(
            &store,
            "img",
            "aa-0",
            &format!("digest={digest}"),
            &frame,
            true,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let (path, is_zstd) = store.find_blob(&hex(&digest)).expect("stored");
        assert!(is_zstd);
        assert_eq!(std::fs::read(&path).unwrap(), frame, "stored verbatim");
        let mut f = std::fs::File::open(&path).unwrap();
        assert_eq!(zstd_canonical_len(&mut f).unwrap(), raw.len() as u64);

        // a frame that decompresses to something else is refused, and takes its session
        let other = zstd_with_size(&vec![4u8; 80_000]).unwrap();
        open_session(&store, "img", "aa-1");
        let res = finish_upload(
            &store,
            "img",
            "aa-1",
            &format!("digest={digest}"),
            &other,
            true,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(
            !store.upload_path("aa-1").exists(),
            "the session is dropped"
        );

        // a body that is not a zstd frame at all is the client's error, not a 500
        open_session(&store, "img", "aa-2");
        let res = finish_upload(
            &store,
            "img",
            "aa-2",
            &format!("digest={digest}"),
            b"not zstd",
            true,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // two frames back to back: `decode_all` (and so a GET) yields both, while the
        // first header — all a HEAD reads — speaks only for the first. Refused, or the
        // two would contradict each other about a blob this server had certified.
        let pair = [frame.clone(), frame.clone()].concat();
        let pair_digest = format!(
            "sha256:{}",
            sha256_hex_raw(&[raw.clone(), raw.clone()].concat())
        );
        assert_eq!(
            zstd_frame_len(&pair),
            Some(raw.len() as u64),
            "the first header only"
        );
        assert_eq!(zstd::decode_all(&pair[..]).unwrap().len(), raw.len() * 2);
        open_session(&store, "img", "aa-4");
        let res = finish_upload(
            &store,
            "img",
            "aa-4",
            &format!("digest={pair_digest}"),
            &pair,
            true,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(!store.has_blob(&hex(&pair_digest)));

        // and a frame that does not declare its content size is not storable either: the
        // header is what `HEAD` reports, so one that says nothing cannot be certified
        let sizeless = zstd::encode_all(&raw[..], ZSTD_LEVEL).unwrap();
        assert_eq!(zstd_frame_len(&sizeless), None);
        open_session(&store, "img", "aa-3");
        let res = finish_upload(
            &store,
            "img",
            "aa-3",
            &format!("digest={digest}"),
            &sizeless,
            true,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A manifest pushed *by digest* is a claim about its own bytes. Storing it under the
    /// digest they actually hash to would answer 201 for content the client then cannot
    /// fetch under the reference it pushed — and would persist bytes it never asked to
    /// store — so the claim is checked, before anything is written.
    #[test]
    fn a_manifest_pushed_by_digest_must_hash_to_that_digest() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-mdig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let body = manifest_body(&format!("sha256:{}", "a".repeat(64)), &[]);
        let right = format!("sha256:{}", sha256_hex_raw(&body));
        let wrong = format!("sha256:{}", "b".repeat(64));

        let res = put_manifest(
            &Authz::NoScopes,
            &store,
            "img",
            &wrong,
            DEFAULT_MANIFEST_TYPE,
            &body,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(
            !store.has_blob(&hex(&right)),
            "a refused push stores nothing"
        );
        assert!(
            store
                .put_manifest("img", &wrong, DEFAULT_MANIFEST_TYPE, &body)
                .is_err()
        );

        let res = put_manifest(
            &Authz::NoScopes,
            &store,
            "img",
            &right,
            DEFAULT_MANIFEST_TYPE,
            &body,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        assert!(store.has_blob(&hex(&right)));
        // a tag reference is not a claim about the bytes, so it is stored under the digest
        // they hash to, as before
        let res = put_manifest(
            &Authz::NoScopes,
            &store,
            "img",
            "v1",
            DEFAULT_MANIFEST_TYPE,
            &body,
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An upload session opened for `name`, the way `start_upload` opens one: the binding
    /// first, then the session. Writing only the session file would leave it unfinishable,
    /// which is what `upload_is_for` failing closed means.
    fn open_session(store: &Store, name: &str, id: &str) {
        create_private(&store.upload_owner_path(id), name.as_bytes()).unwrap();
        create_private(&store.upload_path(id), b"").unwrap();
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

        // A name is a directory path under `repos/`, and `gc` marks from a walk of that
        // tree — so a name deeper than the walk descends would be a name whose blobs get
        // swept. The bound belongs here, where the name is accepted.
        let segs = |n: usize| vec!["a"; n].join("/");
        assert!(valid_name(&segs(MAX_NAME_SEGMENTS)));
        assert!(!valid_name(&segs(MAX_NAME_SEGMENTS + 1)));
    }

    /// `gc` deletes on the strength of the `repos/` walk and the tag/manifest listings it
    /// roots from, so anything it cannot see there has to abort the sweep, exactly as an
    /// unparseable manifest does. Every case runs a *real* sweep (`dry_run = false`) — a
    /// dry run deletes nothing whatever the walk said, so it could not tell the refusal
    /// from the sweep it is meant to prevent.
    #[test]
    fn gc_refuses_to_sweep_on_roots_it_could_not_read() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcwalk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let raw = vec![7u8; 4096];
        let digest = store.put_blob(&raw).unwrap();
        let hex = digest.trim_start_matches("sha256:").to_string();
        let body = manifest_body(&digest, &[]);
        store
            .put_manifest("app", "v1", DEFAULT_MANIFEST_TYPE, &body)
            .unwrap();
        // a retention window the fresh tag is well inside, so a sweep that sees the tag
        // keeps its blob and one that does not deletes it — the difference under test
        let sweep = |store: &Store| store.gc(DAY, DAY, false);
        let refusal = |store: &Store| match sweep(store) {
            Ok(_) => panic!("gc must refuse roots it could not read"),
            Err(e) => e.to_string(),
        };

        // the ordinary case: a complete walk, and the tag keeps its blob alive
        assert!(
            store.repo_dirs("tags").1.is_none(),
            "a plain store is all seen"
        );
        sweep(&store).expect("an ordinary sweep");
        assert!(store.has_blob(&hex), "a tagged manifest's blob survives");

        // a symlink under `repos/` is not followed, so the walk cannot see through it
        let link = dir.join("repos").join("elsewhere");
        std::os::unix::fs::symlink(dir.join("repos").join("app"), &link).unwrap();
        assert_eq!(
            store.repo_dirs("tags").1.as_deref(),
            Some(link.as_path()),
            "the walk names the symlink it would not follow"
        );
        let e = refusal(&store);
        assert!(
            e.contains("refusing to sweep") && e.contains("elsewhere"),
            "{e}"
        );
        assert!(store.has_blob(&hex), "and it deleted nothing");
        std::fs::remove_file(&link).unwrap();

        // a `tags/` directory the walk *reaches* but cannot list: it yields no tags, so
        // without the strict listing the manifest would be unrooted and its blob swept
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tags = dir.join("repos").join("app").join("tags");
            std::fs::set_permissions(&tags, std::fs::Permissions::from_mode(0o000)).unwrap();
            let e = refusal(&store);
            std::fs::set_permissions(&tags, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(e.contains("tags"), "{e}");
            assert!(store.has_blob(&hex), "and it deleted nothing");
        }

        // a `blobs/sha256` the pass cannot list is the same class of blindness, and now a
        // worse one: it decides no blob survived, and the membership and sidecar sweeps that
        // read that answer would drop every record while keeping every blob
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // the membership record a push would have left, which is what the sweeps that
            // read `survivors` would drop
            store.record_blob("app", &hex).unwrap();
            assert!(store.repo_has_blob("app", &hex));

            let pool = dir.join("blobs").join("sha256");
            std::fs::set_permissions(&pool, std::fs::Permissions::from_mode(0o000)).unwrap();
            let e = refusal(&store);
            std::fs::set_permissions(&pool, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(e.contains("blobs"), "{e}");
            assert!(store.has_blob(&hex), "and it deleted nothing");
            assert!(
                store.repo_has_blob("app", &hex),
                "nor revoked the membership that makes it readable"
            );
        }

        // and a repository name of the full permitted depth is still swept: the walk's
        // depth bound and `valid_name`'s have to meet exactly, or a name the store accepts
        // is a name gc refuses forever
        let deep = vec!["a"; MAX_NAME_SEGMENTS].join("/");
        assert!(valid_name(&deep));
        store
            .put_manifest(&deep, "v1", DEFAULT_MANIFEST_TYPE, &body)
            .unwrap();
        assert!(
            store.repo_dirs("tags").1.is_none(),
            "a name of the full permitted depth is not past the walk's bound"
        );
        sweep(&store).expect("and it still sweeps");
        assert!(store.has_blob(&hex));

        let _ = std::fs::remove_dir_all(&dir);
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

    /// Membership is recorded for content the registry received, and nothing else. In
    /// particular a manifest records *itself* but not what it references: a reference is
    /// not evidence that whoever wrote it holds the content.
    #[test]
    fn a_blob_is_a_member_only_of_the_repos_that_hold_it() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-member-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let layer = store.put_blob(b"layer bytes").unwrap();
        let hex = layer.trim_start_matches("sha256:").to_string();
        // `put_blob` alone is content, not entitlement: nobody holds it yet.
        assert!(!store.repo_has_blob("team-a/app", &hex));

        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{layer}","size":11}},"layers":[]}}"#
        );
        let mdigest = store
            .put_manifest(
                "team-a/app",
                "v1",
                DEFAULT_MANIFEST_TYPE,
                manifest.as_bytes(),
            )
            .unwrap();
        let mhex = mdigest.trim_start_matches("sha256:").to_string();

        // The manifest's own bytes are ours, so it is readable through this repo — on the
        // strength of its Content-Type sidecar, which *is* its membership record. There is
        // deliberately no second marker under `blobs/` for it.
        assert!(store.repo_has_manifest("team-a/app", &mhex));
        assert!(!store.repo_has_blob("team-a/app", &mhex));
        assert!(store.any_holds(&["team-a/app".to_string()], &mhex));
        // ... but naming the layer granted nothing. Only an upload, a relay fetch, or an
        // authorized mount does that.
        assert!(!store.repo_has_blob("team-a/app", &hex));
        assert!(!store.repo_has_blob("team-b/app", &hex));

        store.record_blob("team-a/app", &hex).unwrap();
        assert!(store.repo_has_blob("team-a/app", &hex));
        assert!(!store.repo_has_blob("team-b/app", &hex));
        assert!(store.any_holds(&["team-a/app".to_string()], &hex));
        assert!(!store.any_holds(&["team-b/app".to_string()], &hex));

        // and a name nobody pushed to is answered without creating anything for it
        assert!(!store.repo_has_blob("made/up", &hex));
        assert!(!dir.join("repos/made/up").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A marker records which repo may read a blob; it must not keep the blob alive, and
    /// it must not outlive it.
    #[test]
    fn gc_sweeps_a_membership_record_whose_blob_is_gone() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-memgc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let layer = store.put_blob(b"collectible").unwrap();
        let hex = layer.trim_start_matches("sha256:").to_string();
        store.record_blob("team-a/app", &hex).unwrap();
        assert!(store.repo_has_blob("team-a/app", &hex));

        // A dry run reports what a real one would take, records included: it must not
        // read "nothing to sweep" off a blob its own `remove` deliberately left in place.
        let dry = store.gc(Duration::ZERO, Duration::ZERO, true).unwrap();
        assert_eq!(dry.blobs_dropped, 1);
        assert_eq!(dry.blob_markers_dropped, 1);
        assert!(
            store.repo_has_blob("team-a/app", &hex),
            "a dry run removes nothing"
        );

        // Nothing roots the blob — no tag, no manifest — so the sweep takes it, and the
        // record of who could read it goes with it.
        let report = store.gc(Duration::ZERO, Duration::ZERO, false).unwrap();
        assert_eq!(report.blobs_dropped, dry.blobs_dropped);
        assert_eq!(report.blob_markers_dropped, dry.blob_markers_dropped);
        assert!(!store.repo_has_blob("team-a/app", &hex));
        // and the marker did not root it
        assert!(store.find_blob(&hex).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A membership record names content, so it is refused for anything that could not be
    /// content: a bad repository name, or a digest that is not how a blob is named.
    #[test]
    fn recording_a_membership_rejects_an_invalid_name_or_digest() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-memval-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let hex = "a".repeat(64);

        assert!(store.record_blob("team-a/app", &hex).is_ok());
        assert!(store.record_blob("../escape", &hex).is_err());
        assert!(store.record_blob("team-a/blobs", &hex).is_err());
        assert!(store.record_blob("", &hex).is_err());
        assert!(store.record_blob("team-a/app", "").is_err());
        assert!(store.record_blob("team-a/app", "../../etc/passwd").is_err());
        assert!(store.record_blob("team-a/app", &"A".repeat(64)).is_err());
        // and a refusal creates nothing
        assert!(!dir.join("repos/../escape").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A manifest's Content-Type sidecar is its membership record, so the gc must not drop
    /// one whose bytes the same pass keeps. An image index is the case that bites: the mark
    /// aborts on it, so anything removed before the mark is removed on a pass that then
    /// sweeps nothing — and the index's children would be left permanently unreadable.
    #[test]
    fn gc_keeps_the_membership_of_a_manifest_whose_blob_it_keeps() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-memidx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // Two per-arch children, pushed by digest, then an index tagged `v1`.
        let mut children = Vec::new();
        for arch in ["amd64", "arm64"] {
            let body = format!(
                r#"{{"schemaVersion":2,"config":{{"digest":"sha256:{}","size":1}},"layers":[],"arch":"{arch}"}}"#,
                "c".repeat(64)
            );
            let digest = store
                .put_manifest(
                    "team-a/app",
                    &format!("sha256:{}", sha256_hex_raw(body.as_bytes())),
                    DEFAULT_MANIFEST_TYPE,
                    body.as_bytes(),
                )
                .unwrap();
            children.push(digest.trim_start_matches("sha256:").to_string());
        }
        let index = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"digest":"sha256:{}","size":1}},{{"digest":"sha256:{}","size":1}}]}}"#,
            children[0], children[1]
        );
        store
            .put_manifest("team-a/app", "v1", DEFAULT_MANIFEST_TYPE, index.as_bytes())
            .unwrap();
        for hex in &children {
            assert!(store.repo_has_manifest("team-a/app", hex));
        }

        // A retention window that keeps the tag (so the index is a root and the mark
        // reaches it) with no grace on the blobs (so the children are sweep candidates).
        // The mark refuses an index, so the pass aborts — and nothing may have been
        // revoked on the way there.
        assert!(
            store
                .gc(Duration::from_secs(3600), Duration::ZERO, false)
                .is_err(),
            "the gc mark still refuses an image index"
        );
        for hex in &children {
            assert!(
                store.repo_has_manifest("team-a/app", hex),
                "an aborted pass must not have dropped a child's membership"
            );
            assert!(
                store
                    .get_manifest("team-a/app", &format!("sha256:{hex}"))
                    .unwrap()
                    .is_some()
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pull-through cache serving tag pulls holds membership records and nothing else —
    /// a relayed tag manifest is never persisted. `status` has to see that repository, or
    /// it reports no repositories and no records while the inodes pile up.
    #[test]
    fn stats_counts_a_repo_that_holds_only_membership_records() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-memstats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let layer = store.put_blob(b"relayed layer").unwrap();
        let hex = layer.trim_start_matches("sha256:").to_string();
        store.record_blob("cache/app", &hex).unwrap();

        let s = store.stats().unwrap();
        assert_eq!(s.repos.len(), 1, "a records-only repo is still a repo");
        assert_eq!(s.repos[0].name, "cache/app");
        assert_eq!(s.repos[0].tags, 0);
        assert_eq!(s.repos[0].manifests, 0);
        assert_eq!(s.repos[0].members, 1);
        assert_eq!(s.total_members, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The authorization a manifest `PUT` runs costs a `stat` per (referenced digest,
    /// readable repository) pair, under the store lock, so the reference count is capped:
    /// one write-scoped caller must not be able to ask for unbounded work.
    #[test]
    fn a_manifest_referencing_too_many_digests_is_refused() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-memcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let principal = accounts::Principal::Session(accounts::User {
            id: "https://issuer\u{1f}sub-1".to_string(),
            oidc_issuer: "https://issuer".to_string(),
            oidc_subject: "sub-1".to_string(),
            email: None,
            display_name: None,
            is_admin: false,
            created_at: SystemTime::UNIX_EPOCH,
            last_login_at: SystemTime::UNIX_EPOCH,
        });
        let authz = Authz::Accounts(&principal);

        let layers: Vec<String> = (0..=MAX_MANIFEST_REFERENCES)
            .map(|i| format!(r#"{{"digest":"sha256:{i:064x}","size":1}}"#))
            .collect();
        let over = format!(r#"{{"schemaVersion":2,"layers":[{}]}}"#, layers.join(","));
        assert!(matches!(
            authorize_and_mount_manifest_blobs(&authz, &store, "team-a/app", over.as_bytes())
                .unwrap(),
            Mount::TooManyReferences
        ));

        // Just inside the cap is refused for the honest reason instead: the store holds
        // none of it, so the first digest is simply not readable anywhere.
        let under = format!(
            r#"{{"schemaVersion":2,"layers":[{}]}}"#,
            layers[..MAX_MANIFEST_REFERENCES].join(",")
        );
        assert!(matches!(
            authorize_and_mount_manifest_blobs(&authz, &store, "team-a/app", under.as_bytes())
                .unwrap(),
            Mount::Unreadable(_)
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A repository whose path component collides with the layout would be both a
    /// repository and another repository's membership directory — and the walk that stops
    /// at those names would never reach its tags, so the gc would sweep its content.
    #[test]
    fn a_repo_name_may_not_collide_with_the_layout() {
        for kind in REPO_SUBDIRS {
            assert!(!valid_name(kind), "{kind} is a layout directory");
            assert!(!valid_name(&format!("team-a/{kind}")), "{kind} as a leaf");
            assert!(
                !valid_name(&format!("team-a/{kind}/app")),
                "{kind} in the middle"
            );
            // the name is only refused as a whole component
            assert!(valid_name(&format!("team-a/{kind}-cache")));
        }
        assert!(valid_name("team-a/app"));
    }

    /// A manifest readable through a repository that was never pushed it — a mounted index
    /// child, or the cross-repo clause of `readable_through` — has no Content-Type sidecar
    /// there. Answering the default would call a manifest list an image manifest, so the
    /// bytes' own `mediaType` answers instead.
    #[test]
    fn a_manifest_without_a_sidecar_is_served_the_type_it_declares() {
        let dir =
            std::env::temp_dir().join(format!("vk-regserve-nosidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let index_type = "application/vnd.oci.image.index.v1+json";
        let index =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;
        let digest = store
            .put_manifest("team-a/app", "v1", index_type, index)
            .unwrap();

        // Pushed here, so the sidecar answers.
        let (_, _, ctype) = store.get_manifest("team-a/app", &digest).unwrap().unwrap();
        assert_eq!(ctype, index_type);
        // Readable through a repository that never received it: no sidecar, so the
        // manifest says what it is rather than being mislabelled an image manifest.
        store
            .record_blob("team-b/app", digest.trim_start_matches("sha256:"))
            .unwrap();
        let (_, _, ctype) = store.get_manifest("team-b/app", &digest).unwrap().unwrap();
        assert_eq!(ctype, index_type);

        assert_eq!(declared_media_type(b"not json"), None);
        assert_eq!(declared_media_type(br#"{"mediaType":42}"#), None);

        // And a type outside the allowlist is not served, however it got there. These are
        // uploaded bytes, not a pushed manifest, so nothing vouched for them: a caller who
        // may write one repository must not be able to read JSON back off this origin as
        // `text/html`, nor smuggle a header through a `mediaType`.
        let hostile = br#"{"mediaType":"text/html","layers":[]}"#;
        let hhex = sha256_hex_raw(hostile);
        store.put_blob_at(&hhex, hostile).unwrap();
        store.record_blob("team-a/app", &hhex).unwrap();
        let (_, _, ctype) = store
            .get_manifest("team-a/app", &format!("sha256:{hhex}"))
            .unwrap()
            .unwrap();
        assert_eq!(ctype, DEFAULT_MANIFEST_TYPE);
        // same for a pushed Content-Type, which lands in the sidecar verbatim
        let pushed = store
            .put_manifest("team-a/app", "evil", "text/html", br#"{"layers":[]}"#)
            .unwrap();
        let (_, _, ctype) = store.get_manifest("team-a/app", &pushed).unwrap().unwrap();
        assert_eq!(ctype, DEFAULT_MANIFEST_TYPE);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without per-repo scopes there is nothing to authorize *and* nothing to record: a
    /// reference is not evidence in shared-secret mode either. Recording here would hand a
    /// later switch to accounts mode the reference-derived membership the write rule
    /// refuses to build.
    #[test]
    fn a_manifest_put_without_scopes_records_only_the_manifest() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-noscope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let layer = store.put_blob(b"someone else's layer").unwrap();
        let hex = layer.trim_start_matches("sha256:").to_string();
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{layer}","size":20}},"layers":[]}}"#
        );

        // The bytes are in the pool, and the manifest names them — which grants nothing.
        let outcome = authorize_and_mount_manifest_blobs(
            &Authz::NoScopes,
            &store,
            "team-a/app",
            manifest.as_bytes(),
        )
        .unwrap();
        assert!(matches!(outcome, Mount::Done), "nothing to authorize");
        assert!(!store.repo_has_blob("team-a/app", &hex));

        let digest = store
            .put_manifest(
                "team-a/app",
                "v1",
                DEFAULT_MANIFEST_TYPE,
                manifest.as_bytes(),
            )
            .unwrap();
        // Its own bytes, and only those.
        assert!(store.repo_has_manifest("team-a/app", digest.trim_start_matches("sha256:")));
        assert!(!store.repo_has_blob("team-a/app", &hex));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A read that fails part-way ends the body as an error, naming the blob — not as a
    /// short but successful one, which would hand a client a truncated blob under a
    /// `Content-Length` that says otherwise.
    #[tokio::test]
    async fn a_stream_that_fails_part_way_ends_as_an_error() {
        /// Yields one full chunk, then fails.
        struct Flaky(bool);
        impl std::io::Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    buf.fill(b'x');
                    return Ok(buf.len());
                }
                Err(std::io::Error::other("the disk went away"))
            }
        }

        let mut body = stream_body(Flaky(true), "sha256:beef");
        let first = body
            .frame()
            .await
            .expect("a frame")
            .expect("the first chunk must arrive");
        assert_eq!(first.into_data().unwrap().len(), STREAM_CHUNK);

        let err = body
            .frame()
            .await
            .expect("the body must not simply end")
            .expect_err("a failed read must end the body as an error");
        let shown = err.to_string();
        assert!(
            shown.contains("sha256:beef") && shown.contains("the disk went away"),
            "the error must name the blob and the cause, got {shown}"
        );
    }

    /// A reader whose length is an exact multiple of the chunk ends on the empty read,
    /// neither one chunk short nor with a trailing empty frame.
    #[tokio::test]
    async fn a_stream_of_whole_chunks_ends_cleanly() {
        let reader = std::io::Cursor::new(vec![b'x'; 2 * STREAM_CHUNK]);
        let body = stream_body(reader, "sha256:beef");
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected.len(), 2 * STREAM_CHUNK);
        assert!(collected.iter().all(|b| *b == b'x'));
    }

    /// Every magic `already_compressed` claims to recognize, and the two shapes that must
    /// not be mistaken for one: a file too short to carry a magic, and bytes that merely
    /// start like one.
    #[test]
    fn already_compressed_knows_each_container_magic() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-magic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let probe = |name: &str, head: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, head).unwrap();
            already_compressed(&p).unwrap()
        };
        for (name, magic) in [
            ("gz", &[0x1f, 0x8b, 0x08, 0x00][..]),
            ("zst", &[0x28, 0xb5, 0x2f, 0xfd][..]),
            ("xz", &[0xfd, b'7', b'z', b'X', b'Z', 0x00][..]),
            ("bz2", b"BZh9"),
        ] {
            let mut bytes = magic.to_vec();
            bytes.extend(std::iter::repeat_n(0u8, 64));
            assert!(probe(name, &bytes), "{name} magic not recognized");
        }
        // The xz magic is six bytes, so a five-byte prefix of it is not one.
        assert!(!probe("short-xz", &[0xfd, b'7', b'z', b'X', b'Z']));
        assert!(!probe("empty", b""));
        assert!(!probe("tar", b"./PaxHeaders"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What a promoted blob costs on disk is decided on its bytes: one that is already a
    /// compressed container is stored as-is, and one that is not — an image config, an
    /// attestation, a `tar` layer with no compression — is kept as a zstd frame. Either
    /// way the digest still addresses the canonical bytes, so a pull gets back exactly
    /// what upstream served.
    #[test]
    fn a_promoted_blob_is_compressed_only_when_that_shrinks_it() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-promote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        std::fs::create_dir_all(store.uploads_dir()).unwrap();

        let promote = |name: &str, raw: &[u8]| {
            let hex = sha256_hex_raw(raw);
            let tmp = store.uploads_dir().join(name);
            std::fs::write(&tmp, raw).unwrap();
            let staged = store.stage_promotion(&hex, &tmp).unwrap();
            store.promote_staged(&hex, staged).unwrap();
            assert!(
                !tmp.exists(),
                "{name}: the staged file outlived the promote"
            );
            // whatever the storage form, the blob reads back byte-identical
            assert_eq!(
                store.get_blob(&hex).unwrap().as_deref(),
                Some(raw),
                "{name}"
            );
            hex
        };

        // an image config: compressible, so it is kept compressed and takes less room
        let config = br#"{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"]},"rootfs":{"type":"layers","diff_ids":[]}}"#.repeat(8);
        let hex = promote("config", &config);
        assert!(
            store.zstd_blob_path(&hex).is_file(),
            "not stored compressed"
        );
        assert!(std::fs::metadata(store.zstd_blob_path(&hex)).unwrap().len() < config.len() as u64);
        // The frame carries its decompressed size, which is what lets a HEAD answer with
        // the canonical Content-Length without decompressing. Nothing else would fail if a
        // later edit dropped `set_pledged_src_size`/`include_contentsize`.
        assert_eq!(
            zstd_canonical_len(&mut std::fs::File::open(store.zstd_blob_path(&hex)).unwrap())
                .unwrap(),
            config.len() as u64
        );

        // a gzip layer: already a compressed container, so it is never re-compressed
        let gz = {
            let mut v = vec![0x1f, 0x8b, 0x08, 0x00];
            v.extend(std::iter::repeat_n(b'x', 4096));
            v
        };
        let hex = promote("layer.tgz", &gz);
        assert!(
            store.blob_path(&hex).is_file() && !store.zstd_blob_path(&hex).is_file(),
            "an already-compressed layer was re-compressed"
        );

        // incompressible bytes that carry no compressed-container magic: the pass runs,
        // does not pay, and identity storage is kept rather than a frame that is bigger.
        // Chained SHA-256 output avoids patterns that zstd could compress accidentally.
        let noise: Vec<u8> = {
            let mut out = Vec::with_capacity(8192);
            let mut block = [0u8; 32];
            while out.len() < 8192 {
                block = sha2::Sha256::digest(block).into();
                out.extend_from_slice(&block);
            }
            out
        };
        let hex = promote("noise", &noise);
        assert!(
            store.blob_path(&hex).is_file() && !store.zstd_blob_path(&hex).is_file(),
            "a frame that did not shrink was kept"
        );

        // a digest already held: the staged file is dropped, nothing is rewritten
        let hex = sha256_hex_raw(&config);
        let tmp = store.uploads_dir().join("again");
        std::fs::write(&tmp, &config).unwrap();
        let staged = store.stage_promotion(&hex, &tmp).unwrap();
        store.promote_staged(&hex, staged).unwrap();
        assert!(!tmp.exists());
        assert!(!store.blob_path(&hex).is_file(), "stored a second copy");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `repo_dirs` stops at a repository's own subdirectories: descending into `blobs/`
    /// would cost a `stat` per membership marker on every gc, `stats` and listing.
    #[test]
    fn the_repo_walk_does_not_descend_into_membership_markers() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let manifest =
            br#"{"schemaVersion":2,"config":{"digest":"sha256:x","size":0},"layers":[]}"#;
        store
            .put_manifest("team-a/app", "v1", DEFAULT_MANIFEST_TYPE, manifest)
            .unwrap();
        for i in 0..40u32 {
            store
                .record_blob("team-a/app", &format!("{i:064x}"))
                .unwrap();
        }

        // The markers are not repositories, and do not multiply the walk's answers.
        assert_eq!(
            store.all_repo_names().into_iter().collect::<Vec<_>>(),
            vec!["team-a/app".to_string()]
        );
        assert_eq!(store.repo_dirs("tags").0.len(), 1);
        assert_eq!(store.repo_dirs("manifests").0.len(), 1);
        assert_eq!(store.repo_dirs("blobs").0.len(), 1);
        // and the markers change no reported count
        let s = store.stats().unwrap();
        assert_eq!(s.repos.len(), 1);
        assert_eq!(s.total_manifests, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blob_hex_is_lowercase_sha256() {
        assert!(is_blob_hex(&"a".repeat(64)));
        assert!(is_blob_hex(&"0123456789abcdef".repeat(4)));
        assert!(
            !is_blob_hex(&"A".repeat(64)),
            "uppercase is not how we name blobs"
        );
        assert!(!is_blob_hex(&"a".repeat(63)));
        assert!(!is_blob_hex(&"a".repeat(65)));
        assert!(!is_blob_hex(""));
        assert!(!is_blob_hex(&"g".repeat(64)));
        assert!(!is_blob_hex(&".".repeat(64)));
    }

    /// A manifest's Content-Type comes from whoever pushed it, and comes back out of `/v2`
    /// on this origin — the one that serves `/browse` and holds the session cookie. Anyone
    /// who may push must not be able to have stored bytes labelled `text/html`.
    #[test]
    fn a_manifest_is_served_only_as_a_manifest_type() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-mtype-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // A standard type is kept as pushed.
        let index_type = "application/vnd.oci.image.index.v1+json";
        let good = br#"{"schemaVersion":2,"manifests":[]}"#;
        let digest = store
            .put_manifest("team-a/app", "v1", index_type, good)
            .unwrap();
        let (_, _, ctype) = store.get_manifest("team-a/app", "v1").unwrap().unwrap();
        assert_eq!(ctype, index_type);

        // A different body, so this one's sidecar is its own file rather than the one above.
        let evil = br#"{"schemaVersion":2,"layers":[]}"#;
        let evil_digest = store
            .put_manifest("team-a/app", "evil", "text/html", evil)
            .unwrap();
        let evil_hex = evil_digest.trim_start_matches("sha256:");
        // On disk, checked directly: a caller-supplied string is never what is persisted,
        // which the read filter below cannot tell us.
        assert_eq!(
            std::fs::read_to_string(store.manifest_type_path("team-a/app", evil_hex))
                .unwrap()
                .trim(),
            DEFAULT_MANIFEST_TYPE
        );
        let (_, _, ctype) = store.get_manifest("team-a/app", "evil").unwrap().unwrap();
        assert_eq!(ctype, DEFAULT_MANIFEST_TYPE);

        // And on read, so a sidecar written before this rule — or by anything that skips
        // the write filter — is covered too.
        let hex = digest.trim_start_matches("sha256:");
        std::fs::write(store.manifest_type_path("team-a/app", hex), "text/html").unwrap();
        let (_, _, ctype) = store.get_manifest("team-a/app", "v1").unwrap().unwrap();
        assert_eq!(ctype, DEFAULT_MANIFEST_TYPE);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A media type is not a string: parameters and case are part of how HTTP spells one,
    /// and treating a spec-legal variant as unrecognized would relabel an index as an image
    /// manifest — a manifest the distribution spec tells a client to reject.
    #[test]
    fn a_manifest_media_type_is_matched_as_a_media_type() {
        let index = "application/vnd.oci.image.index.v1+json";
        for spelling in [
            index,
            "application/vnd.oci.image.index.v1+json; charset=utf-8",
            "APPLICATION/VND.OCI.IMAGE.INDEX.V1+JSON",
            "  application/vnd.oci.image.index.v1+json  ",
        ] {
            assert_eq!(manifest_media_type(spelling), index, "{spelling}");
        }
        // and everything else is the default, whatever it tries
        for bad in [
            "text/html",
            "text/html; x=application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.index.v1+json.evil",
            "",
            ";",
        ] {
            assert_eq!(manifest_media_type(bad), DEFAULT_MANIFEST_TYPE, "{bad}");
        }
        // every listed type maps to itself, so a stored label is always canonical
        for t in MANIFEST_MEDIA_TYPES {
            assert_eq!(manifest_media_type(t), *t);
        }
    }

    /// An upload id names a file under `uploads/`, so it must not be able to name anything
    /// else — and it carries a random hex tail, so hex digits are part of the alphabet.
    #[test]
    fn upload_id_validation() {
        assert!(valid_upload_id("12345-7"));
        assert!(valid_upload_id("12345-7-0f1e2d3c4b5a69788796a5b4c3d2e1f0"));
        assert!(!valid_upload_id("../escape"));
        assert!(!valid_upload_id("a/b"));
        assert!(!valid_upload_id(""));
        // no `/` and no `.`, so an id can name nothing but a session file — not the
        // `owners/` subdirectory beside them, and not a relay `.relay-*` staging file
        assert!(!valid_upload_id("12345-7.repo"));
        assert!(!valid_upload_id("owners"));
        assert!(!valid_upload_id("nothex-zz"));
        assert!(!valid_upload_id(&"a".repeat(129)));
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

    /// An upload is finishable only in the repository it was started in: otherwise a
    /// caller who may write one repo could push into another by starting there and
    /// finishing here.
    #[test]
    fn an_upload_session_belongs_to_the_repo_it_was_opened_for() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-upown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let res = start_upload(&store, "team-a/app").unwrap();
        let location = res.headers().get("Location").unwrap().to_str().unwrap();
        let id = location.rsplit('/').next().unwrap().to_string();
        assert!(valid_upload_id(&id), "{id}");
        assert!(
            id.len() > "12345-7".len(),
            "the id carries a random tail: {id}"
        );

        assert!(upload_is_for(&store, &id, "team-a/app"));
        assert!(!upload_is_for(&store, &id, "team-b/app"));

        // and the wrong repo cannot append to it
        let denied = patch_upload(&store, "team-b/app", &id, b"bytes").unwrap();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        let ok = patch_upload(&store, "team-a/app", &id, b"bytes").unwrap();
        assert_eq!(ok.status(), StatusCode::ACCEPTED);

        // nor finish it — the check is on the finish as much as on the append, and with a
        // correct digest, so it is the binding being tested and nothing else
        let digest = format!("sha256:{}", sha256_hex_raw(b"bytes"));
        let denied = finish_upload(
            &store,
            "team-b/app",
            &id,
            &format!("digest={digest}"),
            b"",
            false,
        )
        .unwrap();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        assert!(
            !store.has_blob(&hex(&digest)),
            "a finish into the wrong repo stores nothing"
        );
        let ok = finish_upload(
            &store,
            "team-a/app",
            &id,
            &format!("digest={digest}"),
            b"",
            false,
        )
        .unwrap();
        assert_eq!(ok.status(), StatusCode::CREATED);
        assert!(store.has_blob(&hex(&digest)));

        // a binding that cannot be read is not a licence: `upload_is_for` fails closed, so
        // a session whose record is gone is unfinishable rather than finishable anywhere
        let res = start_upload(&store, "team-a/app").unwrap();
        let id = res
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        std::fs::remove_file(store.upload_owner_path(&id)).unwrap();
        assert!(!upload_is_for(&store, &id, "team-a/app"));
        assert_eq!(
            patch_upload(&store, "team-a/app", &id, b"x")
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The record binding an upload to its repository must not read as an upload itself:
    /// `stats` would double-count every push in flight and `gc` would report twice the
    /// uploads it dropped.
    #[test]
    fn an_uploads_owner_record_is_not_counted_as_an_upload() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-upcount-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let res = start_upload(&store, "team-a/app").unwrap();
        let location = res.headers().get("Location").unwrap().to_str().unwrap();
        let id = location.rsplit('/').next().unwrap().to_string();
        assert!(store.upload_owner_path(&id).is_file());

        let s = store.stats().unwrap();
        assert_eq!(s.uploads, 1, "one session in flight, not two");

        // and dropping the abandoned session takes its record with it, counted once
        let report = store.gc(Duration::ZERO, Duration::ZERO, false).unwrap();
        assert_eq!(report.uploads_dropped, 1);
        assert!(!store.upload_owner_path(&id).exists());
        assert_eq!(store.stats().unwrap().uploads, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn percent_decode_handles_digest_colon() {
        assert_eq!(percent_decode("sha256%3Aabc"), "sha256:abc");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("trailing%"), "trailing%");
        assert_eq!(percent_decode("%e2%82%ac"), "\u{20ac}");

        // A byte-length guard is not a char boundary: a `%` before a multi-byte character
        // used to be sliced as a `&str` and panic. Query strings and form bodies come from
        // the caller, so this is a request away.
        assert_eq!(percent_decode("%\u{20ac}"), "%\u{20ac}");
        assert_eq!(percent_decode("%e\u{20ac}"), "%e\u{20ac}");
        assert_eq!(percent_decode("csrf=%\u{1f600}"), "csrf=%\u{1f600}");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
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
