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

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

pub mod accounts;
pub mod admin;
pub mod auth;
pub(crate) mod browse;
pub(crate) mod captions;
pub mod client;
pub mod config;
pub(crate) mod dav;
pub(crate) mod forms;
pub(crate) mod html;
pub mod hub;
pub mod hubtoken;
pub(crate) mod keys;
pub mod lock;
pub mod oidc;
pub mod relay;
pub(crate) mod tags;
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

impl Authenticator {
    /// The `WWW-Authenticate` value an unauthenticated request is challenged with, `None`
    /// when the server is open.
    fn challenge_value(&self) -> Option<&'static str> {
        match self {
            Authenticator::Shared(auth) => auth.challenge_value(),
            Authenticator::Accounts { .. } => Some(accounts::CHALLENGE),
        }
    }
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
    /// Enable WebDAV routes.
    pub webdav: bool,
    /// The hub tokens taken, once enrolled with `[hub] tokens = true`.
    pub tokens: hubtoken::TokenGate,
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

/// Whether `method` on `path` writes to the store: what a read-only registry refuses. The
/// lock service, sign-ins, keys and captions (the accounts db, not the store) do not touch
/// it, and the batched exists probe is a read sent as a POST; a tag deleted from the settings
/// pages is a write.
fn is_store_write(method: &Method, path: &str) -> bool {
    match method.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "PROPFIND" => false,
        _ if path.starts_with("/lock/") || path == EXISTS_PATH => false,
        _ if matches!(path, "/login" | "/auth/callback" | "/logout") => false,
        _ if path == "/settings/keys" || path.starts_with("/settings/keys/") => false,
        _ if path == "/settings/captions" => false,
        _ => true,
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
    known_manifest_media_type(ctype).unwrap_or(DEFAULT_MANIFEST_TYPE)
}

/// Which of [`MANIFEST_MEDIA_TYPES`] `ctype` is, matched as [`manifest_media_type`] matches
/// it, else `None`.
fn known_manifest_media_type(ctype: &str) -> Option<&'static str> {
    let base = ctype.split(';').next().unwrap_or("").trim();
    MANIFEST_MEDIA_TYPES
        .iter()
        .find(|t| t.eq_ignore_ascii_case(base))
        .copied()
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
    /// Refuse writes, as a hub managing the registry asked ([`Store::set_read_only`]).
    read_only: std::sync::atomic::AtomicBool,
    /// Connections a server on this store is serving now.
    connections: std::sync::atomic::AtomicUsize,
    /// Retention windows of their own for the tags under prefixes ([`Store::gc`]).
    prefix_windows: std::sync::Mutex<Vec<PrefixWindow>>,
}

/// A retention window for the tags under a prefix: those of the repositories `prefix` and
/// `prefix/…`, and of the plain files stored as `files/prefix/…`. Under it, a tag is dropped
/// once idle past `window`. A manifest's `org.virtkit.retention=keep` and
/// `org.virtkit.expires` hold as under the store-wide policy when `keep_holds`, and
/// otherwise `keep` never holds and `expires` holds only within the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixWindow {
    pub prefix: String,
    pub window: Duration,
    /// Whether `keep` and `expires` still hold under it: not under a window the registry's
    /// own config sets, since whoever may push there chose the annotations; under one the
    /// hub added, so a hub cannot drop a pinned tag, nor one before its date.
    pub keep_holds: bool,
}

impl From<&config::GcPrefix> for PrefixWindow {
    fn from(p: &config::GcPrefix) -> Self {
        PrefixWindow {
            prefix: p.path.clone(),
            window: Duration::from_secs(p.retention_days.saturating_mul(86_400)),
            keep_holds: false,
        }
    }
}

/// The most specific prefix window in `windows` covering the repository `name`.
pub(crate) fn prefix_window<'a>(
    windows: &'a [PrefixWindow],
    name: &str,
) -> Option<&'a PrefixWindow> {
    use vk_hub_proto::token::under;
    let name = name
        .strip_prefix(vk_hub_proto::token::FILES_REPO)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(name);
    windows
        .iter()
        .filter(|w| under(&w.prefix, name))
        .max_by_key(|w| w.prefix.len())
}

/// A connection counted in [`Store::connections`] until dropped.
struct ConnectionCount<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for ConnectionCount<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What [`Store::remove_empty_repo`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RepoRemoval {
    /// The directory is gone.
    Removed,
    /// A tag, a nested directory, or an entry that is not the repository's layout.
    HasMembers,
    /// A record younger than the grace window that is not a deleted raw file's: a manifest
    /// of another kind, or a membership marker no raw-file manifest in the directory
    /// accounts for.
    HasRecords,
    /// Another holder has the store lock.
    Busy,
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
            read_only: std::sync::atomic::AtomicBool::new(false),
            connections: std::sync::atomic::AtomicUsize::new(0),
            prefix_windows: std::sync::Mutex::new(Vec::new()),
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

    /// A private staging file under `uploads/` for a body whose digest is only known once it
    /// has been read — the WebDAV `PUT`. [`Store::stage_promotion`] and
    /// [`Store::promote_staged`] install it; one a crash leaves behind is swept with the
    /// idle uploads by [`Store::gc`].
    pub(crate) fn stage_file(&self) -> Result<(PathBuf, std::fs::File)> {
        let dir = self.uploads_dir();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = self.upload_path(&format!(
            "{}-{}-{}",
            std::process::id(),
            self.next_upload.fetch_add(1, Ordering::Relaxed),
            accounts::random_token(16),
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok((path, file))
    }

    /// The repositories one level below `name` (`""` for the top level), sorted: the
    /// subdirectories of `repos/<name>` that are not its own layout directories. By
    /// `lstat`, so a symlink is neither followed nor shown; a name no repository could have
    /// is skipped. An absent directory has no children; any other read error is returned.
    pub(crate) fn repo_children(&self, name: &str) -> Result<Vec<String>> {
        if !name.is_empty() && !valid_name(name) {
            return Ok(Vec::new());
        }
        let dir = self.root.join("repos").join(name);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
            let is_dir = entry
                .file_type()
                .with_context(|| format!("listing {}", dir.display()))?
                .is_dir();
            if let Some(n) = entry.file_name().to_str()
                && is_dir
                && !REPO_SUBDIRS.contains(&n)
                && valid_name(n)
            {
                out.push(n.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Whether `repos/<name>` is a directory: a repository, or a path component above one.
    /// What the WebDAV `files/` tree calls a directory, since a nested repository's name
    /// brings its parents into being as directories and a client expects to find them.
    pub(crate) fn repo_dir_exists(&self, name: &str) -> bool {
        valid_name(name)
            && std::fs::symlink_metadata(self.root.join("repos").join(name))
                .is_ok_and(|m| m.is_dir())
    }

    /// Create an empty `tags/` directory and any missing ancestors for WebDAV `MKCOL`.
    /// [`Store::has_repo`] then recognizes the repository before it holds any content.
    /// Hold the shared lock so [`Store::remove_empty_repo`] cannot remove an ancestor
    /// during creation.
    pub(crate) fn create_repo(&self, name: &str) -> Result<()> {
        if !valid_name(name) {
            bail!("invalid repository name {name}");
        }
        let _lock = self.lock_shared()?;
        let tags = self.root.join("repos").join(name).join("tags");
        std::fs::create_dir_all(&tags).with_context(|| format!("creating {}", tags.display()))
    }

    /// Remove repository or parent directory `name` only when it has no tags, nested
    /// directories or records other than leftovers. Leftovers are a deleted raw file's
    /// manifest sidecar and layer/config membership markers, or records past `grace`:
    /// sidecars whose manifest blobs are too old for gc to root, and markers too old to
    /// protect an in-flight push. A fresh manifest of another kind may still be pulled by
    /// digest; a fresh, unaccounted marker may belong to a `/v2/` push awaiting its manifest.
    /// Either returns [`RepoRemoval::HasRecords`].
    ///
    /// Read every listing strictly, unlink only listed entries, then `remove_dir` each
    /// directory. Unreadable entries or new entries appearing during removal cause failure.
    ///
    /// Hold the exclusive store lock, as [`Store::gc`] does. Writers hold it shared and
    /// raw-file writes record membership before the tag; without the lock, a concurrent
    /// write could report success after losing its markers or tag. Try the lock without
    /// waiting and return [`RepoRemoval::Busy`] for the caller to retry if it is held.
    pub(crate) fn remove_empty_repo(&self, name: &str, grace: Duration) -> Result<RepoRemoval> {
        if !valid_name(name) {
            bail!("invalid repository name {name}");
        }
        let Some(_lock) = self.try_lock_exclusive()? else {
            return Ok(RepoRemoval::Busy);
        };
        let now = SystemTime::now();
        // An unreadable or future mtime reads as fresh: never remove on uncertain evidence.
        let idle = |path: &Path| {
            std::fs::symlink_metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > grace)
        };
        let dir = self.root.join("repos").join(name);
        let mut layout: Vec<&'static str> = Vec::new();
        for (entry, ft) in dir_entries_strict(&dir)? {
            match REPO_SUBDIRS.iter().find(|k| entry.to_str() == Some(**k)) {
                Some(k) if ft.is_dir() => layout.push(k),
                _ => return Ok(RepoRemoval::HasMembers),
            }
        }
        if layout.contains(&"tags") && !dir_entries_strict(&dir.join("tags"))?.is_empty() {
            return Ok(RepoRemoval::HasMembers);
        }
        let mut unlink = Vec::new();
        let mut accounted: HashSet<String> = HashSet::from([sha256_hex_raw(RAW_FILE_EMPTY_CONFIG)]);
        if layout.contains(&"manifests") {
            let sub = dir.join("manifests");
            for (entry, ft) in dir_entries_strict(&sub)? {
                let Some(hex) = entry.to_str().filter(|h| ft.is_file() && is_blob_hex(h)) else {
                    return Ok(RepoRemoval::HasRecords);
                };
                // A sidecar whose manifest the gc already swept records nothing.
                if let Some(manifest) = self.get_blob(hex)? {
                    match raw_file_layer(&manifest) {
                        Some((layer, _)) => {
                            accounted.insert(layer);
                        }
                        None if self.find_blob(hex).is_some_and(|(p, _)| !idle(&p)) => {
                            return Ok(RepoRemoval::HasRecords);
                        }
                        None => {}
                    }
                }
                unlink.push(sub.join(hex));
            }
        }
        if layout.contains(&"blobs") {
            let sub = dir.join("blobs");
            for (entry, ft) in dir_entries_strict(&sub)? {
                let Some(hex) = entry.to_str().filter(|h| ft.is_file() && is_blob_hex(h)) else {
                    return Ok(RepoRemoval::HasRecords);
                };
                let marker = sub.join(hex);
                if !accounted.contains(hex) && !idle(&marker) {
                    return Ok(RepoRemoval::HasRecords);
                }
                unlink.push(marker);
            }
        }
        for path in &unlink {
            std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        }
        for kind in layout {
            let sub = dir.join(kind);
            std::fs::remove_dir(&sub).with_context(|| format!("removing {}", sub.display()))?;
        }
        std::fs::remove_dir(&dir).with_context(|| format!("removing {}", dir.display()))?;
        Ok(RepoRemoval::Removed)
    }

    /// Refresh a tag's mtime for uses outside [`Store::get_manifest`]. [`Store::gc`] uses
    /// this timestamp for tag retention.
    pub(crate) fn touch_tag(&self, name: &str, tag: &str) {
        if valid_name(name) && valid_tag(tag) {
            touch(&self.tag_path(name, tag));
        }
    }

    /// Reference a stored blob as `name:tag` by writing the shared empty config, both blob
    /// membership records and a single-layer raw-file manifest, as a `/v2/` push does.
    /// `size` is the blob's canonical length; a non-empty `title` becomes the OCI title
    /// annotation. The caller must hold the shared lock across the check and reference.
    /// Returns the manifest digest.
    pub(crate) fn put_raw_file(
        &self,
        name: &str,
        tag: &str,
        layer_hex: &str,
        size: u64,
        title: Option<&str>,
    ) -> Result<String> {
        self.put_raw_file_annotated(name, tag, layer_hex, size, title, &BTreeMap::new())
    }

    /// [`Store::put_raw_file`] with `annotations` on the manifest: a [`Retention`].
    fn put_raw_file_annotated(
        &self,
        name: &str,
        tag: &str,
        layer_hex: &str,
        size: u64,
        title: Option<&str>,
        annotations: &BTreeMap<String, String>,
    ) -> Result<String> {
        let config_digest = self.put_blob(RAW_FILE_EMPTY_CONFIG)?;
        // Record both blobs here: this server received their bytes for this repository.
        // `put_manifest` records only the manifest's membership; a reference alone does not
        // prove that the repository holds the content.
        self.record_blob(name, config_digest.trim_start_matches("sha256:"))?;
        self.record_blob(name, layer_hex)?;
        let mut layer = serde_json::json!({
            "mediaType": RAW_FILE_MEDIA_TYPE,
            "digest": format!("sha256:{layer_hex}"),
            "size": size,
        });
        // An empty title is worse than none.
        if let Some(title) = title.filter(|t| !t.is_empty()) {
            layer["annotations"] = serde_json::json!({
                "org.opencontainers.image.title": title,
            });
        }
        let mut manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": DEFAULT_MANIFEST_TYPE,
            "config": {
                "mediaType": RAW_FILE_CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": RAW_FILE_EMPTY_CONFIG.len(),
            },
            "layers": [layer],
        });
        if !annotations.is_empty() {
            manifest["annotations"] = serde_json::to_value(annotations)?;
        }
        self.put_manifest(
            name,
            tag,
            DEFAULT_MANIFEST_TYPE,
            serde_json::to_vec(&manifest)?.as_slice(),
        )
    }

    /// Store the file at `path`, whose sha256 hex is `sha256`, as one blob, tagged as a raw
    /// file under each `(name, tag)` of `tags` with `annotations` on the manifest — what
    /// `vk registry put` does to a store it reaches on disk. Streamed through a staging file,
    /// so the file is never held in memory, and hashed on the way: one that no longer hashes
    /// to `sha256` is refused before any tag names it. `title` becomes the layer's OCI title.
    pub fn put_file(
        &self,
        tags: &[(&str, &str)],
        path: &Path,
        sha256: &str,
        title: Option<&str>,
        annotations: &BTreeMap<String, String>,
    ) -> Result<()> {
        for (name, tag) in tags {
            if !valid_name(name) || !valid_tag(tag) {
                bail!("{name}:{tag} is not a valid repository and tag");
            }
        }
        // Stage even an existing blob to recheck the file's hash and measure its size.
        let (staging, file) = self.stage_file()?;
        let staged = (|| {
            let mut src =
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
            let mut out = Sha256Writer::new(std::io::BufWriter::new(file));
            let size = std::io::copy(&mut src, &mut out)
                .with_context(|| format!("copying {}", path.display()))?;
            std::io::Write::flush(&mut out)?;
            let (_, hex) = out.into_hex();
            if hex != sha256 {
                bail!("{} changed while it was put", path.display());
            }
            Ok::<_, anyhow::Error>((size, self.stage_promotion(&hex, &staging)?))
        })();
        let (size, staged) = match staged {
            Ok(s) => s,
            Err(e) => {
                // Preserve the put error; gc sweeps any staging file left in uploads/.
                let _ = std::fs::remove_file(&staging);
                return Err(e);
            }
        };
        let _lock = match self.lock_shared() {
            Ok(lock) => lock,
            Err(e) => {
                staged.discard();
                return Err(e);
            }
        };
        self.promote_staged(sha256, staged)?;
        for (name, tag) in tags {
            self.put_raw_file_annotated(name, tag, sha256, size, title, annotations)?;
        }
        Ok(())
    }

    /// The raw file tagged `name:tag`; `None` when the tag is absent or is not a raw file.
    /// The read bumps the tag, as a pull does.
    pub fn open_file(&self, name: &str, tag: &str) -> Result<Option<OpenFile>> {
        let Some((_, manifest, _)) = self.get_manifest(name, tag)? else {
            return Ok(None);
        };
        let Some((hex, size)) = raw_file_layer(&manifest) else {
            return Ok(None);
        };
        let title = raw_file_title(&manifest);
        let Some((path, is_zstd)) = self.find_blob(&hex) else {
            bail!("{name}:{tag}: its blob sha256:{hex} is missing");
        };
        let file =
            std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let reader: Box<dyn std::io::Read + Send> = if is_zstd {
            Box::new(zstd::stream::read::Decoder::new(file).context("decompressing a stored blob")?)
        } else {
            Box::new(file)
        };
        Ok(Some(OpenFile {
            sha256: hex,
            size,
            title,
            reader,
        }))
    }

    /// Check for a valid repository with at least one repository subdirectory, without walking
    /// its contents. By `lstat`, like [`Store::repo_dir_exists`]: a symlink is not one.
    pub(crate) fn has_repo(&self, name: &str) -> bool {
        valid_name(name)
            && REPO_SUBDIRS.iter().any(|k| {
                std::fs::symlink_metadata(self.root.join("repos").join(name).join(k))
                    .is_ok_and(|m| m.is_dir())
            })
    }

    /// Collection mtime for `repos/<rel>`, falling back to the epoch. Empty `rel` refers to
    /// `repos/`.
    pub(crate) fn repos_path_modified(&self, rel: &str) -> SystemTime {
        std::fs::symlink_metadata(self.root.join("repos").join(rel))
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    /// Return the tag's manifest hex and mtime without refreshing retention. Listings must not
    /// keep tags alive.
    pub(crate) fn tag_target(&self, name: &str, tag: &str) -> Option<(String, SystemTime)> {
        if !valid_name(name) || !valid_tag(tag) {
            return None;
        }
        let path = self.tag_path(name, tag);
        let modified = std::fs::symlink_metadata(&path).ok()?.modified().ok()?;
        let digest = std::fs::read_to_string(&path).ok()?;
        let hex = digest.trim().trim_start_matches("sha256:").to_string();
        is_blob_hex(&hex).then_some((hex, modified))
    }

    /// Manifest length, media type and membership mtime, using the same media-type fallbacks as
    /// [`Store::get_manifest`].
    pub(crate) fn manifest_meta(&self, name: &str, hex: &str) -> Option<(u64, String, SystemTime)> {
        if !valid_name(name) || !is_blob_hex(hex) {
            return None;
        }
        let blob = self.blob_path(hex);
        let len = std::fs::metadata(&blob).ok()?.len();
        let sidecar = self.manifest_type_path(name, hex);
        let modified = std::fs::symlink_metadata(&sidecar)
            .or_else(|_| std::fs::metadata(&blob))
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let ctype = std::fs::read_to_string(&sidecar)
            .ok()
            .map(|s| s.trim().to_string())
            .or_else(|| {
                std::fs::read(&blob)
                    .ok()
                    .and_then(|d| declared_media_type(&d))
            })
            .map(|t| manifest_media_type(&t).to_string())
            .unwrap_or_else(|| DEFAULT_MANIFEST_TYPE.to_string());
        Some((len, ctype, modified))
    }

    /// A blob's canonical length and mtime: one `open`, and for a zstd-stored blob a read
    /// of the frame header — the same length `Content-Length` reports on a `GET`.
    pub(crate) fn blob_meta(&self, hex: &str) -> Option<(u64, SystemTime)> {
        let (path, is_zstd) = self.find_blob(hex)?;
        let mut file = std::fs::File::open(&path).ok()?;
        let meta = file.metadata().ok()?;
        let modified = meta.modified().ok()?;
        let len = if is_zstd {
            zstd_canonical_len(&mut file).ok()?
        } else {
            meta.len()
        };
        Some((len, modified))
    }

    /// Sorted valid digest hexes under `repos/<name>/<kind>` for DAV listings. An absent
    /// directory has none; any other read error is returned.
    pub(crate) fn repo_member_hexes(&self, name: &str, kind: &str) -> Result<Vec<String>> {
        if !valid_name(name) || !REPO_SUBDIRS.contains(&kind) {
            return Ok(Vec::new());
        }
        let dir = self.root.join("repos").join(name).join(kind);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
            if let Some(n) = entry.file_name().to_str()
                && is_blob_hex(n)
            {
                out.push(n.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    fn manifest_type_path(&self, name: &str, hex: &str) -> PathBuf {
        self.root
            .join("repos")
            .join(name)
            .join("manifests")
            .join(hex)
    }

    /// Refuse writes (`true`) or take them again. What a hub managing the registry asks;
    /// it lasts until the server stops.
    pub fn set_read_only(&self, read_only: bool) {
        self.read_only.store(read_only, Ordering::Relaxed);
    }

    /// Whether writes are refused.
    pub fn read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }

    /// The retention windows [`Store::gc`] applies under prefixes, replacing the previous
    /// ones.
    pub fn set_prefix_windows(&self, windows: Vec<PrefixWindow>) {
        *self
            .prefix_windows
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = windows;
    }

    /// The retention windows under prefixes now.
    pub fn prefix_windows(&self) -> Vec<PrefixWindow> {
        self.prefix_windows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Connections a server on this store serves now.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// Count a connection for as long as the returned guard lives.
    fn count_connection(&self) -> ConnectionCount<'_> {
        self.connections.fetch_add(1, Ordering::Relaxed);
        ConnectionCount(&self.connections)
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

    /// Return a blob's decompressed bytes, or `None` if absent or larger than `cap`.
    /// Bounds gc reads of index children, whose blobs the pusher chooses.
    fn read_blob_capped(&self, hex: &str, cap: usize) -> Result<Option<Vec<u8>>> {
        use std::io::Read;
        let Some((path, is_zstd)) = self.find_blob(hex) else {
            return Ok(None);
        };
        let file =
            std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        if !is_zstd
            && file
                .metadata()
                .with_context(|| format!("reading {}", path.display()))?
                .len()
                > cap as u64
        {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        let limit = cap as u64 + 1;
        if is_zstd {
            zstd::stream::read::Decoder::new(file)
                .context("decompressing a stored blob")?
                .take(limit)
                .read_to_end(&mut bytes)
        } else {
            file.take(limit).read_to_end(&mut bytes)
        }
        .with_context(|| format!("reading {}", path.display()))?;
        Ok((bytes.len() <= cap).then_some(bytes))
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
        // The gc mark parses every rooted manifest and aborts on one that will not parse, so
        // storing such bytes would stall collection for as long as their tag is read.
        if !is_json_object(body) {
            bail!("manifest body is not a JSON object");
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
        let _writes = self.flock_at(MANIFEST_WRITES_LOCK, libc::LOCK_EX)?;
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

    /// Whether each of `tags` resolves in `name`, in order — a manifest `HEAD` for every
    /// tag under one shared lock, without reading a single manifest body. A tag that
    /// resolves is bumped like a `HEAD` hit would bump it: the caller is about to build on
    /// it, which is the use [`Store::gc`]'s tag retention keys on. An invalid tag, like an
    /// invalid name, reads as absent rather than failing the batch: the caller asks about
    /// content keys and only wants to know which ones it can restore.
    pub fn has_manifests(&self, name: &str, tags: &[&str]) -> Result<Vec<bool>> {
        if !valid_name(name) {
            return Ok(vec![false; tags.len()]);
        }
        let _lock = self.lock_shared()?;
        Ok(tags
            .iter()
            .map(|tag| {
                if !valid_reference(tag) || tag.starts_with("sha256:") {
                    return false;
                }
                let path = self.tag_path(name, tag);
                let Ok(digest) = std::fs::read_to_string(&path) else {
                    return false;
                };
                let hex = digest.trim().trim_start_matches("sha256:");
                // The same check `get_manifest` makes: a manifest is stored uncompressed, so
                // read the identity blob rather than the zstd form `find_blob` also accepts.
                let present = self.blob_path(hex).is_file();
                if present {
                    touch(&path);
                }
                present
            })
            .collect())
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

    /// The distinct blobs a manifest occupies on disk — the manifest blob itself, each
    /// config/layer it references, and an index's child manifests and theirs, as the gc mark
    /// walks them — as `(hex, on-disk bytes)`, deduped within the one manifest and sized in
    /// whichever storage form is present. `None` if the manifest blob is gone. Lock-free
    /// best-effort, like the rest of the `/browse` reads: a blob a concurrent gc removes
    /// mid-walk is sized 0 rather than failing the page. The same reference set
    /// [`Store::stats`] sizes.
    fn manifest_ondisk_blobs(&self, hex: &str) -> Option<Vec<(String, u64)>> {
        self.find_blob(hex)?;
        let mut out = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut add = |h: &str| {
            if seen.insert(h.to_string()) {
                let size = self
                    .find_blob(h)
                    .map(|(p, _)| std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0))
                    .unwrap_or(0);
                out.push((h.to_string(), size));
            }
        };
        // Not strict, so the walk cannot fail: what it could not read references nothing.
        let _ = self.walk_manifests(&HashSet::from([hex.to_string()]), false, |m, manifest| {
            add(m);
            for (b, _) in manifest.into_iter().flat_map(|(_, refs)| &refs.blobs) {
                add(b);
            }
        });
        Some(out)
    }

    /// Per-tag and whole-repository on-disk sizes for `tags` (which the caller has already
    /// listed): the returned vector is each tag's own on-disk footprint — its manifest and
    /// the blobs it references, deduped within that tag — aligned to `tags` and `None` for a
    /// tag that does not resolve; the `u64` is the repository total, blobs shared between
    /// tags counted once. Lock-free best-effort, and it reads tag files *without* bumping
    /// their mtime — the "last used" record [`Store::gc`] keys tag retention on, which a
    /// listing must not renew (a resolve through [`Store::get_manifest`] would).
    pub(crate) fn repo_size_report(&self, name: &str, tags: &[String]) -> (Vec<Option<u64>>, u64) {
        if !valid_name(name) {
            return (vec![None; tags.len()], 0);
        }
        let mut total_seen: HashSet<String> = HashSet::new();
        let mut total = 0u64;
        let per = tags
            .iter()
            .map(|tag| {
                let digest = std::fs::read_to_string(self.tag_path(name, tag)).ok()?;
                let hex = digest.trim().trim_start_matches("sha256:");
                if !is_blob_hex(hex) {
                    return None;
                }
                let mut per_tag = 0u64;
                for (h, size) in self.manifest_ondisk_blobs(hex)? {
                    per_tag += size;
                    if total_seen.insert(h) {
                        total += size;
                    }
                }
                Some(per_tag)
            })
            .collect();
        (per, total)
    }

    /// Remove a tag — the manual counterpart to what [`Store::gc`] does on a schedule, for
    /// an admin dropping an entry through `/browse`. Only the tag pointer is unlinked: the
    /// manifest and its blobs are content-addressed and may be shared, so reclaiming them is
    /// left to the gc, which does it under the exclusive lock once nothing roots them. Taken
    /// under the shared lock, so it can never drop a tag out from under a gc mid-sweep (which
    /// holds the lock exclusive). `Ok(false)` if the tag was already gone.
    pub fn delete_tag(&self, name: &str, tag: &str) -> Result<bool> {
        if !valid_name(name) || !valid_tag(tag) {
            bail!("invalid tag reference {name}:{tag}");
        }
        let _lock = self.lock_shared()?;
        let path = self.tag_path(name, tag);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("removing the tag {}", path.display())),
        }
    }

    /// `DELETE /v2/<name>/manifests/<reference>`: delete a tag as [`Store::delete_tag`]
    /// does, or a digest's tags and membership in `name`: its sidecar and any mount marker
    /// for an index child declaring a manifest media type. Other repositories' tags and
    /// membership are untouched.
    ///
    /// Bytes remain for gc, as for a deleted tag. Until then [`readable_through`] serves
    /// the digest as one `name` never held. Returns `Ok(false)` if nothing was dropped.
    ///
    /// [`MANIFEST_WRITES_LOCK`] prevents a concurrent [`Store::put_manifest`] from moving
    /// a matched tag before unlink or losing its re-pushed membership.
    pub fn delete_manifest(&self, name: &str, reference: &str) -> Result<bool> {
        let Some(hex) = reference.strip_prefix("sha256:") else {
            return self.delete_tag(name, reference);
        };
        if !valid_name(name) || !is_blob_hex(hex) {
            bail!("invalid manifest reference {name}@{reference}");
        }
        let _lock = self.lock_shared()?;
        let _writes = self.flock_at(MANIFEST_WRITES_LOCK, libc::LOCK_EX)?;
        let mut dropped = false;
        let mut remove = |path: &Path| match std::fs::remove_file(path) {
            Ok(()) => {
                dropped = true;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        };
        for tag in self.list_tags(name) {
            let path = self.tag_path(name, &tag);
            if std::fs::read_to_string(&path).is_ok_and(|d| d.trim() == reference) {
                remove(&path)?;
            }
        }
        remove(&self.manifest_type_path(name, hex))?;
        // Markers also record layers and configs pushed here; deleting them as manifests
        // would break images that use them. Cap the read because the caller chooses the
        // digest.
        let marker = self.repo_blob_path(name, hex);
        if marker.is_file()
            && self
                .read_blob_capped(hex, MAX_MANIFEST_BYTES)?
                .and_then(|data| declared_media_type(&data))
                .is_some_and(|t| known_manifest_media_type(&t).is_some())
        {
            remove(&marker)?;
        }
        Ok(dropped)
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

    /// [`Store::lock_exclusive`] without waiting: `Ok(None)` while another holder has the
    /// lock, shared or exclusive.
    pub(crate) fn try_lock_exclusive(&self) -> Result<Option<LockGuard>> {
        self.try_flock(libc::LOCK_EX)
    }

    /// Lock the store's file `name` with `op` (`LOCK_SH` or `LOCK_EX`), waiting indefinitely or
    /// up to `wait`'s timeout. Return `None` on timeout.
    fn lock_for(&self, name: &str, op: libc::c_int, wait: Wait) -> Result<Option<LockGuard>> {
        let patience = match wait {
            Wait::Block => return self.flock_at(name, op).map(Some),
            Wait::Try => TRY_PATIENCE,
            Wait::Within(d) => d,
        };
        let deadline = Instant::now() + patience;
        loop {
            match self.flock_at(name, op | libc::LOCK_NB) {
                Ok(lock) => return Ok(Some(lock)),
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) => {}
                Err(e) => return Err(e),
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn try_flock(&self, op: libc::c_int) -> Result<Option<LockGuard>> {
        match self.flock(op | libc::LOCK_NB) {
            Ok(lock) => Ok(Some(lock)),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn flock(&self, op: libc::c_int) -> Result<LockGuard> {
        self.flock_at(".lock", op)
    }

    fn flock_at(&self, name: &str, op: libc::c_int) -> Result<LockGuard> {
        use std::os::unix::io::AsRawFd;
        let path = self.root.join(name);
        let f =
            std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        // SAFETY: the fd is owned by `f`, which the guard keeps alive; flock returns
        // 0 or -1/errno and, without `LOCK_NB`, blocks until the lock is granted.
        if unsafe { libc::flock(f.as_raw_fd(), op) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("locking {}", path.display()));
        }
        Ok(LockGuard {
            _file: f,
            root: self.root.clone(),
        })
    }

    /// Take a [`Lease`] on blobs of this store, for a reader that goes on reading them by path
    /// after it lets the store lock go: a lazy disk view over the blob files, which a VM reads
    /// chunk by chunk for as long as it runs. `_held` is the shared lock the reader resolved the
    /// blobs under, and [`Lease::add`] wants it too: a [`Store::gc`] reads the leases under the
    /// exclusive lock, so it sees every blob a reader resolved before it, and a reader that
    /// resolves after it finds the blobs the pass left.
    ///
    /// The directory and the files are as open as the umask lets them be: on a store shared by
    /// a group, every member's gc has to read every member's leases. The directory is sticky,
    /// so none removes another's lease.
    pub fn lease(&self, held: &LockGuard) -> Result<Lease> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        use std::os::unix::io::AsRawFd;
        static SEQ: AtomicU64 = AtomicU64::new(0);

        debug_assert_eq!(
            held.root, self.root,
            "a lease taken under another store's lock"
        );
        let dir = self.root.join(LEASES_DIR);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o1777)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        // The clock as well as the pid: a process of another pid namespace may share the store.
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = dir.join(format!(
            "{}-{nanos}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        // SAFETY: the fd is owned by `file`, which the lease keeps open; the file is new, so
        // nothing else holds it and the call does not wait.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            let _ = std::fs::remove_file(&path);
            return Err(e).with_context(|| format!("locking {}", path.display()));
        }
        Ok(Lease {
            file,
            path,
            root: self.root.clone(),
        })
    }

    /// The blobs the live leases of this store name (see [`Store::lease`]). A lease whose
    /// holder is gone — nobody holds its lock — is removed, but not on a `dry_run`. Read under
    /// the exclusive store lock, and strictly: a lease this misses is a blob a live reader loses.
    fn leased_blobs(&self, dry_run: bool) -> Result<HashSet<String>> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let dir = self.root.join(LEASES_DIR);
        let mut leased = HashSet::new();
        let entries = match dir_entries_strict(&dir) {
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(leased);
            }
            r => r.context("reading the leases of live readers; refusing to sweep without them")?,
        };
        for (name, ft) in entries {
            let path = dir.join(&name);
            if !ft.is_file() {
                bail!(
                    "{} is not a plain file; refusing to sweep on leases that would be incomplete",
                    path.display()
                );
            }
            // Non-blocking, so a FIFO put in its place cannot hang the pass, and checked to be a
            // plain file once open.
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&path)
            {
                Ok(f) => f,
                // Released since the listing.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
            };
            // SAFETY: the fd is owned by `file`, open for the call; LOCK_NB never waits.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
                // Nobody holds it: its reader is gone. One this user may not remove (another's,
                // in a store shared by a group) is left for its owner's gc.
                if !dry_run && let Err(e) = remove_if_present(&path) {
                    eprintln!("vk-registry: gc: leaving a dead lease: {e:#}");
                }
                continue;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::WouldBlock {
                return Err(e).with_context(|| format!("locking {}", path.display()));
            }
            if !file.metadata().is_ok_and(|m| m.is_file()) {
                bail!(
                    "{} is not a plain file; refusing to sweep on leases that would be incomplete",
                    path.display()
                );
            }
            let mut text = String::new();
            file.take(MAX_LEASE_BYTES + 1)
                .read_to_string(&mut text)
                .with_context(|| format!("reading {}", path.display()))?;
            if text.len() as u64 > MAX_LEASE_BYTES {
                bail!(
                    "{} is larger than a lease may be; refusing to sweep on a lease cut short",
                    path.display()
                );
            }
            leased.extend(text.lines().filter(|h| is_blob_hex(h)).map(str::to_string));
        }
        Ok(leased)
    }

    /// Garbage-collect the store, holding the lock exclusive in short spells only (pushers
    /// briefly block; see [`Store::lock_shared`] and [`Store::gc_with`]). Tags idle past `retention` are dropped
    /// (tag mtime = last use), unless their manifest sets a [`Retention`] of its
    /// own — read for every tag, so the mark reads each surviving manifest again.
    /// The surviving tags' manifests — plus digest-pinned manifests (a sidecar with
    /// no tag) whose blob is younger than `grace` — root the mark: their manifest,
    /// config and layer blobs are live. Everything else idle past `grace` is swept:
    /// unmarked blobs (the grace window protects multi-request HTTP pushes, whose
    /// HEAD hits bump blob mtimes but which hold no lock across requests), unrooted
    /// manifest sidecars, and stale `uploads/` (an alive push keeps appending, so
    /// its session file stays fresh). Orphaned `.tmp.*` files from a crashed
    /// `atomic_write` age out with the blob sweep. A blob a live [`Lease`] names is
    /// kept however long it has sat unreferenced. `dry_run` reports without removing
    /// anything. [`Store::gc_with`] takes a fuller policy.
    pub fn gc(&self, retention: Duration, grace: Duration, dry_run: bool) -> Result<GcReport> {
        match self.gc_with(&GcPolicy::new(retention, grace, dry_run))? {
            GcOutcome::Done(report) => Ok(report),
            // The policy waits for the lock, so it never finds it busy.
            GcOutcome::Busy => bail!("the store lock is held"),
        }
    }

    /// [`Store::gc`] under `policy`: tags dropped only in its repository and never one with a
    /// kept prefix, by age only when it sets a retention, then by size (see
    /// [`Store::cap_tags`]); every other repository's manifests root the mark, tagged or not.
    /// [`GcOutcome::Busy`] when, within what `policy.wait` allows, the pass cannot have the gc
    /// lock (another gc runs), the shared store lock, or its first exclusive spell: it has done
    /// nothing. A later spell it cannot have leaves the report
    /// [`incomplete`](GcReport::incomplete).
    ///
    /// The store lock is held exclusive only in short spells, so the pushes and pulls of the
    /// builds sharing it wait for one spell at most, not for the whole pass. Everything slow —
    /// reading every tag and manifest, the size phase, the mark, listing the blobs — is done
    /// under the shared lock, which they share. Each spell first brings the mark up to date
    /// with whatever was tagged or pushed since, and works at least 64 items, then more until
    /// half a second is spent; how long a spell holds the lock thus depends on the store: its
    /// disk, and the tags and manifests written since the last spell. A tag the pass would
    /// drop is dropped in a spell where its bytes and mtime still match what was read; a use
    /// between that comparison and the removal, by a get that touches the tag without the
    /// lock, is lost, which is harmless: the content stays inside the grace window, and the
    /// build pushes the tag again. The blobs are then swept in spells that check each is still
    /// unmarked, unleased and idle past the grace window — a push that references a blob has
    /// touched it, so it is fresh — and the sidecars, markers and uploads last, each checked
    /// again too. The report gives the longest spell.
    pub fn gc_with(&self, policy: &GcPolicy) -> Result<GcOutcome> {
        self.gc_between(policy, &|_| {})
    }

    /// [`Store::gc_with`], running `between` before every exclusive spell, outside every lock:
    /// where pushes and builds come in, for a test to come in too.
    fn gc_between(&self, policy: &GcPolicy, between: &dyn Fn(Phase)) -> Result<GcOutcome> {
        if let Some(r) = &policy.repository
            && !valid_name(r)
        {
            bail!("{r:?} names no repository");
        }
        // One gc at a time, so two do not read the whole store side by side.
        let Some(_gc) = self.lock_for(GC_LOCK, libc::LOCK_EX, policy.wait)? else {
            return Ok(GcOutcome::Busy);
        };
        let mut report = GcReport::default();
        let longest = Cell::new(Duration::ZERO);
        let mut plan = {
            let Some(_shared) = self.lock_for(".lock", libc::LOCK_SH, policy.wait)? else {
                return Ok(GcOutcome::Busy);
            };
            // On a thread of its own, which `lower_planning` may slow without slowing the
            // exclusive spells after it: the lowering of a thread's priority is one-way.
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        if let Some(lower) = policy.lower_planning {
                            lower();
                        }
                        let mut planned = GcReport::default();
                        self.gc_plan(policy, &mut planned)
                            .map(|plan| (plan, planned))
                    })
                    .join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("the gc's planning panicked")))
            })
            .map(|(plan, planned)| {
                report.bytes_before = planned.bytes_before;
                plan
            })?
        };
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
        let dry_run = policy.dry_run;
        let remove = |path: &Path| -> Result<()> {
            if !dry_run {
                std::fs::remove_file(path)
                    .with_context(|| format!("removing {}", path.display()))?;
            }
            Ok(())
        };
        let mut spells = Spells {
            store: self,
            policy,
            longest: &longest,
            between,
            taken: 0,
        };

        // The drops, each only if the tag is still what it was read as.
        let drops = std::mem::take(&mut plan.drops);
        plan.dropping = drops
            .iter()
            .map(|(seen, _)| (seen.path.clone(), (seen.bytes.clone(), seen.mtime)))
            .collect();
        let drops_done = spells.run(
            Phase::Drops,
            &mut plan,
            &idle,
            drops,
            |plan, _, (seen, capped)| {
                plan.dropping.remove(&seen.path);
                if !seen.unchanged() {
                    return Ok(());
                }
                remove(&seen.path)?;
                // On a dry run the tag is still there, and must still read as gone.
                if dry_run {
                    plan.gone_tags.insert(seen.path);
                }
                if capped {
                    report.tags_capped += 1;
                } else {
                    report.tags_dropped += 1;
                }
                Ok(())
            },
        )?;
        if drops_done == Done::Short {
            return Ok(spells.short(report));
        }

        // Sweep unmarked blobs idle past the grace window, in both storage forms, noting every
        // hex that keeps at least one form: that — not what is still on disk — is what the
        // membership sweeps below consult on a dry run, since `remove` then removes nothing.
        let mut survivors: HashSet<String> = HashSet::new();
        let mut swept: HashSet<String> = HashSet::new();
        let candidates = std::mem::take(&mut plan.candidates);
        let swept_all = spells.run(
            Phase::Sweep,
            &mut plan,
            &idle,
            candidates,
            |plan, leased, (blob, hex)| {
                if plan.marked.contains(&hex) || !idle(&blob, policy.grace) {
                    survivors.insert(hex);
                } else if leased.contains(&hex) {
                    report.bytes_leased += disk_bytes(&blob);
                    // One blob, however many storage forms it has.
                    if survivors.insert(hex) {
                        report.blobs_leased += 1;
                    }
                } else {
                    let bytes = disk_bytes(&blob);
                    match remove(&blob) {
                        Ok(()) => {
                            report.bytes_freed += bytes;
                            report.blobs_dropped += 1;
                            swept.insert(hex);
                        }
                        // Gone since the listing: another pass took it.
                        Err(_) if !blob.exists() => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            },
        )?;
        if swept_all == Done::Short {
            return Ok(spells.short(report));
        }
        // Whether `hex` has no stored form left, or on a dry run would have none.
        let gone = |hex: &str| {
            if dry_run {
                (swept.contains(hex) && !survivors.contains(hex)) || self.find_blob(hex).is_none()
            } else {
                self.find_blob(hex).is_none()
            }
        };

        // Then the sidecars, the membership markers and the uploads. A sidecar is a manifest's
        // membership record: one goes exactly when its manifest blob is gone and nothing marks
        // it. Markers are never roots either: one goes when its blob is gone. Each is listed
        // first, outside every lock, and checked again in its spell.
        let mut last: Vec<Last> = plan
            .sidecars
            .iter()
            .filter(|(_, (hex, rooted))| !rooted && !plan.marked.contains(hex) && gone(hex))
            .map(|(path, _)| Last::Sidecar(path.clone()))
            .collect();
        last.extend(
            self.repo_dirs("blobs")
                .0
                .into_iter()
                .flat_map(|dir| dir_files(&dir))
                .filter_map(|marker| {
                    let hex = marker.file_name()?.to_str()?.to_string();
                    // Anything not named like a blob is not a marker; leave it alone.
                    (is_blob_hex(&hex) && !plan.marked.contains(&hex) && gone(&hex))
                        .then_some(Last::Marker(marker, hex))
                }),
        );
        last.extend(
            dir_files(&self.root.join("uploads"))
                .into_iter()
                .map(Last::Upload),
        );
        last.extend(
            dir_files(&self.root.join("uploads").join("owners"))
                .into_iter()
                .map(Last::Owner),
        );
        let last_done = spells.run(Phase::Last, &mut plan, &idle, last, |plan, _, item| {
            match item {
                Last::Sidecar(sidecar) => {
                    let Some((hex, rooted)) = plan.sidecars.get(&sidecar) else {
                        return Ok(());
                    };
                    if *rooted || plan.marked.contains(hex) || !gone(hex) || !sidecar.exists() {
                        return Ok(());
                    }
                    remove(&sidecar)?;
                    report.manifests_dropped += 1;
                }
                Last::Marker(marker, hex) => {
                    if plan.marked.contains(&hex) || !gone(&hex) {
                        return Ok(());
                    }
                    if !dry_run {
                        remove_if_present(&marker)?;
                    }
                    report.blob_markers_dropped += 1;
                }
                Last::Upload(upload) => {
                    if !upload.is_file() || !idle(&upload, policy.grace) {
                        return Ok(());
                    }
                    if let Some(id) = upload.file_name().and_then(|n| n.to_str())
                        && !dry_run
                    {
                        // One syscall, not `exists()` then `remove`: the same path resolved
                        // twice is a race, and a binding already gone is success here.
                        remove_if_present(&self.upload_owner_path(id))?;
                    }
                    remove(&upload)?;
                    report.uploads_dropped += 1;
                }
                // An owner record whose session is already gone (dropped by an earlier sweep,
                // or by a finish that could not clean up) is not an upload and is not counted
                // as one. Gated on `grace` like every other removal here: `start_upload` writes
                // the binding *before* the session, so a binding with no session may simply be
                // a push that started moments ago, and deleting it would leave a session
                // nothing can finish.
                Last::Owner(owner) => {
                    let orphaned = owner
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_none_or(|id| !self.upload_path(id).is_file());
                    if orphaned && owner.is_file() && idle(&owner, policy.grace) {
                        remove(&owner)?;
                    }
                }
            }
            Ok(())
        })?;
        if last_done == Done::Short {
            return Ok(spells.short(report));
        }
        Ok(GcOutcome::Done(finish_report(report, &longest)))
    }

    /// Take the store lock exclusive for one spell of [`Store::gc_with`], waiting as `wait`
    /// says, `longest` keeping the longest spell. `None` once that wait is out.
    fn hold_exclusive<'a>(
        &self,
        wait: Wait,
        longest: &'a Cell<Duration>,
    ) -> Result<Option<Spell<'a>>> {
        let Some(lock) = self.lock_for(".lock", libc::LOCK_EX, wait)? else {
            return Ok(None);
        };
        Ok(Some(Spell {
            _lock: lock,
            started: Instant::now(),
            longest,
        }))
    }

    /// The first, slow part of [`Store::gc_with`], under the shared lock: read every tag and
    /// decide which go, by age and then by size; read every sidecar; mark what the roots left
    /// reach; list the blobs nothing marks.
    fn gc_plan(&self, policy: &GcPolicy, report: &mut GcReport) -> Result<GcPlan> {
        let grace = policy.grace;
        let now = SystemTime::now();
        let idle = |path: &Path, window: Duration| {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > window)
        };
        // Everything the mark roots in is read strictly, and nothing is deleted before all of
        // it is: a root this pass fails to see is a blob it goes on to sweep out from under a
        // live tag. Same reason a manifest that will not parse aborts below — only here the
        // omission would be silent.
        let (tags_dirs, man_dirs) = self.gc_dirs()?;
        // Read only: dead leases are removed under the exclusive lock.
        let leased = self.leased_blobs(true)?;
        // Not idle past the retention window, when there is one.
        // Not idle past the window — a prefix's own when one covers the tag, else the policy's
        // retention — while age removal is on at all.
        let retained = |tag: &Path, window: Option<&PrefixWindow>| match (policy.retention, window)
        {
            (None, _) => true,
            (Some(_), Some(w)) => !idle(tag, w.window),
            (Some(r), None) => !idle(tag, r),
        };
        let windows = self.prefix_windows();
        let repos = self.root.join("repos");

        let mut plan = GcPlan::default();
        let mut kept_tags: Vec<KeptTag> = Vec::new();
        for tags_dir in tags_dirs {
            // Stamped as read, for the spells to tell whether to read it again.
            plan.unchanged(&tags_dir);
            let scoped = self.in_scope(policy, &tags_dir, "tags");
            // A prefix's own window, when one covers this repository.
            let window = tags_dir
                .parent()
                .and_then(|r| r.strip_prefix(&repos).ok())
                .and_then(Path::to_str)
                .and_then(|name| prefix_window(&windows, name));
            for tag in root_dir_files(&tags_dir)? {
                // Every tag is read, even an idle one: only its manifest can say it is
                // kept, and a kept tag left unrooted would have its blobs swept.
                let seen = SeenTag::read(tag)?;
                let d = &seen.bytes;
                let hex =
                    std::str::from_utf8(d).map_or("", |d| d.trim().trim_start_matches("sha256:"));
                let protected = !scoped
                    || seen
                        .path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| {
                            policy
                                .keep_prefixes
                                .iter()
                                .any(|p| n.starts_with(p.as_str()))
                        });
                let mut by_age = false;
                let kept = if protected {
                    true
                } else if !is_blob_hex(hex) {
                    retained(&seen.path, window)
                } else {
                    // A dangling or oversized manifest has no retention to honour; one
                    // that fails to read aborts, as the mark does on an unreadable root,
                    // since it might be the one that keeps this tag.
                    let manifest = self
                        .read_blob_capped(hex, MAX_MANIFEST_BYTES)
                        .with_context(|| {
                            format!(
                                "reading the manifest of the tag {}; refusing to drop a tag \
                                 it might keep. Remove the tag or the blob sha256:{hex}, \
                                 then run the gc again",
                                seen.path.display()
                            )
                        })?;
                    let asked = manifest.map_or(Retention::Idle, |m| Retention::of_manifest(&m));
                    match (window, asked) {
                        // Under a prefix's window, `keep` and `expires` hold as store-wide
                        // where the window says so, from age and size alike; elsewhere
                        // `expires` holds only within it, `keep` not at all, and the size phase
                        // may drop the tag as it may any tag only age keeps.
                        (Some(w), Retention::Until(t)) if w.keep_holds => now < t,
                        (Some(w), Retention::Until(t)) => {
                            by_age = true;
                            now < t && retained(&seen.path, Some(w))
                        }
                        (Some(w), Retention::Keep) if w.keep_holds => true,
                        (Some(w), _) => {
                            by_age = true;
                            retained(&seen.path, Some(w))
                        }
                        (None, Retention::Keep) => true,
                        (None, Retention::Until(t)) => now < t,
                        (None, Retention::Idle) => {
                            by_age = true;
                            retained(&seen.path, None)
                        }
                    }
                };
                if !kept {
                    plan.drops.push((seen, false));
                } else if is_blob_hex(hex) {
                    kept_tags.push(KeptTag {
                        hex: hex.to_string(),
                        cappable: by_age,
                        used: seen.mtime,
                        dropped: false,
                        seen: Some(seen),
                    });
                }
            }
        }
        if policy.max_bytes.is_some() || policy.free_bytes.is_some() {
            self.cap_tags(policy, now, &man_dirs, &mut kept_tags, &leased, report)?;
        }
        let mut roots: HashSet<String> = HashSet::new();
        for t in kept_tags {
            match (t.dropped, t.seen) {
                (true, Some(seen)) => plan.drops.push((seen, true)),
                _ => {
                    roots.insert(t.hex);
                }
            }
        }

        // manifest sidecars: rooted by a surviving tag, or by their own freshness
        // (digest-pinned), or by being another repository's. The rest are *candidates*, not
        // casualties — the removal waits until after the blob sweep, because a sidecar is a
        // manifest's membership record: dropping one whose blob the same pass then decides to
        // keep would make a live manifest permanently unreadable through its repository, with
        // nothing left to rebuild it from. (An index child is exactly that: no tag roots it, so
        // its sidecar is a candidate here, and only the mark finds it live.)
        for man_dir in &man_dirs {
            plan.unchanged(man_dir);
            let scoped = self.in_scope(policy, man_dir, "manifests");
            for sidecar in root_dir_files(man_dir)? {
                let Some(hex) = sidecar.file_name().and_then(|n| n.to_str()) else {
                    bail!(
                        "{} is not named for a manifest digest; refusing to sweep on marks \
                         that would be incomplete",
                        sidecar.display()
                    );
                };
                let rooted = roots.contains(hex)
                    // Another repository's manifest is none of this pass's to drop, however
                    // long it has gone untagged: a push by digest alone leaves just that.
                    || !scoped
                    || self
                        .find_blob(hex)
                        .is_some_and(|(blob, _)| !idle(&blob, grace));
                if rooted {
                    roots.insert(hex.to_string());
                }
                let hex = hex.to_string();
                plan.sidecars.insert(sidecar, (hex, rooted));
            }
        }

        // mark every blob a root manifest references, through an index's child manifests
        // too. A root that does not parse aborts: sweeping with incomplete marks would delete
        // live data. A child that does not read as a manifest is kept and references nothing
        // (see `walk_manifests`).
        self.mark(&roots, &mut plan)?;

        // Read strictly, like the tag and manifest listings above: this listing is what the
        // sweeps delete against, so an unreadable blob directory would leave the membership
        // records without their survivors.
        for sub in ["blobs/sha256", "blobs/zstd"] {
            for blob in root_dir_files_opt(&self.root.join(sub))? {
                let Some(hex) = blob.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !plan.marked.contains(hex) {
                    let hex = hex.to_string();
                    plan.candidates.push((blob, hex));
                }
            }
        }
        Ok(plan)
    }

    /// The `tags` and `manifests` directories of every repository, refusing a store whose
    /// repositories cannot all be seen.
    fn gc_dirs(&self) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
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
        Ok((tags_dirs, man_dirs))
    }

    /// Mark what `roots` reach, those not yet walked, into `plan`.
    fn mark(&self, roots: &HashSet<String>, plan: &mut GcPlan) -> Result<()> {
        let fresh: HashSet<String> = roots.difference(&plan.walked).cloned().collect();
        if fresh.is_empty() {
            return Ok(());
        }
        let marked = &mut plan.marked;
        // Walked only once read: a root whose manifest is missing now — a dangling tag, a
        // sidecar whose blob is gone — is walked again once it is pushed.
        let mut read: Vec<String> = Vec::new();
        self.walk_manifests(&fresh, true, |hex, manifest| {
            marked.insert(hex.to_string());
            if let Some((_, refs)) = manifest {
                marked.extend(refs.blobs.iter().map(|(h, _)| h.clone()));
                if fresh.contains(hex) {
                    read.push(hex.to_string());
                }
            }
        })
        .context("walking the manifests the gc mark keeps")?;
        for hex in fresh {
            if read.contains(&hex) {
                plan.unread.remove(&hex);
            } else {
                plan.unread.insert(hex);
            }
        }
        plan.walked.extend(read);
        Ok(())
    }

    /// Under the exclusive lock, bring `plan`'s mark up to date with what changed since it was
    /// made: a tag that is new, or names another manifest now, roots what it names; so does a
    /// sidecar that is new, or whose manifest was pushed again and is fresh. A tag the pass
    /// dropped is gone, or, on a dry run, counted as gone while it is still as it was read.
    fn refresh_mark(
        &self,
        policy: &GcPolicy,
        plan: &mut GcPlan,
        idle: &dyn Fn(&Path, Duration) -> bool,
    ) -> Result<()> {
        let (tags_dirs, man_dirs) = self.gc_dirs()?;
        let mut roots: HashSet<String> = plan.unread.clone();
        for tags_dir in tags_dirs {
            if plan.unchanged(&tags_dir) {
                continue;
            }
            for tag in root_dir_files(&tags_dir)? {
                if plan.gone_tags.contains(&tag) {
                    continue;
                }
                // Still as read, a tag yet to be dropped roots nothing; changed, it is kept.
                if let Some((bytes, mtime)) = plan.dropping.get(&tag)
                    && std::fs::metadata(&tag).and_then(|m| m.modified()).ok() == *mtime
                    && std::fs::read(&tag).is_ok_and(|b| b == *bytes)
                {
                    continue;
                }
                let bytes = match std::fs::read(&tag) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("reading the tag {}", tag.display()));
                    }
                };
                let hex = std::str::from_utf8(&bytes)
                    .map_or("", |d| d.trim().trim_start_matches("sha256:"));
                if is_blob_hex(hex) && !plan.walked.contains(hex) {
                    roots.insert(hex.to_string());
                }
            }
        }
        for man_dir in &man_dirs {
            if plan.unchanged(man_dir) {
                continue;
            }
            let scoped = self.in_scope(policy, man_dir, "manifests");
            for sidecar in root_dir_files(man_dir)? {
                let Some(hex) = sidecar.file_name().and_then(|n| n.to_str()) else {
                    bail!(
                        "{} is not named for a manifest digest; refusing to sweep on marks \
                         that would be incomplete",
                        sidecar.display()
                    );
                };
                let hex = hex.to_string();
                let entry = plan
                    .sidecars
                    .entry(sidecar)
                    .or_insert_with(|| (hex.clone(), false));
                if entry.1 {
                    continue;
                }
                let rooted = !scoped
                    || self
                        .find_blob(&hex)
                        .is_some_and(|(blob, _)| !idle(&blob, policy.grace));
                if rooted {
                    entry.1 = true;
                    roots.insert(hex);
                }
            }
        }
        self.mark(&roots, plan)
    }

    /// Whether `dir`, a repository's `kind` directory (`tags`, `manifests`), is in the
    /// repository `policy` confines the pass to; every one is when it names none.
    fn in_scope(&self, policy: &GcPolicy, dir: &Path, kind: &str) -> bool {
        policy
            .repository
            .as_ref()
            .is_none_or(|r| dir == self.root.join("repos").join(r).join(kind))
    }

    /// The size phase of [`Store::gc_with`], after the age phase and before the mark: drop the
    /// tags among `kept` that only age could have dropped, least recently used first, until
    /// the blobs the pass leaves come to at most `policy.max_bytes` and the pass frees at least
    /// `policy.free_bytes`, but never one used within `policy.min_age`. The figures are the
    /// blob files' allocated space on disk, both storage forms. What stays whatever this drops is
    /// counted as staying: the closure of every other tag and of the digest-pinned manifests
    /// the mark roots, leased blobs, and unreferenced blobs still inside the grace window. A
    /// blob shared by several dropped tags frees its bytes only with the last of them. So the
    /// target is one the pass may fall short of; `report` says where it ended. Each manifest is
    /// read once here, whichever tags reach it.
    fn cap_tags(
        &self,
        policy: &GcPolicy,
        now: SystemTime,
        man_dirs: &[PathBuf],
        kept: &mut [KeptTag],
        leased: &HashSet<String>,
        report: &mut GcReport,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let fresh = |path: &Path| {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_none_or(|age| age <= policy.grace)
        };
        // hex → (bytes on disk, of them the bytes this pass may remove once nothing marks it)
        let mut sizes: HashMap<String, (u64, u64)> = HashMap::new();
        for sub in ["blobs/sha256", "blobs/zstd"] {
            for blob in root_dir_files_opt(&self.root.join(sub))? {
                let Some(hex) = blob.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let len = std::fs::metadata(&blob)
                    .with_context(|| format!("stat-ing {}", blob.display()))?
                    .blocks()
                    .saturating_mul(512);
                let e = sizes.entry(hex.to_string()).or_default();
                e.0 = e.0.saturating_add(len);
                if !fresh(&blob) {
                    e.1 = e.1.saturating_add(len);
                }
            }
        }
        let total = sizes.values().fold(0u64, |t, s| t.saturating_add(s.0));

        // What stays whatever this drops: every tag it may not drop, and every manifest the
        // mark roots by its sidecar — a fresh one, the manifest of a tag dropped here included,
        // and another repository's.
        let mut fixed_roots: HashSet<String> = kept
            .iter()
            .filter(|t| !t.cappable)
            .map(|t| t.hex.clone())
            .collect();
        for man_dir in man_dirs {
            let scoped = self.in_scope(policy, man_dir, "manifests");
            for sidecar in root_dir_files(man_dir)? {
                let Some(hex) = sidecar.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !scoped || self.find_blob(hex).is_some_and(|(blob, _)| fresh(&blob)) {
                    fixed_roots.insert(hex.to_string());
                }
            }
        }
        // Every manifest any of them reaches, read once: a manifest's blobs and the manifests
        // it lists (an index's children).
        let mut roots = fixed_roots.clone();
        roots.extend(kept.iter().filter(|t| t.cappable).map(|t| t.hex.clone()));
        let mut graph: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
        self.walk_manifests(&roots, true, |hex, manifest| {
            let edges = manifest.map_or_else(Default::default, |(_, r)| {
                (
                    r.blobs.iter().map(|(h, _)| h.clone()).collect(),
                    r.manifests.clone(),
                )
            });
            graph.insert(hex.to_string(), edges);
        })
        .context("walking the manifests the size cap weighs")?;
        let closure_of = |root: &str, into: &mut dyn FnMut(&str)| {
            let mut seen: HashSet<&str> = HashSet::new();
            let mut pending = vec![root];
            while let Some(hex) = pending.pop() {
                if !seen.insert(hex) {
                    continue;
                }
                into(hex);
                if let Some((blobs, children)) = graph.get(hex) {
                    for b in blobs {
                        into(b);
                    }
                    pending.extend(children.iter().map(String::as_str));
                }
            }
        };
        let mut fixed: HashSet<String> = leased.clone();
        for root in &fixed_roots {
            closure_of(root, &mut |h| {
                fixed.insert(h.to_string());
            });
        }

        // Each droppable tag's closure beyond `fixed`, its blobs numbered so thousands of tags
        // over thousands of chunks each stay small; and how many tags reference each blob.
        let mut ids: HashMap<String, usize> = HashMap::new();
        let mut removable: Vec<u64> = Vec::new();
        let mut refs: Vec<u32> = Vec::new();
        let mut order: Vec<usize> = (0..kept.len()).filter(|&i| kept[i].cappable).collect();
        // Least recently used first; an unreadable date last, as the most recent.
        order.sort_by_key(|&i| (kept[i].used.is_none(), kept[i].used));
        let mut closures: Vec<Vec<usize>> = Vec::with_capacity(order.len());
        for &i in &order {
            let mut closure = Vec::new();
            closure_of(&kept[i].hex, &mut |h| {
                if fixed.contains(h) {
                    return;
                }
                let id = *ids.entry(h.to_string()).or_insert_with(|| {
                    removable.push(sizes.get(h).map_or(0, |s| s.1));
                    refs.push(0);
                    removable.len() - 1
                });
                closure.push(id);
            });
            closure.sort_unstable();
            closure.dedup();
            for &id in &closure {
                refs[id] = refs[id].saturating_add(1);
            }
            closures.push(closure);
        }

        // What the pass leaves before dropping anything here: unreferenced blobs past the grace
        // window go anyway.
        let mut left = total;
        for (hex, &(_, gone)) in &sizes {
            if !fixed.contains(hex) && !ids.contains_key(hex) {
                left = left.saturating_sub(gone);
            }
        }
        // Never a tag used within the grace window either: its manifest's sidecar would root
        // it anyway, freeing nothing.
        let min_age = policy.min_age.max(policy.grace);
        let met = |left: u64| {
            policy.max_bytes.is_none_or(|max| left <= max)
                && policy
                    .free_bytes
                    .is_none_or(|need| total.saturating_sub(left) >= need)
        };
        for (n, &i) in order.iter().enumerate() {
            if met(left) {
                break;
            }
            let recent = kept[i]
                .used
                .is_none_or(|t| now.duration_since(t).unwrap_or_default() < min_age);
            if recent {
                // In use order: every tag after this one is as recent.
                break;
            }
            for &id in &closures[n] {
                refs[id] -= 1;
                if refs[id] == 0 {
                    left = left.saturating_sub(removable[id]);
                }
            }
            kept[i].dropped = true;
        }
        report.bytes_before = Some(total);
        Ok(())
    }

    /// Walk manifests reachable from `roots`, including nested image indexes, once each.
    /// Call `visit(hex, manifest)` for each digest with its bytes and references if it parses,
    /// or `None` otherwise. Shared by gc and size reports to count the references gc keeps.
    ///
    /// Read roots whole, even when first reached as index children. Cap child reads at
    /// [`MAX_MANIFEST_BYTES`]; an unparseable child references nothing. An index can name any
    /// blob its pusher can read, so failing on such children or reading them whole would let
    /// pushers stop collection or exhaust memory. With `strict` (gc), read errors and root
    /// parse errors fail the walk. Reports delete nothing, so they visit those as `None`
    /// and under-report instead.
    fn walk_manifests(
        &self,
        roots: &HashSet<String>,
        strict: bool,
        mut visit: impl FnMut(&str, Option<(&[u8], &ManifestReferences)>),
    ) -> Result<()> {
        let mut walked: HashSet<String> = HashSet::new();
        let mut pending: Vec<String> = roots.iter().cloned().collect();
        while let Some(hex) = pending.pop() {
            if !walked.insert(hex.clone()) {
                continue;
            }
            let root = roots.contains(&hex);
            let read = if root {
                self.get_blob(&hex)
            } else {
                self.read_blob_capped(&hex, MAX_MANIFEST_BYTES)
            };
            let bytes = match read {
                Ok(bytes) => bytes,
                Err(e) if strict => return Err(e),
                Err(_) => None,
            };
            let Some(bytes) = bytes else {
                visit(&hex, None); // gone, or a child over a manifest's size
                continue;
            };
            match manifest_references(&bytes) {
                Ok(refs) => {
                    visit(&hex, Some((&bytes, &refs)));
                    pending.extend(refs.manifests);
                }
                Err(e) if strict && root => {
                    return Err(e.context(format!("parsing manifest {hex}")));
                }
                Err(_) => visit(&hex, None),
            }
        }
        Ok(())
    }

    /// Read-only usage snapshot: on-disk blob totals (both storage forms), in-flight
    /// uploads, and a per-repository breakdown — each repo's tag count, latest tag (by
    /// mtime), and logical size (the blobs its tagged manifests reference, counted once
    /// per repo). `logical_naive` (every reference, no dedup) over `referenced_ondisk`
    /// (the distinct referenced blobs' actual on-disk bytes) is the combined dedup+zstd
    /// packing factor. The size and packing figures cover only the manifests reachable from
    /// tags, through image indexes, walked per repository as the gc mark walks them (so a
    /// manifest tagged in one repository but listed by an index in another is read capped
    /// in the other's walk, which affects only its `logical_bytes`); `total_manifests`
    /// counts every manifest sidecar, tagged or digest-pinned. Taken under the shared lock,
    /// so it never reads a store a gc is mid-sweep on. A manifest it cannot read counts
    /// nothing behind it rather than failing the snapshot.
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
            let mut manifest_hexes: HashSet<String> = HashSet::new();
            let mut stage_hexes = Vec::new();
            let mut latest: Option<(SystemTime, String)> = None;
            for tag in dir_files(&repo_dir.join("tags")) {
                r.tags += 1;
                let stage = r.name.rsplit('/').next() == Some(BUILD_CACHE_REPO)
                    && tag
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.strip_prefix("stage-").is_some_and(is_blob_hex));
                if stage {
                    s.completed_stages += 1;
                }
                if let Ok(digest) = std::fs::read_to_string(&tag) {
                    let hex = digest.trim().trim_start_matches("sha256:").to_string();
                    if is_blob_hex(&hex) {
                        if stage {
                            stage_hexes.push(hex.clone());
                        }
                        manifest_hexes.insert(hex);
                    }
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
            // logical (uncompressed) size of the blobs those manifests reference, through
            // an index's child manifests as the gc mark walks them, deduped within the repo;
            // `logical_naive`/`referenced_ondisk` accumulate globally.
            let mut repo_seen: HashSet<String> = HashSet::new();
            // Not strict, so the walk cannot fail: what it could not read references nothing.
            let _ = self.walk_manifests(&manifest_hexes, false, |hex, manifest| {
                ondisk(hex, &mut s, &mut referenced);
                let Some((bytes, refs)) = manifest else {
                    return;
                };
                // the manifest blob is in `referenced_ondisk` (above), so its own bytes
                // count toward the logical total too — keeps the packing ratio symmetric.
                s.logical_naive += bytes.len() as u64;
                for (dhex, size) in &refs.blobs {
                    s.logical_naive += size;
                    ondisk(dhex, &mut s, &mut referenced);
                    if repo_seen.insert(dhex.clone()) {
                        r.logical_bytes += size;
                    }
                }
            });
            for hex in stage_hexes {
                if let Ok(Some(bytes)) = self.get_blob(&hex)
                    && let Some(size) = stage_data_size(&bytes)
                    && let Some(total) = s.stage_data_bytes.checked_add(size)
                {
                    s.stage_data_bytes = total;
                    s.sized_stages += 1;
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

/// The layer media type of a file stored as one blob under a single-layer manifest — what
/// `/upload` and `/dav/files/` write, and what `vk registry pull` refuses: a raw file is for
/// fetching, not for booting.
pub const RAW_FILE_MEDIA_TYPE: &str = "application/vnd.virtkit.raw-file";
pub const RAW_FILE_CONFIG_MEDIA_TYPE: &str = "application/vnd.virtkit.raw-file.config.v1+json";

/// Shared empty config: raw files have no build config, but OCI manifests require a
/// config descriptor. Every raw file references this blob, so it is stored only once.
pub const RAW_FILE_EMPTY_CONFIG: &[u8] = b"{}";

/// A writer that hashes the bytes it forwards with sha256.
pub struct Sha256Writer<W> {
    inner: W,
    hasher: Sha256,
}

impl<W> Sha256Writer<W> {
    pub fn new(inner: W) -> Self {
        Sha256Writer {
            inner,
            hasher: Sha256::new(),
        }
    }

    /// The writer back, and the sha256 hex of everything written through it.
    pub fn into_hex(self) -> (W, String) {
        (self.inner, hex_of(&self.hasher.finalize()))
    }
}

impl<W: std::io::Write> std::io::Write for Sha256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        // `Write::write` returns at most `buf.len()`; `buf.get(..n)` keeps a writer that
        // breaks that contract from panicking here, and the digest check catches it.
        self.hasher.update(buf.get(..n).unwrap_or(buf));
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A raw file [`Store::open_file`] opened.
pub struct OpenFile {
    /// Its sha256 hex, which is its blob's digest.
    pub sha256: String,
    pub size: u64,
    /// Its layer's title: the file's name, when its writer gave one.
    pub title: Option<String>,
    /// Its bytes.
    pub reader: Box<dyn std::io::Read + Send>,
}

/// The OCI title annotation of a raw-file manifest's layer: the file's name, when its
/// writer gave one.
pub fn raw_file_title(manifest: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    v.pointer("/layers/0/annotations/org.opencontainers.image.title")?
        .as_str()
        .map(str::to_string)
}

/// The layer of a raw-file manifest as `(hex, canonical size)`, or `None` for a manifest of
/// any other shape: an image pushed over `/v2/` into a `files/` repository is not a file
/// the WebDAV view serves.
pub fn raw_file_layer(manifest: &[u8]) -> Option<(String, u64)> {
    let v: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    let [layer] = v.pointer("/layers")?.as_array()?.as_slice() else {
        return None;
    };
    if layer.pointer("/mediaType")?.as_str()? != RAW_FILE_MEDIA_TYPE {
        return None;
    }
    let hex = layer
        .pointer("/digest")?
        .as_str()?
        .strip_prefix("sha256:")?;
    if !is_blob_hex(hex) {
        return None;
    }
    Some((hex.to_string(), layer.pointer("/size")?.as_u64()?))
}

/// `vk-registry gc`'s default grace window in days: how long an unreferenced blob, a stale
/// upload or an unrooted digest-pinned manifest is kept past its last use.
pub const DEFAULT_GC_GRACE_DAYS: u64 = 1;

/// [`DEFAULT_GC_GRACE_DAYS`] as a duration.
pub(crate) const DEFAULT_GC_GRACE: Duration = Duration::from_secs(DEFAULT_GC_GRACE_DAYS * 86_400);

/// The manifest annotation that exempts a tag from [`Store::gc`]'s retention window:
/// value [`RETENTION_KEEP`].
pub const RETENTION_ANNOTATION: &str = "org.virtkit.retention";

/// [`RETENTION_ANNOTATION`]'s one value.
pub const RETENTION_KEEP: &str = "keep";

/// The manifest annotation that gives a tag a fixed expiry, in seconds since the Unix
/// epoch: [`Store::gc`] drops the tag past it, used or not, and never before it.
pub const EXPIRES_ANNOTATION: &str = "org.virtkit.expires";

/// Tag retention for [`Store::gc`], set by manifest annotations.
#[derive(Debug, PartialEq, Eq)]
pub enum Retention {
    /// Until it sits unused past the gc's retention window: no annotation.
    Idle,
    /// For good: [`RETENTION_ANNOTATION`].
    Keep,
    /// Until this moment, used or not: [`EXPIRES_ANNOTATION`].
    Until(SystemTime),
}

impl Retention {
    /// The retention a manifest's bytes ask for. [`RETENTION_ANNOTATION`] wins over
    /// [`EXPIRES_ANNOTATION`], whose value must be a plain decimal `u64` (digits only, no
    /// sign or blanks); an expiry past what [`SystemTime`] can hold reads as
    /// [`Retention::Keep`]. A manifest that does not parse, or an annotation that does not,
    /// asks for none: the window applies, as it always has.
    pub fn of_manifest(bytes: &[u8]) -> Retention {
        let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Retention::Idle;
        };
        let annotation = |key: &str| {
            manifest
                .get("annotations")
                .and_then(|a| a.get(key))
                .and_then(serde_json::Value::as_str)
        };
        if annotation(RETENTION_ANNOTATION) == Some(RETENTION_KEEP) {
            return Retention::Keep;
        }
        let expiry = annotation(EXPIRES_ANNOTATION)
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok());
        match expiry {
            Some(secs) => SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(secs))
                .map_or(Retention::Keep, Retention::Until),
            None => Retention::Idle,
        }
    }
}

/// What a [`Store::gc`] pass removed (or, on a dry run, would remove).
#[derive(Default)]
pub struct GcReport {
    pub tags_dropped: usize,
    pub manifests_dropped: usize,
    pub blobs_dropped: usize,
    /// the space the dropped blobs took on disk (allocated blocks)
    pub bytes_freed: u64,
    pub uploads_dropped: usize,
    /// membership markers removed because the blob they named is gone
    pub blob_markers_dropped: usize,
    /// unreferenced blobs past the grace window kept because a live [`Lease`] names them
    pub blobs_leased: usize,
    /// the space they take on disk (allocated blocks)
    pub bytes_leased: u64,
    /// tags dropped by the size phase (see [`GcPolicy::max_bytes`]); not in `tags_dropped`
    pub tags_capped: usize,
    /// with a size phase: the stored bytes of every blob before the pass, and what the pass
    /// leaves by its own count
    pub bytes_before: Option<u64>,
    pub bytes_after: Option<u64>,
    /// the longest the pass held the store lock exclusive, blocking every push and pull
    pub longest_hold: Duration,
    /// a spell could not be had within the policy's wait: what the pass had not reached is
    /// left for the next, stale sidecars and markers included, which only a complete pass removes
    pub incomplete: bool,
}

/// How [`Store::gc_with`] takes the store lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Wait for every holder to let it go.
    Block,
    /// Give up if it stays held for a few spells' worth, under a second or two.
    Try,
    /// Give up if it stays held this long.
    Within(Duration),
}

/// What a [`Store::gc_with`] pass may drop. [`GcPolicy::new`] is [`Store::gc`]'s: every
/// repository, no size phase, waiting for the lock.
#[derive(Clone, Debug)]
pub struct GcPolicy {
    /// Drop tags idle this long; `None` drops none for their age.
    pub retention: Option<Duration>,
    /// Keep unreferenced blobs, digest-pinned manifests and uploads this long past their
    /// last use.
    pub grace: Duration,
    /// Drop only this repository's tags; every other repository's root the mark. `None`:
    /// every repository's.
    pub repository: Option<String>,
    /// Never drop a tag whose name starts with one of these; it roots the mark.
    pub keep_prefixes: Vec<String>,
    /// Then drop tags by size, least recently used first, until the blobs left take at most
    /// this many bytes on disk...
    pub max_bytes: Option<u64>,
    /// ... and the pass frees at least this many.
    pub free_bytes: Option<u64>,
    /// The size phase drops no tag used more recently than this, nor than `grace`.
    pub min_age: Duration,
    pub dry_run: bool,
    pub wait: Wait,
    /// Run first by the thread that reads the store under the shared lock, the slow part of a
    /// pass: lowering its priority there leaves the exclusive spells after it at the caller's.
    /// The shared lock is then held longer, which delays only those who take it exclusive,
    /// such as the removal of an emptied repository.
    pub lower_planning: Option<fn()>,
}

impl GcPolicy {
    pub fn new(retention: Duration, grace: Duration, dry_run: bool) -> GcPolicy {
        GcPolicy {
            retention: Some(retention),
            grace,
            repository: None,
            keep_prefixes: Vec::new(),
            max_bytes: None,
            free_bytes: None,
            min_age: Duration::ZERO,
            dry_run,
            wait: Wait::Block,
            lower_planning: None,
        }
    }
}

/// What [`Store::gc_with`] did.
pub enum GcOutcome {
    Done(GcReport),
    /// A lock could not be had within the policy's wait before anything was done; see
    /// [`Store::gc_with`].
    Busy,
}

/// A tag a [`Store::gc_with`] pass has kept so far.
struct KeptTag {
    /// The manifest it names.
    hex: String,
    /// Kept for its age alone, so the size phase may drop it.
    cappable: bool,
    /// Its last use; `None` when it cannot be read, which the size phase takes as recent.
    used: Option<SystemTime>,
    dropped: bool,
    /// As it was read, for the drop to check it still is.
    seen: Option<SeenTag>,
}

/// A tag as [`Store::gc_plan`] read it: what the drop checks it still is — not used since,
/// pushed again, nor pointed at another manifest.
struct SeenTag {
    path: PathBuf,
    bytes: Vec<u8>,
    mtime: Option<SystemTime>,
}

impl SeenTag {
    fn read(path: PathBuf) -> Result<SeenTag> {
        let bytes =
            std::fs::read(&path).with_context(|| format!("reading the tag {}", path.display()))?;
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Ok(SeenTag { path, bytes, mtime })
    }

    fn unchanged(&self) -> bool {
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        mtime.is_some()
            && mtime == self.mtime
            && std::fs::read(&self.path).is_ok_and(|b| b == self.bytes)
    }
}

/// What [`Store::gc_plan`] decided and found, for the exclusive spells of [`Store::gc_with`] to
/// act on and keep up to date.
#[derive(Default)]
struct GcPlan {
    /// The tags to drop, each as read, and whether by size rather than age.
    drops: Vec<(SeenTag, bool)>,
    /// On a dry run, the tags dropped, which are still there.
    gone_tags: HashSet<PathBuf>,
    /// The tags yet to be dropped, as read: no root while they are still so.
    dropping: HashMap<PathBuf, (Vec<u8>, Option<SystemTime>)>,
    /// Every sidecar seen, its manifest, and whether something roots it.
    sidecars: HashMap<PathBuf, (String, bool)>,
    /// The manifests walked, and every blob they reach.
    walked: HashSet<String>,
    /// Roots whose manifest was missing when walked, tried again by every spell.
    unread: HashSet<String>,
    marked: HashSet<String>,
    /// The blob files nothing marked when they were listed.
    candidates: Vec<(PathBuf, String)>,
    /// Each `tags` and `manifests` dir read, by its mtime then and when it was read.
    dirs: HashMap<PathBuf, (SystemTime, SystemTime)>,
}

impl GcPlan {
    /// Whether the `tags` or `manifests` dir `dir` is as it was when last read, so reading it
    /// again would find nothing new — and if not, stamp it as read now. Every tag and sidecar
    /// is written by a rename into its dir, which changes the dir's mtime: an mtime unchanged
    /// since a read that came over a second after it, beyond any timestamp's coarseness, is a
    /// dir nothing was written into since.
    fn unchanged(&mut self, dir: &Path) -> bool {
        let read_at = SystemTime::now();
        let Ok(mtime) = std::fs::metadata(dir).and_then(|m| m.modified()) else {
            return false;
        };
        if let Some(&(was, at)) = self.dirs.get(dir)
            && was == mtime
            && was + Duration::from_secs(1) < at
        {
            return true;
        }
        self.dirs.insert(dir.to_path_buf(), (mtime, read_at));
        false
    }
}

/// What a spell of [`Store::gc_with`] is for, as a test's hook is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Dropping the tags the plan decided on.
    Drops,
    /// Sweeping the blobs nothing marks.
    Sweep,
    /// Removing the sidecars, markers and uploads left without their content.
    Last,
}

/// How far [`Spells::run`] got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Done {
    All,
    /// A spell could not be had: what it had not reached is left.
    Short,
}

/// An item of the last spells of [`Store::gc_with`].
enum Last {
    Sidecar(PathBuf),
    Marker(PathBuf, String),
    Upload(PathBuf),
    Owner(PathBuf),
}

/// The exclusive spells of one [`Store::gc_with`] pass.
struct Spells<'a> {
    store: &'a Store,
    policy: &'a GcPolicy,
    longest: &'a Cell<Duration>,
    between: &'a dyn Fn(Phase),
    /// How many it has had so far.
    taken: usize,
}

impl Spells<'_> {
    /// Do `work` on each of `items`, in exclusive spells: before each, a pause for the builds
    /// waiting on the lock (flock queues nobody fairly), the mark brought up to date and the
    /// leases read again; in each, at least [`GC_BATCH`] items, then as many as [`GC_SPELL`]
    /// allows. [`Done::Short`] once a spell cannot be had within the policy's wait.
    fn run<T>(
        &mut self,
        phase: Phase,
        plan: &mut GcPlan,
        idle: &dyn Fn(&Path, Duration) -> bool,
        items: Vec<T>,
        mut work: impl FnMut(&mut GcPlan, &HashSet<String>, T) -> Result<()>,
    ) -> Result<Done> {
        let mut items = items.into_iter();
        while items.len() > 0 {
            if self.taken > 0 {
                std::thread::sleep(GC_YIELD);
            }
            (self.between)(phase);
            let Some(_spell) = self.store.hold_exclusive(self.policy.wait, self.longest)? else {
                return Ok(Done::Short);
            };
            self.taken += 1;
            self.store.refresh_mark(self.policy, plan, idle)?;
            let leased = self.store.leased_blobs(self.policy.dry_run)?;
            // Timed from here: what the refresh took does not shorten the batch.
            let started = Instant::now();
            let mut done = 0;
            for item in items.by_ref() {
                work(plan, &leased, item)?;
                done += 1;
                if done >= GC_BATCH && started.elapsed() >= GC_SPELL {
                    break;
                }
            }
        }
        Ok(Done::All)
    }

    /// The outcome of a pass cut short at a spell it could not have: [`GcOutcome::Busy`] if it
    /// never had one, so did nothing; else `report`, [`incomplete`](GcReport::incomplete).
    fn short(&self, mut report: GcReport) -> GcOutcome {
        if self.taken == 0 {
            return GcOutcome::Busy;
        }
        report.incomplete = true;
        GcOutcome::Done(finish_report(report, self.longest))
    }
}

/// One exclusive spell of [`Store::gc_with`]: the lock, and how long it has been held.
struct Spell<'a> {
    _lock: LockGuard,
    started: Instant,
    longest: &'a Cell<Duration>,
}

impl Drop for Spell<'_> {
    fn drop(&mut self) {
        self.longest
            .set(self.longest.get().max(self.started.elapsed()));
    }
}

/// How long [`Store::gc_with`] works in one exclusive spell, past bringing its mark up to
/// date, before it lets the builds waiting on the lock in.
#[cfg(not(test))]
const GC_SPELL: Duration = Duration::from_millis(500);
/// A spell of one item each, for the tests to come in between.
#[cfg(test)]
const GC_SPELL: Duration = Duration::ZERO;
/// The least it does in a spell.
#[cfg(not(test))]
const GC_BATCH: usize = 64;
#[cfg(test)]
const GC_BATCH: usize = 1;
/// How long it leaves the lock between two spells.
const GC_YIELD: Duration = Duration::from_millis(20);
/// How long [`Wait::Try`] keeps trying for a lock: a few spells' worth.
#[cfg(not(test))]
const TRY_PATIENCE: Duration = Duration::from_millis(1500);
#[cfg(test)]
const TRY_PATIENCE: Duration = Duration::from_millis(50);
/// Held by the [`Store::gc_with`] pass that runs, so a second one waits or gives up rather than
/// read the whole store alongside it.
const GC_LOCK: &str = ".gc.lock";
/// Serializes [`Store::put_manifest`]'s sidecar/tag writes with
/// [`Store::delete_manifest`]'s tag reads and unlinks. Index children are mounted before
/// the push acquires this exclusive lock.
const MANIFEST_WRITES_LOCK: &str = ".manifest-writes.lock";

/// `report` with its last figures: what the sweep removed, not what the size phase expected
/// to, and the longest exclusive spell.
fn finish_report(mut report: GcReport, longest: &Cell<Duration>) -> GcReport {
    report.bytes_after = report
        .bytes_before
        .map(|b| b.saturating_sub(report.bytes_freed));
    report.longest_hold = longest.get();
    report
}

/// Where a store keeps its [`Lease`]s, one file each.
const LEASES_DIR: &str = "leases";
/// The most a lease may hold, about a million blobs: what a gc reads of one at most.
const MAX_LEASE_BYTES: u64 = 64 << 20;

/// A reader's claim on blobs it reads by path (see [`Store::lease`]): a file under the store's
/// `leases/` naming one blob per line, locked for as long as this lives. The lock is what a
/// [`Store::gc`] reads, so a reader killed without a destructor releases its lease with its
/// last descriptor, and the next pass removes the file. Dropping it unlinks the file.
pub struct Lease {
    file: std::fs::File,
    path: PathBuf,
    /// The store it leases from.
    root: PathBuf,
}

impl Lease {
    /// Add `blobs` (hex digests) to the lease, under the shared store lock they were resolved
    /// under (see [`Store::lease`]). A name that is not a blob digest is skipped.
    pub fn add<'a>(
        &mut self,
        held: &LockGuard,
        blobs: impl IntoIterator<Item = &'a str>,
    ) -> Result<()> {
        use std::io::Write;
        debug_assert_eq!(
            held.root, self.root,
            "a lease added to under another store's lock"
        );
        // Opened by a newline, so a digest an earlier add wrote only part of stays a fragment
        // of its own line, which names no blob, rather than running into this add's first.
        let mut lines = String::from("\n");
        for hex in blobs.into_iter().filter(|h| is_blob_hex(h)) {
            lines.push_str(hex);
            lines.push('\n');
        }
        self.file
            .write_all(lines.as_bytes())
            .with_context(|| format!("writing {}", self.path.display()))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Unlinked while still locked, so a gc never reads it as dead first. Best-effort: a
        // file left behind is unlocked once this closes, and the next gc removes it.
        let _ = std::fs::remove_file(&self.path);
    }
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
    /// Completed-stage tags, including any whose manifest could not be sized.
    pub completed_stages: usize,
    pub sized_stages: usize,
    /// Uncompressed chunk lengths, summed per completed-stage tag without deduplication.
    /// Complete only when `sized_stages == completed_stages`; excludes sparse holes.
    pub stage_data_bytes: u64,
    pub repos: Vec<RepoStat>,
}

/// Instruction snapshots and completed-stage aliases share this repository.
pub const BUILD_CACHE_REPO: &str = "build-cache";

/// A completed stage's alias for its last instruction snapshot. Kept as an ordinary
/// OCI tag so remote stores and retention apply the same rules as for other images.
pub fn build_stage_tag(snapshot_tag: &str) -> Option<String> {
    let hex = snapshot_tag
        .strip_prefix("snap-")
        .filter(|h| is_blob_hex(h))?;
    Some(format!("stage-{hex}"))
}

/// Data represented by a stage image, excluding sparse holes. Descriptor sizes may
/// describe compressed blobs, so use the placement lengths the image is restored with.
fn stage_data_size(manifest: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    if v.get("artifactType")?.as_str()? != "application/vnd.wallix.microvm.bundle" {
        return None;
    }
    v.get("layers")?
        .as_array()?
        .iter()
        .try_fold(0u64, |sum, layer| {
            match layer.get("mediaType")?.as_str()? {
                "application/vnd.wallix.microvm.ext4.chunk"
                | "application/vnd.wallix.microvm.ext4.chunk.zstd" => {}
                _ => return None,
            }
            let size = layer
                .get("annotations")?
                .get("vnd.wallix.microvm.chunk.length")?
                .as_str()?
                .parse::<u64>()
                .ok()?;
            sum.checked_add(size)
        })
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
/// types it does not know — the one walk [`manifest_references`] and `/browse`'s detail
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
/// index's child manifests. Unlike [`manifest_references`], which fails on bytes that are
/// not JSON so that the gc mark can refuse such a root, this is for recording membership,
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

/// Whether `body` parses as a JSON object, the least every manifest media type is.
fn is_json_object(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| v.is_object())
}

/// What a manifest keeps alive, read structurally so the gc mark needs no OCI types and
/// tolerates media types it doesn't know: its config and every layer (`blobs`, each with
/// its descriptor's `size`, 0 if missing), and an index's child manifests (`manifests`),
/// which the mark walks in turn.
struct ManifestReferences {
    blobs: Vec<(String, u64)>,
    manifests: Vec<String>,
}

fn manifest_references(manifest: &[u8]) -> Result<ManifestReferences> {
    let v: serde_json::Value = serde_json::from_slice(manifest).context("not JSON")?;
    // Only `sha256:<lowercase hex>`, as [`manifest_child_hexes`] reads them: anything else
    // names nothing this store holds, and as a path component it could name anything at all.
    fn hex(d: &serde_json::Value) -> Option<String> {
        let h = d.pointer("/digest")?.as_str()?.strip_prefix("sha256:")?;
        is_blob_hex(h).then(|| h.to_string())
    }
    let size = |d: &serde_json::Value| d.pointer("/size").and_then(|s| s.as_u64()).unwrap_or(0);
    let children = v.pointer("/manifests").and_then(|m| m.as_array());
    Ok(ManifestReferences {
        blobs: manifest_descriptors(&v)
            .into_iter()
            .filter_map(|(_, d)| Some((hex(d)?, size(d))))
            .collect(),
        manifests: children.into_iter().flatten().filter_map(hex).collect(),
    })
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

/// List every entry of `dir` with its `lstat` type. Return any read error, including a
/// missing directory, rather than an incomplete listing.
fn dir_entries_strict(dir: &Path) -> Result<Vec<(std::ffi::OsString, std::fs::FileType)>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let e = e.with_context(|| format!("reading an entry of {}", dir.display()))?;
        let ft = e
            .file_type()
            .with_context(|| format!("stat-ing {}", e.path().display()))?;
        out.push((e.file_name(), ft));
    }
    Ok(out)
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
    /// The store it locks, for a [`Lease`] to check it is added to under its own store's lock.
    root: PathBuf,
}

/// The space the file at `path` takes on disk, in bytes: its allocated blocks, the figure the
/// gc frees and its size phase weighs. 0 when it cannot be read.
fn disk_bytes(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map_or(0, |m| m.blocks().saturating_mul(512))
}

/// Bump a file's mtime to now — the usage record [`Store::gc`] reads (blob: last
/// written or dedup-referenced; tag: last used). Best-effort: a failed touch only
/// ages the entry early.
fn touch(path: &Path) {
    let _ = std::fs::File::open(path).and_then(|f| f.set_modified(std::time::SystemTime::now()));
}

/// Connections waiting to be accepted, capped by `net.core.somaxconn`.
/// Runner fleets start parallel chunk pulls across jobs at each pipeline stage.
/// The kernel drops excess SYNs, costing clients a one-second retransmit before
/// reaching the registry. The default backlog (128) overflowed 110 times in one
/// afternoon of CI.
const LISTEN_BACKLOG: u32 = 4096;

/// Bind the registry address with [`LISTEN_BACKLOG`].
fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    // Match `TcpListener::bind`: allow restarts while old connections are in TIME_WAIT.
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

/// Run a plain local registry until the process is stopped (no relay upstreams).
/// `addr` is the listen address; `root` is the store directory.
pub async fn serve(addr: SocketAddr, root: PathBuf) -> Result<()> {
    serve_config(ServerConfig::local(addr, root)).await
}

/// Run the registry from a full [`ServerConfig`] (relay upstreams, listen address,
/// store root).
pub async fn serve_config(cfg: ServerConfig) -> Result<()> {
    // A registry its hub is updating: the release on trial, or the binary it replaces taking
    // its turn, before anything is bound.
    if let hub::Start::Exec(binary, deadline) = hub::on_start(&cfg.root, vk_peer::now_secs()) {
        return Err(vk_peer::update::exec(&binary, deadline));
    }
    let addr = cfg.addr;
    let facts = cfg.hub_facts();
    let listener = listen(addr).with_context(|| format!("binding {addr}"))?;
    let tls = cfg.build_tls()?;
    // Resolved before `into_state` consumes the config; bound after it, because the
    // listener is only worth having once the db behind it is open.
    let admin_socket = cfg.resolved_admin_socket();
    let limits = ConnLimits {
        connections: cfg.max_connections,
        per_peer: cfg.max_connections_per_client,
        ..CONN_LIMITS
    };
    raise_nofile_limit(limits.connections);
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
    hub::start(state.clone(), facts);
    serve_limited(listener, state, limits).await
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

/// The startup warning for a server with no authentication listening beyond loopback; `None`
/// otherwise.
fn open_server_warning(open: bool, addr: SocketAddr) -> Option<String> {
    // Canonical first: `[::ffff:127.0.0.1]` is loopback, though not as an IPv6 address.
    (open && !addr.ip().to_canonical().is_loopback()).then(|| {
        format!(
            "vk-registry: WARNING: no authentication is configured and {addr} is not loopback: \
             anyone who can reach it may read, push, delete, take build locks and write through \
             WebDAV. Set token_file or username/password_file, or mode = \"accounts\", unless \
             that is intended."
        )
    })
}

/// The URL scheme a server with (or without) TLS is reached over. One place, because every
/// line that prints a virtkit registry's own URL has to agree with the acceptor it has.
fn scheme(tls: bool) -> &'static str {
    if tls { "https" } else { "http" }
}

/// Limits enforced before authentication. Without them, anyone who can reach the port
/// can hold a task and a descriptor indefinitely without sending a request.
#[derive(Clone, Copy)]
struct ConnLimits {
    /// For a TLS client to finish its handshake.
    handshake: Duration,
    /// For a request's headers to arrive whole, counted from when the connection starts
    /// waiting for them: on connect, and again whenever a kept-alive connection goes idle.
    headers: Duration,
    /// Connections served at once; past it, accepting waits for one to close.
    connections: usize,
    /// Connections served at once from one client address; past it, a new one is turned
    /// away as soon as it is accepted, so one host cannot take every slot of `connections`.
    /// An IPv6 client counts by its /64, the block one host is commonly given, and an
    /// IPv4-mapped IPv6 address as the IPv4 address it maps.
    per_peer: usize,
    /// Connections turned away by `per_peer` that are answered 503 at once, each held for at
    /// most `handshake`, twice [`REFUSAL_HEADERS`] and [`REFUSAL_LINGER`]; past it, they are
    /// closed unanswered.
    /// They do not count against `connections`, so this is what bounds their cost.
    refusals: usize,
}

/// The connections a server admits by default (`max_connections`). Each holds a
/// descriptor, so the open-file limit has to be above it; see [`raise_nofile_limit`].
const DEFAULT_MAX_CONNECTIONS: usize = 4096;
/// The connections one client address may hold by default (`max_connections_per_client`).
/// A quarter of the total: a CI host runs a dozen jobs pulling sixteen blobs at a time
/// each, and every one of those requests is a connection of its own over HTTP/1.1.
const DEFAULT_MAX_CONNECTIONS_PER_CLIENT: usize = 1024;

const CONN_LIMITS: ConnLimits = ConnLimits {
    handshake: Duration::from_secs(10),
    headers: Duration::from_secs(30),
    connections: DEFAULT_MAX_CONNECTIONS,
    per_peer: DEFAULT_MAX_CONNECTIONS_PER_CLIENT,
    refusals: 64,
};

/// For a turned-away client to send its request headers before it is closed unanswered.
const REFUSAL_HEADERS: Duration = Duration::from_secs(5);
/// The `Retry-After` a turned-away request is answered with, in seconds.
const REFUSAL_RETRY_AFTER: &str = "2";
/// How long, and how much, a refused request's body is read after the answer before the
/// connection is closed.
const REFUSAL_LINGER: Duration = Duration::from_secs(2);
const REFUSAL_DRAIN: usize = 64 * 1024;
/// How often a stretch at a connection cap is logged: once on reaching it, then at most
/// once per this long, with the count of what went unlogged.
const CAP_LOG_EVERY: Duration = Duration::from_secs(60);

/// Open connections per client address (see [`peer_key`]).
type PeerCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// The address a client's connections are counted under: its IPv4 address, or its IPv6 /64.
fn peer_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

/// One open connection counted against its client address, uncounted on drop.
struct PeerSlot {
    peers: PeerCounts,
    key: IpAddr,
}

impl PeerSlot {
    /// Count a connection from `ip`, or `None` when it already holds `max`.
    fn acquire(peers: &PeerCounts, ip: IpAddr, max: usize) -> Option<PeerSlot> {
        let key = peer_key(ip);
        let mut map = peers.lock().unwrap_or_else(|e| e.into_inner());
        let open = map.entry(key).or_insert(0);
        if *open >= max {
            if *open == 0 {
                map.remove(&key);
            }
            return None;
        }
        *open += 1;
        Some(PeerSlot {
            peers: peers.clone(),
            key,
        })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut map = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(open) = map.get_mut(&self.key) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                map.remove(&self.key);
            }
        }
    }
}

/// Last log time and unlogged refusal count per client address. A busy host repeatedly
/// crosses its cap as connections open and close; logging each crossing would be noisy.
#[derive(Default)]
struct RefusalLog(HashMap<IpAddr, (std::time::Instant, u64)>);

impl RefusalLog {
    /// Count a refusal of `key` at `now`. When it is time to log one, return how many went
    /// unlogged before it.
    fn refused(&mut self, key: IpAddr, now: std::time::Instant) -> Option<u64> {
        if let Some((at, unlogged)) = self.0.get_mut(&key)
            && now.duration_since(*at) < CAP_LOG_EVERY
        {
            *unlogged += 1;
            return None;
        }
        // Addresses not refused for a while are forgotten here, so the map holds only the
        // ones refused within the last `CAP_LOG_EVERY`.
        let before = self.0.remove(&key).map_or(0, |(_, unlogged)| unlogged);
        self.0
            .retain(|_, (at, _)| now.duration_since(*at) < CAP_LOG_EVERY);
        self.0.insert(key, (now, 0));
        Some(before)
    }
}

/// Raise the soft open-file limit to the hard one (at most `fs.nr_open`) and warn when it is
/// still too low for `connections`. Each connection holds a descriptor, and a server out of
/// them fails accepts and store reads alike. The `install-service` unit sets `LimitNOFILE` well
/// above any cap; a server started by hand gets the shell's soft limit, commonly 1024.
fn raise_nofile_limit(connections: usize) {
    // Store files, the listener, upstream and admin sockets, beside the connections.
    const HEADROOM: u64 = 256;
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit only read and write the struct passed.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return;
    }
    // An unlimited hard limit (`RLIM_INFINITY`) is no limit the kernel grants: a process may
    // open at most `fs.nr_open` files, and a soft limit above it is refused.
    let ceiling = std::fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map_or(lim.rlim_max, |nr_open| lim.rlim_max.min(nr_open));
    if lim.rlim_cur < ceiling {
        let raised = libc::rlimit {
            rlim_cur: ceiling,
            rlim_max: lim.rlim_max,
        };
        // SAFETY: as above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            lim = raised;
        }
    }
    let needed = (connections as u64).saturating_add(HEADROOM);
    if lim.rlim_cur < needed {
        eprintln!(
            "vk-registry: warning: the open-file limit is {} but max_connections = \
             {connections} needs about {needed}; raise it (LimitNOFILE=, ulimit -n) or lower \
             max_connections",
            lim.rlim_cur
        );
    }
}

/// Serve on an already-bound listener (so the caller can pick an ephemeral port and
/// learn it first). The store is content-addressed and written atomically, so several
/// servers may serve the same `root` concurrently.
pub async fn serve_on(listener: TcpListener, state: Arc<ServerState>) -> Result<()> {
    serve_limited(listener, state, CONN_LIMITS).await
}

async fn serve_limited(
    listener: TcpListener,
    state: Arc<ServerState>,
    limits: ConnLimits,
) -> Result<()> {
    let refusals = Arc::new(tokio::sync::Semaphore::new(limits.refusals));
    serve_refusing(listener, state, limits, refusals).await
}

/// [`serve_limited`] with caller-supplied refusal permits (`limits.refusals`) so tests can
/// observe their use.
async fn serve_refusing(
    listener: TcpListener,
    state: Arc<ServerState>,
    limits: ConnLimits,
    refusals: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
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
        let open = matches!(&state.auth, Authenticator::Shared(a) if !a.enabled());
        if let Some(warning) = open_server_warning(open, addr) {
            eprintln!("{warning}");
        }
    }
    if !state.webdav {
        eprintln!("vk-registry: WebDAV off (webdav = false): /dav/ answers 404");
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.connections));
    let peers = PeerCounts::default();
    let mut refused = RefusalLog::default();
    // When the cap was last logged: once per stretch at it, and at most every
    // `CAP_LOG_EVERY`, as a server near its cap goes over and back all the time.
    let mut full_logged: Option<std::time::Instant> = None;
    loop {
        // Held for the connection's life: at the cap, new clients wait in the kernel's
        // backlog rather than each costing a task here.
        let slot = match slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                if full_logged.is_none_or(|t| t.elapsed() >= CAP_LOG_EVERY) {
                    full_logged = Some(Instant::now());
                    eprintln!(
                        "vk-registry: {} connections open (max_connections), new ones wait",
                        limits.connections
                    );
                }
                slots
                    .clone()
                    .acquire_owned()
                    .await
                    .context("connection slots")?
            }
        };
        // A failed accept (out of descriptors, a client that reset before it was accepted) is
        // that one connection's, not the server's: wait a moment and keep serving.
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("vk-registry: accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(peer_slot) = PeerSlot::acquire(&peers, peer.ip(), limits.per_peer) else {
            drop(slot);
            let key = peer_key(peer.ip());
            if let Some(unlogged) = refused.refused(key, Instant::now()) {
                let since = match unlogged {
                    0 => String::new(),
                    n => format!(" ({n} turned away since the last notice)"),
                };
                eprintln!(
                    "vk-registry: {} has {} connections open (max_connections_per_client), \
                     new ones are answered 503{since}",
                    match key {
                        IpAddr::V6(_) => format!("{key}/64"),
                        IpAddr::V4(_) => key.to_string(),
                    },
                    limits.per_peer
                );
            }
            // Past `refusals` the client is not even told: it is closed with nothing read.
            if let Ok(permit) = refusals.clone().try_acquire_owned() {
                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    refuse(stream, &state, limits).await;
                });
            }
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _slots = (slot, peer_slot, state.store.count_connection());
            match &state.tls {
                Some(acceptor) => {
                    match tokio::time::timeout(limits.handshake, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => serve_conn(TokioIo::new(tls), state.clone(), limits).await,
                        Ok(Err(e)) => eprintln!("vk-registry: TLS handshake error: {e}"),
                        Err(_) => eprintln!("vk-registry: TLS handshake timed out"),
                    }
                }
                None => serve_conn(TokioIo::new(stream), state.clone(), limits).await,
            }
        });
    }
}

/// Answer one request on a turned-away connection with a 503 and a `Retry-After`, then
/// close it: a client told to come back later can wait, where one whose connection is
/// closed under it cannot tell that from a failure. Nothing is logged: the refusal already
/// was, and a client that hangs up first is one that did not need the answer.
///
/// The 503 carries the server's authentication challenge, as a 401 would: oci-client learns
/// how to authenticate from its first `GET /v2/`, and without a challenge there it sends
/// the requests that follow anonymously.
async fn refuse(stream: tokio::net::TcpStream, state: &ServerState, limits: ConnLimits) {
    let challenge = state.auth.challenge_value();
    match &state.tls {
        Some(acceptor) => {
            if let Ok(Ok(tls)) =
                tokio::time::timeout(limits.handshake, acceptor.accept(stream)).await
            {
                refuse_on(tls, challenge).await;
            }
        }
        None => refuse_on(stream, challenge).await,
    }
}

/// [`refuse`] over any transport.
async fn refuse_on<S>(stream: S, challenge: Option<&'static str>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let svc = service_fn(move |_req| async move {
        let mut resp = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "TOOMANYREQUESTS",
            "too many connections from this address; retry later",
        );
        let headers = resp.headers_mut();
        headers.insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static(REFUSAL_RETRY_AFTER),
        );
        if let Some(challenge) = challenge {
            headers.insert(
                hyper::header::WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static(challenge),
            );
        }
        Ok::<_, Infallible>(resp)
    });
    let conn = http1::Builder::new()
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(REFUSAL_HEADERS)
        .serve_connection(TokioIo::new(stream), svc)
        .without_shutdown();
    // Bounded as a whole too: the answer is small, but a client that never reads it would
    // otherwise hold the write, and with it the permit, for as long as it likes. Errors are
    // the client's: one that resets instead of reading is one that did not need the answer.
    let Ok(Ok(parts)) = tokio::time::timeout(REFUSAL_HEADERS * 2, conn).await else {
        return;
    };
    // Close the write side, then read what the client still sends — the rest of a refused
    // upload, up to `REFUSAL_DRAIN` — so the close is a FIN after the answer, not a reset
    // over unread bytes that can discard the answer before the client reads it.
    let mut stream = parts.io.into_inner();
    let _ = tokio::time::timeout(REFUSAL_LINGER, async {
        stream.shutdown().await?;
        let (mut left, mut buf) = (REFUSAL_DRAIN, [0u8; 8192]);
        while left > 0 {
            match stream.read(&mut buf).await? {
                0 => break,
                n => left = left.saturating_sub(n),
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
}

/// Serve one HTTP/1 connection over any transport (plain TCP or TLS).
async fn serve_conn<I>(io: I, state: Arc<ServerState>, limits: ConnLimits)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| handle(req, state.clone()));
    // hyper requires a timer to enforce the header read timeout.
    match http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.headers)
        .serve_connection(io, svc)
        .await
    {
        // The header timeout also ends every kept-alive connection left idle, so logging it
        // would log every pooled client every 30 s.
        Err(e) if e.is_timeout() => {}
        Err(e) => eprintln!("vk-registry: connection error: {e}"),
        Ok(()) => {}
    }
}

/// `POST /vk/manifests/exists?name=<repo>` — the batched form of `HEAD
/// /v2/<repo>/manifests/<tag>`. Body `{"tags":[…]}`, answer `{"present":[…]}` in the same
/// order. Read access to the repository is authorized once for the whole batch, exactly as
/// a tag `HEAD` is (a tag lives in the repository, so it is already scoped); digests are
/// not accepted, since a digest is not. Answers from this store only — a pull-through
/// mirror says what it holds, and never relays.
pub const EXISTS_PATH: &str = "/vk/manifests/exists";

/// Longest `POST /vk/manifests/exists` body read: [`MAX_MANIFEST_REFERENCES`] tags of the
/// longest valid reference, with JSON around them, is well under this.
const MAX_EXISTS_BODY: usize = 1 << 20;

async fn manifests_exist(
    store: &Store,
    authz: &Authz<'_>,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    if req.method() != Method::POST {
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "use POST",
        ));
    }
    let name = query_param(req.uri().query().unwrap_or(""), "name").unwrap_or_default();
    if !valid_name(&name) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            &name,
        ));
    }
    if let Some(resp) = authorize_or_forbidden(authz, accounts::Action::Read, &name) {
        return Ok(resp);
    }
    #[derive(serde::Deserialize)]
    struct Ask {
        tags: Vec<String>,
    }
    let ask: Ask = match collect_capped(req, MAX_EXISTS_BODY).await {
        Ok(body) => match serde_json::from_slice(&body) {
            Ok(ask) => ask,
            Err(_) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "UNSUPPORTED",
                    r#"body must be {"tags":[…]}"#,
                ));
            }
        },
        Err(_) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "UNSUPPORTED",
                "body over the cap",
            ));
        }
    };
    // The same bound a manifest's references have: the work is a `stat` per tag under
    // the store lock, which is not something one caller gets an unbounded amount of.
    if ask.tags.len() > MAX_MANIFEST_REFERENCES {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "UNSUPPORTED",
            &format!("more than {MAX_MANIFEST_REFERENCES} tags"),
        ));
    }
    let tags: Vec<&str> = ask.tags.iter().map(String::as_str).collect();
    let present = store.has_manifests(&name, &tags)?;
    let body = serde_json::json!({ "present": present }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body_of(Bytes::from(body)))
        .map_err(Into::into)
}

/// Wrap `route`, turning any internal error into a 500: the error chain goes to stderr, the
/// client gets a bare `INTERNAL` (a handler never fails the connection).
async fn handle(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Body>, Infallible> {
    // Kept for the log line; `route` consumes the request.
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let has_body = !hyper::body::Body::is_end_stream(req.body());
    let tls = state.tls.is_some();
    let resp = route(req, state).await.unwrap_or_else(|e| {
        eprintln!("vk-registry: {method} {path}: {e:#}");
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "internal error (details in the server log)",
        )
    });
    Ok(with_hsts(closing_after_refusal(resp, has_body), tls))
}

/// `resp`, with `Connection: close` when it refuses a request that came with a body. A
/// refusal can answer before that body is read through, and hyper then drops the connection
/// after writing a head that still offered keep-alive, so a client pools it and sees its
/// next request reset. A refusal that did read the body costs the client a reconnect. A 303
/// is how a form POST that succeeded answers (`forms::see_other`), after reading its body.
fn closing_after_refusal(mut resp: Response<Body>, has_body: bool) -> Response<Body> {
    let status = resp.status();
    if has_body && !(status.is_success() || status == StatusCode::SEE_OTHER) {
        resp.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
    }
    resp
}

/// Whether the browser says another site made this request (`Sec-Fetch-Site`). A browser
/// that predates the header, and every non-browser client, sends none.
fn cross_site(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !matches!(v, "same-origin" | "none"))
}

/// `resp`, with HSTS when this server terminates TLS: a browser that has seen it uses HTTPS
/// for this host name, on every port, for a year.
fn with_hsts(mut resp: Response<Body>, tls: bool) -> Response<Body> {
    if tls {
        resp.headers_mut().insert(
            hyper::header::STRICT_TRANSPORT_SECURITY,
            hyper::header::HeaderValue::from_static("max-age=31536000"),
        );
    }
    resp
}

/// The answer to a refused hub token: the mode's own challenge, as for any bad credential.
fn token_challenge(auth: &Authenticator) -> Response<Body> {
    match auth {
        Authenticator::Accounts { .. } => accounts::challenge(),
        Authenticator::Shared(auth) => auth.challenge(),
    }
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
    // Browsers attach cookies or Basic credentials to cross-site requests and the machine
    // routes carry no CSRF token, so a cross-site non-GET is refused.
    if !is_human
        && !matches!(req.method(), &Method::GET | &Method::HEAD)
        && cross_site(req.headers())
    {
        return Ok(error_response(
            StatusCode::FORBIDDEN,
            "DENIED",
            "a write to this registry cannot come from another site's page",
        ));
    }

    // A hub token is checked before the mode's own credentials, in either mode: it carries
    // the hub's grants, of which the mode knows nothing. With tokens off it is left to the
    // mode, which refuses it as any credential it does not know.
    let token = match hubtoken::presented(req.headers()) {
        Some(t) => match state.tokens.check(&t, vk_peer::now_secs()) {
            Some(Ok(claims)) => Some(claims),
            Some(Err(why)) => {
                state.tokens.log_refusal(&why);
                return Ok(token_challenge(&state.auth));
            }
            None => None,
        },
        None => None,
    };

    let principal = match &state.auth {
        _ if token.is_some() => None,
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

    // A hub managing the registry may make it refuse writes for a while; reads go on, as do
    // sign-ins, key management (the accounts db, not the store) and the lock service.
    if state.store.read_only() && is_store_write(req.method(), &path) {
        let mut resp = if is_human {
            html::error(
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                None,
                "Read-only for now",
                "The registry takes no writes for now. Try again later.",
            )
        } else {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "UNAVAILABLE",
                "the registry is read-only for now",
            )
        };
        resp.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("60"),
        );
        return Ok(resp);
    }

    // Derived from `state.auth`, not from whether a principal happens to be present: in
    // accounts mode a missing one is refused above, and reading its absence as `NoScopes`
    // here would be a path that silently skips every per-repo check.
    let authz = match (&token, &state.auth, &principal) {
        (Some(claims), _, _) => Authz::Token(claims),
        (None, Authenticator::Accounts { .. }, Some(p)) => Authz::Accounts(p),
        (None, Authenticator::Accounts { .. }, None) => return Ok(accounts::challenge()),
        (None, Authenticator::Shared(_), _) => Authz::NoScopes,
    };
    // A token is for machines: the pages are a person's.
    if token.is_some() && is_human {
        return Ok(error_response(
            StatusCode::FORBIDDEN,
            "DENIED",
            "a hub token reaches no page of this registry",
        ));
    }

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
        if path == "/settings/tags/delete" {
            return tags::route(&state.store, db, p, state.cookies_are_secure(), req).await;
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
        // After `exp`, a token has no lifetime left for a lease or memo.
        // Reject it as expired even within the allowed clock skew.
        if token.as_ref().is_some_and(|c| c.exp <= vk_peer::now_secs()) {
            return Ok(token_challenge(&state.auth));
        }
        return lock::route(&state.locks, req, token.as_ref()).await;
    }
    // The batched manifest probe, also outside `/v2/`: `vk build` asks about every step
    // of a stage in one request instead of a `HEAD` per step.
    if path == EXISTS_PATH {
        return manifests_exist(&state.store, &authz, req).await;
    }

    // DAV authorizes each resource: `files/<dir>` or the OCI repository name. Keep it outside
    // `is_human_path` so clients receive a 401 challenge, not a login redirect.
    // Disabled WebDAV routes fall through to 404.
    if state.webdav && (path == "/dav" || path.starts_with("/dav/")) {
        return dav::route(&state, &authz, req).await;
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

    // <name>/manifests/<tag|digest> — PUT (store) / GET / HEAD / DELETE.
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
        let action = if matches!(method, Method::PUT | Method::DELETE) {
            accounts::Action::Write
        } else {
            accounts::Action::Read
        };
        if let Some(resp) = authorize_or_forbidden(&authz, action, name) {
            return Ok(resp);
        }
        return match method {
            Method::DELETE => delete_manifest(&store, name, reference),
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
    serve_blob(store, digest, head, accept_zstd, head)
}

/// [`get_blob`], with whether a HEAD counts as a use of the blob left to the caller: a
/// WebDAV `HEAD` is an existence check, not a pusher about to reference the blob.
pub(crate) fn serve_blob(
    store: &Store,
    digest: &str,
    head: bool,
    accept_zstd: bool,
    record_use: bool,
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
    if record_use {
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
    // A digest reference that does not match the body is the client's error, not this
    // server's, so it is the spec's 400 rather than `handle`'s JSON 500.
    if reference.starts_with("sha256:") && reference != format!("sha256:{}", sha256_hex_raw(body)) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("the manifest body does not hash to {reference}"),
        ));
    }
    if !is_json_object(body) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "the manifest body is not a JSON object",
        ));
    }
    // shared store lock for the write (vs. an exclusive gc); see lock_shared.
    let _lock = store.lock_shared()?;
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

/// DELETE /v2/<name>/manifests/<tag|digest>: 202 once dropped, 404 when there was nothing.
/// Never relayed: an upstream's copy is not this registry's to delete.
fn delete_manifest(store: &Store, name: &str, reference: &str) -> Result<Response<Body>> {
    if !store.delete_manifest(name, reference)? {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            reference,
        ));
    }
    Response::builder()
        .status(StatusCode::ACCEPTED)
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
    /// A hub token, in either mode: its grants are the whole of what it may do.
    Token(&'a vk_hub_proto::token::Claims),
}

impl Authz<'_> {
    /// Whether this caller may read `repo`.
    fn may_read(&self, repo: &str) -> bool {
        self.may(accounts::Action::Read, repo)
    }

    /// Whether this caller may do `action` on `repo`.
    fn may(&self, action: accounts::Action, repo: &str) -> bool {
        match self {
            Authz::NoScopes => true,
            Authz::Accounts(p) => accounts::authorize(p, action, repo),
            Authz::Token(claims) => claims.allows_repo(
                repo,
                match action {
                    accounts::Action::Read => vk_hub_proto::token::RepoRight::Read,
                    accounts::Action::Write => vk_hub_proto::token::RepoRight::Write,
                },
            ),
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
    // See the shortcut below: not taken for a hub token.
    let shortcut = !matches!(authz, Authz::Token(_));
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
        // repository per guess. Not for a hub token: it confines a job to its namespaces,
        // and the store's holdings outside them are none of its business, by timing or
        // otherwise. It pays the walk over the repositories its grants make readable for
        // every reference, and `readable_repos` lists every repository once per manifest.
        if (shortcut && store.find_blob(&hex).is_none()) || !store.any_holds(&elsewhere, &hex) {
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
        _ if authz.may(action, name) => None,
        Authz::Token(_) => Some(error_response(
            StatusCode::FORBIDDEN,
            "DENIED",
            "the hub token grants nothing for this repository/action",
        )),
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
    path == "/settings/keys"
        || path.starts_with("/settings/keys/")
        || path == "/settings/captions"
        || path == "/settings/tags/delete"
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
pub(crate) const MAX_NAME_SEGMENTS: usize = 16;

/// A repository name: one to [`MAX_NAME_SEGMENTS`] `/`-separated path components, each a
/// non-empty run of `[A-Za-z0-9._-]` and not `.`/`..` — so it never escapes the store dir.
/// Shared with `/browse`, whose repo segment is just as untrusted as the OCI API's
/// `<name>`.
pub fn valid_name(name: &str) -> bool {
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
pub fn valid_tag(t: &str) -> bool {
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
/// endpoints, the `?target=` on a login redirect, and vk-driver's guest proxy re-encoding a
/// lock name it mapped — never HTML, so this needs no HTML-escaping counterpart; that is
/// [`html_escape`].
pub fn percent_encode(s: &str) -> String {
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
pub fn percent_decode(s: &str) -> String {
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

/// `vk registry gc` / `vk-registry gc` — collect `root` and print a one-line summary;
/// see [`Store::gc`] for the retention model. `cmd` is the command the caller was
/// invoked as, so the log lines name the binary the operator actually typed.
pub fn gc(
    cmd: &str,
    root: PathBuf,
    retention: Duration,
    grace: Duration,
    dry_run: bool,
) -> Result<()> {
    gc_windows(cmd, root, retention, grace, dry_run, Vec::new())
}

/// [`gc`], with retention windows of their own under prefixes (`[[gc.prefix]]`).
pub fn gc_windows(
    cmd: &str,
    root: PathBuf,
    retention: Duration,
    grace: Duration,
    dry_run: bool,
    windows: Vec<PrefixWindow>,
) -> Result<()> {
    gc_to(
        &mut std::io::stdout().lock(),
        cmd,
        root,
        (retention, grace, dry_run),
        windows,
    )
}

/// [`gc_windows`] writing its summary to `out` rather than stdout, so a test can read it
/// back.
fn gc_to(
    out: &mut impl std::io::Write,
    cmd: &str,
    root: PathBuf,
    (retention, grace, dry_run): (Duration, Duration, bool),
    windows: Vec<PrefixWindow>,
) -> Result<()> {
    let Some(store) = Store::open(&root)? else {
        writeln!(
            out,
            "{cmd}: gc {}: no store here, nothing to collect",
            root.display()
        )?;
        return Ok(());
    };
    store.set_prefix_windows(windows);
    let r = store.gc(retention, grace, dry_run)?;
    writeln!(
        out,
        "{cmd}: gc {}: {} {} tag(s), {} manifest(s), {} blob(s) ({:.1} MiB), \
         {} upload(s), {} membership record(s)",
        store.root.display(),
        if dry_run { "would drop" } else { "dropped" },
        r.tags_dropped,
        r.manifests_dropped,
        r.blobs_dropped,
        r.bytes_freed as f64 / f64::from(1u32 << 20),
        r.uploads_dropped,
        r.blob_markers_dropped,
    )?;
    writeln!(
        out,
        "{cmd}: gc {}: held the store lock exclusive for {} ms at most",
        store.root.display(),
        r.longest_hold.as_millis()
    )?;
    if r.blobs_leased > 0 {
        writeln!(
            out,
            "{cmd}: gc {}: kept {} leased blob(s) ({:.1} MiB) that running builds read",
            store.root.display(),
            r.blobs_leased,
            r.bytes_leased as f64 / f64::from(1u32 << 20),
        )?;
    }
    Ok(())
}

/// `vk registry status` / `vk-registry status` — print a read-only usage + content
/// report for the store at `root`: stored bytes, tag references, and a per-repository
/// breakdown; see [`Store::stats`]. `cmd` is the command the caller was invoked as, so
/// the report names the binary the operator actually typed.
pub fn status(cmd: &str, root: PathBuf) -> Result<()> {
    status_to(&mut std::io::stdout().lock(), cmd, root)
}

/// [`status`] writing its report to `out` rather than stdout, so a test can read it back.
fn status_to(out: &mut impl std::io::Write, cmd: &str, root: PathBuf) -> Result<()> {
    let Some(store) = Store::open(&root)? else {
        // Not an error: a host that has cached nothing has an empty store by definition,
        // and `--root` pointed at the wrong place reads as this too — which is why the
        // path is named rather than the counts printed as zeroes.
        writeln!(out, "{cmd}: {} — no store here", root.display())?;
        return Ok(());
    };
    let s = store.stats()?;
    let blobs = s.identity_blobs + s.zstd_blobs;
    let blob_bytes = s.identity_bytes + s.zstd_bytes;
    writeln!(out, "{cmd}: {}", store.root.display())?;
    writeln!(
        out,
        "  Stored blobs:       {} ({} files)",
        human_bytes(blob_bytes),
        blobs,
    )?;
    writeln!(
        out,
        "  Referenced by tags: {}",
        human_bytes(s.referenced_ondisk)
    )?;
    let unreferenced = blob_bytes.saturating_sub(s.referenced_ondisk);
    writeln!(out, "  No tag references:  {}", human_bytes(unreferenced))?;
    if s.completed_stages > 0 {
        if s.sized_stages == s.completed_stages {
            writeln!(
                out,
                "  Stage data:         {} uncompressed ({} recorded stage snapshots)",
                human_bytes(s.stage_data_bytes),
                s.completed_stages,
            )?;
            writeln!(
                out,
                "                      Shared data counts per stage; empty disk regions are excluded."
            )?;
        } else {
            writeln!(
                out,
                "  Stage data:         unavailable (some stage manifests could not be sized)"
            )?;
        }
    } else if s
        .repos
        .iter()
        .any(|r| r.name.rsplit('/').next() == Some(BUILD_CACHE_REPO) && r.tags > 0)
    {
        writeln!(
            out,
            "  Stage data:         unknown (no completed stages recorded yet)"
        )?;
    }
    if s.uploads > 0 {
        writeln!(
            out,
            "  Uploads in progress: {} ({} files, separate from stored blobs)",
            human_bytes(s.upload_bytes),
            s.uploads,
        )?;
    }
    if !s.repos.is_empty() {
        writeln!(out)?;
        writeln!(out, "  {:<40} {:>5}", "REPOSITORY", "TAGS")?;
        for r in &s.repos {
            writeln!(out, "  {:<40} {:>5}", r.name, r.tags)?;
        }
    } else {
        writeln!(out, "  No repositories.")?;
    }
    if unreferenced > 0 {
        writeln!(out)?;
        writeln!(
            out,
            "  Blobs without tag references may still be protected by GC's grace period."
        )?;
        writeln!(
            out,
            "  Preview cleanup with `{cmd} gc --dry-run` (use the same store root)."
        )?;
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
/// the point — the server it starts holds one capability and can write only the store, and
/// the binary's directory if its account owns it, for a hub's update to replace the binary.
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
    // A hub's update renames the release over the binary, which `ProtectSystem=strict`
    // would refuse in any directory. Lifting that leaves file permissions in charge: the
    // account still writes the directory only if it owns it, as the update requires.
    let bin_dir = exe
        .parent()
        .with_context(|| format!("the binary {} has no directory", exe.display()))?;
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
         ReadWritePaths={bin_dir}\n\
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
        bin_dir = unit_path("the binary's directory", bin_dir)?,
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

    /// Start a server with `limits` on an ephemeral port over a fresh store named `tag`.
    async fn serve_test_limited(tag: &str, limits: ConnLimits) -> (SocketAddr, PathBuf) {
        let (addr, dir, _) = serve_test_with(tag, limits, auth::Auth::None, None).await;
        (addr, dir)
    }

    /// [`serve_test_limited`] with `auth` and `tls`, and the permits of its refusals.
    async fn serve_test_with(
        tag: &str,
        limits: ConnLimits,
        auth: auth::Auth,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> (SocketAddr, PathBuf, Arc<tokio::sync::Semaphore>) {
        let dir = std::env::temp_dir().join(format!("vk-regserve-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = Arc::new(ServerState {
            store: Arc::new(Store::new(dir.clone()).unwrap()),
            upstreams: Vec::new(),
            locks: lock::LockManager::new(),
            auth: Authenticator::Shared(auth),
            tls,
            webdav: false,
            tokens: Default::default(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let refusals = Arc::new(tokio::sync::Semaphore::new(limits.refusals));
        tokio::spawn(serve_refusing(listener, state, limits, refusals.clone()));
        (addr, dir, refusals)
    }

    /// Wait for `permits` to have `n` available, as the server takes and returns them.
    async fn permits_reach(permits: &tokio::sync::Semaphore, n: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while permits.available_permits() != n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{} refusal permits, not {n}", permits.available_permits()));
    }

    /// A client that stops mid-header is dropped once the header timeout passes, and the
    /// connection cap holds a second client back until a slot frees.
    #[tokio::test]
    async fn a_stalled_client_is_dropped_and_connections_are_capped() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let limits = ConnLimits {
            handshake: Duration::from_secs(1),
            headers: Duration::from_secs(1),
            connections: 1,
            per_peer: 16,
            refusals: 4,
        };
        let (addr, dir) = serve_test_limited("limits", limits).await;

        let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
        stalled.write_all(b"GET /v2/ HTTP/1.1\r\n").await.unwrap();
        // The one slot is taken: a second client is not served while the first holds it.
        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        second
            .write_all(b"GET /v2/ HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), second.read(&mut buf))
                .await
                .is_err(),
            "a client past the cap was served"
        );
        // The header timeout closes the stalled client without a response.
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            let mut rest = Vec::new();
            stalled.read_to_end(&mut rest).await.map(|_| rest)
        })
        .await
        .expect("the stalled client was never dropped")
        .unwrap();
        assert!(closed.is_empty(), "{closed:?}");
        // Closing the stalled client frees the slot for the waiting client.
        let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
            .await
            .expect("the waiting client was never served")
            .unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", &buf[..n]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A kept-alive connection left idle after a request is closed by the header timeout.
    #[tokio::test]
    async fn an_idle_kept_alive_connection_is_closed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let limits = ConnLimits {
            handshake: Duration::from_secs(1),
            headers: Duration::from_secs(1),
            connections: 4,
            per_peer: 4,
            refusals: 4,
        };
        let (addr, dir) = serve_test_limited("idle", limits).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /v2/ HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // The response arrives, then the connection stays open until the timeout ends it.
        let all = tokio::time::timeout(Duration::from_secs(3), async {
            let mut all = Vec::new();
            client.read_to_end(&mut all).await.map(|_| all)
        })
        .await
        .expect("the idle connection was never closed")
        .unwrap();
        assert!(all.starts_with(b"HTTP/1.1 200"), "{all:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Past its per-address cap, a client's new connection is answered 503 with a
    /// `Retry-After` and closed, while another address is still served; past the refusals
    /// answered at once, it is closed unanswered.
    #[tokio::test]
    async fn connections_are_capped_per_client_address() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let limits = ConnLimits {
            handshake: Duration::from_secs(5),
            headers: Duration::from_secs(5),
            connections: 4,
            per_peer: 1,
            refusals: 1,
        };
        let (addr, dir, refusals) =
            serve_test_with("perpeer", limits, auth::Auth::None, None).await;

        let mut held = tokio::net::TcpStream::connect(addr).await.unwrap();
        held.write_all(b"GET /v2/ HTTP/1.1\r\n").await.unwrap();
        // Same address, over its cap: told to come back later, its upload left unread
        // without that answer being lost to a reset.
        let mut over = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = vec![b'x'; 32 * 1024];
        let head = format!(
            "PUT /v2/r/blobs/uploads/u HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        over.write_all(&[head.as_bytes(), &body].concat())
            .await
            .unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(2), async {
            let mut all = Vec::new();
            over.read_to_end(&mut all).await.map(|_| all)
        })
        .await
        .expect("a connection past the per-address cap was kept open")
        .unwrap();
        let answer = String::from_utf8_lossy(&answer).to_ascii_lowercase();
        assert!(answer.starts_with("http/1.1 503"), "{answer}");
        assert!(answer.contains("retry-after: 2"), "{answer}");
        assert!(answer.contains("toomanyrequests"), "{answer}");
        assert!(!answer.contains("www-authenticate"), "{answer}");
        drop(over);
        // A refusal still waiting for its request holds the one permit, so the next one
        // over the cap is closed with nothing read or written.
        permits_reach(&refusals, 1).await;
        let _waiting = tokio::net::TcpStream::connect(addr).await.unwrap();
        permits_reach(&refusals, 0).await;
        let mut unanswered = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), unanswered.read(&mut buf))
            .await
            .expect("a refusal past the permits was kept open")
            .unwrap();
        assert_eq!(n, 0, "{:?}", &buf[..n]);
        // Another loopback address has its own count.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let mut other = socket.connect(addr).await.unwrap();
        other
            .write_all(b"GET /v2/ HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), other.read(&mut buf))
            .await
            .expect("another address was not served")
            .unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", &buf[..n]);
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refusal over TLS is answered after the handshake, and carries the server's
    /// challenge, so a client probing `/v2/` learns how to authenticate even when turned away.
    #[tokio::test]
    async fn a_refusal_over_tls_carries_the_challenge() {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        // The test certificate and key vk-hub's tests use, for `localhost`.
        const TLS_CA: &[u8] = include_bytes!("testdata/tls-ca.pem");
        const TLS_CERT: &[u8] = include_bytes!("testdata/tls-cert.pem");
        const TLS_KEY: &[u8] = include_bytes!("testdata/tls-key.pem");
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = CertificateDer::pem_slice_iter(TLS_CERT)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(TLS_KEY).unwrap();
        let sc = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));
        let limits = ConnLimits {
            handshake: Duration::from_secs(5),
            headers: Duration::from_secs(5),
            connections: 4,
            per_peer: 1,
            refusals: 1,
        };
        let basic = auth::Auth::Basic {
            user: "u".into(),
            pass: "p".into(),
        };
        let (addr, dir, _) = serve_test_with("refuse-tls", limits, basic, Some(acceptor)).await;

        let _held = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(TLS_CA).unwrap())
            .resolve("localhost", addr)
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://localhost:{}/v2/", addr.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let header = |name| resp.headers().get(name).and_then(|v| v.to_str().ok());
        assert_eq!(header(hyper::header::RETRY_AFTER), Some("2"));
        assert_eq!(
            header(hyper::header::WWW_AUTHENTICATE),
            Some("Basic realm=\"vk-registry\"")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The challenge on a refusal is harmless to a client that already sends credentials:
    /// refused, it gets them through once the address is below its cap again.
    #[tokio::test]
    async fn an_authenticated_client_gets_through_after_a_refusal() {
        let limits = ConnLimits {
            handshake: Duration::from_secs(5),
            headers: Duration::from_secs(5),
            connections: 4,
            per_peer: 1,
            refusals: 1,
        };
        let basic = auth::Auth::Basic {
            user: "u".into(),
            pass: "p".into(),
        };
        let (addr, dir, refusals) = serve_test_with("refuse-basic", limits, basic, None).await;
        let held = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client = reqwest::Client::new();
        let probe = || {
            client
                .get(format!("http://{addr}/v2/"))
                .basic_auth("u", Some("p"))
                .send()
        };
        let resp = probe().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().contains_key(hyper::header::WWW_AUTHENTICATE));
        drop((resp, held));
        permits_reach(&refusals, 1).await;
        // The held connection's slot is given back once the server sees it closed.
        let resp = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let resp = probe().await.unwrap();
                if resp.status() != StatusCode::SERVICE_UNAVAILABLE {
                    return resp;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the address stayed over its cap");
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A lock request turned away past the per-address cap is asked again after the
    /// `Retry-After`, not read as the lock being held.
    #[tokio::test]
    async fn a_lock_request_waits_out_a_refusal() {
        let limits = ConnLimits {
            handshake: Duration::from_secs(5),
            headers: Duration::from_secs(5),
            connections: 4,
            per_peer: 1,
            refusals: 1,
        };
        let (addr, dir, _) = serve_test_with("lock-refused", limits, auth::Auth::None, None).await;
        let held = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client = LockClient::new(
            format!("http://{addr}"),
            ClientAuth::None,
            reqwest::Client::new(),
        );
        let start = Instant::now();
        let acquire = client.acquire("k", Duration::from_secs(30), Duration::ZERO, "me");
        let free = async {
            // Well before the `Retry-After` is up, free the address's slot.
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(held);
        };
        let (got, ()) = tokio::join!(acquire, free);
        assert!(got.unwrap().is_some(), "the lock was not acquired");
        // Only a refusal's `Retry-After` takes this long.
        assert!(
            start.elapsed() >= Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A connection's per-address count is released when it closes, and the entry with it.
    #[test]
    fn peer_slots_count_and_release() {
        let peers = PeerCounts::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let a = PeerSlot::acquire(&peers, ip, 2).unwrap();
        let b = PeerSlot::acquire(&peers, ip, 2).unwrap();
        assert!(PeerSlot::acquire(&peers, ip, 2).is_none());
        assert!(PeerSlot::acquire(&peers, "192.0.2.2".parse().unwrap(), 2).is_some());
        drop(a);
        let c = PeerSlot::acquire(&peers, ip, 2).unwrap();
        assert!(PeerSlot::acquire(&peers, ip, 2).is_none());
        drop((b, c));
        assert!(peers.lock().unwrap().is_empty());
    }

    /// An address's refusals are logged at most once per `CAP_LOG_EVERY`, the next line
    /// counting those in between, however often it crosses its cap meanwhile; an address
    /// not refused for that long is forgotten.
    #[test]
    fn refusals_are_logged_at_most_once_a_period() {
        let t0 = Instant::now();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let mut log = RefusalLog::default();
        assert_eq!(log.refused(a, t0), Some(0));
        assert_eq!(log.refused(a, t0 + Duration::from_secs(1)), None);
        assert_eq!(log.refused(a, t0 + Duration::from_secs(59)), None);
        assert_eq!(log.refused(b, t0 + Duration::from_secs(59)), Some(0));
        assert_eq!(log.refused(a, t0 + CAP_LOG_EVERY), Some(2));
        assert_eq!(log.refused(a, t0 + CAP_LOG_EVERY * 2), Some(0));
        // `b` was last refused more than a period before, so the log no longer holds it.
        assert_eq!(log.0.len(), 1);
    }

    /// IPv6 clients count by /64, and an IPv4-mapped address as its IPv4 address.
    #[test]
    fn peers_are_keyed_by_ipv4_address_or_ipv6_64() {
        let key = |s: &str| peer_key(s.parse().unwrap());
        assert_eq!(key("192.0.2.1"), key("::ffff:192.0.2.1"));
        assert_ne!(key("192.0.2.1"), key("192.0.2.2"));
        assert_eq!(
            key("2001:db8:1:2::1"),
            key("2001:db8:1:2:ffff:ffff:ffff:ffff")
        );
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2::"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));

        let peers = PeerCounts::default();
        let _a = PeerSlot::acquire(&peers, "2001:db8::1".parse().unwrap(), 1).unwrap();
        assert!(PeerSlot::acquire(&peers, "2001:db8::2".parse().unwrap(), 1).is_none());
    }

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

    #[test]
    fn a_cross_site_request_is_told_apart() {
        let h = |v: Option<&str>| {
            let mut m = hyper::HeaderMap::new();
            if let Some(v) = v {
                m.insert("sec-fetch-site", v.parse().unwrap());
            }
            cross_site(&m)
        };
        assert!(h(Some("cross-site")));
        assert!(h(Some("same-site")));
        assert!(!h(Some("same-origin")));
        assert!(!h(Some("none")));
        assert!(
            !h(None),
            "a client that sends no header is not judged by it"
        );
    }

    /// A TLS server sends HSTS even on internal errors (500) and cross-site rejections (403);
    /// a plain HTTP server never does. The test uses a cleartext connection and no certificate:
    /// `handle` only checks whether TLS is configured.
    #[tokio::test]
    async fn hsts_is_sent_on_every_answer_only_over_tls() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn ask(tls: bool, request: &str) -> String {
            let dir = std::env::temp_dir().join(format!(
                "vk-regserve-hsts-{tls}-{}-{}",
                request.len(),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let store = Store::new(dir.clone()).unwrap();
            // Make opening an upload session fail on the server.
            std::fs::remove_dir_all(dir.join("uploads/owners")).unwrap();
            std::fs::write(dir.join("uploads/owners"), b"").unwrap();
            let acceptor = tls.then(|| {
                let sc = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(
                        Arc::new(rustls::server::ResolvesServerCertUsingSni::new()),
                    );
                tokio_rustls::TlsAcceptor::from(Arc::new(sc))
            });
            let state = Arc::new(ServerState {
                store: Arc::new(store),
                upstreams: Vec::new(),
                locks: lock::LockManager::new(),
                auth: Authenticator::Shared(auth::Auth::None),
                tls: acceptor,
                webdav: false,
                tokens: Default::default(),
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve_conn(TokioIo::new(stream), state, CONN_LIMITS).await;
            });
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            conn.write_all(request.as_bytes()).await.unwrap();
            let mut resp = String::new();
            conn.read_to_string(&mut resp).await.unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            resp.to_ascii_lowercase()
        }

        let probe = "GET /v2/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        let failing = "POST /v2/r/blobs/uploads/ HTTP/1.1\r\nHost: x\r\n\
                       Content-Length: 0\r\nConnection: close\r\n\r\n";
        let cross_site = "DELETE /v2/r/manifests/t HTTP/1.1\r\nHost: x\r\n\
                          Sec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n";
        let hsts = "strict-transport-security: max-age=31536000";
        for (request, status) in [(probe, "200"), (failing, "500"), (cross_site, "403")] {
            let resp = ask(true, request).await;
            assert!(resp.starts_with(&format!("http/1.1 {status}")), "{resp}");
            assert!(resp.contains(hsts), "{resp}");
            let resp = ask(false, request).await;
            assert!(resp.starts_with(&format!("http/1.1 {status}")), "{resp}");
            assert!(!resp.contains("strict-transport-security"), "{resp}");
        }
    }

    /// An open server says so when it is reachable beyond loopback, and only then.
    #[test]
    fn an_open_server_off_loopback_warns() {
        let lan: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert!(open_server_warning(true, lan).is_some_and(|w| w.contains("WARNING")));
        assert!(open_server_warning(true, lo).is_none());
        assert!(open_server_warning(false, lan).is_none());
        for (addr, warns) in [
            ("[::]:5000", true),
            ("[::1]:5000", false),
            ("[::ffff:127.0.0.1]:5000", false),
        ] {
            assert_eq!(
                open_server_warning(true, addr.parse().unwrap()).is_some(),
                warns,
                "{addr}"
            );
        }
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

        // the account is the one asked for, and the store and the binary's directory, for a
        // hub's update to replace it, are the only writable paths. No `Group=`: the account's
        // own primary group is whatever `useradd` gave it.
        let unit = system_unit(&facts("127.0.0.1:5000"), "registry-svc", installed).unwrap();
        assert!(unit.contains("User=registry-svc\n"), "{unit}");
        assert!(!unit.contains("Group="), "{unit}");
        assert!(unit.contains("ProtectSystem=strict\n"), "{unit}");
        let writable: Vec<&str> = unit
            .lines()
            .filter_map(|l| l.strip_prefix("ReadWritePaths="))
            .collect();
        assert_eq!(
            writable,
            ["\"/srv/vk-registry\"", "\"/usr/local/bin\""],
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
        status("vk-registry", dir.clone()).unwrap();
        gc("vk-registry", dir.clone(), zero, zero, false).unwrap();
        assert!(!dir.exists(), "{} was created by reading it", dir.display());

        // Someone else's directory, named by a mistyped root: reported as no store, and
        // left exactly as empty as it was.
        std::fs::create_dir_all(&dir).unwrap();
        assert!(Store::open(&dir).unwrap().is_none());
        status("vk-registry", dir.clone()).unwrap();
        gc("vk-registry", dir.clone(), zero, zero, false).unwrap();
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
        assert!(status("vk-registry", dir.join("a-file")).is_err());
        std::fs::remove_file(dir.join("a-file")).unwrap();

        // A store that is there is opened as usual — the report is skipped for absence,
        // not for being empty.
        let store = Store::new(dir.clone()).unwrap();
        assert!(Store::open(&store.root).unwrap().is_some());
        status("vk-registry", dir.clone()).unwrap();
        gc("vk-registry", dir.clone(), zero, zero, true).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every command-named line in `status`/`gc` output — the prefixes and the cleanup
    /// hint — carries the command the binary was invoked as, so the standalone binary never
    /// points an operator at a `vk registry` command it does not provide.
    #[test]
    fn status_and_gc_name_the_invoking_command() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-cmdname-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // An orphan blob (no tag references it) so `status` reaches the cleanup-hint line.
        let store = Store::new(dir.clone()).unwrap();
        store.put_blob(b"a blob no tag references").unwrap();
        let zero = Duration::from_secs(0);

        let render = |cmd: &str| {
            let mut s = Vec::new();
            status_to(&mut s, cmd, dir.clone()).unwrap();
            let mut g = Vec::new();
            gc_to(&mut g, cmd, dir.clone(), (zero, zero, true), Vec::new()).unwrap();
            (String::from_utf8(s).unwrap(), String::from_utf8(g).unwrap())
        };

        // The standalone binary names itself, in the report prefix, the gc summary, and the
        // cleanup hint — and never the driver's `vk registry` spelling.
        let (s, g) = render("vk-registry");
        assert!(s.starts_with("vk-registry:"), "{s}");
        assert!(s.contains("`vk-registry gc --dry-run`"), "{s}");
        assert!(!s.contains("vk registry gc"), "{s}");
        assert!(g.starts_with("vk-registry: gc "), "{g}");

        // The driver's spelling is carried through unchanged.
        let (s, g) = render("vk registry");
        assert!(s.starts_with("vk registry:"), "{s}");
        assert!(s.contains("`vk registry gc --dry-run`"), "{s}");
        assert!(g.starts_with("vk registry: gc "), "{g}");

        drop(store);
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

    /// A body that is not a JSON object is refused before anything is written: the gc mark
    /// parses every rooted manifest and stops on one it cannot.
    #[tokio::test]
    async fn a_manifest_that_is_not_a_json_object_is_refused() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-notjson-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        for body in [&b"not json"[..], b"[]", b"\"a string\""] {
            let res = put_manifest(
                &Authz::NoScopes,
                &store,
                "img",
                "v1",
                DEFAULT_MANIFEST_TYPE,
                body,
            )
            .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST);
            let err: serde_json::Value =
                serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(err["errors"][0]["code"], "MANIFEST_INVALID");
            assert!(
                store
                    .put_manifest("img", "v1", DEFAULT_MANIFEST_TYPE, body)
                    .is_err()
            );
        }
        assert!(store.get_manifest("img", "v1").unwrap().is_none());
        assert!(
            !store.tag_path("img", "v1").exists(),
            "a refused push leaves no tag"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DELETE by tag drops that tag only; by digest, every tag of the repository on it and
    /// its membership, leaving other repositories' tags on the same bytes alone. Nothing to
    /// drop is a 404.
    #[tokio::test]
    async fn deleting_a_manifest_by_tag_or_digest() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-mdel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let body = br#"{"a":1}"#;
        let digest = store
            .put_manifest("img", "v1", DEFAULT_MANIFEST_TYPE, body)
            .unwrap();
        for (repo, tag) in [("img", "v2"), ("img", "keep-other"), ("other", "v1")] {
            let b: &[u8] = if tag == "keep-other" {
                br#"{"b":2}"#
            } else {
                body
            };
            store
                .put_manifest(repo, tag, DEFAULT_MANIFEST_TYPE, b)
                .unwrap();
        }

        let res = delete_manifest(&store, "img", "v1").unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        assert!(store.get_manifest("img", "v1").unwrap().is_none());
        assert!(store.get_manifest("img", "v2").unwrap().is_some());
        let res = delete_manifest(&store, "img", "v1").unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = delete_manifest(&store, "img", &digest).unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        assert!(store.get_manifest("img", "v2").unwrap().is_none());
        assert!(!store.repo_has_manifest("img", &digest[7..]));
        assert!(store.get_manifest("img", "keep-other").unwrap().is_some());
        assert!(store.get_manifest("other", "v1").unwrap().is_some());
        assert!(store.repo_has_manifest("other", &digest[7..]));
        let res = delete_manifest(&store, "img", &digest).unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
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
    /// (`sha256:` digests) — the structure `manifest_references` marks from.
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

    /// A blob a live lease names outlives its tag and the grace window; once the lease is
    /// released, or its holder is gone, the next pass sweeps it. A dry run removes no lease.
    #[test]
    fn gc_keeps_what_a_live_lease_names() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gclease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let chunk = store.put_blob(&[7u8; 4096]).unwrap();
        let cfg = store.put_blob(b"cfg-leased").unwrap();
        store
            .put_manifest(
                "repo",
                "t",
                DEFAULT_MANIFEST_TYPE,
                &manifest_body(&cfg, &[&chunk]),
            )
            .unwrap();
        let lease = {
            let held = store.lock_shared().unwrap();
            let mut lease = store.lease(&held).unwrap();
            lease
                .add(&held, [hex(&chunk).as_str(), "not-a-digest"])
                .unwrap();
            lease
        };
        // What a reader killed without a destructor leaves: a lease nobody holds.
        let dead = dir.join(LEASES_DIR).join("1-0-0");
        std::fs::write(&dead, format!("{}\n", hex(&cfg))).unwrap();
        backdate_all(&dir, SystemTime::now() - DAY * 100);

        let dry = store.gc(DAY * 30, DAY, true).unwrap();
        assert_eq!(dry.blobs_leased, 1);
        assert!(dead.exists(), "a dry run removes no lease");
        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.tags_dropped, 1);
        assert_eq!(report.blobs_leased, 1);
        assert!(report.bytes_leased > 0);
        assert!(!dead.exists(), "a dead lease goes");
        assert!(store.has_blob(&hex(&chunk)), "a leased blob stays");
        assert!(!store.has_blob(&hex(&cfg)), "a dead lease protects nothing");

        drop(lease);
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.blobs_leased, 0);
        assert!(
            !store.has_blob(&hex(&chunk)),
            "a released lease protects nothing"
        );
        assert_eq!(std::fs::read_dir(dir.join(LEASES_DIR)).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A digest an add wrote only part of, before failing, does not run into the next add's
    /// first: that one is still leased.
    #[test]
    fn a_torn_add_leaves_the_next_add_whole() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("vk-regserve-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let chunk = store.put_blob(&[11u8; 4096]).unwrap();
        let held = store.lock_shared().unwrap();
        let mut lease = store.lease(&held).unwrap();
        lease.file.write_all(&hex(&chunk).as_bytes()[..20]).unwrap();
        lease.add(&held, [hex(&chunk).as_str()]).unwrap();
        drop(held);
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        let report = store.gc(DAY, DAY, true).unwrap();
        assert_eq!(report.blobs_leased, 1);
        drop(lease);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A lease is live while any process holds its lock: one a forked child still holds after
    /// the parent let its own descriptor go keeps its blob, and the child's exit frees it.
    #[test]
    fn a_lease_lives_as_long_as_any_holder_of_its_lock() {
        use std::os::unix::io::AsRawFd;
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcfork-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let chunk = store.put_blob(&[8u8; 4096]).unwrap();
        std::fs::create_dir_all(dir.join(LEASES_DIR)).unwrap();
        let path = dir.join(LEASES_DIR).join("forked");
        std::fs::write(&path, format!("{}\n", hex(&chunk))).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: plain syscalls on descriptors this test owns; the child runs only
        // async-signal-safe calls (read, _exit) before it exits.
        let pid = unsafe {
            assert_eq!(
                libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB),
                0
            );
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            let pid = libc::fork();
            if pid == 0 {
                libc::close(fds[1]);
                let mut b = 0u8;
                libc::read(fds[0], (&mut b as *mut u8).cast(), 1);
                libc::_exit(0);
            }
            libc::close(fds[0]);
            pid
        };
        assert!(pid > 0);
        // The parent's descriptor goes; the child's copy of it still holds the lock.
        drop(file);
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.blobs_leased, 1);
        assert!(store.find_blob(&hex(&chunk)).is_some());
        assert!(path.exists(), "a live lease stays");

        // SAFETY: closing the pipe's write end lets the child exit; it is then reaped.
        unsafe {
            libc::close(fds[1]);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.blobs_leased, 0);
        assert!(store.find_blob(&hex(&chunk)).is_none());
        assert!(!path.exists(), "a dead lease goes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The leases are read strictly: an entry that is not a plain file, or a lease that cannot
    /// be read, stops the pass before anything is removed. A lease protects its blob even with
    /// no grace at all.
    #[test]
    fn gc_refuses_leases_it_cannot_read_and_honours_one_without_grace() {
        let dir =
            std::env::temp_dir().join(format!("vk-regserve-gcbadlease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let chunk = store.put_blob(&[9u8; 4096]).unwrap();
        let other = store.put_blob(&[10u8; 4096]).unwrap();
        let lease = {
            let held = store.lock_shared().unwrap();
            let mut lease = store.lease(&held).unwrap();
            lease.add(&held, [hex(&chunk).as_str()]).unwrap();
            lease
        };

        let odd = dir.join(LEASES_DIR).join("a-dir");
        std::fs::create_dir(&odd).unwrap();
        assert!(store.gc(Duration::ZERO, Duration::ZERO, false).is_err());
        assert!(
            store.find_blob(&hex(&other)).is_some(),
            "nothing was removed"
        );
        std::fs::remove_dir(&odd).unwrap();

        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = dir.join(LEASES_DIR).join("unreadable");
            std::fs::write(&unreadable, b"").unwrap();
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert!(store.gc(Duration::ZERO, Duration::ZERO, false).is_err());
            assert!(
                store.find_blob(&hex(&other)).is_some(),
                "nothing was removed"
            );
            std::fs::remove_file(&unreadable).unwrap();
        }

        let report = store.gc(Duration::ZERO, Duration::ZERO, false).unwrap();
        assert_eq!(report.blobs_leased, 1);
        assert!(
            store.find_blob(&hex(&chunk)).is_some(),
            "a leased blob stays"
        );
        assert!(store.find_blob(&hex(&other)).is_none());
        drop(lease);
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

    /// Manifest annotations override the window: kept tags survive any idleness,
    /// expired tags are dropped regardless of use, and future expiries survive.
    #[test]
    fn gc_honours_a_manifests_retention() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut chunks = HashMap::new();
        for (byte, tag, key, value) in [
            (1, "kept", RETENTION_ANNOTATION, RETENTION_KEEP.to_string()),
            (2, "expired", EXPIRES_ANNOTATION, (now - 60).to_string()),
            (3, "later", EXPIRES_ANNOTATION, (now + 3600).to_string()),
            (4, "idle", "other", "x".to_string()),
        ] {
            let chunk = store.put_blob(&[byte; 4096]).unwrap();
            let mut body: serde_json::Value =
                serde_json::from_slice(&manifest_body(&chunk, &[&chunk])).unwrap();
            body["annotations"] = serde_json::json!({ key: value });
            store
                .put_manifest(
                    "repo",
                    tag,
                    DEFAULT_MANIFEST_TYPE,
                    &serde_json::to_vec(&body).unwrap(),
                )
                .unwrap();
            chunks.insert(tag, chunk);
        }
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.tag_path("repo", "expired"));

        // A dry run counts the annotated drops too, and removes nothing.
        let dry = store.gc(DAY * 30, DAY, true).unwrap();
        assert_eq!(dry.tags_dropped, 2);
        for tag in chunks.keys() {
            assert!(store.tag_path("repo", tag).exists(), "{tag}");
        }

        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.tags_dropped, 2);
        // A dropped tag's blobs are past the grace window, so this same pass sweeps them;
        // probe via paths only, as get_manifest would bump the mtimes.
        for (tag, present) in [
            ("kept", true),
            ("expired", false),
            ("later", true),
            ("idle", false),
        ] {
            assert_eq!(store.tag_path("repo", tag).exists(), present, "{tag}");
            assert_eq!(
                store.find_blob(&hex(&chunks[tag])).is_some(),
                present,
                "{tag}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Incompressible bytes, so a blob's stored size is its length.
    fn noise(seed: u8, len: usize) -> Vec<u8> {
        let mut x = (u64::from(seed) + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect()
    }

    /// A size-capped policy over `build-cache` that never ages a tag out and keeps `win-` tags.
    fn cap_policy(max_bytes: Option<u64>, dry_run: bool) -> GcPolicy {
        GcPolicy {
            retention: None,
            grace: DAY,
            repository: Some("build-cache".into()),
            keep_prefixes: vec!["win-".into()],
            max_bytes,
            free_bytes: None,
            min_age: DAY,
            dry_run,
            wait: Wait::Block,
            lower_planning: None,
        }
    }

    fn done(outcome: GcOutcome) -> GcReport {
        match outcome {
            GcOutcome::Done(report) => report,
            GcOutcome::Busy => panic!("the store lock was busy"),
        }
    }

    /// The size phase drops the least recently used tags of its repository first, frees a chunk
    /// two tags share only with the last of them, and never drops a tag used within its floor,
    /// one a manifest keeps, a kept prefix, or another repository's. A dry run counts what a
    /// real pass does.
    #[test]
    fn gc_caps_the_cache_least_recently_used_first() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gccap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let chunk = |seed: u8| store.put_blob(&noise(seed, 64 * 1024)).unwrap();
        let shared = chunk(0);
        let mut chunks = HashMap::new();
        let now = SystemTime::now();
        for (seed, repo, tag, days, keep) in [
            (1, "build-cache", "old", 10, false),
            (2, "build-cache", "mid", 5, false),
            (3, "build-cache", "new", 2, false),
            (4, "build-cache", "recent", 0, false),
            (5, "build-cache", "win-layer", 20, false),
            (6, "build-cache", "kept", 20, true),
            (7, "mine", "x", 30, false),
        ] {
            let c = chunk(seed);
            let layers: Vec<&str> = if seed <= 2 {
                vec![&c, &shared]
            } else {
                vec![&c]
            };
            let mut body: serde_json::Value =
                serde_json::from_slice(&manifest_body(&c, &layers)).unwrap();
            if keep {
                body["annotations"] = serde_json::json!({ RETENTION_ANNOTATION: RETENTION_KEEP });
            }
            store
                .put_manifest(
                    repo,
                    tag,
                    DEFAULT_MANIFEST_TYPE,
                    &serde_json::to_vec(&body).unwrap(),
                )
                .unwrap();
            chunks.insert(tag, (repo, c, days));
        }
        backdate_all(&dir, now - DAY * 100);
        for (tag, (repo, _, days)) in &chunks {
            let used = now - DAY * *days - Duration::from_secs(3600);
            let used = if *days == 0 { now } else { used };
            std::fs::File::open(store.tag_path(repo, tag))
                .unwrap()
                .set_modified(used)
                .unwrap();
        }
        let present = |tag: &str| {
            let (repo, c, _) = &chunks[tag];
            (
                store.tag_path(repo, tag).exists(),
                store.find_blob(&hex(c)).is_some(),
            )
        };

        // Everything it may drop: the three tags older than the floor.
        let all = done(store.gc_with(&cap_policy(Some(0), true)).unwrap());
        assert_eq!(all.tags_capped, 3);
        assert_eq!(all.tags_dropped, 0, "no retention, nothing by age");
        let before = all.bytes_before.unwrap();
        assert!(
            all.bytes_after.unwrap() > 0,
            "what it may not drop stays counted"
        );

        // Just under the current size: the oldest goes, and the chunk it shares stays.
        let dry = done(store.gc_with(&cap_policy(Some(before - 1), true)).unwrap());
        let real = done(store.gc_with(&cap_policy(Some(before - 1), false)).unwrap());
        assert_eq!((dry.tags_capped, real.tags_capped), (1, 1));
        assert_eq!(dry.bytes_after, real.bytes_after);
        assert_eq!(real.bytes_freed, before - real.bytes_after.unwrap());
        assert_eq!(present("old"), (false, false));
        assert_eq!(present("mid"), (true, true));
        assert!(store.find_blob(&hex(&shared)).is_some());

        // Nothing fits: the shared chunk goes with the last tag that held it; the rest stays.
        let real = done(store.gc_with(&cap_policy(Some(0), false)).unwrap());
        assert_eq!(real.tags_capped, 2);
        assert!(store.find_blob(&hex(&shared)).is_none());
        for tag in ["mid", "new"] {
            assert_eq!(present(tag), (false, false), "{tag}");
        }
        for tag in ["recent", "win-layer", "kept", "x"] {
            assert_eq!(present(tag), (true, true), "{tag}");
        }
        assert_eq!(
            real.bytes_after,
            Some(real.bytes_before.unwrap() - real.bytes_freed)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pass asked to free some space stops once it has; one that may not wait for the lock
    /// finds it held by a reader and does nothing.
    #[test]
    fn gc_frees_what_it_is_asked_for_and_can_give_up_on_the_lock() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcfree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let now = SystemTime::now();
        let mut chunks = Vec::new();
        for (seed, tag, days) in [(1, "a", 9), (2, "b", 8), (3, "c", 7)] {
            let c = store.put_blob(&noise(seed, 64 * 1024)).unwrap();
            store
                .put_manifest(
                    "build-cache",
                    tag,
                    DEFAULT_MANIFEST_TYPE,
                    &manifest_body(&c, &[&c]),
                )
                .unwrap();
            chunks.push((tag, c, days));
        }
        backdate_all(&dir, now - DAY * 100);
        for (tag, _, days) in &chunks {
            std::fs::File::open(store.tag_path("build-cache", tag))
                .unwrap()
                .set_modified(now - DAY * *days)
                .unwrap();
        }
        let policy = GcPolicy {
            max_bytes: None,
            free_bytes: Some(1),
            ..cap_policy(None, false)
        };

        let held = store.lock_shared().unwrap();
        let busy = store.gc_with(&GcPolicy {
            wait: Wait::Try,
            ..policy.clone()
        });
        assert!(matches!(busy, Ok(GcOutcome::Busy)));
        drop(held);

        let report = done(store.gc_with(&policy).unwrap());
        assert_eq!(report.tags_capped, 1);
        assert!(report.bytes_freed >= 64 * 1024);
        for (tag, c, _) in &chunks {
            let kept = *tag != "a";
            assert_eq!(store.tag_path("build-cache", tag).exists(), kept, "{tag}");
            assert_eq!(store.find_blob(&hex(c)).is_some(), kept, "{tag}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pass confined to one repository drops only its tags, keeps every other repository's
    /// manifests whether tagged or pushed by digest alone, still honours an annotated expiry
    /// with no retention of its own, refuses a scope that names no repository, and gives up
    /// on a lock a reader holds when told not to wait.
    #[test]
    fn gc_with_confines_its_drops_to_one_repository() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcscope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let put = |repo: &str, tag: &str, seed: u8, annotations: Option<serde_json::Value>| {
            let chunk = store.put_blob(&[seed; 4096]).unwrap();
            let mut body: serde_json::Value =
                serde_json::from_slice(&manifest_body(&chunk, &[&chunk])).unwrap();
            if let Some(a) = annotations {
                body["annotations"] = a;
            }
            let body = serde_json::to_vec(&body).unwrap();
            let tag = if tag == "@" {
                format!("sha256:{}", sha256_hex_raw(&body))
            } else {
                tag.to_string()
            };
            store
                .put_manifest(repo, &tag, DEFAULT_MANIFEST_TYPE, &body)
                .unwrap();
            chunk
        };
        let idle = put("build-cache", "idle", 1, None);
        let expired = put(
            "build-cache",
            "expired",
            2,
            Some(serde_json::json!({ EXPIRES_ANNOTATION: "1" })),
        );
        let other = put("mine", "t", 3, None);
        let pinned = put("mine", "@", 4, None);
        let nested = put("build-cache/x", "t", 5, None);
        let kept = put("build-cache", "win-layer", 6, None);
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        let policy = GcPolicy {
            retention: None,
            grace: Duration::ZERO,
            repository: Some("build-cache".into()),
            keep_prefixes: vec!["win-".into()],
            ..GcPolicy::new(Duration::ZERO, Duration::ZERO, false)
        };

        let held = store.lock_shared().unwrap();
        let busy = store.gc_with(&GcPolicy {
            wait: Wait::Try,
            ..policy.clone()
        });
        assert!(matches!(busy, Ok(GcOutcome::Busy)));
        drop(held);
        for bad in ["./build-cache", "build-cache/", ""] {
            let r = store.gc_with(&GcPolicy {
                repository: Some(bad.into()),
                ..policy.clone()
            });
            assert!(r.is_err(), "{bad:?}");
        }

        let GcOutcome::Done(r) = store.gc_with(&policy).unwrap() else {
            panic!("the lock was free");
        };
        assert_eq!(r.tags_dropped, 1, "only the expired tag, with no retention");
        assert!(store.find_blob(&hex(&expired)).is_none());
        for (what, d) in [
            ("an idle tag with no retention", &idle),
            ("another repository's tag", &other),
            ("another repository's digest push", &pinned),
            ("a nested repository's tag", &nested),
            ("a kept prefix", &kept),
        ] {
            assert!(store.find_blob(&hex(d)).is_some(), "{what} was swept");
        }

        // With a retention, the idle tag goes too, and nothing outside the scope.
        let GcOutcome::Done(r) = store
            .gc_with(&GcPolicy {
                retention: Some(DAY),
                ..policy
            })
            .unwrap()
        else {
            panic!("the lock was free");
        };
        assert_eq!(r.tags_dropped, 1);
        assert!(store.find_blob(&hex(&idle)).is_none());
        for d in [&other, &pinned, &nested, &kept] {
            assert!(store.find_blob(&hex(d)).is_some());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What changes while the pass plans, with no exclusive lock held, is honoured when it acts:
    /// a tag used since keeps the drop it was planned for from happening, and a tag pointed at a
    /// manifest the plan did not mark keeps that manifest's chunks. The longest exclusive spell
    /// is reported.
    #[test]
    fn gc_honours_what_changes_while_it_plans() {
        let dir =
            std::env::temp_dir().join(format!("vk-regserve-gcbetween-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let used = store.put_blob(&[21u8; 4096]).unwrap();
        let repointed = store.put_blob(&[22u8; 4096]).unwrap();
        let orphan = store.put_blob(&[23u8; 4096]).unwrap();
        store
            .put_manifest(
                "repo",
                "used",
                DEFAULT_MANIFEST_TYPE,
                &manifest_body(&used, &[&used]),
            )
            .unwrap();
        // A manifest nothing tags: the plan marks nothing of it.
        let body = manifest_body(&repointed, &[&repointed]);
        let pin = format!("sha256:{}", sha256_hex_raw(&body));
        store
            .put_manifest("repo", &pin, DEFAULT_MANIFEST_TYPE, &body)
            .unwrap();
        store
            .put_manifest(
                "repo",
                "moving",
                DEFAULT_MANIFEST_TYPE,
                &manifest_body(&orphan, &[&orphan]),
            )
            .unwrap();
        backdate_all(&dir, SystemTime::now() - DAY * 100);

        let once = Cell::new(false);
        let between = |_: Phase| {
            if once.replace(true) {
                return;
            }
            // Used since the plan read it.
            touch(&store.tag_path("repo", "used"));
            // Pointed at the old, unmarked manifest, which a tag write alone does not touch.
            let tag = store.tag_path("repo", "moving");
            std::fs::write(&tag, &pin).unwrap();
            std::fs::File::open(&tag)
                .unwrap()
                .set_modified(SystemTime::now() - DAY * 100)
                .unwrap();
        };
        let GcOutcome::Done(r) = store
            .gc_between(&GcPolicy::new(DAY * 30, DAY, false), &between)
            .unwrap()
        else {
            panic!("the lock was free");
        };
        assert!(
            store.tag_path("repo", "used").exists(),
            "a tag used meanwhile stays"
        );
        assert!(store.find_blob(&hex(&used)).is_some());
        assert!(
            store.find_blob(&hex(&repointed)).is_some(),
            "what a tag names now is kept, though the plan never marked it"
        );
        assert!(
            store.find_blob(&hex(&orphan)).is_none(),
            "what it named before goes"
        );
        assert!(r.longest_hold > Duration::ZERO);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store for the size-phase cases: manifests over incompressible chunks, everything dated
    /// far past any window but what a case dates again.
    struct CapStore {
        dir: PathBuf,
        store: Store,
    }

    impl CapStore {
        fn new(name: &str) -> CapStore {
            let dir =
                std::env::temp_dir().join(format!("vk-regserve-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let store = Store::new(dir.clone()).unwrap();
            CapStore { dir, store }
        }
        fn chunk(&self, seed: u8) -> String {
            self.store.put_blob(&noise(seed, 64 * 1024)).unwrap()
        }
        /// Tag `repo:tag` (a `sha256:` tag pushes by digest) over `layers`, the first its config.
        fn tag(&self, repo: &str, tag: &str, layers: &[&str]) -> String {
            let body = manifest_body(layers[0], layers);
            let tag = if tag == "@" {
                format!("sha256:{}", sha256_hex_raw(&body))
            } else {
                tag.to_string()
            };
            self.store
                .put_manifest(repo, &tag, DEFAULT_MANIFEST_TYPE, &body)
                .unwrap()
        }
        fn age_all(&self) {
            backdate_all(&self.dir, SystemTime::now() - DAY * 100);
        }
        fn used(&self, repo: &str, tag: &str, ago: Duration) {
            std::fs::File::open(self.store.tag_path(repo, tag))
                .unwrap()
                .set_modified(SystemTime::now() - ago)
                .unwrap();
        }
        fn has(&self, digest: &str) -> bool {
            self.store.find_blob(&hex(digest)).is_some()
        }
    }

    impl Drop for CapStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// What changes between the spells of a pass, one item each under test, is honoured: a
    /// dangling tag's manifest pushed meanwhile keeps its chunk; a tag re-pointed, a manifest
    /// pushed by digest alone and a lease taken before the sweep keep theirs; and what the last
    /// spell would remove, sidecar or marker, is checked again in it.
    #[test]
    fn gc_honours_what_changes_between_its_spells() {
        let c = CapStore::new("gcspells");
        let (dangling, repointed, pinned, leased, gone, redone) = (
            c.chunk(1),
            c.chunk(2),
            c.chunk(3),
            c.chunk(4),
            c.chunk(5),
            c.chunk(6),
        );
        // A tag naming a manifest the store does not have yet.
        let body = manifest_body(&dangling, &[&dangling]);
        let missing = format!("sha256:{}", sha256_hex_raw(&body));
        let tag = c.store.tag_path("repo", "dangling");
        std::fs::create_dir_all(tag.parent().unwrap()).unwrap();
        std::fs::write(&tag, &missing).unwrap();
        // Manifests no tag names, over chunks nothing marks.
        let repointed_body = manifest_body(&repointed, &[&repointed]);
        let repointed_manifest = format!("sha256:{}", sha256_hex_raw(&repointed_body));
        c.store.put_blob(&repointed_body).unwrap();
        let pinned_body = manifest_body(&pinned, &[&pinned]);
        // An idle tag the pass drops, whose manifest the last spell finds pushed again.
        let redone_manifest = c.tag("repo", "redone", &[&redone]);
        // Its membership in another repository, which the pass would drop with the blob.
        let marker = c.store.repo_blob_path("other", &hex(&redone_manifest));
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, b"").unwrap();
        c.tag("repo", "moving", &[&gone]);
        c.age_all();
        c.used("repo", "dangling", Duration::ZERO);
        c.used("repo", "moving", Duration::ZERO);

        let lease = std::cell::RefCell::new(None);
        let between = |phase: Phase| match phase {
            Phase::Drops => {
                // Pushed now, as a blob alone: no sidecar, no tag write.
                c.store.put_blob(&body).unwrap();
            }
            Phase::Sweep if lease.borrow().is_none() => {
                let tag = c.store.tag_path("repo", "moving");
                std::fs::write(&tag, &repointed_manifest).unwrap();
                c.store
                    .put_manifest(
                        "repo",
                        &format!("sha256:{}", sha256_hex_raw(&pinned_body)),
                        DEFAULT_MANIFEST_TYPE,
                        &pinned_body,
                    )
                    .unwrap();
                let held = c.store.lock_shared().unwrap();
                let mut l = c.store.lease(&held).unwrap();
                l.add(&held, [hex(&leased).as_str()]).unwrap();
                *lease.borrow_mut() = Some(l);
            }
            Phase::Sweep => {}
            Phase::Last => {
                if c.store.find_blob(&hex(&redone_manifest)).is_none() {
                    c.tag("repo", "@", &[&redone]);
                }
            }
        };
        let policy = GcPolicy::new(DAY * 30, DAY, false);
        let GcOutcome::Done(r) = c.store.gc_between(&policy, &between).unwrap() else {
            panic!("the lock was free");
        };
        assert!(!r.incomplete);
        assert!(
            c.has(&dangling),
            "a dangling tag's manifest, pushed meanwhile"
        );
        assert!(c.has(&repointed), "what a tag re-pointed meanwhile names");
        assert!(
            c.has(&pinned),
            "what a manifest pushed by digest meanwhile names"
        );
        assert!(
            c.has(&leased) && r.blobs_leased == 1,
            "what a lease taken meanwhile names"
        );
        // A mark only grows within a pass: what the tag named when planned is left to the next.
        assert!(c.has(&gone));
        assert!(
            c.store.find_blob(&hex(&redone_manifest)).is_some()
                && std::fs::read_dir(c.dir.join("repos/repo/manifests"))
                    .unwrap()
                    .flatten()
                    .any(|e| e.file_name() == hex(&redone_manifest).as_str()),
            "a manifest pushed again before the last spell keeps its sidecar"
        );
        assert!(
            marker.exists(),
            "a blob pushed again before the last spell keeps its markers"
        );
        drop(lease);
    }

    /// A dry run counts a tag it drops as gone in every later spell, though the tag is still
    /// there and its dir is read again; so it counts the blobs that only that tag named.
    #[test]
    fn a_dry_run_counts_its_dropped_tags_as_gone_throughout() {
        let c = CapStore::new("gcdrygone");
        let old = c.chunk(1);
        c.tag("repo", "old", &[&old]);
        c.age_all();
        let other = c.chunk(2);
        let between = |phase: Phase| {
            if phase == Phase::Sweep {
                // Another tag written: the dir is read again in the next spell.
                c.tag("repo", "new", &[&other]);
            }
        };
        let GcOutcome::Done(r) = c
            .store
            .gc_between(&GcPolicy::new(DAY * 30, DAY, true), &between)
            .unwrap()
        else {
            panic!("the lock was free");
        };
        assert_eq!(r.tags_dropped, 1);
        assert_eq!(r.blobs_dropped, 2, "the dropped tag's manifest and chunk");
        assert!(c.has(&old), "a dry run removes nothing");
    }

    /// Under [`Wait::Try`], a spell that cannot be had within its patience ends the pass
    /// partway: what was done stays done, the rest is left, and the report says so.
    #[test]
    fn a_try_pass_finishes_partway_when_the_lock_stays_held() {
        let c = CapStore::new("gctry");
        let chunks: Vec<String> = (1..=4).map(|seed| c.chunk(seed)).collect();
        for (n, chunk) in chunks.iter().enumerate() {
            c.tag("repo", &format!("t{n}"), &[chunk]);
        }
        c.age_all();
        let held = std::cell::RefCell::new(None);
        let sweeps = Cell::new(0);
        let between = |phase: Phase| {
            if phase == Phase::Sweep {
                sweeps.set(sweeps.get() + 1);
                if sweeps.get() == 2 {
                    *held.borrow_mut() = Some(c.store.lock_shared().unwrap());
                }
            }
        };
        let policy = GcPolicy {
            wait: Wait::Try,
            ..GcPolicy::new(DAY * 30, DAY, false)
        };
        let GcOutcome::Done(r) = c.store.gc_between(&policy, &between).unwrap() else {
            panic!("the first spells were free");
        };
        assert!(r.incomplete);
        assert_eq!(r.tags_dropped, 4);
        assert_eq!(
            r.blobs_dropped, 1,
            "one spell of one blob before the lock was held"
        );
        drop(held);
    }

    /// What the size phase drops a tag for and what it frees: nothing a fresh sidecar, another
    /// repository's manifest — tagged or pushed by digest alone — or a lease keeps, and a chunk
    /// two dropped tags name only once both are gone.
    #[test]
    fn gc_caps_around_what_other_roots_keep() {
        let c = CapStore::new("gccaproots");
        let (fresh, pin, shared, leased, twin) =
            (c.chunk(1), c.chunk(2), c.chunk(3), c.chunk(4), c.chunk(5));
        let fresh_manifest = c.tag("build-cache", "fresh", &[&fresh]);
        c.tag("mine", "@", &[&pin]);
        let child = c.tag("build-cache", "@", &[&shared]);
        c.tag("mine", "m", &[&shared]);
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{ "mediaType": DEFAULT_MANIFEST_TYPE, "digest": child, "size": 1 }],
        })
        .to_string()
        .into_bytes();
        c.store
            .put_manifest(
                "build-cache",
                "idx",
                "application/vnd.oci.image.index.v1+json",
                &index,
            )
            .unwrap();
        c.tag("build-cache", "leased", &[&leased]);
        c.tag("build-cache", "twin-a", &[&twin]);
        c.tag("build-cache", "twin-b", &[&twin]);
        let lease = {
            let held = c.store.lock_shared().unwrap();
            let mut lease = c.store.lease(&held).unwrap();
            lease.add(&held, [hex(&leased).as_str()]).unwrap();
            lease
        };
        c.age_all();
        touch(&c.store.find_blob(&hex(&fresh_manifest)).unwrap().0);

        let policy = GcPolicy {
            grace: Duration::from_secs(3600),
            min_age: Duration::from_secs(3600),
            ..cap_policy(Some(0), false)
        };
        let r = done(c.store.gc_with(&policy).unwrap());
        assert_eq!(r.tags_capped, 5, "fresh, idx, leased, twin-a, twin-b");
        assert!(c.has(&fresh), "a fresh manifest's sidecar keeps it");
        assert!(c.has(&pin), "another repository's digest push is kept");
        assert!(
            c.has(&shared),
            "an index child another repository tags is kept"
        );
        assert!(
            c.has(&leased) && r.blobs_leased == 1,
            "a leased chunk is kept"
        );
        assert!(
            !c.has(&twin),
            "a chunk two dropped tags named goes with both"
        );
        assert_eq!(
            r.bytes_after,
            Some(r.bytes_before.unwrap() - r.bytes_freed),
            "the sweep says what is left"
        );
        drop(lease);
    }

    /// The edges of the size phase: both storage forms of a blob freed and counted, a tag aged
    /// out counted as dropped and not capped, the floor's boundary, an annotated expiry with no
    /// retention, a byte cap and a free target together, and the scope's repository exactly.
    #[test]
    fn gc_size_phase_edges() {
        let c = CapStore::new("gccapedges");
        let (old, both, mid, young, expiring, nested) = (
            c.chunk(1),
            c.chunk(2),
            c.chunk(3),
            c.chunk(4),
            c.chunk(5),
            c.chunk(6),
        );
        c.tag("build-cache", "old", &[&old]);
        c.tag("build-cache", "both", &[&both]);
        c.tag("build-cache", "mid", &[&mid]);
        c.tag("build-cache", "young", &[&young]);
        let mut body: serde_json::Value =
            serde_json::from_slice(&manifest_body(&expiring, &[&expiring])).unwrap();
        body["annotations"] = serde_json::json!({ EXPIRES_ANNOTATION: "1" });
        c.store
            .put_manifest(
                "build-cache",
                "expiring",
                DEFAULT_MANIFEST_TYPE,
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
        c.tag("build-cache/x", "nested", &[&nested]);
        // `both` stored in both forms as well.
        std::fs::write(c.dir.join("blobs/zstd").join(hex(&both)), vec![1u8; 1000]).unwrap();
        c.age_all();
        c.used("build-cache", "old", DAY * 40);
        c.used("build-cache", "both", DAY * 9);
        c.used("build-cache", "mid", DAY + Duration::from_secs(60));
        c.used("build-cache", "young", DAY - Duration::from_secs(60));

        assert!(
            c.store
                .gc_with(&GcPolicy {
                    repository: Some("./build-cache".into()),
                    ..cap_policy(None, true)
                })
                .is_err(),
            "a scope that names no repository is refused"
        );

        // No retention: only the annotated expiry goes.
        let r = done(c.store.gc_with(&cap_policy(None, false)).unwrap());
        assert_eq!((r.tags_dropped, r.tags_capped), (1, 0));
        assert!(!c.has(&expiring) && c.has(&old));

        // Retention takes `old`; a free target the age phase alone does not meet then takes
        // `both`, whose two forms it counts, and stops before `mid`.
        let r = done(
            c.store
                .gc_with(&GcPolicy {
                    retention: Some(DAY * 30),
                    free_bytes: Some(2 * 64 * 1024),
                    ..cap_policy(None, false)
                })
                .unwrap(),
        );
        assert_eq!(
            (r.tags_dropped, r.tags_capped),
            (1, 1),
            "old by age, both by size"
        );
        assert!(!c.has(&old) && !c.has(&both) && c.has(&mid));
        assert!(!c.dir.join("blobs/zstd").join(hex(&both)).exists());
        assert!(r.bytes_freed >= 2 * 64 * 1024 + 1000, "{}", r.bytes_freed);

        // A cap with a free target already met still caps: `mid`, but not `young`, just inside
        // the floor.
        let r = done(
            c.store
                .gc_with(&GcPolicy {
                    free_bytes: Some(1),
                    ..cap_policy(Some(0), false)
                })
                .unwrap(),
        );
        assert_eq!(r.tags_capped, 1);
        assert!(!c.has(&mid));
        assert!(c.has(&young), "a tag used just inside the floor stays");
        assert!(c.has(&nested), "build-cache/x is another repository");
    }

    /// Idle tags with dangling or oversized manifests, or non-UTF-8 tag files,
    /// follow the retention window and are dropped.
    #[test]
    fn gc_drops_an_idle_tag_without_a_readable_retention() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcnoret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let oversized = store.put_blob(&vec![b' '; MAX_MANIFEST_BYTES + 1]).unwrap();
        let tags: [(&str, Vec<u8>); 3] = [
            (
                "dangling",
                format!("sha256:{}", "ab".repeat(32)).into_bytes(),
            ),
            ("oversized", oversized.into_bytes()),
            ("binary", vec![0xff, 0xfe, 0x00]),
        ];
        for (tag, body) in &tags {
            let path = store.tag_path("repo", tag);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body).unwrap();
        }
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        let report = store.gc(DAY * 30, DAY, false).unwrap();
        assert_eq!(report.tags_dropped, 3);
        for (tag, _) in &tags {
            assert!(!store.tag_path("repo", tag).exists(), "{tag}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tag whose manifest blob is there but cannot be read aborts the pass and stays,
    /// as does its blob: that manifest might be the one keeping the tag.
    #[test]
    fn gc_aborts_on_an_unreadable_manifest() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcbad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let bad = "cd".repeat(32);
        let blob = store.zstd_blob_path(&bad);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"not a zstd frame").unwrap();
        let tag = store.tag_path("repo", "bad");
        std::fs::create_dir_all(tag.parent().unwrap()).unwrap();
        std::fs::write(&tag, format!("sha256:{bad}")).unwrap();
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        let Err(err) = store.gc(DAY * 30, DAY, false) else {
            panic!("gc must refuse an unreadable manifest");
        };
        assert!(format!("{err:#}").contains("refusing to drop"), "{err:#}");
        assert!(tag.exists());
        assert!(blob.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Keep wins over an expiry, and an expiry that does not parse as a plain `u64` — or
    /// lies past what `SystemTime` holds — never panics.
    #[test]
    fn retention_of_manifest_edge_cases() {
        let of = |annotations: serde_json::Value| {
            Retention::of_manifest(
                &serde_json::to_vec(&serde_json::json!({ "annotations": annotations })).unwrap(),
            )
        };
        assert_eq!(
            of(
                serde_json::json!({ RETENTION_ANNOTATION: RETENTION_KEEP, EXPIRES_ANNOTATION: "1" })
            ),
            Retention::Keep
        );
        assert_eq!(
            of(serde_json::json!({ EXPIRES_ANNOTATION: "60" })),
            Retention::Until(SystemTime::UNIX_EPOCH + Duration::from_secs(60))
        );
        for bad in [" 123", "-1", "+1", "1.5", ""] {
            assert_eq!(
                of(serde_json::json!({ EXPIRES_ANNOTATION: bad })),
                Retention::Idle,
                "{bad:?}"
            );
        }
        assert_eq!(
            of(serde_json::json!({ EXPIRES_ANNOTATION: u64::MAX.to_string() })),
            Retention::Keep
        );
        assert_eq!(Retention::of_manifest(b"not json"), Retention::Idle);
    }

    /// A file put on disk reads back whole under each of its tags, as the raw file the
    /// WebDAV view serves, and carries the retention it was put with.
    #[test]
    fn a_put_file_reads_back_under_each_tag() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-putfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.join("store")).unwrap();
        let src = dir.join("medium.iso");
        let bytes: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &bytes).unwrap();
        let keep = BTreeMap::from([(RETENTION_ANNOTATION.to_string(), RETENTION_KEEP.to_string())]);
        let hex = sha256_hex_raw(&bytes);
        let tags = [("files/sha256", "x"), ("files/iso", "medium.iso")];
        store
            .put_file(&tags, &src, &hex, Some("medium.iso"), &keep)
            .unwrap();
        for (name, tag) in tags {
            let mut f = store.open_file(name, tag).unwrap().unwrap();
            let mut got = Vec::new();
            std::io::Read::read_to_end(&mut f.reader, &mut got).unwrap();
            assert_eq!(
                (f.sha256.as_str(), f.size, f.title.as_deref()),
                (hex.as_str(), bytes.len() as u64, Some("medium.iso"))
            );
            assert_eq!(got, bytes);
            let (_, manifest, _) = store.get_manifest(name, tag).unwrap().unwrap();
            assert_eq!(Retention::of_manifest(&manifest), Retention::Keep);
        }
        assert!(store.open_file("files/iso", "absent").unwrap().is_none());
        // A file that no longer hashes as the caller said is refused, and no tag names it.
        let stale = "0".repeat(64);
        assert!(
            store
                .put_file(&[("files/iso", "stale")], &src, &stale, None, &keep)
                .is_err()
        );
        assert!(store.get_manifest("files/iso", "stale").unwrap().is_none());
        assert!(store.find_blob(&stale).is_none());
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

    /// An index may name any blob as a child. One that is not a manifest — a layer, a digest
    /// shaped like a path — neither stops the pass nor is read beyond a manifest's size or
    /// outside the store; what is named and held is kept.
    #[test]
    fn gc_survives_an_index_naming_what_is_not_a_manifest() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcbadidx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // A layer far over a manifest's size, named as a child manifest.
        let layer = store
            .put_blob(&vec![7u8; MAX_MANIFEST_BYTES + 4096])
            .unwrap();
        let stray = store.put_blob(&[9u8; 4096]).unwrap();
        // A manifest outside the store that keeps `stray`, named by a digest that is a path
        // from `blobs/sha256` to it: following it would keep `stray` alive.
        let outside_name = format!("vk-gc-outside-{}", std::process::id());
        let outside = dir.parent().unwrap().join(&outside_name);
        std::fs::write(&outside, manifest_body(&stray, &[&stray])).unwrap();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"mediaType": DEFAULT_MANIFEST_TYPE, "digest": layer, "size": 1},
                {"mediaType": DEFAULT_MANIFEST_TYPE, "digest": format!("sha256:../../../{outside_name}"), "size": 1},
            ],
        })
        .to_string()
        .into_bytes();
        store
            .put_manifest(
                "repo",
                "odd",
                "application/vnd.oci.image.index.v1+json",
                &index,
            )
            .unwrap();

        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.tag_path("repo", "odd"));
        store.gc(DAY * 30, DAY, false).unwrap();
        assert!(
            store.find_blob(&hex(&layer)).is_some(),
            "a named layer is kept"
        );
        assert!(
            store.find_blob(&hex(&stray)).is_none(),
            "the stray is still swept"
        );
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rooted image index keeps its child manifests and everything they reference; an
    /// unreferenced blob idle as long is still swept.
    #[test]
    fn gc_marks_through_an_image_index() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcidx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let config = store.put_blob(b"{}").unwrap();
        let layer = store.put_blob(&[8u8; 4096]).unwrap();
        let stray = store.put_blob(&[9u8; 4096]).unwrap();
        let child = store
            .put_manifest(
                "repo",
                &format!(
                    "sha256:{}",
                    sha256_hex_raw(&manifest_body(&config, &[&layer]))
                ),
                DEFAULT_MANIFEST_TYPE,
                &manifest_body(&config, &[&layer]),
            )
            .unwrap();
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
        let index_digest = store
            .put_manifest(
                "repo",
                "multi",
                "application/vnd.oci.image.index.v1+json",
                &index,
            )
            .unwrap();

        // age everything past retention and grace, then keep only the index's tag live.
        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.tag_path("repo", "multi"));

        store.gc(DAY * 30, DAY, false).unwrap();
        for kept in [&index_digest, &child, &config, &layer] {
            assert!(store.find_blob(&hex(kept)).is_some(), "{kept} was swept");
        }
        assert!(
            store.find_blob(&hex(&stray)).is_none(),
            "the stray survived"
        );
        assert!(store.get_manifest("repo", &child).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An index may list another index: the mark, and `status`, follow the nesting down to the
    /// leaf manifest's blobs.
    #[test]
    fn gc_and_stats_follow_an_index_of_an_index() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcnested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let config = store.put_blob(b"{}").unwrap();
        let layer = store.put_blob(&[8u8; 4096]).unwrap();
        let stray = store.put_blob(&[9u8; 4096]).unwrap();
        let by_digest = |body: &[u8], media: &str| {
            store
                .put_manifest(
                    "repo",
                    &format!("sha256:{}", sha256_hex_raw(body)),
                    media,
                    body,
                )
                .unwrap()
        };
        let index_of = |child: &str| {
            serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{"mediaType": DEFAULT_MANIFEST_TYPE, "digest": child, "size": 1}],
            })
            .to_string()
            .into_bytes()
        };
        let leaf = by_digest(&manifest_body(&config, &[&layer]), DEFAULT_MANIFEST_TYPE);
        let inner = by_digest(&index_of(&leaf), "application/vnd.oci.image.index.v1+json");
        store
            .put_manifest(
                "repo",
                "nested",
                "application/vnd.oci.image.index.v1+json",
                &index_of(&inner),
            )
            .unwrap();

        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.tag_path("repo", "nested"));
        store.gc(DAY * 30, DAY, false).unwrap();
        for kept in [&inner, &leaf, &config, &layer] {
            assert!(store.find_blob(&hex(kept)).is_some(), "{kept} was swept");
        }
        assert!(
            store.find_blob(&hex(&stray)).is_none(),
            "the stray survived"
        );

        let s = store.stats().unwrap();
        assert_eq!(s.referenced_ondisk, s.identity_bytes + s.zstd_bytes);
        assert_eq!(s.repos[0].logical_bytes, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tagged manifest that a tagged index also lists is read as the root it is, however
    /// the mark reaches it first: as a child it would be capped at a manifest's size, and
    /// one larger (stored before that cap, or through the relay) would lose its layers.
    #[test]
    fn gc_reads_a_root_listed_by_an_index_as_a_root() {
        let dir =
            std::env::temp_dir().join(format!("vk-regserve-gcidxroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let config = store.put_blob(b"{}").unwrap();
        let layer = store.put_blob(&[8u8; 4096]).unwrap();
        let mut big: serde_json::Value =
            serde_json::from_slice(&manifest_body(&config, &[&layer])).unwrap();
        big["annotations"] = serde_json::json!({ "pad": "x".repeat(MAX_MANIFEST_BYTES) });
        let big = big.to_string().into_bytes();
        let child = store
            .put_manifest("repo", "big", DEFAULT_MANIFEST_TYPE, &big)
            .unwrap();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{"mediaType": DEFAULT_MANIFEST_TYPE, "digest": child, "size": 1}],
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

        backdate_all(&dir, SystemTime::now() - DAY * 100);
        touch(&store.tag_path("repo", "big"));
        touch(&store.tag_path("repo", "multi"));
        // The roots' visiting order follows a randomly seeded HashSet: repeat until the
        // index has, with overwhelming likelihood, come first at least once.
        for _ in 0..16 {
            store.gc(DAY * 30, DAY, false).unwrap();
            assert!(
                store.find_blob(&hex(&layer)).is_some(),
                "the tagged manifest's layer was swept"
            );
        }
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

    /// Removing an empty repository does not wait for the store lock: while a write holds
    /// it — as a WebDAV `PUT` holds it, across the membership markers and the tag — the
    /// removal is `Busy`, and once the write lands the repository is no longer empty.
    #[test]
    fn removing_an_empty_repo_yields_to_a_write_and_keeps_it() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-rmrepo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let name = "files/x/a";
        store.create_repo(name).unwrap();

        let write = store.lock_shared().unwrap();
        assert_eq!(
            store.remove_empty_repo(name, DEFAULT_GC_GRACE).unwrap(),
            RepoRemoval::Busy,
            "a write holds the lock"
        );
        let hex = store.put_blob(b"payload").unwrap();
        let hex = hex.trim_start_matches("sha256:");
        store.put_raw_file(name, "k", hex, 7, None).unwrap();
        drop(write);

        assert_eq!(
            store.remove_empty_repo(name, DEFAULT_GC_GRACE).unwrap(),
            RepoRemoval::HasMembers,
            "the repository now holds a tag"
        );
        assert!(store.tag_path(name, "k").is_file());
        assert!(store.repo_blob_path(name, hex).is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only a directory holding nothing but leftovers goes, and only what the listing saw
    /// goes with it: a stray entry or a nested directory with a name no repository could
    /// have keeps it whole, and so, until the grace window has passed, do another kind of
    /// manifest and an unaccounted membership marker.
    #[test]
    fn removing_a_repo_refuses_anything_it_does_not_recognise() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-rmstrict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let repo = |n: &str| dir.join("repos").join(n);

        // A deleted raw file's sidecar and markers are all that is left: removed.
        let hex = store.put_blob(b"payload").unwrap();
        let hex = hex.trim_start_matches("sha256:").to_string();
        store
            .put_raw_file("files/done", "k", &hex, 7, None)
            .unwrap();
        assert!(store.delete_tag("files/done", "k").unwrap());
        assert_eq!(
            store
                .remove_empty_repo("files/done", DEFAULT_GC_GRACE)
                .unwrap(),
            RepoRemoval::Removed
        );
        assert!(!repo("files/done").exists());

        // Entries that are not layout: a stray file, and a nested directory `repo_children`
        // would not list.
        store.create_repo("files/stray").unwrap();
        std::fs::write(repo("files/stray/notes"), b"x").unwrap();
        store.create_repo("files/nested").unwrap();
        std::fs::create_dir_all(repo("files/nested/bad name/tags")).unwrap();
        std::fs::write(repo("files/nested/bad name/tags/k"), b"x").unwrap();
        for name in ["files/stray", "files/nested"] {
            assert_eq!(
                store.remove_empty_repo(name, DEFAULT_GC_GRACE).unwrap(),
                RepoRemoval::HasMembers,
                "{name}"
            );
        }
        assert!(repo("files/stray/notes").is_file());
        assert!(repo("files/nested/bad name/tags/k").is_file());

        // A digest-pinned manifest of another kind: something a pull by digest still wants.
        store
            .put_manifest(
                "files/pinned",
                &format!("sha256:{}", sha256_hex_raw(br#"{"schemaVersion":2}"#)),
                DEFAULT_MANIFEST_TYPE,
                br#"{"schemaVersion":2}"#,
            )
            .unwrap();
        // A membership marker with no manifest here: a `/v2/` push that has not reached
        // its manifest yet.
        store.create_repo("files/pushing").unwrap();
        store.record_blob("files/pushing", &hex).unwrap();
        for name in ["files/pinned", "files/pushing"] {
            assert_eq!(
                store.remove_empty_repo(name, DEFAULT_GC_GRACE).unwrap(),
                RepoRemoval::HasRecords,
                "{name}"
            );
        }
        assert!(store.repo_blob_path("files/pushing", &hex).is_file());
        assert!(repo("files/pinned/manifests").is_dir());

        // Past the grace window neither is still wanted: the pin is no gc root, and the
        // marker no push in flight. This is also what a deleted object leaves once the gc
        // has swept its manifest while its layer lives on elsewhere: a marker nothing here
        // accounts for.
        let old = SystemTime::now() - 2 * DEFAULT_GC_GRACE;
        let age = |p: PathBuf| {
            std::fs::File::open(p).unwrap().set_modified(old).unwrap();
        };
        age(store.blob_path(&sha256_hex_raw(br#"{"schemaVersion":2}"#)));
        age(store.repo_blob_path("files/pushing", &hex));
        for name in ["files/pinned", "files/pushing"] {
            assert_eq!(
                store.remove_empty_repo(name, DEFAULT_GC_GRACE).unwrap(),
                RepoRemoval::Removed,
                "{name}"
            );
            assert!(!repo(name).exists(), "{name}");
        }
        assert!(
            store.has_blob(&hex),
            "only the records went, not the content"
        );
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
    /// one whose bytes the same pass keeps. Only the mark's index traversal finds live
    /// children, so dropping their sidecars before marking would leave them permanently
    /// unreadable through their repository.
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
        // reaches it) with no grace on the blobs (so the children are sweep candidates, and
        // only the mark's walk through the index keeps them).
        store
            .gc(Duration::from_secs(3600), Duration::ZERO, false)
            .unwrap();
        for hex in &children {
            assert!(
                store.repo_has_manifest("team-a/app", hex),
                "a kept child must keep its membership"
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

    fn claims(grants: &[(&str, &str)]) -> vk_hub_proto::token::Claims {
        vk_hub_proto::token::Claims {
            kid: "00112233445566778899aabbccddeeff".into(),
            aud: "00112233445566778899aabbccddeeff".into(),
            sub: "job:j".into(),
            jti: "00112233445566778899aabbccddeeff".into(),
            pipeline: None,
            iat: 1,
            exp: 2,
            grants: grants
                .iter()
                .map(|(prefix, rights)| vk_hub_proto::token::Grant {
                    prefix: (*prefix).into(),
                    read: rights.contains('r'),
                    write: rights.contains('w'),
                    lock: rights.contains('l'),
                })
                .collect(),
        }
    }

    /// A token reads and writes only under its grants, plain files included, and mounts
    /// only what it could already read there.
    #[test]
    fn a_token_reaches_only_its_grants() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let c = claims(&[("p/gl/42", "rw"), ("images", "r")]);
        let authz = Authz::Token(&c);
        assert!(authz.may(accounts::Action::Write, "p/gl/42/app"));
        assert!(authz.may(accounts::Action::Read, "files/p/gl/42/x"));
        assert!(authz.may(accounts::Action::Read, "images/debian"));
        assert!(!authz.may(accounts::Action::Write, "images/debian"));
        assert!(!authz.may(accounts::Action::Read, "p/gl/43"));
        assert!(authorize_or_forbidden(&authz, accounts::Action::Write, "other").is_some());

        let layer = store.put_blob(b"another project's layer").unwrap();
        let hex = layer.trim_start_matches("sha256:").to_string();
        store.record_blob("p/gl/43/app", &hex).unwrap();
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{layer}","size":23}},"layers":[]}}"#
        );
        let outcome =
            authorize_and_mount_manifest_blobs(&authz, &store, "p/gl/42/app", manifest.as_bytes())
                .unwrap();
        assert!(matches!(outcome, Mount::Unreadable(h) if h == hex));
        store.record_blob("images/debian", &hex).unwrap();
        let outcome =
            authorize_and_mount_manifest_blobs(&authz, &store, "p/gl/42/app", manifest.as_bytes())
                .unwrap();
        assert!(matches!(outcome, Mount::Done));
        assert!(store.repo_has_blob("p/gl/42/app", &hex));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A prefix's window drops its idle tags well inside the store-wide one, and holds a far
    /// `expires` annotation to itself, and a `keep` too under a window the config sets; under
    /// one the hub added, `keep` and a far `expires` hold, and a past `expires` does not.
    /// Tags elsewhere keep the store's rules.
    #[test]
    fn gc_applies_a_prefix_window() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-gcprefix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let keep =
            format!(r#"{{"schemaVersion":2,"annotations":{{"{RETENTION_ANNOTATION}":"keep"}}}}"#);
        let far = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 365 * 86_400;
        let expires =
            format!(r#"{{"schemaVersion":2,"annotations":{{"{EXPIRES_ANNOTATION}":"{far}"}}}}"#);
        let expired =
            format!(r#"{{"schemaVersion":2,"annotations":{{"{EXPIRES_ANNOTATION}":"1"}}}}"#);
        let plain = r#"{"schemaVersion":2}"#;
        for (repo, body) in [
            ("ci-pipeline/gl/1/7/cache", plain),
            ("ci-pipeline/gl/1/7/kept", keep.as_str()),
            ("ci-pipeline/gl/1/7/expires", expires.as_str()),
            ("files/ci-pipeline/gl/1/7/f", plain),
            ("team/cache", plain),
            ("team/kept", keep.as_str()),
            ("team/expires", expires.as_str()),
            ("team/expired", expired.as_str()),
            ("images/debian", plain),
            ("images/kept", keep.as_str()),
        ] {
            store
                .put_manifest(repo, "t", DEFAULT_MANIFEST_TYPE, body.as_bytes())
                .unwrap();
            let tag = dir.join("repos").join(repo).join("tags").join("t");
            let old = SystemTime::now() - Duration::from_secs(3 * 86_400);
            std::fs::File::options()
                .write(true)
                .open(&tag)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        let window = |prefix: &str, keep_holds| PrefixWindow {
            prefix: prefix.into(),
            window: Duration::from_secs(2 * 86_400),
            keep_holds,
        };
        store.set_prefix_windows(vec![window("ci-pipeline", false), window("team", true)]);
        let report = store
            .gc(
                Duration::from_secs(30 * 86_400),
                Duration::from_secs(86_400),
                false,
            )
            .unwrap();
        assert_eq!(report.tags_dropped, 6);
        let tag = |repo: &str| dir.join("repos").join(repo).join("tags/t").exists();
        assert!(!tag("ci-pipeline/gl/1/7/cache"));
        assert!(
            !tag("ci-pipeline/gl/1/7/kept"),
            "keep holds only within the config's window"
        );
        assert!(
            !tag("ci-pipeline/gl/1/7/expires"),
            "expires holds only within the window"
        );
        assert!(!tag("files/ci-pipeline/gl/1/7/f"));
        assert!(!tag("team/cache"));
        assert!(tag("team/kept"), "keep holds under the hub's window");
        assert!(tag("team/expires"), "so does a far expires");
        assert!(!tag("team/expired"), "but not a past one");
        assert!(tag("images/debian"));
        assert!(tag("images/kept"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Under a [`GcPolicy`], a prefix's window replaces the policy's retention while age
    /// removal is on, and does nothing when it is off; the size phase may drop a tag a window
    /// governs, `keep` or not, as it may any tag only age keeps, but never one kept elsewhere
    /// or under a window the hub set, where `keep` holds.
    #[test]
    fn a_prefix_window_applies_under_a_gc_policy_and_its_size_phase() {
        let dir =
            std::env::temp_dir().join(format!("vk-regserve-gcprefixpol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let keep =
            format!(r#"{{"schemaVersion":2,"annotations":{{"{RETENTION_ANNOTATION}":"keep"}}}}"#);
        let plain = r#"{"schemaVersion":2}"#;
        let put = |repo: &str, body: &str, days: u64| {
            store
                .put_manifest(repo, "t", DEFAULT_MANIFEST_TYPE, body.as_bytes())
                .unwrap();
            let tag = dir.join("repos").join(repo).join("tags").join("t");
            let old = SystemTime::now() - Duration::from_secs(days * 86_400);
            std::fs::File::options()
                .write(true)
                .open(&tag)
                .unwrap()
                .set_modified(old)
                .unwrap();
        };
        let tag = |repo: &str| dir.join("repos").join(repo).join("tags/t").exists();
        store.set_prefix_windows(vec![
            PrefixWindow {
                prefix: "ci-pipeline".into(),
                window: Duration::from_secs(2 * 86_400),
                keep_holds: false,
            },
            PrefixWindow {
                prefix: "hubbed".into(),
                window: Duration::from_secs(2 * 86_400),
                keep_holds: true,
            },
        ]);
        let policy = |retention: Option<Duration>, max_bytes: Option<u64>| GcPolicy {
            retention,
            grace: Duration::from_secs(86_400),
            repository: None,
            keep_prefixes: Vec::new(),
            max_bytes,
            free_bytes: None,
            min_age: Duration::from_secs(86_400),
            dry_run: false,
            wait: Wait::Block,
            lower_planning: None,
        };

        put("ci-pipeline/gl/1/7/aged", plain, 3);
        // Age removal off: the window drops nothing.
        let report = done(store.gc_with(&policy(None, None)).unwrap());
        assert_eq!(report.tags_dropped, 0);
        assert!(tag("ci-pipeline/gl/1/7/aged"));
        // On: the window, not the policy's 30 days, decides.
        let report = done(
            store
                .gc_with(&policy(Some(Duration::from_secs(30 * 86_400)), None))
                .unwrap(),
        );
        assert_eq!(report.tags_dropped, 1);
        assert!(!tag("ci-pipeline/gl/1/7/aged"));

        // The size phase: a `keep` under the config's window may go; one under the hub's
        // window, or outside any, stays.
        put("ci-pipeline/gl/1/8/kept", keep.as_str(), 3);
        put("hubbed/kept", keep.as_str(), 3);
        put("images/kept", keep.as_str(), 3);
        let report = done(store.gc_with(&policy(None, Some(0))).unwrap());
        assert_eq!(report.tags_capped, 1);
        assert!(!tag("ci-pipeline/gl/1/8/kept"));
        assert!(tag("hubbed/kept"));
        assert!(tag("images/kept"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_most_specific_prefix_window_wins() {
        let w = |prefix: &str, days: u64| PrefixWindow {
            prefix: prefix.into(),
            window: Duration::from_secs(days),
            keep_holds: false,
        };
        let windows = [w("p", 1), w("p/gl/42", 9)];
        let found = |name: &str| prefix_window(&windows, name).map(|w| w.window.as_secs());
        assert_eq!(found("p/gl/42/app"), Some(9));
        assert_eq!(found("p/gl/4"), Some(1));
        assert_eq!(found("files/p/x"), Some(1));
        assert_eq!(found("px"), None);
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

    /// The repository total dedups a blob shared between two tags, while each per-tag figure
    /// counts that tag's whole footprint — so the per-tag figures overcount the total by
    /// exactly the shared blob, and the total is every distinct blob once.
    #[test]
    fn repo_size_report_dedups_shared_blobs_across_tags() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        // Tiny, so every blob is stored uncompressed and its on-disk size is its byte length.
        let shared = b"the layer both tags reference".as_slice();
        let (cfg_a, cfg_b) = (b"config a".as_slice(), b"config bee is longer".as_slice());
        let dshared = store.put_blob(shared).unwrap();
        let (dca, dcb) = (
            store.put_blob(cfg_a).unwrap(),
            store.put_blob(cfg_b).unwrap(),
        );
        let manifest = |cfg: &str, cfg_len: usize| {
            serde_json::to_vec(&serde_json::json!({
                "mediaType": DEFAULT_MANIFEST_TYPE,
                "config": {"digest": cfg, "size": cfg_len},
                "layers": [{"digest": dshared, "size": shared.len()}],
            }))
            .unwrap()
        };
        let (ma, mb) = (manifest(&dca, cfg_a.len()), manifest(&dcb, cfg_b.len()));
        store
            .put_manifest("repo", "a", DEFAULT_MANIFEST_TYPE, &ma)
            .unwrap();
        store
            .put_manifest("repo", "b", DEFAULT_MANIFEST_TYPE, &mb)
            .unwrap();

        let (per, total) = store.repo_size_report("repo", &["a".into(), "b".into()]);
        let (pa, pb) = (per[0].unwrap(), per[1].unwrap());
        assert_eq!(pa, (ma.len() + cfg_a.len() + shared.len()) as u64);
        assert_eq!(pb, (mb.len() + cfg_b.len() + shared.len()) as u64);
        // Distinct blobs once: both manifests, both configs, the shared layer a single time.
        let distinct = ma.len() + mb.len() + cfg_a.len() + cfg_b.len() + shared.len();
        assert_eq!(total, distinct as u64);
        // The per-tag figures overcount the total by exactly the once-shared layer.
        assert_eq!(pa + pb - total, shared.len() as u64);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sizing a repository must not renew gc retention: `repo_size_report` reads the tag
    /// files without bumping their mtime, unlike a resolve through `get_manifest`.
    #[test]
    fn repo_size_report_does_not_bump_tag_mtime() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-mtime-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        store
            .put_manifest("repo", "v1", DEFAULT_MANIFEST_TYPE, b"{}")
            .unwrap();

        let tag = store.tag_path("repo", "v1");
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        std::fs::File::open(&tag)
            .unwrap()
            .set_modified(old)
            .unwrap();

        store.repo_size_report("repo", &["v1".into()]);
        assert_eq!(std::fs::metadata(&tag).unwrap().modified().unwrap(), old);

        // A resolve, by contrast, does touch it — so the report above genuinely differs.
        store.get_manifest("repo", "v1").unwrap();
        assert!(std::fs::metadata(&tag).unwrap().modified().unwrap() > old);

        let _ = std::fs::remove_dir_all(&dir);
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

    /// A tagged image index's child manifests, and what they reference, count as referenced
    /// in `status` and on `/browse`, as the gc mark keeps them: nothing the gc would keep is
    /// reported as reclaimable.
    #[test]
    fn stats_counts_an_index_child_as_referenced() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-statsidx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let config = store.put_blob(b"{}").unwrap();
        let layer = store.put_blob(&[8u8; 4096]).unwrap();
        let body = manifest_body(&config, &[&layer]);
        let child = store
            .put_manifest(
                "repo",
                &format!("sha256:{}", sha256_hex_raw(&body)),
                DEFAULT_MANIFEST_TYPE,
                &body,
            )
            .unwrap();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{"mediaType": DEFAULT_MANIFEST_TYPE, "digest": child, "size": body.len()}],
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

        let s = store.stats().unwrap();
        assert_eq!(s.referenced_ondisk, s.identity_bytes + s.zstd_bytes);
        assert_eq!(s.logical_naive, (index.len() + body.len() + 1 + 1) as u64);
        assert_eq!(s.repos[0].logical_bytes, 2);
        let (per, total) = store.repo_size_report("repo", &["multi".into()]);
        assert_eq!(per, vec![Some(total)]);
        assert_eq!(total, s.referenced_ondisk);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `status` sizes only what the gc mark would keep: a digest that is not
    /// `sha256:<lowercase hex>` — uppercase, or shaped like a path out of the store — names
    /// nothing here and counts for nothing.
    #[test]
    fn stats_ignores_a_digest_that_names_no_blob() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-statsodd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();

        let layer = store.put_blob(&[8u8; 4096]).unwrap();
        // A file outside the store a path-shaped digest leads to.
        let outside_name = format!("vk-stats-outside-{}", std::process::id());
        let outside = dir.parent().unwrap().join(&outside_name);
        std::fs::write(&outside, [5u8; 8192]).unwrap();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": format!("sha256:../../../{outside_name}"), "size": 1000},
            "layers": [
                {"digest": layer, "size": 1},
                {"digest": layer.to_uppercase().replace("SHA256:", "sha256:"), "size": 2000},
            ],
        })
        .to_string()
        .into_bytes();
        store
            .put_manifest("repo", "odd", DEFAULT_MANIFEST_TYPE, &manifest)
            .unwrap();

        let s = store.stats().unwrap();
        assert_eq!(s.repos[0].logical_bytes, 1);
        assert_eq!(s.logical_naive, manifest.len() as u64 + 1);
        assert_eq!(s.referenced_ondisk, s.identity_bytes + s.zstd_bytes);

        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stats_counts_uncompressed_data_per_completed_stage() {
        let dir = std::env::temp_dir().join(format!("vk-stage-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        // One compressed blob occupies two positions in each image. Both placements
        // count, and two completed stages count the image twice, even if it is identical.
        let digest = store.put_blob(&[1; 100]).unwrap();
        let layer = serde_json::json!({
            "mediaType": "application/vnd.wallix.microvm.ext4.chunk.zstd",
            "digest": digest, "size": 7,
            "annotations": {"vnd.wallix.microvm.chunk.length": "100"}
        });
        let body = serde_json::to_vec(&serde_json::json!({
            "artifactType": "application/vnd.wallix.microvm.bundle",
            "layers": [layer.clone(), layer]
        }))
        .unwrap();
        for i in 0..3 {
            let snap = format!("snap-{i:064x}");
            store
                .put_manifest(BUILD_CACHE_REPO, &snap, DEFAULT_MANIFEST_TYPE, &body)
                .unwrap();
            if i > 0 {
                store
                    .put_manifest(
                        BUILD_CACHE_REPO,
                        &build_stage_tag(&snap).unwrap(),
                        DEFAULT_MANIFEST_TYPE,
                        &body,
                    )
                    .unwrap();
            }
        }
        let s = store.stats().unwrap();
        assert_eq!(s.total_tags, 5);
        assert_eq!(s.completed_stages, 2);
        assert_eq!(s.sized_stages, 2);
        assert_eq!(s.stage_data_bytes, 400);

        let stage_tag = build_stage_tag(&format!("snap-{:064x}", 4)).unwrap();
        for name in ["team/build-cache", "ordinary-images"] {
            store
                .put_manifest(name, &stage_tag, DEFAULT_MANIFEST_TYPE, &body)
                .unwrap();
        }
        let s = store.stats().unwrap();
        assert_eq!(s.completed_stages, 3);
        assert_eq!(s.stage_data_bytes, 600);

        // An unreadable stage remains in the count, so status cannot call a partial
        // sum the total. An ordinary instruction tag never contributed to it.
        let tag = build_stage_tag(&format!("snap-{:064x}", 3)).unwrap();
        store
            .put_manifest(BUILD_CACHE_REPO, &tag, DEFAULT_MANIFEST_TYPE, b"{}")
            .unwrap();
        let s = store.stats().unwrap();
        assert_eq!(s.completed_stages, 4);
        assert_eq!(s.sized_stages, 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stage_data_size_requires_uncompressed_lengths() {
        let mut manifest = serde_json::json!({
            "artifactType": "application/vnd.wallix.microvm.bundle", "layers": []
        });
        let size = |v: &serde_json::Value| stage_data_size(&serde_json::to_vec(v).unwrap());
        assert_eq!(size(&manifest), Some(0));
        manifest["layers"] = serde_json::json!([{
            "mediaType": "application/vnd.wallix.microvm.ext4.chunk",
            "size": 42,
            "annotations": {"vnd.wallix.microvm.chunk.length": "100"}
        }]);
        assert_eq!(size(&manifest), Some(100));
        for length in [serde_json::Value::Null, serde_json::json!("bad")] {
            manifest["layers"][0]["annotations"]["vnd.wallix.microvm.chunk.length"] = length;
            assert_eq!(size(&manifest), None);
        }
        manifest["layers"][0]["annotations"]["vnd.wallix.microvm.chunk.length"] =
            serde_json::json!(u64::MAX.to_string());
        let layer = manifest["layers"][0].clone();
        manifest["layers"] = serde_json::json!([layer.clone(), layer]);
        assert_eq!(size(&manifest), None);
        assert_eq!(stage_data_size(b"not json"), None);
        assert!(build_stage_tag("snap-not-a-hash").is_none());
        assert!(build_stage_tag(&format!("base-{:064x}", 1)).is_none());
    }

    /// What a read-only registry refuses: what writes the store, and nothing else.
    #[test]
    fn store_writes_are_told_apart() {
        let post = Method::POST;
        for write in [
            "/v2/r/blobs/uploads/",
            "/v2/r/manifests/latest",
            "/settings/tags/delete",
            "/upload",
            "/dav/files/f",
        ] {
            assert!(is_store_write(&post, write), "{write}");
        }
        assert!(is_store_write(&Method::DELETE, "/v2/r/manifests/sha256:00"));
        for not in [
            "/lock/k",
            EXISTS_PATH,
            "/login",
            "/logout",
            "/settings/keys",
            "/settings/keys/1/revoke",
            "/settings/captions",
        ] {
            assert!(!is_store_write(&post, not), "{not}");
        }
        assert!(!is_store_write(&Method::GET, "/settings/tags/delete"));
    }
}
