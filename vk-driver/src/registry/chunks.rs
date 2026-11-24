//! Chunk downloads and the buffers a restore reuses.
//!
//! All requests from [`super::client`] use [`ChunkTransport`]. During a [`ChunkGet`], only
//! GETs for the blob or a descriptor alternate offer `Accept-Encoding: zstd`. The registry
//! can then send its stored frame. The transport decodes a zstd response once for oci-client
//! to verify the descriptor digest. The cache keeps the frame, stripping any outer zstd
//! encoding when the digest names the frame itself. Chunk GETs require 200 on success.
//! Other requests and non-2xx responses pass through unchanged.

use std::future::Future;
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use oci_client::manifest::OciDescriptor;
use oci_client::transport::{self, BoxError, EffectiveUrl};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, HeaderValue};

use super::{CDC_MAX, MAX_CHUNK_BLOB, RESTORE_CONCURRENCY};

/// The two sizes of buffer a restore uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// A chunk as stored or sent: at most [`MAX_CHUNK_BLOB`] bytes, plus the byte that detects
    /// an overlong frame.
    Wire,
    /// A decoded chunk: at most [`CDC_MAX`], plus the byte that detects an overlong frame.
    Decoded,
}

impl Class {
    fn cap(self) -> usize {
        match self {
            Class::Wire => MAX_CHUNK_BLOB as usize + 1,
            Class::Decoded => CDC_MAX + 1,
        }
    }
}

/// Buffers reused within one restore, eager or lazy, remote or from a local store. Each
/// class keeps at most [`RESTORE_CONCURRENCY`] idle buffers, none larger than the class
/// allows. Also counts the work done, which tests check.
#[derive(Default)]
pub(super) struct ChunkPool {
    wire: Mutex<Vec<Vec<u8>>>,
    decoded: Mutex<Vec<Vec<u8>>>,
    /// zstd decode attempts.
    decodes: AtomicU64,
    /// Chunk files read from a cache or a store.
    reads: AtomicU64,
}

impl ChunkPool {
    fn idle(&self, class: Class) -> std::sync::MutexGuard<'_, Vec<Vec<u8>>> {
        // A push or pop preserves the list even if the mutex is poisoned.
        match class {
            Class::Wire => &self.wire,
            Class::Decoded => &self.decoded,
        }
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
    }

    /// Borrow an empty buffer of this class, reusing an idle allocation when available.
    pub(super) fn lend(self: &Arc<Self>, class: Class) -> Lent {
        let buf = self.idle(class).pop().unwrap_or_default();
        Lent {
            buf,
            class,
            pool: Arc::clone(self),
        }
    }

    fn give(&self, class: Class, mut buf: Vec<u8>) {
        if !(1..=class.cap()).contains(&buf.capacity()) {
            return;
        }
        buf.clear();
        let mut idle = self.idle(class);
        if idle.len() < RESTORE_CONCURRENCY {
            idle.push(buf);
        }
    }

    fn note_read(&self) {
        self.reads.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(super) fn decodes(&self) -> u64 {
        self.decodes.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn idle_capacities(&self, class: Class) -> Vec<usize> {
        self.idle(class).iter().map(Vec::capacity).collect()
    }

    /// Pass the image offset and raw bytes to `place`. Compressed chunks use a pooled buffer.
    /// The chunk must fit in `total_size` and match its annotated length, at most [`CDC_MAX`].
    pub(super) fn place<T>(
        self: &Arc<Self>,
        layer: &OciDescriptor,
        blob: &[u8],
        compressed: bool,
        total_size: u64,
        place: impl FnOnce(u64, &[u8]) -> Result<T>,
    ) -> Result<T> {
        let (offset, len) = super::chunk_bounds(layer, total_size)?;
        if !compressed {
            check_len(layer, blob.len(), len)?;
            return place(offset, blob);
        }
        let mut decoded = self.lend(Class::Decoded);
        self.decode(blob, len, &mut decoded)
            .with_context(|| format!("zstd-decompressing chunk {}", layer.digest))?;
        place(offset, &decoded)
    }

    /// [`Self::place`] for every layer naming one blob, decoding it at most once.
    pub(super) fn place_each(
        self: &Arc<Self>,
        layers: &[OciDescriptor],
        blob: &[u8],
        compressed: bool,
        total_size: u64,
        mut place: impl FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let Some((first, rest)) = layers.split_first() else {
            return Ok(());
        };
        self.place(first, blob, compressed, total_size, |offset, raw| {
            place(offset, raw)?;
            for layer in rest {
                let (offset, len) = super::chunk_bounds(layer, total_size)?;
                check_len(layer, raw.len(), len)?;
                place(offset, raw)?;
            }
            Ok(())
        })
    }

    /// Decode exactly `len` bytes. The registry supplies both the descriptor and the frame.
    /// Reject a conflicting header size before decoding and read at most one byte past `len`
    /// to bound memory use. A chunk is one frame. For concatenated frames, only the first
    /// header's size is checked.
    pub(super) fn decode(&self, frame: &[u8], len: u64, out: &mut Vec<u8>) -> Result<()> {
        if len > MAX_CHUNK_BLOB {
            bail!("{len} bytes is more than any chunk");
        }
        if let Ok(Some(declared)) = zstd::zstd_safe::get_frame_content_size(frame)
            && declared != len
        {
            bail!("the zstd frame declares {declared} bytes, not {len}");
        }
        self.decodes.fetch_add(1, Ordering::Relaxed);
        out.clear();
        // Reserve the extra byte so detecting an overlong frame needs no reallocation.
        out.reserve_exact(usize::try_from(len)?.saturating_add(1));
        vk_registry::zstd_reader(frame).and_then(|d| d.take(len + 1).read_to_end(out))?;
        if out.len() as u64 != len {
            bail!("the zstd frame decodes to {} bytes, not {len}", out.len());
        }
        Ok(())
    }
}

fn check_len(layer: &OciDescriptor, got: usize, len: u64) -> Result<()> {
    if got as u64 != len {
        bail!(
            "chunk {} holds {got} bytes, not the {len} it claims",
            layer.digest
        );
    }
    Ok(())
}

/// A borrowed buffer offered back to its [`ChunkPool`] on drop.
pub(super) struct Lent {
    buf: Vec<u8>,
    class: Class,
    pool: Arc<ChunkPool>,
}

impl Lent {
    /// Share the buffer without copying. The last [`Bytes`] owner releases it for reuse.
    pub(super) fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }
}

impl Deref for Lent {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.buf
    }
}

impl DerefMut for Lent {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

impl AsRef<[u8]> for Lent {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for Lent {
    fn drop(&mut self) {
        self.pool.give(self.class, std::mem::take(&mut self.buf));
    }
}

/// Read the chunk file at `path` into a pooled buffer.
pub(super) fn read_file(pool: &Arc<ChunkPool>, path: &std::path::Path) -> std::io::Result<Lent> {
    let file = std::fs::File::open(path)?;
    let mut buf = pool.lend(Class::Wire);
    let size = file.metadata()?.len();
    buf.reserve_exact(size.min(MAX_CHUNK_BLOB) as usize);
    file.take(MAX_CHUNK_BLOB + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_CHUNK_BLOB {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is larger than any chunk", path.display()),
        ));
    }
    pool.note_read();
    Ok(buf)
}

/// A chunk as one download received it.
pub(super) struct Received {
    /// Bytes to cache as received, after stripping any outer encoding from a frame-digest chunk.
    pub(super) wire: Bytes,
    /// Whether `wire` is a zstd frame of the descriptor's raw bytes.
    pub(super) zstd: bool,
    /// Bytes covered by the descriptor digest. May share storage with `wire`.
    pub(super) canonical: Bytes,
}

tokio::task_local! {
    static CHUNK_GET: Arc<ChunkGet>;
}

/// One attempt at downloading one chunk, as the transport sees it.
pub(super) struct ChunkGet {
    /// The end of the registry's blob path: `/blobs/<digest>`.
    blob_path: String,
    /// The descriptor's alternate URLs, which oci-client tries without credentials.
    alternates: Vec<reqwest::Url>,
    /// The digest names the frame itself, so strip any outer zstd encoding before caching.
    frame_digest: bool,
    /// The chunk's decoded length, from its descriptor.
    len: u64,
    /// The blob's size, from its descriptor: a frame's, for a frame-digest chunk.
    size: u64,
    pool: Arc<ChunkPool>,
    received: Mutex<Option<Received>>,
}

impl ChunkGet {
    pub(super) fn new(
        layer: &OciDescriptor,
        frame_digest: bool,
        len: u64,
        pool: &Arc<ChunkPool>,
    ) -> Self {
        let urls = layer.urls.iter().flatten();
        ChunkGet {
            blob_path: format!("/blobs/{}", layer.digest),
            // oci-client refuses an alternate it cannot parse before requesting it.
            alternates: urls.filter_map(|u| unfragmented(u)).collect(),
            frame_digest,
            len,
            size: u64::try_from(layer.size).unwrap_or(u64::MAX),
            pool: Arc::clone(pool),
            received: Mutex::new(None),
        }
    }

    /// Run `download` with requests for this chunk negotiating zstd.
    pub(super) async fn scope<T>(self: &Arc<Self>, download: impl Future<Output = T>) -> T {
        CHUNK_GET.scope(Arc::clone(self), download).await
    }

    /// What the last 200 for this chunk delivered.
    pub(super) fn take(&self) -> Option<Received> {
        self.lock().take()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Received>> {
        self.received.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn matches(&self, req: &transport::Request) -> bool {
        req.method() == reqwest::Method::GET
            && (req.uri().path().ends_with(&self.blob_path)
                || unfragmented(&req.uri().to_string())
                    .is_some_and(|u| self.alternates.contains(&u)))
    }

    /// Read a 200's body into one capped pooled buffer and decode a zstd body once. Answer
    /// oci-client with the decoded bytes, or the body itself, for its digest check.
    async fn receive(
        &self,
        mut resp: reqwest::Response,
    ) -> std::result::Result<transport::Response, BoxError> {
        let mut encodings = resp.headers().get_all(CONTENT_ENCODING).iter();
        let zstd = match (encodings.next(), encodings.next()) {
            (None, _) => false,
            (Some(v), None) if v.as_bytes().eq_ignore_ascii_case(b"identity") => false,
            (Some(v), None) if v.as_bytes().eq_ignore_ascii_case(b"zstd") => true,
            (Some(v), _) => return Err(refused(format!("unsupported Content-Encoding {v:?}"))),
        };
        // A frame of any chunk fits; unencoded, the body is the size its descriptor gives.
        let max = match (zstd, self.frame_digest) {
            (true, _) => MAX_CHUNK_BLOB,
            (false, true) => self.size.min(MAX_CHUNK_BLOB),
            (false, false) => self.len.min(MAX_CHUNK_BLOB),
        } as usize;
        let mut wire = self.pool.lend(Class::Wire);
        // Content-Length sizes the allocation. Enforce the body cap on every piece.
        let claimed = resp.content_length().unwrap_or(0).min(MAX_CHUNK_BLOB);
        wire.reserve_exact(claimed as usize);
        // A body cut short stays a reqwest error, retried as any other.
        while let Some(piece) = resp.chunk().await? {
            if piece.len() > max - wire.len() {
                return Err(refused(format!("the chunk body is over {max} bytes")));
            }
            wire.extend_from_slice(&piece);
        }
        let mut wire = wire.into_bytes();
        let canonical = if zstd {
            // A frame digest covers the inner frame, which is also the cache representation.
            let (class, len) = match self.frame_digest {
                true => (Class::Wire, self.size),
                false => (Class::Decoded, self.len),
            };
            let (pool, frame) = (Arc::clone(&self.pool), wire.clone());
            let decoded = tokio::task::spawn_blocking(move || -> Result<Bytes> {
                let mut out = pool.lend(class);
                pool.decode(&frame, len, &mut out)?;
                Ok(out.into_bytes())
            })
            .await?
            .map_err(|e| refused(format!("decoding the zstd chunk body: {e:#}")))?;
            if self.frame_digest {
                wire = decoded.clone();
            }
            decoded
        } else {
            if !self.frame_digest && wire.len() as u64 != self.len {
                return Err(refused(format!(
                    "the chunk body is {} bytes, not {}",
                    wire.len(),
                    self.len
                )));
            }
            wire.clone()
        };
        let mut out = transport::Response::new(transport::Body::from_bytes(canonical.clone()));
        *out.status_mut() = resp.status();
        *out.version_mut() = resp.version();
        for (name, value) in resp.headers() {
            if name != CONTENT_ENCODING && name != CONTENT_LENGTH {
                out.headers_mut().append(name, value.clone());
            }
        }
        effective_url(&mut out, resp.url());
        *self.lock() = Some(Received {
            wire,
            zstd: zstd && !self.frame_digest,
            canonical,
        });
        Ok(out)
    }
}

/// `url` without its fragment, which a request URI does not carry; `None` if it does not
/// parse.
fn unfragmented(url: &str) -> Option<reqwest::Url> {
    let mut url = reqwest::Url::parse(url).ok()?;
    url.set_fragment(None);
    Some(url)
}

/// A chunk body the transport refuses: final, never retried.
fn refused(why: impl Into<String>) -> BoxError {
    why.into().into()
}

fn effective_url(resp: &mut transport::Response, url: &reqwest::Url) {
    if let Ok(uri) = url.as_str().parse() {
        resp.extensions_mut().insert(EffectiveUrl(uri));
    }
}

/// The transport of [`super::client`]: `http` sends every request, as oci-client's own
/// transport would, and a chunk download marked by [`ChunkGet`] is negotiated and decoded.
#[derive(Clone)]
pub(super) struct ChunkTransport(pub(super) reqwest::Client);

type Sent =
    Pin<Box<dyn Future<Output = std::result::Result<transport::Response, BoxError>> + Send>>;

impl tower_service::Service<transport::Request> for ChunkTransport {
    type Response = transport::Response;
    type Error = BoxError;
    type Future = Sent;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: transport::Request) -> Sent {
        // Only matching GETs in the download's task-local scope offer zstd.
        let chunk = CHUNK_GET
            .try_with(|get| get.matches(&req).then(|| Arc::clone(get)))
            .ok()
            .flatten();
        if chunk.is_some() {
            req.headers_mut()
                .insert(ACCEPT_ENCODING, HeaderValue::from_static("zstd"));
        }
        let http = self.0.clone();
        Box::pin(async move {
            let resp = http.execute(reqwest::Request::try_from(req)?).await?;
            let status = resp.status();
            match chunk {
                Some(chunk) if status == reqwest::StatusCode::OK => chunk.receive(resp).await,
                Some(_) if status.is_success() => Err(refused(format!(
                    "the registry answered a chunk download with {status}"
                ))),
                _ => {
                    let url = resp.url().clone();
                    let mut out = http::Response::from(resp).map(transport::Body::wrap);
                    effective_url(&mut out, &url);
                    Ok(out)
                }
            }
        })
    }
}
