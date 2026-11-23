//! The buffers a restore reuses: chunks as stored and as decoded, across its workers.

use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use oci_client::manifest::OciDescriptor;

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

/// Buffers reused within one restore, remote or from a local store. Each
/// class keeps at most [`RESTORE_CONCURRENCY`] idle buffers, none larger than the class
/// allows.
#[derive(Default)]
pub(super) struct ChunkPool {
    wire: Mutex<Vec<Vec<u8>>>,
    decoded: Mutex<Vec<Vec<u8>>>,
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
    Ok(buf)
}
