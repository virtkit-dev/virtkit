//! Reusable buffers for streaming blobs and verifying pushed zstd frames.
//!
//! A zeroed [`STREAM_CHUNK`] allocation per chunk makes jemalloc return recycled
//! pages to the kernel with `madvise`. Each chunk costs a TLB shootdown and
//! refaults the pages it fills. The pool zeroes each buffer once, at allocation.
//! On reuse, only the prefix reported by the reader is exposed.

use std::sync::{Mutex, MutexGuard, PoisonError};

use bytes::Bytes;

use crate::STREAM_CHUNK;

/// A pool retains up to 16 MiB of idle buffers. In-flight responses can use more.
/// A buffer returned to a full pool is freed.
const MAX_IDLE: usize = 64;

/// Idle buffers, each [`STREAM_CHUNK`] long.
pub(crate) struct ChunkPool(Mutex<Vec<Vec<u8>>>);

/// The pool shared by blob response streams and verification of pushed zstd frames.
pub(crate) static CHUNKS: ChunkPool = ChunkPool::new();

impl ChunkPool {
    pub(crate) const fn new() -> Self {
        ChunkPool(Mutex::new(Vec::new()))
    }

    /// A poisoned lock still guards a valid idle list. A panic leaves each
    /// `push` or `pop` either complete or unapplied.
    fn idle(&self) -> MutexGuard<'_, Vec<Vec<u8>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take an idle buffer or allocate one. Either starts with an empty filled prefix.
    pub(crate) fn take(&'static self) -> Chunk {
        // A separate statement releases the lock before allocating a new buffer.
        let kept = self.idle().pop();
        Chunk {
            buf: kept.unwrap_or_else(|| vec![0u8; STREAM_CHUNK]),
            filled: 0,
            pool: self,
        }
    }

    #[cfg(test)]
    pub(crate) fn idle_count(&self) -> usize {
        self.idle().len()
    }
}

/// A buffer borrowed from a [`ChunkPool`] until drop. Converting it to [`Bytes`]
/// extends the loan until the last reference is dropped.
pub(crate) struct Chunk {
    buf: Vec<u8>,
    /// Length of the prefix from the last [`Chunk::fill`]. The tail retains its old contents.
    filled: usize,
    pool: &'static ChunkPool,
}

impl Chunk {
    /// Replace the filled prefix, reading until the buffer is full or `reader`
    /// reaches EOF. Return the byte count, or `0` if no bytes remain.
    ///
    /// A short read can precede EOF, for example when a zstd decoder returns
    /// one block. Keep reading and retry `Interrupted`.
    pub(crate) fn fill(&mut self, reader: &mut impl std::io::Read) -> std::io::Result<usize> {
        self.filled = 0;
        while let Some(spare) = self.buf.get_mut(self.filled..).filter(|s| !s.is_empty()) {
            match reader.read(spare) {
                Ok(0) => break,
                // Clamp an oversized count to the end of the buffer.
                Ok(n) => self.filled = self.filled.saturating_add(n).min(self.buf.len()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(self.filled)
    }

    /// Expose the filled prefix as `Bytes` without copying it. The last `Bytes`
    /// referencing the buffer, including a clone or slice, releases it to the pool.
    pub(crate) fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }
}

impl AsRef<[u8]> for Chunk {
    /// What the last [`Chunk::fill`] read.
    fn as_ref(&self) -> &[u8] {
        self.buf.get(..self.filled).unwrap_or_default()
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        let mut idle = self.pool.idle();
        if idle.len() < MAX_IDLE {
            idle.push(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slice keeps the buffer out of the pool. After the slice drops, the next
    /// read reuses the same allocation and exposes only its new prefix.
    #[test]
    fn a_buffer_is_returned_and_read_into_again() {
        static POOL: ChunkPool = ChunkPool::new();

        let mut chunk = POOL.take();
        assert_eq!(chunk.fill(&mut &[7u8; 5000][..]).unwrap(), 5000);
        let first = chunk.buf.as_ptr();
        let bytes = chunk.into_bytes();
        let tail = bytes.slice(4000..);
        assert_eq!(bytes[..], [7u8; 5000]);
        drop(bytes);
        assert_eq!(POOL.idle_count(), 0, "a slice still reads the buffer");
        drop(tail);
        assert_eq!(POOL.idle_count(), 1);

        let mut chunk = POOL.take();
        assert_eq!(POOL.idle_count(), 0);
        assert_eq!(chunk.buf.as_ptr(), first, "the same buffer, not a new one");
        assert_eq!(chunk.as_ref(), b"", "nothing is filled before a read");
        assert_eq!(chunk.fill(&mut &b"abc"[..]).unwrap(), 3);
        assert_eq!(chunk.as_ref(), b"abc");
        assert_eq!(chunk.into_bytes()[..], *b"abc");
        assert_eq!(POOL.idle_count(), 1);

        // An empty read exposes no bytes. Dropping the chunk returns its buffer.
        let mut chunk = POOL.take();
        assert_eq!(chunk.fill(&mut std::io::empty()).unwrap(), 0);
        assert_eq!(chunk.as_ref(), b"");
        drop(chunk);
        assert_eq!(POOL.idle_count(), 1);
    }

    /// However many buffers were out at once, at most [`MAX_IDLE`] are kept.
    #[test]
    fn the_pool_keeps_a_bounded_number_of_buffers() {
        static POOL: ChunkPool = ChunkPool::new();
        let out: Vec<Chunk> = (0..MAX_IDLE + 3).map(|_| POOL.take()).collect();
        assert_eq!(POOL.idle_count(), 0);
        drop(out);
        assert_eq!(POOL.idle_count(), MAX_IDLE);
    }
}
