//! Reusable buffers for the registry's chunked reads.
//!
//! Allocating a zeroed [`STREAM_CHUNK`] buffer per chunk is costly under
//! jemalloc (the allocator of musl builds). It can zero recycled memory by
//! returning its pages to the kernel with `madvise`, so the chunk refaults the
//! pages it fills. The pool zeroes each buffer once, at allocation. On reuse,
//! only the prefix reported by the reader is exposed.

use std::sync::{Mutex, MutexGuard, PoisonError};

use bytes::Bytes;

use crate::STREAM_CHUNK;

/// A pool retains at most this many idle buffers, each [`STREAM_CHUNK`] long.
/// In-flight readers can use more. A buffer returned to a full pool is freed.
const MAX_IDLE: usize = 64;

/// Idle buffers, each [`STREAM_CHUNK`] long.
pub(crate) struct ChunkPool(Mutex<Vec<Vec<u8>>>);

/// The pool shared by every chunked read of this crate.
pub(crate) static CHUNKS: ChunkPool = ChunkPool::new();

impl ChunkPool {
    pub(crate) const fn new() -> Self {
        ChunkPool(Mutex::new(Vec::new()))
    }

    /// A poisoned lock still guards a valid idle list: only a `push` or a `pop`
    /// runs under it.
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
    /// Length of the prefix from the last [`Chunk::fill`]. The tail may contain stale bytes.
    filled: usize,
    pool: &'static ChunkPool,
}

impl Chunk {
    /// Replace the filled prefix, reading until the buffer is full or `reader`
    /// reaches EOF. Return the byte count, or `0` if no bytes remain.
    ///
    /// A zstd decoder can return a single block before EOF. Continue after short
    /// reads and retry `Interrupted`. An oversized count or any other read
    /// error leaves the prefix empty.
    pub(crate) fn fill(&mut self, reader: &mut impl std::io::Read) -> std::io::Result<usize> {
        self.filled = 0;
        while let Some(spare) = self.buf.get_mut(self.filled..).filter(|s| !s.is_empty()) {
            let offered = spare.len();
            let err = match reader.read(spare) {
                Ok(0) => break,
                Ok(n) if n <= offered => {
                    self.filled = self.filled.saturating_add(n);
                    continue;
                }
                Ok(_) => std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a reader reported more bytes than the buffer holds",
                ),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => e,
            };
            self.filled = 0;
            return Err(err);
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
        // `fill` keeps `filled` within the buffer.
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

        let mut chunk = POOL.take();
        assert_eq!(chunk.fill(&mut std::io::empty()).unwrap(), 0);
        assert_eq!(chunk.as_ref(), b"");
        drop(chunk);
        assert_eq!(POOL.idle_count(), 1);
    }

    #[test]
    fn an_oversized_read_count_or_a_failed_read_exposes_nothing() {
        struct Lying;
        impl std::io::Read for Lying {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(buf.len() + 1)
            }
        }
        /// Reads 10 bytes, then fails.
        struct Failing(bool);
        impl std::io::Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    buf[..10].fill(b'x');
                    return Ok(10);
                }
                Err(std::io::Error::other("the disk went away"))
            }
        }
        static POOL: ChunkPool = ChunkPool::new();

        let mut chunk = POOL.take();
        let err = chunk.fill(&mut Lying).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(chunk.as_ref(), b"");

        assert_eq!(chunk.fill(&mut &b"abc"[..]).unwrap(), 3);
        let err = chunk.fill(&mut Failing(true)).unwrap_err();
        assert_eq!(err.to_string(), "the disk went away");
        assert_eq!(chunk.as_ref(), b"");
    }

    #[test]
    fn the_pool_keeps_a_bounded_number_of_buffers() {
        static POOL: ChunkPool = ChunkPool::new();
        let out: Vec<Chunk> = (0..MAX_IDLE + 3).map(|_| POOL.take()).collect();
        assert_eq!(POOL.idle_count(), 0);
        drop(out);
        assert_eq!(POOL.idle_count(), MAX_IDLE);
    }
}
