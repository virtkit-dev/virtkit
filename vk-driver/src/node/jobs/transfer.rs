//! Cache and artifact transfers between network, host and guest. Pipes stream archives
//! through a blocking conversion thread. Capped files in the job's scratch dir hold formats
//! that need the whole archive first: a zip read from its end, a blob uploaded by digest.

use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;
use tokio_util::io::SyncIoBridge;

/// The most one file a stage keeps in the job's scratch dir may hold: a downloaded
/// dependency's zip, a cache's compressed layer, an artifact's archive before its upload. The
/// scratch dir is on the node's job disk, which other jobs share, so what a job's guest or a
/// remote server sends is not let to fill it.
pub const MAX_STAGED: u64 = 10 << 30;

/// How much a pipe holds in flight.
const PIPE: usize = 256 * 1024;

pub fn create(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// A writer that fails once more than `max` bytes have been written through it.
pub struct Capped<W> {
    pub inner: W,
    pub written: u64,
    max: u64,
}

impl<W> Capped<W> {
    pub fn new(inner: W, max: u64) -> Self {
        Capped {
            inner,
            written: 0,
            max,
        }
    }
}

impl<W: Write> Write for Capped<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written.saturating_add(buf.len() as u64) > self.max {
            return Err(too_large(self.max));
        }
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Seeks pass through; what is written again after one counts again.
impl<W: io::Seek> io::Seek for Capped<W> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

pub fn too_large(max: u64) -> io::Error {
    io::Error::other(format!(
        "larger than the {} MiB a job may stage on the node",
        max >> 20
    ))
}

/// A pipe whose reading end `f` takes on a blocking thread: what is written to the returned
/// stream reaches `f`, and dropping the stream ends it. Once `f` returns `Ok`, what it left
/// unread is drained, so the writer never fails for padding after the end of an archive.
pub fn into_blocking<T: Send + 'static>(
    f: impl FnOnce(&mut dyn Read) -> Result<T> + Send + 'static,
) -> (DuplexStream, JoinHandle<Result<T>>) {
    let (w, r) = tokio::io::duplex(PIPE);
    let task = tokio::task::spawn_blocking(move || {
        let mut r = SyncIoBridge::new(r);
        let out = f(&mut r)?;
        io::copy(&mut r, &mut io::sink())?;
        Ok(out)
    });
    (w, task)
}

/// A pipe whose writing end `f` takes on a blocking thread: what `f` writes is read from the
/// returned stream, which ends when `f` returns.
pub fn from_blocking<T: Send + 'static>(
    f: impl FnOnce(&mut dyn Write) -> Result<T> + Send + 'static,
) -> (DuplexStream, JoinHandle<Result<T>>) {
    let (w, r) = tokio::io::duplex(PIPE);
    let task = tokio::task::spawn_blocking(move || {
        let mut w = SyncIoBridge::new(w);
        let out = f(&mut w)?;
        w.flush()?;
        w.shutdown()?;
        Ok(out)
    });
    (r, task)
}

/// The rest of a producer's output once its consumer succeeded without reading it all (an
/// extract stops at the archive's end marker), so the producer does not fail on a closed
/// pipe. A read error is the producer's to report.
pub async fn drain<T>(reader: &mut DuplexStream, consumed: &Result<T>) {
    if consumed.is_ok() {
        let _ = tokio::io::copy(reader, &mut tokio::io::sink()).await;
    }
}

/// A blocking task's outcome, its panic or abort included.
pub async fn joined<T>(task: JoinHandle<Result<T>>) -> Result<T> {
    task.await.context("a transfer's worker failed")?
}

/// Whether `e` is a write to a pipe whose reader is gone: a consequence of the other side's
/// failure rather than a cause.
pub fn broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
    })
}

/// The outcome of a producer and a consumer joined by a pipe, as one: the error that caused
/// the other's, where one did.
pub fn both<T, U>(producer: Result<T>, consumer: Result<U>) -> Result<(T, U)> {
    match (producer, consumer) {
        (Ok(p), Ok(c)) => Ok((p, c)),
        (Err(p), Err(c)) if broken_pipe(&p) => Err(c),
        (Err(p), _) | (_, Err(p)) => Err(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capped_writer_refuses_past_its_cap() {
        let mut w = Capped::new(Vec::new(), 4);
        w.write_all(b"abcd").unwrap();
        assert!(w.write_all(b"e").is_err());
        assert_eq!(w.inner, b"abcd");
    }

    #[tokio::test]
    async fn pipes_carry_data_both_ways() {
        let (mut w, task) = into_blocking(|r| {
            let mut s = Vec::new();
            r.take(3).read_to_end(&mut s)?;
            Ok(s)
        });
        tokio::io::AsyncWriteExt::write_all(&mut w, b"abcdef")
            .await
            .unwrap();
        drop(w);
        // What the reader left is drained, so the writer saw no broken pipe.
        assert_eq!(joined(task).await.unwrap(), b"abc");

        let (mut r, task) = from_blocking(|w| Ok(w.write_all(&[7u8; 300_000])?));
        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut got)
            .await
            .unwrap();
        joined(task).await.unwrap();
        assert_eq!(got.len(), 300_000);
    }

    #[tokio::test]
    async fn a_gone_reader_is_reported_as_the_cause() {
        let (mut w, task) = into_blocking(|_| -> Result<()> { anyhow::bail!("bad archive") });
        let consumed = joined(task).await;
        let produced = tokio::io::AsyncWriteExt::write_all(&mut w, &[0u8; 1 << 20])
            .await
            .context("writing");
        let err = both(produced, consumed).unwrap_err();
        assert_eq!(err.to_string(), "bad archive");
    }

    #[tokio::test]
    async fn a_consumer_done_early_leaves_the_producer_whole() {
        use tokio::io::AsyncReadExt;
        let (mut r, task) = from_blocking(|w| Ok(w.write_all(&vec![7u8; 1 << 20])?));
        let mut head = [0u8; 10];
        r.read_exact(&mut head).await.unwrap();
        let consumed: Result<()> = Ok(());
        drain(&mut r, &consumed).await;
        drop(r);
        assert!(both(joined(task).await, consumed).is_ok());
    }
}
