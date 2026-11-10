//! Stream and hash request bodies into staging files under `uploads/` for routes that
//! accept whole objects in one request rather than OCI upload sessions.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::STREAM_CHUNK;

/// Why a streamed body stopped short.
pub(crate) enum DrainError {
    /// the body crossed the cap, decided while reading
    OverCap,
    /// the read or the write failed
    Failed(anyhow::Error),
}

/// A staging file under `uploads/`, unlinked when dropped unless disarmed — including when
/// the handler's future is dropped with the connection mid-body.
///
/// Path-based staging requires trusted writers for the store directory and its ancestors
/// (`DESIGN.md`); otherwise, `uploads/` could be replaced between writing and promotion.
pub(crate) struct Staging {
    path: PathBuf,
    armed: bool,
}

impl Staging {
    /// Own the staging file at `path` ([`crate::Store::stage_file`]).
    pub(crate) fn new(path: PathBuf) -> Self {
        Staging { path, armed: true }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Leave cleanup to the code that promotes or discards the file.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.armed {
            // Promotion or discard may have removed it; other failures leave it for
            // gc's sweep of idle uploads.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Stream `body` to `out`, coalescing small frames and enforcing `cap`, including for chunked
/// bodies; `(bytes written, sha256 hex)` on success. `out` may be a sink when draining a
/// refused request. The generic body allows tests with a small cap.
pub(crate) async fn drain_into<B>(
    out: &mut (impl AsyncWrite + Unpin),
    mut body: B,
    cap: u64,
) -> std::result::Result<(u64, String), DrainError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut buf: Vec<u8> = Vec::with_capacity(STREAM_CHUNK);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let io = |e: std::io::Error| DrainError::Failed(anyhow::Error::from(e).context("writing"));
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            DrainError::Failed(anyhow::Error::from(e).context("reading a PUT body"))
        })?;
        // Trailers carry no body data.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total = total.saturating_add(data.len() as u64);
        if total > cap {
            return Err(DrainError::OverCap);
        }
        hasher.update(&data);
        // Large frames bypass an empty buffer; small frames are coalesced.
        if buf.is_empty() && data.len() >= STREAM_CHUNK {
            out.write_all(&data).await.map_err(io)?;
            continue;
        }
        buf.extend_from_slice(&data);
        if buf.len() >= STREAM_CHUNK {
            out.write_all(&buf).await.map_err(io)?;
            buf.clear();
        }
    }
    if !buf.is_empty() {
        out.write_all(&buf).await.map_err(io)?;
    }
    Ok((total, crate::hex_of(&hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check a small streaming cap across multiple frames and verify the body's digest.
    #[tokio::test]
    async fn a_body_over_the_cap_stops_being_written() {
        let dir = std::env::temp_dir().join(format!("vk-reg-staging-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("staged");

        // Several frames, so the cap is crossed part way through rather than at the first.
        let frames = |len: usize| {
            let chunks: Vec<std::result::Result<hyper::body::Frame<Bytes>, std::io::Error>> = (0
                ..4)
                .map(|_| Ok(hyper::body::Frame::data(Bytes::from(vec![1u8; len]))))
                .collect();
            http_body_util::StreamBody::new(futures::stream::iter(chunks))
        };

        // Refused where the count crossed: what was written stays within the cap, whether
        // the frames were coalesced or written as they came.
        for (len, cap) in [(100, 250), (STREAM_CHUNK, STREAM_CHUNK as u64 * 3 / 2)] {
            let mut file = tokio::fs::File::create(&path).await.unwrap();
            assert!(matches!(
                drain_into(&mut file, frames(len), cap).await,
                Err(DrainError::OverCap)
            ));
            file.flush().await.unwrap();
            drop(file);
            let staged = std::fs::metadata(&path).unwrap().len();
            assert!(staged <= cap, "wrote {staged} bytes past a {cap}-byte cap");
        }

        // Exactly at the cap is not over it, and the digest is the body's.
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        let (n, hex) = drain_into(&mut file, frames(100), 400).await.ok().unwrap();
        file.flush().await.unwrap();
        drop(file);
        assert_eq!(n, 400);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 400);
        assert_eq!(hex, crate::sha256_hex_raw(&vec![1u8; 400]));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
