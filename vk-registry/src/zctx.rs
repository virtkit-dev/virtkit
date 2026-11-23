//! zstd contexts kept between operations.
//!
//! A context holds zstd's tables, its window and, for a stream, its buffers: about 1 MiB to
//! decode a large stream and 1.5 MiB to compress one at the store's settings. A fresh
//! context for each blob stored compressed or served decompressed repeats allocation
//! and table setup. Even with jemalloc, the first access to a nonresident page faults.
//! Resetting a pooled context lets zstd reuse its workspace when it fits and produces
//! the same bytes as a fresh context.
//!
//! zstd's high-level reader and writer create a context or borrow one from the caller.
//! A streamed HTTP body needs a `'static` reader, so the `zstd::stream::zio` adapters
//! used here own their pooled contexts.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

use zstd::stream::raw::{CParameter, InBuffer, Operation, OutBuffer, WriteBuf};
use zstd::stream::zio;
use zstd::zstd_safe::{self, CCtx, DCtx, ResetDirective};

/// Each pool keeps up to this many idle contexts for concurrent transfers, each at most
/// [`MAX_KEPT`] bytes. A context returned to a full pool is freed.
const MAX_IDLE: usize = 16;

/// Maximum retained size per context, in bytes. This leaves several times the space
/// a store frame needs. The sender chooses a pushed frame's window, so an oversized
/// decoder is freed when the transfer ends.
const MAX_KEPT: usize = 8 << 20;

/// What a pool needs of a zstd context.
pub(crate) trait Context: Sized {
    fn create() -> Option<Self>;
    /// Reset the session and its parameters, even after an abandoned frame or an error.
    /// Return `false` if the reset fails.
    fn renew(&mut self) -> bool;
    /// The bytes it holds.
    fn size(&self) -> usize;
}

impl Context for DCtx<'static> {
    fn create() -> Option<Self> {
        DCtx::try_create()
    }
    fn renew(&mut self) -> bool {
        self.reset(ResetDirective::SessionAndParameters).is_ok()
    }
    fn size(&self) -> usize {
        self.sizeof()
    }
}

impl Context for CCtx<'static> {
    fn create() -> Option<Self> {
        CCtx::try_create()
    }
    fn renew(&mut self) -> bool {
        self.reset(ResetDirective::SessionAndParameters).is_ok()
    }
    fn size(&self) -> usize {
        self.sizeof()
    }
}

/// Idle contexts of one kind.
pub(crate) struct Pool<T>(Mutex<Vec<T>>);

static DECODERS: Pool<DCtx<'static>> = Pool::new();
static ENCODERS: Pool<CCtx<'static>> = Pool::new();

impl<T: Context> Pool<T> {
    const fn new() -> Self {
        Pool(Mutex::new(Vec::new()))
    }

    /// The idle list remains valid after a panic because each push or pop is complete
    /// or has made no change.
    fn idle(&self) -> MutexGuard<'_, Vec<T>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Renew an idle context, or create one if the pool is empty or renewal fails.
    fn take(&'static self) -> io::Result<Pooled<T>> {
        // Pop in a separate statement so the lock is released before the reset.
        let kept = self.idle().pop();
        let renewed = kept.and_then(|mut ctx| ctx.renew().then_some(ctx));
        let ctx = match renewed {
            Some(ctx) => ctx,
            None => T::create().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "zstd could not allocate a context",
                )
            })?,
        };
        Ok(Pooled {
            ctx: Some(ctx),
            pool: self,
        })
    }
}

/// A checked-out context. On drop, its [`Pool`] keeps it if both limits allow.
pub(crate) struct Pooled<T: Context + 'static> {
    /// `None` only after `drop` takes the context.
    ctx: Option<T>,
    pool: &'static Pool<T>,
}

impl<T: Context> Pooled<T> {
    fn ctx(&mut self) -> io::Result<&mut T> {
        self.ctx
            .as_mut()
            .ok_or_else(|| io::Error::other("missing zstd context"))
    }
}

impl<T: Context> Drop for Pooled<T> {
    fn drop(&mut self) {
        let Some(ctx) = self.ctx.take() else {
            return;
        };
        if ctx.size() > MAX_KEPT {
            return;
        }
        let mut idle = self.pool.idle();
        if idle.len() < MAX_IDLE {
            idle.push(ctx);
        }
    }
}

/// Wrap zstd's error name in an `io::Error` of kind `Other`.
fn zstd_error(code: usize) -> io::Error {
    io::Error::other(zstd_safe::get_error_name(code))
}

/// The streaming operations of `zstd::stream::raw::Decoder` on a pooled context.
impl Operation for Pooled<DCtx<'static>> {
    fn run<C: WriteBuf + ?Sized>(
        &mut self,
        input: &mut InBuffer<'_>,
        output: &mut OutBuffer<'_, C>,
    ) -> io::Result<usize> {
        self.ctx()?
            .decompress_stream(output, input)
            .map_err(zstd_error)
    }

    fn flush<C: WriteBuf + ?Sized>(&mut self, output: &mut OutBuffer<'_, C>) -> io::Result<usize> {
        // Flush with empty input. If the output buffer fills, only another call tells
        // whether any output remains.
        self.run(&mut InBuffer::around(&[]), output)?;
        Ok(usize::from(output.pos() >= output.capacity()))
    }

    fn reinit(&mut self) -> io::Result<()> {
        self.ctx()?
            .reset(ResetDirective::SessionOnly)
            .map_err(zstd_error)?;
        Ok(())
    }

    fn finish<C: WriteBuf + ?Sized>(
        &mut self,
        _output: &mut OutBuffer<'_, C>,
        finished_frame: bool,
    ) -> io::Result<usize> {
        if finished_frame {
            Ok(0)
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete frame",
            ))
        }
    }
}

/// The streaming operations of `zstd::stream::raw::Encoder` on a pooled context.
impl Operation for Pooled<CCtx<'static>> {
    fn run<C: WriteBuf + ?Sized>(
        &mut self,
        input: &mut InBuffer<'_>,
        output: &mut OutBuffer<'_, C>,
    ) -> io::Result<usize> {
        self.ctx()?
            .compress_stream(output, input)
            .map_err(zstd_error)
    }

    fn flush<C: WriteBuf + ?Sized>(&mut self, output: &mut OutBuffer<'_, C>) -> io::Result<usize> {
        self.ctx()?.flush_stream(output).map_err(zstd_error)
    }

    fn reinit(&mut self) -> io::Result<()> {
        self.ctx()?
            .reset(ResetDirective::SessionOnly)
            .map_err(zstd_error)?;
        Ok(())
    }

    fn finish<C: WriteBuf + ?Sized>(
        &mut self,
        output: &mut OutBuffer<'_, C>,
        _finished_frame: bool,
    ) -> io::Result<usize> {
        self.ctx()?.end_stream(output).map_err(zstd_error)
    }
}

/// Reads consecutive zstd frames from `R` as one decompressed stream.
pub(crate) type Decoder<R> = zio::Reader<R, Pooled<DCtx<'static>>>;

/// Writes one zstd frame to `W`. Call [`finish`] to end it.
pub(crate) type Encoder<W> = zio::Writer<W, Pooled<CCtx<'static>>>;

/// Decode frames from `reader` using zstd's recommended input buffer size.
pub(crate) fn decoder<R: Read>(reader: R) -> io::Result<Decoder<BufReader<R>>> {
    decoder_buffered(BufReader::with_capacity(DCtx::in_size(), reader))
}

/// [`decoder`] for an already buffered input, such as a byte slice.
pub(crate) fn decoder_buffered<R: BufRead>(reader: R) -> io::Result<Decoder<R>> {
    decoder_from(&DECODERS, reader)
}

fn decoder_from<R: BufRead>(
    pool: &'static Pool<DCtx<'static>>,
    reader: R,
) -> io::Result<Decoder<R>> {
    Ok(zio::Reader::new(reader, pool.take()?))
}

/// Decode concatenated frames to the same bytes as `zstd::decode_all`.
pub(crate) fn decode_all(frames: &[u8]) -> io::Result<Vec<u8>> {
    // The sender controls the first frame's size claim. Use it only as a capped
    // reservation hint and continue decoding if the reservation fails.
    const MAX_RESERVED: u64 = 32 << 20;
    let declared = zstd_safe::get_frame_content_size(frames).ok().flatten();
    let mut out = Vec::new();
    let _ = out.try_reserve(declared.unwrap_or(0).min(MAX_RESERVED) as usize);
    decoder_buffered(frames)?.read_to_end(&mut out)?;
    Ok(out)
}

/// Write one frame to `writer` at [`crate::ZSTD_LEVEL`], with the pledged size in its
/// header. Once any byte has been written, the encode fails if the byte count differs
/// from `raw_len`. Calling [`finish`] before any write sets the pledge to zero and
/// successfully emits an empty frame.
pub(crate) fn encoder<W: Write>(writer: W, raw_len: u64) -> io::Result<Encoder<W>> {
    encoder_from(&ENCODERS, writer, raw_len)
}

fn encoder_from<W: Write>(
    pool: &'static Pool<CCtx<'static>>,
    writer: W,
    raw_len: u64,
) -> io::Result<Encoder<W>> {
    let mut pooled = pool.take()?;
    let ctx = pooled.ctx()?;
    ctx.set_parameter(CParameter::CompressionLevel(crate::ZSTD_LEVEL))
        .map_err(zstd_error)?;
    ctx.set_pledged_src_size(Some(raw_len))
        .map_err(zstd_error)?;
    ctx.set_parameter(CParameter::ContentSizeFlag(true))
        .map_err(zstd_error)?;
    Ok(zio::Writer::new(writer, pooled))
}

/// Finish the frame and return the underlying writer.
pub(crate) fn finish<W: Write>(mut encoder: Encoder<W>) -> io::Result<W> {
    encoder.finish()?;
    Ok(encoder.into_inner().0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Partly compressible test data with a repeatable mix of random and patterned bytes.
    fn sample(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|i| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                if i % 7 < 4 {
                    (state >> 56) as u8
                } else {
                    (i % 13) as u8
                }
            })
            .collect()
    }

    /// Encode `raw` with a fresh zstd context and the store's frame settings.
    fn reference_frame(raw: &[u8]) -> Vec<u8> {
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), crate::ZSTD_LEVEL).unwrap();
        enc.set_pledged_src_size(Some(raw.len() as u64)).unwrap();
        enc.include_contentsize(true).unwrap();
        enc.write_all(raw).unwrap();
        enc.finish().unwrap()
    }

    fn encode(pool: &'static Pool<CCtx<'static>>, raw: &[u8]) -> Vec<u8> {
        let mut enc = encoder_from(pool, Vec::new(), raw.len() as u64).unwrap();
        enc.write_all(raw).unwrap();
        finish(enc).unwrap()
    }

    /// Store tests exercise the shared pool. Compare [`decode_all`] with `zstd::decode_all`
    /// on concatenated frames and check that a truncated final frame fails.
    #[test]
    fn decode_all_matches_zstd() {
        let (a, b) = (sample(300_000, 20), sample(10, 21));
        let frames = [reference_frame(&a), reference_frame(&b)].concat();
        assert_eq!(decode_all(&frames).unwrap(), [a, b].concat());
        assert_eq!(
            decode_all(&frames).unwrap(),
            zstd::decode_all(&frames[..]).unwrap()
        );
        assert!(decode_all(&frames[..frames.len() - 3]).is_err());
    }

    fn decode(pool: &'static Pool<DCtx<'static>>, frames: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        decoder_from(pool, frames)?.read_to_end(&mut out)?;
        Ok(out)
    }

    /// A reused encoder produces the same frame bytes as a fresh encoder, whether the
    /// preceding input was larger or smaller.
    #[test]
    fn a_reused_encoder_writes_the_frames_a_new_one_does() {
        static POOL: Pool<CCtx<'static>> = Pool::new();
        for (len, seed) in [
            (0, 1),
            (1, 2),
            (100_000, 3),
            (5 << 20, 4),
            (300, 5),
            (5 << 20, 6),
            (70_000, 7),
        ] {
            let raw = sample(len, seed);
            assert_eq!(encode(&POOL, &raw), reference_frame(&raw), "{len} bytes");
            assert_eq!(POOL.idle().len(), 1, "the context went back to the pool");
        }
    }

    /// An abandoned or failed frame leaves no state in the next encoding.
    #[test]
    fn an_abandoned_encoder_is_reset_before_reuse() {
        static POOL: Pool<CCtx<'static>> = Pool::new();
        let raw = sample(400_000, 8);

        // Half a frame, then dropped.
        let mut enc = encoder_from(&POOL, Vec::new(), raw.len() as u64).unwrap();
        enc.write_all(&raw[..raw.len() / 2]).unwrap();
        drop(enc);
        assert_eq!(POOL.idle().len(), 1);
        assert_eq!(encode(&POOL, &raw), reference_frame(&raw));

        // Fewer bytes than pledged: the frame fails, the next one does not.
        let mut enc = encoder_from(&POOL, Vec::new(), raw.len() as u64).unwrap();
        enc.write_all(&raw[..10]).unwrap();
        assert!(finish(enc).is_err(), "a short frame must not finish");
        assert_eq!(POOL.idle().len(), 1);
        assert_eq!(encode(&POOL, &raw), reference_frame(&raw));
    }

    /// A reused decoder reads back-to-back frames and still decodes a valid frame
    /// after truncated or corrupt input.
    #[test]
    fn a_reused_decoder_reads_what_a_new_one_does() {
        static POOL: Pool<DCtx<'static>> = Pool::new();
        let (a, b) = (sample(300_000, 9), sample(5 << 20, 10));
        let (fa, fb) = (reference_frame(&a), reference_frame(&b));

        assert_eq!(decode(&POOL, &fa).unwrap(), a);
        assert_eq!(decode(&POOL, &fb).unwrap(), b);
        assert_eq!(
            decode(&POOL, &[fa.clone(), fb.clone()].concat()).unwrap(),
            [a.clone(), b.clone()].concat()
        );
        assert_eq!(
            decode(&POOL, &[]).ok(),
            zstd::decode_all(&[][..]).ok(),
            "no input at all"
        );

        // First truncate the input, then stop reading a complete frame early.
        let cut = decode(&POOL, &fb[..fb.len() / 2]).unwrap_err();
        assert_eq!(cut.kind(), io::ErrorKind::UnexpectedEof, "{cut}");
        let mut head = [0u8; 1000];
        decoder_from(&POOL, &fb[..])
            .unwrap()
            .read_exact(&mut head)
            .unwrap();
        assert_eq!(head[..], b[..1000]);
        assert_eq!(decode(&POOL, &fa).unwrap(), a);

        // Non-frame input fails. The damaged frame either fails or decodes to different
        // bytes. Neither outcome affects the next decode.
        assert!(decode(&POOL, b"not a zstd frame").is_err());
        let mut corrupt = fa.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid..mid + 64].fill(0xff);
        assert_ne!(decode(&POOL, &corrupt).ok(), Some(a.clone()));
        assert_eq!(decode(&POOL, &fa).unwrap(), a);

        assert_eq!(POOL.idle().len(), 1, "one context served them all");
        // Compare the streamed blob's `Read` path with zstd's own decoder.
        let mut theirs = Vec::new();
        zstd::stream::read::Decoder::new(&fb[..])
            .unwrap()
            .read_to_end(&mut theirs)
            .unwrap();
        let mut ours = Vec::new();
        decoder_from(&POOL, BufReader::with_capacity(DCtx::in_size(), &fb[..]))
            .unwrap()
            .read_to_end(&mut ours)
            .unwrap();
        assert_eq!(ours, theirs);
    }

    /// The pool keeps at most [`MAX_IDLE`] contexts, however many were out at once, and
    /// none that grew past [`MAX_KEPT`].
    #[test]
    fn the_pool_is_bounded() {
        static POOL: Pool<DCtx<'static>> = Pool::new();
        let out: Vec<_> = (0..MAX_IDLE + 5).map(|_| POOL.take().unwrap()).collect();
        assert_eq!(POOL.idle().len(), 0);
        drop(out);
        assert_eq!(POOL.idle().len(), MAX_IDLE);

        // A 64 MiB window pushes the decoder over the retention limit.
        static BIG: Pool<DCtx<'static>> = Pool::new();
        let raw = sample(2 << 20, 11);
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        enc.window_log(26).unwrap();
        enc.write_all(&raw).unwrap();
        let frame = enc.finish().unwrap();
        assert_eq!(decode(&BIG, &frame).unwrap(), raw);
        assert_eq!(BIG.idle().len(), 0, "an outsized context was kept");
        // The same input in the store's frame format fits within the limit.
        assert_eq!(decode(&BIG, &reference_frame(&raw)).unwrap(), raw);
        assert_eq!(BIG.idle().len(), 1);
    }
}
