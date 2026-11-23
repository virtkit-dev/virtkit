//! zstd contexts kept between operations.
//!
//! For a large store frame, zstd's tables, window and stream buffers take about 1 MiB
//! to decode and 1.3 MiB to compress. The root `Cargo.toml` enables `with-rust-allocator`
//! so jemalloc handles these allocations on musl. A fresh context per blob repeats
//! workspace allocation and compressor table setup. Touching pages the allocator
//! released also incurs page faults. Each reused encoder writes the same frame bytes as
//! a fresh one.
//!
//! zstd's high-level reader and writer create a context or borrow one from the caller.
//! A streamed HTTP body needs a `'static` reader, so the `zstd::stream::zio` adapters
//! used here own their pooled contexts.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

use zstd::stream::raw::{CParameter, InBuffer, Operation, OutBuffer, WriteBuf};
use zstd::stream::zio;
use zstd::zstd_safe::{self, CCtx, DCtx, ResetDirective};

/// Idle contexts kept per pool, 128 MiB at most. A full pool frees any additional
/// context returned to it.
const MAX_IDLE: usize = 16;

/// Per-context retention limit in bytes, several times the workspace for a store
/// frame. A sender can choose a large decode window for a pushed or pulled frame.
const MAX_KEPT: usize = 8 << 20;

pub(crate) trait Context: Sized {
    fn create() -> Option<Self>;
    /// Reset the session and its parameters, even after an abandoned frame or an error.
    /// Return `false` if the reset fails.
    fn renew(&mut self) -> bool;
    /// Bytes allocated to the context.
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

fn zstd_error(code: usize) -> io::Error {
    io::Error::other(zstd_safe::get_error_name(code))
}

/// Pooled equivalent of `zstd::stream::raw::Decoder` for the read paths, which never
/// call `flush`.
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

/// Write one frame at [`crate::ZSTD_LEVEL`] with its content size in the header.
/// The input length must match `raw_len`. Calling [`finish`] as the first operation
/// overrides the pledge and writes an empty frame.
pub(crate) fn encoder<W: Write>(writer: W, raw_len: u64) -> io::Result<Encoder<W>> {
    encoder_from(&ENCODERS, writer, Some(raw_len))
}

/// Write one frame to `writer` at [`crate::ZSTD_LEVEL`] with no pledged size. Its
/// header carries no size unless the frame is empty.
pub(crate) fn encoder_unsized<W: Write>(writer: W) -> io::Result<Encoder<W>> {
    encoder_from(&ENCODERS, writer, None)
}

fn encoder_from<W: Write>(
    pool: &'static Pool<CCtx<'static>>,
    writer: W,
    raw_len: Option<u64>,
) -> io::Result<Encoder<W>> {
    let mut pooled = pool.take()?;
    let ctx = pooled.ctx()?;
    ctx.set_parameter(CParameter::CompressionLevel(crate::ZSTD_LEVEL))
        .map_err(zstd_error)?;
    if let Some(raw_len) = raw_len {
        ctx.set_pledged_src_size(Some(raw_len))
            .map_err(zstd_error)?;
        ctx.set_parameter(CParameter::ContentSizeFlag(true))
            .map_err(zstd_error)?;
    }
    Ok(zio::Writer::new(writer, pooled))
}

/// Finish the frame and return the underlying writer.
pub(crate) fn finish<W: Write>(mut encoder: Encoder<W>) -> io::Result<W> {
    encoder.finish()?;
    Ok(encoder.into_inner().0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Partly compressible test data with a repeatable mix of random and patterned bytes.
    pub(crate) fn sample(len: usize, seed: u64) -> Vec<u8> {
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
        let mut enc = encoder_from(pool, Vec::new(), Some(raw.len() as u64)).unwrap();
        enc.write_all(raw).unwrap();
        finish(enc).unwrap()
    }

    fn encode_unsized(pool: &'static Pool<CCtx<'static>>, raw: &[u8]) -> Vec<u8> {
        let mut enc = encoder_from(pool, Vec::new(), None).unwrap();
        enc.write_all(raw).unwrap();
        finish(enc).unwrap()
    }

    fn decode(pool: &'static Pool<DCtx<'static>>, frames: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        decoder_from(pool, frames)?.read_to_end(&mut out)?;
        Ok(out)
    }

    /// On the shared pool, [`decode_all`] matches `zstd::decode_all` on concatenated
    /// frames and fails on a truncated final frame.
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

    /// A frame declaring more than [`decode_all`] reserves up front still decodes whole.
    #[test]
    fn decode_all_reads_past_its_reservation() {
        let raw = vec![7u8; 40 << 20];
        // Avoid printing two 40 MiB buffers on failure.
        assert!(decode_all(&reference_frame(&raw)).unwrap() == raw);
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

    /// Reused and fresh encoders must produce identical unsized frames after larger,
    /// smaller or sized writes.
    #[test]
    fn a_reused_encoder_writes_the_unsized_frames_a_new_one_does() {
        static POOL: Pool<CCtx<'static>> = Pool::new();
        for (len, seed) in [
            (0, 31),
            (1, 32),
            (100_000, 33),
            (16 << 20, 34),
            (300, 35),
            (5 << 20, 36),
            (70_000, 37),
        ] {
            let raw = sample(len, seed);
            let mut fresh =
                zstd::stream::write::Encoder::new(Vec::new(), crate::ZSTD_LEVEL).unwrap();
            fresh.write_all(&raw).unwrap();
            let frame = encode_unsized(&POOL, &raw);
            assert_eq!(frame, fresh.finish().unwrap(), "{len} bytes");
            // zstd knows the size of an empty frame when it ends it.
            assert_eq!(
                zstd_safe::get_frame_content_size(&frame).ok().flatten(),
                (len == 0).then_some(0),
                "{len} bytes"
            );
            assert_eq!(POOL.idle().len(), 1, "the context went back to the pool");
            // A sized frame in between leaves neither its pledge nor its flag behind.
            assert_eq!(encode(&POOL, &raw), reference_frame(&raw), "{len} bytes");
        }
    }

    /// An abandoned or failed frame leaves no state in the next encoding.
    #[test]
    fn an_abandoned_encoder_is_reset_before_reuse() {
        static POOL: Pool<CCtx<'static>> = Pool::new();
        let raw = sample(400_000, 8);

        let mut enc = encoder_from(&POOL, Vec::new(), Some(raw.len() as u64)).unwrap();
        enc.write_all(&raw[..raw.len() / 2]).unwrap();
        drop(enc);
        assert_eq!(POOL.idle().len(), 1);
        assert_eq!(encode(&POOL, &raw), reference_frame(&raw));

        // Finishing with fewer bytes than pledged fails.
        let mut enc = encoder_from(&POOL, Vec::new(), Some(raw.len() as u64)).unwrap();
        enc.write_all(&raw[..10]).unwrap();
        assert!(finish(enc).is_err(), "a short frame must not finish");
        assert_eq!(POOL.idle().len(), 1);
        assert_eq!(encode(&POOL, &raw), reference_frame(&raw));

        // Finishing immediately overrides the pledge.
        let enc = encoder_from(&POOL, Vec::new(), Some(raw.len() as u64)).unwrap();
        assert_eq!(finish(enc).unwrap(), reference_frame(&[]));
        assert_eq!(encode(&POOL, &raw), reference_frame(&raw));
    }

    /// Threads sharing a pool each get a context of their own and write the frames a
    /// fresh encoder does.
    #[test]
    fn concurrent_encoders_do_not_share_a_context() {
        static POOL: Pool<CCtx<'static>> = Pool::new();
        std::thread::scope(|scope| {
            for seed in 50..58 {
                scope.spawn(move || {
                    for round in 0..20 {
                        let raw = sample(50_000 + 7_000 * round, seed + round as u64);
                        assert_eq!(encode(&POOL, &raw), reference_frame(&raw));
                    }
                });
            }
        });
        let idle = POOL.idle().len();
        assert!((1..=8).contains(&idle), "{idle} idle contexts");
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

        let cut = decode(&POOL, &fb[..fb.len() / 2]).unwrap_err();
        assert_eq!(cut.kind(), io::ErrorKind::UnexpectedEof, "{cut}");
        let mut head = [0u8; 1000];
        decoder_from(&POOL, &fb[..])
            .unwrap()
            .read_exact(&mut head)
            .unwrap();
        assert_eq!(head[..], b[..1000]);
        assert_eq!(decode(&POOL, &fa).unwrap(), a);

        // Corrupt compressed data can decode successfully to different bytes.
        assert!(decode(&POOL, b"not a zstd frame").is_err());
        let mut corrupt = fa.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid..mid + 64].fill(0xff);
        assert_ne!(decode(&POOL, &corrupt).ok(), Some(a.clone()));
        assert_eq!(decode(&POOL, &fa).unwrap(), a);

        assert_eq!(POOL.idle().len(), 1, "one context served them all");
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
        assert_eq!(BIG.idle().len(), 0, "an outsized context is not kept");
        // The same input in the store's frame format fits within the limit.
        assert_eq!(decode(&BIG, &reference_frame(&raw)).unwrap(), raw);
        assert_eq!(BIG.idle().len(), 1);
    }
}
