//! A read-only [`imago::Storage`] backend for `.vk_ro_img` manifests.
//!
//! A `.vk_ro_img` file is written by vk-driver instead of a fully reassembled raw ext4 when
//! restoring a cached build-stage image: it lists the content-addressed, zstd-compressed
//! chunks that tile the image (offset-sorted and non-overlapping, but not necessarily
//! contiguous — a gap between chunks reads as zero) plus the local chunk-cache directory they
//! live in, but holds none of the chunk bytes itself. `LazyChunkStorage` decompresses each
//! chunk lazily, the first time a guest read actually touches it, instead of vk-driver eagerly
//! decompressing the whole image up front.
//!
//! This is deliberately local-disk-only: vk-driver is responsible for ensuring every chunk
//! blob referenced by the manifest is already present in the cache directory before it
//! attaches a `.vk_ro_img` disk (fetching over the network, if needed, happens there) — this
//! module only ever does `std::fs::read` + zstd decode, so it pulls no network/async runtime
//! dependency into libkrun.
//!
//! ## `.vk_ro_img` format
//!
//! Both this reader and vk-driver's writer (`vk-driver/src/registry.rs`) hand-encode this
//! layout independently — there is no shared crate between the two workspaces — so a change
//! here must be mirrored there and vice versa.
//!
//! ```text
//! magic:          [u8; 8]   = b"VKROIMG1"
//! total_size:     u64 LE    // virtual size of the image this is a lazy view of
//! layout:         u8        // 0 = flat, 1 = store_root — see `Layout` below
//! cache_dir_len:  u32 LE
//! cache_dir:      [u8; cache_dir_len]   // UTF-8 path; meaning depends on `layout`
//! chunk_count:    u64 LE
//! chunks:         [ChunkEntry; chunk_count], offset-sorted, non-overlapping, gaps read as
//!                 zero, within [0, total_size)
//!
//! ChunkEntry:
//!   offset:       u64 LE   // position in the reassembled image
//!   length:       u32 LE   // decompressed length
//!   codec:        u8       // 0 = zstd, 1 = raw (stored blob already uncompressed)
//!   digest:       [u8; 32] // raw sha256 of the *stored* blob; cache filename is its hex form
//! ```
//!
//! `layout` picks how a chunk's digest maps to a path under `cache_dir`, matching vk-driver's
//! two registry backends:
//! - `flat` (remote registry): `cache_dir/<hex>` — one flat, homogeneously-compressed cache
//!   (`state_dir/registry/chunks/`).
//! - `store_root` (local registry, `vk_registry::Store`): `cache_dir/blobs/zstd/<hex>` or
//!   `cache_dir/blobs/sha256/<hex>` depending on `codec` — `Store` adaptively picks whichever
//!   form is smaller per blob, so the two live in sibling directories under one root.

use imago::io_buffers::{IoVector, IoVectorMut};
use imago::storage::drivers::CommonStorageHelper;
use imago::{Storage, StorageCreateOptions, StorageOpenOptions};
use maybe_async::maybe_async;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 8] = b"VKROIMG1";
const CODEC_ZSTD: u8 = 0;
const CODEC_RAW: u8 = 1;
const LAYOUT_FLAT: u8 = 0;
const LAYOUT_STORE_ROOT: u8 = 1;

/// How many decompressed chunks to keep in memory. Guest reads are far smaller than a
/// chunk (ext4-block-ish), so without this, adjacent small reads within one chunk would
/// redecompress it repeatedly.
const DECODED_CACHE_ENTRIES: usize = 128;
/// Encoded size of one `ChunkEntry`: offset (8) + length (4) + codec (1) + digest (32).
const CHUNK_ENTRY_SIZE: u64 = 8 + 4 + 1 + 32;

struct ChunkEntry {
    offset: u64,
    length: u32,
    codec: u8,
    digest: [u8; 32],
}

/// Read-only lazy view over a `.vk_ro_img` manifest. See the module docs for the format.
pub struct LazyChunkStorage {
    filename: PathBuf,
    total_size: u64,
    layout: u8,
    cache_dir: PathBuf,
    /// Offset-sorted, non-overlapping, gaps read as zero, within `[0, total_size)` — see the
    /// format doc.
    chunks: Vec<ChunkEntry>,
    decoded: Mutex<lru::LruCache<usize, Arc<Vec<u8>>>>,
    common_storage_helper: CommonStorageHelper,
}

fn digest_hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for b in digest {
        write!(&mut hex, "{b:02x}").unwrap();
    }
    hex
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!(".vk_ro_img: {e}")))
}

impl LazyChunkStorage {
    fn parse(mut f: std::fs::File, filename: PathBuf) -> io::Result<Self> {
        let file_len = f.metadata()?.len();
        let mut magic = [0u8; 8];
        read_exact_or_eof(&mut f, &mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                ".vk_ro_img: bad magic",
            ));
        }
        let mut u64buf = [0u8; 8];
        read_exact_or_eof(&mut f, &mut u64buf)?;
        let total_size = u64::from_le_bytes(u64buf);

        let mut layout_buf = [0u8; 1];
        read_exact_or_eof(&mut f, &mut layout_buf)?;
        let layout = layout_buf[0];
        if layout != LAYOUT_FLAT && layout != LAYOUT_STORE_ROOT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(".vk_ro_img: unknown layout {layout}"),
            ));
        }

        let mut u32buf = [0u8; 4];
        read_exact_or_eof(&mut f, &mut u32buf)?;
        let cache_dir_len = u32::from_le_bytes(u32buf) as usize;
        if cache_dir_len as u64 > file_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(".vk_ro_img: cache_dir_len {cache_dir_len} exceeds file size {file_len}"),
            ));
        }
        let mut cache_dir_bytes = vec![0u8; cache_dir_len];
        read_exact_or_eof(&mut f, &mut cache_dir_bytes)?;
        let cache_dir =
            PathBuf::from(String::from_utf8(cache_dir_bytes).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!(".vk_ro_img: {e}"))
            })?);

        read_exact_or_eof(&mut f, &mut u64buf)?;
        let chunk_count = u64::from_le_bytes(u64buf) as usize;
        if (chunk_count as u64).saturating_mul(CHUNK_ENTRY_SIZE) > file_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(".vk_ro_img: chunk_count {chunk_count} exceeds file size {file_len}"),
            ));
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        let mut expect_offset = 0u64;
        for _ in 0..chunk_count {
            read_exact_or_eof(&mut f, &mut u64buf)?;
            let offset = u64::from_le_bytes(u64buf);
            read_exact_or_eof(&mut f, &mut u32buf)?;
            let length = u32::from_le_bytes(u32buf);
            let mut codec = [0u8; 1];
            read_exact_or_eof(&mut f, &mut codec)?;
            let mut digest = [0u8; 32];
            read_exact_or_eof(&mut f, &mut digest)?;
            // Chunks are offset-sorted and non-overlapping, but NOT necessarily contiguous: a
            // diff push can drop a region that went fully back to zero since its parent
            // instead of re-chunking it (see vk-driver's `push_ext4_diff`) — a gap here reads
            // as zero, exactly like the eager reassembly path leaves it an untouched hole.
            if offset < expect_offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(".vk_ro_img: overlapping chunk at offset {offset}"),
                ));
            }
            expect_offset = offset.checked_add(length as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, ".vk_ro_img: overflow")
            })?;
            chunks.push(ChunkEntry {
                offset,
                length,
                codec: codec[0],
                digest,
            });
        }
        if expect_offset > total_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    ".vk_ro_img: chunks cover {expect_offset} bytes, expected at most {total_size}"
                ),
            ));
        }

        Ok(LazyChunkStorage {
            filename,
            total_size,
            layout,
            cache_dir,
            chunks,
            decoded: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(DECODED_CACHE_ENTRIES).unwrap(),
            )),
            common_storage_helper: Default::default(),
        })
    }

    fn chunk_path(&self, chunk: &ChunkEntry) -> PathBuf {
        let hex = digest_hex(&chunk.digest);
        match self.layout {
            LAYOUT_STORE_ROOT => {
                let sub = if chunk.codec == CODEC_ZSTD {
                    "blobs/zstd"
                } else {
                    "blobs/sha256"
                };
                self.cache_dir.join(sub).join(hex)
            }
            _ => self.cache_dir.join(hex),
        }
    }

    /// Decompressed bytes of chunk `idx`, from the decoded-chunk cache or freshly read off disk.
    ///
    /// Held across a cache-miss decode (not just the map lookup/insert) so two concurrent reads
    /// landing on the same not-yet-decoded chunk don't both hit disk and decompress redundantly.
    fn decode_chunk(&self, idx: usize) -> io::Result<Arc<Vec<u8>>> {
        let mut decoded = self.decoded.lock().unwrap();
        let data = decoded.try_get_or_insert(idx, || {
            let chunk = &self.chunks[idx];
            let path = self.chunk_path(chunk);
            let raw = std::fs::read(&path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "reading chunk {} for {}: {e}",
                        path.display(),
                        self.filename.display()
                    ),
                )
            })?;
            let data = match chunk.codec {
                CODEC_ZSTD => zstd::decode_all(&raw[..]).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("zstd-decompressing chunk {}: {e}", path.display()),
                    )
                })?,
                CODEC_RAW => raw,
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("chunk {}: unknown codec {other}", path.display()),
                    ));
                }
            };
            if data.len() != chunk.length as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "chunk {}: decompressed to {} bytes, expected {}",
                        path.display(),
                        data.len(),
                        chunk.length
                    ),
                ));
            }
            Ok(Arc::new(data))
        })?;
        Ok(Arc::clone(data))
    }

    /// Index of the first chunk that could contain or come after byte `pos` — either the
    /// chunk covering `pos`, or (if `pos` falls in a gap) the next chunk after the gap, or
    /// `chunks.len()` if `pos` is at or past the last chunk's end (a trailing gap to EOF).
    fn chunk_at(&self, pos: u64) -> usize {
        self.chunks
            .partition_point(|c| c.offset + c.length as u64 <= pos)
    }

    fn read_range(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or_else(|| io::Error::other("read offset overflow"))?;
        let mut pos = offset;
        while pos < end {
            if pos >= self.total_size {
                // Past EOF: `Storage::pure_readv` fills the rest with zeroes.
                out[(pos - offset) as usize..].fill(0);
                break;
            }
            let idx = self.chunk_at(pos);
            let in_gap = idx >= self.chunks.len() || self.chunks[idx].offset > pos;
            let copy_end = if in_gap {
                // A gap (dropped by a diff push because it went back to zero) reads as
                // zero, up to wherever the next chunk starts (or EOF).
                let gap_end = self
                    .chunks
                    .get(idx)
                    .map(|c| c.offset)
                    .unwrap_or(self.total_size)
                    .min(end);
                out[(pos - offset) as usize..(gap_end - offset) as usize].fill(0);
                gap_end
            } else {
                let chunk = &self.chunks[idx];
                let chunk_end = chunk.offset + chunk.length as u64;
                let data = self.decode_chunk(idx)?;
                let copy_end = chunk_end.min(end);
                let src = &data[(pos - chunk.offset) as usize..(copy_end - chunk.offset) as usize];
                let dst_start = (pos - offset) as usize;
                out[dst_start..dst_start + src.len()].copy_from_slice(src);
                copy_end
            };
            pos = copy_end;
        }
        Ok(())
    }
}

impl fmt::Debug for LazyChunkStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyChunkStorage")
            .field("filename", &self.filename)
            .field("total_size", &self.total_size)
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

impl Display for LazyChunkStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "vk_ro_img:{:?}", self.filename)
    }
}

#[maybe_async(AFIT)]
impl Storage for LazyChunkStorage {
    async fn open(opts: StorageOpenOptions) -> io::Result<Self> {
        // `opts.write`/`opts.direct` have no public getters on `StorageOpenOptions` (only
        // `get_filename` does) — a caller requesting O_DIRECT or writable semantics can't be
        // detected or honored here; the read-only, page-cache-backed `std::fs::read` this
        // module does is unconditional.
        let Some(filename) = opts.get_filename() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Filename required",
            ));
        };
        let filename = filename.to_path_buf();
        let f = std::fs::File::open(&filename)?;
        Self::parse(f, filename)
    }

    async fn create_open(_opts: StorageCreateOptions) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.total_size)
    }

    fn get_filename(&self) -> Option<PathBuf> {
        Some(self.filename.clone())
    }

    async unsafe fn pure_readv(&self, mut bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        let mut out = vec![0u8; bufv.len() as usize];
        self.read_range(offset, &mut out)?;
        bufv.copy_from_slice(&out);
        Ok(())
    }

    async unsafe fn pure_writev(&self, _bufv: IoVector<'_>, _offset: u64) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    async unsafe fn invalidate_cache(&self) -> io::Result<()> {
        self.decoded.lock().unwrap().clear();
        Ok(())
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        &self.common_storage_helper
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Digest bytes derived from a small counter so each test chunk gets a distinct,
    /// deterministic "hash" without pulling in a real sha256 dependency just for tests.
    fn fake_digest(n: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[31] = n;
        d
    }

    /// Build a `.vk_ro_img` manifest by hand (mirroring `LazyChunkStorage::parse`'s
    /// expected byte layout) plus the chunk blob files it references, and open it.
    struct Fixture {
        dir: std::path::PathBuf,
    }
    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vk-lazy-chunk-storage-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Fixture { dir }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn write_manifest(
        path: &std::path::Path,
        total_size: u64,
        layout: u8,
        cache_dir: &std::path::Path,
        chunks: &[(u64, u32, u8, [u8; 32])],
    ) {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&total_size.to_le_bytes());
        buf.push(layout);
        let cache_dir_bytes = cache_dir.to_str().unwrap().as_bytes();
        buf.extend_from_slice(&(cache_dir_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(cache_dir_bytes);
        buf.extend_from_slice(&(chunks.len() as u64).to_le_bytes());
        for &(offset, length, codec, digest) in chunks {
            buf.extend_from_slice(&offset.to_le_bytes());
            buf.extend_from_slice(&length.to_le_bytes());
            buf.push(codec);
            buf.extend_from_slice(&digest);
        }
        std::fs::write(path, buf).unwrap();
    }

    /// Two chunks — one zstd, one raw — laid out flat (remote-registry style): reads
    /// spanning both, exactly at the boundary, and fully within one, all reassemble the
    /// original bytes.
    #[test]
    fn reads_across_chunk_boundaries_flat_layout() {
        let fx = Fixture::new("flat");
        let chunk_a: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let chunk_b: Vec<u8> = (0..3000u32).map(|i| ((i * 7) % 251) as u8).collect();
        let digest_a = fake_digest(1);
        let digest_b = fake_digest(2);
        let compressed_a = zstd::encode_all(&chunk_a[..], 3).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_a)), &compressed_a).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_b)), &chunk_b).unwrap();

        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            (chunk_a.len() + chunk_b.len()) as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, chunk_a.len() as u32, CODEC_ZSTD, digest_a),
                (
                    chunk_a.len() as u64,
                    chunk_b.len() as u32,
                    CODEC_RAW,
                    digest_b,
                ),
            ],
        );

        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        assert_eq!(
            storage.size().unwrap(),
            (chunk_a.len() + chunk_b.len()) as u64
        );

        let mut whole = chunk_a.clone();
        whole.extend_from_slice(&chunk_b);

        // Fully within chunk_a.
        let mut out = vec![0u8; 100];
        storage.read_range(10, &mut out).unwrap();
        assert_eq!(out, whole[10..110]);

        // Spans the boundary between chunk_a and chunk_b.
        let mut out = vec![0u8; 40];
        let start = chunk_a.len() as u64 - 20;
        storage.read_range(start, &mut out).unwrap();
        assert_eq!(out, whole[start as usize..start as usize + 40]);

        // Fully within chunk_b.
        let mut out = vec![0u8; 50];
        storage
            .read_range(chunk_a.len() as u64 + 10, &mut out)
            .unwrap();
        assert_eq!(out, whole[chunk_a.len() + 10..chunk_a.len() + 60]);

        // The whole image in one read.
        let mut out = vec![0u8; whole.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, whole);
    }

    /// `store_root` layout: a zstd chunk lives under `blobs/zstd/`, a raw one under
    /// `blobs/sha256/` — same directory root, picked per chunk by `codec`, matching
    /// `vk_registry::Store`'s adaptive on-disk layout.
    #[test]
    fn store_root_layout_picks_the_right_subdirectory_per_codec() {
        let fx = Fixture::new("store-root");
        std::fs::create_dir_all(fx.dir.join("blobs/zstd")).unwrap();
        std::fs::create_dir_all(fx.dir.join("blobs/sha256")).unwrap();
        let chunk_a: Vec<u8> = vec![0xAB; 2000];
        let chunk_b: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        let digest_a = fake_digest(3);
        let digest_b = fake_digest(4);
        std::fs::write(
            fx.dir.join("blobs/zstd").join(digest_hex(&digest_a)),
            zstd::encode_all(&chunk_a[..], 3).unwrap(),
        )
        .unwrap();
        std::fs::write(
            fx.dir.join("blobs/sha256").join(digest_hex(&digest_b)),
            &chunk_b,
        )
        .unwrap();

        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            (chunk_a.len() + chunk_b.len()) as u64,
            LAYOUT_STORE_ROOT,
            &fx.dir,
            &[
                (0, chunk_a.len() as u32, CODEC_ZSTD, digest_a),
                (
                    chunk_a.len() as u64,
                    chunk_b.len() as u32,
                    CODEC_RAW,
                    digest_b,
                ),
            ],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        let mut whole = chunk_a.clone();
        whole.extend_from_slice(&chunk_b);
        let mut out = vec![0u8; whole.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, whole);
    }

    /// A gap between chunks (a diff push drops a region that went back to zero since its
    /// parent instead of re-chunking it — see `push_ext4_diff` in vk-driver) reads as zero,
    /// exactly like the eager reassembly path leaves it an untouched hole. Also covers a
    /// trailing gap between the last chunk and `total_size`.
    #[test]
    fn gaps_between_chunks_read_as_zero() {
        let fx = Fixture::new("gap");
        let chunk_a = vec![0xAAu8; 100];
        let chunk_c = vec![0xCCu8; 100];
        let digest_a = fake_digest(1);
        let digest_c = fake_digest(2);
        std::fs::write(fx.dir.join(digest_hex(&digest_a)), &chunk_a).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest_c)), &chunk_c).unwrap();

        let manifest = fx.dir.join("test.vk_ro_img");
        // [0,100) = chunk_a, [100,150) = gap, [150,250) = chunk_c, [250,300) = trailing gap.
        write_manifest(
            &manifest,
            300,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, 100, CODEC_RAW, digest_a),
                (150, 100, CODEC_RAW, digest_c),
            ],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();

        let mut want = vec![0u8; 300];
        want[0..100].copy_from_slice(&chunk_a);
        want[150..250].copy_from_slice(&chunk_c);

        let mut out = vec![0u8; 300];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, want, "whole-image read must zero-fill both gaps");

        // A read entirely inside the inter-chunk gap.
        let mut out = vec![0u8; 20];
        storage.read_range(110, &mut out).unwrap();
        assert_eq!(out, vec![0u8; 20]);

        // A read spanning chunk_a's tail, the gap, and chunk_c's head.
        let mut out = vec![0u8; 100];
        storage.read_range(80, &mut out).unwrap();
        assert_eq!(out, want[80..180]);
    }

    /// Overlapping chunks (offsets going backwards) are a corrupt manifest, unlike a gap —
    /// reject it rather than silently misplacing reads.
    #[test]
    fn rejects_overlapping_chunks() {
        let fx = Fixture::new("overlap");
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            150,
            LAYOUT_FLAT,
            &fx.dir,
            &[
                (0, 100, CODEC_RAW, fake_digest(1)),
                (50, 100, CODEC_RAW, fake_digest(2)),
            ],
        );
        let err =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A decoded chunk is cached: a second read into the same chunk must not need the
    /// backing blob file any more (deleting it between reads still succeeds).
    #[test]
    fn decoded_chunks_are_cached_across_reads() {
        let fx = Fixture::new("cache");
        let chunk: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let digest = fake_digest(9);
        let path = fx.dir.join(digest_hex(&digest));
        std::fs::write(&path, &chunk).unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            chunk.len() as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, chunk.len() as u32, CODEC_RAW, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        let mut out = vec![0u8; chunk.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, chunk);
        std::fs::remove_file(&path).unwrap();
        let mut out2 = vec![0u8; chunk.len()];
        storage.read_range(0, &mut out2).unwrap();
        assert_eq!(
            out2, chunk,
            "second read should hit the decoded-chunk cache"
        );
    }

    /// `invalidate_cache` drops decoded chunks, so a read afterwards must go back to the
    /// backing blob file (and fail once that file is gone).
    #[test]
    fn invalidate_cache_forces_redecode() {
        let fx = Fixture::new("invalidate");
        let chunk: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let digest = fake_digest(9);
        let path = fx.dir.join(digest_hex(&digest));
        std::fs::write(&path, &chunk).unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            chunk.len() as u64,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, chunk.len() as u32, CODEC_RAW, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest.clone())
                .unwrap();
        let mut out = vec![0u8; chunk.len()];
        storage.read_range(0, &mut out).unwrap();
        assert_eq!(out, chunk);

        std::fs::remove_file(&path).unwrap();
        unsafe { storage.invalidate_cache() }.unwrap();
        storage
            .read_range(0, &mut out)
            .expect_err("cache was invalidated, blob file is gone");
    }

    /// A `cache_dir_len` (or `chunk_count`) bigger than the whole manifest file can't possibly
    /// be legitimate — a corrupted or truncated `.vk_ro_img` must fail cleanly instead of
    /// driving an unbounded allocation.
    #[test]
    fn rejects_length_fields_that_exceed_the_file_size() {
        let fx = Fixture::new("oversized-lengths");

        let bad_cache_dir_len = fx.dir.join("bad_cache_dir_len.vk_ro_img");
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.push(LAYOUT_FLAT);
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&bad_cache_dir_len, &buf).unwrap();
        let err = LazyChunkStorage::parse(
            std::fs::File::open(&bad_cache_dir_len).unwrap(),
            bad_cache_dir_len,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let bad_chunk_count = fx.dir.join("bad_chunk_count.vk_ro_img");
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.push(LAYOUT_FLAT);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&u64::MAX.to_le_bytes());
        std::fs::write(&bad_chunk_count, &buf).unwrap();
        let err = LazyChunkStorage::parse(
            std::fs::File::open(&bad_chunk_count).unwrap(),
            bad_chunk_count,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A header that ends mid-field (crash mid-write, truncated copy) must be reported as
    /// `InvalidData`, not panic or silently read garbage.
    #[test]
    fn rejects_truncated_header() {
        let fx = Fixture::new("truncated");
        let manifest = fx.dir.join("test.vk_ro_img");
        std::fs::write(&manifest, &MAGIC[..4]).unwrap();
        let err =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A chunk blob whose bytes aren't a valid zstd frame must surface as `InvalidData`
    /// instead of panicking the decode.
    #[test]
    fn rejects_corrupt_zstd_chunk() {
        let fx = Fixture::new("corrupt-zstd");
        let digest = fake_digest(1);
        std::fs::write(fx.dir.join(digest_hex(&digest)), b"not a zstd frame").unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        write_manifest(
            &manifest,
            100,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, 100, CODEC_ZSTD, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
        let mut out = vec![0u8; 100];
        let err = storage.read_range(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A chunk that decompresses to a different length than the manifest declared must be
    /// rejected rather than silently reassembled with the wrong bytes.
    #[test]
    fn rejects_decompressed_length_mismatch() {
        let fx = Fixture::new("length-mismatch");
        let chunk: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let digest = fake_digest(1);
        let compressed = zstd::encode_all(&chunk[..], 3).unwrap();
        std::fs::write(fx.dir.join(digest_hex(&digest)), &compressed).unwrap();
        let manifest = fx.dir.join("test.vk_ro_img");
        // Manifest claims 200 bytes; the blob actually decompresses to 100.
        write_manifest(
            &manifest,
            200,
            LAYOUT_FLAT,
            &fx.dir,
            &[(0, 200, CODEC_ZSTD, digest)],
        );
        let storage =
            LazyChunkStorage::parse(std::fs::File::open(&manifest).unwrap(), manifest).unwrap();
        let mut out = vec![0u8; 200];
        let err = storage.read_range(0, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
