//! Minimal streamOptimized VMDK writer — packages a raw disk image (a `vk build
//! --disk` artifact) as the compressed VMDK subformat vSphere's OVF/OVA import
//! requires, with no external tools (no qemu-img). The ext4.rs/qcow2.rs of the
//! VMware boundary.
//!
//! Layout (VMware Virtual Disk Format spec, "streamOptimized compressed extent"),
//! written strictly front-to-back so a reader can consume it as a stream — ESXi
//! imports an OVA's disk over HTTP without seeking, which is the whole point of
//! the subformat:
//!
//! ```text
//! sector 0        sparse-extent header, grain directory deferred (gdOffset = -1)
//! sectors 1..21   embedded plain-text descriptor
//! (pad to 128)    the customary metadata overhead readers expect
//! grains          one deflate-compressed grain per non-zero 64 KiB of input,
//!                 each led by a 12-byte {lba, size} grain marker, sector-padded;
//!                 an all-zero grain is skipped (its table entry stays 0)
//! grain tables    each led by a metadata marker (type 1)
//! grain directory led by a metadata marker (type 2); entries point at the tables
//! footer          led by a metadata marker (type 3); the header with gdOffset
//!                 resolved to the directory — the one readers trust
//! end-of-stream   an all-zero marker sector (type 0)
//! ```
//!
//! Scope: writing only, one extent, 64 KiB grains, deflate — exactly what `vk
//! export` produces. Reading VMDKs is out of scope.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

const SECTOR: u64 = 512;
/// 64 KiB grains — the spec constant for streamOptimized (and every VMDK in practice).
const GRAIN_SECTORS: u64 = 128;
const GRAIN_BYTES: usize = (GRAIN_SECTORS * SECTOR) as usize;
/// Grains per grain table; a table is thus 512 × 4 B = 4 sectors covering 32 MiB.
const GTES_PER_GT: usize = 512;
const GT_SECTORS: u64 = (GTES_PER_GT * 4) as u64 / SECTOR;
/// "KDMV" little-endian.
const MAGIC: u32 = 0x564d_444b;
/// Header flags: bit 0 = the newline-detection chars are valid, bit 16 = grains are
/// compressed, bit 17 = markers present. Exactly the streamOptimized triple.
const FLAGS: u32 = 0x0003_0001;
/// `gdOffset` in the stream header: the directory's position is only known at the
/// end, so the header defers to the footer.
const GD_AT_END: u64 = u64::MAX;
/// Where grains start. Only the header + descriptor actually precede them, but 128
/// sectors is the metadata overhead every writer reserves (qemu, VMware), so a
/// reader making assumptions sees the layout it knows.
const OVERHEAD_SECTORS: u64 = 128;
const DESCRIPTOR_SECTORS: u64 = 20;

/// Metadata marker types (the u32 at byte 12 of a marker sector).
const MARKER_EOS: u32 = 0;
const MARKER_GT: u32 = 1;
const MARKER_GD: u32 = 2;
const MARKER_FOOTER: u32 = 3;

/// What a conversion produced, for the caller's report (and the OVF descriptor:
/// `capacity` is the disk's virtual size, `written` roughly its populated size).
#[derive(Debug)]
pub struct VmdkInfo {
    /// virtual disk size in bytes (== the raw input's size)
    pub capacity: u64,
    /// bytes of VMDK actually written
    pub written: u64,
}

/// Package the raw disk image `src` as a streamOptimized VMDK at `dst`. The input
/// must be whole sectors (any real disk image is); all-zero grains are elided, so
/// a mostly-empty disk stays small without needing the input to be sparse.
pub fn write_stream_optimized(src: &Path, dst: &Path) -> Result<VmdkInfo> {
    let input = File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let len = input
        .metadata()
        .with_context(|| format!("sizing {}", src.display()))?
        .len();
    if len == 0 || len % SECTOR != 0 {
        bail!(
            "{}: {len} bytes is not a whole number of 512-byte sectors — not a raw disk image",
            src.display()
        );
    }
    let capacity_sectors = len / SECTOR;
    let grains = len.div_ceil(GRAIN_BYTES as u64) as usize;

    let mut reader = BufReader::with_capacity(GRAIN_BYTES, input);
    let out = File::create(dst).with_context(|| format!("creating {}", dst.display()))?;
    let mut w = CountingWriter {
        inner: BufWriter::new(out),
        written: 0,
    };

    // The descriptor names the extent after the output file, per convention.
    let name = dst
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "disk.vmdk".to_string());
    if name.contains('"') || name.bytes().any(|b| b.is_ascii_control()) {
        bail!(
            "output name {name:?} cannot carry a '\"' or control characters (it is quoted \
             in the plain-text descriptor, and a newline would open a descriptor line)"
        );
    }

    // Header (directory deferred to the footer), a zeroed descriptor slot, and the
    // pad up to the overhead where grains start. The descriptor carries the CID — a
    // checksum of the disk content folded over the grain loop below — so its slot is
    // patched in place at the end. Only this WRITER seeks for that; the produced
    // file stays strictly stream-readable, which is the property importers need.
    w.write_all(&header(capacity_sectors, GD_AT_END))?;
    w.write_all(&vec![0u8; ((OVERHEAD_SECTORS - 1) * SECTOR) as usize])?;

    let mut crc = flate2::Crc::new();
    let mut gtes: Vec<u32> = vec![0; grains];
    let mut cur_sector = OVERHEAD_SECTORS;
    let mut buf = vec![0u8; GRAIN_BYTES];
    let mut remaining = len;
    for (i, gte) in gtes.iter_mut().enumerate() {
        let take = remaining.min(GRAIN_BYTES as u64) as usize;
        reader
            .read_exact(&mut buf[..take])
            .with_context(|| format!("reading {}", src.display()))?;
        remaining -= take as u64;
        // A short final grain compresses zero-padded to the full grain, per spec.
        buf[take..].fill(0);
        crc.update(&buf[..take]);
        if buf.iter().all(|&b| b == 0) {
            continue; // unallocated: reads back as zeros
        }
        let compressed = deflate(&buf)?;
        *gte = u32::try_from(cur_sector).context("VMDK larger than a u32 of sectors")?;
        // Grain marker: {u64 lba, u32 compressed size}, data at byte 12, sector-padded.
        w.write_all(&(i as u64 * GRAIN_SECTORS).to_le_bytes())?;
        w.write_all(&(compressed.len() as u32).to_le_bytes())?;
        w.write_all(&compressed)?;
        let total = 12 + compressed.len() as u64;
        let padded = total.div_ceil(SECTOR) * SECTOR;
        w.write_all(&vec![0u8; (padded - total) as usize])?;
        cur_sector += padded / SECTOR;
    }

    // Grain tables, each announced by a marker; the directory collects their
    // data-sector positions.
    let mut gd: Vec<u32> = Vec::with_capacity(gtes.len().div_ceil(GTES_PER_GT));
    for chunk in gtes.chunks(GTES_PER_GT) {
        w.write_all(&metadata_marker(GT_SECTORS, MARKER_GT))?;
        cur_sector += 1;
        gd.push(u32::try_from(cur_sector).context("VMDK larger than a u32 of sectors")?);
        let mut table = Vec::with_capacity(GTES_PER_GT * 4);
        for gte in chunk {
            table.extend_from_slice(&gte.to_le_bytes());
        }
        table.resize(GTES_PER_GT * 4, 0);
        w.write_all(&table)?;
        cur_sector += GT_SECTORS;
    }

    // Grain directory + footer (the header with gdOffset resolved) + end-of-stream.
    let gd_bytes: Vec<u8> = gd.iter().flat_map(|e| e.to_le_bytes()).collect();
    let gd_sectors = (gd_bytes.len() as u64).div_ceil(SECTOR);
    w.write_all(&metadata_marker(gd_sectors, MARKER_GD))?;
    cur_sector += 1;
    let gd_offset = cur_sector;
    let mut padded_gd = gd_bytes;
    padded_gd.resize((gd_sectors * SECTOR) as usize, 0);
    w.write_all(&padded_gd)?;
    w.write_all(&metadata_marker(1, MARKER_FOOTER))?;
    w.write_all(&header(capacity_sectors, gd_offset))?;
    w.write_all(&metadata_marker(0, MARKER_EOS))?;
    let written = w.written;
    let file = w
        .inner
        .into_inner()
        .map_err(|e| anyhow::anyhow!("flushing the VMDK: {e}"))?;

    // Patch the descriptor into its reserved slot now the content CID is known.
    // 0xffffffff is the CID_NOPARENT sentinel; step past it deterministically.
    let cid = match crc.sum() {
        u32::MAX => 0,
        c => c,
    };
    let mut desc = descriptor(&name, capacity_sectors, cid).into_bytes();
    if desc.len() as u64 > DESCRIPTOR_SECTORS * SECTOR {
        bail!("descriptor overflows its {DESCRIPTOR_SECTORS}-sector slot");
    }
    desc.resize((DESCRIPTOR_SECTORS * SECTOR) as usize, 0);
    use std::os::unix::fs::FileExt;
    file.write_all_at(&desc, SECTOR)
        .context("writing the VMDK descriptor")?;
    file.sync_all().context("syncing the VMDK")?;

    Ok(VmdkInfo {
        capacity: len,
        written,
    })
}

/// One deflate (zlib) pass over a grain.
fn deflate(buf: &[u8]) -> Result<Vec<u8>> {
    let mut enc = flate2::write::ZlibEncoder::new(
        Vec::with_capacity(buf.len() / 4),
        flate2::Compression::default(),
    );
    enc.write_all(buf)?;
    Ok(enc.finish()?)
}

struct CountingWriter {
    inner: BufWriter<File>,
    written: u64,
}

impl CountingWriter {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.inner.write_all(buf).context("writing the VMDK")?;
        self.written += buf.len() as u64;
        Ok(())
    }
}

/// The 512-byte sparse-extent header; also the footer, with `gd_offset` resolved.
fn header(capacity_sectors: u64, gd_offset: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    let mut o = 0usize;
    let mut put = |bytes: &[u8]| {
        h[o..o + bytes.len()].copy_from_slice(bytes);
        o += bytes.len();
    };
    put(&MAGIC.to_le_bytes());
    put(&3u32.to_le_bytes()); // version
    put(&FLAGS.to_le_bytes());
    put(&capacity_sectors.to_le_bytes());
    put(&GRAIN_SECTORS.to_le_bytes());
    put(&1u64.to_le_bytes()); // descriptorOffset
    put(&DESCRIPTOR_SECTORS.to_le_bytes());
    put(&(GTES_PER_GT as u32).to_le_bytes());
    put(&0u64.to_le_bytes()); // rgdOffset: no redundant directory in a stream
    put(&gd_offset.to_le_bytes());
    put(&OVERHEAD_SECTORS.to_le_bytes());
    put(&[0u8]); // uncleanShutdown
    put(b"\n \r\n"); // newline-detection chars
    put(&1u16.to_le_bytes()); // compressAlgorithm: deflate
    h
}

/// The embedded plain-text descriptor. The CID is a checksum of the disk content,
/// so it changes exactly when the content does (VMware only requires it to change
/// on write; a content hash also keeps the output reproducible).
fn descriptor(name: &str, capacity_sectors: u64, cid: u32) -> String {
    // The standard virtual geometry for an lsilogic/scsi disk; cylinders capped at
    // the BIOS ceiling like every writer does.
    let cylinders = (capacity_sectors / (255 * 63)).min(16383);
    format!(
        "# Disk DescriptorFile\n\
         version=1\n\
         CID={cid:08x}\n\
         parentCID=ffffffff\n\
         createType=\"streamOptimized\"\n\
         \n\
         # Extent description\n\
         RW {capacity_sectors} SPARSE \"{name}\"\n\
         \n\
         # The Disk Data Base\n\
         #DDB\n\
         \n\
         ddb.adapterType = \"lsilogic\"\n\
         ddb.geometry.cylinders = \"{cylinders}\"\n\
         ddb.geometry.heads = \"255\"\n\
         ddb.geometry.sectors = \"63\"\n\
         ddb.virtualHWVersion = \"4\"\n"
    )
}

/// A 512-byte metadata marker: {u64 val, u32 size = 0, u32 type}, rest zero. `val`
/// is the number of data sectors that follow (the footer's 1, the EOS's 0).
fn metadata_marker(val: u64, typ: u32) -> [u8; 512] {
    let mut m = [0u8; 512];
    m[..8].copy_from_slice(&val.to_le_bytes());
    // bytes 8..12: size = 0 marks a metadata marker
    m[12..16].copy_from_slice(&typ.to_le_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    // Removes its directory on drop, so a panicking assertion cannot leak it.
    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let dir = std::env::temp_dir().join(format!("vk-vmdk-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TmpDir(dir)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Test-only reader: walk the stream exactly as an importer would — header,
    /// then the footer's directory, tables, and inflated grains — and rebuild the
    /// raw image alongside the flattened grain-table entries (0 = elided zero
    /// grain). Every structural assertion a consumer relies on lives here.
    fn decode(vmdk: &[u8]) -> (Vec<u8>, Vec<u32>) {
        let sector = |n: u64| &vmdk[(n * 512) as usize..(n * 512 + 512) as usize];
        let u32le = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64le = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());

        // Stream header: right magic/version/flags, directory deferred.
        let h = sector(0);
        assert_eq!(u32le(h, 0), MAGIC);
        assert_eq!(u32le(h, 4), 3, "version");
        assert_eq!(u32le(h, 8), FLAGS);
        let capacity = u64le(h, 12);
        assert_eq!(u64le(h, 20), GRAIN_SECTORS);
        assert_eq!(
            u64le(h, 56),
            GD_AT_END,
            "stream header defers the directory"
        );
        assert_eq!(
            u16::from_le_bytes(h[77..79].try_into().unwrap()),
            1,
            "deflate"
        );

        // Tail: ..., footer marker, footer, EOS (all-zero sector).
        let n = vmdk.len() as u64 / 512;
        assert!(
            sector(n - 1).iter().all(|&b| b == 0),
            "end-of-stream marker"
        );
        let fm = sector(n - 3);
        assert_eq!(
            (u64le(fm, 0), u32le(fm, 8), u32le(fm, 12)),
            (1, 0, MARKER_FOOTER)
        );
        let footer = sector(n - 2);
        assert_eq!(u32le(footer, 0), MAGIC);
        let gd_offset = u64le(footer, 56);
        assert_ne!(gd_offset, GD_AT_END, "footer resolves the directory");

        // Directory (marker precedes it) -> tables (markers precede them) -> grains.
        let gdm = sector(gd_offset - 1);
        assert_eq!((u32le(gdm, 8), u32le(gdm, 12)), (0, MARKER_GD));
        let grains = capacity.div_ceil(GRAIN_SECTORS) as usize;
        let num_gts = grains.div_ceil(GTES_PER_GT);
        let mut raw = vec![0u8; (capacity * 512) as usize];
        let mut gtes = Vec::with_capacity(grains);
        for gt_i in 0..num_gts {
            let gt_at = u32le(sector(gd_offset), gt_i * 4) as u64;
            let gtm = sector(gt_at - 1);
            assert_eq!(
                (u64le(gtm, 0), u32le(gtm, 12)),
                (GT_SECTORS, MARKER_GT),
                "table marker"
            );
            let gt = &vmdk[(gt_at * 512) as usize..((gt_at + GT_SECTORS) * 512) as usize];
            for i in 0..GTES_PER_GT.min(grains - gt_i * GTES_PER_GT) {
                let at = u32le(gt, i * 4) as u64;
                gtes.push(at as u32);
                if at == 0 {
                    continue; // an elided zero grain
                }
                let m = &vmdk[(at * 512) as usize..];
                let lba = u64le(m, 0);
                assert_eq!(lba, ((gt_i * GTES_PER_GT + i) as u64) * GRAIN_SECTORS);
                let size = u32le(m, 8) as usize;
                let mut grain = Vec::new();
                flate2::read::ZlibDecoder::new(&m[12..12 + size])
                    .read_to_end(&mut grain)
                    .unwrap();
                assert_eq!(grain.len(), GRAIN_BYTES, "grains inflate to exactly 64K");
                let off = (lba * 512) as usize;
                let take = grain.len().min(raw.len() - off);
                raw[off..off + take].copy_from_slice(&grain[..take]);
            }
        }
        (raw, gtes)
    }

    #[test]
    fn roundtrips_and_elides_zero_grains() {
        let dir = TmpDir::new("rt");
        // Data islands around the interesting seams: grain 0, an unaligned middle
        // run crossing a grain-table boundary would need a >32 MiB file (too big
        // for a unit test), a partial final grain — plus a hole spanning grains.
        let mut raw = vec![0u8; 5 * GRAIN_BYTES + 4096];
        raw[..8192].copy_from_slice(&[0xA5; 8192]);
        let mid = 2 * GRAIN_BYTES + 12345;
        for (i, b) in raw[mid..mid + 100_000].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let end = raw.len() - 600;
        raw[end..].fill(0x5A);
        let src = dir.0.join("disk.raw");
        std::fs::write(&src, &raw).unwrap();

        let out = dir.0.join("disk.vmdk");
        let info = write_stream_optimized(&src, &out).unwrap();
        assert_eq!(info.capacity, raw.len() as u64);

        let vmdk = std::fs::read(&out).unwrap();
        assert_eq!(info.written, vmdk.len() as u64);
        let (decoded, gtes) = decode(&vmdk);
        assert_eq!(decoded, raw, "decoded image differs");
        // Grain 1 is all-zero and grain 4 (within the hole) too: both elided, the
        // other four allocated — asserted on the grain tables themselves.
        assert_eq!(gtes.len(), 6);
        assert_eq!((gtes[1], gtes[4]), (0, 0), "zero grains are elided");
        assert_eq!(gtes.iter().filter(|&&g| g != 0).count(), 4);
        assert!(
            (vmdk.len() as u64) < raw.len() as u64,
            "zero elision + deflate must shrink this input"
        );
    }

    #[test]
    fn a_second_grain_table_roundtrips() {
        // One grain table covers 32 MiB; a grain past it exercises the table
        // chunking and the multi-entry directory. Mostly zeros, so it stays cheap.
        let dir = TmpDir::new("multigt");
        let mut raw = vec![0u8; 32 * (1 << 20) + GRAIN_BYTES];
        raw[..4096].fill(0xA5);
        let last = raw.len() - GRAIN_BYTES;
        raw[last..last + 4096].fill(0x5A);
        let src = dir.0.join("disk.raw");
        std::fs::write(&src, &raw).unwrap();

        let out = dir.0.join("disk.vmdk");
        write_stream_optimized(&src, &out).unwrap();
        let (decoded, gtes) = decode(&std::fs::read(&out).unwrap());
        assert_eq!(decoded, raw, "decoded image differs");
        assert_eq!(
            gtes.len(),
            GTES_PER_GT + 1,
            "grain 512 lands in a second table"
        );
        let allocated: Vec<usize> = (0..gtes.len()).filter(|&i| gtes[i] != 0).collect();
        assert_eq!(allocated, [0, GTES_PER_GT], "first grain of each table");
    }

    #[test]
    fn descriptor_names_the_extent_and_content_keys_the_cid() {
        let dir = TmpDir::new("desc");
        let src = dir.0.join("d.raw");
        std::fs::write(&src, vec![7u8; GRAIN_BYTES]).unwrap();
        let out = dir.0.join("appliance.vmdk");
        write_stream_optimized(&src, &out).unwrap();
        let vmdk = std::fs::read(&out).unwrap();
        let desc = String::from_utf8_lossy(&vmdk[512..512 * 21]).into_owned();
        assert!(desc.contains("createType=\"streamOptimized\""), "{desc}");
        assert!(desc.contains(&format!("RW {} SPARSE \"appliance.vmdk\"", GRAIN_SECTORS)));
        // Same content -> same file (reproducible); different content -> new CID.
        let out2 = dir.0.join("appliance2.vmdk");
        write_stream_optimized(&src, &out2).unwrap();
        let vmdk2 = std::fs::read(&out2).unwrap();
        assert_eq!(
            &vmdk[512 * 21..],
            &vmdk2[512 * 21..],
            "same content, same grains"
        );
        std::fs::write(&src, vec![8u8; GRAIN_BYTES]).unwrap();
        write_stream_optimized(&src, &out2).unwrap();
        let cid_line = |v: &[u8]| {
            String::from_utf8_lossy(&v[512..512 * 21])
                .lines()
                .find(|l| l.starts_with("CID="))
                .unwrap()
                .to_string()
        };
        assert_ne!(cid_line(&vmdk), cid_line(&std::fs::read(&out2).unwrap()));
    }

    #[test]
    fn rejects_a_non_sector_input() {
        let dir = TmpDir::new("badlen");
        let src = dir.0.join("torn.raw");
        std::fs::write(&src, vec![1u8; 1000]).unwrap();
        let err = write_stream_optimized(&src, &dir.0.join("t.vmdk")).unwrap_err();
        assert!(format!("{err:#}").contains("512-byte sectors"), "{err:#}");
    }
}
