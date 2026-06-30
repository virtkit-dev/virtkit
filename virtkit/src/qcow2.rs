//! A minimal read-only qcow2 reader — enough to read a stage's snapshot overlay (and its
//! backing chain) directly, so the cache-push path never has to `qemu-img convert` the whole
//! image to a flat raw just to read the few clusters an instruction changed. That convert
//! wrote a full image per instruction (the dominant disk IO of cache-on); reading the qcow2
//! natively eliminates it.
//!
//! Scope: the qcow2 images this tool itself produces (cloud-hypervisor rw overlays and their
//! `qemu-img create` copies) — version 2/3, 64 KiB clusters, no compression, no encryption,
//! no extended L2, standard refcounts. Anything outside that is rejected rather than
//! mis-read. Read-only: writing/creating overlays stays with `qemu-img`.

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const MAGIC: u32 = 0x5146_49fb; // "QFI\xfb"
// Cluster-offset mask (bits 9..55): both L1 and standard-L2 entries store the host offset
// here; the high bits are the COPIED flag (L1/L2) and the L2 COMPRESSED flag.
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_COMPRESSED: u64 = 1 << 62;
const L2_ZERO: u64 = 1; // QCOW_OFLAG_ZERO (v3): the cluster reads as zeros
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;

/// Where a logical cluster's bytes come from.
enum Cluster {
    /// present in this layer at the given host byte offset
    Data(u64),
    /// this layer marks the cluster all-zero
    Zero,
    /// not in this layer — defer to the backing image (or zero if none)
    Unallocated,
}

enum Backing {
    None,
    /// a raw image: logical offset == file offset (reads past EOF are zero)
    Raw(File),
    Qcow2(Box<Qcow2>),
}

/// A read-only qcow2 image plus its backing chain.
pub struct Qcow2 {
    file: File,
    cluster_bits: u32,
    cluster_size: u64,
    /// L2 entries per L2 table (cluster_size / 8)
    l2_entries: u64,
    virtual_size: u64,
    l1: Vec<u64>,
    /// cached L2 tables, keyed by their host offset
    l2_cache: HashMap<u64, Vec<u64>>,
    backing: Backing,
    /// the resolved path of the immediate backing image, if any (for the export fast path)
    backing_path: Option<PathBuf>,
}

impl Qcow2 {
    /// Open `path` (and recursively its backing image, resolved relative to `path`'s dir).
    pub fn open(path: &Path) -> Result<Qcow2> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut h = [0u8; 104];
        file.read_exact_at(&mut h, 0)
            .with_context(|| format!("reading qcow2 header of {}", path.display()))?;
        if be32(&h, 0) != MAGIC {
            bail!("{}: not a qcow2 image", path.display());
        }
        let version = be32(&h, 4);
        if version != 2 && version != 3 {
            bail!("{}: unsupported qcow2 version {version}", path.display());
        }
        if be32(&h, 32) != 0 {
            bail!("{}: encrypted qcow2 unsupported", path.display());
        }
        if version >= 3 && be64(&h, 72) & INCOMPAT_EXTENDED_L2 != 0 {
            bail!("{}: extended-L2 qcow2 unsupported", path.display());
        }
        let cluster_bits = be32(&h, 20);
        if !(9..=21).contains(&cluster_bits) {
            bail!(
                "{}: implausible cluster_bits {cluster_bits}",
                path.display()
            );
        }
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = be64(&h, 24);
        let l1_size = be32(&h, 36) as usize;
        let l1_offset = be64(&h, 40);

        // Bound the L1 table against the image's virtual size before allocating: a corrupt
        // `l1_size` (an untrusted u32, up to ~4e9) must be rejected, not turned into a
        // multi-GiB allocation (which would also overflow `l1_size * 8` on a 32-bit usize).
        let l2_span = cluster_size * (cluster_size / 8); // guest bytes one L2 table maps
        let max_l1 = virtual_size.div_ceil(l2_span).max(1) * 2;
        if l1_size as u64 > max_l1 {
            bail!("{}: implausible L1 table size {l1_size}", path.display());
        }
        let mut l1_raw = vec![0u8; l1_size * 8];
        file.read_exact_at(&mut l1_raw, l1_offset)
            .with_context(|| format!("reading L1 table of {}", path.display()))?;
        let l1: Vec<u64> = l1_raw.chunks_exact(8).map(|c| be64(c, 0)).collect();

        // backing file: a path string at backing_file_offset, resolved relative to this image.
        let backing_off = be64(&h, 8);
        let backing_len = be32(&h, 16) as usize;
        if backing_len > 4096 {
            bail!(
                "{}: implausible backing file name length {backing_len}",
                path.display()
            );
        }
        let mut backing_path = None;
        let backing = if backing_off != 0 && backing_len != 0 {
            let mut name = vec![0u8; backing_len];
            file.read_exact_at(&mut name, backing_off)
                .context("reading backing file name")?;
            let name = String::from_utf8(name).context("backing file name not utf-8")?;
            let bpath = resolve_backing(path, &name);
            let b = open_backing(&bpath).with_context(|| {
                format!("opening backing {} of {}", bpath.display(), path.display())
            })?;
            backing_path = Some(bpath);
            b
        } else {
            Backing::None
        };

        Ok(Qcow2 {
            file,
            cluster_bits,
            cluster_size,
            l2_entries: cluster_size / 8,
            virtual_size,
            l1,
            l2_cache: HashMap::new(),
            backing,
            backing_path,
        })
    }

    pub fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    /// If this overlay holds no data of its own and sits directly on a raw backing, return
    /// that backing's path: the overlay's logical content IS the backing file, so an export
    /// can move the raw out instead of flattening a full copy. This is the warm-rebuild fast
    /// path — a restored snapshot is wrapped in an empty overlay and never written to.
    pub fn empty_raw_backing(&mut self) -> Result<Option<PathBuf>> {
        if !matches!(self.backing, Backing::Raw(_)) || !self.data_extents()?.is_empty() {
            return Ok(None);
        }
        Ok(self.backing_path.clone())
    }

    /// Read `buf.len()` logical bytes starting at `off`, following the backing chain for
    /// clusters this layer does not hold; bytes past the end of an image read as zero.
    pub fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let l_off = off + done as u64;
            let in_cluster = l_off & (self.cluster_size - 1);
            let n = ((self.cluster_size - in_cluster) as usize).min(buf.len() - done);
            let dst = &mut buf[done..done + n];
            match self.locate(l_off >> self.cluster_bits)? {
                Cluster::Data(host) => self
                    .file
                    .read_exact_at(dst, host + in_cluster)
                    .context("reading qcow2 data cluster")?,
                Cluster::Zero => dst.fill(0),
                Cluster::Unallocated => match &self.backing {
                    Backing::None => dst.fill(0),
                    Backing::Raw(f) => read_raw_or_zero(f, l_off, dst)?,
                    // SAFETY of borrow: take the backing out to read it (no aliasing of self).
                    Backing::Qcow2(_) => self.read_backing_qcow2(l_off, dst)?,
                },
            }
            done += n;
        }
        Ok(())
    }

    fn read_backing_qcow2(&mut self, off: u64, dst: &mut [u8]) -> Result<()> {
        let Backing::Qcow2(b) = &mut self.backing else {
            unreachable!()
        };
        b.read_at(off, dst)
    }

    /// The logical `(offset, length)` byte ranges this layer holds itself (data or
    /// explicit-zero clusters) — the qcow2-native equivalent of `qemu-img map` at depth 0,
    /// i.e. exactly what the overlay's guest wrote since the stage booted.
    pub fn data_extents(&mut self) -> Result<Vec<(u64, u64)>> {
        let clusters = self.virtual_size.div_ceil(self.cluster_size);
        let mut out: Vec<(u64, u64)> = Vec::new();
        for c in 0..clusters {
            let present = matches!(self.locate(c)?, Cluster::Data(_) | Cluster::Zero);
            if !present {
                continue;
            }
            let start = c << self.cluster_bits;
            // clamp the last cluster to the virtual size
            let len = self.cluster_size.min(self.virtual_size - start);
            match out.last_mut() {
                Some(last) if last.0 + last.1 == start => last.1 += len,
                _ => out.push((start, len)),
            }
        }
        Ok(out)
    }

    /// The logical data regions of the *whole chain*: this layer's own clusters merged
    /// with everything its backing image contributes (recursively; a raw backing's data is
    /// found via `SEEK_DATA`/`SEEK_HOLE`). The set of regions that may hold non-zero bytes
    /// — what a flatten needs to read; everything else is a hole top to bottom.
    pub fn chain_data_extents(&mut self) -> Result<Vec<(u64, u64)>> {
        let mut all = self.data_extents()?;
        match &mut self.backing {
            Backing::None => {}
            Backing::Qcow2(b) => all.extend(b.chain_data_extents()?),
            Backing::Raw(f) => all.extend(raw_data_extents(f)?),
        }
        Ok(merge_extents(all))
    }

    /// Map a logical cluster to where its bytes live in this layer.
    fn locate(&mut self, cluster: u64) -> Result<Cluster> {
        let l1_idx = (cluster / self.l2_entries) as usize;
        let l2_off = match self.l1.get(l1_idx) {
            Some(&e) if e & OFFSET_MASK != 0 => e & OFFSET_MASK,
            _ => return Ok(Cluster::Unallocated),
        };
        let l2_idx = (cluster % self.l2_entries) as usize;
        let entry = self.l2_entry(l2_off, l2_idx)?;
        if entry == 0 {
            Ok(Cluster::Unallocated)
        } else if entry & L2_ZERO != 0 {
            Ok(Cluster::Zero)
        } else if entry & L2_COMPRESSED != 0 {
            bail!("compressed qcow2 clusters unsupported")
        } else {
            Ok(Cluster::Data(entry & OFFSET_MASK))
        }
    }

    fn l2_entry(&mut self, l2_off: u64, idx: usize) -> Result<u64> {
        if !self.l2_cache.contains_key(&l2_off) {
            let mut raw = vec![0u8; self.cluster_size as usize];
            self.file
                .read_exact_at(&mut raw, l2_off)
                .context("reading qcow2 L2 table")?;
            let table: Vec<u64> = raw.chunks_exact(8).map(|c| be64(c, 0)).collect();
            self.l2_cache.insert(l2_off, table);
        }
        Ok(self.l2_cache[&l2_off][idx])
    }
}

/// Create an empty qcow2 v3 overlay at `path` backed by `backing` — the native replacement
/// for `qemu-img create -f qcow2 -F <fmt> -b <backing>`. No data clusters are allocated
/// (cloud-hypervisor writes those at boot); just a valid header + backing reference +
/// refcount metadata + a zeroed L1 table, laid out exactly like qemu-img's so CH and
/// qemu-img both accept and grow it. The overlay's virtual size matches the backing's.
pub fn create_overlay(path: &Path, backing: &Path) -> Result<()> {
    const CB: u32 = 16;
    const CS: u64 = 1 << CB; // 64 KiB cluster
    const L2_ENTRIES: u64 = CS / 8; // 8192 entries per L2 table

    // backing format + the overlay's virtual size (= the backing's).
    let (bfmt, size) = {
        let f = File::open(backing).with_context(|| format!("opening {}", backing.display()))?;
        let mut magic = [0u8; 4];
        if f.read_exact_at(&mut magic, 0).is_ok() && be32(&magic, 0) == MAGIC {
            ("qcow2", Qcow2::open(backing)?.virtual_size())
        } else {
            ("raw", f.metadata()?.len())
        }
    };
    let backing_name = backing
        .to_str()
        .context("backing path not utf-8")?
        .as_bytes();

    // layout: cluster 0 header, 1 refcount table, 2 refcount block, 3.. L1 table.
    let l1_size = size.div_ceil(CS * L2_ENTRIES).max(1);
    let l1_clusters = (l1_size * 8).div_ceil(CS);
    let meta_clusters = 3 + l1_clusters; // header + rct + rcb + L1
    let rct_off = CS; // cluster 1
    let rcb_off = 2 * CS; // cluster 2
    let l1_off = 3 * CS; // cluster 3

    // cluster 0: header + a backing-file-format extension + end extension + backing name.
    let mut c0 = vec![0u8; CS as usize];
    c0[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    wbe32(&mut c0, 4, 3); // version 3
    wbe32(&mut c0, 0x14, CB); // cluster_bits
    wbe64(&mut c0, 0x18, size); // virtual size
    wbe32(&mut c0, 0x24, l1_size as u32);
    wbe64(&mut c0, 0x28, l1_off);
    wbe64(&mut c0, 0x30, rct_off);
    wbe32(&mut c0, 0x38, 1); // refcount_table_clusters
    wbe32(&mut c0, 0x60, 4); // refcount_order (16-bit refcounts)
    wbe32(&mut c0, 0x64, 112); // header_length (v3)
    // header extension: backing file format (magic 0xE2792ACA), then the end extension.
    let mut p = 112usize;
    wbe32(&mut c0, p, 0xE279_2ACA);
    wbe32(&mut c0, p + 4, bfmt.len() as u32);
    c0[p + 8..p + 8 + bfmt.len()].copy_from_slice(bfmt.as_bytes());
    p += 8 + bfmt.len().next_multiple_of(8);
    // end-of-extensions marker (magic 0, len 0) already zero at p; advance past it.
    p += 8;
    // backing file name string, 8-aligned.
    let name_off = p.next_multiple_of(8);
    c0[name_off..name_off + backing_name.len()].copy_from_slice(backing_name);
    wbe64(&mut c0, 0x08, name_off as u64); // backing_file_offset
    wbe32(&mut c0, 0x10, backing_name.len() as u32); // backing_file_size

    // cluster 1: refcount table — one entry pointing at the refcount block.
    let mut rct = vec![0u8; CS as usize];
    wbe64(&mut rct, 0, rcb_off);
    // cluster 2: refcount block — every metadata cluster has refcount 1 (16-bit entries).
    let mut rcb = vec![0u8; CS as usize];
    for c in 0..meta_clusters as usize {
        rcb[c * 2..c * 2 + 2].copy_from_slice(&1u16.to_be_bytes());
    }
    // clusters 3..: L1 table (zeroed — no L2 tables yet).
    let l1 = vec![0u8; (l1_clusters * CS) as usize];

    let mut out = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    use std::io::Write;
    out.write_all(&c0)?;
    out.write_all(&rct)?;
    out.write_all(&rcb)?;
    out.write_all(&l1)?;
    Ok(())
}

/// Flatten the full logical content of a qcow2 (resolving its whole backing chain) into a
/// raw image at `out` — the native replacement for `qemu-img convert -O raw`. Only the
/// chain's data regions are read and written; runs of zero are left as holes, so the output
/// is sparse and byte-identical to what `qemu-img convert` produces.
pub fn flatten_to_raw(src: &Path, out: &Path) -> Result<()> {
    let mut q = Qcow2::open(src)?;
    let size = q.virtual_size();
    let outf = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    outf.set_len(size)?;
    let regions = q.chain_data_extents()?;
    let mut buf = vec![0u8; 1 << 20];
    for (off, len) in regions {
        let mut pos = off;
        let end = (off + len).min(size);
        while pos < end {
            let n = ((end - pos) as usize).min(buf.len());
            q.read_at(pos, &mut buf[..n])?;
            // keep holes sparse: skip all-zero blocks (they read back as zero anyway).
            if buf[..n].iter().any(|&b| b != 0) {
                outf.write_all_at(&buf[..n], pos)?;
            }
            pos += n as u64;
        }
    }
    Ok(())
}

/// Debug check (VIRTKIT_QCOW2_VERIFY): flatten `path` with `qemu-img convert` and compare
/// the native reader against it, reporting the first mismatching offset. Used to validate
/// the reader against real (cloud-hypervisor-written) captures during a build.
pub fn verify_against_convert(path: &Path) -> Result<()> {
    use std::io::Read;
    let flat = path.with_extension("verify.raw");
    let st = std::process::Command::new("qemu-img")
        .args(["convert", "-O", "raw"])
        .arg(path)
        .arg(&flat)
        .status()?;
    if !st.success() {
        bail!("verify: qemu-img convert failed");
    }
    // stream-compare in blocks (the image is many GiB — never load it all).
    let mut want_f = File::open(&flat)?;
    let mut q = Qcow2::open(path)?;
    const BLK: usize = 4 * 1024 * 1024;
    let mut wbuf = vec![0u8; BLK];
    let mut gbuf = vec![0u8; BLK];
    let mut off = 0u64;
    let size = q.virtual_size();
    let mut ok = true;
    while off < size {
        let n = (BLK as u64).min(size - off) as usize;
        want_f.read_exact(&mut wbuf[..n])?;
        q.read_at(off, &mut gbuf[..n])?;
        if wbuf[..n] != gbuf[..n] {
            let i = (0..n).find(|&i| wbuf[i] != gbuf[i]).unwrap();
            eprintln!(
                "qcow2-verify MISMATCH {} at offset {} (cluster {}): native={:#04x} convert={:#04x}",
                path.display(),
                off + i as u64,
                (off + i as u64) >> q.cluster_bits,
                gbuf[i],
                wbuf[i]
            );
            ok = false;
            break;
        }
        off += n as u64;
    }
    let _ = std::fs::remove_file(&flat);
    if ok {
        eprintln!("qcow2-verify OK {} ({} bytes)", path.display(), size);
    }
    Ok(())
}

/// A sequential [`std::io::Read`] over a `[start, start+len)` logical range of a qcow2 —
/// for streaming a region into a content-defined chunker without flattening to a raw.
pub struct RegionReader {
    q: Qcow2,
    pos: u64,
    end: u64,
}

impl RegionReader {
    pub fn new(q: Qcow2, start: u64, len: u64) -> Self {
        RegionReader {
            q,
            pos: start,
            end: start + len,
        }
    }
}

impl std::io::Read for RegionReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.end {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.end - self.pos) as usize;
        self.q
            .read_at(self.pos, &mut buf[..n])
            .map_err(std::io::Error::other)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// The data extents (non-hole byte ranges) of a raw file, via `SEEK_DATA`/`SEEK_HOLE`.
fn raw_data_extents(f: &File) -> Result<Vec<(u64, u64)>> {
    use std::os::unix::io::AsRawFd;
    const SEEK_DATA: libc::c_int = 3;
    const SEEK_HOLE: libc::c_int = 4;
    let fd = f.as_raw_fd();
    let size = f.metadata()?.len();
    let mut out = Vec::new();
    let mut pos = 0i64;
    while (pos as u64) < size {
        let data = unsafe { libc::lseek(fd, pos, SEEK_DATA) };
        if data < 0 {
            break; // ENXIO: no more data
        }
        let hole = unsafe { libc::lseek(fd, data, SEEK_HOLE) };
        let end = if hole < 0 { size as i64 } else { hole };
        out.push((data as u64, (end - data) as u64));
        pos = end;
    }
    Ok(out)
}

/// Sort and coalesce overlapping/adjacent extents into a minimal non-overlapping set.
fn merge_extents(mut ext: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ext.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ext.len());
    for (start, len) in ext {
        let end = start + len;
        match out.last_mut() {
            Some(last) if start <= last.0 + last.1 => {
                last.1 = (last.0 + last.1).max(end) - last.0;
            }
            _ => out.push((start, len)),
        }
    }
    out
}

fn open_backing(path: &Path) -> Result<Backing> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    // a backing shorter than 4 bytes can't be qcow2; treat as raw
    if f.read_exact_at(&mut magic, 0).is_ok() && be32(&magic, 0) == MAGIC {
        Ok(Backing::Qcow2(Box::new(Qcow2::open(path)?)))
    } else {
        Ok(Backing::Raw(f))
    }
}

/// Resolve a backing-file name (often absolute, as this tool writes it) relative to the
/// referencing image's directory when it is relative.
fn resolve_backing(image: &Path, name: &str) -> std::path::PathBuf {
    let p = Path::new(name);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        image.parent().unwrap_or(Path::new(".")).join(p)
    }
}

/// Read from a raw backing at `off`, zero-filling any part past EOF.
fn read_raw_or_zero(f: &File, off: u64, dst: &mut [u8]) -> Result<()> {
    let len = f.metadata().context("stat raw backing")?.len();
    if off >= len {
        dst.fill(0);
        return Ok(());
    }
    let avail = ((len - off) as usize).min(dst.len());
    f.read_exact_at(&mut dst[..avail], off)
        .context("reading raw backing")?;
    dst[avail..].fill(0);
    Ok(())
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}
fn wbe32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}
fn wbe64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn have(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    // Build a raw backing + a qcow2 overlay that overwrites one cluster, then check the
    // native reader matches `qemu-img convert` byte-for-byte and reports the right extents.
    #[test]
    fn reads_overlay_over_raw_backing() {
        if !have("qemu-img") || !have("qemu-io") {
            eprintln!("skipping: qemu-img/qemu-io not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("vk-qcow2-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("base.raw");
        let overlay = dir.join("ovl.qcow2");
        let flat = dir.join("flat.raw");
        // 256 KiB raw backing filled with 0xAA.
        std::fs::write(&base, vec![0xAAu8; 256 * 1024]).unwrap();
        assert!(
            Command::new("qemu-img")
                .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
                .arg(&base)
                .arg(&overlay)
                .status()
                .unwrap()
                .success()
        );
        // overwrite the 2nd 64 KiB cluster with 0xBB.
        assert!(
            Command::new("qemu-io")
                .args(["-c", "write -P 0xBB 65536 65536"])
                .arg(&overlay)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("qemu-img")
                .args(["convert", "-O", "raw"])
                .arg(&overlay)
                .arg(&flat)
                .status()
                .unwrap()
                .success()
        );
        let want = std::fs::read(&flat).unwrap();
        let mut q = Qcow2::open(&overlay).unwrap();
        assert_eq!(q.virtual_size(), 256 * 1024);
        let mut got = vec![0u8; want.len()];
        q.read_at(0, &mut got).unwrap();
        assert_eq!(got, want, "native read must match qemu-img convert");
        // the overlay owns exactly the overwritten cluster.
        assert_eq!(q.data_extents().unwrap(), vec![(65536, 65536)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // flatten_to_raw must byte-match `qemu-img convert -O raw` over a chain.
    #[test]
    fn flatten_matches_qemu_convert() {
        if !have("qemu-img") || !have("qemu-io") {
            eprintln!("skipping: qemu-img/qemu-io not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("vk-qcow2-flat-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("base.raw");
        let mid = dir.join("mid.qcow2");
        let top = dir.join("top.qcow2");
        let want = dir.join("want.raw");
        let got = dir.join("got.raw");
        std::fs::write(&base, vec![0xAAu8; 4 * 1024 * 1024]).unwrap();
        let create = |img: &Path, backing: &Path, bfmt: &str| {
            assert!(
                Command::new("qemu-img")
                    .args(["create", "-q", "-f", "qcow2", "-F", bfmt, "-b"])
                    .arg(backing)
                    .arg(img)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        create(&mid, &base, "raw");
        assert!(
            Command::new("qemu-io")
                .args(["-c", "write -P 0xBB 1048576 65536"])
                .arg(&mid)
                .status()
                .unwrap()
                .success()
        );
        create(&top, &mid, "qcow2");
        assert!(
            Command::new("qemu-io")
                .args(["-c", "write -P 0xCC 3145728 65536"])
                .arg(&top)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("qemu-img")
                .args(["convert", "-O", "raw"])
                .arg(&top)
                .arg(&want)
                .status()
                .unwrap()
                .success()
        );
        flatten_to_raw(&top, &got).unwrap();
        assert_eq!(
            std::fs::read(&got).unwrap(),
            std::fs::read(&want).unwrap(),
            "flatten_to_raw must match qemu-img convert"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A deep chain with an EMPTY intermediate overlay (capture -> empty -> mid -> raw),
    // exactly the forked-stage shape: the boot-overlay copy backs a freshly-forked (still
    // empty) stage qcow2 that backs the committed parent. Base data must resolve through the
    // empty level, not read as zero.
    #[test]
    fn reads_through_empty_intermediate() {
        if !have("qemu-img") || !have("qemu-io") {
            eprintln!("skipping: qemu-img/qemu-io not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("vk-qcow2-test3-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("base.raw");
        let mid = dir.join("mid.qcow2");
        let empty = dir.join("empty.qcow2");
        let top = dir.join("top.qcow2");
        let flat = dir.join("flat.raw");
        // base: 0xAA at 0, 2 MiB, 6 MiB across an 8 MiB image; holes elsewhere.
        {
            let f = std::fs::File::create(&base).unwrap();
            f.set_len(8 * 1024 * 1024).unwrap();
            for off in [0u64, 2 << 20, 6 << 20] {
                f.write_all_at(&[0xAA; 65536], off).unwrap();
            }
        }
        let create = |img: &Path, backing: &Path, bfmt: &str| {
            assert!(
                Command::new("qemu-img")
                    .args(["create", "-q", "-f", "qcow2", "-F", bfmt, "-b"])
                    .arg(backing)
                    .arg(img)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        create(&mid, &base, "raw");
        // mid overwrites the 4 MiB cluster with 0xBB.
        assert!(
            Command::new("qemu-io")
                .args(["-c", "write -P 0xBB 4194304 65536"])
                .arg(&mid)
                .status()
                .unwrap()
                .success()
        );
        create(&empty, &mid, "qcow2"); // intentionally left empty
        create(&top, &empty, "qcow2");
        // top overwrites the 1 MiB cluster with 0xCC.
        assert!(
            Command::new("qemu-io")
                .args(["-c", "write -P 0xCC 1048576 65536"])
                .arg(&top)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("qemu-img")
                .args(["convert", "-O", "raw"])
                .arg(&top)
                .arg(&flat)
                .status()
                .unwrap()
                .success()
        );
        let want = std::fs::read(&flat).unwrap();
        let mut q = Qcow2::open(&top).unwrap();
        let mut got = vec![0u8; want.len()];
        q.read_at(0, &mut got).unwrap();
        assert_eq!(
            got, want,
            "must resolve base data through the empty intermediate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A 2-level qcow2 chain (top -> mid -> raw) larger than one L2 table (>512 MiB so the
    // L1 has multiple entries), with writes at high offsets in each layer — exercises
    // backing-chain recursion and L1 indexing, which the forked-stage build hits.
    #[test]
    fn reads_two_level_chain_multi_l2() {
        if !have("qemu-img") || !have("qemu-io") {
            eprintln!("skipping: qemu-img/qemu-io not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("vk-qcow2-test2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("base.raw");
        let mid = dir.join("mid.qcow2");
        let top = dir.join("top.qcow2");
        let flat = dir.join("flat.raw");
        let sz = 768 * 1024 * 1024u64; // > 512 MiB => >1 L1 entry at 64K clusters
        // base: 0xAA at offset 0 and near 600 MiB (second L1 region), holes elsewhere.
        {
            let f = std::fs::File::create(&base).unwrap();
            f.set_len(sz).unwrap();
            f.write_all_at(&[0xAA; 65536], 0).unwrap();
            f.write_all_at(&[0xAA; 65536], 600 * 1024 * 1024).unwrap();
        }
        let create = |img: &Path, backing: &Path, bfmt: &str| {
            assert!(
                Command::new("qemu-img")
                    .args(["create", "-q", "-f", "qcow2", "-F", bfmt, "-b"])
                    .arg(backing)
                    .arg(img)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        create(&mid, &base, "raw");
        // mid overwrites a cluster in the second L1 region (~601 MiB) with 0xBB.
        assert!(
            Command::new("qemu-io")
                .args(["-c", &format!("write -P 0xBB {} 65536", 601 * 1024 * 1024)])
                .arg(&mid)
                .status()
                .unwrap()
                .success()
        );
        create(&top, &mid, "qcow2");
        // top overwrites a cluster at 128 KiB (first L1 region) with 0xCC.
        assert!(
            Command::new("qemu-io")
                .args(["-c", "write -P 0xCC 131072 65536"])
                .arg(&top)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("qemu-img")
                .args(["convert", "-O", "raw"])
                .arg(&top)
                .arg(&flat)
                .status()
                .unwrap()
                .success()
        );
        let want = std::fs::read(&flat).unwrap();
        let mut q = Qcow2::open(&top).unwrap();
        // read in odd-sized chunks crossing cluster + L1 boundaries.
        let mut got = vec![0u8; want.len()];
        let mut pos = 0usize;
        while pos < got.len() {
            let n = (100_003).min(got.len() - pos);
            q.read_at(pos as u64, &mut got[pos..pos + n]).unwrap();
            pos += n;
        }
        assert_eq!(
            got, want,
            "native read of a 2-level chain must match qemu-img"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // create_overlay must produce an overlay qemu accepts (qemu-img check clean) and that is
    // writable+readable: write through qemu-io, then both qemu-img convert and the native
    // reader must agree. Covers both a raw backing and a qcow2 backing.
    #[test]
    fn create_overlay_is_qemu_compatible() {
        if !have("qemu-img") || !have("qemu-io") {
            eprintln!("skipping: qemu-img/qemu-io not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("vk-qcow2-mk-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let check = |img: &Path| {
            assert!(
                Command::new("qemu-img")
                    .arg("check")
                    .arg(img)
                    .status()
                    .unwrap()
                    .success(),
                "qemu-img check must pass on {}",
                img.display()
            );
        };
        let roundtrip = |dir: &Path, backing: &Path, vsize: u64, tag: &str| {
            let overlay = dir.join(format!("ovl-{tag}.qcow2"));
            let flat = dir.join(format!("flat-{tag}.raw"));
            create_overlay(&overlay, backing).unwrap();
            check(&overlay);
            // a fresh overlay reads back exactly as its backing.
            assert_eq!(Qcow2::open(&overlay).unwrap().virtual_size(), vsize);
            // write a cluster near the end (forces an L2 alloc + refcount growth).
            let woff = vsize - 65536;
            assert!(
                Command::new("qemu-io")
                    .args(["-c", &format!("write -P 0xCC {woff} 65536")])
                    .arg(&overlay)
                    .status()
                    .unwrap()
                    .success()
            );
            check(&overlay);
            assert!(
                Command::new("qemu-img")
                    .args(["convert", "-O", "raw"])
                    .arg(&overlay)
                    .arg(&flat)
                    .status()
                    .unwrap()
                    .success()
            );
            let want = std::fs::read(&flat).unwrap();
            let mut q = Qcow2::open(&overlay).unwrap();
            let mut got = vec![0u8; want.len()];
            q.read_at(0, &mut got).unwrap();
            assert_eq!(
                got, want,
                "native read of created overlay ({tag}) must match qemu"
            );
        };
        // raw backing: 4 MiB of 0xAA.
        let raw = dir.join("base.raw");
        std::fs::write(&raw, vec![0xAAu8; 4 * 1024 * 1024]).unwrap();
        roundtrip(&dir, &raw, 4 * 1024 * 1024, "raw");
        // qcow2 backing: a >512 MiB image so the overlay needs a multi-cluster L1.
        let qbase = dir.join("qbase.qcow2");
        assert!(
            Command::new("qemu-img")
                .args(["create", "-q", "-f", "qcow2"])
                .arg(&qbase)
                .arg("768M")
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("qemu-io")
                .args(["-c", "write -P 0xDD 0 65536"])
                .arg(&qbase)
                .status()
                .unwrap()
                .success()
        );
        roundtrip(&dir, &qbase, 768 * 1024 * 1024, "qcow2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
