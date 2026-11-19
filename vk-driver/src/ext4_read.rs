//! Read paths, regular files, directories and symlinks from ext2/ext4 images without a
//! mount or external tools. Supported layouts include this crate's writer ([`crate::ext4`])
//! and Linux `/boot` images from `mke2fs`. Blocks are 1, 2 or 4 KiB. Inode sizes are
//! powers of two from 128 bytes to one block. Each group's block bitmap fits in one block.
//! Files can use extents or direct, single, double and triple indirect block pointers.
//! The reader handles fast symlinks and directories with or without `filetype`. It skips
//! hashed directory indexes while scanning entries. Image contents are untrusted. The
//! reader rejects incompatible features outside [`INCOMPAT_KNOWN`], including inline data,
//! `meta_bg`, encryption and large directories.
//!
//! The reader accepts a raw filesystem or one inside an exported qcow2 root or unit
//! image. It detects the format and reads through the qcow2 layer when needed.

// This module provides a self-contained reader API; it is exercised by its own
// tests and consumed by callers wiring it into commands.
#![allow(dead_code)]

use std::cell::RefCell;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{Context, Result, bail};

const ROOT_INO: u32 = 2;
const SB_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const EXT_MAGIC: u16 = 0xF30A;
const EXTENTS_FL: u32 = 0x0008_0000;
// `s_feature_incompat` bits.
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_MMP: u32 = 0x0100;
const INCOMPAT_FLEX_BG: u32 = 0x0200;
const INCOMPAT_EA_INODE: u32 = 0x0400;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
/// Accepted incompatible features. With `recover`, the reader uses on-disk metadata even
/// if the journal holds newer versions. `ea_inode` only affects xattrs, which it skips.
/// Other incompatible features may change how blocks are interpreted.
const INCOMPAT_KNOWN: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_CSUM_SEED;
/// Pointers in i_block: 12 direct, then single, double and triple indirect.
const DIRECT_BLOCKS: usize = 12;
/// The most group descriptors read, 4 MiB of them: terabytes of 4 KiB blocks, far past a
/// /boot.
const MAX_GDT_BYTES: u64 = 4 << 20;

// i_mode type bits (top nibble).
const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;

/// A short symlink whose target is stored inline in the 60-byte i_block region
/// (fast symlink). The writer uses inline storage iff the target is < 60 bytes.
const FAST_SYMLINK_MAX: u64 = 60;

/// The most a directory's entries are read to: far past any real directory (a million
/// entries), and what an image can make the host allocate for one.
const MAX_DIR_BYTES: u64 = 64 << 20;
/// The most a symlink's target may be: the kernel's own `PATH_MAX`.
const MAX_SYMLINK_TARGET: u64 = 4096;

/// Cap on symlink hops while resolving a path, counted across the whole resolution — every
/// nested target included, as the kernel's own 40 are — so links that point through each
/// other end in an error rather than in unbounded recursion.
const MAX_SYMLINK_HOPS: u32 = 40;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileType {
    Dir,
    Regular,
    Symlink,
    Other,
}

impl FileType {
    fn from_mode(mode: u16) -> FileType {
        match mode & S_IFMT {
            S_IFDIR => FileType::Dir,
            S_IFREG => FileType::Regular,
            S_IFLNK => FileType::Symlink,
            _ => FileType::Other,
        }
    }
}

/// One physical run of a file's data: `len` blocks starting at physical block
/// `phys_start`, mapping logical block `logical` onward.
#[derive(Clone, Copy)]
struct Extent {
    logical: u64,
    phys_start: u64,
    len: u64,
}

/// Parsed inode: type, size and flags, and where its data lies.
struct InodeInfo {
    /// Its number, naming it in errors.
    ino: u32,
    mode: u16,
    size: u64,
    flags: u32,
    /// The raw 60-byte i_block region (holds a fast symlink's target when applicable).
    i_block: [u8; 60],
    is_fast_symlink: bool,
}

impl InodeInfo {
    fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }
}

pub struct Ext4Reader {
    source: Source,
    /// 1024, 2048 or 4096.
    block_size: u64,
    /// `s_inode_size`: 128 for a revision-0 filesystem, else at least that.
    inode_size: u64,
    /// Every block pointer is checked against this before it is read.
    blocks_count: u64,
    /// Logical image size in bytes. Bounds the filesystem at open and inode data at read time.
    image_len: u64,
    inodes_per_group: u32,
    /// Physical block of each group's inode table (`bg_inode_table`).
    inode_tables: Vec<u64>,
    /// Whether directory entries carry their type (`filetype`); without it, that byte is the
    /// high byte of the name's length, and the type is the inode's.
    dirent_types: bool,
}

/// Filesystem source. `Qcow2::read_at` requires `&mut self` to cache L2 tables, while
/// the reader API takes `&self`, so qcow2 uses interior mutability.
enum Source {
    Raw(std::fs::File),
    Qcow2(RefCell<crate::qcow2::Qcow2>),
}

impl Source {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> Result<()> {
        match self {
            Source::Raw(f) => Ok(f.read_exact_at(buf, off)?),
            Source::Qcow2(q) => q.borrow_mut().read_at(off, buf),
        }
    }

    /// Logical image size: the raw file's length or the qcow2's virtual size.
    fn len(&self) -> Result<u64> {
        match self {
            Source::Raw(f) => Ok(f.metadata().context("stat image for size check")?.len()),
            Source::Qcow2(q) => Ok(q.borrow().virtual_size()),
        }
    }
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

impl Ext4Reader {
    /// Read the superblock and group descriptors. Blocks must be 1, 2 or 4 KiB and inode
    /// sizes powers of two from 128 bytes to one block. The first data block must contain
    /// the superblock. Reject incompatible features outside [`INCOMPAT_KNOWN`] and invalid
    /// descriptor sizes. Inode tables must fit the filesystem, and the filesystem its image.
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        // A `.vk_ro_img` is a lazy chunk manifest, not a filesystem. Treating it as raw
        // lets the ext4 magic check reject it like any other non-ext4 input.
        let source = match crate::qcow2::sniff_kind(&file) {
            crate::qcow2::ImageKind::Qcow2 => {
                Source::Qcow2(RefCell::new(crate::qcow2::Qcow2::open(path)?))
            }
            crate::qcow2::ImageKind::Raw | crate::qcow2::ImageKind::Lazy => Source::Raw(file),
        };

        let mut sb = [0u8; 1024];
        source
            .read_exact_at(&mut sb, SB_OFFSET)
            .with_context(|| format!("reading superblock of {}", path.display()))?;

        let name = path.display();
        if rd16(&sb, 0x38) != EXT4_MAGIC {
            bail!("{name}: not an ext2/ext4 image (bad magic)");
        }
        let log_block = rd32(&sb, 0x18);
        if log_block > 2 {
            bail!("{name}: unsupported block size (s_log_block_size {log_block}, over 4 KiB)");
        }
        let block_size = 1024u64 << log_block;
        let incompat = rd32(&sb, 0x60);
        for (bit, what) in [
            (INCOMPAT_META_BG, "meta_bg"),
            (INCOMPAT_INLINE_DATA, "inline_data"),
        ] {
            if incompat & bit != 0 {
                bail!("{name}: unsupported feature {what}");
            }
        }
        if incompat & !INCOMPAT_KNOWN != 0 {
            bail!(
                "{name}: unsupported incompatible features {:#x}",
                incompat & !INCOMPAT_KNOWN
            );
        }
        // Revision 0 has no s_inode_size and fixed 128-byte inodes.
        let inode_size = if rd32(&sb, 0x4C) == 0 {
            128
        } else {
            u64::from(rd16(&sb, 0x58))
        };
        if inode_size < 128 || !inode_size.is_power_of_two() || inode_size > block_size {
            bail!("{name}: unsupported inode size {inode_size}");
        }
        let blocks_count = u64::from(rd32(&sb, 0x04))
            | if incompat & INCOMPAT_64BIT != 0 {
                u64::from(rd32(&sb, 0x150)) << 32
            } else {
                0
            };
        let first_data_block = u64::from(rd32(&sb, 0x14));
        let blocks_per_group = u64::from(rd32(&sb, 0x20));
        let inodes_per_group = rd32(&sb, 0x28);
        // Group counts serve as divisors and determine allocation sizes. Each bitmap
        // occupies one block, so each count must be nonzero and fit its bitmap.
        if blocks_per_group == 0 || blocks_per_group > block_size * 8 {
            bail!("{name}: unsupported blocks-per-group {blocks_per_group}");
        }
        if inodes_per_group == 0 || u64::from(inodes_per_group) > block_size * 8 {
            bail!("{name}: unsupported inodes-per-group {inodes_per_group}");
        }
        // A block within the filesystem must have a representable byte offset within the image.
        let image_len = source.len()?;
        if blocks_count
            .checked_mul(block_size)
            .is_none_or(|bytes| bytes > image_len)
        {
            bail!(
                "{name}: {blocks_count} blocks of {block_size} bytes, past its {image_len}-byte image"
            );
        }
        // The superblock's own block: block 1 with 1 KiB blocks, else block 0.
        if first_data_block != u64::from(block_size == 1024) || first_data_block >= blocks_count {
            bail!("{name}: first data block {first_data_block} with {block_size}-byte blocks");
        }
        let groups = (blocks_count - first_data_block).div_ceil(blocks_per_group);
        // Descriptors are 32 bytes unless the 64bit feature supplies their size in s_desc_size.
        let desc_size = if incompat & INCOMPAT_64BIT != 0 {
            u64::from(rd16(&sb, 0xFE))
        } else {
            32
        };
        let min_desc = if incompat & INCOMPAT_64BIT != 0 {
            64
        } else {
            32
        };
        if !(min_desc..=1024).contains(&desc_size) || !desc_size.is_power_of_two() {
            bail!("{name}: unsupported group descriptor size {desc_size}");
        }
        let gdt_bytes = groups * desc_size;
        if gdt_bytes > MAX_GDT_BYTES {
            bail!("{name}: {groups} block groups, over what this reader takes");
        }
        // The descriptor table follows the superblock at block 2 for 1 KiB blocks, else block 1.
        let mut gdt = vec![0u8; gdt_bytes as usize];
        source
            .read_exact_at(&mut gdt, (first_data_block + 1) * block_size)
            .with_context(|| format!("reading group descriptors of {name}"))?;
        let inode_tables: Vec<u64> = (0..groups as usize)
            .map(|g| {
                let d = g * desc_size as usize;
                let hi = if desc_size >= 64 {
                    u64::from(rd32(&gdt, d + 0x28)) << 32
                } else {
                    0
                };
                u64::from(rd32(&gdt, d + 0x08)) | hi
            })
            .collect();
        // Each table whole inside the filesystem, so no inode read leaves it.
        let table_blocks = (u64::from(inodes_per_group) * inode_size).div_ceil(block_size);
        if let Some(bad) = inode_tables.iter().find(|&&b| {
            b.checked_add(table_blocks)
                .is_none_or(|end| end > blocks_count)
        }) {
            bail!("{name}: an inode table at block {bad} runs past {blocks_count} blocks");
        }

        Ok(Ext4Reader {
            source,
            block_size,
            inode_size,
            blocks_count,
            inodes_per_group,
            inode_tables,
            dirent_types: incompat & INCOMPAT_FILETYPE != 0,
            image_len,
        })
    }

    /// Read block `blk` into `buf`, which is one block long. A pointer past the filesystem
    /// is corruption, refused before it becomes a read.
    fn read_block(&self, blk: u64, buf: &mut [u8]) -> Result<()> {
        if blk >= self.blocks_count {
            bail!(
                "block {blk} past the filesystem's {} blocks",
                self.blocks_count
            );
        }
        // Below blocks_count, which open() bounds by the image, so this cannot overflow.
        self.source
            .read_exact_at(buf, blk * self.block_size)
            .with_context(|| format!("reading block {blk}"))?;
        Ok(())
    }

    fn new_block(&self) -> Vec<u8> {
        vec![0u8; self.block_size as usize]
    }

    /// Byte offset of inode `n` (1-based) in the image.
    fn inode_offset(&self, n: u32) -> Result<u64> {
        if n == 0 {
            bail!("inode 0 is not valid");
        }
        let group = ((n - 1) / self.inodes_per_group) as usize;
        let index = ((n - 1) % self.inodes_per_group) as u64;
        let itb = *self
            .inode_tables
            .get(group)
            .with_context(|| format!("inode {n} in nonexistent group {group}"))?;
        Ok(itb * self.block_size + index * self.inode_size)
    }

    fn read_inode(&self, n: u32) -> Result<InodeInfo> {
        let off = self.inode_offset(n)?;
        // The base 128 bytes hold every field read here.
        let mut raw = [0u8; 128];
        self.source
            .read_exact_at(&mut raw, off)
            .with_context(|| format!("reading inode {n}"))?;

        let mode = rd16(&raw, 0x00);
        // i_size_high is a regular file's upper size. ext2 used it for directory ACLs, and
        // ext4's largedir for directories over 4 GiB, which this reader does not take: a
        // directory's size is its low 32 bits.
        let size_hi = if mode & S_IFMT == S_IFREG {
            u64::from(rd32(&raw, 0x6C)) << 32
        } else {
            0
        };
        let size = u64::from(rd32(&raw, 0x04)) | size_hi;
        let flags = rd32(&raw, 0x20);
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&raw[0x28..0x28 + 60]);

        // Fast symlink: target inline in i_block, no extents (matches the writer's
        // `target.len() < 60` inline threshold).
        let is_fast_symlink = (mode & S_IFMT) == S_IFLNK && size < FAST_SYMLINK_MAX;

        Ok(InodeInfo {
            ino: n,
            mode,
            size,
            flags,
            i_block,
            is_fast_symlink,
        })
    }

    /// The inode's data as physical runs: its extent tree, or its block map, whose walk
    /// grows with the size it covers: [`Self::read_inode_data`] checks that first.
    fn map_data(&self, info: &InodeInfo) -> Result<Vec<Extent>> {
        if info.is_fast_symlink || info.size == 0 {
            Ok(Vec::new())
        } else if info.flags & EXTENTS_FL != 0 {
            self.parse_extents(&info.i_block, info.ino)
        } else {
            self.parse_block_map(&info.i_block, info.size, info.ino)
        }
    }

    /// Parse the extent tree rooted in the 60-byte i_block region into physical runs.
    /// Accepts inline leaves (depth 0) and an index of leaf blocks (depth 1). Checks header
    /// magic, depth and entry counts before following the entries.
    fn parse_extents(&self, i_block: &[u8; 60], inode: u32) -> Result<Vec<Extent>> {
        if rd16(i_block, 0) != EXT_MAGIC {
            bail!("inode {inode}: bad extent header magic");
        }
        let entries = rd16(i_block, 2) as usize;
        let depth = rd16(i_block, 6);

        match depth {
            0 => parse_leaf_extents(i_block, entries),
            1 => {
                if entries == 0 {
                    return Ok(Vec::new());
                }
                // Depth-1 root: index entries at +12, each 12 bytes, pointing at a leaf
                // block. The writer only ever emits a single index -> single leaf, but
                // gather every index defensively. Bound `entries` by the 60-byte i_block
                // so a corrupt header errors instead of indexing out of bounds.
                let max = (i_block.len() - 12) / 12;
                if entries > max {
                    bail!(
                        "inode {inode}: extent index claims {entries} entries, i_block holds {max}"
                    );
                }
                let mut out = Vec::new();
                for i in 0..entries {
                    let e = 12 + i * 12;
                    let leaf_lo = rd32(i_block, e + 4) as u64;
                    let leaf_hi = rd16(i_block, e + 8) as u64;
                    let leaf_blk = (leaf_hi << 32) | leaf_lo;
                    let mut leaf = self.new_block();
                    self.read_block(leaf_blk, &mut leaf)?;
                    if rd16(&leaf, 0) != EXT_MAGIC {
                        bail!("inode {inode}: bad extent leaf magic");
                    }
                    if rd16(&leaf, 6) != 0 {
                        bail!("inode {inode}: extent tree depth > 1 unsupported");
                    }
                    let lentries = rd16(&leaf, 2) as usize;
                    out.extend(parse_leaf_extents(&leaf, lentries)?);
                }
                Ok(out)
            }
            d => bail!("inode {inode}: extent tree depth {d} > 1 unsupported"),
        }
    }

    /// Map a classic ext2/ext3 inode through 12 direct pointers, then single, double and
    /// triple indirection. The file size bounds the walk even for corrupt pointers. Zero
    /// pointers leave holes that read as zeros.
    fn parse_block_map(&self, i_block: &[u8; 60], size: u64, inode: u32) -> Result<Vec<Extent>> {
        let wanted = size.div_ceil(self.block_size);
        let mut map = BlockMap {
            out: Vec::new(),
            next: 0,
            wanted,
        };
        for i in 0..DIRECT_BLOCKS {
            map.push(u64::from(rd32(i_block, i * 4)));
        }
        for depth in 1..=3 {
            let ptr = u64::from(rd32(i_block, (DIRECT_BLOCKS + depth - 1) * 4));
            self.map_indirect(ptr, depth, &mut map)
                .with_context(|| format!("inode {inode}: block map"))?;
        }
        if map.next < wanted {
            bail!("inode {inode}: {size} bytes, past what a block map addresses");
        }
        Ok(map.out)
    }

    /// At depth 1, `ptr` addresses data pointers. At any depth, a zero pointer skips the
    /// logical blocks its subtree covers, up to EOF.
    fn map_indirect(&self, ptr: u64, depth: usize, map: &mut BlockMap) -> Result<()> {
        if map.next >= map.wanted {
            return Ok(());
        }
        let per_block = self.block_size / 4;
        if ptr == 0 {
            map.skip(per_block.pow(depth as u32));
            return Ok(());
        }
        let mut buf = self.new_block();
        self.read_block(ptr, &mut buf)?;
        for i in 0..per_block as usize {
            if map.next >= map.wanted {
                break;
            }
            let p = u64::from(rd32(&buf, i * 4));
            if depth == 1 {
                map.push(p);
            } else {
                self.map_indirect(p, depth - 1, map)?;
            }
        }
        Ok(())
    }

    /// Read inode data, rejecting sizes above the caller's `max` bytes.
    /// Guest-controlled sizes are untrusted.
    fn read_inode_data(&self, info: &InodeInfo, max: u64) -> Result<Vec<u8>> {
        if info.size > max {
            bail!("inode of {} bytes, over the {max} read here", info.size);
        }
        // Reject a corrupt `i_size` larger than the logical image before it can request a
        // gigabyte-scale allocation. For qcow2, use the virtual size rather than the
        // smaller host file; this bound is only as tight as the run-controlled geometry.
        if info.size > self.image_len {
            bail!(
                "inode size {} exceeds image size {}",
                info.size,
                self.image_len
            );
        }
        // Mapped only now that the size is known to fit the image.
        self.read_runs(info, &self.map_data(info)?)
    }

    /// Read `info`'s data from `extents`, its physical runs.
    fn read_runs(&self, info: &InodeInfo, extents: &[Extent]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; info.size as usize];
        // Extents must map ascending, disjoint ranges, as any writer lays them out; so each
        // logical block is read at most once and the work is bounded by the size.
        let mut next_logical = 0;
        for ex in extents {
            if ex.logical < next_logical {
                bail!(
                    "extent at logical block {} overlaps or is out of order",
                    ex.logical
                );
            }
            next_logical = ex.logical + ex.len;
            let mut buf = self.new_block();
            for i in 0..ex.len {
                let logical = ex.logical + i;
                let start = logical * self.block_size;
                if start >= info.size {
                    break; // extent block beyond EOF; ignore trailing padding
                }
                self.read_block(ex.phys_start + i, &mut buf)?;
                let want = ((info.size - start) as usize).min(self.block_size as usize);
                out[start as usize..start as usize + want].copy_from_slice(&buf[..want]);
            }
        }
        // Any logical gap not covered by an extent stays zero-filled (sparse).
        Ok(out)
    }

    /// Iterate a directory inode's entries, invoking `f(inode, file_type, name)`
    /// for each live entry ("." and ".." included; caller filters).
    fn for_each_dirent(
        &self,
        info: &InodeInfo,
        mut f: impl FnMut(u32, u8, &str) -> Result<()>,
    ) -> Result<()> {
        let data = self.read_inode_data(info, MAX_DIR_BYTES)?;
        // Entries never cross blocks. In a hashed directory, `..` covers the root index
        // through the end of the first block. Each other index block is one unused entry.
        let bs = self.block_size as usize;
        let mut blk = 0usize;
        while blk < data.len() {
            let block = &data[blk..(blk + bs).min(data.len())];
            let mut pos = 0usize;
            while pos + 8 <= block.len() {
                let inode = rd32(block, pos);
                let rec_len = rd16(block, pos + 4) as usize;
                if rec_len < 8 || pos + rec_len > block.len() {
                    break; // malformed/padding: stop this block
                }
                let (name_len, file_type) = if self.dirent_types {
                    (block[pos + 6] as usize, block[pos + 7])
                } else {
                    (rd16(block, pos + 6) as usize, 0)
                };
                if inode != 0 && pos + 8 + name_len <= block.len() {
                    let name = String::from_utf8_lossy(&block[pos + 8..pos + 8 + name_len]);
                    f(inode, file_type, &name)?;
                }
                pos += rec_len;
            }
            blk += bs;
        }
        Ok(())
    }

    /// Find the child inode named `name` in directory inode `info`.
    fn dir_lookup(&self, info: &InodeInfo, name: &str) -> Result<Option<u32>> {
        let mut found = None;
        self.for_each_dirent(info, |inode, _ft, ename| {
            if found.is_none() && ename == name {
                found = Some(inode);
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// Read a symlink target from its inode (fast or extent-backed).
    fn symlink_target(&self, info: &InodeInfo) -> Result<String> {
        let bytes = if info.is_fast_symlink {
            info.i_block[..info.size as usize].to_vec()
        } else {
            self.read_inode_data(info, MAX_SYMLINK_TARGET)?
        };
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Resolve `path` to an inode number, walking from the root. Intermediate
    /// directory symlinks are followed (usrmerge); a trailing symlink is left
    /// unresolved so callers can inspect it. Returns None if any component is missing.
    pub fn lookup(&self, path: &str) -> Result<Option<u32>> {
        let mut hops = MAX_SYMLINK_HOPS;
        self.lookup_within(path, &mut hops)
    }

    /// [`Ext4Reader::lookup`] with a symlink hop budget shared by nested resolutions.
    fn lookup_within(&self, path: &str, hops: &mut u32) -> Result<Option<u32>> {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut cur = ROOT_INO;
        for (i, comp) in comps.iter().enumerate() {
            let is_last = i + 1 == comps.len();
            let info = self.read_inode(cur)?;
            if info.file_type() != FileType::Dir {
                return Ok(None); // a path component wasn't a directory
            }
            let Some(child) = self.dir_lookup(&info, comp)? else {
                return Ok(None);
            };
            if is_last {
                return Ok(Some(child));
            }
            // Intermediate component: follow a symlink so the walk can continue
            // into the real directory.
            cur = self.follow_if_symlink(child, path, hops)?;
        }
        // The empty path (or "/") is the root.
        Ok(Some(cur))
    }

    /// If `ino` is a symlink, resolve its target (relative to the fs root or its
    /// containing dir) to an inode; otherwise return `ino` unchanged. Each hop, including
    /// those inside the targets' own resolution, is paid from `hops`.
    fn follow_if_symlink(&self, ino: u32, context_path: &str, hops: &mut u32) -> Result<u32> {
        let mut cur = ino;
        loop {
            let info = self.read_inode(cur)?;
            if info.file_type() != FileType::Symlink {
                return Ok(cur);
            }
            if *hops == 0 {
                bail!("too many symlink hops resolving {context_path}");
            }
            *hops -= 1;
            let target = self.symlink_target(&info)?;
            // usrmerge links are relative (e.g. "usr/lib"); resolve them against the
            // filesystem root, which is where the writer places them.
            cur = self.lookup_within(&target, hops)?.with_context(|| {
                format!("symlink target {target:?} not found (resolving {context_path})")
            })?;
        }
    }

    /// The type at an absolute path (a trailing symlink is NOT followed), or None
    /// if the path is missing.
    pub fn file_type(&self, path: &str) -> Result<Option<FileType>> {
        match self.lookup(path)? {
            Some(ino) => Ok(Some(self.read_inode(ino)?.file_type())),
            None => Ok(None),
        }
    }

    /// The symlink target for a symlink path (does not resolve it).
    pub fn read_link(&self, path: &str) -> Result<String> {
        let ino = self
            .lookup(path)?
            .with_context(|| format!("{path}: not found"))?;
        let info = self.read_inode(ino)?;
        if info.file_type() != FileType::Symlink {
            bail!("{path}: not a symlink");
        }
        self.symlink_target(&info)
    }

    /// List a directory's entries (name, type), excluding "." and "..".
    pub fn list_dir(&self, path: &str) -> Result<Vec<(String, FileType)>> {
        let mut hops = MAX_SYMLINK_HOPS;
        let ino = self
            .lookup_within(path, &mut hops)?
            .with_context(|| format!("{path}: not found"))?;
        // Follow a trailing symlink to the directory it points at.
        let ino = self.follow_if_symlink(ino, path, &mut hops)?;
        let info = self.read_inode(ino)?;
        if info.file_type() != FileType::Dir {
            bail!("{path}: not a directory");
        }
        let mut out = Vec::new();
        self.for_each_dirent(&info, |cino, ft, name| {
            if name != "." && name != ".." {
                let ft = if self.dirent_types {
                    filetype_from_dirent(ft)
                } else {
                    self.read_inode(cino)?.file_type()
                };
                out.push((name.to_string(), ft));
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Read a regular file's full contents by absolute path (follows a trailing
    /// symlink to a regular file). Errors if missing, not a regular file, or larger than
    /// `max` bytes, since guest-controlled sizes are untrusted.
    pub fn read_file(&self, path: &str, max: u64) -> Result<Vec<u8>> {
        let mut hops = MAX_SYMLINK_HOPS;
        let ino = self
            .lookup_within(path, &mut hops)?
            .with_context(|| format!("{path}: not found"))?;
        let ino = self.follow_if_symlink(ino, path, &mut hops)?;
        let info = self.read_inode(ino)?;
        if info.file_type() != FileType::Regular {
            bail!("{path}: not a regular file");
        }
        self.read_inode_data(&info, max)
            .with_context(|| format!("reading {path}"))
    }
}

/// Physical runs being built from a block map, logical block by logical block.
struct BlockMap {
    out: Vec<Extent>,
    /// The next logical block to map.
    next: u64,
    /// How many logical blocks the file's size covers.
    wanted: u64,
}

impl BlockMap {
    /// Map the next logical block to physical block `phys` (0: a hole), extending the last
    /// run when it continues it.
    fn push(&mut self, phys: u64) {
        if self.next >= self.wanted {
            return;
        }
        if phys != 0 {
            match self.out.last_mut() {
                Some(run)
                    if run.logical + run.len == self.next && run.phys_start + run.len == phys =>
                {
                    run.len += 1
                }
                _ => self.out.push(Extent {
                    logical: self.next,
                    phys_start: phys,
                    len: 1,
                }),
            }
        }
        self.next += 1;
    }

    /// Skip up to `n` logical blocks of a hole, stopping at EOF.
    fn skip(&mut self, n: u64) {
        self.next = self.next.saturating_add(n).min(self.wanted);
    }
}

/// Parse `entries` leaf extents following the 12-byte header at the start of `buf`.
/// `entries` comes straight from an on-disk `eh_entries`, so bound it against what
/// `buf` can actually hold before indexing — a corrupt header must error, not panic.
fn parse_leaf_extents(buf: &[u8], entries: usize) -> Result<Vec<Extent>> {
    let max = buf.len().saturating_sub(12) / 12;
    if entries > max {
        bail!("extent header claims {entries} entries, buffer holds at most {max}");
    }
    let mut out = Vec::with_capacity(entries);
    for i in 0..entries {
        let e = 12 + i * 12;
        let logical = rd32(buf, e) as u64;
        let len = rd16(buf, e + 4) as u64;
        let start_hi = rd16(buf, e + 6) as u64;
        let start_lo = rd32(buf, e + 8) as u64;
        // An ee_len above 32768 marks an unwritten (fallocated) extent. Leave it zero-filled.
        if len > 32768 {
            continue;
        }
        out.push(Extent {
            logical,
            phys_start: (start_hi << 32) | start_lo,
            len,
        });
    }
    Ok(out)
}

/// Decode the type byte on filesystems with `filetype`, including this crate's own images.
fn filetype_from_dirent(ft: u8) -> FileType {
    match ft {
        1 => FileType::Regular,
        2 => FileType::Dir,
        7 => FileType::Symlink,
        _ => FileType::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    /// The block size of this crate's writer.
    const BLOCK: u64 = 4096;

    /// A unique scratch dir we create and remove ourselves (no tempfile dep).
    struct Scratch {
        path: std::path::PathBuf,
    }

    impl Scratch {
        /// A distinct dir: concurrent tests can read the same nanosecond, letting one's
        /// `Drop` remove the tree another is building an image from.
        fn new() -> Scratch {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("vk-ext4-read-{}-{seq}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Scratch { path: p }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Deterministic pseudo-random bytes (a simple LCG), so the large-file
    /// round-trip is reproducible and non-trivial.
    fn pseudo_bytes(n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..n {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push((state >> 33) as u8);
        }
        out
    }

    #[test]
    fn round_trip_reader() {
        let scratch = Scratch::new();
        let src = scratch.path.join("src");
        std::fs::create_dir_all(&src).unwrap();

        // top-level small file
        let top = b"hello from the top\n";
        std::fs::write(src.join("top.txt"), top).unwrap();

        // nested dir a/b/ with a file
        std::fs::create_dir_all(src.join("a/b")).unwrap();
        let nested = b"nested content\n";
        std::fs::write(src.join("a/b/nested.txt"), nested).unwrap();

        // large multi-block file (100 KiB) to exercise multi-extent reads
        let big = pseudo_bytes(100 * 1024);
        std::fs::write(src.join("big.bin"), &big).unwrap();

        // usrmerge-style layout: usr/lib with a real file, and lib -> usr/lib
        std::fs::create_dir_all(src.join("usr/lib")).unwrap();
        let libfile = b"a library file\n";
        std::fs::write(src.join("usr/lib/libx.txt"), libfile).unwrap();
        std::os::unix::fs::symlink("usr/lib", src.join("lib")).unwrap();

        // a symlink to a regular file, for trailing-symlink follow
        std::os::unix::fs::symlink("top.txt", src.join("link-to-top")).unwrap();

        // build the image with the real writer
        let img = scratch.path.join("fs.img");
        crate::ext4::build_from_dir(&src, &img).unwrap();

        let r = Ext4Reader::open(&img).unwrap();

        // exact bytes for the small and large files
        assert_eq!(r.read_file("/top.txt", u64::MAX).unwrap(), top);
        assert_eq!(r.read_file("/a/b/nested.txt", u64::MAX).unwrap(), nested);
        let read_big = r.read_file("/big.bin", u64::MAX).unwrap();
        assert_eq!(read_big.len(), big.len());
        assert_eq!(
            read_big, big,
            "large multi-block file must match byte-for-byte"
        );

        // list the root and the nested dir
        let root: std::collections::HashMap<String, FileType> =
            r.list_dir("/").unwrap().into_iter().collect();
        assert_eq!(root.get("top.txt"), Some(&FileType::Regular));
        assert_eq!(root.get("big.bin"), Some(&FileType::Regular));
        assert_eq!(root.get("a"), Some(&FileType::Dir));
        assert_eq!(root.get("usr"), Some(&FileType::Dir));
        assert_eq!(root.get("lib"), Some(&FileType::Symlink));
        assert_eq!(root.get("link-to-top"), Some(&FileType::Symlink));
        assert!(!root.contains_key("."));
        assert!(!root.contains_key(".."));

        let ab: std::collections::HashMap<String, FileType> =
            r.list_dir("/a/b").unwrap().into_iter().collect();
        assert_eq!(ab.get("nested.txt"), Some(&FileType::Regular));

        // read_link returns the target, unresolved
        assert_eq!(r.read_link("/lib").unwrap(), "usr/lib");
        assert_eq!(r.read_link("/link-to-top").unwrap(), "top.txt");

        // trailing symlink NOT followed by lookup/file_type
        assert_eq!(r.file_type("/lib").unwrap(), Some(FileType::Symlink));

        // reading THROUGH an intermediate symlinked dir resolves (lib -> usr/lib)
        assert_eq!(r.read_file("/lib/libx.txt", u64::MAX).unwrap(), libfile);
        assert_eq!(r.read_file("/usr/lib/libx.txt", u64::MAX).unwrap(), libfile);

        // list_dir follows a trailing symlink to the directory
        let libdir: std::collections::HashMap<String, FileType> =
            r.list_dir("/lib").unwrap().into_iter().collect();
        assert_eq!(libdir.get("libx.txt"), Some(&FileType::Regular));

        // read_file follows a trailing symlink to a regular file
        assert_eq!(r.read_file("/link-to-top", u64::MAX).unwrap(), top);

        // missing paths are None
        assert_eq!(r.lookup("/nope").unwrap(), None);
        assert_eq!(r.lookup("/a/b/missing.txt").unwrap(), None);
        assert_eq!(r.file_type("/does/not/exist").unwrap(), None);
    }

    #[test]
    fn open_rejects_non_ext4() {
        let scratch = Scratch::new();
        let bogus = scratch.path.join("bogus.img");
        let mut f = std::fs::File::create(&bogus).unwrap();
        f.write_all(&vec![0u8; 8192]).unwrap();
        drop(f);
        assert!(Ext4Reader::open(&bogus).is_err());
    }

    /// A guest-written image is not trusted for its geometry, its links or its sizes: a zero
    /// inodes-per-group is an error rather than a division by zero, links that point through
    /// each other end in an error rather than a stack overflow, and a read stops at its cap.
    #[test]
    fn a_hostile_image_errors_rather_than_crashing() {
        let scratch = Scratch::new();
        let src = scratch.path.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.txt"), b"twelve bytes").unwrap();
        std::os::unix::fs::symlink("b/x", src.join("a")).unwrap();
        std::os::unix::fs::symlink("a/x", src.join("b")).unwrap();
        let img = scratch.path.join("fs.img");
        crate::ext4::build_from_dir(&src, &img).unwrap();

        let r = Ext4Reader::open(&img).unwrap();
        assert!(
            r.lookup("/a/x").is_err(),
            "mutual links must not recurse forever"
        );
        assert!(
            r.read_file("/f.txt", 11).is_err(),
            "a read stops at its cap"
        );
        assert_eq!(r.read_file("/f.txt", 12).unwrap(), b"twelve bytes");

        let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        f.write_all_at(&0u32.to_le_bytes(), SB_OFFSET + 0x28)
            .unwrap();
        drop(f);
        assert!(Ext4Reader::open(&img).is_err(), "zero inodes per group");
        let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        f.write_all_at(&(BLOCK as u32 * 8 + 1).to_le_bytes(), SB_OFFSET + 0x28)
            .unwrap();
        drop(f);
        assert!(
            Ext4Reader::open(&img).is_err(),
            "more inodes per group than a bitmap block holds"
        );
    }

    /// A link to itself ends in an error, through every entry point that follows links.
    #[test]
    fn a_self_link_errors() {
        let scratch = Scratch::new();
        let src = scratch.path.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::os::unix::fs::symlink("x", src.join("x")).unwrap();
        let img = scratch.path.join("fs.img");
        crate::ext4::build_from_dir(&src, &img).unwrap();

        let r = Ext4Reader::open(&img).unwrap();
        assert!(r.read_file("/x", u64::MAX).is_err());
        assert!(r.list_dir("/x").is_err());
        assert!(r.lookup("/x/y").is_err());
    }

    /// The hop budget spans a whole call: links followed to reach the last component and
    /// those followed from it draw on the same 40.
    #[test]
    fn hops_are_counted_across_the_whole_call() {
        let scratch = Scratch::new();
        let src = scratch.path.join("src");
        std::fs::create_dir_all(src.join("d")).unwrap();
        std::fs::write(src.join("d/f"), b"f").unwrap();
        // /a<n>-0 -> ... -> /d and /d/t<n>-0 -> ... -> /d/f, `n` hops each.
        let chain = |n: usize| {
            for i in 0..n {
                let next = if i + 1 == n {
                    "d".into()
                } else {
                    format!("a{n}-{}", i + 1)
                };
                std::os::unix::fs::symlink(next, src.join(format!("a{n}-{i}"))).unwrap();
                let next = if i + 1 == n {
                    "d/f".into()
                } else {
                    format!("d/t{n}-{}", i + 1)
                };
                std::os::unix::fs::symlink(next, src.join(format!("d/t{n}-{i}"))).unwrap();
            }
        };
        chain(20);
        chain(21);
        let img = scratch.path.join("fs.img");
        crate::ext4::build_from_dir(&src, &img).unwrap();

        let r = Ext4Reader::open(&img).unwrap();
        assert_eq!(r.read_file("/a20-0/t20-0", u64::MAX).unwrap(), b"f");
        assert!(r.read_file("/a21-0/t21-0", u64::MAX).is_err());
    }

    /// Directory and symlink-target reads stop at their caps, and extents that overlap or
    /// run backwards are refused rather than read over and over.
    #[test]
    fn inode_reads_are_bounded() {
        let scratch = Scratch::new();
        let src = scratch.path.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.bin"), pseudo_bytes(3 * BLOCK as usize)).unwrap();
        let img = scratch.path.join("fs.img");
        crate::ext4::build_from_dir(&src, &img).unwrap();
        let r = Ext4Reader::open(&img).unwrap();
        let ino = r.lookup("/f.bin").unwrap().unwrap();
        let f = r.read_inode(ino).unwrap();
        let phys = r.map_data(&f).unwrap()[0].phys_start;
        let with = |mode: u16, size: u64| InodeInfo {
            ino,
            mode,
            size,
            flags: f.flags,
            i_block: f.i_block,
            is_fast_symlink: false,
        };
        let ex = |logical, len| Extent {
            logical,
            phys_start: phys,
            len,
        };

        let dir = with(S_IFDIR, MAX_DIR_BYTES + 1);
        assert!(r.for_each_dirent(&dir, |_, _, _| Ok(())).is_err());
        let link = with(S_IFLNK, MAX_SYMLINK_TARGET + 1);
        assert!(r.symlink_target(&link).is_err());

        let file = with(S_IFREG, 3 * BLOCK);
        assert!(r.read_runs(&file, &[ex(0, 2), ex(2, 1)]).is_ok());
        assert!(r.read_runs(&file, &[ex(0, 2), ex(1, 2)]).is_err());
        assert!(r.read_runs(&file, &[ex(2, 1), ex(0, 2)]).is_err());
    }

    #[test]
    fn open_reads_through_qcow2() {
        // Exported root and unit images wrap ext4 in qcow2. Verify that the reader uses
        // the format layer instead of parsing the qcow2 header as a superblock.
        let scratch = Scratch::new();
        let src = scratch.path.join("src");
        std::fs::create_dir_all(&src).unwrap();
        let top = b"hello through qcow2\n";
        std::fs::write(src.join("top.txt"), top).unwrap();
        // Cross qcow2 cluster boundaries.
        let big = pseudo_bytes(300 * 1024);
        std::fs::write(src.join("big.bin"), &big).unwrap();
        let raw = scratch.path.join("fs.img");
        crate::ext4::build_from_dir(&src, &raw).unwrap();

        let qcow = scratch.path.join("fs.qcow2");
        let size = std::fs::metadata(&raw).unwrap().len();
        let mut w = crate::qcow2::Qcow2Writer::create(&qcow, size, 0o644).unwrap();
        w.import_raw(&raw).unwrap();
        w.finish().unwrap();
        std::fs::remove_file(&raw).unwrap();

        let r = Ext4Reader::open(&qcow).unwrap();
        assert_eq!(r.read_file("/top.txt", u64::MAX).unwrap(), top);
        assert_eq!(r.read_file("/big.bin", u64::MAX).unwrap(), big);
        assert_eq!(r.file_type("/top.txt").unwrap(), Some(FileType::Regular));
    }

    /// Build ext2 `/boot` images with `mke2fs` using the small and large block and inode
    /// sizes from Debian installer layouts. Read files through direct and indirect blocks.
    #[test]
    fn reads_a_boot_partition_mke2fs_made() {
        let scratch = Scratch::new();
        let src = scratch.path.join("boot");
        std::fs::create_dir_all(src.join("grub")).unwrap();
        // With 1 KiB blocks, 12 KiB fits in direct blocks and each indirect block holds
        // 256 pointers. The 300 KiB kernel reaches double indirection, the 70 MiB tail triple.
        let kernel = pseudo_bytes(300 * 1024 + 123);
        let initrd = pseudo_bytes(40 * 1024);
        std::fs::write(src.join("vmlinuz-6.1.0-42-amd64"), &kernel).unwrap();
        std::fs::write(src.join("initrd.img-6.1.0-42-amd64"), &initrd).unwrap();
        std::fs::write(src.join("grub/grub.cfg"), b"set default=0\n").unwrap();
        let sparse = std::fs::File::create(src.join("sparse.bin")).unwrap();
        sparse.write_all_at(b"tail", 70 << 20).unwrap();
        drop(sparse);
        std::os::unix::fs::symlink("vmlinuz-6.1.0-42-amd64", src.join("vmlinuz")).unwrap();
        let long_target = format!("{}/vmlinuz-6.1.0-42-amd64", "./".repeat(40));
        std::os::unix::fs::symlink(&long_target, src.join("slow-link")).unwrap();
        for i in 0..400 {
            // enough entries for a hashed (dir_index) directory
            std::fs::write(src.join(format!("grub/f{i:03}.mod")), b"m").unwrap();
        }

        // The installer's small and large geometries, 2 KiB blocks, 64-bit descriptors (which
        // need extents), a non-default blocks-per-group, and revision 0's fixed 128-byte
        // inodes.
        for (block, args) in [
            (1024u64, &["-b", "1024", "-I", "128"][..]),
            (4096, &["-b", "4096", "-I", "256"]),
            (2048, &["-b", "2048", "-I", "128"]),
            (
                4096,
                &[
                    "-b",
                    "4096",
                    "-I",
                    "256",
                    "-O",
                    "64bit,extent",
                    "-g",
                    "8192",
                ],
            ),
            (1024, &["-b", "1024", "-I", "128", "-g", "4096"]),
            (1024, &["-b", "1024", "-E", "revision=0"]),
        ] {
            let img = scratch.path.join("boot.img");
            mke2fs(&src, &img, args, "128M");

            let r = Ext4Reader::open(&img).unwrap();
            // Check the block size, group counts for custom groups, and revision-0 layout
            // so an ignored mke2fs option cannot silently substitute a default for these.
            assert_eq!(r.block_size, block, "{args:?}");
            let has = |a: &str| args.contains(&a);
            if has("64bit,extent") {
                assert_eq!(r.inode_tables.len(), 4, "{args:?}");
            }
            if has("4096") && block == 1024 {
                assert_eq!(r.inode_tables.len(), 32, "{args:?}");
            }
            let rev0 = has("revision=0");
            assert_eq!(r.dirent_types, !rev0, "{args:?}");
            if rev0 {
                assert_eq!(r.inode_size, 128, "{args:?}");
            }
            assert_eq!(
                r.read_file("/vmlinuz", u64::MAX).unwrap(),
                kernel,
                "{args:?}"
            );
            assert_eq!(
                r.read_file("/initrd.img-6.1.0-42-amd64", u64::MAX).unwrap(),
                initrd
            );
            assert_eq!(r.read_link("/vmlinuz").unwrap(), "vmlinuz-6.1.0-42-amd64");
            assert_eq!(r.read_link("/slow-link").unwrap(), long_target);
            assert_eq!(r.read_file("/slow-link", u64::MAX).unwrap(), kernel);
            assert_eq!(
                r.read_file("/grub/grub.cfg", 100).unwrap(),
                b"set default=0\n"
            );
            assert_eq!(r.list_dir("/grub").unwrap().len(), 401);
            // Each entry's type, from the entry with `filetype`, from its inode without.
            let root = r.list_dir("/").unwrap();
            for (name, ft) in [
                ("grub", FileType::Dir),
                ("vmlinuz", FileType::Symlink),
                ("initrd.img-6.1.0-42-amd64", FileType::Regular),
            ] {
                assert!(root.contains(&(name.to_string(), ft)), "{args:?}: {root:?}");
            }
            assert_eq!(r.read_file("/grub/f399.mod", 10).unwrap(), b"m");
            let s = r.read_file("/sparse.bin", u64::MAX).unwrap();
            assert_eq!(s.len(), (70 << 20) + 4);
            assert_eq!(&s[70 << 20..], b"tail");
            assert!(
                s[..70 << 20].iter().all(|&b| b == 0),
                "a hole reads as zeros"
            );
        }
    }

    /// A block map is guest data: a pointer past the filesystem is refused, not read.
    #[test]
    fn a_block_pointer_past_the_filesystem_is_refused() {
        let scratch = Scratch::new();
        let src = scratch.path.join("boot");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.bin"), pseudo_bytes(2048)).unwrap();
        let img = scratch.path.join("boot.img");
        mke2fs(&src, &img, &["-b", "1024", "-I", "128"], "8M");
        let r = Ext4Reader::open(&img).unwrap();
        let ino = r.lookup("/f.bin").unwrap().unwrap();
        let first = r.inode_offset(ino).unwrap() + 0x28;
        drop(r);
        let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        f.write_all_at(&u32::MAX.to_le_bytes(), first).unwrap();
        drop(f);
        let r = Ext4Reader::open(&img).unwrap();
        let err = format!("{:#}", r.read_file("/f.bin", u64::MAX).unwrap_err());
        assert!(err.contains("past the filesystem"), "{err}");
    }

    /// `mke2fs -t ext2 ARGS -d SRC IMG SIZE`, which must succeed: the development VM and the
    /// CI toolchain image both carry e2fsprogs.
    fn mke2fs(src: &Path, img: &Path, args: &[&str], size: &str) {
        let out = std::process::Command::new("mke2fs")
            .args(["-q", "-F", "-t", "ext2"])
            .args(args)
            .arg("-d")
            .arg(src)
            .arg(img)
            .arg(size)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "mke2fs {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A superblock field this reader refuses, each patched into a good image.
    #[test]
    fn an_unsupported_superblock_is_refused() {
        let scratch = Scratch::new();
        let src = scratch.path.join("boot");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f"), b"x").unwrap();
        let good = scratch.path.join("good.img");
        mke2fs(&src, &good, &["-b", "1024", "-I", "128"], "8M");
        let sb = SB_OFFSET as usize;
        let incompat = rd32(&std::fs::read(&good).unwrap(), sb + 0x60);
        for (off, value, want) in [
            (0x60, (incompat | INCOMPAT_META_BG).to_le_bytes(), "meta_bg"),
            (
                0x60,
                (incompat | INCOMPAT_INLINE_DATA).to_le_bytes(),
                "inline_data",
            ),
            (
                0x60,
                (incompat | 0x1_0000).to_le_bytes(),
                "incompatible features",
            ),
            (0x20, 0u32.to_le_bytes(), "blocks-per-group"),
            (0x20, (1024u32 * 8 + 1).to_le_bytes(), "blocks-per-group"),
            (0x28, 0u32.to_le_bytes(), "inodes-per-group"),
            (0x14, 0u32.to_le_bytes(), "first data block"),
            (0x04, u32::MAX.to_le_bytes(), "past its"),
        ] {
            let mut img = std::fs::read(&good).unwrap();
            img[sb + off..sb + off + 4].copy_from_slice(&value);
            let path = scratch.path.join("bad.img");
            std::fs::write(&path, &img).unwrap();
            let err = Ext4Reader::open(&path).err().expect(want);
            assert!(format!("{err:#}").contains(want), "{want}: {err:#}");
        }
        // A 64-bit descriptor size below the 64 bytes the feature needs.
        let mut img = std::fs::read(&good).unwrap();
        img[sb + 0x60..sb + 0x64].copy_from_slice(&(incompat | INCOMPAT_64BIT).to_le_bytes());
        img[sb + 0xFE..sb + 0x100].copy_from_slice(&32u16.to_le_bytes());
        let path = scratch.path.join("bad.img");
        std::fs::write(&path, &img).unwrap();
        let err = Ext4Reader::open(&path).err().expect("desc size");
        assert!(format!("{err:#}").contains("descriptor size"), "{err:#}");
    }

    /// A type lookup skips the file's invalid block pointers. A read rejects its oversized
    /// inode before following those pointers.
    #[test]
    fn a_forged_block_map_is_walked_only_by_a_read() {
        let scratch = Scratch::new();
        let src = scratch.path.join("boot");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.bin"), pseudo_bytes(2048)).unwrap();
        let img = scratch.path.join("boot.img");
        mke2fs(&src, &img, &["-b", "1024", "-I", "128"], "8M");
        let r = Ext4Reader::open(&img).unwrap();
        let ino = r.lookup("/f.bin").unwrap().unwrap();
        let at = r.inode_offset(ino).unwrap();
        drop(r);
        let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        f.write_all_at(&[0xFF; 4], at + 0x6C).unwrap(); // i_size_high
        for slot in 0..15 {
            f.write_all_at(&u32::MAX.to_le_bytes(), at + 0x28 + 4 * slot)
                .unwrap();
        }
        drop(f);
        let r = Ext4Reader::open(&img).unwrap();
        assert_eq!(r.file_type("/f.bin").unwrap(), Some(FileType::Regular));
        assert!(r.read_file("/f.bin", 1 << 20).is_err());
        let err = r.read_file("/f.bin", u64::MAX).unwrap_err();
        assert!(format!("{err:#}").contains("exceeds image size"), "{err:#}");
    }
}
