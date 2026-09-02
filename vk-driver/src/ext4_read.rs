//! Read-only extractor for ext4 images produced by this crate's own writer
//! ([`crate::ext4`]) — enough to look up paths, read regular files, list
//! directories and follow symlinks, with no external tools and no mount. It
//! deliberately supports only the exact on-disk layout that writer emits (4 KiB
//! blocks, 256-byte inodes, extents, linear `filetype` directories, fast
//! symlinks) and errors out cleanly on anything else, rather than being a
//! general-purpose ext4 parser.
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

const BLOCK: u64 = 4096;
const INODE_SIZE: u64 = 256;
/// Blocks per group the writer always emits; the reader targets only that geometry.
const BLOCKS_PER_GROUP: u64 = 32768;
const ROOT_INO: u32 = 2;
const SB_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const EXT_MAGIC: u16 = 0xF30A;
const EXTENTS_FL: u32 = 0x0008_0000;

// i_mode type bits (top nibble).
const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;

/// A short symlink whose target is stored inline in the 60-byte i_block region
/// (fast symlink). The writer uses inline storage iff the target is < 60 bytes.
const FAST_SYMLINK_MAX: u64 = 60;

/// Cap on symlink hops while resolving a path, to bound loops.
const MAX_SYMLINK_HOPS: u32 = 8;

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

/// Parsed inode: type/size/flags plus its data laid out as physical runs.
struct InodeInfo {
    mode: u16,
    size: u64,
    /// The raw 60-byte i_block region (holds a fast symlink's target when applicable).
    i_block: [u8; 60],
    is_fast_symlink: bool,
    extents: Vec<Extent>,
}

impl InodeInfo {
    fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }
}

pub struct Ext4Reader {
    source: Source,
    inodes_per_group: u32,
    /// Physical block of each group's inode table (`bg_inode_table_lo`).
    inode_tables: Vec<u64>,
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
    /// Open and parse the superblock. Errors if the geometry isn't this writer's
    /// (bad magic, non-4-KiB blocks, or non-256-byte inodes).
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

        if rd16(&sb, 0x38) != EXT4_MAGIC {
            bail!("{}: not an ext4 image (bad magic)", path.display());
        }
        if rd32(&sb, 0x18) != 2 {
            bail!(
                "{}: unsupported block size (s_log_block_size != 2, not 4 KiB)",
                path.display()
            );
        }
        if rd16(&sb, 0x58) as u64 != INODE_SIZE {
            bail!(
                "{}: unsupported inode size {} (expected {INODE_SIZE})",
                path.display(),
                rd16(&sb, 0x58)
            );
        }

        let blocks_count = rd32(&sb, 0x04) as u64;
        let blocks_per_group = rd32(&sb, 0x20) as u64;
        let inodes_per_group = rd32(&sb, 0x28);
        // The writer emits a fixed geometry; validate it so a corrupt superblock
        // can't drive `groups` (and the GDT allocation below) to an absurd size.
        if blocks_per_group != BLOCKS_PER_GROUP {
            bail!(
                "{}: unsupported blocks-per-group {blocks_per_group} (expected {BLOCKS_PER_GROUP})",
                path.display()
            );
        }
        let groups = blocks_count.div_ceil(blocks_per_group);

        // Group-descriptor table starts at block 1 (block size > 1024, so
        // s_first_data_block is 0 and the descriptors follow the superblock's block).
        // Descriptors are 32 bytes (no 64bit feature).
        let mut gdt = vec![0u8; (groups * 32) as usize];
        source
            .read_exact_at(&mut gdt, BLOCK)
            .with_context(|| format!("reading group descriptors of {}", path.display()))?;
        let inode_tables: Vec<u64> = (0..groups as usize)
            .map(|g| rd32(&gdt, g * 32 + 0x08) as u64)
            .collect();

        Ok(Ext4Reader {
            source,
            inodes_per_group,
            inode_tables,
        })
    }

    fn read_block(&self, blk: u64, buf: &mut [u8; BLOCK as usize]) -> Result<()> {
        self.source
            .read_exact_at(buf, blk * BLOCK)
            .with_context(|| format!("reading block {blk}"))?;
        Ok(())
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
        Ok(itb * BLOCK + index * INODE_SIZE)
    }

    fn read_inode(&self, n: u32) -> Result<InodeInfo> {
        let off = self.inode_offset(n)?;
        let mut raw = [0u8; INODE_SIZE as usize];
        self.source
            .read_exact_at(&mut raw, off)
            .with_context(|| format!("reading inode {n}"))?;

        let mode = rd16(&raw, 0x00);
        let size = rd32(&raw, 0x04) as u64;
        let flags = rd32(&raw, 0x20);
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&raw[0x28..0x28 + 60]);

        // Fast symlink: target inline in i_block, no extents (matches the writer's
        // `target.len() < 60` inline threshold).
        let is_fast_symlink = (mode & S_IFMT) == S_IFLNK && size < FAST_SYMLINK_MAX;

        let extents = if is_fast_symlink || size == 0 {
            Vec::new()
        } else {
            if flags & EXTENTS_FL == 0 {
                bail!("inode {n}: no EXTENTS_FL (unsupported non-extent layout)");
            }
            self.parse_extents(&i_block, n)?
        };

        Ok(InodeInfo {
            mode,
            size,
            i_block,
            is_fast_symlink,
            extents,
        })
    }

    /// Parse the extent tree rooted in the 60-byte i_block region into physical runs.
    /// Supports depth 0 (inline leaf extents) and depth 1 (one index -> a single
    /// leaf block); errors on anything deeper or malformed, which this writer never
    /// produces.
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
                    let mut leaf = [0u8; BLOCK as usize];
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

    fn read_inode_data(&self, info: &InodeInfo) -> Result<Vec<u8>> {
        // Reject a corrupt `i_size` larger than the logical image before it can request a
        // gigabyte-scale allocation. For qcow2, use the virtual size rather than the
        // smaller host file; this bound is only as tight as the run-controlled geometry.
        let image_len = self.source.len()?;
        if info.size > image_len {
            bail!("inode size {} exceeds image size {image_len}", info.size);
        }
        let mut out = vec![0u8; info.size as usize];
        for ex in &info.extents {
            for i in 0..ex.len {
                let logical = ex.logical + i;
                let start = logical * BLOCK;
                if start >= info.size {
                    break; // extent block beyond EOF; ignore trailing padding
                }
                let mut buf = [0u8; BLOCK as usize];
                self.read_block(ex.phys_start + i, &mut buf)?;
                let want = ((info.size - start) as usize).min(BLOCK as usize);
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
        let data = self.read_inode_data(info)?;
        // Entries never straddle a 4 KiB block, so walk block by block.
        let mut blk = 0usize;
        while blk < data.len() {
            let block = &data[blk..(blk + BLOCK as usize).min(data.len())];
            let mut pos = 0usize;
            while pos + 8 <= block.len() {
                let inode = rd32(block, pos);
                let rec_len = rd16(block, pos + 4) as usize;
                if rec_len < 8 || pos + rec_len > block.len() {
                    break; // malformed/padding: stop this block
                }
                let name_len = block[pos + 6] as usize;
                let file_type = block[pos + 7];
                if inode != 0 && pos + 8 + name_len <= block.len() {
                    let name = String::from_utf8_lossy(&block[pos + 8..pos + 8 + name_len]);
                    f(inode, file_type, &name)?;
                }
                pos += rec_len;
            }
            blk += BLOCK as usize;
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
            self.read_inode_data(info)?
        };
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Resolve `path` to an inode number, walking from the root. Intermediate
    /// directory symlinks are followed (usrmerge); a trailing symlink is left
    /// unresolved so callers can inspect it. Returns None if any component is missing.
    pub fn lookup(&self, path: &str) -> Result<Option<u32>> {
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
            cur = self.follow_if_symlink(child, path)?;
        }
        // The empty path (or "/") is the root.
        Ok(Some(cur))
    }

    /// If `ino` is a symlink, resolve its target (relative to the fs root or its
    /// containing dir) to an inode; otherwise return `ino` unchanged. Bounded by
    /// `MAX_SYMLINK_HOPS`.
    fn follow_if_symlink(&self, ino: u32, context_path: &str) -> Result<u32> {
        let mut cur = ino;
        for _ in 0..MAX_SYMLINK_HOPS {
            let info = self.read_inode(cur)?;
            if info.file_type() != FileType::Symlink {
                return Ok(cur);
            }
            let target = self.symlink_target(&info)?;
            // usrmerge links are relative (e.g. "usr/lib"); resolve them against the
            // filesystem root, which is where the writer places them.
            let resolved = self.lookup(&target)?.with_context(|| {
                format!("symlink target {target:?} not found (resolving {context_path})")
            })?;
            cur = resolved;
        }
        bail!("too many symlink hops resolving {context_path}");
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
        let ino = self
            .lookup(path)?
            .with_context(|| format!("{path}: not found"))?;
        // Follow a trailing symlink to the directory it points at.
        let ino = self.follow_if_symlink(ino, path)?;
        let info = self.read_inode(ino)?;
        if info.file_type() != FileType::Dir {
            bail!("{path}: not a directory");
        }
        let mut out = Vec::new();
        self.for_each_dirent(&info, |_cino, ft, name| {
            if name != "." && name != ".." {
                out.push((name.to_string(), filetype_from_dirent(ft)));
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Read a regular file's full contents by absolute path (follows a trailing
    /// symlink to a regular file). Errors if missing or not a regular file.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let ino = self
            .lookup(path)?
            .with_context(|| format!("{path}: not found"))?;
        let ino = self.follow_if_symlink(ino, path)?;
        let info = self.read_inode(ino)?;
        if info.file_type() != FileType::Regular {
            bail!("{path}: not a regular file");
        }
        self.read_inode_data(&info)
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
        let mut len = rd16(buf, e + 4) as u64;
        let start_hi = rd16(buf, e + 6) as u64;
        let start_lo = rd32(buf, e + 8) as u64;
        // ee_len > 32768 marks an uninitialized extent; this writer never emits
        // them, but treat the low bits as the length to be safe.
        if len > 32768 {
            len -= 32768;
        }
        out.push(Extent {
            logical,
            phys_start: (start_hi << 32) | start_lo,
            len,
        });
    }
    Ok(out)
}

/// Map a dir entry's `file_type` byte to a [`FileType`]. The writer sets the
/// `filetype` feature, so this byte is authoritative and no extra inode read is needed.
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

    /// A unique scratch dir we create and remove ourselves (no tempfile dep).
    struct Scratch {
        path: std::path::PathBuf,
    }

    impl Scratch {
        fn new() -> Scratch {
            let mut p = std::env::temp_dir();
            let uniq = format!(
                "vk-ext4-read-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            p.push(uniq);
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
        assert_eq!(r.read_file("/top.txt").unwrap(), top);
        assert_eq!(r.read_file("/a/b/nested.txt").unwrap(), nested);
        let read_big = r.read_file("/big.bin").unwrap();
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
        assert_eq!(r.read_file("/lib/libx.txt").unwrap(), libfile);
        assert_eq!(r.read_file("/usr/lib/libx.txt").unwrap(), libfile);

        // list_dir follows a trailing symlink to the directory
        let libdir: std::collections::HashMap<String, FileType> =
            r.list_dir("/lib").unwrap().into_iter().collect();
        assert_eq!(libdir.get("libx.txt"), Some(&FileType::Regular));

        // read_file follows a trailing symlink to a regular file
        assert_eq!(r.read_file("/link-to-top").unwrap(), top);

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

    #[test]
    fn open_rejects_corrupt_blocks_per_group() {
        // A valid image whose superblock is corrupted must error cleanly rather than
        // driving a huge group-descriptor allocation. Superblock is at byte 1024;
        // s_blocks_per_group is a 4-byte LE field at superblock offset 0x20.
        let scratch = Scratch::new();
        let src = scratch.path.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.txt"), b"x").unwrap();
        let img = scratch.path.join("fs.img");
        crate::ext4::build_from_dir(&src, &img).unwrap();
        assert!(Ext4Reader::open(&img).is_ok());

        use std::os::unix::fs::FileExt;
        let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        f.write_all_at(&1u32.to_le_bytes(), SB_OFFSET + 0x20)
            .unwrap();
        drop(f);
        assert!(Ext4Reader::open(&img).is_err());
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
        assert_eq!(r.read_file("/top.txt").unwrap(), top);
        assert_eq!(r.read_file("/big.bin").unwrap(), big);
        assert_eq!(r.file_type("/top.txt").unwrap(), Some(FileType::Regular));
    }
}
