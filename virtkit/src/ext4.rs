//! Minimal ext4 image writer — builds a mountable, e2fsck-clean filesystem from
//! a directory tree with no external tools (no mke2fs) and no root: ownership,
//! mode and symlinks come straight from the source metadata and are written into
//! the inodes directly. The disk counterpart of cpio.rs, for generic images too
//! large to boot from a RAM initramfs.
//!
//! Feature set, all of which the ext4 kernel driver mounts and e2fsck accepts:
//! 4 KiB blocks, 256-byte inodes, **extents**, `filetype`, `sparse_super`,
//! `large_file`. No journal (the rootfs is read-only under a CoW overlay), no
//! metadata_csum, no 64bit, no flex_bg.
//!
//! Multi-block-group: standard per-group layout (each group carries its own block
//! bitmap, inode bitmap and inode-table slice; sparse_super groups also hold a
//! backup superblock + group-descriptor table). A file's data is one extent when
//! it fits between the per-group metadata holes, otherwise several — packed inline
//! in the inode (≤4) or, beyond that, in a single extent-tree leaf block.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const BLOCK: u64 = 4096;
const INODE_SIZE: u64 = 256;
const INODES_PER_BLOCK: u64 = BLOCK / INODE_SIZE; // 16
const ROOT_INO: u32 = 2;
const LOST_FOUND_INO: u32 = 11;
const FIRST_FREE_INO: u32 = 12;
const BLOCKS_PER_GROUP: u64 = BLOCK * 8; // 32768 (one block of bitmap)

// inode i_flags
const EXTENTS_FL: u32 = 0x0008_0000;
// extent header magic
const EXT_MAGIC: u16 = 0xF30A;
// max extent entries inline in an inode's 60-byte i_block (after the 12-byte header)
const INLINE_EXTENTS: usize = 4;
// max extent entries in a 4 KiB leaf block (after the 12-byte header)
const LEAF_EXTENTS: usize = ((BLOCK - 12) / 12) as usize; // 340
// dir entry file types
const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
const FT_SYMLINK: u8 = 7;
// mode type bits
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

enum Kind {
    Dir { entries: Vec<(String, u32, u8)> }, // (name, child inode, file_type)
    File { src: Src, size: u64 },
    Symlink { target: Vec<u8> },
}

/// Where a regular file's data comes from at write time.
enum Src {
    /// a host file (the injected agent/modules, or the build_from_dir case)
    Host(PathBuf),
    /// a (data offset, length) span within the source tar — read straight from it
    /// at write time (no spill copy), via the tar entry's raw_file_position
    Tar { off: u64, len: u64 },
    /// data already written to the image (the streaming path writes file data as
    /// it arrives); nothing to do at finalize
    Written,
}

struct Node {
    ino: u32,
    parent: u32, // for ".." (dirs only; 0 for files/symlinks)
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: u32,
    links: u16,
    kind: Kind,
    /// physical block runs holding this inode's data, in logical order (empty = none)
    runs: Vec<Range<u64>>,
    /// extent-tree leaf block, when the runs don't fit inline (> INLINE_EXTENTS)
    leaf: Option<u64>,
}

impl Node {
    fn data_blocks(&self) -> u64 {
        self.runs.iter().map(|r| r.end - r.start).sum()
    }
}

/// Build an ext4 image at `out` from the directory tree at `src_dir`.
pub fn build_from_dir(src_dir: &Path, out: &Path) -> Result<()> {
    let mut b = Tree::default();
    b.add_reserved();
    let root = b.walk(src_dir)?;
    debug_assert_eq!(root, ROOT_INO);
    b.write(out, 0)
}

/// Filesystem identity stamped into the superblock. `uuid` (None = random) is set
/// to a content fingerprint so the image's identity == what it was built from
/// (drives CoW-overlay reuse and the rebuild/staleness check); `label` is an
/// optional human-readable name (≤16 bytes) for blkid/lsblk.
#[derive(Default, Clone)]
pub struct FsId {
    pub uuid: Option<[u8; 16]>,
    pub label: Option<String>,
}

/// Build an ext4 image at `out` from the rootfs `tar_path`, injecting the static
/// agent (PID 1). Convenience wrapper over [`build_from_tar_injecting`].
pub fn build_from_tar(tar_path: &Path, agent: &Path, out: &Path) -> Result<()> {
    let inj = [("usr/local/bin/virtkit-agent", agent, 0o755)];
    build_from_tar_injecting(tar_path, &inj, 0, &FsId::default(), out)
}

/// Build an ext4 image at `out` from the rootfs `tar_path`, injecting each host
/// file in `injects` at its guest path with the given mode (e.g. the agent
/// agent, an init shim, captured env). `extra_free_blocks` is spare space left
/// free in the filesystem on top of the rootfs (so the guest can write during the
/// job). Ownership/mode of the rootfs come from the tar headers (no root needed);
/// file data is spilled to a temp blob to avoid buffering the whole rootfs in RAM.
/// No kernel modules: generic guests boot the pinned guest kernel.
pub fn build_from_tar_injecting(
    tar_path: &Path,
    injects: &[(&str, &Path, u16)],
    extra_free_blocks: u64,
    fsid: &FsId,
    out: &Path,
) -> Result<()> {
    let mut t = Tree::default();
    t.add_reserved();
    t.tar_path = Some(tar_path.to_path_buf());
    t.uuid = fsid.uuid;
    t.label = fsid.label.clone();
    t.ensure_dir("")?; // root (+ lost+found)

    let mut ar = tar::Archive::new(
        std::fs::File::open(tar_path).with_context(|| format!("opening {}", tar_path.display()))?,
    );
    for entry in ar.entries()? {
        let mut e = entry?;
        let xattrs = tar_xattrs(&mut e);
        let (etype, mode, uid, gid, mtime, size) = {
            let h = e.header();
            (
                h.entry_type(),
                (h.mode().unwrap_or(0o644) & 0o7777) as u16,
                h.uid().unwrap_or(0) as u32,
                h.gid().unwrap_or(0) as u32,
                h.mtime().unwrap_or(0) as u32,
                h.size().unwrap_or(0),
            )
        };
        let path = e.path()?.to_string_lossy().into_owned();
        let name = normalize(&path);
        if name.is_empty() {
            continue;
        }
        if etype.is_dir() {
            let idx = t.ensure_dir(&name)?;
            t.set_dir_meta(idx, mode, uid, gid, mtime);
        } else if etype.is_symlink() {
            let target = e
                .link_name()?
                .map(|p| p.as_os_str().as_encoded_bytes().to_vec())
                .unwrap_or_default();
            t.add_symlink(&name, uid, gid, mtime, target)?;
        } else if etype.is_file() {
            // record the data span in the tar; the bytes are read at write time
            // (no copy here — we don't read the entry, the iterator seeks past it)
            let off = e.raw_file_position();
            t.add_file(
                &name,
                mode,
                uid,
                gid,
                mtime,
                Src::Tar { off, len: size },
                size,
                xattrs,
            )?;
        } else if etype.is_hard_link() {
            let Some(target) = e.link_name()? else {
                continue;
            };
            t.add_hardlink(&name, &normalize(&target.to_string_lossy()))?;
        }
        // device nodes / fifos / sockets: skipped (irrelevant to a guest rootfs)
    }

    for (guest, host, mode) in injects {
        t.add_host_file(guest, host, *mode)?;
    }
    t.write(out, extra_free_blocks)
}

/// Build an ext4 image by STREAMING the rootfs tar from `reader` in a single pass
/// (e.g. `docker export | …`): file data is written into the image as it arrives,
/// with no intermediate tar and no spill. The geometry is fixed up front from
/// `image_bytes` (an upper bound; the image is sparse so over-estimating is free)
/// and `extra_free_blocks`; `inodes_hint` overrides the inode budget. Only metadata
/// is held in RAM — never file data. Bails if the rootfs or inode count exceeds the
/// estimate (raise it and retry).
pub fn build_from_tar_stream(
    reader: impl Read,
    injects: &[(&str, &Path, u16)],
    image_bytes: u64,
    extra_free_blocks: u64,
    inodes_hint: Option<u64>,
    fsid: &FsId,
    out: &Path,
) -> Result<()> {
    let data_est = image_bytes.div_ceil(BLOCK);
    let want_inodes = inodes_hint.unwrap_or((data_est / 4).max(4096));
    let (layout, total_blocks, inodes_count) =
        plan_layout(data_est, want_inodes, extra_free_blocks);

    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    file.set_len(total_blocks * BLOCK)?;
    let mut w = ImageWriter { file };
    let mut alloc = Allocator::new(&layout, total_blocks);

    let mut t = Tree::default();
    t.add_reserved();
    t.uuid = fsid.uuid;
    t.label = fsid.label.clone();
    t.ensure_dir("")?;

    let mut ar = tar::Archive::new(reader);
    for entry in ar.entries()? {
        let mut e = entry?;
        let xattrs = tar_xattrs(&mut e);
        let (etype, mode, uid, gid, mtime, size) = {
            let h = e.header();
            (
                h.entry_type(),
                (h.mode().unwrap_or(0o644) & 0o7777) as u16,
                h.uid().unwrap_or(0) as u32,
                h.gid().unwrap_or(0) as u32,
                h.mtime().unwrap_or(0) as u32,
                h.size().unwrap_or(0),
            )
        };
        let name = normalize(&e.path()?.to_string_lossy());
        if name.is_empty() {
            continue;
        }
        if etype.is_dir() {
            let idx = t.ensure_dir(&name)?;
            t.set_dir_meta(idx, mode, uid, gid, mtime);
        } else if etype.is_symlink() {
            let target = e
                .link_name()?
                .map(|p| p.as_os_str().as_encoded_bytes().to_vec())
                .unwrap_or_default();
            t.add_symlink(&name, uid, gid, mtime, target)?;
        } else if etype.is_file() {
            let nb = size.div_ceil(BLOCK);
            let mut runs = Vec::new();
            let mut leaf = None;
            if nb > 0 {
                runs = alloc.take(nb)?;
                if runs.len() > INLINE_EXTENTS {
                    if runs.len() > LEAF_EXTENTS {
                        bail!(
                            "file {name} needs {} extents (> {LEAF_EXTENTS})",
                            runs.len()
                        );
                    }
                    leaf = Some(alloc.take(1)?[0].start);
                }
                // stream the data straight into the allocated blocks
                write_runs(&mut w, &runs, &mut e)?;
            }
            t.add_file_streamed(&name, mode, uid, gid, mtime, size, runs, leaf, xattrs)?;
            if u64::from(t.next_ino - 1) > inodes_count {
                bail!("inode budget ({inodes_count}) exceeded — raise the size/inode estimate");
            }
        } else if etype.is_hard_link() {
            let Some(target) = e.link_name()? else {
                continue;
            };
            t.add_hardlink(&name, &normalize(&target.to_string_lossy()))?;
        }
        // device nodes / fifos / sockets: skipped
    }

    // injected host files: allocated + written by the finalize pass (host-backed)
    for (guest, host, mode) in injects {
        t.add_host_file(guest, host, *mode)?;
    }

    // allocate blocks for everything not streamed (dirs, symlinks, injects) + leaves
    t.nodes.sort_by_key(|n| n.ino);
    for n in t.nodes.iter_mut() {
        if !n.runs.is_empty() {
            continue; // streamed files already have their blocks
        }
        let nb = match &n.kind {
            Kind::Dir { entries } => dir_blocks(entries),
            Kind::File { size, .. } => size.div_ceil(BLOCK),
            Kind::Symlink { target } if target.len() >= 60 => 1,
            _ => 0,
        };
        if nb == 0 {
            continue;
        }
        n.runs = alloc.take(nb)?;
        if n.runs.len() > INLINE_EXTENTS {
            if n.runs.len() > LEAF_EXTENTS {
                bail!(
                    "inode {} needs {} extents (> {LEAF_EXTENTS})",
                    n.ino,
                    n.runs.len()
                );
            }
            n.leaf = Some(alloc.take(1)?[0].start);
        }
    }

    let used_inodes = u64::from(t.next_ino - 1);
    t.finalize(&mut w, &layout, total_blocks, inodes_count, used_inodes)
}

/// Strip a tar path to a clean relative form (no `./`, no leading/trailing `/`).
fn normalize(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn split_parent(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((p, b)) => (p, b),
        None => ("", path),
    }
}

#[derive(Default)]
struct Tree {
    nodes: Vec<Node>,
    next_ino: u32,
    /// path (no leading/trailing slash) -> node index, used while building from
    /// a tar (where children may precede/follow their parent dir)
    by_path: HashMap<String, usize>,
    /// file path -> inode, so a tar hardlink can point at the file it targets
    file_ino: HashMap<String, u32>,
    /// inode -> node index, to bump a target's link count on a hardlink
    idx_by_ino: HashMap<u32, usize>,
    /// symlink path -> target, so an injection under a symlinked dir (usrmerge:
    /// /sbin -> usr/sbin) resolves to the real directory instead of duplicating it
    symlinks: HashMap<String, String>,
    /// inode -> extended attributes (e.g. security.capability from a tar's
    /// SCHILY.xattr.* records), written into the inode at finalize
    xattrs: HashMap<u32, Vec<(String, Vec<u8>)>>,
    /// the source tar, read at write time for Src::Tar spans (no spill copy)
    tar_path: Option<PathBuf>,
    /// s_uuid to write (None = a random one): set to a content fingerprint so the
    /// image's identity == what it was built from (overlay reuse + staleness check)
    uuid: Option<[u8; 16]>,
    /// s_volume_name to write (a human-readable name for blkid/lsblk; ≤16 bytes)
    label: Option<String>,
}

impl Tree {
    /// Reserve inodes 1..=11 (root=2, lost+found=11 are real; the rest are the
    /// classic reserved set, left unused but counted).
    fn add_reserved(&mut self) {
        self.next_ino = FIRST_FREE_INO;
    }

    fn alloc_ino(&mut self) -> u32 {
        let i = self.next_ino;
        self.next_ino += 1;
        i
    }

    /// Path-keyed directory creation (tar builder): make `path` and any missing
    /// ancestors, return its node index. `""` is the root (gets lost+found).
    fn ensure_dir(&mut self, path: &str) -> Result<usize> {
        if let Some(&i) = self.by_path.get(path) {
            return Ok(i);
        }
        let ino = if path.is_empty() {
            ROOT_INO
        } else {
            self.alloc_ino()
        };
        let idx = self.nodes.len();
        self.nodes.push(Node {
            ino,
            parent: ROOT_INO,
            mode: S_IFDIR | 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
            links: 2,
            kind: Kind::Dir {
                entries: Vec::new(),
            },
            runs: Vec::new(),
            leaf: None,
        });
        self.by_path.insert(path.to_string(), idx);
        if path.is_empty() {
            self.add_lost_found(ROOT_INO);
            self.add_child(idx, "lost+found", LOST_FOUND_INO, FT_DIR);
            self.nodes[idx].links += 1;
        } else {
            let (parent, name) = split_parent(path);
            let pidx = self.ensure_dir(parent)?;
            self.add_child(pidx, name, ino, FT_DIR);
            self.nodes[pidx].links += 1; // the child's ".." references the parent
            self.nodes[idx].parent = self.nodes[pidx].ino;
        }
        Ok(idx)
    }

    fn set_dir_meta(&mut self, idx: usize, mode: u16, uid: u32, gid: u32, mtime: u32) {
        let n = &mut self.nodes[idx];
        n.mode = S_IFDIR | (mode & 0o7777);
        n.uid = uid;
        n.gid = gid;
        n.mtime = mtime;
    }

    fn add_child(&mut self, pidx: usize, name: &str, ino: u32, ft: u8) {
        if let Kind::Dir { entries } = &mut self.nodes[pidx].kind {
            entries.push((name.to_string(), ino, ft));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_file(
        &mut self,
        path: &str,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u32,
        src: Src,
        size: u64,
        xattrs: Vec<(String, Vec<u8>)>,
    ) -> Result<()> {
        let (parent, base) = split_parent(path);
        let pidx = self.ensure_dir(parent)?;
        let ino = self.alloc_ino();
        let idx = self.nodes.len();
        self.nodes.push(Node {
            ino,
            parent: 0,
            mode: S_IFREG | (mode & 0o7777),
            uid,
            gid,
            mtime,
            links: 1,
            kind: Kind::File { src, size },
            runs: Vec::new(),
            leaf: None,
        });
        self.add_child(pidx, base, ino, FT_REG);
        self.file_ino.insert(path.to_string(), ino);
        self.idx_by_ino.insert(ino, idx);
        if !xattrs.is_empty() {
            self.xattrs.insert(ino, xattrs);
        }
        Ok(())
    }

    /// Add a regular file whose data was already written to the image (streaming
    /// path): the runs/leaf are pre-allocated, the data on disk.
    #[allow(clippy::too_many_arguments)]
    fn add_file_streamed(
        &mut self,
        path: &str,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u32,
        size: u64,
        runs: Vec<Range<u64>>,
        leaf: Option<u64>,
        xattrs: Vec<(String, Vec<u8>)>,
    ) -> Result<()> {
        let (parent, base) = split_parent(path);
        let pidx = self.ensure_dir(parent)?;
        let ino = self.alloc_ino();
        let idx = self.nodes.len();
        self.nodes.push(Node {
            ino,
            parent: 0,
            mode: S_IFREG | (mode & 0o7777),
            uid,
            gid,
            mtime,
            links: 1,
            kind: Kind::File {
                src: Src::Written,
                size,
            },
            runs,
            leaf,
        });
        self.add_child(pidx, base, ino, FT_REG);
        self.file_ino.insert(path.to_string(), ino);
        self.idx_by_ino.insert(ino, idx);
        if !xattrs.is_empty() {
            self.xattrs.insert(ino, xattrs);
        }
        Ok(())
    }

    /// A tar hardlink: a second name for an already-seen file. tar emits the data
    /// file first, so `target` is known — point a new dir entry at its inode and
    /// bump that inode's link count (no data is duplicated).
    fn add_hardlink(&mut self, path: &str, target: &str) -> Result<()> {
        let Some(&tino) = self.file_ino.get(target) else {
            bail!("hardlink {path} -> unknown target {target}");
        };
        let (parent, base) = split_parent(path);
        let pidx = self.ensure_dir(parent)?;
        self.add_child(pidx, base, tino, FT_REG);
        let nidx = self.idx_by_ino[&tino];
        self.nodes[nidx].links += 1;
        Ok(())
    }

    fn add_symlink(
        &mut self,
        path: &str,
        uid: u32,
        gid: u32,
        mtime: u32,
        target: Vec<u8>,
    ) -> Result<()> {
        self.symlinks.insert(
            path.to_string(),
            String::from_utf8_lossy(&target).into_owned(),
        );
        let (parent, base) = split_parent(path);
        let pidx = self.ensure_dir(parent)?;
        let ino = self.alloc_ino();
        self.nodes.push(Node {
            ino,
            parent: 0,
            mode: S_IFLNK | 0o777,
            uid,
            gid,
            mtime,
            links: 1,
            kind: Kind::Symlink { target },
            runs: Vec::new(),
            leaf: None,
        });
        self.add_child(pidx, base, ino, FT_SYMLINK);
        Ok(())
    }

    fn add_host_file(&mut self, path: &str, host: &Path, mode: u16) -> Result<()> {
        let size = std::fs::metadata(host)
            .with_context(|| format!("stat {}", host.display()))?
            .len();
        // Resolve symlinked parent dirs (usrmerge) so we land in the real directory.
        let (parent, base) = split_parent(path);
        let rparent = self.resolve_dir(parent);
        let rpath = if rparent.is_empty() {
            base.to_string()
        } else {
            format!("{rparent}/{base}")
        };
        self.add_file(
            &rpath,
            mode,
            0,
            0,
            0,
            Src::Host(host.to_path_buf()),
            size,
            Vec::new(),
        )
    }

    /// Resolve a directory path through known symlinks (a leading-component
    /// usrmerge target like `sbin -> usr/sbin`), returning a real directory path.
    fn resolve_dir(&self, dir: &str) -> String {
        let mut cur = String::new();
        for comp in dir.split('/').filter(|c| !c.is_empty()) {
            let next = if cur.is_empty() {
                comp.to_string()
            } else {
                format!("{cur}/{comp}")
            };
            cur = match self.symlinks.get(&next) {
                // usrmerge targets are root-relative ("usr/sbin"); take as-is
                Some(target) => target
                    .trim_start_matches('/')
                    .trim_end_matches('/')
                    .to_string(),
                None => next,
            };
        }
        cur
    }

    /// Recursively add `dir` as the root directory (inode 2) and return its ino.
    fn walk(&mut self, dir: &Path) -> Result<u32> {
        self.add_dir(dir, ROOT_INO, ROOT_INO)
    }

    /// Add `dir` with inode `ino` whose parent is `parent_ino`; recurse.
    fn add_dir(&mut self, dir: &Path, ino: u32, parent_ino: u32) -> Result<u32> {
        let md =
            std::fs::symlink_metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
        let mut entries: Vec<(String, u32, u8)> = Vec::new();
        let mut links: u16 = 2; // "." and the parent's reference
        // root also gets lost+found
        if ino == ROOT_INO {
            entries.push(("lost+found".into(), LOST_FOUND_INO, FT_DIR));
            self.add_lost_found(ino);
            links += 1;
        }
        let mut children: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)
            .with_context(|| format!("reading dir {}", dir.display()))?
            .collect::<std::io::Result<_>>()?;
        children.sort_by_key(|e| e.file_name());
        for child in children {
            let name = child.file_name().to_string_lossy().into_owned();
            let path = child.path();
            let cmd = std::fs::symlink_metadata(&path)
                .with_context(|| format!("stat {}", path.display()))?;
            let ft = cmd.file_type();
            let cino = self.alloc_ino();
            if ft.is_dir() {
                self.add_dir(&path, cino, ino)?;
                entries.push((name, cino, FT_DIR));
                links += 1; // child's ".." references us
            } else if ft.is_symlink() {
                let target = std::fs::read_link(&path)?
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec();
                self.push_symlink(cino, &cmd, target);
                entries.push((name, cino, FT_SYMLINK));
            } else if ft.is_file() {
                self.push_file(cino, &cmd, path);
                entries.push((name, cino, FT_REG));
            }
            // skip devices/fifos/sockets
        }
        self.nodes.push(Node {
            ino,
            parent: parent_ino,
            mode: S_IFDIR | (md.mode() as u16 & 0o7777),
            uid: md.uid(),
            gid: md.gid(),
            mtime: md.mtime() as u32,
            links,
            kind: Kind::Dir { entries },
            runs: Vec::new(),
            leaf: None,
        });
        Ok(ino)
    }

    fn add_lost_found(&mut self, parent: u32) {
        self.nodes.push(Node {
            ino: LOST_FOUND_INO,
            parent,
            mode: S_IFDIR | 0o700,
            uid: 0,
            gid: 0,
            mtime: 0,
            links: 2,
            kind: Kind::Dir {
                entries: Vec::new(),
            },
            runs: Vec::new(),
            leaf: None,
        });
    }

    fn push_file(&mut self, ino: u32, md: &std::fs::Metadata, src: PathBuf) {
        self.nodes.push(Node {
            ino,
            parent: 0,
            mode: S_IFREG | (md.mode() as u16 & 0o7777),
            uid: md.uid(),
            gid: md.gid(),
            mtime: md.mtime() as u32,
            links: 1,
            kind: Kind::File {
                src: Src::Host(src),
                size: md.len(),
            },
            runs: Vec::new(),
            leaf: None,
        });
    }

    fn push_symlink(&mut self, ino: u32, md: &std::fs::Metadata, target: Vec<u8>) {
        self.nodes.push(Node {
            ino,
            parent: 0,
            mode: S_IFLNK | 0o777,
            uid: md.uid(),
            gid: md.gid(),
            mtime: md.mtime() as u32,
            links: 1,
            kind: Kind::Symlink { target },
            runs: Vec::new(),
            leaf: None,
        });
    }

    fn write(mut self, out: &Path, extra_free_blocks: u64) -> Result<()> {
        self.nodes.sort_by_key(|n| n.ino);
        let used_inodes = u64::from(self.next_ino - 1);

        // Logical block count each inode needs for its own data.
        let logical: Vec<u64> = self
            .nodes
            .iter()
            .map(|n| match &n.kind {
                Kind::Dir { entries } => dir_blocks(entries),
                Kind::File { size, .. } => size.div_ceil(BLOCK),
                // fast (inline) symlink iff it fits in the 60-byte i_block: len < 60
                Kind::Symlink { target } if target.len() >= 60 => 1,
                Kind::Symlink { .. } => 0,
            })
            .collect();
        let data_logical: u64 = logical.iter().sum();

        let want_inodes = used_inodes + used_inodes / 4 + 64;
        let (layout, total_blocks, inodes_count) =
            plan_layout(data_logical, want_inodes, extra_free_blocks);
        let groups = layout.groups;

        // Allocate data block runs to every inode, drawing from each group's free
        // data region in order and skipping the metadata holes.
        let mut alloc = Allocator::new(&layout, total_blocks);
        for (n, &nb) in self.nodes.iter_mut().zip(&logical) {
            if nb == 0 {
                continue;
            }
            n.runs = alloc.take(nb)?;
            if n.runs.len() > INLINE_EXTENTS {
                if n.runs.len() > LEAF_EXTENTS {
                    bail!(
                        "inode {} needs {} extents (> {LEAF_EXTENTS})",
                        n.ino,
                        n.runs.len()
                    );
                }
                n.leaf = Some(alloc.take(1)?[0].start);
            }
        }

        let _ = groups;
        let file =
            std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
        file.set_len(total_blocks * BLOCK)?;
        let mut w = ImageWriter { file };
        self.finalize(&mut w, &layout, total_blocks, inodes_count, used_inodes)
    }

    /// Write all of the on-disk structures once every inode's runs/leaf are
    /// allocated: bitmaps + descriptors + inode tables + the data the write_data
    /// pass still owns (dirs, symlinks, host injects; streamed file data is
    /// already on disk). Shared by the buffered and streaming builders.
    fn finalize(
        &self,
        w: &mut ImageWriter,
        layout: &Layout,
        total_blocks: u64,
        inodes_count: u64,
        used_inodes: u64,
    ) -> Result<()> {
        // One global block-usage bitmap is the single source of truth for the free
        // counts (superblock total and per-group descriptors must agree).
        let mut block_used = BitVec::new(total_blocks);
        for g in 0..layout.groups {
            for b in layout.group_meta_range(g) {
                block_used.set(b);
            }
        }
        for n in &self.nodes {
            for r in &n.runs {
                for b in r.clone() {
                    block_used.set(b);
                }
            }
            if let Some(b) = n.leaf {
                block_used.set(b);
            }
        }
        let free_blocks = (0..total_blocks).filter(|&b| !block_used.get(b)).count() as u64;
        let free_inodes = inodes_count - used_inodes;

        self.write_superblocks(
            w,
            layout,
            total_blocks,
            inodes_count,
            free_blocks,
            free_inodes,
        )?;
        self.write_group_descs(w, layout, &block_used, inodes_count)?;
        self.write_block_bitmaps(w, layout, &block_used)?;
        self.write_inode_bitmaps(w, layout, inodes_count)?;
        self.write_inodes(w, layout)?;
        self.write_data(w)?;
        w.file.flush()?;
        Ok(())
    }

    fn write_superblocks(
        &self,
        w: &mut ImageWriter,
        layout: &Layout,
        total_blocks: u64,
        inodes_count: u64,
        free_blocks: u64,
        free_inodes: u64,
    ) -> Result<()> {
        let mut sb = [0u8; 1024];
        le32(&mut sb, 0x00, inodes_count as u32);
        le32(&mut sb, 0x04, total_blocks as u32); // s_blocks_count_lo
        le32(&mut sb, 0x08, 0); // s_r_blocks_count_lo
        le32(&mut sb, 0x0c, free_blocks as u32);
        le32(&mut sb, 0x10, free_inodes as u32);
        le32(&mut sb, 0x14, 0); // s_first_data_block (0 for >1K blocks)
        le32(&mut sb, 0x18, 2); // s_log_block_size (4096)
        le32(&mut sb, 0x1c, 2); // s_log_cluster_size
        le32(&mut sb, 0x20, BLOCKS_PER_GROUP as u32); // s_blocks_per_group
        le32(&mut sb, 0x24, BLOCKS_PER_GROUP as u32); // s_clusters_per_group
        le32(&mut sb, 0x28, layout.ipg as u32); // s_inodes_per_group
        le16(&mut sb, 0x38, 0xEF53); // s_magic
        le16(&mut sb, 0x3a, 1); // s_state = clean
        le16(&mut sb, 0x3c, 1); // s_errors = continue
        le32(&mut sb, 0x4c, 1); // s_rev_level = dynamic
        le32(&mut sb, 0x54, LOST_FOUND_INO); // s_first_ino
        le16(&mut sb, 0x58, INODE_SIZE as u16); // s_inode_size
        le32(&mut sb, 0x5c, 0); // s_feature_compat
        le32(&mut sb, 0x60, 0x42); // s_feature_incompat = filetype|extents
        le32(&mut sb, 0x64, 0x3); // s_feature_ro_compat = sparse_super|large_file
        // s_uuid (0x68, 16 bytes): the image's identity, used to detect a stale CoW
        // overlay AND (when set to a content fingerprint) to decide a rebuild. A
        // random one (like mke2fs) is the fallback when no fingerprint is given.
        sb[0x68..0x78].copy_from_slice(&self.uuid.unwrap_or_else(random_uuid));
        // s_volume_name (0x78, 16 bytes): an optional human-readable label (blkid).
        if let Some(label) = &self.label {
            let b = label.as_bytes();
            let n = b.len().min(16);
            sb[0x78..0x78 + n].copy_from_slice(&b[..n]);
        }

        // Primary at byte 1024; backups at the start of each sparse_super group,
        // with s_block_group_nr set to that group.
        w.file.seek(SeekFrom::Start(1024))?;
        w.file.write_all(&sb)?;
        for g in 1..layout.groups {
            if sparse_super(g) {
                le16(&mut sb, 0x5a, g as u16); // s_block_group_nr
                w.file.seek(SeekFrom::Start(g * BLOCKS_PER_GROUP * BLOCK))?;
                w.file.write_all(&sb)?;
            }
        }
        Ok(())
    }

    fn write_group_descs(
        &self,
        w: &mut ImageWriter,
        layout: &Layout,
        block_used: &BitVec,
        inodes_count: u64,
    ) -> Result<()> {
        // Per-group counts.
        let mut gdt = vec![0u8; (layout.groups * 32) as usize];
        for g in 0..layout.groups {
            let (bb, ib, it) = layout.group_meta_locs(g);
            let off = (g * 32) as usize;
            le32(&mut gdt, off, bb as u32); // bg_block_bitmap_lo
            le32(&mut gdt, off + 0x04, ib as u32); // bg_inode_bitmap_lo
            le32(&mut gdt, off + 0x08, it as u32); // bg_inode_table_lo
            le16(
                &mut gdt,
                off + 0x0c,
                self.group_free_blocks(layout, block_used, g) as u16,
            );
            le16(
                &mut gdt,
                off + 0x0e,
                self.group_free_inodes(layout, inodes_count, g) as u16,
            );
            le16(&mut gdt, off + 0x10, self.group_dirs(layout, g) as u16);
        }
        // GDT lives at block 1 of group 0, and is duplicated right after each
        // backup superblock.
        let gdt_padded = round_up(gdt.len() as u64, layout.gdt_blocks * BLOCK) as usize;
        let mut padded = gdt.clone();
        padded.resize(gdt_padded, 0);
        w.file.seek(SeekFrom::Start(BLOCK))?;
        w.file.write_all(&padded)?;
        for g in 1..layout.groups {
            if sparse_super(g) {
                w.file
                    .seek(SeekFrom::Start((g * BLOCKS_PER_GROUP + 1) * BLOCK))?;
                w.file.write_all(&padded)?;
            }
        }
        Ok(())
    }

    fn write_block_bitmaps(
        &self,
        w: &mut ImageWriter,
        layout: &Layout,
        block_used: &BitVec,
    ) -> Result<()> {
        for g in 0..layout.groups {
            let mut bm = vec![0u8; BLOCK as usize];
            for i in 0..BLOCKS_PER_GROUP {
                let blk = g * BLOCKS_PER_GROUP + i;
                // beyond the device (last group padding) reads as used
                if blk >= block_used.bits || block_used.get(blk) {
                    bm[(i / 8) as usize] |= 1 << (i % 8);
                }
            }
            let (bb, _, _) = layout.group_meta_locs(g);
            w.file.seek(SeekFrom::Start(bb * BLOCK))?;
            w.file.write_all(&bm)?;
        }
        Ok(())
    }

    fn write_inode_bitmaps(
        &self,
        w: &mut ImageWriter,
        layout: &Layout,
        inodes_count: u64,
    ) -> Result<()> {
        let used_inodes = u64::from(self.next_ino - 1);
        for g in 0..layout.groups {
            let mut bm = vec![0xFFu8; BLOCK as usize]; // bits beyond ipg stay 1
            for i in 0..layout.ipg {
                let ino = g * layout.ipg + i + 1; // 1-based
                let used = ino <= used_inodes || ino > inodes_count;
                if !used {
                    bm[(i / 8) as usize] &= !(1 << (i % 8));
                }
            }
            let (_, ib, _) = layout.group_meta_locs(g);
            w.file.seek(SeekFrom::Start(ib * BLOCK))?;
            w.file.write_all(&bm)?;
        }
        Ok(())
    }

    fn write_inodes(&self, w: &mut ImageWriter, layout: &Layout) -> Result<()> {
        for n in &self.nodes {
            let mut ino = [0u8; INODE_SIZE as usize];
            le16(&mut ino, 0x00, n.mode);
            le16(&mut ino, 0x02, n.uid as u16);
            le16(&mut ino, 0x18, n.gid as u16);
            le16(&mut ino, 0x1a, n.links);
            le32(&mut ino, 0x08, n.mtime); // atime
            le32(&mut ino, 0x0c, n.mtime); // ctime
            le32(&mut ino, 0x10, n.mtime); // mtime
            le16(&mut ino, 0x80, 32); // i_extra_isize
            let size = inode_size(n);
            le32(&mut ino, 0x04, size as u32);
            le32(&mut ino, 0x6c, (size >> 32) as u32); // i_size_high
            let phys = n.data_blocks() + u64::from(n.leaf.is_some());
            le32(&mut ino, 0x1c, (phys * (BLOCK / 512)) as u32); // i_blocks_lo

            match &n.kind {
                Kind::Symlink { target } if target.len() < 60 => {
                    ino[0x28..0x28 + target.len()].copy_from_slice(target);
                }
                _ => {
                    le32(&mut ino, 0x20, EXTENTS_FL);
                    write_inode_extents(&mut ino, n);
                }
            }
            if let Some(xa) = self.xattrs.get(&n.ino)
                && !write_inode_xattrs(&mut ino, xa)
            {
                eprintln!("ext4: inode {} xattrs don't fit in-inode, dropped", n.ino);
            }
            w.file.seek(SeekFrom::Start(layout.inode_offset(n.ino)))?;
            w.file.write_all(&ino)?;
        }
        Ok(())
    }

    fn write_data(&self, w: &mut ImageWriter) -> Result<()> {
        let mut tar = match &self.tar_path {
            Some(p) => {
                Some(std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?)
            }
            None => None,
        };
        for n in &self.nodes {
            // Extent-tree leaf (when runs don't fit inline): a depth-0 header + the runs.
            if let Some(leaf) = n.leaf {
                let mut buf = vec![0u8; BLOCK as usize];
                write_extent_entries(&mut buf, 0, &n.runs);
                w.file.seek(SeekFrom::Start(leaf * BLOCK))?;
                w.file.write_all(&buf)?;
            }
            match &n.kind {
                Kind::Dir { entries } => {
                    let buf = dir_data(n.ino, n.parent, entries);
                    write_runs(w, &n.runs, &mut std::io::Cursor::new(buf))?;
                }
                Kind::File { size, .. } if *size == 0 => {}
                Kind::File {
                    src: Src::Written, ..
                } => {} // streamed: already on disk
                Kind::File {
                    src: Src::Host(p), ..
                } => {
                    let mut f = std::fs::File::open(p)
                        .with_context(|| format!("opening {}", p.display()))?;
                    write_runs(w, &n.runs, &mut f)?;
                }
                Kind::File {
                    src: Src::Tar { off, len },
                    ..
                } => {
                    let tar = tar.as_mut().expect("tar_path set for tar-sourced files");
                    tar.seek(SeekFrom::Start(*off))?;
                    write_runs(w, &n.runs, &mut tar.take(*len))?;
                }
                Kind::Symlink { target } if target.len() >= 60 => {
                    write_runs(w, &n.runs, &mut std::io::Cursor::new(target.clone()))?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    // ---- per-group counting helpers ----

    fn group_free_blocks(&self, _layout: &Layout, block_used: &BitVec, g: u64) -> u64 {
        let group_blocks = group_block_count(g, block_used.bits);
        let mut free = 0;
        for i in 0..group_blocks {
            if !block_used.get(g * BLOCKS_PER_GROUP + i) {
                free += 1;
            }
        }
        free
    }

    fn group_free_inodes(&self, layout: &Layout, inodes_count: u64, g: u64) -> u64 {
        let used_inodes = u64::from(self.next_ino - 1);
        let lo = g * layout.ipg + 1;
        let hi = (lo + layout.ipg).min(inodes_count + 1);
        let mut free = 0;
        for ino in lo..hi {
            if ino > used_inodes {
                free += 1;
            }
        }
        free
    }

    fn group_dirs(&self, layout: &Layout, g: u64) -> u64 {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, Kind::Dir { .. }))
            .filter(|n| (u64::from(n.ino) - 1) / layout.ipg == g)
            .count() as u64
    }
}

/// Per-group geometry of the image.
struct Layout {
    groups: u64,
    ipg: u64,        // inodes per group
    itb: u64,        // inode-table blocks per group
    gdt_blocks: u64, // group-descriptor-table blocks
}

impl Layout {
    /// Blocks consumed by group `g`'s own metadata (backup sb+gdt for sparse_super
    /// groups, plus block bitmap + inode bitmap + inode table).
    fn group_meta_count(&self, g: u64) -> u64 {
        self.meta_off(g) + 2 + self.itb
    }

    /// Leading blocks of group `g` reserved for the superblock + GDT: the primary
    /// pair in group 0 (also a sparse_super group), a backup pair in the other
    /// sparse_super groups, nothing elsewhere.
    fn meta_off(&self, g: u64) -> u64 {
        if sparse_super(g) {
            1 + self.gdt_blocks
        } else {
            0
        }
    }

    /// (block_bitmap, inode_bitmap, inode_table) absolute block numbers for group g.
    fn group_meta_locs(&self, g: u64) -> (u64, u64, u64) {
        let base = g * BLOCKS_PER_GROUP + self.meta_off(g);
        (base, base + 1, base + 2)
    }

    /// Every metadata block of group g (sb/gdt backup + bitmaps + inode table) as
    /// an absolute block range for bitmap marking.
    fn group_meta_range(&self, g: u64) -> Range<u64> {
        let start = g * BLOCKS_PER_GROUP;
        start..start + self.group_meta_count(g)
    }

    fn group_meta_blocks(&self, g: u64) -> u64 {
        self.group_meta_count(g)
    }

    /// First data block (after metadata) of group g.
    fn group_data_start(&self, g: u64) -> u64 {
        g * BLOCKS_PER_GROUP + self.group_meta_count(g)
    }

    /// Byte offset of inode `ino`'s slot in its group's inode table.
    fn inode_offset(&self, ino: u32) -> u64 {
        let idx = u64::from(ino) - 1;
        let g = idx / self.ipg;
        let slot = idx % self.ipg;
        let (_, _, it) = self.group_meta_locs(g);
        it * BLOCK + slot * INODE_SIZE
    }
}

/// Converge the (circular) geometry: the group count depends on the metadata
/// size, which depends on the group count. `data_blocks` is the rootfs data,
/// `want_inodes` the inode budget (spread over the groups), `extra_free` spare
/// blocks left free. Returns (layout, total_blocks, inodes_count).
fn plan_layout(data_blocks: u64, want_inodes: u64, extra_free: u64) -> (Layout, u64, u64) {
    let mut groups = 1u64;
    loop {
        let ipg = round_up(
            (want_inodes.div_ceil(groups)).max(INODES_PER_BLOCK),
            INODES_PER_BLOCK,
        )
        .min(BLOCKS_PER_GROUP);
        let itb = ipg / INODES_PER_BLOCK;
        let gdt_blocks = round_up(groups * 32, BLOCK) / BLOCK;
        let layout = Layout {
            groups,
            ipg,
            itb,
            gdt_blocks,
        };
        let meta: u64 = (0..groups).map(|g| layout.group_meta_blocks(g)).sum();
        let slack = (data_blocks / 16).max(512);
        let total = meta + data_blocks + slack + extra_free;
        let new_groups = total.div_ceil(BLOCKS_PER_GROUP).max(1);
        if new_groups == groups {
            return (layout, groups * BLOCKS_PER_GROUP, ipg * groups);
        }
        groups = new_groups;
    }
}

/// Hands out data block runs group by group, skipping each group's metadata.
struct Allocator<'a> {
    layout: &'a Layout,
    total_blocks: u64,
    group: u64,
    cursor: u64, // next free block within the current group's data region
}

impl<'a> Allocator<'a> {
    fn new(layout: &'a Layout, total_blocks: u64) -> Self {
        Allocator {
            layout,
            total_blocks,
            group: 0,
            cursor: layout.group_data_start(0),
        }
    }

    /// The last block of the current group's usable data region (exclusive).
    fn group_end(&self) -> u64 {
        ((self.group + 1) * BLOCKS_PER_GROUP).min(self.total_blocks)
    }

    fn take(&mut self, mut need: u64) -> Result<Vec<Range<u64>>> {
        let mut runs = Vec::new();
        while need > 0 {
            if self.cursor >= self.group_end() {
                self.group += 1;
                if self.group >= self.layout.groups {
                    bail!("ext4 image out of space (need {need} more blocks)");
                }
                self.cursor = self.layout.group_data_start(self.group);
                continue;
            }
            let avail = self.group_end() - self.cursor;
            let n = need.min(avail);
            runs.push(self.cursor..self.cursor + n);
            self.cursor += n;
            need -= n;
        }
        Ok(runs)
    }
}

struct ImageWriter {
    file: std::fs::File,
}

struct BitVec {
    bytes: Vec<u8>,
    bits: u64,
}

impl BitVec {
    fn new(bits: u64) -> Self {
        BitVec {
            bytes: vec![0u8; bits.div_ceil(8) as usize],
            bits,
        }
    }
    fn set(&mut self, i: u64) {
        self.bytes[(i / 8) as usize] |= 1 << (i % 8);
    }
    fn get(&self, i: u64) -> bool {
        self.bytes[(i / 8) as usize] & (1 << (i % 8)) != 0
    }
}

fn group_block_count(g: u64, total_blocks: u64) -> u64 {
    let start = g * BLOCKS_PER_GROUP;
    (start + BLOCKS_PER_GROUP).min(total_blocks) - start
}

/// sparse_super: backups in group 0, 1, and powers of 3, 5, 7.
fn sparse_super(g: u64) -> bool {
    fn is_pow(mut n: u64, base: u64) -> bool {
        if n == 0 {
            return false;
        }
        while n.is_multiple_of(base) {
            n /= base;
        }
        n == 1
    }
    g == 0 || g == 1 || is_pow(g, 3) || is_pow(g, 5) || is_pow(g, 7)
}

fn inode_size(n: &Node) -> u64 {
    match &n.kind {
        Kind::Dir { .. } => n.data_blocks() * BLOCK,
        Kind::File { size, .. } => *size,
        Kind::Symlink { target } => target.len() as u64,
    }
}

/// Write the inode's extents: inline (≤4 runs) in i_block, or a depth-1 root with
/// one index pointing at the leaf block (which holds the runs).
fn write_inode_extents(ino: &mut [u8], n: &Node) {
    let h = 0x28; // i_block
    if let Some(leaf) = n.leaf {
        le16(ino, h, EXT_MAGIC);
        le16(ino, h + 2, 1); // one index entry
        le16(ino, h + 4, 4); // eh_max
        le16(ino, h + 6, 1); // eh_depth = 1
        le32(ino, h + 8, 0); // eh_generation
        let e = h + 12; // ext4_extent_idx
        le32(ino, e, 0); // ei_block
        le32(ino, e + 4, leaf as u32); // ei_leaf_lo
        le16(ino, e + 8, 0); // ei_leaf_hi
    } else {
        write_extent_entries(ino, h, &n.runs);
    }
}

/// Write an extent header at `off` (depth 0) followed by one entry per run.
fn write_extent_entries(buf: &mut [u8], off: usize, runs: &[Range<u64>]) {
    le16(buf, off, EXT_MAGIC);
    le16(buf, off + 2, runs.len() as u16); // eh_entries
    let max = if off == 0x28 {
        INLINE_EXTENTS
    } else {
        LEAF_EXTENTS
    };
    le16(buf, off + 4, max as u16); // eh_max
    le16(buf, off + 6, 0); // eh_depth = 0 (leaf)
    le32(buf, off + 8, 0); // eh_generation
    let mut logical = 0u32;
    for (i, r) in runs.iter().enumerate() {
        let e = off + 12 + i * 12;
        let len = (r.end - r.start) as u32;
        le32(buf, e, logical); // ee_block
        le16(buf, e + 4, len as u16); // ee_len (≤32768, fits)
        le16(buf, e + 6, 0); // ee_start_hi
        le32(buf, e + 8, r.start as u32); // ee_start_lo
        logical += len;
    }
}

/// Copy `src` into the image across the inode's physical runs, in order.
fn write_runs(w: &mut ImageWriter, runs: &[Range<u64>], src: &mut impl Read) -> Result<()> {
    for r in runs {
        w.file.seek(SeekFrom::Start(r.start * BLOCK))?;
        let len = (r.end - r.start) * BLOCK;
        let copied = std::io::copy(&mut src.take(len), &mut w.file)?;
        let _ = copied; // a short final block is fine (rest stays zero from set_len)
    }
    Ok(())
}

fn dir_blocks(entries: &[(String, u32, u8)]) -> u64 {
    let mut used = 12 + 12; // . and ..
    let mut blocks = 1u64;
    for (name, _, _) in entries {
        let rl = dirent_len(name.len());
        if used + rl > BLOCK as usize {
            blocks += 1;
            used = 0;
        }
        used += rl;
    }
    blocks
}

fn dirent_len(name_len: usize) -> usize {
    round_up((8 + name_len) as u64, 4) as usize
}

/// Render the directory data; entries are packed greedily, never spanning a block;
/// the last entry in each block has its rec_len stretched to the block end.
fn dir_data(ino: u32, parent: u32, entries: &[(String, u32, u8)]) -> Vec<u8> {
    let mut all: Vec<(u32, u8, &str)> = vec![(ino, FT_DIR, "."), (parent, FT_DIR, "..")];
    for (name, cino, ft) in entries {
        all.push((*cino, *ft, name));
    }
    let nblk = dir_blocks(entries) as usize;
    let mut buf = vec![0u8; nblk * BLOCK as usize];
    let mut blk = 0usize;
    let mut pos = 0usize;
    let mut last_off = 0usize;
    for (e_ino, ft, name) in &all {
        let rl = dirent_len(name.len());
        if pos + rl > BLOCK as usize {
            let block_end = (blk + 1) * BLOCK as usize;
            le16(&mut buf, last_off + 4, (block_end - last_off) as u16);
            blk += 1;
            pos = 0;
        }
        let off = blk * BLOCK as usize + pos;
        le32(&mut buf, off, *e_ino);
        le16(&mut buf, off + 4, rl as u16);
        buf[off + 6] = name.len() as u8;
        buf[off + 7] = *ft;
        buf[off + 8..off + 8 + name.len()].copy_from_slice(name.as_bytes());
        last_off = off;
        pos += rl;
    }
    let block_end = (blk + 1) * BLOCK as usize;
    le16(&mut buf, last_off + 4, (block_end - last_off) as u16);
    buf
}

fn round_up(v: u64, to: u64) -> u64 {
    v.div_ceil(to) * to
}

/// A random RFC-4122 v4 UUID from /dev/urandom (zeros if it can't be read — the
/// UUID is only an identity hint, not security-critical).
fn random_uuid() -> [u8; 16] {
    let mut u = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut u);
    }
    u[6] = (u[6] & 0x0f) | 0x40; // version 4
    u[8] = (u[8] & 0x3f) | 0x80; // variant 1
    u
}

// ---- extended attributes (in-inode) -----------------------------------------

/// ext4 in-inode xattr area: just after the 128-byte base inode + i_extra_isize
/// (32), running to the end of the 256-byte inode — 96 bytes for small xattrs.
const XATTR_MAGIC: u32 = 0xEA02_0000;
const XATTR_AREA_OFF: usize = 128 + 32;
/// ext4 name-index prefixes: a known prefix is replaced by its index to save room
/// (longest match wins, e.g. "security." -> 6, remainder "capability").
const XATTR_PREFIXES: &[(u8, &str)] = &[
    (1, "user."),
    (4, "trusted."),
    (6, "security."),
    (7, "system."),
];

/// Collect the xattrs a tar entry carries as PAX `SCHILY.xattr.<name>` records
/// (docker export emits these) — e.g. /usr/bin/ping's security.capability, which
/// would otherwise be dropped on the way into the ext4 inode.
fn tar_xattrs<R: Read>(e: &mut tar::Entry<'_, R>) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if let Ok(Some(exts)) = e.pax_extensions() {
        for ext in exts.flatten() {
            if let Ok(key) = ext.key()
                && let Some(name) = key.strip_prefix("SCHILY.xattr.")
            {
                out.push((name.to_string(), ext.value_bytes().to_vec()));
            }
        }
    }
    out
}

/// Map an xattr name to its (ext4 name index, stored suffix).
fn xattr_name_index(name: &str) -> (u8, &str) {
    XATTR_PREFIXES
        .iter()
        .filter(|(_, p)| name.starts_with(p))
        .max_by_key(|(_, p)| p.len())
        .map_or((0, name), |&(idx, p)| (idx, &name[p.len()..]))
}

/// Write `xattrs` into the inode's in-inode xattr area: a 4-byte magic, then entries
/// growing up, then a zero terminator; values packed at the inode's tail growing
/// down (e_value_offs is relative to the first entry). e_hash is 0, as the kernel
/// leaves it for in-inode entries. Returns false without writing if they don't fit
/// (we don't spill to an external xattr block — fine for the small caps we carry).
fn write_inode_xattrs(ino: &mut [u8], xattrs: &[(String, Vec<u8>)]) -> bool {
    let area_end = INODE_SIZE as usize;
    let ifirst = XATTR_AREA_OFF + 4; // entries start after h_magic
    let entries_len: usize = xattrs
        .iter()
        .map(|(n, _)| (16 + xattr_name_index(n).1.len()).next_multiple_of(4))
        .sum();
    let values_len: usize = xattrs
        .iter()
        .map(|(_, v)| v.len().next_multiple_of(4))
        .sum();
    if 4 + entries_len + 4 + values_len > area_end - XATTR_AREA_OFF {
        return false;
    }
    le32(ino, XATTR_AREA_OFF, XATTR_MAGIC);
    let mut epos = ifirst;
    let mut vtop = area_end;
    for (name, value) in xattrs {
        let (index, suffix) = xattr_name_index(name);
        vtop -= value.len().next_multiple_of(4);
        ino[vtop..vtop + value.len()].copy_from_slice(value);
        ino[epos] = suffix.len() as u8; // e_name_len
        ino[epos + 1] = index; // e_name_index
        le16(ino, epos + 2, (vtop - ifirst) as u16); // e_value_offs (from IFIRST)
        le32(ino, epos + 4, 0); // e_value_inum (0 = value is in-inode)
        le32(ino, epos + 8, value.len() as u32); // e_value_size
        le32(ino, epos + 12, 0); // e_hash (0 in-inode)
        ino[epos + 16..epos + 16 + suffix.len()].copy_from_slice(suffix.as_bytes());
        epos += (16 + suffix.len()).next_multiple_of(4);
    }
    // the 4-byte zero terminator is already present (buffer is zeroed)
    true
}

fn le16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn le32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd16(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
    }
    fn rd32(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }

    #[test]
    fn rounding_and_dirent_len() {
        assert_eq!(round_up(0, 16), 0);
        assert_eq!(round_up(5, 16), 16);
        assert_eq!(round_up(16, 16), 16);
        assert_eq!(dirent_len(1), 12);
        assert_eq!(dirent_len(8), 16);
    }

    #[test]
    fn inline_one_extent() {
        let n = Node {
            ino: 12,
            parent: 0,
            mode: S_IFREG | 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            links: 1,
            kind: Kind::File {
                src: Src::Host(PathBuf::new()),
                size: 3 * BLOCK,
            },
            runs: std::iter::once(68..71).collect(),
            leaf: None,
        };
        let mut ino = [0u8; INODE_SIZE as usize];
        write_inode_extents(&mut ino, &n);
        assert_eq!(rd16(&ino, 0x28), EXT_MAGIC);
        assert_eq!(rd16(&ino, 0x2a), 1);
        assert_eq!(rd16(&ino, 0x2e), 0); // depth 0
        assert_eq!(rd16(&ino, 0x38), 3); // ee_len
        assert_eq!(rd32(&ino, 0x3c), 68); // ee_start_lo
    }

    #[test]
    fn inode_xattr_security_capability() {
        // /usr/bin/ping cap_net_raw=ep: vfs_cap_data v2 (20 bytes).
        let cap = vec![
            0x01, 0x00, 0x00, 0x02, // magic_etc: VFS_CAP_REVISION_2 | EFFECTIVE
            0x00, 0x20, 0x00, 0x00, // permitted[0] = 1<<13 (CAP_NET_RAW)
            0x00, 0x00, 0x00, 0x00, // inheritable[0]
            0x00, 0x00, 0x00, 0x00, // permitted[1]
            0x00, 0x00, 0x00, 0x00, // inheritable[1]
        ];
        let mut ino = [0u8; INODE_SIZE as usize];
        assert!(write_inode_xattrs(
            &mut ino,
            &[("security.capability".into(), cap.clone())]
        ));

        assert_eq!(rd32(&ino, XATTR_AREA_OFF), XATTR_MAGIC);
        let e = XATTR_AREA_OFF + 4; // first entry
        assert_eq!(ino[e], 10); // e_name_len = len("capability")
        assert_eq!(ino[e + 1], 6); // e_name_index = security.
        assert_eq!(rd32(&ino, e + 8), cap.len() as u32); // e_value_size
        assert_eq!(&ino[e + 16..e + 26], b"capability");
        // value sits at IFIRST + e_value_offs and matches the cap bytes
        let voff = rd16(&ino, e + 2) as usize;
        let vpos = (XATTR_AREA_OFF + 4) + voff;
        assert_eq!(&ino[vpos..vpos + cap.len()], &cap[..]);

        // name-index split + the doesn't-fit guard
        assert_eq!(xattr_name_index("security.capability"), (6, "capability"));
        assert_eq!(xattr_name_index("user.foo"), (1, "foo"));
        assert_eq!(xattr_name_index("oddball"), (0, "oddball"));
        assert!(!write_inode_xattrs(
            &mut [0u8; INODE_SIZE as usize],
            &[("user.big".into(), vec![0u8; 200])]
        ));
    }

    #[test]
    fn sparse_super_groups() {
        assert!(sparse_super(0) && sparse_super(1) && sparse_super(3) && sparse_super(5));
        assert!(sparse_super(7) && sparse_super(9) && sparse_super(25) && sparse_super(27));
        assert!(!sparse_super(2) && !sparse_super(4) && !sparse_super(6) && !sparse_super(8));
    }

    // Heavy (writes ~400 MiB): builds a multi-block-group image and checks it is
    // e2fsck-clean. Run with `cargo test -- --ignored ext4::tests::multigroup`.
    #[test]
    #[ignore]
    fn multigroup_e2fsck() {
        let base = std::env::temp_dir().join(format!("ext4mg-{}", std::process::id()));
        let dir = base.join("root");
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("hello.txt"), b"hello-ext4-multigroup\n").unwrap();
        std::fs::write(dir.join("a/small"), vec![0x5au8; 100 * 1024]).unwrap();
        // ~400 MiB → spans >=4 groups and crosses the group 1 & 3 backup holes,
        // so this file needs multiple extents.
        std::fs::write(dir.join("big.bin"), vec![0u8; 400 * 1024 * 1024]).unwrap();
        let img = base.join("fs.img");
        build_from_dir(&dir, &img).expect("build_from_dir");

        let out = std::process::Command::new("e2fsck")
            .arg("-fn")
            .arg(&img)
            .output()
            .expect("run e2fsck");
        println!(
            "e2fsck rc={:?}\n{}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let cat = std::process::Command::new("debugfs")
            .args(["-R", "cat /hello.txt"])
            .arg(&img)
            .output()
            .expect("run debugfs");
        let content = String::from_utf8_lossy(&cat.stdout);
        let _ = std::fs::remove_dir_all(&base);
        assert!(out.status.success(), "e2fsck reported errors");
        assert!(
            content.contains("hello-ext4-multigroup"),
            "content readback: {content:?}"
        );
    }

    #[test]
    fn dir_layout() {
        let entries = vec![("file.txt".to_string(), 12u32, FT_REG)];
        let buf = dir_data(2, 2, &entries);
        assert_eq!(rd32(&buf, 0), 2);
        assert_eq!(buf[6], 1);
        assert_eq!(buf[7], FT_DIR);
        assert_eq!(rd32(&buf, 24), 12);
        assert_eq!(&buf[24 + 8..24 + 16], b"file.txt");
        assert_eq!(rd16(&buf, 24 + 4) as u64, BLOCK - 24);
    }
}
