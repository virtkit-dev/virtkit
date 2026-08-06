//! Minimal ISO 9660 writer — builds a bootable hybrid BIOS+UEFI El Torito image
//! from a staged directory tree with no external tools (no xorriso/mkisofs).
//! The optical sibling of ext4.rs: `vk export iso` packages an auto-install
//! tree (kernel, initrd, bootloader images, compressed disk payload, installer
//! script) the caller stages; this module only provides the container and the
//! boot plumbing.
//!
//! Feature set, all of which the Linux `isofs` driver mounts and firmware
//! accepts:
//! - ISO 9660 primary volume + L/M path tables, with **Rock Ridge** (SUSP
//!   SP/ER, RRIP PX/NM) so the tree keeps real POSIX names when the installer
//!   initramfs mounts it;
//! - **El Torito** boot catalog with an optional BIOS (80x86, no-emulation)
//!   entry and an optional UEFI (0xEF) entry pointing at an embedded FAT ESP
//!   image — either alone, or both for a hybrid CD;
//! - the BIOS **boot info table** patched into the boot image (bytes 8..64),
//!   which isolinux and grub's `cdboot.img` both require;
//! - an optional **hybrid MBR** in the system area so the same file dd's to a
//!   USB stick: caller-supplied x86 boot code (e.g. syslinux's `isohdpfx.bin`),
//!   a partition covering the ISO, and — with an EFI image — a type-0xEF
//!   partition mapping the embedded ESP so USB UEFI firmware finds it.
//!
//! Not supported (rejected, never silently mis-written): files ≥ 4 GiB (ISO
//! multi-extent), symlinks to directories (a cycle risk; the tree is staged,
//! stage the directory itself), Joliet (Rock Ridge covers the Linux consumer).
//! A symlink to a FILE is followed: the staged link stores the file itself.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const SECTOR: usize = 2048;

/// The boot images `write_iso` wires into the El Torito catalog, each named by
/// its path *inside the tree* (they are ordinary members too, so the running
/// installer can read them back).
#[derive(Default)]
pub struct BootSpec {
    /// BIOS (80x86) no-emulation boot image, e.g. isolinux.bin or grub's
    /// eltorito.img. Gets the boot info table patched in.
    pub bios: Option<PathBuf>,
    /// UEFI boot image: a FAT filesystem carrying EFI/BOOT/BOOTX64.EFI.
    pub efi: Option<PathBuf>,
    /// x86 boot code for the hybrid MBR (first 432 bytes are used), e.g.
    /// syslinux's isohdpfx.bin — a HOST path, it is not a tree member.
    pub hybrid_mbr: Option<PathBuf>,
}

/// What an ISO build produced, for the caller's report.
#[derive(Debug)]
pub struct IsoInfo {
    /// image size in bytes
    pub size: u64,
    /// members written (files + directories, the root excluded)
    pub members: u64,
}

/// One member of the tree being packaged.
struct Entry {
    /// real name (Rock Ridge NM); the ISO id is derived and deduplicated
    name: String,
    iso_id: String,
    /// source file (None = directory)
    src: Option<PathBuf>,
    size: u64,
    /// assigned data extent (sector)
    lba: u32,
    /// directory children as indices into the arena, sorted by iso_id
    children: Vec<usize>,
    /// parent index (self for the root)
    parent: usize,
    dir_number: u32,
}

impl Entry {
    fn is_dir(&self) -> bool {
        self.src.is_none()
    }
}

/// Build the ISO at `out` from the staged directory `tree`. `volid` is the
/// volume identifier (A-Z, 0-9, `_`; at most 32 chars). Boot images in `boot`
/// name members of the tree.
pub fn write_iso(tree: &Path, out: &Path, volid: &str, boot: &BootSpec) -> Result<IsoInfo> {
    if volid.is_empty()
        || volid.len() > 32
        || !volid
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        bail!("volume id {volid:?} must be 1-32 chars of [A-Z0-9_]");
    }

    // ---- pass 1: collect the tree and lay everything out ----
    let mut arena: Vec<Entry> = vec![Entry {
        name: String::new(),
        iso_id: String::new(),
        src: None,
        size: 0,
        lba: 0,
        children: Vec::new(),
        parent: 0,
        dir_number: 1,
    }];
    collect(tree, 0, &mut arena).with_context(|| format!("scanning {}", tree.display()))?;

    // Directories in breadth-first order get path-table numbers; their extents
    // are laid out in the same order.
    let mut dirs_bfs = vec![0usize];
    let mut cursor = 0;
    while cursor < dirs_bfs.len() {
        let d = dirs_bfs[cursor];
        cursor += 1;
        for &c in &arena[d].children {
            if arena[c].is_dir() {
                dirs_bfs.push(c);
            }
        }
    }
    for (n, &d) in dirs_bfs.iter().enumerate() {
        arena[d].dir_number = (n + 1) as u32;
    }
    if dirs_bfs.len() > u16::MAX as usize {
        bail!("too many directories for a path table");
    }

    // Path table size (same for the L and M flavors).
    let path_table_len: usize = dirs_bfs
        .iter()
        .map(|&d| {
            let id_len = if d == 0 { 1 } else { arena[d].iso_id.len() };
            (8 + id_len).next_multiple_of(2)
        })
        .sum();
    let pt_sectors = path_table_len.div_ceil(SECTOR);

    // Sector layout: system area, PVD, boot record (when booting), terminator,
    // L+M path tables, directory extents, boot catalog, file extents.
    let has_boot = boot.bios.is_some() || boot.efi.is_some();
    let mut next = 16u32; // system area is sectors 0..16
    let pvd_lba = next;
    next += 1;
    if has_boot {
        next += 1; // El Torito boot record volume descriptor
    }
    next += 1; // terminator
    let pt_l_lba = next;
    next += pt_sectors as u32;
    let pt_m_lba = next;
    next += pt_sectors as u32;
    for &d in &dirs_bfs {
        arena[d].size = dir_extent_len(&arena, d)? as u64;
        arena[d].lba = next;
        next += (arena[d].size as usize).div_ceil(SECTOR) as u32;
    }
    let boot_catalog_lba = has_boot.then(|| {
        let l = next;
        next += 1;
        l
    });
    let files: Vec<usize> = (0..arena.len()).filter(|&i| !arena[i].is_dir()).collect();
    for &f in &files {
        arena[f].lba = next;
        next += (arena[f].size as usize).div_ceil(SECTOR) as u32;
    }
    let total_sectors = next;

    // Resolve the boot images to their member entries now the LBAs are known.
    let boot_member = |rel: &Option<PathBuf>, what: &str| -> Result<Option<usize>> {
        rel.as_ref()
            .map(|rel| {
                find_member(&arena, rel).with_context(|| {
                    format!("{what} boot image {} is not in the tree", rel.display())
                })
            })
            .transpose()
    };
    let bios_member = boot_member(&boot.bios, "BIOS")?;
    let efi_member = boot_member(&boot.efi, "UEFI")?;

    // ---- pass 2: write ----
    let file = File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut w = BufWriter::new(file);

    // System area: zeros, or the hybrid MBR making the file dd-able to USB.
    let mut system_area = [0u8; 16 * SECTOR];
    if let Some(mbr) = &boot.hybrid_mbr {
        let bios = bios_member.map(|m| arena[m].lba);
        let efi = efi_member.map(|m| (arena[m].lba, arena[m].size));
        hybrid_mbr(&mut system_area, mbr, total_sectors, bios, efi)?;
    }
    w.write_all(&system_area)?;

    // Primary volume descriptor.
    let root_record = dir_record(&arena, 0, Dot::Pvd)?;
    assert_eq!(root_record.len(), 34, "the PVD root record field is fixed");
    let mut pvd = [0u8; SECTOR];
    pvd[0] = 1; // type: primary
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1; // version
    put_padded(&mut pvd[8..40], b"LINUX"); // system id
    put_padded(&mut pvd[40..72], volid.as_bytes());
    both_u32(&mut pvd[80..88], total_sectors); // volume space size
    both_u16(&mut pvd[120..124], 1); // volume set size
    both_u16(&mut pvd[124..128], 1); // volume sequence number
    both_u16(&mut pvd[128..132], SECTOR as u16); // logical block size
    both_u32(&mut pvd[132..140], path_table_len as u32);
    pvd[140..144].copy_from_slice(&pt_l_lba.to_le_bytes());
    pvd[148..152].copy_from_slice(&pt_m_lba.to_be_bytes());
    pvd[156..156 + root_record.len()].copy_from_slice(&root_record);
    for range in [190..318, 318..446, 446..574, 574..702, 702..813] {
        put_padded(&mut pvd[range], b""); // volume set/publisher/…/file ids
    }
    // Creation/modification/expiration/effective dates: "not specified" is sixteen
    // ASCII '0' digits + a zero GMT-offset byte — which also keeps the image
    // reproducible, since no real timestamp is ever written.
    for at in [813, 830, 847, 864] {
        pvd[at..at + 16].fill(b'0');
    }
    pvd[881] = 1; // file structure version
    w.write_all(&pvd)?;

    // El Torito boot record volume descriptor.
    if let Some(catalog) = boot_catalog_lba {
        let mut br = [0u8; SECTOR];
        br[1..6].copy_from_slice(b"CD001");
        br[6] = 1;
        br[7..7 + 23].copy_from_slice(b"EL TORITO SPECIFICATION");
        br[0x47..0x4B].copy_from_slice(&catalog.to_le_bytes());
        w.write_all(&br)?;
    }

    // Volume descriptor set terminator.
    let mut term = [0u8; SECTOR];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;
    w.write_all(&term)?;

    // Path tables, L (little-endian) then M (big-endian).
    for big in [false, true] {
        let mut pt = Vec::with_capacity(path_table_len);
        for &d in &dirs_bfs {
            let id: &[u8] = if d == 0 {
                &[0]
            } else {
                arena[d].iso_id.as_bytes()
            };
            let parent = arena[arena[d].parent].dir_number as u16;
            pt.push(id.len() as u8);
            pt.push(0); // extended attr length
            let (lba, par) = (arena[d].lba, parent);
            if big {
                pt.extend_from_slice(&lba.to_be_bytes());
                pt.extend_from_slice(&par.to_be_bytes());
            } else {
                pt.extend_from_slice(&lba.to_le_bytes());
                pt.extend_from_slice(&par.to_le_bytes());
            }
            pt.extend_from_slice(id);
            if pt.len() % 2 == 1 {
                pt.push(0);
            }
        }
        pt.resize(pt_sectors * SECTOR, 0);
        w.write_all(&pt)?;
    }

    // Directory extents.
    for &d in &dirs_bfs {
        let dot = if d == 0 { Dot::Root } else { Dot::Current };
        let mut data = Vec::with_capacity(arena[d].size as usize);
        data.extend_from_slice(&dir_record(&arena, d, dot)?);
        data.extend_from_slice(&dir_record(&arena, arena[d].parent, Dot::Parent)?);
        for &c in &arena[d].children {
            let rec = dir_record(&arena, c, Dot::Named)?;
            // A record never spans a sector boundary: pad to the next sector.
            let room = SECTOR - data.len() % SECTOR;
            if rec.len() > room {
                data.resize(data.len() + room, 0);
            }
            data.extend_from_slice(&rec);
        }
        data.resize((arena[d].size as usize).next_multiple_of(SECTOR), 0);
        w.write_all(&data)?;
    }

    // El Torito boot catalog. With a BIOS image, it is the default entry and
    // the EFI image rides a 0xEF section (the hybrid-CD shape); EFI alone is
    // itself the default entry under a 0xEF validation header (the shape
    // mkisofs/xorriso emit for EFI-only media) — never a dummy entry, which
    // tools flag as a hidden boot image.
    if boot_catalog_lba.is_some() {
        let mut cat = [0u8; SECTOR];
        // Validation entry: header 1, the default entry's platform, key 55AA,
        // checksummed to zero.
        cat[0] = 1;
        cat[1] = if bios_member.is_some() { 0x00 } else { 0xEF };
        cat[0x1E] = 0x55;
        cat[0x1F] = 0xAA;
        let sum: u16 = cat[..32]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .fold(0u16, u16::wrapping_add);
        cat[0x1C..0x1E].copy_from_slice(&(0u16.wrapping_sub(sum)).to_le_bytes());
        // media type 0 = no emulation; load segment 0 = the 0x7C0 default.
        let entry = |cat: &mut [u8; SECTOR], off: usize, lba: u32, vsectors: u16| {
            cat[off] = 0x88; // bootable
            cat[off + 6..off + 8].copy_from_slice(&vsectors.to_le_bytes());
            cat[off + 8..off + 12].copy_from_slice(&lba.to_le_bytes());
        };
        // The whole FAT image is loaded; a huge ESP caps the 16-bit count like
        // xorriso. BIOS loaders take the customary 4 virtual sectors.
        let efi_vsectors = |m: usize| arena[m].size.div_ceil(512).min(0xFFFF) as u16;
        match (bios_member, efi_member) {
            (Some(b), efi) => {
                entry(&mut cat, 32, arena[b].lba, 4);
                if let Some(m) = efi {
                    cat[64] = 0x91; // final section header
                    cat[65] = 0xEF;
                    cat[66..68].copy_from_slice(&1u16.to_le_bytes());
                    entry(&mut cat, 96, arena[m].lba, efi_vsectors(m));
                }
            }
            (None, Some(m)) => entry(&mut cat, 32, arena[m].lba, efi_vsectors(m)),
            (None, None) => unreachable!("has_boot gates the catalog"),
        }
        w.write_all(&cat)?;
    }

    // File extents, streamed — the documented payload is a multi-GiB disk image, which
    // does not belong in RAM. Only the (small) BIOS boot image is buffered, since the
    // boot info table is patched into it in place.
    let mut members = 0u64;
    for &f in &files {
        let src = arena[f].src.as_ref().expect("files carry a source");
        let mut h = File::open(src).with_context(|| format!("opening {}", src.display()))?;
        let written: u64 = if Some(f) == bios_member {
            let mut data = Vec::new();
            h.read_to_end(&mut data)
                .with_context(|| format!("reading {}", src.display()))?;
            boot_info_table(&mut data, pvd_lba, arena[f].lba)?;
            w.write_all(&data)?;
            data.len() as u64
        } else {
            std::io::copy(&mut h, &mut w).with_context(|| format!("copying {}", src.display()))?
        };
        if written != arena[f].size {
            bail!("{} changed size while packing", src.display());
        }
        let pad = written.next_multiple_of(SECTOR as u64) - written;
        w.write_all(&vec![0u8; pad as usize])?;
        members += 1;
    }
    w.flush().context("flushing the ISO")?;

    Ok(IsoInfo {
        size: total_sectors as u64 * SECTOR as u64,
        members: members + dirs_bfs.len() as u64 - 1,
    })
}

/// Recursively collect `dir` into the arena under entry `parent`, assigning
/// deduplicated ISO ids and sorting children by them (the record order the
/// spec requires).
fn collect(dir: &Path, parent: usize, arena: &mut Vec<Entry>) -> Result<()> {
    let mut names = Vec::new();
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        names.push(e?.file_name());
    }
    names.sort();
    let mut used: BTreeMap<String, u32> = BTreeMap::new();
    let mut children = Vec::new();
    for name in names {
        let name = name
            .to_str()
            .with_context(|| format!("non-UTF-8 name {name:?} in {}", dir.display()))?
            .to_string();
        if name.len() > 128 {
            bail!("member name {name:?} is too long (max 128)");
        }
        let path = dir.join(&name);
        // The tree is a staging area: a staged link to the real file stores the file
        // itself. A link to a DIRECTORY is refused instead — following one could walk a
        // cycle, and recursing into content outside the staged tree is never intended.
        let meta = std::fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let is_dir = meta.is_dir();
        if is_dir
            && std::fs::symlink_metadata(&path)
                .with_context(|| format!("stat {}", path.display()))?
                .is_symlink()
        {
            bail!(
                "{} is a symlink to a directory — stage the directory itself",
                path.display()
            );
        }
        if !is_dir && !meta.is_file() {
            bail!("{} is neither a file nor a directory", path.display());
        }
        if !is_dir && meta.len() >= 4 << 30 {
            bail!(
                "{} is {} bytes; files of 4 GiB or more need ISO multi-extent, \
                 which is not supported — split or compress the payload",
                path.display(),
                meta.len()
            );
        }
        let idx = arena.len();
        arena.push(Entry {
            iso_id: iso_id(&name, is_dir, &mut used),
            name,
            src: (!is_dir).then(|| path.clone()),
            size: if is_dir { 0 } else { meta.len() },
            lba: 0,
            children: Vec::new(),
            parent,
            dir_number: 0,
        });
        children.push(idx);
        if is_dir {
            collect(&path, idx, arena)?;
        }
    }
    children.sort_by(|&a, &b| arena[a].iso_id.cmp(&arena[b].iso_id));
    arena[parent].children = children;
    Ok(())
}

/// The ISO 9660 identifier for a member: uppercase d-characters, deduplicated
/// with a numeric suffix; files carry the customary `;1` version. Rock Ridge
/// keeps the real name, so this only needs to be unique and well-formed.
fn iso_id(name: &str, is_dir: bool, used: &mut BTreeMap<String, u32>) -> String {
    let mut id: String = name
        .chars()
        .take(24)
        .map(|c| match c.to_ascii_uppercase() {
            u @ ('A'..='Z' | '0'..='9' | '_') => u,
            '.' if !is_dir => '.',
            _ => '_',
        })
        .collect();
    let n = *used.entry(id.clone()).and_modify(|n| *n += 1).or_insert(1);
    if n > 1 {
        // The suffixed id must itself be unused: a literal `FOO_2` may already
        // sit beside two members that both map to `FOO`.
        let mut k = n;
        while used.contains_key(&format!("{id}_{k}")) {
            k += 1;
        }
        id = format!("{id}_{k}");
        used.insert(id.clone(), 1);
    }
    if is_dir { id } else { format!("{id};1") }
}

/// Find the entry a tree-relative path names.
fn find_member(arena: &[Entry], rel: &Path) -> Result<usize> {
    let mut cur = 0usize;
    for comp in rel.components() {
        let std::path::Component::Normal(name) = comp else {
            bail!("boot image path {} must be tree-relative", rel.display());
        };
        let name = name.to_str().context("non-UTF-8 boot image path")?;
        cur = *arena[cur]
            .children
            .iter()
            .find(|&&c| arena[c].name == name)
            .with_context(|| format!("no member {name:?}"))?;
    }
    if arena[cur].is_dir() {
        bail!("{} is a directory", rel.display());
    }
    Ok(cur)
}

/// Which name a directory record carries.
#[derive(PartialEq, Clone, Copy)]
enum Dot {
    /// the bare 34-byte root record embedded in the PVD (no system-use area —
    /// the field is exactly 34 bytes)
    Pvd,
    /// the root extent's own "." — where Rock Ridge is announced (SP + ER)
    Root,
    /// "." (0x00)
    Current,
    /// ".." (0x01)
    Parent,
    /// the entry's own name
    Named,
}

/// One directory record with its Rock Ridge system-use area.
fn dir_record(arena: &[Entry], idx: usize, dot: Dot) -> Result<Vec<u8>> {
    let e = &arena[idx];
    let id: Vec<u8> = match dot {
        Dot::Pvd | Dot::Root | Dot::Current => vec![0],
        Dot::Parent => vec![1],
        Dot::Named => e.iso_id.as_bytes().to_vec(),
    };

    // Rock Ridge (SUSP + RRIP 1.10): PX everywhere; NM on named entries; the
    // root "." announces the protocol with SP and describes it with ER. The
    // PVD's embedded copy carries none of it.
    let mut susp = Vec::new();
    if dot == Dot::Root {
        susp.extend_from_slice(&[b'S', b'P', 7, 1, 0xBE, 0xEF, 0]);
    }
    if dot != Dot::Pvd {
        susp.extend_from_slice(&[b'P', b'X', 36, 1]);
        let mode: u32 = if e.is_dir() { 0o040755 } else { 0o100444 };
        both_u32_vec(&mut susp, mode);
        both_u32_vec(&mut susp, if e.is_dir() { 2 } else { 1 }); // nlink
        both_u32_vec(&mut susp, 0); // uid
        both_u32_vec(&mut susp, 0); // gid
    }
    if dot == Dot::Named {
        if 5 + e.name.len() > 254 {
            bail!("name {:?} overflows its Rock Ridge entry", e.name);
        }
        susp.extend_from_slice(&[b'N', b'M', (5 + e.name.len()) as u8, 1, 0]);
        susp.extend_from_slice(e.name.as_bytes());
    }
    if dot == Dot::Root {
        const ER: (&[u8], &[u8], &[u8]) = (
            b"RRIP_1991A",
            b"THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS",
            b"PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.",
        );
        susp.extend_from_slice(&[
            b'E',
            b'R',
            (8 + ER.0.len() + ER.1.len() + ER.2.len()) as u8,
            1,
            ER.0.len() as u8,
            ER.1.len() as u8,
            ER.2.len() as u8,
            1, // extension version
        ]);
        susp.extend_from_slice(ER.0);
        susp.extend_from_slice(ER.1);
        susp.extend_from_slice(ER.2);
    }

    let name_field = id.len() + id.len().is_multiple_of(2) as usize; // pad to odd total
    let len = 33 + name_field + susp.len();
    if len > 255 {
        bail!("directory record for {:?} overflows 255 bytes", e.name);
    }
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    both_u32(&mut r[2..10], e.lba);
    let data_len = if e.is_dir() {
        (e.size as usize).next_multiple_of(SECTOR) as u32
    } else {
        e.size as u32
    };
    both_u32(&mut r[10..18], data_len);
    // recording date: zeros are accepted everywhere and keep the image
    // reproducible (the GMT offset byte is the 7th)
    r[25] = if e.is_dir() { 0x02 } else { 0x00 }; // flags
    both_u16(&mut r[28..32], 1); // volume sequence number
    r[32] = id.len() as u8;
    r[33..33 + id.len()].copy_from_slice(&id);
    r[33 + name_field..].copy_from_slice(&susp);
    Ok(r)
}

/// Byte length of a directory's extent: the records in order, none spanning a
/// sector boundary.
fn dir_extent_len(arena: &[Entry], d: usize) -> Result<usize> {
    let dot = if d == 0 { Dot::Root } else { Dot::Current };
    let mut len =
        dir_record(arena, d, dot)?.len() + dir_record(arena, arena[d].parent, Dot::Parent)?.len();
    for &c in &arena[d].children {
        let rec = dir_record(arena, c, Dot::Named)?.len();
        let room = SECTOR - len % SECTOR;
        if rec > room {
            len += room;
        }
        len += rec;
    }
    Ok(len)
}

/// Patch the El Torito boot info table into a BIOS boot image (bytes 8..64):
/// the PVD sector, the image's own sector and byte length, and a checksum of
/// the rest of the file — what isolinux and grub's cdboot.img read to find
/// themselves on the disc.
fn boot_info_table(data: &mut [u8], pvd_lba: u32, file_lba: u32) -> Result<()> {
    if data.len() < 64 {
        bail!("BIOS boot image is too small for a boot info table");
    }
    let sum = data[64..]
        .chunks(4)
        .map(|c| {
            let mut w = [0u8; 4];
            w[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(w)
        })
        .fold(0u32, u32::wrapping_add);
    let len = data.len() as u32;
    data[8..12].copy_from_slice(&pvd_lba.to_le_bytes());
    data[12..16].copy_from_slice(&file_lba.to_le_bytes());
    data[16..20].copy_from_slice(&len.to_le_bytes());
    data[20..24].copy_from_slice(&sum.to_le_bytes());
    data[24..64].fill(0);
    Ok(())
}

/// Lay the hybrid MBR into the system area: caller boot code, a bootable
/// partition covering the ISO (type 0x17, how isohybrid marks it), and — when
/// an EFI image is embedded — a type-0xEF partition over its extent so USB
/// UEFI firmware finds the ESP without El Torito.
fn hybrid_mbr(
    system_area: &mut [u8],
    mbr_code: &Path,
    total_sectors: u32,
    bios: Option<u32>,
    efi: Option<(u32, u64)>,
) -> Result<()> {
    let code = std::fs::read(mbr_code)
        .with_context(|| format!("reading MBR boot code {}", mbr_code.display()))?;
    if code.len() < 32 {
        bail!("{}: too small for MBR boot code", mbr_code.display());
    }
    let n = code.len().min(432);
    system_area[..n].copy_from_slice(&code[..n]);
    // isohdpfx-style boot code reads the 512-byte-sector LBA of the El Torito BIOS
    // boot image from bytes 432..440 (the field isohybrid patches); without it the
    // MBR code loads sector 0 — itself — and legacy-BIOS USB boot hangs.
    if let Some(lba) = bios {
        system_area[432..440].copy_from_slice(&(u64::from(lba) * 4).to_le_bytes());
    }
    // partition 1: the whole ISO, in 512-byte sectors, bootable
    let part = &mut system_area[446..462];
    part[0] = 0x80;
    part[1..4].copy_from_slice(&[0xFF; 3]); // CHS: LBA-only markers
    part[4] = 0x17;
    part[5..8].copy_from_slice(&[0xFF; 3]);
    part[8..12].copy_from_slice(&0u32.to_le_bytes());
    part[12..16].copy_from_slice(&(total_sectors * 4).to_le_bytes());
    if let Some((lba, size)) = efi {
        let part = &mut system_area[462..478];
        part[1..4].copy_from_slice(&[0xFF; 3]);
        part[4] = 0xEF;
        part[5..8].copy_from_slice(&[0xFF; 3]);
        part[8..12].copy_from_slice(&(lba * 4).to_le_bytes());
        part[12..16].copy_from_slice(&(size.div_ceil(512) as u32).to_le_bytes());
    }
    system_area[510] = 0x55;
    system_area[511] = 0xAA;
    Ok(())
}

// ---- both-endian field helpers (ISO "733"/"723" formats) ----

fn both_u32(buf: &mut [u8], v: u32) {
    buf[..4].copy_from_slice(&v.to_le_bytes());
    buf[4..8].copy_from_slice(&v.to_be_bytes());
}

fn both_u32_vec(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
    buf.extend_from_slice(&v.to_be_bytes());
}

fn both_u16(buf: &mut [u8], v: u16) {
    buf[..2].copy_from_slice(&v.to_le_bytes());
    buf[2..4].copy_from_slice(&v.to_be_bytes());
}

/// Space-padded fixed-width text field.
fn put_padded(buf: &mut [u8], text: &[u8]) {
    buf.fill(b' ');
    let n = text.len().min(buf.len());
    buf[..n].copy_from_slice(&text[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let dir = std::env::temp_dir().join(format!("vk-iso-{tag}-{}", std::process::id()));
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

    /// Test-only reader: walk the PVD's directory tree by Rock Ridge names and
    /// return every file's (path, content) — what the installer initramfs will
    /// see when it mounts the disc.
    fn read_tree(iso: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let u32le = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let pvd = &iso[16 * SECTOR..17 * SECTOR];
        assert_eq!(&pvd[1..6], b"CD001");
        assert_eq!(pvd[0], 1);
        let root_lba = u32le(&pvd[156..], 2);
        let root_len = u32le(&pvd[156..], 10) as usize;
        let mut out = BTreeMap::new();
        walk(iso, root_lba, root_len, "", &mut out);
        return out;

        fn walk(
            iso: &[u8],
            lba: u32,
            len: usize,
            prefix: &str,
            out: &mut BTreeMap<String, Vec<u8>>,
        ) {
            let data = &iso[lba as usize * SECTOR..lba as usize * SECTOR + len];
            let mut off = 0;
            while off < data.len() {
                let rlen = data[off] as usize;
                if rlen == 0 {
                    // sector-boundary padding: skip to the next sector
                    off = (off / SECTOR + 1) * SECTOR;
                    continue;
                }
                let rec = &data[off..off + rlen];
                off += rlen;
                let id_len = rec[32] as usize;
                if id_len == 1 && (rec[33] == 0 || rec[33] == 1) {
                    continue; // "." / ".."
                }
                // Rock Ridge NM carries the real name.
                let mut susp = 33 + id_len + id_len.is_multiple_of(2) as usize;
                let mut name = String::new();
                while susp + 4 <= rec.len() {
                    let (sig, slen) = (&rec[susp..susp + 2], rec[susp + 2] as usize);
                    if sig == b"NM" {
                        name = String::from_utf8(rec[susp + 5..susp + slen].to_vec()).unwrap();
                    }
                    susp += slen.max(4);
                }
                assert!(!name.is_empty(), "every named record carries an NM");
                let child_lba = u32::from_le_bytes(rec[2..6].try_into().unwrap());
                let child_len = u32::from_le_bytes(rec[10..14].try_into().unwrap()) as usize;
                let path = format!("{prefix}{name}");
                if rec[25] & 0x02 != 0 {
                    walk(iso, child_lba, child_len, &format!("{path}/"), out);
                } else {
                    let at = child_lba as usize * SECTOR;
                    out.insert(path, iso[at..at + child_len].to_vec());
                }
            }
        }
    }

    fn stage(dir: &Path) {
        std::fs::create_dir_all(dir.join("boot/grub")).unwrap();
        std::fs::create_dir_all(dir.join("payload")).unwrap();
        std::fs::write(dir.join("boot/eltorito.img"), vec![0x90u8; 2048]).unwrap();
        std::fs::write(dir.join("boot/efi.img"), vec![0xF8u8; 4096]).unwrap();
        std::fs::write(dir.join("boot/grub/grub.cfg"), b"menuentry x {}\n").unwrap();
        std::fs::write(dir.join("payload/disk.img.zst"), vec![7u8; 10_000]).unwrap();
        std::fs::write(dir.join("install.sh"), b"#!/bin/sh\n").unwrap();
    }

    #[test]
    fn tree_roundtrips_with_rock_ridge_names() {
        let dir = TmpDir::new("rt");
        let tree = dir.0.join("tree");
        stage(&tree);
        let out = dir.0.join("out.iso");
        let info = write_iso(&tree, &out, "VK_TEST", &BootSpec::default()).unwrap();
        let iso = std::fs::read(&out).unwrap();
        assert_eq!(iso.len() as u64, info.size);
        assert_eq!(iso.len() % SECTOR, 0);
        assert_eq!(info.members, 8, "5 files + 3 directories");

        let got = read_tree(&iso);
        let names: Vec<&str> = got.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "boot/efi.img",
                "boot/eltorito.img",
                "boot/grub/grub.cfg",
                "install.sh",
                "payload/disk.img.zst"
            ]
        );
        assert_eq!(got["payload/disk.img.zst"], vec![7u8; 10_000]);
        assert_eq!(got["boot/grub/grub.cfg"], b"menuentry x {}\n");
    }

    #[test]
    fn el_torito_catalog_points_at_both_boot_images() {
        let dir = TmpDir::new("boot");
        let tree = dir.0.join("tree");
        stage(&tree);
        let out = dir.0.join("out.iso");
        let boot = BootSpec {
            bios: Some("boot/eltorito.img".into()),
            efi: Some("boot/efi.img".into()),
            hybrid_mbr: None,
        };
        write_iso(&tree, &out, "VK_TEST", &boot).unwrap();
        let iso = std::fs::read(&out).unwrap();

        // Boot record volume descriptor right after the PVD.
        let br = &iso[17 * SECTOR..18 * SECTOR];
        assert_eq!(br[0], 0);
        assert_eq!(&br[7..30], b"EL TORITO SPECIFICATION");
        let cat_lba = u32::from_le_bytes(br[0x47..0x4B].try_into().unwrap()) as usize;
        let cat = &iso[cat_lba * SECTOR..(cat_lba + 1) * SECTOR];

        // Validation entry checksums to zero and carries the 55AA key.
        assert_eq!((cat[0], cat[0x1E], cat[0x1F]), (1, 0x55, 0xAA));
        let sum: u16 = cat[..32]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .fold(0u16, u16::wrapping_add);
        assert_eq!(sum, 0);

        // Default entry: bootable, no-emulation, at the BIOS image's extent —
        // whose content got the boot info table patched in.
        assert_eq!(cat[32], 0x88);
        let bios_lba = u32::from_le_bytes(cat[40..44].try_into().unwrap());
        let img = &iso[bios_lba as usize * SECTOR..];
        assert_eq!(u32::from_le_bytes(img[8..12].try_into().unwrap()), 16);
        assert_eq!(
            u32::from_le_bytes(img[12..16].try_into().unwrap()),
            bios_lba
        );
        assert_eq!(u32::from_le_bytes(img[16..20].try_into().unwrap()), 2048);
        let claimed = u32::from_le_bytes(img[20..24].try_into().unwrap());
        let sum = img[64..2048]
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .fold(0u32, u32::wrapping_add);
        assert_eq!(claimed, sum, "boot info table checksum");

        // EFI section: final header for platform EF, then the ESP's extent.
        assert_eq!((cat[64], cat[65]), (0x91, 0xEF));
        assert_eq!(cat[96], 0x88);
        let efi_lba = u32::from_le_bytes(cat[104..108].try_into().unwrap());
        assert_eq!(
            u16::from_le_bytes(cat[102..104].try_into().unwrap()),
            8,
            "4096-byte ESP = 8 virtual sectors"
        );
        // The extent really is the FAT image (its filler byte).
        assert_eq!(iso[efi_lba as usize * SECTOR], 0xF8);

        // A boot image missing from the tree is an error naming it.
        let bad = BootSpec {
            bios: Some("boot/missing.img".into()),
            ..Default::default()
        };
        let err = write_iso(&tree, &dir.0.join("x.iso"), "VK_TEST", &bad).unwrap_err();
        assert!(format!("{err:#}").contains("not in the tree"), "{err:#}");
    }

    #[test]
    fn hybrid_mbr_maps_the_iso_and_the_esp() {
        let dir = TmpDir::new("mbr");
        let tree = dir.0.join("tree");
        stage(&tree);
        let mbr = dir.0.join("isohdpfx.bin");
        std::fs::write(&mbr, vec![0xFAu8; 432]).unwrap();
        let out = dir.0.join("out.iso");
        let boot = BootSpec {
            bios: Some("boot/eltorito.img".into()),
            efi: Some("boot/efi.img".into()),
            hybrid_mbr: Some(mbr),
        };
        write_iso(&tree, &out, "VK_TEST", &boot).unwrap();
        let iso = std::fs::read(&out).unwrap();

        assert_eq!(iso[0], 0xFA, "MBR boot code in place");
        assert_eq!((iso[510], iso[511]), (0x55, 0xAA));
        // isohdpfx-style code finds the El Torito BIOS image via bytes 432..440:
        // its 512-byte-sector LBA, i.e. the extent's 2048-byte LBA times four.
        let bios_512 = u64::from_le_bytes(iso[432..440].try_into().unwrap());
        assert!(bios_512 > 0, "boot image LBA patched into the MBR");
        assert_eq!(bios_512 % 4, 0);
        assert_eq!(
            &iso[bios_512 as usize * 512..bios_512 as usize * 512 + 8],
            &[0x90; 8],
            "the patched LBA points at the staged BIOS image (bytes 0..8 keep \
             the staged filler; the boot info table rewrites 8..64)"
        );
        // partition 1: bootable, covers the ISO in 512-byte sectors
        assert_eq!((iso[446], iso[450]), (0x80, 0x17));
        let p1_size = u32::from_le_bytes(iso[458..462].try_into().unwrap());
        assert_eq!(p1_size as usize * 512, iso.len());
        // partition 2: type EF over the embedded ESP
        assert_eq!(iso[466], 0xEF);
        let p2_start = u32::from_le_bytes(iso[470..474].try_into().unwrap());
        assert_eq!(iso[p2_start as usize * 512], 0xF8, "ESP extent");
        let p2_size = u32::from_le_bytes(iso[474..478].try_into().unwrap());
        assert_eq!(p2_size, 8);
    }

    #[test]
    fn oversized_files_and_bad_volids_are_refused() {
        let dir = TmpDir::new("limits");
        let tree = dir.0.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("f"), b"x").unwrap();
        for bad in ["", "lower", "SP ACE", &"V".repeat(33)] {
            let err =
                write_iso(&tree, &dir.0.join("x.iso"), bad, &BootSpec::default()).unwrap_err();
            assert!(format!("{err:#}").contains("volume id"), "{bad:?}");
        }
        // a ≥4 GiB member is rejected up front (sparse, so cheap to create)
        let big = std::fs::File::create(tree.join("big")).unwrap();
        big.set_len(4 << 30).unwrap();
        let err =
            write_iso(&tree, &dir.0.join("x.iso"), "VKISO", &BootSpec::default()).unwrap_err();
        assert!(format!("{err:#}").contains("multi-extent"), "{err:#}");
    }
}
