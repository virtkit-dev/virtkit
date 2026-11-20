//! Identify ext4 and btrfs root devices and images by their superblock magic.

use std::io::{self, Read, Seek, SeekFrom};

/// ext4's `s_magic`, little-endian, at byte 1080 (superblock at 1024, field at 0x38). ext2 and
/// ext3 share it, and the ext4 driver mounts them.
const EXT4_MAGIC_AT: u64 = 1080;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xef];
/// btrfs's primary superblock is at 64 KiB; its `magic` field at 0x40 into it.
const BTRFS_MAGIC_AT: u64 = 0x10040;
const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";

/// Return `"ext4"` or `"btrfs"` for a matching signature, or `None` if neither matches.
/// Reformatting can leave the old superblock intact. If both signatures match, the
/// active filesystem is ambiguous and the probe returns an error.
pub fn fstype(dev: &mut (impl Read + Seek)) -> io::Result<Option<&'static str>> {
    let btrfs = magic_at(dev, BTRFS_MAGIC_AT, BTRFS_MAGIC)?;
    let ext4 = magic_at(dev, EXT4_MAGIC_AT, &EXT4_MAGIC)?;
    match (ext4, btrfs) {
        (true, true) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "both an ext4 and a btrfs superblock",
        )),
        (true, false) => Ok(Some("ext4")),
        (false, true) => Ok(Some("btrfs")),
        (false, false) => Ok(None),
    }
}

fn magic_at(dev: &mut (impl Read + Seek), at: u64, magic: &[u8]) -> io::Result<bool> {
    dev.seek(SeekFrom::Start(at))?;
    let mut buf = vec![0u8; magic.len()];
    match dev.read_exact(&mut buf) {
        Ok(()) => Ok(buf == magic),
        // Too small to hold this superblock: not this filesystem.
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// [`fstype`] of the file or block device at `path`.
pub fn fstype_of(path: &std::path::Path) -> io::Result<Option<&'static str>> {
    fstype(&mut std::fs::File::open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn image(at: usize, magic: &[u8]) -> Cursor<Vec<u8>> {
        let mut v = vec![0u8; 0x11000];
        v[at..at + magic.len()].copy_from_slice(magic);
        Cursor::new(v)
    }

    #[test]
    fn the_superblock_magic_names_the_filesystem() {
        assert_eq!(fstype(&mut image(1080, &EXT4_MAGIC)).unwrap(), Some("ext4"));
        assert_eq!(
            fstype(&mut image(0x10040, BTRFS_MAGIC)).unwrap(),
            Some("btrfs")
        );
        assert_eq!(fstype(&mut Cursor::new(vec![0u8; 0x11000])).unwrap(), None);
        // too small for either superblock
        assert_eq!(fstype(&mut Cursor::new(vec![0u8; 16])).unwrap(), None);
        // Reformatting btrfs as ext4 can leave the btrfs signature intact.
        let mut both = image(1080, &EXT4_MAGIC).into_inner();
        both[0x10040..0x10048].copy_from_slice(BTRFS_MAGIC);
        assert!(fstype(&mut Cursor::new(both)).is_err());
    }
}
