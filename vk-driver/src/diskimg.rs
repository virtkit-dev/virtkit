//! A disk image read by logical offset — a raw file or a qcow2's guest view — or a window
//! of one, such as a partition. The reader of what a guest wrote ([`crate::ext4_read`]) takes
//! its bytes through it, so a read past the window is refused here rather than becoming a
//! read of a neighbouring partition.

use std::cell::RefCell;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{Context, Result, bail};

pub struct DiskImage {
    inner: Inner,
    /// Where the window starts in the logical image.
    base: u64,
    len: u64,
}

/// `Qcow2::read_at` takes `&mut self` to cache L2 tables, while readers take `&self`.
enum Inner {
    Raw(std::fs::File),
    Qcow2(RefCell<crate::qcow2::Qcow2>),
}

impl DiskImage {
    /// Open the whole image, detecting qcow2 by its header. Read `.vk_ro_img` chunk
    /// manifests as raw bytes so filesystem validation rejects them.
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let (inner, len) = match crate::qcow2::sniff_kind(&file) {
            crate::qcow2::ImageKind::Qcow2 => {
                let q = crate::qcow2::Qcow2::open(path)?;
                let len = q.virtual_size();
                (Inner::Qcow2(RefCell::new(q)), len)
            }
            crate::qcow2::ImageKind::Raw | crate::qcow2::ImageKind::Lazy => {
                let len = file
                    .metadata()
                    .with_context(|| format!("stat {}", path.display()))?
                    .len();
                (Inner::Raw(file), len)
            }
        };
        Ok(DiskImage {
            inner,
            base: 0,
            len,
        })
    }

    /// Return a window of `len` bytes starting at `offset` in this window.
    #[allow(dead_code)] // used by tests until disk boot reads partitions
    pub fn slice(self, offset: u64, len: u64) -> Result<Self> {
        let end = offset.checked_add(len).context("window end overflows")?;
        if end > self.len {
            bail!(
                "window {offset}+{len} past the {} bytes it is cut from",
                self.len
            );
        }
        // base + self.len never passes the whole image, and end is within self.len.
        Ok(DiskImage {
            inner: self.inner,
            base: self.base + offset,
            len,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    /// Fill `buf` from `off` in this window; a read reaching past it is an error.
    pub fn read_exact_at(&self, buf: &mut [u8], off: u64) -> Result<()> {
        let end = off
            .checked_add(buf.len() as u64)
            .context("read end overflows")?;
        if end > self.len {
            bail!(
                "read of {} bytes at {off} past the {}-byte window",
                buf.len(),
                self.len
            );
        }
        // The window fits the image, so adding its base cannot overflow.
        let at = self.base + off;
        match &self.inner {
            Inner::Raw(f) => Ok(f.read_exact_at(buf, at)?),
            Inner::Qcow2(q) => q.borrow_mut().read_at(at, buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_reads_only_its_own_bytes() {
        let path = std::env::temp_dir().join(format!("vk-diskimg-{}", std::process::id()));
        std::fs::write(&path, (0..100u8).collect::<Vec<_>>()).unwrap();
        let open = || DiskImage::open(&path).unwrap();
        let img = open().slice(10, 20).unwrap();
        assert_eq!(img.len(), 20);
        let mut b = [0u8; 5];
        img.read_exact_at(&mut b, 15).unwrap();
        assert_eq!(b, [25, 26, 27, 28, 29]);
        assert!(img.read_exact_at(&mut b, 16).is_err());
        assert!(img.read_exact_at(&mut b, u64::MAX - 1).is_err());
        assert!(img.slice(15, 6).is_err());
        // A window of a window starts from its parent's base.
        let inner = open().slice(10, 20).unwrap().slice(5, 10).unwrap();
        inner.read_exact_at(&mut b, 0).unwrap();
        assert_eq!(b, [15, 16, 17, 18, 19]);
        assert!(open().slice(u64::MAX, 2).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}
