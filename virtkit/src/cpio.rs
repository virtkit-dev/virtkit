//! Minimal cpio "newc" writer — enough to assemble a bootable initramfs from a
//! container rootfs plus a few injected files, with no external tools (no mkfs,
//! no `cpio`, no gzip). The Linux kernel mounts an uncompressed newc archive as
//! the initramfs rootfs directly, so a generic OCI image can boot entirely in
//! RAM: kernel + this cpio, no disk.
//!
//! Format (per entry): a 110-byte ASCII header (`070701` magic + 13 zero-padded
//! 8-hex fields), the NUL-terminated name, NUL padding to a 4-byte boundary, the
//! file data, then NUL padding to a 4-byte boundary. The archive ends with a
//! `TRAILER!!!` entry. Names are relative (no leading `/`).

use std::io::{self, Read, Write};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

pub struct CpioWriter<W: Write> {
    w: W,
    ino: u32,
}

impl<W: Write> CpioWriter<W> {
    pub fn new(w: W) -> Self {
        CpioWriter { w, ino: 0 }
    }

    /// Header + name + padding; the caller streams `datasize` body bytes next.
    fn header(&mut self, name: &str, mode: u32, nlink: u32, datasize: u32) -> io::Result<()> {
        self.ino = self.ino.wrapping_add(1);
        let name = name.as_bytes();
        let namesize = name.len() as u32 + 1; // includes the trailing NUL
        self.w.write_all(b"070701")?;
        for field in [
            self.ino, mode, 0, 0, nlink, 0, datasize, 0, 0, 0, 0, namesize, 0,
        ] {
            write!(self.w, "{field:08x}")?;
        }
        self.w.write_all(name)?;
        self.w.write_all(&[0])?;
        self.pad(HEADER_LEN + namesize as usize)
    }

    fn pad(&mut self, written: usize) -> io::Result<()> {
        let rem = (4 - (written % 4)) % 4;
        if rem > 0 {
            self.w.write_all(&[0u8; 3][..rem])?;
        }
        Ok(())
    }

    pub fn dir(&mut self, name: &str, mode: u32) -> io::Result<()> {
        self.header(name, S_IFDIR | (mode & 0o7777), 2, 0)
    }

    pub fn symlink(&mut self, name: &str, target: &str) -> io::Result<()> {
        let target = target.as_bytes();
        self.header(name, S_IFLNK | 0o777, 1, target.len() as u32)?;
        self.w.write_all(target)?;
        self.pad(target.len())
    }

    /// Stream a regular file: exactly `size` bytes are read from `data`.
    pub fn file(
        &mut self,
        name: &str,
        mode: u32,
        size: u32,
        mut data: impl Read,
    ) -> io::Result<()> {
        self.header(name, S_IFREG | (mode & 0o7777), 1, size)?;
        let copied = io::copy(&mut data, &mut self.w)?;
        if copied != u64::from(size) {
            return Err(io::Error::other(format!(
                "cpio: {name}: wrote {copied} of {size} bytes"
            )));
        }
        self.pad(size as usize)
    }

    #[cfg(test)]
    pub fn file_bytes(&mut self, name: &str, mode: u32, data: &[u8]) -> io::Result<()> {
        self.file(name, mode, data.len() as u32, data)
    }

    /// Emit each parent directory of `path` (e.g. `usr/local/bin` → `usr`,
    /// `usr/local`, `usr/local/bin`). Duplicates across calls are harmless: the
    /// kernel ignores EEXIST on directory creation.
    pub fn dirs_for(&mut self, path: &str, mode: u32) -> io::Result<()> {
        let mut acc = String::new();
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for comp in &comps[..comps.len().saturating_sub(1)] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(comp);
            self.dir(&acc, mode)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.header("TRAILER!!!", 0, 1, 0)?;
        self.w.flush()?;
        Ok(self.w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_is_well_formed() {
        let mut buf = Vec::new();
        let mut c = CpioWriter::new(&mut buf);
        c.dir("usr", 0o755).unwrap();
        c.file_bytes("usr/x", 0o644, b"hello").unwrap();
        c.symlink("link", "usr/x").unwrap();
        c.finish().unwrap();

        // every entry header starts on a 4-byte boundary with the newc magic
        assert_eq!(&buf[0..6], b"070701");
        assert_eq!(buf.len() % 4, 0);
        // the names and the file body appear verbatim
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("usr/x"));
        assert!(s.contains("hello"));
        assert!(s.contains("TRAILER!!!"));
        // a 5-byte file → header(110) + name "usr/x\0"(6) =116 (4-aligned) + 5 data
        // + 3 pad; the magic after it must land aligned
        let second = buf
            .windows(6)
            .enumerate()
            .filter(|(_, w)| *w == b"070701")
            .nth(1)
            .unwrap()
            .0;
        assert_eq!(second % 4, 0);
    }

    #[test]
    fn dirs_for_builds_the_chain() {
        let mut buf = Vec::new();
        let mut c = CpioWriter::new(&mut buf);
        c.dirs_for("usr/local/bin/virtkit-agent", 0o755).unwrap();
        c.finish().unwrap();
        let s = String::from_utf8_lossy(&buf);
        for d in ["usr", "usr/local", "usr/local/bin"] {
            assert!(s.contains(d), "missing dir {d}");
        }
        assert!(
            !s.contains("virtkit-agent"),
            "must not emit the leaf as a dir"
        );
    }
}
