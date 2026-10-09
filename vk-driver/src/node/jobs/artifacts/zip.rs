//! The archive formats GitLab takes artifacts in, written from the tar the guest streams out,
//! and the zip it hands dependencies back in, read into a tar for the guest to unpack.
//!
//! The zip follows gitlab-runner v19.5's `helpers/archives/zip_create.go` and `zip_extra.go`
//! as Go's `archive/zip` writes it: entries in the guest's order, directories as `name/`,
//! symlinks stored with their target as data, regular files deflated, each with the Unix
//! mode, the uid/gid (`0x7875`) and modification time (`0x5455`) extra fields, names flagged
//! UTF-8, and zip64 records where sizes, offsets or the entry count need them. The gzip
//! format follows `gzip_create.go`: one gzip member per regular file, named after it.
//! gitlab-runner is MIT (see [`super::super::mask`] for the notice).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::write::DeflateEncoder;

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;

const ZIP64_EXTRA: u16 = 0x0001;
const UID_GID_EXTRA: u16 = 0x7875;
const TIMESTAMP_EXTRA: u16 = 0x5455;

const VERSION_20: u16 = 20;
const VERSION_45: u16 = 45;
/// Version made by: Unix, as Go's `FileHeader.SetMode` records it.
const CREATOR_UNIX: u16 = 3 << 8;
/// Names and comments are UTF-8.
const FLAG_UTF8: u16 = 0x800;
const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const MSDOS_DIR: u32 = 0x10;
const MSDOS_READ_ONLY: u32 = 0x01;

/// An entry of this many bytes or more is written zip64 from the start: deflate can grow
/// incompressible data a little, and a local header's size fields cannot be widened once
/// the data is behind them.
const ZIP64_THRESHOLD: u64 = 0xF000_0000;
const U32_MAX: u64 = 0xFFFF_FFFF;

/// The most bytes a symlink's target takes, read from either side.
const MAX_LINK: u64 = 4096;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Symlink,
}

/// What an entry is, apart from its data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Meta {
    /// Relative, `/`-separated, without a trailing `/`.
    pub name: Vec<u8>,
    pub kind: Kind,
    /// Permission bits.
    pub perm: u32,
    pub mtime: u64,
    pub uid: u32,
    pub gid: u32,
}

impl Meta {
    fn mode(&self) -> u32 {
        let kind = match self.kind {
            Kind::File => S_IFREG,
            Kind::Dir => S_IFDIR,
            Kind::Symlink => S_IFLNK,
        };
        kind | (self.perm & 0o7777)
    }
}

/// A central directory record, kept until the archive is finished.
struct Central {
    name: Vec<u8>,
    method: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    offset: u64,
    time: u16,
    date: u16,
    external: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
}

/// The largest central directory written or read: its records are held in memory whole.
pub(crate) const MAX_CENTRAL: u64 = 256 << 20;

/// A central directory record's fixed part, and the most extra fields this writer gives one.
const CENTRAL_FIXED: u64 = 46;
const CENTRAL_EXTRA_MAX: u64 = 28 + 24;

/// A zip written to a seekable file: each local header is patched once its data is written,
/// so no data descriptors are needed.
pub(crate) struct ZipWriter<W: Write + Seek> {
    w: W,
    entries: Vec<Central>,
    /// The central directory's size so far, against `max_central`.
    central: u64,
    max_central: u64,
    /// The entry size from which local headers are zip64.
    zip64_at: u64,
}

/// Counts what passes through to the inner writer.
struct Counting<W> {
    w: W,
    n: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.w.write(buf)?;
        self.n = self.n.saturating_add(n as u64);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn clamp32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// The uid/gid and timestamp extra fields gitlab-runner writes on every entry.
fn unix_extra(uid: u32, gid: u32, mtime: u32) -> Vec<u8> {
    let mut e = Vec::with_capacity(24);
    put16(&mut e, UID_GID_EXTRA);
    put16(&mut e, 11);
    e.push(1);
    e.push(4);
    put32(&mut e, uid);
    e.push(4);
    put32(&mut e, gid);
    put16(&mut e, TIMESTAMP_EXTRA);
    put16(&mut e, 5);
    e.push(1);
    put32(&mut e, mtime);
    e
}

/// Seconds since the epoch as an MS-DOS date and time, UTC, clamped to the years it can hold.
pub(crate) fn dos_time(secs: u64) -> (u16, u16) {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil(i64::try_from(days).unwrap_or(i64::MAX));
    if y < 1980 {
        return ((1 << 5) | 1, 0);
    }
    if y > 2107 {
        return (
            ((127 << 9) | (12 << 5) | 31) as u16,
            (23 << 11) | (59 << 5) | 29,
        );
    }
    let date = (((y - 1980) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let (h, mi, s) = (rem / 3600, (rem / 60) % 60, rem % 60);
    let time = ((h as u16) << 11) | ((mi as u16) << 5) | (s as u16 / 2);
    (date, time)
}

/// Days since 1970-01-01 as a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl<W: Write + Seek> ZipWriter<W> {
    pub(crate) fn new(w: W) -> Self {
        ZipWriter {
            w,
            entries: Vec::new(),
            central: 0,
            max_central: MAX_CENTRAL,
            zip64_at: ZIP64_THRESHOLD,
        }
    }

    /// Add an entry. `data` is a file's content or a symlink's target, `size` how many bytes
    /// it holds; a directory has none.
    pub(crate) fn add(&mut self, meta: &Meta, data: &mut dyn Read, size: u64) -> Result<()> {
        let mut name = meta.name.clone();
        let (method, size) = match meta.kind {
            Kind::Dir => {
                name.push(b'/');
                (METHOD_STORE, 0)
            }
            Kind::Symlink => (METHOD_STORE, size),
            Kind::File => (METHOD_DEFLATE, size),
        };
        let name_len = u16::try_from(name.len()).context("an entry name is too long for zip")?;
        self.central = self
            .central
            .saturating_add(CENTRAL_FIXED + u64::from(name_len) + CENTRAL_EXTRA_MAX);
        if self.central > self.max_central {
            bail!(
                "the archive's entries are too many for zip: their directory would be over {} \
                 bytes",
                self.max_central
            );
        }
        let zip64 = size >= self.zip64_at;
        let offset = self.w.stream_position()?;
        let mtime = clamp32(meta.mtime);
        let (date, time) = dos_time(meta.mtime);
        let unix = unix_extra(meta.uid, meta.gid, mtime);
        let mut extra = Vec::new();
        if zip64 {
            put16(&mut extra, ZIP64_EXTRA);
            put16(&mut extra, 16);
            put64(&mut extra, 0);
            put64(&mut extra, 0);
        }
        extra.extend_from_slice(&unix);
        let mut header = Vec::with_capacity(30 + name.len() + extra.len());
        put32(&mut header, LOCAL_SIG);
        put16(&mut header, if zip64 { VERSION_45 } else { VERSION_20 });
        put16(&mut header, FLAG_UTF8);
        put16(&mut header, method);
        put16(&mut header, time);
        put16(&mut header, date);
        put32(&mut header, 0); // crc, patched
        put32(&mut header, if zip64 { u32::MAX } else { 0 });
        put32(&mut header, if zip64 { u32::MAX } else { 0 });
        put16(&mut header, name_len);
        put16(&mut header, extra.len() as u16);
        header.extend_from_slice(&name);
        header.extend_from_slice(&extra);
        self.w.write_all(&header)?;

        let mut crc = flate2::Crc::new();
        let mut usize = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        let mut input = data.take(size);
        let csize = if method == METHOD_DEFLATE {
            let mut enc = DeflateEncoder::new(
                Counting {
                    w: &mut self.w,
                    n: 0,
                },
                Compression::default(),
            );
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                crc.update(&buf[..n]);
                usize += n as u64;
                enc.write_all(&buf[..n])?;
            }
            enc.finish()?.n
        } else {
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                crc.update(&buf[..n]);
                usize += n as u64;
                self.w.write_all(&buf[..n])?;
            }
            usize
        };
        if usize != size {
            bail!(
                "{}: expected {size} bytes, read {usize}",
                String::from_utf8_lossy(&meta.name)
            );
        }
        if !zip64 && csize > U32_MAX {
            bail!(
                "{}: compressed past 4 GiB without zip64",
                String::from_utf8_lossy(&meta.name)
            );
        }
        let end = self.w.stream_position()?;
        self.w.seek(SeekFrom::Start(offset + 14))?;
        let mut patch = Vec::with_capacity(12);
        put32(&mut patch, crc.sum());
        if !zip64 {
            put32(&mut patch, csize as u32);
            put32(&mut patch, usize as u32);
        }
        self.w.write_all(&patch)?;
        if zip64 {
            self.w
                .seek(SeekFrom::Start(offset + 30 + u64::from(name_len) + 4))?;
            let mut sizes = Vec::with_capacity(16);
            put64(&mut sizes, usize);
            put64(&mut sizes, csize);
            self.w.write_all(&sizes)?;
        }
        self.w.seek(SeekFrom::Start(end))?;
        let mut external = meta.mode() << 16;
        if meta.kind == Kind::Dir {
            external |= MSDOS_DIR;
        }
        self.entries.push(Central {
            name,
            method,
            crc: crc.sum(),
            csize,
            usize,
            offset,
            time,
            date,
            external,
            uid: meta.uid,
            gid: meta.gid,
            mtime,
        });
        Ok(())
    }

    /// Write the central directory and its end records. Returns the inner writer.
    pub(crate) fn finish(mut self) -> Result<W> {
        let start = self.w.stream_position()?;
        for e in &self.entries {
            let mut z64 = Vec::new();
            if e.usize >= U32_MAX {
                put64(&mut z64, e.usize);
            }
            if e.csize >= U32_MAX {
                put64(&mut z64, e.csize);
            }
            if e.offset >= U32_MAX {
                put64(&mut z64, e.offset);
            }
            let mut extra = Vec::new();
            if !z64.is_empty() {
                put16(&mut extra, ZIP64_EXTRA);
                put16(&mut extra, z64.len() as u16);
                extra.extend_from_slice(&z64);
            }
            extra.extend_from_slice(&unix_extra(e.uid, e.gid, e.mtime));
            let version = if z64.is_empty() {
                VERSION_20
            } else {
                VERSION_45
            };
            let mut h = Vec::with_capacity(46 + e.name.len() + extra.len());
            put32(&mut h, CENTRAL_SIG);
            put16(&mut h, CREATOR_UNIX | version);
            put16(&mut h, version);
            put16(&mut h, FLAG_UTF8);
            put16(&mut h, e.method);
            put16(&mut h, e.time);
            put16(&mut h, e.date);
            put32(&mut h, e.crc);
            put32(&mut h, clamp32(e.csize));
            put32(&mut h, clamp32(e.usize));
            put16(&mut h, e.name.len() as u16);
            put16(&mut h, extra.len() as u16);
            put16(&mut h, 0); // comment
            put16(&mut h, 0); // disk
            put16(&mut h, 0); // internal attributes
            put32(&mut h, e.external);
            put32(&mut h, clamp32(e.offset));
            h.extend_from_slice(&e.name);
            h.extend_from_slice(&extra);
            self.w.write_all(&h)?;
        }
        let end = self.w.stream_position()?;
        let size = end - start;
        let count = self.entries.len() as u64;
        let mut tail = Vec::new();
        if count >= 0xFFFF || size >= U32_MAX || start >= U32_MAX {
            put32(&mut tail, ZIP64_EOCD_SIG);
            put64(&mut tail, 44);
            put16(&mut tail, CREATOR_UNIX | VERSION_45);
            put16(&mut tail, VERSION_45);
            put32(&mut tail, 0);
            put32(&mut tail, 0);
            put64(&mut tail, count);
            put64(&mut tail, count);
            put64(&mut tail, size);
            put64(&mut tail, start);
            put32(&mut tail, ZIP64_LOCATOR_SIG);
            put32(&mut tail, 0);
            put64(&mut tail, end);
            put32(&mut tail, 1);
        }
        put32(&mut tail, EOCD_SIG);
        put16(&mut tail, 0);
        put16(&mut tail, 0);
        let short = u16::try_from(count).unwrap_or(u16::MAX);
        put16(&mut tail, short);
        put16(&mut tail, short);
        put32(&mut tail, clamp32(size));
        put32(&mut tail, clamp32(start));
        put16(&mut tail, 0);
        self.w.write_all(&tail)?;
        self.w.flush()?;
        Ok(self.w)
    }
}

/// An entry of a zip read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZipEntry {
    /// As the archive names it; directories keep their trailing `/`.
    pub name: Vec<u8>,
    pub method: u16,
    pub crc: u32,
    pub csize: u64,
    pub usize: u64,
    pub offset: u64,
    /// The Unix mode, where the archive was made on Unix.
    pub mode: Option<u32>,
    pub external: u32,
    pub mtime: u64,
    pub zip64: bool,
}

impl ZipEntry {
    pub(crate) fn kind(&self) -> Option<Kind> {
        if self.name.ends_with(b"/") || self.external & MSDOS_DIR != 0 {
            return Some(Kind::Dir);
        }
        match self.mode.map(|m| m & S_IFMT) {
            None | Some(0) | Some(S_IFREG) => Some(Kind::File),
            Some(S_IFDIR) => Some(Kind::Dir),
            Some(S_IFLNK) => Some(Kind::Symlink),
            // Pipes, sockets, devices: ignored, as gitlab-runner ignores them.
            Some(_) => None,
        }
    }

    /// The permission bits: the Unix mode's, else as Go's `msdosModeToFileMode` reads the
    /// MS-DOS attributes, less the `022` umask, the read-only bit taking write away.
    fn perm(&self, kind: Kind) -> u32 {
        let base = match (self.mode, kind) {
            (Some(m), _) if m & 0o7777 != 0 => return m & 0o7777,
            (_, Kind::Dir) => 0o755,
            _ => 0o644,
        };
        match self.mode.is_none() && self.external & MSDOS_READ_ONLY != 0 {
            true => base & !0o222,
            false => base,
        }
    }
}

fn le16(b: &[u8], at: usize) -> Result<u16> {
    let s = b.get(at..at + 2).context("truncated zip record")?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn le32(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).context("truncated zip record")?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le64(b: &[u8], at: usize) -> Result<u64> {
    let s = b.get(at..at + 8).context("truncated zip record")?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

/// The central directory of the zip in `r`.
pub(crate) fn read_central<R: Read + Seek>(r: &mut R) -> Result<Vec<ZipEntry>> {
    let len = r.seek(SeekFrom::End(0))?;
    let tail_len = len.min(22 + 0xFFFF + 20);
    r.seek(SeekFrom::Start(len - tail_len))?;
    let mut tail = vec![0u8; tail_len as usize];
    r.read_exact(&mut tail)?;
    let at = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| {
            le32(&tail, i).ok() == Some(EOCD_SIG)
                && le16(&tail, i + 20).is_ok_and(|c| i + 22 + usize::from(c) <= tail.len())
        })
        .context("not a zip archive: no end of central directory")?;
    let mut count = u64::from(le16(&tail, at + 10)?);
    let mut size = u64::from(le32(&tail, at + 12)?);
    let mut start = u64::from(le32(&tail, at + 16)?);
    if (count == 0xFFFF || size == U32_MAX || start == U32_MAX)
        && at >= 20
        && le32(&tail, at - 20)? == ZIP64_LOCATOR_SIG
    {
        let z64 = le64(&tail, at - 20 + 8)?;
        if z64 > len.saturating_sub(56) {
            bail!("zip64 end of central directory out of range");
        }
        r.seek(SeekFrom::Start(z64))?;
        let mut rec = [0u8; 56];
        r.read_exact(&mut rec)?;
        if le32(&rec, 0)? != ZIP64_EOCD_SIG {
            bail!("bad zip64 end of central directory");
        }
        count = le64(&rec, 32)?;
        size = le64(&rec, 40)?;
        start = le64(&rec, 48)?;
    }
    if size > MAX_CENTRAL {
        bail!("zip central directory of {size} bytes, over {MAX_CENTRAL}");
    }
    if start.checked_add(size).is_none_or(|e| e > len) {
        bail!("zip central directory out of range");
    }
    let mut cd = vec![0u8; usize::try_from(size).context("zip central directory too large")?];
    r.seek(SeekFrom::Start(start))?;
    r.read_exact(&mut cd)?;
    let mut entries = Vec::new();
    let mut p = 0usize;
    while p < cd.len() {
        if le32(&cd, p)? != CENTRAL_SIG {
            bail!("bad zip central directory record");
        }
        let made_by = le16(&cd, p + 4)?;
        let method = le16(&cd, p + 10)?;
        let time = le16(&cd, p + 12)?;
        let date = le16(&cd, p + 14)?;
        let crc = le32(&cd, p + 16)?;
        let mut csize = u64::from(le32(&cd, p + 20)?);
        let mut usize = u64::from(le32(&cd, p + 24)?);
        let n = usize::from(le16(&cd, p + 28)?);
        let e = usize::from(le16(&cd, p + 30)?);
        let c = usize::from(le16(&cd, p + 32)?);
        let external = le32(&cd, p + 38)?;
        let mut offset = u64::from(le32(&cd, p + 42)?);
        let name = cd
            .get(p + 46..p + 46 + n)
            .context("truncated zip name")?
            .to_vec();
        let extra = cd
            .get(p + 46 + n..p + 46 + n + e)
            .context("truncated zip extra")?;
        let mut mtime = dos_to_unix(date, time);
        let mut zip64 = false;
        let mut q = 0usize;
        while q + 4 <= extra.len() {
            let tag = le16(extra, q)?;
            let flen = usize::from(le16(extra, q + 2)?);
            let field = extra
                .get(q + 4..q + 4 + flen)
                .context("truncated zip extra")?;
            match tag {
                ZIP64_EXTRA => {
                    zip64 = true;
                    let mut f = 0usize;
                    for v in [&mut usize, &mut csize, &mut offset] {
                        if *v == U32_MAX {
                            *v = le64(field, f)?;
                            f += 8;
                        }
                    }
                }
                TIMESTAMP_EXTRA if field.first().is_some_and(|f| f & 1 == 1) => {
                    mtime = u64::from(le32(field, 1)?);
                }
                _ => {}
            }
            q += 4 + flen;
        }
        let mode = (made_by >> 8 == 3).then_some(external >> 16);
        entries.push(ZipEntry {
            name,
            method,
            crc,
            csize,
            usize,
            offset,
            mode,
            external,
            mtime,
            zip64,
        });
        p += 46 + n + e + c;
    }
    if entries.len() as u64 != count {
        bail!(
            "zip central directory holds {} entries, not {count}",
            entries.len()
        );
    }
    Ok(entries)
}

fn dos_to_unix(date: u16, time: u16) -> u64 {
    let y = 1980 + i64::from(date >> 9);
    let m = i64::from((date >> 5) & 0xF).clamp(1, 12);
    let d = i64::from(date & 0x1F).max(1);
    // Days from civil (Howard Hinnant's `days_from_civil`).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = i64::from(time >> 11) * 3600
        + i64::from((time >> 5) & 0x3F) * 60
        + i64::from(time & 0x1F) * 2;
    u64::try_from(days * 86_400 + secs).unwrap_or(0)
}

/// The data of `e`, decompressed, read at most `e.usize` bytes from its local header on.
pub(crate) fn open_entry<'a, R: Read + Seek>(
    r: &'a mut R,
    e: &ZipEntry,
) -> Result<Box<dyn Read + 'a>> {
    r.seek(SeekFrom::Start(e.offset))?;
    let mut h = [0u8; 30];
    r.read_exact(&mut h)?;
    if le32(&h, 0)? != LOCAL_SIG {
        bail!(
            "bad zip local header for {}",
            String::from_utf8_lossy(&e.name)
        );
    }
    let skip = i64::from(le16(&h, 26)?) + i64::from(le16(&h, 28)?);
    r.seek(SeekFrom::Current(skip))?;
    let raw = r.take(e.csize);
    let data: Box<dyn Read + 'a> = match e.method {
        METHOD_STORE => Box::new(raw),
        METHOD_DEFLATE => Box::new(flate2::read::DeflateDecoder::new(raw)),
        other => bail!(
            "{}: zip compression method {other} is not supported",
            String::from_utf8_lossy(&e.name)
        ),
    };
    Ok(Box::new(Checked {
        inner: data.take(e.usize),
        crc: flate2::Crc::new(),
        want_crc: e.crc,
        want_len: e.usize,
        name: String::from_utf8_lossy(&e.name).into_owned(),
    }))
}

/// Fails the read that ends short of the declared size or on a wrong CRC.
struct Checked<R> {
    inner: R,
    crc: flate2::Crc,
    want_crc: u32,
    want_len: u64,
    name: String,
}

impl<R: Read> Read for Checked<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() {
            if u64::from(self.crc.amount()) != (self.want_len & 0xFFFF_FFFF) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{}: zip entry shorter than declared", self.name),
                ));
            }
            if self.crc.sum() != self.want_crc {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: zip entry fails its CRC", self.name),
                ));
            }
        }
        self.crc.update(&buf[..n]);
        Ok(n)
    }
}

/// `name` as a safe relative path: no root, no `..`, no empty or `.` components (dropped).
/// `None` for a name that would land outside the directory it is unpacked in.
pub(crate) fn safe_name(name: &[u8]) -> Option<Vec<u8>> {
    let mut parts: Vec<&[u8]> = Vec::new();
    if name.starts_with(b"/") || name.contains(&0) {
        return None;
    }
    for part in name.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => return None,
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join(&b'/'))
}

fn path_of(name: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(name))
}

fn tar_header(kind: Kind, perm: u32, mtime: u64, size: u64) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(match kind {
        Kind::File => tar::EntryType::Regular,
        Kind::Dir => tar::EntryType::Directory,
        Kind::Symlink => tar::EntryType::Symlink,
    });
    h.set_mode(perm & 0o7777);
    h.set_mtime(mtime);
    h.set_size(size);
    h
}

/// Every entry of the zip in `r` into a tar on `out`, for the guest to unpack, as
/// gitlab-runner's `zip_extract.go` extracts them. An entry whose name would escape the
/// directory, or that is a pipe, socket or device, is left out and reported through `warn`.
/// Returns how many entries the tar holds.
pub(crate) fn zip_to_tar<R: Read + Seek, W: Write>(
    r: &mut R,
    out: W,
    warn: &mut dyn FnMut(String),
) -> Result<u64> {
    let entries = read_central(r)?;
    let mut tar = tar::Builder::new(out);
    let mut n = 0u64;
    for e in &entries {
        let shown = String::from_utf8_lossy(&e.name).into_owned();
        let Some(name) = safe_name(&e.name) else {
            warn(format!(
                "{shown:?}: path outside the project directory, ignored"
            ));
            continue;
        };
        let Some(kind) = e.kind() else {
            warn(format!("File ignored: {shown:?}"));
            continue;
        };
        let perm = e.perm(kind);
        match kind {
            Kind::Dir => {
                let mut h = tar_header(kind, perm, e.mtime, 0);
                tar.append_data(&mut h, path_of(&name), io::empty())?;
            }
            Kind::Symlink => {
                if e.usize > MAX_LINK {
                    warn(format!("{shown:?}: symlink target too long, ignored"));
                    continue;
                }
                let mut target = Vec::new();
                open_entry(r, e)?.read_to_end(&mut target)?;
                if target.is_empty() || target.contains(&0) {
                    warn(format!("{shown:?}: symlink target unusable, ignored"));
                    continue;
                }
                let mut h = tar_header(kind, perm, e.mtime, 0);
                tar.append_link(&mut h, path_of(&name), path_of(&target))?;
            }
            Kind::File => {
                let mut h = tar_header(kind, perm, e.mtime, e.usize);
                let data = open_entry(r, e)?;
                tar.append_data(&mut h, path_of(&name), data)
                    .with_context(|| format!("unpacking {shown}"))?;
            }
        }
        n += 1;
    }
    tar.into_inner()?.flush()?;
    Ok(n)
}

/// One entry of the guest's tar, as the archive writers take it.
enum TarItem {
    /// Its metadata, and a symlink's target.
    Keep(Meta, Option<Vec<u8>>),
    /// A kind the archive formats leave out: a hard link, a device.
    Unsupported,
    /// Left out: the root the guest archived from, or a name that would land outside the
    /// directory the archive is unpacked in (`warn` has said so).
    Skip,
}

/// One entry of the guest's tar, its name made relative and checked.
fn tar_meta(entry: &tar::Entry<'_, impl Read>, warn: &mut dyn FnMut(String)) -> Result<TarItem> {
    let h = entry.header();
    let raw: Cow<'_, [u8]> = entry.path_bytes();
    let kind = match h.entry_type() {
        tar::EntryType::Regular | tar::EntryType::Continuous => Kind::File,
        tar::EntryType::Directory => Kind::Dir,
        tar::EntryType::Symlink => Kind::Symlink,
        _ => return Ok(TarItem::Unsupported),
    };
    // `.` alone, the root the guest archived from, is no entry of its own.
    if raw.split(|&b| b == b'/').all(|p| p.is_empty() || p == b".") {
        return Ok(TarItem::Skip);
    }
    let Some(name) = safe_name(&raw) else {
        warn(format!(
            "{:?}: path outside the project directory, ignored",
            String::from_utf8_lossy(&raw)
        ));
        return Ok(TarItem::Skip);
    };
    let link = match kind {
        Kind::Symlink => Some(
            entry
                .link_name_bytes()
                .context("a symlink in the guest's archive has no target")?
                .into_owned(),
        ),
        _ => None,
    };
    let meta = Meta {
        name,
        kind,
        perm: h.mode().unwrap_or(0o644) & 0o7777,
        mtime: h.mtime().unwrap_or(0),
        uid: h
            .uid()
            .ok()
            .and_then(|u| u32::try_from(u).ok())
            .unwrap_or(0),
        gid: h
            .gid()
            .ok()
            .and_then(|g| u32::try_from(g).ok())
            .unwrap_or(0),
    };
    Ok(TarItem::Keep(meta, link))
}

/// The most bytes the tar reader may take between one entry's end and the next entry's
/// data: its headers, GNU long names and links, pax records and sparse blocks, each of which
/// it holds whole in memory. Generous for any archive `vk-agent` writes.
const MAX_HEADERS: u64 = (2 << 20) + 4096;

/// A reader failing past `budget` bytes while one is set.
struct Budgeted<R> {
    inner: R,
    budget: std::rc::Rc<std::cell::Cell<Option<u64>>>,
}

impl<R: Read> Read for Budgeted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.budget.get() else {
            return self.inner.read(buf);
        };
        if left == 0 && !buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the guest's archive has an entry header over {MAX_HEADERS} bytes"),
            ));
        }
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = self.inner.read(buf.get_mut(..want).unwrap_or_default())?;
        self.budget.set(Some(left - n as u64));
        Ok(n)
    }
}

/// `f` on each entry of `tar`, its headers read under [`MAX_HEADERS`] whatever they claim:
/// each entry's data is read to its end before the next header is.
fn each_entry<R: Read>(
    tar: R,
    mut f: impl FnMut(&mut tar::Entry<'_, Budgeted<R>>) -> Result<()>,
) -> Result<()> {
    let budget = std::rc::Rc::new(std::cell::Cell::new(None));
    let mut archive = tar::Archive::new(Budgeted {
        inner: tar,
        budget: budget.clone(),
    });
    let mut entries = archive.entries()?;
    loop {
        budget.set(Some(MAX_HEADERS));
        let next = entries.next();
        budget.set(None);
        let Some(entry) = next else {
            return Ok(());
        };
        let mut entry = entry?;
        // A sparse entry's size is what it claims, not what the stream holds: reading it out
        // could take forever.
        if entry.header().entry_type().is_gnu_sparse() {
            bail!("the guest's archive has a sparse entry, which artifacts cannot hold");
        }
        f(&mut entry)?;
        io::copy(&mut entry, &mut io::sink())?;
    }
}

/// The guest's tar as a zip on `out`. Returns how many entries it holds; entries the zip
/// format leaves out (hard links, devices) are reported through `warn`.
pub(crate) fn tar_to_zip<R: Read, W: Write + Seek>(
    tar: R,
    out: W,
    warn: &mut dyn FnMut(String),
) -> Result<u64> {
    let mut zip = ZipWriter::new(out);
    let mut n = 0u64;
    each_entry(tar, |entry| {
        let (meta, link) = match tar_meta(entry, warn)? {
            TarItem::Keep(meta, link) => (meta, link),
            TarItem::Unsupported => {
                warn(format!(
                    "File ignored: {:?}",
                    String::from_utf8_lossy(&entry.path_bytes())
                ));
                return Ok(());
            }
            TarItem::Skip => return Ok(()),
        };
        match link {
            Some(target) => {
                let len = target.len() as u64;
                zip.add(&meta, &mut target.as_slice(), len)?;
            }
            None => {
                let size = match meta.kind {
                    Kind::File => entry.size(),
                    _ => 0,
                };
                zip.add(&meta, entry, size)?;
            }
        }
        n += 1;
        Ok(())
    })?;
    zip.finish()?;
    Ok(n)
}

/// `gzip_create.go`'s `sanitizePath`: a name with anything but ASCII, or a `%`, is written
/// `e:` and path-escaped, as Go's `url.PathEscape` escapes it.
pub(crate) fn gzip_name(s: &[u8]) -> Vec<u8> {
    if !s.iter().any(|&b| b > 0x7F || b == b'%') {
        return s.to_vec();
    }
    let mut out = b"e:".to_vec();
    for &b in s {
        if b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            )
        {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

/// The guest's tar as gitlab-runner's gzip format: each regular file its own gzip member,
/// named after the file, with its path as the comment. Directories are passed over; a
/// symlink is refused, as gitlab-runner refuses anything but a regular file. Returns how
/// many files it holds.
pub(crate) fn tar_to_gzip<R: Read, W: Write>(
    tar: R,
    mut out: W,
    warn: &mut dyn FnMut(String),
) -> Result<u64> {
    let mut n = 0u64;
    each_entry(tar, |entry| {
        let TarItem::Keep(meta, _) = tar_meta(entry, warn)? else {
            return Ok(());
        };
        match meta.kind {
            Kind::Dir => return Ok(()),
            Kind::Symlink => bail!(
                "the {:?} is not a regular file",
                String::from_utf8_lossy(&meta.name)
            ),
            Kind::File => {}
        }
        let base = meta
            .name
            .rsplit(|&b| b == b'/')
            .next()
            .unwrap_or(&meta.name);
        let mut gz = flate2::GzBuilder::new()
            .filename(gzip_name(base))
            .comment(gzip_name(&meta.name))
            .mtime(clamp32(meta.mtime))
            .write(&mut out, Compression::default());
        io::copy(entry, &mut gz)?;
        gz.finish()?;
        n += 1;
        Ok(())
    })?;
    out.flush()?;
    Ok(n)
}

/// The guest's tar as a raw artifact: the one regular file it holds, as it is.
pub(crate) fn tar_to_raw<R: Read, W: Write>(
    tar: R,
    mut out: W,
    warn: &mut dyn FnMut(String),
) -> Result<()> {
    let mut seen = 0u32;
    each_entry(tar, |entry| {
        match tar_meta(entry, warn)? {
            TarItem::Skip => {}
            TarItem::Keep(meta, _) if meta.kind == Kind::Dir => {}
            TarItem::Keep(meta, _) if meta.kind == Kind::File => {
                seen += 1;
                if seen > 1 {
                    bail!("only one file can be sent as raw");
                }
                io::copy(entry, &mut out)?;
            }
            _ => bail!("only one file can be sent as raw"),
        }
        Ok(())
    })?;
    if seen != 1 {
        bail!("only one file can be sent as raw");
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn meta(name: &str, kind: Kind, perm: u32) -> Meta {
        Meta {
            name: name.as_bytes().to_vec(),
            kind,
            perm,
            mtime: 1_700_000_000,
            uid: 1000,
            gid: 1000,
        }
    }

    fn guest_tar() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar_header(Kind::Dir, 0o755, 1_700_000_000, 0);
        b.append_data(&mut h, "./report", io::empty()).unwrap();
        let body = b"<testsuite/>\n".repeat(100);
        let mut h = tar_header(Kind::File, 0o644, 1_700_000_000, body.len() as u64);
        b.append_data(&mut h, "./report/junit.xml", body.as_slice())
            .unwrap();
        let mut h = tar_header(Kind::Symlink, 0o777, 1_700_000_000, 0);
        b.append_link(&mut h, "report/latest", "junit.xml").unwrap();
        b.into_inner().unwrap()
    }

    /// As `zip_create_test.go` checks a created archive: every entry read back by name, mode
    /// and content.
    #[test]
    fn a_tar_becomes_the_zip_gitlab_runner_writes() {
        let mut warned = Vec::new();
        let mut out = Cursor::new(Vec::new());
        let n = tar_to_zip(guest_tar().as_slice(), &mut out, &mut |w| warned.push(w)).unwrap();
        assert_eq!(n, 3);
        assert!(warned.is_empty());
        let mut zip = Cursor::new(out.into_inner());
        let entries = read_central(&mut zip).unwrap();
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(
            names,
            [&b"report/"[..], b"report/junit.xml", b"report/latest"]
        );
        assert_eq!(entries[0].kind(), Some(Kind::Dir));
        assert_eq!(entries[0].mode, Some(S_IFDIR | 0o755));
        assert_eq!(entries[1].method, METHOD_DEFLATE);
        assert_eq!(entries[1].mode, Some(S_IFREG | 0o644));
        assert_eq!(entries[1].mtime, 1_700_000_000);
        assert!(entries[1].csize < entries[1].usize);
        assert_eq!(entries[2].kind(), Some(Kind::Symlink));
        let mut body = Vec::new();
        open_entry(&mut zip, &entries[1])
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, b"<testsuite/>\n".repeat(100));
        let mut target = Vec::new();
        open_entry(&mut zip, &entries[2])
            .unwrap()
            .read_to_end(&mut target)
            .unwrap();
        assert_eq!(target, b"junit.xml");
        // Local headers carry the UTF-8 flag and the sizes patched in.
        let raw = zip.get_ref();
        let at = entries[1].offset as usize;
        assert_eq!(le32(raw, at).unwrap(), LOCAL_SIG);
        assert_eq!(le16(raw, at + 6).unwrap() & FLAG_UTF8, FLAG_UTF8);
        assert_eq!(le32(raw, at + 14).unwrap(), entries[1].crc);
        assert_eq!(u64::from(le32(raw, at + 18).unwrap()), entries[1].csize);
        assert_eq!(u64::from(le32(raw, at + 22).unwrap()), entries[1].usize);
    }

    #[test]
    fn a_zip_becomes_a_tar_the_guest_can_unpack() {
        let mut out = Cursor::new(Vec::new());
        tar_to_zip(guest_tar().as_slice(), &mut out, &mut |_| {}).unwrap();
        let mut zip = Cursor::new(out.into_inner());
        let mut tar_bytes = Vec::new();
        let n = zip_to_tar(&mut zip, &mut tar_bytes, &mut |w| panic!("{w}")).unwrap();
        assert_eq!(n, 3);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let mut seen = Vec::new();
        for e in archive.entries().unwrap() {
            let mut e = e.unwrap();
            let path = e.path_bytes().into_owned();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            seen.push((path, e.header().entry_type(), data.len()));
        }
        assert_eq!(seen[0].1, tar::EntryType::Directory);
        assert_eq!(
            seen[1],
            (b"report/junit.xml".to_vec(), tar::EntryType::Regular, 1300)
        );
        assert_eq!(seen[2].1, tar::EntryType::Symlink);
    }

    #[test]
    fn names_that_escape_are_left_out() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for name in ["../evil", "/etc/passwd", "ok/../../evil", "fine/file"] {
            zip.add(&meta(name, Kind::File, 0o644), &mut &b"x"[..], 1)
                .unwrap();
        }
        let mut zip = Cursor::new(zip.finish().unwrap().into_inner());
        let mut warned = Vec::new();
        let mut tar_bytes = Vec::new();
        let n = zip_to_tar(&mut zip, &mut tar_bytes, &mut |w| warned.push(w)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(warned.len(), 3);
        assert_eq!(safe_name(b"./a//b/./c"), Some(b"a/b/c".to_vec()));
        assert_eq!(safe_name(b"."), None);
    }

    #[test]
    fn a_corrupt_entry_fails_its_crc() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        zip.add(&meta("f", Kind::Symlink, 0o777), &mut &b"target"[..], 6)
            .unwrap();
        let mut bytes = zip.finish().unwrap().into_inner();
        let entries = read_central(&mut Cursor::new(bytes.clone())).unwrap();
        let data_at = entries[0].offset as usize + 30 + 1 + 24;
        bytes[data_at] ^= 0xFF;
        let mut r = Cursor::new(bytes);
        let mut out = Vec::new();
        let err = open_entry(&mut r, &entries[0])
            .unwrap()
            .read_to_end(&mut out)
            .unwrap_err();
        assert!(err.to_string().contains("CRC"), "{err}");
    }

    #[test]
    fn many_entries_take_zip64_end_records() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..70_000u32 {
            zip.add(
                &meta(&format!("d{i}"), Kind::Dir, 0o755),
                &mut io::empty(),
                0,
            )
            .unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        let entries = read_central(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(entries.len(), 70_000);
        assert_eq!(entries[69_999].name, b"d69999/");
    }

    #[test]
    fn a_large_entry_is_written_zip64() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        // Lowered, so the zip64 layout is checked without writing 4 GiB.
        zip.zip64_at = 10;
        let body = b"0123456789abcdef".repeat(4);
        zip.add(&meta("big", Kind::File, 0o644), &mut body.as_slice(), 64)
            .unwrap();
        let mut r = Cursor::new(zip.finish().unwrap().into_inner());
        let entries = read_central(&mut r).unwrap();
        let raw = r.get_ref();
        assert_eq!(le16(raw, 4).unwrap(), VERSION_45);
        assert_eq!(le32(raw, 18).unwrap(), u32::MAX);
        assert_eq!(le32(raw, 22).unwrap(), u32::MAX);
        assert_eq!(le16(raw, 30 + 3).unwrap(), ZIP64_EXTRA);
        assert_eq!(le64(raw, 30 + 3 + 4).unwrap(), 64);
        assert_eq!(le64(raw, 30 + 3 + 12).unwrap(), entries[0].csize);
        let mut out = Vec::new();
        open_entry(&mut r, &entries[0])
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, body);
    }

    /// As `gzip_create_test.go`: one member per file, named after it.
    #[test]
    fn the_gzip_format_holds_one_member_per_file() {
        let mut out = Vec::new();
        let n = tar_to_gzip(guest_tar_files().as_slice(), &mut out, &mut |_| {}).unwrap();
        assert_eq!(n, 2);
        let mut d = flate2::read::MultiGzDecoder::new(out.as_slice());
        let mut all = Vec::new();
        d.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"onetwo");
        let first = flate2::read::GzDecoder::new(out.as_slice());
        let h = first.header().unwrap();
        assert_eq!(h.filename(), Some(&b"a.txt"[..]));
        assert_eq!(h.comment(), Some(&b"dir/a.txt"[..]));
        assert_eq!(gzip_name("é%".as_bytes()), b"e:%C3%A9%25");
        let err = tar_to_gzip(guest_tar().as_slice(), Vec::new(), &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    fn guest_tar_files() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, body) in [("dir/a.txt", &b"one"[..]), ("dir/b.txt", b"two")] {
            let mut h = tar_header(Kind::File, 0o644, 0, body.len() as u64);
            b.append_data(&mut h, path, body).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn a_raw_artifact_is_its_one_file() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar_header(Kind::Dir, 0o755, 0, 0);
        b.append_data(&mut h, "dir", io::empty()).unwrap();
        let mut h = tar_header(Kind::File, 0o644, 0, 3);
        b.append_data(&mut h, "dir/a", &b"abc"[..]).unwrap();
        let one = b.into_inner().unwrap();
        let mut out = Vec::new();
        tar_to_raw(one.as_slice(), &mut out, &mut |_| {}).unwrap();
        assert_eq!(out, b"abc");
        let err = tar_to_raw(guest_tar_files().as_slice(), Vec::new(), &mut |_| {}).unwrap_err();
        assert_eq!(err.to_string(), "only one file can be sent as raw");
    }

    /// A zip of two stored files, `a` and `b`, and where its end record starts.
    fn two_files() -> (Vec<u8>, usize) {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for name in ["a", "b"] {
            zip.add(&meta(name, Kind::Symlink, 0o777), &mut &b"data"[..], 4)
                .unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        let eocd = bytes.len() - 22;
        assert_eq!(le32(&bytes, eocd).unwrap(), EOCD_SIG);
        (bytes, eocd)
    }

    fn put16_at(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put32_at(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn malformed_zips_are_refused_not_trusted() {
        let (good, eocd) = two_files();
        let read = |b: Vec<u8>| read_central(&mut Cursor::new(b)).map(|e| e.len());
        assert_eq!(read(good.clone()).unwrap(), 2);

        // Cut short: the end record is gone.
        let err = read(good[..good.len() - 5].to_vec()).unwrap_err();
        assert!(
            err.to_string().contains("no end of central directory"),
            "{err}"
        );

        // A central directory shorter than its records.
        let mut short = good.clone();
        let size = le32(&short, eocd + 12).unwrap();
        put32_at(&mut short, eocd + 12, size - 10);
        assert!(read(short).is_err());

        // A central directory reaching past the file.
        let mut long = good.clone();
        put32_at(&mut long, eocd + 12, size + 1000);
        let err = read(long).unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");

        // More entries counted than held.
        let mut count = good.clone();
        put16_at(&mut count, eocd + 8, 3);
        put16_at(&mut count, eocd + 10, 3);
        let err = read(count).unwrap_err();
        assert!(err.to_string().contains("holds 2 entries, not 3"), "{err}");

        // A zip64 locator pointing past the file.
        let mut z64 = good[..eocd].to_vec();
        put32(&mut z64, ZIP64_LOCATOR_SIG);
        put32(&mut z64, 0);
        put64(&mut z64, u64::MAX - 7);
        put32(&mut z64, 1);
        let mut end = good[eocd..].to_vec();
        put16_at(&mut end, 10, 0xFFFF);
        z64.extend_from_slice(&end);
        let err = read(z64).unwrap_err();
        assert!(
            err.to_string()
                .contains("zip64 end of central directory out of range"),
            "{err}"
        );

        // Bytes after the comment, as Go's reader accepts them.
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"junk");
        assert_eq!(read(trailing).unwrap(), 2);
    }

    #[test]
    fn overlapping_entries_are_each_read_within_their_declared_size() {
        let (good, eocd) = two_files();
        let start = le32(&good, eocd + 16).unwrap() as usize;
        let size = le32(&good, eocd + 12).unwrap() as usize;
        // A third record naming `c`, over `a`'s data.
        let first_len = 46 + 1 + usize::from(le16(&good, start + 30).unwrap());
        let mut third = good[start..start + first_len].to_vec();
        third[46] = b'c';
        let mut bytes = good[..start + size].to_vec();
        bytes.extend_from_slice(&third);
        let mut end = good[eocd..].to_vec();
        put16_at(&mut end, 8, 3);
        put16_at(&mut end, 10, 3);
        put32_at(&mut end, 12, (size + first_len) as u32);
        bytes.extend_from_slice(&end);
        let mut tar_bytes = Vec::new();
        let n = zip_to_tar(&mut Cursor::new(bytes), &mut tar_bytes, &mut |w| {
            panic!("{w}")
        })
        .unwrap();
        assert_eq!(n, 3);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let links: Vec<(Vec<u8>, Vec<u8>)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.path_bytes().into_owned(),
                    e.link_name_bytes().unwrap().into_owned(),
                )
            })
            .collect();
        assert_eq!(links[2], (b"c".to_vec(), b"data".to_vec()));
    }

    /// The host only writes the tar; the guest's `vk-agent extract` refuses a path through a
    /// symlink the archive planted (`extraction_stays_inside_its_root` in `vk-agent`).
    #[test]
    fn a_path_through_a_planted_symlink_is_passed_to_the_guest_as_it_is() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        zip.add(&meta("a", Kind::Symlink, 0o777), &mut &b"/"[..], 1)
            .unwrap();
        zip.add(&meta("a/x", Kind::File, 0o644), &mut &b"x"[..], 1)
            .unwrap();
        let mut zip = Cursor::new(zip.finish().unwrap().into_inner());
        let mut tar_bytes = Vec::new();
        assert_eq!(
            zip_to_tar(&mut zip, &mut tar_bytes, &mut |w| panic!("{w}")).unwrap(),
            2
        );
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let kinds: Vec<(Vec<u8>, tar::EntryType)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.path_bytes().into_owned(), e.header().entry_type())
            })
            .collect();
        assert_eq!(
            kinds,
            [
                (b"a".to_vec(), tar::EntryType::Symlink),
                (b"a/x".to_vec(), tar::EntryType::Regular)
            ]
        );
    }

    #[test]
    fn a_symlink_with_an_unusable_target_is_left_out() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        zip.add(&meta("empty", Kind::Symlink, 0o777), &mut &b""[..], 0)
            .unwrap();
        zip.add(&meta("nul", Kind::Symlink, 0o777), &mut &b"a\0b"[..], 3)
            .unwrap();
        zip.add(&meta("ok", Kind::File, 0o644), &mut &b"x"[..], 1)
            .unwrap();
        let mut zip = Cursor::new(zip.finish().unwrap().into_inner());
        let mut warned = Vec::new();
        let n = zip_to_tar(&mut zip, Vec::new(), &mut |w| warned.push(w)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            warned,
            [
                "\"empty\": symlink target unusable, ignored",
                "\"nul\": symlink target unusable, ignored"
            ]
        );
    }

    #[test]
    fn guest_names_that_escape_stay_out_of_the_zip() {
        let mut b = tar::Builder::new(Vec::new());
        for name in ["../evil", "/abs", "ok/../../evil", "./fine"] {
            let mut h = tar::Header::new_gnu();
            h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o644);
            h.set_size(1);
            h.set_cksum();
            b.append(&h, &b"x"[..]).unwrap();
        }
        let tar_bytes = b.into_inner().unwrap();
        let mut warned = Vec::new();
        let mut out = Cursor::new(Vec::new());
        assert_eq!(
            tar_to_zip(tar_bytes.as_slice(), &mut out, &mut |w| warned.push(w)).unwrap(),
            1
        );
        assert_eq!(warned.len(), 3, "{warned:?}");
        let entries = read_central(&mut Cursor::new(out.into_inner())).unwrap();
        assert_eq!(entries[0].name, b"fine");
        let mut gz = Vec::new();
        assert_eq!(
            tar_to_gzip(tar_bytes.as_slice(), &mut gz, &mut |_| {}).unwrap(),
            1
        );
    }

    #[test]
    fn modes_from_other_systems_follow_go() {
        let entry = |mode, external| ZipEntry {
            name: b"f".to_vec(),
            method: METHOD_STORE,
            crc: 0,
            csize: 0,
            usize: 0,
            offset: 0,
            mode,
            external,
            mtime: 0,
            zip64: false,
        };
        assert_eq!(entry(None, 0).perm(Kind::File), 0o644);
        assert_eq!(entry(None, MSDOS_READ_ONLY).perm(Kind::File), 0o444);
        assert_eq!(entry(None, MSDOS_READ_ONLY).perm(Kind::Dir), 0o555);
        assert_eq!(
            entry(Some(S_IFREG | 0o600), MSDOS_READ_ONLY).perm(Kind::File),
            0o600
        );
    }

    #[test]
    fn dos_time_round_trips_at_two_second_resolution() {
        let (date, time) = dos_time(1_700_000_001);
        assert_eq!(dos_to_unix(date, time), 1_700_000_000);
        assert_eq!(dos_time(0), ((1 << 5) | 1, 0));
    }

    #[test]
    fn a_sparse_entry_is_refused_before_it_is_read() {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_path("holes").unwrap();
        h.set_mode(0o644);
        h.set_size(0);
        // GNU's base-256 numbers, for what octal cannot hold.
        let big = |v: u64| {
            let mut f = [0u8; 12];
            f[0] = 0x80;
            f[4..].copy_from_slice(&v.to_be_bytes());
            f
        };
        let gnu = h.as_gnu_mut().unwrap();
        // One empty block at 2^62, in a file of 2^62 bytes: all of it holes.
        gnu.sparse[0].offset = big(1 << 62);
        gnu.sparse[0].numbytes = *b"00000000000\0";
        gnu.realsize = big(1 << 62);
        h.set_cksum();
        let mut tar = h.as_bytes().to_vec();
        tar.extend([0u8; 1024]);
        let started = std::time::Instant::now();
        let err = tar_to_zip(tar.as_slice(), Cursor::new(Vec::new()), &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("sparse entry"), "{err:#}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_central_directory_past_its_bound_is_neither_written_nor_read() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        // Lowered, so the bound is checked without millions of entries.
        zip.max_central = 3 * (CENTRAL_FIXED + 1 + CENTRAL_EXTRA_MAX);
        for name in ["a", "b", "c"] {
            zip.add(&meta(name, Kind::File, 0o644), &mut &b""[..], 0)
                .unwrap();
        }
        let err = zip
            .add(&meta("d", Kind::File, 0o644), &mut &b""[..], 0)
            .unwrap_err();
        assert!(err.to_string().contains("too many for zip"), "{err:#}");
        // An end record claiming a directory over the bound is refused before it is read.
        let mut eocd = Vec::new();
        put32(&mut eocd, EOCD_SIG);
        put16(&mut eocd, 0);
        put16(&mut eocd, 0);
        put16(&mut eocd, 1);
        put16(&mut eocd, 1);
        put32(&mut eocd, clamp32(MAX_CENTRAL + 1));
        put32(&mut eocd, 0);
        put16(&mut eocd, 0);
        let err = read_central(&mut Cursor::new(eocd)).unwrap_err();
        assert!(err.to_string().contains("over"), "{err:#}");
    }
}
