//! The guest kernel, vk-agent, UEFI firmware and its variable store templates, optionally
//! embedded into the `vk` binary.
//!
//! The shipped `vk` is self-contained: build.sh compiles a bare `vk` (`dist/vk-bare`), then
//! `assemble.sh` appends the blobs to it as a payload. At runtime an asset is resolved in this
//! order: an explicit --kernel/--agent path, else the embedded copy (served from an anonymous
//! memfd), else the on-disk default under /usr/local/lib/vk. A plain dev `cargo build` has no
//! payload, so it just uses the flags or the on-disk defaults.
//!
//! The payload is appended after linking, so the compile does not wait for the kernel build
//! and the bare binary is the same whichever blobs it later carries. The loader maps only the
//! ELF's segments, so the bytes after them are never loaded; vk maps its own executable
//! (`/proc/self/exe`, which names the running file even after `vk update` renames a new one
//! over it) and reads the blobs from there:
//!
//! ```text
//! <vk-bare> <blob>... <index> <trailer>
//! index:   one line per blob, "<name> <offset> <size> <sha256>\n" — offset and size in
//!          decimal bytes, the offset from the start of the file, the digest lowercase hex
//! trailer: "VKPAYLOAD1 <index offset> <index length>\n", both 16 lowercase hex digits
//! ```
//!
//! A file that ends where its ELF headers say it does has no payload; the headers are read as
//! little-endian ELF64, what vk is built as (x86_64 and aarch64 Linux). Anything else is held to
//! the format: bytes after the ELF with no trailer (a payload cut short), an index that is out
//! of bounds or does not parse, or a blob that fails its digest, is an error rather than a
//! quiet fall back to the on-disk defaults.
//!
//! Reading the payload needs the executable to be readable through `/proc/self/exe`: an
//! execute-only `vk`, or one with no `/proc`, cannot serve its embedded assets and says so
//! instead of falling back. Taking either for "no payload" would hide a released vk's kernel
//! and agent behind whatever /usr/local/lib/vk holds, and the memfds the assets are handed
//! over in are reached through `/proc` anyway.
//!
//! An embedded asset is materialised into an anonymous (CLOEXEC) memfd rather than a
//! temp file, so nothing touches disk. The kernel is handed to the spawned VMM by
//! clearing CLOEXEC on its fd for that one spawn (`run::spawn_vmm`), which then opens
//! `/proc/self/fd/<n>`; the agent is only ever reopened in this process by the packer. The
//! digest is checked on the bytes as they are written to the memfd, which is then sealed
//! against any further change, so what the VMM boots is what was checked; [`Asset::embedded`],
//! for callers that read the bytes in place, checks each blob once per process.
//!
//! The checks cost a sha256 of each blob used. sha2 picks the SHA-NI instructions at run time
//! where the CPU has them, at roughly 1.5–2 GB/s: some 15–20 ms for a ~24 MB kernel and a
//! ~7 MB agent. Without them it runs at a few hundred MB/s, around 100 ms. (`vk check`, which
//! hashes the kernel and the agent, took 74 ms in all for a 21 MB kernel and a 63 MB debug
//! agent on a SHA-NI host.)
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asset {
    Kernel,
    Agent,
    /// The UEFI firmware a UEFI guest (Windows) boots (`CLOUDHV.fd`, build-firmware.sh).
    Firmware,
    /// The firmware's empty variable store for a new machine (`CLOUDHV_VARS.fd`).
    UefiVars,
    /// The variable store with Microsoft's Secure Boot keys enrolled (`CLOUDHV_VARS.ms.fd`).
    UefiVarsSecureBoot,
}

/// Every asset, in [`Asset::index`] order.
const ASSETS: [Asset; 5] = [
    Asset::Kernel,
    Asset::Agent,
    Asset::Firmware,
    Asset::UefiVars,
    Asset::UefiVarsSecureBoot,
];

impl Asset {
    /// The asset's name in the payload index, and the name given to the memfd backing the
    /// embedded copy. assemble.sh accepts these names only.
    fn filename(self) -> &'static str {
        match self {
            Asset::Kernel => "vmlinux",
            Asset::Agent => "vk-agent",
            Asset::Firmware => "CLOUDHV.fd",
            Asset::UefiVars => "CLOUDHV_VARS.fd",
            Asset::UefiVarsSecureBoot => "CLOUDHV_VARS.ms.fd",
        }
    }

    /// Position in [`ASSETS`].
    fn index(self) -> usize {
        match self {
            Asset::Kernel => 0,
            Asset::Agent => 1,
            Asset::Firmware => 2,
            Asset::UefiVars => 3,
            Asset::UefiVarsSecureBoot => 4,
        }
    }

    /// On-disk fallback when nothing is embedded and no flag is given.
    pub fn default_path(self) -> &'static str {
        match self {
            Asset::Kernel => "/usr/local/lib/vk/vmlinux",
            Asset::Agent => "/usr/local/lib/vk/vk-agent",
            Asset::Firmware => "/usr/local/lib/vk/CLOUDHV.fd",
            Asset::UefiVars => "/usr/local/lib/vk/CLOUDHV_VARS.fd",
            Asset::UefiVarsSecureBoot => "/usr/local/lib/vk/CLOUDHV_VARS.ms.fd",
        }
    }

    /// The embedded copy, `None` when this `vk` carries none; an error when its payload is
    /// damaged or this blob fails its digest, checked once per process.
    pub fn embedded(self) -> Result<Option<&'static [u8]>> {
        static BLOBS: [OnceLock<Lookup>; ASSETS.len()] = [const { OnceLock::new() }; ASSETS.len()];
        let Some(cell) = BLOBS.get(self.index()) else {
            return Ok(None);
        };
        cell.get_or_init(|| {
            let Some(payload) = own_payload()? else {
                return Ok(None);
            };
            payload.index.blob(payload.image, self).map_err(damaged)
        })
        .clone()
        .map_err(anyhow::Error::msg)
    }

    /// The embedded copy and its expected digest, bounds-checked but not hashed.
    fn located(self) -> Result<Option<(&'static [u8], &'static str)>> {
        let Some(payload) = own_payload().map_err(anyhow::Error::msg)? else {
            return Ok(None);
        };
        payload
            .index
            .locate(payload.image, self)
            .map_err(|e| anyhow::Error::msg(damaged(e)))
    }
}

/// What [`Asset::embedded`] found for one asset, kept for the rest of the process.
type Lookup = Result<Option<&'static [u8]>, String>;

fn damaged(e: PayloadError) -> String {
    match e {
        PayloadError::ShortElf => format!("this vk's executable is damaged: {e}"),
        _ => format!("this vk's embedded payload is damaged: {e}"),
    }
}

/// The trailer's leading bytes, which also tell a payload's presence.
const MAGIC: &[u8] = b"VKPAYLOAD1 ";
/// `MAGIC`, two 16-digit hex numbers, a space between them and a newline.
const TRAILER_LEN: usize = MAGIC.len() + 16 + 1 + 16 + 1;

/// Why a payload cannot be read.
#[derive(Debug, PartialEq, Eq)]
enum PayloadError {
    /// The trailer or an index entry points past the bytes there are.
    Truncated,
    /// The ELF headers, or the segments and sections they list, reach past the end of the
    /// file: the executable itself is cut short.
    ShortElf,
    /// Bytes follow the ELF executable but end in no trailer: a payload cut short.
    Unterminated(usize),
    /// The ELF headers, the trailer or an index line do not parse.
    Malformed(String),
    /// A blob's bytes do not hash to the digest the index records.
    Digest(&'static str),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::Truncated => write!(f, "it points past the end of the file"),
            PayloadError::ShortElf => write!(f, "its ELF headers point past the end of the file"),
            PayloadError::Unterminated(n) => write!(
                f,
                "{n} bytes follow the executable with no payload trailer (a payload cut short?)"
            ),
            PayloadError::Malformed(why) => write!(f, "{why}"),
            PayloadError::Digest(name) => write!(f, "{name} does not match its sha256"),
        }
    }
}

/// One blob's place in the file and its expected digest.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    offset: usize,
    size: usize,
    sha256: String,
}

/// A parsed payload index, an entry per asset it carries.
#[derive(Debug, Default, PartialEq, Eq)]
struct Index {
    entries: [Option<Entry>; ASSETS.len()],
}

impl Index {
    /// `asset`'s bytes in `image` and their expected digest, not yet checked against it;
    /// `None` when not carried.
    fn locate<'a, 's>(
        &'s self,
        image: &'a [u8],
        asset: Asset,
    ) -> Result<Option<(&'a [u8], &'s str)>, PayloadError> {
        let Some(Some(e)) = self.entries.get(asset.index()) else {
            return Ok(None);
        };
        let end = e
            .offset
            .checked_add(e.size)
            .ok_or(PayloadError::Truncated)?;
        let bytes = image.get(e.offset..end).ok_or(PayloadError::Truncated)?;
        Ok(Some((bytes, &e.sha256)))
    }

    /// `asset`'s bytes in `image`, checked against their digest; `None` when not carried.
    fn blob<'a>(&self, image: &'a [u8], asset: Asset) -> Result<Option<&'a [u8]>, PayloadError> {
        let Some((bytes, sha256)) = self.locate(image, asset)? else {
            return Ok(None);
        };
        if crate::build::hex(&Sha256::digest(bytes)) != sha256 {
            return Err(PayloadError::Digest(asset.filename()));
        }
        Ok(Some(bytes))
    }
}

/// The payload index of `image`, a whole `vk` file; `None` when it carries no payload.
fn parse(image: &[u8]) -> Result<Option<Index>, PayloadError> {
    let trailer = image
        .len()
        .checked_sub(TRAILER_LEN)
        .and_then(|at| Some((at, image.get(at..)?.strip_prefix(MAGIC)?)));
    let Some((trailer_at, fields)) = trailer else {
        return bare(image);
    };
    let bad = |why: &str| PayloadError::Malformed(format!("its trailer {why}"));
    let fields = fields
        .strip_suffix(b"\n")
        .ok_or_else(|| bad("lacks a newline"))?;
    let [at, len] = fields.split(|&b| b == b' ').collect::<Vec<_>>()[..] else {
        return Err(bad("does not have two fields"));
    };
    let at = hex_field(at).ok_or_else(|| bad("has a bad index offset"))?;
    let len = hex_field(len).ok_or_else(|| bad("has a bad index length"))?;
    let end = at.checked_add(len).ok_or(PayloadError::Truncated)?;
    if end > trailer_at {
        return Err(PayloadError::Truncated);
    }
    if end != trailer_at {
        return Err(bad("leaves a gap before itself"));
    }
    let text = image.get(at..end).ok_or(PayloadError::Truncated)?;
    let mut index = Index::default();
    if text.is_empty() {
        return Ok(Some(index));
    }
    let lines = text
        .strip_suffix(b"\n")
        .ok_or_else(|| PayloadError::Malformed("its index lacks a final newline".to_string()))?;
    for line in lines.split(|&b| b == b'\n') {
        let (asset, entry) = parse_entry(line)?;
        // Blobs lie between the bare binary and the index.
        if entry.offset.checked_add(entry.size).is_none_or(|e| e > at) {
            return Err(PayloadError::Truncated);
        }
        let slot = index.entries.get_mut(asset.index()).ok_or_else(|| {
            PayloadError::Malformed(format!("internal: no index slot for {}", asset.filename()))
        })?;
        if slot.is_some() {
            return Err(PayloadError::Malformed(format!(
                "its index lists {} twice",
                asset.filename()
            )));
        }
        *slot = Some(entry);
    }
    Ok(Some(index))
}

/// An `image` with no trailer: no payload if it ends where its ELF headers say, damaged if
/// anything follows.
fn bare(image: &[u8]) -> Result<Option<Index>, PayloadError> {
    if image.get(..ELF_IDENT.len()) != Some(ELF_IDENT) {
        return Err(PayloadError::Malformed(
            "it is not a little-endian ELF64 executable".to_string(),
        ));
    }
    let end = elf_end(image).ok_or(PayloadError::ShortElf)?;
    match image.len().checked_sub(end) {
        Some(0) => Ok(None),
        Some(extra) => Err(PayloadError::Unterminated(extra)),
        None => Err(PayloadError::ShortElf),
    }
}

/// The magic, ELFCLASS64 and ELFDATA2LSB: the only ELF files vk is built as (x86_64 and
/// aarch64 Linux).
const ELF_IDENT: &[u8] = b"\x7fELF\x02\x01";

/// Where the little-endian ELF64 file `image` ends: the furthest byte its file header,
/// program and section header tables, segments and sections cover. A linked binary ends there
/// (a stripped static-pie with its section header table last); anything after was appended.
/// The extended numbering escapes are followed: `e_shnum` 0 with the count in the first
/// section header's `sh_size`, `e_phnum` `PN_XNUM` with it in that header's `sh_info`. Other
/// ELF classes and byte orders are not handled. `None` when `image` is not such a file or its
/// headers lie outside it.
fn elf_end(image: &[u8]) -> Option<usize> {
    fn bytes<const N: usize>(image: &[u8], at: usize) -> Option<[u8; N]> {
        image.get(at..at.checked_add(N)?)?.try_into().ok()
    }
    let half = |at: usize| bytes::<2>(image, at).map(|b| usize::from(u16::from_le_bytes(b)));
    let word = |at: usize| bytes::<4>(image, at).map(u32::from_le_bytes);
    let xword =
        |at: usize| bytes::<8>(image, at).and_then(|b| usize::try_from(u64::from_le_bytes(b)).ok());
    if image.get(..ELF_IDENT.len())? != ELF_IDENT {
        return None;
    }
    const EHDR_LEN: usize = 64;
    const PN_XNUM: usize = 0xffff;
    let (phoff, shoff) = (xword(0x20)?, xword(0x28)?);
    let (phentsize, mut phnum) = (half(0x36)?, half(0x38)?);
    let (shentsize, mut shnum) = (half(0x3a)?, half(0x3c)?);
    if shoff != 0 && shnum == 0 {
        shnum = xword(shoff.checked_add(32)?)?; // sh[0].sh_size
    }
    if phnum == PN_XNUM {
        phnum = usize::try_from(word(shoff.checked_add(44)?)?).ok()?; // sh[0].sh_info
    }
    let table_end = |off: usize, n: usize, size: usize| off.checked_add(n.checked_mul(size)?);
    let mut end = EHDR_LEN
        .max(table_end(phoff, phnum, phentsize)?)
        .max(table_end(shoff, shnum, shentsize)?);
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        // p_offset, p_filesz.
        let (offset, filesz) = (xword(ph.checked_add(8)?)?, xword(ph.checked_add(32)?)?);
        end = end.max(offset.checked_add(filesz)?);
    }
    const SHT_NOBITS: u32 = 8;
    for i in 0..shnum {
        let sh = shoff.checked_add(i.checked_mul(shentsize)?)?;
        // sh_type, sh_offset, sh_size; a NOBITS section (.bss) takes no room in the file.
        if word(sh.checked_add(4)?)? != SHT_NOBITS {
            let (offset, size) = (xword(sh.checked_add(24)?)?, xword(sh.checked_add(32)?)?);
            end = end.max(offset.checked_add(size)?);
        }
    }
    Some(end)
}

/// One index line, `<name> <offset> <size> <sha256>`.
fn parse_entry(line: &[u8]) -> Result<(Asset, Entry), PayloadError> {
    // Shown in an error only.
    let shown = String::from_utf8_lossy(line);
    let bad = || PayloadError::Malformed(format!("its index line '{shown}' does not parse"));
    let [name, offset, size, sha256] = line.split(|&b| b == b' ').collect::<Vec<_>>()[..] else {
        return Err(bad());
    };
    let asset = ASSETS
        .into_iter()
        .find(|a| a.filename().as_bytes() == name)
        .ok_or_else(|| {
            PayloadError::Malformed(format!("its index names an unknown blob: '{shown}'"))
        })?;
    let offset = decimal_field(offset).ok_or_else(bad)?;
    let size = decimal_field(size).ok_or_else(bad)?;
    if size == 0 {
        return Err(PayloadError::Malformed(format!(
            "its index lists an empty {}",
            asset.filename()
        )));
    }
    if sha256.len() != 64 || !sha256.iter().all(is_lower_hex) {
        return Err(bad());
    }
    let sha256 = String::from_utf8(sha256.to_vec()).map_err(|_| bad())?;
    Ok((
        asset,
        Entry {
            offset,
            size,
            sha256,
        },
    ))
}

fn is_lower_hex(b: &u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
}

/// A 16-digit lowercase hex number.
fn hex_field(s: &[u8]) -> Option<usize> {
    if s.len() != 16 || !s.iter().all(is_lower_hex) {
        return None;
    }
    usize::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok()
}

/// A plain decimal number: digits only, no sign.
fn decimal_field(s: &[u8]) -> Option<usize> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// This process's own executable and the payload index parsed from it.
struct Payload {
    image: &'static [u8],
    index: Index,
}

/// The running `vk`'s payload, mapped and parsed once per process.
fn own_payload() -> Result<Option<&'static Payload>, String> {
    static PAYLOAD: OnceLock<Result<Option<Payload>, String>> = OnceLock::new();
    PAYLOAD
        .get_or_init(|| {
            let image = map_own_executable().map_err(|e| {
                format!("reading this vk's embedded assets needs /proc/self/exe readable: {e}")
            })?;
            match parse(image) {
                Ok(index) => Ok(index.map(|index| Payload { image, index })),
                Err(e) => Err(damaged(e)),
            }
        })
        .as_ref()
        .map(Option::as_ref)
        .map_err(|e| e.clone())
}

/// The running executable, mapped read-only for the rest of the process. Pages are read in
/// only as a blob is used, as the `.rodata` of a linked-in blob would be.
fn map_own_executable() -> std::io::Result<&'static [u8]> {
    // The magic link, not the path it reads as: it opens the file this process runs, even
    // once `vk update` has renamed a new binary over that path.
    let file = File::open("/proc/self/exe")?;
    let len = usize::try_from(file.metadata()?.len())
        .map_err(|_| std::io::Error::other("executable larger than the address space"))?;
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: a fresh read-only private mapping of a file we hold open. The slice handed out
    // relies on the file's bytes never changing, which holds because nothing writes a vk in
    // place: build.sh, assemble.sh, `vk update` and the node's self-update all write a new
    // file and rename it over the old one, leaving this inode as it was. What is handed to the
    // VMM is checked again as it is copied out (`resolve`) regardless.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the mapping is `len` readable bytes and is never unmapped, so it lives as long as
    // the process; closing `file` leaves it in place.
    Ok(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
}

/// A resolved asset: the path to hand a consumer, plus the memfd backing it when the
/// asset is embedded.
pub struct Resolved {
    pub path: PathBuf,
    /// The open (CLOEXEC) memfd for an embedded asset, held so its `/proc/self/fd/<n>`
    /// path stays valid — the VMM opens the kernel (its spawn clears CLOEXEC on this fd)
    /// and the in-process packer reopens the agent. `None` for an explicit --flag path or
    /// the on-disk default.
    fd: Option<File>,
}

impl Resolved {
    /// Whether this resolved to the embedded copy (a memfd) rather than a real path.
    pub fn is_embedded(&self) -> bool {
        self.fd.is_some()
    }
}

/// Resolve an asset. An explicit override wins; otherwise the embedded copy is placed
/// in an anonymous memfd — no disk copy — and addressed as `/proc/self/fd/<n>`, which a
/// spawned VMM inherits and opens (and the in-process packer reopens); otherwise the
/// on-disk default is used. The agent's mode is set by the initramfs/ext4 packers, so
/// the backing file need not be executable.
pub fn resolve(asset: Asset, explicit: Option<&Path>) -> Result<Resolved> {
    if let Some(p) = explicit {
        return Ok(Resolved {
            path: p.to_path_buf(),
            fd: None,
        });
    }
    if let Some((bytes, sha256)) = asset.located()? {
        let (file, path, digest) = memfd(asset.filename(), bytes)?;
        if digest != sha256 {
            anyhow::bail!(damaged(PayloadError::Digest(asset.filename())));
        }
        seal(&file)
            .with_context(|| format!("sealing the memfd of embedded {}", asset.filename()))?;
        return Ok(Resolved {
            path,
            fd: Some(file),
        });
    }
    Ok(Resolved {
        path: PathBuf::from(asset.default_path()),
        fd: None,
    })
}

/// Back `bytes` with an anonymous in-memory file and return it with its
/// `/proc/self/fd/<n>` path and the sha256 of what was written. The fd is `CLOEXEC`, so idle
/// helper children never inherit it; the kernel is handed to the VMM by clearing `CLOEXEC` on
/// its fd only in that spawn (see `run::spawn_vmm`), and the agent is only ever reopened
/// in-process. The caller holds the returned `File` to keep the fd open, and [`seal`]s it once
/// the digest is right.
fn memfd(name: &str, bytes: &[u8]) -> Result<(File, PathBuf, String)> {
    let cname = std::ffi::CString::new(name).expect("asset name has no interior nul");
    // SAFETY: `cname` is a valid C string; memfd_create returns an owned fd or -1/errno.
    let fd =
        unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("memfd_create");
    }
    // SAFETY: `fd` was just created and is owned by us.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut hasher = Sha256::new();
    // Through a buffer of our own: the bytes hashed are the bytes written, whatever the
    // mapping they come from does in between.
    let mut buf = vec![0u8; 1 << 20];
    for chunk in bytes.chunks(buf.len()) {
        let copy = buf.get_mut(..chunk.len()).unwrap_or_default();
        copy.copy_from_slice(chunk);
        hasher.update(&*copy);
        file.write_all(copy)
            .with_context(|| format!("writing embedded {name} to a memfd"))?;
    }
    let digest = crate::build::hex(&hasher.finalize());
    Ok((file, PathBuf::from(format!("/proc/self/fd/{fd}")), digest))
}

/// Make a memfd's contents final: no more writes, growing or shrinking, and no seal changes.
/// Its consumers — the VMM loading the kernel or firmware, the packers and the exec of the
/// agent — only ever open it to read.
fn seal(file: &File) -> std::io::Result<()> {
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: fcntl on an fd we own, with an integer argument.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64 file: the file header and one empty section header after it, which is
    /// where its headers say it ends.
    fn elf() -> Vec<u8> {
        let mut out = vec![0u8; 128];
        out[..6].copy_from_slice(b"\x7fELF\x02\x01");
        out[0x28..0x30].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        out[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        out[0x3c..0x3e].copy_from_slice(&1u16.to_le_bytes()); // e_shnum
        out
    }

    /// `bare` with `blobs` appended as assemble.sh appends them.
    fn assemble(bare: &[u8], blobs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = bare.to_vec();
        let mut index = String::new();
        for (name, bytes) in blobs {
            let sum = crate::build::hex(&Sha256::digest(bytes));
            index.push_str(&format!("{name} {} {} {sum}\n", out.len(), bytes.len()));
            out.extend_from_slice(bytes);
        }
        let at = out.len();
        out.extend_from_slice(index.as_bytes());
        out.extend_from_slice(format!("VKPAYLOAD1 {at:016x} {:016x}\n", index.len()).as_bytes());
        out
    }

    /// `index` and a trailer naming `at` and `len` after a bare binary.
    fn with_trailer(index: &str, at: usize, len: usize) -> Vec<u8> {
        let mut out = elf();
        out.extend_from_slice(index.as_bytes());
        out.extend_from_slice(format!("VKPAYLOAD1 {at:016x} {len:016x}\n").as_bytes());
        out
    }

    /// `index` after a bare binary, with a trailer that frames it exactly.
    fn with_index(index: &str) -> Vec<u8> {
        with_trailer(index, elf().len(), index.len())
    }

    /// Runs `sh assemble.sh <args>`, its output discarded.
    fn assemble_sh<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> std::process::ExitStatus {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../assemble.sh");
        std::process::Command::new("sh")
            .arg(script)
            .args(args)
            .output()
            .unwrap()
            .status
    }

    #[test]
    fn explicit_flag_wins() {
        // resolve() never touches an explicit path (existence is the caller's check).
        let p = Path::new("/nonexistent/vmlinux");
        let r = resolve(Asset::Kernel, Some(p)).unwrap();
        assert_eq!(r.path, p);
        assert!(!r.is_embedded());
    }

    #[test]
    fn a_test_binary_embeds_nothing_and_uses_the_defaults() {
        // This also shows elf_end finding the true end of a real linked binary.
        for asset in ASSETS {
            assert_eq!(asset.embedded().unwrap(), None);
            let r = resolve(asset, None).unwrap();
            assert!(!r.is_embedded());
            assert_eq!(r.path, Path::new(asset.default_path()));
        }
    }

    #[test]
    fn assets_are_listed_in_index_order() {
        for (i, asset) in ASSETS.into_iter().enumerate() {
            assert_eq!(asset.index(), i);
        }
    }

    #[test]
    fn a_bare_elf_is_no_payload() {
        assert_eq!(parse(&elf()), Ok(None));
    }

    #[test]
    fn bytes_after_the_elf_with_no_trailer_are_damage() {
        // A payload cut short loses its trailer, but not the bytes before the cut.
        let whole = assemble(&elf(), &[("vk-agent", b"agent")]);
        let cut = &whole[..whole.len() - 1];
        assert_eq!(parse(cut), Err(PayloadError::Unterminated(cut.len() - 128)));
        let mut junk = elf();
        junk.push(0);
        assert_eq!(parse(&junk), Err(PayloadError::Unterminated(1)));
    }

    #[test]
    fn what_is_not_a_whole_elf_is_refused() {
        // The section header table runs past the end.
        assert_eq!(parse(&elf()[..100]), Err(PayloadError::ShortElf));
        assert!(matches!(parse(b""), Err(PayloadError::Malformed(_))));
        assert!(matches!(
            parse(b"not an executable at all"),
            Err(PayloadError::Malformed(_))
        ));
    }

    #[test]
    fn elf_end_covers_segments_and_sections() {
        let mut image = elf();
        // A program header table at 128 with one segment reaching byte 300.
        image[0x20..0x28].copy_from_slice(&128u64.to_le_bytes()); // e_phoff
        image[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        image[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let mut ph = [0u8; 56];
        ph[8..16].copy_from_slice(&200u64.to_le_bytes()); // p_offset
        ph[32..40].copy_from_slice(&100u64.to_le_bytes()); // p_filesz
        image.extend_from_slice(&ph);
        assert_eq!(elf_end(&image), Some(300));
        // The segment lies past the file's end.
        assert_eq!(parse(&image), Err(PayloadError::ShortElf));
        image.resize(300, 0);
        assert_eq!(parse(&image), Ok(None));
        // A section reaching further, then the same one as NOBITS, which takes no room.
        let mut sh = [0u8; 64];
        sh[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
        sh[24..32].copy_from_slice(&300u64.to_le_bytes()); // sh_offset
        sh[32..40].copy_from_slice(&50u64.to_le_bytes()); // sh_size
        image[64..128].copy_from_slice(&sh);
        assert_eq!(elf_end(&image), Some(350));
        image[68..72].copy_from_slice(&8u32.to_le_bytes()); // SHT_NOBITS
        assert_eq!(elf_end(&image), Some(300));
    }

    #[test]
    fn elf_end_follows_the_extended_numbering_escapes() {
        // e_shnum 0 and e_phnum PN_XNUM: the counts are in the first section header.
        let mut image = elf();
        image[0x3c..0x3e].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
        image[0x38..0x3a].copy_from_slice(&0xffffu16.to_le_bytes()); // e_phnum
        image[0x20..0x28].copy_from_slice(&192u64.to_le_bytes()); // e_phoff
        image[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        // Two section headers (64..192), then one program header (192..248).
        image[64 + 32..64 + 40].copy_from_slice(&2u64.to_le_bytes()); // sh[0].sh_size
        image[64 + 44..64 + 48].copy_from_slice(&1u32.to_le_bytes()); // sh[0].sh_info
        image.resize(248, 0);
        assert_eq!(elf_end(&image), Some(248));
        assert_eq!(parse(&image), Ok(None));
        // The second section header names a section reaching byte 400.
        image[128 + 24..128 + 32].copy_from_slice(&300u64.to_le_bytes()); // sh_offset
        image[128 + 32..128 + 40].copy_from_slice(&100u64.to_le_bytes()); // sh_size
        assert_eq!(elf_end(&image), Some(400));
    }

    #[test]
    fn every_blob_is_found_and_checked() {
        let bare = elf();
        let image = assemble(
            &bare,
            &[
                ("vk-agent", b"agent bytes"),
                ("vmlinux", b"kernel bytes"),
                ("CLOUDHV.fd", b"firmware"),
                ("CLOUDHV_VARS.fd", b"vars"),
                ("CLOUDHV_VARS.ms.fd", b"secure boot vars"),
            ],
        );
        let index = parse(&image).unwrap().unwrap();
        let blob = |a| index.blob(&image, a).unwrap();
        assert_eq!(blob(Asset::Agent), Some(&b"agent bytes"[..]));
        assert_eq!(blob(Asset::Kernel), Some(&b"kernel bytes"[..]));
        assert_eq!(blob(Asset::Firmware), Some(&b"firmware"[..]));
        assert_eq!(blob(Asset::UefiVars), Some(&b"vars"[..]));
        assert_eq!(
            blob(Asset::UefiVarsSecureBoot),
            Some(&b"secure boot vars"[..])
        );
        // The bare binary comes back untouched in front of the payload.
        assert_eq!(&image[..bare.len()], &bare[..]);
    }

    #[test]
    fn a_blob_left_out_is_not_embedded() {
        let image = assemble(&elf(), &[("vk-agent", b"agent")]);
        let index = parse(&image).unwrap().unwrap();
        assert_eq!(index.blob(&image, Asset::Kernel), Ok(None));
        assert_eq!(index.blob(&image, Asset::Firmware), Ok(None));
        let empty = assemble(&elf(), &[]);
        assert_eq!(parse(&empty), Ok(Some(Index::default())));
    }

    #[test]
    fn an_empty_blob_is_refused() {
        let image = assemble(&elf(), &[("vmlinux", b"")]);
        assert!(matches!(parse(&image), Err(PayloadError::Malformed(_))));
    }

    #[test]
    fn a_tampered_blob_fails_its_digest() {
        let mut image = assemble(&elf(), &[("vk-agent", b"agent"), ("vmlinux", b"kernel")]);
        image[128 + b"agent".len()] ^= 1;
        let index = parse(&image).unwrap().unwrap();
        assert_eq!(index.blob(&image, Asset::Agent), Ok(Some(&b"agent"[..])));
        assert_eq!(
            index.blob(&image, Asset::Kernel),
            Err(PayloadError::Digest("vmlinux"))
        );
    }

    #[test]
    fn a_trailer_pointing_past_the_file_is_truncated() {
        let past = with_trailer("", elf().len() + 10, 0);
        assert_eq!(parse(&past), Err(PayloadError::Truncated));
        let overflow = with_trailer("", usize::MAX, 1);
        assert_eq!(parse(&overflow), Err(PayloadError::Truncated));
    }

    #[test]
    fn an_entry_reaching_into_the_index_is_truncated() {
        let sum = "0".repeat(64);
        let image = with_index(&format!("vmlinux 128 100 {sum}\n"));
        assert_eq!(parse(&image), Err(PayloadError::Truncated));
        let image = with_index(&format!("vmlinux {} 1 {sum}\n", usize::MAX));
        assert_eq!(parse(&image), Err(PayloadError::Truncated));
    }

    #[test]
    fn a_malformed_payload_is_refused() {
        let sum = "a".repeat(64);
        let cases = [
            // A gap between the index and the trailer.
            with_trailer("x", elf().len(), 0),
            // Index lines that do not parse.
            with_index("vmlinux 0 1\n"),
            with_index(&format!("vmlinux 0 1 {sum}")),
            with_index(&format!("vmlinux -1 1 {sum}\n")),
            with_index(&format!("vmlinux 0 1 {}\n", "A".repeat(64))),
            with_index(&format!("bzImage 0 1 {sum}\n")),
            with_index(&format!("vmlinux 0 1 {sum}\nvmlinux 1 1 {sum}\n")),
            // Trailers whose numbers are not 16 lowercase hex digits, or with no newline.
            [
                elf().as_slice(),
                b"VKPAYLOAD1 000000000000002G 0000000000000000\n",
            ]
            .concat(),
            [
                elf().as_slice(),
                b"VKPAYLOAD1 0000000000000080 0000000000000000x",
            ]
            .concat(),
        ];
        for image in cases {
            assert!(
                matches!(parse(&image), Err(PayloadError::Malformed(_))),
                "{:?}",
                String::from_utf8_lossy(&image[128..])
            );
        }
    }

    /// The format assemble.sh writes is the one `parse` reads.
    #[test]
    fn assemble_sh_writes_what_parse_reads() {
        let dir = crate::qga::tests::TempDir::new("embed-assemble");
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.0.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };
        let bare = write("vk-bare", &elf());
        let agent = write("vk-agent", b"agent bytes");
        let kernel = write("vmlinux", b"kernel bytes");
        let out = dir.0.join("vk");
        let args = |bare: &Path| {
            [
                out.clone().into_os_string(),
                bare.into(),
                format!("vk-agent={}", agent.display()).into(),
                format!("vmlinux={}", kernel.display()).into(),
            ]
        };
        assert!(assemble_sh(&args(&bare)).success());
        let image = std::fs::read(&out).unwrap();
        assert_eq!(
            image,
            assemble(
                &elf(),
                &[("vk-agent", b"agent bytes"), ("vmlinux", b"kernel bytes")]
            )
        );
        // An assembled vk is refused as the bare one, so a payload is never stacked on another.
        let assembled = write("vk-assembled", &image);
        assert!(!assemble_sh(&args(&assembled)).success());
    }

    #[test]
    fn assemble_sh_refuses_bad_arguments() {
        let dir = crate::qga::tests::TempDir::new("embed-assemble-refuses");
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.0.join(name);
            std::fs::write(&p, bytes).unwrap();
            p.display().to_string()
        };
        let bare = write("vk-bare", &elf());
        let blob = write("blob", b"bytes");
        let empty = write("empty", b"");
        let missing = dir.0.join("missing").display().to_string();
        let out = dir.0.join("vk").display().to_string();
        let with = |rest: &[String]| [vec![out.clone(), bare.clone()], rest.to_vec()].concat();
        let cases: Vec<(&str, Vec<String>)> = vec![
            ("no arguments", vec![]),
            ("no bare vk", vec![out.clone()]),
            ("a missing bare vk", vec![out.clone(), missing.clone()]),
            ("an empty bare vk", vec![out.clone(), empty.clone()]),
            ("a blob with no '='", with(&["vmlinux".into()])),
            ("a blob with no name", with(&[format!("={blob}")])),
            ("an unknown name", with(&[format!("bzImage={blob}")])),
            ("a name with a space", with(&[format!("vm linux={blob}")])),
            (
                "a name twice",
                with(&[format!("vmlinux={blob}"), format!("vmlinux={blob}")]),
            ),
            ("a missing blob", with(&[format!("vmlinux={missing}")])),
            ("an empty blob", with(&[format!("vmlinux={empty}")])),
        ];
        for (what, args) in cases {
            assert!(!assemble_sh(&args).success(), "assemble.sh accepted {what}");
            assert!(
                !Path::new(&out).exists(),
                "assemble.sh left an output for {what}"
            );
        }
    }

    /// The child half of `an_assembled_binary_serves_its_payload`, run in an assembled copy of
    /// this test binary; a no-op when run any other way.
    #[test]
    #[ignore = "run by an_assembled_binary_serves_its_payload"]
    fn assembled_child() {
        if std::env::var_os("VK_EMBED_TEST_CHILD").is_none() {
            return;
        }
        assert_eq!(
            Asset::Agent.embedded().unwrap(),
            Some(&b"e2e agent blob"[..])
        );
        assert_eq!(Asset::Kernel.embedded().unwrap(), None);
        let r = resolve(Asset::Agent, None).unwrap();
        assert!(r.is_embedded());
        assert_eq!(std::fs::read(&r.path).unwrap(), b"e2e agent blob");
        println!("VK_EMBED_TEST_CHILD ok");
    }

    /// End to end: assemble.sh's payload on a real linked binary (this one), read back by the
    /// assembled binary from its own /proc/self/exe.
    #[test]
    fn an_assembled_binary_serves_its_payload() {
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Best effort: a leftover directory only takes disk.
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let exe = std::env::current_exe().unwrap();
        // Beside the test binary rather than under /tmp: it is a copy of it, hundreds of MB.
        // Named by host and pid, so a run killed before its cleanup is swept by the next one
        // on the same host, and one still running elsewhere on a shared target/ is left be.
        let parent = exe.parent().unwrap();
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
        let prefix = format!("vk-embed-e2e-{}-", host.trim());
        for entry in std::fs::read_dir(parent).unwrap().flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
                continue;
            };
            if !Path::new("/proc").join(pid).exists() {
                // Best effort, as the cleanup below.
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        let dir = parent.join(format!("{prefix}{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _cleanup = Cleanup(dir.clone());
        let blob = dir.join("vk-agent");
        std::fs::write(&blob, b"e2e agent blob").unwrap();
        let out = dir.join("vk");
        let status = assemble_sh(&[
            out.clone().into_os_string(),
            exe.into_os_string(),
            format!("vk-agent={}", blob.display()).into(),
        ]);
        assert!(status.success());
        // assemble.sh wrote and closed the file in another process, so no fd of ours is open
        // for writing on it (which would make the exec fail with ETXTBSY).
        let child = std::process::Command::new(&out)
            .args([
                "--exact",
                "embed::tests::assembled_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VK_EMBED_TEST_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success() && stdout.contains("VK_EMBED_TEST_CHILD ok"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&child.stderr)
        );
    }

    #[test]
    fn memfd_round_trips_through_its_proc_path() {
        let (file, path, digest) = memfd("blob", b"embedded bytes").unwrap();
        seal(&file).unwrap();
        // Sealed: neither written through the fd held nor reopened for writing, nor resized.
        assert!((&file).write_all(b"x").is_err());
        assert!(file.set_len(1).is_err());
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|mut f| f.write_all(b"x"))
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"embedded bytes");
        assert_eq!(
            digest,
            crate::build::hex(&Sha256::digest(b"embedded bytes"))
        );
    }
}
