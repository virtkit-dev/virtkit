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
//! A file whose last bytes are not a trailer has no payload. One that has a trailer is held
//! to it: an index that is out of bounds or does not parse, or a blob that fails its digest, is
//! an error rather than a quiet fall back to the on-disk defaults. Each blob's digest is
//! checked once per process, the first time it is used.
//!
//! An embedded asset is materialised into an anonymous (CLOEXEC) memfd rather than a
//! temp file, so nothing touches disk. The kernel is handed to the spawned VMM by
//! clearing CLOEXEC on its fd for that one spawn (`run::spawn_vmm`), which then opens
//! `/proc/self/fd/<n>`; the agent is only ever reopened in this process by the packer.
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
    /// embedded copy.
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
    /// damaged or this blob fails its digest.
    pub fn embedded(self) -> Result<Option<&'static [u8]>> {
        static BLOBS: [OnceLock<Lookup>; ASSETS.len()] = [const { OnceLock::new() }; ASSETS.len()];
        let Some(cell) = BLOBS.get(self.index()) else {
            return Ok(None);
        };
        cell.get_or_init(|| {
            let Some(payload) = own_payload()? else {
                return Ok(None);
            };
            payload
                .index
                .blob(payload.image, self)
                .map_err(|e| format!("this vk's embedded payload is damaged: {e}"))
        })
        .clone()
        .map_err(anyhow::Error::msg)
    }
}

/// What [`Asset::embedded`] found for one asset, kept for the rest of the process.
type Lookup = Result<Option<&'static [u8]>, String>;

/// The trailer's leading bytes, which also tell a payload's presence.
const MAGIC: &[u8] = b"VKPAYLOAD1 ";
/// `MAGIC`, two 16-digit hex numbers, a space between them and a newline.
const TRAILER_LEN: usize = MAGIC.len() + 16 + 1 + 16 + 1;

/// Why a payload cannot be read.
#[derive(Debug, PartialEq, Eq)]
enum PayloadError {
    /// The trailer or an index entry points past the bytes there are.
    Truncated,
    /// The trailer or an index line does not parse.
    Malformed(String),
    /// A blob's bytes do not hash to the digest the index records.
    Digest(&'static str),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::Truncated => write!(f, "it points past the end of the file"),
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
    /// `asset`'s bytes in `image`, checked against their digest; `None` when not carried.
    fn blob<'a>(&self, image: &'a [u8], asset: Asset) -> Result<Option<&'a [u8]>, PayloadError> {
        let Some(Some(e)) = self.entries.get(asset.index()) else {
            return Ok(None);
        };
        let end = e
            .offset
            .checked_add(e.size)
            .ok_or(PayloadError::Truncated)?;
        let bytes = image.get(e.offset..end).ok_or(PayloadError::Truncated)?;
        if crate::build::hex(&Sha256::digest(bytes)) != e.sha256 {
            return Err(PayloadError::Digest(asset.filename()));
        }
        Ok(Some(bytes))
    }
}

/// The payload index of `image`, a whole `vk` file; `None` when it carries no payload.
fn parse(image: &[u8]) -> Result<Option<Index>, PayloadError> {
    let Some(trailer_at) = image.len().checked_sub(TRAILER_LEN) else {
        return Ok(None);
    };
    let trailer = image.get(trailer_at..).unwrap_or_default();
    let Some(fields) = trailer.strip_prefix(MAGIC) else {
        return Ok(None);
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
        let slot = index
            .entries
            .get_mut(asset.index())
            .ok_or(PayloadError::Truncated)?;
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
            let image = map_own_executable().map_err(|e| format!("mapping /proc/self/exe: {e}"))?;
            match parse(image) {
                Ok(index) => Ok(index.map(|index| Payload { image, index })),
                Err(e) => Err(format!("this vk's embedded payload is damaged: {e}")),
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
    // SAFETY: a fresh read-only private mapping of a file we hold open. It is the running
    // executable, mapped as its own code is: whatever rewrote it in place would change the
    // code under the process just the same.
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
    if let Some(bytes) = asset.embedded()? {
        let (file, path) = memfd(asset.filename(), bytes)?;
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
/// `/proc/self/fd/<n>` path. The fd is `CLOEXEC`, so idle helper children never inherit
/// it; the kernel is handed to the VMM by clearing `CLOEXEC` on its fd only in that
/// spawn (see `run::spawn_vmm`), and the agent is only ever reopened in-process. The
/// caller holds the returned `File` to keep the fd open.
fn memfd(name: &str, bytes: &[u8]) -> Result<(File, PathBuf)> {
    let cname = std::ffi::CString::new(name).expect("asset name has no interior nul");
    // SAFETY: `cname` is a valid C string; memfd_create returns an owned fd or -1/errno.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("memfd_create");
    }
    // SAFETY: `fd` was just created and is owned by us.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .with_context(|| format!("writing embedded {name} to a memfd"))?;
    Ok((file, PathBuf::from(format!("/proc/self/fd/{fd}"))))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut out = BARE.to_vec();
        out.extend_from_slice(index.as_bytes());
        out.extend_from_slice(format!("VKPAYLOAD1 {at:016x} {len:016x}\n").as_bytes());
        out
    }

    /// `index` after a bare binary, with a trailer that frames it exactly.
    fn with_index(index: &str) -> Vec<u8> {
        with_trailer(index, BARE.len(), index.len())
    }

    const BARE: &[u8] = b"\x7fELF not really an executable\0\0";

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
    fn no_trailer_is_no_payload() {
        assert_eq!(parse(b""), Ok(None));
        assert_eq!(parse(BARE), Ok(None));
        // A payload cut short loses its trailer and reads as none: the digest a release
        // publishes for the whole file is what catches that.
        let whole = assemble(BARE, &[("vk-agent", b"agent")]);
        assert_eq!(parse(&whole[..whole.len() - 1]), Ok(None));
    }

    #[test]
    fn every_blob_is_found_and_checked() {
        let image = assemble(
            BARE,
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
        assert_eq!(&image[..BARE.len()], BARE);
    }

    #[test]
    fn a_blob_left_out_is_not_embedded() {
        let image = assemble(BARE, &[("vk-agent", b"agent")]);
        let index = parse(&image).unwrap().unwrap();
        assert_eq!(index.blob(&image, Asset::Kernel), Ok(None));
        assert_eq!(index.blob(&image, Asset::Firmware), Ok(None));
        let empty = assemble(BARE, &[]);
        assert_eq!(parse(&empty), Ok(Some(Index::default())));
    }

    #[test]
    fn an_empty_blob_is_refused() {
        let image = assemble(BARE, &[("vmlinux", b"")]);
        assert!(matches!(parse(&image), Err(PayloadError::Malformed(_))));
    }

    #[test]
    fn a_tampered_blob_fails_its_digest() {
        let mut image = assemble(BARE, &[("vk-agent", b"agent"), ("vmlinux", b"kernel")]);
        image[BARE.len() + b"agent".len()] ^= 1;
        let index = parse(&image).unwrap().unwrap();
        assert_eq!(index.blob(&image, Asset::Agent), Ok(Some(&b"agent"[..])));
        assert_eq!(
            index.blob(&image, Asset::Kernel),
            Err(PayloadError::Digest("vmlinux"))
        );
    }

    #[test]
    fn a_trailer_pointing_past_the_file_is_truncated() {
        let past = with_trailer("", BARE.len() + 10, 0);
        assert_eq!(parse(&past), Err(PayloadError::Truncated));
        let overflow = with_trailer("", usize::MAX, 1);
        assert_eq!(parse(&overflow), Err(PayloadError::Truncated));
    }

    #[test]
    fn an_entry_reaching_into_the_index_is_truncated() {
        let sum = "0".repeat(64);
        let image = with_index(&format!("vmlinux {} 100 {sum}\n", BARE.len()));
        assert_eq!(parse(&image), Err(PayloadError::Truncated));
        let image = with_index(&format!("vmlinux {} 1 {sum}\n", usize::MAX));
        assert_eq!(parse(&image), Err(PayloadError::Truncated));
    }

    #[test]
    fn a_malformed_payload_is_refused() {
        let sum = "a".repeat(64);
        let cases = [
            // A gap between the index and the trailer.
            with_trailer("x", BARE.len(), 0),
            // Index lines that do not parse.
            with_index("vmlinux 0 1\n"),
            with_index(&format!("vmlinux 0 1 {sum}")),
            with_index(&format!("vmlinux -1 1 {sum}\n")),
            with_index(&format!("vmlinux 0 1 {}\n", "A".repeat(64))),
            with_index(&format!("bzImage 0 1 {sum}\n")),
            with_index(&format!("vmlinux 0 1 {sum}\nvmlinux 1 1 {sum}\n")),
            // Trailers whose numbers are not 16 lowercase hex digits, or with no newline.
            [
                BARE,
                b"VKPAYLOAD1 000000000000002G 0000000000000000\n".as_slice(),
            ]
            .concat(),
            [
                BARE,
                b"VKPAYLOAD1 0000000000000020 0000000000000000x".as_slice(),
            ]
            .concat(),
        ];
        for image in cases {
            assert!(
                matches!(parse(&image), Err(PayloadError::Malformed(_))),
                "{:?}",
                String::from_utf8_lossy(&image[BARE.len()..])
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
        let bare = write("vk-bare", BARE);
        let agent = write("vk-agent", b"agent bytes");
        let kernel = write("vmlinux", b"kernel bytes");
        let out = dir.0.join("vk");
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../assemble.sh");
        let run = |bare: &Path| {
            std::process::Command::new("sh")
                .arg(&script)
                .arg(&out)
                .arg(bare)
                .arg(format!("vk-agent={}", agent.display()))
                .arg(format!("vmlinux={}", kernel.display()))
                .output()
                .unwrap()
                .status
        };
        assert!(run(&bare).success());
        let image = std::fs::read(&out).unwrap();
        assert_eq!(
            image,
            assemble(
                BARE,
                &[("vk-agent", b"agent bytes"), ("vmlinux", b"kernel bytes")]
            )
        );
        // An assembled vk is refused as the bare one, so a payload is never stacked on another.
        let assembled = write("vk-assembled", &image);
        assert!(!run(&assembled).success());
    }

    #[test]
    fn memfd_round_trips_through_its_proc_path() {
        let (_file, path) = memfd("blob", b"embedded bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"embedded bytes");
    }
}
