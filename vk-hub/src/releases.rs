//! The `vk` binaries the hub holds for its nodes, in `<data_dir>/releases/`, each a file named
//! by its sha256 beside its row in the database.
//!
//! **The hub never runs one.** It holds the database, its TLS key and every node's pinned
//! key, so a binary it was handed is only read: hashed, checked to be an x86-64 ELF, and
//! checked to carry the version the operator states as a string of its own. Running it is
//! left to the node.
//!
//! **Signature verification belongs to the node.** The hub stores optional signatures made
//! offline with `vk release-key sign` and forwards them. Each node verifies them against
//! its configured keys; the hub holds no trusted release key.
//!
//! A binary reaches the hub two ways, both held to the same checks: `release add` copies a
//! file on the hub's host ([`add`]); `release fetch` downloads one from GitHub
//! ([`crate::fetch`]) into a [`Staged`] file here that [`adopt`] takes in.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::server::Hub;
use crate::store::{Release, ReleaseRow};

/// The largest binary the hub takes: a `vk` is a few hundred megabytes at most, even
/// unstripped.
pub const MAX_RELEASE: u64 = 1 << 30;

/// The longest version string: a release number with a suffix, not prose.
const MAX_VERSION: usize = 64;

/// `version` checked to look like one: what a node's smoke test looks for as a word of the
/// binary's `--version`, and what the audit log and the pages print.
pub fn check_version(version: &str) -> Result<()> {
    let shaped = !version.is_empty()
        && version.len() <= MAX_VERSION
        && version.starts_with(|c: char| c.is_ascii_alphanumeric())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'));
    if !shaped {
        bail!("{version:?} is not a version: letters, digits and . _ - + only");
    }
    Ok(())
}

/// `signature`, trimmed, checked to be what `vk release-key sign` prints: an ed25519
/// signature in base64. Whether it verifies is each node's to judge, against its own keys.
fn check_signature(signature: &str) -> Result<String> {
    let signature = signature.trim();
    match vk_hub_proto::from_base64(signature) {
        Some(sig) if sig.len() == vk_hub_proto::SIGNATURE_LEN => Ok(signature.to_string()),
        _ => bail!(
            "the signature is not an ed25519 signature in base64, as `vk release-key sign` \
             prints one"
        ),
    }
}

/// Where release `sha256`'s binary is.
pub fn path(dir: &Path, sha256: &str) -> PathBuf {
    dir.join(sha256)
}

/// The releases directory, created private if it is not there yet.
fn releases_dir(hub: &Hub) -> Result<&Path> {
    let dir = hub.releases_dir()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// A file in the releases directory that is not a release yet: removed when dropped, unless
/// [`publish`] has renamed it into place. A drop is what cleans up after a failure anywhere,
/// a download given up included.
pub struct Staged {
    path: PathBuf,
}

impl Staged {
    /// A new name in the releases directory for a file still to arrive, `.<what>-<random>.tmp`
    /// — nothing is created yet. Names starting with `.` are never a release's.
    pub fn name(hub: &Hub, what: &str) -> Result<Staged> {
        let dir = releases_dir(hub)?;
        Ok(Staged {
            path: dir.join(format!(".{what}-{}.tmp", crate::random_hex(8)?)),
        })
    }

    /// [`Staged::name`], created private and empty, refusing anything already there.
    pub fn create(hub: &Hub, what: &str) -> Result<(Staged, std::fs::File)> {
        let staged = Self::name(hub, what)?;
        let file = create_private(&staged.path)?;
        Ok((staged, file))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Best effort: the error being reported is what matters, not a failed unlink. Gone
        // already is the published case.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Remove the files a hub that stopped mid-add or mid-fetch left in `dir`: every name starting
/// with `.`, which no release has. Run as the hub starts, before anything could be staging one.
pub fn sweep(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".")
            && entry.file_type().is_ok_and(|t| t.is_file())
        {
            // Best effort, as the drop above.
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn create_private(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// Copy the binary at `from` into the hub as `version`, with `signature`, audited as
/// `actor`'s. Its sha256 names it; the file is published whole, by rename, before the row
/// that points at it is written.
pub fn add(
    hub: &Hub,
    actor: &str,
    from: &Path,
    version: &str,
    signature: Option<String>,
) -> Result<Release> {
    check_version(version)?;
    let signature = signature.map(|s| check_signature(&s)).transpose()?;
    releases_dir(hub)?;
    // Non-blocking, so a FIFO opens at once, to be refused below as not a regular file; it
    // changes nothing for a regular file's reads.
    let mut source = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(from)
        .with_context(|| format!("opening {}", from.display()))?;
    let meta = source
        .metadata()
        .with_context(|| format!("reading {}", from.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", from.display());
    }
    if meta.len() > MAX_RELEASE {
        bail!(
            "{} is {} bytes, past the {MAX_RELEASE} a release may be",
            from.display(),
            meta.len()
        );
    }
    let (staged, mut out) = Staged::create(hub, "add")?;
    let (sha256, size) = copy_checked(&mut source, Some((&mut out, staged.path())), version)
        .with_context(|| format!("reading {} as vk {version}", from.display()))?;
    drop(out);
    publish(hub, actor, staged, &sha256, size, version, signature)
}

/// Take the binary `staged` holds — downloaded into it, and closed — into the hub as `version`,
/// with `signature`, audited as `actor`'s: the same checks as [`add`], read in place, and the
/// file renamed to its sha256.
pub fn adopt(
    hub: &Hub,
    actor: &str,
    staged: Staged,
    version: &str,
    signature: Option<String>,
) -> Result<Release> {
    check_version(version)?;
    let signature = signature.map(|s| check_signature(&s)).transpose()?;
    // Not through a link: the directory is the hub's own, but nothing here needs one.
    let mut source = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(staged.path())
        .with_context(|| format!("opening {}", staged.path().display()))?;
    let (sha256, size) = copy_checked(&mut source, None, version)
        .with_context(|| format!("reading the binary as vk {version}"))?;
    drop(source);
    publish(hub, actor, staged, &sha256, size, version, signature)
}

/// Rename `staged`, checked to hash to `sha256`, into place as release `sha256`, and record
/// it.
fn publish(
    hub: &Hub,
    actor: &str,
    staged: Staged,
    sha256: &str,
    size: u64,
    version: &str,
    signature: Option<String>,
) -> Result<Release> {
    let dir = hub.releases_dir()?;
    let sha256 = sha256.to_string();
    let row = ReleaseRow {
        version: version.to_string(),
        size,
        signature,
        added_at: crate::now_secs(),
        added_by: actor.to_string(),
    };
    // From here to the row, one add or remove at a time: a remove between this add's rename
    // and its row would leave a row naming no file.
    let _held = hub.releases_lock();
    let dest = path(dir, &sha256);
    let existing = hub.db.release(&sha256)?;
    if let Some(existing) = &existing {
        if existing.version != row.version || existing.signature != row.signature {
            bail!(
                "release {sha256} is already held, as vk {}{}",
                existing.version,
                if existing.signature == row.signature {
                    ""
                } else {
                    " with another signature"
                }
            );
        }
        // The same bytes as the same release: an add retried after its answer was lost.
        if std::fs::metadata(&dest).is_ok_and(|m| m.is_file() && m.len() == existing.size) {
            return Ok(Release {
                sha256,
                row: existing.clone(),
            });
        }
        // Its file is missing or the wrong size: these bytes restore it, under the row already
        // there.
    }
    std::fs::rename(staged.path(), &dest)
        .with_context(|| format!("publishing {}", dest.display()))?;
    if let Ok(d) = std::fs::File::open(dir) {
        // Best effort, as vk-selfupdate's publish: the rename has happened.
        let _ = d.sync_all();
    }
    if let Some(existing) = existing {
        eprintln!(
            "vk-hub: {actor} restored the binary of release {}",
            crate::store::short(&sha256)
        );
        return Ok(Release {
            sha256,
            row: existing,
        });
    }
    // A file with no row is harmless — nothing serves it — and the next add of the same
    // bytes replaces it.
    hub.db.add_release(&sha256, &row, actor)?;
    hub.touch();
    eprintln!(
        "vk-hub: {actor} added release {} as vk {version}",
        crate::store::short(&sha256)
    );
    Ok(Release { sha256, row })
}

/// Forget release `sha256` and delete its binary. `Ok(false)` when there was none.
pub fn remove(hub: &Hub, actor: &str, sha256: &str) -> Result<bool> {
    let _held = hub.releases_lock();
    let removed = hub.db.remove_release(sha256, actor, crate::now_secs())?;
    if removed {
        hub.touch();
        let file = path(hub.releases_dir()?, sha256);
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", file.display())),
        }
    }
    Ok(removed)
}

/// Read `source` to its end, checking that it is an x86-64 ELF no larger than [`MAX_RELEASE`]
/// and contains `version` as a standalone string; when `out` is given, copy it there and flush
/// it to disk. Return its hex sha256 and size.
fn copy_checked(
    source: &mut std::fs::File,
    mut out: Option<(&mut std::fs::File, &Path)>,
    version: &str,
) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut finder = Finder::new(version.as_bytes());
    let mut header = Vec::with_capacity(ELF_HEADER);
    let mut size = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = source.read(&mut buf).context("reading")?;
        let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else {
            break;
        };
        size = size.saturating_add(n as u64);
        if size > MAX_RELEASE {
            bail!("it grew past the {MAX_RELEASE} bytes a release may be");
        }
        if header.len() < ELF_HEADER {
            let want = ELF_HEADER - header.len();
            header.extend_from_slice(chunk.get(..want.min(chunk.len())).unwrap_or(chunk));
        }
        hasher.update(chunk);
        finder.feed(chunk);
        if let Some((out, tmp)) = &mut out {
            out.write_all(chunk)
                .with_context(|| format!("writing {}", tmp.display()))?;
        }
    }
    finder.finish();
    if !is_x86_64_elf(&header) {
        bail!("it is not an x86-64 ELF executable, as a vk release is");
    }
    if !finder.found {
        bail!(
            "the version {version:?} appears nowhere in it as a string of its own; check \
             --version against what the binary's `--version` prints"
        );
    }
    if let Some((out, tmp)) = out {
        out.sync_all()
            .with_context(|| format!("flushing {}", tmp.display()))?;
    }
    Ok((vk_hub_proto::to_hex(&hasher.finalize()), size))
}

/// Bytes of an ELF header [`is_x86_64_elf`] reads.
const ELF_HEADER: usize = 20;

/// `\x7fELF`, 64-bit, little-endian, and `e_machine` x86-64.
fn is_x86_64_elf(header: &[u8]) -> bool {
    header.len() >= ELF_HEADER
        && header.starts_with(b"\x7fELF")
        && header.get(4) == Some(&2)
        && header.get(5) == Some(&1)
        && header.get(18..20) == Some(&[0x3e, 0][..])
}

/// A streaming search for `needle` as a standalone string: adjacent bytes, if any, must not
/// be version characters, so `0.8.1` does not match inside `10.8.10`.
struct Finder {
    needle: Vec<u8>,
    /// The tail of what was fed, long enough to hold a match with its byte before and after.
    window: Vec<u8>,
    found: bool,
}

impl Finder {
    fn new(needle: &[u8]) -> Self {
        Finder {
            needle: needle.to_vec(),
            // A start-of-input sentinel: no byte before the first is a version byte.
            window: vec![0],
            found: false,
        }
    }

    /// End the input with a sentinel that cannot occur in a version.
    fn finish(&mut self) {
        self.feed(b"\0");
    }

    fn feed(&mut self, chunk: &[u8]) {
        if self.found || self.needle.is_empty() {
            return;
        }
        self.window.extend_from_slice(chunk);
        let n = self.needle.len();
        let part = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+');
        // A match needs the byte after it to judge, so one at the end of the window waits
        // for more input — or for [`Finder::finish`].
        let standalone = |w: &[u8]| {
            w.get(1..=n) == Some(&self.needle[..])
                && w.first().is_some_and(|&b| !part(b))
                && w.last().is_some_and(|&b| !part(b))
        };
        if self.window.windows(n + 2).any(standalone) {
            self.found = true;
            return;
        }
        let keep = n + 1;
        if self.window.len() > keep {
            let cut = self.window.len() - keep;
            self.window.drain(..cut);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(needle: &str, chunks: &[&[u8]]) -> bool {
        let mut f = Finder::new(needle.as_bytes());
        for c in chunks {
            f.feed(c);
        }
        f.finish();
        f.found
    }

    #[test]
    fn a_version_is_found_only_as_a_string_of_its_own() {
        assert!(found("0.84.0", &[b"vk-driver 0.84.0 (abc)"]));
        assert!(found("0.84.0", &[b"\x000.8", b"4.0\x00"]));
        assert!(found("0.84.0", &[b"0.84.0"]));
        assert!(!found("0.84.0", &[b"10.84.0"]));
        assert!(!found("0.84.0", &[b"0.84.00"]));
        assert!(!found("0.84.0", &[b"0.84.0-rc1"]));
        assert!(!found("0.84.0", &[b"nothing here"]));
    }

    #[test]
    fn versions_are_shaped_like_versions() {
        for ok in ["0.84.0", "0.84.0-rc.1", "1.0+build5"] {
            check_version(ok).unwrap();
        }
        for bad in ["", ".1", "0.8 1", "0.8/1", "-x", &"9".repeat(65)] {
            assert!(check_version(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_an_x86_64_elf_passes() {
        let mut header = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
        assert!(is_x86_64_elf(&header));
        header[18] = 0xb7; // aarch64
        assert!(!is_x86_64_elf(&header));
        assert!(!is_x86_64_elf(b"#!/bin/sh\n"));
    }
}
