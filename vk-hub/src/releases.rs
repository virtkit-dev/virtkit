//! The `vk` binaries the hub holds for its nodes, in `<data_dir>/releases/`, each a file named
//! by its sha256 beside its row in the database.
//!
//! **The hub never runs one.** It holds the database, its TLS key and every node's pinned
//! key, so a binary it was handed is only read: hashed, checked to be an x86-64 ELF, and
//! checked to carry the version the operator states as a string of its own. Running it is
//! left to the node.

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

/// Where release `sha256`'s binary is.
pub fn path(dir: &Path, sha256: &str) -> PathBuf {
    dir.join(sha256)
}

/// Copy the binary at `from` into the hub as `version`, audited as `actor`'s. Its sha256
/// names it; the file is published whole, by rename, before the row that points at it is
/// written.
pub fn add(hub: &Hub, actor: &str, from: &Path, version: &str) -> Result<Release> {
    check_version(version)?;
    let dir = hub.releases_dir()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
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
    let tmp = dir.join(format!(".add-{}.tmp", crate::random_hex(8)?));
    let copied = copy_checked(&mut source, &tmp, version)
        .with_context(|| format!("reading {} as vk {version}", from.display()));
    let (sha256, size) = match copied {
        Ok(v) => v,
        Err(e) => {
            // Best effort: the error is what the operator needs, not a failed unlink.
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    let row = ReleaseRow {
        version: version.to_string(),
        size,
        added_at: crate::now_secs(),
        added_by: actor.to_string(),
    };
    // From here to the row, one add or remove at a time: a remove between this add's rename
    // and its row would leave a row naming no file.
    let _held = hub.releases_lock();
    let dest = path(dir, &sha256);
    let existing = hub.db.release(&sha256)?;
    if let Some(existing) = &existing {
        if existing.version != row.version {
            let _ = std::fs::remove_file(&tmp);
            bail!(
                "release {sha256} is already held, as vk {}",
                existing.version
            );
        }
        // The same bytes as the same release: an add retried after its answer was lost.
        if std::fs::metadata(&dest).is_ok_and(|m| m.is_file() && m.len() == existing.size) {
            let _ = std::fs::remove_file(&tmp);
            return Ok(Release {
                sha256,
                row: existing.clone(),
            });
        }
        // Its file is missing or the wrong size: these bytes restore it, under the row already
        // there.
    }
    if let Err(e) = std::fs::rename(&tmp, &dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("publishing {}", dest.display()));
    }
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
        let file = path(hub.releases_dir()?, sha256);
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", file.display())),
        }
    }
    Ok(removed)
}

/// Copy `source` to a new private file at `tmp` and flush it to disk. Check that it is an
/// x86-64 ELF no larger than [`MAX_RELEASE`] and contains `version` as a standalone string
/// while copying. Return its hex sha256 and size.
fn copy_checked(source: &mut std::fs::File, tmp: &Path, version: &str) -> Result<(String, u64)> {
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
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
        out.write_all(chunk)
            .with_context(|| format!("writing {}", tmp.display()))?;
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
    out.sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))?;
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
