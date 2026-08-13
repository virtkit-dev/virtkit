//! How full the guest's writable layer got — the high-water mark of the tmpfs an overlaid
//! share's writes land on.
//!
//! With `VIRTKIT_VIRTIOFS_OVERLAY` (CI's `checkout_overlay`) a job builds on an overlayfs
//! whose upper layer is a guest tmpfs, so every write under the checkout is guest RAM and its
//! capacity — half the VM memory, the kernel's tmpfs default — is the ceiling the build tree
//! has to fit under. Running into it fails the job with `ENOSPC` while every host disk sits
//! empty, and no host counter can say why: tmpfs pages never reach a block device, so the
//! phase's disk figures read as having written nothing at all.
//!
//! So the guest keeps the figure itself. A sampler in PID 1 watches each overlay's tmpfs and
//! publishes the largest it has seen beside it; the host runs `vk-agent fsmark` over the
//! exec channel to read it back for the job's usage line. The mark and not what is left at
//! the end: a phase that unpacks an archive and deletes it would otherwise read as having
//! needed nothing.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use log::warn;

use crate::init::{OVERLAY_ROOT, OVERLAY_RW};

/// How often the sampler asks. Well under the seconds a build takes to write a gigabyte, and
/// one `statvfs` per overlay per pass — the mark itself is only rewritten when it moves, so a
/// job that fills the layer and then sits still costs no writes at all.
const SAMPLE: Duration = Duration::from_millis(500);

/// Where an overlay's mark is published: beside its `rw` tmpfs and never on it, or the file
/// would be part of the figure it carries.
const MARK: &str = "mark";

/// Bytes used and bytes total on the filesystem mounted at `path`. `None` where it cannot be
/// asked — the mount is gone, or the path holds an interior NUL.
fn fs_usage(path: &Path) -> Option<(u64, u64)> {
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: statvfs fills the whole struct through the pointer, and only on success.
    let vfs = unsafe {
        (libc::statvfs(c_path.as_ptr(), buf.as_mut_ptr()) == 0).then(|| buf.assume_init())
    }?;
    // `f_frsize` is the unit `f_blocks` counts in (a page, for tmpfs). Checked because these
    // are figures the kernel filled in: nothing here is worth a panic or a wrapped total.
    let total = vfs.f_blocks.checked_mul(vfs.f_frsize)?;
    let used = vfs
        .f_blocks
        .checked_sub(vfs.f_bfree)?
        .checked_mul(vfs.f_frsize)?;
    Some((used, total))
}

/// The private directory of every overlaid share in this guest, one per tag. Empty where
/// nothing is overlaid, which is every guest but a CI job on an overlaid checkout.
fn overlays() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(OVERLAY_ROOT) else {
        return Vec::new(); // no overlaid share in this guest
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|base| base.join(OVERLAY_RW).is_dir())
        .collect()
}

/// The mark published for `base`, as `(used, total)`. `None` until the sampler has written
/// one, or where the file is not the two figures [`publish`] writes.
fn published(base: &Path) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(base.join(MARK)).ok()?;
    let mut figures = text.split_whitespace();
    let used = figures.next()?.parse().ok()?;
    let total = figures.next()?.parse().ok()?;
    Some((used, total))
}

/// Record a new high-water mark for `base`. Best-effort: a mark that fails to land leaves the
/// previous one, and the next pass over a still-growing layer writes it again.
///
/// Truncated in place rather than staged and renamed: the file is two small figures written by
/// one thread, and a reader that catches it mid-write sees a short line it already treats as
/// no mark at all. Its directory is root-owned, which is what makes reopening the path safe.
fn publish(base: &Path, used: u64, total: u64) {
    use std::io::Write;
    let path = base.join(MARK);
    // World-readable: the host reads the mark back through `vk-agent fsmark`, which runs as
    // the job's own user and not as the root that wrote it.
    let written = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&path)
        .and_then(|mut f| f.write_all(format!("{used} {total}\n").as_bytes()));
    if let Err(e) = written {
        warn!("vk-agent fsmark: publishing {}: {e}", path.display());
    }
}

/// One pass over every overlay, publishing each layer that has grown past its mark.
fn sample() {
    for base in overlays() {
        let Some((used, total)) = fs_usage(&base.join(OVERLAY_RW)) else {
            continue; // the mount went away: nothing to mark
        };
        if published(&base).is_some_and(|(mark, _)| mark >= used) {
            continue;
        }
        publish(&base, used, total);
    }
}

/// The mark of one overlay, the live reading folded in: the sampler may not have run since the
/// layer last grew, and a live reading is the only source of the capacity before any mark has
/// been published at all.
fn mark_of(base: &Path) -> Option<(u64, u64)> {
    match (fs_usage(&base.join(OVERLAY_RW)), published(base)) {
        (Some((live, total)), mark) => Some((live.max(mark.map_or(0, |(m, _)| m)), total)),
        (None, mark) => mark,
    }
}

/// Watch this guest's overlay layers for the life of the VM, keeping each one's high-water
/// mark. A no-op where nothing is overlaid — no layer to watch is no thread to run it.
///
/// Called after PID 1's last fork, deliberately: `fork` in a process with threads clones only
/// the calling one, so a sampler started earlier would be holding the allocator's lock in a
/// child that must still `exec`.
pub(crate) fn watch() {
    if overlays().is_empty() {
        return;
    }
    // Detached: the mark is published as it moves rather than returned, so there is nothing to
    // join — the VM is one-shot and the thread ends with it.
    let sampler = std::thread::Builder::new().name("fsmark".into()).spawn(|| {
        loop {
            sample();
            std::thread::sleep(SAMPLE);
        }
    });
    match sampler {
        Ok(_) => log::info!("vk-agent init: watching the overlay layers"),
        // The job still runs; only its usage line goes without the figure.
        Err(e) => warn!("vk-agent init: starting the fsmark sampler failed: {e}"),
    }
}

/// CLI entry for `vk-agent fsmark`, which the host runs in the guest over the exec channel:
/// print `<used> <total>` in bytes for the writable layer holding the most.
///
/// One figure is what a job's usage line has room for, and of a guest with several overlaid
/// shares the fullest layer is the one that would have failed the job. Exits non-zero where
/// there is no overlay to report, which the host reads as unmeasured rather than as zero.
pub fn main(args: &[String]) -> i32 {
    if !args.is_empty() {
        eprintln!("usage: vk-agent fsmark");
        return 2;
    }
    let Some((used, total)) = overlays()
        .iter()
        .filter_map(|base| mark_of(base))
        .max_by_key(|&(used, _)| used)
    else {
        eprintln!("fsmark: no overlaid share in this guest");
        return 1;
    };
    println!("{used} {total}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guest_with_no_overlay_root_has_no_layers_to_watch() {
        // The common case — every guest that is not a CI job on an overlaid checkout. It must
        // read as "nothing to report" rather than fail: `watch` then starts no thread, and
        // `main` exits non-zero so the host records the figure as unmeasured.
        assert!(overlays().is_empty() || Path::new(OVERLAY_ROOT).is_dir());
    }

    #[test]
    fn fs_usage_reads_a_live_filesystem() {
        // Against /proc, which is mounted wherever the tests run: a pseudo-filesystem reports
        // zero blocks, so this pins the syscall plumbing (and the checked arithmetic under it)
        // without depending on how full any real filesystem happens to be.
        let (used, total) = fs_usage(Path::new("/proc")).expect("statvfs /proc");
        assert!(used <= total, "used {used} exceeds total {total}");
    }

    #[test]
    fn fs_usage_declines_a_path_that_cannot_be_stated() {
        assert_eq!(
            fs_usage(Path::new("/vk-agent-nonexistent-fsmark-target")),
            None
        );
    }

    #[test]
    fn a_published_mark_reads_back_as_the_two_figures_written() {
        let dir = tempdir("published");
        publish(&dir, 9_000, 10_000);
        assert_eq!(published(&dir), Some((9_000, 10_000)));
    }

    #[test]
    fn a_mark_that_is_not_two_figures_is_no_mark() {
        // A reader that accepted a short line could not tell a file caught mid-write from a
        // whole one, so anything but the two figures reads as "not published yet".
        let dir = tempdir("torn");
        for text in ["", "9000", "9000 ", "nine 10000\n"] {
            std::fs::write(dir.join(MARK), text).unwrap();
            assert_eq!(published(&dir), None, "accepted {text:?}");
        }
    }

    #[test]
    fn the_mark_holds_the_high_water_and_not_the_last_reading() {
        // What the whole module exists for: a layer that shrinks back keeps the figure it
        // reached, since that is the size the job actually needed.
        let dir = tempdir("high-water");
        publish(&dir, 9_000, 10_000);
        assert!(published(&dir).is_some_and(|(mark, _)| mark >= 9_000));
        publish(&dir, 1_000, 10_000);
        // `publish` itself always writes: it is `sample` that holds the mark, by declining to
        // call it for a reading below the one already there.
        assert_eq!(published(&dir), Some((1_000, 10_000)));
    }

    /// A private directory for one test, named after the test and the pid so two suites on the
    /// same host never share a path and pull each other's tree out mid-run. Removed first all
    /// the same, so a recycled pid starts clean instead of on an older run's leftovers.
    fn tempdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vk-agent-fsmark-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
