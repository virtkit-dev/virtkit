//! Tracks a guest's peak memory demand for build-stage sizing.
//!
//! Host-side VMM RSS includes faulted guest page cache and can overstate demand after large
//! reads. The guest instead measures `MemTotal - MemAvailable`, excluding reclaimable memory.
//!
//! As in [`crate::fsmark`], a PID 1 sampler publishes the largest reading for the host to read
//! through `vk-agent memmark` before shutdown.
//!
//! The sampler runs only with `VIRTKIT_MEMMARK=1`, which the build backend sets on stage
//! guests. `vk run`, CI job, and development guests incur no cost for a figure nothing reads.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use log::warn;

/// How often the sampler reads the demand. Two orders of magnitude under the seconds a step
/// takes to fault a gigabyte in, as the host's own sampler is: a demand that rises and falls
/// entirely between two passes is missed, and a stage sized from a figure that low is a stage
/// that gets killed out of memory. Two small reads per pass — the demand and the mark — and
/// the mark is only rewritten when a reading passes it, so a guest that peaks early and then
/// sits still costs no writes at all.
const SAMPLE: Duration = Duration::from_millis(100);

/// The mark is a leaf on the agent-mounted `/run` tmpfs, outside the stage image.
///
/// Using a leaf avoids recreating an image-provided directory with its mode and owner, which
/// could give a world-writable directory space for a symlink attack on PID 1. An image-provided
/// directory at this path instead makes the exclusive create fail and leaves the stage
/// unmeasured.
const MARK: &str = "/run/vk-memmark";

const MEMINFO: &str = "/proc/meminfo";

/// Parse `(demand, total)` in bytes from `/proc/meminfo`. Demand is
/// `MemTotal - MemAvailable`, excluding reclaimable memory. Return `None` if either field is
/// absent rather than substituting `MemFree` for demand.
fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let field = |name: &str| {
        text.lines().find_map(|l| {
            let kb: u64 = l
                .strip_prefix(name)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            kb.checked_mul(1024)
        })
    };
    let (total, available) = (field("MemTotal:")?, field("MemAvailable:")?);
    Some((total.saturating_sub(available), total))
}

/// This guest's demand right now, as `(demand, total)` in bytes.
fn demand() -> Option<(u64, u64)> {
    parse_meminfo(&std::fs::read_to_string(MEMINFO).ok()?)
}

/// The published `(demand, total)`, or `None` until a valid mark exists.
fn published(path: &Path) -> Option<(u64, u64)> {
    crate::mark::parse(&std::fs::read_to_string(path).ok()?)
}

/// The sampler's mark. Keeping its descriptor open prevents a detached `/run` mount from
/// redirecting updates to an image-provided file at the same path.
struct Mark {
    file: File,
    used: u64,
}

impl Mark {
    /// Replace the figures through the original descriptor. A mid-write read is invalid rather
    /// than a partial measurement.
    fn publish(&mut self, used: u64, total: u64) -> io::Result<()> {
        self.file.rewind()?;
        self.file.set_len(0)?;
        self.file
            .write_all(crate::mark::render(used, total).as_bytes())?;
        self.used = used;
        Ok(())
    }
}

/// The open parent directory and leaf name. Descriptor-relative creation and removal keep using
/// the original directory even if another mount later covers `/run`.
struct MarkDir {
    dir: OwnedFd,
    name: CString,
}

impl MarkDir {
    /// Open the mark's parent without following a final symlink; failure leaves it unmeasured.
    ///
    /// The descriptor is only an `*at()` anchor, so [`vk_fs::open_dir_nofollow`] uses `O_PATH`.
    /// The agent mounts `/run` itself; a symlink there indicates an invalid layout.
    fn open(path: &Path) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("the mark path names no file"))?;
        let dir = vk_fs::open_dir_nofollow(path.parent().unwrap_or(Path::new("/")))
            .map_err(|e| io::Error::other(format!("{e:#}")))?;
        Ok(MarkDir {
            dir,
            name: CString::new(name.as_bytes()).map_err(io::Error::other)?,
        })
    }

    /// Create and publish the first mark. It is world-readable for the stage user's
    /// `vk-agent memmark`; setting mode at creation avoids a chmod window. `O_EXCL` and
    /// `O_NOFOLLOW` refuse existing files and symlinks.
    fn create(&self, used: u64, total: u64) -> io::Result<Mark> {
        let mode: libc::c_uint = 0o644;
        // SAFETY: the descriptor and the name outlive the call, and `openat`'s variadic mode
        // is the type it reads for an `O_CREAT`.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor this call owns.
        let file = unsafe { File::from_raw_fd(fd) };
        let mut mark = Mark { file, used: 0 };
        if let Err(e) = mark.publish(used, total) {
            drop(mark);
            if let Err(remove) = self.remove() {
                warn!("vk-agent memmark: removing the incomplete mark failed: {remove}");
            }
            return Err(e);
        }
        Ok(mark)
    }

    fn remove(&self) -> io::Result<()> {
        // SAFETY: both the descriptor and the name outlive the call.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// One pass: publish the demand if it has grown past the mark.
fn sample(mark: &mut Mark) {
    let Some((used, total)) = demand() else {
        return;
    };
    if mark.used >= used {
        return;
    }
    // Leave the high-water unchanged so a later pass retries a failed write. Teardown soon
    // kills the guest, bounding repeated warnings.
    if let Err(e) = mark.publish(used, total) {
        warn!("vk-agent memmark: publishing {MARK}: {e}");
    }
}

/// Return whether `path` and `/` have different filesystem device IDs, or `false` if either
/// cannot be stat'd. Shared with [`crate::oomkills`], which needs the same answer about
/// `/run` before it writes there.
pub(crate) fn is_own_mount(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(path), std::fs::metadata("/")) {
        (Ok(m), Ok(root)) => m.dev() != root.dev(),
        _ => false,
    }
}

/// Watch this guest's memory demand when enabled by `VIRTKIT_MEMMARK=1`. Missing demand or an
/// absent ephemeral mark filesystem leaves the guest unmeasured.
///
/// Called after PID 1's last fork, like [`crate::fsmark::watch`], so a child cannot inherit a
/// lock held by a vanished thread before it calls `exec`.
pub(crate) fn watch(enabled: bool) {
    if !enabled {
        return;
    }
    let Some((used, total)) = demand() else {
        return;
    };
    // Without the /run tmpfs, omit the measurement rather than write into the stage image.
    if !is_own_mount(Path::new("/run")) {
        return;
    }
    // Publish the boot reading first. A missing mark then means unmeasured, so [`reported`]
    // cannot pass off a single teardown reading as a peak.
    let at = match MarkDir::open(Path::new(MARK)) {
        Ok(at) => at,
        Err(e) => {
            warn!("vk-agent memmark: cannot open the directory holding {MARK}: {e}");
            return;
        }
    };
    let mark = match at.create(used, total) {
        Ok(mark) => mark,
        Err(e) => {
            warn!("vk-agent memmark: publishing {MARK}: {e}");
            return;
        }
    };
    start_sampler(&at, mark, |mut mark| {
        std::thread::Builder::new()
            .name("memmark".into())
            .spawn(move || {
                loop {
                    sample(&mut mark);
                    std::thread::sleep(SAMPLE);
                }
            })
            .map(|_| ())
    });
}

/// Start the detached sampler. On failure, remove the initial mark so teardown cannot mistake
/// the boot reading for a sampled peak; the stage itself continues. `start` makes that path
/// testable.
fn start_sampler<F>(at: &MarkDir, mark: Mark, start: F)
where
    F: FnOnce(Mark) -> io::Result<()>,
{
    match start(mark) {
        Ok(_) => log::info!("vk-agent init: watching this guest's memory demand"),
        Err(e) => {
            if let Err(remove) = at.remove() {
                warn!("vk-agent init: removing the inactive memmark failed: {remove}");
            }
            warn!("vk-agent init: starting the memmark sampler failed: {e}");
        }
    }
}

/// The peak demand and guest total, or `None` without a complete sampled mark. A teardown-only
/// reading is not a peak, and a mid-write read stays unmeasured rather than understating a
/// sizing figure.
///
/// The live reading is folded in on top of the mark in case demand grew since the last pass.
fn reported(path: &Path) -> Option<(u64, u64)> {
    let (mark, total) = published(path)?;
    Some((mark.max(demand().map_or(0, |(used, _)| used)), total))
}

/// Print `<peak-demand> <total>` in bytes for the host over the guest exec channel. Exit
/// nonzero when no measurement is available so the host does not report zero demand.
pub fn main(args: &[String]) -> i32 {
    if !args.is_empty() {
        eprintln!("usage: vk-agent memmark");
        return 2;
    }
    let Some((used, total)) = reported(Path::new(MARK)) else {
        eprintln!("memmark: this guest's memory demand was not sampled");
        return 1;
    };
    println!("{used} {total}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_demand_discounts_what_the_kernel_would_hand_back() {
        // Reclaimable cache remains available and is excluded from demand.
        let (used, total) = parse_meminfo(
            "MemTotal:        4194304 kB\n\
             MemFree:          131072 kB\n\
             MemAvailable:    3145728 kB\n\
             Cached:          2097152 kB\n",
        )
        .expect("both fields present");
        assert_eq!(total, 4 * 1024 * 1024 * 1024);
        assert_eq!(used, 1024 * 1024 * 1024);
    }

    #[test]
    fn a_meminfo_without_memavailable_is_no_measurement() {
        // Missing MemAvailable leaves demand unmeasured; MemFree is not a substitute.
        assert_eq!(
            parse_meminfo("MemTotal: 4194304 kB\nMemFree: 131072 kB\n"),
            None
        );
        assert_eq!(parse_meminfo("MemAvailable: 3145728 kB\n"), None);
    }

    #[test]
    fn a_field_too_large_to_scale_to_bytes_is_no_measurement() {
        // Reject overflow instead of wrapping it into a dangerously small sizing figure.
        let huge = u64::MAX;
        assert_eq!(
            parse_meminfo(&format!("MemTotal: {huge} kB\nMemAvailable: 1 kB\n")),
            None
        );
        // The parser does not require the kernel's unit annotation.
        assert_eq!(
            parse_meminfo("MemTotal: 4194304\nMemAvailable: 3145728\n"),
            Some((1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024))
        );
    }

    #[test]
    fn the_live_meminfo_reads() {
        // Exercise the parser against the test host's real /proc format. A plausible total
        // confirms that both fields were found and scaled.
        let (used, total) = demand().expect("read /proc/meminfo");
        assert!(total >= 1024 * 1024, "implausible MemTotal {total}");
        assert!(used <= total, "demand {used} exceeds total {total}");
    }

    #[test]
    fn only_a_run_of_its_own_holds_the_mark() {
        // `/proc` represents a separate mount and `/` the root filesystem.
        assert!(is_own_mount(Path::new("/proc")));
        assert!(!is_own_mount(Path::new("/")));
        assert!(!is_own_mount(Path::new(
            "/vk-agent-nonexistent-memmark-target"
        )));
    }

    #[test]
    fn a_published_mark_reads_back_as_the_two_figures_written() {
        let (path, at) = tempmark("published");
        let _mark = at.create(9_000, 10_000).unwrap();
        assert_eq!(published(&path), Some((9_000, 10_000)));
    }

    #[test]
    fn a_revealed_underlying_file_is_not_overwritten() {
        let (path, at) = tempmark("revealed-underlay");
        let mut mark = at.create(0, 10_000).unwrap();

        // Model MNT_DETACH revealing an image-provided file at the same pathname. The sampler
        // must keep writing the detached tmpfs inode it opened, never resolve this path again.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "image content\n").unwrap();
        sample(&mut mark);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "image content\n");
    }

    #[test]
    fn the_mark_is_removed_from_the_directory_it_was_created_in() {
        // Model MNT_DETACH changing the parent path. Descriptor-relative removal must delete
        // the sampler's mark, not a same-named file in the replacement directory.
        let root = tempfile("swapped-parent");
        let _ = std::fs::remove_dir_all(&root);
        let (dir, stash) = (root.join("run"), root.join("stash"));
        std::fs::create_dir_all(&dir).unwrap();
        let at = MarkDir::open(&dir.join("mark")).unwrap();
        at.create(1_000, 10_000).unwrap();

        std::fs::rename(&dir, &stash).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("mark"), "someone else's").unwrap();
        at.remove().unwrap();
        assert!(!stash.join("mark").exists(), "the sampler's mark survived");
        assert_eq!(
            std::fs::read_to_string(dir.join("mark")).unwrap(),
            "someone else's"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_symlink_in_the_marks_place_is_not_written_through() {
        let (target, link) = (tempfile("symlink-target"), tempfile("symlink"));
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(MarkDir::open(&link).unwrap().create(9_000, 10_000).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        std::fs::remove_file(&link).unwrap();
    }

    #[test]
    fn a_sampler_that_does_not_start_leaves_no_measurement() {
        let (path, at) = tempmark("start-failed");
        let mark = at.create(1_000, 10_000).unwrap();
        start_sampler(&at, mark, |_| Err(io::Error::other("injected failure")));
        assert!(!path.exists(), "the inactive sampler left a readable mark");
        assert_eq!(reported(&path), None);
    }

    #[test]
    fn a_mark_that_is_not_two_figures_is_no_mark() {
        // Anything but two figures may be a mid-write read and is not a published mark.
        let path = tempfile("torn");
        for text in ["", "9000", "9000 ", "nine 10000\n"] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(published(&path), None, "accepted {text:?}");
        }
    }

    #[test]
    fn the_mark_holds_the_high_water_and_not_the_last_reading() {
        // `sample` preserves a mark above any possible live reading.
        let (path, at) = tempmark("high-water");
        let mut mark = at.create(u64::MAX, u64::MAX).unwrap();
        sample(&mut mark);
        assert_eq!(published(&path), Some((u64::MAX, u64::MAX)));
        // `publish` itself always writes: holding the mark is `sample`'s job alone.
        mark.publish(1_000, 10_000).unwrap();
        assert_eq!(published(&path), Some((1_000, 10_000)));
    }

    #[test]
    fn a_sample_above_the_mark_raises_it() {
        // Assert a property rather than equality because demand moves between meminfo reads.
        let (path, at) = tempmark("raises");
        let mut mark = at.create(0, 0).unwrap();
        sample(&mut mark);
        let (used, total) = published(&path).expect("the sample published");
        assert!(used > 0, "the 0 mark survived a live reading");
        assert_eq!(total, demand().expect("read /proc/meminfo").1);
    }

    #[test]
    fn a_guest_that_was_never_sampled_reports_nothing() {
        // No mark means no sampler ran, and the live reading alone is not a peak — the host
        // must record the stage as unmeasured rather than size it from a teardown figure.
        let path = tempfile("unsampled");
        assert_eq!(reported(&path), None);
    }

    #[test]
    fn the_report_folds_the_live_reading_over_a_stale_mark() {
        let (path, at) = tempmark("folded");
        // A mark below the live reading: demand grew since the sampler's last pass. The
        // demand itself is not pinned to a second /proc/meminfo read, which would differ.
        let mut mark = at.create(0, 4096).unwrap();
        let (used, total) = reported(&path).expect("a mark exists");
        assert_eq!(
            total, 4096,
            "the total comes from the mark, not the live read"
        );
        assert!(used > 0, "the live reading did not beat the 0 mark");
        // A mark above any live reading is kept as-is.
        mark.publish(u64::MAX, 4096).unwrap();
        assert_eq!(reported(&path), Some((u64::MAX, 4096)));
    }

    /// Return a per-test, per-process path, removing leftovers from a recycled PID.
    fn tempfile(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("vk-agent-memmark-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// The same path, paired with the descriptor the mark is created and removed through.
    fn tempmark(name: &str) -> (PathBuf, MarkDir) {
        let path = tempfile(name);
        let at = MarkDir::open(&path).expect("the temp directory opens");
        (path, at)
    }
}
